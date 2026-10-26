import base64
import calendar
import json
import re
import ssl
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Reader (v1.5): the grouping lives in the Wazuh Alerting monitors (bucket-level monitors,
# one alert per indicator and monitor, state and counts kept by the engine). This node keeps
# NO state of its own: it reads the ACTIVE and ACKNOWLEDGED engine alerts through the Alerting API and writes
# one TheHive alert per engine alert (title, description, summary kept in sync). Credentials
# are read at run time from the parameters of two other nodes of this workflow, never printed:
#   INDEXER_NODE -> Username / Password (read-only indexer user, role alerting_read_access)
#   THEHIVE_NODE -> Headers parameter holding the "Authorization: Bearer ..." line
# Nothing is written to the TheHive comment field (it stays for analysts); every update of the
# title, description and summary is kept by TheHive's History tab.
# v1.4 added the hash monitors (ioc-hash-sha256-t1, -md5-, -sha1-): same mirroring, the observable type is hash
# and the hash type (sha256, md5, sha1) is kept in the tags. IMPHASH is not matched (v1.5).
# v1.6 writes ONE heartbeat document (index ioc-reader-heartbeat, fixed id) as the LAST step of every live run, after
# the TheHive writes. "ok" is false only when the reader could not do its job (Alerting API or TheHive failed);
# MISP trouble only thins the context section and does not count. A Wazuh monitor alerts when no fresh ok document exists.
# ---------------------------------------------------------------------------
VERSION = "1.6"
DRY_RUN = True                       # True: plan only, NOTHING is written
SOURCE = "wazuh-alerting-pilot"      # TheHive alert source (pilot)
ALERT_TYPE = "wazuh-ioc"
INDEXER_URL = "https://10.1.30.10:9200"
THEHIVE_URL = "http://10.1.30.12:9000"
MAX_ALERTS = 500
MAX_TITLE_BYTES = 256                # Sentinel: 256 bytes for AlertName
MAX_DETAILS_BYTES = 2048             # Sentinel custom details: 2 KB combined
MAX_RUN_SECONDS = 50
# engine alert states that keep being mirrored: the vendors (Sentinel, Splunk ES, QRadar) do not stop updating
# an alert because an analyst is working on it; only closing / the time window ends it
READ_STATES = ("ACTIVE", "ACKNOWLEDGED")
# MISP context: a live restSearch per indicator when an alert is written. The query uses the same filters and
# the same decay overrides as the list sync (misp_ioc_sync.py), so "decayed" agrees with list membership.
MISP_URL = "https://10.1.30.15"
MISP_NODE = "misp_key"               # HTTP node (renamed to this label) whose headers parameter holds "Authorization: <MISP auth key>"
MISP_DECAY = {"threshold": 10, "lifetime": 365}
MISP_DECAY_MODEL = "1"
MISP_LIMIT = 50
MISP_TIMEOUT = 10
MAX_CONTEXT_BYTES = 2048
CONTEXT_MARK = "**MISP context**"
ANALYSIS = {"0": "initial", "1": "ongoing", "2": "completed"}
INDEXER_NODE = "http_1"
THEHIVE_NODE = "http_2"
HEARTBEAT_INDEX = "ioc-reader-heartbeat"   # single document, overwritten after every live run
HEARTBEAT_ID = "reader"
HEARTBEAT_TIMEOUT = 10

# monitor name -> how to present its alerts. "source" is the list the indicator comes from
# (Splunk's threat_source_id), "side" which side of the event matched.
MONITORS = {
    "ioc-fw-dst-t1": {"dtype": "ip", "source": "misp-ip-t1", "side": "destination"},
    "ioc-fw-src-t1": {"dtype": "ip", "source": "misp-ip-t1", "side": "source"},
    "ioc-sysmon-ip-t1": {"dtype": "ip", "source": "misp-ip-t1", "side": "destination"},
    "ioc-domain-t1": {"dtype": "domain", "source": "misp-domain-t1", "side": "DNS query"},
    "ioc-hash-sha256-t1": {"dtype": "hash", "source": "misp-hash-t1", "side": "SHA256 (Sysmon hashes field)",
                           "label": "SHA256 hash", "htype": "sha256"},
    "ioc-hash-md5-t1": {"dtype": "hash", "source": "misp-hash-t1", "side": "MD5 (Sysmon hashes field)",
                        "label": "MD5 hash", "htype": "md5"},
    "ioc-hash-sha1-t1": {"dtype": "hash", "source": "misp-hash-t1", "side": "SHA1 (Sysmon hashes field)",
                         "label": "SHA1 hash", "htype": "sha1"},
}
TYPE_LABEL = {"ip": "IP", "domain": "Domain", "hash": "Hash"}
# bucket sub-aggregation -> label; counted lists show "value (n)", ids are plain
DETAIL_FIELDS = (("action", "Action", True), ("proto", "Protocol", True), ("port", "Port", True),
                 ("src", "Source IP", True), ("dst", "Destination IP", True), ("image", "Process", True),
                 ("parent", "Parent process", True), ("event", "Event ID", True),
                 ("query", "DNS query", True), ("kind", "Match kind", True),
                 ("agent", "Reported by", True), ("rule", "Rules", True), ("ids", "Alarm IDs", False))
SUMMARY_RE = re.compile(r"^count=(\d+) first=(\S+) last=(\S+)$")


def to_ms(value):
    # the HTTP API returns epoch milliseconds as floats in scientific notation (1.79E12)
    return int(float(value))


def iso_ms(ms):
    base = datetime.fromtimestamp(ms // 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    return "%s.%03dZ" % (base, ms % 1000)


def parse_iso_ms(text):
    dt = datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ")
    return calendar.timegm(dt.timetuple()) * 1000 + dt.microsecond // 1000


def last_of_summary(text):
    m = SUMMARY_RE.match((text or "").strip())
    if not m:
        return None
    try:
        return parse_iso_ms(m.group(3))
    except Exception:
        return None


def node_params(fe, label):
    wf = fe.get("workflow") or {}
    for action in wf.get("actions") or []:
        if isinstance(action, dict) and (action.get("label") or action.get("name")) == label:
            return {p.get("name"): p.get("value") for p in (action.get("parameters") or [])
                    if isinstance(p, dict)}
    return {}


def http_call(method, url, headers=None, body=None, basic=None, ctx=None, timeout=30):
    data = None
    hdrs = dict(headers or {})
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs.setdefault("Content-Type", "application/json")
    if basic:
        token = base64.b64encode(("%s:%s" % basic).encode("utf-8")).decode("ascii")
        hdrs["Authorization"] = "Basic " + token
    req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        status, raw = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode("utf-8", "replace")
    try:
        return status, json.loads(raw) if raw else None
    except Exception:
        return status, raw


def pairs(bucket, key):
    node = bucket.get(key) or {}
    out = []
    for b in node.get("buckets") or []:
        if isinstance(b, dict) and b.get("key") is not None:
            out.append((str(b.get("key")), int(b.get("doc_count") or 0)))
    return out


def build_title(indicator, source, agents):
    # Splunk's notable title "Threat Activity Detected ($threat_match_value$, $threat_source_id$, ...)"
    # with the reporting host(s) added
    for n in range(len(agents), 0, -1):
        extra = len(agents) - n
        text = ", ".join(agents[:n]) + ((" +%d" % extra) if extra else "")
        title = "Threat Activity Detected (%s, %s, %s)" % (indicator, source, text)
        if len(title.encode("utf-8")) <= MAX_TITLE_BYTES:
            return title
    return ("Threat Activity Detected (%s, %s)" % (indicator, source))[:MAX_TITLE_BYTES]


def build_details(lists):
    # value lists in the manner of Sentinel custom details: 2 KB combined; when too large the
    # last (least frequent, or oldest alarm id) value of the longest list goes first
    d = {k: list(v) for k, v in lists.items()}
    while True:
        lines = []
        for key, label, counted in DETAIL_FIELDS:
            vals = d.get(key) or []
            if not vals:
                continue
            if key == "ids":
                lines.append("- %s (latest %d): %s" % (label, len(vals), ", ".join(v for v, _ in vals)))
            elif counted:
                lines.append("- %s: %s" % (label, ", ".join("%s (%d)" % (v, n) for v, n in vals)))
        text = "\n".join(lines)
        if len(text.encode("utf-8")) <= MAX_DETAILS_BYTES:
            return text
        longest = max(d, key=lambda k: (len(d[k]), k == "ids"))
        if not d[longest]:
            return text
        d[longest].pop()


def cell(text):
    return str(text).replace("|", "/").replace("\n", " ")


def build_description(engine, mon, indicator, count, first_ms, last_ms, lists):
    label = mon.get("label") or TYPE_LABEL.get(mon["dtype"], mon["dtype"])
    lines = ["**Threat Activity Detected** | %s `%s` | source %s" % (label, cell(indicator), mon["source"]), "",
             "- Monitor: %s | engine alert %s | state %s" % (engine.get("monitor_name"), engine.get("id"), engine.get("state")),
             "- Engine alert opened (UTC): %s" % iso_ms(to_ms(engine.get("start_time") or 0)),
             "- Alarms in the monitor window: %d | first seen %s | last seen %s" % (count, iso_ms(first_ms), iso_ms(last_ms)),
             "- Match side: %s" % mon["side"]]
    details = build_details(lists)
    if details:
        lines += ["", "**Details**", "", details]
    return "\n".join(lines)


def parse_headers(text):
    out = {}
    for line in str(text or "").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def clean(text, limit):
    # MISP content is untrusted (feeds write free text): drop control characters, HTML and Markdown link syntax
    s = "".join(" " if ord(c) < 32 else c for c in str(text or ""))
    for ch in "<>`":
        s = s.replace(ch, "")
    s = s.replace("[", "(").replace("]", ")")
    # defang links so that no feed-supplied address becomes clickable in the TheHive description
    s = re.sub(r"\bhttp(s?)://", r"hxxp\1://", s, flags=re.ASCII | re.IGNORECASE)
    s = re.sub(r"\bftp://", "fxp://", s, flags=re.ASCII | re.IGNORECASE)
    s = re.sub(r"\bwww\.", "www[.]", s, flags=re.ASCII | re.IGNORECASE)
    s = " ".join(s.split())
    return s[:limit] + ("..." if len(s) > limit else "")


def key_shape(value):
    # describes the Authorization value without revealing it: length and common copy/paste mistakes
    v = str(value or "")
    flags = [name for name, bad in (("quote", any(c in v for c in "\"'")), ("space", " " in v),
                                    ("Bearer prefix", v.startswith("Bearer"))) if bad]
    return "Authorization length %d%s" % (len(v), (", has " + "/".join(flags)) if flags else "")


def misp_lookup(value, headers, ctx):
    body = {"returnFormat": "json", "value": value, "to_ids": 1, "published": 1, "includeEventTags": 1,
            "includeDecayScore": 1, "modelOverrides": dict(MISP_DECAY), "limit": MISP_LIMIT}
    hdrs = dict(headers)
    hdrs.setdefault("Accept", "application/json")
    try:
        status, res = http_call("POST", MISP_URL + "/attributes/restSearch", headers=hdrs, body=body,
                                ctx=ctx, timeout=MISP_TIMEOUT)
    except Exception as e:
        return None, "misp query failed (%s)" % type(e).__name__
    if status != 200 or not isinstance(res, dict):
        detail = res.get("message") or res.get("name") if isinstance(res, dict) else res
        return None, "misp query failed (status %s: %s; %s)" % (status, clean(detail, 120) or "no message", key_shape(headers.get("Authorization")))
    attrs = (res.get("response") or {}).get("Attribute")
    return [a for a in (attrs or []) if isinstance(a, dict)], None


def decay_entry(attr):
    for d in attr.get("decay_score") or []:
        if isinstance(d, dict) and str((d.get("DecayingModel") or {}).get("id")) == MISP_DECAY_MODEL:
            return d
    return None


def build_context(attrs):
    head = "%s (live MISP query: published events, IDS flag)" % CONTEXT_MARK
    if not attrs:
        return "\n".join([head, "", "- No current MISP record matches this value; the local lists refresh once a day."])
    events, types, cats, tags, comments, firsts, lasts = {}, {}, [], [], [], [], []
    best, alive, scored, model_name = None, 0, 0, None
    for a in attrs:
        ev = a.get("Event") if isinstance(a.get("Event"), dict) else {}
        events.setdefault(str(a.get("event_id") or ev.get("id") or "?"), ev)
        t = str(a.get("type") or "?")
        types[t] = types.get(t, 0) + 1
        c = clean(a.get("category"), 40)
        if c and c not in cats:
            cats.append(c)
        for tg in a.get("Tag") or []:
            name = tg.get("name") if isinstance(tg, dict) else None
            if name and clean(name, 60) not in tags:
                tags.append(clean(name, 60))
        cm = clean(a.get("comment"), 80)
        if cm and cm not in comments:
            comments.append(cm)
        if a.get("first_seen"):
            firsts.append(str(a["first_seen"]))
        if a.get("last_seen"):
            lasts.append(str(a["last_seen"]))
        d = decay_entry(a)
        if d:
            scored += 1
            model_name = model_name or (d.get("DecayingModel") or {}).get("name")
            try:
                sc = float(d.get("score"))
                best = sc if best is None or sc > best else best
            except (TypeError, ValueError):
                pass
            if d.get("decayed") is False:
                alive += 1
    order = sorted(events, key=lambda e: (-int(e) if e.isdigit() else 0, e))

    def render(ev_cap, tag_cap):
        lines = [head, ""]
        shown = []
        for eid in order[:ev_cap]:
            ev = events[eid]
            org = clean((ev.get("Orgc") or {}).get("name"), 40) or "?"
            shown.append("#%s %s (%s, %s, analysis %s)" % (eid, clean(ev.get("info"), 120) or "-", org,
                         clean(ev.get("date"), 12) or "?", ANALYSIS.get(str(ev.get("analysis")), "?")))
        lines.append("- Events: %s%s" % ("; ".join(shown), (" +%d more" % (len(order) - ev_cap)) if len(order) > ev_cap else ""))
        lines.append("- Attributes: %s%s" % (", ".join("%s (%d)" % kv for kv in types.items()),
                                             (" | Category: " + ", ".join(cats)) if cats else ""))
        if tag_cap and tags:
            lines.append("- Tags: %s%s" % (", ".join(tags[:tag_cap]), (" +%d more" % (len(tags) - tag_cap)) if len(tags) > tag_cap else ""))
        if tag_cap and comments:
            lines.append("- Comments: %s" % "; ".join(comments[:3]))
        if firsts or lasts:
            lines.append("- Seen: first %s, last %s" % (min(firsts) if firsts else "-", max(lasts) if lasts else "-"))
        if scored:
            lines.append("- Decay (%s, lifetime %d, threshold %d): best score %s; not decayed in %d of %d attributes" % (
                clean(model_name, 60) or "model " + MISP_DECAY_MODEL, MISP_DECAY["lifetime"], MISP_DECAY["threshold"],
                ("%.2f" % best) if best is not None else "?", alive, len(attrs)))
        lines.append("- MISP: %s" % " ".join("%s/events/view/%s" % (MISP_URL, e) for e in order[:3]))
        return "\n".join(lines)

    text = ""
    for ev_cap, tag_cap in ((10, 20), (5, 10), (3, 5), (1, 0)):
        text = render(ev_cap, tag_cap)
        if len(text.encode("utf-8")) <= MAX_CONTEXT_BYTES:
            break
    return text


def write_heartbeat(out, user, secret, ctx):
    # Written LAST and only after a live run: a fresh document means the run got this far.
    doc = {"last_run": iso_ms(int(time.time() * 1000)), "version": VERSION,
           "ok": out["critical_errors"] == 0, "critical_errors": out["critical_errors"],
           "errors": len(out["errors"]), "alerts_seen": out.get("alerts_seen", 0),
           "created": len(out["created"]), "updated": len(out["updated"]), "recreated": len(out["recreated"])}
    try:
        status, _ = http_call("PUT", "%s/%s/_doc/%s" % (INDEXER_URL, HEARTBEAT_INDEX, HEARTBEAT_ID), body=doc,
                              basic=(user, secret), ctx=ctx, timeout=HEARTBEAT_TIMEOUT)
    except Exception:
        status = 0
    out["heartbeat"] = {"written": status in (200, 201), "status": status, "ok": doc["ok"]}
    if status not in (200, 201):
        out["errors"].append("heartbeat write failed (status %s)" % status)


def sync(fe):
    out = {"version": VERSION, "dry_run": DRY_RUN, "source": SOURCE, "misp_node": MISP_NODE, "errors": [], "created": [],
           "updated": [], "recreated": [], "skipped_closed": [], "ignored_state": 0,
           "ignored_monitor": 0, "plan": {}, "critical_errors": 0, "heartbeat": {"written": False}}
    t0 = time.time()
    ix = node_params(fe, INDEXER_NODE)
    th = node_params(fe, THEHIVE_NODE)
    ix_user, ix_pass = ix.get("username"), ix.get("password")
    hive_headers = parse_headers(th.get("headers"))
    misp_headers = parse_headers(node_params(fe, MISP_NODE).get("headers"))
    if not ix_user or not ix_pass or "Authorization" not in hive_headers:
        out["errors"].append("credentials not found in node parameters (%s / %s)" % (INDEXER_NODE, THEHIVE_NODE))
        return out
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    misp_ready = "Authorization" in misp_headers
    if not misp_ready:
        out["errors"].append("misp credentials not found in node %s; alerts are written without MISP context" % MISP_NODE)

    alerts, seen_ids = [], set()
    out["alerting_status"] = {}
    for state in READ_STATES:
        status, body = http_call("GET", "%s/_plugins/_alerting/monitors/alerts?size=%d&alertState=%s" % (INDEXER_URL, MAX_ALERTS, state),
                                 basic=(ix_user, ix_pass), ctx=ctx)
        out["alerting_status"][state] = status
        if status != 200 or not isinstance(body, dict):
            out["critical_errors"] += 1
            out["errors"].append("alerting query failed (%s alerts, status %s)%s" % (
                state, status, "; is the alerting_read_access role mapped?" if state == READ_STATES[0] else ""))
            continue
        got = body.get("alerts") or []
        if int(body.get("totalAlerts") or 0) > len(got):
            out["errors"].append("%s alert list truncated: %s alerts, %d read" % (state, body.get("totalAlerts"), len(got)))
        for a in got:
            if a.get("id") not in seen_ids:      # a server that ignores the state filter must not double the work
                seen_ids.add(a.get("id"))
                alerts.append(a)
    out["alerts_seen"] = len(alerts)

    def hive(method, path, payload=None):
        return http_call(method, THEHIVE_URL + path, headers=hive_headers, body=payload)

    def latest_alert(tag):
        q = {"query": [{"_name": "listAlert"},
                       {"_name": "filter", "_and": [
                           {"_eq": {"_field": "source", "_value": SOURCE}},
                           {"_eq": {"_field": "tags", "_value": tag}}]},
                       {"_name": "sort", "_fields": [{"_createdAt": "desc"}]},
                       {"_name": "page", "from": 0, "to": 1}]}
        st, res = hive("POST", "/api/v1/query", q)
        if st != 200 or not isinstance(res, list):
            return None, "thehive alert query failed (status %s)" % st
        return (res[0] if res else None), None

    def alert_state(alert):
        stage = alert.get("stage")
        if stage in ("New", "InProgress"):
            return "open"
        if stage == "Closed":
            return "closed"
        if stage == "Imported":
            case_id = alert.get("caseId")
            if not case_id:
                return "unknown"
            st, res = hive("POST", "/api/v1/query", {"query": [{"_name": "getCase", "idOrName": case_id}]})
            if st != 200 or not isinstance(res, list) or not res:
                return "unknown"
            return "closed" if res[0].get("stage") == "Closed" else "open"
        return "unknown"

    for engine in alerts:
        if time.time() - t0 > MAX_RUN_SECONDS:
            out["errors"].append("run time budget reached, the rest is picked up next run")
            break
        mon = MONITORS.get(engine.get("monitor_name"))
        if mon is None:
            out["ignored_monitor"] += 1
            continue
        if engine.get("state") not in READ_STATES:
            out["ignored_state"] += 1
            continue
        content = engine.get("agg_alert_content") or {}
        keys = content.get("bucket_keys") or []
        bucket = content.get("bucket") or {}
        if not keys:
            out["errors"].append("%s: engine alert without bucket key" % engine.get("id"))
            continue
        indicator = str(keys[0])
        engine_id = str(engine.get("id"))
        lists = {k: pairs(bucket, k) for k, _, _ in DETAIL_FIELDS}
        agents = [v for v, _ in lists["agent"]]
        count = int(bucket.get("doc_count") or 0)
        first_ms = to_ms((bucket.get("first") or {}).get("value") or 0)
        last_ms = to_ms((bucket.get("last") or {}).get("value") or 0)
        title = build_title(indicator, mon["source"], agents)
        description = build_description(engine, mon, indicator, count, first_ms, last_ms, lists)
        summary = "count=%d first=%s last=%s" % (count, iso_ms(first_ms), iso_ms(last_ms))
        tag = "engine-alert:" + engine_id
        existing, err = latest_alert(tag)
        if err:
            out["critical_errors"] += 1
            out["errors"].append("%s: %s" % (engine_id, err))
            continue
        action = "create"
        source_ref = engine_id
        if existing:
            state = alert_state(existing)
            if state == "unknown":
                out["errors"].append("%s: cannot determine alert state (stage=%s)" % (engine_id, existing.get("stage")))
                continue
            if state == "open":
                action = "update"
            else:
                seen = last_of_summary(existing.get("summary"))
                if seen is not None and last_ms <= seen:
                    out["skipped_closed"].append(engine_id)
                    continue
                action = "recreate"
                source_ref = "%s|%d" % (engine_id, last_ms)
        block, misp_state = None, "disabled"
        if misp_ready:
            attrs, merr = misp_lookup(indicator, misp_headers, ctx)
            if merr:
                out["errors"].append("%s: %s" % (engine_id, merr))
                misp_state = "unavailable"
            else:
                block, misp_state = build_context(attrs), "ok"
        if block is not None:
            description = description + "\n\n" + block
        elif existing:
            # MISP cannot be asked right now: keep the context section that is already in the alert
            old = existing.get("description") or ""
            idx = old.find("\n\n" + CONTEXT_MARK)
            if idx >= 0:
                description = description + old[idx:]
        out["plan"][engine_id] = {"action": action, "title": title, "summary": summary, "indicator": indicator,
                                  "misp": {"status": misp_state, "attributes": (len(attrs) if misp_state == "ok" else None)}}
        if DRY_RUN:
            continue
        if action == "update":
            changes = {}
            for field, value in (("title", title), ("description", description), ("summary", summary)):
                if (existing.get(field) or "").strip() != value.strip():
                    changes[field] = value
            if changes:
                st, res = hive("PATCH", "/api/v1/alert/%s" % existing.get("_id"), changes)
                if st not in (200, 204):
                    out["critical_errors"] += 1
                    out["errors"].append("%s: alert update failed (status %s)" % (engine_id, st))
                    continue
                out["updated"].append({"engine_alert": engine_id, "fields": sorted(changes)})
            continue
        type_tags = ["hash-type:" + mon["htype"]] if mon.get("htype") else []
        body_new = {"type": ALERT_TYPE, "source": SOURCE, "sourceRef": source_ref,
                    "title": title, "description": description, "summary": summary,
                    "severity": 2, "tlp": 2, "pap": 2, "date": first_ms,
                    "tags": ["misp-ioc", "tier1", "wazuh", "ioc:" + indicator, tag,
                             "monitor:" + str(engine.get("monitor_name"))] + type_tags,
                    "observables": [{"dataType": mon["dtype"], "data": indicator,
                                     "message": "MISP IOC (tier 1)", "tlp": 2, "ioc": True,
                                     "sighted": True, "tags": ["misp-ioc", "tier1"] + type_tags}]}
        st, res = hive("POST", "/api/v1/alert", body_new)
        if st == 201 and isinstance(res, dict):
            (out["recreated"] if action == "recreate" else out["created"]).append(
                {"engine_alert": engine_id, "alert": res.get("_id"), "indicator": indicator})
        elif st == 400:
            out["plan"][engine_id]["result"] = "alert already exists (idempotent skip)"
        else:
            out["critical_errors"] += 1
            out["errors"].append("%s: create failed (status %s)" % (engine_id, st))
    if DRY_RUN:
        out["heartbeat"] = {"written": False, "reason": "dry run"}
    else:
        write_heartbeat(out, ix_user, ix_pass, ctx)
    return out


print(json.dumps(sync(self.full_execution)))
