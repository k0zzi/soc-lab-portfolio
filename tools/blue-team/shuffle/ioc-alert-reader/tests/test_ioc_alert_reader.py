import contextlib, http.server, io, json, os, re, sys, threading
from datetime import datetime, timezone

SCRIPT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "ioc_alert_reader.py")
BASE = 1791000000000
SRC = open(SCRIPT, encoding="utf-8").read()
fails = []
count = [0]


def check(name, cond, info=""):
    count[0] += 1
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(info)[:300]) if (info and not cond) else ""))
    if not cond:
        fails.append(name)


class World:
    def __init__(self):
        self.engine, self.engine_status, self.engine_total = [], 200, None
        self.state_status, self.ignore_state_param = {}, False
        self.misp_fn, self.misp_status, self.misp_requests = None, 200, []
        self.alerts, self.comments, self.cases = {}, [], {}
        self.patches, self.patch_fail, self.gets = [], False, []


W = World()


def iso(ms):  # independent of the node under test
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (ms % 1000)


def mattr(aid, typ, ev_id, info, org="soc.dev", date="2026-06-22", analysis="2", cat="Network activity", tags=(),
          decayed=False, score=34.2, model_id="1", comment="", first_seen=None, last_seen=None):
    return {"id": aid, "type": typ, "category": cat, "to_ids": True, "event_id": ev_id, "comment": comment,
            "timestamp": "1782109706", "first_seen": first_seen, "last_seen": last_seen,
            "Event": {"id": ev_id, "info": info, "Orgc": {"name": org}, "date": date, "analysis": analysis, "uuid": "u" + ev_id},
            "Tag": [{"name": n} for n in tags],
            "decay_score": [{"DecayingModel": {"id": model_id, "name": "NIDS Simple Decaying Model"},
                             "base_score": 80, "decayed": decayed, "score": score}]}


def default_misp(value):
    return [mattr("1390401", "ip-dst", "2258", "TheHive Test"), mattr("1390402", "ip-src", "2258", "TheHive Test"),
            mattr("5984752", "ip-dst", "4935", "Other event", tags=("tlp:white",), decayed=True, score=0.3)]


def lst(items):
    return {"doc_count_error_upper_bound": 0, "sum_other_doc_count": 0,
            "buckets": [{"doc_count": n, "key": k} for k, n in items]}


def eng(aid, monitor, key, count, first, last, agent=(("OPNsense", 1),), state="ACTIVE", start=BASE, **lists):
    bucket = {"doc_count": count, "first": {"value": float(first)}, "last": {"value": float(last)}, "agent": lst(agent)}
    for k, v in lists.items():
        bucket[k] = lst(v)
    return {"id": aid, "monitor_name": monitor, "state": state, "start_time": start,
            "agg_alert_content": {"parent_bucket_path": "g", "bucket_keys": [key], "bucket": bucket}}


class H(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, obj=None):
        raw = json.dumps(obj).encode() if obj is not None else b""
        self.send_response(code)
        if raw:
            self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        W.gets.append(self.path)
        if not self.path.startswith("/_plugins/_alerting/monitors/alerts"):
            return self.reply(404, {})
        m = re.search(r"alertState=([A-Z]+)", self.path)
        state = m.group(1) if m else "ALL"
        if W.engine_status != 200:
            return self.reply(W.engine_status, {"error": "no permissions"})
        if W.state_status.get(state, 200) != 200:
            return self.reply(W.state_status[state], {"error": "bad request"})
        rows = W.engine if (W.ignore_state_param or state == "ALL") else [a for a in W.engine if a["state"] == state]
        total = W.engine_total if W.engine_total is not None else len(rows)
        return self.reply(200, {"alerts": rows, "totalAlerts": total})

    def do_POST(self):
        b = self.body()
        p = self.path
        if p == "/attributes/restSearch":
            W.misp_requests.append((b, self.headers.get("Authorization")))
            if W.misp_status != 200:
                return self.reply(W.misp_status, {"name": "Authentication failed. Please make sure you pass the API key of an API enabled user along in the Authorization header."})
            fn = W.misp_fn or default_misp
            return self.reply(200, {"response": {"Attribute": fn(b["value"])}})
        if p == "/api/v1/query":
            name = b["query"][0]["_name"]
            if name == "getCase":
                c = W.cases.get(b["query"][0]["idOrName"])
                return self.reply(200, [c] if c else [])
            flt = {x["_eq"]["_field"]: x["_eq"]["_value"] for x in b["query"][1]["_and"]}
            found = [a for a in W.alerts.values() if a["source"] == flt["source"] and flt["tags"] in a["tags"]]
            found.sort(key=lambda a: -a["_createdAt"])
            return self.reply(200, found[:1])
        if p == "/api/v1/alert":
            for a in W.alerts.values():
                if (a["type"], a["source"], a["sourceRef"]) == (b["type"], b["source"], b["sourceRef"]):
                    return self.reply(400, {"type": "CreateError"})
            aid = "~A%d" % (len(W.alerts) + 1)
            a = dict(b)
            a.update({"_id": aid, "stage": "New", "_createdAt": len(W.alerts) + 1})
            W.alerts[aid] = a
            return self.reply(201, {"_id": aid})
        if re.match(r"/api/v1/alert/([^/]+)/comment", p):
            W.comments.append(p)
            return self.reply(201, {"_id": "c"})
        self.reply(404, {})

    def do_PATCH(self):
        b = self.body()
        aid = self.path.rsplit("/", 1)[1]
        if W.patch_fail:
            return self.reply(500, {"error": "x"})
        W.patches.append((aid, sorted(b)))
        W.alerts[aid].update(b)
        self.reply(204)


srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % srv.server_address[1]


class Sdk:
    def __init__(self):
        self.full_execution = {"workflow": {"actions": [
            {"label": "http_1", "parameters": [{"name": "username", "value": "u"}, {"name": "password", "value": "p"}]},
            {"label": "http_2", "parameters": [{"name": "headers", "value": "Authorization: Bearer test"}]},
            {"label": "misp_key", "parameters": [{"name": "headers", "value": "Authorization: MISPKEY"}]}]}}


def run(dry=False, src=None, misp_url=None):
    src = src or SRC
    for old, new in (('INDEXER_URL = "https://10.1.30.10:9200"', 'INDEXER_URL = "%s"' % URL),
                     ('MISP_URL = "https://10.1.30.15"', 'MISP_URL = "%s"' % (misp_url or URL)),
                     ('THEHIVE_URL = "http://10.1.30.12:9000"', 'THEHIVE_URL = "%s"' % URL),
                     ("DRY_RUN = True", "DRY_RUN = %s" % dry)):
        assert src.count(old) == 1, old
        src = src.replace(old, new)
    ns = {"self": Sdk(), "__name__": "node"}
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(compile(src, "node", "exec"), ns)
    return json.loads(buf.getvalue().strip().splitlines()[-1])


def reset():
    global W
    W = World()


def alerts_for(indicator):
    return sorted((a for a in W.alerts.values() if "ioc:" + indicator in a["tags"]), key=lambda a: a["_createdAt"])


def fw_alert(aid="E1", count=44, last=BASE + 5000, agent=(("OPNsense", 44),), key="1.2.3.4", monitor="ioc-fw-dst-t1", state="ACTIVE"):
    return eng(aid, monitor, key, count, BASE, last, agent=agent, state=state,
               action=[("pass", 29), ("block", 15)], proto=[("tcp", 24), ("icmp", 20)],
               port=[("4444", 15), ("443", 9)], src=[("10.1.60.10", 28), ("192.168.1.2", 16)],
               rule=[("100330", 44)], ids=[("1792390197.4433242", 1), ("1792390197.4432785", 1)])


# T1 create from a real-shaped engine alert
reset()
W.engine = [fw_alert()]
r = run()
check("T1 one alert created, no errors", len(r["created"]) == 1 and r["errors"] == [], r)
a = alerts_for("1.2.3.4")[0] if alerts_for("1.2.3.4") else {}
check("T1 title follows the Splunk notable pattern with the host",
      a.get("title") == "Threat Activity Detected (1.2.3.4, misp-ip-t1, OPNsense)", a.get("title"))
check("T1 sourceRef is the engine alert id, date is the first seen", a.get("sourceRef") == "E1" and a.get("date") == BASE, a)
check("T1 tags carry indicator, engine alert and monitor",
      {"ioc:1.2.3.4", "engine-alert:E1", "monitor:ioc-fw-dst-t1"} <= set(a.get("tags", [])), a.get("tags"))
check("T1 observable is the indicator as ip", [(o["dataType"], o["data"]) for o in a.get("observables", [])] == [("ip", "1.2.3.4")])
d = a.get("description", "")
for line in ("- Action: pass (29), block (15)", "- Protocol: tcp (24), icmp (20)", "- Port: 4444 (15), 443 (9)",
             "- Source IP: 10.1.60.10 (28), 192.168.1.2 (16)", "- Reported by: OPNsense (44)", "- Rules: 100330 (44)",
             "- Alarm IDs (latest 2): 1792390197.4433242, 1792390197.4432785", "- Match side: destination"):
    check("T1 description line: " + line, line in d.splitlines(), d)
check("T1 summary", a.get("summary") == "count=44 first=%s last=%s" % (iso(BASE), iso(BASE + 5000)), a.get("summary"))
check("T1 nothing written to comments", W.comments == [])
check("T1 label says the ENGINE alert opened", "- Engine alert opened (UTC): " in d and "- Alert opened" not in d, d)

# T2 domain alert (two rules in one bucket)
reset()
W.engine = [eng("E2", "ioc-domain-t1", "ioc-test.example", 3, BASE, BASE + 1000, agent=(("CLT601", 3),),
                rule=[("100322", 2), ("100320", 1)], query=[("www.ioc-test.example", 1)], kind=[("suffix", 2)])]
r = run()
a = alerts_for("ioc-test.example")[0]
check("T2 domain title", a["title"] == "Threat Activity Detected (ioc-test.example, misp-domain-t1, CLT601)", a["title"])
check("T2 domain observable", [(o["dataType"], o["data"]) for o in a["observables"]] == [("domain", "ioc-test.example")])
for line in ("- DNS query: www.ioc-test.example (1)", "- Match kind: suffix (2)", "- Rules: 100322 (2), 100320 (1)", "- Match side: DNS query"):
    check("T2 description line: " + line, line in a["description"].splitlines(), a["description"])

# T3 Sysmon alert, two hosts
reset()
W.engine = [eng("E3", "ioc-sysmon-ip-t1", "8.8.8.8", 5, BASE, BASE + 10, agent=(("CLT601", 3), ("SRV202", 2)),
                image=[("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", 5)], port=[("443", 5)])]
run()
a = alerts_for("8.8.8.8")[0]
check("T3 title lists both hosts", a["title"] == "Threat Activity Detected (8.8.8.8, misp-ip-t1, CLT601, SRV202)", a["title"])
check("T3 process line", any(l.startswith("- Process: C:\\Windows") for l in a["description"].splitlines()))

# T4 only ACTIVE alerts of known monitors
reset()
W.engine = [fw_alert("E1"), fw_alert("E9", state="COMPLETED"), fw_alert("E8", state="DELETED"),
            eng("Z1", "zz-grouptest-monitor", "H1", 5, BASE, BASE + 1), eng("Z2", "ioc-domain-host-group", "CLT601", 4, BASE, BASE + 1)]
W.ignore_state_param = True      # the client-side state filter must hold even if the server returns every state
r = run()
check("T4 only the ACTIVE alert of a known monitor is written", len(W.alerts) == 1 and r["ignored_state"] == 2 and r["ignored_monitor"] == 2, r)

# T5 idempotent rerun
reset()
W.engine = [fw_alert()]
run()
r = run()
check("T5 rerun without change writes nothing", r["created"] == [] and r["updated"] == [] and W.patches == [] and len(W.alerts) == 1, r)

# T6 content change -> description and summary; title only when hosts change
W.engine = [fw_alert(count=46, last=BASE + 65000)]
r = run()
check("T6 count/last change patches description and summary only", W.patches[-1][1] == ["description", "summary"], W.patches)
check("T6 updated values", W.alerts[W.patches[-1][0]]["summary"].startswith("count=46") and "last=%s" % iso(BASE + 65000) in W.alerts[W.patches[-1][0]]["summary"])
W.engine = [fw_alert(count=47, last=BASE + 66000, agent=(("OPNsense", 40), ("SRV202", 7)))]
run()
check("T6 a new reporting host also patches the title", W.patches[-1][1] == ["description", "summary", "title"], W.patches)
check("T6 new title", W.alerts[W.patches[-1][0]]["title"] == "Threat Activity Detected (1.2.3.4, misp-ip-t1, OPNsense, SRV202)")

# T7 one alert per engine alert
reset()
W.engine = [fw_alert("E1", key="1.2.3.4"), fw_alert("E2", key="5.6.7.8"),
            fw_alert("E3", key="9.9.9.9", monitor="ioc-fw-dst-t1"),
            eng("E4", "ioc-sysmon-ip-t1", "9.9.9.9", 2, BASE, BASE + 5, agent=(("CLT601", 2),))]
run()
check("T7 different indicators and families each get their own alert", len(W.alerts) == 4, len(W.alerts))
check("T7 same indicator in two monitors stays two alerts with their own titles",
      sorted(a["title"] for a in alerts_for("9.9.9.9")) == ["Threat Activity Detected (9.9.9.9, misp-ip-t1, CLT601)", "Threat Activity Detected (9.9.9.9, misp-ip-t1, OPNsense)"])

# T8 closed handling: a closed alert is never reopened, new activity opens a new alert
reset()
W.engine = [fw_alert()]
run()
first = alerts_for("1.2.3.4")[0]
first["stage"] = "Closed"
r = run()
check("T8 closed alert without new activity: skipped", r["skipped_closed"] == ["E1"] and len(W.alerts) == 1 and W.patches == [], r)
W.engine = [fw_alert(count=45, last=BASE + 90000)]
r = run()
al = alerts_for("1.2.3.4")
check("T8 new activity after closure opens a NEW alert", len(al) == 2 and len(r["recreated"]) == 1 and al[1]["sourceRef"] == "E1|%d" % (BASE + 90000), [a["sourceRef"] for a in al])
check("T8 closed alert untouched", al[0]["stage"] == "Closed" and al[0]["summary"].startswith("count=44"))
W.engine = [fw_alert(count=46, last=BASE + 91000)]
run()
al = alerts_for("1.2.3.4")
check("T8 the new open alert is updated, no third alert", len(al) == 2 and al[1]["summary"].startswith("count=46"), [a["summary"] for a in al])
reset()
W.engine = [fw_alert()]
run()
x = alerts_for("1.2.3.4")[0]
x["stage"], x["caseId"] = "Imported", "C1"
W.cases["C1"] = {"stage": "Open"}
W.engine = [fw_alert(count=50, last=BASE + 70000)]
r = run()
check("T8 imported alert with an open case is updated", len(r["updated"]) == 1 and x["summary"].startswith("count=50"), r)
W.cases["C1"] = {"stage": "Closed"}
W.engine = [fw_alert(count=51, last=BASE + 80000)]
r = run()
check("T8 imported alert with a closed case counts as closed", len(r["recreated"]) == 1, r)
x2 = alerts_for("1.2.3.4")[-1]
x2["stage"] = "Imported"
r = run()
check("T8 imported alert without a case id is a visible error, nothing written",
      any("cannot determine alert state" in e for e in r["errors"]) and len(alerts_for("1.2.3.4")) == 2, r)

# T9 title bound
reset()
agents = tuple(("HOST-%03d" % i, 100 - i) for i in range(60))
W.engine = [fw_alert(agent=agents)]
run()
t = alerts_for("1.2.3.4")[0]["title"]
check("T9 title stays within 256 bytes, keeps the first host, shows how many were cut",
      len(t.encode()) <= 256 and "HOST-000" in t and re.search(r" \+\d+\)$", t), t)

# T10 details bound (2 KB combined), newest alarm ids and most frequent values survive
reset()
many = lambda p, n: [("%s-%03d-" % (p, i) + "x" * 40, 1) for i in range(n)]
W.engine = [eng("E1", "ioc-domain-t1", "big.example", 500, BASE, BASE + 9, agent=(("CLT601", 500),),
                rule=[("100322", 500)], query=many("q", 50), kind=[("suffix", 400), ("exact", 100)],
                ids=[("17921%05d.1" % (99999 - i), 1) for i in range(50)])]
run()
desc = alerts_for("big.example")[0]["description"]
block = desc.split("**Details**\n\n", 1)[1].split("\n\n**MISP context**")[0]
check("T10 details block within 2 KB", len(block.encode()) <= 2048, len(block.encode()))
check("T10 newest alarm id kept, oldest dropped", "1792199999.1" in block and "1792150000.1" not in block)
check("T10 short important lists kept whole", "- Match kind: suffix (400), exact (100)" in block and "- Reported by: CLT601 (500)" in block)

# T11 indexer errors are visible
reset()
W.engine, W.engine_status = [fw_alert()], 403
r = run()
check("T11 403 from the alerting API is a visible error, nothing written",
      sum("alerting query failed" in e for e in r["errors"]) == 2 and W.alerts == {}, r)
reset()
W.engine, W.engine_total = [fw_alert()], 700
r = run()
check("T11 truncated alert list is a visible error, the readable part is still processed",
      any("truncated" in e for e in r["errors"]) and len(W.alerts) == 1, r)
reset()
W.engine = [eng("E1", "ioc-fw-dst-t1", "1.2.3.4", 1, BASE, BASE)]
W.engine[0]["agg_alert_content"]["bucket_keys"] = []
r = run()
check("T11 engine alert without bucket key is a visible error", any("without bucket key" in e for e in r["errors"]) and W.alerts == {}, r)
reset()
r = run()
check("T11 no active alerts: no errors, nothing written", r["errors"] == [] and W.alerts == {} and r["alerts_seen"] == 0, r)

# T12 dry run
reset()
W.engine = [fw_alert()]
r = run(dry=True)
check("T12 dry run writes nothing but plans the alert", W.alerts == {} and r["plan"]["E1"]["action"] == "create" and r["plan"]["E1"]["title"].startswith("Threat Activity Detected (1.2.3.4"), r)
run()
W.engine = [fw_alert(count=99, last=BASE + 99000)]
r = run(dry=True)
check("T12 dry run on an existing alert plans an update and patches nothing", r["plan"]["E1"]["action"] == "update" and W.patches == [], r)

# T13 failed update is retried on the next run without any stored state
reset()
W.engine = [fw_alert()]
run()
W.engine = [fw_alert(count=60, last=BASE + 70000)]
W.patch_fail = True
r = run()
check("T13 failed update is a visible error", any("alert update failed" in e for e in r["errors"]), r)
W.patch_fail = False
r = run()
check("T13 next run applies it", len(r["updated"]) == 1 and alerts_for("1.2.3.4")[0]["summary"].startswith("count=60"), r)

# T15 acknowledged alerts keep being mirrored (analyst working on it does not stop the updates)
reset()
W.engine = [fw_alert("E1")]
run()
W.engine = [fw_alert("E1", count=47, last=BASE + 80000, state="ACKNOWLEDGED")]
r = run()
a = alerts_for("1.2.3.4")[0]
check("T15 acknowledged engine alert is still read and the TheHive alert updated",
      len(r["updated"]) == 1 and a["summary"].startswith("count=47") and "state ACKNOWLEDGED" in a["description"] and len(W.alerts) == 1, r)
check("T15 no new alert for the same engine alert after acknowledgement", len(alerts_for("1.2.3.4")) == 1)
reset()
W.engine = [fw_alert("E5", state="ACKNOWLEDGED")]
r = run()
check("T15 an acknowledged alert that has no TheHive alert yet is created", len(r["created"]) == 1, r)

# T16 the ACKNOWLEDGED query failing must not stop the ACTIVE work
reset()
W.engine = [fw_alert("E1")]
W.state_status = {"ACKNOWLEDGED": 400}
r = run()
check("T16 failed ACKNOWLEDGED query is a visible error, ACTIVE alerts are still written",
      any("ACKNOWLEDGED" in e and "alerting query failed" in e for e in r["errors"]) and len(W.alerts) == 1, r)
reset()
W.engine = [fw_alert("E1")]
W.state_status = {"ACTIVE": 403}
r = run()
check("T16 failed ACTIVE query is a visible error with the role hint", any("ACTIVE" in e and "alerting_read_access" in e for e in r["errors"]), r)

# T17 a server that ignores the state filter must not double the work or leak other states
reset()
W.engine = [fw_alert("E1"), fw_alert("E9", state="COMPLETED"), fw_alert("E8", state="DELETED"), fw_alert("E7", key="5.6.7.8", state="ACKNOWLEDGED")]
W.ignore_state_param = True
r = run()
check("T17 each engine alert is processed once, COMPLETED/DELETED ignored", len(W.alerts) == 2 and r["alerts_seen"] == 4 and r["ignored_state"] == 2, r)


# M1 MISP context is added to the alert description, queried like the list sync does
reset()
W.engine = [fw_alert("E1")]
r = run()
d = alerts_for("1.2.3.4")[0]["description"]
body, auth = W.misp_requests[0]
check("M1 query: indicator, IDS flag, published, decay overrides and score requested",
      body.get("value") == "1.2.3.4" and body.get("to_ids") == 1 and body.get("published") == 1 and body.get("includeDecayScore") == 1
      and body.get("modelOverrides") == {"threshold": 10, "lifetime": 365} and body.get("includeEventTags") == 1 and body.get("returnFormat") == "json", body)
check("M1 MISP key sent as the Authorization header", auth == "MISPKEY", auth)
ctxlines = d.split("\n\n**MISP context**", 1)[1].splitlines() if "**MISP context**" in d else []
check("M1 context section present and last in the description", "**MISP context** (live MISP query: published events, IDS flag)" in d and d.rstrip().endswith(ctxlines[-1] if ctxlines else "?"), d[-300:])
for line in ("- Events: #4935 Other event (soc.dev, 2026-06-22, analysis completed); #2258 TheHive Test (soc.dev, 2026-06-22, analysis completed)",
             "- Attributes: ip-dst (2), ip-src (1) | Category: Network activity",
             "- Tags: tlp:white",
             "- Decay (NIDS Simple Decaying Model, lifetime 365, threshold 10): best score 34.20; not decayed in 2 of 3 attributes"):
    check("M1 line: " + line[:60], line in d.splitlines(), d)
check("M1 event links", "/events/view/4935" in d and "/events/view/2258" in d, d)
check("M1 plan reports the MISP result", r["plan"]["E1"]["misp"] == {"status": "ok", "attributes": 3}, r["plan"])
check("M1 no secrets in the output", "MISPKEY" not in json.dumps(r))

# M2 context text is untrusted: markup, links and control characters are neutralised
reset()
W.engine = [fw_alert("E1")]
W.misp_fn = lambda v: [mattr("1", "ip-dst", "7", "<b>x</b> [click](http://evil.example)\nsecond `line` www.bad.example ftp://f.example",
                             org="o<rg>", comment="see [this](HTTPS://e.example)", tags=("a[b]",))]
run()
d = alerts_for("1.2.3.4")[0]["description"]
sec = d.split("**MISP context**", 1)[1]
check("M2 no HTML, backticks or Markdown link syntax from MISP text",
      "<" not in sec and ">" not in sec and "`" not in sec and "](" not in sec and sec.count("[") == sec.count("[.]"), sec)
check("M2 links are defanged, nothing clickable comes from MISP text",
      "http://evil" not in sec and "ftp://" not in sec and "HTTPS://" not in sec and "www.bad" not in sec
      and "hxxp://evil.example" in sec and "hxxpS://e.example" in sec and "www[.]bad.example" in sec, sec)
check("M2 the text itself survives, on one line",
      "#7 bx/b (click)(hxxp://evil.example) second line www[.]bad.example fxp://f.example (org, 2026-06-22, analysis completed)" in sec, sec)

# M3 no current MISP record
reset()
W.engine = [fw_alert("E1")]
W.misp_fn = lambda v: []
r = run()
d = alerts_for("1.2.3.4")[0]["description"]
check("M3 empty result is stated, not hidden", "- No current MISP record matches this value" in d and r["plan"]["E1"]["misp"]["attributes"] == 0, d[-200:])

# M4 MISP failing: a new alert is still written; an existing context section is never erased
reset()
W.engine = [fw_alert("E1")]
W.misp_status = 500
r = run()
a = alerts_for("1.2.3.4")[0]
check("M4 create while MISP is down: alert written without the section, error visible",
      len(r["created"]) == 1 and "**MISP context**" not in a["description"] and any("misp query failed (status 500" in e for e in r["errors"]) and r["plan"]["E1"]["misp"]["status"] == "unavailable", r)
W.misp_status = 200
r = run()
check("M4 MISP back: the section is added on the next run", "**MISP context**" in alerts_for("1.2.3.4")[0]["description"] and r["errors"] == [], r)
good = alerts_for("1.2.3.4")[0]["description"].split("\n\n**MISP context**", 1)[1]
W.misp_status = 500
W.engine = [fw_alert("E1", count=60, last=BASE + 90000)]
r = run()
d = alerts_for("1.2.3.4")[0]["description"]
check("M4 update while MISP is down: engine fields refresh, the old context section is kept verbatim",
      "Alarms in the monitor window: 60" in d and d.endswith(good) and any("misp query failed" in e for e in r["errors"]), d[-200:])

# M5 network failure (nothing listening) is an error entry, not a crash
reset()
W.engine = [fw_alert("E1")]
r = run(misp_url="http://127.0.0.1:9")
check("M5 MISP unreachable: alert still written, error names the failure type",
      len(r["created"]) == 1 and any("misp query failed (" in e and "status" not in e for e in r["errors"]), r)

# M6 MISP credentials missing: one visible error, alerts still written
reset()
W.engine = [fw_alert("E1"), fw_alert("E2", key="5.6.7.8")]
no_cred = SRC.replace('MISP_NODE = "misp_key"', 'MISP_NODE = "http_9"')
r = run(src=no_cred)
check("M6 missing MISP credentials: one error, both alerts written, MISP never called",
      sum("misp credentials not found" in e for e in r["errors"]) == 1 and len(W.alerts) == 2 and W.misp_requests == [], r)

# M7 context stays within 2 KB with many events and tags
reset()
W.engine = [fw_alert("E1")]
W.misp_fn = lambda v: [mattr(str(i), "ip-dst", str(1000 + i), "event %d " % i + "x" * 100, tags=tuple("tag-%d-%s" % (i, "y" * 40) for i in range(5)),
                             comment="comment %d" % i) for i in range(60)]
run()
d = alerts_for("1.2.3.4")[0]["description"]
sec = "**MISP context**" + d.split("**MISP context**", 1)[1]
check("M7 context bounded to 2 KB, newest events first, cut is announced",
      len(sec.encode()) <= 2048 and "#1059" in sec and re.search(r"\+\d+ more", sec), (len(sec.encode()), sec[:300]))

# M8 closed alerts without new activity cost no MISP query
reset()
W.engine = [fw_alert("E1")]
run()
alerts_for("1.2.3.4")[0]["stage"] = "Closed"
W.misp_requests.clear()
r = run()
check("M8 skipped closed alert: no MISP query", r["skipped_closed"] == ["E1"] and W.misp_requests == [], r)
W.engine = [fw_alert("E1", count=70, last=BASE + 99000)]
r = run()
check("M8 recreated alert gets its own context", len(r["recreated"]) == 1 and "**MISP context**" in alerts_for("1.2.3.4")[1]["description"] and len(W.misp_requests) == 1, r)

# M9 dry run: MISP is read, nothing is written
reset()
W.engine = [fw_alert("E1")]
r = run(dry=True)
check("M9 dry run queries MISP read-only and plans the context", W.alerts == {} and len(W.misp_requests) == 1 and r["plan"]["E1"]["misp"]["status"] == "ok", r)

# M10 decay agrees with the overrides: an attribute for another model never counts
reset()
W.engine = [fw_alert("E1")]
W.misp_fn = lambda v: [mattr("1", "ip-dst", "7", "e", decayed=True, score=0.3, model_id="2")]
run()
d = alerts_for("1.2.3.4")[0]["description"]
check("M10 only the configured decaying model is reported", "- Decay (" not in d, d[-300:])


# M11 a rejected key is diagnosable from the output without revealing the key
reset()
W.engine = [fw_alert("E1")]
W.misp_status = 403
r = run()
e = next((e for e in r["errors"] if "misp query failed" in e), "")
check("M11 error carries MISP's own message and the shape of the key, never the key",
      "status 403" in e and "Authentication failed" in e and "Authorization length 7" in e and "MISPKEY" not in json.dumps(r), r["errors"])
check("M11 the output names the credential node in use", r.get("misp_node") == "misp_key", r.get("misp_node"))
bad_key = SRC.replace('"Authorization: MISPKEY"', '"Authorization: MISPKEY"')
class SdkBadKey(Sdk):
    def __init__(self):
        super().__init__()
        for a in self.full_execution["workflow"]["actions"]:
            if a["label"] == "misp_key":
                a["parameters"][0]["value"] = 'Authorization: "MISPKEY" '
_orig_sdk = Sdk
Sdk = SdkBadKey
r = run()
Sdk = _orig_sdk
e = next((e for e in r["errors"] if "misp query failed" in e), "")
check("M11 a quoted key is flagged in the error text", "has quote" in e and "MISPKEY" not in e, r["errors"])

# T14 hygiene
reset()
W.engine = [fw_alert()]
r = run()
text = json.dumps(r)
check("T14 output carries no credentials", "Bearer" not in text and "MISPKEY" not in text and '"p"' not in text and "password" not in text.lower(), text[:200])
check("T14 no comment endpoint, no case-folding calls, no cache use, no secrets in the code",
      not re.search(r"/comment|\.lower\(|\.upper\(|casefold|get_cache|set_cache|api[_-]?key\s*=", SRC), "")
check("T14 DRY_RUN ships as True", SRC.count("DRY_RUN = True") == 1)
check("T14 only GET to the alerting API, ACTIVE and ACKNOWLEDGED requested", all(g.startswith("/_plugins/_alerting/monitors/alerts?") and ("alertState=ACTIVE" in g or "alertState=ACKNOWLEDGED" in g) for g in W.gets) and len(W.gets) == 2, W.gets)

# ---------------------------------------------------------------------------
# H: hash monitors (v1.4)
# ---------------------------------------------------------------------------
H256 = "15cd209c995b7d3009c91ca40892d5b8f1fb162f3e5f10716642ea278e8e0d7b"
HMD5 = "040194d8b98280c088c5b435eda3dd1f"
HSHA1 = "a80c0c7fa18b61b33f34ebdfa6b5927dc6344fa8"
HIMP = "f34d5f2d4577ed6d9ceec516c1f5a744"   # an import hash value; no monitor handles it
IMG = "C:\\Windows\\System32\\cmd.exe"
PAR = "C:\\Program Files (x86)\\ossec-agent\\wazuh-agent.exe"


def hash_alert(aid, monitor, key, count=59, last=BASE + 5000, agent=(("CLT601", 59),), state="ACTIVE", **extra):
    lists = dict(rule=[("92052", count)], event=[("1", count)], image=[(IMG, count)], parent=[(PAR, count)],
                 ids=[("1792499837.43550994", 1), ("1792499320.43086261", 1)])
    lists.update(extra)
    return eng(aid, monitor, key, count, BASE, last, agent=agent, state=state, **lists)


# H1 a SHA256 alert end to end
reset()
W.engine = [hash_alert("H1", "ioc-hash-sha256-t1", H256)]
r = run()
a = alerts_for(H256)[0] if alerts_for(H256) else {}
check("H1 one alert created, no errors", len(r["created"]) == 1 and r["errors"] == [], r)
check("H1 title keeps the pattern; the indicator is the full hash",
      a.get("title") == "Threat Activity Detected (%s, misp-hash-t1, CLT601)" % H256, a.get("title"))
check("H1 observable is the hash with type hash", [(o["dataType"], o["data"]) for o in a.get("observables", [])] == [("hash", H256)], a.get("observables"))
check("H1 tags carry indicator, engine alert, monitor and hash type",
      {"ioc:" + H256, "engine-alert:H1", "monitor:ioc-hash-sha256-t1", "hash-type:sha256"} <= set(a.get("tags", [])), a.get("tags"))
check("H1 the observable carries the hash type tag too", "hash-type:sha256" in (a.get("observables") or [{}])[0].get("tags", []), a.get("observables"))
check("H1 sourceRef is the engine alert id, date the first seen", a.get("sourceRef") == "H1" and a.get("date") == BASE, a)
d = a.get("description", "")
check("H1 description header names the hash type and the list",
      d.splitlines()[0] == "**Threat Activity Detected** | SHA256 hash `%s` | source misp-hash-t1" % H256 if d else False, d[:200])
for line in ("- Process: " + IMG + " (59)", "- Parent process: " + PAR + " (59)", "- Event ID: 1 (59)",
             "- Reported by: CLT601 (59)", "- Rules: 92052 (59)", "- Match side: SHA256 (Sysmon hashes field)",
             "- Alarm IDs (latest 2): 1792499837.43550994, 1792499320.43086261"):
    check("H1 description line: " + line[:50], line in d.splitlines(), d)
check("H1 nothing written to comments", W.comments == [])

# H2 every hash monitor is accepted and labelled
for mon, htype, key, label in (("ioc-hash-sha256-t1", "sha256", H256, "SHA256 hash"), ("ioc-hash-md5-t1", "md5", HMD5, "MD5 hash"),
                               ("ioc-hash-sha1-t1", "sha1", HSHA1, "SHA1 hash")):
    reset()
    W.engine = [hash_alert("X", mon, key)]
    r = run()
    al = alerts_for(key)
    ok = len(al) == 1 and r["ignored_monitor"] == 0 and r["errors"] == []
    check("H2 %s: accepted, one alert, no errors" % mon, ok, r)
    if al:
        a = al[0]
        check("H2 %s: hash-type tag and observable type" % mon, "hash-type:" + htype in a["tags"] and a["observables"][0]["dataType"] == "hash", a["tags"])
        check("H2 %s: header label and list" % mon, ("| %s `%s` | source misp-hash-t1" % (label, key)) in a["description"].splitlines()[0], a["description"][:160])
        check("H2 %s: no other hash type tag" % mon, [t for t in a["tags"] if t.startswith("hash-type:")] == ["hash-type:" + htype], a["tags"])

# H3 IP and domain alerts are unchanged: no hash tag, no hash-only detail lines
reset()
W.engine = [fw_alert(), eng("E2", "ioc-domain-t1", "ioc-test.example", 3, BASE, BASE + 1000, agent=(("CLT601", 3),), rule=[("100322", 3)])]
run()
for ind in ("1.2.3.4", "ioc-test.example"):
    a = alerts_for(ind)[0]
    check("H3 %s alert has no hash tag and no hash-only lines" % ind,
          not any(t.startswith("hash-type:") for t in a["tags"]) and "Parent process" not in a["description"] and "Event ID" not in a["description"]
          and not any(t.startswith("hash-type:") for t in a["observables"][0]["tags"]), a["tags"])

# H4 the title stays within 256 bytes and keeps the whole hash
reset()
agents = tuple(("HOST-%03d" % i, 100 - i) for i in range(60))
W.engine = [hash_alert("H4", "ioc-hash-sha256-t1", H256, agent=agents)]
run()
t = alerts_for(H256)[0]["title"]
check("H4 hash title within 256 bytes, whole hash kept, cut announced", len(t.encode()) <= 256 and H256 in t and "HOST-000" in t and re.search(r" \+\d+\)$", t), t)

# H5 MISP context for a hash: queried by value, no decay line when MISP gives no decay score
reset()
W.engine = [hash_alert("H5", "ioc-hash-sha256-t1", H256)]
W.misp_fn = lambda v: [dict(mattr("9", "sha256", "31", "Malware sample", cat="Payload delivery"), decay_score=[]),
                       dict(mattr("10", "filename|sha256", "31", "Malware sample", cat="Payload delivery"), decay_score=[])]
r = run()
d = alerts_for(H256)[0]["description"]
check("H5 MISP is queried with the hash value", len(W.misp_requests) == 1 and W.misp_requests[0][0]["value"] == H256, W.misp_requests)
check("H5 context lists the attribute types of the hash", "- Attributes: sha256 (1), filename|sha256 (1) | Category: Payload delivery" in d.splitlines(), d[-300:])
check("H5 no decay line when no decay score is returned", "- Decay (" not in d and r["plan"]["H5"]["misp"] == {"status": "ok", "attributes": 2}, r["plan"])

# H6 an unknown hash monitor is ignored
reset()
W.engine = [hash_alert("U1", "ioc-hash-sha512-t1", "a" * 128), hash_alert("U2", "ioc-hash-sha256-t1-test", H256)]
r = run()
check("H6 monitors outside the allow-list are ignored, nothing written", r["ignored_monitor"] == 2 and W.alerts == {} and r["errors"] == [], r)

# H7 closed hash alert: new activity opens a new alert that keeps the hash type
reset()
W.engine = [hash_alert("H7", "ioc-hash-sha256-t1", H256)]
run()
alerts_for(H256)[0]["stage"] = "Closed"
W.engine = [hash_alert("H7", "ioc-hash-sha256-t1", H256, count=60, last=BASE + 90000)]
r = run()
al = alerts_for(H256)
check("H7 recreated hash alert keeps the hash type and the engine id", len(al) == 2 and len(r["recreated"]) == 1
      and "hash-type:sha256" in al[1]["tags"] and al[1]["sourceRef"] == "H7|%d" % (BASE + 90000), [a["tags"] for a in al])

# H8 details stay within 2 KB for a hash alert with many processes
reset()
many = lambda p, n: [("%s-%03d-" % (p, i) + "x" * 40, 1) for i in range(n)]
W.engine = [hash_alert("H8", "ioc-hash-sha256-t1", H256, image=many("img", 20), parent=many("par", 20))]
run()
desc = alerts_for(H256)[0]["description"]
block = desc.split("**Details**\n\n", 1)[1].split("\n\n**MISP context**")[0]
check("H8 hash details block within 2 KB", len(block.encode()) <= 2048, len(block.encode()))
check("H8 short lists survive the cut", "- Event ID: 1 (59)" in block and "- Reported by: CLT601 (59)" in block and "- Rules: 92052 (59)" in block, block[:300])

# H9 an engine alert without the hash-only sub-aggregations adds no empty lines
reset()
W.engine = [eng("H9", "ioc-hash-md5-t1", HMD5, 2, BASE, BASE + 5, agent=(("SRV202", 2),), rule=[("100170", 2)])]
run()
d = alerts_for(HMD5)[0]["description"]
check("H9 missing sub-aggregations produce no Parent process or Event ID line", "Parent process" not in d and "Event ID" not in d and "- Rules: 100170 (2)" in d.splitlines(), d)

# H10 dry run plans the hash alert and writes nothing
reset()
W.engine = [hash_alert("H10", "ioc-hash-md5-t1", HMD5)]
r = run(dry=True)
check("H10 dry run plans the md5 alert, writes nothing",
      W.alerts == {} and r["plan"]["H10"]["action"] == "create" and r["plan"]["H10"]["indicator"] == HMD5
      and r["plan"]["H10"]["title"] == "Threat Activity Detected (%s, misp-hash-t1, CLT601)" % HMD5, r)

# H11 version and configuration
check("H11 version is 1.5 and exactly three hash monitors are configured with the same list",
      'VERSION = "1.5"' in SRC and len(re.findall(r'"source": "misp-hash-t1"', SRC)) == 3 and len(re.findall(r'"htype": "', SRC)) == 3, "")

# H12 IMPHASH is not mirrored: an engine alert of an imphash monitor is ignored, nothing is written
reset()
W.engine = [hash_alert("I1", "ioc-hash-imphash-t1", HIMP)]
r = run()
check("H12 an imphash monitor alert is ignored, nothing written, no error",
      r["ignored_monitor"] == 1 and W.alerts == {} and r["errors"] == [] and "imphash" not in SRC, r)

print("\n%d checks, %d failed" % (count[0], len(fails)))
sys.exit(1 if fails else 0)
