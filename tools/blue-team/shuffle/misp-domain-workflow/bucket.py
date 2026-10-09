import json
import re
import string
from datetime import datetime, timezone

# Shuffle "execute_python" node, NAME IT: bucket (start node). One TheHive alert PER Wazuh alert.


def unwrap(value):
    depth = 0
    while isinstance(value, str) and depth < 4:
        text = value.strip()
        if not text or text[0] not in '{["':
            break
        try:
            value = json.loads(text)
        except ValueError:
            break
        depth += 1
    return value


def find_alert(value, depth=0):
    value = unwrap(value)
    if depth > 5:
        return None
    if isinstance(value, dict):
        if isinstance(unwrap(value.get("all_fields")), dict):
            return value
        for item in value.values():
            found = find_alert(item, depth + 1)
            if found is not None:
                return found
    elif isinstance(value, list):
        for item in value:
            found = find_alert(item, depth + 1)
            if found is not None:
                return found
    return None


def event_ms(ts):
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return int(datetime.strptime(str(ts), fmt).timestamp() * 1000)
        except ValueError:
            continue
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def clean(value, limit=200):
    return re.sub(r"[^A-Za-z0-9._:@|/ (),-]", "?", str(value))[:limit]


raw = self.full_execution["execution_argument"]
parsed = unwrap(raw)
alert = find_alert(parsed)
if alert is None:
    alert = parsed if isinstance(parsed, dict) else {}
fields = unwrap(alert.get("all_fields")) if alert.get("all_fields") else (
    alert if ("data" in alert or "agent" in alert) else {})
if not isinstance(fields, dict):
    fields = {}
data = fields.get("data", {}) or {}
md = data.get("misp_domain", {}) or {}
win = (data.get("win", {}) or {}).get("eventdata", {}) or {}

FOLD = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)   # RFC 4343: A-Z only
query = md.get("query") or win.get("queryName") or ""
normalized = md.get("normalized") or query.translate(FOLD)
if normalized.endswith("."):
    normalized = normalized[:-1]
matched = md.get("matched") or normalized
kind = md.get("match_kind") or "exact"
rule_id = str(alert.get("rule_id") or (fields.get("rule", {}) or {}).get("id", ""))
alert_id = str(alert.get("id") or fields.get("id", ""))
host = (fields.get("agent", {}) or {}).get("name", "") or "unknown"
ms = event_ms(fields.get("timestamp", ""))

diag = "input=%s len=%d top_keys=%s alert_found=%s name_found=%s" % (
    type(raw).__name__, len(str(raw)), ",".join(sorted(parsed.keys())[:12]) if isinstance(parsed, dict) else "-",
    bool(fields), bool(query))
if not query:
    diag += " preview=" + str(raw)[:200]

print(json.dumps({
    "diag": diag,
    # one TheHive alert per Wazuh alert: the Wazuh alert id is unique, a repeated delivery of the
    # same alert is refused by TheHive (400) instead of creating a duplicate
    "source_ref": clean(alert_id if alert_id else "%s|%s|%d" % (matched, host, ms)),
    "title": clean("MISP IOC match (tier 1, domain): %s from %s" % (normalized, host), 250),
    "description": clean("Wazuh rule %s matched a DNS query to the MISP indicator %s (%s match). "
                         "Queried name: %s. Wazuh alert id: %s" % (rule_id, matched, kind, query, alert_id), 600),
    "observable": clean(matched, 253),
    "date_ms": str(ms),
}))
