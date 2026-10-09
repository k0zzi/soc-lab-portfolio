"""Tests for the Shuffle 'bucket' node (bucket.py) and the TheHive request body template.

The node runs inside Shuffle with a `self` object; here it is executed with a fake one.
Run: python3 test_bucket.py   (standard library only)
"""
import contextlib
import io
import json
import os
import re
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
CODE = open(os.path.join(HERE, "..", "bucket.py"), encoding="utf-8").read()
BODY = open(os.path.join(HERE, "..", "thehive-alert-body.json"), encoding="utf-8").read().strip()

fails = []


def check(name, cond, info=""):
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(info)[:400]) if (info and not cond) else ""))
    if not cond:
        fails.append(name)


class FakeSelf:
    def __init__(self, arg):
        self.full_execution = {"execution_argument": arg}


def run_node(arg):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        exec(compile(CODE, "bucket", "exec"), {"self": FakeSelf(arg)})
    return json.loads(buf.getvalue().strip())


def render(msg):
    """Shuffle substitutes $bucket.message.<key> in the HTTP node body."""
    out = BODY
    for key, value in msg.items():
        out = out.replace("$bucket.message.%s" % key, value)
    return out


CDB = {"rule_id": "100320", "id": "1791396635.59416101",
       "all_fields": {"id": "1791396635.59416101", "agent": {"name": "CLT601"},
                      "timestamp": "2026-10-07T21:10:35.475+0300",
                      "data": {"win": {"eventdata": {"queryName": "ioc-test-b2.example"}}}}}
SCRIPT = {"rule_id": "100322", "id": "1791396643.59430692",
          "all_fields": {"agent": {"name": "CLT601"}, "timestamp": "2026-10-07T21:10:43.354+0300",
                         "data": {"misp_domain": {"query": "WWW.IOC-TEST-B1.EXAMPLE.",
                                                  "normalized": "www.ioc-test-b1.example",
                                                  "matched": "ioc-test-b1.example",
                                                  "match_kind": "suffix", "entry_type": "domain"}}}}

a, b = run_node(CDB), run_node(SCRIPT)
check("one TheHive alert per Wazuh alert: sourceRef is the Wazuh alert id (CDB alert)", a["source_ref"] == "1791396635.59416101", a)
check("sourceRef is the Wazuh alert id (custom-misp-domain alert)", b["source_ref"] == "1791396643.59430692", b)
check("two alerts for the same indicator get different sourceRefs (nothing is deduplicated)",
      run_node(SCRIPT)["source_ref"] != run_node({**SCRIPT, "id": "1791396700.1"})["source_ref"])
check("the same Wazuh alert delivered twice gets the same sourceRef (TheHive refuses the duplicate)",
      run_node(SCRIPT)["source_ref"] == run_node(SCRIPT)["source_ref"])
expected_ms = int(datetime(2026, 10, 7, 21, 10, 43, 354000, tzinfo=timezone(timedelta(hours=3))).timestamp() * 1000)
check("date is the Wazuh alert's own timestamp in epoch milliseconds (UTC offset honoured)",
      b["date_ms"] == str(expected_ms) and expected_ms == 1791396643354, (b["date_ms"], expected_ms))
check("the observable is the MATCHED indicator, so every occurrence shares it (TheHive similarity)",
      a["observable"] == "ioc-test-b2.example" and b["observable"] == "ioc-test-b1.example")
check("the queried name stays in title and description", "www.ioc-test-b1.example" in b["title"] and "WWW.IOC-TEST-B1.EXAMPLE." in b["description"], b)
check("description names rule id, match kind and the Wazuh alert id",
      "rule 100322" in b["description"] and "(suffix match)" in b["description"] and "1791396643.59430692" in b["description"], b)

for label, msg in (("CDB alert", a), ("custom-misp-domain alert", b)):
    try:
        json.loads(render(msg))
        good = True
    except ValueError as exc:
        good = False
        print(exc)
    check("request body is valid JSON after substitution (%s)" % label, good)
j = json.loads(render(b))
check("body: date is a JSON number, one domain observable flagged ioc and sighted, medium severity",
      isinstance(j["date"], int) and j["date"] == 1791396643354 and j["severity"] == 2
      and j["observables"][0]["dataType"] == "domain" and j["observables"][0]["ioc"] is True
      and j["observables"][0]["sighted"] is True and j["sourceRef"] == "1791396643.59430692", j)
check("body template contains no backslash (they break Shuffle's JSON handling)", "\\" not in BODY)

# payload shapes Shuffle may hand over
for label, arg in (("dict", CDB), ("JSON string", json.dumps(CDB)), ("double-encoded JSON string", json.dumps(json.dumps(CDB))),
                   ("inside a wrapper dict", {"execution_argument": CDB, "x": 1}),
                   ("wrapper holding a JSON string", {"body": json.dumps(CDB)}),
                   ("inside a list", [{"x": 1}, CDB]),
                   ("all_fields content passed directly", CDB["all_fields"])):
    check("payload shape: %s" % label, run_node(arg)["observable"] == "ioc-test-b2.example", run_node(arg))

# robustness
empty = run_node({})
check("an empty payload does not crash and says what it received", set(empty) == {"diag", "source_ref", "title", "description", "observable", "date_ms"} and "name_found=False" in empty["diag"], empty)
garbage = run_node("hello this is not json")
check("garbage text: no crash, diag shows the start of the input", "preview=hello this is not json" in garbage["diag"], garbage)
nots = run_node({"rule_id": "100320", "all_fields": {"agent": {"name": "H"}, "data": {"win": {"eventdata": {"queryName": "x.example"}}}}})
check("no timestamp and no id: date falls back to now, sourceRef to a unique value",
      nots["date_ms"].isdigit() and len(nots["date_ms"]) == 13 and nots["source_ref"].startswith("x.example|H|"), nots)
check("fold is ASCII only and one trailing dot is removed when 'normalized' is missing",
      run_node({"rule_id": "1", "all_fields": {"agent": {"name": "H"}, "data": {"win": {"eventdata": {"queryName": "EVIL.COM."}}}}})["observable"] == "evil.com")
nonascii = run_node({"rule_id": "1", "id": "1.1", "all_fields": {"agent": {"name": "H"}, "timestamp": "2026-10-07T21:10:43.354+0300",
                     "data": {"misp_domain": {"query": "\u0130OC-TEST.EXAMPLE", "normalized": "xn--oc-test-d9e.example", "matched": "xn--oc-test-d9e.example"}}}})
check("a non-ASCII queried name cannot leak into the request: observable stays ASCII, raw name shown with a placeholder",
      nonascii["observable"].isascii() and "?OC-TEST.EXAMPLE" in nonascii["description"], nonascii)
hostile = run_node({"rule_id": "1", "id": 'a"b$c', "all_fields": {"agent": {"name": 'CLT"601\\$x\n'}, "timestamp": "garbage",
                   "data": {"misp_domain": {"query": 'a"b\\c$d\ne.example', "normalized": 'a"b\\c$d.example', "matched": "x$y.example", "match_kind": 'ex"act'}}}})
check("no value contains a quote, backslash, dollar sign or control character", all(not re.search(r'["\\$\n\r\t]', v) for k, v in hostile.items() if k != "diag"), hostile)
try:
    json.loads(render(hostile))
    good = True
except ValueError:
    good = False
check("hostile characters and a garbage timestamp cannot break the request body", good and hostile["date_ms"].isdigit())
check("long values are truncated", len(run_node({"rule_id": "1", "all_fields": {"agent": {"name": "h" * 500}, "data": {"win": {"eventdata": {"queryName": "a" * 400 + ".example"}}}}})["title"]) <= 250)

print("\nFAILED:" if fails else "\nALL PASSED", fails)
raise SystemExit(1 if fails else 0)
