import json, os, random, shutil, socket, stat, string, subprocess, sys, tempfile, time

INSTALLER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "install_domain_integration.py")
STANDALONE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "custom-misp-domain")

CONF = """<ossec_config>
  <global><jsonout_output>yes</jsonout_output></global>
  <ruleset>
    <list>etc/lists/misp-domain-t1</list>
  </ruleset>
  <integration>
    <name>shuffle</name>
    <hook_url>http://10.1.30.11:3001/api/v1/hooks/webhook_SECRET</hook_url>
    <group>misp_ioc_t1</group>
  </integration>
</ossec_config>

<ossec_config>
  <localfile><location>/var/log/x</location></localfile>
</ossec_config>
"""
RULES = '<group name="local,">\n  <rule id="100160" level="3"><description>ATT&CK bare ampersand</description></rule>\n</group>'

T1 = """c2.badhost.net:hostname
evil.com:domain
ioc-test-a5-d.example:domain
legacy.example:
shared.example.org:domain
xn--bcher-kva.de:domain
"""
T2 = """ioc-test-a5-t2.example:domain
raw.example.org:domain
shared.example.org:hostname
"""

def mk_tree(t1=T1, t2=T2, typed=True):
    root = tempfile.mkdtemp() + "/ossec"
    for d in ("etc/rules", "etc/lists", "ruleset/rules", "integrations", "queue/sockets", "logs", "bin"):
        os.makedirs(root + "/" + d)
    open(root + "/etc/ossec.conf", "w").write(CONF); os.chmod(root + "/etc/ossec.conf", 0o660)
    open(root + "/etc/rules/local_rules.xml", "w").write(RULES); os.chmod(root + "/etc/rules/local_rules.xml", 0o640)
    open(root + "/ruleset/rules/0100.xml", "w").write('<group name="x"><rule id="100100" level="3"></rule></group>')
    if not typed:
        t1 = "".join(l.split(":")[0] + ":\n" for l in t1.splitlines()); t2 = "".join(l.split(":")[0] + ":\n" for l in t2.splitlines())
    open(root + "/etc/lists/misp-domain-t1", "w").write(t1)
    open(root + "/etc/lists/misp-domain-t2", "w").write(t2)
    fake = root + "/bin/wazuh-analysisd"
    open(fake, "w").write('#!/bin/sh\nif [ -f "%s/FAIL" ]; then echo "CRITICAL: Configuration error" >&2; exit 1; fi\nexit 0\n' % root)
    os.chmod(fake, 0o755)
    return root

def run_installer(root, *extra):
    p = subprocess.run([sys.executable, INSTALLER, "--ossec-root", root, "--backup-dir", root + "/../bak"] + list(extra), capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr

fails = []
def check(name, cond, info=""):
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(info)[:600]) if (info and not cond) else ""))
    if not cond: fails.append(name)

# ================= installer =================
root = mk_tree(); os.makedirs(root + "/../bak", exist_ok=True)
c0 = open(root + "/etc/ossec.conf", "rb").read(); r0 = open(root + "/etc/rules/local_rules.xml", "rb").read()
rc, out = run_installer(root, "--dry-run")
check("I1 dry-run rc=0, nothing changed", rc == 0 and open(root + "/etc/ossec.conf", "rb").read() == c0 and not os.path.exists(root + "/integrations/custom-misp-domain"), out)
rc, out = run_installer(root); print(out)
check("I2 install rc=0", rc == 0, out)
inst = root + "/integrations/custom-misp-domain"
check("I2 installed script is byte-identical to the standalone file", open(inst, "rb").read() == open(STANDALONE, "rb").read())
check("I2 script mode 750", stat.S_IMODE(os.stat(inst).st_mode) == 0o750)
conf = open(root + "/etc/ossec.conf").read()
check("I2 integration block once, inside the LAST ossec_config block", conf.count("custom-misp-domain") == 1 and conf.rfind("custom-misp-domain") > conf.find("</ossec_config>") and conf.index("custom-misp-domain") > conf.index("/var/log/x"), conf)
check("I2 block is filtered on rule 100160 with JSON format", "<rule_id>100160</rule_id>" in conf and "<alert_format>json</alert_format>" in conf)
check("I2 existing shuffle integration untouched", "webhook_SECRET" in conf and "misp_ioc_t1" in conf)
check("I2 local_rules: original is a prefix, new rules present", open(root + "/etc/rules/local_rules.xml").read().startswith(RULES) and all(('id="%s"' % i) in open(root + "/etc/rules/local_rules.xml").read() for i in ("100322", "100323", "100324")))
baks = os.listdir(root + "/../bak")
check("I2 backups are byte-identical to the originals", len(baks) == 2 and any(open(root + "/../bak/" + b, "rb").read() == c0 for b in baks) and any(open(root + "/../bak/" + b, "rb").read() == r0 for b in baks))
rc, out = run_installer(root)
check("I3 second install aborts, nothing changed", rc == 2 and "already" in out, out)
# rollback
rb = mk_tree(); os.makedirs(rb + "/../bak", exist_ok=True); open(rb + "/FAIL", "w").write("x")
cb = open(rb + "/etc/ossec.conf", "rb").read(); rrb = open(rb + "/etc/rules/local_rules.xml", "rb").read()
rc, out = run_installer(rb)
check("I4 failed analysisd -t: rc 3, files restored byte for byte, script removed", rc == 3 and open(rb + "/etc/ossec.conf", "rb").read() == cb and open(rb + "/etc/rules/local_rules.xml", "rb").read() == rrb and not os.path.exists(rb + "/integrations/custom-misp-domain"), out)
# collisions / preconditions
rcz = mk_tree(); os.makedirs(rcz + "/../bak", exist_ok=True); open(rcz + "/ruleset/rules/0200.xml", "w").write('<group name="y"><rule id="100323" level="3"></rule></group>')
rc, out = run_installer(rcz); check("I5 rule id collision aborts", rc == 2 and "100323 already used" in out, out)
ru = mk_tree(typed=False); os.makedirs(ru + "/../bak", exist_ok=True)
rc, out = run_installer(ru); check("I6 untyped (v0.4) lists abort with an explanation", rc == 2 and "name:domain" in out, out)
rn = mk_tree(); os.makedirs(rn + "/../bak", exist_ok=True); shutil.rmtree(rn + "/integrations")
rc, out = run_installer(rn); check("I7 missing integrations dir aborts", rc == 2 and "integrations directory missing" in out, out)

# ================= the script, installed by the installer =================
sockpath = root + "/queue/sockets/queue"
rx = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); rx.bind(sockpath); rx.settimeout(0.3)

def alert(query, agent=("007", "CLT601", "any"), extra=None):
    a = {"id": "1791300000.1", "rule": {"id": "100160", "level": 3},
         "agent": {"id": agent[0], "name": agent[1], "ip": agent[2]},
         "data": {"win": {"eventdata": {"queryName": query}}}}
    if extra is not None: a = extra
    return a

def fire(a, env=None, raw=None, receive=True):
    f = tempfile.mktemp(suffix=".json")
    open(f, "w", encoding="utf-8").write(raw if raw is not None else json.dumps(a))
    p = subprocess.run([sys.executable, inst, f, "key", "url"], capture_output=True, text=True, env=env)
    msgs = []
    if not receive:
        return p.returncode, msgs
    try:
        while True: msgs.append(rx.recv(65536).decode("utf-8"))
    except socket.timeout:
        pass
    return p.returncode, msgs

def parsed(msgs):
    assert len(msgs) == 1, msgs
    head, _, body = msgs[0].partition("->misp-domain:") if "->misp-domain:" in msgs[0] else ("", "", msgs[0].split("misp-domain:", 1)[1])
    return head, json.loads(body)

def expect(query, tier=None, matched=None, kind=None, typ=None, agent=("007", "CLT601", "any")):
    rc, msgs = fire(alert(query, agent))
    if tier is None:
        return rc == 0 and msgs == [], (rc, msgs)
    if rc != 0 or len(msgs) != 1: return False, (rc, msgs)
    head, body = parsed(msgs); m = body["misp_domain"]
    ok = (m["tier"] == tier and m["matched"] == matched and m["match_kind"] == kind and (typ is None or m["entry_type"] == typ) and m["query"] == query)
    return ok, (head, body)

cases = [
 ("S1 UPPER CASE exact (normalization; the CDB would miss it)", "EVIL.COM", ("t1", "evil.com", "exact", "domain")),
 ("S2 trailing dot", "evil.com.", ("t1", "evil.com", "exact", "domain")),
 ("S3 www. subdomain", "www.evil.com", ("t1", "evil.com", "suffix", "domain")),
 ("S4 deep subdomain", "a.b.deneme.evil.com", ("t1", "evil.com", "suffix", "domain")),
 ("S5 label boundary: notevil.com", "notevil.com", None),
 ("S5 label boundary: xevil.com", "xevil.com", None),
 ("S5 name continues: evil.com.attacker.net", "evil.com.attacker.net", None),
 ("S5 other TLD: evil.org", "evil.org", None),
 ("S5 bare TLD is never a parent: foo.com with only 'com' style", "com", None),
 ("S6 hostname entry, exact", "c2.badhost.net", ("t1", "c2.badhost.net", "exact", "hostname")),
 ("S6 hostname entry, subdomain (hostname = exact only)", "sub.c2.badhost.net", None),
 ("S6 hostname entry, parent", "badhost.net", None),
 ("S7 IDN upper case (BÜCHER.DE)", "B\u00dcCHER.DE", ("t1", "xn--bcher-kva.de", "exact", "domain")),
 ("S7 IDN subdomain", "www.b\u00fccher.de", ("t1", "xn--bcher-kva.de", "suffix", "domain")),
 ("S7 IDN already punycode, upper case", "XN--BCHER-KVA.DE", ("t1", "xn--bcher-kva.de", "exact", "domain")),
 ("S8 Turkish dotted I (U+0130) is a DIFFERENT name", "\u0130OC-TEST-A5-D.EXAMPLE", None),
 ("S8 Turkish dotless i (U+0131) is a DIFFERENT name", "\u0131oc-test-a5-d.example", None),
 ("S8 ASCII upper case of the same marker matches", "IOC-TEST-A5-D.EXAMPLE", ("t1", "ioc-test-a5-d.example", "exact", "domain")),
 ("S8 Cyrillic homograph does not match", "\u0435vil.com", None),
 ("S9 tier 1 wins when a name is in both tiers", "shared.example.org", ("t1", "shared.example.org", "exact", "domain")),
 ("S9 suffix: t1 domain entry beats t2 hostname entry", "www.shared.example.org", ("t1", "shared.example.org", "suffix", "domain")),
 ("S10 tier 2 exact", "raw.example.org", ("t2", "raw.example.org", "exact", "domain")),
 ("S10 tier 2 suffix", "www.raw.example.org", ("t2", "raw.example.org", "suffix", "domain")),
 ("S11 legacy entry without a type = exact only: exact", "legacy.example", ("t1", "legacy.example", "exact", "hostname")),
 ("S11 legacy entry without a type = exact only: subdomain", "www.legacy.example", None),
 ("S12 empty/odd names do nothing", "", None),
]
for label, q, exp in cases:
    ok, info = expect(q, *(exp or (None,)))
    check(label, ok, info)

rc, msgs = fire(alert("www.evil.com", agent=("007", "CLT601", "10.1.60.10")))
check("S13 agent attribution format: 1:[id] (name) ip->misp-domain:{json}", msgs and msgs[0].startswith("1:[007] (CLT601) 10.1.60.10->misp-domain:{"), msgs)
rc, msgs = fire(alert("www.evil.com", agent=("000", "ubuntu", "127.0.0.1")))
check("S13 manager events use 1:misp-domain:{json}", msgs and msgs[0].startswith("1:misp-domain:{"), msgs)
head, body = parsed(fire(alert("www.evil.com"))[1])
check("S13 payload has the fields the rules key on", body["integration"] == "custom-misp-domain" and set(body["misp_domain"]) >= {"tier", "query", "normalized", "matched", "match_kind", "entry_type", "source_rule", "source_alert"} and body["misp_domain"]["source_rule"] == "100160", body)
rc, msgs = fire(None, raw=json.dumps({"id": "1", "rule": {"id": "100160"}, "agent": {"id": "007", "name": "CLT601"}, "data": {}}))
check("S14 alert without queryName: nothing sent, rc 0", rc == 0 and msgs == [], (rc, msgs))
rc, msgs = fire(None, raw="this is not json")
check("S14 broken alert file: failure is REPORTED as an event (rule 100324), rc 0", rc == 0 and len(msgs) == 1 and "misp_domain_error" in msgs[0], (rc, msgs))
check("S14 failure also logged to integrations.log", "FAILED" in open(root + "/logs/integrations.log").read())
# missing list
os.rename(root + "/etc/lists/misp-domain-t2", root + "/etc/lists/_t2")
rc, msgs = fire(alert("www.evil.com"))
check("S15 missing list: reported as error event, not silent", rc == 0 and len(msgs) == 1 and "misp_domain_error" in msgs[0] and "No such file" in msgs[0], (rc, msgs))
os.rename(root + "/etc/lists/_t2", root + "/etc/lists/misp-domain-t2")
# socket gone
rx.close(); os.unlink(sockpath)
rc, msgs = fire(alert("www.evil.com"), receive=False)
check("S16 no socket: rc 1 and the double failure is logged (integratord will log an ERROR)", rc == 1 and "FAILED to report the failure" in open(root + "/logs/integrations.log").read(), rc)

# performance with a list of the real size
big = mk_tree(); os.makedirs(big + "/../bak", exist_ok=True)
random.seed(3)
names = sorted({"".join(random.choice(string.ascii_lowercase + string.digits) for _ in range(random.randint(5, 14))) + random.choice([".com", ".net", ".org", ".top", ".xyz"]) for _ in range(90000)})[:76620]
open(big + "/etc/lists/misp-domain-t1", "w").write("".join("%s:domain\n" % n for n in names))
rc, out = run_installer(big)
bsock = big + "/queue/sockets/queue"; brx = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM); brx.bind(bsock); brx.settimeout(1)
def timed(q):
    f = tempfile.mktemp(suffix=".json"); open(f, "w").write(json.dumps(alert(q)))
    t0 = time.time(); p = subprocess.run([sys.executable, big + "/integrations/custom-misp-domain", f], capture_output=True, text=True); dt = time.time() - t0
    try: m = brx.recv(65536).decode()
    except socket.timeout: m = None
    return dt, m, p.returncode
dt_miss, m, rc1 = timed("www.surely-not-listed-anywhere.example")
last = names[-1]; dt_hit, m2, rc2 = timed("deep.sub." + last.upper())
print("timing on a %d-entry list: miss %.3fs, hit on the LAST entry %.3fs (includes interpreter start)" % (len(names), dt_miss, dt_hit))
check("P1 76k-entry list: miss answers fast and sends nothing", rc1 == 0 and m is None and dt_miss < 0.5, dt_miss)
check("P1 76k-entry list: match on the last line found, suffix kind", rc2 == 0 and m2 and '"match_kind":"suffix"' in m2 and dt_hit < 0.5, (m2, dt_hit))

# language independence
import ast
src = open(STANDALONE).read()
tree = ast.parse(src)
calls = sorted({n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("lower", "upper", "casefold", "title", "swapcase", "capitalize", "setlocale", "getlocale", "getpreferredencoding")})
imports = sorted({a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names} | {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module})
check("L1 STATIC (AST, comments and docstrings ignored): no case-mapping or locale call anywhere in the integration", not calls and "locale" not in imports, (calls, imports))
check("L2 the integration imports only these standard-library modules", set(imports) <= {"json", "os", "socket", "string", "sys", "time"}, imports)

print("\nFAILED:" if fails else "\nALL PASSED", fails)

raise SystemExit(1 if fails else 0)
