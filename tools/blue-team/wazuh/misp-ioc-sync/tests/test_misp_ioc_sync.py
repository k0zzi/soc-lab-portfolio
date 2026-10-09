import http.server, json, os, subprocess, sys, tempfile, threading, shutil, time, re, stat

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "misp_ioc_sync.py")
KEY = "TESTKEY"

BULK_IP = ["11.%d.%d.%d" % (a, b, c) for a in range(1, 4) for b in range(0, 10) for c in range(1, 11)]  # 300
BULK_DOM = ["host%04d.bad-example.net" % i for i in range(700)]                                       # 700 t1 domains

def make_data(dom_t1=None, dom_t2=None):
    d = {}
    d[("ip-dst", 1)] = BULK_IP + ["10.1.2.3", "11.200.0.0/16", "2606:4700::1111", "203.0.113.9"]
    d[("ip-src", 1)] = ["11.50.0.1"]
    d[("ip-dst|port", 1)] = ["11.60.0.1|443"]
    d[("ip-src|port", 1)] = []
    d[("ip-dst", 0)] = ["11.70.0.1", "11.1.0.1"]
    d[("ip-src", 0)] = []; d[("ip-dst|port", 0)] = []; d[("ip-src|port", 0)] = []
    d[("domain", 1)] = (dom_t1 if dom_t1 is not None else BULK_DOM) + [
        "Evil.Example.COM", "evil.example.com.", "*.wild.org", "1.2.3.4", "localhost", "host.soc.dev",
        "bücher.de", "bad_chars!.com", "popular-site.com", "dual.example.net"]
    d[("hostname", 1)] = ["cdn.evil.example.com", "dual.example.net"]
    d[("domain|ip", 1)] = ["pair.example.org|1.2.3.4"]
    d[("hostname|port", 1)] = ["h.example.net|443"]
    d[("domain", 0)] = (dom_t2 if dom_t2 is not None else ["raw%03d.example.org" % i for i in range(194)]) + ["evil.example.com"]
    d[("hostname", 0)] = []; d[("domain|ip", 0)] = []; d[("hostname|port", 0)] = []
    return d

WARNLIST = {"popular-site.com"}

class H(http.server.BaseHTTPRequestHandler):
    data = {}
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); p = json.loads(self.rfile.read(n))
        if self.headers.get("Authorization") != KEY:
            self.send_response(403); self.end_headers(); self.wfile.write(b"denied"); return
        assert p["to_ids"] == 1 and p["excludeDecayed"] == 1 and p["modelOverrides"] == {"threshold": 10, "lifetime": 365}
        lines = list(H.data.get((p["type"], p["published"]), []))
        if p.get("enforceWarninglist"):
            lines = [l for l in lines if l.split("|")[0].lower() not in WARNLIST]
        self.send_response(200); self.end_headers(); self.wfile.write("\n".join(lines).encode())

srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
URL = "http://127.0.0.1:%d" % srv.server_address[1]

def mk_env():
    t = tempfile.mkdtemp()
    os.makedirs(os.path.join(t, "lists"))
    open(os.path.join(t, "key"), "w").write(KEY + "\n"); os.chmod(os.path.join(t, "key"), 0o600)
    for name, body in (("py_ok", 'print(\'{"ok": true, "message": "ok", "warnings": ["w1"], "errors": []}\')'),
                       ("py_refuse", 'print(\'{"ok": false, "message": "no", "warnings": [], "errors": ["boom"]}\')'),
                       ("py_crash", 'import sys; sys.exit(1)')):
        p = os.path.join(t, name)
        open(p, "w").write("#!/usr/bin/env python3\n" + body + "\n"); os.chmod(p, 0o755)
    return t

def conf(t, reload="none", py="py_ok", extra=""):
    c = os.path.join(t, "c.conf")
    open(c, "w").write("[misp]\nurl = %s\nkey_file = %s\n[output]\nlist_dir = %s\nstatus_log = %s\nreload = %s\nreload_python = %s\n%s"
                       % (URL, os.path.join(t, "key"), os.path.join(t, "lists"), os.path.join(t, "status.log"),
                          reload, os.path.join(t, py), extra))
    return c

def run(t, *a, key=None, **kw):
    c = conf(t, **kw)
    if key is not None:
        open(os.path.join(t, "key"), "w").write(key + "\n")
    p = subprocess.run([sys.executable, SCRIPT, "--config", c] + list(a), capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

def rd(t, name):
    return open(os.path.join(t, "lists", name)).read()

fails = []
def check(name, cond, info=""):
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(info)[:600]) if (info and not cond) else ""))
    if not cond: fails.append(name)

# ---- 1 dry-run
H.data = make_data(); t = mk_env()
rc, out, err = run(t, "--dry-run", "--report-warninglist-effect")
print(out)
check("1 dry-run rc=0", rc == 0, err + out)
check("1 dry-run writes nothing", os.listdir(os.path.join(t, "lists")) == [])
check("1 dry-run reports domain tiers", "domain tier t1" in out and "domain tier t2" in out)
check("1 warninglist effect reported for domains", "popular-site" not in out and re.search(r"domain\s+t1\s+domain\s+http=200.*warninglist-removed=1", out) is not None, out)

check("1 dry-run summary shows type counts", re.search(r"domain tier t1:.*types: domain=\d+ hostname=\d+", out) is not None, out)

# ---- 2 real run, reload none
rc, out, err = run(t)
check("2 real run rc=0", rc == 0, err + out)
files = sorted(os.listdir(os.path.join(t, "lists")))
check("2 four list files", files == ["misp-domain-t1", "misp-domain-t2", "misp-ip-t1", "misp-ip-t2"], files)
d1 = rd(t, "misp-domain-t1").splitlines(); d2 = rd(t, "misp-domain-t2").splitlines()
ip1 = rd(t, "misp-ip-t1").splitlines()
check("2 domain format name:domain or name:hostname", all(re.fullmatch(r"[^:]+:(domain|hostname)", l) for l in d1 + d2), [l for l in d1 + d2 if not re.fullmatch(r"[^:]+:(domain|hostname)", l)][:3])
check("2 lowercase + trailing dot removed + deduped", "evil.example.com:domain" in d1 and sum(1 for l in d1 if l.startswith("evil.example.com:")) == 1)
check("2 wildcard/ip/single/internal/nonascii/invalid dropped", not any(l.split(":")[0] in ("*.wild.org", "1.2.3.4", "localhost", "host.soc.dev", "bad_chars!.com") for l in d1))
check("2 types: hostname->hostname, domain|ip->domain, hostname|port->hostname", all(x in d1 for x in ["cdn.evil.example.com:hostname", "pair.example.org:domain", "h.example.net:hostname"]))
check("2 name in BOTH domain and hostname -> domain wins, one line", "dual.example.net:domain" in d1 and sum(1 for l in d1 if l.startswith("dual.example.net:")) == 1, [l for l in d1 if l.startswith("dual")])
check("2 non-ASCII name is CONVERTED to its A-label, not dropped, and the Unicode form is not written", "xn--bcher-kva.de:domain" in d1 and not any(not l.isascii() for l in d1), [l for l in d1 if "bcher" in l or not l.isascii()])
check("2 domain-type bulk entries carry :domain", "host0000.bad-example.net:domain" in d1)
check("2 warninglist applied (popular-site.com absent)", not any(l.startswith("popular-site.com:") for l in d1))
check("2 t2 minus t1", not any(l.startswith("evil.example.com:") for l in d2) and len(d2) == 194)
check("2 domain lists sorted", d1 == sorted(d1) and d2 == sorted(d2))
check("2 IP lines keep the v0.3 format (ip: with empty value)", all(re.fullmatch(r"\d+\.\d+\.\d+\.\d+:", l) for l in ip1))
check("2 ip list v0.3-compatible (public hosts only, no cidr/v6)", "11.1.0.1:" in ip1 and "11.60.0.1:" in ip1 and not any(("/" in l or "2606" in l or l.startswith(("10.", "203.0.113"))) for l in ip1))
check("2 ip t2 minus t1", "11.1.0.1:" not in rd(t, "misp-ip-t2") and "11.70.0.1:" in rd(t, "misp-ip-t2"))
check("2 mode 660, no temp files", all(stat.S_IMODE(os.stat(os.path.join(t, "lists", f)).st_mode) == 0o660 for f in files))
st = [json.loads(l) for l in open(os.path.join(t, "status.log"))]
check("2 status log ok, reload note", st[-1]["result"] == "ok" and st[-1]["reload"].startswith("not requested"))

# ---- 3 unchanged rerun
m = os.stat(os.path.join(t, "lists", "misp-domain-t1")).st_mtime_ns; time.sleep(0.05)
rc, out, err = run(t)
check("3 unchanged: no write, reload skipped", rc == 0 and "wrote " not in out and "skipped: no list changed" in out, out)
check("3 mtime untouched", os.stat(os.path.join(t, "lists", "misp-domain-t1")).st_mtime_ns == m)

# ---- 4 hot reload variants
t4 = mk_env(); H.data = make_data()
rc, out, err = run(t4, reload="hot", py="py_ok")
check("4 hot reload ok", rc == 0 and "reload: ok" in out and "reload warning: w1" in out, out)
t4b = mk_env()
rc, out, err = run(t4b, reload="hot", py="py_refuse")
check("4 refused reload -> rc 4 + error", rc == 4 and "refused the reload" in out and "boom" in out, out)
check("4 refused reload: lists WERE written (documented)", os.path.exists(os.path.join(t4b, "lists", "misp-domain-t1")))
t4c = mk_env()
rc, out, err = run(t4c, reload="hot", py="py_crash")
check("4 crashed reload -> rc 4", rc == 4 and "reload failed (exit 1)" in out, out)
t4d = mk_env()
rc, out, err = run(t4d, reload="hot", py="does_not_exist")
check("4 missing python -> rc 4", rc == 4 and "python not found" in out, out)

# ---- 5 shrink guard on domain t1 (700 -> 200) blocks EVERYTHING, files untouched
before = {f: rd(t, f) for f in os.listdir(os.path.join(t, "lists"))}
H.data = make_data(dom_t1=BULK_DOM[:200])
rc, out, err = run(t)
check("5 domain t1 shrink guard rc=2", rc == 2 and "domain t1: shrink guard" in out, out)
check("5 all lists untouched (all-or-nothing)", all(rd(t, f) == before[f] for f in before))

# ---- 6 small t2 domain list is NOT shrink-guarded (min_previous_domain=500) but empty is refused
H.data = make_data(dom_t2=["raw000.example.org"] * 1)   # 194 -> 1 (+ evil.example.com dup of t1 -> removed)
rc, out, err = run(t)
check("6 small t2 domain shrink accepted", rc == 0, out)
H.data = make_data(dom_t2=[]); d = H.data; d[("domain", 0)] = []
rc, out, err = run(t)
check("6 empty t2 domain refused", rc == 2 and "domain t2: export is empty" in out, out)

# ---- 7 --wazuh compact line: v0.3 field names kept, domain fields additive, no 'status'
H.data = make_data(); t7 = mk_env()
rc, out, err = run(t7, "--wazuh")
line = out.strip()
j = json.loads(line)
check("7 single line", len(out.strip().splitlines()) == 1)
check("7 v0.3 fields kept", all(k in j for k in ("ts", "program", "version", "result", "duration_s", "changed", "reload", "t1_written", "t2_written", "overlap_removed_from_t2", "tiers")))
check("7 domain fields additive", all(k in j for k in ("domain_t1_written", "domain_t2_written", "domain_tiers", "domain_overlap_removed_from_t2")))
check("7 no 'status' key, result ok", "status" not in j and j["result"] == "ok")
check("7 version 0.4, program name", j["version"] == "0.5.1" and j["program"] == "misp-ioc-sync")
check("7 no key in output", KEY not in out)

# ---- 8 errors
rc, out, err = run(mk_env(), key="WRONG")
check("8 wrong key rc=2 HTTP 403", rc == 2 and "HTTP 403" in out)
t8 = mk_env(); c = conf(t8); s = open(c).read().replace(URL, "http://127.0.0.1:9"); open(c, "w").write(s)
p = subprocess.run([sys.executable, SCRIPT, "--config", c], capture_output=True, text=True)
check("8 unreachable rc=2", p.returncode == 2 and "connection error" in p.stdout)
check("8 failure writes nothing", os.listdir(os.path.join(t8, "lists")) == [])

# ---- 9 domains=false behaves like v0.3 (IP only)
t9 = mk_env(); H.data = make_data()
rc, out, err = run(t9, extra="[filters]\ndomains = false\n")
check("9 domains=false: only ip lists", rc == 0 and sorted(os.listdir(os.path.join(t9, "lists"))) == ["misp-ip-t1", "misp-ip-t2"], out)

# ---- 10 version + compile
p = subprocess.run([sys.executable, SCRIPT, "--version"], capture_output=True, text=True)
# shape check
t11 = mk_env(); H.data = make_data(dom_t1=["a.com","b.com","x.y.com","p.q.r.com","m.n.o.p.com"]); 
rc, out, err = run(t11, "--dry-run")
check("11 label shape in summary", "labels: 2=" in out and re.search(r"domain tier t1:.*labels: 2=(\d+) 3=(\d+) 4\+=(\d+)", out) is not None, out)
mm = re.search(r"domain tier t1:.*labels: 2=(\d+) 3=(\d+) 4\+=(\d+)", out)
# t1 = a.com,b.com (2) ; x.y.com (3) ; p.q.r.com (4+) ; m.n.o.p.com (4+) ; plus fixture extras: evil.example.com(3), cdn.evil.example.com(4+), pair.example.org(3), h.example.net(3)
check("11 label shape numbers", mm and list(map(int, mm.groups())) == [3, 5, 3], mm and mm.groups())
check("10 --version", p.stdout.strip() == "misp_ioc_sync.py 0.5.1", p.stdout)

# ---- 12 language independence (RFC 4343: ASCII-only fold, IDNA for the rest)
import importlib.util, inspect, random, string as _string
spec = importlib.util.spec_from_file_location("sync_mod", SCRIPT); mod = importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
def norm(x):
    v, reason, fl = mod.classify_domain(x)
    return v
check("12 plain upper / trailing dot", norm("EXAMPLE.COM") == "example.com" and norm("Example.Com.") == "example.com")
check("12 German umlaut: upper and lower are the same name", norm("B\u00dcCHER.DE") == norm("b\u00fccher.de") == "xn--bcher-kva.de", (norm("B\u00dcCHER.DE"), norm("b\u00fccher.de")))
check("12 Turkish dotted I (U+0130) is NOT the ASCII I name", norm("\u0130OC-TEST.EXAMPLE") not in (None, "ioc-test.example") and norm("\u0130OC-TEST.EXAMPLE") == "xn--ioc-test-o0e.example", norm("\u0130OC-TEST.EXAMPLE"))
check("12 Turkish dotless i (U+0131) is NOT the ASCII i name", norm("\u0131oc-test.example") not in (None, "ioc-test.example"))
check("12 Cyrillic homograph is NOT the ASCII name", norm("\u0430pple.com") not in (None, "apple.com"))
check("12 Greek and CJK convert deterministically", norm("\u03b5\u03bb\u03bb\u03ac\u03b4\u03b1.gr") == "xn--hxakic4aa.gr" and norm("\u4f8b\u3048.jp") == "xn--r8jz45g.jp")
check("12 Latin-1 pair 0xDD/0xFD (Y acute) is not folded together by ASCII fold (RFC 4343 example)", mod.ascii_fold("\u00dd") != mod.ascii_fold("\u00fd"))
long_label = "\u00fc" * 70 + ".com"
check("12 un-convertible name is counted, never crashes", mod.classify_domain(long_label)[1] == "idna_failed")
src = inspect.getsource(mod.classify_domain)
check("12 STATIC: the domain path calls no case/locale method (lower, upper, casefold, title, locale)", not any(x in src for x in (".lower(", ".upper(", ".casefold(", ".title(", "locale")), [x for x in (".lower(", ".upper(", ".casefold(", ".title(", "locale") if x in src])
random.seed(7)
same = True
for _ in range(5000):
    n = "".join(random.choice(_string.ascii_letters + _string.digits + "-") for _ in range(random.randint(1, 12))) + "." + "".join(random.choice(_string.ascii_letters) for _ in range(random.randint(2, 6)))
    if norm(n) != n.lower().rstrip(".") and norm(n) is not None:
        same = False; break
check("12 for ASCII input the result is identical to the previous str.lower() behaviour (lists do not change)", same)

print("\nFAILED:" if fails else "\nALL PASSED", fails)

raise SystemExit(1 if fails else 0)
