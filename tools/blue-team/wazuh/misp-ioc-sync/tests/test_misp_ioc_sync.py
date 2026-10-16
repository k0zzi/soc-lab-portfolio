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
    json_types = set()         # types requested through the JSON path
    decayed = set()            # raw values MISP considers decayed (text export drops them, JSON marks them decayed)
    bulk_bug = False           # MISP 2.5.40: bulk text export + enforceWarninglist also drops legit IPs
    composite_text_bug = False # MISP 2.5.40: bulk text export + excludeDecayed drops composite (ip|port) values
    no_scores = False          # emulate a disabled / wrong decaying model: JSON rows carry no decay score
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0)); p = json.loads(self.rfile.read(n))
        if self.headers.get("Authorization") != KEY:
            self.send_response(403); self.end_headers(); self.wfile.write(b"denied"); return
        lines = list(H.data.get((p["type"], p["published"]), []))
        if p.get("returnFormat") == "json":
            # paged JSON path (retrieval = json-paged): no server-side decay filter, scores on request
            assert p["to_ids"] == 1 and "excludeDecayed" not in p
            H.json_types.add(p["type"])
            if p.get("includeDecayScore"):
                assert p["modelOverrides"] == {"threshold": 10, "lifetime": 365}
            if p.get("enforceWarninglist"):
                lines = [l for l in lines if l.split("|")[0].lower() not in WARNLIST]
            page, limit = p["page"], p["limit"]
            attrs = []
            for l in lines[(page - 1) * limit: page * limit]:
                a = {"value": l}
                if p.get("includeDecayScore") and not H.no_scores:
                    dec = l in H.decayed
                    a["decay_score"] = [{"score": 4.0 if dec else 40.0, "decayed": dec, "DecayingModel": {"id": "1"}}]
                attrs.append(a)
            body = json.dumps({"response": {"Attribute": attrs}}).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers(); self.wfile.write(body)
            return
        assert p["to_ids"] == 1 and p["excludeDecayed"] == 1 and p["modelOverrides"] == {"threshold": 10, "lifetime": 365}
        lines = [l for l in lines if l not in H.decayed]
        if H.composite_text_bug:
            lines = [l for l in lines if "|" not in l]
        if p.get("enforceWarninglist"):
            lines = [l for l in lines if l.split("|")[0].lower() not in WARNLIST]
            if H.bulk_bug:
                lines = [l for l in lines if not l.split("|")[0].endswith(".5")]
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
check("7 version 0.7.1, program name", j["version"] == "0.7.1" and j["program"] == "misp-ioc-sync")
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
check("10 --version", p.stdout.strip() == "misp_ioc_sync.py 0.7.1", p.stdout)

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

# ---- 13 v0.7 retrieval = json-paged (paged JSON, warninglist by MISP, decay decided from MISP's own scores)
JP = "[filters]\nretrieval = json-paged\ndomain_retrieval = json-paged\njson_page_size = 100\n"   # both kinds
JPIP = "[filters]\nretrieval = json-paged\njson_page_size = 100\n"                                      # IP lists only
def lists(t): return {f: rd(t, f) for f in sorted(os.listdir(os.path.join(t, "lists")))}
H.bulk_bug = H.composite_text_bug = H.no_scores = False; H.decayed = set()
H.data = make_data()
t_ref = mk_env(); rc, out, err = run(t_ref)
check("13 reference run (text-bulk, no MISP defects) rc=0", rc == 0, out)
ref = lists(t_ref)

H.bulk_bug = True; H.composite_text_bug = True
t13a = mk_env(); rc, out, err = run(t13a)
l13a = lists(t13a)
check("13a text-bulk LOSES legit IPs under the measured MISP defects (warninglist bulk bug)", rc == 0 and "11.1.0.5:" not in l13a["misp-ip-t1"] and "11.1.0.5:" in ref["misp-ip-t1"], out)
check("13a text-bulk LOSES composite ip|port IPs under the measured MISP decay defect", "11.60.0.1:" not in l13a["misp-ip-t1"] and "11.60.0.1:" in ref["misp-ip-t1"])

t13i_ref = mk_env(); rc, out, err = run(t13i_ref, extra="[filters]\nenforce_warninglist = false\n")   # control: without enforcement the warninglisted domain IS in the list
t13b = mk_env(); rc, out, err = run(t13b, extra=JP)
check("13b json-paged rc=0 under the same MISP defects", rc == 0, err + out)
check("13b json-paged output is IDENTICAL to the reference lists (all four files)", lists(t13b) == ref, [f for f in ref if lists(t13b).get(f) != ref[f]])
check("13b warninglisted domain is still removed (checked line by line)", not any(l.startswith("popular-site.com:") for l in lists(t13b)["misp-domain-t1"].splitlines()) and any(l.startswith("popular-site.com:") for l in lists(t13i_ref)["misp-domain-t1"].splitlines()))

H.bulk_bug = H.composite_text_bug = False
H.decayed = {"11.1.0.2", "11.60.0.1|443", "host0003.bad-example.net"}
t_ref2 = mk_env(); rc, out, err = run(t_ref2)
ref2 = lists(t_ref2)
t13c = mk_env(); rc, out, err = run(t13c, extra=JP)
check("13c decayed values are dropped client-side, result identical to the text export's decision", rc == 0 and lists(t13c) == ref2, out)
check("13c a decayed IP / composite IP / domain really is absent", "11.1.0.2:" not in lists(t13c)["misp-ip-t1"] and "11.60.0.1:" not in lists(t13c)["misp-ip-t1"] and "host0003.bad-example.net:domain" not in lists(t13c)["misp-domain-t1"])

t13d = mk_env(); rc, out, err = run(t13d, extra=JP + "exclude_decayed = false\n")
check("13d exclude_decayed=false keeps the decayed values in json-paged mode", rc == 0 and "11.1.0.2:" in lists(t13d)["misp-ip-t1"], out)
H.decayed = set()

H.no_scores = True
t13e = mk_env(); rc, out, err = run(t13e, extra=JP)
check("13e missing decay scores trip the decay guard: rc=2, message, nothing written",
      rc == 2 and "decay guard" in out and os.listdir(os.path.join(t13e, "lists")) == [], out)
H.no_scores = False

t13f = mk_env(); rc, out, err = run(t13f, extra="[filters]\nretrieval = fancy\n")
check("13f invalid retrieval mode is a config error (rc=2)", rc == 2 and "retrieval" in out, out)

t13g = mk_env(); rc, out, err = run(t13g, extra=JP + "json_max_pages = 2\n")
check("13g page cap reached before the end -> fail closed (rc=2, nothing written)",
      rc == 2 and "did not finish" in out and os.listdir(os.path.join(t13g, "lists")) == [], out)

t13h = mk_env(); rc, out, err = run(t13h, "--dry-run", "--report-warninglist-effect", extra=JP)
check("13h dry-run shows json rows/pages and the warninglist effect (domain t1: 1 removed)",
      re.search(r"domain\s+t1\s+domain\s+http=200.*warninglist-removed=1\s+json: rows=\d+ pages=\d+ decayed-dropped=0", out) is not None, out)

H.data = make_data()
t13i = mk_env(); rc, out, err = run(t13i, extra="[filters]\nretrieval = json-paged\nenforce_warninglist = false\njson_page_size = 100\n")
check("13i enforce_warninglist=false: json-paged keeps warninglisted values (no enforcement requested)",
      rc == 0 and any(l.startswith("popular-site.com:") for l in lists(t13i)["misp-domain-t1"].splitlines()), out)

# ---- 14 v0.7.1: the IP lists can use json-paged while the domain lists stay on text-bulk
H.bulk_bug = H.composite_text_bug = H.no_scores = False; H.decayed = set(); H.data = make_data()
H.json_types = set()
t14 = mk_env(); rc, out, err = run(t14, extra=JPIP)
check("14 IP-only json-paged rc=0, all four lists identical to the reference", rc == 0 and lists(t14) == ref, out)
check("14 the JSON path was used for IP types only (no domain type requested as JSON)",
      H.json_types and all(t.startswith("ip-") for t in H.json_types), sorted(H.json_types))
H.json_types = set()
t14b = mk_env(); rc, out, err = run(t14b, extra="[filters]\ndomain_retrieval = json-paged\njson_page_size = 100\n")
check("14 domain-only json-paged: the JSON path is used for domain types only", rc == 0 and H.json_types and not any(t.startswith("ip-") for t in H.json_types), sorted(H.json_types))
t14c = mk_env(); rc, out, err = run(t14c, extra="[filters]\ndomain_retrieval = fancy\n")
check("14 invalid domain_retrieval is a config error (rc=2)", rc == 2 and "domain_retrieval" in out, out)

# ---- 15 the production invocation (--wazuh) with json-paged keeps the compact status schema
H.bulk_bug = H.composite_text_bug = H.no_scores = False; H.decayed = set(); H.data = make_data()
t15r = mk_env(); rc, out, err = run(t15r, "--wazuh"); jr = json.loads(out.strip())
t15 = mk_env(); rc, out, err = run(t15, "--wazuh", extra=JPIP)
check("15 --wazuh + json-paged prints exactly one line", len(out.strip().splitlines()) == 1, out)
j15 = json.loads(out.strip())
check("15 same compact keys as text-bulk (new per-query fields do not leak into the Wazuh line)", sorted(j15) == sorted(jr), (sorted(j15), sorted(jr)))
check("15 result ok and tier sizes equal the text-bulk run", j15["result"] == "ok" and j15["t1_written"] == jr["t1_written"] and j15["t2_written"] == jr["t2_written"], out)
check("15 no key in the Wazuh line", KEY not in out)

print("\nFAILED:" if fails else "\nALL PASSED", fails)

raise SystemExit(1 if fails else 0)
