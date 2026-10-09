import json, os, stat, subprocess, sys, tempfile

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "domain_ioc_marker_test.py")

def mk(reload_ok=True):
    t = tempfile.mkdtemp()
    os.makedirs(t + "/lists"); os.makedirs(t + "/bak")
    t1 = b"evil-one.com:\nevil-two.net:\n"
    t2 = b"raw-list.example.org:"          # no trailing newline on purpose
    open(t + "/lists/misp-domain-t1", "wb").write(t1); os.chmod(t + "/lists/misp-domain-t1", 0o660)
    open(t + "/lists/misp-domain-t2", "wb").write(t2); os.chmod(t + "/lists/misp-domain-t2", 0o660)
    flag = t + "/reload.called"
    body = ('import sys\nopen(%r, "a").write("x")\nprint(\'{"ok": true, "message": "ok", "warnings": [], "errors": []}\')\n' % flag
            if reload_ok else
            'import sys\nprint(\'{"ok": false, "message": "no", "warnings": [], "errors": ["boom"]}\')\n')
    open(t + "/py", "w").write("#!/usr/bin/env python3\n" + body); os.chmod(t + "/py", 0o755)
    return t, t1, t2, flag

def run(t, *a, tag="a1"):
    cmd = [sys.executable, SCRIPT, "--lists-dir", t + "/lists", "--alerts", t + "/alerts.json",
           "--backup-dir", t + "/bak", "--reload-python", t + "/py", "--tag", tag] + list(a)
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

fails = []
def check(name, cond, info=""):
    print(("PASS " if cond else "FAIL ") + name + ((" :: " + str(info)[:500]) if (info and not cond) else ""))
    if not cond: fails.append(name)

# 1 add
t, o1, o2, flag = mk()
rc, out, err = run(t, "--add"); print(out)
a1 = open(t + "/lists/misp-domain-t1", "rb").read(); a2 = open(t + "/lists/misp-domain-t2", "rb").read()
check("1 add rc=0", rc == 0, out + err)
check("1 t1: marker appended once, original intact", a1 == o1 + b"ioc-test-a1-t1.example:\n")
check("1 t2: newline fixed then marker appended", a2 == o2 + b"\nioc-test-a1-t2.example:\n")
check("1 reload called", os.path.exists(flag))
check("1 mode preserved", stat.S_IMODE(os.stat(t + "/lists/misp-domain-t1").st_mode) == 0o660)
check("1 two backups, byte-identical to originals", sorted(os.listdir(t + "/bak")) and any(open(t + "/bak/" + b, "rb").read() == o1 for b in os.listdir(t + "/bak")) and any(open(t + "/bak/" + b, "rb").read() == o2 for b in os.listdir(t + "/bak")))
check("1 PowerShell block printed (upper case first, Resolve-DnsName, .example only)", "Resolve-DnsName $n.ToUpperInvariant()" in out and out.index("ToUpperInvariant") < out.index("'www.'") and "ioc-test-a1-t1.example" in out and "nslookup" not in out)
check("1 no temp files left", not [f for f in os.listdir(t + "/lists") if f.startswith(".tmp-")])

# 2 idempotent
os.remove(flag)
rc, out, err = run(t, "--add")
check("2 second add: no duplicate, no reload", rc == 0 and open(t + "/lists/misp-domain-t1", "rb").read() == a1 and not os.path.exists(flag) and "nothing changed" in out, out)

# 3 report (basic scenario)
alerts = [
 {"timestamp": "2026-10-07T12:50:01.100+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "IOC-TEST-A1-T1.EXAMPLE"}}}},
 {"timestamp": "2026-10-07T12:50:02.100+0300", "rule": {"id": "100320"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "ioc-test-a1-t1.example"}}}},
 {"timestamp": "2026-10-07T12:50:03.100+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "www.ioc-test-a1-t1.example"}}}},
 {"timestamp": "2026-10-07T12:50:04.100+0300", "rule": {"id": "100321"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "ioc-test-a1-t2.example"}}}},
 {"timestamp": "2026-10-07T12:50:05.100+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "unrelated.example.com"}}}},
 {"timestamp": "2026-10-07T12:50:06.100+0300", "rule": {"id": "92057"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"commandLine": "mentions ioc-test-a1 in a command line"}}}},
]
with open(t + "/alerts.json", "w") as fh:
    for a in alerts: fh.write(json.dumps(a) + "\n")
    fh.write("this line is not json ioc-test-a1\n")
rc, out, err = run(t, "--report"); print(out)
def verdict_of(out, label_part):
    lines = out.splitlines()
    i = [k for k, l in enumerate(lines) if label_part in l and "->" not in l][0]
    v = lines[i + 1].strip()
    return v[3:] if v.startswith("-> ") else v
check("3 report rc=0", rc == 0, out + err)
check("3 exact -> 100320", verdict_of(out, "tier 1, exact name").endswith("rules: 100320"), verdict_of(out, "tier 1, exact name"))
check("3 upper-case variant logged exactly, only 100160 (not IOC)", verdict_of(out, "UPPER CASE").endswith("rules: 100160"))
check("3 trailing dot variant NOT SEEN exactly, equivalent forms shown", verdict_of(out, "trailing dot").startswith("NOT SEEN as that exact string; seen as:") and "ioc-test-a1-t1.example (rule 100320)" in verdict_of(out, "trailing dot"), verdict_of(out, "trailing dot"))
check("3 www variant -> 100160 only", verdict_of(out, "www. subdomain").endswith("rules: 100160"))
check("3 tier 2 exact -> 100321", verdict_of(out, "tier 2, exact").endswith("rules: 100321"))
check("3 unrelated and non-DNS alerts not in table", "unrelated.example.com" not in out and "92057" not in out)

# 3b case scenario
tc, *_ = mk()
rc, out, err = run(tc, "--add", "--tag", "a2", "--scenario", "case"); print(out)
check("3b case block: three APIs, mixed-case names, upper-case marker", all(x in out for x in ["Resolve-DnsName $n.ToUpperInvariant()", "ping -n 1 -w 500 'Ioc-Test-a2-Mixed1.Example'", "[System.Net.Dns]::GetHostAddresses('Ioc-Test-a2-Mixed2.Example')", "Resolve-DnsName 'Ioc-Test-a2-Mixed3.Example'"]) and "--scenario case" in out and "nslookup" not in out, out)
check("3b markers use tag a2", b"ioc-test-a2-t1.example:" in open(tc + "/lists/misp-domain-t1", "rb").read())
calerts = [
 {"timestamp": "2026-10-07T13:10:01.000+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "ioc-test-a2-t1.example"}}}},   # upper logged lowercase, CDB hit would be 100320 normally
 {"timestamp": "2026-10-07T13:10:02.000+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "Ioc-Test-a2-Mixed1.Example"}}}},  # preserved
 {"timestamp": "2026-10-07T13:10:04.000+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "ioc-test-a2-mixed3.example"}}}},  # lowercased
]
with open(tc + "/alerts.json", "w") as fh:
    for a in calerts: fh.write(json.dumps(a) + "\n")
rc, out, err = run(tc, "--report", "--tag", "a2", "--scenario", "case"); print(out)
check("3b case report rc=0", rc == 0, out + err)
check("3b upper marker: seen as lowercase form", verdict_of(out, "UPPER CASE of the tier 1 marker").startswith("NOT SEEN as that exact string; seen as: ioc-test-a2-t1.example (rule 100160)"), verdict_of(out, "UPPER CASE of the tier 1 marker"))
check("3b ping variant preserved exactly", verdict_of(out, "mixed case, ping").endswith("rules: 100160") and verdict_of(out, "mixed case, ping").startswith("logged exactly"))
check("3b .NET variant: no Event 22", verdict_of(out, "mixed case, .NET Dns").startswith("NOT SEEN (no Event 22"))
check("3b Resolve-DnsName variant: logged lowercased", "ioc-test-a2-mixed3.example (rule 100160)" in verdict_of(out, "mixed case, Resolve-DnsName"))

# 4 report with no matches
rc, out, err = run(t, "--report", tag="zz")
check("4 no markers -> rc=1 + hint", rc == 1 and "no alerts carry the marker" in out, out)

# 5 cleanup
if os.path.exists(flag): os.remove(flag)
rc, out, err = run(t, "--cleanup")
b1 = open(t + "/lists/misp-domain-t1", "rb").read(); b2 = open(t + "/lists/misp-domain-t2", "rb").read()
check("5 cleanup restores t1 byte for byte", b1 == o1, b1)
check("5 cleanup removes only the marker from t2 (newline fix stays)", b2 == o2 + b"\n", b2)
check("5 reload called", os.path.exists(flag))
rc, out, err = run(t, "--cleanup")
check("5 second cleanup harmless", rc == 0 and "no marker" in out)

# 6 failed reload
t6, *_ = mk(reload_ok=False)
rc, out, err = run(t6, "--add")
check("6 refused reload -> rc 3 + cleanup hint", rc == 3 and "refused the reload" in out and "--cleanup" in out, out)

# 7 missing list file
t7, *_ = mk(); os.remove(t7 + "/lists/misp-domain-t2")
rc, out, err = run(t7, "--add")
check("7 missing list aborts, t1 untouched", rc != 0 and "list file missing" in (out + err) and open(t7 + "/lists/misp-domain-t1", "rb").read() == b"evil-one.com:\nevil-two.net:\n", out + err)

# 7b caps scenario
tp, *_ = mk()
rc, out, err = run(tp, "--add", "--tag", "a2", "--scenario", "caps"); print(out)
blk = out[out.index("Resolve-DnsName 'ioc-test-a2-warmup"):out.index("Then wait")]
check("7b caps block: warm-up first, two ALL CAPS names, mixed-case t2 marker via ping", blk.splitlines()[0].startswith("Resolve-DnsName 'ioc-test-a2-warmup.example'") and "IOC-TEST-A2-ALLCAPS1.EXAMPLE" in blk and "ping -n 1 -w 500 'IOC-TEST-A2-ALLCAPS2.EXAMPLE'" in blk and "ping -n 1 -w 500 'Ioc-Test-a2-T2.Example'" in blk, blk)
calerts = [
 {"timestamp": "2026-10-07T14:00:01.000+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "IOC-TEST-A2-ALLCAPS2.EXAMPLE"}}}},
 {"timestamp": "2026-10-07T14:00:03.000+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "Ioc-Test-a2-T2.Example"}}}},
]
with open(tp + "/alerts.json", "w") as fh:
    for a in calerts: fh.write(json.dumps(a) + "\n")
rc, out, err = run(tp, "--report", "--tag", "a2", "--scenario", "caps"); print(out)
check("7b caps report: warm-up NOT SEEN, ALLCAPS1 NOT SEEN, ALLCAPS2 logged, mixed T2 = 100160 only",
      verdict_of(out, "warm-up, lowercase").startswith("NOT SEEN (no Event 22")
      and verdict_of(out, "ALL CAPS, Resolve-DnsName").startswith("NOT SEEN (no Event 22")
      and verdict_of(out, "ALL CAPS, ping").endswith("rules: 100160")
      and verdict_of(out, "mixed case of the tier 2 marker").endswith("rules: 100160"), out)

# 7c Turkish dotted capital I must be visible in the report
tt, *_ = mk()
ta = [
 {"timestamp": "2026-10-07T14:24:34.000+0300", "rule": {"id": "100160"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "\u0130OC-TEST-A9-T1.EXAMPLE"}}}},
 {"timestamp": "2026-10-07T14:24:35.000+0300", "rule": {"id": "100320"}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "ioc-test-a9-t1.example"}}}},
]
with open(tt + "/alerts.json", "w") as fh:
    for a in ta: fh.write(json.dumps(a) + "\n")                 # json.dumps escapes as \u0130, like a raw alert might
rc, out, err = run(tt, "--report", "--tag", "a9"); print(out)
check("7c report finds the Turkish-I name and flags it NON-ASCII U+0130", "NON-ASCII: U+0130" in out and "rules: 100320" in out, out)
with open(tt + "/alerts.json", "w") as fh:
    for a in ta: fh.write(json.dumps(a, ensure_ascii=False) + "\n")   # raw UTF-8 variant
rc, out, err = run(tt, "--report", "--tag", "a9")
check("7c same with raw UTF-8 in alerts.json", "NON-ASCII: U+0130" in out, out)

# 8 rate
tr, *_ = mk()
rows = []
def al(ts, rid="100160"): return {"timestamp": ts, "rule": {"id": rid}, "agent": {"name": "CLT601"}, "data": {"win": {"eventdata": {"queryName": "x.example.com"}}}}
for i in range(9): rows.append(al("2026-10-07T10:00:01.%03d+0300" % (i * 100)))      # 9 in one second
for i in range(2): rows.append(al("2026-10-07T10:00:05.%03d+0300" % (i * 100)))      # 2 in another second
for i in range(4): rows.append(al("2026-10-07T10:01:30.%03d+0300" % (i * 100)))      # 4 in a second, next minute
rows.append(al("2026-10-07T10:01:31.000+0300", rid="92057"))                          # other rule: must not count
with open(tr + "/alerts.json", "w") as fh:
    for r in rows: fh.write(json.dumps(r) + "\n")
    fh.write("not json but mentions \"100160\"\n")
rc, out, err = run(tr, "--rate"); print(out)
check("8 rate rc=0", rc == 0, out + err)
check("8 total 15 (other rule and bad line excluded)", "alerts in" in out and ": 15" in out.splitlines()[0], out)
check("8 peak per second 9", "peak per second: 9 (2026-10-07T10:00:01)" in out, out)
check("8 peak per minute 11", "peak per minute: 11 (2026-10-07T10:00)" in out, out)
check("8 average per active minute 7.5", "average per active minute: 7.5" in out, out)
check("8 thresholds: >=3 -> 2 sec, >=7 -> 1 sec, >=20 -> 0", "seconds with >= 3 alerts: 2" in out and "seconds with >= 7 alerts: 1" in out and "seconds with >= 20 alerts: 0" in out, out)
rc, out, err = run(tr, "--rate", "--alerts", tr + "/nope.json")
check("8 missing alerts file -> rc 2", rc == 2, out)

# 9 health
import shutil
def fake_proc(root, pid, target_path, pos, comm="wazuh-integrato", deleted=False, with_fd=True, cmdline=b"/var/ossec/bin/wazuh-integratord\0"):
    os.makedirs(root + "/%s/fd" % pid); os.makedirs(root + "/%s/fdinfo" % pid)
    open(root + "/%s/comm" % pid, "w").write(comm + "\n")
    if cmdline is not None:
        open(root + "/%s/cmdline" % pid, "wb").write(cmdline)
    if with_fd:
        os.symlink(target_path + (" (deleted)" if deleted else ""), root + "/%s/fd/9" % pid)
        open(root + "/%s/fdinfo/9" % pid, "w").write("pos:\t%d\nflags:\t0100000\n" % pos)
    os.makedirs(root + "/1/fd"); open(root + "/1/comm", "w").write("systemd\n")

def health(t, *extra, proc=None):
    cmd = [sys.executable, SCRIPT, "--alerts", t + "/alerts.json", "--ossec-log", t + "/ossec.log",
           "--proc-root", proc or (t + "/proc"), "--lists-dir", t + "/lists", "--backup-dir", t + "/bak",
           "--reload-python", t + "/py", "--health"] + list(extra)
    p = subprocess.run(cmd, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr

th, *_ = mk()
long160 = {"timestamp": "2026-10-07T10:00:00.000+0300", "rule": {"id": "100160"}, "full_log": "x" * 2500, "data": {"win": {"eventdata": {"queryName": "a.example.com"}}}}
short160 = al("2026-10-07T10:00:01.000+0300")
long_other = {"timestamp": "2026-10-07T10:00:02.000+0300", "rule": {"id": "86601"}, "full_log": "y" * 5000}
with open(th + "/alerts.json", "w") as fh:
    for r in (short160, long160, long_other, al("2026-10-07T10:00:03.000+0300")): fh.write(json.dumps(r) + "\n")
size = os.path.getsize(th + "/alerts.json")
open(th + "/ossec.log", "w").write(
    "2026/10/07 08:51:45 wazuh-integratord: ERROR: While running shuffle -> integrations. Output: requests.exceptions.ConnectionError: .../webhook_SECRETUUID...\n"
    "2026/10/07 09:00:01 wazuh-integratord: WARNING: Invalid JSON alert read from 'logs/alerts/alerts.json': '{...'\n"
    "2026/10/07 09:00:02 wazuh-analysisd: INFO: unrelated\n")
# 9a OK, caught up
fake_proc(th + "/proc", "4242", th + "/alerts.json", size)
rc, out, err = health(th); print(out)
check("9a health rc=0", rc == 0, out + err)
check("9a OK: same file, unread 0", "verdict: OK (same inode" in out and "unread: 0 bytes" in out, out)
check("9a line stats: 4 lines, 2 longer than 2048, 1 longer than 4096", "alert lines: 4, longer than 2048: 2, longer than 4096: 1" in out, out)
check("9a rule 100160: 3 lines, 1 long", "rule 100160 lines: 3," in out and "longer than 2048: 1" in out.split("rule 100160 lines")[1].splitlines()[0], out)
check("9a rules producing long lines listed", "100160 x1" in out and "86601 x1" in out, out)
check("9a ossec.log counts, secret not printed", "'Invalid JSON alert' warnings: 1 (last 2026/10/07 09:00:01)" in out and "integratord ERROR lines: 1 (last 2026/10/07 08:51:45)" in out and "SECRETUUID" not in out and "webhook_" not in out, out)
# 9b lag
shutil.rmtree(th + "/proc"); fake_proc(th + "/proc", "4242", th + "/alerts.json", size - 100)
rc, out, err = health(th)
check("9b lag shown", "unread: 100 bytes" in out and "verdict: OK (same inode" in out, out)
# 9c stale: deleted
shutil.rmtree(th + "/proc"); fake_proc(th + "/proc", "4242", th + "/alerts.json", 10, deleted=True)
rc, out, err = health(th)
check("9c descriptor whose file cannot be stat'ed -> STALE", "verdict: STALE" in out, out)
# 9d stale: different inode (file replaced)
shutil.rmtree(th + "/proc"); fake_proc(th + "/proc", "4242", th + "/old-alerts.json", 10)
open(th + "/old-alerts.json", "w").write("{}\n")
rc, out, err = health(th)
check("9d different inode than live -> STALE with both inodes", "verdict: STALE (different file: descriptor inode" in out and "no longer receives the live alerts" in out, out)
# 9e not running / no fd
shutil.rmtree(th + "/proc"); os.makedirs(th + "/proc/1"); open(th + "/proc/1/comm", "w").write("systemd\n")
rc, out, err = health(th)
check("9e integratord not running reported", "NOT running" in out, out)
shutil.rmtree(th + "/proc"); fake_proc(th + "/proc", "77", th + "/alerts.json", 0, with_fd=False)
rc, out, err = health(th)
check("9e no alerts.json descriptor reported", "no open alerts.json descriptor found" in out, out)
# 9g real Linux behaviour: comm is truncated to 15 characters
import inspect
check("9g the real comm for wazuh-integratord is 15 chars: wazuh-integrato", "wazuh-integratord"[:15] == "wazuh-integrato" and len("wazuh-integrato") == 15)
shutil.rmtree(th + "/proc"); fake_proc(th + "/proc", "4242", th + "/alerts.json", size)   # truncated comm + cmdline
rc, out, err = health(th)
check("9g truncated comm + cmdline -> detected", "NOT running" not in out and "verdict: OK (same inode" in out, out)
shutil.rmtree(th + "/proc"); fake_proc(th + "/proc", "4242", th + "/alerts.json", size, cmdline=None)   # cmdline unreadable, truncated comm only
rc, out, err = health(th)
check("9g truncated comm only (no cmdline) -> detected", "NOT running" not in out, out)
shutil.rmtree(th + "/proc"); fake_proc(th + "/proc", "4242", th + "/alerts.json", size, comm="wazuh-modulesd", cmdline=b"/var/ossec/bin/wazuh-modulesd\0")
rc, out, err = health(th)
check("9g another wazuh daemon is NOT mistaken for integratord", "NOT running" in out, out)
# 9h rotation by rename: the process is left on ossec-alerts-DD.json
shutil.rmtree(th + "/proc")
open(th + "/ossec-alerts-07.json", "w").write("{}\n")
fake_proc(th + "/proc", "4242", th + "/ossec-alerts-07.json", 3)
rc, out, err = health(th)
check("9h rotated file (ossec-alerts-DD.json) -> STALE, not 'no descriptor'", "verdict: STALE" in out and "no open alerts.json descriptor" not in out, out)
# 9f missing alerts file
rc, out, err = subprocess.run([sys.executable, SCRIPT, "--alerts", th + "/none.json", "--proc-root", th + "/proc", "--health"], capture_output=True, text=True).returncode, "", ""
check("9f missing alerts.json -> rc 2", rc == 2)

# 10 REAL processes on the real /proc
import time as _time
def real_integratord(tmp, code):
    os.makedirs(tmp, exist_ok=True)
    link = tmp + "/wazuh-integratord"
    if not os.path.exists(link): os.symlink(sys.executable, link)
    return subprocess.Popen([link, "-c", code], cwd=tmp)
def real_health(tmp):
    p = subprocess.run([sys.executable, SCRIPT, "--health", "--alerts", tmp + "/alerts.json", "--ossec-log", "/dev/null"], capture_output=True, text=True)
    return p.stdout
rt = tempfile.mkdtemp() + "/hl"; os.makedirs(rt)
open(rt + "/ossec-alerts-07.json", "w").write("l1\nl2\nl3\n"); os.link(rt + "/ossec-alerts-07.json", rt + "/alerts.json")
pr = real_integratord(rt, 'import time; f=open("alerts.json"); f.read(); time.sleep(30)'); _time.sleep(1)
out = real_health(rt)
check("10a real process, untouched hard link -> OK, unread 0", "verdict: OK (same inode" in out and "unread: 0 bytes" in out and "(deleted)" not in out.split("alert line lengths")[0], out)
os.remove(rt + "/alerts.json"); os.link(rt + "/ossec-alerts-07.json", rt + "/alerts.json")      # Wazuh-style re-link, same file
open(rt + "/alerts.json", "a").write("l4\n")
out = real_health(rt)
check("10b real process, name unlinked and hard-linked again (same inode) -> OK with note, NOT stale", "verdict: OK (same inode" in out and "'(deleted)'" in out and "verdict: STALE" not in out and "unread: 3 bytes" in out, out)
os.remove(rt + "/alerts.json"); open(rt + "/alerts.json", "w").write("brand new file\n")   # truly different inode
out = real_health(rt)
check("10c real process, truly replaced by a different file -> STALE", "verdict: STALE (different file" in out, out)
pr.kill(); pr.wait()

# 11 accept scenario
ta, *_ = mk()
d, h, t2n, u = "ioc-test-a5-d.example", "ioc-test-a5-h.example", "ioc-test-a5-t2.example", "ioc-test-a5-u.example"
rc, out, err = run(ta, "--add", "--tag", "a5", "--scenario", "accept"); print(out)
l1 = open(ta + "/lists/misp-domain-t1", "rb").read(); l2 = open(ta + "/lists/misp-domain-t2", "rb").read()
check("11a accept --add writes TYPED markers (domain, hostname, upper-case-only domain in t1; domain in t2)", b"ioc-test-a5-d.example:domain\n" in l1 and b"ioc-test-a5-h.example:hostname\n" in l1 and b"ioc-test-a5-u.example:domain\n" in l1 and b"ioc-test-a5-t2.example:domain\n" in l2, (l1, l2))
check("11a block uses ToUpperInvariant and an explicit U+0130 char, no culture-dependent ToUpper()", "ToUpperInvariant()" in out and "[char]0x130" in out and ".ToUpper()" not in out, out)
check("11a block queries all 12 names; the upper-case query is of the marker whose lower-case twin is NEVER queried", all(x in out for x in ["$u.ToUpperInvariant()", '"$d."', '"www.$d"', '"a.b.$d"', '"x$d"', '"$d.attacker.example"', "$h", '"www.$h"', "$t", '"www.$t"', "OC-TEST-A5-D.EXAMPLE"]) and "$d.ToUpperInvariant()" not in out and out.count("$u") == 2, out)
rc, out2, err = run(ta, "--add", "--tag", "a5", "--scenario", "accept")
check("11a accept --add is idempotent", "nothing changed" in out2 and open(ta + "/lists/misp-domain-t1", "rb").read() == l1)

def A(ts, rid, **kw):
    dat = {}
    if "q" in kw: dat = {"win": {"eventdata": {"queryName": kw["q"]}}}
    if "mq" in kw: dat = {"misp_domain": {"query": kw["mq"], "tier": "t1"}}
    return {"timestamp": "2026-10-07T15:00:%02d.000+0300" % ts, "rule": {"id": rid}, "agent": {"name": "CLT601"}, "data": dat}
good = [
 A(1, "100320", q=d), A(2, "100160", q=u.upper()), A(2, "100322", mq=u.upper()), A(3, "100160", q=d + "."), A(3, "100322", mq=d + "."),
 A(4, "100160", q="www." + d), A(4, "100322", mq="www." + d), A(5, "100160", q="a.b." + d), A(5, "100322", mq="a.b." + d),
 A(6, "100160", q="x" + d), A(7, "100160", q=d + ".attacker.example"), A(8, "100320", q=h), A(9, "100160", q="www." + h),
 A(10, "100321", q=t2n), A(11, "100160", q="www." + t2n), A(11, "100323", mq="www." + t2n), A(12, "100160", q="\u0130OC-TEST-A5-D.EXAMPLE"),
]
with open(ta + "/alerts.json", "w") as fh:
    for a in good: fh.write(json.dumps(a) + "\n")
rc, out, err = run(ta, "--report", "--tag", "a5", "--scenario", "accept"); print(out)
check("11b all 12 PASS -> rc 0, summary line", rc == 0 and "12 PASS, 0 FAIL, 0 NOT SEEN" in out and "rule 100324) in alerts.json: 0" in out, out)
check("11b the Turkish-I row is flagged NON-ASCII in the table", "NON-ASCII: U+0130" in out, out)
# a false positive on the label boundary must FAIL
bad = [a for a in good if not (a["rule"]["id"] == "100160" and a["data"]["win"]["eventdata"]["queryName"] == "x" + d)] + [A(6, "100322", mq="x" + d)]
with open(ta + "/alerts.json", "w") as fh:
    for a in bad: fh.write(json.dumps(a) + "\n")
rc, out, err = run(ta, "--report", "--tag", "a5", "--scenario", "accept")
check("11c IOC rule on a name that must not match -> FAIL, rc 1", rc == 1 and "1 FAIL" in out and "must NOT match: 100322" in out, out)
# missing variant and a script failure
part = [a for a in good if not (a["rule"]["id"] == "100322" and a["data"].get("misp_domain", {}).get("query") == "www." + d)]
part.append(A(30, "100324", q=""))
with open(ta + "/alerts.json", "w") as fh:
    for a in part: fh.write(json.dumps(a) + "\n")
rc, out, err = run(ta, "--report", "--tag", "a5", "--scenario", "accept")
check("11d expected IOC rule missing -> FAIL; script failures counted; rc 1", rc == 1 and "expected 100322, got 100160" in out and "(rule 100324) in alerts.json: 1" in out, out)
# cleanup removes the typed markers of the tag and nothing else
rc, out, err = run(ta, "--cleanup", "--tag", "a5")
c1 = open(ta + "/lists/misp-domain-t1", "rb").read(); c2 = open(ta + "/lists/misp-domain-t2", "rb").read()
check("11e cleanup removes all four typed markers, original lines intact", c1 == b"evil-one.com:\nevil-two.net:\n" and c2 == b"raw-list.example.org:\n", (c1, c2))
check("11e cleanup says how many lines it removed", "removed 3 marker line(s) from misp-domain-t1" in out and "removed 1 marker line(s) from misp-domain-t2" in out, out)

# 12 .cdb self-check of --add
def cdb(tdir, tier, content): open(tdir + "/lists/misp-domain-%s.cdb" % tier, "wb").write(content)
tc, *_ = mk()
cdb(tc, "t1", b"evil-one.com\0ioc-test-a6-d.example\0ioc-test-a6-h.example\0ioc-test-a6-u.example\0"); cdb(tc, "t2", b"raw-list.example.org\0ioc-test-a6-t2.example\0")
rc, out, err = run(tc, "--add", "--tag", "a6", "--scenario", "accept")
check("12a markers compiled -> 'yes' for both tiers, block printed, rc 0", rc == 0 and out.count("compiled into") == 2 and "NO" not in out.split("PowerShell")[0].split("compiled into")[1] and "$q = @(" in out, out)
tn, *_ = mk()
cdb(tn, "t1", b"evil-one.com\0"); cdb(tn, "t2", b"raw-list.example.org\0")
import time as _t
t0 = _t.time(); rc, out, err = run(tn, "--add", "--tag", "a6", "--scenario", "accept"); dt = _t.time() - t0
check("12b markers NOT in the .cdb -> STOP, rc 4, the CLT601 block is NOT printed", rc == 4 and "STOP" in out and "$q = @(" not in out and "--diagnose" in out, out)
check("12b it waited for the .cdb (poll timeout) instead of failing instantly", dt >= 5.5, dt)
tw, *_ = mk()
cdb(tw, "t1", b"x"); cdb(tw, "t2", b"x")
now = _t.time(); os.utime(tw + "/lists/misp-domain-t1.cdb", (now, now)); os.utime(tw + "/lists/misp-domain-t2.cdb", (now, now))
rc, out, err = run(tw, "--add", "--tag", "a7")
m1 = os.stat(tw + "/lists/misp-domain-t1").st_mtime
check("12c the list is written in a LATER second than its .cdb (so a reload recompiles it)", int(m1) > int(now), (m1, now))

# 12d a running sync blocks --add
tsr, *_ = mk()
fp = tsr + "/proc"; os.makedirs(fp + "/4242"); open(fp + "/4242/cmdline", "wb").write(b"/usr/bin/python3\0/usr/local/sbin/misp_ioc_sync.py\0--wazuh\0")
os.makedirs(fp + "/1"); open(fp + "/1/cmdline", "wb").write(b"/sbin/init\0")
before = (open(tsr + "/lists/misp-domain-t1", "rb").read(), open(tsr + "/lists/misp-domain-t2", "rb").read())
cmd = [sys.executable, SCRIPT, "--add", "--tag", "a8", "--scenario", "accept", "--lists-dir", tsr + "/lists", "--backup-dir", tsr + "/bak", "--reload-python", tsr + "/py", "--proc-root", fp]
p = subprocess.run(cmd, capture_output=True, text=True)
check("12d sync running -> STOP, rc 5, nothing written", p.returncode == 5 and "STOP: misp_ioc_sync.py is running" in p.stdout and "pid 4242" in p.stdout and (open(tsr + "/lists/misp-domain-t1", "rb").read(), open(tsr + "/lists/misp-domain-t2", "rb").read()) == before and not os.path.exists(tsr + "/reload.called"), p.stdout)
shutil.rmtree(fp); os.makedirs(fp + "/1"); open(fp + "/1/cmdline", "wb").write(b"/sbin/init\0")
p = subprocess.run(cmd, capture_output=True, text=True)
check("12d no sync running -> --add proceeds", p.returncode == 0 and "reload ok" in p.stdout, p.stdout)
cmdd = [sys.executable, SCRIPT, "--diagnose", "--tag", "a8", "--lists-dir", tsr + "/lists", "--ossec-root", tsr + "/root", "--ossec-log", tsr + "/o.log", "--sync-log", tsr + "/s.log", "--proc-root", fp]
check("12d diagnose says no sync running", "sync run in progress right now: no" in subprocess.run(cmdd, capture_output=True, text=True).stdout)
os.makedirs(fp + "/4243"); open(fp + "/4243/cmdline", "wb").write(b"python3\0misp_ioc_sync.py\0")
check("12d diagnose says YES when one is running", "sync run in progress right now: YES (pid 4243)" in subprocess.run(cmdd, capture_output=True, text=True).stdout)

# 12e what counts as "the sync is running" (no false alarms from shells, grep, editors)
import importlib.util
sp = importlib.util.spec_from_file_location("mt", SCRIPT); mt = importlib.util.module_from_spec(sp); sp.loader.exec_module(mt)
cases = [
 (b"/usr/bin/python3\0/usr/local/sbin/misp_ioc_sync.py\0--wazuh\0", True, "the wodle command"),
 (b"python3\0/home/wazuh/misp_ioc_sync_v051.py\0--dry-run\0", True, "a manual run of a renamed copy"),
 (b"/var/ossec/framework/python/bin/python3\0/usr/local/sbin/misp_ioc_sync.py\0", True, "run with Wazuh's python"),
 (b"sh\0-c\0cp -p /usr/local/sbin/misp_ioc_sync.py /root/x && python3 domain_ioc_marker_test.py\0", False, "a shell whose -c text mentions the script"),
 (b"grep\0misp_ioc_sync.py\0notes.txt\0", False, "grep"),
 (b"vim\0/usr/local/sbin/misp_ioc_sync.py\0", False, "an editor"),
 (b"python3\0domain_ioc_marker_test.py\0--sync-log\0/var/log/misp-ioc-sync.log\0", False, "this very tool"),
 (b"sudo\0python3\0/usr/local/sbin/misp_ioc_sync.py\0", False, "the sudo parent (its python3 child is the one counted)"),
 (b"", False, "empty cmdline (kernel thread)"),
]
for cmdline, expected, label in cases:
    check("12e %s -> %s" % (label, "sync" if expected else "not the sync"), mt.is_sync_cmdline(cmdline) == expected)

# 13 diagnose
def diag(tdir, tag="a5", extra=()):
    cmd = [sys.executable, SCRIPT, "--diagnose", "--tag", tag, "--lists-dir", tdir + "/lists", "--ossec-root", tdir + "/root",
           "--ossec-log", tdir + "/ossec.log", "--sync-log", tdir + "/sync.log"] + list(extra)
    p = subprocess.run(cmd, capture_output=True, text=True); return p.returncode, p.stdout
td, *_ = mk()
for sub in ("root/integrations", "root/etc/rules", "root/logs"): os.makedirs(td + "/" + sub)
open(td + "/root/etc/ossec.conf", "w").write("<ossec_config><integration><name>custom-misp-domain</name></integration></ossec_config>")
open(td + "/root/etc/rules/local_rules.xml", "w").write('<rule id="100322"/><rule id="100323"/><rule id="100324"/>')
open(td + "/root/integrations/custom-misp-domain", "w").write("#!/bin/sh\n"); os.chmod(td + "/root/integrations/custom-misp-domain", 0o750)
open(td + "/root/logs/integrations.log", "w").write("2026-10-07 15:00:00 custom-misp-domain: FAILED: OSError: boom\n2026-10-07 15:00:01 other-integration: fine\n")
open(td + "/ossec.log", "w").write("2026/10/07 15:30:00 wazuh-analysisd: INFO: Reloading ruleset\n2026/10/07 15:31:00 wazuh-integratord: ERROR: While running custom-misp-domain -> integrations. Output: boom\n2026/10/07 15:32:00 wazuh-integratord: ERROR: webhook_SECRETUUID never printed\n")
open(td + "/sync.log", "w").write(json.dumps({"ts": "2026-10-07T15:20:00+03:00", "version": "0.5.1", "result": "ok", "changed": True, "reload": "ok", "dry_run": False}) + "\nnot json\n")
# (a) markers wiped from the list
rc, out = diag(td); print(out)
check("13a no marker in the list -> says so (sync rewrote it / add failed)", "marker lines in the list file: 0" in out and "holds no marker" in out, out)
check("13a integration state shown: script, ossec.conf, rules", "script: present, mode 750" in out and "custom-misp-domain x1" in out and 'id="100322"' in out, out)
check("13a sync runs and reload times shown", "result=ok changed=True reload=ok" in out and "last ruleset reloads: 2026/10/07 15:30:00" in out, out)
check("13a only custom-misp-domain log lines, webhook text never printed", "FAILED: OSError: boom" in out and "other-integration" not in out and "SECRETUUID" not in out, out)
# (b) in the list but not compiled
open(td + "/lists/misp-domain-t1", "ab").write(b"ioc-test-a5-d.example:domain\n"); cdb(td, "t1", b"evil-one.com\0")
rc, out = diag(td)
check("13b in the list but not in the .cdb -> says NOT compiled", "markers in the .cdb: 0" in out and "NOT compiled into the .cdb" in out, out)
# (c) fine
cdb(td, "t1", b"evil-one.com\0ioc-test-a5-d.example\0")
now = _t.time() + 5; os.utime(td + "/lists/misp-domain-t1.cdb", (now, now))
rc, out = diag(td)
check("13c in both -> fine", "markers in the .cdb: 1" in out and "-> fine" in out, out)
rc, out = diag(mk()[0], extra=("--ossec-root", "/nonexistent"))
check("13d missing files are reported, not a crash", rc == 0 and "script: MISSING" in out and "cannot read" in out, out)

print("\nFAILED:" if fails else "\nALL PASSED", fails)

raise SystemExit(1 if fails else 0)
