#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
domain_ioc_marker_test.py  (v0.7.1)

End-to-end test of the domain IOC rules (100320 tier 1, 100321 tier 2) with
REAL DNS queries, no synthetic event injection.

  --add      appends one harmless marker name per tier to the live CDB lists
             (reserved ".example" TLD, so it can never match real traffic),
             hot-reloads the ruleset, and prints the PowerShell commands to run
             on the client.
  --report   reads the manager's alerts.json and prints which rule fired for
             every DNS query that carried the marker name, plus a per-variant
             verdict.
  --cleanup  removes exactly the marker lines again and hot-reloads.
  --health   read-only check of the integratord daemon and the alert stream:
             whether integratord still reads the LIVE alerts.json (a restart can
             leave it on a deleted file, see wazuh/wazuh#35834), how far it
             lags, how many alert lines exceed 2 KB, and how often ossec.log
             reports integratord problems. Prints numbers only, no secrets.
  --diagnose read-only: are the markers in the list files and compiled into the .cdb,
             is the integration installed, when did the sync run, what do the logs say.
  --rate     measures how many rule 100160 alerts (one per non-excluded DNS
             query) the manager produces per minute and per second, from
             alerts.json. Read-only; needs no marker.

The next sync run (misp_ioc_sync.py) would rewrite the lists without the
markers anyway; --cleanup just does it immediately.

Reload uses Wazuh's own embedded Python and the same framework call as
misp_ioc_sync.py (no API credentials, no restart).
"""
from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

__version__ = "0.7.1"

RELOAD_CODE = (
    "import asyncio, json\n"
    "from wazuh.core.analysis import send_reload_ruleset_msg\n"
    "r = asyncio.run(send_reload_ruleset_msg({'name': 'domain-ioc-marker-test', 'module': 'framework'}))\n"
    "print(json.dumps({'ok': bool(r.is_ok()), 'message': str(r.message), "
    "'warnings': list(r.warnings), 'errors': list(r.errors)}))\n"
)

RULES = ("100160", "100320", "100321", "100322", "100323", "100324")
IOC_RULES = ("100320", "100321", "100322", "100323")


def names(tag):
    return {"t1": "ioc-test-%s-t1.example" % tag, "t2": "ioc-test-%s-t2.example" % tag}


def accept_names(tag):
    """domain marker, hostname marker, tier 2 marker, and a marker that is queried ONLY in
    upper case (its lower-case twin is never queried, so the Windows DNS cache cannot hide
    the upper-case query)."""
    return ("ioc-test-%s-d.example" % tag, "ioc-test-%s-h.example" % tag,
            "ioc-test-%s-t2.example" % tag, "ioc-test-%s-u.example" % tag)


def markers_for(args):
    """{tier: [marker line as bytes]}. The accept scenario writes TYPED entries
    (name:domain / name:hostname) like misp_ioc_sync.py v0.5 does; the older scenarios keep
    the empty value."""
    if args.scenario == "accept":
        d, h, t, u = accept_names(args.tag)
        return {"t1": [("%s:domain\n" % d).encode(), ("%s:hostname\n" % h).encode(),
                       ("%s:domain\n" % u).encode()],
                "t2": [("%s:domain\n" % t).encode()]}
    n = names(args.tag)
    return {"t1": [("%s:\n" % n["t1"]).encode()], "t2": [("%s:\n" % n["t2"]).encode()]}


def strip_markers(data, tag):
    """Remove every line of this tag (any scenario)."""
    prefix = ("ioc-test-%s-" % tag).encode()
    lines = data.splitlines(keepends=True)
    kept = [ln for ln in lines if not ln.startswith(prefix)]
    return b"".join(kept), len(lines) - len(kept)


def list_path(args, tier):
    return os.path.join(args.lists_dir, "misp-domain-%s" % tier)


def atomic_replace(path, data, ref):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, ref.st_mode & 0o7777)
        try:
            os.chown(tmp, ref.st_uid, ref.st_gid)
        except OSError:
            pass
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def hot_reload(args):
    """Return (ok, text)."""
    py = args.reload_python
    if not os.path.exists(py):
        return False, "Wazuh python not found: %s" % py
    try:
        proc = subprocess.run([py, "-c", RELOAD_CODE], capture_output=True, text=True,
                              timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "reload failed to run: %s" % exc
    reply = None
    for line in reversed(proc.stdout.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                reply = json.loads(line)
                break
            except ValueError:
                continue
    if proc.returncode != 0 or reply is None:
        tail = (proc.stderr or proc.stdout).strip().replace("\n", " ")[-200:]
        return False, "reload failed (exit %s): %s" % (proc.returncode, tail)
    if not reply.get("ok"):
        detail = "; ".join(str(e) for e in reply.get("errors", [])) or str(reply.get("message", ""))
        return False, "analysisd refused the reload: %s" % detail[:200]
    return True, "reload ok"


def load_lists(args):
    out = {}
    for tier in ("t1", "t2"):
        p = list_path(args, tier)
        if not os.path.isfile(p):
            raise SystemExit("ABORT: list file missing: %s (run misp_ioc_sync.py first)" % p)
        with open(p, "rb") as fh:
            out[tier] = (fh.read(), os.stat(p))
    return out


def mixed(tag, i):
    return "Ioc-Test-%s-Mixed%d.Example" % (tag, i)


def powershell(tag, scenario="basic"):
    n = names(tag)
    if scenario == "accept":
        d, h, t, u = accept_names(tag)
        return (
            "$d = '%s'; $h = '%s'; $t = '%s'; $u = '%s'\n"
            "$q = @($d, \"$d.\", \"www.$d\", \"a.b.$d\", \"x$d\", \"$d.attacker.example\", "
            "$h, \"www.$h\", $t, \"www.$t\", $u.ToUpperInvariant(), "
            "(([string][char]0x130) + 'OC-TEST-%s-D.EXAMPLE'))\n"
            "foreach ($n in $q) { Resolve-DnsName $n -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null }"
            % (d, h, t, u, tag.upper()))
    if scenario == "caps":
        return (
            "Resolve-DnsName 'ioc-test-%s-warmup.example' -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null\n"
            "Resolve-DnsName 'IOC-TEST-%s-ALLCAPS1.EXAMPLE' -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null\n"
            "ping -n 1 -w 500 'IOC-TEST-%s-ALLCAPS2.EXAMPLE' | Out-Null\n"
            "ping -n 1 -w 500 'Ioc-Test-%s-T2.Example' | Out-Null"
            % (tag, tag.upper(), tag.upper(), tag))
    if scenario == "case":
        return (
            "$n = '%s'\n"
            "Resolve-DnsName $n.ToUpperInvariant() -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null\n"
            "ping -n 1 -w 500 '%s' | Out-Null\n"
            "try { [System.Net.Dns]::GetHostAddresses('%s') | Out-Null } catch {}\n"
            "Resolve-DnsName '%s' -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null"
            % (n["t1"], mixed(tag, 1), mixed(tag, 2), mixed(tag, 3)))
    return (
        "$n = '%s'\n"
        "Resolve-DnsName $n.ToUpperInvariant() -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null\n"
        "Resolve-DnsName ($n + '.') -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null\n"
        "Resolve-DnsName ('www.' + $n) -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null\n"
        "Resolve-DnsName $n -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null\n"
        "Resolve-DnsName '%s' -Type A -DnsOnly -ErrorAction SilentlyContinue | Out-Null"
        % (n["t1"], n["t2"]))


SYNC_SCRIPT_RE = re.compile(r"^misp_ioc_sync[\w.-]*\.py$")
PYTHON_RE = re.compile(r"^python[0-9.]*$")


def is_sync_cmdline(cmd):
    """True for `python3 .../misp_ioc_sync*.py ...` and nothing else. Matching the text anywhere
    in the command line would also catch `sh -c '...misp_ioc_sync.py...'`, grep, tail and so on."""
    args = [a.decode("utf-8", "replace") for a in cmd.split(b"\0") if a]
    if len(args) < 2 or not PYTHON_RE.match(os.path.basename(args[0])):
        return False
    return any(SYNC_SCRIPT_RE.match(os.path.basename(a)) for a in args[1:])


def sync_running(proc_root):
    """PIDs of a running misp_ioc_sync.py. A sync run lasts ~100 s and, when it ends, rewrites the
    lists WITHOUT any marker added meanwhile (observed 7 Oct 2026, run a5)."""
    pids = []
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return pids
    for e in entries:
        if not e.isdigit():
            continue
        try:
            with open(os.path.join(proc_root, e, "cmdline"), "rb") as fh:
                cmd = fh.read()
        except OSError:
            continue
        if is_sync_cmdline(cmd):
            pids.append(e)
    return pids


def wait_next_second(path):
    """A reload recompiles a list only when it is newer than its .cdb, compared at whole-second
    resolution (observed on 7 Oct 2026, see the a3 run): never write within the .cdb's second."""
    try:
        sec = int(os.stat(path).st_mtime)
    except OSError:
        return
    while int(time.time()) <= sec:
        time.sleep(0.2)


def cdb_has(args, tier, lines, timeout=6.0):
    """True/False: are all marker keys inside the compiled .cdb. None: no .cdb to look at."""
    cp = list_path(args, tier) + ".cdb"
    if not os.path.exists(cp):
        return None
    keys = [ln.split(b":")[0] for ln in lines]
    end = time.time() + timeout
    while True:
        with open(cp, "rb") as fh:
            blob = fh.read()
        if all(k in blob for k in keys):
            return True
        if time.time() > end:
            return False
        time.sleep(0.5)


def do_add(args):
    running = sync_running(args.proc_root)
    if running:
        print("STOP: misp_ioc_sync.py is running right now (pid %s). When it finishes it rewrites the "
              "lists and removes any marker added meanwhile. Wait until it is done (about 100 s after "
              "a manager start), then run this again. Nothing was changed." % ", ".join(running))
        return 5
    lists = load_lists(args)
    marks = markers_for(args)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    changed = False
    for tier in ("t1", "t2"):
        data, st = lists[tier]
        missing = [ln for ln in marks[tier] if ln not in data]
        if not missing:
            print("markers already present in misp-domain-%s" % tier)
            continue
        if not data.endswith(b"\n") and data:
            data += b"\n"
        p = list_path(args, tier)
        shutil.copy2(p, os.path.join(args.backup_dir, "misp-domain-%s.bak-%s" % (tier, ts)))
        wait_next_second(p + ".cdb")
        atomic_replace(p, data + b"".join(missing), st)
        changed = True
        print("added to misp-domain-%s: %s" % (tier, ", ".join(ln.decode().strip() for ln in missing)))
    if changed:
        ok, text = hot_reload(args)
        print(text)
        if not ok:
            print("The markers are in the lists but the reload failed. Run --cleanup, "
                  "then check ossec.log.")
            return 3
    else:
        print("nothing changed, no reload")
    verdicts = {t: cdb_has(args, t, marks[t]) for t in ("t1", "t2")}
    for t, v in verdicts.items():
        print("markers compiled into misp-domain-%s.cdb: %s" % (
            t, {True: "yes", False: "NO", None: "cannot verify (no .cdb file)"}[v]))
    if any(v is False for v in verdicts.values()):
        print("\nSTOP: the markers are NOT in the compiled list, so the CDB rules cannot match them. "
              "Do not run anything on CLT601. Likely causes: a sync run rewrote the list right after "
              "this command, or the reload did not recompile. Run --diagnose and send me the output.")
        return 4
    print("\nRun on CLT601 (PowerShell):\n")
    print(powershell(args.tag, args.scenario))
    print("\nThen wait about a minute and run:  sudo python3 %s --report --tag %s --scenario %s"
          % (os.path.basename(sys.argv[0]), args.tag, args.scenario))
    return 0


def do_cleanup(args):
    lists = load_lists(args)
    changed = False
    for tier in ("t1", "t2"):
        data, st = lists[tier]
        new, removed = strip_markers(data, args.tag)
        if not removed:
            print("no marker in misp-domain-%s" % tier)
            continue
        atomic_replace(list_path(args, tier), new, st)
        changed = True
        print("removed %d marker line(s) from misp-domain-%s" % (removed, tier))
    if changed:
        ok, text = hot_reload(args)
        print(text)
        return 0 if ok else 3
    return 0


def do_report(args):
    n = names(args.tag)
    needle = "oc-test-%s" % args.tag      # no leading 'i': a Turkish 'İ' would not lower-case to 'i'
    rows = []
    try:
        with open(args.alerts, "r", errors="replace") as fh:
            for ln in fh:
                if needle not in ln.lower():
                    continue
                try:
                    a = json.loads(ln)
                except ValueError:
                    continue
                rid = str(a.get("rule", {}).get("id", ""))
                if rid not in RULES:
                    continue
                dat = a.get("data", {}) or {}
                qn = (dat.get("win", {}).get("eventdata", {}) or {}).get("queryName", "")
                if not qn:
                    qn = (dat.get("misp_domain", {}) or {}).get("query", "")
                rows.append((a.get("timestamp", ""), rid, qn, a.get("agent", {}).get("name", "")))
    except OSError as exc:
        print("ABORT: cannot read %s: %s" % (args.alerts, exc))
        return 2
    if not rows:
        print("no alerts carry the marker (no Event 22 reached Wazuh, or the rules did not load)")
        return 1
    print("alerts carrying the marker (rule 100160 = every DNS query, 100320/100321 = IOC hit):")
    for ts, rid, qn, agent in sorted(rows):
        flag = ""
        if not qn.isascii():
            flag = "   <-- NON-ASCII: " + " ".join("U+%04X" % ord(c) for c in qn if ord(c) > 127)
        print("  %s  rule %s  agent=%s  queryName=%s%s" % (ts[:23], rid, agent, qn, flag))
    if args.scenario == "accept":
        return report_accept(args, rows)
    if args.scenario == "caps":
        variants = (
            ("warm-up, lowercase, Resolve-DnsName (first query of the block)", "ioc-test-%s-warmup.example" % args.tag),
            ("ALL CAPS, Resolve-DnsName", "IOC-TEST-%s-ALLCAPS1.EXAMPLE" % args.tag.upper()),
            ("ALL CAPS, ping", "IOC-TEST-%s-ALLCAPS2.EXAMPLE" % args.tag.upper()),
            ("mixed case of the tier 2 marker, ping (100321 only if the CDB lookup is case-insensitive)", "Ioc-Test-%s-T2.Example" % args.tag),
        )
    elif args.scenario == "case":
        variants = (
            ("UPPER CASE of the tier 1 marker, Resolve-DnsName (expected 100320 only if CDB is case-insensitive)", n["t1"].upper()),
            ("mixed case, ping", mixed(args.tag, 1)),
            ("mixed case, .NET Dns", mixed(args.tag, 2)),
            ("mixed case, Resolve-DnsName", mixed(args.tag, 3)),
        )
    else:
        variants = (
            ("tier 1, exact name (expected: 100320)", n["t1"]),
            ("tier 1, UPPER CASE (case sensitivity)", n["t1"].upper()),
            ("tier 1, trailing dot", n["t1"] + "."),
            ("tier 1, www. subdomain (expected: NO IOC hit, partial coverage)", "www." + n["t1"]),
            ("tier 2, exact name (expected: 100321)", n["t2"]),
        )
    print("\nper variant:")
    for label, qn in variants:
        print("  %s\n      -> %s" % (label, verdict(rows, qn)))
    print("\nA name logged exactly as sent means Windows preserved it; 'seen as' means the "
          "name was logged in a different form (case or trailing dot changed).")
    return 0


def accept_variants(tag):
    d, h, t, u = accept_names(tag)
    return (
        ("domain marker, exact lowercase (answered by the CDB rule)", d, "100320"),
        ("domain marker, trailing dot", d + ".", "100322"),
        ("domain marker, www. subdomain", "www." + d, "100322"),
        ("domain marker, two-level subdomain", "a.b." + d, "100322"),
        ("a letter glued in front of the domain marker (label boundary)", "x" + d, None),
        ("domain marker as the start of a longer name", d + ".attacker.example", None),
        ("hostname marker, exact", h, "100320"),
        ("hostname marker, www. subdomain (hostname = exact only)", "www." + h, None),
        ("tier 2 domain marker, exact", t, "100321"),
        ("tier 2 domain marker, www. subdomain", "www." + t, "100323"),
        ("domain marker queried ONLY in ASCII UPPER CASE (case folding; the CDB cannot match it)", u.upper(), "100322"),
        ("Turkish dotted capital I (U+0130) instead of I", "\u0130OC-TEST-%s-D.EXAMPLE" % tag.upper(), None),
    )


def judge(rows, qn, expected):
    fired = sorted({rid for _t, rid, q, _a in rows if q == qn})
    if not fired:
        return "NOT SEEN", "no event reached Wazuh for this exact name"
    if expected is None:
        bad = [r for r in fired if r in IOC_RULES]
        if bad:
            return "FAIL", "an IOC rule fired on a name that must NOT match: %s" % ", ".join(bad)
        return "PASS", "no IOC rule, as intended (rules: %s)" % ", ".join(fired)
    if expected in fired:
        return "PASS", "rules: %s" % ", ".join(fired)
    return "FAIL", "expected %s, got %s" % (expected, ", ".join(fired))


def report_accept(args, rows):
    print("\nacceptance test, one line per query:")
    counts = {"PASS": 0, "FAIL": 0, "NOT SEEN": 0}
    for label, qn, expected in accept_variants(args.tag):
        verdict_word, detail = judge(rows, qn, expected)
        counts[verdict_word] += 1
        want = "an IOC rule %s" % expected if expected else "NO IOC rule"
        print("  [%-8s] %s\n             name: %s | wanted: %s | %s" % (verdict_word, label, qn, want, detail))
    failures = 0
    try:
        with open(args.alerts, "r", errors="replace") as fh:
            failures = sum(1 for ln in fh if '"100324"' in ln)
    except OSError:
        pass
    print("\nsummary: %d PASS, %d FAIL, %d NOT SEEN | integration failures (rule 100324) in alerts.json: %d"
          % (counts["PASS"], counts["FAIL"], counts["NOT SEEN"], failures))
    return 0 if counts["FAIL"] == 0 and counts["NOT SEEN"] == 0 and failures == 0 else 1


def norm(x):
    return x.lower().rstrip(".")


def verdict(rows, qn):
    fired = sorted({rid for _t, rid, q, _a in rows if q == qn})
    if fired:
        return "logged exactly as sent, rules: %s" % ", ".join(fired)
    alt = sorted({(q, rid) for _t, rid, q, _a in rows if norm(q) == norm(qn)})
    if alt:
        return "NOT SEEN as that exact string; seen as: " + "; ".join(
            "%s (rule %s)" % (q, rid) for q, rid in alt)
    return "NOT SEEN (no Event 22 reached Wazuh for this query)"


INTEGRATORD = "wazuh-integratord"
ALERTS_FILE_RE = re.compile(r"alerts[^/]*\.json(\.gz)?( \(deleted\))?$")


def is_integratord(proc_root, pid):
    """/proc/<pid>/comm is cut to 15 characters on Linux ('wazuh-integrato'), so the
    full name only shows up in cmdline. Accept either."""
    try:
        with open(os.path.join(proc_root, pid, "cmdline"), "rb") as fh:
            argv0 = fh.read().split(b"\0")[0].decode("utf-8", "replace")
        if os.path.basename(argv0) == INTEGRATORD:
            return True
    except OSError:
        pass
    try:
        with open(os.path.join(proc_root, pid, "comm")) as fh:
            comm = fh.read().strip()
        return comm in (INTEGRATORD, INTEGRATORD[:15])
    except OSError:
        return False


def find_integratord(proc_root):
    pids = []
    try:
        entries = os.listdir(proc_root)
    except OSError:
        return pids
    for e in entries:
        if e.isdigit() and is_integratord(proc_root, e):
            pids.append(e)
    return pids


def alerts_fds(proc_root, pid):
    """Open file descriptors of this process that point at an alerts.json."""
    base = os.path.join(proc_root, pid, "fd")
    found = []
    try:
        fds = os.listdir(base)
    except OSError as exc:
        return None, "cannot read %s: %s (run as root)" % (base, exc)
    for fd in fds:
        path = os.path.join(base, fd)
        try:
            target = os.readlink(path)
        except OSError:
            continue
        # alerts.json itself, its daily rotation (ossec-alerts-DD.json), or either of
        # them with a " (deleted)" suffix: a process left on a rotated or deleted file
        # must show up as STALE, not as "no descriptor"
        if not ALERTS_FILE_RE.search(target):
            continue
        info = {"fd": fd, "target": target, "deleted": target.endswith(" (deleted)"),
                "inode": None, "size": None, "pos": None}
        try:
            st = os.stat(path)
            info["inode"] = st.st_ino
            info["size"] = st.st_size
        except OSError:
            pass
        try:
            with open(os.path.join(proc_root, pid, "fdinfo", fd)) as fh:
                for ln in fh:
                    if ln.startswith("pos:"):
                        info["pos"] = int(ln.split()[1])
        except (OSError, ValueError, IndexError):
            pass
        found.append(info)
    return found, None


def do_health(args):
    print("== integratord process and the alert file it reads ==")
    pids = find_integratord(args.proc_root)
    try:
        live = os.stat(args.alerts)
    except OSError as exc:
        print("ABORT: cannot stat %s: %s" % (args.alerts, exc))
        return 2
    if not pids:
        print("  wazuh-integratord is NOT running")
    for pid in pids:
        fds, err = alerts_fds(args.proc_root, pid)
        if err:
            print("  pid %s: %s" % (pid, err))
            continue
        if not fds:
            print("  pid %s: no open alerts.json descriptor found" % pid)
        for f in fds:
            print("  pid %s fd %s -> %s" % (pid, f["fd"], f["target"]))
            if f["inode"] is None:
                print("      verdict: STALE (the file behind the descriptor cannot be stat'ed)")
            elif f["inode"] != live.st_ino:
                print("      verdict: STALE (different file: descriptor inode %d, live alerts.json inode %d)"
                      % (f["inode"], live.st_ino))
                print("      the descriptor's file is %d bytes and no longer receives the live alerts" % f["size"])
            else:
                note = ""
                if f["deleted"]:
                    note = (" The name shows '(deleted)': the path was unlinked and created again, but "
                            "it is the same inode, so integratord still reads the live data.")
                print("      verdict: OK (same inode %d as the live alerts.json, %d hard link(s)).%s"
                      % (live.st_ino, live.st_nlink, note))
                if f["pos"] is not None:
                    print("      read position %d of %d bytes (unread: %d bytes)"
                          % (f["pos"], live.st_size, live.st_size - f["pos"]))

    print("\n== alert line lengths in %s (bytes per JSON line) ==" % args.alerts)
    total = long2k = long4k = maxlen = 0
    r_n = r_sum = r_max = r_long = 0
    long_by_rule = {}
    try:
        with open(args.alerts, "rb") as fh:
            for ln in fh:
                n = len(ln.rstrip(b"\n"))
                total += 1
                maxlen = max(maxlen, n)
                is_160 = b'"100160"' in ln
                if n > 2048:
                    long2k += 1
                    if n > 4096:
                        long4k += 1
                    try:
                        rid = str(json.loads(ln).get("rule", {}).get("id", "?"))
                    except ValueError:
                        rid = "unparsable"
                    long_by_rule[rid] = long_by_rule.get(rid, 0) + 1
                if is_160:
                    r_n += 1
                    r_sum += n
                    r_max = max(r_max, n)
                    if n > 2048:
                        r_long += 1
    except OSError as exc:
        print("ABORT: cannot read %s: %s" % (args.alerts, exc))
        return 2
    print("  alert lines: %d, longer than 2048: %d, longer than 4096: %d, longest: %d" % (total, long2k, long4k, maxlen))
    if r_n:
        print("  rule 100160 lines: %d, average %d, longest %d, longer than 2048: %d" % (r_n, r_sum // r_n, r_max, r_long))
    else:
        print("  rule 100160 lines: 0")
    if long_by_rule:
        top = sorted(long_by_rule.items(), key=lambda kv: -kv[1])[:5]
        print("  rules producing the long lines: " + ", ".join("%s x%d" % kv for kv in top))

    print("\n== integratord messages in %s (counts and last timestamp only) ==" % args.ossec_log)
    inv = err_n = 0
    inv_last = err_last = "-"
    try:
        with open(args.ossec_log, "r", errors="replace") as fh:
            for ln in fh:
                if "wazuh-integratord" not in ln:
                    continue
                if "Invalid JSON alert" in ln:
                    inv += 1
                    inv_last = ln[:19]
                elif "ERROR" in ln:
                    err_n += 1
                    err_last = ln[:19]
    except OSError as exc:
        print("  cannot read %s: %s" % (args.ossec_log, exc))
        return 0
    print("  'Invalid JSON alert' warnings: %d (last %s)" % (inv, inv_last))
    print("  integratord ERROR lines: %d (last %s)" % (err_n, err_last))
    return 0


def do_diagnose(args):
    import pwd, grp
    prefix = ("ioc-test-%s-" % args.tag).encode()
    running = sync_running(args.proc_root)
    print("== sync run in progress right now: %s ==" % ("YES (pid %s)" % ", ".join(running) if running else "no"))
    print("== markers of tag %s in the lists and in the compiled .cdb ==" % args.tag)
    for tier in ("t1", "t2"):
        lp = list_path(args, tier)
        cp = lp + ".cdb"
        try:
            with open(lp, "rb") as fh:
                ldata = fh.read()
            lst = os.stat(lp)
        except OSError as exc:
            print("  misp-domain-%s: cannot read the list: %s" % (tier, exc))
            continue
        in_list = sum(1 for ln in ldata.splitlines() if ln.startswith(prefix))
        line = "  misp-domain-%s: marker lines in the list file: %d, list written %s" % (
            tier, in_list, time.strftime("%H:%M:%S", time.localtime(lst.st_mtime)))
        try:
            with open(cp, "rb") as fh:
                cdata = fh.read()
            cst = os.stat(cp)
            in_cdb = cdata.count(prefix)
            line += " | markers in the .cdb: %d, .cdb compiled %s" % (
                in_cdb, time.strftime("%H:%M:%S", time.localtime(cst.st_mtime)))
            print(line)
            if in_list == 0:
                print("      -> the list file holds no marker: it was rewritten after they were added "
                      "(sync run) or --add never succeeded")
            elif in_cdb == 0:
                print("      -> markers are in the list but NOT compiled into the .cdb (CDB rules cannot match)")
            elif int(cst.st_mtime) < int(lst.st_mtime):
                print("      -> the .cdb is older than the list: a reload may not have recompiled it")
            else:
                print("      -> fine")
        except OSError as exc:
            print(line + " | no .cdb: %s" % exc)
            if in_list == 0:
                print("      -> the list file holds no marker: it was rewritten after they were added "
                      "(sync run) or --add never succeeded")

    print("\n== integration installed? ==")
    root = args.ossec_root
    script = os.path.join(root, "integrations", "custom-misp-domain")
    try:
        st = os.stat(script)
        try:
            who = "%s:%s" % (pwd.getpwuid(st.st_uid).pw_name, grp.getgrgid(st.st_gid).gr_name)
        except KeyError:
            who = "%d:%d" % (st.st_uid, st.st_gid)
        print("  script: present, mode %o, owner %s, %d bytes" % (st.st_mode & 0o7777, who, st.st_size))
    except OSError:
        print("  script: MISSING (%s)" % script)
    for label, path, needles in (("ossec.conf", os.path.join(root, "etc", "ossec.conf"), ("custom-misp-domain",)),
                                 ("local_rules.xml", os.path.join(root, "etc", "rules", "local_rules.xml"),
                                  ('id="100322"', 'id="100323"', 'id="100324"'))):
        try:
            with open(path, "r", errors="replace") as fh:
                text = fh.read()
            print("  %s: %s" % (label, ", ".join("%s x%d" % (n, text.count(n)) for n in needles)))
        except OSError as exc:
            print("  %s: cannot read (%s)" % (label, exc))

    print("\n== last sync runs (%s) ==" % args.sync_log)
    try:
        with open(args.sync_log, "r", errors="replace") as fh:
            tail = fh.read().splitlines()[-4:]
        for ln in tail:
            try:
                j = json.loads(ln)
                print("  %s v%s result=%s changed=%s reload=%s dry_run=%s" % (
                    j.get("ts", "?"), j.get("version", "?"), j.get("result"), j.get("changed"),
                    j.get("reload"), j.get("dry_run")))
            except ValueError:
                print("  (unparsable line)")
    except OSError as exc:
        print("  cannot read: %s" % exc)

    print("\n== logs (only lines about custom-misp-domain and ruleset reloads; nothing else) ==")
    try:
        with open(os.path.join(root, "logs", "integrations.log"), "r", errors="replace") as fh:
            mine = [ln.rstrip()[:170] for ln in fh if "custom-misp-domain" in ln][-3:]
        print("  integrations.log: %s" % ("none" if not mine else ""))
        for ln in mine:
            print("    " + ln)
    except OSError as exc:
        print("  integrations.log: cannot read (%s)" % exc)
    try:
        mentions, reloads = [], []
        with open(args.ossec_log, "r", errors="replace") as fh:
            for ln in fh:
                if "custom-misp-domain" in ln:
                    mentions.append(ln.rstrip()[:170])
                if "wazuh-analysisd: INFO: Reloading ruleset" in ln:
                    reloads.append(ln[:19])
        print("  ossec.log lines mentioning custom-misp-domain: %d" % len(mentions))
        for ln in mentions[-3:]:
            print("    " + ln)
        print("  last ruleset reloads: %s" % (", ".join(reloads[-4:]) if reloads else "none"))
    except OSError as exc:
        print("  ossec.log: cannot read (%s)" % exc)
    return 0


def do_rate(args):
    from collections import Counter
    per_sec, per_min = Counter(), Counter()
    total = 0
    try:
        with open(args.alerts, "r", errors="replace") as fh:
            for ln in fh:
                if '"100160"' not in ln:
                    continue
                try:
                    a = json.loads(ln)
                except ValueError:
                    continue
                if str(a.get("rule", {}).get("id", "")) != "100160":
                    continue
                ts = a.get("timestamp", "")
                if len(ts) < 19:
                    continue
                total += 1
                per_sec[ts[:19]] += 1
                per_min[ts[:16]] += 1
    except OSError as exc:
        print("ABORT: cannot read %s: %s" % (args.alerts, exc))
        return 2
    if not total:
        print("no rule 100160 alerts in %s" % args.alerts)
        return 1
    first, last = min(per_sec), max(per_sec)
    minutes = len(per_min)
    peak_s = per_sec.most_common(1)[0]
    peak_m = per_min.most_common(1)[0]
    print("rule 100160 alerts in %s: %d" % (args.alerts, total))
    print("  first %s, last %s (%d distinct minutes with at least one alert)" % (first, last, minutes))
    print("  average per active minute: %.1f" % (total / minutes))
    print("  peak per minute: %d (%s)" % (peak_m[1], peak_m[0]))
    print("  peak per second: %d (%s)" % (peak_s[1], peak_s[0]))
    for threshold in (3, 7, 20):
        n = sum(1 for v in per_sec.values() if v >= threshold)
        print("  seconds with >= %d alerts: %d" % (threshold, n))
    print("Note: one 100160 alert = one DNS query that the rule's exclusion filter let through.")
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="Real-DNS marker test for domain IOC rules")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--add", action="store_true")
    g.add_argument("--report", action="store_true")
    g.add_argument("--cleanup", action="store_true")
    g.add_argument("--rate", action="store_true")
    g.add_argument("--health", action="store_true")
    g.add_argument("--diagnose", action="store_true")
    ap.add_argument("--tag", default="a1", help="changes the marker names (default a1)")
    ap.add_argument("--scenario", choices=("basic", "case", "caps", "accept"), default="basic",
                    help="basic = exact/upper/trailing dot/www/tier 2; case = case preservation "
                         "across three Windows resolver APIs; caps = warm-up first, ALL CAPS "
                         "visibility, mixed-case tier 2 marker; accept = acceptance test of rules "
                         "100320-100323 with typed markers, PASS/FAIL per query")
    ap.add_argument("--lists-dir", default="/var/ossec/etc/lists")
    ap.add_argument("--alerts", default="/var/ossec/logs/alerts/alerts.json")
    ap.add_argument("--ossec-log", default="/var/ossec/logs/ossec.log")
    ap.add_argument("--ossec-root", default="/var/ossec")
    ap.add_argument("--sync-log", default="/var/log/misp-ioc-sync.log")
    ap.add_argument("--proc-root", default="/proc", help=argparse.SUPPRESS)
    ap.add_argument("--backup-dir", default="/root")
    ap.add_argument("--reload-python", default="/var/ossec/framework/python/bin/python3")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = ap.parse_args(argv)
    if args.add:
        return do_add(args)
    if args.cleanup:
        return do_cleanup(args)
    if args.rate:
        return do_rate(args)
    if args.health:
        return do_health(args)
    if args.diagnose:
        return do_diagnose(args)
    return do_report(args)


if __name__ == "__main__":
    sys.exit(main())
