#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
install_domain_integration.py  (v0.1)

Installs the custom-misp-domain integration into a Wazuh manager:
  1. /var/ossec/integrations/custom-misp-domain  (embedded below, root:wazuh, mode 750)
  2. an <integration> block in ossec.conf, filtered on rule 100160, JSON alert format
  3. rules 100322 (tier 1 hit, level 10), 100323 (tier 2 hit, level 7) and 100324
     (script failure, level 12) appended to local_rules.xml

Safety: every precondition is checked before anything is written (lists exist and carry
the "name:domain"/"name:hostname" types, rule ids free, nothing installed yet). The two
config files are backed up, `wazuh-analysisd -t` is run, and if it fails everything is
restored byte for byte and the script is removed. `wazuh-analysisd -t` does NOT validate
the <integration> block, and the manager is NOT restarted here: an integration change
needs a restart (Wazuh documentation), which is a separate, visible step.
"""
import argparse
import datetime
import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

__version__ = "0.1"
SCRIPT_NAME = "custom-misp-domain"
RULE_IDS = ("100322", "100323", "100324")

SCRIPT_TEXT = r'''#!/var/ossec/framework/python/bin/python3
# -*- coding: utf-8 -*-
"""
custom-misp-domain  (v0.1)

Wazuh custom integration (integratord runs it once per matching alert).
Input : an alert of rule 100160 (one per Sysmon Event 22 DNS query), as a JSON file
        whose path is argv[1].
Output: when the queried name matches a MISP domain list, ONE event is written back
        to the manager's local queue socket, attributed to the agent that asked. Rules
        100322 / 100323 turn it into an alert; rule 100324 reports a script failure.

Why it exists: Wazuh CDB lookups are exact and case-sensitive and cannot do suffix
matching, and a decoder cannot post-process Windows event fields. This script adds the
missing part of the match, nothing else.

Matching (language independent, RFC 4343):
  * case: only the ASCII letters A-Z are folded, never a language-specific mapping
    (Turkish dotted/dotless i, Latin-1 accents ...). No locale and no str.lower() is used.
  * one trailing dot is ignored.
  * names with non-ASCII characters go through the IDNA transformation to their ASCII
    form (xn--...), the same transformation the list builder (misp_ioc_sync.py) applies.
  * the full name is looked up first, in any list entry type. Then the parent names,
    always on a label boundary and never down to the bare TLD, but ONLY against entries
    of type "domain" (a MISP "hostname" entry means that exact host only).
  * tier 1 is searched before tier 2.

The lists are the plain files written by misp_ioc_sync.py ("name:domain" or
"name:hostname", sorted). They are read with a byte search, not loaded into a dict.
"""
import json
import os
import socket
import string
import sys
import time

NAME = "custom-misp-domain"
LOCATION = "misp-domain"
PWD = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))     # /var/ossec
LISTS = os.path.join(PWD, "etc", "lists")
SOCKET_ADDR = os.path.join(PWD, "queue", "sockets", "queue")
LOG_FILE = os.path.join(PWD, "logs", "integrations.log")
TIERS = ("t1", "t2")
ASCII_FOLD = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def log(msg):
    try:
        with open(LOG_FILE, "a") as fh:
            fh.write("%s %s: %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), NAME, msg))
    except OSError:
        pass


def normalize(name):
    """ASCII-only case fold, one trailing dot dropped, IDNA for non-ASCII."""
    n = name.translate(ASCII_FOLD)
    if n.endswith("."):
        n = n[:-1]
    if not n.isascii():
        try:
            n = n.encode("idna").decode("ascii").translate(ASCII_FOLD)
        except UnicodeError:
            return n, False
    return n, True


def candidates(n):
    labels = n.split(".")
    # the name itself, then its parents with at least two labels left
    return [n] + [".".join(labels[i:]) for i in range(1, len(labels) - 1)]


def read_list(tier):
    with open(os.path.join(LISTS, "misp-domain-%s" % tier), "rb") as fh:
        return b"\n" + fh.read()


def find(blob, cand):
    """Entry type for cand, or None. The key starts at a line start and ends at ':', so
    'evil.com' can never match inside 'notevil.com'."""
    key = ("\n" + cand + ":").encode("utf-8")
    i = blob.find(key)
    if i < 0:
        return None
    j = i + len(key)
    k = blob.find(b"\n", j)
    value = blob[j:k if k >= 0 else len(blob)].decode("ascii", "replace").strip()
    return value if value in ("domain", "hostname") else "hostname"      # unknown: exact only


def match(n, blobs):
    cands = candidates(n)
    for tier in TIERS:
        for idx, cand in enumerate(cands):
            typ = find(blobs[tier], cand)
            if typ is None:
                continue
            if idx == 0:
                return tier, cand, "exact", typ
            if typ == "domain":
                return tier, cand, "suffix", typ
    return None


def send_event(payload, agent):
    msg = json.dumps(payload, separators=(",", ":"), ensure_ascii=True)
    if not agent or agent.get("id") in (None, "", "000"):
        line = "1:%s:%s" % (LOCATION, msg)
    else:
        line = "1:[%s] (%s) %s->%s:%s" % (agent["id"], agent.get("name", "?"),
                                           agent.get("ip", "any"), LOCATION, msg)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        sock.connect(SOCKET_ADDR)
        sock.send(line.encode("utf-8"))
    finally:
        sock.close()


def main(argv):
    if len(argv) < 2:
        log("no alert file argument")
        return 1
    agent = None
    try:
        with open(argv[1], "r", encoding="utf-8") as fh:
            alert = json.load(fh)
        agent = alert.get("agent")
        query = (((alert.get("data") or {}).get("win") or {}).get("eventdata") or {}).get("queryName")
        if not query or not isinstance(query, str):
            return 0                                  # not a DNS query alert: nothing to do
        n, idna_ok = normalize(query)
        if not n or not idna_ok:
            return 0                                  # cannot be on a list (lists hold A-labels)
        hit = match(n, {t: read_list(t) for t in TIERS})
        if hit is None:
            return 0
        tier, matched, kind, typ = hit
        send_event({"integration": NAME,
                    "misp_domain": {"tier": tier, "query": query, "normalized": n,
                                    "matched": matched, "match_kind": kind, "entry_type": typ,
                                    "source_rule": str((alert.get("rule") or {}).get("id", "")),
                                    "source_alert": str(alert.get("id", ""))}}, agent)
        return 0
    except Exception as exc:                          # fail visible: report, never swallow
        text = "%s: %s" % (type(exc).__name__, exc)
        log("FAILED: " + text)
        try:
            send_event({"integration": NAME, "misp_domain_error": text[:300]}, agent)
            return 0
        except Exception as exc2:
            log("FAILED to report the failure: %s: %s" % (type(exc2).__name__, exc2))
            return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''

INTEGRATION_BLOCK = """  <integration>
    <name>custom-misp-domain</name>
    <rule_id>100160</rule_id>
    <alert_format>json</alert_format>
  </integration>
"""

RULES_BLOCK = """<group name="misp_ioc_domain_script,">
  <rule id="100322" level="10">
    <decoded_as>json</decoded_as>
    <field name="integration">^custom-misp-domain$</field>
    <field name="misp_domain.tier">^t1$</field>
    <description>MISP IOC (tier 1, $(misp_domain.match_kind) match): DNS query $(misp_domain.query) matched $(misp_domain.matched)</description>
    <group>misp_ioc_domain_t1,</group>
  </rule>
  <rule id="100323" level="7">
    <decoded_as>json</decoded_as>
    <field name="integration">^custom-misp-domain$</field>
    <field name="misp_domain.tier">^t2$</field>
    <description>MISP IOC (tier 2, $(misp_domain.match_kind) match): DNS query $(misp_domain.query) matched $(misp_domain.matched)</description>
    <group>misp_ioc_domain_t2,</group>
  </rule>
  <rule id="100324" level="12">
    <decoded_as>json</decoded_as>
    <field name="integration">^custom-misp-domain$</field>
    <field name="misp_domain_error">.+</field>
    <description>custom-misp-domain integration failed: $(misp_domain_error)</description>
    <group>misp_ioc_domain_error,</group>
  </rule>
</group>
"""


class Abort(Exception):
    pass


def read_bytes(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except OSError as exc:
        raise Abort("cannot read %s: %s" % (path, exc))


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


def insert_integration(conf):
    i = conf.rfind("</ossec_config>")
    if i < 0:
        raise Abort("no </ossec_config> found in ossec.conf")
    head = conf[:i]
    if not head.endswith("\n"):
        head += "\n"
    return head + INTEGRATION_BLOCK + conf[i:]


def append_rules(rules):
    sep = "" if rules.endswith("\n") or not rules else "\n"
    return rules + sep + "\n" + RULES_BLOCK


def check(paths, conf, rules):
    problems = []
    for tier in ("t1", "t2"):
        p = os.path.join(paths["lists"], "misp-domain-%s" % tier)
        if not os.path.isfile(p) or os.path.getsize(p) == 0:
            problems.append("list missing or empty: %s (run misp_ioc_sync.py first)" % p)
        elif not re.search(rb":(domain|hostname)\r?$", read_bytes(p)[:4096], re.M):
            problems.append("%s has no 'name:domain' / 'name:hostname' lines: install "
                            "misp_ioc_sync.py v0.5 or later and run it first" % p)
    if not os.path.isdir(paths["integrations"]):
        problems.append("integrations directory missing: %s" % paths["integrations"])
    if os.path.exists(paths["script"]):
        problems.append("%s already exists (nothing changed)" % paths["script"])
    if SCRIPT_NAME in conf:
        problems.append("ossec.conf already mentions %s (nothing changed)" % SCRIPT_NAME)
    if 'name="misp_ioc_domain_script,"' in rules:
        problems.append("local_rules.xml already contains the integration rules (nothing changed)")
    idre = re.compile(r'\bid\s*=\s*"(%s)"' % "|".join(RULE_IDS))
    for d in paths["rule_dirs"]:
        for f in sorted(glob.glob(os.path.join(d, "*.xml"))):
            hit = idre.search(read_bytes(f).decode("utf-8", "replace"))
            if hit:
                problems.append("rule id %s already used in %s" % (hit.group(1), f))
    try:
        ET.fromstring("<root>%s</root>" % RULES_BLOCK)
        compile(SCRIPT_TEXT, SCRIPT_NAME, "exec")
    except (ET.ParseError, SyntaxError) as exc:
        problems.append("internal error in the embedded rules or script: %s" % exc)
    return problems


def main(argv=None):
    ap = argparse.ArgumentParser(description="Install the custom-misp-domain integration")
    ap.add_argument("--ossec-root", default="/var/ossec")
    ap.add_argument("--backup-dir", default="/root")
    ap.add_argument("--dry-run", action="store_true", help="run all checks, change nothing")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = ap.parse_args(argv)
    r = args.ossec_root
    paths = {"conf": os.path.join(r, "etc", "ossec.conf"),
             "rules": os.path.join(r, "etc", "rules", "local_rules.xml"),
             "script": os.path.join(r, "integrations", SCRIPT_NAME),
             "integrations": os.path.join(r, "integrations"),
             "lists": os.path.join(r, "etc", "lists"),
             "analysisd": os.path.join(r, "bin", "wazuh-analysisd"),
             "rule_dirs": [os.path.join(r, "ruleset", "rules"), os.path.join(r, "etc", "rules")]}
    try:
        conf_b, rules_b = read_bytes(paths["conf"]), read_bytes(paths["rules"])
        problems = check(paths, conf_b.decode("utf-8"), rules_b.decode("utf-8"))
        if problems:
            raise Abort("; ".join(problems))
        if args.dry_run:
            print("dry run: all checks passed, nothing was changed")
            return 0
        ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        conf_bak = os.path.join(args.backup_dir, "ossec.conf.bak-%s" % ts)
        rules_bak = os.path.join(args.backup_dir, "local_rules.xml.bak-%s" % ts)
        shutil.copy2(paths["conf"], conf_bak)
        shutil.copy2(paths["rules"], rules_bak)
        conf_st, rules_st = os.stat(paths["conf"]), os.stat(paths["rules"])

        with open(paths["script"], "wb") as fh:
            fh.write(SCRIPT_TEXT.encode("utf-8"))
        os.chmod(paths["script"], 0o750)
        try:
            shutil.chown(paths["script"], user="root", group="wazuh")
        except (LookupError, OSError) as exc:
            print("warning: could not set owner root:wazuh on the script (%s); set it by hand" % exc)
        atomic_replace(paths["conf"], insert_integration(conf_b.decode("utf-8")).encode("utf-8"), conf_st)
        atomic_replace(paths["rules"], append_rules(rules_b.decode("utf-8")).encode("utf-8"), rules_st)

        proc = subprocess.run([paths["analysisd"], "-t"], capture_output=True, text=True)
        if proc.returncode != 0:
            atomic_replace(paths["conf"], conf_b, conf_st)
            atomic_replace(paths["rules"], rules_b, rules_st)
            os.unlink(paths["script"])
            tail = (proc.stderr or proc.stdout).strip().splitlines()[-6:]
            print("wazuh-analysisd -t FAILED (exit %d); config files restored, script removed." % proc.returncode)
            for ln in tail:
                print("  " + ln)
            return 3
        print("wazuh-analysisd -t: OK (note: it does not validate the <integration> block)")
        print("installed: %s (750), <integration> block in ossec.conf, rules 100322-100324" % paths["script"])
        print("backups: %s , %s" % (conf_bak, rules_bak))
        print("NEXT: restart the manager (integration changes need it), then verify.")
        return 0
    except Abort as exc:
        print("ABORT, nothing was changed: %s" % exc)
        return 2


if __name__ == "__main__":
    sys.exit(main())
