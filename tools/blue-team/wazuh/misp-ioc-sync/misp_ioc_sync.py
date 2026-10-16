#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
misp_ioc_sync.py  (v0.7.1)

Pulls actionable indicators from MISP (attributes/restSearch, text format) and
writes them as Wazuh CDB list files on the Wazuh manager:
  * IPv4 addresses      -> misp-ip-t1 / misp-ip-t2          (as in v0.3)
  * domains / hostnames -> misp-domain-t1 / misp-domain-t2  (v0.4; since v0.5 each
                           line carries its MISP type as the CDB value:
                           "name:domain" or "name:hostname")

Design (see the IOC-matching roadmap):
  * Runs on the Wazuh manager, no SOAR in the sync path. Meant to be started by
    Wazuh's own command module (wodle), which forwards its stdout to the manager
    as an event, so a failed run becomes a Wazuh alert.
  * Two tiers, split by MISP event publish state:
        t1 = indicators from PUBLISHED events
        t2 = indicators from UNPUBLISHED events
    An indicator present in both tiers is kept in t1 only.
    NOTE: "published" is a publication-state flag in MISP, not a quality signal;
    treating it as a curation proxy is a local heuristic.
  * Filters: to_ids=1, decay with modelOverrides (lifetime/threshold), optional
    enforceWarninglist. Two retrieval modes, chosen separately for the IP lists
    ([filters] retrieval) and the domain lists ([filters] domain_retrieval):
        text-bulk   one large text export per type and tier, MISP applies the
                    decay filter and the warninglists (v0.5 behaviour)
        json-paged  paged JSON (the pattern of the Microsoft Sentinel MISP connector:
                    paged JSON, warninglists enforced by MISP, decay decided from
                    the scores MISP returns): decay decided here
                    from the decay scores MISP returns (includeDecayScore with the
                    same modelOverrides, "not decayed" under decaying model N)
    On MISP 2.5.40 the bulk text export was measured to be wrong in two places:
    with enforceWarninglist it dropped ~35,000 tier 2 IPs that MISP's own
    warninglist check does not flag, and with excludeDecayed it dropped ~19,000
    tier 1 ip-dst|port IPs that MISP's single-value query keeps. The paged JSON
    path agreed with MISP's single-value decisions in every sample taken.
  * Domain normalisation (CDB matching is exact, hash based, no subdomain
    matching): values are lower-cased, one trailing dot is removed, and
    wildcards, IP literals, single-label names, internal suffixes, non-ASCII
    and syntactically invalid names are dropped and counted.
  * Safety: nothing is written unless EVERY query succeeded and ALL new lists
    pass the shrink guard. Lists are only rewritten when their content changed,
    and writes are atomic (temp file + rename).
  * Reload: after a list changed the script asks analysisd to hot-reload its
    ruleset (Wazuh 4.13+). It calls the same framework function the API uses,
    through Wazuh's own embedded Python, so no API credentials are needed and
    the manager is not restarted. A failed reload makes the run an error,
    because lists that Wazuh has not loaded do not detect anything.
  * Every run appends ONE JSON status line to the status log. With --wazuh the
    same information is printed to stdout as a single compact JSON line.

Only the Python standard library is used.
"""
from __future__ import annotations

import argparse
import configparser
import datetime
import getpass
import ipaddress
import json
import os
import re
import ssl
import string
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

__version__ = "0.7.1"
PROG = "misp-ioc-sync"
DEFAULT_CONF = "/etc/misp-ioc-sync/misp-ioc-sync.conf"
FALLBACK_STATUS_LOG = "/var/log/misp-ioc-sync.log"

# tier name -> value of MISP's "published" filter
TIERS = (("t1", 1), ("t2", 0))

# Python's ipaddress.is_global differs between versions, so the checks are
# explicit instead of relying on one flag.
EXTRA_NON_PUBLIC = tuple(ipaddress.ip_network(n) for n in (
    "100.64.0.0/10",    # shared address space (RFC 6598)
    "192.0.0.0/24",     # IETF protocol assignments
    "192.88.99.0/24",   # deprecated 6to4 relay anycast
    "240.0.0.0/4",      # reserved
))

# Domain normalisation
LABEL_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$")
INTERNAL_SUFFIXES = ("local", "localhost", "lan", "internal", "home.arpa",
                     "soc.dev", "arpa")


class SyncError(Exception):
    """Expected failure: reported in the status line, nothing is written."""


class ReloadError(SyncError):
    """Lists were written, but analysisd could not be told to reload them."""


def is_public_ipv4(ip):
    if (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified or not ip.is_global):
        return False
    return not any(ip in net for net in EXTRA_NON_PUBLIC)


# --------------------------------------------------------------------------
# configuration
# --------------------------------------------------------------------------
DEFAULTS = {
    "url": "https://10.1.30.15",
    "key_file": "/etc/misp-ioc-sync/misp.key",
    "verify_tls": False,
    "ca_file": "",
    "timeout": 300,
    "types": ["ip-dst", "ip-src", "ip-dst|port", "ip-src|port"],
    "domains": True,
    "domain_types": ["domain", "hostname", "domain|ip", "hostname|port"],
    "exclude_decayed": True,
    "threshold": 10,
    "lifetime": 365,
    "enforce_warninglist": True,
    "retrieval": "text-bulk",            # IP lists: text-bulk | json-paged
    "domain_retrieval": "text-bulk",     # domain lists: text-bulk | json-paged
    "decay_model_id": 1,                 # MISP decaying model whose score decides (json-paged)
    "json_page_size": 5000,
    "json_max_pages": 600,
    "json_empty_pages": 5,               # stop after this many empty pages in a row
    "list_dir": "/var/ossec/etc/lists",
    "prefix": "misp-ip",
    "domain_prefix": "misp-domain",
    "status_log": FALLBACK_STATUS_LOG,
    "min_keep_ratio": 0.5,
    "min_previous": 100,
    # The t2 domain list is small (~200 entries on 6 Oct 2026) and volatile; a
    # low guard threshold there would block the IP update too. Lists below this
    # size are only protected against becoming empty.
    "min_previous_domain": 500,
    "reload": "hot",             # hot | none
    "reload_python": "/var/ossec/framework/python/bin/python3",
    "reload_timeout": 120,
}


def load_config(path, explicit):
    """Built-in defaults; a config file (if present) overrides them."""
    cfg = dict(DEFAULTS)
    if not os.path.exists(path):
        if explicit:
            raise SyncError("config file not readable: %s" % path)
        return cfg
    cp = configparser.ConfigParser(inline_comment_prefixes=("#", ";"))
    if not cp.read(path):
        raise SyncError("config file not readable: %s" % path)

    def split(v):
        return [t.strip() for t in v.split(",") if t.strip()]
    try:
        cfg.update({
            "url": cp.get("misp", "url", fallback=cfg["url"]).rstrip("/"),
            "key_file": cp.get("misp", "key_file", fallback=cfg["key_file"]),
            "verify_tls": cp.getboolean("misp", "verify_tls", fallback=cfg["verify_tls"]),
            "ca_file": cp.get("misp", "ca_file", fallback=cfg["ca_file"]).strip(),
            "timeout": cp.getint("misp", "timeout", fallback=cfg["timeout"]),
            "types": split(cp.get("filters", "types", fallback=",".join(cfg["types"]))),
            "domains": cp.getboolean("filters", "domains", fallback=cfg["domains"]),
            "domain_types": split(cp.get("filters", "domain_types",
                                         fallback=",".join(cfg["domain_types"]))),
            "exclude_decayed": cp.getboolean("filters", "exclude_decayed",
                                             fallback=cfg["exclude_decayed"]),
            "threshold": cp.getint("filters", "threshold", fallback=cfg["threshold"]),
            "lifetime": cp.getint("filters", "lifetime", fallback=cfg["lifetime"]),
            "enforce_warninglist": cp.getboolean("filters", "enforce_warninglist",
                                                 fallback=cfg["enforce_warninglist"]),
            "retrieval": cp.get("filters", "retrieval",
                                fallback=cfg["retrieval"]).strip().lower(),
            "domain_retrieval": cp.get("filters", "domain_retrieval",
                                       fallback=cfg["domain_retrieval"]).strip().lower(),
            "decay_model_id": cp.getint("filters", "decay_model_id",
                                        fallback=cfg["decay_model_id"]),
            "json_page_size": cp.getint("filters", "json_page_size",
                                        fallback=cfg["json_page_size"]),
            "json_max_pages": cp.getint("filters", "json_max_pages",
                                        fallback=cfg["json_max_pages"]),
            "json_empty_pages": cp.getint("filters", "json_empty_pages",
                                          fallback=cfg["json_empty_pages"]),
            "list_dir": cp.get("output", "list_dir", fallback=cfg["list_dir"]),
            "prefix": cp.get("output", "prefix", fallback=cfg["prefix"]),
            "domain_prefix": cp.get("output", "domain_prefix",
                                    fallback=cfg["domain_prefix"]),
            "status_log": cp.get("output", "status_log", fallback=cfg["status_log"]),
            "min_keep_ratio": cp.getfloat("output", "min_keep_ratio",
                                          fallback=cfg["min_keep_ratio"]),
            "min_previous": cp.getint("output", "min_previous_for_guard",
                                      fallback=cfg["min_previous"]),
            "min_previous_domain": cp.getint("output", "min_previous_for_guard_domain",
                                             fallback=cfg["min_previous_domain"]),
            "reload": cp.get("output", "reload", fallback=cfg["reload"]).strip().lower(),
            "reload_python": cp.get("output", "reload_python", fallback=cfg["reload_python"]),
            "reload_timeout": cp.getint("output", "reload_timeout_s",
                                        fallback=cfg["reload_timeout"]),
        })
    except (configparser.Error, ValueError) as exc:
        raise SyncError("config error: %s" % exc)
    if not cfg["types"]:
        raise SyncError("config error: [filters] types is empty")
    if cfg["domains"] and not cfg["domain_types"]:
        raise SyncError("config error: [filters] domain_types is empty")
    if cfg["reload"] not in ("none", "hot"):
        raise SyncError("config error: [output] reload must be 'hot' or 'none'")
    if (cfg["retrieval"] not in ("text-bulk", "json-paged")
            or cfg["domain_retrieval"] not in ("text-bulk", "json-paged")):
        raise SyncError("config error: [filters] retrieval and domain_retrieval "
                        "must be 'text-bulk' or 'json-paged'")
    if (cfg["json_page_size"] < 100 or cfg["json_max_pages"] < 1
            or cfg["json_empty_pages"] < 1 or cfg["decay_model_id"] < 1):
        raise SyncError("config error: [filters] json_page_size >= 100, "
                        "json_max_pages >= 1, json_empty_pages >= 1, "
                        "decay_model_id >= 1")
    return cfg


def read_key(path, prompt=False):
    if prompt:
        key = getpass.getpass("MISP API key (input hidden): ").strip()
        if not key:
            raise SyncError("empty key")
        return key, None
    try:
        st = os.stat(path)
        with open(path, "r") as fh:
            key = fh.read().strip()
    except OSError as exc:
        raise SyncError("cannot read MISP key file %s: %s" % (path, exc))
    if not key:
        raise SyncError("MISP key file is empty: %s" % path)
    warn = None
    if st.st_mode & 0o077:
        warn = "key file permissions are too open (%o), expected 600" % (st.st_mode & 0o777)
    return key, warn


# --------------------------------------------------------------------------
# MISP access
# --------------------------------------------------------------------------
def build_payload(typ, published, cfg, enforce=None):
    if enforce is None:
        enforce = cfg["enforce_warninglist"]
    payload = {
        "returnFormat": "text",
        "type": typ,
        "to_ids": 1,
        "published": published,
        "limit": 1000000,
    }
    if cfg["exclude_decayed"]:
        payload["excludeDecayed"] = 1
        payload["modelOverrides"] = {
            "threshold": cfg["threshold"],
            "lifetime": cfg["lifetime"],
        }
    if enforce:
        payload["enforceWarninglist"] = 1
    return payload


def misp_query(cfg, key, payload):
    url = cfg["url"] + "/attributes/restSearch"
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        method="POST",
        headers={
            "Authorization": key,
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
    )
    ctx = None
    if url.lower().startswith("https"):
        if cfg["verify_tls"]:
            ctx = ssl.create_default_context(cafile=cfg["ca_file"] or None)
        else:
            ctx = ssl._create_unverified_context()  # noqa: SLF001 (lab PKI)
    desc = "type=%s published=%s" % (payload.get("type"), payload.get("published"))
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=cfg["timeout"], context=ctx) as resp:
            code = resp.status
            body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        snippet = exc.read(200).decode("utf-8", "replace").replace("\n", " ")
        raise SyncError("HTTP %s from MISP (%s): %s" % (exc.code, desc, snippet))
    except (urllib.error.URLError, OSError) as exc:
        raise SyncError("MISP connection error (%s): %s" % (desc, exc))
    if body.lstrip().startswith(("{", "[")):
        raise SyncError("unexpected JSON body for text export (%s): %s"
                        % (desc, body[:200].replace("\n", " ")))
    return code, body, time.time() - t0


def misp_json_rows(cfg, key, typ, published, enforce):
    """Fetch every attribute of one (type, tier) as paged JSON.

    The server-side decay filter is NOT used: MISP applies filters after paging,
    which leaves leading pages empty. With decay wanted the query asks for the
    decay scores instead (the modelOverrides stay in the payload, so the scores
    use the configured lifetime and threshold). Returns (rows, pages, seconds)."""
    payload = build_payload(typ, published, cfg, enforce=enforce)
    payload.pop("excludeDecayed", None)
    payload["returnFormat"] = "json"
    payload["limit"] = cfg["json_page_size"]
    if cfg["exclude_decayed"]:
        payload["includeDecayScore"] = 1
    url = cfg["url"] + "/attributes/restSearch"
    ctx = None
    if url.lower().startswith("https"):
        if cfg["verify_tls"]:
            ctx = ssl.create_default_context(cafile=cfg["ca_file"] or None)
        else:
            ctx = ssl._create_unverified_context()  # noqa: SLF001 (lab PKI)
    desc = "type=%s published=%s (json pages)" % (typ, published)
    rows, empty, page, t0 = [], 0, 1, time.time()
    while empty < cfg["json_empty_pages"]:
        if page > cfg["json_max_pages"]:
            raise SyncError("JSON paging did not finish within %d pages (%s)"
                            % (cfg["json_max_pages"], desc))
        payload["page"] = page
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), method="POST",
            headers={"Authorization": key, "Accept": "application/json",
                     "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=cfg["timeout"], context=ctx) as resp:
                body = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            snippet = exc.read(200).decode("utf-8", "replace").replace("\n", " ")
            raise SyncError("HTTP %s from MISP (%s page %d): %s"
                            % (exc.code, desc, page, snippet))
        except (urllib.error.URLError, OSError) as exc:
            raise SyncError("MISP connection error (%s page %d): %s" % (desc, page, exc))
        try:
            got = json.loads(body)["response"]["Attribute"]
        except (ValueError, KeyError, TypeError):
            raise SyncError("unexpected JSON shape from MISP (%s page %d): %s"
                            % (desc, page, body[:200].replace("\n", " ")))
        if got:
            empty = 0
            rows.extend(got)
        else:
            empty += 1
        page += 1
    return rows, page - 1, time.time() - t0


def decay_alive(row, model_id):
    """True/False from MISP's own decayed flag for one decaying model, None if the
    row carries no score for that model."""
    scores = [d for d in row.get("decay_score", [])
              if str((d.get("DecayingModel") or {}).get("id")) == str(model_id)]
    if not scores:
        return None
    return any(not d.get("decayed", True) for d in scores)


def rows_to_text(cfg, rows, desc):
    """Client-side decay: keep values that are not decayed. Returns
    (text, rows_without_score, rows_dropped_as_decayed). Fails closed when the
    decaying model is missing (every row without a score would silently vanish)."""
    if not cfg["exclude_decayed"]:
        return "\n".join(str(a.get("value", "")) for a in rows), 0, 0
    keep, noscore, dropped = [], 0, 0
    for a in rows:
        alive = decay_alive(a, cfg["decay_model_id"])
        if alive is None:
            noscore += 1
        elif alive:
            keep.append(str(a.get("value", "")))
        else:
            dropped += 1
    if rows and noscore > 0.01 * len(rows):
        raise SyncError("decay guard: %d of %d rows (%s) carry no score for decaying "
                        "model %d (disabled or wrong id?); nothing written"
                        % (noscore, len(rows), desc, cfg["decay_model_id"]))
    return "\n".join(keep), noscore, dropped


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------
def parse_ips(text):
    """Return (set of IPv4 strings, stats). Composite 'ip|port' values keep the ip."""
    stats = {"raw": 0, "nonglobal": 0, "ipv6": 0, "cidr": 0, "invalid": 0}
    out = set()
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        stats["raw"] += 1
        s = s.split("|", 1)[0].strip()
        if "/" in s:
            stats["cidr"] += 1
            continue
        try:
            ip = ipaddress.ip_address(s)
        except ValueError:
            stats["invalid"] += 1
            continue
        if ip.version == 6:
            # ':' is the CDB key/value separator; IPv6 keys are not handled yet
            stats["ipv6"] += 1
            continue
        if not is_public_ipv4(ip):
            stats["nonglobal"] += 1
            continue
        out.add(str(ip))
    return out, stats


# Locale-independent normalisation (RFC 4343): DNS names compare case-insensitively for the
# ASCII letters A-Z only. No language-specific mapping (Turkish dotted/dotless i, Latin-1
# accents, ...) is part of DNS, so no str.lower()/upper()/casefold() and nothing that reads
# the system locale is used on names. Names with non-ASCII characters go through the IDNA
# transformation to their ASCII form (xn--...), exactly where RFC 4343 section 5 puts it.
ASCII_FOLD = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def ascii_fold(s):
    return s.translate(ASCII_FOLD)


def classify_domain(text):
    """Return (normalized_or_None, reason, flags). flags describe the RAW value."""
    s = text.split("|", 1)[0].strip()          # 'domain|ip' / 'hostname|port'
    flags = {"upper": any("A" <= c <= "Z" for c in s), "trailing_dot": s.endswith("."),
             "idna": False}
    if not s:
        return None, "invalid", flags
    if "*" in s:
        return None, "wildcard", flags
    s = ascii_fold(s)
    if s.endswith("."):
        s = s[:-1]
    if not s.isascii():
        try:
            s = ascii_fold(s.encode("idna").decode("ascii"))
            flags["idna"] = True
        except UnicodeError:
            return None, "idna_failed", flags
    try:
        ipaddress.ip_address(s.strip("[]"))
        return None, "ip_literal", flags
    except ValueError:
        pass
    labels = s.split(".")
    if len(labels) < 2:
        return None, "single_label", flags
    if (len(s) > 253 or not all(LABEL_RE.match(x) for x in labels)
            or labels[-1].isdigit()):
        return None, "invalid", flags
    if any(s == x or s.endswith("." + x) for x in INTERNAL_SUFFIXES):
        return None, "internal", flags
    return s, "ok", flags


def parse_domains(text):
    """Return (set of normalized domains, stats)."""
    stats = {"raw": 0, "wildcard": 0, "ip_literal": 0, "single_label": 0,
             "internal": 0, "idna_failed": 0, "invalid": 0,
             "kept_with_uppercase": 0, "kept_with_trailing_dot": 0, "idna_converted": 0}
    out = set()
    for line in text.splitlines():
        if not line.strip():
            continue
        stats["raw"] += 1
        val, reason, flags = classify_domain(line)
        if val is None:
            stats[reason] += 1
            continue
        out.add(val)
        if flags["upper"]:
            stats["kept_with_uppercase"] += 1
        if flags["trailing_dot"]:
            stats["kept_with_trailing_dot"] += 1
        if flags["idna"]:
            stats["idna_converted"] += 1
    return out, stats


def domain_shape(items):
    """Label-count histogram of the kept domains. CDB matching is exact, so only
    names that appear in DNS queries exactly as listed can match; two-label
    entries are the ones most likely to be registrable (apex) domains that are
    queried as subdomains. Counts are a rough indicator (no public-suffix list)."""
    shape = {"labels_2": 0, "labels_3": 0, "labels_4plus": 0}
    for d in items:
        n = d.count(".") + 1
        shape["labels_2" if n == 2 else "labels_3" if n == 3 else "labels_4plus"] += 1
    return shape


# --------------------------------------------------------------------------
# output
# --------------------------------------------------------------------------
def count_lines(path):
    try:
        with open(path, "r") as fh:
            return sum(1 for ln in fh if ln.strip())
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SyncError("cannot read previous list %s: %s" % (path, exc))


def read_bytes(path):
    try:
        with open(path, "rb") as fh:
            return fh.read()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise SyncError("cannot read previous list %s: %s" % (path, exc))


def atomic_write(path, content, ref_dir):
    d = os.path.dirname(path)
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=d)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        try:
            st = os.stat(ref_dir)
            os.chown(tmp, st.st_uid, st.st_gid)
        except OSError:
            pass
        os.chmod(tmp, 0o660)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def append_status(path, obj):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        new = not os.path.exists(path)
        with open(path, "a") as fh:
            fh.write(json.dumps(obj, sort_keys=True) + "\n")
        if new:
            os.chmod(path, 0o640)
    except OSError as exc:
        print("WARNING: cannot write status log %s: %s" % (path, exc), file=sys.stderr)


def add_warning(result, text):
    result.setdefault("warnings", []).append(text)


RELOAD_CODE = (
    "import asyncio, json\n"
    "from wazuh.core.analysis import send_reload_ruleset_msg\n"
    "r = asyncio.run(send_reload_ruleset_msg({'name': 'misp-ioc-sync', 'module': 'framework'}))\n"
    "print(json.dumps({'ok': bool(r.is_ok()), 'message': str(r.message), "
    "'warnings': list(r.warnings), 'errors': list(r.errors)}))\n"
)


def hot_reload(cfg, result):
    """Ask analysisd to reload its ruleset (CDB lists included) without a restart.

    Runs Wazuh's own send_reload_ruleset_msg() under Wazuh's embedded Python, the
    same call PUT /manager/analysisd/reload makes."""
    py = cfg["reload_python"]
    if not os.path.exists(py):
        result["reload"] = "FAILED"
        raise ReloadError("lists written, but reload failed: Wazuh python not found: %s" % py)
    try:
        proc = subprocess.run([py, "-c", RELOAD_CODE], capture_output=True, text=True,
                              timeout=cfg["reload_timeout"])
    except (OSError, subprocess.SubprocessError) as exc:
        result["reload"] = "FAILED"
        raise ReloadError("lists written, but reload failed to run: %s" % exc)
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
        result["reload"] = "FAILED"
        raise ReloadError("lists written, but reload failed (exit %s): %s" % (proc.returncode, tail))
    if not reply.get("ok"):
        detail = "; ".join(str(e) for e in reply.get("errors", [])) or str(reply.get("message", ""))
        result["reload"] = "FAILED"
        raise ReloadError("lists written, but analysisd refused the reload: %s" % detail[:200])
    result["reload"] = "ok"
    for w in reply.get("warnings", []):
        add_warning(result, "reload warning: %s" % w)


# --------------------------------------------------------------------------
# main sync
# --------------------------------------------------------------------------
def domain_label(typ):
    """MISP 'domain' / 'domain|ip' -> 'domain' (the name and everything below it);
    'hostname' / 'hostname|port' -> 'hostname' (that exact host only). Source: the
    MISP data model describes hostname as 'a full host/dnsname' and domain as the
    type to use when the upper domain matters."""
    return "domain" if typ.split("|")[0] == "domain" else "hostname"


KINDS = {
    "ip": {"types_key": "types", "prefix_key": "prefix", "parse": parse_ips,
           "min_key": "min_previous", "tiers_key": "tiers",
           "sort": lambda s: int(ipaddress.ip_address(s)),
           "label": lambda typ: ""},
    "domain": {"types_key": "domain_types", "prefix_key": "domain_prefix",
               "parse": parse_domains, "min_key": "min_previous_domain",
               "tiers_key": "domain_tiers", "sort": lambda s: s,
               "label": domain_label},
}


def fetch_kind(cfg, key, args, result, kind):
    """Query one indicator kind for both tiers. Returns {tier: {name: value}}.
    The value is "" for IPs and "domain"/"hostname" for domain-like indicators."""
    spec = KINDS[kind]
    tier_data = {}
    result[spec["tiers_key"]] = {}
    for tier, published in TIERS:
        data = {}
        agg = None
        for typ in cfg[spec["types_key"]]:
            jq = {}
            mode = cfg["retrieval"] if kind == "ip" else cfg["domain_retrieval"]
            if mode == "json-paged":
                desc = "%s %s %s" % (kind, tier, typ)
                rows, pages, secs = misp_json_rows(cfg, key, typ, published,
                                                   cfg["enforce_warninglist"])
                body, noscore, dropped = rows_to_text(cfg, rows, desc)
                code = 200
                jq = {"json_pages": pages, "rows": len(rows),
                      "decayed_dropped": dropped, "rows_without_score": noscore}
                if noscore:
                    result.setdefault("warnings", []).append(
                        "%s: %d rows without a decay score were left out" % (desc, noscore))
            else:
                code, body, secs = misp_query(cfg, key, build_payload(typ, published, cfg))
            items, st = spec["parse"](body)
            agg = dict(st) if agg is None else {k: agg[k] + st[k] for k in st}
            label = spec["label"](typ)
            for it in items:
                if label == "domain" or it not in data:     # domain wins over hostname
                    data[it] = label
            q = {"kind": kind, "tier": tier, "type": typ, "http": code,
                 "seconds": round(secs, 1), "lines": st["raw"], "usable_unique": len(items)}
            q.update(jq)
            if args.report_warninglist_effect and cfg["enforce_warninglist"]:
                if mode == "json-paged":
                    rows_raw, _p, _s = misp_json_rows(cfg, key, typ, published, False)
                    body_raw, _n, _d = rows_to_text(cfg, rows_raw, desc)
                else:
                    _c, body_raw, _s = misp_query(
                        cfg, key, build_payload(typ, published, cfg, enforce=False))
                raw_items, _st = spec["parse"](body_raw)
                q["without_warninglist"] = len(raw_items)
                q["removed_by_warninglists"] = len(raw_items - items)
            result["queries"].append(q)
        tier_data[tier] = data
        extra = {}
        if kind == "domain":
            extra = domain_shape(data)
            extra["type_domain"] = sum(1 for v in data.values() if v == "domain")
            extra["type_hostname"] = sum(1 for v in data.values() if v == "hostname")
        result[spec["tiers_key"]][tier] = dict(agg, usable_unique=len(data), **extra)
    return tier_data


def plan_kind(cfg, result, kind, tier_sets, problems, payload):
    """Dedupe t2 against t1, render list files, apply the shrink guard."""
    spec = KINDS[kind]
    overlap = set(tier_sets["t2"]) & set(tier_sets["t1"])
    tier_sets["t2"] = {k: v for k, v in tier_sets["t2"].items() if k not in tier_sets["t1"]}
    result["overlap_removed_from_t2" if kind == "ip"
           else "domain_overlap_removed_from_t2"] = len(overlap)
    for tier, _p in TIERS:
        path = os.path.join(cfg["list_dir"], "%s-%s" % (cfg[spec["prefix_key"]], tier))
        ordered = sorted(tier_sets[tier], key=spec["sort"])
        content = "".join("%s:%s\n" % (x, tier_sets[tier][x]) for x in ordered).encode("utf-8")
        payload[(kind, tier)] = (path, content)
        new_n = len(ordered)
        prev_n = count_lines(path)
        t = result[spec["tiers_key"]][tier]
        t["written"] = new_n
        t["previous"] = prev_n
        label = "%s %s" % (kind, tier)
        if new_n == 0:
            problems.append("%s: export is empty, refusing to write" % label)
        elif (prev_n is not None and prev_n >= cfg[spec["min_key"]]
              and new_n < prev_n * cfg["min_keep_ratio"]):
            problems.append("%s: shrink guard, %d -> %d entries (limit %.0f%% of previous)"
                            % (label, prev_n, new_n, cfg["min_keep_ratio"] * 100))


def run_sync(cfg, key, args, result):
    """Fills `result` in place, so partial numbers survive a failure."""
    result["queries"] = []
    kinds = ["ip"] + (["domain"] if cfg["domains"] else [])
    fetched = {k: fetch_kind(cfg, key, args, result, k) for k in kinds}

    problems = []
    payload = {}
    for k in kinds:
        plan_kind(cfg, result, k, fetched[k], problems, payload)
    if problems:
        raise SyncError("; ".join(problems))

    any_changed = False
    for k in kinds:
        for tier, _p in TIERS:
            path, content = payload[(k, tier)]
            changed = read_bytes(path) != content
            result[KINDS[k]["tiers_key"]][tier]["changed"] = changed
            any_changed = any_changed or changed
    result["changed"] = any_changed
    result["list_files"] = []

    if args.dry_run:
        result["note"] = "dry run, no list was written"
        result["reload"] = "skipped: dry run"
        return
    if not os.path.isdir(cfg["list_dir"]):
        raise SyncError("list directory does not exist: %s" % cfg["list_dir"])
    for k in kinds:
        for tier, _p in TIERS:
            path, content = payload[(k, tier)]
            if result[KINDS[k]["tiers_key"]][tier]["changed"]:
                atomic_write(path, content, cfg["list_dir"])
                result["list_files"].append(path)
    if not any_changed:
        result["reload"] = "skipped: no list changed"
    elif cfg["reload"] == "hot":
        hot_reload(cfg, result)
    else:
        result["reload"] = "not requested (reload = none)"


def print_summary(status):
    out = sys.stdout
    out.write("misp-ioc-sync %s: %s%s\n" % (
        __version__, status.get("result", "?").upper(),
        " (dry run)" if status.get("dry_run") else ""))
    if status.get("error"):
        out.write("  error: %s\n" % status["error"])
    for w in status.get("warnings", []):
        out.write("  warning: %s\n" % w)
    for q in status.get("queries", []):
        line = "  %-6s %-3s %-14s http=%s %5.1fs lines=%-7s usable=%-7s" % (
            q.get("kind", "ip"), q["tier"], q["type"], q["http"], q["seconds"],
            q["lines"], q["usable_unique"])
        if "removed_by_warninglists" in q:
            line += " warninglist-removed=%d" % q["removed_by_warninglists"]
        if "json_pages" in q:
            line += " json: rows=%d pages=%d decayed-dropped=%d" % (
                q["rows"], q["json_pages"], q["decayed_dropped"])
        out.write(line + "\n")
    for tier, t in status.get("tiers", {}).items():
        out.write("  ip tier %s: written=%s previous=%s changed=%s dropped(non-global)=%s "
                  "skipped(ipv6)=%s skipped(cidr)=%s invalid=%s\n" % (
                      tier, t.get("written", t.get("usable_unique")), t.get("previous"),
                      t.get("changed"), t.get("nonglobal"), t.get("ipv6"), t.get("cidr"),
                      t.get("invalid")))
    for tier, t in status.get("domain_tiers", {}).items():
        out.write("  domain tier %s: written=%s previous=%s changed=%s dropped: wildcard=%s "
                  "ip_literal=%s single_label=%s internal=%s idna_failed=%s invalid=%s idna_converted=%s | kept "
                  "with uppercase=%s trailing dot=%s | labels: 2=%s 3=%s 4+=%s | types: domain=%s hostname=%s\n" % (
                      tier, t.get("written"), t.get("previous"), t.get("changed"),
                      t.get("wildcard"), t.get("ip_literal"), t.get("single_label"),
                      t.get("internal"), t.get("idna_failed"), t.get("invalid"),
                      t.get("idna_converted"),
                      t.get("kept_with_uppercase"), t.get("kept_with_trailing_dot"),
                      t.get("labels_2"), t.get("labels_3"), t.get("labels_4plus"),
                      t.get("type_domain"), t.get("type_hostname")))
    if "overlap_removed_from_t2" in status:
        out.write("  ip overlap removed from t2: %s\n" % status["overlap_removed_from_t2"])
    if "domain_overlap_removed_from_t2" in status:
        out.write("  domain overlap removed from t2: %s\n"
                  % status["domain_overlap_removed_from_t2"])
    for f in status.get("list_files", []):
        out.write("  wrote %s\n" % f)
    if status.get("reload"):
        out.write("  reload: %s\n" % status["reload"])
    if status.get("note"):
        out.write("  %s\n" % status["note"])
    out.write("  duration: %ss\n" % status.get("duration_s"))


def compact_for_wazuh(status):
    """One small JSON object for the command module. 'result' is used instead of
    'status' because 'status' is a reserved static field name in Wazuh decoders.
    The IP fields keep their v0.3 names; domain fields are additive."""
    keys = ("ts", "program", "version", "result", "error", "dry_run", "duration_s",
            "changed", "reload", "overlap_removed_from_t2",
            "domain_overlap_removed_from_t2", "warnings")
    out = {k: status[k] for k in keys if k in status}
    for src, prefix, nested in (("tiers", "", "tiers"), ("domain_tiers", "domain_", "domain_tiers")):
        tiers = {}
        for tier, t in status.get(src, {}).items():
            tiers[tier] = {k: t[k] for k in ("written", "previous", "changed") if k in t}
            if "written" in t:
                out["%s%s_written" % (prefix, tier)] = t["written"]
        if tiers:
            out[nested] = tiers
    return json.dumps(out, sort_keys=True, separators=(",", ":"))


def main(argv=None):
    ap = argparse.ArgumentParser(description="MISP -> Wazuh CDB IP and domain list sync")
    ap.add_argument("--config", default=None,
                    help="optional config file (default: %s if it exists, else built-in "
                         "defaults)" % DEFAULT_CONF)
    ap.add_argument("--prompt-key", action="store_true",
                    help="ask for the MISP key on the terminal instead of reading a key file")
    ap.add_argument("--dry-run", action="store_true",
                    help="query and report, but do not write any list file")
    ap.add_argument("--report-warninglist-effect", action="store_true",
                    help="also run each query without enforceWarninglist and report "
                         "how many indicators the enabled warninglists removed")
    ap.add_argument("--wazuh", action="store_true",
                    help="print ONE compact JSON status line to stdout (for the Wazuh "
                         "command module) instead of the readable summary")
    ap.add_argument("--version", action="version", version="%(prog)s " + __version__)
    args = ap.parse_args(argv)

    started = time.time()
    status = {"ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
              "program": PROG, "version": __version__, "dry_run": bool(args.dry_run)}
    status_log = FALLBACK_STATUS_LOG
    rc = 0
    try:
        cfg = load_config(args.config or DEFAULT_CONF, explicit=bool(args.config))
        status_log = cfg["status_log"]
        key, warn = read_key(cfg["key_file"], prompt=args.prompt_key)
        if warn:
            add_warning(status, warn)
        run_sync(cfg, key, args, status)
        status["result"] = "ok"
    except ReloadError as exc:
        status["result"] = "error"
        status["error"] = str(exc)
        rc = 4
    except SyncError as exc:
        status["result"] = "error"
        status["error"] = str(exc)
        rc = 2
    except Exception as exc:  # unexpected: still report it
        status["result"] = "error"
        status["error"] = "unexpected %s: %s" % (type(exc).__name__, exc)
        rc = 3
    status["duration_s"] = round(time.time() - started, 1)
    append_status(status_log, status)
    if args.wazuh:
        print(compact_for_wazuh(status))
    else:
        print_summary(status)
    return rc


if __name__ == "__main__":
    sys.exit(main())
