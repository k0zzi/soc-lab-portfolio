#!/usr/bin/env python3
"""misp_hash_slots.py - build IOC hash "slot" documents for OpenSearch terms lookups.

Reads file-hash indicators from MISP (md5, sha1 and sha256 and their
filename|<hash> variants), normalizes them, splits each hash type into a fixed
number of slot documents and writes the documents to an OpenSearch index. An
Alerting monitor reads the slot documents through a terms lookup.

Safety rules:
  * the default run is a dry run; nothing is written without --write
  * nothing is written when any hash type would exceed its slot capacity
    (no silent truncation) or shrinks suddenly (shrink guard)
  * on any error the previous slot documents stay untouched
  * secrets are read from files and never printed or logged
"""
import argparse
import base64
import configparser
import json
import math
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

VERSION = "0.2.0"

HASH_LEN = {"md5": 32, "sha1": 40, "sha256": 64}
HEX_RE = re.compile(r"^[0-9a-f]+$")
WINDOWED_TYPES = ["md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"]
ATTR_TO_HASH = {
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "filename|md5": "md5", "filename|sha1": "sha1", "filename|sha256": "sha256",
}
HASH_ORDER = ("sha256", "md5", "sha1")

EXIT_OK, EXIT_CONFIG, EXIT_MISP, EXIT_REFUSED, EXIT_INDEXER = 0, 1, 2, 3, 4

DEFAULTS = {
    "misp": {
        "url": "https://10.1.30.15",
        "key_file": "/etc/misp-ioc-sync/misp.key",
        "verify_tls": "false",
        "ca_file": "",
        "timeout": "120",
    },
    "indexer": {
        "url": "https://127.0.0.1:9200",
        "user": "ioc_hash_writer",
        "password_file": "/etc/misp-ioc-sync/indexer-writer.pass",
        "ca_file": "/etc/wazuh-indexer/certs/root-ca.pem",
        "index": "ioc-hash-slots",
        "timeout": "60",
    },
    "hash_slots": {
        "window_days": "30",
        "page_size": "5000",
        "max_pages": "600",
        "slot_capacity": "65000",
        "slots_sha256": "4",
        "slots_md5": "4",
        "slots_sha1": "1",
        "shrink_guard_percent": "50",
        "shrink_guard_min_previous": "1000",
        "log_file": "/var/log/misp-hash-slots.log",
    },
}


class ConfigError(Exception):
    pass


class MispError(Exception):
    pass


class RefusedError(Exception):
    pass


class IndexerError(Exception):
    pass


def _int(raw, name, lo):
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError("%s must be an integer" % name)
    if value < lo:
        raise ConfigError("%s must be >= %d" % (name, lo))
    return value


def _bool(raw, name):
    low = str(raw).strip().lower()
    if low in ("1", "true", "yes", "on"):
        return True
    if low in ("0", "false", "no", "off"):
        return False
    raise ConfigError("%s must be true or false" % name)


def read_secret(path, name):
    try:
        with open(path, "r", encoding="utf-8") as handle:
            value = handle.read().rstrip("\r\n")
    except OSError as exc:
        raise ConfigError("cannot read %s file: %s" % (name, exc.strerror or exc))
    if not value:
        raise ConfigError("%s file is empty" % name)
    return value


def load_config(path):
    raw = {section: dict(values) for section, values in DEFAULTS.items()}
    if path:
        parser = configparser.ConfigParser()
        if not parser.read(path):
            raise ConfigError("cannot read config file: %s" % path)
        for section in parser.sections():
            if section not in raw:
                raise ConfigError("unknown section [%s]" % section)
            for key, value in parser.items(section):
                if key not in raw[section]:
                    raise ConfigError("unknown option [%s] %s" % (section, key))
                raw[section][key] = value
    hs, mi, ix = raw["hash_slots"], raw["misp"], raw["indexer"]
    st = {
        "misp_url": mi["url"].rstrip("/"),
        "misp_key_file": mi["key_file"],
        "misp_verify_tls": _bool(mi["verify_tls"], "misp.verify_tls"),
        "misp_ca_file": mi["ca_file"],
        "misp_timeout": _int(mi["timeout"], "misp.timeout", 1),
        "idx_url": ix["url"].rstrip("/"),
        "idx_user": ix["user"],
        "idx_password_file": ix["password_file"],
        "idx_ca_file": ix["ca_file"],
        "idx_index": ix["index"],
        "idx_timeout": _int(ix["timeout"], "indexer.timeout", 1),
        "window_days": _int(hs["window_days"], "hash_slots.window_days", 0),
        "page_size": _int(hs["page_size"], "hash_slots.page_size", 1),
        "max_pages": _int(hs["max_pages"], "hash_slots.max_pages", 1),
        "slot_capacity": _int(hs["slot_capacity"], "hash_slots.slot_capacity", 1),
        "guard_percent": _int(hs["shrink_guard_percent"], "hash_slots.shrink_guard_percent", 0),
        "guard_min_previous": _int(hs["shrink_guard_min_previous"], "hash_slots.shrink_guard_min_previous", 0),
        "log_file": hs["log_file"],
    }
    for htype in HASH_ORDER:
        st["slots_" + htype] = _int(hs["slots_" + htype], "hash_slots.slots_" + htype, 1)
    if st["slot_capacity"] > 65536:
        raise ConfigError("hash_slots.slot_capacity must be <= 65536 (OpenSearch terms limit)")
    if not re.match(r"^[a-z0-9][a-z0-9._-]*$", st["idx_index"]):
        raise ConfigError("indexer.index has an invalid name")
    return st


def _context(url, verify, ca_file):
    if not url.lower().startswith("https://"):
        return None
    if verify:
        return ssl.create_default_context(cafile=ca_file or None)
    return ssl._create_unverified_context()  # noqa: SLF001 (lab PKI, same as misp_ioc_sync.py)


def _http(url, method, headers, body, timeout, context):
    request = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as resp:
            return resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", "replace")


def _snippet(text):
    return " ".join(text.split())[:200]


def misp_search(st, body):
    url = st["misp_url"] + "/attributes/restSearch"
    headers = {"Authorization": st["misp_key"], "Accept": "application/json",
               "Content-Type": "application/json"}
    try:
        status, text = _http(url, "POST", headers, json.dumps(body).encode("utf-8"),
                             st["misp_timeout"],
                             _context(url, st["misp_verify_tls"], st["misp_ca_file"]))
    except (urllib.error.URLError, OSError) as exc:
        raise MispError("MISP unreachable: %s" % (getattr(exc, "reason", None) or exc))
    if status != 200:
        raise MispError("MISP HTTP %d: %s" % (status, _snippet(text)))
    try:
        return json.loads(text)
    except ValueError:
        raise MispError("MISP returned invalid JSON")


def fetch_attributes(st, attr_types, window_days):
    found, page = [], 1
    while True:
        if page > st["max_pages"]:
            raise MispError("pagination did not finish within max_pages=%d" % st["max_pages"])
        body = {"returnFormat": "json", "type": attr_types, "to_ids": 1, "published": 1,
                "enforceWarninglist": 1, "limit": st["page_size"], "page": page}
        if window_days:
            body["publish_timestamp"] = "%dd" % window_days
        data = misp_search(st, body)
        response = data.get("response") if isinstance(data, dict) else None
        attrs = response.get("Attribute") if isinstance(response, dict) else None
        if not isinstance(attrs, list):
            raise MispError("unexpected MISP response shape")
        if not attrs:
            return found
        found.extend(attrs)
        page += 1


def normalize(attrs):
    sets = {htype: set() for htype in HASH_ORDER}
    stats = {htype: {"raw": 0, "composite": 0, "invalid": 0} for htype in HASH_ORDER}
    unexpected = 0
    for attr in attrs:
        atype = attr.get("type") if isinstance(attr, dict) else None
        htype = ATTR_TO_HASH.get(atype)
        if htype is None:
            unexpected += 1
            continue
        stats[htype]["raw"] += 1
        value = attr.get("value")
        if not isinstance(value, str):
            stats[htype]["invalid"] += 1
            continue
        if atype.startswith("filename|"):
            stats[htype]["composite"] += 1
            if "|" not in value:
                stats[htype]["invalid"] += 1
                continue
            value = value.rsplit("|", 1)[1]
        value = value.strip().lower()
        if len(value) != HASH_LEN[htype] or not HEX_RE.match(value):
            stats[htype]["invalid"] += 1
            continue
        sets[htype].add(value)
    return sets, stats, unexpected


def indexer_request(st, method, path, body=None):
    token = base64.b64encode(("%s:%s" % (st["idx_user"], st["idx_password"])).encode("utf-8")).decode("ascii")
    headers = {"Authorization": "Basic " + token, "Accept": "application/json"}
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(body, separators=(",", ":")).encode("utf-8")
    url = st["idx_url"] + path
    try:
        status, text = _http(url, method, headers, data, st["idx_timeout"],
                             _context(url, True, st["idx_ca_file"]))
    except (urllib.error.URLError, OSError) as exc:
        raise IndexerError("indexer unreachable: %s" % (getattr(exc, "reason", None) or exc))
    return status, text


def get_previous(st):
    path = "/%s/_search?size=100&_source_includes=type,slot,count" % st["idx_index"]
    status, text = indexer_request(st, "GET", path)
    if status != 200:
        raise IndexerError("indexer HTTP %d reading previous slots: %s" % (status, _snippet(text)))
    try:
        hits = json.loads(text)["hits"]["hits"]
    except (ValueError, KeyError, TypeError):
        raise IndexerError("unexpected indexer response reading previous slots")
    previous = {}
    for hit in hits:
        source = hit.get("_source", {})
        if source.get("type") in HASH_LEN and isinstance(source.get("count"), int):
            previous[source["type"]] = previous.get(source["type"], 0) + source["count"]
    return previous


def build_plan(st, sets, previous):
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    capacity = st["slot_capacity"]
    docs, per_type = [], {}
    for htype in HASH_ORDER:
        values = sorted(sets[htype])
        slots = st["slots_" + htype]
        if len(values) > slots * capacity:
            raise RefusedError("%s: %d values exceed capacity %d (%d slots x %d)"
                               % (htype, len(values), slots * capacity, slots, capacity))
        prev = previous.get(htype) if previous is not None else None
        if (prev is not None and prev >= st["guard_min_previous"]
                and len(values) < prev * st["guard_percent"] / 100.0):
            raise RefusedError("%s: shrink guard: %d values now, %d before (limit %d%%)"
                               % (htype, len(values), prev, st["guard_percent"]))
        window = st["window_days"]
        for number in range(1, slots + 1):
            chunk = values[(number - 1) * capacity:number * capacity]
            docs.append(("%s-%d" % (htype, number),
                         {"type": htype, "slot": number, "count": len(chunk),
                          "generated_at": stamp, "window_days": window, "values": chunk}))
        per_type[htype] = {"unique": len(values), "slots_used": int(math.ceil(len(values) / float(capacity))),
                           "slots_total": slots, "previous": prev}
    return docs, per_type


def write_docs(st, docs):
    for doc_id, doc in docs:
        status, text = indexer_request(st, "PUT", "/%s/_doc/%s" % (st["idx_index"], doc_id), doc)
        if status not in (200, 201):
            raise IndexerError("indexer HTTP %d writing %s: %s" % (status, doc_id, _snippet(text)))
        try:
            reply = json.loads(text)
        except ValueError:
            raise IndexerError("indexer returned invalid JSON writing %s" % doc_id)
        if reply.get("result") not in ("created", "updated") or reply.get("_shards", {}).get("failed", 0):
            raise IndexerError("indexer did not confirm the write of %s" % doc_id)
    # Read every document back (real-time GET, independent of the index refresh
    # interval) and compare what the indexer stored with what was sent.
    for doc_id, doc in docs:
        status, text = indexer_request(
            st, "GET", "/%s/_doc/%s?_source_includes=type,slot,count" % (st["idx_index"], doc_id))
        if status != 200:
            raise IndexerError("indexer HTTP %d reading back %s" % (status, doc_id))
        try:
            stored = json.loads(text).get("_source", {})
        except ValueError:
            raise IndexerError("indexer returned invalid JSON reading back %s" % doc_id)
        if (stored.get("type") != doc["type"] or stored.get("slot") != doc["slot"]
                or stored.get("count") != doc["count"]):
            raise IndexerError("read-back of %s does not match what was written" % doc_id)
    return len(docs)


def run(st, write):
    started = time.time()
    summary = {"version": VERSION, "dry_run": not write, "window_days": st["window_days"]}
    stage = "config"
    try:
        st["misp_key"] = read_secret(st["misp_key_file"], "MISP key")
        st["idx_password"] = read_secret(st["idx_password_file"], "indexer password")
        stage = "misp"
        windowed = fetch_attributes(st, WINDOWED_TYPES, st["window_days"])
        summary["fetched"] = {"windowed": len(windowed)}
        sets, stats, unexpected = normalize(windowed)
        summary["stats"] = stats
        summary["unexpected_types"] = unexpected
        stage = "indexer"
        try:
            previous = get_previous(st)
        except IndexerError as exc:
            if write:
                raise
            previous = None
            summary["previous_error"] = str(exc)
        stage = "plan"
        docs, per_type = build_plan(st, sets, previous)
        summary["types"] = per_type
        if write:
            stage = "indexer"
            summary["indexer_documents"] = write_docs(st, docs)
        summary["result"] = "ok"
        code = EXIT_OK
    except ConfigError as exc:
        summary.update(result="error", stage="config", error=str(exc))
        code = EXIT_CONFIG
    except MispError as exc:
        summary.update(result="error", stage="misp", error=str(exc))
        code = EXIT_MISP
    except RefusedError as exc:
        summary.update(result="error", stage="plan", error=str(exc))
        code = EXIT_REFUSED
    except IndexerError as exc:
        summary.update(result="error", stage=stage, error=str(exc))
        code = EXIT_INDEXER
    summary["duration_s"] = round(time.time() - started, 1)
    return code, summary


def emit(summary, log_file, write):
    line = json.dumps(summary, sort_keys=True)
    print(line)
    if write and log_file:
        stamped = "%s %s\n" % (datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), line)
        try:
            with open(log_file, "a", encoding="utf-8") as handle:
                handle.write(stamped)
        except OSError:
            pass


def main(argv=None):
    parser = argparse.ArgumentParser(description="Build IOC hash slot documents from MISP.")
    parser.add_argument("--config", help="optional INI file (see README)")
    parser.add_argument("--write", action="store_true", help="write the slot documents (default: dry run)")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args(argv)
    if args.version:
        print("misp_hash_slots.py %s" % VERSION)
        return EXIT_OK
    try:
        st = load_config(args.config)
    except ConfigError as exc:
        print(json.dumps({"version": VERSION, "result": "error", "stage": "config", "error": str(exc)}))
        return EXIT_CONFIG
    code, summary = run(st, args.write)
    emit(summary, st["log_file"], args.write)
    return code


if __name__ == "__main__":
    sys.exit(main())
