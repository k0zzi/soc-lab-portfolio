#!/usr/bin/env python3
"""Tests for misp_hash_slots.py. They run the script as a real process against
fake MISP and fake OpenSearch servers. They do NOT talk to a real MISP or a real
OpenSearch cluster."""
import base64
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.environ.get("MISP_HASH_SLOTS", os.path.join(HERE, "..", "misp_hash_slots.py"))
KEY = "YOUR-MISP-KEY-HERE"
PASSWORD = "YOUR-INDEXER-PASSWORD-HERE"
USER = "ioc_hash_writer"
INDEX = "ioc-hash-slots"
LENGTHS = {"md5": 32, "sha1": 40, "sha256": 64}


def h(number, kind):
    return format(number, "x").zfill(LENGTHS[kind])


def attr(atype, value):
    return {"type": atype, "value": value}


class Base(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def send_json(self, code, obj):
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class MispHandler(Base):
    def do_POST(self):
        state = self.server.state
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
        state["requests"].append({"path": self.path, "headers": dict(self.headers), "body": body})
        if state.get("status", 200) != 200:
            return self.send_json(state["status"], {"message": "boom"})
        data = state["windowed"]
        page, limit = body["page"], body["limit"]
        self.send_json(200, {"response": {"Attribute": data[(page - 1) * limit:page * limit]}})


class IndexHandler(Base):
    def authorized(self):
        expected = "Basic " + base64.b64encode(("%s:%s" % (USER, PASSWORD)).encode()).decode()
        return self.headers.get("Authorization") == expected

    def do_PUT(self):
        state = self.server.state
        length = int(self.headers.get("Content-Length", 0))
        doc = json.loads(self.rfile.read(length))
        state["requests"].append(("PUT", self.path))
        if not self.authorized():
            return self.send_json(401, {"error": "unauthorized"})
        if state.get("put_status", 200) not in (200, 201):
            return self.send_json(state["put_status"], {"error": "denied"})
        doc_id = self.path.split("/_doc/")[1].split("?")[0]
        existed = doc_id in state["docs"]
        if state.get("drop_writes"):
            return self.send_json(201, {"result": "created", "_shards": {"failed": 0}})
        if state.get("corrupt_count"):
            doc = dict(doc, count=doc["count"] + 1)
        if state.get("corrupt_slot"):
            doc = dict(doc, slot=doc["slot"] + 100)
        state["docs"][doc_id] = doc
        if state.get("put_reply_failed"):
            return self.send_json(200, {"result": "noop", "_shards": {"failed": 1}})
        self.send_json(200 if existed else 201, {"result": "updated" if existed else "created",
                                                  "_shards": {"failed": 0}})

    def do_GET(self):
        state = self.server.state
        state["requests"].append(("GET", self.path))
        if not self.authorized():
            return self.send_json(401, {"error": "unauthorized"})
        if "/_search" in self.path:
            if state.get("search_status", 200) != 200:
                return self.send_json(state["search_status"], {"error": "no index"})
            hits = [{"_source": src} for src in state["previous"]]
            return self.send_json(200, {"hits": {"hits": hits}})
        if "/_doc/" in self.path:
            doc_id = self.path.split("/_doc/")[1].split("?")[0]
            if doc_id not in state["docs"]:
                return self.send_json(404, {"found": False})
            doc = state["docs"][doc_id]
            return self.send_json(200, {"found": True, "_source": {k: doc[k] for k in ("type", "slot", "count")}})
        if self.path.endswith("/_count"):
            # Models refresh_interval: documents written in this run are NOT visible yet.
            ids = {"%s-%d" % (p["type"], p["slot"]) for p in state["previous"]}
            return self.send_json(200, {"count": len(ids)})
        self.send_json(404, {})


def serve(handler, state):
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.state = state
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


class SlotTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.misp_state = {"requests": [], "windowed": []}
        self.idx_state = {"requests": [], "docs": {}, "previous": []}
        self.misp = serve(MispHandler, self.misp_state)
        self.idx = serve(IndexHandler, self.idx_state)
        for server in (self.misp, self.idx):
            self.addCleanup(server.server_close)
            self.addCleanup(server.shutdown)
        self.addCleanup(self.tmp.cleanup)
        self.key_file = os.path.join(self.tmp.name, "misp.key")
        self.pw_file = os.path.join(self.tmp.name, "idx.pass")
        self.log_file = os.path.join(self.tmp.name, "run.log")
        with open(self.key_file, "w") as fh:
            fh.write(KEY)
        with open(self.pw_file, "w") as fh:
            fh.write(PASSWORD)

    def conf(self, extra=None, misp_extra=None, idx_extra=None):
        lines = ["[misp]", "url = http://127.0.0.1:%d" % self.misp.server_port,
                 "key_file = %s" % self.key_file]
        lines += ["%s = %s" % kv for kv in (misp_extra or {}).items()]
        lines += ["[indexer]", "url = http://127.0.0.1:%d" % self.idx.server_port,
                  "user = %s" % USER, "password_file = %s" % self.pw_file, "index = %s" % INDEX]
        lines += ["%s = %s" % kv for kv in (idx_extra or {}).items()]
        lines += ["[hash_slots]", "log_file = %s" % self.log_file]
        lines += ["%s = %s" % kv for kv in (extra or {}).items()]
        path = os.path.join(self.tmp.name, "test.conf")
        with open(path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        return path

    def run_script(self, *args, **conf_kw):
        conf = self.conf(**conf_kw)
        proc = subprocess.run([sys.executable, SCRIPT, "--config", conf] + list(args),
                              capture_output=True, text=True, timeout=120)
        summary = None
        if proc.stdout.strip():
            summary = json.loads(proc.stdout.strip().splitlines()[-1])
        return proc.returncode, summary, proc

    def values(self, doc_id):
        return self.idx_state["docs"][doc_id]["values"]

    # ---- basics -------------------------------------------------------
    def test_version(self):
        proc = subprocess.run([sys.executable, SCRIPT, "--version"], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)
        self.assertEqual(proc.stdout.strip(), "misp_hash_slots.py 0.2.0")

    def test_dry_run_writes_nothing(self):
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256")), attr("md5", h(2, "md5"))]
        code, summary, _ = self.run_script()
        self.assertEqual(code, 0)
        self.assertTrue(summary["dry_run"])
        self.assertEqual(summary["types"]["sha256"]["unique"], 1)
        self.assertEqual(self.idx_state["docs"], {})
        self.assertFalse([r for r in self.idx_state["requests"] if r[0] == "PUT"])
        self.assertFalse(os.path.exists(self.log_file))

    def test_write_creates_fixed_slots(self):
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256")), attr("md5", h(2, "md5")),
                                       attr("sha1", h(3, "sha1"))]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 0, summary)
        expected = ["sha256-%d" % n for n in range(1, 5)] + ["md5-%d" % n for n in range(1, 5)] + \
                   ["sha1-1"]
        self.assertEqual(sorted(self.idx_state["docs"]), sorted(expected))
        self.assertEqual(self.values("sha256-1"), [h(1, "sha256")])
        for empty in ("sha256-2", "sha256-3", "sha256-4", "md5-2"):
            self.assertEqual(self.values(empty), [])
            self.assertEqual(self.idx_state["docs"][empty]["count"], 0)
        self.assertEqual(self.idx_state["docs"]["sha256-1"]["window_days"], 30)
        self.assertEqual(self.idx_state["docs"]["sha1-1"]["type"], "sha1")
        self.assertEqual(summary["indexer_documents"], 9)
        self.assertNotIn("imphash-1", self.idx_state["docs"])
        self.assertTrue(os.path.exists(self.log_file))

    # ---- retrieval ----------------------------------------------------
    def test_every_query_carries_the_window_and_only_the_three_hash_types(self):
        self.run_script()
        bodies = [r["body"] for r in self.misp_state["requests"]]
        self.assertTrue(bodies)
        for body in bodies:
            self.assertEqual(body["publish_timestamp"], "30d")
            self.assertEqual(sorted(body["type"]),
                             sorted(["md5", "sha1", "sha256", "filename|md5", "filename|sha1", "filename|sha256"]))
            self.assertEqual((body["to_ids"], body["published"], body["enforceWarninglist"]), (1, 1, 1))
            self.assertEqual(body["returnFormat"], "json")

    def test_window_days_is_configurable(self):
        self.run_script(extra={"window_days": "7"})
        windowed = [r["body"] for r in self.misp_state["requests"]]
        self.assertEqual(windowed[0]["publish_timestamp"], "7d")

    def test_paging_ends_on_empty_page(self):
        self.misp_state["windowed"] = [attr("sha256", h(n, "sha256")) for n in range(1, 6)]
        code, summary, _ = self.run_script("--write", extra={"page_size": "2"})
        self.assertEqual(code, 0, summary)
        self.assertEqual(len(self.values("sha256-1")), 5)
        pages = [r["body"]["page"] for r in self.misp_state["requests"]]
        self.assertEqual(pages, [1, 2, 3, 4])

    def test_max_pages_exceeded_writes_nothing(self):
        self.misp_state["windowed"] = [attr("sha256", h(n, "sha256")) for n in range(1, 6)]
        code, summary, _ = self.run_script("--write", extra={"page_size": "1", "max_pages": "2"})
        self.assertEqual(code, 2)
        self.assertIn("max_pages", summary["error"])
        self.assertEqual(self.idx_state["docs"], {})

    def test_misp_error_writes_nothing(self):
        self.misp_state["status"] = 500
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 2)
        self.assertEqual(summary["stage"], "misp")
        self.assertEqual(self.idx_state["docs"], {})

    # ---- normalization ------------------------------------------------
    def test_normalization(self):
        upper = h(0xABCDEF, "sha256").upper()
        self.misp_state["windowed"] = [
            attr("sha256", upper),
            attr("sha256", "  " + h(0xABCDEF, "sha256") + "  "),
            attr("filename|sha256", "evil.exe|" + h(7, "sha256").upper()),
            attr("filename|sha256", "we|ird|name|" + h(8, "sha256")),
            attr("filename|sha256", h(9, "sha256")),
            attr("sha256", "abc"),
            attr("sha256", "z" * 64),
            attr("filename|md5", "a.dll|" + h(5, "md5")),
        ]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 0, summary)
        self.assertEqual(self.values("sha256-1"), sorted([h(0xABCDEF, "sha256"), h(7, "sha256"), h(8, "sha256")]))
        self.assertEqual(self.values("md5-1"), [h(5, "md5")])
        stats = summary["stats"]["sha256"]
        self.assertEqual((stats["raw"], stats["composite"], stats["invalid"]), (7, 3, 3))

    def test_unexpected_types_are_counted_not_used(self):
        self.misp_state["windowed"] = [attr("ip-dst", "1.2.3.4"), attr("sha256", h(1, "sha256"))]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 0)
        self.assertEqual(summary["unexpected_types"], 1)
        self.assertEqual(self.values("sha256-1"), [h(1, "sha256")])

    def test_imphash_is_not_requested_and_never_stored(self):
        self.misp_state["windowed"] = [attr("md5", h(42, "md5")), attr("imphash", "f" * 32),
                                       attr("filename|imphash", "x.dll|" + "e" * 32)]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["unexpected_types"], 2)
        self.assertEqual(self.values("md5-1"), [h(42, "md5")])
        self.assertFalse([d for d in self.idx_state["docs"] if d.startswith("imphash")])
        for request in self.misp_state["requests"]:
            self.assertFalse([t for t in request["body"]["type"] if "imphash" in t])

    # ---- slots, capacity, guard ----------------------------------------
    def test_chunking_across_slots(self):
        self.misp_state["windowed"] = [attr("sha256", h(n, "sha256")) for n in (5, 1, 7, 3, 2, 6, 4)]
        code, summary, _ = self.run_script("--write", extra={"slot_capacity": "3", "slots_sha256": "3"})
        self.assertEqual(code, 0, summary)
        got = [self.values("sha256-%d" % n) for n in (1, 2, 3)]
        self.assertEqual([len(v) for v in got], [3, 3, 1])
        self.assertEqual(sum(got, []), sorted(h(n, "sha256") for n in range(1, 8)))
        self.assertEqual(summary["types"]["sha256"]["slots_used"], 3)

    def test_overflow_is_refused_without_writing(self):
        self.misp_state["windowed"] = [attr("sha256", h(n, "sha256")) for n in range(1, 4)]
        code, summary, _ = self.run_script("--write", extra={"slot_capacity": "2", "slots_sha256": "1"})
        self.assertEqual(code, 3)
        self.assertIn("exceed capacity", summary["error"])
        self.assertEqual(self.idx_state["docs"], {})

    def test_overflow_in_one_type_blocks_every_type(self):
        self.misp_state["windowed"] = [attr("sha256", h(n, "sha256")) for n in range(1, 4)] + [attr("md5", h(1, "md5"))]
        code, _, _ = self.run_script("--write", extra={"slot_capacity": "2", "slots_sha256": "1"})
        self.assertEqual(code, 3)
        self.assertEqual(self.idx_state["docs"], {})

    def test_shrink_guard_blocks_big_drop(self):
        self.idx_state["previous"] = [{"type": "sha256", "slot": 1, "count": 10000}]
        self.misp_state["windowed"] = [attr("sha256", h(n, "sha256")) for n in range(1, 101)]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 3)
        self.assertIn("shrink guard", summary["error"])
        self.assertEqual(self.idx_state["docs"], {})

    def test_shrink_guard_allows_moderate_drop(self):
        self.idx_state["previous"] = [{"type": "sha256", "slot": 1, "count": 10000}]
        self.misp_state["windowed"] = [attr("sha256", h(n, "sha256")) for n in range(1, 6001)]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 0, summary)
        self.assertEqual(self.idx_state["docs"]["sha256-1"]["count"], 6000)

    def test_shrink_guard_ignores_small_previous(self):
        self.idx_state["previous"] = [{"type": "sha256", "slot": 1, "count": 500}]
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        code, _, _ = self.run_script("--write")
        self.assertEqual(code, 0)

    # ---- indexer behavior ---------------------------------------------
    def test_indexer_write_error(self):
        self.idx_state["put_status"] = 403
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 4)
        self.assertIn("403", summary["error"])

    def test_wrong_indexer_password_fails(self):
        with open(self.pw_file, "w") as fh:
            fh.write("not-the-password")
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 4)
        self.assertIn("401", summary["error"])

    def test_missing_index_fails_in_write_mode_only(self):
        self.idx_state["search_status"] = 404
        code, summary, _ = self.run_script()
        self.assertEqual(code, 0)
        self.assertIn("previous_error", summary)
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 4)
        self.assertEqual(self.idx_state["docs"], {})

    def test_credentials_sent_and_not_leaked(self):
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        code, summary, proc = self.run_script("--write")
        self.assertEqual(code, 0, summary)
        self.assertTrue(all(r["headers"].get("Authorization") == KEY for r in self.misp_state["requests"]))
        with open(self.log_file) as handle:
            output = proc.stdout + proc.stderr + handle.read()
        self.assertNotIn(KEY, output)
        self.assertNotIn(PASSWORD, output)
        self.assertNotIn(base64.b64encode(("%s:%s" % (USER, PASSWORD)).encode()).decode(), output)

    def test_error_output_does_not_leak_secrets(self):
        self.idx_state["put_status"] = 500
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        _, _, proc = self.run_script("--write")
        self.assertNotIn(KEY, proc.stdout + proc.stderr)
        self.assertNotIn(PASSWORD, proc.stdout + proc.stderr)

    def test_misp_error_output_does_not_leak_key(self):
        self.misp_state["status"] = 500
        _, summary, proc = self.run_script("--write")
        self.assertEqual(summary["stage"], "misp")
        self.assertNotIn(KEY, proc.stdout + proc.stderr)

    def test_verification_does_not_depend_on_index_refresh(self):
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 0, summary)
        self.assertEqual(summary["indexer_documents"], 9)
        paths = [path for _, path in self.idx_state["requests"]]
        self.assertFalse([p for p in paths if "/_count" in p])
        self.assertEqual(len([p for p in paths if "/_doc/" in p and p.startswith("/%s/_doc/" % INDEX)]), 18)

    def test_acknowledged_but_lost_write_is_detected(self):
        self.idx_state["drop_writes"] = True
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 4)
        self.assertIn("404", summary["error"])

    def test_read_back_mismatch_is_detected(self):
        self.idx_state["corrupt_count"] = True
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 4)
        self.assertIn("does not match", summary["error"])

    def test_wrong_slot_number_on_read_back_is_detected(self):
        self.idx_state["corrupt_slot"] = True
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 4)
        self.assertIn("does not match", summary["error"])

    def test_unconfirmed_write_reply_is_an_error_even_if_stored(self):
        self.idx_state["put_reply_failed"] = True
        self.misp_state["windowed"] = [attr("sha256", h(1, "sha256"))]
        code, summary, _ = self.run_script("--write")
        self.assertEqual(code, 4)
        self.assertIn("did not confirm", summary["error"])

    # ---- configuration -------------------------------------------------
    def test_unknown_option_is_rejected(self):
        code, summary, _ = self.run_script(extra={"no_such_option": "1"})
        self.assertEqual(code, 1)
        self.assertIn("unknown option", summary["error"])

    def test_removed_imphash_slot_option_is_rejected(self):
        code, summary, _ = self.run_script(extra={"slots_imphash": "1"})
        self.assertEqual(code, 1)
        self.assertIn("unknown option", summary["error"])

    def test_capacity_above_terms_limit_is_rejected(self):
        code, summary, _ = self.run_script(extra={"slot_capacity": "70000"})
        self.assertEqual(code, 1)
        self.assertIn("65536", summary["error"])

    def test_missing_key_file_is_a_config_error(self):
        os.remove(self.key_file)
        code, summary, _ = self.run_script()
        self.assertEqual(code, 1)
        self.assertIn("MISP key", summary["error"])
        self.assertFalse(self.misp_state["requests"])


if __name__ == "__main__":
    unittest.main(verbosity=1)
