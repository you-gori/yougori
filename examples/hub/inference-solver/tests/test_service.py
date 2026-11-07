"""Real HTTP/SQLite checks with a disposable upstream, not a GPU benchmark.

Run: python -I -B examples/hub/inference-solver/tests/test_service.py
"""
from concurrent.futures import ThreadPoolExecutor
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

SITE = Path(__file__).resolve().parents[1] / "site"
sys.path.insert(0, str(SITE))
import attached
from server import Service, Server
from store import Store
import upstream

PASSWORD = "disposable-test-password"
UPSTREAM_KEY = "disposable-upstream-key"


class Model(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, value):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer " + UPSTREAM_KEY:
            return self.reply(401, {"error": UPSTREAM_KEY})
        if self.server.fail_catalog:
            return self.reply(503, {"error": UPSTREAM_KEY})
        self.reply(200, {"data": [{"id": name} for name in self.server.models]})

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + UPSTREAM_KEY:
            return self.reply(401, {"error": UPSTREAM_KEY})
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        with self.server.lock:
            self.server.calls.append(data)
        if getattr(self.server, "broken", False):
            return self.reply(503, {"error": UPSTREAM_KEY})
        first = data["messages"][0].get("content")
        if first == "fail":
            return self.reply(500, {"error": UPSTREAM_KEY})
        if first == "refuse":
            return self.reply(400, {"error": {"message": "The prompt is longer than the context."}})
        if first == "slow":
            time.sleep(0.05)
        usage = {"prompt_tokens": 3, "completion_tokens": 2}
        # Cache reports as vLLM gives them (prompt_tokens_details) or as llama.cpp does (timings).
        if getattr(self.server, "cached", None) is not None:
            usage["prompt_tokens_details"] = {"cached_tokens": self.server.cached}
        extra = {"timings": {"cache_n": self.server.cache_n, "prompt_n": 3}} if getattr(self.server, "cache_n", None) is not None else {}
        if data.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            chunks = [
                {"model": data["model"], "choices": [{"delta": {"content": "hello"}, "index": 0}]},
                {"model": data["model"], "choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_fixture", "type": "function", "function": {"name": "noop", "arguments": "{"}}]}, "index": 0}]},
                {"model": data["model"], "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "}"}}]}, "index": 0, "finish_reason": "tool_calls"}]},
                {"choices": [], "usage": usage, **extra},
            ]
            for chunk in chunks:
                self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
                self.wfile.flush()
            if first != "truncate":
                self.wfile.write(b"data: [DONE]\n\n")
            return
        self.reply(200, {"model": data["model"], "choices": [{"message": {"role": "assistant", "content": "hello"}}], "usage": usage, **extra})


class Flow(unittest.TestCase):
    account_mode = "public"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="inference-solver-test-")
        self.service = Service(self.temp.name, {"email": "admin@example.invalid", "password": PASSWORD}, account_mode=self.account_mode)
        self.web = Server(("127.0.0.1", 0), self.service)
        self.model = ThreadingHTTPServer(("127.0.0.1", 0), Model)
        self.model.models, self.model.calls, self.model.fail_catalog, self.model.lock = ["test/one", "test/two"], [], False, threading.Lock()
        self.threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in (self.web, self.model)]
        for thread in self.threads:
            thread.start()
        self.url = f"http://127.0.0.1:{self.web.server_port}"
        self.model_url = f"http://127.0.0.1:{self.model.server_port}/v1"
        self.admin = self.login("admin@example.invalid")

    def tearDown(self):
        self.service.stopped.set()
        for server in (self.web, self.model):
            server.shutdown()
            server.server_close()
        for thread in self.threads:
            thread.join()
        self.temp.cleanup()

    def call(self, path, body=None, session=None, key=None, headers=None):
        values = {"Origin": self.url, "Content-Type": "application/json"}
        if session:
            values.update({"Cookie": session[0], "X-CSRF-Token": session[1]})
        if key:
            values["Authorization"] = "Bearer " + key
        values.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.web.server_port, timeout=10)
        try:
            conn.request("GET" if body is None else "POST", path, body=None if body is None else json.dumps(body), headers=values)
            result = conn.getresponse()
            raw = result.read().decode()
            return result.status, json.loads(raw) if result.getheader("Content-Type", "").startswith("application/json") else raw, dict(result.getheaders())
        finally:
            conn.close()

    def login(self, email):
        status, _, headers = self.call("/api/login", {"email": email, "password": PASSWORD})
        self.assertEqual(status, 200)
        cookie = headers["Set-Cookie"].split(";")[0]
        status, data, _ = self.call("/api/session", session=(cookie, ""))
        return cookie, data["user"]["csrf"]

    def endpoint(self):
        status, body, _ = self.call("/api/admin/endpoints", {"name": "Test model", "url": self.model_url, "key": UPSTREAM_KEY, "place": "local"}, self.admin)
        self.assertEqual(status, 201, body)
        return body["id"]

    def key(self, scopes=None, session=None):
        status, body, _ = self.call("/api/keys", {"label": "Test", "scopes": scopes or ["*"]}, session or self.admin)
        self.assertEqual(status, 201, body)
        return body

    def completion(self, model, stream=False, content="hello"):
        return {"model": model, "messages": [{"role": "user", "content": content}], "stream": stream}

    def member(self):
        status, data, _ = self.call("/api/admin/invitations", {"email": "member@example.invalid"}, self.admin)
        self.assertEqual(status, 201)
        invite = {"email": "member@example.invalid", "password": PASSWORD, "invitation": data["invitation"], "admin": True}
        status, _, _ = self.call("/api/join", invite)
        self.assertEqual(status, 200)
        self.assertEqual(self.call("/api/join", invite)[0], 400)
        return self.login("member@example.invalid")

    def test_invitation_admin_boundaries_and_csrf(self):
        member = self.member()
        self.assertFalse(self.call("/api/session", session=member)[1]["user"]["admin"])
        for path in ("endpoints", "site", "invitations", "refresh", "endpoints/remove", "models/censorship"):
            self.assertEqual(self.call("/api/admin/" + path, {}, member)[0], 403)
        self.assertEqual(self.call("/api/admin/overview", session=member)[0], 403)
        self.assertEqual(self.call("/api/keys", {"label": "x", "scopes": ["*"]}, self.admin, headers={"Origin": "https://attacker.invalid"})[0], 403)
        self.assertEqual(self.call("/api/keys", {}, self.admin, headers={"X-CSRF-Token": "wrong"})[0], 403)
        self.assertEqual(self.call("/api/join", {"email": "a@example.invalid", "password": PASSWORD, "invitation": 42})[0], 400)
        self.assertEqual(self.call("/api/models")[0], 200)
        self.assertEqual(self.call("/api/session", headers={"Host": "attacker.invalid"})[0], 403)
        self.assertEqual(self.call("/api/logout", {}, self.admin)[0], 200)
        self.assertIsNone(self.call("/api/session", session=self.admin)[1]["user"])

    def test_public_signup_session_and_member_permissions(self):
        self.endpoint()
        status, _, headers = self.call("/api/signup", {
            "email": " New@example.invalid ", "password": PASSWORD, "admin": True, "role": "admin",
        })
        self.assertEqual(status, 201)
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])
        cookie = headers["Set-Cookie"].split(";")[0]
        user = self.call("/api/session", session=(cookie, ""))[1]["user"]
        self.assertEqual(user["email"], "new@example.invalid")
        self.assertFalse(user["admin"])
        member = cookie, user["csrf"]
        for path in ("endpoints", "site", "invitations", "refresh", "endpoints/remove", "models/censorship"):
            self.assertEqual(self.call("/api/admin/" + path, {}, member)[0], 403)
        self.assertEqual(self.call("/api/admin/overview", session=member)[0], 403)
        self.assertEqual(self.call("/api/keys", {"label": "x", "scopes": ["*"]}, member,
                                   headers={"X-CSRF-Token": "wrong"})[0], 403)
        key = self.key(["test/one"], member)
        self.assertEqual(self.call("/v1/chat/completions", self.completion("test/one"), key=key["key"])[0], 200)
        self.assertEqual(self.call("/api/keys", session=self.admin)[1]["keys"], [])
        with self.service.store.db() as db:
            stored = db.execute("SELECT password FROM users WHERE id=?", (user["id"],)).fetchone()[0]
            self.assertNotIn(PASSWORD, stored)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users WHERE admin=1").fetchone()[0], 1)
        self.assertEqual(self.call("/api/logout", {}, member)[0], 200)
        self.assertIsNone(self.call("/api/session", session=member)[1]["user"])
        self.login("new@example.invalid")

    def test_signup_validation_duplicate_race_and_existing_admin(self):
        for address, password in (("bad-email", PASSWORD), ("new@example.invalid", "short")):
            self.assertEqual(self.call("/api/signup", {"email": address, "password": password})[0], 400)
        payload = {"email": "parallel@example.invalid", "password": PASSWORD}
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.call("/api/signup", payload), range(2)))
        self.assertEqual(sorted(result[0] for result in results), [201, 400])
        self.assertEqual(self.call("/api/signup", {**payload, "email": " PARALLEL@example.invalid "})[0], 400)
        self.assertEqual(self.call("/api/signup", {"email": "ADMIN@example.invalid", "password": "different-password"})[0], 400)
        self.login("admin@example.invalid")
        with self.service.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 2)
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users WHERE admin=1").fetchone()[0], 1)

    def test_signup_origin_and_rate_limit(self):
        payload = {"email": "blocked@example.invalid", "password": PASSWORD}
        self.assertEqual(self.call("/api/signup", payload, headers={"Origin": "https://attacker.invalid"})[0], 403)
        # Sign-in and signup share the same bounded attempt window. setUp used one attempt.
        for _ in range(11):
            self.assertEqual(self.call("/api/signup", {**payload, "password": "short"})[0], 400)
        status, _, headers = self.call("/api/signup", payload)
        self.assertEqual(status, 429)
        self.assertIn("Retry-After", headers)
        with self.service.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_account_access_is_independent_of_publication(self):
        for published in (False, True):
            self.service.public = published
            origin = ("https://" if published else "http://") + self.url.split("://", 1)[1]
            for mode in ("public", "private"):
                with self.subTest(published=published, mode=mode):
                    self.service.account_mode = mode
                    self.assertEqual(self.call("/api/session")[1]["mode"], mode)
                    status, _, headers = self.call("/api/signup", {
                        "email": f"{mode}-{published}@example.invalid", "password": PASSWORD,
                    }, headers={"Origin": origin})
                    self.assertEqual(status, 201 if mode == "public" else 403)
                    if status == 201:
                        self.assertEqual("; Secure" in headers["Set-Cookie"], published)
        self.service.public = False
        self.service.account_mode = "private"
        member = self.member()
        self.assertFalse(self.call("/api/session", session=member)[1]["user"]["admin"])
        with self.service.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM users WHERE email LIKE 'private-%'").fetchone()[0], 0)

    def test_visitors_browse_catalog_but_cannot_use_accounts_or_inference(self):
        self.assertEqual(self.call("/api/models")[1], {"models": []})
        status, catalog, _ = self.call("/api/harnesses")
        self.assertEqual(status, 200)
        self.assertEqual(len(catalog["harnesses"]), 21)
        self.endpoint()
        status, catalog, _ = self.call("/api/models")
        self.assertEqual(status, 200)
        self.assertEqual({m["id"] for m in catalog["models"]}, {"test/one", "test/two"})
        for model in catalog["models"]:
            self.assertEqual(set(model), {"id", "upstream", "state", "protocols", "price", "cache", "censorship", "censorship_source"})
        self.assertNotIn(UPSTREAM_KEY, json.dumps(catalog))
        self.assertNotIn(self.model_url, json.dumps(catalog))
        for path in ("/api/keys", "/api/usage", "/api/admin/overview", "/v1/models"):
            self.assertEqual(self.call(path)[0], 401, path)
        for path in ("/api/keys", "/api/keys/revoke", "/api/admin/endpoints", "/api/admin/site", "/api/admin/invitations"):
            self.assertEqual(self.call(path, {})[0], 403, path)
        self.assertEqual(self.call("/v1/chat/completions", self.completion("test/one"))[0], 401)
        self.assertEqual(self.model.calls, [])

    def test_scope_streaming_revocation_and_private_usage(self):
        self.endpoint()
        first, second = "test/one", "test/two"
        key = self.key([first])
        self.assertEqual([m["id"] for m in self.call("/v1/models", key=key["key"])[1]["data"]], [first])
        self.assertEqual(self.call("/v1/chat/completions", self.completion(second), key=key["key"])[0], 403)
        self.assertEqual(len(self.model.calls), 0)
        status, body, _ = self.call("/v1/chat/completions", self.completion(first), key=key["key"])
        self.assertEqual(status, 200)
        self.assertEqual(body["model"], first)
        self.assertEqual(self.model.calls[-1]["model"], "test/one")
        status, stream, _ = self.call("/v1/chat/completions", self.completion(first, True), key=key["key"])
        self.assertEqual(status, 200)
        self.assertIn("data: [DONE]", stream)
        self.assertIn("tool_calls", stream)
        self.assertIn(first, stream)
        self.assertNotIn(UPSTREAM_KEY, stream)
        time.sleep(0.02)
        usage = self.call("/api/usage", session=self.admin)[1]["requests"]
        self.assertEqual(len(usage), 2)
        self.assertTrue(all(row["input_tokens"] == 3 and row["status"] == "completed" for row in usage))
        member = self.member()
        self.assertEqual(self.call("/api/usage", session=member)[1]["requests"], [])
        self.call("/api/keys/revoke", {"id": key["id"]}, member)
        self.assertEqual(self.call("/v1/models", key=key["key"])[0], 200)
        self.call("/api/keys/revoke", {"id": key["id"]}, self.admin)
        self.assertEqual(self.call("/v1/models", key=key["key"])[0], 401)
        listed = json.dumps(self.call("/api/keys", session=self.admin)[1])
        self.assertNotIn(key["key"], listed)
        self.assertNotIn(UPSTREAM_KEY, json.dumps(self.call("/api/admin/overview", session=self.admin)[1]))

    def test_errors_catalog_refresh_staleness_and_concurrent_callers(self):
        self.endpoint()
        model, key = "test/one", self.key()["key"]
        status, error, _ = self.call("/v1/chat/completions", self.completion(model, content="fail"), key=key)
        self.assertEqual(status, 502)
        self.assertNotIn(UPSTREAM_KEY, json.dumps(error))
        _, stream, _ = self.call("/v1/chat/completions", self.completion(model, True, "truncate"), key=key)
        self.assertIn("event: error", stream)
        self.assertNotIn("[DONE]", stream)
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(lambda _: self.call("/v1/chat/completions", self.completion(model, content="slow"), key=key)[0], range(8)))
        self.assertEqual(results, [200] * 8)
        self.model.models = ["test/three"]
        self.service.refresh()
        self.assertEqual(self.call("/v1/chat/completions", self.completion(model), key=key)[0], 404)
        self.assertEqual(self.call("/v1/models", key=key)[1]["data"][0]["id"], "test/three")
        self.model.fail_catalog = True
        self.service.refresh()
        self.assertEqual(self.call("/v1/models", key=key)[1]["data"], [])
        self.assertEqual(self.call("/v1/chat/completions", self.completion("test/three"), key=key)[0], 503)
        self.model.fail_catalog = False
        self.service.refresh()
        with self.service.store.db() as db:
            db.execute("UPDATE endpoints SET checked=1")
        self.assertEqual(self.call("/v1/models", key=key)[1]["data"], [])

    def test_receiver_replay_key_refresh_detach_and_secret_file_cleanup(self):
        request = {"action": "attach", "environment": "model-1", "model": "test/model", "url": self.model_url, "key": UPSTREAM_KEY, "place": "local"}
        for _ in range(2):
            self.assertTrue(attached.receive(self.service.store, request)["attached"])
        with self.service.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0], 1)
        before = [m["id"] for m in self.service.store.models()]
        file = Path(self.temp.name) / "model-request.json"
        file.write_text(json.dumps(request), encoding="utf-8")
        result = subprocess.run([sys.executable, "-I", "-B", str(SITE / "attached.py"), str(file)],
                                env={**os.environ, "SOLVER_DATA": self.temp.name}, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertNotIn(UPSTREAM_KEY, result.stdout + result.stderr)
        self.assertFalse(file.exists())
        self.assertEqual(before, [m["id"] for m in self.service.store.models()])
        for expected in (True, False):
            self.assertEqual(attached.receive(self.service.store, {"action": "detach", "environment": "model-1"})["detached"], expected)
        self.assertEqual(self.service.store.models(), [])

    def test_censorship_comes_from_names_and_admin_labels_survive_refresh(self):
        self.model.models = ["org/Qwen3-8B-abliterated", "test/plain"]
        self.endpoint()
        abliterated, plain = "org/Qwen3-8B-abliterated", "test/plain"
        def labels():
            return {m["id"]: (m["censorship"], m["censorship_source"]) for m in self.call("/api/models")[1]["models"]}
        self.assertEqual(labels(), {abliterated: ("uncensored", "name"), plain: ("censored", "name")})
        for model, value in ((plain, "uncensored"), (abliterated, "censored")):
            self.assertEqual(self.call("/api/admin/models/censorship", {"id": model, "censorship": value}, self.admin)[0], 200)
        # A refresh replaces the model rows; the administrator's labels must outlive it.
        self.service.refresh()
        self.assertEqual(labels(), {abliterated: ("censored", "administrator"), plain: ("uncensored", "administrator")})
        self.assertEqual(self.call("/api/admin/models/censorship", {"id": plain, "censorship": "automatic"}, self.admin)[0], 200)
        self.assertEqual(labels()[plain], ("censored", "name"))
        for bad in ({"id": plain, "censorship": "maybe"}, {"id": "test/missing", "censorship": "censored"}, {"id": 42, "censorship": "censored"}):
            self.assertEqual(self.call("/api/admin/models/censorship", bad, self.admin)[0], 400, bad)
        self.assertEqual(self.call("/api/admin/models/censorship", {"id": plain, "censorship": "censored"})[0], 403)
        self.assertIn("model.labeled", {entry["action"] for entry in self.call("/api/admin/overview", session=self.admin)[1]["audit"]})

    def test_restart_preserves_admin_branding_and_keys(self):
        key = self.key()["key"]
        self.call("/api/admin/site", {"name": "My team", "tagline": "Hello", "accent": "#123abc"}, self.admin)
        reopened = Store(self.temp.name, {"email": "replacement@example.invalid", "password": "replacement-password"})
        self.assertEqual(reopened.settings()["name"], "My team")
        self.assertIsNotNone(reopened.key(key))
        with self.assertRaises(ValueError):
            reopened.login("replacement@example.invalid", "replacement-password")
        self.assertTrue(reopened.login("admin@example.invalid", PASSWORD))

    def test_transport_refuses_metadata_and_public_plaintext_and_does_not_follow_redirects(self):
        for target in ("http://169.254.169.254/v1", "http://[::ffff:169.254.169.254]/v1", "http://[fd00:ec2::254]/v1", "http://8.8.8.8/v1"):
            with self.assertRaises(upstream.UpstreamError), patch.object(upstream.socket, "create_connection") as connect:
                upstream.discover(target, UPSTREAM_KEY)
            connect.assert_not_called()
        for target in ("http://user:password@localhost/v1", "http://localhost/v1?x=1", "http://localhost/metadata", "file:///v1"):
            with self.assertRaises(ValueError):
                upstream.address(target)
        self.assertEqual(self.call("/api/admin/endpoints", {"name": "Bad key", "url": self.model_url, "key": "wrong"}, self.admin)[0], 502)
        # A model endpoint's redirect is an error, never a second credentialed request.
        with patch.object(Model, "do_GET", lambda handler: (handler.send_response(302), handler.send_header("Location", "http://169.254.169.254/latest"), handler.end_headers())):
            with self.assertRaises(upstream.UpstreamError):
                upstream.discover(self.model_url, UPSTREAM_KEY)


if __name__ == "__main__":
    unittest.main(verbosity=2)
