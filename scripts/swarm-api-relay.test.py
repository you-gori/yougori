"""Real loopback relay requests with a fake provider; no real keys or model charges."""
import importlib.util
import io
import json
from pathlib import Path
import threading
import unittest
import urllib.error
import urllib.request

spec = importlib.util.spec_from_file_location("swarm_api_relay", Path(__file__).with_name("swarm-api-relay.py"))
relay = importlib.util.module_from_spec(spec)
spec.loader.exec_module(relay)


class Reply(io.BytesIO):
    def read1(self, size):
        return self.read(size)


class Provider:
    def __init__(self):
        self.calls = []
        self.failure = None

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.failure:
            raise self.failure
        body = json.loads(request.data)
        return Reply(b'data: {"choices":[{"delta":{"content":"OK"}}]}\n\ndata: [DONE]\n\n' if body.get("stream") else b'{"choices":[{"message":{"content":"OK"}}]}')


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.server = relay.Relay(("127.0.0.1", 0), "fixture-model", "https://example.test/v1",
                                  "provider-private", "local-private")
        self.provider = self.server.opener = Provider()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.close)

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()

    def request(self, path, body=None, key="local-private"):
        req = urllib.request.Request(f"http://127.0.0.1:{self.server.server_port}{path}",
            data=json.dumps(body).encode() if body is not None else None,
            headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=3) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()

    def test_auth_model_and_path_are_enforced_without_provider_calls(self):
        self.assertEqual(self.request("/health", key="wrong")[0], 401)
        self.assertEqual(self.request("/v1/other", {})[0], 404)
        self.assertEqual(self.request("/v1/chat/completions", {"model":"other","messages":[]})[0], 400)
        self.assertEqual(self.request("/v1/chat/completions", {"messages":[],"max_tokens":8193})[0], 400)
        self.assertEqual(self.provider.calls, [])

    def test_json_and_stream_use_only_the_protected_provider_key(self):
        for stream in [False, True]:
            status, data = self.request("/v1/chat/completions", {"messages":[], "stream":stream})
            self.assertEqual(status, 200)
            self.assertIn(b"OK", data)
            self.assertNotIn(b"private", data)
        request, timeout = self.provider.calls[0]
        self.assertEqual(request.full_url, "https://example.test/v1/chat/completions")
        self.assertEqual(request.headers["Authorization"], "Bearer provider-private")
        self.assertEqual(request.headers["User-agent"], "Yougori/1.1 (development model relay)")
        self.assertEqual(json.loads(request.data)["model"], "fixture-model")
        self.assertEqual(timeout, 330)
        self.assertFalse(self.server.slot.locked())

    def test_insufficient_credit_is_visible_without_leaking_provider_body(self):
        self.provider.failure = urllib.error.HTTPError(self.server.url, 402, "private", {}, io.BytesIO(b"provider-private"))
        status, data = self.request("/v1/chat/completions", {"messages":[]})
        self.assertEqual(status, 402)
        self.assertIn(b"insufficient credit", data)
        self.assertNotIn(b"provider-private", data)
        self.assertFalse(self.server.slot.locked())

    def test_health_and_busy_requests_do_not_spend_provider_tokens(self):
        self.server.slot.acquire()
        try:
            health = json.loads(self.request("/health")[1])
            self.assertEqual(health["optimizer"]["active"], 1)
            self.assertEqual(health["context"], 65536)
            self.assertEqual(self.request("/v1/chat/completions", {"messages":[]})[0], 429)
            self.assertEqual(self.provider.calls, [])
        finally:
            self.server.slot.release()

    def test_provider_url_rejects_plaintext_and_embedded_credentials(self):
        for url in ["http://example.test/v1", "https://user:pass@example.test/v1", "https://example.test/v1?key=x"]:
            with self.assertRaises(ValueError):
                relay.provider_url(url)


if __name__ == "__main__":
    unittest.main()
