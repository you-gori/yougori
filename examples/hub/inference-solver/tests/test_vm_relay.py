"""Real HTTP boundary tests: untrusted VM requests cannot choose another destination."""
import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
import vm_relay
from vm_host import Control


class Upstream(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.server.seen.append((self.path, dict(self.headers)))
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        self.send_response(302 if body == b"redirect" else 200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Location", self.server.other)
        self.end_headers()
        self.wfile.write(b'data: {"ok":true}\n\ndata: [DONE]\n\n')


class RelayBoundary(unittest.TestCase):
    def setUp(self):
        self.target = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.trap = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
        self.target.seen, self.trap.seen = [], []
        self.target.other = f"http://127.0.0.1:{self.trap.server_port}/v1/chat/completions"
        self.server = f"http://127.0.0.1:{self.target.server_port}"
        for s in (self.target, self.trap):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    def tearDown(self):
        for s in (self.target, self.trap):
            s.shutdown()
            s.server_close()

    def forward(self, **values):
        out = []
        vm_relay.forward(self.server, "disposable-host-only-secret", values, out.append)
        return out

    def test_guest_headers_and_destination_cannot_redirect_credential(self):
        out = self.forward(method="POST", path="/v1/chat/completions", body=base64.b64encode(b"{}").decode(),
                           url=self.target.other, headers={"Host": "evil.invalid", "Authorization": "guest-secret"})
        self.assertEqual(out[0]["status"], 200)
        self.assertTrue(out[-1]["done"])
        self.assertEqual(len(self.target.seen), 1)
        self.assertEqual(self.target.seen[0][1]["Authorization"], "Bearer disposable-host-only-secret")
        self.assertFalse(self.trap.seen)
        self.assertNotIn("disposable-host-only-secret", json.dumps(out))

    def test_redirect_is_not_followed(self):
        out = self.forward(method="POST", path="/v1/chat/completions", body=base64.b64encode(b"redirect").decode())
        self.assertIn("error", out[-1])
        self.assertFalse(self.trap.seen)

    def test_invalid_paths_bodies_and_connect_never_contact_server(self):
        for method, path, body in [("POST", self.target.other, ""), ("CONNECT", "localhost:22", ""),
                ("POST", "/api/keys", ""), ("POST", "/v1/messages", "%%%"),
                ("GET", "/v1/models", base64.b64encode(b"body").decode())]:
            self.assertIn("error", self.forward(method=method, path=path, body=body)[-1])
        self.assertFalse(self.target.seen)

    def test_control_accepts_only_local_owner_publications(self):
        control = Control("http://abc123.localhost:12345/")
        self.assertEqual(control.port, 12345)
        for url in ("http://evil.invalid:12345/", "https://abc.localhost:443/", "http://127.0.0.1:12345/"):
            with self.assertRaises(ValueError):
                Control(url)


if __name__ == "__main__":
    unittest.main(verbosity=2)
