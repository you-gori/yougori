"""The website-hosted production runner: one plain process behind the website's proxy."""
import base64
import hashlib
import http.client
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site"))
from managed import create
from server import Server


def provision(root, access="internal"):
    salt = bytes(range(16))
    key = hashlib.scrypt(b"fixture-password", salt=salt, n=32768, r=8, p=1, dklen=32, maxmem=96 * 1024 * 1024)
    credential = "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(key).decode()
    (root / "provision.json").write_text(json.dumps({
        "id": "inf_" + "b" * 16, "email": "admin@example.test", "passwordHash": credential, "slug": "acme",
        "siteName": "Acme inference", "accessMode": access, "wallet": None,
        "compute": {"neocloud": True, "neoGrid": True, "sandboxGrid": False, "publicContributors": False, "providers": ["runpod"]}}))


class Instance:
    """A managed instance on a free loopback port, in a thread."""

    def __init__(self, root, authority, scheme):
        self.service = create(root, authority, scheme)
        self.server = Server(("127.0.0.1", 0), self.service)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        raw = json.dumps(body).encode() if body is not None else None
        sent = {"Content-Type": "application/json", **(headers or {})}
        connection.request(method, path, body=raw, headers=sent)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, response.getheader("Set-Cookie", ""), data

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.service.close()


class Managed(unittest.TestCase):
    def test_https_instance_serves_its_own_address_with_secure_cookies(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provision(root)
            instance = Instance(root, "acme.yougori.com", "https")
            try:
                own = {"Host": "acme.yougori.com", "Origin": "https://acme.yougori.com"}
                self.assertEqual(instance.request("GET", "/health", headers=own)[0], 200)
                self.assertEqual(instance.request("GET", "/health", headers={"Host": "other.yougori.com"})[0], 403)
                status, cookie, _ = instance.request("POST", "/api/login", {"email": "admin@example.test", "password": "fixture-password"}, own)
                self.assertEqual(status, 200)
                self.assertIn("solver_session=", cookie)
                self.assertIn("; Secure", cookie)
                # Browser requests must come from the https origin.
                status, _, _ = instance.request("POST", "/api/login", {"email": "admin@example.test", "password": "fixture-password"},
                                                {"Host": "acme.yougori.com", "Origin": "http://acme.yougori.com"})
                self.assertEqual(status, 403)
                status, _, _ = instance.request("POST", "/api/login", {"email": "admin@example.test", "password": "wrong-password"}, own)
                self.assertEqual(status, 400)
                self.assertTrue(instance.service.public)
                self.assertEqual(instance.service.account_mode, "private")
                self.assertEqual(instance.service.store.settings()["name"], "Acme inference")
            finally:
                instance.close()

    def test_attempt_limits_use_the_address_the_proxy_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provision(root)
            instance = Instance(root, "acme.localhost:5198", "http")
            try:
                base = {"Host": "acme.localhost:5198", "Origin": "http://acme.localhost:5198"}
                wrong = {"email": "admin@example.test", "password": "wrong-password"}
                first = {**base, "X-Forwarded-For": "203.0.113.5"}
                statuses = [instance.request("POST", "/api/login", wrong, first)[0] for _ in range(13)]
                self.assertEqual(statuses[:12], [400] * 12)
                self.assertEqual(statuses[12], 429)
                # Another visitor behind the same proxy is not locked out with the first one.
                second = {**base, "X-Forwarded-For": "203.0.113.6"}
                self.assertEqual(instance.request("POST", "/api/login", wrong, second)[0], 400)
                status, cookie, _ = instance.request("POST", "/api/login", {"email": "admin@example.test", "password": "fixture-password"}, second)
                self.assertEqual(status, 200)
                self.assertNotIn("Secure", cookie)
            finally:
                instance.close()

    def test_rejects_addresses_and_schemes_the_proxy_would_never_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            provision(root, "public")
            for authority, scheme in [("acme", "https"), ("Acme.yougori.com", "https"), ("acme.yougori.com/x", "https"),
                                      ("acme.yougori.com", "ftp"), ("-acme.yougori.com", "https"), ("acme.yougori.com:99999x", "https")]:
                with self.assertRaises(ValueError, msg=authority):
                    create(root, authority, scheme)
            service = create(root, "acme.yougori.com", "https")
            try:
                self.assertEqual(service.account_mode, "public")
                self.assertEqual(service.hosted["authority"], "acme.yougori.com")
                self.assertTrue(service.hosted["proxied"])
            finally:
                # Its media watcher holds the database while it reads; the folder goes next.
                service.close()


if __name__ == "__main__":
    unittest.main()
