"""The practice app security harnesses may test inside their VM: loopback only, made-up data, and
the flaws it promises really there (so a harness run against it has true findings to report)."""
from pathlib import Path
import sys
import threading
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
import practice_app


class PracticeApp(unittest.TestCase):
    def setUp(self):
        self.server = practice_app.serve(0)
        self.base = "http://127.0.0.1:%d" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def get(self, path, data=None):
        try:
            with self.opener.open(self.base + path, data=data, timeout=10) as response:
                return response.status, response.read().decode()
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode()

    def test_it_listens_on_loopback_only(self):
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_pages_answer(self):
        for path in ("/", "/login", "/search?q=mug", "/hello?name=x", "/account?id=2", "/robots.txt", "/backup"):
            status, _ = self.get(path)
            self.assertEqual(status, 200, path)
        self.assertEqual(self.get("/nothing")[0], 404)

    def test_the_promised_flaws_are_real(self):
        # SQL injection in the search returns every user's password.
        query = urllib.parse.quote("x' UNION SELECT name, password FROM users --")
        status, body = self.get("/search?q=" + query)
        self.assertEqual(status, 200)
        self.assertIn("alice", body)
        # SQL injection in the sign-in check signs in without a password.
        form = urllib.parse.urlencode({"user": "admin' --", "password": "x"}).encode()
        status, body = self.get("/login", form)
        self.assertEqual((status, "Signed in as admin" in body), (200, True))
        # Reflected cross-site scripting.
        self.assertIn("<script>1</script>", self.get("/hello?name=" + urllib.parse.quote("<script>1</script>"))[1])
        # Any account by number, without signing in.
        self.assertIn("admin@practice.invalid", self.get("/account?id=1")[1])
        # robots.txt points at the made-up secrets.
        self.assertIn("/backup", self.get("/robots.txt")[1])
        self.assertIn("practice-only-", self.get("/backup")[1])
        # The weak password works.
        form = urllib.parse.urlencode({"user": "alice", "password": "alice"}).encode()
        self.assertIn("Signed in as alice", self.get("/login", form)[1])

    def test_wrong_credentials_are_refused(self):
        form = urllib.parse.urlencode({"user": "alice", "password": "wrong"}).encode()
        self.assertEqual(self.get("/login", form)[0], 401)


if __name__ == "__main__":
    unittest.main()
