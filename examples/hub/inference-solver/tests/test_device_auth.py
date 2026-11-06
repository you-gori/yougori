"""Real HTTP/browser-code contracts and a CLI downloaded from the actual bundle."""
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import re
import secrets
import subprocess
import sys
import threading
import unittest
import zipfile
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow
import harness_download


class Devices(unittest.TestCase):
    def setUp(self):
        self.flow = Flow()
        self.flow.setUp()
        self.addCleanup(self.flow.tearDown)

    def start(self, harness="pi"):
        key = "is_" + secrets.token_urlsafe(32)
        status, state, _ = self.flow.call("/api/device/start", {"harness": harness, "credential_hash": hashlib.sha256(key.encode()).hexdigest()})
        self.assertEqual(status, 201, state)
        self.assertIsNone(self.flow.service.store.key(key))
        return key, state

    def poll(self, state):
        return self.flow.call("/api/device/poll", {"device_code": state["device_code"]})[1]["status"]

    def test_approval_is_bound_to_member_key_and_is_single_use(self):
        member = self.flow.member()
        key, state = self.start()
        payload = {"user_code": state["user_code"], "approve": True, "admin": True}
        self.assertEqual(self.flow.call("/api/device/decide", payload)[0], 403)
        self.assertEqual(self.flow.call("/api/device/decide", payload, member, headers={"X-CSRF-Token": "bad"})[0], 403)
        self.assertEqual(self.flow.call("/api/device/decide", payload, member, headers={"Origin": "https://other.invalid"})[0], 403)
        self.assertEqual(self.flow.call("/api/device/inspect", payload, member)[1]["name"], "Pi")
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda _: self.flow.call("/api/device/decide", payload, member), range(2)))
        self.assertEqual(sorted(result[0] for result in results), [200, 400])
        self.assertEqual(self.poll(state), "approved")
        self.assertEqual(self.poll(state), "slow_down")
        self.assertEqual(self.flow.call("/v1/models", key=key)[0], 200)
        self.assertEqual(self.flow.call("/api/admin/overview", key=key)[0], 401)
        keys = self.flow.call("/api/keys", session=member)[1]["keys"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(keys[0]["label"], "Harness: pi")
        self.assertEqual(self.flow.call("/api/keys", session=self.flow.admin)[1]["keys"], [])
        self.flow.call("/api/keys/revoke", {"id": keys[0]["id"]}, member)
        self.assertEqual(self.flow.call("/v1/models", key=key)[0], 401)
        with self.flow.service.store.db() as db:
            raw = "\n".join(db.iterdump())
        for secret in (key, state["device_code"], state["user_code"], state["user_code"].replace("-", "")):
            self.assertNotIn(secret, raw)

    def test_denial_expiry_guessing_and_private_registration(self):
        key, state = self.start()
        self.assertEqual(self.poll(state), "pending")
        self.assertEqual(self.flow.call("/api/device/decide", {"user_code": state["user_code"], "approve": False}, self.flow.admin)[0], 200)
        self.assertIsNone(self.flow.service.store.key(key))
        with self.flow.service.store.db() as db:
            db.execute("UPDATE device_authorizations SET next_poll=0")
        self.assertEqual(self.poll(state), "denied")
        key, state = self.start()
        with self.flow.service.store.db() as db:
            db.execute("UPDATE device_authorizations SET expires=0")
        self.assertEqual(self.poll(state), "expired")
        self.assertEqual(self.flow.call("/api/device/decide", {"user_code": state["user_code"], "approve": True}, self.flow.admin)[0], 400)
        self.assertEqual(self.flow.call("/api/device/poll", {"device_code": "bad"})[1]["status"], "expired")
        specs = harness_download.catalog()
        specs['pentagi'] = {**specs['pentagi'], 'blocked': 'Awaiting validation'}
        with patch.object(harness_download, 'catalog', return_value=specs):
            self.assertEqual(self.flow.call("/api/device/start", {"harness": "pentagi", "credential_hash": "a" * 64})[0], 400)
        self.flow.service.account_mode = "private"
        self.assertEqual(self.flow.call("/api/signup", {"email": "no@example.invalid", "password": "disposable-test-password"})[0], 403)
        for _ in range(10):
            self.assertEqual(self.flow.call("/api/device/inspect", {"user_code": "AAAA-AAAA"}, self.flow.admin)[0], 400)
        self.assertEqual(self.flow.call("/api/device/inspect", {"user_code": "AAAA-AAAA"}, self.flow.admin)[0], 429)

    def test_existing_credentials_cannot_be_rebound(self):
        key, state = self.start()
        payload = {"harness": "pi", "credential_hash": hashlib.sha256(key.encode()).hexdigest()}
        self.assertEqual(self.flow.call("/api/device/start", payload)[0], 400)
        self.assertEqual(self.flow.call("/api/device/decide", {"user_code": state["user_code"], "approve": True}, self.flow.admin)[0], 200)
        with self.flow.service.store.db() as db:
            db.execute("DELETE FROM device_authorizations")
        self.assertEqual(self.flow.call("/api/device/start", payload)[0], 400)

    def test_downloaded_cli_connects_and_reuses_its_credential(self):
        folder = Path(self.flow.temp.name) / "download"
        with zipfile.ZipFile(io.BytesIO(harness_download.bundle("pi", self.flow.url))) as archive:
            archive.extractall(folder)
        home = Path(self.flow.temp.name) / "client-profile"
        env = {**os.environ, "LOCALAPPDATA": str(home)}
        command = [sys.executable, "-I", "-B", str(folder / "inference-solver/cli_entry.py"), "solver-pi", "login", "--no-browser"]
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, text=True, env=env)
        lines, output = queue.Queue(), []
        def read():
            for line in process.stdout:
                output.append(line)
                lines.put(line)
            lines.put(None)
        threading.Thread(target=read, daemon=True).start()
        try:
            code = None
            while code is None:
                line = lines.get(timeout=20)
                self.assertIsNotNone(line, "CLI exited before showing a code: " + "".join(output))
                match = re.search(r"Enter code: ([A-Z2-9]{4}-[A-Z2-9]{4})", line)
                if match:
                    code = match[1]
            self.assertEqual(self.flow.call("/api/device/decide", {"user_code": code, "approve": True}, self.flow.admin)[0], 200)
            self.assertEqual(process.wait(timeout=20), 0, "".join(output))
            key_files = list(home.rglob("api-key"))
            self.assertEqual(len(key_files), 1)
            key = key_files[0].read_text().strip()
            self.assertNotIn(key, "".join(output))
            self.assertIn("Connected. Continuing", "".join(output))
            again = subprocess.run(command[:-2] + ["models"], capture_output=True, text=True, env=env, timeout=20)
            self.assertEqual(again.returncode, 0, again.stderr)
            self.assertNotIn("Enter code", again.stdout)
            self.assertEqual(len(self.flow.call("/api/keys", session=self.flow.admin)[1]["keys"]), 1)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
