"""PentAGI's terminal adapter updates a flow (a reply, a stop) the way the pinned server routes it:
PUT /api/v1/flows/{id}. The server answers any other method there with a redirect, which made
replies fail and stops fail silently while the adapter sent PATCH. And every one of its agents asks
no longer reply than its model's budget."""
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site/harnesses"))
import pentagi_cli


class Server(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def answer(self):
        size = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(size) or b"null")
        if self.command == "PUT" and self.path == "/api/v1/flows/7":
            self.server.updates.append(body)
            raw = json.dumps({"status": "success", "data": {"id": 7, "status": "running"}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            return self.wfile.write(raw)
        # The pinned router's fallback for a method it does not route.
        self.send_response(301)
        self.send_header("Location", "/")
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_PUT = do_PATCH = answer


class FlowUpdates(unittest.TestCase):
    def setUp(self):
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Server)
        self.server.updates = []
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = "http://127.0.0.1:%d/api/v1" % self.server.server_address[1]
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()

    def test_a_reply_and_a_stop_reach_the_flow(self):
        self.assertEqual(pentagi_cli.update_flow(self.opener, 7, {"action": "input", "input": "go on"}, self.base)["status"], "running")
        pentagi_cli.update_flow(self.opener, "7", {"action": "stop"}, self.base)
        self.assertEqual(self.server.updates, [{"action": "input", "input": "go on"}, {"action": "stop"}])

    def test_the_server_refuses_patch(self):
        with self.assertRaises(urllib.error.HTTPError):
            pentagi_cli.call(self.opener, "/flows/7", {"action": "stop"}, "PATCH", self.base)


class ReplyBudget(unittest.TestCase):
    """PentAGI's custom provider asks 16,384 tokens of reply for every agent (custom.go at the pinned
    commit); the relay passes on 4,096 and the model's window may leave less (profiles.limits). The
    adapter gives each of its agents the reply budget its profile passes (--max-output), in the file
    PentAGI reads its provider's settings from (LLM_SERVER_CONFIG_PATH)."""

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)

    def started(self, argv):
        """What main() starts PentAGI's server with, its database and server faked: its environment
        and the provider settings that file holds."""
        (self.home / "pentagi-work").mkdir(exist_ok=True)  # The link to the workspace, already made.

        class Process:
            def poll(self):
                return None

            def terminate(self):
                pass

            def wait(self, timeout=None):
                return 0

        class Started(Exception):
            pass
        seen = {}

        def popen(command, **options):
            if command == ["/opt/solver/tool/bin/pentagi"]:
                seen.update(options["env"])
                raise Started()
            return Process()
        with patch.object(pentagi_cli.Path, "home", return_value=self.home), \
                patch.object(pentagi_cli.sys, "argv", ["pentagi_cli.py", *argv]), \
                patch.object(pentagi_cli.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)), \
                patch.object(pentagi_cli.subprocess, "Popen", side_effect=popen), self.assertRaises(Started):
            pentagi_cli.main()
        return seen, json.loads(Path(seen["LLM_SERVER_CONFIG_PATH"]).read_text(encoding="utf-8"))

    def test_every_agent_asks_the_models_reply_budget(self):
        env, config = self.started(["--model", "m", "--max-output", "2048"])
        self.assertEqual(config, {agent: {"max_tokens": 2048} for agent in pentagi_cli.AGENTS})
        # Every agent the pinned provider config has (pconfig.EmptyProviderConfigRaw).
        self.assertEqual(len(set(pentagi_cli.AGENTS)), 13)
        self.assertEqual(Path(env["LLM_SERVER_CONFIG_PATH"]).parent, self.home / "pentagi-local", "in the VM's home, not the workspace")
        self.assertEqual((env["LLM_SERVER_MODEL"], env["LLM_SERVER_URL"]), ("m", "http://127.0.0.1:8080/v1"))
        # Started without the option, as by an older profile: the longest reply the relay passes on.
        self.assertEqual(self.started(["--model", "m"])[1]["pentester"], {"max_tokens": 4096})

    def test_a_budget_beyond_the_relays_or_below_one_token_is_refused(self):
        for wrong in ("0", "4097", "-1", "many"):
            with self.subTest(wrong=wrong), self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                pentagi_cli.parse(["--model", "m", "--max-output", wrong])
        self.assertEqual(pentagi_cli.parse(["--model", "m", "--max-output", "1"]).max_output, 1)


if __name__ == "__main__":
    unittest.main()
