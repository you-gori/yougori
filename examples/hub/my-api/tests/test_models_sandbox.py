"""Service lifecycle tests with disposable child processes; no engine or accounts."""
import importlib.util
import http.client
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.dont_write_bytecode = True
source = Path(__file__).resolve().parents[1] / "site" / "start-models.py"
spec = importlib.util.spec_from_file_location("start_models", source)
models = importlib.util.module_from_spec(spec)
spec.loader.exec_module(models)


def wait_until(predicate):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.05)
    raise AssertionError("Child did not reach the expected state")


class ModelsSandboxTests(unittest.TestCase):
    def test_real_bridge_processes_share_one_host_and_keep_authentication_and_modes(self):
        specs = models.services({**os.environ, "SELECTED_PROVIDERS": "codex,kilo", "BRIDGE_KEY": "fixture-only-secret"})
        ports = []
        for _, _, environment in specs:
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                ports.append(listener.getsockname()[1])
            environment.update(BRIDGE_PORT=str(ports[-1]), SELECTED_PROVIDERS="none", PYTHONDONTWRITEBYTECODE="1")
        stopped = threading.Event()
        runner = threading.Thread(target=models.supervise, args=(specs, stopped))
        runner.start()
        def get(port, path, authorized=False):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
            try:
                connection.request("GET", path, headers={"Authorization": "Bearer fixture-only-secret"} if authorized else {})
                response = connection.getresponse()
                return response.status, json.loads(response.read())
            finally:
                connection.close()
        def ready():
            try:
                return all(get(port, "/health")[0] == 200 for port in ports)
            except OSError:
                return False
        try:
            wait_until(ready)
            for port, provider in zip(ports, ["openai", "kilo"]):
                self.assertEqual(get(port, "/v1/models")[0], 401)
                status, catalogue = get(port, "/v1/models", True)
                self.assertEqual(status, 200)
                self.assertEqual(catalogue["data"], [])
                self.assertIn(provider, catalogue["status"])
        finally:
            stopped.set()
            runner.join(timeout=8)
        self.assertFalse(runner.is_alive())
        for port in ports:
            with socket.socket() as connection:
                self.assertNotEqual(connection.connect_ex(("127.0.0.1", port)), 0)

    @unittest.skipUnless(os.name == "posix", "Ollama's sandbox entrypoint runs on Linux")
    def test_ollama_shell_and_its_child_stop_together(self):
        with tempfile.TemporaryDirectory(prefix="models-ollama-") as folder:
            root = Path(folder)
            binary = root / ".local" / "bin" / "ollama"
            binary.parent.mkdir(parents=True)
            binary.write_text(f"#!{sys.executable}\nimport os, time\nfrom pathlib import Path\n"
                              "Path(os.environ['HOME'], 'ollama.pid').write_text(str(os.getpid()))\n"
                              "while True: time.sleep(.1)\n", encoding="utf-8")
            binary.chmod(0o700)
            specs = models.services({**os.environ, "HOME": folder, "SELECTED_PROVIDERS": "ollama"})
            stopped = threading.Event()
            runner = threading.Thread(target=models.supervise, args=(specs, stopped))
            runner.start()
            try:
                wait_until(lambda: (root / "ollama.pid").exists())
                pid = int((root / "ollama.pid").read_text())
            finally:
                stopped.set()
                runner.join(timeout=8)
            self.assertFalse(runner.is_alive())
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_selected_services_have_distinct_ports_and_do_not_mutate_parent_environment(self):
        environment = {"SELECTED_PROVIDERS": "codex,kilo,ollama", "BRIDGE_KEY": "fixture-only-secret"}
        services = models.services(environment)
        self.assertEqual([name for name, _, _ in services], ["paid", "free", "ollama"])
        self.assertEqual([env["BRIDGE_PORT"] for _, _, env in services[:2]], ["8080", "8081"])
        self.assertNotIn("BRIDGE_MODE", environment)
        for selection, names in (("claude", ["paid"]), ("gemini", ["paid"]), ("opencode", ["free"]),
                                 ("ollama", ["ollama"]), ("", [])):
            self.assertEqual([name for name, _, _ in models.services({"SELECTED_PROVIDERS": selection})], names)

    def test_crashed_service_restarts_without_restarting_its_neighbour_and_stop_reaps_both(self):
        with tempfile.TemporaryDirectory(prefix="models-supervisor-") as folder:
            root = Path(folder)
            child = root / "child.py"
            child.write_text("""import os, sys, time
from pathlib import Path
root, name = Path(sys.argv[1]), sys.argv[2]
with (root / (name + '.pids')).open('a') as file:
    file.write(str(os.getpid()) + '\\n')
if name == 'crash' and not (root / 'crashed').exists():
    (root / 'crashed').touch()
    sys.exit(7)
while True: time.sleep(.1)
""", encoding="utf-8")
            specs = [(name, [sys.executable, str(child), folder, name], dict(os.environ)) for name in ("crash", "stable")]
            stopped = threading.Event()
            started = []
            original = models.subprocess.Popen
            def capture(*args, **kwargs):
                process = original(*args, **kwargs)
                started.append(process)
                return process
            from unittest.mock import patch
            with patch.object(models.subprocess, "Popen", side_effect=capture):
                runner = threading.Thread(target=models.supervise, args=(specs, stopped, .1))
                runner.start()
                try:
                    def pids(name):
                        file = root / (name + '.pids')
                        return file.read_text().splitlines() if file.exists() else []
                    wait_until(lambda: len(pids("crash")) == 2 and len(pids("stable")) == 1)
                    self.assertEqual(len(pids("stable")), 1)
                finally:
                    stopped.set()
                    runner.join(timeout=8)
                self.assertFalse(runner.is_alive())
                self.assertEqual(len(started), 3)
                self.assertTrue(all(process.poll() is not None for process in started))


if __name__ == "__main__":
    unittest.main()
