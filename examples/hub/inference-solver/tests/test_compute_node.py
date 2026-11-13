"""The contributor connector and the answers `yougori inference connect` passes it: the model
environments it shares (--models), the Sandbox VM limits (--sandbox) and the models it ran only
for the website (--release), stopped when it disconnects. A fake Yougori; nothing is shared,
started or paired.

Run: python -I -B examples/hub/inference-solver/tests/test_compute_node.py
"""
import contextlib
import hashlib
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SITE = Path(__file__).resolve().parents[1] / "site"
sys.path.insert(0, str(SITE))
import compute_node
from compute_adapter import ComputeError

SERVER = "https://argon.yougori.com"
MODELS = [
    {"id": "env-1", "name": "Qwen/Qwen2.5-0.5B-Instruct", "state": "ready", "shared": True, "place": "local"},
    {"id": "env-2", "name": "Other/Model", "state": "unavailable", "shared": False, "place": "local"},
]


class Contributing(Exception):
    """Where the connector would start contributing, once its answers are applied."""


class FakeAdapter:
    models = MODELS
    made = []

    def __init__(self, command, folder):
        self.shared = {"env-1", "env-old"}
        self.changes = []
        self.calls = []
        FakeAdapter.made.append(self)

    def inventory(self):
        return {"models": [dict(model) for model in self.models]}

    def share(self, environment, enabled=True):
        self.changes.append((environment, enabled))

    def call(self, method, **params):
        self.calls.append((method, params))
        return {}


class FakeGrid:
    capacity = None
    contributing = False

    def __init__(self, command, folder, capacity):
        FakeGrid.capacity = capacity
        if not FakeGrid.contributing:
            raise Contributing()
        self.stopped = 0

    def stop_all(self):
        self.stopped += 1

    def advertisement(self):
        return {}

    def inventory(self):
        return {}


class ConnectorTest(unittest.TestCase):
    def setUp(self):
        FakeAdapter.made.clear()
        FakeAdapter.models = MODELS
        FakeGrid.capacity, FakeGrid.contributing = None, False
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
        self.home = Path(home.name)
        for patcher in (
            patch.object(compute_node, "executable", return_value="yougori"),
            patch.object(compute_node, "Adapter", FakeAdapter),
            patch.object(compute_node, "GridAdapter", FakeGrid),
            patch.dict("os.environ", {"LOCALAPPDATA": home.name}),
            patch.object(compute_node.subprocess, "check_output", return_value="person"),
            patch.object(compute_node.subprocess, "run"),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def connect(self, *argv):
        """Runs the connector with these arguments; returns what it printed."""
        printed = io.StringIO()
        self.printed = printed
        with patch.object(sys, "argv", ["compute_node.py", *argv]), contextlib.redirect_stdout(printed):
            compute_node.main(SERVER)
        return printed.getvalue()

    def changes(self):
        return FakeAdapter.made[-1].changes

    def test_uses_the_answers_the_cli_passes(self):
        with self.assertRaises(Contributing):
            self.connect("--models", "env-2", "--sandbox", "4,8,2")
        self.assertEqual(set(self.changes()), {("env-1", False), ("env-old", False), ("env-2", True)})
        self.assertEqual(FakeGrid.capacity, {"cpu": 4, "memory_gb": 8, "slots": 2})
        self.assertIn("Only new restricted VMs are shared.", self.printed.getvalue())
        with self.assertRaises(Contributing):
            self.connect("--models", "", "--sandbox", "2,4,1")
        self.assertEqual(FakeGrid.capacity, {"cpu": 2, "memory_gb": 4, "slots": 1})

    def test_refuses_bad_answers_before_sharing_or_unsharing_anything(self):
        for argv, words in (
            (("--models", "", "--sandbox", "none"), "Nothing to share"),
            (("--models", "env-9", "--sandbox", "none"), "no longer on this computer"),
            (("--models", "env-1", "--sandbox", "4,8"), "such as 4,8,2"),
            (("--models", "env-1", "--sandbox", "0,8,2"), "out of range"),
            (("--models", "env-1", "--sandbox", "4,8,17"), "out of range"),
        ):
            with self.subTest(argv=argv), self.assertRaises(ComputeError) as refused:
                self.connect(*argv)
            self.assertIn(words, str(refused.exception))
            self.assertEqual(self.changes(), [])

    def test_runs_only_with_the_answers_of_yougori_inference_connect(self):
        for argv in ((), ("--models", "env-1"), ("--sandbox", "none")):
            with self.subTest(argv=argv), self.assertRaises(ComputeError) as refused:
                self.connect(*argv)
            self.assertEqual(str(refused.exception), "Connect this computer with: yougori inference connect " + SERVER)
        self.assertEqual(FakeAdapter.made, [])

    def test_a_website_without_codes_lets_the_computer_join_at_once(self):
        FakeGrid.contributing = True
        asked = []

        def post(link, path, payload, token=None, timeout=30):
            asked.append(path)
            if path == "/api/compute/pair/start":
                return {"code": "ABCD1234", "device": "device", "expires_in": 600, "connected": True}
            raise KeyboardInterrupt

        with patch.object(compute_node.Link, "post", post), \
                patch.object(compute_node, "receive", lambda link, token, deliver, stopped, connected=None: stopped.wait(5)), \
                self.assertRaises(KeyboardInterrupt):
            self.connect("--models", "env-1", "--sandbox", "none")
        printed = self.printed.getvalue()
        self.assertIn(SERVER + " lets computers join without a code: this computer joined.", printed)
        self.assertNotIn("enter this computer code", printed)
        self.assertNotIn("/api/compute/pair/poll", asked)
        folder = self.home / "InferenceSolver" / ("node-" + hashlib.sha256(SERVER.encode()).hexdigest()[:16])
        self.assertTrue((folder / "credential").is_file())

    def test_ctrl_c_stops_the_models_it_ran_for_the_website_and_no_others(self):
        # An approved computer: its credential is saved, so it starts serving at once.
        FakeGrid.contributing = True
        folder = self.home / "InferenceSolver" / ("node-" + hashlib.sha256(SERVER.encode()).hexdigest()[:16])
        folder.mkdir(parents=True)
        (folder / "credential").write_text("saved-token", encoding="utf-8")

        def interrupted(*_args, **_kwargs):
            raise KeyboardInterrupt

        with patch.object(compute_node.Link, "post", interrupted), \
                patch.object(compute_node, "receive", lambda link, token, deliver, stopped, connected=None: stopped.wait(5)), \
                self.assertRaises(KeyboardInterrupt):
            self.connect("--models", "env-1,env-2", "--sandbox", "none", "--release", "env-2,env-9")
        # Only a chosen model the CLI started for the website stops; the person's own one keeps running.
        self.assertEqual(FakeAdapter.made[-1].calls, [("stop_model", {"environmentId": "env-2"})])
        self.assertIn("Stopping the models this computer ran for " + SERVER, self.printed.getvalue())

    def test_says_when_each_model_can_answer(self):
        """The connector says the website lists each model while it can answer, then one line each
        time a shared model's state changes: a download at most once a minute, then ready."""
        FakeGrid.contributing = True
        folder = self.home / "InferenceSolver" / ("node-" + hashlib.sha256(SERVER.encode()).hexdigest()[:16])
        folder.mkdir(parents=True)
        (folder / "credential").write_text("saved-token", encoding="utf-8")
        downloading = {**MODELS[0], "state": "downloading", "progress": {"received": 3400000000, "total": 8000000000, "rate": 5000000}}
        FakeAdapter.models = [downloading, MODELS[1]]
        reported = []

        def post(link, path, payload, token=None, timeout=30):
            if payload.get("action") == "inventory":
                reported.append([model["state"] for model in payload["models"]])
                if len(reported) == 2:
                    FakeAdapter.models = MODELS  # It has downloaded and loaded.
                if len(reported) == 4:
                    raise KeyboardInterrupt
            return {}

        with patch.object(compute_node.Link, "post", post), patch.object(compute_node, "INVENTORY_SECONDS", 0), \
                patch.object(compute_node, "receive", lambda link, token, deliver, stopped, connected=None: stopped.wait(5)), \
                self.assertRaises(KeyboardInterrupt):
            self.connect("--models", "env-1", "--sandbox", "none")
        printed = self.printed.getvalue()
        self.assertEqual(reported, [["downloading", "unavailable"]] * 2 + [["ready", "unavailable"]] * 2)
        self.assertIn("Connected. " + SERVER + " lists each chosen model while it can answer. Keep this terminal running; Ctrl+C disconnects.", printed)
        self.assertNotIn("appear automatically", printed)
        # Once for two reports of the download; nothing for a model this computer does not share.
        self.assertEqual(printed.count("downloading"), 1)
        self.assertIn("Qwen/Qwen2.5-0.5B-Instruct: downloading 42% (3.4 of 8.0 GB)\n", printed)
        self.assertEqual(printed.count("Qwen/Qwen2.5-0.5B-Instruct is ready; " + SERVER + " lists it\n"), 1)
        self.assertNotIn("Other/Model", printed)

    def test_each_state_is_said_in_words(self):
        said, printed = {}, io.StringIO()
        models = [{"id": "env-1", "name": "test/one", "shared": True, "state": state, **extra} for state, extra in (
            ("starting", {}), ("downloading", {"progress": {"received": 340000000, "total": 800000000, "rate": 0}}),
            ("loading", {}), ("unavailable", {}))]
        with contextlib.redirect_stdout(printed):
            for model in models:
                compute_node.announce([model], SERVER, said)
            compute_node.announce(models[-1:], SERVER, said)  # No change: nothing more.
        self.assertEqual(printed.getvalue().splitlines(), ["test/one is starting", "test/one: downloading 42% (340 of 800 MB)",
                                                           "test/one is loading onto the GPU", "test/one could not load"])


if __name__ == "__main__":
    unittest.main()
