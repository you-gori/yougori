"""The contributor connector's questions and answers: what the Yougori CLI passes (--list,
--models, --sandbox) and the typed questions of older or scripted runs. A fake Yougori; nothing
is shared, started or paired.

Run: python -I -B examples/hub/inference-solver/tests/test_compute_node.py
"""
import contextlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SITE = Path(__file__).resolve().parents[1] / "site"
sys.path.insert(0, str(SITE))
import compute_node
from compute_adapter import ComputeError

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
        FakeAdapter.made.append(self)

    def inventory(self):
        return {"models": [dict(model) for model in self.models]}

    def share(self, environment, enabled=True):
        self.changes.append((environment, enabled))


class FakeGrid:
    capacity = None

    def __init__(self, command, folder, capacity):
        FakeGrid.capacity = capacity
        raise Contributing()


class ConnectorTest(unittest.TestCase):
    def setUp(self):
        FakeAdapter.made.clear()
        FakeAdapter.models = MODELS
        FakeGrid.capacity = None
        home = tempfile.TemporaryDirectory()
        self.addCleanup(home.cleanup)
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

    def connect(self, *argv, typed=()):
        """Runs the connector with these arguments and typed answers; returns what it printed."""
        printed, answers = io.StringIO(), iter(typed)

        def answer(prompt=""):
            printed.write(prompt + "\n")
            return next(answers)

        self.printed = printed
        with patch.object(sys, "argv", ["compute_node.py", *argv]), patch("builtins.input", answer), contextlib.redirect_stdout(printed):
            compute_node.main("https://argon.yougori.com")
        return printed.getvalue()

    def changes(self):
        return FakeAdapter.made[-1].changes

    def test_lists_the_models_for_the_cli_and_changes_nothing(self):
        listed = json.loads(self.connect("--list"))
        self.assertEqual(listed, {"models": [
            {"id": "env-1", "name": "Qwen/Qwen2.5-0.5B-Instruct", "ready": True, "hint": "running", "shared": True},
            {"id": "env-2", "name": "Other/Model", "ready": False, "hint": "stopped; it starts if you choose it", "shared": False}]})
        self.assertEqual(self.changes(), [])

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

    def test_typed_questions_list_the_models_in_words(self):
        with self.assertRaises(Contributing):
            printed = self.connect(typed=["2", "n"])
        printed = self.printed.getvalue()
        self.assertIn("Which models may https://argon.yougori.com use?", printed)
        self.assertIn("  1. Qwen/Qwen2.5-0.5B-Instruct (running)", printed)
        self.assertIn("  2. Other/Model (stopped; it starts if you choose it)", printed)
        self.assertIn("or press Enter for none", printed)
        self.assertIn(("env-2", True), self.changes())
        self.assertEqual(FakeGrid.capacity, {})
        with self.assertRaises(ComputeError):
            self.connect(typed=["3", "n"])

    def test_a_computer_without_models_says_so_and_can_lend_sandbox_vms(self):
        FakeAdapter.models = []
        with self.assertRaises(Contributing):
            self.connect(typed=["y", "2", "4", "1"])
        printed = self.printed.getvalue()
        self.assertIn("This computer has no models in Yougori yet", printed)
        self.assertIn("yougori model run", printed)
        self.assertNotIn("Which models", printed)
        self.assertEqual(FakeGrid.capacity, {"cpu": 2, "memory_gb": 4, "slots": 1})
        with self.assertRaises(ComputeError) as refused:
            self.connect(typed=["n"])
        self.assertIn("Nothing to share", str(refused.exception))

    def test_a_rented_model_does_not_start_when_chosen(self):
        self.assertEqual(compute_node.model_state({"state": "unavailable", "place": "neocloud"}), "not running")


if __name__ == "__main__":
    unittest.main()
