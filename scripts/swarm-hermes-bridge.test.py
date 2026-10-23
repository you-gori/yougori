"""Supervisor lifecycle regressions without a model or Hermes installation."""
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src-tauri/src/swarm"))
from hermes_bridge import Handler, Session


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.session = Session()
        self.handler = Handler.__new__(Handler)
        self.handler.server = SimpleNamespace(args=SimpleNamespace(root="fixture", config="fixture.json"))
        self.handler.send = mock.Mock()
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)

    def test_failed_spawn_cleans_the_turn_home(self):
        with mock.patch("hermes_bridge.tempfile.TemporaryDirectory", return_value=self.home), \
             mock.patch("hermes_bridge.subprocess.Popen", side_effect=OSError("fixture spawn failure")):
            with self.assertRaises(OSError):
                self.handler.turn("ses_fixture", self.session, {"parts": []})
        self.assertFalse(Path(self.home.name).exists())
        self.assertTrue(self.session.aborted)

    def test_child_exiting_before_prompt_still_reaps_and_cleans(self):
        process = mock.Mock()
        process.stdin.write.side_effect = BrokenPipeError("fixture child exit")
        process.poll.return_value = 1
        with mock.patch("hermes_bridge.tempfile.TemporaryDirectory", return_value=self.home), \
             mock.patch("hermes_bridge.subprocess.Popen", return_value=process):
            with self.assertRaises(BrokenPipeError):
                self.handler.turn("ses_fixture", self.session, {"parts": []})
        process.wait.assert_called()
        self.assertTrue(self.session.aborted)
        self.assertFalse(Path(self.home.name).exists())

    @unittest.skipUnless(os.name == "posix", "POSIX process group exit race")
    def test_abort_tolerates_process_exiting_between_poll_and_kill(self):
        process = self.session.process = mock.Mock()
        process.poll.return_value = None
        with mock.patch("hermes_bridge.os.killpg", side_effect=ProcessLookupError):
            self.session.abort()
        process.wait.assert_called_once_with(timeout=5)


if __name__ == "__main__":
    unittest.main()
