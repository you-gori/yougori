"""Failures in the offline gate must never become a green CI result."""
import importlib.util
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch


spec = importlib.util.spec_from_file_location("model_offline_gate", Path(__file__).with_name("test-model-offline.py"))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


class OfflineGateTests(unittest.TestCase):
    def test_environment_drops_inherited_credentials_sources_proxies_and_python_paths(self):
        parent = {"PATH": "tools", "SystemRoot": "Windows", "HF_TOKEN": "private",
                  "YOUGORI_GPU_SOURCE": "private", "OPENAI_API_KEY": "private",
                  "HTTPS_PROXY": "private", "PYTHONPATH": "private", "HOME": "private"}
        env = gate.test_environment(parent, Path("disposable"))
        self.assertNotIn("private", env.values())
        self.assertEqual(env["PATH"], "tools")
        self.assertEqual(env["SystemRoot"], "Windows")
        self.assertEqual(env["HF_HUB_OFFLINE"], "1")
        self.assertEqual(env["CUDA_VISIBLE_DEVICES"], "")
        self.assertEqual(env["HF_HOME"], str(Path("disposable/hf")))
        self.assertEqual(parent["HOME"], "private", "the caller's environment is unchanged")

    def test_empty_failed_skipped_and_expected_failure_results_fail_the_gate(self):
        class Case(unittest.TestCase):
            def passed(self): pass
            def failed(self): self.fail("fixture")
            def skipped(self): self.skipTest("fixture")
            @unittest.expectedFailure
            def expected(self): self.fail("fixture")
            @unittest.expectedFailure
            def unexpected(self): pass
        for method in (None, "passed", "failed", "skipped", "expected", "unexpected"):
            with self.subTest(method=method):
                suite = unittest.TestSuite([] if method is None else [Case(method)])
                result = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
                self.assertEqual(gate.result_passed(result), method == "passed")

    def test_missing_suite_fails_before_starting_any_child(self):
        with patch.object(gate, "SUITES", ("missing-offline-fixture.py",)), \
                patch.object(gate.subprocess, "run") as spawn, patch("sys.stderr", io.StringIO()):
            self.assertEqual(gate.run_all(), 1)
            spawn.assert_not_called()

    def test_child_failure_or_timeout_is_not_hidden_by_later_success(self):
        names = gate.SUITES[:2]
        for first in (SimpleNamespace(returncode=1), subprocess.TimeoutExpired("fixture", 120), OSError("fixture")):
            with self.subTest(first=type(first).__name__), tempfile.TemporaryDirectory() as scratch, \
                    patch.object(gate, "SUITES", names), \
                    patch.object(gate.subprocess, "run", side_effect=[first, SimpleNamespace(returncode=0)]) as spawn, \
                    patch("sys.stdout", io.StringIO()), patch("sys.stderr", io.StringIO()):
                self.assertEqual(gate.run_all(scratch), 1)
                self.assertEqual(spawn.call_count, 2)
                self.assertEqual(list(Path(scratch).iterdir()), [])

    def test_each_suite_gets_an_isolated_process_and_cache_then_cleanup(self):
        paths = []
        def execute(command, **kwargs):
            self.assertEqual(command[1:3], ["-I", "-B"])
            self.assertEqual(command[-2], "--suite")
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["timeout"], 120)
            self.assertNotIn("shell", kwargs)
            cache = Path(kwargs["env"]["HF_HOME"])
            cache.mkdir()
            (cache / "fixture").write_text("disposable", encoding="utf-8")
            self.assertNotIn(cache, paths)
            paths.append(cache)
            return SimpleNamespace(returncode=0)
        with tempfile.TemporaryDirectory() as scratch, patch.object(gate, "SUITES", gate.SUITES[:2]), \
                patch.object(gate.subprocess, "run", side_effect=execute), patch("sys.stdout", io.StringIO()):
            self.assertEqual(gate.run_all(scratch), 0)
            self.assertEqual(len(paths), 2)
            self.assertTrue(all(not path.exists() for path in paths))
            self.assertEqual(list(Path(scratch).iterdir()), [])


if __name__ == "__main__":
    unittest.main()
