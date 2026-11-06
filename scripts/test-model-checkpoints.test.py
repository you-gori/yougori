"""Stdlib regressions for the separate dependency-requiring CPU checkpoint job."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

spec = importlib.util.spec_from_file_location("checkpoint_job", Path(__file__).with_name("test-model-checkpoints.py"))
job = importlib.util.module_from_spec(spec)
spec.loader.exec_module(job)


def tally(**changes):
    return {"tests": 1, "failures": 0, "errors": 0, "skipped": 0,
            "expectedFailures": 0, "unexpectedSuccesses": 0, **changes}


def ready():
    return {"status": "ready", "python": [3, 12, 0], "versions": job.pins()}


class CheckpointJobTests(unittest.TestCase):
    def test_pins_are_exact_and_runner_drift_requires_an_explicit_update(self):
        values = job.pins()
        self.assertEqual(values["torch"], "2.8.0+cpu")
        with tempfile.TemporaryDirectory() as folder:
            server = Path(folder, "server.py")
            server.write_text('MODEL_DEPENDENCIES={"transformers":"different"}', encoding="utf-8")
            with patch.object(job, "SERVER", server), self.assertRaises(ValueError):
                job.pins()

    def test_child_environment_excludes_secrets_and_forces_cpu_offline_caches(self):
        parent = {"PATH": "tools", "SystemRoot": "Windows", "HF_TOKEN": "secret",
                  "OPENAI_API_KEY": "secret", "HTTPS_PROXY": "secret", "PYTHONPATH": "secret",
                  "YOUGORI_MEASUREMENT_SESSION": "secret", "HOME": "secret"}
        env = job.environment(parent, Path("scratch"))
        self.assertNotIn("secret", env.values())
        self.assertEqual(env["SystemRoot"], "Windows")
        self.assertEqual(env["CUDA_VISIBLE_DEVICES"], "")
        self.assertEqual(env["HF_HUB_OFFLINE"], "1")
        self.assertEqual(env["OMP_NUM_THREADS"], "1")
        self.assertEqual(parent["HOME"], "secret")

    def test_empty_skips_expected_failures_and_nonzero_failures_never_pass(self):
        self.assertTrue(job.successful_counts(tally()))
        for field in ("failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"):
            self.assertFalse(job.successful_counts(tally(**{field: 1})))
        for value in (tally(tests=0), tally(tests=True), tally(tests=-1), {**tally(), "prompt": "secret"}):
            self.assertFalse(job.successful_counts(value))

    def test_preflight_distinguishes_missing_wrong_and_exact_cpu_dependencies(self):
        versions = job.pins()
        with patch.object(job.sys, "version_info", (3, 12, 0)):
            with patch.object(job.importlib.metadata, "version", side_effect=versions.__getitem__):
                self.assertEqual(job.preflight()["status"], "ready")
            with patch.object(job.importlib.metadata, "version", side_effect=job.importlib.metadata.PackageNotFoundError):
                result = job.preflight()
                self.assertEqual(result["status"], "dependency_unavailable")
                self.assertTrue(all(v is None for v in result["versions"].values()))
            versions["torch"] = "2.8.0"
            with patch.object(job.importlib.metadata, "version", side_effect=versions.__getitem__):
                self.assertEqual(job.preflight()["status"], "dependency_mismatch")
        with patch.object(job.sys, "version_info", (3, 11, 0)), \
                patch.object(job.importlib.metadata, "version", side_effect=versions.__getitem__):
            self.assertEqual(job.preflight()["status"], "python_mismatch")

    def test_worker_rejects_oversized_unknown_and_false_green_results(self):
        with tempfile.TemporaryDirectory() as folder:
            scratch = Path(folder)
            payloads = [{"status": "passed", "counts": tally(skipped=1)},
                        {"status": "failed", "counts": {**tally(), "secret": "private"}},
                        {"status": "passed", "counts": tally(), "error": "private"},
                        "x" * (job.MAX_RESULT_BYTES + 1)]
            for payload in payloads:
                def write_result(*args):
                    (scratch / "result.json").write_text(json.dumps(payload), encoding="utf-8")
                    return "exited"
                with patch.object(job, "process", side_effect=write_result):
                    self.assertEqual(job.worker(Path(sys.executable), job.SUITES[0], scratch, 1),
                                     {"status": "invalid_result"})

    def test_worker_rechecks_ready_preflight_payload_instead_of_trusting_status(self):
        with tempfile.TemporaryDirectory() as folder:
            scratch = Path(folder)
            value = ready()
            value["versions"]["torch"] = "2.8.0+cuda"
            def execute(*args):
                (scratch / "result.json").write_text(json.dumps(value), encoding="utf-8")
                return "exited"
            with patch.object(job, "process", side_effect=execute):
                self.assertEqual(job.worker(Path(sys.executable), "preflight", scratch, 1)["status"], "invalid_result")

    def test_missing_dependencies_stop_before_running_either_numeric_suite_and_clean_scratch(self):
        with tempfile.TemporaryDirectory() as folder, \
                patch.object(job, "worker", return_value={"status": "dependency_unavailable"}) as worker:
            report = job.run_job(Path(sys.executable), Path(folder), 1)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(report["suites"], [])
            self.assertEqual(worker.call_count, 1)
            self.assertEqual(list(Path(folder).iterdir()), [])
            self.assertNotIn(str(Path(sys.executable)), json.dumps(report))

    def test_failing_first_suite_does_not_hide_second_result_or_leave_cache(self):
        results = [ready(), {"status": "failed", "counts": tally(errors=1)},
                   {"status": "passed", "counts": tally()}]
        with tempfile.TemporaryDirectory() as folder, patch.object(job, "worker", side_effect=results) as worker:
            report = job.run_job(Path(sys.executable), Path(folder), 5)
            self.assertEqual(report["status"], "failed")
            self.assertEqual(len(report["suites"]), 2)
            self.assertEqual(worker.call_count, 3)
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_source_changes_cannot_produce_a_green_report(self):
        results = [ready(), {"status": "passed", "counts": tally()}, {"status": "passed", "counts": tally()}]
        with tempfile.TemporaryDirectory() as folder, patch.object(job, "worker", side_effect=results), \
                patch.object(job, "source_hashes", side_effect=[{"source": "a"}, {"source": "b"}]):
            self.assertEqual(job.run_job(Path(sys.executable), Path(folder), 5)["status"], "source_changed")

    def test_atomic_report_failure_preserves_previous_report_and_removes_temporary(self):
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder, "report.json")
            destination.write_text("previous", encoding="utf-8")
            with patch.object(job.os, "replace", side_effect=OSError("private path")), self.assertRaises(OSError):
                job.write_json(destination, {"status": "failed"})
            self.assertEqual(destination.read_text(encoding="utf-8"), "previous")
            self.assertEqual(list(Path(folder).iterdir()), [destination])

    def test_real_owned_child_timeout_is_reaped(self):
        with tempfile.TemporaryDirectory() as folder:
            outcome = job.process([sys.executable, "-I", "-B", "-c", "import time; time.sleep(30)"],
                                  job.environment(os.environ, Path(folder)), 0.1)
            self.assertEqual(outcome, "timeout")

    def test_interrupted_wait_terminates_owned_process_before_propagating(self):
        child = SimpleNamespace(wait=lambda **kwargs: (_ for _ in ()).throw(KeyboardInterrupt()))
        with patch.object(job.subprocess, "Popen", return_value=child), patch.object(job, "terminate") as stop:
            with self.assertRaises(KeyboardInterrupt):
                job.process(["fixture"], {}, 1)
            stop.assert_called_once_with(child)

    def test_real_preflight_child_writes_only_allowlisted_metadata(self):
        with tempfile.TemporaryDirectory() as folder:
            result = job.worker(Path(sys.executable), "preflight", Path(folder), 30)
            self.assertIn(result["status"], ("ready", "python_mismatch", "dependency_unavailable", "dependency_mismatch"))
            self.assertEqual(set(result), {"status", "python", "versions"})


if __name__ == "__main__":
    unittest.main()
