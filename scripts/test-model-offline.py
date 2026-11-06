"""Run the explicit, stdlib-only model regression gate without installed runtimes."""
import argparse
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
# Deliberately not a glob: runtime/dependency/GPU suites require separate review.
SUITES = (
    "scripts/test-model-offline.test.py",
    "scripts/test-model-checkpoints.test.py",
    "scripts/model-server.test.py",
    "src-tauri/src/model_server_test.py",
    "src-tauri/src/model_verification_test.py",
    "src-tauri/src/model_timing_test.py",
    "src-tauri/src/model_journal_test.py",
    "src-tauri/src/model_registry_test.py",
    "src-tauri/src/gpu_optimizer_test.py",
    "src-tauri/src/gpu_optimizer_protocol_test.py",
    "src-tauri/src/gpu_optimizer_integration_test.py",
    "scripts/model-chat-client.test.py",
)
SUITE_TIMEOUT_SECONDS = 120


def test_environment(parent, scratch):
    # Start from an allowlist, not a copy of developer/provider credentials or
    # YOUGORI_* source injection/configuration. -I also excludes user site/PYTHONPATH.
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE"}
    env = {key: value for key, value in parent.items() if key.upper() in keep}
    root = str(scratch)
    env.update(HOME=root, USERPROFILE=root, APPDATA=root, LOCALAPPDATA=root,
               TMP=root, TEMP=root, TMPDIR=root, XDG_CACHE_HOME=root,
               HF_HOME=str(scratch / "hf"), HF_HUB_OFFLINE="1",
               TRANSFORMERS_OFFLINE="1", HF_HUB_DISABLE_TELEMETRY="1",
               DO_NOT_TRACK="1", CUDA_VISIBLE_DEVICES="", PYTHONDONTWRITEBYTECODE="1",
               NO_PROXY="*", no_proxy="*")
    return env


def result_passed(result):
    # unittest considers skips and expected failures successful. This gate does not.
    return (result.testsRun > 0 and result.wasSuccessful()
            and not result.skipped and not result.expectedFailures)


def run_suite(relative):
    path = ROOT / relative
    # Existing test modules import sibling fixtures, including model_server.
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("offline_model_suite", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result_passed(result):
        print("Offline gate failed: tests must run without failures, skips or expected failures.",
              file=sys.stderr, flush=True)
        return 1
    return 0


def run_all(scratch_root=None):
    missing = [name for name in SUITES if not (ROOT / name).is_file()]
    if missing:
        print("Missing required test suites: " + ", ".join(missing), file=sys.stderr)
        return 1
    failed = []
    for name in SUITES:
        print(f"\n=== Offline model suite: {name} ===", flush=True)
        with tempfile.TemporaryDirectory(prefix="yougori-offline-", dir=scratch_root) as folder:
            environment = test_environment(os.environ, Path(folder))
            try:
                result = subprocess.run(
                    [sys.executable, "-I", "-B", str(Path(__file__).resolve()), "--suite", name],
                    cwd=ROOT, env=environment, stdin=subprocess.DEVNULL,
                    timeout=SUITE_TIMEOUT_SECONDS, check=False,
                )
                if result.returncode != 0:
                    failed.append(name)
            except subprocess.TimeoutExpired:
                print(f"FAILED: suite exceeded {SUITE_TIMEOUT_SECONDS}s: {name}",
                      file=sys.stderr, flush=True)
                failed.append(name)
            except OSError:
                print(f"FAILED: could not start the test interpreter: {name}",
                      file=sys.stderr, flush=True)
                failed.append(name)
    print(f"\nOffline model gate: {len(SUITES) - len(failed)}/{len(SUITES)} suites passed.", flush=True)
    if failed:
        print("Failed suites: " + ", ".join(failed), file=sys.stderr)
    return int(bool(failed))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="List suites without running tests")
    parser.add_argument("--scratch-root", type=Path, help="Existing parent for disposable test directories")
    parser.add_argument("--suite", choices=SUITES, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.list:
        print("\n".join(SUITES))
        return 0
    if args.suite:
        return run_suite(args.suite)
    if args.scratch_root is not None and not args.scratch_root.is_dir():
        parser.error("--scratch-root must be an existing directory")
    return run_all(args.scratch_root)


if __name__ == "__main__":
    raise SystemExit(main())
