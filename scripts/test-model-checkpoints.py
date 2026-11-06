"""Separate pinned CPU checkpoint gate. Never installs dependencies or downloads models."""
import argparse
import ast
import hashlib
import importlib.metadata
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PIN_FILE = ROOT / "scripts/model-checkpoints-requirements.txt"
SERVER = ROOT / "src-tauri/src/model_server.py"
SUITES = ("scripts/model-checkpoint.test.py", "scripts/model-decisions.test.py")
SOURCES = (*SUITES, "src-tauri/src/model_server.py",
           "src-tauri/src/model_runner/engine_backends.py",
           "src-tauri/src/model_runner/gpu_optimizer.py",
           "src-tauri/src/model_runner/adapters/clef/joint_schema_model.py",
           "scripts/model-checkpoints-requirements.txt", "scripts/test-model-checkpoints.py")
MAX_RESULT_BYTES = 32 * 1024
MAX_REPORT_BYTES = 64 * 1024
PREFLIGHT_TIMEOUT = 30


def pins():
    values = {}
    for line in PIN_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"([a-z][a-z0-9-]*)==([0-9][a-zA-Z0-9.+-]{0,63})", line)
        if match is None or match[1] in values:
            raise ValueError("Invalid checkpoint dependency pins")
        values[match[1]] = match[2]
    if set(values) != {"torch", "transformers", "accelerate", "huggingface-hub", "safetensors"}:
        raise ValueError("Invalid checkpoint dependency set")
    tree = ast.parse(SERVER.read_text(encoding="utf-8"))
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == "MODEL_DEPENDENCIES"
                           for target in node.targets)]
    if len(assignments) != 1:
        raise ValueError("Cannot verify runner dependency pins")
    runtime = ast.literal_eval(assignments[0].value)
    if runtime != {name: values[name] for name in ("transformers", "accelerate", "huggingface-hub")}:
        raise ValueError("Checkpoint dependency pins differ from the runner")
    return values


def environment(parent, scratch):
    keep = {"PATH", "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "SYSTEMDRIVE"}
    env = {key: value for key, value in parent.items() if key.upper() in keep}
    root = str(scratch)
    env.update(HOME=root, USERPROFILE=root, APPDATA=root, LOCALAPPDATA=root,
               TMP=root, TEMP=root, TMPDIR=root, XDG_CACHE_HOME=root,
               HF_HOME=str(scratch / "hf"), HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1",
               HF_HUB_DISABLE_TELEMETRY="1", DO_NOT_TRACK="1", CUDA_VISIBLE_DEVICES="",
               PYTHONDONTWRITEBYTECODE="1", TOKENIZERS_PARALLELISM="false",
               OMP_NUM_THREADS="1", MKL_NUM_THREADS="1", NO_PROXY="*", no_proxy="*")
    return env


def checked_version(value):
    return value if isinstance(value, str) and re.fullmatch(r"[a-zA-Z0-9.+-]{1,64}", value) else None


def preflight():
    expected = pins()
    versions = {}
    for name in expected:
        try:
            versions[name] = checked_version(importlib.metadata.version(name))
        except importlib.metadata.PackageNotFoundError:
            versions[name] = None
    status = "ready"
    if sys.version_info[:2] != (3, 12):
        status = "python_mismatch"
    elif any(version is None for version in versions.values()):
        status = "dependency_unavailable"
    elif versions != expected:
        status = "dependency_mismatch"
    return {"status": status, "python": list(sys.version_info[:3]), "versions": versions}


def counts(result):
    return {"tests": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
            "expectedFailures": len(result.expectedFailures),
            "unexpectedSuccesses": len(result.unexpectedSuccesses)}


def successful_counts(value):
    fields = {"tests", "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"}
    return (valid_counts(value) and value["tests"] > 0
            and all(value[key] == 0 for key in fields - {"tests"}))


def valid_counts(value):
    fields = {"tests", "failures", "errors", "skipped", "expectedFailures", "unexpectedSuccesses"}
    return (isinstance(value, dict) and set(value) == fields
            and all(type(number) is int and 0 <= number <= 100_000 for number in value.values()))


def run_suite(relative):
    if relative not in SUITES:
        raise ValueError("Unknown checkpoint suite")
    path = ROOT / relative
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location("checkpoint_job_suite", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    with open(os.devnull, "w", encoding="utf-8") as output:
        result = unittest.TextTestRunner(stream=output, verbosity=0).run(suite)
    summary = counts(result)
    return {"status": "passed" if successful_counts(summary) else "failed", "counts": summary}


def write_json(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("Checkpoint report exceeds its limit")
    path = Path(path)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".checkpoint-result-", delete=False) as file:
            temporary = Path(file.name)
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def terminate(child):
    if os.name == "nt":
        try:
            subprocess.run(["taskkill.exe", "/PID", str(child.pid), "/T", "/F"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
    else:
        try:
            os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    child.kill()
    child.wait()


def process(command, env, timeout):
    options = {"cwd": ROOT, "env": env, "stdin": subprocess.DEVNULL,
               "stdout": subprocess.DEVNULL, "stderr": subprocess.DEVNULL}
    if os.name == "nt":
        options["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    else:
        options["start_new_session"] = True
    try:
        child = subprocess.Popen(command, **options)
    except OSError:
        return "launch_error"
    try:
        return "exited" if child.wait(timeout=timeout) == 0 else "child_failed"
    except subprocess.TimeoutExpired:
        terminate(child)
        return "timeout"
    except BaseException:
        terminate(child)
        raise


def worker(python, action, scratch, timeout):
    report = scratch / "result.json"
    command = [str(python), "-I", "-B", str(Path(__file__).resolve()),
               "--worker", action, "--worker-result", str(report)]
    outcome = process(command, environment(os.environ, scratch), timeout)
    if outcome != "exited":
        return {"status": outcome}
    try:
        with report.open("rb") as file:
            data = file.read(MAX_RESULT_BYTES + 1)
        if len(data) > MAX_RESULT_BYTES:
            raise ValueError("Result limit")
        value = json.loads(data)
        if not isinstance(value, dict):
            raise ValueError("Result shape")
        if action == "preflight":
            expected = pins()
            if (set(value) != {"status", "python", "versions"}
                    or value["status"] not in {"ready", "python_mismatch", "dependency_unavailable", "dependency_mismatch"}
                    or not isinstance(value["python"], list) or len(value["python"]) != 3
                    or any(type(number) is not int or not 0 <= number <= 100 for number in value["python"])
                    or not isinstance(value["versions"], dict) or set(value["versions"]) != set(expected)
                    or any(version is not None and checked_version(version) is None for version in value["versions"].values())
                    or value["status"] == "ready" and (value["versions"] != expected or value["python"][:2] != [3, 12])):
                raise ValueError("Invalid preflight result")
        elif (set(value) != {"status", "counts"} or not valid_counts(value["counts"])
              or value["status"] != ("passed" if successful_counts(value["counts"]) else "failed")):
            raise ValueError("Invalid suite result")
        return value
    except (OSError, ValueError, TypeError, RecursionError):
        return {"status": "invalid_result"}


def source_hashes():
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in SOURCES}


def run_job(python, scratch_root, timeout):
    before = source_hashes()
    report = {"version": 1, "job": "cpu-checkpoints", "status": "failed",
              "expectedVersions": pins(), "sourceHashes": before, "preflight": None, "suites": []}
    with tempfile.TemporaryDirectory(prefix="yougori-checkpoint-", dir=scratch_root) as folder:
        root = Path(folder)
        check = root / "preflight"
        check.mkdir()
        report["preflight"] = worker(python, "preflight", check, PREFLIGHT_TIMEOUT)
        if report["preflight"]["status"] == "ready":
            for index, suite in enumerate(SUITES):
                scratch = root / str(index)
                scratch.mkdir()
                started = time.monotonic_ns()
                result = worker(python, suite, scratch, timeout)
                report["suites"].append({"suite": suite, "result": result,
                                         "elapsedMs": (time.monotonic_ns() - started) // 1_000_000})
            if all(item["result"]["status"] == "passed" for item in report["suites"]):
                report["status"] = "passed"
    if source_hashes() != before:
        report["status"] = "source_changed"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, default=Path(sys.executable), help="Python 3.12 interpreter in a prepared CPU environment")
    parser.add_argument("--scratch-root", type=Path, default=Path("D:/YougoriBuildCache/scratch") if Path("D:/YougoriBuildCache/scratch").is_dir() else None)
    parser.add_argument("--timeout", type=int, default=300, help="Seconds per suite (1–1800)")
    parser.add_argument("--report", type=Path, help="Optional JSON report destination; parent directory must exist")
    parser.add_argument("--worker", choices=("preflight", *SUITES), help=argparse.SUPPRESS)
    parser.add_argument("--worker-result", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        if args.worker_result is None:
            parser.error("worker result destination is required")
        try:
            value = preflight() if args.worker == "preflight" else run_suite(args.worker)
            write_json(args.worker_result, value)
            return 0
        except Exception:
            return 1  # No imported-library exception or traceback reaches the report/log.
    if not 1 <= args.timeout <= 1800 or not args.python.is_file():
        parser.error("choose an existing interpreter and a timeout between 1 and 1800 seconds")
    if args.scratch_root is not None and not args.scratch_root.is_dir():
        parser.error("scratch root must be an existing directory")
    if args.report is not None and not args.report.parent.is_dir():
        parser.error("report parent must be an existing directory")
    try:
        report = run_job(args.python, args.scratch_root, args.timeout)
        if args.report is not None:
            write_json(args.report, report)
        print(json.dumps(report, sort_keys=True, allow_nan=False))
        return int(report["status"] != "passed")
    except (OSError, ValueError, SyntaxError):
        print('{"job":"cpu-checkpoints","status":"configuration_or_storage_error"}')
        return 1
    except KeyboardInterrupt:
        print('{"job":"cpu-checkpoints","status":"cancelled"}')
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
