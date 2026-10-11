"""Native integration: verified tiny weights, auth, real inference, owner loss.

Runs on temporary GitHub Mac runners too. A CPU pass is never a Metal pass.
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / "build/macos-model/runtime"
REVISION = "499bc8821c6b12b4e53c5bffcb21ec206f212d81"
SHA256 = "270cba1bd5109f42d03350f60406024560464db173c0e387d91f0426d3bd256d"


def acceptance(report):
    if sys.platform != "darwin":
        raise RuntimeError("This acceptance test requires native macOS")
    # Check the exact signed binaries that the engine will accept, before probing.
    verified = set()
    for line in (RUNTIME / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*")
        path = (RUNTIME / name).resolve()
        if not path.is_relative_to(RUNTIME.resolve()):
            raise RuntimeError("Invalid native runtime checksum path")
        if name in verified:
            raise RuntimeError(f"Duplicate native runtime checksum: {name}")
        with path.open("rb") as source:
            if hashlib.file_digest(source, "sha256").hexdigest() != digest:
                raise RuntimeError(f"Native runtime checksum mismatch: {name}")
        verified.add(name)
    if not {"llama-server", "yougori-supervise", "REVISION"}.issubset(verified):
        raise RuntimeError("Native runtime manifest is incomplete")
    # Hosted runners contain Homebrew libraries that an end-user Mac may lack.
    # Bundled executables must load only Apple's system libraries/frameworks.
    report["libraries"] = {}
    for binary in ["llama-server", "yougori-supervise"]:
        path = str(RUNTIME / binary)
        subprocess.run(["/usr/bin/codesign", "--verify", "--strict", path], check=True, capture_output=True, timeout=30)
        architecture = subprocess.run(["/usr/bin/lipo", "-archs", path], check=True, capture_output=True, text=True, timeout=30)
        if architecture.stdout.strip() != platform.machine():
            raise RuntimeError(f"Native runtime architecture mismatch: {binary}")
        linkage = subprocess.run(["/usr/bin/otool", "-L", path], check=True, capture_output=True, text=True, timeout=30)
        libraries = [line.strip().split(" (compatibility", 1)[0] for line in linkage.stdout.splitlines()[1:] if line.strip()]
        report["libraries"][binary] = libraries
        for library in libraries:
            if not library.startswith(("/usr/lib/", "/System/Library/")):
                raise RuntimeError(f"Native runtime requires an unbundled library: {library}")
    report["runtimeRevision"] = (RUNTIME / "REVISION").read_text().strip()
    listing = subprocess.run([str(RUNTIME / "llama-server"), "--list-devices"], capture_output=True, text=True, check=True, timeout=30)
    metal_device = next((line.split(":", 1)[0].strip() for line in listing.stdout.splitlines()
                         if re.match(r"^(?:MTL|Metal)\d+:\s", line.strip())), None)
    metal = metal_device is not None
    report["metal"] = "not_run" if metal else "not_available"
    report["metalDevice"] = metal_device
    report["devices"] = listing.stdout.strip()
    with tempfile.TemporaryDirectory(prefix="yougori-native-qa-") as folder:
        weight = Path(folder) / "stories.gguf"
        url = f"https://huggingface.co/ggml-org/models/resolve/{REVISION}/tinyllamas/stories260K.gguf"
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read(1185377)
        assert len(data) == 1185376 and hashlib.sha256(data).hexdigest() == SHA256, "Fixture checksum mismatch"
        weight.write_bytes(data)
        for backend in ["cpu"] + (["metal"] if metal else []):
            with socket.socket() as listener:
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
            key = secrets.token_hex(32)
            env = {"PATH": "/usr/bin:/bin", "LLAMA_API_KEY": key}
            command = [str(RUNTIME / "yougori-supervise"), str(RUNTIME / "llama-server"), "-m", str(weight),
                       "--host", "127.0.0.1", "--port", str(port), "--no-webui", "--device",
                       metal_device if backend == "metal" else "none", "-ngl", "all" if backend == "metal" else "0",
                       "-c", "512", "-t", "2", "--poll", "0"]
            report[backend] = "failed"
            log = tempfile.TemporaryFile(mode="w+b")
            process = None
            base = f"http://127.0.0.1:{port}"

            def request(path, body=None, credential=key):
                headers = {"Authorization": "Bearer " + credential, "Content-Type": "application/json"}
                req = urllib.request.Request(base + path, data=None if body is None else json.dumps(body).encode(), headers=headers)
                with urllib.request.urlopen(req, timeout=30) as response:
                    return json.load(response)

            try:
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=log, stderr=log, env=env)
                deadline = time.monotonic() + 120
                while True:
                    assert process.poll() is None, "Native server exited during startup"
                    try:
                        request("/health")
                        break
                    except (OSError, urllib.error.HTTPError):
                        assert time.monotonic() < deadline, "Native server readiness timed out"
                        time.sleep(0.2)
                try:
                    request("/completion", {"prompt": "Once", "n_predict": 1}, credential="wrong")
                    raise AssertionError("Native server accepted a wrong key")
                except urllib.error.HTTPError as error:
                    assert error.code == 401
                result = request("/completion", {"prompt": "Once upon a time", "n_predict": 8, "temperature": 0})
                assert result.get("tokens_predicted", 0) > 0, "No inference tokens generated"
                # Closing the engine-owned pipe simulates owner crash. The watchdog
                # must stop the process without relying on a graceful engine callback.
                process.stdin.close()
                process.wait(timeout=8)
                report[backend] = "passed_auth_inference_owner_loss"
            finally:
                if process is not None:
                    if process.stdin and not process.stdin.closed:
                        process.stdin.close()
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=8)
                # Keep a bounded, credential-redacted tail even if startup or a
                # test fails. Never upload the inherited environment or raw log.
                log.seek(0, os.SEEK_END)
                log.seek(max(0, log.tell() - 16384))
                report.setdefault("diagnostics", {})[backend] = log.read().decode("utf-8", errors="replace").replace(key, "[REDACTED]")
                log.close()


def main():
    report = {"os": platform.platform(), "architecture": platform.machine(),
              "cpu": "not_run", "metal": "not_run", "status": "failed"}
    path = ROOT / "artifacts/macos-native-acceptance.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        acceptance(report)
        report["status"] = "passed"
    except Exception as error:
        report["error"] = f"{type(error).__name__}: {error}"
        raise
    finally:
        path.write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({key: value for key, value in report.items() if key != "diagnostics"}))


if __name__ == "__main__":
    main()
