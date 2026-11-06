"""Real PowerShell 5.1 installation in a disposable portable folder.

Pass --runtime-zip with the official pinned amd64 embeddable Python ZIP.
This avoids external downloads during the test. --run-client additionally runs
the installed Pi CLI through the real Yougori Sandbox VM and HTTP fixture.
No persistent user PATH, real key, installed application or live model is changed.
"""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import queue
import threading
import time
from unittest.mock import patch
import urllib.request
import winreg
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow
from runtime_harnesses import TextModel
import harness_download


def quote(text):
    return "'" + str(text).replace("'", "''") + "'"


def user_path():
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
        return winreg.QueryValueEx(key, "Path")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime-zip", type=Path, required=True)
    parser.add_argument("--run-client", action="store_true")
    args = parser.parse_args()
    if hashlib.sha256(args.runtime_zip.read_bytes()).hexdigest() != harness_download.PYTHON_SHA256["amd64"]:
        raise ValueError("The supplied Python archive does not match the official pin.")
    scratch = Path("D:/YougoriBuildCache/scratch/solver-cli-install")
    scratch.mkdir(exist_ok=True, parents=True)
    before = user_path()
    powershell = str(Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe")
    fixture = Flow()
    fixture.setUp()
    fixture.model.RequestHandlerClass = TextModel
    fixture.model.harness = 'pi'
    try:
        with tempfile.TemporaryDirectory(prefix="installer-", dir=scratch) as temp:
            root = Path(temp) / "CLI %SOLVER_LITERAL% & O'Brien Ω"
            (root / "cache").mkdir(parents=True)
            shutil.copyfile(args.runtime_zip, root / "cache" / (harness_download.PYTHON_SHA256["amd64"] + ".zip"))
            env = {**os.environ, "INFERENCE_SOLVER_HOME": str(root), "INFERENCE_SOLVER_NO_PATH": "1",
                   "LOCALAPPDATA": str(Path(temp) / "profile"), "PYTHONDONTWRITEBYTECODE": "1", "INFERENCE_SOLVER_NO_LAUNCH":"1"}

            def ps(code, input=None, success=True, approve_device=False):
                code = "[Console]::OutputEncoding = New-Object Text.UTF8Encoding $false; " + code
                encoded = base64.b64encode(code.encode("utf-16-le")).decode()
                invocation = [powershell, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
                if len(encoded) > 22000:
                    # Tampered-archive cases execute the full generated script;
                    # Windows limits CreateProcess command lines to 32 KiB.
                    script_path = Path(temp) / "installer-check.ps1"
                    script_path.write_text(code, encoding="utf-8-sig")
                    invocation = [powershell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(script_path)]
                if approve_device:
                    process = subprocess.Popen(invocation, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                               text=True, encoding="utf-8", errors="replace", env=env)
                    lines, chunks = queue.Queue(), []
                    def read_output():
                        for line in process.stdout:
                            lines.put(line)
                        lines.put(None)
                    threading.Thread(target=read_output, daemon=True).start()
                    deadline = time.monotonic() + 180
                    approved = False
                    try:
                        while True:
                            line = lines.get(timeout=max(.1, deadline - time.monotonic()))
                            if line is None:
                                break
                            chunks.append(line)
                            match = re.search(r"Enter code: ([A-Z2-9]{4}-[A-Z2-9]{4})", line)
                            if match:
                                assert not approved
                                status, _, _ = fixture.call("/api/device/decide", {"user_code": match[1], "approve": True}, fixture.admin)
                                assert status == 200
                                approved = True
                        output = "".join(chunks)
                        assert approved and process.wait(timeout=20) == 0, output
                        return output
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait()
                        process.stdout.close()
                result = subprocess.run(invocation,
                                        input=input, text=True, encoding="utf-8", errors="replace", env=env,
                                        capture_output=True, timeout=180)
                output = result.stdout + result.stderr
                if success:
                    assert result.returncode == 0, output[-5000:]
                else:
                    assert result.returncode != 0, "Expected installation to fail"
                return output

            def install(name, url=fixture.url):
                output = ps("irm " + quote(url + "/install/" + name + ".ps1") + " | iex")
                assert "Installed solver-" + name in output, output
                return output

            names = [name for name, spec in harness_download.catalog().items() if not spec.get("blocked")]
            for name in names:
                install(name)
                command = root / "bin" / ("solver-" + name + ".cmd")
                output = ps("& " + quote(command) + " --version; exit $LASTEXITCODE")
                assert fixture.url in output and "solver-" + name in output
                print(name + ": real PowerShell install and installed CLI passed", flush=True)
            pi = root / "bin/solver-pi.cmd"
            old = pi.read_bytes()
            install("pi")
            assert pi.read_bytes() == old, "Reinstallation changed an identical command"
            output = ps("& " + quote(pi) + " --help; exit $LASTEXITCODE")
            assert "--workspace PATH" in output
            assert not list(root.glob(".stage-*")), "Completed installation left a staging folder"

            alternate = fixture.url.replace("127.0.0.1", "localhost")
            install("pi", alternate)
            alias = "solver-pi-" + hashlib.sha256(alternate.encode()).hexdigest()[:8]
            output = ps("& " + quote(root / "bin" / (alias + ".cmd")) + " --version; exit $LASTEXITCODE")
            assert alias in output and alternate in output and pi.read_bytes() == old
            print("Reinstall, separate servers and special-character paths passed", flush=True)

            script = urllib.request.urlopen(fixture.url + "/install/pi.ps1").read().decode()
            match = re.search(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)", script)
            config = json.loads(base64.b64decode(match[1]))

            def altered(**changes):
                encoded = base64.b64encode(json.dumps({**config, **changes}).encode()).decode()
                return script.replace(match[1], encoded)

            output = ps(altered(sha256="0" * 64), success=False)
            assert "checksum mismatch" in output and pi.read_bytes() == old
            bad = io.BytesIO()
            with zipfile.ZipFile(bad, "w") as archive:
                archive.writestr("../escape.txt", "must not be written")
            data = bad.getvalue()
            with patch.object(harness_download, "bundle", return_value=data):
                output = ps(altered(sha256=hashlib.sha256(data).hexdigest()), success=False)
            assert "escaped its folder" in output and not (root / "escape.txt").exists()
            assert pi.read_bytes() == old and not list(root.glob(".stage-*"))
            print("Bad checksums and ZIP traversal refused; working CLI preserved", flush=True)

            if args.run_client:
                fixture.endpoint()
                model = "test/one"
                fixture.service.refresh()
                output = ps("& " + quote(pi) + " --no-browser --no-tty --model " + quote(model)
                            + " -- --print 'Say SOLVER_OK. Do not call tools.'; exit $LASTEXITCODE", approve_device=True)
                key_files = list((Path(temp) / "profile").rglob("api-key"))
                assert len(key_files) == 1
                secret = key_files[0].read_text().strip()
                assert secret not in output and "SOLVER_OK" in output
                assert fixture.model.calls and all(c["model"] == "test/one" for c in fixture.model.calls)
                assert getattr(fixture.model, 'contract_checked', False)
                print("Installed CLI completed code sign-in and real Yougori VM inference without a manually created key", flush=True)
            assert user_path() == before
            print("Persistent user PATH was unchanged; all Windows installer checks passed", flush=True)
    finally:
        fixture.tearDown()


if __name__ == "__main__":
    main()
