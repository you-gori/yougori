"""Opt-in crash check for an owned GPU VM. The engine mode requires an idle dev engine.
Only the exact PID/creation-time handle is terminated; no process-name sweeps.
"""
import argparse
import ctypes as C
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", required=True)
    parser.add_argument("--app", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--engine", action="store_true")
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    records = []

    def record(name, value):
        records.append({"check": name, "result": value})
        (args.output / "results.json").write_text(json.dumps(records, indent=2), encoding="utf-8")
        print(name, flush=True)

    def command(arguments, params=None):
        result = subprocess.run([args.cli, *arguments], input=json.dumps(params) if params is not None else None,
                                capture_output=True, text=True, encoding="utf-8", timeout=240)
        value = json.loads(result.stdout)
        if result.returncode or not value.get("ok"):
            raise RuntimeError(value.get("error", result.stderr))
        return value["result"]

    def vm(**params):
        return command(["call", "sandbox_vm", "--file", "-", "--yes"], params)

    before = vm(action="status")
    assert not any(row["phase"] == "ready" for row in before["sandboxes"]), "another VM is running"
    status = command(["status"])
    assert status["environments"]["running"] == 0, "another environment is running"
    launched = vm(action="launch", gpu=True, cpu=2, memoryGb=4, internet=True, idleSeconds=0, lifetimeSeconds=0)
    sandbox = launched["sandbox"]
    parent = launched["status"]["process"]
    record("launched", launched)
    directory = None
    for path in (Path(os.environ["LOCALAPPDATA"]) / "Temp/yougori-vm").rglob("worker.json"):
        try:
            if json.loads(path.read_text(encoding="utf-8"))["parent"] == parent:
                directory = path.parent
        except (OSError, ValueError):
            pass
    assert directory is not None, "cannot identify this VM's helper"
    original = json.loads((directory / "status.json").read_text(encoding="utf-8"))
    pid = command(["app", "status"])["pid"] if args.engine else parent["pid"]
    kernel = C.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
    kernel.OpenProcess.restype = W.HANDLE
    kernel.GetProcessTimes.argtypes = [W.HANDLE, *([C.POINTER(W.FILETIME)] * 4)]
    kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
    kernel.TerminateProcess.argtypes = [W.HANDLE, W.UINT]
    kernel.CloseHandle.argtypes = [W.HANDLE]
    handle = kernel.OpenProcess(0x1000 | 1, False, pid)
    assert handle, C.get_last_error()
    engine_ended = False
    try:
        times = [W.FILETIME() for _ in range(4)]
        assert kernel.GetProcessTimes(handle, *(C.byref(value) for value in times))
        created = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
        if not args.engine:
            assert created == parent["start_time_ticks"], "PID was reused"
        path, length = C.create_unicode_buffer(32768), W.DWORD(32768)
        assert kernel.QueryFullProcessImageNameW(handle, 0, path, C.byref(length))
        assert Path(path.value).resolve() == Path(args.app).resolve(), "different executable"
        started = time.monotonic()
        assert kernel.TerminateProcess(handle, 90), C.get_last_error()
        engine_ended = args.engine
        record("terminated exact dev process", {"pid": pid, "created": created, "engine": args.engine})
        removed = None
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            try:
                value = json.loads((directory / "status.json").read_text(encoding="utf-8"))
                if value.get("id") == original["id"] and value.get("removed") is True:
                    removed = value
                    break
            except (OSError, ValueError):
                pass
            time.sleep(.02)
        assert removed, "HCS did not confirm removal of this VM"
        record("HCS VM and endpoint removed", {"seconds": time.monotonic() - started, "status": removed})
    finally:
        kernel.CloseHandle(handle)
        if engine_ended:
            record("dev engine restarted", command(["app", "start", "--app", args.app]))
        record("stop receipt", vm(action="stop", sandbox=sandbox))
        record("test workspace discarded", vm(action="workspace", op="discard", sandbox=sandbox))
    ledger = command(["call", "model_ledger", "--file", "-", "--yes"], {})
    assert not any(row["provenance"].get("execution") == sandbox for row in (ledger or {}).get("open", []))
    record("reservation released", ledger)


if __name__ == "__main__":
    main()
