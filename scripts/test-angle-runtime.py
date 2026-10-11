#!/usr/bin/env python3
"""Exercise replacement ANGLE DLLs in diskless, isolated QEMU processes."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parent.parent


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--angle", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    results = []
    with tempfile.TemporaryDirectory(prefix="angle-smoke-", dir=ROOT / "build") as temporary:
        base = Path(temporary)
        for part in ("qemu", "qemu-secure"):
            runtime = base / part
            shutil.copytree(ROOT / "src-tauri/resources/runtime" / part, runtime)
            shutil.copyfile(args.angle / "libEGL.dll", runtime / "libEGL_angle.dll")
            shutil.copyfile(args.angle / "libGLESv2.dll", runtime / "libGLESv2.dll")
            adapters = json.loads(subprocess.check_output([str(runtime / "yougori-gpu-probe.exe")], creationflags=subprocess.CREATE_NO_WINDOW))
            if not adapters:
                raise RuntimeError("No physical GPU available for validation")
            for selected in [None, *adapters, {"luid": "7fffffff:ffffffff", "name": "intentionally missing GPU"}]:
                invalid = selected and selected["luid"] == "7fffffff:ffffffff"
                report = base / "gpu.json"
                report.unlink(missing_ok=True)
                env = os.environ.copy()
                env.pop("YOUGORI_GPU_LUID", None)
                if selected:
                    env["YOUGORI_GPU_LUID"] = selected["luid"]
                env["YOUGORI_GPU_REPORT"] = str(report)
                command = [str(runtime / "qemu-system-x86_64.exe"), "-L", str(base / "qemu/share"),
                           "-machine", "q35", "-accel", "tcg,thread=multi", "-m", "128", "-nodefaults", "-S",
                           "-device", "virtio-vga-gl,max_outputs=1" if part == "qemu-secure" else "virtio-gpu-gl-pci,max_outputs=1",
                           "-display", "egl-headless", "-qmp", "stdio", "-monitor", "none", "-serial", "none"]
                stdout_path, stderr_path = base / "stdout.txt", base / "stderr.txt"
                with stdout_path.open("wb") as out, stderr_path.open("wb") as err:
                    with subprocess.Popen(command, cwd=runtime, env=env, stdin=subprocess.PIPE, stdout=out,
                                          stderr=err, creationflags=subprocess.CREATE_NO_WINDOW) as child:
                        deadline = time.monotonic() + 25
                        initialized = False
                        while time.monotonic() < deadline and child.poll() is None:
                            if not invalid and report.exists() and b'"QMP"' in stdout_path.read_bytes():
                                initialized = True
                                break
                            time.sleep(0.1)
                        natural_exit = child.poll()
                        if natural_exit is None:
                            # This owned fixture has no disks or guest workload.
                            child.kill()
                        child.wait(timeout=5)
                stdout, stderr = stdout_path.read_bytes(), stderr_path.read_bytes()
                actual = json.loads(report.read_text()) if report.exists() else {}
                if invalid:
                    assert natural_exit and actual.get("ok") is False, (part, actual, stderr.decode(errors="replace"))
                else:
                    assert initialized and actual.get("ok"), (part, actual, stdout.decode(errors="replace"), stderr.decode(errors="replace"))
                    if selected:
                        assert actual["luid"] == selected["luid"], (part, selected, actual)
                results.append({"runtime": part, "requested": selected, "actual": {k: v for k, v in actual.items() if k != "pid"},
                                "naturalExitCode": natural_exit, "disklessFixtureStopped": natural_exit is None,
                                "stderr": stderr.decode(errors="replace"), "passed": True})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    print(f"Passed {len(results)} diskless QEMU GPU checks, including automatic selection and rejection of a missing GPU.")


if __name__ == "__main__":
    main()
