"""Check real dedicated VM sizing using a disposable Windows acceptance engine.

Correlates guest MemTotal/boot IDs with host QEMU PIDs, argv and the shared ledger.
Does not connect to the installed engine. Failed attempts retain their evidence.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import time

spec = importlib.util.spec_from_file_location(
    "migration_acceptance", Path(__file__).with_name("model-migration-recovery.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Run(base.Run):
    def __init__(self, args):
        super().__init__(args)
        self.sandboxes = []

    def result(self, method, params, label=None):
        return self.call(method, params, label)["result"]

    def processes(self):
        command = ('Get-CimInstance Win32_Process -Filter "Name=\'qemu-system-x86_64.exe\'" | '
                   'Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress')
        result = subprocess.run(["powershell", "-NoProfile", "-Command", command],
                                capture_output=True, text=True, timeout=30,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert result.returncode == 0, result.stderr
        rows = json.loads(result.stdout) if result.stdout.strip() else []
        if not isinstance(rows, list):
            rows = [rows]
        marker = str(self.data).replace("\\", "/").lower()
        return [row for row in rows if marker in
                (row.get("CommandLine") or "").replace("\\", "/").lower()]

    def wait_no_vm(self):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rows = self.processes()
            if not rows:
                return
            time.sleep(1)
        raise AssertionError(f"Owned VM processes survived: {rows}")

    def run(self):
        self.start()
        assert self.result("sandbox_vm", {"action": "plan"}, "plan")["launchable"]
        refused = self.call("sandbox_vm", {"action": "launch", "memoryGb": 0.2},
                            "under-minimum-refused", checked=False)
        assert not refused["ok"], refused
        assert not self.processes()
        baseline = self.result("model_ledger", {}, "ledger-before")["open"]
        assert not baseline, baseline
        boots, pids, checks = set(), set(), []
        for host_mib, guest_mib in [(1024, 768), (2048, 1792), (320, 256)]:
            launch = self.result("sandbox_vm", {"action": "launch", "memoryGb": host_mib / 1024},
                                 f"launch-{host_mib}")
            sandbox = launch["sandbox"]
            self.sandboxes.append(sandbox)
            report = self.result("sandbox_vm", {
                "action": "exec", "sandbox": sandbox,
                "input": "cat /proc/meminfo; cat /proc/sys/kernel/random/boot_id",
                "timeoutSeconds": 30}, f"guest-{host_mib}")
            assert report["exit_code"] == 0, report
            text = report["output_text"]
            total_kib = int(re.search(r"MemTotal:\s+(\d+) kB", text).group(1))
            assert (guest_mib - 128) * 1024 < total_kib <= guest_mib * 1024, text
            boot = text.strip().splitlines()[-1]
            assert re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot), boot
            assert boot not in boots
            boots.add(boot)
            status = self.result("sandbox_vm", {"action": "status"}, f"status-{host_mib}")
            row = next(row for row in status["sandboxes"] if row["sandbox"] == sandbox)
            pid = row["process"]["pid"]
            assert pid not in pids
            pids.add(pid)
            host = self.processes()
            process = next(row for row in host if row["ProcessId"] == pid)
            command = process["CommandLine"]
            assert re.search(rf'(?:^|\s)"?-m"?\s+"?{guest_mib}M"?(?:\s|$)', command), command
            assert "whpx" in command and "tcg" not in command, command
            assert len(host) == len(self.sandboxes), host
            ledger = self.result("model_ledger", {}, f"ledger-{host_mib}")
            owned = [row for row in ledger["open"] if row["parent"] is None
                     and row.get("provenance", {}).get("execution") == sandbox]
            assert len(owned) == 1 and owned[0]["currentHostBytes"] == host_mib * (1 << 20), owned
            checks.append({"sandbox": sandbox, "pid": pid, "host_mib": host_mib,
                           "guest_mib": guest_mib, "guest_mem_total_kib": total_kib,
                           "boot_id": boot, "host_process": process})
        self.write("simultaneous-vms", checks)
        for sandbox in self.sandboxes:
            self.result("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "stop-vm")
        self.wait_no_vm()
        ledger = self.result("model_ledger", {}, "ledger-after")
        assert not ledger["open"], ledger
        self.write("passed", {"profiles": len(checks), "distinct_kernel_boots": len(boots),
                              "no_owned_qemu": True, "no_open_reservations": True})

    def clean(self):
        if self.process is not None and self.process.poll() is None:
            try:
                for sandbox in self.sandboxes:
                    self.call("sandbox_vm", {"action": "stop", "sandbox": sandbox},
                              "cleanup-vm", checked=False)
            finally:
                self.stop()
        self.wait_no_vm()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    args.model, args.reuse_fixture, args.from_case = args.root / "unused-model", False, None
    run = Run(args)
    try:
        run.run()
    finally:
        run.clean()
