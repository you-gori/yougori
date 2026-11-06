"""Validate the integrated model/VM lifecycle on one disposable acceptance engine.

Uses a local Transformers model, a fresh catalog and a private workspace. Checks real
inference beside a real VM, shared-ledger ownership, VM isolation/cleanup, and an engine
crash with both workloads present. Never addresses the installed engine. A failed run
retains evidence; only resources created by this run are eligible for cleanup.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import time


spec = importlib.util.spec_from_file_location(
    "migration_acceptance", Path(__file__).with_name("model-migration-recovery.py"))
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)


def redacted(value):
    if isinstance(value, dict):
        return {key: "[redacted]" if key.lower().replace("_", "") in
                {"apikey", "token", "secret", "authorization", "password"} else redacted(item)
                for key, item in value.items()}
    if isinstance(value, list):
        return [redacted(item) for item in value]
    return value


class Combined(migration.Run):
    def __init__(self, args):
        super().__init__(args)
        self.port = args.port
        self.sandboxes = []
        self.source_hashes = {str(p.relative_to(self.model)): migration.digest(p)
                              for p in self.model.rglob("*") if p.is_file()}

    def write(self, name, body):
        super().write(name, redacted(body))

    def result(self, method, params, label=None):
        return self.call(method, params, label)["result"]

    def wait_ready(self):
        deadline = time.monotonic() + 1800
        previous = None
        while time.monotonic() < deadline:
            health = self.result("model_status", {"environmentId": self.environment_id})
            state = health.get("status")
            if state != previous:
                self.write("model-state", health)
                previous = state
            if state == "ready":
                return health
            if state == "error":
                raise RuntimeError("model failed; inspect model-state evidence")
            time.sleep(2)
        raise TimeoutError("model did not become ready in 30 minutes")

    def chat(self, label):
        reply = self.result("model_chat", {
            "environmentId": self.environment_id,
            "messages": [{"role": "user", "content": "What is an API? Answer in one short sentence."}],
            "temperature": 0, "maxTokens": 32,
        }, label)
        text = reply["choices"][0]["message"]["content"]
        assert text.strip(), "empty inference response"
        return text

    def ledger(self, label=None):
        return self.result("model_ledger", {}, label)

    def host_memory(self, label):
        # The ledger deliberately keeps standby/cache pages charged. Record the exact
        # counters it consumes, as well as Windows' broader available-memory number,
        # so an admission refusal is distinguishable from a lifecycle failure.
        code = ("$ErrorActionPreference='Stop'; "
                "$os=Get-CimInstance Win32_OperatingSystem; "
                "$m=Get-CimInstance Win32_PerfRawData_PerfOS_Memory; "
                "[pscustomobject]@{totalBytes=[uint64]$os.TotalVisibleMemorySize*1024; "
                "freeAndZeroBytes=$m.FreeAndZeroPageListBytes; availableBytes=$m.AvailableBytes; "
                "committedBytes=$m.CommittedBytes; commitLimitBytes=$m.CommitLimit; "
                "compilers=@(Get-Process rustc,lld-link -ErrorAction SilentlyContinue | "
                "Select-Object Name,Id,WorkingSet64)} | ConvertTo-Json -Depth 4 -Compress")
        reply = subprocess.run(["powershell", "-NoProfile", "-Command", code],
                               capture_output=True, text=True, timeout=30)
        assert reply.returncode == 0, reply.stderr
        reading = json.loads(reply.stdout)
        self.write(label, reading)
        return reading

    def launch(self, workspace):
        self.host_memory("memory-before-vm")
        reply = self.result("sandbox_vm", {"action": "launch", "memoryGb": 0.5,
                                             "workspace": str(workspace)}, "launch-vm")
        sandbox = reply["sandbox"]
        self.sandboxes.append(sandbox)
        return sandbox

    def execute(self, sandbox, command, label):
        result = self.result("sandbox_vm", {"action": "exec", "sandbox": sandbox,
                              "input": command, "timeoutSeconds": 30}, label)
        assert result["exit_code"] == 0, result
        return result.get("output_text", "")

    def processes(self):
        code = ('Get-CimInstance Win32_Process -Filter "Name=\'qemu-system-x86_64.exe\'" | '
                'Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress')
        reply = subprocess.run(["powershell", "-NoProfile", "-Command", code],
                               capture_output=True, text=True, timeout=30)
        assert reply.returncode == 0, reply.stderr
        value = json.loads(reply.stdout) if reply.stdout.strip() else []
        rows = value if isinstance(value, list) else [value]
        marker = str(self.data).replace("\\", "/").lower()
        return [r for r in rows if marker in (r.get("CommandLine") or "").replace("\\", "/").lower()]

    def wait_no_vm(self):
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            remaining = self.processes()
            if not remaining:
                return
            time.sleep(1)
        raise AssertionError(f"owned VM processes remain: {remaining}")

    def clean(self):
        if self.process is None or self.process.poll() is not None:
            return
        for sandbox in self.sandboxes:
            self.call("sandbox_vm", {"action": "stop", "sandbox": sandbox},
                      "cleanup-vm", checked=False)
        if self.environment_id:
            self.call("stop_model", {"environmentId": self.environment_id},
                      "cleanup-model-stop", checked=False)
            reply = self.call("delete_environment", {"environmentId": self.environment_id},
                              "cleanup-model-delete", checked=False)
            if reply.get("ok"):
                self.environment_id = None

    def run(self):
        workspace = self.root / "workspace"
        workspace.mkdir(exist_ok=self.reuse_fixture)
        original = workspace / "input.txt"
        if original.exists():
            assert original.read_text() == "combined-model-vm\n", "prior source was changed"
        else:
            original.write_text("combined-model-vm\n", encoding="utf-8")
        assert not (workspace / "output.txt").exists(), "prior run changed the source"
        self.write("source-before", self.source_hashes)
        self.host_memory("memory-before-model")
        self.start()
        if self.reuse_fixture:
            state = self.result("get_platform_state", {}, "reuse-empty-fixture")
            assert not state.get("environments"), "reused fixture still has environments"
            # Catalog recovery follows host-capacity initialization asynchronously. Wait
            # for its postcondition; do not mistake IPC readiness for recovery completion.
            recovery_deadline = time.monotonic() + 60
            while time.monotonic() < recovery_deadline:
                catalog = self.catalog(None)
                views = self.root / "catalog" / "views"
                if catalog["catalog"]["live_leases"] == 0 and not (views.exists() and any(views.iterdir())):
                    break
                time.sleep(1)
            self.catalog("reuse-released-catalog", empty=True)
            self.wait_no_vm()
        before = self.ledger("ledger-before")
        assert not (before or {}).get("open"), before
        created = self.result("run_model", {"model": "local/combined-qwen05",
                                "folder": str(self.model), "port": self.port}, "create-model")
        self.environment_id = created["id"]
        health = self.wait_ready()
        assert health.get("runner") in ("transformers", "yougori-transformers-chat"), health.get("runner")
        baseline = self.chat("chat-before-vm")
        model_only = self.ledger("ledger-model-only")
        assert any(row.get("environment") == self.environment_id for row in model_only["open"])
        sandbox = self.launch(workspace)
        live = self.processes()
        assert live, "positive control: no owned QEMU found in host process list"
        output = self.execute(sandbox, "cat /run/yougori/workspace/input.txt\nprintf guest-only > /run/yougori/workspace/output.txt\n", "vm-exec")
        assert "combined-model-vm" in output
        assert not (workspace / "output.txt").exists(), "VM wrote into the original workspace"
        both = self.ledger("ledger-model-and-vm")
        assert {r["id"] for r in model_only["open"]} < {r["id"] for r in both["open"]}, "VM has no additional shared reservation"
        assert both["gpu"]["reservedBytes"] == model_only["gpu"]["reservedBytes"], "VM changed GPU reservation"
        assert self.chat("chat-beside-vm") == baseline, "inference changed beside the VM"
        self.result("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "stop-vm")
        self.wait_no_vm()
        after = self.ledger("ledger-after-vm-stop")
        assert {r["id"] for r in after["open"]} == {r["id"] for r in model_only["open"]}, "VM reservation leaked or model reservation changed"
        assert self.chat("chat-after-vm-stop") == baseline
        sandbox = self.launch(workspace)
        assert self.processes(), "positive control: second VM missing before crash"
        self.write("before-crash", {"pid": self.process.pid, "sandbox": sandbox,
                                    "model": self.environment_id, "ledger": self.ledger()})
        self.process.kill()
        self.process.wait(timeout=30)
        self.wait_no_vm()
        self.write("supervisor-stopped-vm", {"owned_qemu_remaining": self.processes()})
        self.start()
        self.result("recover_environment_runtime_report", {
            "environmentId": self.environment_id, "confirmed": True}, "recover-abandoned-model")
        self.result("start_model", {"environmentId": self.environment_id}, "restart-model")
        self.wait_ready()
        assert self.chat("chat-after-recovery") == baseline
        # Both lifecycle routes must settle the exact grant, even when deletion removes
        # the workload options before the optimizer's next poll. Keep the same volume
        # for the second start so this does not add a second cold import.
        self.result("stop_model", {"environmentId": self.environment_id}, "explicit-model-stop")
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            stopped = self.ledger()
            if not stopped.get("open") and not stopped.get("models"):
                break
            time.sleep(1)
        self.write("ledger-after-explicit-stop", stopped)
        assert not stopped.get("open") and not stopped.get("models"), "stop left model reservations"
        self.result("start_model", {"environmentId": self.environment_id}, "restart-for-direct-delete")
        self.wait_ready()
        assert self.chat("chat-before-direct-delete") == baseline
        active = self.ledger("ledger-before-direct-delete")
        assert any(row.get("environment") == self.environment_id for row in active["open"])
        self.result("delete_environment", {"environmentId": self.environment_id}, "delete-running-model")
        self.environment_id = None
        self.clean()
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            final = self.ledger()
            if not final.get("open") and not final.get("models"):
                break
            time.sleep(1)
        self.write("ledger-final", final)
        assert not final.get("open") and not final.get("models"), "reservations remain after cleanup"
        assert self.environment_id is None, "fixture deletion failed"
        self.catalog("catalog-final", empty=True)
        self.wait_no_vm()
        assert self.source_hashes == {str(p.relative_to(self.model)): migration.digest(p)
                                      for p in self.model.rglob("*") if p.is_file()}
        assert (workspace / "input.txt").read_text() == "combined-model-vm\n"
        assert not (workspace / "output.txt").exists()
        self.stop()
        self.write("PASS", {"mixed_inference": True, "shared_ledger": True,
                            "independent_vm_cleanup": True, "real_engine_crash": True,
                            "supervisor_stopped_vm": True, "inference_recovered": True,
                            "explicit_stop_releases_gpu": True, "running_delete_releases_gpu": True,
                            "sources_unchanged": True, "reservations_and_views_released": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("root", "engine", "cli", "runtime", "model"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--port", type=int, default=18887)
    parser.add_argument("--reuse-fixture", action="store_true",
                        help="Reuse a cleaned disposable runtime, append evidence and refuse remaining environments/leases")
    parser.set_defaults(from_case=0)
    run = Combined(parser.parse_args())
    try:
        run.run()
    finally:
        if run.process is not None and run.process.poll() is None:
            run.clean()
            run.stop()


if __name__ == "__main__":
    main()
