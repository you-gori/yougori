"""Pause only this disposable engine and its supervisor, then test real VM expiry.

Process handles/pidfds and creation-time checks prevent PID-reuse signalling.
--baseline records the old defect: an expired VM survives the supervisor's resume.
No host suspend, clock change, installed app or other engine is touched.
"""
import argparse
import ctypes
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import time

spec = importlib.util.spec_from_file_location("oci", Path(__file__).with_name("oci-vm.py"))
oci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oci)


class Watched:
    def __init__(self, identity):
        self.identity, self.paused = dict(identity), False
        if os.name == "nt":
            from ctypes import wintypes as w
            self.k = ctypes.WinDLL("kernel32", use_last_error=True)
            self.n = ctypes.WinDLL("ntdll")
            self.k.OpenProcess.argtypes, self.k.OpenProcess.restype = [w.DWORD, w.BOOL, w.DWORD], w.HANDLE
            self.k.CloseHandle.argtypes = [w.HANDLE]
            self.k.GetProcessTimes.argtypes = [w.HANDLE] + [ctypes.POINTER(w.FILETIME)] * 4
            self.k.WaitForSingleObject.argtypes, self.k.WaitForSingleObject.restype = [w.HANDLE, w.DWORD], w.DWORD
            for fn in (self.n.NtSuspendProcess, self.n.NtResumeProcess):
                fn.argtypes, fn.restype = [w.HANDLE], ctypes.c_long
            self.handle = self.k.OpenProcess(0x00100000 | 0x1000 | 0x0800, False, identity["pid"])
            if not self.handle:
                raise ctypes.WinError(ctypes.get_last_error())
            times = [w.FILETIME() for _ in range(4)]
            if not self.k.GetProcessTimes(self.handle, *[ctypes.byref(t) for t in times]):
                self.close()
                raise ctypes.WinError(ctypes.get_last_error())
            ticks = times[0].dwHighDateTime << 32 | times[0].dwLowDateTime
        else:
            self.handle = os.pidfd_open(identity["pid"])
            try:
                fields = Path(f"/proc/{identity['pid']}/stat").read_text().rsplit(")", 1)[1].split()
                ticks = int(fields[19])
            except Exception:
                self.close()
                raise
        if ticks != identity.get("start_time_ticks", ticks):
            self.close()
            raise RuntimeError("process identity changed before opening its handle")
        self.identity["start_time_ticks"] = ticks
        assert not self.ended(), "process already ended"

    def ended(self):
        if os.name == "nt":
            result = self.k.WaitForSingleObject(self.handle, 0)
            assert result in (0, 258), f"process wait failed: {result}"
            return result == 0
        return bool(select.select([self.handle], [], [], 0)[0])

    def pause(self):
        if os.name == "nt":
            assert self.n.NtSuspendProcess(self.handle) == 0
        else:
            signal.pidfd_send_signal(self.handle, signal.SIGSTOP)
        self.paused = True

    def resume(self):
        if self.paused:
            if not self.ended():
                if os.name == "nt":
                    assert self.n.NtResumeProcess(self.handle) == 0
                else:
                    signal.pidfd_send_signal(self.handle, signal.SIGCONT)
            self.paused = False

    def close(self):
        if self.handle is not None:
            self.resume()
            if os.name == "nt":
                self.k.CloseHandle(self.handle)
            else:
                os.close(self.handle)
            self.handle = None


class Run(oci.Run):
    def run_expiry(self, baseline):
        self.env["YOUGORI_ACCEPTANCE_SUPERVISOR_SILENCE_SECONDS"] = "90"
        self.env["YOUGORI_ACCEPTANCE_SUPERVISOR_GRACE_SECONDS"] = "1"
        self.start()
        observations = []
        for kind, limits in [("absolute", {"idleSeconds": 300, "lifetimeSeconds": 20}),
                             ("idle", {"idleSeconds": 20, "lifetimeSeconds": 300})]:
            launch = self.vm({"action": "launch", "memoryGb": 0.5, **limits}, kind + "-launch")
            sandbox = launch["sandbox"]
            self.sandboxes.append(sandbox)
            watched = []
            try:
                for identity in ({"pid": self.process.pid}, launch["supervisor"]["supervisor"], launch["status"]["process"]):
                    watched.append(Watched(identity))
                engine, supervisor, vm = watched
                engine.pause()
                supervisor.pause()
                started = time.monotonic()
                time.sleep(24)
                assert not vm.ended(), "VM ended before supervisor resumed; this would not prove its enforcement"
                supervisor.resume()
                resumed = time.monotonic()
                while not vm.ended() and time.monotonic() - resumed < 3:
                    time.sleep(0.025)
                ended = vm.ended()
                observation = {"kind": kind, "sandbox": sandbox, "baseline": baseline,
                               "paused_seconds": resumed - started, "ended_on_resume": ended,
                               "after_resume_seconds": time.monotonic() - resumed,
                               "identities": [w.identity for w in watched]}
                self.write(kind + "-resume", observation)
                observations.append(observation)
                assert ended != baseline, observation
            finally:
                # Always resume the engine before invoking cleanup, including failures.
                for item in reversed(watched):
                    item.close()
            until = time.monotonic() + 30
            while time.monotonic() < until:
                status = self.vm({"action": "status"}, kind + "-status")
                row = next(s for s in status["sandboxes"] if s["sandbox"] == sandbox)
                if row["state"] in ("revoked", "stopped", "failed"):
                    break
                time.sleep(0.25)
            self.vm({"action": "stop", "sandbox": sandbox}, kind + "-cleanup")
            self.wait_no_qemu()
            # Keep the supervisor's own cause and gap record, not merely CLI state.
            records = []
            for journal in (self.data / "sandbox-vm" / "supervisor").glob("*.jsonl"):
                records.extend(json.loads(line) for line in journal.read_text().splitlines())
            self.write(kind + "-journal", records)
            assert any(r.get("event", {}).get("kind") == "gap" and
                       r["event"]["gap_ms"] > 10_000 for r in records), records
            if not baseline:
                assert any(r.get("event", {}).get("kind") == "ended" and
                           r["event"]["end"]["sandbox"] == sandbox and
                           r["event"]["end"]["cause"] == kind + "_limit" and
                           r["event"]["end"]["kill_rounds"] >= 1 for r in records), records
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        assert self.catalog("final-catalog")["catalog"]["live_leases"] == 0
        self.stop()
        self.wait_no_qemu()
        self.write("result", {"passed": True, "baseline_defect": baseline, "cases": observations,
                              "open_reservations": 0, "live_leases": 0})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--baseline", action="store_true")
    args = parser.parse_args()
    args.reuse_fixture, args.from_case, args.model, args.fixture = False, None, args.engine.parent, args.engine
    run = Run(args)
    try:
        run.run_expiry(args.baseline)
    finally:
        if run.process and run.process.poll() is None:
            for sandbox in run.sandboxes:
                run.call("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "cleanup", checked=False)
            run.stop()
