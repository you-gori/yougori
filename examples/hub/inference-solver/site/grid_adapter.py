"""Owner-authorized Sandbox VM operations. This module never runs host commands."""
import json
from pathlib import Path
import re
import subprocess
import threading
import time


class GridAdapter:
    def __init__(self, command, folder, capacity):
        self.command, self.capacity = command, capacity
        self.path = Path(folder) / "grid-vms.json"
        self.vms = json.loads(self.path.read_text()) if self.path.exists() else {}
        self.lock = threading.Lock()

    def save(self):
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.vms), encoding="utf-8")
        temporary.replace(self.path)

    def advertisement(self):
        if not self.capacity:
            return {}
        try:
            self.call("status")
            return {**self.capacity,"available":True,"detail":""}
        except (ValueError,OSError,subprocess.TimeoutExpired):
            return {**self.capacity,"available":False,
                    "detail":"This computer needs a running Yougori engine with Sandbox VM support."}

    def call(self, action, **params):
        process = subprocess.run([self.command,"call","sandbox_vm","--file","-","--yes"],
            input=json.dumps({"action":action,**params}),text=True,encoding="utf-8",capture_output=True,timeout=180,
            creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0))
        try:
            value = json.loads(process.stdout)
        except ValueError:
            raise ValueError("Yougori did not return a VM response. Check Sandbox VM support on this computer.") from None
        if process.returncode or value.get("ok") is not True:
            raise ValueError("Yougori could not complete this VM action. Check Sandbox VM support on the contributing computer.")
        return value["result"]

    def execute(self, job):
        with self.lock:
            vm, kind, payload = job["vm"],job["kind"],job["payload"]
            if not isinstance(vm,str) or not re.fullmatch(r"[a-f0-9]{32}",vm):
                raise ValueError("Invalid VM identity.")
            record = self.vms.get(vm)
            if kind == "launch":
                if record:
                    if record.get("sandbox"):
                        return {"sandbox":record["sandbox"]}
                    raise ValueError("An earlier launch needs local inspection; it will not be repeated.")
                cpu, memory = payload.get("cpu"),payload.get("memory_gb")
                active = [v for v in self.vms.values() if not v.get("stopped")]
                if (not self.capacity or type(cpu) is not int or type(memory) is not int or cpu < 1 or memory < 1 or
                    len(active) >= self.capacity["slots"] or sum(v["cpu"] for v in active)+cpu > self.capacity["cpu"] or
                    sum(v["memory_gb"] for v in active)+memory > self.capacity["memory_gb"]):
                    raise ValueError("The requested VM exceeds this computer owner's contribution.")
                record = {"cpu":cpu,"memory_gb":memory,"created":int(time.time())}
                self.vms[vm] = record
                self.save()  # Unknown launch outcomes must never cause a second VM.
                result = self.call("launch",cpu=cpu,memoryGb=memory,idleSeconds=0,lifetimeSeconds=0)
                identity = result.get("sandbox")
                if not isinstance(identity,str) or not re.fullmatch(r"exe-[a-f0-9]{32}",identity):
                    raise ValueError("Yougori did not return a VM identity.")
                record["sandbox"] = identity
                self.save()
                return {"sandbox":identity}
            if not record or not record.get("sandbox") or record.get("stopped"):
                raise ValueError("This VM is not managed by this contribution.")
            if kind == "exec":
                command = payload.get("input")
                if not isinstance(command,str) or not 1 <= len(command) <= 16000:
                    raise ValueError("Invalid guest command.")
                result = self.call("exec",sandbox=record["sandbox"],input=command,timeoutSeconds=60,maxOutputBytes=65536)
                return {"output":str(result.get("output_text",""))[:65536],"exit_code":result.get("exit_code")}
            if kind == "stop":
                self.call("stop",sandbox=record["sandbox"])
                record["stopped"] = True
                self.save()
                return {}
            raise ValueError("Unsupported VM action.")

    def inventory(self):
        # Enforce our lease locally as well as in the engine. Reconcile only
        # identities owned by this connector, never adopt a host's other VMs.
        if not self.lock.acquire(blocking=False):
            return {}  # Keep inference heartbeats moving during a slow VM job.
        try:
            records = {vm:dict(v) for vm,v in self.vms.items()}
        finally:
            self.lock.release()
        active = [v for v in records.values() if v.get("sandbox") and not v.get("stopped")]
        if active:
            observed = {v["sandbox"]:v for v in self.call("status").get("sandboxes",[])}
            if self.lock.acquire(blocking=False):
                try:
                    for vm,record in records.items():
                        status = observed.get(record.get("sandbox"))
                        if status and status.get("state") == "stopped" and status.get("process") is None:
                            self.vms[vm]["stopped"] = True
                            record["stopped"] = True
                    self.save()
                finally:
                    self.lock.release()
        # Retain launch tombstones locally for idempotency, but bound heartbeats.
        # Active leases always fit the owner's maximum of 16 VM slots.
        active = [(vm,v) for vm,v in records.items() if not v.get("stopped")]
        recent = sorted(((vm,v) for vm,v in records.items() if v.get("stopped")),
                        key=lambda pair:pair[1].get("created",0),reverse=True)[:240]
        return {vm:{"sandbox":v.get("sandbox",""),"stopped":bool(v.get("stopped"))} for vm,v in active+recent}

    def stop_all(self):
        for vm, record in list(self.vms.items()):
            if record.get("sandbox") and not record.get("stopped"):
                try:
                    self.execute({"vm":vm,"kind":"stop","payload":{}})
                except (ValueError,OSError,subprocess.TimeoutExpired):
                    pass  # Keep its identity for stop/reconciliation on the next connection.
