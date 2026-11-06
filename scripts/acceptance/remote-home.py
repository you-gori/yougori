"""Real home engine -> owner-pinned SSH -> real remote engine / hardware VM.

No control-frame fixture: the product worker owns the real parent delegation.
Uses only two disposable engines, an already prepared key-only loopback SSH
server, and their existing runtimes. Does not install or change host policy.
"""
import argparse
import base64
import contextlib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import queue
import secrets
import subprocess
import sys
import threading
import time

spec = importlib.util.spec_from_file_location("expiry", Path(__file__).with_name("supervisor-expiry.py"))
expiry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(expiry)


def arguments(parser):
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument("--" + name, type=Path, required=True)


def make_run(args):
    args.reuse_fixture, args.from_case = False, None
    args.model, args.fixture = args.engine.parent, args.engine
    return expiry.oci.Run(args)


def server(args, hooks=None):
    # Keep this control stream JSON-only. Run.write still records all evidence.
    output = sys.stdout
    with contextlib.redirect_stdout(sys.stderr):
        run = make_run(args)
        watches = {}
        try:
            run.start()
            # Existing cloud profiles store a bare type/blob pair. The optional
            # ssh-keygen comment is not part of the key or its fingerprint.
            host_public_key = hooks.start(run) if hooks else args.host_public_key
            key = " ".join(host_public_key.read_text(encoding="utf-8").split()[:2])
            public_blob = base64.b64decode(key.split()[1], validate=True)
            pin = "SHA256:" + base64.b64encode(hashlib.sha256(public_blob).digest()).decode().rstrip("=")
            print(json.dumps({"ready": True, "endpoint": run.pipe, "program": str(run.engine),
                              "engine_sha256": expiry.oci.base.digest(run.engine), "public_key": key, "pin": pin}), file=output, flush=True)
            for line in sys.stdin:
                request = json.loads(line)
                try:
                    op = request["op"]
                    if op == "vm":
                        result = run.vm(request["params"], request["label"])
                    elif op == "ledger":
                        result = run.result("model_ledger", {}, request["label"])
                    elif op == "kill":
                        run.process.kill()  # Exact Popen process owned by this fixture.
                        run.process.wait(timeout=20)
                        result = {"killed": True}
                    elif op == "restart":
                        run.start()
                        result = {"started": True}
                    elif op == "watch":
                        identity = request["identity"]
                        key = str(identity)
                        if key not in watches:
                            watches[key] = expiry.Watched(identity)
                        result = {"ended": watches[key].ended()}
                    elif op == "clean":
                        run.wait_no_qemu()
                        result = {"no_owned_qemu": True, "ledger": run.result("model_ledger", {}, "final-ledger")}
                    elif op == "quit":
                        run.stop()
                        print(json.dumps({"ok": True, "result": {"quit": True}}), file=output, flush=True)
                        break
                    elif hooks and op in hooks.operations:
                        result = hooks.call(request)
                    else:
                        raise ValueError("Unknown fixture operation")
                    print(json.dumps({"ok": True, "result": result}), file=output, flush=True)
                except Exception as error:
                    print(json.dumps({"ok": False, "error": str(error)}), file=output, flush=True)
        finally:
            try:
                for watch in watches.values():
                    watch.close()
                if run.process and run.process.poll() is None:
                    status = run.call("sandbox_vm", {"action": "status"}, "cleanup-status", checked=False)
                    for vm in status.get("result", {}).get("sandboxes", []):
                        run.call("sandbox_vm", {"action": "stop", "sandbox": vm["sandbox"]}, "fixture-cleanup", checked=False)
                    run.stop()
            finally:
                if hooks:
                    hooks.close()


class Server:
    def __init__(self, args, root):
        self.log = (root / "server-controller.log").open("w", encoding="utf-8")
        self.process = subprocess.Popen([
            "wsl.exe", "-d", args.distro, "-u", "root", "--", "python3", "-u", args.server_script,
            "--server", "--root", args.server_root, "--engine", args.server_engine, "--cli", args.server_cli,
            "--runtime", args.server_runtime, "--host-public-key", args.server_host_public_key, "--port", str(args.port),
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self.log, text=True, encoding="utf-8",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        self.lines = queue.Queue()
        threading.Thread(target=self.read_lines, daemon=True).start()
        self.info = self.read(150)
        assert self.info["ready"], self.info

    def read_lines(self):
        for line in self.process.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def read(self, timeout=180):
        line = self.lines.get(timeout=timeout)
        assert line is not None, "Disposable Linux controller exited; inspect its log"
        return json.loads(line)

    def call(self, op, **params):
        self.process.stdin.write(json.dumps({"op": op, **params}) + "\n")
        self.process.stdin.flush()
        answer = self.read()
        assert answer["ok"], answer
        return answer["result"]

    def close(self):
        if self.process.poll() is None:
            self.call("quit")
            self.process.wait(timeout=60)
        self.log.close()


class Home(expiry.oci.Run):
    def remote(self, operation, label, checked=True, **params):
        result = self.call("sandbox_vm", {"action": "remote", "operation": operation, **params}, label, checked=checked)
        return result["result"] if checked else result

    def phase(self, run, phases, label, timeout=60):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            view = self.remote("status", None, run=run)
            if view["phase"] in phases:
                self.write(label, view)
                return view
            assert view["phase"] not in ("unconfirmed", "ended", "creation_cancelled"), view
            time.sleep(0.3)
        raise AssertionError(("remote phase timeout", view))

    def outcome(self, run, command, label, timeout=55):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            result = self.remote("outcome", None, run=run, command=command)
            if result["state"] == "completed":
                assert result["source"] == "guest_report", result
                self.write(label, result)
                return result["outcome"]
            time.sleep(0.5)
        raise AssertionError("Remote command did not complete")

    def parent(self):
        parent = self.vm({"action": "launch", "memoryGb": 0.5, "lifetimeSeconds": 600}, "real-home-parent")
        self.sandboxes.append(parent["sandbox"])
        return parent["sandbox"]

    def work(self, run, text, label):
        return self.remote("start", label, run=run, input_hex=text.encode().hex(), timeout_seconds=90)

    def wait_native(self, server, observed, label, timeout=45):
        until = time.monotonic() + timeout
        while time.monotonic() < until:
            if server.call("watch", identity=observed["process"])["ended"]:
                self.write(label, {"ended": True, "identity": observed["process"]})
                return
            time.sleep(0.3)
        raise AssertionError("Exact remote VM survived its authority")

    def run_home(self, args, server):
        self.start()
        info = server.info
        profile = {"name": "Disposable remote VM host", "vendor": "other", "host": "127.0.0.1",
                   "port": args.port, "username": "root", "identityFile": str(args.identity.resolve()), "hostKey": info["public_key"]}
        added = self.result("add_cloud_environment", {"request": profile}, "saved-owned-ssh-profile")
        # The add method returns the updated platform state.
        environment = next(e for e in added["environments"] if e["name"] == profile["name"])
        parent = self.parent()
        launch = {"connection": environment["id"], "parent": parent, "program": info["program"],
                  "endpoint": info["endpoint"], "engine_sha256": info["engine_sha256"], "memory_mib": 512, "lifetime_seconds": 300}
        assert not self.remote("launch", "missing-owner-pin", False, **launch)["ok"]
        assert not self.remote("launch", "wrong-owner-pin", False, **launch, accept_host_key="SHA256:wrong")["ok"]
        ordinary = server.call("vm", label="ordinary-remote-vm", params={"action": "launch", "memoryGb": 0.5})
        launched = self.remote("launch", "home-launch", **launch, accept_host_key=info["pin"])
        run = launched["run"]
        ready = self.phase(run, {"ready"}, "ready-after-real-delegation")
        observed = ready["observation"]
        assert observed["engine_sha256"] == info["engine_sha256"] and observed["accelerator"] == "kvm"
        self.write("home-ledger-with-parent", self.result("model_ledger", {}, "home-accounting"))
        server.call("watch", identity=observed["process"])
        started = self.work(run, "printf 'inside-remote-vm\\n'; uname -s", "real-remote-command")
        result = self.outcome(run, started["command"], "real-remote-output")
        assert result["exit_code"] == 0 and b"inside-remote-vm\nLinux" in bytes.fromhex(result["output"])
        started = self.work(run, "sleep 36; printf renewed", "command-across-renewal")
        result = self.outcome(run, started["command"], "renewed-output")
        assert result["exit_code"] == 0 and b"renewed" in bytes.fromhex(result["output"])
        started = self.work(run, "sleep 60", "cancel-start")
        self.remote("cancel", "cancel-command", run=run, command=started["command"])
        self.outcome(run, started["command"], "cancel-outcome")
        self.remote("stop", "request-stop", run=run)
        ended = self.phase(run, {"ended"}, "confirmed-native-stop")
        assert ended["receipt"]["proof"]["process"] == observed["process"]
        assert ended["receipt"]["server_power_changed"] is False
        isolated = server.call("vm", label="ordinary-survived", params={"action": "exec", "sandbox": ordinary["sandbox"], "input": "printf ordinary-survived"})
        assert "ordinary-survived" in isolated["output_text"]

        run = self.remote("launch", "parent-revoke-launch", **launch)["run"]
        ready = self.phase(run, {"ready"}, "parent-revoke-ready")
        server.call("watch", identity=ready["observation"]["process"])
        self.vm({"action": "revoke", "sandbox": parent, "reason": "user_requested"}, "revoke-real-parent")
        self.phase(run, {"ended"}, "parent-revoke-cleaned")
        self.wait_native(server, ready["observation"], "parent-revoke-native-end")
        assert not self.remote("start", "ended-run-refuses-work", False, run=run, input_hex=b"printf must-not-run".hex())["ok"]

        launch["parent"] = self.parent()
        run = self.remote("launch", "home-crash-launch", **launch)["run"]
        ready = self.phase(run, {"ready"}, "home-crash-ready")
        server.call("watch", identity=ready["observation"]["process"])
        self.work(run, "sleep 60", "home-crash-inflight")
        self.process.kill(); self.process.wait(timeout=20)
        self.wait_native(server, ready["observation"], "home-crash-remote-ended")
        self.start()
        # Observe durable recovery before asking the sandbox API. Startup itself
        # must perform reconciliation; a status request must not be the trigger.
        journal = self.data / "sandbox-vm" / "remote-home" / "runs" / f"{run}.json"
        until = time.monotonic() + 60
        while time.monotonic() < until:
            recovered = json.loads(journal.read_text(encoding="utf-8"))
            if recovered["phase"] == "ended": break
            time.sleep(0.3)
        assert recovered["phase"] == "ended", recovered
        self.write("startup-reconciled-without-status", {"run": run, "phase": recovered["phase"], "receipt": recovered["receipt"]})
        assert recovered["receipt"]["proof"]["process"] == ready["observation"]["process"]
        launch["parent"] = self.parent()
        assert not self.remote("launch", "restart-does-not-forgive-trust", False, **launch)["ok"]
        run = self.remote("launch", "owner-reconfirmed-after-recovery", **launch, accept_host_key=info["pin"])["run"]
        ready = self.phase(run, {"ready"}, "remote-crash-ready")
        server.call("watch", identity=ready["observation"]["process"])
        server.call("kill")
        self.wait_native(server, ready["observation"], "remote-engine-death-native-end")
        self.phase(run, {"unconfirmed"}, "remote-down-cleanup-unconfirmed", timeout=55)
        server.call("restart")
        self.remote("reconcile", "retry-exact-cleanup", run=run)
        ended = self.phase(run, {"ended"}, "remote-restart-native-proof")
        assert ended["receipt"]["proof_source"] == "native_supervisor"

        nonce = secrets.token_hex(32)
        receipt = server.call("vm", label="cancel-before-launch", params={"action": "remote_manage", "op": "reconcile", "run": nonce})
        assert receipt["state"] == "creation_cancelled"
        late = server.call("vm", label="late-launch-cancelled", params={"action": "remote_manage", "op": "launch", "run": nonce, "memory_mib": 512, "lifetime_seconds": 60})
        assert late == receipt
        server.call("kill"); server.call("restart")
        assert server.call("vm", label="cancel-survives-restart", params={"action": "remote_manage", "op": "launch", "run": nonce, "memory_mib": 512, "lifetime_seconds": 60}) == receipt
        for sandbox in self.sandboxes:
            self.call("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "stop-home-parent", checked=False)
        self.wait_no_qemu()
        assert not self.result("model_ledger", {}, "final-home-ledger")["open"]
        assert not server.call("clean")["ledger"]["open"]
        self.stop()
        self.write("home-result", {"passed": True, "home_sender": "production_engine_with_real_parent",
            "checks": ["explicit-owner-pin", "actual-runtime-admission", "real-command", "renewal", "cancel", "exact-stop",
                       "ordinary-isolation", "parent-revocation", "home-death", "startup-recovery", "remote-death",
                       "native-reconcile", "late-launch-cancellation", "restart-no-replay", "zero-accounting"],
            "server_power_changed": False})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    arguments(parser)
    parser.add_argument("--server", action="store_true")
    parser.add_argument("--host-public-key", type=Path)
    parser.add_argument("--distro")
    for name in ("server-script", "server-root", "server-engine", "server-cli", "server-runtime", "server-host-public-key"):
        parser.add_argument("--" + name)
    parser.add_argument("--identity", type=Path)
    parser.add_argument("--port", type=int, default=22843)
    args = parser.parse_args()
    if args.server:
        assert os.name == "posix" and args.host_public_key
        server(args)
    else:
        assert os.name == "nt" and args.identity and args.distro
        args.reuse_fixture, args.from_case, args.model, args.fixture = False, None, args.engine.parent, args.engine
        home = Home(args)
        remote = None
        try:
            remote = Server(args, home.root)
            home.run_home(args, remote)
        finally:
            if home.process and home.process.poll() is None:
                for sandbox in home.sandboxes:
                    home.call("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "fixture-parent-cleanup", checked=False)
                home.stop()
            if remote:
                remote.close()
