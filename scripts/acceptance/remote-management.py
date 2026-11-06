"""Real pinned SSH management, VM execution identity and interrupted cleanup.

The home control sender remains a labelled wire fixture. These results validate
the remote product management API, not complete home-to-remote orchestration.
Only disposable engine processes created here are stopped. No server power change.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import subprocess
import time

spec = importlib.util.spec_from_file_location("receiver", Path(__file__).with_name("remote-receiver.py"))
receiver = importlib.util.module_from_spec(spec)
spec.loader.exec_module(receiver)


class Run(receiver.Run):
    def __init__(self, args):
        super().__init__(args)
        self.launch_engine = None
        if args.replace_engine_image:
            assert os.name == "posix"
            self.launch_engine = self.root / "engine-running"

    def start(self, phase=None):
        if self.launch_engine is None:
            return super().start(phase)
        engine = self.engine
        shutil.copy2(engine, self.launch_engine)
        self.engine = self.launch_engine
        try:
            return super().start(phase)
        finally:
            self.engine = engine  # SSH bridges always use the immutable candidate.

    def management_args(self):
        args = [str(self.engine), "--sandbox-remote-call", self.pipe]
        if not self.args.local_agent:
            options = {"StrictHostKeyChecking": "yes", "UserKnownHostsFile": str(self.args.known_hosts),
                       "GlobalKnownHostsFile": "none", "UpdateHostKeys": "no", "CheckHostIP": "no",
                       "VerifyHostKeyDNS": "no", "HostKeyAlgorithms": "ssh-ed25519", "BatchMode": "yes",
                       "PreferredAuthentications": "publickey", "IdentitiesOnly": "yes", "IdentityAgent": "none",
                       "ForwardAgent": "no", "ForwardX11": "no", "ClearAllForwardings": "yes",
                       "PermitLocalCommand": "no", "ProxyCommand": "none", "ProxyJump": "none",
                       "ControlMaster": "no", "ControlPath": "none", "RequestTTY": "no", "EscapeChar": "none",
                       "ConnectTimeout": "3", "ServerAliveInterval": "1", "ServerAliveCountMax": "3"}
            ssh = [str(self.args.ssh), "-F", "none", "-T", "-i", str(self.args.identity)]
            for key, value in options.items():
                ssh += ["-o", key + "=" + value]
            args = ssh + ["-p", str(self.args.port), "-l", self.args.user, "--", self.args.host, shlex.join(args)]
        env = {"SystemRoot": os.environ["SystemRoot"]} if os.name == "nt" else {}
        return args, env

    def manage(self, params, label, checked=True):
        args, env = self.management_args()
        result = subprocess.run(args, input=json.dumps({"protocol": 1, "params": params}).encode(),
                                cwd=self.root, env=env, capture_output=True, timeout=150,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            envelope = json.loads(result.stdout)
        except ValueError:
            envelope = None
        record = {"exit": result.returncode, "reply": envelope, "stderr": result.stderr.decode(errors="replace")}
        if label:
            self.write(label, record)
        if checked:
            assert result.returncode == 0 and envelope and envelope["protocol"] == 1, record
            return envelope["result"]
        assert result.returncode != 0, record
        return record

    def lose_launch_reply(self, request):
        args, env = self.management_args()
        process = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   cwd=self.root, env=env, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            process.stdin.write(json.dumps({"protocol": 1, "params": request}).encode())
            process.stdin.close()
            process.stdin = None
            intent = self.data / "sandbox-vm" / "remote-runs" / (request["run"] + ".json")
            until = time.monotonic() + 20
            while not intent.exists() and time.monotonic() < until:
                assert process.poll() is None, "management ended before an intent existed"
                time.sleep(0.005)
            assert intent.exists(), "no durable launch intent was observed"
            record = json.loads(intent.read_text())
            assert record["observation"] is None and process.poll() is None, "the reply was already produced; this is not an interrupted launch"
            process.kill()  # The fixture's exact SSH client / local bridge only.
            process.communicate(timeout=10)
            self.write("launch-caller-killed-before-observation", {"run": request["run"], "execution": record["execution"],
                       "caller_exit": process.returncode, "observation_was_absent": True})
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=10)

    def begin(self, label, lose_reply=False):
        request = {"op": "launch", "run": secrets.token_hex(32), "memory_mib": 512, "lifetime_seconds": 240}
        if lose_reply:
            self.lose_launch_reply(request)
        answer = self.manage(request, label + "-launch")
        assert answer["state"] == "ready", answer
        observation = answer["observation"]
        with self.engine.open("rb") as image:
            assert observation["engine_sha256"] == hashlib.file_digest(image, "sha256").hexdigest()
        assert observation["binding"]["run"] == request["run"]
        sandbox = observation["binding"]["execution"]
        self.sandboxes.append(sandbox)
        self.watches[sandbox] = receiver.expiry.Watched(observation["process"])
        return request, observation

    def start_command(self, binding, text, label, checked=True):
        return self.manage({"op": "start", "binding": binding, "input_hex": text.encode().hex(),
                            "output_bytes": 4096, "deadline_seconds": 15}, label, checked)

    def outcome(self, binding, command, label):
        until = time.monotonic() + 20
        while time.monotonic() < until:
            answer = self.manage({"op": "outcome", "binding": binding, "command": command}, None)
            assert answer["binding"] == binding and answer["command"] == command, answer
            if answer["state"] == "completed":
                self.write(label, answer)
                return answer["outcome"]
            assert answer["state"] == "running", answer
            time.sleep(0.05)
        raise AssertionError("A remote command did not finish within its bound")

    def run_management(self):
        self.start()
        ordinary = self.vm({"action": "launch", "memoryGb": 0.5}, "ordinary-launch")
        self.sandboxes.append(ordinary["sandbox"])
        if self.launch_engine is not None:
            replacement = self.root / "engine-replacement"
            replacement.write_bytes(b"not an executable\n")
            os.replace(replacement, self.launch_engine)
            self.write("running-image-path-replaced", {"path": str(self.launch_engine), "running_process": self.process.pid})
        request, observation = self.begin("first", lose_reply=True)
        binding = observation["binding"]
        sandbox = binding["execution"]
        repeated = self.manage(request, "lost-launch-reply-reconciled")
        assert repeated["observation"] == observation, repeated
        status = self.vm({"action": "status"}, "two-vms-only")
        assert len([s for s in status["sandboxes"] if s["process"]]) == 2
        self.manage({**request, "memory_mib": 1024}, "run-settings-change-refused", False)
        self.manage({"op": "probe", "binding": {**binding, "boot": binding["boot"] + 1}}, "wrong-boot-refused", False)
        self.manage({"op": "probe", "binding": {**binding, "run": secrets.token_hex(32)}}, "wrong-run-refused", False)
        self.start_command(binding, "printf must-not-run", "pregrant-refused", False)
        channel = receiver.Channel(self, sandbox)
        try:
            channel.grant(50)
            self.await_grant(sandbox)
            started = self.start_command(binding, "printf management-ok", "command-start")
            outcome = self.outcome(binding, started["command"], "command-outcome")
            assert outcome["exit_code"] == 0 and bytes.fromhex(outcome["output"]) == b"management-ok", outcome
            self.manage({"op": "outcome", "binding": binding, "command": started["command"]}, "claimed-result-not-replayed", False)
            started = self.start_command(binding, "sleep 12", "cancel-start")
            self.manage({"op": "cancel", "binding": binding, "command": started["command"]}, "command-cancel")
            outcome = self.outcome(binding, started["command"], "cancel-outcome")
            assert outcome["end"]["end"] == "cancelled", outcome
            ended = self.manage({"op": "stop", "binding": binding}, "explicit-stop")
            assert ended["state"] == "ended" and ended["server_power_changed"] is False, ended
            assert self.watches[sandbox].ended()
            assert self.manage(request, "ended-launch-not-revived")["state"] == "ended"
            self.start_command(binding, "printf must-not-run", "ended-command-refused", False)
        finally:
            channel.close()
        self.exec(ordinary["sandbox"], "ordinary-survives-remote-stop")
        request2, observation2 = self.begin("engine-death")
        binding2 = observation2["binding"]
        channel = receiver.Channel(self, binding2["execution"])
        try:
            channel.grant(25)
            self.await_grant(binding2["execution"])
            self.start_command(binding2, "sleep 12", "interrupted-command")
            self.process.kill()  # The Popen engine owned by this fixture only.
            self.process.wait(timeout=20)
            until = time.monotonic() + 30
            while time.monotonic() < until and not self.watches[binding2["execution"]].ended():
                time.sleep(0.1)
            assert self.watches[binding2["execution"]].ended()
        finally:
            channel.close()
        self.start()
        recovered = self.manage({"op": "reconcile", "run": request2["run"]}, "recovery-native-proof")
        assert recovered["state"] == "ended" and recovered["proof_source"] == "native_supervisor", recovered
        assert recovered["proof"]["process"] == observation2["process"], recovered
        assert self.manage(request2, "restart-cannot-recreate")["state"] == "ended"
        self.start_command(binding2, "printf must-not-run", "restart-cannot-command", False)
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        assert self.catalog("final-catalog")["catalog"]["live_leases"] == 0
        self.wait_no_qemu()
        self.stop()
        self.write("management-result", {"passed": True, "checks": ["launch-idempotency", "identity-refusal",
                   "pregrant-refusal", "start-poll-cancel", "native-stop", "ordinary-isolation", "engine-death-recovery"],
                   "home_sender": "wire_fixture", "server_power_changed": False})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("ssh", "identity", "known-hosts"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=22843)
    parser.add_argument("--user", default="root")
    parser.add_argument("--local-agent", action="store_true")
    parser.add_argument("--replace-engine-image", action="store_true")
    args = parser.parse_args()
    assert args.local_agent or (os.name == "posix" and all((args.ssh, args.identity, args.known_hosts)))
    args.reuse_fixture, args.from_case, args.model, args.fixture = False, None, args.engine.parent, args.engine
    run = Run(args)
    try:
        run.run_management()
    finally:
        if run.process and run.process.poll() is None:
            for sandbox in run.sandboxes:
                run.call("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "cleanup", checked=False)
            run.stop()
        for watch in run.watches.values():
            watch.close()
