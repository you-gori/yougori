"""Real receiver/SSH boundary checks, not full home-to-remote product acceptance.

The home sender here is an independent wire fixture with disposable authority IDs.
The receiver, its CORE-04 child leases, SSH, KVM VM and native supervisor are real.
No fake home lease is claimed as end-to-end delegation evidence. Use a disposable
engine/sshd only; --local-agent checks the same bridge and native supervisor on
Windows without claiming an SSH run. Signalled processes are opened by identity.
"""
import argparse
import hashlib
import hmac
import importlib.util
import json
import os
from pathlib import Path
import queue
import secrets
import shlex
import subprocess
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("expiry", Path(__file__).with_name("supervisor-expiry.py"))
expiry = importlib.util.module_from_spec(spec)
spec.loader.exec_module(expiry)


def digest_parts(*parts):
    result = hashlib.sha256()
    for part in parts:
        result.update(len(part).to_bytes(8, "big"))
        result.update(part)
    return result.digest()


def frame_tag(key, frame):
    body = frame["body"]
    parts = [b"yougori/remote/control-frame/v1", bytes.fromhex(frame["session"]),
             bytes.fromhex(frame["identity"]), frame["sequence"].to_bytes(8, "big"),
             body["body"].encode()]
    if body["body"] in ("grant", "renewal_request"):
        grant = body["grant"] if body["body"] == "grant" else body
        authority = grant["authority"]
        assert authority["authority"] == "lease", authority
        parts += [b"lease", authority["lease"].to_bytes(8, "big"), uuid.UUID(grant["clock"]).bytes]
        if body["body"] == "grant":
            parts += [grant["ttl_nanos"].to_bytes(8, "big")]
    else:
        assert body["body"] in ("heartbeat", "stop"), body
    return hmac.new(key, digest_parts(*parts), hashlib.sha256).hexdigest()


class Channel:
    def __init__(self, run, sandbox):
        self.run, self.sandbox = run, sandbox
        self.key, self.session, self.identity = secrets.token_bytes(32), secrets.token_hex(32), secrets.token_hex(32)
        self.clock = str(uuid.uuid4())
        self.sent = self.received = 0
        # These synthetic HOME fields deliberately do not stand for a real home VM.
        self.authority = {"authority": "lease", "lease": 301}
        self.messages = queue.Queue(maxsize=64)
        command = shlex.join([str(run.engine), "--sandbox-remote-agent", run.pipe, sandbox])
        options = {
            "StrictHostKeyChecking": "yes", "UserKnownHostsFile": str(run.args.known_hosts),
            "GlobalKnownHostsFile": "none", "UpdateHostKeys": "no", "CheckHostIP": "no",
            "VerifyHostKeyDNS": "no", "HostKeyAlgorithms": "ssh-ed25519", "BatchMode": "yes",
            "PreferredAuthentications": "publickey", "IdentitiesOnly": "yes", "IdentityAgent": "none",
            "ForwardAgent": "no", "ForwardX11": "no", "ClearAllForwardings": "yes",
            "PermitLocalCommand": "no", "ProxyCommand": "none", "ProxyJump": "none",
            "ControlMaster": "no", "ControlPath": "none", "RequestTTY": "no", "EscapeChar": "none",
            "ConnectTimeout": "3", "ServerAliveInterval": "1", "ServerAliveCountMax": "3",
        }
        if run.args.local_agent:
            argv = [str(run.engine), "--sandbox-remote-agent", run.pipe, sandbox]
        else:
            argv = [str(run.args.ssh), "-F", "none", "-T", "-i", str(run.args.identity)]
            for name, value in options.items():
                argv += ["-o", name + "=" + value]
            argv += ["-p", str(run.args.port), "-l", run.args.user, "--", run.args.host, command]
        env = {"SystemRoot": os.environ["SystemRoot"]} if os.name == "nt" else {}
        self.process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, cwd=run.root, env=env)
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        try:
            self.write(self.key)
            self.send({"body": "heartbeat"})
            assert self.receive()["body"] == "heartbeat"
        except BaseException:
            self.close()
            raise

    def write(self, payload):
        self.process.stdin.write(len(payload).to_bytes(4, "big") + payload)
        self.process.stdin.flush()

    def read(self):
        def exact(n):
            value = b""
            while len(value) < n:
                part = self.process.stdout.read(n - len(value))
                if not part:
                    raise EOFError("SSH control stdout ended")
                value += part
            return value
        try:
            while True:
                size = int.from_bytes(exact(4), "big")
                assert 0 < size <= 16384, size
                self.messages.put(json.loads(exact(size)), timeout=3)
        except Exception as error:
            try:
                self.messages.put(error, timeout=3)
            except queue.Full:
                pass

    def send(self, body):
        frame = {"session": self.session, "identity": self.identity, "sequence": self.sent, "body": body}
        sealed = {"frame": frame, "tag": frame_tag(self.key, frame)}
        self.write(json.dumps(sealed, separators=(",", ":")).encode())
        self.sent += 1
        return sealed

    def receive(self, timeout=6):
        reply = self.messages.get(timeout=timeout)
        if isinstance(reply, Exception):
            raise reply
        frame = reply["frame"]
        assert frame["session"] == self.session and frame["identity"] == self.identity
        assert frame["sequence"] == self.received
        assert hmac.compare_digest(reply["tag"], frame_tag(self.key, frame))
        self.received += 1
        return frame["body"]

    def grant(self, seconds=20):
        return self.send({"body": "grant", "grant": {"authority": self.authority,
                         "clock": self.clock, "ttl_nanos": seconds * 1_000_000_000}})

    def renewal(self):
        deadline = time.monotonic() + 25
        while time.monotonic() < deadline:
            body = self.receive()
            if body["body"] == "renewal_request":
                assert body["authority"] == self.authority and body["clock"] == self.clock
                return
        raise AssertionError("No renewal request")

    def agent(self):
        if self.run.args.local_agent:
            return expiry.Watched({"pid": self.process.pid})
        found = []
        for proc in Path("/proc").iterdir():
            if proc.name.isdigit():
                try:
                    args = (proc / "cmdline").read_bytes().split(b"\0")
                    if b"--sandbox-remote-agent" in args and self.run.pipe.encode() in args and self.sandbox.encode() in args:
                        found.append(int(proc.name))
                except (FileNotFoundError, ProcessLookupError):
                    pass
        assert len(found) == 1, found
        return expiry.Watched({"pid": found[0]})

    def close(self):
        if self.process.stdin and not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except BrokenPipeError:
                pass
        try:
            self.process.wait(timeout=6)
        except subprocess.TimeoutExpired:
            self.process.kill()  # This exact Popen client only, never a searched PID.
            self.process.wait(timeout=6)
        self.reader.join(timeout=2)
        self.process.stdout.close()
        self.process.stderr.close()


class Run(expiry.oci.Run):
    def __init__(self, args):
        self.args = args
        self.watches = {}
        super().__init__(args)

    def launch_remote(self, label):
        launched = self.vm({"action": "launch", "memoryGb": 0.5, "idleSeconds": 120,
                            "lifetimeSeconds": 180, "remoteBootstrap": True}, label + "-launch")
        self.sandboxes.append(launched["sandbox"])
        self.watches[launched["sandbox"]] = expiry.Watched(launched["status"]["process"])
        return launched

    def control(self, sandbox):
        return self.vm({"action": "remote_control", "op": "status", "sandbox": sandbox}, None)["control"]

    def await_grant(self, sandbox):
        until = time.monotonic() + 5
        while time.monotonic() < until:
            status = self.control(sandbox)
            if status.get("lease") is not None and not status["closed"]:
                return status
            time.sleep(0.05)
        raise AssertionError("Engine did not issue a remote child lease")

    def exec(self, sandbox, label, checked=True):
        answer = self.call("sandbox_vm", {"action": "exec", "sandbox": sandbox,
                           "input": "printf remote-receiver-ok", "timeoutSeconds": 5}, label, checked=checked)
        if checked:
            assert answer["result"]["exit_code"] == 0 and answer["result"]["output_text"] == "remote-receiver-ok"
        return answer

    def ended(self, launch, label, timeout=30):
        started = time.monotonic()
        watch = self.watches[launch["sandbox"]]
        while time.monotonic() - started < timeout:
            status = self.control(launch["sandbox"])
            if status["closed"] and watch.ended():
                denied = self.exec(launch["sandbox"], label + "-refusal", False)
                assert denied["ok"] is False, denied
                self.write(label, {"closed": status, "observed_seconds": time.monotonic() - started,
                                   "process": watch.identity, "process_ended": watch.ended()})
                return
            time.sleep(0.1)
        raise AssertionError("Remote VM did not end within its bound")

    def run_receiver(self):
        self.start()
        ordinary = self.vm({"action": "launch", "memoryGb": 0.5,
                            "idleSeconds": 300, "lifetimeSeconds": 600}, "ordinary-launch")
        self.sandboxes.append(ordinary["sandbox"])
        self.exec(ordinary["sandbox"], "ordinary-positive")
        launch = self.launch_remote("renew-replay")
        sandbox = launch["sandbox"]
        refused = self.exec(sandbox, "bootstrap-work-refused", False)
        assert refused["ok"] is False and "delegated" in str(refused).lower(), refused
        channel = Channel(self, sandbox)
        try:
            channel.grant()
            first = self.await_grant(sandbox)
            self.exec(sandbox, "delegated-command")
            channel.renewal()
            repeated = channel.grant()
            until = time.monotonic() + 4
            while time.monotonic() < until:
                next_grant = self.control(sandbox)
                if next_grant["lease"] != first["lease"]:
                    break
                time.sleep(0.05)
            assert next_grant["lease"] != first["lease"] and next_grant["remaining_ms"] > 12_000
            self.write("renewed", {"before": first, "after": next_grant})
            self.exec(sandbox, "renewed-command")
            # Same authenticated sequence again must close the entire remote boot.
            channel.write(json.dumps(repeated).encode())
            self.ended(launch, "replay-ended")
        finally:
            channel.close()
        self.exec(ordinary["sandbox"], "ordinary-after-remote-replay")

        launch = self.launch_remote("paused-agent")
        channel = Channel(self, launch["sandbox"])
        try:
            channel.grant()
            self.await_grant(launch["sandbox"])
            channel.renewal()
            agent = channel.agent()
            try:
                agent.pause()
                channel.grant(60)  # Queued on SSH while this exact bridge is stopped.
                self.ended(launch, "queued-renewal-expired")
            finally:
                agent.close()
            time.sleep(0.5)
            assert self.control(launch["sandbox"])["closed"]
            assert self.exec(launch["sandbox"], "late-frame-cannot-revive", False)["ok"] is False
        finally:
            channel.close()

        launch = self.launch_remote("lost-channel")
        channel = Channel(self, launch["sandbox"])
        channel.grant()
        self.await_grant(launch["sandbox"])
        self.exec(launch["sandbox"], "before-disconnect")
        channel.close()
        self.ended(launch, "disconnect-ended")
        self.exec(ordinary["sandbox"], "ordinary-after-disconnect")

        for sandbox in self.sandboxes:
            self.call("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "owned-cleanup", checked=False)
        self.wait_no_qemu()
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        assert self.catalog("final-catalog")["catalog"]["live_leases"] == 0
        self.stop()
        self.write("PASS", {"receiver_over_real_ssh": not self.args.local_agent, "real_remote_vm": True,
                            "ordinary_vm_preserved": True, "grant_required": True,
                            "renewal_replay_pause_loss": True, "empty_final_accounting": True,
                            "home_sender_is_wire_fixture": True, "full_home_product_validated": False})

    def run_paused_engine(self, baseline):
        self.start()
        launch = self.launch_remote("engine-pause")
        channel = Channel(self, launch["sandbox"])
        engine = expiry.Watched({"pid": self.process.pid})
        try:
            if self.args.immediate:
                # Establish the periodic pump's old bootstrap deadline, then
                # grant and pause before its next two-second tick can help.
                until = time.monotonic() + 6
                while time.monotonic() < until:
                    supervisor = self.vm({"action": "status"}, None)["supervisor"]
                    age = supervisor.get("heartbeat_age_ms")
                    if age is not None and age < 150:
                        break
                    time.sleep(0.03)
                else:
                    raise AssertionError("No supervisor heartbeat barrier")
                barrier = time.monotonic()
            channel.grant(15)
            self.await_grant(launch["sandbox"])
            self.exec(launch["sandbox"], "before-engine-pause")
            if self.args.immediate:
                assert time.monotonic() - barrier < 1, "Test missed the immediate-pause window"
            else:
                time.sleep(3)
            terms = self.control(launch["sandbox"])
            assert terms["remaining_ms"] > 5_000
            engine.pause()
            until = time.monotonic() + terms["remaining_ms"] / 1000 + 2
            watch = self.watches[launch["sandbox"]]
            while time.monotonic() < until and not watch.ended():
                time.sleep(0.05)
            ended = watch.ended()
            self.write("paused-engine-bound", {"baseline": baseline, "immediate": self.args.immediate,
                       "terms_before_pause": terms,
                       "vm_ended": ended, "engine": engine.identity, "vm": watch.identity})
            assert ended != baseline, "native supervisor did not respect the delegated bound"
        finally:
            engine.close()
            channel.close()
        self.ended(launch, "after-engine-resume")
        self.vm({"action": "stop", "sandbox": launch["sandbox"]}, "owned-cleanup")
        self.wait_no_qemu()
        records = []
        for journal in (self.data / "sandbox-vm" / "supervisor").glob("*.jsonl"):
            records.extend(json.loads(line) for line in journal.read_text().splitlines())
        self.write("native-supervisor-journal", records)
        if not baseline:
            assert any(r.get("event", {}).get("kind") == "ended" and
                       r["event"]["end"]["sandbox"] == launch["sandbox"] and
                       r["event"]["end"]["process"] == watch.identity and
                       r["event"]["end"]["cause"] == "renewal_limit" and
                       r["event"]["end"]["kill_rounds"] >= 1 for r in records), records
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        self.stop()
        self.write("paused-engine-result", {"passed": True, "baseline_defect_reproduced": baseline})

    def run_guard_retention(self, baseline):
        self.start()
        launch = self.launch_remote("guard-retention")
        channel = Channel(self, launch["sandbox"])
        engine = expiry.Watched({"pid": self.process.pid})
        supervisor = expiry.Watched(launch["supervisor"]["supervisor"])
        vm = self.watches[launch["sandbox"]]
        try:
            channel.grant(50)
            self.await_grant(launch["sandbox"])
            self.exec(launch["sandbox"], "before-guard-pause")
            supervisor.pause()
            # Exceeds the native client's 10-second request wait and the old
            # replacement kill bound. No process lookup or name-based kill.
            time.sleep(20)
            alive = not supervisor.ended()
            self.write("guard-after-timeout", {"baseline": baseline, "original_guard_alive": alive,
                       "supervisor": supervisor.identity, "vm": vm.identity})
            assert alive != baseline, "The live independent guard was removed after an IPC timeout"
            if not baseline:
                status = self.vm({"action": "status"}, "after-guard-timeout")["supervisor"]
                assert status["control_connected"] is False and status["running"] is True, status
                terms = self.control(launch["sandbox"])
                assert terms["remaining_ms"] > 5_000
                engine.pause()
                time.sleep(terms["remaining_ms"] / 1000 + 1)
                assert not vm.ended(), "The VM ended before the independent guard resumed"
                supervisor.resume()
                until = time.monotonic() + 4
                while time.monotonic() < until and not vm.ended():
                    time.sleep(0.05)
                self.write("retained-guard-enforced", {"process_ended": vm.ended(), "process": vm.identity})
                assert vm.ended(), "The retained guard failed to enforce its old deadline"
        finally:
            engine.close()
            supervisor.close()
            channel.close()
        self.ended(launch, "after-guard-recovery")
        self.vm({"action": "stop", "sandbox": launch["sandbox"]}, "owned-cleanup")
        self.wait_no_qemu()
        records = []
        for journal in (self.data / "sandbox-vm" / "supervisor").glob("*.jsonl"):
            records.extend(json.loads(line) for line in journal.read_text().splitlines())
        self.write("guard-journal", records)
        if not baseline:
            assert any(r.get("event", {}).get("kind") == "ended" and
                       r["event"]["end"]["process"] == vm.identity and
                       r["event"]["end"]["cause"] == "renewal_limit" and
                       r["event"]["end"]["kill_rounds"] >= 1 for r in records), records
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        self.stop()
        self.write("guard-retention-result", {"passed": True, "baseline_defect_reproduced": baseline})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument("--" + name, type=Path, required=True)
    for name in ("ssh", "identity", "known-hosts"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=22843)
    parser.add_argument("--user", default="root")
    parser.add_argument("--paused-engine", action="store_true")
    parser.add_argument("--baseline", action="store_true")
    parser.add_argument("--local-agent", action="store_true")
    parser.add_argument("--immediate", action="store_true")
    parser.add_argument("--guard-retention", action="store_true")
    args = parser.parse_args()
    assert args.local_agent or (os.name == "posix" and Path("/proc").is_dir() and
                               all((args.ssh, args.identity, args.known_hosts)))
    args.reuse_fixture, args.from_case, args.model, args.fixture = False, None, args.engine.parent, args.engine
    run = Run(args)
    try:
        if args.guard_retention:
            run.run_guard_retention(args.baseline)
        elif args.paused_engine:
            run.run_paused_engine(args.baseline)
        else:
            assert not args.baseline
            run.run_receiver()
    finally:
        if run.process and run.process.poll() is None:
            for sandbox in run.sandboxes:
                run.call("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "cleanup", checked=False)
            run.stop()
        for watch in run.watches.values():
            watch.close()
