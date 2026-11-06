"""Generated template -> real parent VM -> owned SSH -> real remote VM.

Uses disposable Windows/Linux engines and an existing key-only loopback server.
Kills only its own home engine after a durable template launch intent, then checks
that recovery/retry observes that original effect rather than creating another VM.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import time

spec = importlib.util.spec_from_file_location("home", Path(__file__).with_name("remote-home.py"))
home = importlib.util.module_from_spec(spec)
spec.loader.exec_module(home)


class Run(home.Home):
    def archive_live_probe(self, run):
        pass

    def archive_terminal(self, run):
        pass

    def write(self, name, body):
        # Setup outputs use "key" for a public output name, not a credential.
        # Preserve those names while removing actual credential-bearing fields.
        def redact(value):
            if isinstance(value, dict):
                return {key: "[redacted]" if isinstance(item, str) and key.lower().replace("_", "") in
                        {"apikey", "token", "secret", "authorization", "password"} else redact(item)
                        for key, item in value.items()}
            if isinstance(value, list):
                return [redact(item) for item in value]
            return value
        home.expiry.oci.base.Run.write(self, name, redact(body))

    def setup(self, name):
        listed = self.result("setup_list", {}, "list-setups")
        rows = listed if isinstance(listed, list) else listed["setups"]
        matches = [row for row in rows if row["name"] == name]
        assert len(matches) == 1, matches
        return matches[0]["setupId"]

    def records(self):
        result = {}
        for kind in ("runs", "history"):
            folder = self.data / "sandbox-vm" / "remote-home" / kind
            for path in folder.glob("*.json"):
                body = json.loads(path.read_text(encoding="utf-8"))
                assert body["run"] not in result or result[body["run"]] == body, "Conflicting retained records"
                result[body["run"]] = body
        return result

    def run_template(self, args, server):
        self.start()
        info = server.info
        profile = {"name": "Disposable template SSH", "vendor": "other", "host": "127.0.0.1",
                   "port": args.port, "username": "root", "identityFile": str(args.identity.resolve()),
                   "hostKey": info["public_key"]}
        added = self.result("add_cloud_environment", {"request": profile}, "save-owned-profile")
        connection = next(e["id"] for e in added["environments"] if e["name"] == profile["name"])
        self.remote("trust", "explicit-owner-trust", connection=connection, accept_host_key=info["pin"])
        draft = {"name": "Remote box", "summary": "An explicitly owned remote VM with a local parent.",
                 "capabilities": {
            "sandbox.vm": {"selected": True, "mode": "required", "runnerEditable": True,
                "settings": {"vm_memory_gb": 0.5, "vm_lifetime_minutes": 60}},
            "sandbox.remote": {"selected": True, "mode": "required", "runnerEditable": True,
                "settings": {"remote_connection": connection, "remote_program": info["program"],
                    "remote_endpoint": info["endpoint"], "remote_engine_sha256": info["engine_sha256"],
                    "remote_memory_gb": 0.5, "remote_lifetime_minutes": 5}}}}
        made = self.result("setup_validate", {"draft": draft}, "generate-remote-template")
        package = self.root / "template"
        package.mkdir()
        files = {"yougori-template.yaml": made["manifest"], "yougori.yaml": made["project"], **made.get("files", {})}
        for name, body in files.items():
            assert Path(name).name == name, name
            (package / name).write_text(body, encoding="utf-8", newline="\n")
        self.command("template", "check", str(package), label="template-check")
        dry = self.command("template", "run", str(package), "--name", "remote-box", "--dry-run", label="template-review")
        review = json.dumps(dry)
        assert info["engine_sha256"] in review and connection in review, dry
        assert "external" in review.lower() and "parent" in review.lower(), dry
        assert not self.records(), "Review created a remote intent"
        assert not self.vm({"action": "status"}, "no-vm-before-confirmation")["sandboxes"]

        self.command("template", "run", str(package), "--name", "remote-box", "--yes", label="template-run")
        setup = self.setup("remote-box")
        details = self.result("setup_get", {"setupId": setup}, "running-template-details")
        outputs = {o["key"]: o["value"] for o in details["outputs"]}
        parent, run = outputs["vm_sandbox"], outputs["remote_vm"]
        self.sandboxes.append(parent)
        ready = self.phase(run, {"ready"}, "template-remote-ready")
        assert ready["parent"] == parent and ready["request_key"], ready
        assert ready["observation"]["accelerator"] == "kvm", ready
        server.call("watch", identity=ready["observation"]["process"])
        self.archive_live_probe(run)
        work = self.work(run, "printf 'template-real-vm\\n'; uname -s", "template-command")
        outcome = self.outcome(run, work["command"], "template-command-result")
        assert outcome["exit_code"] == 0 and b"template-real-vm\nLinux" in bytes.fromhex(outcome["output"])
        params = {**ready["launch"], "request_key": ready["request_key"]}
        repeated = self.remote("launch", "same-request-adopted", **params)
        assert repeated["run"] == run and repeated["observation"] == ready["observation"]
        assert not self.remote("launch", "changed-request-refused", False,
                               **{**params, "program": "/different-engine"})["ok"]
        assert len(self.records()) == 1, self.records()

        self.command("template", "stop", setup, label="template-stop")
        self.phase(run, {"ended"}, "template-stop-confirmed")
        self.wait_native(server, ready["observation"], "template-stop-native-end")
        self.wait_no_qemu()
        self.archive_terminal(run)
        self.command("template", "start", setup, label="template-start-again")
        details = self.result("setup_get", {"setupId": setup}, "restarted-template-details")
        outputs = {o["key"]: o["value"] for o in details["outputs"]}
        assert outputs["vm_sandbox"] != parent and outputs["remote_vm"] != run, outputs
        parent, run = outputs["vm_sandbox"], outputs["remote_vm"]
        self.sandboxes.append(parent)
        ready = self.phase(run, {"ready"}, "template-restarted-remote-ready")
        assert ready["parent"] == parent and len(self.records()) == 2, ready
        assert server.call("watch", identity=ready["observation"]["process"])["ended"] is False
        work = self.work(run, "printf restarted", "restarted-template-command")
        assert bytes.fromhex(self.outcome(run, work["command"], "restarted-template-result")["output"]) == b"restarted"

        previous = ready
        self.command("template", "configure", setup, "--input", "remote_memory_gb=0.625", "--yes", label="template-update-remote-memory")
        details = self.result("setup_get", {"setupId": setup}, "updated-template-details")
        outputs = {o["key"]: o["value"] for o in details["outputs"]}
        assert outputs["vm_sandbox"] == parent and outputs["remote_vm"] != run, outputs
        self.phase(run, {"ended"}, "update-ended-previous-run")
        self.wait_native(server, previous["observation"], "update-previous-native-end")
        self.archive_terminal(run)
        run = outputs["remote_vm"]
        ready = self.phase(run, {"ready"}, "updated-remote-ready")
        assert ready["launch"]["memory_mib"] == 640 and len(self.records()) == 3, ready
        assert server.call("watch", identity=ready["observation"]["process"])["ended"] is False
        work = self.work(run, "printf updated", "updated-template-command")
        assert bytes.fromhex(self.outcome(run, work["command"], "updated-template-result")["output"]) == b"updated"
        self.command("template", "rm", setup, "--yes", label="template-remove")
        ended = self.phase(run, {"ended"}, "template-exact-end")
        assert ended["receipt"]["proof"]["process"] == ready["observation"]["process"]
        assert ended["receipt"]["server_power_changed"] is False
        self.wait_native(server, ready["observation"], "template-native-ended")
        self.wait_no_qemu()
        assert not self.result("model_ledger", {}, "template-remove-ledger")["open"]
        assert not server.call("clean")["ledger"]["open"]
        self.archive_terminal(run)

        # Interrupt the actual setup operation after its durable effect identity
        # exists but before its remote step returns a receipt to the setup engine.
        before = set(self.records())
        with (self.root / "interrupted-cli.stdout").open("w", encoding="utf-8") as out, \
             (self.root / "interrupted-cli.stderr").open("w", encoding="utf-8") as err:
            cli = subprocess.Popen([str(self.cli), "template", "run", str(package), "--name", "interrupted-box", "--yes"],
                cwd=self.root, env=self.env, stdout=out, stderr=err,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            until = time.monotonic() + 120
            interrupted = None
            while time.monotonic() < until:
                fresh = [value for key, value in self.records().items() if key not in before]
                if fresh:
                    assert len(fresh) == 1 and fresh[0]["phase"] == "starting", fresh
                    interrupted = fresh[0]
                    self.process.kill()
                    self.process.wait(timeout=20)
                    break
                assert cli.poll() is None, "Template CLI ended before the remote intent"
                time.sleep(0.01)
            assert interrupted is not None, "No remote template intent appeared"
            cli.wait(timeout=60)
        self.write("killed-after-durable-intent", interrupted)
        self.start()
        run = interrupted["run"]
        until = time.monotonic() + 80
        while time.monotonic() < until:
            recovered = self.records()[run]
            if recovered["phase"] in ("ended", "creation_cancelled"):
                break
            time.sleep(0.3)
        assert recovered["phase"] in ("ended", "creation_cancelled"), recovered
        self.write("original-intent-recovered", recovered)
        self.archive_terminal(run)
        setup = self.setup("interrupted-box")
        self.result("setup_get", {"setupId": setup}, "interrupted-details-before-continue")
        self.command("template", "continue", setup, label="continue-original-operation")
        details = self.result("setup_get", {"setupId": setup}, "interrupted-details-after-continue")
        current = self.records()
        assert set(current) == before | {run}, "Continue duplicated the remote effect"
        original = self.remote("status", "recovered-original-view", run=run)
        repeated = self.remote("launch", "terminal-retry-no-new-authority",
                               **original["launch"], request_key=original["request_key"])
        assert repeated["run"] == run and repeated["phase"] == original["phase"]
        self.command("template", "rm", setup, "--yes", label="interrupted-template-remove")
        self.wait_no_qemu()
        assert not self.result("model_ledger", {}, "final-home-ledger")["open"]
        assert not server.call("clean")["ledger"]["open"]
        self.stop()
        self.write("result", {"passed": True, "checks": ["generated-visible-capability", "template-check",
            "review-no-effects", "parent-before-remote", "real-guest-command", "same-request-idempotent",
            "changed-request-refused", "stop-start-fresh-authority", "update-exact-old-cleanup", "exact-remove", "external-billing-unknown", "actual-engine-interruption",
            "startup-grant-free-cleanup", "continue-no-duplicate", "terminal-retry-no-new-authority", "zero-ledgers"]})


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    home.arguments(parser)
    parser.add_argument("--distro", required=True)
    for name in ("server-script", "server-root", "server-engine", "server-cli", "server-runtime", "server-host-public-key"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--port", type=int, default=22843)
    args = parser.parse_args()
    assert os.name == "nt"
    args.reuse_fixture, args.from_case, args.model, args.fixture = False, None, args.engine.parent, args.engine
    run, remote = Run(args), None
    try:
        remote = home.Server(args, run.root)
        run.run_template(args, remote)
    finally:
        if run.process and run.process.poll() is None:
            status = run.call("sandbox_vm", {"action": "status"}, "fixture-cleanup-status", checked=False)
            for vm in status.get("result", {}).get("sandboxes", []):
                run.call("sandbox_vm", {"action": "stop", "sandbox": vm["sandbox"]}, "fixture-cleanup-vm", checked=False)
            run.stop()
        if remote:
            remote.close()
