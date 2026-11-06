"""Exercise host-file permissions from a real guest, against disposable host files only."""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess

spec = importlib.util.spec_from_file_location("vm_memory", Path(__file__).with_name("vm-guest-memory.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Run(base.Run):
    def owner(self, operation, **fields):
        return self.result("sandbox_vm", dict(action="host_access", sandbox=self.vm,
                           operation=operation, **fields), "owner-" + operation)

    def guest(self, operation, **fields):
        payload = json.dumps(dict(operation=operation, **fields), separators=(",", ":"))
        report = self.result("sandbox_vm", dict(action="exec", sandbox=self.vm,
                             input="wget -qO- --post-data=" + shlex.quote(payload) + " http://host.yougori/",
                             timeoutSeconds=30), "guest-" + operation)
        assert report["exit_code"] == 0, report
        return json.loads(report["output_text"])

    def grant(self, path, mode, duration):
        asked = self.guest("request", path=path, mode=mode)
        assert asked["ok"], asked
        request = asked["result"]["id"]
        self.owner("approve", request=request, mode=mode, duration=duration)
        return self.guest("request_status", request=request)["result"]["grant"]

    def run(self):
        host = self.root / "host-files"
        host.mkdir()
        leaf = host / "read-me.txt"
        leaf.write_text("disposable-private-content", encoding="utf-8")
        target = leaf.as_posix()
        self.start()
        launch = self.result("sandbox_vm", {"action": "launch", "memoryGb": 1}, "launch")
        self.vm = launch["sandbox"]
        self.sandboxes.append(self.vm)
        # No settings or owner grants: every guest operation is refused.
        assert not self.guest("tree")["ok"]
        assert not self.guest("request", path=target, mode="read")["ok"]
        assert not self.guest("read", path=target, grant="invented")["ok"]
        self.owner("policy", policy=dict(treeVisible=True, askForAccess=False))
        tree = self.guest("tree", path=host.as_posix())
        assert tree["ok"] and any(e["name"] == leaf.name for e in tree["result"]["entries"]), tree
        assert "disposable-private-content" not in json.dumps(tree)
        assert not self.guest("request", path=target, mode="read")["ok"]
        self.owner("policy", policy=dict(treeVisible=False, askForAccess=True))
        assert not self.guest("tree", path=host.as_posix())["ok"]
        once = self.grant(target, "read", "once")
        read = self.guest("read", path=target, grant=once)
        assert read["ok"] and base64.b64decode(read["result"]["contentBase64"]) == leaf.read_bytes(), read
        assert not self.guest("read", path=target, grant=once)["ok"]
        concurrent = self.grant(target, "read", "once")
        payload = json.dumps(dict(operation="read", path=target, grant=concurrent), separators=(",", ":"))
        call = "wget -qO- --post-data=" + shlex.quote(payload) + " http://host.yougori/"
        report = self.result("sandbox_vm", dict(action="exec", sandbox=self.vm,
                             input=f"{call} & {call} & wait", timeoutSeconds=30), "concurrent-once")
        text, replies = report["output_text"].strip(), []
        while text:
            value, end = json.JSONDecoder().raw_decode(text)
            replies.append(value)
            text = text[end:].lstrip()
        assert len(replies) == 2 and sum(reply["ok"] for reply in replies) == 1, replies
        assert not self.guest("approve", request="forged", mode="read_write", duration="always")["ok"]
        denied_path = (host / "not-approved.txt").as_posix()
        request = self.guest("request", path=denied_path, mode="read")["result"]
        self.owner("deny", request=request["id"])
        repeated = self.guest("request", path=denied_path, mode="read")["result"]
        assert repeated["id"] == request["id"] and repeated["state"] == "denied", repeated
        grant = self.grant(host.as_posix(), "read", "always")
        assert not self.guest("write", path=target, grant=grant, contentBase64="bmV3")["ok"]
        assert leaf.read_text(encoding="utf-8") == "disposable-private-content"
        assert not self.guest("read", path=host.as_posix() + "/../outside.txt", grant=grant)["ok"]
        self.owner("revoke", grant=grant)
        assert not self.guest("read", path=target, grant=grant)["ok"]
        write = self.grant(host.as_posix(), "read_write", "always")
        first_vm = self.vm
        second = self.result("sandbox_vm", {"action": "launch", "memoryGb": 0.5}, "second-vm")
        self.vm = second["sandbox"]
        self.sandboxes.append(self.vm)
        try:
            assert not self.guest("read", path=target, grant=write, sandbox=first_vm)["ok"]
            assert not self.guest("write", path=target, grant=write, sandbox=first_vm, contentBase64="")["ok"]
        finally:
            self.result("sandbox_vm", {"action": "stop", "sandbox": self.vm}, "second-stop")
            self.vm = first_vm
        # The safe resolver must reject a link planted after owner approval as well.
        outside = self.root / "outside-hard-link"
        os.link(leaf, outside)
        assert not self.guest("read", path=target, grant=write)["ok"]
        assert not self.guest("write", path=target, grant=write, contentBase64="")["ok"]
        assert outside.read_bytes() == b"disposable-private-content"
        outside.unlink()
        outside_dir = self.root / "outside-folder"
        outside_dir.mkdir()
        (outside_dir / "secret.txt").write_bytes(b"outside-the-grant")
        link = host / "planted-link"
        if os.name == "nt":
            quote = lambda value: "'" + str(value).replace("'", "''") + "'"
            command = f"New-Item -ItemType Junction -Path {quote(link)} -Value {quote(outside_dir)} | Out-Null"
            made = subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True,
                                  text=True, timeout=30, creationflags=subprocess.CREATE_NO_WINDOW)
            assert made.returncode == 0, made.stderr
        else:
            link.symlink_to(outside_dir, target_is_directory=True)
        assert not self.guest("read", path=(link / "secret.txt").as_posix(), grant=write)["ok"]
        assert not self.guest("write", path=(link / "secret.txt").as_posix(), grant=write, contentBase64="")["ok"]
        assert (outside_dir / "secret.txt").read_bytes() == b"outside-the-grant"
        assert self.guest("write", path=target, grant=write, contentBase64="bmV3")["ok"]
        assert leaf.read_bytes() == b"new"
        empty = (host / "empty.txt").as_posix()
        assert self.guest("write", path=empty, grant=write, contentBase64="")["ok"]
        assert Path(empty).read_bytes() == b""
        created = (host / "new-file.txt").as_posix()
        assert self.guest("write", path=created, grant=write, contentBase64="bmV3")["ok"]
        assert Path(created).read_bytes() == b"new"
        self.owner("revoke", grant=write)
        assert not self.guest("write", path=target, grant=write, contentBase64="")["ok"]
        assert leaf.read_bytes() == b"new"
        # More than the link's 1 MiB pending window: hash inside the guest, so stdout
        # bounds cannot hide an incomplete response or turn this into a mock transport test.
        large = host / "large.bin"
        content = bytes(range(256)) * (12 << 10)
        large.write_bytes(content)
        grant = self.grant(large.as_posix(), "read", "always")
        payload = json.dumps(dict(operation="read", path=large.as_posix(), grant=grant), separators=(",", ":"))
        # The endpoint returns one base64 field; BusyBox sed/base64 suffice in the pinned guest.
        command = "wget -qO- --post-data=" + shlex.quote(payload) + r""" http://host.yougori/ | sed -n 's/.*"contentBase64":"\([^"]*\)".*/\1/p' | base64 -d | sha256sum"""
        report = self.result("sandbox_vm", dict(action="exec", sandbox=self.vm, input=command, timeoutSeconds=45), "guest-large-read")
        assert report["exit_code"] == 0 and report["output_text"].strip().startswith(hashlib.sha256(content).hexdigest()), report
        self.owner("revoke", grant=grant)
        self.result("sandbox_vm", {"action": "stop", "sandbox": self.vm}, "stop")
        ended = self.owner("status")
        assert not ended["grants"] and not ended["requests"] and not ended["policy"]["askForAccess"], ended
        self.wait_no_vm()
        assert not self.result("model_ledger", {}, "ledger-after")["open"]
        self.write("passed", {"guest_default_denied": True, "independent_switches": True,
                   "tree_names_only": True, "one_time_replay_denied": True, "owner_only_approval": True,
                   "read_only_enforced": True, "folder_scope_enforced": True, "writes_and_revocation": True,
                   "large_read_bytes": len(content), "no_owned_vm_or_reservation": True})


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
