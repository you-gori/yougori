"""The remaining host-file permission matrix with a real guest (VM-W host access, overnight item 2).

Disposable host files only. Cases: a sibling folder whose name starts with the approved one;
the approved folder replaced at its path; a revocation while a large read streams to a slow
guest reader; a revocation racing a large write (the file ends as exactly the old or the new
bytes and nothing lands afterwards); an engine restart (VMs end, their grants with them, and a
new VM inherits none). Every response is retained.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import shlex
import threading
import time
from pathlib import Path

spec = importlib.util.spec_from_file_location("host_access", Path(__file__).with_name("vm-host-access.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Matrix(base.Run):
    def exec(self, command, label, timeout=60):
        return self.result("sandbox_vm", dict(action="exec", sandbox=self.vm, input=command, timeoutSeconds=timeout), label)

    def launch(self, label):
        # A workspace gives the guest its one writable directory (its root and /tmp are read-only).
        scratch = self.root / f"workspace-{label}"
        scratch.mkdir(exist_ok=True)
        launch = self.result("sandbox_vm", {"action": "launch", "memoryGb": 1, "workspace": str(scratch)}, label)
        self.vm = launch["sandbox"]
        self.sandboxes.append(self.vm)
        self.owner("policy", policy=dict(treeVisible=False, askForAccess=True))

    def run(self):
        host = self.root / "host-files"
        host.mkdir()
        results = {}
        self.start()
        self.launch("launch")

        # Sibling prefix: approving dir never covers dir-sibling.
        (host / "dir").mkdir()
        (host / "dir" / "inside.txt").write_text("inside", encoding="utf-8")
        (host / "dir-sibling").mkdir()
        (host / "dir-sibling" / "secret.txt").write_text("sibling-secret", encoding="utf-8")
        grant = self.grant((host / "dir").as_posix(), "read", "always")
        inside = self.guest("read", path=(host / "dir" / "inside.txt").as_posix(), grant=grant)
        sibling = self.guest("read", path=(host / "dir-sibling" / "secret.txt").as_posix(), grant=grant)
        assert inside["ok"] and not sibling["ok"] and "sibling-secret" not in json.dumps(sibling), (inside, sibling)
        results["sibling_prefix_refused"] = True
        self.owner("revoke", grant=grant)

        # Replaced folder: the grant follows the approved folder, not its path.
        project = host / "project"
        project.mkdir()
        (project / "notes.txt").write_text("approved", encoding="utf-8")
        grant = self.grant(project.as_posix(), "read", "always")
        first = self.guest("read", path=(project / "notes.txt").as_posix(), grant=grant)
        assert first["ok"] and base64.b64decode(first["result"]["contentBase64"]) == b"approved", first
        project.rename(host / "project-moved")
        project.mkdir()
        (project / "notes.txt").write_text("replacement-content", encoding="utf-8")
        replaced = self.guest("read", path=(project / "notes.txt").as_posix(), grant=grant)
        assert not replaced["ok"] and "replacement-content" not in json.dumps(replaced), replaced
        results["replaced_folder_refused"] = replaced.get("error")
        self.owner("revoke", grant=grant)

        # Revocation while a large read streams to a guest reader that drains slowly.
        large = host / "large.bin"
        content = bytes(range(256)) * (32 << 10)  # 8 MiB
        large.write_bytes(content)
        grant = self.grant(large.as_posix(), "read", "always")
        payload = json.dumps(dict(operation="read", path=large.as_posix(), grant=grant), separators=(",", ":"))
        command = ("wget -qO- --post-data=" + shlex.quote(payload) + " http://host.yougori/ | "
                   r"""(sleep 6; sed -n 's/.*"contentBase64":"\([^"]*\)".*/\1/p' | base64 -d 2>/dev/null | sha256sum)""")
        outcome = {}
        reader = threading.Thread(target=lambda: outcome.update(report=self.call(
            "sandbox_vm", dict(action="exec", sandbox=self.vm, input=command, timeoutSeconds=60), "revoke-during-read-exec", checked=False)))
        reader.start()
        time.sleep(2)
        revoked_at = time.monotonic()
        self.owner("revoke", grant=grant)
        revoke_seconds = time.monotonic() - revoked_at
        reader.join(90)
        report = outcome.get("report", {})
        text = (report.get("result") or {}).get("output_text", "")
        expected = hashlib.sha256(content).hexdigest()
        after = self.guest("read", path=large.as_posix(), grant=grant)
        assert not after["ok"], after
        results["revoke_during_read"] = {"guest_hash_complete": text.strip().startswith(expected),
                                         "revoke_seconds": revoke_seconds, "later_read_refused": True}
        assert not results["revoke_during_read"]["guest_hash_complete"], "the revoked read delivered every byte"

        # Revocation racing a large write: never a partial file, nothing after the revoke.
        target = host / "written.bin"
        target.write_bytes(b"old-content")
        grant = self.grant(target.as_posix(), "read_write", "always")
        prefix = json.dumps(dict(operation="write", path=target.as_posix(), grant=grant), separators=(",", ":"))[:-1] + ',"contentBase64":"'
        # The guest's root and /tmp are read-only: the payload goes to its workspace.
        build = ("for d in /run/yougori/workspace /dev/shm /run /var/tmp /tmp; do if ( : > $d/.w ) 2>/dev/null; then D=$d; break; fi; done; "
                 "[ -n \"$D\" ] || { echo no-writable-directory; exit 9; }; "
                 "head -c 6291456 /dev/urandom > $D/w.bin && sha256sum $D/w.bin | cut -d' ' -f1 > $D/w.sha && "
                 "printf '%s' " + shlex.quote(prefix) + " > $D/w.json && base64 $D/w.bin | tr -d '\\n' >> $D/w.json && printf '\"}' >> $D/w.json && "
                 "rm -f $D/w.bin && echo $D $(cat $D/w.sha)")
        built = self.exec(build, "write-race-build")
        assert built["exit_code"] == 0, built
        directory, new_hash = built["output_text"].split()
        assert len(new_hash) == 64, built
        post = f"wget -qO- --post-file={directory}/w.json http://host.yougori/; echo exit=$?"
        outcome = {}
        writer = threading.Thread(target=lambda: outcome.update(report=self.call(
            "sandbox_vm", dict(action="exec", sandbox=self.vm, input=post, timeoutSeconds=60),
            "write-race-exec", checked=False)))
        writer.start()
        time.sleep(0.3)
        self.owner("revoke", grant=grant)
        writer.join(90)
        landed = hashlib.sha256(target.read_bytes()).hexdigest()
        old = hashlib.sha256(b"old-content").hexdigest()
        assert landed in (old, new_hash), "a partial write was left on the host"
        raced = ((outcome.get("report") or {}).get("result") or {}).get("output_text", "")
        assert "can't open" not in raced, raced
        again = self.exec(post, "write-after-revoke")
        assert hashlib.sha256(target.read_bytes()).hexdigest() == landed, "a write landed after the revocation returned"
        text = again.get("output_text", "")
        results["revoke_racing_write"] = {"file_is": "new" if landed == new_hash else "old", "raced_reply": raced[-300:],
                                          "later_write_reply": text[-300:], "later_write_refused": "exit=0" not in text or '"ok":false' in text}
        assert results["revoke_racing_write"]["later_write_refused"], text

        # Engine restart: the VM ends with the engine and its grants with it.
        kept = self.grant((host / "dir").as_posix(), "read", "always")
        unused = self.grant((host / "dir" / "inside.txt").as_posix(), "read", "once")
        old_vm = self.vm
        self.stop()
        self.sandboxes.clear()
        self.start()
        settings = self.data / "sandbox-vm" / "host-access.json"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            saved = json.loads(settings.read_text(encoding="utf-8")) if settings.exists() else {"grants": {}}
            if not any(g.get("sandbox") == old_vm.split(":")[-1] or old_vm.endswith(g.get("sandbox", "?")) for g in saved.get("grants", {}).values()):
                break
            time.sleep(1)
        self.write("restart-settings", saved)
        self.launch("launch-after-restart")
        for name, grant in (("always", kept), ("once", unused)):
            reply = self.guest("read", path=(host / "dir" / "inside.txt").as_posix(), grant=grant)
            assert not reply["ok"], (name, reply)
        results["restart_grants_ended"] = True
        self.result("sandbox_vm", {"action": "stop", "sandbox": self.vm}, "stop-final")
        ended = self.owner("status")
        assert not ended["grants"] and not ended["requests"], ended
        self.wait_no_vm()
        assert not self.result("model_ledger", {}, "ledger-after")["open"]
        self.write("passed", results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    args.model, args.reuse_fixture, args.from_case = args.root / "unused-model", False, None
    run = Matrix(args)
    try:
        run.run()
    finally:
        run.clean()
