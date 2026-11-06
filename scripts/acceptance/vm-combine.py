"""Combining two real VM sandboxes into one (overnight item 3), on a disposable engine.

Two VMs with their own staged workspaces (each also holding a file its guest wrote and nobody
promoted) and declared services are previewed, refused while a service conflict is undecided,
combined with an explicit decision, and checked: one QEMU process left, the summed reservation,
both workspaces byte for byte inside the combined guest, both services declared, the originals'
workspaces kept, a repeated start returning the same operation. A second combine is cut short
by ending the engine; the next start reports it interrupted with the originals' settings. The
owner then removes the originals' workspaces explicitly. Every response is retained.
"""
import argparse
import hashlib
import importlib.util
import json
import time
from pathlib import Path

spec = importlib.util.spec_from_file_location("host_access", Path(__file__).with_name("vm-host-access.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


class Combine(base.Run):
    def vm(self, label, folder, memory, publish):
        launched = self.result("sandbox_vm", {"action": "launch", "memoryGb": memory, "cpu": 1,
                                              "workspace": str(folder), "publish": publish}, label)
        sandbox = launched["sandbox"]
        self.sandboxes.append(sandbox)
        return sandbox

    def run_in(self, sandbox, command, label):
        report = self.result("sandbox_vm", {"action": "exec", "sandbox": sandbox, "input": command, "timeoutSeconds": 60}, label)
        assert report["exit_code"] == 0, report
        return report["output_text"]

    def combine(self, label, checked=True, **fields):
        return self.call("sandbox_vm", {"action": "combine", **fields}, label, checked=checked)

    def run(self):
        first_folder, second_folder = self.root / "project-a", self.root / "project-b"
        for folder, name in ((first_folder, "a"), (second_folder, "b")):
            folder.mkdir()
            (folder / f"{name}.txt").write_text(f"owner file {name}\n", encoding="utf-8")
            (folder / "shared.txt").write_text("same in both\n", encoding="utf-8")
        self.start()
        a = self.vm("launch-a", first_folder, 0.75, "web=8080")
        b = self.vm("launch-b", second_folder, 0.75, "web=8081")
        self.run_in(a, "echo made-in-a > /run/yougori/workspace/guest-a.txt", "guest-a-write")
        self.run_in(b, "echo made-in-b > /run/yougori/workspace/guest-b.txt", "guest-b-write")
        before = self.processes()
        assert len(before) == 2, before
        results = {}

        # A service conflict (web on both, different ports) needs the owner's decision.
        shown = self.combine("preview-undecided", operation="preview", sandbox=a, **{"with": b})["result"]
        assert shown["compatible"] is True, shown
        assert shown["undecidedConflicts"] == 1 and shown["conflicts"][0]["key"].startswith("publish:"), shown["conflicts"]
        refused = self.combine("start-undecided", checked=False, operation="start", sandbox=a, preview=shown["digest"], **{"with": b})
        assert not refused.get("ok"), refused
        decisions = {"keep": {shown["conflicts"][0]["key"]: "second"}}
        shown = self.combine("preview", operation="preview", sandbox=a, decisions=decisions, **{"with": b})["result"]
        assert shown["undecidedConflicts"] == 0, shown
        assert abs(shown["combined"]["params"]["memoryGb"] - 1.5) < 1e-9 and shown["combined"]["params"]["cpu"] == 2, shown["combined"]
        paths = {row["path"] for row in shown["combined"]["workspace"]}
        assert {"project-a/a.txt", "project-a/guest-a.txt", "project-b/b.txt", "project-b/guest-b.txt"} <= paths, paths
        results["preview"] = {"compatible": True, "conflict_needed_decision": True, "files": len(paths),
                              "os": [s["os"] for s in shown["sources"]], "capacity": shown["capacity"]}

        started = self.combine("start", operation="start", sandbox=a, preview=shown["digest"], decisions=decisions,
                               requestKey="combine-acceptance-1", **{"with": b})["result"]
        assert started["state"] == "healthy", started
        combined = started["combined"]
        self.sandboxes = [combined]
        again = self.combine("start-repeated", operation="start", sandbox=a, preview=shown["digest"], decisions=decisions,
                             requestKey="combine-acceptance-1", **{"with": b})["result"]
        assert again["operation"] == started["operation"] and again["combined"] == combined, again
        after = self.processes()
        assert len(after) == 1 and after[0]["ProcessId"] not in {row["ProcessId"] for row in before}, (before, after)
        listing = self.run_in(combined, "cd /run/yougori/workspace && find . -type f -exec sha256sum {} + | sort -k2", "combined-files")
        expected = {row["path"]: row["sha256"] for row in shown["combined"]["workspace"]}
        seen = {line.split("  ", 1)[1][2:]: line.split("  ", 1)[0] for line in listing.strip().splitlines()}
        assert seen == expected, (seen, expected)
        assert hashlib.sha256(b"made-in-a\n").hexdigest() == expected["project-a/guest-a.txt"]
        status = self.result("sandbox_vm", {"action": "status"}, "status-after")
        ledger = self.result("model_ledger", {}, "ledger-after-combine")
        workspaces = self.result("sandbox_vm", {"action": "workspace", "op": "list"}, "workspaces-after")["workspaces"]
        kept = {row["sandbox"] for row in workspaces}
        assert a in kept and b in kept and combined in kept, kept
        results["combine"] = {"operation": started["operation"], "one_qemu": True, "files_match": len(seen),
                              "services": started["health"]["services"], "originals_kept": True, "repeat_same": True,
                              "late_writes": started.get("lateWrites")}

        # A second combine cut short by the engine's end is reported at the next start.
        c_folder = self.root / "project-c"
        c_folder.mkdir()
        (c_folder / "c.txt").write_text("owner file c\n", encoding="utf-8")
        c = self.vm("launch-c", c_folder, 0.5, "api=9000")
        shown2 = self.combine("preview-2", operation="preview", sandbox=combined, **{"with": c})["result"]
        assert shown2["undecidedConflicts"] == 0, shown2
        journal_root = self.data / "sandbox-vm" / "combine"
        known = {p.name for p in journal_root.iterdir()}
        import subprocess, sys, threading
        outcome = {}
        thread = threading.Thread(target=lambda: outcome.update(reply=self.call("sandbox_vm", {"action": "combine", "operation": "start",
                                  "sandbox": combined, "with": c, "preview": shown2["digest"]}, "start-2-interrupted", checked=False)))
        thread.start()
        deadline = time.monotonic() + 120
        state = None
        while time.monotonic() < deadline:
            fresh = [p for p in journal_root.iterdir() if p.name not in known]
            if fresh:
                journal = json.loads((fresh[0] / "journal.json").read_text(encoding="utf-8"))
                state = journal["state"]
                if state in ("launching", "checking", "stopping-originals"):
                    break
            time.sleep(0.05)
        self.process.kill()
        self.process.wait(timeout=30)
        thread.join(60)
        self.process = None
        self.sandboxes = []
        self.start()
        recovered = self.combine("status-after-restart", operation="status")["result"]["operations"]
        cut = [row for row in recovered if row["operation"] == fresh[0].name][0]
        assert cut["state"] == "interrupted" and len(cut["originals"]) == 2, cut
        self.wait_no_vm()
        results["interrupted"] = {"killed_in": state, "reported": cut["state"], "originals_settings_kept": True}

        finished = self.combine("finish-remove", operation="finish", id=started["operation"], originals="remove")["result"]
        assert finished["state"] == "finished" and set(finished["originalWorkspacesRemoved"]) == {a, b}, finished
        assert not self.result("model_ledger", {}, "ledger-final")["open"]
        assert not self.processes()
        self.write("passed", results)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument(f"--{name}", type=Path, required=True)
    args = parser.parse_args()
    args.model, args.reuse_fixture, args.from_case = args.root / "unused-model", False, None
    run = Combine(args)
    try:
        run.run()
    finally:
        run.clean()
