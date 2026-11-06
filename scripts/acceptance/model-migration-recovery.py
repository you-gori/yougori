"""Kill and recover a disposable acceptance engine at real migration side effects.

Requires acceptance engine/CLI builds, a verified runtime, and a local model folder.
Creates one disposable CUDA container through the public API. Never edits engine state.
Only the exact Popen engine owned by this harness is terminated. No inference benchmark.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


class Run:
    def __init__(self, args):
        self.root = args.root.resolve()
        self.root.mkdir(parents=True, exist_ok=args.reuse_fixture)
        self.data = self.root / "data"
        self.out = self.root / "evidence"
        self.out.mkdir(exist_ok=args.reuse_fixture)
        self.reuse_fixture = args.reuse_fixture
        self.from_case = args.from_case
        self.engine = args.engine.resolve()
        self.cli = args.cli.resolve()
        self.model = args.model.resolve()
        self.pipe = (rf"\\.\pipe\Yougori.MigrationRecovery.{os.getpid()}" if os.name == "nt"
                     else f"/tmp/yougori-{os.geteuid()}/acceptance-{os.getpid()}.sock")
        self.env = dict(os.environ)
        self.env.pop("YOUGORI_ACCEPTANCE_MIGRATION_PAUSE", None)
        self.env.update({
            "YOUGORI_ACCEPTANCE_ENDPOINT": self.pipe,
            "YOUGORI_ACCEPTANCE_DATA_DIR": str(self.data),
            "YOUGORI_ACCEPTANCE_RUNTIME_DIR": str(args.runtime.resolve()),
            "YOUGORI_NETWORK_URL": "http://127.0.0.1:9",
            "YOUGORI_CATALOG_ROOT": str(self.root / "catalog"),
            "YOUGORI_CATALOG_QUOTA_BYTES": str(8 * 1024 ** 3),
            "YOUGORI_LEDGER_HISTORY_DIR": str(self.root / "ledger"),
            "USERPROFILE": str(self.root / "home"),
        })
        if os.name != "nt":
            self.env.update({"XDG_DATA_HOME": str(self.root / "home" / "data"),
                             "XDG_CONFIG_HOME": str(self.root / "home" / "config"),
                             "YOUGORI_CGROUP_BASE": f"yougori-acceptance-{os.getpid()}",
                             "YOUGORI_VM_ACCOUNT": "yougori-vm"})
        self.process = None
        self.number = max((int(p.name.split("-")[0]) for p in self.out.glob("*.json")), default=0)
        self.environment_id = None
        self.write("build", {"engine_sha256": digest(self.engine), "cli_sha256": digest(self.cli),
                             "pipe": self.pipe, "data": str(self.data)})

    def write(self, name, body):
        self.number += 1
        (self.out / f"{self.number:03d}-{name}.json").write_text(
            json.dumps(body, indent=2), encoding="utf-8", newline="\n")
        print(name, flush=True)

    def command(self, *words, params=None, checked=True, label=None):
        result = subprocess.run([str(self.cli), *words], input=None if params is None else json.dumps(params),
                                env=self.env, cwd=self.root, capture_output=True, text=True,
                                encoding="utf-8", timeout=600, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            body = json.loads(result.stdout)
        except ValueError:
            body = {"ok": False, "stdout": result.stdout}
        if label:
            self.write(label, {"exit": result.returncode, "reply": body, "stderr": result.stderr})
        if checked:
            assert result.returncode == 0 and body.get("ok"), (words, body, result.stderr)
        return body

    def call(self, method, params, label, checked=True):
        return self.command("call", method, "--yes", "--file", "-", params=params,
                            label=label, checked=checked)

    def migration(self, action, label):
        return self.call("model_migration", {"action": action}, label)["result"]

    def start(self, phase=None):
        assert self.process is None or self.process.poll() is not None
        marker = self.data / "model-migration" / "acceptance-pause.json"
        marker.unlink(missing_ok=True)
        env = dict(self.env)
        if phase:
            env["YOUGORI_ACCEPTANCE_MIGRATION_PAUSE"] = phase
        with (self.root / "engine.log").open("ab") as log:
            self.process = subprocess.Popen([str(self.engine)], env=env, cwd=self.root,
                                            stdout=log, stderr=subprocess.STDOUT,
                                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            assert self.process.poll() is None, "acceptance engine exited; inspect engine.log"
            status = self.command("app", "status", checked=False)
            if status.get("ok"):
                assert status["result"]["endpoint"] == self.pipe and status["result"]["engineOnly"] is True, status
                self.write("engine-start", {"pid": self.process.pid, "phase": phase, "status": status})
                return
            time.sleep(0.25)
        raise RuntimeError("acceptance endpoint did not answer")

    def stop(self):
        if self.process is not None and self.process.poll() is None:
            self.command("app", "quit", "--yes", label="engine-quit")
            self.process.wait(timeout=60)

    def record(self):
        return json.loads((self.data / "model-migration" / "record.json").read_text())

    def options(self):
        return json.loads((self.data / "runtime" / "workload-options" /
                           f"{self.environment_id}.json").read_text())

    def catalog(self, label, empty=False):
        result = self.call("catalog_status", {}, label)["result"]
        views = self.root / "catalog" / "views"
        live_views = list(views.iterdir()) if views.exists() else []
        if empty:
            assert not live_views, live_views
            assert result["catalog"]["live_leases"] == 0, result
        return result

    def interrupt(self, phase, recovery):
        self.stop()
        self.start(phase)
        process = subprocess.Popen([str(self.cli), "call", "model_migration", "--yes", "--file", "-"],
                                   env=self.env, cwd=self.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                   creationflags=subprocess.CREATE_NO_WINDOW)
        process.stdin.write(json.dumps({"action": "apply"}))
        process.stdin.close()
        process.stdin = None
        marker = self.data / "model-migration" / "acceptance-pause.json"
        deadline = time.monotonic() + 180
        while not marker.exists() and time.monotonic() < deadline:
            if process.poll() is not None:
                raise RuntimeError(("apply ended before the selected boundary", process.communicate()))
            time.sleep(0.02)
        assert marker.exists(), "no confirmed interruption boundary"
        observed = json.loads(marker.read_text())
        assert observed == {"phase": phase, "pid": self.process.pid}, observed
        self.process.kill()
        self.process.wait(timeout=30)
        stdout, stderr = process.communicate(timeout=90)
        record = self.record()
        assert any(row.get("intent") is not None for row in record["items"]), record
        self.write(f"crash-{phase}-{recovery}", {"marker": observed, "record": record,
                                                "options": self.options(), "client_exit": process.returncode,
                                                "stdout": stdout, "stderr": stderr})
        self.start()
        self.migration("status", "recovered-status")
        # A hard-killed engine can leave its CUDA pool alive. Use the public, explicitly
        # confirmed Stop recovery, which verifies ownership; never terminate a distro by name.
        self.call("recover_environment_runtime_report", {"environmentId": self.environment_id, "confirmed": True},
                  "recover-abandoned-runtime")
        if recovery == "apply":
            result = self.migration("apply", "resume")
            assert result["status"] == {"status": "completed"}, result
            after = self.record()
            assert all(row.get("intent") is None for row in after["items"])
            self.catalog("catalog-resumed")
            prior = digest(self.data / "model-migration" / "record.json")
            noop = self.migration("apply", "repeat-apply")
            assert noop["status"] == {"status": "not_needed"}, noop
            assert digest(self.data / "model-migration" / "record.json") == prior
        rolled = self.migration("rollback", "rollback")
        assert rolled["rolledBack"] is True, rolled
        assert self.options() == self.original, "rollback did not restore exact options"
        self.catalog("catalog-rolled-back", empty=True)

    def run(self):
        files = [{"name": p.name, "sha256": digest(p), "size": p.stat().st_size}
                 for p in sorted(self.model.iterdir()) if p.is_file() and not p.name.startswith(".")]
        self.write("source-before", files)
        self.start()
        workload = {"environment": {"YOUGORI_MODEL": "Qwen/Qwen2.5-0.5B-Instruct",
                                     "YOUGORI_MODEL_PATH": "/yougori-model",
                                     "YOUGORI_LOCAL_MANIFEST": json.dumps({"files": files})},
                    "binds": [{"source": str(self.model), "target": "/yougori-model", "readOnly": True}]}
        request = {"name": "Migration recovery fixture", "kind": "container", "provider": "yougoriCuda",
                   "runtime": "docker.io/library/alpine:3.23", "autoSetupCuda": True,
                   "description": "Hugging Face · Qwen/Qwen2.5-0.5B-Instruct", "networkAccess": False,
                   "gpuAccess": True, "storageGb": 20, "workload": workload,
                   "resourcePolicy": {"cpu": {"min": 2, "preferred": 2, "max": 2},
                                      "memoryGb": {"min": 4, "preferred": 4, "max": 4}, "priority": "normal"}}
        if self.reuse_fixture:
            created = self.call("get_platform_state", {}, "existing-fixture")["result"]
        else:
            created = self.call("create_environment", {"request": request}, "create")["result"]
        subjects = [row for row in created["environments"] if row["name"] == request["name"]]
        assert len(subjects) == 1 and subjects[0]["status"] == "stopped", subjects
        self.environment_id = subjects[0]["id"]
        self.original = self.options()
        if self.reuse_fixture and (self.data / "model-migration" / "record.json").exists():
            fixtures = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.out.glob("*-fixture.json"))]
            self.original = next(row["original_options"] for row in fixtures if "original_options" in row)
            self.call("recover_environment_runtime_report", {"environmentId": self.environment_id, "confirmed": True},
                      "recover-prior-attempt")
            self.migration("rollback", "restore-prior-attempt")
            assert self.options() == self.original
        preview = self.migration("preview", "preview")
        self.write("fixture", {"id": self.environment_id, "original_options": self.original})
        assert "own_volume" in json.dumps(preview) and "catalog_publish" in json.dumps(preview), preview
        cases = [(phase, recovery) for phase in ("options-installed", "runtime-configured", "catalog-prepared")
                 for recovery in ("rollback", "apply")]
        for phase, recovery in cases[self.from_case:]:
            self.interrupt(phase, recovery)
        result = self.migration("apply", "apply-after-rollback")
        assert result["status"] == {"status": "completed"}, result
        self.call("set_environment_status", {"environmentId": self.environment_id, "status": "running"},
                  "start-migrated-runtime")
        self.call("set_environment_status", {"environmentId": self.environment_id, "status": "stopped"},
                  "stop-migrated-runtime")
        self.migration("rollback", "final-rollback")
        assert self.options() == self.original
        self.catalog("final-catalog", empty=True)
        self.call("delete_environment", {"environmentId": self.environment_id}, "delete-fixture")
        self.environment_id = None
        self.stop()
        assert all(digest(self.model / row["name"]) == row["sha256"] for row in files)
        self.write("PASS", {"confirmed_crashes": len(cases[self.from_case:]), "from_case": self.from_case,
                            "source_unchanged": True,
                            "rollback_options_exact": True, "repeat_apply_record_preserved": True,
                            "reapply_after_rollback": True, "runtime_started_after_migration": True,
                            "fixture_deleted": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("root", "engine", "cli", "runtime", "model"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--reuse-fixture", action="store_true", help="recover this harness's existing fixture")
    parser.add_argument("--from-case", type=int, default=0, choices=range(6))
    run = Run(parser.parse_args())
    try:
        run.run()
    finally:
        if run.process is not None and run.process.poll() is None:
            try:
                run.stop()
            except Exception:
                run.process.kill()
                run.process.wait(timeout=30)


if __name__ == "__main__":
    main()
