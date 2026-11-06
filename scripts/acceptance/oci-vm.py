"""Real OCI importer/consumer acceptance; only a disposable engine is addressed.

Defaults to a supplied locally built static fixture. The explicit registry case
fetches a digest-pinned Alpine image from the selected public registry; no paid resource.
Checks literal argv without a shell, uid, private writable roots, hostile archives,
cleanup, and actual engine death with a live image VM. Keeps failed evidence.
"""
import argparse
import hashlib
import gzip
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
import http.client

spec = importlib.util.spec_from_file_location("base", Path(__file__).with_name("model-migration-recovery.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)


IMAGE_NAMES = ("Data", "data", "usr/lib/x:y", "docs/café", "docs/cafe\u0301", "NUL.txt", "trail. ", "a~1")


def layout(path, executable, serve=False, hostile=False, bomb=False, corrupt=False,
           codec="tar", docker=False, linux_names=False, encoder=None, trailing=False, duplicate=False):
    path.mkdir(parents=True)
    blobs = path / "blobs" / "sha256"
    blobs.mkdir(parents=True)
    def blob(body, media):
        digest = hashlib.sha256(body).hexdigest()
        (blobs / digest).write_bytes(body)
        return {"mediaType": media, "digest": "sha256:" + digest, "size": len(body)}
    def encoded(value):
        return json.dumps(value, separators=(",", ":")).encode()
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.PAX_FORMAT) as tar:
        tmp = tarfile.TarInfo("tmp")
        tmp.type = tarfile.DIRTYPE
        tmp.mode = 0o1777
        tar.addfile(tmp)
        body = bytes(8 << 20) if bomb else executable.read_bytes()
        app = tarfile.TarInfo("../escape" if hostile else "app")
        app.size = len(body)
        app.mode = 0o755
        tar.addfile(app, io.BytesIO(body))
        if duplicate:
            tar.addfile(app, io.BytesIO(body))
        if linux_names:
            for name in IMAGE_NAMES:
                entry = tarfile.TarInfo(name)
                content = name.encode("utf-8")
                entry.size, entry.mode = len(content), 0o644
                tar.addfile(entry, io.BytesIO(content))
    unpacked = stream.getvalue()
    if bomb: codec = "gzip"
    if codec == "zstd":
        assert encoder and encoder.is_file(), "Provide the host-native fixture encoder"
        encoded_layer = subprocess.run([str(encoder), "compress"], input=unpacked,
                                       capture_output=True, check=True, timeout=60).stdout
    else:
        encoded_layer = gzip.compress(unpacked, mtime=0) if codec == "gzip" else unpacked
    if trailing: encoded_layer += encoded_layer
    media = "application/vnd.docker.image.rootfs.diff.tar.gzip" if docker else "application/vnd.oci.image.layer.v1.tar" + ("+"+codec if codec != "tar" else "")
    layer = blob(encoded_layer, media)
    if corrupt:
        target = blobs / layer["digest"].split(":")[1]
        target.write_bytes(bytes([encoded_layer[0] ^ 1]) + encoded_layer[1:])
    cmd = ["serve"] if serve else ["literal $(touch /tmp/bad)", "a b", "'\""]
    if linux_names: cmd = ["names"]
    config_media = "application/vnd.docker.container.image.v1+json" if docker else "application/vnd.oci.image.config.v1+json"
    manifest_media = "application/vnd.docker.distribution.manifest.v2+json" if docker else "application/vnd.oci.image.manifest.v1+json"
    config = blob(encoded({"architecture": "amd64", "os": "linux", "config": {
        "Entrypoint": ["/app"], "Cmd": cmd, "User": "1000:1000", "Env": ["OCI_LITERAL=a=b"]},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(unpacked).hexdigest()]}}), config_media)
    manifest = blob(encoded({"schemaVersion": 2, "mediaType": manifest_media,
                            "config": config, "layers": [layer]}), manifest_media)
    manifest["platform"] = {"os": "linux", "architecture": "amd64"}
    (path / "index.json").write_bytes(encoded({"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [manifest]}))
    (path / "oci-layout").write_bytes(encoded({"imageLayoutVersion": "1.0.0"}))
    return manifest["digest"]


class Run(base.Run):
    def __init__(self, args):
        super().__init__(args)
        self.fixture = args.fixture.resolve()
        self.sandboxes = []

    def result(self, method, params, label):
        return self.call(method, params, label)["result"]

    def write(self, name, body):
        def redact(value):
            if isinstance(value, dict):
                return {k: "[redacted]" if k.lower() in {"url", "token", "secret", "key"} else redact(v) for k, v in value.items()}
            if isinstance(value, list):
                return [redact(v) for v in value]
            return value
        super().write(name, redact(body))

    def vm(self, params, label):
        return self.result("sandbox_vm", params, label)

    def no_owned_qemu(self):
        if os.name != "nt":
            for proc in Path("/proc").iterdir():
                if not proc.name.isdigit():
                    continue
                try:
                    if not (proc / "comm").read_text().startswith("qemu-system"):
                        continue
                    args = (proc / "cmdline").read_bytes().decode(errors="replace")
                    if str(self.data) in args:
                        return False
                except (FileNotFoundError, ProcessLookupError):
                    pass
            return True
        command = ('Get-CimInstance Win32_Process -Filter "Name=\'qemu-system-x86_64.exe\'" | '
                   'Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress')
        out = subprocess.run(["powershell", "-NoProfile", "-Command", command], capture_output=True, text=True, timeout=30)
        assert out.returncode == 0, out.stderr
        rows = json.loads(out.stdout) if out.stdout.strip() else []
        if not isinstance(rows, list): rows = [rows]
        marker = str(self.data).replace("\\", "/").lower()
        return not any(marker in (r.get("CommandLine") or "").replace("\\", "/").lower() for r in rows)

    def wait_no_qemu(self):
        until = time.monotonic() + 150
        while time.monotonic() < until:
            if self.no_owned_qemu(): return
            time.sleep(1)
        raise AssertionError("Owned QEMU process survived cleanup")

    def wait_outcome(self, sandbox):
        until = time.monotonic() + 300
        while time.monotonic() < until:
            status = self.call("sandbox_vm", {"action": "status"}, None)["result"]
            row = next((i for i in status.get("images", []) if i["sandbox"] == sandbox), None)
            if row and row.get("outcome"):
                boot = next(s["boot"] for s in status["sandboxes"] if s["sandbox"] == sandbox)
                assert row["overlay"]["owner"] == sandbox and row["overlay"]["generation"] == boot, row
                assert row["overlay"]["shared"] is False, row
                self.write("image-outcome", row)
                return row["outcome"]
            time.sleep(1)
        raise AssertionError("Image command did not produce an outcome")

    def launch(self, image, publish=False):
        params = {"action": "launch", "memoryGb": 1, "image": image}
        if publish: params["publish"] = "api=8080"
        result = self.vm(params, "image-launch")
        self.sandboxes.append(result["sandbox"])
        return result["sandbox"]

    def interrupt_import(self, folder):
        child = subprocess.Popen([str(self.cli), "call", "sandbox_vm", "--yes", "--file", "-"],
                                 env=self.env, cwd=self.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True, encoding="utf-8",
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        child.stdin.write(json.dumps({"action": "image", "operation": "import", "layout": str(folder),
                                     "ownerSelected": True, "rootGb": 0.0625}))
        child.stdin.close()
        child.stdin = None
        until = time.monotonic() + 120
        source = self.data / "sandbox-vm" / "images" / "imports"
        workspaces = self.data / "sandbox-vm" / "workspaces"
        while time.monotonic() < until:
            staged = [p for p in source.glob("*/plan.json")
                      if (workspaces / p.parent.name / "workspace.json").is_file()]
            if staged:
                ledger = self.result("model_ledger", {}, "import-live-ledger")
                execution = staged[0].parent.name
                owned = [r for r in ledger["open"] if r.get("provenance", {}).get("execution") == execution and r["parent"] is None]
                assert sorted(r["grantedHostBytes"] for r in owned) == [1 << 30, 2 << 30], owned
                assert sum(r["currentHostBytes"] for r in owned) == 3 << 30, owned
                self.process.kill()
                self.process.wait(timeout=30)
                stdout, stderr = child.communicate(timeout=60)
                self.write("import-death", {"staged": [p.parent.name for p in staged], "workspace_present_before_kill": True,
                                            "client_exit": child.returncode, "stdout": stdout, "stderr": stderr})
                self.wait_no_qemu()
                self.start()
                self.vm({"action": "status"}, "import-recovered-status")
                assert not list(source.iterdir()), "import source survived recovery"
                # The generated importer copy is disposable, not a retained user workspace.
                for staged_file in staged:
                    assert not list(workspaces.rglob(staged_file.parent.name)), "import workspace survived recovery"
                return
            if child.poll() is not None:
                raise AssertionError(("import ended before the observed staging boundary", child.communicate()))
            time.sleep(0.01)
        child.kill()
        child.communicate(timeout=30)
        raise AssertionError("import did not reach staging")

    def request(self, url):
        from urllib.parse import urlsplit
        parts = urlsplit(url)
        until = time.monotonic() + 90
        while True:
            try:
                connection = http.client.HTTPConnection("127.0.0.1", parts.port, timeout=10)
                try:
                    connection.request("GET", parts.path, headers={"Host": parts.netloc})
                    response = connection.getresponse()
                    body = response.read().decode()
                    assert response.status == 200, (response.status, body)
                    return body
                finally:
                    connection.close()
            except Exception:
                if time.monotonic() > until: raise
                time.sleep(1)

    def run(self):
        good, server, bad = [self.root / name for name in ("layout-argv", "layout-service", "layout-hostile")]
        argv_id = layout(good, self.fixture)
        server_id = layout(server, self.fixture, serve=True)
        layout(bad, self.fixture, hostile=True)
        before = {str(p.relative_to(good)): base.digest(p) for p in good.rglob("*") if p.is_file()}
        self.start()
        self.vm({"action": "plan"}, "vm-plan")
        refused = self.call("sandbox_vm", {"action": "image", "operation": "import", "layout": str(good)},
                            "unsigned-without-owner-selection", checked=False)
        assert not refused.get("ok") and "ownerSelected" in json.dumps(refused), refused
        for folder, expected in [(good, argv_id), (server, server_id)]:
            result = self.command("sandbox", "image", "import", "--layout", str(folder),
                                  "--owner-selected", "true", "--root-gb", "0.0625", "--yes",
                                  label="image-import")["result"]
            assert result["id"] == expected and result["inspection"] == "separate_vm", result
            self.wait_no_qemu()
        refused = self.call("sandbox_vm", {"action": "image", "operation": "import", "layout": str(bad),
                            "ownerSelected": True, "rootGb": 0.0625}, "hostile-import", checked=False)
        assert not refused.get("ok") and "unsafe_name" in json.dumps(refused), refused
        assert not (self.root / "escape").exists()
        self.wait_no_qemu()
        for name, options in [("bomb", {"bomb": True}), ("corrupt", {"corrupt": True})]:
            folder = self.root / ("layout-" + name)
            layout(folder, self.fixture, **options)
            refused = self.call("sandbox_vm", {"action": "image", "operation": "import", "layout": str(folder),
                                "ownerSelected": True, "rootGb": 0.0625}, name + "-import", checked=False)
            assert not refused.get("ok"), refused
            reason = json.dumps(refused).lower()
            expected = ("ratio_exceeded" in reason if name == "bomb" else
                        "declared sha256:" in reason and "the bytes hash to sha256:" in reason)
            assert expected, refused
            self.wait_no_qemu()
        refused = self.call("sandbox_vm", {"action": "launch", "memoryGb": 0.3125, "image": argv_id},
                            "insufficient-root-budget", checked=False)
        assert not refused.get("ok") and "512 MiB" in json.dumps(refused), refused
        self.wait_no_qemu()
        self.interrupt_import(good)
        a = self.launch(argv_id)
        outcome = self.wait_outcome(a)
        assert outcome["exit_code"] == 0, outcome
        report = json.loads(outcome["output_text"])
        assert report == {"uid": 1000, "gid": 1000, "args": ["literal $(touch /tmp/bad)", "a b", "'\""], "env": "a=b"}, report
        self.vm({"action": "stop", "sandbox": a}, "stop-argv")
        b, c = self.launch(server_id, True), self.launch(server_id, True)
        images = self.vm({"action": "status"}, "overlay-owners")["images"]
        overlays = [row["overlay"] for row in images if row["sandbox"] in (b, c)]
        assert len(overlays) == 2 and len({o["id"] for o in overlays}) == 2, overlays
        assert {o["owner"] for o in overlays} == {b, c} and all(o["shared"] is False for o in overlays), overlays
        urls = []
        for sandbox in (b, c):
            published = self.vm({"action": "publish", "sandbox": sandbox, "service": "api", "audience": "owner"}, "publish")
            url = published["url"]
            # Preserve the owner token query while selecting the service path.
            from urllib.parse import urlsplit, urlunsplit
            parts = urlsplit(url)
            urls.append(urlunsplit(parts._replace(path="/counter")))
        counts = [self.request(urls[0]), self.request(urls[0]), self.request(urls[1])]
        assert counts == ["1", "2", "1"], counts
        self.write("private-roots", {"counters": counts})
        self.vm({"action": "stop", "sandbox": b}, "stop-first-image")
        assert self.request(urls[1]) == "2", "Stopping one image affected the other"
        self.process.kill()
        self.process.wait(timeout=30)
        self.wait_no_qemu()
        self.write("engine-death", {"owned_qemu_gone": True})
        self.start()
        self.vm({"action": "status"}, "recovered-status")
        for kind in ("views", "imports"):
            folder = self.data / "sandbox-vm" / "images" / kind
            assert not folder.exists() or not list(folder.iterdir()), list(folder.iterdir())
        restarted = self.launch(argv_id)
        assert self.wait_outcome(restarted)["exit_code"] == 0
        self.vm({"action": "stop", "sandbox": restarted}, "stop-restarted-image")
        self.vm({"action": "status"}, "final-status")
        catalog = self.catalog("final-catalog")
        assert catalog["catalog"]["live_leases"] == 0, catalog
        ledger = self.result("model_ledger", {}, "final-ledger")
        assert not ledger["open"], ledger
        assert before == {str(p.relative_to(good)): base.digest(p) for p in good.rglob("*") if p.is_file()}
        self.stop()
        self.wait_no_qemu()
        self.write("result", {"passed": True, "source_unchanged": True, "live_leases": 0, "open_reservations": 0})

    def interruption_only(self):
        good = self.root / "layout-argv"
        image = layout(good, self.fixture)
        before = {str(p.relative_to(good)): base.digest(p) for p in good.rglob("*") if p.is_file()}
        self.start()
        self.interrupt_import(good)
        imported = self.vm({"action": "image", "operation": "import", "layout": str(good),
                            "ownerSelected": True, "rootGb": 0.0625}, "retry-interrupted-import")
        assert imported["id"] == image, imported
        sandbox = self.launch(image)
        assert self.wait_outcome(sandbox)["exit_code"] == 0
        self.vm({"action": "stop", "sandbox": sandbox}, "stop-after-import-retry")
        self.vm({"action": "status"}, "final-status")
        assert self.catalog("final-catalog")["catalog"]["live_leases"] == 0
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        assert before == {str(p.relative_to(good)): base.digest(p) for p in good.rglob("*") if p.is_file()}
        self.stop()
        self.wait_no_qemu()
        self.write("result", {"passed": True, "case": "import-interruption", "workspace_present_before_kill": True,
                              "source_unchanged": True, "live_leases": 0, "open_reservations": 0})

    def template_only(self):
        good = self.root / "layout-argv"
        image = layout(good, self.fixture)
        self.start()
        self.vm({"action": "image", "operation": "import", "layout": str(good),
                 "ownerSelected": True, "rootGb": 0.0625}, "template-image-import")
        draft = {"name": "OCI box", "summary": "Run an imported image in a restricted VM.", "capabilities": {
            "sandbox.vm": {"selected": True, "mode": "required", "runnerEditable": True,
                           "settings": {"vm_image": image, "vm_memory_gb": 1,
                                        "vm_idle_minutes": 30, "vm_lifetime_minutes": 60}}}}
        made = self.result("setup_validate", {"draft": draft}, "generate-template")
        package = self.root / "template"
        package.mkdir()
        files = {"yougori-template.yaml": made["manifest"], "yougori.yaml": made["project"], **made.get("files", {})}
        for name, body in files.items():
            assert Path(name).name == name, name
            (package / name).write_text(body, encoding="utf-8")
        self.command("template", "check", str(package), label="template-check")
        dry = self.command("template", "run", str(package), "--name", "oci-box", "--dry-run", label="template-review")
        assert image in json.dumps(dry), dry
        assert not self.vm({"action": "status"}, "before-template-run").get("images")
        self.command("template", "run", str(package), "--name", "oci-box", "--yes", label="template-run")
        listed = self.result("setup_list", {}, "list-setups")
        rows = listed if isinstance(listed, list) else listed["setups"]
        matches = [row for row in rows if row["name"] == "oci-box"]
        assert len(matches) == 1, matches
        setup = matches[0]["setupId"]
        details = self.result("setup_get", {"setupId": setup}, "template-details")
        sandbox = next(o["value"] for o in details["outputs"] if o["key"] == "vm_sandbox")
        self.sandboxes.append(sandbox)
        outcome = self.wait_outcome(sandbox)
        assert outcome["exit_code"] == 0 and json.loads(outcome["output_text"])["uid"] == 1000, outcome
        self.command("template", "rm", setup, "--yes", label="template-remove")
        self.vm({"action": "status"}, "final-status")
        assert self.catalog("final-catalog")["catalog"]["live_leases"] == 0
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        self.stop()
        self.wait_no_qemu()
        self.write("result", {"passed": True, "case": "template", "entrypoint_uid": 1000,
                              "live_leases": 0, "open_reservations": 0})

    def compatibility(self, encoder):
        self.start()
        completed = []
        for case, options in [("docker-gzip", {"codec":"gzip", "docker":True}),
                              ("oci-zstd", {"codec":"zstd", "encoder":encoder})]:
            folder = self.root / case
            expected = layout(folder, self.fixture, linux_names=True, **options)
            before = {str(p.relative_to(folder)):base.digest(p) for p in folder.rglob("*") if p.is_file()}
            imported = self.vm({"action":"image", "operation":"import", "layout":str(folder),
                               "ownerSelected":True, "rootGb":0.0625}, case+"-import")
            assert imported["id"] == expected and imported["inspection"] == "separate_vm", imported
            sandbox = self.launch(expected)
            outcome = self.wait_outcome(sandbox)
            assert outcome["exit_code"] == 0, outcome
            result = json.loads(outcome["output_text"])
            assert result["uid"] == 1000 and result["files"] == {n:n for n in IMAGE_NAMES}, result
            self.write(case+"-names", result)
            self.vm({"action":"stop", "sandbox":sandbox}, case+"-stop")
            self.wait_no_qemu()
            assert before == {str(p.relative_to(folder)):base.digest(p) for p in folder.rglob("*") if p.is_file()}
            completed.append(case)
        for case, options, reason in [("zstd-extra-frame", {"codec":"zstd", "encoder":encoder, "trailing":True}, "trailing_data"),
                                      ("duplicate-entry", {"duplicate":True}, "duplicate")]:
            folder = self.root / case
            layout(folder,self.fixture,**options)
            refused = self.call("sandbox_vm", {"action":"image", "operation":"import", "layout":str(folder),
                                "ownerSelected":True, "rootGb":0.0625}, case, checked=False)
            assert not refused.get("ok") and reason in json.dumps(refused), refused
            self.wait_no_qemu()
            completed.append(case+"-refused")
        self.vm({"action":"status"}, "final-status")
        assert self.catalog("final-catalog")["catalog"]["live_leases"] == 0
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        self.stop()
        self.wait_no_qemu()
        self.write("result", {"passed":True, "case":"compatibility", "checks":completed,
                              "live_leases":0, "open_reservations":0, "source_unchanged":True})

    def registry_only(self, reference, auth_origin):
        assert reference and "@sha256:" in reference, "Provide a pinned Alpine registry reference"
        self.start()
        words = ["sandbox", "image", "import", "--reference", reference,
                 "--root-gb", "0.125", "--owner-selected", "true", "--yes"]
        if auth_origin:
            words += ["--auth-origin", auth_origin]
        imported = self.command(*words, label="registry-import")["result"]
        assert imported["source"]["kind"] == "registry", imported
        assert imported["source"]["root"] == reference.split("@")[-1], imported
        assert imported["trust"] == "owner_selected" and imported["inspection"] == "separate_vm", imported
        sandbox = self.launch(imported["id"])
        result = self.vm({"action": "exec", "sandbox": sandbox,
                          "input": "id -u && /bin/arch && test -s /etc/ssl1.1/cert.pem && cat /etc/alpine-release\n",
                          "timeoutSeconds": 120}, "registry-image-command")
        lines = result["output_text"].splitlines()
        assert result["exit_code"] == 0 and len(lines) == 3, result
        assert lines[:2] == ["1000", "x86_64"] and all(p.isdigit() for p in lines[2].split(".")), result
        self.vm({"action": "stop", "sandbox": sandbox}, "stop-registry-image")
        self.vm({"action": "status"}, "final-status")
        assert self.catalog("final-catalog")["catalog"]["live_leases"] == 0
        assert not self.result("model_ledger", {}, "final-ledger")["open"]
        self.stop()
        self.wait_no_qemu()
        self.write("result", {"passed": True, "case": "registry", "reference": reference,
                              "entrypoint_uid": 1000, "alpine_version": lines[2],
                              "absolute_link_and_chain": True, "live_leases": 0, "open_reservations": 0})


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    for name in ("root", "engine", "cli", "runtime", "fixture"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--case", choices=("full", "import-interruption", "template", "registry", "compatibility"), default="full")
    parser.add_argument("--registry-reference")
    parser.add_argument("--auth-origin")
    parser.add_argument("--encoder", type=Path)
    args = parser.parse_args()
    args.reuse_fixture, args.from_case, args.model = False, None, args.fixture.parent
    run = Run(args)
    try:
        if args.case == "compatibility":
            run.compatibility(args.encoder)
        elif args.case == "registry":
            run.registry_only(args.registry_reference, args.auth_origin)
        elif args.case == "import-interruption":
            run.interruption_only()
        elif args.case == "template":
            run.template_only()
        else:
            run.run()
    finally:
        if run.process and run.process.poll() is None:
            for sandbox in run.sandboxes:
                run.call("sandbox_vm", {"action": "stop", "sandbox": sandbox}, "cleanup", checked=False)
            run.stop()
