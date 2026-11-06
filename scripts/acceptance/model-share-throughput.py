"""Matched real model/FUSE measurements on a fresh disposable acceptance engine.

The timer inside the guest measures reads and SHA256, not IPC or command startup.
First model creation includes provisioning, publication, import and readiness; it
is deliberately not labelled a pure weight-load or cold-storage measurement.
No host cache, driver, power or security setting is changed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import random
import shlex
import time

spec = importlib.util.spec_from_file_location(
    "combined_acceptance", Path(__file__).with_name("combined-model-vm.py"))
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)


class Run(combined.Combined):
    def benchmark_model(self):
        """Optional additional measurements while this exact model is loaded."""
        pass

    def guest(self, source, label):
        response = self.result("execute_environment_command", {"request": {
            "environmentId": self.environment_id,
            "command": "python3 -c " + shlex.quote(source)}}, label)
        assert response["exitCode"] == 0, response
        return json.loads(response["stdout"])

    def measure(self, path, block, label):
        source = f"""
import hashlib, json, time
h=hashlib.sha256(); count=0; started=time.perf_counter()
with open({path!r}, 'rb', buffering=0) as f:
    while True:
        block=f.read({block})
        if not block: break
        h.update(block); count+=len(block)
elapsed=time.perf_counter()-started
print(json.dumps(dict(bytes=count, sha256=h.hexdigest(), seconds=elapsed,
    mib_per_second=count/1048576/elapsed, block_bytes={block})))
"""
        result = self.guest(source, label)
        assert result["bytes"] == self.bytes and result["sha256"] == self.expected, result
        return result

    def run(self):
        source = self.root / "source"
        source.mkdir(exist_ok=self.reuse_fixture)
        payload = source / "payload.bin"
        generator = random.Random(1287303)
        if self.reuse_fixture:
            assert payload.stat().st_size == 64*1024*1024
            import hashlib
            expected = hashlib.sha256()
            for _ in range(64): expected.update(generator.randbytes(1024*1024))
            assert combined.migration.digest(payload) == expected.hexdigest(), "Prior source changed"
        else:
            with payload.open("xb") as stream:
                for _ in range(64):
                    stream.write(generator.randbytes(1024 * 1024))
        self.bytes = payload.stat().st_size
        self.expected = combined.migration.digest(payload)
        self.write("measurement-plan", {"source_bytes": self.bytes, "source_sha256": self.expected,
            "samples": 3, "block_sizes": [131072, 1048576],
            "cache": "OS-managed; source creation and hashing precede reads, no cache flush",
            "timer": "guest perf_counter around read+sha256; IPC excluded",
            "model_creation_timer": "host monotonic, creation stages included",
            "reused_own_fixture": self.reuse_fixture,
            "runtime_image_and_catalog_cache": "retained from own earlier attempt" if self.reuse_fixture else "new acceptance installation"})
        self.start()
        self.host_memory("host-before")
        self.write("gpu-before", {"note": "model residency and allocations checked on shared ledger"})
        assert not (self.ledger("ledger-before") or {}).get("open")
        begin = time.monotonic()
        resources = {"storageDrive": self.storage_drive} if self.storage_drive else {}
        created = self.result("run_model", {"model": "local/share-benchmark-qwen05",
            "folder": str(self.model), "port": self.port, "resources": resources}, "create-model")
        self.created = created
        self.environment_id = created["id"]
        health = self.wait_ready()
        self.write("first-model-ready", {"seconds": time.monotonic()-begin, "health": health})
        reply_before = self.chat("chat-before")
        self.write("runtime", self.guest("import json, platform, torch; print(json.dumps(dict(python=platform.python_version(), kernel=platform.release(), torch=torch.__version__, cuda=torch.version.cuda, gpu=torch.cuda.get_device_name(0))))", "guest-runtime"))
        share = self.result("attach_host_folder", {"environmentId": self.environment_id,
            "path": str(source), "readOnly": True}, "attach-source")
        assert share["readOnly"] is True and share["mountPath"].startswith("/"), share
        mounted = share["mountPath"] + "/payload.bin"
        samples = []
        for size in [131072, 1048576]:
            for index in range(3):
                samples.append(self.measure(mounted, size, f"share-{size}-{index}"))
        copied = self.guest(f"""
import json, shutil, time
started=time.perf_counter()
with open({mounted!r}, 'rb', buffering=0) as a, open('/tmp/yougori-share-benchmark.bin', 'xb') as b:
    shutil.copyfileobj(a,b,1048576)
print(json.dumps(dict(seconds=time.perf_counter()-started)))
""", "copy-into-guest")
        local = [self.measure("/tmp/yougori-share-benchmark.bin", 1048576, f"guest-local-{i}") for i in range(3)]
        refusal = self.guest(f"""
import json
try:
    with open({mounted!r}, 'r+b') as f: f.write(b'changed')
    denied=False
except OSError:
    denied=True
print(json.dumps(dict(denied=denied)))
""", "read-only-refusal")
        assert refusal["denied"]
        self.result("detach_host_folder", {"shareId": share["id"]}, "detach-source")
        detached = self.guest(f"""
import json, os
metadata_exists=os.path.exists({mounted!r})
try:
    with open({mounted!r}, 'rb', buffering=0) as f: content=f.read(1)
    denied=False
except OSError:
    denied=True
print(json.dumps(dict(metadata_exists=metadata_exists, read_denied=denied)))
""", "detached-read")
        # FUSE metadata may outlive an unmounted/revoked endpoint briefly. The
        # boundary is that a new read cannot obtain content, even through that entry.
        assert detached["read_denied"], detached
        assert self.chat("chat-after") == reply_before
        assert combined.migration.digest(payload) == self.expected
        assert {str(p.relative_to(self.model)): combined.migration.digest(p)
                for p in self.model.rglob("*") if p.is_file()} == self.source_hashes
        self.benchmark_model()
        self.clean()
        limit = time.monotonic() + 60
        while time.monotonic() < limit:
            ledger = self.ledger("ledger-cleanup")
            if not ledger.get("open") and not ledger.get("models"): break
            time.sleep(1)
        assert not ledger.get("open") and not ledger.get("models"), ledger
        self.catalog("catalog-cleanup", empty=True)
        self.stop()
        self.write("PASS", {"share_samples": samples, "copy": copied,
            "guest_local_samples": local, "source_unchanged": True,
            "reply_unchanged": True, "ledger_empty": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("root", "engine", "cli", "runtime", "model"):
        parser.add_argument("--"+key, required=True, type=Path)
    parser.add_argument("--port", default=18891, type=int)
    parser.add_argument("--storage-drive")
    parser.add_argument("--reuse-fixture", action="store_true", help="reuse this harness's own stopped installation; label retained caches")
    args = parser.parse_args()
    args.from_case = 0
    run = Run(args)
    run.storage_drive = args.storage_drive
    try:
        run.run()
    finally:
        run.clean()
        run.stop()


if __name__ == "__main__":
    main()
