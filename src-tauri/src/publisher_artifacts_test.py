"""Actual HTTP download routes, without a GPU or third-party model dependencies."""
import base64
import hashlib
import hmac
import io
import json
import os
import tarfile
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
import zlib
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("YOUGORI_MODEL", "owner/tiny")
os.environ.setdefault("YOUGORI_MODEL_TOKEN", "private-test-token")
os.environ["YOUGORI_PUBLISHER_SOURCE"] = base64.b64encode(zlib.compress((Path(__file__).parent / "model_runner/publisher_artifacts.py").read_bytes())).decode()
import model_server as model

class PublisherTests(unittest.TestCase):
    def setUp(self):
        model.PUBLISH_VALIDATING = False
        model.STATE.pop("sourceOnly", None)
        self.folder = tempfile.TemporaryDirectory()
        root = Path(self.folder.name)
        self.weights = b"test safe weights" * 100
        (root / "model.safetensors").write_bytes(self.weights)
        (root / "config.json").write_text('{"model_type":"llama"}')
        (root / "tokenizer.json").write_text('{}')
        (root / "yougori-usage.json").write_text('private usage')
        (root / "chat-history.json").write_text('private conversation')
        (root / ".env").write_text('private credentials')
        (root / "disk.qcow2").write_text('private disk')
        model.MODEL_SNAPSHOT_ROOT, model.MODEL_SNAPSHOT_FILES = self.folder.name, None
        model.STATE.update(status="ready", revision="a" * 40)
        model.PUBLISH_ENABLED, model.PUBLISH_MANIFEST = True, None
        model.publisher_build()
        self.manifest = model.publisher_snapshot()
        self.server = model.Server(("127.0.0.1", 0), model.Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.base = "http://127.0.0.1:" + str(self.server.server_port)
    def tearDown(self):
        model.STATE.pop("sourceOnly", None)
        self.server.shutdown(); self.server.server_close(); self.thread.join()
        self.folder.cleanup()
    def cap(self, scope="part", **fields):
        payload = {"scope": scope, "revision": self.manifest["artifactRevision"], "exp": int(time.time()) + 300, **fields}
        value = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        return value + "." + hmac.new(model.TOKEN.encode(), value.encode(), hashlib.sha256).hexdigest()
    def request(self, path, owner=False, body=None):
        request = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(), headers={"Authorization": "Bearer " + model.TOKEN} if owner else {})
        try:
            with urllib.request.urlopen(request) as response:
                return response.status, response.read()
        except urllib.error.HTTPError as error:
            return error.code, error.read()
    def test_only_model_assets_are_exported_and_bundle_streams_real_files(self):
        self.assertEqual({f["name"] for f in self.manifest["files"]}, {"model.safetensors", "config.json", "tokenizer.json"})
        status, data = self.request("/v1/yougori/bundle?grant=" + self.cap("bundle"))
        self.assertEqual(status, 200)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            self.assertEqual(set(archive.getnames()), {f["name"] for f in self.manifest["files"]})
            self.assertEqual(archive.extractfile("model.safetensors").read(), self.weights)
    def test_downloads_remain_available_while_verified_gpu_weights_are_idle(self):
        with patch.object(model, "GPU_ENABLED", True), patch.dict(model.STATE, {"status":"idle", "weightsVerified":True}):
            status, data = self.request("/v1/yougori/artifacts", owner=True)
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(data)["artifactRevision"], self.manifest["artifactRevision"])
            self.assertEqual(self.request("/v1/yougori/bundle?grant=" + self.cap("bundle"))[0], 200)
            model.STATE["status"]="error"
            with self.assertRaises(ValueError): model.publisher_files()

    def test_closed_publisher_exposes_only_bounded_license_card_metadata_to_gateway(self):
        root = Path(self.folder.name)
        (root / "README.md").write_text('---\nlicense: apache-2.0\n---\nMy model', encoding="utf-8")
        (root / "LICENSE").write_text('Apache License\nVersion 2.0', encoding="utf-8")
        (root / "CITATION.cff").write_text('title: Test model', encoding="utf-8")
        model.PUBLISH_ENABLED = False
        status, data = self.request("/v1/yougori/metadata", owner=True)
        self.assertEqual(status, 200)
        metadata = json.loads(data)
        names = {item["name"] for item in metadata["files"]}
        self.assertEqual(names, {"README.md", "LICENSE", "CITATION.cff", "config.json"})
        for item in metadata["files"]:
            raw = base64.b64decode(item["data"])
            self.assertEqual(hashlib.sha256(raw).hexdigest(), item["sha256"])
        self.assertEqual(self.request("/v1/yougori/metadata")[0], 403)
        self.assertEqual(self.request("/v1/yougori/bundle?grant=" + self.cap("bundle"))[0], 403)
    def test_source_only_publisher_exports_code_and_empty_files_but_never_serves_inference(self):
        root = Path(self.folder.name)
        (root / "model.safetensors").unlink()
        (root / "modeling_quadorbit.py").write_text("raise AssertionError('must never execute')")
        (root / "__init__.py").write_bytes(b"")
        (root / "requirements.txt").write_text("transformers>=5.0")
        model.STATE.update(sourceOnly=True, inferenceAvailable=False)
        model.publisher_build()
        self.manifest = model.publisher_snapshot()
        self.assertTrue(self.manifest["sourceOnly"])
        self.assertFalse(self.manifest["inferenceAvailable"])
        self.assertEqual(self.request("/v1/chat/completions", owner=True, body={"messages": [{"role":"user","content":"Hello"}]})[0], 503)
        self.assertEqual(json.loads(self.request("/v1/models", owner=True)[1])["data"], [])
        code, data = self.request("/v1/yougori/bundle?grant=" + self.cap("bundle"))
        self.assertEqual(code, 200)
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            self.assertEqual(archive.extractfile("__init__.py").read(), b"")
            self.assertIn("modeling_quadorbit.py", archive.getnames())
            self.assertNotIn("chat-history.json", archive.getnames())
    def test_grants_are_file_scoped_and_do_not_authorize_inference_or_metadata(self):
        index = next(i for i, f in enumerate(self.manifest["files"]) if f["name"] == "model.safetensors")
        grant = self.cap(file=index, part=0)
        self.assertEqual(self.request("/v1/yougori/part?grant=" + grant), (200, self.weights))
        self.assertEqual(self.request("/v1/yougori/artifacts?grant=" + grant)[0], 403)
        self.assertEqual(self.request("/health?grant=" + grant)[0], 401)
        self.assertEqual(self.request("/v1/yougori/part?grant=" + grant[:-1] + "x")[0], 403)
        self.assertEqual(self.request("/v1/yougori/bundle?grant=" + grant)[0], 403)
        self.assertEqual(self.request("/v1/yougori/part?grant=" + self.cap(file=index, part=0, exp=int(time.time())-1))[0], 403)
    def test_closed_transition_immediately_revokes_existing_grants_without_reloading(self):
        grant = self.cap("bundle")
        self.assertEqual(self.request("/v1/yougori/publishing", body={"downloads": False})[0], 401)
        self.assertEqual(self.request("/v1/yougori/publishing", owner=True, body={"downloads": False})[0], 200)
        self.assertEqual(self.request("/v1/yougori/bundle?grant=" + grant)[0], 403)
        self.assertEqual(model.STATE["status"], "ready")
        self.request("/v1/yougori/publishing", owner=True, body={"downloads": True})
        self.assertEqual(self.request("/v1/yougori/artifacts", owner=True)[0], 200)
    def test_changed_files_are_not_served_under_the_old_manifest(self):
        (Path(self.folder.name) / "model.safetensors").write_bytes(b"changed")
        self.assertEqual(self.request("/v1/yougori/bundle?grant=" + self.cap("bundle"))[0], 403)
        self.assertEqual(self.request("/v1/yougori/artifacts", owner=True)[0], 503)
    def test_shared_folder_identity_changes_revalidate_bytes_without_republishing(self):
        revision = self.manifest["artifactRevision"]
        model.PUBLISH_STATS = [(path, (before[0] + 1, before[1] + 100, before[2], before[3])) for path, before in model.PUBLISH_STATS]
        self.assertEqual(self.request("/v1/yougori/artifacts", owner=True)[0], 200)
        self.assertEqual(model.publisher_snapshot()["artifactRevision"], revision)
        self.assertTrue(all(model.file_stat(path) == before for path, before in model.PUBLISH_STATS))
        weight = Path(self.folder.name) / "model.safetensors"
        weight.write_bytes(b"x" * len(self.weights))
        self.assertEqual(self.request("/v1/yougori/artifacts", owner=True)[0], 503)
    def test_large_identity_changes_verify_in_background_without_blocking_download_control(self):
        from unittest.mock import patch
        model.PUBLISH_STATS = [(path, (before[0], before[1] + 1, before[2], before[3])) for path, before in model.PUBLISH_STATS]
        with patch.object(model, "PART_BYTES", 8):
            self.assertEqual(self.request("/v1/yougori/artifacts", owner=True)[0], 503)
            deadline = time.monotonic() + 3
            while model.PUBLISH_VALIDATING and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertFalse(model.PUBLISH_VALIDATING)
            self.assertIsNone(model.PUBLISH_ERROR)
            self.assertEqual(self.request("/v1/yougori/artifacts", owner=True)[0], 200)

if __name__ == "__main__": unittest.main()
