"""Uploaded artifacts are verified offline in the GPU mount before model loading."""
import hashlib
import base64
import json
import os
import tempfile
import unittest
import zlib
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault("YOUGORI_MODEL", "yg/test/tiny")
os.environ.setdefault("YOUGORI_MODEL_TOKEN", "private-test-token")
os.environ["YOUGORI_REGISTRY_SOURCE"] = base64.b64encode(zlib.compress((Path(__file__).parent / "model_runner/registry_snapshot.py").read_bytes().replace(b"\r\n", b"\n"))).decode("ascii")
import model_server as model

class RegistrySnapshotTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="yougori-registry-model-")
        self.revision = "a" * 64
        self.saved = (model.MODEL_PATH, model.MODEL_REVISION)
        model.MODEL_PATH, model.MODEL_REVISION = self.folder.name, self.revision
        self.bytes = b"uploaded safe model weights"
        with open(os.path.join(self.folder.name, "model.safetensors"), "wb") as file:
            file.write(self.bytes)
        self.manifest = {"revision": self.revision, "files": [{"name": "model.safetensors", "size": len(self.bytes), "sha256": hashlib.sha256(self.bytes).hexdigest()}]}
        self.write_manifest()
    def write_manifest(self):
        with open(os.path.join(self.folder.name, ".yougori-verified-files.json"), "w", encoding="utf-8") as file:
            json.dump(self.manifest, file)
    def tearDown(self):
        model.MODEL_PATH, model.MODEL_REVISION = self.saved
        self.folder.cleanup()
    def test_uploaded_snapshot_uses_local_weights_without_hugging_face_requests(self):
        with patch.object(model, "download_snapshot", side_effect=AssertionError("Unexpected network download")):
            self.assertEqual(model.verified_snapshot(self.revision), self.folder.name)
        self.assertEqual(model.STATE["download"]["transport"], "yougori-registry")
    def test_tampered_weights_and_revision_fail_before_loading(self):
        with open(os.path.join(self.folder.name, "model.safetensors"), "wb") as file:
            file.write(b"changed")
        with self.assertRaisesRegex(RuntimeError, "checksum"):
            model.registry_snapshot()
        self.manifest["revision"] = "b" * 64
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "revision"):
            model.registry_snapshot()
    def test_unsafe_artifact_paths_are_rejected(self):
        for path in ["../private", "/private", "folder\\private"]:
            self.manifest["files"][0]["name"] = path
            self.write_manifest()
            with self.assertRaisesRegex(RuntimeError, "identity"):
                model.registry_snapshot()

if __name__ == "__main__":
    unittest.main()
