"""Uploaded artifacts are verified offline in the GPU mount before model loading."""
import hashlib
import base64
import json
import os
import re
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
        scratch = "D:/YougoriBuildCache/scratch"
        self.folder = tempfile.TemporaryDirectory(prefix="yougori-registry-model-", dir=scratch if os.path.isdir(scratch) else None)
        environment = dict(os.environ)
        environment.pop("YOUGORI_LOCAL_MANIFEST", None)
        environment_patch = patch.object(model.os, "environ", environment)
        environment_patch.start()
        self.addCleanup(environment_patch.stop)
        self.revision = "a" * 64
        self.saved = (model.MODEL_PATH, model.MODEL_REVISION, model.REGISTRY_VERIFIED)
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
        model.MODEL_PATH, model.MODEL_REVISION, model.REGISTRY_VERIFIED = self.saved
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
        for path in ["../private", "/private", "folder\\private", "", ".", "./model.safetensors",
                     "dir//weights", "C:/private", "C:private", "name:stream", "name\0private",
                     "dir/../weights", "dir/./weights", "dir./weights", "a" * 241]:
            self.manifest["files"][0]["name"] = path
            self.write_manifest()
            with patch.object(model, "verify_file", side_effect=AssertionError("hashed invalid name")), self.assertRaisesRegex(RuntimeError, "identity"):
                model.registry_snapshot()

    def assert_refused_before_hashing(self, record, pattern="manifest|identity|revision"):
        for source in ("file", "environment"):
            encoded = json.dumps(record)
            if source == "file":
                model.os.environ.pop("YOUGORI_LOCAL_MANIFEST", None)
                Path(self.folder.name, ".yougori-verified-files.json").write_text(encoded, encoding="utf-8")
            else:
                model.os.environ["YOUGORI_LOCAL_MANIFEST"] = encoded
            with self.subTest(source=source), patch.object(model, "verify_file", side_effect=AssertionError("hashed before preflight")), \
                 self.assertRaisesRegex(RuntimeError, pattern):
                model.registry_snapshot()

    def test_non_object_and_invalid_file_list_shapes_are_safe_errors(self):
        for record in (None, [], "PRIVATE", {}, {"revision": self.revision, "files": None},
                       {"revision": self.revision, "files": []},
                       {"revision": self.revision, "files": [self.manifest["files"][0]] * 513},
                       {**self.manifest, "extra": "PRIVATE"}):
            self.assert_refused_before_hashing(record)

    def test_all_entries_are_validated_before_any_artifact_hash(self):
        good = self.manifest["files"][0]
        other = {**good, "name": "other.safetensors"}
        invalid = [None, [], "PRIVATE", {}, {**other, "extra": "PRIVATE"}]
        invalid += [{**other, "size": value} for value in (None, True, -1, 1.5, "12", 2**63)]
        invalid += [{**other, "sha256": value} for value in (None, [], 12, True, "z" * 64)]
        invalid += [{**good, "name": value} for value in (None, [], 12)]
        for bad in invalid:
            self.assert_refused_before_hashing({"revision": self.revision, "files": [good, bad]})

    def test_duplicate_names_and_json_fields_are_rejected(self):
        self.assert_refused_before_hashing({"revision": self.revision, "files": self.manifest["files"] * 2})
        encoded = json.dumps(self.manifest)
        for duplicate in (encoded.replace('"files":', '"files": [], "files":', 1),
                          encoded.replace('"size":', '"size": 0, "size":', 1)):
            model.os.environ["YOUGORI_LOCAL_MANIFEST"] = duplicate
            with patch.object(model, "verify_file", side_effect=AssertionError("hashed duplicate JSON")), \
                 self.assertRaisesRegex(RuntimeError, "manifest"):
                model.registry_snapshot()

    def test_manifest_byte_limit_applies_before_json_parsing_to_both_sources(self):
        limit = 1024 * 1024
        path = Path(self.folder.name, ".yougori-verified-files.json")
        for source in ("file", "environment"):
            for value in (" " * (limit + 1), "\u00e9" * (limit // 2 + 1)):
                if source == "file":
                    model.os.environ.pop("YOUGORI_LOCAL_MANIFEST", None)
                    path.write_bytes(value.encode("utf-8"))
                else:
                    model.os.environ["YOUGORI_LOCAL_MANIFEST"] = value
                with self.subTest(source=source, chars=len(value)), \
                     patch.object(model.json, "loads", side_effect=AssertionError("parsed oversized manifest")), \
                     self.assertRaisesRegex(RuntimeError, "manifest"):
                    model.registry_snapshot()

    def test_exact_byte_limit_is_accepted_for_engine_manifest(self):
        encoded = json.dumps(self.manifest)
        encoded += " " * (1024 * 1024 - len(encoded.encode("utf-8")))
        for source in ("file", "environment"):
            if source == "file":
                model.os.environ.pop("YOUGORI_LOCAL_MANIFEST", None)
                Path(self.folder.name, ".yougori-verified-files.json").write_bytes(encoded.encode("utf-8"))
            else:
                model.os.environ["YOUGORI_LOCAL_MANIFEST"] = encoded
            self.assertEqual(model.registry_snapshot(), self.folder.name)

    def test_invalid_encoding_deep_json_and_empty_environment_are_safe_errors(self):
        path = Path(self.folder.name, ".yougori-verified-files.json")
        for value in (b"\xffPRIVATE", b"[" * 2000 + b"0" + b"]" * 2000):
            path.write_bytes(value)
            with patch.object(model, "verify_file", side_effect=AssertionError("hashed invalid JSON")), \
                 self.assertRaisesRegex(RuntimeError, "manifest") as error:
                model.registry_snapshot()
            self.assertNotIn("PRIVATE", str(error.exception))
        self.write_manifest()
        model.os.environ["YOUGORI_LOCAL_MANIFEST"] = ""
        with self.assertRaisesRegex(RuntimeError, "manifest"):
            model.registry_snapshot()

    def test_nested_files_git_hash_and_empty_files_remain_supported(self):
        Path(self.folder.name, "nested").mkdir()
        Path(self.folder.name, "nested", "weights.gguf").write_bytes(self.bytes)
        Path(self.folder.name, "config.json").write_bytes(b"")
        git_digest = hashlib.sha1(b"blob " + str(len(self.bytes)).encode() + b"\0" + self.bytes).hexdigest()
        model.MODEL_REVISION = "a" * 40
        self.manifest = {"revision": model.MODEL_REVISION, "files": [
            {"name": "nested/weights.gguf", "size": len(self.bytes), "sha256": git_digest},
            {"name": "config.json", "size": 0, "sha256": hashlib.sha256(b"").hexdigest()}]}
        model.os.environ["YOUGORI_LOCAL_MANIFEST"] = json.dumps(self.manifest)
        self.assertEqual(model.registry_snapshot(), self.folder.name)
        self.assertEqual(model.MODEL_SNAPSHOT_FILES, ["nested/weights.gguf", "config.json"])
        self.assertEqual(model.STATE["download"]["totalBytes"], len(self.bytes))

    def test_hardlink_aliases_are_rejected_before_hashing(self):
        os.link(Path(self.folder.name, "model.safetensors"), Path(self.folder.name, "alias.safetensors"))
        self.manifest["files"].append({**self.manifest["files"][0], "name": "alias.safetensors"})
        self.assert_refused_before_hashing(self.manifest)

    def test_resolved_path_escape_is_rejected_before_stat_or_hash(self):
        root = os.path.realpath(self.folder.name)
        realpath = model.os.path.realpath

        def escape(path):
            return root + "-outside" if path.endswith("model.safetensors") else realpath(path)

        with patch.object(model.os.path, "realpath", side_effect=escape), \
             patch.object(model.os, "stat", side_effect=AssertionError("stat outside root")), \
             patch.object(model, "verify_file", side_effect=AssertionError("hash outside root")), \
             self.assertRaisesRegex(RuntimeError, "identity"):
            model.registry_snapshot()

    def test_failed_revalidation_clears_previous_verification_state(self):
        self.assertEqual(model.registry_snapshot(), self.folder.name)
        self.assertIsNotNone(model.REGISTRY_VERIFIED)
        self.manifest["files"][0]["sha256"] = "b" * 64
        self.write_manifest()
        with self.assertRaisesRegex(RuntimeError, "checksum"):
            model.registry_snapshot()
        self.assertIsNone(model.REGISTRY_VERIFIED)
        self.assertFalse(hasattr(model, "MODEL_SNAPSHOT_FILES"))
        self.assertFalse(hasattr(model, "MODEL_SNAPSHOT_ROOT"))

    def test_embedded_verifier_digest_matches_exact_lf_source(self):
        source = Path(__file__).parent
        helper = (source / "model_runner/registry_snapshot.py").read_bytes().replace(b"\r\n", b"\n")
        server = (source / "model_server.py").read_text(encoding="utf-8")
        pattern = r'if hashlib.sha256\(source\).hexdigest\(\) != "([a-f0-9]{64})":\s+raise RuntimeError\("Bundled registry verifier'
        self.assertEqual(re.findall(pattern, server), [hashlib.sha256(helper).hexdigest()])

if __name__ == "__main__":
    unittest.main()
