"""Exercise payload rejection before any existing filesystem is modified."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("oci_verify", Path(__file__).with_name("verify.py"))
V = importlib.util.module_from_spec(spec)
spec.loader.exec_module(V)


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.archive = self.root / "yougori-oci-runtime-linux-amd64.tar.gz"
        self.manifest = self.root / "payload.json"
        header = bytearray(64)
        header[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<HH", header, 16, 2, 62)
        self.data = bytes(header) + b"fixture"

    def write(self, change=None, omit=None, extra=None):
        files = []
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(V.RUNTIME_PATHS):
                files.append({"path": name, "bytes": len(self.data), "mode": 0o755,
                              "sha256": hashlib.sha256(self.data).hexdigest()})
                if name == omit:
                    continue
                info = tarfile.TarInfo(name)
                info.mode, info.size = 0o755, len(self.data)
                if change and name == "bin/runc":
                    change(info)
                archive.addfile(info, io.BytesIO(self.data) if info.isfile() else None)
            if extra:
                archive.addfile(extra, io.BytesIO(self.data))
        manifest = {"schemaVersion": 1, "target": "linux/amd64", "compiler": "go1.27.2", "files": files,
                    "archive": {"file": self.archive.name, "bytes": self.archive.stat().st_size,
                                "sha256": V.sha256(self.archive)}}
        self.manifest.write_text(json.dumps(manifest))
        return manifest

    def test_complete_verified_set_extracts(self):
        self.write()
        destination = self.root / "clean"
        result = V.verify_manifest(self.archive, self.manifest, destination)
        self.assertEqual(len(result["files"]), 10)
        self.assertEqual({str(p.relative_to(destination)).replace("\\", "/") for p in destination.rglob("*") if p.is_file()}, V.RUNTIME_PATHS)

    def test_links_are_rejected_before_extraction(self):
        def link(info):
            info.type, info.linkname, info.size = tarfile.SYMTYPE, "/etc/passwd", 0
        self.write(change=link)
        destination = self.root / "untouched"
        with self.assertRaises(ValueError):
            V.verify_manifest(self.archive, self.manifest, destination)
        self.assertFalse(destination.exists())

    def test_unexpected_path_and_duplicate_are_rejected(self):
        for name in ("../escape", "bin/runc"):
            info = tarfile.TarInfo(name)
            info.mode, info.size = 0o755, len(self.data)
            self.write(extra=info)
            with self.assertRaises(ValueError):
                V.verify_manifest(self.archive, self.manifest)

    def test_missing_binary_is_rejected(self):
        self.write(omit="bin/runc")
        with self.assertRaises(ValueError):
            V.verify_manifest(self.archive, self.manifest)

    def test_changed_member_digest_is_rejected(self):
        value = self.write()
        value["files"][0]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(value))
        with self.assertRaises(ValueError):
            V.verify_manifest(self.archive, self.manifest)

    def test_expanded_size_is_bounded_before_decompression(self):
        value = self.write()
        for record in value["files"]:
            record["bytes"] = V.MAX_FILE
        self.manifest.write_text(json.dumps(value))
        with self.assertRaisesRegex(ValueError, "expanded"):
            V.verify_manifest(self.archive, self.manifest)

    def test_nonempty_destination_preserves_existing_file(self):
        self.write()
        destination = self.root / "existing"
        destination.mkdir()
        original = destination / "user-data"
        original.write_text("preserve")
        with self.assertRaises(ValueError):
            V.verify_manifest(self.archive, self.manifest, destination)
        self.assertEqual(original.read_text(), "preserve")
        self.assertEqual(list(destination.iterdir()), [original])

    def test_boolean_schema_or_size_is_not_an_integer(self):
        for field in ("schemaVersion", "bytes"):
            value = self.write()
            if field == "schemaVersion":
                value[field] = True
            else:
                value["files"][0][field] = True
            self.manifest.write_text(json.dumps(value))
            with self.assertRaises(ValueError):
                V.verify_manifest(self.archive, self.manifest)

    def test_source_path_replacement_cannot_swap_extracted_bytes(self):
        self.write()
        original_reader = V.read_regular
        def replacing_reader(path, limit):
            data = original_reader(path, limit)
            if path == self.archive:
                path.write_bytes(b"unverified archive replacement")
            return data
        destination = self.root / "bound-snapshot"
        with mock.patch.object(V, "read_regular", side_effect=replacing_reader):
            V.verify_manifest(self.archive, self.manifest, destination)
        self.assertEqual((destination / "bin/runc").read_bytes(), self.data)


if __name__ == "__main__":
    unittest.main()
