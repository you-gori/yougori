import hashlib
import importlib.util
import io
import json
from pathlib import Path
import struct
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("nvidia_verify", Path(__file__).with_name("verify.py"))
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


class TrustedNvidiaPayload(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        self.archive = self.root / "yougori-nvidia-cdi-linux-amd64.tar.gz"
        self.manifest = self.root / "yougori-nvidia-cdi-linux-amd64.manifest.json"
        self.contents = bytearray(64)
        self.contents[:6] = b"\x7fELF\x02\x01"
        struct.pack_into("<H", self.contents, 16, 2)
        struct.pack_into("<H", self.contents, 18, 62)

    def payload(self, extra=None, link=False):
        files = []
        with tarfile.open(self.archive, "w:gz", format=tarfile.USTAR_FORMAT) as archive:
            for name in sorted(verify.PATHS):
                member = tarfile.TarInfo(name)
                member.mode, member.size = 0o755, len(self.contents)
                if link and name.endswith("nvidia-ctk"):
                    member.type, member.linkname, member.size = tarfile.SYMTYPE, "/tmp/other", 0
                archive.addfile(member, io.BytesIO(self.contents) if member.isfile() else None)
                files.append({"path": name, "mode": 0o755, "bytes": len(self.contents), "sha256": hashlib.sha256(self.contents).hexdigest()})
            if extra:
                member = tarfile.TarInfo(extra)
                member.mode, member.size = 0o755, len(self.contents)
                archive.addfile(member, io.BytesIO(self.contents))
        record = {"schemaVersion": 1, "kind": "nvidia-cdi", "target": "linux/amd64", "compiler": "go1.27.2", "archive": {"file": self.archive.name, "bytes": self.archive.stat().st_size, "sha256": verify.digest(self.archive)}, "files": files}
        self.manifest.write_text(json.dumps(record))
        return record

    def test_exact_two_approved_tools(self):
        self.payload()
        self.assertEqual(len(verify.verify_manifest(self.archive, self.manifest)["files"]), 2)

    def test_extra_runtime_is_rejected(self):
        self.payload(extra="bin/nvidia-container-runtime")
        with self.assertRaisesRegex(ValueError, "Unexpected"):
            verify.verify_manifest(self.archive, self.manifest)

    def test_link_is_rejected(self):
        self.payload(link=True)
        with self.assertRaisesRegex(ValueError, "Non-regular"):
            verify.verify_manifest(self.archive, self.manifest)

    def test_corrupted_digest_is_rejected(self):
        data = self.payload()
        data["files"][0]["sha256"] = "0" * 64
        self.manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "digest mismatch"):
            verify.verify_manifest(self.archive, self.manifest)

    def test_oci_kind_is_rejected(self):
        data = self.payload()
        data["kind"] = "oci-runtime"
        self.manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            verify.verify_manifest(self.archive, self.manifest)

    def test_wrong_architecture_is_rejected(self):
        struct.pack_into("<H", self.contents, 18, 183)
        self.payload()
        with self.assertRaisesRegex(ValueError, "AMD64"):
            verify.verify_manifest(self.archive, self.manifest)

    def test_duplicate_manifest_key_is_rejected(self):
        self.payload()
        self.manifest.write_text('{"kind":"nvidia-cdi","kind":"nvidia-cdi"}')
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            verify.verify_manifest(self.archive, self.manifest)

    def test_boolean_schema_is_rejected(self):
        data = self.payload()
        data["schemaVersion"] = True
        self.manifest.write_text(json.dumps(data))
        with self.assertRaisesRegex(ValueError, "Unsupported"):
            verify.verify_manifest(self.archive, self.manifest)


if __name__ == "__main__":
    unittest.main()
