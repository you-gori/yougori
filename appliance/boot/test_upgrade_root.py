"""Regression tests for updating preserved appliance disks before boot."""

from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
UPDATER = ROOT / "appliance/boot/upgrade-root.sh"
spec = importlib.util.spec_from_file_location("prepare_initramfs", ROOT / "scripts/prepare-appliance-initramfs.py")
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class BootUpgradeTests(unittest.TestCase):
    def fixture(self, temp):
        root, payload = Path(temp) / "legacy-root", Path(temp) / "trusted-initramfs"
        root.mkdir()
        payload.mkdir()
        for entry in prepare.PAYLOAD_FILES:
            name = entry.lstrip("/")
            source = payload / name
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_bytes(b"current-security-payload:" + name.encode())
        return root, payload

    def run_upgrade(self, root, payload):
        return subprocess.run(["/bin/sh", str(UPDATER), str(root), str(payload)], capture_output=True)

    def test_updates_legacy_agent_and_preserves_application_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            legacy_agent = root / "usr/local/sbin/opendock-agent"
            legacy_agent.parent.mkdir(parents=True)
            legacy_agent.write_bytes(b"old-agent")
            application = root / "var/lib/opendock/container-storage/project/data.db"
            application.parent.mkdir(parents=True)
            application.write_bytes(b"user data stays byte-for-byte")
            result = self.run_upgrade(root, payload)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(legacy_agent.read_bytes(), (payload / "usr/local/sbin/opendock-agent").read_bytes())
            self.assertEqual(legacy_agent.stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / "etc/sysctl.d/90-yougori-security.conf").stat().st_mode & 0o777, 0o644)
            self.assertEqual(application.read_bytes(), b"user data stays byte-for-byte")
            result = self.run_upgrade(root, payload)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(application.read_bytes(), b"user data stays byte-for-byte")
            self.assertEqual(list(root.rglob(".yougori-boot.*")), [])

    def test_rejects_symlinked_destination_ancestors(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            external = Path(temp) / "outside"
            external.mkdir()
            (root / "usr").symlink_to(external, target_is_directory=True)
            result = self.run_upgrade(root, payload)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(list(external.iterdir()), [])

    def test_replaces_leaf_symlink_without_modifying_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            original = Path(temp) / "user-original"
            original.write_bytes(b"preserve the symlink target")
            agent = root / "usr/local/sbin/opendock-agent"
            agent.parent.mkdir(parents=True)
            agent.symlink_to(original)
            result = self.run_upgrade(root, payload)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertFalse(agent.is_symlink())
            self.assertEqual(original.read_bytes(), b"preserve the symlink target")

    def test_replaces_hardlinked_leaf_without_changing_other_link(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            source = payload / "usr/local/sbin/opendock-agent"
            other = Path(temp) / "user-linked-file"
            other.write_bytes(source.read_bytes())
            other.chmod(0o600)
            agent = root / "usr/local/sbin/opendock-agent"
            agent.parent.mkdir(parents=True)
            os.link(other, agent)
            result = self.run_upgrade(root, payload)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(other.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(other.stat().st_ino, agent.stat().st_ino)

    def test_patches_both_disk_and_diskless_switch_root_sites(self):
        source = 'sysroot="$ROOT"/sysroot\nif true; then\n\texec switch_root $sysroot "$KOPT_init"\nfi\nexec switch_root $sysroot "$KOPT_init"\n'
        patched = prepare.patch_init(source)
        self.assertEqual(patched.count('yougori-upgrade-root "$sysroot"'), 2)
        for entry in patched.splitlines():
            if "yougori-upgrade-root" in entry:
                self.assertIn("exit 1", entry)
        for malformed in ["exec switch_root /sysroot /sbin/init\n", source + 'exec switch_root $sysroot "$KOPT_init"\n']:
            with self.assertRaises(ValueError):
                prepare.patch_init(malformed)


if __name__ == "__main__":
    unittest.main()
