"""Regression tests for updating preserved appliance disks before boot."""

from pathlib import Path
import importlib.util
import hashlib
import io
import os
import subprocess
import tempfile
import tarfile
import unittest
from unittest import mock

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
        modules = payload / "usr/local/lib/yougori-boot"
        modules.mkdir(parents=True, exist_ok=True)
        kernel = os.uname().release
        (modules / "kernel-version").write_text(kernel + "\n")
        archive = modules / "kernel-modules.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            info = tarfile.TarInfo(kernel + "/kernel/fs/fuse/fuse.ko")
            info.size = len(b"trusted-module")
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(b"trusted-module"))
        (modules / "kernel-modules.sha256").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "\n")
        self.write_vendor_files(payload)
        prepare.prepare_vendor(payload)
        return root, payload

    def write_vendor_files(self, payload):
        for name in prepare.VENDOR_FILES:
            executable = payload / name
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00" + name.encode())

    def replace_vendor_archive(self, payload, changed_name, change):
        archive = payload / "usr/local/lib/yougori-boot/oci-runtime.tar.gz"
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for name in prepare.VENDOR_FILES:
                info = tarfile.TarInfo(name)
                info.mode = 0o755
                contents = (payload / name).read_bytes()
                info.size = len(contents)
                if name == changed_name:
                    if change == "escape":
                        info.name = "../../outside"
                    else:
                        info.type = tarfile.SYMTYPE if change == "symlink" else tarfile.LNKTYPE
                        info.linkname = "/etc/passwd"
                        info.size = 0
                tar.addfile(info, io.BytesIO(contents) if info.isfile() else None)
        archive.with_name("oci-runtime.sha256").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "\n")

    def run_upgrade(self, root, payload):
        busybox = os.environ.get("YOUGORI_BOOT_TEST_BUSYBOX")
        if not busybox:
            return subprocess.run(["/bin/sh", str(UPDATER), str(root), str(payload)], capture_output=True)
        with tempfile.TemporaryDirectory(prefix="yougori-boot-busybox-") as directory:
            applets = subprocess.check_output([busybox, "--list"], text=True).splitlines()
            for applet in applets:
                (Path(directory) / applet).symlink_to(busybox)
            return subprocess.run([busybox, "sh", str(UPDATER), str(root), str(payload)],
                                  env={**os.environ, "PATH": directory}, capture_output=True)

    def test_updates_legacy_agent_and_preserves_application_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            legacy_agent = root / "usr/local/sbin/opendock-agent"
            legacy_agent.parent.mkdir(parents=True)
            legacy_agent.write_bytes(b"old-agent")
            legacy_helper = root / "usr/local/sbin/opendock-mount-helper"
            legacy_helper.write_bytes(b"old-mount-helper")
            application = root / "var/lib/opendock/container-storage/project/data.db"
            application.parent.mkdir(parents=True)
            application.write_bytes(b"user data stays byte-for-byte")
            result = self.run_upgrade(root, payload)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(legacy_agent.read_bytes(), (payload / "usr/local/sbin/opendock-agent").read_bytes())
            self.assertEqual(legacy_helper.read_bytes(), (payload / "usr/local/sbin/opendock-mount-helper").read_bytes())
            self.assertEqual(legacy_agent.stat().st_mode & 0o777, 0o755)
            self.assertEqual((root / "etc/sysctl.d/90-yougori-security.conf").stat().st_mode & 0o777, 0o644)
            self.assertEqual(application.read_bytes(), b"user data stays byte-for-byte")
            self.assertEqual((root / "lib/modules" / os.uname().release / "kernel/fs/fuse/fuse.ko").read_bytes(), b"trusted-module")
            for name in prepare.VENDOR_FILES:
                self.assertEqual((root / name).read_bytes(), (payload / name).read_bytes())
                self.assertEqual((root / name).stat().st_mode & 0o777, 0o755)
            result = self.run_upgrade(root, payload)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(application.read_bytes(), b"user data stays byte-for-byte")
            self.assertEqual(list(root.rglob(".yougori-boot.*")), [])
            self.assertEqual(list(root.glob(".yougori-oci.*")), [])

    def test_replaces_complete_legacy_vendor_set_and_preserves_link_targets(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            for name in prepare.VENDOR_FILES:
                executable = root / name
                executable.parent.mkdir(parents=True, exist_ok=True)
                executable.write_bytes(b"old vulnerable vendor executable")
            user_link = Path(temp) / "outside-user-file"
            user_link.write_bytes((payload / prepare.VENDOR_FILES[0]).read_bytes())
            user_link.chmod(0o600)
            containerd = root / prepare.VENDOR_FILES[0]
            containerd.unlink()
            os.link(user_link, containerd)
            external = Path(temp) / "outside-symlink-file"
            external.write_bytes(b"keep user file")
            nerdctl = root / "usr/local/bin/nerdctl"
            nerdctl.unlink()
            nerdctl.symlink_to(external)
            result = self.run_upgrade(root, payload)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            for name in prepare.VENDOR_FILES:
                self.assertEqual((root / name).read_bytes(), (payload / name).read_bytes())
                self.assertFalse((root / name).is_symlink())
            self.assertEqual(user_link.stat().st_mode & 0o777, 0o600)
            self.assertNotEqual(user_link.stat().st_ino, containerd.stat().st_ino)
            self.assertEqual(external.read_bytes(), b"keep user file")

    def test_vendor_rejects_tamper_and_invalid_manifest_before_replacements(self):
        for tamper in ("archive", "digest", "unexpected-path", "duplicate", "oversized-file", "oversized-total"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as temp:
                root, payload = self.fixture(temp)
                legacy = root / "usr/local/bin/containerd"
                legacy.parent.mkdir(parents=True)
                legacy.write_bytes(b"preserved until complete verification")
                boot = payload / "usr/local/lib/yougori-boot"
                if tamper == "archive":
                    with (boot / "oci-runtime.tar.gz").open("ab") as archive:
                        archive.write(b"tampered")
                else:
                    manifest = boot / "oci-runtime.files"
                    lines = manifest.read_text().splitlines()
                    if tamper == "digest":
                        fields = lines[-1].split()
                        fields[0] = "0" * 64
                        lines[-1] = " ".join(fields)
                    elif tamper == "unexpected-path":
                        lines[-1] = lines[-1].replace(prepare.VENDOR_FILES[-1], "../../outside")
                    elif tamper == "duplicate":
                        lines[-1] = lines[0]
                    else:
                        for index in range(len(lines) if tamper == "oversized-total" else 1):
                            fields = lines[index].split()
                            fields[1] = str(prepare.MAX_VENDOR_FILE_BYTES + (tamper == "oversized-file"))
                            lines[index] = " ".join(fields)
                    manifest.write_text("\n".join(lines) + "\n")
                result = self.run_upgrade(root, payload)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(legacy.read_bytes(), b"preserved until complete verification")
                self.assertFalse((root / "usr/local/sbin/opendock-agent").exists())
                self.assertEqual(list(root.glob(".yougori-oci.*")), [])

    def test_vendor_archive_rejects_links_and_escape_even_with_matching_archive_hash(self):
        for change in ("escape", "symlink", "hardlink"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                root, payload = self.fixture(temp)
                self.replace_vendor_archive(payload, prepare.VENDOR_FILES[-1], change)
                result = self.run_upgrade(root, payload)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "usr/local/bin/containerd").exists())
                self.assertFalse((Path(temp) / "outside").exists())
                self.assertEqual(list(root.glob(".yougori-oci.*")), [])

    def test_vendor_preflights_all_destination_ancestors(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            legacy = root / "usr/local/bin/containerd"
            legacy.parent.mkdir(parents=True)
            legacy.write_bytes(b"do not partially upgrade")
            external = Path(temp) / "outside-cni"
            external.mkdir()
            cni = root / "usr/local/libexec/cni"
            cni.parent.mkdir(parents=True)
            cni.symlink_to(external, target_is_directory=True)
            result = self.run_upgrade(root, payload)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(legacy.read_bytes(), b"do not partially upgrade")
            self.assertEqual(list(external.iterdir()), [])
            self.assertEqual(list(root.glob(".yougori-oci.*")), [])

    def test_vendor_archive_is_deterministic_and_rejects_invalid_executables(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            self.write_vendor_files(root)
            prepare.prepare_vendor(root)
            archive = root / "usr/local/lib/yougori-boot/oci-runtime.tar.gz"
            before = archive.read_bytes()
            prepare.prepare_vendor(root)
            self.assertEqual(archive.read_bytes(), before)
            with tarfile.open(archive) as tar:
                self.assertEqual([member.name for member in tar], list(prepare.VENDOR_FILES))
                self.assertTrue(all(member.isfile() for member in tar.getmembers()))
            executable = root / prepare.VENDOR_FILES[0]
            executable.write_bytes(b"not an executable")
            with self.assertRaises(ValueError):
                prepare.prepare_vendor(root)
            self.write_vendor_files(root)
            executable.unlink()
            executable.symlink_to("/bin/sh")
            with self.assertRaises(ValueError):
                prepare.prepare_vendor(root)
            executable.unlink()
            external = root / "external-hardlink"
            external.write_bytes(b"\x7fELF\x02\x01" + b"\x00" * 12 + b"\x3e\x00" + b"outside")
            os.link(external, executable)
            with self.assertRaises(ValueError):
                prepare.prepare_vendor(root)

    def test_vendor_builder_refuses_payload_redirects_without_writing_targets(self):
        for redirect in ("leaf", "ancestor"):
            with self.subTest(redirect=redirect), tempfile.TemporaryDirectory() as temp:
                root = Path(temp) / "root"
                self.write_vendor_files(root)
                prepare.prepare_vendor(root)
                external = Path(temp) / "outside"
                if redirect == "leaf":
                    external.write_bytes(b"preserve outside archive")
                    archive = root / "usr/local/lib/yougori-boot/oci-runtime.tar.gz"
                    archive.unlink()
                    archive.symlink_to(external)
                else:
                    external.mkdir()
                    (root / "usr/local/lib").rename(root / "usr/local/retained-lib")
                    (root / "usr/local/lib").symlink_to(external, target_is_directory=True)
                with self.assertRaises(ValueError):
                    prepare.prepare_vendor(root)
                if redirect == "leaf":
                    self.assertEqual(external.read_bytes(), b"preserve outside archive")
                else:
                    self.assertEqual(list(external.iterdir()), [])

    def test_vendor_budget_guards_and_compressed_only_feature(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            with mock.patch.object(prepare, "MAX_VENDOR_FILE_BYTES", 1):
                with self.assertRaises(ValueError):
                    prepare.prepare_vendor(payload)
            with mock.patch.object(prepare, "MAX_VENDOR_EXPANDED_BYTES", 1):
                with self.assertRaises(ValueError):
                    prepare.prepare_vendor(payload)
            module = payload / "lib/modules/6.18.55-0-virt/kernel/fs/fuse/fuse.ko"
            module.parent.mkdir(parents=True)
            module.write_bytes(b"trusted-module")
            init = payload / "usr/share/mkinitfs/initramfs-init"
            init.parent.mkdir(parents=True)
            init.write_text('sysroot=/sysroot\nexec switch_root $sysroot /sbin/init\nexec switch_root $sysroot /sbin/init\n')
            output = Path(temp) / "patched-init"
            prepare.prepare(payload, output)
            feature = (payload / "etc/mkinitfs/features.d/yougori-security.files").read_text().splitlines()
            self.assertTrue(set(prepare.VENDOR_PAYLOAD_FILES).issubset(feature))
            self.assertTrue(set("/" + name for name in prepare.VENDOR_FILES).isdisjoint(feature))
            with mock.patch.object(prepare, "MAX_BOOT_UPDATE_BYTES", 1):
                with self.assertRaises(ValueError):
                    prepare.prepare(payload, output)

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

    def test_modules_reject_wrong_version_and_tampered_archive(self):
        for tamper in ("version", "archive"):
            with self.subTest(tamper=tamper), tempfile.TemporaryDirectory() as temp:
                root, payload = self.fixture(temp)
                modules = payload / "usr/local/lib/yougori-boot"
                if tamper == "version":
                    (modules / "kernel-version").write_text("wrong-kernel\n")
                else:
                    with (modules / "kernel-modules.tar.gz").open("ab") as archive:
                        archive.write(b"tampered")
                result = self.run_upgrade(root, payload)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "usr/local/sbin/opendock-agent").exists())

    def test_module_archive_is_deterministic_and_rejects_links(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            module = root / "lib/modules/6.18.55-0-virt/kernel/fs/fuse/fuse.ko"
            module.parent.mkdir(parents=True)
            module.write_bytes(b"trusted-module")
            (module.parents[3] / "vmlinuz").symlink_to("/boot/vmlinuz-virt")
            prepare.prepare_modules(root)
            archive = root / "usr/local/lib/yougori-boot/kernel-modules.tar.gz"
            before = archive.read_bytes()
            prepare.prepare_modules(root)
            self.assertEqual(before, archive.read_bytes())
            (module.parent / "escape.ko").symlink_to("/etc/passwd")
            with self.assertRaises(ValueError):
                prepare.prepare_modules(root)

    def test_supports_only_expected_usr_library_alias(self):
        with tempfile.TemporaryDirectory() as temp:
            root, payload = self.fixture(temp)
            (root / "usr/lib").mkdir(parents=True)
            (root / "lib").symlink_to("usr/lib", target_is_directory=True)
            result = self.run_upgrade(root, payload)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual((root / "usr/lib/modules" / os.uname().release / "kernel/fs/fuse/fuse.ko").read_bytes(), b"trusted-module")

    def test_cleanup_preserves_failure_and_rejects_failed_readonly_restore(self):
        # Exercise the actual shipped cleanup function with a failed mount;
        # simulated roots cannot perform a real ext4 remount in unit tests.
        source = UPDATER.read_text()
        function = "cleanup() {" + source.split("cleanup() {", 1)[1].split("\n}\n", 1)[0] + "\n}\n"
        with tempfile.TemporaryDirectory() as temp:
            mount = Path(temp) / "mount"
            mount.write_text("#!/bin/sh\nexit 1\n")
            mount.chmod(0o755)
            env = {**os.environ, "PATH": temp + ":" + os.environ["PATH"]}
            variables = "yougori_temp=\nyougori_module_temp=\nyougori_vendor_temp=\nyougori_restore_read_only=1\nyougori_root=/fixture-root\n"
            for status, expected in ((0, 1), (7, 7)):
                result = subprocess.run(["/bin/sh", "-c", function + variables + f"cleanup {status}\n"], env=env)
                self.assertEqual(result.returncode, expected)
            result = subprocess.run(["/bin/sh", "-c", function + variables + "yougori_restore_read_only=0\ncleanup 7\n"], env=env)
            self.assertEqual(result.returncode, 7)


if __name__ == "__main__":
    unittest.main()
