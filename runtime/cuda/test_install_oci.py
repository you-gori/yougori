"""Exercise verified OCI upgrades against disposable owned roots.

Run directly with Python on Windows or Linux; no CUDA device or daemon needed.
The executable fixtures are inert ELF headers, never executed by these tests.
"""
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import struct
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

SPEC = importlib.util.spec_from_file_location('cuda_install_oci', Path(__file__).with_name('install-oci.py'))
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)

# This is the shipping contract, independent of the installer's allowlist.
EXECUTABLES = (
    'bin/containerd', 'bin/containerd-shim-runc-v2', 'bin/nerdctl', 'bin/runc',
    'libexec/cni/bridge', 'libexec/cni/firewall', 'libexec/cni/host-local',
    'libexec/cni/loopback', 'libexec/cni/portmap', 'libexec/cni/tuning',
)


def elf_fixture(name, machine=62, elf_class=2):
    header = bytearray(64)
    header[:7] = b'\x7fELF' + bytes((elf_class, 1, 1))
    struct.pack_into('<HHI', header, 16, 2, machine, 1)
    struct.pack_into('<HH', header, 52, 64, 56)
    return bytes(header) + b'inert-new-runtime-fixture:' + name.encode()


def old_tree(root):
    for name in EXECUTABLES:
        path = root / 'usr/local' / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b'original-runtime:' + name.encode())
        path.chmod(0o600)
    data = root / 'var/lib/containerd/projects/data.db'
    data.parent.mkdir(parents=True, exist_ok=True)
    data.write_bytes(b'user image layers and project data must survive byte-for-byte')
    return data


def fixture(directory):
    base = Path(directory)
    root, producer = base / 'owned-root', base / 'producer'
    root.mkdir()
    producer.mkdir()
    data = old_tree(root)
    return SimpleNamespace(base=base, root=root, producer=producer, data=data,
                           archive=producer / 'verified-oci.tar.gz', manifest=producer / 'verified-oci.json')


def write_payload(item, change_contents=None, change_members=None, change_manifest=None, names=EXECUTABLES):
    contents = {name: elf_fixture(name) for name in names}
    if change_contents:
        change_contents(contents)
    members = [{'name': name, 'contents': contents[name], 'type': tarfile.REGTYPE, 'mode': 0o755, 'linkname': ''}
               for name in names]
    if change_members:
        change_members(members)
    with tarfile.open(item.archive, 'w:gz', format=tarfile.USTAR_FORMAT) as archive:
        for entry in members:
            member = tarfile.TarInfo(entry['name'])
            member.mode, member.type, member.linkname = entry['mode'], entry['type'], entry['linkname']
            member.size = len(entry['contents']) if member.isfile() else 0
            archive.addfile(member, io.BytesIO(entry['contents']) if member.isfile() else None)
    record = {
        'schemaVersion': 1, 'target': 'linux/amd64', 'compiler': 'go1.27.2',
        'archive': {'file': item.archive.name, 'bytes': item.archive.stat().st_size,
                    'sha256': hashlib.sha256(item.archive.read_bytes()).hexdigest()},
        'files': [{'path': name, 'bytes': len(contents[name]), 'mode': 0o755,
                   'sha256': hashlib.sha256(contents[name]).hexdigest()} for name in names],
    }
    if change_manifest:
        change_manifest(record)
    item.manifest.write_text(json.dumps(record), encoding='utf-8')
    return contents


def snapshot(root):
    paths = [root / 'usr/local' / name for name in EXECUTABLES]
    paths.append(root / 'var/lib/containerd/projects/data.db')
    return {path.relative_to(root).as_posix():
            (path.read_bytes(), path.stat().st_ino, stat.S_IMODE(path.stat().st_mode)) if path.exists() else None
            for path in paths}


class OCIInstallTests(unittest.TestCase):
    def test_nvidia_component_is_explicit_and_cannot_expand_oci_allowlist(self):
        with tempfile.TemporaryDirectory() as directory:
            item = fixture(directory)
            before = snapshot(item.root)
            names = ('bin/nvidia-ctk', 'bin/nvidia-cdi-hook')
            contents = write_payload(item, names=names,
                                     change_manifest=lambda record: record.update(kind='nvidia-cdi'))
            with self.assertRaises(ValueError):
                installer.install(item.archive, item.manifest, item.root)
            self.assert_unchanged(item, before)
            result = installer.install(item.archive, item.manifest, item.root, component='nvidia-cdi')
            self.assertEqual(result['installed'], 2)
            self.assertEqual(snapshot(item.root), before)
            for name, data in contents.items():
                self.assertEqual((item.root / 'usr/local' / name).read_bytes(), data)
            write_payload(item, names=names)
            with self.assertRaisesRegex(ValueError, 'NVIDIA CDI manifest'):
                installer.install(item.archive, item.manifest, item.root, component='nvidia-cdi')
            with self.assertRaisesRegex(ValueError, 'Unknown managed runtime component'):
                installer.install(item.archive, item.manifest, item.root, component='arbitrary')

    def assert_unchanged(self, item, before):
        self.assertEqual(snapshot(item.root), before)
        self.assertEqual(list((item.root / 'usr/local').glob('.yougori-oci-install-*')), [])

    def test_valid_upgrade_preserves_user_data_and_original_hardlinked_inode(self):
        with tempfile.TemporaryDirectory() as directory:
            item = fixture(directory)
            contents = write_payload(item)
            original = item.root / 'usr/local/bin/containerd'
            other_link = item.base / 'user-linked-original'
            os.link(original, other_link)
            original_info = (other_link.read_bytes(), other_link.stat().st_ino, stat.S_IMODE(other_link.stat().st_mode))
            retained = item.data.read_bytes()
            result = installer.install(item.archive, item.manifest, item.root)
            self.assertEqual(result['installed'], 10)
            self.assertEqual(result['archiveSha256'], hashlib.sha256(item.archive.read_bytes()).hexdigest())
            for name, data in contents.items():
                destination = item.root / 'usr/local' / name
                self.assertEqual(destination.read_bytes(), data)
                if os.name == 'posix':
                    self.assertEqual(stat.S_IMODE(destination.stat().st_mode), 0o755)
            self.assertEqual(item.data.read_bytes(), retained)
            self.assertEqual((other_link.read_bytes(), other_link.stat().st_ino,
                              stat.S_IMODE(other_link.stat().st_mode)), original_info)
            self.assertNotEqual(original.stat().st_ino, other_link.stat().st_ino)
            self.assertEqual(list((item.root / 'usr/local').glob('.yougori-oci-install-*')), [])

    def exercise_redirect(self, junction=False):
        for location in ('root', 'root-ancestor', 'managed-ancestor'):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as directory:
                item = fixture(directory)
                write_payload(item)
                external = item.base / 'outside'
                external.mkdir()
                old_tree(external)
                before = snapshot(external)
                alias = item.base / 'redirect'
                target, requested = external, alias
                if location == 'root-ancestor':
                    target = item.base / 'outside-parent'
                    target.mkdir()
                    external.rename(target / 'owned')
                    external = target / 'owned'
                    requested = alias / 'owned'
                elif location == 'managed-ancestor':
                    alias = item.root / 'usr/local'
                    alias.rename(item.base / 'retained-local')
                    target = external / 'usr/local'
                    requested = item.root
                if junction:
                    subprocess.run(['cmd.exe', '/d', '/c', 'mklink', '/J', str(alias), str(target)],
                                   capture_output=True, check=True)
                else:
                    try:
                        alias.symlink_to(target, target_is_directory=True)
                    except OSError as error:
                        if os.name == 'nt' and getattr(error, 'winerror', None) == 1314:
                            self.skipTest('Windows symlink privilege unavailable; junction coverage is separate')
                        raise
                try:
                    with self.assertRaises(ValueError):
                        installer.install(item.archive, item.manifest, requested)
                    self.assertEqual(snapshot(external), before)
                    self.assertEqual(list((external / 'usr/local').glob('.yougori-oci-install-*')), [])
                finally:
                    if junction:
                        os.rmdir(alias)
                    else:
                        alias.unlink()

    def test_symlink_ancestors_are_rejected_before_external_files_change(self):
        self.exercise_redirect()

    @unittest.skipUnless(os.name == 'nt', 'Windows junction behavior')
    def test_windows_junction_ancestors_are_rejected_before_external_files_change(self):
        self.exercise_redirect(junction=True)

    def test_per_file_hash_mismatch_keeps_complete_original_set(self):
        with tempfile.TemporaryDirectory() as directory:
            item = fixture(directory)
            before = snapshot(item.root)
            write_payload(item, change_manifest=lambda record: record['files'][-1].update(sha256='0' * 64))
            with self.assertRaisesRegex(ValueError, 'file integrity mismatch'):
                installer.install(item.archive, item.manifest, item.root)
            self.assert_unchanged(item, before)

    def test_archive_tampering_is_rejected_before_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            item = fixture(directory)
            before = snapshot(item.root)
            write_payload(item)
            with item.archive.open('ab') as archive:
                archive.write(b'altered archive')
            with self.assertRaisesRegex(ValueError, 'archive integrity mismatch'):
                installer.install(item.archive, item.manifest, item.root)
            self.assert_unchanged(item, before)

    def test_tar_duplicates_escape_links_and_missing_members_preserve_old_programs(self):
        changes = {
            'duplicate': lambda members: members.append(dict(members[0])),
            'escape': lambda members: members[-1].update(name='../../outside-user-file'),
            'absolute': lambda members: members[-1].update(name='/usr/local/bin/foreign'),
            'symlink': lambda members: members[-1].update(type=tarfile.SYMTYPE, linkname='../../outside-user-file'),
            'hardlink': lambda members: members[-1].update(type=tarfile.LNKTYPE, linkname='../../outside-user-file'),
            'directory': lambda members: members[-1].update(type=tarfile.DIRTYPE),
            'mode': lambda members: members[-1].update(mode=0o4755),
            'missing': lambda members: members.pop(),
        }
        for name, change in changes.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                item = fixture(directory)
                before = snapshot(item.root)
                outside = item.base / 'outside-user-file'
                outside.write_bytes(b'outside bytes stay intact')
                # The overall archive digest is valid, so its content checks
                # must reject these members independently of transport hashes.
                write_payload(item, change_members=change)
                with self.assertRaises(ValueError):
                    installer.install(item.archive, item.manifest, item.root)
                self.assert_unchanged(item, before)
                self.assertEqual(outside.read_bytes(), b'outside bytes stay intact')

    def test_hash_valid_wrong_architecture_or_non_elf_is_rejected(self):
        for data in (elf_fixture('foreign', machine=183), elf_fixture('foreign', elf_class=1), b'not an ELF executable'):
            with self.subTest(header=data[:20]), tempfile.TemporaryDirectory() as directory:
                item = fixture(directory)
                before = snapshot(item.root)
                write_payload(item, change_contents=lambda contents: contents.update({'bin/runc': data}))
                with self.assertRaisesRegex(ValueError, 'not an AMD64 ELF'):
                    installer.install(item.archive, item.manifest, item.root)
                self.assert_unchanged(item, before)

    def test_invalid_manifest_metadata_is_rejected_before_archive_extraction(self):
        changes = {
            'schema-bool': lambda record: record.update(schemaVersion=True),
            'schema-version': lambda record: record.update(schemaVersion=2),
            'target': lambda record: record.update(target='linux/arm64'),
            'old-compiler': lambda record: record.update(compiler='go1.26.5'),
            'archive-bound': lambda record: record['archive'].update(bytes=96 * 1024 * 1024 + 1),
            'file-bound': lambda record: record['files'][0].update(bytes=96 * 1024 * 1024 + 1),
            'file-bool': lambda record: record['files'][0].update(bytes=True),
            'file-zero': lambda record: record['files'][0].update(bytes=0),
            'setuid-mode': lambda record: record['files'][0].update(mode=0o4755),
            'duplicate-path': lambda record: record['files'][-1].update(path=record['files'][0]['path']),
            'escape-path': lambda record: record['files'][-1].update(path='../../outside'),
            'missing-file': lambda record: record['files'].pop(),
            'expanded-bound': lambda record: [entry.update(bytes=96 * 1024 * 1024) for entry in record['files']],
        }
        for name, change in changes.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                item = fixture(directory)
                before = snapshot(item.root)
                write_payload(item, change_manifest=change)
                with mock.patch.object(installer.tarfile, 'open', side_effect=AssertionError('Invalid metadata reached extraction')) as extraction:
                    with self.assertRaises(ValueError):
                        installer.install(item.archive, item.manifest, item.root)
                    extraction.assert_not_called()
                self.assert_unchanged(item, before)

    def test_oversized_manifest_is_rejected_before_json_parse(self):
        with tempfile.TemporaryDirectory() as directory:
            item = fixture(directory)
            before = snapshot(item.root)
            write_payload(item)
            with item.manifest.open('wb') as manifest:
                manifest.seek(4 * 1024 * 1024)
                manifest.write(b' ')
            with self.assertRaisesRegex(ValueError, 'manifest exceeds limit'):
                installer.install(item.archive, item.manifest, item.root)
            self.assert_unchanged(item, before)

    def test_mid_install_replace_failure_restores_existing_inodes_and_removes_new_files(self):
        with tempfile.TemporaryDirectory() as directory:
            item = fixture(directory)
            write_payload(item)
            (item.root / 'usr/local/bin/containerd').unlink()
            linked = item.root / 'usr/local/bin/nerdctl'
            other_link = item.base / 'user-link'
            os.link(linked, other_link)
            before, linked_before = snapshot(item.root), (other_link.read_bytes(), other_link.stat().st_ino)
            actual_replace = os.replace
            attempts = []

            def fail_fifth(source, destination):
                if Path(source).parent.name != 'saved':
                    attempts.append(str(destination))
                    if len(attempts) == 5:
                        raise OSError('Injected mid-install replacement failure')
                return actual_replace(source, destination)

            with mock.patch.object(installer.os, 'replace', side_effect=fail_fifth):
                with self.assertRaisesRegex(OSError, 'Injected mid-install'):
                    installer.install(item.archive, item.manifest, item.root)
            self.assertEqual(len(attempts), 5)
            self.assert_unchanged(item, before)
            self.assertEqual((other_link.read_bytes(), other_link.stat().st_ino), linked_before)

    def test_directory_sync_failure_also_rolls_back_replaced_files(self):
        with tempfile.TemporaryDirectory() as directory:
            item = fixture(directory)
            write_payload(item)
            before = snapshot(item.root)
            actual_sync, calls = installer.sync_directory, []

            def fail_once(path):
                calls.append(path)
                if len(calls) == 3:
                    raise OSError('Injected directory durability failure')
                return actual_sync(path)

            with mock.patch.object(installer, 'sync_directory', side_effect=fail_once):
                with self.assertRaisesRegex(OSError, 'durability failure'):
                    installer.install(item.archive, item.manifest, item.root)
            self.assert_unchanged(item, before)

    def test_failed_rollback_retains_recovery_backups_and_user_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            item = fixture(directory)
            write_payload(item)
            original = item.root / 'usr/local/bin/containerd'
            other_link = item.base / 'user-original-link'
            os.link(original, other_link)
            original_bytes, original_inode = other_link.read_bytes(), other_link.stat().st_ino
            actual_replace, attempts, rollback_failures = os.replace, [], []

            def fail_install_and_one_undo(source, destination):
                if Path(source).parent.name == 'saved':
                    if not rollback_failures:
                        rollback_failures.append(str(source))
                        raise OSError('Injected failed rollback')
                else:
                    attempts.append(str(destination))
                    if len(attempts) == 4:
                        raise OSError('Injected install failure')
                return actual_replace(source, destination)

            with mock.patch.object(installer.os, 'replace', side_effect=fail_install_and_one_undo):
                with self.assertRaisesRegex(RuntimeError, 'requires recovery; saved files retained'):
                    installer.install(item.archive, item.manifest, item.root)
            transactions = list((item.root / 'usr/local').glob('.yougori-oci-install-*'))
            self.assertEqual(len(transactions), 1)
            backups = list((transactions[0] / 'saved').iterdir())
            self.assertTrue(backups)
            self.assertTrue(all(path.read_bytes().startswith(b'original-runtime:') for path in backups))
            self.assertEqual((other_link.read_bytes(), other_link.stat().st_ino), (original_bytes, original_inode))


if __name__ == '__main__':
    unittest.main()
