#!/usr/bin/env python3
"""Verify and atomically install the managed OCI executables in an owned root."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tarfile
import tempfile

FILES = frozenset(['bin/' + name for name in (
    'containerd', 'containerd-shim-runc-v2', 'nerdctl', 'runc',
)] + ['libexec/cni/' + name for name in (
    'bridge', 'firewall', 'host-local', 'loopback', 'portmap', 'tuning',
)])
NVIDIA_FILES = frozenset(('bin/nvidia-ctk', 'bin/nvidia-cdi-hook'))
MAX_ARCHIVE = MAX_FILE = 96 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(65536), b''):
            value.update(chunk)
    return value.hexdigest()


def ordinary(path, directory=False):
    info = path.lstat()
    require(not getattr(info, 'st_file_attributes', 0) & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0),
            'Redirected managed path: ' + str(path))
    require(stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode),
            'Unexpected managed path type: ' + str(path))
    return info


def directory(root, path):
    ordinary(root, directory=True)
    cursor = root
    for part in path.relative_to(root).parts:
        cursor = cursor / part
        if not cursor.exists() and not cursor.is_symlink():
            cursor.mkdir(mode=0o755)
        ordinary(cursor, directory=True)


def sync_directory(path):
    if os.name == 'posix':
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def install(archive, manifest, root=Path('/'), component='oci'):
    require(component in ('oci', 'nvidia-cdi'), 'Unknown managed runtime component')
    files = NVIDIA_FILES if component == 'nvidia-cdi' else FILES
    root = root.absolute()
    for ancestor in [*reversed(root.parents), root]:
        ordinary(ancestor, directory=True)
    require(root.resolve() == root, 'Redirected managed root')
    ordinary(archive)
    ordinary(manifest)
    require(manifest.stat().st_size <= 4 * 1024 * 1024, 'OCI manifest exceeds limit')
    record = json.loads(manifest.read_text(encoding='utf-8'))
    require(type(record.get('schemaVersion')) is int and record.get('schemaVersion') == 1 and record.get('target') == 'linux/amd64'
            and record.get('compiler') == 'go1.27.2', 'Unsupported OCI manifest')
    if component == 'nvidia-cdi':
        require(record.get('kind') == 'nvidia-cdi', 'Unexpected NVIDIA CDI manifest')
    expected_archive = record['archive']
    require(expected_archive['file'] == archive.name
            and type(expected_archive['bytes']) is int and 0 < expected_archive['bytes'] <= MAX_ARCHIVE
            and archive.stat().st_size == expected_archive['bytes']
            and re.fullmatch(r'[a-f0-9]{64}', expected_archive['sha256'])
            and digest(archive) == expected_archive['sha256'], 'OCI archive integrity mismatch')
    expected = {}
    require(type(record['files']) is list and len(record['files']) == len(files), 'Wrong OCI file count')
    for item in record['files']:
        name = item['path']
        require(name in files and name not in expected, 'Unexpected/duplicate OCI file')
        require(type(item['bytes']) is int and 0 < item['bytes'] <= MAX_FILE
                and type(item['mode']) is int and item['mode'] == 0o755
                and re.fullmatch(r'[a-f0-9]{64}', item['sha256']), 'Invalid OCI file record')
        expected[name] = item
    require(sum(item['bytes'] for item in expected.values()) <= MAX_EXPANDED, 'OCI expanded size exceeds limit')
    prefix = root / 'usr/local'
    directory(root, prefix)
    for name in sorted(files):
        destination = prefix / name
        directory(root, destination.parent)
        if destination.exists() or destination.is_symlink():
            ordinary(destination)
    scratch = Path(tempfile.mkdtemp(prefix='.yougori-oci-install-', dir=prefix))
    saved = scratch / 'saved'
    saved.mkdir(mode=0o700)
    changed = []
    preserve_transaction = False
    try:
        seen = set()
        with tarfile.open(archive, 'r|gz') as stream:
            for member in stream:
                name = member.name
                require(name in expected and name not in seen and member.isfile()
                        and not member.pax_headers and member.sparse is None,
                        'Unsafe/duplicate OCI archive member')
                item = expected[name]
                require(member.size == item['bytes'] and member.mode == 0o755, 'OCI archive file metadata mismatch')
                seen.add(name)
                temporary = scratch / name
                temporary.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                checksum, size, header = hashlib.sha256(), 0, b''
                with stream.extractfile(member) as source, temporary.open('xb') as output:
                    for chunk in iter(lambda: source.read(65536), b''):
                        size += len(chunk)
                        require(size <= item['bytes'], 'OCI file exceeds declared size')
                        if len(header) < 20:
                            header = (header + chunk)[:20]
                        checksum.update(chunk)
                        output.write(chunk)
                    output.flush()
                    temporary.chmod(0o755)
                    os.fsync(output.fileno())
                require(size == item['bytes'] and checksum.hexdigest() == item['sha256'], 'OCI file integrity mismatch')
                require(header[:7] == b'\x7fELF\x02\x01\x01' and header[18:20] == b'\x3e\x00', 'OCI file is not an AMD64 ELF')
        require(seen == files, 'OCI archive omits required executables')
        # Save original leaf inodes without modifying them or their hardlinks.
        # No daemon is started until every verified replacement has succeeded.
        for index, name in enumerate(sorted(files)):
            destination = prefix / name
            backup = saved / str(index)
            if destination.exists():
                ordinary(destination)
                os.link(destination, backup)
            os.replace(scratch / name, destination)
            changed.append((destination, backup))
            sync_directory(destination.parent)
        for name, item in expected.items():
            require(digest(prefix / name) == item['sha256'], 'Installed OCI bytes differ')
        sync_directory(prefix)
    except BaseException:
        rollback_errors = []
        for destination, backup in reversed(changed):
            try:
                if backup.exists():
                    os.replace(backup, destination)
                else:
                    destination.unlink()
                sync_directory(destination.parent)
            except OSError as error:
                rollback_errors.append(str(error))
        if rollback_errors:
            preserve_transaction = True
            raise RuntimeError('OCI rollback requires recovery; saved files retained at ' + str(scratch))
        raise
    finally:
        require(scratch.parent == prefix and scratch.name.startswith('.yougori-oci-install-')
                and scratch.resolve() == scratch, 'Unexpected OCI transaction directory')
        if not preserve_transaction:
            shutil.rmtree(scratch)
    return {'installed': len(files), 'archiveSha256': expected_archive['sha256']}


def main():
    require(os.geteuid() == 0 and Path('/etc/opendock-cuda-runtime').is_file(), 'Use only the owned CUDA root')
    for process in Path('/proc').glob('[0-9]*/comm'):
        try:
            name = process.read_text().strip()
        except (FileNotFoundError, ProcessLookupError):
            continue
        require(not name.startswith(('containerd', 'opendock-agent')), 'Stop CUDA workloads before updating OCI')
    require(len(sys.argv) in (3, 4), 'Expected archive, manifest and optional component')
    component = sys.argv[3] if len(sys.argv) == 4 else 'oci'
    print(json.dumps(install(Path(sys.argv[1]), Path(sys.argv[2]), component=component)))


if __name__ == '__main__':
    main()
