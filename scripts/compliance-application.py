"""Collect and independently check Yougori's complete tracked application source.

Runtime payloads are supplied/rebuilt separately; their source archives are in
the same release index. Never traverse untracked files, caches or Git metadata.
Compatible with Python 3.10+ used by the Linux compliance workflow.
"""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import subprocess
import tarfile

EVIDENCE = 'compliance/evidence/application-source.json'
ARCHIVE = 'yougori-application-source.tar.gz'
MANIFEST = 'YOUGORI_SOURCE_MANIFEST.json'
EXCLUDED_FILES = (EVIDENCE, 'compliance/release.json')
EXCLUDED_PREFIXES = ('src-tauri/resources/runtime/', 'compliance/source-updates/')
REQUIRED = (
    'distribution.txt', 'distribution.rs',
    'LICENSE', 'COPYING', 'NOTICE', 'COMMERCIAL_LICENSE.txt', 'docs/rebuilding-third-party.txt',
    'package.json', 'package-lock.json', 'index.html', 'vite.config.ts',
    'tsconfig.json', 'src/main.tsx', 'src-tauri/src/lib.rs', 'src-tauri/src/main.rs',
    'src-tauri/Cargo.toml', 'src-tauri/Cargo.lock', 'src-tauri/build.rs',
    'src-tauri/tauri.conf.json', 'src-tauri/tauri.windows.conf.json',
    'src-tauri/tauri.linux.conf.json', 'src-tauri/tauri.macos.conf.json',
    'cli/src/main.rs', 'cli/Cargo.toml', 'cli/Cargo.lock',
    'engine/src/main.rs', 'engine/Cargo.toml', 'engine/Cargo.lock',
    'vault/src/main.rs', 'vault/src/lib.rs', 'vault/Cargo.toml', 'vault/Cargo.lock',
    'skills/yougori/SKILL.txt', 'skills/yougori/references/cli.txt',
    'runtime/cuda/host/Cargo.toml', 'runtime/cuda/host/Cargo.lock',
    'src-tauri/boot-helper/main.c', 'scripts/build-bundled-runtime.ps1',
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def canonical(data):
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return data
    return data if '\0' in text else text.replace('\r\n', '\n').replace('\r', '\n').encode()


def safe_file(root, name):
    if not name or any(c in name for c in ('\\', ':', '\0')) or any(p in ('', '.', '..') for p in name.split('/')):
        raise ValueError('Unsafe application source path: ' + name)
    path = root / name
    path.resolve().relative_to(root.resolve())
    current = root
    for part in name.split('/'):
        current = current / part
        if current.is_symlink():
            raise ValueError('Application source links are not accepted: ' + name)
    if not path.is_file():
        raise ValueError('Application source missing: ' + name)
    return path


def inventory(root):
    result = subprocess.check_output(['git', 'ls-files', '--stage', '-z'], cwd=root).decode()
    files = []
    names = set()
    for entry in sorted(filter(None, result.split('\0')), key=lambda s: s.split('\t', 1)[1]):
        metadata, name = entry.split('\t', 1)
        mode, _, stage = metadata.split()
        if stage != '0' or mode not in ('100644', '100755'):
            raise ValueError('Unmerged, linked or submodule source requires review: ' + name)
        if name in EXCLUDED_FILES or name.startswith(EXCLUDED_PREFIXES):
            continue
        if name.lower() in names or name == MANIFEST:
            raise ValueError('Duplicate/reserved application source path: ' + name)
        names.add(name.lower())
        data = canonical(safe_file(root, name).read_bytes())
        files.append({'path': name, 'sha256': sha(data), 'bytes': len(data), 'mode': int(mode, 8) & 0o777})
    paths = {entry['path'] for entry in files}
    missing = sorted(set(REQUIRED) - paths)
    if missing:
        raise ValueError('Required application source missing from Git: ' + ', '.join(missing))
    untracked = subprocess.check_output(['git', 'ls-files', '--others', '--exclude-standard', '-z'], cwd=root).decode().split('\0')
    pending = [n for n in untracked if n in ('distribution.txt', 'distribution.rs') or n.startswith(('src/', 'src-tauri/src/', 'src-tauri/icons/', 'assets/', 'public/', 'cli/src/', 'engine/', 'crates/', '.cargo/', '.github/', 'vault/', 'vendor/', 'skills/', 'runtime/', 'scripts/'))
               or ('/' not in n and Path(n).suffix.lower() in ('.svg', '.png', '.jpg', '.jpeg', '.webp', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.otf'))]
    if pending:
        raise ValueError('Stage new source files before collecting: ' + ', '.join(pending))
    return {'schemaVersion': 1, 'normalization': 'lf-for-utf8-text',
            'scope': 'All tracked application source, assets, configuration and build material; runtime payloads are separate.',
            'excludedFiles': list(EXCLUDED_FILES), 'excludedPrefixes': list(EXCLUDED_PREFIXES), 'files': files}


def encoded(value):
    return (json.dumps(value, indent=2) + '\n').encode()


def collect(root, bundle):
    manifest = inventory(root)
    bundle.mkdir(parents=True, exist_ok=True)
    output = bundle / ARCHIVE
    with output.with_suffix('.part').open('wb') as raw:
        with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0, filename='') as gz:
            with tarfile.open(fileobj=gz, mode='w|') as archive:
                for item in manifest['files'] + [{'path': MANIFEST, 'mode': 0o644}]:
                    data = encoded(manifest) if item['path'] == MANIFEST else canonical(safe_file(root, item['path']).read_bytes())
                    if item['path'] != MANIFEST and sha(data) != item['sha256']:
                        raise ValueError('Application source changed during collection: ' + item['path'])
                    info = tarfile.TarInfo(item['path'])
                    info.size, info.mode = len(data), item['mode']
                    archive.addfile(info, io.BytesIO(data))
    output.with_suffix('.part').replace(output)
    evidence = root / EVIDENCE
    evidence.parent.mkdir(parents=True, exist_ok=True)
    evidence.write_bytes(encoded(manifest))
    record = {'id': 'yougori-application-source', 'status': 'collected', 'file': ARCHIVE,
              'sha256': sha(output.read_bytes()), 'bytes': output.stat().st_size,
              'manifest': EVIDENCE, 'manifestSha256': sha(encoded(manifest)), 'fileCount': len(manifest['files'])}
    records_path = root / 'build/compliance/application-sources.json'
    records_path.parent.mkdir(parents=True, exist_ok=True)
    records_path.write_bytes(encoded([record]))
    return record


def check(root, bundle, report, *, archive=True):
    manifest = inventory(root)
    if json.loads(safe_file(root, EVIDENCE).read_text(encoding='utf-8')) != manifest:
        raise ValueError('Application source manifest is stale or incomplete; recollect application sources')
    records = [r for r in report['components'] if r.get('id') == 'yougori-application-source']
    if len(records) != 1 or records[0].get('status') != 'collected':
        raise ValueError('Missing reviewed Yougori application source archive')
    record = records[0]
    if record.get('manifestSha256') != sha(encoded(manifest)) or record.get('fileCount') != len(manifest['files']):
        raise ValueError('Application source manifest does not match its archive record')
    indexed = [r for r in report['archives'] if r['file'] == record['file']]
    if len(indexed) != 1 or any(indexed[0][k] != record[k] for k in ('sha256', 'bytes')):
        raise ValueError('Application source archive is absent from release checksums')
    if not archive:
        return
    path = safe_file(bundle, record['file'])
    if sha(path.read_bytes()) != record['sha256']:
        raise ValueError('Application source archive checksum mismatch')
    expected = {r['path']: r for r in manifest['files']}
    seen = set()
    with tarfile.open(path) as source:
        for member in source:
            if not member.isfile() or member.name in seen or member.name not in {*expected, MANIFEST}:
                raise ValueError('Unexpected, duplicate or linked application archive member: ' + member.name)
            seen.add(member.name)
            data = source.extractfile(member).read()
            if member.name == MANIFEST:
                if data != encoded(manifest):
                    raise ValueError('Embedded application source manifest differs')
            else:
                item = expected[member.name]
                if sha(data) != item['sha256'] or len(data) != item['bytes'] or member.mode != item['mode']:
                    raise ValueError('Application archive source differs: ' + member.name)
    missing = {*expected, MANIFEST} - seen
    if missing:
        raise ValueError('Application archive omits source files: ' + ', '.join(sorted(missing)))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('collect', 'check'))
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--bundle', type=Path)
    parser.add_argument('--manifest-only', action='store_true')
    args = parser.parse_args()
    root = args.root.resolve()
    bundle = args.bundle.resolve() if args.bundle else root / 'build/compliance/bundle'
    if args.action == 'collect':
        print(json.dumps(collect(root, bundle)))
    else:
        check(root, bundle, json.loads((root / 'compliance/release.json').read_text()), archive=not args.manifest_only)
        print('Application source files and archive coverage verified.')
