#!/usr/bin/env python3
"""Retain license texts from the exact guest-source and Windows binary archives.

Does not execute any archived program. Coverage findings remain explicit. This
supplements existing component notices; it is not a complete licensing review.
"""
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import runpy
import subprocess
import tarfile
import zipfile

M = runpy.run_path(str(Path(__file__).with_name('collect-compliance.py')))
ROOT, WORK, BUNDLE = M['ROOT'], M['WORK'], M['BUNDLE']


def is_notice(name):
    path = PurePosixPath(name)
    return bool(re.match(r'^(?:LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICEN[CS]E)(?:S?$|[._-])', path.name, re.I)
                or 'licenses' in [part.lower() for part in path.parts[:-1]])


def tar_notices(archive):
    for member in archive:
        if member.isfile() and is_notice(member.name) and member.size <= 1024 * 1024:
            yield member.name, archive.extractfile(member).read()


def main():
    sections, records = [], []
    source_records = {(item['package'], item['version']): item
                      for item in json.loads((WORK / 'msys-sources.json').read_text(encoding='utf-8'))}
    def retain(component, entries):
        texts = []
        for name, contents in entries:
            if b'\0' in contents or not contents.strip():
                continue
            texts.append({'path': name, 'sha256': hashlib.sha256(contents).hexdigest()})
            sections.append('=' * 72 + '\n' + component + '\nFile: ' + name + '\n\n' + contents.decode('utf-8', errors='replace') + '\n')
        records.append({'component': component, 'texts': texts})

    for item in json.loads((WORK / 'alpine-sources.json').read_text(encoding='utf-8')):
        package = item['packages'][0]
        directory = WORK / 'alpine' / package['origin'] / package['revision']
        texts = []
        print('Runtime notices: Alpine', package['origin'], flush=True)
        for entry in item['inputs']:
            path = directory / entry['file']
            if M['digest'](path, 'sha512') != entry['sha512']:
                raise ValueError('Alpine source input changed: ' + entry['file'])
            if is_notice(path.name):
                texts.append((entry['file'], path.read_bytes()))
            elif tarfile.is_tarfile(path):
                with tarfile.open(path, 'r:*') as archive:
                    texts.extend((entry['file'] + '/' + name, data) for name, data in tar_notices(archive))
        # Small Alpine packages consist entirely of their recipe's scripts or
        # data. Retain those complete files, including all embedded attribution.
        if not texts:
            texts = [(p.relative_to(directory).as_posix(), p.read_bytes())
                     for p in directory.rglob('*') if p.is_file() and p.stat().st_size < 1024 * 1024
                     and not p.name.endswith('.part') and not tarfile.is_tarfile(p)]
        retain(item['id'], texts)

    for kind in ('go', 'go-main'):
        for item in json.loads((WORK / (kind + '-sources.json')).read_text(encoding='utf-8')):
            if item['status'] != 'collected':
                continue
            path = BUNDLE / item['file']
            if M['digest'](path) != item['sha256']:
                raise ValueError('Source archive changed: ' + item['file'])
            if path.suffix == '.zip':
                with zipfile.ZipFile(path) as archive:
                    retain(item['id'], ((entry.filename, archive.read(entry)) for entry in archive.infolist()
                                        if not entry.is_dir() and entry.file_size <= 1024 * 1024 and is_notice(entry.filename)))
            else:
                with tarfile.open(path, 'r|gz') as archive:
                    retain(item['id'], tar_notices(archive))

    dlls = json.loads((ROOT / 'compliance/evidence/windows-dlls.json').read_text(encoding='utf-8'))
    packages = {(item['package'], item['version']): item for item in dlls if 'package' in item}
    for (name, version), item in sorted(packages.items()):
        print('Runtime notices:', name, version, flush=True)
        locations = (ROOT / 'build/secure-runtime/toolchain/msys64/var/cache/pacman/pkg', WORK / 'stock-binary-packages')
        candidates = [path for directory in locations for path in directory.glob(name + '-' + version + '-any.pkg.tar.*') if not path.name.endswith('.sig')]
        if len(candidates) != 1:
            records.append({'component': name + '/' + version, 'texts': [], 'issue': 'Original binary package unavailable'})
            continue
        path = candidates[0]
        if item.get('binaryPackageSha256') and M['digest'](path) != item['binaryPackageSha256']:
            raise ValueError('Binary package changed: ' + name)
        process = subprocess.Popen(['7z', 'e', '-so', str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
            retain(name + '/' + version, tar_notices(archive))
        # Tar parsing ends at its end markers. Drain remaining archive padding
        # before waiting, otherwise Windows' small pipe buffer can deadlock.
        while process.stdout.read(1024 * 1024):
            pass
        if process.wait():
            raise RuntimeError(process.stderr.read().decode())
        if not records[-1]['texts']:
            source = source_records.get((name, version), {})
            if source.get('status') == 'collected':
                # Some binary packages omit their standalone GPL/LGPL text.
                # Recover it from the exact recipe-verified source input.
                directory = WORK / 'msys' / item['base'] / version
                extra = []
                for entry in source.get('inputs', []):
                    algorithm = 'sha256' if 'sha256' in entry else 'sha512' if 'sha512' in entry else None
                    if algorithm is None:
                        continue
                    path = directory / entry['file']
                    if M['digest'](path, algorithm) != entry[algorithm]:
                        raise ValueError('MSYS source input changed: ' + entry['file'])
                    if is_notice(path.name):
                        extra.append((entry['file'], path.read_bytes()))
                    elif tarfile.is_tarfile(path):
                        with tarfile.open(path, 'r:*') as archive:
                            extra.extend(('source-input/' + path.name + '/' + member, contents)
                                         for member, contents in tar_notices(archive))
                records.pop()
                retain(name + '/' + version, extra)
        # The actual GNU library sources offer a GPLv2-compatible option even
        # where a package-level label mentions only LGPLv3/GPLv3.
        if item['base'] in ('mingw-w64-gmp', 'mingw-w64-libunistring', 'mingw-w64-nettle'):
            source = source_records[(name, version)]
            directory = WORK / 'msys' / item['base'] / version
            texts = []
            for entry in source['inputs']:
                algorithm = 'sha256' if 'sha256' in entry else 'sha512' if 'sha512' in entry else None
                if algorithm is None:
                    continue
                path = directory / entry['file']
                if M['digest'](path, algorithm) != entry[algorithm]:
                    raise ValueError('GNU library source input changed: ' + entry['file'])
                if tarfile.is_tarfile(path):
                    with tarfile.open(path) as archive:
                        for member in archive:
                            if member.isfile() and len(PurePosixPath(member.name).parts) <= 2 and (
                                PurePosixPath(member.name).name in ('README', 'COPYINGv2', 'COPYING.LESSER', 'COPYING.LIB', 'sha256.c')):
                                texts.append((member.name, archive.extractfile(member).read()))
            texts.append(('Selected GPL version 2', (ROOT / 'build/runtime-cache/qemu-secure-src/COPYING').read_bytes()))
            retain(name + '/' + version + ' GPL-2.0-or-later library option', texts)
    for path in sorted((ROOT / 'compliance/notices').glob('*.txt')):
        retain(path.stem, [(path.name, path.read_bytes())])
    versions = sorted(set(re.findall(rb'go1\.\d+\.\d+', (ROOT / 'src-tauri/resources/runtime/cuda/yougori-agent').read_bytes())))
    for version in versions:
        value = version.decode()
        path = WORK / 'standard-licenses' / (value + '-LICENSE')
        M['download']('https://raw.githubusercontent.com/golang/go/' + value + '/LICENSE', path)
        retain('Go standard library ' + value, [('LICENSE', path.read_bytes())])

    M['write_json'](ROOT / 'compliance/evidence/runtime-notices.json', records)
    header = ('YOUGORI RUNTIME DEPENDENCY NOTICES\n\n'
              'Texts retained from checksum-verified source archives and matched MSYS2 binary packages.\n'
              'This conservative inventory includes nested dependency notices. It supplements the\n'
              'notices packaged with each runtime and does not certify source or license completeness.\n'
              'See compliance/evidence/runtime-notices.json and docs/compliance-status.md.\n\n')
    (ROOT / 'src-tauri/resources/RUNTIME_LICENSES.txt').write_text(header + '\n'.join(sections), encoding='utf-8')
    print(f'Retained runtime notices for {sum(bool(item["texts"]) for item in records)} of {len(records)} source/package entries.')
    for item in records:
        if not item['texts']:
            print('Notice review:', item['component'])


if __name__ == '__main__':
    main()
