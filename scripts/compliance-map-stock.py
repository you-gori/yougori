#!/usr/bin/env python3
"""Match shipped DLL bytes against MSYS2 archives, including recent history.

No downloaded DLL or build recipe is executed. Package names identify candidates;
only exact DLL SHA-256 equality establishes a package match. Cached matches are
rechecked against both the shipped file and the retained binary archive.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess
import tarfile
import urllib.parse

M = runpy.run_path(str(Path(__file__).with_name('collect-compliance.py')))
WORK, ROOT = M['WORK'], M['ROOT']


def package_fields(contents):
    values = {}
    for key, value in re.findall(r'^([^= ]+) = (.+)$', contents.decode(), re.M):
        values.setdefault(key, []).append(value)
    return {key: '\n'.join(items) for key, items in values.items()}


def record_match(item, archive, member):
    expected = M['digest'](ROOT / item['file'])
    if expected != item['sha256']:
        raise ValueError('Shipped DLL changed since inventory')
    actual = hashlib.sha256(M['run'](M['TAR'], '-xOf', archive, member)).hexdigest()
    if actual != expected:
        return False
    pkg = package_fields(M['run'](M['TAR'], '-xOf', archive, '.PKGINFO'))
    build = package_fields(M['run'](M['TAR'], '-xOf', archive, '.BUILDINFO'))
    item.update(package=pkg['pkgname'], version=pkg['pkgver'], base=pkg['pkgbase'],
                license=pkg.get('license', 'UNKNOWN'), provenance='matched-msys-package-by-sha256',
                binaryPackageSha256=M['digest'](archive), pkgbuildSha256=build['pkgbuild_sha256sum'],
                binaryArchive=archive.name, archiveMember=member)
    return True


def owners():
    database = WORK / 'mingw64.files'
    M['download']('https://repo.msys2.org/mingw/mingw64/mingw64.files', database)
    process = subprocess.Popen(['7z', 'e', '-so', str(database)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    packages = {}
    with tarfile.open(fileobj=process.stdout, mode='r|') as archive:
        for member in archive:
            if member.isfile() and member.name.endswith(('/desc', '/files')):
                text = archive.extractfile(member).read().decode()
                packages.setdefault(member.name.split('/')[0], {}).update(
                    dict(re.findall(r'%([^%]+)%\n(.*?)(?:\n\n|\Z)', text, re.S)))
    while process.stdout.read(1024 * 1024):
        pass
    if process.wait():
        raise RuntimeError(process.stderr.read().decode())
    result = {}
    for pkg in packages.values():
        for member in pkg.get('FILES', '').splitlines():
            if member.startswith('mingw64/bin/') and member.lower().endswith('.dll'):
                result[Path(member).name.lower()] = (member, pkg)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--history', type=int, default=8, help='Maximum recent archive candidates per unmatched DLL')
    args = parser.parse_args()
    if not 0 <= args.history <= 20:
        parser.error('--history must be between 0 and 20')
    inventory_path = ROOT / 'compliance/evidence/windows-dlls.json'
    items = json.loads(inventory_path.read_text(encoding='utf-8'))
    cache_path = WORK / 'stock-dll-matches.json'
    cached = {entry['file']: entry for entry in json.loads(cache_path.read_text(encoding='utf-8'))} if cache_path.exists() else {}
    package_owners = owners()
    index_path = WORK / 'mingw-index.html'
    M['download']('https://repo.msys2.org/mingw/mingw64/', index_path)
    filenames = re.findall(r'href="([^"/]+\.pkg\.tar\.(?:zst|xz))"', index_path.read_text(encoding='utf-8'))
    for item in items:
        if item['provenance'] not in ('unresolved-exact-binary-source', 'matched-msys-package-by-sha256'):
            continue
        prior = cached.get(item['file'], item)
        if prior.get('sha256') == item['sha256'] and prior.get('binaryArchive'):
            archive = WORK / 'stock-binary-packages' / M['safe_name'](prior['binaryArchive'])
            if archive.exists() and M['digest'](archive) == prior['binaryPackageSha256']:
                if record_match(item, archive, prior['archiveMember']):
                    continue
        # A stale proof must not survive a failed recheck.
        item = {key: item[key] for key in ('file', 'sha256')}
        item['provenance'] = 'unresolved-exact-binary-source'
        items[next(index for index, value in enumerate(items) if value['file'] == item['file'])] = item
        name = Path(item['file']).name.lower()
        member_and_pkg = package_owners.get('libegl.dll' if name == 'libegl_angle.dll' else name)
        if member_and_pkg is None:
            continue
        member, pkg = member_and_pkg
        candidates = [filename for filename in filenames if re.fullmatch(re.escape(pkg['NAME']) + r'-[0-9].*-any\.pkg\.tar\.(?:zst|xz)', filename)]
        def version_key(value):
            return [(1, int(part)) if part.isdigit() else (0, part) for part in re.split(r'(\d+)', value)]
        candidates = [pkg['FILENAME']] + sorted(candidates, key=version_key, reverse=True)[:args.history]
        print('Match DLL:', name, flush=True)
        for filename in dict.fromkeys(candidates):
            try:
                archive = WORK / 'stock-binary-packages' / M['safe_name'](filename)
                checksum = pkg['SHA256SUM'] if filename == pkg['FILENAME'] else None
                M['download']('https://repo.msys2.org/mingw/mingw64/' + urllib.parse.quote(filename), archive, checksum)
                if record_match(item, archive, member):
                    print('  matched', filename, flush=True)
                    break
            except (OSError, ValueError, RuntimeError, KeyError) as error:
                print('  unresolved candidate:', str(error)[:150], flush=True)
        M['write_json'](inventory_path, items)
    M['write_json'](inventory_path, items)
    matches = [item for item in items if item['provenance'] == 'matched-msys-package-by-sha256']
    M['write_json'](cache_path, matches)
    print(f'Matched {len(matches)} stock DLLs; {sum(item["provenance"] == "unresolved-exact-binary-source" for item in items)} unresolved.', flush=True)


if __name__ == '__main__':
    main()
