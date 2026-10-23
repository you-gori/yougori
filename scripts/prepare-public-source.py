"""Export a public source snapshot without copying private Git history or changing the laptop.

Usage: python scripts/prepare-public-source.py NEW_DIRECTORY [--ref COMMIT_OR_TREE]
Only the selected Git tree is exported, including LFS pointers rather than local runtime images.
The destination is deliberately not a Git repository: base its eventual commit on public/main,
never merge or push the private branch into the public repository.
"""
import argparse
import json
from pathlib import Path, PurePosixPath
import subprocess

ROOT = Path(__file__).resolve().parents[1]
PROFILE = b'public\n'
REQUIRED = ('distribution.txt', 'distribution.rs', 'cli/src/lib.rs', 'grid/src/lib.rs',
            'grid/src/bounty_project.rs', 'src/lib/distribution.ts',
            'src/components/closed-bounty-dialog.tsx', 'src-tauri/src/swarm/closed.rs')


def public_source(source, destination, reference='HEAD'):
    source, destination = source.resolve(), destination.resolve()
    if destination.exists():
        raise ValueError('Use a new destination; existing files are never overwritten')
    if destination == source or source in destination.parents:
        raise ValueError('The public checkout must be outside the private working tree')
    if reference.startswith('-'):
        raise ValueError('Choose a Git commit or tree')
    tree = subprocess.check_output(['git', 'rev-parse', '--verify', reference + '^{tree}'], cwd=source, text=True).strip()
    # Review the tree before creating anything. Links, submodules, credentials and nested Git
    # metadata must not become an accidental public export.
    entries = subprocess.check_output(['git', 'ls-tree', '-r', '-z', tree], cwd=source).decode().split('\0')
    files = []
    for entry in filter(None, entries):
        metadata, name = entry.split('\t', 1)
        mode, kind, oid = metadata.split()
        path = PurePosixPath(name)
        if mode not in ('100644', '100755') or kind != 'blob':
            raise ValueError('Linked or submodule source requires review: ' + name)
        if path.is_absolute() or any(part in ('.', '..', '.git') for part in path.parts) or '\\' in name or ':' in name:
            raise ValueError('Unsafe source path: ' + name)
        leaf = path.name.lower()
        if (leaf == '.env' or leaf.startswith('.env.') and leaf not in ('.env.example', '.env.sample', '.env.template')
                or leaf in ('.npmrc', '.netrc', '.git-credentials', 'credentials.json', 'credentials.toml', 'id_rsa', 'id_ed25519')
                or path.suffix.lower() in ('.pfx', '.p12', '.key', '.pem', '.keystore')):
            raise ValueError('Credential-like source requires review: ' + name)
        files.append((name, mode, oid))
    missing = set(REQUIRED) - {name for name, _, _ in files}
    if missing:
        raise ValueError('Missing distribution controls: ' + ', '.join(sorted(missing)))
    destination.mkdir(parents=True)
    # Read only bytes stored in Git: ignored credentials, current worker data, caches and
    # uncommitted files can never be collected by walking the private workspace.
    # git archive can apply LFS smudging, export-ignore and export-subst. Read raw blobs
    # instead: the exported snapshot must retain every selected byte and LFS pointer.
    with subprocess.Popen(['git', 'cat-file', '--batch'], cwd=source,
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE) as blobs:
        try:
            for name, mode, oid in files:
                blobs.stdin.write((oid + '\n').encode('ascii'))
                blobs.stdin.flush()
                header = blobs.stdout.readline().split()
                if len(header) != 3 or header[:2] != [oid.encode('ascii'), b'blob']:
                    raise ValueError('Git could not read source blob: ' + name)
                remaining = int(header[2])
                path = destination.joinpath(*PurePosixPath(name).parts)
                path.resolve().relative_to(destination)
                path.parent.mkdir(parents=True, exist_ok=True)
                with path.open('wb') as outgoing:
                    while remaining:
                        chunk = blobs.stdout.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise ValueError('Incomplete source blob: ' + name)
                        outgoing.write(chunk)
                        remaining -= len(chunk)
                if blobs.stdout.read(1) != b'\n':
                    raise ValueError('Invalid source blob boundary: ' + name)
                path.chmod(int(mode, 8) & 0o777)
        except BaseException:
            blobs.kill()
            raise
        finally:
            blobs.stdin.close()
        if blobs.wait() != 0:
            raise ValueError('Git could not export the selected tree')
    (destination / 'distribution.txt').write_bytes(PROFILE)
    # Source archives may be built without Git. The public restriction travels with the sources.
    if (destination / '.git').exists() or (destination / 'distribution.txt').read_bytes() != PROFILE:
        raise ValueError('The public export did not pass its distribution checks')
    return {'distribution': 'public', 'files': len(files), 'sourceTree': tree, 'destination': str(destination), 'privateHistoryCopied': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination', type=Path)
    parser.add_argument('--ref', default='HEAD')
    args = parser.parse_args()
    print(json.dumps(public_source(ROOT, args.destination, args.ref), indent=2))


if __name__ == '__main__':
    main()
