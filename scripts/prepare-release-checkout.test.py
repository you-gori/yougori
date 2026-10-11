"""Exercise local release capture without touching the developer index/runtime."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('prepare-release-checkout.py')


class LocalSnapshot(unittest.TestCase):
    def test_new_sources_assets_and_private_index(self):
        with tempfile.TemporaryDirectory(prefix='yougori-release-snapshot-') as temporary:
            base = Path(temporary)
            source, destination = base / 'source', base / 'candidate'
            source.mkdir()
            script = source / 'scripts/prepare-release-checkout.py'
            script.parent.mkdir()
            script.write_bytes(SCRIPT.read_bytes())
            clean_env = {key: value for key, value in os.environ.items()
                         if key not in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE')}

            def put(name, data=b'fixture'):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)

            def git(*args, env=None, cwd=source):
                return subprocess.check_output(['git', *args], cwd=cwd, env=env or clean_env)

            git('init', '--quiet')
            put('src/old.ts')
            put('src/deleted.ts')
            put('.gitignore', b'node_modules/\nsrc-tauri/resources/cli/\nsrc-tauri/resources/vault/\n')
            for directory in ('node_modules', 'src-tauri/resources/cli', 'src-tauri/resources/vault'):
                put(directory + '/dependency')
            runtime = source / 'src-tauri/resources/runtime'
            for name in ('appliance-base.qcow2', 'initramfs-virt', 'vmlinuz-virt'):
                put('src-tauri/resources/runtime/appliance/' + name)
            checksum = hashlib.sha256(b'fixture').hexdigest()
            put('src-tauri/resources/runtime/appliance/SHA256SUMS', ''.join(
                f'{checksum}  {name}\n' for name in ('appliance-base.qcow2', 'initramfs-virt', 'vmlinuz-virt')).encode())
            put('src-tauri/resources/runtime/cuda/yougori-agent')
            put('src-tauri/resources/runtime/cuda/SHA256SUMS', f'{checksum}  yougori-agent\n'.encode())
            git('add', '.')
            developer_index = git('ls-files', '--stage', '-z')
            (source / 'src/deleted.ts').unlink()
            put('src/new.ts', b'new source')
            put('new-image.png', b'new root image')
            put('assets/new.svg', b'new asset')
            put('public/new.svg', b'new public asset')
            put('.env', b'never copy secrets')
            # Unstaged new sources stop the snapshot instead of being collected or skipped.
            result = subprocess.run(['python' if os.name == 'nt' else 'python3', str(script), str(destination),
                                     '--runtime', str(runtime)], capture_output=True, text=True, env=clean_env)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('Stage new release sources', result.stderr)
            self.assertIn('src/new.ts', result.stderr)
            self.assertFalse(destination.exists())
            git('add', 'src/new.ts', 'new-image.png', 'assets/new.svg', 'public/new.svg')
            put('notes/private.txt', b'unrelated untracked file outside release sources')
            developer_index = git('ls-files', '--stage', '-z')
            result = subprocess.run(['python' if os.name == 'nt' else 'python3', str(script), str(destination),
                                     '--runtime', str(runtime)], capture_output=True, text=True, env=clean_env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(git('ls-files', '--stage', '-z'), developer_index)
            self.assertFalse((destination / 'notes/private.txt').exists())
            for name in ('src/new.ts', 'new-image.png', 'assets/new.svg', 'public/new.svg'):
                self.assertEqual((destination / name).read_bytes(), (source / name).read_bytes())
            self.assertFalse((destination / '.env').exists())
            self.assertFalse((destination / 'src/deleted.ts').exists())
            env = {**clean_env, **json.loads((base / 'candidate.environment.json').read_text())}
            self.assertIn(b'src/new.ts', git('ls-files', env=env, cwd=destination))
            self.assertEqual((runtime / 'appliance/appliance-base.qcow2').read_bytes(), b'fixture')
            self.assertEqual((destination / 'src-tauri/resources/runtime/appliance/appliance-base.qcow2').read_bytes(), b'fixture')
            # Existing candidates are immutable, including their private index.
            repeated = subprocess.run(['python' if os.name == 'nt' else 'python3', str(script), str(destination),
                                      '--runtime', str(runtime)], capture_output=True, text=True, env=clean_env)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertIn('existing files are never overwritten', repeated.stderr)
            # Fresh native checkouts do not contain ignored bundled binaries.
            import shutil
            for name in ('node_modules', 'src-tauri/resources/cli', 'src-tauri/resources/vault'):
                shutil.rmtree(source / name)
            fresh = base / 'fresh-candidate'
            result = subprocess.run(['python' if os.name == 'nt' else 'python3', str(script), str(fresh),
                                     '--runtime', str(runtime)], capture_output=True, text=True, env=clean_env)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue((fresh / 'src-tauri/resources/cli').is_dir())
            # Tracked credential-like files stop the snapshot.
            for name in ('docs/.npmrc', 'scripts/release.p8', 'cli/.ssh/config', 'build/tauri.signing.json'):
                put(name, b'secret')
                git('add', '--force', name)
                blocked = subprocess.run(['python' if os.name == 'nt' else 'python3', str(script), str(base / ('blocked-' + Path(name).name)),
                                          '--runtime', str(runtime)], capture_output=True, text=True, env=clean_env)
                self.assertNotEqual(blocked.returncode, 0, name)
                self.assertIn('Potential credential', blocked.stderr)
                git('rm', '--cached', '--quiet', name)
                (source / name).unlink()


if __name__ == '__main__':
    unittest.main()
