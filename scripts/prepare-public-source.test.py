import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('public_source', Path(__file__).with_name('prepare-public-source.py'))
export = importlib.util.module_from_spec(spec)
spec.loader.exec_module(export)


class PublicSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='yougori-public-source-')
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / 'private'
        self.output = Path(self.temp.name) / 'public'
        self.source.mkdir()
        self.env = {k: v for k, v in os.environ.items() if k not in ('GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE')}
        self.git('init', '-q')
        for name in export.REQUIRED:
            file = self.source / name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b'private\n' if name == 'distribution.txt' else b'fixture\n')
        self.git('add', '.')
        self.tree = self.git('write-tree').decode().strip()

    def git(self, *args):
        return subprocess.check_output(['git', *args], cwd=self.source, env=self.env)

    def test_public_tree_has_no_private_history_local_secrets_or_uncommitted_edits(self):
        original_index = self.git('ls-files', '--stage')
        (self.source / '.env').write_text('local secret')
        (self.source / 'distribution.rs').write_text('unstaged change')
        report = export.public_source(self.source, self.output, self.tree)
        self.assertEqual((self.output / 'distribution.txt').read_bytes(), b'public\n')
        self.assertEqual((self.output / 'distribution.rs').read_bytes(), b'fixture\n')
        self.assertFalse((self.output / '.env').exists())
        self.assertFalse((self.output / '.git').exists())
        self.assertFalse(report['privateHistoryCopied'])
        self.assertEqual((self.source / 'distribution.txt').read_bytes(), b'private\n')
        self.assertEqual(self.git('ls-files', '--stage'), original_index)
        with self.assertRaisesRegex(ValueError, 'existing files'):
            export.public_source(self.source, self.output, self.tree)

    def test_missing_controls_and_tracked_credentials_stop_before_creating_the_export(self):
        self.git('rm', '--cached', 'distribution.rs')
        with self.assertRaisesRegex(ValueError, 'Missing distribution controls'):
            export.public_source(self.source, self.output, self.git('write-tree').decode().strip())
        self.assertFalse(self.output.exists())
        self.git('add', 'distribution.rs')
        (self.source / '.env').write_text('must remain private')
        self.git('add', '.env')
        with self.assertRaisesRegex(ValueError, 'Credential-like'):
            export.public_source(self.source, self.output, self.git('write-tree').decode().strip())
        self.assertFalse(self.output.exists())

    def test_never_exports_inside_the_private_checkout(self):
        with self.assertRaisesRegex(ValueError, 'outside the private'):
            export.public_source(self.source, self.source / 'public', self.tree)

    def test_raw_blobs_keep_lfs_pointers_and_ignore_archive_transforms(self):
        pointer = b'version https://git-lfs.github.com/spec/v1\noid sha256:' + b'a' * 64 + b'\nsize 123\n'
        (self.source / 'runtime.bin').write_bytes(pointer)
        (self.source / 'kept.txt').write_bytes(b'$Format:%H$\n')
        self.git('add', 'runtime.bin', 'kept.txt')
        (self.source / '.gitattributes').write_text('runtime.bin filter=lfs\nkept.txt export-ignore export-subst\n')
        self.git('add', '.gitattributes')
        tree = self.git('write-tree').decode().strip()
        # A failing smudge filter makes any attempt to expand a pointer observable.
        self.git('config', 'filter.lfs.process', '')
        self.git('config', 'filter.lfs.smudge', 'exit 1')
        self.git('config', 'filter.lfs.required', 'true')
        export.public_source(self.source, self.output, tree)
        self.assertEqual((self.output / 'runtime.bin').read_bytes(), pointer)
        self.assertEqual((self.output / 'kept.txt').read_bytes(), b'$Format:%H$\n')


if __name__ == '__main__':
    unittest.main()
