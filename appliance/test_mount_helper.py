#!/usr/bin/env python3
"""Exercise the real privileged helper without mounting host or guest filesystems."""

import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).with_name("mount-helper.c").resolve()


@unittest.skipUnless(sys.platform.startswith("linux"), "requires Linux openat/procfs")
class MountHelperTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        compiler = shutil.which("gcc")
        if compiler is None:
            raise RuntimeError("gcc is required to verify the Linux mount helper")
        cls.build = tempfile.TemporaryDirectory(prefix="yougori-mount-helper-build-")
        cls.addClassCleanup(cls.build.cleanup)
        build = Path(cls.build.name)
        cls.helper = build / "opendock-mount-helper"
        cls.harness = build / "directory-harness"
        flags = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror"]
        result = subprocess.run([*flags, str(SOURCE), "-o", str(cls.helper)],
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"production helper compilation failed:\n{result.stderr}")
        harness_source = build / "directory-harness.c"
        # Include the production functions; this harness only provides fixture
        # root descriptors and does not duplicate their path handling.
        harness_source.write_text(r"""
#define main mount_helper_program_main
#include SOURCE_PATH
#undef main

int main(int argc, char **argv) {
  if (argc < 3) return 2;
  int root = open(argv[2], O_PATH | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
  if (root < 0) return 1;
  int result;
  if (strcmp(argv[1], "alias") == 0 && argc == 3) {
    result = make_shared_alias(root);
  } else {
    const char *relative;
    bool create;
    if (strcmp(argv[1], "rename") == 0 && argc == 5) {
      if (rename(argv[2], argv[3]) != 0 || mkdir(argv[2], 0755) != 0) {
        close(root);
        return 1;
      }
      relative = argv[4];
      create = true;
    } else if ((strcmp(argv[1], "mkdir") == 0 ||
                strcmp(argv[1], "open") == 0) && argc == 4) {
      relative = argv[3];
      create = strcmp(argv[1], "mkdir") == 0;
    } else {
      close(root);
      return 2;
    }
    int directory = open_relative_directory(root, relative, create);
    result = directory < 0 ? -1 : 0;
    if (directory >= 0) {
      struct stat status;
      if (fstat(directory, &status) != 0) result = -1;
      else printf("%llu %llu\n", (unsigned long long)status.st_dev,
                  (unsigned long long)status.st_ino);
      close(directory);
    }
  }
  close(root);
  return result == 0 ? 0 : 1;
}
""".replace("SOURCE_PATH", json.dumps(str(SOURCE))), encoding="utf-8")
        result = subprocess.run([*flags, str(harness_source), "-o", str(cls.harness)],
                                capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(f"test harness compilation failed:\n{result.stderr}")

    def setUp(self):
        self.fixture = tempfile.TemporaryDirectory(prefix="yougori-mount-helper-test-")
        self.addCleanup(self.fixture.cleanup)
        self.base = Path(self.fixture.name)
        self.root = self.base / "guest"
        self.outside = self.base / "outside"
        self.root.mkdir()
        self.outside.mkdir()
        (self.outside / "sentinel").write_bytes(b"outside remains untouched\n")

    def run_harness(self, mode, *args, root=None):
        return subprocess.run([str(self.harness), mode, str(root or self.root),
                               *map(str, args)], capture_output=True, text=True,
                              timeout=10)

    def assert_outside_unchanged(self):
        self.assertEqual(sorted(path.name for path in self.outside.iterdir()),
                         ["sentinel"])
        self.assertEqual((self.outside / "sentinel").read_bytes(),
                         b"outside remains untouched\n")

    def test_creates_nested_destination_and_opens_existing_source_inode(self):
        result = self.run_harness("mkdir", "opendock/shared/slot/nested")
        self.assertEqual(result.returncode, 0, result.stderr)
        target = self.root / "opendock/shared/slot/nested"
        status = target.stat()
        self.assertEqual(tuple(map(int, result.stdout.split())),
                         (status.st_dev, status.st_ino))
        source = self.run_harness("open", "opendock/shared/slot/nested")
        self.assertEqual(source.returncode, 0, source.stderr)
        self.assertEqual(source.stdout, result.stdout)
        self.assert_outside_unchanged()

    def test_source_lookup_does_not_create_missing_directories(self):
        result = self.run_harness("open", "var/lib/opendock/shares/missing")
        self.assertEqual(result.returncode, 1)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assert_outside_unchanged()

    def test_every_ancestor_and_leaf_symlink_is_refused_for_source_and_target(self):
        components = ["opendock", "shared", "slot"]
        for mode in ("mkdir", "open"):
            for position in range(len(components)):
                with self.subTest(mode=mode, symlink=components[position]):
                    root = self.base / f"{mode}-{position}"
                    root.mkdir()
                    parent = root
                    for component in components[:position]:
                        parent /= component
                        parent.mkdir()
                    (parent / components[position]).symlink_to(self.outside,
                                                               target_is_directory=True)
                    result = self.run_harness(mode, "/".join(components), root=root)
                    self.assertEqual(result.returncode, 1)
                    self.assert_outside_unchanged()

    def test_regular_file_at_an_intermediate_or_leaf_component_is_refused(self):
        for relative in ("opendock", "opendock/shared/slot"):
            with self.subTest(relative=relative):
                root = self.base / relative.replace("/", "-")
                root.mkdir()
                leaf = root / relative
                leaf.parent.mkdir(parents=True, exist_ok=True)
                leaf.write_bytes(b"owned file")
                result = self.run_harness("mkdir", "opendock/shared/slot", root=root)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(leaf.read_bytes(), b"owned file")
                self.assert_outside_unchanged()

    def test_empty_absolute_parent_and_ambiguous_components_are_refused(self):
        relatives = ["", "/outside", ".", "..", "a/../b", "a/./b", "a//b",
                     "a/", "x" * 4096]
        for relative in relatives:
            with self.subTest(relative=relative[:80]):
                result = self.run_harness("mkdir", relative)
                self.assertEqual(result.returncode, 1)
                self.assert_outside_unchanged()

    def test_pinned_root_survives_rename_and_path_replacement(self):
        renamed = self.base / "renamed-guest"
        result = self.run_harness("rename", renamed, "opendock/shared/slot")
        self.assertEqual(result.returncode, 0, result.stderr)
        target = renamed / "opendock/shared/slot"
        self.assertTrue(target.is_dir())
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(tuple(map(int, result.stdout.split())),
                         (target.stat().st_dev, target.stat().st_ino))
        self.assert_outside_unchanged()

    def test_shared_alias_is_created_and_idempotent_without_guest_programs(self):
        self.assertEqual(self.run_harness("alias").returncode, 0)
        alias = self.root / "yougori/shared"
        self.assertEqual(os.readlink(alias), "/opendock/shared")
        inode = alias.lstat().st_ino
        self.assertEqual(self.run_harness("alias").returncode, 0)
        self.assertEqual(alias.lstat().st_ino, inode)
        self.assertFalse((self.root / "bin").exists())
        self.assert_outside_unchanged()

    def test_alias_refuses_redirected_ancestor_and_preserves_foreign_leaf(self):
        for kind in ("ancestor", "file", "directory", "link", "long-link"):
            with self.subTest(kind=kind):
                root = self.base / f"alias-{kind}"
                root.mkdir()
                parent = root / "yougori"
                if kind == "ancestor":
                    parent.symlink_to(self.outside, target_is_directory=True)
                    leaf = parent
                else:
                    parent.mkdir()
                    leaf = parent / "shared"
                    if kind == "file":
                        leaf.write_bytes(b"user-owned alias name")
                    elif kind == "directory":
                        leaf.mkdir()
                        (leaf / "marker").write_bytes(b"preserved")
                    else:
                        leaf.symlink_to(str(self.outside) if kind == "link" else "x" * 256)
                inode = leaf.lstat().st_ino
                result = self.run_harness("alias", root=root)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(leaf.lstat().st_ino, inode)
                if kind == "file":
                    self.assertEqual(leaf.read_bytes(), b"user-owned alias name")
                elif kind == "directory":
                    self.assertEqual((leaf / "marker").read_bytes(), b"preserved")
                self.assert_outside_unchanged()

    def test_cli_rejects_invalid_arguments_before_process_lookup(self):
        source = "/var/lib/opendock/shares/slot"
        destination = "/opendock/shared/slot"
        cases = [[], ["2"], ["2", "--shared-alias", "extra"]]
        for pid in ("", "0", "1", "-1", "abc", "2junk", "2147483648", "9" * 100):
            cases.append([pid, source, destination, "false"])
            cases.append([pid, "--shared-alias"])
        cases.extend([
            ["2147483647", "/outside", destination, "false"],
            ["2147483647", source, "/outside", "false"],
            ["2147483647", source + "/../escape", destination, "false"],
            ["2147483647", source, destination + "/../escape", "false"],
            ["2147483647", source, destination, "yes"],
            ["2147483647", source, destination, "1"],
            ["2147483647", "--unmount", "/outside"],
        ])
        for arguments in cases:
            with self.subTest(arguments=arguments):
                result = subprocess.run([str(self.helper), *arguments],
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assert_outside_unchanged()

    def test_cli_unmount_of_missing_process_is_idempotent(self):
        self.assertFalse(Path("/proc/2147483647").exists())
        result = subprocess.run([str(self.helper), "2147483647", "--unmount",
                                 "/opendock/shared/slot"], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list(self.root.iterdir()), [])
        self.assert_outside_unchanged()

    @unittest.skipUnless(hasattr(os, "geteuid") and os.geteuid() == 0,
                         "requires root for a disposable child chroot")
    def test_real_process_alias_works_in_empty_chroot_and_rejects_escape(self):
        # Python is loaded before chroot. The guest contains no executable;
        # the helper must operate through the child's pinned procfs root.
        child = subprocess.Popen([
            sys.executable, "-c",
            "import os,sys,time; os.chroot(sys.argv[1]); os.chdir('/'); "
            "print('ready',flush=True); time.sleep(120)", str(self.root),
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            readable, _, _ = select.select([child.stdout], [], [], 10)
            self.assertTrue(readable, "disposable chroot child did not become ready")
            self.assertEqual(child.stdout.readline().strip(), "ready")
            command = [str(self.helper), str(child.pid), "--shared-alias"]
            for _ in range(2):
                result = subprocess.run(command, capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
            alias = self.root / "yougori/shared"
            self.assertEqual(os.readlink(alias), "/opendock/shared")
            alias.unlink()
            alias.parent.rmdir()
            (self.root / "yougori").symlink_to(self.outside, target_is_directory=True)
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assert_outside_unchanged()
        finally:
            child.terminate()
            try:
                child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=10)


if __name__ == "__main__":
    unittest.main()
