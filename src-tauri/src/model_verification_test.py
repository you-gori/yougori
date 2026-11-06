"""Offline checkpoint integrity and cache-hint recovery with tiny local files."""
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

with patch.dict(os.environ, YOUGORI_MODEL="fixture/model", YOUGORI_MODEL_TOKEN="fixture-token"):
    import model_server as model


class VerificationTests(unittest.TestCase):
    def setUp(self):
        scratch = "D:/YougoriBuildCache/scratch"
        self.folder = tempfile.TemporaryDirectory(dir=scratch if os.path.isdir(scratch) else None)
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        self.path = self.root / "weights.bin"
        self.content = b"tiny fixture weights"
        self.path.write_bytes(self.content)
        self.digest = hashlib.sha256(self.content).hexdigest()
        self.record = self.root / "yougori-verified.json"
        self.cache = patch.object(model, "CACHE", str(self.root))
        self.cache.start()
        self.addCleanup(self.cache.stop)

    def test_sha256_and_git_blob_hashes_and_invalid_identities(self):
        git_digest = hashlib.sha1(b"blob " + str(len(self.content)).encode() + b"\0" + self.content).hexdigest()
        for digest in (self.digest, self.digest.upper(), git_digest):
            self.assertTrue(model.verify_file(str(self.path), digest))
        for digest in (None, 17, "z" * 64, "a" * 39, "a" * 64):
            self.assertFalse(model.verify_file(str(self.path), digest))
            self.assertFalse(model.verified_weight(str(self.path), digest))

    def test_growing_file_is_rejected_after_bounded_reads(self):
        real_open = open
        sizes = []

        class GrowingReader:
            def __init__(inner):
                inner.file = real_open(self.path, "rb")

            def __enter__(inner):
                return inner

            def __exit__(inner, *_):
                inner.file.close()

            def fileno(inner):
                return inner.file.fileno()

            def read(inner, size):
                sizes.append(size)
                data = inner.file.read(size)
                with real_open(self.path, "ab") as writer:
                    writer.write(b"growth")
                return data

        with patch("builtins.open", return_value=GrowingReader()):
            self.assertFalse(model.verify_file(str(self.path), self.digest, progress=True))
        self.assertEqual(sizes, [len(self.content), 1])
        self.assertEqual(model.STATE["verification"]["totalBytes"], len(self.content))

    def test_path_identity_change_during_hash_is_rejected(self):
        real_stat = model.os.stat
        calls = 0

        def changed(path, *args, **kwargs):
            nonlocal calls
            info = real_stat(path, *args, **kwargs)
            calls += 1
            if calls == 2:
                values = {key: getattr(info, key) for key in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}
                values["st_ino"] += 1
                return SimpleNamespace(**values)
            return info

        with patch.object(model.os, "stat", side_effect=changed):
            self.assertFalse(model.verify_file(str(self.path), self.digest))

    def test_distinct_ctime_semantics_still_detect_descriptor_changes(self):
        original_fstat = model.os.fstat
        path_ctime = self.path.stat().st_ctime_ns
        for mutation in (False, True):
            calls = 0

            def descriptor_info(descriptor):
                nonlocal calls
                calls += 1
                info = original_fstat(descriptor)
                values = {key: getattr(info, key) for key in ("st_mode", "st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}
                values["st_ctime_ns"] = path_ctime + 1000000 + (calls if mutation else 0)
                return SimpleNamespace(**values)

            with self.subTest(mutation=mutation), patch.object(model.os, "fstat", side_effect=descriptor_info):
                self.assertEqual(model.verify_file(str(self.path), self.digest), not mutation)

    def test_change_after_hash_cannot_publish_a_verification_hint(self):
        verify = model.verify_file

        def changed(*args, **kwargs):
            result = verify(*args, **kwargs)
            with self.path.open("ab") as writer:
                writer.write(b"changed")
            return result

        with patch.object(model, "verify_file", side_effect=changed):
            self.assertFalse(model.verified_weight(str(self.path), self.digest))
        self.assertFalse(self.record.exists())

    def test_stable_file_reuses_hint_but_old_stamp_rehashes(self):
        info = self.path.stat()
        self.record.write_text(json.dumps({str(self.path.resolve()): [info.st_size, info.st_mtime_ns, info.st_ctime_ns, self.digest]}))
        with patch.object(model, "verify_file", wraps=model.verify_file) as verify:
            self.assertTrue(model.verified_weight(str(self.path), self.digest, len(self.content)))
            verify.assert_called_once()
        with patch.object(model, "verify_file", side_effect=AssertionError("unchanged file rehashed")):
            self.assertTrue(model.verified_weight(str(self.path), self.digest))
        self.assertFalse(model.verified_weight(str(self.path), self.digest, len(self.content) + 1))

    def test_missing_nonregular_and_corrupted_files_are_refused(self):
        self.assertFalse(model.verify_file(str(self.root), self.digest))
        self.assertFalse(model.verified_weight(str(self.root), self.digest))
        self.path.unlink()
        self.assertFalse(model.verify_file(str(self.path), self.digest))
        self.assertFalse(model.verified_weight(str(self.path), self.digest))
        self.path.write_bytes(b"bad")
        self.assertFalse(model.verified_weight(str(self.path), self.digest))
        self.assertFalse(self.record.exists())

    def test_cache_hit_rechecks_file_after_reading_hint(self):
        self.assertTrue(model.verified_weight(str(self.path), self.digest))
        encoded = self.record.read_text()

        class ChangedDuringCacheRead(io.StringIO):
            def read(inner, size):
                result = super().read(size)
                self.path.write_bytes(b"changed during hint read")
                return result

        with patch("builtins.open", return_value=ChangedDuringCacheRead(encoded)), \
             patch.object(model, "verify_file", side_effect=AssertionError("cache-hit path")):
            self.assertFalse(model.verified_weight(str(self.path), self.digest))

    def test_corrupt_oversized_or_nested_cache_rehashes(self):
        for value in ("[]", "PRIVATE", " " * (2 * 1024 * 1024 + 1), "[" * 2000 + "0" + "]" * 2000):
            with self.subTest(length=len(value)):
                self.record.write_text(value)
                with patch.object(model, "verify_file", wraps=model.verify_file) as verify:
                    self.assertTrue(model.verified_weight(str(self.path), self.digest))
                    verify.assert_called_once()
                self.assertEqual(len(json.loads(self.record.read_text())), 1)

    def test_cache_has_bounded_entries_and_discards_invalid_shapes(self):
        stamp = model.verification_stamp(self.path.stat(), self.digest)
        rows = {"old-" + str(index): stamp for index in range(2000)}
        rows.update(private="PRIVATE", wrong_shape=[2], bool_stamp=[2, True, *stamp[2:]])
        self.record.write_text(json.dumps(rows))
        self.assertTrue(model.verified_weight(str(self.path), self.digest))
        rows = json.loads(self.record.read_text())
        self.assertEqual(len(rows), 1024)
        self.assertNotIn("PRIVATE", self.record.read_text())
        self.assertNotIn("bool_stamp", rows)
        self.assertIn(str(self.path.resolve()), rows)

    def test_cache_write_failure_does_not_reject_verified_content(self):
        with patch.object(model.os, "replace", side_effect=PermissionError("PRIVATE")):
            self.assertTrue(model.verified_weight(str(self.path), self.digest))
        self.assertEqual(list(self.root.glob("*.tmp")), [])
        self.assertFalse(self.record.exists())

    def test_temp_collision_never_removes_another_writers_file(self):
        other = self.root / "yougori-verified.json.collision.tmp"
        other.write_bytes(b"other writer")
        with patch.object(model.secrets, "token_hex", return_value="collision"):
            self.assertTrue(model.verified_weight(str(self.path), self.digest))
        self.assertEqual(other.read_bytes(), b"other writer")

    def test_concurrent_cache_writers_use_independent_temporary_files(self):
        second = self.root / "other.bin"
        second.write_bytes(self.content)
        barrier = threading.Barrier(2)
        replace = model.os.replace
        sources, results, errors = [], [], []

        def synchronized(source, target):
            sources.append(source)
            barrier.wait(timeout=3)
            replace(source, target)

        def verify(path):
            try:
                results.append(model.verified_weight(str(path), self.digest))
            except Exception as error:
                errors.append(error)

        with patch.object(model.os, "replace", side_effect=synchronized):
            threads = [threading.Thread(target=verify, args=(path,)) for path in (self.path, second)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(5)
        self.assertTrue(all(not thread.is_alive() for thread in threads))
        self.assertEqual(errors, [])
        self.assertEqual(results, [True, True])
        self.assertEqual(len(set(sources)), 2)
        self.assertIsInstance(json.loads(self.record.read_text()), dict)
        self.assertEqual(list(self.root.glob("*.tmp")), [])


class PreparedSourceTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(dir="D:/YougoriBuildCache/scratch" if os.path.isdir("D:/YougoriBuildCache/scratch") else None)
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name) / "snapshot"
        self.root.mkdir()
        self.config = {"model_type": "fixture", "architectures": ["Fixture"]}
        contents = {"config.json": json.dumps(self.config).encode(), "model.safetensors": b"weights",
                    "tokenizer.json": b"{}", "model.safetensors.index.json": b"{}"}
        self.items = []
        for name, content in contents.items():
            (self.root / name).write_bytes(content)
            self.items.append(SimpleNamespace(rfilename=name, size=len(content),
                lfs={"sha256": hashlib.sha256(content).hexdigest()}))
        self.metadata = SimpleNamespace(sha="a" * 40, siblings=self.items)
        for name, value in [("CACHE", self.folder.name), ("MODEL_REVISION", "a" * 40), ("VLLM_PREPARED", None)]:
            p = patch.object(model, name, value); p.start(); self.addCleanup(p.stop)
        p = patch.dict(os.environ, YOUGORI_VLLM_SOURCE_REUSE="1"); p.start(); self.addCleanup(p.stop)

    def capture(self):
        model.remember_vllm_source(self.metadata, str(self.root), self.config, 7)
        self.assertIsNotNone(model.VLLM_PREPARED)

    def test_reuses_verified_files_without_hashing_unchanged_bytes(self):
        self.capture()
        with patch.object(model, "verify_file", side_effect=AssertionError("unexpected hash")):
            root, config, size = model.prepared_vllm_source()
        self.assertEqual((root, config, size), (str(self.root), self.config, 7))
        config["model_type"] = "mutated caller copy"
        self.assertEqual(model.prepared_vllm_source()[1], self.config)

    def test_changed_weights_configuration_tokenizer_and_index_are_refused(self):
        for item in self.items:
            with self.subTest(name=item.rfilename):
                path = self.root / item.rfilename
                original = path.read_bytes()
                self.capture()
                path.write_bytes(b"x" * len(original))
                with self.assertRaisesRegex(RuntimeError, "source changed"):
                    model.prepared_vllm_source()
                self.assertIsNone(model.VLLM_PREPARED)
                path.write_bytes(original)

    def test_added_removed_and_replaced_files_invalidate_the_memo(self):
        self.capture()
        extra = self.root / "unexpected.safetensors"; extra.write_bytes(b"extra")
        with self.assertRaises(RuntimeError): model.prepared_vllm_source()
        extra.unlink()
        self.capture()
        original = (self.root / "tokenizer.json").read_bytes()
        (self.root / "tokenizer.json").unlink()
        with self.assertRaises(RuntimeError): model.prepared_vllm_source()
        (self.root / "tokenizer.json").write_bytes(original)
        self.capture()
        replacement = self.root / "replacement"
        replacement.write_bytes(original)
        replacement.replace(self.root / "tokenizer.json")
        # Same pinned bytes are valid after a fresh hash, even with a new inode.
        with patch.object(model, "verify_file", wraps=model.verify_file) as verify:
            self.assertIsNotNone(model.prepared_vllm_source())
        self.assertGreater(verify.call_count, 0)

    def test_identity_changes_and_opt_out_keep_the_cold_path(self):
        for name, value in [("MODEL", "other/model"), ("MODEL_REVISION", "b" * 40),
                            ("VLLM_VERSION", "different"), ("CACHE", str(self.root))]:
            self.capture()
            with patch.object(model, name, value):
                self.assertIsNone(model.prepared_vllm_source())
            self.assertIsNone(model.VLLM_PREPARED)
        self.capture()
        with patch.dict(os.environ, YOUGORI_VLLM_SOURCE_REUSE="0"):
            self.assertIsNone(model.prepared_vllm_source())
            model.remember_vllm_source(self.metadata, str(self.root), self.config, 7)
            self.assertIsNone(model.VLLM_PREPARED)

    def test_incomplete_metadata_never_creates_an_offline_trust_shortcut(self):
        for field, value in [("lfs", None), ("size", True), ("size", -1)]:
            with patch.object(self.items[0], field, value):
                model.remember_vllm_source(self.metadata, str(self.root), self.config, 7)
            self.assertIsNone(model.VLLM_PREPARED)
        self.metadata.siblings.append(self.items[0])
        model.remember_vllm_source(self.metadata, str(self.root), self.config, 7)
        self.assertIsNone(model.VLLM_PREPARED)

    def test_capture_checks_config_matches_preflight_and_bounds_inventory(self):
        with self.assertRaisesRegex(RuntimeError, "configuration changed"):
            model.remember_vllm_source(self.metadata, str(self.root), {"other": True}, 7)
        self.assertIsNone(model.VLLM_PREPARED)
        entries = [SimpleNamespace(name=str(i), is_dir=lambda **kw:False, is_file=lambda:True) for i in range(4097)]
        from unittest.mock import MagicMock
        with patch.object(model.os, "scandir", return_value=MagicMock(__enter__=lambda _: iter(entries), __exit__=lambda *args:None)):
            with self.assertRaises(ValueError): model.source_inventory(str(self.root))

    def test_membership_change_during_verification_never_returns_reusable_source(self):
        self.capture()
        original = model.verified_weight
        def mutate(*args):
            (self.root / "new.json").write_bytes(b"{}")
            return original(*args)
        with patch.object(model, "verified_weight", side_effect=mutate), self.assertRaises(RuntimeError):
            model.prepared_vllm_source()
        self.assertIsNone(model.VLLM_PREPARED)


if __name__ == "__main__":
    unittest.main()
