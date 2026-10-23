"""Exercise the native owner's guest script against disposable receipt files."""
import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock
import uuid

source = (Path(__file__).resolve().parents[1] / "src-tauri/src/swarm/guest.rs").read_text(encoding="utf-8")
SCRIPT = source.split("pub(crate) async fn drain_tools(", 1)[1].split('let script = r#"', 1)[1].split('"#;', 1)[0]


@unittest.skipUnless(hasattr(os, "O_NOFOLLOW"), "The native spool runs in the Linux guest")
class SpoolTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.script = SCRIPT.replace("p='/srv/yougori-swarm/spool'", "p=" + repr(str(self.root)))
        self.identity = str(uuid.uuid4())

    def drain(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            exec(compile(self.script, "native-tool-spool", "exec"), {})
        return json.loads(output.getvalue())

    def test_receipts_removed_after_directory_listing_do_not_stop_the_worker(self):
        for suffix in [".ack", ".pending", ".response", ".request"]:
            with self.subTest(suffix=suffix):
                path = self.root / (self.identity + suffix)
                path.write_text("{}", encoding="utf-8")
                lstat = os.lstat

                def removed_before_stat(candidate, *args, **kwargs):
                    if str(candidate) == str(path) and path.exists():
                        path.unlink()
                    return lstat(candidate, *args, **kwargs)

                with mock.patch("os.lstat", side_effect=removed_before_stat):
                    self.assertEqual(self.drain(), [])

    def test_request_removed_before_open_does_not_stop_the_worker(self):
        path = self.root / (self.identity + ".request")
        path.write_text(json.dumps({"id": self.identity, "action": "check"}), encoding="utf-8")
        open_file = os.open

        def removed_before_open(candidate, *args, **kwargs):
            if str(candidate) == str(path):
                path.unlink()
            return open_file(candidate, *args, **kwargs)

        with mock.patch("os.open", side_effect=removed_before_open):
            self.assertEqual(self.drain(), [])

    def test_valid_requests_survive_and_invalid_receipts_stay_rejected(self):
        request = {"id": self.identity, "action": "check", "params": {"index": 1}}
        path = self.root / (self.identity + ".request")
        path.write_text(json.dumps(request), encoding="utf-8")
        self.assertEqual(self.drain(), [request])
        self.assertTrue(path.exists())
        (self.root / (str(uuid.uuid4()) + ".response")).symlink_to(path)
        with self.assertRaisesRegex(ValueError, "Invalid retained tool receipt"):
            self.drain()


if __name__ == "__main__":
    unittest.main()
