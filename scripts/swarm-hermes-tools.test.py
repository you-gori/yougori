"""Disposable source fixtures; no Hermes installation or model required."""
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src-tauri/src/swarm"))
from hermes_tools import ManagedTools


class SourceToolsTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        (self.root / "project").mkdir()
        self.tools = ManagedTools(self.root, "ses_fixture")

    def test_read_and_grep_reach_lines_after_the_first_64k(self):
        (self.root / "project/source.py").write_text(
            ("x" * 99 + "\n") * 700 + "CANARY = True\nlast line\n", encoding="utf-8")
        read = self.tools.handler("read")
        self.assertEqual(read({"filePath": "project/source.py", "offset": 701, "limit": 1}), "CANARY = True")
        self.assertEqual(read({"filePath": "project/source.py", "offset": 702, "limit": 1}), "last line")
        self.assertIn("source.py:701: CANARY = True", self.tools.handler("grep")({"pattern": "CANARY"}))

    def test_giant_first_line_does_not_hide_subsequent_lines(self):
        (self.root / "project/large.txt").write_text("x" * 100000 + "\nneedle\n", encoding="utf-8")
        read = self.tools.handler("read")
        self.assertEqual(len(read({"filePath": "project/large.txt", "limit": 1})), 16000)
        self.assertEqual(read({"filePath": "project/large.txt", "offset": 2}), "needle")
        self.assertIn("large.txt:2: needle", self.tools.handler("grep")({"pattern": "needle"}))

    def test_outside_source_and_oversized_files_remain_refused(self):
        (self.root / "private.txt").write_text("private", encoding="utf-8")
        with self.assertRaises(PermissionError):
            self.tools.handler("read")({"filePath": "project/../private.txt"})
        with (self.root / "project/oversized").open("wb") as output:
            output.truncate(8 * 1024 * 1024 + 1)
        with self.assertRaises(ValueError):
            self.tools.handler("read")({"filePath": "project/oversized"})

    def test_large_search_results_are_bounded_complete_json(self):
        line = "needle " + "\u2603\\\"" * 130
        (self.root / "project/matches.txt").write_text((line + "\n") * 200, encoding="utf-8")
        output = self.tools.handler("grep")({"pattern": "needle"})
        self.assertLessEqual(len(output), 16000)
        matches = json.loads(output)
        self.assertGreater(len(matches), 0)
        self.assertLess(len(matches), 200)
        self.assertEqual(matches[0], "project/matches.txt:1: " + line[:400])

    def test_large_glob_results_are_bounded_complete_json(self):
        for index in range(200):
            (self.root / "project" / (str(index) + "x" * 100)).touch()
        output = self.tools.handler("glob")({"pattern": "*"})
        self.assertLessEqual(len(output), 16000)
        matches = json.loads(output)
        self.assertGreater(len(matches), 0)
        self.assertTrue(all((self.root / path).is_file() for path in matches))

    def test_grep_can_search_one_file(self):
        (self.root / "project/source.py").write_text("needle\n", encoding="utf-8")
        output = self.tools.handler("grep")({"pattern": "needle", "path": "project/source.py"})
        self.assertEqual(json.loads(output), ["project/source.py:1: needle"])


if __name__ == "__main__":
    unittest.main()
