"""Verify release builds reject compilers below the standard-library patch floor."""

from pathlib import Path
import os
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class AgentGoPatchFloorTests(unittest.TestCase):
    def test_rejects_old_go_and_accepts_patched_or_newer_go(self):
        with tempfile.TemporaryDirectory() as temp:
            go = Path(temp) / "go"
            go.write_text('#!/bin/sh\nprintf "go version go%s linux/amd64\\n" "$YOUGORI_TEST_GO_VERSION"\n')
            go.chmod(0o755)
            for version, expected in (("1.25.0", 1), ("1.27.1", 1), ("1.27.2", 0), ("1.28.0", 0)):
                with self.subTest(version=version):
                    env = {**os.environ, "PATH": str(go.parent) + ":" + os.environ["PATH"], "YOUGORI_TEST_GO_VERSION": version}
                    result = subprocess.run(["bash", str(ROOT / "scripts/check-agent-go.sh")], env=env, capture_output=True)
                    self.assertEqual(result.returncode, expected, result.stderr.decode())
                    if expected:
                        self.assertIn("patched Go 1.27.2", result.stderr.decode())


if __name__ == "__main__":
    unittest.main()
