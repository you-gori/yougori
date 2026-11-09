import base64
from contextlib import closing
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site"))
from hosted import create
from store import Store, password_matches


class Hosted(unittest.TestCase):
    def config(self, root):
        salt = bytes(range(16))
        key = hashlib.scrypt(b"fixture-password", salt=salt, n=32768, r=8, p=1, dklen=32, maxmem=96*1024*1024)
        credential = "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(key).decode()
        value = {"id": "inf_" + "a"*16, "email": "admin@example.test", "passwordHash": credential,
                 "siteName": "Hosted test", "accessMode": "internal", "wallet": None,
                 "compute": {"neocloud": False, "neoGrid": True, "sandboxGrid": True, "publicContributors": False}}
        (root / "provision.json").write_text(json.dumps(value))
        return value

    def test_imported_credential_and_committed_data_survive_a_new_vm_working_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = self.config(root)
            first = create(root, "abc.localhost:12000", root / "vm1")
            try:
                with first.store.db() as db:
                    admin = db.execute("SELECT password FROM users WHERE admin=1").fetchone()[0]
                    self.assertTrue(password_matches("fixture-password", admin))
                    self.assertFalse(password_matches("wrong-password", admin))
                    db.execute("UPDATE settings SET name='Persisted change' WHERE id=1")
            finally:
                first.close()  # its media watcher holds the database while it reads
            with closing(sqlite3.connect(root / "data/inference-solver.sqlite3")) as db:
                self.assertEqual(db.execute("SELECT name FROM settings").fetchone()[0], "Persisted change")
            second = create(root, "def.localhost:12001", root / "vm2")
            try:
                self.assertEqual(second.store.settings()["name"], "Persisted change")
                self.assertEqual(second.account_mode, "private")
            finally:
                second.close()
            config["accessMode"] = "public"
            (root / "provision.json").write_text(json.dumps(config))
            with self.assertRaisesRegex(ValueError, "another inference or access mode"):
                create(root, "ghi.localhost:12002", root / "vm3")

    def test_snapshot_failure_blocks_more_operations_and_keeps_last_durable_database(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = Store(root / "data", {"email":"admin@example.test","password":"fixture-password"},
                          journal_mode="DELETE", runtime_folder=root / "vm")
            with patch.object(Path, "replace", side_effect=OSError("fixture disk failure")):
                with self.assertRaises(OSError):
                    with store.db() as db:
                        db.execute("UPDATE settings SET name='Must not be acknowledged' WHERE id=1")
            with self.assertRaisesRegex(OSError, "durable database"):
                with store.db():
                    pass
            recovered = Store(root / "data", runtime_folder=root / "vm2", journal_mode="DELETE")
            self.assertEqual(recovered.settings()["name"], "Inference Solver")


if __name__ == "__main__":
    unittest.main()
