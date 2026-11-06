"""Offline checks; these do not establish GPU support on any machine."""
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("gpu_probe", Path(__file__).with_name("probe.py"))
probe = importlib.util.module_from_spec(spec)
spec.loader.exec_module(probe)


class ProbeTests(unittest.TestCase):
    def test_no_host_mounts_nics_or_guest_manager(self):
        config = probe.configuration(Path("C:/fixed"))
        vm = config["VirtualMachine"]
        self.assertTrue(config["ShouldTerminateOnLastHandleClosed"])
        self.assertEqual(set(vm["Devices"]), {"HvSocket"})
        self.assertNotIn("GuestConnection", vm)
        self.assertNotIn("Gpu", vm["ComputeTopology"])
        sockets = vm["Devices"]["HvSocket"]["HvSocketConfig"]
        self.assertEqual(sockets["DefaultBindSecurityDescriptor"], "D:P")
        self.assertFalse(sockets["ServiceTable"][probe.SERVICE]["AllowWildcardBinds"])
        service = sockets["ServiceTable"][probe.SERVICE]
        self.assertEqual(service["BindSecurityDescriptor"], "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
        self.assertEqual(service["ConnectSecurityDescriptor"], service["BindSecurityDescriptor"])

    def test_bad_hash_and_extra_paths_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = {}
            for name in ["kernel", "initrd"]:
                (root / name).write_bytes(name.encode())
                files[name] = hashlib.sha256(name.encode()).hexdigest()
            manifest = {"version": 1, "localOnly": True, "files": files}
            (root / "manifest.json").write_text(json.dumps(manifest))
            probe.verify_bundle(root)
            (root / "initrd").write_bytes(b"changed")
            with self.assertRaisesRegex(ValueError, "checksum"):
                probe.verify_bundle(root)
            files["../outside"] = "0" * 64
            (root / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "not a local"):
                probe.verify_bundle(root)


if __name__ == "__main__":
    unittest.main()
