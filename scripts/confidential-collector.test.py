import importlib.util
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
import subprocess
import sys

spec = importlib.util.spec_from_file_location('collector', Path(__file__).parents[1] / 'runtime/confidential/collect-attestation.py')
collector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(collector)


class CollectorTests(unittest.TestCase):
    @unittest.skipIf(os.name != 'posix', 'The collector runs inside a Linux confidential VM')
    def test_vendor_output_is_capped_before_it_can_fill_memory(self):
        process = subprocess.Popen([sys.executable, '-c', 'import sys;sys.stdout.buffer.write(b"x" * 1048576)'], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with self.assertRaises(ValueError): collector.bounded_token(process)
        finally:
            process.kill(); process.wait(); process.stdout.close()

    def test_exact_public_descriptor_and_cpu_gpu_requirements_reach_the_vendor(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = Path(folder) / 'vendor-cli'; binary.write_bytes(b'synthetic binary')
            config = Path(folder) / 'vendor.json'; config.write_text('{}'); config.chmod(0o600)
            manifest = {'binary': str(binary.resolve()), 'binarySha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'config': str(config.resolve()), 'policyIds': ['composite-policy']}
            descriptor = dict(version=1, nodeId='nd_test', model='test/model', revision='a' * 40,
                              nonce='A' * 43, recipient='age1test', signingKey='B' * 43, issuedAt=1, expiresAt=61)
            args = collector.command(manifest, descriptor)
            self.assertIn('--tdx', args); self.assertIn('--nvgpu', args)
            self.assertIn('--policy-must-match', args); self.assertNotIn('--no-verifier-nonce', args)
            import base64
            self.assertEqual(json.loads(base64.b64decode(args[args.index('--user-data') + 1])), descriptor)
            for changes in ({'binarySha256': '0' * 64}, {'policyIds': []}, {'operatorKey': 'forbidden'}):
                with self.assertRaises(ValueError): collector.command({**manifest, **changes}, descriptor)
            with self.assertRaises(ValueError): collector.command(manifest, {**descriptor, 'prompt': 'must never be quoted'})


if __name__ == '__main__': unittest.main()
