"""Publisher artifact import preserves each harness's VM filesystem budget."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'site/harnesses'))
import vm_host


class ImportBudget(unittest.TestCase):
    def test_shannon_budget_survives_archive_entries_and_cache(self):
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, 'w') as archive:
            archive.writestr('oci-layout', '{}')
            archive.writestr('blobs/sha256/' + 'a' * 64, '{}')
        raw = stream.getvalue()
        digest = hashlib.sha256(raw).hexdigest()
        descriptor = {'sha256': digest, 'bytes': len(raw), 'runtime': 'yougori-sandbox-vm', 'platform': 'linux/amd64'}
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_GET(self):
                body = raw if self.path.endswith(digest) else json.dumps(descriptor).encode()
                self.send_response(200)
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        imports = []
        identity = 'sha256:' + 'b' * 64
        def engine(action, **params):
            if action == 'status': return {}
            if params['operation'] == 'list': return [{'id': identity}]
            imports.append(params)
            return {'id': identity}
        with tempfile.TemporaryDirectory() as folder, patch.object(vm_host, 'call', side_effect=engine):
            root = Path(folder)
            url = f'http://127.0.0.1:{server.server_port}'
            vm_host.install('shannon', url, root)
            self.assertEqual(imports[-1]['rootGb'], 3)
            vm_host.install('shannon', url, root)
            self.assertEqual(len(imports), 1)
            # Same archive bytes with a different requested budget cannot reuse
            # an incompatible import record.
            vm_host.install('pi', url, root)
            self.assertEqual(imports[-1]['rootGb'], 2)
            self.assertEqual(len(imports), 2)


class LaunchChoices(unittest.TestCase):
    """What the permission menu chose reaches the VM launch, and nothing more."""

    def test_defaults_reach_only_the_inference(self):
        params = vm_host.launch_params('pi', 'sha256:' + 'a' * 64, None)
        self.assertEqual((params['cpu'], params['memoryGb']), (2, 4))
        # Long sessions: the relay publication is the owner's alone, with an owner session's budget.
        self.assertIs(params['ownerSession'], True)
        self.assertNotIn('internet', params)
        self.assertNotIn('workspace', params)
        self.assertEqual(vm_host.launch_params('shannon', 'sha256:' + 'a' * 64, None)['memoryGb'], 6)

    def test_chosen_size_folder_and_internet(self):
        params = vm_host.launch_params('pi', 'sha256:' + 'a' * 64, Path('C:/work/app'), cpu=6, memory=12, internet=True)
        self.assertEqual((params['cpu'], params['memoryGb'], params['internet']), (6, 12, True))
        self.assertEqual(Path(params['workspace']), Path('C:/work/app'))
        # The model relay is published as before: internet adds to it, never replaces it.
        self.assertEqual(params['publish'], 'solver=8090')

    def test_launcher_refuses_sizes_outside_the_engine_range(self):
        import solver
        self.assertEqual(solver.vm_size(None, None), (None, None))
        self.assertEqual(solver.vm_size(4, 8), (4, 8))
        for cpu, memory in ((0, None), (256, None), (None, 0), (None, 1025)):
            with self.assertRaises(ValueError):
                solver.vm_size(cpu, memory)
        self.assertNotIn('off', solver.INTERNET)  # the VM always reaches the inference


if __name__ == '__main__': unittest.main()
