"""Published VM origins keep their identity without using DNS or leaking credentials."""
import hashlib
import base64
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sys
import subprocess
import threading
import tempfile
import unittest
import urllib.error
import zipfile
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'site'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'site/harnesses'))
import harness_download
import compute_node
import device_login
import relay
import solver
from transport import opener
from vm_host import artifact_base, prepare_tool
import vm_relay


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def do_GET(self):
        self.server.seen.append((self.headers.get('Host'), self.headers.get('Authorization')))
        if self.path == '/redirect':
            self.send_response(302); self.send_header('Location', 'http://example.invalid/'); self.end_headers(); return
        raw = json.dumps({'data': [], 'host': self.headers.get('Host'),
                          'origin': self.headers.get('Origin'), 'authorization': self.headers.get('Authorization')}).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_POST(self):
        self.rfile.read(int(self.headers.get('Content-Length', 0)))
        self.do_GET()


class HostedDownloads(unittest.TestCase):
    def test_contributor_bundle_starts_in_isolated_python_and_reaches_its_origin(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler); server.seen = []
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        origin = 'http://abc123.localhost:' + str(server.server_port)
        try:
            with tempfile.TemporaryDirectory() as folder:
                with zipfile.ZipFile(io.BytesIO(harness_download.bundle('node', origin))) as archive:
                    archive.extractall(folder)
                root = Path(folder) / 'inference-solver'
                result = subprocess.run([sys.executable, '-I', '-B', str(root / 'cli_entry.py'), 'solver-node', '--help'],
                                        capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Contribute selected models', result.stdout)
                probe = root / 'probe.py'
                probe.write_text('import sys\nfrom pathlib import Path\nsys.path.insert(0,str(Path(__file__).resolve().parent))\n'
                                 'from compute_node import site_request\nimport json\n'
                                 'print(json.dumps(site_request(' + repr(origin) + ', "/api/compute/agent", {}, "fixture-key")))\n')
                result = subprocess.run([sys.executable, '-I', '-B', str(probe)], capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, 0, result.stderr)
                reply = json.loads(result.stdout)
                self.assertEqual(reply['host'], origin.removeprefix('http://'))
                self.assertEqual(reply['origin'], origin)
                self.assertEqual(reply['authorization'], 'Bearer fixture-key')
            with self.assertRaises(compute_node.SiteError) as raised:
                compute_node.site_request(origin, '/redirect', {}, 'fixture-key')
            self.assertEqual(raised.exception.code, 302)
        finally: server.shutdown(); server.server_close(); thread.join()

    def test_large_transfers_reconcile_lost_ack_and_smaller_runtime_limits(self):
        raw = b'package-transfer' * 180000
        digest = hashlib.sha256(raw).hexdigest()
        for small_limit in (False, True):
            class Control:
                def __init__(self): self.received = bytearray(); self.ready = False; self.lost = False
                def post(self, path, data):
                    if path == '/package/status':
                        return {'offset': len(self.received), 'phase': 'ready' if self.ready else 'waiting'}
                    if path == '/package/finish': self.ready = True; return {}
                    block = base64.b64decode(data['data'])
                    self_outer.assertEqual(data['offset'], len(self.received))
                    if small_limit and len(block) > 32 << 10: raise OSError('older runtime body limit')
                    self.received.extend(block)
                    if not self.lost:
                        self.lost = True
                        raise OSError('lost acknowledgement after accepted write')
                    return {'offset': len(self.received)}
            self_outer = self
            with tempfile.TemporaryDirectory() as folder:
                root = Path(folder); (root / 'tools').mkdir()
                (root / 'tools' / (digest + '.tar.gz')).write_bytes(raw)
                (root / 'tool-package.json').write_text(json.dumps({'sha256': digest, 'bytes': len(raw)}))
                control = Control()
                with patch('builtins.print'): prepare_tool(control, root)
                self.assertEqual(bytes(control.received), raw)
                self.assertTrue(control.ready)

    def test_isolated_origin_auth_and_model_calls_pin_loopback_and_preserve_host(self):
        server = ThreadingHTTPServer(('127.0.0.1', 0), Handler); server.seen = []
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        origin = 'http://abc123.localhost:' + str(server.server_port)
        try:
            self.assertEqual(harness_download.origin(origin), origin)
            self.assertEqual(solver.url(origin), origin)
            self.assertEqual(relay.server_url(origin).hostname, 'abc123.localhost')
            self.assertEqual(device_login.request(origin, '/auth', {})['host'], origin.removeprefix('http://'))
            self.assertEqual(solver.models(origin, 'fixture-key'), [])
            replies = []
            vm_relay.forward(origin, 'fixture-key', {'method':'GET','path':'/v1/models'}, replies.append)
            self.assertEqual(replies[0]['status'], 200)
            self.assertTrue(all(host == origin.removeprefix('http://') for host, _ in server.seen))
            with self.assertRaises(urllib.error.HTTPError): opener().open(origin + '/redirect')
            for invalid in ('http://abc.localhost.example.com', 'http://abc.localhost.', 'http://169.254.169.254'):
                with self.assertRaises(ValueError): solver.url(invalid)
        finally: server.shutdown(); server.server_close(); thread.join()

    def test_artifact_download_destination_is_narrow_and_does_not_allow_metadata_or_redirects(self):
        origin = 'http://abc123.localhost:12345'
        base = 'http://127.0.0.1:5173/api/inference/artifacts'
        self.assertEqual(artifact_base(origin, {'download_base': base}), base)
        self.assertEqual(artifact_base(origin, {}), origin + '/api/harness-image')
        for value in ('http://169.254.169.254/api/inference/artifacts', 'http://127.0.0.1:5173/admin',
                      'https://example.com/api/inference/artifacts', base + '?x=1', 'http://user@127.0.0.1:5173/api/inference/artifacts'):
            with self.assertRaises(ValueError): artifact_base(origin, {'download_base': value})
        with self.assertRaises(ValueError): artifact_base('https://remote.example', {'download_base': base})


if __name__ == '__main__': unittest.main()
