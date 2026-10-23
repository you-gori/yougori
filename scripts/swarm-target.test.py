"""Exercise the actual managed HTTP probe against disposable loopback fixtures.

This checks the probe implementation, not container isolation or model accuracy.
"""
import base64
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie


class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.paths.append(self.path)
        cookies = SimpleCookie(self.headers.get('Cookie', ''))
        account = cookies['account'].value if 'account' in cookies else 'anonymous'
        status = 302 if self.path == '/redirect' else 200
        if self.path == '/private' and self.headers.get('Cookie') != 'fixture=test':
            status = 403
        if self.path.startswith('/accounts/') and self.path != '/accounts/' + account:
            status = 403
        self.send_response(status)
        if self.path == '/login':
            self.send_header('Set-Cookie', 'fixture=test; Path=/')
        if self.path in ['/login/alice', '/login/bob']:
            self.send_header('Set-Cookie', 'account=' + self.path.rsplit('/', 1)[1] + '; Path=/')
        if self.path == '/redirect':
            self.send_header('Location', '/landing')
        if self.path == '/large':
            for index in range(32):
                self.send_header(f'X-Fixture-{index}', 'a' * 2048)
        self.end_headers()
        self.wfile.write(b'\xff' * 20000 if self.path == '/large' else account.encode() if self.path == '/whoami' else b'fixture response')


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='yougori-probe-test-')
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        self.server.paths = []
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        source = (Path(__file__).resolve().parents[1] / 'src-tauri/src/swarm/target.rs').read_text()
        self.script = re.search(r'const HTTP_PROBE\s*:\s*&str\s*=\s*r#"(.*?)"#;', source, re.S).group(1)
        self.script = self.script.replace('/tmp/yougori-target-cookies', str(Path(self.folder.name) / 'cookies').replace('\\', '/'))

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)
        self.folder.cleanup()

    def probe(self, path, **options):
        args = {'method': 'GET', 'path': path, 'port': self.server.server_address[1]}
        args.update(options)
        encoded = base64.b64encode(json.dumps(args).encode()).decode()
        script = self.script.replace('__INPUT__', f"json.loads(base64.b64decode('{encoded}'))")
        result = subprocess.run([sys.executable, '-c', script], capture_output=True, timeout=15, check=True)
        self.assertLess(len(result.stdout), 21000)
        return json.loads(result.stdout)

    def test_real_http_status_cookies_and_no_redirect_following(self):
        self.assertEqual(self.probe('/private')['status'], 403)
        self.assertEqual(self.probe('/login')['status'], 200)
        self.assertEqual(self.probe('/private')['status'], 200)
        self.assertEqual(self.probe('/redirect')['status'], 302)
        self.assertNotIn('/landing', self.server.paths)

    def test_hostile_response_stays_bounded_and_returns_valid_receipt(self):
        result = self.probe('/large')
        self.assertEqual(result['status'], 200)
        self.assertTrue(result['truncated'])
        self.assertLessEqual(len(result['headers']), 16)

    def test_two_accounts_and_anonymous_requests_never_share_stored_cookies(self):
        self.probe('/login/alice', session='tenant-a')
        self.probe('/login/bob', session='tenant-b')
        for session, account in [('tenant-a', 'alice'), ('tenant-b', 'bob')]:
            response = self.probe('/whoami', session=session)
            self.assertEqual(response['session'], session)
            self.assertEqual(response['body'], account)
            self.assertEqual(self.probe('/accounts/' + account, session=session)['status'], 200)
        self.assertEqual(self.probe('/accounts/alice', session='tenant-b')['status'], 403)
        self.assertEqual(self.probe('/accounts/bob', session='tenant-a')['status'], 403)
        self.probe('/login/alice', session='anonymous')
        self.assertEqual(self.probe('/whoami', session='anonymous')['body'], 'anonymous')
        self.assertEqual(self.probe('/whoami')['body'], 'anonymous')
        self.assertFalse((Path(self.folder.name) / 'cookies-anonymous').exists())

    def test_session_reset_preserves_other_accounts_and_can_establish_a_new_login(self):
        self.probe('/login/alice', session='tenant-a')
        self.probe('/login/bob', session='tenant-b')
        self.assertEqual(self.probe('/whoami', session='tenant-a', resetSession=True)['body'], 'anonymous')
        self.assertEqual(self.probe('/whoami', session='tenant-a')['body'], 'anonymous')
        self.assertEqual(self.probe('/whoami', session='tenant-b')['body'], 'bob')
        self.probe('/login/alice', session='tenant-b', resetSession=True)
        self.assertEqual(self.probe('/whoami', session='tenant-b')['body'], 'alice')
        if os.name == 'posix':
            self.assertEqual((Path(self.folder.name) / 'cookies-tenant-b').stat().st_mode & 0o777, 0o600)


class StartupTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'linux' and hasattr(os, 'geteuid') and os.geteuid() == 0, 'uses Linux su with the existing nobody account')
    def test_service_starts_unprivileged_passes_health_and_reuses_its_process(self):
        source = (Path(__file__).resolve().parents[1] / 'src-tauri/src/swarm/target.rs').read_text()
        script = re.search(r'const SUPERVISOR\s*:\s*&str\s*=\s*r#"(.*?)"#;', source, re.S).group(1)
        with tempfile.TemporaryDirectory(prefix='yougori-startup-test-') as directory:
            root = Path(directory)
            root.chmod(0o755)
            (root / 'build').mkdir(mode=0o755)
            (root / '.yougori').mkdir(mode=0o755)
            (root / 'build/index.html').write_text('startup fixture')
            with socket.socket() as port_socket:
                port_socket.bind(('127.0.0.1', 0))
                port = port_socket.getsockname()[1]
            (root / '.yougori/target-recipe.json').write_text(json.dumps({'port': port, 'healthPath': '/', 'startCommand': f'python3 -m http.server {port} --bind 127.0.0.1'}))
            script = script.replace('/srv/yougori-swarm', directory).replace('yougori-test', 'nobody')
            state = root / '.yougori/target.json'
            try:
                first = subprocess.run([sys.executable, '-c', script], capture_output=True, timeout=80, check=True)
                self.assertIn(b'Target healthy', first.stdout)
                process = json.loads(state.read_text())
                subprocess.run([sys.executable, '-c', script], capture_output=True, timeout=80, check=True)
                self.assertEqual(process, json.loads(state.read_text()))
            finally:
                if state.exists():
                    pid = json.loads(state.read_text())['pid']
                    try:
                        os.killpg(pid, signal.SIGTERM)
                    except ProcessLookupError:
                        pass


if __name__ == '__main__':
    unittest.main()
