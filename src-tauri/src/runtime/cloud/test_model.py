"""Linux process/API integration tests; no provider account, GPU or model download."""
import importlib.util
import base64
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from unittest.mock import patch


def module():
    spec = importlib.util.spec_from_file_location('cloud_models', Path(__file__).with_name('model.py'))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


SERVER = '''import json, os
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get('Authorization') != 'Bearer ' + os.environ['YOUGORI_MODEL_TOKEN']:
            self.send_response(401); self.end_headers(); return
        self.send_response(200); self.end_headers()
        self.wfile.write(json.dumps({'model':os.environ['YOUGORI_MODEL'], 'status':'ready'}).encode())
HTTPServer((os.environ['YOUGORI_MODEL_BIND'], 8000), Handler).serve_forever()
'''


class ModelTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.env = patch.dict(os.environ, HOME=self.home.name)
        self.env.start()
        self.runner = module()
        self.body = dict(model='HuggingFaceTB/SmolLM2-135M', token='a' * 64, source=SERVER)
        # Avoid pip/venv setup downloads in these process tests.
        python = self.runner.root_dir() / 'venv' / 'bin' / 'python'
        python.parent.mkdir(parents=True)
        python.symlink_to(sys.executable)

    def tearDown(self):
        self.runner.request('stop', self.body)
        self.env.stop()
        self.home.cleanup()

    def ready(self):
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                req = urllib.request.Request('http://127.0.0.1:8000/v1/models', headers={'Authorization': 'Bearer ' + self.body['token']})
                with urllib.request.urlopen(req, timeout=1) as response:
                    return json.load(response)
            except (OSError, urllib.error.URLError):
                time.sleep(.1)
        self.fail(self.runner.request('logs', {}))

    def test_reuse_reconnect_authenticated_api_stop_and_resume(self):
        self.assertFalse(self.runner.request('run', self.body)['reused'])
        self.assertEqual(self.ready()['model'], self.body['model'])

        self.assertEqual(self.runner.request('status', self.body)['status'], 'ready')
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen('http://127.0.0.1:8000/v1/models')
        self.assertEqual(error.exception.code, 401)
        pid = self.runner.running(self.runner.root_dir())['pid']
        original = self.runner
        self.runner = module()  # A new connector retains the detached process and key.
        self.assertTrue(self.runner.request('run', self.body)['reused'])
        self.assertEqual(self.runner.running(self.runner.root_dir())['pid'], pid)
        self.assertEqual(stat.S_IMODE((self.runner.root_dir() / 'config.json').stat().st_mode), 0o600)
        self.assertTrue(self.runner.request('stop', self.body)['stopped'])
        for child in original.children.values():
            child.wait(timeout=5)
        self.assertFalse(self.runner.request('status', {})['running'])
        self.assertFalse(self.runner.request('run', self.body)['reused'])
        self.assertEqual(self.ready()['status'], 'ready')


    def test_huggingface_token_is_protected_and_injected_without_returning_it(self):
        self.body['hfToken'] = 'hf_private_read_token'
        self.body['source'] = SERVER.replace("'status':'ready'", "'status':'ready', 'hfConfigured':os.environ.get('HF_TOKEN') == 'hf_private_read_token'")
        self.assertEqual(self.runner.request('run', self.body), {'reused': False})
        self.assertTrue(self.ready()['hfConfigured'])
        config = self.runner.root_dir() / 'config.json'
        self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
        self.assertNotIn('hf_private_read_token', json.dumps(self.runner.request('status', self.body)))

    def test_conflicting_model_and_key_cannot_replace_or_stop_active_model(self):
        self.runner.request('run', self.body)
        self.ready()
        with self.assertRaisesRegex(ValueError, 'already runs'):
            self.runner.request('run', dict(self.body, model='Other/Model'))
        with self.assertRaisesRegex(ValueError, 'another Yougori'):
            self.runner.request('run', dict(self.body, token='b' * 64))
        with self.assertRaisesRegex(ValueError, 'another Yougori'):
            self.runner.request('stop', dict(token='b' * 64))
        self.assertTrue(self.runner.request('status', {})['running'])

    def test_port_conflicts_fail_without_spawning(self):
        with socket.socket() as occupied:
            occupied.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            occupied.bind(('127.0.0.1', 8000))
            occupied.listen()
            with self.assertRaisesRegex(ValueError, 'Port 8000'):
                self.runner.request('run', self.body)
        self.assertFalse(self.runner.request('status', {})['running'])

    def test_reused_pid_is_not_signalled(self):
        root = self.runner.root_dir()
        (root / 'process.json').write_text(json.dumps(dict(pid=os.getpid(), start='wrong', model='a/b')))
        self.runner.request('stop', self.body)
        self.assertFalse(self.runner.request('status', {})['running'])

    def test_helper_bootstraps_inside_the_actual_ssh_connector(self):
        helper = base64.b64encode(Path(__file__).with_name('model.py').read_bytes()).decode()
        source = ("import types, base64\nyougori_models = types.ModuleType('yougori_models')\n"
                  "exec(base64.b64decode('" + helper + "'), yougori_models.__dict__)\n"
                  + Path(__file__).with_name('agent.py').read_text()).encode()
        bootstrap = 'import sys;code=sys.stdin.buffer.read(int(sys.stdin.buffer.readline()));exec(compile(code,"yougori-agent","exec"))'
        with subprocess.Popen([sys.executable, '-u', '-c', bootstrap], stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE) as connector:
            connector.stdin.write(str(len(source)).encode() + b'\n' + source)
            connector.stdin.write(json.dumps(dict(requestId='model-status', path='model/status', body={})).encode() + b'\n')
            connector.stdin.flush()
            response = json.loads(connector.stdout.readline())
            self.assertEqual(response['requestId'], 'model-status')
            self.assertFalse(response['result']['running'])
            connector.stdin.close()
            connector.wait(timeout=5)
            self.assertEqual(connector.returncode, 0, connector.stderr.read().decode())


if __name__ == '__main__':
    unittest.main()
