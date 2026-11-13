"""Publisher artifact import preserves each harness's VM filesystem budget."""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
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


class LeftoverVms(unittest.TestCase):
    """A run leaves no VM in the app's list, only a copy with the harness's changes to review."""

    def engine(self, changes=(), stopped=(), missing=False):
        calls = []

        def call(action, **params):
            calls.append((action, params.get('op'), params.get('sandbox')))
            if action == 'status':
                return {'sandboxes': [{'sandbox': s, 'state': 'stopped'} for s in stopped]}
            if missing and params.get('op') in ('show', 'discard'):
                raise ValueError('Sandbox ' + params['sandbox'] + ' has no workspace.')
            if params.get('op') == 'show':
                return {'changes': [{'name': name, 'change': change} for name, change in changes]}
            return {'discarded': True}
        return calls, patch.object(vm_host, 'call', call)

    def test_a_copy_goes_unless_the_harness_changed_the_project(self):
        vm = 'exe-' + 'a' * 32
        calls, engine = self.engine()
        with engine:
            self.assertFalse(vm_host.tidy(vm, None))  # Yougori's own empty copy: no project folder
        self.assertEqual(calls, [('workspace', 'discard', vm)])
        calls, engine = self.engine(changes=[('yougori.py', 'added'), ('.agents/skills/yougori-setup/SKILL.md', 'added')])
        with engine:
            self.assertFalse(vm_host.tidy(vm, 'C:/work/app'))  # only the setup package was added
        self.assertEqual(calls[-1], ('workspace', 'discard', vm))
        for change in (('src/app.py', 'modified'), ('yougori.py', 'modified'), ('notes.md', 'added'), ('old.txt', 'deleted')):
            calls, engine = self.engine(changes=[change])
            with engine:
                self.assertTrue(vm_host.tidy(vm, 'C:/work/app'), change)
            self.assertNotIn('discard', [op for _, op, _ in calls])
        calls, engine = self.engine(missing=True)
        with engine:
            self.assertFalse(vm_host.tidy(vm, None))  # already gone

    def test_earlier_runs_that_ended_without_tidying_are_tidied_once_stopped(self):
        stopped, running = 'exe-' + 'b' * 32, 'exe-' + 'c' * 32
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            vm_host.remembered(root, lambda known: [{'sandbox': stopped, 'workspace': None}, {'sandbox': running, 'workspace': None}])
            calls, engine = self.engine(stopped=[stopped])
            with engine:
                vm_host.tidy_earlier(root)
            self.assertIn(('workspace', 'discard', stopped), calls)
            self.assertNotIn(('workspace', 'discard', running), calls)
            self.assertEqual([item['sandbox'] for item in vm_host.remembered(root)], [running])  # another terminal's VM


class Console:
    """A Windows console's input: each part is there at once, the next arrives after a pause."""

    def __init__(self, *parts):
        # getwch gives UTF-16 code units: a character beyond U+FFFF is two of them.
        units = (part.encode('utf-16-le', 'surrogatepass') for part in parts)
        self.parts = [[chr(int.from_bytes(raw[i:i + 2], 'little')) for i in range(0, len(raw), 2)] for raw in units]

    def kbhit(self):
        if self.parts and not self.parts[0]:
            self.parts.pop(0)
            return False  # the next part is still on its way
        return bool(self.parts)

    def getwch(self):
        return self.parts[0].pop(0)


class TerminalInput(unittest.TestCase):
    """A terminal's answers reach the harness whole, so it never shows them as typed text."""

    def test_an_answer_arriving_in_pieces_is_sent_whole(self):
        done = threading.Event()
        answer = '\x1b]11;rgb:0c0c/0c0c/0c0c\x1b\\\x1b[?1016;2$y\x1b[?2027;2$y\x1b[1;1R\x1b[4;1040;1790t'
        self.assertEqual(vm_host.console_input(Console(answer[:30], answer[30:]), done), answer)
        # Typing is not held back: without an escape sequence the pause ends what is sent.
        console = Console('hi', ' there')
        self.assertEqual(vm_host.console_input(console, done), 'hi')
        self.assertEqual(vm_host.console_input(console, done), ' there')

    def test_keys_wide_characters_and_the_detach_key(self):
        done = threading.Event()
        self.assertEqual(vm_host.console_input(Console('\xe0H\xe0P\x00S'), done), '\x1b[A\x1b[B\x1b[3~')
        self.assertEqual(vm_host.console_input(Console('ok 😀'), done), 'ok \U0001F600')  # comes as two halves
        self.assertIsNone(vm_host.console_input(Console('ab\x1d'), done))
        # A paste larger than one request is sent in requests the VM accepts.
        paste = Console('€' * 9000)
        sizes = [len(vm_host.console_input(paste, done).encode()) for _ in range(3)]
        self.assertEqual(sum(sizes), 27000)
        self.assertLessEqual(max(sizes), 16384)

    @unittest.skipUnless(os.name == 'nt', 'the Windows console')
    def test_one_request_carries_an_answer(self):
        posts, done = [], threading.Event()

        class Control:
            def post(self, path, body):
                posts.append(base64.b64decode(body['data']).decode())
                done.set()
                return {}
        answer = '\x1b[?1016;2$y\x1b[?2004;2$y'
        with patch.dict(sys.modules, {'msvcrt': Console(answer)}):
            vm_host.terminal_input(Control(), done)
        self.assertEqual(posts, [answer])


if __name__ == '__main__': unittest.main()
