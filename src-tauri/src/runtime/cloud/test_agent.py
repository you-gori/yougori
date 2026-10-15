"""Linux integration tests for the actual ephemeral connector (no cloud account)."""
import base64, http.client, json, os, pathlib, queue, shlex, socket, struct, subprocess, sys, tempfile, threading, time, unittest

class ConnectorTests(unittest.TestCase):
    def setUp(self):
        source = pathlib.Path(__file__).with_name('agent.py').read_bytes()
        bootstrap = 'import sys;code=sys.stdin.buffer.read(int(sys.stdin.buffer.readline()));exec(compile(code,"yougori-agent","exec"))'
        self.process = subprocess.Popen([sys.executable, '-u', '-c', bootstrap], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.process.stdin.write(str(len(source)).encode() + b'\n' + source)
        self.process.stdin.flush()
        self.messages = queue.Queue()
        self.pending = []
        def read():
            for line in self.process.stdout:
                self.messages.put(json.loads(line))
        threading.Thread(target=read, daemon=True).start()
        self.health = self.rpc('health', {})
    def tearDown(self):
        if not self.process.stdin.closed: self.process.stdin.close()
        self.process.wait(timeout=5)
        self.assertEqual(self.process.returncode, 0, self.process.stderr.read().decode())
        self.process.stdout.close(); self.process.stderr.close()
    def send(self, value):
        self.process.stdin.write((json.dumps(value) + '\n').encode()); self.process.stdin.flush()
    def receive(self, predicate):
        for i, value in enumerate(self.pending):
            if predicate(value): return self.pending.pop(i)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            value = self.messages.get(timeout=max(.1, deadline - time.monotonic()))
            if predicate(value): return value
            self.pending.append(value)
        self.fail('Missing connector response')
    def drain(self, predicate, quiet=.5):
        self.pending = [v for v in self.pending if not predicate(v)]
        while True:
            try: value = self.messages.get(timeout=quiet)
            except queue.Empty: return
            if not predicate(value): self.pending.append(value)
    def rpc(self, path, body, error=False):
        ident = str(time.monotonic_ns())
        self.send(dict(requestId=ident, path=path, body=body))
        value = self.receive(lambda v: v.get('requestId') == ident)
        if error: return value.get('error')
        self.assertNotIn('error', value)
        return value['result']
    def test_remote_file_access_is_scoped_without_shell_permission(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as outside:
            pathlib.Path(folder, 'file').write_bytes(b'hello')
            pathlib.Path(outside, 'secret').write_bytes(b'private')
            os.symlink(outside, os.path.join(folder, 'escape'))
            os.link(os.path.join(outside, 'secret'), os.path.join(folder, 'hard'))
            def call(operation, path, **kwargs):
                return self.rpc('/v1/remote/files', dict(root=folder, operation=operation, path=path, readOnly=True, **kwargs), error=True)
            result = self.rpc('/v1/remote/files', dict(root=folder, operation='read', path='file', length=5, readOnly=True))
            self.assertEqual(result['data'], 'aGVsbG8=')
            for path in ('../secret', '/etc/passwd', 'escape/secret', 'hard'):
                self.assertTrue(call('read', path))
            self.assertTrue(call('write', 'file', data='eA=='))
            self.rpc('/v1/remote/files', dict(root=folder, operation='create', path='new', readOnly=False))
            self.rpc('/v1/remote/files', dict(root=folder, operation='write', path='new', readOnly=False, data='aGVsbG8='))
            self.assertEqual(pathlib.Path(folder, 'new').read_bytes(), b'hello')
            self.rpc('/v1/remote/files', dict(root=folder, operation='replace', path='new', readOnly=False, expectedData='aGVsbG8=', data='bmV3'))
            self.assertEqual(pathlib.Path(folder, 'new').read_bytes(), b'new')
            self.assertTrue(self.rpc('/v1/remote/files', dict(root=folder, operation='replace', path='new', readOnly=False, expectedData='aGVsbG8=', data='bmV3'), error=True))


    def test_health_and_exec_are_remote(self):
        self.assertEqual(self.health['platform'], 'linux')
        self.assertEqual(self.rpc('/v1/services/list', {}), [])
        result = self.rpc('exec', {'command': "printf 'cloud ✓'; exit 7"})
        self.assertEqual(result, dict(exitCode=7, stdout='cloud ✓', stderr=''))
    def test_terminal_paste_resize_interrupt_and_close(self):
        ident = 'term-integration'
        self.rpc('/v1/terminal/create', dict(sessionId=ident))
        self.rpc('/v1/terminal/resize', dict(sessionId=ident, rows=42, cols=123))
        def write(text): self.rpc('/v1/terminal/write', dict(sessionId=ident, data=base64.b64encode(text.encode()).decode()))
        write("printf 'REMOTE_%s\\n' OK; stty size; printf 'HOME_CWD_%s\\n' \"$PWD\"\n")
        text = ''
        offset = 0
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and '42 123' not in text:
            data = self.rpc('/v1/terminal/read', dict(sessionId=ident, offset=offset))
            offset = data['offset']; text += base64.b64decode(data['data']).decode()
            time.sleep(.05)
        self.assertIn('REMOTE_OK', text); self.assertIn('42 123', text)
        self.assertIn('HOME_CWD_' + os.path.expanduser('~'), text)
        write('sleep 100\n'); time.sleep(.2); write('\x03'); write("printf 'INTERRUPT_%s\\n' OK\n")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and 'INTERRUPT_OK' not in text:
            data = self.rpc('/v1/terminal/read', dict(sessionId=ident, offset=offset))
            offset = data['offset']; text += base64.b64decode(data['data']).decode(); time.sleep(.05)
        self.assertIn('INTERRUPT_OK', text)
        self.rpc('/v1/terminal/close', dict(sessionId=ident))
        self.assertIn('closed', self.rpc('/v1/terminal/read', dict(sessionId=ident), error=True))
    def test_remote_service_binary_duplex(self):
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1)
        self.addCleanup(listener.close)
        self.rpc('stream/open', dict(streamId='test-service', port=listener.getsockname()[1]))
        peer, _ = listener.accept(); self.addCleanup(peer.close)
        payload = bytes(range(256)) * 128
        self.send(dict(event='data', streamId='test-service', data=base64.b64encode(payload).decode()))
        received = b''
        while len(received) < len(payload): received += peer.recv(32768)
        self.assertEqual(received, payload)
        peer.sendall(b'reply\x00\xff')
        event = self.receive(lambda v: v.get('event') == 'data' and v.get('streamId') == 'test-service')
        self.assertEqual(base64.b64decode(event['data']), b'reply\x00\xff')
        self.send(dict(event='closed', streamId='test-service'))
        peer.settimeout(2); self.assertEqual(peer.recv(1), b'')
    def test_duplicate_stream_cannot_replace_active_connection_or_leak_slots(self):
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1)
        self.addCleanup(listener.close)
        body = dict(streamId='duplicate-service', port=listener.getsockname()[1])
        self.rpc('stream/open', body)
        peer, _ = listener.accept(); self.addCleanup(peer.close); peer.settimeout(2)
        for _ in range(35):
            self.assertIn('Duplicate', self.rpc('stream/open', body, error=True))
            rejected, _ = listener.accept()
            with rejected:
                rejected.settimeout(2)
                self.assertEqual(rejected.recv(1), b'')
        self.send(dict(event='data', streamId='duplicate-service', data=base64.b64encode(b'original').decode()))
        self.assertEqual(peer.recv(8), b'original')
        self.send(dict(event='closed', streamId='duplicate-service'))
        self.rpc('stream/open', dict(body, streamId='new-service'))
        fresh, _ = listener.accept(); fresh.close()
        self.send(dict(event='closed', streamId='new-service'))
    def test_full_terminal_input_is_bounded_and_does_not_block_other_terminals(self):
        blocked, other = 'term-blocked', 'term-other'
        for ident in (blocked, other): self.rpc('/v1/terminal/create', dict(sessionId=ident))
        command = "stty -echo -icanon; printf 'INPUT_%s\\n' READY; sleep 30\n"
        self.rpc('/v1/terminal/write', dict(sessionId=blocked, data=base64.b64encode(command.encode()).decode()))
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            value = self.rpc('/v1/terminal/read', dict(sessionId=blocked))
            if b'INPUT_READY' in base64.b64decode(value['data']): break
            time.sleep(.02)
        else: self.fail('Blocked terminal setup did not complete')
        # More input than the raw-mode PTY can buffer while sleep reads none.
        self.send(dict(requestId='blocked-write', path='/v1/terminal/write',
                       body=dict(sessionId=blocked, data=base64.b64encode(b'x' * 32768).decode())))
        time.sleep(.1)  # Let the first write reach PTY backpressure.
        started = time.monotonic()
        self.rpc('/v1/terminal/resize', dict(sessionId=other, cols=100, rows=30))
        self.assertLess(time.monotonic() - started, 1.5, 'Other terminals stalled behind a full PTY')
        result = self.receive(lambda v: v.get('requestId') == 'blocked-write')
        self.assertIn('input is full', result.get('error', ''))
        for ident in (blocked, other): self.rpc('/v1/terminal/close', dict(sessionId=ident))
    def test_followed_terminal_pushes_output_in_order_without_reads(self):
        ident = 'term-follow'
        self.rpc('/v1/terminal/create', dict(sessionId=ident))
        def write(text): self.rpc('/v1/terminal/write', dict(sessionId=ident, data=base64.b64encode(text.encode()).decode()))
        write("printf 'BEFORE_%s\\n' FOLLOW\n")
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and 'BEFORE_FOLLOW' not in base64.b64decode(self.rpc('/v1/terminal/read', dict(sessionId=ident, offset=0))['data']).decode(): time.sleep(.05)
        # Following replays what was buffered, then pushes new output as events with contiguous offsets.
        self.assertEqual(self.rpc('/v1/terminal/follow', dict(sessionId=ident, offset=0))['ok'], True)
        write("printf 'AFTER_%s\\n' FOLLOW\n")
        text, offset = '', 0
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and 'AFTER_FOLLOW' not in text:
            event = self.receive(lambda v: v.get('event') == 'terminal' and v.get('sessionId') == ident)
            data = base64.b64decode(event['data'])
            self.assertEqual(event['offset'] - len(data), offset, 'Pushed output must be contiguous')
            offset = event['offset']; text += data.decode()
        self.assertIn('BEFORE_FOLLOW', text); self.assertIn('AFTER_FOLLOW', text)
        self.assertGreaterEqual(self.rpc('/v1/terminal/read', dict(sessionId=ident, offset=0))['offset'], offset, 'Reads still work while following')
        # Unfollowing stops the pushes; closing a followed terminal reports the end.
        self.rpc('/v1/terminal/unfollow', dict(sessionId=ident))
        write("printf 'QUIET_%s\\n' NOW\n"); time.sleep(.3)
        # Events pushed before the unfollow took effect are not part of the replay.
        self.drain(lambda v: v.get('event') == 'terminal' and v.get('sessionId') == ident)
        self.rpc('/v1/terminal/follow', dict(sessionId=ident, offset=0))
        replay, offset, deadline = '', 0, time.monotonic() + 5
        while time.monotonic() < deadline and 'QUIET_NOW' not in replay:
            event = self.receive(lambda v: v.get('event') == 'terminal' and v.get('sessionId') == ident)
            data = base64.b64decode(event['data'])
            self.assertEqual(event['offset'] - len(data), offset, 'The replay starts where the follow asked')
            offset = event['offset']; replay += data.decode()
        self.assertIn('QUIET_NOW', replay, 'Output while unfollowed is replayed by the next follow')
        write('exit\n')
        event = self.receive(lambda v: v.get('event') == 'terminal' and v.get('sessionId') == ident and v.get('done'))
        self.assertTrue(event['done'])
        self.rpc('/v1/terminal/close', dict(sessionId=ident))
    def test_unknown_terminal_action_is_rejected(self):
        self.assertIn('Unsupported', self.rpc('/v1/terminal/not-real', dict(sessionId='term-test'), error=True))
    def test_socks_rejects_lan_without_asking_host(self):
        sock = socket.create_connection(('127.0.0.1', self.health['socksPort'])); self.addCleanup(sock.close)
        sock.sendall(b'\x05\x01\x00'); self.assertEqual(sock.recv(2), b'\x05\x00')
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('192.168.1.1') + struct.pack('!H', 80))
        self.assertEqual(sock.recv(10)[1], 2)
    def test_remote_service_half_close_keeps_response_channel_open(self):
        listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(1)
        self.addCleanup(listener.close)
        self.rpc('stream/open', dict(streamId='half-close', port=listener.getsockname()[1]))
        peer, _ = listener.accept(); self.addCleanup(peer.close); peer.settimeout(3)
        self.send(dict(event='data', streamId='half-close', data=base64.b64encode(b'request').decode()))
        self.send(dict(event='eof', streamId='half-close'))
        received = b''
        while True:
            data = peer.recv(32768)
            if not data: break
            received += data
        self.assertEqual(received, b'request')
        payload = bytes(range(256)) * 1024
        peer.sendall(payload); peer.shutdown(socket.SHUT_WR)
        received = b''
        while True:
            event = self.receive(lambda v: v.get('streamId') == 'half-close')
            if event['event'] == 'eof': break
            self.assertEqual(event['event'], 'data')
            received += base64.b64decode(event['data'])
        self.assertEqual(received, payload)
        self.send(dict(event='closed', streamId='half-close'))
    def test_socks_connected_peer_requires_host_permission(self):
        sock = socket.create_connection(('127.0.0.1', self.health['socksPort'])); self.addCleanup(sock.close)
        sock.sendall(b'\x05\x01\x00'); self.assertEqual(sock.recv(2), b'\x05\x00')
        sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton('10.200.1.2') + struct.pack('!H', 5432))
        event = self.receive(lambda v: v.get('event') == 'connect')
        self.assertEqual(event['address'], '10.200.1.2'); self.assertEqual(event['port'], 5432)
        self.send(dict(requestId=event['requestId'], error='Connection not permitted'))
        self.assertEqual(sock.recv(10)[1], 2)
    def test_files_browser_rejects_cross_origin(self):
        conn = http.client.HTTPConnection('127.0.0.1', self.health['filesPort'], timeout=3)
        self.addCleanup(conn.close)
        conn.request('GET', '/', headers={'Origin': 'https://evil.example'})
        self.assertEqual(conn.getresponse().status, 403)
    def test_files_request_relay_preserves_scope(self):
        result = queue.Queue()
        def request():
            conn = http.client.HTTPConnection('127.0.0.1', self.health['filesPort'], timeout=5)
            conn.request('POST', '/api', body=json.dumps(dict(connectionId='conn-selected', operation='list', path='')),
                         headers={'Content-Type': 'application/json'})
            response = conn.getresponse(); result.put((response.status, response.read())); conn.close()
        thread = threading.Thread(target=request); thread.start()
        event = self.receive(lambda v: v.get('event') == 'files')
        request_data = base64.b64decode(event['data'])
        self.assertIn(b'Host: 10.192.0.1:7444', request_data)
        self.assertIn(b'conn-selected', request_data)
        response = b'HTTP/1.1 403 Forbidden\r\nContent-Length: 6\r\nConnection: close\r\n\r\ndenied'
        self.send(dict(requestId=event['requestId'], result=base64.b64encode(response).decode()))
        thread.join(5); self.assertEqual(result.get(timeout=1), (403, b'denied'))
    def test_command_output_is_bounded(self):
        self.assertIn('256 KB', self.rpc('exec', {'command': 'yes output'}, error=True))
    def test_disconnect_terminates_its_inflight_exec(self):
        with tempfile.TemporaryDirectory() as directory:
            pid_file = pathlib.Path(directory) / 'owned-exec.pid'
            command = 'echo $$ > ' + shlex.quote(str(pid_file)) + '; sleep 30'
            self.send(dict(requestId='inflight-exec', path='exec', body=dict(command=command)))
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and not pid_file.exists(): time.sleep(.02)
            self.assertTrue(pid_file.exists(), 'Test exec did not start')
            pid = int(pid_file.read_text().strip())
            self.process.stdin.close()
            self.process.wait(timeout=5)
            self.assertFalse(pathlib.Path('/proc', str(pid)).exists(), 'Connector left its own exec process running')

if __name__ == '__main__': unittest.main()
