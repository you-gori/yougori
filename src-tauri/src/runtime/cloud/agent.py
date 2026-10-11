"""Ephemeral Linux connector, executed over pinned SSH.

stdout is exclusively bounded JSON RPC. Listeners bind loopback only. Ending SSH
removes the connector and its terminals; it never powers off the server. An
explicit selected-folder connection may launch a temporary FUSE helper through
passwordless sudo; no system packages or permanent service are installed.
"""
import base64, concurrent.futures, fcntl, hashlib, http.server, ipaddress, json, os, platform, pty
import re, select, shutil, signal, socket, stat, struct, subprocess, sys, tempfile, termios, threading, time, uuid

MAX = 1024 * 1024
out_lock = threading.Lock()
lock = threading.RLock()
share_lock = threading.RLock()
terminals, streams, waiters = {}, {}, {}
commands = {}
share_upload = None
share_helper = None
share_directory = None
mounted_shares = {}
closing = threading.Event()
pool = concurrent.futures.ThreadPoolExecutor(max_workers=12)
slots = threading.BoundedSemaphore(32)

def emit(value):
    with out_lock:
        sys.stdout.write(json.dumps(value, separators=(',', ':')) + '\n')
        sys.stdout.flush()

def decode(value, limit=MAX):
    if not isinstance(value, str) or len(value) > limit * 2:
        raise ValueError('Payload too large')
    data = base64.b64decode(value, validate=True)
    if len(data) > limit: raise ValueError('Payload too large')
    return data

def encode(data): return base64.b64encode(data).decode('ascii')

def private_directory(path):
    if os.path.lexists(path):
        info = os.lstat(path)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError('Yougori shared path must be a directory owned by this account')
    else: os.mkdir(path, 0o700)
    os.chmod(path, 0o700)

def shared_root():
    parent = os.path.join(os.path.expanduser('~'), 'Yougori')
    private_directory(parent)
    root = os.path.join(parent, 'shared')
    private_directory(root)
    return root

def share_helper_request(body):
    global share_upload, share_helper, share_directory
    action = body.get('action')
    if action == 'begin':
        if share_upload is not None:
            share_upload['file'].close()
            try: os.unlink(share_upload['upload'])
            except FileNotFoundError: pass
            share_upload = None
        if share_directory is None:
            shared_root()
            runtime = os.path.join(os.path.expanduser('~'), 'Yougori', '.runtime')
            private_directory(runtime)
            share_directory = tempfile.mkdtemp(prefix='share-helper-', dir=runtime)
        target = os.path.join(share_directory, 'yougori-cloud-share')
        upload = os.path.join(share_directory, 'upload')
        if os.path.exists(upload): os.unlink(upload)
        share_upload = dict(file=open(upload, 'xb'), bytes=0, checksum=body.get('checksum'), target=target, upload=upload)
        return dict(ok=True)
    if action == 'chunk':
        if share_upload is None: raise ValueError('No share helper upload is active')
        data = decode(body.get('data', ''), 65536)
        if not data or share_upload['bytes'] + len(data) > 8 * 1024 * 1024: raise ValueError('Invalid share helper size')
        share_upload['file'].write(data)
        share_upload['bytes'] += len(data)
        return dict(bytes=share_upload['bytes'])
    if action == 'finish':
        if share_upload is None: raise ValueError('No share helper upload is active')
        upload = share_upload
        share_upload = None
        upload['file'].close()
        data = open(upload['upload'], 'rb').read(8 * 1024 * 1024 + 1)
        if len(data) != upload['bytes'] or len(data) > 8 * 1024 * 1024 or hashlib.sha256(data).hexdigest() != upload['checksum']:
            os.unlink(upload['upload'])
            raise ValueError('Share helper failed integrity verification')
        os.chmod(upload['upload'], 0o700)
        os.replace(upload['upload'], upload['target'])
        share_helper = upload['target']
        return dict(ok=True)
    raise ValueError('Invalid share helper action')

def detach_share(key):
    item = mounted_shares.get(key)
    if item is None: return
    path, process = item
    try:
        if stale_yougori_mount(path):
            subprocess.run(['sudo', '-n', 'umount', '-l', '--', path], timeout=10, check=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        mounted_shares.pop(key, None)
    finally:
        if key not in mounted_shares:
            try: process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
            try: os.rmdir(path)
            except OSError: pass

def stale_yougori_mount(path):
    with open('/proc/self/mountinfo', encoding='utf-8') as info:
        for line in info:
            before, divider, after = line.partition(' - ')
            if not divider: continue
            fields = before.split()
            kind = after.split()
            if len(fields) > 4 and kind and kind[0] == 'fuse.yougori':
                mounted = fields[4].replace('\\040', ' ').replace('\\011', '\t').replace('\\134', '\\')
                if mounted == path: return True
    return False

def reclaim_stale_share(path):
    if stale_yougori_mount(path):
        subprocess.run(['sudo', '-n', 'umount', '-l', '--', path], timeout=10, check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if not os.path.lexists(path): return
    if not os.path.islink(path) and os.path.isdir(path) and os.stat(path).st_uid == os.getuid():
        try: os.rmdir(path)
        except OSError: pass

def attach_share(body):
    if share_helper is None: raise ValueError('Yougori cloud share helper is unavailable')
    connection = body.get('connectionId', '')
    index = body.get('index')
    label = body.get('label', '')
    if not isinstance(connection, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', connection): raise ValueError('Invalid connection')
    if not isinstance(index, int) or not 0 <= index < 8: raise ValueError('Invalid selected folder')
    if not isinstance(label, str) or len(label) > 80: raise ValueError('Invalid folder label')
    key = (connection, index)
    if key in mounted_shares:
        path, process = mounted_shares[key]
        if process.poll() is None and os.path.ismount(path): return dict(mountPath=path)
        detach_share(key)
    root = shared_root()
    name = re.sub(r'[^A-Za-z0-9._-]', '-', label).strip('.-') or 'Environment'
    name = name[:48]
    path = os.path.join(root, name)
    reclaim_stale_share(path)
    if os.path.lexists(path):
        path = os.path.join(root, name + '-' + connection[-8:] + '-' + str(index))
        reclaim_stale_share(path)
    if os.path.lexists(path): raise ValueError('Shared folder path is already in use')
    os.mkdir(path, 0o700)
    read_only = bool(body.get('readOnly'))
    process = None
    try:
        process = subprocess.Popen(['sudo', '-n', share_helper, path, str(files.server_port), connection,
                                    str(index), str(read_only).lower(), str(os.getuid()), str(os.getgid())],
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        ready, _, _ = select.select([process.stdout], [], [], 25)
        if not ready or process.stdout.readline().strip() != b'yougori-share-ready' or not os.path.ismount(path):
            detail = process.stderr.read(4096).decode('utf-8', 'replace') if process.poll() is not None else ''
            raise ValueError('Cloud folder mount failed. Check FUSE and passwordless sudo. ' + detail[:1000])
        mounted_shares[key] = (path, process)
        return dict(mountPath=path)
    except Exception:
        if process is not None:
            if os.path.ismount(path):
                subprocess.run(['sudo', '-n', 'umount', '-l', '--', path], timeout=10, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            process.kill()
            process.wait(timeout=3)
        try: os.rmdir(path)
        except OSError: pass
        raise

def host_request(kind, **data):
    ident = 'remote-' + uuid.uuid4().hex
    done = threading.Event()
    with lock: waiters[ident] = [done, None]
    try:
        emit(dict(event=kind, requestId=ident, **data))
        if not done.wait(20): raise TimeoutError('Yougori connection timed out')
        with lock: reply = waiters[ident][1]
        if reply.get('error'): raise ValueError(reply['error'])
        return reply.get('result')
    finally:
        with lock: waiters.pop(ident, None)

def pump(ident, sock):
    try:
        while True:
            try: data = sock.recv(32768)
            except socket.timeout: continue
            if not data:
                emit(dict(event='eof', streamId=ident))
                return
            emit(dict(event='data', streamId=ident, data=encode(data)))
    except OSError:
        stream_close(ident)
        emit(dict(event='closed', streamId=ident))

def stream_close(ident):
    with lock: sock = streams.pop(ident, None)
    if sock:
        try: sock.shutdown(socket.SHUT_RDWR)
        except OSError: pass
        sock.close()
        slots.release()

def stream_start(ident, sock):
    if not isinstance(ident, str) or not ident or len(ident) > 128:
        sock.close()
        raise ValueError('Invalid stream ID')
    if not slots.acquire(False):
        sock.close()
        raise ValueError('Too many connections')
    try:
        with lock:
            if ident in streams: raise ValueError('Duplicate stream ID')
            sock.settimeout(10)
            streams[ident] = sock
        threading.Thread(target=pump, args=(ident, sock), daemon=True).start()
    except Exception:
        with lock:
            if streams.get(ident) is sock: streams.pop(ident)
        sock.close()
        slots.release()
        raise

def peer_uid(sock):
    """Account owning the other end of a loopback connection, from /proc/net/tcp.

    The SOCKS and file listeners have no credentials (existing tools and the
    shipped share helper connect without them), so restrict them to this
    account and the root-run share helper instead of every user on the server.
    """
    try:
        client_ip, client_port = sock.getpeername()[:2]
        server_ip, server_port = sock.getsockname()[:2]
        def entry(ip, port): return '%08X:%04X' % (struct.unpack('=I', socket.inet_aton(ip))[0], port)
        local, remote = entry(client_ip, client_port), entry(server_ip, server_port)
        with open('/proc/net/tcp', encoding='ascii') as table:
            next(table)
            for line in table:
                fields = line.split()
                if len(fields) > 7 and fields[1] == local and fields[2] == remote:
                    return int(fields[7])
    except (OSError, ValueError, StopIteration, struct.error):
        pass
    return None

def trusted_peer(sock):
    return peer_uid(sock) in (0, os.getuid())

def exact(sock, size):
    data = b''
    while len(data) < size:
        block = sock.recv(size - len(data))
        if not block: raise OSError('Connection closed')
        data += block
    return data

def socks_client(sock):
    try:
        sock.settimeout(20)
        version, count = exact(sock, 2)
        methods = exact(sock, count)
        if version != 5 or 0 not in methods: raise ValueError('SOCKS5 required')
        sock.sendall(b'\x05\x00')
        version, command, reserved, address_type = exact(sock, 4)
        if version != 5 or command != 1 or reserved: raise ValueError('TCP CONNECT only')
        if address_type == 1: address = socket.inet_ntoa(exact(sock, 4))
        elif address_type == 3: address = exact(sock, exact(sock, 1)[0]).decode('ascii')
        else: raise ValueError('IPv4 only')
        port = struct.unpack('!H', exact(sock, 2))[0]
        if ipaddress.ip_address(address) not in ipaddress.ip_network('10.192.0.0/11'):
            raise ValueError('Only connected Yougori nodes are accessible')
        ident = 'remote-' + uuid.uuid4().hex
        host_request('connect', streamId=ident, address=address, port=port)
        sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        sock.settimeout(None)
        stream_start(ident, sock)
        emit(dict(event='ready', streamId=ident))
    except Exception:
        try: sock.sendall(b'\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00')
        except OSError: pass
        sock.close()

def accept_socks(listener):
    while True:
        sock, _ = listener.accept()
        if not trusted_peer(sock): sock.close(); continue
        if not slots.acquire(False): sock.close(); continue
        def serve(sock=sock):
            try: socks_client(sock)
            finally: slots.release()
        threading.Thread(target=serve, daemon=True).start()

class Files(http.server.BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def handle_request(self):
        try:
            if not trusted_peer(self.connection): raise ValueError('Connection refused for this account')
            expected = '127.0.0.1:' + str(self.server.server_port)
            if self.headers.get('Host') != expected: raise ValueError('Invalid host')
            if self.headers.get('Origin') not in (None, 'http://' + expected):
                raise ValueError('Cross-origin access blocked')
            if self.headers.get('Transfer-Encoding'): raise ValueError('Invalid framing')
            sizes = self.headers.get_all('Content-Length', [])
            if len(sizes) > 1: raise ValueError('Invalid framing')
            size = int(sizes[0]) if sizes else 0
            if size < 0 or size > MAX: raise ValueError('File request too large')
            body = self.rfile.read(size)
            request = (self.command + ' ' + self.path + ' HTTP/1.1\r\nHost: 10.192.0.1:7444\r\n'
                       'X-Yougori-Files: 1\r\nContent-Length: ' + str(len(body)) + '\r\n\r\n').encode() + body
            reply = decode(host_request('files', data=encode(request)), MAX + 32768)
            self.wfile.write(reply)
            self.close_connection = True
        except Exception as error:
            self.send_error(403, str(error))
    do_GET = handle_request
    do_POST = handle_request

def term_read(ident, term):
    while True:
        with term['io_lock']:
            if term['closed']: break
            fd = term['fd']
        try: ready, _, _ = select.select([fd], [], [], .25)
        except (OSError, ValueError): break
        if not ready: continue
        with term['io_lock']:
            if term['closed']: break
            try: data = os.read(term['fd'], 32768)
            except BlockingIOError: data = None
            except OSError: break
        if data is None: continue
        if not data: break
        with lock:
            if terminals.get(ident) is not term: break
            term['buffer'].extend(data)
            trim = max(0, len(term['buffer']) - 262144)
            if trim:
                del term['buffer'][:trim]
                term['start'] += trim
    term['process'].wait()

def term_write(term, data):
    # A full/stopped PTY must not hold the global connector lock and freeze
    # every other terminal, file request and network stream. Serialize writes
    # per terminal; use nonblocking I/O and report backpressure explicitly.
    if not term['write_lock'].acquire(False):
        raise ValueError('Another terminal write is in progress; wait before retrying')
    sent = 0
    deadline = time.monotonic() + 3
    try:
        while sent < len(data):
            with term['io_lock']:
                if term['closed']: raise ValueError('Terminal closed')
                try: sent += os.write(term['fd'], data[sent:])
                except BlockingIOError: pass
            if sent < len(data):
                if time.monotonic() >= deadline:
                    raise TimeoutError('Terminal input is full (' + str(sent) + ' of ' + str(len(data)) +
                                       ' bytes sent). Let the command read input before sending more.')
                time.sleep(.01)
    finally:
        term['write_lock'].release()

def term_close(term):
    with term['io_lock']:
        if term['closed']: return
        term['closed'] = True
        os.close(term['fd'])
    if term['process'].poll() is None:
        try: os.killpg(term['process'].pid, signal.SIGHUP)
        except ProcessLookupError: pass

def remote_files(body):
    # File-only sharing uses descriptor-relative operations, never a shell.
    import stat
    root_path = body.get('root', '')
    relative = body.get('path', '')
    def parts(value):
        if len(value) > 4096 or any(c in value for c in ('\\', ':', '\x00')):
            raise ValueError('Invalid shared path')
        result = [v for v in value.split('/') if v not in ('', '.')]
        if '..' in result: raise ValueError('Path leaves the shared folder')
        return result
    if not root_path.startswith('/') or relative.startswith('/'):
        raise ValueError('Invalid file root or relative path')
    operation = body.get('operation')
    writing = operation not in ('list', 'stat', 'read')
    names = parts(relative)
    if writing and (body.get('readOnly', True) or not names):
        raise ValueError('File operation not permitted')
    descriptors = []
    def directory(parent, name):
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
        descriptors.append(fd)
        return fd
    try:
        root = directory(None, '/')
        for part in parts(root_path): root = directory(root, part)
        device = os.fstat(root).st_dev
        parent = root
        for part in names[:-1]:
            parent = directory(parent, part)
            if os.fstat(parent).st_dev != device: raise ValueError('Mounted filesystems are not shared')
        name = names[-1] if names else '.'
        if operation == 'mkdir':
            os.mkdir(name, 0o755, dir_fd=parent)
            return dict(ok=True)
        if operation == 'remove':
            m = os.stat(name, dir_fd=parent, follow_symlinks=False)
            if stat.S_ISDIR(m.st_mode): os.rmdir(name, dir_fd=parent)
            elif stat.S_ISREG(m.st_mode): os.unlink(name, dir_fd=parent)
            else: raise ValueError('Only ordinary files are shared')
            return dict(ok=True)
        flags = os.O_WRONLY if operation in ("write", "truncate", "create") else os.O_RDONLY
        if operation == 'create': flags |= os.O_CREAT | os.O_EXCL
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o644, dir_fd=parent)
        descriptors.append(fd)
        m = os.fstat(fd)
        if m.st_dev != device or not (stat.S_ISREG(m.st_mode) or stat.S_ISDIR(m.st_mode)):
            raise ValueError('Only ordinary files in this folder are shared')
        if stat.S_ISREG(m.st_mode) and m.st_nlink > 1: raise ValueError('Hard links are not shared')
        if operation == 'stat': return dict(info=dict(name=name, directory=stat.S_ISDIR(m.st_mode), size=m.st_size))
        if operation == 'list':
            entries = []
            with os.scandir(fd) as items:
                for item in items:
                    if len(entries) >= 5000: raise ValueError('Folder exceeds 5000 entries')
                    if item.is_symlink(): continue
                    details = item.stat(follow_symlinks=False)
                    if stat.S_ISREG(details.st_mode) or stat.S_ISDIR(details.st_mode):
                        entries.append(dict(name=item.name, directory=stat.S_ISDIR(details.st_mode), size=details.st_size))
            return dict(entries=entries)
        if not stat.S_ISREG(m.st_mode): raise ValueError('Choose an ordinary file')
        offset = int(body.get('offset', 0)); length = int(body.get('length', 65536))
        if not 0 <= offset <= 2**40 or not 0 <= length <= 2**40: raise ValueError('Invalid file range')
        if operation == 'replace':
            expected = decode(body.get('expectedData', ''), 65536)
            data = decode(body.get('data', ''), 65536)
            if os.pread(fd, 65537, 0) != expected: raise ValueError('File changed; reopen it before saving')
            temp = '.yougori-save-' + uuid.uuid4().hex
            temporary = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, stat.S_IMODE(m.st_mode), dir_fd=parent)
            try:
                offset = 0
                while offset < len(data): offset += os.write(temporary, data[offset:])
                os.fsync(temporary)
                os.rename(temp, name, src_dir_fd=parent, dst_dir_fd=parent)
            finally:
                os.close(temporary)
                try: os.unlink(temp, dir_fd=parent)
                except FileNotFoundError: pass
            return dict(count=len(data))
        if operation == 'read': return dict(data=encode(os.pread(fd, min(length, 65536), offset)))
        if operation == 'write':
            data = decode(body.get('data', ''), 65536)
            return dict(count=os.pwrite(fd, data, offset))
        if operation == 'truncate': os.ftruncate(fd, length); return dict(ok=True)
        if operation == 'create': return dict(ok=True)
        raise ValueError('Unsupported file operation')
    finally:
        for fd in reversed(descriptors): os.close(fd)


def dispatch(path, body):
    if path.startswith('model/'):
        return yougori_models.request(path.split('/', 1)[1], body)
    if path == 'share/helper':
        with share_lock: return share_helper_request(body)
    if path == 'share/attach':
        with share_lock: return attach_share(body)
    if path == 'share/detach':
        connection = body.get('connectionId', '')
        index = body.get('index')
        if not isinstance(connection, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', connection) or not isinstance(index, int) or not 0 <= index < 8:
            raise ValueError('Invalid shared folder')
        with share_lock: detach_share((connection, index))
        return dict(ok=True)
    if path == "/v1/remote/files": return remote_files(body)
    if path == 'health':
        return dict(ready=True, platform=sys.platform, architecture=platform.machine(), socksPort=socks.getsockname()[1], filesPort=files.server_port)
    if path == 'stream/open':
        port = int(body['port'])
        if not 1 <= port <= 65535: raise ValueError('Invalid service port')
        stream_start(body['streamId'], socket.create_connection(('127.0.0.1', port), timeout=10))
        return dict(ok=True)
    if path == 'exec':
        command = body['command']
        if not command or len(command) > 32768: raise ValueError('Invalid command length')
        # Bounded output, even for an accidentally unbounded command.
        with lock:
            if closing.is_set(): raise ValueError('Cloud connector is closing')
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                       start_new_session=True)
            commands[process.pid] = process
        result = bytearray()
        deadline = time.monotonic() + 20
        try:
            while True:
                if time.monotonic() > deadline: raise TimeoutError('Command exceeded 20 seconds; use a terminal for long-running commands')
                ready, _, _ = select.select([process.stdout], [], [], .1)
                if ready:
                    data = os.read(process.stdout.fileno(), 32768)
                    if not data: break
                    result.extend(data)
                    if len(result) > 262144: raise ValueError('Command output exceeded 256 KB; use a terminal')
            return dict(exitCode=process.wait(timeout=1), stdout=result.decode('utf-8', 'replace'), stderr='')
        finally:
            try:
                if process.poll() is None:
                    try: os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError: pass
                    process.wait()
            finally:
                with lock: commands.pop(process.pid, None)
                process.stdout.close()
    if path == '/v1/services/list': return []
    if path.startswith('/v1/terminal/'):
        action = path.rsplit('/', 1)[1]
        ident = body['sessionId']
        if action not in ('create', 'read', 'write', 'resize', 'close'):
            raise ValueError('Unsupported terminal operation')
        if not ident.startswith('term-') or len(ident) > 80: raise ValueError('Invalid terminal')
        with lock:
            if closing.is_set(): raise ValueError('Cloud connector is closing')
            if action == 'create':
                if len(terminals) >= 16 or ident in terminals: raise ValueError('Terminal limit reached or duplicate terminal')
                master, slave = pty.openpty()
                home = os.path.expanduser('~')
                env = dict(os.environ, TERM='xterm-256color', YOUGORI_SOCKS_PROXY='socks5h://127.0.0.1:' + str(socks.getsockname()[1]),
                           YOUGORI_SHARED_FILES='http://127.0.0.1:' + str(files.server_port), YOUGORI_SHARED_ROOT=os.path.join(home, 'Yougori', 'shared'))
                # A fresh helper sets the controlling TTY, then execs the shell.
                # Avoid preexec_fn in this multithreaded process (fork deadlocks).
                shell = os.environ.get('SHELL', '/bin/sh')
                helper = 'import fcntl,os,sys,termios;fcntl.ioctl(0,termios.TIOCSCTTY,0);os.execv(sys.argv[1],[sys.argv[1],"-i"])'
                try:
                    process = subprocess.Popen([sys.executable, '-c', helper, shell], stdin=slave, stdout=slave, stderr=slave,
                                               env=env, start_new_session=True, cwd=home)
                    os.set_blocking(master, False)
                except Exception:
                    os.close(master)
                    raise
                finally:
                    os.close(slave)
                term = dict(fd=master, process=process, buffer=bytearray(), start=0, closed=False,
                            io_lock=threading.Lock(), write_lock=threading.Lock())
                terminals[ident] = term
                threading.Thread(target=term_read, args=(ident, term), daemon=True).start()
            term = terminals.get(ident)
            if term is None:
                if action == 'close': return dict(ok=True)
                raise ValueError('Terminal closed')
            if action == 'read':
                offset = max(term['start'], min(term['start'] + len(term['buffer']), int(body.get('offset', 0))))
                data = bytes(term['buffer'][offset - term['start']:offset - term['start'] + 32768])
                return dict(data=encode(data), offset=offset + len(data), done=term['process'].poll() is not None)
            if action == 'close':
                terminals.pop(ident)
        if action in ('create', 'resize'):
            rows = max(2, min(250, int(body.get('rows', 24))))
            cols = max(2, min(500, int(body.get('cols', 80))))
            with term['io_lock']:
                if term['closed']: raise ValueError('Terminal closed')
                fcntl.ioctl(term['fd'], termios.TIOCSWINSZ, struct.pack('HHHH', rows, cols, 0, 0))
        if action == 'write': term_write(term, decode(body.get('data', ''), 32768))
        if action == 'close': term_close(term)
        return dict(ok=True)
    raise ValueError('Unsupported cloud operation')

def request(message):
    try: emit(dict(requestId=message['requestId'], result=dispatch(message['path'], message.get('body', {}))))
    except Exception as error: emit(dict(requestId=message['requestId'], error=str(error)))
    finally: request_slots.release()

socks = socket.socket()
socks.bind(('127.0.0.1', 0)); socks.listen(16)
files = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Files)
files.daemon_threads = True
threading.Thread(target=accept_socks, args=(socks,), daemon=True).start()
threading.Thread(target=files.serve_forever, daemon=True).start()
request_slots = threading.BoundedSemaphore(24)
try:
    while True:
        line = sys.stdin.buffer.readline(MAX * 2 + 1)
        if not line: break
        if len(line) > MAX * 2: raise ValueError('Oversized frame')
        message = json.loads(line)
        if 'path' in message:
            if not request_slots.acquire(False):
                emit(dict(requestId=message['requestId'], error='Too many pending operations'))
            else: pool.submit(request, message)
        elif message.get('event') == 'data':
            with lock: sock = streams.get(message['streamId'])
            if sock:
                try: sock.sendall(decode(message['data'], 32768))
                except OSError: stream_close(message['streamId'])
        elif message.get('event') == 'eof':
            with lock: sock = streams.get(message['streamId'])
            if sock:
                try: sock.shutdown(socket.SHUT_WR)
                except OSError: stream_close(message['streamId'])
        elif message.get('event') == 'closed':
            stream_close(message['streamId'])
        else:
            with lock:
                waiter = waiters.get(message.get('requestId'))
                if waiter: waiter[1] = message; waiter[0].set()
finally:
    # os._exit below intentionally bypasses executor shutdown. First stop the
    # commands owned by this connector; otherwise an SSH disconnect leaves
    # in-flight exec children running without their 20-second deadline.
    with lock:
        closing.set()
        active_commands = list(commands.values())
        active_terminals = list(terminals.values())
    for process in active_commands:
        if process.poll() is None:
            try: os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            try: process.wait(timeout=2)
            except subprocess.TimeoutExpired: pass
    for term in active_terminals:
        try: term_close(term)
        except OSError: pass
    for key in list(mounted_shares):
        try: detach_share(key)
        except Exception: pass
    if share_upload is not None:
        try: share_upload['file'].close()
        except Exception: pass
    if share_directory is not None:
        shutil.rmtree(share_directory, ignore_errors=True)
    for sock in list(streams.values()): sock.close()
    # Own ephemeral connector only. Never shut down the server or other processes.
    os._exit(0)
