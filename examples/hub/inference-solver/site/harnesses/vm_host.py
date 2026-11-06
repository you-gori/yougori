"""Launch real Yougori Sandbox VMs. No container engine or host-tool fallback."""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile
import vm_relay
import vm_tunnel
from transport import opener as transport_opener


def executable():
    value = os.environ.get("INFERENCE_SOLVER_YOUGORI") or shutil.which("yougori")
    if not value and os.name == "nt":
        candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Yougori/cli/yougori.exe"
        value = str(candidate) if candidate.is_file() else None
    if not value:
        raise ValueError("Install Yougori first, then run this harness again.")
    return value


def call(action, **params):
    process = subprocess.run([executable(), "call", "sandbox_vm", "--file", "-", "--yes"],
        input=json.dumps({"action": action, **params}), text=True, capture_output=True, timeout=900)
    try:
        reply = json.loads(process.stdout)
    except ValueError:
        raise ValueError("Yougori did not return a sandbox response. Start/update Yougori and try again.") from None
    if process.returncode or not reply.get("ok"):
        detail = reply.get("error", "The VM operation failed.")
        raise ValueError(str(detail)[:1500])
    return reply["result"]


def ready():
    call("status")  # An older engine must refuse; never silently run outside the VM.


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def preflight(name, server):
    ready()
    opener=transport_opener()
    try:
        with opener.open(server+'/api/harnesses',timeout=30) as response:
            catalog=json.loads(response.read(1024*1024))
        item=next(h for h in catalog['harnesses'] if h['id']==name)
        if not item['setup']['available']:
            raise ValueError(item['setup']['reason'])
    except (OSError,KeyError,StopIteration):
        raise ValueError('Cannot check this harness on the server. Check the website connection and try again.') from None


def artifact_base(server, descriptor):
    base = descriptor.get('download_base', server + '/api/harness-image')
    p, origin = urlsplit(base), urlsplit(server)
    same = (p.scheme, p.hostname, p.port) == (origin.scheme, origin.hostname, origin.port)
    development = (origin.scheme == 'http' and bool(re.fullmatch(r'[a-z0-9]+\.localhost', origin.hostname or ''))
                   and p.scheme == 'http' and p.hostname == '127.0.0.1' and p.port is not None
                   and p.path == '/api/inference/artifacts')
    if p.username or p.password or p.query or p.fragment or not (same or development):
        raise ValueError('The artifact publisher is outside this server\'s allowed origin.')
    if same and p.path not in ('/api/harness-image', '/api/inference/artifacts'):
        raise ValueError('Invalid artifact publisher path.')
    return base


def install(name, server, root):
    root_gb = 3 if name == 'shannon' else 2
    ready()
    opener = transport_opener()
    try:
        with opener.open(server + "/api/harness-image/" + name, timeout=30) as response:
            descriptor = json.loads(response.read(65537))
    except (OSError, ValueError):
        raise ValueError("This server has not prepared this harness's Yougori VM image yet.") from None
    digest, size = descriptor.get("sha256"), descriptor.get("bytes")
    if not isinstance(digest, str) or not re.fullmatch("[a-f0-9]{64}", digest) or not isinstance(size, int) or not 0 < size <= 300 << 20:
        raise ValueError("Invalid VM image descriptor.")
    if descriptor.get("runtime") != "yougori-sandbox-vm" or descriptor.get("platform") != "linux/amd64":
        raise ValueError("This VM image targets an unsupported runtime or platform.")
    download_base = artifact_base(server, descriptor)
    tool = descriptor.get('tool')
    if tool:
        if (not isinstance(tool,dict) or not re.fullmatch('[a-f0-9]{64}',str(tool.get('sha256',''))) or
            type(tool.get('bytes')) is not int or not 0<tool['bytes']<=512<<20):
            raise ValueError('Invalid tool package descriptor.')
        tool_path = root/'tools'/(tool['sha256']+'.tar.gz')
        tool_path.parent.mkdir(exist_ok=True)
        valid = False
        if tool_path.is_file() and tool_path.stat().st_size == tool['bytes']:
            with tool_path.open('rb') as stream: valid = hashlib.file_digest(stream,'sha256').hexdigest() == tool['sha256']
        if not valid:
            print('Downloading tool files ('+str(round(tool['bytes']/(1024*1024)))+' MB)...',flush=True)
            temporary=tool_path.with_suffix('.partial')
            try:
                sha=hashlib.sha256(); total=0
                with opener.open(download_base+'/'+name+'/'+tool['sha256']+'/tool',timeout=180) as response,temporary.open('wb') as output:
                    while block:=response.read(1024*1024):
                        total+=len(block)
                        if total>tool['bytes']: raise ValueError('Tool package exceeded its declared size.')
                        sha.update(block);output.write(block)
                if total!=tool['bytes'] or sha.hexdigest()!=tool['sha256']: raise ValueError('Tool package checksum mismatch.')
                temporary.replace(tool_path)
            finally:temporary.unlink(missing_ok=True)
    (root/'tool-package.json').write_text(json.dumps(tool))
    record = root / "vm-image.json"
    if record.exists():
        cached = json.loads(record.read_text())
        if cached.get("archive") == digest and cached.get('root_gb') == root_gb and any(image.get("id") == cached.get("digest")
                for image in call("image", operation="list")):
            return cached["digest"]
    # Only hash-pinned public artifacts use the configured publisher. No account
    # credentials, session cookies or inference requests go to that destination.
    folder = root / "images" / digest
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / "image.zip"
    if not archive.exists() or hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        print('Downloading Sandbox VM image ('+str(round(size/(1024*1024)))+' MB)...',flush=True)
        temporary = folder / "download.partial"
        total, sha = 0, hashlib.sha256()
        try:
            with opener.open(download_base + "/" + name + "/" + digest, timeout=180) as response, temporary.open("wb") as output:
                while block := response.read(1024 * 1024):
                    total += len(block)
                    if total > size:
                        raise ValueError("VM image exceeded its declared size.")
                    sha.update(block)
                    output.write(block)
            if total != size or sha.hexdigest() != digest:
                raise ValueError("VM image checksum did not match.")
            os.replace(temporary, archive)
        finally:
            temporary.unlink(missing_ok=True)
    layout = folder / "layout"
    layout.mkdir(exist_ok=True)
    with zipfile.ZipFile(archive) as package:
        names = package.namelist()
        if len(names) > 256 or len(names) != len(set(names)) or sum(i.file_size for i in package.infolist()) > 300 << 20:
            raise ValueError("Invalid OCI archive bounds.")
        for info in package.infolist():
            entry = info.filename
            if not (entry in ("oci-layout", "index.json") or re.fullmatch("blobs/sha256/[a-f0-9]{64}", entry)) or info.file_size > 256 << 20:
                raise ValueError("Invalid OCI archive entry.")
            target = layout / entry
            target.parent.mkdir(exist_ok=True, parents=True)
            target.write_bytes(package.read(info))
    print("Preparing the verified image in Yougori...", flush=True)
    result = call("image", operation="import", layout=str(layout), ownerSelected=True, rootGb=root_gb)
    identity = result.get("id")
    if not isinstance(identity, str) or not re.fullmatch("sha256:[a-f0-9]{64}", identity):
        raise ValueError("Yougori did not return an imported image identity.")
    (root / "vm-image.json").write_text(json.dumps({"digest": identity, "archive": digest, "root_gb": root_gb}), encoding="utf-8")
    return identity


class Control:
    def __init__(self, url):
        p = urlsplit(url)
        if p.scheme != "http" or not p.hostname or not p.hostname.endswith(".localhost") or not p.port:
            raise ValueError("Yougori did not return an owner-only local publication.")
        self.port = p.port
        self.token = p.hostname.removesuffix(".localhost")
        if not re.fullmatch("[a-zA-Z0-9_-]+", self.token):
            raise ValueError("Invalid publication identity.")

    def post(self, path, data):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=35)
        try:
            connection.request("POST", path, body=json.dumps(data).encode(), headers={
                "Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(6 * 1024 * 1024 + 1)
            if response.status != 200 or len(raw) > 6 * 1024 * 1024:
                raise ValueError("The Yougori VM connection failed (HTTP " + str(response.status) + "): " + raw[:350].decode('utf-8','replace'))
            return json.loads(raw)
        finally:
            connection.close()


def prepare_tool(control,root):
    spec=json.loads((root/'tool-package.json').read_text())
    if not spec: return
    print('Preparing the tool inside your VM...',flush=True)
    deadline=time.monotonic()+1800
    status=None
    while time.monotonic()<deadline:
        try: status=control.post('/package/status',{});break
        except (OSError,ValueError,http.client.HTTPException):time.sleep(.5)
    if status is None: raise ValueError('The VM tool installer did not become ready.')
    if status['phase']=='waiting':
        offset=status['offset']
        if type(offset) is not int or not 0<=offset<=spec['bytes']: raise ValueError('Invalid package transfer offset.')
        with (root/'tools'/(spec['sha256']+'.tar.gz')).open('rb') as stream:
            # The VM takes up to 2 MiB a chunk (vm_package); each chunk is one request through the
            # owner publication, so large chunks make the transfer several times faster.
            chunk_bytes=2<<20
            reported=0
            last_report=time.monotonic()
            while offset<spec['bytes']:
                if time.monotonic()>=deadline:raise ValueError('The VM tool transfer timed out.')
                stream.seek(offset);block=stream.read(chunk_bytes)
                try: reply=control.post('/package/chunk',{'offset':offset,'data':base64.b64encode(block).decode()})
                except (OSError,ValueError,http.client.HTTPException):
                    # A lost acknowledgement is resolved by the guest's exact
                    # offset; never duplicate a write. Some runtimes accept only
                    # small request bodies, so retry an unwritten chunk once at
                    # the conservative transport size.
                    reply=control.post('/package/status',{})
                    if reply.get('offset')==offset and chunk_bytes>32<<10:
                        chunk_bytes=256<<10 if chunk_bytes>256<<10 else 32<<10;continue
                    if reply.get('offset')!=offset+len(block):raise
                offset+=len(block)
                if reply.get('offset')!=offset:raise ValueError('The tool package transfer was interrupted.')
                progress=offset*100//spec['bytes']
                if progress>=reported+5 or time.monotonic()-last_report>=10 or offset==spec['bytes']:
                    reported=progress;last_report=time.monotonic()
                    print('Preparing tool: '+str(progress)+'% ('+str(offset//(1024*1024))+'/'+str(spec['bytes']//(1024*1024))+' MB)',flush=True)
        control.post('/package/finish',{})
    while time.monotonic()<deadline:
        status=control.post('/package/status',{})
        if status['phase']=='ready':return
        if status['phase']=='failed':raise ValueError(status['error'])
        time.sleep(.5)
    raise ValueError('The VM tool installation timed out.')


def terminal_input(control, done):
    try:
        if os.name == "nt":
            import msvcrt
            while not done.wait(.02):
                if not msvcrt.kbhit():
                    continue
                char = msvcrt.getwch()
                if char in ("\x00", "\xe0"):
                    char = {"H": "\x1b[A", "P": "\x1b[B", "K": "\x1b[D", "M": "\x1b[C",
                            "S": "\x1b[3~", "G": "\x1b[H", "O": "\x1b[F"}.get(msvcrt.getwch(), "")
                if char == "\x1d":
                    done.set()
                    return
                control.post("/input", {"data": base64.b64encode(char.encode()).decode()})
        else:
            import select
            while not done.is_set():
                if select.select([sys.stdin], [], [], .1)[0]:
                    raw = os.read(sys.stdin.fileno(), 16384)
                    if not raw or b"\x1d" in raw:
                        done.set()
                        return
                    control.post("/input", {"data": base64.b64encode(raw).decode()})
    except (OSError, ValueError, http.client.HTTPException):
        done.set()


def launch_params(name, identity, workspace, cpu=None, memory=None, internet=False):
    """The Sandbox VM launch. Model requests always leave through this launcher's relay; internet
    adds the engine's outgoing network for everything else (no incoming access)."""
    # An owner session: the relay publication reaches only this launcher, and a whole session of
    # prompts, replies and terminal output fits its release account (not VM-D12's 8 MiB).
    params = {"image": identity, "cpu": cpu or 2, "memoryGb": memory or (6 if name == 'shannon' else 4),
              "publish": "solver=8090", "idleSeconds": 0, "lifetimeSeconds": 0, "ownerSession": True}
    if workspace:
        params["workspace"] = str(workspace)
    if internet:
        params["internet"] = True
    return params


def launch(name, server, key_file, model, workspace, arguments, interactive=True, cpu=None, memory=None, internet=False,
           sites=None):
    root = key_file.parent
    identity = install(name, server, root)
    print("Starting Yougori Sandbox VM. " + ("It can reach the internet; model requests still go only through Yougori's relay."
          if internet else "It reaches only this inference and " + ", ".join(sites) + ", through Yougori's relay."
          if sites else "It reaches only this inference: Yougori relays its model requests."), flush=True)
    sandbox = None
    done = threading.Event()
    relay_failed = threading.Event()
    original = None
    tunnels = None
    try:
        params = launch_params(name, identity, workspace, cpu, memory, internet)
        result = call("launch", **params)
        sandbox = result.get("sandbox")
        if not isinstance(sandbox, str) or not re.fullmatch("exe-[a-f0-9]{32}", sandbox):
            raise ValueError("Yougori did not return the VM identity.")
        (root / "last-vm.json").write_text(json.dumps({"sandbox": sandbox, "workspace": str(workspace) if workspace else None}))
        publication = call("publish", sandbox=sandbox, service="solver", audience="owner", minutes=0)
        control = Control(publication["url"])
        prepare_tool(control,root)
        size = shutil.get_terminal_size((100, 30))
        started = False
        deadline = time.monotonic() + 600
        attempt = 0
        while time.monotonic() < deadline:
            try:
                body = {"model": model, "arguments": arguments, "workspace": bool(workspace),
                        "columns": max(10, min(500, size.columns)), "rows": max(2, min(300, size.lines))}
                if sites:
                    body["sites"] = sites
                started = control.post("/start", body)
                break
            except (OSError, ValueError, http.client.HTTPException):
                if attempt % 10 == 0:
                    status = call("status")
                    for image in status.get("images", []):
                        if image.get("sandbox") == sandbox and image.get("outcome"):
                            outcome = image["outcome"]
                            raise ValueError("VM harness startup failed: " + json.dumps({k:outcome.get(k) for k in ("exit_code","end","output_text")})[-3000:])
                attempt += 1
                time.sleep(.5)
        if not started:
            raise ValueError("The VM harness service did not start.")
        if sites:
            # An image from before chosen sites starts without its proxy: stop rather than run
            # a session that cannot reach what was chosen.
            if started.get("tunnels") is not True:
                raise ValueError("This harness's VM image cannot reach chosen sites yet. Ask the administrator to publish "
                                 "a newer image, or choose another internet option.")
            tunnels = vm_tunnel.HostTunnels(lambda message: control.post("/tunnel", message), sites)
        secret = key_file.read_text().strip()
        pending = set()
        if interactive and sys.stdin.isatty():
            if os.name != "nt":
                import termios
                import tty
                original = termios.tcgetattr(sys.stdin)
                tty.setraw(sys.stdin)
            threading.Thread(target=terminal_input, args=(control, done), daemon=True).start()
        while not done.is_set():
            packet = control.post("/poll", {})
            output = base64.b64decode(packet.get("output", ""), validate=True)
            if output:
                sys.stdout.buffer.write(output)
                sys.stdout.buffer.flush()
            if relay_failed.is_set():
                raise ValueError("The VM inference relay ended unexpectedly.")
            pending = {worker for worker in pending if worker.is_alive()}
            for request in packet.get("requests", []):
                if len(pending) >= 4 or not isinstance(request, dict) or not re.fullmatch("[a-f0-9]{32}", str(request.get("id", ""))):
                    raise ValueError("Invalid VM relay request.")
                identity = request["id"]
                def deliver(value, request_id=identity):
                    if not done.is_set():
                        control.post("/response", {**value, "id": request_id})
                def forward(value=request, send=deliver):
                    try:
                        vm_relay.forward(server, secret, value, send)
                    except (OSError, ValueError, http.client.HTTPException):
                        relay_failed.set()
                worker = threading.Thread(target=forward, daemon=True)
                pending.add(worker)
                worker.start()
            for event in packet.get("tunnels", []):
                if tunnels is None:
                    raise ValueError("The VM opened a tunnel this session did not allow.")
                tunnels.handle(event)
            if packet.get("exit") is not None:
                return int(packet["exit"])
            current = shutil.get_terminal_size((100, 30))
            if current != size:
                size = current
                control.post("/input", {"columns": max(10, min(500, size.columns)), "rows": max(2, min(300, size.lines))})
        return 130
    except KeyboardInterrupt:
        return 130
    finally:
        done.set()
        if tunnels:
            tunnels.close_all()
        if original:
            import termios
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, original)
        if sandbox:
            try:
                call("stop", sandbox=sandbox)
            except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                print("The VM could not be stopped automatically: " + str(error), file=sys.stderr)
            if workspace:
                print("\nYour original project is unchanged. Review the VM copy with:\n"
                      + "yougori sandbox review " + sandbox, flush=True)
