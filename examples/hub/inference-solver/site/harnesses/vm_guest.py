"""VM terminal, inference mailboxes and chosen-site tunnels, reached through an owner publication.

The VM has no network card unless its owner allowed the whole internet; chosen sites are reached
through vm_tunnel's proxy, which the launcher on the host opens only to those sites."""
import base64
import collections
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pty
import queue
import struct
import subprocess
import sys
import tarfile
import termios
import threading
import uuid
from pathlib import Path
from relay import LIMIT, allowed
from vm_package import Package
from vm_tunnel import PROXY_PORT, GuestTunnels, serve_proxy, sites as chosen_sites

HERE = Path(__file__).resolve().parent


class State:
    def __init__(self):
        self.lock = threading.Condition()
        self.requests = collections.deque()
        self.responses = {}
        self.output = bytearray()
        self.process = None
        self.master = None
        self.started = False
        self.package = Package(HERE)
        self.tunnels = None

    def output_reader(self):
        try:
            while block := os.read(self.master, 16384):
                with self.lock:
                    self.lock.wait_for(lambda: len(self.output) < 1024 * 1024, timeout=180)
                    if len(self.output) >= 1024 * 1024:
                        self.process.terminate()
                        return
                    self.output.extend(block)
                    self.lock.notify_all()
        except OSError:
            pass
        finally:
            self.process.wait()
            with self.lock:
                self.lock.notify_all()

    def start(self, data):
        with self.lock:
            if self.started:
                raise ValueError("This VM already has a harness session.")
            if self.package.status()['phase'] != 'ready':
                raise ValueError("The verified tool package is not ready.")
            arguments = data.get("arguments", [])
            if (not isinstance(arguments, list) or len(arguments) > 256 or
                    any(not isinstance(a, str) or "\0" in a or len(a) > 65536 for a in arguments)):
                raise ValueError("Invalid harness arguments.")
            model = data.get("model")
            if not isinstance(model, str) or not 1 <= len(model) <= 1024 or "\0" in model:
                raise ValueError("Invalid model.")
            harness = (HERE / "harness-name").read_text().strip()
            environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": "/home/node", "TERM": "xterm-256color",
                           "LANG": "C.UTF-8", "SOLVER_MODEL": model}
            if data.get("sites") is not None:
                # Chosen sites: the tool's HTTPS goes through the VM's proxy; model requests stay
                # on the relay at loopback.
                self.tunnels = GuestTunnels(chosen_sites(data["sites"]), self.lock)
                serve_proxy(self.tunnels)
                proxy = "http://127.0.0.1:%d" % PROXY_PORT
                for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
                    environment[name] = proxy
                environment["NO_PROXY"] = environment["no_proxy"] = "127.0.0.1,localhost"
            workspace = Path("/run/yougori/workspace")
            if data.get('workspace') is not True:
                workspace = Path("/workspace")
                workspace.mkdir(exist_ok=True)
                environment["SOLVER_EMPTY_WORKSPACE"] = "1"
            elif not workspace.is_dir():
                raise ValueError('The selected workspace is unavailable in this VM.')
            self.master, slave = pty.openpty()
            self.resize(data.get("columns", 100), data.get("rows", 30))
            try:
                self.process = subprocess.Popen([sys.executable, str(HERE / "runtime.py"), "run", harness, *arguments],
                    stdin=slave, stdout=slave, stderr=slave, env=environment, cwd=workspace, start_new_session=True)
            finally:
                os.close(slave)
            self.started = True
            threading.Thread(target=self.output_reader, daemon=True).start()

    def resize(self, columns, rows):
        if not isinstance(columns, int) or not isinstance(rows, int) or not 10 <= columns <= 500 or not 2 <= rows <= 300:
            raise ValueError("Invalid terminal size.")
        if self.master is not None:
            fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def send_json(self, status, value):
        body = json.dumps(value, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(body)

    def body(self, bound):
        self.connection.settimeout(30)
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            raise ValueError("Use one Content-Length.")
        size = int(self.headers["Content-Length"])
        if not 0 <= size <= bound:
            raise ValueError("Request too large.")
        raw = self.rfile.read(size)
        if len(raw) != size:
            raise ValueError("Incomplete request.")
        return raw


class Control(Handler):
    def do_POST(self):
        state = self.server.state
        try:
            data = json.loads(self.body(3 * 1024 * 1024 if self.path in ('/package/chunk', '/tunnel') else 128 * 1024))
            if not isinstance(data, dict):
                raise ValueError("Expected an object.")
            if self.path == '/package/status':
                return self.send_json(200,state.package.status())
            if self.path == '/package/chunk':
                return self.send_json(200,state.package.chunk(data))
            if self.path == '/package/finish':
                state.package.finish()
                return self.send_json(200,state.package.status())
            if self.path == "/start":
                state.start(data)
                # "tunnels": this VM serves chosen sites; an older image would leave them out.
                return self.send_json(200, {"started": True, "tunnels": True})
            if self.path == "/poll":
                with state.lock:
                    state.lock.wait_for(lambda: state.output or state.requests or (state.tunnels and state.tunnels.events) or
                        (state.process and state.process.poll() is not None), timeout=5)
                    output = bytes(state.output[:65536])
                    del state.output[:len(output)]
                    requests = [state.requests.popleft()] if state.requests else []
                    tunnels = state.tunnels.take() if state.tunnels else []
                    state.lock.notify_all()
                    return self.send_json(200, {"output": base64.b64encode(output).decode(), "requests": requests, "tunnels": tunnels,
                        "exit": state.process.poll() if state.process and not state.output else None})
            if self.path == "/input":
                raw = base64.b64decode(data.get("data", ""), validate=True)
                if len(raw) > 16384 or state.master is None:
                    raise ValueError("Invalid terminal input.")
                if raw:
                    os.write(state.master, raw)
                if "columns" in data:
                    state.resize(data["columns"], data["rows"])
                return self.send_json(200, {})
            if self.path == "/tunnel":
                if state.tunnels is None or not state.tunnels.from_host(data):
                    return self.send_json(410, {"error": "Tunnel ended."})
                return self.send_json(200, {})
            if self.path == "/response":
                with state.lock:
                    channel = state.responses.get(data.get("id"))
                if channel is None:
                    return self.send_json(410, {"error": "Request ended."})
                channel.put(data, timeout=30)
                return self.send_json(200, {})
            self.send_json(404, {})
        except (ValueError, TypeError, KeyError, OSError, queue.Full):
            self.send_json(400, {"error": "Invalid or expired control request."})


class Inference(Handler):
    def do_GET(self):
        self.forward()

    def do_POST(self):
        self.forward()

    def forward(self):
        state = self.server.state
        identity = None
        started = False
        try:
            if not allowed(self.command, self.path):
                return self.send_json(403, {"error": "Only Inference Solver model requests are allowed."})
            body = self.body(LIMIT) if self.command == "POST" else b""
            channel = queue.Queue(maxsize=8)
            with state.lock:
                if len(state.responses) >= 4:
                    return self.send_json(429, {"error": "Four inference requests are already pending."})
                identity = uuid.uuid4().hex
                state.responses[identity] = channel
                state.requests.append({"id": identity, "method": self.command, "path": self.path,
                                       "body": base64.b64encode(body).decode()})
                state.lock.notify_all()
            while True:
                reply = channel.get(timeout=190)
                if "error" in reply:
                    if not started:
                        self.send_json(502, {"error": {"message": reply["error"]}})
                    return
                if "status" in reply:
                    self.send_response(reply["status"])
                    self.send_header("Content-Type", reply["content_type"])
                    self.send_header("Connection", "close")
                    self.end_headers()
                    started = True
                if "data" in reply:
                    self.wfile.write(base64.b64decode(reply["data"], validate=True))
                    self.wfile.flush()
                if reply.get("done"):
                    return
        except (ValueError, OSError, queue.Empty):
            if not started:
                self.send_json(502, {"error": {"message": "The VM relay connection ended."}})
        finally:
            if identity:
                with state.lock:
                    state.responses.pop(identity, None)


def main():
    archive = HERE / "tool.tar.gz"
    if archive.exists():
        with tarfile.open(archive) as stream:
            stream.extractall(HERE, filter="data")
    state = State()
    inference = ThreadingHTTPServer(("127.0.0.1", 8080), Inference)
    inference.state = state
    threading.Thread(target=inference.serve_forever, daemon=True).start()
    control = ThreadingHTTPServer(("127.0.0.1", 8090), Control)
    control.state = state
    control.serve_forever()


if __name__ == "__main__":
    main()
