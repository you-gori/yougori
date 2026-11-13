"""VM terminal, inference mailboxes and chosen-site tunnels, reached through an owner publication.

The VM has no network card unless its owner allowed the internet or chose targets, and Yougori's
filter on the host holds that card to the public internet or to the targets alone; chosen sites
are reached through vm_tunnel's proxy, which the launcher on the host opens only to those sites."""
import base64
import collections
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pty
import queue
import re
import signal
import struct
import subprocess
import sys
import tarfile
import termios
import threading
import uuid
from pathlib import Path
from profiles import SETUP_FILES
from relay import LIMIT, allowed
from vm_package import Package
from vm_tunnel import PROXY_PORT, GuestTunnels, serve_proxy, shares_name, sites as chosen_sites, target_ports

HERE = Path(__file__).resolve().parent
HOME = Path("/home/node")
# The person's folder, as the VM's copy of it.
WORKSPACE = Path("/run/yougori/workspace")
# How long a session that the launcher ends (/finish) has after each signal: hangup, then
# SIGTERM, then SIGKILL. With git's check of the setup files (GIT_SECONDS), within the launcher's 35
# seconds for a control request.
FINISH_SECONDS = 6
GIT_SECONDS = 10
# The Yougori harness's base image, which holds whichever harness's pack the launcher declares.
YOUGORI = "yougori"
UNTOLD = "This VM has not been told which harness to run. Start the harness again."
# What the person's terminal shows, as the launcher says (/start "colorterm").
COLORTERMS = ("truecolor", "24bit")
ANSWER_ID = re.compile(r"[a-z][a-z0-9_]{0,31}")
TARGET = re.compile(r"[a-z0-9.-]{1,253}(?::[0-9]{1,5})?")
REACH = ("inference", "sites", "targets", "full")


class Refusal(ValueError):
    """A /start this VM refuses whatever the timing; the launcher stops instead of asking again.
    Its words are fixed: never a value the launcher sent."""


def bounded(value, most):
    """A string of at most `most` characters without NUL."""
    return isinstance(value, str) and len(value) <= most and "\0" not in value


def target_list(data):
    """The /start's targets (`host[:port]`, at most 64), checked."""
    targets = data.get("targets", [])
    if (not isinstance(targets, list) or len(targets) > 64
            or not all(isinstance(target, str) and TARGET.fullmatch(target) for target in targets)):
        raise Refusal("The harness's targets are not valid.")
    return targets


def target_hosts(data):
    """The hosts of the /start's targets, each once: they go straight out on the VM's network
    card, which Yougori holds to them."""
    return list(dict.fromkeys(target.split(":")[0] for target in target_list(data)))


def proxy_bypass(sites, data):
    """What NO_PROXY names beside the sites' proxy: loopback, where the model relay is, and each
    target host that goes straight out on the card. A target that is a chosen site, lies under
    one or has one under it stays on the proxy, which opens it straight out on its own ports
    too: NO_PROXY covers a name's subdomains and never a port, so naming it there would take the
    site off the proxy as well, and the card would refuse the site."""
    return ["127.0.0.1", "localhost", *(host for host in target_hosts(data) if not shares_name(sites, host))]


def harness_environment(data, model):
    """The environment runtime.py starts with: the VM's own, the model, and what the person's
    terminal shows as the launcher says it (/start): no colour at all (NO_COLOR), or 24-bit colour
    (COLORTERM)."""
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(HOME), "TERM": "xterm-256color",
                   "LANG": "C.UTF-8", "SOLVER_MODEL": model}
    if data.get("no_color") is True:
        environment["NO_COLOR"] = "1"
    elif data.get("colorterm") in COLORTERMS:
        environment["COLORTERM"] = data["colorterm"]
    return environment


def harness_session(data, image, environment, home=HOME):
    """A /start for the Yougori harness, which holds `image`: the harness this VM's image was made
    for, or on the Yougori harness's base the one whose pack the launcher declared. Checks what
    the launcher sent, writes the setup answers where runtime.py reads them (owner-only, in the
    home, never in the workspace) and adds SOLVER_HARNESS, SOLVER_REACH and one
    YOUGORI_SECRET_<ID> variable per secret answer to `environment`. Secrets go nowhere else.
    Returns runtime.py's command."""
    harness = data.get("harness")
    if harness != image:
        raise Refusal("This VM was made for another harness. Start the harness again.")
    answers, secrets, reach = data.get("answers", {}), data.get("secrets", {}), data.get("reach", {})
    if (not isinstance(answers, dict) or len(answers) > 64 or any(not ANSWER_ID.fullmatch(str(key)) or not (
            isinstance(value, bool) or bounded(value, 8000) or (isinstance(value, list) and len(value) <= 64
            and all(bounded(item, 8000) for item in value))) for key, value in answers.items())):
        raise Refusal("The harness's setup answers are not valid.")
    if (not isinstance(secrets, dict) or len(secrets) > 16 or any(not ANSWER_ID.fullmatch(str(key)) or not bounded(value, 4096)
            or not value or "\n" in value or "\r" in value for key, value in secrets.items())):
        raise Refusal("The harness's secret answers are not valid.")
    if not isinstance(reach, dict) or reach.get("mode", "inference") not in REACH:
        raise Refusal("The harness's reach is not valid.")
    sites, targets = reach.get("sites", []), reach.get("targets", [])
    if (not isinstance(sites, list) or not isinstance(targets, list) or len(sites) > 64 or len(targets) > 64
            or not all(bounded(site, 253) for site in sites) or not all(isinstance(t, str) and TARGET.fullmatch(t) for t in targets)):
        raise Refusal("The harness's reach is not valid.")
    folder = home / ".yougori"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    written = folder / ".answers.json.partial"
    descriptor = os.open(written, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(answers, stream)
    os.chmod(written, 0o600)
    os.replace(written, folder / "answers.json")
    environment["SOLVER_HARNESS"] = harness
    environment["SOLVER_REACH"] = json.dumps({"mode": reach.get("mode", "inference"), "sites": sites, "targets": targets},
                                             separators=(",", ":"))
    for answer, value in secrets.items():
        environment["YOUGORI_SECRET_" + answer.upper()] = value
    return ["run", "yougori"]


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def kept_setup(data):
    """The setup files that the person's folder already holds, as the launcher says (/start
    "setup_in_folder"). They are the person's files, so they stay in the copy. A name that is not a
    setup file is ignored."""
    names = data.get("setup_in_folder", [])
    if not isinstance(names, list) or len(names) > 64 or not all(isinstance(name, str) for name in names):
        raise Refusal("The launcher's list of setup files is not valid.")
    return {name for name in names if name in SETUP_FILES}


def setup_files(workspace, kept=()):
    """The setup files that the engine's setup package added to `workspace`, the VM's copy of the
    person's folder, as a session starts, by name: what each holds. The package adds them at every
    launch, except the ones the folder already holds (`kept`), which it leaves as they are."""
    found = {}
    for name in SETUP_FILES:
        if name in kept:
            continue
        try:
            found[name] = digest(Path(workspace) / name)
        except OSError:
            continue
    return found


def tracked(workspace, names):
    """Which of `names` the workspace's own git repository tracks: none without git or one."""
    try:
        done = subprocess.run(["git", "-c", "safe.directory=*", "-C", str(workspace), "ls-files", "-z", "--", *names],
                              capture_output=True, timeout=GIT_SECONDS, env={"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                              "HOME": str(HOME), "GIT_CONFIG_NOSYSTEM": "1", "GIT_OPTIONAL_LOCKS": "0"})
    except (OSError, subprocess.SubprocessError):
        return set()
    if done.returncode:
        return set()
    return {name for name in done.stdout.decode("utf-8", "replace").split("\0") if name}


def tidy_setup(workspace, found):
    """After a session, the setup files that the setup package added leave the VM's copy of the
    folder (`found`, as the session started), so the person's review lists only what the harness
    changed: each file that still holds what it held then and that the project's git does not
    track, then the folders the setup package made for them, once empty. Harnesses read them during
    the session. The names removed."""
    if not found:
        return []
    workspace, own = Path(workspace), tracked(workspace, sorted(found))
    removed = []
    for name, held in sorted(found.items()):
        if name in own:
            continue
        try:
            if digest(workspace / name) != held:
                continue
            (workspace / name).unlink()
        except OSError:
            continue
        removed.append(name)
    folders = {parent for name in removed for parent in Path(name).parents if parent != Path(".")}
    for folder in sorted(folders, key=lambda folder: len(folder.parts), reverse=True):
        try:
            (workspace / folder).rmdir()
        except OSError:
            continue
    return removed


class State:
    def __init__(self, root=HERE, home=HOME):
        """`root`: where the image keeps its harness-name and receives its tool package; `home`:
        the harness's home, where a session's answers are written."""
        self.home = home
        self.lock = threading.Condition()
        self.requests = collections.deque()
        self.responses = {}
        self.output = bytearray()
        self.process = None
        self.master = None
        self.started = False
        # The harness's exit code once it has ended and the copy of the folder is tidied
        # (tidy_setup), with what that tidying needs: where the copy is and its setup files.
        self.exit_code = None
        self.workspace = None
        self.setup = {}
        name = Path(root) / "harness-name"
        # The harness this image was made for; the Yougori harness's base holds the harness whose
        # pack the launcher declares first (vm_package), or Yougori's own agent, which needs none.
        self.image = name.read_text().strip() if name.is_file() else ""
        self.shared = self.image == YOUGORI
        self.package = Package(root, shared=self.shared)
        self.tunnels = None

    def command(self, data, environment):
        """runtime.py's command for a /start, with what its session adds to `environment`. An image
        made for one harness starts it as before, or holds it in a Yougori harness session; the
        Yougori harness's base starts only a session, holding the harness the launcher declared."""
        if not self.shared:
            return harness_session(data, self.image, environment, self.home) if "harness" in data else ["run", self.image]
        if "harness" not in data:
            raise Refusal("This VM starts harnesses only inside the Yougori harness. Update Yougori: yougori update")
        held = self.package.status().get("harness")
        if held is None:
            raise Refusal(UNTOLD)
        return harness_session(data, held, environment, self.home)

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

    def ended(self):
        """Waits for the harness to end, takes Yougori's setup files out of the copy of the folder,
        then gives its exit code: the launcher stops the VM once it has it."""
        code = self.process.wait()
        tidy_setup(self.workspace, self.setup)
        with self.lock:
            self.exit_code = code
            self.lock.notify_all()

    def finish(self, seconds=FINISH_SECONDS):
        """Ends the session for a launcher that leaves first (Ctrl+]), as a closed terminal would: a
        hangup to the harness's process group, then SIGTERM and SIGKILL, each after `seconds` while it
        runs, so it can save its work. Waits until the copy of the folder is tidied (ended). The
        launcher asks for this (/finish) before it stops the VM: once a stop has begun, the VM's agent
        refuses every file of the copy. The exit code; None without a session or when the harness
        outlasts SIGKILL."""
        with self.lock:
            process, code = self.process, self.exit_code
        if process is None or code is not None:
            return code
        for number in (signal.SIGHUP, signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, number)
            except OSError:
                pass
            with self.lock:
                if self.lock.wait_for(lambda: self.exit_code is not None, timeout=seconds):
                    return self.exit_code
        return None

    def start(self, data):
        with self.lock:
            if self.started:
                raise ValueError("This VM already has a harness session.")
            package = self.package.status()
            if self.shared and "harness" not in package:
                raise Refusal(UNTOLD)
            if package['phase'] != 'ready':
                raise ValueError("The verified tool package is not ready.")
            arguments = data.get("arguments", [])
            if (not isinstance(arguments, list) or len(arguments) > 256 or
                    any(not isinstance(a, str) or "\0" in a or len(a) > 65536 for a in arguments)):
                raise ValueError("Invalid harness arguments.")
            model = data.get("model")
            if not isinstance(model, str) or not 1 <= len(model) <= 1024 or "\0" in model:
                raise ValueError("Invalid model.")
            kept = kept_setup(data)
            environment = harness_environment(data, model)
            command = self.command(data, environment)
            if data.get("sites") is not None:
                # Chosen sites: the tool's HTTPS goes through the VM's proxy; model requests stay
                # on the relay at loopback; the proxy opens chosen targets straight out.
                sites = chosen_sites(data["sites"])
                self.tunnels = GuestTunnels(sites, self.lock, target_ports(target_list(data)))
                serve_proxy(self.tunnels)
                proxy = "http://127.0.0.1:%d" % PROXY_PORT
                for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
                    environment[name] = proxy
                environment["NO_PROXY"] = environment["no_proxy"] = ",".join(proxy_bypass(sites, data))
            workspace = WORKSPACE
            if data.get('workspace') is not True:
                workspace = Path("/workspace")
                workspace.mkdir(exist_ok=True)
                environment["SOLVER_EMPTY_WORKSPACE"] = "1"
            elif not workspace.is_dir():
                raise ValueError('The selected workspace is unavailable in this VM.')
            else:
                # The person's folder: the setup files the setup package added leave it when the
                # session ends. The ones the folder already held are the person's, and stay.
                self.workspace, self.setup = workspace, setup_files(workspace, kept)
            self.master, slave = pty.openpty()
            self.resize(data.get("columns", 100), data.get("rows", 30))
            try:
                self.process = subprocess.Popen([sys.executable, str(HERE / "runtime.py"), *command, *arguments],
                    stdin=slave, stdout=slave, stderr=slave, env=environment, cwd=workspace, start_new_session=True)
            finally:
                os.close(slave)
            self.started = True
            threading.Thread(target=self.output_reader, daemon=True).start()
            threading.Thread(target=self.ended, daemon=True).start()

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
            if self.path == '/package/expect':
                try:
                    return self.send_json(200, state.package.expect(data))
                except ValueError as refusal:
                    # vm_package's fixed words: a declaration this VM cannot take is not taken by
                    # asking again.
                    return self.send_json(409, {"error": str(refusal)})
            if self.path == '/package/chunk':
                return self.send_json(200,state.package.chunk(data))
            if self.path == '/package/finish':
                state.package.finish()
                return self.send_json(200,state.package.status())
            if self.path == "/start":
                try:
                    state.start(data)
                except Refusal as refusal:
                    return self.send_json(409, {"error": str(refusal)})
                # "tunnels": this VM serves chosen sites; "yougori": it takes a Yougori harness
                # session's answers; "targets": beside chosen sites, its targets go straight out
                # (past the proxy, or through it when they share a site's name). An older image
                # would leave them out.
                return self.send_json(200, {"started": True, "tunnels": True, "yougori": True, "targets": True})
            if self.path == "/poll":
                with state.lock:
                    state.lock.wait_for(lambda: state.output or state.requests or (state.tunnels and state.tunnels.events) or
                        state.exit_code is not None, timeout=5)
                    output = bytes(state.output[:65536])
                    del state.output[:len(output)]
                    requests = [state.requests.popleft()] if state.requests else []
                    tunnels = state.tunnels.take() if state.tunnels else []
                    state.lock.notify_all()
                    return self.send_json(200, {"output": base64.b64encode(output).decode(), "requests": requests, "tunnels": tunnels,
                        "exit": state.exit_code if not state.output else None})
            if self.path == "/finish":
                return self.send_json(200, {"exit": state.finish()})
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
