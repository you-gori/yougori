"""VM terminal, inference mailboxes and chosen-site tunnels, reached through an owner publication.

The VM has no network card unless its owner allowed the internet or chose targets, and Yougori's
filter on the host holds that card to the public internet or to the targets alone; chosen sites
are reached through vm_tunnel's proxy, which the launcher on the host opens only to those sites."""
import base64
import collections
import fcntl
import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import pty
import queue
import re
import secrets as tokens
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
HARNESS = re.compile(r"[a-z][a-z0-9-]{0,31}")
# Switching harness from the screen (/harness): the screen's switch command (runtime.py switch)
# asks this guest with the session's token, which only the screen's own process gets
# (YOUGORI_SWITCH_TOKEN; never an engine or a service), in this header. The launcher on the host
# takes the request from /poll and answers it (/switch/progress, accepted, done, failed).
SWITCH_HEADER = "X-Yougori-Switch"
SWITCH_TOKEN = "YOUGORI_SWITCH_TOKEN"
SWITCH_MODES = ("in-place", "new-vm")
# What the launcher tells a Yougori harness session about the harnesses it can switch to, written
# beside the answers for runtime.py to put in every spec: the list, the VM's base and memory, and
# the inference's address.
SESSION_FIELDS = ("harnesses", "vm_base", "vm_memory", "server")
SESSION_BYTES = 96 * 1024
BUSY = "Another harness switch is under way."


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


def valid_answers(answers):
    """Setup answers as a session or a switch takes them: at most 64, each a yes/no, a text or a
    list of texts, by answer id."""
    return isinstance(answers, dict) and len(answers) <= 64 and all(ANSWER_ID.fullmatch(str(key)) and (
        isinstance(value, bool) or bounded(value, 8000) or (isinstance(value, list) and len(value) <= 64
        and all(bounded(item, 8000) for item in value))) for key, value in answers.items())


def valid_secrets(secrets):
    """Secret answers: at most 16, each one line, by answer id."""
    return isinstance(secrets, dict) and len(secrets) <= 16 and all(ANSWER_ID.fullmatch(str(key)) and bounded(value, 4096)
        and value and "\n" not in value and "\r" not in value for key, value in secrets.items())


def session_fields(data):
    """What a Yougori harness session's launcher tells it about switching harness (SESSION_FIELDS),
    checked; {} from a launcher that tells nothing (switching is then not offered). The list's
    entries are the website's, as the launcher read them; the screen asks their questions."""
    if not any(name in data for name in SESSION_FIELDS):
        return {}
    fields = {name: data.get(name) for name in SESSION_FIELDS}
    harnesses, base, memory, server = (fields[name] for name in SESSION_FIELDS)
    def entry(item):
        return (isinstance(item, dict) and isinstance(item.get("id"), str) and HARNESS.fullmatch(item["id"])
                and bounded(item.get("name"), 80) and item.get("category") in ("coding", "security")
                and bounded(item.get("description", ""), 600) and isinstance(item.get("questions", []), list)
                and len(item.get("questions", [])) <= 32 and isinstance(item.get("base"), str) and HARNESS.fullmatch(item["base"])
                and type(item.get("memory")) is int and 0 < item["memory"] <= 1024 and isinstance(item.get("ready"), bool)
                and bounded(item.get("reason", ""), 300))
    if (not isinstance(harnesses, list) or not 1 <= len(harnesses) <= 64 or not all(entry(item) for item in harnesses)
            or len({item["id"] for item in harnesses}) != len(harnesses) or not isinstance(base, str) or not HARNESS.fullmatch(base)
            or type(memory) is not int or not 0 < memory <= 1024 or not bounded(server, 2048)
            or not re.fullmatch(r"https?://[^\s/]+", server) or len(json.dumps(fields)) > SESSION_BYTES):
        raise Refusal("The launcher's list of harnesses is not valid.")
    return fields


def private_json(folder, name, value):
    """Writes `value` to folder/name, readable by this user alone, whole or not at all."""
    written = folder / (".%s.partial" % name)
    descriptor = os.open(written, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(value, stream)
    os.chmod(written, 0o600)
    os.replace(written, folder / name)


def harness_session(data, image, environment, home=HOME, token=None):
    """A /start for the Yougori harness, which holds `image`: the harness this VM's image was made
    for, or on the Yougori harness's base the one whose pack the launcher declared. Checks what
    the launcher sent, writes the setup answers where runtime.py reads them (owner-only, in the
    home, never in the workspace) and adds SOLVER_HARNESS, SOLVER_REACH and one
    YOUGORI_SECRET_<ID> variable per secret answer to `environment`. Secrets go nowhere else. With
    the harnesses it may switch to (session_fields) and a `token`, it writes them beside the
    answers (session.json) and gives the screen the switch token. Returns runtime.py's command."""
    harness = data.get("harness")
    if harness != image:
        raise Refusal("This VM was made for another harness. Start the harness again.")
    answers, secrets, reach = data.get("answers", {}), data.get("secrets", {}), data.get("reach", {})
    if not valid_answers(answers):
        raise Refusal("The harness's setup answers are not valid.")
    if not valid_secrets(secrets):
        raise Refusal("The harness's secret answers are not valid.")
    if not isinstance(reach, dict) or reach.get("mode", "inference") not in REACH:
        raise Refusal("The harness's reach is not valid.")
    sites, targets = reach.get("sites", []), reach.get("targets", [])
    if (not isinstance(sites, list) or not isinstance(targets, list) or len(sites) > 64 or len(targets) > 64
            or not all(bounded(site, 253) for site in sites) or not all(isinstance(t, str) and TARGET.fullmatch(t) for t in targets)):
        raise Refusal("The harness's reach is not valid.")
    fields = session_fields(data)
    folder = home / ".yougori"
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(folder, 0o700)
    private_json(folder, "answers.json", answers)
    if fields and token:
        private_json(folder, "session.json", fields)
        environment[SWITCH_TOKEN] = token
    else:
        (folder / "session.json").unlink(missing_ok=True)
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
        # Switching harness from the screen: the session's token, the harnesses it may switch to
        # (their ids), and the one switch under way or last ended (switch_begin).
        self.token = tokens.token_urlsafe(32)
        self.switchable = set()
        self.switch = None

    def command(self, data, environment):
        """runtime.py's command for a /start, with what its session adds to `environment`. An image
        made for one harness starts it as before, or holds it in a Yougori harness session; the
        Yougori harness's base starts only a session, holding the harness the launcher declared,
        and switches harness from the screen when the launcher listed the harnesses to switch to."""
        if not self.shared:
            return harness_session(data, self.image, environment, self.home) if "harness" in data else ["run", self.image]
        if "harness" not in data:
            raise Refusal("This VM starts harnesses only inside the Yougori harness. Update Yougori: yougori update")
        held = self.package.status().get("harness")
        if held is None:
            raise Refusal(UNTOLD)
        command = harness_session(data, held, environment, self.home, self.token)
        self.switchable = {item["id"] for item in session_fields(data).get("harnesses", [])}
        return command

    # ---- switching harness (/harness in the screen)

    def switch_begin(self, data):
        """The screen's switch command asks for another harness (runtime.py switch): `harness`,
        `model`, its `answers` and `mode` (in-place: its pack comes into this VM; new-vm: the
        launcher starts another VM for it, with `targets`, `memory` and `secrets`). One at a time.
        The id the screen asks about."""
        harness, mode = data.get("harness"), data.get("mode")
        targets, secrets = data.get("targets", []), data.get("secrets", {})
        if (not isinstance(harness, str) or harness not in self.switchable or mode not in SWITCH_MODES
                or not bounded(data.get("model"), 1024) or not data.get("model") or not valid_answers(data.get("answers", {}))
                or not isinstance(targets, list) or len(targets) > 64
                or not all(isinstance(target, str) and TARGET.fullmatch(target) for target in targets)
                or not valid_secrets(secrets) or (mode == "in-place" and (targets or secrets))
                or ("memory" in data and (type(data["memory"]) is not int or not 0 < data["memory"] <= 1024))):
            raise ValueError("Invalid harness switch.")
        with self.lock:
            if not self.started or self.exit_code is not None:
                raise ValueError("This VM has no harness session.")
            if self.switch is not None and self.switch["state"] in ("waiting", "working", "accepted"):
                raise Refusal(BUSY)
            package = self.package.status()
            self.switch = {"id": uuid.uuid4().hex, "harness": harness, "model": data["model"], "answers": data.get("answers", {}),
                           "mode": mode, "targets": targets, "secrets": secrets, "state": "waiting", "progress": "",
                           "reason": "", "cancelled": False, "before": (package.get("harness"), self.package.spec)}
            if "memory" in data:
                self.switch["memory"] = data["memory"]
            self.lock.notify_all()
            return self.switch["id"]

    def switch_record(self, identity):
        """The switch `identity` names (the lock held), or a refusal."""
        if self.switch is None or not isinstance(identity, str) or not hmac.compare_digest(identity, self.switch["id"]):
            raise ValueError("No such harness switch.")
        return self.switch

    def kept(self, record):
        """Whether the harness before a switch can start again: its pack is still the one installed."""
        package = self.package.status()
        return package["phase"] == "ready" and (package.get("harness"), self.package.spec) == record["before"]

    def switch_status(self, identity):
        with self.lock:
            record = self.switch_record(identity)
            value = {name: record[name] for name in ("state", "progress", "reason")}
            if record["state"] == "failed":
                value["kept"] = self.kept(record)
            return value

    def switch_cancel(self, identity):
        """The screen stopped waiting (Esc): a switch the launcher has not taken ends here; one it is
        working on ends at its next step (its pack is refused from now on)."""
        with self.lock:
            record = self.switch_record(identity)
            if record["state"] == "waiting":
                record.update(state="failed", reason="Cancelled.")
                record.pop("secrets", None)
            elif record["state"] in ("working", "accepted"):
                record["cancelled"] = True
            self.lock.notify_all()
            return {"state": record["state"]}

    def switch_take(self):
        """The waiting switch for the launcher, once (in /poll): its secrets leave this VM's memory
        with it."""
        record = self.switch
        if record is None or record["state"] != "waiting":
            return None
        record["state"] = "working"
        taken = {name: record[name] for name in ("id", "harness", "model", "answers", "mode")}
        if record["mode"] == "new-vm":
            taken.update(targets=record["targets"], secrets=record.pop("secrets", {}))
            if "memory" in record:
                taken["memory"] = record["memory"]
        else:
            record.pop("secrets", None)
        return taken

    def switch_report(self, path, data):
        """The launcher's word on the switch it took: progress text, accepted (new-vm), done
        (in-place) or failed with its reason. Whether the screen has cancelled it."""
        with self.lock:
            record = self.switch_record(data.get("id"))
            if record["state"] != "working" and not (path == "/switch/failed" and record["state"] == "accepted"):
                raise ValueError("This harness switch has ended.")
            text = data.get("text") if path == "/switch/progress" else data.get("reason")
            words = "".join(c for c in text if not (ord(c) < 32 or 127 <= ord(c) <= 159))[:300] if isinstance(text, str) else ""
            if path == "/switch/progress":
                record["progress"] = words
            elif path == "/switch/accepted":
                if record["mode"] != "new-vm":
                    raise ValueError("This harness switch stays in this VM.")
                record["state"] = "accepted"
            elif path == "/switch/done":
                if record["mode"] != "in-place" or record["cancelled"]:
                    raise ValueError("This harness switch cannot end that way.")
                record["state"] = "done"
            else:
                record.update(state="failed", reason=words or "The harness could not be switched.")
            self.lock.notify_all()
            return {"cancelled": record["cancelled"]}

    def switch_pack(self, data):
        """A pack declaration the launcher sends for the in-place switch it is working on: it takes
        the place of the pack installed. Refused once the screen cancelled the switch."""
        with self.lock:
            record = self.switch
            replacing = (record is not None and record["state"] == "working" and record["mode"] == "in-place"
                         and isinstance(data, dict) and data.get("harness") == record["harness"])
            if replacing and record["cancelled"]:
                raise ValueError("The harness switch was cancelled.")
        return self.package.expect(data, replace=replacing)

    def switch_end(self):
        """The session ended: a switch under way ends with it, and any secrets it held go."""
        with self.lock:
            if self.switch is not None:
                self.switch.pop("secrets", None)
                if self.switch["state"] in ("waiting", "working"):
                    self.switch.update(state="failed", reason="The session ended.")
                self.lock.notify_all()

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
        self.switch_end()
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
                    return self.send_json(200, state.switch_pack(data))
                except ValueError as refusal:
                    # vm_package's fixed words: a declaration this VM cannot take is not taken by
                    # asking again.
                    return self.send_json(409, {"error": str(refusal)})
            if self.path == '/package/chunk':
                with state.lock:
                    cancelled = state.switch is not None and state.switch["state"] == "working" and state.switch["cancelled"]
                if cancelled:
                    return self.send_json(409, {"error": "The harness switch was cancelled."})
                return self.send_json(200,state.package.chunk(data))
            if self.path in ("/switch", "/switch/status", "/switch/cancel"):
                # From inside the VM: the screen's switch command, with the session's token.
                given = self.headers.get(SWITCH_HEADER) or ""
                if not hmac.compare_digest(given.encode(), state.token.encode()):
                    return self.send_json(403, {"error": "Switching harness needs the screen's own request."})
                try:
                    if self.path == "/switch":
                        return self.send_json(200, {"id": state.switch_begin(data)})
                    if self.path == "/switch/status":
                        return self.send_json(200, state.switch_status(data.get("id")))
                    return self.send_json(200, state.switch_cancel(data.get("id")))
                except Refusal as refusal:
                    return self.send_json(409, {"error": str(refusal)})
                except ValueError as error:
                    return self.send_json(400, {"error": str(error)})
            if self.path in ("/switch/progress", "/switch/accepted", "/switch/done", "/switch/failed"):
                # From the launcher, for the switch it took from /poll.
                return self.send_json(200, state.switch_report(self.path, data))
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
                        state.exit_code is not None or (state.switch is not None and state.switch["state"] == "waiting"), timeout=5)
                    output = bytes(state.output[:65536])
                    del state.output[:len(output)]
                    requests = [state.requests.popleft()] if state.requests else []
                    tunnels = state.tunnels.take() if state.tunnels else []
                    switch = state.switch_take()
                    state.lock.notify_all()
                    packet = {"output": base64.b64encode(output).decode(), "requests": requests, "tunnels": tunnels,
                              "exit": state.exit_code if not state.output else None}
                    if switch is not None:
                        packet["switch"] = switch
                    return self.send_json(200, packet)
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
