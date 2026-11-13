"""Plandex (2.2.1) behind the Yougori screen, over ACP.

Plandex's own server, database and CLI run in the VM as plandex_cli.py starts them for its terminal
client (PostgreSQL, plandex-server, the OpenAI-only model proxy, a local account, this inference's
model as the custom model pack), and the session works on one plan in the workspace. Each prompt
becomes the plan's next step: `plandex tell` (or `plandex chat` in the chat mode), given the prompt
in a file of its own, runs in a terminal of its own, as Plandex's stream screen needs one, while
the bridge follows the plan's stream through Plandex's server: the reply streams as messages,
context loading, file builds and describing as progress. When the step leaves changes pending,
they come as diffs and the person is asked before they are applied (`plandex apply`, which may
also run the plan's commands); a rejection runs `plandex reject --all`. Plandex's own keyboard
questions during a command (yes/no,
menus) are asked through the screen; its changes menu is left with Enter, as the bridge offers the
changes itself. This inference's models switch in place, between steps (a switch during a turn
is taken by the next one). A cancel stops the plan through Plandex's server, then the command.
"""
import base64
import errno
import hashlib
import http.client
import json
import os
import re
import shlex
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from http.server import ThreadingHTTPServer
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
if __package__ in (None, ""):
    sys.path[:] = [p for p in sys.path if os.path.abspath(p or os.curdir) != _HERE]
    sys.path.append(os.path.dirname(_HERE))

from bridges import support_acp as support  # noqa: E402
from bridges.acp import Cancelled  # noqa: E402

import plandex_cli  # noqa: E402  (the terminal client's launcher: its model proxy and API helper)

HOST, PORT = "127.0.0.1", 8099
SEPARATOR = b"@@PX@@"
FINISH = "<PlandexFinish/>"
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[PX^_][^\x1b]*\x1b\\|\x1b[@-Z\\-_]")
ALT_ON, ALT_OFF = b"\x1b[?1049h", b"\x1b[?1049l"
QUERIES = ((b"\x1b]11;?", b"\x1b]11;rgb:1e1e/1e1e/1e1e\x1b\\"), (b"\x1b]10;?", b"\x1b]10;rgb:d0d0/d0d0/d0d0\x1b\\"),
           (b"\x1b[6n", b"\x1b[1;1R"), (b"\x1b[c", b"\x1b[?62;22c"), (b"\x1b[0c", b"\x1b[?62;22c"))
YES_NO = re.compile(r"([^\n]*?)\s*\(y\)es \| \(n\)o(?: \| \(c\)ancel)?\s*>")
SELECT = re.compile(r"\?\s+(.+?)\s+\[Use arrows to move")
# Plandex's changes menu after a step (plan_exec/action_menu.go), which waits for one raw key.
HOTKEYS = re.compile(r"Press a hotkey,[^\n]*?to exit menu/keep iterating>")
MODES = [{"id": "tell", "name": "Tell", "description": "Plan and make changes to files (plandex tell)."},
         {"id": "chat", "name": "Chat", "description": "Talk about the plan without changing files (plandex chat)."}]
COMMANDS = [
    {"name": "diff", "description": "Show the plan's pending changes"},
    {"name": "apply", "description": "Apply the pending changes (asks first)"},
    {"name": "reject", "description": "Reject all pending changes"},
    {"name": "continue", "description": "Continue the plan"},
    {"name": "load", "description": "Load files or folders into the plan's context", "hint": "paths (-r for folders)"},
    {"name": "context", "description": "List the plan's context (plandex ls)"},
    {"name": "log", "description": "Show the plan's history"},
    {"name": "convo", "description": "Show the plan's conversation"},
    {"name": "summary", "description": "Show the plan's summary"},
    {"name": "rewind", "description": "Rewind the plan", "hint": "steps or sha"},
]
OUTPUT_LIMIT = 256 * 1024
ROLES = ("planner", "coder", "planSummary", "builder", "wholeFileBuilder", "namer", "commitMsg", "execStatus",
         "contextLoader")


class Proxy(ThreadingHTTPServer):
    """plandex_cli.py's model proxy. A reply Plandex's server stopped reading (a cancelled plan) is
    no error to print."""
    daemon_threads = True

    def handle_error(self, request, client_address):
        if not isinstance(sys.exc_info()[1], (BrokenPipeError, ConnectionResetError)):
            super().handle_error(request, client_address)


def version():
    try:
        return (plandex_cli.TOOL / "bin" / "version.txt").read_text().strip() or "2.2.1"
    except OSError:
        return "2.2.1"


def plain(data):
    text = data.decode("utf-8", errors="replace") if isinstance(data, (bytes, bytearray)) else data
    text = ANSI.sub("", text)
    out = []
    for line in text.replace("\r\n", "\n").split("\n"):
        out.append(line.rsplit("\r", 1)[-1])
    return "\n".join(out)


class Terminal:
    """One Plandex CLI command in a terminal of its own: its stream screen and its keyboard
    questions need one. The command leads its own session (setsid -c), so a stop reaches all of it."""

    def __init__(self, argv, cwd, env, on_screen=None, on_prompt=None, columns=160, rows=48):
        import fcntl
        import termios
        master, slave = os.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, columns, 0, 0))
        self.master = master
        self.output = bytearray()
        self.seen = 0
        self.screen = False
        self.nudged = None
        self.on_screen, self.on_prompt = on_screen, on_prompt
        self.lock = threading.Lock()
        try:
            self.process = subprocess.Popen(["setsid", "-c", *argv], stdin=slave, stdout=slave, stderr=slave, cwd=cwd,
                                            env=env, close_fds=True)
        finally:
            os.close(slave)
        support.remember_group(self.process.pid)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while True:
            try:
                block = os.read(self.master, 65536)
            except OSError:
                break
            if not block:
                break
            self._answer_queries(block)
            with self.lock:
                self.output += block
                if len(self.output) > OUTPUT_LIMIT:
                    cut = len(self.output) - OUTPUT_LIMIT
                    del self.output[:cut]
                    self.seen = max(0, self.seen - cut)
            if ALT_ON in block and self.on_screen:
                self.screen = True
                self.on_screen(True)
            if ALT_OFF in block:
                if self.screen and self.on_screen:
                    self.on_screen(False)
                self.screen = False
            if not self.screen:
                self._prompts()

    def _answer_queries(self, block):
        """Answers what a terminal answers (Plandex's colour and screen libraries ask, then wait
        for the reply): the cursor position, the device attributes, a dark background."""
        for query, reply in QUERIES:
            if query in block:
                self.write(reply)

    def _prompts(self):
        with self.lock:
            fresh = plain(bytes(self.output[self.seen:]))
        if HOTKEYS.search(fresh):
            # Plandex's changes menu: Enter leaves it ("exit menu"), and the bridge then offers the
            # pending changes through the screen. A key that arrives before the menu reads its
            # keyboard reads as another one ("Invalid hotkey"); the menu then shows again and is
            # answered again.
            with self.lock:
                self.seen = len(self.output)
            time.sleep(0.3)
            self.write(b"\r")
            return
        if self.on_prompt is None:
            return
        match = YES_NO.search(fresh)
        if match:
            with self.lock:
                self.seen = len(self.output)
            self.on_prompt(self, "yes_no", match.group(1).strip(), None)
            return
        match = SELECT.search(fresh)
        if match:
            time.sleep(0.2)  # the options follow the question
            with self.lock:
                fresh = plain(bytes(self.output[self.seen:]))
                self.seen = len(self.output)
            after = fresh[fresh.find(match.group(0)) + len(match.group(0)):]
            options = [line.strip().lstrip(">").strip() for line in after.split("\n")[1:] if line.strip()][:12]
            self.on_prompt(self, "select", match.group(1).strip(), options)

    def write(self, data):
        try:
            os.write(self.master, data)
        except OSError:
            pass

    def text(self):
        with self.lock:
            return plain(bytes(self.output))

    def wait(self, cancel=None, on_cancel=None):
        """The exit code; on cancel, `on_cancel` runs once and the wait goes on."""
        asked = False
        while True:
            try:
                return self.process.wait(timeout=0.2)
            except subprocess.TimeoutExpired:
                if cancel is not None and cancel.is_set() and not asked:
                    asked = True
                    if on_cancel:
                        threading.Thread(target=on_cancel, args=(self,), daemon=True).start()

    def stop(self, grace=5.0):
        support.stop_group(self.process, grace=grace, first=signal.SIGTERM)

    def close(self):
        self.reader.join(timeout=2)
        try:
            os.close(self.master)
        except OSError:
            pass
        support.forget_group(self.process.pid)


# The folder `plandex new` writes into the workspace (PLANDEX_ENV=development).
PROJECT = ".plandex-dev-v2"


class PlandexBridge(support.QueuedBridge):
    def __init__(self, args, stdin, **options):
        super().__init__("Plandex", version(), stdin, title="Plandex", models=args.models, model=args.model,
                         modes=[dict(m) for m in MODES], mode="tell", **options)
        self.args = args
        self.workspace = None
        # Whether the workspace had Plandex's project folder before this session (stop_services).
        self.had_project = True
        self.ready = threading.Event()
        self.failure = None
        self.processes = []
        self.proxy = None
        self.auth = None
        self.environment = None
        self.cli = str(plandex_cli.TOOL / "bin" / "plandex")
        self.terminal = None
        self.ids = 0
        self.lock = threading.Lock()
        self.reply_open = self.spoke = False
        self.held = ""
        self.watching = None
        # The stages of the command the plan's stream follows (builds, processing), by name: each
        # command's progress lines are its own (the screen updates a line by its id).
        self.streams = 0
        self.stages = {}
        # The model Plandex's pack and proxy are on, and one chosen while a turn ran (or while
        # Plandex started), which the next turn takes before its first command.
        self.applied = None
        self.pending_model = None
        self.turn_open = False
        self.switch_lock = threading.Lock()

    # Services, as plandex_cli.py starts them.

    def new_session(self, cwd, mcp_servers):
        self.workspace = cwd
        self.had_project = os.path.isdir(os.path.join(cwd, PROJECT))
        if os.path.isdir(cwd):
            os.chdir(cwd)
        self.commands(COMMANDS)
        threading.Thread(target=self._start, daemon=True).start()

    def _start(self):
        # Started by the protocol's reader, which keeps SIGINT and SIGTERM blocked: the services
        # and commands started from here must not inherit that.
        support.unblock_signals()
        try:
            self.start_services()
            self.new_plan()
        except Exception as error:
            traceback.print_exc()
            self.failure = "Plandex could not start: %s" % (error,)
            self.notice(self.failure, "error")
        finally:
            self.ready.set()

    def start_services(self):
        self.progress("plandex-start", "Starting Plandex's server and database")
        home = Path.home()
        state = home / "plandex-local"
        state.mkdir(exist_ok=True)
        pg = Path("/usr/lib/postgresql/17/bin")
        database = state / "database"
        tool = plandex_cli.TOOL
        environment = {**os.environ, "PLANDEX_ENV": "development", "PLANDEX_API_HOST": plandex_cli.SERVER, "GOENV": "development",
                       "LOCAL_MODE": "1", "DATABASE_URL": "postgres://node@127.0.0.1:5432/plandex?sslmode=disable",
                       "MIGRATIONS_DIR": str(tool / "migrations"), "PLANDEX_BASE_DIR": str(state / "plans"),
                       "SOLVER_API_KEY": "solver-local-relay"}
        cli_home = home / ".plandex-home-dev-v2"
        cli_home.mkdir(exist_ok=True)
        shutil.copytree(tool / "tokenizer", cli_home / "cache", dirs_exist_ok=True)
        environment["TIKTOKEN_CACHE_DIR"] = str(cli_home / "cache")
        environment["PLANDEX_COLUMNS"] = "160"
        # Plandex pages some output (log, convo) through `less`, which the VM image does not have;
        # here the pager only passes the text on.
        pager = state / "bin"
        pager.mkdir(exist_ok=True)
        (pager / "less").write_text("#!/bin/sh\nexec cat\n")
        (pager / "less").chmod(0o755)
        environment["PATH"] = str(pager) + os.pathsep + environment.get("PATH", "/usr/bin:/bin")
        self.environment = environment
        # One model throughout the start; one chosen meanwhile waits for the first turn.
        model = self.model
        try:
            self.proxy = Proxy(("127.0.0.1", 4000), plandex_cli.Bridge)
        except OSError as error:
            if error.errno == errno.EADDRINUSE:
                raise RuntimeError("another Plandex session is running in this VM (its model port 4000 is taken); "
                                   "close it first") from None
            raise
        self.proxy.model = model
        threading.Thread(target=self.proxy.serve_forever, daemon=True).start()
        log = (state / "services.log").open("a")
        if not database.exists():
            subprocess.run([str(pg / "initdb"), "-D", str(database), "--auth=trust", "--no-locale"], check=True, stdout=log,
                           stderr=log, stdin=subprocess.DEVNULL)
        postgres = subprocess.Popen([str(pg / "postgres"), "-D", str(database), "-h", "127.0.0.1", "-k", str(state), "-c",
                                     "jit=off"], stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        self.processes.append(("postgres", postgres))
        for _ in range(240):
            if subprocess.run([str(pg / "pg_isready"), "-h", "127.0.0.1"], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0:
                break
            if postgres.poll() is not None:
                raise RuntimeError("its database stopped; see ~/plandex-local/services.log in the VM")
            time.sleep(0.25)
        else:
            raise RuntimeError("its database did not become ready")
        subprocess.run([str(pg / "createdb"), "-h", "127.0.0.1", "plandex"], stdout=log, stderr=log, stdin=subprocess.DEVNULL)
        server = subprocess.Popen([str(tool / "bin/plandex-server")], env=environment, cwd=state, stdout=log, stderr=log,
                                  stdin=subprocess.DEVNULL)
        self.processes.append(("plandex-server", server))
        for _ in range(240):
            try:
                plandex_cli.request("/health")
                break
            except OSError:
                if server.poll() is not None:
                    raise RuntimeError("its server stopped; see ~/plandex-local/services.log in the VM")
                time.sleep(0.25)
        else:
            raise RuntimeError("its server did not become ready")
        stored = cli_home / "auth.json"
        try:
            account = plandex_cli.request("/accounts", {"email": "solver@localhost.local", "userName": "Inference Solver"})
        except OSError:
            # Started again in the same VM: its database already has the account the last start made.
            if not stored.exists():
                raise
            self.auth = json.loads(stored.read_text())
        else:
            auth = {**{key: account[key] for key in ("userId", "token", "email", "userName")}, "orgId": "", "orgName": "",
                    "isCloud": False, "host": plandex_cli.SERVER, "isLocalMode": True, "orgIsTrial": False,
                    "integratedModelsMode": False}
            orgs = account.get("orgs") or []
            org = orgs[0] if orgs else plandex_cli.request("/orgs", {"name": "Inference Solver", "autoAddDomainUsers": False},
                                                           auth)
            auth.update(orgId=org["id"], orgName=org.get("name", "Inference Solver"))
            stored.write_text(json.dumps(auth))
            self.auth = auth
        self.custom_models(model)
        code, output = self.run_cli(["set-model", "default", "Inference Solver"])
        if code:
            raise RuntimeError("it did not take the model pack: %s" % output.strip()[-400:])
        self.applied = model
        self.progress("plandex-start", "Plandex's server is ready", finished=True)

    def custom_models(self, model):
        """This inference's model as Plandex's custom model pack (every role), as plandex_cli.py sets it."""
        budget = self.args.context_window
        definition = {"modelId": "solver-selected", "publisher": "custom", "description": "Selected Inference Solver model",
                      "maxTokens": budget, "defaultMaxConvoTokens": budget // 2, "maxOutputTokens": 1024,
                      "reservedOutputTokens": 1024, "preferredOutputFormat": "xml",
                      "providers": [{"provider": "custom", "customProvider": "Inference Solver", "modelName": model}]}
        roles = {name: {"modelId": "solver-selected"} for name in ROLES}
        plandex_cli.request("/custom_models", {
            "providers": [{"name": "Inference Solver", "baseUrl": "http://127.0.0.1:4000/v1", "apiKeyEnvVar": "SOLVER_API_KEY"}],
            "models": [definition], "modelPacks": [{"name": "Inference Solver", "description": "One server; no external fallback",
                                                     **roles}]}, self.auth)

    def new_plan(self):
        code, output = self.in_terminal(["new"], watch=False)
        if code:
            raise RuntimeError("it could not start a plan: %s" % output.strip()[-400:])
        text = output.strip()
        if text:
            self.notice(text)

    def stop_services(self):
        # `plandex new` writes its project file into the workspace; it points at a plan in a
        # database that goes with the VM, so it is not left for the person to review. First: the
        # harness gives a bridge 3 s after SIGTERM, less than the services below may take.
        if self.workspace and not self.had_project:
            shutil.rmtree(os.path.join(self.workspace, PROJECT), ignore_errors=True)
        for name, process in reversed(self.processes):
            if process.poll() is not None:
                continue
            process.send_signal(signal.SIGINT if name == "postgres" else signal.SIGTERM)
            try:
                process.wait(timeout=8)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        self.processes = []
        if self.proxy is not None:
            self.proxy.shutdown()
            self.proxy.server_close()
            self.proxy = None

    # The CLI.

    def run_cli(self, args, timeout=600):
        """A Plandex command without a terminal (nothing it runs here asks anything)."""
        try:
            done = subprocess.run([self.cli, *args], cwd=self.workspace, env=self.environment, capture_output=True,
                                  stdin=subprocess.DEVNULL, timeout=timeout)
        except subprocess.TimeoutExpired:
            return 1, "Plandex did not answer within %d s." % timeout
        return done.returncode, plain(done.stdout + done.stderr)

    def in_terminal(self, args, watch=True):
        """A Plandex command in a terminal of its own, its stream followed and its questions asked."""
        if watch:
            self.streams += 1
            self.stages = {}
        terminal = Terminal([self.cli, *args], self.workspace, self.environment,
                            on_screen=self.screen_changed if watch else None, on_prompt=self.answer_prompt)
        self.terminal = terminal
        if watch:
            threading.Thread(target=self.guard_screen, args=(terminal,), daemon=True).start()
        try:
            code = terminal.wait(self.cancel_event, self.stop_plan)
        finally:
            self.terminal = None
            terminal.close()
            watcher = self.watching
            if watcher is not None:
                watcher.join(timeout=10)
        text = terminal.text()
        self.keep_transcript(args, code, text)
        if code and terminal.nudged == "finished":
            # The plan finished on the server; only its screen missed the end (and the reply, which
            # came before it started): the reply is taken from the conversation instead.
            code = 0
            if not self.spoke:
                self.last_reply()
        if watch:
            if not code and not self.cancel_event.is_set():
                # Stages still open when the command ended well are done; otherwise the screen
                # shows them stopped when the turn ends.
                for name, (label, amounts) in list(self.stages.items()):
                    self.stage(name, label, finished=True, **amounts)
            self.stages = {}
        return code, text

    def stage(self, name, label, finished=False, **amounts):
        """One stage of the followed command as progress."""
        if finished:
            self.stages.pop(name, None)
        else:
            self.stages[name] = (label, amounts)
        self.progress("plandex-%d-%s" % (self.streams, name), label, finished=finished, **amounts)

    def last_reply(self):
        try:
            plan, branch = self.plan_ids()
            status, raw = self.api("GET", "/plans/%s/%s/convo" % (plan, branch))
            if status >= 400:
                return
            messages = json.loads(raw or b"[]") or []
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            return
        for entry in reversed(messages):
            if (entry.get("role") or entry.get("Role")) == "assistant":
                text = markdown(entry.get("message") or entry.get("Message") or "")
                if text:
                    self.reply(text)
                return

    def keep_transcript(self, args, code, text):
        """What each command showed, for the log beside Plandex's services.log."""
        try:
            with open(Path.home() / "plandex-local" / "terminal.log", "a", encoding="utf-8") as log:
                log.write("\n===== plandex %s (exit %s) %s\n" % (" ".join(args)[:200], code, time.strftime("%H:%M:%S")))
                log.write(text[-20000:])
        except OSError:
            pass

    def guard_screen(self, terminal):
        """Plandex's stream screen waits for the plan's `finished` message; when the whole reply
        came before the screen started (a very fast model), that message is lost and the screen
        would wait forever. Once the plan is over on the server for a few seconds while the screen
        still waits, the screen is closed as Ctrl+C closes it."""
        over = 0
        while terminal.process.poll() is None:
            time.sleep(2)
            if not terminal.screen or self.cancel_event.is_set():
                over = 0
                continue
            state = self.plan_status()
            over = over + 1 if state in ("finished", "stopped", "error") else 0
            if over >= 2 and terminal.process.poll() is None:
                terminal.nudged = state
                terminal.write(b"\x03")
                return

    def plan_status(self):
        """The plan branch's status on Plandex's server (replying, building, finished...), or None."""
        try:
            plan, branch = self.plan_ids()
            status, raw = self.api("GET", "/plans/%s/branches" % plan, timeout=10)
            if status >= 400:
                return None
            # The server sends its database rows (Name, Status); the CLI's type says name, status.
            for entry in json.loads(raw or b"[]") or []:
                if (entry.get("Name") or entry.get("name")) == branch:
                    return entry.get("Status") or entry.get("status")
        except (OSError, ValueError, KeyError, TypeError, AttributeError, http.client.HTTPException):
            return None
        return None

    def screen_changed(self, on):
        if on and (self.watching is None or not self.watching.is_alive()):
            self.watching = threading.Thread(target=self.watch, daemon=True)
            self.watching.start()

    def answer_prompt(self, terminal, kind, question, options):
        """One of Plandex's keyboard questions, asked through the screen and typed into its terminal."""
        tool = self.next_id("ask")
        if kind == "yes_no":
            self.tool_call(tool, question or "Plandex asks", kind="other", status="pending")
            try:
                choice = self.ask_permission(tool, question or "Plandex asks", options=[
                    {"optionId": "y", "name": "Yes", "kind": "allow_once"},
                    {"optionId": "n", "name": "No", "kind": "reject_once"}])
            except (Cancelled, ConnectionError, RuntimeError, TimeoutError):
                choice = None
            self.tool_update(tool, status="completed" if choice == "y" else "failed")
            terminal.write(b"y" if choice == "y" else b"n")
            return
        choices = options or []
        try:
            answer = self.question(question, choices=choices)
        except (Cancelled, ConnectionError, RuntimeError, TimeoutError):
            answer = None
        if not answer or answer[0] not in choices:
            # Dismissed: the menu's safe way out when it has one (after failed commands: roll back),
            # else what Ctrl+C does there.
            safe = next((c for c in choices if c.lower().startswith("rollback")), None)
            if safe is None:
                terminal.write(b"\x03")
                return
            answer = [safe]
        terminal.write(b"\x1b[B" * choices.index(answer[0]) + b"\r")

    # The plan.

    def plan_ids(self):
        """The CLI's current project, plan and branch, from its own files."""
        user = self.auth["userId"]
        with open(os.path.join(self.workspace, PROJECT, "projects-v2.json"), encoding="utf-8") as stream:
            project = json.load(stream)[user]["id"]
        base = Path.home() / ".plandex-home-dev-v2" / project
        with open(base / "current-plans-v2.json", encoding="utf-8") as stream:
            plan = json.load(stream)[user]["id"]
        branch = "main"
        try:
            with open(base / plan / "settings-v2.json", encoding="utf-8") as stream:
                branch = json.load(stream)[user].get("branch") or "main"
        except (OSError, ValueError, KeyError, TypeError):
            pass
        return plan, branch

    def headers(self):
        auth = self.auth
        state = {"token": auth["token"], "orgId": auth["orgId"],
                 "hash": hashlib.sha256((auth["orgName"] + "|false|false").encode()).hexdigest()}
        return {"Content-Type": "application/json", "X-Client-Version": version(),
                "Authorization": "Bearer " + base64.urlsafe_b64encode(json.dumps(state, separators=(",", ":")).encode()).decode()}

    def api(self, method, path, timeout=30):
        connection = http.client.HTTPConnection(HOST, PORT, timeout=timeout)
        try:
            connection.request(method, path, headers=self.headers())
            response = connection.getresponse()
            return response.status, response.read(16 * 1024 * 1024)
        finally:
            connection.close()

    def watch(self):
        """Follows the plan's stream on Plandex's server while its CLI shows it."""
        try:
            plan, branch = self.plan_ids()
        except (OSError, ValueError, KeyError, TypeError):
            return
        for _ in range(8):
            connection = http.client.HTTPConnection(HOST, PORT, timeout=60)
            try:
                connection.request("PATCH", "/plans/%s/%s/connect" % (plan, branch), headers=self.headers())
                response = connection.getresponse()
                if response.status >= 400:
                    response.read()
                    connection.close()
                    if self.terminal is None or not self.terminal.screen:
                        return
                    time.sleep(0.25)
                    continue
                buffer = b""
                while True:
                    block = response.read1(65536)
                    if not block:
                        break
                    buffer += block
                    while SEPARATOR in buffer:
                        raw, buffer = buffer.split(SEPARATOR, 1)
                        if self.stream_message(raw):
                            return
                return
            except (OSError, http.client.HTTPException):
                return
            finally:
                connection.close()

    def stream_message(self, raw):
        """One message of the plan's stream; True when the stream is over."""
        raw = raw.strip()
        if not raw or raw == b"heartbeat":
            return False
        try:
            message = json.loads(raw)
        except ValueError:
            return False
        kind = message.get("type")
        if kind == "multi":
            return any([self.stream_message(json.dumps(m).encode()) for m in message.get("streamMessages") or []])
        if kind == "connectActive":
            # What the plan said before this connection, as the server stored it (its own markup).
            replies = [markdown(r) for r in message.get("initReplies") or [] if r]
            if any(replies):
                self.reply("\n\n".join(r for r in replies if r))
        elif kind == "reply":
            if message.get("replyChunk"):
                if "processing" in self.stages:
                    # The server processed the last reply (as its CLI's spinner shows) and goes on.
                    self.stage("processing", "Processing the reply", finished=True)
                self.reply(message["replyChunk"])
        elif kind == "buildInfo":
            info = message.get("buildInfo") or {}
            path = info.get("path") or "file"
            label = ("Removing %s" if info.get("removed") else "Building %s") % path
            amounts = {"done": info["numTokens"], "unit": "tokens"} if info.get("numTokens") is not None else {}
            self.stage("build-" + path, label, finished=bool(info.get("finished")), **amounts)
            self.reply_open = False
        elif kind == "describing":
            # Plandex's server processes a reply that ended (its tasks, context, the next step).
            self.stage("processing", "Processing the reply")
            self.reply_open = False
        elif kind == "loadContext":
            files = message.get("loadContextFiles") or []
            if files:
                self.tool_call(self.next_id("context"), "Load context: %s" % ", ".join(files[:6]) + (" (+%d)" % (len(files) - 6)
                               if len(files) > 6 else ""), kind="read", status="completed",
                               locations=[{"path": os.path.join(self.workspace, f)} for f in files[:50]])
            self.reply_open = False
        elif kind == "promptMissingFile":
            path = message.get("missingFilePath")
            if path:
                self.notice("Plandex is loading %s, which the plan needs." % path)
        elif kind == "repliesFinished":
            self.stage("processing", "Processing the reply", finished=True)
        elif kind == "error":
            error = message.get("error") or {}
            self.notice("Plandex: %s" % (error.get("msg") or "the plan stopped with an error"), "error")
            return True
        elif kind in ("finished", "aborted"):
            return True
        return False

    def reply(self, text):
        # Plandex's end-of-reply tag stays out of the screen, also when a chunk ends inside it.
        text = (self.held + text).replace(FINISH, "")
        self.held = ""
        for size in range(min(len(FINISH) - 1, len(text)), 0, -1):
            if FINISH.startswith(text[-size:]):
                text, self.held = text[:-size], text[-size:]
                break
        if not text:
            return
        if not self.reply_open and self.spoke:
            text = "\n\n" + text.lstrip("\n")
        self.reply_open = True
        self.spoke = True
        self.message(text)

    def stop_plan(self, terminal):
        """A cancel: Plandex's server stops the plan (its screen then ends); the command after that."""
        try:
            plan, branch = self.plan_ids()
            self.api("DELETE", "/plans/%s/%s/stop" % (plan, branch), timeout=10)
        except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
            pass
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and terminal.process.poll() is None:
            time.sleep(0.1)
        if terminal.process.poll() is None:
            terminal.write(b"\x03")
            time.sleep(1)
        if terminal.process.poll() is None:
            terminal.stop()

    # Turns.

    def next_id(self, kind):
        with self.lock:
            self.ids += 1
            return "plandex-%s-%d" % (kind, self.ids)

    def prompt(self, text, blocks):
        while not self.ready.wait(0.2):
            if self.cancel_event.is_set():
                return "cancelled"
        if self.failure:
            raise RuntimeError(self.failure)
        with self.switch_lock:
            self.turn_open = True
            model, self.pending_model = self.pending_model, None
        try:
            if model is not None and model != self.applied:
                self.switch_to(model)
            return self.run_turn(text)
        finally:
            with self.switch_lock:
                self.turn_open = False

    def switch_to(self, model):
        """A model chosen during the last turn, taken before this turn's first command."""
        try:
            self.use_model(model)
        except (OSError, ValueError, http.client.HTTPException) as error:
            with self.switch_lock:
                if self.pending_model is None:
                    self.pending_model = model  # tried again at the next turn
            raise RuntimeError("Plandex could not switch to %s: %s" % (model, error)) from None

    def run_turn(self, text):
        self.spoke = self.reply_open = False
        self.held = ""
        text = text.strip()
        if text.startswith("/"):
            return self.command(text)
        if not text:
            return "end_turn"
        path = self.prompt_file(text)
        try:
            code, output = self.step(["chat", "--file", path] if self.mode == "chat" else
                                     ["tell", "--skip-menu", "--file", path])
        finally:
            try:
                os.remove(path)
            except OSError:
                pass
        if self.cancel_event.is_set():
            return "cancelled"
        if code:
            raise RuntimeError(last_lines(output) or "Plandex stopped (exit %s)." % code)
        if self.mode != "chat":
            return self.review()
        return "end_turn"

    @staticmethod
    def prompt_file(text):
        """The prompt in a file of its own for `--file` (private to this user): as an argument, a
        prompt that starts with '-' (a Markdown list) reads as Plandex's options, and one over
        128 KiB is more than an argument may be."""
        handle, path = tempfile.mkstemp(prefix="plandex-prompt-", suffix=".md")
        try:
            with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
                stream.write(text)
        except BaseException:
            try:
                os.remove(path)
            except OSError:
                pass
            raise
        return path

    def step(self, args):
        """A tell, chat or continue. The plan's previous stream may still be closing on the server
        (its summary): Plandex then refuses the new one, which is sent again a moment later."""
        deadline = time.monotonic() + 60
        while True:
            code, output = self.in_terminal(args)
            busy = code and "already has an active stream" in output
            if not busy or self.cancel_event.is_set() or time.monotonic() > deadline:
                if self.held:
                    # The reply ended with what only looked like the start of Plandex's end tag.
                    self.message(self.held)
                    self.held = ""
                return code, output
            time.sleep(1)

    def command(self, text):
        name, _, rest = text[1:].partition(" ")
        rest = rest.strip()
        if name == "apply":
            return self.review(ask=True, explicit=True)
        if name == "diff":
            self.review(ask=False, explicit=True)
            return "end_turn"
        if name == "continue":
            # As for tell: without --skip-menu, Plandex ends the step in its changes menu, waiting
            # for a key; the bridge offers the changes itself (review) instead.
            code, output = self.step(["continue", "--skip-menu"] + (["--chat"] if self.mode == "chat" else []))
            if self.cancel_event.is_set():
                return "cancelled"
            if code:
                raise RuntimeError(last_lines(output) or "Plandex stopped (exit %s)." % code)
            return self.review() if self.mode != "chat" else "end_turn"
        # Commands that only show something run without a terminal (Plandex pages them in one);
        # those that may ask run in one, their questions asked through the screen.
        shows = {"reject": ["reject", "--all"], "context": ["ls"], "log": ["log"], "convo": ["convo", "--plain"],
                 "summary": ["summary"]}
        asks = {"load": ["load"] + split(rest), "rewind": ["rewind"] + split(rest)}
        if name in shows:
            code, output = self.run_cli(shows[name])
        elif name in asks:
            code, output = self.in_terminal(asks[name], watch=False)
        else:
            names = ", ".join("/" + c["name"] for c in COMMANDS)
            self.notice("Plandex has no /%s here. Its commands: %s." % (name, names), "warn")
            return "end_turn"
        if self.cancel_event.is_set():
            return "cancelled"
        # The conversation as Plandex stored it carries its reply markup.
        shown = markdown(output) if name == "convo" else output.strip()
        if shown:
            self.notice(shown[-8000:], "error" if code else "info")
        return "end_turn"

    def pending(self):
        """The plan's pending changes: [(path, old, new)] and its commands (_apply.sh), if any."""
        plan, branch = self.plan_ids()
        status, raw = self.api("GET", "/plans/%s/%s/diffs?plain=true" % (plan, branch))
        if status >= 400:
            raise RuntimeError("Plandex did not give its changes (%s)." % status)
        diff = raw.decode("utf-8", errors="replace")
        paths = list(dict.fromkeys(re.findall(r"^diff --git a/(.+?) b/", diff, re.M)))
        status, raw = self.api("GET", "/plans/%s/%s/current_plan" % (plan, branch))
        if status >= 400:
            raise RuntimeError("Plandex did not give its plan (%s)." % status)
        state = json.loads(raw or b"{}")
        files = (state.get("currentPlanFiles") or {}).get("files") or {}
        removed = (state.get("currentPlanFiles") or {}).get("removedByPath") or {}
        script = files.get("_apply.sh") or ""
        changes = []
        for path in paths:
            if path == "_apply.sh":
                continue
            absolute = os.path.join(self.workspace, path)
            old = support.read_text(absolute) if os.path.exists(absolute) else None
            new = "" if removed.get(path) else files.get(path)
            if new is None or new == old:
                continue
            changes.append((absolute, old, new))
        return changes, script

    def review(self, ask=True, explicit=False):
        """The plan's pending changes as diffs, applied only if the person says so."""
        try:
            changes, script = self.pending()
        except (OSError, ValueError, KeyError, TypeError, RuntimeError, http.client.HTTPException) as error:
            self.notice("Plandex's pending changes could not be read: %s" % error, "warn")
            return "end_turn"
        if not changes and not script.strip():
            if explicit:
                self.notice("Plandex has no pending changes.")
            return "end_turn"
        tool = self.next_id("changes")
        content = [self.diff(path, old, new) for path, old, new in changes]
        if script.strip():
            content.append(self.text("Plandex's commands (_apply.sh):\n```bash\n%s\n```" % script.strip()))
        count = len(changes)
        files = "%d file%s" % (count, "" if count == 1 else "s")
        locations = [{"path": path} for path, _, _ in changes] or None
        if not ask:
            # Shown only: they stay pending.
            self.tool_call(tool, "Plandex's pending changes (%s, not applied)" % (files if count else "commands only"),
                           kind="read", status="completed", content=content, locations=locations)
            return "end_turn"
        title = "Apply Plandex's changes to %s" % files if count else "Run Plandex's commands"
        self.tool_call(tool, title, kind="edit", status="pending", content=content, locations=locations)
        options = [{"optionId": "apply", "name": "Apply" + (" without running its commands" if script.strip() else ""),
                    "kind": "allow_once"}]
        if script.strip():
            options.append({"optionId": "apply-run", "name": "Apply and run its commands", "kind": "allow_once"})
        options += [{"optionId": "later", "name": "Not now (keep them pending)", "kind": "reject_once"},
                    {"optionId": "reject", "name": "Reject the changes", "kind": "reject_always"}]
        try:
            choice = self.ask_permission(tool, title + "?", options=options)
        except Cancelled:
            self.tool_update(tool, status="failed")
            return "cancelled"
        except (ConnectionError, RuntimeError, TimeoutError):
            choice = None
        if choice in ("apply", "apply-run"):
            self.tool_update(tool, status="in_progress")
            code, output = self.in_terminal(["apply", "--auto-exec" if choice == "apply-run" else "--no-exec"])
            shown = last_lines(output, 30)
            self.tool_update(tool, status="failed" if code or self.cancel_event.is_set() else "completed",
                             content=content + ([self.text(shown)] if shown else []))
            if self.cancel_event.is_set():
                return "cancelled"
            if code:
                raise RuntimeError(last_lines(output) or "Plandex could not apply the changes (exit %s)." % code)
        elif choice == "reject":
            code, output = self.run_cli(["reject", "--all"])
            self.tool_update(tool, status="failed", title=title + " (rejected)",
                             content=content + [self.text(output.strip()[-2000:] or "Rejected.")])
        else:
            self.tool_update(tool, status="failed", title=title + " (kept pending)",
                             content=content + [self.text("Kept pending: /apply applies them, /reject rejects them.")])
        return "end_turn"

    # Models, modes, cancel, end.

    def set_model(self, model):
        """Another of this inference's models. Plandex's server keeps the model a step started with
        for the whole step, and the proxy serves only the model it is on: a switch during a turn
        (or while Plandex starts) is taken at the start of the next turn; otherwise now."""
        with self.switch_lock:
            if self.turn_open or not self.ready.is_set():
                self.pending_model = model
                if self.turn_open and model != self.applied:
                    self.notice("Plandex finishes this step on %s; your next message uses %s." % (self.applied, model))
            else:
                self.pending_model = None
                if model != self.applied:
                    self.use_model(model)
            self.model = model

    def use_model(self, model):
        """Plandex's model pack and its model proxy on `model`."""
        if self.auth is not None:
            self.custom_models(model)
        if self.proxy is not None:
            self.proxy.model = model
        self.applied = model

    def set_mode(self, mode):
        if mode not in ("tell", "chat"):
            raise ValueError("Plandex has no %s mode." % mode)
        self.mode = mode

    def cancelled(self):
        terminal = self.terminal
        if terminal is not None:
            threading.Thread(target=self.stop_plan, args=(terminal,), daemon=True).start()

    def closing(self):
        self.cancelled()


def markdown(text):
    """Plandex's own reply markup as the screen shows it: <PlandexBlock> as a fenced code block (as
    Plandex's server does when it streams), its end-of-reply tag left out."""
    text = re.sub(r'<PlandexBlock\s+lang="([^"]*)"[^>]*>\n?', lambda m: "```%s\n" % m.group(1), text)
    text = text.replace("</PlandexBlock>", "```")
    return text.replace("<PlandexFinish/>", "").strip()


def split(text):
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def last_lines(text, count=12):
    lines = [line.rstrip() for line in (text or "").splitlines() if line.strip()]
    return "\n".join(lines[-count:])


def main(argv=None):
    args = support.arguments(sys.argv[1:] if argv is None else argv, "Plandex over ACP for the Yougori harness.")
    stdin = support.prepare()
    bridge = PlandexBridge(args, stdin)
    support.on_exit(bridge.stop_services)
    support.serve(bridge)


if __name__ == "__main__":
    main()
