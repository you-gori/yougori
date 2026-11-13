"""Switching harness from the Yougori harness's screen (/harness): the guest taking the screen's
request with the session's token and passing it to the launcher once; the launcher bringing the
next harness's pack into the running VM in its place, or ending the session for a new VM; the run
going on in that new VM; the list of harnesses a session may switch to; and runtime.py's switch
command, which the screen runs.

Run: python -I -B examples/hub/inference-solver/tests/test_harness_switch.py
"""
import base64
import contextlib
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

SITE = Path(__file__).resolve().parents[1] / "site"
sys.path.insert(0, str(SITE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.append(str(SITE / "harnesses"))
for linux_only in ("fcntl", "pty", "termios"):
    sys.modules.setdefault(linux_only, types.ModuleType(linux_only))
import harness_download  # noqa: E402
import runtime  # noqa: E402
import vm_guest  # noqa: E402
import vm_host  # noqa: E402
from test_yougori_launch import KILO, OPENCODE, PLANDEX, VERSION, Website, listing, pack_archive, sha  # noqa: E402

STRIX = pack_archive("strix")
SECRET = "correct horse battery staple"


def bad_pack():
    """A pack whose entry leaves its two roots: the VM refuses it after the pack before is gone."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        info = tarfile.TarInfo("elsewhere/app")
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    return stream.getvalue()


def images():
    """The Yougori harness's images with a security harness's pack beside the coding ones."""
    value = listing()
    value["packs"]["strix"] = {"sha256": sha(STRIX), "bytes": len(STRIX), "version": VERSION["strix"]["version"],
                               "base": "base", "disk": 2, "memory": 6}
    return value


TARGET = {"id": "target", "type": "target", "question": "What should it test?", "required": True}


def harnesses():
    """The website's harnesses as GET /api/harnesses lists them."""
    def item(ident, category="coding", available=True, reason="", **more):
        held = {"available": available, **({"reason": reason} if reason else {})}
        return {"id": ident, "name": ident.title(), "category": category, "description": ident + " works here.",
                "held": held, "questions": [], **more}
    return {"harnesses": [item("strix", "security", questions=[TARGET]), item("opencode"),
                          item("kilo", available=False, reason="The administrator has not published it yet."),
                          item("yougori", name="Yougori"), item("plandex"), item("aider"), item("pi", offered=False),
                          item("unknown-harness")]}


class Site(Website):
    """The website: its harness list beside the Yougori harness's image routes."""

    def do_GET(self):
        if self.path == "/api/harnesses":
            body = json.dumps(self.server.catalog).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


KNOWN = {"yougori", "opencode", "kilo", "plandex", "strix", "aider", "pi"}


class Fixture(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.folder = Path(folder.name)
        self.site = ThreadingHTTPServer(("127.0.0.1", 0), Site)
        self.site.lock, self.site.requests, self.site.listing = threading.Lock(), [], images()
        self.site.files = {sha(raw): raw for raw in (OPENCODE, KILO, PLANDEX, STRIX)}
        self.site.barrier, self.site.slow, self.site.catalog = None, False, harnesses()
        threading.Thread(target=self.site.serve_forever, daemon=True).start()
        self.addCleanup(self.site.server_close)
        self.addCleanup(self.site.shutdown)
        self.url = "http://127.0.0.1:%d" % self.site.server_port
        self.host = self.folder / "host"
        (self.host / "tools").mkdir(parents=True)
        (self.host / "tools" / (sha(OPENCODE) + ".tar.gz")).write_bytes(OPENCODE)

    def entries(self):
        fields = vm_host.switch_list(self.url, "opencode", 4, KNOWN)
        return {entry["id"]: entry for entry in fields["harnesses"]}

    def guest(self):
        """The VM's guest on the Yougori harness's base, holding OpenCode's pack, in a session whose
        screen may switch to the session's list."""
        root = self.folder / "vm"
        (root / "home").mkdir(parents=True)
        (root / "harness-name").write_text("yougori\n")
        state = vm_guest.State(root, root / "home")
        server = ThreadingHTTPServer(("127.0.0.1", 0), vm_guest.Control)
        server.state = state
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        control = vm_host.Control("http://abc123.localhost:%d/" % server.server_port)
        with contextlib.redirect_stdout(io.StringIO()):
            vm_host.prepare_tool(control, self.host, {"harness": "opencode", "sha256": sha(OPENCODE), "bytes": len(OPENCODE)})
        state.started = True
        state.switchable = {"yougori", "opencode", "kilo", "plandex", "strix"}
        self.state, self.root, self.control = state, root, control
        self.vm_url = "http://127.0.0.1:%d" % server.server_port
        return state

    def ask(self, path, data, token=None):
        """A request from inside the VM, as runtime.py's switch command makes it."""
        with patch.object(runtime, "GUEST", self.vm_url):
            return runtime.guest(path, data, self.state.token if token is None else token)

    def take(self):
        """The switch request the launcher gets from /poll."""
        for _ in range(20):
            packet = self.control.post("/poll", {})
            if "switch" in packet:
                return packet["switch"]
        self.fail("no switch request reached the launcher")


class Guest(Fixture):
    def test_only_the_screen_asks_and_one_switch_at_a_time(self):
        self.guest()
        request = {"harness": "kilo", "model": "m", "answers": {}, "mode": "in-place"}
        for token in ("", "wrong"):
            with self.assertRaisesRegex(ValueError, "needs the screen's own request"):
                self.ask("/switch", request, token)
        for bad in ({**request, "harness": "aider"}, {**request, "mode": "elsewhere"}, {**request, "model": ""},
                    {**request, "secrets": {"login_password": SECRET}}, {**request, "targets": ["a.example:443"]},
                    {**request, "answers": {"Bad Id": 1}}, {**request, "mode": "new-vm", "targets": ["A B"]}):
            with self.assertRaisesRegex(ValueError, "Invalid harness switch"):
                self.ask("/switch", bad)
        identity = self.ask("/switch", request)["id"]
        with self.assertRaisesRegex(ValueError, "Another harness switch is under way"):
            self.ask("/switch", {**request, "harness": "plandex"})
        self.assertEqual(self.ask("/switch/status", {"id": identity})["state"], "waiting")
        with self.assertRaisesRegex(ValueError, "No such harness switch"):
            self.ask("/switch/status", {"id": "0" * 32})
        # The launcher gets it once, with nothing secret.
        taken = self.take()
        self.assertEqual(taken, {"id": identity, "harness": "kilo", "model": "m", "answers": {}, "mode": "in-place"})
        self.assertNotIn("switch", self.control.post("/poll", {}))
        self.assertEqual(self.ask("/switch/status", {"id": identity})["state"], "working")

    def test_a_new_vm_request_takes_its_secrets_to_the_launcher_once(self):
        self.guest()
        request = {"harness": "strix", "model": "m", "answers": {"target": "staging.example.com:443", "permission": True},
                   "mode": "new-vm", "targets": ["staging.example.com:443"], "secrets": {"login_password": SECRET}, "memory": 6}
        self.ask("/switch", request)
        taken = self.take()
        self.assertEqual((taken["secrets"], taken["targets"], taken["memory"]), ({"login_password": SECRET}, ["staging.example.com:443"], 6))
        self.assertNotIn("secrets", self.state.switch)
        self.assertNotIn(SECRET, json.dumps(self.state.switch))

    def test_the_session_tells_the_screen_what_it_may_switch_to(self):
        state = self.guest()
        fields = vm_host.switch_list(self.url, "opencode", 4, KNOWN)
        data = {"harness": "opencode", "answers": {}, "secrets": {}, "reach": {"mode": "inference", "sites": [], "targets": []}, **fields}
        environment = {}
        self.assertEqual(state.command(data, environment), ["run", "yougori"])
        self.assertEqual(environment[vm_guest.SWITCH_TOKEN], state.token)
        written = json.loads((self.root / "home/.yougori/session.json").read_text())
        self.assertEqual(written, fields)
        self.assertEqual(state.switchable, {"yougori", "opencode", "kilo", "plandex", "strix"})
        # runtime.py puts them, with the switch command, in every spec it writes.
        spec = runtime.with_session({"harness": "opencode"}, self.root / "home")
        self.assertEqual(spec["switch"], ["python3", "/opt/solver/runtime.py", "switch"])
        self.assertEqual((spec["vm_base"], spec["vm_memory"], spec["server"]), ("base", 4, self.url))
        # A launcher that tells nothing: no token, no list, and the spec says nothing of switching.
        environment = {}
        state.command({"harness": "opencode"}, environment)
        self.assertNotIn(vm_guest.SWITCH_TOKEN, environment)
        self.assertFalse((self.root / "home/.yougori/session.json").exists())
        self.assertNotIn("switch", runtime.with_session({}, self.root / "home"))
        for bad in ({**fields, "harnesses": []}, {**fields, "vm_base": "Bad Base"}, {**fields, "server": "ftp://x"},
                    {**fields, "harnesses": fields["harnesses"] * 2}, {**fields, "vm_memory": 0}):
            with self.assertRaises(vm_guest.Refusal):
                state.command({**data, **bad}, {})


class InPlace(Fixture):
    def begin(self, harness, **more):
        identity = self.ask("/switch", {"harness": harness, "model": "m", "answers": {}, "mode": "in-place", **more})["id"]
        return identity, self.take()

    def switch(self, request, entries=None):
        vm_host.switch_in_place(self.control, request, entries or self.entries(), "base", self.url, self.host)

    def test_the_next_pack_takes_the_place_of_the_one_before(self):
        self.guest()
        seen = []
        original = self.control.post

        def post(path, data):
            if path == "/switch/progress":
                seen.append(data["text"])
            return original(path, data)
        self.control.post = post
        self.site.listing["packs"]["kilo"]["version"] = VERSION["kilo"]["version"]
        entries = self.entries()
        entries["kilo"]["ready"] = True
        identity, request = self.begin("kilo")
        self.switch(request, entries)
        self.assertEqual(self.ask("/switch/status", {"id": identity}), {"state": "done", "progress": seen[-1], "reason": ""})
        self.assertEqual((self.root / "tool/bin/app").read_bytes(), b"kilo")
        self.assertEqual(self.state.package.status()["harness"], "kilo")
        self.assertTrue(any(text.startswith("Downloading Kilo") for text in seen), seen)
        self.assertTrue(any(text.startswith("Installing Kilo: 100%") for text in seen), seen)
        # Back to the harness before: its pack comes again, in place of this one.
        identity, request = self.begin("opencode")
        self.switch(request, entries)
        self.assertEqual(self.ask("/switch/status", {"id": identity})["state"], "done")
        self.assertEqual((self.root / "tool/bin/app").read_bytes(), b"opencode")

    def test_a_refusal_before_the_pack_is_replaced_keeps_the_harness_before(self):
        self.guest()
        for harness, said in (("kilo", "The administrator has not published it yet."),
                              ("plandex", "Plandex needs a new VM. Choose it again in /harness to start one.")):
            identity, request = self.begin(harness)
            self.switch(request)
            status = self.ask("/switch/status", {"id": identity})
            self.assertEqual((status["state"], status["reason"], status["kept"]), ("failed", said, True))
            self.assertEqual((self.root / "tool/bin/app").read_bytes(), b"opencode")

    def test_a_pack_the_vm_refuses_leaves_no_harness_before(self):
        self.guest()
        broken = bad_pack()
        self.site.files[sha(broken)] = broken
        self.site.listing["packs"]["kilo"].update(sha256=sha(broken), bytes=len(broken))
        entries = self.entries()
        entries["kilo"]["ready"] = True
        identity, request = self.begin("kilo")
        self.switch(request, entries)
        status = self.ask("/switch/status", {"id": identity})
        self.assertEqual((status["state"], status["kept"]), ("failed", False))
        self.assertIn("could not be installed", status["reason"])
        self.assertFalse((self.root / "tool").exists())

    def test_the_screen_cancels_before_and_while_the_launcher_works(self):
        self.guest()
        identity = self.ask("/switch", {"harness": "strix", "model": "m", "answers": {}, "mode": "in-place"})["id"]
        self.ask("/switch/cancel", {"id": identity})
        self.assertEqual(self.ask("/switch/status", {"id": identity}), {"state": "failed", "progress": "", "reason": "Cancelled.", "kept": True})
        self.assertNotIn("switch", self.control.post("/poll", {}))
        identity, request = self.begin("strix")
        self.ask("/switch/cancel", {"id": identity})
        self.switch(request)
        status = self.ask("/switch/status", {"id": identity})
        self.assertEqual((status["state"], status["reason"], status["kept"]), ("failed", "Cancelled.", True))
        # Its pack is refused once cancelled, and the session's end ends any switch.
        self.assertEqual((self.root / "tool/bin/app").read_bytes(), b"opencode")
        self.ask("/switch", {"harness": "strix", "model": "m", "answers": {}, "mode": "in-place"})
        self.state.switch_end()
        self.assertEqual(self.state.switch["state"], "failed")


class NewVm(Fixture):
    def test_a_new_vm_is_accepted_with_what_it_needs(self):
        self.guest()
        request = {"harness": "strix", "model": "m", "answers": {"target": "staging.example.com:443", "permission": True},
                   "mode": "new-vm", "targets": ["staging.example.com:443"], "secrets": {"login_password": SECRET}}
        identity = self.ask("/switch", request)["id"]
        taken = self.take()
        relaunch = vm_host.take_switch(self.control, taken, self.entries(), "base", 4, self.url, self.host)
        self.assertIsInstance(relaunch, vm_host.Relaunch)
        self.assertEqual({key: relaunch.request[key] for key in ("harness", "name", "category", "memory", "targets", "secrets")},
                         {"harness": "strix", "name": "Strix", "category": "security", "memory": 6,
                          "targets": ["staging.example.com:443"], "secrets": {"login_password": SECRET}})
        self.assertEqual(self.ask("/switch/status", {"id": identity})["state"], "accepted")
        # One the session does not offer is refused, and nothing is relaunched.
        self.state.switch = None
        identity = self.ask("/switch", {**request, "harness": "kilo", "targets": [], "secrets": {}})["id"]
        self.assertIsNone(vm_host.take_switch(self.control, self.take(), self.entries(), "base", 4, self.url, self.host))
        status = self.ask("/switch/status", {"id": identity})
        self.assertEqual((status["state"], status["reason"]), ("failed", "The administrator has not published it yet."))


class List(Fixture):
    def test_the_list_holds_what_starts_here_yougori_first(self):
        fields = vm_host.switch_list(self.url, "opencode", 4, KNOWN)
        self.assertEqual((fields["vm_base"], fields["vm_memory"], fields["server"]), ("base", 4, self.url))
        listed = {entry["id"]: entry for entry in fields["harnesses"]}
        # Offered, known here and with a pack; Yougori first, then coding, then security.
        self.assertEqual([entry["id"] for entry in fields["harnesses"]], ["yougori", "opencode", "kilo", "plandex", "strix"])
        self.assertEqual((listed["kilo"]["ready"], listed["kilo"]["reason"]), (False, "The administrator has not published it yet."))
        self.assertEqual((listed["plandex"]["base"], listed["plandex"]["memory"]), ("postgres", 5))
        self.assertEqual((listed["strix"]["category"], listed["strix"]["memory"], listed["strix"]["questions"]), ("security", 6, [TARGET]))
        self.assertEqual(listed["opencode"]["description"], "opencode works here.")

    def test_no_list_without_yougori_or_a_website_that_answers(self):
        self.site.catalog = {"harnesses": [item for item in harnesses()["harnesses"] if item["id"] != "yougori"]}
        self.assertEqual(vm_host.switch_list(self.url, "opencode", 4, KNOWN), {})
        self.site.catalog = harnesses()
        self.assertEqual(vm_host.switch_list("http://127.0.0.1:9", "opencode", 4, KNOWN), {})
        self.site.listing = b"not json"
        self.assertEqual(vm_host.switch_list(self.url, "opencode", 4, KNOWN), {})


class Session(unittest.TestCase):
    """run_session: the run going on in each new VM its screen switches to."""

    def run_session(self, results, ask=lambda question: "y", interactive=True, **keywords):
        calls = []

        def launch(name, server, key_file, model, workspace, arguments, interactive=True, **options):
            calls.append({"name": name, **options})
            options["reviews"].append("yougori sandbox review exe-" + str(len(calls)) * 32)
            return results[len(calls) - 1]
        printed = io.StringIO()
        with patch.object(vm_host, "launch", launch), patch.object(sys.stdin, "isatty", lambda: True), contextlib.redirect_stdout(printed):
            code = vm_host.run_session("opencode", "https://argon.example", Path("key"), "m", Path("folder"), interactive,
                                       cpu=2, memory=None, internet=True, answers={}, secrets={}, known=KNOWN, ask=ask, **keywords)
        return code, calls, printed.getvalue()

    def relaunch(self, harness, category="coding", memory=4, **more):
        return vm_host.Relaunch({"harness": harness, "name": harness.title(), "category": category, "memory": memory,
                                 "answers": {"issue": "x"}, "model": "m", **more})

    def test_a_coding_harness_goes_on_in_a_new_vm_with_the_runs_reach(self):
        code, calls, printed = self.run_session([self.relaunch("plandex", memory=5), 0])
        self.assertEqual(code, 0)
        self.assertEqual([call["name"] for call in calls], ["opencode", "plandex"])
        second = calls[1]
        self.assertEqual((second["harness"], second["answers"], second["memory"], second["internet"], second["cpu"]),
                         ("plandex", {"issue": "x"}, 5, True, 2))
        self.assertIn("Starting Plandex in a new VM...", printed)
        # Every VM's copy is named at the end, once.
        self.assertTrue(printed.rstrip().endswith("exe-" + "1" * 32 + "\nyougori sandbox review exe-" + "2" * 32), printed)
        self.assertEqual(printed.count("Review the VM copies with:"), 1)

    def test_a_security_harness_asks_this_terminal_for_wider_targets(self):
        target = ["staging.example.com:443"]
        asked = []
        code, calls, _ = self.run_session([self.relaunch("strix", "security", 6, targets=target, secrets={"login_password": SECRET}), 0],
                                          ask=lambda question: asked.append(question) or "yes")
        self.assertEqual(len(asked), 1)
        self.assertIn("Start Strix in a new VM that reaches only staging.example.com:443 and this inference? [y/N]", asked[0])
        second = calls[1]
        self.assertEqual((second["targets"], second["internet"], second["sites"], second["secrets"], second["memory"]),
                         (target, False, None, {"login_password": SECRET}, 6))
        # A no, or no terminal to ask: nothing more starts.
        code, calls, printed = self.run_session([self.relaunch("strix", "security", targets=target), 0], ask=lambda question: "n")
        self.assertEqual((code, len(calls)), (0, 1))
        self.assertIn("Nothing more was started.", printed)
        code, calls, printed = self.run_session([self.relaunch("strix", "security", targets=target), 0], interactive=False)
        self.assertEqual((code, len(calls)), (0, 1))
        self.assertIn("only the person at this terminal can allow that", printed)
        # Targets the run already held, or the practice app: nothing to ask.
        code, calls, _ = self.run_session([self.relaunch("strix", "security", targets=target), 0], targets=target,
                                          ask=lambda question: self.fail("asked again"))
        self.assertEqual(len(calls), 2)
        code, calls, _ = self.run_session([self.relaunch("strix", "security"), 0], ask=lambda question: self.fail("asked"))
        self.assertEqual((calls[1]["targets"], calls[1]["internet"]), (None, False))


class Unreachable(unittest.TestCase):
    """A control request whose connection never opened is asked again; nothing else is."""

    def test_a_request_that_never_reached_the_vm_goes_again(self):
        tries = []

        def post(path, data):
            tries.append(path)
            if len(tries) < 3:
                raise vm_host.Unreached("timed out")
            return {"ok": True}
        with patch.object(vm_host.time, "sleep", lambda seconds: None):
            self.assertEqual(vm_host.again(post, "/poll", {}), {"ok": True})
        self.assertEqual(tries, ["/poll"] * 3)
        # Not past its time, nor once the session is done, nor for any other failure.
        def never(path, data):
            raise vm_host.Unreached("timed out")
        with patch.object(vm_host.time, "sleep", lambda seconds: None), self.assertRaises(vm_host.Unreached):
            vm_host.again(never, "/poll", {}, seconds=0)
        done = threading.Event()
        done.set()
        with patch.object(vm_host.time, "sleep", lambda seconds: None), self.assertRaises(vm_host.Unreached):
            vm_host.again(never, "/input", {}, done)

        def lost(path, data):
            tries.append(path)
            raise ConnectionResetError("reset after it was sent")
        with self.assertRaises(ConnectionResetError):
            vm_host.again(lost, "/input", {})

    def test_a_publication_that_takes_no_connection_is_unreached(self):
        listener = __import__("socket").socket()
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()
        with self.assertRaises(vm_host.Unreached):
            vm_host.Control("http://abc123.localhost:%d/" % port).post("/poll", {})


class GuestThatSwitches(BaseHTTPRequestHandler):
    """A guest whose screen asks for a new VM, then exits 75 once the launcher accepted it."""

    def log_message(self, *_):
        pass

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        server = self.server
        server.paths.append(self.path)
        if self.path == "/start":
            server.started = data
            reply = {"started": True, "tunnels": True, "yougori": True}
        elif self.path == "/switch/accepted":
            server.accepted = True
            reply = {"cancelled": False}
        elif self.path == "/poll":
            if not server.asked:
                server.asked = True
                reply = {"output": "", "requests": [], "tunnels": [], "exit": None, "switch": server.request}
            else:
                reply = {"output": "", "requests": [], "tunnels": [], "exit": 75 if server.accepted else 0}
        else:
            reply = {}
        raw = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Launch(Fixture):
    """launch(): the list at /start, and the session ending for a new VM."""

    def test_the_session_ends_for_a_new_vm_and_says_so(self):
        guest = ThreadingHTTPServer(("127.0.0.1", 0), GuestThatSwitches)
        guest.paths, guest.asked, guest.accepted = [], False, False
        guest.request = {"id": "a" * 32, "harness": "plandex", "model": "m", "answers": {}, "mode": "new-vm", "targets": [],
                         "secrets": {}}
        threading.Thread(target=guest.serve_forever, daemon=True).start()
        self.addCleanup(guest.server_close)
        self.addCleanup(guest.shutdown)
        key_file = self.folder / "opencode" / "api-key"
        key_file.parent.mkdir()
        key_file.write_text("is_test-key")

        def call(action, **params):
            if action == "launch":
                return {"sandbox": "exe-" + "a" * 32}
            if action == "publish":
                return {"url": "http://abc123.localhost:%d/" % guest.server_port}
            return {}
        reviews = []
        with patch.object(vm_host, "install_yougori", lambda held, server, root: ("sha256:" + "d" * 64, {"harness": held}, 4)), \
                patch.object(vm_host, "call", call), patch.object(vm_host, "tidy", lambda sandbox, folder: True), \
                patch.object(vm_host, "prepare_tool", lambda *given, **options: None), contextlib.redirect_stdout(io.StringIO()):
            result = vm_host.launch("opencode", self.url, key_file, "m", self.folder, [], False, harness="opencode", answers={},
                                    secrets={}, images=self.host, known=KNOWN, reviews=reviews)
        self.assertIsInstance(result, vm_host.Relaunch)
        self.assertEqual((result.request["harness"], result.request["name"], result.request["memory"]), ("plandex", "Plandex", 5))
        # The screen had the list; the VM's copy is kept for review, named at the run's end.
        self.assertEqual([entry["id"] for entry in guest.started["harnesses"]], ["yougori", "opencode", "kilo", "plandex", "strix"])
        self.assertEqual((guest.started["vm_base"], guest.started["vm_memory"]), ("base", 4))
        self.assertEqual(reviews, ["yougori sandbox review exe-" + "a" * 32])


class FakeGuest(BaseHTTPRequestHandler):
    """The guest as the switch command sees it: the token checked, then the statuses in turn."""

    def log_message(self, *_):
        pass

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        server = self.server
        server.asked.append((self.path, data))
        if self.headers.get("X-Yougori-Switch") != "token":
            status, reply = 403, {"error": "Switching harness needs the screen's own request."}
        elif self.path == "/switch":
            status, reply = 200, {"id": "s" * 32}
        elif self.path == "/switch/cancel":
            server.cancelled = True
            status, reply = 200, {"state": "working"}
        else:
            status = 200
            reply = server.statuses.pop(0) if len(server.statuses) > 1 else server.statuses[0]
            if server.cancelled and server.after_cancel:
                reply = server.after_cancel
        raw = json.dumps(reply).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Command(unittest.TestCase):
    """runtime.py switch, as the screen runs it."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.home = Path(folder.name)
        (self.home / ".yougori").mkdir()
        self.fields = {"harnesses": [{"id": "yougori"}, {"id": "kilo"}], "vm_base": "base", "vm_memory": 4, "server": "https://a.example"}
        (self.home / ".yougori/session.json").write_text(json.dumps(self.fields))
        self.guest = ThreadingHTTPServer(("127.0.0.1", 0), FakeGuest)
        self.guest.asked, self.guest.cancelled, self.guest.after_cancel = [], False, None
        threading.Thread(target=self.guest.serve_forever, daemon=True).start()
        self.addCleanup(self.guest.server_close)
        self.addCleanup(self.guest.shutdown)

    def run_switch(self, request, statuses=(), token="token", cancel=None):
        self.guest.statuses = list(statuses) or [{"state": "waiting"}]
        stdout, stderr = io.StringIO(), io.StringIO()
        cancelled = threading.Event()
        if cancel is not None:
            threading.Timer(cancel, cancelled.set).start()
        headless = lambda harness, model, catalog, root, answers=None, cwd=None, reach=None: {"harness": harness, "model": model,
                                                                                              "answers": dict(answers or {})}
        environment = {"YOUGORI_SWITCH_TOKEN": token} if token else {}
        with patch.object(runtime, "GUEST", "http://127.0.0.1:%d" % self.guest.server_port), patch.object(runtime, "headless", headless), \
                patch.object(runtime, "wait_for_catalog", lambda: []), patch.object(runtime, "HOME", str(self.home)), \
                patch.dict(os.environ, environment, clear=False), contextlib.redirect_stderr(stderr):
            if not token:
                os.environ.pop("YOUGORI_SWITCH_TOKEN", None)
            code = runtime.switch(self.home, io.StringIO(json.dumps(request)), stdout, poll=0.01, cancelled=cancelled)
        said = [json.loads(line) for line in stderr.getvalue().splitlines()]
        return code, stdout.getvalue(), said

    def test_in_place_it_prints_the_next_harnesss_spec(self):
        request = {"harness": "kilo", "model": "m", "answers": {"issue": "x"}, "mode": "in-place"}
        statuses = [{"state": "working", "progress": "Downloading Kilo: 10%"}, {"state": "working", "progress": "Installing Kilo: 100%"},
                    {"state": "done", "progress": "Installing Kilo: 100%"}]
        code, printed, said = self.run_switch(request, statuses)
        self.assertEqual(code, 0)
        spec = json.loads(printed)
        self.assertEqual((spec["harness"], spec["answers"], spec["switch"], spec["harnesses"]),
                         ("kilo", {"issue": "x"}, runtime.SWITCH, self.fields["harnesses"]))
        self.assertEqual(said, [{"progress": "Downloading Kilo: 10%"}, {"progress": "Installing Kilo: 100%"}])
        self.assertEqual(json.loads((self.home / ".yougori/answers.json").read_text()), {"issue": "x"})
        self.assertEqual(json.loads((self.home / ".yougori/engine.json").read_text())["harness"], "kilo")
        self.assertEqual(self.guest.asked[0], ("/switch", request))

    def test_a_new_vm_is_said_once_accepted(self):
        request = {"harness": "kilo", "model": "m", "answers": {}, "mode": "new-vm", "secrets": {"login_password": SECRET}}
        code, printed, _ = self.run_switch(request, [{"state": "working"}, {"state": "accepted"}])
        self.assertEqual((code, json.loads(printed)), (0, {"new_vm": True}))

    def test_a_failure_says_why_and_whether_the_harness_before_is_kept(self):
        request = {"harness": "kilo", "model": "m", "answers": {}, "mode": "in-place"}
        code, printed, said = self.run_switch(request, [{"state": "failed", "reason": "Not published.", "kept": False}])
        self.assertEqual((code, printed, said[-1]), (1, "", {"error": "Not published.", "kept": False}))
        code, _, said = self.run_switch(request, token="wrong")
        self.assertEqual((code, said[-1]), (1, {"error": "Switching harness needs the screen's own request.", "kept": True}))

    def test_esc_cancels_and_the_guest_says_what_is_kept(self):
        self.guest.after_cancel = {"state": "failed", "reason": "Cancelled.", "kept": False}
        request = {"harness": "kilo", "model": "m", "answers": {}, "mode": "in-place"}
        code, printed, said = self.run_switch(request, [{"state": "working"}], cancel=0.1)
        self.assertEqual((code, printed, said[-1]), (130, "", {"error": "Cancelled.", "kept": False}))
        self.assertTrue(self.guest.cancelled)

    def test_yougori_needs_no_guest_and_an_older_session_says_update(self):
        self.guest.shutdown()
        code, printed, _ = self.run_switch({"harness": "yougori", "model": "m", "answers": {"x": 1}, "mode": "in-place"})
        self.assertEqual((code, json.loads(printed)["harness"], json.loads(printed)["answers"]), (0, "yougori", {}))
        code, _, said = self.run_switch({"harness": "kilo", "model": "m", "mode": "in-place"}, token=None)
        self.assertEqual((code, said[-1]), (1, {"error": runtime.OLDER, "kept": True}))
        (self.home / ".yougori/session.json").unlink()
        code, _, said = self.run_switch({"harness": "kilo", "model": "m", "mode": "in-place"})
        self.assertEqual((code, said[-1]), (1, {"error": runtime.OLDER, "kept": True}))

    def test_an_address_starts_nothing_without_the_permission_yes(self):
        request = {"harness": "strix", "model": "m", "answers": {"target": "staging.example.com:443"}, "mode": "new-vm"}
        code, _, said = self.run_switch(request)
        self.assertEqual((code, said[-1]["error"]), (1, runtime.PERMISSION_REFUSAL))
        self.assertEqual(self.guest.asked, [])
        code, _, said = self.run_switch({**request, "answers": {"target": "practice"}, "mode": "in-place"}, [{"state": "done"}])
        self.assertEqual(code, 0)

    def test_a_request_it_cannot_read_is_refused(self):
        for request in ({}, {"harness": "kilo"}, {"harness": "kilo", "model": "m", "mode": "sideways"}, [1]):
            code, _, said = self.run_switch(request)
            self.assertEqual((code, said[-1]), (1, {"error": "The harness switch was not understood.", "kept": True}))


if __name__ == "__main__":
    unittest.main()
