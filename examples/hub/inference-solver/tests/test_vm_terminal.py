"""The person's terminal around a harness's VM: the keys a Windows console gives (msvcrt) reach the
VM as an xterm sends them, Shift+Tab and Ctrl+C included; a session that ends under its program
leaves the terminal as it was; the cleanup after it finishes whatever the keyboard does; the VM's
programs are told what colours the terminal shows.

Run: python -I -B examples/hub/inference-solver/tests/test_vm_terminal.py
"""
import base64
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest.mock import patch

HARNESSES = Path(__file__).resolve().parents[1] / "site/harnesses"
sys.path.insert(0, str(HARNESSES))
# vm_guest runs in the Linux VM; its terminal modules are not needed for what these tests check.
for linux_only in ("fcntl", "pty", "termios"):
    sys.modules.setdefault(linux_only, types.ModuleType(linux_only))
import vm_guest
import vm_host

# What msvcrt.getwch gives after "\x00" or "\xe0" for each key, and what an xterm sends for it.
KEYS = {
    "PageUp": ("I", "\x1b[5~"), "PageDown": ("Q", "\x1b[6~"), "Insert": ("R", "\x1b[2~"), "Delete": ("S", "\x1b[3~"),
    "Home": ("G", "\x1b[H"), "End": ("O", "\x1b[F"), "Up": ("H", "\x1b[A"), "Down": ("P", "\x1b[B"),
    "Right": ("M", "\x1b[C"), "Left": ("K", "\x1b[D"),
    "Ctrl+Up": ("\x8d", "\x1b[1;5A"), "Ctrl+Down": ("\x91", "\x1b[1;5B"), "Ctrl+Right": ("t", "\x1b[1;5C"),
    "Ctrl+Left": ("s", "\x1b[1;5D"), "Ctrl+Home": ("w", "\x1b[1;5H"), "Ctrl+End": ("u", "\x1b[1;5F"),
    "Ctrl+PageUp": ("\x84", "\x1b[5;5~"), "Ctrl+PageDown": ("v", "\x1b[6;5~"), "Ctrl+Insert": ("\x92", "\x1b[2;5~"),
    "Ctrl+Delete": ("\x93", "\x1b[3;5~"), "Alt+Up": ("\x98", "\x1b[1;3A"), "Alt+Left": ("\x9b", "\x1b[1;3D"),
    "Alt+Home": ("\x97", "\x1b[1;3H"), "Alt+PageDown": ("\xa1", "\x1b[6;3~"), "Alt+Delete": ("\xa3", "\x1b[3;3~"),
    "F1": (";", "\x1bOP"), "F2": ("<", "\x1bOQ"), "F3": ("=", "\x1bOR"), "F4": (">", "\x1bOS"), "F5": ("?", "\x1b[15~"),
    "F6": ("@", "\x1b[17~"), "F7": ("A", "\x1b[18~"), "F8": ("B", "\x1b[19~"), "F9": ("C", "\x1b[20~"),
    "F10": ("D", "\x1b[21~"), "F11": ("\x85", "\x1b[23~"), "F12": ("\x86", "\x1b[24~"),
    "Shift+F1": ("T", "\x1b[1;2P"), "Shift+F5": ("X", "\x1b[15;2~"), "Ctrl+F10": ("g", "\x1b[21;5~"),
    "Alt+F4": ("k", "\x1b[1;3S"), "Shift+F12": ("\x88", "\x1b[24;2~"), "Ctrl+F11": ("\x89", "\x1b[23;5~"),
    "Alt+F12": ("\x8c", "\x1b[24;3~"), "Shift+Tab": ("\x0f", "\x1b[Z"),
}


class Console:
    """A Windows console as msvcrt reads it: each part is there at once, the next arrives after a
    pause. `shifted`: which characters, counted in the order they are read, are Tabs typed with
    Shift, which getwch gives as plain Tabs (ShiftTab's stand-in tells them apart)."""

    def __init__(self, *parts, shifted=()):
        # getwch gives UTF-16 code units: a character beyond U+FFFF is two of them.
        units = (part.encode("utf-16-le", "surrogatepass") for part in parts)
        self.parts = [[chr(int.from_bytes(raw[i:i + 2], "little")) for i in range(0, len(raw), 2)] for raw in units]
        self.shifted = set(shifted)
        self.read = 0

    def kbhit(self):
        if self.parts and not self.parts[0]:
            self.parts.pop(0)
            return False  # the next part is still on its way
        return bool(self.parts)

    def getwch(self):
        self.read += 1
        return self.parts[0].pop(0)

    def shift_tab(self):
        return self.read in self.shifted


class Keys(unittest.TestCase):
    """console_input, fed the codes msvcrt.getwch gives."""

    def read(self, console):
        return vm_host.console_input(console, threading.Event(), console.shift_tab)

    def test_each_key_a_console_gives_as_two_characters_reaches_the_vm_as_an_xterm_sends_it(self):
        for name, (code, sent) in KEYS.items():
            for prefix in ("\x00", "\xe0"):
                with self.subTest(key=name, prefix=prefix):
                    self.assertEqual(self.read(Console(prefix + code)), sent)
        # Several keys and typed text at once, in order; a key the table does not name is dropped.
        typed = "".join(prefix + KEYS[name][0] for prefix, name in (("\xe0", "PageUp"), ("\x00", "F5"), ("\xe0", "Ctrl+Left")))
        self.assertEqual(self.read(Console("ls" + typed + "\x00\x01!")), "ls\x1b[5~\x1b[15~\x1b[1;5D!")

    def test_shift_tab_is_told_from_tab(self):
        # The console gives Shift+Tab as a Tab: the key's own record says Shift was down.
        self.assertEqual(self.read(Console("a\tb\t", shifted={1})), "a\x1b[Zb\t")
        self.assertEqual(self.read(Console("\t\t", shifted={0, 1})), "\x1b[Z\x1b[Z")
        # Without the console's word, a Tab stays a Tab.
        self.assertEqual(vm_host.console_input(Console("\t"), threading.Event()), "\t")

    def test_requests_stay_within_the_vm_bound_and_never_split_a_key_or_a_character(self):
        # 4,000 F12 presses are 20,000 bytes: more than one request, each whole keys.
        console, sent = Console("\xe0\x86" * 4000), []
        while text := self.read(console):
            sent.append(text)
        self.assertEqual("".join(sent), "\x1b[24~" * 4000)
        self.assertTrue(all(len(text.encode()) <= vm_host.INPUT_BYTES and len(text) % 5 == 0 for text in sent), [len(t) for t in sent])
        # A character beyond U+FFFF that falls on the bound goes whole in the first request.
        filler = "a" * (vm_host.INPUT_BYTES - 2 * vm_host.KEY_BYTES)
        console = Console(filler + "\U0001F600" + "tail")
        first, second = self.read(console), self.read(console)
        self.assertEqual((first, second), (filler + "\U0001F600", "tail"))
        self.assertLessEqual(len(first.encode()), vm_host.INPUT_BYTES)

    @unittest.skipUnless(os.name == "nt", "a Windows console")
    def test_a_real_console_gives_these_codes_and_says_which_tab_had_shift(self):
        """Key presses written into a console of its own (hidden), read back as a harness's VM gets
        them: the C runtime's codes and the Shift+Tab peek, not stand-ins."""
        program = r"""
import ctypes, json, msvcrt, sys, threading
from ctypes import wintypes
sys.path.insert(0, sys.argv[1])
import vm_host
SHIFT, CTRL, ALT, GREY = 0x10, 0x08, 0x02, 0x100
presses = [(0x58, 0x2D, "x", 0), (0x21, 0x49, "\0", GREY), (0x74, 0x3F, "\0", 0), (0x26, 0x48, "\0", GREY | CTRL),
           (0x10, 0x2A, "\0", SHIFT), (0x09, 0x0F, "\t", SHIFT), (0x09, 0x0F, "\t", 0), (0x7B, 0x58, "\0", 0),
           (0x24, 0x47, "\0", GREY | CTRL), (0x25, 0x4B, "\0", GREY | ALT), (0x70, 0x3B, "\0", SHIFT), (0x2D, 0x52, "\0", 0)]
class Key(ctypes.Structure):
    _fields_ = [("down", wintypes.BOOL), ("repeat", wintypes.WORD), ("key", wintypes.WORD), ("scan", wintypes.WORD),
                ("char", wintypes.WCHAR), ("state", wintypes.DWORD)]
class Event(ctypes.Union):
    _fields_ = [("key", Key), ("size", ctypes.c_byte * 16)]
class Record(ctypes.Structure):
    _fields_ = [("type", wintypes.WORD), ("event", Event)]
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
console = kernel32.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)
records = (Record * (2 * len(presses)))()
for index, (key, scan, char, state) in enumerate(presses):
    for offset, down in enumerate((True, False)):
        record = records[2 * index + offset]
        record.type = 1
        record.event.key.down, record.event.key.repeat, record.event.key.key = down, 1, key
        record.event.key.scan, record.event.key.char, record.event.key.state = scan, char, state
written = wintypes.DWORD()
assert kernel32.WriteConsoleInputW(console, records, len(records), ctypes.byref(written)), ctypes.get_last_error()
shift_tab = vm_host.ShiftTab()
try:
    print(json.dumps([vm_host.console_input(msvcrt, threading.Event(), shift_tab), ctypes.sizeof(Record)]))
finally:
    shift_tab.close()
"""
        result = subprocess.run([sys.executable, "-I", "-c", program, str(HARNESSES)], capture_output=True, text=True, timeout=60,
                                stdin=subprocess.DEVNULL, creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, result.stderr[-2000:])
        typed, size = json.loads(result.stdout)
        self.assertEqual(size, 20)  # INPUT_RECORD, as the console gives it
        self.assertEqual(typed, "x\x1b[5~\x1b[15~\x1b[1;5A\x1b[Z\t\x1b[24~\x1b[1;5H\x1b[1;3D\x1b[1;2P\x1b[2~")


ON = b"\x1b[?1049h\x1b[?25l\x1b[?2004h\x1b[>1u"
# What the Yougori harness writes when it puts the terminal back itself (harness/src/ui/term.rs).
OFF = b"\x1b[<u\x1b[0m\x1b[?2026l\x1b[?2004l\x1b[?1007h\x1b[?25h\x1b[?1049l"


class Terminal:
    """A person's terminal, as launch writes to it: text and the VM's output bytes."""

    def __init__(self):
        self.buffer = io.BytesIO()
        self.text = io.StringIO()

    def isatty(self):
        return True

    def write(self, text):
        return self.text.write(text)

    def flush(self):
        pass


class Session:
    """vm_host.launch for `pi`, with the engine and the image replaced and a VM guest that gives
    `packets` and is then gone."""

    def guest(self, packets):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Guest)
        server.bodies, server.packets = [], list(packets)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return server

    def launch(self, guest, terminal, environment=None, console_vt=False):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        key_file = Path(folder.name) / "api-key"
        key_file.write_text("is_test-key")

        def call(action, **params):
            if action == "launch":
                return {"sandbox": "exe-" + "a" * 32}
            if action == "publish":
                return {"url": "http://abc123.localhost:%d/" % guest.server_port}
            return {}
        given = environment or {}
        with patch.object(vm_host, "install", lambda name, server, root: "sha256:" + "b" * 64), \
                patch.object(vm_host, "call", call), patch.object(vm_host, "tidy", lambda sandbox, folder: False), \
                patch.object(vm_host, "prepare_tool", lambda control, root, declaration=None: None), \
                patch.object(vm_host.Screen, "take_console", lambda screen: console_vt), \
                patch.dict(os.environ, given), contextlib.redirect_stdout(terminal):
            for name in ("NO_COLOR", "COLORTERM", "WT_SESSION"):
                if name not in given:
                    os.environ.pop(name, None)
            return vm_host.launch("pi", "http://127.0.0.1:9", key_file, "m", None, [], False)


class Reset(Session, unittest.TestCase):
    """Screen: what the session's output turned on, put back when the session ends under it."""

    def test_what_the_output_left_on_is_put_back(self):
        screen = vm_host.Screen()
        # Sequences split between packets are followed too.
        for packet in (b"\x1b[?10", b"49h\x1b", b"[?25l\x1b[?2004h\x1b[>", b"1uhello\x1b[?1000;1006h", b"\x1b[?20"):
            screen.feed(packet)
        self.assertEqual(screen.reset(abrupt=True),
                         b"\x1b[<1u\x1b[?1000l\x1b[?1006l\x1b[?2004l\x1b[?25h\x1b[?1049l\x1b[0m")
        # Turned off again by the program: nothing to put back, even after an abrupt end but colours.
        screen.feed(b"26h\x1b[?1000;1006l" + OFF)
        self.assertEqual(screen.reset(abrupt=False), b"")
        self.assertEqual(screen.reset(abrupt=True), b"\x1b[0m")

    def test_keyboard_flags_are_popped_as_often_as_they_were_pushed(self):
        screen = vm_host.Screen()
        screen.feed(b"\x1b[>1u\x1b[>3u\x1b[>1u\x1b[<2u\x1b[?u")
        self.assertEqual(screen.reset(abrupt=False), b"\x1b[<1u\x1b[0m")
        screen.feed(b"\x1b[<u\x1b[<u")
        self.assertEqual(screen.reset(abrupt=False), b"")
        # A long run of digits is no sequence worth waiting for.
        screen.feed(b"\x1b[?" + b"1" * 100)
        self.assertEqual(screen.tail, b"")

    def test_the_terminal_is_put_back_only_when_the_vm_ends_under_the_program(self):
        guest = self.guest([{"output": base64.b64encode(ON).decode()}])
        terminal, failure = Terminal(), None
        try:
            self.launch(guest, terminal)
        except ValueError as error:
            failure = error
        self.assertIn("HTTP 500", str(failure))
        self.assertEqual(terminal.buffer.getvalue(), ON + b"\x1b[<1u\x1b[?2004l\x1b[?25h\x1b[?1049l\x1b[0m")
        # The program put the terminal back itself and ended: nothing more is written.
        guest = self.guest([{"output": base64.b64encode(ON).decode()}, {"output": base64.b64encode(OFF).decode(), "exit": 0}])
        terminal = Terminal()
        self.assertEqual(self.launch(guest, terminal), 0)
        self.assertEqual(terminal.buffer.getvalue(), ON + OFF)
        # It ended without putting it back (killed): what it left on is put back all the same.
        guest = self.guest([{"output": base64.b64encode(ON).decode(), "exit": 137}])
        terminal = Terminal()
        self.assertEqual(self.launch(guest, terminal), 137)
        self.assertEqual(terminal.buffer.getvalue(), ON + b"\x1b[<1u\x1b[?2004l\x1b[?25h\x1b[?1049l\x1b[0m")


class Guest(BaseHTTPRequestHandler):
    """A VM's guest that gives the packets it was handed, then is gone (HTTP 500)."""

    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.bodies.append((self.path, body))
        reply = {}
        if self.path == "/start":
            reply = {"started": True, "tunnels": True, "yougori": True, "targets": True}
        elif self.path == "/poll":
            if not self.server.packets:
                self.send_response(500)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            reply = {"output": "", "requests": [], "tunnels": [], "exit": None, **self.server.packets.pop(0)}
        raw = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Colours(Session, unittest.TestCase):
    """What the VM's programs are told of the person's terminal."""

    def test_the_launcher_says_what_the_terminal_shows(self):
        self.assertEqual(vm_host.colours({"NO_COLOR": "1", "COLORTERM": "truecolor"}), {"no_color": True})
        self.assertEqual(vm_host.colours({"NO_COLOR": "", "COLORTERM": "24bit"}), {"colorterm": "truecolor"})
        self.assertEqual(vm_host.colours({"COLORTERM": "TrueColor"}), {"colorterm": "truecolor"})
        self.assertEqual(vm_host.colours({"WT_SESSION": "4f1c"}), {"colorterm": "truecolor"})
        self.assertEqual(vm_host.colours({}, console_vt=True), {"colorterm": "truecolor"})
        self.assertEqual(vm_host.colours({"COLORTERM": "256", "TERM": "xterm-256color"}), {})

    def test_the_start_request_carries_it_to_the_vm(self):
        def start(environment, console_vt=False):
            guest = self.guest([{"exit": 0}])
            self.launch(guest, Terminal(), environment, console_vt)
            return next(body for path, body in guest.bodies if path == "/start")
        body = start({"NO_COLOR": "1"})
        self.assertIs(body["no_color"], True)
        self.assertNotIn("colorterm", body)
        self.assertEqual(start({"COLORTERM": "24bit"})["colorterm"], "truecolor")
        self.assertEqual(start({}, console_vt=True)["colorterm"], "truecolor")
        self.assertFalse({"no_color", "colorterm"} & set(start({})))

    def test_the_vm_passes_it_to_the_harness(self):
        environment = vm_guest.harness_environment({"no_color": True, "colorterm": "truecolor"}, "m")
        self.assertEqual((environment.get("NO_COLOR"), "COLORTERM" in environment), ("1", False))
        self.assertEqual(vm_guest.harness_environment({"colorterm": "24bit"}, "m")["COLORTERM"], "24bit")
        for data in ({}, {"colorterm": "256"}, {"colorterm": ["truecolor"]}, {"no_color": "yes"}):
            environment = vm_guest.harness_environment(data, "m")
            self.assertFalse({"NO_COLOR", "COLORTERM"} & set(environment), data)
            self.assertEqual((environment["TERM"], environment["SOLVER_MODEL"]), ("xterm-256color", "m"))


SANDBOX = "exe-" + "a" * 32
REVIEW = "\nYour original project is unchanged. Review the VM copy with:\nyougori sandbox review " + SANDBOX + "\n"


class Cleanup(Session, unittest.TestCase):
    """After a session: the VM stopped, its copy tidied and the review line printed, whatever the
    keyboard does meanwhile."""

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)

    def test_a_ctrl_c_while_the_vm_stops_cuts_nothing_short(self):
        guest = self.guest([{"exit": 0}])
        key_file = self.root / "api-key"
        key_file.write_text("is_test-key")
        steps = []

        def call(action, **params):
            steps.append(action)
            if action == "launch":
                return {"sandbox": SANDBOX}
            if action == "publish":
                return {"url": "http://abc123.localhost:%d/" % guest.server_port}
            if action == "stop":
                signal.raise_signal(signal.SIGINT)  # a second Ctrl+C while the VM stops
            if action == "workspace":
                return {"changes": [{"change": "modified", "name": "notes.txt"}]}
            return {}
        before = {number: signal.getsignal(number) for number in vm_host.KEYBOARD}
        terminal = Terminal()
        with patch.object(vm_host, "install", lambda name, server, root: "sha256:" + "b" * 64), patch.object(vm_host, "call", call), \
                patch.object(vm_host, "prepare_tool", lambda control, root, declaration=None: None), \
                patch.object(vm_host.Screen, "take_console", lambda screen: False), contextlib.redirect_stdout(terminal):
            code = vm_host.launch("pi", "http://127.0.0.1:9", key_file, "m", self.root, [], False)
        self.assertEqual(code, 0)
        self.assertEqual(steps[-2:], ["stop", "workspace"])
        self.assertTrue(terminal.text.getvalue().endswith(REVIEW), terminal.text.getvalue())
        # Afterwards each key does what it did before.
        self.assertEqual({number: signal.getsignal(number) for number in vm_host.KEYBOARD}, before)

    def launch_folder(self, packets, workspace, size=None):
        """vm_host.launch for `pi` on `workspace`, the VM's guest giving `packets`. Returns the exit
        code, what the guest was sent and what it had been sent when the VM was stopped."""
        guest = self.guest(packets)
        key_file = self.root / "api-key"
        key_file.write_text("is_test-key")
        at_stop = []

        def call(action, **params):
            if action == "launch":
                return {"sandbox": SANDBOX}
            if action == "publish":
                return {"url": "http://abc123.localhost:%d/" % guest.server_port}
            if action == "stop":
                at_stop.extend(path for path, _ in guest.bodies)
            if action == "workspace":
                return {"changes": []}
            return {}
        with patch.object(vm_host, "install", lambda name, server, root: "sha256:" + "b" * 64), patch.object(vm_host, "call", call), \
                patch.object(vm_host, "prepare_tool", lambda control, root, declaration=None: None), \
                patch.object(vm_host.Screen, "take_console", lambda screen: False), \
                patch.object(vm_host.shutil, "get_terminal_size", size or (lambda fallback: os.terminal_size(fallback))), \
                contextlib.redirect_stdout(Terminal()):
            code = vm_host.launch("pi", "http://127.0.0.1:9", key_file, "m", workspace, [], False)
        return code, guest.bodies, at_stop

    def test_a_session_the_launcher_ends_is_finished_in_the_vm_before_it_stops(self):
        """Ctrl+] or Ctrl+C ended the session in the launcher, which stopped the VM without a word to
        its guest: the harness had no hangup in which to save its work, and the setup files stayed in
        the copy for the review."""
        sizes = []

        def size(fallback):
            sizes.append(fallback)
            if len(sizes) > 1:
                raise KeyboardInterrupt  # Pressed while the session runs.
            return os.terminal_size(fallback)
        code, _, at_stop = self.launch_folder([{"output": ""}], self.root, size)
        self.assertEqual(code, 130)
        self.assertEqual(at_stop[-1], "/finish")
        # A harness that ended by itself ended the session: nothing more is asked of the guest.
        code, sent, at_stop = self.launch_folder([{"exit": 0}], self.root)
        self.assertEqual(code, 0)
        self.assertNotIn("/finish", [path for path, _ in sent])

    def test_the_vm_is_told_which_setup_files_the_folder_already_holds(self):
        """The guest took every setup file out of the copy, also those the folder held already: the
        review listed them as deleted and the copy was kept for a session that changed nothing."""
        self.assertEqual(vm_host.setup_in_folder(self.root), [])
        (self.root / "yougori.py").write_text("// Yougori setup package\n", encoding="utf-8")
        (self.root / "node_modules/yougori").mkdir(parents=True)
        (self.root / "node_modules/yougori/package.json").write_text("{}", encoding="utf-8")
        (self.root / ".agents/skills/yougori-setup/SKILL.md").mkdir(parents=True)  # A folder is not the file.
        held = ["node_modules/yougori/package.json", "yougori.py"]
        self.assertEqual(vm_host.setup_in_folder(self.root), held)
        _, sent, _ = self.launch_folder([{"exit": 0}], self.root)
        self.assertEqual(next(body for path, body in sent if path == "/start")["setup_in_folder"], held)
        # Without a folder the VM works in an empty one of its own: nothing to say.
        _, sent, _ = self.launch_folder([{"exit": 0}], None)
        self.assertNotIn("setup_in_folder", next(body for path, body in sent if path == "/start"))

    def test_a_vm_that_could_not_be_stopped_is_named_with_the_command_that_stops_it(self):
        def call(action, **params):
            if action == "stop":
                raise ValueError("Yougori did not return a sandbox response. Start/update Yougori and try again.")
            raise AssertionError("nothing is tidied while the VM may still run: " + action)
        for workspace, review in ((None, ""), (Path("C:/work/app"), REVIEW)):
            printed, said = io.StringIO(), io.StringIO()
            with patch.object(vm_host, "call", call), contextlib.redirect_stdout(printed), contextlib.redirect_stderr(said):
                vm_host.finish(SANDBOX, workspace, self.root)
            self.assertEqual(said.getvalue(), "The VM could not be stopped automatically: Yougori did not return a sandbox "
                             "response. Start/update Yougori and try again.\nStop it with: yougori sandbox stop " + SANDBOX + " --yes\n")
            self.assertEqual(printed.getvalue(), review)

    def test_the_review_line_comes_even_when_a_step_fails_unexpectedly(self):
        printed = io.StringIO()
        with patch.object(vm_host, "call", lambda action, **params: ["not", "an", "object"] if action == "workspace" else {}), \
                contextlib.redirect_stdout(printed), self.assertRaises(AttributeError):
            vm_host.finish(SANDBOX, Path("C:/work/app"), self.root)
        self.assertEqual(printed.getvalue(), REVIEW)

    def test_each_engine_call_starts_where_no_key_pressed_in_the_console_reaches(self):
        seen = {}

        def run(argv, **options):
            seen.update(options)
            return subprocess.CompletedProcess(argv, 0, stdout='{"ok": true, "result": {}}', stderr="")
        with patch.dict(os.environ, {"INFERENCE_SOLVER_YOUGORI": "yougori"}), patch.object(vm_host.subprocess, "run", run):
            self.assertEqual(vm_host.call("status"), {})
        # A console of its own, without a window. A process group of its own would keep out Ctrl+C
        # alone, and Ctrl+Break would still end the call (RealConsole).
        self.assertEqual(seen.get("creationflags"), subprocess.CREATE_NO_WINDOW if os.name == "nt" else None)


class ConsoleMode(unittest.TestCase):
    """ConsoleKeys: the console's input mode while the session reads keys, put back exactly."""

    def test_a_key_being_read_as_the_session_ends_leaves_the_mode_as_it_was(self):
        class Console:
            """The console's input mode (kernel32) and msvcrt reading a key as the C runtime does:
            the mode set to 0 for the read, then back to what it found."""
            def __init__(self):
                self.mode, self.unread = 0x1F7, ["a"]
                self.reading, self.finish = threading.Event(), threading.Event()

            def SetConsoleMode(self, handle, mode):
                self.mode = mode
                return 1

            def CloseHandle(self, handle):
                return 1

            def kbhit(self):
                return bool(self.unread)

            def getwch(self):
                found, self.mode = self.mode, 0
                self.reading.set()
                self.finish.wait(10)
                self.mode = found
                return self.unread.pop()
        console, keys, done = Console(), vm_host.ConsoleKeys(), threading.Event()
        # As take() leaves it.
        keys.kernel32, keys.handle, keys.mode = console, 1, console.mode
        console.mode &= ~keys.PROCESSED_INPUT
        read = []
        reader = threading.Thread(target=lambda: read.append(keys.read(console, done, lambda: False)))
        reader.start()
        self.assertTrue(console.reading.wait(10))
        # The session ends while the key is read: the mode comes back once the read is over.
        done.set()
        restorer = threading.Thread(target=keys.restore)
        restorer.start()
        restorer.join(.2)
        self.assertTrue(restorer.is_alive())
        console.finish.set()
        reader.join(10)
        restorer.join(10)
        self.assertEqual((read, console.mode, keys.handle), (["a"], 0x1F7, None))
        # No key is read after it.
        console.unread.append("b")
        self.assertEqual(keys.read(console, done, lambda: False), "")
        self.assertEqual(console.unread, ["b"])


class PseudoConsole:
    """A program in a console of its own, hidden, as Windows Terminal starts one (a pseudoconsole):
    keys go in as the terminal sends them (Ctrl+C as 0x03, which the console turns into a signal
    while its input mode has ENABLE_PROCESSED_INPUT) and the screen comes out."""

    def __init__(self, argv):
        import ctypes
        from ctypes import wintypes

        class Coord(ctypes.Structure):
            _fields_ = [("X", wintypes.SHORT), ("Y", wintypes.SHORT)]

        class StartupInfo(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR), ("lpDesktop", wintypes.LPWSTR),
                        ("lpTitle", wintypes.LPWSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD), ("dwXSize", wintypes.DWORD),
                        ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                        ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD), ("wShowWindow", wintypes.WORD),
                        ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                        ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

        class StartupInfoEx(ctypes.Structure):
            _fields_ = [("StartupInfo", StartupInfo), ("lpAttributeList", ctypes.c_void_p)]

        class ProcessInformation(ctypes.Structure):
            _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE), ("dwProcessId", wintypes.DWORD),
                        ("dwThreadId", wintypes.DWORD)]
        k = self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle, pointer = wintypes.HANDLE, ctypes.c_void_p
        k.CreatePipe.argtypes = [ctypes.POINTER(handle), ctypes.POINTER(handle), pointer, wintypes.DWORD]
        k.CreatePseudoConsole.argtypes = [Coord, handle, handle, wintypes.DWORD, ctypes.POINTER(pointer)]
        k.CreatePseudoConsole.restype = ctypes.c_long
        k.ClosePseudoConsole.argtypes = [pointer]
        k.InitializeProcThreadAttributeList.argtypes = [pointer, wintypes.DWORD, wintypes.DWORD, ctypes.POINTER(ctypes.c_size_t)]
        k.UpdateProcThreadAttribute.argtypes = [pointer, wintypes.DWORD, ctypes.c_size_t, pointer, ctypes.c_size_t, pointer, pointer]
        k.DeleteProcThreadAttributeList.argtypes = [pointer]
        k.CreateProcessW.argtypes = [wintypes.LPCWSTR, wintypes.LPWSTR, pointer, pointer, wintypes.BOOL, wintypes.DWORD, pointer,
                                     wintypes.LPCWSTR, ctypes.POINTER(StartupInfo), ctypes.POINTER(ProcessInformation)]
        k.ReadFile.argtypes = [handle, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), pointer]
        k.WriteFile.argtypes = [handle, pointer, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), pointer]
        k.WaitForSingleObject.argtypes = [handle, wintypes.DWORD]
        k.GetExitCodeProcess.argtypes = [handle, ctypes.POINTER(wintypes.DWORD)]
        k.TerminateProcess.argtypes = [handle, wintypes.UINT]
        k.CloseHandle.argtypes = [handle]
        self.ctypes, self.wintypes = ctypes, wintypes
        keys_read, self.keys, output, output_write = handle(), handle(), handle(), handle()
        assert k.CreatePipe(ctypes.byref(keys_read), ctypes.byref(self.keys), None, 0), ctypes.get_last_error()
        assert k.CreatePipe(ctypes.byref(output), ctypes.byref(output_write), None, 0), ctypes.get_last_error()
        self.console = pointer()
        assert k.CreatePseudoConsole(Coord(120, 30), keys_read, output_write, 0, ctypes.byref(self.console)) == 0
        k.CloseHandle(keys_read)
        k.CloseHandle(output_write)
        size = ctypes.c_size_t()
        k.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        self.attributes = ctypes.create_string_buffer(size.value)
        assert k.InitializeProcThreadAttributeList(self.attributes, 1, 0, ctypes.byref(size)), ctypes.get_last_error()
        # PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE.
        assert k.UpdateProcThreadAttribute(self.attributes, 0, 0x00020016, self.console, ctypes.sizeof(pointer), None, None)
        info = StartupInfoEx()
        info.StartupInfo.cb = ctypes.sizeof(StartupInfoEx)
        # STARTF_USESTDHANDLES with none given: the program's standard handles are the console's.
        info.StartupInfo.dwFlags = 0x100
        info.lpAttributeList = ctypes.cast(self.attributes, pointer)
        self.process = ProcessInformation()
        line = ctypes.create_unicode_buffer(subprocess.list2cmdline(argv))
        # EXTENDED_STARTUPINFO_PRESENT.
        assert k.CreateProcessW(None, line, None, None, False, 0x00080000, None, None, ctypes.byref(info.StartupInfo),
                                ctypes.byref(self.process)), ctypes.get_last_error()
        self.screen, self.arrived = bytearray(), threading.Condition()
        self.reader = threading.Thread(target=self.drain, args=(output,), daemon=True)
        self.reader.start()
        self.output = output

    def drain(self, output):
        chunk, count = self.ctypes.create_string_buffer(4096), self.wintypes.DWORD()
        while self.kernel32.ReadFile(output, chunk, 4096, self.ctypes.byref(count), None) and count.value:
            with self.arrived:
                self.screen.extend(chunk.raw[:count.value])
                self.arrived.notify_all()

    def wait_for(self, text, timeout=60):
        with self.arrived:
            return self.arrived.wait_for(lambda: text in self.screen, timeout)

    def type(self, keys):
        written = self.wintypes.DWORD()
        assert self.kernel32.WriteFile(self.keys, keys, len(keys), self.ctypes.byref(written), None) and written.value == len(keys)

    def wait(self, timeout=60):
        """The program's exit code, or None while it runs."""
        if self.kernel32.WaitForSingleObject(self.process.hProcess, int(timeout * 1000)) != 0:
            return None
        code = self.wintypes.DWORD()
        self.kernel32.GetExitCodeProcess(self.process.hProcess, self.ctypes.byref(code))
        return code.value

    def text(self):
        with self.arrived:
            return bytes(self.screen).decode("utf-8", "replace")

    def close(self):
        k = self.kernel32
        if self.wait(0) is None:
            k.TerminateProcess(self.process.hProcess, 1)
        k.ClosePseudoConsole(self.console)
        k.CloseHandle(self.keys)
        self.reader.join(10)
        k.CloseHandle(self.output)
        k.CloseHandle(self.process.hProcess)
        k.CloseHandle(self.process.hThread)
        k.DeleteProcThreadAttributeList(self.attributes)


# A session as `yougori inference run` starts one, in a pseudoconsole: the launcher as it is, the
# VM's guest a server in this process, the engine a stand-in program (ENGINE) that vm_host.call
# starts as it starts yougori, the console's input mode noted as the VM stops. Its guest ends the
# session at the harness's word on Ctrl+C, as many harnesses do; with "break", the console gives
# Ctrl+Break when "b" is typed.
SESSION = r'''
import base64, ctypes, json, subprocess, sys, threading, time
from ctypes import wintypes
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
harnesses, folder, scenario = sys.argv[1], Path(sys.argv[2]), sys.argv[3]
sys.path.insert(0, harnesses)
import vm_host
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
# Ctrl+C processed as a person's terminal has it; a test runner may start this with it ignored.
kernel32.SetConsoleCtrlHandler(None, False)
kernel32.CreateFileW.restype = wintypes.HANDLE
kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                 wintypes.DWORD, wintypes.HANDLE]
kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
console = kernel32.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)


def mode():
    value = wintypes.DWORD()
    assert kernel32.GetConsoleMode(console, ctypes.byref(value))
    return value.value


seen = {"before": mode(), "typed": ""}


class Guest(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        reply = {}
        if self.path == "/start":
            reply = {"started": True, "tunnels": True, "yougori": True, "targets": True}
        elif self.path == "/input":
            seen["typed"] += base64.b64decode(body.get("data", "")).decode()
            seen["session"] = mode()
            if scenario == "break" and "b" in seen["typed"] and not seen.get("broken"):
                seen["broken"] = True
                kernel32.GenerateConsoleCtrlEvent(1, 0)  # CTRL_BREAK_EVENT, to every process in this console
        elif self.path == "/poll":
            time.sleep(.02)
            shown, seen["shown"] = seen.get("shown"), True
            reply = {"output": "" if shown else base64.b64encode(b"SESSION\r\n").decode(), "requests": [], "tunnels": [],
                     "exit": 0 if "\x03" in seen["typed"] else None}
        raw = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


guest = ThreadingHTTPServer(("127.0.0.1", 0), Guest)
threading.Thread(target=guest.serve_forever, daemon=True).start()
(folder / "guest-port").write_text(str(guest.server_port))
started = subprocess.run


def engine(argv, **options):
    """yougori, started as vm_host.call starts it, with its options as they are."""
    if json.loads(options["input"])["action"] == "stop":
        seen["stopping"] = mode()
    return started([sys.executable, "-I", str(folder / "engine.py"), str(folder), *argv[1:]], **options)


subprocess.run = engine
vm_host.install = lambda name, server, root: "sha256:" + "b" * 64
vm_host.prepare_tool = lambda control, root, declaration=None: None
(folder / "project").mkdir()
(folder / "keys").mkdir()
(folder / "keys" / "api-key").write_text("is_test-key")
seen["code"] = vm_host.launch("pi", "http://127.0.0.1:9", folder / "keys" / "api-key", "m", folder / "project", [], True)
seen["after"] = mode()
(folder / "result.json").write_text(json.dumps(seen))
'''

# `yougori call sandbox_vm --file - --yes`, standing in: the VM it launches is the session's guest;
# stopping it says so (a file named stopping), then waits for the test to have pressed its keys.
# Each call it finishes is added to calls.txt.
ENGINE = r'''
import json, sys, time
from pathlib import Path
folder = Path(sys.argv[1])
request = json.load(sys.stdin)
result = {}
if request["action"] == "launch":
    result = {"sandbox": "exe-0123456789abcdef0123456789abcdef"}
elif request["action"] == "publish":
    result = {"url": "http://abc123.localhost:%s/" % (folder / "guest-port").read_text()}
elif request["action"] == "stop":
    (folder / "stopping").write_text("")
    end = time.monotonic() + 30
    while not (folder / "pressed").exists() and time.monotonic() < end:
        time.sleep(.05)
elif request["action"] == "workspace" and request.get("op") == "show":
    result = {"changes": [{"change": "modified", "name": "notes.txt"}]}
with (folder / "calls.txt").open("a", encoding="utf-8") as calls:
    calls.write(" ".join(filter(None, (request["action"], request.get("op")))) + "\n")
print(json.dumps({"ok": True, "result": result}))
'''

# Ctrl+Break as Windows Terminal types it into a console (win32-input-mode): the Break key
# (VK_CANCEL) with Ctrl, pressed and let go. The console gives it to every process on it.
CTRL_BREAK = b"\x1b[3;70;0;1;8;1_\x1b[3;70;0;0;8;1_"


@unittest.skipUnless(os.name == "nt", "a Windows console")
class RealConsole(unittest.TestCase):
    """A session in a real console, hidden (a pseudoconsole, as Windows Terminal gives a program),
    its keys typed into it: a Ctrl+C reaches the harness, neither a second one nor a Ctrl+Break
    while the VM stops cuts anything short, Ctrl+Break ends the session with its cleanup, Ctrl+] is
    still the way out, and the console's input mode is as it was at the end."""

    def session(self, scenario, keys, stopping=b""):
        """The session's result, `keys` typed during it and `stopping` while its VM stops."""
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        (root / "session.py").write_text(SESSION, encoding="utf-8")
        (root / "engine.py").write_text(ENGINE, encoding="utf-8")
        console = PseudoConsole([sys.executable, "-I", str(root / "session.py"), str(HARNESSES), str(root), scenario])
        self.addCleanup(console.close)
        self.assertTrue(console.wait_for(b"SESSION"), console.text())
        for key in keys:
            console.type(key)
            time.sleep(.3)
        end = time.monotonic() + 60
        while not (root / "stopping").exists() and time.monotonic() < end:
            time.sleep(.05)
        self.assertTrue((root / "stopping").exists(), console.text())
        if stopping:
            console.type(stopping)
            time.sleep(.5)
        (root / "pressed").write_text("")
        self.assertEqual(console.wait(), 0, console.text())
        result = json.loads((root / "result.json").read_text())
        screen = console.text()
        self.assertNotIn("Traceback", screen)
        # The engine finished the stop, then showed the copy's changes, which keep it for review.
        self.assertEqual((root / "calls.txt").read_text(encoding="utf-8").splitlines()[-2:], ["stop", "workspace show"], screen)
        self.assertNotIn("could not be stopped", screen)
        self.assertIn("sandbox review exe-0123456789abcdef0123456789abcdef", screen)
        # The console's input mode: processed input as the person had it, back before the VM was
        # stopped, so a key pressed then is a signal, and the same at the end.
        processed = vm_host.ConsoleKeys.PROCESSED_INPUT
        self.assertTrue(result["before"] & processed)
        self.assertEqual((result["stopping"], result["after"]), (result["before"], result["before"]))
        return result

    def test_ctrl_c_reaches_the_harness_and_a_second_one_while_the_vm_stops_cuts_nothing_short(self):
        result = self.session("ctrl-c", [b"a", b"\x03"], stopping=b"\x03")
        # The harness had both keys, and Ctrl+C reached it as a key: its own exit code ends the run.
        self.assertEqual((result["typed"], result["code"]), ("a\x03", 0))
        self.assertFalse(result["session"] & vm_host.ConsoleKeys.PROCESSED_INPUT)

    def test_ctrl_break_while_the_vm_stops_cuts_nothing_short(self):
        # The console gives Ctrl+Break to every process on it, whatever its process group: the
        # launcher ignores it during the cleanup, and the engine call stopping the VM, on a console
        # of its own, never gets it.
        result = self.session("ctrl-c", [b"a", b"\x03"], stopping=CTRL_BREAK)
        self.assertEqual((result["typed"], result["code"]), ("a\x03", 0))

    def test_ctrl_break_ends_the_session_with_its_cleanup(self):
        result = self.session("break", [b"a", b"b"])
        self.assertEqual((result["typed"], result["code"]), ("ab", 130))

    def test_ctrl_bracket_is_still_the_way_out(self):
        result = self.session("leave", [b"a", b"\x1d"])
        self.assertEqual((result["typed"], result["code"]), ("a", 130))


if __name__ == "__main__":
    unittest.main()
