"""The launcher starting a harness inside the Yougori harness: the base that harness starts on and
its pack, from the website's Yougori harness images, kept once for every harness and safe for
launches at the same time; the pack declared to the VM's guest before any of it arrives, then
delivered and checked; the guest holding only the harness it was told; the preflight reading
whether a harness starts inside Yougori.

Run: python -I -B examples/hub/inference-solver/tests/test_yougori_launch.py
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
import zipfile

SITE = Path(__file__).resolve().parents[1] / "site"
sys.path.insert(0, str(SITE))
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.append(str(SITE / "harnesses"))
# vm_guest runs in the Linux VM; its terminal modules are not needed for what these tests check.
for linux_only in ("fcntl", "pty", "termios"):
    sys.modules.setdefault(linux_only, types.ModuleType(linux_only))
import harness_download
import vm_guest
import vm_host


def oci_zip(label):
    """An image archive as the website serves one: an OCI layout of one blob."""
    blob = ("layer of " + label).encode()
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("oci-layout", '{"imageLayoutVersion":"1.0.0"}')
        archive.writestr("index.json", json.dumps({"label": label}))
        archive.writestr("blobs/sha256/" + hashlib.sha256(blob).hexdigest(), blob)
    return stream.getvalue()


def pack_archive(text):
    """A pack as the build script makes one: a tool archive of tool/ and source/."""
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz") as archive:
        for name, data in (("tool/bin/app", text.encode()), ("source/LICENSE", b"MIT")):
            info = tarfile.TarInfo(name)
            info.size, info.mode = len(data), 0o755
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


BASE, POSTGRES = oci_zip("base"), oci_zip("postgres")
OPENCODE, KILO, PLANDEX = pack_archive("opencode"), pack_archive("kilo"), pack_archive("plandex")
VERSION = harness_download.catalog()


def listing():
    """The Yougori harness's images as /api/harness-image/yougori lists them."""
    def pack(raw, name, base="base", memory=4):
        return {"sha256": sha(raw), "bytes": len(raw), "version": VERSION[name]["version"], "base": base, "disk": 2, "memory": memory}
    return {"runtime": "yougori-sandbox-vm", "platform": "linux/amd64", "version": VERSION["yougori"]["version"],
            "bases": {"base": {"sha256": sha(BASE), "bytes": len(BASE), "disk": 2},
                      "postgres": {"sha256": sha(POSTGRES), "bytes": len(POSTGRES), "disk": 2}},
            "packs": {"yougori": {"base": "base", "disk": 2, "memory": 4}, "opencode": pack(OPENCODE, "opencode"),
                      "kilo": pack(KILO, "kilo"), "plandex": pack(PLANDEX, "plandex", "postgres", 5)}}


class Website(BaseHTTPRequestHandler):
    """The website's image routes: the listing, the bases and the packs, in small slow pieces so
    launches at the same time overlap; `barrier` holds base downloads until that many ask."""

    def log_message(self, *_):
        pass

    def do_GET(self):
        server = self.server
        with server.lock:
            server.requests.append(self.path)
        parts = self.path.removeprefix("/api/harness-image/yougori").strip("/").split("/")
        if parts == [""]:
            body = server.listing if isinstance(server.listing, bytes) else json.dumps(server.listing).encode()
        else:
            body = server.files.get(parts[0]) if parts[1:] in ([], ["tool"]) else None
            if body is None:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if parts[1:] == [] and server.barrier is not None:
                server.barrier.wait(10)
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        for start in range(0, len(body), 64):
            self.wfile.write(body[start:start + 64])
            if server.slow:
                time.sleep(.001)


class Engine:
    """Yougori's image store: imports keep the layout's files and root size, as the engine copies
    them before the call returns. `barrier`: imports wait until that many are under way."""

    def __init__(self):
        self.lock = threading.Lock()
        self.images = set()
        self.imports = []
        self.barrier = None

    def __call__(self, action, **params):
        if action == "status":
            return {}
        if action == "image" and params.get("operation") == "list":
            with self.lock:
                return [{"id": identity} for identity in sorted(self.images)]
        if action == "image" and params.get("operation") == "import":
            layout = Path(params["layout"])
            if self.barrier is not None:
                self.barrier.wait(10)
            files = sorted(path.relative_to(layout).as_posix() for path in layout.rglob("*") if path.is_file())
            identity = "sha256:" + sha(json.dumps([files, (layout / "index.json").read_text(), params["rootGb"]]).encode())
            with self.lock:
                self.images.add(identity)
                self.imports.append({"rootGb": params["rootGb"], "files": files, "layout": layout})
            return {"id": identity}
        raise AssertionError(action)


def leftovers(root):
    """What a launch would have left half-made: downloads under way and unpacked layouts."""
    return [path for path in root.rglob("*") if path.name.endswith(".partial") or path.name.startswith("layout")]


class Images(unittest.TestCase):
    """install_yougori: the base and the pack a harness needs, from the Yougori harness images."""

    def setUp(self):
        self.website = ThreadingHTTPServer(("127.0.0.1", 0), Website)
        self.website.lock, self.website.requests, self.website.listing = threading.Lock(), [], listing()
        self.website.files = {sha(raw): raw for raw in (BASE, POSTGRES, OPENCODE, KILO, PLANDEX)}
        self.website.barrier, self.website.slow = None, False
        threading.Thread(target=self.website.serve_forever, daemon=True).start()
        self.addCleanup(self.website.server_close)
        self.addCleanup(self.website.shutdown)
        self.url = "http://127.0.0.1:%d" % self.website.server_port
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.root = Path(folder.name)
        self.engine = Engine()

    def install(self, held):
        with patch.object(vm_host, "call", self.engine), contextlib.redirect_stdout(io.StringIO()):
            return vm_host.install_yougori(held, self.url, self.root)

    def asked(self, raw, tool=False):
        return self.website.requests.count("/api/harness-image/yougori/" + sha(raw) + ("/tool" if tool else ""))

    def test_a_harness_starts_on_its_base_with_its_pack(self):
        identity, declaration, memory = self.install("opencode")
        self.assertEqual(declaration, {"harness": "opencode", "sha256": sha(OPENCODE), "bytes": len(OPENCODE)})
        self.assertEqual(memory, 4)
        self.assertEqual((self.root / "tools" / (sha(OPENCODE) + ".tar.gz")).read_bytes(), OPENCODE)
        self.assertEqual(len(self.engine.imports), 1)
        imported = self.engine.imports[0]
        self.assertEqual(imported["rootGb"], 2)
        self.assertEqual(imported["files"], ["blobs/sha256/" + sha(b"layer of base"), "index.json", "oci-layout"])
        # The layout was this launch's own and went once Yougori held its copy.
        self.assertFalse(imported["layout"].exists())
        self.assertEqual(leftovers(self.root), [])
        # Another harness on the same base: its own pack, and the base neither downloaded nor imported again.
        again, declaration, _ = self.install("kilo")
        self.assertEqual((again, declaration["sha256"]), (identity, sha(KILO)))
        self.assertEqual((len(self.engine.imports), self.asked(BASE)), (1, 1))
        # A pack kept whole is not downloaded again; a harness on another base gets that base, with its memory.
        self.install("opencode")
        self.assertEqual(self.asked(OPENCODE, tool=True), 1)
        other, declaration, memory = self.install("plandex")
        self.assertNotEqual(other, identity)
        self.assertEqual((declaration["sha256"], memory, self.asked(POSTGRES)), (sha(PLANDEX), 5, 1))

    def test_yougori_own_agent_needs_no_pack(self):
        identity, declaration, memory = self.install("yougori")
        self.assertEqual((declaration, memory), ({"harness": "yougori"}, 4))
        self.assertTrue(identity.startswith("sha256:"))
        self.assertFalse([path for path in self.website.requests if path.endswith("/tool")])
        self.assertFalse((self.root / "tools").exists())

    def test_a_base_is_imported_again_for_another_root_or_once_the_engine_lost_it(self):
        self.install("opencode")
        self.engine.images.clear()
        self.install("opencode")
        self.assertEqual(len(self.engine.imports), 2)
        self.assertEqual(self.asked(BASE), 1)  # the kept archive, checked, is imported again
        self.website.listing["bases"]["base"]["disk"] = 3
        self.install("opencode")
        self.assertEqual([item["rootGb"] for item in self.engine.imports], [2, 2, 3])
        # A record that cannot be read is no shortcut.
        (self.root / "images" / sha(BASE) / "imported.json").write_text("{")
        self.install("opencode")
        self.assertEqual(len(self.engine.imports), 4)

    def test_a_listing_out_of_bounds_is_refused_before_anything_is_downloaded(self):
        def changed(change):
            value = listing()
            change(value)
            return value
        bad = [
            lambda v: v.update(runtime="other"), lambda v: v.update(platform="linux/arm64"), lambda v: v.update(bases=[]),
            lambda v: v.update(packs=[]), lambda v: v["packs"]["opencode"].update(base="chromium"),
            lambda v: v["packs"]["opencode"].update(base=None), lambda v: v["bases"]["base"].update(sha256=sha(BASE).upper()),
            lambda v: v["bases"]["base"].update(sha256=int("1" * 64)), lambda v: v["bases"]["base"].update(bytes=0),
            lambda v: v["bases"]["base"].update(bytes=(300 << 20) + 1), lambda v: v["bases"]["base"].update(bytes=True),
            lambda v: v["bases"]["base"].update(disk=9), lambda v: v["packs"]["opencode"].update(disk=3),
            lambda v: v["packs"]["opencode"].update(memory=2), lambda v: v["packs"]["opencode"].update(memory=1025),
            lambda v: v["packs"]["opencode"].pop("sha256"), lambda v: v["packs"]["opencode"].update(bytes=(512 << 20) + 1),
            lambda v: v["packs"]["opencode"].update(version=""), lambda v: v["packs"]["opencode"].update(sha256="e"),
            lambda v: v.update(download_base="https://elsewhere.example/api/harness-image"),
        ]
        for change in bad:
            self.website.listing = changed(change)
            with self.subTest(listing=self.website.listing), self.assertRaises(ValueError):
                self.install("opencode")
        self.website.listing = changed(lambda v: v["packs"]["yougori"].update(sha256=sha(BASE), bytes=len(BASE)))
        with self.assertRaises(ValueError):
            self.install("yougori")
        self.website.listing = changed(lambda v: v["packs"].pop("opencode"))
        with self.assertRaisesRegex(ValueError, "not made this harness ready"):
            self.install("opencode")
        for raw in (b"[1]", b"{" + b" " * (1 << 20) + b"}", b"not json"):
            self.website.listing = raw
            with self.assertRaisesRegex(ValueError, "not prepared the Yougori harness's VM images"):
                self.install("opencode")
        self.assertEqual([path for path in self.website.requests if not path.endswith("/yougori")], [])
        self.assertEqual(self.engine.imports, [])

    def test_a_damaged_download_is_refused_and_leaves_nothing(self):
        self.website.files[sha(OPENCODE)] = OPENCODE[:-1] + bytes([OPENCODE[-1] ^ 1])
        with self.assertRaisesRegex(ValueError, "did not match its checksum"):
            self.install("opencode")
        self.website.files[sha(OPENCODE)] = OPENCODE + b"more"
        with self.assertRaisesRegex(ValueError, "exceeded its declared size"):
            self.install("opencode")
        self.assertFalse((self.root / "tools" / (sha(OPENCODE) + ".tar.gz")).exists())
        self.assertEqual(leftovers(self.root), [])
        self.assertEqual(self.engine.imports, [])

    def test_each_download_goes_to_a_file_of_its_own_launch(self):
        """Two launches fetch the same base at once: halfway, each writes its own file."""
        halfway = threading.Barrier(3)

        class Download:
            def __init__(self):
                self.reads = 0

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def read(self, most):
                self.reads += 1
                if self.reads == 1:
                    return BASE[:10]
                if self.reads == 2:
                    halfway.wait(10)  # both launches wrote their first piece
                    halfway.wait(10)  # the files were looked at
                    return BASE[10:]
                return b""

        class Opener:
            def open(self, url, timeout):
                return Download()
        path, errors = self.root / "images" / "image.zip", []

        def fetch():
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    vm_host.fetch(Opener(), self.url, path, sha(BASE), len(BASE), "Sandbox VM image")
            except Exception as error:  # reported below
                errors.append(error)
        threads = [threading.Thread(target=fetch) for _ in range(2)]
        for thread in threads:
            thread.start()
        halfway.wait(10)
        partial = sorted(path.parent.glob("*.partial"))
        halfway.wait(10)
        for thread in threads:
            thread.join(30)
        self.assertEqual(len(partial), 2, partial)
        self.assertEqual((errors, path.read_bytes(), leftovers(self.root)), ([], BASE, []))

    def test_launches_at_once_share_the_images_without_writing_into_each_other(self):
        # Both launches download the shared base together, in small pieces, and import it at once.
        self.website.barrier, self.website.slow = threading.Barrier(2), True
        self.engine.barrier = threading.Barrier(2)
        results, errors = {}, []

        def launch(held):
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    results[held] = vm_host.install_yougori(held, self.url, self.root)
            except Exception as error:  # reported below with its harness
                errors.append((held, error))
        with patch.object(vm_host, "call", self.engine):
            threads = [threading.Thread(target=launch, args=(held,)) for held in ("opencode", "kilo")]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(60)
        self.assertEqual(errors, [])
        self.assertEqual(self.asked(BASE), 2)
        self.assertEqual(results["opencode"][0], results["kilo"][0])
        # Each import read a whole layout of its own launch's.
        self.assertEqual(len({str(item["layout"]) for item in self.engine.imports}), 2)
        self.assertTrue(all(len(item["files"]) == 3 for item in self.engine.imports), self.engine.imports)
        self.assertEqual((self.root / "images" / sha(BASE) / "image.zip").read_bytes(), BASE)
        self.assertEqual((self.root / "tools" / (sha(KILO) + ".tar.gz")).read_bytes(), KILO)
        self.assertEqual(leftovers(self.root), [])


class Delivery(unittest.TestCase):
    """prepare_tool with a pack declaration, against the VM's own guest (vm_guest, vm_package) over
    its control connection: what the VM receives, holds and starts."""

    def guest(self, image="yougori", pinned=None):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        root = Path(folder.name)
        (root / "harness-name").write_text(image + "\n")
        if pinned:
            (root / "tool-package.json").write_text(json.dumps(pinned))
        (root / "home").mkdir()
        state = vm_guest.State(root, root / "home")
        server = ThreadingHTTPServer(("127.0.0.1", 0), vm_guest.Control)
        server.state = state
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return state, root, vm_host.Control("http://abc123.localhost:%d/" % server.server_port)

    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.host = Path(folder.name)
        (self.host / "tools").mkdir()
        (self.host / "tools" / (sha(OPENCODE) + ".tar.gz")).write_bytes(OPENCODE)
        self.declaration = {"harness": "opencode", "sha256": sha(OPENCODE), "bytes": len(OPENCODE)}

    def prepare(self, control, declaration):
        with contextlib.redirect_stdout(io.StringIO()):
            vm_host.prepare_tool(control, self.host, declaration)

    def test_the_pack_arrives_checked_and_the_vm_holds_its_harness(self):
        state, root, control = self.guest()
        self.assertEqual(state.package.status()["phase"], "expecting")
        self.prepare(control, self.declaration)
        self.assertEqual((root / "tool/bin/app").read_bytes(), b"opencode")
        self.assertEqual(state.package.status(), {"phase": "ready", "offset": len(OPENCODE), "error": "", "harness": "opencode"})
        session = {"harness": "opencode", "answers": {}, "secrets": {}, "reach": {"mode": "inference", "sites": [], "targets": []}}
        environment = {}
        self.assertEqual(state.command(session, environment), ["run", "yougori"])
        self.assertEqual(environment["SOLVER_HARNESS"], "opencode")
        self.assertTrue((root / "home/.yougori/answers.json").is_file())
        # The base holds only the harness it was told, and only in a session.
        for data in ({**session, "harness": "strix"}, {"model": "m"}):
            with self.assertRaises(vm_guest.Refusal):
                state.command(data, {})

    def test_yougori_own_agent_is_declared_with_no_pack(self):
        state, root, control = self.guest()
        posted = []
        original = control.post

        def post(path, data):
            posted.append(path)
            return original(path, data)
        control.post = post
        self.prepare(control, {"harness": "yougori"})
        self.assertEqual(state.package.status(), {"phase": "ready", "offset": 0, "error": "", "harness": "yougori"})
        self.assertNotIn("/package/chunk", posted)
        self.assertEqual(state.command({"harness": "yougori"}, {}), ["run", "yougori"])

    def test_a_declaration_whose_reply_was_lost_is_sent_again(self):
        state, root, control = self.guest()
        original, expected = control.post, []

        def post(path, data):
            reply = original(path, data)
            if path == "/package/expect":
                expected.append(reply)
                if len(expected) == 1:
                    raise OSError("connection reset")  # the VM took it; its answer was lost
            return reply
        control.post = post
        self.prepare(control, self.declaration)
        self.assertEqual(len(expected), 2)
        self.assertEqual(state.package.status()["phase"], "ready")

    def test_a_vm_told_another_harness_or_taking_no_declaration_is_refused(self):
        state, _, control = self.guest()
        state.package.expect({"harness": "kilo", "sha256": sha(KILO), "bytes": len(KILO)})
        with self.assertRaises(vm_host.Refused) as refused:
            self.prepare(control, self.declaration)
        self.assertEqual(str(refused.exception), "This VM already expects another pack.")
        # The same harness with another pack is refused alike.
        state, _, control = self.guest()
        state.package.expect({"harness": "opencode", "sha256": sha(KILO), "bytes": len(KILO)})
        with self.assertRaises(vm_host.Refused):
            self.prepare(control, self.declaration)
        # An image made for one harness takes no declaration, pinned package or not.
        for pinned in ({"sha256": sha(OPENCODE), "bytes": len(OPENCODE)}, None):
            state, _, control = self.guest("opencode", pinned)
            with self.assertRaisesRegex(ValueError, "cannot take this harness's pack"):
                self.prepare(control, self.declaration)
            self.assertNotIn("harness", state.package.status())
        # The base, started as an image made for one harness would be, says so at once.
        state, _, control = self.guest()
        (self.host / "tool-package.json").write_text(json.dumps({"sha256": sha(OPENCODE), "bytes": len(OPENCODE)}))
        with self.assertRaisesRegex(ValueError, "starts harnesses only inside the Yougori harness"):
            self.prepare(control, None)
        self.assertEqual(state.package.status()["phase"], "expecting")

    def test_the_base_refuses_to_start_before_it_is_told_and_says_so_at_once(self):
        state, _, control = self.guest()
        with self.assertRaises(vm_host.Refused) as refused:
            control.post("/start", {"model": "m", "harness": "opencode"})
        self.assertEqual(str(refused.exception), "This VM has not been told which harness to run. Start the harness again.")
        self.assertFalse(state.started)
        for harness in ("opencode", None):
            with self.assertRaises(vm_guest.Refusal):
                state.command({"harness": harness}, {})
        with self.assertRaises(vm_host.Refused) as refused:
            control.post("/package/expect", {"harness": "Bad Name"})
        self.assertEqual(str(refused.exception), "Invalid pack declaration.")


class GuestThatEnds(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        reply = {"started": True, "tunnels": True, "yougori": True} if self.path == "/start" else \
            {"output": "", "requests": [], "tunnels": [], "exit": 0}
        raw = json.dumps(reply).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


class Launch(unittest.TestCase):
    """vm_host.launch: which images a session starts from, with what memory and which pack."""

    def setUp(self):
        guest = ThreadingHTTPServer(("127.0.0.1", 0), GuestThatEnds)
        threading.Thread(target=guest.serve_forever, daemon=True).start()
        self.addCleanup(guest.server_close)
        self.addCleanup(guest.shutdown)
        self.port = guest.server_port
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        self.key_file = Path(folder.name) / "opencode" / "api-key"
        self.key_file.parent.mkdir()
        self.key_file.write_text("is_test-key")
        self.images = Path(folder.name) / "yougori"
        self.images.mkdir()

    def launch(self, name, **keywords):
        # Kept on the test: `order` says when the images were ready and when the VM started.
        self.seen = seen = {"installed": [], "prepared": [], "order": []}
        declaration = {"harness": name, "sha256": "c" * 64, "bytes": 3}

        def call(action, **params):
            if action == "launch":
                seen["launched"] = params
                seen["order"].append("vm")
                return {"sandbox": "exe-" + "a" * 32}
            if action == "publish":
                return {"url": "http://abc123.localhost:%d/" % self.port}
            return {}

        def install_yougori(held, server, root):
            seen["installed"].append(("yougori", held, root))
            seen["order"].append("images")
            return "sha256:" + "d" * 64, declaration, 6

        def install(harness, server, root):
            seen["installed"].append(("own", harness, root))
            seen["order"].append("images")
            return "sha256:" + "e" * 64
        with patch.object(vm_host, "install_yougori", install_yougori), patch.object(vm_host, "install", install), \
                patch.object(vm_host, "call", call), patch.object(vm_host, "tidy", lambda sandbox, folder: False), \
                patch.object(vm_host, "prepare_tool", lambda control, root, declared=None: seen["prepared"].append((root, declared))), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(vm_host.launch(name, "http://127.0.0.1:9", self.key_file, "m", None, [], False, **keywords), 0)
        return seen, declaration

    def test_a_held_harness_starts_on_the_yougori_images_with_its_pack(self):
        seen, declaration = self.launch("opencode", harness="opencode", answers={}, secrets={}, images=self.images)
        self.assertEqual(seen["installed"], [("yougori", "opencode", self.images)])
        self.assertEqual((seen["launched"]["image"], seen["launched"]["memoryGb"]), ("sha256:" + "d" * 64, 6))
        self.assertEqual(seen["prepared"], [(self.images, declaration)])
        # The person's size wins over the pack's.
        seen, _ = self.launch("opencode", harness="opencode", answers={}, secrets={}, images=self.images, memory=12, cpu=6)
        self.assertEqual((seen["launched"]["memoryGb"], seen["launched"]["cpu"]), (12, 6))
        # Without a folder for the images, the key's folder keeps them.
        seen, _ = self.launch("opencode", harness="opencode", answers={}, secrets={})
        self.assertEqual(seen["installed"], [("yougori", "opencode", self.key_file.parent)])

    def test_a_harness_from_its_own_image_starts_as_before(self):
        seen, _ = self.launch("opencode")
        self.assertEqual(seen["installed"], [("own", "opencode", self.key_file.parent)])
        self.assertEqual(seen["prepared"], [(self.key_file.parent, None)])
        self.assertEqual((seen["launched"]["image"], seen["launched"]["memoryGb"]), ("sha256:" + "e" * 64, 4))

    def test_the_model_is_checked_once_the_images_are_ready_and_before_the_vm_starts(self):
        """The images can take minutes to arrive; the model may have dropped out meanwhile."""
        def catalog(server, secret):
            self.seen["order"].append("catalog")
            return [{"id": "m"}]
        for keywords in ({"harness": "opencode", "answers": {}, "secrets": {}, "images": self.images}, {}):
            seen, _ = self.launch("opencode", catalog=catalog, **keywords)
            self.assertEqual(seen["order"], ["images", "catalog", "vm"])


class Catalog(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        body = self.server.catalog if isinstance(self.server.catalog, bytes) else json.dumps(self.server.catalog).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class Preflight(unittest.TestCase):
    """preflight: inside the Yougori harness (`held`) or from the harness's own image (`setup`)."""

    def setUp(self):
        self.website = ThreadingHTTPServer(("127.0.0.1", 0), Catalog)
        threading.Thread(target=self.website.serve_forever, daemon=True).start()
        self.addCleanup(self.website.server_close)
        self.addCleanup(self.website.shutdown)

    def check(self, catalog, name, held):
        self.website.catalog = catalog
        with patch.object(vm_host, "ready"):
            vm_host.preflight(name, "http://127.0.0.1:%d" % self.website.server_port, held=held)

    def test_inside_yougori_reads_held_and_alone_reads_setup(self):
        unpublished = "The administrator has not published this harness's Sandbox VM image yet."
        catalog = {"harnesses": [
            {"id": "opencode", "setup": {"available": True}, "held": {"available": False, "reason": unpublished}},
            {"id": "yougori", "setup": {"available": False, "reason": harness_download.OWN_AGENT}, "held": {"available": True}}]}
        self.check(catalog, "opencode", held=False)
        self.check(catalog, "yougori", held=True)
        for name, held, said in (("opencode", True, unpublished), ("yougori", False, harness_download.OWN_AGENT)):
            with self.assertRaises(ValueError) as refused:
                self.check(catalog, name, held)
            self.assertEqual(str(refused.exception), said)
        # A website from before the Yougori harness says nothing of it.
        older = {"harnesses": [{"id": "opencode", "setup": {"available": True}}]}
        self.check(older, "opencode", held=False)
        with self.assertRaises(ValueError) as refused:
            self.check(older, "opencode", held=True)
        self.assertEqual(str(refused.exception), vm_host.WEBSITE_BEFORE_HELD)

    def test_the_websites_reason_reaches_the_person_as_plain_words(self):
        said = "\x1b]0;owned\x07\x1b[2JNot \u0085offered\x7f." + "x" * 400
        with self.assertRaises(ValueError) as refused:
            self.check({"harnesses": [{"id": "opencode", "held": {"available": False, "reason": said}}]}, "opencode", True)
        shown = str(refused.exception)
        self.assertTrue(shown.startswith("]0;owned[2JNot offered.xxx"), shown)
        self.assertEqual(len(shown), 300)
        self.assertFalse(any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in shown))
        for state in ({"available": False, "reason": 7}, {"available": "yes"}, {"available": False}):
            with self.assertRaises(ValueError) as refused:
                self.check({"harnesses": [{"id": "opencode", "held": state}]}, "opencode", True)
            self.assertEqual(str(refused.exception), "This website cannot start this harness yet.")
        for catalog in (b"not json", b"[1]", {"harnesses": [{"name": "opencode"}]}, {"harnesses": [{"id": "opencode", "held": []}]}):
            with self.assertRaisesRegex(ValueError, "Cannot check this harness on the server"):
                self.check(catalog, "opencode", True)


class PreflightOnTheWebsite(unittest.TestCase):
    """preflight against the template's own website, with its images published as an administrator would."""

    def test_a_harness_starts_inside_yougori_once_its_pack_is_published(self):
        import test_service
        from artifact_fixture import publish_catalog_fixtures, unpublish_catalog_fixtures
        flow = test_service.Flow()
        with patch.dict(os.environ):
            flow.setUp()
            self.addCleanup(flow.tearDown)
            publish_catalog_fixtures(flow.temp.name)
            with patch.object(vm_host, "ready"):
                vm_host.preflight("opencode", flow.url, held=True)
                vm_host.preflight("yougori", flow.url, held=True)
                unpublish_catalog_fixtures(flow.temp.name, ["opencode"])
                with self.assertRaises(ValueError) as refused:
                    vm_host.preflight("opencode", flow.url, held=True)
                self.assertEqual(str(refused.exception), harness_download.UNPUBLISHED)


if __name__ == "__main__":
    unittest.main()
