"""Launch real Yougori Sandbox VMs. No container engine or host-tool fallback."""
import base64
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from urllib.parse import urlsplit
import zipfile
import vm_relay
import vm_tunnel
from transport import opener as transport_opener

# The Yougori harness, which holds every other harness: its VM images are a few base images and a
# pack per harness (its engine), listed by /api/harness-image/yougori (harness_download.py).
YOUGORI = "yougori"
RUNTIME, PLATFORM = "yougori-sandbox-vm", "linux/amd64"
DIGEST = re.compile("[a-f0-9]{64}")
HARNESS = re.compile("[a-z][a-z0-9-]{0,31}")
# The launcher's bounds: an image archive, a tool package or pack, the largest root Yougori imports
# and the Yougori harness's image listing.
IMAGE_BYTES = 300 << 20
PACK_BYTES = 512 << 20
ROOT_GB = 8
LISTING_BYTES = 1 << 20
# What a website from before the Yougori harness says of every harness, as `yougori inference run` does.
WEBSITE_BEFORE_HELD = "This website does not start harnesses inside Yougori yet. Its administrator needs to update it."


def executable():
    value = os.environ.get("INFERENCE_SOLVER_YOUGORI") or shutil.which("yougori")
    if not value and os.name == "nt":
        candidate = Path(os.environ.get("LOCALAPPDATA", "")) / "Yougori/cli/yougori.exe"
        value = str(candidate) if candidate.is_file() else None
    if not value:
        raise ValueError("Install Yougori first, then run this harness again.")
    return value


# A Windows console gives Ctrl+C and Ctrl+Break to every process attached to it, and a process
# group of its own keeps out Ctrl+C alone. So each `yougori call` starts on a console of its own,
# without a window: no key pressed in the person's console reaches it, and none ends one part way
# (the stop after a session included). Elsewhere a child does what the launcher does with the
# keyboard's signals when it starts, and the cleanup after a session ignores them (Keyboard).
OWN_CONSOLE = {"creationflags": subprocess.CREATE_NO_WINDOW} if os.name == "nt" else {}


def call(action, **params):
    process = subprocess.run([executable(), "call", "sandbox_vm", "--file", "-", "--yes"],
        input=json.dumps({"action": action, **params}), text=True, capture_output=True, timeout=900, **OWN_CONSOLE)
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


def plain(text, most=300):
    """Words from the website as this launcher shows them: without control characters (C0, DEL,
    C1), at most `most` characters."""
    return "".join(c for c in text if not (ord(c) < 32 or 127 <= ord(c) <= 159))[:most]


def preflight(name, server, held=False):
    """Checks that the website can start `name` before anything is asked or signed in: inside the
    Yougori harness (`held`: its `held`, as `yougori inference run` starts every harness) or from
    the harness's own image (its `setup`, as a launcher for that harness alone starts it). Raises
    the website's reason."""
    ready()
    opener=transport_opener()
    try:
        with opener.open(server+'/api/harnesses',timeout=30) as response:
            catalog=json.loads(response.read(1024*1024))
        item=next(h for h in catalog['harnesses'] if isinstance(h,dict) and h.get('id')==name)
    except (OSError,ValueError,KeyError,TypeError,StopIteration):
        raise ValueError('Cannot check this harness on the server. Check the website connection and try again.') from None
    if held and 'held' not in item:
        raise ValueError(WEBSITE_BEFORE_HELD)
    state=item.get('held' if held else 'setup')
    if not isinstance(state,dict):
        raise ValueError('Cannot check this harness on the server. Check the website connection and try again.')
    if state.get('available') is not True:
        reason=state.get('reason')
        raise ValueError((plain(reason) if isinstance(reason,str) else '') or 'This website cannot start this harness yet.')


def artifact_base(server, descriptor):
    base = descriptor.get('download_base', server + '/api/harness-image')
    if not isinstance(base, str):
        raise ValueError('Invalid artifact publisher path.')
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


def published(opener, url, most, missing):
    """The JSON object the website publishes at `url` (at most `most` bytes); `missing` when it
    publishes none there."""
    try:
        with opener.open(url, timeout=30) as response:
            raw = response.read(most + 1)
        value = json.loads(raw)
    except (OSError, ValueError, http.client.HTTPException):
        raise ValueError(missing) from None
    if len(raw) > most or not isinstance(value, dict):
        raise ValueError(missing)
    return value


def write_atomically(path, text):
    """Writes `path` whole or not at all: a launch reading it at the same time finds the earlier
    text or this one."""
    handle, temporary = tempfile.mkstemp(prefix=path.name + ".", suffix=".partial", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def verified(path, digest, size):
    """Whether `path` is the file of this sha256 and size."""
    if not path.is_file() or path.stat().st_size != size:
        return False
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest() == digest


def printed(text):
    print(text, flush=True)


def fetch(opener, url, path, digest, size, label, say=printed, progress=None):
    """Makes `path` the file of this sha256 and size: kept when it already is, else downloaded from
    `url` and checked before it takes the name. Each download goes to a file of its own launch,
    so launches fetching one file at the same time never write into each other's. `say` shows
    what it does (the terminal, or a switch's progress in the screen); `progress(done, size)` is
    told each megabyte that arrives."""
    if verified(path, digest, size):
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    say("Downloading " + label + " (" + str(round(size / (1024 * 1024))) + " MB)...")
    handle, name = tempfile.mkstemp(prefix=path.name + ".", suffix=".partial", dir=path.parent)
    temporary = Path(name)
    try:
        sha, total = hashlib.sha256(), 0
        with os.fdopen(handle, "wb") as output, opener.open(url, timeout=180) as response:
            while block := response.read(1024 * 1024):
                total += len(block)
                if total > size:
                    raise ValueError("The download of the " + label + " exceeded its declared size.")
                sha.update(block)
                output.write(block)
                if progress is not None:
                    progress(total, size)
        if total != size or sha.hexdigest() != digest:
            raise ValueError("The download of the " + label + " did not match its checksum.")
        try:
            os.replace(temporary, path)
        except PermissionError:
            # Windows keeps a file another launch is reading from being replaced: that launch
            # put it there, checked as this one checks it.
            if not verified(path, digest, size):
                raise
    finally:
        temporary.unlink(missing_ok=True)


def unpack(archive, layout):
    """The OCI layout in a verified image archive, within the launcher's bounds."""
    try:
        with zipfile.ZipFile(archive) as package:
            entries = package.infolist()
            names = [info.filename for info in entries]
            if len(names) > 256 or len(names) != len(set(names)) or sum(info.file_size for info in entries) > IMAGE_BYTES:
                raise ValueError("Invalid OCI archive bounds.")
            for info in entries:
                entry = info.filename
                if not (entry in ("oci-layout", "index.json") or re.fullmatch("blobs/sha256/[a-f0-9]{64}", entry)) or info.file_size > 256 << 20:
                    raise ValueError("Invalid OCI archive entry.")
                target = layout / entry
                target.parent.mkdir(exist_ok=True, parents=True)
                with package.open(info) as source, target.open("wb") as output:
                    shutil.copyfileobj(source, output, 1024 * 1024)
    except zipfile.BadZipFile:
        raise ValueError("The VM image archive is damaged. The administrator needs to prepare it again.") from None


def imported(opener, url, folder, digest, size, root_gb, record):
    """The engine's image of the archive of this sha256 with `root_gb` GB of root: the one imported
    before, as `record` says, while the engine still has it; otherwise the archive (kept in
    `folder`; downloaded from `url` unless it is there whole) imported now, from a layout of this
    launch's own, removed once Yougori holds its copy. Returns the image's identity."""
    try:
        cached = json.loads(record.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        cached = None
    if isinstance(cached, dict) and cached.get("archive") == digest and cached.get("root_gb") == root_gb:
        images = call("image", operation="list")
        if isinstance(images, list) and any(isinstance(image, dict) and image.get("id") == cached.get("digest") for image in images):
            return cached["digest"]
    # Only hash-pinned public artifacts use the configured publisher. No account
    # credentials, session cookies or inference requests go to that destination.
    folder.mkdir(parents=True, exist_ok=True)
    archive = folder / "image.zip"
    fetch(opener, url, archive, digest, size, "Sandbox VM image")
    layout = Path(tempfile.mkdtemp(prefix="layout-", dir=folder))
    try:
        unpack(archive, layout)
        print("Preparing the verified image in Yougori...", flush=True)
        result = call("image", operation="import", layout=str(layout), ownerSelected=True, rootGb=root_gb)
    finally:
        shutil.rmtree(layout, ignore_errors=True)
    identity = result.get("id") if isinstance(result, dict) else None
    if not isinstance(identity, str) or not re.fullmatch("sha256:[a-f0-9]{64}", identity):
        raise ValueError("Yougori did not return an imported image identity.")
    try:
        write_atomically(record, json.dumps({"digest": identity, "archive": digest, "root_gb": root_gb}))
    except OSError:
        pass  # Only a shortcut for later launches, which import the kept archive again.
    return identity


def install(name, server, root):
    """Prepares `name`'s own Sandbox VM image, as /api/harness-image/NAME describes it, in `root`:
    its image archive and tool package, each kept by its sha256 and checked, the image imported
    once for its root size, and the tool package's pin in root/tool-package.json for
    prepare_tool. Returns the imported image's identity."""
    root_gb = 3 if name == 'shannon' else 2
    ready()
    opener = transport_opener()
    descriptor = published(opener, server + "/api/harness-image/" + name, 65536,
                           "This server has not prepared this harness's Yougori VM image yet.")
    digest, size = descriptor.get("sha256"), descriptor.get("bytes")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest) or type(size) is not int or not 0 < size <= IMAGE_BYTES:
        raise ValueError("Invalid VM image descriptor.")
    if descriptor.get("runtime") != RUNTIME or descriptor.get("platform") != PLATFORM:
        raise ValueError("This VM image targets an unsupported runtime or platform.")
    download_base = artifact_base(server, descriptor)
    tool = descriptor.get('tool') or None
    if tool:
        if (not isinstance(tool, dict) or not isinstance(tool.get('sha256'), str) or not DIGEST.fullmatch(tool['sha256'])
                or type(tool.get('bytes')) is not int or not 0 < tool['bytes'] <= PACK_BYTES):
            raise ValueError('Invalid tool package descriptor.')
        tool = {'sha256': tool['sha256'], 'bytes': tool['bytes']}
        fetch(opener, download_base + '/' + name + '/' + tool['sha256'] + '/tool', root / 'tools' / (tool['sha256'] + '.tar.gz'),
              tool['sha256'], tool['bytes'], 'tool files')
    write_atomically(root / 'tool-package.json', json.dumps(tool))
    return imported(opener, download_base + "/" + name + "/" + digest, root / "images" / digest, digest, size, root_gb,
                    root / "vm-image.json")


def yougori_pack(listing, held):
    """The pack `held` starts from in the Yougori harness's image listing and the base it starts on,
    checked as the website checks them (harness_download.yougori_image): Yougori's own agent
    needs no pack. Raises ValueError."""
    def count(number, most):
        return type(number) is int and 0 < number <= most
    invalid = "The website's Yougori harness images are not valid. Its administrator needs to prepare them again."
    if (listing.get("runtime") != RUNTIME or listing.get("platform") != PLATFORM or not isinstance(listing.get("bases"), dict)
            or not isinstance(listing.get("packs"), dict)):
        raise ValueError(invalid)
    pack = listing["packs"].get(held)
    if pack is None:
        raise ValueError("This website has not made this harness ready inside the Yougori harness.")
    base = listing["bases"].get(pack.get("base")) if isinstance(pack, dict) and isinstance(pack.get("base"), str) else None
    if (not isinstance(base, dict) or not isinstance(base.get("sha256"), str) or not DIGEST.fullmatch(base["sha256"])
            or not count(base.get("bytes"), IMAGE_BYTES) or not count(base.get("disk"), ROOT_GB)
            or not count(pack.get("disk"), base["disk"]) or not count(pack.get("memory"), 1024) or pack["memory"] < base["disk"] + 1):
        raise ValueError(invalid)
    if held == YOUGORI:
        if any(key in pack for key in ("sha256", "bytes", "version")):
            raise ValueError(invalid)
    elif (not isinstance(pack.get("sha256"), str) or not DIGEST.fullmatch(pack["sha256"]) or not count(pack.get("bytes"), PACK_BYTES)
            or not isinstance(pack.get("version"), str) or not pack["version"]):
        raise ValueError(invalid)
    return pack, base


def install_yougori(held, server, root):
    """Prepares the Yougori harness's images for a session holding `held` (Yougori's own agent
    included), as /api/harness-image/yougori lists them: the base that harness starts on, imported
    once for its root size, and the harness's pack, each kept in `root` by its sha256 and checked.
    `root` is shared by every harness and by launches running at once. Returns the imported base's
    identity, the declaration the VM gets before any of the pack (prepare_tool; {"harness"} alone
    when the harness needs none) and the VM's memory in GB when the person kept the default."""
    if not isinstance(held, str) or not HARNESS.fullmatch(held):
        raise ValueError("Choose the harness Yougori holds.")
    ready()
    opener = transport_opener()
    listing = published(opener, server + "/api/harness-image/" + YOUGORI, LISTING_BYTES,
                        "This server has not prepared the Yougori harness's VM images yet.")
    pack, base = yougori_pack(listing, held)
    download_base = artifact_base(server, listing)
    declaration = {"harness": held}
    if held != YOUGORI:
        fetch(opener, download_base + "/" + YOUGORI + "/" + pack["sha256"] + "/tool", root / "tools" / (pack["sha256"] + ".tar.gz"),
              pack["sha256"], pack["bytes"], "the harness's files")
        declaration.update(sha256=pack["sha256"], bytes=pack["bytes"])
    folder = root / "images" / base["sha256"]
    identity = imported(opener, download_base + "/" + YOUGORI + "/" + base["sha256"], folder, base["sha256"], base["bytes"],
                        base["disk"], folder / "imported.json")
    return identity, declaration, pack["memory"]


def switch_list(server, held, memory, known, opener=None):
    """What a Yougori harness session gets at /start to switch harness from its screen (/harness):
    the website's harnesses (GET /api/harnesses) that it offers, that start inside the Yougori
    harness here and that this launcher knows (`known`), Yougori's own agent first, then the coding
    and the security ones, each with its questions, the base it starts on and its memory (the Yougori
    harness's image listing); the base this VM starts on (that of `held`), its `memory` and the
    website's address. {} when the website lists none, or cannot be read: the screen then says
    switching is not offered."""
    opener = opener or transport_opener()
    try:
        catalog = published(opener, server + "/api/harnesses", 1 << 20, "")
        listing = published(opener, server + "/api/harness-image/" + YOUGORI, LISTING_BYTES, "")
        vm_base = yougori_pack(listing, held)[0]["base"]
    except ValueError:
        return {}
    entries = []
    for item in catalog.get("harnesses") or []:
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or item["id"] not in known:
            continue
        if item.get("offered") is False or not isinstance(item.get("held"), dict):
            continue
        try:
            pack = yougori_pack(listing, item["id"])[0]
        except ValueError:
            continue
        questions = item.get("questions") if isinstance(item.get("questions"), list) else []
        reason = item["held"].get("reason")
        entries.append({"id": item["id"], "name": plain(item.get("name") or item["id"], 80),
                        "category": "security" if item.get("category") == "security" else "coding",
                        "description": plain(item.get("description") or "", 600) if isinstance(item.get("description"), str) else "",
                        "questions": questions[:32], "base": pack["base"], "memory": pack["memory"],
                        "ready": item["held"].get("available") is True,
                        "reason": plain(reason, 300) if isinstance(reason, str) else ""})
    entries.sort(key=lambda entry: (entry["id"] != YOUGORI, entry["category"] == "security"))
    if not any(entry["id"] == YOUGORI for entry in entries):
        return {}
    fields = {"harnesses": entries, "vm_base": vm_base, "vm_memory": memory, "server": server}
    # The VM takes at most 96 KiB of them: the descriptions go first, then the list does.
    if len(json.dumps(fields)) > 90 * 1024:
        for entry in entries:
            entry["description"] = ""
    return fields if len(json.dumps(fields)) <= 90 * 1024 else {}


class Cancelled(ValueError):
    """The screen stopped waiting for a switch (Esc)."""


class Relaunch:
    """A session that ended so the next harness starts in a new VM (the screen's /harness, a new-VM
    switch): the request the screen made, with its secrets, kept in memory only."""

    def __init__(self, request):
        self.request = request


def switch_in_place(control, request, entries, vm_base, server, images, opener=None):
    """Brings the harness the screen switched to into the running VM (runs on a thread of its own,
    so the screen stays live): checked against the session's list and the VM's base, its pack
    downloaded into `images` and delivered as at the start, its progress shown in the screen. The VM
    is told it is done, or why it failed."""
    identity, harness = request["id"], request["harness"]
    entry = entries.get(harness)
    name = entry["name"] if entry else harness
    last = [0.0]

    def say(text, every=0.0):
        now = time.monotonic()
        if now - last[0] < every:
            return
        last[0] = now
        try:
            reply = control.post("/switch/progress", {"id": identity, "text": text})
        except (OSError, ValueError, http.client.HTTPException):
            return
        if reply.get("cancelled"):
            raise Cancelled("Cancelled.")

    try:
        if entry is None:
            raise ValueError("This inference does not offer " + name + " here.")
        if not entry["ready"]:
            raise ValueError(entry["reason"] or name + " cannot start here yet.")
        opener = opener or transport_opener()
        listing = published(opener, server + "/api/harness-image/" + YOUGORI, LISTING_BYTES,
                            "This server has not prepared the Yougori harness's VM images yet.")
        pack, _ = yougori_pack(listing, harness)
        if pack["base"] != vm_base:
            raise ValueError(name + " needs a new VM. Choose it again in /harness to start one.")
        declaration = {"harness": harness}
        if harness != YOUGORI:
            mb = lambda count: str(round(count / (1024 * 1024)))
            fetch(opener, artifact_base(server, listing) + "/" + YOUGORI + "/" + pack["sha256"] + "/tool",
                  images / "tools" / (pack["sha256"] + ".tar.gz"), pack["sha256"], pack["bytes"], name + "'s files", say=say,
                  progress=lambda done, size: say("Downloading " + name + ": " + str(done * 100 // size) + "% (" + mb(done)
                                                  + " of " + mb(size) + " MB)", every=0.5))
            declaration.update(sha256=pack["sha256"], bytes=pack["bytes"])
        prepare_tool(control, images, declaration, say=lambda text: say(text.replace("Preparing tool", "Installing " + name)))
        control.post("/switch/done", {"id": identity})
    except (ValueError, OSError, http.client.HTTPException) as error:
        reason = plain(str(error)) or name + " could not be started."
        try:
            control.post("/switch/failed", {"id": identity, "reason": reason})
        except (OSError, ValueError, http.client.HTTPException):
            pass


# The screen's exit code once a new-VM switch is accepted: the run goes on in a new VM.
RELAUNCH_EXIT = 75


def take_switch(control, request, entries, vm_base, memory, server, images):
    """A switch the screen asked for, as the VM passes it on (/poll). In place: brought into this VM
    on a thread of its own (switch_in_place). A new VM: checked against the session's list and
    accepted; the Relaunch the session ends with once the screen exits RELAUNCH_EXIT, with the
    harness's name, kind and memory. None otherwise."""
    identity, harness = request.get("id"), request.get("harness")
    if not isinstance(identity, str) or not isinstance(harness, str):
        return None
    if request.get("mode") == "in-place":
        threading.Thread(target=switch_in_place, args=(control, request, entries, vm_base, server, images), daemon=True).start()
        return None
    entry = entries.get(harness)
    reason = ("This inference does not offer " + harness + " here." if entry is None
              else "" if entry["ready"] else entry["reason"] or entry["name"] + " cannot start here yet.")
    try:
        if reason:
            control.post("/switch/failed", {"id": identity, "reason": reason})
            return None
        control.post("/switch/accepted", {"id": identity})
    except (OSError, ValueError, http.client.HTTPException):
        return None
    wanted = request.get("memory") if type(request.get("memory")) is int else 0
    return Relaunch({**request, "name": entry["name"], "category": entry["category"],
                     "memory": max(wanted, entry["memory"], 1)})


def run_session(name, server, key_file, model, workspace, interactive=True, cpu=None, memory=None, internet=False,
                sites=None, targets=None, answers=None, secrets=None, images=None, catalog=None, known=None, ask=input):
    """A Yougori harness session holding `name`, through every new VM its screen switches to: each
    one ends the VM before (its copy with changes kept for review) and starts the next with the same
    model, folder and CPU, the next harness's answers and secrets, and memory enough for it. A
    security harness reaches only its targets and this inference; when they go beyond what this run
    already held, the person confirms them here, on their own terminal, never in the VM. A coding
    harness keeps the run's reach. The review lines of every VM come at the end. The exit code."""
    reviews, held, chosen = [], set(targets or []), memory
    try:
        while True:
            result = launch(name, server, key_file, model, workspace, [], interactive, cpu=cpu, memory=memory,
                            internet=internet, sites=sites, targets=targets, harness=name, answers=answers, secrets=secrets,
                            images=images, catalog=catalog, known=known, reviews=reviews)
            if not isinstance(result, Relaunch):
                return result
            request = result.request
            label, wanted = request["name"], [t for t in request.get("targets") or [] if isinstance(t, str)]
            if request["category"] == "security":
                wider = [target for target in wanted if target not in held]
                if wider:
                    question = ("Start " + label + " in a new VM that reaches only " + shown_targets(wanted)
                                + " and this inference? [y/N] ")
                    if not (interactive and sys.stdin.isatty()):
                        print("\n" + label + " needs a new VM that reaches " + shown_targets(wanted)
                              + ", and only the person at this terminal can allow that. Nothing more was started.", flush=True)
                        return 0
                    if ask("\n" + question).strip().lower() not in ("y", "yes"):
                        print("Nothing more was started.", flush=True)
                        return 0
                    held.update(wanted)
                internet, sites, targets = False, None, wanted or None
            name, answers, secrets = request["harness"], request.get("answers") or {}, request.get("secrets") or {}
            memory = max(chosen or 0, request["memory"])
            print("\nStarting " + label + " in a new VM...", flush=True)
    finally:
        if reviews:
            print("\nYour original project is unchanged. Review the VM " + ("copies" if len(reviews) > 1 else "copy")
                  + " with:\n" + "\n".join(reviews), flush=True)


class Refused(ValueError):
    """The VM refused a request for a reason that asking again cannot change (HTTP 409)."""


class Ended(ValueError):
    """What a message was for has ended in the VM (HTTP 410): a model request its client left or
    stopped waiting for, or a tunnel that closed. Nothing more goes to it."""


class Unreached(OSError):
    """A control request whose connection to the VM's publication never opened: nothing of it
    reached the VM, so sending it again is safe."""


# How long a control connection may take to open, and how long a session keeps asking again when
# the publication takes none (seen while a switch's pack moved beside the session's own requests).
CONNECT_SECONDS = 10
UNREACHED_SECONDS = 120


def again(post, path, data, done=None, seconds=UNREACHED_SECONDS):
    """`post(path, data)`, asked again while its connection does not open, for up to `seconds` in
    all (and not once the session is `done`)."""
    first = None
    while True:
        try:
            return post(path, data)
        except Unreached:
            first = first or time.monotonic()
            if time.monotonic() - first > seconds or (done is not None and done.is_set()):
                raise
            time.sleep(.5)


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
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=CONNECT_SECONDS)
        try:
            try:
                connection.connect()
            except OSError as error:
                raise Unreached(str(error)) from error
            connection.sock.settimeout(35)
            connection.request("POST", path, body=json.dumps(data).encode(), headers={
                "Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(6 * 1024 * 1024 + 1)
            if response.status == 409 and len(raw) <= 4096:
                try:
                    said = json.loads(raw).get("error")
                except (ValueError, AttributeError):
                    said = None
                raise Refused(said[:300] if isinstance(said, str) and said else "The VM refused this harness session.")
            if response.status == 410:
                raise Ended("The VM no longer waits for this.")
            if response.status != 200 or len(raw) > 6 * 1024 * 1024:
                raise ValueError("The Yougori VM connection failed (HTTP " + str(response.status) + "): " + raw[:350].decode('utf-8','replace'))
            return json.loads(raw)
        finally:
            connection.close()


def declare(control, declaration, status):
    """Tells a VM on the Yougori harness's base which harness's pack to expect (`declaration`),
    before any of it. The VM takes one declaration, answers the same one again unchanged (so one
    whose reply was lost is sent again) and refuses any other. Returns the VM's status once it
    holds the declared harness. An image that takes no declaration (made for one harness, or a
    base older than packs) is refused before anything is sent."""
    cannot = ("This VM's image cannot take this harness's pack. Ask the administrator to publish newer Yougori "
              "harness images.")
    if status.get('phase') != 'expecting' and 'harness' not in status:
        raise ValueError(cannot)
    try:
        status = control.post('/package/expect', declaration)
    except Refused:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        status = control.post('/package/expect', declaration)
    if status.get('harness') != declaration['harness']:
        raise ValueError(cannot)
    return status


def prepare_tool(control,root,declaration=None,say=printed):
    """Delivers the harness's tool package from root/tools into the VM through its private control
    connection, and waits until the VM has checked and unpacked it. An image made for one harness
    pins its package (root/tool-package.json, written by install). The Yougori harness's base pins
    none: with `declaration` (install_yougori), the VM is first told which harness's pack to
    expect, with its hash and size, or that the harness needs none. During a session, a switch
    declares the next harness's pack the same way, and the VM puts it in the place of the one
    installed. `say` shows the progress (the terminal, or the screen during a switch)."""
    spec=declaration if declaration is not None else json.loads((root/'tool-package.json').read_text())
    if not spec: return
    if spec.get('sha256'): say('Preparing the tool inside your VM...')
    deadline=time.monotonic()+1800
    status=None
    while time.monotonic()<deadline:
        try: status=control.post('/package/status',{});break
        except (OSError,ValueError,http.client.HTTPException):time.sleep(.5)
    if status is None: raise ValueError('The VM tool installer did not become ready.')
    if declaration is not None:
        status=declare(control,declaration,status)
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
                    say('Preparing tool: '+str(progress)+'% ('+str(offset//(1024*1024))+'/'+str(spec['bytes']//(1024*1024))+' MB)')
        control.post('/package/finish',{})
    while time.monotonic()<deadline:
        status=control.post('/package/status',{})
        if status['phase']=='ready':return
        if status['phase']=='failed':raise ValueError(status['error'])
        if status['phase']=='expecting':
            # The Yougori harness's base waits to be told which harness it holds; only a session
            # inside the Yougori harness tells it.
            raise ValueError("This VM's image starts harnesses only inside the Yougori harness. Update Yougori: yougori update")
        time.sleep(.5)
    raise ValueError('The VM tool installation timed out.')


def _xterm_keys():
    """The keys a Windows console gives as two characters (msvcrt.getwch: "\\x00" or "\\xe0", then
    a code; the code alone tells the key), as xterm sends them: the arrows, Home, End, Insert,
    Delete, PageUp and PageDown, alone and with Ctrl or Alt, and F1 to F12, alone and with Shift,
    Ctrl or Alt. The console gives Shift with the others as the key alone, and Ctrl+PageUp on
    the grey keys as F12."""
    def modified(sequence, modifier):
        # xterm's modifier parameter: 2 Shift, 3 Alt, 5 Ctrl.
        if modifier == 1:
            return sequence
        if sequence.startswith("\x1bO"):
            return "\x1b[1;" + str(modifier) + sequence[2:]
        if sequence.endswith("~"):
            return sequence[:-1] + ";" + str(modifier) + "~"
        return "\x1b[1;" + str(modifier) + sequence[2:]
    keys = {}
    cursor = {"up": "\x1b[A", "down": "\x1b[B", "right": "\x1b[C", "left": "\x1b[D", "home": "\x1b[H", "end": "\x1b[F",
              "insert": "\x1b[2~", "delete": "\x1b[3~", "pageup": "\x1b[5~", "pagedown": "\x1b[6~"}
    for modifier, codes in ((1, {"up": 72, "down": 80, "right": 77, "left": 75, "home": 71, "end": 79, "insert": 82, "delete": 83,
                                 "pageup": 73, "pagedown": 81}),
                            (5, {"up": 141, "down": 145, "right": 116, "left": 115, "home": 119, "end": 117, "insert": 146,
                                 "delete": 147, "pageup": 132, "pagedown": 118}),
                            (3, {"up": 152, "down": 160, "right": 157, "left": 155, "home": 151, "end": 159, "insert": 162,
                                 "delete": 163, "pageup": 153, "pagedown": 161})):
        keys.update({chr(code): modified(cursor[key], modifier) for key, code in codes.items()})
    function = ["\x1bOP", "\x1bOQ", "\x1bOR", "\x1bOS", "\x1b[15~", "\x1b[17~", "\x1b[18~", "\x1b[19~", "\x1b[20~", "\x1b[21~",
                "\x1b[23~", "\x1b[24~"]
    for modifier, first, eleventh in ((1, 59, 133), (2, 84, 135), (5, 94, 137), (3, 104, 139)):
        codes = [*range(first, first + 10), eleventh, eleventh + 1]
        keys.update({chr(code): modified(sequence, modifier) for code, sequence in zip(codes, function)})
    keys["\x0f"] = "\x1b[Z"  # Shift+Tab, when the console gives it as a key rather than a Tab
    return keys


WINDOWS_KEYS = _xterm_keys()
# The VM takes at most 16 KiB of terminal input a request (vm_guest), and one key adds at most this.
INPUT_BYTES = 16384
KEY_BYTES = max(3, *map(len, WINDOWS_KEYS.values()))


class ShiftTab:
    """Tells Shift+Tab from Tab on a Windows console, which msvcrt.getwch gives alike: the key it
    gives next is the first key press waiting in the console's input that types a character or
    is a key it gives as two characters. Peeked from the input msvcrt reads (CONIN$), never taken."""
    KEY_EVENT, VK_TAB, SHIFT, CONTROL_OR_ALT = 1, 0x09, 0x10, 0x0F
    # Shift, Ctrl, Alt, Caps Lock, the Windows and menu keys, Num Lock, Scroll Lock (and their
    # left and right): a press of these alone gives msvcrt nothing.
    MODIFIERS = {0x10, 0x11, 0x12, 0x14, 0x5B, 0x5C, 0x5D, 0x90, 0x91, 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5}

    def __init__(self):
        import ctypes
        from ctypes import wintypes

        class Key(ctypes.Structure):
            _fields_ = [("down", wintypes.BOOL), ("repeat", wintypes.WORD), ("key", wintypes.WORD), ("scan", wintypes.WORD),
                        ("char", wintypes.WCHAR), ("state", wintypes.DWORD)]

        class Event(ctypes.Union):
            _fields_ = [("key", Key), ("size", ctypes.c_byte * 16)]

        class Record(ctypes.Structure):
            _fields_ = [("type", wintypes.WORD), ("event", Event)]
        self.ctypes = ctypes
        self.kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.kernel32.CreateFileW.restype = wintypes.HANDLE
        self.kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                              wintypes.DWORD, wintypes.HANDLE]
        self.kernel32.PeekConsoleInputW.argtypes = [wintypes.HANDLE, ctypes.POINTER(Record), wintypes.DWORD,
                                                    ctypes.POINTER(wintypes.DWORD)]
        self.kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        # GENERIC_READ | GENERIC_WRITE, shared for reading and writing, OPEN_EXISTING.
        handle = self.kernel32.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)
        self.handle = handle if handle not in (None, wintypes.HANDLE(-1).value) else None
        self.records = (Record * 64)()
        self.count = wintypes.DWORD()

    def __call__(self):
        if self.handle is None or not self.kernel32.PeekConsoleInputW(self.handle, self.records, len(self.records),
                                                                      self.ctypes.byref(self.count)):
            return False
        for record in self.records[:self.count.value]:
            key = record.event.key
            if record.type != self.KEY_EVENT or not key.down or (key.char == "\0" and key.key in self.MODIFIERS):
                continue
            return (key.char == "\t" and key.key == self.VK_TAB and bool(key.state & self.SHIFT)
                    and not key.state & self.CONTROL_OR_ALT)
        return False

    def close(self):
        if self.handle is not None:
            self.kernel32.CloseHandle(self.handle)
            self.handle = None


def console_input(msvcrt, done, shift_tab=lambda: False):
    """Everything waiting in the Windows console, at once, as an xterm sends it; None after Ctrl+].
    A terminal answers a harness's questions (its colours, modes, cursor position) with escape
    sequences: sent a character at a time, an answer reaches the harness too slowly to be read as
    one, and the harness shows it as typed text. `shift_tab` says whether the key msvcrt gives next
    is Shift+Tab, which it gives as a Tab (ShiftTab)."""
    typed, size = [], 0
    # Room for one more key and, after a character's first half, its second: within the VM's
    # bound a request, and never half a character left for the next.
    while size <= INPUT_BYTES - 2 * KEY_BYTES or (typed and "\ud800" <= typed[-1] <= "\udbff"):
        if not msvcrt.kbhit():
            # The rest of an answer may still be arriving.
            if not typed or "\x1b" not in "".join(typed[-64:]) or done.wait(.005) or not msvcrt.kbhit():
                break
        shifted = shift_tab()
        char = msvcrt.getwch()
        if char in ("\x00", "\xe0"):
            char = WINDOWS_KEYS.get(msvcrt.getwch(), "")
        elif char == "\t" and shifted:
            char = "\x1b[Z"
        if char == "\x1d":
            return None
        typed.append(char)
        size += len(char.encode("utf-8", "surrogatepass"))
    # A character beyond U+FFFF comes as two halves, neither of which is UTF-8 alone.
    return "".join(typed).encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


class ConsoleKeys:
    """Ctrl+C as a key of the session on a Windows console. While the console's input mode has
    ENABLE_PROCESSED_INPUT, a Ctrl+C is a signal: it would end the launcher, and the session with
    it, and the harness, whose own screen takes Ctrl+C, would never see it. take() clears that flag
    for the session; restore() puts back exactly the mode the console had, however the session ends.
    msvcrt.getwch sets the mode to 0 for each key and back to what it found, so keys are read
    under the lock restore() takes, and none after it. Ctrl+] still ends the session."""
    PROCESSED_INPUT = 0x0001

    def __init__(self):
        self.lock = threading.Lock()
        self.kernel32 = self.handle = self.mode = None
        self.closed = False

    def take(self):
        """Clears ENABLE_PROCESSED_INPUT on the console's input. Whether it did: a launcher without
        a console has none to change."""
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                         wintypes.DWORD, wintypes.HANDLE]
        kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        # The console's input, which msvcrt reads (CONIN$): GENERIC_READ | GENERIC_WRITE, shared
        # for reading and writing, OPEN_EXISTING.
        handle = kernel32.CreateFileW("CONIN$", 0xC0000000, 3, None, 3, 0, None)
        if handle in (None, wintypes.HANDLE(-1).value):
            return False
        mode = wintypes.DWORD()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)) or \
                not kernel32.SetConsoleMode(handle, mode.value & ~self.PROCESSED_INPUT):
            kernel32.CloseHandle(handle)
            return False
        self.kernel32, self.handle, self.mode = kernel32, handle, mode.value
        return True

    def read(self, msvcrt, done, shift_tab):
        """What console_input gives, read under the lock; nothing once restore() has run."""
        with self.lock:
            return "" if self.closed else console_input(msvcrt, done, shift_tab)

    def restore(self):
        """Puts back the mode take() found. No key is read after it."""
        with self.lock:
            self.closed = True
            if self.handle is not None:
                self.kernel32.SetConsoleMode(self.handle, self.mode)
                self.kernel32.CloseHandle(self.handle)
                self.handle = None


def terminal_input(control, done, keys=None):
    """Sends what the person types to the VM until the session ends (`done`) or Ctrl+] ends it. On
    a Windows console, `keys` (ConsoleKeys) reads the keys while the session holds the console."""
    try:
        if os.name == "nt":
            import msvcrt
            shift_tab = ShiftTab()
            read = keys.read if keys else console_input
            try:
                while not done.is_set():
                    if not msvcrt.kbhit():
                        done.wait(.02)
                        continue
                    text = read(msvcrt, done, shift_tab)
                    if text is None:
                        done.set()
                        return
                    if text:
                        again(control.post, "/input", {"data": base64.b64encode(text.encode()).decode()}, done)
            finally:
                shift_tab.close()
        else:
            import select
            while not done.is_set():
                if select.select([sys.stdin], [], [], .1)[0]:
                    raw = os.read(sys.stdin.fileno(), 16384)
                    if not raw or b"\x1d" in raw:
                        done.set()
                        return
                    again(control.post, "/input", {"data": base64.b64encode(raw).decode()}, done)
    except (OSError, ValueError, http.client.HTTPException):
        done.set()


class Screen:
    """The person's terminal while a session's output passes to it (`output`; None when it is not a
    terminal). What that output turns on is followed as it passes, a sequence perhaps split
    between two packets, so a session ending without its program turning it off again (the VM
    stopped, the connection was lost, Ctrl+]) leaves the terminal as it was: the keyboard
    protocol's flags popped, mouse and focus reports, bracketed paste, synchronized output and
    application cursor keys off, the cursor shown, the main screen back, colours reset."""
    SEQUENCE = re.compile(rb"\x1b\[(?:\?([0-9;]*)([hl])|([<>])([0-9]*)u)")
    PARTIAL = re.compile(rb"\x1b(?:\[(?:\?[0-9;]*|[<>][0-9]*)?)?")
    # Turned off in this order, before the cursor is shown and the main screen comes back.
    OFF = (1000, 1002, 1003, 1005, 1006, 1015, 1004, 2004, 2026, 1)
    SCREENS = (1049, 1047, 47)

    def __init__(self, output=None):
        self.output = output
        self.modes = {}
        self.pushed = 0
        self.tail = b""
        self.console = None

    def feed(self, data):
        text = self.tail + data
        end = 0
        for match in self.SEQUENCE.finditer(text):
            end = match.end()
            if match.group(2):
                for mode in match.group(1).split(b";"):
                    if mode.isdigit():
                        self.modes[int(mode)] = match.group(2) == b"h"
            elif match.group(3) == b">":
                self.pushed += 1
            else:
                self.pushed = max(0, self.pushed - int(match.group(4) or 1))
        rest = text[end:]
        start = rest.rfind(b"\x1b")
        self.tail = rest[start:] if start >= 0 and len(rest) - start <= 32 and self.PARTIAL.fullmatch(rest[start:]) else b""

    def reset(self, abrupt):
        """What puts the terminal back: whatever the output left on, and colours too after an
        abrupt end."""
        parts = [b"\x1b[<%du" % self.pushed] if self.pushed else []
        parts += [b"\x1b[?%dl" % mode for mode in self.OFF if self.modes.get(mode)]
        if self.modes.get(25) is False:
            parts.append(b"\x1b[?25h")
        parts += [b"\x1b[?%dl" % mode for mode in self.SCREENS if self.modes.get(mode)]
        if parts or abrupt:
            parts.append(b"\x1b[0m")
        return b"".join(parts)

    def take_console(self):
        """On a Windows console, turns on the VT processing the programs' screens need (put back
        as it was by restore). Whether the console takes VT sequences, and with them 24-bit
        colour (Windows Terminal, and the console host since Windows 10 1703)."""
        if os.name != "nt" or self.output is None:
            return False
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetStdHandle.restype = wintypes.HANDLE
        kernel32.GetConsoleMode.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        kernel32.SetConsoleMode.argtypes = [wintypes.HANDLE, wintypes.DWORD]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = wintypes.DWORD()
        if not handle or not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        if mode.value & 0x4:  # ENABLE_VIRTUAL_TERMINAL_PROCESSING
            return True
        if not kernel32.SetConsoleMode(handle, mode.value | 0x4):
            return False
        self.console = (kernel32, handle, mode.value)
        return True

    def restore(self, abrupt):
        """Puts the person's terminal back after the session (`abrupt`: it ended without its
        program's own exit)."""
        reset = self.reset(abrupt)
        if self.output is not None and reset:
            try:
                self.output.write(reset)
                self.output.flush()
            except (OSError, ValueError):
                pass  # The terminal is gone; nothing to put back.
        if self.console:
            kernel32, handle, mode = self.console
            kernel32.SetConsoleMode(handle, mode)
            self.console = None


def colours(environment, console_vt=False):
    """What the VM's programs are told of the person's terminal (/start): no colour when NO_COLOR
    is set (no-color.org: any value but an empty one); otherwise 24-bit colour where the terminal
    shows it: one that says so (COLORTERM truecolor or 24bit), Windows Terminal, or a Windows
    console taking VT sequences (`console_vt`)."""
    if environment.get("NO_COLOR"):
        return {"no_color": True}
    if environment.get("COLORTERM", "").lower() in ("truecolor", "24bit") or environment.get("WT_SESSION") or console_vt:
        return {"colorterm": "truecolor"}
    return {}


# What Yougori's setup package adds to every VM's workspace copy: a copy with only these added
# holds nothing the harness changed.
SETUP_FILES = {"yougori.py", "node_modules/yougori/index.mjs", "node_modules/yougori/index.d.ts",
               "node_modules/yougori/package.json", ".agents/skills/yougori-setup/SKILL.md"}


def setup_in_folder(folder):
    """Which setup files the person's folder already holds as files of its own, which the engine
    copies into the VM's copy. The VM's guest leaves those in the copy after the session (/start
    "setup_in_folder") and takes out only the ones the setup package added."""
    def own(name):
        path = Path(folder)
        for part in name.split("/"):
            path = path / part
            if path.is_symlink():
                return False  # The engine copies no link, nor anything under one.
        return path.is_file()
    return sorted(name for name in SETUP_FILES if own(name))


def tidy(sandbox, folder):
    """Removes a stopped VM's workspace copy, which takes the VM off the app's list, unless the
    copy holds changes to review: the copy Yougori made for a run without a project folder always
    goes, a project folder's when the harness changed nothing in it. Whether the copy is kept."""
    try:
        if folder:
            changes = call("workspace", op="show", sandbox=sandbox).get("changes") or []
            if any(not (change.get("change") == "added" and change.get("name") in SETUP_FILES) for change in changes):
                return True
        call("workspace", op="discard", sandbox=sandbox)
    except (ValueError, OSError, subprocess.TimeoutExpired) as error:
        if "has no workspace" not in str(error):
            print("The VM's copy could not be removed: " + str(error), file=sys.stderr)
            return bool(folder)
    return False


def remembered(root, update=None):
    """The VMs this launcher started for this harness and website and has not tidied yet."""
    path = root / "launched-vms.json"
    try:
        known = [item for item in json.loads(path.read_text()) if isinstance(item, dict) and re.fullmatch("exe-[a-f0-9]{32}", str(item.get("sandbox")))]
    except (OSError, ValueError, TypeError):
        known = []
    if update is not None:
        known = update(known)[-32:]
        path.write_text(json.dumps(known), encoding="utf-8")
    return known


def tidy_earlier(root):
    """Tidies the VMs of earlier runs that ended without it (a closed terminal, a restart): each
    one that has stopped. One still running belongs to a run in another terminal."""
    known = remembered(root)
    if not known:
        return
    stopped = {status.get("sandbox") for status in call("status").get("sandboxes", []) if status.get("state") == "stopped"}
    done = set()
    for item in known:
        if item["sandbox"] in stopped:
            # A copy kept for review stays until the person reviews it; it is not checked again.
            tidy(item["sandbox"], item.get("workspace"))
            done.add(item["sandbox"])
    if done:
        remembered(root, lambda current: [item for item in current if item["sandbox"] not in done])


def finish(sandbox, workspace, root, reviews=None):
    """After a session: stops its VM and tidies it, so a run leaves no VM behind in the app, only a
    copy with changes to review. The review line comes whenever a copy may hold changes, even when
    a step fails (into `reviews` when given: a run that goes on in a new VM shows them all at its
    end), and a VM that could not be stopped is named with the command that stops it."""
    kept = bool(workspace)
    try:
        try:
            call("stop", sandbox=sandbox)
        except (ValueError, OSError, subprocess.TimeoutExpired) as error:
            print("The VM could not be stopped automatically: " + str(error) + "\nStop it with: yougori sandbox stop "
                  + sandbox + " --yes", file=sys.stderr)
        else:
            kept = tidy(sandbox, workspace)
            try:
                remembered(root, lambda known: [item for item in known if item["sandbox"] != sandbox])
            except OSError:
                pass
    finally:
        if kept:
            line = "yougori sandbox review " + sandbox
            if reviews is not None:
                reviews.append(line)
            else:
                print("\nYour original project is unchanged. Review the VM copy with:\n" + line, flush=True)


def launch_params(name, identity, workspace, cpu=None, memory=None, internet=False, targets=None):
    """The Sandbox VM launch. Model requests always leave through this launcher's relay; internet
    adds the engine's outgoing network for everything else (no incoming access; with Yougori's
    filter the public internet alone, never this computer or its network); targets add a network
    card Yougori holds to those hosts' addresses (a name's as resolved at launch, where each
    HTTPS and HTTP connection must ask for a named host) and ports alone."""
    # An owner session: the relay publication reaches only this launcher, and a whole session of
    # prompts, replies and terminal output fits its release account (not VM-D12's 8 MiB).
    params = {"image": identity, "cpu": cpu or 2, "memoryGb": memory or (6 if name == 'shannon' else 4),
              "publish": "solver=8090", "idleSeconds": 0, "lifetimeSeconds": 0, "ownerSession": True}
    if workspace:
        params["workspace"] = str(workspace)
    if internet:
        params["internet"] = True
    if targets:
        params["targets"] = list(targets)
    return params


THIS_COMPUTER = "A VM never reaches this computer's own services; name another computer."


def target_parts(target):
    """A target as solver.target_host gives it: its host and port (None: every port)."""
    host, separator, port = target.rpartition(":")
    return (host, int(port)) if separator else (target, None)


def shown_targets(targets):
    """The targets as the person is told of them: a host alone is each of its ports."""
    return ", ".join(target if target_parts(target)[1] else target + " (every port)" for target in targets)


def this_computer():
    """The IPv4 addresses this computer is known by: loopback, its name's addresses and those it
    would leave from (a UDP socket's route, which sends nothing). Yougori checks every address
    the computer holds when it starts the VM."""
    found = {"127.0.0.1"}
    try:
        found.update(entry[4][0] for entry in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET))
    except OSError:
        pass
    for probe in ("192.0.2.1", "10.255.255.254", "172.31.255.254", "192.168.255.254"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
                route.connect((probe, 9))
                found.add(route.getsockname()[0])
        except OSError:
            pass
    return found


def check_targets(targets, resolve=None, own=None):
    """Checks the chosen targets on this computer before anything starts, as Yougori checks them
    again when it starts the VM: each name resolves here (IPv4); no target is this computer or
    leads to it, or lies in the VM's own network (10.0.2.0/24, which leads back to it); a name
    leads to a private address only when that address is named itself. Returns the targets."""
    def system(host):
        return [entry[4][0] for entry in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)]
    resolve = resolve or system
    own = this_computer() if own is None else own
    named = {host for host, _ in map(target_parts, targets) if re.fullmatch(r"[0-9.]+", host)}
    names = {socket.gethostname().lower(), "localhost"}
    for target in targets:
        host, port = target_parts(target)
        if host.lower() in names:
            raise ValueError(host + " is this computer. " + THIS_COMPUTER)
        literal = host in named
        try:
            addresses = [host] if literal else list(dict.fromkeys(resolve(host)))
        except (OSError, UnicodeError):
            addresses = []
        if not addresses:
            raise ValueError(host + " could not be found from this computer. Check the name, or name the computer's "
                             "address instead.")
        for address in addresses:
            value = ipaddress.ip_address(address)
            leads = " is" if literal else " leads to " + address + ", which is"
            if address in own or value.is_loopback:
                raise ValueError(host + (" is an address of this computer. " if literal else
                                         " leads to this computer (" + address + "). ") + THIS_COMPUTER)
            if value in ipaddress.ip_network("10.0.2.0/24"):
                raise ValueError(host + leads + " in the VM's own network (10.0.2.0/24), which leads back to this "
                                 "computer. Name another address.")
            if value.is_link_local or value.is_multicast or value.is_unspecified or value.is_reserved:
                raise ValueError(host + leads + " an address a VM never reaches.")
            if not literal and not value.is_global and address not in named:
                example = address + (":" + str(port) if port else "")
                raise ValueError(host + " leads to " + address + ", an address on a private network. Name " + example +
                                 " too to let the VM reach it.")
    return list(targets)


def filters_cards():
    """Whether this Yougori passes every frame of a VM's network card through its filter on the
    host, which holds the card to the chosen targets or to the public internet alone. It says so
    in its capabilities (`targets`, which came with the filter). An older one gives a full-internet
    VM QEMU's plain user network, which also reaches this computer's own services (through the
    gateway) and its network."""
    try:
        result = call("capabilities")
    except (ValueError, OSError, subprocess.TimeoutExpired):
        return False
    reach = result.get("targets") if isinstance(result, dict) else None
    return isinstance(reach, dict) and reach.get("available") is True


def hold_targets():
    """Refuses to start anything on a Yougori that cannot hold a VM to chosen targets: an older
    one would leave the VM's network as it was, so nothing starts."""
    if not filters_cards():
        raise ValueError("This Yougori cannot hold a VM to chosen targets yet. Update Yougori (yougori update), then "
                         "start the harness again.")


SHARED_ADDRESSES = (" Yougori checks the site each HTTPS and HTTP connection asks for, so other sites sharing a named "
                    "host's addresses are refused; other kinds of connection there, such as SSH, reach whatever answers "
                    "on the chosen ports.")


def reaches(internet=False, sites=None, targets=None, filtered=False):
    """What the person is told the VM reaches. Full internet is the public internet alone only on
    a Yougori whose filter holds the card to it (`filtered`); an older one gives the VM QEMU's
    plain user network, and the person is told so. A host named by its name is held to its
    addresses, which other sites may share (a CDN, shared hosting): Yougori's filter checks the
    site each HTTPS and HTTP connection there asks for, and other protocols name no site."""
    if internet:
        if filtered:
            return ("It can reach the public internet, never this computer or its network; model requests still go "
                    "only through Yougori's relay.")
        return ("It can reach the internet, and also this computer's own services and its network, because this "
                "Yougori does not filter a VM's network yet (yougori update fixes that); model requests still go only "
                "through Yougori's relay.")
    chosen = ([shown_targets(targets)] if targets else []) + ([", ".join(sites) + " through Yougori's relay"] if sites else [])
    if not chosen:
        return "It reaches only this inference: Yougori relays its model requests."
    told = "It reaches only this inference and " + ", and ".join(chosen) + "."
    if any(not re.fullmatch(r"[0-9.]+", target_parts(target)[0]) for target in targets or ()):
        told += SHARED_ADDRESSES
    return told


def reach(internet=False, sites=None, targets=None):
    """What the VM may reach besides the inference, as the harness inside it is told
    (SOLVER_REACH): the mode, the chosen sites and the chosen targets."""
    mode = "full" if internet else "targets" if targets else "sites" if sites else "inference"
    return {"mode": mode, "sites": list(sites or []), "targets": list(targets or [])}


def session(harness, answers, secrets, internet=False, sites=None, targets=None):
    """The /start fields of a Yougori harness session: the harness it holds, the setup answers,
    the secret answers (only ever in this request and the harness's environment) and the reach."""
    return {"harness": harness, "answers": dict(answers or {}), "secrets": dict(secrets or {}),
            "reach": reach(internet, sites, targets)}


def held(started, fields):
    """Whether the VM's guest took a Yougori harness session. A guest from an image older than the
    Yougori harness ignores the session's fields and starts its harness's own screen: that is
    today's harness, as it was, when nothing was asked of it, chosen targets included (Yougori's
    filter holds the VM's card to them whatever the image); with answers or secrets it would run
    without them, so the session stops."""
    if not fields or started.get("yougori") is True:
        return True
    if fields["answers"] or fields["secrets"]:
        raise ValueError("This harness's VM image is older than the Yougori harness and cannot take its answers. "
                         "Ask the administrator to publish a newer image.")
    return False


def unavailable(model):
    """What the person is told when the website's live catalog does not list the chosen model: the
    words the VM uses when it finds the same (profiles.UNAVAILABLE)."""
    return ("The model " + plain(model, 200) + " is not available on this server right now. Choose another model, or start "
            "again when it is back.")


# The keyboard's signals: Ctrl+C, with Ctrl+Break on Windows or Ctrl+\ elsewhere.
KEYBOARD = tuple(getattr(signal, name) for name in ("SIGINT", "SIGBREAK", "SIGQUIT") if hasattr(signal, name))


class Keyboard:
    """What the keyboard's signals do while a VM runs for a session. Until the cleanup after it,
    Ctrl+C ends the session as KeyboardInterrupt, and so does Ctrl+Break on Windows, which a console
    always gives as a signal: by Python's default it would end the launcher at once, with the VM
    still running and the console's input mode still changed. During the cleanup (ignore) none of
    them does anything, here or in the engine calls it makes (OWN_CONSOLE), so the VM is stopped,
    its copy tidied and the review line printed whatever is pressed; afterwards (restore) each does
    what it did before. Python takes signals in its main thread alone: elsewhere nothing changes."""

    def __init__(self):
        self.saved = {}
        if hasattr(signal, "SIGBREAK"):
            self.handle(signal.SIGBREAK, signal.default_int_handler)

    def handle(self, number, handler):
        if threading.current_thread() is threading.main_thread():
            self.saved.setdefault(number, signal.signal(number, handler))

    def ignore(self):
        for number in KEYBOARD:
            while True:
                try:
                    self.handle(number, signal.SIG_IGN)
                    break
                except KeyboardInterrupt:
                    pass  # A press still pending as the cleanup starts: ignored, as later ones are.

    def restore(self):
        for number, handler in self.saved.items():
            if handler is not None:
                signal.signal(number, handler)
        self.saved = {}


# The VM's guest lets a harness have four model requests under way at once (vm_guest), and frees a
# place as soon as its own side of a request ends, while the request can still be finishing here.
# So the relay forwards four at once and keeps up to four more waiting their turn; a request beyond
# those is answered 429, which a harness's client retries, and the session goes on.
RELAY_AT_ONCE = 4
RELAY_WAITING = 4
REQUEST_ID = re.compile("[a-f0-9]{32}")
RELAY_BUSY = "Too many model requests from this VM are under way. Try again shortly."


class Relay:
    """The session's model requests, forwarded from the VM to the website with the API key, which
    never enters the VM. `failed` is set when a reply could not reach the VM."""

    def __init__(self, control, server, secret, done):
        self.control, self.server, self.secret, self.done = control, server, secret, done
        self.failed = threading.Event()
        self.places = threading.BoundedSemaphore(RELAY_AT_ONCE)
        self.workers = set()

    def take(self, request):
        """A request from the VM's poll: forwarded once one of the places is free, or answered 429
        when RELAY_AT_ONCE requests are under way and RELAY_WAITING wait. Anything but a request
        ends the session."""
        if not isinstance(request, dict) or not isinstance(request.get("id"), str) or not REQUEST_ID.fullmatch(request["id"]):
            raise ValueError("Invalid VM relay request.")
        self.workers = {worker for worker in self.workers if worker.is_alive()}
        if len(self.workers) >= RELAY_AT_ONCE + RELAY_WAITING:
            self.busy(request["id"])
            return
        worker = threading.Thread(target=self.forward, args=(request,), daemon=True)
        self.workers.add(worker)
        worker.start()

    def send(self, request_id, value):
        """One part of a reply to the VM; Ended once the session is over or the VM no longer waits
        for the request (its client left)."""
        if self.done.is_set():
            raise Ended("The session ended.")
        again(self.control.post, "/response", {**value, "id": request_id}, self.done)

    def forward(self, request):
        with self.places:
            if self.done.is_set():
                return
            try:
                vm_relay.forward(self.server, self.secret, request, lambda value: self.send(request["id"], value))
            except Ended:
                pass  # Nothing more goes to it; vm_relay closed its connection to the website.
            except (OSError, ValueError, http.client.HTTPException):
                self.failed.set()

    def busy(self, request_id):
        body = json.dumps({"error": {"message": RELAY_BUSY, "type": "rate_limit_error"}}).encode()
        try:
            for value in ({"status": 429, "content_type": "application/json"}, {"data": base64.b64encode(body).decode()},
                          {"done": True}):
                self.send(request_id, value)
        except Ended:
            pass


def launch(name, server, key_file, model, workspace, arguments, interactive=True, cpu=None, memory=None, internet=False,
           sites=None, targets=None, harness=None, answers=None, secrets=None, images=None, catalog=None, known=None,
           reviews=None):
    """Starts `name`'s VM image and its harness in this terminal. With `harness` (the Yougori
    harness, holding `name`), the VM starts on the Yougori harness's base with that harness's pack
    (both kept in `images`, the folder every harness Yougori holds shares; by default the key's)
    and gets the setup `answers`, the `secrets` and the reach; with `known` (the harnesses this
    launcher knows), also the harnesses its screen may switch to (/harness, switch_list): one that
    starts on this VM's base comes into it (switch_in_place), any other ends this session, which
    returns a Relaunch for the next VM. With `targets`, Yougori holds the
    VM's network card to those hosts' addresses and ports alone (and answers its DNS for them
    alone, and checks the site each HTTPS and HTTP connection to a named host's addresses asks
    for); with `sites` as well, both apply. With `internet`, a Yougori with the filter holds the
    card to the public internet; the person is told what an older one gives. `catalog`
    (solver.models) reads the website's live catalog again once the images are ready: a model it
    no longer lists is refused by name before the VM starts. Whatever ends the session, the
    person's terminal is left as it was. `reviews` collects the review line instead of printing it."""
    filtered = False
    if targets:
        if internet:
            raise ValueError("Choose the whole internet or chosen targets, not both.")
        # Checked here first, and nothing starts on a Yougori that would not hold them.
        targets = check_targets(targets)
        hold_targets()
    elif internet:
        filtered = filters_cards()
    fields = session(harness, answers, secrets, internet, sites, targets) if harness else None
    root = key_file.parent
    declaration = None
    switching, entries = {}, {}
    if harness:
        store = images or root
        identity, declaration, standard = install_yougori(harness, server, store)
        memory = memory or standard
        if known:
            switching = switch_list(server, harness, memory, known)
            entries = {entry["id"]: entry for entry in switching.get("harnesses", [])}
            fields.update(switching)
    else:
        store = root
        identity = install(name, server, root)
    try:
        tidy_earlier(root)
    except (ValueError, OSError, subprocess.TimeoutExpired):
        pass  # Earlier VMs stay listed; this run is unaffected.
    secret = key_file.read_text().strip()
    # The images can take minutes to arrive, and the harness asks for its model as soon as it
    # starts: a model the website no longer lists is refused here, not in the VM after its pack.
    if catalog is not None and model not in {entry["id"] for entry in catalog(server, secret)}:
        raise ValueError(unavailable(model))
    print("Starting Yougori Sandbox VM. " + reaches(internet, sites, targets, filtered), flush=True)
    sandbox = None
    done = threading.Event()
    original = None
    keys = None
    tunnels = None
    screen = None
    ended = False
    started = False
    keyboard = Keyboard()
    try:
        params = launch_params(name, identity, workspace, cpu, memory, internet, targets)
        # As the engine copies the folder: the setup files it already holds stay in the copy.
        kept = setup_in_folder(workspace) if workspace else []
        try:
            result = call("launch", **params)
        except ValueError as error:
            # A command line older than targets refuses the parameter itself: nothing started.
            if targets and "Unknown parameter 'targets'" in str(error):
                raise ValueError("This Yougori cannot hold a VM to chosen targets yet. Update Yougori (yougori update), "
                                 "then start the harness again.") from None
            raise
        sandbox = result.get("sandbox")
        if not isinstance(sandbox, str) or not re.fullmatch("exe-[a-f0-9]{32}", sandbox):
            raise ValueError("Yougori did not return the VM identity.")
        record = {"sandbox": sandbox, "workspace": str(workspace) if workspace else None}
        (root / "last-vm.json").write_text(json.dumps(record))
        remembered(root, lambda known: [*known, record])
        held_by = result.get("reach")
        held_to = held_by.get("targets") if isinstance(held_by, dict) else None
        if targets and not (isinstance(held_to, list) and held_to):
            # Yougori says what it holds the card to; one that does not would not hold it.
            raise ValueError("This Yougori did not hold the VM to the chosen targets, so it was stopped. Update Yougori "
                             "(yougori update), then start the harness again.")
        publication = call("publish", sandbox=sandbox, service="solver", audience="owner", minutes=0)
        control = Control(publication["url"])
        prepare_tool(control, store, declaration)
        size = shutil.get_terminal_size((100, 30))
        screen = Screen(sys.stdout.buffer if sys.stdout.isatty() else None)
        # The programs in the VM draw for this terminal: whether it shows colour, and 24-bit colour.
        told = colours(os.environ, screen.take_console())
        started = False
        deadline = time.monotonic() + 600
        attempt = 0
        while time.monotonic() < deadline:
            try:
                body = {"model": model, "arguments": arguments, "workspace": bool(workspace),
                        "columns": max(10, min(500, size.columns)), "rows": max(2, min(300, size.lines)), **told}
                if workspace:
                    body["setup_in_folder"] = kept
                if sites:
                    body["sites"] = sites
                if targets:
                    body["targets"] = targets
                if fields:
                    body.update(fields)
                started = control.post("/start", body)
                break
            except Refused:
                raise
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
        held(started, fields)
        if sites:
            # An image from before chosen sites starts without its proxy: stop rather than run
            # a session that cannot reach what was chosen.
            if started.get("tunnels") is not True:
                raise ValueError("This harness's VM image cannot reach chosen sites yet. Ask the administrator to publish "
                                 "a newer image, or choose another internet option.")
            tunnels = vm_tunnel.HostTunnels(lambda message: control.post("/tunnel", message), sites)
            # With the sites' proxy, an image from before targets would send the targets to the
            # proxy too, which refuses them.
            if targets and started.get("targets") is not True:
                raise ValueError("This harness's VM image cannot combine chosen sites with targets yet. Ask the "
                                 "administrator to publish a newer image, or choose the targets alone.")
        relay = Relay(control, server, secret, done)
        if interactive and sys.stdin.isatty():
            if os.name != "nt":
                import termios
                import tty
                original = termios.tcgetattr(sys.stdin)
                tty.setraw(sys.stdin)
            else:
                keys = ConsoleKeys()
                keys.take()
            threading.Thread(target=terminal_input, args=(control, done, keys), daemon=True).start()
        relaunch = None
        while not done.is_set():
            packet = again(control.post, "/poll", {}, done)
            output = base64.b64decode(packet.get("output", ""), validate=True)
            if output:
                screen.feed(output)
                sys.stdout.buffer.write(output)
                sys.stdout.buffer.flush()
            if relay.failed.is_set():
                raise ValueError("The VM inference relay ended unexpectedly.")
            for request in packet.get("requests", []):
                relay.take(request)
            for event in packet.get("tunnels", []):
                if tunnels is None:
                    raise ValueError("The VM opened a tunnel this session did not allow.")
                tunnels.handle(event)
            request = packet.get("switch")
            if isinstance(request, dict) and switching:
                relaunch = take_switch(control, request, entries, switching["vm_base"], memory, server, store) or relaunch
            if packet.get("exit") is not None:
                ended = True
                if relaunch is not None and int(packet["exit"]) == RELAUNCH_EXIT:
                    return relaunch
                return int(packet["exit"])
            current = shutil.get_terminal_size((100, 30))
            if current != size:
                size = current
                control.post("/input", {"columns": max(10, min(500, size.columns)), "rows": max(2, min(300, size.lines))})
        return 130
    except KeyboardInterrupt:
        return 130
    finally:
        # First: from here to the end, a key pressed (a second Ctrl+C) cuts nothing short.
        keyboard.ignore()
        try:
            done.set()
            if tunnels:
                tunnels.close_all()
            if screen is not None:
                # Before anything else is printed: what the program left on in the terminal goes off
                # when the VM ended under it.
                screen.restore(abrupt=not ended)
            if original:
                import termios
                termios.tcsetattr(sys.stdin, termios.TCSADRAIN, original)
            if keys:
                keys.restore()
            if started and not ended:
                # The session ends here first (Ctrl+], Ctrl+C, a lost connection). The VM's guest
                # hangs up the harness, which can save its work, and takes the setup files out of
                # the copy. Once the VM stops, its agent refuses every file of the copy.
                try:
                    control.post("/finish", {})
                except (OSError, ValueError, http.client.HTTPException):
                    pass
            if sandbox:
                finish(sandbox, workspace, root, reviews)
        finally:
            keyboard.restore()
