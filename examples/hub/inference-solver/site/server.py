"""Inference Solver: a standalone, private website for existing model servers.

Public or invitation-only accounts, with scoped server-side Yougori compute management.
"""
import argparse
from collections import defaultdict, deque
import getpass
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import secrets
import signal
import socket
import sqlite3
import sys
import threading
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
import gateway
import protocols
import google_protocol
import harness_download
import routing
from device_auth import Devices
from compute import Compute, ComputeInput, MOST_PER_COMPUTER
from media import Media, MediaInput
from sandbox_grid import Grid, GridInput
from payments import Payments, WalletInput
from subscriptions import SubscriptionInput
from rentals import Rentals
from store import AccountError, Store, digest
from upstream import UpstreamError, address, discover_catalog

HERE = Path(__file__).resolve().parent
STATIC = {"/": ("index.html", "text/html"), "/app.js": ("app.js", "text/javascript"),
          "/compute-ui.js": ("compute-ui.js", "text/javascript"),
          "/infrastructure-ui.js": ("infrastructure-ui.js", "text/javascript"),
          "/payments-ui.js": ("payments-ui.js", "text/javascript"),
          "/sandboxes-ui.js": ("sandboxes-ui.js", "text/javascript"),
          "/control-ui.js": ("control-ui.js", "text/javascript"),
          "/style.css": ("style.css", "text/css"),
          "/theme.js": ("theme.js", "text/javascript"),
          "/icon.svg": ("icon.svg", "image/svg+xml"), "/fonts/hanken-grotesk.woff2": ("fonts/hanken-grotesk.woff2", "font/woff2")}
# The pages an administrator can make the main page, and why a hidden harness cannot be set up.
HOMES = ("harnesses", "models", "sandboxes")
# The colour styles in style.css; the administrator's choice applies to every visitor.
PALETTES = ("navy", "nord", "solarized", "catppuccin", "rose-pine", "gruvbox")
NOT_OFFERED = "The administrator of this inference has not offered this harness."
UNPUBLISHED = "The administrator has not published this harness's Sandbox VM image yet."


class ChoiceInput(ValueError):
    """A main page or harness choice the administrator can correct."""


class Service:
    def __init__(self, folder, bootstrap=None, site_name="Inference Solver", public=False, account_mode="private", hosted=None):
        if account_mode not in ("public", "private"):
            raise ValueError("Choose public or private account access.")
        self.hosted = hosted
        self.store = Store(folder, bootstrap, site_name, journal_mode="DELETE" if hosted else "WAL",
                           runtime_folder=hosted.get("runtime_folder") if hosted else None)
        self.devices = Devices(self.store)
        self.compute = Compute(self.store)
        # Which connected computer or model server serves each request for a model name.
        self.router = self.compute.router = routing.Router()
        self.grid = Grid(self.store)
        self.payments = Payments(self.store)
        # GPUs the website rents from neoclouds itself, with the administrator's provider keys.
        self.rentals = Rentals(self.store, self.compute)
        self.control = self.compute.control
        self.stopped = threading.Event()
        # Media jobs (images, video, speech, sound) through the same keys, routing and billing.
        self.media = Media(self)
        # Account admission is independent of publication/TLS (the public flag).
        self.account_mode = account_mode
        self.public = public
        self.inference_slots = threading.BoundedSemaphore(32)
        self.refresh_lock = threading.Lock()
        self.rate_lock = threading.Lock()
        self.attempts = defaultdict(deque)
        self.harnesses = json.loads((HERE / "harnesses.json").read_text(encoding="utf-8"))
        self.categories = json.loads((HERE / "categories.json").read_text(encoding="utf-8"))

    def throttle(self, peer):
        now = time.monotonic()
        with self.rate_lock:
            for key in list(self.attempts):
                if not self.attempts[key] or self.attempts[key][-1] < now - 60:
                    del self.attempts[key]
            if peer not in self.attempts and len(self.attempts) >= 4096:
                return False
            queue = self.attempts[peer]
            while queue and queue[0] < now - 60:
                queue.popleft()
            if len(queue) >= 12:
                return False
            queue.append(now)
            return True

    def refresh_endpoint(self, item):
        if item["url"].startswith("compute://"):
            # Outbound contributors report their own catalog. Never resolve these as URLs.
            return
        try:
            models = discover_catalog(item["url"], item["secret"])
            state, detail = "ready", "Catalog connected. Inference capabilities depend on the selected model."
        except (UpstreamError, ValueError) as error:
            models, state, detail = None, "unavailable", str(error)
        with self.store.db() as db:
            # A deleted or reconfigured connection must not be resurrected by an old refresh.
            current = db.execute("SELECT url,secret FROM endpoints WHERE id=?", (item["id"],)).fetchone()
            if not current or current["url"] != item["url"] or current["secret"] != item["secret"]:
                return
            db.execute("UPDATE endpoints SET state=?,detail=?,checked=? WHERE id=?", (state, detail, int(time.time()), item["id"]))
            if models is not None:
                self.store.replace_models(db, item["id"], models)

    def close(self):
        """Stops the background work and waits for the media watcher, which holds the database
        while it reads (a test removing its data folder, a hosted instance's shutdown)."""
        self.stopped.set()
        self.media.watcher.join(10)

    def refresh(self):
        if not self.refresh_lock.acquire(blocking=False):
            return
        try:
            with self.store.db() as db:
                endpoints = [dict(r) for r in db.execute("SELECT * FROM endpoints")]
            for endpoint in endpoints:
                if self.stopped.is_set():
                    break
                self.refresh_endpoint(endpoint)
        finally:
            self.refresh_lock.release()

    def watch(self):
        while not self.stopped.is_set():
            try:
                self.refresh()
                # Rented GPUs are watched while nobody has Admin open: one whose model cannot
                # start is deleted, so it stops charging.
                self.rentals.refresh()
                # Models listed before models were checked get their check.
                self.compute.check_listed()
            except (sqlite3.Error, OSError):
                # Disk pressure or a temporary database lock must not silently
                # end health monitoring for the lifetime of the server.
                print('Model health refresh is temporarily unavailable; retrying.',file=sys.stderr,flush=True)
            self.stopped.wait(30)

    def offered(self, name):
        """Whether people may set up this harness here. Names outside the catalogue, such as the
        contributor's `node` bundle, are not choices; their own checks apply."""
        return name not in self.store.choices()["hidden"]

    @staticmethod
    def setup(name, published=None):
        """Whether this harness's own Sandbox VM image is ready here (/api/harness-image/NAME): what
        every launcher that starts a harness from its own image checks, the ones from before the
        Yougori harness included. Yougori's own agent has no image of its own. A harness the
        launcher has no package for cannot start."""
        if name not in harness_download.catalog():
            return {"available": False, "reason": UNPUBLISHED, "version": None}
        return harness_download.availability(name, published)

    @staticmethod
    def held(name, published=None):
        """Whether this harness starts inside the Yougori harness here: from the Yougori harness's
        base image and the harness's pack (Yougori's own agent needs no pack)."""
        return harness_download.held(name, published)

    def offered_names(self):
        """The catalogue harnesses people may set up here: offered by the administrator and not
        blocked in the catalogue."""
        hidden = set(self.store.choices()["hidden"])
        return {name for name, spec in harness_download.catalog().items() if name not in hidden and not spec.get("blocked")}

    def choose(self, actor, data):
        """The administrator's main page and the catalogue harnesses offered here."""
        home, chosen = data.get("home"), data.get("harnesses")
        if home not in HOMES:
            raise ChoiceInput("Choose Harnesses, Models or Sandboxes as the main page.")
        ids = [h["id"] for h in self.harnesses]
        if not isinstance(chosen, list) or len(chosen) > len(ids) or any(not isinstance(n, str) or n not in ids for n in chosen):
            raise ChoiceInput("Choose harnesses from this inference's catalogue.")
        if home == "harnesses" and not chosen:
            raise ChoiceInput("Offer at least one harness, or choose another main page.")
        self.store.choose(actor, home, [n for n in ids if n not in chosen])
        return self.store.choices()

    def add_endpoint(self, actor, data):
        name, url, secret, place = data.get("name"), data.get("url"), data.get("key", ""), data.get("place", "local")
        if not isinstance(name, str) or not 1 <= len(name.strip()) <= 60:
            raise ValueError("Give this connection a name of 1 to 60 characters.")
        if place not in ("local", "neocloud"):
            raise ValueError("Choose local or neocloud.")
        url = address(url)
        models = discover_catalog(url, secret)
        endpoint_id = secrets.token_hex(5)
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0] >= 10:
                raise ValueError("This version supports up to ten model-server connections.")
            if db.execute("SELECT 1 FROM endpoints WHERE url=?", (url,)).fetchone():
                raise ValueError("This model server is already connected.")
            db.execute("INSERT INTO endpoints VALUES(?,?,?,?,?,'ready',?,?)", (endpoint_id, name.strip(), url, secret, place,
                       int(time.time()), "Catalog connected. Inference capabilities depend on the selected model."))
            self.store.replace_models(db, endpoint_id, models)
            self.store.audit(db, actor, "endpoint.connected", endpoint_id)
        return {"id": endpoint_id, "models": len(models)}


class Server(ThreadingHTTPServer):
    # Windows SO_REUSEADDR permits two processes to accept connections at the
    # same address. That would split device/compute state across server instances.
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt":
            self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_EXCLUSIVEADDRUSE,1)
        super().server_bind()

    daemon_threads = True
    request_queue_size = 64

    def __init__(self, bind, service):
        self.service = service
        self.slots = threading.BoundedSemaphore(64)
        # Connector streams last minutes, so they have their own budget: one per enrolled computer.
        self.streams = threading.BoundedSemaphore(100)
        super().__init__(bind, Handler)

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nRetry-After: 2\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(30)
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "InferenceSolver"
    sys_version = ""

    def log_message(self, *_):
        pass  # Access paths and provider responses can contain private information.

    def begin(self, status, content_type="application/json", length=None, cookie=None, retry=False, extra=None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        for name, value in (extra or {}).items():
            self.send_header(name, value)
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        self.send_header("Connection", "close")
        if length is not None:
            self.send_header("Content-Length", str(length))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        if retry:
            self.send_header("Retry-After", "2")
        self.end_headers()
        self.close_connection = True

    def json(self, status, value, cookie=None, retry=False):
        raw = json.dumps(value, allow_nan=False).encode()
        self.begin(status, length=len(raw), cookie=cookie, retry=retry)
        self.wfile.write(raw)

    def error(self, status, message, retry=False):
        self.json(status, {"error": {"message": message}}, retry=retry)

    def session_token(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            return cookie["solver_session"].value if "solver_session" in cookie else ""
        except Exception:
            return ""

    @property
    def peer(self):
        """The client address for attempt limits. Behind the website's loopback proxy it is the
        address that proxy reports; the proxy replaces anything the client sent."""
        hosted = self.server.service.hosted
        if hosted and hosted.get("proxied") and self.client_address[0] in ("127.0.0.1", "::1"):
            forwarded = self.headers.get("X-Forwarded-For", "").split(",")[-1].strip()
            if forwarded and len(forwarded) <= 45 and not any(c.isspace() for c in forwarded):
                return forwarded
        return self.client_address[0]

    def cookie(self, token, seconds=43200):
        return f"solver_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={seconds}" + ("; Secure" if self.server.service.public else "")

    def body(self, limit=2 * 1024 * 1024):
        if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
            raise ValueError("Send JSON with one Content-Length header.")
        length = int(self.headers["Content-Length"])
        if not 0 < length <= limit:
            raise ValueError("Request bodies must be between 1 byte and " + str(limit // (1024 * 1024)) + " MiB.")
        if self.headers.get_content_type() != "application/json":
            raise ValueError("Send Content-Type: application/json.")
        raw = self.rfile.read(length)
        if len(raw) != length:
            raise ValueError("The request body is incomplete.")
        data = json.loads(raw, parse_constant=lambda _: (_ for _ in ()).throw(ValueError("JSON numbers must be finite.")))
        if not isinstance(data, dict):
            raise ValueError("Send one JSON object.")
        return data

    def dispatch(self, method):
        service, store = self.server.service, self.server.service.store
        path = urlsplit(self.path).path
        host = self.headers.get("Host", "")
        parsed_host = urlsplit("//" + host)
        if not parsed_host.hostname or parsed_host.username or parsed_host.path or any(c.isspace() for c in host):
            return self.error(400, "Invalid host.")
        if service.hosted and host != service.hosted["authority"]:
            return self.error(403, "Use this inference's own address.")
        if not service.public and not service.hosted and parsed_host.hostname not in ("localhost", "127.0.0.1", "::1"):
            return self.error(403, "Local preview accepts localhost only.")
        if method == "GET" and path == "/health":
            if store.persistence_failed:
                return self.json(503, {"status": "storage_unavailable"})
            return self.json(200, {"status": "ok"})
        if method == "GET" and path in STATIC:
            filename, content_type = STATIC[path]
            raw = (HERE / filename).read_bytes()
            if path == "/":
                # The page arrives in the administrator's colour style, before any script runs.
                palette = store.settings()["palette"]
                if palette in PALETTES:
                    raw = raw.replace(b'data-palette="navy"', b'data-palette="' + palette.encode() + b'"', 1)
            self.begin(200, content_type + "; charset=utf-8", len(raw))
            return self.wfile.write(raw)
        google_route = google_protocol.route(self.path)
        if path.startswith("/v1/") or google_route:
            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else self.headers.get("x-api-key", "") if path == "/v1/messages" else ""
            key = store.key(token) if token else None
            if not key:
                return self.error(401, "Use an active Inference Solver API key.")
            if method == "POST" and google_route:
                return google_protocol.complete(self, key, self.body(), *google_route)
            if method == "GET" and path == "/v1/models":
                models = store.models(key["scopes"])
                # Each entry names the kind of model, as Yougori's model server does, so a client
                # reading the catalog knows which take jobs and which answer chat, and the context
                # its ready servers report (the smallest), so a harness sizes its conversation by it.
                return self.json(200, {"object": "list", "data": [{"id": m["id"], "object": "model", "owned_by": "inference-solver", "task": m["task"],
                                                                  **({"context_length": m["context_length"]} if "context_length" in m else {}),
                                                                  "capabilities": {"structuredOutput": m["features"]["json"], **({"media": m["task"]} if "media" in m["features"] else {})}}
                                                                 for m in models if m["state"] == "ready"]})
            if service.media.route(self, key, method, path, urlsplit(self.path).query):
                return
            if method == "POST" and path == "/v1/chat/completions":
                return gateway.complete(self, key, self.body())
            if method == "POST" and path in ("/v1/responses", "/v1/messages"):
                return protocols.complete(self, key, self.body(), path.rsplit("/", 1)[-1])
            return self.error(501, "Supported endpoints: models, chat/completions, responses, messages, jobs, files, images/generations, audio/speech and videos. This operation is not available.")
        user = store.session(self.session_token())
        if method == "POST" and path == "/api/compute/agent":
            auth = self.headers.get("Authorization", "")
            host_node = service.compute.host(auth[7:] if auth.startswith("Bearer ") else "")
            data = self.body()
            action = data.get("action")
            if action == "inventory":
                service.compute.inventory(host_node, data)
                service.grid.inventory(host_node, data.get("grid"))
                service.grid.reconcile(host_node, data.get("grid_vms", {}))
                return self.json(200, {"ok": True})
            if action == "stream":
                return service.compute.stream(self, host_node, data)
            if action == "ack":
                return self.json(200, {"ok": True, "cancelled": not service.compute.ack(host_node, data)})
            if action == "poll":
                return self.json(200, service.compute.poll(host_node, accept_job=False))
            if action == "grid_poll":
                return self.json(200, service.grid.poll(host_node))
            if action == "grid_result":
                service.grid.result(host_node, data)
                return self.json(200, {"ok": True})
            if action == "chunk":
                accepted = service.compute.chunk(host_node, data)
                return self.json(200, {"ok": True, "cancelled": not accepted})
            return self.error(400, "This connector action is not available.")
        if method == "GET" and path == "/api/session":
            choices = store.choices()
            return self.json(200, {"user": user, "site": store.settings(), "mode": service.account_mode, "version": "0.1.0",
                                   "choices": {"home": choices["home"], "chosen": choices["chosen"]}})
        # Browsing is public; inference and account actions still require credentials.
        if method == "GET" and path.startswith("/api/harness-image/"):
            parts = path.removeprefix("/api/harness-image/").split("/")
            if len(parts) not in (1, 2, 3):
                return self.error(404, "This VM image is unavailable.")
            published = service.hosted.get('artifacts') if service.hosted else None
            if parts[0] == harness_download.YOUGORI:
                # Every harness offered here starts from the Yougori harness's images, Yougori's own
                # agent hidden or not: they list only the packs of the harnesses offered here and not
                # blocked, and the bases those start from, and only the files they list are served.
                # Nothing is, when the catalogue blocks the Yougori harness itself or has none.
                own = harness_download.catalog().get(parts[0])
                if own is None or own.get("blocked"):
                    return self.error(404, "This VM image is unavailable.")
                record = published.get('images', {}).get(parts[0]) if published is not None else harness_download.vm_image(parts[0])
                shown = harness_download.offered_image(harness_download.yougori_image(record), service.offered_names()) if record else None
                if shown is not None and not shown["packs"]:
                    return self.error(404, NOT_OFFERED)
                if published is not None:
                    if len(parts) != 1 or shown is None:
                        return self.error(404, "This artifact is not published here.")
                    return self.json(200, {**shown, 'download_base': published['base']})
                if shown is None:
                    return self.error(404, "The administrator has not prepared the Yougori harness's VM images yet.")
                if len(parts) == 1:
                    return self.json(200, shown)
                listed = shown["packs"].values() if parts[2:] == ["tool"] else shown["bases"].values()
                value = harness_download.vm_image(*parts) if parts[1] in {item.get("sha256") for item in listed} else None
            else:
                if not service.offered(parts[0]):
                    return self.error(404, NOT_OFFERED)
                if published is not None:
                    record = published.get('images', {}).get(parts[0])
                    if len(parts) != 1 or not record:
                        return self.error(404, "This artifact is not published here.")
                    return self.json(200, {**record, 'download_base': published['base']})
                value = harness_download.vm_image(*parts)
                if value is not None and len(parts) == 1:
                    return self.json(200, value)
            if value is None:
                return self.error(404, "The administrator has not prepared this harness's Yougori VM image yet.")
            with value.open("rb") as stream:
                self.begin(200, "application/gzip" if value.suffix == '.gz' else "application/zip", value.stat().st_size)
                while block := stream.read(1024 * 1024):
                    self.wfile.write(block)
            return
        if method == "GET" and path.startswith("/install/") and path.endswith(".ps1"):
            name = path.removeprefix("/install/").removesuffix(".ps1")
            if not service.offered(name):
                return self.error(404, NOT_OFFERED)
            raw = harness_download.powershell(name, ("https://" if service.public else "http://") + host)
            self.begin(200, "text/plain; charset=utf-8", len(raw))
            return self.wfile.write(raw)
        if method == "GET" and path == "/api/harnesses":
            # Hidden harnesses stay listed, unavailable with the reason, so `yougori inference run`
            # explains why instead of failing to find them; the pages list only the offered ones.
            # Every catalogue field passes through: `yougori inference run` asks each harness's
            # `questions` and sizes its VM from `size`. `setup` says whether the harness's own image
            # is ready (Service.setup), as every launcher that starts a harness from its own image
            # reads it, older ones included; `held` says whether it starts inside the Yougori
            # harness here (Service.held), from the Yougori harness's base image and its pack.
            hidden = set(store.choices()["hidden"])
            published = service.hosted.get('artifacts') if service.hosted else None
            listed = []
            for h in service.harnesses:
                setup, held = service.setup(h['id'], published), service.held(h['id'], published)
                if h['id'] in hidden:
                    setup = {**setup, "available": False, "reason": NOT_OFFERED}
                    held = {**held, "available": False, "reason": NOT_OFFERED}
                listed.append({**h, "offered": h['id'] not in hidden, "setup": setup, "held": held})
            return self.json(200, {"harnesses": listed, "categories": service.categories})
        if method == "GET" and path.startswith("/api/harness-download/"):
            name = path.removeprefix("/api/harness-download/")
            if not service.offered(name):
                return self.error(404, NOT_OFFERED)
            raw = harness_download.bundle(name, ("https://" if service.public else "http://") + host)
            self.send_response(200)
            self.send_header("Content-Type", "application/zip")
            self.send_header("Content-Disposition", 'attachment; filename="inference-solver-' + name + '.zip"')
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            return self.wfile.write(raw)
        if method == "GET" and path == "/api/models":
            catalog = store.models()
            if not user:
                # "detail": what a model still starting is doing (a download's progress), never which computer.
                fields = ("id", "upstream", "state", "detail", "protocols", "features", "price", "cache", "censorship", "censorship_source", "task", "media_price")
                catalog = [{field: model[field] for field in fields if field in model} for model in catalog]
            return self.json(200, {"models": catalog})
        if method == "GET" and path == "/api/sandboxes":
            return self.json(200,service.grid.catalog())
        if method == "GET" and path == "/api/compute/models":
            # What `yougori inference connect` offers a computer to install: the administrator's list.
            return self.json(200, {"models": service.compute.offered(), "most": MOST_PER_COMPUTER, "needs": service.compute.needs()})
        if method == "GET" and path == "/api/compute/rental-agent":
            # A rented GPU downloads its agent with its own credential (neocloud.boot).
            auth = self.headers.get("Authorization", "")
            service.rentals.agent(auth[7:] if auth.startswith("Bearer ") else "")
            raw = harness_download.bundle("rental", ("https://" if service.public else "http://") + host)
            self.begin(200, "application/zip", len(raw))
            return self.wfile.write(raw)
        if method != "GET":
            origin = self.headers.get("Origin", "")
            if origin != ("https://" if service.public else "http://") + host:
                return self.error(403, "Open this page from the service's own address and try again.")
            if path not in ("/api/login", "/api/join", "/api/signup", "/api/device/start", "/api/device/poll", "/api/compute/pair/start", "/api/compute/pair/poll") and (not user or not secrets.compare_digest(self.headers.get("X-CSRF-Token", ""), user["csrf"])):
                return self.error(403, "Your session changed. Refresh the page and try again.")
        if path.startswith("/api/media/"):
            # The model page's Try it box: a signed-in member's own jobs and files, by session.
            if not user:
                return self.error(401, "Sign in to generate media.")
            if service.media.route(self, {"id": "session", "user_id": user["id"], "scopes": ["*"]}, method, "/v1/" + path[len("/api/media/"):], urlsplit(self.path).query):
                return
            return self.error(404, "This media route is not available.")
        if method == "POST" and path in ("/api/compute/pair/start", "/api/compute/pair/poll"):
            if not service.throttle("compute-pair:" + self.peer):
                return self.error(429, "Too many computer connection attempts. Wait one minute.", retry=True)
            data = self.body()
            value = service.compute.pair(data) if path.endswith("/start") else service.compute.pair_status(data.get("device"))
            return self.json(200, value)
        if method == "POST" and path == "/api/device/start":
            if not service.throttle("device-start:" + self.peer):
                return self.error(429, "Too many connection attempts. Wait one minute.", retry=True)
            data = self.body()
            name = data.get("harness")
            specs = harness_download.catalog()
            if not isinstance(name, str) or name not in specs or specs[name].get("blocked"):
                return self.error(400, "This harness is not available to connect.")
            if not service.offered(name):
                return self.error(400, NOT_OFFERED)
            result = service.devices.start(name, data.get("credential_hash"))
            result["verification_uri"] = ("https://" if service.public else "http://") + host + "/#connect"
            return self.json(201, result)
        if method == "POST" and path == "/api/device/poll":
            return self.json(200, service.devices.poll(self.body().get("device_code")))
        if method == "POST" and path in ("/api/login", "/api/join", "/api/signup"):
            if path == "/api/signup" and service.account_mode != "public":
                return self.error(403, "This inference is invitation-only. Ask its administrator for an invitation.")
            if not service.throttle(self.peer):
                return self.error(429, "Too many account attempts. Wait one minute.", retry=True)
            data = self.body()
            if path == "/api/join":
                store.redeem(data.get("email"), data.get("password"), data.get("invitation", ""))
            elif path == "/api/signup":
                store.signup(data.get("email"), data.get("password"))
            token = store.login(data.get("email"), data.get("password"))
            return self.json(201 if path == "/api/signup" else 200, {"ok": True}, cookie=self.cookie(token))
        if not user:
            return self.error(401, "Sign in or create an account to continue.")
        if method == "POST" and path in ("/api/compute/pair/inspect", "/api/compute/pair/approve"):
            if not service.throttle("compute-approval:" + self.peer):
                return self.error(429, "Too many code attempts. Wait one minute.", retry=True)
            data = self.body()
            return self.json(200, service.compute.inspect_pair(data.get("code")) if path.endswith("/inspect") else service.compute.approve(user, data))
        if method == "POST" and path in ("/api/device/inspect", "/api/device/decide"):
            if not service.throttle("device-approve:" + self.peer) or not service.throttle("device-user:" + user["id"]):
                return self.error(429, "Too many code attempts. Wait one minute.", retry=True)
            data = self.body()
            if path.endswith("/inspect"):
                info = service.devices.inspect(data.get("user_code"))
                info["name"] = next((h["name"] for h in service.harnesses if h["id"] == info["harness"]), info["harness"])
                return self.json(200, info)
            return self.json(200, service.devices.decide(data.get("user_code"), user["id"], data.get("approve")))
        if method == "POST" and path == "/api/logout":
            with store.db() as db:
                db.execute("DELETE FROM sessions WHERE hash=?", (digest(self.session_token()),))
            return self.json(200, {"ok": True}, cookie=self.cookie("", 0))
        if path.startswith("/api/admin/") and not user["admin"]:
            return self.error(403, "Only the administrator can change this setting.")
        if method == 'POST' and path == '/api/presence':
            service.control.presence(user['id'])
            return self.json(200,{'ok':True})
        if method == 'GET' and path == '/api/admin/control':
            return self.json(200,service.control.snapshot(service.compute,service.grid))
        if method == 'POST' and path == '/api/admin/users/role':
            return self.json(200,store.change_role(user['id'],self.body()))
        if method == "GET" and path == "/api/grid":
            return self.json(200, service.grid.snapshot(user))
        if method == "GET" and path == "/api/payments":
            return self.json(200, service.payments.snapshot(user['id']))
        if method == "POST" and path in ("/api/payments/invoice", "/api/payments/submit", "/api/payments/cancel"):
            if not service.throttle('payments:' + user['id']):
                return self.error(429, 'Too many payment requests. Wait one minute.', retry=True)
            action = {'/api/payments/invoice':service.payments.create, '/api/payments/submit':service.payments.submit,
                      '/api/payments/cancel':service.payments.cancel}[path]
            return self.json(200, action(user['id'], self.body()))
        # Subscriptions: the plans offered and one's own, bought from the balance; Admin manages the
        # plans and can reset anyone's window.
        if method == "GET" and path == "/api/subscriptions":
            return self.json(200, service.payments.subscriptions.snapshot(user["id"]))
        if method == "POST" and path == "/api/subscriptions/subscribe":
            if not service.throttle('payments:' + user['id']):
                return self.error(429, 'Too many payment requests. Wait one minute.', retry=True)
            return self.json(200, service.payments.subscriptions.subscribe(user["id"], self.body(), Payments.balance))
        if method == "GET" and path == "/api/admin/subscriptions":
            return self.json(200, service.payments.subscriptions.admin_snapshot())
        if method == "POST" and path in ("/api/admin/subscriptions/plan", "/api/admin/subscriptions/remove", "/api/admin/subscriptions/reset",
                                         "/api/admin/subscriptions/switch"):
            subscriptions = service.payments.subscriptions
            action = {"/api/admin/subscriptions/plan": subscriptions.save_plan, "/api/admin/subscriptions/remove": subscriptions.remove_plan,
                      "/api/admin/subscriptions/reset": subscriptions.reset, "/api/admin/subscriptions/switch": subscriptions.switch}[path]
            return self.json(200, action(user["id"], self.body()))
        if method == "POST" and path == "/api/admin/prices":
            return self.json(200, service.payments.price(user['id'],self.body()))
        if method == "POST" and path == "/api/admin/wallet":
            return self.json(200, service.payments.save(user["id"], self.body()))
        if method == "POST" and path == "/api/admin/media/prices":
            return self.json(200, service.payments.media_price(user["id"], self.body()))
        if method == "GET" and path == "/api/admin/media":
            return self.json(200, service.media.snapshot())
        if method == "POST" and path == "/api/admin/media":
            return self.json(200, service.media.configure(user["id"], self.body()))
        if method == "POST" and path == "/api/grid/jobs":
            return self.json(202, service.grid.submit(user, self.body()))
        if method == "POST" and path == "/api/admin/grid":
            return self.json(200, service.grid.configure(user["id"], self.body()))
        if method == "GET" and path == "/api/admin/compute":
            return self.json(200, service.compute.snapshot())
        if method == "POST" and path == "/api/admin/compute/jobs":
            return self.json(202, service.compute.submit(user["id"], self.body()))
        if method == "GET" and path == "/api/admin/rentals":
            service.rentals.refresh()
            return self.json(200, service.rentals.view())
        if method == "POST" and path == "/api/admin/rentals/account":
            return self.json(200, service.rentals.connect(user["id"], self.body()))
        if method == "POST" and path == "/api/admin/rentals/forget":
            return self.json(200, service.rentals.forget(user["id"], self.body().get("provider")))
        if method == "POST" and path == "/api/admin/rentals/check":
            return self.json(200, service.rentals.check(self.body().get("model")))
        if method == "POST" and path == "/api/admin/rentals/offers":
            return self.json(200, service.rentals.quote(user["id"], self.body()))
        if method == "POST" and path == "/api/admin/rentals/rent":
            # The GPU connects back to the address this page came from.
            return self.json(201, service.rentals.rent(user["id"], self.body(), ("https://" if service.public else "http://") + host))
        if method == "POST" and path == "/api/admin/rentals/stop":
            return self.json(200, service.rentals.stop(user["id"], self.body().get("id")))
        if method == "POST" and path == "/api/admin/compute/models":
            return self.json(200, service.compute.offer(user["id"], self.body().get("models")))
        if method == "POST" and path == "/api/admin/compute/admission":
            service.compute.admit(user["id"], self.body().get("open"))
            return self.json(200, {"open": service.compute.admission()})
        if method == "POST" and path == "/api/admin/compute/password":
            service.compute.policy(user["id"], self.body().get("password", ""))
            return self.json(200, {"ok": True})
        if method == "POST" and path == "/api/admin/compute/disconnect":
            service.compute.revoke(user["id"], self.body().get("id"))
            return self.json(200, {"ok": True})
        if method == "GET" and path == "/api/keys":
            with store.db() as db:
                rows = db.execute("SELECT id,label,scopes,created,revoked FROM api_keys WHERE user_id=? ORDER BY created DESC", (user["id"],))
                return self.json(200, {"keys": [{**dict(r), "scopes": json.loads(r["scopes"])} for r in rows]})
        if method == "POST" and path == "/api/keys":
            data = self.body()
            return self.json(201, store.create_key(user["id"], data.get("label"), data.get("scopes")))
        if method == "POST" and path == "/api/keys/revoke":
            data = self.body()
            with store.db() as db:
                db.execute("UPDATE api_keys SET revoked=1 WHERE id=? AND user_id=?", (data.get("id"), user["id"]))
            return self.json(200, {"ok": True})
        if method == "GET" and path == "/api/usage":
            with store.db() as db:
                rows = db.execute("SELECT model,started,duration_ms,status,input_tokens,d.cached_tokens AS cached_tokens,output_tokens,b.charged AS cost_microusd,b.state AS billing_state,m.images,m.output_ms FROM requests r LEFT JOIN billing_results b ON b.id=r.id LEFT JOIN request_details d ON d.id=r.id LEFT JOIN request_media m ON m.id=r.id WHERE user_id=? ORDER BY started DESC LIMIT 100", (user["id"],))
                return self.json(200, {"requests": [dict(r) for r in rows]})
        if method == "GET" and path == "/api/admin/overview":
            with store.db() as db:
                endpoints = [dict(r) for r in db.execute("SELECT id,name,url,place,state,checked,detail FROM endpoints ORDER BY name")]
                counts = {"users": db.execute("SELECT COUNT(*) FROM users").fetchone()[0],
                          "requests": db.execute("SELECT COUNT(*) FROM requests").fetchone()[0],
                          "completed": db.execute("SELECT COUNT(*) FROM requests WHERE status='completed'").fetchone()[0]}
                audit = [dict(r) for r in db.execute("SELECT at,action,target FROM audit ORDER BY id DESC LIMIT 30")]
            return self.json(200, {"endpoints": endpoints, "counts": counts, "audit": audit})
        if method == "POST" and path == "/api/admin/endpoints":
            return self.json(201, service.add_endpoint(user["id"], self.body()))
        if method == "POST" and path == "/api/admin/endpoints/remove":
            data = self.body()
            with store.db() as db:
                db.execute("DELETE FROM endpoints WHERE id=?", (data.get("id"),))
                store.audit(db, user["id"], "endpoint.disconnected", str(data.get("id", ""))[:100])
            return self.json(200, {"ok": True})
        if method == "POST" and path == "/api/admin/models/censorship":
            data = self.body()
            store.label_model(user["id"], data.get("id"), data.get("censorship"))
            return self.json(200, {"ok": True})
        if method == "POST" and path == "/api/admin/refresh":
            service.refresh()
            return self.json(200, {"ok": True})
        if method == "POST" and path == "/api/admin/invitations":
            data=self.body()
            return self.json(201, store.invite(user["id"], data.get("email"),data.get('admin',False)))
        if method == "POST" and path == "/api/admin/choices":
            return self.json(200, service.choose(user["id"], self.body()))
        if method == "POST" and path == "/api/admin/site":
            data = self.body()
            if not isinstance(data.get("name"), str) or not 1 <= len(data["name"].strip()) <= 80:
                raise ValueError("Use a website name of 1 to 80 characters.")
            if not isinstance(data.get("tagline"), str) or len(data["tagline"]) > 200 or data.get("palette") not in PALETTES:
                raise ValueError("Use a tagline of up to 200 characters and one of the colour styles.")
            with store.db() as db:
                db.execute("UPDATE settings SET name=?,tagline=? WHERE id=1", (data["name"].strip(), data["tagline"]))
                db.execute("INSERT OR REPLACE INTO site_palette VALUES(1,?)", (data["palette"],))
                store.audit(db, user["id"], "site.updated", "branding")
            return self.json(200, {"ok": True})
        return self.error(404, "This page or action does not exist.")

    def run_request(self, method):
        try:
            self.dispatch(method)
        except MediaInput as error:
            self.json(error.status, {"error": {"code": error.code, "message": str(error)}})
        except (AccountError, ChoiceInput, ComputeInput, GridInput, WalletInput, SubscriptionInput) as error:
            self.error(400, str(error))
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            self.error(400, "Check the supplied values and try again.")
        except UpstreamError as error:
            self.error(error.status, str(error))
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except (sqlite3.Error, OSError):
            self.error(503, "The service could not finish this operation. Try again shortly.")

    def do_GET(self):
        self.run_request("GET")

    def do_POST(self):
        self.run_request("POST")

    def do_DELETE(self):
        self.run_request("DELETE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", default=os.getenv("SOLVER_DATA", "/data"))
    parser.add_argument("--host", default=os.getenv("SOLVER_BIND", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=3000)
    parser.add_argument("--account-mode", choices=("public", "private"), default=os.getenv("ACCOUNT_MODE", "private"),
                        help="Public allows signup; private requires invitations. Independent of the website URL.")
    parser.add_argument("--bootstrap", action="store_true", help="Create the admin interactively; the password is hidden.")
    parser.add_argument("--bootstrap-stdin", action="store_true", help="Read initial email/password JSON from protected standard input.")
    args = parser.parse_args()
    bootstrap = None
    try:
        if args.bootstrap:
            bootstrap = {"email": input("Administrator email: "), "password": getpass.getpass("Administrator password (12+ characters): ")}
        elif args.bootstrap_stdin:
            raw = sys.stdin.buffer.read(4097)
            if len(raw) > 4096:
                raise ValueError("Administrator input is too large.")
            bootstrap = json.loads(raw)
        else:
            initial_email = os.environ.pop("ADMIN_BOOTSTRAP_EMAIL", "")
            initial_password = os.environ.pop("ADMIN_BOOTSTRAP_PASSWORD", "")
            if initial_email and initial_password:
                bootstrap = {"email": initial_email, "password": initial_password}
        service = Service(args.data, bootstrap, os.getenv("SITE_NAME", "Inference Solver"),
                          os.getenv("WEB_ACCESS", "private") != "private", account_mode=args.account_mode)
        server = Server((args.host, args.port), service)
    except (ValueError, KeyError, TypeError, OSError):
        print("Cannot start. Create an admin with --bootstrap and check the data folder and port.", file=sys.stderr)
        return 1
    bootstrap = None
    watcher = threading.Thread(target=service.watch, daemon=True)
    watcher.start()
    settlement = threading.Thread(target=service.payments.watch, args=(service.stopped,), daemon=True)
    settlement.start()
    # This is the website's own backend, not a browser connection to the visitor's PC.
    # Packaged deployments without Yougori keep an explicit unavailable state.
    from compute_adapter import Adapter, executable, serve_local
    command = executable()
    if command and os.getenv("SOLVER_COMPUTE", "1") != "0":
        adapter = Adapter(command, service.store.folder / "compute-host", controller=True)
        threading.Thread(target=serve_local, args=(service.compute, adapter, service.stopped), daemon=True).start()
    def stop(*_):
        service.stopped.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    print(f"Inference Solver listening on port {server.server_port}. Account access: {service.account_mode}; compute is managed from Admin.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        service.stopped.set()
        server.server_close()
        watcher.join(timeout=6)
        settlement.join(timeout=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
