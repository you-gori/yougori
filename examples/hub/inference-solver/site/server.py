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
from compute import Compute, ComputeInput
from media import Media, MediaInput
from sandbox_grid import Grid, GridInput
from payments import Payments, WalletInput
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
            except (sqlite3.Error, OSError):
                # Disk pressure or a temporary database lock must not silently
                # end health monitoring for the lifetime of the server.
                print('Model health refresh is temporarily unavailable; retrying.',file=sys.stderr,flush=True)
            self.stopped.wait(30)

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
                # reading the catalog knows which take jobs and which answer chat.
                return self.json(200, {"object": "list", "data": [{"id": m["id"], "object": "model", "owned_by": "inference-solver", "task": m["task"],
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
            return self.json(200, {"user": user, "site": store.settings(), "mode": service.account_mode, "version": "0.1.0"})
        # Browsing is public; inference and account actions still require credentials.
        if method == "GET" and path.startswith("/api/harness-image/"):
            parts = path.removeprefix("/api/harness-image/").split("/")
            if len(parts) not in (1, 2, 3):
                return self.error(404, "This VM image is unavailable.")
            published = service.hosted.get('artifacts') if service.hosted else None
            if published is not None:
                record = published.get('images', {}).get(parts[0])
                if len(parts) != 1 or not record:
                    return self.error(404, "This artifact is not published here.")
                return self.json(200, {**record, 'download_base': published['base']})
            value = harness_download.vm_image(*parts)
            if value is None:
                return self.error(404, "The administrator has not prepared this harness's Yougori VM image yet.")
            if len(parts) == 1:
                return self.json(200, value)
            with value.open("rb") as stream:
                self.begin(200, "application/gzip" if value.suffix == '.gz' else "application/zip", value.stat().st_size)
                while block := stream.read(1024 * 1024):
                    self.wfile.write(block)
            return
        if method == "GET" and path.startswith("/install/") and path.endswith(".ps1"):
            name = path.removeprefix("/install/").removesuffix(".ps1")
            raw = harness_download.powershell(name, ("https://" if service.public else "http://") + host)
            self.begin(200, "text/plain; charset=utf-8", len(raw))
            return self.wfile.write(raw)
        if method == "GET" and path == "/api/harnesses":
            return self.json(200, {"harnesses": [{**h, "setup": harness_download.availability(h['id'], service.hosted.get('artifacts') if service.hosted else None)} for h in service.harnesses],
                "categories": service.categories})
        if method == "GET" and path.startswith("/api/harness-download/"):
            name = path.removeprefix("/api/harness-download/")
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
                fields = ("id", "upstream", "state", "protocols", "features", "price", "cache", "censorship", "censorship_source", "task", "media_price")
                catalog = [{field: model[field] for field in fields} for model in catalog]
            return self.json(200, {"models": catalog})
        if method == "GET" and path == "/api/sandboxes":
            return self.json(200,service.grid.catalog())
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
        if method == "POST" and path == "/api/admin/site":
            data = self.body()
            if not isinstance(data.get("name"), str) or not 1 <= len(data["name"].strip()) <= 80:
                raise ValueError("Use a website name of 1 to 80 characters.")
            if not isinstance(data.get("tagline"), str) or len(data["tagline"]) > 200 or not re.fullmatch(r"#[0-9a-fA-F]{6}", data.get("accent", "")):
                raise ValueError("Use a tagline of up to 200 characters and a six-digit accent color.")
            with store.db() as db:
                db.execute("UPDATE settings SET name=?,tagline=?,accent=? WHERE id=1", (data["name"].strip(), data["tagline"], data["accent"]))
                store.audit(db, user["id"], "site.updated", "branding")
            return self.json(200, {"ok": True})
        return self.error(404, "This page or action does not exist.")

    def run_request(self, method):
        try:
            self.dispatch(method)
        except MediaInput as error:
            self.json(error.status, {"error": {"code": error.code, "message": str(error)}})
        except (AccountError, ComputeInput, GridInput, WalletInput) as error:
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
