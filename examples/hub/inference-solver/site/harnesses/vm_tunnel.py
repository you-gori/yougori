"""Tunnels to the sites a harness session may reach.

A harness VM has no network card unless its owner allowed the whole internet. When the owner chose
sites instead, the harness reaches them through an HTTPS proxy inside the VM (HTTPS_PROXY): each
CONNECT becomes a tunnel over the same owner-only channel that carries the model relay, and the
launcher on the host opens it only to a chosen site, on port 443, at a public address. The host's
check is the one that counts; the VM's answers 403 early. TLS runs end to end between the tool and
the site; neither half reads it.
"""
import base64
import collections
import http.client
import http.server
import ipaddress
import queue
import re
import secrets
import socket
import threading

PROXY_PORT = 3128
CHUNK = 256 * 1024  # raw bytes in one tunnel message, either way
QUEUED = 4 * 1024 * 1024  # VM bytes waiting for the host before the proxy waits too
POLL_BYTES = 1024 * 1024  # encoded tunnel bytes one poll carries
MAX_TUNNELS = 32
MAX_SITES = 64
SITE = re.compile(r"(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")
IDENTITY = re.compile(r"[a-f0-9]{32}")


def sites(values):
    """The chosen site names, lowercased and without repeats. Each is a DNS name with a dot (never
    an address) and also covers its subdomains: github.com allows api.github.com."""
    if not isinstance(values, (list, tuple)) or not 1 <= len(values) <= MAX_SITES:
        raise ValueError("Choose 1 to %d sites." % MAX_SITES)
    chosen = []
    for value in values:
        name = value.strip().lower().rstrip(".") if isinstance(value, str) else ""
        if not SITE.fullmatch(name):
            raise ValueError("%r is not a site name such as github.com." % (value,))
        if name not in chosen:
            chosen.append(name)
    return chosen


def allowed(chosen, host):
    """Whether `host` is a chosen site or one of its subdomains."""
    host = host.lower().rstrip(".") if isinstance(host, str) else ""
    return any(host == site or host.endswith("." + site) for site in chosen)


class Tunnel:
    def __init__(self, client):
        self.id = secrets.token_hex(16)
        self.client = client
        self.answered = threading.Event()
        self.error = None


class GuestTunnels:
    """The VM's half: the proxy's tunnels and the messages waiting for the host's next poll. `lock`
    is the session's condition, so a waiting poll wakes for tunnel traffic too."""

    def __init__(self, chosen, lock):
        self.sites = chosen
        self.lock = lock
        self.tunnels = {}
        self.events = collections.deque()
        self.queued = 0

    def open(self, host, port, client):
        with self.lock:
            if len(self.tunnels) >= MAX_TUNNELS:
                return None
            tunnel = Tunnel(client)
            self.tunnels[tunnel.id] = tunnel
            self.events.append({"tunnel": tunnel.id, "open": host, "port": port})
            self.lock.notify_all()
        return tunnel

    def send(self, identity, block):
        """Queues the client's bytes for the host; waits while too much is queued."""
        with self.lock:
            self.lock.wait_for(lambda: self.queued < QUEUED or identity not in self.tunnels, timeout=120)
            if identity not in self.tunnels or self.queued >= QUEUED:
                return False
            self.events.append({"tunnel": identity, "data": base64.b64encode(block).decode()})
            self.queued += len(block)
            self.lock.notify_all()
        return True

    def close(self, identity, tell):
        with self.lock:
            tunnel = self.tunnels.pop(identity, None)
            if tunnel is not None and tell:
                self.events.append({"tunnel": identity, "close": True})
            self.lock.notify_all()
        if tunnel is not None:
            tunnel.answered.set()
            try:
                tunnel.client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        return tunnel is not None

    def take(self):
        """The messages for one poll. Call with the lock held."""
        taken, size = [], 0
        while self.events and size < POLL_BYTES:
            event = self.events.popleft()
            if "data" in event:
                self.queued = max(0, self.queued - len(event["data"]) * 3 // 4)
                size += len(event["data"])
            taken.append(event)
        if taken:
            self.lock.notify_all()
        return taken

    def from_host(self, data):
        """A message from the host: its answer to an open, bytes for the client, or the end."""
        identity = data.get("tunnel")
        with self.lock:
            tunnel = self.tunnels.get(identity)
        if tunnel is None:
            return False
        if data.get("error") is not None:
            tunnel.error = str(data["error"])[:300]
            tunnel.answered.set()
            return True
        if data.get("opened") is True:
            tunnel.answered.set()
        if data.get("data"):
            block = base64.b64decode(data["data"], validate=True)
            if len(block) > CHUNK:
                raise ValueError("Tunnel message too large.")
            try:
                tunnel.client.sendall(block)
            except OSError:
                self.close(identity, tell=True)
        if data.get("close") is True:
            self.close(identity, tell=False)
        return True


class Proxy(http.server.BaseHTTPRequestHandler):
    """The VM's HTTPS proxy: CONNECT to a chosen site on port 443, nothing else."""
    rbufsize = 0  # nothing the client sends after CONNECT may sit in a buffer
    server_version = "YougoriSites"
    sys_version = ""

    def log_message(self, *_):
        pass

    def refuse(self, status, text):
        self.send_response(status, " ".join(text.split())[:200])
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_CONNECT(self):
        tunnels = self.server.tunnels
        host, _, port = self.path.rpartition(":")
        if port != "443" or not allowed(tunnels.sites, host):
            return self.refuse(403, "Only the sites chosen for this session are reachable")
        tunnel = tunnels.open(host.lower().rstrip("."), 443, self.connection)
        if tunnel is None:
            return self.refuse(503, "Too many open connections")
        if not tunnel.answered.wait(45) or tunnel.error or tunnel.id not in tunnels.tunnels:
            tunnels.close(tunnel.id, tell=True)
            return self.refuse(502, tunnel.error or "The site did not answer")
        self.send_response(200, "Connection established")
        self.end_headers()
        try:
            while block := self.connection.recv(CHUNK):
                if not tunnels.send(tunnel.id, block):
                    break
        except OSError:
            pass
        tunnels.close(tunnel.id, tell=True)

    def plain(self):
        self.refuse(405, "Use HTTPS: this proxy only opens tunnels to the chosen sites")

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = do_OPTIONS = plain


def serve_proxy(tunnels, port=PROXY_PORT):
    """Starts the VM's proxy on loopback for `tunnels`."""
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Proxy)
    server.daemon_threads = True
    server.tunnels = tunnels
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def public_connection(host, port, timeout=20):
    """A TCP connection to a chosen site at a public address only: never this computer, its
    network or another non-global address, whatever the name resolves to."""
    last = None
    for family, kind, proto, _, address in socket.getaddrinfo(host, port, type=socket.SOCK_STREAM):
        if not ipaddress.ip_address(address[0].split("%")[0]).is_global:
            last = ValueError(host + " resolves to a private or local address.")
            continue
        connection = socket.socket(family, kind, proto)
        try:
            connection.settimeout(timeout)
            connection.connect(address)
            connection.settimeout(None)
            return connection
        except OSError as error:
            connection.close()
            last = error
    raise last or OSError("No address for " + host + ".")


class HostTunnels:
    """The launcher's half: opens a tunnel only to a chosen site, then moves its bytes. `post`
    sends one message to the VM (its /tunnel)."""

    def __init__(self, post, chosen, connect=public_connection):
        self.post, self.sites, self.connect = post, chosen, connect
        self.lock = threading.Lock()
        self.open = {}

    def handle(self, event):
        identity = event.get("tunnel") if isinstance(event, dict) else None
        if not isinstance(identity, str) or not IDENTITY.fullmatch(identity):
            raise ValueError("Invalid VM tunnel message.")
        if "open" in event:
            with self.lock:
                if len(self.open) >= MAX_TUNNELS or identity in self.open:
                    raise ValueError("Invalid VM tunnel message.")
                self.open[identity] = None
            threading.Thread(target=self.run, args=(identity, event.get("open"), event.get("port")), daemon=True).start()
        elif "data" in event:
            with self.lock:
                entry = self.open.get(identity)
            if entry is not None:
                try:
                    entry[1].put(base64.b64decode(event["data"], validate=True), timeout=60)
                except queue.Full:
                    self.finish(identity, tell=True)
        elif event.get("close") is True:
            self.finish(identity, tell=False)
        else:
            raise ValueError("Invalid VM tunnel message.")

    def run(self, identity, host, port):
        try:
            if port != 443 or not allowed(self.sites, host):
                raise ValueError("That site was not chosen for this session.")
            connection = self.connect(host, port)
        except (OSError, ValueError) as error:
            with self.lock:
                self.open.pop(identity, None)
            self.tell({"tunnel": identity, "error": str(error) or "The site could not be reached."})
            return
        outgoing = queue.Queue(maxsize=64)
        with self.lock:
            if identity not in self.open:
                connection.close()
                return
            self.open[identity] = (connection, outgoing)
        threading.Thread(target=self.write, args=(identity, connection, outgoing), daemon=True).start()
        if not self.tell({"tunnel": identity, "opened": True}):
            return self.finish(identity, tell=False)
        try:
            while block := connection.recv(CHUNK):
                if not self.tell({"tunnel": identity, "data": base64.b64encode(block).decode()}):
                    break
        except OSError:
            pass
        self.finish(identity, tell=True)

    def write(self, identity, connection, outgoing):
        while (block := outgoing.get()) is not None:
            try:
                connection.sendall(block)
            except OSError:
                return self.finish(identity, tell=True)

    def tell(self, message):
        try:
            self.post(message)
            return True
        except (OSError, ValueError, http.client.HTTPException):
            return False

    def finish(self, identity, tell):
        with self.lock:
            entry = self.open.pop(identity, None)
        if not entry:
            return
        connection, outgoing = entry
        try:
            outgoing.put_nowait(None)
        except queue.Full:
            pass
        try:
            connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        connection.close()
        if tell:
            self.tell({"tunnel": identity, "close": True})

    def close_all(self):
        with self.lock:
            identities = list(self.open)
        for identity in identities:
            self.finish(identity, tell=False)
