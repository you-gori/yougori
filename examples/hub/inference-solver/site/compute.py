"""Scoped compute enrollment, provisioning jobs and outbound model connections.

The website never accepts a shell command, provider URL or engine method. Keys
for model servers stay on the contributing computer. Paid jobs are claimed once.
"""
import base64
import io
import json
import queue
import re
import secrets
import threading
import time

from store import digest, password_hash, password_matches
from upstream import UpstreamError
from compute_options import rental_options
from sandbox_grid import Grid


class ComputeInput(ValueError):
    pass


# A connector's stream (action "stream") stays open this long, then the connector reconnects.
STREAM_SECONDS = 300
# A comment line keeps idle proxies (Cloudflare closes after 100 s of silence) from closing it.
HEARTBEAT_SECONDS = 15
# A request delivered on a stream must be acknowledged this soon, or it fails over to another
# computer: a connection that dropped without closing would otherwise hold it for two minutes.
ACK_SECONDS = 8
# A queued request waits this long for a computer to take it, then this long for the first bytes
# of the answer once taken, and then this long between chunks. Time spent in the queue is not
# charged against the answer: a long reply on a slow computer is cut off only when it stalls.
QUEUE_SECONDS = 120
ANSWER_SECONDS = 120
IDLE_SECONDS = 120


def model_name(value):
    if not isinstance(value, str) or len(value) > 200 or not re.fullmatch(r"(?:hf.co/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ComputeInput("Choose a Hugging Face model repository, such as Qwen/Qwen3-8B.")
    return value


class Response(io.RawIOBase):
    def __init__(self):
        super().__init__()
        self.parts = queue.Queue(8)
        self.pending = b""
        self.headers = threading.Event()
        self.status = 502
        self.content_type = "application/json"
        # When an unclaimed request leaves the queue unserved; a claimed one lives until its caller closes it.
        self.expires = time.monotonic() + QUEUE_SECONDS
        self.ended = False
        self.total = 0
        self.sequence = 0
        self.lock = threading.Lock()

    def readable(self):
        return True

    def close(self):
        super().close()
        self.headers.set()
        try:
            self.parts.put_nowait(None)
        except queue.Full:
            pass

    def readinto(self, target):
        if self.closed:
            return 0
        if not self.pending and not self.ended:
            try:
                chunk = self.parts.get(timeout=IDLE_SECONDS)
            except queue.Empty:
                raise UpstreamError("The contributing computer stopped responding.", 504) from None
            if chunk is None:
                self.ended = True
            else:
                self.pending = chunk
        count = min(len(target), len(self.pending))
        target[:count], self.pending = self.pending[:count], self.pending[count:]
        return count

    def getheader(self, name, default=None):
        return self.content_type if name.lower() == "content-type" else default


class Connection:
    def __init__(self, owner, request_id, raw):
        self.owner, self.request_id, self.raw = owner, request_id, raw

    def close(self):
        with self.owner.lock:
            self.owner.requests.pop(self.request_id, None)
            # A computer at capacity takes its next queued request now, not at its next heartbeat.
            self.owner.changed.notify_all()
        self.raw.close()


class Compute:
    def __init__(self, store):
        from control_panel import ControlPanel
        self.store = store
        self.control = ControlPanel(store)
        self.lock = threading.Lock()
        # Notified when a request is queued for a computer, or when a computer's stream must end.
        self.changed = threading.Condition(self.lock)
        self.requests = {}
        self.sensitive = {}
        self.local_adapter = None
        self.router = None
        self.generations = {}  # host -> the number of its newest stream; older ones end
        self.capacities = {}   # host -> requests its connector serves at once, across its models
        with store.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS compute_policy(id INTEGER PRIMARY KEY CHECK(id=1), password TEXT NOT NULL);
                INSERT OR IGNORE INTO compute_policy VALUES(1,'');
                CREATE TABLE IF NOT EXISTS compute_hosts(id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL, seen INTEGER NOT NULL,
                    inventory TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS compute_pairs(code TEXT PRIMARY KEY, device TEXT UNIQUE NOT NULL,
                    host TEXT NOT NULL REFERENCES compute_hosts(id), expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS compute_jobs(id TEXT PRIMARY KEY, host TEXT NOT NULL REFERENCES compute_hosts(id),
                    kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL, result TEXT NOT NULL,
                    detail TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL);
            """)

    def local_host(self, name):
        """Only called by the trusted startup configuration, never by an HTTP route."""
        token = secrets.token_urlsafe(32)
        with self.store.db() as db:
            db.execute("INSERT INTO compute_hosts VALUES('website-host',?,?,'controller',1,0,'{}') "
                       "ON CONFLICT(id) DO UPDATE SET token=excluded.token,name=excluded.name,active=1",
                       (digest(token), name[:80]))
            db.execute("UPDATE compute_jobs SET state='attention',detail='Connector restarted. Inspect this operation before retrying.' "
                       "WHERE host='website-host' AND state='running'")
        return token

    def pair(self, data):
        token_hash, name, role = data.get("credential_hash"), data.get("name"), data.get("role")
        if (not isinstance(token_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", token_hash)
                or not isinstance(name, str) or not 1 <= len(name) <= 80 or role != "contributor"):
            raise ComputeInput("Invalid computer enrollment.")
        code, device, host = secrets.token_hex(4).upper(), secrets.token_urlsafe(32), secrets.token_hex(16)
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM compute_pairs WHERE expires<?", (int(time.time()),))
            db.execute("DELETE FROM compute_hosts WHERE active=0 AND id NOT IN (SELECT host FROM compute_pairs)")
            if db.execute("SELECT COUNT(*) FROM compute_hosts").fetchone()[0] >= 100:
                raise ComputeInput("Computer enrollment is full.")
            db.execute("INSERT INTO compute_hosts VALUES(?,?,?,?,0,0,'{}')", (host, token_hash, name, role))
            db.execute("INSERT INTO compute_pairs VALUES(?,?,?,?)", (digest(code), digest(device), host, int(time.time()) + 600))
        return {"code": code, "device": device, "expires_in": 600}

    def pair_status(self, device):
        with self.store.db() as db:
            row = db.execute("SELECT h.active,p.expires FROM compute_pairs p JOIN compute_hosts h ON h.id=p.host WHERE device=?", (digest(str(device)),)).fetchone()
        return {"connected": bool(row and row["active"] == 1), "expired": not row or row["expires"] < time.time()}

    def approve(self, user, data):
        grid_allowed = Grid(self.store).contributor_allowed(user, data.get("password", ""))
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT h.*,p.expires FROM compute_pairs p JOIN compute_hosts h ON h.id=p.host WHERE p.code=?",
                             (digest(str(data.get("code", "")).strip().upper()),)).fetchone()
            if not row or row["active"] or row["expires"] < time.time():
                raise ComputeInput("This computer code has expired or was already used.")
            stored = db.execute("SELECT password FROM compute_policy WHERE id=1").fetchone()[0]
            if not user["admin"] and not grid_allowed and (row["role"] == "controller" or not stored or not password_matches(data.get("password", ""), stored)):
                raise ComputeInput("Ask the administrator to approve this computer, or use the contributor password.")
            db.execute("UPDATE compute_hosts SET active=1 WHERE id=?", (row["id"],))
            self.store.audit(db, user["id"], "compute.approved", row["id"])
        return {"connected": True, "name": row["name"], "role": row["role"]}

    def inspect_pair(self, code):
        with self.store.db() as db:
            row = db.execute("SELECT h.name,h.role,p.expires,h.active FROM compute_pairs p JOIN compute_hosts h ON h.id=p.host WHERE p.code=?",
                             (digest(str(code).strip().upper()),)).fetchone()
        if not row or row["active"] or row["expires"] < time.time():
            raise ComputeInput("This computer code has expired or was already used.")
        return {"name": row["name"], "role": row["role"]}

    def policy(self, actor, value):
        if not isinstance(value, str):
            raise ComputeInput("Use a password or leave it empty.")
        hashed = password_hash(value) if value else ""
        with self.store.db() as db:
            db.execute("UPDATE compute_policy SET password=? WHERE id=1", (hashed,))
            self.store.audit(db, actor, "compute.password.changed", "contributors")

    def host(self, token):
        with self.store.db() as db:
            row = db.execute("SELECT * FROM compute_hosts WHERE token=? AND active=1", (digest(token),)).fetchone()
        if not row:
            raise UpstreamError("Reconnect this computer with a new approval code.", 401)
        return dict(row)

    def snapshot(self):
        with self.store.db() as db:
            hosts = [dict(row) for row in db.execute("SELECT id,name,role,seen,inventory FROM compute_hosts WHERE active=1")]
            jobs = [dict(row) for row in db.execute("SELECT id,host,kind,state,result,detail,created,updated FROM compute_jobs ORDER BY created DESC LIMIT 50")]
            protected = bool(db.execute("SELECT password FROM compute_policy WHERE id=1").fetchone()[0])
        for host in hosts:
            host["online"] = host["seen"] > time.time() - 45
            host["inventory"] = json.loads(host["inventory"])
        for job in jobs:
            job["result"] = json.loads(job["result"])
        return {"hosts": hosts, "jobs": jobs, "password_set": protected}

    def revoke(self, actor, host):
        with self.store.db() as db:
            db.execute("UPDATE compute_hosts SET active=2 WHERE id=?", (host,))
            db.execute("DELETE FROM endpoints WHERE url LIKE ?", ("compute://" + host + "/%",))
            db.execute("UPDATE compute_jobs SET state='cancelled',detail='Computer disconnected.' WHERE host=? AND state='queued'", (host,))
            self.store.audit(db, actor, "compute.disconnected", host)
        with self.lock:
            for request in self.requests.values():
                if request["host"] == host:
                    request["response"].close()
            self.generations[host] = self.generations.get(host, 0) + 1
            self.changed.notify_all()

    def inventory(self, host, data):
        from control_panel import clean
        items = data.get("models", [])
        if not isinstance(items, list) or len(items) > 64:
            raise ComputeInput("Too many models in this computer's inventory.")
        cleaned = []
        for item in items:
            if (not isinstance(item, dict) or not isinstance(item.get("id"), str)
                    or not re.fullmatch(r"[a-zA-Z0-9_.-]{1,100}", item["id"])):
                raise ComputeInput("Invalid model identity.")
            cleaned.append({"id": item["id"], "name": str(item.get("name", "Model"))[:200],
                            "state": "ready" if item.get("state") == "ready" else "unavailable",
                            "shared": item.get("shared") is True, "place": "neocloud" if item.get("place") == "neocloud" else "local",
                            # Requests its model server generates together, when the connector knows.
                            **({"slots": item["slots"]} if type(item.get("slots")) is int and 1 <= item["slots"] <= 256 else {})})
        inventory = {"models": cleaned, "platform": str(data.get("platform", ""))[:80],
                     "detail": str(data.get("detail", ""))[:200], "connected": data.get("connected", True) is True,
                     "telemetry":clean(data.get('telemetry'))}
        capacity = data.get("capacity")
        with self.lock:
            if type(capacity) is int and 1 <= capacity <= 64:
                self.capacities[host["id"]] = capacity
            capacity = self.capacities.get(host["id"])
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE compute_hosts SET inventory=?,seen=? WHERE id=? AND active=1", (json.dumps(inventory), now, host["id"]))
            self.control.record(db,host['id'],inventory['telemetry'])
            prefix = "compute://" + host["id"] + "/"
            db.execute("UPDATE endpoints SET state='unavailable' WHERE url LIKE ?", (prefix + "%",))
            for item in cleaned:
                identity = "node-" + digest(host["id"] + ":" + item["id"])[:32]
                if not item["shared"]:
                    db.execute("DELETE FROM endpoints WHERE id=?", (identity,))
                    continue
                db.execute("INSERT INTO endpoints VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,"
                           "state=excluded.state,checked=excluded.checked,detail=excluded.detail",
                           (identity, host["name"] + " · " + item["name"], prefix + item["id"], "", item["place"], item["state"], now, "Connected automatically by Yougori."))
                db.execute("DELETE FROM models WHERE endpoint_id=?", (identity,))
                db.execute("INSERT INTO models VALUES(?,?,?)", (identity + ":" + item["name"], identity, item["name"]))
                if self.router and "slots" in item:
                    self.router.report_slots(identity + ":" + item["name"], item["slots"])
                if self.router and capacity:
                    # The connector's limit is across its models: two shared models share the eight.
                    self.router.report_group(identity + ":" + item["name"], host["id"], capacity)

    def submit(self, actor, data):
        kind, host_id = data.get("kind"), data.get("host")
        if kind not in ("offers", "share", "load", "rent", "stop", "provider", "start", "account"):
            raise ComputeInput("Unknown compute action.")
        identity = data.get("request_id")
        if not isinstance(identity, str) or not re.fullmatch(r"[a-f0-9-]{16,64}", identity):
            raise ComputeInput("A request identity is required.")
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT id FROM compute_jobs WHERE id=?", (identity,)).fetchone()
            if previous:
                return {"id": identity}
            host = db.execute("SELECT * FROM compute_hosts WHERE id=? AND active=1", (host_id,)).fetchone()
            if not host or host["role"] != "controller" or host["seen"] < time.time() - 45:
                raise ComputeInput("Connect an online Yougori controller first.")
            payload = {}
            if kind == "offers":
                payload = rental_options(data)
            if kind == "share":
                found = next((m for m in json.loads(host["inventory"]).get("models", []) if m["id"] == data.get("environment")), None)
                if not found:
                    raise ComputeInput("This model is no longer on the selected computer.")
                payload = {"environment": found["id"], "enabled": data.get("enabled") is True}
            if kind in ("load", "rent"):
                payload["model"] = model_name(data.get("model"))
            if kind == "rent":
                if data.get("cost_acknowledged") is not True:
                    raise ComputeInput("Review and accept the provider's charges first.")
                quotes = db.execute("SELECT result,updated FROM compute_jobs WHERE host=? AND kind='offers' AND state='done' " +
                    ("AND id=? " if data.get("quote_id") else "") + "ORDER BY updated DESC LIMIT 1",
                    (host_id,data["quote_id"]) if data.get("quote_id") else (host_id,)).fetchone()
                if not quotes or quotes["updated"] < time.time() - 120:
                    raise ComputeInput("Refresh GPU offers before renting.")
                offer = next((o for o in json.loads(quotes["result"]).get("offers", []) if o["id"] == data.get("offer")), None)
                if not offer:
                    raise ComputeInput("Choose an available GPU offer.")
                payload["offer"] = offer
            if kind == "stop":
                rental = db.execute("SELECT result FROM compute_jobs WHERE id=? AND host=? AND kind='rent'", (data.get("rental"), host_id)).fetchone()
                environment = json.loads(rental[0]).get("environment") if rental else None
                if not environment:
                    raise ComputeInput("No managed rental was found.")
                payload = {"environment": environment}
            pending = db.execute("SELECT COUNT(*) FROM compute_jobs WHERE host=? AND state IN ('queued','running')", (host_id,)).fetchone()[0]
            if pending >= 8 and kind != "stop":
                raise ComputeInput("This computer is busy. Wait for its current operations.")
            if kind == "provider":
                key = data.get("key")
                if not isinstance(key, str) or not 8 <= len(key) <= 1024:
                    raise ComputeInput("Enter your RunPod account key.")
                # One delivery only, never written to the database or audit log.
                with self.lock:
                    self.sensitive[identity] = key
            now = int(time.time())
            db.execute("INSERT INTO compute_jobs VALUES(?,?,?,?,'queued','{}','Waiting for Yougori.',?,?)", (identity, host_id, kind, json.dumps(payload), now, now))
            self.store.audit(db, actor, "compute." + kind, identity)
        return {"id": identity}

    def claim(self, host, via, count=1, capacity=None):
        """Hands queued requests for `host` to one connector (the lock is held). With `capacity`,
        never more than that many of the host's requests are in progress at once."""
        now = time.monotonic()
        busy = sum(1 for r in self.requests.values() if r["host"] == host and r["claimed"]) if capacity else 0
        tasks = []
        for identity, request in list(self.requests.items()):
            if len(tasks) >= count or (capacity and busy >= capacity):
                break
            if request["response"].closed or (not request["claimed"] and request["response"].expires < now):
                self.requests.pop(identity, None)
            elif request["host"] == host and not request["claimed"]:
                request.update(claimed=True, via=via, claimed_at=now)
                busy += 1
                tasks.append({"id": identity, "environment": request["environment"], "payload": request["payload"]})
        return tasks

    def unclaim(self, identities):
        with self.lock:
            for identity in identities:
                request = self.requests.get(identity)
                if request and not request["acked"]:
                    request.update(claimed=False, via=None, claimed_at=None)
            self.changed.notify_all()

    def ack(self, host, data):
        """A connector confirms it received a request from its stream and is serving it."""
        with self.lock:
            request = self.requests.get(data.get("id"))
            if not request or request["host"] != host["id"] or not request["claimed"] or request["response"].closed:
                return False
            request["acked"] = True
            return True

    def stream(self, handler, host, data):
        """Delivers a computer's inference requests over one long-lived response, the moment each
        arrives, instead of the connector asking several times a second. Each line is a Server-Sent
        Event; comment lines keep idle proxies from closing it. A newer stream from the same computer
        replaces this one. The stream does not hold one of the website's request slots."""
        capacity = data.get("capacity", 4)
        if type(capacity) is not int or not 1 <= capacity <= 64:
            raise ComputeInput("Invalid connector capacity.")
        server = handler.server
        with self.lock:
            self.capacities[host["id"]] = capacity
        if not server.streams.acquire(blocking=False):
            raise UpstreamError("Too many computers are connected. Retry shortly.", 503)
        server.slots.release()
        try:
            with self.lock:
                generation = self.generations[host["id"]] = self.generations.get(host["id"], 0) + 1
                self.changed.notify_all()
            handler.begin(200, "text/event-stream; charset=utf-8")
            handler.wfile.write(b": connected\n\n")
            handler.wfile.flush()
            ends, beat = time.monotonic() + STREAM_SECONDS, time.monotonic()
            while time.monotonic() < ends and not server.service.stopped.is_set():
                with self.changed:
                    if self.generations.get(host["id"]) != generation:
                        return self.replaced(handler, host)
                    tasks = self.claim(host["id"], "stream", capacity, capacity)
                    remaining = min(HEARTBEAT_SECONDS - (time.monotonic() - beat), ends - time.monotonic())
                    if not tasks and remaining > 0:
                        self.changed.wait(remaining)
                        if self.generations.get(host["id"]) != generation:
                            return self.replaced(handler, host)
                        tasks = self.claim(host["id"], "stream", capacity, capacity)
                try:
                    for task in tasks:
                        handler.wfile.write(b"data: " + json.dumps({"inference": task}, allow_nan=False).encode() + b"\n\n")
                    if not tasks and time.monotonic() - beat >= HEARTBEAT_SECONDS:
                        handler.wfile.write(b": ping\n\n")
                    if tasks or time.monotonic() - beat >= HEARTBEAT_SECONDS:
                        handler.wfile.flush()
                        beat = time.monotonic()
                except OSError:
                    # Undelivered requests go back to the queue for this computer's next stream or poll.
                    self.unclaim([task["id"] for task in tasks])
                    return
        finally:
            server.streams.release()
            server.slots.acquire()

    def replaced(self, handler, host):
        """Tells a connector whose stream a newer one replaced, when the computer is still
        connected: a second connector was started with the same credential, and the first one
        stops rather than both reconnecting forever. A disconnected computer learns that from
        its next request instead."""
        with self.store.db() as db:
            active = db.execute("SELECT 1 FROM compute_hosts WHERE id=? AND active=1", (host["id"],)).fetchone()
        if not active:
            return
        try:
            handler.wfile.write(b"data: " + json.dumps({"replaced": True}).encode() + b"\n\n")
            handler.wfile.flush()
        except OSError:
            pass

    def poll(self, host, accept_job=True):
        with self.lock:
            tasks = self.claim(host["id"], "poll")
        if tasks:
            return {"inference": tasks[0]}
        if host["role"] == "controller":
            with self.store.db() as db:
                db.execute("BEGIN IMMEDIATE")
                job = db.execute("SELECT * FROM compute_jobs WHERE host=? AND state='queued' " +
                                 ("" if accept_job else "AND kind='stop' ") + "ORDER BY created LIMIT 1", (host["id"],)).fetchone()
                if job:
                    db.execute("UPDATE compute_jobs SET state='running',updated=? WHERE id=?", (int(time.time()), job["id"]))
                    value = {"id": job["id"], "kind": job["kind"], "payload": json.loads(job["payload"])}
                    if job["kind"] == "provider":
                        with self.lock:
                            value["payload"]["key"] = self.sensitive.pop(job["id"], None)
                    return {"job": value}
        return {}

    def result(self, host, data):
        state = data.get("state")
        if state not in ("running", "done", "attention"):
            raise ComputeInput("Invalid operation state.")
        result = data.get("result", {})
        # Allow only public resource descriptions. Never pass arbitrary agent data through.
        clean = {k: result[k] for k in ("environment", "offers", "checked_at", "name", "account") if k in result}
        if len(json.dumps(clean)) > 100000:
            raise ComputeInput("Operation result is too large.")
        with self.store.db() as db:
            db.execute("UPDATE compute_jobs SET state=?,result=?,detail=?,updated=? WHERE id=? AND host=? AND state='running'",
                       (state, json.dumps(clean), str(data.get("detail", ""))[:300], int(time.time()), data.get("id"), host["id"]))

    def connect(self, url, payload):
        host, environment = url.removeprefix("compute://").split("/", 1)
        with self.store.db() as db:
            available = db.execute("SELECT 1 FROM compute_hosts WHERE id=? AND active=1 AND seen>?", (host, time.time() - 45)).fetchone()
        if not available:
            raise UpstreamError("This contributing computer is offline.", 503)
        if host == "website-host" and self.local_adapter:
            from urllib.parse import urlsplit
            from upstream import connect
            with self.local_adapter.lock:
                api = self.local_adapter.apis.get(environment) if environment in self.local_adapter.shared else None
            if not api:
                raise UpstreamError("This model is no longer shared.", 503)
            parsed = urlsplit(api["apiUrl"])
            if parsed.scheme != "http" or parsed.hostname not in ("localhost", "127.0.0.1", "::1") or parsed.username or parsed.password:
                raise UpstreamError("Yougori did not provide a local model connection.", 503)
            return connect(api["apiUrl"], api["apiKey"], "/chat/completions", {**payload, "model": api["model"]}, timeout=120)
        raw, identity = Response(), secrets.token_hex(16)
        with self.lock:
            if len(self.requests) >= 32:
                raise UpstreamError("The contributing computers are busy. Retry shortly.", 429)
            self.requests[identity] = {"host": host, "environment": environment, "payload": payload, "response": raw,
                                       "claimed": False, "via": None, "claimed_at": None, "acked": False}
            self.changed.notify_all()
        connection = Connection(self, identity, raw)
        queued = time.monotonic()
        while not raw.headers.wait(.2):
            now = time.monotonic()
            with self.lock:
                item = self.requests.get(identity) or {}
                taken = item.get("claimed_at")
                lost = item.get("via") == "stream" and not item["acked"] and now - taken > ACK_SECONDS
            if lost:
                connection.close()
                raise UpstreamError("The contributing computer did not take the request.", 503)
            if now > (taken + ANSWER_SECONDS if taken else queued + QUEUE_SECONDS):
                connection.close()
                raise UpstreamError("The contributing computer did not answer.", 504)
        if raw.status != 200:
            connection.close()
            # A model server's refusal (400) or a full queue (429) is passed on as such.
            if raw.status in (400, 429):
                raise UpstreamError("The model server refused this request. Check its context length and parameters." if raw.status == 400
                                    else "The contributing computer is busy. Retry shortly.", raw.status)
            raise UpstreamError("The contributing computer could not serve this request.", 502)
        response = io.BufferedReader(raw)
        response.getheader = raw.getheader
        return connection, response

    def chunk(self, host, data):
        with self.lock:
            item = self.requests.get(data.get("id"))
            if item and item["host"] == host["id"]:
                item["acked"] = True
        if not item or item["response"].closed:
            # The caller may finish at SSE [DONE] before the connector sees EOF.
            return False
        if item["host"] != host["id"]:
            raise ComputeInput("This inference request is no longer active.")
        raw = item["response"]
        content = base64.b64decode(data.get("data", ""), validate=True)
        if len(content) > 65536:
            raise ComputeInput("Response chunk too large.")
        with raw.lock:
            if type(data.get("sequence")) is int and data["sequence"] == raw.sequence - 1:
                return True  # The previous chunk again: its upload was retried after a lost reply.
            if type(data.get("sequence")) is not int or data["sequence"] != raw.sequence:
                raise ComputeInput("Response chunks must arrive in order.")
            if raw.total + len(content) > 16 * 1024 * 1024:
                raise ComputeInput("Response too large.")
            if not raw.headers.is_set():
                raw.status = data.get("status", 502)
                raw.content_type = "text/event-stream" if data.get("stream") is True else "application/json"
                raw.headers.set()
            try:
                if content:
                    raw.parts.put(content, timeout=10)
                if data.get("done") is True:
                    raw.parts.put(None, timeout=10)
            except queue.Full:
                raw.close()
                raise UpstreamError("The inference caller stopped reading.", 503) from None
            raw.sequence += 1
            raw.total += len(content)
        return True
