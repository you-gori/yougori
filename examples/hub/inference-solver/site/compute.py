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

from store import MEDIA_TASKS, digest, password_hash, password_matches
from upstream import UpstreamError
from compute_adapter import download_words, trim
from compute_options import rental_options
from sandbox_grid import Grid
import model_check


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
# What one relayed answer may carry: a chat reply, or a media job's file (a video of minutes).
REPLY_LIMIT = 16 * 1024 * 1024
FILE_LIMIT = 2 * 1024 ** 3
CHUNK_LIMIT = 1024 * 1024
# What a relayed answer may be: chat and job records, or a media job's file.
RELAYED_TYPES = {"application/json", "text/event-stream", "image/png", "image/jpeg", "image/webp", "video/mp4", "audio/wav", "audio/x-wav"}
# A connector's steps for a model that cannot answer yet; the website lists such a model as loading.
PREPARING = ("downloading", "loading", "starting")
# How a connector refuses a chat request for a model that cannot answer yet, with a fallback reason.
NOT_READY = {"model_downloading": "The model is still downloading on the contributing computer.",
             "model_loading": "The model is still loading onto the contributing computer's GPU.",
             "model_starting": "The model is still starting on the contributing computer.",
             "model_unavailable": "The model could not load on the contributing computer."}


def checked_progress(value):
    """A connector's download progress, when it is whole numbers with 0 <= received <= total <=
    10^13, total above 0 and a rate (bytes a second) of at least 0; None otherwise."""
    if not isinstance(value, dict):
        return None
    received, total, rate = (value.get(key) for key in ("received", "total", "rate"))
    if any(type(number) is not int for number in (received, total, rate)) or not (0 <= received <= total <= 10 ** 13 and total > 0 and 0 <= rate <= 10 ** 13):
        return None
    return {"received": received, "total": total, "rate": rate}


def preparing(phase, progress):
    """What a model a computer is still preparing is doing, in the website's own words, built only
    from the numbers it checked: it follows "is still" in a refusal and shows in the catalog."""
    if phase == "downloading":
        return "downloading" + (" (" + download_words(progress) + ")" if progress else "")
    return "loading onto the GPU" if phase == "loading" else "starting its model server"


def model_name(value):
    if not isinstance(value, str) or len(value) > 200 or not re.fullmatch(r"(?:hf.co/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        # References pasted from other tools end in a quantization (owner/model-GGUF:UD-Q4_K_M),
        # which Yougori chooses itself; say what to change instead of only refusing.
        if isinstance(value, str) and len(value) <= 200 and re.fullmatch(r"(?:hf.co/)?[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+", value):
            raise ComputeInput("Type only owner/model, without the ending after ':'. For a GGUF repository, Yougori "
                               "picks the file itself: Q4_K_M when the repository has one (a UD-Q4_K_M file counts as Q4_K_M).")
        if isinstance(value, str) and len(value) <= 200 and re.fullmatch(r"[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?", value):
            raise ComputeInput("Type the owner too, as owner/model, such as Qwen/Qwen3-8B or unsloth/Qwen3-8B-GGUF.")
        raise ComputeInput("Choose a Hugging Face model repository, such as Qwen/Qwen3-8B.")
    return value


# The models the administrator lets connected computers run. Each computer installs 1 to
# MOST_PER_COMPUTER of them; a website without any takes only Sandbox VMs from computers.
OFFERED_LIMIT = 20
MOST_PER_COMPUTER = 3


def offered_key(name):
    """A model's name as the list compares it: hf.co/Owner/Name is Owner/Name, in any case."""
    return name.removeprefix("hf.co/").lower()


class Response(io.RawIOBase):
    def __init__(self, limit=REPLY_LIMIT):
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
        self.limit = limit
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
        # How a model added for computers is checked (model_check.check; tests give a fake).
        self.check_model = model_check.check
        self.generations = {}  # host -> the number of its newest stream; older ones end
        self.capacities = {}   # host -> requests its connector serves at once, across its models
        self.media_hosts = set()  # hosts whose connector relays a media model's job routes and files
        with store.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS compute_policy(id INTEGER PRIMARY KEY CHECK(id=1), password TEXT NOT NULL);
                INSERT OR IGNORE INTO compute_policy VALUES(1,'');
                -- Whether a connecting computer joins at once (open) or shows a code to approve.
                CREATE TABLE IF NOT EXISTS compute_admission(id INTEGER PRIMARY KEY CHECK(id=1), open INTEGER NOT NULL);
                INSERT OR IGNORE INTO compute_admission VALUES(1,0);
                CREATE TABLE IF NOT EXISTS compute_hosts(id TEXT PRIMARY KEY, token TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL, seen INTEGER NOT NULL,
                    inventory TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS compute_pairs(code TEXT PRIMARY KEY, device TEXT UNIQUE NOT NULL,
                    host TEXT NOT NULL REFERENCES compute_hosts(id), expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS compute_jobs(id TEXT PRIMARY KEY, host TEXT NOT NULL REFERENCES compute_hosts(id),
                    kind TEXT NOT NULL, payload TEXT NOT NULL, state TEXT NOT NULL, result TEXT NOT NULL,
                    detail TEXT NOT NULL, created INTEGER NOT NULL, updated INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS compute_models(repo TEXT PRIMARY KEY COLLATE NOCASE, position INTEGER NOT NULL);
                -- What each listed model needs from a GPU, checked when it was added (model_check).
                CREATE TABLE IF NOT EXISTS compute_model_facts(repo TEXT PRIMARY KEY COLLATE NOCASE, facts TEXT NOT NULL, checked INTEGER NOT NULL);
            """)

    def offered(self):
        """The models connected computers may run, in the administrator's order."""
        with self.store.db() as db:
            return [row["repo"] for row in db.execute("SELECT repo FROM compute_models ORDER BY position")]

    def offer(self, actor, models):
        """Replaces the models connected computers may run. A model taken off the list leaves the
        catalog at each computer's next inventory, within seconds."""
        if not isinstance(models, list) or len(models) > OFFERED_LIMIT:
            raise ComputeInput(f"List at most {OFFERED_LIMIT} models for computers to run.")
        names = [model_name(value.strip() if isinstance(value, str) else value).removeprefix("hf.co/") for value in models]
        known = self.model_facts()
        chosen, checked = [], {}
        for name in names:
            facts = known.get(offered_key(name))
            if facts is None:
                # A model added now is checked first: one Yougori cannot run is refused, with why.
                try:
                    facts = self.check_model(name)
                except model_check.CheckError as error:
                    raise ComputeInput(str(error)) from None
                checked[offered_key(facts["model"])] = facts
            name = facts["model"]
            if offered_key(name) not in map(offered_key, chosen):
                chosen.append(name)
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM compute_models")
            db.executemany("INSERT INTO compute_models VALUES(?,?)", [(name, place) for place, name in enumerate(chosen)])
            db.executemany("INSERT INTO compute_model_facts VALUES(?,?,?) ON CONFLICT(repo) DO UPDATE SET facts=excluded.facts,checked=excluded.checked",
                           [(facts["model"], json.dumps(facts), now) for facts in checked.values()])
            self.store.audit(db, actor, "compute.models.changed", ", ".join(chosen)[:500])
        return {"models": chosen}

    def check_listed(self):
        """Checks each listed model that has no check yet (listed before models were checked),
        once. One Yougori cannot run keeps the reason, which Admin shows; one Hugging Face did
        not answer for is tried again next time."""
        known = self.model_facts()
        for name in self.offered():
            if offered_key(name) in known:
                continue
            try:
                facts = self.check_model(name)
            except model_check.CheckError as error:
                if error.transient:
                    continue
                facts = {"model": name, "problem": str(error)}
            with self.store.db() as db:
                db.execute("INSERT INTO compute_model_facts VALUES(?,?,?) ON CONFLICT(repo) DO UPDATE SET facts=excluded.facts,checked=excluded.checked",
                           (name, json.dumps(facts), int(time.time())))

    def model_facts(self):
        """What each checked model needs, by its offered_key."""
        with self.store.db() as db:
            return {offered_key(row["repo"]): json.loads(row["facts"]) for row in db.execute("SELECT repo,facts FROM compute_model_facts")}

    def needs(self):
        """For connecting computers: each listed model's GPU memory, generation and summary."""
        known = self.model_facts()
        return {name: {key: known[offered_key(name)][key] for key in ("gpu_gb", "compute", "summary")}
                for name in self.offered() if "gpu_gb" in known.get(offered_key(name), {})}

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
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM compute_pairs WHERE expires<?", (now,))
            db.execute("DELETE FROM compute_hosts WHERE active=0 AND id NOT IN (SELECT host FROM compute_pairs)")
            # Without codes, any computer joins at once: approved, as the administrator would.
            open_ = db.execute("SELECT open FROM compute_admission WHERE id=1").fetchone()[0] == 1
            if open_ and db.execute("SELECT COUNT(*) FROM compute_hosts").fetchone()[0] >= 100:
                # Room for new computers: those that joined without a code and have been gone a month.
                db.execute("DELETE FROM compute_hosts WHERE role='contributor' AND active=1 AND seen<? AND id NOT IN (SELECT host FROM compute_pairs)",
                           (now - 30 * 86400,))
            if db.execute("SELECT COUNT(*) FROM compute_hosts").fetchone()[0] >= 100:
                raise ComputeInput("Computer enrollment is full.")
            db.execute("INSERT INTO compute_hosts VALUES(?,?,?,?,?,0,'{}')", (host, token_hash, name, role, 1 if open_ else 0))
            db.execute("INSERT INTO compute_pairs VALUES(?,?,?,?)", (digest(code), digest(device), host, now + 600))
            if open_:
                self.store.audit(db, "open-admission", "compute.joined", host)
        return {"code": code, "device": device, "expires_in": 600, **({"connected": True} if open_ else {})}

    def admission(self):
        """Whether connecting computers join without a code."""
        with self.store.db() as db:
            return db.execute("SELECT open FROM compute_admission WHERE id=1").fetchone()[0] == 1

    def admit(self, actor, open_):
        """Lets computers join without a code (open), or asks each for its code again."""
        if not isinstance(open_, bool):
            raise ComputeInput("Choose whether computers need a code.")
        with self.store.db() as db:
            db.execute("UPDATE compute_admission SET open=? WHERE id=1", (int(open_),))
            self.store.audit(db, actor, "compute.admission." + ("open" if open_ else "code"), "contributors")

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
        # Each listed model with what it needs and how many connected computers have a GPU for it.
        known, computers = self.model_facts(), [h for h in hosts if h["role"] == "contributor" and h["online"]]
        gpus = [[(gpu.get("name"), (gpu.get("memory_total_mb") or 0) / 1024) for gpu in ((h["inventory"].get("telemetry") or {}).get("gpus") or [])
                 if isinstance(gpu, dict)] for h in computers]
        needs = {name: {**known[offered_key(name)], "computers": len(computers),
                        **({} if "problem" in known[offered_key(name)] else {"fits": sum(model_check.fits(known[offered_key(name)], listed) for listed in gpus)})}
                 for name in self.offered() if offered_key(name) in known}
        return {"hosts": hosts, "jobs": jobs, "password_set": protected, "offered": self.offered(), "needs": needs, "open": self.admission()}

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
            # A model still downloading, loading or starting is listed as loading, with what it is
            # doing in the website's words; older connectors say only ready or unavailable.
            said = item.get("state")
            state = "ready" if said == "ready" else "loading" if said in PREPARING else "unavailable"
            progress = checked_progress(item.get("progress")) if said == "downloading" else None
            cleaned.append({"id": item["id"], "name": str(item.get("name", "Model"))[:200],
                            "state": state,
                            **({"phase": said, "detail": preparing(said, progress), **({"progress": progress} if progress else {})} if state == "loading" else {}),
                            "shared": item.get("shared") is True, "place": "neocloud" if item.get("place") == "neocloud" else "local",
                            # Requests its model server generates together, when the connector knows.
                            **({"slots": item["slots"]} if type(item.get("slots")) is int and 1 <= item["slots"] <= 256 else {}),
                            # Whether its model server enforces a JSON reply format, when the connector knows.
                            **({"json": item["json"]} if isinstance(item.get("json"), bool) else {}),
                            # The kind of model its server serves (text-generation, or a media task).
                            **({"task": item["task"]} if isinstance(item.get("task"), str) and re.fullmatch(r"[a-z][a-z-]{0,39}", item["task"]) else {}),
                            # The context, in tokens, its model server serves, when the connector knows.
                            **({"context": item["context"]} if type(item.get("context")) is int and 256 <= item["context"] <= 1048576 else {})})
        # A contributing computer serves only the models the administrator lists for computers;
        # the website's own server and the GPUs it rents serve what the administrator chose there.
        if host.get("role") == "contributor":
            offered = set(map(offered_key, self.offered()))
            for item in cleaned:
                item["offered"] = offered_key(item["name"]) in offered
        inventory = {"models": cleaned, "platform": str(data.get("platform", ""))[:80],
                     "detail": str(data.get("detail", ""))[:200], "connected": data.get("connected", True) is True,
                     # A rented GPU whose model could not start (the website then deletes the GPU).
                     "failed": data.get("failed") is True,
                     "telemetry":clean(data.get('telemetry'))}
        capacity = data.get("capacity")
        with self.lock:
            if type(capacity) is int and 1 <= capacity <= 64:
                self.capacities[host["id"]] = capacity
            capacity = self.capacities.get(host["id"])
            # A connector that relays media jobs says so; an older one relays chat only.
            (self.media_hosts.add if data.get("media") is True else self.media_hosts.discard)(host["id"])
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("UPDATE compute_hosts SET inventory=?,seen=? WHERE id=? AND active=1", (json.dumps(inventory), now, host["id"]))
            self.control.record(db,host['id'],inventory['telemetry'])
            prefix = "compute://" + host["id"] + "/"
            db.execute("UPDATE endpoints SET state='unavailable',detail='Connected automatically by Yougori.' WHERE url LIKE ?", (prefix + "%",))
            for item in cleaned:
                identity = "node-" + digest(host["id"] + ":" + item["id"])[:32]
                if not item["shared"] or item.get("offered") is False:
                    db.execute("DELETE FROM endpoints WHERE id=?", (identity,))
                    continue
                db.execute("INSERT INTO endpoints VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,"
                           "state=excluded.state,checked=excluded.checked,detail=excluded.detail",
                           (identity, host["name"] + " · " + item["name"], prefix + item["id"], "", item["place"], item["state"], now,
                            item.get("detail") or "Connected automatically by Yougori."))
                self.store.replace_models(db, identity, [(item["name"], {"json": item.get("json"), "task": item.get("task"), "context": item.get("context")})])
                if self.router and item.get("task") in MEDIA_TASKS:
                    # A media model generates one job at a time: the router spreads jobs by that.
                    self.router.report_slots(identity + ":" + item["name"], 1)
                elif self.router and "slots" in item:
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
                # The route and method tell a connector what to relay: chat by default, a media
                # model's job routes and files otherwise (an older connector relays chat only).
                tasks.append({"id": identity, "environment": request["environment"], "payload": request["payload"],
                              "path": request.get("path", "/chat/completions"), "method": request.get("method", "POST"),
                              "limit": request["response"].limit})
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

    def connect(self, url, payload, path="/chat/completions", method="POST", limit=REPLY_LIMIT):
        """Opens one request to a model a contributing computer shares: the connector relays it to
        the model's own API (`path` under its base, `method`) and streams the answer back, of at
        most `limit` bytes."""
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
            body = None if method == "GET" else {**payload, "model": api["model"]} if path == "/chat/completions" else payload
            if body is not None and path == "/chat/completions":
                # A reply limit the model takes, as a contributor's connector trims it: at most
                # 4,096 tokens and what the context leaves.
                known = self.local_adapter.facts_read.get(environment, ({}, 0))[0]
                body = trim(body, api.get("context") or known.get("context"), api.get("reply_limit", 4096))
            return connect(api["apiUrl"], api["apiKey"], path, body, timeout=600 if path != "/chat/completions" else 120, expect=(200, 201, 202, 206), method=method)
        if path != "/chat/completions":
            with self.lock:
                relays = host in self.media_hosts
            if not relays:
                raise UpstreamError("The computer sharing this model runs a connector that predates media jobs. Update Yougori there and reconnect.", 503)
        raw, identity = Response(limit), secrets.token_hex(16)
        with self.lock:
            if len(self.requests) >= 32:
                raise UpstreamError("The contributing computers are busy. Retry shortly.", 429)
            self.requests[identity] = {"host": host, "environment": environment, "payload": payload, "response": raw, "path": path, "method": method,
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
        if raw.status not in (200, 201, 202, 206):
            # A model server's refusal (400) or a full queue (429) is passed on as such; a media
            # route's own answers (404 unknown job, 409 not done, 410 failed) keep their words.
            if raw.status in (400, 429) and path == "/chat/completions":
                # A refusal carries the model server's own reason when the connector sends it: a
                # conversation too long for the model's context, for example.
                body = io.BufferedReader(raw).read(65536) if raw.status == 400 else b""
                connection.close()
                message, code = "", ""
                try:
                    detail = json.loads(body)["error"]
                    message = re.sub(r"[^ -~]", "", str(detail.get("message", "")))[:300]
                    code = str(detail.get("code", ""))[:40] if re.fullmatch(r"[a-z_]{1,40}", str(detail.get("code", ""))) else ""
                except (ValueError, KeyError, TypeError, AttributeError):
                    pass
                raise UpstreamError(message or ("The model server refused this request. Check its context length and parameters." if raw.status == 400
                                                else "The contributing computer is busy. Retry shortly."), raw.status, code)
            if raw.status == 503 and path == "/chat/completions":
                # A model the computer is still downloading or loading is refused at once, with how
                # far it has got. Any other 503 is the computer's failure, as before.
                body = io.BufferedReader(raw).read(65536)
                connection.close()
                message, code = "", ""
                try:
                    detail = json.loads(body)["error"]
                    message, code = re.sub(r"[^ -~]", "", str(detail.get("message", "")))[:300], str(detail.get("code", ""))
                except (ValueError, KeyError, TypeError, AttributeError):
                    pass
                if code in NOT_READY:
                    raise UpstreamError(message or NOT_READY[code], 503, code)
                raise UpstreamError("The contributing computer could not serve this request.", 502)
            if path != "/chat/completions" and raw.status in (400, 404, 409, 410, 429, 503):
                body = io.BufferedReader(raw).read(65536)
                connection.close()
                try:
                    detail = json.loads(body)["error"]
                    message, code = str(detail.get("message", ""))[:300], str(detail.get("code", ""))[:40]
                except (ValueError, KeyError, TypeError, AttributeError):
                    message, code = "The model server refused this request.", ""
                raise UpstreamError(message or "The model server refused this request.", raw.status, code)
            connection.close()
            raise UpstreamError("The contributing computer could not serve this request.", 502)
        response = io.BufferedReader(raw)
        response.getheader = raw.getheader
        response.status = raw.status
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
        if len(content) > CHUNK_LIMIT:
            raise ComputeInput("Response chunk too large.")
        with raw.lock:
            if type(data.get("sequence")) is int and data["sequence"] == raw.sequence - 1:
                return True  # The previous chunk again: its upload was retried after a lost reply.
            if type(data.get("sequence")) is not int or data["sequence"] != raw.sequence:
                raise ComputeInput("Response chunks must arrive in order.")
            if raw.total + len(content) > raw.limit:
                raise ComputeInput("Response too large.")
            if not raw.headers.is_set():
                status = data.get("status")
                raw.status = status if type(status) is int and 100 <= status <= 599 else 502
                kind = data.get("content_type")
                kind = kind.split(";")[0].strip().lower() if isinstance(kind, str) else ""
                raw.content_type = "text/event-stream" if data.get("stream") is True else kind if kind in RELAYED_TYPES else "application/json"
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
