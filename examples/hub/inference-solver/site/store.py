"""Private inference-service state. One short-lived SQLite connection per operation."""
import contextlib
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import shutil
import time
import threading
import unicodedata

# Common markers in the names of models published without refusal training. An administrator's label wins.
UNCENSORED = re.compile(r"uncensor|decensor|abliterat|obliterat|unfilter|unalign|heretic|dolphin", re.I)
# Replica states, best first: a model takes the state of its best replica.
STATES = ("ready", "checking", "stale", "unavailable")
# Completed requests with reported cache use before a model's cache hit rate is published.
CACHE_MINIMUM = 5


class AccountError(ValueError):
    """An account validation message that is safe to show to the user."""


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def email(value):
    if not isinstance(value, str) or len(value) > 254:
        raise ValueError("Enter a valid email address.")
    value = value.strip().lower()
    if not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", value):
        raise ValueError("Enter a valid email address.")
    return value


def password_hash(value, salt=None):
    if not isinstance(value, str) or not 12 <= len(value) <= 1024:
        raise ValueError("Use a password of 12 to 1024 characters.")
    salt = salt or secrets.token_hex(16)
    hashed = hashlib.scrypt(value.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()
    return salt + ":" + hashed


def password_matches(value, stored):
    try:
        if stored.startswith("scrypt$"):
            _, salt, expected = stored.split("$")
            actual = hashlib.scrypt(unicodedata.normalize("NFKC", value).encode(),
                salt=base64.b64decode(salt, validate=True), n=32768, r=8, p=1, dklen=32, maxmem=96*1024*1024)
            return hmac.compare_digest(actual, base64.b64decode(expected, validate=True))
        return hmac.compare_digest(password_hash(value, stored.split(":")[0]), stored)
    except (ValueError, TypeError):
        return False


class Store:
    def __init__(self, folder, bootstrap=None, site_name="Inference Solver", journal_mode="WAL", runtime_folder=None):
        if journal_mode not in ("WAL", "DELETE"):
            raise ValueError("Unsupported database journal mode.")
        self.database_lock = threading.RLock()
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.folder / "inference-solver.sqlite3"
        self.snapshot = None
        self.persistence_failed = False
        if runtime_folder is not None:
            self.snapshot = self.path
            runtime = Path(runtime_folder)
            runtime.mkdir(parents=True, exist_ok=True, mode=0o700)
            self.path = runtime / "inference-solver.sqlite3"
            if self.snapshot.exists():
                shutil.copyfile(self.snapshot, self.path)
        with self.db() as db:
            db.execute("PRAGMA journal_mode=" + journal_mode)
            db.executescript("""
                CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY CHECK(id=1), name TEXT NOT NULL,
                    tagline TEXT NOT NULL, accent TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL, admin INTEGER NOT NULL DEFAULT 0 CHECK(admin IN (0,1)));
                CREATE TABLE IF NOT EXISTS sessions (hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES users(id),
                    csrf TEXT NOT NULL, expires INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS invites (hash TEXT PRIMARY KEY, email TEXT NOT NULL, expires INTEGER NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS api_keys (id TEXT PRIMARY KEY, hash TEXT UNIQUE NOT NULL,
                    user_id TEXT NOT NULL REFERENCES users(id), label TEXT NOT NULL, scopes TEXT NOT NULL,
                    created INTEGER NOT NULL, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS endpoints (id TEXT PRIMARY KEY, name TEXT NOT NULL, url TEXT NOT NULL,
                    secret TEXT NOT NULL, place TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'checking',
                    checked INTEGER NOT NULL DEFAULT 0, detail TEXT NOT NULL DEFAULT '');
                CREATE TABLE IF NOT EXISTS models (id TEXT PRIMARY KEY, endpoint_id TEXT NOT NULL REFERENCES endpoints(id)
                    ON DELETE CASCADE, upstream TEXT NOT NULL);
                -- Refreshes replace model rows, so labels are kept apart; a reconnected model keeps its label.
                CREATE TABLE IF NOT EXISTS model_labels (id TEXT PRIMARY KEY, uncensored INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS token_prices (model TEXT PRIMARY KEY, input_microusd INTEGER NOT NULL, output_microusd INTEGER NOT NULL);
                -- Prompt tokens a model server reused from its cache. Without a row they cost the input price.
                CREATE TABLE IF NOT EXISTS token_cache_prices (model TEXT PRIMARY KEY, cached_microusd INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS invite_roles(hash TEXT PRIMARY KEY,admin INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS requests (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, key_id TEXT NOT NULL,
                    model TEXT NOT NULL, started INTEGER NOT NULL, duration_ms INTEGER NOT NULL, status TEXT NOT NULL,
                    input_tokens INTEGER, output_tokens INTEGER);
                CREATE INDEX IF NOT EXISTS requests_user ON requests(user_id, started);
                -- Which computer or model server served a request, and the prompt tokens it had cached.
                CREATE TABLE IF NOT EXISTS request_details (id TEXT PRIMARY KEY, endpoint TEXT NOT NULL, source TEXT NOT NULL,
                    cached_tokens INTEGER);
                CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY, at INTEGER NOT NULL,
                    user_id TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL);
            """)
            db.execute("BEGIN IMMEDIATE")
            db.execute("INSERT OR IGNORE INTO settings VALUES(1, ?, ?, ?)",
                       (site_name[:80], "Your models. Your infrastructure. Your rules.", "#0b1f4d"))
            if not db.execute("SELECT 1 FROM users WHERE admin=1").fetchone():
                if not bootstrap:
                    raise ValueError("Create the administrator in the CLI with --bootstrap, or supply the template's admin credentials.")
                imported = bootstrap.get("password_hash")
                if imported is not None:
                    scheme, salt, key = imported.split("$")
                    if scheme != "scrypt" or len(base64.b64decode(salt, validate=True)) != 16 or len(base64.b64decode(key, validate=True)) != 32:
                        raise ValueError("Invalid administrator credential.")
                db.execute("INSERT INTO users VALUES(?,?,?,1)", (secrets.token_hex(16), email(bootstrap["email"]),
                                                               imported or password_hash(bootstrap["password"])))
        if os.name != "nt":
            os.chmod(self.path, 0o600)

    @contextlib.contextmanager
    def db(self):
        with self.database_lock:
            if self.persistence_failed:
                raise OSError("The durable database snapshot failed. Restart this instance before accepting more changes.")
            connection = sqlite3.connect(self.path, timeout=10)
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA foreign_keys=ON")
            if self.snapshot:
                # Bound both the guest working copy and its atomic workspace snapshot.
                connection.execute("PRAGMA max_page_count=8192")
            before = connection.execute("PRAGMA schema_version").fetchone()[0]
            try:
                with connection:
                    yield connection
                if self.snapshot and (connection.total_changes or connection.execute("PRAGMA schema_version").fetchone()[0] != before):
                    temporary = self.snapshot.with_suffix(".next")
                    try:
                        with temporary.open("wb") as output:
                            output.write(connection.serialize())
                            output.flush()
                            os.fsync(output.fileno())
                        temporary.replace(self.snapshot)
                    except BaseException:
                        self.persistence_failed = True
                        raise
            finally:
                connection.close()

    @staticmethod
    def audit(db, user, action, target):
        db.execute("INSERT INTO audit(at,user_id,action,target) VALUES(?,?,?,?)", (int(time.time()), user, action, target))

    def settings(self):
        with self.db() as db:
            return dict(db.execute("SELECT name,tagline,accent FROM settings WHERE id=1").fetchone())

    def signup(self, address, password):
        try:
            address, hashed = email(address), password_hash(password)
        except ValueError as error:
            raise AccountError(str(error)) from None
        user_id = secrets.token_hex(16)
        with self.db() as db:
            try:
                # Public registration can never create or replace an administrator.
                db.execute("INSERT INTO users VALUES(?,?,?,0)", (user_id, address, hashed))
            except sqlite3.IntegrityError:
                raise AccountError("An account with this email already exists. Sign in instead.") from None
            self.audit(db, user_id, "account.created", user_id)

    def login(self, address, password):
        address = email(address)
        with self.db() as db:
            user = db.execute("SELECT * FROM users WHERE email=?", (address,)).fetchone()
        # Unknown accounts take the same password-derivation path as known accounts.
        stored = user["password"] if user else "00" * 16 + ":" + "00" * 64
        if not password_matches(password, stored) or not user:
            raise ValueError("Email or password is incorrect.")
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with self.db() as db:
            db.execute("DELETE FROM sessions WHERE expires<=?", (int(time.time()),))
            db.execute("INSERT INTO sessions VALUES(?,?,?,?)", (digest(token), user["id"], csrf, int(time.time()) + 43200))
        return token

    def session(self, token):
        with self.db() as db:
            row = db.execute("SELECT u.id,u.email,u.admin,s.csrf FROM sessions s JOIN users u ON u.id=s.user_id "
                             "WHERE s.hash=? AND s.expires>?", (digest(token), int(time.time()))).fetchone()
            return dict(row) if row else None

    def invite(self, actor, address, admin=False):
        if type(admin) is not bool: raise AccountError("Choose a valid account role.")
        token, address = secrets.token_urlsafe(32), email(address)
        with self.db() as db:
            if db.execute("SELECT 1 FROM users WHERE email=?", (address,)).fetchone():
                raise ValueError("This account already exists.")
            db.execute("INSERT INTO invites VALUES(?,?,?,0)", (digest(token), address, int(time.time()) + 86400))
            db.execute("INSERT INTO invite_roles VALUES(?,?)",(digest(token),int(admin)))
            self.audit(db, actor, "invite.admin_created" if admin else "invite.created", address)
        return {"invitation": token, "email": address, "expiresIn": 86400}

    def redeem(self, address, password, token):
        if not isinstance(token, str) or not 1 <= len(token) <= 256:
            raise ValueError("This invitation is invalid, expired, or already used.")
        address, hashed = email(address), password_hash(password)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM invites WHERE hash=? AND email=? AND used=0 AND expires>?",
                             (digest(token), address, int(time.time()))).fetchone()
            if not row:
                raise ValueError("This invitation is invalid, expired, or already used.")
            try:
                role = db.execute("SELECT admin FROM invite_roles WHERE hash=?",(digest(token),)).fetchone()
                db.execute("INSERT INTO users VALUES(?,?,?,?)", (secrets.token_hex(16), address, hashed, role[0] if role else 0))
            except sqlite3.IntegrityError:
                raise ValueError("This account already exists.") from None
            db.execute("UPDATE invites SET used=1 WHERE hash=?", (digest(token),))

    def change_role(self,actor,data):
        if type(data.get('admin')) is not bool:
            raise AccountError('Choose member or administrator.')
        with self.db() as db:
            db.execute('BEGIN IMMEDIATE')
            caller=db.execute('SELECT admin FROM users WHERE id=?',(actor,)).fetchone()
            target=db.execute('SELECT admin FROM users WHERE id=?',(data.get('id'),)).fetchone()
            if not caller or not caller['admin'] or not target:
                raise AccountError('Only an administrator can change an existing account role.')
            if target['admin'] and not data['admin'] and db.execute('SELECT COUNT(*) FROM users WHERE admin=1').fetchone()[0]<=1:
                raise AccountError('Keep at least one administrator.')
            db.execute('UPDATE users SET admin=? WHERE id=?',(int(data['admin']),data['id']))
            self.audit(db,actor,'account.admin' if data['admin'] else 'account.member',data['id'])
        return {'ok':True}

    def create_key(self, user, label, scopes):
        if not isinstance(label, str) or not 1 <= len(label.strip()) <= 60:
            raise ValueError("Give the key a name of 1 to 60 characters.")
        if not isinstance(scopes, list) or not scopes or len(scopes) > 100 or any(not isinstance(s, str) for s in scopes):
            raise ValueError("Choose at least one model, or all models.")
        token, key_id = "is_" + secrets.token_urlsafe(32), secrets.token_hex(12)
        with self.db() as db:
            if db.execute("SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked=0", (user,)).fetchone()[0] >= 50:
                raise ValueError("Revoke an unused key before creating another.")
            known = {r[0] for r in db.execute("SELECT DISTINCT upstream FROM models")}
            if scopes != ["*"] and any(s not in known for s in scopes):
                raise ValueError("One of the selected models is no longer in the catalog.")
            db.execute("INSERT INTO api_keys VALUES(?,?,?,?,?,?,0)",
                       (key_id, digest(token), user, label.strip(), json.dumps(scopes), int(time.time())))
        return {"id": key_id, "key": token}

    def key(self, token):
        with self.db() as db:
            row = db.execute("SELECT id,user_id,scopes FROM api_keys WHERE hash=? AND revoked=0", (digest(token),)).fetchone()
        if not row:
            return None
        return {**dict(row), "scopes": json.loads(row["scopes"])}

    def models(self, scopes=None):
        """The catalog: one entry per model name, however many replicas (connected computers or
        model servers) serve it. The name is the model's own name, as its servers report it."""
        now = int(time.time())
        with self.db() as db:
            rows = db.execute("SELECT m.upstream,e.name AS source,e.place,e.state,e.checked FROM models m "
                              "JOIN endpoints e ON e.id=m.endpoint_id ORDER BY m.upstream,e.name").fetchall()
            labels = {r[0]: r[1] for r in db.execute("SELECT id,uncensored FROM model_labels")}
            prices = {r["model"]: r for r in db.execute("SELECT * FROM token_prices")}
            cached = {r[0]: r[1] for r in db.execute("SELECT model,cached_microusd FROM token_cache_prices")}
            cache = {r["model"]: r for r in db.execute(
                "SELECT r.model,COUNT(*) AS requests,SUM(r.input_tokens) AS prompt,SUM(d.cached_tokens) AS cached FROM requests r "
                "JOIN request_details d ON d.id=r.id WHERE r.started>? AND r.status='completed' AND r.input_tokens IS NOT NULL "
                "AND d.cached_tokens IS NOT NULL GROUP BY r.model", (now - 86400,))}
        groups = {}
        for row in rows:
            groups.setdefault(row["upstream"], []).append(row)
        catalog = []
        for name, replicas in groups.items():
            if scopes is not None and "*" not in scopes and name not in scopes:
                continue
            states = [r["state"] if r["checked"] > now - 90 else "stale" for r in replicas]
            # One ready replica makes the model available.
            state = min(states, key=lambda s: STATES.index(s) if s in STATES else len(STATES))
            places = {r["place"] for r in replicas}
            price, label, stats = prices.get(name), labels.get(name), cache.get(name)
            inputs = price["input_microusd"] if price else 0
            uncensored = bool(UNCENSORED.search(name)) if label is None else bool(label)
            catalog.append({"id": name, "upstream": name, "state": state, "checked": max(r["checked"] for r in replicas),
                            "place": places.pop() if len(places) == 1 else "mixed",
                            "source": ", ".join(r["source"] for r in replicas),
                            "replicas": [{"name": r["source"], "place": r["place"], "state": s} for r, s in zip(replicas, states)],
                            "protocols": ["chat_completions"],
                            "price": {"input_microusd_per_million": inputs, "output_microusd_per_million": price["output_microusd"] if price else 0,
                                      "cached_microusd_per_million": cached.get(name, inputs)},
                            # The share of prompt tokens served from a model server's cache in the last 24 hours.
                            "cache": {"hit_rate": round(stats["cached"] / stats["prompt"], 4), "requests": stats["requests"]}
                                     if stats and stats["prompt"] and stats["requests"] >= CACHE_MINIMUM else None,
                            "censorship": "uncensored" if uncensored else "censored",
                            "censorship_source": "name" if label is None else "administrator"})
        return catalog

    def label_model(self, actor, model_id, censorship):
        if not isinstance(model_id, str) or censorship not in ("censored", "uncensored", "automatic"):
            raise ValueError("Choose censored, uncensored or automatic for a connected model.")
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM models WHERE upstream=?", (model_id,)).fetchone():
                raise ValueError("This model is no longer connected.")
            if censorship == "automatic":
                db.execute("DELETE FROM model_labels WHERE id=?", (model_id,))
            else:
                db.execute("INSERT INTO model_labels VALUES(?,?) ON CONFLICT(id) DO UPDATE SET uncensored=excluded.uncensored",
                           (model_id, int(censorship == "uncensored")))
            self.audit(db, actor, "model.labeled", model_id[:100])

    def request_done(self, request_id, key, model, started, status, usage=None, db=None, replica=None, cached=None):
        usage = usage or {}
        def tokens(name):
            value = usage.get(name)
            return value if type(value) is int and 0 <= value <= 2**40 else None
        def write(connection):
            connection.execute("INSERT OR IGNORE INTO requests VALUES(?,?,?,?,?,?,?,?,?)", (
                request_id, key["user_id"], key["id"], model, int(started), max(0, int((time.time() - started) * 1000)),
                status, tokens("prompt_tokens"), tokens("completion_tokens")))
            if replica:
                connection.execute("INSERT OR IGNORE INTO request_details VALUES(?,?,?,?)", (
                    request_id, replica["endpoint"], replica["source"][:200], cached if type(cached) is int and 0 <= cached <= 2**40 else None))
        if db is not None:
            write(db)
        else:
            with self.db() as connection:
                write(connection)
