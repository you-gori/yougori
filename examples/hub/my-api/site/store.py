"""Accounts, API keys, model prices, credits and the admin wallet.

Everything lives in one SQLite file under /data, so a restart keeps it. The CLI
provisions the admin before the website starts. Public signups are ordinary users.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time
import math
import re
import sys
from decimal import Decimal, ROUND_CEILING

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import chain
import prices

DATA = os.environ.get("MY_API_DATA", "/data")
DATABASE = os.path.join(DATA, "my-api.db")

# Legacy example rows are retained for database compatibility, not verified prices.
# They remain unavailable until discovered and explicitly priced by the admin.
LEGACY_EXAMPLE_MODELS = [
    # (provider, model, sandbox) — actual IDs come from discovery.
    ("openai", "gpt-5.1", "paid"),
    ("openai", "gpt-5.1-mini", "paid"),
    ("anthropic", "claude-opus-4.5", "paid"),
    ("anthropic", "claude-sonnet-4.5", "paid"),
    ("anthropic", "claude-haiku-4.5", "paid"),
    ("google", "gemini-3-pro", "paid"),
    ("google", "gemini-3-flash", "paid"),
    ("ollama", "llama3.3:70b", "local"),
    ("ollama", "qwen3:32b", "local"),
    ("ollama", "deepseek-r1:14b", "local"),
    ("opencode", "opencode-free", "free"),
    ("kilo", "kilo-free", "free"),
]

# Prices and credits are in USDT, so credits are bought with USDT on these networks. The pattern
# is a quick first check; chain.address() then checks the checksum where the network has one.
NETWORKS = {
    "tron": ("Tron (TRC-20)", "USDT", r"^T[1-9A-HJ-NP-Za-km-z]{33}$", "A Tron address, T and 33 more characters."),
    "ethereum": ("Ethereum (ERC-20)", "USDT", r"^0x[a-fA-F0-9]{40}$", "An Ethereum-style address, 0x and 40 characters."),
    "bsc": ("BNB Smart Chain (BEP-20)", "USDT", r"^0x[a-fA-F0-9]{40}$", "An Ethereum-style address, 0x and 40 characters."),
    "solana": ("Solana", "USDT", r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", "A Solana address, 32 to 44 characters."),
    "polygon": ("Polygon", "USDT", r"^0x[a-fA-F0-9]{40}$", "An Ethereum-style address, 0x and 40 characters."),
    "arbitrum": ("Arbitrum One", "USDT", r"^0x[a-fA-F0-9]{40}$", "An Ethereum-style address, 0x and 40 characters."),
}


# The database layout this code writes. An older database is copied to /data/backups before it is
# changed, and the site refuses to start rather than change it without that copy.
SCHEMA_VERSION = 2
# Open payment requests one person may have at once.
MAX_WAITING_PAYMENTS = 5


class MigrationRefused(RuntimeError):
    """The database needs upgrading and its copy could not be made, so nothing was changed."""


class PaymentConflict(ValueError):
    """The transaction id already confirmed another payment."""


_local = threading.local()


def close():
    connection = getattr(_local, "db", None)
    if connection is not None:
        connection.close()
        del _local.db


def connect():
    """One connection per thread. The website serves requests on several threads, and a
    SQLite connection belongs to the thread that opened it."""
    existing = getattr(_local, "db", None)
    if existing is not None:
        return existing
    os.makedirs(DATA, exist_ok=True)
    db = sqlite3.connect(DATABASE, timeout=30)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA busy_timeout=30000")
    db.execute("PRAGMA foreign_keys=ON")
    _local.db = db
    return db


def backup_before_upgrade(db, version):
    """Copies the database before an upgrade. Raises MigrationRefused when it can't."""
    folder = os.path.join(DATA, "backups")
    target = os.path.join(folder, f"my-api-v{version}-before-v{SCHEMA_VERSION}-{int(time.time())}.db")
    try:
        os.makedirs(folder, exist_ok=True)
        copy = sqlite3.connect(target)
        try:
            db.backup(copy)
        finally:
            copy.close()
        check = sqlite3.connect(target)
        try:
            if check.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise sqlite3.DatabaseError("the copy failed its integrity check")
        finally:
            check.close()
    except (OSError, sqlite3.Error) as error:
        raise MigrationRefused(
            f"The database needs an upgrade, and its copy could not be saved first ({error}). "
            "Nothing was changed. Free some space under /data and restart the website.") from None
    return target


def setup():
    db = connect()
    version = db.execute("PRAGMA user_version").fetchone()[0]
    existing = db.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'").fetchone() is not None
    if existing and version < SCHEMA_VERSION:
        backup_before_upgrade(db, version)
    with db:
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY,
          email TEXT NOT NULL UNIQUE COLLATE NOCASE,
          password_hash TEXT NOT NULL,
          salt TEXT NOT NULL,
          is_admin INTEGER NOT NULL DEFAULT 0,
          credits_micro INTEGER NOT NULL DEFAULT 0,
          created_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
          token_hash TEXT PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          created_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS api_keys (
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          name TEXT NOT NULL,
          prefix TEXT NOT NULL,
          key_hash TEXT NOT NULL UNIQUE,
          model TEXT,
          exhausted_note TEXT,
          created_at INTEGER NOT NULL,
          last_used_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS models (
          id INTEGER PRIMARY KEY,
          provider TEXT NOT NULL,
          name TEXT NOT NULL UNIQUE,
          price_in REAL NOT NULL,
          price_out REAL NOT NULL,
          sandbox TEXT NOT NULL,
          available INTEGER NOT NULL DEFAULT 0,
          note TEXT
        );
        CREATE TABLE IF NOT EXISTS settings (
          key TEXT PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS payments (
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          dollars REAL NOT NULL,
          network TEXT NOT NULL,
          address TEXT NOT NULL,
          reference TEXT NOT NULL UNIQUE,
          state TEXT NOT NULL DEFAULT 'waiting',
          created_at INTEGER NOT NULL,
          confirmed_at INTEGER
        );
        CREATE TABLE IF NOT EXISTS usage (
          id INTEGER PRIMARY KEY,
          user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          key_id INTEGER,
          model TEXT NOT NULL,
          tokens_in INTEGER NOT NULL,
          tokens_out INTEGER NOT NULL,
          cost_micro INTEGER NOT NULL,
          at INTEGER NOT NULL
        );
        """)
        columns = {row[1] for row in db.execute("PRAGMA table_info(models)")}
        if "price_ready" not in columns:
            db.execute("ALTER TABLE models ADD COLUMN price_ready INTEGER NOT NULL DEFAULT 0")
        if "upstream" not in columns:
            db.execute("ALTER TABLE models ADD COLUMN upstream TEXT")
        if "cost_in" not in columns:
            # The price a gateway reports for a model, per million tokens: its cost to the admin.
            db.execute("ALTER TABLE models ADD COLUMN cost_in REAL")
            db.execute("ALTER TABLE models ADD COLUMN cost_out REAL")
        if "price_source" not in columns:
            # Where a price came from: 'list' (the provider's published price, kept current),
            # 'admin' (set by the admin, never overwritten) or '' (not priced yet). Paid models
            # already approved before this column existed were priced by the admin.
            db.execute("ALTER TABLE models ADD COLUMN price_source TEXT NOT NULL DEFAULT ''")
            db.execute("UPDATE models SET price_source = 'admin' WHERE sandbox = 'paid' AND price_ready = 1")
        # Models started with `yougori run MODEL --template INSTANCE`: one per model, the
        # latest start wins. The key is the model API's own; only this sandbox keeps it.
        db.execute("CREATE TABLE IF NOT EXISTS attached (model TEXT PRIMARY KEY, environment TEXT NOT NULL, url TEXT NOT NULL, "
                   "key TEXT NOT NULL, place TEXT NOT NULL DEFAULT 'local', created_at INTEGER NOT NULL)")
        db.execute("CREATE TABLE IF NOT EXISTS reservations (id TEXT PRIMARY KEY, user_id INTEGER NOT NULL, key_id INTEGER NOT NULL, model TEXT NOT NULL, amount INTEGER NOT NULL, price_in REAL NOT NULL, price_out REAL NOT NULL, state TEXT NOT NULL DEFAULT 'pending', created_at INTEGER NOT NULL)")
        # Buyers see a model's own name. Older rows named after their gateway or runtime
        # ("kilo/...", "ollama/...") are renamed, with the keys, usage and holds that use them.
        marks = ",".join("?" * len(UNBRANDED))
        for row in db.execute(f"SELECT id, provider, name FROM models WHERE provider IN ({marks})", UNBRANDED).fetchall():
            if not row["name"].startswith(row["provider"] + "/"):
                continue
            new = public_name(row["provider"], row["name"][len(row["provider"]) + 1:])
            # A never-discovered example row may hold the name already.
            db.execute("DELETE FROM models WHERE name = ? AND upstream IS NULL AND available = 0 AND price_source = ''", (new,))
            if not new or db.execute("SELECT 1 FROM models WHERE name = ?", (new,)).fetchone():
                continue
            db.execute("UPDATE models SET name = ?, upstream = COALESCE(upstream, ?) WHERE id = ?", (new, row["name"], row["id"]))
            for table in ("api_keys", "usage", "reservations"):
                db.execute(f"UPDATE {table} SET model = ? WHERE model = ?", (new, row["name"]))
        # Nothing is free unless the admin sets 0 and 0: earlier automatic zero prices are
        # priced again by the next discovery.
        db.execute("UPDATE models SET price_ready = 0, price_source = '' WHERE price_source = 'free'")
        for provider, name, sandbox in LEGACY_EXAMPLE_MODELS:
            db.execute(
                "INSERT OR IGNORE INTO models (provider, name, price_in, price_out, sandbox, note) VALUES (?, ?, 0, 0, ?, 'Example only; refresh discovery to find actual model IDs.')",
                (provider, name, sandbox))
        # Version 2: payments carry the transaction that paid them, who confirmed or closed them and
        # when they were rejected or cancelled; models carry when they were last found and priced.
        paid = {row[1] for row in db.execute("PRAGMA table_info(payments)")}
        for column, kind in (("tx_id", "TEXT"), ("confirmed_by", "INTEGER"), ("closed_at", "INTEGER")):
            if column not in paid:
                db.execute(f"ALTER TABLE payments ADD COLUMN {column} {kind}")
        # One transaction confirms one payment, whatever happens at the same moment elsewhere.
        db.execute("CREATE UNIQUE INDEX IF NOT EXISTS payments_transaction ON payments(network, tx_id) WHERE tx_id IS NOT NULL")
        listed = {row[1] for row in db.execute("PRAGMA table_info(models)")}
        for column in ("checked_at", "priced_at"):
            if column not in listed:
                db.execute(f"ALTER TABLE models ADD COLUMN {column} INTEGER")
        db.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
    return db


def setting(db, key, value=None):
    if value is None:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else None
    with db:
        db.execute("INSERT INTO settings (key, value) VALUES (?, ?) "
                   "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, value))
    return value


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.scrypt(password.encode(), salt=salt.encode(), n=16384, r=8, p=1, dklen=32)
    return digest.hex(), salt


def check_password(password, stored_hash, salt):
    candidate, _ = hash_password(password, salt)
    return secrets.compare_digest(candidate, stored_hash)


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def has_admin(db):
    return db.execute("SELECT 1 FROM users WHERE is_admin = 1").fetchone() is not None


def validate_account(email, password, minimum=10):
    if not isinstance(email, str) or len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email.strip()):
        raise ValueError("Enter a valid email address.")
    if not isinstance(password, str) or not minimum <= len(password) <= 1024:
        raise ValueError(f"Use a password of {minimum} to 1024 characters.")


def bootstrap_admin(db, email, password):
    """Create the CLI's admin once. An existing admin and password are never changed.

    The write lock covers the check and insert, including competing startups. No
    HTTP route calls this function; regular signup cannot promote an account.
    """
    with db:
        db.execute("BEGIN IMMEDIATE")
        if has_admin(db):
            return False
        validate_account(email, password, minimum=12)
        if user_by_email(db, email):
            raise ValueError("That email already belongs to a user. Choose another admin email in CLI setup.")
        password_hash, salt = hash_password(password)
        db.execute("INSERT INTO users (email,password_hash,salt,is_admin,created_at) VALUES (?,?,?,1,?)",
                   (email.strip(), password_hash, salt, int(time.time())))
    return True


def create_user(db, email, password):
    """Public signups always create ordinary users, after CLI admin setup finishes."""
    validate_account(email, password)
    password_hash, salt = hash_password(password)
    with db:
        db.execute("BEGIN IMMEDIATE")
        if not has_admin(db):
            raise ValueError("The admin account must be created through the Yougori CLI before signup opens.")
        cursor = db.execute(
            "INSERT INTO users (email, password_hash, salt, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
            (email.strip(), password_hash, salt, 0, int(time.time())))
    return cursor.lastrowid, False


def user_by_email(db, email):
    return db.execute("SELECT * FROM users WHERE email = ?", (email.strip(),)).fetchone()


def start_session(db, user_id, days=30):
    token = "sess_" + secrets.token_urlsafe(32)
    now = int(time.time())
    with db:
        db.execute("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
                   (token_hash(token), user_id, now, now + days * 86400))
    return token


def session_user(db, token):
    if not token:
        return None
    row = db.execute(
        "SELECT u.* FROM sessions s JOIN users u ON u.id = s.user_id "
        "WHERE s.token_hash = ? AND s.expires_at > ?", (token_hash(token), int(time.time()))).fetchone()
    return row


def end_session(db, token):
    if token:
        with db:
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (token_hash(token),))


def create_api_key(db, user_id, name, model=None):
    """Returned once. Only its hash is kept, so a lost key cannot be recovered."""
    secret = "yg-" + secrets.token_urlsafe(32)
    with db:
        db.execute("INSERT INTO api_keys (user_id, name, prefix, key_hash, model, created_at) "
                   "VALUES (?, ?, ?, ?, ?, ?)",
                   (user_id, name[:60], secret[:11], token_hash(secret), model, int(time.time())))
    return secret


def api_key_owner(db, secret):
    return db.execute(
        "SELECT k.*, u.credits_micro, u.email FROM api_keys k JOIN users u ON u.id = k.user_id "
        "WHERE k.key_hash = ?", (token_hash(secret),)).fetchone()


def models(db, only_available=False):
    query = "SELECT * FROM models"
    if only_available:
        query += " WHERE available = 1 AND price_ready = 1"
    return db.execute(query + " ORDER BY provider, name").fetchall()


def set_price(db, name, price_in, price_out):
    if any(not math.isfinite(value) or value < 0 or value > 10000 for value in (price_in, price_out)):
        raise ValueError("Invalid price")
    with db:
        changed = db.execute("UPDATE models SET price_in = ?, price_out = ?, price_ready = 1, price_source = 'admin', priced_at = ? "
                             "WHERE name = ?", (price_in, price_out, int(time.time()), name))
        if not changed.rowcount:
            raise ValueError("Unknown model")


def upstream_id(provider, name):
    """The provider's own model ID, from a `provider/model` routing ID."""
    prefix = (provider or "") + "/"
    return name[len(prefix):] if name.startswith(prefix) else name


def row_upstream(row):
    """The provider's own ID for a stored model."""
    return upstream_id(row["provider"], row["upstream"] or row["name"])


# Gateways and runtimes stay out of model names: buyers see the model, not where it runs.
# "yougori" is a Hugging Face model started with `yougori run MODEL --template INSTANCE`.
UNBRANDED = ("kilo", "opencode", "ollama", "yougori")


# A gateway's routers send each request to a model of their choosing ("kilo-auto/free",
# "openrouter/free", "openrouter/auto"): no model anyone can name or price, so never sold.
ROUTERS = ("openrouter", "kilo", "kilocode", "kilo-auto", "auto", "router")


def router(provider, upstream):
    if provider not in ("kilo", "opencode"):
        return False
    name = upstream.lower()
    vendor, _, bare = name.rpartition("/")
    return vendor in ROUTERS or bare in ROUTERS or "auto" in re.split(r"[/:._-]", name)


def public_name(provider, upstream):
    """The name buyers see and call: `openai/gpt-6`, `anthropic/claude-sonnet-4.5`, `llama3.3:70b`."""
    if provider not in UNBRANDED:
        return provider + "/" + upstream
    return upstream[:-len(":free")] if upstream.endswith(":free") else upstream


# Who made a model, from the vendor in its name or else its family.
VENDORS = {"openai": "openai", "anthropic": "anthropic", "google": "google", "meta-llama": "meta", "meta": "meta",
           "qwen": "qwen", "deepseek": "deepseek", "deepseek-ai": "deepseek", "z-ai": "zai", "zai-org": "zai",
           "thudm": "zai", "moonshotai": "moonshot", "minimax": "minimax", "mistralai": "mistral",
           "microsoft": "microsoft", "x-ai": "xai", "nvidia": "nvidia", "cohere": "cohere", "ibm-granite": "ibm",
           "allenai": "allenai", "nousresearch": "nous", "amazon": "amazon", "baidu": "baidu", "tencent": "tencent",
           "bytedance": "bytedance", "bytedance-seed": "bytedance", "stepfun-ai": "stepfun", "inclusionai": "inclusionai",
           "arcee-ai": "arcee", "liquid": "liquid", "ai21": "ai21", "perplexity": "perplexity"}
FAMILIES = (("gpt-oss", "openai"), ("gpt", "openai"), ("chatgpt", "openai"), ("claude", "anthropic"),
            ("gemini", "google"), ("gemma", "google"), ("codegemma", "google"), ("llama", "meta"), ("codellama", "meta"),
            ("qwen", "qwen"), ("qwq", "qwen"), ("deepseek", "deepseek"), ("glm", "zai"), ("kimi", "moonshot"),
            ("minimax", "minimax"), ("mistral", "mistral"), ("mixtral", "mistral"), ("codestral", "mistral"),
            ("devstral", "mistral"), ("magistral", "mistral"), ("ministral", "mistral"), ("pixtral", "mistral"),
            ("phi", "microsoft"), ("grok", "xai"), ("nemotron", "nvidia"), ("command", "cohere"), ("aya", "cohere"),
            ("granite", "ibm"), ("olmo", "allenai"), ("hermes", "nous"), ("smollm", "huggingface"), ("lfm", "liquid"),
            ("jamba", "ai21"), ("ernie", "baidu"), ("hunyuan", "tencent"), ("falcon", "tii"), ("starcoder", "bigcode"))


def maker(provider, name):
    """'openai', 'meta', ... for a model, or '' when its maker is unknown."""
    if provider not in UNBRANDED:
        return provider
    vendor, _, bare = name.lower().rpartition("/")
    vendor = vendor.rsplit("/", 1)[-1]
    if vendor in VENDORS:
        return VENDORS[vendor]
    family = next((who for word, who in FAMILIES if bare.startswith(word)), "")
    return family or (vendor if re.fullmatch(r"[a-z0-9][a-z0-9-]{1,30}", vendor) and vendor not in ("kilo", "kilocode", "opencode", "ollama") else "")


def attach_model(db, model, environment, url, key, place="local"):
    """Lists a model started with `yougori run MODEL --template INSTANCE`, reached at `url`."""
    with db:
        db.execute("INSERT INTO attached (model, environment, url, key, place, created_at) VALUES (?,?,?,?,?,?) "
                   "ON CONFLICT(model) DO UPDATE SET environment=excluded.environment, url=excluded.url, key=excluded.key, "
                   "place=excluded.place, created_at=excluded.created_at",
                   (model, environment, url, key, place, int(time.time())))


def detach_model(db, environment):
    """Takes every model that `environment` serves off the site. Returns how many."""
    with db:
        return db.execute("DELETE FROM attached WHERE environment = ?", (environment,)).rowcount


def attached_models(db):
    return db.execute("SELECT * FROM attached ORDER BY created_at, model").fetchall()


def attachment(db, model):
    return db.execute("SELECT * FROM attached WHERE model = ?", (model,)).fetchone()


MAX_MARKUP = 1000


def markup(db):
    """The admin's markup on default prices, in percent. Zero sells at the default."""
    try:
        value = float(setting(db, "markup_percent") or 0)
    except ValueError:
        return 0.0
    return value if math.isfinite(value) and 0 <= value <= MAX_MARKUP else 0.0


DEFAULT_SOURCES = ("list", "market", "estimate")
NOTES = {"list": "Provider list price", "market": "Market price", "estimate": "Estimated price; check it"}


def valid_cost(cost):
    """A gateway's reported (input, output) price per million tokens, or None."""
    if (isinstance(cost, (list, tuple)) and len(cost) == 2 and
            all(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 10000 for value in cost)):
        return float(cost[0]), float(cost[1])
    return None


def row_cost(row):
    return valid_cost([row["cost_in"], row["cost_out"]]) if row["cost_in"] is not None else None


def default_price(db, provider, upstream, sandbox="paid", cost=None, percent=None):
    """A model's default selling price with the admin's markup: (input, output, source),
    or None for models that do not chat. `upstream` is the provider's own model ID.
    See prices.py for how the default is chosen."""
    found = prices.default_price(provider, upstream, sandbox, cost)
    if found is None:
        return None
    factor = 1 + (markup(db) if percent is None else percent) / 100
    return round(found[0] * factor, 6), round(found[1] * factor, 6), found[2]


def set_markup(db, percent):
    """Saves the markup and reprices every model on a default price. Prices the admin
    set by hand are left alone. Returns how many models changed."""
    if not math.isfinite(percent) or not 0 <= percent <= MAX_MARKUP:
        raise ValueError("Use a markup from 0 to 1000 percent.")
    changed = 0
    with db:
        db.execute("INSERT INTO settings (key, value) VALUES ('markup_percent', ?) "
                   "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (str(float(percent)),))
        for row in db.execute("SELECT * FROM models WHERE price_source IN ('list', 'market', 'estimate')").fetchall():
            price = default_price(db, row["provider"], row_upstream(row), row["sandbox"], row_cost(row), percent)
            if price is not None:
                db.execute("UPDATE models SET price_in = ?, price_out = ?, price_source = ?, priced_at = ? WHERE name = ?",
                           (price[0], price[1], price[2], int(time.time()), row["name"]))
                changed += 1
    return changed


def reset_price(db, name):
    """Puts a model back on its default price. Refused when the model has none."""
    row = db.execute("SELECT * FROM models WHERE name = ?", (name,)).fetchone()
    if row is None:
        raise ValueError("Unknown model")
    price = default_price(db, row["provider"], row_upstream(row), row["sandbox"], row_cost(row))
    if price is None:
        raise ValueError("This model has no default price; set one yourself.")
    with db:
        db.execute("UPDATE models SET price_in = ?, price_out = ?, price_ready = 1, price_source = ?, note = ?, priced_at = ? WHERE name = ?",
                   (price[0], price[1], price[2], NOTES[price[2]], int(time.time()), name))
    return price[0], price[1]


def set_available(db, sandbox, names, settings=None, keep=None):
    """Retain discovered models under the names buyers see and give each its default price.
    A price the admin set is never touched. This runs on every discovery, so introductory
    prices end on their dates and the markup stays applied without anyone pressing a button."""
    percent = markup(db)
    found, routers = {}, set()
    for item in names:
        item = {"id": item} if isinstance(item, str) else item
        route = item.get("id")
        if not isinstance(route, str) or not route or len(route) > 250:
            continue
        provider = item.get("provider", sandbox)
        upstream = item.get("upstream") if isinstance(item.get("upstream"), str) and item["upstream"] else upstream_id(provider, route)
        name = public_name(provider, upstream)
        if router(provider, upstream):
            routers.add(name)
            continue
        # A gateway's free tier costs the admin nothing; it is still sold at the market price.
        free = sandbox == "free" and item.get("free") is True
        # A gateway can list a model's free tier beside its paid one: sell the paid one.
        if not name or len(name) > 250 or (name in found and (free or not found[name]["free"])):
            continue
        found[name] = {"provider": provider, "upstream": upstream, "free": free,
                       "route": upstream if sandbox in ("local", "attached") else route,
                       "cost": (0.0, 0.0) if free else valid_cost(item.get("cost"))}
    with db:
        # A provider that is only throttled keeps its models listed until it answers again.
        kept = sorted(set(keep or ()))
        marks = ",".join("?" * len(kept))
        db.execute("UPDATE models SET available = 0 WHERE sandbox = ?" + (f" AND provider NOT IN ({marks})" if kept else ""), (sandbox, *kept))
        # Routers listed before are forgotten, unless the admin priced one by hand.
        db.executemany("DELETE FROM models WHERE name = ? AND sandbox = ? AND price_source != 'admin'",
                       [(name, sandbox) for name in routers])
        now = int(time.time())
        # A name another source already sells stays with that source; the admin is told which.
        taken = []
        for name, item in found.items():
            provider, cost = item["provider"], item["cost"]
            owner = db.execute("SELECT sandbox FROM models WHERE name=?", (name,)).fetchone()
            if owner is not None and owner[0] != sandbox:
                taken.append({"name": name, "owner": owner[0]})
                continue
            db.execute("INSERT INTO models (provider,name,price_in,price_out,sandbox,available,note,price_ready,upstream,cost_in,cost_out,checked_at) "
                       "VALUES (?,?,0,0,?,1,'Needs a selling price',0,?,?,?,?) "
                       "ON CONFLICT(name) DO UPDATE SET available=1, upstream=excluded.upstream, cost_in=excluded.cost_in, "
                       "cost_out=excluded.cost_out, checked_at=excluded.checked_at WHERE models.sandbox=excluded.sandbox",
                       (provider, name, sandbox, item["route"], cost[0] if cost else None, cost[1] if cost else None, now))
            price = default_price(db, provider, item["upstream"], sandbox, cost, percent)
            if price is None:
                db.execute("UPDATE models SET price_ready=0, price_source='', note='Needs a selling price' "
                           "WHERE name=? AND sandbox=? AND price_source != 'admin'", (name, sandbox))
            else:
                db.execute("UPDATE models SET priced_at=? WHERE name=? AND sandbox=? AND price_source != 'admin' "
                           "AND (price_in IS NOT ? OR price_out IS NOT ? OR priced_at IS NULL)", (now, name, sandbox, price[0], price[1]))
                db.execute("UPDATE models SET price_in=?, price_out=?, price_ready=1, price_source=?, note=? "
                           "WHERE name=? AND sandbox=? AND price_source != 'admin'",
                           (price[0], price[1], price[2], NOTES[price[2]], name, sandbox))
        db.execute("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                   ("name_taken_" + sandbox, json.dumps(taken)))
        # Refresh metadata is published in the same transaction as the catalogue.
        for key, value in (settings or {}).items():
            db.execute("INSERT INTO settings (key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                       (key, value))


def add_credits(db, user_id, dollars):
    with db:
        db.execute("UPDATE users SET credits_micro = credits_micro + ? WHERE id = ?",
                   (int(round(dollars * 1_000_000)), user_id))


def charge(db, user_id, key_id, model, tokens_in, tokens_out):
    """Charges a completed request. Returns the cost in dollars, or None when the
    balance cannot cover it."""
    row = db.execute("SELECT price_in, price_out FROM models WHERE name = ?", (model,)).fetchone()
    if row is None:
        return None
    micro = cost_micro(row["price_in"], row["price_out"], tokens_in, tokens_out)
    cost = micro / 1_000_000
    with db:
        changed = db.execute("UPDATE users SET credits_micro = credits_micro - ? WHERE id = ? AND credits_micro >= ?",
                             (micro, user_id, micro))
        if not changed.rowcount:
            return None
        db.execute("INSERT INTO usage (user_id, key_id, model, tokens_in, tokens_out, cost_micro, at) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?)",
                   (user_id, key_id, model, tokens_in, tokens_out, micro, int(time.time())))
    return cost


def note_exhausted(db, key_id, note):
    """When a provider says the tokens are gone, the message is shown on the key."""
    with db:
        db.execute("UPDATE api_keys SET exhausted_note = ? WHERE id = ?", (note, key_id))


def wallet(db):
    raw = setting(db, "wallet")
    saved = json.loads(raw) if raw else None
    # A wallet saved on a network that no longer takes USDT payments must be chosen again.
    return saved if saved and saved.get("network") in NETWORKS else None


def set_wallet(db, network, address, token=None):
    """Saves where payments go. `token` is the USDT contract or mint on that network, entered by
    the admin from Tether's own list; buyers see it only when it is set."""
    saved = {"network": network, "address": address, "at": int(time.time())}
    if token:
        saved["token"] = token
    setting(db, "wallet", json.dumps(saved))


def waiting_payments(db, user_id):
    return db.execute("SELECT COUNT(*) FROM payments WHERE user_id=? AND state='waiting'", (user_id,)).fetchone()[0]


def confirm_payment(db, reference, admin_id=None, tx_id=None):
    """Adds a waiting payment's credits once. With a transaction id, that transaction can confirm
    no other payment: it raises PaymentConflict naming the payment it already confirmed. Returns
    the amount, or None when the payment is not waiting (already confirmed, closed or unknown)."""
    with db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM payments WHERE reference=? AND state='waiting'", (reference,)).fetchone()
        if row is None:
            return None
        if tx_id:
            used = db.execute("SELECT reference FROM payments WHERE network=? AND tx_id=?", (row["network"], tx_id)).fetchone()
            if used is not None:
                raise PaymentConflict(used["reference"])
        db.execute("UPDATE payments SET state='paid',confirmed_at=?,confirmed_by=?,tx_id=? WHERE id=?",
                   (int(time.time()), admin_id, tx_id or None, row["id"]))
        db.execute("UPDATE users SET credits_micro=credits_micro+? WHERE id=?",
                   (int(round(row["dollars"] * 1_000_000)), row["user_id"]))
        return row["dollars"]


def close_payment(db, reference, state, user_id=None, admin_id=None):
    """Rejects (the admin) or cancels (its buyer) a waiting payment. No credits move. Returns
    whether a waiting payment was closed."""
    if state not in ("rejected", "cancelled"):
        raise ValueError("Unknown payment state")
    query = "UPDATE payments SET state=?, closed_at=?, confirmed_by=? WHERE reference=? AND state='waiting'"
    values = [state, int(time.time()), admin_id, reference]
    if user_id is not None:
        query += " AND user_id=?"
        values.append(user_id)
    with db:
        return db.execute(query, values).rowcount == 1


def mark_unavailable(db, sandbox, provider=None, model=None):
    """Takes models off sale until the next discovery finds them again: one model, or every model
    of a provider whose sign-in failed."""
    with db:
        if model is not None:
            db.execute("UPDATE models SET available=0 WHERE name=? AND sandbox=?", (model, sandbox))
        elif provider is not None:
            db.execute("UPDATE models SET available=0 WHERE sandbox=? AND provider=?", (sandbox, provider))


def cost_micro(price_in, price_out, tokens_in, tokens_out):
    if any(type(value) is not int or value < 0 for value in (tokens_in, tokens_out)):
        raise ValueError("Invalid token usage")
    return int((Decimal(str(price_in))*tokens_in + Decimal(str(price_out))*tokens_out).to_integral_value(rounding=ROUND_CEILING))


def reserve(db, key, model, input_bound, output_bound):
    """Reserve before inference; concurrent requests cannot spend the same balance."""
    amount = cost_micro(model["price_in"], model["price_out"], input_bound, output_bound)
    reservation = secrets.token_hex(16)
    with db:
        changed = db.execute("UPDATE users SET credits_micro=credits_micro-? WHERE id=? AND credits_micro>=?",
                             (amount, key["user_id"], amount))
        if not changed.rowcount:
            return None
        db.execute("INSERT INTO reservations (id,user_id,key_id,model,amount,price_in,price_out,created_at) VALUES (?,?,?,?,?,?,?,?)",
                   (reservation,key["user_id"],key["id"],model["name"],amount,model["price_in"],model["price_out"],int(time.time())))
    return reservation


def settle(db, reservation, usage=None):
    with db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT * FROM reservations WHERE id=? AND state='pending'", (reservation,)).fetchone()
        if row is None:
            return None
        cost = 0 if usage is None else cost_micro(row["price_in"],row["price_out"],*usage)
        if cost > row["amount"]:
            raise ValueError("Provider usage exceeded the reserved limit")
        db.execute("UPDATE users SET credits_micro=credits_micro+? WHERE id=?", (row["amount"]-cost,row["user_id"]))
        db.execute("UPDATE reservations SET state=? WHERE id=?", ("refunded" if usage is None else "complete",reservation))
        if usage is not None:
            db.execute("INSERT INTO usage (user_id,key_id,model,tokens_in,tokens_out,cost_micro,at) VALUES (?,?,?,?,?,?,?)",
                       (row["user_id"],row["key_id"],row["model"],*usage,cost,int(time.time())))
        return cost / 1_000_000


def recover_reservations(db):
    """One website process owns this database. Interrupted calls are refunded on startup.
    The operator absorbs upstream costs with unknown outcomes, never the customer.
    """
    for row in db.execute("SELECT id FROM reservations WHERE state='pending'").fetchall():
        settle(db,row["id"])
