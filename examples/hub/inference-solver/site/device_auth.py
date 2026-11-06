"""Browser approval for CLI credentials. Only hashes are stored, never bearer keys."""
import re
import secrets
import time

from store import AccountError, digest

LIFETIME = 600
INTERVAL = 3
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


def user_code(value):
    if not isinstance(value, str) or len(value) > 20:
        raise AccountError("Enter the code shown in your terminal.")
    value = value.upper().replace("-", "").replace(" ", "")
    if len(value) != 8 or any(c not in ALPHABET for c in value):
        raise AccountError("Enter the eight-character code shown in your terminal.")
    return value


class Devices:
    def __init__(self, store):
        self.store = store
        with store.db() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS device_authorizations (
                device_hash TEXT PRIMARY KEY, user_hash TEXT UNIQUE NOT NULL,
                credential_hash TEXT UNIQUE NOT NULL, harness TEXT NOT NULL,
                expires INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
                next_poll INTEGER NOT NULL DEFAULT 0, key_id TEXT)
            """)

    def start(self, harness, credential_hash):
        if not isinstance(credential_hash, str) or not re.fullmatch(r"[a-f0-9]{64}", credential_hash):
            raise AccountError("Invalid CLI credential request.")
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute("DELETE FROM device_authorizations WHERE expires<=?", (now,))
            if db.execute("SELECT COUNT(*) FROM device_authorizations").fetchone()[0] >= 1024:
                raise AccountError("Too many pending connections. Try again in a few minutes.")
            if (db.execute("SELECT 1 FROM device_authorizations WHERE credential_hash=?", (credential_hash,)).fetchone()
                    or db.execute("SELECT 1 FROM api_keys WHERE hash=?", (credential_hash,)).fetchone()):
                raise AccountError("Start a new connection from the CLI.")
            while True:
                code = "".join(secrets.choice(ALPHABET) for _ in range(8))
                if not db.execute("SELECT 1 FROM device_authorizations WHERE user_hash=?", (digest(code),)).fetchone():
                    break
            device = secrets.token_urlsafe(32)
            db.execute("INSERT INTO device_authorizations(device_hash,user_hash,credential_hash,harness,expires) VALUES(?,?,?,?,?)",
                       (digest(device), digest(code), credential_hash, harness, now + LIFETIME))
        return {"device_code": device, "user_code": code[:4] + "-" + code[4:], "expires_in": LIFETIME, "interval": INTERVAL}

    def inspect(self, code):
        with self.store.db() as db:
            row = db.execute("SELECT harness,expires FROM device_authorizations WHERE user_hash=? AND status='pending' AND expires>?",
                             (digest(user_code(code)), int(time.time()))).fetchone()
        if not row:
            raise AccountError("That code is invalid, expired, or already used. Start again in the CLI.")
        return dict(row)

    def decide(self, code, actor, approve):
        if not isinstance(approve, bool):
            raise AccountError("Choose Allow or Deny.")
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM device_authorizations WHERE user_hash=? AND status='pending' AND expires>?",
                             (digest(user_code(code)), now)).fetchone()
            if not row:
                raise AccountError("That code is invalid, expired, or already used. Start again in the CLI.")
            key_id = None
            if approve:
                if db.execute("SELECT COUNT(*) FROM api_keys WHERE user_id=? AND revoked=0", (actor,)).fetchone()[0] >= 50:
                    raise AccountError("Remove an unused connection in API keys before connecting another tool.")
                key_id = secrets.token_hex(12)
                db.execute("INSERT INTO api_keys VALUES(?,?,?,?,?,?,0)",
                           (key_id, row["credential_hash"], actor, "Harness: " + row["harness"], '["*"]', now))
            db.execute("UPDATE device_authorizations SET status=?,key_id=? WHERE device_hash=?",
                       ("approved" if approve else "denied", key_id, row["device_hash"]))
            self.store.audit(db, actor, "harness.connected" if approve else "harness.denied", row["harness"])
        return {"status": "approved" if approve else "denied"}

    def poll(self, device):
        if not isinstance(device, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", device):
            return {"status": "expired"}
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM device_authorizations WHERE device_hash=?", (digest(device),)).fetchone()
            if not row or row["expires"] <= now:
                return {"status": "expired"}
            if row["next_poll"] > now:
                return {"status": "slow_down", "interval": INTERVAL}
            db.execute("UPDATE device_authorizations SET next_poll=? WHERE device_hash=?", (now + INTERVAL, digest(device)))
            if row["status"] == "approved":
                key = db.execute("SELECT revoked FROM api_keys WHERE id=?", (row["key_id"],)).fetchone()
                if not key or key["revoked"]:
                    return {"status": "denied"}
            return {"status": row["status"], "interval": INTERVAL}
