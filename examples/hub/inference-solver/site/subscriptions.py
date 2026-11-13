"""Subscriptions: one to five plans the administrator offers, bought from the balance 30 days at a time.

Each plan names the models it includes and a number of tokens per window, either every five hours
or every week. A window opens with the first included request after the previous one has ended. A
priced request to an included model that starts while its window still has tokens left is included
in the plan, and its measured tokens count in that window; past them, and for other models, requests
are charged from the balance at the model's token prices until the window resets. The administrator
can reset anyone's window early, and can switch subscriptions off: then nothing can be bought, and
periods already paid for run to their end.

Subscribers never see a plan's tokens: they see how much of the window's limit they have used, as a
share, and when it resets. People keep what they paid for: a subscription records its plan's name,
models, tokens and window when it is bought or renewed, so changing or removing a plan later never
changes a paid period. Each person has one subscription at a time.
"""
import json
import re
import secrets
import time

PLAN_LIMIT = 5
PERIOD = 30 * 86400
WINDOWS = {"5h": 5 * 3600, "week": 7 * 86400}


class SubscriptionInput(ValueError):
    """A message for the person who sent the request."""


def usd(value, maximum):
    """Microdollars from a decimal string with up to six places; never a float."""
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9][0-9]{0,5})(\.[0-9]{1,6})?", value):
        raise SubscriptionInput("Enter a price in USD with up to six decimal places.")
    whole, _, fraction = value.partition(".")
    amount = int(whole) * 1000000 + int(fraction.ljust(6, "0"))
    if amount > maximum * 1000000:
        raise SubscriptionInput(f"Choose a price of at most {maximum} USD.")
    return amount


def tokens(value):
    """Tokens from millions written as a decimal string with up to three places: 2.5 is 2,500,000."""
    if not isinstance(value, str) or not re.fullmatch(r"(0|[1-9][0-9]{0,5})(\.[0-9]{1,3})?", value):
        raise SubscriptionInput("Enter the tokens in millions, such as 5 or 0.5.")
    whole, _, fraction = value.partition(".")
    count = int(whole) * 1000000 + int(fraction.ljust(3, "0")) * 1000
    if count < 1000:
        raise SubscriptionInput("Include at least 0.001 million (1,000) tokens.")
    return count


def window(row, now):
    """The open window of a subscription as (start, tokens used), or (None, 0) once it has ended."""
    start = row["window_start"]
    if start is not None and now < start + WINDOWS[row["resets"]]:
        return start, row["window_used"]
    return None, 0


class Subscriptions:
    def __init__(self, store):
        self.store = store
        with store.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS subscription_plans (id TEXT PRIMARY KEY, name TEXT NOT NULL,
                    price_microusd INTEGER NOT NULL, token_limit INTEGER NOT NULL, resets TEXT NOT NULL, models TEXT NOT NULL,
                    created INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS subscriptions (user_id TEXT PRIMARY KEY REFERENCES users(id), plan_id TEXT NOT NULL,
                    name TEXT NOT NULL, token_limit INTEGER NOT NULL, resets TEXT NOT NULL, models TEXT NOT NULL, started INTEGER NOT NULL,
                    ends INTEGER NOT NULL, window_start INTEGER, window_used INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS subscription_settings (id INTEGER PRIMARY KEY CHECK(id=1), enabled INTEGER NOT NULL);
                -- Requests running under a plan, with the window they count in.
                CREATE TABLE IF NOT EXISTS subscription_requests (id TEXT PRIMARY KEY, user_id TEXT NOT NULL,
                    window_start INTEGER NOT NULL);
            """)

    @staticmethod
    def plan(row, admin=False):
        # Only the administrator sees a plan's tokens.
        keys = ("id", "name", "price_microusd", "resets") + (("token_limit",) if admin else ())
        return {**{key: row[key] for key in keys}, "models": json.loads(row["models"])}

    @staticmethod
    def plans(db, admin=False):
        return [Subscriptions.plan(row, admin) for row in db.execute("SELECT * FROM subscription_plans ORDER BY price_microusd,created,id")]

    @staticmethod
    def enabled(db):
        row = db.execute("SELECT enabled FROM subscription_settings WHERE id=1").fetchone()
        return bool(row["enabled"]) if row else True

    @staticmethod
    def running(db, user, now):
        return db.execute("SELECT * FROM subscriptions WHERE user_id=? AND ends>?", (user, now)).fetchone()

    @staticmethod
    def view(row, now, admin=False):
        """A subscription as its owner sees it: the share of the window's limit used, never the
        tokens; the administrator also sees the tokens."""
        start, used = window(row, now)
        shown = {"plan": row["plan_id"], "name": row["name"], "resets": row["resets"], "models": json.loads(row["models"]),
                 "ends": row["ends"], "used_percent": min(100, used * 100 // row["token_limit"]),
                 "resets_at": start + WINDOWS[row["resets"]] if start is not None else None}
        return {**shown, "used": used, "token_limit": row["token_limit"]} if admin else shown

    def snapshot(self, user):
        now = int(time.time())
        with self.store.db() as db:
            row = self.running(db, user, now)
            enabled = self.enabled(db)
            return {"enabled": enabled, "plans": self.plans(db) if enabled else [], "subscription": self.view(row, now) if row else None}

    def admin_snapshot(self):
        now = int(time.time())
        with self.store.db() as db:
            people = db.execute("SELECT s.*,u.email FROM subscriptions s JOIN users u ON u.id=s.user_id WHERE s.ends>? ORDER BY s.ends,u.email", (now,)).fetchall()
            return {"enabled": self.enabled(db), "plans": self.plans(db, admin=True), "limit": PLAN_LIMIT,
                    "subscribers": [{"user": row["user_id"], "email": row["email"], **self.view(row, now, admin=True)} for row in people]}

    def switch(self, actor, data):
        """Subscriptions on or off. Off: nothing can be bought; paid periods run to their end."""
        if not isinstance(data.get("enabled"), bool):
            raise SubscriptionInput("Choose whether subscriptions are offered.")
        with self.store.db() as db:
            db.execute("INSERT INTO subscription_settings VALUES(1,?) ON CONFLICT(id) DO UPDATE SET enabled=excluded.enabled", (int(data["enabled"]),))
            self.store.audit(db, actor, "subscription.offered" if data["enabled"] else "subscription.switched_off", "subscriptions")
        return self.admin_snapshot()

    def save_plan(self, actor, data):
        name = data.get("name").strip() if isinstance(data.get("name"), str) else ""
        if not 1 <= len(name) <= 40:
            raise SubscriptionInput("Give the subscription a name of 1 to 40 characters.")
        price, count = usd(data.get("price_usd"), 10000), tokens(data.get("tokens_millions"))
        if data.get("resets") not in WINDOWS:
            raise SubscriptionInput("Choose whether the tokens reset every 5 hours or every week.")
        chosen = data.get("models")
        if not isinstance(chosen, list) or not chosen or len(chosen) > 200 or not all(isinstance(m, str) for m in chosen):
            raise SubscriptionInput("Choose the models this subscription includes.")
        chosen = sorted(set(chosen))
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if any(not db.execute("SELECT 1 FROM models WHERE upstream=?", (model,)).fetchone() for model in chosen):
                raise SubscriptionInput("Choose models this inference serves.")
            models = json.dumps(chosen)
            if data.get("id"):
                if not db.execute("UPDATE subscription_plans SET name=?,price_microusd=?,token_limit=?,resets=?,models=? WHERE id=?",
                                  (name, price, count, data["resets"], models, data["id"])).rowcount:
                    raise SubscriptionInput("This subscription no longer exists.")
                identity = data["id"]
            else:
                if db.execute("SELECT COUNT(*) FROM subscription_plans").fetchone()[0] >= PLAN_LIMIT:
                    raise SubscriptionInput(f"Offer at most {PLAN_LIMIT} subscriptions. Remove one before adding another.")
                identity = secrets.token_hex(8)
                db.execute("INSERT INTO subscription_plans VALUES(?,?,?,?,?,?,?)", (identity, name, price, count, data["resets"], models, int(time.time())))
            self.store.audit(db, actor, "subscription.plan", identity)
        return self.admin_snapshot()

    def remove_plan(self, actor, data):
        with self.store.db() as db:
            if not db.execute("DELETE FROM subscription_plans WHERE id=?", (data.get("id"),)).rowcount:
                raise SubscriptionInput("This subscription no longer exists.")
            self.store.audit(db, actor, "subscription.plan_removed", data.get("id"))
        return self.admin_snapshot()

    def subscribe(self, user, data, balance):
        """Pays one 30-day period from the balance. The same plan again adds 30 days to a running one,
        on the plan's current terms; another plan can be chosen once the running one has ended."""
        now = int(time.time())
        with self.store.db() as db:
            db.execute("BEGIN IMMEDIATE")
            if not self.enabled(db):
                raise SubscriptionInput("Subscriptions are not offered at the moment.")
            plan = db.execute("SELECT * FROM subscription_plans WHERE id=?", (data.get("plan"),)).fetchone()
            if not plan:
                raise SubscriptionInput("This subscription is no longer offered.")
            current = self.running(db, user, now)
            if current and current["plan_id"] != plan["id"]:
                raise SubscriptionInput(f"Your {current['name']} subscription is still running. You can choose another one when it ends.")
            if balance(db, user) < plan["price_microusd"]:
                raise SubscriptionInput("Your balance is below the price of this subscription. Top up first.")
            if plan["price_microusd"]:
                db.execute("INSERT INTO credit_ledger VALUES(?,?,?,?,?,NULL,NULL)",
                           ("subscription-" + secrets.token_hex(16), user, -plan["price_microusd"], "subscription", now))
            terms = (plan["name"], plan["token_limit"], plan["resets"], plan["models"])
            if current:
                db.execute("UPDATE subscriptions SET name=?,token_limit=?,resets=?,models=?,ends=ends+? WHERE user_id=?", (*terms, PERIOD, user))
            else:
                db.execute("INSERT OR REPLACE INTO subscriptions VALUES(?,?,?,?,?,?,?,?,NULL,0)", (user, plan["id"], *terms, now, now + PERIOD))
            self.store.audit(db, user, "subscription.bought", plan["id"])
        return self.snapshot(user)

    def reset(self, actor, data):
        """Gives someone a fresh window now: their tokens count from zero again."""
        with self.store.db() as db:
            if not db.execute("UPDATE subscriptions SET window_start=NULL,window_used=0 WHERE user_id=? AND ends>?",
                              (data.get("user"), int(time.time()))).rowcount:
                raise SubscriptionInput("This person has no running subscription.")
            self.store.audit(db, actor, "subscription.reset", data.get("user"))
        return self.admin_snapshot()

    # Called by Payments inside its own transactions.
    def cover(self, db, user, model, request, now):
        """True when a priced request to this model is included in the person's plan, and records it."""
        row = self.running(db, user, now)
        if not row or model not in json.loads(row["models"]):
            return False
        start, used = window(row, now)
        if used >= row["token_limit"]:
            return False
        if start is None:
            start = now
            db.execute("UPDATE subscriptions SET window_start=?,window_used=0 WHERE user_id=?", (start, user))
        db.execute("INSERT INTO subscription_requests VALUES(?,?,?)", (request, user, start))
        return True

    @staticmethod
    def settle(db, request, counted):
        """Counts a finished request's tokens in the window it started in. False when it was not
        included in a plan. A request that did not complete, or whose window was reset meanwhile,
        counts nothing."""
        row = db.execute("SELECT * FROM subscription_requests WHERE id=?", (request,)).fetchone()
        if not row:
            return False
        db.execute("DELETE FROM subscription_requests WHERE id=?", (request,))
        if counted:
            db.execute("UPDATE subscriptions SET window_used=window_used+? WHERE user_id=? AND window_start=?",
                       (counted, row["user_id"], row["window_start"]))
        return True

    def used_up(self, db, user, model, now):
        """When the person's used-up window for this model resets, or None when it has tokens left,
        or the model is not in their plan, or they have none."""
        row = self.running(db, user, now)
        if not row or model not in json.loads(row["models"]):
            return None
        start, used = window(row, now)
        return start + WINDOWS[row["resets"]] if start is not None and used >= row["token_limit"] else None
