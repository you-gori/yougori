"""My API: one website in front of your model sandboxes.

The CLI creates the admin account before the website starts. The admin signs in
to choose the payment network and wallet. Other people can sign up as users,
buy credits, make API keys and call the models their sandboxes offer.

No third-party packages: this runs on the Python standard library alone.
"""
import json
import os
import re
import secrets
import time
import sys
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from http.cookies import SimpleCookie

# Import the two files beside this one, whatever the working directory or flags.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import attached
import pages
import prices
import store
from transport import Failure, request as http_json
from http_limits import Server, exit_on_stop

PORT = int(os.environ.get("PORT", "3000"))
SITE_NAME = os.environ.get("SITE_NAME", "My API")
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

store.recover_reservations(store.setup())

# The website's fonts, read once at start. Only these exact file names are ever served.
FONT_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fonts")
FONTS = {}
if os.path.isdir(FONT_FOLDER):
    for entry in sorted(os.listdir(FONT_FOLDER)):
        if re.fullmatch(r"[a-z0-9-]+\.woff2", entry):
            with open(os.path.join(FONT_FOLDER, entry), "rb") as font_file:
                FONTS["/fonts/" + entry] = font_file.read()
STATIC_CACHE = "public, max-age=604800"


class Database:
    """Hands each thread its own SQLite connection, so `db.execute(...)` is always
    safe whichever worker thread is serving the request."""

    def __getattr__(self, name):
        return getattr(store.connect(), name)

    def __enter__(self):
        return store.connect().__enter__()

    def __exit__(self, *details):
        return store.connect().__exit__(*details)


db = Database()
login_attempts = {}
login_lock = threading.Lock()
catalogue_lock = threading.Lock()
CATALOGUE_INTERVAL = 30


def refresh_catalogue():
    """One refresh at a time; publish each sandbox as soon as it answers."""
    if not catalogue_lock.acquire(blocking=False):
        return {"refreshing": True}
    try:
        found, statuses = {}, {}
        with ThreadPoolExecutor(max_workers=4) as pool:
            futures = {pool.submit(discover, sandbox, os.environ.get(variable, "")): sandbox
                       for sandbox, variable in (("local", "LOCAL_SANDBOX"), ("paid", "PAID_SANDBOX"), ("free", "FREE_SANDBOX"),
                                                 ("attached", ""))}
            for future in as_completed(futures):
                sandbox = futures[future]
                try:
                    result = future.result()
                    found[sandbox] = result["data"]
                    statuses[sandbox] = result.get("status", {sandbox: "Connected"})
                    tools = result.get("toolModels", [])
                except Failure as error:
                    found[sandbox], tools = [], []
                    statuses[sandbox] = {sandbox: str(error)}
                except Exception:
                    found[sandbox], tools = [], []
                    statuses[sandbox] = {sandbox: "Discovery is temporarily unavailable; retrying automatically."}
                store.set_available(db, sandbox, found[sandbox], {
                    "tool_models_" + sandbox: json.dumps(tools),
                    "provider_status": json.dumps(statuses), "catalogue_updated": str(int(time.time()))})
        return {"available": found, "status": statuses}
    finally:
        catalogue_lock.release()


class CatalogueWorker:
    def __init__(self, interval=CATALOGUE_INTERVAL):
        self.interval = interval
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name="model-discovery", daemon=True)

    def start(self):
        # A restarted service must recheck saved availability and subscription state.
        for sandbox in ("local", "paid", "free", "attached"):
            store.set_available(db, sandbox, [])
            store.setting(db, "tool_models_" + sandbox, "[]")
        store.setting(db, "catalogue_updated", "0")
        self.thread.start()
        return self

    def run(self):
        try:
            while not self.stop.is_set():
                started = time.monotonic()
                try:
                    refresh_catalogue()
                except Exception:
                    # A transient database or provider error must not kill future refreshes.
                    print("Model discovery will retry automatically.", flush=True)
                if self.stop.wait(max(.05, self.interval - (time.monotonic() - started))):
                    break
        finally:
            store.close()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=65)


def body(handler, limit=64 * 1024):
    try:
        length = int(handler.headers.get("content-length") or 0)
    except ValueError:
        raise Failure(400, "Invalid content length")
    if handler.headers.get("transfer-encoding") or not 0 < length <= limit:
        raise Failure(413, "Request body is missing or too large")
    if handler.headers.get_content_type() != "application/json":
        raise Failure(415, "Send application/json")
    try:
        data = json.loads(handler.rfile.read(length), parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
        if not isinstance(data, dict):
            raise ValueError("Expected object")
        return data
    except (ValueError, UnicodeError):
        raise Failure(400, "Send a JSON object")


def viewer(handler):
    cookie = SimpleCookie(handler.headers.get("cookie", ""))
    token = cookie["my_api"].value if "my_api" in cookie else None
    return store.session_user(db, token), token


def bearer(handler):
    header = handler.headers.get("authorization", "")
    return header[7:].strip() if header.lower().startswith("bearer ") else ""


class Handler(BaseHTTPRequestHandler):
    server_version = "MyAPI"
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(300)

    def finish(self):
        try:
            super().finish()
        finally:
            store.close()

    def log_message(self, *args):
        pass  # The engine already records requests; no second copy with addresses.

    # ---- replies ---------------------------------------------------------
    def send(self, status, payload, kind="application/json", cookie=None, cache="no-store"):
        # Cloudflare replaces a 502 or 504 from the site with its own HTML page, so an API
        # client would never read the JSON error. A 503 passes through unchanged.
        if status in (502, 504):
            status = 503
        data = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", kind)
        self.send_header("content-length", str(len(data)))
        self.send_header("cache-control", cache)
        self.send_header("connection", "close")
        self.close_connection = True
        self.send_header("x-content-type-options", "nosniff")
        self.send_header("referrer-policy", "no-referrer")
        self.send_header("content-security-policy", "default-src 'self'; style-src 'self' 'unsafe-inline'")
        if cookie:
            if os.environ.get("COOKIE_SECURE") == "1":
                cookie += "; Secure"
            self.send_header("set-cookie", cookie)
        self.end_headers()
        self.wfile.write(data)

    def fail(self, status, message):
        self.send(status, {"error": message})

    # ---- routing ---------------------------------------------------------
    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/health":
            return self.send(200, {"ok": True, "name": SITE_NAME})
        if path in ("/", "/keys", "/credits", "/admin", "/signin", "/signup"):
            return self.send(200, pages.shell(SITE_NAME).encode(), "text/html; charset=utf-8")
        if path == "/app.css":
            return self.send(200, pages.CSS.encode(), "text/css; charset=utf-8")
        if path == "/app.js":
            return self.send(200, pages.SCRIPT.encode(), "text/javascript; charset=utf-8")
        if path == "/theme.js":
            return self.send(200, pages.THEME_SCRIPT.encode(), "text/javascript; charset=utf-8")
        if path == "/grain.svg":
            return self.send(200, pages.GRAIN.encode(), "image/svg+xml", cache=STATIC_CACHE)
        if path in FONTS:
            return self.send(200, FONTS[path], "font/woff2", cache=STATIC_CACHE)
        if path == "/api/me":
            return self.me()
        if path == "/api/models":
            return self.list_models()
        if path == "/api/keys":
            return self.list_keys()
        if path == "/api/usage":
            return self.list_usage()
        if path == "/api/payments":
            return self.list_payments()
        if path == "/api/wallet":
            return self.show_wallet()
        if path == "/api/admin/overview":
            return self.admin_overview()
        if path == "/v1/models":
            return self.openai_models()
        return self.fail(404, "Not found")

    def do_POST(self):
        try:
            origin = self.headers.get("Origin")
            if origin and urlsplit(origin).netloc != self.headers.get("Host"):
                return self.fail(403, "Cross-site request refused")
            return self.post()
        except Failure as error:
            self.send(error.status, {"error": {"message": str(error), "code": error.code}})
        except sqlite3.IntegrityError:
            self.fail(409, "That record already exists.")
        except (ValueError, TypeError, OverflowError):
            self.fail(400, "Invalid request values.")
        except sqlite3.Error:
            self.fail(503, "Storage is busy. Try again.")

    def post(self):
        path = self.path.split("?")[0]
        if path in ("/api/signup", "/api/signin"):
            now = time.monotonic()
            with login_lock:
                for address in list(login_attempts):
                    if now - login_attempts[address][0] > 60:
                        del login_attempts[address]
                address = self.client_address[0]
                started, count = login_attempts.get(address, (now, 0))
                if count >= 30 or len(login_attempts) >= 4096:
                    return self.fail(429, "Too many sign-in attempts. Wait a minute.")
                login_attempts[address] = (started, count + 1)
        routes = {
            "/api/signup": self.signup,
            "/api/signin": self.signin,
            "/api/signout": self.signout,
            "/api/keys": self.create_key,
            "/api/keys/delete": self.delete_key,
            "/api/credits/buy": self.buy_credits,
            "/api/admin/wallet": self.save_wallet,
            "/api/admin/price": self.save_price,
            "/api/admin/price/reset": self.reset_price,
            "/api/admin/markup": self.save_markup,
            "/api/admin/refresh": self.refresh_models,
            "/api/admin/confirm": self.confirm_payment,
            "/v1/chat/completions": self.chat,
        }
        action = routes.get(path)
        return action() if action else self.fail(404, "Not found")

    # ---- accounts --------------------------------------------------------
    def signup(self):
        if not store.has_admin(db):
            return self.fail(409, "Create the admin account through the Yougori CLI before signing up.")
        data = body(self)
        email, password = str(data.get("email", "")).strip(), str(data.get("password", ""))
        if not EMAIL.match(email):
            return self.fail(400, "Enter an email address.")
        if len(password) < 10 or len(password) > 1024:
            return self.fail(400, "Use a password of at least 10 characters.")
        if store.user_by_email(db, email):
            return self.fail(409, "That email already has an account.")
        try:
            user_id, is_admin = store.create_user(db, email, password)
        except ValueError as error:
            return self.fail(400, str(error))
        token = store.start_session(db, user_id)
        return self.send(200, {"admin": is_admin, "first": is_admin},
                         cookie=f"my_api={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000")

    def signin(self):
        data = body(self)
        row = store.user_by_email(db, str(data.get("email", "")))
        password = str(data.get("password", ""))
        if row is None or not store.check_password(password, row["password_hash"], row["salt"]):
            return self.fail(401, "That email and password do not match.")
        token = store.start_session(db, row["id"])
        return self.send(200, {"admin": bool(row["is_admin"])},
                         cookie=f"my_api={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=2592000")

    def signout(self):
        _, token = viewer(self)
        store.end_session(db, token)
        return self.send(200, {"ok": True}, cookie="my_api=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")

    def me(self):
        user, _ = viewer(self)
        if user is None:
            return self.send(200, {"signedIn": False, "anyAdmin": store.has_admin(db), "siteName": SITE_NAME})
        return self.send(200, {
            "signedIn": True, "email": user["email"], "admin": bool(user["is_admin"]),
            "credits": round(user["credits_micro"] / 1_000_000, 6), "siteName": SITE_NAME,
            "walletSet": store.wallet(db) is not None,
        })

    # ---- models ----------------------------------------------------------
    def list_models(self):
        user, _ = viewer(self)
        admin = user is not None and bool(user["is_admin"])
        listed = []
        for row in store.models(db):
            ready = bool(row["available"] and row["price_ready"])
            if not admin and not ready:
                continue
            # Buyers see a model's name, maker and price, never the gateway or runtime behind it.
            item = {"name": row["name"], "maker": store.maker(row["provider"], row["name"]),
                    "priceIn": row["price_in"], "priceOut": row["price_out"], "available": ready, "discovered": bool(row["available"])}
            if admin:
                # What the model costs the admin, what the market charges and the default the
                # site uses, so the price table can show the margin and the reasoning.
                upstream = store.row_upstream(row)
                own = row["sandbox"] in ("local", "attached")  # Runs on the admin's own or rented GPU.
                cost = None if own else (prices.list_price(row["provider"], upstream) or store.row_cost(row))
                market = None if own else prices.market_price(row["provider"], upstream)
                default = store.default_price(db, row["provider"], upstream, row["sandbox"], store.row_cost(row))
                item.update({
                    "provider": row["provider"], "sandbox": row["sandbox"], "priceSource": row["price_source"] or "",
                    "note": "Needs a selling price" if row["available"] and not row["price_ready"] else row["note"],
                    "costIn": cost[0] if cost else None, "costOut": cost[1] if cost else None,
                    "marketIn": market[0] if market else None, "marketOut": market[1] if market else None,
                    "defaultIn": default[0] if default else None, "defaultOut": default[1] if default else None,
                    "defaultSource": default[2] if default else None,
                    "promoEnds": None if own else prices.promotion_ends(row["provider"], upstream),
                })
            listed.append(item)
        reply = {"models": listed,
                 "updatedAt": int(store.setting(db, "catalogue_updated") or 0),
                 "refreshSeconds": CATALOGUE_INTERVAL, "refreshing": catalogue_lock.locked()}
        if admin:
            reply.update({"markup": store.markup(db), "pricesAsOf": prices.AS_OF, "priceSources": prices.SOURCES,
                          "toolModels": [item for sandbox in ("paid", "free")
                                         for item in json.loads(store.setting(db, "tool_models_" + sandbox) or "[]")]})
        return self.send(200, reply)

    def openai_models(self):
        """The OpenAI-shaped list, so existing tools can point straight at this site."""
        key = store.api_key_owner(db, bearer(self))
        if key is None:
            return self.fail(401, "Send a valid API key.")
        rows = [row for row in store.models(db, only_available=True) if not key["model"] or key["model"] == row["name"]]
        return self.send(200, {"object": "list", "data": [
            {"id": row["name"], "object": "model", "owned_by": store.maker(row["provider"], row["name"]) or "other"} for row in rows]})

    def refresh_models(self):
        """Ask each sandbox which models it can actually serve, and show only those."""
        user, _ = viewer(self)
        if user is None or not user["is_admin"]:
            return self.fail(403, "Only the admin can do this.")
        return self.send(200, refresh_catalogue())

    # ---- keys ------------------------------------------------------------
    def list_keys(self):
        user, _ = viewer(self)
        if user is None:
            return self.fail(401, "Sign in first.")
        rows = db.execute("SELECT id, name, prefix, model, exhausted_note, created_at, last_used_at "
                          "FROM api_keys WHERE user_id = ? ORDER BY id DESC", (user["id"],)).fetchall()
        return self.send(200, {"keys": [dict(row) for row in rows]})

    def create_key(self):
        user, _ = viewer(self)
        if user is None:
            return self.fail(401, "Sign in first.")
        data = body(self)
        name = str(data.get("name", "")).strip() or "Key"
        model = data.get("model") or None
        if model and not db.execute("SELECT 1 FROM models WHERE name = ?", (model,)).fetchone():
            return self.fail(400, "That model is not on this site.")
        secret = store.create_api_key(db, user["id"], name, model)
        return self.send(200, {"key": secret, "shownOnce": True})

    def delete_key(self):
        user, _ = viewer(self)
        if user is None:
            return self.fail(401, "Sign in first.")
        key_id = body(self).get("id")
        with db:
            db.execute("DELETE FROM api_keys WHERE id = ? AND user_id = ?", (key_id, user["id"]))
        return self.send(200, {"deleted": True})

    def list_usage(self):
        user, _ = viewer(self)
        if user is None:
            return self.fail(401, "Sign in first.")
        rows = db.execute("SELECT model, tokens_in, tokens_out, cost_micro, at FROM usage "
                          "WHERE user_id = ? ORDER BY id DESC LIMIT 100", (user["id"],)).fetchall()
        return self.send(200, {"usage": [{
            "model": row["model"], "tokensIn": row["tokens_in"], "tokensOut": row["tokens_out"],
            "cost": round(row["cost_micro"] / 1_000_000, 6), "at": row["at"]} for row in rows]})

    # ---- money -----------------------------------------------------------
    def list_payments(self):
        user, _ = viewer(self)
        if user is None:
            return self.fail(401, "Sign in first.")
        rows = db.execute("SELECT reference,dollars,network,address,state,created_at,confirmed_at FROM payments WHERE user_id=? ORDER BY id DESC LIMIT 100", (user["id"],)).fetchall()
        return self.send(200, {"payments": [{**dict(row), "label": store.NETWORKS.get(row["network"], (row["network"],))[0]} for row in rows]})

    def show_wallet(self):
        saved = store.wallet(db)
        network = (saved or {}).get("network")
        label, coin, _, hint = store.NETWORKS.get(network, (None, None, None, "Choose the network that should receive credit payments."))
        return self.send(200, {
            "set": saved is not None, "network": network, "label": label, "coin": coin, "hint": hint,
            "address": (saved or {}).get("address"),
            "networks": [{"value": key, "label": value[0], "coin": value[1], "hint": value[3]}
                         for key, value in store.NETWORKS.items()],
        })

    def save_wallet(self):
        user, _ = viewer(self)
        if user is None or not user["is_admin"]:
            return self.fail(403, "Only the admin can set the wallet.")
        data = body(self)
        network = str(data.get("network", "")).strip()
        address = str(data.get("address", "")).strip()
        if network not in store.NETWORKS:
            return self.fail(400, "Choose one of the networks listed.")
        pattern = store.NETWORKS[network][2]
        if not re.match(pattern, address):
            return self.fail(400, f"That is not a {store.NETWORKS[network][0]} address. {store.NETWORKS[network][3]}")
        store.set_wallet(db, network, address)
        return self.send(200, {"saved": True, "network": network, "address": address})

    def buy_credits(self):
        """Shows where to pay. The admin confirms the payment, then the credits land."""
        user, _ = viewer(self)
        if user is None:
            return self.fail(401, "Sign in first.")
        saved = store.wallet(db)
        if saved is None:
            return self.fail(409, "The admin has not attached a wallet yet, so credits cannot be bought.")
        try:
            dollars = float(body(self).get("dollars", 0))
        except (TypeError, ValueError):
            return self.fail(400, "Enter an amount in USDT.")
        if not 1 <= dollars <= 10000 or round(dollars, 2) != dollars:
            return self.fail(400, "Choose an amount between 1 and 10000 USDT.")
        reference = "pay_" + secrets.token_hex(8)
        with db:
            db.execute("INSERT INTO payments (user_id, dollars, network, address, reference, created_at) "
                       "VALUES (?, ?, ?, ?, ?, ?)",
                       (user["id"], dollars, saved["network"], saved["address"], reference, int(time.time())))
        label, coin, _, _ = store.NETWORKS[saved["network"]]
        return self.send(200, {
            "reference": reference, "dollars": dollars, "network": label, "coin": coin,
            "address": saved["address"],
            "instruction": f"Send exactly {dollars:.2f} {coin} on {label} to the address below. Your balance goes up on this page as soon as the payment is received.",
        })

    def confirm_payment(self):
        user, _ = viewer(self)
        if user is None or not user["is_admin"]:
            return self.fail(403, "Only the admin can confirm a payment.")
        reference = str(body(self).get("reference", "")).strip()
        dollars = store.confirm_payment(db, reference)
        if dollars is None:
            return self.fail(409, "This payment is already confirmed or does not exist.")
        return self.send(200, {"confirmed": True, "dollars": dollars})

    def save_price(self):
        user, _ = viewer(self)
        if user is None or not user["is_admin"]:
            return self.fail(403, "Only the admin can change prices.")
        data = body(self)
        name = str(data.get("name", ""))
        try:
            store.set_price(db, name, float(data.get("priceIn", 0)), float(data.get("priceOut", 0)))
        except (TypeError, ValueError):
            return self.fail(400, "Prices are numbers in USDT per million tokens.")
        return self.send(200, {"saved": True})

    def save_markup(self):
        """One percentage on top of every list price. Hand-set prices are not touched."""
        user, _ = viewer(self)
        if user is None or not user["is_admin"]:
            return self.fail(403, "Only the admin can change prices.")
        value = body(self).get("percent")
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return self.fail(400, "Use a markup from 0 to 1000 percent.")
        try:
            changed = store.set_markup(db, float(value))
        except ValueError as error:
            return self.fail(400, str(error))
        return self.send(200, {"saved": True, "percent": float(value), "changed": changed})

    def reset_price(self):
        """Puts one model back on its default price: the list price plus the markup."""
        user, _ = viewer(self)
        if user is None or not user["is_admin"]:
            return self.fail(403, "Only the admin can change prices.")
        try:
            price_in, price_out = store.reset_price(db, str(body(self).get("name", "")))
        except ValueError as error:
            return self.fail(400, str(error))
        return self.send(200, {"saved": True, "priceIn": price_in, "priceOut": price_out})

    def admin_overview(self):
        user, _ = viewer(self)
        if user is None or not user["is_admin"]:
            return self.fail(403, "Only the admin can see this.")
        users = db.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]
        waiting = db.execute("SELECT reference, dollars, network, address, created_at, user_id FROM payments "
                             "WHERE state = 'waiting' ORDER BY id DESC LIMIT 50").fetchall()
        earned = db.execute("SELECT COALESCE(SUM(dollars), 0) AS total FROM payments WHERE state = 'paid'").fetchone()
        spent = db.execute("SELECT COALESCE(SUM(cost_micro), 0) AS total FROM usage").fetchone()
        return self.send(200, {
            "users": users, "paid": round(earned["total"], 2),
            "spent": round(spent["total"] / 1_000_000, 6),
            "waiting": [{**dict(row), "label": store.NETWORKS.get(row["network"], (row["network"],))[0]} for row in waiting],
            "providers": json.loads(store.setting(db, "provider_status") or "{}"),
        })

    # ---- the API itself --------------------------------------------------
    def chat(self):
        """OpenAI-shaped. The key decides who pays; the model decides which sandbox."""
        secret = bearer(self)
        if not secret:
            return self.fail(401, "Send your key as: Authorization: Bearer yg-...")
        key = store.api_key_owner(db, secret)
        if key is None:
            return self.fail(401, "That key does not belong to this site.")
        data = body(self, limit=1024 * 1024)
        model = str(data.get("model", ""))
        if key["model"] and key["model"] != model:
            return self.fail(403, f"This key is only for {key['model']}.")
        row = db.execute("SELECT * FROM models WHERE name = ?", (model,)).fetchone()
        if row is None or not row["available"] or not row["price_ready"]:
            return self.fail(404, "That model is unavailable or awaits price approval.")
        messages = data.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 100:
            return self.fail(400, "Send 1–100 text messages.")
        if any(not isinstance(message, dict) or set(message) != {"role", "content"} or
               message["role"] not in ("user", "assistant", "system", "developer") or not isinstance(message["content"], str)
               for message in messages):
            return self.fail(400, "Only text messages with role and content are supported.")
        allowed = {"model", "messages", "max_tokens", "max_completion_tokens", "stream", "stream_options"}
        if set(data) - allowed:
            return self.fail(400, "Unsupported parameter. This endpoint supports text chat, token limits and streaming.")
        limit = data.get("max_completion_tokens", data.get("max_tokens", 1024))
        if type(limit) is not int or not 1 <= limit <= 8192 or type(data.get("stream", False)) is not bool:
            return self.fail(400, "Token limit must be 1–8192; stream must be true or false.")
        input_bound = len(json.dumps(messages, ensure_ascii=False).encode()) + 4096
        if input_bound > 65536:
            return self.fail(413, "Messages are too large.")
        reservation = store.reserve(db, key, row, input_bound, limit)
        if reservation is None:
            return self.fail(402, "Insufficient credits for this request's maximum cost. Lower the token limit or add credits.")
        try:
            payload = {"messages": messages, "max_tokens": limit}
            if row["sandbox"] in ("paid", "free"):
                # A gateway's free tier is sold at a price, but must never fall through to its paid tier.
                payload["_yougori_free_only"] = row["sandbox"] == "free" and (
                    row["price_source"] == "free" or store.row_cost(row) == (0.0, 0.0))
            answer = ask_sandbox(row["sandbox"], row["upstream"] or model,
                                 payload)
            usage = answer.get("usage", {})
            counts = usage.get("prompt_tokens"), usage.get("completion_tokens")
            if any(type(value) is not int or value < 0 for value in counts) or counts[0] > input_bound or counts[1] > limit:
                raise Failure(502, "Provider returned missing or invalid token usage.")
            choices = answer.get("choices")
            if not isinstance(choices, list) or len(choices) != 1 or not isinstance(choices[0].get("message"), dict):
                raise Failure(502, "Provider returned an invalid completion.")
            if choices[0]["message"].get("content") is None:
                # A reasoning model can spend the whole token limit before it answers: no text,
                # but the tokens were used. That is a complete, billed answer with empty content.
                choices[0]["message"]["content"] = ""
            if not isinstance(choices[0]["message"]["content"], str):
                raise Failure(502, "Provider returned an invalid completion.")
            cost = store.settle(db, reservation, counts)
        except (Failure, ValueError, TypeError, AttributeError) as error:
            store.settle(db, reservation)
            if isinstance(error, Failure) and error.code == "quota_exhausted":
                store.note_exhausted(db, key["id"], str(error))
            if isinstance(error, Failure):
                raise
            raise Failure(502, "Provider returned an invalid completion.") from None
        store.note_exhausted(db, key["id"], None)
        with db:
            db.execute("UPDATE api_keys SET last_used_at=? WHERE id=?", (int(time.time()), key["id"]))
        answer["model"], answer["cost_usd"] = model, round(cost, 6)
        if data.get("stream"):
            base = {"id": answer.get("id", "chatcmpl-" + secrets.token_hex(8)), "object": "chat.completion.chunk", "created": int(time.time()), "model": model}
            chunks = [{**base, "choices": [{"index": 0, "delta": choices[0]["message"], "finish_reason": None}]},
                      {**base, "choices": [{"index": 0, "delta": {}, "finish_reason": choices[0].get("finish_reason", "stop")}]}]
            if isinstance(data.get("stream_options"), dict) and data["stream_options"].get("include_usage"):
                chunks.append({**base, "choices": [], "usage": usage})
            wire = "".join("data: " + json.dumps(chunk) + "\n\n" for chunk in chunks) + "data: [DONE]\n\n"
            return self.send(200, wire.encode(), "text/event-stream")
        return self.send(200, answer)


def endpoint(sandbox):
    name = os.environ.get({"local": "LOCAL_SANDBOX", "paid": "PAID_SANDBOX", "free": "FREE_SANDBOX"}[sandbox], "")
    if not name or not re.fullmatch(r"[A-Za-z0-9_.-]+", name):
        raise Failure(503, "Sandbox address is not configured.")
    return f"http://{name}:" + ("11434" if sandbox == "local" else "8080")


def discover(sandbox, name):
    if sandbox == "attached":
        # Models started with `yougori run MODEL --template INSTANCE` (see attached.py). This
        # runs on a short-lived discovery thread, so its database connection closes here.
        try:
            return attached.discover(db)
        finally:
            store.close()
    if sandbox == "local" and "SELECTED_PROVIDERS" in os.environ and "ollama" not in os.environ["SELECTED_PROVIDERS"].split(","):
        return {"data": [], "status": {"ollama": "Not selected during setup."}}
    base = endpoint(sandbox)
    if sandbox == "local":
        result = http_json(base + "/api/tags", timeout=12)
        if not isinstance(result.get("models"), list):
            raise Failure(502, "Ollama returned an invalid model catalogue.")
        return {"data": [{"id": "ollama/" + item["name"], "provider": "ollama", "upstream": item["name"]}
                         for item in result.get("models", []) if isinstance(item, dict) and isinstance(item.get("name"), str)]}
    result = http_json(base + "/v1/models", headers={"Authorization": "Bearer " + os.environ.get("BRIDGE_KEY", "")}, timeout=60)
    rows, status = result.get("data"), result.get("status", {})
    if (not isinstance(rows, list) or len(rows) > 20000 or
        any(not isinstance(item, dict) or not isinstance(item.get("id"), str) or
            not isinstance(item.get("provider"), str) for item in rows) or
        not isinstance(status, dict) or any(not isinstance(value, str) for value in status.values())):
        raise Failure(502, "Bridge returned an invalid model catalogue.")
    tool_rows = result.get("toolModels", [])
    if (not isinstance(tool_rows, list) or len(tool_rows) > 20000 or
        any(not isinstance(item, dict) or item.get("access") != "coding-tool" or
            item.get("tool") not in ("codex", "opencode", "kilo") or
            any(not isinstance(item.get(key), str) or len(item[key]) > 250 for key in ("id", "label", "model")) or
            type(item.get("free")) is not bool for item in tool_rows)):
        raise Failure(502, "Bridge returned an invalid coding-tool catalogue.")
    return result


def ask_sandbox(sandbox, model, data):
    if sandbox == "attached":
        target = store.attachment(db, model)
        if target is None:
            raise Failure(503, "This model is not available right now. Try again shortly.", "provider_unavailable")
        # A model started by Yougori answers up to 4,096 tokens and serves one model, so the
        # request names none: its server accepts only its own exact ID there.
        payload = {"messages": data["messages"], "max_tokens": min(data.get("max_tokens", 1024), 4096), "stream": False}
        return http_json(target["url"] + "/chat/completions", payload,
                         headers={"Authorization": "Bearer " + target["key"]}, timeout=240)
    return http_json(endpoint(sandbox) + "/v1/chat/completions", {**data, "model": model, "stream": False},
                     headers={} if sandbox == "local" else {"Authorization": "Bearer " + os.environ.get("BRIDGE_KEY", "")}, timeout=240)


def initialize_admin():
    # The CLI stores the password in the credential vault and binds it only to this
    # sandbox. Consume it before serving requests; the database keeps only its hash.
    email = os.environ.pop("ADMIN_BOOTSTRAP_EMAIL", "")
    password = os.environ.pop("ADMIN_BOOTSTRAP_PASSWORD", "")
    if not store.has_admin(db) and (not email or not password):
        raise ValueError("No admin account exists. Run the template setup in the CLI and choose Create admin account.")
    return store.bootstrap_admin(db, email, password)


if __name__ == "__main__":
    if os.environ.get("COOKIE_SECURE") == "1" and len(os.environ.get("BRIDGE_KEY", "")) < 16:
        raise SystemExit("Public hosting requires a BRIDGE_KEY secret of at least 16 characters.")
    try:
        created = initialize_admin()
        print("CLI admin account created." if created else "Existing admin account preserved; use its existing sign-in.", flush=True)
    except ValueError as error:
        # The site stays up and its pages say the admin setup is not finished; exiting would
        # only restart it forever.
        print(f"The admin account was not created: {error} Run yougori template update with Create admin account.", flush=True)
    exit_on_stop()
    server = Server(("0.0.0.0", PORT), Handler)
    worker = CatalogueWorker().start()
    try:
        server.serve_forever()
    finally:
        # The discovery thread may wait on a provider for a minute; it ends with the process.
        worker.stop.set()
        server.server_close()
