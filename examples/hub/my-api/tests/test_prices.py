"""Default prices: the market rate, never below cost; the admin's markup; hand-set prices that stick.

Offline: no engine, provider accounts or payments.
"""
import http.client
import json
import os
from datetime import date
from pathlib import Path
import sqlite3
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest.mock import patch

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site"))
scratch = tempfile.TemporaryDirectory(prefix="my-api-prices-")
os.environ["MY_API_DATA"] = scratch.name
import pages
import prices
import server
import store

PAID = [
    {"id": "openai/gpt-6-astra", "provider": "openai", "upstream": "gpt-6-astra"},
    {"id": "openai/gpt-7-preview", "provider": "openai", "upstream": "gpt-7-preview"},
    {"id": "google/models/gemini-2.5-flash", "provider": "google", "upstream": "models/gemini-2.5-flash"},
    {"id": "google/models/gemini-embedding-2", "provider": "google", "upstream": "models/gemini-embedding-2"},
]


def fresh_database(directory, name="my-api.db"):
    store.close()
    store._local = threading.local()
    store.DATA = directory
    store.DATABASE = str(Path(directory) / name)


class PriceTableTests(unittest.TestCase):
    def test_provider_prices(self):
        lp = prices.list_price
        self.assertEqual(lp("openai", "gpt-6-astra"), (10.00, 50.00))
        self.assertEqual(lp("openai", "gpt-4o-mini-2024-07-18"), (0.15, 0.60))
        self.assertEqual(lp("openai", "gpt-4o-2024-05-13"), (5.00, 15.00))
        self.assertEqual(lp("google", "models/gemini-2.5-flash-001"), (0.30, 2.50))
        self.assertEqual(lp("anthropic", "claude-sonnet-4-5-20250929"), (3.00, 15.00))
        self.assertEqual(lp("anthropic", "claude-haiku-5-5"), (0.10, 0.50))
        self.assertIsNone(lp("openai", "gpt-7-preview"))
        self.assertIsNone(lp("openai", None))

    def test_introductory_prices_end_on_their_last_day(self):
        lp = prices.list_price
        self.assertEqual(lp("google", "gemini-4-argon", date(2026, 11, 30)), (2.00, 10.00))
        self.assertEqual(lp("google", "gemini-4-argon", date(2026, 12, 1)), (4.00, 20.00))
        self.assertEqual(lp("google", "models/gemini-3.8-flash", date(2027, 1, 1)), (1.50, 7.50))
        self.assertEqual(prices.promotion_ends("google", "gemini-4-argon", date(2026, 10, 24)), "2026-11-30")
        self.assertIsNone(prices.promotion_ends("google", "gemini-4-argon", date(2026, 12, 1)))
        self.assertEqual(prices.promotion_ends("openai", "gpt-5.6-sol", date(2026, 10, 24)), "2026-11-21")

    def test_the_default_is_the_market_price_never_below_cost(self):
        dp = prices.default_price
        self.assertEqual(dp("openai", "gpt-6-astra"), (10.00, 50.00, "list"))
        # The market charges more than Google during the introduction, so the market wins.
        self.assertEqual(dp("google", "models/gemini-3.8-flash", today=date(2026, 10, 24)), (0.825, 4.125, "market"))
        # After it, Google's regular price is above the old market price, so cost wins.
        self.assertEqual(dp("google", "models/gemini-3.8-flash", today=date(2027, 1, 1)), (1.50, 7.50, "list"))
        self.assertEqual(dp("openai", "gpt-5.1-codex"), (1.25, 10, "market"))
        # A gateway's own listed price is its cost; the market only lifts it.
        self.assertEqual(dp("kilo", "anthropic/claude-sonnet-4.5", "free", cost=(3.3, 16.5)), (3.3, 16.5, "list"))
        self.assertEqual(dp("kilo", "anthropic/claude-sonnet-4.5", "free", cost=(1.0, 2.0)), (3, 15, "market"))
        self.assertEqual(dp("opencode", "kimi-k2.5", "free"), (0.5, 2.5, "market"))

    def test_local_models_use_the_market_price_of_the_same_open_model(self):
        dp = prices.default_price
        self.assertEqual(dp("ollama", "llama3.3:70b", "local"), (0.10, 0.32, "market"))
        self.assertEqual(dp("ollama", "llama3.3:latest", "local"), (0.10, 0.32, "market"))
        self.assertEqual(dp("ollama", "gpt-oss:120b", "local"), (0.15, 0.60, "market"))
        self.assertEqual(dp("ollama", "mystery:13b-q4_K_M", "local"), (0.10, 0.25, "estimate"))
        self.assertEqual(dp("ollama", "mystery:405b", "local"), (0.50, 2.00, "estimate"))
        self.assertEqual(dp("ollama", "mystery:latest", "local"), (0.15, 0.50, "estimate"))

    def test_unpriced_models_get_a_cautious_estimate_and_non_chat_models_none(self):
        dp = prices.default_price
        self.assertEqual(dp("openai", "gpt-7-preview"), (10.00, 50.00, "estimate"))
        self.assertEqual(dp("openai", "gpt-7-mini"), (0.75, 4.50, "estimate"))
        self.assertEqual(dp("anthropic", "claude-opus-6"), (15.00, 75.00, "estimate"))
        self.assertEqual(dp("opencode", "brand-new-model", "free"), (3.00, 12.00, "estimate"))
        for provider, model, sandbox in (("google", "models/gemini-embedding-2", "paid"), ("google", "models/imagen-4", "paid"),
                                         ("google", "gemini-3.8-flash-tts", "paid"), ("ollama", "nomic-embed-text:latest", "local")):
            with self.subTest(model=model):
                self.assertIsNone(dp(provider, model, sandbox))

    def test_tables_are_plausible(self):
        tables = [(provider, table) for provider, table in prices.LIST_PRICES.items()]
        tables += [("market/" + provider, table) for provider, table in prices.MARKET.items()]
        tables += [("open", prices.MARKET_OPEN), ("ollama", {"/".join(key): price for key, price in prices.OPEN_MODELS.items()})]
        for name, table in tables:
            for model, (price_in, price_out) in table.items():
                with self.subTest(model=f"{name}/{model}"):
                    self.assertTrue(0 < price_in <= 1000 and 0 < price_out <= 1000)


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="my-api-price-case-")
        fresh_database(self.directory.name)
        self.db = store.setup()

    def tearDown(self):
        store.close()
        self.directory.cleanup()

    def row(self, name):
        return self.db.execute("SELECT * FROM models WHERE name = ?", (name,)).fetchone()

    def test_every_chat_model_gets_a_default_and_can_be_called(self):
        store.set_available(self.db, "paid", PAID)
        astra = self.row("openai/gpt-6-astra")
        self.assertEqual((astra["price_in"], astra["price_out"], astra["price_ready"], astra["price_source"]), (10.0, 50.0, 1, "list"))
        unknown = self.row("openai/gpt-7-preview")
        self.assertEqual((unknown["price_ready"], unknown["price_source"], unknown["price_in"]), (1, "estimate", 10.0))
        embedding = self.row("google/models/gemini-embedding-2")
        self.assertEqual((embedding["price_ready"], embedding["price_source"]), (0, ""))

    def test_admin_price_survives_refresh_and_markup(self):
        store.set_available(self.db, "paid", PAID)
        store.set_price(self.db, "openai/gpt-6-astra", 12.5, 61.0)
        store.set_markup(self.db, 50)
        store.set_available(self.db, "paid", PAID)
        astra = self.row("openai/gpt-6-astra")
        self.assertEqual((astra["price_in"], astra["price_out"], astra["price_source"]), (12.5, 61.0, "admin"))

    def test_markup_reprices_every_default_and_later_discoveries(self):
        store.set_available(self.db, "paid", PAID[:2])
        store.set_available(self.db, "local", [{"id": "ollama/llama3.3:70b", "provider": "ollama", "upstream": "llama3.3:70b"}])
        self.assertEqual(store.set_markup(self.db, 20), 3)
        self.assertEqual((self.row("openai/gpt-6-astra")["price_in"], self.row("openai/gpt-6-astra")["price_out"]), (12.0, 60.0))
        self.assertEqual(self.row("openai/gpt-7-preview")["price_in"], 12.0)
        self.assertEqual((self.row("llama3.3:70b")["price_in"], self.row("llama3.3:70b")["price_out"]), (0.12, 0.384))
        store.set_available(self.db, "paid", PAID)
        self.assertEqual((self.row("google/models/gemini-2.5-flash")["price_in"], self.row("google/models/gemini-2.5-flash")["price_out"]), (0.36, 3.0))
        self.assertEqual(store.set_markup(self.db, 0), 4)
        self.assertEqual(self.row("openai/gpt-6-astra")["price_in"], 10.0)

    def test_markup_cannot_go_below_the_default_or_be_nonsense(self):
        for value in (-1, 1000.5, float("nan"), float("inf")):
            with self.subTest(value=value), self.assertRaises(ValueError):
                store.set_markup(self.db, value)
        self.assertEqual(store.markup(self.db), 0)
        store.setting(self.db, "markup_percent", "not a number")
        self.assertEqual(store.markup(self.db), 0)

    def test_reset_returns_to_the_default_plus_markup(self):
        store.set_available(self.db, "paid", PAID)
        store.set_markup(self.db, 10)
        store.set_price(self.db, "openai/gpt-6-astra", 1.0, 2.0)
        self.assertEqual(store.reset_price(self.db, "openai/gpt-6-astra"), (11.0, 55.0))
        self.assertEqual(self.row("openai/gpt-6-astra")["price_source"], "list")
        store.set_price(self.db, "openai/gpt-7-preview", 1.0, 2.0)
        self.assertEqual(store.reset_price(self.db, "openai/gpt-7-preview"), (11.0, 55.0))
        self.assertEqual(self.row("openai/gpt-7-preview")["price_source"], "estimate")
        for name in ("google/models/gemini-embedding-2", "openai/not-on-this-site"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                store.reset_price(self.db, name)

    def test_local_and_free_tier_models_get_market_prices_and_plain_names(self):
        store.set_available(self.db, "local", [{"id": "ollama/llama3.3:70b", "provider": "ollama", "upstream": "llama3.3:70b"}])
        store.set_available(self.db, "free", [{"id": "kilo/minimax/minimax-m2:free", "provider": "kilo", "upstream": "minimax/minimax-m2:free", "free": True}])
        local = self.row("llama3.3:70b")
        self.assertEqual((local["price_in"], local["price_out"], local["price_ready"], local["price_source"], local["upstream"]),
                         (0.1, 0.32, 1, "market", "llama3.3:70b"))
        free = self.row("minimax/minimax-m2")
        self.assertEqual((free["price_in"], free["price_out"], free["price_source"], free["cost_in"], free["cost_out"], free["upstream"]),
                         (0.255, 1.02, "market", 0, 0, "kilo/minimax/minimax-m2:free"))
        self.assertIsNone(self.row("ollama/llama3.3:70b"))
        store.set_markup(self.db, 25)
        self.assertEqual(self.row("llama3.3:70b")["price_in"], 0.125)
        # Free only when the admin sets 0 and 0; [default] puts the price back.
        store.set_price(self.db, "llama3.3:70b", 0, 0)
        self.assertEqual(self.row("llama3.3:70b")["price_source"], "admin")
        self.assertEqual(store.reset_price(self.db, "llama3.3:70b"), (0.125, 0.4))

    def test_gateway_routers_are_never_sold(self):
        # A router listed before this rule, and one the admin priced by hand.
        with self.db:
            self.db.execute("INSERT INTO models (provider,name,price_in,price_out,sandbox,available,price_ready,price_source,upstream) VALUES "
                            "('kilo','kilo-auto/free',3,12,'free',1,1,'estimate','kilo/kilo-auto/free'),"
                            "('kilo','openrouter/auto',5,5,'free',1,1,'admin','kilo/openrouter/auto')")
        store.set_available(self.db, "free", [
            {"id": "kilo/kilo-auto/free", "provider": "kilo", "upstream": "kilo-auto/free", "free": True},
            {"id": "kilo/openrouter/free", "provider": "kilo", "upstream": "openrouter/free", "free": True},
            {"id": "kilo/openrouter/auto", "provider": "kilo", "upstream": "openrouter/auto"},
            {"id": "kilo/minimax/minimax-m2:free", "provider": "kilo", "upstream": "minimax/minimax-m2:free", "free": True}])
        offered = [row["name"] for row in self.db.execute("SELECT name FROM models WHERE available = 1")]
        self.assertEqual(offered, ["minimax/minimax-m2"])
        self.assertIsNone(self.row("kilo-auto/free"))
        self.assertIsNone(self.row("openrouter/free"))
        self.assertEqual((self.row("openrouter/auto")["price_source"], self.row("openrouter/auto")["available"]), ("admin", 0))

    def test_a_free_tier_and_its_paid_listing_become_one_model(self):
        twins = [{"id": "kilo/minimax/minimax-m2:free", "provider": "kilo", "upstream": "minimax/minimax-m2:free", "free": True},
                 {"id": "kilo/minimax/minimax-m2", "provider": "kilo", "upstream": "minimax/minimax-m2", "free": False, "cost": [0.3, 1.2]}]
        for order in (twins, twins[::-1]):
            with self.subTest(first=order[0]["id"]):
                store.set_available(self.db, "free", order)
                rows = self.db.execute("SELECT name, upstream, cost_in FROM models WHERE sandbox = 'free' AND available = 1").fetchall()
                self.assertEqual([tuple(row) for row in rows], [("minimax/minimax-m2", "kilo/minimax/minimax-m2", 0.3)])

    def test_gateway_models_use_their_listed_cost_and_the_free_tier_is_still_sold(self):
        model = {"id": "kilo/anthropic/claude-sonnet-4.5", "provider": "kilo", "upstream": "anthropic/claude-sonnet-4.5", "free": True}
        name = "anthropic/claude-sonnet-4.5"
        store.set_available(self.db, "free", [model])
        row = self.row(name)
        self.assertEqual((row["price_in"], row["price_out"], row["price_source"], row["cost_in"], row["upstream"]), (3, 15, "market", 0, model["id"]))
        model.update(free=False, cost=[3.3, 16.5])
        store.set_available(self.db, "free", [model])
        row = self.row(name)
        self.assertEqual((row["price_in"], row["price_out"], row["price_source"], row["cost_in"]), (3.3, 16.5, "list", 3.3))
        store.set_markup(self.db, 10)
        self.assertEqual(self.row(name)["price_in"], 3.63)
        store.set_price(self.db, name, 3, 4)
        store.set_available(self.db, "free", [model])
        self.assertEqual((self.row(name)["price_source"], self.row(name)["price_in"]), ("admin", 3))
        store.set_available(self.db, "free", [{"id": "kilo/bogus", "provider": "kilo", "cost": ["x", float("nan")]}])
        self.assertEqual(self.row("bogus")["price_source"], "estimate")
        self.assertIsNone(self.row("bogus")["cost_in"])

    def test_older_names_are_renamed_and_automatic_free_prices_are_priced_again(self):
        with self.db:
            self.db.execute("INSERT INTO models (provider,name,price_in,price_out,sandbox,available,price_ready,price_source,upstream) VALUES "
                            "('ollama','ollama/llama3.3:70b',0,0,'local',1,1,'free','llama3.3:70b'),"
                            "('kilo','kilo/minimax-m2:free',0,0,'free',1,1,'free','kilo/minimax-m2:free'),"
                            "('kilo','kilo/paid-one',5,6,'free',1,1,'admin','kilo/paid-one')")
            self.db.execute("INSERT INTO users (email,password_hash,salt,created_at) VALUES ('buyer@example.invalid','x','y',1)")
            self.db.execute("INSERT INTO api_keys (user_id,name,prefix,key_hash,model,created_at) VALUES (1,'k','yg-','h','kilo/minimax-m2:free',1)")
            self.db.execute("INSERT INTO usage (user_id,model,tokens_in,tokens_out,cost_micro,at) VALUES (1,'ollama/llama3.3:70b',1,1,0,1)")
        store.close()
        self.db = store.setup()
        local, gateway, admin = self.row("llama3.3:70b"), self.row("minimax-m2"), self.row("paid-one")
        self.assertEqual((local["upstream"], local["price_source"], local["price_ready"]), ("llama3.3:70b", "", 0))
        self.assertEqual((gateway["upstream"], gateway["price_source"], gateway["price_ready"]), ("kilo/minimax-m2:free", "", 0))
        self.assertEqual((admin["upstream"], admin["price_source"], admin["price_in"]), ("kilo/paid-one", "admin", 5))
        self.assertEqual(self.db.execute("SELECT model FROM api_keys").fetchone()[0], "minimax-m2")
        self.assertEqual(self.db.execute("SELECT model FROM usage").fetchone()[0], "llama3.3:70b")
        self.assertFalse(self.db.execute("SELECT 1 FROM models WHERE name LIKE 'kilo/%' OR name LIKE 'ollama/%'").fetchall())
        store.set_available(self.db, "local", [{"id": "ollama/llama3.3:70b", "provider": "ollama", "upstream": "llama3.3:70b"}])
        self.assertEqual((self.row("llama3.3:70b")["price_source"], self.row("llama3.3:70b")["price_in"]), ("market", 0.1))

    def test_migration_keeps_approved_prices_as_the_admins(self):
        fresh_database(self.directory.name, "old.db")
        old = sqlite3.connect(store.DATABASE)
        old.executescript("""
        CREATE TABLE models (id INTEGER PRIMARY KEY, provider TEXT NOT NULL, name TEXT NOT NULL UNIQUE,
          price_in REAL NOT NULL, price_out REAL NOT NULL, sandbox TEXT NOT NULL, available INTEGER NOT NULL DEFAULT 0,
          note TEXT, price_ready INTEGER NOT NULL DEFAULT 0, upstream TEXT);
        INSERT INTO models (provider, name, price_in, price_out, sandbox, available, price_ready, upstream)
          VALUES ('openai', 'openai/gpt-6-astra', 11, 55, 'paid', 1, 1, 'openai/gpt-6-astra'),
                 ('openai', 'openai/gpt-6-luna', 0, 0, 'paid', 1, 0, 'openai/gpt-6-luna');
        """)
        old.commit()
        old.close()
        self.db = store.setup()
        self.assertEqual(self.row("openai/gpt-6-astra")["price_source"], "admin")
        store.set_available(self.db, "paid", [
            {"id": "openai/gpt-6-astra", "provider": "openai", "upstream": "gpt-6-astra"},
            {"id": "openai/gpt-6-luna", "provider": "openai", "upstream": "gpt-6-luna"},
        ])
        self.assertEqual(tuple(self.db.execute("SELECT price_in, price_out FROM models WHERE name = 'openai/gpt-6-astra'").fetchone()), (11.0, 55.0))
        luna = self.row("openai/gpt-6-luna")
        self.assertEqual((luna["price_in"], luna["price_out"], luna["price_ready"]), (0.10, 0.50, 1))


class EndpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Request threads are joined after each test, so no database is still open when it is deleted.
        cls.web = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.web.daemon_threads = False
        cls.thread = threading.Thread(target=cls.web.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.web.shutdown()
        cls.web.server_close()
        cls.thread.join()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="my-api-price-http-")
        self.env = patch.dict(os.environ, {"ADMIN_BOOTSTRAP_EMAIL":"owner@example.invalid", "ADMIN_BOOTSTRAP_PASSWORD":"fixture-password", "COOKIE_SECURE": ""})
        self.env.start()
        fresh_database(self.directory.name)
        store.setup()
        server.login_attempts.clear()
        server.initialize_admin()
        self.admin = self.call("/api/signin", {"email": "owner@example.invalid", "password": "fixture-password"})[2].split(";")[0]
        self.user = self.call("/api/signup", {"email": "user@example.invalid", "password": "fixture-password"})[2].split(";")[0]
        store.set_available(store.connect(), "paid", PAID)

    def tearDown(self):
        self.web._threads.join()
        self.env.stop()
        store.close()
        self.directory.cleanup()

    def call(self, path, data=None, cookie=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.web.server_port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if cookie:
            headers["Cookie"] = cookie
        connection.request("GET" if data is None else "POST", path, body=None if data is None else json.dumps(data), headers=headers)
        response = connection.getresponse()
        payload = response.read()
        try:
            result = json.loads(payload)
        except ValueError:
            try:
                result = payload.decode()
            except UnicodeDecodeError:
                result = payload  # A font or other binary file.
        outcome = response.status, result, response.getheader("Set-Cookie", ""), response
        connection.close()
        return outcome

    def models(self, cookie=None):
        reply = self.call("/api/models", cookie=cookie)[1]
        return reply, {model["name"]: model for model in reply["models"]}

    def test_costs_market_prices_and_markup_are_shown_to_the_admin_only(self):
        for cookie in (None, self.user):
            reply, rows = self.models(cookie)
            self.assertNotIn("markup", reply)
            for field in ("costIn", "marketIn", "defaultIn", "promoEnds"):
                self.assertNotIn(field, rows["openai/gpt-6-astra"])
        reply, rows = self.models(self.admin)
        astra, unknown = rows["openai/gpt-6-astra"], rows["openai/gpt-7-preview"]
        self.assertEqual(reply["markup"], 0)
        self.assertEqual((astra["costIn"], astra["costOut"], astra["marketIn"], astra["marketOut"]), (10.0, 50.0, 10, 50))
        self.assertEqual((astra["defaultIn"], astra["defaultSource"], astra["priceSource"]), (10.0, "list", "list"))
        self.assertIsNone(astra["promoEnds"])
        self.assertEqual((unknown["costIn"], unknown["marketIn"], unknown["defaultSource"], unknown["priceSource"]), (None, None, "estimate", "estimate"))
        self.assertTrue(astra["available"] and unknown["available"])
        self.assertFalse(rows["google/models/gemini-embedding-2"]["available"])
        self.assertIn("market", reply["priceSources"])

    def test_markup_endpoint(self):
        self.assertEqual(self.call("/api/admin/markup", {"percent": 20}, self.user)[0], 403)
        for bad in ("20", -5, 1001, True, None):
            with self.subTest(value=bad):
                self.assertEqual(self.call("/api/admin/markup", {"percent": bad}, self.admin)[0], 400)
        status, result, _, _ = self.call("/api/admin/markup", {"percent": 20}, self.admin)
        self.assertEqual((status, result["changed"]), (200, 3))
        _, rows = self.models()
        self.assertEqual((rows["openai/gpt-6-astra"]["priceIn"], rows["openai/gpt-6-astra"]["priceOut"]), (12.0, 60.0))

    def test_reset_endpoint(self):
        self.call("/api/admin/price", {"name": "openai/gpt-6-astra", "priceIn": 3, "priceOut": 4}, self.admin)
        self.assertEqual(self.call("/api/admin/price/reset", {"name": "openai/gpt-6-astra"}, self.user)[0], 403)
        status, result, _, _ = self.call("/api/admin/price/reset", {"name": "openai/gpt-6-astra"}, self.admin)
        self.assertEqual((status, result["priceIn"], result["priceOut"]), (200, 10.0, 50.0))
        status, result, _, _ = self.call("/api/admin/price/reset", {"name": "google/models/gemini-embedding-2"}, self.admin)
        self.assertEqual(status, 400)
        self.assertIn("no default price", result["error"])

    def test_every_page_address_serves_the_site_under_the_content_policy(self):
        for path in ("/", "/keys", "/credits", "/admin", "/signin", "/signup"):
            with self.subTest(path=path):
                status, body, _, response = self.call(path)
                self.assertEqual(status, 200)
                self.assertIn('<script src="/app.js">', body)
                self.assertIn("default-src 'self'", response.getheader("Content-Security-Policy"))
        for path, kind in (("/app.js", "text/javascript"), ("/app.css", "text/css"), ("/grain.svg", "image/svg+xml")):
            status, _, _, response = self.call(path)
            self.assertEqual(status, 200)
            self.assertTrue(response.getheader("Content-Type").startswith(kind))

    def test_fonts_are_served_from_the_site_and_nothing_else_is(self):
        referenced = sorted(set(__import__("re").findall(r"url\((/fonts/[a-z0-9-]+\.woff2)\)", pages.CSS)))
        self.assertEqual(len(referenced), 5)
        for path in referenced:
            with self.subTest(path=path):
                status, body, _, response = self.call(path)
                self.assertEqual(status, 200)
                self.assertEqual(response.getheader("Content-Type"), "font/woff2")
                self.assertEqual(body[:4], b"wOF2")
                self.assertIn("max-age", response.getheader("Cache-Control"))
        for path in ("/fonts/../server.py", "/fonts/LICENSE-Geist.txt", "/fonts/missing.woff2", "/fonts/", "/fonts/geist.woff2/.."):
            with self.subTest(path=path):
                self.assertEqual(self.call(path)[0], 404)
        self.assertEqual(self.call("/api/me")[3].getheader("Cache-Control"), "no-store")

    def test_font_licences_travel_with_the_fonts(self):
        folder = Path(__file__).resolve().parents[1] / "site" / "fonts"
        for licence in ("LICENSE-Geist.txt", "LICENSE-KodeMono.txt", "LICENSE-Tinos.txt"):
            with self.subTest(licence=licence):
                self.assertIn("SIL Open Font License", (folder / licence).read_text(encoding="utf-8"))

    def test_the_page_never_parses_html_from_data(self):
        for risky in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(risky, pages.SCRIPT)
        self.assertIn("&lt;b&gt;", pages.shell("<b>"))


if __name__ == "__main__":
    try:
        unittest.main()
    finally:
        store._local = threading.local()
        scratch.cleanup()
