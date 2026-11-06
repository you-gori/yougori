"""Offline regression suite. No engine, GPU, provider accounts or payments used."""
import concurrent.futures
import contextlib
import http.client
import importlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "site"))
scratch = tempfile.TemporaryDirectory(prefix="my-api-tests-")
os.environ["MY_API_DATA"] = scratch.name
import server
import store
import bridge
import attached
from transport import Failure


class Provider(BaseHTTPRequestHandler):
    mode = "ok"
    calls = 0
    def log_message(self, *args): pass
    def reply(self, status, data):
        wire = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(wire)))
        self.end_headers()
        self.wfile.write(wire)
    def do_GET(self):
        if self.mode == "bad_catalogue":
            return self.reply(200, {"data": None, "models": None})
        if self.path == "/api/tags":
            return self.reply(200, {"models": [{"name": "fixture:latest"}]})
        self.reply(200, {"data": [{"id": "gpt-fixture", "pricing": {"prompt": "0", "completion": "0"}}]})
    def do_POST(self):
        Provider.calls += 1
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        Provider.last = {"path": self.path, "authorization": self.headers.get("Authorization"), "body": data}
        if self.mode == "quota":
            return self.reply(429, {"error": {"code": "insufficient_quota"}})
        if self.mode == "rate":
            return self.reply(429, {"error": "rate limit"})
        if self.mode == "down":
            return self.reply(503, {"secret": "must never reach customer"})
        result = {"id": "chatcmpl-fixture", "object": "chat.completion", "model": data.get("model", "served-model"),
                  "choices": [{"index": 0, "message": {"role": "assistant", "content": "Fixture response"}, "finish_reason": "stop"}],
                  "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
        if self.mode == "bad_usage": result.pop("usage")
        if self.mode == "over_usage": result["usage"]["completion_tokens"] = 999999
        if self.mode == "reasoning_only": result["choices"][0]["message"]["content"] = None; result["choices"][0]["finish_reason"] = "length"
        if self.mode == "no_message": result["choices"][0].pop("message")
        self.reply(200, result)


def start(handler):
    http = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    http.daemon_threads = False
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    return http, thread


class ServiceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.provider, cls.provider_thread = start(Provider)
        cls.provider_url = f"http://127.0.0.1:{cls.provider.server_port}"
        cls.bridged, cls.bridge_thread = start(bridge.Handler)
        cls.bridged.mode = "paid"
        cls.bridge_url = f"http://127.0.0.1:{cls.bridged.server_port}"
        cls.free_bridge, cls.free_thread = start(bridge.Handler)
        cls.free_bridge.mode = "free"
        cls.free_url = f"http://127.0.0.1:{cls.free_bridge.server_port}"
        cls.web, cls.web_thread = start(server.Handler)

    @classmethod
    def tearDownClass(cls):
        for http, thread in ((cls.web,cls.web_thread),(cls.bridged,cls.bridge_thread),(cls.free_bridge,cls.free_thread),(cls.provider,cls.provider_thread)):
            http.shutdown(); http.server_close(); thread.join()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="my-api-case-")
        self.env = patch.dict(os.environ, {"BRIDGE_KEY": "fixture-bridge-secret", "OPENAI_API_KEY": "fixture-api-key",
                              "ANTHROPIC_API_KEY": "", "GEMINI_API_KEY": "", "ADMIN_BOOTSTRAP_EMAIL": "owner@example.invalid", "ADMIN_BOOTSTRAP_PASSWORD": "fixture-password", "COOKIE_SECURE": ""})
        self.env.start()
        store.DATA = self.directory.name
        store.DATABASE = str(Path(store.DATA) / "my-api.db")
        store.close()
        store._local = threading.local()
        store.setup()
        Provider.mode, Provider.calls = "ok", 0
        server.login_attempts.clear()
        self.provider_patch = patch.dict(bridge.PROVIDERS, {"openai": (self.provider_url, "OPENAI_API_KEY"), "kilo": (self.provider_url, "KILO_API_KEY")})
        self.provider_patch.start()
        self.endpoint_patch = patch.object(server, "endpoint", side_effect=lambda sandbox: {"local":self.provider_url,"paid":self.bridge_url,"free":self.free_url}[sandbox])
        self.endpoint_patch.start()
        self.assertTrue(server.initialize_admin())
        _, result, cookie = self.call("/api/signin", {"email":"owner@example.invalid","password":"fixture-password"})
        self.assertTrue(result["admin"])
        self.cookie = cookie.split(";")[0]

    def tearDown(self):
        self.web._threads.join()
        self.endpoint_patch.stop(); self.provider_patch.stop(); self.env.stop()
        store.close()
        self.directory.cleanup()

    def call(self, path, data=None, token=None, cookie=None, raw=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.web.server_port, timeout=10)
        headers = {"Content-Type": "application/json"}
        if token: headers["Authorization"] = "Bearer " + token
        if cookie: headers["Cookie"] = cookie
        wire = raw if raw is not None else None if data is None else json.dumps(data)
        connection.request("GET" if wire is None else "POST", path, body=wire, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        try: result = json.loads(payload)
        except ValueError: result = payload.decode()
        result_tuple = response.status, result, response.getheader("Set-Cookie", "")
        connection.close()
        return result_tuple

    def ready(self, dollars=1):
        status, found, _ = self.call("/api/admin/refresh", {}, cookie=self.cookie)
        self.assertEqual(status,200)
        self.assertIn("openai/gpt-fixture", [item["id"] for item in found["available"]["paid"]])
        self.call("/api/admin/price", {"name":"openai/gpt-fixture","priceIn":1,"priceOut":2},cookie=self.cookie)
        store.add_credits(store.connect(),1,dollars)
        return self.call("/api/keys", {"name":"Fixture"},cookie=self.cookie)[1]["key"]

    def chat(self, token, **changes):
        return self.call("/v1/chat/completions", {"model":"openai/gpt-fixture","messages":[{"role":"user","content":"Hello"}], **changes},token=token)

    def test_successful_request_crosses_real_http_bridge_and_bills_exact_usage(self):
        token = self.ready()
        status, answer, _ = self.chat(token)
        self.assertEqual(status,200)
        self.assertEqual(answer["choices"][0]["message"]["content"],"Fixture response")
        self.assertEqual(answer["cost_usd"],0.00002)
        self.assertEqual(store.connect().execute("SELECT credits_micro FROM users WHERE id=1").fetchone()[0],999980)
        self.assertEqual(Provider.calls,1)

    def test_a_reasoning_model_that_used_its_whole_limit_answers_empty_and_is_billed(self):
        token = self.ready()
        Provider.mode = "reasoning_only"
        status, answer, _ = self.chat(token)
        self.assertEqual(status, 200)
        self.assertEqual(answer["choices"][0]["message"]["content"], "")
        self.assertEqual(answer["choices"][0]["finish_reason"], "length")
        self.assertEqual(store.connect().execute("SELECT credits_micro FROM users WHERE id=1").fetchone()[0], 999980)

    def test_stream_format_contains_done_and_usage(self):
        status, answer, _ = self.chat(self.ready(),stream=True,stream_options={"include_usage":True})
        self.assertEqual(status,200)
        self.assertIn("data: [DONE]",answer)
        self.assertIn('"usage"',answer)

    def test_ollama_models_are_named_plainly_and_priced(self):
        token = self.ready()
        self.assertEqual(self.chat(token,model="ollama/fixture:latest")[0],404)
        status, answer, _ = self.chat(token,model="fixture:latest")
        self.assertEqual(status,200)
        self.assertEqual(answer["model"],"fixture:latest")
        self.assertGreater(answer["cost_usd"],0)
        row=store.connect().execute("SELECT * FROM models WHERE name='fixture:latest'").fetchone()
        self.assertEqual((row["price_ready"],row["price_source"],row["upstream"]),(1,"estimate","fixture:latest"))

    def test_free_tier_gateway_models_are_sold_at_a_price(self):
        token = self.ready()
        self.assertEqual(self.chat(token,model="kilo/gpt-fixture")[0],404)
        status, answer, _ = self.chat(token,model="gpt-fixture")
        self.assertEqual(status,200)
        self.assertEqual(answer["model"],"gpt-fixture")
        self.assertGreater(answer["cost_usd"],0)
        row=store.connect().execute("SELECT * FROM models WHERE name='gpt-fixture'").fetchone()
        # It costs the admin nothing and stays on the free tier: the bridge is told so.
        self.assertEqual((row["sandbox"],row["cost_in"],row["cost_out"],row["upstream"]),("free",0,0,"kilo/gpt-fixture"))
        db=store.connect()
        with db: db.execute("UPDATE users SET credits_micro=0 WHERE id=1")
        self.assertEqual(self.chat(token,model="gpt-fixture")[0],402)

    def attach(self, request):
        """Runs site/attached.py as the CLI does: one request file, removed once read."""
        path = Path(self.directory.name) / "attach-request.json"
        path.write_text(json.dumps(request))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = attached.main(["attached.py", str(path)])
        self.assertFalse(path.exists(), "the request file holds a key and must be removed")
        return code, json.loads(out.getvalue()), out.getvalue()

    def test_models_started_with_template_are_listed_priced_and_called(self):
        token = self.ready()
        code, result, printed = self.attach({"action": "attach", "model": "hf.co/Qwen/Qwen3-8B", "environment": "env-model-1",
                                              "url": self.provider_url + "/v1", "key": "fixture-model-key", "place": "local"})
        self.assertEqual(code, 0)
        self.assertNotIn("fixture-model-key", printed)
        self.assertEqual((result["name"], result["reachable"], result["priced"], result["priceIn"], result["priceOut"], result["currency"]),
                         ("Qwen/Qwen3-8B", True, True, 0.1, 0.2, "USDT"))
        status, answer, _ = self.chat(token, model="Qwen/Qwen3-8B", max_tokens=8000)
        self.assertEqual(status, 200)
        self.assertEqual(answer["model"], "Qwen/Qwen3-8B")
        self.assertEqual(answer["cost_usd"], 0.000002)
        self.assertEqual((Provider.last["path"], Provider.last["authorization"]), ("/v1/chat/completions", "Bearer fixture-model-key"))
        self.assertEqual(Provider.last["body"], {"messages": [{"role": "user", "content": "Hello"}], "max_tokens": 4096, "stream": False})
        buyer = next(m for m in self.call("/api/models")[1]["models"] if m["name"] == "Qwen/Qwen3-8B")
        self.assertEqual(buyer["maker"], "qwen")
        self.assertNotIn("fixture-model-key", json.dumps(self.call("/api/models", cookie=self.cookie)[1]))
        # Discovery keeps it listed while it answers; a refresh does not lose it.
        self.call("/api/admin/refresh", {}, cookie=self.cookie)
        self.assertEqual(self.chat(token, model="Qwen/Qwen3-8B")[0], 200)
        code, result, _ = self.attach({"action": "detach", "environment": "env-model-1"})
        self.assertEqual((code, result), (0, {"detached": 1}))
        self.assertEqual(self.chat(token, model="Qwen/Qwen3-8B")[0], 404)

    def test_an_unreachable_or_malformed_model_is_never_listed(self):
        code, result, _ = self.attach({"model": "hf.co/meta-llama/Llama-3.1-8B-Instruct", "environment": "env-model-2",
                                       "url": "http://127.0.0.1:9/v1", "key": "fixture-model-key"})
        self.assertEqual((code, result["reachable"], result["priced"]), (0, False, False))
        self.assertNotIn("meta-llama/Llama-3.1-8B-Instruct", [m["name"] for m in self.call("/api/models")[1]["models"]])
        for bad in ({"model": "not a repo", "environment": "e", "url": "http://x/v1", "key": "k" * 16},
                    {"model": "a/b", "environment": "e", "url": "file:///etc/passwd", "key": "k" * 16},
                    {"model": "a/b", "environment": "e", "url": "http://user:pass@x/v1", "key": "k" * 16},
                    {"model": "a/b", "environment": "e", "url": "http://x/v1", "key": "short"},
                    {"model": "a/b", "environment": "e", "url": "http://x/v1", "key": "k" * 16, "place": "moon"},
                    {"action": "delete-everything"}, ["not", "an", "object"]):
            with self.subTest(bad=bad):
                code, result, _ = self.attach(bad)
                self.assertEqual(code, 1)
                self.assertIn("error", result)
        self.assertEqual(store.connect().execute("SELECT COUNT(*) FROM attached").fetchone()[0], 1)

    def test_buyers_see_model_names_makers_and_prices_only(self):
        self.ready()
        customer=self.call("/api/signup",{"email":"customer@example.invalid","password":"fixture-password"})[2].split(";")[0]
        for cookie in (None, customer):
            data=self.call("/api/models",cookie=cookie)[1]
            models={m["name"]: m for m in data["models"]}
            self.assertEqual(set(models),{"openai/gpt-fixture","gpt-fixture","fixture:latest"})
            self.assertEqual((models["gpt-fixture"]["maker"],models["openai/gpt-fixture"]["maker"]),("openai","openai"))
            for m in data["models"]:
                self.assertEqual(set(m),{"name","maker","priceIn","priceOut","available","discovered"})
            self.assertNotIn("toolModels",data)
            self.assertNotRegex(json.dumps(data).lower(),"kilo|ollama|opencode|codex|free|sandbox|provider")
        admin=self.call("/api/models",cookie=self.cookie)[1]
        self.assertIn("toolModels",admin)
        self.assertEqual(next(m for m in admin["models"] if m["name"]=="gpt-fixture")["sandbox"],"free")

    def test_insufficient_balance_stops_before_provider_call(self):
        self.assertEqual(self.chat(self.ready(dollars=0))[0],402)
        self.assertEqual(Provider.calls,0)

    def test_unknown_paid_models_get_a_cautious_default_price(self):
        self.call("/api/admin/refresh",{},cookie=self.cookie)
        row=store.connect().execute("SELECT * FROM models WHERE name='openai/gpt-fixture'").fetchone()
        self.assertEqual((row["price_ready"], row["price_source"], row["price_in"], row["price_out"]), (1, "estimate", 10.0, 50.0))

    def test_failures_refund_reservations_and_only_quota_marks_key(self):
        token=self.ready()
        for mode in ("rate","down","bad_usage","over_usage","no_message","quota"):
            with self.subTest(mode=mode):
                Provider.mode=mode
                status, answer, _=self.chat(token)
                self.assertGreaterEqual(status,400)
                # Cloudflare swaps a 502 or 504 for its own HTML page; buyers must get the JSON.
                self.assertNotIn(status,(502,504))
                self.assertNotIn("must never reach customer",str(answer))
                self.assertEqual(store.connect().execute("SELECT credits_micro FROM users WHERE id=1").fetchone()[0],1000000)
                note=store.api_key_owner(store.connect(),token)["exhausted_note"]
                self.assertEqual(bool(note),mode=="quota")
        Provider.mode="ok"
        self.assertEqual(self.chat(token)[0],200)
        self.assertIsNone(store.api_key_owner(store.connect(),token)["exhausted_note"])

    def test_model_key_restriction_and_authenticated_model_list(self):
        self.ready()
        key=self.call("/api/keys",{"name":"local","model":"fixture:latest"},cookie=self.cookie)[1]["key"]
        self.assertEqual(self.chat(key)[0],403)
        self.assertEqual(self.call("/v1/models")[0],401)
        rows=self.call("/v1/models",token=key)[1]["data"]
        self.assertEqual([(item["id"],item["owned_by"]) for item in rows],[("fixture:latest","other")])
        everything=self.call("/api/keys",{"name":"all"},cookie=self.cookie)[1]["key"]
        owners={item["id"]: item["owned_by"] for item in self.call("/v1/models",token=everything)[1]["data"]}
        self.assertEqual(owners,{"openai/gpt-fixture":"openai","gpt-fixture":"openai","fixture:latest":"other"})

    def test_malformed_json_and_nonfinite_prices_fail_cleanly(self):
        for raw in ("[]", "null", "broken", '{"priceIn":NaN}'):
            self.assertEqual(self.call("/api/admin/price",raw=raw,cookie=self.cookie)[0],400)
        for value in (-1,1e99):
            self.assertEqual(self.call("/api/admin/price",{"name":"gpt-5.1","priceIn":value,"priceOut":1},cookie=self.cookie)[0],400)

    def test_credits_are_bought_in_usdt_and_retired_networks_are_chosen_again(self):
        self.assertEqual(self.call("/api/admin/wallet",{"network":"bitcoin","address":"bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"},cookie=self.cookie)[0],400)
        self.assertEqual(self.call("/api/admin/wallet",{"network":"tron","address":"T"+"1"*33},cookie=self.cookie)[0],200)
        result=self.call("/api/credits/buy",{"dollars":25},cookie=self.cookie)[1]
        self.assertEqual((result["coin"],result["network"]),("USDT","Tron (TRC-20)"))
        self.assertTrue(result["instruction"].startswith("Send exactly 25.00 USDT on Tron (TRC-20)"))
        # A wallet saved before payments moved to USDT, on a network no longer offered.
        store.set_wallet(store.connect(),"base","0x"+"1"*40)
        self.assertFalse(self.call("/api/wallet")[1]["set"])
        self.assertEqual(self.call("/api/credits/buy",{"dollars":25},cookie=self.cookie)[0],409)

    def test_confirm_payment_is_atomic_and_idempotent(self):
        db=store.connect()
        with db: db.execute("INSERT INTO payments (user_id,dollars,network,address,reference,created_at) VALUES (1,5,'base','fixture','payment',1)")
        def confirm(_):
            connection=store.connect()
            try: return store.confirm_payment(connection,"payment")
            finally: store.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            results=list(pool.map(confirm,range(8)))
        self.assertEqual(results.count(5),1)
        self.assertEqual(db.execute("SELECT credits_micro FROM users WHERE id=1").fetchone()[0],5000000)

    def test_concurrent_cli_bootstraps_create_exactly_one_admin(self):
        db=store.connect()
        with db: db.execute("DELETE FROM sessions"); db.execute("DELETE FROM users")
        barrier=threading.Barrier(4)
        def signup(index):
            connection=store.connect()
            try:
                barrier.wait(timeout=10)
                return store.bootstrap_admin(connection,f"fixture{index}@example.invalid","fixture-password")
            finally: store.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(signup,range(4)))
        self.assertEqual(results.count(True),1)

    def test_web_signup_cannot_create_admin_even_with_the_old_setup_secret(self):
        db=store.connect()
        with db: db.execute("DELETE FROM sessions"); db.execute("DELETE FROM users")
        with patch.dict(os.environ,{"ADMIN_SETUP_KEY":"fixture-setup-secret"}):
            with self.assertRaises(ValueError): store.create_user(db,"attacker@example.invalid","fixture-password")
            status, _, _ = self.call("/api/signup", {"email":"attacker@example.invalid", "password":"fixture-password", "setupKey":"fixture-setup-secret", "admin":True})
            self.assertEqual(status,409)
        self.assertFalse(store.has_admin(db))
        store.bootstrap_admin(db,"owner@example.invalid","fixture-password")
        status, result, _ = self.call("/api/signup", {"email":"customer@example.invalid", "password":"fixture-password", "admin":True, "is_admin":1})
        self.assertEqual(status,200)
        self.assertFalse(result["admin"])

    def test_cli_account_survives_restart_and_does_not_reset_existing_credentials(self):
        row=dict(store.user_by_email(store.connect(),"owner@example.invalid"))
        with patch.dict(os.environ,{"ADMIN_BOOTSTRAP_EMAIL":"different@example.invalid", "ADMIN_BOOTSTRAP_PASSWORD":"replacement-password"}):
            self.assertFalse(server.initialize_admin())
            self.assertNotIn("ADMIN_BOOTSTRAP_PASSWORD",os.environ)
            self.assertNotIn("ADMIN_BOOTSTRAP_EMAIL",os.environ)
        self.assertEqual(dict(store.user_by_email(store.connect(),"owner@example.invalid")),row)
        self.assertIsNone(store.user_by_email(store.connect(),"different@example.invalid"))
        self.assertEqual(self.call("/api/signin",{"email":"owner@example.invalid","password":"fixture-password"})[0],200)
        self.assertEqual(self.call("/api/signin",{"email":"owner@example.invalid","password":"replacement-password"})[0],401)
        self.assertFalse(server.initialize_admin(), "an existing account starts without bootstrap credentials")

    def test_missing_or_invalid_cli_credentials_stop_initialization(self):
        db=store.connect()
        with db: db.execute("DELETE FROM sessions"); db.execute("DELETE FROM users")
        with self.assertRaisesRegex(ValueError,"CLI"):
            server.initialize_admin()
        for email,password in [("not-an-email","long-enough-password"),("owner@example.invalid","short"),("owner@example.invalid","x"*1025)]:
            with patch.dict(os.environ,{"ADMIN_BOOTSTRAP_EMAIL":email,"ADMIN_BOOTSTRAP_PASSWORD":password}):
                with self.assertRaises(ValueError): server.initialize_admin()
            self.assertFalse(store.has_admin(db))

    def test_payment_network_is_chosen_on_website_after_admin_signin(self):
        info=self.call("/api/wallet")[1]
        self.assertFalse(info["set"])
        self.assertIsNone(info["network"])
        self.assertEqual(len(info["networks"]),6)
        self.assertEqual(self.call("/api/credits/buy",{"dollars":10},cookie=self.cookie)[0],409)
        self.assertEqual(self.call("/api/admin/wallet",{"address":"0x"+"1"*40},cookie=self.cookie)[0],400)
        wallet={"network":"polygon","address":"0x"+"1"*40}
        self.assertEqual(self.call("/api/admin/wallet",wallet,cookie=self.cookie)[0],200)
        server.initialize_admin()
        self.assertEqual(self.call("/api/wallet")[1]["network"],"polygon")
        customer=self.call("/api/signup",{"email":"customer@example.invalid","password":"fixture-password"})[2].split(";")[0]
        self.assertEqual(self.call("/api/admin/wallet",wallet,cookie=customer)[0],403)

    def test_concurrent_reservations_cannot_overspend_and_recovery_refunds(self):
        token=self.ready(dollars=0.00005)
        db=store.connect()
        key=store.api_key_owner(db,token)
        model=db.execute("SELECT * FROM models WHERE name='openai/gpt-fixture'").fetchone()
        def reserve(_):
            connection=store.connect()
            try: return store.reserve(connection,key,model,10,0)
            finally: store.close()
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
            results=list(pool.map(reserve,range(10)))
        self.assertEqual(sum(result is not None for result in results),5)
        self.assertEqual(db.execute("SELECT credits_micro FROM users WHERE id=1").fetchone()[0],0)
        store.recover_reservations(db)
        store.recover_reservations(db)
        self.assertEqual(db.execute("SELECT credits_micro FROM users WHERE id=1").fetchone()[0],50)

    def test_free_catalogue_fails_closed_for_unknown_and_nonzero_prices(self):
        for pricing in ({},{"prompt":"0"},{"prompt":"0","completion":"0.01"},{"prompt":"NaN","completion":"0"}, {"prompt":"0","completion":"0","request":"1"}):
            self.assertFalse(bridge.free_model({"pricing":pricing}))
        self.assertTrue(bridge.free_model({"pricing":{"prompt":"0","completion":"0"}}))

    def test_subscription_and_deselected_providers_never_call_the_api(self):
        with patch.dict(os.environ, {"SELECTED_PROVIDERS":"codex", "CODEX_ACCESS":"subscription", "OPENAI_API_KEY":"fixture-unused"}), patch.object(bridge,"request") as outbound:
            self.assertEqual(bridge.catalogue("paid")["data"], [])
            outbound.assert_not_called()
        with patch.dict(os.environ, {"SELECTED_PROVIDERS":"ollama"}), patch.object(bridge,"request") as outbound:
            self.assertEqual(bridge.catalogue("free")["data"], [])
            outbound.assert_not_called()

    def test_anthropic_uses_only_its_api_key_even_with_an_old_subscription_choice(self):
        with patch.dict(os.environ, {"SELECTED_PROVIDERS":"claude", "CLAUDE_ACCESS":"subscription", "ANTHROPIC_API_KEY":"fixture-key"}), \
             patch.object(bridge,"request",return_value={"data":[{"id":"claude-fixture"}]}) as outbound:
            self.assertEqual([m["id"] for m in bridge.catalogue("paid")["data"]], ["anthropic/claude-fixture"])
        self.assertEqual(outbound.call_args.args[0], "https://api.anthropic.com/v1/models")
        self.assertEqual(outbound.call_args.kwargs["headers"]["x-api-key"], "fixture-key")

    def test_paid_kilo_opt_in_requires_a_key_and_preserves_price_classification(self):
        rows = [{"id":"free", "pricing":{"prompt":"0","completion":"0"}},
                {"id":"paid", "pricing":{"prompt":"0.001","completion":"0.002"}},
                {"id":"unknown"}]
        selected = {"SELECTED_PROVIDERS":"kilo", "KILO_SCOPE":"all", "KILO_ACCESS":"api", "KILO_API_KEY":""}
        with patch.dict(os.environ, selected), patch.object(bridge,"request") as outbound:
            self.assertEqual(bridge.catalogue("free")["data"], [])
            outbound.assert_not_called()
        with patch.dict(os.environ, {**selected,"KILO_API_KEY":"fixture-key"}), patch.object(bridge,"request",return_value={"data":rows}):
            data = bridge.catalogue("free")["data"]
            self.assertEqual([m["free"] for m in data], [True,False,False])
            with self.assertRaises(Failure) as error:
                bridge.completion("free", {"model":"kilo/paid", "messages":[{"role":"user","content":"Hi"}], "_yougori_free_only":True})
            self.assertEqual(error.exception.status, 409)
        with patch.dict(os.environ, {**selected,"KILO_SCOPE":"free"}), patch.object(bridge,"request",return_value={"data":rows}):
            self.assertEqual([m["id"] for m in bridge.catalogue("free")["data"]], ["kilo/free"])

    def test_opencode_exports_only_opted_in_supported_paid_chat_models(self):
        settings={"SELECTED_PROVIDERS":"opencode", "OPENCODE_SCOPE":"all", "OPENCODE_ACCESS":"api", "OPENCODE_API_KEY":"fixture-key"}
        rows=[{"id":name} for name in ("glm-5.3-flash", "gpt-6-astra", "big-pickle", "glm-5.3-flash-free", "unknown")]
        with patch.dict(os.environ, settings), patch.object(bridge,"request",return_value={"data":rows}):
            models=bridge.catalogue("free")["data"]
            self.assertEqual([m["id"] for m in models], ["opencode/glm-5.3-flash"])
            self.assertFalse(models[0]["free"])
        with patch.dict(os.environ, {**settings,"OPENCODE_SCOPE":"free"}), patch.object(bridge,"request") as outbound:
            self.assertEqual(bridge.catalogue("free")["data"], [])
            outbound.assert_not_called()

    def test_anthropic_translation_and_usage(self):
        calls=[]
        def upstream(url,payload=None,headers=None,timeout=None):
            calls.append((url,payload))
            if payload is None: return {"data":[{"id":"claude-fixture"}]}
            return {"id":"fixture","content":[{"type":"text","text":"Hello"}],"usage":{"input_tokens":3,"output_tokens":2},"stop_reason":"end_turn"}
        with patch.dict(os.environ,{"OPENAI_API_KEY":"","ANTHROPIC_API_KEY":"fixture-api-key"}),patch.object(bridge,"request",side_effect=upstream):
            answer=bridge.completion("paid",{"model":"anthropic/claude-fixture","messages":[{"role":"system","content":"Be concise"},{"role":"user","content":"Hi"}],"max_tokens":16})
        self.assertEqual(answer["usage"]["prompt_tokens"],3)
        self.assertEqual(calls[-1][1]["system"],"Be concise")

    def test_malformed_catalogue_and_removed_credentials_disable_models(self):
        self.ready()
        Provider.mode="bad_catalogue"
        status, result, _=self.call("/api/admin/refresh",{},cookie=self.cookie)
        self.assertEqual(status,200)
        self.assertEqual(result["available"]["local"],[])
        self.assertEqual(result["available"]["paid"],[])
        self.assertIn("invalid",str(result["status"]).lower())
        Provider.mode="ok"
        with patch.dict(os.environ,{"OPENAI_API_KEY":""}):
            result=self.call("/api/admin/refresh",{},cookie=self.cookie)[1]
        self.assertEqual(result["available"]["paid"],[])
        self.assertEqual(result["status"]["paid"]["openai"],"API key not configured")

    def test_free_model_becoming_paid_is_refused_before_inference(self):
        free={"id":"fixture","pricing":{"prompt":"0","completion":"0"}}
        with patch.object(bridge,"request",return_value={"data":[free]}):
            self.assertEqual(len(bridge.catalogue("free")["data"]),1)
        free["pricing"]["completion"]="0.01"
        with patch.object(bridge,"request",return_value={"data":[free]}) as outbound:
            with self.assertRaises(Failure):
                bridge.completion("free",{"model":"kilo/fixture","messages":[{"role":"user","content":"Hi"}]})
            self.assertEqual(outbound.call_count,1)

    def test_google_adapter_and_anthropic_catalogue_pagination(self):
        calls=[]
        def upstream(url,payload=None,headers=None,timeout=None):
            calls.append((url,payload,headers))
            if payload is None:
                return {"data":[{"id":"gemini-fixture"}]}
            return {"choices":[],"usage":{}}
        with patch.dict(os.environ,{"OPENAI_API_KEY":"","GEMINI_API_KEY":"fixture-google-key"}),patch.object(bridge,"request",side_effect=upstream):
            bridge.completion("paid",{"model":"google/gemini-fixture","messages":[{"role":"user","content":"Hi"}],"max_tokens":17})
        self.assertEqual(calls[-1][1]["model"],"gemini-fixture")
        self.assertEqual(calls[-1][1]["max_tokens"],17)
        self.assertEqual(calls[-1][2]["Authorization"],"Bearer fixture-google-key")
        with patch.dict(os.environ,{"OPENAI_API_KEY":"","ANTHROPIC_API_KEY":"fixture-key"}),patch.object(bridge,"request",side_effect=[
            {"data":[{"id":"claude-one"}],"has_more":True,"last_id":"claude-one"},
            {"data":[{"id":"claude-two"}],"has_more":False}]) as outbound:
            self.assertEqual(len(bridge.catalogue("paid")["data"]),2)
            self.assertIn("after_id=claude-one",outbound.call_args.args[0])

    def test_prices_are_frozen_for_a_reserved_request(self):
        key=self.ready()
        db=store.connect()
        model=db.execute("SELECT * FROM models WHERE name='openai/gpt-fixture'").fetchone()
        reservation=store.reserve(db,store.api_key_owner(db,key),model,100,100)
        store.set_price(db,model["name"],100,200)
        self.assertEqual(store.settle(db,reservation,(10,5)),0.00002)
        self.assertIsNone(store.settle(db,reservation,(10,5)))

    def test_payment_history_preserves_wallet_snapshot_and_is_private(self):
        self.assertEqual(self.call("/api/payments")[0],401)
        wallet={"network":"polygon","address":"0x"+"1"*40}
        self.call("/api/admin/wallet",wallet,cookie=self.cookie)
        self.assertEqual(self.call("/api/credits/buy",{"dollars":1.001},cookie=self.cookie)[0],400)
        self.call("/api/credits/buy",{"dollars":5},cookie=self.cookie)
        self.call("/api/admin/wallet",{**wallet,"network":"ethereum"},cookie=self.cookie)
        rows=self.call("/api/payments",cookie=self.cookie)[1]["payments"]
        self.assertEqual((rows[0]["network"],rows[0]["label"]),("polygon","Polygon"))
        _,_,cookie=self.call("/api/signup",{"email":"second@example.invalid","password":"fixture-password"})
        self.assertEqual(self.call("/api/payments",cookie=cookie.split(";")[0])[1]["payments"],[])

    def test_automatic_discovery_starts_without_admin_refresh_and_tracks_changes(self):
        import time
        from tool_models import entry
        state = {"generation": 0}
        def discovery(sandbox, name):
            if sandbox != "free": return {"data": []}
            generation = state["generation"]
            return {"data": [{"id": "kilo/free-" + str(generation), "provider": "kilo", "free": True}],
                    "toolModels": [entry("opencode", "tool-" + str(generation), free=True)]}
        with patch.object(server, "discover", side_effect=discovery):
            worker = server.CatalogueWorker(interval=.08).start()
            try:
                def wait_for(generation):
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        data = self.call("/api/models")[1]
                        if any(m["name"] == "free-" + str(generation) and m["available"] for m in data["models"]):
                            return data
                        time.sleep(.02)
                    self.fail("Automatic discovery did not update the website")
                wait_for(0)
                self.assertEqual(self.call("/api/models", cookie=self.cookie)[1]["toolModels"][0]["model"], "tool-0")
                state["generation"] = 1
                second = wait_for(1)
                self.assertNotIn("free-0", [m["name"] for m in second["models"]])
                self.assertEqual(self.call("/api/models", cookie=self.cookie)[1]["toolModels"][0]["model"], "tool-1")
                token = self.call("/api/keys", {}, cookie=self.cookie)[1]["key"]
                ids = [m["id"] for m in self.call("/v1/models", token=token)[1]["data"]]
                self.assertEqual(ids, ["free-1"])
            finally:
                worker.close()
        self.assertFalse(worker.thread.is_alive())

    def test_automatic_discovery_retries_failed_provider_and_late_signin(self):
        import time
        from tool_models import entry
        tries = []
        def discovery(sandbox, name):
            if sandbox != "paid": return {"data": []}
            tries.append(1)
            if len(tries) == 1: raise Failure(503, "Not ready")
            return {"data": [], "toolModels": [entry("codex", "signed-in-model")]}
        with patch.object(server, "discover", side_effect=discovery):
            worker = server.CatalogueWorker(interval=.08).start()
            try:
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    data = self.call("/api/models", cookie=self.cookie)[1]
                    if data["toolModels"]: break
                    time.sleep(.02)
                self.assertEqual(data["toolModels"][0]["model"], "signed-in-model")
                self.assertGreaterEqual(len(tries), 2)
            finally:
                worker.close()

    def test_manual_refresh_does_not_overlap_automatic_refresh(self):
        entered, release = threading.Event(), threading.Event()
        def discovery(sandbox, name):
            entered.set()
            release.wait(3)
            return {"data": []}
        with patch.object(server, "discover", side_effect=discovery) as outbound:
            worker = server.CatalogueWorker(interval=60).start()
            try:
                self.assertTrue(entered.wait(2))
                self.assertEqual(self.call("/api/admin/refresh", {}, cookie=self.cookie)[1], {"refreshing": True})
                self.assertLessEqual(outbound.call_count, 4)
            finally:
                release.set()
                worker.close()

    def test_bridge_authentication_and_invalid_payload(self):
        connection=http.client.HTTPConnection("127.0.0.1",self.bridged.server_port,timeout=5)
        connection.request("GET","/v1/models")
        response=connection.getresponse()
        self.assertEqual(response.status,401)
        response.read(); connection.close()
        with self.assertRaises(Failure) as failure:
            bridge.completion("paid",[])
        self.assertEqual(failure.exception.status,400)


if __name__ == "__main__":
    try: unittest.main()
    finally:
        store._local=threading.local()
        scratch.cleanup()
