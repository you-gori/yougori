"""One model name over several replicas, cached-input billing and the connector stream, through
real website HTTP, SQLite and disposable model servers. No GPU.

Run: python -I -B examples/hub/inference-solver/tests/test_routing.py
"""
import hashlib
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import sys
import threading
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow, Model, UPSTREAM_KEY
import compute
import compute_node
import routing
from compute_adapter import Adapter


class RoutingFlow(Flow):
    def model_server(self, models=("test/one",)):
        server = ThreadingHTTPServer(("127.0.0.1", 0), Model)
        server.models, server.calls, server.fail_catalog, server.lock = list(models), [], False, threading.Lock()
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(lambda: (server.shutdown(), server.server_close(), thread.join()))
        return f"http://127.0.0.1:{server.server_port}/v1", server

    def connect(self, url, name):
        status, body, _ = self.call("/api/admin/endpoints", {"name": name, "url": url, "key": UPSTREAM_KEY, "place": "local"}, self.admin)
        self.assertEqual(status, 201, body)
        return body["id"]

    def two_replicas(self):
        """The fixture's server and a second one, both serving test/one."""
        first = self.connect(self.model_url, "First server")
        url, second_server = self.model_server()
        second = self.connect(url, "Second server")
        return {first: self.model, second: second_server}

    def turn(self, key, conversation, content, headers=None, stream=False):
        conversation.append({"role": "user", "content": content})
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": list(conversation), "stream": stream}, key=key, headers=headers)
        self.assertEqual(status, 200, body)
        conversation.append({"role": "assistant", "content": "hello"})
        return body

    @staticmethod
    def served(servers):
        return {endpoint: len(server.calls) for endpoint, server in servers.items()}

    def credit(self, session, amount):
        user = self.call("/api/session", session=session)[1]["user"]["id"]
        with self.service.store.db() as db:
            db.execute("INSERT INTO credit_ledger VALUES(?,?,?,'payment',?,?,?)", (secrets.token_hex(8), user, amount, int(time.time()), "base", secrets.token_hex(8)))

    def pair_node(self):
        token = secrets.token_urlsafe(32)
        status, pair, _ = self.call("/api/compute/pair/start", {"credential_hash": hashlib.sha256(token.encode()).hexdigest(), "name": "Contributor", "role": "contributor"})
        self.assertEqual(status, 200, pair)
        self.assertEqual(self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)[0], 200)
        return token

    def agent(self, token, action, **data):
        return self.call("/api/compute/agent", {"action": action, **data}, headers={"Authorization": "Bearer " + token})

    def test_one_name_for_every_replica_and_a_conversation_keeps_to_one(self):
        servers = self.two_replicas()
        catalog = {m["id"]: m for m in self.call("/api/models", session=self.admin)[1]["models"]}
        self.assertEqual(sorted(catalog), ["test/one", "test/two"])  # The first server also serves test/two.
        self.assertEqual(sorted(r["name"] for r in catalog["test/one"]["replicas"]), ["First server", "Second server"])
        self.assertEqual([r["name"] for r in catalog["test/two"]["replicas"]], ["First server"])
        self.assertEqual(catalog["test/one"]["state"], "ready")
        key = self.key()["key"]
        self.assertEqual(sorted(m["id"] for m in self.call("/v1/models", key=key)[1]["data"]), ["test/one", "test/two"])
        # Every turn of one conversation reaches the same server: its prompt prefix is cached there.
        for _ in range(3):
            before = self.served(servers)
            conversation = [{"role": "system", "content": "You review code."}]
            for index in range(4):
                self.turn(key, conversation, f"Question {index} of conversation {secrets.token_hex(4)}" if index == 0 else f"Follow-up {index}", stream=index % 2 == 1)
            grew = [endpoint for endpoint, count in self.served(servers).items() if count != before[endpoint]]
            self.assertEqual(len(grew), 1, self.served(servers))
        # New conversations spread over both servers.
        for index in range(24):
            self.turn(key, [], f"Separate conversation {index}")
        self.assertTrue(all(count >= 3 for count in self.served(servers).values()), self.served(servers))
        details = self.call("/api/admin/control", session=self.admin)[1]
        self.assertEqual(sorted(s["source"] for s in details["sources"]), ["First server", "Second server"])
        self.assertEqual(sum(r["requests"] for r in details["routing"]), 36)
        self.assertEqual(sum(r["same"] for r in details["routing"]), 9)

    def test_a_client_session_id_wins_and_routing_hints_are_not_forwarded(self):
        servers = self.two_replicas()
        key = self.key()["key"]
        for header in ({"X-Session-ID": "codex-session-1"},):
            before = self.served(servers)
            for index in range(6):
                # Different openings would spread; the explicit session keeps them together.
                self.turn(key, [], f"Unrelated opening {index}", headers=header)
            self.assertEqual(sum(1 for e, c in self.served(servers).items() if c != before[e]), 1)
        before = self.served(servers)
        for index in range(6):
            status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": [{"role": "user", "content": f"Other {index}"}],
                                                                 "prompt_cache_key": "conversation-7"}, key=key)
            self.assertEqual(status, 200, body)
        self.assertEqual(sum(1 for e, c in self.served(servers).items() if c != before[e]), 1)
        calls = [call for server in servers.values() for call in server.calls]
        self.assertFalse(any("prompt_cache_key" in call for call in calls))
        # Claude Code's session (Messages metadata.user_id) and Codex's (Responses prompt_cache_key).
        before = self.served(servers)
        for index in range(6):
            status, body, _ = self.call("/v1/messages", {"model": "test/one", "max_tokens": 32, "metadata": {"user_id": "user_x_account_y_session_z"},
                                                         "messages": [{"role": "user", "content": f"Message {index}"}]}, key=key)
            self.assertEqual(status, 200, body)
        self.assertEqual(sum(1 for e, c in self.served(servers).items() if c != before[e]), 1)
        before = self.served(servers)
        for index in range(6):
            status, body, _ = self.call("/v1/responses", {"model": "test/one", "input": f"Responses {index}", "prompt_cache_key": "codex-thread"}, key=key)
            self.assertEqual(status, 200, body)
        self.assertEqual(sum(1 for e, c in self.served(servers).items() if c != before[e]), 1)
        self.assertFalse(any("metadata" in call or "prompt_cache_key" in call for server in servers.values() for call in server.calls))

    def test_a_failing_server_is_skipped_before_anything_is_sent_and_refusals_are_not_retried(self):
        servers = self.two_replicas()
        broken = next(iter(servers.values()))
        broken.broken = True
        key = self.key()["key"]
        # New conversations until one is routed to the broken server first (each has an even chance).
        for index in range(40):
            body = self.turn(key, [], f"Opening {index}", stream=index % 2 == 0)
            self.assertIn("hello", str(body))
            if broken.calls:
                break
        self.assertEqual(len(broken.calls), 1)  # Tried, failed, cooled; the other answered.
        for index in range(4):
            self.turn(key, [], f"Later opening {index}")
        self.assertEqual(len(broken.calls), 1)  # Cooling: tried after the healthy server only.
        cooling = [r for r in self.call("/api/admin/control", session=self.admin)[1]["routing"] if r["cooling"]]
        self.assertEqual(len(cooling), 1)
        broken.broken = False
        calls = sum(len(s.calls) for s in servers.values())
        status, body, _ = self.call("/v1/chat/completions", self.completion("test/one", content="refuse"), key=key)
        self.assertEqual(status, 400, body)
        self.assertEqual(sum(len(s.calls) for s in servers.values()), calls + 1)
        for server in servers.values():
            server.broken = True
        status, body, _ = self.call("/v1/chat/completions", self.completion("test/one"), key=key)
        self.assertEqual(status, 502, body)
        self.assertNotIn(UPSTREAM_KEY, json.dumps(body))

    def test_router_keeps_a_conversation_unless_its_replica_is_full_and_another_has_room(self):
        router = routing.Router()
        now = time.time()
        replicas = [{"id": name, "upstream": "m", "endpoint": name, "source": name, "url": "", "secret": "", "state": "ready", "checked": now}
                    for name in ("a", "b", "c")]
        first = router.order(replicas, "conversation")
        self.assertEqual(len(first), 3)
        self.assertFalse(first[0]["same"])
        router.remember("conversation", first[0], first[0]["same"])
        again = router.order(replicas, "conversation")
        self.assertEqual(again[0]["id"], first[0]["id"])
        self.assertTrue(again[0]["same"])
        router.report_slots(first[0]["id"], 1)
        router.begin(first[0]["id"])
        moved = router.order(replicas, "conversation")
        self.assertNotEqual(moved[0]["id"], first[0]["id"])
        for replica in replicas:
            router.report_slots(replica["id"], 1)
            if replica["id"] != first[0]["id"]:
                router.begin(replica["id"])
        self.assertEqual(router.order(replicas, "conversation")[0]["id"], first[0]["id"])  # All full: stay warm.
        router.end(first[0]["id"], failed=True)
        self.assertNotEqual(router.order(replicas, "conversation")[0]["id"], first[0]["id"])  # Failed: cooling.
        stale = [dict(r, checked=now - 120) for r in replicas]
        self.assertEqual(router.order(stale, "conversation"), [])
        self.assertEqual(routing.cached_tokens({"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": 12}}), 10)
        self.assertEqual(routing.cached_tokens({"prompt_tokens": 10}, {"cache_n": 4}), 4)
        self.assertIsNone(routing.cached_tokens({"prompt_tokens": 10}))
        self.assertIsNone(routing.cached_tokens({"prompt_tokens": 10, "prompt_tokens_details": {"cached_tokens": -1}}))

    def test_cached_input_is_billed_at_its_own_price_and_reported_in_every_protocol(self):
        self.connect(self.model_url, "Server")
        self.model.cached = 2  # Of 3 prompt tokens.
        member = self.member()
        key = self.key(session=member)["key"]
        self.assertEqual(self.call("/api/admin/prices", {"model": "test/one", "input_usd": "1", "output_usd": "2", "cached_usd": "1.5"}, self.admin)[0], 400)
        self.assertEqual(self.call("/api/admin/prices", {"model": "test/one", "input_usd": "1", "output_usd": "2", "cached_usd": "0.1"}, self.admin)[0], 200)
        price = next(m for m in self.call("/api/models")[1]["models"] if m["id"] == "test/one")["price"]
        self.assertEqual(price, {"input_microusd_per_million": 1000000, "output_microusd_per_million": 2000000, "cached_microusd_per_million": 100000})
        self.credit(member, 1000000)  # $1: the reservation covers the request's largest possible size.
        for stream in (False, True):
            status, body, _ = self.call("/v1/chat/completions", self.completion("test/one", stream), key=key)
            self.assertEqual(status, 200, body)
            self.assertIn("cached_tokens", json.dumps(body) if not stream else body)
        usage = self.call("/api/usage", session=member)[1]["requests"]
        # 1 uncached input token at $1/M, 2 cached at $0.10/M, 2 output at $2/M: 5.2 microdollars, rounded up.
        self.assertEqual([(r["cached_tokens"], r["cost_microusd"], r["billing_state"]) for r in usage], [(2, 6, "charged"), (2, 6, "charged")])
        # Without a cached price, cached tokens cost the input price.
        self.assertEqual(self.call("/api/admin/prices", {"model": "test/one", "input_usd": "1", "output_usd": "2"}, self.admin)[0], 200)
        self.call("/v1/chat/completions", self.completion("test/one"), key=key)
        self.assertEqual(sorted(r["cost_microusd"] for r in self.call("/api/usage", session=member)[1]["requests"]), [6, 6, 7])
        # llama.cpp reports its cache in timings; Messages and Responses report it in their own fields.
        self.model.cached, self.model.cache_n = None, 1
        status, message, _ = self.call("/v1/messages", {"model": "test/one", "max_tokens": 16, "messages": [{"role": "user", "content": "hi"}]}, key=key)
        self.assertEqual(status, 200, message)
        self.assertEqual(message["usage"], {"input_tokens": 2, "cache_read_input_tokens": 1, "cache_creation_input_tokens": 0, "output_tokens": 2})
        status, response, _ = self.call("/v1/responses", {"model": "test/one", "input": "hi"}, key=key)
        self.assertEqual(status, 200, response)
        self.assertEqual(response["usage"]["input_tokens_details"], {"cached_tokens": 1})
        status, gemini, _ = self.call("/v1beta/models/test%2Fone:generateContent", {"contents": [{"role": "user", "parts": [{"text": "hi"}]}]}, key=key)
        self.assertEqual(status, 200, gemini)
        self.assertEqual(gemini["usageMetadata"]["cachedContentTokenCount"], 1)
        # Five completed requests with cache reports publish the model's hit rate: (2+2+2+1+1+1)/(6*3).
        stats = next(m for m in self.call("/api/models")[1]["models"] if m["id"] == "test/one")["cache"]
        self.assertEqual(stats, {"hit_rate": round(9 / 18, 4), "requests": 6})
        control = self.call("/api/admin/control", session=self.admin)[1]["models"][0]
        self.assertEqual((control["cached_tokens"], control["cache_input"]), (9, 18))

    def test_connector_stream_delivers_requests_at_once_and_a_silent_computer_fails_over(self):
        token = self.pair_node()
        models = [{"id": "env-one", "name": "test/one", "state": "ready", "shared": True, "slots": 2}]
        self.assertEqual(self.agent(token, "inventory", models=models)[0], 200)
        replica = next(m["id"] for m in self.service.store.models() if m["id"] == "test/one")
        self.assertEqual(replica, "test/one")
        self.assertEqual(sorted(self.service.router.slots.values()), [2])
        adapter = Adapter("unused", Path(self.temp.name) / "node")
        adapter.shared = {"env-one"}
        adapter.apis = {"env-one": {"apiUrl": self.model_url, "apiKey": UPSTREAM_KEY, "model": "test/one"}}
        link = compute_node.Link(self.url)
        stopped, delivered, silent = threading.Event(), [], threading.Event()

        def deliver(task):
            delivered.append(task["id"])
            if silent.is_set():
                return  # A connection that dropped without closing: nothing is acknowledged.
            def serve():
                link.post("/api/compute/agent", {"action": "ack", "id": task["id"]}, token)
                adapter.inference(task, lambda part: link.post("/api/compute/agent", {"action": "chunk", **part}, token))
            threading.Thread(target=serve, daemon=True).start()

        listener = threading.Thread(target=compute_node.receive, args=(link, token, deliver, stopped), daemon=True)
        listener.start()
        for _ in range(200):
            if self.service.compute.generations:
                break
            time.sleep(.01)
        # A stream holds none of the website's 64 request slots.
        self.assertEqual(self.web.slots._value, 64)
        key = self.key()["key"]
        for stream in (True, False, True):
            started = time.monotonic()
            status, body, _ = self.call("/v1/chat/completions", self.completion("test/one", stream), key=key)
            self.assertEqual(status, 200, body)
            self.assertIn("hello", str(body))
            self.assertLess(time.monotonic() - started, 5)
        self.assertEqual(len(delivered), 3)
        self.assertFalse(self.service.compute.requests)
        # A silent computer: its request fails over to a model server that answers. The server is
        # made to look busy so that the first request goes to the computer.
        server = self.connect(self.model_url, "Website server") + ":test/one"
        self.service.router.report_slots(server, 1)
        self.service.router.begin(server)
        silent.set()
        with patch.object(compute, "ACK_SECONDS", .5):
            served = 0
            for index in range(6):
                status, body, _ = self.call("/v1/chat/completions", self.completion("test/one", content=f"Opening {index}"), key=key)
                self.assertEqual(status, 200, body)
                served += 1
        self.assertEqual(served, 6)
        self.assertEqual(len(delivered), 4)  # Once: the computer is then cooling and tried last.
        # Disconnecting the computer ends its stream at once.
        host = self.service.compute.host(token)
        self.assertEqual(self.call("/api/admin/compute/disconnect", {"id": host["id"]}, self.admin)[0], 200)
        listener.join(5)
        self.assertFalse(listener.is_alive())
        stopped.set()

    def test_a_computer_at_capacity_takes_its_next_request_as_soon_as_one_finishes(self):
        from concurrent.futures import ThreadPoolExecutor
        token = self.pair_node()
        self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}])
        adapter = Adapter("unused", Path(self.temp.name) / "node")
        adapter.shared = {"env-one"}
        adapter.apis = {"env-one": {"apiUrl": self.model_url, "apiKey": UPSTREAM_KEY, "model": "test/one"}}
        link, stopped, active, peak = compute_node.Link(self.url), threading.Event(), [0], [0]
        lock = threading.Lock()

        def deliver(task):
            def serve():
                with lock:
                    active[0] += 1
                    peak[0] = max(peak[0], active[0])
                link.post("/api/compute/agent", {"action": "ack", "id": task["id"]}, token)
                time.sleep(.3)  # A request in progress while the next one waits.
                with lock:
                    active[0] -= 1
                adapter.inference(task, lambda part: link.post("/api/compute/agent", {"action": "chunk", **part}, token))
            threading.Thread(target=serve, daemon=True).start()

        with patch.object(compute_node, "CAPACITY", 1):
            listener = threading.Thread(target=compute_node.receive, args=(link, token, deliver, stopped), daemon=True)
            listener.start()
            for _ in range(200):
                if self.service.compute.generations:
                    break
                time.sleep(.01)
        key = self.key()["key"]
        started = time.monotonic()
        with ThreadPoolExecutor(2) as pool:
            results = list(pool.map(lambda index: self.call("/v1/chat/completions", self.completion("test/one", content=f"Opening {index}"), key=key)[0], range(2)))
        self.assertEqual(results, [200, 200])
        self.assertEqual(peak[0], 1)  # Never more than the computer's capacity at once.
        self.assertLess(time.monotonic() - started, compute.HEARTBEAT_SECONDS)  # Not held until the next heartbeat.
        host = self.service.compute.host(token)
        self.call("/api/admin/compute/disconnect", {"id": host["id"]}, self.admin)
        listener.join(5)
        stopped.set()

    def test_stream_claims_respect_capacity_a_newer_stream_replaces_the_older_and_old_connectors_still_poll(self):
        token = self.pair_node()
        self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}])
        host = self.service.compute.host(token)
        work = self.service.compute
        for index in range(3):
            work.requests["r" + str(index)] = {"host": host["id"], "environment": "env-one", "payload": {}, "response": compute.Response(),
                                               "claimed": False, "via": None, "claimed_at": None, "acked": False}
        with work.lock:
            self.assertEqual(len(work.claim(host["id"], "stream", 8, 2)), 2)
            self.assertEqual(work.claim(host["id"], "stream", 8, 2), [])
        self.assertTrue(work.ack(host, {"id": "r0"}))
        work.unclaim(["r0", "r1"])  # Only the unacknowledged one returns to the queue.
        self.assertEqual(self.agent(token, "poll")[1]["inference"]["id"], "r1")
        self.assertTrue(work.requests["r0"]["claimed"])
        work.requests.clear()
        self.assertEqual(self.agent(token, "stream", capacity=0)[0], 400)
        link = compute_node.Link(self.url)
        stopped = threading.Event()
        results = []
        older = threading.Thread(target=lambda: results.append(compute_node.receive(link, token, lambda task: None, stopped)), daemon=True)
        older.start()
        for _ in range(200):
            if work.generations.get(host["id"]) == 1:
                break
            time.sleep(.01)
        newer = threading.Thread(target=lambda: results.append(compute_node.receive(link, token, lambda task: None, stopped)), daemon=True)
        newer.start()
        older.join(5)
        self.assertEqual(results, [True])  # The older stream ended cleanly when the newer one began.
        work.revoke("test", host["id"])
        newer.join(5)
        self.assertEqual(results, [True, True])
        stopped.set()


def load_tests(loader, tests, pattern):
    # Only this file's tests; the inherited service tests run in test_service.py.
    return unittest.TestSuite(RoutingFlow(name) for name in loader.getTestCaseNames(RoutingFlow) if name in RoutingFlow.__dict__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
