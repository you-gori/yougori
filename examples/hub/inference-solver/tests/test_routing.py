"""One model name over several replicas, cached-input billing and the connector stream, through
real website HTTP, SQLite and disposable model servers. No GPU.

Run: python -I -B examples/hub/inference-solver/tests/test_routing.py
"""
import base64
import copy
import functools
import hashlib
from http.server import ThreadingHTTPServer
import importlib.util
import io
import json
import os
from pathlib import Path
import secrets
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow, Model, UPSTREAM_KEY
import compute
import compute_node
import gateway
import routing
from compute_adapter import Adapter


@functools.lru_cache(maxsize=None)
def yougori_model_server():
    """Yougori's model server (src-tauri/src/model_server.py) as a module, for its own request checks.
    It reads its model and key when loaded; nothing of it starts."""
    with patch.dict(os.environ, {"YOUGORI_MODEL": "test/one", "YOUGORI_MODEL_TOKEN": "t" * 64}):
        spec = importlib.util.spec_from_file_location("yougori_model_server", Path(__file__).resolve().parents[4] / "src-tauri/src/model_server.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    return module


class YougoriModel(Model):
    """A model server that refuses what Yougori's refuses, with its words and codes: the body limit its
    handler checks, then validate_chat. What it takes, it answers as the fixture model does."""

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + UPSTREAM_KEY:
            return self.reply(401, {"error": UPSTREAM_KEY})
        checks, raw = self.server.checks, self.rfile.read(int(self.headers["Content-Length"]))
        try:
            if len(raw) > (524288 if checks.agent_limits() else 65536):
                raise checks.RequestLimit("Send a JSON body of at most " + ("512" if checks.agent_limits() else "64") + " KiB with Content-Length")
            checks.validate_chat(copy.deepcopy(json.loads(raw)))
        except (checks.RequestLimit, checks.ContextRefusal) as error:
            refusal = error.body()
        except (ValueError, TypeError):
            refusal = {"error": {"message": "Invalid model request. Check message roles, content, context length and generation settings."}}
        else:
            # Taken: answered (and recorded) as the fixture model does.
            self.rfile = io.BytesIO(raw)
            return super().do_POST()
        with self.server.lock:
            self.server.calls.append(json.loads(raw))
        return self.reply(400, refusal)


class EchoingModel(Model):
    """A model server that refuses every chat and writes the key it was sent into its words."""

    def do_POST(self):
        self.rfile.read(int(self.headers["Content-Length"]))
        return self.reply(400, {"error": {"message": "This key may not chat: " + self.headers.get("Authorization", "")}})


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
        # A contributing computer serves only the models the administrator lists for computers.
        self.assertEqual(self.call("/api/admin/compute/models", {"models": ["test/one"]}, self.admin)[0], 200)
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

    def test_v1_models_gives_the_smallest_context_its_ready_servers_report(self):
        """/v1/models gives each model the context its ready servers report, the smallest where
        they differ, so a harness sizes its conversation to fit whichever serves it: from a model
        server's own catalog (vLLM's max_model_len, another inference's context_length) and from a
        connected computer's inventory. A server that is not ready does not count; a model none of
        whose ready servers says, or says something unbelievable, has no context_length."""
        self.model.entries = {"test/one": {"max_model_len": 65536}, "test/two": {"context_length": 100}}
        self.connect(self.model_url, "First server")
        url, second_server = self.model_server()
        second_server.entries = {"test/one": {"context_length": 16384}}
        second = self.connect(url, "Second server")
        key = self.key()["key"]

        def listed():
            return {m["id"]: m.get("context_length", "unsaid") for m in self.call("/v1/models", key=key)[1]["data"]}
        self.assertEqual(listed(), {"test/one": 16384, "test/two": "unsaid"})
        self.assertEqual({m["id"]: m.get("context_length") for m in self.call("/api/models", session=self.admin)[1]["models"]}, {"test/one": 16384, "test/two": None})
        second_server.fail_catalog = True
        self.service.refresh()
        with self.service.store.db() as db:
            self.assertEqual(db.execute("SELECT state FROM endpoints WHERE id=?", (second,)).fetchone()[0], "unavailable")
        self.assertEqual(listed(), {"test/one": 65536, "test/two": "unsaid"})
        # A server that stops saying, at its next refresh, no longer counts.
        self.model.entries = {}
        self.service.refresh()
        self.assertEqual(listed(), {"test/one": "unsaid", "test/two": "unsaid"})
        # A connected computer says what its model server serves.
        token = self.pair_node()
        computer = {"id": "env-one", "name": "test/one", "state": "ready", "shared": True}
        self.assertEqual(self.agent(token, "inventory", models=[{**computer, "context": 8192}])[0], 200)
        self.assertEqual(listed()["test/one"], 8192)
        for unbelievable in (255, 1048577, 8192.0, True, "8192", None):
            with self.subTest(context=unbelievable):
                self.assertEqual(self.agent(token, "inventory", models=[{**computer, "context": unbelievable}])[0], 200)
                self.assertEqual(listed()["test/one"], "unsaid")
        # Still loading: not counted until it is ready.
        self.assertEqual(self.agent(token, "inventory", models=[{**computer, "state": "loading", "context": 4096}])[0], 200)
        self.assertEqual(listed()["test/one"], "unsaid")

    def test_json_output_goes_only_to_replicas_whose_server_enforces_it(self):
        """A request with OpenAI's response_format is served by a replica whose server enforces
        it (Yougori's model server says so in its catalog), never by one that said it does not,
        and still by one that did not say; the format travels as given, including through the
        Responses adapter's text.format; the catalog shows the model as JSON-capable while any
        replica enforces it, and a model with no such replica refuses the request."""
        self.model.json = {"test/one": True}
        servers = self.two_replicas()
        first, second = list(servers)
        servers[second].json = {"test/one": False}
        self.service.refresh()
        key = self.key(["test/one"])["key"]
        schema = {"type": "json_schema", "json_schema": {"name": "answer", "schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}}, "strict": True}}
        for index in range(6):
            status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": [{"role": "user", "content": f"json {index}"}], "response_format": schema},
                                        key=key, headers={"X-Session-ID": f"json-{index}"})
            self.assertEqual(status, 200, body)
        self.assertEqual(self.served(servers), {first: 6, second: 0})
        self.assertEqual(servers[first].calls[-1]["response_format"], schema)
        # Plain requests may go to either replica as before.
        for index in range(4):
            self.turn(key, [], f"plain {index}", headers={"X-Session-ID": f"plain-{index}"})
        self.assertEqual(sum(self.served(servers).values()), 10)
        catalog = {m["id"]: m for m in self.call("/api/models")[1]["models"]}
        self.assertEqual(catalog["test/one"]["features"], {"json": True})
        # The Responses API names the format text.format; it reaches the server as response_format.
        status, body, _ = self.call("/v1/responses", {"model": "test/one", "input": "json please", "text": {"format": {"type": "json_schema", "name": "answer", "schema": schema["json_schema"]["schema"], "strict": True}}}, key=key)
        self.assertEqual(status, 200, body)
        self.assertEqual(servers[first].calls[-1]["response_format"], schema)
        # Once no replica enforces it, the catalog says so and such requests are refused, not served as text.
        self.model.json = {"test/one": False}
        self.service.refresh()
        self.assertEqual({m["id"]: m["features"] for m in self.call("/api/models")[1]["models"]}["test/one"], {"json": False})
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": [{"role": "user", "content": "json"}], "response_format": {"type": "json_object"}}, key=key)
        self.assertEqual(status, 400)
        self.assertIn("JSON output", body["error"]["message"])
        self.assertEqual(self.turn(key, [], "still text")["choices"][0]["message"]["content"], "hello")
        # A server that lists no capabilities (a plain vLLM or llama.cpp connected by address) is not refused.
        url, third = self.model_server(("test/three",))
        self.connect(url, "Third server")
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/three", "messages": [{"role": "user", "content": "json"}], "response_format": {"type": "json_object"}}, key=self.key(["test/three"])["key"])
        self.assertEqual(status, 200, body)
        self.assertEqual(third.calls[-1]["response_format"], {"type": "json_object"})
        self.assertEqual({m["id"]: m["features"] for m in self.call("/api/models")[1]["models"]}["test/three"], {"json": None})

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

    def test_a_failing_server_is_skipped_before_anything_is_sent_and_a_refusal_is_tried_on_the_other_replica(self):
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
        # A refusal (a prompt longer than one replica's context) is tried on the other replica, which
        # may have a longer context; it is the caller's answer when both refuse, in the server's own
        # words, and neither cools.
        status, body, _ = self.call("/v1/chat/completions", self.completion("test/one", content="refuse"), key=key)
        self.assertEqual((status, body["error"]["message"]), (400, "The prompt is longer than the context."))
        self.assertEqual(sum(len(s.calls) for s in servers.values()), calls + 2)
        self.assertEqual(sum(r["failed"] for r in self.call("/api/admin/control", session=self.admin)[1]["routing"]), 1)  # The earlier failure only.
        for server in servers.values():
            server.broken = True
        status, body, _ = self.call("/v1/chat/completions", self.completion("test/one"), key=key)
        self.assertEqual(status, 502, body)
        self.assertNotIn(UPSTREAM_KEY, json.dumps(body))

    def test_a_model_that_calls_no_tools_still_answers_every_harness_in_text(self):
        self.connect(self.model_url, "Model server")
        self.model.plain = True
        key = self.key()["key"]
        schema = {"type": "object", "properties": {}}
        # A coding agent's next turn: its tools, two calls it made, their results, a long reply limit.
        conversation = [{"role": "system", "content": "You are a coding agent."}, {"role": "user", "content": "Open the notes"},
                        {"role": "assistant", "content": None, "tool_calls": [
                            {"id": "call_1", "type": "function", "function": {"name": "read", "arguments": '{"path": "notes.txt"}'}},
                            {"id": "call_2", "type": "function", "function": {"name": "read", "arguments": '{"path": "todo.txt"}'}}]},
                        {"role": "tool", "tool_call_id": "call_1", "content": "Buy milk"},
                        {"role": "tool", "tool_call_id": "call_2", "content": [{"type": "text", "text": "Ship it"}]}]
        before = len(self.model.calls)
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": conversation, "max_tokens": 32000, "tool_choice": "auto",
                                                             "tools": [{"type": "function", "function": {"name": "read", "description": "Read a file", "parameters": schema}}]}, key=key)
        self.assertEqual(status, 200, body)
        self.assertIn("hello", json.dumps(body))
        # Refused as sent, then with the reply limit the relay takes and the tools kept, then as plain chat.
        asked, refused, sent = self.model.calls[before:]
        self.assertEqual([("tools" in call, call["max_tokens"]) for call in (asked, refused, sent)], [(True, 32000), (True, 4096), (False, 4096)])
        self.assertFalse({"tools", "tool_choice", "truncate"} & set(sent))  # truncate only for Yougori's own model servers
        # The model is told that no tool is available and that nothing it writes runs, after the agent's own instructions.
        self.assertEqual(sent["messages"], [
            {"role": "system", "content": "You are a coding agent.\n\n" + gateway.NO_TOOLS}, {"role": "user", "content": "Open the notes"},
            {"role": "assistant", "content": 'Called read with {"path": "notes.txt"}\n\nCalled read with {"path": "todo.txt"}'},
            {"role": "user", "content": "Result of read:\nBuy milk\n\nResult of read:\nShip it"}])
        self.assertIn("Nothing you write runs.", gateway.NO_TOOLS)
        # The other harnesses' protocols: Messages (Claude Code, a reply limit of 32,000 first capped), Responses (Codex), Gemini.
        for path, data, tries in [
                ("/v1/messages", {"model": "test/one", "max_tokens": 32000, "messages": [{"role": "user", "content": "hi"}],
                                  "tools": [{"name": "Read", "description": "Read a file", "input_schema": schema}]}, 3),
                ("/v1/responses", {"model": "test/one", "input": "hi", "tools": [{"type": "function", "name": "shell", "description": "Run", "parameters": schema}]}, 2),
                ("/v1beta/models/test%2Fone:generateContent", {"contents": [{"role": "user", "parts": [{"text": "hi"}]}],
                                                              "tools": [{"functionDeclarations": [{"name": "read", "description": "Read", "parameters": schema}]}]}, 2)]:
            before = len(self.model.calls)
            status, body, _ = self.call(path, data, key=key)
            self.assertEqual(status, 200, (path, body))
            self.assertEqual(len(self.model.calls), before + tries, path)
            self.assertIn("tools", self.model.calls[-2])
            self.assertNotIn("tools", self.model.calls[-1])
            self.assertEqual(self.model.calls[-1]["messages"][0], {"role": "system", "content": gateway.NO_TOOLS}, path)

    def test_a_computer_takes_plain_chat_with_old_turns_dropped_but_a_too_long_conversation_is_not_sent_again(self):
        class Computer:
            def __init__(self, refusal):
                self.bodies, self.refusal = [], refusal

            def connect(self, url, body):
                self.bodies.append(body)
                if self.refusal:
                    refusal, self.refusal = self.refusal, None
                    raise refusal
                return "connection", "response"

        replica = {"id": "computer", "upstream": "test/one", "url": "compute://host/env", "secret": "", "same": False}
        payload = {"model": "test/one", "messages": [{"role": "user", "content": "hi"}],
                   "tools": [{"type": "function", "function": {"name": "read", "parameters": {"type": "object"}}}]}
        computer = Computer(compute.UpstreamError("The model server refused this request.", 400))
        self.assertEqual(gateway.dispatch(SimpleNamespace(router=routing.Router(), compute=computer), [replica], payload, "chat")[2], replica)
        self.assertEqual([("tools" in body, body.get("truncate")) for body in computer.bodies], [(True, None), (False, True)])
        computer = Computer(compute.UpstreamError("Conversation exceeds this model's 8704-token context window", 400, "yougori_context_window"))
        with self.assertRaises(compute.UpstreamError) as refused:
            gateway.dispatch(SimpleNamespace(router=routing.Router(), compute=computer), [replica], payload, "chat")
        self.assertIn("8704-token", str(refused.exception))
        self.assertEqual(len(computer.bodies), 1)
        # A refusal of the tools' size is not answered by sending the request without them.
        computer = Computer(compute.UpstreamError("Tool definitions exceed 48 KiB", 400, "yougori_request_limit"))
        with self.assertRaises(compute.UpstreamError) as refused:
            gateway.dispatch(SimpleNamespace(router=routing.Router(), compute=computer), [replica], payload, "chat")
        self.assertEqual(str(refused.exception), "Tool definitions exceed 48 KiB. This request sent 1 tool definition "
                                                 f"({len(json.dumps(payload['tools']))} bytes) and 1 message. Nothing reached the model.")
        self.assertEqual(refused.exception.code, "yougori_request_limit")
        self.assertEqual(len(computer.bodies), 1)

    def yougori_server(self, form="gguf"):
        """A model server that checks requests as Yougori's does (model_server.validate_chat, its own
        code), its runner `form` (gguf calls tools; safetensors, the Transformers runner, calls none)."""
        model_server = yougori_model_server()
        patcher = patch.object(model_server, "FORMAT", form)
        patcher.start()
        self.addCleanup(patcher.stop)
        url, server = self.model_server()
        server.RequestHandlerClass = YougoriModel
        server.checks = model_server
        return url, server

    def test_a_request_over_a_yougori_model_servers_tool_limits_reaches_the_harness_as_that_refusal(self):
        url, server = self.yougori_server()
        self.connect(url, "Model server")
        key = self.key()["key"]
        # 150 tools as HexStrike sent, then 33, then 30 whose definitions exceed 48 KiB, then 32 in a body over
        # 64 KiB: refused once each, never sent again without the tools, and the harness is told what was too large.
        for count, size, words in ((150, 30, "Agent tools require the GGUF or vLLM runner and 1 to 32 function definitions"),
                                   (33, 100, "1 to 32 function definitions"), (30, 1700, "Tool definitions exceed 48 KiB"),
                                   (32, 2100, "Send a JSON body of at most 64 KiB")):
            tools = [{"type": "function", "function": {"name": f"tool_{n}", "description": "d" * size, "parameters": {"type": "object"}}}
                     for n in range(count)]
            before = len(server.calls)
            status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "tools": tools,
                                                                 "messages": [{"role": "user", "content": "Test the app"}]}, key=key)
            with self.subTest(count=count):
                self.assertEqual(status, 400, body)
                self.assertEqual(len(server.calls), before + 1)
                message = body["error"]["message"]
                self.assertIn(words, message)
                self.assertIn(f"This request sent {count} tool definitions ({len(json.dumps(tools)):,} bytes) and 1 message. "
                              "Nothing reached the model.", message)
        # Within the limits the tools reach the model.
        tools = [{"type": "function", "function": {"name": f"tool_{n}", "description": "d" * 1000, "parameters": {"type": "object"}}} for n in range(30)]
        self.assertLessEqual(len(json.dumps(tools)), 48 * 1024)
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "tools": tools, "messages": [{"role": "user", "content": "Test"}]}, key=key)
        self.assertEqual(status, 200, body)
        self.assertEqual(len(server.calls[-1]["tools"]), 30)

    def test_an_output_budget_over_the_relays_limit_is_capped_and_the_tools_stay(self):
        url, server = self.yougori_server()
        self.connect(url, "Model server")
        key = self.key()["key"]
        tools = [{"type": "function", "function": {"name": "read", "description": "Read a file", "parameters": {"type": "object"}}}]
        # DeepSeek asks 32,768 as max_completion_tokens; Claude Code 32,000 as max_tokens through Messages.
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "tools": tools, "max_completion_tokens": 32768,
                                                             "messages": [{"role": "user", "content": "Read it"}]}, key=key)
        self.assertEqual(status, 200, body)
        self.assertEqual([(len(call["tools"]), call["max_completion_tokens"]) for call in server.calls], [(1, 32768), (1, 4096)])
        before = len(server.calls)
        status, body, _ = self.call("/v1/messages", {"model": "test/one", "max_tokens": 32000, "messages": [{"role": "user", "content": "hi"}],
                                                     "tools": [{"name": "Read", "description": "Read a file", "input_schema": {"type": "object"}}]}, key=key)
        self.assertEqual(status, 200, body)
        self.assertEqual([(len(call["tools"]), call["max_tokens"]) for call in server.calls[before:]], [(1, 32000), (1, 4096)])
        # A conversation over the server's own limit reaches the harness in the server's words, sent once.
        before = len(server.calls)
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": [{"role": "user", "content": "x" * 40000}]}, key=key)
        self.assertEqual((status, body["error"]["message"]), (400, "Conversation exceeds 32,768 characters; start a new chat"))
        self.assertEqual(len(server.calls), before + 1)

    def test_a_model_whose_runner_calls_no_tools_answers_in_text_and_is_told_that_nothing_runs(self):
        url, server = self.yougori_server("safetensors")
        self.connect(url, "Model server")
        key = self.key()["key"]
        tools = [{"type": "function", "function": {"name": "nmap_scan", "description": "Scan", "parameters": {"type": "object"}}}]
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "tools": tools, "messages": [
            {"role": "system", "content": "Use the available tools."}, {"role": "user", "content": "Scan the app"}]}, key=key)
        self.assertEqual(status, 200, body)
        refused, sent = server.calls
        self.assertIn("tools", refused)
        self.assertNotIn("tools", sent)
        self.assertEqual(sent["messages"][0], {"role": "system", "content": "Use the available tools.\n\n" + gateway.NO_TOOLS})
        # A request refused as plain chat too is the caller's answer after one more try, and one with
        # nothing to drop is not sent again.
        for extra, tries in (({"tools": tools}, 2), ({}, 1)):
            before = len(server.calls)
            status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": [{"role": "user", "content": "x" * 40000}], **extra}, key=key)
            self.assertEqual((status, body["error"]["message"]), (400, "Conversation exceeds 32,768 characters; start a new chat"))
            self.assertEqual(len(server.calls), before + tries)

    def test_a_refusal_without_a_yougori_code_goes_once_more_as_plain_chat_even_to_a_server_that_calls_tools(self):
        """dispatch(): plain chat follows every refusal but a size or context refusal. A refusal
        without a Yougori code can come from a server that does call tools: the request still goes
        once more as plain chat, and the model is told that no tools are available and that nothing
        it writes runs."""
        url, server = self.yougori_server()
        self.connect(url, "Model server")
        key = self.key()["key"]
        tools = [{"type": "function", "function": {"name": "read", "description": "Read a file", "parameters": {"type": "object"}}}]
        # A tool result that answers no call: Yougori's server refuses it in its generic words, without a code.
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "tools": tools, "messages": [
            {"role": "user", "content": "Read it"}, {"role": "tool", "tool_call_id": "call_9", "content": "Buy milk"}]}, key=key)
        self.assertEqual(status, 200, body)
        refused, sent = server.calls
        self.assertIn("tools", refused)
        self.assertNotIn("tools", sent)
        self.assertEqual(sent["messages"], [{"role": "system", "content": gateway.NO_TOOLS},
                                            {"role": "user", "content": "Read it\n\nResult of a tool:\nBuy milk"}])

    def test_a_chat_without_a_user_message_goes_with_its_instructions_as_the_users(self):
        """Plandex names each plan with a system message alone. Yougori's model server refuses a chat
        without a user message, and the relay put its own words over the server's: every Plandex
        prompt failed with "Check its context length and parameters"."""
        url, server = self.yougori_server()
        self.connect(url, "Model server")
        key = self.key()["key"]
        text = "You name plans. Reply with three words."
        for messages, sent in (
                # As Plandex sends it: one system message in parts.
                ([{"role": "system", "content": [{"type": "text", "text": text}]}], [{"role": "user", "content": [{"type": "text", "text": text}]}]),
                ([{"role": "system", "content": text}, {"role": "developer", "content": "Use English."}],
                 [{"role": "user", "content": text + "\n\nUse English."}])):
            with self.subTest(messages=messages):
                status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": messages, "max_tokens": 16}, key=key)
                self.assertEqual(status, 200, body)
                self.assertEqual(server.calls[-1]["messages"], sent)
        # Through the Responses API too: instructions with no input.
        status, body, _ = self.call("/v1/responses", {"model": "test/one", "instructions": text, "input": []}, key=key)
        self.assertEqual(status, 200, body)
        self.assertEqual(server.calls[-1]["messages"], [{"role": "user", "content": text}])
        # A chat with a user message goes as it is.
        conversation = [{"role": "system", "content": text}, {"role": "user", "content": "Add sign-in"}]
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": conversation}, key=key)
        self.assertEqual(status, 200, body)
        self.assertEqual(server.calls[-1]["messages"], conversation)
        # A chat the server still refuses reaches the caller in the server's own words, sent once.
        before = len(server.calls)
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/one", "messages": [{"role": "assistant", "content": "Hello"}]}, key=key)
        self.assertEqual((status, body["error"]["message"]), (400, "Invalid model request. Check message roles, content, context length and generation settings."))
        self.assertEqual(len(server.calls), before + 1)

    def test_a_refusal_reaches_the_caller_in_the_model_servers_own_words(self):
        """refusal(): the server's error message on one line of printable ASCII, at most 300
        characters, with its code when that is a lower-case name; the relay's own words only when
        it gave none."""
        class Response:
            def __init__(self, raw):
                self.raw, self.closed = raw, False

            def read(self, limit):
                return self.raw[:limit]

            def close(self):
                self.closed = True

        for raw, words, code in (
                (b'{"error": {"code": "yougori_request_limit", "message": "Tool definitions exceed 48 KiB"}}', "Tool definitions exceed 48 KiB", "yougori_request_limit"),
                (b'{"error": {"code": "yougori_context_window", "message": "Conversation exceeds\\u00e9 the\\n window\\u001b[2J"}}',
                 "Conversation exceeds the window[2J", "yougori_context_window"),
                # Yougori's own words for a request it does not take, which name no code.
                (b'{"error": {"message": "Invalid model request. Check message roles, content, context length and generation settings."}}',
                 "Invalid model request. Check message roles, content, context length and generation settings.", ""),
                # Other servers: llama.cpp, OpenAI, older vLLM (the message at the top) and a bare error.
                (b'{"error": {"code": 400, "message": "the request exceeds the available context size, try increasing it", "type": "exceed_context_size_error"}}',
                 "the request exceeds the available context size, try increasing it", ""),
                (b'{"error": {"code": "context_length_exceeded", "message": "This model\'s maximum context length is 8192 tokens."}}',
                 "This model's maximum context length is 8192 tokens.", "context_length_exceeded"),
                (b'{"object": "error", "message": "max_tokens must be at most 2048", "code": 400}', "max_tokens must be at most 2048", ""),
                (b'{"error": "tools are not supported by this model"}', "tools are not supported by this model", ""),
                (b'{"error": {"code": "Not A Code", "message": "' + b"w" * 400 + b'"}}', "w" * 300, ""),
                (b'{"error": {"message": " \\u00e9 "}}', gateway.REFUSED, ""),
                (b'{"error": {}}', gateway.REFUSED, ""),
                (b"[]", gateway.REFUSED, ""),
                (b"not json", gateway.REFUSED, "")):
            response, connection = Response(raw), Response(b"")
            error = gateway.refusal(connection, response)
            with self.subTest(raw=raw):
                self.assertEqual((str(error), error.status, error.code), (words, 400, code))
                self.assertTrue(response.closed and connection.closed)
        # A server that echoes its own key never passes it on, not even in part at the cut.
        for message, words in (("Key " + UPSTREAM_KEY + " may not use tools", "Key [hidden] may not use tools"),
                               ("w" * 290 + UPSTREAM_KEY, "w" * 290 + "[hidden]")):
            error = gateway.refusal(Response(b""), Response(json.dumps({"error": {"message": message}}).encode()), UPSTREAM_KEY)
            self.assertEqual(str(error), words)
        url, server = self.model_server()
        server.RequestHandlerClass = EchoingModel
        self.connect(url, "Model server")
        status, body, _ = self.call("/v1/chat/completions", self.completion("test/one"), key=self.key()["key"])
        self.assertEqual((status, body["error"]["message"]), (400, "This key may not chat: Bearer [hidden]"))
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
        # A connector's capacity is across its models: with one request in flight on one of its two
        # shared models, both of its replicas are full, and another computer's replica goes first.
        grouped = routing.Router()
        grouped.report_group("a", "pc", 1)
        grouped.report_group("b", "pc", 1)
        grouped.begin("a")
        self.assertEqual(grouped.order(replicas, "fresh")[0]["id"], "c")
        grouped.begin("c")
        grouped.report_slots("c", 1)
        self.assertEqual(grouped.order(replicas, "fresh")[0]["id"], "c")  # All full: the least loaded share.
        grouped.end("a")
        self.assertIn(grouped.order(replicas, "fresh")[0]["id"], ("a", "b"))
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
                                               "path": "/chat/completions", "method": "POST",
                                               "claimed": False, "via": None, "claimed_at": None, "acked": False}
        with work.lock:
            self.assertEqual(len(work.claim(host["id"], "stream", 8, 2)), 2)
            self.assertEqual(work.claim(host["id"], "stream", 8, 2), [])
        self.assertTrue(work.ack(host, {"id": "r0"}))
        work.unclaim(["r0", "r1"])  # Only the unacknowledged one returns to the queue.
        self.assertEqual(self.agent(token, "poll")[1]["inference"]["id"], "r1")
        self.assertTrue(work.requests["r0"]["claimed"])
        # A request in progress is never dropped for its age; an unclaimed one leaves the queue.
        for name, claimed in (("old-claimed", True), ("old-queued", False)):
            response = compute.Response()
            response.expires = time.monotonic() - 1
            work.requests[name] = {"host": host["id"], "environment": "env-one", "payload": {}, "response": response,
                                   "claimed": claimed, "via": "poll" if claimed else None, "claimed_at": time.monotonic() if claimed else None, "acked": claimed}
        with work.lock:
            self.assertEqual([task["id"] for task in work.claim(host["id"], "poll", 8)], ["r2"])
        self.assertEqual(set(work.requests) - {"r0", "r1", "r2"}, {"old-claimed"})
        # A chunk uploaded twice (the connector retried after a lost reply) counts once.
        request = work.requests["old-claimed"]
        chunk = {"id": "old-claimed", "sequence": 0, "status": 200, "data": base64.b64encode(b"hello").decode()}
        self.assertTrue(work.chunk(host, chunk))
        self.assertTrue(work.chunk(host, chunk))
        self.assertEqual((request["response"].sequence, request["response"].total), (1, 5))
        with self.assertRaises(compute.ComputeInput):
            work.chunk(host, {**chunk, "sequence": 2})
        work.requests.clear()
        self.assertEqual(self.agent(token, "stream", capacity=0)[0], 400)
        link = compute_node.Link(self.url)
        stopped = threading.Event()
        results = []

        def receive():
            try:
                results.append(compute_node.receive(link, token, lambda task: None, stopped))
            except compute_node.Replaced:
                results.append("replaced")

        older = threading.Thread(target=receive, daemon=True)
        older.start()
        for _ in range(200):
            if work.generations.get(host["id"]) == 1:
                break
            time.sleep(.01)
        newer = threading.Thread(target=receive, daemon=True)
        newer.start()
        older.join(5)
        # The older connector is told that another one replaced it, so the two do not take turns forever.
        self.assertEqual(results, ["replaced"])
        work.revoke("test", host["id"])
        newer.join(5)
        self.assertEqual(results, ["replaced", True])  # A disconnected computer's stream just ends.
        stopped.set()

    def test_a_caller_waits_in_the_queue_and_then_for_the_answer_separately(self):
        token = self.pair_node()
        self.agent(token, "inventory", models=[{"id": "env-one", "name": "test/one", "state": "ready", "shared": True}])
        host = self.service.compute.host(token)
        work = self.service.compute
        with patch.object(compute, "QUEUE_SECONDS", .4), patch.object(compute, "ANSWER_SECONDS", 10):
            started = time.monotonic()
            with self.assertRaises(compute.UpstreamError) as refused:
                work.connect("compute://" + host["id"] + "/env-one", {})
            self.assertEqual(refused.exception.status, 504)
            self.assertLess(time.monotonic() - started, 3)
        with patch.object(compute, "QUEUE_SECONDS", 10), patch.object(compute, "ANSWER_SECONDS", .4):
            taken = threading.Event()

            def take():
                while not work.poll(host).get("inference"):
                    time.sleep(.02)
                taken.set()

            threading.Thread(target=take, daemon=True).start()
            started = time.monotonic()
            with self.assertRaises(compute.UpstreamError) as refused:
                work.connect("compute://" + host["id"] + "/env-one", {})
            self.assertEqual(refused.exception.status, 504)
            self.assertTrue(taken.is_set())
            self.assertLess(time.monotonic() - started, 3)
        self.assertFalse(work.requests)

    def test_the_connector_program_takes_queued_work_as_slots_free_and_stops_when_replaced(self):
        """The connector as contributors run it (main), against the website and the fixture model."""
        from concurrent.futures import ThreadPoolExecutor
        import os
        token = self.pair_node()
        server, model_url = self.url, self.model_url
        home = Path(self.temp.name) / "home"
        folder = home / "InferenceSolver" / ("node-" + hashlib.sha256(server.encode()).hexdigest()[:16])
        folder.mkdir(parents=True)
        (folder / "credential").write_text(token, encoding="utf-8")

        class FakeAdapter(Adapter):
            def inventory(self):
                return {"platform": "test", "models": [{"id": "env-one", "name": "test/one", "state": "ready", "shared": True, "slots": 4}], "detail": ""}

            def share(self, environment, enabled=True):
                self.shared.add(environment)
                self.apis[environment] = {"apiUrl": model_url, "apiKey": UPSTREAM_KEY, "model": "test/one"}

        outcome = []

        def run():
            try:
                compute_node.main(server)
            except BaseException as error:  # noqa: the connector reports its own ending
                outcome.append(error)

        with patch.dict(os.environ, {"LOCALAPPDATA": str(home)}), patch.object(compute_node, "executable", lambda: "unused"), \
                patch.object(compute_node, "Adapter", FakeAdapter), patch.object(compute_node, "CAPACITY", 1), \
                patch("sys.argv", ["compute_node.py", "--models", "env-one", "--sandbox", "none"]):
            connector = threading.Thread(target=run, daemon=True)
            connector.start()
            for _ in range(500):
                if self.service.compute.generations and self.service.router.groups:
                    break
                time.sleep(.02)
            self.assertTrue(self.service.compute.generations, outcome)
            self.assertEqual(list(self.service.router.groups.values()), [(self.service.compute.host(token)["id"], 1)])
            key = self.key()["key"]
            # Three callers at once on a computer that serves one request at a time: each is handed
            # over the moment the previous one finishes, while the connector is still freeing its slot.
            with ThreadPoolExecutor(3) as pool:
                results = list(pool.map(lambda index: self.call("/v1/chat/completions", self.completion("test/one", stream=index != 1, content=f"Opening {index}"), key=key), range(3)))
            self.assertEqual([status for status, _, _ in results], [200, 200, 200], results)
            self.assertFalse(self.service.compute.requests)
            # A second connector with the same credential: the first one stops and says why.
            stopped = threading.Event()
            second = threading.Thread(target=lambda: compute_node.receive(compute_node.Link(server), token, lambda task: None, stopped), daemon=True)
            second.start()
            connector.join(10)
            self.assertFalse(connector.is_alive())
            self.assertIsInstance(outcome[0], compute_node.Replaced)
            self.assertIn("Another connector is running", str(outcome[0]))
            stopped.set()
            self.service.compute.revoke("test", self.service.compute.host(token)["id"])
            second.join(5)


def load_tests(loader, tests, pattern):
    # Only this file's tests; the inherited service tests run in test_service.py.
    return unittest.TestSuite(RoutingFlow(name) for name in loader.getTestCaseNames(RoutingFlow) if name in RoutingFlow.__dict__)


if __name__ == "__main__":
    unittest.main(verbosity=2)
