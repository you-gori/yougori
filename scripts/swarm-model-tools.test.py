"""Local-model tool protocol tests using a real loopback relay and synthetic runner.

No model downloads, GPU allocation, existing containers, or public endpoints.
"""
import copy
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch


cache = tempfile.TemporaryDirectory(prefix="yougori-swarm-tool-test-")
os.environ.update(
    YOUGORI_MODEL="example/tool-model-GGUF",
    YOUGORI_MODEL_TOKEN="test-private-api-token" * 3,
    YOUGORI_MODEL_FORMAT="gguf",
    HF_HOME=cache.name,
)
spec = importlib.util.spec_from_file_location(
    "swarm_model_server", Path(__file__).parents[1] / "src-tauri/src/model_server.py"
)
model = importlib.util.module_from_spec(spec)
spec.loader.exec_module(model)

TOOLS = [{"type": "function", "function": {
    "name": "yougori_probe", "description": "Return an exact harmless probe value",
    "parameters": {"type": "object", "properties": {"value": {"type": "string"}},
                   "required": ["value"], "additionalProperties": False},
}}]
CALL = {"id": "call_probe_1", "type": "function", "function": {
    "name": "yougori_probe", "arguments": '{"value":"tool-round-trip"}'
}}


class Output:
    def __init__(self):
        self.wfile = io.BytesIO()
        self.status = None

    def send_response(self, status):
        self.status = status

    def send_header(self, *_):
        pass

    def end_headers(self):
        pass


class Runner(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, value):
        data = json.dumps(value).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + model.LLAMA["key"]:
            self.send_error(401)
            return
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, body))
        if self.path == "/apply-template":
            return self.reply({"prompt": "bounded synthetic prompt"})
        if self.path == "/tokenize":
            return self.reply({"tokens": list(range(11))})
        tool_result = any(message["role"] == "tool" for message in body["messages"])
        if not body.get("stream"):
            message = ({"role": "assistant", "content": None, "tool_calls": [CALL]}
                       if body.get("tools") and not tool_result
                       else {"role": "assistant", "content": "Probe completed"})
            return self.reply({"choices": [{"message": message,
                                          "finish_reason": "tool_calls" if message.get("tool_calls") else "stop"}],
                               "usage": {"prompt_tokens": 11, "completion_tokens": 7}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        deltas = [
            {"tool_calls": [{"index": 0, "id": CALL["id"], "type": "function",
                             "function": {"name": "yougori_probe", "arguments": '{"value":'}}]},
            {"tool_calls": [{"index": 0, "function": {"arguments": '"tool-round-trip"}'}}]},
        ]
        for delta in deltas:
            event = {"choices": [{"delta": delta, "finish_reason": None}]}
            self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
        event = {"choices": [{"delta": {}, "finish_reason": "tool_calls"}],
                 "usage": {"prompt_tokens": 11, "completion_tokens": 7}}
        self.wfile.write(("data: " + json.dumps(event) + "\n\ndata: [DONE]\n\n").encode())
        self.wfile.flush()
        self.close_connection = True


class ToolRoundTripTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = ThreadingHTTPServer(("127.0.0.1", 0), Runner)
        cls.runner.seen = []
        cls.thread = threading.Thread(target=cls.runner.serve_forever, daemon=True)
        cls.thread.start()
        model.LLAMA.update(port=cls.runner.server_address[1], context=4096)

    @classmethod
    def tearDownClass(cls):
        cls.runner.shutdown()
        cls.runner.server_close()
        cls.thread.join(2)
        cache.cleanup()

    def setUp(self):
        self.runner.seen.clear()

    def body(self, **extra):
        return {"model": model.MODEL, "messages": [{"role": "user", "content": "Use the harmless probe"}],
                "tools": copy.deepcopy(TOOLS), "tool_choice": "required",
                "parallel_tool_calls": False, "max_tokens": 128, **extra}

    def test_function_schema_is_tokenized_and_forwarded_without_cloud_fallback(self):
        body = self.body()
        status, reply = model.generate(body, Output(), {})
        self.assertEqual(status, 200)
        self.assertEqual(reply["choices"][0]["message"]["tool_calls"], [CALL])
        self.assertEqual(reply["choices"][0]["finish_reason"], "tool_calls")
        request = [b for path, b in self.runner.seen if path == "/v1/chat/completions"][-1]
        self.assertEqual(request["tools"], TOOLS)
        self.assertEqual(request["tool_choice"], "required")
        self.assertFalse(request["parallel_tool_calls"])
        template = [b for path, b in self.runner.seen if path == "/apply-template"][-1]
        self.assertEqual(template["tools"], TOOLS)
        self.assertEqual(reply["usage"]["completion_tokens"], 7)

    def test_tool_only_assistant_response_can_complete_a_following_tool_turn(self):
        body = self.body()
        _status, first = model.generate(body, Output(), {})
        body["messages"].extend([first["choices"][0]["message"],
                                 {"role": "tool", "tool_call_id": CALL["id"],
                                  "content": "tool-round-trip"}])
        status, final = model.generate(body, Output(), {})
        self.assertEqual(status, 200)
        self.assertEqual(final["choices"][0]["message"]["content"], "Probe completed")
        self.assertFalse(model.GENERATION.locked())

    def test_stream_preserves_split_tool_calls_finish_reason_and_usage(self):
        output, meter = Output(), {}
        self.assertIsNone(model.generate(self.body(stream=True), output, meter))
        events = [json.loads(line[6:]) for line in output.wfile.getvalue().decode().split("\n\n")
                  if line.startswith("data: {")]
        calls = [event["choices"][0]["delta"]["tool_calls"][0]
                 for event in events if event.get("choices") and event["choices"][0]["delta"].get("tool_calls")]
        self.assertEqual(calls[0]["id"], CALL["id"])
        self.assertEqual("".join(call["function"]["arguments"] for call in calls), CALL["function"]["arguments"])
        self.assertEqual(events[-1]["choices"][0]["finish_reason"], "tool_calls")
        self.assertEqual(events[-1]["usage"]["completion_tokens"], 7)
        self.assertEqual(meter["outcome"], "ok")

    def test_invalid_tool_schemas_and_foreign_result_ids_fail_before_runner_request(self):
        bodies = [
            self.body(tools=[]),
            self.body(tools=TOOLS + TOOLS),
            self.body(tool_choice={"type": "function", "function": {"name": "unknown"}}),
            self.body(parallel_tool_calls="false"),
            self.body(tools=[{"type": "function", "function": {"name": "bad;name", "parameters": {}}}]),
            self.body(messages=[{"role": "user", "content": "Probe"},
                                {"role": "tool", "tool_call_id": "foreign", "content": "result"}]),
        ]
        for body in bodies:
            with self.subTest(body=body), self.assertRaises(ValueError):
                model.generate(body, Output(), {})
        self.assertEqual(self.runner.seen, [])
        self.assertFalse(model.GENERATION.locked())

    def test_unsupported_model_format_is_not_marked_tool_compatible(self):
        with patch.object(model, "FORMAT", "safetensors"):
            with self.assertRaisesRegex(ValueError, "GGUF runner"):
                model.validate_chat(self.body())
        self.assertEqual(self.runner.seen, [])

    def test_existing_plain_chat_and_text_parts_remain_compatible(self):
        body = {"messages": [{"role": "user", "content": [{"type": "text", "text": "Hello"}]}],
                "max_completion_tokens": 32, "top_p": 0.9, "stop": ["END"]}
        status, reply = model.generate(body, Output(), {})
        self.assertEqual(status, 200)
        self.assertEqual(reply["choices"][0]["message"]["content"], "Probe completed")
        request = [b for path, b in self.runner.seen if path == "/v1/chat/completions"][-1]
        self.assertEqual(request["messages"][0]["content"], "Hello")
        self.assertEqual(request["max_tokens"], 32)
        self.assertNotIn("tools", request)

    def test_cpu_threads_respect_allocation_and_agent_thinking_is_disabled(self):
        with patch.dict(os.environ, {"YOUGORI_MODEL_CPU": "1", "YOUGORI_MODEL_CPU_THREADS": "2",
                                    "YOUGORI_MODEL_AGENT_API": "1"}):
            options = model.llama_cpu_options()
            self.assertEqual(options[options.index("--threads") + 1], "2")
            self.assertEqual(options[options.index("--threads-batch") + 1], "2")
            self.assertEqual(options[options.index("--poll") + 1], "0")
            status, _ = model.generate(self.body(), Output(), {})
            self.assertEqual(status, 200)
            request = [b for path, b in self.runner.seen if path == "/v1/chat/completions"][-1]
            self.assertEqual(request["chat_template_kwargs"], {"enable_thinking": False})
        with patch.dict(os.environ, {"YOUGORI_MODEL_CPU": "1", "YOUGORI_MODEL_CPU_THREADS": "invalid"}):
            self.assertIn("2", model.llama_cpu_options())


if __name__ == "__main__":
    unittest.main()
