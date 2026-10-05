"""Exercise the GGUF HTTP relay without downloading weights or taking a GPU."""
import io
import json
import os
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

cache = tempfile.TemporaryDirectory(prefix="yougori-model-test-")
os.environ.update(YOUGORI_MODEL="ressl/gemma-4-31B-it-uncensored-GGUF",
                  YOUGORI_MODEL_TOKEN="test-token-" * 8, YOUGORI_MODEL_FORMAT="gguf", HF_HOME=cache.name)
import model_server as model


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


class Provider(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, status, value):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        if self.headers.get("Authorization") != "Bearer " + model.LLAMA["key"]:
            return self.reply(401, {})
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.seen.append((self.path, body))
        if self.path == "/apply-template":
            if any(message["role"] == "system" for message in body["messages"]):
                return self.reply(400, {"error": {"message": "System role unsupported"}})
            return self.reply(200, {"prompt": "".join(message["content"] for message in body["messages"])})
        if self.path == "/tokenize":
            return self.reply(200, {"tokens": list(range(len(body["content"]) // 2))})
        if not body["stream"]:
            return self.reply(200, {"choices": [{"message": {"content": "Hi there"}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 9, "completion_tokens": 3}})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Connection", "close")
        self.end_headers()
        for content in ["Hel", "lo", "!"]:
            self.wfile.write(("data: " + json.dumps({"choices": [{"delta": {"content": content}, "finish_reason": None}]}) + "\n\n").encode())
        self.wfile.write(("data: " + json.dumps({"choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": 3}}) + "\n\ndata: [DONE]\n\n").encode())
        self.wfile.flush()
        self.close_connection = True


class ModelRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        cls.server.seen = []
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        model.LLAMA.update(port=cls.server.server_address[1], context=4096)
        model.STATE["status"] = "ready"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(2)
        cache.cleanup()

    def test_non_streaming_folds_system_role_and_counts_actual_tokens(self):
        meter = {}
        status, reply = model.generate({"messages": [{"role": "system", "content": "Be nice"}, {"role": "user", "content": "Hello"}], "max_tokens": 50}, Output(), meter)
        self.assertEqual(status, 200)
        self.assertEqual(reply["choices"][0]["message"]["content"], "Hi there")
        self.assertEqual(reply["usage"]["completion_tokens"], 3)
        self.assertEqual(meter["outcome"], "ok")
        body = [body for path, body in self.server.seen if path == "/v1/chat/completions"][-1]
        self.assertEqual(body["messages"][0]["role"], "user")
        self.assertTrue(body["messages"][0]["content"].startswith("Be nice"))

    def test_streaming_delivers_text_final_usage_and_done(self):
        output, meter = Output(), {}
        self.assertIsNone(model.generate({"messages": [{"role": "user", "content": "Hello"}], "stream": True, "truncate": True}, output, meter))
        text = output.wfile.getvalue().decode()
        events = [json.loads(line[6:]) for line in text.split("\n\n") if line.startswith("data: {")]
        self.assertEqual("".join(event["choices"][0]["delta"].get("content", "") for event in events if event.get("choices")), "Hello!")
        self.assertEqual(events[-1]["usage"]["completion_tokens"], 3)
        self.assertEqual(events[-1]["usage"]["context_window"], 4096)
        self.assertTrue(text.rstrip().endswith("data: [DONE]"))
        self.assertEqual(meter["outcome"], "ok")

    def test_context_failure_releases_gpu_lock_and_busy_requests_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "context window"):
            model.generate({"messages": [{"role": "user", "content": "x" * 9000}], "max_tokens": 100}, Output(), {})
        self.assertFalse(model.GENERATION.locked())
        model.GENERATION.acquire()
        try:
            meter = {}
            status, _reply = model.generate({"messages": [{"role": "user", "content": "Hello"}]}, Output(), meter)
            self.assertEqual(status, 429)
            self.assertEqual(meter["outcome"], "busy")
        finally:
            model.GENERATION.release()


if __name__ == "__main__":
    unittest.main()
