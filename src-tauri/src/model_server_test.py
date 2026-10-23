"""Exercise the GGUF HTTP relay without downloading weights or taking a GPU."""
import io
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

cache = tempfile.TemporaryDirectory(prefix="yougori-model-test-")
os.environ.update(YOUGORI_MODEL="ressl/gemma-4-31B-it-uncensored-GGUF",
                  YOUGORI_MODEL_TOKEN="test-token-" * 8, YOUGORI_MODEL_FORMAT="gguf", HF_HOME=cache.name)
import model_server as model


class CudaDevicesTests(unittest.TestCase):
    def test_model_oom_is_distinguished_from_other_process_failures(self):
        with patch.object(model, "model_memory_events", return_value={"oom_kill": 2}), \
                patch("builtins.open", return_value=io.StringIO("4294967296")):
            message = model.llama_exit_error(-9, {"oom_kill": 1})
        self.assertIn("system RAM", message)
        self.assertIn("4.0 GiB limit", message)
        with patch.object(model, "model_memory_events", return_value={"oom_kill": 2}):
            message = model.llama_exit_error(-6, {"oom_kill": 2})
        self.assertNotIn("out of system RAM", message, "a historic OOM must not misclassify this exit")
        self.assertIn("exit code -6", message)
        with patch.object(model, "model_memory_events", return_value={}):
            self.assertIn("exit code 1", model.llama_exit_error(1, {}))

    def test_llama_threads_fit_the_sandbox_quota_on_gpu_and_cpu(self):
        quota = tempfile.NamedTemporaryFile("w", delete=False)
        quota.write("200000 100000\n")
        quota.close()
        real_open = open
        def fake_open(path, *args, **kwargs):
            return real_open(quota.name, *args, **kwargs) if path == "/sys/fs/cgroup/cpu.max" else real_open(path, *args, **kwargs)
        try:
            with patch.dict(os.environ, {}, clear=False), patch("builtins.open", fake_open):
                os.environ.pop("YOUGORI_MODEL_CPU_THREADS", None)
                os.environ.pop("YOUGORI_MODEL_CPU", None)
                # A GPU runner in a two-core quota gets two threads and no busy polling.
                self.assertEqual(model.llama_cpu_options(), ["--threads", "2", "--threads-batch", "2", "--poll", "0", "--poll-batch", "0"])
                os.environ.update(YOUGORI_MODEL_CPU="1", YOUGORI_MODEL_CPU_THREADS="6")
                self.assertEqual(model.llama_cpu_options()[:4], ["-ngl", "0", "--threads", "6"])
                os.environ["YOUGORI_MODEL_CPU_THREADS"] = "invalid"
                self.assertEqual(model.llama_threads(), 2, "an invalid setting falls back to the quota")
        finally:
            os.environ.pop("YOUGORI_MODEL_CPU", None)
            os.environ.pop("YOUGORI_MODEL_CPU_THREADS", None)
            os.unlink(quota.name)

    def test_native_backend_keeps_verified_frontend_and_private_credentials(self):
        previous = dict(model.LLAMA)
        try:
            for backend in ("metal", "cpu"):
                with patch.dict(os.environ, {"YOUGORI_NATIVE_BACKEND": backend,
                        "YOUGORI_NATIVE_TOKEN": "c" * 64, "YOUGORI_NATIVE_PORT": "12345"}), \
                        patch.object(model, "verified_gguf") as verify, \
                        patch.object(model, "llama_json", side_effect=[{}, {"default_generation_settings": {"n_ctx": 2048}}]), \
                        patch.object(model.subprocess, "Popen") as spawn:
                    model.load_gguf()
                    verify.assert_called_once()
                    spawn.assert_not_called()
                    self.assertEqual(model.LLAMA["host"], "10.0.2.2")
                    self.assertEqual(model.LLAMA["key"], "c" * 64)
                    self.assertEqual(model.STATE["backend"], backend)
                    self.assertEqual(model.STATE["gpuCount"], int(backend == "metal"))
                    self.assertTrue(model.STATE["weightsVerified"])
                    self.assertTrue(model.STATE["toolCalling"])
            self.assertIn("YOUGORI_NATIVE_TOKEN", model.PRIVATE_ENVIRONMENT)
        finally:
            model.LLAMA.clear()
            model.LLAMA.update(previous)

    def test_native_backend_refuses_invalid_connection_before_loading(self):
        for backend, token, port in [("cuda", "c" * 64, "12345"), ("metal", "bad", "12345"), ("cpu", "c" * 64, "0")]:
            with patch.dict(os.environ, {"YOUGORI_NATIVE_BACKEND": backend, "YOUGORI_NATIVE_TOKEN": token, "YOUGORI_NATIVE_PORT": port}), \
                    patch.object(model, "verified_gguf") as verify:
                with self.assertRaisesRegex(RuntimeError, "Invalid native"):
                    model.load_native_gguf()
                verify.assert_not_called()

    def test_device_listing_works_without_old_startup_diagnostics(self):
        listing = "Available devices:\n  CUDA0: NVIDIA GeForce RTX 5090 Laptop GPU (24462 MiB, 23119 MiB free)\n  CUDA1: NVIDIA RTX 4090 (24564 MiB, 22000 MiB free)\n"
        with patch.object(model.subprocess, "run", return_value=SimpleNamespace(stdout=listing, stderr="")) as run:
            devices = model.llama_cuda_devices("/runner/llama-server", {"LD_LIBRARY_PATH": "/runner"})
        self.assertEqual(devices, {"CUDA0": "NVIDIA GeForce RTX 5090 Laptop GPU", "CUDA1": "NVIDIA RTX 4090"})
        self.assertEqual(run.call_args.args[0], ["/runner/llama-server", "--list-devices"])

    def test_no_cuda_and_failed_query_remain_errors(self):
        for listing in ("Available devices:\n", "Available devices:\n  CPU: Generic processor (32000 MiB, 16000 MiB free)\n"):
            with patch.object(model.subprocess, "run", return_value=SimpleNamespace(stdout=listing)):
                with self.assertRaisesRegex(RuntimeError, "found no CUDA GPU"):
                    model.llama_cuda_devices("runner", {})
        with patch.object(model.subprocess, "run", side_effect=subprocess.TimeoutExpired("runner", 30)):
            with self.assertRaisesRegex(RuntimeError, "could not query CUDA devices"):
                model.llama_cuda_devices("runner", {})


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
        if self.server.complete:
            self.wfile.write(("data: " + json.dumps({"choices": [{"delta": {}, "finish_reason": "stop"}]}) + "\n\n").encode())
        self.wfile.write(("data: " + json.dumps({"choices": [], "usage": {"prompt_tokens": 9, "completion_tokens": 3}}) + "\n\ndata: [DONE]\n\n").encode())
        self.wfile.flush()
        self.close_connection = True


class ModelRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        cls.server.seen = []
        cls.server.complete = True
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

    def test_usage_without_a_completed_stream_is_rejected(self):
        self.server.complete = False
        try:
            output, meter = Output(), {}
            model.generate({"messages": [{"role": "user", "content": "Hello"}], "stream": True}, output, meter)
            self.assertEqual(meter["outcome"], "error")
            self.assertIn("ended before a complete response", output.wfile.getvalue().decode())
        finally:
            self.server.complete = True

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


class ModelDownloadTests(unittest.TestCase):
    def test_cache_progress_and_completion_at_stall_boundary_are_accepted(self):
        for events in ([{"kind": "cached", "files": ["weights.gguf"]},
                        {"kind": "done", "root": "/snapshot"}],
                       [{"kind": "done", "root": "/snapshot"}]):
            process = Mock(stdin=io.StringIO(),
                           stdout=io.StringIO("\n".join(json.dumps(event) for event in events)),
                           returncode=0)
            process.poll.return_value = 0
            with self.subTest(events=events), patch.object(model.subprocess, "Popen", return_value=process) as spawn, \
                 patch.object(model, "incomplete_downloads", return_value=set()), \
                 patch.object(model, "DOWNLOAD_STALL_SECONDS", 1), \
                 patch.object(model.time, "monotonic", side_effect=[0, 1.1, 1.2]):
                self.assertEqual(model.download_snapshot("a" * 40, {"weights.gguf": 100}), "/snapshot")
                self.assertEqual(model.STATE["download"]["receivedBytes"], 100)
                spawn.assert_called_once()
                process.terminate.assert_not_called()

    def test_auto_precision_fits_large_models_without_exceeding_free_gpu_memory(self):
        gib = 1024 ** 3
        torch = SimpleNamespace(cuda=SimpleNamespace(mem_get_info=lambda index: (24 * gib, 24 * gib)), bfloat16="bf16")
        transformers = SimpleNamespace(BitsAndBytesConfig=lambda **options: options)
        with patch.object(model, "TORCH", torch), patch.object(model, "install") as install, \
             patch.dict("sys.modules", transformers=transformers), patch.dict(os.environ, YOUGORI_MODEL_PRECISION="auto"):
            self.assertEqual(model.inference_options(4 * gib, 1), {})
            install.assert_not_called()
            self.assertTrue(model.inference_options(27 * gib, 1)["quantization_config"]["load_in_8bit"])
            four_bit = model.inference_options(54 * gib, 1)["quantization_config"]
            self.assertTrue(four_bit["load_in_4bit"])
            self.assertEqual(four_bit["bnb_4bit_compute_dtype"], "bf16")
            with self.assertRaisesRegex(RuntimeError, "does not fit"):
                model.inference_options(100 * gib, 1)

    def test_worker_keeps_complete_cache_and_restarts_only_unfinished_files(self):
        with tempfile.TemporaryDirectory() as directory:
            with open(os.path.join(directory, "huggingface_hub.py"), "w", encoding="utf-8") as file:
                file.write('''
def try_to_load_from_cache(model, name, revision):
    return "/cached/config.json" if name == "config.json" else None
def snapshot_download(model, revision, allow_patterns, max_workers, tqdm_class, force_download):
    assert allow_patterns == ["model.safetensors"]
    assert max_workers == 2 and force_download
    with tqdm_class(total=200, unit="B", desc="Downloading bytes") as progress:
        progress.update(200)
    with tqdm_class(total=200, unit="B", desc="Reconstructing") as progress:
        progress.update(200)
    return "/snapshot"
''')
            request = json.dumps({"model": "test/model", "revision": "a" * 40, "files": ["config.json", "model.safetensors"], "restart_partial": True})
            result = subprocess.run([sys.executable, "-u", "-c", model.DOWNLOAD_WORKER], input=request,
                text=True, capture_output=True, timeout=10, env={**os.environ, "PYTHONPATH": directory})
            self.assertEqual(result.returncode, 0, result.stderr)
            events = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertIn({"kind": "cached", "files": ["config.json"]}, events)
            self.assertTrue(any(event.get("kind") == "written" and event.get("bytes") == 200 for event in events))
            self.assertEqual(events[-1], {"kind": "done", "root": "/snapshot"})

    def test_native_stall_is_killed_then_https_is_used_without_provider_key(self):
        worker = '''
import json, os, sys, time
request = json.load(sys.stdin)
assert "YOUGORI_MODEL_TOKEN" not in os.environ
assert os.environ["HF_XET_RECONSTRUCTION_DOWNLOAD_BUFFER_LIMIT"] == "512mb"
if os.environ.get("HF_HUB_DISABLE_XET") != "1":
    root = os.path.join(os.environ["HF_HOME"], "hub", "models--" + request["model"].replace("/", "--"), "blobs")
    with open(os.path.join(root, "bbbbbbbb.22222222.incomplete"), "wb") as file:
        file.write(b"unfinished native transfer")
    time.sleep(30)
else:
    assert request["restart_partial"]
    root = os.path.join(os.environ["HF_HOME"], "hub", "models--" + request["model"].replace("/", "--"), "blobs")
    assert os.path.exists(os.path.join(root, "aaaaaaaa.11111111.incomplete"))
    assert not os.path.exists(os.path.join(root, "bbbbbbbb.22222222.incomplete"))
    print(json.dumps({"kind": "cached", "files": ["config.json"]}), flush=True)
    print(json.dumps({"kind": "written", "bytes": 100}), flush=True)
    print(json.dumps({"kind": "done", "root": "/verified-snapshot"}), flush=True)
'''
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, HF_HOME=directory), \
             patch.object(model, "CACHE", directory), patch.object(model, "DOWNLOAD_WORKER", worker), patch.object(model, "DOWNLOAD_STALL_SECONDS", 1):
            root = os.path.join(directory, "hub", "models--" + model.MODEL.replace("/", "--"), "blobs")
            os.makedirs(root)
            with open(os.path.join(root, "aaaaaaaa.11111111.incomplete"), "wb") as file:
                file.write(b"older cache")
            self.assertEqual(model.download_snapshot("a" * 40, {"config.json": 10, "weights.safetensors": 100}), "/verified-snapshot")
        self.assertEqual(model.STATE["download"]["receivedBytes"], 110)
        self.assertEqual(model.STATE["download"]["transport"], "https")

    def test_both_transports_fail_with_a_bounded_credential_free_error(self):
        worker = 'import sys; print("https://cdn.test/?secret=PRIVATE", file=sys.stderr); sys.exit(1)'
        with patch.object(model, "DOWNLOAD_WORKER", worker):
            with self.assertRaisesRegex(RuntimeError, "Completed files are cached") as error:
                model.download_snapshot("a" * 40, {"weights.safetensors": 100})
        self.assertNotIn("PRIVATE", str(error.exception))

    def test_failed_final_download_attempt_does_not_leave_large_partial_files(self):
        worker = '''import json,os,sys
r=json.load(sys.stdin)
root=os.path.join(os.environ["HF_HOME"],"hub","models--"+r["model"].replace("/","--"),"blobs")
with open(os.path.join(root,"bbbbbbbb.22222222.incomplete"),"wb") as f:f.write(b"partial"*1024)
sys.exit(1)
'''
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, HF_HOME=directory), patch.object(model, "CACHE", directory), patch.object(model, "DOWNLOAD_WORKER", worker):
            root = os.path.join(directory, "hub", "models--" + model.MODEL.replace("/", "--"), "blobs")
            os.makedirs(root)
            for name in ["completed-weight", "aaaaaaaa.11111111.incomplete"]:
                with open(os.path.join(root, name), "wb") as file: file.write(b"existing data")
            with self.assertRaises(RuntimeError): model.download_snapshot("a"*40, {"weights.safetensors":100})
            self.assertEqual(set(os.listdir(root)), {"completed-weight", "aaaaaaaa.11111111.incomplete"})

    def test_checksum_cache_reuses_unchanged_weights_and_rechecks_changed_bytes(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(model, "CACHE", directory):
            path = os.path.join(directory, "model.safetensors")
            with open(path, "wb") as file:
                file.write(b"verified weights")
            digest = hashlib.sha256(b"verified weights").hexdigest()
            self.assertTrue(model.verified_weight(path, digest, 16))
            with patch.object(model, "verify_file", side_effect=AssertionError("cached weights were hashed again")):
                self.assertTrue(model.verified_weight(path, digest, 16))
            with open(path, "wb") as file:
                file.write(b"tampered weights")
            self.assertFalse(model.verified_weight(path, digest, 16))
            self.assertFalse(model.verified_weight(path, digest, 17))


class AgentToolCallingTests(unittest.TestCase):
    """Tools on vLLM only for a server the pod launcher started for a Swarm worker."""
    BODY = {"messages": [{"role": "user", "content": "Check"}],
            "tools": [{"type": "function", "function": {"name": "worker_ready", "parameters": {"type": "object", "properties": {"ready": {"type": "boolean"}}}}}],
            "tool_choice": {"type": "function", "function": {"name": "worker_ready"}}}

    def test_vllm_takes_tools_only_when_started_with_a_parser(self):
        with patch.object(model, "FORMAT", "vllm"), patch.object(model, "TOOL_PARSER", ""):
            with self.assertRaisesRegex(ValueError, "Agent tools require"):
                model.validate_chat(self.BODY)
            self.assertEqual(model.agent_arguments(), [])
        with patch.object(model, "FORMAT", "vllm"), patch.object(model, "TOOL_PARSER", "hermes"):
            model.validate_chat(self.BODY)
            self.assertEqual(model.agent_arguments(), ["--enable-auto-tool-choice", "--tool-call-parser", "hermes"])
        # Transformers has no tool calling, whatever the environment says.
        with patch.object(model, "FORMAT", "safetensors"), patch.object(model, "TOOL_PARSER", "hermes"):
            with self.assertRaisesRegex(ValueError, "Agent tools require"):
                model.validate_chat(self.BODY)
            self.assertEqual(model.agent_arguments(), [])

    def test_gguf_tools_are_unchanged(self):
        with patch.object(model, "FORMAT", "gguf"), patch.object(model, "TOOL_PARSER", ""):
            model.validate_chat(self.BODY)

    def test_only_reviewed_parsers_are_used(self):
        self.assertEqual(model.allowed_tool_parser("hermes"), "hermes")
        self.assertEqual(model.allowed_tool_parser("qwen3_coder"), "qwen3_coder")
        for value in ("", "pythonic", "hermes --trust-remote-code", "../hermes"):
            self.assertEqual(model.allowed_tool_parser(value), "")

    def test_tool_results_follow_their_call_on_an_agent_server(self):
        history = {"messages": [
            {"role": "user", "content": "Check"},
            {"role": "assistant", "content": None, "tool_calls": [{"id": "chatcmpl-tool-1a2b", "type": "function", "function": {"name": "worker_ready", "arguments": "{\"ready\": true}"}}]},
            {"role": "tool", "tool_call_id": "chatcmpl-tool-1a2b", "content": "ok"},
        ], "tools": self.BODY["tools"]}
        with patch.object(model, "FORMAT", "vllm"), patch.object(model, "TOOL_PARSER", "hermes"):
            model.validate_chat(history)
        with patch.object(model, "FORMAT", "vllm"), patch.object(model, "TOOL_PARSER", ""):
            with self.assertRaises(ValueError):
                model.validate_chat({**history, "tools": None})


if __name__ == "__main__":
    unittest.main()
