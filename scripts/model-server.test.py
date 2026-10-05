import importlib.util
import http.client
import io
import json
import hashlib
import tempfile
import os
from pathlib import Path
import threading
import unittest
import queue
import time
from contextlib import contextmanager, ExitStack
from unittest.mock import Mock, patch
from types import SimpleNamespace
from urllib.request import Request, urlopen
from urllib.error import HTTPError

os.environ["YOUGORI_MODEL"] = "example/test-model"
os.environ["YOUGORI_MODEL_TOKEN"] = "a" * 64
spec = importlib.util.spec_from_file_location("model_server", Path(__file__).parents[1] / "src-tauri/src/model_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)

class ChatConfig:
    model_type = "llama"
    max_position_embeddings = 2048


@contextmanager
def model_startup(count=1, files=("model.safetensors",), config=None, versions=None):
    config = config or ChatConfig()
    network = Mock(config=config)
    network.eval.return_value = network
    models = Mock()
    models._model_mapping = {ChatConfig: object}
    models.from_pretrained.return_value = network
    transformers = SimpleNamespace(AutoConfig=Mock(), AutoModelForCausalLM=models, AutoTokenizer=Mock())
    transformers.AutoConfig.from_pretrained.return_value = config
    hub = SimpleNamespace(HfApi=Mock(), hf_hub_download=Mock(), snapshot_download=Mock())
    hub.HfApi.return_value.model_info.return_value = SimpleNamespace(
        sha="a" * 40, siblings=[SimpleNamespace(rfilename=name, lfs={"sha256":hashlib.sha256(b"test weights").hexdigest()}) for name in files])
    torch = SimpleNamespace(float16="float16", cuda=SimpleNamespace(
        is_available=lambda: True, device_count=lambda: count, get_device_name=lambda index: "Test GPU"))
    installed = {"transformers": "5.18.0", "accelerate": "1.15.0", "huggingface-hub": "1.33.0", **(versions or {})}
    with ExitStack() as stack:
        snapshot = stack.enter_context(tempfile.TemporaryDirectory())
        for name in files:
            file=Path(snapshot)/name
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_bytes(b"test weights")
        hub.snapshot_download.return_value=snapshot
        stack.enter_context(patch.object(server, "CACHE", snapshot))
        stack.enter_context(patch.object(server, "download_snapshot", side_effect=lambda revision, selected:
            hub.snapshot_download(server.MODEL, revision=revision, allow_patterns=list(selected))))
        stack.enter_context(patch.dict("sys.modules", torch=torch, transformers=transformers, huggingface_hub=hub))
        stack.enter_context(patch.object(server.importlib.metadata, "version", side_effect=installed.__getitem__))
        stack.enter_context(patch.object(server.threading, "Thread"))
        install = stack.enter_context(patch.object(server.subprocess, "run"))
        stack.enter_context(patch.dict(os.environ, YOUGORI_INSTALL_TORCH="0"))
        stack.enter_context(patch.dict(server.STATE, status="installing", error=None))
        for name in ("NETWORK", "TOKENIZER", "TORCH"):
            stack.enter_context(patch.object(server, name, None))
        yield SimpleNamespace(transformers=transformers, hub=hub, install=install, models=models, config=config)


class ModelServerTests(unittest.TestCase):
    def test_model_http_failures_never_disclose_the_api_key(self):
        torch = SimpleNamespace(inference_mode=lambda: ExitStack(), cuda=SimpleNamespace(OutOfMemoryError=MemoryError))
        for failure in (ValueError, TypeError, TimeoutError):
            with self.subTest(failure=failure.__name__), \
                 patch.dict("sys.modules", transformers=SimpleNamespace(StoppingCriteriaList=list)), \
                 patch.object(server, "TORCH", torch), \
                 patch.object(server, "NETWORK", SimpleNamespace(generate=Mock(side_effect=failure("sensitive detail " + server.TOKEN)))), \
                 patch.object(server, "TOKENIZER", SimpleNamespace(pad_token_id=0, eos_token_id=1)), \
                 patch.object(server, "prepare", return_value=({}, 2, 0)), \
                 patch.dict(server.STATE, status="ready", error=None):
                listener = server.Server(("127.0.0.1", 0), server.Handler)
                worker = threading.Thread(target=listener.serve_forever, daemon=True)
                worker.start()
                client = http.client.HTTPConnection("127.0.0.1", listener.server_port, timeout=2)
                try:
                    client.request("POST", "/v1/chat/completions", json.dumps({"messages":[{"role":"user", "content":"hello"}]}),
                                   {"Authorization":"Bearer " + server.TOKEN})
                    response = client.getresponse()
                    self.assertEqual(response.status, 400 if failure in (ValueError, TypeError) else 500)
                    self.assertNotIn(server.TOKEN.encode(), response.read())
                    self.assertFalse(server.GENERATION.locked())
                finally:
                    client.close()
                    listener.shutdown()
                    listener.server_close()
                    worker.join()

    def test_stalled_non_streaming_generation_has_a_bounded_response_and_exclusive_gpu(self):
        started, release, stopping = threading.Event(), threading.Event(), {}
        def stall(**kwargs):
            stopping["event"] = kwargs.get("stopping_criteria", [SimpleNamespace(event=threading.Event())])[0].event
            started.set()
            release.wait(3)
            return None
        lock, meter, result = threading.Lock(), {}, {}
        torch = SimpleNamespace(inference_mode=lambda: ExitStack(), cuda=SimpleNamespace(OutOfMemoryError=MemoryError))
        with patch.dict("sys.modules", transformers=SimpleNamespace(StoppingCriteriaList=list)), \
             patch.object(server, "GENERATION", lock), patch.object(server, "TORCH", torch), \
             patch.object(server, "NETWORK", SimpleNamespace(generate=stall)), \
             patch.object(server, "TOKENIZER", SimpleNamespace(pad_token_id=0, eos_token_id=1)), \
             patch.object(server, "prepare", return_value=({}, 2, 0)), \
             patch.dict(server.STATE, status="ready", error=None), \
             patch.object(server, "GENERATION_MAX_SECONDS", .1, create=True), \
             patch.object(server, "STREAM_CANCEL_GRACE_SECONDS", .05):
            def request():
                result["reply"] = server.generate({"messages":[{"role":"user", "content":"hello"}]}, None, meter)
            response = threading.Thread(target=request)
            try:
                response.start()
                self.assertTrue(started.wait(1))
                response.join(.6)
                self.assertFalse(response.is_alive(), "A stalled generation kept its HTTP worker forever")
                self.assertEqual(result["reply"][0], 504)
                self.assertEqual(meter["outcome"], "error")
                self.assertTrue(stopping["event"].is_set())
                self.assertTrue(lock.locked())
                self.assertEqual(server.STATE["status"], "error")
            finally:
                release.set()
                response.join(4)
                deadline = time.monotonic() + 1
                while lock.locked() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertFalse(lock.locked())

    def test_stream_success_failure_and_client_disconnect_release_gpu_ownership(self):
        class Streamer:
            def __init__(self, tokenizer, **kwargs):
                self.timeout = kwargs.get("timeout")
                self.queue = queue.Queue()
            def __iter__(self):
                return self
            def __next__(self):
                value = self.queue.get(timeout=self.timeout)
                if value is None:
                    raise StopIteration
                return value
            def end(self):
                self.queue.put(None)
        class Disconnected:
            def write(self, value):
                raise BrokenPipeError("client disconnected")
        for mode in ("success", "error", "disconnect"):
            with self.subTest(mode=mode):
                output, lock, meter = io.BytesIO(), threading.Lock(), {}
                handler = SimpleNamespace(wfile=Disconnected() if mode == "disconnect" else output,
                                          send_response=lambda *args: None, send_header=lambda *args: None,
                                          end_headers=lambda: None)
                def generate(**kwargs):
                    if mode == "error":
                        raise RuntimeError("sensitive engine detail " + server.TOKEN)
                    if mode == "disconnect":
                        self.assertTrue(kwargs["stopping_criteria"][0].event.wait(2))
                    else:
                        kwargs["streamer"].queue.put("hello")
                    kwargs["streamer"].end()
                    return SimpleNamespace(shape=(1, 4))
                torch = SimpleNamespace(inference_mode=lambda: ExitStack(), cuda=SimpleNamespace(OutOfMemoryError=MemoryError))
                with patch.dict("sys.modules", transformers=SimpleNamespace(TextIteratorStreamer=Streamer, StoppingCriteriaList=list)), \
                     patch.object(server, "GENERATION", lock), patch.object(server, "TORCH", torch), \
                     patch.object(server, "NETWORK", SimpleNamespace(generate=generate)), \
                     patch.object(server, "TOKENIZER", SimpleNamespace(pad_token_id=0, eos_token_id=1)), \
                     patch.object(server, "prepare", return_value=({}, 2, 0)), \
                     patch.object(server, "STREAM_POLL_SECONDS", .05), \
                     patch.dict(server.STATE, status="ready", error=None):
                    result = server.generate({"messages":[{"role":"user", "content":"hello"}], "stream":True}, handler, meter)
                    self.assertIsNone(result)
                    self.assertFalse(lock.locked())
                    self.assertEqual(meter["outcome"], {"success":"ok", "error":"error", "disconnect":"cancelled"}[mode])
                    self.assertEqual(server.STATE["status"], "ready")
                    self.assertNotIn(server.TOKEN.encode(), output.getvalue())
                    if mode != "disconnect":
                        self.assertIn(b"[DONE]", output.getvalue())

    def test_stalled_stream_finishes_its_response_without_releasing_a_busy_gpu(self):
        started, release = threading.Event(), threading.Event()
        class Streamer:
            def __init__(self, tokenizer, **kwargs):
                self.timeout = kwargs.get("timeout")
                self.queue = queue.Queue()
            def __iter__(self):
                return self
            def __next__(self):
                value = self.queue.get(timeout=self.timeout)
                if value is None:
                    raise StopIteration
                return value
            def end(self):
                self.queue.put(None)
        class Handler:
            wfile = io.BytesIO()
            send_response = send_header = end_headers = lambda *args: None
        def stall(**kwargs):
            started.set()
            release.wait(3)
            kwargs["streamer"].end()
            return SimpleNamespace(shape=(1, 4))
        lock = threading.Lock()
        torch = SimpleNamespace(inference_mode=lambda: ExitStack(), cuda=SimpleNamespace(OutOfMemoryError=MemoryError))
        network = SimpleNamespace(generate=stall)
        meter = {}
        with patch.dict("sys.modules", transformers=SimpleNamespace(TextIteratorStreamer=Streamer, StoppingCriteriaList=list)), \
             patch.object(server, "GENERATION", lock), patch.object(server, "TORCH", torch), \
             patch.object(server, "NETWORK", network), \
             patch.object(server, "TOKENIZER", SimpleNamespace(pad_token_id=0, eos_token_id=1)), \
             patch.object(server, "prepare", return_value=({}, 2, 0)), \
             patch.dict(server.STATE, status="ready", error=None), \
             patch.object(server, "STREAM_MAX_SECONDS", .1, create=True), \
             patch.object(server, "STREAM_POLL_SECONDS", .05, create=True), \
             patch.object(server, "STREAM_CANCEL_GRACE_SECONDS", .05, create=True):
            response = threading.Thread(target=server.generate, args=({"messages":[{"role":"user", "content":"hello"}], "stream":True}, Handler(), meter))
            try:
                response.start()
                self.assertTrue(started.wait(1))
                response.join(.6)
                self.assertFalse(response.is_alive(), "A stalled generation kept its HTTP worker forever")
                self.assertEqual(meter["outcome"], "error")
                self.assertTrue(lock.locked(), "Never start a second GPU generation while the first is still running")
                self.assertEqual(server.STATE["status"], "error")
                self.assertIn(b"[DONE]", Handler.wfile.getvalue())
            finally:
                release.set()
                response.join(4)
                deadline = time.monotonic() + 1
                while lock.locked() and time.monotonic() < deadline:
                    time.sleep(.01)
                self.assertFalse(lock.locked(), "The finished worker must eventually release GPU ownership")

    def test_malformed_saved_usage_hour_names_cannot_break_request_accounting(self):
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(server, "USAGE_PATH", os.path.join(folder, "usage.json")):
            for hour in ("\u00b2", "9" * 5000):
                with self.subTest(hour_length=len(hour)):
                    value = server.empty_usage()
                    value["hours"][hour] = dict.fromkeys(server.COUNTERS, 0)
                    Path(server.USAGE_PATH).write_text(json.dumps(value))
                    with patch.object(server, "USAGE", server.load_usage()):
                        server.record_usage("api", "ok", 2, 1)
                        self.assertEqual(server.load_usage()["totals"]["requests"], 1)

    def test_checkpoint_requires_the_requested_immutable_revision(self):
        for actual in (None, "main", "a" * 39, "g" * 40, "b" * 40):
            with self.subTest(actual=actual), model_startup() as fixture, \
                 patch.object(server, "MODEL_REVISION", "a" * 40):
                fixture.hub.HfApi.return_value.model_info.return_value.sha = actual
                server.load_model()
                self.assertEqual(server.STATE["status"], "error")
                self.assertIn("revision", server.STATE["error"].lower())
                fixture.transformers.AutoConfig.from_pretrained.assert_not_called()
                fixture.hub.snapshot_download.assert_not_called()

    def test_malformed_saved_usage_cannot_break_request_accounting(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder, \
             patch.object(server, "USAGE_PATH", os.path.join(folder, "usage.json")):
            for change in ({"totals": {"requests": "broken"}},
                           {"sources": {"api": None}},
                           {"hours": {str(int(server.time.time() // 3600)): []}}):
                with self.subTest(change=change):
                    value = server.empty_usage()
                    value.update(change)
                    Path(server.USAGE_PATH).write_text(json.dumps(value))
                    with patch.object(server, "USAGE", server.load_usage()):
                        server.record_usage("api", "ok", 2, 1)
                        self.assertEqual(server.load_usage()["totals"]["requests"], 1)

    def test_slow_usage_reader_does_not_block_recording_model_requests(self):
        import tempfile
        replying, release = threading.Event(), threading.Event()

        class SlowReader(server.Handler):
            def reply(self, status, value):
                replying.set()
                release.wait(3)
                super().reply(status, value)

        with tempfile.TemporaryDirectory() as folder, \
             patch.object(server, "USAGE_PATH", os.path.join(folder, "usage.json")), \
             patch.object(server, "USAGE", server.empty_usage()):
            listener = server.Server(("127.0.0.1", 0), SlowReader)
            worker = threading.Thread(target=listener.serve_forever, daemon=True)
            worker.start()
            client = http.client.HTTPConnection("127.0.0.1", listener.server_port, timeout=4)
            recorded = threading.Event()
            recorder = None
            try:
                client.request("GET", "/v1/usage", headers={"Authorization": "Bearer " + "a" * 64})
                self.assertTrue(replying.wait(2))
                def record():
                    server.record_usage("api", "ok", 2, 1)
                    recorded.set()
                recorder = threading.Thread(target=record)
                recorder.start()
                self.assertTrue(recorded.wait(1), "A usage response held the lock while sending to its client")
                release.set()
                response = client.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(json.loads(response.read())["totals"]["requests"], 0)
                self.assertEqual(server.load_usage()["totals"]["requests"], 1)
            finally:
                release.set()
                if recorder:
                    recorder.join(4)
                client.close()
                listener.shutdown()
                listener.server_close()
                worker.join()

    def test_non_ascii_api_key_is_rejected_with_an_http_response(self):
        listener = server.Server(("127.0.0.1", 0), server.Handler)
        worker = threading.Thread(target=listener.serve_forever, daemon=True)
        worker.start()
        client = http.client.HTTPConnection("127.0.0.1", listener.server_port, timeout=2)
        try:
            client.request("GET", "/health", headers={"Authorization": "Bearer \u00e9"})
            response = client.getresponse()
            self.assertEqual(response.status, 401)
            self.assertEqual(json.loads(response.read())["error"]["message"], "A model API token is required")
        finally:
            client.close()
            listener.shutdown()
            listener.server_close()
            worker.join()

    def test_model_loading_uses_all_visible_gpus_when_more_than_one_is_attached(self):
        for count in [1, 2, 8]:
            with self.subTest(count=count), model_startup(count=count) as fixture:
                server.load_model()
                self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
                self.assertEqual(server.STATE["gpuCount"], count)
                fixture.install.assert_not_called()
                options = fixture.models.from_pretrained.call_args.kwargs
                self.assertEqual(options["device_map"], "balanced" if count > 1 else {"": 0})
                self.assertEqual(options["dtype"], "auto")
                self.assertFalse(options["trust_remote_code"])
                self.assertTrue(options["use_safetensors"])

    def test_model_start_upgrades_dependencies_that_cannot_recognize_qwen3_5(self):
        with model_startup(versions={"transformers": "4.57.2", "accelerate": "1.11.0"}) as fixture:
            server.load_model()
            self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
            fixture.install.assert_called_once()
            installed = fixture.install.call_args.args[0]
            self.assertIn("transformers==5.18.0", installed)
            self.assertIn("accelerate==1.15.0", installed)
            self.assertNotIn("torch==2.8.0", installed, "Do not replace the existing CUDA PyTorch")

    def test_dependency_failure_stops_before_model_downloads(self):
        with model_startup(versions={"transformers": "4.57.2", "accelerate": "1.11.0"}) as fixture:
            fixture.install.side_effect = server.subprocess.CalledProcessError(1, "pip")
            server.load_model()
            self.assertEqual(server.STATE["status"], "error")
            fixture.hub.HfApi.assert_not_called()
            fixture.models.from_pretrained.assert_not_called()

    def test_custom_decision_head_is_not_silently_ignored_by_the_chat_runner(self):
        with model_startup(files=("config.json", "model.safetensors", "joint_head_config.json", "joint_head.safetensors")) as fixture, \
             patch.object(server, "MODEL", "example/custom-decision"):
            server.load_model()
            self.assertEqual(server.STATE["status"], "error")
            self.assertIn("decision", server.STATE["error"])
            self.assertIn("example/custom-decision", server.STATE["error"])
            fixture.transformers.AutoConfig.from_pretrained.assert_not_called()
            fixture.transformers.AutoTokenizer.from_pretrained.assert_not_called()
            fixture.models.from_pretrained.assert_not_called()

    def test_non_chat_architecture_is_rejected_before_tokenizer_and_weights(self):
        with model_startup(config=SimpleNamespace(model_type="bert")) as fixture:
            server.load_model()
            self.assertEqual(server.STATE["status"], "error")
            self.assertIn("bert", server.STATE["error"])
            fixture.transformers.AutoTokenizer.from_pretrained.assert_not_called()
            fixture.models.from_pretrained.assert_not_called()

    def test_config_tokenizer_and_weights_use_the_same_checkpoint_revision(self):
        with model_startup() as fixture:
            server.load_model()
            self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
            self.assertEqual(fixture.hub.HfApi.return_value.model_info.call_count,2)
            fixture.hub.HfApi.return_value.model_info.assert_any_call(server.MODEL, revision=server.MODEL_REVISION, files_metadata=True, timeout=30)
            fixture.hub.HfApi.return_value.model_info.assert_any_call(server.MODEL, revision="a"*40, files_metadata=True, timeout=30)
            for loader in (fixture.transformers.AutoConfig, fixture.transformers.AutoTokenizer, fixture.models):
                options = loader.from_pretrained.call_args.kwargs
                self.assertEqual(options["revision"], "a" * 40)
                self.assertFalse(options["trust_remote_code"])
            self.assertIs(fixture.models.from_pretrained.call_args.kwargs["config"], fixture.config)

    def test_corrupt_direct_guest_weights_fail_before_model_load(self):
        with model_startup() as fixture:
            file=Path(fixture.hub.snapshot_download.return_value)/"model.safetensors"
            file.write_bytes(b"corrupt cache")
            server.load_model()
            self.assertEqual(server.STATE["status"],"error")
            self.assertIn("checksum",server.STATE["error"])
            fixture.models.from_pretrained.assert_not_called()

    def test_unverifiable_weights_fail_closed_before_model_load(self):
        with model_startup() as fixture:
            fixture.hub.HfApi.return_value.model_info.return_value.siblings[0].lfs=None
            server.load_model()
            self.assertEqual(server.STATE["status"],"error")
            self.assertIn("verifiable",server.STATE["error"])
            fixture.models.from_pretrained.assert_not_called()

    def test_nested_text_context_is_used_for_qwen3_5(self):
        for maximum, expected in [(262144, 32768), (2048, 2048)]:
            with self.subTest(maximum=maximum), patch.object(server, "NETWORK", SimpleNamespace(
                    config=SimpleNamespace(text_config=SimpleNamespace(max_position_embeddings=maximum)))):
                self.assertEqual(server.context_window(), expected)

    def test_chat_validation_rejects_unbounded_and_unsupported_inputs(self):
        valid = {"messages": [{"role": "user", "content": "hello"}]}
        self.assertEqual(server.validate_chat(valid)[1], 256)
        for extra in [{"max_tokens": 0}, {"max_tokens": True}, {"max_tokens": 4097}, {"stream": "yes"}, {"truncate": 1}, {"messages": [{"role": "system", "content": "only"}]}, {"temperature": float("nan")}, {"model": "other/model"}, {"messages": [{"role": "tool", "content": "x"}]}, {"messages": [{"role": "user", "content": "x" * 32769}]}]:
            with self.assertRaises(ValueError):
                server.validate_chat({**valid, **extra})

    def test_truncation_drops_whole_oldest_turns_and_keeps_the_system_prompt(self):
        class Inputs(dict):
            def to(self, device):
                return self
        class Shape:
            def __init__(self, n):
                self.shape = (1, n)
        class Tokenizer:
            chat_template = None
            def __call__(self, text, return_tensors):
                return Inputs(input_ids=Shape(len(text.split())))
        class Config:
            max_position_embeddings = 20
        server.TOKENIZER, server.NETWORK = Tokenizer(), type("Network", (), {"config": Config()})()
        try:
            conversation = [{"role": "system", "content": "be brief"}, {"role": "user", "content": "one two three"}, {"role": "assistant", "content": "four five six"}, {"role": "user", "content": "seven"}]
            with self.assertRaises(ValueError):
                server.prepare(conversation, 8, False)
            _, tokens, dropped = server.prepare(conversation, 8, True)
            self.assertEqual((tokens, dropped), (6, 2))
            with self.assertRaises(ValueError):
                server.prepare([{"role": "user", "content": "x " * 30}], 8, True)
            with self.assertRaises(ValueError):
                server.prepare(conversation, 20, True)
        finally:
            server.TOKENIZER = server.NETWORK = None

    def test_usage_is_recorded_persisted_and_reset_without_prompt_text(self):
        import tempfile
        with tempfile.TemporaryDirectory() as folder:
            server.USAGE_PATH, server.USAGE = os.path.join(folder, "usage.json"), server.empty_usage()
            server.record_usage("api", "ok", 120, 30, 1.5, True)
            server.record_usage("yougori", "busy")
            server.record_usage("api", "rejected")
            usage = server.load_usage()
            self.assertEqual(usage["totals"], {"requests": 2, "prompt_tokens": 120, "completion_tokens": 30, "errors": 1, "rejected": 1, "api": 1, "yougori": 1})
            self.assertEqual(usage["sources"], {"yougori": 1, "api": 1})
            self.assertEqual(sum(h["requests"] for h in usage["hours"].values()), 2)
            self.assertEqual([r["outcome"] for r in usage["recent"]], ["ok", "busy", "rejected"])
            self.assertEqual(set(usage["recent"][0]), {"time", "source", "outcome", "prompt_tokens", "completion_tokens", "seconds", "stream"})
            http = server.Server(("127.0.0.1", 0), server.Handler)
            worker = threading.Thread(target=http.serve_forever, daemon=True)
            worker.start()
            base = "http://127.0.0.1:" + str(http.server_port)
            headers = {"Authorization": "Bearer " + "a" * 64}
            try:
                with self.assertRaises(HTTPError):
                    urlopen(Request(base + "/v1/chat/completions", data=b"{}", headers={"Authorization": "Bearer wrong"}))
                with urlopen(Request(base + "/v1/usage", headers=headers)) as response:
                    self.assertEqual(json.load(response)["totals"]["rejected"], 2)
                with self.assertRaises(HTTPError) as denied:
                    urlopen(Request(base + "/v1/usage/reset", data=b"{}"))
                self.assertEqual(denied.exception.code, 401)
                urlopen(Request(base + "/v1/usage/reset", data=b"{}", headers=headers)).close()
                self.assertEqual(server.load_usage()["totals"]["requests"], 0)
            finally:
                http.shutdown()
                http.server_close()
                worker.join()

    def test_http_auth_status_and_readiness_do_not_load_a_model(self):
        http = server.Server(("127.0.0.1", 0), server.Handler)
        worker = threading.Thread(target=http.serve_forever, daemon=True)
        worker.start()
        base = "http://127.0.0.1:" + str(http.server_port)
        try:
            with self.assertRaises(HTTPError) as denied:
                urlopen(base + "/health")
            self.assertEqual(denied.exception.code, 401)
            headers = {"Authorization": "Bearer " + "a" * 64}
            with urlopen(Request(base + "/health", headers=headers)) as response:
                self.assertEqual(json.load(response)["status"], "installing")
            with self.assertRaises(HTTPError) as loading:
                urlopen(Request(base + "/v1/chat/completions", data=b'{}', headers=headers))
            self.assertEqual(loading.exception.code, 503)
            self.assertNotIn("a" * 64, loading.exception.read().decode())
        finally:
            http.shutdown()
            http.server_close()
            worker.join()

if __name__ == "__main__":
    unittest.main()
