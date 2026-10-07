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
    def test_repository_chat_template_is_tokenized_without_duplicate_special_tokens(self):
        tokenizer=Mock(chat_template="repository template")
        tokenizer.apply_chat_template.return_value="<bos>user: hello<turn>assistant:"
        class Inputs(dict):
            def to(self, device): return self
        tokenizer.return_value=Inputs(input_ids=SimpleNamespace(shape=(1,5)))
        with patch.object(server,"TOKENIZER",tokenizer), patch.object(server,"context_window",return_value=2048):
            server.prepare([{"role":"user","content":"hello"}],64,False)
        tokenizer.assert_called_once_with("<bos>user: hello<turn>assistant:",return_tensors="pt",add_special_tokens=False)

    def test_base_reply_delimiters_never_leak_across_stream_chunk_boundaries(self):
        for role in ("user", "Assistant", "system"):
            content="Hello, how can I help?\n"+role+": fabricated turn"
            for split in range(len(content)):
                reply=server.BaseReplyFilter()
                output=reply.push(content[:split])+reply.push(content[split:])+reply.push("",final=True)
                self.assertEqual(output,"Hello, how can I help?")
                self.assertTrue(reply.done)
        reply=server.BaseReplyFilter()
        self.assertEqual(reply.push("First line\nSecond line")+reply.push("",final=True),"First line\nSecond line")
        # Chat checkpoints bypass this base-model filter and preserve their response text.
        with patch.object(server,"TOKENIZER",SimpleNamespace(chat_template="official")):
            self.assertFalse(server.base_chat())

    def test_stream_stops_at_the_invented_phone_conversation_without_marking_it_cancelled(self):
        class Streamer:
            def __init__(self, *args, **kwargs): self.queue=queue.Queue()
            def __iter__(self): return self
            def __next__(self):
                value=self.queue.get(timeout=1)
                if value is None: raise StopIteration
                return value
            def end(self): self.queue.put(None)
        def generate(**kwargs):
            for text in ["Hello! How can I assist you today?", "\n\n  u", "ser: i want to get a new phone", "\nassistant: Great choice!"]:
                kwargs["streamer"].queue.put(text)
            self.assertTrue(kwargs["stopping_criteria"][0].event.wait(2))
            kwargs["streamer"].end()
            return SimpleNamespace(shape=(1,15))
        output=io.BytesIO()
        handler=SimpleNamespace(wfile=output,send_response=lambda *args:None,send_header=lambda *args:None,end_headers=lambda:None)
        torch=SimpleNamespace(inference_mode=lambda:ExitStack(),cuda=SimpleNamespace(OutOfMemoryError=MemoryError))
        meter={}
        with patch.dict("sys.modules",transformers=SimpleNamespace(TextIteratorStreamer=Streamer,StoppingCriteriaList=list)), \
             patch.object(server,"TOKENIZER",SimpleNamespace(chat_template=None,pad_token_id=0,eos_token_id=1)), \
             patch.object(server,"TORCH",torch),patch.object(server,"NETWORK",SimpleNamespace(generate=generate)), \
             patch.object(server,"prepare",return_value=({},2,0)),patch.object(server,"GENERATION",threading.Lock()):
            server.generate({"messages":[{"role":"user","content":"hi"}],"stream":True},handler,meter)
        events=[json.loads(line[6:]) for line in output.getvalue().decode().splitlines() if line.startswith("data: {")]
        text="".join(event["choices"][0]["delta"].get("content","") for event in events)
        self.assertEqual(text,"Hello! How can I assist you today?\n")
        self.assertNotIn("phone",text)
        self.assertEqual(meter["outcome"],"ok")
        self.assertEqual(events[-1]["choices"][0]["finish_reason"],"stop")

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
                    body = response.read()
                    self.assertNotIn(server.TOKEN.encode(), body)
                    self.assertNotIn(b"sensitive detail", body)
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
            def __call__(self, text, return_tensors, add_special_tokens):
                assert add_special_tokens is True
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

class NetworkPrecisionTests(unittest.TestCase):
    def test_original_precision_clears_previous_quantized_identity(self):
        with patch.dict(os.environ, YOUGORI_MODEL_PRECISION="original"), patch.dict(server.STATE, quant="NF4", precision="4bit"):
            self.assertEqual(server.inference_options(10, 1), {})
            self.assertIsNone(server.STATE["quant"])
            self.assertEqual(server.STATE["precision"], "original")

    def test_four_and_eight_bit_precision_are_exposed_in_health(self):
        for precision, quant in [("4bit", "NF4"), ("8bit", "INT8")]:
            module = SimpleNamespace(BitsAndBytesConfig=Mock(return_value=object()))
            with patch.dict(os.environ, YOUGORI_MODEL_PRECISION=precision), patch.dict(server.STATE), patch.object(server, "install"), patch.object(server, "TORCH", SimpleNamespace(bfloat16="bf16")), patch.dict("sys.modules", transformers=module):
                server.inference_options(10, 1)
                self.assertEqual(server.STATE["quant"], quant)

class TypedDecisionTransportTests(unittest.TestCase):
    def test_decision_sse_completes_with_json_and_real_input_usage(self):
        class Handler:
            def __init__(self): self.wfile = io.BytesIO(); self.headers = {}
            def send_response(self, status): self.status = status
            def send_header(self, name, value): self.headers[name] = value
            def end_headers(self): pass
        request = {"state": "new state", "questions": {"risk": {"type": "noul"}}}
        result = {"model": server.MODEL, "answers": {"risk": {"type": "noul", "noul": 0.9}}, "usage": {"input_tokens": 123, "output_tokens": 0}}
        def decide(value, meter):
            self.assertEqual(value, request)
            meter.update(outcome="ok", prompt_tokens=123, completion_tokens=0)
            return 200, result
        handler, meter = Handler(), {}
        messages = [{"role": "user", "content": '{"state":"old"}'}, {"role": "assistant", "content": "old answer"}, {"role": "user", "content": json.dumps(request)}]
        with patch.object(server, "DECISION_MODEL", True), patch.object(server, "FORMAT", "transformers"), patch.object(server, "generate_decision", side_effect=decide):
            self.assertIsNone(server.generate({"messages": messages, "stream": True}, handler, meter))
        data = handler.wfile.getvalue().decode()
        chunk = json.loads(data.splitlines()[0][6:])
        self.assertEqual(json.loads(chunk["choices"][0]["delta"]["content"]), result)
        self.assertEqual(chunk["choices"][0]["finish_reason"], "stop")
        self.assertEqual(chunk["usage"], {"prompt_tokens":123, "completion_tokens":0, "total_tokens":123})
        self.assertIn("data: [DONE]", data)
        self.assertTrue(meter["stream"])

    def test_invalid_decision_json_never_starts_inference(self):
        with patch.object(server, "DECISION_MODEL", True), patch.object(server, "FORMAT", "transformers"), patch.object(server, "generate_decision") as run:
            with self.assertRaises(ValueError): server.generate({"messages":[{"role":"user","content":"hello"}], "stream":True}, None, {})
            run.assert_not_called()

class VllmRunnerTests(unittest.TestCase):
    def test_authenticated_public_proxy_streams_vllm_and_hides_native_endpoints(self):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        captured=[]
        class Engine(BaseHTTPRequestHandler):
            def log_message(self,*args): pass
            def do_POST(self):
                if self.headers.get('Authorization') != 'Bearer '+server.LLAMA['key']:
                    self.send_response(401);self.end_headers();return
                body=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                captured.append((self.path,body))
                self.send_response(200)
                self.send_header('Content-Type','text/event-stream' if self.path.startswith('/v1/') else 'application/json')
                self.end_headers()
                if self.path=='/tokenize': self.wfile.write(b'{"count":5}')
                else:
                    for value in [{'choices':[{'delta':{'content':'Hello'},'finish_reason':None}]}, {'choices':[{'delta':{},'finish_reason':'stop'}]}, {'choices':[], 'usage':{'completion_tokens':1}}]:
                        self.wfile.write(b'data: '+json.dumps(value).encode()+b'\n\n')
                    self.wfile.write(b'data: [DONE]\n\n')
        native=ThreadingHTTPServer(('127.0.0.1',0),Engine)
        public=server.Server(('127.0.0.1',0),server.Handler)
        for listener in (native,public):threading.Thread(target=listener.serve_forever,daemon=True).start()
        try:
            with patch.object(server,'FORMAT','vllm'),patch.object(server,'DECISION_MODEL',False),patch.dict(server.LLAMA,port=native.server_port,context=2048),patch.dict(server.STATE,status='ready'),patch.object(server,'record_usage'):
                base='http://127.0.0.1:'+str(public.server_port)
                body=json.dumps({'messages':[{'role':'user','content':'Hello'}],'stream':True}).encode()
                with self.assertRaises(HTTPError) as unauthorized: urlopen(Request(base+'/v1/chat/completions',data=body),timeout=3)
                self.assertEqual(unauthorized.exception.code,401)
                self.assertEqual(captured,[])
                with self.assertRaises(HTTPError) as hidden: urlopen(Request(base+'/tokenize',data=b'{}',headers={'Authorization':'Bearer '+server.TOKEN}),timeout=3)
                self.assertEqual(hidden.exception.code,404)
                with urlopen(Request(base+'/v1/chat/completions',data=body,headers={'Authorization':'Bearer '+server.TOKEN}),timeout=3) as response:
                    content=response.read().decode()
                events=[json.loads(line[6:]) for line in content.splitlines() if line.startswith('data: {')]
                self.assertEqual(events[1]['choices'][0]['delta']['content'],'Hello')
                self.assertEqual(events[-1]['usage'],{'prompt_tokens':5,'completion_tokens':1,'total_tokens':6})
                self.assertIn('data: [DONE]',content)
                self.assertEqual([p for p,_ in captured],['/tokenize','/v1/chat/completions'])
                self.assertFalse(server.GENERATION.locked())
        finally:
            for listener in (public,native):listener.shutdown();listener.server_close()

    def test_moe_memory_counts_all_weights_before_any_download(self):
        cuda = SimpleNamespace(is_available=lambda:True, device_count=lambda:1,
            get_device_capability=lambda i:(12,0), mem_get_info=lambda i:(24*2**30,24*2**30))
        with self.assertRaisesRegex(RuntimeError, "No model weights were downloaded"):
            server.vllm_hardware({"num_attention_heads":48,"num_key_value_heads":4}, 78*2**30, cuda)
        cuda.device_count=lambda:2
        cuda.mem_get_info=lambda i:(80*2**30,80*2**30)
        self.assertEqual(server.vllm_hardware({"num_attention_heads":48,"num_key_value_heads":4},78*2**30,cuda),2)
        cuda.device_count=lambda:5
        with self.assertRaisesRegex(RuntimeError,"attention heads"):
            server.vllm_hardware({"num_attention_heads":48,"num_key_value_heads":4},78*2**30,cuda)

    def test_tokenization_and_generation_share_the_same_template_options(self):
        request={"messages":[{"role":"user","content":"Hello"}],"max_tokens":20,"stream":False}
        upstream={"choices":[{"message":{"content":"Hi"},"finish_reason":"stop"}],"usage":{"completion_tokens":2}}
        connection, response=Mock(),Mock(status=200)
        response.read.return_value=json.dumps(upstream).encode()
        def tokenize(path, body):
            self.assertEqual(path,"/tokenize")
            self.assertEqual(body["chat_template_kwargs"],{"enable_thinking":False})
            self.assertFalse(body["add_special_tokens"])
            return {"count":5}
        with patch.object(server,"FORMAT","vllm"),patch.dict(server.STATE,chatTemplate=False),patch.dict(server.LLAMA,context=2048),patch.object(server,"llama_json",side_effect=tokenize),patch.object(server,"llama",return_value=(connection,response)) as call:
            meter={}
            status,result=server.generate(request,None,meter)
        self.assertEqual(status,200)
        self.assertEqual(result["choices"][0]["message"]["content"],"Hi")
        self.assertEqual(result["usage"],{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7})
        forwarded=call.call_args.args[1]
        self.assertEqual(forwarded["model"],server.MODEL)
        self.assertEqual(forwarded["chat_template_kwargs"],{"enable_thinking":False})
        self.assertEqual(forwarded["chat_template"],server.BASE_TEMPLATE)
        self.assertIn("\nuser:",forwarded["stop"])
        self.assertNotIn("t_max_predict_ms",forwarded)
        connection.close.assert_called_once()
        self.assertFalse(server.GENERATION.locked())

    def test_partial_stream_is_an_error_and_not_a_completed_response(self):
        handler=Mock(wfile=io.BytesIO())
        response=io.BytesIO(b'data: {"choices":[{"delta":{"content":"partial"}}]}\n\n')
        meter={}
        server.stream_gguf(handler,response,10,30,{},meter)
        self.assertEqual(meter["outcome"],"error")
        self.assertIn(b'before a complete response',handler.wfile.getvalue())

    def test_kolibri_startup_pins_revision_and_keeps_private_engine_offline(self):
        with tempfile.TemporaryDirectory() as folder:
            config={"model_type":"kolibri1","architectures":["Kolibri1ForCausalLM"],"num_attention_heads":48,"num_key_value_heads":4,"max_position_embeddings":262144,"quantization_config":{"quant_method":"fp8"},"dtype":"bfloat16"}
            path=Path(folder)/'config.json';path.write_text(json.dumps(config))
            cuda=SimpleNamespace(is_available=lambda:True,device_count=lambda:2,get_device_capability=lambda i:(9,0),mem_get_info=lambda i:(80*2**30,80*2**30),get_device_name=lambda i:'H100')
            meta=SimpleNamespace(sha='a'*40,siblings=[SimpleNamespace(rfilename='model.safetensors',size=78*2**30)])
            hub=SimpleNamespace(HfApi=Mock(),hf_hub_download=Mock(return_value=str(path)))
            hub.HfApi.return_value.model_info.return_value=meta
            process=Mock();process.poll.return_value=None
            connection,response=Mock(),Mock(status=200)
            with ExitStack() as stack:
                stack.enter_context(patch.dict('sys.modules',torch=SimpleNamespace(cuda=cuda),huggingface_hub=hub))
                stack.enter_context(patch.object(server,'MODEL_REVISION','a'*40))
                stack.enter_context(patch.object(server.importlib.metadata,'version',return_value='0.29.0'))
                stack.enter_context(patch.object(server,'kolibri_plugin'))
                snapshot=stack.enter_context(patch.object(server,'verified_snapshot',return_value=folder))
                spawn=stack.enter_context(patch.object(server.subprocess,'Popen',return_value=process))
                stack.enter_context(patch.object(server,'llama',return_value=(connection,response)))
                stack.enter_context(patch.object(server.threading,'Thread'))
                stack.enter_context(patch.dict(server.STATE));stack.enter_context(patch.dict(server.LLAMA))
                stack.enter_context(patch.object(server,'ENGINE_PROCESS',None))
                stack.enter_context(patch.dict(os.environ,HF_TOKEN='private-hf',YOUGORI_MODEL_TOKEN='private-model'))
                server.load_vllm()
                self.assertEqual(server.STATE['runner'],'vllm')
                self.assertEqual(server.STATE['quant'],'FP8')
                self.assertEqual(server.STATE['context'],32768)
                snapshot.assert_called_once_with('a'*40)
                args=spawn.call_args.args[0];env=spawn.call_args.kwargs['env']
                self.assertIn('--reasoning-parser',args);self.assertIn('kolibri1',args)
                self.assertNotIn('--trust-remote-code',args);self.assertNotIn('--enable-log-requests',args)
                self.assertNotIn('HF_TOKEN',env);self.assertNotIn('YOUGORI_MODEL_TOKEN',env)
                self.assertEqual(env['HF_HUB_OFFLINE'],'1')
                self.assertEqual(env['VLLM_PLUGINS'],'aleph_alpha_inference')
                self.assertEqual(args[args.index('--host')+1],'127.0.0.1')
                self.assertEqual(spawn.call_args.kwargs['stdout'],server.subprocess.DEVNULL)
                self.assertEqual(spawn.call_args.kwargs['stderr'],server.subprocess.DEVNULL)
                meta.sha='b'*40
                snapshot.reset_mock()
                with self.assertRaisesRegex(RuntimeError,'immutable revision'): server.load_vllm()
                snapshot.assert_not_called()

class FreeListenerTests(unittest.TestCase):
    def records(self,path):
        deadline=time.monotonic()+2
        while time.monotonic()<deadline:
            data=path.read_text() if path.exists() else ""
            if data.endswith("\n"): return json.loads(data)
            time.sleep(0.01)
        self.fail("Inference recording was not saved")
    @contextmanager
    def listener(self, generate=None):
        with ExitStack() as stack:
            folder=stack.enter_context(tempfile.TemporaryDirectory())
            path=Path(folder)/"yougori-listen"/"requests.jsonl"
            stack.enter_context(patch.object(server,"LISTEN_PATH",str(path)))
            stack.enter_context(patch.object(server,"LISTEN",{"enabled":False,"expires":0.0,"generation":0,"error":None}))
            stack.enter_context(patch.object(server,"record_usage"))
            stack.enter_context(patch.dict(server.STATE,status="ready"))
            if generate: stack.enter_context(patch.object(server,"generate",side_effect=generate))
            http=server.Server(("127.0.0.1",0),server.Handler)
            worker=threading.Thread(target=http.serve_forever,daemon=True);worker.start()
            base="http://127.0.0.1:"+str(http.server_port)
            def request(endpoint, body=None, authorized=True):
                headers={"Authorization":"Bearer "+server.TOKEN} if authorized else {}
                return urlopen(Request(base+endpoint,data=json.dumps(body).encode() if body is not None else None,headers=headers),timeout=3)
            try: yield path,request
            finally: http.shutdown();http.server_close();worker.join()

    def test_recording_is_off_by_default_and_requires_authenticated_free_configuration(self):
        def generate(body,handler,meter):
            meter.update(outcome="ok",prompt_tokens=5,completion_tokens=2)
            return 200,{"choices":[{"message":{"content":"private reply"}}]}
        body={"messages":[{"role":"user","content":"private prompt"}]}
        with self.listener(generate) as (path,request):
            request("/v1/chat/completions",body).close()
            self.assertFalse(path.exists())
            for config,auth,status in [({"enabled":True,"mode":"free"},False,401),({"enabled":True,"mode":"paid"},True,400),({"enabled":True,"mode":"free","token":"secret"},True,400)]:
                with self.assertRaises(HTTPError) as error: request("/v1/listen/config",config,auth)
                self.assertEqual(error.exception.code,status)
            request("/v1/listen/config",{"enabled":True,"mode":"free"}).close()
            request("/v1/chat/completions",body).close()
            value=self.records(path)
            self.assertEqual(value["request"],body)
            self.assertEqual(value["response"]["choices"][0]["message"]["content"],"private reply")
            self.assertNotIn(server.TOKEN,path.read_text())
            size=path.stat().st_size
            request("/v1/listen/config",{"enabled":False,"mode":"paid"}).close()
            request("/v1/chat/completions",body).close()
            self.assertEqual(path.stat().st_size,size)
            with self.assertRaises(HTTPError) as error: request("/v1/listen/requests")
            self.assertEqual(error.exception.code,404,"Recording files must not be public API endpoints")

    def test_streamed_reply_and_cancelled_partial_output_are_recorded_without_headers(self):
        def generate(body,handler,meter):
            meter.update(outcome="cancelled",stream=True,prompt_tokens=6,completion_tokens=2)
            handler.send_response(200);handler.send_header("Content-Type","text/event-stream");handler.end_headers()
            for content in ["hello ","world"]:
                event={"choices":[{"delta":{"content":content}}]}
                handler.wfile.write(("data: "+json.dumps(event)+"\n\n").encode())
            handler.wfile.write(b"data: [DONE]\n\n")
        with self.listener(generate) as (path,request):
            request("/v1/listen/config",{"enabled":True,"mode":"free"}).close()
            request("/v1/chat/completions",{"messages":[{"role":"user","content":"hi"}],"stream":True}).read()
            value=self.records(path)
            self.assertEqual(value["response"]["content"],"hello world")
            self.assertEqual(value["outcome"],"cancelled")
            self.assertEqual(len(value["response"]["events"]),2)
            self.assertNotIn("Content-Type",path.read_text())

    def test_typed_decisions_and_storage_errors_do_not_break_inference(self):
        def decide(body,meter):
            meter.update(outcome="ok",prompt_tokens=42,completion_tokens=0)
            return 200,{"answers":{"risk":0.7}}
        with self.listener() as (path,request), patch.object(server,"DECISION_MODEL",True), patch.object(server,"generate_decision",side_effect=decide):
            request("/v1/listen/config",{"enabled":True,"mode":"free"}).close()
            body={"model":server.MODEL,"state":"account activity","questions":{"risk":{"type":"score"}}}
            request("/v1/systemone",body).read()
            value=self.records(path);self.assertEqual(value["request"],body);self.assertEqual(value["response"]["answers"]["risk"],0.7)
            with patch.object(server,"listen_file",side_effect=OSError("caller content must not leak")):
                result=json.load(request("/v1/systemone",body));self.assertEqual(result["answers"]["risk"],0.7)
                self.assertEqual(server.listen_snapshot()["error"],"Cannot write recording history; check model storage")

    def test_lease_expiry_rotation_and_disable_discard_inflight_recording(self):
        with self.listener() as (path,request):
            server.configure_listen({"enabled":True,"mode":"free"})
            body={"messages":[{"role":"user","content":"hello"}]};meter={"outcome":"ok"}
            def capture():
                value=server.ListenCapture(io.BytesIO());value.write(b'HTTP/1.1 200 OK\r\nAuthorization: Bearer secret\r\n\r\n{"answer":"reply"}');return value
            with patch.object(server,"LISTEN_MAX_FILE",256):
                for _ in range(8): server.record_listen(capture(),body,"api","/v1/chat/completions",meter,1)
            self.assertEqual(len(list(path.parent.glob("requests.jsonl*"))),5)
            for item in path.parent.glob("requests.jsonl*"): self.assertNotIn("Bearer",item.read_text())
            old=capture();size=path.stat().st_size
            server.configure_listen({"enabled":False,"mode":"paid"})
            server.record_listen(old,body,"api","/v1/chat/completions",meter,1)
            self.assertEqual(path.stat().st_size,size)
            server.configure_listen({"enabled":True,"mode":"free"})
            server.LISTEN["expires"]=0
            self.assertFalse(server.listen_snapshot()["enabled"])
            self.assertIsNone(capture().generation)

    def test_oversized_output_is_bounded_and_marked_truncated(self):
        with self.listener() as (path,request):
            server.configure_listen({"enabled":True,"mode":"free"})
            with patch.object(server,"LISTEN_MAX_RESPONSE",128):
                capture=server.ListenCapture(io.BytesIO());capture.write(b'HTTP/1.1 200 OK\r\n\r\n'+b'x'*1000)
                self.assertEqual(len(capture.data),128);self.assertTrue(capture.truncated)
            server.record_listen(capture,{"messages":[{"role":"user","content":"hi"}]},"api","/v1/chat/completions",{"outcome":"ok"},1)
            self.assertTrue(self.records(path)["truncated"])

if __name__ == "__main__":
    unittest.main()
