import ast
import base64
import importlib.util
import http.client
import io
import json
import hashlib
import tempfile
import zlib
import os
from pathlib import Path
import shutil
import select
import socket
import sys
import threading
import unittest
import queue
import time
from contextlib import contextmanager, ExitStack
from unittest.mock import Mock, patch
from types import FunctionType, SimpleNamespace
from urllib.request import Request, urlopen
from urllib.error import HTTPError

os.environ["YOUGORI_MODEL"] = "example/test-model"
os.environ["YOUGORI_MODEL_TOKEN"] = "a" * 64
os.environ["YOUGORI_MODEL_ADMIN_TOKEN"] = "b" * 64
spec = importlib.util.spec_from_file_location("model_server", Path(__file__).parents[1] / "src-tauri/src/model_server.py")
server = importlib.util.module_from_spec(spec)
spec.loader.exec_module(server)
# The bundled verifier exactly as model_runner.rs ships it (registry_source(): CRLF normalized to LF).
VERIFIER_SOURCE = base64.b64encode(zlib.compress((Path(__file__).parents[1] / "src-tauri/src/model_runner/registry_snapshot.py").read_bytes().replace(b"\r\n", b"\n"))).decode("ascii")
LOCAL_VLLM_CONFIG = {"model_type":"llama", "architectures":["LlamaForCausalLM"], "num_attention_heads":8, "num_key_value_heads":8,
                     "max_position_embeddings":4096, "torch_dtype":"bfloat16"}


def local_vllm_startup(stack, root):
    """Stub load_vllm's neighbours for a verified local mount (YOUGORI_MODEL_PATH with a manifest of fake
    safetensors files). The Hugging Face hub, the snapshot download and the Kolibri plugin fail the test if touched."""
    contents = {"config.json":json.dumps(LOCAL_VLLM_CONFIG).encode(), "model-00001-of-00002.safetensors":b"fixture weights one",
                "model-00002-of-00002.safetensors":b"fixture weights two", "tokenizer_config.json":b'{"chat_template":"fixture"}'}
    for name, data in contents.items(): (root/name).write_bytes(data)
    files = [{"name":name, "size":len(data), "sha256":hashlib.sha256(data).hexdigest()} for name, data in contents.items()]
    revision = hashlib.sha256(json.dumps(files).encode()).hexdigest()  # model_runner/local.rs: the 64-hex manifest digest
    hub = SimpleNamespace(HfApi=Mock(side_effect=AssertionError("HfApi constructed on the local path")),
                          hf_hub_download=Mock(side_effect=AssertionError("hf_hub_download on the local path")))
    cuda = SimpleNamespace(is_available=lambda:True, device_count=lambda:1, get_device_capability=lambda i:(12,0),
                           mem_get_info=lambda i:(20*2**30, 24*2**30), get_device_name=lambda i:"fixture GPU")
    registry = SimpleNamespace(ModelRegistry=SimpleNamespace(get_supported_archs=lambda:["LlamaForCausalLM", "Qwen3ForCausalLM"]))
    stack.enter_context(patch.dict("sys.modules", {"torch":SimpleNamespace(cuda=cuda), "huggingface_hub":hub, "vllm":SimpleNamespace(),
        "vllm.model_executor":SimpleNamespace(), "vllm.model_executor.models":SimpleNamespace(), "vllm.model_executor.models.registry":registry}))
    stack.enter_context(patch.dict(os.environ, YOUGORI_REGISTRY_SOURCE=VERIFIER_SOURCE, YOUGORI_LOCAL_MANIFEST=json.dumps({"revision":revision, "files":files})))
    for name, value in (("MODEL_PATH", str(root)), ("MODEL_REVISION", revision), ("REGISTRY_VERIFIED", None), ("VLLM_PREPARED", None), ("ENGINE_PROCESS", None)):
        stack.enter_context(patch.object(server, name, value))
    stack.callback(lambda: [server.__dict__.pop(key, None) for key in ("MODEL_SNAPSHOT_ROOT", "MODEL_SNAPSHOT_FILES")])
    stack.enter_context(patch.object(server.importlib.metadata, "version", return_value=server.VLLM_VERSION))
    stack.enter_context(patch.object(server, "download_snapshot", side_effect=AssertionError("snapshot download on the local path")))
    stack.enter_context(patch.object(server, "kolibri_plugin", side_effect=AssertionError("Kolibri plugin for a Llama checkpoint")))
    stack.enter_context(patch.dict(server.STATE)); stack.enter_context(patch.dict(server.LLAMA))
    stack.enter_context(patch.object(server, "llama", return_value=(Mock(), Mock(status=200))))
    stack.enter_context(patch.object(server.threading, "Thread"))
    return SimpleNamespace(hub=hub, revision=revision, files=files,
        weight_bytes=sum(len(data) for name, data in contents.items() if name.endswith(".safetensors")),
        spawn=stack.enter_context(patch.object(server.subprocess, "Popen", side_effect=lambda *args, **kwargs: Mock(poll=Mock(return_value=None)))),
        admission=stack.enter_context(patch.object(server, "gpu_before_load")),
        hardware=stack.enter_context(patch.object(server, "vllm_hardware", wraps=server.vllm_hardware)),
        verify=stack.enter_context(patch.object(server, "verify_file", wraps=server.verify_file)))

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
        is_available=lambda: True, device_count=lambda: count, get_device_name=lambda index: "Test GPU",
        empty_cache=Mock()))
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

    def test_a_measured_transformers_stream_records_every_token_at_the_flush_that_carried_it(self):
        class Streamer:
            """Transformers' TextIteratorStreamer as far as the server uses it: one queued piece
            per generated token (empty until a word is complete), one more at the end."""
            def __init__(self, tokenizer, skip_prompt=False, **kwargs):
                self.queue, self.skip_prompt, self.next_tokens_are_prompt = queue.Queue(), skip_prompt, True
                self.pieces = iter(["", "Hello", "", " there", "!", ""])
            def __iter__(self): return self
            def __next__(self):
                value = self.queue.get(timeout=1)
                if value is None: raise StopIteration
                return value
            def put(self, value):
                if self.skip_prompt and self.next_tokens_are_prompt:
                    self.next_tokens_are_prompt = False
                    return
                self.queue.put(next(self.pieces))
            def end(self):
                self.queue.put("")
                self.queue.put(None)
        def generate(**kwargs):
            streamer = kwargs["streamer"]
            streamer.put(SimpleNamespace(shape=(1, 2)))  # the prompt
            for _ in range(6):  # five pieces of text and the end of sequence
                streamer.put(SimpleNamespace(shape=(1,)))
            streamer.end()
            return SimpleNamespace(shape=(1, 8))
        trace_run = {"start": time.monotonic_ns()}
        trace = server.TokenEmissionTrace(server.RUNNER_TIMINGS, trace_run, "transformers-streamer-flush")
        output = io.BytesIO()
        handler = SimpleNamespace(wfile=output, send_response=lambda *args: None, send_header=lambda *args: None, end_headers=lambda: None)
        torch = SimpleNamespace(inference_mode=lambda: ExitStack(), cuda=SimpleNamespace(OutOfMemoryError=MemoryError))
        meter = {}
        with patch.dict("sys.modules", transformers=SimpleNamespace(TextIteratorStreamer=Streamer, StoppingCriteriaList=list)), \
             patch.object(server, "TOKENIZER", SimpleNamespace(chat_template="official", pad_token_id=0, eos_token_id=1)), \
             patch.object(server, "TORCH", torch), patch.object(server, "NETWORK", SimpleNamespace(generate=generate)), \
             patch.object(server, "prepare", return_value=({}, 2, 0)), patch.object(server, "GENERATION", threading.Lock()), \
             patch.object(server.RUNNER_TIMINGS, "token_trace", return_value=trace) as token_trace:
            server.generate({"messages": [{"role": "user", "content": "hi"}], "stream": True}, handler, meter)
        token_trace.assert_called_once_with("transformers-streamer-flush")
        events = [json.loads(line[6:]) for line in output.getvalue().decode().splitlines() if line.startswith("data: {")]
        self.assertEqual("".join(e["choices"][0]["delta"].get("content", "") for e in events), "Hello there!")
        self.assertEqual(meter["outcome"], "ok")
        # Six generated tokens: two crossed the flush of "Hello", two of " there", one of "!",
        # and the end of sequence the finishing chunk's flush; nothing unaccounted.
        record = trace.record
        self.assertEqual(record["outputTokens"], 6)
        self.assertEqual(len(record["emittedMs"]), 6)
        self.assertTrue(record["complete"])
        emitted = record["emittedMs"]
        self.assertEqual(emitted[0], emitted[1])
        self.assertEqual(emitted[2], emitted[3])
        self.assertEqual(emitted, sorted(emitted))
        # A trace whose pieces outran their counts, or a base model's held-back text, is not exact.
        broken = server.TokenEmissionTrace(server.RUNNER_TIMINGS, trace_run, "transformers-streamer-flush")
        broken.flush(2, None)
        broken.finish(True)
        self.assertFalse(broken.record["complete"])
        with self.assertRaises(ValueError):
            server.TokenEmissionTrace(server.RUNNER_TIMINGS, trace_run, "invented-source")
        self.assertIn("transformers-streamer-flush", server.TokenEmissionTrace.SOURCES)

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
                    # These exceptions originate in the model's generation
                    # thread, after request validation. They are server errors.
                    self.assertEqual(response.status, 500)
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

    def test_a_transformers_grant_caps_memory_before_weights_load_at_original_precision(self):
        gib = 2 ** 30
        grant = {"YOUGORI_GPU_CAPACITY_POLICY": "local-single-transformers-v1", "YOUGORI_GPU_CAPACITY_BYTES": str(14 * gib),
                 "YOUGORI_GPU_CAPACITY_CONTEXT": "1024"}
        for policy in ("transformers", None, "local-single-vllm-v1"):
            with self.subTest(policy=policy), model_startup() as fixture, patch.object(server, "GPU_CAPACITY", None), \
                 patch.object(server, "GPU_CAPACITY_CONTEXT", None), patch.dict(os.environ, YOUGORI_MODEL_PRECISION="auto"):
                for name in grant:
                    os.environ.pop(name, None)
                if policy == "transformers":
                    os.environ.update(grant)
                elif policy is not None:
                    os.environ.update(grant, YOUGORI_GPU_CAPACITY_POLICY=policy)
                # 10 GiB of weights and 6 GiB free: "auto" alone would load them at 4-bit.
                server.STATE["download"] = {"totalBytes": 10 * gib}
                cuda = sys.modules["torch"].cuda
                cuda.mem_get_info = lambda index: (6 * gib if policy == "transformers" else 20 * gib, 24 * gib)
                cuda.set_per_process_memory_fraction = Mock(
                    side_effect=lambda fraction, device: self.assertFalse(fixture.models.from_pretrained.called))
                server.load_model()
                self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
                self.assertNotIn("quantization_config", fixture.models.from_pretrained.call_args.kwargs)
                self.assertEqual(server.STATE["precision"], "original")
                self.assertIsNone(server.STATE["quant"])
                if policy == "transformers":
                    cuda.set_per_process_memory_fraction.assert_called_once_with(14 / 24, 0)
                    self.assertEqual(server.gpu_snapshot()["capacityBytes"], 14 * gib)
                    # The ready state serves the context the grant covers, not the checkpoint's 2,048.
                    self.assertEqual(server.gpu_snapshot()["capacityContext"], 1024)
                    self.assertEqual(server.STATE["context"], 1024)
                else:
                    cuda.set_per_process_memory_fraction.assert_not_called()
                    self.assertIsNone(server.gpu_snapshot()["capacityBytes"])
                    self.assertIsNone(server.gpu_snapshot()["capacityContext"])
                    self.assertEqual(server.STATE["context"], 2048)

    def test_a_grants_terms_shorten_the_stamp_and_never_widen_it(self):
        gib = 2 ** 30
        stamp = {"YOUGORI_GPU_CAPACITY_POLICY": "local-single-transformers-v1", "YOUGORI_GPU_CAPACITY_BYTES": str(14 * gib),
                 "YOUGORI_GPU_CAPACITY_CONTEXT": "9728"}
        with patch.dict(os.environ, stamp):
            with patch.object(server, "GPU_GRANT_TERMS", None):
                self.assertEqual(server.gpu_capacity_demand(), (14 * gib, 9728))
            # A grant beside resident models covers less: the runner holds itself to the grant.
            with patch.object(server, "GPU_GRANT_TERMS", (6 * gib, 4096)):
                self.assertEqual(server.gpu_capacity_demand(), (6 * gib, 4096))
            # A grant can never widen the stamp, whatever it says.
            with patch.object(server, "GPU_GRANT_TERMS", (20 * gib, 32768)):
                self.assertEqual(server.gpu_capacity_demand(), (14 * gib, 9728))
        self.assertIsNone(server.gpu_grant_terms({"action": "grant"}))
        self.assertEqual(server.gpu_grant_terms({"bytes": 6 * gib, "context": 4096}), (6 * gib, 4096))
        for body in ({"bytes": 6 * gib}, {"context": 4096}, {"bytes": "6", "context": 4096},
                     {"bytes": 0, "context": 4096}, {"bytes": 6 * gib, "context": 2 ** 21}, {"bytes": True, "context": 4096}):
            with self.subTest(body=body), self.assertRaises(ValueError):
                server.gpu_grant_terms(body)

    def test_a_trim_holds_the_runner_to_the_asked_grant_or_to_what_it_holds_plus_a_margin_never_wider(self):
        gib, mib = 2 ** 30, 2 ** 20
        fraction = Mock()
        cuda = SimpleNamespace(empty_cache=Mock(), memory_reserved=lambda index: 2 * gib,
                               mem_get_info=lambda index: (10 * gib, 24 * gib), set_per_process_memory_fraction=fraction)
        with patch.object(server, "TORCH", SimpleNamespace(cuda=cuda)), patch.object(server, "GPU_CAPACITY", 14 * gib), \
             patch.object(server, "GPU_CAPACITY_CONTEXT", 9728), patch.object(server, "GPU_GRANT_TERMS", None), \
             patch.object(server, "GPU_ACTIVE", 0), patch.dict(server.STATE, context=9728):
            # Idle: the asked terms are accepted when they exceed what is held plus 64 MiB.
            self.assertEqual(server.gpu_trim((6 * gib, 4096)), (6 * gib, 4096))
            fraction.assert_called_with(6 / 24, 0)
            self.assertEqual((server.GPU_CAPACITY, server.GPU_CAPACITY_CONTEXT, server.GPU_GRANT_TERMS), (6 * gib, 4096, (6 * gib, 4096)))
            self.assertEqual(server.STATE["context"], 4096)
            cuda.empty_cache.assert_called()
            # Asked below what is held: what is held plus the idle margin is accepted instead.
            self.assertEqual(server.gpu_trim((gib, 2048)), (2 * gib + 64 * mib, 2048))
            # Never wider than the current grant, in bytes or context.
            self.assertEqual(server.gpu_trim((20 * gib, 32768)), (2 * gib + 64 * mib, 2048))
        with patch.object(server, "TORCH", SimpleNamespace(cuda=cuda)), patch.object(server, "GPU_CAPACITY", 14 * gib), \
             patch.object(server, "GPU_CAPACITY_CONTEXT", 9728), patch.object(server, "GPU_GRANT_TERMS", None), \
             patch.object(server, "GPU_ACTIVE", 1), patch.dict(server.STATE, context=9728):
            # Busy: a quarter of what is held, at least 256 MiB, stays as margin.
            self.assertEqual(server.gpu_trim((gib, 4096)), (2 * gib + 512 * mib, 4096))
        with patch.object(server, "TORCH", None), patch.object(server, "GPU_CAPACITY", 14 * gib), patch.object(server, "GPU_CAPACITY_CONTEXT", 9728):
            with self.assertRaises(server.GPUControlConflict):
                server.gpu_trim((6 * gib, 4096))

    def test_a_grow_raises_the_cap_and_context_to_the_terms_between_what_is_held_and_the_stamp(self):
        gib = 2 ** 30
        stamp = {"YOUGORI_GPU_CAPACITY_POLICY": "local-single-transformers-v1", "YOUGORI_GPU_CAPACITY_BYTES": str(14 * gib),
                 "YOUGORI_GPU_CAPACITY_CONTEXT": "9728"}
        fraction = Mock()
        cuda = SimpleNamespace(mem_get_info=lambda index: (10 * gib, 24 * gib), set_per_process_memory_fraction=fraction)
        network = SimpleNamespace(config=SimpleNamespace(max_position_embeddings=32768))
        held = (6 * gib, 4096)
        with patch.dict(os.environ, stamp), patch.object(server, "TORCH", SimpleNamespace(cuda=cuda)), \
             patch.object(server, "NETWORK", network), patch.object(server, "GPU_CAPACITY", held[0]), \
             patch.object(server, "GPU_CAPACITY_CONTEXT", held[1]), patch.object(server, "GPU_GRANT_TERMS", held), \
             patch.dict(server.STATE, context=4096):
            # Past the stamp, or below what is held, is refused and nothing changes.
            for terms in ((15 * gib, 8192), (10 * gib, 16384), (5 * gib, 8192), (10 * gib, 2048)):
                with self.subTest(terms=terms), self.assertRaises(ValueError):
                    server.gpu_grow(terms)
            fraction.assert_not_called()
            self.assertEqual((server.GPU_CAPACITY, server.GPU_CAPACITY_CONTEXT, server.STATE["context"]), (6 * gib, 4096, 4096))
            # Within them: the cap, the grant terms and the context served rise to exactly the terms.
            self.assertEqual(server.gpu_grow((10 * gib, 8192)), (10 * gib, 8192))
            fraction.assert_called_with(10 / 24, 0)
            self.assertEqual((server.GPU_CAPACITY, server.GPU_CAPACITY_CONTEXT, server.GPU_GRANT_TERMS), (10 * gib, 8192, (10 * gib, 8192)))
            self.assertEqual(server.STATE["context"], 8192)
            self.assertEqual(server.gpu_capacity_demand(), (10 * gib, 8192))
            # Up to the whole stamp.
            self.assertEqual(server.gpu_grow((14 * gib, 9728)), (14 * gib, 9728))
            self.assertEqual(server.STATE["context"], 9728)
        # Without a stamp or a loaded, capped model there is nothing to grow.
        with patch.object(server, "TORCH", SimpleNamespace(cuda=cuda)), patch.object(server, "GPU_CAPACITY", held[0]), \
             patch.object(server, "GPU_CAPACITY_CONTEXT", held[1]), patch.dict(os.environ, {"YOUGORI_GPU_CAPACITY_POLICY": ""}):
            with self.assertRaises(server.GPUControlConflict):
                server.gpu_grow((10 * gib, 8192))
        with patch.dict(os.environ, stamp), patch.object(server, "TORCH", SimpleNamespace(cuda=cuda)), \
             patch.object(server, "GPU_CAPACITY", None), patch.object(server, "GPU_CAPACITY_CONTEXT", None):
            with self.assertRaises(server.GPUControlConflict):
                server.gpu_grow((10 * gib, 8192))

    def test_the_grow_control_is_fenced_and_answers_with_the_terms_it_holds(self):
        gib = 2 ** 30
        grown = Mock(return_value=(10 * gib, 8192))
        with patch.object(server, "gpu_grow", grown), patch.object(server, "GPU_ENABLED", True), \
             patch.object(server, "GPU_LOADING", False), patch.object(server, "GPU_RELEASE_UNCERTAIN", False), \
             patch.object(server, "gpu_snapshot", lambda refresh=True: {"resident": True}), patch.object(server, "gpu_refresh", lambda: None), \
             patch.object(server, "gpu_publish", lambda force=False: None):
            # An unfenced grow, or one without terms, is refused before anything grows.
            with self.assertRaises(ValueError):
                server.gpu_control({"action": "grow", "bytes": 10 * gib, "context": 8192})
            fence = {"expectedInstanceId": server.GPU_INSTANCE_ID, "expectedSequence": server.GPU_SEQUENCE}
            with self.assertRaises(ValueError):
                server.gpu_control({"action": "grow", **fence})
            grown.assert_not_called()
            answer = server.gpu_control({"action": "grow", "bytes": 10 * gib, "context": 8192, **fence})
            grown.assert_called_once_with((10 * gib, 8192))
            self.assertEqual((answer["grown"], answer["terms"]), (True, {"bytes": 10 * gib, "context": 8192}))
            self.assertEqual(answer["controlAck"]["action"], "grow")
        with patch.object(server, "gpu_grow", grown), patch.object(server, "GPU_ENABLED", True), \
             patch.object(server, "GPU_LOADING", True), patch.object(server, "gpu_refresh", lambda: None), \
             patch.object(server, "gpu_publish", lambda force=False: None):
            fence = {"expectedInstanceId": server.GPU_INSTANCE_ID, "expectedSequence": server.GPU_SEQUENCE}
            with self.assertRaises(server.GPUControlConflict):
                server.gpu_control({"action": "grow", "bytes": 10 * gib, "context": 8192, **fence})

    def test_a_named_helper_bundle_is_read_from_its_bind_and_the_rest_keeps_source_injection(self):
        with tempfile.TemporaryDirectory() as root:
            entry = Path(root) / "gpu-optimizer" / "gpu_optimizer.py"
            entry.parent.mkdir(parents=True)
            entry.write_bytes(b"FROM_BUNDLE = True\n")
            outside = Path(root).parent / "outside.py"
            injected = base64.b64encode(zlib.compress(b"FROM_SOURCE = True\n")).decode()
            named = json.dumps({"gpu-optimizer": {"entry": str(entry), "pin": "pin-1"}})
            with patch.object(server, "HELPERS_ROOT", root), patch.dict(os.environ, YOUGORI_HELPERS=named), patch.dict(server.HELPERS_SERVED, clear=True):
                self.assertEqual(server.helper_bytes("gpu-optimizer", injected), b"FROM_BUNDLE = True\n")
                self.assertEqual(server.HELPERS_SERVED["gpu-optimizer"]["served"], "bundle")
                self.assertEqual(server.HELPERS_SERVED["gpu-optimizer"]["pin"], "pin-1")
                # A helper the variable does not name keeps the injected source.
                self.assertEqual(server.helper_bytes("publisher-routes", injected), b"FROM_SOURCE = True\n")
                self.assertEqual(server.HELPERS_SERVED["publisher-routes"]["served"], "source_injection")
                with self.assertRaises(RuntimeError):
                    server.helper_bytes("clef-adapter", None)
            # An entry outside the bind is refused, whatever the variable says.
            escaped = json.dumps({"gpu-optimizer": {"entry": str(outside), "pin": "pin-2"}})
            with patch.object(server, "HELPERS_ROOT", root), patch.dict(os.environ, YOUGORI_HELPERS=escaped), patch.dict(server.HELPERS_SERVED, clear=True):
                with self.assertRaises(RuntimeError):
                    server.helper_bytes("gpu-optimizer", injected)
            # A malformed variable refuses every bundle rather than guessing.
            for bad in ("not json", json.dumps(["x"]), json.dumps({"gpu-optimizer": {"entry": 1, "pin": "p"}}), json.dumps({"gpu-optimizer": {"entry": "e", "pin": "p", "extra": 1}})):
                with patch.dict(os.environ, YOUGORI_HELPERS=bad), self.assertRaises(RuntimeError):
                    server.bundled_helpers()
            with patch.dict(os.environ, YOUGORI_HELPERS=""):
                self.assertEqual(server.bundled_helpers(), {})

    BACKENDS = (Path(__file__).parents[1] / "src-tauri/src/model_runner/engine_backends.py").read_bytes()

    def without_backends(self, file=None):
        """The server's names without the engine backends' (as a runner has them before its first
        GGUF or vLLM load) and load_backends bound to them; `file` stands for the server's own path."""
        defined = set()
        for node in ast.parse(self.BACKENDS).body:
            if isinstance(node, ast.FunctionDef):
                defined.add(node.name)
            elif isinstance(node, ast.Assign):
                defined.update(target.id for target in node.targets if isinstance(target, ast.Name))
            elif isinstance(node, ast.Import):
                defined.update(alias.name for alias in node.names)
        namespace = {name: value for name, value in vars(server).items() if name not in defined and name != "__file__"}
        if file is not None:
            namespace["__file__"] = file
        return namespace, FunctionType(server.load_backends.__code__, namespace)

    def test_the_engine_backends_load_once_from_checked_injection_a_bundle_or_the_source_tree(self):
        # The digest the server ships is the source tree's file, as the engine compresses it (LF).
        self.assertEqual(server.BACKENDS_SHA256, hashlib.sha256(self.BACKENDS.replace(b"\r\n", b"\n")).hexdigest())
        injected = base64.b64encode(zlib.compress(self.BACKENDS)).decode()
        with patch.dict(server.HELPERS_SERVED, clear=True), patch.dict(os.environ, YOUGORI_HELPERS="", YOUGORI_BACKENDS_SOURCE=injected):
            namespace, load = self.without_backends()
            self.assertNotIn("load_vllm", namespace)
            load()
            self.assertEqual(namespace["VLLM_VERSION"], "0.29.0")
            self.assertTrue(callable(namespace["load_gguf"]) and callable(namespace["vllm_park"]))
            self.assertEqual(server.HELPERS_SERVED["engine-backends"], {"served": "source_injection", "sha256": server.BACKENDS_SHA256})
            # Once per process: a second load executes nothing again.
            namespace["VLLM_PARKED"] = "kept"
            load()
            self.assertEqual(namespace["VLLM_PARKED"], "kept")
        # Injected source the server does not ship is refused before any of it runs.
        changed = base64.b64encode(zlib.compress(self.BACKENDS + b"\nLOAD_MARK = 1\n")).decode()
        with patch.dict(server.HELPERS_SERVED, clear=True), patch.dict(os.environ, YOUGORI_HELPERS="", YOUGORI_BACKENDS_SOURCE=changed):
            namespace, load = self.without_backends()
            with self.assertRaisesRegex(RuntimeError, "engine backends failed integrity verification"):
                load()
            self.assertNotIn("LOAD_MARK", namespace)
            self.assertNotIn("load_vllm", namespace)
        # Nothing carried, nothing bundled and no source tree: the update message, nothing run.
        with patch.dict(server.HELPERS_SERVED, clear=True), patch.dict(os.environ, YOUGORI_HELPERS="", YOUGORI_BACKENDS_SOURCE=""):
            namespace, load = self.without_backends()
            with self.assertRaisesRegex(RuntimeError, "missing the bundled helper engine-backends"):
                load()
            self.assertNotIn("load_vllm", namespace)
            # A server run from a source tree reads the file beside it, unrecorded.
            namespace, load = self.without_backends(server.__file__)
            load()
            self.assertEqual(namespace["LLAMA_BUILD"], "b11425")
            self.assertNotIn("engine-backends", server.HELPERS_SERVED)
        # A bundle the rollout serves is read from the helpers bind; its integrity is the catalog's.
        with tempfile.TemporaryDirectory() as root:
            entry = Path(root) / "engine-backends" / "engine_backends.py"
            entry.parent.mkdir(parents=True)
            entry.write_bytes(self.BACKENDS + b"\nBUNDLE_MARK = 1\n")
            named = json.dumps({"engine-backends": {"entry": str(entry), "pin": "pin-backends"}})
            with patch.object(server, "HELPERS_ROOT", root), patch.dict(server.HELPERS_SERVED, clear=True), \
                 patch.dict(os.environ, YOUGORI_HELPERS=named, YOUGORI_BACKENDS_SOURCE=injected):
                namespace, load = self.without_backends(server.__file__)
                load()
                self.assertEqual(namespace["BUNDLE_MARK"], 1)
                self.assertEqual(server.HELPERS_SERVED["engine-backends"]["served"], "bundle")
                self.assertEqual(server.HELPERS_SERVED["engine-backends"]["pin"], "pin-backends")

    VLLM_METRICS = """# HELP vllm:request_queue_time_seconds Histogram of time spent in WAITING phase for request.
# TYPE vllm:request_queue_time_seconds histogram
vllm:request_queue_time_seconds_sum{{engine="0",model_name="m"}} {queue}
vllm:request_queue_time_seconds_count{{engine="0",model_name="m"}} {count}
vllm:request_prefill_time_seconds_sum{{engine="0",model_name="m"}} {prefill}
vllm:request_prefill_time_seconds_count{{engine="0",model_name="m"}} {count}
vllm:request_decode_time_seconds_sum{{engine="0",model_name="m"}} {decode}
vllm:request_decode_time_seconds_count{{engine="0",model_name="m"}} {count}
vllm:request_prompt_tokens_sum{{engine="0",model_name="m"}} {prompt}
vllm:request_prompt_tokens_count{{engine="0",model_name="m"}} {count}
vllm:request_prefill_kv_computed_tokens_sum{{engine="0",model_name="m"}} {computed}
vllm:request_prefill_kv_computed_tokens_count{{engine="0",model_name="m"}} {count}
vllm:request_generation_tokens_sum{{engine="0",model_name="m"}} {generated}
vllm:request_generation_tokens_count{{engine="0",model_name="m"}} {count}
vllm:kv_cache_usage_perc{{engine="0",model_name="m"}} 0.25
"""

    def metrics_reply(self, **values):
        body = self.VLLM_METRICS.format(**values).encode()
        response = SimpleNamespace(status=200, read=lambda limit: body)
        return SimpleNamespace(close=lambda: None), response

    def test_vllm_clocks_are_the_growth_of_its_histograms_across_exactly_one_request(self):
        recorded = []
        before = dict(queue=1.0, prefill=2.0, decode=3.0, prompt=1000, computed=900, generated=40, count=4)
        after = dict(queue=1.00025, prefill=2.05, decode=3.04, prompt=1120, computed=1000, generated=43, count=5)
        with patch.object(server, "FORMAT", "vllm"), patch.object(server.RUNNER_TIMINGS, "backend", recorded.append):
            with patch.object(server, "llama", return_value=self.metrics_reply(**before)):
                start = server.backend_observation_start()
            self.assertEqual(start["vllm:request_prompt_tokens_sum"], 1000)
            with patch.object(server, "llama", return_value=self.metrics_reply(**after)):
                server.backend_observation_finish(start)
            self.assertEqual(recorded, [{"version": 1, "source": "vllm-metrics-delta", "promptTokens": 120, "cachedTokens": 20,
                                         "queueMs": 0.25, "prefillMs": 50.0, "decodeMs": 40.0, "outputTokens": 3}])
            # Two requests counted in between: not one request's clocks, nothing recorded.
            with patch.object(server, "llama", return_value=self.metrics_reply(**{**after, "count": 6})):
                server.backend_observation_finish(start)
            self.assertEqual(len(recorded), 1)
            # Unreadable metrics record nothing either.
            with patch.object(server, "llama", side_effect=OSError("down")):
                self.assertIsNone(server.backend_observation_start())
                server.backend_observation_finish(start)
            self.assertEqual(len(recorded), 1)

    def test_llama_cpp_clocks_are_its_reply_timings(self):
        recorded = []
        timings = {"cache_n": 20, "prompt_n": 100, "prompt_ms": 50.5, "prompt_per_second": 1980.2,
                   "predicted_n": 3, "predicted_ms": 40.25}
        with patch.object(server, "FORMAT", "gguf"), patch.object(server.RUNNER_TIMINGS, "backend", recorded.append):
            self.assertEqual(server.backend_observation_start(), {})
            server.backend_observation_finish({}, timings)
            server.backend_observation_finish({}, None)
            server.backend_observation_finish({}, {"prompt_n": "x"})
        self.assertEqual(recorded, [{"version": 1, "source": "llama-cpp-timings", "promptTokens": 120, "cachedTokens": 20,
                                     "queueMs": None, "prefillMs": 50.5, "decodeMs": 40.25, "outputTokens": 3}])

    def test_a_parked_vllm_says_it_slept_and_its_wake_is_timed_as_its_own_stages(self):
        process = Mock()
        process.poll.return_value = None
        timings = server.RunnerTimings()
        with patch.object(server, "FORMAT", "vllm"), patch.object(server, "ENGINE_PROCESS", process), \
             patch.object(server, "VLLM_ROOT", "/root"), patch.object(server, "VLLM_PARKED", None), \
             patch.object(server, "RUNNER_TIMINGS", timings), \
             patch.object(server, "llama_json", return_value={}) as calls, patch.dict(server.STATE, clear=False):
            server.STATE.pop("parked", None)
            self.assertTrue(server.vllm_park())
            self.assertEqual(server.STATE["parked"], "sleep")
            calls.assert_called_with("/sleep?level=2", {}, timeout=120)
            with timings.run("load") as run:
                self.assertTrue(server.vllm_wake())
                run["outcome"] = "ok"
            self.assertEqual(set(run["stages"]), {"engine_wake", "weight_reload"})

    ADAPTER_CONFIG = {"peft_type": "LORA", "r": 8, "target_modules": ["q_proj", "v_proj"], "use_dora": False,
                      "modules_to_save": None, "base_model_name_or_path": "Qwen/Qwen2.5-0.5B-Instruct"}
    ADAPTER_REVISION = "e" * 40

    def adapter_world(self, root, config=None, served=None, base=None, limits="2:16", fmt="vllm", tampered=None):
        """A vLLM launch with adapters enabled, a pinned adapter repository and the base it
        names, all fake: what the runner reads, never the network."""
        snapshot = Path(root) / "snapshot"
        snapshot.mkdir(exist_ok=True)
        (snapshot / "adapter_config.json").write_text(json.dumps(config or self.ADAPTER_CONFIG), encoding="utf-8")
        (snapshot / "adapter_model.safetensors").write_bytes(b"adapter weights")
        weights = {"model.safetensors": "a" * 64}
        adapter_digest = hashlib.sha256(b"adapter weights").hexdigest()
        hub = {"owner/adapter": ({"adapter_model.safetensors": (adapter_digest, 15)}, self.ADAPTER_REVISION),
               "Qwen/Qwen2.5-0.5B-Instruct": ({name: (digest, 1) for name, digest in (base or weights).items()}, "f" * 40)}
        calls = []

        def reply(path, body=None, timeout=30):
            calls.append((path, body))
            response = SimpleNamespace(status=200, read=lambda limit: b"Success")
            return SimpleNamespace(close=lambda: None), response
        stack = ExitStack()
        stack.enter_context(patch.object(server, "FORMAT", fmt))
        stack.enter_context(patch.dict(os.environ, YOUGORI_VLLM_ADAPTERS=limits, YOUGORI_ADAPTERS=""))
        stack.enter_context(patch.dict(server.ADAPTERS, clear=True))
        stack.enter_context(patch.object(server, "hub_weights", lambda repo, revision: hub[repo]))
        stack.enter_context(patch.object(server, "served_weights", lambda: served or weights))
        stack.enter_context(patch.dict(server.STATE, status="ready"))
        stack.enter_context(patch.object(server, "llama", reply))
        stack.enter_context(patch.dict(sys.modules, {"huggingface_hub": SimpleNamespace(
            hf_hub_download=lambda repo, name, revision: str(snapshot / name))}))
        if tampered is not None:
            (snapshot / "adapter_model.safetensors").write_bytes(tampered)
        return stack, calls, str(snapshot)

    def test_an_adapter_is_verified_and_loaded_into_vllm_only_within_the_launchs_limits(self):
        with tempfile.TemporaryDirectory() as root:
            stack, calls, snapshot = self.adapter_world(root)
            with stack:
                self.assertEqual(server.adapter_limits(), (2, 16))
                attached = server.adapter_attach("fin", "owner/adapter", None)
                self.assertEqual((attached["revision"], attached["rank"], attached["modules"]), (self.ADAPTER_REVISION, 8, ["q_proj", "v_proj"]))
                # The adapter's check leaves the serving runner as it was (the real checker ran).
                self.assertEqual(server.STATE["status"], "ready")
                self.assertEqual(calls[-1], ("/v1/load_lora_adapter", {"lora_name": "fin", "lora_path": snapshot}))
                # The same pinned adapter under its name is already there; another one is not.
                self.assertIs(server.adapter_attach("fin", "owner/adapter", self.ADAPTER_REVISION), attached)
                with self.assertRaisesRegex(server.BackendRefusal, "attached already"):
                    server.adapter_attach("fin", "owner/adapter", "d" * 40)
                # A request names it as its model; anything else is the model.
                self.assertEqual(server.vllm_model({"model": "fin"}), "fin")
                self.assertEqual(server.vllm_model({"model": "other"}), server.MODEL)
                server.adapter_attach("second", "owner/adapter", self.ADAPTER_REVISION)
                with self.assertRaisesRegex(server.BackendRefusal, "All 2 adapter slots"):
                    server.adapter_attach("third", "owner/adapter", self.ADAPTER_REVISION)
                capabilities = server.backend_capabilities()
                self.assertTrue(capabilities["adapters"]["supported"])
                self.assertIn("attached: fin, second", capabilities["adapters"]["detail"])
                self.assertEqual([a["name"] for a in capabilities["adapters"]["attached"]], ["fin", "second"])
                # After a wake each is unloaded and loaded again (its slots did not survive).
                calls.clear()
                server.reattach_adapters()
                self.assertEqual([path for path, _ in calls], ["/v1/unload_lora_adapter", "/v1/load_lora_adapter"] * 2)
                self.assertEqual(server.adapter_detach("fin")["name"], "fin")
                self.assertEqual(calls[-1], ("/v1/unload_lora_adapter", {"lora_name": "fin"}))
                with self.assertRaisesRegex(server.BackendRefusal, "No adapter named fin"):
                    server.adapter_detach("fin")

    def test_adapters_are_refused_with_why_outside_the_launchs_terms(self):
        cases = [
            ({"limits": ""}, "serves no adapters"),
            ({"fmt": "gguf"}, "only at start, from GGUF files"),
            ({"config": {**self.ADAPTER_CONFIG, "r": 32}}, "rank 32 is above"),
            ({"config": {**self.ADAPTER_CONFIG, "use_dora": True}}, "plain LoRA"),
            ({"config": {**self.ADAPTER_CONFIG, "target_modules": ["lm_head"]}}, "other than the attention and MLP"),
            ({"config": {**self.ADAPTER_CONFIG, "peft_type": "IA3"}}, "plain LoRA"),
            ({"base": {"model.safetensors": "c" * 64}}, "whose weights are not the served model's"),
            ({"tampered": b"other weights!!"}, "failed checksum verification"),
            ({"tampered": b"adapter weights, longer"}, "failed checksum verification"),
        ]
        for world, message in cases:
            with self.subTest(message=message), tempfile.TemporaryDirectory() as root:
                stack, calls, _ = self.adapter_world(root, **world)
                with stack, self.assertRaisesRegex(server.BackendRefusal, message):
                    server.adapter_attach("fin", "owner/adapter", self.ADAPTER_REVISION)
                self.assertFalse([path for path, _ in calls if path.endswith("load_lora_adapter")])
        # A base repository that keeps another shard set beside the served one (a consolidated
        # file, as Mistral's do) is still the served model's: only the served files are compared.
        with tempfile.TemporaryDirectory() as root:
            stack, calls, _ = self.adapter_world(root, base={"model.safetensors": "a" * 64, "consolidated.safetensors": "b" * 64})
            with stack:
                self.assertEqual(server.adapter_attach("fin", "owner/adapter", self.ADAPTER_REVISION)["name"], "fin")
        with tempfile.TemporaryDirectory() as root:
            stack, _, _ = self.adapter_world(root)
            with stack:
                for name, repo, revision in (("bad name!", "owner/adapter", None), ("fin", "not a repo", None),
                                             ("fin", "owner/adapter", "main"), (server.MODEL, "owner/adapter", None)):
                    with self.subTest(name=name, repo=repo), self.assertRaises(ValueError):
                        server.adapter_attach(name, repo, revision)

    def test_gguf_prompts_are_counted_with_the_completions_template_options(self):
        tools = [{"type": "function", "function": {"name": "lookup", "parameters": {"type": "object"}}}]
        for agent, kwargs in (("1", {"enable_thinking": False}), ("", None)):
            templates = []

            def backend(path, body=None, timeout=30):
                if path == "/apply-template":
                    templates.append(body)
                    # The first template refuses the system role; the retry folds it into the user turn.
                    if len(templates) == 1:
                        raise ValueError("System role not supported")
                    return {"prompt": "templated"}
                return {"tokens": [1, 2, 3]}
            with self.subTest(agent=agent), patch.object(server, "FORMAT", "gguf"), patch.object(server, "llama_json", side_effect=backend), \
                    patch.dict(os.environ, {"YOUGORI_MODEL_AGENT_API": agent}), patch.dict(server.LLAMA, context=4096):
                sent, tokens, dropped = server.prepare_gguf([{"role": "system", "content": "Be brief."}, {"role": "user", "content": "hi"}], 16, False, tools)
                self.assertEqual((tokens, dropped, len(templates)), (3, 0, 2))
                # Both attempts carry the completion's own template inputs: tools and, with the
                # agent API, thinking off; without it, no template arguments at all.
                for body in templates:
                    self.assertEqual(body.get("chat_template_kwargs"), kwargs)
                    self.assertEqual(body["tools"], tools)

    def test_the_owner_resets_the_backends_reusable_kv(self):
        calls = []

        def reply(path, body=None, timeout=30):
            calls.append(path)
            return SimpleNamespace(close=lambda: None), SimpleNamespace(status=200, read=lambda limit: b"")
        with patch.object(server, "llama", reply), patch.dict(server.STATE, status="ready"), patch.dict(server.LLAMA, slots=1):
            with patch.object(server, "FORMAT", "vllm"):
                self.assertEqual(server.backend_command("kv", {"action": "reset"}), {"reset": True})
                with patch.object(server, "VLLM_KOLIBRI", True), self.assertRaises(server.BackendRefusal):
                    server.backend_command("kv", {"action": "reset"})
            with patch.object(server, "FORMAT", "gguf"), patch.dict(os.environ, {"YOUGORI_NATIVE_BACKEND": ""}):
                self.assertEqual(server.backend_command("kv", {"action": "reset"}), {"reset": True, "slots": 1})
                # Every slot of a parallel launch is erased (they share one pool).
                with patch.dict(server.LLAMA, slots=3):
                    self.assertEqual(server.backend_command("kv", {"action": "reset"}), {"reset": True, "slots": 3})
                # An unloaded or parked model holds nothing: no backend call.
                for state in ({"status": "idle"}, {"status": "ready", "parked": "sleep"}):
                    with patch.dict(server.STATE, state):
                        self.assertEqual(server.backend_command("kv", {"action": "reset"})["slots"], 0)
            with patch.object(server, "FORMAT", "gguf"), patch.dict(os.environ, {"YOUGORI_NATIVE_BACKEND": "metal"}):
                with self.assertRaises(server.BackendRefusal):
                    server.backend_command("kv", {"action": "reset"})
        self.assertEqual(calls, ["/reset_prefix_cache", "/slots/0?action=erase", "/slots/0?action=erase", "/slots/1?action=erase", "/slots/2?action=erase"])
        with self.assertRaises(ValueError):
            server.backend_command("kv", {"action": "grow"})

    SHADOW_RUNNER = (Path(__file__).parents[1] / "src-tauri/src/model_runner/helper_shadow.py").read_bytes()

    def shadow_fixture(self, root, candidate, name="gpu-optimizer", points=None):
        """A shadow candidate file under the helpers bind, named in YOUGORI_HELPERS_SHADOW, and the
        engine's shadow runner beside it, loaded as the server's hook loads it on its first call."""
        entry = Path(root) / "shadow" / name / "entry.py"
        entry.parent.mkdir(parents=True, exist_ok=True)
        entry.write_bytes(candidate)
        (Path(root) / "shadow" / "yougori-shadow.py").write_bytes(self.SHADOW_RUNNER)
        stack = ExitStack()
        stack.enter_context(patch.object(server, "HELPERS_ROOT", root))
        stack.enter_context(patch.dict(os.environ, YOUGORI_HELPERS_SHADOW=json.dumps({name: {"entry": str(entry), "pin": "pin-shadow"}})))
        stack.enter_context(patch.dict(server.SHADOW, clear=True))
        exec(compile(self.SHADOW_RUNNER, "yougori-shadow", "exec"), server.SHADOW)
        if points is not None:
            server.SHADOW["SHADOW_POINTS"][name] = points
        return stack

    def test_the_shadow_runner_is_read_from_the_helpers_bind_only_when_a_runner_shadows(self):
        with tempfile.TemporaryDirectory() as root, patch.object(server, "HELPERS_ROOT", root), patch.dict(server.SHADOW, clear=True):
            source = {}
            exec("def gpu_grant_terms(body):\n    return len(body)\ndef gpu_capacity_demand():\n    return None\n", source)
            serving = dict(source)
            # No candidate: nothing is read and nothing reported.
            with patch.dict(os.environ, YOUGORI_HELPERS_SHADOW=""):
                server.shadow_attach("gpu-optimizer", source)
                self.assertEqual(server.shadow_snapshot(), {})
            entry = Path(root) / "shadow" / "gpu-optimizer" / "entry.py"
            entry.parent.mkdir(parents=True)
            entry.write_bytes(b"def gpu_grant_terms(body):\n    return len(body)\ndef gpu_capacity_demand():\n    return None\n")
            with patch.dict(os.environ, YOUGORI_HELPERS_SHADOW=json.dumps({"gpu-optimizer": {"entry": str(entry), "pin": "p"}})):
                # The engine's runner missing: reported, and what serves is untouched.
                server.shadow_attach("gpu-optimizer", source)
                self.assertIs(source["gpu_grant_terms"], serving["gpu_grant_terms"])
                self.assertIn("FileNotFoundError", server.shadow_snapshot()["runner"]["loadError"])
                # Written beside the candidates, it is read once and runs them.
                server.SHADOW.clear()
                (Path(root) / "shadow" / "yougori-shadow.py").write_bytes(self.SHADOW_RUNNER)
                server.shadow_attach("gpu-optimizer", source)
                self.assertEqual(source["gpu_grant_terms"]({"a": 1}), 1)
                server.SHADOW["SHADOW_QUEUE"].join()
                shadow = server.shadow_snapshot()["gpu-optimizer"]
                self.assertEqual((shadow["calls"], shadow["agreed"]), (1, 1))

    def test_a_shadow_candidate_is_compared_on_every_serving_call_and_never_serves(self):
        serving = {"LIMIT": 10}
        exec("def double(x):\n    return x * 2 if x < LIMIT else None\n", serving)
        with tempfile.TemporaryDirectory() as root:
            # The same decisions: every call agrees, and the serving results are the serving helper's.
            with self.shadow_fixture(root, b"def double(x):\n    return x * 2 if x < LIMIT else None\n", points=(("double", ("LIMIT",)),)):
                source = dict(serving)
                server.shadow_attach("gpu-optimizer", source)
                self.assertEqual([source["double"](n) for n in (1, 2, 30)], [2, 4, None])
                server.SHADOW["SHADOW_QUEUE"].join()
                shadow = server.shadow_snapshot()["gpu-optimizer"]
                self.assertEqual((shadow["pin"], shadow["calls"], shadow["agreed"], shadow["disagreed"], shadow["candidateErrors"]), ("pin-shadow", 3, 3, 0, 0))
                self.assertEqual(shadow["points"], ["double"])
                self.assertGreater(shadow["candidateNanos"], 0)
                self.assertIsNone(shadow["loadError"])
                self.assertFalse(shadow["hung"])
            # Different decisions are counted with what differed; what serves is unchanged.
            with self.shadow_fixture(root, b"def double(x):\n    return x * 3\n", points=(("double", ()),)):
                source = dict(serving)
                server.shadow_attach("gpu-optimizer", source)
                self.assertEqual(source["double"](2), 4)
                server.SHADOW["SHADOW_QUEUE"].join()
                shadow = server.shadow_snapshot()["gpu-optimizer"]
                self.assertEqual((shadow["calls"], shadow["agreed"], shadow["disagreed"]), (1, 0, 1))
                self.assertEqual(shadow["differences"][0]["serving"]["value"], "4")
                self.assertEqual(shadow["differences"][0]["candidate"]["value"], "6")

    def test_a_shadow_candidates_failures_are_counted_and_a_serving_failure_is_raised_as_it_was(self):
        serving = {}
        exec("def parse(text):\n    if not text:\n        raise ValueError('empty')\n    return int(text)\n", serving)
        with tempfile.TemporaryDirectory() as root:
            with self.shadow_fixture(root, b"def parse(text):\n    raise RuntimeError('candidate broke')\n", points=(("parse", ()),)):
                source = dict(serving)
                server.shadow_attach("gpu-optimizer", source)
                self.assertEqual(source["parse"]("7"), 7)
                with self.assertRaisesRegex(ValueError, "empty"):
                    source["parse"]("")
                server.SHADOW["SHADOW_QUEUE"].join()
                shadow = server.shadow_snapshot()["gpu-optimizer"]
                self.assertEqual((shadow["calls"], shadow["disagreed"], shadow["candidateErrors"]), (2, 2, 2))
            # A candidate raising what the serving helper raised agrees.
            with self.shadow_fixture(root, b"def parse(text):\n    if not text:\n        raise ValueError('empty')\n    return int(text)\n", points=(("parse", ()),)):
                source = dict(serving)
                server.shadow_attach("gpu-optimizer", source)
                with self.assertRaises(ValueError):
                    source["parse"]("")
                server.SHADOW["SHADOW_QUEUE"].join()
                self.assertEqual(server.shadow_snapshot()["gpu-optimizer"]["agreed"], 1)

    def test_a_shadow_candidate_that_cannot_load_or_compare_leaves_the_serving_helper_untouched(self):
        serving = {}
        exec("def double(x):\n    return x * 2\n", serving)
        with tempfile.TemporaryDirectory() as root:
            for candidate, expected in ((b"def double(x:\n", "SyntaxError"), (b"OTHER = 1\n", "lacks double")):
                with self.shadow_fixture(root, candidate, points=(("double", ()),)):
                    source = dict(serving)
                    server.shadow_attach("gpu-optimizer", source)
                    self.assertIs(source["double"], serving["double"])
                    shadow = server.shadow_snapshot()["gpu-optimizer"]
                    self.assertIn(expected, shadow["loadError"])
                    self.assertEqual(shadow["candidateErrors"], 1)
            # A helper with no decision points (the model server itself) cannot be shadowed.
            with self.shadow_fixture(root, b"x = 1\n", name="model-server"):
                server.shadow_attach("model-server", {})
                self.assertIn("no decision points", server.shadow_snapshot()["model-server"]["loadError"])
            # An entry outside the bind is refused, whatever the variable says.
            outside = Path(root).parent / "outside-shadow.py"
            with self.shadow_fixture(root, b"x = 1\n"), \
                 patch.dict(os.environ, YOUGORI_HELPERS_SHADOW=json.dumps({"gpu-optimizer": {"entry": str(outside), "pin": "p"}})):
                source = dict(serving)
                server.shadow_attach("gpu-optimizer", source)
                self.assertIs(source["double"], serving["double"])
                self.assertIn("outside", server.shadow_snapshot()["gpu-optimizer"]["loadError"])
            # A malformed variable runs no candidate and says why.
            with self.shadow_fixture(root, b"x = 1\n"), patch.dict(os.environ, YOUGORI_HELPERS_SHADOW="[1]"):
                source = dict(serving)
                server.shadow_attach("gpu-optimizer", source)
                self.assertIs(source["double"], serving["double"])
                self.assertIn("YOUGORI_HELPERS_SHADOW", server.shadow_snapshot()["gpu-optimizer"]["loadError"])

    def test_a_hanging_shadow_candidate_never_delays_serving_and_is_reported(self):
        serving = {}
        exec("def double(x):\n    return x * 2\n", serving)
        release = threading.Event()
        with tempfile.TemporaryDirectory() as root:
            with self.shadow_fixture(root, b"def double(x):\n    RELEASE.wait(30)\n    return x * 2\n", points=(("double", ()),)):
                server.SHADOW["SHADOW_HANG_SECONDS"] = 0.2
                source = dict(serving, RELEASE=release)
                server.shadow_attach("gpu-optimizer", source)
                started = time.monotonic()
                calls = server.SHADOW["SHADOW_QUEUE"].maxsize + 8
                self.assertEqual([source["double"](n) for n in range(calls)], [n * 2 for n in range(calls)])
                self.assertLess(time.monotonic() - started, 2.0)
                time.sleep(0.4)
                shadow = server.shadow_snapshot()["gpu-optimizer"]
                self.assertTrue(shadow["hung"])
                self.assertGreaterEqual(shadow["dropped"], 1)
                release.set()
                server.SHADOW["SHADOW_QUEUE"].join()
                self.assertFalse(server.shadow_snapshot()["gpu-optimizer"]["hung"])

    def test_the_gpu_optimizers_decision_points_are_shadowed_with_the_state_they_read(self):
        source = (Path(__file__).parents[1] / "src-tauri/src/model_runner/gpu_optimizer.py").read_bytes()
        grant = {"YOUGORI_GPU_CAPACITY_POLICY": "local-single-transformers-v1", "YOUGORI_GPU_CAPACITY_BYTES": str(8 * 2 ** 30),
                 "YOUGORI_GPU_CAPACITY_CONTEXT": "8192"}
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, grant), patch.dict(server.__dict__):
            with self.shadow_fixture(root, source):
                server.shadow_attach("gpu-optimizer", server.__dict__)
                self.assertEqual(server.shadow_snapshot()["gpu-optimizer"]["points"], ["gpu_grant_terms", "gpu_capacity_demand"])
                self.assertEqual(server.gpu_grant_terms({"bytes": 2 ** 30, "context": 4096}), (2 ** 30, 4096))
                with self.assertRaises(ValueError):
                    server.gpu_grant_terms({"bytes": 2 ** 30})
                server.GPU_GRANT_TERMS = (4 * 2 ** 30, 4096)
                self.assertEqual(server.gpu_capacity_demand(), (4 * 2 ** 30, 4096))
                server.SHADOW["SHADOW_QUEUE"].join()
                shadow = server.shadow_snapshot()["gpu-optimizer"]
                self.assertEqual((shadow["calls"], shadow["agreed"], shadow["disagreed"], shadow["candidateErrors"]), (3, 3, 0, 0))

    def test_the_engine_backends_decision_points_are_shadowed_on_vllm_and_llama_cpp_runners(self):
        source = (Path(__file__).parents[1] / "src-tauri/src/model_runner/engine_backends.py").read_bytes()
        for fmt in ("vllm", "gguf"):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as root, patch.dict(server.__dict__), \
                 patch.dict(os.environ, YOUGORI_VLLM_ADAPTERS="2:16" if fmt == "vllm" else ""):
                server.FORMAT = fmt
                with self.shadow_fixture(root, source, name="engine-backends"):
                    server.shadow_attach("engine-backends", server.__dict__)
                    self.assertEqual(server.shadow_snapshot()["engine-backends"]["points"], ["backend_capabilities", "vllm_model"])
                    facts = server.runner_capabilities()
                    self.assertEqual(facts["adapters"]["supported"], fmt == "vllm")
                    self.assertEqual(server.vllm_model({"model": "other"}), server.MODEL)
                    server.SHADOW["SHADOW_QUEUE"].join()
                    shadow = server.shadow_snapshot()["engine-backends"]
                    self.assertEqual((shadow["calls"], shadow["agreed"], shadow["disagreed"], shadow["candidateErrors"]), (2, 2, 0, 0))

    # The deliberately failing engine-backends candidate of the GPU run (scripts/a2shadow3.py).
    WRONG_BACKENDS = ((' "kvReuse": {"supported": True,', ' "kvReuse": {"supported": False,'),
                      ('    return body["model"] if body.get("model") in ADAPTERS else MODEL\n',
                       '    raise RuntimeError("a deliberately failing candidate")\n'))

    def test_a_failing_engine_backends_candidate_is_counted_and_never_changes_what_serves(self):
        source = (Path(__file__).parents[1] / "src-tauri/src/model_runner/engine_backends.py").read_text(encoding="utf-8")
        for old, new in self.WRONG_BACKENDS:
            self.assertEqual(source.count(old), 2 if "kvReuse" in old else 1)
            source = source.replace(old, new)
        for fmt in ("vllm", "gguf"):
            with self.subTest(fmt=fmt), tempfile.TemporaryDirectory() as root, patch.dict(server.__dict__), \
                 patch.dict(os.environ, YOUGORI_VLLM_ADAPTERS=""):
                server.FORMAT = fmt
                with self.shadow_fixture(root, source.encode(), name="engine-backends"):
                    server.shadow_attach("engine-backends", server.__dict__)
                    self.assertTrue(server.runner_capabilities()["kvReuse"]["supported"])
                    self.assertEqual(server.vllm_model({"model": "other"}), server.MODEL)
                    server.SHADOW["SHADOW_QUEUE"].join()
                    shadow = server.shadow_snapshot()["engine-backends"]
                    self.assertEqual((shadow["calls"], shadow["agreed"], shadow["disagreed"], shadow["candidateErrors"]), (2, 0, 2, 1))
                    self.assertEqual({d["point"] for d in shadow["differences"]}, {"backend_capabilities", "vllm_model"})

    def test_a_transformers_grant_on_another_gpu_count_never_loads_weights(self):
        grant = {"YOUGORI_GPU_CAPACITY_POLICY": "local-single-transformers-v1", "YOUGORI_GPU_CAPACITY_BYTES": str(2 ** 30),
                 "YOUGORI_GPU_CAPACITY_CONTEXT": "2048"}
        with model_startup(count=2) as fixture, patch.object(server, "GPU_CAPACITY", None), patch.object(server, "GPU_CAPACITY_CONTEXT", None), patch.dict(os.environ, grant):
            cuda = sys.modules["torch"].cuda
            cuda.set_per_process_memory_fraction = Mock()
            server.load_model()
            self.assertEqual(server.STATE["status"], "error")
            self.assertIn("admitted for one GPU", server.STATE["error"])
            cuda.set_per_process_memory_fraction.assert_not_called()
            fixture.models.from_pretrained.assert_not_called()
            self.assertIsNone(server.gpu_snapshot()["capacityBytes"])

    def test_over_use_of_a_capped_grant_is_the_bounded_out_of_memory_reply(self):
        lock, meter, empty = threading.Lock(), {}, Mock()
        def over(**kwargs):
            raise MemoryError("CUDA out of memory: this process has a memory fraction limit " + server.TOKEN)
        torch = SimpleNamespace(inference_mode=lambda: ExitStack(), cuda=SimpleNamespace(OutOfMemoryError=MemoryError, empty_cache=empty))
        with patch.dict("sys.modules", transformers=SimpleNamespace(StoppingCriteriaList=list)), \
             patch.object(server, "GENERATION", lock), patch.object(server, "TORCH", torch), \
             patch.object(server, "GPU_CAPACITY", 2 ** 30), \
             patch.object(server, "NETWORK", SimpleNamespace(generate=over)), \
             patch.object(server, "TOKENIZER", SimpleNamespace(pad_token_id=0, eos_token_id=1)), \
             patch.object(server, "prepare", return_value=({}, 2, 0)), \
             patch.dict(server.STATE, status="ready", error=None):
            status, body = server.generate({"messages":[{"role":"user", "content":"hello"}]}, None, meter)
            self.assertEqual(server.STATE["status"], "ready")
        self.assertEqual(status, 507)
        self.assertEqual(body["error"]["message"], "Not enough GPU memory. Shorten the conversation or choose a smaller model.")
        # The typed code lets the engine render the refusal in its own words (streaming.rs typed_refusal).
        self.assertEqual(body["error"]["code"], "yougori_gpu_memory")
        empty.assert_called_once()
        self.assertFalse(lock.locked())
        self.assertEqual(meter["outcome"], "error")

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

    def test_a_transformers_grant_bounds_the_context_window_it_covers(self):
        """G03: under the engine's Transformers admission profile the runner serves no prompt past the
        context its grant covers; the grant never widens a model's own window, and Clef keeps its own."""
        network = SimpleNamespace(config=SimpleNamespace(max_position_embeddings=32768))
        for covered, expected in [(None, 32768), (12288, 12288), (40000, 32768)]:
            with self.subTest(covered=covered), patch.object(server, "NETWORK", network), patch.object(server, "GPU_CAPACITY_CONTEXT", covered):
                self.assertEqual(server.context_window(), expected)
        with patch.object(server, "GPU_CAPACITY_CONTEXT", 12288), patch.object(server, "MODEL", "Cloudflare/clef"):
            self.assertEqual(server.context_window(), 16384)
        # The runner's own grant check sets the context together with the allocator cap.
        fraction = Mock()
        torch = SimpleNamespace(cuda=SimpleNamespace(mem_get_info=lambda index: (20 * 2**30, 24 * 2**30), set_per_process_memory_fraction=fraction))
        with patch.object(server, "GPU_CAPACITY", None), patch.object(server, "GPU_CAPACITY_CONTEXT", None), patch.object(server, "NETWORK", network), \
             patch.dict(os.environ, YOUGORI_GPU_CAPACITY_POLICY="local-single-transformers-v1", YOUGORI_GPU_CAPACITY_BYTES=str(21 * 2**30), YOUGORI_GPU_CAPACITY_CONTEXT="12288", YOUGORI_MODEL_PRECISION="auto"):
            self.assertEqual(server.gpu_cap_memory(torch, 1), 21 * 2**30)
            self.assertEqual(server.context_window(), 12288)
            self.assertEqual(server.gpu_snapshot()["capacityContext"], 12288)
            with self.assertRaisesRegex(ValueError, "12288-token context window"):
                server.fit([{"role": "user", "content": "long"}], 64, False, server.context_window(), lambda messages: (messages, 12300))

    def test_a_context_refusal_carries_the_runners_integers_as_a_typed_code_and_nothing_of_the_caller(self):
        """The engine renders yougori_context_window from the window, the prompt's tokens, max_tokens and the
        grant's context (streaming.rs typed_refusal); the message text is the runner's fixed sentence."""
        measure = lambda messages: (messages, 10294)
        with self.assertRaises(server.ContextRefusal) as refused:
            server.fit([{"role": "user", "content": "secret prompt text"}], 256, False, 9728, measure)
        body = refused.exception.body()["error"]
        self.assertEqual((body["code"], body["context"], body["promptTokens"], body["maxTokens"]), ("yougori_context_window", 9728, 10294, 256))
        self.assertNotIn("secret", json.dumps(body))
        self.assertEqual(body["message"], "Conversation exceeds this model's 9728-token context window; shorten it or reduce max_tokens")
        self.assertNotIn("grantContext", body)
        # Under a grant whose context is the window the refusal names it, so the engine can say so.
        network = SimpleNamespace(config=SimpleNamespace(max_position_embeddings=32768))
        with patch.object(server, "NETWORK", network), patch.object(server, "GPU_CAPACITY_CONTEXT", 9728):
            self.assertEqual(refused.exception.body()["error"]["grantContext"], 9728)
        with self.assertRaises(server.ContextRefusal) as too_many:
            server.fit([{"role": "user", "content": "x"}], 4096, False, 4096, measure)
        body = too_many.exception.body()["error"]
        self.assertEqual((body["context"], body["maxTokens"]), (4096, 4096))
        self.assertNotIn("promptTokens", body)
        # Truncation still drops the oldest turns instead of refusing.
        measured, tokens, dropped = server.fit([{"role": "user", "content": "a"}, {"role": "assistant", "content": "b"}, {"role": "user", "content": "c"}], 10, True, 30,
            lambda messages: (messages, 10 * len(messages)))
        self.assertEqual((tokens, dropped), (10, 2))
        # The chat handler answers a ContextRefusal with its body, while other ValueErrors keep the generic 400.
        replies = []
        handler = SimpleNamespace(reply=lambda status, body: replies.append((status, body)))
        for error, expected in [(server.ContextRefusal("m", 4096, tokens=5000, count=16), (400, "yougori_context_window")), (ValueError("tokenizer echo: secret"), (400, None))]:
            try:
                raise error
            except server.ContextRefusal as refusal:
                handler.reply(400, refusal.body())
            except (ValueError, TypeError):
                handler.reply(400, {"error": {"message": "Invalid model request. Check message roles, content, context length and generation settings."}})
            status, body = replies[-1]
            self.assertEqual((status, body["error"].get("code")), expected)
            self.assertNotIn("secret", json.dumps(body))

    def test_the_runner_reports_what_its_launch_supports_for_kv_growth_and_adapters(self):
        """The product surfaces show these facts of the pinned launches (G06, U02); they are not CORE-01 evidence."""
        for fmt, kv_words, adapter_words, reuse in [("safetensors", "grows per generated token", "no unmerged adapters", False),
                                                    ("gguf", "allocates the context's KV cache", "only at start, from GGUF files", True),
                                                    ("vllm", "takes its KV blocks when it starts", "does not enable LoRA adapters", True)]:
            with self.subTest(fmt=fmt), patch.object(server, "FORMAT", fmt), patch.object(server, "GPU_CAPACITY_CONTEXT", 9728 if fmt == "safetensors" else None), \
                 patch.dict(os.environ, YOUGORI_VLLM_ADAPTERS=""):
                facts = server.runner_capabilities()
                self.assertEqual(set(facts), {"kvGrowth", "adapters", "kvReuse", "concurrency", "structuredOutput"})
                self.assertEqual(facts["concurrency"]["slots"], server.INFERENCE_QUEUE.slots if fmt != "safetensors" else 1)
                self.assertFalse(facts["kvGrowth"]["supported"])
                self.assertFalse(facts["adapters"]["supported"])
                self.assertEqual(facts["kvReuse"]["supported"], reuse)
                self.assertIn(kv_words, facts["kvGrowth"]["detail"])
                self.assertIn(adapter_words, facts["adapters"]["detail"])
                # JSON output (response_format) is enforced by the two backends with a grammar or
                # structured outputs, and by nothing in the Transformers runner.
                self.assertEqual(facts["structuredOutput"]["supported"], fmt != "safetensors")
                self.assertIn("response_format", facts["structuredOutput"]["detail"])
                if fmt == "safetensors":
                    self.assertIn("9728", facts["kvGrowth"]["detail"])
        # A megakernel launch decodes with the owner's kernel: no schema is enforced.
        with patch.object(server, "FORMAT", "vllm"), patch.object(server, "MEGAKERNEL", {"serving": True}), patch.dict(os.environ, YOUGORI_VLLM_ADAPTERS=""):
            self.assertFalse(server.runner_capabilities()["structuredOutput"]["supported"])
        with patch.object(server, "FORMAT", "source"):
            self.assertEqual(server.runner_capabilities(), {})

    def test_chat_validation_rejects_unbounded_and_unsupported_inputs(self):
        valid = {"messages": [{"role": "user", "content": "hello"}]}
        self.assertEqual(server.validate_chat(valid)[1], 256)
        for extra in [{"max_tokens": 0}, {"max_tokens": True}, {"max_tokens": 4097}, {"stream": "yes"}, {"truncate": 1}, {"messages": [{"role": "system", "content": "only"}]}, {"temperature": float("nan")}, {"model": "other/model"}, {"messages": [{"role": "tool", "content": "x"}]}, {"messages": [{"role": "user", "content": "x" * 32769}]}]:
            with self.assertRaises(ValueError):
                server.validate_chat({**valid, **extra})
        # Fields ordinary OpenAI clients send are accepted: ignored, or passed to vLLM and llama.cpp.
        server.validate_chat({**valid, "seed": 7, "user": "u1", "presence_penalty": 0.5, "frequency_penalty": -1, "n": 1, "logprobs": False,
                              "metadata": {"run": "a"}, "store": False, "service_tier": "auto", "prompt_cache_key": "k", "reasoning_effort": "low"})
        for extra in [{"n": 2}, {"logprobs": True}, {"seed": -1}, {"seed": "7"}, {"presence_penalty": 3}, {"frequency_penalty": True}, {"user": 5}, {"metadata": "x"}, {"logit_bias": {}}]:
            with self.assertRaises(ValueError):
                server.validate_chat({**valid, **extra})
        # OpenAI's reply formats, checked for shape only here (what enforces them is the launch's
        # business): the two JSON kinds pass, text is no format, and anything else is refused
        # with a typed sentence that never echoes the request.
        schema = {"type": "object", "properties": {"ok": {"type": "boolean"}}, "required": ["ok"]}
        for value, kind in [({"type": "json_object"}, "json_object"), ({"type": "text"}, None),
                            ({"type": "json_schema", "json_schema": {"name": "reply", "schema": schema, "strict": True, "description": "yes or no"}}, "json_schema"),
                            ({"type": "json_schema", "json_schema": {"schema": schema}}, "json_schema")]:
            server.validate_chat({**valid, "response_format": value})
            self.assertEqual(server.response_format_kind({"response_format": value}), kind)
        self.assertIsNone(server.response_format_kind(valid))
        for value in ["json", {"type": "xml"}, {"type": "json_object", "schema": schema}, {"type": "json_schema"}, {"type": "json_schema", "json_schema": {}},
                      {"type": "json_schema", "json_schema": {"schema": schema, "name": "bad name"}}, {"type": "json_schema", "json_schema": {"schema": schema, "strict": "yes"}},
                      {"type": "json_schema", "json_schema": {"schema": schema, "other": 1}},
                      {"type": "json_schema", "json_schema": {"schema": {"description": "x" * 17000}}}]:
            with self.assertRaises(server.StructuredOutputRefusal) as refused:
                server.validate_chat({**valid, "response_format": value})
            self.assertEqual(refused.exception.body()["error"]["code"], "yougori_structured_output")
            self.assertNotIn("xml", refused.exception.body()["error"]["message"])

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
            # A chat model's media counters stay at zero; a media model's token counters do.
            self.assertEqual(usage["totals"], {"requests": 2, "prompt_tokens": 120, "completion_tokens": 30, "errors": 1, "rejected": 1, "api": 1, "yougori": 1, "images": 0, "output_ms": 0, "compute_ms": 0})
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
                # The shared API key alone cannot reset the owner's usage history.
                with self.assertRaises(HTTPError) as denied:
                    urlopen(Request(base + "/v1/usage/reset", data=b"{}", headers=headers))
                self.assertEqual(denied.exception.code, 403)
                urlopen(Request(base + "/v1/usage/reset", data=b"{}", headers={**headers, "X-Yougori-Admin": "b" * 64})).close()
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
                urlopen(Request(base + "/v1/chat/completions", data=b'{"messages":[{"role":"user","content":"hello"}]}', headers=headers))
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
                self.assertEqual(events[-1]['usage'],{'prompt_tokens':5,'completion_tokens':1,'total_tokens':6,'prompt_tokens_details':{'cached_tokens':0}})
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
        upstream={"choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}],"usage":{"completion_tokens":2}}
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
        self.assertEqual(result["usage"],{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7,"prompt_tokens_details":{"cached_tokens":0}})
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
                self.assertIn('--enforce-eager',args);self.assertNotIn('--speculative-config',args)
                self.assertEqual(server.STATE['launch'],'eager')
                self.assertNotIn('--trust-remote-code',args);self.assertNotIn('--enable-log-requests',args)
                self.assertNotIn('HF_TOKEN',env);self.assertNotIn('YOUGORI_MODEL_TOKEN',env)
                self.assertEqual(env['HF_HUB_OFFLINE'],'1')
                self.assertEqual(env['VLLM_PLUGINS'],'aleph_alpha_inference')
                self.assertEqual(args[args.index('--host')+1],'127.0.0.1')
                # Output is drained through a pipe; only a failed load ever shows any of it.
                self.assertEqual(spawn.call_args.kwargs['stdout'],server.subprocess.PIPE)
                self.assertEqual(spawn.call_args.kwargs['stderr'],server.subprocess.STDOUT)
                meta.sha='b'*40
                snapshot.reset_mock()
                with self.assertRaisesRegex(RuntimeError,'immutable revision'): server.load_vllm()
                snapshot.assert_not_called()

    def test_one_gpu_runs_vllm_in_process_and_wsl_uses_the_v1_model_runner(self):
        # Found on the Windows CUDA runtime (WSL 2): the multiprocess executor's shared-memory
        # queues need more /dev/shm than its containers have, and the V2 model runner needs
        # pinned host memory, which WSL 2 does not give.
        for devices, release, backend, v2 in ((1, '5.15.167.4-microsoft-standard-WSL2', 'uni', '0'),
                                               (2, '6.8.0-45-generic', 'mp', None)):
            with tempfile.TemporaryDirectory() as folder:
                config={"model_type":"kolibri1","architectures":["Kolibri1ForCausalLM"],"num_attention_heads":48,"num_key_value_heads":4,"max_position_embeddings":4096,"dtype":"bfloat16"}
                path=Path(folder)/'config.json';path.write_text(json.dumps(config))
                cuda=SimpleNamespace(is_available=lambda:True,device_count=lambda:devices,get_device_capability=lambda i:(12,0),mem_get_info=lambda i:(24*2**30,24*2**30),get_device_name=lambda i:'RTX')
                meta=SimpleNamespace(sha='a'*40,siblings=[SimpleNamespace(rfilename='model.safetensors',size=2*2**30)])
                hub=SimpleNamespace(HfApi=Mock(),hf_hub_download=Mock(return_value=str(path)))
                hub.HfApi.return_value.model_info.return_value=meta
                process=Mock();process.poll.return_value=None
                with ExitStack() as stack:
                    stack.enter_context(patch.dict('sys.modules',torch=SimpleNamespace(cuda=cuda),huggingface_hub=hub))
                    stack.enter_context(patch.object(server,'MODEL_REVISION','a'*40))
                    stack.enter_context(patch.object(server.importlib.metadata,'version',return_value='0.29.0'))
                    stack.enter_context(patch.object(server,'kolibri_plugin'))
                    stack.enter_context(patch.object(server,'verified_snapshot',return_value=folder))
                    spawn=stack.enter_context(patch.object(server.subprocess,'Popen',return_value=process))
                    stack.enter_context(patch.object(server,'llama',return_value=(Mock(),Mock(status=200))))
                    stack.enter_context(patch.object(server.threading,'Thread'))
                    stack.enter_context(patch.object(server.platform,'uname',return_value=SimpleNamespace(release=release)))
                    stack.enter_context(patch.dict(server.STATE));stack.enter_context(patch.dict(server.LLAMA))
                    stack.enter_context(patch.object(server,'ENGINE_PROCESS',None))
                    server.load_vllm()
                    args=spawn.call_args.args[0];env=spawn.call_args.kwargs['env']
                    self.assertEqual(args[args.index('--distributed-executor-backend')+1],backend)
                    self.assertEqual(env.get('VLLM_USE_V2_MODEL_RUNNER'),v2)

    def test_a_failed_vllm_load_prints_a_bounded_redacted_tail_of_its_output(self):
        key = "k" * 32
        lines = [("line %d" % index).encode() + b"\n" for index in range(60)]
        lines.append(("RuntimeError: CUDA error with api key " + key + "\n").encode())
        tail, loading = server.deque(maxlen=server.VLLM_LOAD_TAIL_LINES), server.threading.Event()
        loading.set()
        reader = server.threading.Thread(target=server.vllm_load_output, args=(io.BytesIO(b"".join(lines)), tail, loading))
        reader.start()
        printed = io.StringIO()
        with patch.dict(server.LLAMA, key=key), patch("sys.stdout", printed):
            server.report_vllm_load_failure(reader, tail, loading)
        text = printed.getvalue()
        self.assertIn("last 40 lines", text)
        self.assertIn("RuntimeError: CUDA error", text)
        self.assertNotIn(key, text)
        self.assertIn("[redacted]", text)
        self.assertNotIn("line 20\n", text)  # older lines fell out of the bounded tail
        self.assertFalse(loading.is_set())
        self.assertEqual(len(tail), 0)

    def test_vllm_output_after_loading_is_drained_and_never_kept(self):
        tail, loading = server.deque(maxlen=server.VLLM_LOAD_TAIL_LINES), server.threading.Event()
        server.vllm_load_output(io.BytesIO(b"a prompt someone sent\nanother line\n"), tail, loading)
        self.assertEqual(len(tail), 0)
        loading.set()
        server.vllm_load_output(io.BytesIO(b"x" * 5000 + b"\n"), tail, loading)
        self.assertEqual(len(tail[0]), server.VLLM_LOAD_LINE_BYTES)

    def test_vllm_reload_reuses_verified_local_files_with_network_unavailable(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder) / "snapshot"; root.mkdir()
            config = {"model_type":"kolibri1", "architectures":["Kolibri1ForCausalLM"],
                      "num_attention_heads":8, "num_key_value_heads":8, "max_position_embeddings":2048}
            contents = {"config.json":json.dumps(config).encode(), "model.safetensors":b"fixture weights",
                        "tokenizer_config.json":b'{"chat_template":"fixture"}'}
            siblings = []
            for name, data in contents.items():
                (root/name).write_bytes(data)
                siblings.append(SimpleNamespace(rfilename=name, size=len(data), lfs={"sha256":hashlib.sha256(data).hexdigest()}))
            meta = SimpleNamespace(sha="a"*40, siblings=siblings)
            hub = SimpleNamespace(HfApi=Mock(), hf_hub_download=Mock(return_value=str(root/"config.json")))
            hub.HfApi.return_value.model_info.return_value = meta
            cuda = SimpleNamespace(is_available=lambda:True,device_count=lambda:1,
                get_device_capability=lambda i:(9,0),mem_get_info=lambda i:(8*2**30,8*2**30),get_device_name=lambda i:"fixture GPU")
            stack.enter_context(patch.dict("sys.modules", torch=SimpleNamespace(cuda=cuda), huggingface_hub=hub))
            stack.enter_context(patch.object(server, "MODEL_REVISION", "a"*40))
            stack.enter_context(patch.object(server, "CACHE", folder))
            stack.enter_context(patch.object(server, "VLLM_PREPARED", None))
            stack.enter_context(patch.object(server, "ENGINE_PROCESS", None))
            stack.enter_context(patch.object(server.importlib.metadata,"version",return_value=server.VLLM_VERSION))
            stack.enter_context(patch.object(server,"kolibri_plugin"))
            stack.enter_context(patch.dict(server.STATE));stack.enter_context(patch.dict(server.LLAMA))
            stack.enter_context(patch.dict(os.environ, YOUGORI_VLLM_SOURCE_REUSE="1"))
            snapshot = stack.enter_context(patch.object(server,"verified_snapshot",return_value=str(root)))
            processes = [Mock(poll=Mock(return_value=None)),Mock(poll=Mock(return_value=None))]
            spawn = stack.enter_context(patch.object(server.subprocess,"Popen",side_effect=processes))
            stack.enter_context(patch.object(server,"llama",return_value=(Mock(),Mock(status=200))))
            stack.enter_context(patch.object(server.threading,"Thread"))
            admission = stack.enter_context(patch.object(server,"gpu_before_load"))
            server.load_vllm()
            self.assertFalse(server.STATE["sourceReused"])
            self.assertIsNotNone(server.VLLM_PREPARED)
            first_args = spawn.call_args.args[0]
            server.gpu_release_memory()
            self.assertIsNone(server.ENGINE_PROCESS)
            hub.HfApi.side_effect = AssertionError("remote metadata during reload")
            hub.hf_hub_download.side_effect = AssertionError("remote config during reload")
            snapshot.side_effect = AssertionError("snapshot preparation during reload")
            server.load_vllm()
            self.assertTrue(server.STATE["sourceReused"])
            self.assertEqual(spawn.call_args.args[0], first_args)
            self.assertEqual(admission.call_count,2)
            self.assertEqual(snapshot.call_count,1)
            self.assertEqual(spawn.call_count,2)
            server.gpu_release_memory()
            (root/"tokenizer_config.json").write_bytes(b"corrupted")
            with self.assertRaisesRegex(RuntimeError,"source changed"):
                server.load_vllm()
            self.assertFalse(server.STATE["sourceReused"])
            self.assertEqual(spawn.call_count,2)
            self.assertEqual(admission.call_count,2)

    def test_vllm_local_path_serves_the_verified_root_without_hugging_face(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)/"mount"; root.mkdir()
            fixture = local_vllm_startup(stack, root)
            before = {name:(root/name).read_bytes() for name in os.listdir(root)}
            server.load_vllm()
            fixture.hub.HfApi.assert_not_called(); fixture.hub.hf_hub_download.assert_not_called()
            args = fixture.spawn.call_args.args[0]; env = fixture.spawn.call_args.kwargs["env"]
            self.assertEqual(args[args.index("serve")+1], os.path.realpath(root))
            self.assertEqual(args[args.index("--load-format")+1], "safetensors")
            self.assertEqual(args[args.index("--served-model-name")+1], server.MODEL)
            self.assertEqual(env["HF_HUB_OFFLINE"], "1")
            self.assertEqual(fixture.hardware.call_args.args[1], fixture.weight_bytes, "size comes from the verified safetensors files")
            self.assertEqual(fixture.admission.call_count, 1)
            self.assertEqual(fixture.verify.call_count, len(fixture.files), "every manifest file is hashed before vLLM starts")
            self.assertEqual(server.STATE["source"], "verified-local-path")
            self.assertFalse(server.STATE["sourceReused"])
            self.assertEqual(server.STATE["revision"], fixture.revision)
            self.assertEqual(server.STATE["runner"], "vllm"); self.assertTrue(server.STATE["weightsVerified"]); self.assertTrue(server.STATE["chatTemplate"])
            self.assertEqual(server.STATE["download"]["transport"], "yougori-registry")
            self.assertEqual(server.STATE["precision"], "bfloat16")
            self.assertEqual({name:(root/name).read_bytes() for name in os.listdir(root)}, before, "nothing is written into the model path")
            # A reload in this process never uses the Hugging Face download memo, and never trusts the
            # verifier's memo either (review finding R5): the mount is hashed again before vLLM starts.
            server.gpu_release_memory()
            server.load_vllm()
            self.assertTrue(server.STATE["sourceReused"]); self.assertIsNone(server.VLLM_PREPARED)
            self.assertEqual(fixture.verify.call_count, 2 * len(fixture.files), "every manifest file is hashed again on the reload")
            self.assertEqual(fixture.spawn.call_count, 2); self.assertEqual(fixture.spawn.call_args.args[0], args)
            fixture.hub.HfApi.assert_not_called()

    def test_a_vllm_launch_that_fails_steps_down_to_compiled_then_eager_then_one_sequence(self):
        # Each failed start steps down once: the speculative launch (the default), then compiled
        # without speculation, then eager with the same sequences (the launch that served before
        # 6 November), then eager with one sequence. A launch saved as compiled starts a step lower.
        S, C, E = "speculative", "compiled", "eager"
        for saved, exits, launched in ((None, [False], [("6", S)]), (None, [True, False], [("6", S), ("6", C)]),
                                       (None, [True, True, False], [("6", S), ("6", C), ("6", E)]),
                                       (None, [True, True, True, False], [("6", S), ("6", C), ("6", E), ("1", E)]),
                                       (None, [True, True, True, True], None),
                                       (C, [True, False], [("6", C), ("6", E)])):
            with self.subTest(saved=saved, exits=exits), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                root = Path(folder)/"mount"; root.mkdir()
                fixture = local_vllm_startup(stack, root)
                stack.enter_context(patch.object(server, "VLLM_PARKED", None)); stack.enter_context(patch.object(server, "VLLM_ROOT", None))
                stack.enter_context(patch.object(server, "FORMAT", "vllm"))
                stack.enter_context(patch.object(server, "INFERENCE_QUEUE", server.InferenceQueue(slots=8)))
                stack.enter_context(patch.dict(os.environ, YOUGORI_MODEL_PARALLEL="6"))
                os.environ.pop("YOUGORI_MODEL_LAUNCH", None)
                if saved:
                    os.environ["YOUGORI_MODEL_LAUNCH"] = saved
                launches, during, pending = [], [], list(exits)
                cache = Path(folder)/"cache"; (cache/"vllm-compile").mkdir(parents=True)  # graphs an earlier start compiled
                stack.enter_context(patch.object(server, "CACHE", str(cache)))
                def popen(args, **kwargs):
                    launches.append(list(args)); during.append(server.INFERENCE_QUEUE.slots)
                    return Mock(poll=Mock(return_value=1 if pending.pop(0) else None))
                fixture.spawn.side_effect = popen
                if launched is None:
                    with self.assertRaisesRegex(RuntimeError, "vLLM stopped while loading"):
                        server.load_vllm()
                    self.assertEqual(len(launches), 4)
                    continue
                server.load_vllm()
                mode = lambda args: E if "--enforce-eager" in args else S if "--speculative-config" in args else C
                self.assertEqual([(args[args.index("--max-num-seqs")+1], mode(args)) for args in launches], launched)
                # Nothing else about the launch changes, and the queue admits one request while it
                # starts, then as many as the launch that serves.
                flags = ("--enforce-eager", "--speculative-config", server.NGRAM_SPECULATION)
                rest = lambda args: tuple(a for i, a in enumerate(args) if a not in flags and i != args.index("--max-num-seqs")+1)
                self.assertEqual(len({rest(args) for args in launches}), 1)
                self.assertEqual((during, server.INFERENCE_QUEUE.slots), ([1]*len(launched), int(launched[-1][0])))
                self.assertEqual(server.STATE.get("servingFallback", "")[:28], "vLLM stopped while loading. " if len(launched) > 1 else "")
                self.assertEqual(server.STATE["launch"], launched[-1][1])
                # Both compiled launches failed: the compiled graphs are cleared for the next start.
                cleared = any(mode(args) == E for args in launches)
                self.assertEqual((cache/"vllm-compile").is_dir(), not cleared)
                self.assertEqual("compiled graphs were cleared" in server.STATE.get("servingFallback", ""), cleared)
                if not cleared:
                    continue
                # A parked engine that fell back wakes and still says eager; a launch changed meanwhile restarts.
                stack.enter_context(patch.object(server, "llama_json", return_value={}))
                self.assertTrue(server.vllm_park())
                server.load_vllm()
                self.assertEqual((len(launches), server.STATE["launch"]), (len(launched), E))
                self.assertTrue(server.vllm_park())
                os.environ["YOUGORI_MODEL_LAUNCH"] = E
                pending.append(False)
                server.load_vllm()
                self.assertEqual((len(launches), server.STATE["launch"]), (len(launched) + 1, E))

    def test_a_megakernel_launch_serves_through_its_host_or_falls_back_to_vllm(self):
        # The saved launch "megakernel" with a runner starts the host (load_megakernel) on the
        # verified checkpoint, skipping vLLM's registry and memory checks; when the host cannot
        # serve, vLLM's own checks run and its launches follow, with why in health. Without a
        # runner, or with adapters, the default launch serves.
        for runner, adapters, served, launched in (("/yougori-runner", None, True, []), ("/yougori-runner", None, False, ["speculative"]),
                                                   (None, None, None, ["speculative"]), ("/yougori-runner", (2, 16), None, ["compiled"])):
            with self.subTest(runner=runner, adapters=adapters, served=served), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                root = Path(folder)/"mount"; root.mkdir()
                fixture = local_vllm_startup(stack, root)
                stack.enter_context(patch.object(server, "VLLM_PARKED", None)); stack.enter_context(patch.object(server, "VLLM_ROOT", None))
                stack.enter_context(patch.object(server, "FORMAT", "vllm"))
                stack.enter_context(patch.object(server, "MEGAKERNEL", None)); stack.enter_context(patch.object(server, "MEGAKERNEL_REFUSED", None))
                stack.enter_context(patch.object(server, "adapter_limits", return_value=adapters))
                stack.enter_context(patch.dict(os.environ, YOUGORI_MODEL_LAUNCH="megakernel"))
                if runner: os.environ["YOUGORI_MODEL_RUNNER"] = runner
                else: os.environ.pop("YOUGORI_MODEL_RUNNER", None)
                calls = []
                def load_megakernel(root_, config, revision):
                    calls.append((root_, config["architectures"], revision))
                    if served:
                        server.MEGAKERNEL = {"serving": True, "name": "fixture"}
                        server.STATE.update(status="ready", runner="megakernel", launch="megakernel", gpu="fixture GPU")
                        return True
                    server.MEGAKERNEL_REFUSED = "the check question went unanswered"
                    server.STATE["megakernel"] = {"serving": False, "refused": server.MEGAKERNEL_REFUSED}
                    return False
                stack.enter_context(patch.object(server, "load_megakernel", load_megakernel))
                server.load_vllm()
                mode = lambda args: "eager" if "--enforce-eager" in args else "speculative" if "--speculative-config" in args else "compiled"
                self.assertEqual([mode(call.args[0]) for call in fixture.spawn.call_args_list], launched)
                self.assertEqual(len(calls), 1 if served is not None else 0)
                if served:
                    self.assertEqual(calls[0][0], os.path.realpath(root)); self.assertEqual(calls[0][2], fixture.revision)
                    self.assertEqual(fixture.hardware.call_count, 0, "the runner's manifest states the GPU it needs")
                    self.assertEqual((server.STATE["runner"], server.STATE["launch"]), ("megakernel", "megakernel"))
                    self.assertEqual(fixture.admission.call_count, 1)
                elif served is False:
                    self.assertEqual(fixture.hardware.call_count, 1, "vLLM's memory check runs once it serves after all")
                    self.assertEqual((server.STATE["runner"], server.STATE["launch"]), ("vllm", "speculative"))
                    self.assertEqual(server.STATE["megakernel"]["refused"], "the check question went unanswered")
                    self.assertIsNone(server.MEGAKERNEL)
                else:
                    self.assertEqual(fixture.hardware.call_count, 1)
                    self.assertEqual(server.STATE["launch"], launched[0])
                # A reload in the same process after a refusal goes straight to vLLM.
                if served is False:
                    server.gpu_release_memory()
                    server.load_vllm()
                    self.assertEqual(len(calls), 1); self.assertEqual(server.STATE["launch"], "speculative")

    def test_a_megakernel_launch_has_no_adapters_or_kv_reuse_and_reports_the_runner(self):
        with ExitStack() as stack:
            stack.enter_context(patch.object(server, "FORMAT", "vllm")); stack.enter_context(patch.dict(server.STATE, status="ready"))
            stack.enter_context(patch.object(server, "MEGAKERNEL", {"serving": True, "name": "fixture", "tokensPerSecond": 640.5}))
            stack.enter_context(patch.dict(server.LLAMA, slots=1, pool=0, servingFallback=None))
            stack.enter_context(patch.dict(os.environ, YOUGORI_VLLM_ADAPTERS="2:16"))
            self.assertIsNone(server.adapter_limits(), "a megakernel launch serves no adapters whatever the owner saved")
            with self.assertRaisesRegex(server.BackendRefusal, "megakernel launch serves no LoRA adapters"):
                server.adapter_attach("a", "acme/adapter", "a" * 40)
            self.assertEqual(server.kv_check({"action": "reset"})["slots"], 0)
            capabilities = server.backend_capabilities()
            self.assertFalse(capabilities["adapters"]["supported"]); self.assertFalse(capabilities["kvReuse"]["supported"])
            self.assertEqual(capabilities["megakernel"]["tokensPerSecond"], 640.5)
            self.assertEqual(server.backend_observation_start(), {}, "no vLLM metrics are read from the host")
            self.assertFalse(server.vllm_park())
        # vllm_launch keeps megakernel only with a runner and no adapters.
        with patch.dict(os.environ, YOUGORI_MODEL_LAUNCH="megakernel", YOUGORI_MODEL_RUNNER="/yougori-runner"):
            self.assertEqual(server.vllm_launch(False, None), "megakernel")
            self.assertEqual(server.vllm_launch(False, (1, 8)), "compiled")
            self.assertEqual(server.vllm_launch(True, None), "eager")
            os.environ.pop("YOUGORI_MODEL_RUNNER")
            self.assertEqual(server.vllm_launch(False, None), "speculative")

    def test_the_launch_mode_picks_cuda_graphs_and_compilation_speculation_or_eager(self):
        speculation = ["--speculative-config", server.NGRAM_SPECULATION]
        self.assertEqual(json.loads(server.NGRAM_SPECULATION)["method"], "ngram")
        for mode, adapters, expected, flags in ((None, None, "speculative", speculation), ("compiled", None, "compiled", []),
                                                ("speculative", None, "speculative", speculation), ("eager", None, "eager", ["--enforce-eager"]),
                                                ("unknown", None, "speculative", speculation), ("speculative", (2, 16), "compiled", []),
                                                (None, (2, 16), "compiled", [])):
            with self.subTest(mode=mode, adapters=adapters), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                root = Path(folder)/"mount"; root.mkdir()
                fixture = local_vllm_startup(stack, root)
                stack.enter_context(patch.object(server, "VLLM_PARKED", None)); stack.enter_context(patch.object(server, "VLLM_ROOT", None))
                stack.enter_context(patch.object(server, "FORMAT", "vllm"))
                stack.enter_context(patch.object(server, "adapter_limits", return_value=adapters))
                cache = Path(folder)/"volume"; cache.mkdir()
                stack.enter_context(patch.object(server, "CACHE", str(cache)))
                stack.enter_context(patch.dict(os.environ, YOUGORI_MODEL_LAUNCH=mode or ""))
                if mode is None:
                    os.environ.pop("YOUGORI_MODEL_LAUNCH")
                server.load_vllm()
                args, env = fixture.spawn.call_args.args[0], fixture.spawn.call_args.kwargs["env"]
                # The base list asks vLLM to report cached prompt tokens and leaves graphs and compilation on.
                self.assertIn("--enable-prompt-tokens-details", args)
                self.assertEqual([a for a in args if a in ("--enforce-eager", "--speculative-config", server.NGRAM_SPECULATION)], flags)
                self.assertEqual(server.STATE["launch"], expected)
                self.assertEqual("--enable-lora" in args, adapters is not None)
                # Compiled graphs go to the model's cache volume, so a restart reuses them.
                self.assertEqual(env["VLLM_CACHE_ROOT"], os.path.join(str(cache), "vllm-compile"))
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)/"mount"; root.mkdir()
            fixture = local_vllm_startup(stack, root)
            stack.enter_context(patch.object(server, "VLLM_PARKED", None)); stack.enter_context(patch.object(server, "VLLM_ROOT", None))
            stack.enter_context(patch.object(server, "CACHE", str(Path(folder)/"missing")))
            server.load_vllm()
            self.assertNotIn("VLLM_CACHE_ROOT", fixture.spawn.call_args.kwargs["env"])
            self.assertFalse((Path(folder)/"missing").exists())

    def test_replies_report_the_prompt_tokens_the_backend_reused_from_its_cache(self):
        # vLLM: usage.prompt_tokens_details, at most the prompt; left out when none were reused.
        with patch.object(server, "FORMAT", "vllm"):
            self.assertEqual(server.backend_cached({"prompt_tokens_details": {"cached_tokens": 64}}, None, 80), 64)
            self.assertEqual(server.backend_cached({"prompt_tokens_details": {"cached_tokens": 96}}, None, 80), 80)
            self.assertEqual(server.backend_cached({"completion_tokens": 3}, None, 80), 0)
        # llama.cpp: timings.cache_n; with no report, nothing is claimed.
        with patch.object(server, "FORMAT", "gguf"):
            self.assertEqual(server.backend_cached(None, {"cache_n": 20, "prompt_n": 5}, 25), 20)
            self.assertIsNone(server.backend_cached({"completion_tokens": 3}, None, 25))
            self.assertIsNone(server.backend_cached(None, {"cache_n": -1}, 25))
            self.assertEqual(server.cache_details(None), {})
            # A stream's final chunk carries it.
            handler = Mock(wfile=io.BytesIO())
            events = [{"choices": [{"delta": {"content": "Hi"}, "finish_reason": None}]},
                      {"choices": [{"delta": {}, "finish_reason": "stop"}], "timings": {"cache_n": 7, "prompt_n": 3}},
                      {"choices": [], "usage": {"completion_tokens": 1}}]
            response = io.BytesIO(b"".join(b"data: " + json.dumps(event).encode() + b"\n\n" for event in events) + b"data: [DONE]\n\n")
            meter = {}
            server.stream_gguf(handler, response, 10, 30, {}, meter)
        self.assertEqual(meter["outcome"], "ok")
        final = [json.loads(line[6:]) for line in handler.wfile.getvalue().decode().splitlines() if line.startswith("data: {")][-1]
        self.assertEqual(final["usage"], {"prompt_tokens": 10, "completion_tokens": 1, "total_tokens": 11, "prompt_tokens_details": {"cached_tokens": 7}})

    def test_a_parallel_llama_cpp_launch_shares_one_kv_pool_and_falls_back_to_one_slot_once(self):
        for exits, props, served in (([False], {"total_slots": 4, "default_generation_settings": {"n_ctx": 32768}}, (4, 32768)),
                                     ([True, False], {"total_slots": 1, "default_generation_settings": {"n_ctx": 32768}}, (1, 0))):
            with self.subTest(exits=exits), tempfile.TemporaryDirectory() as saves, ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, YOUGORI_MODEL_PARALLEL="4", YOUGORI_MODEL_CPU="1"))
                os.environ.pop("YOUGORI_NATIVE_BACKEND", None)
                stack.enter_context(patch.object(server, "FORMAT", "gguf"))
                # The queue as an earlier parallel launch left it: four slots sharing a pool.
                queue = server.InferenceQueue(slots=4)
                queue.pool = 32768
                stack.enter_context(patch.object(server, "INFERENCE_QUEUE", queue))
                stack.enter_context(patch.dict(server.STATE)); stack.enter_context(patch.dict(server.LLAMA, port=1, key="k"))
                launches, during, pending = [], [], list(exits)
                seen = lambda *args, result=None, **kwargs: (during.append((server.INFERENCE_QUEUE.slots, server.INFERENCE_QUEUE.pool)), result)[1]
                for name, value in (("install", Mock(side_effect=seen)), ("llama_server", Mock(side_effect=lambda: seen(result="/opt/llama/llama-server"))),
                                    ("verified_gguf", Mock(side_effect=lambda: seen(result="/models/model.gguf"))), ("gpu_before_load", Mock(side_effect=seen)),
                                    ("llama", Mock(return_value=(Mock(), Mock(status=200)))), ("llama_json", Mock(return_value=props)),
                                    ("ENGINE_PROCESS", None)):
                    stack.enter_context(patch.object(server, name, value))
                def popen(args, **kwargs):
                    launches.append(list(args)); seen()
                    return Mock(poll=Mock(return_value=1 if pending.pop(0) else None), returncode=1)
                stack.enter_context(patch.object(server.subprocess, "run"))
                stack.enter_context(patch.object(server.subprocess, "Popen", side_effect=popen))
                stack.enter_context(patch.object(server.threading, "Thread"))
                stack.enter_context(patch.object(server.tempfile, "mkdtemp", return_value=saves))
                server.load_gguf()
                first = launches[0]
                self.assertEqual(first[first.index("-np")+1:first.index("-np")+3], ["4", "--kv-unified"])
                for args in launches:
                    self.assertEqual((args[args.index("-c")+1], args[args.index("--cache-ram")+1]), ("32768", "0"))
                if len(exits) == 2:
                    self.assertEqual(launches[1][launches[1].index("-np")+1], "1")
                    self.assertNotIn("--kv-unified", launches[1])
                    self.assertIn("exit code 1", server.STATE["servingFallback"])
                else:
                    self.assertNotIn("servingFallback", server.STATE)
                # One request and no pool from the load's start (dependencies, download, GPU
                # admission, every launch attempt), then the slots and pool the launch reports.
                self.assertEqual(during, [(1, 0)] * (4 + len(exits)))
                self.assertEqual((server.INFERENCE_QUEUE.slots, server.INFERENCE_QUEUE.pool), served)
                self.assertEqual((server.LLAMA["slots"], server.LLAMA["pool"]), served)
                self.assertEqual(server.backend_capabilities()["concurrency"]["slots"], served[0])
                self.assertEqual(server.STATE["status"], "ready")

    def test_a_parked_vllm_sleeps_and_wakes_with_its_weights_reloaded_instead_of_restarting(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)/"mount"; root.mkdir()
            fixture = local_vllm_startup(stack, root)
            stack.enter_context(patch.object(server, "VLLM_PARKED", None)); stack.enter_context(patch.object(server, "VLLM_ROOT", None))
            stack.enter_context(patch.object(server, "FORMAT", "vllm"))
            server.load_vllm()
            args = fixture.spawn.call_args.args[0]; env = fixture.spawn.call_args.kwargs["env"]
            self.assertIn("--enable-sleep-mode", args); self.assertEqual(env["VLLM_SERVER_DEV_MODE"], "1")
            calls, refuse = [], set()
            def engine(path, body=None, timeout=30):
                calls.append((path, body))
                if path in refuse: raise ValueError("refused")
                return {}
            stack.enter_context(patch.object(server, "llama_json", side_effect=engine))
            process = server.ENGINE_PROCESS
            self.assertTrue(server.vllm_park())
            self.assertFalse(server.vllm_park(), "a parked engine is not parked twice")
            server.load_vllm()
            self.assertEqual(fixture.spawn.call_count, 1, "the parked engine woke; nothing was started")
            self.assertEqual(calls, [("/sleep?level=2", {}), ("/wake_up", {}), ("/collective_rpc", {"method": "reload_weights"})])
            self.assertIs(server.ENGINE_PROCESS, process); self.assertEqual(server.STATE["status"], "ready")
            self.assertEqual(fixture.verify.call_count, 2 * len(fixture.files), "the files are verified before the weights reload")
            # A refused wake ends the parked engine and starts another; a refused sleep parks nothing.
            self.assertTrue(server.vllm_park()); refuse.add("/wake_up")
            server.load_vllm()
            self.assertEqual(fixture.spawn.call_count, 2); process.terminate.assert_called()
            refuse.add("/sleep?level=2")
            self.assertFalse(server.vllm_park()); self.assertIsNone(server.VLLM_PARKED)

    def test_vllm_local_path_manifest_mismatch_refuses_before_starting_the_engine(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)/"mount"; root.mkdir()
            fixture = local_vllm_startup(stack, root)
            (root/"model-00002-of-00002.safetensors").write_bytes(b"fixture weights TWO")  # same size, other bytes
            with self.assertRaisesRegex(RuntimeError, "checksum verification"): server.load_vllm()
            (root/"model-00002-of-00002.safetensors").write_bytes(b"fixture weights two"); os.unlink(root/"config.json")
            with self.assertRaisesRegex(RuntimeError, "checksum verification"): server.load_vllm()
            (root/"config.json").write_bytes(json.dumps(LOCAL_VLLM_CONFIG).encode())
            with patch.object(server, "MODEL_REVISION", "b"*64), self.assertRaisesRegex(RuntimeError, "revision does not match"): server.load_vllm()
            fixture.spawn.assert_not_called(); fixture.admission.assert_not_called(); fixture.hardware.assert_not_called()
            fixture.hub.HfApi.assert_not_called()
            self.assertIsNone(server.REGISTRY_VERIFIED); self.assertFalse(server.STATE["sourceReused"])
            server.load_vllm()  # the restored mount verifies and starts
            self.assertEqual(fixture.spawn.call_count, 1)

    def test_vllm_without_model_path_keeps_the_hugging_face_source(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            config = {"model_type":"kolibri1", "architectures":["Kolibri1ForCausalLM"], "num_attention_heads":8, "num_key_value_heads":8, "max_position_embeddings":2048}
            path = Path(folder)/"config.json"; path.write_text(json.dumps(config))
            meta = SimpleNamespace(sha="a"*40, siblings=[SimpleNamespace(rfilename="model.safetensors", size=2**30)])
            hub = SimpleNamespace(HfApi=Mock(), hf_hub_download=Mock(return_value=str(path))); hub.HfApi.return_value.model_info.return_value = meta
            cuda = SimpleNamespace(is_available=lambda:True, device_count=lambda:1, get_device_capability=lambda i:(9,0), mem_get_info=lambda i:(8*2**30, 8*2**30), get_device_name=lambda i:"fixture GPU")
            stack.enter_context(patch.dict("sys.modules", torch=SimpleNamespace(cuda=cuda), huggingface_hub=hub))
            for name, value in (("MODEL_PATH", None), ("MODEL_REVISION", "a"*40), ("VLLM_PREPARED", None), ("ENGINE_PROCESS", None)):
                stack.enter_context(patch.object(server, name, value))
            stack.enter_context(patch.object(server.importlib.metadata, "version", return_value=server.VLLM_VERSION))
            stack.enter_context(patch.object(server, "kolibri_plugin"))
            stack.enter_context(patch.object(server, "registry_snapshot", side_effect=AssertionError("local verifier on the Hugging Face path")))
            snapshot = stack.enter_context(patch.object(server, "verified_snapshot", return_value=folder))
            spawn = stack.enter_context(patch.object(server.subprocess, "Popen", return_value=Mock(poll=Mock(return_value=None))))
            stack.enter_context(patch.object(server, "llama", return_value=(Mock(), Mock(status=200))))
            stack.enter_context(patch.object(server.threading, "Thread")); stack.enter_context(patch.object(server, "gpu_before_load"))
            stack.enter_context(patch.dict(server.STATE)); stack.enter_context(patch.dict(server.LLAMA))
            stack.enter_context(patch.dict(os.environ, YOUGORI_VLLM_SOURCE_REUSE="0"))
            server.load_vllm()
            hub.HfApi.return_value.model_info.assert_called_once_with(server.MODEL, revision="a"*40, files_metadata=True, timeout=30)
            hub.hf_hub_download.assert_called_once_with(server.MODEL, "config.json", revision="a"*40)
            snapshot.assert_called_once_with("a"*40)
            args = spawn.call_args.args[0]; self.assertEqual(args[args.index("serve")+1], folder)
            self.assertEqual(server.STATE["source"], "huggingface"); self.assertFalse(server.STATE["sourceReused"])
            # Only a 40-hex commit pins a Hugging Face checkpoint; the 64-hex manifest digest belongs to local mounts.
            with patch.object(server, "MODEL_REVISION", "a"*64), self.assertRaisesRegex(RuntimeError, "immutable revision"): server.load_vllm()
            self.assertEqual(hub.HfApi.return_value.model_info.call_count, 1); self.assertEqual(spawn.call_count, 1)

    # Review finding R5: a path and revision remembered from an earlier load are not a content proof.
    # Every warm load runs the verifier again; a changed file refuses before the engine respawns.
    def warm_local_mutation(self, name, mutate, message):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)/"mount"; root.mkdir()
            fixture = local_vllm_startup(stack, root)
            server.load_vllm()
            self.assertEqual(fixture.spawn.call_count, 1)
            self.assertEqual(fixture.verify.call_count, len(fixture.files))
            server.gpu_release_memory()
            path = root/name
            before = path.read_bytes()
            changed = mutate(before)
            self.assertNotEqual(before, changed)
            path.write_bytes(changed)
            with self.assertRaisesRegex(RuntimeError, message):
                server.load_vllm()
            self.assertEqual(fixture.spawn.call_count, 1, "the warm load respawned on changed files")
            self.assertEqual(fixture.admission.call_count, 1, "no admission for a refused reload")
            self.assertFalse(server.STATE["sourceReused"])
            self.assertIsNone(server.REGISTRY_VERIFIED, "a refused check leaves no memo for the next load")
            self.assertGreater(fixture.verify.call_count, len(fixture.files), "the warm load hashed the mount again")
            # Restoring the file restores the load: a fresh verification, since the refused
            # check left no memo, not a reuse.
            path.write_bytes(before)
            server.load_vllm()
            self.assertEqual(fixture.spawn.call_count, 2)
            self.assertFalse(server.STATE["sourceReused"])

    def test_r5_warm_local_weights_are_rechecked_before_respawn(self):
        def same_length_other_bytes(before):
            changed = b"fixture weights TWO"
            self.assertEqual(len(before), len(changed))
            self.assertNotEqual(hashlib.sha256(before).digest(), hashlib.sha256(changed).digest())
            return changed
        self.warm_local_mutation("model-00002-of-00002.safetensors", same_length_other_bytes, "checksum verification")

    def test_r5_warm_local_config_is_rechecked_before_respawn(self):
        def wider_context_same_length(before):
            changed = before.replace(b"4096", b"8192")
            self.assertEqual(len(before), len(changed))
            return changed
        self.warm_local_mutation("config.json", wider_context_same_length, "checksum verification")
        # The refused configuration never became the serving context.
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)/"mount"; root.mkdir()
            fixture = local_vllm_startup(stack, root)
            server.load_vllm(); server.gpu_release_memory()
            (root/"config.json").write_bytes(json.dumps({**LOCAL_VLLM_CONFIG, "max_position_embeddings":8192}).encode())
            with self.assertRaisesRegex(RuntimeError, "checksum verification"): server.load_vllm()
            self.assertEqual(server.LLAMA["context"], 4096)
            self.assertEqual(fixture.spawn.call_count, 1)

    def test_r5_warm_local_removed_file_is_refused_before_respawn(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)/"mount"; root.mkdir()
            fixture = local_vllm_startup(stack, root)
            server.load_vllm(); server.gpu_release_memory()
            os.unlink(root/"tokenizer_config.json")
            with self.assertRaisesRegex(RuntimeError, "checksum verification"): server.load_vllm()
            self.assertEqual(fixture.spawn.call_count, 1)
            self.assertIsNone(server.REGISTRY_VERIFIED)

    def test_r5_warm_imported_copy_is_rechecked_and_a_changed_copy_is_imported_again(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            root = Path(folder)/"mount"; root.mkdir()
            volume = Path(folder)/"volume"; volume.mkdir()
            fixture = local_vllm_startup(stack, root)
            stack.enter_context(patch.dict(os.environ, YOUGORI_MODEL_IMPORT="1"))
            for name, value in (("CACHE", str(volume)), ("MODEL_IMPORTED", None), ("RUNNER_TIMINGS", server.RunnerTimings())):
                stack.enter_context(patch.object(server, name, value))
            server.load_vllm()
            self.assertEqual(server.STATE["source"], "imported"); self.assertFalse(server.STATE["sourceReused"])
            copied = Path(server.MODEL_IMPORTED[2])
            self.assertTrue(copied.is_relative_to(Path(os.path.realpath(volume))))
            args = fixture.spawn.call_args.args[0]
            self.assertEqual(args[args.index("serve")+1], str(copied), "vLLM serves the imported copy, not the mount")
            # An unchanged copy passes its cheap check and is reused without reading the mount.
            server.gpu_release_memory()
            with source_opens(root) as opened:
                server.load_vllm()
            self.assertEqual(opened, [])
            self.assertTrue(server.STATE["sourceReused"]); self.assertEqual(server.STATE["source"], "imported-cached")
            self.assertEqual(fixture.spawn.call_count, 2)
            # A copy changed while the model was unloaded fails its check: it is discarded and
            # imported again from the mount, and the load is not a reuse.
            server.gpu_release_memory()
            target = copied/"model-00002-of-00002.safetensors"
            target.write_bytes(b"fixture weights TWO")
            server.load_vllm()
            self.assertEqual(fixture.spawn.call_count, 3)
            self.assertEqual(target.read_bytes(), b"fixture weights two", "the copy was imported again from the mount")
            self.assertEqual(server.STATE["source"], "imported"); self.assertEqual(server.STATE["import"]["status"], "imported")
            self.assertFalse(server.STATE["sourceReused"], "a copy imported again is not reuse")
            # With the mount changed as well, nothing can be imported and the load refuses.
            server.gpu_release_memory()
            target.write_bytes(b"fixture weights TWO")
            (root/"model-00002-of-00002.safetensors").write_bytes(b"fixture weights TWO")
            with self.assertRaisesRegex(RuntimeError, "checksum verification"): server.load_vllm()
            self.assertEqual(fixture.spawn.call_count, 3)
            self.assertFalse(server.STATE["sourceReused"])


IMPORT_CONTENTS = {"config.json": json.dumps(LOCAL_VLLM_CONFIG).encode(), "model-00001-of-00002.safetensors": b"fixture weights one",
                   "model-00002-of-00002.safetensors": b"fixture weights two", "nested/tokenizer.json": b'{"fixture":"tokenizer"}',
                   "model-q4.gguf": b"fixture gguf weights"}


def manifest_for(contents):
    files = [{"name":name, "size":len(data), "sha256":hashlib.sha256(data).hexdigest()} for name, data in contents.items()]
    return files, hashlib.sha256(json.dumps(files).encode()).hexdigest()  # model_runner/local.rs: the 64-hex manifest digest


def import_fixture(stack, folder, contents=IMPORT_CONTENTS, registry=False):
    """A source folder behind YOUGORI_MODEL_PATH and an empty model volume at CACHE, in an environment
    the engine made with its own volume (YOUGORI_MODEL_IMPORT=1). `registry` puts the manifest in the
    folder, as a registry version has it, instead of YOUGORI_LOCAL_MANIFEST."""
    source, volume = Path(folder)/"source", Path(folder)/"volume"
    source.mkdir(); volume.mkdir()
    for name, data in contents.items():
        (source/name).parent.mkdir(parents=True, exist_ok=True); (source/name).write_bytes(data)
    files, revision = manifest_for(contents)
    environment = {"YOUGORI_REGISTRY_SOURCE":VERIFIER_SOURCE, "YOUGORI_MODEL_IMPORT":"1"}
    if registry:
        (source/".yougori-verified-files.json").write_text(json.dumps({"revision":revision, "files":files}))
    else:
        environment["YOUGORI_LOCAL_MANIFEST"] = json.dumps({"revision":revision, "files":files})
    stack.enter_context(patch.dict(os.environ, environment))
    if registry:
        os.environ.pop("YOUGORI_LOCAL_MANIFEST", None)
    for name, value in (("MODEL_PATH", str(source)), ("MODEL_REVISION", revision), ("REGISTRY_VERIFIED", None), ("MODEL_IMPORTED", None),
                        ("CACHE", str(volume)), ("TRANSFORMERS_PREPARED", None), ("RUNNER_TIMINGS", server.RunnerTimings())):
        stack.enter_context(patch.object(server, name, value))
    stack.callback(lambda: [server.__dict__.pop(key, None) for key in ("MODEL_SNAPSHOT_ROOT", "MODEL_SNAPSHOT_FILES")])
    stack.enter_context(patch.dict(server.STATE))
    imports = volume/"yougori-import"
    return SimpleNamespace(source=source, volume=volume, files=files, revision=revision, contents=contents, imports=imports,
                           committed=imports/revision, root=os.path.realpath(imports/revision/"model"))


@contextmanager
def source_opens(root):
    """Every open() of a path under `root`, with its mode; reads through the bind are counted here."""
    real_open, opened, prefix = open, [], os.path.realpath(root) + os.sep
    def watch(file, mode="r", *args, **kwargs):
        if isinstance(file, (str, os.PathLike)) and os.path.realpath(file).startswith(prefix):
            opened.append((os.path.realpath(file)[len(prefix):].replace(os.sep, "/"), mode))
        return real_open(file, mode, *args, **kwargs)
    with patch("builtins.open", watch):
        yield opened


def source_state(root):
    return {str(path.relative_to(root)): (path.read_bytes(), path.stat().st_mtime_ns, path.stat().st_mode)
            for path in sorted(Path(root).rglob("*")) if path.is_file()}


class ModelImportTests(unittest.TestCase):
    """G04: /yougori-model is an import source, read once; every load reads the copy in the model's volume."""
    def reset(self):
        server.REGISTRY_VERIFIED = None

    def test_first_start_imports_each_file_once_and_every_loader_reads_the_imported_root(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            fixture = import_fixture(stack, folder)
            stack.enter_context(patch.object(server, "IMPORT_BUFFER", 8))
            progress, real_progress = [], server.import_progress
            def observe(copied, total, started):
                real_progress(copied, total, started)
                progress.append((server.STATE["status"], dict(server.STATE["download"])))
            with patch.object(server, "import_progress", side_effect=observe), source_opens(fixture.source) as opened, \
                 patch.object(server, "verify_file", wraps=server.verify_file) as hashed, server.RUNNER_TIMINGS.run("load"):
                root = server.registry_snapshot()
            self.assertEqual(root, fixture.root)
            self.assertEqual(sorted(opened), sorted((name, "rb") for name in fixture.contents), "each source file is opened once, read-only")
            self.assertTrue(all(not os.path.realpath(call.args[0]).startswith(os.path.realpath(fixture.source)) for call in hashed.call_args_list),
                            "the mount is never hashed a second time; the read-back hashes the copy")
            for name, data in fixture.contents.items():
                self.assertEqual((Path(root)/name).read_bytes(), data)
            total = sum(len(data) for data in fixture.contents.values())
            self.assertGreater(len(progress), len(fixture.contents), "large reads are bounded by the import buffer")
            self.assertTrue(all(status == "downloading" and download["transport"] == "yougori-import" and download["totalBytes"] == total
                                for status, download in progress))
            self.assertEqual([download["receivedBytes"] for _status, download in progress][-1], total)
            self.assertEqual(server.STATE["source"], "imported")
            self.assertEqual(server.STATE["import"]["status"], "imported"); self.assertEqual(server.STATE["import"]["totalBytes"], total)
            self.assertEqual(server.STATE["download"], {**server.STATE["download"], "receivedBytes":total, "totalBytes":total, "transport":"yougori-import"})
            stages = server.RUNNER_TIMINGS.snapshot()["recent"][-1]["stages"]
            self.assertEqual((stages["import"]["calls"], stages["import"]["failedCalls"]), (1, 0))
            self.assertEqual(server.MODEL_SNAPSHOT_ROOT, root); self.assertEqual(server.MODEL_SNAPSHOT_FILES, list(fixture.contents))
            self.assertEqual(sorted(path.name for path in fixture.imports.iterdir()), [fixture.revision], "no temporary directory remains")
            record = json.loads((fixture.committed/"import.json").read_text())
            self.assertEqual(set(record), {"version", "revision", "manifest", "bytes", "files"}); self.assertEqual(record["bytes"], total)
            # The other loaders take the same imported root, never the mount.
            self.reset()
            with source_opens(fixture.source) as opened:
                self.assertEqual(server.local_vllm_source()[0], root)
                self.reset()
                gguf = [file for file in fixture.files if file["name"].endswith(".gguf")]
                with patch.dict(os.environ, YOUGORI_MODEL_FILES=json.dumps(gguf)):
                    self.assertEqual(server.verified_gguf(), os.path.join(root, "model-q4.gguf"))
            self.assertEqual(opened, [])
            self.assertEqual(server.MODEL_SNAPSHOT_ROOT, root, "publisher downloads read the same copy")

    def test_a_transformers_load_and_reload_read_only_the_imported_root(self):
        with tempfile.TemporaryDirectory() as folder, model_startup() as startup, ExitStack() as stack:
            fixture = import_fixture(stack, folder)
            server.load_model()
            self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
            startup.hub.HfApi.assert_not_called()
            self.assertEqual(startup.transformers.AutoConfig.from_pretrained.call_args.args[0], fixture.root)
            self.assertEqual(startup.transformers.AutoTokenizer.from_pretrained.call_args.args[0], fixture.root)
            self.assertEqual(startup.models.from_pretrained.call_args.args[0], fixture.root)
            self.assertEqual(server.STATE["source"], "imported"); self.assertFalse(server.STATE["sourceReused"])
            # The same memo serves the imported root: a reload checks stamps only, with the folder gone.
            shutil.rmtree(fixture.source)
            with patch.object(server, "registry_snapshot", side_effect=AssertionError("import check on a reload")), \
                 patch.object(server, "verify_file", side_effect=AssertionError("rehash on a reload")):
                server.load_model()
            self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
            self.assertTrue(server.STATE["sourceReused"]); self.assertEqual(server.STATE["source"], "imported-cached")
            self.assertEqual(startup.transformers.AutoConfig.from_pretrained.call_count, 1)
            self.assertEqual(startup.models.from_pretrained.call_count, 2)
            self.assertEqual(startup.models.from_pretrained.call_args.args[0], fixture.root)

    def test_a_second_start_reuses_the_import_without_reading_the_source(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            fixture = import_fixture(stack, folder)
            first = server.registry_snapshot()
            self.reset(); server.STATE.pop("import")
            shutil.rmtree(fixture.source)  # Nothing is left to read: the start must not need it.
            (fixture.imports/".tmp-0123456789abcdef"/"model").mkdir(parents=True)  # A stopped import's leftovers.
            with source_opens(fixture.source) as opened, patch.object(server, "verify_file", side_effect=AssertionError("rehashed a cached copy")), \
                 server.RUNNER_TIMINGS.run("load"):
                self.assertEqual(server.registry_snapshot(), first)
            self.assertEqual(opened, [])
            self.assertEqual(server.STATE["source"], "imported-cached"); self.assertEqual(server.STATE["import"]["status"], "imported-cached")
            self.assertNotIn("import", server.RUNNER_TIMINGS.snapshot()["recent"][-1]["stages"])
            self.assertEqual(server.MODEL_IMPORTED[2], first)
            self.assertEqual([path.name for path in fixture.imports.iterdir()], [fixture.revision])

    def test_a_tampered_source_file_fails_the_import_and_commits_nothing(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            fixture = import_fixture(stack, folder)
            (fixture.source/"model-00002-of-00002.safetensors").write_bytes(b"fixture weights TWO")  # Same size, other bytes.
            with server.RUNNER_TIMINGS.run("load"), self.assertRaisesRegex(RuntimeError, "checksum verification"):
                server.registry_snapshot()
            self.assertEqual(list(fixture.imports.iterdir()), [], "no committed directory and no partial copy")
            self.assertEqual((server.STATE["import"]["status"], server.STATE["import"]["stage"]), ("failed", "verify"))
            self.assertIsNone(server.REGISTRY_VERIFIED); self.assertIsNone(server.MODEL_IMPORTED)
            self.assertEqual(server.RUNNER_TIMINGS.snapshot()["recent"][-1]["stages"]["import"]["failedCalls"], 1)
            (fixture.source/"model-00002-of-00002.safetensors").write_bytes(b"fixture weights twice")  # Another size.
            with self.assertRaisesRegex(RuntimeError, "checksum verification"):
                server.registry_snapshot()
            self.assertEqual(server.STATE["import"]["stage"], "preflight")
            (fixture.source/"model-00002-of-00002.safetensors").write_bytes(b"fixture weights two")
            self.assertEqual(server.registry_snapshot(), fixture.root)

    def test_an_interrupted_import_leaves_only_a_temporary_directory_that_the_next_import_removes(self):
        for interruption in (OSError(28, "No space left on device"), KeyboardInterrupt()):
            with self.subTest(interruption=type(interruption).__name__), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                fixture = import_fixture(stack, folder)
                stack.enter_context(patch.object(server, "IMPORT_BUFFER", 4))
                calls = []
                def interrupt(copied, total, started):
                    calls.append(copied)
                    if len(calls) == 5:
                        raise interruption
                with patch.object(server, "import_progress", side_effect=interrupt), \
                     self.assertRaises(RuntimeError if isinstance(interruption, OSError) else KeyboardInterrupt) as raised:
                    server.registry_snapshot()
                if isinstance(interruption, OSError):
                    self.assertIn("No space left on device", str(raised.exception))
                    self.assertEqual((server.STATE["import"]["status"], server.STATE["import"]["stage"]), ("failed", "copy"))
                left = [path.name for path in fixture.imports.iterdir()]
                self.assertEqual(len(left), 1); self.assertTrue(left[0].startswith(".tmp-"))
                self.assertIsNone(server.REGISTRY_VERIFIED)
                self.assertEqual(server.registry_snapshot(), fixture.root)
                self.assertEqual([path.name for path in fixture.imports.iterdir()], [fixture.revision])
                self.assertEqual(server.STATE["source"], "imported")

    def test_a_revision_change_imports_into_a_new_directory_and_keeps_the_old_one(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            fixture = import_fixture(stack, folder)
            first = server.registry_snapshot()
            before = source_state(fixture.committed)
            changed = {**fixture.contents, "model-00001-of-00002.safetensors": b"retrained weights one"}
            (fixture.source/"model-00001-of-00002.safetensors").write_bytes(changed["model-00001-of-00002.safetensors"])
            files, revision = manifest_for(changed)
            os.environ["YOUGORI_LOCAL_MANIFEST"] = json.dumps({"revision":revision, "files":files})
            server.MODEL_REVISION = revision
            self.reset()
            second = server.registry_snapshot()
            self.assertEqual(second, os.path.realpath(fixture.imports/revision/"model"))
            self.assertNotEqual(second, first)
            self.assertEqual(sorted(path.name for path in fixture.imports.iterdir()), sorted([fixture.revision, revision]))
            self.assertEqual(source_state(fixture.committed), before, "a committed revision is never overwritten")
            self.assertEqual((Path(second)/"model-00001-of-00002.safetensors").read_bytes(), b"retrained weights one")

    def test_the_source_folder_is_never_written(self):
        for registry in (False, True):
            with self.subTest(registry=registry), tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
                fixture = import_fixture(stack, folder, registry=registry)
                before = source_state(fixture.source)
                with source_opens(fixture.source) as opened:
                    root = server.registry_snapshot()
                    self.reset()
                    self.assertEqual(server.registry_snapshot(), root)
                self.assertTrue(opened and all(mode == "rb" for _name, mode in opened))
                self.assertEqual(source_state(fixture.source), before)
                self.assertFalse((Path(root)/".yougori-verified-files.json").exists(), "the copy holds exactly the manifest's files")

    def test_a_full_volume_refuses_before_copying(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            fixture = import_fixture(stack, folder)
            with patch.object(server.shutil, "disk_usage", return_value=SimpleNamespace(total=2**30, used=2**30 - 4096, free=4096)), \
                 source_opens(fixture.source) as opened, self.assertRaisesRegex(RuntimeError, "storage has 0.0 GB free") as refused:
                server.registry_snapshot()
            self.assertIn("The model folder was not changed", str(refused.exception))
            self.assertEqual(opened, []); self.assertEqual(list(fixture.imports.iterdir()), [])
            self.assertEqual((server.STATE["import"]["status"], server.STATE["import"]["stage"]), ("failed", "space"))

    def test_a_changed_copy_is_discarded_and_imported_again(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            fixture = import_fixture(stack, folder)
            root = server.registry_snapshot()
            (Path(root)/"config.json").write_bytes(json.dumps({**LOCAL_VLLM_CONFIG, "model_type":"other"}).encode()[:len(fixture.contents["config.json"])])
            self.reset()
            with source_opens(fixture.source) as opened:
                self.assertEqual(server.registry_snapshot(), root)
            self.assertIn(("config.json", "rb"), opened)
            self.assertEqual(server.STATE["source"], "imported")
            self.assertEqual((Path(root)/"config.json").read_bytes(), fixture.contents["config.json"])
            self.assertEqual([path.name for path in fixture.imports.iterdir()], [fixture.revision])

    def test_an_environment_without_its_own_volume_keeps_reading_the_mount(self):
        with tempfile.TemporaryDirectory() as folder, ExitStack() as stack:
            fixture = import_fixture(stack, folder)
            os.environ.pop("YOUGORI_MODEL_IMPORT")
            with patch.object(server, "verify_file", wraps=server.verify_file) as hashed:
                self.assertEqual(server.registry_snapshot(), os.path.realpath(fixture.source))
            self.assertEqual(hashed.call_count, len(fixture.contents))
            self.assertFalse(fixture.imports.exists())
            self.assertEqual(server.STATE["download"]["transport"], "yougori-registry")
            self.assertIsNone(server.MODEL_IMPORTED)


class TransformersReuseTests(unittest.TestCase):
    """GPU-W01: a Transformers reload in the same runner reuses its verified Hugging Face source."""
    @contextmanager
    def startup(self, reuse="1"):
        with model_startup(files=("config.json", "model.safetensors", "tokenizer.json")) as fixture, \
             tempfile.TemporaryDirectory() as cache, ExitStack() as stack:
            for item in fixture.hub.HfApi.return_value.model_info.return_value.siblings:
                item.size = len(b"test weights")
            # Verification records live beside, not inside, the snapshot root.
            for name, value in (("CACHE", cache), ("MODEL_REVISION", "a"*40), ("TRANSFORMERS_PREPARED", None),
                                ("SNAPSHOT_METADATA", None), ("RUNNER_TIMINGS", server.RunnerTimings())):
                stack.enter_context(patch.object(server, name, value))
            stack.enter_context(patch.dict(os.environ, YOUGORI_TRANSFORMERS_SOURCE_REUSE=reuse))
            fixture.snapshot = Path(fixture.hub.snapshot_download.return_value)
            yield fixture

    def test_a_reload_makes_no_hugging_face_call_and_starts_no_download_worker(self):
        with self.startup() as fixture:
            server.load_model()
            self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
            self.assertFalse(server.STATE["sourceReused"]); self.assertIsNotNone(server.TRANSFORMERS_PREPARED)
            self.assertEqual(fixture.hub.HfApi.return_value.model_info.call_count, 2)
            fixture.hub.HfApi.side_effect = AssertionError("Hugging Face metadata during a reload")
            fixture.hub.snapshot_download.side_effect = AssertionError("snapshot download during a reload")
            with patch.object(server.subprocess, "Popen", side_effect=AssertionError("download worker during a reload")), \
                 patch.object(server, "verify_file", side_effect=AssertionError("rehash of unchanged files")):
                server.load_model()
            self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
            self.assertTrue(server.STATE["sourceReused"])
            self.assertEqual(fixture.hub.snapshot_download.call_count, 1)
            self.assertEqual(fixture.transformers.AutoConfig.from_pretrained.call_count, 1)
            self.assertEqual(fixture.models.from_pretrained.call_count, 2)
            for loader in (fixture.transformers.AutoTokenizer, fixture.models):
                self.assertEqual(loader.from_pretrained.call_args.kwargs["revision"], "a"*40)
                self.assertTrue(loader.from_pretrained.call_args.kwargs["local_files_only"])
            cold, warm = server.RUNNER_TIMINGS.snapshot()["recent"]
            self.assertTrue({"checkpoint", "snapshot", "weight_load"} <= set(cold["stages"]))
            self.assertTrue({"snapshot", "weight_verification", "weight_load"} <= set(warm["stages"]))
            self.assertFalse({"checkpoint", "download", "weight_hash"} & set(warm["stages"]))
            self.assertEqual(warm["outcome"], "ok")

    def test_a_changed_file_refuses_the_reload(self):
        with self.startup() as fixture:
            server.load_model()
            (fixture.snapshot/"tokenizer.json").write_bytes(b"changed tokenizer")
            server.load_model()
            self.assertEqual(server.STATE["status"], "error")
            self.assertIn("source changed", server.STATE["error"])
            self.assertIsNone(server.TRANSFORMERS_PREPARED)
            self.assertEqual(fixture.models.from_pretrained.call_count, 1)
            failed = server.RUNNER_TIMINGS.snapshot()["recent"][-1]
            self.assertEqual(failed["stages"]["snapshot"]["failedCalls"], 1)

    def test_turning_reuse_off_restores_todays_calls(self):
        with self.startup(reuse="0") as fixture:
            server.load_model()
            server.load_model()
            self.assertEqual(server.STATE["status"], "ready", server.STATE["error"])
            self.assertIsNone(server.TRANSFORMERS_PREPARED); self.assertFalse(server.STATE["sourceReused"])
            self.assertEqual(fixture.hub.HfApi.return_value.model_info.call_count, 4)
            self.assertEqual(fixture.hub.snapshot_download.call_count, 2)
            self.assertEqual(fixture.transformers.AutoConfig.from_pretrained.call_count, 2)


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
            def request(endpoint, body=None, authorized=True, admin=True):
                headers={"Authorization":"Bearer "+server.TOKEN} if authorized else {}
                if authorized and admin: headers["X-Yougori-Admin"]=server.ADMIN_TOKEN
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
            # An API-key holder cannot claim free sharing to turn on recording.
            with self.assertRaises(HTTPError) as error: request("/v1/listen/config",{"enabled":True,"mode":"free"},admin=False)
            self.assertEqual(error.exception.code,403)
            with patch.object(server,"ADMIN_TOKEN",""), self.assertRaises(HTTPError) as error: request("/v1/listen/config",{"enabled":True,"mode":"free"})
            self.assertEqual(error.exception.code,403,"A server without an owner credential refuses owner settings")
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
            body={"model":server.MODEL,"state":"account activity","questions":{"risk":{"type":"noul"}}}
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

    def test_the_adapter_and_kv_routes_answer_only_the_owner_and_say_why_they_refuse(self):
        with self.listener() as (_, request), patch.dict(server.__dict__):
            for route in ("/v1/yougori/adapters", "/v1/yougori/kv"):
                with self.subTest(route=route), self.assertRaises(HTTPError) as error:
                    request(route, {"action": "list"}, admin=False)
                self.assertEqual(error.exception.code, 403)
            server.__dict__.pop("backend_command", None)
            with self.assertRaises(HTTPError) as error:
                request("/v1/yougori/adapters", {"action": "list"})
            self.assertEqual(error.exception.code, 409)
            self.assertIn("Transformers runner serves no adapters", json.loads(error.exception.read())["error"]["message"])
            for failure, status in ((server.BackendRefusal("All 2 adapter slots"), 409), (ValueError("bad"), 400),
                                    (OSError("/private/path"), 502)):
                def command(route, body, failure=failure):
                    raise failure
                server.backend_command = command
                with self.subTest(status=status), self.assertRaises(HTTPError) as error:
                    request("/v1/yougori/adapters", {"action": "attach"})
                self.assertEqual(error.exception.code, status)
                self.assertNotIn("/private/path", error.exception.read().decode())
            with self.assertRaises(HTTPError) as error:
                request("/v1/yougori/kv", ["reset"])
            self.assertEqual(error.exception.code, 400)
            server.backend_command = lambda route, body: {"route": route, "action": body["action"]}
            server.kv_check = lambda body: None
            with request("/v1/yougori/kv", {"action": "reset"}) as response:
                self.assertEqual(json.loads(response.read()), {"route": "kv", "action": "reset"})


class ServingAgreementTests(unittest.TestCase):
    @contextmanager
    def endpoint(self, tools=False):
        def generate(body, handler, meter):
            meter["outcome"] = "ok"
            if body.get("stream"):
                handler.send_response(200)
                handler.send_header("Content-Type", "text/event-stream")
                handler.end_headers()
                handler.wfile.write(b'data: {"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}\n\ndata: [DONE]\n\n')
                return None
            return 200, {"choices":[]}
        with patch.object(server,"gpu_enter",return_value=True) as enter, \
             patch.object(server,"gpu_leave"), patch.object(server,"record_usage"), \
             patch.object(server,"tools_enabled",return_value=tools), \
             patch.object(server,"generate",side_effect=generate) as generated:
            http = server.Server(("127.0.0.1",0), server.Handler)
            worker = threading.Thread(target=http.serve_forever,kwargs={"poll_interval":0.01},daemon=True)
            worker.start()
            try:
                yield http.server_port, enter, generated
            finally:
                http.shutdown();http.server_close();worker.join(2)

    def request(self, port, headers=(), body=None, authorized=True):
        body = body or {"messages":[{"role":"user","content":"synthetic"}],"stream":True}
        data = json.dumps(body).encode()
        connection = http.client.HTTPConnection("127.0.0.1",port,timeout=3)
        try:
            connection.putrequest("POST","/v1/chat/completions")
            if authorized: connection.putheader("Authorization","Bearer "+server.TOKEN)
            connection.putheader("Content-Length",str(len(data)))
            for name,value in headers: connection.putheader(name,value)
            connection.endheaders(data)
            reply = connection.getresponse()
            return reply.status, dict(reply.getheaders()), reply.read()
        finally:
            connection.close()

    def offer(self, version="1", features="stream"):
        return [("X-Yougori-Serving-Protocol",version),("X-Yougori-Serving-Features",features)]

    def tool_body(self):
        return {"messages":[{"role":"user","content":"synthetic"}],"stream":True,
                "tools":[{"type":"function","function":{"name":"lookup","parameters":{"type":"object"}}}]}

    def test_current_and_headerless_clients_receive_the_actual_agreement(self):
        with self.endpoint() as (port,enter,generated):
            for headers in ([],self.offer()):
                status,headers,data=self.request(port,headers)
                self.assertEqual(status,200)
                self.assertEqual(headers["X-Yougori-Serving-Protocol"],"1")
                self.assertEqual(headers["X-Yougori-Serving-Features"],"stream")
                self.assertIn(b"[DONE]",data)
            self.assertEqual(enter.call_count,2)
            self.assertEqual(generated.call_count,2)

    def test_invalid_versions_features_and_duplicates_never_enter_the_model(self):
        with self.endpoint() as (port,enter,generated):
            for headers in (self.offer("2"),self.offer("01"),self.offer(features="unknown"),
                    self.offer(features="stream,stream"),self.offer()[:1],self.offer()[1:],
                    self.offer()+self.offer()[:1],self.offer()+self.offer()[1:]):
                status,_,data=self.request(port,headers)
                self.assertIn(status,(400,412))
                self.assertTrue(json.loads(data)["error"]["code"].startswith("yougori_serving_"))
            enter.assert_not_called();generated.assert_not_called()

    def test_feature_body_mismatch_and_unconfigured_tools_refuse_before_loading(self):
        with self.endpoint() as (port,enter,generated):
            for headers,body,code in [(self.offer(features="stream,tools"),None,"yougori_serving_request"),
                    (self.offer(),self.tool_body(),"yougori_serving_request"),
                    (self.offer(features="stream,tools"),self.tool_body(),"yougori_serving_features")]:
                status,_,data=self.request(port,headers,body)
                self.assertIn(status,(400,412));self.assertEqual(json.loads(data)["error"]["code"],code)
            enter.assert_not_called();generated.assert_not_called()

    def test_tool_route_acknowledges_selection_only_after_request_validation(self):
        with self.endpoint(tools=True) as (port,enter,generated):
            status,headers,_=self.request(port,self.offer(features="stream,tools"),self.tool_body())
            self.assertEqual(status,200);self.assertEqual(headers["X-Yougori-Serving-Features"],"stream,tools")
            body=self.tool_body();body["tools"][0]["function"]["name"]="bad name"
            status,headers,_=self.request(port,self.offer(features="stream,tools"),body)
            self.assertEqual(status,400);self.assertNotIn("X-Yougori-Serving-Features",headers)
            self.assertEqual(generated.call_count,1);self.assertEqual(enter.call_count,1)

    def test_authentication_precedes_version_checks(self):
        with self.endpoint() as (port,enter,generated):
            status,headers,_=self.request(port,self.offer("999"),authorized=False)
            self.assertEqual(status,401);self.assertNotIn("X-Yougori-Serving-Protocol",headers)
            enter.assert_not_called();generated.assert_not_called()

    def test_tool_result_continuations_cannot_hide_their_input_requirements(self):
        body={"stream":True,"messages":[{"role":"assistant","content":None,"tool_calls":[{}]},
                                          {"role":"tool","content":"synthetic"}]}
        with self.assertRaises(server.ServingAgreementError): server.serving_selection(body,"stream")
        with patch.object(server,"tools_enabled",return_value=True):
            self.assertEqual(server.serving_selection(body,"stream,tools"),"stream,tools")


    def test_the_model_listing_says_whether_json_output_is_enforced_and_a_bad_format_is_a_typed_refusal(self):
        """/v1/models carries the launch's structured-output fact for websites and connectors
        that read the catalog, and a malformed response_format answers 400 with its code before
        admission, never the generic sentence."""
        for fmt, enforced in (("gguf", True), ("safetensors", False)):
            with self.subTest(fmt=fmt), patch.object(server, "FORMAT", fmt), self.endpoint() as (port, enter, generated):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
                try:
                    connection.request("GET", "/v1/models", headers={"Authorization": "Bearer " + server.TOKEN})
                    reply = connection.getresponse()
                    listing = json.loads(reply.read())
                finally:
                    connection.close()
                self.assertEqual(reply.status, 200)
                self.assertEqual(listing["data"][0]["capabilities"], {"structuredOutput": enforced})
                status, _, raw = self.request(port, body={"messages": [{"role": "user", "content": "synthetic"}], "stream": False, "response_format": {"type": "xml"}})
                self.assertEqual(status, 400)
                self.assertEqual(json.loads(raw)["error"]["code"], "yougori_structured_output")
                self.assertEqual((enter.call_count, generated.call_count), (0, 0))

    def test_buffered_negotiation_and_mode_mismatch_before_admission(self):
        with self.endpoint(tools=True) as (port,enter,generated):
            for tools in (False,True):
                body=self.tool_body() if tools else {"messages":[{"role":"user","content":"synthetic"}]}
                body["stream"]=False
                feature="json,tools" if tools else "json"
                status,headers,_=self.request(port,self.offer(features=feature),body)
                self.assertEqual(status,200)
                self.assertEqual(headers["X-Yougori-Serving-Features"],feature)
                status,_,_=self.request(port,self.offer(features="stream,tools" if tools else "stream"),body)
                self.assertEqual(status,400)
            self.assertEqual(enter.call_count,2);self.assertEqual(generated.call_count,2)


class BufferedRelayTests(unittest.TestCase):
    def generate(self, value):
        response=Mock(status=200,read=Mock(return_value=json.dumps(value).encode()))
        connection=Mock()
        with patch.object(server,"FORMAT","gguf"), patch.object(server,"prepare_gguf",return_value=([],1,0)), \
                patch.object(server,"llama",return_value=(connection,response)):
            try:
                return server.generate_gguf({"messages":[{"role":"user","content":"fixture"}],"stream":False},Mock(),{})
            finally:
                connection.close.assert_called_once()
                self.assertTrue(server.GENERATION.acquire(blocking=False))
                server.GENERATION.release()

    def test_a_vllm_reply_names_the_adapter_that_served_it(self):
        reply = {"model": "ignored", "choices": [{"index": 0, "message": {"role": "assistant", "content": "fixture"}, "finish_reason": "stop"}]}
        sent = []

        def llama(path, request, timeout=30, caller=None, holder=None):
            sent.append(request["model"])
            return Mock(), Mock(status=200, read=Mock(return_value=json.dumps(reply).encode()))
        with patch.object(server, "FORMAT", "vllm"), patch.object(server, "prepare_gguf", return_value=([], 1, 0)), \
                patch.object(server, "llama", llama), patch.dict(server.ADAPTERS, {"fin": {"name": "fin"}}, clear=True):
            for asked, served in (("fin", "fin"), (None, server.MODEL), (server.MODEL, server.MODEL)):
                body = {"messages": [{"role": "user", "content": "fixture"}], "stream": False, **({"model": asked} if asked else {})}
                status, value = server.generate_gguf(body, Mock(), {})
                self.assertEqual((status, value["model"], sent[-1]), (200, served, served))
            # A name that is neither the model nor an attached adapter is refused before vLLM.
            with self.assertRaisesRegex(ValueError, "This endpoint serves"):
                server.generate_gguf({"messages": [{"role": "user", "content": "fixture"}], "stream": False, "model": "other"}, Mock(), {})
            self.assertEqual(len(sent), 3)

    def test_a_json_reply_format_is_forwarded_to_the_backend_and_refused_where_nothing_enforces_it(self):
        """response_format reaches llama.cpp and vLLM as given (they enforce it); a text format
        is not forwarded; a megakernel launch and the Transformers runner answer the typed 400
        before anything is generated."""
        reply = {"choices": [{"index": 0, "message": {"role": "assistant", "content": "{\"ok\": true}"}, "finish_reason": "stop"}]}
        sent = []

        def llama(path, request, timeout=30, caller=None, holder=None):
            sent.append(request)
            return Mock(), Mock(status=200, read=Mock(return_value=json.dumps(reply).encode()))
        schema = {"type": "json_schema", "json_schema": {"name": "reply", "schema": {"type": "object", "properties": {"ok": {"type": "boolean"}}}, "strict": True}}
        for fmt in ("gguf", "vllm"):
            with self.subTest(fmt=fmt), patch.object(server, "FORMAT", fmt), patch.object(server, "prepare_gguf", return_value=([], 1, 0)), patch.object(server, "llama", llama):
                for value in (schema, {"type": "json_object"}):
                    meter = {}
                    status, body = server.generate_gguf({"messages": [{"role": "user", "content": "fixture"}], "stream": False, "response_format": value}, Mock(), meter)
                    self.assertEqual((status, meter["outcome"], sent[-1]["response_format"]), (200, "ok", value))
                    self.assertEqual(body["choices"][0]["message"]["content"], "{\"ok\": true}")
                server.generate_gguf({"messages": [{"role": "user", "content": "fixture"}], "stream": False, "response_format": {"type": "text"}}, Mock(), {})
                self.assertNotIn("response_format", sent[-1])
        self.assertEqual(len(sent), 6)
        with patch.object(server, "FORMAT", "vllm"), patch.object(server, "MEGAKERNEL", {"serving": True}), patch.object(server, "llama", llama):
            meter = {}
            status, body = server.generate_gguf({"messages": [{"role": "user", "content": "fixture"}], "stream": False, "response_format": schema}, Mock(), meter)
            self.assertEqual((status, meter["outcome"], body["error"]["code"]), (400, "invalid", "yougori_structured_output"))
            self.assertIn("megakernel", body["error"]["message"])
        with patch.object(server, "FORMAT", "safetensors"), patch.object(server, "NETWORK", Mock()), patch.object(server, "prepare", side_effect=AssertionError("generated anyway")):
            meter = {}
            status, body = server.generate({"messages": [{"role": "user", "content": "fixture"}], "response_format": {"type": "json_object"}}, None, meter)
            self.assertEqual((status, meter["outcome"], body["error"]["code"]), (400, "invalid", "yougori_structured_output"))
            self.assertIn("--runner vllm", body["error"]["message"])
            self.assertTrue(server.GENERATION.acquire(blocking=False))
            server.GENERATION.release()
        self.assertEqual(len(sent), 6, "nothing reached a backend after a refusal")

    def test_preserves_refusal_tools_reasoning_and_actual_terminal(self):
        message={"role":"assistant","content":None,"refusal":"fixture refusal","reasoning_content":"fixture reasoning",
                 "tool_calls":[{"id":"a","type":"function","function":{"name":"lookup","arguments":"{}"}}]}
        status,value=self.generate({"choices":[{"index":0,"message":message,"finish_reason":"length"}]})
        self.assertEqual(status,200)
        self.assertEqual(value["choices"][0]["message"],message)
        self.assertEqual(value["choices"][0]["finish_reason"],"length")

    def test_never_invents_role_index_or_finish_from_a_broken_backend(self):
        good={"index":0,"message":{"role":"assistant","content":"fixture"},"finish_reason":"stop"}
        for changes in ({"index":True},{"index":1},{"message":{"content":"fixture"}},
                        {"message":{"role":"assistant","content":{}}},{"finish_reason":None},{"finish_reason":""}):
            with self.subTest(changes=changes),self.assertRaises(RuntimeError):
                self.generate({"choices":[{**good,**changes}]})
        for choices in ([],[good,good]):
            with self.assertRaises(RuntimeError): self.generate({"choices":choices})
        with self.assertRaises(RuntimeError): self.generate({"choices":[good],"error":{"message":"fixture"}})

class FakeImage:
    """What a Diffusers pipeline returns: something with a size that saves itself."""
    def __init__(self, width=512, height=512):
        self.width, self.height = width, height

    def save(self, path, format="PNG"):
        with open(path, "wb") as file:
            file.write(b"\x89PNG\r\n\x1a\n" + format.encode() + b"\x00" * 64)


class FakePipeline:
    """A Diffusers-like pipeline: three steps with the modern step callback, images or frames."""
    def __init__(self, delay=0.0, frames=False, fail=None):
        self.delay, self.frames, self.fail = delay, frames, fail
        self.scheduler = SimpleNamespace(timesteps=[3, 2, 1])
        self.calls = []

    def __call__(self, prompt, num_images_per_prompt=1, generator=None, callback_on_step_end=None, num_inference_steps=None,
                 guidance_scale=None, width=None, height=None, negative_prompt=None, num_frames=None, image=None):
        self.calls.append({"prompt": prompt, "count": num_images_per_prompt, "steps": num_inference_steps, "guidance": guidance_scale,
                           "width": width, "height": height, "negative": negative_prompt, "frames": num_frames, "generator": generator})
        if self.fail:
            raise self.fail
        for step in range(3):
            time.sleep(self.delay)
            if callback_on_step_end:
                callback_on_step_end(self, step, 0, {})
        if self.frames:
            return SimpleNamespace(frames=[[FakeImage(width or 256, height or 256) for _ in range(num_frames or 8)]])
        return SimpleNamespace(images=[FakeImage(width or 512, height or 512) for _ in range(num_images_per_prompt)])


class MediaRunnerTests(unittest.TestCase):
    """The media runner with a fake pipeline and no GPU: the files a pipeline needs, job
    validation, the job API with files and ranges, the OpenAI shapes, cancellation, the queue
    limit, retention, the restart rule and what health and /v1/models say."""

    @classmethod
    def setUpClass(cls):
        with patch.dict(os.environ, YOUGORI_MEDIA_TASK="text-to-image"):
            server.load_media_backends()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="yg-media-test-")
        self.stack = ExitStack()
        self.stack.enter_context(patch.object(server, "FORMAT", "media"))
        self.stack.enter_context(patch.object(server, "MEDIA_TASK", "text-to-image"))
        self.stack.enter_context(patch.dict(server.STATE, status="ready", task="text-to-image", error=None))
        self.stack.enter_context(patch.object(server, "TORCH", SimpleNamespace(cuda=SimpleNamespace(empty_cache=lambda: None))))
        self.stack.enter_context(patch.dict("sys.modules", torch=SimpleNamespace(Generator=lambda device: SimpleNamespace(manual_seed=lambda seed: ("generator", seed)))))
        self.usage = self.stack.enter_context(patch.object(server, "record_usage"))
        self.pipeline = FakePipeline()
        self.stack.enter_context(patch.dict(server.MEDIA, {"pipeline": self.pipeline, "task": "text-to-image", "class": "FakePipeline", "speed": {}, "sampleRate": 16000}))
        self.jobs = server.MediaJobs(os.path.join(self.temp.name, "media"))
        self.jobs.start()
        self.stack.enter_context(patch.object(server, "JOBS", self.jobs))
        self.web = server.Server(("127.0.0.1", 0), server.Handler)
        self.worker = threading.Thread(target=self.web.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        self.worker.start()

    def tearDown(self):
        self.web.shutdown()
        self.web.server_close()
        self.worker.join(2)
        self.jobs.stop()
        self.jobs.thread.join(5)
        self.stack.close()
        try:
            self.temp.cleanup()
        except OSError:
            pass

    def request(self, method, path, body=None, headers=None, raw=False):
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        connection = http.client.HTTPConnection("127.0.0.1", self.web.server_port, timeout=30)
        try:
            connection.putrequest(method, path, skip_host="Host" in (headers or {}))
            connection.putheader("Authorization", "Bearer " + server.TOKEN)
            for name, value in (headers or {}).items():
                connection.putheader(name, value)
            if data is not None:
                connection.putheader("Content-Length", str(len(data)))
                connection.putheader("Content-Type", "application/json")
            connection.endheaders(data)
            reply = connection.getresponse()
            payload = reply.read()
            return reply.status, dict(reply.getheaders()), payload if raw else json.loads(payload)
        finally:
            connection.close()

    def submit(self, inputs, status=202):
        code, _, body = self.request("POST", "/v1/jobs", {"input": inputs})
        self.assertEqual(code, status, body)
        return body

    def done(self, job_id):
        code, _, body = self.request("GET", "/v1/jobs/" + job_id + "?wait=30")
        self.assertEqual(code, 200, body)
        return body

    def test_adapter_and_pipeline_runner_are_repositories_at_a_commit(self):
        """`--adapter` and a media `--runner` name a repository at a commit. The adapter's
        safetensors load onto the pipeline with Diffusers' LoRA loading once peft is installed;
        a pipeline runner's pipeline.py becomes the custom pipeline and its requirements.txt may
        only pin packages; health names both."""
        commit = "a" * 40
        self.assertEqual(server.media_reference("hf:Pika-Labs/Pika-H3-Flex@" + commit, "adapter"), ("Pika-Labs/Pika-H3-Flex", commit))
        self.assertEqual(server.media_reference("Pika-Labs/Pika-H3-Flex@" + commit, "adapter")[0], "Pika-Labs/Pika-H3-Flex")
        for bad in ("Pika-Labs/Pika-H3-Flex", "hf:Pika-Labs/Pika-H3-Flex@main", "hf:Pika-Labs@" + commit, "hf:a/b@" + "A" * 40):
            with self.assertRaises(RuntimeError):
                server.media_reference(bad, "adapter")
        runner = Path(self.temp.name) / "runner"
        runner.mkdir()
        git = "diffusers @ git+https://github.com/huggingface/diffusers@" + "b" * 40
        (runner / "requirements.txt").write_text(git + "\nsentencepiece==0.2.3  # the tokenizer\n\n", encoding="utf-8")
        self.assertEqual(server.media_requirements(str(runner)), [git, "sentencepiece==0.2.3"])
        for line in ("diffusers>=0.30", "evil --index-url https://example.invalid", "name @ git+https://gitlab.com/a/b@" + "b" * 40, "diffusers @ git+https://github.com/huggingface/diffusers@main"):
            (runner / "requirements.txt").write_text(line + "\n", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                server.media_requirements(str(runner))
        self.assertEqual(server.media_requirements(str(Path(self.temp.name) / "none")), [])
        # The custom pipeline reaches Diffusers as the pipeline runner's folder.
        loaded = []

        class Pipeline:
            components = {}

            def set_progress_bar_config(self, **_):
                pass

            def to(self, device):
                loaded.append(("to", device))
                return self

            def enable_model_cpu_offload(self):
                loaded.append(("offload",))

            def load_lora_weights(self, folder):
                loaded.append(("lora", folder))
        diffusers = SimpleNamespace(DiffusionPipeline=SimpleNamespace(from_pretrained=lambda root, **kwargs: loaded.append(("from_pretrained", root, kwargs)) or Pipeline()))
        torch = SimpleNamespace(float16="fp16", bfloat16="bf16", float32="fp32", cuda=SimpleNamespace(mem_get_info=lambda index: (64 * 1024 ** 3, 64 * 1024 ** 3)))
        with patch.dict("sys.modules", diffusers=diffusers), patch.object(server, "MEDIA_RUNNER", "hf:acme/pipeline@" + commit), patch.dict(server.MEDIA, {}):
            pipeline = server.media_load_pipeline(torch, "/weights", {"variant": "fp16", "weights": ["unet/x.safetensors"]}, "fp16", custom=str(runner))
            self.assertEqual(loaded[0], ("from_pretrained", "/weights", {"torch_dtype": "fp16", "local_files_only": True, "variant": "fp16", "custom_pipeline": str(runner)}))
            self.assertEqual(server.MEDIA["pipelineSource"], "hf:acme/pipeline@" + commit)
            # The adapter: fetched at its commit (safetensors required), peft installed, LoRA loaded.
            adapter = Path(self.temp.name) / "adapter"
            adapter.mkdir()
            installed, fetched = [], []
            with patch.object(server, "install", lambda required: installed.append(dict(required))), \
                 patch.object(server, "media_fetch", lambda reference, what, patterns: fetched.append((what, reference, tuple(patterns))) or str(adapter)):
                with self.assertRaises(RuntimeError):
                    server.media_load_adapter(pipeline, "hf:Pika-Labs/Pika-H3-Flex@" + commit)  # no safetensors
                (adapter / "pytorch_lora_weights.safetensors").write_bytes(b"\0" * 8)
                server.media_load_adapter(pipeline, "hf:Pika-Labs/Pika-H3-Flex@" + commit)
                with self.assertRaises(RuntimeError):
                    server.media_load_adapter(SimpleNamespace(), "hf:Pika-Labs/Pika-H3-Flex@" + commit)  # no LoRA loading
            self.assertEqual(installed, [server.MEDIA_ADAPTER_DEPENDENCIES] * 2)
            self.assertEqual(fetched[0][:2], ("adapter", "hf:Pika-Labs/Pika-H3-Flex@" + commit))
            self.assertEqual(loaded[-1], ("lora", str(adapter)))
            self.assertEqual(server.MEDIA["adapter"], "hf:Pika-Labs/Pika-H3-Flex@" + commit)
            health = server.media_health()
            self.assertEqual((health["adapter"], health["pipelineSource"]), ("hf:Pika-Labs/Pika-H3-Flex@" + commit, "hf:acme/pipeline@" + commit))

    def test_a_pipeline_downloads_one_variant_of_its_components_and_leaves_single_file_checkpoints(self):
        index = {"_class_name": "StableDiffusionPipeline", "unet": ["diffusers", "UNet2DConditionModel"], "vae": ["diffusers", "AutoencoderKL"],
                 "text_encoder": ["transformers", "CLIPTextModel"], "tokenizer": ["transformers", "CLIPTokenizer"], "safety_checker": [None, None]}
        names = ["sd_turbo.safetensors", "unet/diffusion_pytorch_model.safetensors", "unet/diffusion_pytorch_model.fp16.safetensors",
                 "vae/diffusion_pytorch_model.safetensors", "vae/diffusion_pytorch_model.fp16.safetensors",
                 "text_encoder/model.safetensors", "text_encoder/model.fp16.safetensors", "comfy/loras/x.safetensors"]
        plan = server.media_plan(names, index)
        self.assertEqual(plan["variant"], "fp16")
        self.assertEqual(plan["weights"], ["text_encoder/model.fp16.safetensors", "unet/diffusion_pytorch_model.fp16.safetensors", "vae/diffusion_pytorch_model.fp16.safetensors"])
        # One component without the variant: the plain files for all, shards included.
        mixed = server.media_plan([n for n in names if "text_encoder/model.fp16" not in n] + ["transformer/diffusion_pytorch_model-00001-of-00002.safetensors"],
                                  {**index, "transformer": ["diffusers", "X"]})
        self.assertIsNone(mixed["variant"])
        self.assertNotIn("unet/diffusion_pytorch_model.fp16.safetensors", mixed["weights"])
        self.assertIn("transformer/diffusion_pytorch_model-00001-of-00002.safetensors", mixed["weights"])
        self.assertNotIn("sd_turbo.safetensors", mixed["weights"])
        self.assertEqual(server.media_plan(["sd_turbo.safetensors"], index)["weights"], [])
        self.assertEqual(server.media_frames(2, 24, 8), 49)
        self.assertEqual(server.media_frames(0.5, 16, 4), 9)
        self.assertEqual(server.media_frames(2, 8, 1), 16)

    def test_job_inputs_are_checked_per_task(self):
        with self.assertRaisesRegex(server.MediaInput, "prompt is required"):
            server.validate_job({"input": {}})
        with self.assertRaisesRegex(server.MediaInput, "Unknown input field"):
            server.validate_job({"input": {"prompt": "x", "cfg": 1}})
        with self.assertRaisesRegex(server.MediaInput, "multiple of 8"):
            server.validate_job({"input": {"prompt": "x", "width": 500}})
        with self.assertRaisesRegex(server.MediaInput, "seconds applies"):
            server.validate_job({"input": {"prompt": "x", "seconds": 2}})
        with self.assertRaisesRegex(server.MediaInput, "format must be"):
            server.validate_job({"input": {"prompt": "x", "format": "gif"}})
        with self.assertRaisesRegex(server.MediaInput, "serves"):
            server.validate_job({"model": "other/model", "input": {"prompt": "x"}})
        job = server.validate_job({"input": {"prompt": "a cat", "count": 2, "steps": 4, "guidance": 0, "seed": 7, "format": "jpeg"}})
        self.assertEqual((job["count"], job["steps"], job["guidance"], job["seed"], job["format"]), (2, 4, 0, 7, "jpeg"))
        self.assertIn("seed", server.validate_job({"input": {"prompt": "x"}}))
        with patch.object(server, "MEDIA_TASK", "image-to-video"):
            with self.assertRaisesRegex(server.MediaInput, "image is required"):
                server.validate_job({"input": {"prompt": "x"}})
            with self.assertRaisesRegex(server.MediaInput, "count applies"):
                server.validate_job({"input": {"prompt": "x", "count": 2, "image": "data:image/png;base64,AAAA"}})
            job = server.validate_job({"input": {"image": "data:image/png;base64,AAAA", "seconds": 3, "fps": 8}})
            self.assertEqual((job["image"], job["seconds"], job["fps"], job["format"], job["_image"]), ({"bytes": 3}, 3, 8, "mp4", b"\x00\x00\x00"))
        with patch.object(server, "MEDIA_TASK", "text-to-speech"):
            self.assertEqual(server.validate_job({"input": {"text": "hello", "voice": "v2/en_speaker_6"}})["prompt"], "hello")

    def test_jobs_run_one_at_a_time_with_progress_results_files_and_usage(self):
        self.pipeline.delay = 0.2
        first = self.submit({"prompt": "a red bicycle", "count": 2, "steps": 3, "guidance": 1.5, "seed": 11})
        second = self.submit({"prompt": "a blue bicycle", "width": 256, "height": 192})
        self.assertIn(first["status"], ("queued", "running"))
        self.assertEqual((first["task"], first["model"], first["object"]), ("text-to-image", server.MODEL, "job"))
        time.sleep(0.3)
        code, _, running = self.request("GET", "/v1/jobs/" + first["id"])
        self.assertEqual(code, 200)
        self.assertEqual(running["status"], "running")
        code, _, waiting = self.request("GET", "/v1/jobs/" + second["id"])
        self.assertEqual((waiting["status"], waiting["position"]), ("queued", 1))
        done = self.done(first["id"])
        self.assertEqual((done["status"], done["progress"]), ("succeeded", 1.0), done)
        self.assertEqual(len(done["output"]["images"]), 2)
        self.assertEqual(done["output"]["seed"], 11)
        self.assertEqual(done["usage"]["images"], 2)
        self.assertEqual(done["output"]["files"][0]["url"], "/v1/files/" + first["id"] + ".1")
        self.assertEqual(done["output"]["images"][1]["file"], first["id"] + ".2")
        self.assertEqual(self.pipeline.calls[0]["steps"], 3)
        self.assertEqual(self.pipeline.calls[0]["guidance"], 1.5)
        self.assertEqual(self.pipeline.calls[0]["generator"], ("generator", 11))
        self.done(second["id"])
        self.assertEqual((self.pipeline.calls[1]["width"], self.pipeline.calls[1]["height"]), (256, 192))
        code, _, result = self.request("GET", "/v1/jobs/" + first["id"] + "/result")
        self.assertEqual(code, 200)
        self.assertEqual(result["images"][0]["width"], 512)
        code, headers, data = self.request("GET", "/v1/files/" + first["id"] + ".1", raw=True)
        self.assertEqual((code, headers["Content-Type"], headers["Accept-Ranges"]), (200, "image/png", "bytes"))
        self.assertTrue(data.startswith(b"\x89PNG"))
        code, headers, part = self.request("GET", "/v1/files/" + first["id"] + ".1", headers={"Range": "bytes=2-5"}, raw=True)
        self.assertEqual((code, headers["Content-Range"], part), (206, "bytes 2-5/" + str(len(data)), data[2:6]))
        self.assertEqual(self.request("GET", "/v1/files/" + first["id"] + ".3")[0], 404)
        code, _, listing = self.request("GET", "/v1/jobs?limit=5")
        self.assertEqual([item["id"] for item in listing["data"]], [second["id"], first["id"]])
        self.usage.assert_called()
        source, outcome = self.usage.call_args_list[0].args[:2]
        self.assertEqual((source, outcome, self.usage.call_args_list[0].kwargs["media"]["images"]), ("api", "ok", 2))
        health = server.media_health()
        self.assertEqual((health["queue"]["waiting"], health["queue"]["running"], health["outputs"]["jobs"], health["outputs"]["keptHours"]), (0, 0, 2, 24))
        self.assertGreater(health["outputs"]["bytes"], 0)
        self.assertIn("secondsPerImage", health["speed"])
        self.assertEqual(server.runner_capabilities()["media"]["task"], "text-to-image")
        # The unknown parameter of a pipeline is left out and noted, never passed.
        self.pipeline.delay = 0
        with patch.object(server, "MEDIA_TASK", "image-to-image"), patch.dict(server.MEDIA, task="image-to-image"), patch.object(server, "media_pil", lambda data: "pil:" + str(len(data))):
            job = self.submit({"prompt": "again", "image": "data:image/png;base64,AAAA", "strength": 0.5})
            done = self.done(job["id"])
            self.assertEqual(done["status"], "succeeded", done)
            self.assertEqual(done["notes"], ["strength"])
            self.assertEqual(done["input"]["image"], {"bytes": 3})

    def test_cancellation_the_queue_limit_and_failures(self):
        self.pipeline.delay = 0.3
        running = self.submit({"prompt": "slow"})
        queued = [self.submit({"prompt": "waiting " + str(i)}) for i in range(server.MEDIA_QUEUE_LIMIT)]
        code, _, body = self.request("POST", "/v1/jobs", {"input": {"prompt": "one too many"}})
        self.assertEqual((code, body["error"]["code"]), (429, "media_queue_full"))
        code, _, cancelled = self.request("POST", "/v1/jobs/" + queued[-1]["id"] + "/cancel")
        self.assertEqual((code, cancelled["status"]), (200, "cancelled"))
        time.sleep(0.2)
        code, _, stopped = self.request("POST", "/v1/jobs/" + running["id"] + "/cancel")
        self.assertEqual(code, 200)
        self.assertEqual(self.done(running["id"])["status"], "cancelled")
        self.assertFalse(os.path.isdir(os.path.join(self.jobs.outputs, running["id"])))
        for job in queued[:-1]:
            self.request("POST", "/v1/jobs/" + job["id"] + "/cancel")
        self.assertEqual(self.request("GET", "/v1/jobs/job_" + "0" * 24)[0], 404)
        self.assertEqual(self.request("POST", "/v1/jobs/job_" + "0" * 24 + "/cancel")[0], 404)
        self.pipeline.delay = 0
        self.pipeline.fail = RuntimeError("CUDA out of memory " + server.TOKEN)
        failed = self.done(self.submit({"prompt": "too big"})["id"])
        self.assertEqual(failed["status"], "failed")
        self.assertIn("Not enough GPU memory", failed["error"])
        self.assertNotIn(server.TOKEN, failed["error"])
        self.pipeline.fail = ValueError("shape mismatch at " + server.TOKEN)
        failed = self.done(self.submit({"prompt": "wrong"})["id"])
        self.assertEqual(failed["error"], "ValueError: shape mismatch at [redacted]")
        code, _, body = self.request("GET", "/v1/jobs/" + failed["id"] + "/result")
        self.assertEqual((code, body["error"]["code"]), (410, "job_failed"))
        code, _, body = self.request("POST", "/v1/jobs", {"input": {"prompt": "x", "count": 99}})
        self.assertEqual((code, body["error"]["code"]), (400, "media_input"))
        code, _, body = self.request("POST", "/v1/chat/completions", {"messages": [{"role": "user", "content": "hi"}]})
        self.assertEqual((code, body["error"]["code"]), (404, "task_mismatch"))
        self.assertEqual(self.usage.call_args_list[-1].args[1], "error")

    def test_a_deleted_running_job_leaves_when_it_ends_and_a_job_cancelled_once_picked_never_runs(self):
        self.pipeline.delay = 0.2
        running = self.submit({"prompt": "slow"})
        for _ in range(100):
            if self.jobs.row(running["id"])["status"] == "running":
                break
            time.sleep(0.01)
        code, _, body = self.request("DELETE", "/v1/jobs/" + running["id"])
        self.assertEqual(code, 200, body)
        # The worker ends it at its next step, counts its usage, and removes the record and files.
        for _ in range(200):
            if self.jobs.row(running["id"]) is None:
                break
            time.sleep(0.02)
        self.assertIsNone(self.jobs.row(running["id"]))
        self.assertFalse(os.path.isdir(os.path.join(self.jobs.outputs, running["id"])))
        self.assertEqual(self.usage.call_args_list[-1].args[1], "cancelled")
        # A job cancelled after the worker picked it, before it started, does not run.
        self.jobs.stop()
        self.jobs.thread.join(5)
        queued = self.submit({"prompt": "picked then cancelled"})
        picked = self.jobs.row(queued["id"])
        self.jobs.cancel(queued["id"])
        self.jobs.run(picked)
        self.assertNotIn("picked then cancelled", [call["prompt"] for call in self.pipeline.calls])
        self.assertEqual(self.jobs.row(queued["id"])["status"], "cancelled")

    def test_openai_images_speech_and_videos_shapes(self):
        code, _, body = self.request("POST", "/v1/images/generations", {"prompt": "a cat", "n": 2, "size": "256x256", "seed": 3})
        self.assertEqual(code, 200, body)
        self.assertEqual(len(body["data"]), 2)
        self.assertTrue(base64.b64decode(body["data"][0]["b64_json"]).startswith(b"\x89PNG"))
        self.assertEqual(body["usage"]["images"], 2)
        code, _, body = self.request("POST", "/v1/images/generations", {"prompt": "a cat", "response_format": "url"}, headers={"Host": "models.example.test"})
        self.assertEqual(code, 200, body)
        self.assertTrue(body["data"][0]["url"].startswith("http://models.example.test/v1/files/job_"), body)
        self.assertEqual(self.request("POST", "/v1/images/generations", {"prompt": "x", "size": "big"})[0], 400)
        self.assertEqual(self.request("POST", "/v1/audio/speech", {"input": "hi"})[0], 404)
        self.assertEqual(self.request("POST", "/v1/videos", {"prompt": "hi"})[0], 404)
        # Speech: the WAV bytes of one job.
        speech = SimpleNamespace(calls=[])
        speech.__call__ = None
        def speak(text, **kwargs):
            speech.calls.append((text, kwargs))
            return {"audio": [0.0] * 8, "sampling_rate": 16000}
        written = []
        def write_audio(folder, name, audio, rate):
            path = os.path.join(folder, name)
            with open(path, "wb") as file:
                file.write(b"RIFF" + b"\x00" * 40)
            written.append((name, len(audio), rate))
            return path
        with patch.object(server, "MEDIA_TASK", "text-to-speech"), patch.dict(server.MEDIA, task="text-to-speech", pipeline=speak), \
                patch.object(server, "media_write_audio", write_audio), patch.object(server, "media_audio_seconds", lambda path: 0.5):
            code, headers, data = self.request("POST", "/v1/audio/speech", {"input": "Hello there", "voice": "alloy"}, raw=True)
            self.assertEqual((code, headers["Content-Type"]), (200, "audio/wav"))
            self.assertTrue(data.startswith(b"RIFF"))
            self.assertEqual(written, [("speech.wav", 8, 16000)])
            self.assertEqual(speech.calls[0][0], "Hello there")
            self.assertEqual(self.request("POST", "/v1/audio/speech", {"input": "x", "response_format": "mp3"})[0], 400)
            done = self.done(self.submit({"text": "again"})["id"])
            self.assertEqual((done["output"]["audio"]["seconds"], done["usage"]["output_seconds"]), (0.5, 0.5))
        # Video: OpenAI's video object, polled, then its content.
        exported = []
        def export_to_video(frames, path, fps):
            exported.append((len(frames), fps))
            with open(path, "wb") as file:
                file.write(b"\x00\x00\x00\x18ftypmp42" + b"\x00" * 32)
        video_pipeline = FakePipeline(frames=True)
        with patch.object(server, "MEDIA_TASK", "text-to-video"), patch.dict(server.MEDIA, task="text-to-video", pipeline=video_pipeline, **{"class": "TextToVideoSDPipeline"}), \
                patch.dict("sys.modules", {"diffusers": SimpleNamespace(utils=SimpleNamespace(export_to_video=export_to_video)), "diffusers.utils": SimpleNamespace(export_to_video=export_to_video)}):
            code, _, video = self.request("POST", "/v1/videos", {"prompt": "waves", "seconds": "2", "size": "256x256"})
            # The worker may have taken the job between its submission and this read.
            self.assertEqual((code, video["object"]), (200, "video"), video)
            self.assertIn(video["status"], ("queued", "in_progress"), video)
            self.request("GET", "/v1/jobs/" + video["id"] + "?wait=30")
            code, _, finished = self.request("GET", "/v1/videos/" + video["id"])
            self.assertEqual((finished["status"], finished["progress"], finished["seconds"], finished["size"]), ("completed", 100, 2.0, "256x256"), finished)
            self.assertEqual(exported, [(16, 8)])
            code, headers, data = self.request("GET", "/v1/videos/" + video["id"] + "/content", raw=True)
            self.assertEqual((code, headers["Content-Type"]), (200, "video/mp4"))
            self.assertIn(b"ftyp", data)
            code, _, deleted = self.request("DELETE", "/v1/videos/" + video["id"])
            self.assertEqual((code, deleted["deleted"]), (200, True))
            self.assertEqual(self.request("GET", "/v1/videos/" + video["id"])[0], 404)

    def test_outputs_expire_fit_the_cap_and_a_restart_fails_what_was_running(self):
        first = self.done(self.submit({"prompt": "one"})["id"])
        second = self.done(self.submit({"prompt": "two"})["id"])
        code, _, body = self.request("POST", "/v1/yougori/media", {"action": "configure", "keepHours": 1})
        self.assertEqual(code, 403)
        code, _, body = self.request("POST", "/v1/yougori/media", {"action": "configure", "keepHours": 1}, headers={"X-Yougori-Admin": server.ADMIN_TOKEN})
        self.assertEqual((code, body["outputs"]["keptHours"]), (200, 1), body)
        self.assertEqual(self.request("POST", "/v1/yougori/media", {"action": "configure", "keepHours": 0}, headers={"X-Yougori-Admin": server.ADMIN_TOKEN})[0], 400)
        with self.jobs.db() as db:
            db.execute("UPDATE jobs SET expires=? WHERE id=?", (time.time() - 1, first["id"]))
        self.jobs.sweep()
        self.assertEqual(self.request("GET", "/v1/jobs/" + first["id"])[0], 404)
        self.assertFalse(os.path.isdir(os.path.join(self.jobs.outputs, first["id"])))
        self.assertEqual(self.request("GET", "/v1/jobs/" + second["id"])[0], 200)
        with patch.object(server, "MEDIA_CAP_BYTES", 1):
            self.jobs.sweep()
        self.assertEqual(self.request("GET", "/v1/jobs/" + second["id"])[0], 404)
        # A job left running by a stopped server is failed by the next start, not resumed.
        with self.jobs.db() as db:
            db.execute("INSERT INTO jobs (id,created,started,status,task,source,input) VALUES (?,?,?,?,?,?,?)",
                       ("job_" + "a" * 24, time.time(), time.time(), "running", "text-to-image", "api", "{}"))
        restarted = server.MediaJobs(self.jobs.root)
        row = restarted.row("job_" + "a" * 24)
        self.assertEqual(row["status"], "failed")
        self.assertIn("restarted", row["error"])

    def test_before_the_load_a_job_is_told_to_wait_and_the_listing_names_the_task(self):
        with patch.object(server, "JOBS", None), patch.dict(server.STATE, status="downloading"):
            code, _, body = self.request("POST", "/v1/jobs", {"input": {"prompt": "x"}})
            self.assertEqual((code, body["error"]["code"]), (503, "model_loading"))
            self.assertEqual(self.request("GET", "/v1/jobs")[0], 503)
            self.assertEqual(self.request("GET", "/v1/usage")[0], 200)
        code, _, listing = self.request("GET", "/v1/models")
        self.assertEqual((listing["data"][0]["task"], listing["data"][0]["capabilities"]), ("text-to-image", {"structuredOutput": False, "media": os.environ.get("YOUGORI_MEDIA_TASK", "")}))


class CatalogViewVerifierTests(unittest.TestCase):
    """What the engine's catalog path (model_runner/catalog_binding.rs) hands the runner, run
    through the real bundled verifier (model_runner/registry_snapshot.py) as model_runner.rs
    ships it: YOUGORI_LOCAL_MANIFEST of exactly {"revision","files"} with files of exactly
    {"name","size","sha256"} (lines 35 and 45), a view whose duplicate bytes are separate
    files, and a registry view verified against its own record (no YOUGORI_LOCAL_MANIFEST)."""

    def verify(self, root, revision, manifest=None):
        import ast, base64, zlib
        source = (Path(__file__).parents[1] / "src-tauri/src/model_runner/registry_snapshot.py").read_bytes().replace(b"\r\n", b"\n")
        defined = [node.name for node in ast.parse(source).body if isinstance(node, ast.FunctionDef)]
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, YOUGORI_REGISTRY_SOURCE=base64.b64encode(zlib.compress(source)).decode("ascii")))
            if manifest is None:
                os.environ.pop("YOUGORI_LOCAL_MANIFEST", None)
            else:
                os.environ["YOUGORI_LOCAL_MANIFEST"] = json.dumps(manifest)
            # The loader replaces itself and defines the verifier's functions in the server's
            # globals; every one is put back afterwards.
            for name in defined:
                stack.enter_context(patch.object(server, name, server.__dict__[name]) if name in server.__dict__ else patch.object(server, name, None, create=True))
            for name, value in (("MODEL_PATH", str(root)), ("MODEL_REVISION", revision), ("REGISTRY_VERIFIED", None)):
                stack.enter_context(patch.object(server, name, value))
            stack.enter_context(patch.dict(server.STATE))
            stack.callback(lambda: [server.__dict__.pop(key, None) for key in ("MODEL_SNAPSHOT_ROOT", "MODEL_SNAPSHOT_FILES")])
            return server.registry_snapshot()

    def folder(self, root, contents):
        for name, data in contents.items():
            (root / name).write_bytes(data)
        files = [{"name": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in contents.items()]
        return files, hashlib.sha256(json.dumps(files).encode()).hexdigest()

    def test_the_local_folder_manifest_shape_verifies_and_an_added_content_key_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files, revision = self.folder(root, {"config.json": b'{"model_type":"llama"}', "model.safetensors": b"fixture weights"})
            self.assertEqual(self.verify(root, revision, {"revision": revision, "files": files}), os.path.realpath(root))
            # A catalog content key inside the runner's manifest is refused (line 45).
            extended = [dict(files[0], content="a" * 64)] + files[1:]
            with self.assertRaisesRegex(RuntimeError, "Invalid uploaded artifact identity"):
                self.verify(root, revision, {"revision": revision, "files": extended})
            with self.assertRaisesRegex(RuntimeError, "Invalid uploaded checkpoint manifest"):
                self.verify(root, revision, {"revision": revision, "files": files, "content": {}})

    def test_a_view_needs_separate_files_for_equal_bytes_and_a_registry_view_its_record(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = b'{"model":{"type":"BPE","vocab":{}}}'
            files, revision = self.folder(root, {"added_tokens.json": data, "config.json": b"{}", "model.safetensors": b"weights"})
            entry = {"name": "tokenizer.json", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            files.append(entry)
            manifest = {"revision": revision, "files": files}
            # Two entries that are one file (a second hard link) are refused...
            os.link(root / "added_tokens.json", root / "tokenizer.json")
            with self.assertRaisesRegex(RuntimeError, "Invalid uploaded artifact identity"):
                self.verify(root, revision, manifest)
            # ...a separate copy of the same bytes, as the view makes, verifies.
            (root / "tokenizer.json").unlink()
            (root / "tokenizer.json").write_bytes(data)
            self.assertEqual(self.verify(root, revision, manifest), os.path.realpath(root))
            # The registry path sets no YOUGORI_LOCAL_MANIFEST: the record in the mount is used.
            (root / ".yougori-verified-files.json").write_text(json.dumps(manifest))
            self.assertEqual(self.verify(root, revision), os.path.realpath(root))
            (root / ".yougori-verified-files.json").unlink()
            with self.assertRaisesRegex(RuntimeError, "Invalid uploaded checkpoint manifest"):
                self.verify(root, revision)

class ConcurrentServingTests(unittest.TestCase):
    """Real HTTP and real generation/stream relay, with a deterministic CPU backend."""
    @contextmanager
    def endpoint(self, limit=128, timeout=5, slots=1, pool=0, tokens=2):
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        gate = threading.Event()
        seen, holds, closed, lingers, trickle = [], {}, [], {}, set()
        inflight, counting = {"now": 0, "most": 0}, threading.Lock()
        class Backend(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                text = body["messages"][-1]["content"]
                seen.append(text)
                with counting:
                    inflight["now"] += 1; inflight["most"] = max(inflight["most"], inflight["now"])
                try:
                    self.answer(body, text)
                finally:
                    with counting: inflight["now"] -= 1
            def trickle(self, text):
                # A stream that keeps producing until the relay ends it, as llama.cpp's does.
                self.send_response(200); self.send_header("Content-Type", "text/event-stream"); self.end_headers()
                chunk = ('data: ' + json.dumps({"choices":[{"index":0,"delta":{"content":"x"},"finish_reason":None}]}) + '\n\n').encode()
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if select.select([self.connection], [], [], 0)[0] and self.connection.recv(1, socket.MSG_PEEK) == b"":
                        break
                    try:
                        self.wfile.write(chunk); self.wfile.flush()
                    except OSError:
                        break
                    time.sleep(0.05)
                else:
                    raise AssertionError("The relay never ended the stream")
                closed.append(text)
                if text in lingers: lingers[text].wait(10)
            def answer(self, body, text):
                if body.get("stream") and text in trickle:
                    return self.trickle(text)
                hold, deadline = holds.get(text, gate), time.monotonic() + 10
                while not hold.wait(0.01):
                    # Like llama.cpp between tokens, notice a relay that closed its connection.
                    if select.select([self.connection], [], [], 0)[0] and self.connection.recv(1, socket.MSG_PEEK) == b"":
                        closed.append(text)
                        # A backend that takes its time to end the request keeps its connection.
                        if text in lingers: lingers[text].wait(10)
                        return
                    if time.monotonic() > deadline: raise AssertionError("Test did not release the backend")
                time.sleep(0.005)
                if text == "fail":
                    data = b'{"error":{"message":"synthetic backend failure"}}'
                    self.send_response(500)
                elif body.get("stream"):
                    data = ('data: ' + json.dumps({"choices":[{"index":0,"delta":{"content":text},"finish_reason":None}]}) +
                            '\n\ndata: ' + json.dumps({"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],
                                                       "usage":{"prompt_tokens":2,"completion_tokens":1}}) + '\n\ndata: [DONE]\n\n').encode()
                    self.send_response(200)
                else:
                    data = json.dumps({"choices":[{"index":0,"message":{"role":"assistant","content":text},"finish_reason":"stop"}],
                                       "usage":{"prompt_tokens":2,"completion_tokens":1}}).encode()
                    self.send_response(200)
                self.send_header("Content-Length",str(len(data)))
                self.end_headers();self.wfile.write(data)
        with ExitStack() as stack:
            backend = ThreadingHTTPServer(("127.0.0.1",0),Backend)
            stack.enter_context(patch.dict(server.STATE,status="ready",error=None))
            stack.enter_context(patch.dict(server.LLAMA,port=backend.server_port,context=4096))
            stack.enter_context(patch.object(server,"FORMAT","gguf"))
            stack.enter_context(patch.object(server,"GPU_ENABLED",False))
            stack.enter_context(patch.object(server,"GPU_ACTIVE",0))
            queue = server.InferenceQueue(limit,timeout,slots)
            queue.pool = pool
            stack.enter_context(patch.object(server,"INFERENCE_QUEUE",queue))
            stack.enter_context(patch.object(server,"GENERATION",threading.Lock()))
            stack.enter_context(patch.object(server,"prepare_gguf",side_effect=lambda messages,*args:(messages,tokens,0)))
            stack.enter_context(patch.object(server,"record_usage"))
            frontend = server.Server(("127.0.0.1",0),server.Handler)
            workers = [threading.Thread(target=http.serve_forever,kwargs={"poll_interval":0.01},daemon=True) for http in (backend,frontend)]
            for worker in workers: worker.start()
            try: yield SimpleNamespace(port=frontend.server_port,gate=gate,seen=seen,queue=server.INFERENCE_QUEUE,inflight=inflight,holds=holds,closed=closed,lingers=lingers,trickle=trickle)
            finally:
                gate.set()
                for hold in holds.values(): hold.set()
                for http in (frontend,backend): http.shutdown();http.server_close()
                for worker in workers: worker.join(2)

    @staticmethod
    def connection(port,text,stream=False,token=None):
        client = http.client.HTTPConnection("127.0.0.1",port,timeout=10)
        client.request("POST","/v1/chat/completions",json.dumps({"messages":[{"role":"user","content":text}],"stream":stream,"max_tokens":4}),
                       {"Authorization":"Bearer "+(token or server.TOKEN),"Content-Type":"application/json"})
        return client

    def request(self,port,text,stream=False,token=None):
        client = self.connection(port,text,stream,token)
        try:
            response = client.getresponse()
            return response.status,dict(response.getheaders()),response.read()
        finally: client.close()

    def until(self,predicate):
        deadline = time.monotonic()+5
        while not predicate():
            if time.monotonic()>deadline: self.fail("Concurrent serving condition was not reached")
            time.sleep(0.01)

    def test_sixty_four_simultaneous_callers_all_finish_with_health_still_responsive(self):
        from concurrent.futures import ThreadPoolExecutor
        with self.endpoint() as runtime, ThreadPoolExecutor(max_workers=64) as pool:
            barrier=threading.Barrier(65)
            def call(index):
                barrier.wait(5)
                return self.request(runtime.port,str(index),stream=index%2==0)
            futures=[pool.submit(call,index) for index in range(64)]
            barrier.wait(5)
            try:
                self.until(lambda:runtime.queue.snapshot()["waiting"]==63)
                health=http.client.HTTPConnection("127.0.0.1",runtime.port,timeout=2)
                try:
                    health.request("GET","/health",headers={"Authorization":"Bearer "+server.TOKEN})
                    response=health.getresponse();self.assertEqual(response.status,200)
                    self.assertEqual(json.loads(response.read())["requestQueue"]["waiting"],63)
                finally: health.close()
                self.assertEqual(server.GPU_ACTIVE,1)
                # Queued callers are demand: the scheduler must not evict the model between them.
                self.assertEqual(server.gpu_snapshot(refresh=False)["pending"],63)
            finally: runtime.gate.set()
            replies=[future.result(10) for future in futures]
            self.assertEqual([reply[0] for reply in replies],[200]*64)
            for index,(_,_,data) in enumerate(replies):
                if index%2==0:
                    events=[json.loads(line[6:]) for line in data.decode().split("\n\n") if line.startswith("data: {")]
                    self.assertEqual("".join(e["choices"][0]["delta"].get("content","") for e in events if e.get("choices")),str(index))
                    self.assertTrue(data.rstrip().endswith(b"data: [DONE]"))
                else: self.assertEqual(json.loads(data)["choices"][0]["message"]["content"],str(index))
            self.until(lambda:runtime.queue.snapshot()["active"]==0)
            self.assertEqual(runtime.queue.snapshot()["waiting"],0)
            self.assertEqual(server.GPU_ACTIVE,0)
            self.assertFalse(server.GENERATION.locked())

    def test_fifo_queue_overflow_and_authentication_are_separate(self):
        from concurrent.futures import ThreadPoolExecutor
        with self.endpoint(limit=2) as runtime, ThreadPoolExecutor(max_workers=3) as pool:
            first=pool.submit(self.request,runtime.port,"first")
            self.until(lambda:runtime.seen==["first"])
            second=pool.submit(self.request,runtime.port,"second")
            self.until(lambda:runtime.queue.snapshot()["waiting"]==1)
            third=pool.submit(self.request,runtime.port,"third")
            self.until(lambda:runtime.queue.snapshot()["waiting"]==2)
            try:
                status,headers,data=self.request(runtime.port,"overflow")
                self.assertEqual(status,429);self.assertEqual(headers["Retry-After"],"1")
                self.assertEqual(json.loads(data)["error"]["code"],"model_queue_full")
                self.assertEqual(self.request(runtime.port,"unauthorized",token="wrong")[0],401)
            finally: runtime.gate.set()
            self.assertEqual([future.result(10)[0] for future in (first,second,third)],[200]*3)
            self.assertEqual(runtime.seen,["first","second","third"])

    def test_queue_timeout_and_disconnection_never_generate_and_capacity_recovers(self):
        from concurrent.futures import ThreadPoolExecutor
        with self.endpoint(timeout=0.25) as runtime, ThreadPoolExecutor(max_workers=1) as pool:
            first=pool.submit(self.request,runtime.port,"first")
            self.until(lambda:runtime.seen==["first"])
            try:
                cancelled=self.connection(runtime.port,"cancelled")
                self.until(lambda:runtime.queue.snapshot()["waiting"]==1)
                cancelled.close()
                self.until(lambda:runtime.queue.snapshot()["waiting"]==0)
                status,_,data=self.request(runtime.port,"expired")
                self.assertEqual(status,504)
                self.assertEqual(json.loads(data)["error"]["code"],"model_queue_timeout")
                self.assertEqual(runtime.queue.snapshot()["waiting"],0)
            finally: runtime.gate.set()
            self.assertEqual(first.result(10)[0],200)
            self.assertEqual(self.request(runtime.port,"after")[0],200)
            self.assertEqual(runtime.seen,["first","after"])

    def test_backend_error_does_not_strand_the_next_caller(self):
        from concurrent.futures import ThreadPoolExecutor
        with self.endpoint() as runtime, ThreadPoolExecutor(max_workers=2) as pool:
            failed=pool.submit(self.request,runtime.port,"fail")
            self.until(lambda:runtime.seen==["fail"])
            next_call=pool.submit(self.request,runtime.port,"after")
            self.until(lambda:runtime.queue.snapshot()["waiting"]==1)
            runtime.gate.set()
            self.assertEqual(failed.result(10)[0],500)
            self.assertEqual(next_call.result(10)[0],200)
            self.until(lambda:runtime.queue.snapshot()["active"]==0)
            self.assertFalse(server.GENERATION.locked())
            self.assertEqual(server.GPU_ACTIVE,0)

    def submit_in_order(self,pool,runtime,texts):
        """Starts each request only after the previous one reached the backend or a queue."""
        futures=[]
        for index,text in enumerate(texts):
            futures.append(pool.submit(self.request,runtime.port,text))
            self.until(lambda:len(runtime.seen)+runtime.queue.snapshot()["waiting"]+len(runtime.queue.reserving)==index+1)
        return futures

    def test_parallel_slots_generate_together_and_later_callers_wait_in_order(self):
        from concurrent.futures import ThreadPoolExecutor
        with self.endpoint(slots=4) as runtime, ThreadPoolExecutor(max_workers=6) as pool:
            runtime.holds["0"]=threading.Event()
            try:
                futures=self.submit_in_order(pool,runtime,[str(i) for i in range(6)])
                self.until(lambda:len(runtime.seen)==4 and runtime.queue.snapshot()["waiting"]==2)
                self.assertEqual((runtime.inflight["now"],server.GPU_ACTIVE,runtime.queue.snapshot()["active"]),(4,4,4))
                self.assertEqual(runtime.queue.snapshot()["slots"],4)
                # One slot frees: the earliest waiter takes it, the later one keeps waiting.
                runtime.holds["0"].set()
                self.until(lambda:len(runtime.seen)==5)
                self.assertEqual((runtime.seen[4],runtime.queue.snapshot()["waiting"]),("4",1))
            finally: runtime.gate.set()
            self.assertEqual([future.result(10)[0] for future in futures],[200]*6)
            self.assertEqual(runtime.seen,[str(i) for i in range(6)])
            self.assertEqual(runtime.inflight["most"],4)
            self.until(lambda:runtime.queue.snapshot()["active"]==0)
            self.assertEqual(server.GPU_ACTIVE,0)

    def test_a_shared_kv_pool_admits_requests_only_while_they_fit_first_come_first_served(self):
        from concurrent.futures import ThreadPoolExecutor
        # Each request reserves its 2 prompt tokens, its 4 max_tokens and the margin.
        per=2+4+server.RESERVE_MARGIN_TOKENS
        for pool_tokens,together in ((2*per-1,1),(2*per,2)):
            with self.subTest(pool=pool_tokens),self.endpoint(slots=4,pool=pool_tokens) as runtime,ThreadPoolExecutor(max_workers=3) as pool:
                try:
                    futures=self.submit_in_order(pool,runtime,["a","b","c"])
                    self.until(lambda:len(runtime.seen)==together)
                    snapshot=runtime.queue.snapshot()
                    self.assertEqual((snapshot["active"],snapshot["reservedTokens"],len(runtime.queue.reserving)),(3,per*together,3-together))
                    self.assertLessEqual(snapshot["reservedTokens"],pool_tokens)
                finally: runtime.gate.set()
                self.assertEqual([future.result(10)[0] for future in futures],[200]*3)
                self.assertEqual((runtime.seen,runtime.inflight["most"]),(["a","b","c"],together))
                # An ok reply's cells are returned before the reply is written, not later.
                self.assertEqual(runtime.queue.snapshot()["reservedTokens"],0)
                self.until(lambda:runtime.queue.snapshot()["active"]==0)

    def test_a_kv_reset_waits_for_admitted_requests_and_admits_nothing_meanwhile(self):
        from concurrent.futures import ThreadPoolExecutor
        reset=Mock(return_value={"reset":True,"slots":2})
        with self.endpoint(slots=2) as runtime, ThreadPoolExecutor(max_workers=3) as pool, \
                patch.object(server,"backend_command",reset,create=True):
            def kv():
                client=http.client.HTTPConnection("127.0.0.1",runtime.port,timeout=10)
                try:
                    client.request("POST","/v1/yougori/kv",json.dumps({"action":"reset"}),{"Authorization":"Bearer "+server.TOKEN,
                                   "X-Yougori-Admin":server.ADMIN_TOKEN,"Content-Type":"application/json"})
                    response=client.getresponse();return response.status,json.loads(response.read())
                finally: client.close()
            try:
                first=pool.submit(self.request,runtime.port,"first")
                self.until(lambda:runtime.seen==["first"])
                owner=pool.submit(kv)
                self.until(lambda:runtime.queue.drain is not None)
                later=pool.submit(self.request,runtime.port,"later")
                self.until(lambda:runtime.queue.snapshot()["waiting"]==1)
                time.sleep(0.1)
                self.assertEqual((runtime.seen,reset.call_count),(["first"],0))
                # A second owner operation is refused while one waits.
                with self.assertRaises(server.QueueRefusal): runtime.queue.exclusive().__enter__()
            finally: runtime.gate.set()
            self.assertEqual(owner.result(10),(200,{"reset":True,"slots":2}))
            self.assertEqual((first.result(10)[0],later.result(10)[0]),(200,200))
            self.assertEqual(runtime.seen,["first","later"])
        # It waits a bounded time: still busy afterwards is a retryable refusal that admits again.
        queue=server.InferenceQueue(slots=2)
        queue.active=1
        with self.assertRaises(server.QueueRefusal) as refused:
            with queue.exclusive(seconds=0.2): pass
        self.assertEqual((refused.exception.status,queue.drain),(409,None))

    def test_a_non_streaming_caller_who_disconnects_ends_its_generation_and_frees_its_slot(self):
        with self.endpoint(slots=2,pool=64) as runtime:
            try:
                gone=self.connection(runtime.port,"gone")
                self.until(lambda:runtime.seen==["gone"])
                gone.close()
                # The relay ends its backend request and the backend sees it: the slot frees at once,
                # and the KV cells once the backend has closed its end.
                self.until(lambda:runtime.closed==["gone"] and runtime.queue.snapshot()["active"]==0 and server.GPU_ACTIVE==0)
                self.until(lambda:runtime.queue.snapshot()["reservedTokens"]==0)
                self.assertFalse(runtime.gate.is_set())
            finally: runtime.gate.set()
            self.assertEqual(self.request(runtime.port,"after")[0],200)

    def test_an_abandoned_pooled_request_keeps_its_cells_until_the_backend_closes_its_end(self):
        for stream in (False,True):
            with self.subTest(stream=stream),self.endpoint(slots=2,pool=64) as runtime:
                runtime.lingers["gone"]=threading.Event()
                if stream: runtime.trickle.add("gone")
                try:
                    gone=self.connection(runtime.port,"gone",stream=stream)
                    self.until(lambda:runtime.seen==["gone"])
                    gone.close()
                    self.until(lambda:runtime.closed==["gone"] and runtime.queue.snapshot()["active"]==0)
                    # Longer than any fixed grace period: the backend still holds the request.
                    time.sleep(2)
                    self.assertEqual(runtime.queue.snapshot()["reservedTokens"],2+4+server.RESERVE_MARGIN_TOKENS)
                    runtime.lingers["gone"].set()
                    self.until(lambda:runtime.queue.snapshot()["reservedTokens"]==0)
                finally:
                    runtime.lingers["gone"].set();runtime.gate.set()
                self.assertEqual(self.request(runtime.port,"after")[0],200)

    def test_a_pooled_request_the_backend_fails_returns_its_cells_and_the_next_one_is_served(self):
        with self.endpoint(slots=2,pool=64) as runtime:
            runtime.gate.set()
            status,_,data=self.request(runtime.port,"fail")
            self.assertEqual((status,json.loads(data)["error"]["message"]),(500,"synthetic backend failure"))
            self.until(lambda:runtime.queue.snapshot()["reservedTokens"]==0 and runtime.queue.snapshot()["active"]==0)
            self.assertEqual(self.request(runtime.port,"after")[0],200)

    def test_a_reservation_has_its_own_timeout_and_never_asks_for_more_than_the_pool(self):
        from concurrent.futures import ThreadPoolExecutor
        queue=server.InferenceQueue(timeout=5,slots=2)
        queue.pool=6
        caller,peer=socket.socketpair()
        try:
            # A prompt and max_tokens that fill the pool still fit: the margin stops at the pool.
            self.assertEqual(queue.reserve(SimpleNamespace(connection=caller,queue_deadline=0),6),6)
            # A deadline that passed while the model loaded does not count: this one waits its turn.
            with ThreadPoolExecutor(max_workers=1) as pool:
                later=pool.submit(queue.reserve,SimpleNamespace(connection=caller,queue_deadline=0),1)
                self.until(lambda:len(queue.reserving)==1)
                queue.unreserve(6)
                self.assertEqual(later.result(5),6)
        finally: caller.close();peer.close()

    def test_kv_refusals_and_no_ops_answer_at_once_without_draining_admitted_requests(self):
        from concurrent.futures import ThreadPoolExecutor
        reset=Mock(return_value={"reset":True,"slots":2})
        with self.endpoint(slots=2) as runtime, ThreadPoolExecutor(max_workers=1) as pool, \
                patch.object(server,"backend_command",reset,create=True):
            def kv(action):
                client=http.client.HTTPConnection("127.0.0.1",runtime.port,timeout=10)
                try:
                    client.request("POST","/v1/yougori/kv",json.dumps({"action":action}),{"Authorization":"Bearer "+server.TOKEN,
                                   "X-Yougori-Admin":server.ADMIN_TOKEN,"Content-Type":"application/json"})
                    response=client.getresponse();return response.status,json.loads(response.read())
                finally: client.close()
            try:
                first=pool.submit(self.request,runtime.port,"first")
                self.until(lambda:runtime.seen==["first"])
                # The admitted request still generates; none of these waits for it.
                self.assertEqual(kv("grow")[0],409)
                with patch.dict(server.STATE,parked="sleep"):
                    self.assertEqual(kv("reset"),(200,{"reset":True,"slots":0,"detail":"The model holds no KV while it is unloaded or parked."}))
                with patch.object(server,"FORMAT","vllm"),patch.object(server,"VLLM_KOLIBRI",True):
                    self.assertEqual(kv("reset")[0],409)
                self.assertEqual((runtime.queue.drain,reset.call_count,runtime.queue.snapshot()["active"]),(None,0,1))
            finally: runtime.gate.set()
            self.assertEqual(first.result(10)[0],200)

    def test_connection_overload_returns_retryable_http_instead_of_reset(self):
        with self.endpoint() as runtime, patch.object(server,"REQUESTS",threading.BoundedSemaphore(0)):
            import socket
            client=socket.create_connection(("127.0.0.1",runtime.port),timeout=3)
            try:
                # The refusal is written immediately, before HTTP parsing.
                response=http.client.HTTPResponse(client)
                response.begin()
                self.assertEqual(response.status,503)
                self.assertEqual(response.getheader("Retry-After"),"1")
                self.assertEqual(json.loads(response.read())["error"]["code"],"model_connections_full")
            finally: client.close()


if __name__ == "__main__":
    unittest.main()
