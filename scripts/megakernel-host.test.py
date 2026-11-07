"""Tests of the megakernel runner host (src-tauri/src/model_runner/megakernel_host.py) without a
GPU: a fake tokenizer and a fake runner folder stand in for the model and the kernel, and the
host's own server answers the routes the model server relays to. NVRTC compilation runs when
the CUDA compiler library is installed (the toolkit or the nvidia-cuda-nvrtc wheel) and is
skipped otherwise; nothing here touches a GPU."""
import http.client
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
import types
import unittest
from contextlib import ExitStack
from unittest.mock import patch

HOST_PATH = Path(__file__).parents[1] / "src-tauri/src/model_runner/megakernel_host.py"
spec = importlib.util.spec_from_file_location("megakernel_host", HOST_PATH)
host_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(host_module)

EOS = 1  # the fake tokenizer's end token; every other id is a UTF-8 byte plus 2


def encode(text):
    return [byte + 2 for byte in text.encode("utf-8")]


def decode(tokens):
    return bytes(token - 2 for token in tokens if token >= 2).decode("utf-8", "replace")


class FakeTokenizer:
    """Byte tokens: a multi-byte character is several tokens, as in a real tokenizer's worst case."""
    eos_token_id = EOS
    chat_template = "{% for m in messages %}{{ m.role }}: {{ m.content }}\n{% endfor %}assistant: {{ enable_thinking }}"

    def apply_chat_template(self, messages, tokenize=True, add_generation_prompt=True, chat_template=None, **kwargs):
        text = "".join(message["role"] + ": " + message["content"] + "\n" for message in messages) + "assistant:"
        if chat_template:
            text = "[custom]" + text
        return encode(text) if tokenize else text

    def __call__(self, text):
        return {"input_ids": encode(text)}

    def decode(self, tokens, skip_special_tokens=True):
        return decode(tokens)


RUNNER = '''
import time
import yougori_runner

CALLS = {"active": 0, "peak": 0, "closed": 0, "settings": None}


class Runner:
    def __init__(self, settings):
        CALLS["settings"] = settings
        self.facts = yougori_runner.device()

    def generate(self, tokens, max_tokens, stop, temperature=0.0, top_p=1.0):
        CALLS["active"] += 1
        CALLS["peak"] = max(CALLS["peak"], CALLS["active"])
        try:
            prompt = bytes(t - 2 for t in tokens if t >= 2).decode("utf-8", "replace")
            if "France" in prompt:
                reply = [b + 2 for b in "Paris, naturally.".encode()] + [1]
            elif "numbers" in prompt:
                reply = [b + 2 for b in " ".join(str(n) for n in range(1, 400)).encode()]
            elif "slow" in prompt:
                reply = [b + 2 for b in ("x " * 200).encode()]
            elif "fail" in prompt:
                raise RuntimeError("the kernel died: " + prompt)
            else:
                reply = [b + 2 for b in ("echo: " + prompt.split("user: ")[-1].split("\\n")[0] + " caf\\u00e9 \\u00e9t\\u00e9 done").encode()] + [1]
            for token in reply[:max_tokens]:
                if "slow" in prompt:
                    time.sleep(0.01)
                yield token
        finally:
            CALLS["active"] -= 1
            CALLS["closed"] += 1


def load(model_dir, settings):
    settings["say"]("fake runner loading")
    return Runner(settings)
'''

FACTS = {"device": 0, "gpu": "Fixture GPU", "computeCapability": [12, 0], "multiprocessors": 82,
         "totalMemoryBytes": 24 << 30, "freeMemoryBytes": 20 << 30}


def runner_folder(root, manifest=None, module=RUNNER):
    folder = Path(root) / "runner"
    folder.mkdir(exist_ok=True)
    (folder / "runner.json").write_text(json.dumps({"name": "fixture-kernel", "version": "3", **(manifest or {})}))
    (folder / "runner.py").write_text(module)
    return folder


def model_folder(root):
    folder = Path(root) / "model"
    folder.mkdir(exist_ok=True)
    (folder / "config.json").write_text(json.dumps({"architectures": ["Qwen3ForCausalLM"], "max_position_embeddings": 40960}))
    (folder / "generation_config.json").write_text(json.dumps({"eos_token_id": [EOS, 1]}))
    return folder


def arguments(root, runner, **more):
    values = {"runner": str(runner), "model": str(model_folder(root)), "name": "Qwen/Qwen3-0.6B", "revision": "a" * 40, "port": 0,
              "parallel": 4, "context": 8192, "build": str(Path(root) / "build"), "status": str(Path(root) / "status.json"), **more}
    return types.SimpleNamespace(**values)


class HostFixture:
    """A host started on a fake runner, with transformers and the GPU facts replaced."""

    def __init__(self, stack, root, manifest=None, module=RUNNER, **more):
        transformers = types.SimpleNamespace(AutoTokenizer=types.SimpleNamespace(from_pretrained=lambda *a, **k: FakeTokenizer()))
        stack.enter_context(patch.dict(sys.modules, {"transformers": transformers}))
        stack.enter_context(patch.object(host_module.MkHost, "gpu", lambda self: dict(FACTS)))
        self.lines = []
        self.host = host_module.MkHost(arguments(root, runner_folder(root, manifest, module), **more), "k" * 48)
        stack.enter_context(patch("builtins.print", lambda *a, **k: self.lines.append(" ".join(str(x) for x in a))))
        stack.callback(lambda: sys.modules.pop("yougori_runner", None))


class ServedFixture(HostFixture):
    def __init__(self, stack, root, **more):
        super().__init__(stack, root, **more)
        self.host.start()
        host_module.MkHandler.host = self.host
        self.server = host_module.MkServer(("127.0.0.1", 0), host_module.MkHandler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
        stack.callback(self.server.shutdown)

    def request(self, path, body=None, key="k" * 48, raw=False):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        data = None if body is None else json.dumps(body).encode()
        connection.request("GET" if body is None else "POST", path, data, {"Authorization": "Bearer " + key, "Content-Type": "application/json"})
        response = connection.getresponse()
        if raw:
            return connection, response
        payload = response.read()
        connection.close()
        return response.status, json.loads(payload)


class ManifestTests(unittest.TestCase):
    def test_a_manifest_is_checked_field_by_field(self):
        with tempfile.TemporaryDirectory() as root:
            folder = runner_folder(root, {"gpu": {"computeCapability": "8.0", "memoryGb": 2}, "parallel": 2, "context": 2048, "precision": "Q4"})
            manifest = host_module.mk_manifest(str(folder))
            self.assertEqual((manifest["name"], manifest["version"], manifest["module"], manifest["parallel"]), ("fixture-kernel", "3", "runner.py", 2))
            self.assertEqual(manifest["gpu"], {"computeCapability": (8, 0), "memoryGb": 2.0})
            self.assertEqual(manifest["check"], host_module.MK_CHECK)
            for bad, message in (({"name": "bad name"}, "name"), ({"version": "v" * 40}, "version"), ({"module": "../x.py"}, "module"),
                                 ({"models": []}, "models"), ({"gpu": {"computeCapability": 8}}, "computeCapability"), ({"parallel": 0}, "parallel"),
                                 ({"sampling": "yes"}, "sampling"), ({"context": 10}, "context"), ({"check": {"prompt": "x"}}, "check"), ({"extra": 1}, "may name")):
                runner_folder(root, bad)
                with self.assertRaisesRegex(RuntimeError, message):
                    host_module.mk_manifest(str(folder))
            (folder / "runner.json").write_text("{")
            with self.assertRaisesRegex(RuntimeError, "valid JSON"):
                host_module.mk_manifest(str(folder))
            with self.assertRaisesRegex(RuntimeError, "no runner.json"):
                host_module.mk_manifest(root)

    def test_a_runner_reference_is_a_folder_or_a_pinned_hugging_face_repository(self):
        with tempfile.TemporaryDirectory() as root:
            folder = runner_folder(root)
            self.assertEqual(host_module.mk_resolve(str(folder), root, print), str(folder))
            with self.assertRaisesRegex(RuntimeError, "not a folder"):
                host_module.mk_resolve(str(folder) + "-missing", root, print)
            # A downloaded repository is reused from the build root without the hub.
            commit = "0123456789abcdef0123456789abcdef01234567"
            downloaded = Path(root) / "runners" / "acme--fast-qwen-0123456789ab"
            downloaded.mkdir(parents=True)
            (downloaded / "runner.json").write_text("{}")
            self.assertEqual(host_module.mk_resolve("hf:acme/fast-qwen@" + commit, root, print), str(downloaded))


class TextTests(unittest.TestCase):
    def test_text_is_shown_once_its_characters_are_complete_and_stop_strings_cut_it(self):
        text = host_module.MkText(FakeTokenizer(), [])
        pieces = [text.push(token)[0] for token in encode("caf\u00e9!")]
        self.assertEqual(pieces, ["c", "a", "f", "", "\u00e9", "!"], "the two bytes of \u00e9 are shown together")
        self.assertEqual(text.flush(), "")
        text = host_module.MkText(FakeTokenizer(), ["END", "\n\n"])
        out, stopped = [], False
        for token in encode("one END two"):
            piece, stopped = text.push(token)
            out.append(piece)
            if stopped:
                break
        self.assertTrue(stopped)
        self.assertEqual("".join(out) + text.flush(), "one ")
        text = host_module.MkText(FakeTokenizer(), ["END"])
        shown = "".join(text.push(token)[0] for token in encode("abcdef"))
        self.assertEqual(shown, "abcd", "two characters (one less than the longest stop) are held back")
        self.assertEqual(text.flush(), "ef")


class HostTests(unittest.TestCase):
    def test_the_host_loads_checks_and_measures_the_runner(self):
        with tempfile.TemporaryDirectory() as root, ExitStack() as stack:
            fixture = HostFixture(stack, root, {"parallel": 2, "precision": "BF16", "context": 4096, "gpu": {"computeCapability": "9.0", "memoryGb": 4}})
            fixture.host.start()
            facts = fixture.host.facts
            self.assertEqual((facts["name"], facts["version"], facts["precision"], facts["parallel"], facts["context"], facts["gpu"]), ("fixture-kernel", "3", "BF16", 2, 4096, "Fixture GPU"))
            self.assertEqual(facts["check"], {"prompt": host_module.MK_CHECK["prompt"], "answer": "Paris, naturally.", "passed": True})
            self.assertGreater(facts["tokensPerSecond"], 0)
            self.assertGreaterEqual(facts["measuredRuns"], 2)
            self.assertEqual(fixture.host.stop_ids, {EOS})
            settings = sys.modules["yougori_runner_fixture_kernel"].CALLS["settings"]
            self.assertEqual((settings["model"], settings["gpu"], settings["parallel"], settings["context"]), ("Qwen/Qwen3-0.6B", "Fixture GPU", 2, 4096))
            self.assertTrue(settings["buildDir"].startswith(str(Path(root) / "build" / "fixture-kernel-3" / "fixture-gpu-sm120")), settings["buildDir"])
            self.assertTrue(Path(settings["buildDir"]).is_dir())
            self.assertIn("fake runner loading", fixture.lines)
            status = json.loads(Path(root, "status.json").read_text())
            self.assertTrue(status["ready"])
            self.assertIn("serves Qwen/Qwen3-0.6B", status["stage"])

    def test_a_runner_that_fails_its_check_or_does_not_fit_is_refused(self):
        with tempfile.TemporaryDirectory() as root, ExitStack() as stack:
            fixture = HostFixture(stack, root, {"check": {"prompt": "What is the capital of France?", "expect": "Lyon"}})
            with self.assertRaisesRegex(RuntimeError, 'answered the check question with "Paris, naturally." .* "Lyon" was expected'):
                fixture.host.start()
        for manifest, message in (({"gpu": {"computeCapability": "13.0"}}, "needs compute capability 13.0"), ({"gpu": {"memoryGb": 48}}, "needs 48 GB of free GPU memory"),
                                  ({"models": ["acme/other"]}, "serves acme/other, not Qwen/Qwen3-0.6B"), ({"architectures": ["LlamaForCausalLM"]}, "serves LlamaForCausalLM, not Qwen3ForCausalLM")):
            with tempfile.TemporaryDirectory() as root, ExitStack() as stack:
                fixture = HostFixture(stack, root, manifest)
                with self.assertRaisesRegex(RuntimeError, message):
                    fixture.host.start()
        with tempfile.TemporaryDirectory() as root, ExitStack() as stack:
            fixture = HostFixture(stack, root, module="def load(model_dir, settings):\n    return object()\n")
            with self.assertRaisesRegex(RuntimeError, "without generate"):
                fixture.host.start()

    def test_the_main_entry_prints_the_contract_and_reports_a_failed_start(self):
        with patch("builtins.print") as printed:
            self.assertEqual(host_module.main(["contract"]), 0)
        self.assertIn("runner.json", printed.call_args.args[0])
        with tempfile.TemporaryDirectory() as root, patch.dict(os.environ, YOUGORI_MEGAKERNEL_KEY="k" * 48), patch("builtins.print"):
            code = host_module.main(["serve", "--runner", str(Path(root) / "missing"), "--model", root, "--name", "x/y", "--revision", "a" * 40,
                                     "--port", "1", "--build", str(Path(root) / "build"), "--status", str(Path(root) / "status.json")])
            self.assertEqual(code, 1)
            self.assertIn("not a folder", json.loads(Path(root, "status.json").read_text())["error"])
            self.assertNotIn("YOUGORI_MEGAKERNEL_KEY", os.environ, "the key never reaches the runner's environment")
        with patch.dict(os.environ, YOUGORI_MEGAKERNEL_KEY="short"), patch("builtins.print"):
            self.assertEqual(host_module.main(["serve", "--runner", "x", "--model", "y", "--name", "x/y", "--revision", "a", "--port", "1", "--build", "b", "--status", "s"]), 2)


class ServingTests(unittest.TestCase):
    def test_the_routes_answer_as_vllm_would(self):
        with tempfile.TemporaryDirectory() as root, ExitStack() as stack:
            served = ServedFixture(stack, root)
            status, health = served.request("/health")
            self.assertEqual((status, health["status"], health["runner"]["name"]), (200, "ready", "fixture-kernel"))
            self.assertEqual(served.request("/tokenize", {"messages": [{"role": "user", "content": "hi"}]}, key="wrong")[0], 401)
            status, counted = served.request("/tokenize", {"messages": [{"role": "user", "content": "hi"}], "chat_template_kwargs": {"enable_thinking": False}})
            self.assertEqual((status, counted["count"]), (200, len(encode("user: hi\nassistant:"))))
            status, custom = served.request("/tokenize", {"messages": [{"role": "user", "content": "hi"}], "chat_template": "{{ x }}"})
            self.assertEqual(custom["count"], counted["count"] + len("[custom]"), "a template the relay sends is applied")
            body = {"messages": [{"role": "user", "content": "What is the capital of France?"}], "max_tokens": 64, "temperature": 0.7, "model": "Qwen/Qwen3-0.6B",
                    "chat_template_kwargs": {"enable_thinking": False}}
            status, reply = served.request("/v1/chat/completions", body)
            self.assertEqual(status, 200, reply)
            self.assertEqual(reply["choices"][0]["message"], {"role": "assistant", "content": "Paris, naturally."})
            self.assertEqual(reply["choices"][0]["finish_reason"], "stop")
            self.assertEqual(reply["usage"], {"prompt_tokens": counted["count"] + len("What is the capital of France?") - 2, "completion_tokens": len("Paris, naturally.") + 1,
                                              "total_tokens": reply["usage"]["prompt_tokens"] + reply["usage"]["completion_tokens"]})
            self.assertEqual((reply["timings"]["predicted_n"], reply["timings"]["cache_n"]), (reply["usage"]["completion_tokens"], 0))
            self.assertEqual(reply["model"], "Qwen/Qwen3-0.6B")
            # Length, stop strings, tools, context and the runner's own failure.
            status, reply = served.request("/v1/chat/completions", {"messages": [{"role": "user", "content": "numbers"}], "max_tokens": 5})
            self.assertEqual((reply["choices"][0]["finish_reason"], reply["usage"]["completion_tokens"], reply["choices"][0]["message"]["content"]), ("length", 5, "1 2 3"))
            status, reply = served.request("/v1/chat/completions", {"messages": [{"role": "user", "content": "numbers"}], "max_tokens": 40, "stop": ["7 8", "zzz"]})
            self.assertEqual((reply["choices"][0]["finish_reason"], reply["choices"][0]["message"]["content"]), ("stop", "1 2 3 4 5 6 "))
            status, reply = served.request("/v1/chat/completions", {"messages": [{"role": "user", "content": "hi"}], "tools": [{"type": "function"}]})
            self.assertEqual((status, reply["error"]["message"]), (400, "This megakernel runner has no tool calling"))
            status, reply = served.request("/v1/chat/completions", {"messages": [{"role": "user", "content": "hi"}], "max_tokens": 8192})
            self.assertEqual(status, 400)
            self.assertIn("exceed this runner's context of 4096 tokens", reply["error"]["message"])
            status, reply = served.request("/v1/chat/completions", {"messages": [{"role": "user", "content": "please fail"}]})
            self.assertEqual((status, reply["error"]["message"]), (500, "The megakernel runner failed during generation (RuntimeError)"))
            self.assertNotIn("please fail", json.dumps(reply), "the conversation never leaves in an error")
            # A multi-byte reply streams whole characters, then usage and [DONE].
            connection, response = served.request("/v1/chat/completions", {"messages": [{"role": "user", "content": "hello"}], "stream": True, "stream_options": {"include_usage": True}}, raw=True)
            events = []
            while True:
                line = response.readline()
                if not line:
                    break
                if line.startswith(b"data: ") and line.strip() != b"data: [DONE]":
                    events.append(json.loads(line[6:]))
                elif line.strip() == b"data: [DONE]":
                    events.append("DONE")
            connection.close()
            self.assertEqual(events[0]["choices"][0]["delta"], {"role": "assistant", "content": ""})
            text = "".join(event["choices"][0]["delta"].get("content", "") for event in events[1:-2])
            self.assertEqual(text, "echo: hello caf\u00e9 \u00e9t\u00e9 done")
            self.assertTrue(all("\ufffd" not in (event["choices"][0]["delta"].get("content") or "") for event in events[1:-2]))
            self.assertEqual((events[-2]["choices"][0]["finish_reason"], events[-2]["usage"]["completion_tokens"], events[-1]), ("stop", len(text.encode()) + 1, "DONE"))

    def test_requests_run_in_parallel_up_to_the_runner_slots_and_a_gone_caller_stops_generation(self):
        with tempfile.TemporaryDirectory() as root, ExitStack() as stack:
            served = ServedFixture(stack, root, manifest={"parallel": 2})
            calls = sys.modules["yougori_runner_fixture_kernel"].CALLS
            calls["peak"] = 0
            results = []
            def ask():
                results.append(served.request("/v1/chat/completions", {"messages": [{"role": "user", "content": "slow"}], "max_tokens": 60})[0])
            threads = [threading.Thread(target=ask) for _ in range(3)]
            for thread in threads: thread.start()
            for thread in threads: thread.join(30)
            self.assertEqual(results, [200, 200, 200])
            self.assertEqual(calls["peak"], 2, "two generate at once (the manifest's parallel), the third waits")
            closed = calls["closed"]
            connection, response = served.request("/v1/chat/completions", {"messages": [{"role": "user", "content": "slow"}], "stream": True}, raw=True)
            response.readline()
            connection.close()
            deadline = time.monotonic() + 10
            while calls["closed"] == closed and time.monotonic() < deadline:
                time.sleep(0.05)
            self.assertEqual(calls["closed"], closed + 1, "the generator is closed when the caller goes away")
            self.assertEqual(calls["active"], 0)


class CompilerTests(unittest.TestCase):
    def test_nvrtc_compiles_a_kernel_for_the_gpu_and_caches_it(self):
        try:
            nvrtc = host_module.MkNvrtc()
        except RuntimeError as error:
            self.skipTest(str(error))
        self.assertGreaterEqual(nvrtc.version[0], 12)
        self.assertIn(80, nvrtc.archs)
        with tempfile.TemporaryDirectory() as root:
            module = host_module.mk_runner_module(root, {**FACTS, "computeCapability": [8, 0]})
            source = 'extern "C" __global__ void add_one(float* values, int n) { int i = blockIdx.x * blockDim.x + threadIdx.x; if (i < n) values[i] += 1.0f; }\n'
            image = module.compile(source, "add_one")
            self.assertTrue(image.startswith(b"\x7fELF"), "sm_80 is compiled to a cubin")
            cached = [name for name in os.listdir(root) if name.startswith("add_one-") and name.endswith(".cubin")]
            self.assertEqual(len(cached), 1)
            self.assertEqual(module.compile(source, "add_one"), image, "the same source and options come from the cache")
            with self.assertRaisesRegex(RuntimeError, "did not compile"):
                module.compile('__global__ void broken( { }', "broken")
            # A GPU newer than this NVRTC gets PTX for the newest architecture it knows.
            option, cubin = nvrtc.target((99, 9))
            self.assertEqual((option, cubin), ("--gpu-architecture=compute_" + str(max(nvrtc.archs)), False))
            fp16 = module.compile('#include <cuda_fp16.h>\nextern "C" __global__ void halves(__half* v) { v[threadIdx.x] = __float2half(1.0f); }\n', "halves")
            self.assertTrue(fp16.startswith(b"\x7fELF"), "the fp16 header is found (the CUDA runtime's include folder or NVRTC's own)")

    def test_the_owners_qwen3_megakernel_compiles_when_its_source_is_at_hand(self):
        kernel = Path(os.environ.get("YOUGORI_TEST_MEGAKERNEL", "D:/Argon AI Model/mega_lab/yougori-runner/kernel.cu"))
        if not kernel.is_file():
            self.skipTest("no megakernel source at " + str(kernel))
        try:
            host_module.MkNvrtc()
        except RuntimeError as error:
            self.skipTest(str(error))
        with tempfile.TemporaryDirectory() as root:
            module = host_module.mk_runner_module(root, {**FACTS, "computeCapability": [12, 0]})
            began = time.monotonic()
            image = module.compile(kernel.read_text(encoding="utf-8"), "mk_decode")
            self.assertGreater(len(image), 10000)
            print("compiled the Qwen3-0.6B megakernel in %.1f s (%d bytes)" % (time.monotonic() - began, len(image)))


if __name__ == "__main__":
    unittest.main(verbosity=1)
