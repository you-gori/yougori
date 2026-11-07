"""Yougori's megakernel runner host: the model server's vLLM-format runner starts this script
(engine_backends.py, load_megakernel) beside itself in the model's container, without its
credentials, when the model's launch is "megakernel". It loads the owner's runner (a folder with
runner.json and a Python module: CONTRACT), builds it for this GPU through the `yougori_runner`
module it provides, checks that it answers a question, measures its speed, then serves /health,
/tokenize and /v1/chat/completions on the container's loopback the way vLLM does, so the model
server relays requests to it unchanged (generate_gguf).

    python3 megakernel_host.py serve --runner FOLDER|hf:OWNER/REPO@COMMIT --model DIR ...
    python3 megakernel_host.py contract
"""
import argparse
import ctypes
import ctypes.util
import glob
import hashlib
import http.server
import importlib.util
import json
import os
import re
import secrets
import select
import socket
import sys
import threading
import time
import types

CONTRACT = """A megakernel runner is a folder (bound read-only at /yougori-runner, or a public Hugging
Face repository named hf:OWNER/REPO@REVISION with the commit's 40-hex id) holding:

runner.json
  name            "[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
  version         a short string (at most 32 characters); a new version builds again
  module          the Python file beside it with load() (default "runner.py")
  models          optional: the Hugging Face model ids this runner serves (others are refused)
  architectures   optional: config.json architectures it serves (others are refused)
  gpu             optional: {"computeCapability": "8.0", "memoryGb": 2} it needs at least
  parallel        conversations it generates at once (1-16, default 1); generate() is then called
                  from that many threads at once
  sampling        true when generate() honours temperature and top_p (default false: greedy)
  context         the longest conversation plus reply, in tokens (default 4096)
  precision       shown in the model's health, for example "Q4" or "BF16" (optional)
  check           {"prompt": "...", "expect": "..."}: the question the runner must answer at
                  start, greedy, with the expected text somewhere in its reply (default: the
                  capital of France, "Paris"); null skips the check

runner.py
  def load(model_dir, settings) -> runner
      model_dir: the verified checkpoint's folder (config.json, tokenizer, safetensors)
      settings: {"model", "revision", "device": 0, "gpu": name, "computeCapability": [major,
                 minor], "multiprocessors", "totalMemoryBytes", "freeMemoryBytes",
                 "buildDir": a writable folder kept per GPU, runner version and checkpoint
                 (packed weights and compiled kernels go there), "context", "parallel",
                 "say": a function for progress lines}
  runner.generate(tokens, max_tokens, stop, temperature=0.0, top_p=1.0)
      tokens: the whole conversation as token ids (the chat template is applied by Yougori);
      yields the reply's token ids one by one and returns at a token in `stop` (a set of ids),
      after max_tokens, or when the consumer closes the generator (the caller went away).
  runner.close()   optional

import yougori_runner   (provided by Yougori; needs no install)
  yougori_runner.device() -> the settings' GPU facts
  yougori_runner.compile(source, name="kernel", options=(), include_dirs=()) -> bytes
      CUDA C++ compiled with NVRTC for this GPU (cubin, or PTX when NVRTC predates it), cached
      in buildDir by its source and options; kernels are plain `extern "C" __global__` functions
  yougori_runner.load(image) -> module; module.function(name) -> function
      function.max_dynamic_shared(bytes); function.blocks_per_multiprocessor(block, shared)
      function.launch(grid, block, shared, params, stream=0): params is a ctypes.Structure
      passed by value as the kernel's one parameter; launch() returns after the kernel ends
  yougori_runner.synchronize()
"""

MK_CHECK = {"prompt": "What is the capital of France? Answer in one word.", "expect": "Paris"}
MK_SPEED_PROMPT = "Write the numbers from 1 to 300 separated by spaces, nothing else."
MK_NAME = r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}"
MK_HF = r"hf:([A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)@([0-9a-f]{40})"
MK_RUNNER_FILES = ["runner.json", "*.py", "*.cu", "*.cuh", "*.h", "*.hpp", "*.json", "*.txt", "*.md", "*.cubin", "*.ptx", "*.so", "*.npy", "*.bin"]


def mk_manifest(folder):
    """The runner's manifest, checked field by field (CONTRACT)."""
    path = os.path.join(folder, "runner.json")
    try:
        with open(path, encoding="utf-8") as file:
            manifest = json.loads(file.read(65536))
    except OSError:
        raise RuntimeError("The runner folder has no runner.json") from None
    except ValueError:
        raise RuntimeError("runner.json is not valid JSON") from None
    if not isinstance(manifest, dict) or set(manifest) - {"name", "version", "module", "models", "architectures", "gpu", "parallel",
                                                           "sampling", "context", "precision", "check"}:
        raise RuntimeError("runner.json may name name, version, module, models, architectures, gpu, parallel, sampling, context, precision and check")
    name, version = manifest.get("name"), manifest.get("version", "1")
    if not isinstance(name, str) or not re.fullmatch(MK_NAME, name):
        raise RuntimeError("runner.json needs a name of up to 64 letters, digits, dots, dashes or underscores")
    if not isinstance(version, str) or not 1 <= len(version) <= 32 or not re.fullmatch(r"[A-Za-z0-9._-]+", version):
        raise RuntimeError("runner.json's version is a short string of letters, digits, dots, dashes or underscores")
    module = manifest.get("module", "runner.py")
    if not isinstance(module, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.py", module) or os.sep in module or "/" in module:
        raise RuntimeError("runner.json's module is a Python file beside it")
    for key in ("models", "architectures"):
        values = manifest.get(key)
        if values is not None and (not isinstance(values, list) or not values or any(not isinstance(v, str) or not 1 <= len(v) <= 200 for v in values)):
            raise RuntimeError("runner.json's " + key + " is a list of names")
    gpu = manifest.get("gpu") or {}
    if not isinstance(gpu, dict) or set(gpu) - {"computeCapability", "memoryGb"}:
        raise RuntimeError("runner.json's gpu names computeCapability and memoryGb")
    capability = gpu.get("computeCapability", "7.0")
    if not isinstance(capability, str) or not re.fullmatch(r"\d{1,2}\.\d", capability):
        raise RuntimeError("runner.json's gpu.computeCapability reads like \"8.0\"")
    memory = gpu.get("memoryGb", 0)
    if type(memory) not in (int, float) or not 0 <= memory <= 4096:
        raise RuntimeError("runner.json's gpu.memoryGb is a number of gigabytes")
    parallel = manifest.get("parallel", 1)
    if type(parallel) is not int or not 1 <= parallel <= 16:
        raise RuntimeError("runner.json's parallel is 1-16")
    if type(manifest.get("sampling", False)) is not bool:
        raise RuntimeError("runner.json's sampling is true or false")
    context = manifest.get("context", 4096)
    if type(context) is not int or not 256 <= context <= 1 << 20:
        raise RuntimeError("runner.json's context is 256 to 1,048,576 tokens")
    precision = manifest.get("precision")
    if precision is not None and (not isinstance(precision, str) or not 1 <= len(precision) <= 16):
        raise RuntimeError("runner.json's precision is a short label")
    check = manifest.get("check", MK_CHECK)
    if check is not None and (not isinstance(check, dict) or set(check) != {"prompt", "expect"} or any(not isinstance(check[k], str) or not 1 <= len(check[k]) <= 2000 for k in check)):
        raise RuntimeError("runner.json's check is {\"prompt\": ..., \"expect\": ...} or null")
    return {"name": name, "version": version, "module": module, "models": manifest.get("models"), "architectures": manifest.get("architectures"),
            "gpu": {"computeCapability": tuple(int(p) for p in capability.split(".")), "memoryGb": float(memory)}, "parallel": parallel,
            "sampling": manifest.get("sampling", False), "context": context, "precision": precision, "check": check}


def mk_resolve(reference, build_root, say):
    """The runner folder a reference names: a folder (the engine binds a local one at
    /yougori-runner), or a public Hugging Face repository at a pinned commit, downloaded once into
    the build root and checked against that commit."""
    found = re.fullmatch(MK_HF, reference or "")
    if found:
        repo, revision = found[1], found[2]
        folder = os.path.join(build_root, "runners", repo.replace("/", "--") + "-" + revision[:12])
        if os.path.isfile(os.path.join(folder, "runner.json")):
            return folder
        say("Downloading the runner " + repo + " at " + revision[:12] + "...")
        from huggingface_hub import HfApi, snapshot_download
        environment = dict(os.environ)
        for name in ("HF_HUB_OFFLINE", "TRANSFORMERS_OFFLINE"):
            os.environ.pop(name, None)
        try:
            info = HfApi().model_info(repo, revision=revision, timeout=30)
            if info.sha != revision:
                raise RuntimeError("The runner repository " + repo + " has no commit " + revision)
            staging = folder + ".download"
            snapshot_download(repo, revision=revision, local_dir=staging, allow_patterns=MK_RUNNER_FILES, max_workers=4)
            os.replace(staging, folder)
        finally:
            os.environ.clear()
            os.environ.update(environment)
        return folder
    if not reference or not os.path.isdir(reference):
        raise RuntimeError("The runner " + (reference or "(none)") + " is not a folder; name a folder or hf:OWNER/REPO@COMMIT")
    return reference


def mk_libraries(patterns):
    """Library candidates in the Python environment, the CUDA toolkit and the loader path."""
    roots = []
    for base in sys.path:
        if base and os.path.isdir(base):
            roots += [os.path.join(base, "nvidia", "cuda_nvrtc"), os.path.join(base, "torch", "lib"), os.path.join(base, "nvidia", "cuda_runtime")]
    for variable in ("CUDA_HOME", "CUDA_PATH"):
        if os.environ.get(variable):
            roots.append(os.environ[variable])
    roots += ["/usr/local/cuda"] + sorted(glob.glob("C:/Program Files/NVIDIA GPU Computing Toolkit/CUDA/v*"), reverse=True)
    found = []
    for root in roots:
        for pattern in patterns:
            found += sorted(glob.glob(os.path.join(root, pattern)), reverse=True)
    return found


class MkNvrtc:
    """NVRTC, the CUDA C++ compiler library that ships with the GPU PyTorch Yougori's images use,
    through ctypes: a kernel source becomes a cubin for this GPU (or PTX when this NVRTC predates
    it, which the driver finishes) without a CUDA toolkit install."""

    def __init__(self):
        path = os.environ.get("YOUGORI_NVRTC") or next(iter(mk_libraries(["lib/libnvrtc.so.1*", "lib64/libnvrtc.so.1*", "libnvrtc.so.1*", "bin/nvrtc64_1*_0.dll", "nvrtc64_1*_0.dll"])), None)
        if not path:
            path = ctypes.util.find_library("nvrtc")
        if not path:
            raise RuntimeError("NVRTC (the CUDA compiler library) was not found; install nvidia-cuda-nvrtc-cu12 or set YOUGORI_NVRTC")
        self.path = path
        if hasattr(os, "add_dll_directory"):
            # NVRTC opens its builtins library by name at compile time: from its own folder.
            self.folder_handle = os.add_dll_directory(os.path.dirname(os.path.abspath(path)))
        self.lib = ctypes.CDLL(path)
        c_void_pp, c_size_tp, c_intp = ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_size_t), ctypes.POINTER(ctypes.c_int)
        for name, argtypes, restype in (
                ("nvrtcCreateProgram", [c_void_pp, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p], ctypes.c_int),
                ("nvrtcCompileProgram", [ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)], ctypes.c_int),
                ("nvrtcGetProgramLogSize", [ctypes.c_void_p, c_size_tp], ctypes.c_int), ("nvrtcGetProgramLog", [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_int),
                ("nvrtcGetCUBINSize", [ctypes.c_void_p, c_size_tp], ctypes.c_int), ("nvrtcGetCUBIN", [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_int),
                ("nvrtcGetPTXSize", [ctypes.c_void_p, c_size_tp], ctypes.c_int), ("nvrtcGetPTX", [ctypes.c_void_p, ctypes.c_char_p], ctypes.c_int),
                ("nvrtcDestroyProgram", [c_void_pp], ctypes.c_int), ("nvrtcGetErrorString", [ctypes.c_int], ctypes.c_char_p),
                ("nvrtcVersion", [c_intp, c_intp], ctypes.c_int), ("nvrtcGetNumSupportedArchs", [c_intp], ctypes.c_int), ("nvrtcGetSupportedArchs", [c_intp], ctypes.c_int)):
            function = getattr(self.lib, name)
            function.argtypes, function.restype = argtypes, restype
        major, minor = ctypes.c_int(), ctypes.c_int()
        self.lib.nvrtcVersion(ctypes.byref(major), ctypes.byref(minor))
        self.version = (major.value, minor.value)
        count = ctypes.c_int()
        self.lib.nvrtcGetNumSupportedArchs(ctypes.byref(count))
        archs = (ctypes.c_int * max(1, count.value))()
        self.lib.nvrtcGetSupportedArchs(archs)
        self.archs = sorted(set(archs[:count.value]))

    def include_dirs(self):
        """Where cuda_fp16.h and its siblings are: the CUDA runtime's Python package or toolkit."""
        folders = [os.path.join(os.path.dirname(os.path.dirname(self.path)), "include")]
        folders += [os.path.dirname(path) for path in mk_libraries(["include/cuda_fp16.h", "cuda_fp16.h"])]
        return [folder for folder in dict.fromkeys(folders) if os.path.isfile(os.path.join(folder, "cuda_fp16.h"))]

    def target(self, capability):
        """The architecture option for this GPU: its own SASS when this NVRTC knows the GPU, else
        PTX for the newest architecture it knows, which the driver compiles for the GPU."""
        arch = capability[0] * 10 + capability[1]
        if arch in self.archs:
            return "--gpu-architecture=sm_" + str(arch), True
        older = [known for known in self.archs if known < arch]
        if not older:
            raise RuntimeError("NVRTC " + ".".join(map(str, self.version)) + " knows no architecture this GPU (compute capability " + ".".join(map(str, capability)) + ") can run")
        return "--gpu-architecture=compute_" + str(max(older)), False

    def compile(self, source, name, options):
        """The compiled image (cubin or PTX by the options) or the compiler's log as the error."""
        program = ctypes.c_void_p()
        self.check(self.lib.nvrtcCreateProgram(ctypes.byref(program), source.encode("utf-8"), name.encode("utf-8"), 0, None, None))
        try:
            array = (ctypes.c_char_p * max(1, len(options)))(*[option.encode("utf-8") for option in options])
            result = self.lib.nvrtcCompileProgram(program, len(options), array)
            size = ctypes.c_size_t()
            self.lib.nvrtcGetProgramLogSize(program, ctypes.byref(size))
            log = ctypes.create_string_buffer(size.value + 1)
            self.lib.nvrtcGetProgramLog(program, log)
            text = log.value.decode("utf-8", "replace").strip()
            if result:
                raise RuntimeError("The kernel " + name + " did not compile:\n" + text[-6000:])
            cubin = any(option.startswith("--gpu-architecture=sm_") or option.startswith("-arch=sm_") for option in options)
            getter_size, getter = (self.lib.nvrtcGetCUBINSize, self.lib.nvrtcGetCUBIN) if cubin else (self.lib.nvrtcGetPTXSize, self.lib.nvrtcGetPTX)
            self.check(getter_size(program, ctypes.byref(size)))
            image = ctypes.create_string_buffer(size.value)
            self.check(getter(program, image))
            return image.raw[:size.value] if cubin else image.raw.split(b"\0", 1)[0] + b"\0"
        finally:
            self.lib.nvrtcDestroyProgram(ctypes.byref(program))

    def check(self, result):
        if result:
            raise RuntimeError("NVRTC: " + (self.lib.nvrtcGetErrorString(result) or b"error").decode("utf-8", "replace"))


class MkDriver:
    """The CUDA driver API this host's runners launch with, through ctypes, on the GPU's primary
    context (the one PyTorch uses, so tensors' addresses are kernel arguments as they are)."""
    MAX_DYNAMIC_SHARED = 8
    MULTIPROCESSOR_COUNT = 16

    def __init__(self, device=0):
        name = "nvcuda.dll" if sys.platform == "win32" else "libcuda.so.1"
        try:
            self.lib = ctypes.CDLL(name)
        except OSError:
            raise RuntimeError("The CUDA driver library " + name + " is not available in this container") from None
        c_void_pp, c_intp = ctypes.POINTER(ctypes.c_void_p), ctypes.POINTER(ctypes.c_int)
        for function, argtypes in (
                ("cuInit", [ctypes.c_uint]), ("cuDeviceGet", [c_intp, ctypes.c_int]), ("cuDevicePrimaryCtxRetain", [c_void_pp, ctypes.c_int]),
                ("cuCtxSetCurrent", [ctypes.c_void_p]), ("cuDeviceGetAttribute", [c_intp, ctypes.c_int, ctypes.c_int]),
                ("cuModuleLoadData", [c_void_pp, ctypes.c_void_p]), ("cuModuleGetFunction", [c_void_pp, ctypes.c_void_p, ctypes.c_char_p]),
                ("cuFuncSetAttribute", [ctypes.c_void_p, ctypes.c_int, ctypes.c_int]),
                ("cuOccupancyMaxActiveBlocksPerMultiprocessor", [c_intp, ctypes.c_void_p, ctypes.c_int, ctypes.c_size_t]),
                ("cuLaunchKernel", [ctypes.c_void_p] + [ctypes.c_uint] * 7 + [ctypes.c_void_p, c_void_pp, c_void_pp]),
                ("cuCtxSynchronize", []), ("cuGetErrorString", [ctypes.c_int, ctypes.POINTER(ctypes.c_char_p)])):
            handle = getattr(self.lib, function)
            handle.argtypes, handle.restype = argtypes, ctypes.c_int
        self.check(self.lib.cuInit(0))
        handle = ctypes.c_int()
        self.check(self.lib.cuDeviceGet(ctypes.byref(handle), device))
        self.device = handle.value
        context = ctypes.c_void_p()
        self.check(self.lib.cuDevicePrimaryCtxRetain(ctypes.byref(context), self.device))
        self.context = context
        self.current()

    def check(self, result):
        if result:
            message = ctypes.c_char_p()
            self.lib.cuGetErrorString(result, ctypes.byref(message))
            raise RuntimeError("CUDA driver error " + str(result) + ": " + (message.value or b"").decode("utf-8", "replace"))

    def current(self):
        """Makes the primary context current on this thread (each request thread needs it)."""
        self.check(self.lib.cuCtxSetCurrent(self.context))

    def attribute(self, attribute):
        value = ctypes.c_int()
        self.check(self.lib.cuDeviceGetAttribute(ctypes.byref(value), attribute, self.device))
        return value.value

    def module(self, image):
        self.current()
        buffer = ctypes.create_string_buffer(bytes(image), len(image))
        handle = ctypes.c_void_p()
        self.check(self.lib.cuModuleLoadData(ctypes.byref(handle), buffer))
        return MkModule(self, handle, buffer)

    def synchronize(self):
        self.current()
        self.check(self.lib.cuCtxSynchronize())


class MkModule:
    def __init__(self, driver, handle, image):
        self.driver, self.handle, self.image = driver, handle, image

    def function(self, name):
        handle = ctypes.c_void_p()
        self.driver.check(self.driver.lib.cuModuleGetFunction(ctypes.byref(handle), self.handle, name.encode("utf-8")))
        return MkFunction(self.driver, handle, name)


class MkFunction:
    def __init__(self, driver, handle, name):
        self.driver, self.handle, self.name = driver, handle, name

    def max_dynamic_shared(self, size):
        self.driver.check(self.driver.lib.cuFuncSetAttribute(self.handle, MkDriver.MAX_DYNAMIC_SHARED, int(size)))

    def blocks_per_multiprocessor(self, block, shared):
        count = ctypes.c_int()
        self.driver.check(self.driver.lib.cuOccupancyMaxActiveBlocksPerMultiprocessor(ctypes.byref(count), self.handle, int(block), int(shared)))
        return count.value

    def launch(self, grid, block, shared, params, stream=0):
        """Runs the kernel with `params` (a ctypes.Structure, or bytes) as its one by-value
        argument and waits for it (the GPU's own errors, an illegal address for one, surface
        here); grid and block are ints or (x, y, z)."""
        grid, block = [list(g) if isinstance(g, (tuple, list)) else [g] for g in (grid, block)]
        grid, block = (grid + [1, 1])[:3], (block + [1, 1])[:3]
        buffer = params if isinstance(params, ctypes.Structure) else ctypes.create_string_buffer(bytes(params), len(params))
        arguments = (ctypes.c_void_p * 1)(ctypes.addressof(buffer))
        self.driver.current()
        self.driver.check(self.driver.lib.cuLaunchKernel(self.handle, *grid, *block, int(shared), ctypes.c_void_p(stream or None), arguments, None))
        self.driver.check(self.driver.lib.cuCtxSynchronize())


def mk_runner_module(build_dir, facts):
    """The `yougori_runner` module a runner imports (CONTRACT): compiled kernels are cached in
    the build folder by their source and options; the driver is opened on first use."""
    module = types.ModuleType("yougori_runner")
    module.__doc__ = CONTRACT
    module.BUILD_DIR = build_dir
    holders = {}

    def driver():
        if "driver" not in holders:
            holders["driver"] = MkDriver(facts["device"])
        return holders["driver"]

    def device():
        return dict(facts)

    def compile(source, name="kernel", options=(), include_dirs=()):
        if not isinstance(source, str) or not source.strip():
            raise ValueError("compile() takes the kernel's CUDA C++ source")
        if "nvrtc" not in holders:
            holders["nvrtc"] = MkNvrtc()
        nvrtc = holders["nvrtc"]
        target, cubin = nvrtc.target(tuple(facts["computeCapability"]))
        options = [target, "-default-device", "--std=c++17"] + ["-I" + folder for folder in list(include_dirs) + nvrtc.include_dirs()] + list(options)
        key = hashlib.sha256(("\0".join(options) + "\0" + source).encode("utf-8")).hexdigest()[:16]
        path = os.path.join(build_dir, re.sub(r"[^A-Za-z0-9_.-]", "_", name) + "-" + key + (".cubin" if cubin else ".ptx"))
        if os.path.isfile(path):
            with open(path, "rb") as file:
                return file.read()
        os.makedirs(build_dir, exist_ok=True)
        image = nvrtc.compile(source, name, options)
        with open(path + ".part", "wb") as file:
            file.write(image)
        os.replace(path + ".part", path)
        return image

    def load(image):
        return driver().module(image)

    def synchronize():
        driver().synchronize()

    module.device, module.compile, module.load, module.synchronize = device, compile, load, synchronize
    return module


class MkText:
    """Turns a reply's token ids into text as they arrive, the way vLLM detokenizes: the text of
    the tokens since the last complete piece is decoded together with that piece, so a token that
    only completes a character or a word's leading space is never shown on its own. Stop strings
    cut the text where they begin, and that many characters are held back until the reply ends."""

    def __init__(self, tokenizer, stops):
        self.tokenizer, self.stops = tokenizer, [stop for stop in stops if stop]
        self.tokens, self.prefix, self.read = [], 0, 0
        self.text, self.sent, self.hold = "", 0, max((len(stop) for stop in self.stops), default=1) - 1

    def decode(self, tokens):
        return self.tokenizer.decode(tokens, skip_special_tokens=True) if tokens else ""

    def push(self, token):
        """The text to send for this token, and whether a stop string ended the reply."""
        self.tokens.append(token)
        before = self.decode(self.tokens[self.prefix:self.read])
        after = self.decode(self.tokens[self.prefix:])
        if len(after) > len(before) and not after.endswith("\ufffd"):
            self.text += after[len(before):]
            self.prefix, self.read = self.read, len(self.tokens)
        cut = min((self.text.find(stop) for stop in self.stops if stop in self.text), default=-1)
        if cut >= 0:
            self.text = self.text[:cut]
            return self.flush(), True
        return self.take(len(self.text) - self.hold), False

    def take(self, until):
        piece = self.text[self.sent:until] if until > self.sent else ""
        self.sent = max(self.sent, until)
        return piece

    def flush(self):
        return self.take(len(self.text))


class MkHost:
    """The runner, its tokenizer and the facts the model server reads from /health."""

    def __init__(self, args, key):
        self.args, self.key = args, key
        self.manifest = self.runner = self.tokenizer = None
        self.stop_ids, self.facts, self.lock = set(), {}, None
        self.started = time.perf_counter()

    def say(self, text, **more):
        """A progress line for the model's log, and the stage for the model's health."""
        print(text, flush=True)
        self.status(stage=text, **more)

    def status(self, **fields):
        try:
            with open(self.args.status + ".part", "w", encoding="utf-8") as file:
                json.dump(fields, file)
            os.replace(self.args.status + ".part", self.args.status)
        except OSError:
            pass

    def gpu(self):
        """This container's first GPU, as the runner's settings describe it."""
        try:
            import torch
        except ImportError:
            raise RuntimeError("The megakernel host needs PyTorch, which Yougori's GPU model images carry") from None
        if not torch.cuda.is_available():
            raise RuntimeError("The megakernel runner needs a CUDA GPU; none is visible in this container")
        properties = torch.cuda.get_device_properties(0)
        free, total = torch.cuda.mem_get_info(0)
        return {"device": 0, "gpu": properties.name, "computeCapability": [properties.major, properties.minor],
                "multiprocessors": properties.multi_processor_count, "totalMemoryBytes": int(total), "freeMemoryBytes": int(free)}

    def load(self):
        """Resolves, checks and loads the runner; returns nothing, raises with why it cannot."""
        args = self.args
        os.makedirs(args.build, exist_ok=True)
        folder = mk_resolve(args.runner, args.build, self.say)
        manifest = self.manifest = mk_manifest(folder)
        with open(os.path.join(args.model, "config.json"), encoding="utf-8") as file:
            config = json.loads(file.read(2 * 1024 * 1024))
        if manifest["models"] is not None and args.name.lower() not in [name.lower() for name in manifest["models"]]:
            raise RuntimeError("The runner " + manifest["name"] + " serves " + ", ".join(manifest["models"]) + ", not " + args.name)
        if manifest["architectures"] is not None and not set(config.get("architectures") or []) & set(manifest["architectures"]):
            raise RuntimeError("The runner " + manifest["name"] + " serves " + ", ".join(manifest["architectures"]) + ", not " + ", ".join(config.get("architectures") or ["this checkpoint"]))
        facts = self.gpu()
        needed = manifest["gpu"]
        if tuple(facts["computeCapability"]) < needed["computeCapability"]:
            raise RuntimeError("The runner needs compute capability " + ".".join(map(str, needed["computeCapability"])) + "; " + facts["gpu"] + " has " + ".".join(map(str, facts["computeCapability"])))
        if facts["freeMemoryBytes"] < needed["memoryGb"] * 2**30:
            raise RuntimeError("The runner needs " + format(needed["memoryGb"], "g") + " GB of free GPU memory; " + format(facts["freeMemoryBytes"] / 2**30, ".1f") + " GB is free on " + facts["gpu"])
        self.say("Loading the tokenizer...")
        from transformers import AutoTokenizer
        self.tokenizer = AutoTokenizer.from_pretrained(args.model, local_files_only=True, trust_remote_code=False)
        self.stop_ids = self.stops(args.model)
        parallel = max(1, min(manifest["parallel"], args.parallel))
        self.context = max(256, min(manifest["context"], args.context))
        slug = re.sub(r"[^A-Za-z0-9]+", "-", facts["gpu"]).strip("-").lower() + "-sm" + "".join(map(str, facts["computeCapability"]))
        build_dir = os.path.join(args.build, manifest["name"] + "-" + manifest["version"], slug, args.revision[:12])
        os.makedirs(build_dir, exist_ok=True)
        settings = {**facts, "model": args.name, "revision": args.revision, "buildDir": build_dir, "context": self.context, "parallel": parallel, "say": self.say}
        sys.modules["yougori_runner"] = mk_runner_module(build_dir, facts)
        sys.path.insert(0, folder)
        spec = importlib.util.spec_from_file_location("yougori_runner_" + re.sub(r"[^A-Za-z0-9_]", "_", manifest["name"]), os.path.join(folder, manifest["module"]))
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        if not callable(getattr(module, "load", None)):
            raise RuntimeError("The runner module " + manifest["module"] + " has no load(model_dir, settings) function")
        self.say("Loading the runner " + manifest["name"] + " " + manifest["version"] + " for " + facts["gpu"] + " (a first start builds it)...")
        began = time.perf_counter()
        self.runner = module.load(args.model, settings)
        if not callable(getattr(self.runner, "generate", None)):
            raise RuntimeError("The runner's load() returned an object without generate()")
        self.lock = threading.BoundedSemaphore(parallel)
        self.facts = {"name": manifest["name"], "version": manifest["version"], "precision": manifest["precision"], "parallel": parallel,
                      "context": self.context, "sampling": manifest["sampling"], "gpu": facts["gpu"], "loadSeconds": round(time.perf_counter() - began, 1)}

    def stops(self, model_dir):
        """The token ids that end a reply: the tokenizer's end token and generation_config's."""
        ids = {self.tokenizer.eos_token_id} if isinstance(self.tokenizer.eos_token_id, int) else set()
        try:
            with open(os.path.join(model_dir, "generation_config.json"), encoding="utf-8") as file:
                listed = json.loads(file.read(65536)).get("eos_token_id")
            ids |= {value for value in (listed if isinstance(listed, list) else [listed]) if type(value) is int}
        except (OSError, ValueError, AttributeError):
            pass
        return ids

    def prompt_tokens(self, messages, template_kwargs, template=None):
        """The conversation as the model's chat template renders it, tokenized."""
        for message in messages:
            if not isinstance(message, dict) or not isinstance(message.get("role"), str) or not isinstance(message.get("content"), str):
                raise ValueError("Messages need a role and text content")
        has_template = bool(getattr(self.tokenizer, "chat_template", None)) or template is not None
        if has_template:
            tokens = self.tokenizer.apply_chat_template(messages, tokenize=True, add_generation_prompt=True, **({"chat_template": template} if template else {}), **template_kwargs)
        else:
            text = "".join(message["role"] + ": " + message["content"] + "\n" for message in messages) + "assistant:"
            tokens = self.tokenizer(text)["input_ids"]
        if hasattr(tokens, "input_ids"):
            tokens = tokens["input_ids"]
        if hasattr(tokens, "tolist"):
            tokens = tokens.tolist()
        if tokens and isinstance(tokens[0], list):
            tokens = tokens[0]
        if not isinstance(tokens, list) or not tokens or any(type(token) is not int for token in tokens):
            raise ValueError("The chat template produced no tokens")
        return tokens

    def generate(self, tokens, max_tokens, temperature, top_p, stops, sink, cancelled):
        """Runs the runner on `tokens` and feeds `sink` the text pieces and the end: returns
        (finish reason, tokens generated, prompt seconds, generation seconds)."""
        text = MkText(self.tokenizer, stops)
        began, first, count, finish = time.perf_counter(), None, 0, "length"
        if not self.lock.acquire(timeout=300):
            raise TimeoutError("The runner is busy")
        try:
            stream = self.runner.generate(list(tokens), max_tokens, set(self.stop_ids), temperature=temperature, top_p=top_p)
            try:
                for token in stream:
                    if first is None:
                        first = time.perf_counter()
                    if type(token) is not int:
                        raise RuntimeError("The runner yielded " + type(token).__name__ + " instead of a token id")
                    count += 1
                    if token in self.stop_ids:
                        finish = "stop"
                        break
                    piece, stopped = text.push(token)
                    if piece:
                        sink(piece)
                    if stopped:
                        finish = "stop"
                        break
                    if count >= max_tokens or cancelled():
                        break
            finally:
                close = getattr(stream, "close", None)
                if close is not None:
                    close()
        finally:
            self.lock.release()
        if finish == "length" and cancelled():
            finish = "cancelled"
        rest = text.flush()
        if rest:
            sink(rest)
        ended = time.perf_counter()
        return finish, count, (first or ended) - began, ended - (first or ended)

    def answer(self, messages, max_tokens):
        """A whole reply, greedy: the check question and the speed runs."""
        pieces = []
        tokens = self.prompt_tokens(messages, {"enable_thinking": False} if getattr(self.tokenizer, "chat_template", None) and "enable_thinking" in str(self.tokenizer.chat_template) else {})
        finish, count, prompt_seconds, seconds = self.generate(tokens, max_tokens, 0.0, 1.0, [], pieces.append, lambda: False)
        return "".join(pieces), count, prompt_seconds, seconds

    def check(self):
        check = self.manifest["check"]
        if check is None:
            self.facts["check"] = None
            return
        self.say("Checking the runner's answer to: " + check["prompt"])
        text, count, _, _ = self.answer([{"role": "user", "content": check["prompt"]}], 48)
        shown = text.strip()[:200]
        if check["expect"].casefold() not in text.casefold():
            raise RuntimeError("The runner answered the check question with \"" + shown + "\" (" + str(count) + " tokens); \"" + check["expect"] + "\" was expected")
        self.facts["check"] = {"prompt": check["prompt"], "answer": shown, "passed": True}

    def measure(self):
        """One conversation's speed, after the GPU has warmed up: runs of up to 64 tokens until
        the best rate stops improving (at most 20 seconds); the best run is reported."""
        self.say("Measuring the runner's speed...")
        best, runs, since, start = 0.0, 0, time.perf_counter(), time.perf_counter()
        while time.perf_counter() - start < 20 and runs < 12:
            _, count, _, seconds = self.answer([{"role": "user", "content": MK_SPEED_PROMPT}], 64)
            runs += 1
            rate = (count - 1) / seconds if count > 1 and seconds > 0 else 0.0
            if rate > best * 1.03:
                best, since = rate, time.perf_counter()
            elif time.perf_counter() - since > 1.0 and runs >= 2:
                break
        self.facts["tokensPerSecond"] = round(best, 1)
        self.facts["measuredRuns"] = runs

    def start(self):
        self.load()
        self.check()
        self.measure()
        self.facts["startSeconds"] = round(time.perf_counter() - self.started, 1)
        self.say("The runner " + self.facts["name"] + " serves " + self.args.name + " at " + str(self.facts["tokensPerSecond"]) + " tokens/s on " + self.facts["gpu"] + ".", ready=True)

    def close(self):
        close = getattr(self.runner, "close", None)
        if close is not None:
            try:
                close()
            except Exception:
                pass


class MkHandler(http.server.BaseHTTPRequestHandler):
    """vLLM's routes as the model server uses them: /health, /tokenize and /v1/chat/completions."""
    protocol_version = "HTTP/1.1"
    host = None

    def log_message(self, *args):
        pass  # requests carry conversations; nothing of them is logged

    def reply(self, status, value):
        data = json.dumps(value).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def refuse(self, status, message):
        self.reply(status, {"error": {"message": message, "type": "invalid_request_error" if status == 400 else "server_error"}})

    def do_GET(self):
        if self.path == "/health":
            return self.reply(200, {"status": "ready", "runner": self.host.facts})
        self.refuse(404, "Unknown route")

    def do_POST(self):
        if not secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + self.host.key):
            return self.refuse(401, "Unauthorized")
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if not 0 < length <= 8 * 1024 * 1024:
                return self.refuse(400, "Request body is empty or larger than 8 MiB")
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict):
                raise ValueError("JSON object expected")
        except (ValueError, OSError):
            return self.refuse(400, "Invalid JSON request")
        try:
            if self.path == "/tokenize":
                tokens = self.host.prompt_tokens(body.get("messages") or [], self.template_kwargs(body), body.get("chat_template"))
                return self.reply(200, {"count": len(tokens), "max_model_len": self.host.context})
            if self.path == "/v1/chat/completions":
                return self.completion(body)
        except ValueError as error:
            return self.refuse(400, str(error)[:300])
        except TimeoutError as error:
            return self.refuse(503, str(error)[:300])
        except Exception as error:  # the runner's own failure: its type, never the conversation
            return self.refuse(500, "The megakernel runner failed during generation (" + type(error).__name__ + ")")
        self.refuse(404, "Unknown route")

    def template_kwargs(self, body):
        kwargs = body.get("chat_template_kwargs") or {}
        if not isinstance(kwargs, dict) or set(kwargs) - {"enable_thinking"} or any(type(value) is not bool for value in kwargs.values()):
            raise ValueError("chat_template_kwargs may set enable_thinking")
        if "enable_thinking" in kwargs and "enable_thinking" not in str(getattr(self.host.tokenizer, "chat_template", "") or "") and body.get("chat_template") is None:
            kwargs = {}
        return kwargs

    def completion(self, body):
        if body.get("tools"):
            raise ValueError("This megakernel runner has no tool calling")
        messages = body.get("messages")
        if not isinstance(messages, list) or not 1 <= len(messages) <= 128:
            raise ValueError("Provide 1-128 chat messages")
        max_tokens = body.get("max_tokens", 256)
        temperature, top_p, stream = body.get("temperature", 0.0), body.get("top_p", 1.0), body.get("stream", False)
        if type(max_tokens) is not int or not 1 <= max_tokens <= 8192 or type(stream) is not bool:
            raise ValueError("max_tokens is 1-8192 and stream a boolean")
        if type(temperature) not in (int, float) or not 0 <= temperature <= 2 or type(top_p) not in (int, float) or not 0 < top_p <= 1:
            raise ValueError("temperature is 0-2 and top_p above 0 and at most 1")
        stops = body.get("stop") or []
        stops = [stops] if isinstance(stops, str) else stops
        if not isinstance(stops, list) or len(stops) > 8 or any(not isinstance(stop, str) or len(stop) > 256 for stop in stops):
            raise ValueError("stop is a string or up to 8 strings")
        if not self.host.manifest["sampling"]:
            temperature, top_p = 0.0, 1.0
        tokens = self.host.prompt_tokens(messages, self.template_kwargs(body), body.get("chat_template"))
        if len(tokens) + max_tokens > self.host.context:
            raise ValueError("The conversation (" + str(len(tokens)) + " tokens) and the reply (" + str(max_tokens) + ") exceed this runner's context of " + str(self.host.context) + " tokens")
        ident, created, model = "chatcmpl-" + secrets.token_hex(12), int(time.time()), body.get("model") or self.host.args.name
        sock = self.connection

        def gone():
            """The relay closed its side: a caller went away (the model server does the same)."""
            try:
                return bool(select.select([sock], [], [], 0)[0]) and sock.recv(1, socket.MSG_PEEK) == b""
            except (OSError, ValueError):
                return True

        def timings(count, prompt_seconds, seconds):
            return {"prompt_n": len(tokens), "prompt_ms": round(prompt_seconds * 1000, 3), "predicted_n": count, "predicted_ms": round(seconds * 1000, 3), "cache_n": 0}

        def usage(count):
            return {"prompt_tokens": len(tokens), "completion_tokens": count, "total_tokens": len(tokens) + count}

        if not stream:
            pieces = []
            finish, count, prompt_seconds, seconds = self.host.generate(tokens, max_tokens, temperature, top_p, stops, pieces.append, gone)
            if finish == "cancelled":
                return
            return self.reply(200, {"id": ident, "object": "chat.completion", "created": created, "model": model,
                                    "choices": [{"index": 0, "message": {"role": "assistant", "content": "".join(pieces)}, "finish_reason": finish}],
                                    "usage": usage(count), "timings": timings(count, prompt_seconds, seconds)})
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        alive = [True]

        def send(event):
            try:
                self.wfile.write(b"data: " + json.dumps(event, ensure_ascii=False).encode("utf-8") + b"\n\n")
                self.wfile.flush()
            except OSError:
                alive[0] = False

        def chunk(delta, finish=None, **more):
            return {"id": ident, "object": "chat.completion.chunk", "created": created, "model": model, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}], **more}

        send(chunk({"role": "assistant", "content": ""}))
        finish, count, prompt_seconds, seconds = self.host.generate(tokens, max_tokens, temperature, top_p, stops, lambda piece: send(chunk({"content": piece})), lambda: not alive[0] or gone())
        if not alive[0] or finish == "cancelled":
            return
        send(chunk({}, finish, usage=usage(count), timings=timings(count, prompt_seconds, seconds)))
        try:
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except OSError:
            pass


class MkServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False
    request_queue_size = 64


def main(argv):
    """`serve ...` runs the host until it is ended; `contract` prints what a runner folder holds."""
    parser = argparse.ArgumentParser(prog="python3 megakernel_host.py", description="Yougori's megakernel runner host")
    actions = parser.add_subparsers(dest="action", required=True)
    serve = actions.add_parser("serve", help="load the runner and serve it on the loopback")
    serve.add_argument("--runner", required=True, help="a folder, or hf:OWNER/REPO@COMMIT")
    serve.add_argument("--model", required=True, help="the verified checkpoint folder")
    serve.add_argument("--name", required=True, help="the model's name")
    serve.add_argument("--revision", required=True)
    serve.add_argument("--port", type=int, required=True)
    serve.add_argument("--parallel", type=int, default=1)
    serve.add_argument("--context", type=int, default=4096)
    serve.add_argument("--build", required=True, help="the writable build folder (kept)")
    serve.add_argument("--status", required=True, help="where the host writes its stage and errors")
    actions.add_parser("contract", help="print the runner contract")
    args = parser.parse_args(argv)
    if args.action == "contract":
        print(CONTRACT)
        return 0
    key = os.environ.pop("YOUGORI_MEGAKERNEL_KEY", "")
    if len(key) < 32:
        print("The megakernel host needs its key in YOUGORI_MEGAKERNEL_KEY", flush=True)
        return 2
    host = MkHost(args, key)
    try:
        host.start()
    except Exception as error:
        reason = str(error)[:1000] or type(error).__name__
        host.status(error=reason)
        print("The megakernel runner could not start: " + reason, flush=True)
        host.close()
        return 1
    MkHandler.host = host
    try:
        server = MkServer(("127.0.0.1", args.port), MkHandler)
    except OSError as error:
        host.status(error="The host could not listen on port " + str(args.port) + ": " + str(error))
        host.close()
        return 1
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        host.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
