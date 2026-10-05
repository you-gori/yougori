"""Yougori's single-model CUDA chat/API workload. No remote repository code is executed."""
import http.client
import importlib.metadata
import json
import hashlib
import os
import queue
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tarfile
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = os.environ["YOUGORI_MODEL"]
MODEL_REVISION = os.environ.get("YOUGORI_MODEL_REVISION")
TOKEN = os.environ["YOUGORI_MODEL_TOKEN"]
# "gguf" serves quantized weights with llama.cpp; anything else uses Transformers safetensors.
FORMAT = os.environ.get("YOUGORI_MODEL_FORMAT", "safetensors")
STATE = {"status": "installing", "model": MODEL, "error": None}
GENERATION = threading.Lock()
REQUESTS = threading.BoundedSemaphore(8)
TOKENIZER = NETWORK = TORCH = None
MODEL_DEPENDENCIES = {"transformers": "5.18.0", "accelerate": "1.15.0", "huggingface-hub": "1.33.0"}
CACHE = os.environ.get("HF_HOME", "/root/.cache/huggingface")
# A pinned llama.cpp release built for CUDA 12.8, plus the CUDA runtime it links against.
LLAMA_BUILD = "b11425"
LLAMA_ARCHIVES = (
    ("llama-b11425-bin-ubuntu-cuda-12.8-x64.tar.gz", "ff7f7134ee3677bddf9ead356a1bc8b9cbc479d2b1e26b9e0d6753a5401e632b", 171642941),
    ("cudart-llama-b11425-bin-ubuntu-cuda-12.8-x64.tar.gz", "efe82ad6fea3820fef207e7cf73748760de3dcf604c1aaa9aa01d4c1ec2f79cb", 594377568),
)
LLAMA = {"port": 8001, "key": secrets.token_hex(24), "context": 0}
# Usage lives beside the model cache so it survives restarts. Prompts and replies are never recorded.
USAGE_PATH = os.path.join(CACHE, "yougori-usage.json")
USAGE_LOCK = threading.Lock()
USAGE_HOURS = 90 * 24
USAGE_RECENT = 100
COUNTERS = ("requests", "prompt_tokens", "completion_tokens", "errors", "rejected")
GENERATION_MAX_SECONDS = 90
STREAM_MAX_SECONDS = 300
STREAM_POLL_SECONDS = 1
STREAM_CANCEL_GRACE_SECONDS = 2


def usage_hour_valid(hour):
    return isinstance(hour, str) and 1 <= len(hour) <= 12 and hour.isascii() and hour.isdigit()


def empty_usage():
    return {"version": 1, "since": int(time.time()), "totals": dict.fromkeys(COUNTERS, 0), "sources": {"yougori": 0, "api": 0}, "hours": {}, "recent": []}


def load_usage():
    try:
        with open(USAGE_PATH, encoding="utf-8") as file:
            value = json.load(file)
        def counters_valid(counters):
            return isinstance(counters, dict) and all(type(count) is int and count >= 0 for count in counters.values())
        if (value.get("version") == 1
                and counters_valid(value.get("totals")) and counters_valid(value.get("sources"))
                and isinstance(value.get("hours"), dict) and all(usage_hour_valid(hour) and counters_valid(bucket) for hour, bucket in value["hours"].items())
                and isinstance(value.get("recent"), list)):
            return value
    except (OSError, ValueError, AttributeError):
        pass
    return empty_usage()


def save_usage():
    try:
        temporary = USAGE_PATH + ".tmp"
        with open(temporary, "w", encoding="utf-8") as file:
            json.dump(USAGE, file, separators=(",", ":"))
        os.replace(temporary, USAGE_PATH)
    except OSError:
        pass  # Usage is best effort; it never blocks generation.


USAGE = load_usage()


def record_usage(source, outcome, prompt_tokens=0, completion_tokens=0, seconds=0.0, stream=False):
    """outcome: ok, cancelled, busy, invalid, error or rejected (bad API key)."""
    now = time.time()
    failed = outcome in ("busy", "invalid", "error")
    with USAGE_LOCK:
        hour = str(int(now // 3600))
        bucket = USAGE["hours"].setdefault(hour, dict.fromkeys(COUNTERS, 0))
        for target in (USAGE["totals"], bucket):
            if outcome == "rejected":
                target["rejected"] = target.get("rejected", 0) + 1
                continue
            target["requests"] = target.get("requests", 0) + 1
            target["prompt_tokens"] = target.get("prompt_tokens", 0) + prompt_tokens
            target["completion_tokens"] = target.get("completion_tokens", 0) + completion_tokens
            target["errors"] = target.get("errors", 0) + (1 if failed else 0)
            target[source] = target.get(source, 0) + 1
        if outcome != "rejected":
            USAGE["sources"][source] = USAGE["sources"].get(source, 0) + 1
        oldest = int(now // 3600) - USAGE_HOURS
        for key in [k for k in USAGE["hours"] if not usage_hour_valid(k) or int(k) < oldest]:
            del USAGE["hours"][key]
        USAGE["recent"] = (USAGE["recent"] + [{"time": int(now), "source": source, "outcome": outcome, "prompt_tokens": prompt_tokens,
                                               "completion_tokens": completion_tokens, "seconds": round(seconds, 3), "stream": stream}])[-USAGE_RECENT:]
        save_usage()


def validate_chat(body):
    # "truncate" is a Yougori extension: drop the oldest turns instead of failing when the context is full.
    if not isinstance(body, dict) or set(body) - {"model", "messages", "max_tokens", "temperature", "stream", "truncate"}:
        raise ValueError("Use model, messages, max_tokens, temperature, stream and truncate")
    if body.get("model", MODEL) != MODEL:
        raise ValueError("This endpoint serves " + MODEL)
    stream, truncate = body.get("stream", False), body.get("truncate", False)
    if type(stream) is not bool or type(truncate) is not bool:
        raise ValueError("stream and truncate must be booleans")
    messages = body.get("messages")
    if not isinstance(messages, list) or not 1 <= len(messages) <= 128:
        raise ValueError("Provide 1–128 chat messages")
    total = 0
    for message in messages:
        if not isinstance(message, dict) or set(message) != {"role", "content"}:
            raise ValueError("Messages require role and content")
        if message["role"] not in ("system", "user", "assistant") or not isinstance(message["content"], str):
            raise ValueError("Invalid message role/content")
        total += len(message["content"])
    if total > 32768:
        raise ValueError("Conversation exceeds 32,768 characters; start a new chat")
    if not any(m["role"] == "user" for m in messages):
        raise ValueError("Include at least one user message")
    tokens = body.get("max_tokens", 256)
    temperature = body.get("temperature", 0.7)
    if type(tokens) is not int or not 1 <= tokens <= 4096:
        raise ValueError("max_tokens must be 1–4096")
    if type(temperature) not in (int, float) or not 0 <= temperature <= 2:
        raise ValueError("temperature must be 0–2")
    return messages, tokens, temperature, stream, truncate


def checkpoint():
    """Inspect metadata before downloading weights; never substitute a chat backbone for a custom head."""
    from huggingface_hub import HfApi
    from transformers import AutoConfig, AutoModelForCausalLM
    metadata = HfApi().model_info(MODEL, revision=MODEL_REVISION, files_metadata=True, timeout=30)
    files = {item.rfilename for item in metadata.siblings or []}
    if {"joint_head_config.json", "joint_head.safetensors"} <= files:
        raise RuntimeError(MODEL + " is a structured decision model with a custom prediction head. "
                           "Yougori's model runner serves text chat and cannot run this decision head. "
                           "See https://huggingface.co/" + MODEL + " for its decision API and runner.")
    revision = metadata.sha
    if (not isinstance(revision, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", revision)
            or MODEL_REVISION is not None and revision != MODEL_REVISION):
        raise RuntimeError("Model metadata did not return the requested immutable checkpoint revision")
    config = AutoConfig.from_pretrained(MODEL, revision=revision, trust_remote_code=False)
    if type(config) not in AutoModelForCausalLM._model_mapping:
        raise RuntimeError("The " + config.model_type + " architecture is not supported by Yougori's text chat runner. "
                           "Choose a causal language model with built-in Transformers support and safetensors weights.")
    return config, revision


def verify_file(path, expected):
    """True when the file matches its pinned SHA-256 (64 hex) or Git blob SHA-1 (40 hex)."""
    digest = hashlib.sha256() if len(expected) == 64 else hashlib.sha1()
    if len(expected) == 40:
        digest.update(("blob " + str(os.path.getsize(path)) + "\0").encode())
    with open(path, "rb") as file:
        while True:
            chunk = file.read(4 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return secrets.compare_digest(digest.hexdigest(), expected)


def verified_snapshot(revision):
    """Download directly into the persistent guest cache and verify pinned weight identities."""
    from huggingface_hub import HfApi, hf_hub_download, snapshot_download
    metadata = HfApi().model_info(MODEL, revision=revision, files_metadata=True, timeout=30)
    if metadata.sha != revision:
        raise RuntimeError("Model revision changed during download preflight")
    names = {item.rfilename for item in metadata.siblings or []}
    weights = sorted(name for name in names if name.endswith(".safetensors"))
    # Some repositories carry several shard sets; download only the one the index names.
    if "model.safetensors.index.json" in names:
        with open(hf_hub_download(MODEL, "model.safetensors.index.json", revision=revision), encoding="utf-8") as file:
            indexed = set(json.load(file).get("weight_map", {}).values())
        if indexed and indexed <= names:
            weights = sorted(indexed)
    root = snapshot_download(MODEL, revision=revision,
                             allow_patterns=weights + ["*.json", "*.txt", "*.model", "*.tiktoken", "*.jinja"])
    verified = 0
    for item in metadata.siblings or []:
        if item.rfilename not in weights:
            continue
        path = os.path.join(root, item.rfilename)
        if not os.path.isfile(path):
            raise RuntimeError("A pinned safetensors weight file is missing from the persistent model cache")
        lfs = getattr(item, "lfs", None)
        expected = (lfs.get("sha256") if isinstance(lfs, dict) else getattr(lfs, "sha256", None)) or getattr(item, "blob_id", None)
        if not isinstance(expected, str) or len(expected) not in (40, 64):
            raise RuntimeError("The repository did not provide a verifiable weight checksum")
        if not verify_file(path, expected):
            raise RuntimeError("A downloaded model weight failed checksum verification; do not load this checkpoint")
        verified += 1
    if not verified:
        raise RuntimeError("No verified safetensors weights were found")
    print("Verified " + str(verified) + " safetensors weight files in persistent guest storage at revision " + revision + ".", flush=True)
    return root


def install(required):
    needed = []
    for package, version in required.items():
        try:
            installed = importlib.metadata.version(package)
        except importlib.metadata.PackageNotFoundError:
            installed = None
        if installed != version:
            needed.append(package + "==" + version)
    if needed:
        print("Installing model dependencies: " + ", ".join(needed), flush=True)
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", *needed], check=True, timeout=1800)


def load_transformers():
    global TOKENIZER, NETWORK, TORCH
    required = dict(MODEL_DEPENDENCIES)
    if os.environ.get('YOUGORI_INSTALL_TORCH') == '1':
        try:
            importlib.metadata.version('torch')
        except importlib.metadata.PackageNotFoundError:
            required['torch'] = '2.8.0'
    install(required)
    STATE["status"] = "downloading"
    import torch
    from transformers import AutoModelForCausalLM, AutoTokenizer
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is unavailable. Check the GPU runtime and NVIDIA driver in Yougori.")
    TORCH = torch
    gpu_count = torch.cuda.device_count()
    print("Checking model compatibility...", flush=True)
    config, revision = checkpoint()
    verified_snapshot(revision)
    print("Downloading tokenizer for " + MODEL + "...", flush=True)
    TOKENIZER = AutoTokenizer.from_pretrained(MODEL, revision=revision, trust_remote_code=False, local_files_only=True)
    STATE["status"] = "loading"
    print("Downloading model weights and loading onto the GPU (cached files are reused)...", flush=True)
    NETWORK = AutoModelForCausalLM.from_pretrained(
        MODEL, config=config, revision=revision, trust_remote_code=False, use_safetensors=True,
        local_files_only=True,
        dtype="auto",
        device_map="balanced" if gpu_count > 1 else {"": 0},
        attn_implementation="eager",
    ).eval()
    gpu_name = torch.cuda.get_device_name(0)
    STATE.update(status="ready", gpu=f"{gpu_count} × {gpu_name}" if gpu_count > 1 else gpu_name,
                 gpuCount=gpu_count, context=context_window(), stream=True, weightsVerified=True, revision=revision, runner="transformers")


def download(url, path, size, expected):
    """Streams a pinned release archive to disk and checks its size and SHA-256."""
    digest, received = hashlib.sha256(), 0
    with urllib.request.urlopen(url, timeout=60) as response, open(path, "wb") as file:
        while True:
            chunk = response.read(4 * 1024 * 1024)
            if not chunk:
                break
            received += len(chunk)
            if received > size:
                raise RuntimeError("The llama.cpp download is larger than its pinned size")
            digest.update(chunk)
            file.write(chunk)
    if received != size or not secrets.compare_digest(digest.hexdigest(), expected):
        raise RuntimeError("The llama.cpp download failed checksum verification")


def llama_server():
    """The pinned llama.cpp server with its CUDA runtime beside it, kept in persistent model storage."""
    root = os.path.join(CACHE, "yougori-llama.cpp", LLAMA_BUILD)
    folder = os.path.join(root, "llama-" + LLAMA_BUILD)
    binary = os.path.join(folder, "llama-server")
    marker = os.path.join(root, "verified")
    if os.path.isfile(binary) and os.path.isfile(marker):
        return binary
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    for name, expected, size in LLAMA_ARCHIVES:
        print("Downloading " + name + " (" + str(size // 1048576) + " MB)...", flush=True)
        path = os.path.join(root, name)
        download("https://github.com/ggml-org/llama.cpp/releases/download/" + LLAMA_BUILD + "/" + name, path, size, expected)
        with tarfile.open(path) as archive:
            archive.extractall(root, filter="data")
        os.remove(path)
    runtime = os.path.join(root, "cudart-llama-" + LLAMA_BUILD + "-bin-ubuntu-cuda-12.8-x64")
    # The binaries load the CUDA runtime from their own folder ($ORIGIN).
    for library in os.listdir(runtime):
        shutil.move(os.path.join(runtime, library), os.path.join(folder, library))
    os.rmdir(runtime)
    os.chmod(binary, 0o755)
    with open(marker, "w", encoding="utf-8") as file:
        file.write(LLAMA_BUILD)
    return binary


def verified_gguf():
    """Downloads the pinned GGUF file(s) and checks their SHA-256 once per file version."""
    from huggingface_hub import hf_hub_download
    files = json.loads(os.environ["YOUGORI_MODEL_FILES"])
    record_path = os.path.join(CACHE, "yougori-verified.json")
    try:
        with open(record_path, encoding="utf-8") as file:
            record = json.load(file)
    except (OSError, ValueError):
        record = {}
    paths = []
    for item in files:
        print("Downloading " + item["name"] + " (" + str(item["size"] // 1048576) + " MB; cached files are reused)...", flush=True)
        path = hf_hub_download(MODEL, item["name"], revision=MODEL_REVISION)
        real = os.path.realpath(path)
        stamp = [os.path.getsize(real), int(os.path.getmtime(real)), item["sha256"]]
        if record.get(real) != stamp:
            if stamp[0] != item["size"] or not verify_file(real, item["sha256"]):
                raise RuntimeError("A downloaded GGUF file failed checksum verification; do not load this checkpoint")
            record[real] = stamp
            with open(record_path + ".tmp", "w", encoding="utf-8") as file:
                json.dump(record, file)
            os.replace(record_path + ".tmp", record_path)
        paths.append(path)
    print("Verified " + str(len(paths)) + " GGUF file(s) at revision " + str(MODEL_REVISION) + ".", flush=True)
    return paths[0]


def llama(path, body=None, timeout=30):
    """One request to the private llama.cpp server inside this container."""
    connection = http.client.HTTPConnection("127.0.0.1", LLAMA["port"], timeout=timeout)
    data = None if body is None else json.dumps(body).encode("utf-8")
    connection.request("GET" if body is None else "POST", path, data, {"Authorization": "Bearer " + LLAMA["key"], "Content-Type": "application/json"})
    return connection, connection.getresponse()


def llama_json(path, body=None, timeout=30):
    connection, response = llama(path, body, timeout)
    try:
        value = json.loads(response.read(16 * 1024 * 1024) or b"{}")
    finally:
        connection.close()
    if response.status != 200:
        raise ValueError(str((value.get("error") or {}).get("message") or "llama.cpp returned HTTP " + str(response.status))[:500])
    return value


def load_gguf():
    if not any(os.path.exists(os.path.join(folder, "libgomp.so.1")) for folder in ("/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu")):
        print("Installing the OpenMP runtime used by llama.cpp...", flush=True)
        quiet = {"stdout": subprocess.DEVNULL, "env": {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}}
        subprocess.run(["apt-get", "update"], check=True, timeout=900, **quiet)
        subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", "libgomp1"], check=True, timeout=900, **quiet)
    install({"huggingface-hub": MODEL_DEPENDENCIES["huggingface-hub"]})
    STATE["status"] = "downloading"
    binary = llama_server()
    model = verified_gguf()
    STATE["status"] = "loading"
    print("Loading " + MODEL + " onto the GPU with llama.cpp " + LLAMA_BUILD + "...", flush=True)
    environment = dict(os.environ)
    environment.pop("YOUGORI_MODEL_TOKEN", None)
    environment["LD_LIBRARY_PATH"] = os.path.dirname(binary) + (":" + environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else "")
    process = subprocess.Popen(
        [binary, "-m", model, "--host", "127.0.0.1", "--port", str(LLAMA["port"]), "--api-key", LLAMA["key"],
         "--no-webui", "-np", "1", "-c", "32768", "--jinja", "--reasoning-format", "none"],
        env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, errors="replace")
    devices, tail = [], []

    def logs():
        for line in process.stderr:
            line = line.rstrip()
            tail[:] = (tail + [line])[-20:]
            found = re.search(r"Device \d+: (.+?), compute capability", line)
            if found:
                devices.append(found.group(1))
            print(line, file=sys.stderr, flush=True)
    threading.Thread(target=logs, daemon=True).start()
    deadline = time.monotonic() + 3600
    while True:
        if process.poll() is not None:
            raise RuntimeError("llama.cpp stopped while loading the model: " + " | ".join(tail[-4:])[:1500])
        try:
            connection, response = llama("/health", timeout=5)
            response.read()
            connection.close()
            if response.status == 200:
                break
        except OSError:
            pass
        if time.monotonic() > deadline:
            raise RuntimeError("llama.cpp did not finish loading the model within an hour")
        time.sleep(2)
    settings = llama_json("/props").get("default_generation_settings") or {}
    LLAMA["context"] = int(settings.get("n_ctx") or 4096)
    if not devices:
        process.kill()
        raise RuntimeError("llama.cpp found no CUDA GPU. Check the GPU runtime and NVIDIA driver in Yougori.")

    def watch():
        process.wait()
        STATE.update(status="error", error="llama.cpp stopped unexpectedly. Restart this model. " + " | ".join(tail[-3:])[:1500])
    threading.Thread(target=watch, daemon=True).start()
    gpu = (str(len(devices)) + " × " + devices[0]) if len(devices) > 1 else devices[0]
    STATE.update(status="ready", gpu=gpu, gpuCount=len(devices), context=LLAMA["context"], stream=True, weightsVerified=True,
                 revision=MODEL_REVISION, runner="llama.cpp", quant=os.environ.get("YOUGORI_MODEL_QUANT"))


def load_model():
    try:
        print("Checking model dependencies...", flush=True)
        threading.Thread(target=report_loading, daemon=True).start()
        if FORMAT == "gguf":
            load_gguf()
        else:
            load_transformers()
        print("Model ready on " + STATE["gpu"] + ". Chat and API requests are available.", flush=True)
    except Exception as error:
        # Token values and full Python tracebacks never enter the API response.
        detail = str(error).replace(TOKEN, "[redacted]")
        if os.environ.get("HF_TOKEN"):
            detail = detail.replace(os.environ["HF_TOKEN"], "[redacted]")
        STATE.update(status="error", error=detail[:2000])
        print("Model could not load: " + detail[:2000], file=sys.stderr, flush=True)


def report_loading():
    started = time.monotonic()
    while STATE["status"] not in ("ready", "error"):
        time.sleep(15)
        if STATE["status"] not in ("ready", "error"):
            print("Model startup: " + STATE["status"] + " (" + str(int(time.monotonic() - started)) + "s elapsed)", flush=True)


def context_window():
    config = getattr(NETWORK.config, "text_config", None) or NETWORK.config
    return min(getattr(config, "max_position_embeddings", None) or 4096, 32768)


def fold_system(messages):
    """Some templates (for example Gemma) reject the system role; fold it into the first user turn."""
    system = "\n\n".join(m["content"] for m in messages if m["role"] == "system")
    rest = [dict(m) for m in messages if m["role"] != "system"]
    if not system or not rest or rest[0]["role"] != "user":
        return None
    rest[0]["content"] = system + "\n\n" + rest[0]["content"]
    return rest


def render(messages):
    if not TOKENIZER.chat_template:
        return "\n".join(m["role"] + ": " + m["content"] for m in messages) + "\nassistant:"
    try:
        return TOKENIZER.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
    except Exception:
        rest = fold_system(messages)
        if rest is None:
            raise
        return TOKENIZER.apply_chat_template(rest, tokenize=False, add_generation_prompt=True)


def prepare(messages, count, truncate):
    """Tokenize the conversation, dropping the oldest turns when truncate is set. Returns (inputs, tokens, dropped)."""
    def measure(messages):
        inputs = TOKENIZER(render(messages), return_tensors="pt")
        return inputs, inputs["input_ids"].shape[-1]
    inputs, tokens, dropped = fit(messages, count, truncate, context_window(), measure)
    return inputs.to("cuda"), tokens, dropped


def prepare_gguf(messages, count, truncate):
    """Counts prompt tokens with llama.cpp's own template and tokenizer. Returns (messages to send, tokens, dropped)."""
    def measure(messages):
        try:
            prompt = llama_json("/apply-template", {"messages": messages})["prompt"]
        except ValueError:
            folded = fold_system(messages)
            if folded is None:
                raise
            messages, prompt = folded, llama_json("/apply-template", {"messages": folded})["prompt"]
        return messages, len(llama_json("/tokenize", {"content": prompt, "add_special": True})["tokens"])
    return fit(messages, count, truncate, LLAMA["context"], measure)


def fit(messages, count, truncate, context, measure):
    """Measures the conversation, dropping the oldest turns when truncate is set. Returns (measured, tokens, dropped)."""
    dropped = 0
    if count >= context:
        raise ValueError("max_tokens must be below this model's " + str(context) + "-token context window")
    messages = list(messages)
    while True:
        measured, tokens = measure(messages)
        if tokens + count <= context:
            return measured, tokens, dropped
        turns = [i for i, m in enumerate(messages) if m["role"] != "system"]
        if not truncate or len(turns) <= 1:
            raise ValueError("Conversation exceeds this model's " + str(context) + "-token context window; shorten it or reduce max_tokens")
        # Remove the oldest turn and anything before the next user message so roles still alternate.
        del messages[turns[0]]
        dropped += 1
        while True:
            rest = [i for i, m in enumerate(messages) if m["role"] != "system"]
            if len(rest) <= 1 or messages[rest[0]]["role"] == "user":
                break
            del messages[rest[0]]
            dropped += 1


class Cancelled:
    def __init__(self, event):
        self.event = event

    def __call__(self, input_ids, scores, **kwargs):
        return TORCH.full((input_ids.shape[0],), self.event.is_set(), dtype=TORCH.bool, device=input_ids.device)


def completion_id():
    return "chatcmpl-" + secrets.token_hex(12)


class GenerationTimeout(RuntimeError):
    """Only server-created, credential-free timeout messages may reach the API."""


def non_streaming_output(inputs, kwargs, meter):
    from transformers import StoppingCriteriaList
    stop, finished, ownership, result = threading.Event(), threading.Event(), threading.Lock(), {}
    detached = False
    def work():
        try:
            with TORCH.inference_mode():
                result["output"] = NETWORK.generate(**inputs, **kwargs, stopping_criteria=StoppingCriteriaList([Cancelled(stop)]))
        except BaseException as error:
            result["error"] = error
        finally:
            with ownership:
                finished.set()
                if detached:
                    GENERATION.release()
    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    thread.join(GENERATION_MAX_SECONDS)
    timed_out = not finished.is_set()
    if timed_out:
        stop.set()
        thread.join(STREAM_CANCEL_GRACE_SECONDS)
    with ownership:
        if not finished.is_set():
            detached = True
            meter["_generation_deferred"] = True
            STATE.update(status="error", error="Model generation did not stop after cancellation. Restart this model before sending more requests.")
    if timed_out:
        raise GenerationTimeout(STATE["error"] if detached else "Model generation exceeded its time limit; shorten the conversation or choose a smaller response.")
    if "error" in result:
        raise result["error"]
    return result["output"]


def generate_gguf(body, handler, meter):
    """generate() for llama.cpp: the same validation, single-generation lock, limits and reply shape."""
    messages, count, temperature, stream, truncate = validate_chat(body)
    meter["stream"] = stream
    if not GENERATION.acquire(blocking=False):
        meter["outcome"] = "busy"
        return 429, {"error": {"message": "The GPU is busy with another response; retry shortly"}}
    try:
        messages, input_tokens, dropped = prepare_gguf(messages, count, truncate)
        meter["prompt_tokens"] = input_tokens
        extra = {"truncated_messages": dropped, "context_window": LLAMA["context"]} if truncate else {}
        limit = STREAM_MAX_SECONDS if stream else GENERATION_MAX_SECONDS
        request = {"messages": messages, "max_tokens": count, "temperature": temperature, "stream": stream, "t_max_predict_ms": limit * 1000}
        if stream:
            request["stream_options"] = {"include_usage": True}
        connection, response = llama("/v1/chat/completions", request, timeout=limit + 30)
        try:
            if response.status != 200:
                try:
                    detail = str(json.loads(response.read(65536))["error"]["message"])[:500]
                except (ValueError, KeyError, TypeError):
                    detail = "Generation failed. Check the model's compatibility and available GPU memory."
                meter["outcome"] = "invalid" if response.status == 400 else "error"
                return (400 if response.status == 400 else 500), {"error": {"message": detail}}
            if stream:
                stream_gguf(handler, response, input_tokens, count, extra, meter)
                return None
            value = json.loads(response.read(8 * 1024 * 1024))
            choice = value["choices"][0]
            generated = int((value.get("usage") or {}).get("completion_tokens") or 0)
            meter.update(outcome="ok", completion_tokens=generated)
            return 200, {"id": completion_id(), "object": "chat.completion", "created": int(time.time()), "model": MODEL,
                         "choices": [{"index": 0, "message": {"role": "assistant", "content": (choice.get("message") or {}).get("content") or ""}, "finish_reason": choice.get("finish_reason") or "stop"}],
                         "usage": {"prompt_tokens": input_tokens, "completion_tokens": generated, "total_tokens": input_tokens + generated, **extra}}
        finally:
            connection.close()
    except TimeoutError:
        meter["outcome"] = "error"
        return 504, {"error": {"message": "Model generation exceeded its time limit; shorten the conversation or choose a smaller response."}}
    finally:
        GENERATION.release()


def stream_gguf(handler, response, input_tokens, count, extra, meter):
    """Relays llama.cpp's stream as this server's own chunks; closing it stops generation."""
    ident, created = completion_id(), int(time.time())
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Connection", "close")
    handler.end_headers()

    def send(value):
        try:
            data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode("utf-8")
            handler.wfile.write(b"data: " + data + b"\n\n")
            handler.wfile.flush()
            return True
        except OSError:
            return False

    def chunk(delta, finish=None, **more):
        return {"id": ident, "object": "chat.completion.chunk", "created": created, "model": MODEL, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}], **more}

    generated, finish, failed = 0, None, None
    if not send(chunk({"role": "assistant", "content": ""})):
        meter["outcome"] = "cancelled"
        return
    try:
        while True:
            raw = response.readline(1 << 20)
            if not raw:
                break
            line = raw.strip()
            if not line.startswith(b"data:"):
                continue
            data = line[5:].strip()
            if data == b"[DONE]":
                break
            event = json.loads(data)
            if event.get("error"):
                failed = str(event["error"].get("message") or "Generation failed")[:500]
                break
            choices = event.get("choices") or []
            if choices:
                text = (choices[0].get("delta") or {}).get("content")
                if text and not send(chunk({"content": text})):
                    meter.update(outcome="cancelled", completion_tokens=generated)
                    return
                finish = choices[0].get("finish_reason") or finish
            if event.get("usage"):
                generated = int(event["usage"].get("completion_tokens") or generated)
    except (OSError, ValueError):
        failed = "The model stopped responding; try again or shorten the conversation"
    meter["completion_tokens"] = generated
    if failed:
        meter["outcome"] = "error"
        send({"error": {"message": failed}})
    else:
        meter["outcome"] = "ok"
        send(chunk({}, finish or ("length" if generated >= count else "stop"),
                   usage={"prompt_tokens": input_tokens, "completion_tokens": generated, "total_tokens": input_tokens + generated, **extra}))
    send(b"[DONE]")


def generate(body, handler, meter):
    """Returns (status, json) for a regular reply, or None after streaming server-sent events to handler.
    Fills meter with the outcome and token counts for usage tracking."""
    if FORMAT == "gguf":
        return generate_gguf(body, handler, meter)
    messages, count, temperature, stream, truncate = validate_chat(body)
    meter["stream"] = stream
    if not GENERATION.acquire(blocking=False):
        meter["outcome"] = "busy"
        return 429, {"error": {"message": "The GPU is busy with another response; retry shortly"}}
    try:
        inputs, input_tokens, dropped = prepare(messages, count, truncate)
        meter["prompt_tokens"] = input_tokens
        pad = TOKENIZER.pad_token_id if TOKENIZER.pad_token_id is not None else TOKENIZER.eos_token_id
        kwargs = {"max_new_tokens": count, "max_time": STREAM_MAX_SECONDS if stream else GENERATION_MAX_SECONDS, "do_sample": temperature > 0, "pad_token_id": pad}
        if temperature > 0:
            kwargs["temperature"] = temperature
        extra = {"truncated_messages": dropped, "context_window": context_window()} if truncate else {}
        if stream:
            stream_reply(handler, inputs, input_tokens, count, kwargs, extra, meter)
            return None
        output = non_streaming_output(inputs, kwargs, meter)
        generated = output[0, input_tokens:]
        meter.update(outcome="ok", completion_tokens=len(generated))
        return 200, {"id": completion_id(), "object": "chat.completion", "created": int(time.time()), "model": MODEL,
                     "choices": [{"index": 0, "message": {"role": "assistant", "content": TOKENIZER.decode(generated, skip_special_tokens=True)}, "finish_reason": "stop" if len(generated) < count else "length"}],
                     "usage": {"prompt_tokens": input_tokens, "completion_tokens": len(generated), "total_tokens": input_tokens + len(generated), **extra}}
    except GenerationTimeout as error:
        meter["outcome"] = "error"
        return 504, {"error": {"message": str(error)}}
    except TORCH.cuda.OutOfMemoryError:
        TORCH.cuda.empty_cache()
        meter["outcome"] = "error"
        return 507, {"error": {"message": "Not enough GPU memory. Shorten the conversation or choose a smaller model."}}
    finally:
        # A stalled GPU worker cannot safely be killed from another Python thread.
        # Its finalizer owns this lock until it actually stops; the HTTP worker can
        # return a bounded failure without allowing overlapping GPU generations.
        if not meter.pop("_generation_deferred", False):
            GENERATION.release()


def stream_reply(handler, inputs, input_tokens, count, kwargs, extra, meter):
    from transformers import StoppingCriteriaList, TextIteratorStreamer
    stop, finished, ownership, result = threading.Event(), threading.Event(), threading.Lock(), {}
    detached = False
    streamer = TextIteratorStreamer(TOKENIZER, skip_prompt=True, skip_special_tokens=True, timeout=STREAM_POLL_SECONDS)

    def work():
        try:
            with TORCH.inference_mode():
                result["output"] = NETWORK.generate(**inputs, **kwargs, streamer=streamer, stopping_criteria=StoppingCriteriaList([Cancelled(stop)]))
        except BaseException as error:
            result["error"] = error
            streamer.end()
        finally:
            with ownership:
                finished.set()
                if detached:
                    GENERATION.release()

    ident, created = completion_id(), int(time.time())
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Connection", "close")
    handler.end_headers()

    disconnected = False
    def send(value):
        nonlocal disconnected
        if disconnected:
            return
        try:
            data = value if isinstance(value, bytes) else json.dumps(value, ensure_ascii=False).encode("utf-8")
            handler.wfile.write(b"data: " + data + b"\n\n")
            handler.wfile.flush()
        except OSError:
            disconnected = True
            stop.set()  # The client disconnected; generation stops at the next token.

    def chunk(delta, finish=None, **more):
        return {"id": ident, "object": "chat.completion.chunk", "created": created, "model": MODEL, "choices": [{"index": 0, "delta": delta, "finish_reason": finish}], **more}

    thread = threading.Thread(target=work, daemon=True)
    thread.start()
    deadline, timed_out = time.monotonic() + STREAM_MAX_SECONDS, False
    send(chunk({"role": "assistant", "content": ""}))
    while not stop.is_set():
        if time.monotonic() >= deadline:
            timed_out = True
            stop.set()
            break
        try:
            text = next(streamer)
        except queue.Empty:
            if finished.is_set():
                break
            continue
        except StopIteration:
            break
        if text:
            send(chunk({"content": text}))
    thread.join(STREAM_CANCEL_GRACE_SECONDS)
    with ownership:
        if not finished.is_set():
            detached = True
            meter["_generation_deferred"] = True
            STATE.update(status="error", error="Model generation did not stop after cancellation. Restart this model before sending more requests.")
    if detached or timed_out:
        meter["outcome"] = "error"
        send({"error": {"message": STATE["error"] if detached else "Model generation exceeded its time limit; shorten the conversation or choose a smaller response."}})
        send(b"[DONE]")
        return
    error = result.get("error")
    meter["outcome"] = "error" if error is not None else "cancelled" if stop.is_set() else "ok"
    if error is None:
        meter["completion_tokens"] = result["output"].shape[-1] - input_tokens
    if error is not None:
        if isinstance(error, TORCH.cuda.OutOfMemoryError):
            TORCH.cuda.empty_cache()
            send({"error": {"message": "Not enough GPU memory. Shorten the conversation or choose a smaller model."}})
        else:
            send({"error": {"message": "Generation failed. Check the model's compatibility and available GPU memory."}})
    else:
        generated = result["output"].shape[-1] - input_tokens
        finish = "stop" if generated < count else "length"
        send(chunk({}, finish, usage={"prompt_tokens": input_tokens, "completion_tokens": generated, "total_tokens": input_tokens + generated, **extra}))
    send(b"[DONE]")


class Handler(BaseHTTPRequestHandler):
    server_version = "YougoriModel/1"
    def setup(self):
        super().setup()
        self.connection.settimeout(120)

    def log_message(self, *args):
        pass  # Never log prompts or credentials.

    def reply(self, status, value):
        data = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        value = self.headers.get("Authorization", "")
        # HTTP header values may contain Latin-1 bytes. compare_digest rejects
        # non-ASCII strings, so malformed keys must fail authentication first.
        return value.isascii() and secrets.compare_digest(value, "Bearer " + TOKEN)

    def do_GET(self):
        if not self.authorized():
            return self.reply(401, {"error": {"message": "A model API token is required"}})
        if self.path == "/health":
            return self.reply(200, dict(STATE))
        if self.path == "/v1/models":
            return self.reply(200, {"object": "list", "data": [{"id": MODEL, "object": "model", "owned_by": "local"}]})
        if self.path == "/v1/usage":
            with USAGE_LOCK:
                usage = json.loads(json.dumps(USAGE))
            return self.reply(200, usage)
        self.reply(404, {"error": {"message": "Endpoint not found"}})

    def do_POST(self):
        # The label only sorts usage into Yougori chat versus API callers; it grants nothing.
        source = "yougori" if self.headers.get("X-Yougori-Client") == "yougori" else "api"
        if not self.authorized():
            if self.path == "/v1/chat/completions":
                record_usage(source, "rejected")
            return self.reply(401, {"error": {"message": "A model API token is required"}})
        if self.path == "/v1/usage/reset":
            global USAGE
            with USAGE_LOCK:
                USAGE = empty_usage()
                save_usage()
            return self.reply(200, {"reset": True})
        if self.path != "/v1/chat/completions":
            return self.reply(404, {"error": {"message": "Endpoint not found"}})
        if STATE["status"] != "ready":
            return self.reply(503, {"error": {"message": STATE.get("error") or "Model is " + STATE["status"]}})
        started, meter = time.monotonic(), {"outcome": "error"}
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= 65536 or self.headers.get("Transfer-Encoding"):
                raise ValueError("Send a JSON body of at most 64 KiB with Content-Length")
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError("Incomplete request")
            reply = generate(json.loads(raw), self, meter)
            if reply is not None:
                self.reply(*reply)
        except (ValueError, TypeError) as error:
            meter["outcome"] = "invalid"
            self.reply(400, {"error": {"message": str(error).replace(TOKEN, "[redacted]")}})
        except Exception:
            meter["outcome"] = "error"
            self.reply(500, {"error": {"message": "Generation failed. Check the model's compatibility and available GPU memory."}})
        finally:
            record_usage(source, meter["outcome"], meter.get("prompt_tokens", 0), meter.get("completion_tokens", 0), time.monotonic() - started, meter.get("stream", False))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    def process_request(self, request, address):
        if not REQUESTS.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except Exception:
            REQUESTS.release()
            raise
    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            REQUESTS.release()


def stop(*_):
    # A usage save in progress finishes first; each save replaces the file atomically anyway.
    USAGE_LOCK.acquire(timeout=2)
    os._exit(0)


if __name__ == "__main__":
    # As the container's first process the server would ignore stop signals it does not handle,
    # making every stop wait for the runtime to kill it.
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    server = Server((os.environ.get("YOUGORI_MODEL_BIND", "0.0.0.0"), 8000), Handler)
    threading.Thread(target=load_model, daemon=True).start()
    server.serve_forever()
