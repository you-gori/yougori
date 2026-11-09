"""The llama.cpp and vLLM loaders of the model server (the engine-backends helper). Executed in the
model server namespace before a GGUF or vLLM load (`load_backends`); no caller content retained."""
import tarfile
import tempfile
import platform

# A pinned llama.cpp release built for CUDA 12.8, plus the CUDA runtime it links against.
LLAMA_BUILD = "b11425"
LLAMA_ARCHIVES = (
    ("llama-b11425-bin-ubuntu-cuda-12.8-x64.tar.gz", "ff7f7134ee3677bddf9ead356a1bc8b9cbc479d2b1e26b9e0d6753a5401e632b", 171642941),
    ("cudart-llama-b11425-bin-ubuntu-cuda-12.8-x64.tar.gz", "efe82ad6fea3820fef207e7cf73748760de3dcf604c1aaa9aa01d4c1ec2f79cb", 594377568),
)
LLAMA_CPU_ARCHIVES = (
    ("llama-b11425-bin-ubuntu-x64.tar.gz", "6a47856d08ecc4030b2fa8b8bf761c96d142d689567f69a0f75e42de430dc34c", 17682320),
)
VLLM_VERSION = "0.29.0"
# How often a load asks the backend's local /health whether it is ready. A two-second poll added up
# to two seconds to every load and wake (measured: a wake waited 0.5 s longer than llama.cpp alone).
READY_POLL_SECONDS = 0.1
KOLIBRI_WHEEL = ("aleph_alpha_inference-1.0.0-py3-none-any.whl",
    "https://files.pythonhosted.org/packages/b0/d7/1eda35b6ee0293f2a52d7a653cf5a4d54c93f21e2e359fe70a7e7b87a851/aleph_alpha_inference-1.0.0-py3-none-any.whl",
    "5a0ca118e67924f10c4f9c04dd64bef117007a17dd820233a8841b9cb8d6f211", 13392)
# A vLLM parked by sleep level 2 (vllm_park): its process and the root it serves; woken by the next load.
VLLM_PARKED = None  # (process, root, the launch asked for, the launch it runs) while parked
VLLM_ROOT = None
VLLM_ASKED = None   # the launch load_vllm asked for; the process may run a fallback launch
VLLM_PREPARED = None
# A Kolibri launch: no LoRA switches and no development routes (prefix-cache reset, sleep).
VLLM_KOLIBRI = False
# The megakernel runner serving this vLLM-format model (load_megakernel): the facts its host
# reported when it came up (name, version, speed, check), or None while vLLM serves; and why a
# runner that failed in this process is not tried again until the model restarts.
MEGAKERNEL = None
MEGAKERNEL_REFUSED = None
# How vLLM runs the model (YOUGORI_MODEL_LAUNCH, saved per model like its parallel requests):
# "compiled" captures CUDA graphs and compiles the model with torch.compile (vLLM's own defaults),
# "speculative" adds n-gram speculative decoding to that, and "eager" runs every layer eagerly,
# as every launch did before 6 November 2026. Speculative is the default: measured on 6 November
# 2026 (7B, 8 slots), code edits generated 1.8-2.7 times faster than compiled at 1-8 callers,
# and analysis replies, which rarely repeat their prompt, as fast as compiled. "megakernel" serves
# the same verified checkpoint with the owner's own decode kernel instead of vLLM: the runner
# YOUGORI_MODEL_RUNNER names (load_megakernel), started in its own process with no adapters.
VLLM_LAUNCHES = ("compiled", "speculative", "eager", "megakernel")
VLLM_DEFAULT_LAUNCH = "speculative"
# N-gram (prompt lookup) speculation drafts the next tokens by matching the latest output against
# the prompt, without a draft model, and the model checks the drafts in the same step, so replies
# are unchanged. It pays off when replies repeat their context: code edits, quotes, JSON.
NGRAM_SPECULATION = '{"method": "ngram", "num_speculative_tokens": 4, "prompt_lookup_max": 4, "prompt_lookup_min": 2}'


def vllm_launch(kolibri, limits):
    """The launch this model asked for, where its launch can take it: Kolibri's plugin keeps the
    eager launch it was validated with, LoRA adapters are not speculated, and a megakernel launch
    needs a runner to run and takes no adapters (it falls to the default launch otherwise)."""
    mode = os.environ.get("YOUGORI_MODEL_LAUNCH", VLLM_DEFAULT_LAUNCH)
    if mode not in VLLM_LAUNCHES:
        mode = VLLM_DEFAULT_LAUNCH
    if kolibri:
        return "eager"
    if mode == "megakernel" and (limits or not os.environ.get("YOUGORI_MODEL_RUNNER")):
        mode = VLLM_DEFAULT_LAUNCH
    return "compiled" if mode == "speculative" and limits else mode


def launch_arguments(mode):
    """The flags a launch mode adds to the launch list."""
    if mode == "eager":
        return ["--enforce-eager"]
    return ["--speculative-config", NGRAM_SPECULATION] if mode == "speculative" else []


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


@timed_stage("runtime_artifact")
def llama_server():
    """The pinned llama.cpp server with its CUDA runtime beside it, kept in persistent model storage."""
    cpu_only = os.environ.get("YOUGORI_MODEL_CPU") == "1"
    root = os.path.join(CACHE, "yougori-llama.cpp", LLAMA_BUILD + ("-cpu" if cpu_only else ""))
    folder = os.path.join(root, "llama-" + LLAMA_BUILD)
    binary = os.path.join(folder, "llama-server")
    marker = os.path.join(root, "verified")
    if os.path.isfile(binary) and os.path.isfile(marker):
        return binary
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(root)
    for name, expected, size in (LLAMA_CPU_ARCHIVES if cpu_only else LLAMA_ARCHIVES):
        print("Downloading " + name + " (" + str(size // 1048576) + " MB)...", flush=True)
        path = os.path.join(root, name)
        download("https://github.com/ggml-org/llama.cpp/releases/download/" + LLAMA_BUILD + "/" + name, path, size, expected)
        with tarfile.open(path) as archive:
            archive.extractall(root, filter="data")
        os.remove(path)
    runtime = os.path.join(root, "cudart-llama-" + LLAMA_BUILD + "-bin-ubuntu-cuda-12.8-x64")
    # The binaries load the CUDA runtime from their own folder ($ORIGIN).
    if not cpu_only:
        for library in os.listdir(runtime):
            shutil.move(os.path.join(runtime, library), os.path.join(folder, library))
        os.rmdir(runtime)
    os.chmod(binary, 0o755)
    with open(marker, "w", encoding="utf-8") as file:
        file.write(LLAMA_BUILD)
    return binary


@timed_stage("snapshot")
def verified_gguf():
    """Downloads the pinned GGUF file(s) and checks their SHA-256 once per file version."""
    files = json.loads(os.environ["YOUGORI_MODEL_FILES"])
    STATE["modelFile"] = files[0]["name"]
    root = registry_snapshot() if MODEL_PATH else download_snapshot(MODEL_REVISION, {item["name"]: item["size"] for item in files})
    paths = []
    for item in files:
        print("Downloading " + item["name"] + " (" + str(item["size"] // 1048576) + " MB; cached files are reused)...", flush=True)
        path = os.path.join(root, item["name"])
        if not verified_weight(path, item["sha256"], item["size"]):
            raise RuntimeError("A downloaded GGUF file failed checksum verification; do not load this checkpoint")
        paths.append(path)
    print("Verified " + str(len(paths)) + " GGUF file(s) at revision " + str(MODEL_REVISION) + ".", flush=True)
    return paths[0]


LLAMA_DEVICES = {}


def llama_cuda_devices(binary, environment):
    """Query the backend directly, once per runner process: a container's GPUs do not change while
    it runs, and a wake then skips the query's process start. Diagnostic wording is not an API."""
    if binary in LLAMA_DEVICES:
        return LLAMA_DEVICES[binary]
    try:
        result = subprocess.run([binary, "--list-devices"], env=environment, capture_output=True,
                                text=True, errors="replace", timeout=30, check=True)
    except (OSError, subprocess.SubprocessError):
        raise RuntimeError("llama.cpp could not query CUDA devices. Check the GPU runtime and NVIDIA driver in Yougori.") from None
    devices = dict(re.findall(r"^\s*(CUDA\d+):\s+(.+?)\s+\(\d+ MiB,.*\)\s*$", result.stdout, re.MULTILINE))
    if not devices:
        raise RuntimeError("llama.cpp found no CUDA GPU. Check the GPU runtime and NVIDIA driver in Yougori.")
    LLAMA_DEVICES[binary] = devices
    return devices


def llama_threads():
    """CPU threads that fit this sandbox's CPU quota. By default llama.cpp starts one
    busy-polling thread per host core; inside a two-core quota they are throttled so
    hard that a GPU runner generates a few tokens per second while the GPU sits idle."""
    try:
        return max(1, min(64, int(os.environ["YOUGORI_MODEL_CPU_THREADS"])))
    except (KeyError, ValueError):
        pass
    try:
        with open("/sys/fs/cgroup/cpu.max") as handle:
            quota, period = handle.read().split()[:2]
        if quota != "max":
            return max(1, min(64, math.ceil(int(quota) / int(period))))
    except (OSError, ValueError):
        pass
    return max(1, min(64, os.cpu_count() or 2))


def llama_cpu_options():
    threads = str(llama_threads())
    # Polling threads also consume a constrained container's CPU budget.
    options = ["--threads", threads, "--threads-batch", threads, "--poll", "0", "--poll-batch", "0"]
    return (["-ngl", "0"] if os.environ.get("YOUGORI_MODEL_CPU") == "1" else []) + options


def model_memory_events():
    """Numeric cgroup counters only; never retain prompts or native stderr."""
    try:
        with open("/sys/fs/cgroup/memory.events") as handle:
            return {key: int(value) for key, value in (line.split() for line in handle)}
    except (OSError, ValueError):
        return {}


def llama_exit_error(returncode, before, engine="llama.cpp"):
    after = model_memory_events()
    if after.get("oom_kill", 0) > before.get("oom_kill", 0):
        limit = ""
        try:
            with open("/sys/fs/cgroup/memory.max") as handle:
                limit = " (" + format(int(handle.read().strip()) / 1073741824, ".1f") + " GiB limit)"
        except (OSError, ValueError):
            pass
        return "Linux killed " + engine + " because the model container ran out of system RAM" + limit + ". Increase this model's RAM allocation in Resources, then restart it. GPU memory is a separate limit."
    return engine + " stopped unexpectedly (exit code " + str(returncode) + "). Restart this model."


def launch_serves(slots, pool=0):
    """What the running launch serves: the queue's admission, and the facts capabilities report
    (in LLAMA, which the helper shadow copies as one state)."""
    LLAMA["slots"], LLAMA["pool"] = slots, pool
    INFERENCE_QUEUE.serve(slots, pool)


def load_gguf():
    if os.environ.get("YOUGORI_NATIVE_BACKEND"):
        return load_native_gguf()
    # Until this launch reports its slots the queue admits one request (it may fall back to one).
    launch_serves(1)
    if not any(os.path.exists(os.path.join(folder, "libgomp.so.1")) for folder in ("/usr/lib/x86_64-linux-gnu", "/lib/x86_64-linux-gnu")):
        print("Installing the OpenMP runtime used by llama.cpp...", flush=True)
        quiet = {"stdout": subprocess.DEVNULL, "env": {**os.environ, "DEBIAN_FRONTEND": "noninteractive"}}
        subprocess.run(["apt-get", "update"], check=True, timeout=900, **quiet)
        subprocess.run(["apt-get", "install", "-y", "--no-install-recommends", "libgomp1"], check=True, timeout=900, **quiet)
    install({"huggingface-hub": MODEL_DEPENDENCIES["huggingface-hub"]})
    STATE["status"] = "downloading"
    binary = llama_server()
    model = verified_gguf()
    gpu_before_load()
    STATE["status"] = "loading"
    cpu_only = os.environ.get("YOUGORI_MODEL_CPU") == "1"
    print("Loading " + MODEL + " on " + ("CPU" if cpu_only else "GPU") + " with llama.cpp " + LLAMA_BUILD + "...", flush=True)
    environment = {k: v for k, v in os.environ.items() if k not in PRIVATE_ENVIRONMENT + ("HF_TOKEN",)}
    environment["LD_LIBRARY_PATH"] = os.path.dirname(binary) + (":" + environment["LD_LIBRARY_PATH"] if environment.get("LD_LIBRARY_PATH") else "")
    devices = {} if cpu_only else llama_cuda_devices(binary, environment)
    global ENGINE_PROCESS
    memory_before = model_memory_events()
    # llama.cpp refuses every slot action, the erase of the owner's KV reset included, without a
    # save path; this empty private directory enables them, and nothing is ever saved there.
    saves = tempfile.mkdtemp(prefix="yougori-llama-slots-")

    def start(parallel):
        """Starts llama-server and waits until it answers. Several slots share one 32,768-cell KV
        pool (--kv-unified; the queue reserves each request's cells in it) and keep no prompt cache
        in host RAM (--cache-ram 0: unaccounted, and llama.cpp's default exceeds small containers).
        One slot is the launch used before parallel serving (the known-good fallback), now also
        without the host-RAM prompt cache."""
        global ENGINE_PROCESS
        flags = ["-np", str(parallel), "--kv-unified"] if parallel > 1 else ["-np", "1"]
        process = ENGINE_PROCESS = subprocess.Popen(
            [binary, "-m", model, "--host", "127.0.0.1", "--port", str(LLAMA["port"]), "--api-key", LLAMA["key"],
             "--no-webui", *flags, "-c", "32768", "--cache-ram", "0", "--jinja", "--reasoning-format", "none", "--slot-save-path", saves,
             "--device", ",".join(devices) if devices else "none", *llama_cpu_options()],
            env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, errors="replace")

        def logs():
            for line in process.stderr:
                # Native diagnostics may include prompt text. Drain stderr without
                # retaining or forwarding it to workload logs or health responses.
                pass
        threading.Thread(target=logs, daemon=True).start()
        deadline = time.monotonic() + 3600
        while True:
            if process.poll() is not None:
                raise RuntimeError(llama_exit_error(process.returncode, memory_before))
            try:
                connection, response = llama("/health", timeout=5)
                response.read()
                connection.close()
                if response.status == 200:
                    return process
            except OSError:
                pass
            if time.monotonic() > deadline:
                end_engine(process)
                raise RuntimeError("llama.cpp did not finish loading the model within an hour")
            time.sleep(READY_POLL_SECONDS)

    wanted = serving_slots()
    STATE.pop("servingFallback", None)
    LLAMA["servingFallback"] = None
    with RUNNER_TIMINGS.stage("engine_start_to_ready"):
        try:
            process = start(wanted)
        except RuntimeError as error:
            if wanted == 1 or "within an hour" in str(error):
                raise
            # Once, the launch that served before; why the parallel one failed stays in health.
            # Its own exit is diagnosed against counters read after the first attempt ended.
            STATE["servingFallback"] = LLAMA["servingFallback"] = str(error)[:300]
            memory_before = model_memory_events()
            process = start(1)
    props = llama_json("/props")
    settings = props.get("default_generation_settings") or {}
    LLAMA["context"] = int(settings.get("n_ctx") or 4096)
    slots = max(1, int(props.get("total_slots") or 1))
    # Slots holding more than 32,768 cells between them share the one pool: each request reserves
    # its prompt plus max_tokens there. Slots splitting the cells cannot overflow one another.
    launch_serves(slots, LLAMA["context"] if slots > 1 and LLAMA["context"] * slots > 32768 else 0)

    def watch():
        returncode = process.wait()
        if ENGINE_PROCESS is process:
            STATE.update(status="error", error=llama_exit_error(returncode, memory_before))
    threading.Thread(target=watch, daemon=True).start()
    first_device = next(iter(devices.values()), "CPU")
    gpu = (str(len(devices)) + " × " + first_device) if len(devices) > 1 else first_device
    STATE.update(status="ready", gpu=gpu, gpuCount=len(devices), context=LLAMA["context"], stream=True, toolCalling=True, weightsVerified=True,
                 revision=MODEL_REVISION, runner="llama.cpp", quant=os.environ.get("YOUGORI_MODEL_QUANT"))


def load_native_gguf():
    """The owner verified weights before starting the private host service.

    Keep the ordinary publisher, usage, recording, tools and API authorization
    in this sandbox. No arbitrary host address or executable is accepted here.
    """
    backend = os.environ["YOUGORI_NATIVE_BACKEND"]
    key = os.environ.get("YOUGORI_NATIVE_TOKEN", "")
    port = int(os.environ.get("YOUGORI_NATIVE_PORT", "0"))
    if backend not in ("metal", "cpu") or not 0 < port < 65536 or len(key) != 64 or any(c not in string.hexdigits for c in key):
        raise RuntimeError("Invalid native model connection")
    LLAMA.update(host="10.0.2.2", port=port, key=key)
    # Validate the read-only mount too, preserving publication integrity.
    verified_gguf()
    STATE["status"] = "loading"
    with RUNNER_TIMINGS.stage("native_ready_wait"):
        deadline = time.monotonic() + 3600
        while True:
            try:
                llama_json("/health")
                break
            except (OSError, ValueError, http.client.HTTPException):
                if time.monotonic() > deadline:
                    raise RuntimeError("Native model did not become ready within an hour") from None
                time.sleep(READY_POLL_SECONDS)
    settings = llama_json("/props").get("default_generation_settings") or {}
    LLAMA["context"] = int(settings.get("n_ctx") or 4096)
    STATE.update(status="ready", gpu="Apple Metal" if backend == "metal" else "Native Mac CPU",
                 gpuCount=int(backend == "metal"), backend=backend, native=True,
                 unifiedMemory=backend == "metal", context=LLAMA["context"], stream=True,
                 toolCalling=True, weightsVerified=True, revision=MODEL_REVISION,
                 runner="llama.cpp", quant=os.environ.get("YOUGORI_MODEL_QUANT"))


def vllm_hardware(config, weight_bytes, cuda):
    """Every MoE expert stays resident. Check before downloading weights; no implicit CPU offload."""
    count = cuda.device_count() if cuda.is_available() else 0
    required = (weight_bytes / 1073741824 + 2) / 0.90
    if not count or any(cuda.get_device_capability(i) < (7, 5) for i in range(count)):
        raise RuntimeError("vLLM needs CUDA GPUs with compute capability 7.5 or newer")
    available = count * min(cuda.mem_get_info(i)[0] for i in range(count)) / 1073741824
    if not weight_bytes or available < required:
        raise RuntimeError("This checkpoint needs approximately {:.0f} GB of free GPU memory; {:.1f} GB is available. All MoE experts must fit, including inactive experts. No model weights were downloaded.".format(required, available))
    heads = int(config.get("num_attention_heads") or 1)
    kv_heads = int(config.get("num_key_value_heads") or heads)
    if heads % count or (kv_heads % count and count % kv_heads):
        raise RuntimeError("This model's attention heads cannot be split across the available GPU count")
    return count


def kolibri_plugin():
    """Install only the reviewed, checksum-pinned wheel; keep the image's torch/vLLM unchanged."""
    try:
        if importlib.metadata.version("aleph-alpha-inference") == "1.0.0": return
    except importlib.metadata.PackageNotFoundError:
        pass
    name, url, sha, size = KOLIBRI_WHEEL
    folder = os.path.join(CACHE, "yougori-vllm-plugin")
    os.makedirs(folder, exist_ok=True)
    wheel = os.path.join(folder, name)
    download(url, wheel, size, sha)
    environment = {k:v for k,v in os.environ.items() if k not in PRIVATE_ENVIRONMENT + ("HF_TOKEN",)}
    subprocess.run([sys.executable, "-m", "pip", "install", "--no-deps", "--no-index", wheel],
                   env=environment, check=True, timeout=120, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def vllm_source_key():
    return (MODEL, MODEL_REVISION, os.path.realpath(CACHE), VLLM_VERSION)


def remember_vllm_source(metadata, root, config, weight_bytes):
    """A process-local memo, never a persisted manifest or independent catalog."""
    global VLLM_PREPARED
    VLLM_PREPARED = None
    if os.environ.get("YOUGORI_VLLM_SOURCE_REUSE", "1") == "0":
        return
    pinned = pinned_source_files(metadata, root)
    if pinned is None:
        return
    names, files = pinned
    # Verify all loader inputs, including configuration/tokenizers/indexes, not
    # only weights. Existing hash/stamp handling avoids rehashing unchanged files.
    for name, digest, size in files:
        if not verified_weight(os.path.join(root, name), digest, size):
            raise RuntimeError("A pinned model source file failed verification; refusing to start vLLM")
    with open(os.path.join(root, "config.json"), encoding="utf-8") as file:
        encoded = file.read(2 * 1024 * 1024 + 1)
    if len(encoded) > 2 * 1024 * 1024 or json.loads(encoded) != config:
        raise RuntimeError("Model configuration changed during preparation; refusing to start vLLM")
    if source_inventory(root) != names:
        raise RuntimeError("Model source membership changed during preparation")
    VLLM_PREPARED = (vllm_source_key(), os.path.abspath(root), tuple(files),
                     json.dumps(config, sort_keys=True), weight_bytes)


@timed_stage("snapshot")
def prepared_vllm_source():
    global VLLM_PREPARED
    saved = VLLM_PREPARED
    if os.environ.get("YOUGORI_VLLM_SOURCE_REUSE", "1") == "0" or saved is None:
        return None
    key, root, files, config, weight_bytes = saved
    if key != vllm_source_key():
        VLLM_PREPARED = None
        return None
    if not unchanged_source(root, tuple(item[0] for item in files), files):
        VLLM_PREPARED = None
        raise RuntimeError("Prepared model source changed or is incomplete. Restore the pinned files before reloading.")
    return root, json.loads(config), weight_bytes


def local_vllm_source():
    """vLLM's inputs from the verified local mount (YOUGORI_MODEL_PATH), or the copy imported from it.

    verified_snapshot() runs the bundled verifier (registry_snapshot) against YOUGORI_LOCAL_MANIFEST
    or the registry manifest before anything here is read, so config.json and the weight set are
    taken only from files that manifest names. Nothing is downloaded and nothing is written into
    the mount; the Hugging Face API is never consulted.
    """
    root = verified_snapshot(MODEL_REVISION)
    names = set(globals().get("MODEL_SNAPSHOT_FILES") or ())
    if "config.json" not in names:
        raise RuntimeError("The verified local checkpoint manifest does not include config.json")
    if {"joint_head_config.json", "joint_head.safetensors"} <= names:
        raise RuntimeError("A custom prediction head needs a reviewed decision adapter")
    weights = sorted(name for name in names if name.endswith(".safetensors"))
    if not weights:
        raise RuntimeError("No verified safetensors weights were found")
    with open(os.path.join(root, "config.json"), encoding="utf-8") as file:
        encoded = file.read(2 * 1024 * 1024 + 1)
    try:
        config = json.loads(encoded) if len(encoded) <= 2 * 1024 * 1024 else None
    except ValueError:
        config = None
    if not isinstance(config, dict):
        raise RuntimeError("Invalid local model configuration")
    size = sum(os.stat(os.path.join(root, name)).st_size for name in weights)
    return root, config, size


VLLM_LOAD_TAIL_LINES = 40
VLLM_LOAD_LINE_BYTES = 400


def vllm_load_output(stream, tail, loading):
    """Drain vLLM's combined output so the pipe never blocks it. While `loading` is set (no
    request exists yet) keep the last lines in `tail`; afterwards discard every line, since
    serving diagnostics can contain caller content."""
    try:
        for raw in iter(stream.readline, b""):
            if loading.is_set():
                tail.append(raw[:VLLM_LOAD_LINE_BYTES].decode("utf-8", "replace").rstrip())
    except (OSError, ValueError):
        pass


def report_vllm_load_failure(reader, tail, loading):
    """Print the bounded tail vLLM wrote before its load failed, with the API key redacted."""
    reader.join(timeout=2)
    loading.clear()
    key = LLAMA.get("key") or ""
    lines = [line.replace(key, "[redacted]") if key else line for line in list(tail)]
    tail.clear()
    if lines:
        print("vLLM output before the load failed (last " + str(len(lines)) + " lines):\n" + "\n".join(lines), flush=True)


def vllm_park():
    """Parks a serving native vLLM by sleep level 2 instead of ending it (the scheduler's unload):
    weights and KV cache leave the GPU, the process stays. False when it cannot, changing nothing."""
    global VLLM_PARKED
    process = ENGINE_PROCESS
    if FORMAT != "vllm" or MEGAKERNEL is not None or VLLM_ROOT is None or process is None or process.poll() is not None or VLLM_PARKED is not None:
        return False
    try:
        llama_json("/sleep?level=2", {}, timeout=120)
    except (OSError, ValueError):
        return False
    RUNNER_TIMINGS.invalidate_load()
    VLLM_PARKED = (process, VLLM_ROOT, VLLM_ASKED, STATE.get("launch"))
    # The runner's word, in its health and its unload answer: the engine probes the GPU around
    # it for CORE-01 evidence of the mode (sleep-mode weight discarding).
    STATE["parked"] = "sleep"
    return True


def vllm_wake():
    """Wakes a parked vLLM and reloads its weights from the files this load just verified, each
    step timed as its own stage (G01: the retained-process wake)."""
    try:
        with RUNNER_TIMINGS.stage("engine_wake"):
            llama_json("/wake_up", {}, timeout=600)
        with RUNNER_TIMINGS.stage("weight_reload"):
            llama_json("/collective_rpc", {"method": "reload_weights"}, timeout=1800)
        return True
    except (OSError, ValueError):
        return False


# vLLM's own per-request histograms (vllm.v1.metrics): their sums grow by exactly one request's
# values only when that request alone finished during its window; when sequences overlap, the
# growth mixes requests and is not recorded (backend_observation_finish).
VLLM_HISTOGRAMS = ("vllm:request_queue_time_seconds", "vllm:request_prefill_time_seconds",
                   "vllm:request_decode_time_seconds", "vllm:request_prompt_tokens",
                   "vllm:request_prefill_kv_computed_tokens", "vllm:request_generation_tokens")


def vllm_metrics():
    """The sums and counts of VLLM_HISTOGRAMS from vLLM's /metrics (this container's loopback),
    or None when they cannot be read."""
    try:
        connection, response = llama("/metrics", timeout=5)
        try:
            text = response.read(4 * 1024 * 1024).decode("utf-8", "replace")
        finally:
            connection.close()
    except (OSError, http.client.HTTPException):
        return None
    if response.status != 200:
        return None
    values = {}
    for line in text.splitlines():
        name = line.split("{", 1)[0].split(" ", 1)[0]
        if name.endswith(("_sum", "_count")) and name.rsplit("_", 1)[0] in VLLM_HISTOGRAMS:
            try:
                values[name] = values.get(name, 0.0) + float(line.rsplit(" ", 1)[1])
            except (ValueError, IndexError):
                return None
    return values


def backend_observation_start():
    """Before a measured request: vLLM's histograms now; llama.cpp's reply and the megakernel
    host's carry their own."""
    return vllm_metrics() if FORMAT == "vllm" and MEGAKERNEL is None else {}


def backend_observation_finish(before, timings=None):
    """Records the backend's clocks for the request just answered (RUNNER_TIMINGS.backend):
    the growth of vLLM's histograms when each counted exactly this one request (queue: from the
    request's arrival in the engine to its first scheduling; prefill: from there to the first
    token; decode: from the first to the last token), or llama.cpp's timings (prompt
    processing and generation; it reports no queue of its own; the megakernel host reports the
    same shape). Nothing when the backend said nothing exact."""
    if FORMAT == "vllm" and MEGAKERNEL is None:
        after = vllm_metrics() if before is not None else None
        if after is None:
            return
        delta = {name: after.get(name, 0.0) - before.get(name, 0.0) for name in after}
        if any(round(delta.get(name + "_count", 0.0)) != 1 for name in VLLM_HISTOGRAMS):
            return
        prompt = round(delta["vllm:request_prompt_tokens_sum"])
        computed = round(delta["vllm:request_prefill_kv_computed_tokens_sum"])
        RUNNER_TIMINGS.backend({"version": 1, "source": "vllm-metrics-delta", "promptTokens": prompt,
                                "cachedTokens": max(0, prompt - computed),
                                "queueMs": round(max(0.0, delta["vllm:request_queue_time_seconds_sum"]) * 1000, 6),
                                "prefillMs": round(max(0.0, delta["vllm:request_prefill_time_seconds_sum"]) * 1000, 6),
                                "decodeMs": round(max(0.0, delta["vllm:request_decode_time_seconds_sum"]) * 1000, 6),
                                "outputTokens": round(delta["vllm:request_generation_tokens_sum"])})
    elif isinstance(timings, dict):
        try:
            cached, processed = int(timings.get("cache_n") or 0), int(timings["prompt_n"])
            RUNNER_TIMINGS.backend({"version": 1, "source": "megakernel-timings" if MEGAKERNEL is not None else "llama-cpp-timings", "promptTokens": processed + cached,
                                    "cachedTokens": cached, "queueMs": None,
                                    "prefillMs": round(float(timings["prompt_ms"]), 6),
                                    "decodeMs": round(float(timings["predicted_ms"]), 6),
                                    "outputTokens": int(timings["predicted_n"])})
        except (KeyError, TypeError, ValueError):
            return


# G06: unmerged LoRA adapters on a vLLM launch the owner enabled them for
# (YOUGORI_VLLM_ADAPTERS = "<slots>:<largest rank>"), loaded at runtime through vLLM's own
# routes. Each is a pinned Hugging Face revision whose weights are verified before vLLM reads
# them, and whose declared base must have exactly the served weights (by digest, never by
# name). vLLM keys its prefix cache by adapter, so KV is never reused across adapters.
ADAPTERS = {}
ADAPTER_MODULES = frozenset(("q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"))


def adapter_limits():
    """The adapter slots and the largest rank this vLLM launch enables, or None (a Kolibri launch
    enables none whatever the owner saved, and a megakernel launch serves none)."""
    found = re.fullmatch(r"([1-8]):(8|16|32|64)", os.environ.get("YOUGORI_VLLM_ADAPTERS", ""))
    return (int(found[1]), int(found[2])) if found and FORMAT == "vllm" and not VLLM_KOLIBRI and MEGAKERNEL is None else None


def vllm_model(body):
    """The name vLLM serves a request under: an attached adapter it names, else the model."""
    return body["model"] if body.get("model") in ADAPTERS else MODEL


def hub_weights(repo, revision):
    """{file: sha256} of a Hugging Face revision's safetensors, from its metadata, with the
    commit it resolved to."""
    from huggingface_hub import HfApi
    info = HfApi().model_info(repo, revision=revision, files_metadata=True, timeout=30)
    weights = {}
    for item in info.siblings or []:
        lfs = getattr(item, "lfs", None)
        digest = lfs.get("sha256") if isinstance(lfs, dict) else getattr(lfs, "sha256", None)
        if item.rfilename.endswith(".safetensors") and isinstance(digest, str):
            weights[item.rfilename] = (digest.lower(), getattr(item, "size", None))
    return weights, info.sha


def served_weights():
    """{file: sha256} of the safetensors this load verified: the local manifest, or the pinned
    Hugging Face revision's metadata."""
    if MODEL_PATH:
        files = (json.loads(os.environ.get("YOUGORI_LOCAL_MANIFEST") or "{}").get("files")) or []
        return {item["name"]: item["sha256"].lower() for item in files if str(item.get("name", "")).endswith(".safetensors")}
    if VLLM_PREPARED is not None:
        return {name: digest for name, digest, _ in VLLM_PREPARED[2] if name.endswith(".safetensors")}
    return {name: digest for name, (digest, _) in hub_weights(MODEL, MODEL_REVISION)[0].items()}


def vllm_adapter(action, name, path=None):
    """vLLM's own runtime adapter route: load or unload."""
    connection, response = llama("/v1/" + action + "_lora_adapter", {"lora_name": name, **({"lora_path": path} if path else {})}, timeout=300)
    try:
        detail = response.read(65536).decode("utf-8", "replace")
    finally:
        connection.close()
    if response.status != 200:
        raise BackendRefusal("vLLM did not " + action + " the adapter " + name + ": " + detail[:300])


def adapter_attach(name, repo, revision):
    """Verifies and loads one adapter; idempotent for the same pinned adapter under its name."""
    limits = adapter_limits()
    if limits is None:
        raise BackendRefusal("This Kolibri launch takes no LoRA adapters." if FORMAT == "vllm" and VLLM_KOLIBRI
                             else "This megakernel launch serves no LoRA adapters; vLLM launches do." if FORMAT == "vllm" and MEGAKERNEL is not None
                             else "This model's launch serves no adapters. Enable them (model_adapters --action enable) and restart the model."
                             if FORMAT == "vllm" else "llama.cpp loads LoRA adapters only at start, from GGUF files; this launch loads none and attaches none at runtime.")
    if revision is None and isinstance(repo, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", repo):
        revision = hub_weights(repo, None)[1]  # Pinned to the commit its default branch names now.
    if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", name) or name == MODEL
            or not isinstance(repo, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", repo)
            or not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{40}", revision)):
        raise ValueError("An adapter needs a name, a Hugging Face repository and its 40-hex revision")
    attached = ADAPTERS.get(name)
    if attached is not None:
        if (attached["repo"], attached["revision"]) == (repo, revision):
            return attached
        raise BackendRefusal("An adapter named " + name + " is attached already; detach it first.")
    if len(ADAPTERS) >= limits[0]:
        raise BackendRefusal("All " + str(limits[0]) + " adapter slots of this launch are in use; detach one first.")
    from huggingface_hub import hf_hub_download
    weights, pinned = hub_weights(repo, revision)
    if pinned != revision or "adapter_model.safetensors" not in weights:
        raise BackendRefusal("The adapter revision is not a PEFT adapter with adapter_model.safetensors.")
    config_path = hf_hub_download(repo, "adapter_config.json", revision=revision)
    model_path = hf_hub_download(repo, "adapter_model.safetensors", revision=revision)
    digest, size = weights["adapter_model.safetensors"]
    # verify_file, not the model's startup verifier: an adapter's check changes no runner state.
    try:
        sized = size is None or os.path.getsize(model_path) == size
    except OSError:
        sized = False
    if not sized or not verify_file(model_path, digest):
        raise BackendRefusal("The adapter's weights failed checksum verification; nothing was loaded.")
    with open(config_path, encoding="utf-8") as file:
        config = json.loads(file.read(256 * 1024))
    rank, modules = config.get("r"), config.get("target_modules")
    if config.get("peft_type") != "LORA" or config.get("use_dora") or config.get("modules_to_save"):
        raise BackendRefusal("Only plain LoRA adapters are served (no DoRA, no modules saved whole).")
    if type(rank) is not int or not 1 <= rank <= limits[1]:
        raise BackendRefusal("The adapter's rank " + str(rank) + " is above this launch's largest rank " + str(limits[1]) + ".")
    if not isinstance(modules, list) or not modules or not set(modules) <= ADAPTER_MODULES:
        raise BackendRefusal("The adapter targets layers other than the attention and MLP projections vLLM adapts.")
    base = config.get("base_model_name_or_path")
    if not isinstance(base, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*", base):
        raise BackendRefusal("The adapter names no Hugging Face base model.")
    base_weights = {file: value[0] for file, value in hub_weights(base, config.get("revision") or None)[0].items()}
    # The served weights are the shard set the load verified (a repository with several sets,
    # such as a consolidated file beside indexed shards, serves only the indexed one): each must
    # be the base repository's own file, byte for byte; files the load did not serve are not compared.
    served = served_weights()
    if not served or any(base_weights.get(file) != digest for file, digest in served.items()):
        raise BackendRefusal("The adapter was made for " + base + ", whose weights are not the served model's.")
    vllm_adapter("load", name, os.path.dirname(model_path))
    ADAPTERS[name] = {"name": name, "repo": repo, "revision": revision, "rank": rank, "modules": sorted(modules),
                      "sha256": digest, "path": os.path.dirname(model_path)}
    return ADAPTERS[name]


def adapter_detach(name):
    if name not in ADAPTERS:
        raise BackendRefusal("No adapter named " + str(name) + " is attached.")
    vllm_adapter("unload", name)
    return ADAPTERS.pop(name)


def reattach_adapters():
    """After a wake or a start, the adapters this runner serves are loaded into vLLM again (its
    adapter slots do not survive a sleep that discarded the weights); after a restart, the ones
    the workload names (YOUGORI_ADAPTERS). One that cannot be is dropped with why."""
    if adapter_limits() is None:
        return
    wanted = list(ADAPTERS.values()) or json.loads(os.environ.get("YOUGORI_ADAPTERS") or "[]")
    errors = {}
    for adapter in wanted:
        if not isinstance(adapter, dict):
            continue
        name = adapter.get("name")
        try:
            if name in ADAPTERS:
                try:
                    vllm_adapter("unload", name)
                except BackendRefusal:
                    pass
                vllm_adapter("load", name, ADAPTERS[name]["path"])
            else:
                adapter_attach(name, adapter.get("repo"), adapter.get("revision"))
        except (BackendRefusal, ValueError, OSError, RuntimeError) as error:
            ADAPTERS.pop(name, None)
            errors[str(name)[:64]] = str(error)[:300]
    if errors:
        STATE["adapterErrors"] = errors


def kv_check(body):
    """A KV request answered without the backend: refused (any action but reset, the native
    service, Kolibri) or a no-op while nothing is loaded. None for a reset that erases slots,
    which the model server runs while no request is admitted (InferenceQueue.exclusive)."""
    if body.get("action") != "reset":
        raise BackendRefusal("No pinned backend grows or trims its KV cache in increments; the only KV operation is reset.")
    if os.environ.get("YOUGORI_NATIVE_BACKEND"):
        raise BackendRefusal("The native llama.cpp service keeps its own cache; it is not reset from here.")
    if FORMAT == "vllm" and VLLM_KOLIBRI:
        raise BackendRefusal("This vLLM launch (Kolibri) has no prefix-cache reset route.")
    if STATE.get("status") != "ready" or STATE.get("parked"):
        return {"reset": True, "slots": 0, "detail": "The model holds no KV while it is unloaded or parked."}
    if FORMAT == "vllm" and MEGAKERNEL is not None:
        return {"reset": True, "slots": 0, "detail": "The megakernel runner reads each request's whole conversation and keeps no KV between requests."}
    return None


def kv_reset():
    """Drops the backend's reusable KV: vLLM's prefix cache, every llama.cpp slot. Checked again
    here: the model may have parked while admitted requests finished."""
    answer = kv_check({"action": "reset"})
    if answer is not None:
        return answer
    paths = ["/reset_prefix_cache"] if FORMAT == "vllm" else ["/slots/" + str(slot) + "?action=erase" for slot in range(LLAMA.get("slots", 1))]
    for path in paths:
        connection, response = llama(path, {}, timeout=60)
        try:
            response.read(65536)
        finally:
            connection.close()
        if response.status != 200:
            raise BackendRefusal("The backend did not reset its KV cache (HTTP " + str(response.status) + ").")
    return {"reset": True, **({"slots": len(paths)} if FORMAT == "gguf" else {})}


def backend_command(route, body):
    """The owner's adapter and KV operations (/v1/yougori/adapters, /v1/yougori/kv)."""
    action = body.get("action")
    if route == "kv":
        return kv_check(body) or kv_reset()
    if action == "attach":
        return {"attached": adapter_attach(body.get("name"), body.get("repo"), body.get("revision"))}
    if action == "detach":
        return {"detached": adapter_detach(body.get("name"))}
    if action == "list":
        return {"adapters": list(ADAPTERS.values())}
    raise ValueError("Unknown adapter action")


def backend_capabilities():
    """What this launch does and does not support (G06), as the launch's own facts."""
    slots, fallback = LLAMA.get("slots") or 1, LLAMA.get("servingFallback")
    concurrency = {"supported": slots > 1, "slots": slots, "detail": (str(slots) + " requests generate together, batched by the backend; more wait in order (requestQueue). A reply generated beside others can differ from the same request generated alone (batched arithmetic); parallel 1 generates one at a time."
                   if slots > 1 else "One request generates at a time; more wait in order (requestQueue).") + (" Parallel serving failed to start, so the one-slot launch serves: " + fallback if fallback else "")}
    native = bool(os.environ.get("YOUGORI_NATIVE_BACKEND"))
    if FORMAT == "gguf":
        pool = LLAMA.get("pool") or 0
        return {
            "kvGrowth": {"supported": False, "detail": "llama.cpp allocates the context's KV cache when the model loads (-c 32768); it does not grow in increments."},
            "adapters": {"supported": False, "detail": "llama.cpp loads LoRA adapters only at start, from GGUF files; this launch loads none and attaches none at runtime."},
            "kvReuse": {"supported": True, "reset": not native, "detail": ("llama.cpp's " + str(slots) + " slots share one " + str(pool) + "-token KV pool; each reuses its cached prompt prefix while it stays there" if pool else "llama.cpp reuses the cached prompt prefix of each slot")
                        + ". The cache serves every caller of this model and is dropped when the model unloads" + ("; the native service's cache is not reset from here." if native else "; the owner can erase every slot (model_adapters --action kv-reset).")},
            "concurrency": concurrency,
            "structuredOutput": structured_output(),
        }
    if MEGAKERNEL is not None:
        return {
            "kvGrowth": {"supported": False, "detail": "The megakernel runner keeps one conversation's KV per request; nothing grows in increments."},
            "adapters": {"supported": False, "configurable": False, "detail": "This megakernel launch serves no LoRA adapters; vLLM launches do."},
            "kvReuse": {"supported": False, "reset": False, "detail": "The megakernel runner reads each request's whole conversation and keeps no KV between requests; a reset changes nothing."},
            "concurrency": concurrency,
            "structuredOutput": structured_output(),
            "megakernel": MEGAKERNEL,
        }
    limits = adapter_limits()
    attached = ", ".join(sorted(ADAPTERS)) or "none"
    adapters = ({"supported": True, "configurable": True, "detail": "LoRA adapters attach at runtime: " + str(limits[0]) + " slot(s), rank up to " + str(limits[1]) + "; a request names one as its model; attached: " + attached + ".",
                 "maxAdapters": limits[0], "maxRank": limits[1], "attached": [{key: a[key] for key in ("name", "repo", "revision", "rank")} for a in ADAPTERS.values()]}
                if limits else {"supported": False, "configurable": not VLLM_KOLIBRI, "detail": "This Kolibri launch takes no LoRA adapters." if VLLM_KOLIBRI else "This vLLM launch does not enable LoRA adapters; the owner enables them (model_adapters --action enable) and restarts the model."})
    return {
        "kvGrowth": {"supported": False, "detail": "vLLM takes its KV blocks when it starts (--gpu-memory-utilization 0.90); this launch does not grow or trim them."},
        "adapters": adapters,
        "kvReuse": {"supported": True, "reset": not VLLM_KOLIBRI, "detail": "vLLM reuses the KV of a shared prompt prefix, keyed by adapter. The cache serves every caller of this model and is dropped when the model parks or unloads"
                    + ("; this Kolibri launch has no reset route." if VLLM_KOLIBRI else "; the owner can reset it (model_adapters --action kv-reset).")},
        "concurrency": concurrency,
        "structuredOutput": structured_output(),
    }


def end_engine(process):
    """Ends an engine process this runner owns; forgotten first, so its watcher reports nothing."""
    global ENGINE_PROCESS
    if ENGINE_PROCESS is process:
        ENGINE_PROCESS = None
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def vllm_registry(config):
    """Built-in registry only. vLLM's Transformers/remote-code fallback is never enabled."""
    from vllm.model_executor.models.registry import ModelRegistry
    if not set(config.get("architectures", [])) & set(ModelRegistry.get_supported_archs()):
        raise RuntimeError("No native implementation exists in the pinned vLLM runtime")


def vllm_after_megakernel(config, size, cuda):
    """vLLM's own checks, made when it serves a model whose megakernel runner could not."""
    vllm_registry(config)
    return vllm_hardware(config, size, cuda)


# The megakernel runner host (model_runner/megakernel_host.py), carried by vLLM runners beside
# these backends (YOUGORI_MEGAKERNEL_SOURCE) and run as its own process by load_megakernel. The
# injected source must match the digest these backends ship; a runner started from a source tree
# reads the file beside them.
MEGAKERNEL_HOST_SHA256 = "c540a7e2a75553fdadfa890fd70e9c6c2ef83eea47be9b522ec256d97c65ad9c"


def megakernel_host_source():
    injected = globals().get("__YOUGORI_MEGAKERNEL_SOURCE__") or os.environ.get("YOUGORI_MEGAKERNEL_SOURCE")
    beside = os.path.join(os.path.dirname(os.path.abspath(globals().get("__file__") or os.sep)), "model_runner", "megakernel_host.py")
    if not injected and "__file__" in globals() and os.path.isfile(beside):
        with open(beside, "rb") as handle:
            return handle.read()
    if not injected:
        raise RuntimeError("This build is missing the megakernel host. Update Yougori.")
    source = zlib.decompress(base64.b64decode(injected))
    if hashlib.sha256(source).hexdigest() != MEGAKERNEL_HOST_SHA256:
        raise RuntimeError("Bundled megakernel host failed integrity verification")
    return source


def megakernel_status(folder):
    """What the host last wrote about itself (megakernel_host.py: stage, error), or {}."""
    try:
        with open(os.path.join(folder, "status.json"), encoding="utf-8") as file:
            status = json.loads(file.read(65536))
        return status if isinstance(status, dict) else {}
    except (OSError, ValueError):
        return {}


def load_megakernel(root, config, revision):
    """Starts the megakernel host for the runner YOUGORI_MODEL_RUNNER names (a folder bound at
    /yougori-runner, or hf:OWNER/REPO@REVISION) on the verified checkpoint at `root`, in its own
    process without this runner's credentials, and waits until it serves: the host resolves the
    runner, builds it for this GPU on first start (cached in the model's volume), answers a check
    question, measures its speed and then listens on this container's loopback like vLLM would.
    True when it serves (STATE ready, MEGAKERNEL its facts); False with why in health (megakernel.
    refused, and MEGAKERNEL_REFUSED for this process) when it cannot, so vLLM serves instead."""
    global ENGINE_PROCESS, MEGAKERNEL, MEGAKERNEL_REFUSED
    import torch
    reference = os.environ.get("YOUGORI_MODEL_RUNNER", "")
    folder = os.path.join(CACHE, "yougori-megakernel")
    os.makedirs(folder, exist_ok=True)
    host = os.path.join(folder, "megakernel_host.py")
    with open(host, "wb") as file:
        file.write(megakernel_host_source())
    try:
        os.remove(os.path.join(folder, "status.json"))
    except OSError:
        pass
    parallel = serving_slots()
    environment = {k: v for k, v in os.environ.items() if k not in PRIVATE_ENVIRONMENT + ("HF_TOKEN",)}
    environment.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", YOUGORI_MEGAKERNEL_KEY=LLAMA["key"])
    args = [sys.executable, "-u", host, "serve", "--runner", reference, "--model", root, "--name", MODEL,
            "--revision", str(revision), "--port", str(LLAMA["port"]), "--parallel", str(parallel),
            "--context", str(LLAMA["context"]), "--build", os.path.join(folder, "build"), "--status", os.path.join(folder, "status.json")]
    memory_before = model_memory_events()
    STATE.pop("servingFallback", None)
    LLAMA["servingFallback"] = None
    STATE["megakernel"] = {"serving": False, "reference": reference, "stage": "starting"}
    launch_serves(1)
    print("Starting the megakernel runner " + reference + "...", flush=True)
    with RUNNER_TIMINGS.stage("engine_start_to_ready"):
        process = ENGINE_PROCESS = subprocess.Popen(args, env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        tail, loading = deque(maxlen=VLLM_LOAD_TAIL_LINES), threading.Event()
        loading.set()
        reader = threading.Thread(target=vllm_load_output, args=(process.stdout, tail, loading), daemon=True)
        reader.start()
        facts, refused = None, None
        deadline = time.monotonic() + 3600
        while True:
            if process.poll() is not None:
                report_vllm_load_failure(reader, tail, loading)
                status = megakernel_status(folder)
                refused = str(status.get("error") or "The megakernel runner stopped while starting (exit code " + str(process.returncode) + ").")[:300]
                break
            try:
                connection, response = llama("/health", timeout=5)
                try:
                    body = response.read(1 << 20)
                finally:
                    connection.close()
                if response.status == 200:
                    facts = json.loads(body).get("runner")
                    if not isinstance(facts, dict):
                        raise ValueError("no runner facts")
                    break
            except (OSError, ValueError, http.client.HTTPException):
                pass
            if time.monotonic() >= deadline:
                refused = "The megakernel runner did not finish starting within an hour."
                break
            stage = megakernel_status(folder).get("stage")
            if stage:
                STATE["megakernel"]["stage"] = str(stage)[:120]
            time.sleep(READY_POLL_SECONDS)
        loading.clear()
        tail.clear()
    if facts is None:
        end_engine(process)
        MEGAKERNEL_REFUSED = refused
        STATE["megakernel"] = {"serving": False, "reference": reference, "refused": refused}
        STATE["servingFallback"] = LLAMA["servingFallback"] = "The megakernel runner could not serve, so vLLM does: " + refused
        print("The megakernel runner could not serve, so vLLM does: " + refused, flush=True)
        return False
    MEGAKERNEL = {"serving": True, "reference": reference, **{key: facts[key] for key in facts if key not in ("serving", "reference")}}
    STATE["megakernel"] = MEGAKERNEL
    LLAMA["context"] = max(256, min(LLAMA["context"], int(facts.get("context") or LLAMA["context"])))
    launch_serves(max(1, min(parallel, int(facts.get("parallel") or 1))))

    def watch():
        returncode = process.wait()
        if ENGINE_PROCESS is process:
            STATE.update(status="error", error=llama_exit_error(returncode, memory_before, "The megakernel runner"))
    threading.Thread(target=watch, daemon=True).start()
    quant = (config.get("quantization_config") or {}).get("quant_method")
    STATE.update(status="ready", gpu=str(facts.get("gpu") or torch.cuda.get_device_name(0)), gpuCount=1, context=LLAMA["context"], stream=True,
                 weightsVerified=True, revision=revision, runner="megakernel", launch="megakernel",
                 quant=str(quant).upper() if quant else None, precision=str(facts.get("precision") or config.get("dtype") or config.get("torch_dtype") or "auto"))
    print("The megakernel runner " + str(facts.get("name")) + " serves: " + str(facts.get("tokensPerSecond")) + " tokens/s on " + STATE["gpu"] + ".", flush=True)
    return True


def load_vllm():
    global ENGINE_PROCESS, VLLM_PARKED, VLLM_ROOT, VLLM_ASKED, VLLM_KOLIBRI, MEGAKERNEL
    MEGAKERNEL = None  # load_megakernel sets it again when the runner serves this load
    STATE["sourceReused"] = False
    if os.environ.get("YOUGORI_INSTALL_VLLM") == "1": install({"vllm": VLLM_VERSION})
    if importlib.metadata.version("vllm") != VLLM_VERSION:
        raise RuntimeError("Use Yougori's pinned vLLM runtime image (vLLM " + VLLM_VERSION + ")")
    import torch
    # A Hugging Face checkpoint is pinned to its 40-hex commit. A local mount is pinned to the 64-hex
    # manifest digest the engine computed (model_runner/local.rs), which registry_snapshot() rechecks.
    pinned = r"[a-fA-F0-9]{40}|[a-f0-9]{64}" if MODEL_PATH else r"[a-fA-F0-9]{40}"
    if not isinstance(MODEL_REVISION, str) or not re.fullmatch(pinned, MODEL_REVISION):
        raise RuntimeError("vLLM requires the exact immutable revision approved by preflight")
    metadata, revision, prepared, reused = None, MODEL_REVISION, None, False
    remembered = begin_local_load()
    if MODEL_PATH:
        # The process-local download memo (remember_vllm_source/prepared_vllm_source) describes a
        # Hugging Face snapshot and is bypassed here: the bundled verifier checks the local files
        # again on every load attempt (begin_local_load, verified_snapshot; review finding R5),
        # so a reload in this process reuses the files only after that check found them unchanged.
        root, config, size = local_vllm_source()
        # Diagnostic only: the earlier verification's files were found unchanged and nothing was
        # downloaded or imported again. A copy imported again in this call is not reuse.
        reused = remembered and not (MODEL_IMPORTED is not None and STATE.get("import", {}).get("status") == "imported")
    else:
        prepared = prepared_vllm_source()
        reused = prepared is not None
        if prepared is not None:
            root, config, size = prepared
        else:
            from huggingface_hub import HfApi, hf_hub_download
            metadata = HfApi().model_info(MODEL, revision=revision, files_metadata=True, timeout=30)
            if metadata.sha != revision:
                raise RuntimeError("vLLM requires the exact immutable revision approved by preflight")
            with open(hf_hub_download(MODEL, "config.json", revision=revision), encoding="utf-8") as file:
                config = json.load(file)
            if {"joint_head_config.json", "joint_head.safetensors"} <= {s.rfilename for s in metadata.siblings or []}:
                raise RuntimeError("A custom prediction head needs a reviewed decision adapter")
            weights = [s for s in metadata.siblings or [] if s.rfilename.endswith(".safetensors")]
            size = sum((getattr(s, "size", None) or (s.lfs.get("size") if isinstance(getattr(s,"lfs",None),dict) else getattr(getattr(s,"lfs",None),"size",0)) or 0) for s in weights)
    kolibri = VLLM_KOLIBRI = config.get("model_type") == "kolibri1"
    # G06: adapters only where the owner enabled them, loaded at runtime (vllm_adapter).
    limits = adapter_limits() if not kolibri else None
    mode = vllm_launch(kolibri, limits)
    if mode == "megakernel" and MEGAKERNEL_REFUSED is not None:
        # The runner failed earlier in this process (why stays in health); vLLM serves this load.
        mode = VLLM_DEFAULT_LAUNCH
    if kolibri:
        if "Kolibri1ForCausalLM" not in config.get("architectures", []): raise RuntimeError("Unknown Kolibri implementation")
        kolibri_plugin()
    elif mode != "megakernel":
        vllm_registry(config)
    gpu_before_load()
    if mode == "megakernel":
        # The runner's manifest states the GPU it needs (megakernel_host.py checks it); vLLM's own
        # memory check runs only if vLLM serves after all (vllm_after_megakernel).
        count = 1
    else:
        count = vllm_hardware(config, size, torch.cuda)
    if not MODEL_PATH and prepared is None:
        root = verified_snapshot(revision)
        remember_vllm_source(metadata, root, config, size)
    # Diagnostic only: this is source reuse, never a claim of retained GPU/KV state.
    STATE["sourceReused"] = reused
    if MODEL_PATH and MODEL_IMPORTED is not None:
        if reused:
            STATE["source"] = "imported-cached"  # Otherwise the import's own label stays.
    else:
        STATE["source"] = "verified-local-path" if MODEL_PATH else "huggingface"
    template = None
    tokenizer_config = os.path.join(root, "tokenizer_config.json")
    if os.path.isfile(tokenizer_config):
        with open(tokenizer_config, encoding="utf-8") as file: template = json.load(file).get("chat_template")
    STATE["chatTemplate"] = bool(template) or os.path.isfile(os.path.join(root, "chat_template.jinja"))
    if not STATE["chatTemplate"]:
        STATE["chatWarning"] = "This is a base checkpoint without a chat template. Use an instruction-tuned checkpoint for assistant chat."
    STATE["status"] = "loading"
    LLAMA["context"] = min(int(config.get("max_position_embeddings") or 4096), 32768)
    if mode == "megakernel":
        # The owner's kernel serves this load; a vLLM parked by an earlier load is ended first.
        parked, VLLM_PARKED = VLLM_PARKED, None
        STATE.pop("parked", None)
        if parked is not None:
            end_engine(parked[0])
        if load_megakernel(root, config, revision):
            return
        # The runner could not serve (why: health's megakernel.refused); vLLM does, after the
        # checks it would have made first.
        mode = VLLM_DEFAULT_LAUNCH
        count = vllm_after_megakernel(config, size, torch.cuda)
    sequences = serving_slots()
    args = [sys.executable, "-m", "vllm.entrypoints.cli.main", "serve", root,
        "--served-model-name", MODEL, "--host", "127.0.0.1", "--port", str(LLAMA["port"]),
        "--model-impl", "vllm", "--load-format", "safetensors", "--max-model-len", str(LLAMA["context"]),
        "--tensor-parallel-size", str(count), "--distributed-executor-backend", "mp" if count > 1 else "uni", "--gpu-memory-utilization", "0.90",
        "--max-num-seqs", str(sequences), "--enable-prompt-tokens-details", "--generation-config", "vllm"]
    at = len(args) - 4  # where the sequences value is, for the one-sequence fallback
    if kolibri: args += ["--reasoning-parser", "kolibri1"]
    if not kolibri: args += ["--enable-sleep-mode"]
    if limits: args += ["--enable-lora", "--max-loras", str(limits[0]), "--max-lora-rank", str(limits[1]), "--max-cpu-loras", str(limits[0])]
    args += agent_arguments()
    if kolibri and (config.get("quantization_config") or {}).get("quant_method") == "fp8": args += ["--kv-cache-dtype", "fp8"]
    environment = {k:v for k,v in os.environ.items() if k not in PRIVATE_ENVIRONMENT + ("HF_TOKEN",)}
    environment.update(HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1", VLLM_NO_USAGE_STATS="1",
                       VLLM_PLUGINS="aleph_alpha_inference" if kolibri else "", VLLM_API_KEY=LLAMA["key"])
    # Compiled graphs are kept in the model's cache volume beside its files, so a restart reuses
    # them instead of compiling again; without a writable volume vLLM keeps its own default.
    if os.path.isdir(CACHE) and os.access(CACHE, os.W_OK):
        environment["VLLM_CACHE_ROOT"] = os.path.join(CACHE, "vllm-compile")
    # One GPU runs in vLLM's own process ("uni" above): the "mp" workers' shared-memory queues need
    # more /dev/shm than the CUDA runtime's containers have. WSL 2 gives no pinned host memory,
    # which vLLM 0.29.0's V2 model runner requires; its V1 runner serves there.
    if "microsoft" in platform.uname().release.lower():
        environment["VLLM_USE_V2_MODEL_RUNNER"] = "0"
    # Sleep and wake (vllm_park) are development endpoints; vLLM listens on this container's
    # loopback only and the model server relays none of them.
    if not kolibri:
        environment["VLLM_SERVER_DEV_MODE"] = "1"
    if limits:
        environment["VLLM_ALLOW_RUNTIME_LORA_UPDATING"] = "True"
    quant = (config.get("quantization_config") or {}).get("quant_method")

    def ready(launch):
        gpu = torch.cuda.get_device_name(0)
        STATE.update(status="ready", gpu=(str(count) + " × " + gpu) if count > 1 else gpu, gpuCount=count,
            context=LLAMA["context"], stream=True, weightsVerified=True, revision=revision, runner="vllm", **({"toolCalling": True} if TOOL_PARSER else {}),
            quant=str(quant).upper() if quant else None, precision=str(config.get("dtype") or config.get("torch_dtype") or "auto"), launch=launch)
    # A parked vLLM serving this root wakes with its weights reloaded from the files verified above,
    # and reports the launch it runs (a fallback stays a fallback). A launch the owner changed
    # since it was parked starts afresh instead.
    parked, VLLM_PARKED = VLLM_PARKED, None
    STATE.pop("parked", None)
    if parked is not None:
        if parked[0] is ENGINE_PROCESS and parked[0].poll() is None and parked[1] == root and parked[2] == mode and vllm_wake():
            ready(parked[3] or mode)
            return reattach_adapters()
        end_engine(parked[0])
    VLLM_ROOT, VLLM_ASKED = root, mode
    # Native engine diagnostics can contain caller content once requests arrive, so serving
    # output never reaches workload logs. While loading no request exists yet: the last lines
    # are kept in memory and shown only if the load fails (vllm_load_output).
    memory_before = model_memory_events()
    STATE.pop("servingFallback", None)
    LLAMA["servingFallback"] = None
    launch_serves(1)
    cleared = ""  # a note that the compiled graphs were cleared, kept through later fallbacks
    with RUNNER_TIMINGS.stage("engine_start_to_ready"):
        while True:
            process = ENGINE_PROCESS = subprocess.Popen(args + launch_arguments(mode), env=environment, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            tail, loading = deque(maxlen=VLLM_LOAD_TAIL_LINES), threading.Event()
            loading.set()
            reader = threading.Thread(target=vllm_load_output, args=(process.stdout, tail, loading), daemon=True)
            reader.start()
            try:
                deadline = time.monotonic() + 3600
                while True:
                    if process.poll() is not None:
                        report_vllm_load_failure(reader, tail, loading)
                        raise RuntimeError("vLLM stopped while loading. Check GPU memory, driver and checkpoint compatibility.")
                    try:
                        connection, response = llama("/health", timeout=5)
                        response.read(); connection.close()
                        if response.status == 200: break
                    except OSError: pass
                    if time.monotonic() >= deadline:
                        report_vllm_load_failure(reader, tail, loading)
                        raise RuntimeError("vLLM did not finish loading within an hour")
                    time.sleep(READY_POLL_SECONDS)
                break
            except BaseException as error:
                loading.clear()
                process.terminate()
                try: process.wait(timeout=5)
                except subprocess.TimeoutExpired: process.kill(); process.wait()
                if not isinstance(error, RuntimeError) or (mode == "eager" and sequences == 1) or "within an hour" in str(error):
                    raise
                # The launches that served before, one step at a time: compiled (no speculation),
                # eager (no CUDA graphs or compilation either), then one sequence. Why the faster
                # one failed stays in health.
                memory_before = model_memory_events()
                if mode == "speculative":
                    mode = "compiled"
                elif mode != "eager":
                    mode = "eager"
                    # Both compiled launches failed. Damaged compiled graphs would fail every
                    # start the same way, so they are cleared and the next start compiles afresh;
                    # a launch that failed for another reason wrote none.
                    if environment.get("VLLM_CACHE_ROOT") and os.path.isdir(environment["VLLM_CACHE_ROOT"]):
                        shutil.rmtree(environment["VLLM_CACHE_ROOT"], ignore_errors=True)
                        cleared = " The compiled graphs were cleared; the next start compiles them again."
                else:
                    sequences = 1
                    args[at] = "1"
                STATE["servingFallback"] = LLAMA["servingFallback"] = str(error)[:300] + cleared
        # Serving begins: from here on every line is drained and discarded.
        loading.clear()
        tail.clear()
    launch_serves(sequences)
    def watch():
        returncode = process.wait()
        if ENGINE_PROCESS is process:
            # Its exit code or the container's out-of-memory kill, never its output (serving
            # output can carry caller content).
            STATE.update(status="error", error=llama_exit_error(returncode, memory_before, "vLLM"))
    threading.Thread(target=watch, daemon=True).start()
    ready(mode)
    reattach_adapters()
