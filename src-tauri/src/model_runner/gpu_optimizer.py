"""Runner residency controls. Executed in the model server namespace; no caller content retained."""
import gc
import socket

GPU_LOCK = threading.RLock()
GPU_GRANTED = threading.Event()
GPU_LEASES = {}
GPU_ENABLED = os.environ.get("YOUGORI_GPU_OPTIMIZER") == "1" and FORMAT != "source"
GPU_PINNED = os.environ.get("YOUGORI_GPU_PINNED") == "1"
GPU_ACTIVE = 0
GPU_LOADING = False
GPU_WAITING_FOR_GRANT = False
GPU_LAST_USED = time.monotonic()
GPU_WAITING_SINCE = None
GPU_IDLE_SECONDS = max(10, min(3600, int(os.environ.get("YOUGORI_GPU_IDLE_SECONDS", "120"))))
GPU_INITIAL = False


def gpu_snapshot():
    with GPU_LOCK:
        now = time.monotonic()
        for key in list(GPU_LEASES):
            if GPU_LEASES[key] <= now:
                del GPU_LEASES[key]
        if not GPU_LEASES and not GPU_INITIAL and not GPU_LOADING and STATE.get("status") in ("queued", "freeing_memory"):
            STATE["status"] = "idle"
        loaded = STATE.get("status") == "ready"
        memory = None
        if TORCH is not None and TORCH.cuda.is_available():
            try:
                memory = sum(TORCH.cuda.memory_allocated(i) for i in range(TORCH.cuda.device_count()))
            except (AttributeError, RuntimeError):
                pass
        return {"supported": FORMAT != "source" and bool(os.environ.get("YOUGORI_GPU_CONTROL_TOKEN")), "enabled": GPU_ENABLED, "pinned": GPU_PINNED,
                "resident": loaded, "loading": GPU_LOADING, "active": GPU_ACTIVE,
                "pending": len(GPU_LEASES) + int(GPU_INITIAL), "waitingSince": GPU_WAITING_SINCE,
                "idleSeconds": int(now - GPU_LAST_USED), "idleTimeoutSeconds": GPU_IDLE_SECONDS,
                "allocatedBytes": memory}


def gpu_before_load():
    """Only the local host scheduler grants admission; public prepare merely queues demand."""
    global GPU_LOADING, GPU_INITIAL, GPU_WAITING_SINCE, GPU_WAITING_FOR_GRANT
    with GPU_LOCK:
        if not GPU_ENABLED:
            return
        GPU_INITIAL = not STATE.get("weightsVerified", False)
        GPU_WAITING_SINCE = GPU_WAITING_SINCE or time.time()
        GPU_WAITING_FOR_GRANT = True
        STATE.update(status="queued", error=None)
    granted = GPU_GRANTED.wait(1800)
    with GPU_LOCK:
        GPU_WAITING_FOR_GRANT = False
        if not granted:
            raise RuntimeError("GPU admission timed out. Open Yougori and check Automatic GPU memory.")
        if STATE.get("weightsVerified") and STATE.get("precision") in ("original", "4bit", "8bit"):
            os.environ["YOUGORI_MODEL_PRECISION"] = STATE["precision"]
        GPU_GRANTED.clear()
        GPU_LOADING = True
        GPU_INITIAL = False
        STATE.update(status="loading", error=None)


def gpu_after_load():
    global GPU_LOADING, GPU_LAST_USED, GPU_WAITING_SINCE, NETWORK, TOKENIZER, PROCESSOR, CLEF
    with GPU_LOCK:
        if STATE.get("status") == "error" and not GPU_ACTIVE and GENERATION.acquire(blocking=False):
            try:
                NETWORK = TOKENIZER = PROCESSOR = CLEF = None
                gc.collect()
                if TORCH is not None:
                    try: TORCH.cuda.empty_cache()
                    except RuntimeError: pass
            finally:
                GENERATION.release()
        GPU_LOADING = False
        GPU_LAST_USED = time.monotonic()
        GPU_WAITING_SINCE = None


def gpu_prepare(key):
    global GPU_WAITING_SINCE
    if not isinstance(key, str) or not re.fullmatch(r"[A-Za-z0-9_-]{16,80}", key):
        raise ValueError("Invalid preparation lease")
    with GPU_LOCK:
        gpu_snapshot()
        if key not in GPU_LEASES and len(GPU_LEASES) >= 32:
            raise ValueError("Model queue is full")
        GPU_LEASES[key] = time.monotonic() + 20
        if GPU_ENABLED and STATE["status"] == "idle":
            GPU_WAITING_SINCE = GPU_WAITING_SINCE or time.time()
            STATE["status"] = "queued"
        return {"state": "error" if STATE["status"] == "error" else "freeing_memory" if STATE["status"] == "freeing_memory" else "ready" if STATE["status"] == "ready" else "loading_model" if GPU_LOADING else "queued",
                "optimizer": gpu_snapshot()}


def gpu_unload():
    global NETWORK, TOKENIZER, PROCESSOR, CLEF, ENGINE_PROCESS, GPU_LAST_USED
    with GPU_LOCK:
        snapshot = gpu_snapshot()
        if not GPU_ENABLED or GPU_PINNED or GPU_LOADING or GPU_ACTIVE or snapshot["pending"] or not GENERATION.acquire(blocking=False):
            return False
        try:
            STATE["status"] = "unloading"
            process = ENGINE_PROCESS
            ENGINE_PROCESS = None
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
            NETWORK = TOKENIZER = PROCESSOR = CLEF = None
            gc.collect()
            if TORCH is not None:
                TORCH.cuda.empty_cache()
            GPU_LAST_USED = time.monotonic()
            STATE.update(status="idle", error=None)
            return True
        finally:
            GENERATION.release()


def gpu_control(body):
    global GPU_ENABLED, GPU_PINNED, GPU_IDLE_SECONDS, GPU_LOADING, GPU_INITIAL, GPU_WAITING_SINCE
    action = body.get("action")
    with GPU_LOCK:
        if action == "configure":
            if type(body.get("enabled")) is not bool or type(body.get("pinned", False)) is not bool:
                raise ValueError("Invalid optimizer settings")
            timeout = body.get("idleTimeoutSeconds", 120)
            if type(timeout) is not int or not 10 <= timeout <= 3600:
                raise ValueError("Idle timeout must be 10–3600 seconds")
            GPU_ENABLED, GPU_PINNED, GPU_IDLE_SECONDS = body["enabled"], body.get("pinned", False), timeout
            if GPU_ENABLED and GPU_PINNED and STATE["status"] == "idle":
                GPU_INITIAL = True
                GPU_WAITING_SINCE = time.time()
                STATE["status"] = "queued"
            if not GPU_ENABLED:
                GPU_GRANTED.set()
                if STATE["status"] in ("idle", "queued", "freeing_memory") and not GPU_LOADING and not GPU_WAITING_FOR_GRANT:
                    GPU_LOADING = True
                    threading.Thread(target=load_model, daemon=True).start()
        elif action == "grant":
            if GPU_ENABLED and not GPU_LOADING and STATE["status"] in ("idle", "queued", "freeing_memory"):
                # A startup loader may already be blocked at gpu_before_load.
                if STATE.get("weightsVerified") and not GPU_WAITING_FOR_GRANT:
                    GPU_LOADING = True
                    threading.Thread(target=load_model, daemon=True).start()
                GPU_GRANTED.set()
        elif action == "unload":
            return {"unloaded": gpu_unload(), "optimizer": gpu_snapshot()}
        elif action == "phase":
            if STATE["status"] in ("idle", "queued", "freeing_memory"):
                STATE["status"] = "freeing_memory" if body.get("phase") == "freeing_memory" else "queued"
        else:
            raise ValueError("Invalid optimizer action")
        return {"optimizer": gpu_snapshot()}


def gpu_enter(handler):
    """Keep inference protected from eviction, including a stalled generation worker."""
    global GPU_ACTIVE, GPU_LAST_USED
    key = secrets.token_hex(16)
    deadline = time.monotonic() + 1800
    try:
        while True:
            with GPU_LOCK:
                gpu_prepare(key)
                if STATE["status"] == "ready":
                    GPU_LEASES.pop(key, None)
                    GPU_ACTIVE += 1
                    GPU_LAST_USED = time.monotonic()
                    return True
                if not GPU_ENABLED or STATE["status"] == "error":
                    return False
            if time.monotonic() >= deadline:
                return False
            # Detect a disconnected HTTP client without consuming request bytes.
            readable, _, _ = __import__("select").select([handler.connection], [], [], 0)
            if readable and handler.connection.recv(1, socket.MSG_PEEK) == b"":
                return False
            time.sleep(0.25)
    finally:
        with GPU_LOCK:
            GPU_LEASES.pop(key, None)


def gpu_leave():
    global GPU_ACTIVE, GPU_LAST_USED
    with GPU_LOCK:
        GPU_ACTIVE = max(0, GPU_ACTIVE - 1)
        GPU_LAST_USED = time.monotonic()


def gpu_route(handler):
    if handler.path not in ("/v1/yougori/prepare", "/v1/yougori/release", "/v1/yougori/optimizer"):
        return False
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if not 0 < length <= 1024 or handler.headers.get("Transfer-Encoding"):
            raise ValueError("Invalid optimizer request")
        body = json.loads(handler.rfile.read(length))
        if handler.path.endswith("optimizer"):
            # X-Yougori-Client is not authorization. Control requires a separate
            # credential kept in the container and local engine, never in public API keys.
            expected = os.environ.get("YOUGORI_GPU_CONTROL_TOKEN", "")
            supplied = handler.headers.get("X-Yougori-GPU-Control", "")
            if not expected or not supplied.isascii() or not secrets.compare_digest(expected, supplied):
                handler.reply(403, {"error": {"message": "Local GPU control credential required"}})
                return True
            value = gpu_control(body)
        elif handler.path.endswith("release"):
            with GPU_LOCK:
                GPU_LEASES.pop(body.get("lease"), None)
            value = {"released": True}
        else:
            value = gpu_prepare(body.get("lease"))
        handler.reply(200, value)
    except (ValueError, TypeError, OSError):
        handler.reply(400, {"error": {"message": "Invalid GPU preparation request"}})
    return True
