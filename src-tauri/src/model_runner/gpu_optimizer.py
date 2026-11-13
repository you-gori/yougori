"""Runner residency controls. Executed in the model server namespace; no caller content retained."""
import gc
import socket

GPU_LOCK = threading.RLock()
GPU_CHANGED = threading.Condition(GPU_LOCK)
GPU_GRANTED = threading.Event()
GPU_LEASES = {}
GPU_ENABLED = os.environ.get("YOUGORI_GPU_OPTIMIZER") == "1" and FORMAT != "source"
GPU_PINNED = os.environ.get("YOUGORI_GPU_PINNED") == "1"
GPU_ACTIVE = 0
GPU_LOADING = False
GPU_RELEASE_UNCERTAIN = False
GPU_WAITING_FOR_GRANT = False
GPU_LAST_USED = time.monotonic()
GPU_WAITING_SINCE = None
GPU_IDLE_SECONDS = int(os.environ.get("YOUGORI_GPU_IDLE_SECONDS", "0"))
if GPU_IDLE_SECONDS != 0:
    GPU_IDLE_SECONDS = max(10, min(3600, GPU_IDLE_SECONDS))
GPU_INITIAL = False
GPU_INSTANCE_ID = secrets.token_hex(16)
GPU_SEQUENCE = 0
GPU_SEQUENCE_LIMIT = 2**53 - 1
GPU_OBSERVED = None
GPU_COMMITTING = False
GPU_WATCHERS = 0
GPU_MAX_WATCHERS = 4
GPU_WATCH_SLOTS = threading.BoundedSemaphore(GPU_MAX_WATCHERS)
GPU_WATCH_LOCK = threading.Lock()
GPU_REVISION_EVENT = threading.Event()
# The engine's single-GPU Transformers admission profile (capacity.rs): its grant is the
# demand in YOUGORI_GPU_CAPACITY_BYTES, and this runner holds itself to it (G03).
GPU_CAPACITY_PROFILE = "local-single-transformers-v1"
# The allocator cap this runner enforces, in bytes; None while uncapped.
GPU_CAPACITY = None
# The context, in tokens, the grant covers (YOUGORI_GPU_CAPACITY_CONTEXT): the runner serves no
# longer prompt under the profile (context_window in the model server); None while uncapped.
GPU_CAPACITY_CONTEXT = None
# The terms the engine's last grant carried (bytes, context), when it carried any: what this
# runner holds itself to for that load, never above the stamped demand (capacity.rs,
# GrantTerms; G03 co-residency: a model admitted beside resident ones gets the longest context
# that fits what is left). Cleared by an unload; a grant without terms means the stamp.
GPU_GRANT_TERMS = None


class GPUControlConflict(Exception):
    pass


class GPUWatchBusy(Exception):
    pass


class GPUWatchDisconnected(Exception):
    pass


def gpu_publish(force=False):
    """Caller holds GPU_LOCK. Coalesce semantic changes, never clock/lease renewals."""
    global GPU_OBSERVED, GPU_SEQUENCE, GPU_INSTANCE_ID, GPU_REVISION_EVENT
    if GPU_COMMITTING:
        return
    observed = (STATE.get("status"), bool(STATE.get("error")), bool(STATE.get("weightsVerified")),
                GPU_ENABLED, GPU_PINNED, GPU_ACTIVE, GPU_LOADING, GPU_RELEASE_UNCERTAIN,
                GPU_WAITING_FOR_GRANT, GPU_INITIAL, len(GPU_LEASES), GPU_WAITING_SINCE,
                GPU_IDLE_SECONDS, GPU_GRANTED.is_set())
    if force or observed != GPU_OBSERVED:
        GPU_OBSERVED = observed
        if GPU_SEQUENCE >= GPU_SEQUENCE_LIMIT:
            GPU_INSTANCE_ID, GPU_SEQUENCE = secrets.token_hex(16), 0
        GPU_SEQUENCE += 1
        event, GPU_REVISION_EVENT = GPU_REVISION_EVENT, threading.Event()
        event.set()
        GPU_CHANGED.notify_all()


def gpu_refresh():
    """Expire demand before a snapshot or control precondition is evaluated."""
    global GPU_WAITING_SINCE
    now = time.monotonic()
    for key in list(GPU_LEASES):
        if GPU_LEASES[key] <= now:
            del GPU_LEASES[key]
    if not GPU_LEASES and not GPU_INITIAL and not GPU_LOADING and STATE.get("status") in ("queued", "freeing_memory"):
        STATE["status"] = "idle"
        if not GPU_WAITING_FOR_GRANT:
            GPU_WAITING_SINCE = None
    gpu_publish()


def gpu_snapshot(refresh=True):
    with GPU_LOCK:
        if refresh:
            gpu_refresh()
        now = time.monotonic()
        loaded = STATE.get("status") == "ready"
        memory = reserved = peak = None
        if TORCH is not None and TORCH.cuda.is_available():
            try:
                memory = sum(TORCH.cuda.memory_allocated(i) for i in range(TORCH.cuda.device_count()))
            except (AttributeError, RuntimeError):
                pass
            # An observation only (GPU-W01: truthful retention): allocator segments this
            # process still holds. It never changes residency, release or admission.
            try:
                reserved = sum(TORCH.cuda.memory_reserved(i) for i in range(TORCH.cuda.device_count()))
            except (AttributeError, RuntimeError):
                pass
            # An observation only (GPU-W00: resource peaks): the most this process's allocator
            # held at once since its last unload, which the admission demand must cover (G03).
            try:
                peak = sum(TORCH.cuda.max_memory_allocated(i) for i in range(TORCH.cuda.device_count()))
            except (AttributeError, RuntimeError):
                pass
        return {"supported": FORMAT != "source" and bool(os.environ.get("YOUGORI_GPU_CONTROL_TOKEN")),
                "controlProtocol": 1, "instanceId": GPU_INSTANCE_ID, "sequence": GPU_SEQUENCE,
                "enabled": GPU_ENABLED, "pinned": GPU_PINNED,
                "resident": loaded or GPU_RELEASE_UNCERTAIN, "releaseUncertain": GPU_RELEASE_UNCERTAIN,
                "loading": GPU_LOADING, "active": GPU_ACTIVE,
                # Requests queued for a slot are demand too: the model is not evictable between them.
                "pending": len(GPU_LEASES) + int(GPU_INITIAL) + (INFERENCE_QUEUE.snapshot()["waiting"] if "INFERENCE_QUEUE" in globals() else 0),
                "waitingSince": GPU_WAITING_SINCE,
                "idleSeconds": int(now - GPU_LAST_USED), "idleTimeoutSeconds": GPU_IDLE_SECONDS,
                "allocatedBytes": memory, "reservedBytes": reserved, "peakAllocatedBytes": peak,
                "capacityBytes": GPU_CAPACITY, "capacityContext": GPU_CAPACITY_CONTEXT,
                "endsParkedWhileWaiting": True}


def gpu_capacity_stamp():
    """The demand in bytes and the context in tokens this model was stamped with under the
    Transformers profile (YOUGORI_GPU_CAPACITY_BYTES and _CONTEXT), or None under any other.
    A malformed or missing demand or context fails closed."""
    if os.environ.get("YOUGORI_GPU_CAPACITY_POLICY") != GPU_CAPACITY_PROFILE:
        return None
    value = os.environ.get("YOUGORI_GPU_CAPACITY_BYTES", "")
    context = os.environ.get("YOUGORI_GPU_CAPACITY_CONTEXT", "")
    if (not (value.isascii() and value.isdigit()) or not 0 < int(value) <= 2 ** 50
            or not (context.isascii() and context.isdigit()) or not 0 < int(context) <= 2 ** 20):
        raise RuntimeError("This model's GPU grant is invalid. Recreate it to restore shared admission.")
    return int(value), int(context)


def gpu_capacity_demand():
    """The grant this runner holds itself to under the Transformers profile: its demand in bytes
    and the context, in tokens, that demand covers (capacity.rs, ContextDemand), or None.

    Other profiles are not the runner's to enforce (vLLM takes its own fraction of the GPU),
    and the engine refuses unknown ones before any grant. A malformed or missing demand or
    context fails closed.
    """
    stamp = gpu_capacity_stamp()
    if stamp is None:
        return None
    demand, covered = stamp
    with GPU_LOCK:
        terms = GPU_GRANT_TERMS
    if terms is not None:
        # The grant may cover less than the stamp (what fit beside the resident models), never more.
        demand, covered = min(demand, terms[0]), min(covered, terms[1])
    return demand, covered


def gpu_trim(terms):
    """Holds this resident runner to a smaller grant (G03 co-residency; GPU-W05 "reclaim unused
    scratch"): the engine asks for (bytes, context); the runner frees its allocator's cached
    blocks and accepts the larger of what was asked and what it still holds plus a margin (a
    quarter of it, at least 256 MiB, while a request is active; 64 MiB when idle), never more
    than its current grant, and serves no prompt past the accepted context from now on.
    Returns what it accepted. The engine's reservation follows the host probe, not this word.
    """
    global GPU_CAPACITY, GPU_CAPACITY_CONTEXT, GPU_GRANT_TERMS
    asked_bytes, asked_context = terms
    torch = TORCH
    if torch is None or GPU_CAPACITY is None or GPU_CAPACITY_CONTEXT is None:
        raise GPUControlConflict()
    try:
        torch.cuda.empty_cache()
        held = int(torch.cuda.memory_reserved(0))
        total = int(torch.cuda.mem_get_info(0)[1])
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise RuntimeError("This runner cannot measure what it holds on the GPU; its grant is unchanged.") from None
    with GPU_LOCK:
        margin = max(256 * 1024 * 1024, held // 4) if GPU_ACTIVE else 64 * 1024 * 1024
        accepted_bytes = min(GPU_CAPACITY, max(asked_bytes, held + margin))
        accepted_context = min(GPU_CAPACITY_CONTEXT, asked_context)
        try:
            torch.cuda.set_per_process_memory_fraction(min(1.0, accepted_bytes / total), 0)
        except (AttributeError, RuntimeError, TypeError, ValueError, ZeroDivisionError):
            raise RuntimeError("This runner cannot hold the model to its smaller GPU grant; its grant is unchanged.") from None
        GPU_CAPACITY, GPU_CAPACITY_CONTEXT = accepted_bytes, accepted_context
        GPU_GRANT_TERMS = (accepted_bytes, accepted_context)
    if STATE.get("context"):
        STATE["context"] = min(int(STATE["context"]), accepted_context)
    return accepted_bytes, accepted_context


def gpu_grow(terms):
    """Lets this resident runner hold more of the GPU again (G03 grow-back): a neighbour left and
    the engine reserved the extra bytes on the host ledger before asking. The allocator cap and
    the context served rise to exactly the terms, which must lie between what the runner holds
    itself to now and its stamped demand and context; anything else is refused and nothing
    changes. Returns the terms now held to. The engine shows the longer context only from this
    answer, or from the runner's next report.
    """
    global GPU_CAPACITY, GPU_CAPACITY_CONTEXT, GPU_GRANT_TERMS
    asked_bytes, asked_context = terms
    torch = TORCH
    stamp = gpu_capacity_stamp()
    if torch is None or stamp is None or GPU_CAPACITY is None or GPU_CAPACITY_CONTEXT is None:
        raise GPUControlConflict()
    if asked_bytes > stamp[0] or asked_context > stamp[1]:
        raise ValueError("A GPU grow asks for more than this model was stamped with")
    if asked_bytes < GPU_CAPACITY or asked_context < GPU_CAPACITY_CONTEXT:
        raise ValueError("A GPU grow asks for less than this model holds itself to")
    try:
        total = int(torch.cuda.mem_get_info(0)[1])
    except (AttributeError, RuntimeError, TypeError, ValueError):
        raise RuntimeError("This runner cannot measure the GPU; its grant is unchanged.") from None
    with GPU_LOCK:
        try:
            torch.cuda.set_per_process_memory_fraction(min(1.0, asked_bytes / total), 0)
        except (AttributeError, RuntimeError, TypeError, ValueError, ZeroDivisionError):
            raise RuntimeError("This runner cannot raise its GPU cap; its grant is unchanged.") from None
        GPU_CAPACITY, GPU_CAPACITY_CONTEXT = asked_bytes, asked_context
        GPU_GRANT_TERMS = (asked_bytes, asked_context)
    if STATE.get("context"):
        STATE["context"] = context_window()
    return asked_bytes, asked_context


def gpu_grant_terms(body):
    """The terms a grant carries, validated: (bytes, context) or None when it carries none.

    Both must come together as positive integers within the same bounds as the stamp; anything
    else refuses the grant, since a runner must never guess what it may hold.
    """
    if "bytes" not in body and "context" not in body:
        return None
    demand, context = body.get("bytes"), body.get("context")
    if (type(demand) is not int or type(context) is not int
            or not 0 < demand <= 2 ** 50 or not 0 < context <= 2 ** 20):
        raise ValueError("Invalid GPU grant terms")
    return demand, context


def gpu_cap_memory(torch, gpu_count):
    """Before weights load, hold this runner to its Transformers grant (G03, GPU-W02).

    Caps the one granted device's caching allocator at the demand and pins precision to
    original, the precision the demand was estimated at, so a stamped model never quantizes
    itself into a different demand. The demand covers the prefill of a prompt as long as the
    grant's context (eager attention needs memory quadratic in the prompt), so the runner also
    serves no longer prompt (context_window): a longer conversation is refused or truncated
    by fit() with its context window named, instead of running past the grant into the
    driver's slow spill to system memory. Over-use that still happens fails as CUDA out of
    memory (the bounded 507 answer), never as memory taken from another grant. The CUDA
    context and other driver allocations live outside the allocator and are not capped; the
    host probe counts them as used at the next admission. Without the profile nothing
    changes. Returns the cap in bytes, or None.
    """
    global GPU_CAPACITY, GPU_CAPACITY_CONTEXT
    granted = gpu_capacity_demand()
    if granted is None:
        return None
    demand, context = granted
    if gpu_count != 1:
        raise RuntimeError("This model was admitted for one GPU, but its runner sees " + str(gpu_count) +
                           ". Recreate it to restore shared admission.")
    try:
        total = torch.cuda.mem_get_info(0)[1]
        torch.cuda.set_per_process_memory_fraction(min(1.0, demand / total), 0)
    except (AttributeError, RuntimeError, TypeError, ValueError, ZeroDivisionError):
        # Native CUDA errors are not echoed; the load fails before any weight is placed.
        raise RuntimeError("This runner cannot hold the model to its GPU grant. Update Yougori or recreate the model.") from None
    os.environ["YOUGORI_MODEL_PRECISION"] = "original"
    with GPU_LOCK:
        GPU_CAPACITY = min(demand, total)
        GPU_CAPACITY_CONTEXT = context
    return GPU_CAPACITY


def gpu_before_load():
    """Only the local host scheduler grants admission; public prepare merely queues demand."""
    global GPU_LOADING, GPU_INITIAL, GPU_WAITING_SINCE, GPU_WAITING_FOR_GRANT
    with GPU_LOCK:
        if GPU_RELEASE_UNCERTAIN:
            raise RuntimeError("Previous GPU memory release is unconfirmed. Retry unloading or restart this model environment.")
        if not GPU_ENABLED:
            # Admission may be disabled while this runner still owns GPU memory.
            # Publish allocation ownership before the backend can begin loading.
            GPU_LOADING = True
            GPU_INITIAL = False
            GPU_WAITING_FOR_GRANT = False
            GPU_WAITING_SINCE = None
            STATE.update(status="loading", error=None)
            gpu_publish()
            return
        GPU_INITIAL = not STATE.get("weightsVerified", False)
        GPU_WAITING_SINCE = GPU_WAITING_SINCE or time.time()
        GPU_WAITING_FOR_GRANT = True
        STATE.update(status="queued", error=None)
        gpu_publish()
    granted = GPU_GRANTED.wait(1800)
    with GPU_LOCK:
        GPU_WAITING_FOR_GRANT = False
        if not granted:
            gpu_publish()
            raise RuntimeError("GPU admission timed out. Open Yougori and check Automatic GPU memory.")
        if STATE.get("weightsVerified") and STATE.get("precision") in ("original", "4bit", "8bit"):
            os.environ["YOUGORI_MODEL_PRECISION"] = STATE["precision"]
        GPU_GRANTED.clear()
        GPU_LOADING = True
        GPU_INITIAL = False
        STATE.update(status="loading", error=None)
        gpu_publish()


def gpu_after_load():
    global GPU_LOADING, GPU_LAST_USED, GPU_WAITING_SINCE, GPU_RELEASE_UNCERTAIN
    with GPU_LOCK:
        if STATE.get("status") == "error":
            # Failure is not evidence that a partially initialized engine or its
            # allocator released memory. Retain occupancy until cleanup succeeds.
            GPU_RELEASE_UNCERTAIN = True
            if not GPU_ACTIVE and GENERATION.acquire(blocking=False):
                try:
                    gpu_release_memory()
                    GPU_RELEASE_UNCERTAIN = False
                except Exception:
                    # Cleanup failures may contain native argv or backend secrets.
                    STATE["error"] = "GPU memory release is unconfirmed. Retry unloading or restart this model environment."
                finally:
                    GENERATION.release()
            else:
                STATE["error"] = "GPU memory release is unconfirmed. Retry unloading or restart this model environment."
        GPU_LOADING = False
        GPU_LAST_USED = time.monotonic()
        GPU_WAITING_SINCE = None
        gpu_publish()


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
        gpu_publish()
        return {"state": "error" if STATE["status"] == "error" else "freeing_memory" if STATE["status"] == "freeing_memory" else "ready" if STATE["status"] == "ready" else "loading_model" if GPU_LOADING else "queued",
                "optimizer": gpu_snapshot()}


def gpu_release_memory():
    """Caller holds GPU_LOCK and GENERATION; never forget a live owned engine."""
    global NETWORK, TOKENIZER, PROCESSOR, CLEF, ENGINE_PROCESS
    observer = globals().get("RUNNER_TIMINGS")
    if observer is not None:
        observer.invalidate_load()
    process = ENGINE_PROCESS
    STATE.pop("parked", None)
    if process is not None:
        ENGINE_PROCESS = None  # first, as end_engine does: its watcher must not report a crash
        try:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
        except BaseException:
            if process.poll() is None:
                ENGINE_PROCESS = process
            raise
    # The next launch reports what it serves; until then the queue admits one request.
    queue = globals().get("INFERENCE_QUEUE")
    if queue is not None:
        queue.serve(1)
    NETWORK = TOKENIZER = PROCESSOR = CLEF = None
    gc.collect()
    if TORCH is not None:
        gpu_clear_cublas_workspaces()
        TORCH.cuda.empty_cache()
        # The peak observation starts over with the next residency (an observation only).
        try:
            TORCH.cuda.reset_peak_memory_stats()
        except (AttributeError, RuntimeError, TypeError):
            pass


def gpu_clear_cublas_workspaces():
    """Free PyTorch's per-process cuBLAS workspaces before returning cached segments.

    The first matmul places the workspace in the free tail of the weights' caching-allocator
    segment and keeps it for the whole process, so empty_cache() cannot return that segment
    (observed on the RTX 5090: one 8.5 MB workspace held a 942 MiB segment after unload).
    The next matmul allocates it again. `_cuda_clearCublasWorkspaces` is a private PyTorch
    API: when it is absent or fails, release proceeds as before (reservedBytes shows what
    stays held). Returns whether it was called successfully.
    """
    clear = getattr(getattr(TORCH, "_C", None), "_cuda_clearCublasWorkspaces", None)
    if not callable(clear):
        return False
    try:
        clear()
    except (AttributeError, RuntimeError):
        return False
    return True


def gpu_unload():
    global GPU_LAST_USED, GPU_RELEASE_UNCERTAIN, GPU_GRANT_TERMS
    with GPU_LOCK:
        snapshot = gpu_snapshot()
        # A parked vLLM's leftover can keep the model first in line refused: its engine ends even
        # while its own requests wait (endsParkedWhileWaiting), and they keep their place.
        waiting = bool(snapshot["pending"])
        if waiting and not (STATE.get("parked") == "sleep" and not snapshot["resident"]):
            return False
        if not GPU_ENABLED or GPU_PINNED or GPU_LOADING or GPU_ACTIVE or not GENERATION.acquire(blocking=False):
            return False
        try:
            STATE["status"] = "unloading"
            GPU_RELEASE_UNCERTAIN = True
            # A native vLLM parks by sleep, its process kept for the next load (vllm_park).
            park = globals().get("vllm_park")
            if not (park and park()):
                gpu_release_memory()
            GPU_LAST_USED = time.monotonic()
            GPU_RELEASE_UNCERTAIN = False
            STATE.update(status="queued" if waiting else "idle", error=None)
            GPU_GRANTED.clear()
            GPU_GRANT_TERMS = None
            gpu_publish()
            return True
        except Exception:
            STATE.update(status="error", error="GPU memory release is unconfirmed. Retry unloading or restart this model environment.")
            gpu_publish()
            raise
        finally:
            GENERATION.release()


def gpu_watch(body, handler=None):
    """Bounded private long-poll: changes, restart, expiry or heartbeat snapshot."""
    global GPU_WATCHERS
    instance, since, wait_ms = body.get("instanceId"), body.get("since"), body.get("waitMs", 5000)
    if (not isinstance(instance, str) or not re.fullmatch(r"[a-f0-9]{32}", instance)
            or type(since) is not int or not 0 <= since <= GPU_SEQUENCE_LIMIT
            or type(wait_ms) is not int or not 0 <= wait_ms <= 5000):
        raise ValueError("Invalid GPU observation cursor")
    deadline = time.monotonic() + wait_ms / 1000
    if not GPU_WATCH_SLOTS.acquire(blocking=False):
        raise GPUWatchBusy()
    with GPU_WATCH_LOCK:
        GPU_WATCHERS += 1
    try:
        while True:
            remaining = max(0, deadline - time.monotonic())
            if not GPU_LOCK.acquire(timeout=min(0.25, remaining)):
                if time.monotonic() >= deadline:
                    raise GPUWatchBusy()
                continue
            try:
                gpu_refresh()
                remaining = deadline - time.monotonic()
                if instance != GPU_INSTANCE_ID or since != GPU_SEQUENCE or remaining <= 0:
                    return {"status": STATE.get("status"), "optimizer": gpu_snapshot(refresh=False)}
                event = GPU_REVISION_EVENT
                expiry = min(GPU_LEASES.values(), default=deadline) - time.monotonic()
            finally:
                GPU_LOCK.release()
            if handler is not None:
                try:
                    readable, _, _ = __import__("select").select([handler.connection], [], [], 0)
                    if readable and handler.connection.recv(1, socket.MSG_PEEK) == b"":
                        raise GPUWatchDisconnected()
                except OSError:
                    raise GPUWatchDisconnected() from None
            # Capture the revision event under the state lock, then wait outside
            # it. Native cleanup cannot strand a condition's lock reacquisition.
            event.wait(timeout=max(0, min(0.25, remaining, expiry)))
    finally:
        with GPU_WATCH_LOCK:
            GPU_WATCHERS -= 1
        GPU_WATCH_SLOTS.release()


def gpu_control(body, handler=None):
    global GPU_ENABLED, GPU_PINNED, GPU_IDLE_SECONDS, GPU_LOADING, GPU_INITIAL, GPU_WAITING_SINCE, GPU_COMMITTING, GPU_GRANT_TERMS
    if not isinstance(body, dict):
        raise ValueError("Invalid optimizer request")
    action = body.get("action")
    if action == "watch":
        return gpu_watch(body, handler)
    with GPU_LOCK:
        gpu_refresh()
        # Rotate the cursor epoch before accepting a CAS at the safe integer limit.
        if GPU_SEQUENCE >= GPU_SEQUENCE_LIMIT:
            gpu_publish(force=True)
        has_instance = "expectedInstanceId" in body
        has_sequence = "expectedSequence" in body
        if has_instance != has_sequence:
            raise ValueError("Incomplete GPU control precondition")
        fenced = has_instance and has_sequence
        if fenced:
            if (not isinstance(body["expectedInstanceId"], str)
                    or not re.fullmatch(r"[a-f0-9]{32}", body["expectedInstanceId"])
                    or type(body["expectedSequence"]) is not int
                    or not 0 <= body["expectedSequence"] <= GPU_SEQUENCE_LIMIT):
                raise ValueError("Invalid GPU control precondition")
            if body["expectedInstanceId"] != GPU_INSTANCE_ID or body["expectedSequence"] != GPU_SEQUENCE:
                raise GPUControlConflict()
        accepted, result = False, {}
        GPU_COMMITTING = True
        try:
            if action == "configure":
                if type(body.get("enabled")) is not bool or type(body.get("pinned", False)) is not bool:
                    raise ValueError("Invalid optimizer settings")
                timeout = body.get("idleTimeoutSeconds", GPU_IDLE_SECONDS)
                if type(timeout) is not int or (timeout != 0 and not 10 <= timeout <= 3600):
                    raise ValueError("Idle timeout must be 0 (keep loaded until switching) or 10–3600 seconds")
                if body["enabled"] and not GPU_ENABLED:
                    GPU_GRANTED.clear()
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
                accepted = True
            elif action in ("grant", "phase"):
                if fenced and (not GPU_ENABLED or GPU_LOADING or GPU_ACTIVE or GPU_RELEASE_UNCERTAIN or GPU_GRANTED.is_set()
                               or STATE.get("status") not in ("idle", "queued", "freeing_memory")
                               or not (GPU_LEASES or GPU_INITIAL)):
                    raise GPUControlConflict()
                if action == "grant":
                    terms = gpu_grant_terms(body)
                    if GPU_ENABLED and not GPU_LOADING and STATE["status"] in ("idle", "queued", "freeing_memory"):
                        GPU_GRANT_TERMS = terms
                        # A startup loader may already be blocked at gpu_before_load.
                        if STATE.get("weightsVerified") and not GPU_WAITING_FOR_GRANT:
                            GPU_LOADING = True
                            threading.Thread(target=load_model, daemon=True).start()
                        GPU_GRANTED.set()
                        accepted = True
                    result["granted"] = accepted
                else:
                    if body.get("phase") not in ("queued", "freeing_memory"):
                        raise ValueError("Invalid GPU phase")
                    if STATE["status"] in ("idle", "queued", "freeing_memory"):
                        STATE["status"] = body["phase"]
                        accepted = True
                    result["phased"] = accepted
            elif action == "unload":
                accepted = gpu_unload()
                result["unloaded"] = accepted
                if accepted and STATE.get("parked"):
                    result["parked"] = STATE["parked"]
            elif action == "trim":
                terms = gpu_grant_terms(body)
                if terms is None:
                    raise ValueError("A GPU trim names the bytes and context to hold to")
                snapshot = gpu_snapshot()
                if fenced and (not GPU_ENABLED or GPU_LOADING or GPU_RELEASE_UNCERTAIN or not snapshot["resident"]):
                    raise GPUControlConflict()
                accepted_bytes, accepted_context = gpu_trim(terms)
                result["terms"] = {"bytes": accepted_bytes, "context": accepted_context}
                result["trimmed"] = True
                accepted = True
            elif action == "grow":
                terms = gpu_grant_terms(body)
                if terms is None or not fenced:
                    raise ValueError("A GPU grow is fenced and names the bytes and context to hold to")
                if not GPU_ENABLED or GPU_LOADING or GPU_RELEASE_UNCERTAIN or not gpu_snapshot()["resident"]:
                    raise GPUControlConflict()
                grown_bytes, grown_context = gpu_grow(terms)
                result["terms"] = {"bytes": grown_bytes, "context": grown_context}
                result["grown"] = True
                accepted = True
            else:
                raise ValueError("Invalid optimizer action")
        finally:
            GPU_COMMITTING = False
            # One accepted fenced command consumes exactly one revision, including
            # an idempotent phase. Nested changes cannot publish partial ACKs.
            gpu_publish(force=accepted and fenced)
        result.update(status=STATE.get("status"), optimizer=gpu_snapshot(refresh=False))
        if fenced and accepted:
            result["controlAck"] = {"action": action, "instanceId": GPU_INSTANCE_ID,
                                    "expectedSequence": body["expectedSequence"], "sequence": GPU_SEQUENCE}
        return result


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
                    observer = globals().get("RUNNER_TIMINGS")
                    if observer is not None:
                        observer.capture_demand_load()
                    GPU_LEASES.pop(key, None)
                    GPU_ACTIVE += 1
                    GPU_LAST_USED = time.monotonic()
                    gpu_publish()
                    return True
                if not GPU_ENABLED or STATE["status"] == "error":
                    return False
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                # Nonblocking disconnect check; never consume request bytes.
                readable, _, _ = __import__("select").select([handler.connection], [], [], 0)
                if readable and handler.connection.recv(1, socket.MSG_PEEK) == b"":
                    return False
                # Atomically release the state lock and wait. A completed load
                # cannot notify between our state check and registration as a
                # waiter. Reconcile missed notifications and disconnects as before.
                GPU_CHANGED.wait(timeout=min(0.25, remaining))
    finally:
        with GPU_LOCK:
            GPU_LEASES.pop(key, None)
            gpu_publish()


def gpu_leave():
    global GPU_ACTIVE, GPU_LAST_USED
    with GPU_LOCK:
        GPU_ACTIVE = max(0, GPU_ACTIVE - 1)
        GPU_LAST_USED = time.monotonic()
        gpu_publish()


def gpu_route(handler):
    if handler.path not in ("/v1/yougori/prepare", "/v1/yougori/release", "/v1/yougori/optimizer"):
        return False
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if not 0 < length <= 1024 or handler.headers.get("Transfer-Encoding"):
            raise ValueError("Invalid optimizer request")
        body = json.loads(handler.rfile.read(length))
        if not isinstance(body, dict):
            raise ValueError("Invalid optimizer request")
        if handler.path.endswith("optimizer"):
            # X-Yougori-Client is not authorization. Control requires a separate
            # credential kept in the container and local engine, never in public API keys.
            expected = os.environ.get("YOUGORI_GPU_CONTROL_TOKEN", "")
            supplied = handler.headers.get("X-Yougori-GPU-Control", "")
            if not expected or not supplied.isascii() or not secrets.compare_digest(expected, supplied):
                handler.reply(403, {"error": {"message": "Local GPU control credential required"}})
                return True
            value = gpu_control(body, handler)
        elif handler.path.endswith("release"):
            with GPU_LOCK:
                GPU_LEASES.pop(body.get("lease"), None)
                gpu_refresh()
            value = {"released": True}
        else:
            value = gpu_prepare(body.get("lease"))
        handler.reply(200, value)
    except GPUControlConflict:
        with GPU_LOCK:
            snapshot = gpu_snapshot()
            value = {"error": {"message": "GPU state changed. Observe current state before retrying."},
                     "status": STATE.get("status"), "optimizer": snapshot}
        handler.reply(409, value)
    except GPUWatchBusy:
        handler.reply(429, {"error": {"message": "GPU observation capacity is full. Retry later."}})
    except GPUWatchDisconnected:
        pass
    except (ValueError, TypeError, OSError):
        handler.reply(400, {"error": {"message": "Invalid GPU preparation request"}})
    except Exception:
        # Native process exceptions can contain argv, including private API keys.
        handler.reply(503, {"error": {"message": "GPU control failed. Check model status before retrying."}})
    return True
