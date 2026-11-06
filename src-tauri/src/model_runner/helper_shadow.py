"""The shadow runner of the model server (G08, the shadow stage; see model_server.py's
`shadow_attach`). The engine writes this file beside the shadow candidates it serves a runner
(`/yougori-helpers/shadow/yougori-shadow.py`, read-only); the model server executes it once, when
YOUGORI_HELPERS_SHADOW names a candidate, and calls `attach` after each serving helper it
executes and `snapshot` for /health.
"""
import copy
import json
import os
import queue
import threading
import time
import tracemalloc
from functools import wraps


# G08, the shadow stage: a candidate the rollout proposed runs beside the helper that serves
# and never serves. YOUGORI_HELPERS_SHADOW names it as YOUGORI_HELPERS names a bundle. Its entry
# is executed into a namespace of its own, a copy of the names the serving helper was executed
# into, and its decision points (SHADOW_POINTS) are called by one worker thread with copies of
# the inputs each serving call received and of the state it read, after the serving call
# returned. What serves is never changed or delayed: the serving result or exception goes back
# as it was, the comparison is queued (a full queue is counted as dropped, never waited on), and
# a candidate's exception, difference or hang is only counted. Results are compared exactly;
# both sides' time and the Python allocations during the candidate's calls are measured (the
# peak is process-wide, so an upper bound). The engine's trial reads the counts from /health
# (`helperShadow`) and decides the shadow stage on them.
SHADOW_POINTS = {
    # A grant's terms and the demand this runner holds itself to: functions of the grant body
    # and of the terms of the last grant.
    "gpu-optimizer": (("gpu_grant_terms", ()), ("gpu_capacity_demand", ("GPU_GRANT_TERMS",))),
    # The manifest the verifier reads and the files it resolves, before any byte is hashed.
    "registry-verifier": (("registry_manifest", ()), ("registry_artifacts", ())),
    # The llama.cpp and vLLM loaders: the launch facts a runner reports on every /health, and
    # the name a vLLM request is served under (an attached adapter or the model).
    "engine-backends": (("backend_capabilities", ("ADAPTERS", "LLAMA")), ("vllm_model", ("ADAPTERS",))),
}
HELPERS_SHADOW = {}
SHADOW_LOCK = threading.Lock()
SHADOW_QUEUE = queue.Queue(maxsize=64)
SHADOW_WORKER = []
SHADOW_HANG_SECONDS = 10


def shadow_candidates():
    """The shadow candidates YOUGORI_HELPERS_SHADOW names, validated like YOUGORI_HELPERS."""
    raw = os.environ.get("YOUGORI_HELPERS_SHADOW", "")
    if not raw:
        return {}
    try:
        named = json.loads(raw)
    except ValueError:
        raise RuntimeError("YOUGORI_HELPERS_SHADOW is not JSON; no shadow candidate runs") from None
    if not isinstance(named, dict) or len(named) > 16:
        raise RuntimeError("YOUGORI_HELPERS_SHADOW is not an object of at most 16 helpers")
    for name, entry in named.items():
        if (not isinstance(name, str) or not isinstance(entry, dict) or not isinstance(entry.get("entry"), str)
                or not isinstance(entry.get("pin"), str) or set(entry) - {"entry", "pin"}):
            raise RuntimeError("YOUGORI_HELPERS_SHADOW names a helper without its entry and pin")
    return named


def shadow_outcome(kind, value):
    """A comparable outcome: a result, or an exception by its type and message."""
    if kind == "error":
        return ("error", type(value).__name__, str(value))
    return ("result", value)


def shadow_brief(outcome):
    return {"kind": outcome[0], "value": (outcome[1] + ": " + outcome[2]) if outcome[0] == "error" else repr(outcome[1])[:300]}


def shadow_worker():
    while True:
        item = SHADOW_QUEUE.get()
        try:
            shadow_compare(*item)
        except Exception:  # noqa: BLE001 - the worker outlives any comparison
            pass
        finally:
            SHADOW_QUEUE.task_done()


def shadow_compare(helper, point, candidate, namespace, state, args, kwargs, outcome, serving_nanos):
    record = HELPERS_SHADOW.get(helper)
    if record is None:
        return
    try:
        with SHADOW_LOCK:
            record["inFlightSince"] = time.monotonic()
        namespace.update(state)
        tracing = not tracemalloc.is_tracing()
        if tracing:
            tracemalloc.start()
        tracemalloc.reset_peak()
        started = time.perf_counter_ns()
        try:
            shadow = shadow_outcome("result", candidate(*args, **kwargs))
        except Exception as error:  # the candidate's failure, counted below
            shadow = shadow_outcome("error", error)
        elapsed = time.perf_counter_ns() - started
        peak = tracemalloc.get_traced_memory()[1]
        if tracing:
            tracemalloc.stop()
        with SHADOW_LOCK:
            record["inFlightSince"] = None
            record["calls"] += 1
            record["servingNanos"] += serving_nanos
            record["candidateNanos"] += elapsed
            record["candidateMaxNanos"] = max(record["candidateMaxNanos"], elapsed)
            record["candidatePeakBytes"] = max(record["candidatePeakBytes"], peak)
            if shadow == outcome:
                record["agreed"] += 1
            else:
                record["disagreed"] += 1
                if shadow[0] == "error":
                    record["candidateErrors"] += 1
                if len(record["differences"]) < 4:
                    record["differences"].append({"point": point, "serving": shadow_brief(outcome), "candidate": shadow_brief(shadow)})
    except Exception as error:  # the comparison itself failed: the candidate's call is not trusted
        with SHADOW_LOCK:
            record["inFlightSince"] = None
            record["candidateErrors"] += 1
            if len(record["differences"]) < 4:
                record["differences"].append({"point": point, "comparison": type(error).__name__ + ": " + str(error)[:200]})


def shadowed(helper, point, serving, candidate, namespace, state, source):
    """`serving`, unchanged in what it returns or raises, with every call compared in shadow."""
    @wraps(serving)
    def call(*args, **kwargs):
        try:
            copied = copy.deepcopy((args, kwargs, {name: source.get(name) for name in state}))
        except Exception:  # an input a comparison cannot copy is not compared
            copied = None
        started = time.perf_counter_ns()
        try:
            result = serving(*args, **kwargs)
        except Exception as error:
            outcome = shadow_outcome("error", error)
            shadow_enqueue(helper, point, candidate, namespace, copied, outcome, time.perf_counter_ns() - started)
            raise
        shadow_enqueue(helper, point, candidate, namespace, copied, shadow_outcome("result", result), time.perf_counter_ns() - started)
        return result
    return call


def shadow_enqueue(helper, point, candidate, namespace, copied, outcome, serving_nanos):
    record = HELPERS_SHADOW[helper]
    with SHADOW_LOCK:
        if copied is None:
            record["uncompared"] += 1
            return
        try:
            SHADOW_QUEUE.put_nowait((helper, point, candidate, namespace, copied[2], copied[0], copied[1], outcome, serving_nanos))
        except queue.Full:
            record["dropped"] += 1


def shadow_attach(name, source, base=None, helpers_root="/yougori-helpers"):
    """Runs helper `name`'s shadow candidate, if YOUGORI_HELPERS_SHADOW names one, beside the
    serving helper just executed into `source`. The candidate is executed into a copy of `base`,
    the names from before the serving helper was executed (so nothing the serving helper
    defined stands in for what the candidate lacks), and must define each decision point
    itself. Never raises: a candidate that cannot be loaded is recorded as failed and what
    serves is untouched."""
    try:
        entry = shadow_candidates().get(name)
    except RuntimeError as error:
        HELPERS_SHADOW[name] = {"pin": None, "loadError": str(error), "points": []}
        return
    if entry is None:
        return
    record = {"pin": entry["pin"], "points": [], "loadError": None, "calls": 0, "agreed": 0, "disagreed": 0,
              "candidateErrors": 0, "dropped": 0, "uncompared": 0, "servingNanos": 0, "candidateNanos": 0,
              "candidateMaxNanos": 0, "candidatePeakBytes": 0, "inFlightSince": None, "differences": []}
    HELPERS_SHADOW[name] = record
    points = SHADOW_POINTS.get(name)
    if not points:
        record["loadError"] = "the " + name + " helper has no decision points a shadow can compare"
        return
    try:
        path = os.path.realpath(entry["entry"])
        root = os.path.realpath(helpers_root)
        if os.path.commonpath([path, root]) != root:
            raise RuntimeError("the shadow candidate names a file outside " + helpers_root)
        with open(path, "rb") as handle:
            code = handle.read(16 * 1024 * 1024 + 1)
        if len(code) > 16 * 1024 * 1024:
            raise RuntimeError("the shadow candidate's file is larger than 16 MiB")
        namespace = dict(source if base is None else base)
        for point, _state in points:
            namespace.pop(point, None)
        exec(compile(code, "yougori-shadow-" + name, "exec"), namespace)
    except Exception as error:  # a candidate that does not load has failed its shadow
        record["loadError"] = type(error).__name__ + ": " + str(error)[:200]
        record["candidateErrors"] += 1
        return
    for point, state in points:
        serving, candidate = source.get(point), namespace.get(point)
        if not callable(serving) or not callable(candidate):
            record["loadError"] = "the candidate or the serving helper lacks " + point
            record["candidateErrors"] += 1
            continue
        source[point] = shadowed(name, point, serving, candidate, namespace, state, source)
        record["points"].append(point)
    with SHADOW_LOCK:
        if not SHADOW_WORKER:
            worker = threading.Thread(target=shadow_worker, name="yougori-helper-shadow", daemon=True)
            worker.start()
            SHADOW_WORKER.append(worker)


def shadow_snapshot():
    """What every shadow candidate showed so far, for /health; a call running longer than
    SHADOW_HANG_SECONDS is reported as a hang."""
    with SHADOW_LOCK:
        now = time.monotonic()
        snapshot = {}
        for name, record in HELPERS_SHADOW.items():
            view = {key: value for key, value in record.items() if key != "inFlightSince"}
            since = record.get("inFlightSince")
            view["hung"] = since is not None and now - since > SHADOW_HANG_SECONDS
            view["queued"] = SHADOW_QUEUE.qsize()
            view["differences"] = list(record.get("differences", []))
            snapshot[name] = view
        return snapshot


attach = shadow_attach
snapshot = shadow_snapshot
