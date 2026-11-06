"""Simultaneous-caller throughput on an isolated acceptance engine (G02, E03/E04).

Measures what callers see when several send requests at once: per-request first text and
completion time, and the aggregate generation rate of each synchronized wave. Every prompt
carries a unique ticket so no request reuses another's prompt cache. A correctness set
compares greedy replies of the same prompts served one at a time and together. Every
attempt, refusal and failure is retained. Measured phases wait for a quiet host (no compiler,
no other program computing on the GPU); a wave, wake or reload during which another program
computed on the GPU is kept in the evidence, marked, and measured again (bounded), and the
aggregates use clean measurements only.

The baseline (an engine without parallel serving) runs with --parallel none: its callers
queue for the one slot. A candidate runs each --parallel value after restarting the model.
--launch compares vLLM launch modes (eager, compiled, speculative) the same way: each mode, with
each --parallel value, is saved, the model restarted, and the launch checked to serve in that
mode without a fallback. --prompt-kind edit asks for a code edit whose reply repeats most of the
prompt, the workload n-gram speculation is for; the default asks for an analysis.
--keep leaves the model environment for another engine on the same data folder; --reuse
serves an existing one instead of creating it (matched runtime, files and guest).
"""
import argparse
import concurrent.futures
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import random
import statistics
import subprocess
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("performance", Path(__file__).with_name("model-performance-benchmark.py"))
performance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(performance)

CORRECTNESS = (
    "List three uses of a hash function, one line each.",
    "Explain what a mutex protects against in two sentences.",
    "Give a one-paragraph summary of how TCP retransmission works.",
    "Name four properties of a good unit test, one line each.",
)
# Desktop processes nvidia-smi lists with a GPU context though they compute nothing measurable.
DESKTOP = {"explorer.exe", "dwm.exe", "searchhost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
           "textinputhost.exe", "msedgewebview2.exe", "widgets.exe", "phoneexperiencehost.exe", "lockapp.exe",
           "whatsapp.root.exe"}
ATTEMPTS = 5
QUIET = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0), "capture_output": True, "text": True, "errors": "replace", "timeout": 30}
COMPILERS = ('"rustc.exe"', '"cargo.exe"', '"link.exe"', '"lld-link.exe"')


class Throughput(performance.Run):
    def __init__(self, args):
        super().__init__(args)
        # Raw GPU samples beside this run's own evidence: a later run in the same root keeps its own.
        self.sampler = performance.Sampler(self.out / f"gpu-samples-{time.strftime('%Y%m%d-%H%M%S')}.jsonl")

    def ticket_prompt(self, base):
        return f"Ticket {uuid.uuid4().hex}.\n" + base

    def health(self, label):
        value = self.result("model_status", {"environmentId": self.environment_id}, label)
        queue = value.get("requestQueue") or {}
        return value, queue

    def ready_fast(self, limit=1800):
        """Readiness polled every 0.25 s, for start-to-ready timings (wait_ready sleeps 2 s)."""
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            reply = self.call("model_status", {"environmentId": self.environment_id}, None, checked=False)
            state = reply.get("result", {}).get("status") if reply.get("ok") else None
            if state == "ready":
                return reply["result"]
            if state == "error":
                raise RuntimeError("Model failed; status retained")
            time.sleep(0.25)
        raise TimeoutError("Model not ready")

    @staticmethod
    def edit_prompt(functions):
        """A code edit: the reply repeats most of the prompt, as an agent's file edits do."""
        rng = random.Random(4417)
        body = "\n".join(f"def measure_{i:04d}(zone, units):\n    \"\"\"Zone {rng.randrange(1, 99)} reading.\"\"\"\n"
                         f"    return round(units * {rng.randrange(2, 9)} / {rng.randrange(10, 99)}, 3)\n" for i in range(functions))
        return ("Rename the parameter units to amount everywhere in this file. Reply with the complete file "
                "and nothing else.\n\n```python\n" + body + "```")

    def set_setting(self, launch, slots):
        """Saves a launch mode and/or a slot count, restarts the model and checks it serves them."""
        name = "-".join(part for part in (launch, slots and f"parallel-{slots}") if part)
        if launch:
            # Through the owner's own command, so a run also proves the CLI reaches the setting.
            saved = self.command("model", "optimize", self.environment_id, "--launch", launch, label=f"{name}-launch-saved")
            assert saved["result"] == {"launch": launch, "restartRequired": True}, saved
        if slots:
            self.result("model_optimizer", {"environmentId": self.environment_id, "parallel": slots}, f"{name}-parallel-saved")
        for attempt in range(ATTEMPTS):
            label = name + (f"-again{attempt}" if attempt else "")
            self.result("stop_model", {"environmentId": self.environment_id}, f"{label}-stop")
            # The model's memory is free while this waits: it never loads beside another program's
            # GPU work (a load into a full GPU spills to shared memory and crawls).
            self.quiet(f"{label}-start")
            with self.watched() as foreign:
                begin = time.perf_counter()
                self.result("start_model", {"environmentId": self.environment_id}, f"{label}-start")
                health = self.ready_fast()
                seconds = time.perf_counter() - begin
                # Warmed up like the baseline's one launch, unmeasured: every setting starts its levels alike.
                warm = self.stream("Explain what a secure sandbox does in two sentences.", f"{label}-warmup", count=32)
            self.write(f"{label}-ready", {"seconds": seconds, "health": health, "foreign_gpu": sorted(foreign)})
            if foreign:
                continue  # kept, marked, loaded again on a quiet host
            # A launch that fell back (to eager or to one slot) must never be reported as the setting asked for.
            observed = (health.get("requestQueue") or {}).get("slots")
            assert not health.get("servingFallback"), (launch, slots, health.get("servingFallback"))
            assert slots is None or observed == slots, (slots, observed)
            assert launch is None or health.get("launch") == launch, (launch, health.get("launch"))
            assert warm["ok"], warm
            return
        raise RuntimeError(f"Another program computed on the GPU during every load of {name}")

    def wave(self, prompt, concurrency, label, count):
        barrier = threading.Barrier(concurrency)
        begin = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [pool.submit(self.stream, self.ticket_prompt(prompt), f"{label}-{i}", count, barrier)
                       for i in range(concurrency)]
            rows = [future.result() for future in futures]
        seconds = time.perf_counter() - begin
        tokens = sum(row.get("output_tokens", 0) for row in rows if row["ok"])
        return rows, {"seconds": seconds, "accepted": sum(row["ok"] for row in rows),
                      "output_tokens": tokens, "aggregate_output_tokens_s": tokens / seconds}

    def correctness(self, setting):
        passes, replies = {}, {}
        for name, together in (("sequential-1", False), ("together", True), ("sequential-2", False)):
            self.kv_reset(f"correctness-{setting}-{name}-reset")
            if together:
                barrier = threading.Barrier(len(CORRECTNESS))
                with concurrent.futures.ThreadPoolExecutor(max_workers=len(CORRECTNESS)) as pool:
                    futures = [pool.submit(self.stream, prompt, f"correctness-{setting}-{name}-{i}", 48, barrier)
                               for i, prompt in enumerate(CORRECTNESS)]
                    rows = [future.result() for future in futures]
            else:
                rows = [self.stream(prompt, f"correctness-{setting}-{name}-{i}", 48) for i, prompt in enumerate(CORRECTNESS)]
            passes[name] = [row.get("reply_sha256") if row["ok"] else None for row in rows]
            replies[name] = [row.get("reply") if row["ok"] else None for row in rows]
        first = passes["sequential-1"]
        prefix = lambda other: [len(os.path.commonprefix([a, b])) if a is not None and b is not None else None
                                for a, b in zip(replies["sequential-1"], replies[other])]
        return {"passes": passes,
                "together_matches_sequential": sum(a is not None and a == b for a, b in zip(first, passes["together"])),
                "sequential_repeat_matches": sum(a is not None and a == b for a, b in zip(first, passes["sequential-2"])),
                "reply_characters": [len(a) if a is not None else None for a in replies["sequential-1"]],
                "together_common_prefix_characters": prefix("together"),
                "repeat_common_prefix_characters": prefix("sequential-2"),
                "prompts": len(CORRECTNESS)}

    @staticmethod
    def foreign_gpu():
        """Programs other than the desktop computing on the GPU, as nvidia-smi lists them (this
        benchmark's model runs inside WSL, whose processes it does not list)."""
        try:
            done = subprocess.run(["nvidia-smi", "--query-compute-apps=pid,process_name", "--format=csv,noheader"], **QUIET)
        except (OSError, subprocess.SubprocessError):
            return ["nvidia-smi did not answer"]
        if done.returncode != 0:
            first = next((line.strip() for line in (done.stdout or done.stderr or "").splitlines() if line.strip()), "no output")
            return [f"nvidia-smi failed (exit {done.returncode}): {first[:120]}"]
        rows = []
        for line in done.stdout.splitlines():
            pid, _, name = line.partition(",")
            name = os.path.basename(name.strip().replace("\\", "/"))
            if name and name.lower() not in DESKTOP:
                rows.append(f"{name} (pid {pid.strip()})")
        return rows

    @staticmethod
    def gpu_utilization():
        """The GPU's highest utilization over about two seconds."""
        highest = 0
        for _ in range(5):
            try:
                value = subprocess.run(["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"], **QUIET).stdout
                highest = max(highest, int(value.split()[0]))
            except (OSError, subprocess.SubprocessError, ValueError, IndexError):
                return 100
            time.sleep(0.5)
        return highest

    @staticmethod
    def compilers():
        try:
            busy = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], **QUIET).stdout.lower()
        except (OSError, subprocess.SubprocessError, AttributeError):
            return ["tasklist did not answer"]
        return [name.strip('"') for name in COMPILERS if name in busy]

    def quiet(self, label):
        """Measured phases wait until no compiler runs on this host (it would contend for CPU and
        memory) and the GPU is quiet: no other program computes on it and, with this model serving
        nothing, it is at most 10% busy (which also covers GPU work inside WSL, whose processes
        nvidia-smi does not list). How long they waited, and for what, is recorded; an hour
        without a quiet host ends the run rather than measure a busy one."""
        self.phase(f"quiet-{label}")
        begin, reasons, gave_up = time.monotonic(), set(), True
        while time.monotonic() - begin < 3600:
            compilers = self.compilers()
            foreign = self.foreign_gpu()
            utilization = self.gpu_utilization() if not compilers and not foreign else None
            if not compilers and not foreign and utilization <= 10:
                gave_up = False
                break
            reasons.update(compilers + foreign + ([f"GPU {utilization}% busy"] if utilization else []))
            time.sleep(10)
        waited = time.monotonic() - begin
        if waited >= 5 or gave_up:
            self.write(f"quiet-{label}", {"waited_seconds": waited, "gave_up_waiting": gave_up, "waited_for": sorted(reasons)})
        if gave_up:
            raise RuntimeError(f"The host was not quiet for an hour before {label}: {sorted(reasons)}")

    @contextmanager
    def watched(self):
        """Every other program seen computing on the GPU while a measurement runs."""
        seen, stop = set(), threading.Event()

        def watch():
            tick = 0
            while not stop.is_set():
                try:
                    seen.update(self.foreign_gpu())
                    if tick % 5 == 0:
                        seen.update(f"compiler {name}" for name in self.compilers())
                except Exception as error:  # a broken watcher must never pass a measurement as clean
                    seen.add(f"watcher failed: {type(error).__name__}")
                tick += 1
                stop.wait(1)
        thread = threading.Thread(target=watch, daemon=True)
        thread.start()
        try:
            yield seen
        finally:
            stop.set()
            thread.join(60)

    def matrix(self, setting, base, levels):
        health, queue = self.health(f"setting-{setting}-health")
        result = {"requestQueue": queue, "capabilities": health.get("capabilities"), "levels": {}}
        for concurrency in levels:
            rows, waves = [], []
            for index in range(self.args.waves):
                for attempt in range(ATTEMPTS):
                    label = f"s{setting}-c{concurrency}-w{index}" + (f"-again{attempt}" if attempt else "")
                    # Every attempt starts on a quiet host and gets its own phase (GPU samples).
                    self.quiet(label)
                    phase = f"setting-{setting}-c{concurrency}-w{index}" + (f"-again{attempt}" if attempt else "")
                    self.phase(phase)
                    with self.watched() as foreign:
                        batch, wave = self.wave(base, concurrency, label, self.args.output_tokens)
                    # GPU work inside WSL never shows as a process: the whole GPU must be idle
                    # again once this model has finished the wave.
                    time.sleep(1)
                    busy = self.gpu_utilization()
                    if busy > 10:
                        foreign.add(f"GPU {busy}% busy after the wave")
                    wave.update(label=label, phase=phase, foreign_gpu=sorted(foreign))
                    waves.append(wave)
                    if not foreign:
                        rows.extend(batch)
                        break
                    # Another program computed on the GPU meanwhile: kept, marked, measured again.
            # Aggregates only over clean waves where every caller completed; a partial or
            # contended wave is listed, never averaged in.
            complete = [w for w in waves if w["accepted"] == concurrency and not w["foreign_gpu"]]
            rates = [w["aggregate_output_tokens_s"] for w in complete]
            result["levels"][str(concurrency)] = {
                **self.summarize(rows), "waves": waves, "complete_waves": len(complete),
                "contended_waves": sum(bool(w["foreign_gpu"]) for w in waves),
                "aggregate_output_tokens_s": {"median": statistics.median(rates), "min": min(rates), "max": max(rates)} if rates else None}
            self.write(f"setting-{setting}-c{concurrency}", result["levels"][str(concurrency)])
        self.phase(f"setting-{setting}-correctness")
        result["correctness"] = self.correctness(setting)
        # Per attempt; a level's figures are its clean attempts' (waves[].phase).
        result["gpu"] = {phase: summary for phase, summary in self.sampler.summary().items() if phase.startswith(f"setting-{setting}-")}
        result["ledger"] = self.ledger(f"setting-{setting}-ledger")
        return result

    def loading(self, base):
        """Retained-process wakes (idle unload, then the first request) and stopped-process reloads
        with the model's files kept, each followed by a measured request: what bringing a known
        model back costs, separate from first setup."""
        result = {"wakes": [], "reloads": []}
        for index in range(self.args.wakes * 2):
            if sum(not row["foreign_gpu"] for row in result["wakes"]) == self.args.wakes:
                break
            self.quiet(f"wake-{index}")
            self.phase(f"wake-{index}")
            self.result("model_optimizer", {"environmentId": self.environment_id, "enabled": True, "pinned": False,
                                            "idleTimeoutSeconds": 10}, f"wake-{index}-idle-setting")
            deadline = time.monotonic() + 180
            while time.monotonic() < deadline:
                health = self.result("model_status", {"environmentId": self.environment_id})
                if health.get("status") == "idle" and health.get("optimizer", {}).get("resident") is False:
                    break
                time.sleep(0.5)
            else:
                raise TimeoutError("The model never unloaded after its idle timeout")
            time.sleep(1)
            with self.watched() as foreign:
                request = self.stream(self.ticket_prompt(base), f"wake-{index}-request", 32)
            health = self.result("model_status", {"environmentId": self.environment_id}, f"wake-{index}-health")
            result["wakes"].append({"request": request, "load": health.get("load"), "reload": health.get("reload"), "foreign_gpu": sorted(foreign)})
            self.result("model_optimizer", {"environmentId": self.environment_id, "enabled": True, "pinned": False,
                                            "idleTimeoutSeconds": 0}, f"wake-{index}-idle-restored")
        for index in range(self.args.reloads * 2):
            if sum(not row["foreign_gpu"] for row in result["reloads"]) == self.args.reloads:
                break
            self.quiet(f"reload-{index}")
            self.phase(f"reload-{index}")
            self.result("stop_model", {"environmentId": self.environment_id}, f"reload-{index}-stop")
            with self.watched() as foreign:
                begin = time.perf_counter()
                self.result("start_model", {"environmentId": self.environment_id}, f"reload-{index}-start")
                health = self.ready_fast()
                ready = time.perf_counter() - begin
                request = self.stream(self.ticket_prompt(base), f"reload-{index}-request", 32)
            result["reloads"].append({"start_to_ready_seconds": ready, "request": request, "load": health.get("load"), "foreign_gpu": sorted(foreign)})
        # Summaries over clean measurements; contended ones stay listed above.
        ok = lambda rows: [row["request"] for row in rows if row["request"]["ok"] and not row["foreign_gpu"]]
        result["summary"] = {"wake_first_text_ms": [r["first_text_ms"] for r in ok(result["wakes"])],
                             "reload_start_to_ready_seconds": [row["start_to_ready_seconds"] for row in result["reloads"] if not row["foreign_gpu"]],
                             "reload_first_text_ms": [r["first_text_ms"] for r in ok(result["reloads"])]}
        self.write("loading", result)
        return result

    def existing(self):
        for row in self.result("get_platform_state", {}, "reuse-state")["environments"]:
            if row.get("name") == self.args.reuse:
                return row
        raise RuntimeError("No environment named " + self.args.reuse)

    def run(self):
        self.start()
        self.sampler.start()
        self.phase("setup")
        self.host_memory("host-before")
        self.ledger("ledger-before")
        slot_counts = [None] if self.args.parallel == "none" else [int(v) for v in self.args.parallel.split(",")]
        launches = [None] if self.args.launch == "none" else self.args.launch.split(",")
        settings = [(launch, slots) for launch in launches for slots in slot_counts]
        levels = [int(v) for v in self.args.concurrency.split(",")]
        self.write("plan", {"model": self.args.model_id, "parallel": self.args.parallel, "launch": self.args.launch,
                            "prompt_kind": self.args.prompt_kind, "concurrency": levels,
                            "waves": self.args.waves, "output_tokens": self.args.output_tokens,
                            "prompt_tokens_target": self.args.prompt_tokens, "temperature": 0, "runner": self.args.runner,
                            "prompts": "unique ticket per request; no prompt-cache reuse between requests",
                            "correctness": "greedy replies of 4 fixed prompts: sequential, together, sequential again",
                            "reuse": self.args.reuse, "keep": self.args.keep})
        if self.args.reuse:
            row = self.existing()
            self.environment_id = row["id"]
            self.result("start_model", {"environmentId": self.environment_id}, "reuse-start")
            access = self.result("model_api", {"environmentId": self.environment_id, "port": self.port}, "reuse-api")
            self.created = {"id": row["id"], "apiKey": access["apiKey"]}
        else:
            assert not self.result("get_platform_state", {}, "empty-start")["environments"]
            # A safetensors repository served by vLLM has no GGUF quantization to choose.
            selection = {"model": self.args.model_id, **({"quant": self.args.quant} if self.args.quant else {})}
            if not self.args.repository:
                selection["folder"] = str(self.model)
            checked = self.result("model_preflight", selection, "preflight")
            if self.args.expected_revision:
                assert checked["revision"] == self.args.expected_revision, "Repository revision changed"
            begin = time.perf_counter()
            submitted = self.command("call", "run_model", "--yes", "--no-wait", "--file", "-", params={
                **selection, "port": self.port, "resources": {"storageDrive": self.args.storage_drive, "cpu": 8,
                                                                "memoryGb": self.args.memory_gb, "agentApi": True,
                                                                **({"runner": self.args.runner} if self.args.runner else {})}}, label="submitted")
            job = submitted["result"]["jobId"]
            deadline = time.monotonic() + 5400
            while time.monotonic() < deadline:
                status = self.result("jobs_get", {"jobId": job, "wait": 1000})
                if status["status"] == "complete":
                    self.created = status["result"]
                    self.environment_id = self.created["id"]
                    break
                if status["status"] in ("failed", "cancelled", "interrupted"):
                    self.write("creation-terminal", status)
                    raise RuntimeError("Creation failed; job evidence retained")
                time.sleep(1)
            else:
                raise TimeoutError("Model creation exceeded 90 minutes")
            self.write("created", {"seconds": time.perf_counter() - begin})
        health = self.wait_ready()
        self.write("ready", {"health": health})
        warm = self.stream("Explain what a secure sandbox does in two sentences.", "warmup", count=32)
        assert warm["ok"], warm
        kinds = self.args.prompt_kind.split(",")
        bases = {"analysis": self.prompt(max(1, self.args.prompt_tokens // 27)),
                 "edit": self.edit_prompt(max(1, self.args.prompt_tokens // 34))}
        base = bases[kinds[0]]
        results = {}
        for launch, slots in settings:
            if launch is not None or slots is not None:
                self.set_setting(launch, slots)
            key = "-".join(str(part) for part in (launch, slots) if part is not None) or "none"
            # Every prompt kind on the same launch: one load per setting.
            for kind in kinds:
                name = key if len(kinds) == 1 else f"{key}-{kind}"
                results[name] = self.matrix(name, bases[kind], levels)
        results["loading"] = self.loading(base)
        self.phase("cleanup")
        if self.args.keep:
            self.result("stop_model", {"environmentId": self.environment_id}, "keep-stop")
            self.environment_id = None
        else:
            self.clean()
            assert not self.result("get_platform_state", {}, "empty-finish")["environments"]
            ledger = self.ledger("ledger-cleanup") or {}
            assert not ledger.get("open") and not ledger.get("models"), ledger
        time.sleep(2)
        self.sampler.stop()
        self.stop()
        self.write("complete", {"results": results, "gpu": self.sampler.summary(), "all_attempts_retained": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "engine", "cli", "runtime", "model", "catalog-root"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--model-id", default="local/throughput-benchmark")
    parser.add_argument("--quant", default="Q4_K_M")
    parser.add_argument("--port", type=int, default=18894)
    parser.add_argument("--repository")
    parser.add_argument("--expected-revision")
    parser.add_argument("--parallel", default="none", help="none, or comma-separated slot counts (candidate only)")
    parser.add_argument("--launch", default="none", help="none, or comma-separated vLLM launch modes: eager, compiled, speculative")
    parser.add_argument("--prompt-kind", default="analysis", help="analysis, edit, or both comma-separated")
    parser.add_argument("--runner", choices=("auto", "vllm"), help="vllm serves a safetensors repository with vLLM")
    parser.add_argument("--concurrency", default="1,2,4,8")
    parser.add_argument("--waves", type=int, default=3)
    parser.add_argument("--output-tokens", type=int, default=128)
    parser.add_argument("--prompt-tokens", type=int, default=512)
    parser.add_argument("--memory-gb", type=int, default=24)
    parser.add_argument("--storage-drive", default="D:\\")
    parser.add_argument("--reuse", help="name of an existing model environment to serve")
    parser.add_argument("--wakes", type=int, default=2)
    parser.add_argument("--reloads", type=int, default=2)
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--existing-root", action="store_true", help="continue evidence in an existing root")
    args = parser.parse_args()
    if not args.prompt_kind or set(args.prompt_kind.split(",")) - {"analysis", "edit"}:
        parser.error("--prompt-kind takes analysis, edit or both")
    if args.repository:
        args.model_id = args.repository
    args.reuse_fixture = args.existing_root or bool(args.reuse)
    args.from_case = 0
    args.samples = 3
    args.expected_sha256 = None
    run = Throughput(args)
    try:
        run.run()
    except BaseException as error:
        run.write("FAILED", {"type": type(error).__name__, "error": str(error)})
        raise
    finally:
        if not args.keep:
            run.clean()
        run.stop()
        run.sampler.stop()


if __name__ == "__main__":
    main()
