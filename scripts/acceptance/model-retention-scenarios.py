"""Preparation, retention and pressure scenarios on an isolated acceptance engine (G05, E03).

Two local models: A (a GGUF on llama.cpp) and B (safetensors on the Transformers runner).
  S1  A prepared, then used through its own loopback API (not the engine's chat path): the
      preparation must count that use and keep the model serving.
  S2  A prepared and never used: its keep ends, the preparation stops it and accounts for the
      load and the GPU memory it held for nothing.
  S3  B resident and serving; A prepared beside it: B is never parked or trimmed for the
      preparation, which loads only into free memory or waits.
  S4  A prepared, then cancelled while it loads: stopped, nothing left.
  S5  A second environment with the same files: its preparation is refused while A's runs.
  S6  Outside GPU pressure (host torch) leaves no room: B's start waits; released, B loads.
Every response is retained; nothing is retried. Only this run's environments are removed.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

spec = importlib.util.spec_from_file_location("combined", Path(__file__).with_name("combined-model-vm.py"))
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)


class Scenarios(combined.Combined):
    def __init__(self, args):
        super().__init__(args)
        self.args = args
        self.environments = {}
        self.keys = {}
        self.env["YOUGORI_CATALOG_ROOT"] = str(args.catalog_root.resolve())
        self.env["YOUGORI_CATALOG_QUOTA_BYTES"] = str(16 * 1024 ** 3)

    def create(self, name, folder, port, memory, quant=None):
        params = {"model": "local/" + name, "folder": str(folder), "port": port, "resources": {"memoryGb": memory}}
        if quant:
            params["quant"] = quant
        created = self.result("run_model", params, f"create-{name}")
        self.environments[name] = created["id"]
        self.keys[name] = (port, created["apiKey"])
        return created["id"]

    def status(self, name, label=None):
        return self.result("model_status", {"environmentId": self.environments[name]}, label)

    def ready(self, name, limit=1800):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            reply = self.call("model_status", {"environmentId": self.environments[name]}, None, checked=False)
            if reply.get("ok") and reply["result"].get("status") == "ready":
                return reply["result"]
            if reply.get("ok") and reply["result"].get("status") == "error":
                raise RuntimeError(f"{name} failed; status retained")
            time.sleep(1)
        raise TimeoutError(f"{name} not ready")

    def stopped(self, name, limit=300):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            state = self.result("get_platform_state", {})
            row = next(r for r in state["environments"] if r["id"] == self.environments[name])
            if row["status"] == "stopped":
                return
            time.sleep(1)
        raise TimeoutError(f"{name} did not stop")

    def stop(self, name=None):
        if name is None:
            return super().stop()
        self.result("stop_model", {"environmentId": self.environments[name]}, f"stop-{name}")
        self.stopped(name)

    def prepare(self, action, label, **fields):
        return self.result("model_prepare", {"action": action, **fields}, label)

    def entry(self, name):
        status = self.prepare("status", None)
        for row in status["preparations"]:
            if row["environment"] == self.environments[name]:
                return row, status
        return None, status

    def until_prepared(self, name, states, limit, label):
        deadline = time.monotonic() + limit
        while time.monotonic() < deadline:
            row, status = self.entry(name)
            if row and (row["state"] in states or row["finished"]):
                self.write(label, {"entry": row, "accounting": status.get("accounting")})
                return row, status
            time.sleep(1)
        raise TimeoutError(f"{name} preparation did not reach {states}")

    def request(self, name, label, count=32):
        port, key = self.keys[name]
        body = json.dumps({"model": "local/" + name, "messages": [{"role": "user", "content": "Name three uses of a hash function."}],
                           "temperature": 0, "max_tokens": count, "stream": True}).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{port}/v1/chat/completions", data=body,
                                         headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
        begin = time.perf_counter()
        first = None
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=600) as response:
            for line in response:
                if line.startswith(b"data:") and b'"content"' in line and first is None:
                    first = time.perf_counter()
        record = {"first_text_ms": None if first is None else (first - begin) * 1000, "seconds": time.perf_counter() - begin}
        self.write(label, record)
        return record

    def run(self):
        self.start()
        self.host_memory("host-before")
        self.ledger("ledger-before")
        a = self.create("prep-gguf", self.args.gguf, self.args.port, 6, quant="Q4_K_M")
        b = self.create("prep-transformers", self.args.model, self.args.port + 1, 8)
        self.ready("prep-gguf")
        self.ready("prep-transformers")
        self.stop("prep-gguf")
        self.stop("prep-transformers")
        results = {}

        # S1: prepared, used through the loopback API only.
        started = self.prepare("start", "s1-start", environment=a, readyWithinSeconds=600, keepSeconds=120)
        row, _ = self.until_prepared("prep-gguf", {"ready"}, 900, "s1-ready")
        used = self.request("prep-gguf", "s1-loopback-request")
        row, status = self.until_prepared("prep-gguf", set(), 60, "s1-finished")
        health = self.status("prep-gguf", "s1-health-after")
        results["s1"] = {"start": started, "entry": row, "request": used, "still_ready": health.get("status") == "ready",
                         "accounting": status["accounting"]}
        assert row["finished"] and row["state"] in ("used",), row
        assert health.get("status") == "ready", "the used model must keep serving"
        self.stop("prep-gguf")

        # S2: prepared, never used: kept 20 s, then stopped and accounted as waste.
        self.prepare("start", "s2-start", environment=a, readyWithinSeconds=600, keepSeconds=20)
        self.until_prepared("prep-gguf", {"ready"}, 900, "s2-ready")
        row, status = self.until_prepared("prep-gguf", set(), 120, "s2-finished")
        self.stopped("prep-gguf")
        results["s2"] = {"entry": row, "accounting": status["accounting"]}
        assert row["state"] == "released", row

        # S3: B resident and serving; A prepared beside it never displaces B.
        self.result("start_model", {"environmentId": b}, "s3-start-b")
        self.ready("prep-transformers")
        self.request("prep-transformers", "s3-b-request")
        before = self.status("prep-transformers", "s3-b-before")
        self.prepare("start", "s3-start", environment=a, readyWithinSeconds=90, keepSeconds=30)
        polls = []
        deadline = time.monotonic() + 150
        while time.monotonic() < deadline:
            bh = self.status("prep-transformers")
            ah = self.call("model_status", {"environmentId": a}, None, checked=False)
            row, _ = self.entry("prep-gguf")
            polls.append({"b_resident": bh.get("optimizer", {}).get("resident"), "b_status": bh.get("status"),
                          "b_capacity": bh.get("optimizer", {}).get("capacityBytes"),
                          "a_status": ah.get("result", {}).get("status") if ah.get("ok") else None,
                          "a_waiting": ah.get("result", {}).get("optimizer", {}).get("waitingFor") if ah.get("ok") else None,
                          "prepare": row})
            if row and row["finished"]:
                break
            time.sleep(2)
        self.write("s3-polls", {"polls": polls})
        results["s3"] = {"b_before": before.get("optimizer"), "polls": len(polls),
                         "b_always_resident": all(p["b_resident"] is True for p in polls),
                         "b_capacity_unchanged": len({p["b_capacity"] for p in polls}) <= 1,
                         "final": polls[-1]["prepare"] if polls else None}
        assert results["s3"]["b_always_resident"], "a preparation displaced a resident model"
        for name in ("prep-gguf",):
            state = self.result("get_platform_state", {})
            if next(r for r in state["environments"] if r["id"] == self.environments[name])["status"] != "stopped":
                self.stop(name)

        # S4: cancelled while loading.
        self.stop("prep-transformers")
        self.prepare("start", "s4-start", environment=a, readyWithinSeconds=600, keepSeconds=60)
        time.sleep(2)
        cancelled = self.prepare("cancel", "s4-cancel", environment=a)
        row, status = self.until_prepared("prep-gguf", set(), 300, "s4-finished")
        self.stopped("prep-gguf")
        results["s4"] = {"cancel": cancelled, "entry": row}

        # S5: the same files in a second environment are not prepared twice.
        twin = self.create("prep-gguf-twin", self.args.gguf, self.args.port + 2, 6, quant="Q4_K_M")
        self.ready("prep-gguf-twin")
        self.stop("prep-gguf-twin")
        self.prepare("start", "s5-start-a", environment=a, readyWithinSeconds=600, keepSeconds=30)
        refused = self.call("model_prepare", {"action": "start", "environment": twin, "readyWithinSeconds": 600, "keepSeconds": 30},
                            "s5-start-twin", checked=False)
        results["s5"] = {"twin_refused": not refused.get("ok"), "reply": refused}
        assert not refused.get("ok"), "a duplicate preparation was admitted"
        self.prepare("cancel", "s5-cancel-a", environment=a)
        self.until_prepared("prep-gguf", set(), 300, "s5-finished")
        self.stopped("prep-gguf")

        # S6: outside GPU pressure leaves no room for B; released, B loads.
        stop_file = self.root / "pressure.stop"
        stop_file.unlink(missing_ok=True)
        free = int(subprocess.run(["nvidia-smi", "--query-gpu=memory.free", "--format=csv,noheader,nounits"],
                                  capture_output=True, text=True).stdout.split()[0])
        gib = max(1, (free - 512) // 1024)
        holder = subprocess.Popen([sys.executable, "-P", "-B", str(self.args.pressure), str(gib), str(stop_file), str(self.root / "pressure.json")],
                                  stdout=subprocess.PIPE, text=True)
        holder.stdout.readline()
        self.result("start_model", {"environmentId": b}, "s6-start-b-under-pressure")
        time.sleep(45)
        waiting = self.call("model_status", {"environmentId": b}, "s6-b-under-pressure", checked=False)
        stop_file.write_text("stop")
        holder.wait(timeout=60)
        released = time.perf_counter()
        health = self.ready("prep-transformers", 900)
        results["s6"] = {"held_gib": gib, "b_under_pressure": waiting.get("result", {}).get("status") if waiting.get("ok") else waiting,
                         "seconds_to_ready_after_release": time.perf_counter() - released, "ready": health.get("status")}
        assert results["s6"]["b_under_pressure"] != "ready", "B loaded although the GPU had no room"

        self.write("results", results)
        final = self.prepare("status", "final-prepare-status")
        self.write("accounting", final.get("accounting"))
        for name in list(self.environments):
            self.result("stop_model", {"environmentId": self.environments[name]}, f"cleanup-stop-{name}")
            self.result("delete_environment", {"environmentId": self.environments.pop(name)}, f"cleanup-delete-{name}")
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            ledger = self.ledger() or {}
            if not ledger.get("open") and not ledger.get("models"):
                break
            time.sleep(1)
        self.write("ledger-final", self.ledger() or {})
        assert not self.result("get_platform_state", {}, "empty-finish")["environments"]
        super().stop()
        self.write("complete", {"results": results})

    def clean(self):
        if self.process is None or self.process.poll() is not None:
            return
        for name in list(self.environments):
            self.call("stop_model", {"environmentId": self.environments[name]}, f"cleanup-model-stop-{name}", checked=False)
            self.call("delete_environment", {"environmentId": self.environments[name]}, f"cleanup-model-delete-{name}", checked=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("root", "engine", "cli", "runtime", "model", "gguf", "catalog-root", "pressure"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--port", type=int, default=18910)
    parser.add_argument("--existing-root", action="store_true")
    args = parser.parse_args()
    args.reuse_fixture = args.existing_root
    args.from_case = 0
    run = Scenarios(args)
    try:
        run.run()
    except BaseException as error:
        run.write("FAILED", {"type": type(error).__name__, "error": str(error)})
        raise
    finally:
        run.clean()
        run.stop()


if __name__ == "__main__":
    main()
