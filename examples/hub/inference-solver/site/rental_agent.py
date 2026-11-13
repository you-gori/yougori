"""Runs on a GPU this website rented with its administrator's provider account (neocloud.py
starts it): starts the model on the machine's loopback with the pinned serving runtime, then
serves the website's requests over outbound connections, as a connected computer does
(compute_node.py). Nothing listens on the machine's public addresses, and the model's key never
leaves it. The website deletes the GPU when its model cannot start.

Environment: YOUGORI_SERVER (the website), YOUGORI_AGENT_TOKEN (this GPU's credential there),
YOUGORI_MODEL (the Hugging Face model).
"""
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.request

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compute_adapter import Adapter
from compute_node import ACK_WAIT, CAPACITY, Link, SiteError, receive

PORT = 8000
# The longest context served, as Yougori's engine caps it.
CONTEXT = 32768
# Requests the model generates together; the website sends at most CAPACITY at once.
SEQUENCES = 16
LOG = Path("/var/log/yougori-model.log")


def context_length(model):
    """The model's own context (max_position_embeddings in its config), at most CONTEXT."""
    try:
        with urllib.request.urlopen("https://huggingface.co/" + model + "/resolve/main/config.json", timeout=60) as response:
            config = json.loads(response.read(1024 * 1024))
        return max(256, min(int(config.get("max_position_embeddings") or 8192), CONTEXT))
    except (OSError, ValueError, TypeError, AttributeError):
        return 8192


def gpu_count():
    try:
        listed = subprocess.run(["nvidia-smi", "-L"], capture_output=True, text=True, timeout=30).stdout
        return max(1, sum(1 for line in listed.splitlines() if line.startswith("GPU ")))
    except (OSError, subprocess.SubprocessError):
        return 1


def fitted_length(log):
    """The context the runtime said fits this GPU's memory, when it refused a longer one."""
    found = re.findall(r"estimated maximum model length is (\d+)", log)
    return int(found[-1]) if found else None


def last_error(log):
    """The runtime's own last error line, shortened, for the administrator."""
    lines = [line.strip() for line in log.splitlines() if line.strip()]
    errors = [line for line in lines if re.search(r"Error|error:|CUDA|out of memory", line)]
    return re.sub(r"\s+", " ", (errors or lines or ["the model server stopped."])[-1])[:180]


def healthy():
    connection = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    try:
        connection.request("GET", "/health")
        return connection.getresponse().status == 200
    except (OSError, http.client.HTTPException):
        return False
    finally:
        connection.close()


class Model:
    """The model server on this machine's loopback, and what to tell the website of it."""

    def __init__(self, model, key, log=LOG):
        self.model, self.key, self.log = model, key, log
        self.context, self.gpus = context_length(model), gpu_count()
        self.process, self.retried = None, False
        self.state, self.detail = "loading", "Downloading and loading " + model + "."

    def command(self):
        return [sys.executable, "-m", "vllm.entrypoints.cli.main", "serve", self.model, "--served-model-name", self.model,
                "--host", "127.0.0.1", "--port", str(PORT), "--max-model-len", str(self.context),
                "--tensor-parallel-size", str(self.gpus), "--distributed-executor-backend", "mp" if self.gpus > 1 else "uni",
                "--gpu-memory-utilization", "0.90", "--max-num-seqs", str(SEQUENCES),
                "--enable-prompt-tokens-details", "--generation-config", "vllm"]

    def start(self):
        environment = {name: value for name, value in os.environ.items() if name != "YOUGORI_AGENT_TOKEN"}
        environment.update(VLLM_API_KEY=self.key, VLLM_NO_USAGE_STATS="1", HF_HUB_DISABLE_TELEMETRY="1")
        self.log.parent.mkdir(parents=True, exist_ok=True)
        with open(self.log, "ab") as output:
            self.process = subprocess.Popen(self.command(), stdout=output, stderr=subprocess.STDOUT, env=environment)

    def check(self):
        """Ready once the server answers its health route. A server that stopped starts once more
        with the context the runtime said fits; otherwise the model failed."""
        if self.state == "failed":
            return
        if self.process.poll() is None:
            if self.state != "ready" and healthy():
                self.state, self.detail = "ready", "Serving " + self.model + "."
            return
        log = self.log.read_text(encoding="utf-8", errors="replace")[-20000:] if self.log.exists() else ""
        fitted = fitted_length(log)
        if fitted and not self.retried and 256 <= fitted < self.context:
            self.retried, self.context = True, fitted
            self.state, self.detail = "loading", f"Loading {self.model} again with a {fitted}-token context, which fits this GPU."
            self.start()
            return
        self.state, self.detail = "failed", "The model could not start: " + last_error(log)

    def report(self):
        """This GPU's inventory for the website, with the context its server was started with."""
        return {"action": "inventory", "platform": "Linux", "capacity": CAPACITY, "media": False,
                "models": [{"id": "model", "name": self.model, "state": "ready" if self.state == "ready" else "unavailable",
                            "shared": True, "slots": SEQUENCES, "context": self.context}],
                "detail": self.detail, "failed": self.state == "failed"}


def serve(link, token, runtime, adapter, stopped, tick=1.0):
    """Reports the model and serves the website's requests until the website revokes this GPU
    (it was stopped) or `stopped` is set."""
    slots = threading.BoundedSemaphore(CAPACITY)
    polling, revoked = threading.Event(), threading.Event()

    def request(payload):
        return link.post("/api/compute/agent", payload, token)

    def send(data):
        for attempt in range(3):
            try:
                return request({"action": "chunk", **data})
            except SiteError as error:
                if error.status != 503 or attempt == 2:
                    raise
            except (OSError, http.client.HTTPException):
                if attempt == 2:
                    raise
            time.sleep(1)

    def quietly(action, data, attempts=1):
        for _ in range(attempts):
            try:
                return request({"action": action, **data})
            except Exception:
                time.sleep(.5)

    def infer(task, acknowledge):
        try:
            if acknowledge:
                threading.Thread(target=quietly, args=("ack", {"id": task["id"]}, 4), daemon=True).start()
            adapter.inference(task, send)
        finally:
            slots.release()

    def take(task):
        if slots.acquire(timeout=ACK_WAIT):
            infer(task, True)
        else:
            quietly("chunk", {"id": task["id"], "sequence": 0, "status": 429, "done": True})

    def listen():
        while not stopped.is_set() and not revoked.is_set():
            try:
                if not receive(link, token, lambda task: threading.Thread(target=take, args=(task,), daemon=True).start(),
                               stopped, connected=polling.clear):
                    polling.set()
                    return
            except SiteError as error:
                if error.status == 401:
                    revoked.set()
                    return
                stopped.wait(5)
            except Exception:
                stopped.wait(2)

    threading.Thread(target=listen, daemon=True).start()
    reported, said = 0, None
    while not stopped.is_set() and not revoked.is_set():
        try:
            runtime.check()
            # The context may shrink once (a retry that fits the GPU): replies are trimmed to it.
            if "model" in adapter.apis and getattr(runtime, "context", None):
                adapter.apis["model"]["context"] = runtime.context
            now = (runtime.state, runtime.detail)
            if now != said or time.monotonic() - reported > 10:
                request(runtime.report())
                if now != said:
                    print(runtime.detail, flush=True)
                reported, said = time.monotonic(), now
            if polling.is_set() and runtime.state == "ready" and slots.acquire(blocking=False):
                try:
                    task = request({"action": "poll"})
                    if "inference" in task:
                        threading.Thread(target=infer, args=(task["inference"], False), daemon=True).start()
                    else:
                        slots.release()
                except Exception:
                    slots.release()
                    raise
        except SiteError as error:
            if error.status == 401:
                revoked.set()
                break
            stopped.wait(5)
        except Exception:
            stopped.wait(5)
        stopped.wait(tick)
    return revoked.is_set()


def main():
    server, token, model = os.environ["YOUGORI_SERVER"], os.environ["YOUGORI_AGENT_TOKEN"], os.environ["YOUGORI_MODEL"]
    key = secrets.token_urlsafe(32)
    runtime = Model(model, key)
    runtime.start()
    adapter = Adapter(None, Path(__file__).resolve().parents[1] / "state")
    adapter.shared = {"model"}
    adapter.apis = {"model": {"apiUrl": "http://127.0.0.1:%d/v1" % PORT, "apiKey": key, "model": model, "context": runtime.context, "reply_limit": None}}
    print("Connected to " + server + ". " + runtime.detail, flush=True)
    serve(Link(server), token, runtime, adapter, threading.Event())
    print("The website stopped this GPU.", flush=True)
    if runtime.process and runtime.process.poll() is None:
        runtime.process.terminate()


if __name__ == "__main__":
    main()
