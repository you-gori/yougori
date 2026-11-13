"""Server-side Yougori adapter. Only named compute operations, never remote shell."""
import base64
import json
import math
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import threading
import time
from compute_options import rental_options, public_account


class ComputeError(Exception):
    pass


def executable():
    configured = os.getenv("SOLVER_YOUGORI")
    if configured:
        return configured if Path(configured).is_file() else None
    found = shutil.which("yougori")
    if found:
        return found
    if os.name == "nt":
        path = Path(os.environ.get("LOCALAPPDATA", "")) / "Yougori/cli/yougori.exe"
        if path.is_file():
            return str(path)
    return None


def trim(payload, context, cap):
    """A chat request whose reply limit (max_tokens, max_completion_tokens) the model can take: at
    most `cap` (None: no cap) and what `context` leaves after the conversation, estimated
    generously (3 characters a token). Anything already within both is unchanged. A request that
    names no limit: a rented GPU's vLLM (no cap) keeps none and gives a reply all its context
    leaves; a Yougori model server is told the cap, or the room when less, since one released
    up to 1.2.4 stops every reply at 256 tokens unless told. With no room left to estimate, none
    is added, and the model server's own default takes what the context leaves."""
    keys = [key for key in ("max_tokens", "max_completion_tokens") if type(payload.get(key)) is int]
    room = None
    if context:
        estimate = context - (len(json.dumps(payload.get("messages", []))) + len(json.dumps(payload.get("tools", [])))) // 3 - 64
        room = estimate if estimate >= 64 else None
    if not keys:
        if cap is None or (context and room is None):
            return payload
        return {**payload, "max_tokens": cap if room is None else min(cap, room)}
    wanted = min(payload[key] for key in keys)
    allowed = min(wanted, cap) if cap else wanted
    if room is not None:
        allowed = min(allowed, room)
    return payload if allowed >= wanted else {**payload, **{key: max(1, allowed) for key in keys}}


# A shared model's health is read with every inventory, at most this long. A model server busy
# freeing GPU memory answers it late (its health waits for the unload), so a late answer keeps the
# model's last state this long, and the catalog does not flicker.
HEALTH_SECONDS = 3
KEEP_SECONDS = 30
# What a model loaded once, with its files checked, passes through while automatic GPU memory
# unloads it and loads it again: a request wakes it, so it is listed as ready meanwhile.
ON_DEMAND = ("idle", "queued", "freeing_memory", "loading", "unloading")
# A start that fails right after a restart stopped a running model is tried again after this long.
RESTART_RETRY_SECONDS = 5


def download_progress(download):
    """A download's progress as a model server's health gives it (receivedBytes, totalBytes,
    bytesPerSecond), in whole numbers {"received", "total", "rate"}; None without a size."""
    if not isinstance(download, dict):
        return None
    numbers = []
    for key in ("receivedBytes", "totalBytes", "bytesPerSecond"):
        value = download.get(key, 0)
        if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
            return None
        numbers.append(int(value))
    received, total, rate = numbers
    if not 0 < total <= 10 ** 13:
        return None
    return {"received": min(received, total), "total": total, "rate": min(rate, 10 ** 13)}


def readiness(health):
    """Whether a model can answer, from its model server's health: (state, progress). "ready" when
    it says so, when it says nothing of its state (a server that is not Yougori's, such as a rented
    GPU's raw vLLM), and while automatic GPU memory unloads and loads a model it loaded once;
    "downloading" with how far it has got; "unavailable" when it could not load; "loading" for
    every other step before it first loads (installing, waiting for the GPU, checking files)."""
    status = health.get("status") if isinstance(health, dict) else None
    if not isinstance(status, str) or status == "ready":
        return "ready", None
    if status == "error":
        return "unavailable", None
    optimizer = health.get("optimizer") if isinstance(health.get("optimizer"), dict) else {}
    if health.get("weightsVerified") is True and optimizer.get("enabled") is True and status in ON_DEMAND:
        return "ready", None
    if status == "downloading":
        return "downloading", download_progress(health.get("download"))
    return "loading", None


def size_words(count):
    """Bytes as people read them: "8.0 GB", or "640 MB" under a gigabyte."""
    return f"{count / 1e9:.1f} GB" if count >= 1e9 else f"{max(1, round(count / 1e6))} MB"


def download_words(progress):
    """How far a download has got, in plain ASCII: "42% of 8.0 GB, about 15 minutes left"."""
    received, total, rate = progress["received"], progress["total"], progress["rate"]
    words = f"{received * 100 // total}% of {size_words(total)}"
    if rate > 0 and received < total:
        seconds = (total - received) / rate
        minutes = round(seconds / 60)
        words += (", less than a minute left" if seconds < 60 else f", about {minutes} minute{'s' * (minutes != 1)} left" if minutes < 90
                  else f", about {max(2, round(seconds / 3600))} hours left")
    return words


def not_ready(model, state, progress):
    """Why a shared model cannot answer yet, for the caller, in plain ASCII (the website passes on
    a refusal's printable ASCII only)."""
    if state == "downloading":
        return model + " is still downloading on this computer" + (": " + download_words(progress) if progress else "") + ". It answers once it has loaded."
    if state == "loading":
        return model + " is loading onto the GPU on this computer. It answers once it has loaded."
    if state == "starting":
        return model + " is starting on this computer. It answers once it has loaded."
    return model + " could not load on this computer."


class Adapter:
    METHODS = {"get_platform_state", "refresh_host_metrics", "model_api_status", "model_api", "run_model", "start_model", "stop_model", "model_preflight",
               "model_agent_api", "runpod_gpu_offers", "runpod_connect", "runpod_status", "runpod_create_pod", "run_neocloud_model", "runpod_action"}

    def __init__(self, command, folder, controller=False):
        self.command, self.controller = command, controller
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.folder / "shared-models.json"
        self.shared = set(json.loads(self.path.read_text(encoding="utf-8"))) if self.path.exists() else set()
        self.apis = {}
        self.stopping = set()
        self.lock = threading.Lock()
        self.facts_read = {}  # environment -> ({"slots", "json"}, when read)
        # What each shared model's health said last, as inventory reports it: environment ->
        # (state, progress); and when its health last answered. A model without an entry is taken
        # as ready: a rented GPU's agent relays through this adapter and never reads inventory.
        self.readiness, self.health_read = {}, {}

    @staticmethod
    def loopback(api):
        """The model API Yougori created on this computer, or None for anything else."""
        from urllib.parse import urlsplit
        url = urlsplit(api.get("apiUrl") or "")
        if url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost", "::1") or url.username or url.password or not url.port:
            return None
        return url

    def facts(self, environment, api):
        """What the model server says of its launch, read from its own health route at most once
        a minute: "slots", how many requests it generates together (its requestQueue; the website
        routes by it), "json", whether it enforces a JSON reply format (response_format; the
        website sends such requests only where it is enforced), "task" and "context", the tokens it
        serves. None where unknown."""
        known = self.facts_read.get(environment)
        if known and known[1] > time.monotonic() - 60:
            return known[0]
        import http.client
        url, value = self.loopback(api), {"slots": None, "json": None, "task": None, "context": None}
        if url:
            connection = http.client.HTTPConnection(url.hostname, url.port, timeout=3)
            try:
                connection.request("GET", "/health", headers={"Authorization": "Bearer " + api.get("apiKey", "")})
                response = connection.getresponse()
                raw = response.read(1024 * 1024 + 1)
                if response.status == 200 and len(raw) <= 1024 * 1024:
                    health = json.loads(raw)
                    count = (health.get("requestQueue") or {}).get("slots")
                    value["slots"] = count if type(count) is int and 1 <= count <= 256 else None
                    enforced = ((health.get("capabilities") or {}).get("structuredOutput") or {}).get("supported")
                    value["json"] = enforced if isinstance(enforced, bool) else None
                    # The kind of model: a media runner names its task (text-to-image, ...); the website routes jobs by it.
                    task = health.get("task") or ((health.get("capabilities") or {}).get("media") or {}).get("task")
                    value["task"] = task if isinstance(task, str) and re.fullmatch(r"[a-z][a-z-]{0,39}", task) else None
                    # The context the model serves: a reply limit is trimmed to fit it (trim()).
                    context = health.get("context")
                    value["context"] = context if type(context) is int and 256 <= context <= 1048576 else None
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
        self.facts_read[environment] = (value, time.monotonic())
        return value

    def health(self, api):
        """A model server's health, read now: its answer (a dict; empty for a server that says
        nothing of its state, such as raw vLLM), "starting" while nothing answers there yet,
        "unavailable" when the read is refused, or None when it did not answer in time."""
        import http.client
        url = self.loopback(api)
        if not url:
            return {}
        connection = http.client.HTTPConnection(url.hostname, url.port, timeout=HEALTH_SECONDS)
        try:
            connection.request("GET", "/health", headers={"Authorization": "Bearer " + api.get("apiKey", "")})
            response = connection.getresponse()
            raw = response.read(1024 * 1024)
            if response.status in (502, 503, 504):
                return "starting"
            if response.status != 200:
                return "unavailable"
            try:
                value = json.loads(raw)
            except ValueError:
                return {}
            return value if isinstance(value, dict) else {}
        except (ConnectionRefusedError, ConnectionResetError, ConnectionAbortedError, http.client.BadStatusLine):
            # Nothing listens there yet, or Yougori's port answers while the model server behind
            # it has not started.
            return "starting"
        except (OSError, http.client.HTTPException):
            return None
        finally:
            connection.close()

    def check(self, environment, api):
        """Whether a shared model can answer now, from its health read afresh: (state, progress),
        kept for inventory and requests. A late answer keeps the last state for a while; a model
        that turns ready has its launch facts read again (slots, JSON output, context)."""
        answer = self.health(api)
        now = time.monotonic()
        with self.lock:
            before = self.readiness.get(environment)
            if answer is None and before and now - self.health_read.get(environment, 0) < KEEP_SECONDS:
                return before
            if answer is None:
                state = ("starting", None)
            else:
                state = (answer, None) if isinstance(answer, str) else readiness(answer)
                self.health_read[environment] = now
            self.readiness[environment] = state
            if state[0] == "ready" and (before or ("",))[0] != "ready":
                self.facts_read.pop(environment, None)
        return state

    def call(self, method, **params):
        if method not in self.METHODS:
            raise ComputeError("This compute operation is not supported.")
        try:
            result = subprocess.run([self.command, "call", method, "--file", "-", "--yes"],
                                    input=json.dumps(params), text=True, encoding="utf-8", capture_output=True,
                                    timeout=1200 if method in {"run_model", "start_model", "run_neocloud_model", "runpod_create_pod", "runpod_connect"} else 45,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                                    env={**os.environ, "YOUGORI_NO_UPDATE_CHECK": "1"})
            value = json.loads(result.stdout)
            if result.returncode or value.get("ok") is not True:
                if "YOUGORI_CUDA_UPDATE_REQUIRED" in str(value.get("error", "")):
                    raise ComputeError("Update NVIDIA CUDA in Yougori on the website server, then retry this model. Your model is listed as unavailable until it starts.")
                raise ValueError()
            return value["result"]
        except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
            # Provider/engine errors may contain private account information.
            raise ComputeError("Yougori could not complete " + method.replace("_", " ") + ". Check the website server's Yougori diagnostics.") from None

    def save(self):
        with self.lock:
            temporary = self.path.with_suffix(".tmp")
            temporary.write_text(json.dumps(sorted(self.shared)), encoding="utf-8")
            temporary.replace(self.path)

    @staticmethod
    def port():
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            return listener.getsockname()[1]

    def inventory(self):
        fresh = True
        try:
            state = self.call("refresh_host_metrics")
        except ComputeError:
            state = self.call("get_platform_state")
            fresh = False
        models, apis = [], {}
        for env in state.get("environments", []):
            identity = env.get("id", "")
            model = str(env.get("description", "")).removeprefix("Hugging Face · ") if str(env.get("description", "")).startswith("Hugging Face · ") else None
            if not model and env.get("kind") != "model" and identity not in self.shared:
                continue
            api = {}
            if env.get("status") == "running":
                try:
                    api = self.call("model_api_status", environmentId=identity)
                except ComputeError:
                    pass
            if api.get("apiUrl") and api.get("apiKey"):
                apis[identity] = api
            shared = identity in self.shared
            if identity in apis:
                # A shared model is listed by what its model server says: ready only while it can
                # answer, otherwise how far it has got. Another model, by its API alone.
                phase, progress = self.check(identity, api) if shared else ("ready", None)
            else:
                phase, progress = "starting" if shared and env.get("status") == "provisioning" else "unavailable", None
                if shared:
                    with self.lock:
                        self.readiness[identity] = (phase, None)
            facts = self.facts(identity, api) if identity in apis and shared else {"slots": None, "json": None, "task": None, "context": None}
            models.append({"id": identity, "name": api.get("model") or model or env.get("name", "Model"),
                           "state": phase, **({"progress": progress} if progress else {}), "shared": shared,
                           "place": "neocloud" if env.get("kind") == "cloud" else "local",
                           **({"slots": facts["slots"]} if facts["slots"] else {}), **({"json": facts["json"]} if facts["json"] is not None else {}),
                           **({"task": facts["task"]} if facts["task"] else {}),
                           # The context its server serves: the website lists the smallest of a model's for harnesses.
                           **({"context": facts["context"]} if facts.get("context") else {})})
        with self.lock:
            self.apis = apis
        from control_panel import sample
        # "media": this connector relays a media model's job routes and files, not only chat.
        return {"platform": platform.system(), "models": models[:64], "detail": "Yougori is connected on " + socket.gethostname() + ".", "telemetry":sample(state, fresh), "media": True}

    def share(self, environment, enabled=True):
        if enabled:
            state = self.call("get_platform_state")
            item = next((e for e in state.get("environments", []) if e.get("id") == environment), None)
            if not item:
                raise ComputeError("This model environment no longer exists.")
            # Persist the user's catalog choice even when startup needs attention.
            # Inventory truthfully reports unavailable until the API is running.
            with self.lock:
                self.shared.add(environment)
            self.save()
            restarted = False
            if item.get("kind") != "cloud":
                try:
                    # The limits coding agents need (longer conversations, more messages, larger
                    # requests), from the model's next start: one running without them starts again.
                    # The engine says restartRequired only while limits saved after the container was
                    # configured have not reached it (also after a restart for them failed), never
                    # for a model installed with them or one whose start marks another setting.
                    given = self.call("model_agent_api", environmentId=environment)
                    if isinstance(given, dict) and given.get("restartRequired") is True:
                        self.call("stop_model", environmentId=environment)
                        item, restarted = {**item, "status": "stopped"}, True
                except ComputeError:
                    pass  # An older Yougori, or a model that takes no such limits (a media model): shared as it is.
            if item.get("kind") != "cloud" and item.get("status") != "running":
                try:
                    self.call("start_model", environmentId=environment)
                except ComputeError:
                    if not restarted:
                        raise
                    # It ran before this restart: tried once more, so a refusal while another
                    # operation on it finishes does not leave it stopped.
                    time.sleep(RESTART_RETRY_SECONDS)
                    self.call("start_model", environmentId=environment)
            api = self.call("model_api_status", environmentId=environment)
            if not api.get("apiUrl"):
                api = self.call("model_api", environmentId=environment, port=self.port())
            with self.lock:
                self.shared.add(environment)
                self.apis[environment] = api
        else:
            with self.lock:
                self.shared.discard(environment)
                self.apis.pop(environment, None)
        self.save()

    def agent_runtime(self, model):
        """Whether a model runs on vLLM for coding agents: where the engine runs its architecture
        there natively, calling tools in the model family's format with a long context. Otherwise
        the engine's own choice."""
        try:
            found = self.call("model_preflight", model=model)
        except ComputeError:
            return False
        return isinstance(found, dict) and found.get("supported") is True and (found.get("runner") == "yougori-vllm" or isinstance(found.get("vllmNative"), dict))

    def environment_ids(self):
        """The environments on this computer now, by ID."""
        return {env.get("id") for env in self.call("get_platform_state").get("environments", [])}

    def offers(self, options=None):
        options = rental_options(options or {})
        result = self.call("runpod_gpu_offers", containerDiskGb=options["disk_gb"] + options["volume_gb"], gpuCount=options["gpu_count"])
        offers = []
        for gpu in result.get("gpus", []):
            for cloud in ("secure", "community"):
                price = gpu.get(cloud + "Offer", {}).get("price")
                if (gpu.get(cloud + "Offer", {}).get("available") is True and type(price) in (float, int)
                        and math.isfinite(price) and price > 0):
                    offers.append({"id": cloud + ":" + gpu["id"], "gpu": gpu["id"], "name": gpu["name"],
                                   "cloud": cloud, "vram_gb": gpu.get("vramGb"), "hourly_usd": price * options["gpu_count"], "provider": "RunPod", "options": options})
        return {"offers": sorted(offers, key=lambda o: o["hourly_usd"])[:200], "checked_at": int(time.time())}

    def execute(self, job, progress):
        if not self.controller:
            raise ComputeError("Contributors cannot rent servers or receive management commands.")
        kind, payload = job["kind"], job["payload"]
        if kind == "start":
            try:
                result = subprocess.run([self.command, "app", "start"], capture_output=True, text=True,
                                        encoding="utf-8", timeout=90, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
                if result.returncode or json.loads(result.stdout).get("ok") is not True:
                    raise ValueError()
            except (OSError, ValueError, subprocess.TimeoutExpired):
                raise ComputeError("Yougori could not start on the website server. Inspect its startup diagnostics.") from None
            return {}
        if kind == "offers":
            return self.offers(payload)
        if kind == "account":
            return {"account": public_account(self.call("runpod_status"))}
        if kind == "provider":
            if not payload.get("key"):
                raise ComputeError("Re-enter the provider key; it was not saved during a restart.")
            return {"account": public_account(self.call("runpod_connect", apiKey=payload["key"]))}
        if kind == "share":
            self.share(payload["environment"], payload["enabled"])
            return {"environment": payload["environment"]}
        if kind == "stop":
            with self.lock:
                self.stopping.add(payload["environment"])
            self.call("runpod_action", environmentId=payload["environment"], action="stop")
            self.share(payload["environment"], False)
            return {"environment": payload["environment"]}
        if kind == "load":
            # With the limits coding agents need, on vLLM where it serves the model natively, as
            # `yougori inference connect` installs a contributor's models.
            request = {"model": payload["model"], "port": self.port(), "resources": {"agentApi": True}}
            before = None
            if self.agent_runtime(payload["model"]):
                request["runner"] = "vllm"
                before = self.environment_ids()
            try:
                result = self.call("run_model", **request)
            except ComputeError:
                # vLLM takes a model only when all of it fits the GPU, and refuses one that does not
                # before it makes anything; the engine's own runner may still fit it (quantized).
                # Asked once more without vLLM, and only when the refused request made nothing.
                if before is None or self.environment_ids() - before:
                    raise
                del request["runner"]
                result = self.call("run_model", **request)
            identity = result["id"]
            self.share(identity)
            return {"environment": identity}
        if kind != "rent":
            raise ComputeError("Unsupported compute action.")
        # Resolve compatibility before incurring provider charges.
        preflight = self.call("model_preflight", model=payload["model"])
        if not preflight.get("supported") or preflight.get("runner") == "yougori-llama-cpp":
            raise ComputeError("Choose a supported safetensors model for the cloud GPU. No rental was made.")
        offer = payload["offer"]
        options = rental_options(offer.get("options", {}))
        needed = preflight.get("resources", {}).get("gpuMemoryGbEstimated")
        if needed and offer.get("vram_gb") and needed > offer["vram_gb"]:
            raise ComputeError("This model needs more GPU memory than the selected offer. No rental was made.")
        if preflight.get("resources", {}).get("storageGbRecommended", 0) > options["disk_gb"]:
            raise ComputeError("This model needs a larger runtime disk. Increase the disk and refresh offers; no rental was made.")
        name = "solver-" + job["id"].replace("-", "")[:24]
        state = self.call("get_platform_state")
        existing = next((e for e in state.get("environments", []) if e.get("name") == name), None)
        if existing:
            raise ComputeError("This rental already has a Yougori resource. Inspect it before retrying.")
        progress("Renting the GPU at the approved maximum price.", {})
        try:
            state = self.call("runpod_create_pod", request={"name": name, "compute": "gpu", "gpuId": offer["gpu"],
                "gpuCount": options["gpu_count"], "cloud": offer["cloud"], "containerDiskGb": options["disk_gb"],
                "volumeGb": options["volume_gb"], "volumeMountPath": "/workspace",
                "image": "runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404", "maxHourlyUsd": offer["hourly_usd"]})
        except ComputeError:
            # The engine records even an ambiguous create. Never create again automatically.
            state = self.call("get_platform_state")
            record = next((e for e in state.get("environments", []) if e.get("name") == name), None)
            if record:
                progress("Rental outcome needs inspection. The provider may be charging for this GPU.", {"environment": record["id"], "name": name})
            raise
        env = next((e for e in state.get("environments", []) if e.get("name") == name), None)
        if not env:
            raise ComputeError("The rental response is incomplete. Inspect RunPod before trying again.")
        result = {"environment": env["id"], "name": name}
        progress("GPU rented. Waiting for its connection, then loading the model. Provider charges are active.", result)
        # Only readiness is retried. Purchase is never repeated.
        for _ in range(60):
            if env["id"] in self.stopping:
                raise ComputeError("This GPU was stopped. Model setup was cancelled.")
            state = self.call("runpod_action", environmentId=env["id"], action="refresh")
            record = next((e for e in state.get("environments", []) if e.get("id") == env["id"]), {})
            if record.get("status") == "running":
                break
            time.sleep(5)
        else:
            raise ComputeError("The GPU is rented but not ready yet. Inspect or stop it from this page; charges may continue.")
        self.call("run_neocloud_model", environmentId=env["id"], model=payload["model"], port=self.port())
        if env["id"] in self.stopping:
            raise ComputeError("This GPU was stopped. Model setup was cancelled.")
        self.share(env["id"])
        return result

    # The model server routes a connector relays: chat, and a media model's jobs and files.
    RELAYED = re.compile(r"/(chat/completions|jobs|jobs/job_[a-f0-9]{24}(/result|/cancel)?|files/job_[a-f0-9]{24}\.[0-9]{1,2})(\?wait=[0-9]{1,3})?")

    def inference(self, task, send):
        """Relays one request to the shared model's own API and uploads its answer in chunks:
        a chat completion (streamed as it comes), or a media model's job route or file (`path`,
        `method`), of at most `limit` bytes. A media route's own refusal keeps its words."""
        # The only network destination comes from this node's own engine, never the website request.
        import http.client
        with self.lock:
            api = self.apis.get(task["environment"]) if task["environment"] in self.shared else None
        sequence = 0
        connection = None
        failure, refusal = 502, None
        path, method = task.get("path") or "/chat/completions", task.get("method") or "POST"
        chat = path == "/chat/completions"
        limit = task.get("limit") if type(task.get("limit")) is int and 0 < task.get("limit") <= 2 * 1024 ** 3 else 16 * 1024 * 1024
        try:
            if not api:
                raise ComputeError("This model is not shared.")
            url = self.loopback(api)
            if not url:
                raise ComputeError("Only Yougori's authenticated loopback model API is used.")
            if method not in ("GET", "POST", "DELETE") or not self.RELAYED.fullmatch(path):
                raise ComputeError("This route is not relayed.")
            if chat:
                with self.lock:
                    said = self.readiness.get(task["environment"], ("ready", None))
                if said[0] != "ready":
                    said = self.check(task["environment"], api)  # It may have loaded since the last inventory.
                if said[0] != "ready":
                    # Refused at once, with how far it has got: its model server would hold the
                    # request until it has loaded, past the website's time limit.
                    failure = 503
                    refusal = json.dumps({"error": {"code": "model_" + said[0], "message": not_ready(api.get("model") or "This model", *said)}}).encode()
                    raise ComputeError("This model cannot answer yet.")
            connection = http.client.HTTPConnection(url.hostname, url.port, timeout=120 if chat else 600)
            payload = {**task["payload"], "model": api["model"]} if chat else task.get("payload")
            if chat:
                # A reply limit the model cannot take (coding agents ask for 32,000) is trimmed to
                # what it can: the engine's model server takes 4,096, and what the context leaves.
                known = self.facts_read.get(task["environment"], ({}, 0))[0]
                payload = trim(payload, api.get("context") or known.get("context"), api.get("reply_limit", 4096))
            body = None if method == "GET" or not isinstance(payload, dict) else json.dumps(payload)
            headers = {"Authorization": "Bearer " + api["apiKey"]}
            if body is not None:
                headers["Content-Type"] = "application/json"
            connection.request(method, url.path.rstrip("/") + path, body, headers)
            response = connection.getresponse()
            if response.status not in (200, 201, 202, 206):
                # A refused request (400) or a full queue (429) is reported as such, never its text;
                # a media route's own answer (an unknown job, a job not done) keeps its words, which
                # are the model server's own.
                failure = response.status if response.status in (400, 429) or (not chat and response.status in (404, 409, 410, 503)) else 502
                # The model server's own refusal (Yougori's never repeats the request) says what to
                # change: a conversation too long for its context, for example.
                if failure != 502 and (not chat or failure == 400):
                    refusal = response.read(65536)
                raise ComputeError("Model refused the request.")
            kind = response.getheader("Content-Type", "application/json")
            total = 0
            while True:
                chunk = response.read1(32768) if chat else response.read(1024 * 1024)
                total += len(chunk)
                if total > limit:
                    raise ComputeError("Model response too large.")
                ack = send({"id": task["id"], "sequence": sequence, "status": response.status, "stream": chat and payload.get("stream") is True,
                            "content_type": kind, "data": base64.b64encode(chunk).decode(), "done": not chunk})
                sequence += 1
                if not chunk or (isinstance(ack, dict) and ack.get("cancelled")):
                    break
        except Exception:
            # Never send a provider's raw error, credentials, or local paths.
            try:
                send({"id": task["id"], "sequence": sequence, "status": failure, "done": True,
                      **({"content_type": "application/json", "data": base64.b64encode(refusal).decode()} if refusal else {})})
            except Exception:
                pass
        finally:
            if connection:
                connection.close()

def serve_local(compute, adapter, stopped):
    """Trusted website-host worker; browsers get no engine endpoint or credential."""
    token = compute.local_host(socket.gethostname())
    compute.local_adapter = adapter
    host = compute.host(token)
    tasks, tasks_lock = set(), threading.Lock()
    inference_slots = threading.BoundedSemaphore(4)
    last_inventory = 0
    from sandbox_grid import Grid
    from grid_adapter import GridAdapter
    grid = Grid(compute.store)
    grid_adapter = GridAdapter(adapter.command, adapter.folder, grid.local_capacity())
    grid_busy = threading.Event()

    def grid_work(job):
        try:
            result = grid_adapter.execute(job)
            grid.result(host, {"id": job["id"], "ok": True, "result": result})
        except Exception:
            grid.result(host, {"id": job["id"], "ok": False, "result": {"error": "VM action failed. Inspect this website server's Yougori Sandbox VM diagnostics."}})
        finally:
            grid_busy.clear()

    def work(job):
        latest = {}
        def progress(detail, result):
            latest.update(result)
            compute.result(host, {"id": job["id"], "state": "running", "detail": detail, "result": latest})
        try:
            latest.update(adapter.execute(job, progress))
            if job["kind"] in ("share", "load", "rent", "stop", "start"):
                try:
                    compute.inventory(host, adapter.inventory())
                except ComputeError:
                    pass  # The periodic inventory retries without repeating the operation.
            compute.result(host, {"id": job["id"], "state": "done", "result": latest, "detail": "Yougori completed this operation."})
        except Exception as error:
            if job["kind"] == "share":
                try:
                    compute.inventory(host, adapter.inventory())
                except ComputeError:
                    pass
            detail = str(error) if isinstance(error, ComputeError) else "Yougori could not finish this operation. Inspect its diagnostics before retrying."
            compute.result(host, {"id": job["id"], "state": "attention", "result": latest, "detail": detail})
        finally:
            with tasks_lock:
                tasks.discard(job["id"])

    def infer(task):
        try:
            adapter.inference(task, lambda data: compute.chunk(host, data))
        finally:
            inference_slots.release()

    while not stopped.is_set():
        try:
            host = compute.host(token)
            if time.monotonic() - last_inventory > 10:
                try:
                    inventory = adapter.inventory()
                except ComputeError as error:
                    inventory = {"models": [], "detail": str(error), "connected": False}
                compute.inventory(host, inventory)
                grid_adapter.capacity = grid.local_capacity()
                grid.inventory(host, grid_adapter.advertisement())
                grid.reconcile(host, grid_adapter.inventory())
                last_inventory = time.monotonic()
            if not grid_busy.is_set():
                grid_job = grid.poll(host)
                if grid_job:
                    grid_busy.set()
                    threading.Thread(target=grid_work, args=(grid_job,), daemon=True).start()
            if inference_slots.acquire(blocking=False):
                with tasks_lock:
                    accept_job = not tasks
                task = compute.poll(host, accept_job=accept_job)
                if "inference" in task:
                    threading.Thread(target=infer, args=(task["inference"],), daemon=True).start()
                else:
                    inference_slots.release()
                if "job" in task:
                    with tasks_lock:
                        tasks.add(task["job"]["id"])
                    threading.Thread(target=work, args=(task["job"],), daemon=True).start()
        except Exception:
            pass
        stopped.wait(.25)
