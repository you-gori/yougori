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


class Adapter:
    METHODS = {"get_platform_state", "refresh_host_metrics", "model_api_status", "model_api", "run_model", "start_model", "model_preflight",
               "runpod_gpu_offers", "runpod_connect", "runpod_status", "runpod_create_pod", "run_neocloud_model", "runpod_action"}

    def __init__(self, command, folder, controller=False):
        self.command, self.controller = command, controller
        self.folder = Path(folder)
        self.folder.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = self.folder / "shared-models.json"
        self.shared = set(json.loads(self.path.read_text(encoding="utf-8"))) if self.path.exists() else set()
        self.apis = {}
        self.stopping = set()
        self.lock = threading.Lock()
        self.slot_counts = {}  # environment -> (slots, when read)

    @staticmethod
    def loopback(api):
        """The model API Yougori created on this computer, or None for anything else."""
        from urllib.parse import urlsplit
        url = urlsplit(api.get("apiUrl") or "")
        if url.scheme != "http" or url.hostname not in ("127.0.0.1", "localhost", "::1") or url.username or url.password or not url.port:
            return None
        return url

    def slots(self, environment, api):
        """How many requests the model server generates together (its requestQueue), read from its
        own health route at most once a minute. The website routes by it; None when unknown."""
        known = self.slot_counts.get(environment)
        if known and known[1] > time.monotonic() - 60:
            return known[0]
        import http.client
        url, value = self.loopback(api), None
        if url:
            connection = http.client.HTTPConnection(url.hostname, url.port, timeout=3)
            try:
                connection.request("GET", "/health", headers={"Authorization": "Bearer " + api.get("apiKey", "")})
                response = connection.getresponse()
                raw = response.read(1024 * 1024 + 1)
                if response.status == 200 and len(raw) <= 1024 * 1024:
                    count = (json.loads(raw).get("requestQueue") or {}).get("slots")
                    value = count if type(count) is int and 1 <= count <= 256 else None
            except (OSError, ValueError, http.client.HTTPException):
                pass
            finally:
                connection.close()
        self.slot_counts[environment] = (value, time.monotonic())
        return value

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
            slots = self.slots(identity, api) if identity in apis and identity in self.shared else None
            models.append({"id": identity, "name": api.get("model") or model or env.get("name", "Model"),
                           "state": "ready" if identity in apis else "unavailable", "shared": identity in self.shared,
                           "place": "neocloud" if env.get("kind") == "cloud" else "local", **({"slots": slots} if slots else {})})
        with self.lock:
            self.apis = apis
        from control_panel import sample
        return {"platform": platform.system(), "models": models[:64], "detail": "Yougori is connected on " + socket.gethostname() + ".", "telemetry":sample(state, fresh)}

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
            if item and item.get("kind") != "cloud" and item.get("status") != "running":
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
            result = self.call("run_model", model=payload["model"], port=self.port())
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

    def inference(self, task, send):
        # The only network destination comes from this node's own engine, never the website request.
        import http.client
        with self.lock:
            api = self.apis.get(task["environment"]) if task["environment"] in self.shared else None
        sequence = 0
        connection = None
        failure = 502
        try:
            if not api:
                raise ComputeError("This model is not shared.")
            url = self.loopback(api)
            if not url:
                raise ComputeError("Only Yougori's authenticated loopback model API is used.")
            connection = http.client.HTTPConnection(url.hostname, url.port, timeout=120)
            payload = {**task["payload"], "model": api["model"]}
            connection.request("POST", url.path.rstrip("/") + "/chat/completions", json.dumps(payload),
                               {"Content-Type": "application/json", "Authorization": "Bearer " + api["apiKey"]})
            response = connection.getresponse()
            if response.status != 200:
                # A refused request (400) or a full queue (429) is reported as such, never its text.
                failure = response.status if response.status in (400, 429) else 502
                raise ComputeError("Model refused the request.")
            total = 0
            while True:
                chunk = response.read1(32768)
                total += len(chunk)
                if total > 16 * 1024 * 1024:
                    raise ComputeError("Model response too large.")
                ack = send({"id": task["id"], "sequence": sequence, "status": 200, "stream": payload.get("stream") is True,
                      "data": base64.b64encode(chunk).decode(), "done": not chunk})
                sequence += 1
                if not chunk or (isinstance(ack, dict) and ack.get("cancelled")):
                    break
        except Exception:
            # Never send a provider's raw error, credentials, or local paths.
            try:
                send({"id": task["id"], "sequence": sequence, "status": failure, "done": True})
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
