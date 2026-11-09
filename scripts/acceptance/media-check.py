"""Media models on a disposable acceptance engine, end to end on this computer's GPU.

For each of four small open models (images, speech, video, sound), the check runs the model
through the engine exactly as `yougori model run` does, waits for it, and then:

1. generates with the real CLI (`yougori model generate NAME --prompt ... --output FOLDER`) and
   checks the saved files by their first bytes (PNG, RIFF/WAVE, MP4 ftyp);
2. calls the OpenAI-shaped route of its kind (/v1/images/generations, /v1/audio/speech,
   /v1/videos then /v1/videos/ID/content) or the job routes (sound), and reads /v1/jobs;
3. queues two jobs and cancels the waiting one; asks for a bad input and reads the typed 400;
4. sets the output retention with `yougori model optimize NAME --keep-outputs 2` and reads it
   back from health, reads `yougori model usage NAME` for images and output seconds, and checks
   that `yougori model chat NAME` says to use generate instead;
5. with --hosted, runs the inference template (examples/hub/inference-solver) in this process:
   the model connected by address, priced, a job and the OpenAI shape of its kind through the
   website with the file copied to it and the job charged by what it made; and, for the image
   model, the same through a contributor's connector (compute_node, chunked relay);
6. stops the model before the next one starts, so the GPU is never shared.

Every request and reply is kept as evidence under ROOT/evidence. The installed engine is never
touched: the acceptance engine has its own pipe, data folder and home.

Run (after building the engine and CLI with --features acceptance into their own target dir):
  python -I -B scripts/acceptance/media-check.py --root D:/tmp/yg-media --engine ENGINE.exe
    --cli CLI.exe --runtime src-tauri/resources/runtime [--only image,speech] [--hosted]
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request

TEMPLATE = Path(__file__).resolve().parents[2] / "examples" / "hub" / "inference-solver"
spec = importlib.util.spec_from_file_location("migration", Path(__file__).with_name("model-migration-recovery.py"))
migration = importlib.util.module_from_spec(spec)
spec.loader.exec_module(migration)

MODELS = {
    "image": {"model": "hf.co/stabilityai/sd-turbo", "task": "text-to-image", "port": 18901,
              "generate": ["--prompt", "a red bicycle leaning on a white wall, morning light", "--steps", "2", "--guidance", "0", "--size", "512x512", "--seed", "7"],
              "input": {"prompt": "a small lighthouse on a cliff", "steps": 2, "guidance": 0, "width": 512, "height": 512}},
    "speech": {"model": "hf.co/facebook/mms-tts-eng", "task": "text-to-speech", "port": 18902,
               "generate": ["--prompt", "Yougori serves images, video and speech from the same inference."],
               "input": {"text": "The quick brown fox jumps over the lazy dog."}},
    "video": {"model": "hf.co/ali-vilab/text-to-video-ms-1.7b", "task": "text-to-video", "port": 18903,
              "generate": ["--prompt", "waves rolling onto a sandy beach at sunset", "--seconds", "2", "--steps", "20", "--size", "256x256", "--seed", "3"],
              "input": {"prompt": "a hot air balloon drifting over hills", "seconds": 2, "steps": 20, "width": 256, "height": 256}},
    # AudioLDM (v1): AudioLDM2's pipeline calls a GPT-2 internal that Transformers 5 removed.
    "sound": {"model": "hf.co/cvssp/audioldm-s-full-v2", "task": "text-to-audio", "port": 18904,
              "generate": ["--prompt", "rain falling on a tin roof", "--seconds", "4", "--steps", "40", "--seed", "11"],
              "input": {"prompt": "a dog barking twice", "seconds": 3, "steps": 40}},
}
MAGIC = {"image/png": b"\x89PNG", "audio/wav": b"RIFF", "video/mp4": b"ftyp"}


def looks_like_bytes(head, content_type):
    magic = MAGIC[content_type]
    return head[:16].startswith(magic) or (content_type == "video/mp4" and magic in head[:16])


def looks_like(path, content_type):
    with open(path, "rb") as file:
        head = file.read(16)
    return looks_like_bytes(head, content_type)


class Check(migration.Run):
    def __init__(self, args):
        args.model = Path(__file__).parent
        args.from_case = 0
        super().__init__(args)
        self.args = args
        self.kept = {}
        self.site = None

    def result(self, method, params, label=None):
        return self.call(method, params, label)["result"]

    def yougori(self, *words, label=None, stdin=None, check=True):
        """The real CLI with the test engine's environment, its JSON output parsed."""
        result = subprocess.run([str(self.cli), *words], input=stdin, env=self.env, cwd=self.root, capture_output=True, text=True,
                                encoding="utf-8", timeout=3600, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        try:
            body = json.loads(result.stdout)
        except ValueError:
            body = {"ok": False, "stdout": result.stdout[-4000:]}
        if label:
            self.write(label, {"words": list(words), "exit": result.returncode, "reply": body, "stderr": result.stderr[-3000:]})
        if check:
            assert result.returncode == 0 and body.get("ok"), (words, body, result.stderr[-2000:])
        return body

    def http(self, port, key, method, path, body=None, label=None, raw=False):
        request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=None if body is None else json.dumps(body).encode(), method=method,
                                         headers={"Content-Type": "application/json", "Authorization": "Bearer " + key})
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        record = {"method": method, "path": path, "body": body}
        try:
            with opener.open(request, timeout=1800) as response:
                payload = response.read()
                record["status"] = response.status
                record["contentType"] = response.getheader("Content-Type")
                if raw:
                    record["bytes"] = len(payload)
                    record["head"] = payload[:12].hex()
                else:
                    record["reply"] = json.loads(payload)
        except urllib.error.HTTPError as error:
            record["status"] = error.code
            try:
                record["error"] = json.loads(error.read(65536) or b"{}")
            except ValueError:
                record["error"] = {}
            payload = b""
        if label:
            self.write(label, record)
        return record, payload

    def wait_ready(self, environment_id, limit=3600):
        deadline, previous = time.monotonic() + limit, None
        while time.monotonic() < deadline:
            reply = self.call("model_status", {"environmentId": environment_id}, None, checked=False)
            health = reply.get("result") if reply.get("ok") else {"status": "server-starting", "reply": reply}
            if health.get("status") != previous:
                self.write("model-state", {k: v for k, v in health.items() if k not in ("helpers", "helperShadow")})
                previous = health.get("status")
            if health.get("status") == "ready":
                return health
            if health.get("status") == "error":
                raise RuntimeError("The model failed to load; see the model-state evidence")
            time.sleep(3)
        raise TimeoutError("The model did not become ready in time")

    def existing_name(self, environment_id):
        state = self.result("get_platform_state", {})
        return next(e["name"] for e in state["environments"] if e["id"] == environment_id)

    def create(self, label, spec):
        state = self.result("get_platform_state", {})
        found = next((e for e in state["environments"] if e.get("description") == "Hugging Face · " + spec["model"].removeprefix("hf.co/")), None)
        if found:
            self.write(label + "-reused", {"id": found["id"], "name": found["name"]})
            if found["status"] != "running":
                self.result("start_model", {"environmentId": found["id"]}, label + "-start")
            health = self.wait_ready(found["id"])
            access = self.result("model_api_status", {"environmentId": found["id"]})
            if not access.get("apiUrl"):
                access = self.result("model_api", {"environmentId": found["id"], "port": spec["port"]})
            port = int(access["apiUrl"].rsplit(":", 1)[1].split("/", 1)[0])
            return found["id"], found["name"], port, access["apiKey"], health
        preflight = self.result("model_preflight", {"model": spec["model"]}, label + "-preflight")
        assert preflight["supported"] is True and preflight["format"] == "media" and preflight["task"] == spec["task"], preflight
        submitted = self.command("call", "run_model", "--yes", "--no-wait", "--file", "-",
                                 params={"model": spec["model"], "port": spec["port"], "resources": {"storageDrive": self.args.storage_drive}}, label=label + "-submitted")
        job, deadline = submitted["result"]["jobId"], time.monotonic() + 5400
        while time.monotonic() < deadline:
            status = self.result("jobs_get", {"jobId": job, "wait": 1000})
            if status["status"] == "complete":
                created = status["result"]
                self.write(label + "-created", {k: v for k, v in created.items() if k != "apiKey"})
                health = self.wait_ready(created["id"])
                return created["id"], self.existing_name(created["id"]), spec["port"], created["apiKey"], health
            if status["status"] in ("failed", "cancelled", "interrupted"):
                self.write(label + "-creation-failed", status)
                raise RuntimeError("Creating " + spec["model"] + " failed; see the evidence")
            time.sleep(2)
        raise TimeoutError("Model creation exceeded 90 minutes")

    def check_model(self, label, spec):
        self.write("phase", {"model": label, "repository": spec["model"]})
        environment_id, name, port, key, health = self.create(label, spec)
        self.kept[label] = {"id": environment_id, "name": name, "port": port}
        assert health["task"] == spec["task"] and health.get("api") == "jobs", {k: health.get(k) for k in ("task", "api", "runner", "pipeline")}
        self.write(label + "-health", {k: health.get(k) for k in ("task", "runner", "pipeline", "gpu", "precision", "offload", "queue", "outputs", "capabilities")})
        # 1. The CLI generates and saves the files.
        folder = self.root / "outputs" / label
        saved = self.yougori("model", "generate", name, *spec["generate"], "--output", str(folder), label=label + "-cli-generate")["result"]
        assert saved["files"], saved
        for item in saved["files"]:
            assert os.path.getsize(item["path"]) == item["bytes"] > 0, item
            assert looks_like(item["path"], item["contentType"]), item
        self.write(label + "-cli-files", saved["files"])
        # 2. The route of its kind.
        task = spec["task"]
        if task == "text-to-image":
            record, _ = self.http(port, key, "POST", "/v1/images/generations", {"prompt": spec["input"]["prompt"], "n": 2, "size": "512x512", "steps": 2, "guidance": 0, "response_format": "b64_json"}, label + "-images-route")
            assert record["status"] == 200 and len(record["reply"]["data"]) == 2 and record["reply"]["usage"]["images"] == 2, record
            record["reply"]["data"] = ["b64 of " + str(len(d["b64_json"])) + " chars" for d in record["reply"]["data"]]
            self.write(label + "-images-route-summary", record)
        elif task == "text-to-speech":
            record, payload = self.http(port, key, "POST", "/v1/audio/speech", {"input": spec["input"]["text"], "response_format": "wav"}, label + "-speech-route", raw=True)
            assert record["status"] == 200 and record["contentType"] == "audio/wav" and payload.startswith(b"RIFF"), record
        elif task == "text-to-video":
            record, _ = self.http(port, key, "POST", "/v1/videos", {"prompt": spec["input"]["prompt"], "seconds": 2, "size": "256x256", "steps": 20}, label + "-videos-route")
            assert record["status"] == 200 and record["reply"]["object"] == "video", record
            video_id = record["reply"]["id"]
            for _ in range(200):
                record, _ = self.http(port, key, "GET", "/v1/jobs/" + video_id + "?wait=30")
                if record["reply"]["status"] in ("succeeded", "failed", "cancelled"):
                    break
            record, _ = self.http(port, key, "GET", "/v1/videos/" + video_id, label=label + "-video-object")
            assert record["reply"]["status"] == "completed" and record["reply"]["progress"] == 100, record
            record, payload = self.http(port, key, "GET", "/v1/videos/" + video_id + "/content", label=label + "-video-content", raw=True)
            assert record["status"] == 200 and record["contentType"] == "video/mp4" and b"ftyp" in payload[:16], record
        else:
            record, _ = self.http(port, key, "POST", "/v1/jobs", {"input": spec["input"]}, label + "-job-submitted")
            assert record["status"] == 202, record
            job_id = record["reply"]["id"]
            for _ in range(200):
                record, _ = self.http(port, key, "GET", "/v1/jobs/" + job_id + "?wait=30")
                if record["reply"]["status"] in ("succeeded", "failed", "cancelled"):
                    break
            self.write(label + "-job-done", record)
            assert record["reply"]["status"] == "succeeded", record
            record, payload = self.http(port, key, "GET", record["reply"]["output"]["files"][0]["url"], label=label + "-job-file", raw=True)
            assert record["status"] == 200 and payload.startswith(b"RIFF"), record
        record, _ = self.http(port, key, "GET", "/v1/jobs?limit=10", label=label + "-jobs-list")
        assert record["status"] == 200 and record["reply"]["data"], record
        # 3. Two jobs: the second waits and is cancelled; a wrong input is a typed 400.
        first, _ = self.http(port, key, "POST", "/v1/jobs", {"input": spec["input"]})
        second, _ = self.http(port, key, "POST", "/v1/jobs", {"input": spec["input"]})
        assert first["status"] == 202 and second["status"] == 202, (first, second)
        cancelled, _ = self.http(port, key, "POST", "/v1/jobs/" + second["reply"]["id"] + "/cancel", {}, label + "-cancel")
        assert cancelled["reply"]["status"] == "cancelled", cancelled
        bad, _ = self.http(port, key, "POST", "/v1/jobs", {"input": {**spec["input"], "count": 99}}, label + "-bad-input")
        assert bad["status"] == 400 and bad["error"]["error"]["code"] == "media_input", bad
        for _ in range(200):
            record, _ = self.http(port, key, "GET", "/v1/jobs/" + first["reply"]["id"] + "?wait=30")
            if record["reply"]["status"] in ("succeeded", "failed", "cancelled"):
                break
        assert record["reply"]["status"] == "succeeded", record
        # 4. Retention, usage and the chat refusal, through the CLI.
        kept = self.yougori("model", "optimize", name, "--keep-outputs", "2", label=label + "-keep-outputs")["result"]
        assert kept["keepOutputsHours"] == 2 and kept["applied"] is True, kept
        health = self.result("model_status", {"environmentId": environment_id})
        assert health["outputs"]["keptHours"] == 2, health["outputs"]
        self.write(label + "-health-after", {k: health.get(k) for k in ("queue", "outputs", "speed")})
        usage = self.yougori("model", "usage", name, label=label + "-usage")["result"]
        totals = usage["totals"]
        assert totals["requests"] >= 3 and (totals.get("images", 0) > 0 or totals.get("output_ms", 0) > 0), totals
        chat = self.yougori("model", "chat", name, stdin="hello\n", label=label + "-chat-refused", check=False)
        assert not chat.get("ok") and "generate" in json.dumps(chat), chat
        # 5. The hosted inference: the template in this process serves the same model.
        if self.args.hosted:
            self.hosted(label, spec, port, key)
        # 6. Stop before the next model.
        self.result("stop_model", {"environmentId": environment_id}, label + "-stop")
        self.write(label + "-complete", {"name": name, "files": [os.path.basename(item["path"]) for item in saved["files"]]})

    def website(self):
        """The inference template in this process, started once: its admin session, an API key
        and a ten-dollar balance."""
        if self.site:
            return self.site
        sys.path.insert(0, str(TEMPLATE / "site"))
        from server import Service, Server  # noqa: E402
        import http.client
        folder = tempfile.mkdtemp(prefix="yg-media-template-", dir=str(self.root))
        service = Service(folder, {"email": "admin@example.invalid", "password": "disposable-admin-password"}, account_mode="public")
        web = Server(("127.0.0.1", 0), service)
        thread = threading.Thread(target=web.serve_forever, daemon=True)
        thread.start()

        def call(path, body=None, session=None, key=None, method=None, headers=None):
            values = {"Origin": f"http://127.0.0.1:{web.server_port}", "Content-Type": "application/json", **(headers or {})}
            if session:
                values.update({"Cookie": session[0], "X-CSRF-Token": session[1]})
            if key:
                values["Authorization"] = "Bearer " + key
            connection = http.client.HTTPConnection("127.0.0.1", web.server_port, timeout=1800)
            try:
                connection.request(method or ("GET" if body is None else "POST"), path, body=None if body is None else json.dumps(body), headers=values)
                response = connection.getresponse()
                raw = response.read()
                kind = response.getheader("Content-Type", "")
                return response.status, json.loads(raw) if kind.startswith("application/json") else raw, dict(response.getheaders())
            finally:
                connection.close()
        status, _, headers = call("/api/login", {"email": "admin@example.invalid", "password": "disposable-admin-password"})
        assert status == 200, status
        cookie = headers["Set-Cookie"].split(";")[0]
        session = (cookie, call("/api/session", session=(cookie, ""))[1]["user"]["csrf"])
        status, created, _ = call("/api/keys", {"label": "media-check", "scopes": ["*"]}, session)
        assert status == 201, created
        user = call("/api/session", session=session)[1]["user"]["id"]
        with service.store.db() as db:
            db.execute("INSERT INTO credit_ledger VALUES(?,?,?,'payment',?,?,?)", (secrets.token_hex(8), user, 10000000, int(time.time()), "base", secrets.token_hex(8)))
        self.site = {"service": service, "web": web, "thread": thread, "call": call, "session": session, "key": created["key"], "url": f"http://127.0.0.1:{web.server_port}"}
        return self.site

    def hosted_job(self, site, label, model, inputs, kind):
        """One job through the website: submitted, followed to its end, its first file read."""
        call, key = site["call"], site["key"]
        status, job, _ = call("/v1/jobs", {"model": model, "input": inputs}, key=key)
        self.write(label + "-submitted", {"status": status, "reply": job})
        assert status == 202 and job["status"] in ("queued", "running"), job
        for _ in range(120):
            status, view, _ = call(f"/v1/jobs/{job['id']}?wait=30", key=key)
            assert status == 200, view
            if view["status"] in ("succeeded", "failed", "cancelled"):
                break
        self.write(label + "-finished", {"status": status, "reply": view})
        assert view["status"] == "succeeded", view
        entry = view["output"]["files"][0]
        assert entry["url"] == "/v1/files/" + job["id"] + ".1" and entry["content_type"] == kind, entry
        status, content, headers = call(entry["url"], key=key)
        assert status == 200 and headers.get("Content-Type") == kind and looks_like_bytes(content, kind), (status, headers, content[:16])
        self.write(label + "-file", {"status": status, "contentType": headers.get("Content-Type"), "bytes": len(content), "head": content[:12].hex()})
        return view

    def hosted(self, label, spec, port, key):
        """The inference template serving this model: connected by address and, for the image
        model, through a contributor's connector; a job and the OpenAI shape through the website."""
        site = self.website()
        call, session, api_key = site["call"], site["session"], site["key"]
        status, body, _ = call("/api/admin/endpoints", {"name": label + " server", "url": f"http://127.0.0.1:{port}/v1", "key": key, "place": "local"}, session)
        assert status == 201, body
        endpoint = body["id"]
        catalog = {m["id"]: m for m in call("/api/models")[1]["models"]}
        model = next(m for m in catalog.values() if m["task"] == spec["task"])
        self.write(label + "-hosted-catalog", {k: v for k, v in model.items() if k in ("id", "state", "task", "protocols", "features", "replicas")})
        assert model["state"] == "ready" and model["protocols"][0] == "jobs" and model["features"]["media"] == spec["task"], model
        status, body, _ = call("/api/admin/media/prices", {"model": model["id"], "image_usd": "0.01", "second_usd": "0.02"}, session)
        assert status == 200, body
        status, body, _ = call("/v1/chat/completions", {"model": model["id"], "messages": [{"role": "user", "content": "hi"}]}, key=api_key)
        assert status == 404 and body["error"]["code"] == "task_mismatch", (status, body)
        kind = {"image": "image/png", "speech": "audio/wav", "video": "video/mp4", "sound": "audio/wav"}[label]
        view = self.hosted_job(site, label + "-hosted-job", model["id"], spec["input"], kind)
        # OpenAI's shape of this kind, through the website.
        if label == "image":
            status, body, _ = call("/v1/images/generations", {"model": model["id"], "prompt": spec["input"]["prompt"], "size": "512x512", "steps": 2, "guidance": 0}, key=api_key)
            self.write(label + "-hosted-images", {"status": status, "job": body.get("job"), "usage": body.get("usage"), "images": len(body.get("data", []))})
            assert status == 200 and base64.b64decode(body["data"][0]["b64_json"]).startswith(MAGIC["image/png"]), (status, str(body)[:300])
        elif label == "speech":
            status, content, headers = call("/v1/audio/speech", {"model": model["id"], "input": spec["input"]["text"]}, key=api_key)
            self.write(label + "-hosted-speech", {"status": status, "contentType": headers.get("Content-Type"), "bytes": len(content), "head": content[:12].hex()})
            assert status == 200 and looks_like_bytes(content, "audio/wav"), (status, content[:16])
        elif label == "video":
            status, video, _ = call("/v1/videos", {"model": model["id"], "prompt": spec["input"]["prompt"], "seconds": 2, "size": "256x256", "steps": 20}, key=api_key)
            assert status == 200 and video["object"] == "video", (status, video)
            for _ in range(120):
                status, video, _ = call(f"/v1/videos/{video['id']}?wait=30", key=api_key)
                if video["status"] in ("completed", "failed"):
                    break
            self.write(label + "-hosted-video", {"status": status, "reply": video})
            assert video["status"] == "completed", video
            status, content, headers = call(f"/v1/videos/{video['id']}/content", key=api_key)
            assert status == 200 and looks_like_bytes(content, "video/mp4"), (status, content[:16])
        usage = call("/api/usage", session=session)[1]["requests"]
        charged = [u for u in usage if u["model"] == model["id"]]
        self.write(label + "-hosted-usage", charged[:3])
        assert charged and charged[0]["status"] == "completed" and charged[0]["billing_state"] == "charged" and charged[0]["cost_microusd"] > 0, charged[:3]
        if label == "image":
            self.hosted_relay(site, endpoint, spec, port, key, model["id"])
        else:
            status, body, _ = call("/api/admin/endpoints/remove", {"id": endpoint}, session)
            assert status == 200, body

    def hosted_relay(self, site, endpoint, spec, port, key, model):
        """The same model through a contributor's connector: the website's request stream, the
        job routes and the file relayed in chunks by compute_node and the adapter."""
        import compute_node  # noqa: E402
        from compute_adapter import Adapter  # noqa: E402
        call, session = site["call"], site["session"]
        token = secrets.token_urlsafe(32)
        status, pair, _ = call("/api/compute/pair/start", {"credential_hash": hashlib.sha256(token.encode()).hexdigest(), "name": "Contributor", "role": "contributor"})
        assert status == 200, pair
        assert call("/api/compute/pair/approve", {"code": pair["code"]}, session)[0] == 200
        adapter = Adapter("unused", Path(tempfile.mkdtemp(prefix="yg-media-node-", dir=str(self.root))))
        adapter.shared = {"env-live"}
        adapter.apis = {"env-live": {"apiUrl": f"http://127.0.0.1:{port}/v1", "apiKey": key, "model": model}}
        facts = adapter.facts("env-live", adapter.apis["env-live"])
        assert facts["task"] == spec["task"], facts
        inventory = {"models": [{"id": "env-live", "name": model, "state": "ready", "shared": True, "task": facts["task"]}], "media": True, "platform": "check", "detail": "live check"}
        status, body, _ = call("/api/compute/agent", {"action": "inventory", **inventory}, headers={"Authorization": "Bearer " + token})
        assert status == 200, body
        # Only the connector serves the model now.
        assert call("/api/admin/endpoints/remove", {"id": endpoint}, session)[0] == 200
        link = compute_node.Link(site["url"])
        stopped, relayed = threading.Event(), []

        def deliver(task):
            relayed.append({"path": task["path"], "method": task["method"], "limit": task.get("limit")})

            def serve():
                link.post("/api/compute/agent", {"action": "ack", "id": task["id"]}, token)
                adapter.inference(task, lambda part: link.post("/api/compute/agent", {"action": "chunk", **part}, token))
            threading.Thread(target=serve, daemon=True).start()
        threading.Thread(target=compute_node.receive, args=(link, token, deliver, stopped), daemon=True).start()
        for _ in range(200):
            if site["service"].compute.generations:
                break
            time.sleep(.05)
        try:
            self.hosted_job(site, "image-relay-job", model, spec["input"], "image/png")
        finally:
            stopped.set()
        self.write("image-relay-paths", relayed)
        assert any(r["path"] == "/jobs" for r in relayed) and any(r["path"].startswith("/files/") for r in relayed), relayed
        assert call("/api/compute/agent", {"action": "inventory", **{**inventory, "models": []}}, headers={"Authorization": "Bearer " + token})[0] == 200

    def run(self):
        self.start()
        for label in self.args.only:
            self.check_model(label, MODELS[label])
        self.write("complete", {"models": self.kept, "hosted": bool(self.args.hosted)})

    def clean(self):
        if self.site:
            self.site["service"].stopped.set()
            self.site["web"].shutdown()
            self.site["web"].server_close()
            self.site["thread"].join(5)
            self.site = None
        if self.process is None or self.process.poll() is not None:
            return
        for label, item in self.kept.items():
            self.call("stop_model", {"environmentId": item["id"]}, "cleanup-" + label + "-stop", checked=False)
            if self.args.delete:
                self.call("delete_environment", {"environmentId": item["id"]}, "cleanup-" + label + "-delete", checked=False)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for name in ("root", "engine", "cli", "runtime"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--only", default="image,speech,video,sound", help="which of image, speech, video, sound to check")
    parser.add_argument("--existing-root", action="store_true", help="continue evidence in an existing root")
    parser.add_argument("--storage-drive", default="D:\\")
    parser.add_argument("--delete", action="store_true", help="delete the model environments afterwards (they are kept by default)")
    parser.add_argument("--hosted", action="store_true", help="also serve each model through the inference template in this process")
    args = parser.parse_args()
    args.only = [name.strip() for name in args.only.split(",") if name.strip()]
    unknown = [name for name in args.only if name not in MODELS]
    if unknown:
        parser.error("--only takes image, speech, video and sound")
    args.reuse_fixture = args.existing_root
    check = Check(args)
    try:
        check.run()
    except BaseException as error:
        check.write("FAILED", {"type": type(error).__name__, "error": str(error)[:4000]})
        raise
    finally:
        check.clean()
        check.stop()


if __name__ == "__main__":
    main()
