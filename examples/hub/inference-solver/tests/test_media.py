"""Media jobs through the website: images, video, speech and sound from a disposable media model
server, over real website HTTP and SQLite, by address and through a contributing computer's
connector. No GPU.

Run: python -I -B examples/hub/inference-solver/tests/test_media.py
"""
import base64
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import http.client
import json
from pathlib import Path
import secrets
import sys
import threading
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow, UPSTREAM_KEY
import compute_node
from compute_adapter import Adapter

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
WAV = b"RIFF" + (36 + 64).to_bytes(4, "little") + b"WAVEfmt " + (16).to_bytes(4, "little") + (1).to_bytes(2, "little") + (1).to_bytes(2, "little") \
    + (16000).to_bytes(4, "little") + (32000).to_bytes(4, "little") + (2).to_bytes(2, "little") + (16).to_bytes(2, "little") + b"data" + (64).to_bytes(4, "little") + bytes(64)
MP4 = b"\x00\x00\x00\x18ftypisom" + bytes(1500)
OUTPUTS = {"text-to-image": ("image-1.png", "image/png", PNG, {"width": 1, "height": 1}, {"images": 1, "output_seconds": 0.0}),
           "text-to-speech": ("audio.wav", "audio/wav", WAV, {"seconds": 0.002, "sample_rate": 16000}, {"images": 0, "output_seconds": 0.002}),
           "text-to-video": ("video.mp4", "video/mp4", MP4, {"seconds": 2.0, "fps": 8, "frames": 16, "width": 256, "height": 256, "audio": False}, {"images": 0, "output_seconds": 2.0}),
           "text-to-audio": ("audio.wav", "audio/wav", WAV, {"seconds": 0.002, "sample_rate": 16000}, {"images": 0, "output_seconds": 0.002})}


class MediaModel(BaseHTTPRequestHandler):
    """Yougori's media runner as its job routes answer: one model, one job at a time."""

    def log_message(self, *_):
        pass

    def reply(self, status, value):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data)

    def authorized(self):
        if self.headers.get("Authorization") != "Bearer " + UPSTREAM_KEY:
            self.reply(401, {"error": {"message": UPSTREAM_KEY}})
            return False
        return True

    def view(self, job):
        with self.server.lock:
            self.server.run(job)
            value = {k: v for k, v in job.items() if not k.startswith("_")}
        return value

    def do_GET(self):
        if not self.authorized():
            return
        server, path, _, query = self.server, *self.path.partition("?")
        if path == "/health":
            return self.reply(200, {"status": "ready", "task": server.task, "capabilities": {"media": {"supported": True, "task": server.task}, "structuredOutput": {"supported": False}}})
        if path == "/v1/models":
            return self.reply(200, {"data": [{"id": server.model, "object": "model", "task": server.task, "capabilities": {"structuredOutput": False, "media": server.task}}]})
        parts = path.strip("/").split("/")
        if parts[:2] == ["v1", "jobs"] and len(parts) == 2:
            with server.lock:
                return self.reply(200, {"object": "list", "data": [self.view(j) for j in server.jobs.values()]})
        if parts[:2] == ["v1", "jobs"] and len(parts) in (3, 4):
            job = server.jobs.get(parts[2])
            if not job:
                return self.reply(404, {"error": {"code": "job_unknown", "message": "No such job; it may have expired."}})
            wait = int(query.split("wait=")[1]) if "wait=" in query else 0
            ends = time.monotonic() + wait
            while self.view(job)["status"] in ("queued", "running") and time.monotonic() < ends:
                time.sleep(0.02)
            view = self.view(job)
            if len(parts) == 3:
                return self.reply(200, view)
            if view["status"] != "succeeded":
                return self.reply(409 if view["status"] in ("queued", "running") else 410, {"error": {"code": "job_" + view["status"], "message": "The job is " + view["status"]}})
            return self.reply(200, view["output"])
        if parts[:2] == ["v1", "files"] and len(parts) == 3:
            job_id, _, index = parts[2].partition(".")
            job = server.jobs.get(job_id)
            if not job or self.view(job)["status"] != "succeeded" or not index.isdigit() or not 1 <= int(index) <= job["input"].get("count", 1):
                return self.reply(404, {"error": {"code": "file_unknown", "message": "No such file; it may have expired."}})
            name, kind, content, _, _ = OUTPUTS[server.task]
            self.send_response(200)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return
        self.reply(404, {"error": {"message": "Endpoint not found"}})

    def do_POST(self):
        if not self.authorized():
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = json.loads(self.rfile.read(length)) if length else {}
        server, parts = self.server, self.path.partition("?")[0].strip("/").split("/")
        if self.path == "/v1/chat/completions":
            return self.reply(404, {"error": {"code": "task_mismatch", "message": "This model generates " + server.task + "; use /v1/jobs."}})
        if self.path == "/v1/jobs":
            if body.get("model") != server.model:
                return self.reply(400, {"error": {"code": "media_input", "message": "This model server serves " + server.model}})
            raw = body.get("input", {})
            if not isinstance(raw.get("prompt", raw.get("text", "x")), str) or not raw.get("prompt", raw.get("text", "x")):
                return self.reply(400, {"error": {"code": "media_input", "message": "prompt is required"}})
            with server.lock:
                server.calls.append(body)
                if len([j for j in server.jobs.values() if j["status"] in ("queued", "running")]) >= server.queue_limit:
                    return self.reply(429, {"error": {"code": "media_queue_full", "message": "This model has jobs waiting; retry later."}})
                job_id = "job_" + secrets.token_hex(12)
                image = raw.pop("image", None)
                job = {"id": job_id, "object": "job", "status": "queued", "task": server.task, "model": server.model, "created": int(time.time()), "started": None,
                       "finished": None, "progress": 0.0, "input": {**raw, "seed": raw.get("seed", 7), "count": raw.get("count", 1), **({"image": {"bytes": len(image)}} if image else {})},
                       "error": None, "output": None, "usage": None, "expires": int(time.time()) + 86400, "position": 1, "_ready": time.monotonic() + server.delay}
                server.jobs[job_id] = job
            return self.reply(202, self.view(job))
        if parts[:2] == ["v1", "jobs"] and len(parts) == 4 and parts[3] == "cancel":
            job = server.jobs.get(parts[2])
            if not job:
                return self.reply(404, {"error": {"code": "job_unknown", "message": "No such job; it may have expired."}})
            with server.lock:
                if job["status"] == "running" and server.slow_cancel:
                    # The real runner stops a running job at its next step: it still runs for now.
                    job["_cancel_at"] = time.monotonic() + server.slow_cancel
                elif job["status"] in ("queued", "running"):
                    job.update(status="cancelled", finished=int(time.time()), error=None)
            return self.reply(200, self.view(job))
        self.reply(404, {"error": {"message": "Endpoint not found"}})

    def do_DELETE(self):
        if not self.authorized():
            return
        parts = self.path.strip("/").split("/")
        job = self.server.jobs.pop(parts[2], None) if parts[:2] == ["v1", "jobs"] and len(parts) == 3 else None
        if not job:
            return self.reply(404, {"error": {"code": "job_unknown", "message": "No such job."}})
        self.server.deleted.append(parts[2])
        self.reply(200, {"id": parts[2], "object": "job.deleted", "deleted": True})


def media_server(task="text-to-image", model=None, delay=0.05, queue_limit=16):
    server = ThreadingHTTPServer(("127.0.0.1", 0), MediaModel)
    server.task, server.model, server.delay, server.queue_limit = task, model or "test/" + task, delay, queue_limit
    server.jobs, server.calls, server.deleted, server.lock = {}, [], [], threading.Lock()
    server.slow_cancel = 0  # seconds a running job keeps running after its cancel

    def run(job):
        """What the runner's worker would do: the job ends once its delay passed."""
        if job["status"] == "running" and job.get("_cancel_at") and time.monotonic() >= job["_cancel_at"]:
            job.update(status="cancelled", finished=int(time.time()), error=None)
        if job["status"] == "queued" and time.monotonic() >= job["_ready"] - server.delay / 2:
            job.update(status="running", started=int(time.time()), progress=0.5)
        if job["status"] == "running" and time.monotonic() >= job["_ready"]:
            name, kind, content, metadata, usage = OUTPUTS[server.task]
            count = job["input"].get("count", 1) if server.task == "text-to-image" else 1
            files = [{"name": name if count == 1 else name.replace("1", str(i)), "content_type": kind, "bytes": len(content), "file": job["id"] + "." + str(i), "url": "/v1/files/" + job["id"] + "." + str(i), **metadata} for i in range(1, count + 1)]
            key = "images" if server.task == "text-to-image" else "video" if server.task == "text-to-video" else "audio"
            output = {"files": files, "seed": job["input"]["seed"], key: [metadata] * count if key == "images" else metadata}
            job.update(status="succeeded", finished=int(time.time()), progress=1.0, output=output, usage={**usage, "images": count if key == "images" else 0, "compute_seconds": 0.5})
    server.run = run
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


class MediaFlow(Flow):
    def setUp(self):
        super().setUp()
        self.media_servers = []

    def tearDown(self):
        for server, thread in self.media_servers:
            server.shutdown()
            server.server_close()
            thread.join()
        super().tearDown()

    def media(self, **options):
        server, thread = media_server(**options)
        self.media_servers.append((server, thread))
        return server, f"http://127.0.0.1:{server.server_port}/v1"

    def connect(self, url, name):
        status, body, _ = self.call("/api/admin/endpoints", {"name": name, "url": url, "key": UPSTREAM_KEY, "place": "local"}, self.admin)
        self.assertEqual(status, 201, body)
        return body["id"]

    def request(self, method, path, body=None, session=None, key=None, headers=None):
        """Like call(), with the method given: a DELETE, or a GET with a body-less header set."""
        values = {"Origin": self.url, "Content-Type": "application/json"}
        if session:
            values.update({"Cookie": session[0], "X-CSRF-Token": session[1]})
        if key:
            values["Authorization"] = "Bearer " + key
        values.update(headers or {})
        conn = http.client.HTTPConnection("127.0.0.1", self.web.server_port, timeout=60)
        try:
            conn.request(method, path, body=None if body is None else json.dumps(body), headers=values)
            result = conn.getresponse()
            raw = result.read()
            kind = result.getheader("Content-Type", "")
            return result.status, json.loads(raw) if kind.startswith("application/json") else raw, dict(result.getheaders())
        finally:
            conn.close()

    def credit(self, session, amount):
        user = self.call("/api/session", session=session)[1]["user"]["id"]
        with self.service.store.db() as db:
            db.execute("INSERT INTO credit_ledger VALUES(?,?,?,'payment',?,?,?)", (secrets.token_hex(8), user, amount, int(time.time()), "base", secrets.token_hex(8)))

    def balance(self, session):
        return self.call("/api/payments", session=session)[1]["balance_microusd"]

    def finished(self, key, job_id):
        for _ in range(100):
            status, body, _ = self.call(f"/v1/jobs/{job_id}?wait=5", key=key)
            self.assertEqual(status, 200, body)
            if body["status"] in ("succeeded", "failed", "cancelled"):
                return body
        self.fail("The job did not end: " + json.dumps(body))

    def test_media_model_takes_jobs_serves_files_and_is_billed_by_what_it_made(self):
        """A model whose server generates images is listed as such, refuses chat, takes jobs with
        the model server's own routes, keeps the job's files on the website under the website's
        own ids, records the job as a request by what it made and charges its image price."""
        server, url = self.media(task="text-to-image", model="test/draw")
        self.connect(self.model_url, "Chat server")
        self.connect(url, "Drawing server")
        self.assertEqual(self.call("/api/admin/media/prices", {"model": "test/draw", "image_usd": "0.01", "second_usd": "0"}, self.admin)[0], 200)
        catalog = {m["id"]: m for m in self.call("/api/models")[1]["models"]}
        model = catalog["test/draw"]
        self.assertEqual((model["task"], model["protocols"], model["features"]), ("text-to-image", ["jobs", "images"], {"json": False, "media": "text-to-image"}))
        self.assertEqual(model["media_price"], {"image_microusd": 10000, "second_microusd": 0})
        self.assertEqual(catalog["test/one"]["task"], "text-generation")
        self.assertNotIn("media", catalog["test/one"]["features"])
        key = self.key()["key"]
        listed = {m["id"]: m for m in self.call("/v1/models", key=key)[1]["data"]}
        self.assertEqual((listed["test/draw"]["task"], listed["test/draw"]["capabilities"]["media"]), ("text-to-image", "text-to-image"))
        self.assertNotIn("media", listed["test/one"]["capabilities"])
        status, body, _ = self.call("/v1/chat/completions", {"model": "test/draw", "messages": [{"role": "user", "content": "hi"}]}, key=key)
        self.assertEqual((status, body["error"]["code"]), (404, "task_mismatch"))
        self.credit(self.admin, 1000000)
        before = self.balance(self.admin)
        status, job, _ = self.call("/v1/jobs", {"model": "test/draw", "input": {"prompt": "a cat", "count": 2, "seed": 3}}, key=key)
        self.assertEqual(status, 202, job)
        self.assertTrue(job["id"].startswith("job_") and len(job["id"]) == 28)
        self.assertEqual((job["status"], job["model"], job["task"]), ("queued", "test/draw", "text-to-image"))
        remote = list(server.jobs)[0]
        self.assertNotEqual(remote, job["id"])
        self.assertEqual(server.calls[-1], {"model": "test/draw", "input": {"prompt": "a cat", "count": 2, "seed": 3}})
        done = self.finished(key, job["id"])
        self.assertEqual(done["status"], "succeeded")
        self.assertNotIn(remote, json.dumps(done))
        self.assertEqual([f["url"] for f in done["output"]["files"]], ["/v1/files/" + job["id"] + ".1", "/v1/files/" + job["id"] + ".2"])
        self.assertEqual(done["usage"]["images"], 2)
        self.assertGreater(done["expires"], time.time() + 3600)
        status, content, headers = self.request("GET", "/v1/files/" + job["id"] + ".1", key=key)
        self.assertEqual((status, content, headers["Content-Type"]), (200, PNG, "image/png"))
        status, content, headers = self.request("GET", "/v1/files/" + job["id"] + ".2", key=key, headers={"Range": "bytes=0-3"})
        self.assertEqual((status, content, headers["Content-Range"]), (206, PNG[:4], "bytes 0-3/" + str(len(PNG))))
        self.assertEqual(self.call("/v1/jobs/" + job["id"] + "/result", key=key)[1]["files"][0]["file"], job["id"] + ".1")
        self.assertEqual(self.call("/v1/jobs", key=key)[1]["data"][0]["id"], job["id"])
        # The model server's copy was removed once the website had the files.
        for _ in range(50):
            if server.deleted:
                break
            time.sleep(0.02)
        self.assertEqual(server.deleted, [remote])
        # Recorded as a request by what it made, and charged two images at a cent each.
        usage = self.call("/api/usage", session=self.admin)[1]["requests"]
        self.assertEqual((usage[0]["model"], usage[0]["status"], usage[0]["images"], usage[0]["cost_microusd"], usage[0]["billing_state"]), ("test/draw", "completed", 2, 20000, "charged"))
        self.assertEqual(before - self.balance(self.admin), 20000)
        control = self.call("/api/admin/control", session=self.admin)[1]
        self.assertEqual(next(m for m in control["models"] if m["model"] == "test/draw")["images"], 2)
        self.assertEqual(self.call("/api/admin/media", session=self.admin)[1]["jobs"], 1)
        # Another key's holder cannot see the job; its owner can delete it.
        other = self.key(session=self.login_new("other@example.invalid"))["key"]
        self.assertEqual(self.call("/v1/jobs/" + job["id"], key=other)[0], 404)
        self.assertEqual(self.request("DELETE", "/v1/jobs/" + job["id"], key=key)[1]["deleted"], True)
        self.assertEqual(self.call("/v1/jobs/" + job["id"], key=key)[0], 404)
        self.assertEqual(self.request("GET", "/v1/files/" + job["id"] + ".1", key=key)[0], 404)
        # Refusals in the model server's shape: input, scope, balance.
        self.assertEqual(self.call("/v1/jobs", {"model": "test/draw", "input": "a cat"}, key=key)[1]["error"]["code"], "media_input")
        self.assertEqual(self.call("/v1/jobs", {"model": "test/draw", "input": {"prompt": ""}}, key=key)[0], 400)
        self.assertEqual(self.call("/v1/jobs", {"model": "test/one", "input": {"prompt": "x"}}, key=key)[1]["error"]["code"], "task_mismatch")
        self.assertEqual(self.call("/v1/jobs", {"model": "test/draw", "input": {"prompt": "x"}}, key=self.key(["test/one"])["key"])[0], 403)
        self.assertEqual(self.call("/v1/jobs", {"model": "test/draw", "input": {"prompt": "x"}}, key=other)[1]["error"]["code"], "insufficient_balance")

    def login_new(self, email):
        status, _, _ = self.call("/api/signup", {"email": email, "password": "disposable-test-password"})
        self.assertEqual(status, 201)
        return self.login(email)

    def test_openai_shapes_images_speech_and_videos(self):
        """OpenAI's images, speech and videos endpoints on top of jobs: inline or linked images,
        WAV bytes, and a video object to poll with its content route."""
        _, draw = self.media(task="text-to-image", model="test/draw")
        _, speak = self.media(task="text-to-speech", model="test/speak")
        _, film = self.media(task="text-to-video", model="test/film")
        for url, name in ((draw, "Drawing"), (speak, "Speech"), (film, "Film")):
            self.connect(url, name)
        key = self.key()["key"]
        status, body, _ = self.call("/v1/images/generations", {"model": "test/draw", "prompt": "a cat", "n": 1, "size": "256x256"}, key=key)
        self.assertEqual(status, 200, body)
        self.assertEqual(base64.b64decode(body["data"][0]["b64_json"]), PNG)
        status, body, _ = self.call("/v1/images/generations", {"model": "test/draw", "prompt": "a cat", "response_format": "url"}, key=key)
        self.assertEqual(status, 200, body)
        self.assertEqual(body["data"][0]["url"], self.url + "/v1/files/" + body["job"] + ".1")
        self.assertEqual(self.call("/v1/images/generations", {"model": "test/speak", "prompt": "x"}, key=key)[1]["error"]["code"], "task_mismatch")
        status, content, headers = self.request("POST", "/v1/audio/speech", {"model": "test/speak", "input": "Hello there"}, key=key)
        self.assertEqual((status, content, headers["Content-Type"]), (200, WAV, "audio/wav"))
        status, video, _ = self.call("/v1/videos", {"model": "test/film", "prompt": "a boat", "seconds": "2", "size": "256x256"}, key=key)
        self.assertEqual((status, video["object"], video["status"]), (200, "video", "queued"), video)
        for _ in range(100):
            status, video, _ = self.call("/v1/videos/" + video["id"] + "?wait=5", key=key)
            if video["status"] == "completed":
                break
        self.assertEqual((video["status"], video["seconds"], video["size"]), ("completed", 2.0, "256x256"))
        status, content, headers = self.request("GET", "/v1/videos/" + video["id"] + "/content", key=key)
        self.assertEqual((status, content, headers["Content-Type"]), (200, MP4, "video/mp4"))
        self.assertEqual(self.request("DELETE", "/v1/videos/" + video["id"], key=key)[1]["object"], "video.deleted")
        usage = self.call("/api/usage", session=self.admin)[1]["requests"]
        self.assertEqual(sorted((u["model"], u["images"], u["output_ms"]) for u in usage), [("test/draw", 1, 0), ("test/draw", 1, 0), ("test/film", 0, 2000), ("test/speak", 0, 2)])

    def test_cancel_limits_retention_and_a_vanished_computer(self):
        """A cancelled job is not charged; outputs leave after the retention or beyond the cap;
        a job whose model server is disconnected is failed, not left in progress."""
        server, url = self.media(task="text-to-video", model="test/film", delay=30)
        endpoint = self.connect(url, "Film")
        self.assertEqual(self.call("/api/admin/media/prices", {"model": "test/film", "image_usd": "0", "second_usd": "0.5"}, self.admin)[0], 200)
        self.credit(self.admin, 5000000)
        key = self.key()["key"]
        # The reservation covers the seconds asked for; a job asking for more than the balance covers is refused.
        self.assertEqual(self.call("/v1/jobs", {"model": "test/film", "input": {"prompt": "x", "seconds": 60}}, key=key)[1]["error"]["code"], "insufficient_balance")
        status, job, _ = self.call("/v1/jobs", {"model": "test/film", "input": {"prompt": "a boat", "seconds": 2}}, key=key)
        self.assertEqual(status, 202, job)
        self.assertLess(self.balance(self.admin), 5000000)  # held
        status, cancelled, _ = self.call("/v1/jobs/" + job["id"] + "/cancel", {}, key=key)
        self.assertEqual((status, cancelled["status"]), (200, "cancelled"))
        self.assertEqual(self.balance(self.admin), 5000000)  # released
        usage = self.call("/api/usage", session=self.admin)[1]["requests"]
        self.assertEqual((usage[0]["status"], usage[0]["billing_state"], usage[0]["cost_microusd"]), ("cancelled", "refunded", 0))
        self.assertEqual(self.call("/v1/jobs/" + job["id"] + "/result", key=key)[0], 410)
        # Retention: a stored job past its expiry leaves at the sweep, with its files.
        server.delay = 0.05
        status, job, _ = self.call("/v1/jobs", {"model": "test/film", "input": {"prompt": "a boat", "seconds": 2}}, key=key)
        done = self.finished(key, job["id"])
        self.assertEqual(done["status"], "succeeded")
        folder = self.service.media.folder / job["id"]
        self.assertTrue((folder / "1.mp4").is_file())
        # Two seconds of video at fifty cents a second.
        self.assertEqual(self.call("/api/usage", session=self.admin)[1]["requests"][0]["cost_microusd"], 1000000)
        self.assertEqual(self.balance(self.admin), 4000000)
        self.assertEqual(self.call("/api/admin/media", {"keep_hours": 1, "cap_gb": 1}, self.admin)[1]["keep_hours"], 1)
        with self.service.store.db() as db:
            db.execute("UPDATE media_jobs SET expires=? WHERE id=?", (int(time.time()) - 1, job["id"]))
        self.service.media.sweep()
        self.assertFalse(folder.exists())
        self.assertEqual(self.call("/v1/jobs/" + job["id"], key=key)[0], 404)
        self.assertEqual(len(self.call("/api/usage", session=self.admin)[1]["requests"]), 2)  # the record stays
        # A computer that vanishes mid-job: the job is failed and its hold released.
        server.delay = 30
        status, job, _ = self.call("/v1/jobs", {"model": "test/film", "input": {"prompt": "a boat", "seconds": 2}}, key=key)
        self.assertEqual(status, 202, job)
        self.assertEqual(self.call("/api/admin/endpoints/remove", {"id": endpoint}, self.admin)[0], 200)
        status, view, _ = self.call("/v1/jobs/" + job["id"], key=key)
        self.assertEqual((status, view["status"]), (200, "failed"))
        self.assertIn("no longer connected", view["error"])
        self.assertEqual(self.balance(self.admin), 4000000)  # the hold released, the earlier charge kept

    def test_a_running_job_deleted_is_hidden_and_recorded_and_freed_when_it_ends(self):
        """Deleting a job that still runs hides it at once, but its record stays until it ends: it
        is then recorded, its hold released and its computer freed, and only then removed. A wait
        for an OpenAI-shaped answer on a computer that stopped answering does not spin."""
        import media
        from upstream import UpstreamError
        server, url = self.media(task="text-to-video", model="test/film", delay=60)
        server.slow_cancel = 1.5
        self.connect(url, "Film")
        self.assertEqual(self.call("/api/admin/media/prices", {"model": "test/film", "image_usd": "0", "second_usd": "0.5"}, self.admin)[0], 200)
        self.credit(self.admin, 5000000)
        key = self.key()["key"]
        status, job, _ = self.call("/v1/jobs", {"model": "test/film", "input": {"prompt": "a boat", "seconds": 2}}, key=key)
        self.assertEqual(status, 202, job)
        with server.lock:
            remote = next(iter(server.jobs.values()))
            remote.update(status="running", started=int(time.time()), progress=0.5)
        status, deleted, _ = self.request("DELETE", "/v1/jobs/" + job["id"], key=key)
        self.assertEqual((status, deleted["deleted"]), (200, True))
        self.assertEqual(self.call("/v1/jobs/" + job["id"], key=key)[0], 404)  # hidden at once
        self.assertEqual(self.call("/v1/jobs", key=key)[1]["data"], [])
        with self.service.store.db() as db:
            self.assertEqual(db.execute("SELECT done FROM media_jobs WHERE id=?", (job["id"],)).fetchone()[0], 0)
        self.assertEqual(sum(r["active"] for r in self.service.router.snapshot().values()), 1)
        self.assertLess(self.balance(self.admin), 5000000)  # still held while it runs
        # The watcher reads it when it ends (cancelled at its next step): recorded, freed, removed.
        for _ in range(200):
            with self.service.store.db() as db:
                left = db.execute("SELECT COUNT(*) FROM media_jobs WHERE id=?", (job["id"],)).fetchone()[0]
            if not left:
                break
            time.sleep(0.05)
        self.assertEqual(left, 0)
        with self.service.store.db() as db:
            self.assertEqual(db.execute("SELECT COUNT(*) FROM media_deleted").fetchone()[0], 0)
        self.assertEqual(sum(r["active"] for r in self.service.router.snapshot().values()), 0)
        self.assertEqual(self.balance(self.admin), 5000000)  # cancelled: not charged
        usage = self.call("/api/usage", session=self.admin)[1]["requests"]
        self.assertEqual((usage[0]["status"], usage[0]["billing_state"]), ("cancelled", "refunded"))
        # A computer that stops answering: the wait reads the job a few times, not in a tight loop.
        status, job, _ = self.call("/v1/jobs", {"model": "test/film", "input": {"prompt": "a boat", "seconds": 2}}, key=key)
        self.assertEqual(status, 202, job)
        user = self.call("/api/session", session=self.admin)[1]["user"]["id"]
        calls, relay, wait = [], self.service.media.relay, media.OPENAI_WAIT

        def unreachable(*_, **__):
            calls.append(1)
            raise UpstreamError("The model server could not be reached securely.", 502)
        self.service.media.relay, media.OPENAI_WAIT = unreachable, 3
        try:
            view = self.service.media.await_job({"user_id": user}, job["id"])
        finally:
            self.service.media.relay, media.OPENAI_WAIT = relay, wait
        self.assertIn(view["status"], ("queued", "running"))
        self.assertLessEqual(len(calls), 6)

    def pair_node(self):
        token = secrets.token_urlsafe(32)
        status, pair, _ = self.call("/api/compute/pair/start", {"credential_hash": hashlib.sha256(token.encode()).hexdigest(), "name": "Contributor", "role": "contributor"})
        self.assertEqual(status, 200, pair)
        self.assertEqual(self.call("/api/compute/pair/approve", {"code": pair["code"]}, self.admin)[0], 200)
        # A contributing computer serves only the models the administrator lists for computers.
        self.assertEqual(self.call("/api/admin/compute/models", {"models": ["test/draw"]}, self.admin)[0], 200)
        return token

    def agent(self, token, action, **data):
        return self.call("/api/compute/agent", {"action": action, **data}, headers={"Authorization": "Bearer " + token})

    def test_connector_relays_jobs_and_files_from_a_contributing_computer(self):
        """A contributing computer reports a media model's task from its server's health; its
        connector relays the job routes and copies the file back in chunks with its content type;
        a connector that predates media jobs is not sent one."""
        server, url = self.media(task="text-to-image", model="test/draw")
        token = self.pair_node()
        adapter = Adapter("unused", Path(self.temp.name) / "node")
        adapter.call = lambda method, **params: ({"environments": [{"id": "env-draw", "kind": "container", "status": "running", "description": "Hugging Face · test/draw"}]}
                                                 if method in ("get_platform_state", "refresh_host_metrics") else {"model": "test/draw", "apiUrl": url, "apiKey": UPSTREAM_KEY})
        adapter.shared.add("env-draw")
        inventory = adapter.inventory()
        self.assertEqual((inventory["models"][0]["task"], inventory["media"]), ("text-to-image", True))
        # An older connector: no task, no media relay. Its model is a chat model to the website.
        self.assertEqual(self.agent(token, "inventory", models=[{"id": "env-draw", "name": "test/draw", "state": "ready", "shared": True}])[0], 200)
        self.assertEqual(self.call("/api/models")[1]["models"][0]["task"], "text-generation")
        # The current connector: the task reaches the catalog, and jobs are relayed to it.
        self.assertEqual(self.agent(token, "inventory", **inventory)[0], 200)
        catalog = {m["id"]: m for m in self.call("/api/models")[1]["models"]}
        self.assertEqual(catalog["test/draw"]["task"], "text-to-image")
        link = compute_node.Link(self.url)
        stopped, relayed = threading.Event(), []

        def deliver(task):
            relayed.append((task["path"], task["method"], task.get("limit")))
            def serve():
                link.post("/api/compute/agent", {"action": "ack", "id": task["id"]}, token)
                adapter.inference(task, lambda part: link.post("/api/compute/agent", {"action": "chunk", **part}, token))
            threading.Thread(target=serve, daemon=True).start()

        listener = threading.Thread(target=compute_node.receive, args=(link, token, deliver, stopped), daemon=True)
        listener.start()
        for _ in range(200):
            if self.service.compute.generations:
                break
            time.sleep(.01)
        key = self.key()["key"]
        status, job, _ = self.call("/v1/jobs", {"model": "test/draw", "input": {"prompt": "a cat"}}, key=key)
        self.assertEqual(status, 202, job)
        done = self.finished(key, job["id"])
        self.assertEqual(done["status"], "succeeded", done)
        status, content, headers = self.request("GET", "/v1/files/" + job["id"] + ".1", key=key)
        self.assertEqual((status, content, headers["Content-Type"]), (200, PNG, "image/png"))
        paths = [path for path, _, _ in relayed]
        self.assertIn("/jobs", paths)
        self.assertTrue(any(path.startswith("/files/") for path in paths), paths)
        self.assertEqual([method for path, method, _ in relayed if path.startswith("/files/")], ["GET"])
        self.assertTrue(any(limit == 2 * 1024 ** 3 for path, _, limit in relayed if path.startswith("/files/")))
        for _ in range(50):
            if server.deleted:
                break
            time.sleep(0.02)
        self.assertEqual(len(server.deleted), 1)
        # A refusal from the model server keeps its words through the relay.
        status, body, _ = self.call("/v1/jobs", {"model": "test/draw", "input": {"prompt": ""}}, key=key)
        self.assertEqual((status, body["error"]["code"]), (400, "media_input"), body)
        self.assertIn("prompt is required", body["error"]["message"])
        stopped.set()
        # The same model shared by a connector that predates media jobs: the job is not sent there.
        self.assertEqual(self.agent(token, "inventory", **{**inventory, "media": False})[0], 200)
        status, body, _ = self.call("/v1/jobs", {"model": "test/draw", "input": {"prompt": "a cat"}}, key=key)
        self.assertEqual(status, 503, body)
        self.assertIn("predates media jobs", body["error"]["message"])

    def test_session_try_it_routes(self):
        """The model page's Try it box uses the session's own routes: the signed-in member's jobs
        and files, with the CSRF token on writes; nobody else's, and nothing when signed out."""
        _, url = self.media(task="text-to-speech", model="test/speak")
        self.connect(url, "Speech")
        # Signed out: a write is stopped by the same-origin and session gate; a read says to sign in.
        self.assertEqual(self.call("/api/media/jobs", {"model": "test/speak", "input": {"text": "hello"}})[0], 403)
        self.assertEqual(self.call("/api/media/jobs")[0], 401)
        status, job, _ = self.call("/api/media/jobs", {"model": "test/speak", "input": {"text": "hello"}}, self.admin)
        self.assertEqual(status, 202, job)
        for _ in range(100):
            status, view, _ = self.call("/api/media/jobs/" + job["id"] + "?wait=5", session=self.admin)
            if view["status"] == "succeeded":
                break
        self.assertEqual(view["status"], "succeeded", view)
        status, content, headers = self.request("GET", "/api/media/files/" + job["id"] + ".1", session=self.admin)
        self.assertEqual((status, content, headers["Content-Type"]), (200, WAV, "audio/wav"))
        self.assertEqual(self.call("/api/media/jobs", session=self.admin)[1]["data"][0]["id"], job["id"])
        other = self.login_new("other@example.invalid")
        self.assertEqual(self.call("/api/media/jobs/" + job["id"], session=other)[0], 404)
        self.assertEqual(self.request("GET", "/api/media/files/" + job["id"] + ".1", session=other)[0], 404)
        self.assertEqual(self.request("GET", "/api/media/files/" + job["id"] + ".1")[0], 401)
        usage = self.call("/api/usage", session=self.admin)[1]["requests"]
        self.assertEqual((usage[0]["model"], usage[0]["status"]), ("test/speak", "completed"))


if __name__ == "__main__":
    unittest.main()
