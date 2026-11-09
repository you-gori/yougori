"""Media jobs through the hosted inference: images, video, speech and sound.

A media model, one whose server generates media (Yougori's media runner), takes jobs, not chat.
A job goes to one replica of its model, chosen like a chat request; its state is read from
there while it runs; and when it ends its files are copied here, the job is recorded like a
request and billed by what it made, and the model server's own copy is removed. A result stays
on this website for the retention the administrator sets, whatever happens to the computer
that made it. The routes are the model server's own (`/v1/jobs`, `/v1/files`, and OpenAI's
images, speech and videos shapes), so a client written against one Yougori model works here.
"""
import base64
import binascii
import http.client
import json
import os
import re
import secrets
import shutil
import sqlite3
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs

from compute import FILE_LIMIT, REPLY_LIMIT
from upstream import UpstreamError, connect

BODY_LIMIT = 24 * 1024 * 1024    # A job with an image input: a data URL of at most 16 MiB.
IMAGE_LIMIT = 16 * 1024 * 1024
OPEN_LIMIT = 64                  # Unfinished jobs across the website.
LIST_LIMIT = 100
WAIT_LIMIT = 30                  # Seconds one status read may wait on the model server.
OPENAI_WAIT = 300                # Seconds the images and speech shapes wait for their job: under the
                                 # website proxy's six-minute answer limit; a longer job continues as a job.
KEEP_LIMIT = 24 * 30             # Hours outputs may be kept, at most.
UNREACHABLE_SECONDS = 600        # A job whose computer stayed silent this long is failed.
FILE_TYPES = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp", "video/mp4": "mp4", "audio/wav": "wav", "audio/x-wav": "wav"}
JOB = re.compile(r"job_[a-f0-9]{24}")
FILE = re.compile(r"(job_[a-f0-9]{24})\.([0-9]{1,2})")
UPLOAD = re.compile(r"in_[a-f0-9]{24}")
TERMINAL = ("succeeded", "failed", "cancelled")
IMAGE_TASKS = ("text-to-image", "image-to-image")
VIDEO_TASKS = ("text-to-video", "image-to-video")
REQUEST_STATUS = {"succeeded": "completed", "cancelled": "cancelled"}


class MediaInput(ValueError):
    """A refusal in the model server's own shape: a code the caller can act on, and a status."""

    def __init__(self, message, code="media_input", status=400):
        super().__init__(message)
        self.code, self.status = code, status


def video_object(view):
    """A job as OpenAI's video object shows it."""
    status = {"queued": "queued", "running": "in_progress", "succeeded": "completed", "failed": "failed", "cancelled": "failed"}[view["status"]]
    video = (view.get("output") or {}).get("video") or {}
    return {"id": view["id"], "object": "video", "model": view["model"], "status": status, "progress": int(round(float(view.get("progress") or 0) * 100)),
            "created_at": view.get("created"), "completed_at": view.get("finished") if view["status"] == "succeeded" else None,
            "expires_at": view.get("expires"), "seconds": video.get("seconds") or (view.get("input") or {}).get("seconds"),
            "size": (str(video["width"]) + "x" + str(video["height"])) if video.get("width") else None,
            "error": {"code": "cancelled" if view["status"] == "cancelled" else "failed", "message": view.get("error") or "The job was cancelled."} if status == "failed" else None}


def send_file(handler, path, content_type, size):
    """The file's bytes, whole or the one byte range asked for (a browser's video player seeks)."""
    start, end, status = 0, size - 1, 200
    wanted = handler.headers.get("Range", "")
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", wanted.strip()) if wanted else None
    if match and (match.group(1) or match.group(2)):
        if match.group(1):
            start = int(match.group(1))
            end = int(match.group(2)) if match.group(2) else size - 1
        else:
            start = max(0, size - int(match.group(2)))
        end = min(end, size - 1)
        if start > end or start >= size:
            handler.begin(416, "application/json", 0, extra={"Content-Range": "bytes */" + str(size)})
            return True
        status = 206
    length = end - start + 1
    extra = {"Accept-Ranges": "bytes", "Content-Disposition": "inline"}
    if status == 206:
        extra["Content-Range"] = "bytes " + str(start) + "-" + str(end) + "/" + str(size)
    handler.begin(status, content_type, length, extra=extra)
    with open(path, "rb") as file:
        file.seek(start)
        left = length
        while left > 0:
            piece = file.read(min(1024 * 1024, left))
            if not piece:
                break
            handler.wfile.write(piece)
            left -= len(piece)
    return True


def decode_image(value):
    """(content type, bytes) of an image given as a data URL, as the model server takes it."""
    if not isinstance(value, str) or not value.startswith("data:") or len(value) > IMAGE_LIMIT * 4 // 3 + 64:
        raise MediaInput("image is a data URL of a PNG, JPEG or WebP image of at most 16 MiB, or an uploaded file id")
    head, _, payload = value[5:].partition(",")
    kind = head.split(";")[0].strip().lower()
    if kind not in ("image/png", "image/jpeg", "image/webp") or not head.endswith(";base64"):
        raise MediaInput("image is a data URL of a PNG, JPEG or WebP image (data:image/png;base64,...)")
    try:
        content = base64.b64decode(payload, validate=True)
    except (ValueError, binascii.Error):
        raise MediaInput("image is not valid base64") from None
    if not content or len(content) > IMAGE_LIMIT:
        raise MediaInput("image is empty or larger than 16 MiB")
    return kind, content


def read_json(connection, response, limit=1024 * 1024):
    """The JSON object a model server answered, the connection closed either way."""
    try:
        raw = response.read(limit + 1)
        if len(raw) > limit:
            raise UpstreamError("The model server's answer is too large.", 502)
        value = json.loads(raw)
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, OSError, http.client.HTTPException):
        raise UpstreamError("The model server did not answer with a valid job record.", 502) from None
    finally:
        response.close()
        connection.close()


class Media:
    def __init__(self, service):
        self.service, self.store = service, service.store
        self.folder = Path(service.store.folder) / "media"
        self.lock = threading.Lock()
        self.finishing = set()
        with self.store.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS media_jobs (id TEXT PRIMARY KEY, remote TEXT NOT NULL, user_id TEXT NOT NULL, key_id TEXT NOT NULL,
                    model TEXT NOT NULL, replica TEXT NOT NULL, endpoint TEXT NOT NULL, source TEXT NOT NULL, task TEXT NOT NULL,
                    created INTEGER NOT NULL, state TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, view TEXT NOT NULL,
                    expires INTEGER, bytes INTEGER NOT NULL DEFAULT 0, reached INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS media_jobs_open ON media_jobs(done, created);
                CREATE TABLE IF NOT EXISTS media_inputs (id TEXT PRIMARY KEY, user_id TEXT NOT NULL, content_type TEXT NOT NULL,
                    bytes INTEGER NOT NULL, created INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS media_settings (id INTEGER PRIMARY KEY CHECK(id=1), keep_hours INTEGER NOT NULL, cap_gb INTEGER NOT NULL);
                INSERT OR IGNORE INTO media_settings VALUES(1, 24, 20);
                -- Jobs their owner deleted while they still ran: hidden at once, recorded and billed
                -- by what they made when they end, and removed then.
                CREATE TABLE IF NOT EXISTS media_deleted (id TEXT PRIMARY KEY);
            """)
        self.watcher = threading.Thread(target=self.watch, daemon=True)
        self.watcher.start()

    # --- settings and storage ------------------------------------------------------------
    def settings(self):
        with self.store.db() as db:
            row = db.execute("SELECT keep_hours,cap_gb FROM media_settings WHERE id=1").fetchone()
        return {"keep_hours": row["keep_hours"], "cap_gb": row["cap_gb"]}

    def configure(self, actor, data):
        keep, cap = data.get("keep_hours"), data.get("cap_gb")
        if type(keep) is not int or not 1 <= keep <= KEEP_LIMIT:
            raise MediaInput("Keep outputs for 1 to " + str(KEEP_LIMIT) + " hours.")
        if type(cap) is not int or not 1 <= cap <= 10000:
            raise MediaInput("Cap stored outputs at 1 to 10,000 GB.")
        with self.store.db() as db:
            db.execute("UPDATE media_settings SET keep_hours=?,cap_gb=? WHERE id=1", (keep, cap))
            self.store.audit(db, actor, "media.retention", str(keep) + "h")
        self.sweep()
        return self.snapshot()

    def snapshot(self):
        with self.store.db() as db:
            row = db.execute("SELECT keep_hours,cap_gb FROM media_settings WHERE id=1").fetchone()
            kept = db.execute("SELECT COUNT(*) AS jobs, COALESCE(SUM(bytes),0) AS bytes FROM media_jobs WHERE done=1").fetchone()
            open_jobs = db.execute("SELECT COUNT(*) FROM media_jobs WHERE done=0").fetchone()[0]
        return {"keep_hours": row["keep_hours"], "cap_gb": row["cap_gb"], "jobs": kept["jobs"], "bytes": kept["bytes"], "open": open_jobs, "open_limit": OPEN_LIMIT}

    def sweep(self):
        """Removes finished jobs past the retention, the oldest beyond the storage cap, and
        uploaded inputs after a day. The usage records stay."""
        now, settings = int(time.time()), self.settings()
        with self.store.db() as db:
            expired = [dict(r) for r in db.execute("SELECT id FROM media_jobs WHERE done=1 AND expires<?", (now,))]
            kept = [dict(r) for r in db.execute("SELECT id,bytes FROM media_jobs WHERE done=1 AND expires>=? ORDER BY created DESC", (now,))]
            inputs = [dict(r) for r in db.execute("SELECT id,content_type FROM media_inputs WHERE created<?", (now - 86400,))]
        total = 0
        for row in kept:
            total += row["bytes"]
            if total > settings["cap_gb"] * 1024 ** 3:
                expired.append(row)
        for row in expired:
            shutil.rmtree(self.folder / row["id"], ignore_errors=True)
            with self.store.db() as db:
                db.execute("DELETE FROM media_jobs WHERE id=?", (row["id"],))
        for row in inputs:
            try:
                (self.folder / "inputs" / (row["id"] + "." + FILE_TYPES.get(row["content_type"], "bin"))).unlink()
            except OSError:
                pass
            with self.store.db() as db:
                db.execute("DELETE FROM media_inputs WHERE id=?", (row["id"],))
        with self.store.db() as db:
            db.execute("DELETE FROM media_deleted WHERE id NOT IN (SELECT id FROM media_jobs)")

    # --- the model servers -----------------------------------------------------------------
    def relay(self, replica, path, payload=None, method=None, limit=REPLY_LIMIT):
        """One request to the replica's model server, by the replica's connection: a connected
        computer's relay, or the server's address. (connection, response); the caller reads."""
        method = method or ("GET" if payload is None else "POST")
        if replica["url"].startswith("compute://"):
            return self.service.compute.connect(replica["url"], payload if payload is not None else {}, path, method, limit)
        return connect(replica["url"], replica["secret"], path, payload, timeout=WAIT_LIMIT + 30 if method != "POST" else 120, expect=(200, 201, 202, 206), method=method)

    def replica(self, row):
        """The job's replica as it is connected now, or None once it is gone."""
        for candidate in self.service.router.replicas(self.store, row["model"]):
            if candidate["id"] == row["replica"]:
                return candidate
        return None

    def task_of(self, model):
        tasks = {r["task"] for r in self.service.router.media_replicas(self.service.router.replicas(self.store, model))}
        return tasks.pop() if len(tasks) == 1 else None

    @staticmethod
    def rewrite(view, remote, job_id, model):
        """The job as this website shows it: its own id in place of the model server's, so its
        file links lead here, and the model's catalog name."""
        shown = json.loads(json.dumps(view).replace(remote, job_id))
        shown["model"] = model
        return shown

    # --- jobs ------------------------------------------------------------------------------
    def inline(self, key, inputs):
        """A job's inputs as the model server takes them: an uploaded image goes as its data URL."""
        image = inputs.get("image")
        if isinstance(image, str) and UPLOAD.fullmatch(image):
            with self.store.db() as db:
                row = db.execute("SELECT content_type FROM media_inputs WHERE id=? AND user_id=?", (image, key["user_id"])).fetchone()
            path = self.folder / "inputs" / (image + "." + FILE_TYPES[row["content_type"]]) if row else None
            if not path or not path.is_file():
                raise MediaInput("No such uploaded file; it may have expired.", "file_unknown", 404)
            return {**inputs, "image": "data:" + row["content_type"] + ";base64," + base64.b64encode(path.read_bytes()).decode("ascii")}
        if image is not None:
            decode_image(image)
        return inputs

    def submit(self, key, body, source):
        """Starts one job on a replica of its model; the job as accepted, with this website's id."""
        model = body.get("model")
        if not isinstance(model, str) or not model:
            raise MediaInput("Name the model.")
        if "*" not in key["scopes"] and model not in key["scopes"]:
            raise MediaInput("This API key cannot use that model.", "forbidden", 403)
        inputs = body.get("input", {name: value for name, value in body.items() if name != "model"})
        if not isinstance(inputs, dict):
            raise MediaInput("input must be an object: prompt, negative_prompt, width, height, steps, guidance, seed, count, seconds, fps, voice, image, strength, format")
        inputs = self.inline(key, inputs)
        replicas = self.service.router.replicas(self.store, model)
        if not replicas:
            raise MediaInput("This model is no longer in the catalog.", "model_unknown", 404)
        media = self.service.router.media_replicas(replicas)
        if not media:
            raise MediaInput("This model answers chat, not media jobs; use /v1/chat/completions.", "task_mismatch", 404)
        task = media[0]["task"]
        with self.store.db() as db:
            if db.execute("SELECT COUNT(*) FROM media_jobs WHERE done=0").fetchone()[0] >= OPEN_LIMIT:
                raise MediaInput("This service has " + str(OPEN_LIMIT) + " jobs in progress; retry shortly.", "media_queue_full", 429)
        job_id = "job_" + secrets.token_hex(12)
        order = self.service.router.order(media, job_id)
        if not order:
            raise MediaInput("No computer serving this model is available right now.", "model_unavailable", 503)
        if not self.service.payments.reserve_media(key["user_id"], model, job_id, inputs, task):
            raise MediaInput("Balance is below the job's reservation. Top up in Usage, or ask for fewer images or seconds.", "insufficient_balance", 402)
        self.service.control.presence(key["user_id"], api=True)
        started = time.time()
        last, view, replica = None, None, None
        for candidate in order:
            self.service.router.begin(candidate["id"])
            try:
                connection, response = self.relay(candidate, "/jobs", {"model": candidate["upstream"], "input": inputs})
                view = read_json(connection, response)
                remote = view.get("id")
                if not isinstance(remote, str) or not JOB.fullmatch(remote) or view.get("status") not in ("queued", "running"):
                    raise UpstreamError("The model server did not accept the job.", 502)
                replica = candidate
                break
            except UpstreamError as error:
                # The job's own refusal (400) is the caller's answer; a full queue (429) or a
                # model still loading (503) is tried on the model's other replicas.
                self.service.router.end(candidate["id"], failed=error.status not in (400, 429), cool=error.status not in (400, 429))
                last = error
                if error.status == 400:
                    break
            except BaseException:
                self.service.router.end(candidate["id"], failed=True)
                raise
        if replica is None:
            self.service.payments.finish_media(job_id, False, None, record=lambda db: self.store.request_done(job_id, key, model, started, "failed", db=db))
            raise MediaInput(str(last) if last else "No computer serving this model is available right now.", getattr(last, "code", "") or "model_unavailable", last.status if last else 503)
        shown = self.rewrite(view, remote, job_id, model)
        now = int(time.time())
        with self.store.db() as db:
            db.execute("INSERT INTO media_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,0,?,NULL,0,?)",
                       (job_id, remote, key["user_id"], key["id"], model, replica["id"], replica["endpoint"], replica["source"][:200], task, now, view["status"], json.dumps(shown), now))
        return shown

    def row(self, key, job_id):
        """The caller's job, or None; a job its owner deleted is gone to them at once."""
        if not isinstance(job_id, str) or not JOB.fullmatch(job_id):
            return None
        with self.store.db() as db:
            row = db.execute("SELECT * FROM media_jobs WHERE id=? AND id NOT IN (SELECT id FROM media_deleted)", (job_id,)).fetchone()
        return dict(row) if row and row["user_id"] == key["user_id"] else None

    def purge(self, job_id):
        """Removes a job and its files here; its request and billing records stay."""
        shutil.rmtree(self.folder / job_id, ignore_errors=True)
        with self.store.db() as db:
            db.execute("DELETE FROM media_jobs WHERE id=?", (job_id,))
            db.execute("DELETE FROM media_deleted WHERE id=?", (job_id,))

    def view(self, key, job_id, wait=0):
        """The caller's job as it stands; `wait` seconds for it to end, at most WAIT_LIMIT."""
        row = self.row(key, job_id)
        if not row:
            raise MediaInput("No such job; it may have expired.", "job_unknown", 404)
        if row["done"]:
            return json.loads(row["view"])
        return self.refresh(row, min(max(0, wait), WAIT_LIMIT))

    def refresh(self, row, wait=0):
        """The job's state read from its model server; a job that ended is finished here. A
        server that cannot be reached leaves the last known state, for ten minutes."""
        replica = self.replica(row)
        if replica is None:
            return self.finish(row, None, "The computer that ran this job is no longer connected.")
        try:
            connection, response = self.relay(replica, "/jobs/" + row["remote"] + ("?wait=" + str(wait) if wait else ""))
            view = read_json(connection, response)
        except UpstreamError as error:
            if error.status in (404, 410):
                return self.finish(row, None, "The computer that ran this job no longer has it.")
            if row["reached"] < time.time() - UNREACHABLE_SECONDS:
                return self.finish(row, None, "The computer that ran this job stopped answering.")
            return json.loads(row["view"])
        if view.get("status") in TERMINAL:
            return self.finish(row, view, None, replica)
        shown = self.rewrite(view, row["remote"], row["id"], row["model"])
        with self.store.db() as db:
            db.execute("UPDATE media_jobs SET state=?,view=?,reached=? WHERE id=? AND done=0",
                       (view["status"] if view.get("status") in ("queued", "running") else row["state"], json.dumps(shown), int(time.time()), row["id"]))
        return shown

    def copy(self, replica, remote, view, folder):
        """Copies a finished job's files from its model server into `folder`; their total size."""
        files = (view.get("output") or {}).get("files") or []
        if not isinstance(files, list) or not 1 <= len(files) <= 16 or any(not isinstance(f, dict) for f in files):
            raise UpstreamError("The job's output is not a list of files.", 502)
        folder.mkdir(parents=True, exist_ok=True)
        total = 0
        for index, entry in enumerate(files, 1):
            kind = entry.get("content_type")
            if kind not in FILE_TYPES:
                raise UpstreamError("The job's output is not an image, video or sound file.", 502)
            path = folder / (str(index) + "." + FILE_TYPES[kind])
            connection, response = self.relay(replica, "/files/" + remote + "." + str(index), limit=FILE_LIMIT)
            size = 0
            try:
                with open(path, "wb") as target:
                    while True:
                        piece = response.read(1024 * 1024)
                        if not piece:
                            break
                        size += len(piece)
                        if total + size > FILE_LIMIT:
                            raise UpstreamError("The job's files exceed 2 GiB.", 502)
                        target.write(piece)
            except OSError:
                raise UpstreamError("The output could not be stored on this website.", 503) from None
            finally:
                response.close()
                connection.close()
            if type(entry.get("bytes")) is int and entry["bytes"] != size:
                raise UpstreamError("An output file arrived incomplete.", 502)
            total += size
        return total

    def finish(self, row, view, failure, replica=None):
        """Ends a job here: a succeeded job's files are copied from its model server, the request
        is recorded and billed by what the job made, and the server's copy is removed."""
        with self.lock:
            if row["id"] in self.finishing:
                return json.loads(row["view"])
            self.finishing.add(row["id"])
        try:
            with self.store.db() as db:
                current = db.execute("SELECT done,view FROM media_jobs WHERE id=?", (row["id"],)).fetchone()
            if not current:
                raise MediaInput("No such job; it may have expired.", "job_unknown", 404)
            if current["done"]:
                return json.loads(current["view"])
            size, vanished = 0, view is None
            if vanished:
                shown = {**json.loads(current["view"]), "status": "failed", "error": failure, "finished": int(time.time()), "output": None}
            else:
                if view.get("status") == "succeeded":
                    try:
                        size = self.copy(replica, row["remote"], view, self.folder / row["id"])
                    except UpstreamError as problem:
                        shutil.rmtree(self.folder / row["id"], ignore_errors=True)
                        size, view = 0, {**view, "status": "failed", "error": "The output could not be copied from the computer that made it: " + str(problem), "output": None}
                shown = self.rewrite(view, row["remote"], row["id"], row["model"])
            status = shown["status"] if shown.get("status") in TERMINAL else "failed"
            shown["expires"] = int(time.time()) + self.settings()["keep_hours"] * 3600
            usage = shown.get("usage") if isinstance(shown.get("usage"), dict) else {}
            made = {"images": usage.get("images") if type(usage.get("images")) is int else 0,
                    "output_ms": int(usage["output_seconds"] * 1000) if isinstance(usage.get("output_seconds"), (int, float)) and not isinstance(usage.get("output_seconds"), bool) else 0,
                    "compute_ms": int(usage["compute_seconds"] * 1000) if isinstance(usage.get("compute_seconds"), (int, float)) and not isinstance(usage.get("compute_seconds"), bool) else 0}
            key, served = {"id": row["key_id"], "user_id": row["user_id"]}, {"endpoint": row["endpoint"], "source": row["source"]}

            def record(db):
                self.store.request_done(row["id"], key, row["model"], row["created"], REQUEST_STATUS.get(status, "failed"), db=db, replica=served, media=made)
                db.execute("UPDATE media_jobs SET state=?,done=1,view=?,expires=?,bytes=?,reached=? WHERE id=?",
                           (status, json.dumps(shown), shown["expires"], size, int(time.time()), row["id"]))
            self.service.payments.finish_media(row["id"], status == "succeeded", made, record=record)
            self.service.router.end(row["replica"], failed=vanished)
            if replica is not None:
                # The model server keeps its own copy for its retention; this website has it now.
                try:
                    connection, response = self.relay(replica, "/jobs/" + row["remote"], method="DELETE")
                    response.close()
                    connection.close()
                except (UpstreamError, OSError):
                    pass
            # A job deleted while it ran is recorded and billed above, then removed.
            with self.store.db() as db:
                deleted = db.execute("SELECT 1 FROM media_deleted WHERE id=?", (row["id"],)).fetchone()
            if deleted:
                self.purge(row["id"])
            return shown
        finally:
            with self.lock:
                self.finishing.discard(row["id"])

    def cancel(self, key, job_id):
        row = self.row(key, job_id)
        if not row:
            raise MediaInput("No such job; it may have expired.", "job_unknown", 404)
        if row["done"]:
            return json.loads(row["view"])
        replica = self.replica(row)
        if replica is None:
            return self.finish(row, None, "The computer that ran this job is no longer connected.")
        try:
            connection, response = self.relay(replica, "/jobs/" + row["remote"] + "/cancel", {})
            view = read_json(connection, response)
        except UpstreamError as error:
            if error.status in (404, 410):
                return self.finish(row, None, "The computer that ran this job no longer has it.")
            raise MediaInput(str(error), "model_unavailable", 503) from None
        if view.get("status") in TERMINAL:
            return self.finish(row, view, None, replica)
        # A running job stops at its next step; the next read shows it cancelled.
        return self.refresh(row)

    def delete(self, key, job_id):
        """Deletes the caller's job. A job still running is cancelled and hidden at once, but its
        record stays until it ends: then it is recorded and billed by what it made, its replica
        is freed, and it is removed (`finish`)."""
        row = self.row(key, job_id)
        if not row:
            raise MediaInput("No such job; it may have expired.", "job_unknown", 404)
        if not row["done"]:
            try:
                self.cancel(key, job_id)
            except (MediaInput, UpstreamError):
                pass  # The computer is unreachable: the watcher ends the job and removes it.
            with self.store.db() as db:
                db.execute("INSERT OR IGNORE INTO media_deleted VALUES(?)", (row["id"],))
                current = db.execute("SELECT done FROM media_jobs WHERE id=?", (row["id"],)).fetchone()
            if current and not current["done"]:
                return {"id": job_id, "object": "job.deleted", "deleted": True}
        self.purge(row["id"])
        return {"id": job_id, "object": "job.deleted", "deleted": True}

    def listing(self, key, limit=20):
        with self.store.db() as db:
            rows = db.execute("SELECT view FROM media_jobs WHERE user_id=? AND id NOT IN (SELECT id FROM media_deleted) ORDER BY created DESC LIMIT ?",
                              (key["user_id"], max(1, min(LIST_LIMIT, limit)))).fetchall()
        return [json.loads(r["view"]) for r in rows]

    def file(self, key, file_id):
        """(path, content type, size) of an output file `JOB.N` of the caller's job, or None."""
        match = FILE.fullmatch(file_id or "")
        row = self.row(key, match.group(1)) if match else None
        if not row or not row["done"] or row["state"] != "succeeded":
            return None
        files = (json.loads(row["view"]).get("output") or {}).get("files") or []
        index = int(match.group(2))
        if not 1 <= index <= len(files):
            return None
        kind = files[index - 1].get("content_type")
        path = self.folder / row["id"] / (str(index) + "." + FILE_TYPES.get(kind, "bin"))
        if kind not in FILE_TYPES or not path.is_file():
            return None
        return path, kind, path.stat().st_size

    def upload(self, key, body):
        """Keeps an image input for a day, for jobs that name it by id instead of carrying it."""
        kind, content = decode_image(body.get("data"))
        file_id = "in_" + secrets.token_hex(12)
        folder = self.folder / "inputs"
        folder.mkdir(parents=True, exist_ok=True)
        (folder / (file_id + "." + FILE_TYPES[kind])).write_bytes(content)
        now = int(time.time())
        with self.store.db() as db:
            db.execute("INSERT INTO media_inputs VALUES(?,?,?,?,?)", (file_id, key["user_id"], kind, len(content), now))
        return {"id": file_id, "object": "file", "bytes": len(content), "content_type": kind, "expires": now + 86400}

    def await_job(self, key, job_id):
        """The job once it ended, or as it stands after OPENAI_WAIT seconds."""
        ends = time.monotonic() + OPENAI_WAIT
        while True:
            asked = time.monotonic()
            view = self.view(key, job_id, WAIT_LIMIT)
            if view["status"] in TERMINAL or time.monotonic() >= ends:
                return view
            # A read that came back at once (the computer cannot be reached, so the last known
            # state was given) is not repeated at once: that would spin for the whole wait.
            if time.monotonic() - asked < 1 and self.service.stopped.wait(min(2, max(0, ends - time.monotonic()))):
                return view  # The website is shutting down.

    def watch(self):
        """Reads every unfinished job's state a few times a minute, so a job nobody polls is
        still recorded, billed and copied when it ends; and sweeps stored outputs."""
        last_sweep = 0
        while not self.service.stopped.is_set():
            try:
                with self.store.db() as db:
                    rows = [dict(r) for r in db.execute("SELECT * FROM media_jobs WHERE done=0 ORDER BY created LIMIT ?", (OPEN_LIMIT,))]
                for row in rows:
                    if self.service.stopped.is_set():
                        break
                    try:
                        self.refresh(row)
                    except (MediaInput, UpstreamError, OSError, ValueError, sqlite3.Error):
                        pass
                if time.monotonic() - last_sweep > 60:
                    self.sweep()
                    last_sweep = time.monotonic()
            except (sqlite3.Error, OSError):
                pass
            self.service.stopped.wait(3)

    # --- HTTP ------------------------------------------------------------------------------
    @staticmethod
    def reply(handler, status, value):
        handler.json(status, value)
        return True

    @staticmethod
    def drain(handler):
        """A POST whose body is optional (a cancel): whatever was sent is read and dropped."""
        length = handler.headers.get("Content-Length", "0")
        if length.isdigit() and int(length):
            handler.rfile.read(min(int(length), 65536))

    def absolute(self, handler, url):
        scheme = handler.headers.get("X-Forwarded-Proto") or ("https" if self.service.public or self.service.hosted else "http")
        return scheme + "://" + handler.headers.get("Host", "") + url

    def route(self, handler, key, method, path, query):
        """Answers a media request under /v1 for `key`; False when the path is none of them."""
        parts = path.strip("/").split("/")
        if parts[:2] not in (["v1", "jobs"], ["v1", "files"], ["v1", "videos"]) and path not in ("/v1/images/generations", "/v1/audio/speech"):
            return False
        fields = parse_qs(query, max_num_fields=4) if query else {}
        wait = fields.get("wait", ["0"])[0]
        wait = int(wait) if wait.isdigit() else 0
        source = "web" if key.get("id") == "session" else "api"
        try:
            if path == "/v1/jobs":
                if method == "POST":
                    return self.reply(handler, 202, self.submit(key, handler.body(BODY_LIMIT), source))
                if method == "GET":
                    limit = fields.get("limit", ["20"])[0]
                    return self.reply(handler, 200, {"object": "list", "data": self.listing(key, int(limit) if limit.isdigit() else 20)})
                return False
            if parts[1] in ("jobs", "videos") and len(parts) in (3, 4):
                kind, job_id = parts[1], parts[2]
                if len(parts) == 3 and method == "GET":
                    view = self.view(key, job_id, wait)
                    return self.reply(handler, 200, video_object(view) if kind == "videos" else view)
                if len(parts) == 3 and method == "DELETE":
                    return self.reply(handler, 200, {**self.delete(key, job_id), "object": "video.deleted" if kind == "videos" else "job.deleted"})
                if len(parts) == 4 and parts[3] == "cancel" and method == "POST":
                    self.drain(handler)
                    return self.reply(handler, 200, self.cancel(key, job_id))
                if len(parts) == 4 and parts[3] in ("result", "content") and method == "GET":
                    view = self.view(key, job_id, wait)
                    if view["status"] != "succeeded":
                        waiting = view["status"] in ("queued", "running")
                        raise MediaInput("The job is " + view["status"] + ("." if waiting else ": " + str(view.get("error") or "no output.")), "job_" + view["status"], 409 if waiting else 410)
                    if parts[3] == "result":
                        return self.reply(handler, 200, view["output"])
                    files = (view.get("output") or {}).get("files") or []
                    found = self.file(key, files[0]["file"]) if files else None
                    if not found:
                        raise MediaInput("The output file is gone.", "file_unknown", 404)
                    return send_file(handler, *found)
                return False
            if parts[1] == "files":
                if len(parts) == 3 and method == "GET":
                    found = self.file(key, parts[2])
                    if not found:
                        raise MediaInput("No such file; it may have expired.", "file_unknown", 404)
                    return send_file(handler, *found)
                if len(parts) == 2 and method == "POST":
                    return self.reply(handler, 201, self.upload(key, handler.body(BODY_LIMIT)))
                return False
            if method != "POST":
                return False
            if path == "/v1/images/generations":
                return self.images(handler, key, handler.body(BODY_LIMIT), source)
            if path == "/v1/audio/speech":
                return self.speech(handler, key, handler.body(), source)
            return self.reply(handler, 200, video_object(self.submit(key, self.videos_body(handler.body(BODY_LIMIT)), source)))
        except MediaInput as refusal:
            handler.json(refusal.status, {"error": {"code": refusal.code, "message": str(refusal)}}, retry=refusal.status == 429)
            return True
        except UpstreamError as error:
            handler.json(error.status, {"error": {"code": error.code or "model_unavailable", "message": str(error)}}, retry=error.status in (429, 503))
            return True

    def expect_task(self, model, tasks, shape):
        task = self.task_of(model) if isinstance(model, str) else None
        if task is None:
            raise MediaInput("This model does not generate media; use /v1/chat/completions.", "task_mismatch", 404)
        if task not in tasks:
            raise MediaInput("This model generates " + task + "; use /v1/jobs rather than " + shape + ".", "task_mismatch", 404)
        return task

    def job_failure(self, handler, view):
        if view["status"] in ("queued", "running"):
            return self.reply(handler, 504, {"error": {"code": "job_timeout", "message": "The job did not finish within " + str(OPENAI_WAIT) + " seconds; it continues as job " + view["id"] + "."}, "job": view["id"]})
        return self.reply(handler, 500 if view["status"] == "failed" else 499, {"error": {"code": "job_" + view["status"], "message": view.get("error") or "The job was cancelled."}, "job": view["id"]})

    def images(self, handler, key, body, source):
        """OpenAI's images endpoint on top of a job: one request, the images inline or as links."""
        self.expect_task(body.get("model"), IMAGE_TASKS, "/v1/images/generations")
        if set(body) - {"model", "prompt", "n", "size", "response_format", "seed", "steps", "guidance", "negative_prompt", "output_format", "quality", "style", "user", "image", "strength"}:
            raise MediaInput("Unknown field; use prompt, n, size, response_format (b64_json or url), output_format, seed, steps, guidance, negative_prompt, image and strength")
        inputs = {"prompt": body.get("prompt")}
        size = body.get("size")
        if isinstance(size, str) and size != "auto":
            match = re.fullmatch(r"(\d{2,4})x(\d{2,4})", size)
            if not match:
                raise MediaInput("size is WIDTHxHEIGHT, such as 1024x1024")
            inputs.update(width=int(match.group(1)), height=int(match.group(2)))
        if "n" in body:
            inputs["count"] = body["n"]
        for name in ("seed", "steps", "guidance", "negative_prompt", "image", "strength"):
            if name in body:
                inputs[name] = body[name]
        inputs["format"] = body.get("output_format", "png")
        delivery = body.get("response_format", "b64_json")
        if delivery not in ("b64_json", "url"):
            raise MediaInput("response_format is b64_json or url")
        submitted = self.submit(key, {"model": body["model"], "input": inputs}, source)
        view = self.await_job(key, submitted["id"])
        if view["status"] != "succeeded":
            return self.job_failure(handler, view)
        data = []
        for entry in (view.get("output") or {}).get("files") or []:
            item = {"revised_prompt": None}
            if delivery == "url":
                item["url"] = self.absolute(handler, "/v1/files/" + entry["file"])
            else:
                found = self.file(key, entry["file"])
                if not found:
                    raise MediaInput("The output file is gone.", "file_unknown", 404)
                item["b64_json"] = base64.b64encode(Path(found[0]).read_bytes()).decode("ascii")
            data.append(item)
        return self.reply(handler, 200, {"created": view.get("finished"), "data": data, "job": view["id"], "usage": view.get("usage")})

    def speech(self, handler, key, body, source):
        """OpenAI's speech endpoint: the WAV bytes of one job."""
        self.expect_task(body.get("model"), ("text-to-speech",), "/v1/audio/speech")
        if set(body) - {"model", "input", "voice", "response_format", "speed", "instructions"}:
            raise MediaInput("Unknown field; use input, voice and response_format (wav)")
        if body.get("response_format", "wav") != "wav":
            raise MediaInput("This model answers WAV; set response_format to wav")
        inputs = {"text": body.get("input")}
        if body.get("voice"):
            inputs["voice"] = body["voice"]
        submitted = self.submit(key, {"model": body["model"], "input": inputs}, source)
        view = self.await_job(key, submitted["id"])
        if view["status"] != "succeeded":
            return self.job_failure(handler, view)
        files = (view.get("output") or {}).get("files") or []
        found = self.file(key, files[0]["file"]) if files else None
        if not found:
            raise MediaInput("The speech file is gone.", "file_unknown", 404)
        return send_file(handler, *found)

    def videos_body(self, body):
        """OpenAI's videos request as a job: the job is answered at once, as a video object to poll."""
        self.expect_task(body.get("model"), VIDEO_TASKS, "/v1/videos")
        if set(body) - {"model", "prompt", "seconds", "size", "fps", "input_reference", "seed", "steps", "guidance", "negative_prompt"}:
            raise MediaInput("Unknown field; use prompt, seconds, size, fps, input_reference, seed, steps, guidance and negative_prompt")
        inputs = {}
        if "prompt" in body:
            inputs["prompt"] = body["prompt"]
        if "seconds" in body:
            inputs["seconds"] = float(body["seconds"]) if isinstance(body["seconds"], str) and re.fullmatch(r"\d{1,3}(\.\d+)?", body["seconds"]) else body["seconds"]
        size = body.get("size")
        if isinstance(size, str):
            match = re.fullmatch(r"(\d{2,4})x(\d{2,4})", size)
            if not match:
                raise MediaInput("size is WIDTHxHEIGHT, such as 1280x720")
            inputs.update(width=int(match.group(1)), height=int(match.group(2)))
        for name in ("fps", "seed", "steps", "guidance", "negative_prompt"):
            if name in body:
                inputs[name] = body[name]
        if "input_reference" in body:
            inputs["image"] = body["input_reference"]
        return {"model": body["model"], "input": inputs}
