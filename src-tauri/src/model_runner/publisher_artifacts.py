"""Publisher-owned model files. No prompts, credentials, disks or uploads are exported."""
import base64
import hashlib
import hmac
import tarfile
from urllib.parse import urlsplit, parse_qs

PUBLISH_LOCK = threading.RLock()
PUBLISH_ENABLED = False
PUBLISH_MANIFEST = None
PUBLISH_ERROR = None
PUBLISH_BUILDING = False
PUBLISH_VALIDATING = False
PUBLISH_PARTS = []
PUBLISH_STATS = []
PART_BYTES = 8 * 1024 * 1024
MODEL_ASSETS = {"config.json", "generation_config.json", "tokenizer.json", "tokenizer_config.json",
                "special_tokens_map.json", "added_tokens.json", "vocab.json", "merges.txt",
                "tokenizer.model", "tokenizer.tiktoken", "chat_template.jinja",
                "model.safetensors.index.json", "joint_head_config.json", "README.md", "LICENSE", "LICENSE.txt", "LICENSE.md",
                "COPYING", "COPYING.txt", "NOTICE", "NOTICE.txt", "PAPER_LICENSE.txt", "CITATION.cff", "requirements.txt"}
PUBLICATION_DOCS = {"README.md", "LICENSE", "LICENSE.txt", "LICENSE.md", "COPYING", "COPYING.txt",
                    "NOTICE", "NOTICE.txt", "PAPER_LICENSE.txt", "CITATION.cff", "config.json"}
STATE["publicationMetadata"] = True


def publisher_metadata():
    """Small named card/license files only; works while weight downloads are closed."""
    _, paths = publisher_files()
    files, total = [], 0
    for name, path in paths:
        if name not in PUBLICATION_DOCS:
            continue
        with open(path, "rb") as file:
            data = file.read(65537)
        if len(data) > 65536 or total + len(data) > 131072:
            continue
        total += len(data)
        files.append({"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest(), "data": base64.b64encode(data).decode("ascii")})
    return {"model": MODEL, "revision": STATE.get("revision") or MODEL_REVISION, "files": files}


def load_source():
    # A file-only publisher has no ML dependencies and never imports model code.
    registry_snapshot()
    STATE.update(status="ready", revision=MODEL_REVISION, runner="file-publisher", sourceOnly=True, inferenceAvailable=False, stream=False)
    print("Source files ready. No weights: downloads only; chat and inference API are unavailable.", flush=True)


def publisher_files():
    root = globals().get("MODEL_SNAPSHOT_ROOT") or MODEL_PATH
    cached = globals().get("GPU_ENABLED", False) and STATE.get("weightsVerified") is True and STATE.get("status") in ("idle", "queued", "freeing_memory", "loading", "unloading")
    if not root or not (STATE.get("status") == "ready" or cached):
        raise ValueError("Wait until the model is ready")
    names = globals().get("MODEL_SNAPSHOT_FILES") or os.listdir(root)
    files = []
    for name in sorted(set(names)):
        if name in MODEL_ASSETS or name.endswith((".safetensors", ".gguf", ".py")):
            if not re.fullmatch(r"[A-Za-z0-9_./-]{1,240}", name) or ".." in name or name.startswith("/"):
                raise ValueError("Invalid model file name")
            path = os.path.join(root, name)
            # HF snapshot symlinks resolve to verified cache blobs; user folders are verified by the runner.
            if os.path.isfile(path):
                files.append((name, path))
    if not files or len(files) > 512 or (not STATE.get("sourceOnly") and not any(name.endswith((".safetensors", ".gguf")) for name, _ in files)):
        raise ValueError("No supported model weights to publish")
    return root, files


def file_stat(path):
    st = os.stat(path)
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns)


def verified_stat(path, before, size, digest):
    """Shared-folder mounts can replace inode identities without changing bytes."""
    current = file_stat(path)
    if current == before:
        return current
    if current[2] != size:
        raise ValueError("Published model files changed")
    checksum = hashlib.sha256()
    with open(path, "rb") as file:
        while True:
            chunk = file.read(PART_BYTES)
            if not chunk:
                break
            checksum.update(chunk)
    after = file_stat(path)
    if after[2] != size or checksum.hexdigest() != digest:
        raise ValueError("Published model files changed")
    return after


def publisher_validate(changed):
    global PUBLISH_VALIDATING, PUBLISH_ERROR
    try:
        for index, path, before, item in changed:
            after = verified_stat(path, before, item["bytes"], item["sha256"])
            with PUBLISH_LOCK:
                PUBLISH_STATS[index] = (path, after)
        with PUBLISH_LOCK:
            PUBLISH_ERROR = None
    except (ValueError, OSError):
        with PUBLISH_LOCK:
            PUBLISH_ERROR = "Published files no longer match their verified checksums. Restore the original files or rerun the model folder to publish a new version."
    finally:
        with PUBLISH_LOCK:
            PUBLISH_VALIDATING = False


def publisher_build():
    global PUBLISH_MANIFEST, PUBLISH_PARTS, PUBLISH_STATS, PUBLISH_ERROR, PUBLISH_BUILDING
    try:
        _, paths = publisher_files()
        files, parts, stats = [], [], []
        for name, path in paths:
            before = file_stat(path)
            full, chunks = hashlib.sha256(), []
            with open(path, "rb") as file:
                while True:
                    chunk = file.read(PART_BYTES)
                    if not chunk:
                        break
                    full.update(chunk)
                    chunks.append({"sha256": hashlib.sha256(chunk).hexdigest(), "bytes": len(chunk)})
            before = verified_stat(path, before, before[2], full.hexdigest())
            files.append({"name": name, "bytes": before[2], "sha256": full.hexdigest(), "partCount": len(chunks)})
            parts.append(chunks)
            stats.append((path, before))
        model_type, prequantized = None, False
        config_path = os.path.join(publisher_files()[0], "config.json")
        if os.path.isfile(config_path):
            with open(config_path, encoding="utf-8") as file:
                config = json.loads(file.read(2 * 1024 * 1024))
                model_type = (config.get("text_config") or config).get("model_type")
                prequantized = bool(config.get("quantization_config") or (config.get("text_config") or {}).get("quantization_config"))
        identity = hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        with PUBLISH_LOCK:
            PUBLISH_MANIFEST = {"revision": STATE.get("revision") or MODEL_REVISION, "artifactRevision": identity,
                                "model": MODEL, "modelType": model_type, "prequantized": prequantized, "sourceOnly": bool(STATE.get("sourceOnly")), "inferenceAvailable": not bool(STATE.get("sourceOnly")), "files": files, "partBytes": PART_BYTES}
            PUBLISH_PARTS, PUBLISH_STATS = parts, stats
    except Exception:
        with PUBLISH_LOCK:
            PUBLISH_ERROR = "Model files could not be prepared for download. Check files and restart publishing."
    finally:
        with PUBLISH_LOCK:
            PUBLISH_BUILDING = False


def publisher_config(body):
    global PUBLISH_ENABLED, PUBLISH_BUILDING, PUBLISH_ERROR
    if not isinstance(body, dict) or set(body) != {"downloads"} or type(body["downloads"]) is not bool:
        raise ValueError("Provide downloads: true or false")
    with PUBLISH_LOCK:
        PUBLISH_ENABLED = body["downloads"]
        if PUBLISH_ENABLED and not PUBLISH_MANIFEST and not PUBLISH_BUILDING:
            PUBLISH_BUILDING, PUBLISH_ERROR = True, None
            threading.Thread(target=publisher_build, daemon=True).start()
        return {"downloads": PUBLISH_ENABLED, "preparing": PUBLISH_ENABLED and PUBLISH_MANIFEST is None}


def publisher_snapshot():
    global PUBLISH_VALIDATING
    with PUBLISH_LOCK:
        if not PUBLISH_ENABLED:
            raise PermissionError("Downloads are disabled for this model")
        if not PUBLISH_MANIFEST:
            raise ValueError(PUBLISH_ERROR or "Preparing model downloads; retry shortly")
        if PUBLISH_VALIDATING:
            raise ValueError("Verifying published files; retry shortly")
        changed = [(i, path, before, PUBLISH_MANIFEST["files"][i]) for i, (path, before) in enumerate(PUBLISH_STATS) if file_stat(path) != before]
        if changed:
            if any(item["bytes"] > PART_BYTES for _, _, _, item in changed):
                PUBLISH_VALIDATING = True
                threading.Thread(target=publisher_validate, args=(changed,), daemon=True).start()
                raise ValueError("Verifying published files; retry shortly")
            for i, path, before, item in changed:
                PUBLISH_STATS[i] = (path, verified_stat(path, before, item["bytes"], item["sha256"]))
        return PUBLISH_MANIFEST


def publisher_cap(value, scope):
    if not isinstance(value, str) or len(value) > 2048:
        raise PermissionError("Invalid download grant")
    try:
        data, signature = value.split(".")
        expected = hmac.new(TOKEN.encode(), data.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise ValueError()
        payload = json.loads(base64.urlsafe_b64decode(data + "=" * (-len(data) % 4)))
        now = int(time.time())
        if payload["scope"] != scope or type(payload["exp"]) is not int or not now < payload["exp"] <= now + 300:
            raise ValueError()
        if payload["revision"] != publisher_snapshot()["artifactRevision"]:
            raise ValueError()
        return payload
    except (ValueError, KeyError, TypeError):
        raise PermissionError("Download grant expired or invalid") from None


def publisher_route(handler):
    url = urlsplit(handler.path)
    if not url.path.startswith("/v1/yougori/"):
        return False
    started = False
    try:
        if url.path == "/v1/yougori/artifacts" and handler.authorized():
            handler.reply(200, publisher_snapshot())
        elif url.path == "/v1/yougori/chunks" and handler.authorized():
            publisher_snapshot()
            query = parse_qs(url.query)
            index, start = int(query.get("file", ["-1"])[0]), int(query.get("start", ["0"])[0])
            if not 0 <= index < len(PUBLISH_PARTS) or not 0 <= start < len(PUBLISH_PARTS[index]):
                raise ValueError("Invalid model part")
            handler.reply(200, {"parts": PUBLISH_PARTS[index][start:start + 64]})
        elif url.path in ("/v1/yougori/part", "/v1/yougori/bundle"):
            query = parse_qs(url.query)
            grant = publisher_cap(query.get("grant", [""])[0], "part" if url.path.endswith("/part") else "bundle")
            manifest = publisher_snapshot()
            if grant["scope"] == "part":
                index, part = grant["file"], grant["part"]
                if type(index) is not int or type(part) is not int or not 0 <= index < len(PUBLISH_STATS) or not 0 <= part < len(PUBLISH_PARTS[index]):
                    raise ValueError("Invalid model part")
                path, _ = PUBLISH_STATS[index]
                with open(path, "rb") as file:
                    file.seek(part * PART_BYTES)
                    data = file.read(PUBLISH_PARTS[index][part]["bytes"])
                if hashlib.sha256(data).hexdigest() != PUBLISH_PARTS[index][part]["sha256"]:
                    raise ValueError("Model file changed")
                started = True
                handler.send_response(200)
                handler.send_header("Content-Type", "application/octet-stream")
                handler.send_header("Content-Length", str(len(data)))
                handler.send_header("Cache-Control", "no-store")
                handler.send_header("Connection", "close")
                handler.end_headers()
                handler.wfile.write(data)
            else:
                started = True
                handler.send_response(200)
                handler.send_header("Content-Type", "application/x-tar")
                handler.send_header("Content-Disposition", 'attachment; filename="yougori-model.tar"')
                handler.send_header("Cache-Control", "no-store")
                handler.send_header("Connection", "close")
                handler.end_headers()
                handler.close_connection = True
                with tarfile.open(fileobj=handler.wfile, mode="w|") as archive:
                    for index, item in enumerate(manifest["files"]):
                        publisher_snapshot()  # Stop an active transfer after downloads are disabled.
                        entry = tarfile.TarInfo(item["name"])
                        entry.size, entry.mode = item["bytes"], 0o644
                        with open(PUBLISH_STATS[index][0], "rb") as file:
                            archive.addfile(entry, file)
        else:
            raise PermissionError("A publisher credential or download grant is required")
    except PermissionError as error:
        if started:
            handler.close_connection = True
            return True
        handler.reply(403, {"error": {"message": str(error)}})
    except (ValueError, OSError, IndexError, KeyError):
        if started:
            handler.close_connection = True
            return True
        handler.reply(503, {"error": {"message": "Model download unavailable; retry while its publisher is online"}})
    return True


def publisher_post(handler):
    try:
        length = int(handler.headers.get("Content-Length", "0"))
        if not 0 < length <= 256 or handler.headers.get("Transfer-Encoding"):
            raise ValueError()
        return handler.reply(200, publisher_config(json.loads(handler.rfile.read(length))))
    except (ValueError, TypeError):
        return handler.reply(400, {"error": {"message": "Invalid publishing settings"}})


# Install additive publishing routes without increasing the guest startup command.
_publisher_download = download_snapshot
_publisher_get = Handler.do_GET
_publisher_post = Handler.do_POST


def publisher_download_snapshot(revision, files):
    root = _publisher_download(revision, files)
    globals().update(MODEL_SNAPSHOT_ROOT=root, MODEL_SNAPSHOT_FILES=list(files))
    return root


def publisher_get(handler):
    if handler.path == "/v1/yougori/metadata" and handler.authorized():
        try:
            return handler.reply(200, publisher_metadata())
        except (ValueError, OSError):
            return handler.reply(503, {"error": {"message": "Model metadata is unavailable until the publisher is ready"}})
    if STATE.get("sourceOnly") and handler.path == "/v1/models" and handler.authorized():
        return handler.reply(200, {"object": "list", "data": []})
    if not publisher_route(handler):
        return _publisher_get(handler)


def publisher_handle_post(handler):
    if handler.path == "/v1/yougori/publishing" and handler.authorized():
        return publisher_post(handler)
    if STATE.get("sourceOnly") and handler.authorized():
        return handler.reply(503, {"error": {"message": "Source files only: no weights were supplied. Chat and inference API are unavailable."}})
    return _publisher_post(handler)


download_snapshot = publisher_download_snapshot
Handler.do_GET = publisher_get
Handler.do_POST = publisher_handle_post
