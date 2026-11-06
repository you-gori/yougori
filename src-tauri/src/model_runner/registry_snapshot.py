def registry_manifest_object(pairs):
    """JSON object keys cannot silently overwrite earlier manifest identities."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate manifest field")
        result[key] = value
    return result


def registry_manifest(path):
    """The manifest's bytes, its checked identities and their total size; no artifact is opened.

    A local folder's manifest arrives in YOUGORI_LOCAL_MANIFEST; otherwise it is the file at
    `path` (a registry version's `.yougori-verified-files.json`, or an import's copy of it).
    """
    limit = 1024 * 1024
    try:
        if "YOUGORI_LOCAL_MANIFEST" in os.environ:
            text = os.environ["YOUGORI_LOCAL_MANIFEST"]
            if len(text) > limit:
                raise ValueError("Oversized manifest")
            encoded = text.encode("utf-8")
        else:
            with open(path, "rb") as file:
                encoded = file.read(limit + 1)
        if len(encoded) > limit:
            raise ValueError("Oversized manifest")
        record = json.loads(encoded.decode("utf-8"), object_pairs_hook=registry_manifest_object)
    except (OSError, ValueError, UnicodeError, RecursionError):
        raise RuntimeError("Invalid uploaded checkpoint manifest") from None
    if not isinstance(record, dict) or set(record) != {"revision", "files"}:
        raise RuntimeError("Invalid uploaded checkpoint manifest")
    if (not isinstance(MODEL_REVISION, str) or record.get("revision") != MODEL_REVISION
            or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", MODEL_REVISION)):
        raise RuntimeError("Uploaded checkpoint revision does not match the model manifest")
    files = record.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 512:
        raise RuntimeError("Invalid uploaded checkpoint manifest")
    total, candidates, names = 0, [], set()
    for item in files:
        if not isinstance(item, dict) or set(item) != {"name", "size", "sha256"}:
            raise RuntimeError("Invalid uploaded artifact identity")
        name, size, digest = item.get("name"), item.get("size"), item.get("sha256")
        # Match engine-generated ASCII names and exclude component/path aliases.
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,240}", name)
                or ".." in name or any(part in ("", ".") or part.endswith(".") for part in name.split("/"))
                or name in names or type(size) is not int or not 0 <= size <= 2**63 - 1
                or not isinstance(digest, str) or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", digest)):
            raise RuntimeError("Invalid uploaded artifact identity")
        names.add(name)
        total += size
        if total > 2**63 - 1:
            raise RuntimeError("Invalid uploaded artifact identity")
        candidates.append((name, size, digest))
    return encoded, candidates, total


def registry_artifacts(root, candidates):
    """Each manifest file's path under `root` with its digest and size, before any is hashed.

    Preflight the whole manifest before hashing any artifact, including aliases
    that resolve to the same file through links or case-insensitive names.
    """
    resolved, paths, identities = [], set(), set()
    for name, size, digest in candidates:
        try:
            path = os.path.realpath(os.path.join(root, name))
            key = os.path.normcase(path)
            if os.path.commonpath([root, path]) != root or key in paths:
                raise RuntimeError("Invalid uploaded artifact identity")
            info = os.stat(path)
            identity = (info.st_dev, info.st_ino)
            if info.st_ino and identity in identities:
                raise RuntimeError("Invalid uploaded artifact identity")
            if not stat.S_ISREG(info.st_mode) or info.st_size != size:
                raise RuntimeError("An uploaded model artifact failed checksum verification")
        except (OSError, ValueError):
            raise RuntimeError("An uploaded model artifact failed checksum verification") from None
        paths.add(key)
        if info.st_ino:
            identities.add(identity)
        resolved.append((path, digest, size))
    return resolved


def registry_snapshot():
    """The engine stages authorized artifacts; recheck them inside the read-only GPU mount.

    An environment with its own model volume (G04) instead imports them from the mount once,
    hashing each file as it is copied, and every start checks and uses only that copy
    (import_model_source in model_server.py).
    """
    global REGISTRY_VERIFIED
    REGISTRY_VERIFIED = None
    globals().pop("MODEL_SNAPSHOT_ROOT", None)
    globals().pop("MODEL_SNAPSHOT_FILES", None)
    try:
        if not isinstance(MODEL_PATH, str) or not MODEL_PATH or "\0" in MODEL_PATH:
            raise ValueError("Invalid mount")
        root = os.path.realpath(MODEL_PATH)
    except (OSError, ValueError):
        raise RuntimeError("Invalid uploaded checkpoint manifest") from None
    if model_import_enabled():
        root, names = import_model_source(root)
    else:
        _encoded, candidates, total = registry_manifest(os.path.join(root, ".yougori-verified-files.json"))
        resolved = registry_artifacts(root, candidates)
        STATE["status"] = "verifying"
        for path, digest, _size in resolved:
            if not verify_file(path, digest):
                raise RuntimeError("An uploaded model artifact failed checksum verification")
        STATE["download"] = {"receivedBytes": total, "totalBytes": total, "bytesPerSecond": 0, "transport": "yougori-registry"}
        print("Verified uploaded model artifacts at revision " + MODEL_REVISION + ".", flush=True)
        names = [name for name, _size, _digest in candidates]
    globals().update(MODEL_SNAPSHOT_ROOT=root, MODEL_SNAPSHOT_FILES=names)
    REGISTRY_VERIFIED = (MODEL_PATH, MODEL_REVISION, root)
    return root


def local_checkpoint():
    """Only explicitly selected local code is imported, after every file is verified."""
    from transformers import AutoConfig, AutoModelForCausalLM
    # The verified root: the mount, or the copy imported from it.
    root = globals().get("MODEL_SNAPSHOT_ROOT") or MODEL_PATH
    if os.environ.get("YOUGORI_LOCAL_CODE") != "1":
        return AutoConfig.from_pretrained(root, trust_remote_code=False, local_files_only=True)
    from transformers.dynamic_module_utils import get_class_from_dynamic_module
    with open(os.path.join(root, "config.json"), encoding="utf-8") as file:
        config = json.load(file)
    declarations = config.get("auto_map", {})
    refs = [declarations.get(key) for key in ("AutoConfig", "AutoModelForCausalLM")]
    names = set(globals().get("MODEL_SNAPSHOT_FILES", []))
    if any(not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*", ref)
           or ref.split(".")[0] + ".py" not in names for ref in refs):
        raise RuntimeError("Custom model classes must refer to verified local Python files")
    install_local_requirements(names)
    config_class, model_class = [get_class_from_dynamic_module(ref, root, local_files_only=True) for ref in refs]
    AutoConfig.register(config_class.model_type, config_class, exist_ok=True)
    AutoModelForCausalLM.register(config_class, model_class, exist_ok=True)
    STATE["localCode"] = True
    return config_class.from_pretrained(root, local_files_only=True)


def install_local_requirements(names):
    if "requirements.txt" not in names:
        return
    from packaging.requirements import Requirement, InvalidRequirement
    with open(os.path.join(globals().get("MODEL_SNAPSHOT_ROOT") or MODEL_PATH, "requirements.txt"), encoding="utf-8") as file:
        text = file.read(65537)
    if len(text) > 65536:
        raise RuntimeError("Local model requirements exceed 64 KiB")
    needed = []
    for line in text.splitlines():
        line = line.split(" #", 1)[0].strip()
        if not line or line.startswith("#"):
            continue
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            raise RuntimeError("Use package names and version constraints in local requirements.txt") from None
        if requirement.url or len(needed) >= 64:
            raise RuntimeError("Local requirements cannot install URLs, paths or pip options")
        if requirement.marker and not requirement.marker.evaluate():
            continue
        try:
            version = importlib.metadata.version(requirement.name)
        except importlib.metadata.PackageNotFoundError:
            version = None
        if version and requirement.specifier.contains(version) and not requirement.extras:
            continue
        if requirement.name.lower().replace("_", "-") in ("torch", "transformers", "accelerate", "huggingface-hub") and version:
            raise RuntimeError("Local model requires a different " + requirement.name + " version; supply an isolated dedicated runner for this dependency set")
        needed.append(str(requirement))
    if needed:
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", *needed], check=True, timeout=1800)


# G04: an environment with its own model volume imports the mount into it once
# (registry_snapshot above, model_import_enabled); its constants and MODEL_IMPORTED stay in the
# model server, these functions travel with the verifier they serve.
def model_import_enabled():
    """Only environments made with their own model volume import; older ones keep the bind."""
    return bool(MODEL_PATH) and os.environ.get("YOUGORI_MODEL_IMPORT") == "1" and os.access(CACHE, os.W_OK)


def import_root():
    """Committed copies at <revision>/ and an importer's temporary .tmp-<random>/ directories."""
    return os.path.join(CACHE, "yougori-import")


@contextmanager
def import_lock():
    """One importer per model volume. The lock ends with its process: a stopped import never blocks
    the next one, and any .tmp- directory seen while holding it belongs to a dead importer."""
    try:
        import fcntl
    except ImportError:  # Windows test hosts; the runner itself is Linux.
        fcntl = None
    if fcntl is None:
        yield
        return
    with open(os.path.join(CACHE, "yougori-import.lock"), "a+b") as file:
        fcntl.flock(file.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(file.fileno(), fcntl.LOCK_UN)


def sync_directory(path):
    """Make new entries and a rename durable; Windows test hosts cannot open a directory."""
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_durable(path, data):
    with open(path, "xb") as file:
        file.write(data)
        file.flush()
        os.fsync(file.fileno())


def import_progress(copied, total, started):
    """Numeric import progress only, in the download fields the app and CLI already show."""
    elapsed = max(0.001, time.monotonic() - started)
    STATE["download"] = {"receivedBytes": copied, "totalBytes": total,
                         "bytesPerSecond": copied / elapsed, "transport": "yougori-import"}
    STATE["import"].update(checkedBytes=copied, seconds=round(elapsed, 3))


def import_file(path, target, size, expected, progress):
    """Copy one source file through one sequential open, hashing exactly the bytes written.

    No stat identity is compared: a FUSE share can renumber a file during a long read, and the
    digest of the copied bytes is the proof. False when they are not the manifest's bytes.
    """
    digest = artifact_digest(expected, size)
    buffer = bytearray(max(1, min(IMPORT_BUFFER, size)))
    view = memoryview(buffer)
    copied = 0
    with open(path, "rb", buffering=0) as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size != size:
            return False
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "xb") as copy_file:
            while copied < size:
                count = source.readinto(view[:min(len(buffer), size - copied)])
                if not count:
                    return False  # Shorter than the manifest says.
                digest.update(view[:count])
                copy_file.write(view[:count])
                copied += count
                progress(count)
            if source.read(1):
                return False  # Longer than the manifest says.
            copy_file.flush()
            os.fsync(copy_file.fileno())
    return secrets.compare_digest(digest.hexdigest(), expected.lower())


@timed_stage("import")
def copy_model_source(source, committed):
    """Bounded source verification, a temporary copy, then a durable commit by rename (plan 3.3).

    The source is read once, in large sequential reads, and never written. A refusal leaves
    nothing behind; an interrupted copy leaves only its .tmp- directory for the next import.
    """
    folder = os.path.dirname(committed)
    stage = "preflight"
    try:
        manifest, candidates, total = registry_manifest(os.path.join(source, ".yougori-verified-files.json"))
        resolved = registry_artifacts(source, candidates)
        stage = "space"
        free = shutil.disk_usage(folder).free
        if free < total + IMPORT_HEADROOM:
            raise RuntimeError("This model's storage has {:.1f} GB free; importing its {:.1f} GB of model files needs {:.1f} GB. "
                               "Give the model more storage, then start it again. The model folder was not changed."
                               .format(free / 1e9, total / 1e9, (total + IMPORT_HEADROOM) / 1e9))
        stage = "copy"
        temporary = os.path.join(folder, ".tmp-" + secrets.token_hex(8))
        model = os.path.join(temporary, "model")
        os.makedirs(model)
        started, copied = time.monotonic(), 0
        STATE.update(status="downloading", download={"receivedBytes": 0, "totalBytes": total, "bytesPerSecond": 0, "transport": "yougori-import"})
        STATE["import"].update(status="importing", stage=stage, totalBytes=total)

        def progress(count):
            nonlocal copied
            copied += count
            import_progress(copied, total, started)

        for (name, size, digest), (path, _digest, _size) in zip(candidates, resolved):
            if not import_file(path, os.path.join(model, *name.split("/")), size, digest, progress):
                stage = "verify"
                shutil.rmtree(temporary, ignore_errors=True)
                raise RuntimeError("An uploaded model artifact failed checksum verification")
        stage = "commit"
        write_durable(os.path.join(temporary, "manifest.json"), manifest)
        record = {"version": 1, "revision": MODEL_REVISION, "manifest": hashlib.sha256(manifest).hexdigest(),
                  "bytes": total, "files": len(candidates)}
        write_durable(os.path.join(temporary, "import.json"), json.dumps(record, separators=(",", ":")).encode("ascii"))
        for directory, _folders, _files in os.walk(temporary, topdown=False):
            sync_directory(directory)
        os.rename(temporary, committed)
        sync_directory(folder)
        STATE["import"]["seconds"] = round(time.monotonic() - started, 3)
    except RuntimeError:
        STATE["import"].update(status="failed", stage=stage)
        raise
    except OSError as error:
        STATE["import"].update(status="failed", stage=stage)
        raise RuntimeError("Importing the model files into this model's storage stopped (" + (error.strerror or "I/O error")
                           + "). Start the model again to retry; the incomplete copy is removed first.") from None


def checked_import(committed):
    """A committed copy's cheap check, or None: its record against the manifest's digest, the
    files' names and sizes, and verified_weight's stamps, which hash only a file not seen before
    (the read-back right after an import)."""
    try:
        with open(os.path.join(committed, "import.json"), "rb") as file:
            encoded = file.read(IMPORT_RECORD_LIMIT + 1)
        record = json.loads(encoded.decode("ascii"), object_pairs_hook=registry_manifest_object) if len(encoded) <= IMPORT_RECORD_LIMIT else None
        if (not isinstance(record, dict) or set(record) != {"version", "revision", "manifest", "bytes", "files"}
                or type(record["version"]) is not int or record["version"] != 1 or record["revision"] != MODEL_REVISION
                or not isinstance(record["manifest"], str) or not re.fullmatch(r"[a-f0-9]{64}", record["manifest"])
                or type(record["bytes"]) is not int or type(record["files"]) is not int):
            return None
        manifest, candidates, total = registry_manifest(os.path.join(committed, "manifest.json"))
        if (not secrets.compare_digest(hashlib.sha256(manifest).hexdigest(), record["manifest"])
                or total != record["bytes"] or len(candidates) != record["files"]):
            return None
        root = os.path.realpath(os.path.join(committed, "model"))
        resolved = registry_artifacts(root, candidates)
        names = [name for name, _size, _digest in candidates]
        if source_inventory(root) != tuple(sorted(names)):
            return None
        for path, digest, size in resolved:
            if not verified_weight(path, digest, size):
                return None
    except (OSError, ValueError, RuntimeError, UnicodeError, RecursionError):
        return None
    return root, names, tuple((name, digest, size) for name, size, digest in candidates), total


def remove_stale_imports(folder):
    """Called holding the import lock: every .tmp- entry is a stopped import's or a discarded copy."""
    with os.scandir(folder) as entries:
        stale = [entry for entry in entries if entry.name.startswith(".tmp-")]
    for entry in stale:
        if entry.is_dir(follow_symlinks=False):
            shutil.rmtree(entry.path)
        else:
            os.unlink(entry.path)


def discard_import(committed):
    """A committed copy that fails its check is never used or repaired in place: it is renamed
    aside first, so an interrupted removal leaves only a .tmp- directory for the next import."""
    aside = os.path.join(os.path.dirname(committed), ".tmp-" + secrets.token_hex(8))
    os.rename(committed, aside)
    shutil.rmtree(aside, ignore_errors=True)


def import_model_source(source):
    """The manifest's files in this model's own volume: imported once from the read-only mount
    at `source`, then reused by every start after a cheap check. Returns (root, names)."""
    global MODEL_IMPORTED
    MODEL_IMPORTED = None
    if not isinstance(MODEL_REVISION, str) or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", MODEL_REVISION):
        raise RuntimeError("Uploaded checkpoint revision does not match the model manifest")
    folder = import_root()
    committed = os.path.join(folder, MODEL_REVISION)
    STATE["import"] = {"status": "checking", "stage": "check", "revision": MODEL_REVISION,
                       "checkedBytes": 0, "totalBytes": 0, "seconds": 0}
    try:
        with import_lock():
            os.makedirs(folder, exist_ok=True)
            remove_stale_imports(folder)
            checked = checked_import(committed) if os.path.lexists(committed) else None
            label = "imported-cached"
            if checked is None:
                if os.path.lexists(committed):
                    discard_import(committed)
                copy_model_source(source, committed)
                checked = checked_import(committed)
                if checked is None:
                    discard_import(committed)
                    STATE["import"].update(status="failed", stage="check")
                    raise RuntimeError("The imported model files failed verification in this model's storage. Start the model again to import them again.")
                label = "imported"
    except OSError as error:
        STATE["import"].update(status="failed")
        raise RuntimeError("This model's storage cannot hold its imported files (" + (error.strerror or "I/O error") + ").") from None
    root, names, files, total = checked
    MODEL_IMPORTED = (MODEL_PATH, MODEL_REVISION, root, files)
    STATE["source"] = label
    STATE["import"].update(status=label, stage=None, checkedBytes=total, totalBytes=total)
    rate = STATE.get("download", {}).get("bytesPerSecond", 0) if label == "imported" else 0
    STATE["download"] = {"receivedBytes": total, "totalBytes": total, "bytesPerSecond": rate, "transport": "yougori-import"}
    amount = str(len(names)) + " model files (" + format(total / 1e9, ".2f") + " GB)"
    print("Imported " + amount + " into this model's storage at revision " + MODEL_REVISION + "; later starts read this copy."
          if label == "imported" else
          "Using the " + amount + " imported earlier at revision " + MODEL_REVISION + "; the model folder was not read.", flush=True)
    return root, names
