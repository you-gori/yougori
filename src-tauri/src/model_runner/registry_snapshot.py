def registry_snapshot():
    """The engine stages authorized artifacts; recheck them inside the read-only GPU mount."""
    global REGISTRY_VERIFIED
    root = os.path.realpath(MODEL_PATH)
    if os.environ.get("YOUGORI_LOCAL_MANIFEST"):
        record = json.loads(os.environ["YOUGORI_LOCAL_MANIFEST"])
    else:
        with open(os.path.join(root, ".yougori-verified-files.json"), encoding="utf-8") as file:
            record = json.loads(file.read(1024 * 1024 + 1))
    if record.get("revision") != MODEL_REVISION or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", MODEL_REVISION or ""):
        raise RuntimeError("Uploaded checkpoint revision does not match the model manifest")
    files = record.get("files")
    if not isinstance(files, list) or not 1 <= len(files) <= 512:
        raise RuntimeError("Invalid uploaded checkpoint manifest")
    STATE["status"] = "verifying"
    total = 0
    for item in files:
        name, size, digest = item.get("name"), item.get("size"), item.get("sha256")
        if (not isinstance(name, str) or name.startswith(("/", "\\")) or ".." in name or "\\" in name
                or type(size) is not int or size < 0 or not re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", digest or "")):
            raise RuntimeError("Invalid uploaded artifact identity")
        path = os.path.realpath(os.path.join(root, name))
        if os.path.commonpath([root, path]) != root or not os.path.isfile(path) or os.path.getsize(path) != size or not verify_file(path, digest):
            raise RuntimeError("An uploaded model artifact failed checksum verification")
        total += size
    STATE["download"] = {"receivedBytes": total, "totalBytes": total, "bytesPerSecond": 0, "transport": "yougori-registry"}
    print("Verified uploaded model artifacts at revision " + MODEL_REVISION + ".", flush=True)
    globals().update(MODEL_SNAPSHOT_ROOT=root, MODEL_SNAPSHOT_FILES=[item["name"] for item in files])
    REGISTRY_VERIFIED = (MODEL_PATH, MODEL_REVISION, root)
    return root


def local_checkpoint():
    """Only explicitly selected local code is imported, after every file is verified."""
    from transformers import AutoConfig, AutoModelForCausalLM
    if os.environ.get("YOUGORI_LOCAL_CODE") != "1":
        return AutoConfig.from_pretrained(MODEL_PATH, trust_remote_code=False, local_files_only=True)
    from transformers.dynamic_module_utils import get_class_from_dynamic_module
    with open(os.path.join(MODEL_PATH, "config.json"), encoding="utf-8") as file:
        config = json.load(file)
    declarations = config.get("auto_map", {})
    refs = [declarations.get(key) for key in ("AutoConfig", "AutoModelForCausalLM")]
    names = set(globals().get("MODEL_SNAPSHOT_FILES", []))
    if any(not isinstance(ref, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*\.[A-Za-z_][A-Za-z0-9_]*", ref)
           or ref.split(".")[0] + ".py" not in names for ref in refs):
        raise RuntimeError("Custom model classes must refer to verified local Python files")
    install_local_requirements(names)
    config_class, model_class = [get_class_from_dynamic_module(ref, MODEL_PATH, local_files_only=True) for ref in refs]
    AutoConfig.register(config_class.model_type, config_class, exist_ok=True)
    AutoModelForCausalLM.register(config_class, model_class, exist_ok=True)
    STATE["localCode"] = True
    return config_class.from_pretrained(MODEL_PATH, local_files_only=True)


def install_local_requirements(names):
    if "requirements.txt" not in names:
        return
    from packaging.requirements import Requirement, InvalidRequirement
    with open(os.path.join(MODEL_PATH, "requirements.txt"), encoding="utf-8") as file:
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
