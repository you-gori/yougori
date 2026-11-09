"""The media loaders and job runner of the model server (the media-backends helper): Diffusers
pipelines for images, video and sound, Transformers text-to-speech, the asynchronous job API
(/v1/jobs, /v1/files) and the OpenAI-shaped images, speech and videos routes on top of it.
Executed in the model server namespace before a media load (`load_media_backends`); no caller
content is retained beyond a job's own record, which its outputs' retention removes."""
import inspect
import sqlite3
from urllib.parse import parse_qs

# Pinned at first start into the Transformers image, as the chat runner pins its own.
MEDIA_DEPENDENCIES = {"diffusers": "0.42.1", "transformers": "5.18.0", "accelerate": "1.15.0", "huggingface-hub": "1.33.0",
                      "imageio": "2.38.1", "imageio-ffmpeg": "0.8.1", "soundfile": "0.14.0", "sentencepiece": "0.2.3", "protobuf": "7.36.2"}
MEDIA_TASKS = ("text-to-image", "image-to-image", "text-to-video", "image-to-video", "text-to-audio", "text-to-speech")
MEDIA_TASK = os.environ.get("YOUGORI_MEDIA_TASK", "")
# A LoRA adapter on the pipeline, and a pipeline runner (a Diffusers custom pipeline with its own
# pinned packages), each a Hugging Face repository at a commit: hf:OWNER/REPO@COMMIT.
MEDIA_ADAPTER = os.environ.get("YOUGORI_MEDIA_ADAPTER", "")
MEDIA_RUNNER = os.environ.get("YOUGORI_MEDIA_RUNNER", "")
MEDIA_REFERENCE = re.compile(r"(?:hf:)?([A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*)@([0-9a-f]{40})")
MEDIA_ADAPTER_DEPENDENCIES = {"peft": "0.17.1"}
MEDIA_REQUIREMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(==[A-Za-z0-9.!+-]{1,40}| @ git\+https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+@[0-9a-f]{40})")
# Jobs waiting beyond the one generating; a 17th is refused with 429.
MEDIA_QUEUE_LIMIT = 16
MEDIA_JOB_MAX_SECONDS = 1800
MEDIA_BODY_LIMIT = 28 * 1024 * 1024  # a 20 MiB image is about 26.7 MiB as a data URL
MEDIA_INPUT_LIMIT = 20 * 1024 * 1024
MEDIA_WAIT_LIMIT = 600
MEDIA_LIST_LIMIT = 100
MEDIA_KEEP_HOURS_DEFAULT = 24
MEDIA_CAP_BYTES = int(float(os.environ.get("YOUGORI_MEDIA_CAP_GB", "20")) * 1024 ** 3)
MEDIA_ROOT = os.path.join(CACHE, "yougori-media")
MEDIA_CONTENT_TYPES = {"png": "image/png", "jpeg": "image/jpeg", "webp": "image/webp", "mp4": "video/mp4", "wav": "audio/wav"}
# What the pipeline serves, once loaded: its class, the variant and dtype it loaded, whether it
# offloads to the CPU, its sample rate (sound) or frame rate (video), and the last jobs' speed.
MEDIA = {"pipeline": None, "task": MEDIA_TASK, "class": None, "variant": None, "dtype": None, "offload": False,
         "sampleRate": None, "fps": None, "speed": {}}
JOBS = None


class MediaInput(ValueError):
    """A job request that is wrong in a way the caller can fix; the sentence is fixed text."""


class MediaCancelled(Exception):
    """The job's cancellation, raised inside the pipeline's step callback."""


class MediaTimeout(Exception):
    """A job past MEDIA_JOB_MAX_SECONDS, raised inside the pipeline's step callback."""


def media_checkpoint():
    from huggingface_hub import HfApi
    metadata = HfApi().model_info(MODEL, revision=MODEL_REVISION, files_metadata=True, timeout=30)
    revision = metadata.sha
    if not isinstance(revision, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", revision) or MODEL_REVISION is not None and revision != MODEL_REVISION:
        raise RuntimeError("Model metadata did not return the requested immutable checkpoint revision")
    return metadata, revision


def media_reference(value, what):
    """(repository, commit) of an adapter or pipeline runner reference, hf:OWNER/REPO@COMMIT."""
    match = MEDIA_REFERENCE.fullmatch((value or "").strip())
    if not match:
        raise RuntimeError("The " + what + " is a Hugging Face repository at a commit: hf:OWNER/REPO@COMMIT (40 hex characters)")
    return match.group(1), match.group(2)


def media_fetch(reference, what, patterns):
    """The files of a repository at its commit, downloaded into the runner's cache. A commit is
    immutable, so the files are the ones the reference names, whatever the repository does later."""
    repository, commit = media_reference(reference, what)
    from huggingface_hub import snapshot_download
    print("Downloading the " + what + " " + repository + " at " + commit[:12] + "...", flush=True)
    return snapshot_download(repository, revision=commit, allow_patterns=patterns)


def media_requirements(folder):
    """The packages a pipeline runner's requirements.txt pins, each NAME==VERSION or NAME @
    git+https://github.com/OWNER/REPO@COMMIT (a Diffusers commit newer than the pinned release,
    as some pipelines need). Anything else is refused before anything is installed."""
    path = os.path.join(folder, "requirements.txt")
    if not os.path.isfile(path):
        return []
    lines = []
    with open(path, encoding="utf-8") as file:
        for raw in file:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            if not MEDIA_REQUIREMENT.fullmatch(line) or len(lines) >= 32:
                raise RuntimeError("A pipeline runner's requirements.txt pins at most 32 packages, as NAME==VERSION or NAME @ git+https://github.com/OWNER/REPO@COMMIT; refused: " + line[:80])
            lines.append(line)
    return lines


def media_install_requirements(lines):
    if lines:
        print("Installing the pipeline runner's pinned packages: " + ", ".join(lines), flush=True)
        subprocess.run([sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", *lines], check=True, timeout=1800)


def media_load_adapter(pipeline, reference):
    """A LoRA adapter from a repository at a commit, loaded onto the pipeline with Diffusers'
    PEFT integration (peft is installed first); health then names it."""
    if not hasattr(pipeline, "load_lora_weights"):
        raise RuntimeError("This pipeline (" + type(pipeline).__name__ + ") takes no LoRA adapter")
    install(MEDIA_ADAPTER_DEPENDENCIES)
    folder = media_fetch(reference, "adapter", ["*.safetensors", "*.json", "*.txt", "*.md"])
    if not any(name.endswith(".safetensors") for name in os.listdir(folder)):
        raise RuntimeError("The adapter repository has no safetensors weights; this runner loads no pickle checkpoints")
    pipeline.load_lora_weights(folder)
    MEDIA["adapter"] = reference


def media_plan(names, index):
    """Which safetensors files a Diffusers pipeline needs: each component folder its
    model_index.json names, in one variant for all of them (fp16 where every component has
    it, else the plain files). Single-file checkpoints at the root and folders the index does
    not name (ComfyUI copies, LoRAs) are left on the Hub."""
    components = sorted(name for name, value in index.items()
                        if not name.startswith("_") and isinstance(value, list) and len(value) == 2 and value[0] and value[1])
    per = {}
    for component in components:
        files = [name for name in names if name.startswith(component + "/") and name.endswith(".safetensors")]
        if files:
            per[component] = files
    fp16 = bool(per) and all(any(".fp16." in name for name in files) for files in per.values())
    weights = []
    for files in per.values():
        chosen = [name for name in files if ".fp16." in name] if fp16 else [name for name in files if not re.search(r"\.(fp16|bf16|fp32)\.", name)] or files
        weights.extend(chosen)
    return {"components": components, "variant": "fp16" if fp16 else None, "weights": sorted(weights)}


def media_dtype(torch, variant):
    chosen = os.environ.get("YOUGORI_MEDIA_DTYPE") or ("fp16" if variant == "fp16" else "bf16")
    if chosen not in ("fp16", "bf16", "fp32"):
        raise RuntimeError("YOUGORI_MEDIA_DTYPE must be fp16, bf16 or fp32")
    return {"fp16": torch.float16, "bf16": torch.bfloat16, "fp32": torch.float32}[chosen], chosen


def media_module_bytes(pipeline):
    """What the pipeline's weights take once loaded, from the modules themselves."""
    total = 0
    for component in getattr(pipeline, "components", {}).values():
        parameters = getattr(component, "parameters", None)
        if callable(parameters):
            total += sum(p.numel() * p.element_size() for p in parameters())
    return total


def media_load_pipeline(torch, root, plan, dtype, custom=None):
    """The Diffusers pipeline from the verified files (a pipeline runner's pipeline.py when one
    was given), on the GPU when it fits beside 2 GB of working memory, otherwise with its
    components offloaded to the CPU between uses."""
    from diffusers import DiffusionPipeline
    kwargs = {"torch_dtype": dtype, "local_files_only": True}
    if plan["variant"]:
        kwargs["variant"] = plan["variant"]
    if custom:
        kwargs["custom_pipeline"] = custom
        MEDIA["pipelineSource"] = MEDIA_RUNNER
    pipeline = DiffusionPipeline.from_pretrained(root, **kwargs)
    pipeline.set_progress_bar_config(disable=True)
    needed = media_module_bytes(pipeline)
    free = torch.cuda.mem_get_info(0)[0]
    if needed + 2 * 1024 ** 3 <= free:
        pipeline.to("cuda")
        MEDIA["offload"] = False
    else:
        pipeline.enable_model_cpu_offload()
        MEDIA["offload"] = True
        print("The pipeline's " + str(round(needed / 1e9, 1)) + " GB of weights do not fit the free GPU memory; components are offloaded to the CPU between uses.", flush=True)
    MEDIA["class"] = type(pipeline).__name__
    MEDIA["weightBytes"] = needed
    vocoder = getattr(pipeline, "vocoder", None)
    vae = getattr(pipeline, "vae", None)
    for holder in (vocoder, vae):
        rate = getattr(getattr(holder, "config", None), "sampling_rate", None)
        if isinstance(rate, int) and rate > 0:
            MEDIA["sampleRate"] = rate
            break
    MEDIA["fps"] = media_video_defaults(MEDIA["class"])[0]
    return pipeline


def media_load_speech(torch, root):
    """A Transformers text-to-speech pipeline (VITS, Bark) at full precision on the GPU."""
    from transformers import pipeline as transformers_pipeline
    speech = transformers_pipeline("text-to-speech", model=root, device=0)
    MEDIA["class"] = type(speech.model).__name__
    MEDIA["weightBytes"] = sum(p.numel() * p.element_size() for p in speech.model.parameters())
    rate = getattr(speech.model.config, "sampling_rate", None)
    MEDIA["sampleRate"] = rate if isinstance(rate, int) and rate > 0 else None
    return speech


def load_media():
    """Downloads and verifies the pipeline's files, loads it onto the GPU and starts the job
    runner; health then says the task, the pipeline and the queue."""
    global NETWORK, TORCH, JOBS
    if MEDIA_TASK not in MEDIA_TASKS:
        raise RuntimeError("This media runner serves text-to-image, image-to-image, text-to-video, image-to-video, text-to-audio and text-to-speech models")
    install(MEDIA_DEPENDENCIES)
    STATE.update(status="downloading", task=MEDIA_TASK, api="jobs")
    import torch
    if not torch.cuda.is_available():
        raise RuntimeError("CUDA is unavailable. Check the GPU runtime and NVIDIA driver in Yougori.")
    TORCH = torch
    begin_local_load()
    metadata, revision = media_checkpoint()
    names = {item.rfilename: (getattr(item, "size", None) or 0) for item in metadata.siblings or []}
    speech = MEDIA_TASK == "text-to-speech"
    if speech and (MEDIA_ADAPTER or MEDIA_RUNNER):
        raise RuntimeError("Adapters and pipeline runners apply to Diffusers pipelines, not to text-to-speech models")
    for value, what in ((MEDIA_ADAPTER, "adapter"), (MEDIA_RUNNER, "pipeline runner")):
        if value:
            media_reference(value, what)
    custom = None
    if MEDIA_RUNNER:
        custom = media_fetch(MEDIA_RUNNER, "pipeline runner", ["*.py", "requirements.txt", "*.json", "*.md"])
        if not os.path.isfile(os.path.join(custom, "pipeline.py")):
            raise RuntimeError("The pipeline runner repository has no pipeline.py (a Diffusers custom pipeline)")
        media_install_requirements(media_requirements(custom))
    plan = {"variant": None, "weights": [name for name in names if name.endswith(".safetensors") and "/" not in name]}
    if not speech:
        from huggingface_hub import hf_hub_download
        with open(hf_hub_download(MODEL, "model_index.json", revision=revision), encoding="utf-8") as file:
            index = json.load(file)
        plan = media_plan(names, index)
        if not plan["weights"]:
            raise RuntimeError("No safetensors weights were found for the pipeline's components; this runner does not load pickle checkpoints")
    root = verified_snapshot(revision, lambda available: sorted(name for name in plan["weights"] if name in available))
    gpu_before_load()
    STATE["status"] = "loading"
    dtype, MEDIA["dtype"] = media_dtype(torch, plan["variant"])
    MEDIA["variant"] = plan["variant"]
    print("Loading the pipeline onto the GPU...", flush=True)
    with RUNNER_TIMINGS.stage("weight_load"):
        pipeline = media_load_speech(torch, root) if speech else media_load_pipeline(torch, root, plan, dtype, custom)
    if MEDIA_ADAPTER:
        # The LoRA's weights load onto the pipeline: part of loading weights, under the stage
        # names the measurement reports know.
        with RUNNER_TIMINGS.stage("weight_load"):
            media_load_adapter(pipeline, MEDIA_ADAPTER)
    MEDIA["pipeline"] = pipeline
    NETWORK = pipeline
    JOBS = MediaJobs(MEDIA_ROOT)
    JOBS.start()
    STATE.update(status="ready", gpu=torch.cuda.get_device_name(0), gpuCount=1, stream=False, weightsVerified=True, revision=revision,
                 runner="speech" if speech else "diffusers", task=MEDIA_TASK, api="jobs", pipeline=MEDIA["class"],
                 precision="fp32" if speech else MEDIA["dtype"], offload=MEDIA["offload"],
                 **{k: MEDIA[k] for k in ("adapter", "pipelineSource") if MEDIA.get(k)})
    print("The " + str(MEDIA["class"]) + " pipeline serves " + MEDIA_TASK + " jobs on " + STATE["gpu"] + ".", flush=True)


def media_video_defaults(class_name):
    """The frame rate a video pipeline family renders at, and the frame count step its
    architecture needs (frames = k * step + 1)."""
    name = (class_name or "").lower()
    if "ltx" in name:
        return 24, 8
    if "wan" in name or "cogvideox" in name or "hunyuan" in name:
        return 16 if "wan" in name else 8 if "cogvideox" in name else 24, 4
    if "stablevideo" in name:
        return 7, 1
    return 8, 1


def media_frames(seconds, fps, step):
    """The frame count nearest to `seconds` at `fps` that the architecture renders (k * step + 1)."""
    frames = max(1, round(seconds * fps))
    if step > 1:
        frames = max(step + 1, round((frames - 1) / step) * step + 1)
    return frames


def media_number(value, name, low, high, integer=False):
    if value is None:
        return None
    if type(value) is bool or not isinstance(value, (int, float)) or value != value or not low <= value <= high or (integer and type(value) is not int):
        raise MediaInput(name + " must be " + ("an integer" if integer else "a number") + " from " + str(low) + " to " + str(high))
    return value


def media_image_input(value):
    """An input image as a data URL (at most 20 MiB) or the id of an uploaded file."""
    if isinstance(value, str) and value.startswith("in_") and JOBS is not None:
        path = JOBS.input_path(value)
        if not path:
            raise MediaInput("The uploaded input file is unknown or expired")
        with open(path, "rb") as file:
            return file.read(MEDIA_INPUT_LIMIT + 1)
    if not isinstance(value, str) or not value.startswith("data:") or ";base64," not in value[:128]:
        raise MediaInput("image must be a data URL (data:image/png;base64,...) or an uploaded file id")
    head, payload = value.split(";base64,", 1)
    if len(payload) > MEDIA_INPUT_LIMIT * 4 // 3 + 4:
        raise MediaInput("The input image exceeds 20 MiB")
    try:
        return base64.b64decode(payload, validate=True)
    except (ValueError, binascii_error()):
        raise MediaInput("The input image is not valid base64") from None


def binascii_error():
    import binascii
    return binascii.Error


def validate_job(body):
    """The job a request asks for, checked field by field, as the record keeps it. The image
    is kept as bytes only for the job's life; the record echoes its size."""
    if not isinstance(body, dict):
        raise MediaInput("Send a JSON object")
    raw = body.get("input", body)
    if not isinstance(raw, dict):
        raise MediaInput("input must be an object")
    if body.get("model", MODEL) != MODEL:
        raise MediaInput("This model server serves " + MODEL)
    task = MEDIA_TASK
    allowed = {"prompt", "negative_prompt", "width", "height", "steps", "guidance", "seed", "count", "seconds", "fps", "voice", "image", "format", "strength", "text"}
    if set(raw) - allowed:
        raise MediaInput("Unknown input field; use prompt, negative_prompt, width, height, steps, guidance, seed, count, seconds, fps, voice, image, strength or format")
    job = {}
    prompt = raw.get("text") if task == "text-to-speech" else raw.get("prompt")
    if prompt is None and task == "text-to-speech":
        prompt = raw.get("prompt")
    if prompt is not None and (not isinstance(prompt, str) or not 1 <= len(prompt) <= 8000):
        raise MediaInput("prompt is text of 1 to 8,000 characters")
    if prompt is None and task != "image-to-video":
        raise MediaInput("prompt is required")
    job["prompt"] = prompt or ""
    negative = raw.get("negative_prompt")
    if negative is not None and (not isinstance(negative, str) or len(negative) > 8000):
        raise MediaInput("negative_prompt is text of at most 8,000 characters")
    if negative:
        job["negative_prompt"] = negative
    for name, low, high in (("width", 64, 4096), ("height", 64, 4096)):
        value = media_number(raw.get(name), name, low, high, integer=True)
        if value is not None:
            if value % 8:
                raise MediaInput(name + " must be a multiple of 8")
            job[name] = value
    steps = media_number(raw.get("steps"), "steps", 1, 200, integer=True)
    if steps is not None:
        job["steps"] = steps
    guidance = media_number(raw.get("guidance"), "guidance", 0, 50)
    if guidance is not None:
        job["guidance"] = guidance
    strength = media_number(raw.get("strength"), "strength", 0, 1)
    if strength is not None:
        job["strength"] = strength
    seed = media_number(raw.get("seed"), "seed", 0, 2 ** 53, integer=True)
    job["seed"] = seed if seed is not None else secrets.randbelow(2 ** 31)
    count = media_number(raw.get("count"), "count", 1, 8, integer=True)
    if count is not None and task not in ("text-to-image", "image-to-image"):
        raise MediaInput("count applies to image generation only")
    job["count"] = count or 1
    seconds = media_number(raw.get("seconds"), "seconds", 0.5, 60)
    if seconds is not None and task not in ("text-to-video", "image-to-video", "text-to-audio"):
        raise MediaInput("seconds applies to video and audio generation only")
    if seconds is not None:
        job["seconds"] = seconds
    fps = media_number(raw.get("fps"), "fps", 1, 60, integer=True)
    if fps is not None and task not in ("text-to-video", "image-to-video"):
        raise MediaInput("fps applies to video generation only")
    if fps is not None:
        job["fps"] = fps
    voice = raw.get("voice")
    if voice is not None and (not isinstance(voice, str) or not re.fullmatch(r"[A-Za-z0-9_./-]{1,64}", voice)):
        raise MediaInput("voice is a short name")
    if voice:
        job["voice"] = voice
    layout = raw.get("format")
    kinds = {"text-to-image": ("png", "jpeg", "webp"), "image-to-image": ("png", "jpeg", "webp")}.get(task, ("mp4",) if "video" in task else ("wav",))
    if layout is not None and layout not in kinds:
        raise MediaInput("format must be one of " + ", ".join(kinds))
    job["format"] = layout or kinds[0]
    if task in ("image-to-image", "image-to-video"):
        if "image" not in raw:
            raise MediaInput("image is required: a data URL or an uploaded file id")
        job["_image"] = media_image_input(raw["image"])
        job["image"] = {"bytes": len(job["_image"])}
    elif "image" in raw:
        raise MediaInput("image applies to image-to-image and image-to-video models")
    return job


def media_pil(data):
    from PIL import Image
    import io as io_module
    try:
        image = Image.open(io_module.BytesIO(data))
        image.load()
    except Exception:
        raise MediaInput("The input image could not be decoded (PNG, JPEG or WebP)") from None
    return image.convert("RGB")


def media_call(pipeline, kwargs, notes):
    """Calls the pipeline with the inputs it declares; others are noted and left out, since
    pipelines differ in what they take (num_frames, audio_length_in_s, callback forms)."""
    try:
        parameters = inspect.signature(pipeline.__call__).parameters
    except (TypeError, ValueError):
        parameters = {}
    if not any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
        for key in list(kwargs):
            if key not in parameters:
                # The two callback forms are ours, offered for whichever the pipeline takes.
                if key not in ("callback_on_step_end", "callback", "callback_steps"):
                    notes.append(key)
                kwargs.pop(key)
    return pipeline(**kwargs)


def media_generate(job, progress, cancelled):
    """Runs one job on the pipeline: returns (output, usage, files) where files is a list of
    (name, content_type, metadata) written under the job's folder, which `progress(fraction)`
    is told about as the steps go by and `cancelled()` ends early."""
    import torch
    pipeline, task = MEDIA["pipeline"], MEDIA["task"]
    inputs = job["input"]
    started = time.monotonic()
    notes = []
    folder = job["folder"]
    os.makedirs(folder, exist_ok=True)
    if task == "text-to-speech":
        # The speech checkpoints this runner loads have one voice each (Bark's presets need speaker
        # embeddings it does not load); a voice name, which OpenAI clients always send, is noted
        # and the model's own voice used rather than failing the job.
        if inputs.get("voice"):
            notes.append("This model speaks in its own voice; the voice " + json.dumps(inputs["voice"])[:80] + " was not applied.")
        output = pipeline(inputs["prompt"])
        audio = output["audio"] if isinstance(output, dict) else output[0]["audio"]
        rate = int((output if isinstance(output, dict) else output[0])["sampling_rate"])
        path = media_write_audio(folder, "speech.wav", audio, rate)
        seconds = media_audio_seconds(path)
        files = [("speech.wav", "audio/wav", {"seconds": seconds, "sample_rate": rate})]
        return {"audio": {"seconds": seconds, "sample_rate": rate}}, {"images": 0, "output_seconds": seconds}, files, notes
    generator = torch.Generator("cuda").manual_seed(int(inputs["seed"]))
    requested = inputs.get("steps")

    def total_steps():
        timesteps = getattr(getattr(pipeline, "scheduler", None), "timesteps", None)
        try:
            return len(timesteps) if timesteps is not None and len(timesteps) else (requested or 50)
        except TypeError:
            return requested or 50

    def check(step):
        if cancelled():
            raise MediaCancelled()
        if time.monotonic() - started > MEDIA_JOB_MAX_SECONDS:
            raise MediaTimeout()
        progress(min(0.99, (step + 1) / max(1, total_steps())))

    def on_step_end(pipe, step, timestep, callback_kwargs):
        check(step)
        return callback_kwargs

    def on_step(step, timestep, latents):
        check(step)
    kwargs = {"prompt": inputs["prompt"], "generator": generator, "callback_on_step_end": on_step_end, "callback": on_step, "callback_steps": 1}
    if inputs.get("negative_prompt"):
        kwargs["negative_prompt"] = inputs["negative_prompt"]
    if requested:
        kwargs["num_inference_steps"] = requested
    if inputs.get("guidance") is not None:
        kwargs["guidance_scale"] = inputs["guidance"]
    for name in ("width", "height"):
        if inputs.get(name):
            kwargs[name] = inputs[name]
    if task in ("text-to-image", "image-to-image"):
        kwargs["num_images_per_prompt"] = inputs["count"]
        if task == "image-to-image":
            kwargs["image"] = media_pil(job["_image"])
            if inputs.get("strength") is not None:
                kwargs["strength"] = inputs["strength"]
            kwargs.pop("width", None)
            kwargs.pop("height", None)
        result = media_call(pipeline, kwargs, notes)
        images = list(result.images)
        files = []
        layout = inputs["format"]
        for index, image in enumerate(images, 1):
            name = "image-" + str(index) + "." + layout
            image.save(os.path.join(folder, name), format={"png": "PNG", "jpeg": "JPEG", "webp": "WEBP"}[layout])
            files.append((name, MEDIA_CONTENT_TYPES[layout], {"width": image.width, "height": image.height}))
        output = {"images": [{"width": image.width, "height": image.height} for image in images]}
        return output, {"images": len(images), "output_seconds": 0.0}, files, notes
    if task in ("text-to-video", "image-to-video"):
        fps, step = media_video_defaults(MEDIA["class"])
        fps = inputs.get("fps") or fps
        frames = media_frames(inputs.get("seconds") or 2, fps, step)
        kwargs["num_frames"] = frames
        if task == "image-to-video":
            kwargs["image"] = media_pil(job["_image"])
        result = media_call(pipeline, kwargs, notes)
        rendered = result.frames[0]
        from diffusers.utils import export_to_video
        path = os.path.join(folder, "video.mp4")
        export_to_video(list(rendered), path, fps=fps)
        count = len(rendered)
        seconds = round(count / fps, 3)
        first = rendered[0]
        width, height = (first.width, first.height) if hasattr(first, "width") else (int(first.shape[1]), int(first.shape[0]))
        files = [("video.mp4", "video/mp4", {"seconds": seconds, "fps": fps, "frames": count, "width": width, "height": height})]
        return {"video": {"seconds": seconds, "fps": fps, "frames": count, "width": width, "height": height, "audio": False}}, {"images": 0, "output_seconds": seconds}, files, notes
    # text-to-audio: sound and music pipelines name their length differently.
    seconds = inputs.get("seconds") or 5
    kwargs.update(audio_length_in_s=float(seconds), audio_end_in_s=float(seconds))
    kwargs.pop("width", None)
    kwargs.pop("height", None)
    result = media_call(pipeline, kwargs, notes)
    audio = result.audios[0]
    rate = MEDIA["sampleRate"] or 16000
    path = media_write_audio(folder, "audio.wav", audio, rate)
    seconds = media_audio_seconds(path)
    files = [("audio.wav", "audio/wav", {"seconds": seconds, "sample_rate": rate})]
    return {"audio": {"seconds": seconds, "sample_rate": rate}}, {"images": 0, "output_seconds": seconds}, files, notes


def media_write_audio(folder, name, audio, rate):
    import numpy
    import soundfile
    data = numpy.asarray(audio, dtype="float32")
    if data.ndim == 2 and data.shape[0] <= 8 and data.shape[0] < data.shape[1]:
        data = data.T  # (channels, samples) to (samples, channels)
    if data.ndim > 2:
        data = data.reshape(-1, data.shape[-1]) if data.shape[-1] <= 8 else data.reshape(-1)
    path = os.path.join(folder, name)
    soundfile.write(path, data, rate, subtype="PCM_16")
    return path


def media_audio_seconds(path):
    import soundfile
    info = soundfile.info(path)
    return round(info.frames / info.samplerate, 3)


class MediaJobs:
    """The job records and outputs of this model, kept in its volume: a bounded queue run one
    job at a time on the GPU, results kept for `keepHours` under a size cap (oldest out first),
    and a restart that fails what was running rather than guessing."""

    def __init__(self, root):
        self.root = root
        self.outputs = os.path.join(root, "outputs")
        self.inputs = os.path.join(root, "inputs")
        for folder in (root, self.outputs, self.inputs):
            os.makedirs(folder, exist_ok=True)
        self.path = os.path.join(root, "jobs.sqlite3")
        self.lock = threading.RLock()
        self.changed = threading.Condition(self.lock)
        self.cancelling = set()
        self.deleting = set()  # running jobs deleted by their owner: removed once the worker ends them
        self.images = {}  # job id -> input image bytes while the job lives
        self.keep_hours = MEDIA_KEEP_HOURS_DEFAULT
        try:
            self.keep_hours = max(1, min(720, int(os.environ.get("YOUGORI_MEDIA_KEEP_HOURS", str(MEDIA_KEEP_HOURS_DEFAULT)))))
        except ValueError:
            pass
        self.running = None
        self.thread = None
        self.stopped = threading.Event()
        with self.db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, created REAL NOT NULL, started REAL, finished REAL,
                    status TEXT NOT NULL, task TEXT NOT NULL, source TEXT NOT NULL, input TEXT NOT NULL,
                    progress REAL NOT NULL DEFAULT 0, error TEXT, output TEXT, usage TEXT, notes TEXT,
                    bytes INTEGER NOT NULL DEFAULT 0, expires REAL);
                CREATE TABLE IF NOT EXISTS inputs (id TEXT PRIMARY KEY, created REAL NOT NULL, content_type TEXT NOT NULL, bytes INTEGER NOT NULL);
            """)
            # Whatever was queued or running when the server stopped did not finish.
            db.execute("UPDATE jobs SET status='failed', finished=?, error=?, expires=? WHERE status IN ('queued','running')",
                       (time.time(), "The model restarted before this job finished; submit it again.", time.time() + self.keep_hours * 3600))
        self.sweep()

    def db(self):
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA journal_mode=WAL")
        return _Transaction(connection)

    def start(self):
        self.thread = threading.Thread(target=self.work, name="media-jobs", daemon=True)
        self.thread.start()
        threading.Thread(target=self.sweeper, name="media-sweeper", daemon=True).start()

    def stop(self):
        """Ends the worker and sweeper once the job in hand is done (tests; the server exits)."""
        self.stopped.set()
        with self.changed:
            self.changed.notify_all()

    # --- records -------------------------------------------------------------------------
    def row(self, job_id):
        with self.db() as db:
            row = db.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return dict(row) if row else None

    def counts(self):
        with self.db() as db:
            waiting = db.execute("SELECT COUNT(*) FROM jobs WHERE status='queued'").fetchone()[0]
            running = db.execute("SELECT COUNT(*) FROM jobs WHERE status='running'").fetchone()[0]
            kept = db.execute("SELECT COUNT(*), COALESCE(SUM(bytes),0) FROM jobs WHERE status='succeeded'").fetchone()
        return {"waiting": waiting, "running": running, "kept": kept[0], "bytes": kept[1]}

    def position(self, job_id, created):
        with self.db() as db:
            return db.execute("SELECT COUNT(*) FROM jobs WHERE status='queued' AND created<?", (created,)).fetchone()[0] + 1

    def view(self, row):
        """A job as the API shows it; the input image is its size, never its bytes."""
        value = {"id": row["id"], "object": "job", "status": row["status"], "task": row["task"], "model": MODEL,
                 "created": int(row["created"]), "started": int(row["started"]) if row["started"] else None,
                 "finished": int(row["finished"]) if row["finished"] else None, "progress": round(float(row["progress"]), 3),
                 "input": json.loads(row["input"]), "error": row["error"], "output": json.loads(row["output"]) if row["output"] else None,
                 "usage": json.loads(row["usage"]) if row["usage"] else None, "expires": int(row["expires"]) if row["expires"] else None}
        if row["status"] == "queued":
            value["position"] = self.position(row["id"], row["created"])
        if row["notes"]:
            value["notes"] = json.loads(row["notes"])
        return value

    def submit(self, body, source):
        job = validate_job(body)
        image = job.pop("_image", None)
        job_id = "job_" + secrets.token_hex(12)
        with self.lock:
            if self.counts()["waiting"] >= MEDIA_QUEUE_LIMIT:
                raise MediaQueueFull()
            with self.db() as db:
                db.execute("INSERT INTO jobs (id,created,status,task,source,input) VALUES (?,?,?,?,?,?)",
                           (job_id, time.time(), "queued", MEDIA_TASK, source, json.dumps(job)))
            if image is not None:
                self.images[job_id] = image
            self.changed.notify_all()
        return self.view(self.row(job_id))

    def wait(self, job_id, seconds):
        """The job once it ends, or as it stands after `seconds`."""
        deadline = time.monotonic() + max(0, min(MEDIA_WAIT_LIMIT, seconds))
        while True:
            row = self.row(job_id)
            if row is None or row["status"] in ("succeeded", "failed", "cancelled"):
                return row
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return row
            with self.changed:
                self.changed.wait(min(remaining, 1.0))

    def cancel(self, job_id):
        with self.lock:
            row = self.row(job_id)
            if row is None:
                return None
            if row["status"] == "queued":
                with self.db() as db:
                    db.execute("UPDATE jobs SET status='cancelled', finished=?, expires=? WHERE id=? AND status='queued'",
                               (time.time(), time.time() + self.keep_hours * 3600, job_id))
                self.images.pop(job_id, None)
                self.changed.notify_all()
            elif row["status"] == "running":
                self.cancelling.add(job_id)
        return self.view(self.row(job_id))

    def delete(self, job_id):
        """Cancels and removes a job and its outputs."""
        self.cancel(job_id)
        with self.lock:
            row = self.row(job_id)
            if row is None:
                return False
            if row["status"] == "running":
                self.deleting.add(job_id)  # the worker removes it, record and outputs, when it ends
                return True
            self.remove(job_id)
        return True

    def remove(self, job_id):
        shutil.rmtree(os.path.join(self.outputs, job_id), ignore_errors=True)
        with self.db() as db:
            db.execute("DELETE FROM jobs WHERE id=?", (job_id,))
        self.images.pop(job_id, None)

    def listing(self, limit):
        with self.db() as db:
            rows = db.execute("SELECT * FROM jobs ORDER BY created DESC LIMIT ?", (max(1, min(MEDIA_LIST_LIMIT, limit)),)).fetchall()
        return [self.view(dict(row)) for row in rows]

    def file(self, file_id):
        """(path, content_type, size) of an output file `JOB.N`, or None."""
        match = re.fullmatch(r"(job_[a-f0-9]{24})\.([0-9]{1,2})", file_id or "")
        if not match:
            return None
        row = self.row(match.group(1))
        if not row or row["status"] != "succeeded" or not row["output"]:
            return None
        files = json.loads(row["output"]).get("files") or []
        index = int(match.group(2))
        if not 1 <= index <= len(files):
            return None
        entry = files[index - 1]
        path = os.path.join(self.outputs, row["id"], entry["name"])
        if not os.path.isfile(path):
            return None
        return path, entry["content_type"], os.path.getsize(path)

    def save_input(self, data, content_type):
        extension = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}.get(content_type)
        if not extension:
            raise MediaInput("Upload a PNG, JPEG or WebP image")
        file_id = "in_" + secrets.token_hex(12)
        with open(os.path.join(self.inputs, file_id + "." + extension), "wb") as file:
            file.write(data)
        with self.db() as db:
            db.execute("INSERT INTO inputs VALUES (?,?,?,?)", (file_id, time.time(), content_type, len(data)))
        return {"id": file_id, "object": "file", "bytes": len(data), "content_type": content_type, "expires": int(time.time() + 86400)}

    def input_path(self, file_id):
        if not re.fullmatch(r"in_[a-f0-9]{24}", file_id or ""):
            return None
        with self.db() as db:
            row = db.execute("SELECT content_type FROM inputs WHERE id=?", (file_id,)).fetchone()
        if not row:
            return None
        extension = {"image/png": "png", "image/jpeg": "jpg", "image/webp": "webp"}[row[0]]
        path = os.path.join(self.inputs, file_id + "." + extension)
        return path if os.path.isfile(path) else None

    def configure(self, keep_hours):
        if type(keep_hours) is not int or not 1 <= keep_hours <= 720:
            raise MediaInput("keepHours must be an integer from 1 to 720")
        with self.lock:
            self.keep_hours = keep_hours
            with self.db() as db:
                db.execute("UPDATE jobs SET expires=finished+? WHERE finished IS NOT NULL", (keep_hours * 3600,))
        self.sweep()
        return self.snapshot()

    def snapshot(self):
        counts = self.counts()
        return {"queue": {"waiting": counts["waiting"], "running": counts["running"], "limit": MEDIA_QUEUE_LIMIT},
                "outputs": {"keptHours": self.keep_hours, "capGb": round(MEDIA_CAP_BYTES / 1024 ** 3, 1), "bytes": counts["bytes"], "jobs": counts["kept"]},
                "speed": dict(MEDIA["speed"]), "pipeline": MEDIA["class"], "offload": MEDIA["offload"]}

    # --- the worker ----------------------------------------------------------------------
    def next_job(self):
        with self.changed:
            while not self.stopped.is_set():
                with self.db() as db:
                    row = db.execute("SELECT * FROM jobs WHERE status='queued' ORDER BY created LIMIT 1").fetchone()
                if row:
                    return dict(row)
                self.changed.wait(5)
        return None

    def work(self):
        while not self.stopped.is_set():
            try:
                job = self.next_job()
                if job is not None:
                    self.run(job)
            except Exception as error:  # the worker never dies; a job that broke it is failed
                print("Media job runner error: " + type(error).__name__, flush=True)
                self.stopped.wait(1)

    def progress(self, job_id, fraction):
        with self.db() as db:
            db.execute("UPDATE jobs SET progress=? WHERE id=? AND status='running'", (fraction, job_id))

    def run(self, job):
        job_id = job["id"]
        with self.lock:
            with self.db() as db:
                started = db.execute("UPDATE jobs SET status='running', started=? WHERE id=? AND status='queued'", (time.time(), job_id)).rowcount
            if not started:
                return  # cancelled or deleted between being picked and starting: it does not run
            self.running = job_id
            self.changed.notify_all()
        record = {"id": job_id, "input": json.loads(job["input"]), "folder": os.path.join(self.outputs, job_id), "_image": self.images.get(job_id)}
        started = time.monotonic()
        status, error, output, usage, files, notes = "failed", None, None, None, [], []
        with GENERATION:
            try:
                output, usage, files, notes = media_generate(record, lambda fraction: self.progress(job_id, fraction), lambda: job_id in self.cancelling)
                status = "succeeded"
            except MediaCancelled:
                status = "cancelled"
            except MediaTimeout:
                error = "The job exceeded " + str(MEDIA_JOB_MAX_SECONDS // 60) + " minutes and was stopped."
            except MediaInput as refusal:
                error = str(refusal)
            except Exception as failure:
                error = media_failure(failure)
        compute = time.monotonic() - started
        if TORCH is not None:
            try:
                TORCH.cuda.empty_cache()
            except Exception:
                pass
        total = 0
        if status == "succeeded":
            kept = []
            for index, (name, content_type, metadata) in enumerate(files, 1):
                size = os.path.getsize(os.path.join(record["folder"], name))
                total += size
                kept.append({"name": name, "content_type": content_type, "bytes": size, "file": job_id + "." + str(index), "url": "/v1/files/" + job_id + "." + str(index), **metadata})
            output = {**output, "files": kept, "seed": record["input"]["seed"]}
            for key in ("images", "video", "audio"):
                if key in output and isinstance(output[key], list):
                    output[key] = [{**item, **{k: v for k, v in kept[i].items() if k in ("file", "url", "content_type", "bytes")}} for i, item in enumerate(output[key])]
                elif key in output and isinstance(output[key], dict) and kept:
                    output[key] = {**output[key], **{k: v for k, v in kept[0].items() if k in ("file", "url", "content_type", "bytes")}}
            usage = {**usage, "compute_seconds": round(compute, 3)}
        else:
            shutil.rmtree(record["folder"], ignore_errors=True)
        with self.lock:
            self.cancelling.discard(job_id)
            self.images.pop(job_id, None)
            self.running = None
            with self.db() as db:
                db.execute("UPDATE jobs SET status=?, finished=?, progress=?, error=?, output=?, usage=?, notes=?, bytes=?, expires=? WHERE id=?",
                           (status, time.time(), 1.0 if status == "succeeded" else job.get("progress") or 0, error,
                            json.dumps(output) if output else None, json.dumps(usage) if usage else None,
                            json.dumps(notes) if notes else None, total, time.time() + self.keep_hours * 3600, job_id))
            self.changed.notify_all()
        if status == "succeeded":
            speed = MEDIA["speed"]
            speed["lastJobSeconds"] = round(compute, 2)
            if usage.get("images"):
                speed["secondsPerImage"] = round(compute / usage["images"], 2)
            if usage.get("output_seconds"):
                speed["secondsPerOutputSecond"] = round(compute / usage["output_seconds"], 2)
        record_usage(job["source"], {"succeeded": "ok", "cancelled": "cancelled"}.get(status, "error"), seconds=compute,
                     media={"images": (usage or {}).get("images", 0), "output_ms": int(((usage or {}).get("output_seconds") or 0) * 1000), "compute_ms": int(compute * 1000)})
        with self.lock:
            deleted = job_id in self.deleting
            self.deleting.discard(job_id)
            if deleted:
                self.remove(job_id)  # deleted while it ran: its usage is counted, the job is gone
        self.sweep()

    def sweeper(self):
        while not self.stopped.wait(600):
            try:
                self.sweep()
            except Exception:
                pass

    def sweep(self):
        """Removes outputs past their time, then the oldest beyond the size cap, and inputs
        older than a day."""
        now = time.time()
        with self.lock:
            with self.db() as db:
                expired = [row[0] for row in db.execute("SELECT id FROM jobs WHERE expires IS NOT NULL AND expires<? AND status!='running'", (now,))]
            for job_id in expired:
                self.remove(job_id)
            with self.db() as db:
                total = db.execute("SELECT COALESCE(SUM(bytes),0) FROM jobs").fetchone()[0]
                oldest = [dict(row) for row in db.execute("SELECT id,bytes FROM jobs WHERE status='succeeded' ORDER BY finished")]
            for row in oldest:
                if total <= MEDIA_CAP_BYTES:
                    break
                self.remove(row["id"])
                total -= row["bytes"]
            with self.db() as db:
                stale = [row[0] for row in db.execute("SELECT id FROM inputs WHERE created<?", (now - 86400,))]
                for file_id in stale:
                    for name in os.listdir(self.inputs):
                        if name.startswith(file_id + "."):
                            try:
                                os.remove(os.path.join(self.inputs, name))
                            except OSError:
                                pass
                    db.execute("DELETE FROM inputs WHERE id=?", (file_id,))


class _Transaction:
    """A connection used as `with`: commits on success, rolls back on an error, always closes."""

    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        self.connection.execute("BEGIN")
        return self.connection

    def __exit__(self, kind, value, traceback):
        try:
            # executescript commits on its own; only an open transaction is ended here.
            if self.connection.in_transaction:
                self.connection.execute("COMMIT" if kind is None else "ROLLBACK")
        finally:
            self.connection.close()


class MediaQueueFull(Exception):
    pass


def media_failure(failure):
    """A failed job's reason in fixed words: the error's kind and a bounded message with the
    model's token, if it ever appeared, redacted."""
    name = type(failure).__name__
    if "OutOfMemory" in name or "out of memory" in str(failure).lower():
        return "Not enough GPU memory for this job; reduce the size, the frame count or the image count."
    detail = str(failure).replace(TOKEN, "[redacted]")[:300]
    return name + ": " + detail if detail else name


def media_health():
    """What health adds for a media model: the queue, the kept outputs, the last jobs' speed,
    and the adapter and pipeline runner it loaded."""
    extra = {k: MEDIA[k] for k in ("adapter", "pipelineSource") if MEDIA.get(k)}
    if JOBS is None:
        return {"task": MEDIA_TASK, "api": "jobs", **extra}
    return {"task": MEDIA_TASK, "api": "jobs", **extra, **JOBS.snapshot()}


def media_capabilities():
    return {
        "concurrency": {"supported": False, "slots": 1, "detail": "One job generates at a time; up to " + str(MEDIA_QUEUE_LIMIT) + " wait in order (/v1/jobs)."},
        "structuredOutput": {"supported": False, "detail": "A media model takes job inputs, not chat; response_format does not apply."},
        "media": {"supported": True, "task": MEDIA_TASK, "detail": "Asynchronous jobs: POST /v1/jobs, GET /v1/jobs/ID (wait=SECONDS long-polls), GET /v1/jobs/ID/result, GET /v1/files/ID; "
                  + {"text-to-image": "POST /v1/images/generations answers in OpenAI's shape.", "text-to-speech": "POST /v1/audio/speech answers with the WAV bytes.",
                     "text-to-video": "POST /v1/videos, GET /v1/videos/ID and /v1/videos/ID/content follow OpenAI's video objects.",
                     "image-to-video": "POST /v1/videos with input_reference, GET /v1/videos/ID and /v1/videos/ID/content follow OpenAI's video objects."}.get(MEDIA_TASK, "")},
    }


# --- HTTP --------------------------------------------------------------------------------
def media_body(handler, limit=MEDIA_BODY_LIMIT):
    length = int(handler.headers.get("Content-Length", "0"))
    if not 0 < length <= limit or handler.headers.get("Transfer-Encoding"):
        raise MediaInput("Send a JSON body of at most " + str(limit // (1024 * 1024)) + " MiB with Content-Length")
    raw = handler.rfile.read(length)
    if len(raw) != length:
        raise MediaInput("Incomplete request")
    body = json.loads(raw)
    if not isinstance(body, dict):
        raise MediaInput("Send a JSON object")
    return body


def media_send_file(handler, path, content_type, size):
    """The file's bytes, whole or the one byte range asked for, streamed in pieces."""
    start, end = 0, size - 1
    status = 200
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
            handler.send_response(416)
            handler.send_header("Content-Range", "bytes */" + str(size))
            handler.send_header("Content-Length", "0")
            handler.send_header("Connection", "close")
            handler.end_headers()
            return
        status = 206
    handler.send_response(status)
    handler.send_header("Content-Type", content_type)
    handler.send_header("Content-Length", str(end - start + 1))
    handler.send_header("Accept-Ranges", "bytes")
    if status == 206:
        handler.send_header("Content-Range", "bytes " + str(start) + "-" + str(end) + "/" + str(size))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Connection", "close")
    handler.end_headers()
    with open(path, "rb") as file:
        file.seek(start)
        remaining = end - start + 1
        while remaining > 0:
            chunk = file.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            handler.wfile.write(chunk)
            remaining -= len(chunk)
    handler.wfile.flush()


def media_video_object(view):
    status = {"queued": "queued", "running": "in_progress", "succeeded": "completed", "failed": "failed", "cancelled": "failed"}[view["status"]]
    output = view.get("output") or {}
    video = output.get("video") or {}
    value = {"id": view["id"], "object": "video", "model": MODEL, "status": status, "progress": int(round(view["progress"] * 100)),
             "created_at": view["created"], "completed_at": view["finished"] if view["status"] == "succeeded" else None,
             "expires_at": view["expires"], "seconds": video.get("seconds") or view["input"].get("seconds"),
             "size": (str(video["width"]) + "x" + str(video["height"])) if video.get("width") else None,
             "error": {"code": "cancelled" if view["status"] == "cancelled" else "failed", "message": view["error"] or "The job was cancelled."} if status == "failed" else None}
    return value


def media_not_ready(handler):
    if JOBS is None or STATE.get("status") != "ready":
        handler.reply(503, {"error": {"code": "model_loading", "message": "The model is still " + str(STATE.get("status")) + "; retry shortly."}})
        return True
    return False


def media_absolute(handler, url):
    host = handler.headers.get("Host") or "127.0.0.1:8000"
    scheme = handler.headers.get("X-Forwarded-Proto") or "http"
    return scheme + "://" + host + url


def media_route(handler, method):
    """Answers a media request; False when `handler.path` is not one of this runner's routes.
    Authorization was checked by the caller; the admin route checks its own credential."""
    path, _, query = handler.path.partition("?")
    fields = parse_qs(query, max_num_fields=4) if query else {}
    source = "yougori" if handler.headers.get("X-Yougori-Client") == "yougori" else "api"
    parts = path.strip("/").split("/")
    try:
        if method == "GET":
            if parts[:2] == ["v1", "jobs"] and len(parts) == 2:
                if media_not_ready(handler):
                    return True
                return handler.reply(200, {"object": "list", "data": JOBS.listing(int(fields.get("limit", ["20"])[0]) if fields.get("limit", ["20"])[0].isdigit() else 20)}) or True
            if parts[:2] in (["v1", "jobs"], ["v1", "videos"]) and len(parts) in (3, 4):
                if media_not_ready(handler):
                    return True
                job_id, kind = parts[2], parts[1]
                if len(parts) == 4 and parts[3] not in ("result", "content"):
                    return False
                wait = fields.get("wait", ["0"])[0]
                row = JOBS.wait(job_id, int(wait)) if wait.isdigit() else JOBS.row(job_id)
                if row is None:
                    return handler.reply(404, {"error": {"code": "job_unknown", "message": "No such job; it may have expired."}}) or True
                view = JOBS.view(row)
                if len(parts) == 3:
                    return handler.reply(200, media_video_object(view) if kind == "videos" else view) or True
                if view["status"] != "succeeded":
                    return handler.reply(409 if view["status"] in ("queued", "running") else 410, {"error": {"code": "job_" + view["status"], "message": "The job is " + view["status"] + ("." if view["status"] in ("queued", "running") else ": " + str(view.get("error") or "no output."))}}) or True
                if parts[3] == "result":
                    return handler.reply(200, view["output"]) or True
                found = JOBS.file(view["output"]["files"][0]["file"]) if view["output"].get("files") else None
                if not found:
                    return handler.reply(404, {"error": {"code": "file_unknown", "message": "The output file is gone."}}) or True
                media_send_file(handler, *found)
                return True
            if parts[:2] == ["v1", "files"] and len(parts) == 3:
                if media_not_ready(handler):
                    return True
                found = JOBS.file(parts[2])
                if not found:
                    return handler.reply(404, {"error": {"code": "file_unknown", "message": "No such file; it may have expired."}}) or True
                media_send_file(handler, *found)
                return True
            return False
        if method == "DELETE":
            if parts[:2] in (["v1", "jobs"], ["v1", "videos"]) and len(parts) == 3:
                if media_not_ready(handler):
                    return True
                deleted = JOBS.delete(parts[2])
                if not deleted:
                    return handler.reply(404, {"error": {"code": "job_unknown", "message": "No such job; it may have expired."}}) or True
                return handler.reply(200, {"id": parts[2], "object": "video.deleted" if parts[1] == "videos" else "job.deleted", "deleted": True}) or True
            return False
        if path == "/v1/yougori/media":
            if not handler.admin_authorized():
                return handler.reply(403, {"error": {"message": "Only the local Yougori engine can change this model's output retention"}}) or True
            body = media_body(handler, 1024)
            if media_not_ready(handler):
                return True
            if body.get("action") == "configure":
                return handler.reply(200, JOBS.configure(body.get("keepHours"))) or True
            return handler.reply(200, JOBS.snapshot()) or True
        if path == "/v1/jobs":
            body = media_body(handler)
            if media_not_ready(handler):
                return True
            return handler.reply(202, JOBS.submit(body, source)) or True
        if parts[:2] == ["v1", "jobs"] and len(parts) == 4 and parts[3] == "cancel":
            media_body_optional(handler)
            if media_not_ready(handler):
                return True
            view = JOBS.cancel(parts[2])
            if view is None:
                return handler.reply(404, {"error": {"code": "job_unknown", "message": "No such job; it may have expired."}}) or True
            return handler.reply(200, view) or True
        if path == "/v1/files":
            body = media_body(handler)
            if media_not_ready(handler):
                return True
            data = media_image_input(body.get("data"))
            head = body["data"][5:body["data"].index(";")] if isinstance(body.get("data"), str) and body["data"].startswith("data:") else "image/png"
            return handler.reply(201, JOBS.save_input(data, head)) or True
        if path == "/v1/images/generations":
            body = media_body(handler)
            if media_not_ready(handler):
                return True
            return media_images_route(handler, body, source) or True
        if path == "/v1/audio/speech":
            body = media_body(handler)
            if media_not_ready(handler):
                return True
            return media_speech_route(handler, body, source) or True
        if path == "/v1/videos":
            body = media_body(handler)
            if media_not_ready(handler):
                return True
            return media_videos_route(handler, body, source) or True
        return False
    except MediaQueueFull:
        handler.reply(429, {"error": {"code": "media_queue_full", "message": "This model has " + str(MEDIA_QUEUE_LIMIT) + " jobs waiting; retry later."}})
        return True
    except MediaInput as refusal:
        handler.reply(400, {"error": {"code": "media_input", "message": str(refusal)}})
        return True
    except (ValueError, TypeError, KeyError):
        handler.reply(400, {"error": {"code": "media_input", "message": "Invalid media request."}})
        return True


def media_body_optional(handler):
    length = int(handler.headers.get("Content-Length", "0") or 0)
    if length:
        handler.rfile.read(min(length, 4096))


def media_images_route(handler, body, source):
    """OpenAI's images endpoint on top of a job: one request, the images inline or as links."""
    if MEDIA_TASK not in ("text-to-image", "image-to-image"):
        return handler.reply(404, {"error": {"code": "task_mismatch", "message": "This model generates " + MEDIA_TASK + "; use /v1/jobs."}})
    if set(body) - {"model", "prompt", "n", "size", "response_format", "seed", "steps", "guidance", "negative_prompt", "output_format", "quality", "style", "user", "image", "strength"}:
        raise MediaInput("Unknown field; use prompt, n, size, response_format (b64_json or url), output_format, seed, steps, guidance and negative_prompt")
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
    layout = body.get("output_format", "png")
    inputs["format"] = layout
    delivery = body.get("response_format", "b64_json")
    if delivery not in ("b64_json", "url"):
        raise MediaInput("response_format is b64_json or url")
    submitted = JOBS.submit({"model": body.get("model", MODEL), "input": inputs}, source)
    row = JOBS.wait(submitted["id"], MEDIA_WAIT_LIMIT)
    view = JOBS.view(row)
    if view["status"] != "succeeded":
        return media_job_failure(handler, view)
    data = []
    for entry in view["output"]["files"]:
        item = {"revised_prompt": None}
        if delivery == "url":
            item["url"] = media_absolute(handler, entry["url"])
        else:
            with open(os.path.join(JOBS.outputs, view["id"], entry["name"]), "rb") as file:
                item["b64_json"] = base64.b64encode(file.read()).decode("ascii")
        data.append(item)
    return handler.reply(200, {"created": view["finished"], "data": data, "job": view["id"], "usage": view["usage"]})


def media_job_failure(handler, view):
    if view["status"] in ("queued", "running"):
        return handler.reply(504, {"error": {"code": "job_timeout", "message": "The job did not finish within " + str(MEDIA_WAIT_LIMIT) + " seconds; it continues as job " + view["id"] + "."}, "job": view["id"]})
    return handler.reply(500 if view["status"] == "failed" else 499, {"error": {"code": "job_" + view["status"], "message": view["error"] or "The job was cancelled."}, "job": view["id"]})


def media_speech_route(handler, body, source):
    """OpenAI's speech endpoint: the WAV bytes of one job."""
    if MEDIA_TASK != "text-to-speech":
        return handler.reply(404, {"error": {"code": "task_mismatch", "message": "This model generates " + MEDIA_TASK + "; use /v1/jobs."}})
    if set(body) - {"model", "input", "voice", "response_format", "speed", "instructions"}:
        raise MediaInput("Unknown field; use input, voice and response_format (wav)")
    if body.get("response_format", "wav") != "wav":
        raise MediaInput("This model answers WAV; set response_format to wav")
    inputs = {"text": body.get("input")}
    if body.get("voice"):
        inputs["voice"] = body["voice"]
    submitted = JOBS.submit({"model": body.get("model", MODEL), "input": inputs}, source)
    row = JOBS.wait(submitted["id"], MEDIA_WAIT_LIMIT)
    view = JOBS.view(row)
    if view["status"] != "succeeded":
        return media_job_failure(handler, view)
    found = JOBS.file(view["output"]["files"][0]["file"])
    if not found:
        return handler.reply(500, {"error": {"code": "file_unknown", "message": "The speech file is gone."}})
    media_send_file(handler, *found)


def media_videos_route(handler, body, source):
    """OpenAI's videos endpoint: a job answered at once as a video object to poll."""
    if MEDIA_TASK not in ("text-to-video", "image-to-video"):
        return handler.reply(404, {"error": {"code": "task_mismatch", "message": "This model generates " + MEDIA_TASK + "; use /v1/jobs."}})
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
    submitted = JOBS.submit({"model": body.get("model", MODEL), "input": inputs}, source)
    return handler.reply(200, media_video_object(submitted))
