"""What a Hugging Face model needs from a GPU, checked when an administrator adds it, before any
computer installs it or any GPU is rented: whether Yougori can run it at all, on which GPUs
(memory, and the GPU generation its weights' number formats need), and where (computers running
Yougori, or the GPUs this website rents). It mirrors the engine's own check
(model_runner/preflight.rs): the same architecture lists, no repository code, the same memory
estimates. A model that ships its own megakernel program is refused with the reason.
"""
import json
import math
from pathlib import Path
import urllib.error
import urllib.parse
import urllib.request

import neocloud

HUGGING_FACE = "https://huggingface.co"
HERE = Path(__file__).resolve().parent
# Architectures the engine's runtimes serve: Transformers 5.18.0 by model type, the pinned vLLM
# 0.29.0 (the runtime rented GPUs run) by architecture.
TRANSFORMERS = set(json.loads((HERE / "transformers_architectures.json").read_text(encoding="utf-8"))["types"])
VLLM = neocloud.ARCHITECTURES
TEXT_TASKS = {None, "text-generation", "image-text-to-text", "any-to-any"}
MEDIA_TASKS = {"text-to-image", "image-to-image", "text-to-video", "image-to-video", "text-to-speech", "text-to-audio"}
# The GGUF file a computer installs by default, best first (the engine's order).
GGUF_PREFERENCE = ("Q4_K_M", "Q4_K_XL", "Q4_K_S", "IQ4_XS", "IQ4_NL", "Q5_K_M", "Q5_K_S", "Q6_K", "Q8_0", "Q3_K_M", "Q3_K_S", "Q2_K", "BF16", "F16")
# The oldest GPU generation (CUDA compute capability) a quantization's kernels run on.
QUANTIZATION = {"fp8": 8.9, "fbgemm_fp8": 8.9, "mxfp4": 8.0, "nvfp4": 10.0, "modelopt": 10.0, "modelopt_fp4": 10.0,
                "awq": 7.5, "gptq": 7.5, "gptq_marlin": 8.0, "awq_marlin": 8.0, "compressed-tensors": 8.0, "bitsandbytes": 7.5}

# GPU names to their generation (compute capability); specific names first. AMD GPUs are not
# CUDA GPUs: none of Yougori's runtimes run on them.
GENERATIONS = (("rtx pro", 12.0), ("pro 6000", 12.0), ("pro 5000", 12.0), ("pro 4500", 12.0), ("pro 4000", 12.0),
               ("rtx 50", 12.0), ("gb200", 10.0), ("b300", 10.3), ("b200", 10.0),
               ("gh200", 9.0), ("h200", 9.0), ("h100", 9.0), ("h800", 9.0),
               (" ada", 8.9), ("rtx 40", 8.9), ("l40", 8.9), ("l4", 8.9),
               ("a100", 8.0), ("a800", 8.0), ("a30", 8.0),
               ("rtx a", 8.6), ("rtx 30", 8.6), ("a40", 8.6), ("a10", 8.6), ("a16", 8.6), ("a2", 8.6),
               ("v100", 7.0), ("titan v", 7.0),
               ("rtx 20", 7.5), ("gtx 16", 7.5), ("titan rtx", 7.5), ("quadro rtx", 7.5), ("t4", 7.5),
               ("gtx 10", 6.1), ("p40", 6.1), ("p100", 6.0))
AMD = ("amd", "radeon", "instinct", "mi300", "mi325", "mi250", "mi210")


class CheckError(Exception):
    """Why Yougori cannot run a model, in words for the administrator. `transient` when Hugging
    Face did not answer, so the model was not checked at all."""

    def __init__(self, message, transient=False):
        super().__init__(message)
        self.transient = transient


def gpu_generation(name):
    """A GPU's compute capability from its name ("NVIDIA GeForce RTX 4090", "RTX A6000",
    "H100 SXM"), 0 for an AMD GPU, None when unknown."""
    name = " " + str(name or "").lower().replace("geforce ", "").replace("nvidia ", "") + " "
    if any(word in name for word in AMD):
        return 0.0
    return next((value for fragment, value in GENERATIONS if fragment in name), None)


def generation_words(capability):
    """The GPU generation that starts at this compute capability, with examples."""
    for floor, words in ((12.0, "Blackwell (RTX 50, RTX PRO)"), (10.0, "Blackwell (RTX 50, B200)"), (9.0, "Hopper (H100, H200)"),
                         (8.9, "Ada (RTX 40, L4, L40S)"), (8.0, "Ampere (RTX 30, A100, A40)"), (7.5, "Turing (RTX 20, T4)")):
        if capability >= floor:
            return words
    return "Pascal (GTX 10)"


def fetch(path):
    """(status, JSON) from Hugging Face's API, following only its own redirects (a renamed
    model), never another host's, and never through a proxy."""
    url = HUGGING_FACE + path
    for _ in range(3):
        request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "Yougori-Inference/1"})
        try:
            with neocloud._OPENER.open(request, timeout=20) as response:
                return response.status, json.loads(response.read(8 * 1024 * 1024 + 1) or b"{}")
        except urllib.error.HTTPError as error:
            location = error.headers.get("Location") if error.code in (301, 302, 307, 308) else None
            target = urllib.parse.urljoin(url, location) if location else ""
            if not target or urllib.parse.urlsplit(target).netloc != urllib.parse.urlsplit(HUGGING_FACE).netloc:
                return error.code, {}
            url = target
        except (urllib.error.URLError, OSError, ValueError):
            raise CheckError("Hugging Face did not answer. Retry in a moment.", transient=True) from None
    raise CheckError("Hugging Face kept redirecting this model. Check its name.")


def media_bytes(files):
    """The weights a media runtime loads: each component folder's half-precision files when it
    has them, else all of its files; a single-file checkpoint only without component folders."""
    folders = {}
    for name, size in files.items():
        if name.endswith(".safetensors") and "/" in name:
            folders.setdefault(name.split("/")[0], []).append((name, size))
    if folders:
        total = 0
        for entries in folders.values():
            half = [size for name, size in entries if ".fp16." in name or "_fp16." in name]
            total += sum(half) if half else sum(size for _, size in entries)
        return total
    single = [size for name, size in files.items() if name.endswith(".safetensors")]
    return min(single) if single else 0


def check(repo, depth=0):
    """What `repo` needs, or CheckError: {"model", "kind" (text, gguf or media), "weights_gb",
    "gpu_gb", "disk_gb" (on a rented GPU), "compute" (the oldest GPU generation), "computers"
    (computers running Yougori can run it), "rent" (rented GPUs can), "summary", "notes"}."""
    status, value = fetch("/api/models/" + urllib.parse.quote(repo, safe="/") + "?blobs=true")
    if status in (401, 403, 404):
        raise CheckError(f"Hugging Face has no public model {repo}.")
    if status != 200 or not isinstance(value, dict):
        raise CheckError("Hugging Face did not answer. Retry in a moment.", transient=True)
    model = str(value.get("id") or repo)
    if value.get("gated") not in (False, None) or value.get("private") is True or value.get("disabled") is True:
        raise CheckError(f"{model} is gated or private on Hugging Face. Computers and rented GPUs download only public models.")
    tags = [tag for tag in value.get("tags") or [] if isinstance(tag, str)]
    base = next((tag.split(":", 1)[1] for tag in tags if tag.startswith("base_model:") and tag.count(":") == 1), None)

    def instead():
        """Its base model, when Yougori runs that one."""
        if not base or depth:
            return ""
        try:
            check(base, depth + 1)
        except CheckError:
            return ""
        return f" To serve the same model, add its base model {base}, which Yougori runs."
    files = {}
    for sibling in value.get("siblings") or []:
        if isinstance(sibling, dict) and isinstance(sibling.get("rfilename"), str):
            size = (sibling.get("lfs") or {}).get("size") or sibling.get("size") or 0
            files[sibling["rfilename"]] = size if isinstance(size, int) else 0
    config = value.get("config") if isinstance(value.get("config"), dict) else {}
    if "runner.json" in files:
        raise CheckError(f"{model} is a megakernel runner, not a model: add the model it runs.")
    if "megakernel" in (tag.lower() for tag in tags) or any(name.lower().endswith((".dll", ".cubin")) for name in files):
        raise CheckError(f"{model} ships its own megakernel program, built for particular GPUs, instead of standard weights. "
                         "Yougori's runtimes cannot run it on your computers or on rented GPUs." + instead())
    if config.get("auto_map"):
        raise CheckError(f"{model} needs its own repository code, which Yougori never runs." + instead())
    task = value.get("pipeline_tag")
    gib = 1024 ** 3
    gguf = {name: size for name, size in files.items() if name.lower().endswith(".gguf")}
    safetensors = sum(size for name, size in files.items() if name.endswith(".safetensors"))
    if gguf and not safetensors:
        # The file a computer installs: the preferred quantization (all of its parts).
        chosen = next((sum(size for name, size in gguf.items() if quant in name.upper()) for quant in GGUF_PREFERENCE
                       if any(quant in name.upper() for name in gguf)), min(gguf.values()))
        weights = chosen / gib
        return facts(model, "gguf", weights, math.ceil(weights * 1.2 + 2), 6.1, rent=False,
                     why="rented GPUs run safetensors chat models; GGUF files run on computers with Yougori")
    if task in MEDIA_TASKS or value.get("library_name") == "diffusers":
        if not safetensors:
            raise CheckError(f"{model} has no safetensors weights, which Yougori's media runtimes load.")
        weights = media_bytes(files) / gib
        return facts(model, "media", weights, math.ceil(weights * 1.1 + 4), 8.0, rent=False,
                     why="rented GPUs run chat models; image, video and speech models run on computers with Yougori")
    if task not in TEXT_TASKS:
        raise CheckError(f"{model} is a {task} model. Yougori serves chat, image, video and speech models.")
    parameters = (value.get("safetensors") or {}).get("parameters") if isinstance(value.get("safetensors"), dict) else None
    parameters = parameters if isinstance(parameters, dict) else {}
    if not safetensors:
        raise CheckError(f"{model} has no safetensors weights. Choose a model published in safetensors (or GGUF for computers).")
    architectures = [name for name in config.get("architectures") or [] if isinstance(name, str)]
    served_by_vllm = bool(VLLM.intersection(architectures))
    if not served_by_vllm and config.get("model_type") not in TRANSFORMERS:
        raise CheckError(f"{model}'s architecture ({', '.join(architectures) or 'unknown'}) is not one Yougori's runtimes serve yet.")
    weights = safetensors / gib
    # bf16 needs Ampere; the kernels of a quantized format may need a newer GPU.
    capability = 8.0 if "BF16" in parameters or not parameters else 7.5
    quant = str((config.get("quantization_config") or {}).get("quant_method") or "").lower() if isinstance(config.get("quantization_config"), dict) else ""
    capability = max(capability, QUANTIZATION.get(quant, 7.5))
    # The engine's estimates: Transformers needs weights x 1.2 + 2 GB, vLLM (weights + 2) / 0.9.
    gpu = math.ceil(max(weights * 1.2 + 2, (weights + 2) / 0.9))
    return facts(model, "text", weights, gpu, capability, rent=served_by_vllm, quant=quant,
                 why="its architecture runs on computers with Yougori, not on the runtime rented GPUs use")


def facts(model, kind, weights, gpu, capability, rent, why, quant=""):
    words = {"text": "Chat model", "gguf": "Chat model (GGUF)", "media": "Image, video or speech model"}[kind]
    label = {"modelopt": "FP4", "modelopt_fp4": "FP4", "nvfp4": "FP4", "compressed-tensors": "quantized", "bitsandbytes": "quantized"}.get(quant, quant.upper())
    summary = f"{words} · about {gpu} GB of GPU memory · {generation_words(capability)} or newer" + (f" · {label}" if quant else "")
    return {"model": model, "kind": kind, "weights_gb": round(weights, 1), "gpu_gb": gpu, "disk_gb": math.ceil(weights * 1.15 + neocloud.IMAGE_DISK_GB + 1),
            "compute": capability, "computers": True, "rent": rent, "summary": summary,
            "notes": [] if rent else ["Rented GPUs cannot run it: " + why + "."]}


def fits(facts_, gpus):
    """Whether one of these GPUs (name, memory in GB) runs the model: enough memory, a new
    enough generation (an unknown name is given the benefit of the doubt), and not AMD."""
    for name, memory in gpus:
        generation = gpu_generation(name)
        if generation == 0.0:
            continue
        if (memory or 0) >= facts_["gpu_gb"] and (generation is None or generation >= facts_["compute"]):
            return True
    return False
