"""Neocloud GPUs the website rents itself with its administrator's own provider keys: RunPod
pods and Vast.ai instances, as Yougori's engine rents them. Only these named operations reach a
provider, at fixed addresses; a request never supplies a provider URL. Keys stay on this server.

A rented GPU runs one model with the serving runtime Yougori pins (vLLM 0.29.0, its CUDA 12.9
build, by digest) and connects back to the website on its own (rental_agent.py), as a
connected computer does: nothing listens on the machine's public addresses.
"""
import json
from pathlib import Path
import re
import urllib.error
import urllib.parse
import urllib.request

RUNPOD_GRAPHQL = "https://api.runpod.io/graphql"
RUNPOD_REST = "https://rest.runpod.io/v1"
VAST = "https://console.vast.ai/api/v0"
HUGGING_FACE = "https://huggingface.co"

PROVIDERS = {"runpod": "RunPod", "vast": "Vast.ai"}
# vLLM 0.29.0, the release Yougori's engine pins, in its CUDA 12.9 build: more rentable machines
# have a driver for CUDA 12.9 than for the default build's 13.0.
IMAGE = "vllm/vllm-openai@sha256:7ef5a35d1ef8ce2cf9d671dd91eec6e367c5849262e0362b4d3d4a26be0d87d2"
MIN_CUDA = 12.9
# The text architectures that runtime serves (the engine's architectures-vllm-0.29.0.json).
ARCHITECTURES = set(json.loads((Path(__file__).resolve().parent / "vllm_architectures.json").read_text(encoding="utf-8"))["architectures"])
# Where the runtime image and its packages go beside the model's own files.
IMAGE_DISK_GB = 35

# What GPU type RunPod lists, available at this count and disk, in Secure and Community Cloud
# (the engine's own query).
OFFERS_QUERY = """
query YougoriGpuOffers($secure: GpuLowestPriceInput!, $community: GpuLowestPriceInput!) {
  gpuTypes {
    id displayName memoryInGb secureCloud communityCloud securePrice communityPrice
    secure: lowestPrice(input: $secure) { stockStatus uninterruptablePrice availableGpuCounts }
    community: lowestPrice(input: $community) { stockStatus uninterruptablePrice availableGpuCounts }
  }
}"""


class ProviderError(Exception):
    """A provider's refusal, or no answer, in words for the administrator. `definite` is False
    when the provider may still have acted on a request it never answered."""

    def __init__(self, message, definite=True):
        super().__init__(message)
        self.definite = definite


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # A provider that redirects is answered as an error, never followed.


_OPENER = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))


def call(method, url, key=None, body=None, timeout=30, limit=8 * 1024 * 1024):
    """One JSON request: (status, value). A network failure raises ProviderError(definite=False)."""
    headers = {"Accept": "application/json", "User-Agent": "Yougori-Inference/1"}
    if key:
        headers["Authorization"] = "Bearer " + key
    data = None if body is None else json.dumps(body).encode()
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with _OPENER.open(request, timeout=timeout) as response:
            status, raw = response.status, response.read(limit + 1)
    except urllib.error.HTTPError as error:
        status, raw = error.code, error.read(65536)
    except (urllib.error.URLError, OSError, ValueError):
        raise ProviderError("The provider did not answer. Check its status page, then retry.", definite=False) from None
    if len(raw) > limit:
        raise ProviderError("The provider sent an oversized answer.")
    try:
        return status, json.loads(raw) if raw.strip() else {}
    except ValueError:
        return status, {}


def key_text(provider, key):
    """An account key as the administrator pasted it: one line of printable characters."""
    if provider not in PROVIDERS:
        raise ProviderError("Choose RunPod or Vast.ai.")
    key = key.strip() if isinstance(key, str) else ""
    if not 8 <= len(key) <= 512 or any(not 33 <= ord(c) <= 126 for c in key):
        raise ProviderError("Paste your " + PROVIDERS[provider] + " API key.")
    return key


def number(value):
    try:
        value = float(value)
    except (TypeError, ValueError):
        return None
    return value if value == value and value not in (float("inf"), float("-inf")) else None


def account(provider, key):
    """The account behind a key, read-only: its balance and spend, which also proves the key."""
    if provider == "runpod":
        status, value = call("POST", RUNPOD_GRAPHQL, key, {"query": "query { myself { id clientBalance currentSpendPerHr } }"})
        me = (value.get("data") or {}).get("myself") if isinstance(value, dict) else None
        if status != 200 or not isinstance(me, dict) or not me.get("id"):
            raise ProviderError("RunPod did not accept this API key. Create one under Settings, API Keys, with read and write access.")
        return {"balance": number(me.get("clientBalance")), "spend_per_hour": number(me.get("currentSpendPerHr"))}
    status, value = call("GET", VAST + "/users/current/", key)
    if status != 200 or not isinstance(value, dict) or not value.get("id"):
        raise ProviderError("Vast.ai did not accept this API key. Create one under Account, Keys.")
    return {"balance": number(value.get("credit")), "spend_per_hour": None}


def _runpod_offers(key, gpu_count, disk_gb):
    lowest = {"gpuCount": gpu_count, "minDisk": disk_gb, "minCudaVersion": str(MIN_CUDA)}
    variables = {"secure": {**lowest, "secureCloud": True, "supportPublicIp": False}, "community": {**lowest, "secureCloud": False}}
    status, value = call("POST", RUNPOD_GRAPHQL, key, {"query": OFFERS_QUERY, "variables": variables})
    rows = (value.get("data") or {}).get("gpuTypes") if isinstance(value, dict) else None
    if status != 200 or value.get("errors") or not isinstance(rows, list):
        raise ProviderError("RunPod could not list its GPUs right now. Retry in a moment.")
    offers = []
    for row in rows:
        for cloud in ("secure", "community"):
            live = row.get(cloud) or {}
            price = number(live.get("uninterruptablePrice"))
            counts = live.get("availableGpuCounts")
            stock = str(live.get("stockStatus") or "").lower()
            if (row.get(cloud + "Cloud") is True and price and price > 0 and stock != "none"
                    and (not isinstance(counts, list) or gpu_count in counts)):
                offers.append({"id": "runpod:" + cloud + ":" + str(row.get("id")), "provider": "runpod", "gpu": str(row.get("id")),
                               "name": str(row.get("displayName") or row.get("id")), "vram_gb": number(row.get("memoryInGb")),
                               "gpu_count": gpu_count, "hourly_usd": round(price * gpu_count, 4),
                               "where": "Secure Cloud" if cloud == "secure" else "Community Cloud", "cloud": cloud.upper()})
    return offers


def _vast_offers(key, gpu_count, disk_gb):
    # Turing or newer (compute capability 7.5, as Vast.ai writes it 750): older GPUs, which Vast.ai
    # lists cheapest, cannot run the runtime.
    query = {"limit": 64, "type": "ondemand", "verified": {"eq": True}, "rentable": {"eq": True}, "rented": {"eq": False},
             "num_gpus": {"eq": gpu_count}, "disk_space": {"gte": disk_gb}, "cuda_max_good": {"gte": MIN_CUDA}, "compute_cap": {"gte": 750},
             "reliability": {"gte": 0.98}, "allocated_storage": disk_gb, "order": [["dph_total", "asc"]]}
    status, value = call("POST", VAST + "/bundles/", key, query)
    rows = value.get("offers") if isinstance(value, dict) else None
    if status != 200 or not isinstance(rows, list):
        raise ProviderError("Vast.ai could not list its GPUs right now. Retry in a moment.")
    offers = []
    for row in rows:
        price, identity = number(row.get("dph_total")), row.get("id")
        if not price or price <= 0 or not isinstance(identity, int):
            continue
        memory = number(row.get("gpu_ram"))
        offers.append({"id": "vast:" + str(identity), "provider": "vast", "gpu": str(row.get("gpu_name") or "GPU"),
                       "name": str(row.get("gpu_name") or "GPU"), "vram_gb": round(memory / 1000, 1) if memory else None,
                       "gpu_count": int(row.get("num_gpus") or gpu_count), "hourly_usd": round(price, 4),
                       "where": str(row.get("geolocation") or "Vast.ai")[:60], "ask": identity,
                       # Its GPU generation as Vast.ai lists it (compute capability x 100).
                       "compute": round(number(row.get("compute_cap")) / 100, 1) if number(row.get("compute_cap")) else None})
    return offers


def offers(provider, key, gpu_count, disk_gb):
    """Rentable GPUs right now, cheapest first, for `gpu_count` GPUs and `disk_gb` of disk. Both
    providers list them without a key (`key` None); renting needs one."""
    found = _runpod_offers(key, gpu_count, disk_gb) if provider == "runpod" else _vast_offers(key, gpu_count, disk_gb)
    return sorted(found, key=lambda offer: offer["hourly_usd"])[:100]


def boot():
    """What the rented machine runs first: fetch this website's agent with its own credential,
    then run it (rental_agent.py), retrying while the website is out of reach."""
    return ("import io,os,sys,time,urllib.request as u,zipfile as z\n"
            "for attempt in range(60):\n"
            " try:\n"
            "  r=u.Request(os.environ['YOUGORI_SERVER']+'/api/compute/rental-agent',headers={'Authorization':'Bearer '+os.environ['YOUGORI_AGENT_TOKEN']})\n"
            "  z.ZipFile(io.BytesIO(u.urlopen(r,timeout=120).read())).extractall('/opt/yougori-agent');break\n"
            " except Exception as e:\n"
            "  print('Waiting for the website:',e,flush=True);time.sleep(10)\n"
            "os.execv(sys.executable,[sys.executable,'-I','-B','/opt/yougori-agent/inference-solver/rental_agent.py'])\n")


def create(provider, key, offer, name, environment, disk_gb):
    """Rents the offer: one pod or instance running IMAGE with the agent. Returns the provider's
    resource ID and its hourly price. A ProviderError with definite=False means the provider may
    have created it anyway; it is never asked again."""
    if provider == "runpod":
        body = {"name": name, "imageName": IMAGE, "gpuTypeIds": [offer["gpu"]], "gpuCount": offer["gpu_count"],
                "cloudType": offer["cloud"], "containerDiskInGb": disk_gb, "volumeInGb": 0, "ports": [],
                "env": environment, "dockerEntrypoint": ["python3", "-c", boot()], "dockerStartCmd": [],
                "allowedCudaVersions": ["12.9", "13.0"], "interruptible": False}
        status, value = call("POST", RUNPOD_REST + "/pods", key, body, timeout=60)
        if status in (200, 201) and isinstance(value, dict) and value.get("id"):
            return str(value["id"]), number(value.get("costPerHr")) or offer["hourly_usd"]
        if status >= 500:
            raise ProviderError("RunPod did not confirm the rental. Check your RunPod pods for " + name + " before trying again.", definite=False)
        raise ProviderError("RunPod refused the rental: " + _said(value, "the GPU may no longer be available. Find GPUs again."))
    variables = " ".join("-e " + k + "=" + v for k, v in environment.items())
    script = ("cat > /opt/yougori-boot.py <<'YOUGORI'\n" + boot() + "YOUGORI\n"
              "nohup python3 /opt/yougori-boot.py > /var/log/yougori-agent.log 2>&1 &\n")
    body = {"client_id": "me", "image": IMAGE, "env": variables, "disk": disk_gb, "label": name, "onstart": script, "runtype": "ssh"}
    status, value = call("PUT", VAST + "/asks/" + str(offer["ask"]) + "/", key, body, timeout=60)
    if status == 200 and isinstance(value, dict) and value.get("success") and value.get("new_contract"):
        return str(value["new_contract"]), offer["hourly_usd"]
    if status >= 500:
        raise ProviderError("Vast.ai did not confirm the rental. Check your Vast.ai instances for " + name + " before trying again.", definite=False)
    raise ProviderError("Vast.ai refused the rental: " + _said(value, "the GPU may no longer be available. Find GPUs again."))


def _said(value, fallback):
    """A provider's own refusal, shortened; it names the problem (no balance, no capacity)."""
    text = ""
    if isinstance(value, dict):
        text = value.get("error") or value.get("msg") or value.get("message") or ""
        if isinstance(value.get("errors"), list) and value["errors"]:
            text = (value["errors"][0] or {}).get("message", "") if isinstance(value["errors"][0], dict) else str(value["errors"][0])
    text = re.sub(r"\s+", " ", str(text)).strip()[:200]
    return text + ("" if text.endswith(".") else ".") if text else fallback


def status(provider, key, resource):
    """What the provider says of a rented GPU: running, starting, stopped (it no longer charges
    for the GPU) or gone; None when it did not answer."""
    path = (RUNPOD_REST + "/pods/" if provider == "runpod" else VAST + "/instances/") + urllib.parse.quote(resource, safe="") + "/" * (provider == "vast")
    try:
        code, value = call("GET", path, key)
    except ProviderError:
        return None
    if code == 404:
        return "gone"
    if code != 200 or not isinstance(value, dict):
        return None
    if provider == "runpod":
        desired = str(value.get("desiredStatus") or "").upper()
        return {"RUNNING": "running", "EXITED": "stopped", "TERMINATED": "gone"}.get(desired)
    instance = value.get("instances")
    if not isinstance(instance, dict):
        return "gone"
    actual = str(instance.get("actual_status") or "").lower()
    if actual == "running":
        return "running"
    if actual in ("exited", "offline", "unknown") or str(instance.get("intended_status") or "").lower() == "stopped":
        return "stopped"
    return "starting"


def terminate(provider, key, resource):
    """Deletes a rented GPU, which ends its charges. True once the provider confirms it or no
    longer has it."""
    path = (RUNPOD_REST + "/pods/" if provider == "runpod" else VAST + "/instances/") + urllib.parse.quote(resource, safe="") + "/" * (provider == "vast")
    code, _ = call("DELETE", path, key, timeout=60)
    return code in (200, 202, 204, 404)
