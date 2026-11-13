"""Portable source-only CLI bundle. No database, account or key files."""
import io
import base64
import hashlib
import json
import os
from pathlib import Path
import re
from urllib.parse import urlsplit
import zipfile
from harnesses.transport import local_hostname

ROOT = Path(__file__).resolve().parent / "harnesses"
FILES = ("solver.py", "device_login.py", "transport.py", "vm_host.py", "vm_relay.py", "vm_guest.py", "vm_package.py", "vm_tunnel.py", "shannon_cli.py", "pentagi_cli.py", "install_shannon.py", "install_pentagi.py", "pentagi_vm.go", "pentagi_vm_test.go", "hexstrike_cli.py", "plandex_cli.py", "strix_cli.py", "cli_entry.py", "packages.json", "installer.py", "profiles.py", "runtime.py", "relay.py", "blue.py", "README.md")

# Official CPython Windows embeddable distributions, fetched over HTTPS and pinned.
# https://www.python.org/downloads/release/python-31410/
PYTHON_VERSION = "3.14.10"
PYTHON_SHA256 = {
    "amd64": "90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159",
    "arm64": "bbe116bb1248820359cbf25127ac5c7794ea161869d83686cfbc9a45203ff836",
}


def origin(value):
    p = urlsplit(value)
    if (p.scheme not in ("http", "https") or not p.hostname or p.username or p.password
            or p.path not in ("", "/") or p.query or p.fragment
            or not re.fullmatch(r"[A-Za-z0-9.\-:\[\]]+", p.netloc)
            or not 1 <= (p.port if p.port is not None else (443 if p.scheme == "https" else 80)) <= 65535):
        raise ValueError("Use a valid service origin without credentials or a path.")
    if p.scheme == "http" and not local_hostname(p.hostname):
        raise ValueError("Published installers require HTTPS.")
    return value.rstrip("/")


def catalog():
    return json.loads((ROOT / "packages.json").read_text())


UNPUBLISHED = "The administrator has not published this harness's Sandbox VM image yet."
STALE = "The published VM image needs updating before this harness can start."
INCOMPLETE = "The published VM files are incomplete. The administrator needs to prepare them again."
UNREADABLE = "The published VM image is unavailable. The administrator needs to prepare it again."
# Yougori's own agent has no image of its own: a launcher that starts a harness from its own image
# cannot start it.
OWN_AGENT = "This version of Yougori cannot start Yougori's own agent. Update Yougori: yougori update"

# The Yougori harness holds every other harness. Its images (scripts/build-vm-images.py yougori)
# are one base image in a few variants and a pack per harness (its engine: a tool archive), all in
# vm-images/yougori beside one image.json:
#   {"runtime", "platform", "version",
#    "bases": {NAME: {"sha256", "bytes", "disk"}},
#    "packs": {HARNESS: {"sha256", "bytes", "version", "base", "disk", "memory"},
#              "yougori": {"base", "disk", "memory"}}}
# A base is imported once with `disk` GB of root (room for each of its packs); a harness's VM
# starts from its base with `memory` GB unless the person chose a size, and gets its pack through
# the VM's private control connection. Yougori's own agent needs no pack.
YOUGORI = "yougori"
RUNTIME = "yougori-sandbox-vm"
PLATFORM = "linux/amd64"
DIGEST = re.compile(r"[a-f0-9]{64}")
NAME = re.compile(r"[a-z][a-z0-9-]{0,31}")
# The launcher's bounds: an image archive and a pack it downloads, and the largest root Yougori imports.
IMAGE_BYTES = 300 << 20
PACK_BYTES = 512 << 20
ROOT_GB = 8


def yougori_image(value):
    """The Yougori harness's image.json, checked: every base and pack well formed, every pack on a
    listed base whose root has room for it, with memory for that root (the base's root and
    512 MiB for the VM). Raises ValueError otherwise."""
    def count(number, most):
        return type(number) is int and 0 < number <= most
    if (not isinstance(value, dict) or value.get("runtime") != RUNTIME or value.get("platform") != PLATFORM
            or not isinstance(value.get("version"), str) or not value["version"] or not isinstance(value.get("bases"), dict)
            or not isinstance(value.get("packs"), dict) or not 1 <= len(value["bases"]) <= 8 or len(value["packs"]) > 256):
        raise ValueError("Invalid image descriptor.")
    for name, base in value["bases"].items():
        if (not NAME.fullmatch(name) or not isinstance(base, dict) or not DIGEST.fullmatch(str(base.get("sha256", "")))
                or not count(base.get("bytes"), IMAGE_BYTES) or not count(base.get("disk"), ROOT_GB)):
            raise ValueError("Invalid image descriptor.")
    for name, pack in value["packs"].items():
        base = value["bases"].get(pack.get("base")) if isinstance(pack, dict) and isinstance(pack.get("base"), str) else None
        if (not NAME.fullmatch(name) or base is None or not count(pack.get("disk"), base["disk"])
                or not count(pack.get("memory"), 1024) or pack["memory"] < base["disk"] + 1):
            raise ValueError("Invalid image descriptor.")
        has_pack = any(key in pack for key in ("sha256", "bytes", "version"))
        if name == YOUGORI:
            if has_pack:
                raise ValueError("Invalid image descriptor.")
        elif (not DIGEST.fullmatch(str(pack.get("sha256", ""))) or not count(pack.get("bytes"), PACK_BYTES)
                or not isinstance(pack.get("version"), str) or not pack["version"]):
            raise ValueError("Invalid image descriptor.")
    return value


def offered_image(record, offered):
    """The Yougori harness's image.json as this website hands it out: only the packs of the
    harnesses offered here, and the bases they start from."""
    packs = {name: pack for name, pack in record["packs"].items() if name in offered}
    used = {pack["base"] for pack in packs.values()}
    return {**record, "bases": {name: base for name, base in record["bases"].items() if name in used}, "packs": packs}


def held(name, published=None):
    """Whether `name` can start inside the Yougori harness here, as `yougori inference run` starts
    every harness: the Yougori harness's images list its pack at the pinned version (Yougori's own
    agent needs none), and that pack and its base image are published whole. With `published` (a
    hosted instance's artifacts, served elsewhere) only the listing is checked."""
    specs = catalog()
    spec = specs.get(name)
    if spec is None or YOUGORI not in specs:
        return {"available": False, "reason": UNPUBLISHED, "version": None}
    reason = spec.get("blocked", "") or specs[YOUGORI].get("blocked", "")
    if not reason:
        try:
            record = published.get("images", {}).get(YOUGORI) if published is not None else vm_image(YOUGORI)
            if not record:
                reason = UNPUBLISHED
            else:
                record = yougori_image(record)
                pack = record["packs"].get(name)
                if record["version"] != specs[YOUGORI].get("version"):
                    reason = STALE
                elif pack is None:
                    reason = UNPUBLISHED
                elif name != YOUGORI and pack["version"] != spec.get("version"):
                    reason = STALE
                elif published is None:
                    base = record["bases"][pack["base"]]
                    image = vm_image(YOUGORI, base["sha256"])
                    archive = vm_image(YOUGORI, pack["sha256"], "tool") if name != YOUGORI else None
                    if (not image or image.stat().st_size != base["bytes"]
                            or (name != YOUGORI and (not archive or archive.stat().st_size != pack["bytes"]))):
                        reason = INCOMPLETE
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            reason = UNREADABLE
    return {"available": not reason, "reason": reason, "version": spec.get("version")}


def availability(name, published=None):
    """Whether `name`'s own Sandbox VM image is ready here (/api/harness-image/NAME): what every
    launcher that starts a harness from its own image checks, the ones from before the Yougori
    harness included. Yougori's own agent has none; it starts only from the Yougori harness's
    images (held)."""
    spec=catalog()[name]
    reason=spec.get('blocked','')
    if name == YOUGORI:
        return {'available': False, 'reason': reason or OWN_AGENT, 'version': spec.get('version')}
    if published is not None:
        record = published.get('images', {}).get(name)
        if not reason and (not record or record.get('version') != spec.get('version')):
            reason = 'The administrator has not published this harness\'s Sandbox VM image yet.'
        return {'available': not bool(reason), 'reason': reason, 'version': spec.get('version')}
    try:
        record=vm_image(name) if not reason else None
        if not reason:
            if not record:
                reason='The administrator has not published this harness\'s Sandbox VM image yet.'
            elif record.get('version')!=spec.get('version') or record.get('runtime')!='yougori-sandbox-vm' or record.get('platform')!='linux/amd64':
                reason='The published VM image needs updating before this harness can start.'
            else:
                image=vm_image(name,record['sha256'])
                tool=record.get('tool')
                package=vm_image(name,tool['sha256'],'tool') if tool else None
                if not image or image.stat().st_size!=record.get('bytes') or (tool and (not package or package.stat().st_size!=tool.get('bytes'))):
                    reason='The published VM files are incomplete. The administrator needs to prepare them again.'
    except (OSError,ValueError,KeyError,TypeError):
        reason='The published VM image is unavailable. The administrator needs to prepare it again.'
    return {'available':not bool(reason),'reason':reason,'version':spec.get('version')}


def vm_image(harness, digest=None, kind=None):
    """Only publisher-prepared, immutable OCI archives; never arbitrary site files."""
    if harness not in catalog() or catalog()[harness].get("blocked"):
        raise ValueError("Unknown or unavailable harness.")
    base = Path(os.environ.get("SOLVER_VM_IMAGES", ROOT.parent / "vm-images"))
    folder = base / harness
    if digest is None:
        path = folder / "image.json"
        if not path.is_file():
            return None
        value = json.loads(path.read_text(encoding="utf-8"))
        if harness == YOUGORI:
            return yougori_image(value)
        if not isinstance(value, dict) or not re.fullmatch(r"[a-f0-9]{64}", str(value.get("sha256", ""))):
            raise ValueError("Invalid image descriptor.")
        return value
    if not re.fullmatch(r"[a-f0-9]{64}", digest):
        raise ValueError("Invalid image identity.")
    if kind not in (None,'tool'): raise ValueError('Unknown artifact kind.')
    path = folder / (digest + (".tar.gz" if kind == 'tool' else ".zip"))
    return path if path.is_file() and not path.is_symlink() else None


def bundle(harness, server):
    server = origin(server)
    specs = catalog()
    if harness not in ("node", "rental") and harness not in specs:
        raise ValueError("Unknown harness.")
    if harness not in ("node", "rental") and specs[harness].get("blocked"):
        raise ValueError(specs[harness]["blocked"])
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        def put(name, raw):
            info = zipfile.ZipInfo("inference-solver/" + name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
        if harness in ("node", "rental"):
            # A rented GPU's agent (rental_agent.py) serves through the connector's own code.
            for name in ("compute_node.py", "compute_adapter.py", "compute_options.py", "grid_adapter.py", "control_panel.py") + (("rental_agent.py",) if harness == "rental" else ()):
                put(name, (ROOT.parent / name).read_bytes())
            put("harnesses/transport.py", (ROOT / "transport.py").read_bytes())
        if harness == "node":
            put("cli_entry.py", b'import json,runpy,sys\nfrom pathlib import Path\np=Path(__file__).resolve().parent\nsys.argv=[sys.argv[1],*sys.argv[2:]]\nrunpy.run_path(str(p/"compute_node.py"),run_name="__main__")\n')
        if harness not in ("node", "rental"):
            for name in FILES:
                put(name, (ROOT / name).read_bytes())
        put("connection.json", json.dumps({"server": server, "harness": harness}))
    return stream.getvalue()


def powershell(harness, server):
    server = origin(server)
    raw = bundle(harness, server)  # Also rejects unknown/unavailable tools.
    config = {"harness": harness, "server": server, "sha256": hashlib.sha256(raw).hexdigest(),
              "bundle": server + "/api/harness-download/" + harness, "python_version": PYTHON_VERSION,
              "python": {arch: {"url": f"https://www.python.org/ftp/python/{PYTHON_VERSION}/python-{PYTHON_VERSION}-embed-{arch}.zip",
                                "sha256": sha} for arch, sha in PYTHON_SHA256.items()}}
    encoded = base64.b64encode(json.dumps(config).encode()).decode()
    return (ROOT.parent / "install-harness.ps1").read_text(encoding="utf-8").replace("__SOLVER_CONFIG_BASE64__", encoded).encode()
