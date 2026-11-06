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


def availability(name, published=None):
    spec=catalog()[name]
    reason=spec.get('blocked','')
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
        if not re.fullmatch(r"[a-f0-9]{64}", str(value.get("sha256", ""))):
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
    if harness != "node" and harness not in specs:
        raise ValueError("Unknown harness.")
    if harness != "node" and specs[harness].get("blocked"):
        raise ValueError(specs[harness]["blocked"])
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", zipfile.ZIP_DEFLATED) as archive:
        def put(name, raw):
            info = zipfile.ZipInfo("inference-solver/" + name, (1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, raw)
        if harness == "node":
            for name in ("compute_node.py", "compute_adapter.py", "compute_options.py", "grid_adapter.py", "control_panel.py"):
                put(name, (ROOT.parent / name).read_bytes())
            put("harnesses/transport.py", (ROOT / "transport.py").read_bytes())
            put("cli_entry.py", b'import json,runpy,sys\nfrom pathlib import Path\np=Path(__file__).resolve().parent\nsys.argv=[sys.argv[1],*sys.argv[2:]]\nrunpy.run_path(str(p/"compute_node.py"),run_name="__main__")\n')
        else:
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
