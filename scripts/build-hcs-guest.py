"""Assemble a local HCS guest from the verified Yougori guest and this PC's GPU driver.

Run in the existing Linux builder. No driver download or host share is used.
This local driver bundle must not be included in public release artifacts.
"""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


def sha(path):
    with open(path, "rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def build(repo, guest, output):
    repo, guest, output = repo.resolve(), guest.resolve(), output.resolve()
    if (output / "manifest.json").exists():
        raise ValueError("choose a new output directory")
    record = json.loads((guest / "artifacts.json").read_text())
    for entry in record["artifacts"]:
        if sha(guest / entry["name"]) != entry["sha256"]:
            raise ValueError("base guest checksum mismatch: " + entry["name"])
    kernel = Path("/mnt/c/Program Files/WSL/tools/kernel")
    drivers = sorted(Path("/usr/lib/wsl/drivers").glob("*/libcuda.so.1.1"))
    if len(drivers) != 1:
        raise ValueError("exactly one installed NVIDIA GPU driver is required")
    vendor = drivers[0].parent
    if not (vendor / "nvcubins.bin").is_file():
        raise ValueError("the NVIDIA driver is missing nvcubins.bin")
    output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="yougori-hcs-") as temporary:
        tree = Path(temporary) / "initrd"
        for name in ["dev", "proc", "sys", "newroot", "etc/yougori", "gpu/usr/lib/wsl/lib", "gpu/lib64", "gpu/lib/x86_64-linux-gnu", "gpu/opt/yougori-gpu"]:
            (tree / name).mkdir(parents=True)
        (tree / "etc/yougori/hcs").write_text("1\n")
        shutil.copyfile(guest / "yougori-sandbox-agent", tree / "init")
        (tree / "init").chmod(0o755)
        shutil.copyfile(guest / "root.img", tree / "root.img")
        copied = set()

        def copy(source, target=None):
            source = Path(source)
            destination = tree / "gpu" / (target or str(source)).lstrip("/")
            if str(destination) in copied:
                return
            copied.add(str(destination))
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, destination)
            destination.chmod(0o555)
            deps = subprocess.run(["ldd", str(source)], capture_output=True, text=True)
            for line in deps.stdout.splitlines():
                if "not found" in line:
                    raise ValueError("missing GPU library dependency: " + line)
                match = re.search(r"(/[^\s()]+)", line)
                if match and match.group(1) != str(source):
                    copy(match.group(1))

        for source in Path("/usr/lib/wsl/lib").glob("*.so*"):
            copy(source)
        for source in vendor.glob("*.so*"):
            copy(source)
        copy(vendor / "nvcubins.bin")
        copy("/usr/lib/wsl/lib/nvidia-smi", "/opt/yougori-gpu/nvidia-smi")
        probe = repo / "src-tauri/resources/runtime/cuda/yougori-cuda-probe"
        if f"{sha(probe)}  yougori-cuda-probe" not in (probe.parent / "SHA256SUMS").read_text():
            raise ValueError("CUDA probe checksum mismatch")
        copy(probe, "/opt/yougori-gpu/cuda-probe")
        # Some dependencies use the /usr spelling; keep one readonly tree for
        # their canonical glibc path, irrespective of the builder's usr-merge.
        extra = tree / "gpu/usr/lib/x86_64-linux-gnu"
        if extra.exists():
            shutil.copytree(extra, tree / "gpu/lib/x86_64-linux-gnu", dirs_exist_ok=True)
        paths = [str(p.relative_to(tree)) for p in sorted(tree.rglob("*"))]
        archive = Path(temporary) / "initrd.cpio"
        with archive.open("wb") as dest:
            subprocess.run(["cpio", "--null", "-o", "-H", "newc", "--owner=0:0"], input=("\0".join(paths) + "\0").encode(), cwd=tree, stdout=dest, check=True)
            # PID 1's Go libraries may open /dev/null before devtmpfs is mounted.
            subprocess.run(["python3", "-I", str(repo / "guest/guest_build.py"), "devices", str(record["source_date_epoch"])], stdout=dest, check=True)
        with archive.open("rb") as src, (output / "initrd").open("wb") as dest:
            with gzip.GzipFile(fileobj=dest, mode="wb", mtime=0, compresslevel=1) as gz:
                shutil.copyfileobj(src, gz)
    shutil.copyfile(kernel, output / "kernel")
    with gzip.open("/proc/config.gz", "rb") as source:
        (output / "kernel.config").write_bytes(source.read())
    manifest = {"format": "yougori-hcs-guest/v1", "local_only": True,
                "files": {name: sha(output / name) for name in ["kernel", "initrd", "kernel.config"]},
                "root_sha256": sha(guest / "root.img"), "agent_build": record["agent_build"],
                "base_record_sha256": sha(guest / "artifacts.json"),
                "kernel_release": os.uname().release, "driver_source": str(vendor)}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps({"output": str(output), "files": manifest["files"]}))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ["repo", "guest", "output"]:
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args()
    build(args.repo, args.guest, args.output)
