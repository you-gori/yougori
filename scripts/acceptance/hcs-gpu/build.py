"""Build a local-only GPU test initrd using this PC's installed WSL drivers.

Run inside the existing Linux build distro. No downloads, host shares in the
resulting VM, or changes to the shipped guest. Driver files must not be published.
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
    with open(path, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def build(repo, output):
    repo, output = repo.resolve(), output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if (output / "manifest.json").exists():
        raise RuntimeError("output already contains a bundle; choose an empty output directory")
    kernel = Path("/mnt/c/Program Files/WSL/tools/kernel")
    probe = repo / "src-tauri/resources/runtime/cuda/yougori-cuda-probe"
    pins = (repo / "src-tauri/resources/runtime/cuda/SHA256SUMS").read_text()
    if f"{sha(probe)}  yougori-cuda-probe" not in pins:
        raise RuntimeError("CUDA probe does not match the bundled checksum")
    # Assemble on the build distro's Linux filesystem. Hundreds of ELF reads
    # through a Windows mount make cpio needlessly slow; only the final archive
    # and its manifest belong in the Windows build cache.
    with tempfile.TemporaryDirectory(prefix="hcs-gpu-") as temporary:
        root = Path(temporary) / "root"
        root.mkdir()
        for directory in ["proc", "sys", "dev", "bin", "tmp", "usr/lib/wsl/lib", "usr/lib/wsl/drivers"]:
            (root / directory).mkdir(parents=True, exist_ok=True)

        copied = set()
        def copy(source, target=None):
            source = Path(source)
            target = root / (target or str(source)).lstrip("/")
            if str(target) in copied:
                return
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(0o755)
            copied.add(str(target))
            # ldd only inspects the installed trusted runtime libraries.
            result = subprocess.run(["ldd", str(source)], capture_output=True, text=True)
            for line in result.stdout.splitlines():
                if "not found" in line:
                    raise RuntimeError(f"missing dependency: {line}")
                match = re.search(r"(/[^\s()]+)", line)
                if match:
                    dependency = match.group(1)
                    if dependency != str(source):
                        copy(dependency)

        copy(probe, "/cuda-probe")
        copy("/bin/busybox")
        copy("/usr/bin/strace")
        # The libcuda loader discovers the matching vendor library by driver-store
        # path returned by dxgkrnl. Copy files, never mount the host DriverStore.
        vendor_dirs = sorted(Path("/usr/lib/wsl/drivers").glob("*/libcuda.so.1.1"))
        if len(vendor_dirs) != 1:
            raise RuntimeError("expected exactly one installed CUDA driver; choose explicitly before extending this probe")
        for source in Path("/usr/lib/wsl/lib").glob("*.so*"):
            copy(source)
        for source in vendor_dirs[0].parent.glob("*.so*"):
            copy(source)
        # The Windows CUDA driver also loads device code from this data file.
        # Copying only shared libraries makes cuInit crash in an otherwise valid
        # GPU-PV VM (the syscall trace reports ENOENT immediately before SIGSEGV).
        cubins = vendor_dirs[0].parent / "nvcubins.bin"
        if not cubins.is_file():
            raise RuntimeError("the installed CUDA driver is missing nvcubins.bin")
        copy(cubins)
        env = {**os.environ, "CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": "amd64", "GOTOOLCHAIN": "local", "GOPROXY": "off"}
        go = shutil.which("go") or "/opt/go/bin/go"
        subprocess.run([go, "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-ldflags=-s -w -buildid=", "-o", str(root / "init"), str(repo / "scripts/acceptance/hcs-gpu/guest.go")], cwd=repo / "appliance/agent", env=env, check=True)
        paths = ["."] + [str(p.relative_to(root)) for p in sorted(root.rglob("*"))]
        archive = Path(temporary) / "initrd.cpio"
        with archive.open("wb") as dest:
            subprocess.run(["cpio", "--null", "-o", "-H", "newc", "--owner=0:0"], input=("\0".join(paths) + "\0").encode(), cwd=root, stdout=dest, check=True)
        with archive.open("rb") as src, (output / "initrd").open("wb") as dest:
            with gzip.GzipFile(fileobj=dest, mode="wb", compresslevel=1, mtime=0) as gz:
                shutil.copyfileobj(src, gz)
        archive.unlink()
    shutil.copyfile(kernel, output / "kernel")
    manifest = {"version": 1, "localOnly": True, "files": {name: sha(output / name) for name in ["kernel", "initrd"]}, "probeSha256": sha(probe), "kernelSource": str(kernel), "driverSource": str(vendor_dirs[0].parent)}
    (output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"bundle": str(output), "files": manifest["files"]}))


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", type=Path, required=True)
    p.add_argument("--output", type=Path, required=True)
    a = p.parse_args()
    build(a.repo, a.output)
