#!/usr/bin/env python3
"""Add the trusted appliance update payload to Alpine's boot initramfs."""

from pathlib import Path
import gzip
import hashlib
import os
import re
import sys
import tarfile

PAYLOAD_FILES = (
    "/usr/local/sbin/opendock-agent",
    "/usr/local/sbin/yougori-upgrade-root",
    "/etc/init.d/opendock-agent",
    "/etc/init.d/containerd",
    "/etc/containerd/config.toml",
    "/etc/sysctl.d/90-yougori-security.conf",
)

MODULE_PAYLOAD_FILES = (
    "/usr/local/lib/yougori-boot/kernel-modules.tar.gz",
    "/usr/local/lib/yougori-boot/kernel-version",
    "/usr/local/lib/yougori-boot/kernel-modules.sha256",
)


def prepare_modules(rootfs: Path) -> None:
    library = rootfs / "lib"
    if library.is_symlink():
        if os.readlink(library) not in ("usr/lib", "/usr/lib"):
            raise ValueError("Unexpected trusted build library symlink")
        library = rootfs / "usr/lib"
    modules = library / "modules"
    versions = [path for path in modules.iterdir() if path.is_dir() and path.name.endswith("-virt")]
    if len(versions) != 1 or not re.fullmatch(r"[A-Za-z0-9._+-]{1,80}", versions[0].name):
        raise ValueError("Expected one trusted appliance kernel module version")
    version = versions[0]
    if version.is_symlink() or not version.resolve().is_relative_to(rootfs.resolve()):
        raise ValueError("Kernel modules escape the trusted build root")
    files = []
    for path in sorted(version.rglob("*")):
        # The disk's kernel image is not loaded by modprobe and is separately
        # packaged for direct boot. Alpine's module package links to that image.
        if path == version / "vmlinuz" and path.is_symlink() and os.readlink(path) == "/boot/vmlinuz-virt":
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(rootfs.resolve()):
            raise ValueError(f"Unsafe kernel module payload entry: {path}")
        if path.is_dir():
            continue
        if not path.is_file() or any(character in str(path.relative_to(version)) for character in "\r\n\x00"):
            raise ValueError(f"Invalid kernel module payload entry: {path}")
        files.append(path)
    if not files or sum(path.stat().st_size for path in files) > 96 * 1024 * 1024:
        raise ValueError("Kernel module payload exceeds the minimum appliance boot memory budget")
    payload = rootfs / "usr/local/lib/yougori-boot"
    payload.mkdir(parents=True, exist_ok=True)
    archive = payload / "kernel-modules.tar.gz"
    with archive.open("wb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as tar:
                for path in files:
                    name = version.name + "/" + path.relative_to(version).as_posix()
                    info = tarfile.TarInfo(name)
                    info.size = path.stat().st_size
                    info.mode = 0o644
                    info.mtime = 0
                    with path.open("rb") as source:
                        tar.addfile(info, source)
    if archive.stat().st_size > 64 * 1024 * 1024:
        raise ValueError("Compressed kernel modules exceed the minimum appliance boot memory budget")
    (payload / "kernel-version").write_text(version.name + "\n")
    (payload / "kernel-modules.sha256").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "\n")
    print(f"Trusted kernel module boot payload: {version.name}, {archive.stat().st_size} bytes")


def patch_init(source: str) -> str:
    lines = source.splitlines(keepends=True)
    sites = [i for i, line in enumerate(lines) if line.lstrip().startswith("exec switch_root ")]
    if len(sites) != 2 or 'sysroot=' not in source:
        raise ValueError("Unsupported Alpine init layout; refusing an incomplete boot security update")
    if "yougori-upgrade-root" in source:
        raise ValueError("Alpine init already contains a Yougori boot update")
    hook = ('/usr/local/sbin/yougori-upgrade-root "$sysroot" || '
            '{ echo "Yougori security update failed; keeping workloads stopped"; exit 1; }\n')
    for site in reversed(sites):
        indent = lines[site][:len(lines[site]) - len(lines[site].lstrip())]
        lines.insert(site, indent + hook)
    return "".join(lines)


def prepare(rootfs: Path, output: Path) -> None:
    for name in PAYLOAD_FILES:
        file = rootfs / name.lstrip("/")
        if not file.is_file() or file.is_symlink():
            raise ValueError(f"Missing or unsafe trusted boot payload: {name}")
    prepare_modules(rootfs)
    source = (rootfs / "usr/share/mkinitfs/initramfs-init").read_text()
    output.write_text(patch_init(source))
    features = rootfs / "etc/mkinitfs/features.d"
    features.mkdir(parents=True, exist_ok=True)
    (features / "yougori-security.files").write_text("\n".join(PAYLOAD_FILES + MODULE_PAYLOAD_FILES) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare-appliance-initramfs.py <rootfs> <patched-init>")
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
