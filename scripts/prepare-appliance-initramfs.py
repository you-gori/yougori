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
    "/usr/local/sbin/opendock-mount-helper",
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

VENDOR_FILES = (
    "usr/local/bin/containerd",
    "usr/local/bin/containerd-shim-runc-v2",
    "usr/local/bin/nerdctl",
    "usr/local/bin/runc",
    "usr/local/libexec/cni/bridge",
    "usr/local/libexec/cni/firewall",
    "usr/local/libexec/cni/host-local",
    "usr/local/libexec/cni/loopback",
    "usr/local/libexec/cni/portmap",
    "usr/local/libexec/cni/tuning",
)
VENDOR_PAYLOAD_FILES = (
    "/usr/local/lib/yougori-boot/oci-runtime.tar.gz",
    "/usr/local/lib/yougori-boot/oci-runtime.sha256",
    "/usr/local/lib/yougori-boot/oci-runtime.files",
)
MAX_VENDOR_FILE_BYTES = 96 * 1024 * 1024
MAX_VENDOR_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_VENDOR_ARCHIVE_BYTES = 96 * 1024 * 1024
MAX_BOOT_UPDATE_BYTES = 192 * 1024 * 1024


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def boot_payload_directory(rootfs: Path) -> Path:
    if rootfs.is_symlink() or not rootfs.is_dir():
        raise ValueError("Unexpected trusted build root")
    payload = rootfs
    for component in ("usr", "local", "lib", "yougori-boot"):
        payload = payload / component
        if payload.is_symlink() or (payload.exists() and not payload.is_dir()):
            raise ValueError("Unexpected trusted boot payload directory redirect")
    payload.mkdir(parents=True, exist_ok=True)
    for name in MODULE_PAYLOAD_FILES + VENDOR_PAYLOAD_FILES:
        file = rootfs / name.lstrip("/")
        if file.is_symlink() or (file.exists() and (not file.is_file() or file.stat().st_nlink != 1)):
            raise ValueError(f"Unexpected trusted boot payload file redirect: {name}")
    return payload


def trusted_vendor_file(rootfs: Path, name: str) -> Path:
    path = rootfs
    for component in name.split("/"):
        path = path / component
        if path.is_symlink():
            raise ValueError(f"Symlink in trusted OCI payload: {path}")
    if not path.is_file() or path.stat().st_nlink != 1 or not path.resolve().is_relative_to(rootfs.resolve()):
        raise ValueError(f"Missing or unsafe trusted OCI payload: {name}")
    size = path.stat().st_size
    if not 0 < size <= MAX_VENDOR_FILE_BYTES:
        raise ValueError(f"Trusted OCI payload file exceeds boot budget: {name}")
    with path.open("rb") as source:
        header = source.read(20)
    if len(header) != 20 or header[:6] != b"\x7fELF\x02\x01" or header[18:20] != b"\x3e\x00":
        raise ValueError(f"Expected a trusted Linux x86-64 OCI executable: {name}")
    return path


def prepare_vendor(rootfs: Path) -> None:
    # Keep vendor executables compressed in initramfs. The boot hook extracts
    # them onto the mounted disk, instead of allocating their expanded size
    # in the minimum 512 MiB appliance's in-memory root filesystem.
    files = [(name, trusted_vendor_file(rootfs, name)) for name in VENDOR_FILES]
    expanded = sum(path.stat().st_size for _, path in files)
    if expanded > MAX_VENDOR_EXPANDED_BYTES:
        raise ValueError("Expanded OCI payload exceeds the minimum appliance boot memory budget")
    payload = boot_payload_directory(rootfs)
    archive = payload / "oci-runtime.tar.gz"
    with archive.open("wb") as output:
        with gzip.GzipFile(filename="", fileobj=output, mode="wb", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for name, path in files:
                    info = tarfile.TarInfo(name)
                    info.size = path.stat().st_size
                    info.mode = 0o755
                    info.mtime = 0
                    with path.open("rb") as source:
                        tar.addfile(info, source)
    if archive.stat().st_size > MAX_VENDOR_ARCHIVE_BYTES:
        raise ValueError("Compressed OCI payload exceeds the minimum appliance boot memory budget")
    (payload / "oci-runtime.sha256").write_text(sha256_file(archive) + "\n")
    (payload / "oci-runtime.files").write_text("".join(
        f"{sha256_file(path)} {path.stat().st_size} {name}\n" for name, path in files))
    print(f"Trusted OCI boot payload: {len(files)} executables, {archive.stat().st_size} compressed / {expanded} expanded bytes")


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
    payload = boot_payload_directory(rootfs)
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
    prepare_vendor(rootfs)
    payload_bytes = sum((rootfs / name.lstrip("/")).stat().st_size
                        for name in PAYLOAD_FILES + MODULE_PAYLOAD_FILES + VENDOR_PAYLOAD_FILES)
    if payload_bytes > MAX_BOOT_UPDATE_BYTES:
        raise ValueError("Combined trusted boot update exceeds the minimum appliance boot memory budget")
    source = (rootfs / "usr/share/mkinitfs/initramfs-init").read_text()
    output.write_text(patch_init(source))
    features = rootfs / "etc/mkinitfs/features.d"
    features.mkdir(parents=True, exist_ok=True)
    (features / "yougori-security.files").write_text("\n".join(PAYLOAD_FILES + MODULE_PAYLOAD_FILES + VENDOR_PAYLOAD_FILES) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare-appliance-initramfs.py <rootfs> <patched-init>")
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
