#!/usr/bin/env python3
"""Add the trusted appliance update payload to Alpine's boot initramfs."""

from pathlib import Path
import sys

PAYLOAD_FILES = (
    "/usr/local/sbin/opendock-agent",
    "/usr/local/sbin/yougori-upgrade-root",
    "/etc/init.d/opendock-agent",
    "/etc/init.d/containerd",
    "/etc/containerd/config.toml",
    "/etc/sysctl.d/90-yougori-security.conf",
)


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
    source = (rootfs / "usr/share/mkinitfs/initramfs-init").read_text()
    output.write_text(patch_init(source))
    features = rootfs / "etc/mkinitfs/features.d"
    features.mkdir(parents=True, exist_ok=True)
    (features / "yougori-security.files").write_text("\n".join(PAYLOAD_FILES) + "\n")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: prepare-appliance-initramfs.py <rootfs> <patched-init>")
    prepare(Path(sys.argv[1]), Path(sys.argv[2]))
