"""Helpers for scripts/build-guest.sh, the minimal pinned sandbox guest build (VM-W05).

Run with `python3 -I guest_build.py <command> ...`:

  release <bzImage>                       print the kernel release from the setup header
  ikconfig <configs.ko[.gz]> <output>     extract the kernel configuration (IKCONFIG=m)
  resolve <modules-dir> <modules.list>    print the module files to load, dependencies first
  artifacts <arguments>                   write artifacts.json (see `artifacts --help`)

Standard library only; reads local files only.
"""

import argparse
import gzip
import hashlib
import json
import os
import re
import sys


def fail(message):
    print(f"guest_build: {message}", file=sys.stderr)
    sys.exit(1)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


CONTENT_KEY_DOMAIN = b"yougori/content/v1"


def link_protocol(wire_go):
    """The link protocol version the agent speaks: its ProtocolVersion constant."""
    with open(wire_go, encoding="utf-8") as source:
        match = re.search(r"^\s*ProtocolVersion uint8 = (\d+)$", source.read(), re.M)
    if match is None:
        raise SystemExit(f"no ProtocolVersion in {wire_go}")
    return int(match.group(1))


def content_key_file(path):
    """foundation::ids ContentKey::of: SHA-256 over the length-prefixed domain and the
    length-prefixed bytes, as hexadecimal."""
    digest = hashlib.sha256()
    digest.update(len(CONTENT_KEY_DOMAIN).to_bytes(8, "big") + CONTENT_KEY_DOMAIN)
    digest.update(os.path.getsize(path).to_bytes(8, "big"))
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def kernel_version(path):
    """The full version string of an x86 bzImage (boot protocol 2.00+ kernel_version)."""
    with open(path, "rb") as handle:
        data = handle.read(1 << 16)
    if data[0x202:0x206] != b"HdrS":
        fail(f"{path} is not a bzImage")
    offset = int.from_bytes(data[0x20E:0x210], "little") + 0x200
    end = data.find(b"\0", offset)
    if offset <= 0x200 or end < 0:
        fail(f"{path} carries no kernel version string")
    return data[offset:end].decode("ascii")


def command_release(arguments):
    print(kernel_version(arguments.kernel).split(" ")[0])


def command_ikconfig(arguments):
    with open(arguments.module, "rb") as handle:
        data = handle.read()
    if data[:2] == b"\x1f\x8b":
        data = gzip.decompress(data)
    start = data.find(b"IKCFG_ST")
    end = data.find(b"IKCFG_ED", start + 8)
    if start < 0 or end < 0:
        fail(f"{arguments.module} holds no IKCFG markers")
    config = gzip.decompress(data[start + 8 : end])
    with open(arguments.output, "wb") as handle:
        handle.write(config)


def stem(path):
    base = os.path.basename(path)
    for suffix in (".gz", ".xz", ".zst"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
    if base.endswith(".ko"):
        base = base[:-3]
    return base.replace("-", "_")


def read_names(path):
    names = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            name = line.split("#", 1)[0].strip()
            if name:
                names.append(name)
    return names


def command_resolve(arguments):
    directory = arguments.modules_dir
    dependencies = {}
    with open(os.path.join(directory, "modules.dep"), encoding="utf-8") as handle:
        for line in handle:
            if ":" not in line:
                continue
            module, rest = line.split(":", 1)
            dependencies[module.strip()] = rest.split()
    builtin = set()
    with open(os.path.join(directory, "modules.builtin"), encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                builtin.add(stem(line.strip()))
    by_stem = {}
    for module in dependencies:
        by_stem.setdefault(stem(module), module)
    order = []

    def add(module, chain):
        if module in order:
            return
        if module in chain:
            fail(f"dependency cycle through {module}")
        if module not in dependencies:
            fail(f"{module} is not in modules.dep")
        for dependency in dependencies[module]:
            add(dependency, chain + [module])
        if not os.path.isfile(os.path.join(directory, module)):
            fail(f"{module} is listed but absent from the pinned module set")
        order.append(module)

    for name in read_names(arguments.modules_list):
        key = name.replace("-", "_")
        if key in builtin:
            print(f"guest_build: {name} is built into the kernel; skipped", file=sys.stderr)
            continue
        if key not in by_stem:
            fail(f"module {name} is not in the pinned module set")
        add(by_stem[key], [])
    for module in order:
        print(module)


def tree_digest(root, relative_dirs):
    """SHA-256 over the sorted (path, length, content) of every file under the dirs."""
    digest = hashlib.sha256()
    paths = []
    for relative in relative_dirs:
        for directory, _, files in os.walk(os.path.join(root, relative)):
            for name in files:
                paths.append(os.path.relpath(os.path.join(directory, name), root).replace(os.sep, "/"))
    for path in sorted(paths):
        with open(os.path.join(root, path), "rb") as handle:
            content = handle.read()
        digest.update(path.encode() + b"\0" + str(len(content)).encode() + b"\0" + content)
    return digest.hexdigest(), len(paths)


def command_artifacts(arguments):
    output = arguments.output_dir
    repo = arguments.repo_root
    release = arguments.release
    modules = [line.strip() for line in open(arguments.modules_load, encoding="utf-8") if line.strip()]
    agent_sha = sha256_file(arguments.agent)

    def artifact(name, role, version, source):
        path = os.path.join(output, name)
        return {"name": name, "role": role, "sha256": sha256_file(path), "content_key": content_key_file(path),
                "bytes": os.path.getsize(path), "version": version, "source": source}

    def repo_input(relative, note):
        path = os.path.join(repo, relative)
        return {"path": relative, "sha256": sha256_file(path), "bytes": os.path.getsize(path), "note": note}

    source_digest, source_files = tree_digest(os.path.join(repo, "appliance", "agent"), ["link", "cmd/yougori-sandbox-agent", "gridkit", "setupkit"])
    record = {
        "format": "yougori-guest-artifacts/v1",
        "profile": "sandbox-minimal",
        "source_date_epoch": int(arguments.epoch),
        "kernel_release": release,
        "kernel_version": kernel_version(os.path.join(output, "vmlinuz")),
        "kernel_arguments": arguments.kernel_arguments.split(" "),
        "init": "/init in the initrd is yougori-sandbox-agent (PID 1)",
        "agent_build": content_key_file(arguments.agent),
        "link_protocol": link_protocol(os.path.join(repo, "appliance", "agent", "link", "wire.go")),
        "artifacts": [
            artifact("vmlinuz", "kernel", release, "src-tauri/resources/runtime/appliance/vmlinuz-virt, pinned in src-tauri/resources/runtime/SHA256SUMS, copied unchanged"),
            artifact("initrd", "initrd", f"agent {agent_sha[:16]}, modules {' '.join(stem(m) for m in modules)}",
                     "built: newc cpio (sorted, owner 0:0, mtime SOURCE_DATE_EPOCH, renumbered inodes) of the layout in guest/README.md, gzip -n -9"),
            artifact("root.img", "root_image", "alpine-minirootfs 3.24.1 plus the sandbox user 1000:1000",
                     "built: build/appliance-cache/alpine-minirootfs-3.24.1-x86_64.tar.gz as squashfs (xz, all-root, all-time SOURCE_DATE_EPOCH, no xattrs, 4 KiB padded); attach read-only as a raw drive"),
            artifact(f"config-{release}", "kernel_configuration", release, "the kernel's own IKCONFIG, from kernel/kernel/configs.ko.gz in the module set of src-tauri/resources/runtime/appliance/appliance-base.qcow2"),
            artifact("yougori-sandbox-agent", "agent", "go: " + arguments.go_version,
                     "built: appliance/agent/cmd/yougori-sandbox-agent, CGO_ENABLED=0 GOOS=linux GOARCH=amd64 -trimpath -buildvcs=false -ldflags='-s -w -buildid='; identical to /init; its content key is the agent build the guest's Hello carries (guest_image AgentFeatures::build)"),
        ],
        "modules": [
            {"path": module, "sha256": sha256_file(os.path.join(arguments.modules_dir, module)), "bytes": os.path.getsize(os.path.join(arguments.modules_dir, module))}
            for module in modules
        ],
        "inputs": [
            repo_input("src-tauri/resources/runtime/appliance/vmlinuz-virt", "kernel"),
            repo_input("src-tauri/resources/runtime/appliance/appliance-base.qcow2", "module set and kernel configuration"),
            repo_input("src-tauri/resources/runtime/SHA256SUMS", "pins the two above"),
            repo_input("build/appliance-cache/alpine-minirootfs-3.24.1-x86_64.tar.gz", "root filesystem"),
            repo_input("build/appliance-cache/alpine-minirootfs-3.24.1-x86_64.tar.gz.checksum", "pins the root filesystem"),
            repo_input("guest/modules.list", "module names"),
            repo_input("guest/guest_build.py", "this helper"),
            repo_input("scripts/build-guest.sh", "the build"),
            repo_input("appliance/agent/go.mod", "agent module"),
            repo_input("appliance/agent/go.sum", "agent module sums"),
            {"path": "appliance/agent/{link,cmd/yougori-sandbox-agent,gridkit,setupkit}", "sha256": source_digest, "files": source_files,
             "note": "agent sources: SHA-256 over sorted path, length and content"},
        ],
        "toolchain": [line.rstrip("\n") for line in open(arguments.toolchain, encoding="utf-8") if line.strip()],
        "commands": [line.rstrip("\n") for line in open(arguments.commands, encoding="utf-8") if line.strip()],
    }
    with open(arguments.json, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(record, handle, indent=2, sort_keys=False)
        handle.write("\n")


# The initrd's device nodes, which the builder needs no privilege to make: PID 1's standard
# descriptors open /dev/console, and the agent's FUSE library opens /dev/null as it starts,
# both before the agent mounts devtmpfs over /dev. (name, mode, rdev major, rdev minor)
DEVICE_NODES = (("dev/console", 0o020600, 5, 1), ("dev/null", 0o020666, 1, 3))


def newc_entry(ino, name, mode, mtime, rdev_major=0, rdev_minor=0):
    """One newc cpio header and name, padded to four bytes; device nodes carry no data."""
    encoded = name.encode("ascii") + b"\0"
    fields = (ino, mode, 0, 0, 1, mtime, 0, 0, 0, rdev_major, rdev_minor, len(encoded), 0)
    header = b"070701" + b"".join(b"%08X" % value for value in fields) + encoded
    return header + b"\0" * (-len(header) % 4)


def command_devices(arguments):
    """Writes a newc cpio archive of DEVICE_NODES to stdout, owned by 0:0 at the epoch. The
    kernel unpacks it after the main archive, which already holds dev/."""
    mtime = int(arguments.epoch)
    archive = b"".join(newc_entry(index + 1, name, mode, mtime, major, minor)
                       for index, (name, mode, major, minor) in enumerate(DEVICE_NODES))
    archive += newc_entry(0, "TRAILER!!!", 0, 0)
    archive += b"\0" * (-len(archive) % 512)
    sys.stdout.buffer.write(archive)


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    release = commands.add_parser("release")
    release.add_argument("kernel")
    release.set_defaults(run=command_release)
    ikconfig = commands.add_parser("ikconfig")
    ikconfig.add_argument("module")
    ikconfig.add_argument("output")
    ikconfig.set_defaults(run=command_ikconfig)
    resolve = commands.add_parser("resolve")
    resolve.add_argument("modules_dir")
    resolve.add_argument("modules_list")
    resolve.set_defaults(run=command_resolve)
    devices = commands.add_parser("devices")
    devices.add_argument("epoch")
    devices.set_defaults(run=command_devices)
    artifacts = commands.add_parser("artifacts")
    for name in ("--output-dir", "--repo-root", "--release", "--epoch", "--kernel-arguments", "--modules-load",
                 "--modules-dir", "--agent", "--go-version", "--toolchain", "--commands", "--json"):
        artifacts.add_argument(name, required=True)
    artifacts.set_defaults(run=command_artifacts)
    arguments = parser.parse_args()
    arguments.run(arguments)


if __name__ == "__main__":
    main()
