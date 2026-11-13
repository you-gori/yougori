"""Publisher-only OCI packaging with Buildah on Linux. No Docker daemon.

Run in a disposable Linux build machine/WSL build distro, before user accounts
or projects are attached. Downloaded harnesses require only Yougori, not Buildah.

  build-vm-images.py NAME... --output DIR [--split-tools] [--reuse-tools] [--draft]
      Each harness's own image (Containerfile) in DIR/NAME, for launchers from before the
      Yougori harness.

  build-vm-images.py yougori --output DIR --binary PATH [--reuse-tools | --rebuild NAME...|all]
      The Yougori harness's images (Containerfile.yougori) in DIR/yougori, laid out as the website
      serves them (harness_download): the base image in each variant the harnesses need
      (<sha>.zip), one pack per harness (<sha>.tar.gz, its engine: tool/ and source/), and
      image.json listing them; build.json beside them records sizes, what each pack was built from
      and where it came from. It records each pack as soon as the pack is in the output, so a build
      that stops partway keeps the packs it made. A pack is built from its pins, its build OS (the
      stage's layers) and the pack stage: its instructions and the files it copies in that the
      harness's install reads (installer.py for every harness, a kind's own helper and adapter
      sources for that kind alone: KIND_FILES). One built from all the same is kept from this
      output. Otherwise a harness's own image (localhost/inference-solver-vm-NAME) built with the
      same pins on the same OS from the same installer files gives its pack, as the per-harness
      Containerfile installs a harness as the pack stage does, unless this output's last pack for
      the harness came from another pack stage. Any other pack is built. --rebuild builds the
      named packs (all: every pack) whatever was built before. --reuse-tools refreshes only the
      bases (runtime Python and the harness binary) and never builds a pack. PATH is
      yougori-harness built for Linux x86-64 (in the Yougori-Release-Build distro).
"""
import argparse
import datetime
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

ROOT = Path(__file__).resolve().parents[1] / "site/harnesses"
YOUGORI = "yougori"
# What Yougori imports (src-tauri/src/sandbox_vm/engine/images.rs): the compressed image, each
# expanded layer, its entries and files, and the largest root an image can have.
IMAGE_BYTES = 256 << 20
IMAGE_EXPANDED = 2 << 30
IMAGE_ENTRIES = 8000
IMAGE_FILE = 1 << 30
ROOT_GB = 8
# What the launcher downloads (vm_host) and the VM unpacks (vm_package) as a pack.
PACK_BYTES = 512 << 20
PACK_EXPANDED = 1400 << 20
PACK_ENTRIES = 100000
# Yougori keeps an image's root in the VM's memory, a page at least per entry. Beside the base and
# its pack, a harness's VM keeps this much root for its home: sessions, logs, databases.
PAGE = 4096
HEADROOM = 512 << 20
# Today's root and memory for a harness's VM (packages.json yougori.memory names larger ones).
DISK_GB = 2
MEMORY_GB = 4
# The base image's variants and the Containerfile.yougori stage each starts from.
VARIANTS = {"base": "os", "postgres": "os-postgres", "chromium": "os-chromium"}
# Shannon's pack carries Chromium's own folder from the same installation as the chromium variant.
PACK_STAGE = {"chromium": "os-chromium"}
# The pack stage's files that only one kind of harness's install reads (packages.json "kind"):
# installer.py imports a kind's helper only for that kind, and the helper copies in its adapter.
# Every other file the stage copies is read by every harness's install.
KIND_FILES = {"shannon": {"install_shannon.py"}, "pentagi": {"install_pentagi.py", "pentagi_vm.go", "pentagi_vm_test.go"}}


def normalize_layout(folder):
    # Older Buildah omits optional OCI document mediaType/platform fields.
    # Yougori deliberately requires these; normalize and rehash before publishing.
    index = json.loads((folder / "index.json").read_text())
    index["mediaType"] = "application/vnd.oci.image.index.v1+json"
    for descriptor in index["manifests"]:
        old = folder / "blobs/sha256" / descriptor["digest"].split(":")[1]
        manifest = json.loads(old.read_text())
        manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
        raw = json.dumps(manifest, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw).hexdigest()
        (folder / "blobs/sha256" / digest).write_bytes(raw)
        descriptor.update(digest="sha256:" + digest, size=len(raw), platform={"os": "linux", "architecture": "amd64"})
        if old.name != digest:
            old.unlink()
    (folder / "index.json").write_text(json.dumps(index, separators=(",", ":")))


class Metered(io.RawIOBase):
    """A readable stream that counts what is read through it."""
    def __init__(self, stream):
        self.stream = stream
        self.bytes = 0

    def readable(self):
        return True

    def readinto(self, buffer):
        data = self.stream.read(len(buffer))
        buffer[:len(data)] = data
        self.bytes += len(data)
        return len(data)


def layout_size(folder, name):
    """Checks an OCI layout against what Yougori imports. Returns its compressed bytes, expanded
    bytes, entries and file bytes (its root needs file bytes and a page per entry)."""
    blobs = folder / "blobs/sha256"
    compressed = sum(path.stat().st_size for path in blobs.iterdir())
    if compressed > IMAGE_BYTES:
        raise ValueError(f"{name} exceeds Yougori's 256 MiB image bound ({compressed / 2**20:.1f} MiB); it was not published.")
    index = json.loads((folder / "index.json").read_text())
    manifest = json.loads((blobs / index["manifests"][0]["digest"].split(":")[1]).read_text())
    expanded = entries = files = 0
    for layer in manifest["layers"]:
        layer_entries = 0
        with gzip.open(blobs / layer["digest"].split(":")[1]) as stream:
            metered = Metered(stream)
            with tarfile.open(fileobj=metered, mode="r|") as archive:
                for member in archive:
                    layer_entries += 1
                    if member.isfile():
                        files += member.size
                        if member.size > IMAGE_FILE:
                            raise ValueError(f"{name} holds {member.name}, larger than Yougori's 1 GiB file bound.")
            while metered.read(1 << 20):
                pass
        expanded += metered.bytes
        entries += layer_entries
        if metered.bytes > IMAGE_EXPANDED or layer_entries > IMAGE_ENTRIES:
            raise ValueError(f"{name} has a layer beyond Yougori's 2 GiB and 8,000 entry bounds.")
    if expanded > IMAGE_EXPANDED or entries > IMAGE_ENTRIES:
        raise ValueError(f"{name} exceeds Yougori's 2 GiB and 8,000 entry image bounds ({expanded / 2**20:.1f} MiB, {entries} entries).")
    return {"compressed": compressed, "expanded": expanded, "entries": entries, "files": files}


def package_image(flat, temp, destination, name):
    """Pushes the squashed image `flat` as an OCI layout, checks it against Yougori's import bounds
    and stores it zipped as DESTINATION/<sha256>.zip. Returns its digest, size and measures."""
    layout = Path(temp) / "flat"
    shutil.rmtree(layout, ignore_errors=True)
    subprocess.run(["buildah", "push", "--format", "oci", flat, "oci:" + str(layout) + ":latest"], check=True)
    normalize_layout(layout)
    measured = layout_size(layout, name)
    archive = Path(temp) / "image.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as package:
        for path in sorted(layout.rglob("*")):
            if path.is_file():
                package.write(path, path.relative_to(layout).as_posix())
    shutil.rmtree(layout)
    with archive.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    destination.mkdir(parents=True, exist_ok=True)
    archive.replace(destination / (digest + ".zip"))
    return {"sha256": digest, "bytes": (destination / (digest + ".zip")).stat().st_size, **measured}


def harness_image(args, specs, name):
    """One harness's own image, for launchers from before the Yougori harness."""
    if name == YOUGORI:
        raise ValueError("The Yougori harness has no image of its own: build-vm-images.py yougori --output DIR --binary PATH")
    if name not in specs or (specs[name].get("blocked") and not args.draft) or not specs[name].get("kind"):
        raise ValueError("Choose an implemented harness.")
    spec = {k:v for k,v in specs[name].items() if k != "blocked"}
    tag = "localhost/inference-solver-vm-" + name
    if args.reuse_tools:
        prior=json.loads(subprocess.check_output(['buildah','inspect','--type','image',tag],text=True))
        env=prior['OCIv1']['config']['Env']
        saved=next((v.removeprefix('TOOL_SPEC=') for v in env if v.startswith('TOOL_SPEC=')),None)
        if not saved or json.loads(saved)!=spec: raise ValueError('Existing tool image has different pins; run a full build.')
    else:
        subprocess.run(["buildah", "bud", "--isolation", "oci", "--layers", "--force-rm", "--format", "oci",
            "--build-arg", "HARNESS=" + name, "--build-arg", "TOOL_SPEC=" + json.dumps(spec), "-f", str(ROOT / "Containerfile"), "-t", tag, str(ROOT)], check=True)
    with tempfile.TemporaryDirectory(prefix="solver-oci-", dir=args.output) as temp:
        # Flatten build layers with Buildah's commit --squash before publication;
        # discarded dependency trees must not occupy the runtime/import budget.
        container = subprocess.check_output(["buildah", "from", tag], text=True).strip()
        tool = None
        try:
            if args.reuse_tools:
                runtime=('relay.py','transport.py','blue.py','profiles.py','runtime.py','vm_guest.py','vm_package.py','vm_tunnel.py','hexstrike_cli.py','plandex_cli.py','strix_cli.py','shannon_cli.py','pentagi_cli.py')
                subprocess.run(['buildah','copy',container,*[str(ROOT/file) for file in runtime],'/opt/solver/'],check=True)
            if args.split_tools:
                mounted=Path(subprocess.check_output(['buildah','mount',container],text=True).strip())
                if name == 'shannon':
                    # Headless Chromium needs fonts/libraries, not desktop
                    # icon and MIME catalogs (thousands of OCI entries).
                    for relative in ('usr/share/icons','usr/share/mime','var/lib/dpkg','usr/share/perl','usr/share/perl5'):
                        unused=mounted/relative
                        if unused.is_symlink(): unused.unlink()
                        elif unused.exists(): shutil.rmtree(unused)
                source=mounted/'opt/solver/tool.tar.gz'
                with source.open('rb') as stream: tool_hash=hashlib.file_digest(stream,'sha256').hexdigest()
                tool={'sha256':tool_hash,'bytes':source.stat().st_size}
                if not 0<tool['bytes']<=PACK_BYTES: raise ValueError('Tool package exceeds 512 MiB.')
                destination=args.output/name;destination.mkdir(exist_ok=True)
                shutil.copyfile(source,destination/(tool_hash+'.tar.gz'))
                source.unlink()
                (mounted/'opt/solver/tool-package.json').write_text(json.dumps(tool))
                subprocess.run(['buildah','unmount',container],check=True)
            subprocess.run(["buildah", "commit", "--squash", "--format", "oci", container, tag + "-flat"], check=True)
        finally:
            subprocess.run(["buildah", "rm", container], check=True)
        destination = args.output / name
        image = package_image(tag + "-flat", temp, destination, name)
        record = {"sha256": image["sha256"], "bytes": image["bytes"],
                  "version": specs[name]["version"], "platform": "linux/amd64", "runtime": "yougori-sandbox-vm"}
        if tool: record['tool']=tool
        temporary = destination / "image.json.partial"
        temporary.write_text(json.dumps(record, indent=2))
        temporary.replace(destination / "image.json")
        print("Prepared " + name + " for Yougori Sandbox VM", flush=True)


# The Yougori harness's images.

def inspect(image):
    """Buildah's view of a local image, or None when there is no such image."""
    found = subprocess.run(["buildah", "inspect", "--type", "image", image], capture_output=True, text=True)
    return json.loads(found.stdout) if found.returncode == 0 else None


def layers(image):
    return (inspect(image) or {}).get("OCIv1", {}).get("rootfs", {}).get("diff_ids", [])


def pins(image):
    """The tool pins (TOOL_SPEC) an image's pack was installed with, or None."""
    env = (inspect(image) or {}).get("OCIv1", {}).get("config", {}).get("Env") or []
    saved = next((value.removeprefix("TOOL_SPEC=") for value in env if value.startswith("TOOL_SPEC=")), None)
    try:
        return json.loads(saved) if saved else None
    except ValueError:
        return None


def build(target, tag, arguments, context=None):
    """Builds a Containerfile.yougori stage with Buildah's layer cache, so stages that did not
    change are the same layers each time. --force-rm: Buildah 1.33 otherwise leaves a working
    container behind for the node stage (FROM alone) on every build."""
    command = ["buildah", "bud", "--isolation", "oci", "--layers", "--force-rm", "--format", "oci", "--target", target]
    for name, value in arguments.items():
        command += ["--build-arg", name + "=" + value]
    if context:
        command += ["--build-context", "harness=" + str(context)]
    subprocess.run([*command, "-f", str(ROOT / "Containerfile.yougori"), "-t", tag, str(ROOT)], check=True)


def stage_layers(stage):
    """The layers of a Containerfile.yougori OS stage: a pack and the base variant it runs on must
    start from the same ones."""
    tag = "localhost/yougori-vm-stage-" + stage
    build(stage, tag, {})
    found = layers(tag)
    if not found:
        raise ValueError("Buildah did not keep the " + stage + " stage.")
    return found


def digest_of(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def stage_instructions(root, name):
    """A Containerfile.yougori stage's instructions, its FROM first, comments and layout aside."""
    instructions, current = [], []
    for line in (root / "Containerfile.yougori").read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continued = stripped.endswith("\\")
        current.append(stripped[:-1] if continued else stripped)
        if not continued:
            instructions.append(" ".join(" ".join(current).split()))
            current = []
    if current:
        instructions.append(" ".join(" ".join(current).split()))
    starts = [index for index, instruction in enumerate(instructions) if instruction.split()[0].upper() == "FROM"]
    first = next((index for index in starts if re.fullmatch(r"FROM \S+ AS " + re.escape(name), instructions[index], re.IGNORECASE)), None)
    if first is None:
        raise ValueError("Containerfile.yougori has no " + name + " stage.")
    return instructions[first:next((index for index in starts if index > first), len(instructions))]


def pack_stage(root=None):
    """What Containerfile.yougori's pack stage builds a pack from besides its pins and build OS:
    the stage's instructions (comments and layout aside) and the build-context files they copy in
    (the installer and the adapter sources), each by sha256. Returns {"containerfile", "files"}."""
    root = root or ROOT
    stage = stage_instructions(root, "pack")
    files = {}
    for instruction in stage[1:]:
        word, _, rest = instruction.partition(" ")
        if word.upper() not in ("COPY", "ADD"):
            continue
        arguments = json.loads(rest) if rest.startswith("[") else rest.split()
        if any(argument.startswith("--from=") for argument in arguments):
            continue  # Another stage's files, built from what that stage's layers already show.
        for source in [argument for argument in arguments if not argument.startswith("--")][:-1]:
            if "://" in source or PurePosixPath(source).is_absolute() or ".." in PurePosixPath(source).parts:
                raise ValueError("The pack stage may copy only files of its build context, not " + source + ".")
            found = sorted(root.glob(source)) if any(mark in source for mark in "*?[") else [root / source]
            paths = [file for path in found for file in (sorted(path.rglob("*")) if path.is_dir() else [path])]
            if not found or any(not path.exists() for path in paths):
                raise ValueError("The pack stage copies " + source + ", which its build context does not have.")
            for path in paths:
                if path.is_file():
                    files[path.relative_to(root).as_posix()] = digest_of(path)
    return {"containerfile": hashlib.sha256("\n".join(stage).encode()).hexdigest(), "files": files}


def pack_inputs(stage, kind):
    """What one kind of harness's pack is built from in the pack stage (`stage`, pack_stage): its
    instructions and the files it copies in but those only other kinds' installs read (KIND_FILES).
    A fix to one kind's helper or adapter changes that kind's packs; one to installer.py, or to the
    stage's instructions, changes every pack."""
    others = {file for owner, files in KIND_FILES.items() if owner != kind for file in files}
    return {"containerfile": stage["containerfile"],
            "files": {file: digest for file, digest in stage["files"].items() if file not in others}}


def same_installer(image, files):
    """Whether a harness's own image holds these installer and adapter files (name -> sha256) where
    it installed its harness from them (/opt/solver, as the pack stage does)."""
    container = subprocess.check_output(["buildah", "from", "--pull=never", image], text=True).strip()
    try:
        mounted = Path(subprocess.check_output(["buildah", "mount", container], text=True).strip()).resolve()
        folder = mounted / "opt/solver"
        if folder.resolve() != folder:
            return False
        for name, digest in files.items():
            path = folder / PurePosixPath(name).name
            if path.is_symlink() or not path.is_file() or digest_of(path) != digest:
                return False
        return True
    finally:
        subprocess.run(["buildah", "umount", container], check=False, capture_output=True)
        subprocess.run(["buildah", "rm", container], check=True, capture_output=True)


def check_pack(path):
    """A pack (tool archive) as the VM takes it (vm_package): within the launcher's download bound
    and the VM's extraction budget, holding only tool/ and source/ with no special files, path
    escapes or links leaving /opt/solver. Returns its digest and measures."""
    size = path.stat().st_size
    if not 0 < size <= PACK_BYTES:
        raise ValueError(f"{path.name} exceeds the 512 MiB pack bound.")
    with path.open("rb") as stream:
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
    entries = unpacked = 0
    with tarfile.open(path) as archive:
        for member in archive:
            parts = PurePosixPath(member.name).parts
            if (not parts or parts[0] not in ("tool", "source") or ".." in parts
                    or not (member.isfile() or member.isdir() or member.issym() or member.islnk())):
                raise ValueError("Invalid pack entry " + member.name[:200] + ".")
            tarfile.data_filter(member, "/opt/solver")
            entries += 1
            unpacked += member.size
    if unpacked > PACK_EXPANDED or entries > PACK_ENTRIES:
        raise ValueError(f"{path.name} exceeds the VM's 1,400 MiB and 100,000 entry pack budget.")
    return {"sha256": digest, "bytes": size, "entries": entries, "unpacked": unpacked}


def take_pack(image, folder):
    """Copies the pack an image built (/opt/solver/tool.tar.gz) into the output, checked."""
    container = subprocess.check_output(["buildah", "from", "--pull=never", image], text=True).strip()
    partial = folder / "pack.partial"
    try:
        mounted = Path(subprocess.check_output(["buildah", "mount", container], text=True).strip())
        shutil.copyfile(mounted / "opt/solver/tool.tar.gz", partial)
        measured = check_pack(partial)
        partial.replace(folder / (measured["sha256"] + ".tar.gz"))
        return measured
    finally:
        partial.unlink(missing_ok=True)
        subprocess.run(["buildah", "umount", container], check=False, capture_output=True)
        subprocess.run(["buildah", "rm", container], check=True, capture_output=True)


def reuse_pack(name, spec, base_layers, inputs, folder, previous):
    """A pack already built from what this build builds it from: its pins, its build OS (the
    stage's layers) and the pack stage (`inputs`, pack_inputs). One in this output (build.json) is
    kept. Otherwise the harness's own image gave the same pack when it was built with these pins
    on this OS from these installer files, unless this output's last pack for the harness came
    from another pack stage. Returns its measures, where it was first made and how it was found,
    or None: it has to be built."""
    packs = previous.get("packs") if isinstance(previous, dict) else None
    known = packs.get(name) if isinstance(packs, dict) else None
    known = known if isinstance(known, dict) else {}
    if (known.get("pins") == spec and known.get("from") == base_layers and known.get("inputs") == inputs
            and re.fullmatch(r"[a-f0-9]{64}", str(known.get("sha256", "")))):
        path = folder / (known["sha256"] + ".tar.gz")
        if path.is_file() and path.stat().st_size == known.get("bytes"):
            measured = check_pack(path)
            if measured["sha256"] == known["sha256"]:
                return measured, str(known.get("origin", "")), "kept"
    recorded = known.get("inputs")
    if isinstance(recorded, dict) and recorded.get("containerfile") != inputs["containerfile"]:
        return None
    image = "localhost/inference-solver-vm-" + name
    if pins(image) == spec and layers(image)[:len(base_layers)] == base_layers and same_installer(image, inputs["files"]):
        return take_pack(image, folder), image, "reused"
    return None


def make_packs(harnesses, specs, variant_of, base_layers, inputs, folder, previous, rebuild, reuse_tools):
    """Each harness's pack in the output, with what it was built from (its build.json record):
    kept or reused when reuse_pack finds one and `rebuild` does not name the harness, built
    otherwise. With `reuse_tools` nothing is built: a pack that has to be is refused. `inputs` is
    the pack stage (pack_stage); each pack is known by the part its install reads (pack_inputs).
    Each pack's record goes into build.json, written whole, as soon as the pack is in the output:
    a build that stops partway keeps the packs it made, and the next one keeps them. The rest of
    build.json is written when the build finishes."""
    packs = {}
    known = previous.get("packs") if isinstance(previous, dict) else None
    progress = {**(previous if isinstance(previous, dict) else {}), "packs": dict(known) if isinstance(known, dict) else {}}
    for name in harnesses:
        clock = time.monotonic()
        spec = {key: value for key, value in specs[name].items() if key != "blocked"}
        stage = PACK_STAGE.get(variant_of.get(name), "os")
        own = pack_inputs(inputs, spec.get("kind"))
        found = None if name in rebuild else reuse_pack(name, spec, base_layers[stage], own, folder, previous)
        if found is None:
            if reuse_tools:
                raise ValueError(name + "'s pack has to be built again (its pins, build OS, installer files or the pack stage "
                                 "changed since): run a full build (without --reuse-tools).")
            found = build_pack(name, spec, stage, base_layers[stage], folder)
        measured, origin, how = found
        packs[name] = {**measured, "pins": spec, "from": base_layers[stage], "inputs": own, "origin": origin, "how": how,
                       "seconds": round(time.monotonic() - clock, 1)}
        progress["packs"][name] = packs[name]
        write_json(folder / "build.json", progress)
        print(f"Pack {name}: {measured['bytes'] / 2**20:.1f} MiB, {measured['unpacked'] / 2**20:.1f} MiB unpacked, "
              f"{measured['entries']} entries ({how}, made in {origin})", flush=True)
    return packs


def build_pack(name, spec, stage, base_layers, folder):
    """Builds a harness's pack with today's installer on its build OS (Containerfile.yougori pack)."""
    tag = "localhost/yougori-pack-" + name
    build("pack", tag, {"PACK_FROM": stage, "HARNESS": name, "TOOL_SPEC": json.dumps(spec)})
    try:
        if layers(tag)[:len(base_layers)] != base_layers:
            raise ValueError(name + "'s pack was not built on the " + stage + " stage.")
        return take_pack(tag, folder), tag, "built"
    finally:
        # The pack is in the output now, which is where a later build reuses it from.
        subprocess.run(["buildah", "rmi", tag], check=False, capture_output=True)


def check_binary(path, version):
    """The Yougori harness binary: a Linux x86-64 executable of this version. Returns its record."""
    raw = path.read_bytes()
    # ELF, 64-bit, little-endian, machine x86-64 (62).
    if raw[:4] != b"\x7fELF" or raw[4] != 2 or raw[5] != 1 or int.from_bytes(raw[18:20], "little") != 62:
        raise ValueError(str(path) + " is not a Linux x86-64 executable. Build yougori-harness in the Yougori-Release-Build distro.")
    with tempfile.TemporaryDirectory(prefix="yougori-harness-check-") as temp:
        probe = Path(temp) / "yougori-harness"
        probe.write_bytes(raw)
        probe.chmod(0o755)
        said = subprocess.run([str(probe), "--version"], capture_output=True, text=True, timeout=30, stdin=subprocess.DEVNULL)
    if said.returncode or said.stdout.strip() != "yougori-harness " + version:
        raise ValueError(f"{path} reports {said.stdout.strip()[:80]!r}, not yougori-harness {version}.")
    return {"sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw), "version": version}


def plan(version, specs, variant_of, bases, packs, memory):
    """image.json for these measured bases and packs. A harness's VM root holds its base's files and
    its pack's, a page at least per entry, and room for its home; a base is imported once, with the
    root its largest harness needs, and each harness's VM has memory for that root (`memory` names
    harnesses that need more than 4 GB)."""
    def gigabytes(need):
        return max(DISK_GB, math.ceil(need / (1 << 30)))
    root = {variant: base["files"] + base["entries"] * PAGE for variant, base in bases.items()}
    disk = {name: gigabytes(root[variant_of.get(name, "base")] + pack["unpacked"] + pack["entries"] * PAGE + HEADROOM)
            for name, pack in packs.items()}
    disk[YOUGORI] = gigabytes(root["base"] + HEADROOM)
    base_disk = {variant: max(size for name, size in disk.items() if variant_of.get(name, "base") == variant) for variant in bases}
    if max(base_disk.values()) > ROOT_GB:
        raise ValueError("A harness needs more than Yougori's 8 GB image root.")
    sizes = {name: max(memory.get(name, MEMORY_GB), base_disk[variant_of.get(name, "base")] + 1) for name in disk}
    return {"runtime": "yougori-sandbox-vm", "platform": "linux/amd64", "version": version,
            "bases": {variant: {"sha256": base["sha256"], "bytes": base["bytes"], "disk": base_disk[variant]}
                      for variant, base in bases.items()},
            "packs": {YOUGORI: {"base": "base", "disk": disk[YOUGORI], "memory": sizes[YOUGORI]},
                      **{name: {"sha256": pack["sha256"], "bytes": pack["bytes"], "version": specs[name]["version"],
                                "base": variant_of.get(name, "base"), "disk": disk[name], "memory": sizes[name]}
                         for name, pack in packs.items()}}}


def server_check(image):
    """The website's own check of image.json (harness_download.yougori_image)."""
    sys.path.insert(0, str(ROOT.parent))
    try:
        import harness_download
    finally:
        sys.path.pop(0)
    harness_download.yougori_image(image)


def write_json(path, value):
    """Writes a record whole or not at all: a build that stops while writing leaves the last one."""
    temporary = path.with_name(path.name + ".partial")
    try:
        with temporary.open("w", encoding="utf-8") as stream:
            stream.write(json.dumps(value, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def yougori_images(args, specs):
    started = time.monotonic()
    entry = specs[YOUGORI]
    version = entry["version"]
    harnesses = [name for name, spec in specs.items() if name != YOUGORI and not spec.get("blocked")]
    rebuild = set(harnesses) if "all" in args.rebuild else set(args.rebuild)
    if rebuild - set(harnesses):
        raise ValueError("--rebuild names no pack built here: " + ", ".join(sorted(rebuild - set(harnesses))) + ".")
    binary = check_binary(args.binary, version)
    folder = args.output / YOUGORI
    folder.mkdir(parents=True, exist_ok=True)
    try:
        previous = json.loads((folder / "build.json").read_text())
    except (OSError, ValueError):
        previous = {}
    if not isinstance(previous, dict):
        previous = {}
    variant_of = {}
    for variant, names in entry.get("bases", {}).items():
        if variant not in VARIANTS or variant == "base":
            raise ValueError("packages.json names an unknown base variant " + variant + ".")
        for name in names:
            if name not in specs or name == YOUGORI:
                raise ValueError("packages.json gives a base variant to an unknown harness " + name + ".")
            variant_of[name] = variant
    used = {"base"} | {variant_of.get(name, "base") for name in harnesses}
    stages = {VARIANTS[variant] for variant in used} | {PACK_STAGE.get(variant_of.get(name), "os") for name in harnesses}
    base_layers = {stage: stage_layers(stage) for stage in sorted(stages)}
    packs = make_packs(harnesses, specs, variant_of, base_layers, pack_stage(), folder, previous, rebuild, args.reuse_tools)

    bases = {}
    with tempfile.TemporaryDirectory(prefix="yougori-oci-", dir=args.output) as temp:
        context = Path(temp) / "harness"
        context.mkdir()
        shutil.copyfile(args.binary, context / "yougori-harness")
        (context / "yougori-harness").chmod(0o755)
        for variant, stage in VARIANTS.items():
            if variant not in used:
                continue
            clock = time.monotonic()
            tag = "localhost/yougori-vm-" + variant
            build("runtime", tag, {"VARIANT": stage}, context)
            if layers(tag)[:len(base_layers[stage])] != base_layers[stage]:
                raise ValueError("The " + variant + " base was not built on the " + stage + " stage its packs were built on.")
            container = subprocess.check_output(["buildah", "from", "--pull=never", tag], text=True).strip()
            try:
                subprocess.run(["buildah", "commit", "--squash", "--format", "oci", container, tag + "-flat"], check=True)
            finally:
                subprocess.run(["buildah", "rm", container], check=True, capture_output=True)
            try:
                measured = package_image(tag + "-flat", temp, folder, "The " + variant + " base")
            finally:
                # The squashed copy is only for publishing; the zip holds it now.
                subprocess.run(["buildah", "rmi", tag + "-flat"], check=False, capture_output=True)
            bases[variant] = {**measured, "stage": stage, "seconds": round(time.monotonic() - clock, 1)}
            print(f"Base {variant}: {measured['bytes'] / 2**20:.1f} MiB, {measured['expanded'] / 2**20:.1f} MiB expanded, "
                  f"{measured['entries']} entries", flush=True)

    image = plan(version, specs, variant_of, bases, packs, entry.get("memory", {}))
    server_check(image)
    record = {"version": version, "built": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
              "seconds": round(time.monotonic() - started, 1), "binary": binary, "bases": bases, "packs": packs}
    write_json(folder / "build.json", record)
    write_json(folder / "image.json", image)
    # The website serves only the files image.json lists; earlier builds' others go.
    listed = {item["sha256"] for item in [*image["bases"].values(), *image["packs"].values()] if "sha256" in item}
    for path in folder.iterdir():
        digest, _, suffix = path.name.partition(".")
        if suffix in ("zip", "tar.gz") and len(digest) == 64 and digest not in listed:
            path.unlink()
    print(f"Prepared the Yougori harness's images in {folder} ({record['seconds']} s)", flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("names", nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--draft", action="store_true", help="Build a pinned adapter awaiting runtime validation; does not enable website downloads")
    parser.add_argument("--split-tools", action="store_true", help="Deliver a verified tool archive through the private VM control connection")
    parser.add_argument("--reuse-tools", action="store_true", help="Refresh only runtime Python from an existing same-pin image; do not use after installer or OS dependency edits")
    parser.add_argument("--binary", type=Path, help="With yougori: the yougori-harness binary built for Linux x86-64")
    parser.add_argument("--rebuild", nargs="+", action="extend", default=[], metavar="NAME",
                        help="With yougori: build these harnesses' packs again (all: every pack) instead of reusing them")
    args = parser.parse_args()
    specs = json.loads((ROOT / "packages.json").read_text())
    if YOUGORI in args.names:
        if args.names != [YOUGORI] or args.draft or args.split_tools or not args.binary:
            parser.error("Build the Yougori harness's images alone: yougori --output DIR --binary PATH "
                         "[--reuse-tools | --rebuild NAME...|all] (its packs are always split; blocked harnesses get none).")
        if args.rebuild and args.reuse_tools:
            parser.error("--rebuild builds packs, and --reuse-tools builds none: choose one.")
        args.output.mkdir(parents=True, exist_ok=True)
        return yougori_images(args, specs)
    if args.binary or args.rebuild:
        parser.error("--binary and --rebuild go with yougori.")
    args.output.mkdir(parents=True, exist_ok=True)
    for name in args.names:
        harness_image(args, specs, name)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
