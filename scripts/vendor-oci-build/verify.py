"""Verify the complete, bounded OCI payload before extracting into an empty directory."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import struct
import stat
import tarfile

RUNTIME_PATHS = {
    "bin/containerd", "bin/containerd-shim-runc-v2", "bin/nerdctl", "bin/runc",
    *(f"libexec/cni/{name}" for name in ("bridge", "firewall", "host-local", "loopback", "portmap", "tuning")),
}
MAX_ARCHIVE = 96 * 1024 * 1024
MAX_FILE = 96 * 1024 * 1024
MAX_EXPANDED = 256 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def read_regular(path, limit):
    require(not path.is_symlink(), "Linked OCI input")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= limit, "Invalid or oversized OCI input")
        data = stream.read(limit + 1)
        require(len(data) == info.st_size and len(data) <= limit, "OCI input changed while being read")
        return data


def elf_header(contents):
    require(len(contents) >= 64 and contents[:6] == b"\x7fELF\x02\x01", "OCI member is not 64-bit little-endian ELF")
    require(struct.unpack_from("<H", contents, 18)[0] == 62, "OCI member is not AMD64")
    require(struct.unpack_from("<H", contents, 16)[0] in (2, 3), "OCI member is not executable ELF")


def verify_manifest(archive_path, manifest_path, destination=None):
    archive_path, manifest_path = Path(archive_path), Path(manifest_path)
    manifest = json.loads(read_regular(manifest_path, 1024 * 1024).decode("utf-8"))
    require(type(manifest.get("schemaVersion")) is int and manifest["schemaVersion"] == 1 and
            manifest.get("target") == "linux/amd64", "Unsupported OCI manifest")
    require(manifest.get("compiler") == "go1.27.2", "OCI compiler is not the reviewed security version")
    archive_record = manifest["archive"]
    require(archive_record["file"] == "yougori-oci-runtime-linux-amd64.tar.gz", "Invalid OCI archive name")
    # Both validation and extraction consume the same bounded immutable bytes,
    # so replacing or modifying a source path cannot swap in a later archive.
    archive_bytes = read_regular(archive_path, MAX_ARCHIVE)
    require(type(archive_record["bytes"]) is int and 0 < archive_record["bytes"] <= MAX_ARCHIVE and
            len(archive_bytes) == archive_record["bytes"], "OCI archive size mismatch")
    require(hashlib.sha256(archive_bytes).hexdigest() == archive_record["sha256"], "OCI archive digest mismatch")
    files = manifest["files"]
    require(isinstance(files, list) and len(files) == len(RUNTIME_PATHS), "OCI manifest must contain exactly ten files")
    expected = {}
    for record in files:
        name = record["path"]
        require(name in RUNTIME_PATHS and name not in expected, "Unexpected or duplicate OCI path")
        require(type(record["bytes"]) is int and 0 < record["bytes"] <= MAX_FILE, "Invalid OCI member size")
        require(type(record["mode"]) is int and record["mode"] == 0o755 and
                re.fullmatch(r"[0-9a-f]{64}", record["sha256"]), "Invalid OCI member metadata")
        expected[name] = record
    require(set(expected) == RUNTIME_PATHS and sum(item["bytes"] for item in files) <= MAX_EXPANDED, "Invalid OCI expanded set")
    seen = set()
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        for member in archive:
            require(member.name in expected and member.name not in seen, "Unexpected or duplicate OCI archive member")
            require(member.type in (tarfile.REGTYPE, tarfile.AREGTYPE) and
                    not member.sparse and not member.pax_headers,
                    "OCI archive contains a non-regular or extended member")
            record = expected[member.name]
            require(member.size == record["bytes"] and member.mode == record["mode"] and member.uid == member.gid == 0,
                    "OCI member size/mode/owner mismatch")
            digest = hashlib.sha256()
            with archive.extractfile(member) as stream:
                header = stream.read(64)
                elf_header(header)
                digest.update(header)
                while block := stream.read(1024 * 1024):
                    digest.update(block)
            require(digest.hexdigest() == record["sha256"], "OCI member digest mismatch")
            seen.add(member.name)
    require(seen == RUNTIME_PATHS, "OCI archive is incomplete")
    if destination is not None:
        destination = Path(destination).absolute()
        require(destination.resolve() == destination and not destination.is_symlink(), "Linked OCI extraction directory")
        destination.mkdir(mode=0o700, parents=True, exist_ok=True)
        require(not any(destination.iterdir()), "OCI extraction directory must be empty")
        with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
            for member in archive:
                path = destination / member.name
                path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                with os.fdopen(os.open(path, flags, 0o755), "wb") as output, archive.extractfile(member) as stream:
                    while block := stream.read(1024 * 1024):
                        output.write(block)
                path.chmod(0o755)
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--destination", type=Path)
    args = parser.parse_args()
    verified = verify_manifest(args.archive, args.manifest, args.destination)
    print(json.dumps({"status": "verified", "files": len(verified["files"]), "sha256": verified["archive"]["sha256"]}))


if __name__ == "__main__":
    main()
