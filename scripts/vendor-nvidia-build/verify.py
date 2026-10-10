"""Validate the exact two-file NVIDIA CDI archive before trusted installation."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import tarfile

PATHS = {"bin/nvidia-ctk", "bin/nvidia-cdi-hook"}
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_FILE = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unique_object(rows):
    result = {}
    for key, value in rows:
        require(key not in result, "Duplicate NVIDIA manifest key")
        result[key] = value
    return result


def verify_manifest(archive_path, manifest_path):
    archive_path, manifest_path = Path(archive_path), Path(manifest_path)
    require(archive_path.is_file() and not archive_path.is_symlink(), "Missing or linked NVIDIA archive")
    require(manifest_path.is_file() and not manifest_path.is_symlink() and manifest_path.stat().st_size <= 1024 * 1024, "Missing, linked or oversized NVIDIA manifest")
    manifest = json.loads(manifest_path.read_text(), object_pairs_hook=unique_object)
    require(type(manifest.get("schemaVersion")) is int and manifest.get("schemaVersion") == 1 and manifest.get("kind") == "nvidia-cdi" and manifest.get("target") == "linux/amd64", "Unsupported NVIDIA manifest")
    require(manifest.get("compiler") == "go1.27.2", "Unreviewed NVIDIA compiler")
    record = manifest["archive"]
    require(record["file"] == "yougori-nvidia-cdi-linux-amd64.tar.gz", "Unexpected NVIDIA archive filename")
    require(type(record["bytes"]) is int and 0 < record["bytes"] <= MAX_ARCHIVE and archive_path.stat().st_size == record["bytes"], "NVIDIA archive size mismatch")
    require(re.fullmatch("[0-9a-f]{64}", record["sha256"]) and digest(archive_path) == record["sha256"], "NVIDIA archive digest mismatch")
    require(isinstance(manifest["files"], list) and len(manifest["files"]) == 2, "NVIDIA payload must contain exactly two executables")
    expected = {}
    for item in manifest["files"]:
        name = item["path"]
        require(name in PATHS and name not in expected, "Unexpected or duplicate NVIDIA path")
        require(type(item["bytes"]) is int and 64 <= item["bytes"] <= MAX_FILE and type(item["mode"]) is int and item["mode"] == 0o755, "Invalid NVIDIA member size or mode")
        require(re.fullmatch("[0-9a-f]{64}", item["sha256"]), "Invalid NVIDIA member digest")
        expected[name] = item
    require(set(expected) == PATHS and sum(row["bytes"] for row in expected.values()) <= MAX_EXPANDED, "Invalid NVIDIA expanded set")
    seen = set()
    with tarfile.open(archive_path, "r:gz") as archive:
        for member in archive:
            require(member.name in expected and member.name not in seen, "Unexpected or duplicate NVIDIA archive entry")
            require(member.isfile() and not member.islnk() and not member.issym() and not member.sparse and not member.pax_headers, "Non-regular or extended NVIDIA member")
            item = expected[member.name]
            require(member.mode == item["mode"] and member.size == item["bytes"] and member.uid == member.gid == 0, "NVIDIA member metadata mismatch")
            with archive.extractfile(member) as stream:
                header = stream.read(64)
                require(header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == 62 and struct.unpack_from("<H", header, 16)[0] in (2, 3), "NVIDIA member is not executable AMD64 ELF")
                sha = hashlib.sha256(header)
                while block := stream.read(1024 * 1024):
                    sha.update(block)
            require(sha.hexdigest() == item["sha256"], "NVIDIA member digest mismatch")
            seen.add(member.name)
    require(seen == PATHS, "Incomplete NVIDIA payload")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    result = verify_manifest(args.archive, args.manifest)
    print(json.dumps({"status": "verified", "files": 2, "sha256": result["archive"]["sha256"]}))


if __name__ == "__main__":
    main()
