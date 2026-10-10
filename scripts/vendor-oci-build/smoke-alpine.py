"""Start every rebuilt OCI executable in a fresh verified Alpine minirootfs."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import posixpath
import shutil
import subprocess
import tarfile
import uuid

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("oci_verify", HERE / "verify.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)
ALPINE_SHA256 = "41f73e3cf5fa919b8aa5ca6b30dc48f0da2720776d7423e2a7748211456fe081"


def alpine_filter(member, destination):
    # Absolute busybox aliases refer to paths inside the eventual chroot.
    # Make those links relative so Python can still enforce containment while
    # extracting without following any alias into the builder's host root.
    if member.linkname.startswith("/"):
        target = member.linkname.lstrip("/")
        if member.issym():
            target = posixpath.relpath(target, posixpath.dirname(member.name) or ".")
        member = member.replace(linkname=target)
    return tarfile.data_filter(member, destination)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--alpine", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--helper", type=Path)
    args = parser.parse_args()
    verify.require(os.geteuid() == 0, "The isolated Alpine startup check requires root for chroot")
    verify.require(args.work.absolute() == args.work.resolve() and not args.work.is_symlink(), "Linked startup-check directory")
    args.work.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.umask(0o077)
    root = args.work / ("alpine-startup-" + uuid.uuid4().hex)
    root.mkdir(mode=0o700)
    alpine = verify.read_regular(args.alpine, 8 * 1024 * 1024)
    verify.require(hashlib.sha256(alpine).hexdigest() == ALPINE_SHA256, "Alpine startup input differs from verified 3.24.1 minirootfs")
    with tarfile.open(fileobj=io.BytesIO(alpine), mode="r:gz") as archive:
        archive.extractall(root, filter=alpine_filter)
    vendor = args.work / ("vendor-startup-" + uuid.uuid4().hex)
    manifest = verify.verify_manifest(args.archive, args.manifest, vendor)
    results = []
    for item in manifest["files"]:
        source = vendor / item["path"]
        output = root / "usr/local" / item["path"]
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, output)
        output.chmod(0o755)
        command = ["chroot", str(root), "/usr/local/" + item["path"], "--version"]
        completed = subprocess.run(command, capture_output=True, text=True)
        results.append({"path": item["path"], "command": command, "exitCode": completed.returncode,
                        "output": completed.stdout + completed.stderr, "sha256": item["sha256"]})
        verify.require(completed.returncode == 0, "Rebuilt OCI executable failed startup in Alpine: " + item["path"])
    features = subprocess.check_output(["chroot", str(root), "/usr/local/bin/runc", "features"], text=True)
    parsed = json.loads(features)
    verify.require(parsed.get("linux", {}).get("seccomp", {}).get("enabled") is True, "Rebuilt runc lost seccomp support")
    if args.helper:
        helper = root / "usr/local/bin/opendock-mount-helper"
        shutil.copyfile(args.helper, helper)
        helper.chmod(0o755)
        completed = subprocess.run(["chroot", str(root), "/usr/local/bin/opendock-mount-helper"], capture_output=True, text=True)
        verify.require(completed.returncode == 2 and "usage:" in completed.stderr, "Static helper failed Alpine startup")
        results.append({"path": "custom/opendock-mount-helper", "sha256": verify.sha256(args.helper),
                        "exitCode": completed.returncode, "output": completed.stdout + completed.stderr})
    args.record.parent.mkdir(parents=True, exist_ok=True)
    record = {"schemaVersion": 1, "status": "passed", "archiveSha256": manifest["archive"]["sha256"],
              "alpineSha256": ALPINE_SHA256, "rootfs": str(root), "executables": results, "runcFeatures": parsed}
    args.record.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"status": "passed", "executables": len(results), "seccompEnabled": True}))


if __name__ == "__main__":
    main()
