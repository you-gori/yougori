"""Verify the secure QEMU's modified sources against the exported upstream and the recorded build.

The bundled secure QEMU is built from the checksum-verified upstream archive, the functional
patches, the dated notice patch and Yougori's TPM sources (SOURCE_BUILD.json). This restores the
affected files in a temporary tree and checks that:
  - applying exactly those inputs reproduces every source file the build used
    (compliance/evidence/source-restoration.json), and
  - the notice patch only adds the dated comment headers to the functional sources.
`--record-build TREE` first records the source files of the build tree that was compiled.
Only restores the affected source files; does not compile or execute QEMU.
"""
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
FUNCTIONAL = ("qemu-windows-tpm.patch", "qemu-whpx-tpm-ppi.patch", "qemu-whpx-reboot.patch")
NOTICE = "runtime/security/qemu-license-notices.patch"
TPM_SOURCES = ("tpm-api.h", "tpm-qemu.c")
RESTORATION = ROOT / "compliance/evidence/source-restoration.json"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def upstream_archive():
    release = json.loads((ROOT / "compliance/release.json").read_text(encoding="utf-8"))
    upstream = next(item for item in release["components"] if item["id"] == "qemu-secure-src")
    archive = ROOT / "build/compliance/bundle" / upstream["file"]
    with archive.open("rb") as stream:
        if hashlib.file_digest(stream, "sha256").hexdigest() != upstream["sha256"]:
            raise ValueError("QEMU upstream archive differs from recorded source")
    return upstream, archive


def affected_files():
    affected = set()
    for name in FUNCTIONAL:
        affected.update(re.findall(r"^diff --git a/(\S+) b/", (ROOT / "runtime/security" / name).read_text(), re.M))
    annotated = set(re.findall(r"^diff --git a/(\S+) b/", (ROOT / NOTICE).read_text(), re.M))
    if not affected or affected != annotated:
        raise ValueError("Dated notice patch must cover every modified upstream QEMU file")
    return affected


def restore(archive, affected, directory, notices):
    """Upstream files plus the functional patches (and the notice patch), with Yougori's TPM sources."""
    tree = Path(directory)
    subprocess.run(["git", "init", "--quiet", str(tree)], check=True)
    with tarfile.open(archive) as source:
        for name in sorted(affected):
            member = source.getmember(name)
            if not member.isfile():
                raise ValueError("Expected regular QEMU source file: " + name)
            source.extract(member, tree, filter="data")
    for name in FUNCTIONAL + ((Path(NOTICE).name,) if notices else ()):
        subprocess.run(["git", "apply", str(ROOT / "runtime/security" / name)], cwd=tree, check=True)
    for name in TPM_SOURCES:
        (tree / "backends/tpm" / name).write_bytes((ROOT / "runtime/security" / name).read_bytes())
    return tree


def build_inputs():
    """The secure QEMU's recorded build inputs must be exactly these local files."""
    record = json.loads((ROOT / "src-tauri/resources/runtime/qemu-secure/SOURCE_BUILD.json").read_text(encoding="utf-8"))
    recorded = {item["path"]: item["sha256"] for item in record["patches"]}
    for path in [f"runtime/security/{name}" for name in FUNCTIONAL] + [NOTICE] + [f"runtime/security/{name}" for name in TPM_SOURCES]:
        if recorded.get(path) != sha((ROOT / path).read_bytes()):
            raise ValueError("Secure QEMU build record does not name this source: " + path)
    return record


def record_build(tree):
    """Record the source files of the compiled tree, after proving restoration reproduces them."""
    build_inputs()
    upstream, archive = upstream_archive()
    affected = affected_files()
    paths = sorted(affected | {f"backends/tpm/{name}" for name in TPM_SOURCES})
    with tempfile.TemporaryDirectory(prefix="qemu-restore-", dir=ROOT / "build/compliance") as directory:
        restored = restore(archive, affected, directory, notices=True)
        results = []
        for path in paths:
            built = sha((tree / path).read_bytes())
            again = sha((restored / path).read_bytes())
            if built != again:
                raise ValueError("Restored source differs from the compiled tree: " + path)
            results.append({"path": path, "builtTreeSha256": built, "restoredTreeSha256": again, "matches": True})
    record = {"build": "2026-10-11 secure QEMU rebuild", "upstreamRevision": upstream["revision"],
              "method": "Verified upstream archive restored into a fresh directory; the recorded functional patches and the dated notice patch applied with git apply and Yougori's TPM sources added; compared with the source tree that was compiled",
              "results": results}
    RESTORATION.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Recorded {len(results)} compiled source files of the secure QEMU build")


def verify():
    build_inputs()
    upstream, archive = upstream_archive()
    affected = affected_files()
    baseline = json.loads(RESTORATION.read_text(encoding="utf-8"))["results"]
    with tempfile.TemporaryDirectory(prefix="qemu-notice-check-", dir=ROOT / "build/compliance") as directory:
        built = restore(archive, affected, Path(directory) / "built", notices=True)
        functional = restore(archive, affected, Path(directory) / "functional", notices=False)
        results = []
        for item in baseline:
            data = (built / item["path"]).read_bytes()
            if sha(data) != item["builtTreeSha256"]:
                raise ValueError("QEMU source no longer matches the recorded build: " + item["path"])
            original = data
            if item["path"] in affected:
                pattern = (rb"\A/\*\n \* Yougori modifications first recorded 2026-09-09:\n \* [^\n]+\n \* This dated notice was added 2026-09-13\.\n \*/\n"
                           if item["path"].endswith((".c", ".h")) else
                           rb"\A# Yougori modifications first recorded 2026-09-09:\n# [^\n]+\n# This dated notice was added 2026-09-13\.\n")
                original, count = re.subn(pattern, b"", data, count=1)
                if count != 1:
                    raise ValueError("Missing dated QEMU source notice: " + item["path"])
            if original != (functional / item["path"]).read_bytes():
                raise ValueError("Notice patch changed functional source: " + item["path"])
            results.append({"path": item["path"], "annotated": item["path"] in affected,
                            "annotatedSha256": sha(data), "withoutNoticeSha256": sha(original),
                            "builtTreeSha256": item["builtTreeSha256"], "matches": True})
    result = {"date": "2026-09-13", "upstreamRevision": upstream["revision"],
              "patch": {"path": NOTICE, "sha256": sha((ROOT / NOTICE).read_bytes())},
              "method": "Restored affected files from the checksum-verified upstream archive; applied the recorded functional patches, the notice patch and Yougori's TPM sources. This reproduces every compiled source file, and removing only the dated comment headers leaves exactly the functional sources.",
              "results": results}
    (ROOT / "compliance/evidence/qemu-modification-notices.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(f"Verified {len(affected)} dated QEMU notices; all {len(results)} compiled source files match the recorded build.")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--record-build":
        record_build(Path(sys.argv[2]).resolve())
    elif len(sys.argv) != 1:
        raise SystemExit("usage: compliance-qemu-notices.py [--record-build COMPILED-SOURCE-TREE]")
    verify()
