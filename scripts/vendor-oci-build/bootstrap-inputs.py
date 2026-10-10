"""Freeze primary upstream source inputs before a reviewed OCI runtime rebuild.

This preparation helper is not invoked by production builds. The resulting
inputs.json and patched module files are reviewed and committed separately.
"""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shutil
import tarfile
import urllib.request
import uuid

COMPONENTS = {
    "containerd": ("containerd/containerd", "v2.3.6", "ee2735368117d2eb259779949d5e75cdafec9761"),
    "nerdctl": ("containerd/nerdctl", "v2.3.5", "347782c28efe1753d5cc9652f6304752ed431221"),
    "runc": ("opencontainers/runc", "v1.5.1", "8f2685a471d3347a686ad3909783d8aafc6bb208"),
    "cni": ("containernetworking/plugins", "v1.9.1", "adc3e6b5b581638afbd194cf2e9319ecbb0151a1"),
}

FLOORS = {
    "github.com/cilium/ebpf": "v0.22.0",
    "github.com/cloudflare/circl": "v1.6.3",
    "github.com/containerd/containerd/v2": "v2.3.6",
    "github.com/containers/ocicrypt": "v1.3.2",
    "github.com/klauspost/compress": "v1.18.7",
    "go.opentelemetry.io/otel": "v1.45.0",
    "go.opentelemetry.io/otel/sdk": "v1.45.0",
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace": "v1.45.0",
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc": "v1.45.0",
    "go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp": "v1.45.0",
    "golang.org/x/crypto": "v0.57.0",
    "golang.org/x/mod": "v0.41.0",
    "golang.org/x/net": "v0.60.0",
    "golang.org/x/text": "v0.42.0",
    "google.golang.org/grpc": "v1.83.2",
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch(url, target):
    if not target.exists():
        temporary = target.with_name(target.name + ".part-" + uuid.uuid4().hex)
        with urllib.request.urlopen(url, timeout=90) as response, temporary.open("xb") as stream:
            shutil.copyfileobj(response, stream)
        temporary.rename(target)
    if target.is_symlink() or not target.is_file():
        raise ValueError("Linked or missing source cache entry")
    return {"file": target.name, "url": url, "sha256": digest(target), "bytes": target.stat().st_size}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--existing-compliance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.cache.mkdir(parents=True, exist_ok=True)
    locks = {}

    def component(item):
        name, (repository, version, revision) = item
        url = f"https://codeload.github.com/{repository}/tar.gz/{revision}"
        record = fetch(url, args.cache / f"{name}-{version}-{revision[:12]}.tar.gz")
        return name, {"repository": repository, "version": version, "revision": revision, "source": record}

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        for name, record in pool.map(component, COMPONENTS.items()):
            if name == "runc":
                record["compatibilityFloors"] = {"github.com/opencontainers/cgroups": "v0.1.0"}
            locks[name] = record
            print("Frozen", name, record["source"]["sha256"], flush=True)

    musl_revision = "f5640d3a10f664c9119720c60515265d3d6f6d01"
    original = args.existing_compliance / "alpine" / "musl" / musl_revision
    source = original / "distfiles/musl-1.2.6.tar.gz"
    assert digest(source) == "d585fd3b613c66151fc3249e8ed44f77020cb5e6c1e635a616d3f9f82460512a"
    shutil.copyfile(source, args.cache / source.name)
    musl = {"version": "1.2.6-r2", "aportsRevision": musl_revision, "source": {
        "file": source.name, "url": "https://distfiles.alpinelinux.org/distfiles/v3.24/musl-1.2.6.tar.gz",
        "sha256": digest(source), "bytes": source.stat().st_size}, "patches": []}
    for name in ("handle-aux-at_base.patch", "0001-add-stub-for-pthread_mutexattr_setprioceiling.patch",
                 "fix-loongarch64-zero-len-extcontext.patch", "CVE-2026-6042.patch", "CVE-2026-40200.patch"):
        path = original / "recipe" / name
        shutil.copyfile(path, args.cache / name)
        musl["patches"].append({"file": name, "sha256": digest(path), "bytes": path.stat().st_size,
            "url": f"https://raw.githubusercontent.com/alpinelinux/aports/{musl_revision}/main/musl/{name}"})
    seccomp = fetch("https://github.com/seccomp/libseccomp/releases/download/v2.6.1/libseccomp-2.6.1.tar.gz",
                    args.cache / "libseccomp-2.6.1.tar.gz")
    assert seccomp["sha256"] == "501f66c667225d53791b97e1d7cf85ab764c297d04881f60f38f451c4b0ee1be"
    debian = args.existing_compliance / "debian/btrfs-progs-6.14-1"
    btrfs = []
    known_btrfs = {
        "btrfs-progs_6.14.orig.tar.gz": "5a85b791f0f32a4994e864ac4cb7abccce08e56db3010a1855ad0edeebc70b4c",
        "btrfs-progs_6.14-1.debian.tar.xz": "0701b7d38fc7b1568f1f48bf8665b6a8ac503c8056e06ff4e3f7536656c0590c",
        "btrfs-progs_6.14-1.dsc": "eccdbf28fbb3414fe012d89a996fe1288807431d07f6cba0302db209714f6a8d",
    }
    for name in ("btrfs-progs_6.14.orig.tar.gz", "btrfs-progs_6.14-1.debian.tar.xz", "btrfs-progs_6.14-1.dsc"):
        path = debian / name
        if not path.exists():
            path = args.cache / name
            bundle = args.existing_compliance / "bundle/debian-btrfs-progs-6.14-1.tar.gz"
            assert digest(bundle) == "844fc11a0c2654252cfb0c8f46329455b48c8166e0dab8aa2fe30dafc89eeb81"
            with tarfile.open(bundle) as archive:
                matches = [entry for entry in archive if Path(entry.name).name == name and entry.isfile()]
                assert len(matches) == 1
                path.write_bytes(archive.extractfile(matches[0]).read())
        assert digest(path) == known_btrfs[name]
        if path != args.cache / name:
            shutil.copyfile(path, args.cache / name)
        btrfs.append({"file": name, "sha256": digest(path), "bytes": path.stat().st_size,
                      "url": f"https://deb.debian.org/debian/pool/main/b/btrfs-progs/{name}"})
    result = {"schemaVersion": 1, "target": "linux/amd64", "goVersion": "go1.27.2",
        "goArchiveSha256": "ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5",
        "sourceDateEpoch": 0, "components": locks, "moduleFloors": FLOORS,
        "native": {"musl": musl, "libseccomp": {"version": "2.6.1", "source": seccomp},
                   "btrfs": {"version": "6.14-1", "sources": btrfs}}}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
