#!/usr/bin/env python3
"""Download the pinned macOS runtime sources and verify each SHA-256 before use."""
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch(destination):
    destination.mkdir(parents=True, exist_ok=True)
    inputs = json.loads((HERE / "inputs.json").read_text(encoding="utf-8"))
    for source in inputs["sources"]:
        url = source["url"]
        if not url.startswith("https://"):
            raise SystemExit(f"{source['name']}: only HTTPS sources are allowed")
        name = source["name"] + "-" + source["version"] + "".join(Path(url).suffixes[-2:])
        path = destination / name
        if not path.is_file() or digest(path) != source["sha256"]:
            partial = path.with_name(path.name + ".part")
            request = urllib.request.Request(url, headers={"User-Agent": "yougori-macos-runtime-build"})
            with urllib.request.urlopen(request, timeout=300) as response, partial.open("wb") as output:
                while chunk := response.read(1 << 20):
                    output.write(chunk)
            partial.replace(path)
        actual = digest(path)
        if actual != source["sha256"]:
            path.unlink()
            raise SystemExit(f"{source['name']}: SHA-256 {actual} does not match the pinned {source['sha256']}")
        print(f"{source['name']} {source['version']}: verified {path.name}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("usage: fetch.py <download-directory>")
    fetch(Path(sys.argv[1]))
