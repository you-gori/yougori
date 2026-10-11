#!/usr/bin/env python3
"""Copy each bundled component's license files and record where its exact source came from."""
import json
import re
import shutil
import sys
from pathlib import Path

NOTICE = re.compile(r"^(COPYING|LICEN[CS]E|COPYRIGHT|NOTICE|README\.license)", re.IGNORECASE)


def notices(directory):
    return sorted(path for path in directory.iterdir() if path.is_file() and NOTICE.match(path.name))


def collect(inputs_path, sources, output, arch):
    inputs = json.loads(inputs_path.read_text(encoding="utf-8"))
    licenses = output / "licenses"
    components = []
    for source in inputs["sources"]:
        found = notices(sources / source["name"])
        if not found:
            raise SystemExit(f"{source['name']}: no license text found in its source")
        target = licenses / source["name"]
        target.mkdir(parents=True, exist_ok=True)
        for path in found:
            shutil.copy2(path, target / path.name)
        components.append({key: source[key] for key in ("name", "version", "license", "url", "sha256")}
                          | {"licenseFiles": [f"licenses/{source['name']}/{path.name}" for path in found]})
    # Meson wraps glib downloaded and built into libglib (proxy-libintl on macOS).
    for wrap in sorted((sources / "glib" / "subprojects").glob("*.wrap")):
        fields = dict(re.findall(r"^(\w+)\s*=\s*(.+?)\s*$", wrap.read_text(encoding="utf-8"), re.MULTILINE))
        directory = sources / "glib" / "subprojects" / fields.get("directory", wrap.stem)
        if not directory.is_dir() or "source_url" not in fields:
            continue
        found = notices(directory)
        if not found:
            raise SystemExit(f"glib subproject {wrap.stem}: no license text found")
        target = licenses / ("glib-" + wrap.stem)
        target.mkdir(parents=True, exist_ok=True)
        for path in found:
            shutil.copy2(path, target / path.name)
        components.append({"name": "glib-" + wrap.stem, "builtInto": "glib", "url": fields["source_url"],
                           "sha256": fields.get("source_hash"),
                           "licenseFiles": [f"licenses/glib-{wrap.stem}/{path.name}" for path in found]})
    record = {"schemaVersion": 1, "architecture": arch, "deploymentTarget": inputs["deploymentTarget"],
              "correspondingSource": f"yougori-macos-runtime-sources-{arch}.tar, published with each macOS release",
              "components": components}
    (output / "SOURCES.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    print(f"Recorded {len(components)} components with their license texts", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: collect_notices.py <inputs.json> <sources> <output> <arch>")
    collect(Path(sys.argv[1]), Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4])
