#!/usr/bin/env python3
"""Copy the build prefix's dylibs that QEMU loads into OUTPUT/lib and point every
reference at them, so the runtime works from inside Yougori.app. Anything loaded from
outside macOS itself and that prefix (Homebrew, /usr/local) fails the build."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

SYSTEM = ("/usr/lib/", "/System/Library/")


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def install_id(path):
    lines = run("otool", "-D", str(path)).splitlines()
    return lines[1].strip() if len(lines) > 1 else None


def references(path):
    own = install_id(path)
    found = []
    for line in run("otool", "-L", str(path)).splitlines()[1:]:
        name = line.strip().split(" (compatibility")[0]
        if name and name != own:
            found.append(name)
    return found


def rpaths(path):
    lines = run("otool", "-l", str(path)).splitlines()
    return [lines[index + 2].split()[1] for index, line in enumerate(lines)
            if line.strip() == "cmd LC_RPATH" and index + 2 < len(lines)]


def main(output, prefix):
    output, prefix = output.resolve(), prefix.resolve()
    library = output / "lib"
    library.mkdir(exist_ok=True)
    queue = [(output / "qemu-system-x86_64", "@executable_path/lib/"), (output / "qemu-img", "@executable_path/lib/")]
    bundled = {}
    while queue:
        binary, location = queue.pop()
        for reference in references(binary):
            if reference.startswith(SYSTEM):
                continue
            name = Path(reference).name
            if reference.startswith("@rpath/"):
                source = prefix / "lib" / name
            elif reference.startswith(str(prefix) + "/") or reference.startswith(os.path.realpath(prefix) + "/"):
                source = Path(reference)
            elif reference.startswith(("@executable_path/lib/", "@loader_path/")) and (library / name).is_file():
                continue
            else:
                raise SystemExit(f"{binary.name} loads {reference}, which is outside macOS and this build")
            if not source.is_file():
                raise SystemExit(f"{binary.name} needs {reference}, which this build did not produce")
            if name not in bundled:
                target = library / name
                shutil.copy2(source.resolve(), target)
                target.chmod(0o644)
                run("install_name_tool", "-id", "@rpath/" + name, str(target))
                bundled[name] = target
                queue.append((target, "@loader_path/"))
            run("install_name_tool", "-change", reference, location + name, str(binary))
        for path in rpaths(binary):
            if path.startswith(str(prefix)) or path.startswith(os.path.realpath(prefix)):
                run("install_name_tool", "-delete_rpath", path, str(binary))
    for binary in [output / "qemu-system-x86_64", output / "qemu-img", *bundled.values()]:
        for reference in references(binary):
            name = Path(reference).name
            if not (reference.startswith(SYSTEM) or reference in ("@executable_path/lib/" + name, "@loader_path/" + name)
                    and (library / name).is_file()):
                raise SystemExit(f"{binary.name} still loads {reference}")
    print(f"Bundled {len(bundled)} libraries: {', '.join(sorted(bundled))}", flush=True)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.platform != "darwin":
        raise SystemExit("usage (macOS): bundle_dylibs.py <runtime-output> <build-prefix>")
    main(Path(sys.argv[1]), Path(sys.argv[2]))
