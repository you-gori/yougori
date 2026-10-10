"""Compile a Yougori C helper with the verified private patched musl toolchain."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess


def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    lock = json.loads(Path(__file__).with_name("inputs.json").read_text())
    data = json.loads(args.manifest.read_text())
    data = data.get("nativeBuild", data)
    require(data["musl"] == lock["native"]["musl"], "Private musl source/patch manifest mismatch")
    prefix = Path(data["muslPrefix"]).resolve()
    require(prefix == Path(data["muslPrefix"]), "Linked private musl prefix")
    files = {row["path"]: row for row in data["compilerInputs"] + data["libraries"]}
    compiler = prefix / "bin/musl-gcc"
    specs = prefix / "lib/musl-gcc.specs"
    libc = prefix / "lib/libc.a"
    for file in (compiler, specs, libc):
        require(str(file) in files and file.is_file() and not file.is_symlink(), "Private musl compiler input is missing or linked")
        row = files[str(file)]
        require(file.stat().st_size == row["bytes"] and sha256(file) == row["sha256"], "Private musl compiler input changed")
    gcc_row = data["compilerInputs"][0]
    gcc = Path(gcc_row["path"])
    require(gcc.is_file() and not gcc.is_symlink() and gcc.stat().st_size == gcc_row["bytes"] and
            sha256(gcc) == gcc_row["sha256"], "Recorded native GCC changed")
    arguments = args.arguments[1:] if args.arguments[:1] == ["--"] else args.arguments
    require(arguments and args.source.is_file() and not args.source.is_symlink() and str(args.source) in arguments,
            "A recorded helper source must be compiled")
    require(arguments.count("-o") == 1 and arguments.index("-o") + 1 < len(arguments), "An explicit helper output is required")
    output = Path(arguments[arguments.index("-o") + 1])
    require(output.parent.resolve() == output.parent.absolute() and not output.is_symlink(), "Linked C helper output")
    environment = {"PATH": "/usr/bin:/bin", "REALGCC": str(gcc), "LANG": "C.UTF-8", "TZ": "UTC", "SOURCE_DATE_EPOCH": "0"}
    subprocess.run([compiler, *arguments], env=environment, check=True)
    proof = subprocess.check_output(["readelf", "--program-headers", "--dynamic", output], env=environment, text=True)
    require("INTERP" not in proof and "(NEEDED)" not in proof and "Elf file type is DYN" in proof,
            "The C helper must be a static position-independent executable")
    args.record.parent.mkdir(parents=True, exist_ok=True)
    result = {"schemaVersion": 1, "source": {"path": str(args.source), "sha256": sha256(args.source)},
              "arguments": arguments, "musl": data["musl"], "compilerInputs": data["compilerInputs"],
              "libc": files[str(libc)], "wrapperPatch": data["wrapperPatch"], "manifestSha256": sha256(args.manifest),
              "output": {"path": str(output), "bytes": output.stat().st_size, "sha256": sha256(output)}, "elf": proof}
    args.record.write_text(json.dumps(result, indent=2) + "\n")
    print("C helper built with verified patched musl 1.2.6-r2.")


if __name__ == "__main__":
    main()
