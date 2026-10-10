"""Rebuild the exact two CDI tools, preserving upstream1.20.0 and dynamic NVML loading.

Preparation freezes reviewed modules. Builds consume verified source, checksum
locks, and the precise compiler/native package versions; two clean source trees
must produce identical ELF and deterministic archive bytes.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tarfile
import urllib.request

HERE = Path(__file__).resolve().parent
NAME = "yougori-nvidia-cdi-linux-amd64"
PATHS = ("bin/nvidia-cdi-hook", "bin/nvidia-ctk")


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def write_json(path, data):
    Path(path).write_text(json.dumps(data, sort_keys=True, indent=2) + "\n")


def run(args, cwd, env, log):
    print("Running", " ".join(map(str, args)), flush=True)
    structured = Path(log).suffix == ".json"
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, text=True, encoding="utf-8",
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE if structured else subprocess.STDOUT)
    Path(log).write_text(result.stdout)
    if structured:
        Path(log).with_suffix(".stderr.log").write_text(result.stderr)
    require(result.returncode == 0, f"Command failed ({result.returncode}); inspect {log}")
    return result.stdout


def json_stream(text):
    decoder, position, records = json.JSONDecoder(), 0, []
    while position < len(text):
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            break
        record, position = decoder.raw_decode(text, position)
        records.append(record)
    return records


def verified_source(lock, cache):
    record = lock["upstream"]["source"]
    archive = cache / record["file"]
    if not archive.exists():
        temporary = archive.with_suffix(".part")
        with urllib.request.urlopen(record["url"], timeout=120) as response, temporary.open("xb") as output:
            shutil.copyfileobj(response, output)
        require(temporary.stat().st_size == record["bytes"] and digest(temporary) == record["sha256"], "Source download mismatch")
        temporary.rename(archive)
    require(archive.is_file() and not archive.is_symlink() and archive.stat().st_size == record["bytes"] and digest(archive) == record["sha256"], "NVIDIA source input mismatch")
    return archive


def extract(archive, destination):
    require(not destination.exists(), f"Fresh source directory required: {destination}")
    destination.mkdir(parents=True)
    with tarfile.open(archive, "r:gz") as source:
        source.extractall(destination, filter="data")
    roots = list(destination.iterdir())
    require(len(roots) == 1 and roots[0].is_dir() and not roots[0].is_symlink(), "Invalid source archive root")
    return roots[0]


def freeze_modules(go, source, env, records):
    run([go, "get", "golang.org/x/mod@v0.40.0"], source, env, records / "prepare-modules.log")
    run([go, "mod", "edit", "-go=1.27.2"], source, env, records / "prepare-go-version.log")
    run([go, "mod", "tidy"], source, env, records / "prepare-tidy.log")
    run([go, "mod", "verify"], source, env, records / "prepare-verify.log")
    modules = HERE / "modules"
    modules.mkdir(exist_ok=True)
    for name in ("go.mod", "go.sum"):
        shutil.copyfile(source / name, modules / name)
    original = extract(verified_source(json.loads((HERE / "inputs.json").read_text()), records.parent / "cache"), records.parent / "original")
    patches = []
    for name in ("go.mod", "go.sum"):
        import difflib
        patches.extend(difflib.unified_diff((original / name).read_text().splitlines(True), (source / name).read_text().splitlines(True),
                                          fromfile="a/" + name, tofile="b/" + name))
    (modules / "modules.patch").write_text("".join(patches))
    write_json(modules / "lock.json", {name: digest(modules / name) for name in ("go.mod", "go.sum", "modules.patch")})


def apply_modules(source):
    lock = json.loads((HERE / "modules/lock.json").read_text())
    for name in ("go.mod", "go.sum", "modules.patch"):
        require(digest(HERE / "modules" / name) == lock[name], "Frozen NVIDIA module input changed")
    for name in ("go.mod", "go.sum"):
        shutil.copyfile(HERE / "modules" / name, source / name)
    return lock


def apply_source_patches(source, lock, env, records, label):
    for item in lock.get("patches", []):
        path = HERE / item["file"]
        require(path.is_file() and not path.is_symlink() and path.stat().st_size == item["bytes"] and digest(path) == item["sha256"], "NVIDIA source patch input changed")
        run(["patch", "--batch", "--fuzz=0", "-p1", "-i", path], source, env, records / (label + "-" + path.name + ".log"))


def check_native(lock):
    records = []
    for package, version in lock["nativePackages"].items():
        text = subprocess.check_output(["dpkg-query", "-W", "-f=${Package}|${Version}|${source:Package}|${source:Version}", package], text=True)
        fields = text.split("|")
        require(fields[1] == version, f"Native input {package} changed: {fields[1]} != {version}")
        records.append(dict(zip(("package", "version", "sourcePackage", "sourceVersion"), fields)))
    return records


def scan(go, source, binary, env, records, prefix):
    scanner = [go, "run", "golang.org/x/vuln/cmd/govulncheck@v1.8.0"]
    if binary is None:
        args = [*scanner, "-C", str(source), "-json", "./cmd/nvidia-ctk", "./cmd/nvidia-cdi-hook"]
    else:
        args = [*scanner, "-json", "-mode=binary", str(binary)]
    print("Running", " ".join(map(str, args)), flush=True)
    with (records / (prefix + ".json")).open("w") as stdout, (records / (prefix + ".log")).open("w") as stderr:
        result = subprocess.run(list(map(str, args)), env=env, stdout=stdout, stderr=stderr, text=True)
    require(result.returncode == 0, f"Official NVIDIA scanner failed; inspect {prefix}.log")
    output = (records / (prefix + ".json")).read_text()
    messages = json_stream(output)
    findings = [item["finding"] for item in messages if "finding" in item]
    require(not findings, f"NVIDIA vulnerability findings remain: {prefix}")
    return {"findings": 0, "scanner": "golang.org/x/vuln/cmd/govulncheck@v1.8.0", "record": prefix + ".json"}


def archive_files(files, target):
    with target.open("xb") as output, gzip.GzipFile(fileobj=output, mode="wb", filename="", mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for name in PATHS:
                data = files[name].read_bytes()
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(data), 0o755, 0
                member.uid = member.gid = 0
                member.uname = member.gname = ""
                archive.addfile(member, io.BytesIO(data))


def build_once(go, archive, work, label, env, lock, records):
    source = extract(archive, work / (label + "-source"))
    apply_modules(source)
    apply_source_patches(source, lock, env, records, label)
    run([go, "mod", "verify"], source, env, records / (label + "-mod-verify.log"))
    modules = json_stream(run([go, "list", "-m", "-json", "all"], source, env, records / (label + "-modules.json")))
    source_scan = scan(go, source, None, env, records, label + "-source-govulncheck")
    if label == "first":
        scopes = ["./cmd/nvidia-ctk/cdi/...", "./cmd/nvidia-cdi-hook/...", "./pkg/nvcdi/...", "./internal/discover/...", "./internal/lookup/..."]
        tests = [go, "test", "-p=2", "-count=1", *scopes]
        if Path("/usr/lib/wsl/lib/libnvidia-ml.so.1").is_file():
            require(os.geteuid() == 0, "WSL NVIDIA fixtures require a root-owned private build with mount-namespace isolation")
            tests = ["unshare", "--mount", "--fork", "--propagation", "private", sys.executable, HERE / "test-no-driver.py",
                     "--parent-namespace", os.readlink("/proc/self/ns/mnt"), "--record", records / "test-driver-isolation.json", *tests]
        run(tests, source, env, records / "tests.log")
        run([go, "vet", *scopes], source, env, records / "vet.log")
    files, evidence = {}, []
    for name in PATHS:
        target = work / label / name
        target.parent.mkdir(parents=True, exist_ok=True)
        tool = Path(name).name
        native_env = dict(env, CGO_ENABLED="1", CC="gcc", CGO_CFLAGS="-O2 -fPIE -fstack-protector-strong -ffile-prefix-map=" + str(source) + "=/build/nvidia -fdebug-prefix-map=" + str(source) + "=/build/nvidia", CGO_LDFLAGS="-Wl,--build-id=none")
        # Preserve NVIDIA's NVML/dxcore dynamic-loader link options.
        flags = "-s -w -buildid= '-extldflags=-Wl,--export-dynamic -Wl,--unresolved-symbols=ignore-in-object-files -Wl,-z,lazy -Wl,-z,relro -Wl,-z,noexecstack -Wl,--build-id=none' -X github.com/NVIDIA/nvidia-container-toolkit/internal/info.version=1.20.0 -X github.com/NVIDIA/nvidia-container-toolkit/internal/info.gitCommit=" + lock["upstream"]["revision"] + "+yougori-security"
        run([go, "build", "-p=2", "-buildmode=pie", "-trimpath", "-buildvcs=false", "-ldflags=" + flags, "-o", target, "./cmd/" + tool], source, native_env, records / (label + "-" + tool + "-build.log"))
        header = target.read_bytes()[:64]
        require(header[:6] == b"\x7fELF\x02\x01" and struct.unpack_from("<H", header, 18)[0] == 62 and struct.unpack_from("<H", header, 16)[0] == 3, "NVIDIA tool must be position-independent AMD64 ELF")
        target.chmod(0o755)
        info = run([go, "version", "-m", target], None, env, records / (label + "-" + tool + "-buildinfo.txt"))
        require(info.splitlines()[0].endswith("go1.27.2"), "Wrong actual NVIDIA compiler")
        elf = run(["readelf", "-d", target], None, env, records / (label + "-" + tool + "-dynamic.txt"))
        require("libc.so.6" in elf, "Missing required dynamic libc linkage for NVML")
        segments = run(["readelf", "--program-headers", "--wide", target], None, env, records / (label + "-" + tool + "-segments.txt"))
        stack = next((line for line in segments.splitlines() if "GNU_STACK" in line), "")
        require("GNU_RELRO" in segments and stack and " RW " in stack and " RWE " not in stack, "NVIDIA ELF lacks RELRO or has an executable stack")
        version = run([target, "--version"], None, env, records / (label + "-" + tool + "-version.txt"))
        require("1.20.0" in version, "NVIDIA product version changed")
        binary_scan = scan(go, source, target, env, records, label + "-" + tool + "-binary-govulncheck")
        files[name] = target
        evidence.append({"path": name, "bytes": target.stat().st_size, "sha256": digest(target), "mode": 0o755, "scan": binary_scan})
    output = work / label / (NAME + ".tar.gz")
    archive_files(files, output)
    return {"archive": output, "files": evidence, "sourceScan": source_scan, "modules": modules}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args()
    work = args.work.absolute()
    require(work.resolve() == work and not work.exists(), "Fresh real work directory required")
    work.mkdir(parents=True)
    records = work / "records"
    records.mkdir()
    cache = work / "cache"
    cache.mkdir()
    lock = json.loads((HERE / "inputs.json").read_text())
    env = dict(os.environ, GOTOOLCHAIN="local", GOFLAGS="-mod=readonly", GOPROXY="https://proxy.golang.org,direct", GOSUMDB="sum.golang.org", LC_ALL="C", TZ="UTC", SOURCE_DATE_EPOCH="0", GOMAXPROCS="2", PATH=str(args.go.parent) + ":" + os.environ["PATH"])
    env.pop("GOVERSION", None)
    version = run([args.go, "version"], None, env, records / "go-version.txt").strip()
    require(version == "go version go1.27.2 linux/amd64", "Reviewed Go compiler required")
    compiler_archive = args.go.parent.parent.parent / "go1.27.2.linux-amd64.tar.gz"
    require(digest(compiler_archive) == lock["goArchiveSha256"], "Compiler archive differs from official checksum pin")
    with tarfile.open(compiler_archive, "r:gz") as toolchain:
        original_go = hashlib.sha256(toolchain.extractfile("go/bin/go").read()).hexdigest()
    require(digest(args.go) == original_go, "Actual Go binary differs from verified official toolchain")
    archive = verified_source(lock, cache)
    if args.prepare:
        source = extract(archive, work / "prepare-source")
        freeze_modules(args.go, source, env, records)
        print("Frozen exact NVIDIA module patch", flush=True)
        return
    require(args.output is not None, "--output required for actual build")
    native = check_native(lock)
    first = build_once(args.go, archive, work, "first", env, lock, records)
    second = build_once(args.go, archive, work, "second", env, lock, records)
    require([{key: row[key] for key in ("path", "bytes", "sha256", "mode")} for row in first["files"]] ==
            [{key: row[key] for key in ("path", "bytes", "sha256", "mode")} for row in second["files"]], "Independent NVIDIA binaries differ")
    require(digest(first["archive"]) == digest(second["archive"]), "Deterministic NVIDIA archives differ")
    output = args.output.absolute()
    require(output.resolve() == output and not output.exists(), "Fresh actual output directory required")
    output.mkdir(parents=True)
    target = output / (NAME + ".tar.gz")
    shutil.copyfile(first["archive"], target)
    manifest = {"schemaVersion": 1, "kind": "nvidia-cdi", "target": "linux/amd64", "compiler": "go1.27.2", "upstream": lock["upstream"], "archive": {"file": target.name, "bytes": target.stat().st_size, "sha256": digest(target)}, "files": [{key: row[key] for key in ("path", "bytes", "sha256", "mode")} for row in first["files"]]}
    patched_source = work / "first-source" / ("nvidia-container-toolkit-" + lock["upstream"]["revision"])
    changed_files = ["go.mod", "go.sum", "cmd/nvidia-cdi-hook/cudacompat/cudacompat.go", "pkg/nvcdi/driver-wsl.go"]
    manifest["provenance"] = {"inputs": lock, "inputsSha256": digest(HERE / "inputs.json"), "moduleInputs": json.loads((HERE / "modules/lock.json").read_text()), "buildInputs": {name: digest(HERE / name) for name in ("build.py", "verify.py", "test-no-driver.py")}, "patchedSourceFiles": {name: digest(patched_source / name) for name in changed_files}, "nativeBuildPackages": native, "nativeLinkage": "Dynamic libc.so.6; preserves NVML dlopen and WSL GPU bridge; no NVIDIA driver bundled", "independentBuildsMatch": True, "sourceScan": first["sourceScan"], "secondSourceScan": second["sourceScan"]}
    write_json(output / (NAME + ".manifest.json"), manifest)
    verifier_spec = importlib.util.spec_from_file_location("nvidia_verify", HERE / "verify.py")
    verifier = importlib.util.module_from_spec(verifier_spec)
    verifier_spec.loader.exec_module(verifier)
    verifier.verify_manifest(target, output / (NAME + ".manifest.json"))
    write_json(records / "build-provenance.json", {**manifest["provenance"], "artifacts": {key: manifest[key] for key in ("archive", "files")}})
    print(json.dumps({"status": "verified", "archive": str(target), "sha256": digest(target), "files": 2, "independentBuildsMatch": True}), flush=True)


if __name__ == "__main__":
    main()
