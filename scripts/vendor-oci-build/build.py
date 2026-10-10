"""Rebuild only Yougori's ten pinned OCI executables and verify their results.

Preparation freezes changed go.mod/go.sum files. Normal builds consume those
files read-only, use the pinned module checksums and never select latest tags.
"""
import argparse
import gzip
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import tarfile
import urllib.request
import uuid

HERE = Path(__file__).resolve().parent
NAME = "yougori-oci-runtime-linux-amd64"
spec = importlib.util.spec_from_file_location("oci_verify", HERE / "verify.py")
verify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(verify)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def run(args, cwd=None, env=None, output=None):
    print("Running", " ".join(map(str, args)), flush=True)
    result = subprocess.run(list(map(str, args)), cwd=cwd, env=env, text=True, encoding="utf-8",
                            stdout=subprocess.PIPE if output else None, stderr=subprocess.STDOUT if output else None)
    if output:
        Path(output).write_text(result.stdout, encoding="utf-8")
    require(result.returncode == 0, f"Command failed ({result.returncode}): {args[0]}; inspect {output or 'build log'}")
    return result.stdout


def json_stream(text):
    decoder = json.JSONDecoder()
    result, position = [], 0
    while position < len(text):
        if text[position:].isspace():
            break
        while text[position].isspace():
            position += 1
        item, position = decoder.raw_decode(text, position)
        result.append(item)
    return result


def reviewed_findings(events, dependencies):
    findings = [event["finding"] for event in events if "finding" in event]
    residual = []
    for finding in findings:
        trace = finding.get("trace", [])
        # x/crypto is also used for maintained SSH/TLS primitives. Govulncheck
        # emits a module-level notice for deprecated OpenPGP even when none of
        # its packages are compiled. Keep that notice and prove absence rather
        # than treating a module-only advisory as an executable symbol finding.
        if (finding["osv"] == "GO-2026-5932" and len(trace) == 1 and
                trace[0].get("module") == "golang.org/x/crypto" and not trace[0].get("package")):
            require(not any(item == "golang.org/x/crypto/openpgp" or item.startswith("golang.org/x/crypto/openpgp/")
                            for item in dependencies), "Unsafe OpenPGP packages are still compiled")
            residual.append({"advisory": finding["osv"], "level": "module",
                             "assessment": "No deprecated OpenPGP package in the compiled dependency graph; maintained ocicrypt replacement retained."})
        else:
            raise RuntimeError(f"Unresolved OCI vulnerability finding: {finding}")
    return residual


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verified_input(record, cache):
    path = cache / record["file"]
    if not path.exists():
        require(record["url"].startswith("https://"), "Non-HTTPS OCI source input")
        temporary = path.with_name(path.name + ".part")
        with urllib.request.urlopen(record["url"], timeout=120) as response, temporary.open("xb") as stream:
            shutil.copyfileobj(response, stream)
        require(sha256(temporary) == record["sha256"], "Downloaded OCI source digest mismatch")
        temporary.rename(path)
    require(not path.is_symlink() and path.stat().st_size == record["bytes"] and sha256(path) == record["sha256"],
            f"OCI source input changed: {path}")
    return path


def extract_source(path, destination):
    require(not destination.exists(), f"Source extraction already exists: {destination}")
    destination.mkdir()
    with tarfile.open(path) as archive:
        archive.extractall(destination, filter="data")
    roots = list(destination.iterdir())
    require(len(roots) == 1 and roots[0].is_dir() and not roots[0].is_symlink(), "Invalid OCI source archive root")
    return roots[0]


def source_checkout(name, record, work, cache, env):
    verified_input(record["source"], cache)
    path = work / "sources" / name
    if not path.exists():
        path.mkdir(parents=True)
        run(["git", "init", path], env=env)
        run(["git", "remote", "add", "origin", "https://github.com/" + record["repository"] + ".git"], cwd=path, env=env)
        run(["git", "fetch", "--depth=1", "origin", record["revision"]], cwd=path, env=env)
        run(["git", "checkout", "--detach", "FETCH_HEAD"], cwd=path, env=env)
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=path, env=env, text=True).strip()
    require(revision == record["revision"], "Wrong upstream OCI revision")
    # The compiler derives honest main-module versions from actual upstream
    # tags. A shallow SHA-only checkout invents an old-branch pseudoversion.
    run(["git", "fetch", "--depth=1", "origin", "tag", record["version"]], cwd=path, env=env)
    tagged = subprocess.check_output(["git", "rev-parse", record["version"] + "^{}"], cwd=path, env=env, text=True).strip()
    require(tagged == revision, "Upstream OCI tag does not identify the pinned source commit")
    return path


def semver(version):
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)(?:[-+].*)?", version)
    require(match, f"Cannot compare module version: {version}")
    return tuple(map(int, match.groups()))


def enforce_floors(go, path, name, lock, env, records, phase):
    floors = dict(lock["moduleFloors"], **lock["components"][name].get("compatibilityFloors", {}))
    for iteration in range(8):
        module_rows = json_stream(run([go, "list", "-mod=mod", "-m", "-json", "all"], cwd=path, env=env,
                                     output=records / f"{name}-{phase}-{iteration}-modules.json"))
        selected = []
        for module in module_rows:
            floor = floors.get(module["Path"])
            if floor and not module.get("Main") and semver(module["Version"]) < semver(floor):
                selected.append(module["Path"] + "@" + floor)
        if not selected:
            break
        run([go, "get", *selected], cwd=path, env=env)
    else:
        raise RuntimeError("OCI fixed module graph did not converge")


def prepare_modules(go, path, name, lock, env, records):
    run(["git", "restore", "--source=HEAD", "--", "go.mod", "go.sum"], cwd=path, env=env)
    enforce_floors(go, path, name, lock, env, records, "prepare")
    run([go, "mod", "edit", "-go=1.27.2"], cwd=path, env=env)
    run([go, "mod", "tidy"], cwd=path, env=env)
    # tidy can drop a direct security floor for packages that only upstream
    # tests or optional commands import. Freeze the reviewed complete graph,
    # including those modules, after tidy has removed obsolete dependencies.
    enforce_floors(go, path, name, lock, env, records, "post-tidy")
    run([go, "mod", "verify"], cwd=path, env=env)
    target = HERE / "modules" / name
    target.mkdir(parents=True, exist_ok=True)
    for file in ("go.mod", "go.sum"):
        shutil.copyfile(path / file, target / file)
    patch = run(["git", "diff", "--", "go.mod", "go.sum"], cwd=path, env=env,
                output=target / "modules.patch")
    require(patch, "OCI module preparation unexpectedly made no patch")


def apply_modules(path, name, env, go, records):
    target = HERE / "modules" / name
    for file in ("go.mod", "go.sum"):
        require((target / file).is_file(), "Frozen OCI module files are missing; run reviewed preparation first")
        shutil.copyfile(target / file, path / file)
    run([go, "mod", "verify"], cwd=path, env=env)
    rows = json_stream(run([go, "list", "-mod=readonly", "-m", "-json", "all"], cwd=path, env=env,
                          output=records / f"{name}-modules.json"))
    lock = json.loads((HERE / "inputs.json").read_text())
    floors = dict(lock["moduleFloors"], **lock["components"][name].get("compatibilityFloors", {}))
    for row in rows:
        floor = floors.get(row["Path"])
        if floor and not row.get("Main"):
            require(semver(row["Version"]) >= semver(floor),
                    f"Frozen OCI graph predates a reviewed security floor: {row['Path']} {row['Version']} < {floor}")
    return rows


def native_build(lock, work, cache, env, jobs, records):
    marker = work / "native-complete.json"
    wrapper_patch = {"file": "scripts/vendor-oci-build/musl-static-pie.patch",
                     "sha256": sha256(HERE / "musl-static-pie.patch"),
                     "reference": "https://www.openwall.com/lists/musl/2021/04/15/1"}
    if marker.exists():
        data = json.loads(marker.read_text())
        require(all(data[name] == lock["native"][name] for name in ("musl", "libseccomp", "btrfs")), "Native build inputs changed")
        if data.get("wrapperPatch") == wrapper_patch:
            require(all(Path(item["path"]).is_file() and not Path(item["path"]).is_symlink() and
                        sha256(item["path"]) == item["sha256"] for item in data["libraries"]), "Native link input changed")
            return native_link_inputs(data, env, marker)
        marker.rename(work / ("native-manifest-previous-" + uuid.uuid4().hex + ".json"))
    native = work / ("native-" + sha256(HERE / "inputs.json")[:12])
    if native.exists():
        require(native.resolve().parent == work and not native.is_symlink(), "Unsafe unfinished native build path")
        native.rename(work / ("native-incomplete-" + uuid.uuid4().hex))
    native.mkdir()
    musl = lock["native"]["musl"]
    prefix = native / "musl-prefix"
    source = extract_source(verified_input(musl["source"], cache), native / "musl-source")
    native_env = dict(env, CC="gcc", CFLAGS=f"-O2 -ffile-prefix-map={work}=/build/oci -fdebug-prefix-map={work}=/build/oci")
    for patch in musl["patches"]:
        run(["patch", "-p1", "-i", verified_input(patch, cache)], cwd=source, env=native_env,
            output=records / ("musl-" + patch["file"] + ".log"))
    run(["patch", "-p1", "-i", HERE / "musl-static-pie.patch"], cwd=source, env=native_env,
        output=records / "musl-static-pie.log")
    # Preserve the reviewed Alpine recipe's portable x86_64 implementations.
    for name in ("memcpy.s", "memmove.s"):
        file = source / "src/string/x86_64" / name
        require(file.is_file(), "Missing pinned musl assembly input")
        file.unlink()
    run(["./configure", f"--prefix={prefix}", "--disable-shared"], cwd=source, env=native_env, output=records / "musl-configure.log")
    run(["make", f"-j{jobs}"], cwd=source, env=native_env, output=records / "musl-build.log")
    run(["make", "install"], cwd=source, env=native_env, output=records / "musl-install.log")
    # Only Linux UAPI headers are needed in the musl prefix; glibc headers never
    # enter the runc/libseccomp compiler's include tree.
    for origin, name in (("/usr/include/linux", "linux"), ("/usr/include/asm-generic", "asm-generic"),
                         ("/usr/include/x86_64-linux-gnu/asm", "asm")):
        shutil.copytree(origin, prefix / "include" / name)
    seccomp = extract_source(verified_input(lock["native"]["libseccomp"]["source"], cache), native / "libseccomp-source")
    seccomp_env = dict(native_env, CC=str(prefix / "bin/musl-gcc"))
    run(["./configure", f"--prefix={prefix}", "--enable-static", "--disable-shared", "--disable-python"], cwd=seccomp, env=seccomp_env, output=records / "libseccomp-configure.log")
    run(["make", f"-j{jobs}"], cwd=seccomp, env=seccomp_env, output=records / "libseccomp-build.log")
    run(["make", "install"], cwd=seccomp, env=seccomp_env, output=records / "libseccomp-install.log")
    btrfs_record = lock["native"]["btrfs"]
    btrfs = extract_source(verified_input(btrfs_record["sources"][0], cache), native / "btrfs-source")
    btrfs_prefix = native / "btrfs-prefix"
    run(["./autogen.sh"], cwd=btrfs, env=native_env, output=records / "btrfs-autogen.log")
    run(["./configure", f"--prefix={btrfs_prefix}", "--disable-documentation", "--disable-python",
         "--disable-convert", "--disable-zstd", "--disable-lzo", "--disable-libudev", "--with-crypto=builtin"], cwd=btrfs, env=native_env, output=records / "btrfs-configure.log")
    run(["make", f"-j{jobs}", "libbtrfs.a", "libbtrfsutil.a"], cwd=btrfs, env=native_env, output=records / "btrfs-build.log")
    (btrfs_prefix / "lib").mkdir(parents=True)
    (btrfs_prefix / "include/btrfs").mkdir(parents=True)
    for file in ("libbtrfs.a", "libbtrfsutil.a"):
        shutil.copyfile(btrfs / file, btrfs_prefix / "lib" / file)
    for file in ("libbtrfs/send-stream.h", "libbtrfs/send-utils.h", "libbtrfs/send.h", "kernel-lib/rbtree_types.h",
                 "libbtrfs/kerncompat.h", "libbtrfs/ioctl.h", "libbtrfs/ctree.h", "libbtrfs/version.h"):
        shutil.copyfile(btrfs / file, btrfs_prefix / "include/btrfs" / Path(file).name)
    packages = run(["dpkg-query", "-W", "-f=${Package}\t${Version}\t${source:Package}\t${source:Version}\n",
                    "libc6", "libc6-dev", "linux-libc-dev", "gcc-11", "libgcc-11-dev"], env=env,
                   output=records / "native-packages.txt")
    gcc = run(["gcc", "--version"], env=env, output=records / "gcc-version.txt")
    data = {"inputsSha256": sha256(HERE / "inputs.json"), "muslPrefix": str(prefix), "btrfsPrefix": str(btrfs_prefix),
            "musl": musl, "wrapperPatch": wrapper_patch,
            "nativeInputsSha256": hashlib.sha256(json.dumps(lock["native"], sort_keys=True).encode()).hexdigest(),
            "libseccomp": lock["native"]["libseccomp"], "btrfs": btrfs_record,
            "packages": packages, "gcc": gcc, "flags": native_env["CFLAGS"],
            "libraries": [{"path": str(file), "sha256": sha256(file)} for file in
                          (prefix / "lib/libc.a", prefix / "lib/libseccomp.a", btrfs_prefix / "lib/libbtrfs.a")]}
    write_json(marker, data)
    return native_link_inputs(data, env, marker)


def native_link_inputs(data, env, marker):
    # Bind Ubuntu's actual static libc/compiler runtime and startup objects,
    # rather than inheriting the old nerdctl release's Debian provenance.
    lock = json.loads((HERE / "inputs.json").read_text())
    require(all(data[name] == lock["native"][name] for name in ("musl", "libseccomp", "btrfs")), "Reused native source inputs changed")
    data.setdefault("initialPreparationInputsSha256", data["inputsSha256"])
    data["inputsSha256"] = sha256(HERE / "inputs.json")
    data["nativeInputsSha256"] = hashlib.sha256(json.dumps(lock["native"], sort_keys=True).encode()).hexdigest()
    names = ("libc.a", "libm.a", "libpthread.a", "libdl.a", "libresolv.a", "libgcc.a", "libgcc_eh.a",
             "crt1.o", "crti.o", "crtn.o", "crtbeginT.o", "crtbeginS.o", "crtend.o", "crtendS.o")
    current = {item["path"]: item for item in data["libraries"]}
    for name in names:
        raw = subprocess.check_output(["gcc", "-print-file-name=" + name], env=env, text=True).strip()
        file = Path(raw).resolve()
        require(file.is_absolute() and file.is_file(), f"Missing native link input: {name}")
        owner = subprocess.check_output(["dpkg-query", "-S", str(file)], env=env, text=True).strip()
        current[str(file)] = {"path": str(file), "sha256": sha256(file), "bytes": file.stat().st_size, "package": owner}
    for row in current.values():
        row["bytes"] = Path(row["path"]).stat().st_size
    data["libraries"] = list(current.values())
    compiler_files = [Path(subprocess.check_output(["which", "gcc"], env=env, text=True).strip()).resolve(),
                      Path(data["muslPrefix"]) / "bin/musl-gcc", Path(data["muslPrefix"]) / "lib/musl-gcc.specs"]
    data["compilerInputs"] = [{"path": str(file), "bytes": file.stat().st_size, "sha256": sha256(file)} for file in compiler_files]
    data["libcStrategy"] = {"containerd": "static Ubuntu glibc; netgo/osusergo/static_build; original btrfs 6.14",
                            "runc": "static PIE patched Alpine musl 1.2.6-r2 and libseccomp 2.6.1; seccomp retained"}
    write_json(marker, data)
    return data


def static_elf(path, records, env):
    text = run(["readelf", "--program-headers", "--dynamic", path], env=env,
               output=records / (path.name + "-elf.txt"))
    require("INTERP" not in text and "(NEEDED)" not in text, f"OCI executable is dynamically linked: {path}")
    verify.elf_header(path.read_bytes()[:64])


def build_binary(go, source, relative, output, env, tags, ldflags, pie=False, strip=True):
    output.parent.mkdir(parents=True, exist_ok=True)
    args = [go, "build", "-mod=readonly", "-trimpath", "-buildvcs=true", "-p", "4", "-tags", tags,
            "-ldflags", ("-s -w " if strip else "") + "-buildid= " + ldflags, "-o", output]
    if pie:
        args.extend(["-buildmode=pie"])
    args.append(relative)
    run(args, cwd=source, env=env)


def elf_code_sections(path):
    data = path.read_bytes()
    verify.elf_header(data[:64])
    offset = struct.unpack_from("<Q", data, 40)[0]
    size, count, names_index = struct.unpack_from("<HHH", data, 58)
    require(size == 64 and 0 < count < 65535 and names_index < count and offset + size * count <= len(data),
            "Invalid OCI ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, offset + index * size) for index in range(count)]
    names = sections[names_index]
    require(names[4] + names[5] <= len(data), "Invalid OCI ELF names section")
    strings = data[names[4]:names[4] + names[5]]
    found = {}
    for row in sections:
        require(row[0] < len(strings), "Invalid OCI ELF section name")
        name = strings[row[0]:].split(b"\0", 1)[0].decode("ascii")
        if name in (".text", ".gopclntab"):
            require(name not in found and row[4] + row[5] <= len(data), "Invalid OCI ELF code section")
            found[name] = data[row[4]:row[4] + row[5]]
    require(set(found) == {".text", ".gopclntab"}, "OCI executable is missing reference code sections")
    return found


def paired_reference(go, tool, binary, target, output, label, records, dependencies):
    source, package, source_env, tags, flags, pie = target
    reference = output / "references" / label
    build_binary(go, source, package, reference, source_env, tags, flags, pie=pie, strip=False)
    actual, readable = elf_code_sections(binary), elf_code_sections(reference)
    require(actual == readable, "Unstripped OCI reference differs from shipped executable code")
    run([tool, "-mode=extract", binary], env=source_env, output=records / (label + ".extract.json"))
    run([tool, "-mode=extract", reference], env=source_env, output=records / (label + ".reference-extract.json"))
    shipped_extract = json_stream((records / (label + ".extract.json")).read_text())[-1]
    extracted = json_stream((records / (label + ".reference-extract.json")).read_text())[-1]
    require(not shipped_extract.get("pkgSymbols"), "Binary finding did not use the reviewed stripped-symbol fallback")
    symbols = extracted.get("pkgSymbols", [])
    require(symbols and not any(row.get("pkg", "") == "golang.org/x/crypto/openpgp" or
                               row.get("pkg", "").startswith("golang.org/x/crypto/openpgp/") for row in symbols),
            "Unstripped reference cannot prove absence of unsafe OpenPGP symbols")
    run([tool, "-mode=binary", "-json", reference], env=source_env, output=records / (label + ".reference-scan.json"))
    residual = reviewed_findings(json_stream((records / (label + ".reference-scan.json")).read_text()), dependencies)
    return {"schemaVersion": 1, "file": "references/" + label, "bytes": reference.stat().st_size,
            "sha256": sha256(reference), "difference": "Only Go linker -s -w flags omitted; same source, compiler, native inputs and build flags",
            "sections": {name: {"bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, data in actual.items()},
            "referenceExtractedSymbols": len(symbols), "deprecatedOpenPgpSymbols": 0,
            "referencePackageFindings": 0, "referenceSymbolFindings": 0, "moduleOnlyAssessments": residual,
            "shippedExtractSha256": sha256(records / (label + ".extract.json")),
            "referenceExtractSha256": sha256(records / (label + ".reference-extract.json")),
            "referenceReportSha256": sha256(records / (label + ".reference-scan.json"))}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--go", required=True, type=Path)
    parser.add_argument("--govuln", type=Path)
    parser.add_argument("--jobs", type=int, default=4)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--native-only", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    work = args.work.resolve()
    work.mkdir(parents=True, exist_ok=True)
    require(work.is_dir() and not args.work.is_symlink(), "Linked OCI work directory")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    records = output / "records"
    records.mkdir(exist_ok=True)
    cache = work / "cache"
    cache.mkdir(exist_ok=True)
    lock = json.loads((HERE / "inputs.json").read_text())
    env = {"PATH": f"{args.go.parent}:/usr/bin:/bin", "HOME": os.environ["HOME"], "LANG": "C.UTF-8", "TZ": "UTC",
           "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOPROXY": "https://proxy.golang.org",
           "GOSUMDB": "sum.golang.org", "GOOS": "linux", "GOARCH": "amd64", "GOAMD64": "v1",
           "CGO_ENABLED": "0", "GOCACHE": str(work / "go-build"), "GOMODCACHE": str(work / "go-mod"),
           "SOURCE_DATE_EPOCH": "0", "GOMAXPROCS": str(args.jobs)}
    version = subprocess.check_output([args.go, "version"], env=env, text=True).strip()
    require(version == "go version go1.27.2 linux/amd64", "OCI compiler differs from reviewed Go 1.27.2")
    archive = args.go.parent.parent.parent / "go1.27.2.linux-amd64.tar.gz"
    require(sha256(archive) == lock["goArchiveSha256"], "OCI compiler archive differs from official pinned input")
    if args.native_only:
        native_build(lock, work, cache, env, args.jobs, records)
        print("Pinned native OCI libraries built.", flush=True)
        return
    sources, module_records = {}, {}
    for name, record in lock["components"].items():
        source = source_checkout(name, record, work, cache, env)
        sources[name] = source
        if args.prepare:
            prepare_modules(args.go, source, name, lock, env, records)
        else:
            module_records[name] = apply_modules(source, name, env, args.go, records)
    if args.prepare:
        print("Frozen OCI module files prepared; review them before normal builds.", flush=True)
        return
    require(args.govuln and args.govuln.is_file(), "Pinned govulncheck executable is required")
    env["GOFLAGS"] = "-mod=readonly"
    native = native_build(lock, work, cache, env, args.jobs, records)
    # Build twice from the same pinned source/native inputs and independent Go
    # caches, so an executable reused from the first cache cannot pass the check.
    bins, build_targets = [], {}
    for repetition in ("first", "second"):
        build_env = dict(env, GOCACHE=str(work / ("go-build-" + repetition)))
        destination = work / repetition
        if destination.exists():
            require(destination.resolve().parent == work and not destination.is_symlink(), "Unsafe previous OCI output path")
            destination.rename(work / (repetition + "-previous-" + uuid.uuid4().hex))
        for binary in ("containerd", "containerd-shim-runc-v2"):
            component = lock["components"]["containerd"]
            go_env = dict(build_env, CGO_ENABLED="1", CC="gcc", CGO_CFLAGS=f"-I{native['btrfsPrefix']}/include",
                          CGO_LDFLAGS=f"-L{native['btrfsPrefix']}/lib")
            flags = f"-X github.com/containerd/containerd/v2/version.Version={component['version']} -X github.com/containerd/containerd/v2/version.Revision={component['revision']} -X github.com/containerd/containerd/v2/version.Package=github.com/containerd/containerd/v2 -linkmode=external -extldflags=-static"
            build_binary(args.go, sources["containerd"], "./cmd/" + binary, destination / "bin" / binary,
                         go_env, "urfave_cli_no_docs,osusergo,netgo,static_build", flags)
            build_targets["bin/" + binary] = (sources["containerd"], "./cmd/" + binary,
                                             go_env, "urfave_cli_no_docs,osusergo,netgo,static_build", flags, False)
        component = lock["components"]["nerdctl"]
        flags = f"-X github.com/containerd/nerdctl/v2/pkg/version.Version={component['version']} -X github.com/containerd/nerdctl/v2/pkg/version.Revision={component['revision']}"
        build_binary(args.go, sources["nerdctl"], "./cmd/nerdctl", destination / "bin/nerdctl", build_env, "", flags)
        build_targets["bin/nerdctl"] = (sources["nerdctl"], "./cmd/nerdctl", build_env, "", flags, False)
        component = lock["components"]["runc"]
        prefix = native["muslPrefix"]
        go_env = dict(build_env, CGO_ENABLED="1", CC=prefix + "/bin/musl-gcc", PKG_CONFIG_PATH=prefix + "/lib/pkgconfig",
                      PKG_CONFIG_LIBDIR=prefix + "/lib/pkgconfig")
        flags = f"-X main.version={component['version'].removeprefix('v')} -X main.gitCommit={component['revision']} -linkmode=external -extldflags=-static-pie"
        build_binary(args.go, sources["runc"], ".", destination / "bin/runc", go_env,
                     "seccomp,urfave_cli_no_docs,netgo,osusergo", flags, pie=True)
        build_targets["bin/runc"] = (sources["runc"], ".", go_env, "seccomp,urfave_cli_no_docs,netgo,osusergo", flags, True)
        for plugin, directory in (("bridge", "main"), ("firewall", "meta"), ("host-local", "ipam"),
                                  ("loopback", "main"), ("portmap", "meta"), ("tuning", "meta")):
            build_binary(args.go, sources["cni"], f"./plugins/{directory}/{plugin}", destination / "libexec/cni" / plugin,
                         build_env, "", "-X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v1.9.1")
            build_targets["libexec/cni/" + plugin] = (sources["cni"], f"./plugins/{directory}/{plugin}", build_env, "",
                "-X github.com/containernetworking/plugins/pkg/utils/buildversion.BuildVersion=v1.9.1", False)
        for path in sorted(verify.RUNTIME_PATHS):
            file = destination / path
            static_elf(file, records, env)
            first = work / "first" / path
            if repetition == "second":
                require(sha256(first) == sha256(file), f"Non-reproducible OCI executable: {path}")
        if repetition == "first":
            bins = [{"path": path, "bytes": (destination / path).stat().st_size,
                     "sha256": sha256(destination / path), "mode": 0o755} for path in sorted(verify.RUNTIME_PATHS)]
    scans = []
    for record in bins:
        file = work / "first" / record["path"]
        label = record["path"].replace("/", "__")
        info = run([args.go, "version", "-m", file], env=env, output=records / (label + ".buildinfo.txt"))
        require("go1.27.2" in info, "OCI binary compiler metadata is wrong")
        source, package, source_env, tags, flags, pie = build_targets[record["path"]]
        dependencies = run([args.go, "list", "-mod=readonly", "-deps", "-tags", tags, package], cwd=source, env=source_env,
                           output=records / (label + ".packages.txt")).splitlines()
        require(not any(item == "golang.org/x/crypto/openpgp" or item.startswith("golang.org/x/crypto/openpgp/")
                        for item in dependencies), "Unsafe OpenPGP package remains in OCI executable")
        run([args.govuln, "-mode=binary", "-json", file], env=env, output=records / (label + ".scan.json"))
        run([args.govuln, "-json", "-tags", tags, package], cwd=source, env=source_env,
            output=records / (label + ".source-scan.json"))
        source_residual = reviewed_findings(json_stream((records / (label + ".source-scan.json")).read_text()), dependencies)
        binary_events = json_stream((records / (label + ".scan.json")).read_text())
        raw = [item["finding"] for item in binary_events if "finding" in item]
        reference = None
        if any(any(frame.get("package") for frame in finding.get("trace", [])) for finding in raw):
            require(all(item["osv"] == "GO-2026-5932" and len(item["trace"]) == 1 and
                        item["trace"][0].get("module") == "golang.org/x/crypto" and
                        (not item["trace"][0].get("function") or item["trace"][0]["function"].endswith("/*"))
                        for item in raw), "Unexpected binary symbol/package finding")
            reference = paired_reference(args.go, args.govuln, file, build_targets[record["path"]], output, label, records, dependencies)
            residual = [{"advisory": "GO-2026-5932", "assessment": "Govulncheck's stripped-symbol fallback creates wildcard entries; same-code unstripped reference and source package graph prove absence. Raw report retained."}]
        else:
            residual = reviewed_findings(binary_events, dependencies)
        scans.append({"path": record["path"], "status": "passed", "symbolFindings": 0, "packageFindings": 0,
                      "rawBinaryFindings": len(raw), "strippedFallbackReference": reference,
                      "moduleOnlyAssessments": residual, "sourceModuleOnlyAssessments": source_residual,
                      "packagesSha256": sha256(records / (label + ".packages.txt")),
                      "sourceReportSha256": sha256(records / (label + ".source-scan.json")),
                      "reportSha256": sha256(records / (label + ".scan.json"))})
    manifest = {"schemaVersion": 1, "target": "linux/amd64", "compiler": "go1.27.2", "files": bins,
                "components": lock["components"], "dependencyFixes": lock.get("dependencyFixes", {}),
                "nativeBuild": native, "moduleFiles": {
                    name: {file: sha256(HERE / "modules" / name / file) for file in ("go.mod", "go.sum", "modules.patch")}
                    for name in sources}, "reproducibility": {"builds": 2, "identicalExecutables": 10}, "vulnerabilityScans": scans}
    tar_path = output / (NAME + ".tar.gz")
    with tar_path.open("xb") as stream, gzip.GzipFile(filename="", fileobj=stream, mode="wb", mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for record in bins:
                data = (work / "first" / record["path"]).read_bytes()
                header = tarfile.TarInfo(record["path"])
                header.mode, header.size, header.mtime, header.uid, header.gid = 0o755, len(data), 0, 0, 0
                archive.addfile(header, io.BytesIO(data))
    manifest["archive"] = {"file": tar_path.name, "bytes": tar_path.stat().st_size, "sha256": sha256(tar_path)}
    manifest_path = output / (NAME + ".manifest.json")
    write_json(manifest_path, manifest)
    verify.verify_manifest(tar_path, manifest_path)
    write_json(output / "build-record.json", manifest)
    print(json.dumps({"status": "built-verified", "artifact": str(tar_path), "sha256": manifest["archive"]["sha256"]}), flush=True)


if __name__ == "__main__":
    main()
