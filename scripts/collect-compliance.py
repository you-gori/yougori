#!/usr/bin/env python3
"""Collect release evidence without running guest software or upstream build recipes.

Python 3.11+, Git, gh and 7-Zip are needed for the Windows inventory. Large
archives live outside Git in build/compliance. An inventory is NOT a legal
compliance certificate; unresolved items are retained and block distribution.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import runpy
import shlex
import shutil
import subprocess
import tempfile
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parent.parent
WORK = ROOT / "build/compliance"
BUNDLE = WORK / "bundle"
EVIDENCE = ROOT / "compliance/evidence"
RUNTIME = ROOT / "src-tauri/resources/runtime"
APPLICATION = runpy.run_path(str(ROOT / "scripts/compliance-application.py"))


def cargo_lockfiles(root=ROOT):
    """Discover every tracked Rust dependency graph, including vendored builds.

    Do not walk caches or use a hand-maintained list that can omit a new binary.
    Include untracked manifests/locks so new components cannot silently escape.
    """
    files = subprocess.check_output(["git", "ls-files", "--cached", "--others",
                                     "--exclude-standard", "-z"], cwd=root).decode().split("\0")
    return sorted({name for name in files if name == "Cargo.lock" or name.endswith("/Cargo.lock")})


def cargo_packages(root=ROOT):
    try:
        import tomllib
    except ImportError as error:
        raise RuntimeError("Dependency compliance checks require Python 3.11 or newer (CI uses Python 3.12).") from error
    packages = {}
    for relative in cargo_lockfiles(root):
        path = APPLICATION["safe_file"](root, relative)
        for pkg in tomllib.loads(path.read_text(encoding="utf-8")).get("package", []):
            source = pkg.get("source", "")
            if source and source != "registry+https://github.com/rust-lang/crates.io-index":
                raise ValueError(f"Non-crates.io dependency needs explicit source collection: {relative}: {pkg['name']} ({source})")
            if source:
                key = (pkg["name"], pkg["version"])
                if key in packages and packages[key]["checksum"] != pkg["checksum"]:
                    raise ValueError(f"Conflicting locked source checksums: {key}")
                packages[key] = pkg
    return packages


def run(*args, cwd=ROOT):
    result = subprocess.run([str(a) for a in args], cwd=cwd, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError(result.stderr.decode(errors="replace")[-1500:])
    return result.stdout


def digest(path, algorithm="sha256"):
    checksum = hashlib.new(algorithm)
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            checksum.update(chunk)
    return checksum.hexdigest()


def matching_build_source(root, relative, expected):
    """Resolve preserved build inputs without changing an old binary's record."""
    candidates = [relative]
    if relative == "runtime/security/tpm-qemu.c":
        candidates.append("runtime/security/shipped/tpm-qemu.c")
    for name in candidates:
        path = root / name
        if path.is_file() and not path.is_symlink() and digest(path) == expected:
            return path
    raise ValueError("No matching retained build source: " + relative)


def reviewed_scope(root, runtime_inputs, archives, review):
    # Exclude only the review itself and its derived application tar to avoid a
    # self-referential hash. All other tracked source, runtime and upstream
    # archives remain bound to the review. Regeneration cannot reuse approval.
    source = APPLICATION["inventory"](root)
    files = [{"path": p["path"], "sha256": p["sha256"]} for p in source["files"]
             if p["path"] != "compliance/engineering-review.json"]
    files += [{"path": p["path"], "sha256": p["sha256"]} for p in runtime_inputs
              if p["path"].startswith("src-tauri/resources/runtime/")]
    covered = {"files": sorted(files, key=lambda p: p["path"]),
               "archives": sorted([p for p in archives if p["file"] != APPLICATION["ARCHIVE"]], key=lambda p: p["file"])}
    fingerprint = hashlib.sha256(json.dumps(covered, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    current = dict(review)
    if current.get("status") == "approved" and current.get("sourceFingerprint") != fingerprint:
        current.update(status="pending", pendingReason="Source/runtime/archive scope changed or lacks a matching sourceFingerprint. Review this candidate before packaging.")
    return fingerprint, current


def write_json(path, value, canonical=False):
    path.parent.mkdir(parents=True, exist_ok=True)
    newline = "\r\n" if not canonical and path.exists() and b"\r\n" in path.read_bytes() else "\n"
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline=newline)


def safe_name(name):
    if not re.fullmatch(r"[a-zA-Z0-9_.+@-]+", name) or name in (".", ".."):
        raise ValueError(f"Unsafe component filename: {name!r}")
    return name


def download(url, path, expected=None, algorithm="sha256"):
    if not url.startswith("https://"):
        raise ValueError("Source downloads must use HTTPS")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and (expected is None or digest(path, algorithm) == expected):
        return
    for attempt in range(3):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Yougori-source-compliance/1.0"})
            with urllib.request.urlopen(request, timeout=45) as response:
                if not response.url.startswith("https://"):
                    raise ValueError("Insecure source redirect")
                with path.with_suffix(path.suffix + ".part").open("wb") as output:
                    shutil.copyfileobj(response, output, 1024 * 1024)
            partial = path.with_suffix(path.suffix + ".part")
            if expected and digest(partial, algorithm) != expected:
                # GitHub can increase abbreviated blob IDs in generated PR
                # patches as a repository grows. Recover only if an older
                # index-line width reproduces the FULL pinned checksum.
                recovered = (recover_patch_checksum(partial.read_bytes(), expected, algorithm)
                             if url.startswith("https://patch-diff.githubusercontent.com/raw/")
                             and path.suffix == ".patch" else None)
                if recovered is None:
                    raise ValueError(f"Source checksum mismatch: {path.name}")
                partial.write_bytes(recovered)
            partial.replace(path)
            return
        except urllib.error.HTTPError as error:
            if error.code in (400, 401, 403, 404, 422):
                raise
            if attempt == 2:
                raise
        except (OSError, TimeoutError):
            if attempt == 2:
                raise
        time.sleep(attempt + 1)


def recover_patch_checksum(data, expected, algorithm):
    pattern = rb"(?m)^index ([a-f0-9]+)\.\.([a-f0-9]+)"
    matches = list(re.finditer(pattern, data))
    if not data.startswith(b"From ") or not matches:
        return None
    for width in range(7, max(len(match[1]) for match in matches)):
        candidate = re.sub(pattern, lambda match: b"index " + match[1][:width] + b".." + match[2][:width], data)
        if hashlib.new(algorithm, candidate).hexdigest() == expected:
            return candidate
    return None


def api(endpoint):
    return json.loads(run("gh", "api", endpoint))


def github_directory(repository, revision, directory, destination):
    """Retain all recipe files, verifying Git blob IDs; never execute the recipe."""
    entries = api(f"repos/{repository}/contents/{directory}?ref={revision}")
    if not isinstance(entries, list):
        raise ValueError("Expected a GitHub directory")
    for entry in entries:
        name = safe_name(entry["name"])
        target = destination / name
        if entry["type"] == "dir":
            github_directory(repository, revision, entry["path"], target)
        elif entry["type"] == "file":
            download(entry["download_url"], target)
            contents = target.read_bytes()
            blob = hashlib.sha1(f"blob {len(contents)}\0".encode() + contents).hexdigest()
            if blob != entry["sha"]:
                raise ValueError(f"Recipe Git blob mismatch: {entry['path']}")
        else:
            raise ValueError(f"Unsupported recipe entry: {entry['type']} {entry['path']}")


def archive_directory(directory, output, canonical_source=False):
    """Archive an allowlisted source tree, refusing links and inspection disks."""
    with output.with_suffix(output.suffix + ".part").open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as archive:
                paths = directory.rglob("*")
                paths = sorted(paths, key=lambda item: item.relative_to(directory).as_posix()) if canonical_source else sorted(paths)
                for path in paths:
                    if path.is_symlink():
                        raise ValueError(f"Refusing source-tree symlink: {path}")
                    if path.is_file():
                        entry = archive.gettarinfo(str(path), path.relative_to(directory).as_posix())
                        entry.uid = entry.gid = entry.mtime = 0
                        entry.uname = entry.gname = ""
                        if canonical_source:
                            contents = path.read_bytes()
                            try:
                                text = contents.decode("utf-8")
                            except UnicodeDecodeError:
                                pass
                            else:
                                if "\0" not in text:
                                    contents = text.replace("\r\n", "\n").replace("\r", "\n").encode()
                            entry.mode = 0o755 if path.suffix == ".sh" else 0o644
                            entry.size = len(contents)
                            archive.addfile(entry, io.BytesIO(contents))
                        else:
                            with path.open("rb") as stream:
                                archive.addfile(entry, stream)
    output.with_suffix(output.suffix + ".part").replace(output)


def archive_record(path, **fields):
    return {**fields, "file": path.relative_to(BUNDLE).as_posix(),
            "sha256": digest(path), "bytes": path.stat().st_size}


def apk_packages(source):
    packages = []
    for block in re.split(r"\n\s*\n", source):
        fields = dict(re.findall(r"^([PVALocU]):(.*)$", block, re.M))
        if "P" in fields:
            packages.append({"name": fields["P"], "version": fields["V"],
                             "architecture": fields["A"], "license": fields["L"],
                             "origin": fields.get("o", fields["P"]),
                             "revision": fields.get("c"), "url": fields.get("U")})
    if not packages:
        raise ValueError("Empty APK package inventory")
    return packages


def cpio_files(data):
    offset = 0
    while offset < len(data):
        while offset < len(data) and data[offset] == 0:
            offset += 1
        if offset == len(data):
            break
        header = data[offset:offset + 110]
        if header[:6] not in (b"070701", b"070702"):
            raise ValueError("Unsupported initramfs CPIO header")
        size = int(header[54:62], 16)
        namesize = int(header[94:102], 16)
        if namesize < 1 or offset + 110 + namesize > len(data):
            raise ValueError("Truncated CPIO name")
        name = data[offset + 110:offset + 110 + namesize - 1].decode()
        start = (offset + 110 + namesize + 3) & ~3
        if start + size > len(data):
            raise ValueError("Truncated CPIO payload")
        if name != "TRAILER!!!":
            yield name.removeprefix("./"), data[start:start + size]
        offset = (start + size + 3) & ~3


def inventory():
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    inspection = WORK / "inspection"
    inspection.mkdir(parents=True, exist_ok=True)
    disk = inspection / "appliance.img"
    # Only the immutable, versioned appliance base is inspected. No app-data
    # path or existing user's container disk is accepted by this command.
    if disk.exists():
        disk.unlink()
    try:
        run(RUNTIME / "qemu/qemu-img.exe", "convert", "-O", "raw",
            RUNTIME / "appliance/appliance-base.qcow2", disk)
        installed = run("7z", "e", "-so", disk, "lib/apk/db/installed")
        (EVIDENCE / "appliance-apk-installed.txt").write_bytes(installed)
    finally:
        disk.unlink(missing_ok=True)
    packages = apk_packages(installed.decode())
    write_json(EVIDENCE / "alpine-packages.json", packages)
    # File digests prove which private utilities and Go programs actually ship
    # in the initramfs. They also expose package additions outside the APK DB.
    files = []
    go_modules = []
    for name, contents in cpio_files(gzip.decompress((RUNTIME / "appliance/initramfs-virt").read_bytes())):
        if contents:
            files.append({"path": name, "bytes": len(contents),
                          "sha256": hashlib.sha256(contents).hexdigest()})
            for module, version, checksum in re.findall(rb"dep\t([^\t\n]+)\t([^\t\n]+)\t([^\n]+)", contents):
                go_modules.append({"binary": name, "module": module.decode(),
                                   "version": version.decode(), "goSum": checksum.decode(errors="replace")})
    write_json(EVIDENCE / "initramfs-files.json", files)
    write_json(EVIDENCE / "guest-go-modules.json", go_modules)
    runtime_files = []
    for path in sorted(RUNTIME.rglob("*")):
        if path.is_file():
            runtime_files.append({"path": path.relative_to(ROOT).as_posix(),
                                  "sha256": digest(path), "bytes": path.stat().st_size})
    write_json(EVIDENCE / "runtime-files.json", runtime_files)
    # Package-manager ownership alone is insufficient: also match the actual
    # shipped DLL against the package-managed toolchain file byte for byte.
    toolchain = ROOT / "build/secure-runtime/toolchain/msys64"
    owners = {}
    for desc in (toolchain / "var/lib/pacman/local").glob("*/desc"):
        fields = dict(re.findall(r"%([^%]+)%\n(.*?)(?:\n\n|\Z)", desc.read_text(encoding="utf-8"), re.S))
        filelist = desc.with_name("files")
        if filelist.exists():
            for name in filelist.read_text(encoding="utf-8").splitlines():
                if name.startswith("ucrt64/bin/") and name.endswith(".dll"):
                    owners[Path(name).name.lower()] = (name, fields)
    dlls = []
    angle_evidence = EVIDENCE / "angle-build.json"
    angle_build = json.loads(angle_evidence.read_text(encoding="utf-8")) if angle_evidence.exists() else {}
    angle_binaries = {("libEGL_angle.dll" if item["file"] == "libEGL.dll" else item["file"]): item["sha256"]
                      for item in angle_build.get("binaries", [])}
    for part in ("qemu", "qemu-secure"):
        for dll in sorted((RUNTIME / part).glob("*.dll")):
            entry = {"file": dll.relative_to(ROOT).as_posix(), "sha256": digest(dll)}
            owned = owners.get(dll.name.lower())
            if angle_binaries.get(dll.name) == entry["sha256"]:
                entry.update({"provenance": "local-angle-d3d11-build", "source": "compliance/evidence/angle-build.json",
                              "sourceComponent": angle_build["sourceComponent"],
                              "licenseReview": "compliance/native.json"})
            elif owned and (toolchain / owned[0]).exists() and digest(toolchain / owned[0]) == entry["sha256"]:
                fields = owned[1]
                entry.update({"package": fields["NAME"], "version": fields["VERSION"],
                              "base": fields["BASE"], "license": fields["LICENSE"],
                              "buildDate": fields["BUILDDATE"], "url": fields["URL"],
                              "provenance": "matched-local-package-by-sha256"})
            elif dll.name == "libEGL.dll":
                entry.update({"provenance": "local-gpu-bridge", "source": "runtime/gpu/egl-bridge.c"})
            elif dll.name == "opendock-tpm.dll":
                entry.update({"provenance": "local-tpm-build", "source": "runtime/security/SOURCES.txt"})
            elif dll.name == "libEGL_angle.dll":
                candidate = toolchain / "ucrt64/bin/libEGL.dll"
                if candidate.exists() and digest(candidate) == entry["sha256"]:
                    fields = owners["libegl.dll"][1]
                    entry.update({"package": fields["NAME"], "version": fields["VERSION"],
                                  "base": fields["BASE"], "license": fields["LICENSE"],
                                  "buildDate": fields["BUILDDATE"], "url": fields["URL"],
                                  "provenance": "matched-local-package-by-sha256"})
            entry.setdefault("provenance", "unresolved-exact-binary-source")
            dlls.append(entry)
    write_json(EVIDENCE / "windows-dlls.json", dlls)
    print(f"Inventoried {len(packages)} Alpine packages, {len(dlls)} DLLs, {len(files)} initramfs files.", flush=True)


def collect_alpine():
    packages = json.loads((EVIDENCE / "alpine-packages.json").read_text(encoding="utf-8"))
    origins = {}
    for package in packages:
        origins.setdefault((package["origin"], package["revision"]), []).append(package)
    results = []
    for (origin, revision), members in origins.items():
        component = {"id": f"alpine/{origin}/{revision}", "packages": members}
        directory = WORK / "alpine" / safe_name(origin) / safe_name(revision)
        try:
            print(f"Alpine source: {origin}", flush=True)
            if not re.fullmatch(r"[a-f0-9]{40}", revision):
                raise ValueError("APK package lacks an exact source revision")
            recipe = directory / "recipe"
            if not (directory / "recipe-verified.json").exists():
                github_directory("alpinelinux/aports", revision, f"main/{origin}", recipe)
                write_json(directory / "recipe-verified.json", {"revision": revision})
            apkbuild = (recipe / "APKBUILD").read_text(encoding="utf-8")
            sums = re.search(r"^sha512sums=([\"'])(.*?)\1", apkbuild, re.M | re.S)
            if not sums and re.search(r"^source(?:\+)?=", apkbuild, re.M):
                raise ValueError("Recipe SHA512 source inventory needs manual review")
            inputs = []
            for checksum, name in re.findall(r"^([a-f0-9]{128})\s+([^\s]+)\s*$", sums[2] if sums else "", re.M):
                safe_name(name)
                path = recipe / name
                if not path.exists():
                    path = directory / "distfiles" / name
                    url = f"https://distfiles.alpinelinux.org/distfiles/v3.24/{urllib.parse.quote(name)}"
                    download(url, path, checksum, "sha512")
                if digest(path, "sha512") != checksum:
                    raise ValueError(f"Alpine source checksum mismatch: {name}")
                inputs.append({"file": path.relative_to(directory).as_posix(), "sha512": checksum})
            # Reject omitted or shell-computed checksum entries instead of
            # treating an incomplete regex match as a completed source set.
            nonempty = [line for line in (sums[2] if sums else "").splitlines() if line.strip()]
            if len(inputs) != len(nonempty) or (not inputs and "source=" in apkbuild and 'source=""' not in apkbuild):
                raise ValueError("Unresolved Alpine source checksum entries")
            component["inputs"] = inputs
            component["recipeRevision"] = revision
            output = BUNDLE / f"alpine-{origin}-{revision[:12]}.tar.gz"
            BUNDLE.mkdir(parents=True, exist_ok=True)
            archive_directory(directory, output)
            component.update(archive_record(output, status="collected"))
        except (OSError, ValueError, RuntimeError) as error:
            component.update(status="blocked", reason=str(error))
            print(f"  BLOCKED: {error}", flush=True)
        results.append(component)
        write_json(WORK / "alpine-sources.json", results)
    return results


def expand_recipe(value, variables):
    """Small literal-only subset of shell expansion. Never eval/source PKGBUILD."""
    def replace(match):
        expression = match[1] or match[2]
        name = re.match(r"[a-zA-Z_]\w*", expression)[0]
        if name not in variables:
            raise ValueError(f"Unresolved recipe variable: {name}")
        result = variables[name]
        suffix = expression[len(name):]
        if suffix == "%.*":
            return result.rsplit(".", 1)[0]
        if suffix == "%%.*":
            return result.split(".", 1)[0]
        if re.fullmatch(r":\d+:\d+", suffix):
            start, length = map(int, suffix[1:].split(":"))
            return result[start:start + length]
        if suffix.startswith("//"):
            old, new = suffix[2:].split("/", 1)
            return result.replace(old, new)
        if suffix:
            raise ValueError(f"Unsupported recipe expression: {expression}")
        return result
    for _ in range(12):
        updated = re.sub(r"\$\{([^}]+)\}|\$([a-zA-Z_]\w*)", replace, value)
        if updated == value:
            break
        value = updated
    if "$" in value or "`" in value:
        raise ValueError("Recipe expression requires manual review")
    return value


def recipe_sources(value, variables):
    sources = []
    for item in shlex.split(value, comments=True):
        item = expand_recipe(item, variables)
        brace = re.fullmatch(r"([^{}]*)\{([^{}]+)\}([^{}]*)", item)
        if brace:
            sources.extend(brace[1] + suffix + brace[3] for suffix in brace[2].split(","))
        else:
            sources.append(item)
    return sources


def collect_vcs_source(url, target, expected, algorithm):
    """Match makepkg's pinned Git archive checksum without executing recipes."""
    match = re.fullmatch(r"git\+(https://[^#]+)#(commit|tag)=([a-zA-Z0-9._/+~-]+)", url)
    if not match:
        raise ValueError("VCS source must pin an HTTPS Git commit or tag")
    repository, kind, ref = match.groups()
    if kind == "commit" and not re.fullmatch(r"[a-f0-9]{40}", ref):
        raise ValueError("VCS commit must be a complete Git object ID")
    if target.exists() and digest(target, algorithm) == expected:
        return
    cache = WORK / "vcs" / hashlib.sha256(url.encode()).hexdigest()[:24]
    if not (cache / "HEAD").exists():
        cache.mkdir(parents=True, exist_ok=True)
        run("git", "init", "--bare", cache)
    fetch_ref = f"refs/tags/{ref}" if kind == "tag" else ref
    run("git", "-C", cache, "fetch", "--depth=1", repository, fetch_ref)
    revision = run("git", "-C", cache, "rev-parse", "FETCH_HEAD^{commit}").decode().strip()
    if kind == "commit" and revision != ref:
        raise ValueError("Fetched VCS revision differs from recipe")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".part")
    with temporary.open("wb") as output:
        result = subprocess.run(["git", "-c", "core.abbrev=no", "-C", str(cache), "archive", "--format=tar", "FETCH_HEAD"], stdout=output, stderr=subprocess.PIPE, timeout=180)
    if result.returncode or digest(temporary, algorithm) != expected:
        raise ValueError("VCS source archive differs from makepkg's pinned checksum")
    temporary.replace(target)


def collect_msys(retry_blocked=False):
    dlls = json.loads((EVIDENCE / "windows-dlls.json").read_text(encoding="utf-8"))
    packages = {(item["package"], item["version"]): item for item in dlls if "package" in item}
    cache = ROOT / "build/secure-runtime/toolchain/msys64/var/cache/pacman/pkg"
    prior_path = WORK / "msys-sources.json"
    prior = {item["id"]: item for item in json.loads(prior_path.read_text(encoding="utf-8"))} if retry_blocked and prior_path.exists() else {}
    results = []
    for (name, version), package in sorted(packages.items()):
        base = package["base"]
        directory = WORK / "msys" / safe_name(base) / safe_name(version)
        record = {"id": f"msys/{name}/{version}", "package": name, "version": version,
                  "license": package["license"]}
        previous = prior.get(record["id"])
        if previous and previous.get("status") == "collected" and digest(BUNDLE / previous["file"]) == previous["sha256"]:
            results.append(previous)
            continue
        try:
            print(f"MSYS source: {name} {version}", flush=True)
            matches = list(cache.glob(f"{name}-{version}-any.pkg.tar.*"))
            matches += list((WORK / "stock-binary-packages").glob(f"{name}-{version}-any.pkg.tar.*"))
            matches = [path for path in matches if not path.name.endswith(".sig")]
            if len(matches) != 1:
                raise ValueError("Matching original binary package / BUILDINFO unavailable")
            buildinfo = run("tar", "-xOf", matches[0], ".BUILDINFO")
            fields = dict(re.findall(r"^([^= ]+) = (.+)$", buildinfo.decode(), re.M))
            expected = fields["pkgbuild_sha256sum"]
            directory.mkdir(parents=True, exist_ok=True)
            (directory / f"BUILDINFO-{name}.txt").write_bytes(buildinfo)
            record["binaryPackageSha256"] = digest(matches[0])
            recipe = directory / "recipe"
            proof = directory / "recipe-verified.json"
            if proof.exists():
                revision = json.loads(proof.read_text(encoding="utf-8"))["revision"]
                if digest(recipe / "PKGBUILD") != expected:
                    raise ValueError("Cached PKGBUILD no longer matches BUILDINFO")
            else:
                commits = api(f"repos/msys2/MINGW-packages/commits?path={base}/PKGBUILD&per_page=40")
                revision = None
                for commit in commits:
                    candidate = WORK / "msys-candidates" / f"{base}-{commit['sha']}"
                    download(f"https://raw.githubusercontent.com/msys2/MINGW-packages/{commit['sha']}/{base}/PKGBUILD",
                             candidate)
                    if digest(candidate) == expected:
                        revision = commit["sha"]
                        break
                if not revision:
                    raise ValueError("Exact PKGBUILD hash from BUILDINFO not found in history")
                github_directory("msys2/MINGW-packages", revision, base, recipe)
                if digest(recipe / "PKGBUILD") != expected:
                    raise ValueError("Retrieved recipe differs from binary BUILDINFO")
                write_json(proof, {"revision": revision, "pkgbuildSha256": expected})
            source = (recipe / "PKGBUILD").read_text(encoding="utf-8")
            variables = {"MINGW_PACKAGE_PREFIX": "mingw-w64-ucrt-x86_64" if "-ucrt-" in name else "mingw-w64-x86_64"}
            for key, raw in re.findall(r"^([a-zA-Z_]\w*)=([^\n]*)$", source, re.M):
                if not raw.startswith("("):
                    variables[key] = raw.strip().strip("\"'")
                elif re.fullmatch(r'\(["\'][a-f0-9]{40}["\']\)', raw.strip()):
                    variables[key] = raw.strip()[2:-2]
            # Explicitly reviewed release branch of GCC's conditional recipe.
            # Its resulting archive still has to match the BUILDINFO-pinned
            # recipe checksum. Do not execute the condition or general shell.
            if base == "mingw-w64-gcc" and not variables.get("_rc") and not variables.get("_snapshot"):
                variables["pkgver"] = variables["_pkgver"]
                variables["_sourcedir"] = "gcc-" + variables["_pkgver"]
                variables["_url"] = "https://ftp.gnu.org/gnu/gcc/" + variables["_sourcedir"]
            source_array = re.search(r"^source=\((.*?)\)\s*\n", source, re.M | re.S)
            sums_array = re.search(r"^(sha256|sha512)sums=\((.*?)\)\s*\n", source, re.M | re.S)
            if not source_array or not sums_array or re.search(r"^source(?:_[a-z0-9_]+|\+)=", source, re.M):
                raise ValueError("Source arrays need manual review")
            sources = recipe_sources(source_array[1], variables)
            checksums = shlex.split(sums_array[2], comments=True)
            if len(sources) != len(checksums):
                raise ValueError("Source/checksum array lengths differ")
            inputs = []
            for item, checksum in zip(sources, checksums):
                if checksum == "SKIP" and item.endswith((".sig", ".asc")):
                    inputs.append({"file": item, "role": "signature-only; source verified by recipe digest"})
                    continue
                if not re.fullmatch(r"[a-f0-9]{64}|[a-f0-9]{128}", checksum):
                    raise ValueError("VCS/SKIP source needs a separately verified source archive")
                filename, url = item.split("::", 1) if "::" in item else (item.rsplit("/", 1)[-1], item)
                if url.startswith("git+"):
                    filename = safe_name(filename.replace("/", "_")) + ".tar"
                    target = directory / "distfiles" / filename
                    collect_vcs_source(url, target, checksum, sums_array[1])
                    inputs.append({"file": target.relative_to(directory).as_posix(), sums_array[1]: checksum, "origin": url})
                    continue
                safe_name(filename)
                target = recipe / filename
                if not target.exists():
                    target = directory / "distfiles" / filename
                    if url.startswith(("git+", "git://")):
                        raise ValueError("Pinned VCS input needs a verified source archive; this collector does not execute makepkg or clone recipe VCS sources")
                    if url.startswith("http://"):
                        url = "https://" + url[7:]
                    download(url, target, checksum, sums_array[1])
                if digest(target, sums_array[1]) != checksum:
                    raise ValueError(f"MSYS source checksum mismatch: {filename}")
                inputs.append({"file": target.relative_to(directory).as_posix(), sums_array[1]: checksum})
            output = BUNDLE / f"msys-{name}-{version}.tar.gz"
            archive_directory(directory, output)
            record.update(archive_record(output, status="collected", revision=revision, inputs=inputs))
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            record.update(status="blocked", reason=str(error))
            print(f"  BLOCKED: {error}", flush=True)
        results.append(record)
        write_json(WORK / "msys-sources.json", results)
    # Cached entries also belong in the final inventory, including entries
    # after the last newly collected item and runs containing only cache hits.
    write_json(WORK / "msys-sources.json", results)
    return results


def go_zip_hash(path):
    lines = []
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)):
            raise ValueError("Duplicate Go source zip names")
        for name in sorted(names):
            if name.endswith("/"):
                continue
            with archive.open(name) as stream:
                # Ubuntu 22.04's Python 3.10 has no hashlib.file_digest.
                hasher = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    hasher.update(chunk)
                checksum = hasher.hexdigest()
            lines.append(f"{checksum}  {name}\n")
    return "h1:" + base64.b64encode(hashlib.sha256("".join(lines).encode()).digest()).decode()


def collect_go():
    modules = json.loads((EVIDENCE / "guest-go-modules.json").read_text(encoding="utf-8"))
    main_modules = []
    def inspect(binary, contents):
        main = re.search(rb"\nmod\t([a-zA-Z0-9./_~-]+)\t([a-zA-Z0-9.()+-]+)", contents)
        revision = re.search(rb"build\tvcs.revision=([a-f0-9]{40})", contents)
        if main:
            main_modules.append({"binary": binary, "module": main[1].decode(), "version": main[2].decode(),
                                 "revision": revision[1].decode() if revision else None})
        for module, version, checksum in re.findall(rb"dep\t([^\t\n]+)\t([^\t\n]+)\t(h1:[a-zA-Z0-9+/=]+)", contents):
            modules.append({"binary": binary, "module": module.decode(), "version": version.decode(), "goSum": checksum.decode()})
    for binary in [*(RUNTIME / "cuda").glob("opendock-*"),
                   *(RUNTIME / "cloud").glob("yougori-share-linux-*")]:
        if binary.is_file():
            inspect(binary.relative_to(RUNTIME).as_posix(), binary.read_bytes())
    distribution = ROOT / "build/appliance-cache/nerdctl-full-2.3.5-linux-amd64.tar.gz"
    expected = "b697295c623639734aaab737523c808fd3cc8d3046039fd94fff1744e4c317aa"
    if digest(distribution) != expected:
        raise ValueError("OCI distribution differs from the build script's pinned input")
    names = {"bin/containerd", "bin/containerd-shim-runc-v2", "bin/nerdctl", "bin/runc"}
    names.update(f"libexec/cni/{plugin}" for plugin in ("bridge", "firewall", "host-local", "loopback", "portmap", "tuning"))
    with tarfile.open(distribution, "r|gz") as archive:
        for member in archive:
            if member.name.removeprefix("./") in names:
                inspect(member.name, archive.extractfile(member).read())
    write_json(EVIDENCE / "all-guest-go-modules.json", modules)
    write_json(EVIDENCE / "guest-main-modules.json", main_modules)
    mains = []
    for item in {entry["module"]: entry for entry in main_modules}.values():
        if item["module"].startswith("opendock.local/"):
            continue
        record = {"id": "go-main/" + item["module"], **item}
        try:
            if not item["module"].startswith("github.com/") or not re.fullmatch(r"[a-f0-9]{40}", item["revision"] or ""):
                raise ValueError("Main Go module lacks an exact upstream revision")
            repository = "/".join(item["module"].split("/")[1:3])
            path = BUNDLE / f"go-main-{repository.replace('/', '_')}-{item['revision'][:12]}.tar.gz"
            download(f"https://codeload.github.com/{repository}/tar.gz/{item['revision']}", path)
            record.update(archive_record(path, status="collected"))
        except (OSError, ValueError, RuntimeError) as error:
            record.update(status="blocked", reason=str(error))
        mains.append(record)
    write_json(WORK / "go-main-sources.json", mains)
    unique = {(item["module"], item["version"], item["goSum"]): item for item in modules}
    results = []
    for (module, version, expected), item in sorted(unique.items()):
        record = {"id": f"go/{module}@{version}", "module": module, "version": version, "goSum": expected}
        print(f"Go source: {module} {version}", flush=True)
        try:
            if not re.fullmatch(r"[a-zA-Z0-9./_~-]+", module) or ".." in module.split("/"):
                raise ValueError("Invalid Go module path")
            if not re.fullmatch(r"v[a-zA-Z0-9.+-]+", version):
                raise ValueError("Unpinned/replaced Go module needs review")
            escaped = re.sub(r"[A-Z]", lambda m: "!" + m[0].lower(), module)
            filename = "go-" + module.replace("/", "_") + "-" + version + ".zip"
            output = BUNDLE / safe_name(filename)
            download(f"https://proxy.golang.org/{escaped}/@v/{version}.zip", output)
            if go_zip_hash(output) != expected:
                raise ValueError("Go source checksum differs from shipped binary's build information")
            record.update(archive_record(output, status="collected"))
        except (OSError, ValueError, RuntimeError) as error:
            record.update(status="blocked", reason=str(error))
            print(f"  BLOCKED: {error}", flush=True)
        results.append(record)
        write_json(WORK / "go-sources.json", results)
    return results


def git_archive(directory, revision, output):
    """Archive committed upstream files; changes are supplied separately."""
    if not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("Source revision must be a full Git commit")
    actual = run("git", "rev-parse", "HEAD", cwd=directory).decode().strip()
    if actual != revision:
        raise ValueError(f"Cached source revision mismatch: {directory.name}")
    partial = output.with_suffix(output.suffix + ".part")
    with partial.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", mtime=0, filename="") as compressed:
            process = subprocess.Popen(["git", "archive", "--format=tar", revision], cwd=directory,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            shutil.copyfileobj(process.stdout, compressed)
            error = process.stderr.read()
            if process.wait() != 0:
                raise RuntimeError(error.decode(errors="replace"))
    partial.replace(output)


def collect_local():
    BUNDLE.mkdir(parents=True, exist_ok=True)
    results = []
    sources = [
        ("qemu-secure-src", "84f07211cc5b4fc6a371559bf8a5de4fb068e648"),
        ("ms-tpm-20-ref", "ee21db0a941decd3cac67925ea3310873af60ab3"),
        ("edk2-secure-src", "2970e5699ba6267f3384ffab20f96647578aebc8"),
        ("secureboot-objects", "9a2bbf82e86b62694e44aba3a4068d8dd0c943d7"),
    ]
    for name, revision in sources:
        directory = ROOT / "build/runtime-cache" / name
        output = BUNDLE / f"{name}-{revision[:12]}.tar.gz"
        print(f"Local upstream source: {name}", flush=True)
        git_archive(directory, revision, output)
        results.append(archive_record(output, id=name, revision=revision, status="collected"))
        submodules = run("git", "submodule", "status", "--recursive", cwd=directory).decode().splitlines()
        for line in submodules:
            # Only initialized submodules were available to the actual build.
            # The x86 firmware ROM submodules used by our staging profile are
            # initialized too. Unused architectures/tests are not claimed.
            if line.startswith("-"):
                continue
            match = re.match(r" ([a-f0-9]{40}) ([^ ]+)", line)
            if not match:
                raise ValueError(f"Source submodule needs review: {line}")
            commit, relative = match.groups()
            sub_output = BUNDLE / f"{name}-{relative.replace('/', '_')}-{commit[:12]}.tar.gz"
            git_archive(directory / relative, commit, sub_output)
            results.append(archive_record(sub_output, id=f"{name}/{relative}", revision=commit,
                                          mountAt=relative, parent=name, status="collected"))
        if name == "qemu-secure-src":
            for relative in ("subprojects/dtc", "subprojects/keycodemapdb"):
                subdir = directory / relative
                commit = run("git", "rev-parse", "HEAD", cwd=subdir).decode().strip()
                sub_output = BUNDLE / f"qemu-{Path(relative).name}-{commit[:12]}.tar.gz"
                git_archive(subdir, commit, sub_output)
                results.append(archive_record(sub_output, id=f"{name}/{relative}", revision=commit,
                                              mountAt=relative, parent=name, status="collected"))
    results.append(collect_build_material())
    novnc = ROOT / "node_modules/@novnc/novnc"
    output = BUNDLE / "novnc-1.7.0-used-source.tar.gz"
    archive_directory(novnc, output)
    results.append(archive_record(output, id="novnc", version="1.7.0", status="collected"))
    write_json(WORK / "local-sources.json", results)
    APPLICATION["collect"](ROOT, BUNDLE)
    return results


def collect_build_material():
    # Include only source/build material, preserving component rights as
    # explained in docs/licensing.txt. Never archive Git metadata, credentials,
    # generated runtime disks, signing keys or the whole working directory.
    output = BUNDLE / "yougori-runtime-build-material.tar.gz"
    candidates = run("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0")
    frontend_files = set(frontend_inventory()["files"])
    with tempfile.TemporaryDirectory(prefix="source-material-", dir=WORK) as temporary:
        material = Path(temporary)
        for relative in sorted(set(candidates)):
            if not (relative in frontend_files or relative in ("LICENSE", "COPYING", "NOTICE", "COMMERCIAL_LICENSE.txt", "docs/licensing.txt", "docs/rebuilding-third-party.txt",
                                                              "package.json", "package-lock.json") or
                    relative.startswith(("runtime/security/", "runtime/gpu/", "appliance/", "runtime/cuda/", "scripts/",
                                         "compliance/notices/", "src-tauri/boot-helper/"))):
                continue
            path = ROOT / relative
            if path.is_symlink() or not path.is_file():
                raise ValueError(f"Source material missing or linked: {relative}")
            target = material / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
        archive_directory(material, output, canonical_source=True)
    return archive_record(output, id="local-build-material", status="collected")


def refresh_build_material():
    record = collect_build_material()
    path = WORK / "local-sources.json"
    records = json.loads(path.read_text(encoding="utf-8"))
    records = [entry for entry in records if entry["id"] != "local-build-material"]
    records.append(record)
    write_json(path, records)
    APPLICATION["collect"](ROOT, BUNDLE)
    print("Updated local source/build material archive.", flush=True)


def frontend_inventory():
    return json.loads(run("node", "scripts/compliance-frontend.mjs"))


def prepare_cache():
    """Use verified upstream archives from a cache, recreating only local source.

    The checked-in release inventory is authoritative. Never update its hashes
    or silently accept a cache from another upstream/runtime revision.
    """
    release = json.loads((ROOT / "compliance/release.json").read_text(encoding="utf-8"))
    expected = next(item for item in release["components"] if item["id"] == "local-build-material")
    current = collect_build_material()
    if current["sha256"] != expected["sha256"]:
        raise ValueError("Local source material differs from its reviewed archive; regenerate and review release evidence")
    expected_application = next(item for item in release["components"] if item["id"] == "yougori-application-source")
    current_application = APPLICATION["collect"](ROOT, BUNDLE)
    if current_application != expected_application:
        raise ValueError("Application source differs from its reviewed archive; regenerate and review release evidence")
    for item in release["archives"]:
        path = BUNDLE / safe_name(item["file"])
        if path.is_symlink() or digest(path) != item["sha256"]:
            raise ValueError("Cached source archive does not match this release: " + item["file"])
    write_source_index(release)
    print("Prepared matching sources from verified upstream cache and reviewed local material.", flush=True)


def dependency_notices():
    """Conservative inventory: include all lockfile crates, not just one target.

    This deliberately over-includes build/target dependencies. Missing texts
    remain explicit findings instead of inventing a license from a package name.
    """
    import tomllib  # Only TOML collection requires Python 3.11+; cache works on 3.10.
    records = []
    sections = []
    frontend = frontend_inventory()
    shipped_packages = {item["packagePath"] for item in frontend["npmImports"]}
    lock = json.loads((ROOT / "package-lock.json").read_text(encoding="utf-8"))
    for relative, metadata in lock["packages"].items():
        if not relative or (metadata.get("dev") and relative not in shipped_packages):
            continue
        directory = ROOT / relative
        pkg = json.loads((directory / "package.json").read_text(encoding="utf-8")) if (directory / "package.json").exists() else {}
        record = {"ecosystem": "npm", "name": pkg.get("name", relative),
                  "version": metadata["version"], "license": pkg.get("license", metadata.get("license", "UNKNOWN")),
                  "integrity": metadata.get("integrity"), "texts": []}
        if pkg.get("version") != metadata["version"]:
            raise ValueError("Installed dependency differs from lockfile: " + relative)
        if relative in shipped_packages:
            record["shippedFrontend"] = True
        add_notices(directory, record, sections)
        if not record["texts"]:
            try:
                metadata_path = WORK / "npm-metadata" / f"{safe_name(pkg.get('name', '').replace('/', '_'))}-{record['version']}.json"
                download(f"https://registry.npmjs.org/{urllib.parse.quote(pkg['name'], safe='')}/{record['version']}", metadata_path)
                registry = json.loads(metadata_path.read_text(encoding="utf-8"))
                if registry.get("dist", {}).get("integrity") != record["integrity"]:
                    raise ValueError("Registry package integrity does not match the lockfile")
                repository = registry.get("repository", {})
                upstream_notices(repository.get("url", "") if isinstance(repository, dict) else repository,
                                 registry.get("gitHead", ""), record, sections)
            except (OSError, ValueError, RuntimeError, KeyError) as error:
                record["noticeIssue"] = str(error)
        records.append(record)
    for component in frontend["vendoredComponents"]:
        record = {"ecosystem": "vendored", "name": component["id"], "version": component["reviewedRevision"],
                  "license": component["license"], "upstream": component["upstream"],
                  "files": component["files"], "texts": []}
        for relative in component["noticeFiles"]:
            text = (ROOT / relative).read_text(encoding="utf-8")
            record["texts"].append({"path": relative, "sha256": hashlib.sha256(text.encode()).hexdigest(), "normalization": "lf"})
            sections.append(f"{'=' * 72}\nvendored: {component['name']}\nDeclared license: {component['license']}\n"
                            f"Source: {component['upstream']}\nFile: {relative}\n\n{text}\n")
        records.append(record)
    crates = cargo_packages(ROOT)
    cache = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))) / "registry/src"
    for (name, version), pkg in sorted(crates.items()):
        matches = list(cache.glob(f"*/{name}-{version}"))
        directory = matches[0] if matches else None
        if directory is None:
            crate = WORK / "crates" / f"{name}-{version}.crate"
            download(f"https://static.crates.io/crates/{name}/{name}-{version}.crate", crate, pkg["checksum"])
            extraction = WORK / "crate-sources"
            with tarfile.open(crate) as archive:
                for member in archive:
                    parts = Path(member.name).parts
                    if member.issym() or member.islnk() or Path(member.name).is_absolute() or ".." in parts:
                        raise ValueError("Unsafe crate archive member")
                    archive.extract(member, extraction, filter="data")
            directory = extraction / f"{name}-{version}"
        data = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8")) if directory else {}
        record = {"ecosystem": "cargo", "name": name, "version": version,
                  "scope": "lockfile-includes-build-and-other-target-dependencies",
                  "checksum": pkg.get("checksum"), "license": data.get("package", {}).get("license", "UNKNOWN"), "texts": []}
        if directory:
            add_notices(directory, record, sections)
            if not record["texts"]:
                try:
                    vcs = json.loads((directory / ".cargo_vcs_info.json").read_text(encoding="utf-8"))
                    upstream_notices(data["package"].get("repository", ""), vcs["git"]["sha1"], record, sections)
                except (OSError, ValueError, RuntimeError, KeyError) as error:
                    record["noticeIssue"] = f"Supplementary upstream notice lookup: {type(error).__name__}"
            if not record["texts"]:
                declared_standard_notice(directory, data.get("package", {}), record, sections)
            # Actual source is retained for non-permissive/Mozilla components;
            # choosing a permissive OR branch still requires its notice text.
            if re.search(r"MPL|[AL]?GPL|CDDL|EPL", record["license"]):
                output = BUNDLE / f"crate-{name}-{version}.tar.gz"
                archive_directory(directory, output)
                record["source"] = archive_record(output)
        records.append(record)
    # Path patches are not registry packages. Retain their actual license/source
    # provenance instead of silently dropping them after Cargo.lock loses source=.
    patches = tomllib.loads((ROOT / "src-tauri/Cargo.toml").read_text(encoding="utf-8")).get("patch", {}).get("crates-io", {})
    for name, patch in sorted(patches.items()):
        if "path" not in patch:
            raise ValueError("Non-local Cargo patch needs a source collector: " + name)
        directory = (ROOT / "src-tauri" / patch["path"]).resolve()
        relative = directory.relative_to(ROOT).as_posix()
        metadata = tomllib.loads((directory / "Cargo.toml").read_text(encoding="utf-8"))["package"]
        record = {"ecosystem": "cargo-vendored", "name": name, "version": metadata["version"],
                  "license": metadata.get("license", "UNKNOWN"), "sourcePath": relative,
                  "sourceDelivery": "yougori-application-source.tar.gz", "texts": []}
        add_notices(directory, record, sections)
        records.append(record)
    for record in records:
        if record["ecosystem"] == "cargo":
            prefix = f"{'=' * 72}\ncargo: {record['name']} {record['version']}\n"
            record["noticeSectionSha256"] = [hashlib.sha256((section.replace("\r\n", "\n").replace("\r", "\n").rstrip("\n") + "\n").encode()).hexdigest()
                                              for section in sections if section.startswith(prefix)]
    write_json(EVIDENCE / "application-dependencies.json", records)
    write_json(EVIDENCE / "frontend-dependencies.json", frontend)
    header = ("YOUGORI APPLICATION DEPENDENCY NOTICES\n\n"
              "Generated from production npm packages, shipped CSS/assets, copied code and Cargo lockfiles.\n"
              "Build dependencies contributing shipped frontend code or assets are included.\n"
              "Cargo entries conservatively include build-only and other-target packages.\n"
              "Each component keeps its own license. Yougori's license does not override it.\n"
              "Runtime package notices and sources are tracked separately.\n\n")
    (ROOT / "src-tauri/resources/APPLICATION_LICENSES.txt").write_text(header + "\n".join(sections), encoding="utf-8")
    print(f"Recorded {len(records)} application dependencies; {sum(not r['texts'] for r in records)} need notice review.", flush=True)


def declared_standard_notice(directory, metadata, record, sections):
    """Preserve an explicit upstream declaration, never infer a copyright owner.

    Some crates declare Apache/MPL in Cargo.toml and source headers but omit a
    standalone license file. Include that declaration, existing header notices,
    and the unmodified standard text for an explicitly offered license option.
    """
    expression = record["license"].replace("/", " OR ")
    options = [part.strip() for part in expression.split(" OR ")]
    selected = "Apache-2.0" if "Apache-2.0" in options else "MPL-2.0" if options == ["MPL-2.0"] else None
    if selected is None:
        return
    if selected == "Apache-2.0":
        standard = WORK / "standard-licenses/Apache-2.0.txt"
        download("https://www.apache.org/licenses/LICENSE-2.0.txt", standard)
    else:
        standard = ROOT / "node_modules/@novnc/novnc/docs/LICENSE.MPL-2.0"
    headers = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink() or not path.is_file() or path.suffix not in (".rs", ".c", ".h", ".md") or path.stat().st_size > 1024 * 1024:
            continue
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        indexes = set()
        for index, line in enumerate(lines):
            if re.search(r"copyright|SPDX-License|Licensed under|This Source Code Form", line, re.I):
                indexes.update(range(max(0, index - 1), min(len(lines), index + 9)))
        if indexes:
            headers.append(f"Source: {path.relative_to(directory).as_posix()}\n" + "\n".join(lines[index] for index in sorted(indexes)))
    declaration = (f"Upstream Cargo.toml license declaration: {record['license']}\n"
                   f"Upstream package authors metadata: {json.dumps(metadata.get('authors', []), ensure_ascii=False)}\n"
                   f"Redistribution license option: {selected}\n\n" + "\n\n".join(headers))
    text = declaration + "\n\n" + standard.read_text(encoding="utf-8")
    record["licenseSelection"] = selected
    record["texts"].append({"path": "Cargo.toml and source notices + standard license text",
                            "sha256": hashlib.sha256(text.encode()).hexdigest(),
                            "declarationSha256": digest(directory / "Cargo.toml"),
                            "standardLicenseSha256": digest(standard)})
    sections.append(f"{'=' * 72}\n{record['ecosystem']}: {record['name']} {record['version']}\n{text}\n")
    record.pop("noticeIssue", None)


def upstream_notices(repository, revision, record, sections):
    match = re.search(r"github\.com[/:]([^/]+/[^/#]+)", repository)
    if not match or not re.fullmatch(r"[a-f0-9]{40}", revision):
        raise ValueError("Missing exact upstream revision for supplementary notices")
    repository = match[1].removesuffix(".git")
    directory = WORK / "upstream-notices" / repository / revision
    marker = directory / "verified.json"
    if not marker.exists():
        entries = api(f"repos/{repository}/contents/?ref={revision}")
        for entry in entries:
            if re.match(r"^(?:LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICEN[CS]E)(?:S?$|[._-])", entry["name"], re.I):
                if entry["type"] == "dir":
                    github_directory(repository, revision, entry["path"], directory / safe_name(entry["name"]))
                elif entry["type"] == "file":
                    target = directory / safe_name(entry["name"])
                    download(entry["download_url"], target)
                    contents = target.read_bytes()
                    if hashlib.sha1(f"blob {len(contents)}\0".encode() + contents).hexdigest() != entry["sha"]:
                        raise ValueError("Supplementary notice Git blob mismatch")
        write_json(marker, {"repository": repository, "revision": revision})
    record["supplementaryNoticeOrigin"] = f"https://github.com/{repository}/tree/{revision}"
    add_notices(directory, record, sections)


def add_notices(directory, record, sections):
    candidates = []
    for path in directory.rglob("*"):
        relative = path.relative_to(directory)
        if len(relative.parts) > 3 or "node_modules" in relative.parts or path.is_symlink():
            continue
        if path.is_file() and (re.match(r"^(?:LICEN[CS]E|COPYING|COPYRIGHT|NOTICE|UNLICEN[CS]E)(?:$|[._-])", path.name, re.I)
                               or (path.name == "AUTHORS" and b"Permission is hereby granted" in path.read_bytes())
                               or any(part.lower() == "licenses" for part in relative.parts[:-1])):
            candidates.append(path)
    for path in sorted(candidates):
        if path.stat().st_size > 1024 * 1024:
            raise ValueError(f"Unexpectedly large license notice: {path}")
        text = path.read_text(encoding="utf-8", errors="replace")
        relative = path.relative_to(directory).as_posix()
        record["texts"].append({"path": relative, "sha256": digest(path)})
        if record["ecosystem"] == "npm" and path.is_relative_to(ROOT / "node_modules"):
            record["texts"][-1]["installedPath"] = path.relative_to(ROOT).as_posix()
        sections.append(f"{'=' * 72}\n{record['ecosystem']}: {record['name']} {record['version']}\n"
                        f"Declared license: {record['license']}\nFile: {relative}\n\n{text}\n")


def report():
    inputs = json.loads((EVIDENCE / "runtime-files.json").read_text(encoding="utf-8"))
    tracked = run("git", "ls-files", "--cached", "--others", "--exclude-standard", "-z").decode().split("\0")
    selected = [name for name in tracked if name in ("LICENSE", "COPYING", "NOTICE", "COMMERCIAL_LICENSE.txt", "docs/licensing.txt", "package.json", "package-lock.json",
                "src-tauri/Cargo.lock", "cli/Cargo.lock", "vault/Cargo.lock", "runtime/cuda/host/Cargo.lock")
                or name.startswith(("runtime/security/", "runtime/gpu/", "appliance/", "runtime/cuda/", "scripts/", "compliance/source-updates/"))]
    selected += ["NOTICE", "docs/licensing.txt", "docs/rebuilding-third-party.txt", "compliance/engineering-review.json", "compliance/source-cache.json", "src-tauri/resources/APPLICATION_LICENSES.txt",
                 "src-tauri/resources/THIRD_PARTY_NOTICES.txt", "src-tauri/resources/WORKSPACE_LICENSES.txt",
                 "src-tauri/Cargo.toml", "cli/Cargo.toml", "vault/Cargo.toml", "compliance/native.json"]
    selected += [path.relative_to(ROOT).as_posix() for path in (ROOT / "scripts").glob("*compliance*") if path.is_file()]
    selected += [path.relative_to(ROOT).as_posix() for path in EVIDENCE.glob("*") if path.is_file()]
    selected += [path.relative_to(ROOT).as_posix() for path in (ROOT / "compliance/notices").glob("*") if path.is_file()]
    selected += [path.relative_to(ROOT).as_posix() for path in (ROOT / "src-tauri").glob("tauri*.conf.json")]
    selected += frontend_inventory()["files"]
    selected += [".gitattributes", ".github/workflows/linux.yml"]
    selected += cargo_lockfiles(ROOT)
    selected += [str(Path(name).with_name("Cargo.toml")).replace("\\", "/") for name in cargo_lockfiles(ROOT)]
    if (ROOT / "src-tauri/resources/RUNTIME_LICENSES.txt").exists():
        selected.append("src-tauri/resources/RUNTIME_LICENSES.txt")
    for name in sorted(set(selected)):
        path = ROOT / name
        if path.is_file():
            contents = path.read_bytes()
            try:
                normalized = contents.decode("utf-8").replace("\r\n", "\n").replace("\r", "\n").encode()
            except UnicodeDecodeError:
                inputs.append({"path": name, "sha256": digest(path), "bytes": len(contents)})
            else:
                inputs.append({"path": name, "sha256": hashlib.sha256(normalized).hexdigest(),
                               "normalization": "lf", "bytes": len(normalized)})
    components = []
    for name in ("local", "application", "alpine", "msys", "go", "go-main", "debian"):
        source = WORK / f"{name}-sources.json"
        if source.exists():
            components += json.loads(source.read_text(encoding="utf-8"))
    archives = [{key: item[key] for key in ("file", "sha256", "bytes")} for item in components if item.get("status") == "collected"]
    dependencies = json.loads((EVIDENCE / "application-dependencies.json").read_text(encoding="utf-8"))
    for item in dependencies:
        if item.get("source"):
            archives.append(item["source"])
    blockers = [{"id": item["id"], "reason": item["reason"]} for item in components if item.get("status") == "blocked"]
    if not any(item.get("id") == "yougori-application-source" for item in components):
        blockers.append({"id": "yougori-application-source", "reason": "Collect the complete application source archive with the material action."})
    annotation_path = EVIDENCE / "qemu-modification-notices.json"
    if not annotation_path.exists():
        blockers.append({"id": "qemu-modification-notices", "reason": "Missing dated source modification notice verification."})
    else:
        annotation = json.loads(annotation_path.read_text(encoding="utf-8"))
        patch = ROOT / annotation["patch"]["path"]
        if (not patch.is_file() or digest(patch) != annotation["patch"]["sha256"]
                or not annotation.get("results") or not all(item.get("matches") for item in annotation["results"])):
            blockers.append({"id": "qemu-modification-notices", "reason": "Dated QEMU notice patch differs from its verified source evidence."})
    unresolved = [item for item in json.loads((EVIDENCE / "windows-dlls.json").read_text(encoding="utf-8"))
                  if item["provenance"] == "unresolved-exact-binary-source"]
    if unresolved:
        blockers.append({"id": "windows-dll-sources", "reason": f"{len(unresolved)} DLLs lack an exact source mapping."})
    component_ids = {item["id"] for item in components if item.get("status") == "collected"}
    for dll in json.loads((EVIDENCE / "windows-dlls.json").read_text(encoding="utf-8")):
        if "package" in dll and f"msys/{dll['package']}/{dll['version']}" not in component_ids:
            blockers.append({"id": "missing-source/" + dll["package"], "reason": "The current runtime package has no collected source record."})
    for part in ("qemu", "qemu-secure"):
        source_record = RUNTIME / part / "SOURCE_BUILD.json"
        if not source_record.exists():
            blockers.append({"id": part + "-source", "reason": "Missing source-build provenance."})
            continue
        record = json.loads(source_record.read_text(encoding="utf-8"))
        if record["revision"] != "84f07211cc5b4fc6a371559bf8a5de4fb068e648":
            blockers.append({"id": part + "-revision", "reason": "This QEMU revision needs its own source collection."})
        for patch in record["patches"]:
            try:
                matching_build_source(ROOT, patch["path"], patch["sha256"])
            except ValueError:
                blockers.append({"id": part + "/" + patch["path"], "reason": "Bundled runtime provenance differs from local source."})
        for name in ("libdb-6.2.dll", "libjack64.dll", "brlapi-0.8.dll", "libssp-0.dll"):
            if (RUNTIME / part / name).exists():
                blockers.append({"id": part + "/" + name, "reason": "The retired stock dependency has returned; review is required."})
    for required in ("debian/glibc/2.41-12+deb13u3", "debian/libseccomp/2.6.0-2", "debian/btrfs-progs/6.14-1"):
        if required not in component_ids:
            blockers.append({"id": required, "reason": "Missing source for an OCI native-library input."})
    missing = [item for item in dependencies if not item["texts"]]
    if missing:
        blockers.append({"id": "application-notices", "reason": f"{len(missing)} lockfile dependencies still need notice review (includes build-only/other-target entries). See evidence/application-dependencies.json."})
    runtime_notices = EVIDENCE / "runtime-notices.json"
    if runtime_notices.exists():
        missing_runtime = [item for item in json.loads(runtime_notices.read_text(encoding="utf-8")) if not item["texts"]]
        if missing_runtime:
            blockers.append({"id": "runtime-notices", "reason": f"{len(missing_runtime)} source/package entries have no recognized standalone notice in the collected inputs. Review applicable notices; see evidence/runtime-notices.json."})
    else:
        blockers.append({"id": "runtime-notices", "reason": "Runtime dependency notice inventory has not been collected."})
    review_file = ROOT / "compliance/engineering-review.json"
    review = json.loads(review_file.read_text(encoding="utf-8")) if review_file.exists() else {"status": "pending"}
    review_fingerprint, review = reviewed_scope(ROOT, inputs, archives, review)
    result = {"schemaVersion": 1, "sourceCommit": run("git", "rev-parse", "HEAD").decode().strip(),
              "sourceCommitMeaning": "Collection base revision; exact candidate contents are identified by the application source manifest, including uncommitted reviewed changes. Public release metadata requires a clean committed checkout.",
              "scope": "Current checkout runtime bytes; not a blanket certification of previous releases",
              "inputs": inputs, "archives": sorted(archives, key=lambda item: item["file"]),
              "components": components, "blockers": blockers,
              "reviewFingerprint": review_fingerprint, "review": review, "publication": {"status": "not-published"},
              "historicalReleaseIssues": [{"id": "older-installer-coverage", "reason": "Older installer payloads, including the retired stock QEMU build, need their own source records. This new runtime does not retroactively establish their coverage. See compliance/history."}]}
    write_json(ROOT / "compliance/release.json", result)
    write_source_index(result)
    size = sum(item["bytes"] for item in archives)
    print(f"Recorded {len(archives)} source archives ({size / 1024**3:.2f} GiB); {len(blockers)} unresolved items.", flush=True)


def write_source_index(result):
    sums = "".join(f"{item['sha256']}  {item['file']}\n" for item in result["archives"])
    (BUNDLE / "SHA256SUMS").write_text(sums, encoding="utf-8", newline="\n")
    write_json(BUNDLE / "SOURCE_INDEX.json", {key: result[key] for key in ("schemaVersion", "scope", "archives", "components", "blockers")}, canonical=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("inventory", "alpine", "local", "notices", "msys", "go", "material", "cache", "report"))
    parser.add_argument("--retry-blocked", action="store_true", help="For msys, reuse unchanged already collected archives")
    args = parser.parse_args()
    WORK.mkdir(parents=True, exist_ok=True)
    BUNDLE.mkdir(parents=True, exist_ok=True)
    {"inventory": inventory, "alpine": collect_alpine, "local": collect_local,
     "notices": dependency_notices, "msys": lambda: collect_msys(args.retry_blocked), "go": collect_go,
     "material": refresh_build_material, "cache": prepare_cache, "report": report}[args.action]()


if __name__ == "__main__":
    main()
