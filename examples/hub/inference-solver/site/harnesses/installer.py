"""Build-time only installer; runs before any credentials or workspace are mounted."""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import urllib.request
HERE = Path(__file__).resolve().parent

def install(name):
    if name == "relay":
        return
    spec = json.loads(os.environ["TOOL_SPEC"]) if os.getenv("TOOL_SPEC") else json.loads((HERE / "packages.json").read_text())[name]
    if spec.get("blocked"):
        raise ValueError(spec["blocked"])
    if spec["kind"] == "npm":
        subprocess.run(["npm", "install", "--prefix", "/opt/solver/tool", "--no-audit", "--no-fund",
                        spec["package"] + "@" + spec["version"]], check=True, stdin=subprocess.DEVNULL)
    elif spec["kind"] in ("pip", "git", "hexstrike", "plandex", "strix", "shannon", "pentagi"):
        subprocess.run([sys.executable, "-m", "venv", "--copies", "/opt/solver/tool"], check=True)
        requirement = [spec["package"] + "==" + spec["version"]] if spec["kind"] in ("pip","strix") else ["-e", "/opt/solver/source"]
        if spec["kind"] in ("git", "hexstrike", "plandex", "shannon", "pentagi"):
            source = Path("/opt/solver/source")
            source.mkdir()
            subprocess.run(["git", "init", str(source)], check=True)
            subprocess.run(["git", "-C", str(source), "remote", "add", "origin", spec["repository"]], check=True)
            subprocess.run(["git", "-C", str(source), "fetch", "--depth=1", "origin", spec["commit"]], check=True)
            subprocess.run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"], check=True)
            actual = subprocess.check_output(["git", "-C", str(source), "rev-parse", "HEAD"], text=True).strip()
            if actual != spec["commit"]:
                raise ValueError("Source revision did not match the pin.")
        if spec["kind"] == "shannon":
            from install_shannon import build
            build(source,spec)
            return
        if spec["kind"] == "pentagi":
            from install_pentagi import build
            build(source,spec)
            return
        if spec["kind"] == "plandex":
            import shutil
            # Upstream drops BaseModelConfig on an ordinary retry, then
            # dereferences it. Preserve the current model so errors stay errors.
            fallback = source/'app/shared/ai_models_errors.go'
            before = '\treturn FallbackResult{\n\t\tModelRoleConfig: m,\n\t\tIsFallback:      false,\n\t}'
            text = fallback.read_text()
            if text.count(before) != 1: raise ValueError('Pinned Plandex retry implementation changed.')
            fallback.write_text(text.replace(before,before.replace('ModelRoleConfig: m,','ModelRoleConfig: m,\n\t\tBaseModelConfig: m.GetBaseModelConfig(authVars, settings, orgUserConfig),')))
            target = Path("/opt/solver/tool")
            environment = {**os.environ,"CGO_ENABLED":"1","GOCACHE":"/home/node/.cache/go"}
            for component, name in (("cli","plandex"),("server","plandex-server")):
                subprocess.run(["go","build","-trimpath","-ldflags","-s -w -X plandex-cli/version.Version=2.2.1",
                                "-o",str(target/"bin"/name),"."],cwd=source/"app"/component,env=environment,check=True)
            shutil.copytree(source/"app/server/migrations",target/"migrations")
            (target/"bin/version.txt").write_text("2.2.1")
            shutil.copy2(source/"LICENSE",target/"PLANDEX-LICENSE")
            # Tokenization must work offline; cache upstream's two encodings.
            for encoding in ("cl100k_base","o200k_base"):
                url="https://openaipublic.blob.core.windows.net/encodings/"+encoding+".tiktoken"
                cache=target/"tokenizer"; cache.mkdir(exist_ok=True)
                with urllib.request.urlopen(url,timeout=120) as response:
                    raw=response.read(20*1024*1024+1)
                if len(raw)>20*1024*1024: raise ValueError("Tokenizer too large.")
                (cache/hashlib.sha1(url.encode()).hexdigest()).write_bytes(raw)
            shutil.rmtree(source)
            return
        if spec["kind"] == "hexstrike":
            requirement = spec["requirements"]
            # Upstream's health route launches a command process for every
            # executable on every probe. Probe PATH directly instead; capability
            # reporting stays truthful and readiness does not exhaust the VM.
            server = source / "hexstrike_server.py"
            original = 'result = execute_command(f"which {tool}", use_cache=True)\n            tools_status[tool] = result["success"]'
            patched = server.read_text()
            if patched.count(original) != 1:
                raise ValueError("Pinned HexStrike health check changed; review the adapter.")
            patched = patched.replace(original, 'tools_status[tool] = __import__("shutil").which(tool) is not None')
            server.write_text(patched)
            mcp_source = source / "hexstrike_mcp.py"
            patched = mcp_source.read_text()
            original = 'mcp = FastMCP("hexstrike-ai-mcp")'
            if patched.count(original) != 1:
                raise ValueError("Pinned HexStrike MCP setup changed; review the adapter.")
            # The VM deliberately refuses project credential files, including
            # .env. All runtime configuration is supplied by our profile.
            patched = patched.replace(original, 'from mcp.server.fastmcp.server import Settings\n    Settings.model_config["env_file"] = None\n    '+original)
            mcp_source.write_text(patched)
            # Keep upstream executable sources and license, excluding Git history
            # and screenshots from the immutable runtime artifact.
            import shutil
            for child in source.iterdir():
                if child.name not in ("hexstrike_server.py","hexstrike_mcp.py","LICENSE","README.md"):
                    if child.is_dir(): shutil.rmtree(child)
                    else: child.unlink()
        subprocess.run(["/opt/solver/tool/bin/pip", "install", "--disable-pip-version-check",
                        *requirement, *spec.get("extra", [])], check=True)
        if spec["kind"] == "strix":
            asset = spec["caido"]
            archive = Path("/opt/solver/caido.tar.gz")
            subprocess.run(["curl","--fail","--location","--max-time","180","--output",str(archive),asset["url"]],check=True)
            if hashlib.file_digest(archive.open("rb"),"sha256").hexdigest() != asset["sha256"]:
                raise ValueError("Caido official release checksum did not match.")
            with tarfile.open(archive) as package:
                matches = [m for m in package.getmembers() if m.isfile() and Path(m.name).name == "caido-cli"]
                if len(matches) != 1: raise ValueError("Caido executable missing from pinned release.")
                target = Path("/opt/solver/tool/bin/caido-cli")
                target.write_bytes(package.extractfile(matches[0]).read()); target.chmod(0o755)
            archive.unlink()
    elif spec["kind"] in ("release", "binary"):
        arch = "arm64" if platform.machine() in ("aarch64", "arm64") else "amd64"
        if arch not in spec["assets"]:
            raise ValueError("This pinned tool release is not packaged for " + arch)
        asset = spec["assets"][arch]
        cached = Path.home() / ".cache/solver-artifacts" / asset["sha256"]
        if cached.is_file():
            raw = cached.read_bytes()
        else:
            with urllib.request.urlopen(asset["url"], timeout=120) as response:
                raw = response.read(300 * 1024 * 1024 + 1)
        if len(raw) > 300 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != asset["sha256"]:
            raise ValueError("Official release checksum did not match.")
        cached.parent.mkdir(parents=True, exist_ok=True)
        cached.write_bytes(raw)
        if spec["kind"] == "binary":
            target = Path("/opt/solver/tool/bin") / spec["binary"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(raw)
            target.chmod(0o755)
            return
        with tarfile.open(fileobj=io.BytesIO(raw)) as archive:
            found = [m for m in archive.getmembers() if m.isfile() and Path(m.name).name == spec["binary"]]
            if len(found) != 1:
                raise ValueError("Official release does not contain the expected executable.")
            target = Path("/opt/solver/tool/bin") / spec["binary"]
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(found[0]).read())
            target.chmod(0o755)


if __name__ == "__main__":
    install(sys.argv[1])
