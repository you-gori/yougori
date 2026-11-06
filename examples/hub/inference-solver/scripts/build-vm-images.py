"""Publisher-only OCI packaging with Buildah on Linux. No Docker daemon.

Run in a disposable Linux build machine/WSL build distro, before user accounts
or projects are attached. Downloaded harnesses require only Yougori, not Buildah.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1] / "site/harnesses"


def normalize_layout(folder):
    # Older Buildah omits optional OCI document mediaType/platform fields.
    # Yougori deliberately requires these; normalize and rehash before publishing.
    index = json.loads((folder / "index.json").read_text())
    index["mediaType"] = "application/vnd.oci.image.index.v1+json"
    for descriptor in index["manifests"]:
        old = folder / "blobs/sha256" / descriptor["digest"].split(":")[1]
        manifest = json.loads(old.read_text())
        manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
        raw = json.dumps(manifest, separators=(",", ":")).encode()
        digest = hashlib.sha256(raw).hexdigest()
        (folder / "blobs/sha256" / digest).write_bytes(raw)
        descriptor.update(digest="sha256:" + digest, size=len(raw), platform={"os": "linux", "architecture": "amd64"})
        if old.name != digest:
            old.unlink()
    (folder / "index.json").write_text(json.dumps(index, separators=(",", ":")))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("names", nargs="+")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--draft", action="store_true", help="Build a pinned adapter awaiting runtime validation; does not enable website downloads")
    parser.add_argument("--split-tools", action="store_true", help="Deliver a verified tool archive through the private VM control connection")
    parser.add_argument("--reuse-tools", action="store_true", help="Refresh only runtime Python from an existing same-pin image; do not use after installer or OS dependency edits")
    args = parser.parse_args()
    specs = json.loads((ROOT / "packages.json").read_text())
    args.output.mkdir(parents=True, exist_ok=True)
    for name in args.names:
        if name not in specs or (specs[name].get("blocked") and not args.draft) or not specs[name].get("kind"):
            raise ValueError("Choose an implemented harness.")
        spec = {k:v for k,v in specs[name].items() if k != "blocked"}
        tag = "localhost/inference-solver-vm-" + name
        if args.reuse_tools:
            prior=json.loads(subprocess.check_output(['buildah','inspect','--type','image',tag],text=True))
            env=prior['OCIv1']['config']['Env']
            saved=next((v.removeprefix('TOOL_SPEC=') for v in env if v.startswith('TOOL_SPEC=')),None)
            if not saved or json.loads(saved)!=spec: raise ValueError('Existing tool image has different pins; run a full build.')
        else:
            subprocess.run(["buildah", "bud", "--isolation", "oci", "--layers", "--format", "oci",
                "--build-arg", "HARNESS=" + name, "--build-arg", "TOOL_SPEC=" + json.dumps(spec), "-f", str(ROOT / "Containerfile"), "-t", tag, str(ROOT)], check=True)
        with tempfile.TemporaryDirectory(prefix="solver-oci-", dir=args.output) as temp:
            # Flatten build layers with Buildah's commit --squash before publication;
            # discarded dependency trees must not occupy the runtime/import budget.
            container = subprocess.check_output(["buildah", "from", tag], text=True).strip()
            tool = None
            try:
                if args.reuse_tools:
                    runtime=('relay.py','transport.py','blue.py','profiles.py','runtime.py','vm_guest.py','vm_package.py','vm_tunnel.py','hexstrike_cli.py','plandex_cli.py','strix_cli.py','shannon_cli.py','pentagi_cli.py')
                    subprocess.run(['buildah','copy',container,*[str(ROOT/file) for file in runtime],'/opt/solver/'],check=True)
                if args.split_tools:
                    mounted=Path(subprocess.check_output(['buildah','mount',container],text=True).strip())
                    if name == 'shannon':
                        # Headless Chromium needs fonts/libraries, not desktop
                        # icon and MIME catalogs (thousands of OCI entries).
                        for relative in ('usr/share/icons','usr/share/mime','var/lib/dpkg','usr/share/perl','usr/share/perl5'):
                            unused=mounted/relative
                            if unused.is_symlink(): unused.unlink()
                            elif unused.exists(): shutil.rmtree(unused)
                    source=mounted/'opt/solver/tool.tar.gz'
                    with source.open('rb') as stream: tool_hash=hashlib.file_digest(stream,'sha256').hexdigest()
                    tool={'sha256':tool_hash,'bytes':source.stat().st_size}
                    if not 0<tool['bytes']<=512<<20: raise ValueError('Tool package exceeds 512 MiB.')
                    destination=args.output/name;destination.mkdir(exist_ok=True)
                    shutil.copyfile(source,destination/(tool_hash+'.tar.gz'))
                    source.unlink()
                    (mounted/'opt/solver/tool-package.json').write_text(json.dumps(tool))
                    subprocess.run(['buildah','unmount',container],check=True)
                subprocess.run(["buildah", "commit", "--squash", "--format", "oci", container, tag + "-flat"], check=True)
            finally:
                subprocess.run(["buildah", "rm", container], check=True)
            flat = Path(temp) / "flat"
            subprocess.run(["buildah", "push", "--format", "oci", tag + "-flat", "oci:" + str(flat) + ":latest"], check=True)
            normalize_layout(flat)
            blobs = list((flat / "blobs/sha256").iterdir())
            if sum(p.stat().st_size for p in blobs) > 256 << 20:
                raise ValueError(name + " exceeds Yougori's 256 MiB image bound; it was not published.")
            archive = Path(temp) / "image.zip"
            with zipfile.ZipFile(archive, "w", zipfile.ZIP_STORED) as package:
                for path in sorted(flat.rglob("*")):
                    if path.is_file():
                        package.write(path, path.relative_to(flat).as_posix())
            digest = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
            destination = args.output / name
            destination.mkdir(exist_ok=True)
            archive.replace(destination / (digest + ".zip"))
            record = {"sha256": digest, "bytes": (destination / (digest + ".zip")).stat().st_size,
                      "version": specs[name]["version"], "platform": "linux/amd64", "runtime": "yougori-sandbox-vm"}
            if tool: record['tool']=tool
            temporary = destination / "image.json.partial"
            temporary.write_text(json.dumps(record, indent=2))
            temporary.replace(destination / "image.json")
            print("Prepared " + name + " for Yougori Sandbox VM", flush=True)


if __name__ == "__main__":
    main()
