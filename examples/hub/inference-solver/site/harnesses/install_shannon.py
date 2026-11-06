"""Build-time adaptation of the pinned Shannon worker; no container runtime."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile


def replace(path,before,after):
    text=path.read_text()
    if text.count(before)!=1: raise ValueError('Pinned Shannon source changed: '+str(path))
    path.write_text(text.replace(before,after))


def build(source,spec):
    replace(source/'apps/worker/src/paths.ts',"export const MODELS_CONFIG_PATH = '/app/models.json';",
            "export const MODELS_CONFIG_PATH = process.env.SHANNON_SOLVER_MODELS || '/app/models.json';")
    replace(source/'apps/worker/src/ai/models.ts','allowModelNetwork: true,','allowModelNetwork: false,')
    subprocess.run(['npm','install','--prefix','/opt/solver/build-tools','--ignore-scripts','pnpm@10.33.0'],check=True)
    pnpm='/opt/solver/build-tools/node_modules/.bin/pnpm'
    subprocess.run([pnpm,'install','--frozen-lockfile'],cwd=source,check=True)
    subprocess.run([pnpm,'--filter','@shannon/worker','run','build'],cwd=source,check=True)
    for directory in [source/'node_modules',*source.glob('apps/*/node_modules')]:
        if directory.exists(): shutil.rmtree(directory)
    subprocess.run([pnpm,'install','--frozen-lockfile','--prod'],cwd=source,check=True)
    subprocess.run(['npm','install','--prefix','/opt/solver/tool','--ignore-scripts','@playwright/cli@0.1.1'],check=True)
    for binary in ('temporal','typst'):
        archive=Path('/opt/solver')/(binary+'.archive')
        asset=spec[binary]
        subprocess.run(['curl','--fail','--location','--max-time','240','--output',str(archive),asset['url']],check=True)
        with archive.open('rb') as stream:
            if hashlib.file_digest(stream,'sha256').hexdigest()!=asset['sha256']: raise ValueError(binary+' release checksum mismatch.')
        with tarfile.open(archive) as package:
            files=[m for m in package.getmembers() if m.isfile() and Path(m.name).name==binary]
            if len(files)!=1: raise ValueError('Missing '+binary+' executable.')
            target=Path('/opt/solver/tool/bin')/binary
            target.write_bytes(package.extractfile(files[0]).read());target.chmod(0o755)
        archive.unlink()
    for name in ('save-deliverable','generate-totp','set-report-meta'):
        (Path('/opt/solver/tool/bin')/name).symlink_to(Path('../../source/apps/worker/dist/scripts')/(name+'.js'))
        (source/'apps/worker/dist/scripts'/(name+'.js')).chmod(0o755)
    for directory in (source/'.git',Path('/opt/solver/build-tools'),source/'assets',source/'benchmark',source/'sample-reports'):
        if directory.exists(): shutil.rmtree(directory)
    # Keep the pinned source, its complete licenses and notices with the runtime.
