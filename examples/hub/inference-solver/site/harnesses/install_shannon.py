"""Build-time adaptation of the pinned Shannon worker; no container runtime."""
import hashlib
from pathlib import Path
import shutil
import subprocess
import tarfile

# Shannon's pi extension that bounds every bash call (BASH_TIMEOUT at the pinned commit) refuses a
# call that gives no timeout, and only tells the model to use 120 seconds (DEFAULT_TIMEOUT_SECONDS)
# next time. Gemma left the timeout out 31 times in a row (round 2, pre-recon attempt 2), each call was
# refused in 0-1 ms and nothing ran. A call without one runs with that default instead: pi hands a
# tool_call handler the arguments the tool then runs with (event.input), so setting it there is
# enough. The default is within Shannon's limit (MAX_TIMEOUT_SECONDS, 600); a timeout above it is
# refused as before. The file must be the pinned one byte for byte, so a new pin is looked at again.
BASH_TIMEOUT = 'apps/worker/src/ai/extensions/bash-timeout/index.ts'
BASH_TIMEOUT_SHA256 = '7ae5bff6adb69a8afb6c469b906bbf2c8bd359d59cded2ee4f39964e99f0b3fa'
BASH_TIMEOUT_CHECK = '    return evaluateBashTimeout(event.input.timeout);\n'
BASH_TIMEOUT_DEFAULT = '    if (event.input.timeout == null) event.input.timeout = DEFAULT_TIMEOUT_SECONDS;\n'


def replace(path,before,after):
    text=path.read_text()
    if text.count(before)!=1: raise ValueError('Pinned Shannon source changed: '+str(path))
    path.write_text(text.replace(before,after))


def default_bash_timeout(source):
    """Shannon's bash-timeout extension gives a bash call without a timeout its default of 120
    seconds instead of refusing it. Refuses an extension that is not the pinned commit's."""
    path=Path(source)/BASH_TIMEOUT
    pinned=path.read_bytes()
    if hashlib.sha256(pinned).hexdigest()!=BASH_TIMEOUT_SHA256:
        raise ValueError('Pinned Shannon source changed: '+str(path))
    text=pinned.decode('utf-8')
    path.write_bytes(text.replace(BASH_TIMEOUT_CHECK,BASH_TIMEOUT_DEFAULT+BASH_TIMEOUT_CHECK).encode('utf-8'))


def build(source,spec):
    replace(source/'apps/worker/src/paths.ts',"export const MODELS_CONFIG_PATH = '/app/models.json';",
            "export const MODELS_CONFIG_PATH = process.env.SHANNON_SOLVER_MODELS || '/app/models.json';")
    replace(source/'apps/worker/src/ai/models.ts','allowModelNetwork: true,','allowModelNetwork: false,')
    default_bash_timeout(source)
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
