"""Strix's registered process backend, only inside the outer Yougori Sandbox VM: Strix's own image,
or the Yougori harness's shared base image with Strix's pack delivered into it.

Its own options pass through unchanged: the Yougori harness gives it a --target for each target
and an --instruction with the setup brief (profiles.py). Strix works in the workspace and keeps its
runs in the home; each run's report, findings and log are copied into the workspace's
reports/strix, so they come back to the person's folder after their review."""
import asyncio
import functools
import importlib
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time

# Strix's sandbox is this VM, not a container beside the person's computer: a target on loopback
# (the practice app) is this VM's own, so it is not rewritten to Docker's host gateway name.
HOST_GATEWAY = '127.0.0.1'
MARKER = Path('/opt/solver/harness-name')
# Strix keeps each run in strix_runs, in the folder it works in, with the run's state beside its
# report: agents.db, SQLite in WAL mode, which needs the shared memory maps that the VM's workspace
# does not offer ("disk I/O error" before the first turn). Its runs go to the home (RUNS) instead,
# and all of each run but its state (STATE) goes to the workspace's reports/strix (REPORTS).
RUNS = 'strix'
REPORTS = Path('reports/strix')
STATE = '.state'


def allowed_here(marker=MARKER, environment=None, platform=None):
    """Whether this is a Yougori VM that holds Strix: Strix's own image, or the Yougori harness's
    shared base image (harness-name `yougori`) with Strix's pack delivered (SOLVER_HARNESS)."""
    if (platform or sys.platform) != 'linux':
        return False
    try:
        image = Path(marker).read_text(encoding='utf-8').strip()
    except OSError:
        return False
    chosen = (os.environ if environment is None else environment).get('SOLVER_HARNESS')
    return image == 'strix' or (image == 'yougori' and chosen == 'strix')


async def backend(*,image,manifest,exposed_ports,bind_mounts=None):
    if bind_mounts:
        raise ValueError('Host mounts are not part of the Inference Solver runtime.')
    from agents.sandbox.manifest import Environment
    from agents.sandbox.sandboxes.unix_local import UnixLocalSandboxClient,UnixLocalSandboxClientOptions
    from agents.sandbox.workspace_paths import SandboxPathGrant
    root = Path('/home/node/strix-workspace'); root.mkdir(exist_ok=True)
    grants = tuple(SandboxPathGrant(path=str(Path(entry.src).resolve(strict=True)),read_only=True)
                   for entry in manifest.entries.values() if getattr(entry,'src',None))
    environment = Environment(value={**manifest.environment.value,'HOST_GATEWAY':HOST_GATEWAY})
    manifest = manifest.model_copy(update={'root':str(root),'extra_path_grants':grants,'environment':environment},deep=True)
    # The SDK's "local" process is inside the outer VM. Its environment is the
    # small guest environment supplied by vm_guest, never the user's host one.
    client = UnixLocalSandboxClient()
    session = await client.create(manifest=manifest,options=UnixLocalSandboxClientOptions(exposed_ports=exposed_ports))
    await session.start()
    return client,session


def keep_runs(folder):
    """Strix's runs go to `folder`/strix_runs, whichever folder Strix works in: every helper of
    strix.core.paths joins its RUNS_DIR_NAME to that folder, and an absolute name takes its place.
    The runs folder."""
    from strix.core import paths
    runs = Path(folder)/'strix_runs'
    paths.RUNS_DIR_NAME = str(runs)
    return runs


class Reports:
    """Copies Strix's runs (`runs`, a folder each) into the workspace's reports/strix (`target`), all
    of each but its state. A file goes again only once it changed."""

    def __init__(self, runs, target):
        self.runs, self.target, self.copied = Path(runs), Path(target), {}

    def copy(self):
        try:
            files = sorted(path for path in self.runs.rglob('*') if path.is_file() and not path.is_symlink())
        except OSError:
            return
        for source in files:
            relative = source.relative_to(self.runs)
            if relative.parts[1:2] == (STATE,):
                continue
            try:
                status = source.stat()
                seen = (status.st_size, status.st_mtime_ns)
                if self.copied.get(relative) == seen:
                    continue
                destination = self.target/relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source, destination)
                self.copied[relative] = seen
            except OSError:
                continue


def copy_after_saves(state, reports):
    """After each save of a run (`state`'s save_run_data: as the run starts, at each finding, as it
    ends and when Strix is stopped), the run goes to the workspace too, so what Strix saved comes
    back however the session ends."""
    saved = state.save_run_data

    @functools.wraps(saved)
    def save_run_data(self, *args, **kwargs):
        try:
            return saved(self, *args, **kwargs)
        finally:
            reports.copy()
    state.save_run_data = save_run_data


def main():
    if not allowed_here():
        raise ValueError('Launch this adapter with solver-strix inside Yougori.')
    from strix.runtime.backends import register_backend
    from strix.runtime import session_manager
    from strix.interface import scan_setup
    from strix.report.state import ReportState
    entry = importlib.import_module('strix.interface.main')
    register_backend('yougori_vm',backend)
    session_manager._WORKSPACE_ROOT='/home/node/strix-workspace'
    scan_setup.HOST_GATEWAY_HOSTNAME=HOST_GATEWAY
    reports = Reports(keep_runs(Path.home()/RUNS), Path.cwd()/REPORTS)
    copy_after_saves(ReportState, reports)
    # The enclosing VM supplies isolation. Do not probe a host container engine
    # or download an image during runtime. Packages update only at build time.
    entry.check_docker_installed=lambda: None
    entry.pull_docker_image=lambda: None
    entry.start_background_check=lambda: None
    entry.prompt_update_if_available=lambda *_: False
    arguments=sys.argv[1:]
    if arguments[:1] == ['--print']:
        if len(arguments)!=2: raise ValueError('Use --print followed by one prompt.')
        target=Path.home()/'strix-check'; target.mkdir(exist_ok=True)
        (target/'README.md').write_text('A local fixture. No external target is configured.\n')
        arguments=['--non-interactive','--target',str(target),'--instruction',arguments[1]]
    sys.argv=['strix',*arguments]
    with (Path.home()/'caido.log').open('w') as log:
        sidecar=subprocess.Popen(['/opt/solver/tool/bin/caido-cli','--listen','127.0.0.1:48080','--allow-guests','--no-logging','--no-open'],stdout=log,stderr=log)
        try:
            for _ in range(120):
                if sidecar.poll() is not None: raise ValueError('Caido stopped; inspect ~/caido.log inside the VM.')
                try:
                    with socket.create_connection(('127.0.0.1',48080),timeout=1): break
                except OSError: time.sleep(.25)
            else: raise ValueError('Caido startup timed out.')
            entry.main()
        finally:
            sidecar.terminate()
            try: sidecar.wait(timeout=5)
            except subprocess.TimeoutExpired: sidecar.kill(); sidecar.wait()
            reports.copy()
            if reports.copied and os.environ.get('SOLVER_EMPTY_WORKSPACE')!='1':
                print("Strix's report is in reports/strix in the workspace. It comes back to your folder after your review.",flush=True)


if __name__=='__main__': main()
