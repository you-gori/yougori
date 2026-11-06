"""Strix's registered process backend, only inside the outer Yougori Sandbox VM."""
import asyncio
import importlib
import os
from pathlib import Path
import socket
import subprocess
import sys
import time


async def backend(*,image,manifest,exposed_ports,bind_mounts=None):
    if bind_mounts:
        raise ValueError('Host mounts are not part of the Inference Solver runtime.')
    from agents.sandbox.sandboxes.unix_local import UnixLocalSandboxClient,UnixLocalSandboxClientOptions
    from agents.sandbox.workspace_paths import SandboxPathGrant
    root = Path('/home/node/strix-workspace'); root.mkdir(exist_ok=True)
    grants = tuple(SandboxPathGrant(path=str(Path(entry.src).resolve(strict=True)),read_only=True)
                   for entry in manifest.entries.values() if getattr(entry,'src',None))
    manifest = manifest.model_copy(update={'root':str(root),'extra_path_grants':grants},deep=True)
    # The SDK's "local" process is inside the outer VM. Its environment is the
    # small guest environment supplied by vm_guest, never the user's host one.
    client = UnixLocalSandboxClient()
    session = await client.create(manifest=manifest,options=UnixLocalSandboxClientOptions(exposed_ports=exposed_ports))
    await session.start()
    return client,session


def main():
    if sys.platform != 'linux' or Path('/opt/solver/harness-name').read_text().strip() != 'strix':
        raise ValueError('Launch this adapter with solver-strix inside Yougori.')
    from strix.runtime.backends import register_backend
    from strix.runtime import session_manager
    entry = importlib.import_module('strix.interface.main')
    register_backend('yougori_vm',backend)
    session_manager._WORKSPACE_ROOT='/home/node/strix-workspace'
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


if __name__=='__main__': main()
