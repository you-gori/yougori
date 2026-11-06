"""Check a running VM site's public packages and a portable Windows installation.

--config is a private JSON file containing {"server": "http://TOKEN.localhost:PORT"}.
No user login, API key, persistent PATH or model is changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'site/harnesses'))
from transport import opener
from vm_host import artifact_base, install, preflight


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--python-zip', type=Path, required=True)
    args = parser.parse_args()
    server = json.loads(args.config.read_text())['server']
    p = urlsplit(server)
    args.root.mkdir(parents=True, exist_ok=True)
    client = opener()
    checks = []
    def record(message): checks.append(message); print('PASS ' + message, flush=True)
    with client.open(server + '/api/harnesses') as response: catalog = json.load(response)['harnesses']
    available = [item['id'] for item in catalog if item['setup']['available']]
    assert available, 'No harness packages are advertised'
    for name in available:
        with client.open(server + '/api/harness-image/' + name) as response: spec = json.load(response)
        base = artifact_base(server, spec)
        for kind, value in [('image', spec), ('tool', spec.get('tool'))]:
            if not value: continue
            path = base + '/' + name + '/' + value['sha256'] + ('/tool' if kind == 'tool' else '')
            total, digest = 0, hashlib.sha256()
            with client.open(path, timeout=180) as response:
                assert response.getheader('Set-Cookie') is None
                while block := response.read(1 << 20):
                    total += len(block); digest.update(block)
            assert total == value['bytes'] and digest.hexdigest() == value['sha256'], name + ': invalid package'
        record(name + ': full image/tool downloads match their checksums')
    runtime_hash = '90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159'
    with args.python_zip.open('rb') as stream: assert hashlib.file_digest(stream, 'sha256').hexdigest() == runtime_hash
    folder = args.root / 'portable-cli'
    (folder / 'cache').mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.python_zip, folder / 'cache' / (runtime_hash + '.zip'))
    env = {**os.environ, 'INFERENCE_SOLVER_HOME': str(folder), 'INFERENCE_SOLVER_NO_PATH': '1',
           'INFERENCE_SOLVER_NO_LAUNCH': '1', 'LOCALAPPDATA': str(args.root / 'profile')}
    command = "irm 'http://127.0.0.1:" + str(p.port) + "/install/pi.ps1' -Headers @{Host='" + p.netloc + "'} | iex"
    ps = str(Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe')
    result = subprocess.run([ps, '-NoProfile', '-NonInteractive', '-Command', command], env=env, capture_output=True, text=True, timeout=180)
    assert result.returncode == 0, (result.stdout + result.stderr).replace(server, '[instance]')[-3000:]
    assert 'Installed solver-pi' in result.stdout
    record('PowerShell 5.1 installs the server-bound Pi command from the VM origin')
    owner = json.loads((folder / 'bin/solver-pi.owner.json').read_text())
    assert owner['server'] == server
    release = folder / 'releases' / owner['release'] / 'inference-solver'
    assert (release / 'transport.py').is_file()
    preflight('pi', server)
    image_root = args.root / 'pi-image'; image_root.mkdir(exist_ok=True)
    identity = install('pi', server, image_root)
    assert identity.startswith('sha256:')
    record('Pi downloads, verifies and imports its real image through the running Yougori engine')
    (args.root / 'result.json').write_text(json.dumps({'checks': checks, 'passed': True}, indent=2))


if __name__ == '__main__': main()
