"""A persistent, private model process inside an existing Linux pod."""
import fcntl
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

children = {}


def root_dir():
    root = Path.home() / '.local' / 'share' / 'yougori-model'
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or root.stat().st_uid != os.getuid():
        raise ValueError('Model directory must belong to this account')
    root.chmod(0o700)
    return root


def identity(pid):
    try:
        # A PID plus Linux start time prevents stopping an unrelated reused PID.
        fields = Path('/proc', str(pid), 'stat').read_text().rsplit(')', 1)[1].split()
        return fields[19] if fields[0] != 'Z' else None
    except (OSError, IndexError):
        return None


def running(root):
    try:
        saved = json.loads((root / 'process.json').read_text())
        if saved['start'] is not None and identity(saved['pid']) == saved['start']:
            return saved
    except (OSError, ValueError, KeyError):
        pass
    return None


def request(action, body):
    for pid, child in list(children.items()):
        if child.poll() is not None:
            children.pop(pid, None)
    root = root_dir()
    with open(root / 'lock', 'a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        current = running(root)
        if action == 'status':
            if not current:
                return {'running': False, 'status': 'error', 'error': 'The model process stopped. Check `yougori logs POD_NAME`, then use `yougori model chat POD_NAME` to restart it.'}
            token = body.get('token')
            if token is None:
                return {'running': True}
            req = urllib.request.Request('http://127.0.0.1:8000/health', headers={'Authorization': 'Bearer ' + token})
            try:
                # Ignore proxy environment variables: this is only the pod's own loopback server.
                with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req, timeout=2) as response:
                    result = json.loads(response.read(65536))
                    result['running'] = True
                    return result
            except urllib.error.HTTPError:
                raise ValueError('The model rejected its API key. Check which Yougori installation owns this pod.')
            except (OSError, urllib.error.URLError):
                return {'running': True, 'status': 'starting'}
        if action == 'logs':
            try:
                with open(root / 'server.log', 'rb') as log:
                    log.seek(0, 2)
                    log.seek(max(0, log.tell() - 65536))
                    return log.read().decode('utf-8', 'replace')
            except FileNotFoundError:
                return ''
        if action == 'stop':
            if current:
                if json.loads((root / 'config.json').read_text())['token'] != body.get('token'):
                    raise ValueError('This model belongs to another Yougori installation')
                try:
                    os.killpg(current['pid'], signal.SIGTERM)
                except ProcessLookupError:
                    pass
                for _ in range(50):
                    if not running(root):
                        break
                    time.sleep(.1)
                if running(root):
                    try:
                        os.killpg(current['pid'], signal.SIGKILL)
                    except ProcessLookupError:
                        pass
            (root / 'process.json').unlink(missing_ok=True)
            if current and current['pid'] in children:
                children.pop(current['pid']).wait(timeout=5)
            return {'stopped': True}
        if action != 'run':
            raise ValueError('Unknown model operation')
        model, token = body['model'], body['token']
        model_format = body.get('format', 'safetensors')
        if model_format not in ('safetensors', 'vllm'):
            raise ValueError('Unsupported model runner')
        revision=body.get('revision')
        if revision is not None and not re.fullmatch(r'[a-f0-9]{40}',revision):
            raise ValueError('Model revision must be an immutable checkpoint SHA')
        if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', model) or not re.fullmatch(r'[a-f0-9]{64}', token):
            raise ValueError('Invalid model configuration')
        if current:
            if current['model'] != model:
                raise ValueError('This pod already runs ' + current['model'] + '. Stop that model before choosing another.')
            # Refuse a second local client whose saved key differs from this process.
            saved = json.loads((root / 'config.json').read_text())
            if saved['token'] != token:
                raise ValueError('This pod has a model managed by another Yougori installation')
            return {'reused': True}
        probe = socket.socket()
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(('127.0.0.1', 8000))
        except OSError:
            raise ValueError('Port 8000 is in use in this pod. Stop that service before running the model.')
        finally:
            probe.close()
        source = body['source']
        if not isinstance(source, str) or len(source) > 262144:
            raise ValueError('Invalid model server')
        hf_token = body.get('hfToken')
        if hf_token is not None and (not isinstance(hf_token, str) or not 1 <= len(hf_token) <= 1024 or any(char in hf_token for char in '\r\n\0')):
            raise ValueError('Invalid protected Hugging Face token; value withheld')
        for name, data in [('server.py', source), ('config.json', json.dumps({'model': model, 'token': token, 'revision':revision, 'hfToken':hf_token, 'format':model_format}))]:
            path = root / name
            with open(path, 'w', opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)) as file:
                file.write(data)
            path.chmod(0o600)
        # The isolated Python environment can reuse CUDA PyTorch already installed in the pod.
        bootstrap = '''import json, os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
python = root / 'venv' / 'bin' / 'python'
if not python.exists():
    subprocess.run([sys.executable, '-m', 'venv', '--system-site-packages', str(root / 'venv')], check=True)
config = json.loads((root / 'config.json').read_text())
os.environ.update(YOUGORI_MODEL=config['model'], YOUGORI_MODEL_TOKEN=config['token'],
    YOUGORI_MODEL_BIND='127.0.0.1', YOUGORI_INSTALL_TORCH='1',
    HF_HOME=str(root / 'cache'), HF_HUB_DISABLE_TELEMETRY='1')
os.environ['YOUGORI_MODEL_FORMAT']=config.get('format','safetensors')
os.environ['YOUGORI_INSTALL_VLLM']='1' if config.get('format')=='vllm' else '0'
if config.get('revision'):
    os.environ['YOUGORI_MODEL_REVISION']=config['revision']
if config.get('hfToken'):
    os.environ['HF_TOKEN']=config['hfToken']
(root / 'cache').mkdir(exist_ok=True)
os.execv(str(python), [str(python), '-u', str(root / 'server.py')])
'''
        with open(root / 'server.log', 'wb') as log:
            process = subprocess.Popen([sys.executable, '-u', '-c', bootstrap, str(root)],
                                       stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
        saved = {'pid': process.pid, 'start': identity(process.pid), 'model': model}
        children[process.pid] = process
        (root / 'process.json').write_text(json.dumps(saved))
        time.sleep(.2)
        if process.poll() is not None:
            raise ValueError('Model startup failed. Check model logs (the pod needs Python venv support).')
        return {'reused': False}
