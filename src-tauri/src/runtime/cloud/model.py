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
# G08 remote delivery: what one model run may carry of helper bundles.
HELPER_FILES, HELPER_BYTES = 64, 32 * 1024 * 1024
HELPER_PATH = re.compile(r'[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}(/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}){0,7}')
# vLLM tool-call parsers for agent tool calling: only Swarm workers on a rented GPU ask for one.
TOOL_PARSERS = ('hermes', 'qwen3_coder', 'llama3_json', 'openai', 'gemma4')
# The vLLM launch modes the engine saves (model_runner/optimizer.rs LAUNCHES) and the form a
# megakernel runner takes on a pod: a public Hugging Face repository pinned to a commit.
LAUNCHES = ('compiled', 'speculative', 'eager', 'megakernel')
RUNNER_REFERENCE = r'hf:[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9][A-Za-z0-9._-]*@[0-9a-f]{40}'


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


def helper_delivery(root, delivery):
    """Writes the helper bundles the engine delivered under a fresh `helpers` directory after
    checking every file's SHA-256 and the bounds, removing an earlier delivery; returns the
    variables that name them for the runner. No delivery removes an earlier one."""
    import shutil
    target = root / 'helpers'
    staging = root / 'helpers.new'
    if staging.is_symlink() or target.is_symlink():
        raise ValueError('Invalid helpers directory')
    shutil.rmtree(staging, ignore_errors=True)
    if delivery is None:
        shutil.rmtree(target, ignore_errors=True)
        return {}
    if not isinstance(delivery, dict) or set(delivery) != {'files', 'named', 'shadow'}:
        raise ValueError('Invalid helper delivery')
    files, named, shadow = delivery['files'], delivery['named'], delivery['shadow']
    if not isinstance(files, list) or not 1 <= len(files) <= HELPER_FILES:
        raise ValueError('Invalid helper delivery')
    staging.mkdir(mode=0o700)
    try:
        variables = write_delivery(staging, target, files, named, shadow)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    shutil.rmtree(target, ignore_errors=True)
    os.rename(staging, target)
    variables['YOUGORI_HELPERS_ROOT'] = str(target)
    return variables


def write_delivery(staging, target, files, named, shadow):
    """Checks and writes `files` under `staging`; the variables naming `named` and `shadow`
    under `target`, where `staging` becomes the delivery."""
    import base64, hashlib
    written, total = set(), 0
    for item in files:
        if not isinstance(item, dict) or set(item) != {'path', 'data', 'sha256'}:
            raise ValueError('Invalid helper file')
        path = item['path']
        if not isinstance(path, str) or not HELPER_PATH.fullmatch(path) or '..' in path.split('/') or path in written:
            raise ValueError('Invalid helper file path')
        try:
            data = base64.b64decode(item['data'], validate=True)
        except (TypeError, ValueError):
            raise ValueError('Invalid helper file') from None
        total += len(data)
        if total > HELPER_BYTES:
            raise ValueError('The helper delivery is larger than a model run carries')
        if not isinstance(item['sha256'], str) or hashlib.sha256(data).hexdigest() != item['sha256']:
            raise ValueError('A delivered helper file failed its checksum; nothing was installed')
        destination = staging / path
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        with open(destination, 'xb', opener=lambda p, flags: os.open(p, flags | os.O_NOFOLLOW, 0o600)) as file:
            file.write(data)
        written.add(path)
    variables = {}
    for name, entries in (('YOUGORI_HELPERS', named), ('YOUGORI_HELPERS_SHADOW', shadow)):
        if not isinstance(entries, dict) or len(entries) > 16:
            raise ValueError('Invalid helper delivery')
        resolved = {}
        for helper, entry in entries.items():
            if (not isinstance(helper, str) or not re.fullmatch(r'[a-z][a-z0-9-]{0,63}', helper) or not isinstance(entry, dict)
                    or set(entry) != {'entry', 'pin'} or entry['entry'] not in written
                    or not isinstance(entry['pin'], str) or not re.fullmatch(r'[a-f0-9]{64}', entry['pin'])):
                raise ValueError('Invalid helper entry')
            resolved[helper] = {'entry': str(target / entry['entry']), 'pin': entry['pin']}
        if resolved:
            variables[name] = json.dumps(resolved)
    return variables


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
        tool_parser = body.get('toolParser')
        if tool_parser is not None and (model_format != 'vllm' or tool_parser not in TOOL_PARSERS):
            raise ValueError('Unsupported tool-call parser')
        # The vLLM launch mode and megakernel runner saved for the model (the engine's optimizer).
        launch, runner = body.get('launch'), body.get('runner')
        if launch is not None and (model_format != 'vllm' or launch not in LAUNCHES):
            raise ValueError('Unsupported launch mode')
        if runner is not None and (model_format != 'vllm' or not isinstance(runner, str) or not re.fullmatch(RUNNER_REFERENCE, runner)):
            raise ValueError('A pod runner is a public Hugging Face repository at a commit: hf:OWNER/REPO@COMMIT')
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
            # A server with agent tool calling also serves plain chat; one without cannot serve an agent.
            if tool_parser and saved.get('toolParser') != tool_parser:
                started = 'with a different tool-call parser' if saved.get('toolParser') else 'without agent tool calling'
                raise ValueError('This pod already runs ' + model + ' ' + started + '. Stop its model, then retry.')
            if (launch, runner) != (saved.get('launch'), saved.get('runner')):
                raise ValueError('This pod already runs ' + model + ' with another launch. Stop its model, then retry.')
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
        admin_token = body.get('adminToken')
        if admin_token is not None and (not isinstance(admin_token, str) or not re.fullmatch(r'[a-f0-9]{64}', admin_token)):
            raise ValueError('Invalid model configuration')
        helpers = helper_delivery(root, body.get('helpers'))
        for name, data in [('server.py', source), ('config.json', json.dumps({'model': model, 'token': token, 'adminToken': admin_token, 'revision':revision, 'hfToken':hf_token, 'format':model_format, **({'toolParser': tool_parser} if tool_parser else {}), **({'launch': launch} if launch else {}), **({'runner': runner} if runner else {}), **({'helpers': helpers} if helpers else {})}))]:
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
if config.get('adminToken'):
    os.environ['YOUGORI_MODEL_ADMIN_TOKEN']=config['adminToken']
if config.get('toolParser'):
    os.environ['YOUGORI_TOOL_PARSER']=config['toolParser']
if config.get('launch'):
    os.environ['YOUGORI_MODEL_LAUNCH']=config['launch']
if config.get('runner'):
    os.environ['YOUGORI_MODEL_RUNNER']=config['runner']
os.environ.update(config.get('helpers') or {})
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
