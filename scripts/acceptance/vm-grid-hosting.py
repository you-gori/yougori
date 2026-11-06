"""Opt-in live validation on disposable Sandbox VMs; no public exposure or rental.

Use --cli PATH --output DIRECTORY and optionally --image DIGEST and --model-env ID.
The optional model must already exist and be stopped; it is stopped again afterwards.
Credentials stay in the private output directory and are removed after the run.
"""
import argparse
import http.client
import json
import os
from pathlib import Path
import subprocess
import time
from urllib.parse import urlsplit


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cli', required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--image')
    ap.add_argument('--model-env')
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    checks, vms, processes = [], [], []
    model_started = False

    def cli(words, body=None, timeout=180):
        p = subprocess.run([args.cli, *words], input=json.dumps(body) if body is not None else '',
                           text=True, capture_output=True, timeout=timeout,
                           env={**os.environ, 'YOUGORI_NO_UPDATE_CHECK': '1'})
        try:
            value = json.loads(p.stdout)
        except ValueError:
            raise RuntimeError('CLI returned a non-JSON result') from None
        if p.returncode or not value.get('ok'):
            raise RuntimeError(value.get('error', 'CLI operation failed'))
        return value['result']

    def vm(body, wait=True):
        return cli(['call', 'sandbox_vm', '--file', '-', '--yes', *([] if wait else ['--no-wait'])], body)

    def execute(sandbox, script):
        result = vm({'action': 'exec', 'sandbox': sandbox, 'input': script,
                     'timeoutSeconds': 30, 'maxOutputBytes': 32768})
        if result.get('exit_code') != 0:
            raise RuntimeError('Guest grid command failed: ' + result.get('output_text', ''))
        return result.get('output_text', '')

    def request(base, path, key=None, body=None, expected=None):
        u = urlsplit(base)
        assert u.scheme == 'http' and (u.hostname.endswith('.localhost') or u.hostname == '127.0.0.1')
        conn = http.client.HTTPConnection('127.0.0.1', u.port, timeout=10)
        headers = {'Host': u.netloc, 'Content-Type': 'application/json'}
        if key:
            headers['Authorization'] = 'Bearer ' + key
        conn.request('POST' if body is not None else 'GET', u.path.rstrip('/') + path,
                     json.dumps(body) if body is not None else None, headers)
        res = conn.getresponse()
        raw = res.read(1048577)
        conn.close()
        if (expected is not None and res.status != expected) or (expected is None and res.status >= 300):
            raise RuntimeError(f'HTTP {res.status}')
        return json.loads(raw)

    def record(name):
        checks.append(name)
        print('PASS ' + name, flush=True)

    try:
        launch = vm({'action': 'launch', 'cpu': 1, 'memoryGb': 1,
                     'gridHosting': ['gpu', 'sandbox']})
        sandbox = launch['sandbox']
        vms.append(sandbox)
        assert launch['grid_hosting']['enabled'] == ['gpu', 'sandbox']
        assert launch['grid_hosting']['gpu_passthrough'] is False
        text = execute(sandbox, 'command -v yougori; test -s "$WORKSPACE/.agents/skills/yougori-grid/SKILL.md"; echo SKILL_READY')
        assert '/run/yougori/bin/yougori' in text and 'SKILL_READY' in text
        record('Minimal VM installs the native command and skill with both grid selections')
        config = json.loads(execute(sandbox, 'cat "$WORKSPACE/.yougori-grid/config.json"'))
        vm({'action': 'exec', 'sandbox': sandbox, 'input': 'exec yougori grid serve',
            'timeoutSeconds': 0, 'maxOutputBytes': 4096}, wait=False)
        published = vm({'action': 'publish', 'sandbox': sandbox, 'service': 'grid',
                        'audience': 'owner', 'application': True, 'minutes': 0})
        base = published['url']
        for _ in range(30):
            try:
                status = request(base, '/status', config['adminToken'])
                break
            except (OSError, RuntimeError):
                time.sleep(.25)
        else:
            raise RuntimeError('Controller did not become ready')
        assert status['enabled'] == ['gpu', 'cpu', 'memory']
        record('Authenticated controller serves through an isolated owner publication')

        invite = request(base, '/invites', config['adminToken'], {})
        worker = request(base, '/worker/join', invite['token'], {
            'name': 'acceptance CPU/memory worker', 'capacity': {'cpu': 2, 'memoryGb': 4, 'gpu': 0},
            'models': [], 'kinds': ['sum']})
        job = request(base, '/jobs', config['adminToken'], {
            'kind': 'sum', 'resources': {'cpu': 2, 'memoryGb': 4, 'gpu': 0}, 'payload': [2, 3, 4]})
        claimed = request(base, '/worker/claim', worker['token'], {})['job']
        assert claimed['id'] == job['id']
        request(base, '/worker/complete', worker['token'], {'id': job['id'], 'result': sum(claimed['payload']), 'error': ''})
        assert request(base, '/jobs/' + job['id'], config['adminToken'])['result'] == 9
        record('CPU/memory resource matching and custom job completion work across the VM boundary')

        # The desktop uses these same bounded guest configuration commands.
        shown = execute(sandbox, 'yougori grid config')
        assert config['adminToken'] not in shown
        assert json.loads(shown)['enabled'] == ['gpu', 'sandbox']
        pending = request(base, '/jobs', config['adminToken'], {
            'kind': 'sum', 'resources': {'cpu': 1, 'memoryGb': 1, 'gpu': 0}, 'payload': [5]})
        assert request(base, '/worker/claim', worker['token'], {})['job']['id'] == pending['id']
        changed = json.loads(execute(sandbox, 'yougori grid configure --resources gpu'))
        assert changed['enabled'] == ['gpu']
        assert request(base, '/status', config['adminToken'])['enabled'] == ['gpu']
        request(base, '/worker/complete', worker['token'], {'id': pending['id'], 'result': 5}, expected=409)
        assert request(base, '/jobs/' + pending['id'], config['adminToken'])['state'] == 'failed'
        record('Live configuration disables Sandbox Grid and rejects an already-leased result')
        assert json.loads(execute(sandbox, 'yougori grid configure --resources none'))['enabled'] == []
        assert request(base, '/status', config['adminToken'])['enabled'] == []
        request(base, '/jobs', config['adminToken'], {'kind': 'sum', 'resources': {}, 'payload': [1]}, expected=400)
        record('Both grids can be disabled and zero-resource jobs cannot bypass all-off')
        assert json.loads(execute(sandbox, 'yougori grid configure --resources gpu,sandbox'))['enabled'] == ['gpu', 'sandbox']
        after = request(base, '/jobs', config['adminToken'], {
            'kind': 'sum', 'resources': {'cpu': 1, 'memoryGb': 1, 'gpu': 0}, 'payload': [7]})
        assert request(base, '/worker/claim', worker['token'], {})['job']['id'] == after['id']
        request(base, '/worker/complete', worker['token'], {'id': after['id'], 'result': 7})
        assert request(base, '/jobs/' + after['id'], config['adminToken'])['result'] == 7
        record('Reenabled grid accepts work with the original controller and worker credentials')

        if args.image:
            second = vm({'action': 'launch', 'cpu': 1, 'memoryGb': 2, 'image': args.image, 'gridHosting': ['sandbox']})
            vms.append(second['sandbox'])
            assert second['grid_hosting']['enabled'] == ['sandbox']
            installed = json.loads(execute(second['sandbox'], 'cat "$WORKSPACE/.yougori-grid/config.json"'))
            assert installed['enabled'] == ['cpu', 'memory']
            text = execute(second['sandbox'], '/run/yougori/bin/yougori grid --help 2>&1; test -s "$WORKSPACE/.agents/skills/yougori-grid/SKILL.md"; echo OCI_READY')
            assert 'OCI_READY' in text
            record('OCI VM receives only the selected resources and the same native tool/skill')

        if args.model_env:
            current = cli(['status'])
            original = next(row for row in current['environments']['list'] if row['id'] == args.model_env)
            assert original['status'] == 'stopped', 'Only an initially stopped test model may be used'
            cli(['env', 'start', args.model_env, '--yes'])
            model_started = True
            api = cli(['model', 'api', args.model_env])
            upstream, model_key = api['apiUrl'], api['apiKey']
            catalog = request(upstream, '/models', model_key)
            model = catalog['data'][0]['id']
            invite = request(base, '/invites', config['adminToken'], {})
            invite_file, key_file = args.output / 'invitation.private.json', args.output / 'model.private.key'
            invite_file.write_text(json.dumps(invite), encoding='utf-8')
            key_file.write_text(model_key, encoding='utf-8')
            worker_process = subprocess.Popen([args.cli, 'grid', 'contribute', '--server', base,
                '--join-file', str(invite_file), '--model-url', upstream, '--model', model,
                '--model-key-file', str(key_file), '--gpu', '1'], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
            processes.append(worker_process)
            job = request(base, '/jobs', config['adminToken'], {
                'kind': 'chat', 'model': model, 'resources': {'gpu': 1, 'cpu': 0, 'memoryGb': 0},
                'payload': {'messages': [{'role': 'user', 'content': 'Say hello in one short sentence.'}], 'max_tokens': 24, 'temperature': 0}})
            for _ in range(90):
                done = request(base, '/jobs/' + job['id'], config['adminToken'])
                if done['state'] in ('done', 'failed'):
                    break
                if worker_process.poll() is not None:
                    raise RuntimeError('Native contributor ended before completing its model job')
                time.sleep(1)
            assert done['state'] == 'done' and done['result']['choices'][0]['message']['content'], done.get('error')
            record('Native PC contributor discovers the existing model and completes inference for the VM grid')
            checks.append({'model': model, 'modelEnvironment': args.model_env})
    finally:
        for process in processes:
            process.terminate()
            process.wait(timeout=10)
        if model_started:
            cli(['env', 'stop', args.model_env, '--yes'])
        for sandbox in reversed(vms):
            vm({'action': 'stop', 'sandbox': sandbox})
            vm({'action': 'workspace', 'sandbox': sandbox, 'op': 'discard'})
        for name in ('invitation.private.json', 'model.private.key'):
            (args.output / name).unlink(missing_ok=True)
        (args.output / 'result.json').write_text(json.dumps({'checks': checks}, indent=2), encoding='utf-8')
    record('Disposable VMs stopped, test workspaces removed, contributor credentials deleted')


if __name__ == '__main__':
    main()
