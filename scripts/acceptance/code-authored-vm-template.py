"""Opt-in real VM capture/install test. Uses only disposable fixture VMs and secrets.

Run against the newly built dev engine with --cli PATH --output ABSOLUTE_DIRECTORY.
Imports python:3.12-slim if needed; no public publication or cloud rental.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cli', required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    root = args.output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    checks, owned = [], []
    instance = 'author-check-' + str(int(time.time()))
    attempted_install = False

    def command(words, body=None, timeout=600):
        result = subprocess.run([args.cli, *words], input=None if body is None else json.dumps(body),
                                text=True, encoding='utf-8', capture_output=True, timeout=timeout,
                                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
                                env={**os.environ, 'YOUGORI_NO_UPDATE_CHECK': '1'})
        try:
            reply = json.loads(result.stdout)
        except ValueError:
            raise RuntimeError('CLI returned non-JSON output for ' + ' '.join(words[:3])) from None
        if result.returncode or not reply.get('ok'):
            raise RuntimeError(reply.get('error', 'CLI operation failed'))
        return reply['result']

    def vm(action, **params):
        return command(['call', 'sandbox_vm', '--file', '-', '--yes'], {'action': action, **params})

    def execute(sandbox, code):
        result = vm('exec', sandbox=sandbox, input=code, timeoutSeconds=30, maxOutputBytes=8192)
        assert result['exit_code'] == 0, 'Guest fixture command failed'
        return result.get('output_text', '')

    def record(name):
        checks.append(name)
        (root / 'result.json').write_text(json.dumps({'checks': checks}, indent=2), encoding='utf-8')
        print('PASS ' + name, flush=True)

    def current():
        return vm('status')['sandboxes']

    try:
        before = {entry['sandbox'] for entry in current()}
        image = vm('image', operation='import', reference='docker.io/library/python:3.12-alpine', ownerSelected=True)
        for name, port in [('website', 3000), ('models', 8081)]:
            source = root / name
            source.mkdir()
            app = f'''from yougori import Setup
from pathlib import Path
import hashlib
from http.server import BaseHTTPRequestHandler, HTTPServer
setup=Setup('{name}',image='docker.io/library/python@{image['id']}',files=['app.py'],command=['python','app.py'])
setup.admin()
setup.checkbox('signup','Allow signup?')
setup.grid('sandbox',when='signup')
@setup.on_setup
def initialize(values):
    if values['admin_email']=='fail@example.com': raise ValueError('fixture hook failed')
    print('startup logging ' * 6000, flush=True)
    with open('hook-count','a') as stream: stream.write('x')
    Path('admin-hash').write_text(hashlib.sha256(values['admin_password'].encode()).hexdigest())
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.end_headers(); self.wfile.write(b'{name}-ready')
    def log_message(self,*args): pass
setup.run(lambda values: HTTPServer(('0.0.0.0',{port}), Handler).serve_forever())
'''
            (source / 'app.py').write_text(app, encoding='utf-8')
            launched = vm('launch', image=image['id'], runEntrypoint=False, workspace=str(source),
                          memoryGb=2, cpu=1, idleSeconds=0, lifetimeSeconds=0,
                          publish=f'{name}={port}', **({'connect': 'models=8081'} if name == 'website' else {}))
            owned.append(launched['sandbox'])
            execute(owned[-1], 'cd "$WORKSPACE" && python app.py\n')
        vm('connect', sandbox=owned[0], endpoint='models', to=owned[1], service='models')
        preview = vm('template', operation='preview', sandboxes=owned, name='author-fixture')
        assert len(preview['sandboxes']) == 2 and len(preview['questions']) == 6
        assert preview['sandboxes'][0]['connections'] == ['models']
        exported = vm('template', operation='export', sandboxes=owned, name='author-fixture',
                      digest=preview['digest'], folder=str(root / 'package'))
        record('Two actual VM declarations and their connection captured')
        execute(owned[0], 'cd "$WORKSPACE" && printf "\\n# changed\\n" >> app.py\n')
        try:
            vm('template', operation='export', sandboxes=owned, name='author-fixture', digest=preview['digest'], folder=str(root / 'stale'))
        except RuntimeError as error:
            assert 'changed' in str(error)
        else:
            raise AssertionError('Changed source was exported with stale review')
        record('Changed source invalidates capture approval')
        for sandbox in owned:
            vm('stop', sandbox=sandbox)
        package = exported['folder']
        command(['template', 'check', package])
        answers = {'vm1_admin_email': 'owner@example.com', 'vm2_admin_email': 'owner@example.com',
                   'vm1_signup': False, 'vm2_signup': True}
        (root / 'inputs.json').write_text(json.dumps(answers), encoding='utf-8')
        secrets = {'vm1_admin_password': 'fixture-password-one', 'vm2_admin_password': 'fixture-password-two'}
        attempted_install = True
        try:
            command(['template', 'run', package, '--name', instance, '--inputs', str(root / 'inputs.json'),
                     '--secrets', '-', '--yes'], secrets)
        except RuntimeError as error:
            if 'Registry request failed' not in str(error):
                raise
            (root / 'registry-retry.json').write_text(json.dumps({'first_attempt': str(error)}), encoding='utf-8')
            command(['template', 'continue', instance, '--yes'])
        recipient = [entry['sandbox'] for entry in current() if entry['sandbox'] not in before and entry['sandbox'] not in owned and entry['phase'] == 'ready']
        owned.extend(recipient)
        assert len(recipient) == 2, 'Installation must create exactly two user VMs'
        roles = {}
        for sandbox in recipient:
            name = execute(sandbox, 'cd "$WORKSPACE" && python -c "import json; print(json.load(open(\'.yougori/setup.json\'))[\'name\'])"\n').strip()
            roles[name] = sandbox
            assert execute(sandbox, 'cd "$WORKSPACE" && cat hook-count\n').strip() == 'x'
            password = secrets['vm1_admin_password' if name == 'website' else 'vm2_admin_password']
            assert execute(sandbox, 'cd "$WORKSPACE" && cat admin-hash\n').strip() == hashlib.sha256(password.encode()).hexdigest()
        assert 'models-ready' in execute(roles['website'], 'python -c "import urllib.request; print(urllib.request.urlopen(\'http://models:8081\').read().decode())"\n')
        record('Shared installer ran hooks and apps; website reaches models over captured grant')
        grid_status = json.loads(execute(roles['models'], 'yougori grid status\n'))
        assert grid_status['enabled'] == ['cpu', 'memory']
        fingerprint = 'cd "$WORKSPACE" && python -c "import hashlib; print(hashlib.sha256(open(\'.yougori-grid/config.json\',\'rb\').read()).hexdigest())"\n'
        grid_identity = execute(roles['models'], fingerprint).strip()
        assert execute(roles['website'], 'test ! -f "$WORKSPACE/.yougori-grid/config.json" && echo disabled\n').strip() == 'disabled'
        record('Installer checkbox starts Sandbox Grid only in the selected VM')
        for file in (root / 'package').rglob('*'):
            if file.is_file():
                assert not any(secret.encode() in file.read_bytes() for secret in secrets.values())
        record('Private installer answers absent from exported package')
        for sandbox in recipient:
            execute(sandbox, 'cd "$WORKSPACE" && printf retained > private-state\n')
        command(['template', 'stop', instance])
        command(['template', 'start', instance])
        restarted = [entry['sandbox'] for entry in current() if entry['sandbox'] not in before and entry['sandbox'] not in owned and entry['phase'] == 'ready']
        owned.extend(restarted)
        assert len(restarted) == 2
        for sandbox in restarted:
            assert execute(sandbox, 'cd "$WORKSPACE" && cat private-state\n').strip() == 'retained'
            assert execute(sandbox, 'cd "$WORKSPACE" && cat hook-count\n').strip() == 'x'
            if 'models' in execute(sandbox, 'cd "$WORKSPACE" && python -c "import json; print(json.load(open(\'.yougori/setup.json\'))[\'name\'])"\n'):
                assert execute(sandbox, fingerprint).strip() == grid_identity
                assert json.loads(execute(sandbox, 'yougori grid status\n'))['enabled'] == ['cpu', 'memory']
        record('Stop/start keeps private data and does not repeat completed setup hooks')
        # Exercise the actual application start failure path with fresh configuration.
        failed = vm('launch', image=image['id'], runEntrypoint=False, workspace=str(root / 'website'), memoryGb=2)
        owned.append(failed['sandbox'])
        execute(failed['sandbox'], 'cd "$WORKSPACE" && python app.py\n')
        try:
            vm('application', sandbox=failed['sandbox'], argv=['python', 'app.py'],
               secret=json.dumps({'admin_email': 'fail@example.com', 'admin_password': 'fixture-password-fail'}))
        except RuntimeError as error:
            assert 'during setup' in str(error) and 'fixture-password-fail' not in str(error)
        else:
            raise AssertionError('A failing setup was reported ready')
        record('Real failed setup is refused without exposing answers')
    finally:
        if attempted_install:
            try:
                command(['template', 'rm', instance, '--yes', '--delete-data'])
            except Exception:
                pass
        cleanup_errors = []
        for sandbox in reversed(owned):
            for action, params in [('stop', {}), ('workspace', {'op': 'discard'})]:
                try:
                    vm(action, sandbox=sandbox, **params)
                except Exception as error:
                    if action == 'workspace' and 'has no workspace.' in str(error):
                        continue  # template rm --delete-data already removed it
                    cleanup_errors.append({'sandbox': sandbox, 'action': action, 'error': str(error)})
        (root / 'cleanup.json').write_text(json.dumps(cleanup_errors, indent=2), encoding='utf-8')
        if cleanup_errors:
            print('Review cleanup.json for refused cleanup operations.', flush=True)


if __name__ == '__main__':
    main()
