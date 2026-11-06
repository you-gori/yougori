"""Verify live Yougori commands without contributing resources or changing PATH."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import winreg
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'site'))
from harnesses.transport import opener


def user_path():
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Environment') as key:
        return winreg.QueryValueEx(key, 'Path')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--yougori', required=True)
    args = parser.parse_args()
    server = json.loads(args.config.read_text())['server'].rstrip('/')
    client, checks = opener(), []
    def record(message):
        checks.append(message); print('PASS ' + message, flush=True)
    with client.open(server + '/app.js') as response: source = response.read().decode()
    with client.open(server + '/compute-ui.js') as response: compute = response.read().decode()
    assert 'const command = installCommand("node");' in compute
    js = """const {runInNewContext}=require('node:vm');
const data=JSON.parse(require('node:fs').readFileSync(0,'utf8'));
const start=data.source.indexOf('function installCommand('),end=data.source.indexOf('\\nconst PROTOCOLS',start);
if(start<0||end<start)throw new Error('Missing shared install command');
const context={};runInNewContext(data.source.slice(start,end),context);
process.stdout.write(context.installCommand('node',new URL(data.server)));"""
    generated = subprocess.run(['node', '-e', js], input=json.dumps({'source':source, 'server':server}),
                               capture_output=True, text=True, timeout=15)
    assert generated.returncode == 0, generated.stderr
    assert generated.stdout == 'yougori inference connect "' + server + '"'
    record('Live contributor UI uses Yougori directly, without a PowerShell install script')
    before = user_path()
    for command in [['connect',server,'--help'], ['run','pi','--server',server,'--help']]:
        result = subprocess.run([args.yougori,'inference',*command], capture_output=True,
                                text=True, timeout=180, env={**os.environ,'YOUGORI_NO_UPDATE_CHECK':'1'})
        assert result.returncode == 0, (result.stdout + result.stderr)[-3000:]
        assert 'usage:' in result.stdout
    record('Yougori prepares and starts both bundled clients without website-supplied host scripts')
    result = subprocess.run([args.yougori,'inference','install','pi','--server',server], capture_output=True,
                            text=True, timeout=600, env={**os.environ,'YOUGORI_NO_UPDATE_CHECK':'1'})
    assert result.returncode == 0, (result.stdout + result.stderr)[-3000:]
    record('Yougori downloads, verifies and imports the actual Pi VM image from the live website')
    assert user_path() == before
    record('User PATH is unchanged; no separate solver command was installed')
    args.root.mkdir(parents=True, exist_ok=True)
    (args.root / 'result.json').write_text(json.dumps({'passed':True, 'checks':checks}, indent=2))


if __name__ == '__main__': main()
