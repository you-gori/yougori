"""Shannon's worker and Temporal service inside one networkless Yougori VM."""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlsplit


def parser():
    parser = argparse.ArgumentParser(description='Shannon, connected only to Inference Solver. Targets must run inside this VM.')
    parser.add_argument('--model',required=True)
    parser.add_argument('--target',help='HTTP service already running inside this VM')
    parser.add_argument('--validate-model',action='store_true')
    parser.add_argument('--config',type=Path)
    parser.add_argument('--context-budget',type=int,default=32768)
    parser.add_argument('--verbose',action='store_true',help='Show internal worker logs')
    return parser


def target_url(value):
    target = urlsplit(value)
    if target.scheme not in ('http','https') or target.hostname not in ('127.0.0.1','localhost','::1') or target.username or target.password:
        raise ValueError('The target must run inside this VM. External networking is disabled.')
    return value


def stop_worker(process):
    # Stop children too: another task in this same VM must not inherit a previous
    # worker's activity processes. The process has its own Linux session/group.
    try: os.killpg(process.pid,signal.SIGTERM)
    except ProcessLookupError: pass
    try: process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass
        process.wait()
    finally:
        # The parent may have exited before an activity child. Reap the whole
        # task group even when that child ignored TERM.
        try: os.killpg(process.pid,signal.SIGKILL)
        except ProcessLookupError: pass


def worker(command,environment,source,log_path,verbose=False):
    lines=queue.Queue(maxsize=256)
    with log_path.open('w',encoding='utf-8') as log:
        process=subprocess.Popen(command,env=environment,cwd=source,stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,text=True,encoding='utf-8',errors='replace',
                                 start_new_session=True)
        def read():
            for line in process.stdout: lines.put(line)
            lines.put(None)
        threading.Thread(target=read,daemon=True).start()
        began=time.monotonic()
        next_update=began+10
        try:
            while True:
                try: line=lines.get(timeout=1)
                except queue.Empty: line=''
                if line is None: break
                if line:
                    log.write(line);log.flush()
                    if verbose: print(line,end='',flush=True)
                    elif line.startswith(('Model validated.', 'Scan completed', 'Scan failed', 'Duration:', 'Agents resolved:', 'Total turns:')):
                        print(line.rstrip(),flush=True)
                if not verbose and time.monotonic()>=next_update:
                    print('Shannon is working... '+str(int(time.monotonic()-began))+'s',flush=True)
                    next_update=time.monotonic()+10
            code=process.wait()
            if code:
                print('Shannon stopped with an error (exit '+str(code)+'). Details: '+str(log_path),flush=True)
            return code
        finally:
            stop_worker(process)
            process.stdout.close()


HELP = '''Commands
  check           Check the model connection; no scan
  shell           Open a shell inside this VM; type exit to return
  scan URL        Run Shannon against a service already running inside this VM
  logs            Show the last worker log
  help            Show these commands
  exit            Close Shannon and stop this VM

The prepared VM stays open between commands. External networking is blocked.
Use solver-shannon --workspace "C:\\path\\to\\project" to work on a project copy.'''


def session(args):
    print('\n\x1b[34mShannon | Inference Solver\x1b[0m\nModel: '+args.model+'\n\n'+HELP,flush=True)
    while True:
        try:
            command=input('\nshannon> ').strip()
            if not command: continue
            words=shlex.split(command)
            if words in (['exit'],['quit']): return 0
            if words==['help']: print(HELP,flush=True)
            elif words==['shell']:
                print('VM shell. Start your local service here; type exit to return to Shannon.',flush=True)
                subprocess.call(['/bin/sh','-i'])
            elif words==['logs']:
                path=Path.home()/'shannon-worker.log'
                print(path.read_text(encoding='utf-8') if path.is_file() else 'No worker has run in this session.',flush=True)
            elif words==['check'] or (len(words)==2 and words[0]=='scan'):
                scan=words[0]=='scan'
                if scan and os.environ.get('SOLVER_EMPTY_WORKSPACE')=='1':
                    print('Select a project first: solver-shannon --workspace "C:\\path\\to\\project"',flush=True)
                    continue
                target=target_url(words[1]) if scan else None
                code=run_once(argparse.Namespace(**{**vars(args),'target':target,'validate_model':not scan}))
                if code: print('Type logs for details or check to retry the connection.',flush=True)
            else: print('Unknown command. Type help.',flush=True)
        except (EOFError,KeyboardInterrupt):
            print('\nClosing Shannon.',flush=True)
            return 0
        except (ValueError,OSError) as error:
            print(str(error),flush=True)


def run_once(args):
    validation_site = None
    workspace = Path.cwd()
    if not args.target:
        if not args.validate_model:
            raise ValueError('--target is required for a scan; use --validate-model to check the selected model only.')
        # Upstream's model-only check also validates a repository and HTTP target.
        # Supply an explicit, disposable local fixture, never an external target.
        workspace = Path.home()/'shannon-model-check'
        workspace.mkdir(exist_ok=True)
        (workspace/'README.md').write_text('Local model-connection check. No scan is requested.\n')
        class Check(BaseHTTPRequestHandler):
            def log_message(self,*_): pass
            def do_GET(self):
                self.send_response(200);self.send_header('Content-Length','2');self.end_headers();self.wfile.write(b'OK')
        validation_site = ThreadingHTTPServer(('127.0.0.1',0),Check)
        threading.Thread(target=validation_site.serve_forever,daemon=True).start()
        args.target = 'http://127.0.0.1:'+str(validation_site.server_port)
    target_url(args.target)
    if not 4096 <= args.context_budget <= 131072:
        raise ValueError('Choose a context budget from 4096 to 131072 tokens that fits your model.')
    home = Path.home()
    source = Path('/opt/solver/source')
    # Upstream's --output accepts only its container-specific /app/output mount.
    # Keep its canonical run directory inside the staged guest workspace instead.
    reports = workspace/'.shannon/runs'
    reports.mkdir(parents=True,exist_ok=True)
    runs = source/'workspaces'
    if runs.is_dir() and not runs.is_symlink() and {p.name for p in runs.iterdir()} <= {'.gitkeep'}:
        (runs/'.gitkeep').unlink(missing_ok=True)
        runs.rmdir()  # Only the upstream package's empty placeholder.
    if runs.is_symlink():
        if runs.resolve() != reports.resolve():
            # Check and task reports stay in their own directories. Only retarget
            # our link after the preceding worker has ended; never delete reports.
            allowed={(home/'shannon-model-check/.shannon/runs').resolve(),(Path.cwd()/'.shannon/runs').resolve()}
            if runs.resolve() not in allowed: raise ValueError('Shannon has an unrelated report directory; it was preserved.')
            runs.unlink();runs.symlink_to(reports,target_is_directory=True)
    elif not runs.exists():
        runs.symlink_to(reports,target_is_directory=True)
    else:
        raise ValueError('Shannon already has a run directory. Start a new VM session.')
    config = home/'shannon-models.json'
    # The local endpoint implements chat completions, not OpenAI's storage or
    # reasoning extensions. Pi otherwise assumes those extensions from the URL.
    # A connection check needs a short answer, not the scan's full output budget.
    model = {'id':args.model,'contextWindow':args.context_budget,
             'maxTokens':128 if args.validate_model else min(4096,args.context_budget//4),
             'compat':{'supportsStore':False,'supportsDeveloperRole':False,
                       'supportsReasoningEffort':False,'supportsLongCacheRetention':False,
                       'maxTokensField':'max_tokens'}}
    config.write_text(json.dumps({'providers':{'solver':{'baseUrl':'http://127.0.0.1:8080/v1','api':'openai-completions',
        'apiKey':'solver-local-relay','models':[model]}}}))
    environment = {**os.environ,'SHANNON_AI_MODEL':'solver:'+args.model,'SHANNON_AI_API_KEY':'solver-local-relay',
        'SHANNON_AI_BASE_URL':'http://127.0.0.1:8080/v1','SHANNON_SOLVER_MODELS':str(config),
        'TEMPORAL_ADDRESS':'127.0.0.1:7233','PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD':'1',
        'PLAYWRIGHT_MCP_EXECUTABLE_PATH':'/usr/bin/chromium','PI_CODING_AGENT_DIR':str(home/'.pi/agent')}
    command = ['node',str(source/'apps/worker/dist/temporal/worker.js'),args.target,str(workspace),
               '--task-queue','solver-'+uuid.uuid4().hex]
    if args.validate_model: command.append('--validate-model')
    if args.config: command += ['--config',str(args.config.resolve(strict=True))]
    with (home/'shannon-temporal.log').open('w') as log:
        process = subprocess.Popen(['/opt/solver/tool/bin/temporal','server','start-dev','--ip','127.0.0.1',
                                    '--headless','--db-filename',str(home/'shannon-temporal.sqlite')],stdout=log,stderr=log)
        try:
            for _ in range(240):
                if process.poll() is not None: raise ValueError('Temporal stopped; inspect ~/shannon-temporal.log inside the VM.')
                try:
                    with socket.create_connection(('127.0.0.1',7233),timeout=1): break
                except OSError: time.sleep(.25)
            else: raise ValueError('Temporal startup timed out.')
            print('Checking the model connection...' if args.validate_model else 'Running Shannon on '+args.target+'...',flush=True)
            return worker(command,environment,source,home/'shannon-worker.log',args.verbose)
        finally:
            if validation_site: validation_site.shutdown();validation_site.server_close()
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait()


def main():
    args=parser().parse_args()
    if not 4096<=args.context_budget<=131072:
        raise ValueError('Choose a context budget from 4096 to 131072 tokens that fits your model.')
    if not args.target and not args.validate_model: return session(args)
    return run_once(args)


if __name__=='__main__': sys.exit(main())
