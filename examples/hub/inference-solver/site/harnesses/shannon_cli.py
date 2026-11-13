"""Shannon's worker and Temporal service inside one networkless Yougori VM."""
import argparse
import contextlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import queue
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from urllib.parse import urlsplit


def parser():
    parser = argparse.ArgumentParser(description='Shannon, connected only to Inference Solver. Targets run inside this VM, '
                                                 'or are ones this VM reaches.')
    parser.add_argument('--model',required=True)
    parser.add_argument('--target',action='append',help='HTTP service inside this VM, or one this VM reaches; '
                        'repeat it to scan several in turn, after which Shannon stays open in a terminal')
    parser.add_argument('--validate-model',action='store_true')
    parser.add_argument('--config',type=Path)
    parser.add_argument('--context-budget',type=int,default=32768)
    parser.add_argument('--max-output',type=int,default=4096,help="The model's longest reply, in tokens")
    parser.add_argument('--verbose',action='store_true',help='Show internal worker logs')
    return parser


LOOPBACK = ('127.0.0.1','localhost','::1')
# Shannon commits each checkpoint of its deliverables to a git repository of their own, and the VM
# has no git identity, so every commit failed and the scan ended GIT_CHECKPOINT_FAILED. Its worker
# commits as Yougori, never as the person.
GIT_IDENTITY = {'GIT_AUTHOR_NAME':'Yougori','GIT_AUTHOR_EMAIL':'yougori@localhost',
                'GIT_COMMITTER_NAME':'Yougori','GIT_COMMITTER_EMAIL':'yougori@localhost'}
# That repository was .shannon/deliverables/.git in the workspace, so its objects, refs and logs came
# back through the person's review beside the report, and promoting them left a broken repository.
# It is kept in the home instead (DELIVERABLES_GIT): while the worker runs, the deliverables folder
# holds only a .git file that points there. Shannon takes that as its repository and makes no other
# (initDeliverableGit skips its git init and first commit when .git is there).
DELIVERABLES = Path('.shannon/deliverables')
DELIVERABLES_GIT = 'shannon-deliverables.git'
# At the start of each scan Shannon's worker writes a stealth browser config for playwright-cli into
# the workspace, unless the workspace has one of its own: .playwright/cli.config.json, whose
# browser.initScript names the script it writes beside it, .playwright/scripts/stealth.js
# (apps/worker/src/ai/playwright-config-writer.ts). Shannon's own image mounts a folder of its own
# over .playwright; here both came back through the person's review (round 2), so they leave the
# workspace once the worker has stopped (playwright_config).
PLAYWRIGHT_CONFIG = Path('.playwright/cli.config.json')
PLAYWRIGHT_SCRIPT = Path('.playwright/scripts/stealth.js')
# Where playwright-cli keeps the page snapshots the agents take, in its working folder: scratch of
# the scan (the report is in .shannon), so it leaves with the config when the workspace had none.
PLAYWRIGHT_SNAPSHOTS = Path('.playwright-cli')


def reach():
    """What this VM reaches besides the inference, as the person chose it (SOLVER_REACH, which the
    Yougori harness passes on): its mode, and the targets as host:port or host (every port)."""
    try: value = json.loads(os.environ.get('SOLVER_REACH') or '{}')
    except ValueError: value = {}
    if not isinstance(value,dict): value = {}
    mode = value.get('mode') if value.get('mode') in ('inference','sites','targets','full') else 'inference'
    targets = [t.lower() for t in value.get('targets') or [] if isinstance(t,str)]
    return mode,targets


def target_url(value):
    """A target Shannon may scan: an http(s) address without a login, inside this VM, or one this
    VM reaches: a target the person named for it, or anything when they chose the whole internet."""
    mode,targets = reach()
    target = urlsplit(value)
    try: port = target.port or {'http':80,'https':443}.get(target.scheme)
    except ValueError: port = None
    host = target.hostname
    if target.scheme in ('http','https') and host and port and not target.username and not target.password:
        if host in LOOPBACK or mode=='full' or host in targets or '%s:%d' % (host,port) in targets:
            return value
    if mode=='full':
        raise ValueError('Give the target as an http:// or https:// address without a login in it.')
    if targets:
        raise ValueError('This VM reaches only the inference and '+', '.join(targets)+'. Give an http:// or https:// '
                         'address of one of them, without a login in it, or of a service inside this VM.')
    raise ValueError('The target must run inside this VM. External networking is disabled.')


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
  scan URL        Run Shannon against a service inside this VM, or a target this VM reaches
  logs            Show the last worker log
  help            Show these commands
  exit            Close Shannon and stop this VM

The prepared VM stays open between commands. {reach}
Reports go to .shannon/runs in the workspace.
Use solver-shannon --workspace "C:\\path\\to\\project" to work on a project copy.'''


def help_text():
    mode,targets = reach()
    if mode=='full': where = 'This VM reaches the internet.'
    elif targets: where = 'Besides the inference this VM reaches only '+', '.join(targets)+'.'
    else: where = 'External networking is blocked.'
    return HELP.format(reach=where)


def banner(args):
    print('\n\x1b[34mShannon | Inference Solver\x1b[0m\nModel: '+args.model+'\n',flush=True)


def session(args,greet=True):
    if greet: banner(args)
    print(help_text(),flush=True)
    while True:
        try:
            command=input('\nshannon> ').strip()
            if not command: continue
            words=shlex.split(command)
            if words in (['exit'],['quit']): return 0
            if words==['help']: print(help_text(),flush=True)
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


def models_config(args):
    """The models file Shannon's agents read (SHANNON_SOLVER_MODELS): the chosen model with its window
    (the context budget) and the reply length it asks. The local endpoint implements chat
    completions, not OpenAI's storage or reasoning extensions, which Pi otherwise assumes from the
    URL. A connection check needs a short answer, not the scan's whole reply budget."""
    model = {'id':args.model,'contextWindow':args.context_budget,
             'maxTokens':128 if args.validate_model else min(args.max_output,args.context_budget//4),
             'compat':{'supportsStore':False,'supportsDeveloperRole':False,
                       'supportsReasoningEffort':False,'supportsLongCacheRetention':False,
                       'maxTokensField':'max_tokens'}}
    return {'providers':{'solver':{'baseUrl':'http://127.0.0.1:8080/v1','api':'openai-completions',
        'apiKey':'solver-local-relay','models':[model]}}}


def worker_environment(args, home, config, workspace):
    """The environment Shannon's worker runs in: the VM's, the relay as its model, its models file
    (`config`) and Yougori's git identity for its checkpoint commits. Git never looks above the
    workspace's .shannon folder for a repository, so a checkpoint without its own repository (a
    broken .git that an earlier review brought back, say) is skipped and never goes to the person's
    repository."""
    ceiling = os.pathsep.join(filter(None, [str(Path(workspace)/'.shannon'), os.environ.get('GIT_CEILING_DIRECTORIES')]))
    return {**os.environ,'SHANNON_AI_MODEL':'solver:'+args.model,'SHANNON_AI_API_KEY':'solver-local-relay',
        'SHANNON_AI_BASE_URL':'http://127.0.0.1:8080/v1','SHANNON_SOLVER_MODELS':str(config),
        'TEMPORAL_ADDRESS':'127.0.0.1:7233','PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD':'1',
        # The VM has no user namespaces and no setuid chrome-sandbox, so Chromium's own sandbox cannot
        # start ("No usable sandbox!") and every playwright-cli open failed; the VM is the boundary.
        # playwright-cli 0.1.1 reads PLAYWRIGHT_MCP_SANDBOX (its NO_SANDBOX spelling is ignored).
        'PLAYWRIGHT_MCP_SANDBOX':'false',
        'PLAYWRIGHT_MCP_EXECUTABLE_PATH':'/usr/bin/chromium','PI_CODING_AGENT_DIR':str(Path(home)/'.pi/agent'),**GIT_IDENTITY,
        'GIT_CEILING_DIRECTORIES':ceiling}


def git_step(arguments, folder, environment):
    """One git command in `folder`, in the worker's environment: whether it succeeded."""
    try:
        return subprocess.run(['git',*arguments],cwd=folder,env=environment,stdin=subprocess.DEVNULL,
                              capture_output=True,timeout=60).returncode==0
    except (OSError,subprocess.SubprocessError):
        return False


def points_to(dot_git, repository):
    """Whether `dot_git` is a .git file that points to `repository`, as git writes one."""
    try:
        text = Path(dot_git).read_text(encoding='utf-8')
    except (OSError,ValueError):
        return False
    return text.startswith('gitdir: ') and Path(text[len('gitdir: '):].strip()).resolve()==Path(repository).resolve()


@contextlib.contextmanager
def deliverables_git(workspace, home, environment):
    """Shannon's deliverables repository in the home, while its worker runs: the deliverables folder
    gets a .git file that points to it, made as Shannon makes its own (git init, then an empty first
    commit). Afterwards that file goes again, so nothing of the repository reaches the review. A
    .git file that an earlier session left there is used and stays as it was. A .git of any other
    kind stays as it is, and Shannon uses it as before."""
    folder, repository = Path(workspace)/DELIVERABLES, Path(home)/DELIVERABLES_GIT
    dot_git = folder/'.git'
    left = None
    if os.path.lexists(dot_git):
        if not points_to(dot_git, repository):
            yield
            return
        left = dot_git.read_bytes()
    try:
        if left is None or not (repository/'HEAD').is_file():
            if left is not None:
                dot_git.unlink()  # git makes no repository behind a .git file that points to none
            folder.mkdir(parents=True,exist_ok=True)
            if (git_step(['init','-q','--separate-git-dir',str(repository),str(folder)],folder,environment)
                    and not git_step(['rev-parse','--verify','-q','HEAD'],folder,environment)):
                git_step(['commit','-q','--allow-empty','-m','Initial deliverables checkpoint'],folder,environment)
        yield
    finally:
        try:
            if left is None:
                if points_to(dot_git, repository): dot_git.unlink()
            elif not os.path.lexists(dot_git) or (dot_git.is_file() and dot_git.read_bytes()!=left):
                dot_git.write_bytes(left)
        except OSError:
            pass


def shannons_config(config, script):
    """Whether `config` is the browser config Shannon writes: JSON whose browser runs `script` alone."""
    try:
        value = json.loads(Path(config).read_text(encoding='utf-8'))
    except (OSError,ValueError):
        return False
    browser = value.get('browser') if isinstance(value,dict) else None
    scripts = browser.get('initScript') if isinstance(browser,dict) else None
    return (isinstance(scripts,list) and len(scripts)==1 and isinstance(scripts[0],str)
            and Path(scripts[0])==Path(script))


@contextlib.contextmanager
def playwright_config(workspace):
    """Shannon's browser config for playwright-cli in the workspace while its worker runs. Afterwards
    the config and script it wrote leave again, then their folders once empty, so the person's
    review does not list them. What the workspace held before the worker started stays: a config of
    its own (Shannon then writes none), and a script or folder of the same name."""
    workspace = Path(workspace)
    config, script = workspace/PLAYWRIGHT_CONFIG, workspace/PLAYWRIGHT_SCRIPT
    folders = [script.parent, config.parent]
    snapshots = workspace/PLAYWRIGHT_SNAPSHOTS
    held = {path for path in (config,script,*folders,snapshots) if os.path.lexists(path)}
    try:
        yield
    finally:
        if snapshots not in held and not snapshots.is_symlink() and snapshots.is_dir():
            shutil.rmtree(snapshots, ignore_errors=True)
        links = any(path.is_symlink() for path in (config,*folders))
        if config not in held and not links and shannons_config(config, script):
            for path in (config,script):
                try:
                    if path not in held and not path.is_symlink() and path.is_file(): path.unlink()
                except OSError:
                    pass
            for folder in folders:
                try:
                    if folder not in held: folder.rmdir()
                except OSError:
                    pass


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
    if not 1 <= args.max_output <= args.context_budget:
        raise ValueError('Choose a reply length from 1 token to the context budget.')
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
    config.write_text(json.dumps(models_config(args)))
    environment = worker_environment(args, home, config, workspace)
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
            # The model check's folder is in the home already. The worker has stopped when worker()
            # returns, so no checkpoint can follow the .git file out of the workspace, and it writes
            # no browser config after playwright_config takes it out.
            with contextlib.nullcontext() if validation_site is not None else deliverables_git(workspace,home,environment), \
                    playwright_config(workspace):
                return worker(command,environment,source,home/'shannon-worker.log',args.verbose)
        finally:
            if validation_site: validation_site.shutdown();validation_site.server_close()
            process.terminate()
            try: process.wait(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.wait()


def scans(args,targets):
    """The targets given with --target (the Yougori harness gives the setup answers' targets), each
    in turn, then the session stays open for more commands. Every target is checked first, so a
    target this VM cannot reach starts nothing."""
    for target in targets: target_url(target)
    banner(args)
    if os.environ.get('SOLVER_EMPTY_WORKSPACE')=='1':
        print('Select a project first: solver-shannon --workspace "C:\\path\\to\\project"',flush=True)
        return session(args,greet=False)
    for index,target in enumerate(targets,1):
        if len(targets)>1: print('Target '+str(index)+' of '+str(len(targets))+': '+target,flush=True)
        try:
            code=run_once(argparse.Namespace(**{**vars(args),'target':target,'validate_model':False}))
        except KeyboardInterrupt:
            print('\nStopped the scans.',flush=True)
            break
        except (ValueError,OSError) as error:
            print(str(error),flush=True);code=1
        if code: print('Type logs for details of this scan.',flush=True)
    print('Reports are in .shannon/runs in the workspace. Shannon stays open for more commands.',flush=True)
    return session(args,greet=False)


def hang_up_cleanly():
    """A hangup or SIGTERM ends Shannon as Ctrl+C does, so its worker stops and its deliverables'
    .git file leaves the workspace. A session that the launcher ends gets a hangup first
    (vm_guest /finish)."""
    def interrupt(number, frame):
        raise KeyboardInterrupt
    for name in ('SIGHUP','SIGTERM'):
        if hasattr(signal,name):
            signal.signal(getattr(signal,name),interrupt)


def main(argv=None):
    args=parser().parse_args(argv)
    if not 4096<=args.context_budget<=131072:
        raise ValueError('Choose a context budget from 4096 to 131072 tokens that fits your model.')
    if not 1<=args.max_output<=args.context_budget:
        raise ValueError('Choose a reply length from 1 token to the context budget.')
    targets=list(dict.fromkeys(args.target or []))
    if args.validate_model:
        return run_once(argparse.Namespace(**{**vars(args),'target':targets[0] if targets else None}))
    if not targets: return session(args)
    return scans(args,targets)


if __name__=='__main__':
    hang_up_cleanly()
    sys.exit(main())
