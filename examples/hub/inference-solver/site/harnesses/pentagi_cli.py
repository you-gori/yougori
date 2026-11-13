"""A terminal for the real PentAGI server in a private Yougori VM."""
import argparse
import base64
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlencode


API='http://127.0.0.1:8099/api/v1'
# The longest reply the website passes on (site/gateway.py REPLY_TOKENS, profiles.REPLY_TOKENS).
REPLY_TOKENS=4096
# PentAGI's agents, each with its own call options in the custom provider's config (pconfig).
AGENTS=('simple','simple_json','primary_agent','assistant','generator','refiner','adviser','reflector',
        'searcher','enricher','coder','installer','pentester')


def call(opener,path,data=None,method=None,base=API):
    """One PentAGI REST call; its `data` envelope's contents. Flow updates (input, stop) are PUT
    /flows/{id}: the pinned server routes no other method there (server/router.go:561)."""
    req=urllib.request.Request(base+path,
        data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method=method)
    with opener.open(req,timeout=60) as response:
        raw=response.read(8<<20)
    value=json.loads(raw)
    return value.get('data',value)


def update_flow(opener,identity,data,base=API):
    return call(opener,'/flows/'+str(identity),data,'PUT',base)


# Relative to the workspace, where this terminal starts: the flow's messages come back to the
# person's folder only after their review.
REPORTS=Path('reports/pentagi')


def hidden_values(environment=None):
    """The secret setup answers this terminal holds (a test login's password): never saved."""
    environment=os.environ if environment is None else environment
    return [value for name,value in environment.items() if name.startswith('YOUGORI_SECRET_') and value]


# Hiding secrets. hexstrike_cli.py holds the same code, and a test checks that the two agree.
HIDDEN = "[hidden]"
# A run of base64, standard or URL-safe, such as an HTTP Basic authorization's credentials.
BASE64 = re.compile(r"[A-Za-z0-9+/_-]{8,}={0,2}")
# What some JSON encoder writes as an escape besides control characters and non-ASCII text: PHP
# escapes /, Go < > &, Jinja's tojson also ', .NET also + and `.
JSON_ESCAPED = frozenset('"\\/<>&\'+`')
SHORT_ESCAPES = {'"': '\\"', '\\': '\\\\', '/': '\\/', '\b': '\\b', '\f': '\\f', '\n': '\\n', '\r': '\\r', '\t': '\\t'}


def _in_json(c):
    """Every way a JSON encoder writes the character `c` inside a string: as itself where JSON lets
    it, as a short escape, or as a \\u escape in either case (a surrogate pair beyond the BMP)."""
    if c.isascii() and c.isprintable() and c not in JSON_ESCAPED:
        return {c}
    ways = set() if c in '"\\' or ord(c) < 0x20 else {c}
    if c in SHORT_ESCAPES:
        ways.add(SHORT_ESCAPES[c])
    units = c.encode("utf-16-be")
    escape = "".join("\\u%02x%02x" % (units[i], units[i + 1]) for i in range(0, len(units), 2))
    return ways | {escape, escape.upper().replace("\\U", "\\u")}


def _nested(text):
    """`text` written into a JSON string once more inside the VM: by Python's json, with and without
    \\u escapes for non-ASCII text (pydantic writes as the latter), or by Go's, which escapes <, >
    and & too."""
    plain = json.dumps(text, ensure_ascii=False)[1:-1]
    return {json.dumps(text)[1:-1], plain, re.sub("[<>&\u2028\u2029]", lambda c: "\\u%04x" % ord(c.group(0)), plain)}


def secret_pattern(values):
    """Each secret value as typed and inside a JSON string as any encoder writes it, nested up to
    three deep (a target's JSON answer in a tool's output, in the tool's JSON result, saved as JSON
    once more); None without a value. A character's ways at one depth are prefix-free (each decodes
    to it alone), so a match never backtracks."""
    choices = []
    for value in sorted(set(filter(None, values)), key=lambda value: (-len(value), value)):
        levels = [[{c} for c in value], [_in_json(c) for c in value]]
        for _ in range(2):
            levels.append([{again for way in ways for again in _nested(way)} for ways in levels[-1]])
        for level in reversed(levels):
            choice = "".join(re.escape(next(iter(ways))) if len(ways) == 1 else
                             "(?:" + "|".join(re.escape(way) for way in sorted(ways, key=lambda way: (-len(way), way))) + ")"
                             for ways in level)
            if choice not in choices:
                choices.append(choice)
    return re.compile("|".join(choices)) if choices else None


def _percent(text, keep, space, lower=False):
    """`text` percent-encoded: ASCII letters, digits and `keep` stay, a space is `space`, every other
    character is its UTF-8 bytes as %XX."""
    digits = "%%%02x" if lower else "%%%02X"
    return "".join(space if c == " " else c if c.isascii() and (c.isalnum() or c in keep)
                   else "".join(digits % byte for byte in c.encode("utf-8")) for c in text)


def secret_forms(values):
    """Each secret value percent-encoded in a URL or a form body, as the screen hides it too
    (harness/src/ui/mask.rs), longest first so that a form holding another is hidden whole."""
    forms = set()
    for value in filter(None, values):
        forms.update(_percent(value, "-._~", space, lower) for space in ("%20", "+") for lower in (False, True))
        forms.add(_percent(value, "-._~!'()*", "%20"))  # JavaScript's encodeURIComponent
        forms.add(_percent(value, "-._~/", "%20"))  # Python's quote()
        forms.add(_percent(value, "*-._", "+"))  # a form body as browsers and Java write it
    return sorted(forms, key=lambda form: (-len(form), form))


def _secret_bytes(values):
    """Each secret's bytes as an HTTP Basic authorization carries them (UTF-8, or Latin-1 as Python's
    requests writes them); a value under 4 bytes could turn up by chance in decoded text."""
    found = set()
    for value in filter(None, values):
        for encoding in ("utf-8", "latin-1"):
            try:
                data = value.encode(encoding)
            except UnicodeEncodeError:
                continue
            if len(data) >= 4:
                found.add(data)
    return found


def _base64_holds(run, secrets):
    """Whether a base64 run decodes, from any of its first four characters, to bytes holding a secret."""
    run = run.rstrip("=").replace("-", "+").replace("_", "/")
    for start in range(4):
        piece = run[start:]
        if len(piece) % 4 == 1:
            piece = piece[:-1]  # a lone last character holds no whole byte
        try:
            data = base64.b64decode(piece + "=" * (-len(piece) % 4))
        except ValueError:
            continue
        if any(secret in data for secret in secrets):
            return True
    return False


class Mask:
    """Hides secret values in text: as typed, in JSON (secret_pattern), percent-encoded
    (secret_forms) and in a base64 run."""
    def __init__(self, values):
        values = [value for value in values if value]
        self.pattern = secret_pattern(values)
        self.forms = secret_forms(values)
        self.raw = _secret_bytes(values)

    def __call__(self, text):
        if self.pattern is not None:
            text = self.pattern.sub(HIDDEN, text)
        for form in self.forms:
            if form in text:
                text = text.replace(form, HIDDEN)
        if self.raw:
            text = BASE64.sub(lambda run: HIDDEN if _base64_holds(run.group(0), self.raw) else run.group(0), text)
        return text


MESSAGE_LIMIT=65536


class Report:
    """A flow's task, its messages as the REST API returns them, the replies and how it ended, in
    reports/pentagi. A secret value never reaches the file, in any form Mask hides; if the file
    cannot be written the flow goes on and the terminal says so once."""
    def __init__(self,folder,identity,task,hidden):
        self.mask=Mask(hidden);self.failed=False
        self.path=Path(folder)/('flow-'+str(identity)+'-'+time.strftime('%Y%m%d-%H%M%S')+'.md')
        self.write('# PentAGI flow '+str(identity)+'\n\n## Task\n\n'+task.strip()+'\n\n## Messages\n')
    def write(self,text):
        if self.failed:return
        try:
            self.path.parent.mkdir(parents=True,exist_ok=True)
            with self.path.open('a',encoding='utf-8') as stream:stream.write(self.mask(text))
        except OSError as error:
            self.failed=True
            print('The flow goes on, but its report could not be saved: '+str(error),flush=True)
    def message(self,text):
        # Hidden before the cut, so a secret that crosses it leaves no part behind.
        text=self.mask(text)
        self.write('\n'+text[:MESSAGE_LIMIT].rstrip()+('\n[cut at 65,536 characters]' if len(text)>MESSAGE_LIMIT else '')+'\n')
    def reply(self,text):self.write('\n**Reply:** '+text.strip()+'\n')
    def end(self,how):
        self.write('\n## End\n\nThe flow '+how+'.\n')
        if not self.failed:print('Saved the flow\'s messages to '+str(REPORTS/self.path.name)+' in the workspace.',flush=True)


PAGE=100
# A tool's result can come long after its message: PentAGI's adapter stops a command after 20 minutes.
LATER_SECONDS=1800
# The result of a question, a subtask's end and an input is PentAGI's own bookkeeping ("function
# ask successfully processed arguments") or this terminal's input: their message is what counts.
OWN_RESULT=('ask','done','input')


def message_id(message):
    try:return int(message.get('id') or 0)
    except (TypeError,ValueError):return 0


class Messages:
    """A flow's messages from PentAGI's REST API, each shown once, in the terminal and the report:
    its message when it appears, and its result as soon as there is one. PentAGI stores a tool's
    message before the tool runs and the tool's result after, so a result can come later than its
    message. `written` says whether a write-up (a task's or the flow's report, or a question for
    the person) newer than the last input has been read."""
    def __init__(self,request,identity,report=None,mask=None):
        self.request=request;self.identity=str(identity);self.report=report;self.mask=mask or Mask([])
        self.cursor=0;self.mark=0;self.written=False
        self.later={}  # id of a message read before its result -> (when it was read, its first line)
    def page(self,condition):
        query=urlencode([('page',1),('pageSize',PAGE),('type','filter'),
            ('sort[]',json.dumps({'prop':'id','order':'ascending'})),('filters[]',json.dumps(condition))])
        found=self.request('/flows/'+self.identity+'/msglogs/?'+query)
        if isinstance(found,dict):found=found.get('msglogs') or []
        return [message for message in found if isinstance(message,dict)] if isinstance(found,list) else []
    def show(self,text):
        print(self.mask(text)[:MESSAGE_LIMIT],flush=True)
        if self.report:self.report.message(text)
    def read(self,now):
        """Shows the results that came for messages read before them, then the new messages."""
        if self.later:
            for message in self.page({'field':'id','operator':'in','value':sorted(self.later)}):
                key=message_id(message)
                if key in self.later and message.get('result'):
                    label=self.later.pop(key)[1]
                    self.show('Result of "'+label+'":\n\n'+str(message['result']).strip())
            self.later={key:value for key,value in self.later.items() if now-value[0]<=LATER_SECONDS}
        for message in self.page({'field':'id','operator':'>','value':self.cursor}):
            key=message_id(message)
            if key<=self.cursor:continue
            self.cursor=key
            kind=message.get('type')
            text=str(message.get('message') or '').strip()
            result='' if kind in OWN_RESULT else str(message.get('result') or '').strip()
            if kind!='input' and (text or result):self.show('\n\n'.join(part for part in (text,result) if part))
            if kind not in OWN_RESULT and not result:
                self.later[key]=(now,(text.splitlines() or [str(kind or 'message')])[0][:120])
                while len(self.later)>PAGE:del self.later[min(self.later)]
            if key>self.mark and (kind=='ask' or (kind=='report' and not message.get('subtask_id'))):
                self.written=True
    def sent(self):
        """The person's input went to the flow: only a write-up after it answers it."""
        self.mark=self.cursor;self.written=False


ENDS=('waiting','finished','failed')
# PentAGI stores a task's report just after it marks the task done; a reply moves the flow on at once.
SETTLE_SECONDS=15


def follow(request,update,identity,report=None,one_shot=False,ask=input,clock=time.monotonic,pause=time.sleep,mask=None):
    """Shows the flow's messages until it ends; when it waits, asks the person for a reply (with
    `one_shot`, returns instead). PentAGI marks a task done, which makes the flow wait, before it
    stores the task's report, so before asking, returning or ending, the messages are read again
    until a write-up newer than the last input has come or the flow goes on, for up to
    SETTLE_SECONDS. Returns 0; raises ValueError when the flow fails or the session's hour ends."""
    identity=str(identity)
    messages=Messages(request,identity,report,mask)
    deadline=clock()+3600
    while clock()<deadline:
        messages.read(clock())
        status=request('/flows/'+identity).get('status')
        settle=clock()+SETTLE_SECONDS
        while status in ENDS and not messages.written and clock()<settle:
            pause(.25)
            messages.read(clock())
            status=request('/flows/'+identity).get('status')
        if status=='failed':
            if report:report.end('failed')
            raise ValueError('PentAGI reported a failed flow; inspect its VM service log.')
        if status=='finished':
            if report:report.end('finished')
            return 0
        if status=='waiting':
            if one_shot:return 0
            reply=''
            while not reply:reply=ask('Reply (or /exit): ').strip()
            if reply=='/exit':
                if report:report.end('was stopped from this terminal')
                return 0
            if report:report.reply(reply)
            messages.sent()
            update({'action':'input','input':reply})
        pause(1)
    if report:report.end('reached this session’s one-hour limit')
    raise ValueError('PentAGI reached this session’s one-hour limit.')


def parse(argv=None):
    parser=argparse.ArgumentParser(description='PentAGI in Yougori, connected only to Inference Solver.')
    parser.add_argument('--model',required=True)
    first=parser.add_mutually_exclusive_group()
    first.add_argument('--print',dest='prompt',help='Run one task and leave when the flow waits or ends')
    first.add_argument('--task',help='Start the flow with this task, then answer its questions here; '
                       'its messages are saved in reports/pentagi in the workspace')
    parser.add_argument('--max-output',type=int,default=REPLY_TOKENS,help="The model's longest reply, in tokens")
    args=parser.parse_args(argv)
    if args.task is not None and not args.task.strip():parser.error('--task needs a task.')
    if not 1<=args.max_output<=REPLY_TOKENS:parser.error(f'--max-output takes 1 to {REPLY_TOKENS} tokens.')
    return args


def llm_config(path,max_output):
    """PentAGI's custom provider asks 16,384 tokens of reply for every agent (custom.go); the relay
    passes on at most 4,096, and the model's window may leave less (profiles.limits). Each agent's
    own max_tokens in the file LLM_SERVER_CONFIG_PATH names layers over that default."""
    path.write_text(json.dumps({agent:{'max_tokens':max_output} for agent in AGENTS}),encoding='utf-8')
    return path


def main():
    args=parse()
    home=Path.home();state=home/'pentagi-local';state.mkdir(exist_ok=True)
    pg=Path('/usr/lib/postgresql/17/bin');database=state/'database'
    # Every run owns its database, tool processes and one flow. No daemon socket
    # or nested container runtime exists; /work is only the selected guest copy.
    work=home/'pentagi-work'
    if not work.exists(): work.symlink_to(Path.cwd(),target_is_directory=True)
    environment={**os.environ,'SOLVER_VM_RUNTIME':'1','DATA_DIR':str(state/'data'),
        'LLM_SERVER_CONFIG_PATH':str(llm_config(state/'llm-config.json',args.max_output)),
        'DATABASE_URL':'postgres://node@127.0.0.1:5432/pentagi?sslmode=disable','SERVER_HOST':'127.0.0.1','SERVER_PORT':'8099',
        'COOKIE_SIGNING_SALT':secrets.token_hex(32),'LLM_SERVER_URL':'http://127.0.0.1:8080/v1',
        'LLM_SERVER_KEY':'solver-local-relay','LLM_SERVER_MODEL':args.model,'LLM_SERVER_API_TYPE':'openai',
        'DOCKER_DEFAULT_IMAGE':'yougori-vm','DOCKER_DEFAULT_IMAGE_FOR_PENTEST':'yougori-vm',
        'DOCKER_IMAGE_SELECTION_MODE':'fixed','DOCKER_ALLOWED_IMAGES':'yougori-vm',
        'TERMINAL_TOOL_TIMEOUT':'120','EMBEDDING_PROVIDER':'none','ASK_USER':'true'}
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def request(path,data=None,method=None):
        return call(opener,path,data,method)
    processes=[];flow=None;report=None
    with (state/'services.log').open('w') as log:
        try:
            subprocess.run([str(pg/'initdb'),'-D',str(database),'--auth=trust','--no-locale'],check=True,stdout=log,stderr=log)
            processes.append(subprocess.Popen([str(pg/'postgres'),'-D',str(database),'-h','127.0.0.1','-k',str(state),'-c','jit=off'],stdout=log,stderr=log))
            for _ in range(120):
                if subprocess.run([str(pg/'pg_isready'),'-h','127.0.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode==0:break
                if processes[-1].poll() is not None:raise ValueError('PentAGI database stopped. Inspect ~/pentagi-local/services.log in the VM.')
                time.sleep(.25)
            else:raise ValueError('Database startup timed out.')
            subprocess.run([str(pg/'createdb'),'-h','127.0.0.1','pentagi'],check=True,stdout=log,stderr=log)
            processes.append(subprocess.Popen(['/opt/solver/tool/bin/pentagi'],cwd=state,env=environment,stdout=log,stderr=log))
            for _ in range(240):
                if processes[-1].poll() is not None:raise ValueError('PentAGI server stopped. Inspect ~/pentagi-local/services.log in the VM.')
                try:request('/info');break
                except OSError:time.sleep(.25)
            else:raise ValueError('PentAGI server startup timed out.')
            password=secrets.token_urlsafe(32)
            # A random guest-only login replaces upstream's seed credential before
            # the terminal connects. It never leaves this VM.
            sql="CREATE EXTENSION IF NOT EXISTS pgcrypto; UPDATE users SET password=crypt('"+password+"',gen_salt('bf')) WHERE mail='admin@pentagi.com';"
            subprocess.run([str(pg/'psql'),'-h','127.0.0.1','-d','pentagi','-v','ON_ERROR_STOP=1'],input=sql,text=True,check=True,stdout=log,stderr=log)
            request('/auth/login',{'mail':'admin@pentagi.com','password':password})
            print('PentAGI · Inference Solver · private VM services ready',flush=True)
            if args.task:print('Task:\n'+args.task.strip()+'\n',flush=True)
            prompt=args.prompt or (args.task or '').strip() or input('Task (or /exit): ').strip()
            if not prompt or prompt=='/exit':return 0
            flow=request('/flows/',{'input':prompt,'provider':'custom'})
            identity=str(flow['id'])
            if not args.prompt:report=Report(Path.cwd()/REPORTS,identity,prompt,hidden_values())
            return follow(request,lambda data:update_flow(opener,identity,data),identity,report,bool(args.prompt),
                          mask=report.mask if report else Mask(hidden_values()))
        except (KeyboardInterrupt,EOFError):
            if report:report.end('was stopped from this terminal')
            raise
        finally:
            if flow:
                try:update_flow(opener,flow['id'],{'action':'stop'})
                except OSError:pass
            for process in reversed(processes):
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':sys.exit(main())
