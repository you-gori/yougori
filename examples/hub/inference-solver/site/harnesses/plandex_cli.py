"""Plandex's real CLI/server/database, all private to the enclosing Yougori VM."""
import argparse
import base64
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
import time
import urllib.request


TOOL = Path('/opt/solver/tool')
SERVER = 'http://127.0.0.1:8099'


class Bridge(BaseHTTPRequestHandler):
    """OpenAI-only replacement for Plandex's optional multi-provider proxy."""
    def log_message(self, *_): pass

    def do_GET(self):
        self.send_response(200 if self.path == '/health' else 404)
        self.send_header('Content-Length','0'); self.end_headers()

    def do_POST(self):
        connection = None
        try:
            length = int(self.headers.get('Content-Length','0'))
            if self.path != '/v1/chat/completions' or not 0 < length <= 8*1024*1024:
                self.send_error(400); return
            payload = json.loads(self.rfile.read(length))
            if payload.get('model') not in (self.server.model,'openai/'+self.server.model):
                self.send_error(403,'Only the selected Inference Solver model is available.'); return
            payload['model'] = self.server.model
            for name in ('api_key','api_base','base_url','custom_llm_provider'): payload.pop(name,None)
            connection = http.client.HTTPConnection('127.0.0.1',8080,timeout=180)
            connection.request('POST',self.path,json.dumps(payload),{'Content-Type':'application/json','Authorization':'Bearer solver-local-relay'})
            response = connection.getresponse()
            if response.status >= 400:
                # The local relay's safe error contains no prompts or provider keys.
                raw = response.read(4096)
                print('Plandex model request refused ('+str(response.status)+'): '+raw.decode(errors='replace'),flush=True)
                self.send_response(response.status);self.send_header('Content-Length',str(len(raw)));self.end_headers();self.wfile.write(raw)
                return
            self.send_response(response.status)
            self.send_header('Content-Type',response.getheader('Content-Type','application/json'))
            self.send_header('Connection','close'); self.end_headers()
            total = 0
            while chunk := response.read1(32768):
                total += len(chunk)
                if total > 16*1024*1024: break
                self.wfile.write(chunk); self.wfile.flush()
        finally:
            self.close_connection = True
            if connection: connection.close()


def request(path, data=None, auth=None):
    headers = {'Content-Type':'application/json','X-Client-Version':'2.2.1'}
    if auth:
        state = {'token':auth['token'],'orgId':auth['orgId'],
                 'hash':hashlib.sha256((auth['orgName']+'|false|false').encode()).hexdigest()}
        headers['Authorization'] = 'Bearer '+base64.urlsafe_b64encode(json.dumps(state,separators=(',',':')).encode()).decode()
    req = urllib.request.Request(SERVER+path,data=None if data is None else json.dumps(data).encode(),headers=headers)
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(req,timeout=30) as response:
        raw = response.read(4*1024*1024)
    return json.loads(raw) if raw and raw != b'OK' else None


def main():
    parser = argparse.ArgumentParser(description='Plandex inside Yougori, connected only to Inference Solver.')
    parser.add_argument('--solver-model',required=True)
    parser.add_argument('--context-budget',type=int,default=32768,help='Plandex context budget; must fit your selected model (its system prompt needs at least 16K)')
    parser.add_argument('--print',dest='prompt')
    args, rest = parser.parse_known_args()
    if not 16384 <= args.context_budget <= 131072: raise ValueError('Plandex requires a model with a context budget from 16384 to 131072.')
    home = Path.home()
    state = home/'plandex-local'; state.mkdir(exist_ok=True)
    pg = Path('/usr/lib/postgresql/17/bin')
    database = state/'database'
    environment = {**os.environ,'PLANDEX_ENV':'development','PLANDEX_API_HOST':SERVER,'GOENV':'development','LOCAL_MODE':'1',
                   'DATABASE_URL':'postgres://node@127.0.0.1:5432/plandex?sslmode=disable','MIGRATIONS_DIR':str(TOOL/'migrations'),
                   'PLANDEX_BASE_DIR':str(state/'plans'),'SOLVER_API_KEY':'solver-local-relay'}
    cli_home = home/'.plandex-home-dev-v2'; cli_home.mkdir(exist_ok=True)
    shutil.copytree(TOOL/'tokenizer',cli_home/'cache',dirs_exist_ok=True)
    os.environ['TIKTOKEN_CACHE_DIR'] = str(cli_home/'cache')
    environment['TIKTOKEN_CACHE_DIR'] = str(cli_home/'cache')
    processes = []
    bridge = ThreadingHTTPServer(('127.0.0.1',4000),Bridge); bridge.model = args.solver_model
    threading.Thread(target=bridge.serve_forever,daemon=True).start()
    with (state/'services.log').open('w') as log:
        try:
            if not database.exists():
                subprocess.run([str(pg/'initdb'),'-D',str(database),'--auth=trust','--no-locale'],check=True,stdout=log,stderr=log)
            processes.append(subprocess.Popen([str(pg/'postgres'),'-D',str(database),'-h','127.0.0.1','-k',str(state),'-c','jit=off'],stdout=log,stderr=log))
            for _ in range(120):
                if subprocess.run([str(pg/'pg_isready'),'-h','127.0.0.1'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL).returncode == 0: break
                if processes[-1].poll() is not None: raise ValueError('Plandex database stopped; inspect ~/plandex-local/services.log in the VM.')
                time.sleep(.25)
            else: raise ValueError('Plandex database readiness timed out.')
            subprocess.run([str(pg/'createdb'),'-h','127.0.0.1','plandex'],check=True,stdout=log,stderr=log)
            processes.append(subprocess.Popen([str(TOOL/'bin/plandex-server')],env=environment,cwd=state,stdout=log,stderr=log))
            for _ in range(120):
                try: request('/health'); break
                except OSError:
                    if processes[-1].poll() is not None: raise ValueError('Plandex server stopped; inspect ~/plandex-local/services.log in the VM.')
                    time.sleep(.25)
            else: raise ValueError('Plandex server readiness timed out.')
            account = request('/accounts',{'email':'solver@localhost.local','userName':'Inference Solver'})
            auth = {**{key:account[key] for key in ('userId','token','email','userName')},'orgId':'','orgName':'',
                    'isCloud':False,'host':SERVER,'isLocalMode':True,'orgIsTrial':False,'integratedModelsMode':False}
            orgs = account.get('orgs') or []
            org = orgs[0] if orgs else request('/orgs',{'name':'Inference Solver','autoAddDomainUsers':False},auth)
            auth.update(orgId=org['id'],orgName=org.get('name','Inference Solver'))
            (cli_home/'auth.json').write_text(json.dumps(auth))
            model_id = 'solver-selected'
            definition = {'modelId':model_id,'publisher':'custom','description':'Selected Inference Solver model',
                          'maxTokens':args.context_budget,'defaultMaxConvoTokens':args.context_budget//2,
                          'maxOutputTokens':1024,'reservedOutputTokens':1024,'preferredOutputFormat':'xml',
                          'providers':[{'provider':'custom','customProvider':'Inference Solver','modelName':args.solver_model}]}
            roles = {name:{'modelId':model_id} for name in ('planner','coder','planSummary','builder','wholeFileBuilder','namer','commitMsg','execStatus','contextLoader')}
            request('/custom_models',{'providers':[{'name':'Inference Solver','baseUrl':'http://127.0.0.1:4000/v1','apiKeyEnvVar':'SOLVER_API_KEY'}],
                    'models':[definition],'modelPacks':[{'name':'Inference Solver','description':'One server; no external fallback',**roles}]},auth)
            cli = [str(TOOL/'bin/plandex')]
            subprocess.run([*cli,'set-model','default','Inference Solver'],env=environment,check=True)
            print('Plandex · Inference Solver · private VM services ready',flush=True)
            if args.prompt:
                subprocess.run([*cli,'new','--name','Inference Solver','--no-auto'],env=environment,check=True)
                return subprocess.call([*cli,'tell',args.prompt],env=environment)
            return subprocess.call([*cli,*rest],env=environment)
        finally:
            bridge.shutdown(); bridge.server_close()
            for process in reversed(processes):
                process.terminate()
                try: process.wait(timeout=10)
                except subprocess.TimeoutExpired: process.kill(); process.wait()


if __name__ == '__main__':
    sys.exit(main())
