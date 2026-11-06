"""A terminal for the real PentAGI server in a private Yougori VM."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request
from urllib.parse import urlencode


def main():
    parser=argparse.ArgumentParser(description='PentAGI in Yougori, connected only to Inference Solver.')
    parser.add_argument('--model',required=True)
    parser.add_argument('--print',dest='prompt')
    args=parser.parse_args()
    home=Path.home();state=home/'pentagi-local';state.mkdir(exist_ok=True)
    pg=Path('/usr/lib/postgresql/17/bin');database=state/'database'
    # Every run owns its database, tool processes and one flow. No daemon socket
    # or nested container runtime exists; /work is only the selected guest copy.
    work=home/'pentagi-work'
    if not work.exists(): work.symlink_to(Path.cwd(),target_is_directory=True)
    environment={**os.environ,'SOLVER_VM_RUNTIME':'1','DATA_DIR':str(state/'data'),
        'DATABASE_URL':'postgres://node@127.0.0.1:5432/pentagi?sslmode=disable','SERVER_HOST':'127.0.0.1','SERVER_PORT':'8099',
        'COOKIE_SIGNING_SALT':secrets.token_hex(32),'LLM_SERVER_URL':'http://127.0.0.1:8080/v1',
        'LLM_SERVER_KEY':'solver-local-relay','LLM_SERVER_MODEL':args.model,'LLM_SERVER_API_TYPE':'openai',
        'DOCKER_DEFAULT_IMAGE':'yougori-vm','DOCKER_DEFAULT_IMAGE_FOR_PENTEST':'yougori-vm',
        'DOCKER_IMAGE_SELECTION_MODE':'fixed','DOCKER_ALLOWED_IMAGES':'yougori-vm',
        'TERMINAL_TOOL_TIMEOUT':'120','EMBEDDING_PROVIDER':'none','ASK_USER':'true'}
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
    def request(path,data=None,method=None):
        req=urllib.request.Request('http://127.0.0.1:8099/api/v1'+path,
            data=None if data is None else json.dumps(data).encode(),headers={'Content-Type':'application/json'},method=method)
        with opener.open(req,timeout=60) as response:
            raw=response.read(8<<20)
        value=json.loads(raw)
        return value.get('data',value)
    processes=[];flow=None
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
            prompt=args.prompt or input('Task (or /exit): ').strip()
            if not prompt or prompt=='/exit':return 0
            flow=request('/flows/',{'input':prompt,'provider':'custom'})
            identity=str(flow['id']);cursor=0;deadline=time.monotonic()+3600
            while time.monotonic()<deadline:
                query=urlencode({'page':1,'pageSize':100,'type':'filter',
                    'sort[]':json.dumps({'prop':'id','order':'ascending'}),
                    'filters[]':json.dumps({'field':'id','operator':'>','value':cursor})})
                messages=request('/flows/'+identity+'/msglogs/?'+query)
                if isinstance(messages,dict):messages=messages.get('msglogs',[])
                for message in messages:
                    key=int(message['id'])
                    if key>cursor:
                        cursor=key
                        value=message.get('result') or message.get('message') or message.get('content') or ''
                        if value:print(str(value)[:65536],flush=True)
                flow=request('/flows/'+identity)
                if flow['status']=='failed':raise ValueError('PentAGI reported a failed flow; inspect its VM service log.')
                if flow['status']=='finished':return 0
                if flow['status']=='waiting':
                    if args.prompt:return 0
                    prompt=input('Reply (or /exit): ').strip()
                    if prompt=='/exit':return 0
                    request('/flows/'+identity,{'action':'input','input':prompt},'PATCH')
                time.sleep(1)
            raise ValueError('PentAGI reached this session’s one-hour limit.')
        finally:
            if flow:
                try:request('/flows/'+str(flow['id']),{'action':'stop'},'PATCH')
                except OSError:pass
            for process in reversed(processes):
                process.terminate()
                try:process.wait(timeout=10)
                except subprocess.TimeoutExpired:process.kill();process.wait()


if __name__=='__main__':sys.exit(main())
