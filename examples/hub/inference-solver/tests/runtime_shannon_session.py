"""Opt-in real VM: two model checks and a shell in one prepared Shannon session.

Uses disposable service accounts and an HTTP model fixture by default. --local
uses the already approved local Shannon connection and its first available model.
No scan is started. Credentials are copied only to an owner-private test folder.
"""
import argparse
import base64
import json
from pathlib import Path
import sys
import tempfile
import time
from unittest.mock import patch

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
from runtime_harnesses import TextModel, Flow
sys.path.insert(0,str(HERE.parent/'site/harnesses'))
import solver
import vm_host


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root',type=Path,required=True)
    parser.add_argument('--local',action='store_true')
    args=parser.parse_args()
    args.root.mkdir(parents=True,exist_ok=True)
    fixture=None
    if args.local:
        url='http://127.0.0.1:3002'
        key=(solver.profile(url)/'shannon/api-key').read_text().strip()
        model=solver.models(url,key)[0]['id']
    else:
        import threading
        fixture=Flow();fixture.setUp()
        fixture.model.RequestHandlerClass=TextModel;fixture.model.harness='shannon'
        threading.Thread(target=fixture.service.watch,daemon=True).start()
        fixture.endpoint();url=fixture.url;key=fixture.key()['key']
        model=fixture.call('/api/models')[1]['models'][0]['id']
    try:
        with tempfile.TemporaryDirectory(prefix='shannon-session-',dir=args.root) as temp:
            root=Path(temp).resolve()
            assert root.is_relative_to(args.root.resolve())
            solver.private_folder(root)
            credential=root/'api-key';credential.write_text(key)
            original=vm_host.Control.post
            transfer=vm_host.prepare_tool
            state={'output':'','step':0,'preparations':0,'checks':[]}
            deadline=time.monotonic()+900
            def prepare(*params):
                state['preparations']+=1
                return transfer(*params)
            def post(control,path,data):
                if time.monotonic()>deadline: raise TimeoutError('Shannon session validation exceeded 15 minutes.')
                reply=original(control,path,data)
                if path=='/poll':
                    state['output']+=base64.b64decode(reply.get('output','')).decode('utf-8','replace')
                    count=state['output'].count('shannon> ')
                    command=None
                    if state['step']==0 and count>=1: command='check\n'
                    elif state['step']==1 and count>=2:
                        state['checks'].append(time.monotonic());command='shell\n'
                    elif state['step']==2 and 'VM shell. Start your local service' in state['output']:
                        command="printf 'SESSION_SHELL_%s\\n' OK; exit\n"
                    elif state['step']==3 and count>=3: command='check\n'
                    elif state['step']==4 and count>=4:
                        state['checks'].append(time.monotonic());command='exit\n'
                    if command:
                        state['step']+=1
                        original(control,'/input',{'data':base64.b64encode(command.encode()).decode()})
                return reply
            with patch.object(vm_host.Control,'post',post),patch.object(vm_host,'prepare_tool',prepare):
                status=vm_host.launch('shannon',url,credential,model,None,[],interactive=False)
            assert status==0,status
            assert state['step']==5,state['step']
            assert state['preparations']==1,state['preparations']
            assert state['output'].count('Model validated.')==2
            assert 'SESSION_SHELL_OK' in state['output']
            assert 'taskToken:' not in state['output'] and 'webpack' not in state['output']
            assert len(state['checks'])==2
            print('SHANNON_SESSION_OK: two model checks, guest shell, clean exit; one preparation; '+
                  str(round(state['checks'][1]-state['checks'][0],1))+'s between completed checks',flush=True)
    finally:
        if fixture:fixture.tearDown()


if __name__=='__main__':main()
