"""Opt-in HTTP -> contributor -> real Yougori VM check. No cloud or host mounts."""
import argparse
import os
from pathlib import Path
import secrets
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_service import Flow
from grid_adapter import GridAdapter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root',type=Path,required=True)
    args = parser.parse_args()
    if not os.getenv('YOUGORI_ACCEPTANCE_ENDPOINT'):
        raise ValueError('Use a disposable acceptance engine.')
    args.root.mkdir(parents=True,exist_ok=True)
    adapter = GridAdapter(os.environ['INFERENCE_SOLVER_YOUGORI'],args.root,{'cpu':1,'memory_gb':1,'slots':1})
    flow = Flow(); flow.setUp()
    try:
        token = flow.service.compute.local_host('Disposable grid host')
        host = flow.service.compute.host(token)
        flow.service.grid.inventory(host,adapter.capacity)
        status,_,_ = flow.call('/api/admin/grid',{'enabled':True,'admission':'private'},flow.admin)
        assert status == 200
        def execute(kind,**data):
            status,created,_ = flow.call('/api/grid/jobs',{'kind':kind,'request_id':secrets.token_hex(16),**data},flow.admin)
            assert status == 202,created
            task = flow.service.grid.poll(host)
            result = adapter.execute(task)
            status,body,_ = flow.call('/api/compute/agent',{'action':'grid_result','id':task['id'],'ok':True,'result':result},headers={'Authorization':'Bearer '+token})
            assert status == 200,body
            return created,result
        created,result = execute('launch',host=host['id'],cpu=1,memory_gb=1,name='HTTP grid check')
        _,result = execute('exec',vm=created['vm'],input='uname -s; printf SOLVER_GRID_OK')
        assert result['exit_code'] == 0 and 'Linux\nSOLVER_GRID_OK' == result['output'],result
        execute('stop',vm=created['vm'])
        status,snapshot,_ = flow.call('/api/grid',session=flow.admin)
        assert status == 200 and snapshot['vms'][0]['state'] == 'stopped'
        print('REAL_GRID_OK: HTTP launch, native VM command, guest output, stop, website reconciliation.')
    finally:
        adapter.stop_all(); flow.tearDown()


if __name__ == '__main__': main()
