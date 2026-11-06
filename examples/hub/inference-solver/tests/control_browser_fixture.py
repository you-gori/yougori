"""Disposable HTTP website with explicitly synthetic hardware for browser checks."""
from pathlib import Path
import json
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parent))
from test_service import Flow, PASSWORD

flow=Flow()
try:
    flow.setUp();flow.endpoint()
    flow.service.store.signup('operator@example.invalid',PASSWORD)
    host=flow.service.compute.host(flow.service.compute.local_host('Fixture PC'))
    telemetry={'cpu_percent':42,'cpu_cores':8,'memory_used_gb':6,'memory_total_gb':16,'disk_used_gb':80,'disk_total_gb':200,
               'gpus':[{'name':'Fixture NVIDIA GPU','utilization_percent':70,'temperature_c':65,'memory_used_mb':4096,'memory_total_mb':8192,'power_w':90}]}
    flow.service.compute.inventory(host,{'models':[],'telemetry':telemetry})
    flow.service.grid.inventory(host,{'cpu':4,'memory_gb':8,'slots':2})
    flow.service.grid.configure('fixture',{'enabled':True,'admission':'open'})
    with flow.service.store.db() as db:
        for ago in (30,20,10):db.execute('INSERT OR REPLACE INTO operator_samples VALUES(?,?,?)',(host['id'],int(time.time())-ago,json.dumps(telemetry)))
    print(flow.url,flush=True)
    sys.stdin.readline()
finally:flow.tearDown()
