"""Bounded operator telemetry, presence and usage summaries. No prompts or secrets."""
import csv
import io
import json
import math
import shutil
import subprocess
import time
import threading


def number(value, maximum=1000000000):
    return value if type(value) in (int,float) and math.isfinite(value) and 0 <= value <= maximum else None


def clean(data):
    if not isinstance(data,dict): return {}
    result={k:number(data.get(k),100 if k.endswith('_percent') else 1000000000) for k in
            ('cpu_percent','cpu_cores','memory_used_gb','memory_total_gb','disk_used_gb','disk_total_gb','gpu_percent','cpu_temperature_c')}
    result['gpus']=[]
    for gpu in data.get('gpus',[])[:16] if isinstance(data.get('gpus'),list) else []:
        if not isinstance(gpu,dict):continue
        result['gpus'].append({'name':str(gpu.get('name','GPU'))[:120],**{k:number(gpu.get(k),100 if k=='utilization_percent' else 1000000)
            for k in ('utilization_percent','memory_used_mb','memory_total_mb','temperature_c','power_w')}})
    result['workloads']=[]
    for item in data.get('workloads',[])[:100] if isinstance(data.get('workloads'),list) else []:
        if not isinstance(item,dict):continue
        result['workloads'].append({k:str(item.get(k,''))[:100] for k in ('id','name','kind','state') } |
            {k:number(item.get(k)) for k in ('cpu_percent','memory_gb','network_rx_mbps','network_tx_mbps')})
    return result


def sample(state, fresh=True):
    # An older/unavailable engine may return a cached inventory. Do not turn it
    # into a new live measurement; NVIDIA sampling below is independent.
    host=state.get('host',{}) if fresh else {}
    result={'cpu_percent':host.get('usedCpuPercent'),'cpu_cores':host.get('totalCpu'),'memory_used_gb':host.get('usedMemoryGb'),
            'memory_total_gb':host.get('totalMemoryGb'),'disk_used_gb':host.get('usedStorageGb'),'disk_total_gb':host.get('totalStorageGb'),
            'gpu_percent':host.get('gpuUsagePercent'),'gpus':[], 'workloads':[
                {'id':e.get('id'),'name':e.get('name'),'kind':e.get('kind'),'state':e.get('status'),
                 'cpu_percent':e.get('cpuUsage') if fresh else None,'memory_gb':e.get('memoryUsageGb') if fresh else None,
                 'network_rx_mbps':e.get('networkRxMbps') if fresh else None,'network_tx_mbps':e.get('networkTxMbps') if fresh else None}
                for e in state.get('environments',[])[:100]]}
    executable=shutil.which('nvidia-smi')
    if executable:
        try:
            out=subprocess.run([executable,'--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu,power.draw',
                                '--format=csv,noheader,nounits'],capture_output=True,text=True,timeout=3,
                               creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if out.returncode==0 and len(out.stdout)<16000:
                for row in csv.reader(io.StringIO(out.stdout)):
                    if len(row)!=6:continue
                    values=[]
                    for value in row[1:]:
                        try:values.append(float(value))
                        except ValueError:values.append(None)
                    result['gpus'].append(dict(zip(('name','utilization_percent','memory_used_mb','memory_total_mb','temperature_c','power_w'),[row[0].strip(),*values])))
        except (OSError,subprocess.TimeoutExpired):pass
    return clean(result)


class ControlPanel:
    def __init__(self,store):
        self.store=store
        self.active=set()
        self.lock=threading.Lock()
        with store.db() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS operator_samples(host TEXT NOT NULL,at INTEGER NOT NULL,metrics TEXT NOT NULL,PRIMARY KEY(host,at));
                CREATE TABLE IF NOT EXISTS account_presence(user_id TEXT PRIMARY KEY,web_seen INTEGER NOT NULL DEFAULT 0,api_seen INTEGER NOT NULL DEFAULT 0);
                CREATE INDEX IF NOT EXISTS requests_started ON requests(started);
            ''')

    def presence(self,user,api=False):
        column='api_seen' if api else 'web_seen'
        with self.store.db() as db:
            db.execute(f'INSERT INTO account_presence(user_id,{column}) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET {column}=excluded.{column}',(user,int(time.time())))

    def record(self,db,host,data):
        if not data:return
        now=int(time.time())
        db.execute('INSERT OR REPLACE INTO operator_samples VALUES(?,?,?)',(host,now//10*10,json.dumps(clean(data))))
        db.execute('DELETE FROM operator_samples WHERE at<?',(now-3600,))

    def snapshot(self,compute,grid):
        now=int(time.time())
        with self.store.db() as db:
            counts={'users':db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
                'admins':db.execute('SELECT COUNT(*) FROM users WHERE admin=1').fetchone()[0],
                'online':db.execute('SELECT COUNT(*) FROM account_presence WHERE web_seen>?',(now-90,)).fetchone()[0],
                'api_users':db.execute('SELECT COUNT(*) FROM account_presence WHERE api_seen>?',(now-300,)).fetchone()[0]}
            requests=[dict(r) for r in db.execute("SELECT started/300*300 AS at,COUNT(*) AS requests,SUM(status='completed') AS completed,COUNT(DISTINCT user_id) AS users,AVG(duration_ms) AS latency_ms,SUM(input_tokens) AS input_tokens,SUM(output_tokens) AS output_tokens FROM requests WHERE started>? GROUP BY at ORDER BY at",(now-86400,))]
            # Cache use counts only requests whose model server reported it (cache_input is their input).
            by_model=[dict(r) for r in db.execute("SELECT r.model,COUNT(*) AS requests,SUM(r.status='completed') AS completed,SUM(r.input_tokens) AS input_tokens,SUM(d.cached_tokens) AS cached_tokens,"
                "SUM(CASE WHEN d.cached_tokens IS NOT NULL THEN r.input_tokens END) AS cache_input,SUM(r.output_tokens) AS output_tokens,SUM(r.input_tokens IS NULL OR r.output_tokens IS NULL) AS unknown_usage,"
                "SUM(m.images) AS images,SUM(m.output_ms) AS output_ms "
                "FROM requests r LEFT JOIN request_details d ON d.id=r.id LEFT JOIN request_media m ON m.id=r.id WHERE r.started>? GROUP BY r.model ORDER BY requests DESC LIMIT 100",(now-86400,))]
            by_source=[dict(r) for r in db.execute("SELECT d.source,COUNT(*) AS requests,SUM(r.status='completed') AS completed,AVG(r.duration_ms) AS latency_ms,SUM(d.cached_tokens) AS cached_tokens,"
                "SUM(CASE WHEN d.cached_tokens IS NOT NULL THEN r.input_tokens END) AS cache_input FROM requests r JOIN request_details d ON d.id=r.id WHERE r.started>? "
                "GROUP BY d.source ORDER BY requests DESC LIMIT 100",(now-86400,))]
            names={r['id']:(r['upstream'],r['source']) for r in db.execute('SELECT m.id,m.upstream,e.name AS source FROM models m JOIN endpoints e ON e.id=m.endpoint_id')}
            revenue=db.execute("SELECT COALESCE(-SUM(amount),0) FROM credit_ledger WHERE kind='inference' AND at>?",(now-86400,)).fetchone()[0]
            deposits=db.execute("SELECT COALESCE(SUM(amount),0) FROM credit_ledger WHERE kind='payment' AND at>?",(now-86400,)).fetchone()[0]
            nodes=compute.snapshot()['hosts']
            for node in nodes:
                node['samples']=[{'at':r['at'],**json.loads(r['metrics'])} for r in db.execute('SELECT at,metrics FROM operator_samples WHERE host=? ORDER BY at',(node['id'],))]
            users=[dict(r) for r in db.execute('SELECT u.id,u.email,u.admin,COALESCE(p.web_seen,0) AS web_seen,COALESCE(p.api_seen,0) AS api_seen FROM users u LEFT JOIN account_presence p ON p.user_id=u.id ORDER BY u.admin DESC,u.email LIMIT 500')]
        with self.lock:active=len(self.active)
        # Live routing since this website started: requests in progress per replica, its slots, and
        # how many requests continued a conversation on the same computer.
        routing=[{'model':names[replica][0],'source':names[replica][1],**state} for replica,state in
                 (compute.router.snapshot().items() if compute.router else []) if replica in names]
        return {'at':now,'counts':{**counts,'active_requests':active},'requests':requests,'models':by_model,'sources':by_source,
                'routing':sorted(routing,key=lambda r:(r['model'],r['source'])),'nodes':nodes,'users':users,
                'revenue_microusd':revenue,'deposits_microusd':deposits,'grid':grid.snapshot({'admin':True}),
                'cloud':compute.snapshot()['jobs']}
