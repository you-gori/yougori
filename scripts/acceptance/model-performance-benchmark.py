"""Real local API performance matrix on an isolated acceptance engine.

Preserves every attempt. Main latency runs use default instrumentation; a separate
diagnostic session records backend clocks. OS caches are not flushed. Concurrency
refusals are results, not retried requests. No public service or paid provider.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import random
import shutil
import statistics
import subprocess
import threading
import time
import urllib.error
import urllib.request

spec=importlib.util.spec_from_file_location('combined',Path(__file__).with_name('combined-model-vm.py'))
combined=importlib.util.module_from_spec(spec);spec.loader.exec_module(combined)


def percentile(values,fraction):
    return sorted(values)[max(0,math.ceil(len(values)*fraction)-1)] if values else None


class Sampler:
    def __init__(self,path):
        self.path=path;self.samples=[];self.phase='initial';self.process=None
    def start(self):
        fields='uuid,name,driver_version,memory.total,memory.used,utilization.gpu,power.draw,temperature.gpu,clocks.sm,clocks.mem,pstate'
        self.process=subprocess.Popen(['nvidia-smi','--query-gpu='+fields,'--format=csv,noheader,nounits','-lms','200'],
            stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        def read():
            with self.path.open('w',encoding='utf-8',newline='\n') as output:
                for line in self.process.stdout:
                    fields=[v.strip() for v in line.split(',')]
                    if len(fields)!=11:continue
                    record={'epoch':time.time(),'monotonic':time.perf_counter(),'phase':self.phase,
                        'uuid':fields[0],'name':fields[1],'driver':fields[2],'pstate':fields[10]}
                    for key,value in zip(('total_mib','used_mib','gpu_percent','power_w','temperature_c','sm_mhz','memory_mhz'),fields[3:10]):
                        try:record[key]=float(value)
                        except ValueError:record[key]=None
                    self.samples.append(record);output.write(json.dumps(record)+'\n');output.flush()
        self.thread=threading.Thread(target=read,daemon=True);self.thread.start()
    def stop(self):
        if self.process is not None:
            if self.process.poll() is None:self.process.terminate()
            self.process.wait(timeout=10);self.thread.join(timeout=10);self.process=None
    def summary(self):
        result={}
        for phase in sorted({x['phase'] for x in self.samples}):
            rows=[x for x in self.samples if x['phase']==phase]
            result[phase]={'samples':len(rows)}
            for key in ('used_mib','gpu_percent','power_w','temperature_c','sm_mhz'):
                values=[x[key] for x in rows if x.get(key) is not None]
                if values:result[phase][key]={'min':min(values),'median':statistics.median(values),'max_observed':max(values)}
        return result


class Run(combined.Combined):
    def __init__(self,args):
        super().__init__(args)
        self.args=args;self.created=None;self.requests=[];self.groups={};self.write_lock=threading.Lock()
        self.catalog_root=args.catalog_root.resolve()
        self.env['YOUGORI_CATALOG_ROOT']=str(self.catalog_root)
        self.env['YOUGORI_CATALOG_QUOTA_BYTES']=str(40*1024**3)
        self.sampler=Sampler(self.root/'gpu-samples.jsonl')
        self.measurement_active=False
    def catalog(self,label,empty=False):
        value=self.result('catalog_status',{},label)
        if empty:
            views=self.catalog_root/'views'
            assert not list(views.iterdir()) if views.exists() else True
            assert value['catalog']['live_leases']==0,value
        return value
    def phase(self,name):
        self.sampler.phase=name;self.write('phase',{'name':name,'epoch':time.time(),'monotonic':time.perf_counter()})
    def wait_ready(self,limit=3600):
        end=time.monotonic()+limit;previous=None
        while time.monotonic()<end:
            reply=self.call('model_status',{'environmentId':self.environment_id},None,checked=False)
            if not reply.get('ok'):
                # The normal repository launch returns its environment before the
                # guest has installed the server. Only that documented startup
                # response is transient; preserve and fail on every other error.
                if reply.get('error')=='Model server is starting. Check Logs for installation/download progress and try again.':
                    h={'status':'server-starting','response':reply}
                else:
                    self.write('model-status-failure',reply)
                    raise RuntimeError('Model status failed; response retained')
            else:h=reply['result']
            if h.get('status')!=previous:
                self.write('model-state',h);previous=h.get('status')
            if h.get('status')=='ready':return h
            if h.get('status')=='error':raise RuntimeError('Model refused or failed; model-state evidence retained')
            time.sleep(2)
        raise TimeoutError('Model did not become ready within the declared limit')
    def stream(self,prompt,label,count=256,barrier=None):
        body={'model':self.args.model_id,'messages':[{'role':'user','content':prompt}],
            'temperature':0,'max_tokens':count,'stream':True,'stream_options':{'include_usage':True}}
        request=urllib.request.Request(f'http://127.0.0.1:{self.port}/v1/chat/completions',data=json.dumps(body).encode(),
            headers={'Content-Type':'application/json','Authorization':'Bearer '+self.created['apiKey']})
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        if barrier:barrier.wait(timeout=30)
        begin=time.perf_counter();first=None;last=None;text=[];usage=None;finish=None;chunks=0;done=False
        record={'label':label,'started':begin,'epoch':time.time(),'max_output_tokens':count,'http_status':None}
        try:
            with opener.open(request,timeout=600) as response:
                record['http_status']=response.status
                for line in response:
                    if not line.startswith(b'data:'):continue
                    value=line[5:].strip()
                    if value==b'[DONE]':done=True;break
                    event=json.loads(value)
                    if 'error' in event:raise RuntimeError(str(event['error']))
                    if event.get('usage'):usage=event['usage']
                    for choice in event.get('choices',[]):
                        content=choice.get('delta',{}).get('content')
                        if content:
                            now=time.perf_counter();first=first or now;last=now;chunks+=1;text.append(content)
                        if choice.get('finish_reason'):finish=choice['finish_reason']
            joined=''.join(text);elapsed=time.perf_counter()-begin
            assert done and usage and finish,{'done':done,'usage':usage,'finish':finish}
            tokens=usage['completion_tokens']
            if count>1:assert joined.strip() and tokens>0,'Empty completion'
            record.update(ok=True,seconds=elapsed,first_text_ms=None if first is None else (first-begin)*1000,
                prompt_tokens=usage['prompt_tokens'],output_tokens=tokens,end_to_end_tokens_s=tokens/elapsed,
                text_chunks=chunks,finish_reason=finish,reply=joined,
                reply_sha256=hashlib.sha256(joined.encode()).hexdigest(),usage=usage)
        except urllib.error.HTTPError as error:
            record.update(ok=False,http_status=error.code,error=error.read(16384).decode('utf-8',errors='replace'))
        except Exception as error:record.update(ok=False,error=f'{type(error).__name__}: {error}')
        record['seconds']=time.perf_counter()-begin
        with self.write_lock:
            self.requests.append(record);self.write('request-'+label,record)
        return record
    def kv_reset(self,label):
        result=self.result('model_adapters',{'environment':self.environment_id,'action':'kv-reset'},label)
        assert result.get('reset') is True,result
    @staticmethod
    def prompt(lines):
        rng=random.Random(789331)
        records=[f'Record {i:05d}: zone {rng.randrange(1,99)} measured {rng.randrange(10,900)} units; a reviewer checked the equipment and saved the result.' for i in range(lines)]
        return '\n'.join(records)+'\nWrite a detailed twelve-point analysis of how to validate, store and audit these measurements. Use at least 400 words. Answer directly.'
    def calibrate(self,target):
        lines=max(1,target//27)
        for attempt in range(5):
            prompt=self.prompt(lines);self.kv_reset(f'calibrate-{target}-reset-{attempt}')
            result=self.stream(prompt,f'calibrate-{target}-{attempt}',count=1)
            assert result['ok'],result
            observed=result['prompt_tokens']
            if abs(observed-target)<=64:return prompt,observed
            lines=max(1,round(lines*target/observed))
        raise RuntimeError(f'Cannot calibrate a {target}-token prompt; observed {observed}')
    def summarize(self,rows):
        ok=[x for x in rows if x['ok']]
        result={'attempts':len(rows),'successes':len(ok),'failures':len(rows)-len(ok),
            'http_status_counts':{str(code):sum(x['http_status']==code for x in rows) for code in {x['http_status'] for x in rows}}}
        for key in ('first_text_ms','seconds','end_to_end_tokens_s','prompt_tokens','output_tokens'):
            values=[x[key] for x in ok if x.get(key) is not None]
            if values:result[key]={'median':statistics.median(values),'p95_nearest_rank':percentile(values,.95),'min':min(values),'max':max(values)}
        result['distinct_reply_hashes']=len({x['reply_sha256'] for x in ok})
        return result
    def run(self):
        self.start();self.sampler.start();self.phase('setup')
        assert not self.result('get_platform_state',{},'empty-start')['environments']
        self.host_memory('host-before');self.ledger('ledger-before')
        self.write('plan',{'model':self.args.model_id,'source':str(self.model),'quant':'UD-Q4_K_M','temperature':0,
            'agent_api':True,'thinking':'disabled by the standard agent API launch','samples_per_primary_length':self.args.samples,
            'primary_lengths':[512,2048,8192,16384],'output_limit':256,'cache':'explicit KV reset before each primary request; OS caches not flushed',
            'diagnostic_timings':'separate instrumented requests, not mixed into primary API latency',
            'gpu_sampling_ms':200,'tail_limits':'Small-sample descriptive p95; not a production tail-latency guarantee',
            'resources':{'cpu':8,'memory_gb':24,'storage_drive':'C:'},'scope':'Single model performance, no model-quality or other-system superiority claim'})
        selection={'model':self.args.model_id,'quant':'Q4_K_M'}
        if not self.args.repository:selection['folder']=str(self.model)
        checked=self.result('model_preflight',selection)
        self.write('preflight',checked)
        if self.args.expected_revision:assert checked['revision']==self.args.expected_revision,'Repository revision changed'
        if self.args.expected_sha256:
            assert len(checked['files'])==1 and checked['files'][0]['sha256']==self.args.expected_sha256,'Checkpoint identity changed'
        begin=time.perf_counter()
        submitted=self.command('call','run_model','--yes','--no-wait','--file','-',params={**selection,'port':self.port,
            'resources':{'storageDrive':'C:\\','cpu':8,'memoryGb':24,'agentApi':True}},label='submitted')
        job=submitted['result']['jobId'];deadline=time.monotonic()+5400;prior=None
        while time.monotonic()<deadline:
            status=self.result('jobs_get',{'jobId':job,'wait':1000})
            progress=status.get('progress')
            if progress!=prior:self.write('creation-progress',status);prior=progress
            if status['status'] in ('complete','failed','cancelled','interrupted'):self.write('creation-terminal',status)
            if status['status']=='complete':
                self.created=status['result'];self.environment_id=self.created['id'];break
            if status['status'] in ('failed','cancelled','interrupted'):raise RuntimeError('Creation failed; job evidence retained')
            time.sleep(1)
        else:raise TimeoutError('Model creation exceeded 90 minutes')
        health=self.wait_ready()
        if self.args.expected_revision:assert health['revision']==self.args.expected_revision,'The loaded revision differs from the pinned model'
        self.write('first-ready',{'setup_seconds':time.perf_counter()-begin,'health':health})
        self.ledger('ledger-ready');self.catalog('catalog-ready')
        self.phase('warmup')
        warm=self.stream('Explain what a secure sandbox does in two sentences.','warmup',count=64)
        assert warm['ok'],warm
        prompts={}
        for target in (512,2048,8192,16384):
            self.phase(f'calibration-{target}');prompt,tokens=self.calibrate(target);prompts[target]=prompt
            self.write(f'prompt-{target}',{'prompt':prompt,'actual_tokens':tokens})
            self.phase(f'uncached-{target}');rows=[]
            for index in range(self.args.samples):
                self.kv_reset(f'uncached-{target}-reset-{index}')
                result=self.stream(prompt,f'uncached-{target}-{index}');rows.append(result)
                if not result['ok'] and result['http_status']==400:break
            self.groups[f'uncached-{target}']=self.summarize(rows)
        self.phase('cached-2048');rows=[]
        self.kv_reset('cached-warmup-reset');self.stream(prompts[2048],'cached-warmup')
        for index in range(self.args.samples):rows.append(self.stream(prompts[2048],f'cached-2048-{index}'))
        self.groups['cached-2048']=self.summarize(rows)
        for concurrency in (2,4):
            self.phase(f'concurrency-{concurrency}');rows=[];waves=[]
            for wave in range(3):
                self.kv_reset(f'concurrency-{concurrency}-reset-{wave}')
                barrier=threading.Barrier(concurrency);start=time.perf_counter()
                with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                    futures=[pool.submit(self.stream,prompts[2048],f'concurrent-{concurrency}-{wave}-{i}',256,barrier) for i in range(concurrency)]
                    batch=[f.result() for f in futures]
                seconds=time.perf_counter()-start;rows.extend(batch)
                waves.append({'seconds':seconds,'accepted':sum(x['ok'] for x in batch),
                    'output_tokens_s':sum(x.get('output_tokens',0) for x in batch)/seconds})
            self.groups[f'concurrency-{concurrency}']={**self.summarize(rows),'waves':waves}
        self.phase('backend-diagnostics')
        self.result('model_measurement',{'environmentId':self.environment_id,'action':'start'},'measurement-start');self.measurement_active=True
        for target,prompt in prompts.items():
            for index in range(3):
                self.kv_reset(f'diagnostic-{target}-reset-{index}');self.stream(prompt,f'diagnostic-{target}-{index}')
            self.result('model_measurement',{'environmentId':self.environment_id,'action':'collect'},f'measurement-collect-{target}')
        self.result('model_measurement',{'environmentId':self.environment_id,'action':'seal'},'measurement-seal');self.measurement_active=False
        exported=self.result('model_measurement',{'environmentId':self.environment_id,'action':'export'},'measurement-export')
        shutil.copyfile(exported['path'],self.root/'backend-measurements.json')
        self.phase('idle-wake');wakes=[]
        for index in range(3):
            self.result('model_optimizer',{'environmentId':self.environment_id,'enabled':True,'pinned':False,'idleTimeoutSeconds':10},f'idle-{index}-settings')
            start=time.perf_counter();deadline=time.monotonic()+180
            while time.monotonic()<deadline:
                h=self.result('model_status',{'environmentId':self.environment_id})
                if h.get('status')=='idle' and h.get('optimizer',{}).get('resident') is False:break
                time.sleep(.5)
            else:raise TimeoutError('Model never unloaded after the idle timeout')
            self.write(f'idle-{index}',{'observed_seconds_after_setting':time.perf_counter()-start,'health':h})
            time.sleep(1)
            result=self.stream(prompts[512],f'wake-{index}')
            wakes.append({'request':result,'health':self.result('model_status',{'environmentId':self.environment_id})})
            self.result('model_optimizer',{'environmentId':self.environment_id,'enabled':True,'pinned':False,'idleTimeoutSeconds':0},f'idle-{index}-restored')
        self.groups['wake']={'samples':wakes,'summary':self.summarize([x['request'] for x in wakes])}
        reloads=[]
        for index in range(2):
            self.phase(f'process-reload-{index}')
            self.result('stop_model',{'environmentId':self.environment_id},f'reload-{index}-stop')
            start=time.perf_counter();self.result('start_model',{'environmentId':self.environment_id},f'reload-{index}-start')
            health=self.wait_ready();reloads.append({'seconds':time.perf_counter()-start,'health':health})
            reply=self.stream(prompts[512],f'reload-{index}-request');assert reply['ok'],reply
        self.groups['process-reloads']=reloads
        self.phase('cleanup');self.clean()
        assert not self.result('get_platform_state',{},'empty-finish')['environments']
        ledger=self.ledger('ledger-cleanup') or {};assert not ledger.get('open') and not ledger.get('models'),ledger
        self.catalog('catalog-cleanup',empty=True)
        assert self.source_hashes=={str(p.relative_to(self.model)):combined.migration.digest(p) for p in self.model.rglob('*') if p.is_file()}
        time.sleep(2);self.sampler.stop();self.stop()
        self.write('complete',{'groups':self.groups,'gpu':self.sampler.summary(),'source_unchanged':True,'cleanup_verified':True,
            'all_attempts_retained':True,'primary_failures':sum(g.get('failures',0) for n,g in self.groups.items() if n.startswith('uncached-'))})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('root','engine','cli','runtime','model','catalog-root'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--model-id',default='local/qwen38-27b-benchmark');parser.add_argument('--port',type=int,default=18893)
    parser.add_argument('--repository',help='Use the standard Hugging Face launch instead of importing the local folder')
    parser.add_argument('--expected-revision');parser.add_argument('--expected-sha256')
    parser.add_argument('--samples',type=int,default=10);args=parser.parse_args()
    assert 3<=args.samples<=100
    if args.repository:args.model_id=args.repository
    args.reuse_fixture=False;args.from_case=0
    run=Run(args)
    try:run.run()
    except BaseException as error:
        run.write('FAILED',{'type':type(error).__name__,'error':str(error)})
        raise
    finally:
        if run.measurement_active and run.environment_id:
            run.call('model_measurement',{'environmentId':run.environment_id,'action':'seal'},'cleanup-measurement',checked=False)
        if not run.environment_id and run.process is not None and run.process.poll() is None:
            state=run.result('get_platform_state',{},'cleanup-state')
            for row in state['environments']:
                if row.get('name')==args.model_id.split('/')[-1]:run.environment_id=row['id']
        run.clean();run.stop();run.sampler.stop()


if __name__=='__main__':main()
