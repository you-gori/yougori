"""Exercise the actual model HTTP server with a local, CUDA-backed Transformers model.

No downloads, external APIs or installed engine state. This tests concurrent serving,
not model provisioning or batching throughput. Credentials exist only in this process.
"""
import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import statistics
import tempfile
import threading
import time
import urllib.request
import urllib.error


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model",type=Path,required=True)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    import torch
    from transformers import AutoModelForCausalLM,AutoTokenizer
    if not torch.cuda.is_available(): raise RuntimeError("A CUDA GPU is required")
    root=Path(__file__).resolve().parents[2]
    source=root/"src-tauri/src/model_server.py"
    token=secrets.token_hex(32)
    records={"scope":"Current HTTP/generation code; local model initialization outside engine provisioning",
             "model":str(args.model.resolve()),"gpu":torch.cuda.get_device_name(0),"torch":torch.__version__,
             "source_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"groups":[],"attempts":[]}
    with tempfile.TemporaryDirectory(prefix="yougori-concurrent-") as cache:
        os.environ.update(YOUGORI_MODEL="local/concurrency-check",YOUGORI_MODEL_TOKEN=token,
                          YOUGORI_MODEL_ADMIN_TOKEN=secrets.token_hex(32),YOUGORI_GPU_OPTIMIZER="0",
                          YOUGORI_MODEL_FORMAT="safetensors",HF_HOME=cache)
        spec=importlib.util.spec_from_file_location("concurrency_server",source)
        runner=importlib.util.module_from_spec(spec);spec.loader.exec_module(runner)
        runner.TORCH=torch
        print("Loading the cached model on CUDA...",flush=True)
        runner.TOKENIZER=AutoTokenizer.from_pretrained(args.model,local_files_only=True,trust_remote_code=False)
        runner.NETWORK=AutoModelForCausalLM.from_pretrained(args.model,local_files_only=True,trust_remote_code=False,dtype=torch.float16).to("cuda").eval()
        runner.STATE.update(status="ready",error=None,chatTemplate=bool(runner.TOKENIZER.chat_template))
        listener=runner.Server(("127.0.0.1",0),runner.Handler)
        service=threading.Thread(target=listener.serve_forever,kwargs={"poll_interval":0.05},daemon=True);service.start()
        url="http://127.0.0.1:"+str(listener.server_port)+"/v1/chat/completions"
        def request(index,stream,barrier=None):
            if barrier: barrier.wait(10)
            started=time.monotonic()
            body={"messages":[{"role":"user","content":"Say hello in one short sentence. Request "+str(index)}],
                  "max_tokens":16,"temperature":0,"stream":stream}
            req=urllib.request.Request(url,data=json.dumps(body).encode(),headers={"Authorization":"Bearer "+token,"Content-Type":"application/json"})
            row={"index":index,"stream":stream}
            try:
                with urllib.request.urlopen(req,timeout=600) as response:
                    raw=response.read();row["status"]=response.status
                if stream:
                    events=[json.loads(line[6:]) for line in raw.decode().split("\n\n") if line.startswith("data: {")]
                    text="".join(event["choices"][0]["delta"].get("content","") for event in events if event.get("choices"))
                    finished=any(event.get("choices") and event["choices"][0].get("finish_reason") for event in events)
                    usage=next((event["usage"] for event in reversed(events) if "usage" in event),{})
                    row["complete"]=bool(finished and raw.rstrip().endswith(b"data: [DONE]"))
                else:
                    result=json.loads(raw);text=result["choices"][0]["message"]["content"];usage=result["usage"]
                    row["complete"]=bool(result["choices"][0]["finish_reason"])
                row.update(nonempty=bool(text.strip()),completion_tokens=usage.get("completion_tokens"),reply_sha256=hashlib.sha256(text.encode()).hexdigest())
            except urllib.error.HTTPError as error:
                row.update(status=error.code,error=error.read().decode()[:500])
            except Exception as error:
                row.update(status=None,error=type(error).__name__)
            row["seconds"]=time.monotonic()-started
            return row
        try:
            warmup=request(-1,False)
            if warmup.get("status")!=200: raise RuntimeError("Warmup failed: "+str(warmup))
            for count in (2,16,64):
                barrier=threading.Barrier(count+1)
                start=time.monotonic();maximum_waiting=0
                with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
                    futures=[pool.submit(request,index,index%2==0,barrier) for index in range(count)]
                    barrier.wait(10)
                    while not all(f.done() for f in futures):
                        maximum_waiting=max(maximum_waiting,runner.INFERENCE_QUEUE.snapshot()["waiting"])
                        time.sleep(0.01)
                    rows=[f.result() for f in futures]
                records["attempts"].extend({"callers":count,**row} for row in rows)
                good=sum(row.get("status")==200 and row.get("complete") and row.get("nonempty") for row in rows)
                group={"callers":count,"successful":good,"attempts":len(rows),"seconds":time.monotonic()-start,
                       "max_waiting_observed":maximum_waiting,"queue_after":runner.INFERENCE_QUEUE.snapshot(),
                       "latency_median_seconds":statistics.median(row["seconds"] for row in rows),
                       "http_429":sum(row.get("status")==429 for row in rows)}
                records["groups"].append(group);print(json.dumps(group),flush=True)
            records["gpu_peak_allocated_bytes"]=torch.cuda.max_memory_allocated()
            records["generation_lock_released"]=not runner.GENERATION.locked()
            records["gpu_active_after"]=runner.GPU_ACTIVE
            records["passed"]=all(g["successful"]==g["attempts"] and g["queue_after"]["active"]==0 and g["queue_after"]["waiting"]==0 for g in records["groups"])
        finally:
            listener.shutdown();listener.server_close();service.join(2)
            runner.NETWORK=None
            import gc
            gc.collect();torch.cuda.empty_cache()
            records["gpu_allocated_after_cleanup"]=torch.cuda.memory_allocated()
            args.report.write_text(json.dumps(records,indent=2),encoding="utf-8")
        if not records.get("passed") or not records.get("generation_lock_released") or records.get("gpu_active_after")!=0:
            raise RuntimeError("Concurrency acceptance failed; see report")


if __name__=="__main__":main()
