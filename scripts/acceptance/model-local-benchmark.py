"""Local benchmark extension: real HTTP first text, output rate and idle wake.

Run after compiler gates finish. Uses one disposable model, no host cache flush
or power changes. File/import comparisons use model-share-throughput's baseline;
inference results are current measurements, not an unmeasured speedup claim.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import statistics
import subprocess
import time
import urllib.request

spec = importlib.util.spec_from_file_location("share", Path(__file__).with_name("model-share-throughput.py"))
share = importlib.util.module_from_spec(spec)
spec.loader.exec_module(share)
SHORT = "What is an API? Answer in one short sentence."
LONG = ("A sandbox isolates a program. A model serves requests. A cache keeps reusable data. " * 40
        + "Summarize these three ideas in three short sentences.")


class Run(share.Run):
    def gpu(self, name):
        probe = subprocess.run(["nvidia-smi", "--query-gpu=uuid,name,driver_version,memory.total,memory.used,temperature.gpu,pstate",
                                "--format=csv,noheader,nounits"], capture_output=True, text=True,
                               timeout=20, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
        assert probe.returncode == 0, probe.stderr
        self.write(name, {"gpu":probe.stdout.strip(), "memory_note":"snapshot, not peak"})

    def stream(self, prompt, label):
        payload = json.dumps({"model":"local/share-benchmark-qwen05", "messages":[{"role":"user","content":prompt}],
                              "temperature":0, "max_tokens":64, "stream":True,
                              "stream_options":{"include_usage":True}}).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}/v1/chat/completions", data=payload,
            headers={"Content-Type":"application/json", "Authorization":"Bearer "+self.created["apiKey"]})
        started = time.perf_counter()
        first = None
        text = []
        usage = None
        finish = None
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with opener.open(request, timeout=120) as response:
            assert response.status == 200
            for line in response:
                if not line.startswith(b"data:"): continue
                body = line[5:].strip()
                if body == b"[DONE]": break
                event = json.loads(body)
                assert "error" not in event, event
                if event.get("usage"): usage = event["usage"]
                for choice in event.get("choices", []):
                    content = choice.get("delta",{}).get("content")
                    if content:
                        if first is None: first = time.perf_counter()
                        text.append(content)
                    if choice.get("finish_reason"): finish = choice["finish_reason"]
        elapsed = time.perf_counter()-started
        joined = "".join(text)
        assert joined.strip() and first is not None and finish and usage, {"text":joined,"finish":finish,"usage":usage}
        assert isinstance(usage.get("completion_tokens"),int) and usage["completion_tokens"] > 0
        result = {"seconds":elapsed,"first_text_ms":(first-started)*1000,
                  "output_tokens":usage["completion_tokens"],"prompt_tokens":usage["prompt_tokens"],
                  "output_tokens_per_second_end_to_end":usage["completion_tokens"]/elapsed,
                  "reply_sha256":hashlib.sha256(joined.encode()).hexdigest(),
                  "finish_reason":finish,"reply":joined}
        self.write(label,result)
        return result

    def benchmark_model(self):
        self.gpu("benchmark-gpu-before")
        self.write("benchmark-plan", {"samples_per_prompt":5,"prompts":{"short":SHORT,"long":LONG},
            "temperature":0,"max_tokens":64,"transport":"real localhost HTTP SSE; no CLI polling in timers",
            "first_text":"first nonempty text chunk, not a hardware token clock",
            "throughput":"backend completion tokens / complete HTTP request seconds",
            "gpu_peak":"runner allocator lifetime high-water, includes loading; host GPU snapshots are not peaks",
            "scope":"one local Qwen2.5-0.5B model; OS caches managed normally"})
        summaries = {}
        references = {}
        for name,prompt in (("short",SHORT),("long",LONG)):
            self.stream(prompt,f"benchmark-{name}-warmup")
            samples=[self.stream(prompt,f"benchmark-{name}-{i}") for i in range(5)]
            assert len({s["reply_sha256"] for s in samples}) == 1, "Greedy output changed between repetitions"
            references[name]=samples[0]["reply_sha256"]
            summaries[name]={"samples":5,"first_text_ms_median":statistics.median(s["first_text_ms"] for s in samples),
                "request_ms_median":1000*statistics.median(s["seconds"] for s in samples),
                "output_tokens_per_second_median":statistics.median(s["output_tokens_per_second_end_to_end"] for s in samples),
                "prompt_tokens":samples[0]["prompt_tokens"],"output_tokens":samples[0]["output_tokens"],
                "reply_sha256":references[name]}
        ready=self.result("model_status",{"environmentId":self.environment_id},"benchmark-health")
        self.write("benchmark-allocator", {"allocated_bytes":ready.get("optimizer",{}).get("allocatedBytes"),
            "reserved_bytes":ready.get("optimizer",{}).get("reservedBytes"),
            "lifetime_peak_allocated_bytes":ready.get("optimizer",{}).get("peakAllocatedBytes"),
            "note":"allocator high-water since this runner started; not a per-request or whole-device peak"})
        wakes=[]
        for index in range(2):
            self.result("model_optimizer",{"environmentId":self.environment_id,"enabled":True,"pinned":False,
                "idleTimeoutSeconds":10},f"wake-{index}-settings")
            deadline=time.monotonic()+90
            while time.monotonic()<deadline:
                health=self.result("model_status",{"environmentId":self.environment_id})
                if health.get("optimizer",{}).get("resident") is False and health.get("status")=="idle": break
                time.sleep(1)
            else: raise AssertionError("Model never became idle/unloaded")
            self.write(f"wake-{index}-idle",health)
            self.gpu(f"wake-{index}-gpu-idle")
            measured=self.stream(SHORT,f"wake-{index}-request")
            assert measured["reply_sha256"]==references["short"], "Wake changed greedy output"
            resumed=self.result("model_status",{"environmentId":self.environment_id},f"wake-{index}-health")
            wakes.append({"request":measured,"load":resumed.get("load")})
            self.result("model_optimizer",{"environmentId":self.environment_id,"enabled":True,"pinned":False,
                "idleTimeoutSeconds":0},f"wake-{index}-settings-restored")
        self.gpu("benchmark-gpu-after")
        self.write("benchmark-summary",{"inference":summaries,"wake":wakes,"current_measurements_only":True})


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("root","engine","cli","runtime","model"):
        parser.add_argument("--"+name,type=Path,required=True)
    parser.add_argument("--port",type=int,default=18891)
    parser.add_argument("--storage-drive")
    parser.add_argument("--reuse-fixture",action="store_true")
    args=parser.parse_args();args.from_case=0
    run=Run(args);run.storage_drive=args.storage_drive
    try: run.run()
    finally:
        run.clean()
        run.stop()

if __name__=="__main__": main()
