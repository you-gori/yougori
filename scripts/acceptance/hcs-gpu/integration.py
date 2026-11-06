"""Opt-in integration checks through the real engine/CLI. Creates only disposable VMs.
No downloads, Wi-Fi bridge, public exposure, driver installation or paid resources.
Windows may request UAC approval for each GPU VM.
"""
import argparse
import json
import os
import re
from pathlib import Path
import subprocess
import time


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--cli", required=True)
    ap.add_argument("--output", required=True, type=Path)
    ap.add_argument("--internet", action="store_true")
    ap.add_argument("--memory-gb", type=int, default=4)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    workspace=args.output / "workspace"
    workspace.mkdir()
    (workspace / "input.txt").write_bytes(b"owned test source\n")
    results=[]
    held=[]
    created=[]
    def call(method,params):
        proc=subprocess.run([args.cli,"call",method,"--file","-","--yes"],input=json.dumps(params),capture_output=True,text=True,encoding="utf-8",timeout=240,env={**os.environ,"YOUGORI_NO_UPDATE_CHECK":"1"})
        response=json.loads(proc.stdout)
        if proc.returncode or not response.get("ok"): raise RuntimeError(response.get("error",proc.stderr))
        return response["result"]
    def vm(**params):return call("sandbox_vm",params)
    def check(name,value):
        results.append({"check":name,"result":value})
        (args.output / "results.json").write_text(json.dumps(results,indent=2),encoding="utf-8")
        print(name,flush=True)
    def execute(sandbox,script):
        result=vm(action="exec",sandbox=sandbox,input="set -eu\n"+script,timeoutSeconds=45,maxOutputBytes=32768)
        check("exec",result)
        if result.get("exit_code")!=0:raise RuntimeError(result.get("output_text","guest command failed"))
        return result["output_text"]
    try:
        check("capabilities",vm(action="capabilities"))
        cpu=vm(action="launch",cpu=1,memoryGb=1,idleSeconds=0,lifetimeSeconds=0)["sandbox"]
        held.append(cpu)
        created.append(cpu)
        cpu_output=execute(cpu,'test ! -e /dev/dxg; id -u; cat /proc/sys/kernel/random/boot_id; echo GPU_OFF_PASS')
        check("CPU VM stopped",vm(action="stop",sandbox=cpu));held.remove(cpu)
        baseline=call("model_ledger",{})
        gpu=vm(action="launch",gpu=True,cpu=2,memoryGb=args.memory_gb,workspace=str(workspace.resolve()),internet=args.internet,idleSeconds=0,lifetimeSeconds=0)["sandbox"]
        held.append(gpu)
        created.append(gpu)
        output=execute(gpu,'id -u; cat /proc/sys/kernel/random/boot_id; test -c /dev/dxg; /opt/yougori-gpu/cuda-probe')
        assert "CUDA KERNEL PASS:" in output and "uid=1000" in output,output
        assert cpu_output.splitlines()[1] != output.splitlines()[1],"guest kernel boot identity reused"
        mounts=execute(gpu,'test "$(cat "$WORKSPACE/input.txt")" = "owned test source"; printf "guest change\\n" > "$WORKSPACE/output.txt"; cat /proc/mounts; echo WORKSPACE_PASS')
        assert not re.search(r" (9p|virtiofs|drvfs|cifs) ", mounts),"host filesystem share present"
        assert not (workspace / "output.txt").exists()
        check("workspace review",vm(action="workspace",op="review",sandbox=gpu))
        if args.internet:
            execute(gpu,'/bin/busybox ip addr; /bin/busybox ip route; page=$(/bin/busybox wget -qO- https://example.com); test -n "$page"; printf "%.100s\\n" "$page"')
        else:
            execute(gpu,'test ! -e /sys/class/net/eth0; echo OFFLINE_PASS')
        during=call("model_ledger",{})
        check("ledger while running",during)
        before_ids={row["id"] for row in (baseline or {}).get("open",[])}
        held_ids={row["id"] for row in during["open"] if row["id"] not in before_ids}
        assert held_ids and any(row["id"] in held_ids and row["currentBytes"]>0 for row in during["open"])
        check("GPU VM stopped",vm(action="stop",sandbox=gpu));held.remove(gpu)
        after=call("model_ledger",{})
        check("ledger after stop",after)
        assert not held_ids.intersection(row["id"] for row in after["open"]),"VM reservations survived stop"
        check("complete",True)
    finally:
        for sandbox in held:
            try: check("cleanup",vm(action="stop",sandbox=sandbox))
            except Exception as error: check("cleanup error",str(error))
        for sandbox in created:
            try: check("discard test workspace",vm(action="workspace",op="discard",sandbox=sandbox))
            except Exception as error: check("discard error",str(error))

if __name__=="__main__":main()
