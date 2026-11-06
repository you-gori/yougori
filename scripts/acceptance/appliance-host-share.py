"""Smoke-test the rebuilt ordinary appliance payload through its real container.

Uses only an explicitly supplied disposable installation left empty by the model
benchmark. Verifies bytes, write refusal, detach, and removal; no GPU is requested.
"""
import argparse
import importlib.util
from pathlib import Path
import shlex

spec=importlib.util.spec_from_file_location("base",Path(__file__).with_name("model-migration-recovery.py"))
base=importlib.util.module_from_spec(spec);spec.loader.exec_module(base)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("root","engine","cli","runtime","model"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();args.reuse_fixture=True;args.from_case=0
    run=base.Run(args);environment=None
    def call(method,params,label):return run.call(method,params,label)["result"]
    def execute(command,label):
        return run.call("execute_environment_command",{"request":{"environmentId":environment,
            "command":command}},label,checked=False)
    try:
        run.start()
        assert not call("get_platform_state",{},"appliance-before")["environments"]
        request={"name":"Appliance share acceptance","description":"Disposable host file transport check",
            "kind":"container","provider":"yougoriOci","runtime":"docker.io/library/alpine:3.23",
            "gpuAccess":False,"networkAccess":True,"storageGb":4,"storageDrive":"C:\\",
            "resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1},
                              "memoryGb":{"min":1,"preferred":1,"max":1},"priority":"normal"}}
        state=call("create_environment",{"request":request},"appliance-create")
        rows=[row for row in state["environments"] if row["name"]==request["name"]]
        assert len(rows)==1;environment=rows[0]["id"]
        call("set_environment_status",{"environmentId":environment,"status":"running"},"appliance-start")
        source=run.root/"source";expected=base.digest(source/"payload.bin")
        shared=call("attach_host_folder",{"environmentId":environment,"path":str(source),"readOnly":True},"appliance-attach")
        path=shared["mountPath"]+"/payload.bin"
        reply=execute("sha256sum -- "+shlex.quote(path),"appliance-read")
        assert reply["ok"] and reply["result"]["exitCode"]==0,reply
        assert reply["result"]["stdout"].split()[0]==expected
        denied=execute("printf changed > "+shlex.quote(path),"appliance-write-refused")
        assert denied["ok"] and denied["result"]["exitCode"]!=0,denied
        call("detach_host_folder",{"shareId":shared["id"]},"appliance-detach")
        denied=execute("head -c 1 -- "+shlex.quote(path),"appliance-detached-read-refused")
        assert denied["ok"] and denied["result"]["exitCode"]!=0 and denied["result"]["stdout"]=="",denied
        assert base.digest(source/"payload.bin")==expected
        call("delete_environment",{"environmentId":environment},"appliance-delete");environment=None
        assert not call("get_platform_state",{},"appliance-after")["environments"]
        run.write("appliance-PASS",{"bytes_identical":True,"write_and_detached_read_refused":True,"source_unchanged":True})
    finally:
        if environment and run.process is not None and run.process.poll() is None:
            run.call("delete_environment",{"environmentId":environment},"appliance-cleanup",checked=False)
        run.stop()

if __name__=="__main__":main()
