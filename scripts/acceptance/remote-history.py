"""Real remote template lifecycle with archived terminal identities and restart.

Reuses the generated-template acceptance through the actual Windows/SSH/Linux VM
path, archiving each ended effect before the next template lifecycle operation.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import time

spec=importlib.util.spec_from_file_location("template",Path(__file__).with_name("remote-template.py"))
template=importlib.util.module_from_spec(spec)
spec.loader.exec_module(template)
home=template.home


class Run(template.Run):
    def __init__(self,args):
        self.archived={}
        super().__init__(args)

    def archive_live_probe(self,run):
        result=self.command("sandbox","remote","archive",run,"--yes",checked=False,label="live-archive-refused")
        assert result["ok"] is False
        assert self.remote("status","live-still-ready",run=run)["phase"]=="ready"
        assert (self.data/"sandbox-vm/remote-home/runs"/f"{run}.json").exists()

    def archive_terminal(self,run):
        original=self.remote("status","before-archive",run=run)
        assert original["phase"] in ("ended","creation_cancelled"),original
        until=time.monotonic()+20
        while True:
            result=self.command("sandbox","remote","archive",run,"--yes",checked=False)
            if result["ok"]: break
            assert "still finishing" in json.dumps(result) and time.monotonic()<until,result
            time.sleep(0.2)
        archived=result["result"]
        self.write("archive-through-cli",result)
        assert archived["archived"] is True and archived["receipt"]==original["receipt"]
        assert archived["launch"]==original["launch"] and archived["billing"]=="externally_managed"
        assert self.command("sandbox","remote","archive",run,"--yes",label="archive-retry")["result"]==archived
        assert self.remote("status","archived-key-lookup",request_key=original["request_key"])["match"]==archived
        assert self.remote("launch","archived-launch-retry",**original["launch"],request_key=original["request_key"])==archived
        assert self.remote("launch","archived-changed-launch-refused",False,
            **{**original["launch"],"program":"/different-engine"},request_key=original["request_key"])["ok"] is False
        assert self.remote("stop","archived-stop-readonly",run=run)==archived
        assert self.remote("reconcile","archived-reconcile-readonly",run=run)==archived
        root=self.data/"sandbox-vm/remote-home"
        assert not (root/"runs"/f"{run}.json").exists(),"Archived effect recreated an active journal"
        path=root/"history"/f"{run}.json"
        self.archived[run]=hashlib.sha256(path.read_bytes()).hexdigest()
        active=self.remote("status","active-list-after-archive")
        assert all(row["run"]!=run for row in active["runs"]),active
        listing=self.command("sandbox","remote","status","--archived","true",label="archive-page")["result"]
        assert listing["archive_limit"]==4096 and listing["archive_byte_limit"]==32*1024*1024
        assert any(row==archived for row in listing["runs"])
        assert listing["archived_count"]==len(self.archived) and len(listing["runs"])<=100
        for previous,digest in self.archived.items():
            assert hashlib.sha256((root/"history"/f"{previous}.json").read_bytes()).hexdigest()==digest
            assert self.remote("status",None,run=previous)["archived"] is True
            assert not (root/"runs"/f"{previous}.json").exists()
        self.write("archive-retained-proofs",{"count":len(self.archived),"hashes":self.archived})

    def run_template(self,args,server):
        super().run_template(args,server)
        assert len(self.archived)==4 and len(self.records())==4
        self.write("history-result",{"passed":True,"archived_runs":4,"template_groups":16,
            "checks":["active-refused-without-effects","exact-proof-and-request-retained","idempotent-archive",
                "archived-request-no-replay","changed-archived-request-refused","old-stop-reconcile-readonly",
                "template-start-update-remove-with-archived-predecessors","restart-retains-byte-identical-archives",
                "interrupted-template-adopts-archived-original","bounded-history-page","zero-final-ledgers"]})


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    home.arguments(parser)
    parser.add_argument("--distro",required=True)
    for name in ("server-script","server-root","server-engine","server-cli","server-runtime","server-host-public-key"):
        parser.add_argument("--"+name,required=True)
    parser.add_argument("--identity",type=Path,required=True)
    parser.add_argument("--port",type=int,default=22843)
    args=parser.parse_args()
    assert os.name=="nt"
    args.reuse_fixture,args.from_case,args.model,args.fixture=False,None,args.engine.parent,args.engine
    run,remote=Run(args),None
    try:
        remote=home.Server(args,run.root)
        run.run_template(args,remote)
    finally:
        if run.process and run.process.poll() is None:
            status=run.call("sandbox_vm",{"action":"status"},"fixture-cleanup-status",checked=False)
            for vm in status.get("result",{}).get("sandboxes",[]):
                run.call("sandbox_vm",{"action":"stop","sandbox":vm["sandbox"]},"fixture-cleanup-vm",checked=False)
            run.stop()
        if remote: remote.close()
