"""Cancel real catalog preparation through the job API, before any VM is created."""
import argparse
import importlib.util
from pathlib import Path
import time

spec=importlib.util.spec_from_file_location("combined",Path(__file__).with_name("combined-model-vm.py"))
combined=importlib.util.module_from_spec(spec);spec.loader.exec_module(combined)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("root","engine","cli","runtime","model"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();args.port=18891;args.reuse_fixture=False;args.from_case=0
    run=combined.Combined(args)
    try:
        run.start()
        assert not run.result("get_platform_state",{},"before")["environments"]
        start=run.command("call","run_model","--yes","--no-wait","--file","-",
            params={"model":"local/cancel-preparation","folder":str(run.model),"resources":{"storageDrive":"C:\\"}},label="submitted")
        job=start["result"]["jobId"]
        deadline=time.monotonic()+90
        while time.monotonic()<deadline:
            status=run.result("jobs_get",{"jobId":job,"wait":50})
            if status.get("status") in ("complete","failed","cancelled","interrupted"):
                raise AssertionError("Preparation ended before the catalog cancellation point: "+str(status.get("status")))
            progress=status.get("progress") or {}
            if progress.get("phase")=="modelImport" and progress.get("stage")=="catalog" and status.get("cancellable"):
                run.write("catalog-copy-observed",status)
                break
            time.sleep(.02)
        else: raise AssertionError("Catalog preparation did not become cancellable")
        begin=time.monotonic()
        run.result("jobs_cancel",{"jobId":job},"cancel-requested")
        while time.monotonic()<deadline:
            status=run.result("jobs_get",{"jobId":job,"wait":100})
            if status.get("status") in ("complete","failed","cancelled","interrupted"): break
        run.write("terminal",status)
        assert status["status"]=="cancelled" and status.get("errorCode")=="operation_cancelled",status
        assert not run.result("get_platform_state",{},"after")["environments"]
        run.catalog("catalog-cleanup",empty=True)
        ledger=run.ledger("ledger-cleanup")
        assert not ledger.get("open") and not ledger.get("models"),ledger
        assert run.source_hashes=={str(p.relative_to(run.model)):combined.migration.digest(p) for p in run.model.rglob("*") if p.is_file()}
        run.write("PASS",{"cancel_seconds":time.monotonic()-begin,"no_environment_created":True,
            "source_unchanged":True,"views_leases_and_ledger_empty":True,
            "published_verified_files_may_remain_for_retry":True})
    finally:
        # If the acceptance missed its intended phase, remove only an environment
        # created in this fresh installation, never a user's engine or workload.
        if run.process is not None and run.process.poll() is None:
            state=run.result("get_platform_state",{},"cleanup-state")
            for environment in state["environments"]:
                run.call("delete_environment",{"environmentId":environment["id"]},"cleanup-environment",checked=False)
        run.stop()

if __name__=="__main__":main()
