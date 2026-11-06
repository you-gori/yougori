"""Check catalog cleanup after real model-launch admission refusals.

Uses the application's normal folder publication with a real model, then deliberately
invalid resource requests. No model may start. Check leases and views on the SAME
engine immediately after the refusal; restarting it would hide the original defect.
Only a cleaned disposable acceptance fixture may be reused. No installed engine.
"""
import argparse
import importlib.util
from pathlib import Path
import time


spec = importlib.util.spec_from_file_location(
    "combined_acceptance", Path(__file__).with_name("combined-model-vm.py"))
combined = importlib.util.module_from_spec(spec)
spec.loader.exec_module(combined)


class Refusal(combined.Combined):
    def run(self, expect_retained):
        self.write("refusal-source-before", self.source_hashes)
        self.start()
        state = self.result("get_platform_state", {}, "refusal-empty-fixture")
        assert not state.get("environments"), "fixture is not empty"
        deadline = time.monotonic() + 60
        views = self.root / "catalog" / "views"
        while time.monotonic() < deadline:
            catalog = self.catalog(None)
            if not catalog["catalog"]["live_leases"] and not (views.exists() and any(views.iterdir())):
                break
            time.sleep(1)
        self.catalog("refusal-catalog-before", empty=True)
        cases = [("cpu", {"cpu": 1}, "at least 2 CPU cores"),
                 ("storage", {"storageGb": 19}, "persistent storage")]
        if expect_retained:
            cases = cases[:1]
        for name, resources, reason in cases:
            reply = self.call("run_model", {"model": "local/refusal-qwen05",
                              "folder": str(self.model), "resources": resources},
                              "refusal-" + name, checked=False)
            assert not reply.get("ok") and reason in reply.get("error", ""), reply
            state = self.result("get_platform_state", {}, "refusal-state-" + name)
            assert not state.get("environments"), "refused launch created an environment"
            catalog = self.catalog("refusal-catalog-" + name)
            live_views = [p.name for p in views.iterdir()] if views.exists() else []
            self.write("refusal-views-" + name, {"views": live_views,
                        "live_leases": catalog["catalog"]["live_leases"]})
            assert any(row["published"]["objects"] > 0
                       for scope in catalog["catalog"]["scopes"]
                       for row in scope["classes"]), "publication was never reached"
            if expect_retained:
                assert live_views and catalog["catalog"]["live_leases"] > 0, "baseline defect not reproduced"
            else:
                assert not live_views and catalog["catalog"]["live_leases"] == 0, "refusal retained its binding"
        assert self.source_hashes == {str(p.relative_to(self.model)): combined.migration.digest(p)
                                      for p in self.model.rglob("*") if p.is_file()}
        self.stop()
        self.write("refusal-BASELINE-REPRODUCED" if expect_retained else "refusal-PASS",
                   {"cases": len(cases), "expected_retention": expect_retained,
                    "sources_unchanged": True, "no_environment_created": True})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("root", "engine", "cli", "runtime", "model"):
        parser.add_argument("--" + key, required=True, type=Path)
    parser.add_argument("--reuse-fixture", action="store_true")
    parser.add_argument("--expect-retained", action="store_true",
                        help="Baseline only: require the old leak to be positively observed")
    parser.set_defaults(from_case=0, port=18887)
    args = parser.parse_args()
    run = Refusal(args)
    try:
        run.run(args.expect_retained)
    finally:
        run.stop()


if __name__ == "__main__":
    main()
