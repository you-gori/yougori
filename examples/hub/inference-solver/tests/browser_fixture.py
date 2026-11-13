"""A disposable service for browser checks; ends when its parent's stdin closes or sends an empty line.

Lines it reads before then change what it serves, each answered with one line:
`unpublish NAME...` removes those harnesses' published VM images (every harness's without a name), as
before the administrator publishes them, and answers `unpublished`; `publish` publishes every image
again and answers `published`.
"""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow
from artifact_fixture import publish_catalog_fixtures, unpublish_catalog_fixtures
import harness_download
import neocloud

# Rent a cloud GPU asks no real provider: this address answers nothing, so the page says so.
for name in ("RUNPOD_GRAPHQL", "RUNPOD_REST", "VAST", "HUGGING_FACE"):
    setattr(neocloud, name, "http://127.0.0.1:9")

fixture = Flow()
if len(sys.argv) > 1:
    fixture.account_mode = sys.argv[1]
try:
    fixture.setUp()
    publish_catalog_fixtures(fixture.temp.name)
    fixture.endpoint()
    print(fixture.url, flush=True)
    for line in iter(sys.stdin.readline, ""):
        words = line.split()
        if not words:
            break
        if words[0] == "unpublish":
            catalog = harness_download.catalog()
            for name in words[1:]:
                if name not in catalog:
                    raise SystemExit(f"No harness {name} to unpublish.")
            unpublish_catalog_fixtures(fixture.temp.name, words[1:])
            print("unpublished", flush=True)
        elif words[0] == "publish":
            publish_catalog_fixtures(fixture.temp.name)
            print("published", flush=True)
        else:
            raise SystemExit(f"Unknown fixture command {words[0]}.")
finally:
    fixture.tearDown()
