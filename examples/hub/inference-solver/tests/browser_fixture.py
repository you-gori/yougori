"""A disposable service for browser checks; ends when its parent's stdin closes."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_service import Flow
from artifact_fixture import publish_catalog_fixtures

fixture = Flow()
if len(sys.argv) > 1:
    fixture.account_mode = sys.argv[1]
try:
    fixture.setUp()
    publish_catalog_fixtures(fixture.temp.name)
    fixture.endpoint()
    print(fixture.url, flush=True)
    sys.stdin.readline()
finally:
    fixture.tearDown()
