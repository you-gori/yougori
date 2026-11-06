"""Yougori's idempotent model receiver. Credentials arrive in a short-lived file."""
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
from store import Store, digest
from upstream import address, discover


def receive(store, request):
    if not isinstance(request, dict):
        raise ValueError("Expected a model request.")
    environment = request.get("environment")
    if not isinstance(environment, str) or not 1 <= len(environment) <= 200 or any(ord(c) < 33 for c in environment):
        raise ValueError("Expected a model environment identity.")
    endpoint = "yg-" + digest(environment)[:32]
    if request.get("action") == "detach":
        with store.db() as db:
            removed = db.execute("DELETE FROM endpoints WHERE id=?", (endpoint,)).rowcount
            store.audit(db, "yougori", "endpoint.detached", endpoint)
        return {"detached": bool(removed)}
    if request.get("action") != "attach":
        raise ValueError("Unknown model request.")
    url, key, name, place = address(request.get("url")), request.get("key"), request.get("model"), request.get("place")
    if not isinstance(name, str) or not name.strip() or len(name) > 200 or place not in ("local", "neocloud"):
        raise ValueError("Invalid model identity or placement.")
    models = discover(url, key)
    with store.db() as db:
        db.execute("BEGIN IMMEDIATE")
        exists = db.execute("SELECT 1 FROM endpoints WHERE id=?", (endpoint,)).fetchone()
        if not exists and db.execute("SELECT COUNT(*) FROM endpoints").fetchone()[0] >= 10:
            raise ValueError("At most ten model servers can be connected.")
        if db.execute("SELECT 1 FROM endpoints WHERE url=? AND id!=?", (url, endpoint)).fetchone():
            raise ValueError("This model server is already connected manually.")
        db.execute("INSERT INTO endpoints VALUES(?,?,?,?,?,'ready',?,?) ON CONFLICT(id) DO UPDATE SET "
                   "name=excluded.name,url=excluded.url,secret=excluded.secret,place=excluded.place,"
                   "state=excluded.state,checked=excluded.checked,detail=excluded.detail",
                   (endpoint, name[:60], url, key, place, int(time.time()), "Attached by Yougori; catalog connected."))
        db.execute("DELETE FROM models WHERE endpoint_id=?", (endpoint,))
        db.executemany("INSERT INTO models VALUES(?,?,?)", [(endpoint + ":" + model, endpoint, model) for model in models])
        store.audit(db, "yougori", "endpoint.attached", endpoint)
    return {"attached": True, "reachable": True, "name": name, "models": len(models)}


def main():
    try:
        if len(sys.argv) != 2:
            raise ValueError("Expected one private request file.")
        file = Path(sys.argv[1])
        try:
            with file.open("rb") as incoming:
                raw = incoming.read(65537)
            if len(raw) > 65536:
                raise ValueError("Request too large.")
            request = json.loads(raw)
        finally:
            file.unlink(missing_ok=True)
        result = receive(Store(os.environ.get("SOLVER_DATA", "/data")), request)
    except Exception:
        # Errors from libraries and servers can contain credentials. Never print them.
        print(json.dumps({"error": "Model attachment failed. Check the running server, its credential, and the website's connection limit."}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
