"""Start one hosted development instance inside its Yougori Sandbox VM."""
import json
import os
from pathlib import Path
import re
import signal
import sys
import threading

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server import Service, Server


def load(folder):
    """The private per-instance configuration the website wrote for this instance."""
    raw = (Path(folder) / "provision.json").read_bytes()
    if len(raw) > 16384:
        raise ValueError("Invalid hosted instance.")
    config = json.loads(raw)
    if config["accessMode"] not in ("internal", "public") or not re.fullmatch(r"inf_[A-Za-z0-9_-]+", config["id"]):
        raise ValueError("Invalid hosted configuration.")
    return config


def build(folder, config, hosted, public=False):
    """A service for one website-created instance: the onboarding administrator, the fixed access
    mode, the compute choices and, once only, the grid admission and receiving wallet."""
    folder = Path(folder)
    service = Service(folder / "data", {"email": config["email"], "password_hash": config["passwordHash"]},
        config["siteName"], public=public, account_mode="public" if config["accessMode"] == "public" else "private",
        hosted={**hosted, "id": config["id"], "compute": config["compute"], "artifacts": config.get("artifacts")})
    try:
        with service.store.db() as db:
            actor = db.execute("SELECT id FROM users WHERE admin=1 ORDER BY rowid LIMIT 1").fetchone()[0]
            db.execute("CREATE TABLE IF NOT EXISTS hosted_identity(id INTEGER PRIMARY KEY CHECK(id=1), tenant TEXT NOT NULL, access TEXT NOT NULL)")
            previous = db.execute("SELECT tenant,access FROM hosted_identity WHERE id=1").fetchone()
            if previous and tuple(previous) != (config["id"], config["accessMode"]):
                raise ValueError("This data belongs to another inference or access mode.")
            db.execute("INSERT OR IGNORE INTO hosted_identity VALUES(1,?,?)", (config["id"], config["accessMode"]))
    except BaseException:
        # A refused instance leaves no background work holding its data behind.
        service.close()
        raise
    if not previous:
        service.grid.configure(actor, {"enabled": config["compute"]["sandboxGrid"], "admission": "private"})
        wallet = config.get("wallet")
        if wallet:
            service.payments.save(actor, wallet)
    return service


def create(folder, authority, runtime_folder):
    if not re.fullmatch(r"[a-z0-9]+\.localhost:[0-9]{1,5}", authority):
        raise ValueError("Invalid hosted instance.")
    return build(folder, load(folder), {"authority": authority, "runtime_folder": runtime_folder})


def serve(service, port):
    """Run the website on the loopback port until SIGTERM or SIGINT."""
    server = Server(("127.0.0.1", port), service)
    watcher = threading.Thread(target=service.watch, daemon=True)
    watcher.start()
    def stop(*_):
        service.stopped.set()
        threading.Thread(target=server.shutdown, daemon=True).start()
    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        server.serve_forever()
    finally:
        service.stopped.set()
        server.server_close()
        watcher.join(timeout=6)


def main():
    # No engine socket, CLI, host folders, provider credential or ambient network is given
    # to the guest. Computers connect to its own authenticated contributor endpoints.
    os.environ["SOLVER_COMPUTE"] = "0"
    serve(create(sys.argv[1], sys.argv[2], "/workspace/hosted-state"), 3000)


if __name__ == "__main__":
    main()
