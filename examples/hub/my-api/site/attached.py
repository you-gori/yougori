"""Models started with `yougori run hf.co/OWNER/MODEL --template INSTANCE`.

The Yougori CLI starts the model on this computer's GPU or on a rented Neocloud pod, links
this sandbox to it with a private connection, then runs this file here with one request:

    python /app/site/attached.py REQUEST_FILE      (or - to read standard input)

    {"action": "attach", "model": "hf.co/OWNER/MODEL", "environment": "ENV_ID",
     "url": "http://PRIVATE_ADDRESS:PORT/v1", "key": "MODEL_API_KEY", "place": "local"}
    {"action": "detach", "environment": "ENV_ID"}

The request file holds the model API's key, so it is deleted as soon as it is read, and
the key never appears in the answer. The model is then listed under its repository name
at the market rate for its size and called over that connection. Importing this file
runs nothing; only main() does.
"""
import json
import os
import re
import sqlite3
import sys
from urllib.parse import urlsplit

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import store
from transport import Failure, request as http_json

REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,95}){1,2}")
ENVIRONMENT = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
PLACES = ("local", "neocloud")
LIMIT = 64 * 1024


def repository(value):
    """`hf.co/Qwen/Qwen3-8B`, `https://huggingface.co/Qwen/Qwen3-8B` or `Qwen/Qwen3-8B`
    all name the model `Qwen/Qwen3-8B`."""
    name = value.strip() if isinstance(value, str) else ""
    for prefix in ("https://huggingface.co/", "http://huggingface.co/", "huggingface.co/", "hf.co/"):
        if name.lower().startswith(prefix):
            name = name[len(prefix):]
            break
    name = name.strip("/")
    if not REPOSITORY.fullmatch(name):
        raise ValueError("Name the model's repository, such as hf.co/OWNER/MODEL.")
    return name


def address(value):
    """The model API's base URL as this sandbox reaches it, such as http://10.88.0.5:8000/v1."""
    text = value.strip() if isinstance(value, str) else ""
    parts = urlsplit(text)
    if (len(text) > 512 or parts.scheme not in ("http", "https") or not parts.hostname
            or parts.username or parts.password or parts.query or parts.fragment):
        raise ValueError("The model's address must be an http or https URL without credentials.")
    return text.rstrip("/")


def secret(value):
    if not isinstance(value, str) or not 8 <= len(value) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise ValueError("The model's API key is missing or malformed.")
    return value


def environment(value):
    if not isinstance(value, str) or not ENVIRONMENT.fullmatch(value):
        raise ValueError("Name the environment that runs the model.")
    return value


def discover(db):
    """Every attached model whose API answers, for the catalogue. A stopped or unreachable
    model is left out until it answers again."""
    rows, status = [], {}
    for item in store.attached_models(db):
        try:
            http_json(item["url"] + "/models", headers={"Authorization": "Bearer " + item["key"]}, timeout=8)
        except Failure as error:
            # Any other answer still proves the API is up; no answer or a refused key does not.
            if error.code in ("provider_unavailable", "provider_auth"):
                status[item["model"]] = str(error)
                continue
        rows.append({"id": item["model"], "provider": "yougori", "upstream": item["model"]})
        status[item["model"]] = "Connected"
    return {"data": rows, "status": status}


def attach(db, request):
    model = repository(request.get("model"))
    place = request.get("place", "local")
    if place not in PLACES:
        raise ValueError("The model runs either on this computer (local) or on a Neocloud pod (neocloud).")
    store.attach_model(db, model, environment(request.get("environment")), address(request.get("url")),
                       secret(request.get("key")), place)
    found = discover(db)
    store.set_available(db, "attached", found["data"])
    row = db.execute("SELECT * FROM models WHERE name = ?", (model,)).fetchone()
    ready = bool(row and row["available"] and row["price_ready"])
    return {"attached": True, "name": model, "reachable": any(item["id"] == model for item in found["data"]),
            "status": found["status"].get(model, ""), "priced": ready,
            "priceIn": row["price_in"] if ready else None, "priceOut": row["price_out"] if ready else None,
            "currency": "USDT"}


def detach(db, request):
    removed = store.detach_model(db, environment(request.get("environment")))
    store.set_available(db, "attached", discover(db)["data"])
    return {"detached": removed}


def read(path):
    if path == "-":
        return sys.stdin.buffer.read(LIMIT + 1)
    try:
        with open(path, "rb") as handle:
            return handle.read(LIMIT + 1)
    finally:
        # The request holds the model's API key: it must not stay on disk.
        try:
            os.remove(path)
        except OSError:
            pass


def main(argv):
    if len(argv) != 2:
        print(json.dumps({"error": "Usage: attached.py REQUEST_FILE, or - for standard input."}))
        return 2
    try:
        raw = read(argv[1])
        if len(raw) > LIMIT:
            raise ValueError("The request is larger than 64 KiB.")
        request = json.loads(raw)
        if not isinstance(request, dict):
            raise ValueError("The request must be one JSON object.")
        action = request.get("action", "attach")
        if action not in ("attach", "detach"):
            raise ValueError("Use the action attach or detach.")
        db = store.setup()
        result = attach(db, request) if action == "attach" else detach(db, request)
    except (ValueError, OSError, sqlite3.Error) as error:
        print(json.dumps({"error": str(error)}))
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
