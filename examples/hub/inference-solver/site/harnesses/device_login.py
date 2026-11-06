"""First-use browser approval. Credentials never appear in argv, URLs or output."""
import hashlib
import json
import os
import re
import secrets
import tempfile
import time
import urllib.error
import urllib.request
from transport import opener as transport_opener


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def request(server, path, data):
    req = urllib.request.Request(server + path, data=json.dumps(data).encode(),
                                 headers={"Content-Type": "application/json", "Origin": server})
    opener = transport_opener()
    try:
        with opener.open(req, timeout=20) as response:
            raw = response.read(65537)
    except urllib.error.HTTPError as error:
        if error.code == 429:
            raise ValueError("Too many sign-in attempts. Wait one minute and try again.") from None
        raise ValueError("The server refused sign-in. Check the server address and try again.") from None
    if len(raw) > 65536:
        raise ValueError("Invalid sign-in response.")
    result = json.loads(raw)
    if not isinstance(result, dict):
        raise ValueError("Invalid sign-in response.")
    return result


def save(path, key):
    # The caller creates an owner-only directory before we write anything to it.
    handle, temporary = tempfile.mkstemp(prefix=".credential-", dir=path.parent)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(key)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def login(server, harness, key_file, open_browser=False):
    key = "is_" + secrets.token_urlsafe(32)
    state = request(server, "/api/device/start", {"harness": harness, "credential_hash": hashlib.sha256(key.encode()).hexdigest()})
    # Use the installed origin, not a server-supplied browser redirect.
    verification = server + "/#connect"
    code = state.get("user_code")
    device = state.get("device_code")
    if (not isinstance(code, str) or not re.fullmatch(r"[A-Z2-9]{4}-[A-Z2-9]{4}", code)
            or not isinstance(device, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", device)
            or not isinstance(state.get("expires_in"), int) or not 1 <= state["expires_in"] <= 600):
        raise ValueError("Invalid sign-in response.")
    interval = max(3, min(30, int(state.get("interval", 3))))
    print(f"\nSign in to Inference Solver\nOpen: {verification}\nEnter code: {code}\n", flush=True)
    print("Approve this harness on the website. This terminal will continue automatically.", flush=True)
    # Never open a browser/window automatically. The user follows the printed link.
    deadline = time.monotonic() + state["expires_in"]
    while time.monotonic() < deadline:
        time.sleep(interval)
        result = request(server, "/api/device/poll", {"device_code": device})
        status = result.get("status")
        if status == "approved":
            save(key_file, key)
            print("Connected. Continuing in your terminal.\n", flush=True)
            return key
        if status == "denied":
            raise ValueError("Connection denied or revoked. Run the command again to sign in.")
        if status == "expired":
            break
        if status not in ("pending", "slow_down"):
            raise ValueError("Invalid sign-in response.")
        if status == "slow_down":
            interval = min(interval + 3, 30)
    raise ValueError("The sign-in code expired. Run the command again for a new code.")
