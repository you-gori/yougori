"""Optional contributor CLI. Rentals always run on the website's backend.

Inference requests arrive over one long-lived stream from the website (action "stream"), the
moment each is queued, and their answers go back over kept-alive connections, so a request costs
no polling delay and no new TLS handshake per chunk. A website without the stream is polled.
"""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import sys
import threading
import time
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from compute_adapter import Adapter, ComputeError, executable
from grid_adapter import GridAdapter
from harnesses.transport import LocalConnection

# Requests this computer serves at once, across its shared models. The website never sends more.
CAPACITY = 8
# The website sends a comment at least every 15 seconds; three missed ones mean the stream is gone.
STREAM_SILENCE = 45
# A request handed over while the previous one's slot is being freed waits this long for it; the
# website fails a request over if it is not acknowledged within eight seconds.
ACK_WAIT = 5
LIMIT = 3 * 1024 * 1024


class SiteError(Exception):
    def __init__(self, status):
        super().__init__("The website answered HTTP " + str(status) + ".")
        self.status = self.code = status


class Replaced(ComputeError):
    """A second connector was started for this computer with the same credential."""


class Link:
    """Kept-alive connections to the website. Never through a proxy, never following redirects."""

    def __init__(self, server):
        parts = urlsplit(server)
        if parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or parts.path not in ("", "/"):
            raise ComputeError("Use the inference website's address, such as https://name.yougori.com.")
        self.server, self.https = server.rstrip("/"), parts.scheme == "https"
        self.host, self.port = parts.hostname, parts.port or (443 if parts.scheme == "https" else 80)
        self.idle, self.lock = [], threading.Lock()
        self.context = ssl.create_default_context() if self.https else None

    def connection(self, timeout):
        if self.https:
            return http.client.HTTPSConnection(self.host, self.port, timeout=timeout, context=self.context)
        return LocalConnection(self.host, self.port, timeout=timeout)

    def open(self, path, payload, token=None, timeout=30, connection=None):
        """Sends one POST and returns its response; the caller reads it."""
        connection = connection or self.connection(timeout)
        headers = {"Content-Type": "application/json", "Origin": self.server}
        if token:
            headers["Authorization"] = "Bearer " + token
        connection.request("POST", path, json.dumps(payload).encode(), headers)
        return connection, connection.getresponse()

    def post(self, path, payload, token=None, timeout=30):
        for attempt in (0, 1):
            with self.lock:
                reused = self.idle.pop() if self.idle else None
            connection = reused or self.connection(timeout)
            try:
                if connection.sock:
                    connection.sock.settimeout(timeout)
                connection, response = self.open(path, payload, token, timeout, connection)
                raw = response.read(LIMIT + 1)
            except (http.client.RemoteDisconnected, ConnectionResetError, BrokenPipeError):
                connection.close()
                # A kept-alive connection the other end had closed: the request never arrived.
                if reused and attempt == 0:
                    continue
                raise
            except BaseException:
                connection.close()
                raise
            if response.will_close or len(raw) > LIMIT:
                connection.close()  # An oversized reply is left half read: never reused.
            else:
                with self.lock:
                    if len(self.idle) < CAPACITY + 2:
                        self.idle.append(connection)
                    else:
                        connection.close()
            if len(raw) > LIMIT:
                raise ComputeError("The website returned an oversized request.")
            if not 200 <= response.status < 300:
                raise SiteError(response.status)  # A redirect is never followed.
            return json.loads(raw)
        raise ComputeError("The website closed the connection.")


def site_request(server, path, payload, token=None):
    """One request to the website on a connection of its own; a redirect is an error (SiteError)."""
    return Link(server).post(path, payload, token)


def receive(link, token, deliver, stopped, connected=None):
    """Reads the website's request stream until it ends. Returns False if the website has none."""
    connection, response = link.open("/api/compute/agent", {"action": "stream", "capacity": CAPACITY}, token, STREAM_SILENCE)
    try:
        if response.status == 400:
            return False  # An older website: poll it instead.
        if response.status != 200:
            raise SiteError(response.status)
        if connected:
            connected()
        lines = []
        while not stopped.is_set():
            line = response.readline(LIMIT + 1)
            if not line:
                return True  # The website ended this stream; the caller opens the next one.
            if len(line) > LIMIT:
                raise ComputeError("The website sent an oversized request.")
            line = line.rstrip(b"\r\n")
            if line.startswith(b"data:"):
                lines.append(line[5:].strip())
            elif not line and lines:
                event, lines = json.loads(b"\n".join(lines)), []
                if isinstance(event, dict) and event.get("replaced") is True:
                    raise Replaced("Another connector is running for this computer with the same credential. Stop one of them; a computer runs one connector.")
                if isinstance(event, dict) and isinstance(event.get("inference"), dict):
                    deliver(event["inference"])
        return True
    finally:
        connection.close()


def main(server):
    parser = argparse.ArgumentParser(description="Contribute selected models and optional, resource-limited Sandbox VMs. No host commands or cloud purchases.")
    parser.add_argument("--reconnect", action="store_true")
    args = parser.parse_args()
    command = executable()
    if not command:
        raise ComputeError("Install and start Yougori on the contributing computer first.")
    link = Link(server)
    identity = hashlib.sha256(server.encode()).hexdigest()[:16]
    folder = Path(os.getenv("LOCALAPPDATA", Path.home() / ".local/share")) / "InferenceSolver" / ("node-" + identity)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        user = subprocess.check_output(["whoami"], text=True).strip()
        subprocess.run(["icacls", str(folder), "/inheritance:r", "/grant:r", user + ":(OI)(CI)F"], check=True, capture_output=True)
    else:
        folder.chmod(0o700)
    adapter = Adapter(command, folder)
    available = adapter.inventory()["models"]
    print("Choose the models this website may use. Other models and files stay private.")
    for index, model in enumerate(available, 1):
        print(f"  {index}. {model['name']} ({model['state']})")
    selected = [v for v in input("Model numbers, separated by commas (Enter for none): ").split(",") if v.strip()]
    if any(not v.strip().isdigit() or not 1 <= int(v) <= len(available) for v in selected):
        raise ComputeError("Choose valid model numbers. Nothing was connected.")
    chosen = {available[int(v) - 1]["id"] for v in selected}
    for prior in list(adapter.shared - chosen):
        adapter.share(prior, False)
    for model in chosen:
        adapter.share(model)
    capacity = {}
    if input("Allow this website to run isolated Sandbox VMs on this PC? [y/N]: ").strip().lower() == "y":
        for key, prompt, maximum in (("cpu","Total CPU cores",64),("memory_gb","Total memory in GB",256),("slots","Maximum simultaneous VMs",16)):
            number = input(prompt + ": ")
            if not number.isdigit() or not 1 <= int(number) <= maximum:
                raise ComputeError("Invalid resource limit. Nothing was connected.")
            capacity[key] = int(number)
        print("Only new restricted VMs are shared. No host folders, host commands or outside network access. VMs run until stopped or this connector disconnects.")
    if not chosen and not capacity:
        raise ComputeError("Choose at least one model or a sandbox contribution.")
    grid_adapter = GridAdapter(command, folder, capacity)
    # A previous connector's VMs must be stopped before reusing its capacity.
    grid_adapter.stop_all()
    file = folder / "credential"
    token = file.read_text(encoding="utf-8") if file.exists() and not args.reconnect else secrets.token_urlsafe(32)

    def request(path, payload, authenticated=False):
        return link.post(path, payload, token if authenticated else None)

    if not file.exists() or args.reconnect:
        pair = request("/api/compute/pair/start", {"name": socket.gethostname(), "role": "contributor", "credential_hash": hashlib.sha256(token.encode()).hexdigest()})
        print("Open " + server + "/#contribute and enter this computer code: " + pair["code"])
        print("The administrator approves it there, or a signed-in contributor joins under the website's public access policy.")
        end = time.monotonic() + 600
        while time.monotonic() < end:
            time.sleep(8)
            status = request("/api/compute/pair/poll", {"device": pair["device"]})
            if status.get("connected"):
                file.write_text(token, encoding="utf-8")
                file.chmod(0o600)
                break
            if status.get("expired"):
                raise ComputeError("This computer code expired. Start again for a new code.")
        else:
            raise ComputeError("Computer approval timed out.")
    slots, last_inventory, last_grid = threading.BoundedSemaphore(CAPACITY), 0, 0
    grid_busy, stopped, disconnected, polling, replaced = (threading.Event() for _ in range(5))
    print("Connected. Selected models appear automatically. Keep this terminal running; Ctrl+C disconnects.")

    def send(data):
        """Uploads one reply chunk. A website that was briefly unreachable or full gets it again:
        the website accepts the same chunk twice, so a lost reply never ends the answer."""
        for attempt in range(3):
            try:
                return request("/api/compute/agent", {"action": "chunk", **data}, True)
            except SiteError as error:
                if error.status != 503 or attempt == 2:
                    raise
            except (OSError, http.client.HTTPException):
                if attempt == 2:
                    raise
            time.sleep(1)

    def quietly(action, data, attempts=1):
        for attempt in range(attempts):
            try:
                return request("/api/compute/agent", {"action": action, **data}, True)
            except Exception:
                time.sleep(.5)  # The website fails the request over to another computer.

    def infer(task, acknowledge):
        try:
            if acknowledge:
                # Confirms receipt while the model starts, again if the website was busy for a
                # moment; the website fails the request over to another computer otherwise.
                threading.Thread(target=quietly, args=("ack", {"id": task["id"]}, 4), daemon=True).start()
            adapter.inference(task, send)
        finally:
            slots.release()

    def take(task):
        # A finished request frees its slot a moment after the website hands over the next one.
        if slots.acquire(timeout=ACK_WAIT):
            infer(task, True)
        else:
            quietly("chunk", {"id": task["id"], "sequence": 0, "status": 429, "done": True})

    def deliver(task):
        threading.Thread(target=take, args=(task,), daemon=True).start()

    def listen():
        failures = 0
        while not stopped.is_set():
            try:
                if not receive(link, token, deliver, stopped, connected=lambda: polling.clear()):
                    polling.set()
                    return
                failures = 0
            except Replaced:
                replaced.set()
                return
            except SiteError as error:
                if error.status == 401:
                    disconnected.set()
                    return
                failures += 1
                stopped.wait(5)
            except (OSError, ValueError, ComputeError, http.client.HTTPException):
                failures += 1
                stopped.wait(2)
            if failures >= 3:
                # A website that keeps refusing the stream (full, for example) is polled meanwhile.
                polling.set()

    def grid_work(job):
        try:
            try:
                result = {"id":job["id"],"ok":True,"result":grid_adapter.execute(job)}
            except Exception:
                result = {"id":job["id"],"ok":False,"result":{"error":"VM action failed on the contributing computer. Inspect its Yougori diagnostics."}}
            request("/api/compute/agent",{"action":"grid_result",**result},True)
        finally:
            grid_busy.clear()

    threading.Thread(target=listen, daemon=True).start()
    try:
        while True:
            try:
                if disconnected.is_set():
                    raise SiteError(401)
                if replaced.is_set():
                    raise Replaced("Another connector is running for this computer with the same credential. Stop one of them; a computer runs one connector.")
                if time.monotonic() - last_inventory > 10:
                    request("/api/compute/agent", {"action": "inventory", **adapter.inventory(), "capacity": CAPACITY,
                                                   "grid": grid_adapter.advertisement(), "grid_vms": grid_adapter.inventory()}, True)
                    last_inventory = time.monotonic()
                if capacity and not grid_busy.is_set() and time.monotonic() - last_grid > 1:
                    last_grid = time.monotonic()
                    job = request("/api/compute/agent", {"action":"grid_poll"}, True)
                    if job:
                        grid_busy.set()
                        threading.Thread(target=grid_work,args=(job,),daemon=True).start()
                if polling.is_set() and slots.acquire(blocking=False):
                    try:
                        task = request("/api/compute/agent", {"action": "poll"}, True)
                        if "inference" in task:
                            threading.Thread(target=infer, args=(task["inference"], False), daemon=True).start()
                        else:
                            slots.release()
                    except Exception:
                        slots.release()
                        raise
                time.sleep(.3)
            except Replaced:
                raise
            except SiteError as error:
                if error.status == 401:
                    grid_adapter.stop_all()
                    raise ComputeError("This computer was disconnected. Run again with --reconnect for a new approval.") from None
                if time.monotonic() - last_inventory > 45:
                    grid_adapter.stop_all()
                time.sleep(5)
            except (OSError, ValueError, ComputeError, http.client.HTTPException):
                if time.monotonic() - last_inventory > 45:
                    grid_adapter.stop_all()
                print("Connection interrupted. Retrying; no new models or resources will be created.")
                time.sleep(5)
            except KeyboardInterrupt:
                grid_adapter.stop_all()
                raise
    finally:
        stopped.set()


if __name__ == "__main__":
    try:
        main(json.loads(Path(__file__).with_name("connection.json").read_text(encoding="utf-8"))["server"])
    except KeyboardInterrupt:
        print("Contributor disconnected.")
    except ComputeError as error:
        # Its own words: a disconnected computer is told to reconnect, not to check the address.
        sys.exit(str(error))
    except (OSError, ValueError):
        sys.exit("Contributor could not connect. Check Yougori and the website address, then retry.")
