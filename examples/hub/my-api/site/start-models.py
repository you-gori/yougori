"""Run the selected provider services together in the private models sandbox."""
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time


HERE = Path(__file__).resolve().parent


def services(environment):
    selected = set(environment.get("SELECTED_PROVIDERS", "").split(","))
    result = []
    for mode, providers, port in (
        ("paid", {"codex", "claude", "gemini"}, 8080),
        ("free", {"opencode", "kilo"}, 8081),
    ):
        if selected & providers:
            env = {**environment, "BRIDGE_MODE": mode, "BRIDGE_PORT": str(port)}
            result.append((mode, [sys.executable, "-u", str(HERE / "bridge.py")], env))
    if "ollama" in selected:
        result.append(("ollama", ["sh", str(HERE / "start-ollama.sh")], dict(environment)))
    return result


def stop_child(child, force=False):
    if os.name == "posix":
        # Includes Ollama and its waiting shell, not just the immediate child.
        try:
            os.killpg(child.pid, signal.SIGKILL if force else signal.SIGTERM)
        except ProcessLookupError:
            pass
    elif child.poll() is None:
        child.kill() if force else child.terminate()


def supervise(specs, stopped, retry_seconds=5):
    children, retry_at = {}, {}
    try:
        if not specs:
            print("No providers selected. Add them with yougori template configure.", flush=True)
        while not stopped.is_set():
            for name, command, environment in specs:
                child = children.get(name)
                if child is not None and child.poll() is not None:
                    stop_child(child, force=True)
                    print(f"{name} stopped (exit {child.returncode}); restarting shortly.", flush=True)
                    del children[name]
                    retry_at[name] = time.monotonic() + retry_seconds
                if name not in children and time.monotonic() >= retry_at.get(name, 0):
                    try:
                        children[name] = subprocess.Popen(command, env=environment,
                                                          start_new_session=os.name == "posix")
                        print(f"Started {name} in the models sandbox.", flush=True)
                    except OSError:
                        print(f"Could not start {name}; retrying shortly.", flush=True)
                        retry_at[name] = time.monotonic() + retry_seconds
            stopped.wait(.2)
    finally:
        for child in children.values():
            stop_child(child)
        deadline = time.monotonic() + 5
        for child in children.values():
            try:
                child.wait(timeout=max(.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                pass
        for child in children.values():
            stop_child(child, force=True)
            child.wait()


if __name__ == "__main__":
    if len(os.environ.get("BRIDGE_KEY", "")) < 16:
        raise SystemExit("Set BRIDGE_KEY to at least 16 characters through a Hub secret.")
    stopped = threading.Event()
    for signum in (signal.SIGTERM, signal.SIGINT):
        signal.signal(signum, lambda *_: stopped.set())
    supervise(services(os.environ), stopped)
