#!/usr/bin/env python3
"""Install and launch server-bound harnesses; requires Python 3.12+ and Yougori.

Harnesses run inside Yougori Sandbox VMs. Model requests to the configured server are relayed
by the host launcher, which keeps the API key. By default the VM reaches nothing else;
--internet full also gives it the whole internet.
"""
import argparse
from functools import cache
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid
from urllib.parse import urlsplit
import urllib.request
import urllib.error

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import device_login
from transport import local_hostname, opener as transport_opener
PACKAGES = json.loads((HERE / "packages.json").read_text())


def call(argv, capture=False, check=True):
    return subprocess.run(argv, check=check, text=True, capture_output=capture)


def url(value):
    p = urlsplit(value)
    if p.scheme not in ("https", "http") or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
        raise ValueError("Use the website's URL, with no path or credentials.")
    if p.scheme == "http" and not local_hostname(p.hostname):
        raise ValueError("Remote websites require HTTPS.")
    if not 1 <= (p.port or 443) <= 65535 or any(ord(c) <= 32 for c in value):
        raise ValueError("Invalid service URL.")
    return value.rstrip("/")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def models(server, secret):
    req = urllib.request.Request(server + "/v1/models", headers={"Authorization": "Bearer " + secret})
    opener = transport_opener()
    with opener.open(req, timeout=20) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Catalog too large.")
    data = json.loads(raw)["data"]
    if not isinstance(data, list) or len(data) > 1000 or any(not isinstance(m, dict) or not isinstance(m.get("id"), str) for m in data):
        raise ValueError("Invalid model catalog.")
    return data


def private_folder(path):
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "nt":
        identity = call(["whoami"], capture=True).stdout.strip()
        call(["icacls", str(path), "/inheritance:r", "/grant:r", identity + ":(OI)(CI)F"], capture=True)
    else:
        path.chmod(0o700)


def supported(name):
    if PACKAGES[name].get("blocked"):
        raise ValueError(PACKAGES[name]["blocked"])


def profile(server):
    digest = hashlib.sha256(server.encode()).hexdigest()[:20]
    root = Path(os.environ.get("LOCALAPPDATA", Path.home() / ".local/share")) / "InferenceSolver" / digest
    private_folder(root)
    return root


from vm_host import launch

# What the harness VM may reach. Never nothing: prompts and replies always go to this inference,
# through Yougori's relay, with the API key kept outside the VM.
INTERNET = {"inference": "only this inference", "sites": "this inference and the chosen sites",
            "full": "this inference and the whole internet"}


def vm_size(cpu, memory):
    """The VM's virtual CPUs and host memory in GB, as chosen; None keeps the harness's default."""
    if cpu is not None and not 1 <= cpu <= 255:
        raise ValueError("Choose 1 to 255 CPUs for the harness VM.")
    if memory is not None and not 1 <= memory <= 1024:
        raise ValueError("Choose 1 to 1024 GB of memory for the harness VM.")
    return cpu, memory


def site_list(internet, value):
    """The chosen sites for --internet sites, checked; None for the other choices."""
    if internet != "sites":
        if value:
            raise ValueError("--sites needs --internet sites.")
        return None
    if not value:
        raise ValueError("Add --sites with the sites the harness may reach, such as github.com,pypi.org.")
    import vm_tunnel
    return vm_tunnel.sites(value.split(","))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["list", "install", "models", "run", "login", "check"])
    parser.add_argument("harness", nargs="?", choices=sorted(PACKAGES))
    parser.add_argument("--server", help="Inference Solver website URL; defaults to the downloaded connection.json")
    parser.add_argument("--model", help="Exact model ID from this server")
    parser.add_argument("--workspace", type=Path, help="Stage a copy of this project; review and promote changes through Yougori")
    parser.add_argument("--cpu", type=int, help="Virtual CPUs for the harness VM (default 2)")
    parser.add_argument("--memory", type=int, help="Host memory for the harness VM in GB (default 4; Shannon 6)")
    parser.add_argument("--internet", choices=sorted(INTERNET), default="inference",
                        help="inference: only this inference (default); sites: also the --sites; full: the whole internet as well")
    parser.add_argument("--sites", help="With --internet sites: comma-separated sites such as github.com,pypi.org "
                        "(each covers its subdomains; reached over HTTPS through Yougori's relay)")
    parser.add_argument("--key-stdin", action="store_true", help="Read the service key from protected stdin instead of prompting")
    parser.add_argument("--no-tty", action="store_true", help="Headless invocation")
    parser.add_argument("--no-browser", action="store_true", help="Print the sign-in address without opening a browser")
    args, extra = parser.parse_known_args()
    if args.action == "list":
        for name, spec in PACKAGES.items():
            print(name + ": " + (spec.get("blocked") or "isolated CLI profile; " + spec["version"]))
        return 0
    if args.action in ("run", "install", "check") and not args.harness:
        parser.error("Choose a harness.")
    if args.action in ("run", "install", "check"):
        supported(args.harness)
    cpu, memory = vm_size(args.cpu, args.memory)
    chosen_sites = site_list(args.internet, args.sites)
    bundled = json.loads((HERE / "connection.json").read_text()) if (HERE / "connection.json").exists() else {}
    server = url(args.server or bundled.get("server", ""))
    name = args.harness or bundled.get("harness")
    if name not in PACKAGES:
        raise ValueError("Choose the harness you want to connect.")
    supported(name)
    root = profile(server) / name
    private_folder(root)
    if args.action in ('run', 'check'):
        from vm_host import preflight
        preflight(name,server)  # Check runtime/image availability before asking for sign-in.
        if args.action == 'check':
            return 0  # Yougori asks its questions only once this harness can start.
    if args.action == "install":
        from vm_host import install
        install(name, server, root)
        return 0
    key_file = root / "api-key"
    if args.key_stdin:
        key = sys.stdin.readline(1026).strip()
        if not re.fullmatch(r"[!-~]{1,1024}", key):
            raise ValueError("Invalid API key.")
        catalog = models(server, key)  # Validate before saving; never use provider credentials.
        device_login.save(key_file, key)
    else:
        key = (device_login.login(server, name, key_file, False)
               if args.action == "login" or not key_file.exists() else key_file.read_text().strip())
        try:
            catalog = models(server, key)
        except urllib.error.HTTPError as error:
            if error.code != 401:
                raise
            key = device_login.login(server, name, key_file, False)
            catalog = models(server, key)
    if args.action == "login":
        return 0
    for index, entry in enumerate(catalog, 1):
        print(f"{index}. {entry['id']}")
    if args.action == "models":
        return 0
    if not catalog:
        raise ValueError("This server has no available models. Connect a model in its Admin page first.")
    model = args.model
    if not model:
        if len(catalog) == 1:
            model = catalog[0]["id"]
        elif sys.stdin.isatty():
            choice = int(input("Choose a model number: "))
            if not 1 <= choice <= len(catalog):
                raise ValueError("Invalid model number.")
            model = catalog[choice - 1]["id"]
        else:
            raise ValueError("Select a model with --model.")
    if model not in {m["id"] for m in catalog}:
        raise ValueError("The model is not available from this server with your key.")
    workspace = args.workspace.resolve(strict=True) if args.workspace else None
    if workspace and (not workspace.is_dir() or workspace == Path(workspace.anchor) or "," in str(workspace)):
        raise ValueError("Choose a project folder, not a drive root.")
    if args.harness == "swe":
        if workspace and not (workspace / ".git").is_dir():
            raise ValueError("SWE-agent needs a Git repository with its .git directory in the selected workspace.")
        if not any(argument.startswith("--problem_statement.") for argument in extra):
            if not sys.stdin.isatty():
                raise ValueError("Pass --problem_statement.text followed by the task for SWE-agent.")
            task = input("What should SWE-agent work on? ").strip()
            if not task:
                raise ValueError("Enter a task for SWE-agent.")
            extra += ["--problem_statement.text", task]
    extra = extra[1:] if extra[:1] == ["--"] else extra
    if name == "shannon" and not extra:
        if args.no_tty:
            raise ValueError('Headless Shannon needs -- --validate-model or -- --target URL. Omit --no-tty to open its command prompt.')
        print("Opening Shannon's command prompt. Type help for commands; exit closes the VM.", flush=True)
    reaches = INTERNET[args.internet] + (": " + ", ".join(chosen_sites) if chosen_sites else "")
    print("Inference Solver | " + name + " | " + server + " | reaches " + reaches, flush=True)
    return launch(args.harness, server, key_file, model, workspace, extra, not args.no_tty,
                  cpu=cpu, memory=memory, internet=args.internet == "full", sites=chosen_sites)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as error:
        sys.exit(str(error))
    except (KeyError, OSError, subprocess.CalledProcessError, http.client.HTTPException):
        sys.exit("Could not start. Check the selected harness, Yougori, service URL, sign-in, and available models. No fallback was launched.")
