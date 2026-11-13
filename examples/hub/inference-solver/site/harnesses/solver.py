#!/usr/bin/env python3
"""Install and launch server-bound harnesses; requires Python 3.12+ and Yougori.

Harnesses run inside Yougori Sandbox VMs. Model requests to the configured server are relayed
by the host launcher, which keeps the API key. By default the VM reaches nothing else;
--internet targets also gives it the --targets hosts and ports alone (Yougori's filter on the
host holds its network card to their addresses, a name's as resolved at launch, answers its DNS
for them alone and checks the site each HTTPS and HTTP connection to a named host's addresses
asks for); --internet full gives it the public internet, never this computer or its network
(on a Yougori with that filter).

`run yougori --harness NAME` starts the Yougori harness, which holds NAME, on the Yougori
harness's base image with NAME's pack (without --harness: Yougori's own agent, which needs no
pack): its setup answers come from --answers-file (never secrets) and its secret answers only
from YOUGORI_SECRET_<ID> environment variables.

A security harness reaches only its target and this inference, as `yougori inference run` holds
it: no --sites and no --internet sites or full. Inside the Yougori harness its target is the
target answer (the practice app inside the VM needs only the inference), and --targets may name
only that answer's hosts; started alone, it has no target question and --targets names its target.
"""
import argparse
import contextlib
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


def model_id(value):
    """A model id as the launcher takes one from the website: 1 to 1024 characters, none of them a
    control character (C0, DEL, C1), so it never reaches a terminal or the VM as anything else."""
    return isinstance(value, str) and 1 <= len(value) <= 1024 and not any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value)


def models(server, secret):
    req = urllib.request.Request(server + "/v1/models", headers={"Authorization": "Bearer " + secret})
    opener = transport_opener()
    with opener.open(req, timeout=20) as response:
        raw = response.read(1024 * 1024 + 1)
    if len(raw) > 1024 * 1024:
        raise ValueError("Catalog too large.")
    data = json.loads(raw)["data"]
    if not isinstance(data, list) or len(data) > 1000 or any(not isinstance(m, dict) or not model_id(m.get("id")) for m in data):
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


from vm_host import THIS_COMPUTER, launch, plain, run_session, unavailable
from profiles import NAMES, SECURITY

# What the harness VM may reach. Never nothing: prompts and replies always go to this inference,
# through Yougori's relay, with the API key kept outside the VM.
INTERNET = {"inference": "only this inference", "sites": "this inference and the chosen sites",
            "targets": "this inference and the chosen targets",
            "full": "this inference and the whole internet"}

# The Yougori harness: Yougori's own terminal agent, which also holds every other harness.
YOUGORI = "yougori"
SECRET = "YOUGORI_SECRET_"
ANSWER_ID = re.compile(r"[a-z][a-z0-9_]{0,31}")
ANSWERS_BYTES = 64 * 1024
# The answers file `yougori inference run` writes into its stage folder, beside this launcher.
ANSWERS_FILE = "answers.json"
LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
DIGITS = re.compile(r"[0-9]+")
TROUBLE = ("Could not start. Check the selected harness, Yougori, service URL, sign-in, and available models. "
           "No fallback was launched.")


def vm_size(cpu, memory):
    """The VM's virtual CPUs and host memory in GB, as chosen; None keeps the harness's default."""
    if cpu is not None and not 1 <= cpu <= 255:
        raise ValueError("Choose 1 to 255 CPUs for the harness VM.")
    if memory is not None and not 1 <= memory <= 1024:
        raise ValueError("Choose 1 to 1024 GB of memory for the harness VM.")
    return cpu, memory


def site_list(internet, value):
    """The chosen sites for --internet sites (or beside the targets of --internet targets),
    checked; None otherwise."""
    if internet not in ("sites", "targets"):
        if value:
            raise ValueError("--sites needs --internet sites or targets.")
        return None
    if not value:
        if internet == "sites":
            raise ValueError("Add --sites with the sites the harness may reach, such as github.com,pypi.org.")
        return None
    import vm_tunnel
    return vm_tunnel.sites(value.split(","))


def url_target(text):
    """What the VM must reach for a web address: its host and port (by its scheme when it names
    none), as `yougori inference run` takes an address to test."""
    try:
        address = urlsplit(text)
        given = address.port
    except ValueError:
        raise ValueError(text + " is not a web address such as https://staging.example.com.") from None
    scheme = address.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(text + " is not an http or https address.")
    if address.username is not None or address.password is not None:
        raise ValueError("Give the login in its own question, not in the address.")
    if not address.hostname or "[" in address.netloc:
        raise ValueError(text + " needs a host name or an IPv4 address (IPv6 addresses are not taken).")
    return target_host(address.hostname + ":" + str(given if given is not None else 443 if scheme == "https" else 80))


def target_host(entry):
    """One target as `host:port`, or a host alone for each of its ports: a DNS name (one label only
    with a port) or an IPv4 address, never this VM itself or a link-local, multicast or broadcast
    address, and never a path or an address range. A web address is taken as its host and port.
    Mirrors `yougori inference run`'s check and Yougori's own."""
    text = entry.strip().lower()
    if "://" in text:
        return url_target(entry.strip())
    if "/" in text:
        raise ValueError(entry.strip() + " is not a host such as staging.example.com:443: name the host and its port alone, "
                         "without a path or an address range.")
    host, port = text, None
    if text.count(":") == 1:
        host, port = text.split(":")
        if not DIGITS.fullmatch(port) or len(port) > 5 or not 1 <= int(port) <= 65535 or port.startswith("0"):
            raise ValueError(entry.strip() + " has no valid port (1 to 65535).")
    elif ":" in text:
        raise ValueError(entry.strip() + " is not a host such as staging.example.com:443 (IPv6 addresses are not taken).")
    octets = host.split(".")
    if len(octets) == 4 and all(DIGITS.fullmatch(part) for part in octets):
        if any(len(part) > 3 or int(part) > 255 or (len(part) > 1 and part.startswith("0")) for part in octets):
            raise ValueError(entry.strip() + " is not an IPv4 address.")
        first, second = int(octets[0]), int(octets[1])
        if first == 127:
            raise ValueError(entry.strip() + " is this computer. " + THIS_COMPUTER)
        if first == 0 or first >= 224 or (first, second) == (169, 254):
            raise ValueError(entry.strip() + " is not an address of a computer to test.")
    else:
        labels = host.removesuffix(".").split(".")
        if labels[-1] == "localhost":
            raise ValueError(entry.strip() + " is this computer. " + THIS_COMPUTER)
        if (not 1 <= len(host) <= 253 or not all(LABEL.fullmatch(label) for label in labels)
                or (len(labels) == 1 and port is None) or labels[-1] == "localhost" or DIGITS.fullmatch(labels[-1])):
            raise ValueError(entry.strip() + " is not a host such as staging.example.com or staging.example.com:443.")
        host = ".".join(labels)
    return host + (":" + port if port else "")


def target_list(internet, value):
    """The targets for --internet targets, checked; None for the other choices."""
    if internet != "targets":
        if value:
            raise ValueError("--targets needs --internet targets.")
        return None
    targets = []
    for entry in (value or "").split(","):
        if entry.strip() and (host := target_host(entry)) not in targets:
            targets.append(host)
    if not 1 <= len(targets) <= 64:
        raise ValueError("Add --targets with 1 to 64 hosts the harness may reach, such as staging.example.com:443.")
    return targets


def security_reach(name):
    """What a security harness is told when an option would let its VM reach more than its target:
    the words of `yougori inference run` (cli/src/inference.rs, security_reach)."""
    return (NAMES[name] + " reaches only its target and this inference: it takes no --sites, no --targets and no "
            "--internet sites or full. The target question names what it tests.")


def answer_targets(answers):
    """The hosts the VM must reach for the target answer, each once, as `yougori inference run`
    names them in --targets (cli/src/inference.rs, reach_targets): none for the practice app inside
    the VM (profiles.py starts it there) or without a target answer."""
    value = answers.get("target")
    if value is None or value == "practice" or answers.get("practice") is True:
        return []
    if not isinstance(value, (str, list)):
        raise ValueError("The answers file has an invalid answer target.")
    hosts = []
    for entry in value.split(",") if isinstance(value, str) else value:
        if entry.strip() and (host := target_host(entry)) not in hosts:
            hosts.append(host)
    if len(hosts) > 64:
        raise ValueError("The target answer names more than 64 hosts; the VM reaches at most 64.")
    return hosts


def held_to_target(name, internet, sites, targets, answers):
    """The reach of security harness `name`, held to its target as `yougori inference run` holds
    it (cli/src/inference.rs, resolve_reach): never chosen sites or the whole internet. With
    `answers` (inside the Yougori harness) the target answer decides: only the inference for the
    practice app, the target's hosts for addresses, and --targets may name only those. Without
    (started alone, with no target question) --targets names the target. `internet` is None when
    not given. Returns the --internet choice and the targets."""
    title = NAMES[name]
    if answers is None:
        if sites is not None or internet in ("sites", "full"):
            raise ValueError(title + " reaches only its target and this inference: it takes no --sites and no --internet "
                             "sites or full. Name its target with --internet targets --targets HOST:PORT.")
        internet = internet or "inference"
        return internet, target_list(internet, targets)
    if sites is not None or internet in ("sites", "full"):
        raise ValueError(security_reach(name))
    hosts = answer_targets(answers)
    if internet == "targets" and not hosts:
        raise ValueError("--internet targets needs a target outside the VM: answer the target question with an address.")
    if internet == "inference" and hosts:
        raise ValueError("--internet inference leaves " + title + "'s target out of reach: leave it out, and " + title +
                         " reaches the target and this inference.")
    if targets:
        given = target_list("targets", targets)
        outside = [host for host in given if host not in hosts]
        if outside:
            raise ValueError(title + " reaches only its target and this inference: " + outside[0] + " is not its target. "
                             "The target question names what it tests.")
        return "targets", given
    return ("targets", hosts) if hosts else ("inference", None)


def reach_options(name, holder, args, answers):
    """What the VM reaches besides the inference, from --internet, --sites and --targets (and, for a
    security harness inside the Yougori harness, its target answer): the --internet choice, the
    sites and the targets, checked."""
    if name in SECURITY:
        internet, targets = held_to_target(name, args.internet, args.sites, args.targets,
                                           (answers or {}) if holder else None)
        return internet, None, targets
    internet = args.internet or "inference"
    return internet, site_list(internet, args.sites), target_list(internet, args.targets)


def answer_file(path):
    """The Yougori harness's setup answers, as `yougori inference run` wrote them: answer ids to
    text, yes or no, or lists of text. Never secrets: those come only from the environment."""
    if path is None:
        return {}
    try:
        with path.open("rb") as stream:
            raw = stream.read(ANSWERS_BYTES + 1)
        answers = json.loads(raw)
    except (OSError, ValueError):
        raise ValueError("Cannot read the answers file " + str(path) + ".") from None
    if len(raw) > ANSWERS_BYTES or not isinstance(answers, dict) or len(answers) > 64:
        raise ValueError("The answers file must hold one JSON object of at most 64 answers.")

    def text(item):
        return isinstance(item, str) and len(item) <= 8000 and "\0" not in item
    for key, value in answers.items():
        if not ANSWER_ID.fullmatch(key) or not (isinstance(value, bool) or text(value) or (
                isinstance(value, list) and len(value) <= 64 and all(text(item) for item in value))):
            raise ValueError("The answers file has an invalid answer " + key[:40] + ".")
    # The copy `yougori inference run` wrote for this launch, beside this launcher in its stage
    # folder, is read once: it goes now rather than when the command ends. A file of the
    # person's own, anywhere else, stays.
    if path.name == ANSWERS_FILE and path.resolve().parent == HERE:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass  # `yougori inference run` removes it when the command ends.
    return answers


def take_secrets(environment):
    """Takes the YOUGORI_SECRET_<ID> variables out of `environment`, so no program this launcher
    starts (yougori, whoami, icacls) inherits a secret answer."""
    return {name: environment.pop(name) for name in [name for name in environment if name.upper().startswith(SECRET)]}


def secret_answers(variables):
    """The secret setup answers of the YOUGORI_SECRET_<ID> variables, by answer id. Names are
    checked; values are never shown."""
    found = {}
    for name, value in variables.items():
        answer = name[len(SECRET):].lower()
        if (not ANSWER_ID.fullmatch(answer) or not value or len(value) > 4096
                or any(character in value for character in "\0\r\n")):
            raise ValueError("The secret answer " + name[:60] + " is not valid: give 1 to 4096 characters on one line.")
        found[answer] = value
    return found


def signed_in(args, server, name, key_file):
    """This person's key for the server and the models it reaches: the saved key, or a new one
    from the website's device sign-in when there is none (or it was revoked), or one read from
    stdin with --key-stdin."""
    if args.key_stdin:
        key = sys.stdin.readline(1026).strip()
        if not re.fullmatch(r"[!-~]{1,1024}", key):
            raise ValueError("Invalid API key.")
        catalog = models(server, key)  # Validate before saving; never use provider credentials.
        device_login.save(key_file, key)
        return catalog
    key = (device_login.login(server, name, key_file, False)
           if args.action == "login" or not key_file.exists() else key_file.read_text().strip())
    try:
        return models(server, key)
    except urllib.error.HTTPError as error:
        if error.code != 401:
            raise
        key = device_login.login(server, name, key_file, False)
        return models(server, key)


def model_json(args, server, name):
    """`models --json`, for `yougori inference run`: checks that the harness can start here inside
    the Yougori harness, as that command starts every harness, signs in when needed and prints one
    JSON object, the model ids or the error. The sign-in's words go to stderr, so stdout holds
    only that object."""
    output = sys.stdout
    try:
        with contextlib.redirect_stdout(sys.stderr):
            root = profile(server) / name
            private_folder(root)
            from vm_host import preflight
            preflight(name, server, held=True)
            catalog = signed_in(args, server, name, root / "api-key")
        reply, code = {"models": [entry["id"] for entry in catalog]}, 0
    except KeyboardInterrupt:
        return 130
    except ValueError as error:
        reply, code = {"error": str(error)}, 1
    except (KeyError, OSError, subprocess.CalledProcessError, http.client.HTTPException):
        reply, code = {"error": TROUBLE}, 1
    print(json.dumps(reply), file=output, flush=True)
    return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["list", "install", "models", "run", "login", "check"])
    parser.add_argument("harness", nargs="?", choices=sorted(set(PACKAGES) | {YOUGORI}))
    parser.add_argument("--harness", dest="held", choices=sorted(PACKAGES), metavar="NAME",
                        help="With yougori: the harness Yougori holds (default: Yougori's own agent)")
    parser.add_argument("--server", help="Inference Solver website URL; defaults to the downloaded connection.json")
    parser.add_argument("--model", help="Exact model ID from this server")
    parser.add_argument("--workspace", type=Path, help="Stage a copy of this project; review and promote changes through Yougori")
    parser.add_argument("--cpu", type=int, help="Virtual CPUs for the harness VM (default 2)")
    parser.add_argument("--memory", type=int, help="Host memory for the harness VM in GB (default 4; Shannon 6)")
    parser.add_argument("--internet", choices=sorted(INTERNET),
                        help="inference: only this inference (the default; a security harness: its target and this "
                        "inference); sites: also the --sites; targets: also the --targets; full: the whole internet as well")
    parser.add_argument("--sites", help="With --internet sites (or targets): comma-separated sites such as github.com,pypi.org "
                        "(each covers its subdomains; reached over HTTPS through Yougori's relay)")
    parser.add_argument("--targets", help="With --internet targets: comma-separated hosts such as staging.example.com:443 "
                        "(a host without a port: each of its ports; a web address: its host and port)")
    parser.add_argument("--answers-file", type=Path, help="With run yougori: the setup answers as a JSON object "
                        "(never secrets: those come only from YOUGORI_SECRET_<ID> environment variables)")
    parser.add_argument("--json", action="store_true", help="With models: sign in if needed, then print the models as JSON")
    parser.add_argument("--key-stdin", action="store_true", help="Read the service key from protected stdin instead of prompting")
    parser.add_argument("--no-tty", action="store_true", help="Headless invocation")
    parser.add_argument("--no-browser", action="store_true", help="Print the sign-in address without opening a browser")
    args, extra = parser.parse_known_args()
    # Secret answers live only in this process's memory from here on.
    variables = take_secrets(os.environ)
    if args.action == "list":
        for name, spec in PACKAGES.items():
            print(name + ": " + (spec.get("blocked") or "isolated CLI profile; " + spec["version"]))
        return 0
    if args.action in ("run", "install", "check") and not args.harness:
        parser.error("Choose a harness.")
    holder = args.harness == YOUGORI
    if not holder and (args.held or args.answers_file):
        parser.error("--harness and --answers-file go with yougori.")
    # The Yougori harness passes nothing on to the harness it holds: a stray option would only be
    # dropped, so it is refused.
    if holder and (extra[1:] if extra[:1] == ["--"] else extra):
        raise ValueError("yougori takes no tool arguments or other options: " + plain(" ".join(extra), 200))
    # The Yougori harness starts on its own base image with the pack of the harness it holds,
    # signed in with that harness's key.
    if holder and (args.held or YOUGORI) not in PACKAGES:
        raise ValueError("This launcher cannot start Yougori's own agent yet. Choose a harness with --harness NAME.")
    if args.action in ("run", "install", "check"):
        supported((args.held or YOUGORI) if holder else args.harness)
    cpu, memory = vm_size(args.cpu, args.memory)
    if args.json and args.action != "models":
        parser.error("--json goes with models.")
    bundled = json.loads((HERE / "connection.json").read_text()) if (HERE / "connection.json").exists() else {}
    server = url(args.server or bundled.get("server", ""))
    name = (args.held or YOUGORI) if holder else (args.harness or bundled.get("harness"))
    if name not in PACKAGES:
        raise ValueError("Choose the harness you want to connect.")
    supported(name)
    answers = answer_file(args.answers_file) if holder and args.action == "run" else None
    # Checked before anything is signed in or started: a security harness reaches only its target.
    internet, chosen_sites, chosen_targets = reach_options(name, holder, args, answers)
    if args.json:
        return model_json(args, server, name)
    secrets = secret_answers(variables) if holder and args.action == "run" else None
    root = profile(server) / name
    private_folder(root)
    # The Yougori harness's images (its bases and every harness's pack), kept once for every
    # harness it holds.
    images = profile(server) / YOUGORI if holder else None
    if images is not None and images != root:
        private_folder(images)
    if args.action in ('run', 'install', 'check'):
        from vm_host import preflight
        # Check runtime/image availability before asking for sign-in or downloading anything:
        # inside the Yougori harness, or from the harness's own image.
        preflight(name, server, held=holder)
        if args.action == 'check':
            return 0  # Yougori asks its questions only once this harness can start.
    if args.action == "install":
        if holder:
            from vm_host import install_yougori
            install_yougori(name, server, images)
        else:
            from vm_host import install
            install(name, server, root)
        return 0
    key_file = root / "api-key"
    catalog = signed_in(args, server, name, key_file)
    if args.action == "login":
        return 0
    # The numbered list is for choosing; `yougori inference run` names the model it chose.
    if args.action == "models" or not (holder and args.model):
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
        raise ValueError(unavailable(model))
    workspace = args.workspace.resolve(strict=True) if args.workspace else None
    if workspace and (not workspace.is_dir() or workspace == Path(workspace.anchor) or "," in str(workspace)):
        raise ValueError("Choose a project folder, not a drive root.")
    if name == "swe" and workspace and not (workspace / ".git").is_dir():
        raise ValueError("SWE-agent needs a Git repository with its .git directory in the selected workspace.")
    if name == "swe" and not holder:
        if not any(argument.startswith("--problem_statement.") for argument in extra):
            if not sys.stdin.isatty():
                raise ValueError("Pass --problem_statement.text followed by the task for SWE-agent.")
            task = input("What should SWE-agent work on? ").strip()
            if not task:
                raise ValueError("Enter a task for SWE-agent.")
            extra += ["--problem_statement.text", task]
    extra = extra[1:] if extra[:1] == ["--"] else extra
    if name == "shannon" and not extra and not holder:
        if args.no_tty:
            raise ValueError('Headless Shannon needs -- --validate-model or -- --target URL. Omit --no-tty to open its command prompt.')
        print("Opening Shannon's command prompt. Type help for commands; exit closes the VM.", flush=True)
    chosen = (chosen_targets or []) + (chosen_sites or [])
    reaches = INTERNET[internet] + (": " + ", ".join(chosen) if chosen else "")
    print("Inference Solver | " + ("Yougori with " + name if holder else name) + " | " + server + " | reaches " + reaches, flush=True)
    # The live catalog is read again once the images are ready, just before the VM starts.
    if not holder:
        return launch(args.harness, server, key_file, model, workspace, extra, not args.no_tty,
                      cpu=cpu, memory=memory, internet=internet == "full", sites=chosen_sites, targets=chosen_targets,
                      catalog=models)
    # Inside the Yougori harness the screen switches harness (/harness): in this VM, or in a new one
    # this run starts, among the harnesses this launcher knows.
    return run_session(name, server, key_file, model, workspace, not args.no_tty, cpu=cpu, memory=memory,
                       internet=internet == "full", sites=chosen_sites, targets=chosen_targets,
                       answers=answers, secrets=secrets, images=images, catalog=models, known=set(PACKAGES))


def run():
    """The launcher's exit: main's code, or the reason it could not start, which is printed; 130
    after a Ctrl+C, as a terminal reports it, with no traceback. With YOUGORI_LAUNCHER_TRACE naming
    a file, an unexpected failure's traceback (code lines only, never a value) is written there."""
    try:
        return main()
    except KeyboardInterrupt:
        return 130
    except ValueError as error:
        return str(error)
    except (KeyError, OSError, subprocess.CalledProcessError, http.client.HTTPException):
        trace = os.environ.get("YOUGORI_LAUNCHER_TRACE")
        if trace:
            import traceback
            try:
                Path(trace).write_text("".join(traceback.format_exc(limit=30)), encoding="utf-8")
            except OSError:
                pass
        return TROUBLE


if __name__ == "__main__":
    sys.exit(run())
