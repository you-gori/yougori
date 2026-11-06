"""Start one website-hosted production instance: a plain process on the Yougori website's server.

The website's own server starts one of these per created inference, proxies the inference's
address (https://NAME.yougori.com) to its loopback port and restarts it if it stops. The process
gets the instance folder, no engine, no provider credential and no website secret. Compute comes
from computers the administrator connects with `yougori inference connect URL`.
"""
import argparse
import os
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hosted import build, load, serve

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
AUTHORITY = re.compile(rf"{LABEL}(?:\.{LABEL})+(?::[0-9]{{1,5}})?")


def create(folder, authority, scheme):
    if scheme not in ("http", "https") or not AUTHORITY.fullmatch(authority):
        raise ValueError("Invalid hosted instance.")
    # Over https the cookies are Secure and browser requests must come from the https origin;
    # the website's proxy passes the real client address for the sign-in limits.
    return build(folder, load(folder), {"authority": authority, "runtime_folder": None, "proxied": True},
                 public=scheme == "https")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("folder", help="The instance folder with provision.json; data goes in its data/ subfolder.")
    parser.add_argument("--authority", required=True, help="The address browsers use, for example acme.yougori.com.")
    parser.add_argument("--scheme", choices=("http", "https"), default="https")
    parser.add_argument("--port", type=int, required=True, help="The loopback port the website's proxy connects to.")
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        raise SystemExit("Choose a loopback port between 1024 and 65535.")
    os.environ["SOLVER_COMPUTE"] = "0"
    serve(create(args.folder, args.authority, args.scheme), args.port)


if __name__ == "__main__":
    main()
