"""Run unchanged NVIDIA unit fixtures in an isolated no-driver mount namespace."""
import argparse
import json
import os
from pathlib import Path
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--parent-namespace", required=True)
    parser.add_argument("--record", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    namespace = os.readlink("/proc/self/ns/mnt")
    if os.geteuid() != 0 or namespace == args.parent_namespace or not args.command:
        raise RuntimeError("Root in a newly isolated mount namespace is required")
    subprocess.run(["mount", "--make-rprivate", "/"], check=True)
    hidden = []
    for directory in ("/usr/lib/wsl/lib", "/usr/lib/wsl/drivers"):
        if Path(directory).is_dir():
            subprocess.run(["mount", "-t", "tmpfs", "-o", "ro,nosuid,nodev,noexec", "tmpfs", directory], check=True)
            hidden.append(directory)
    args.record.write_text(json.dumps({"purpose": "Upstream fixtures require no installed host NVIDIA driver; no tests skipped or source expectations changed", "mountNamespaceBefore": args.parent_namespace, "mountNamespaceDuring": namespace, "hiddenOnlyInChildNamespace": hidden}, indent=2) + "\n")
    result = subprocess.run(args.command)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
