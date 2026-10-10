#!/usr/bin/env python3
"""Boot one disposable legacy overlay with old then current media at 512 MiB.

Requires Linux QEMU/qemu-img. Keeps logs, the overlay and a JSON report for
inspection. It never changes or rebases the supplied immutable backing image.
"""

import argparse
import base64
import gzip
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import shlex
import socket
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request

ENVIRONMENT = "migration-fixture"
MARKER = "legacy-data-preserved-after-kernel-upgrade"
PROJECT = b"real FUSE share survived the security migration\n"
MICRO_OPTIONS = {"entrypoint": [], "args": ["sleep", "2147483647"]}
VENDOR_FILES = (
    "usr/local/bin/containerd", "usr/local/bin/containerd-shim-runc-v2",
    "usr/local/bin/nerdctl", "usr/local/bin/runc",
    "usr/local/libexec/cni/bridge", "usr/local/libexec/cni/firewall",
    "usr/local/libexec/cni/host-local", "usr/local/libexec/cni/loopback",
    "usr/local/libexec/cni/portmap", "usr/local/libexec/cni/tuning",
)


def trusted_vendor_manifest(initramfs):
    # Read only the small manifest from gzip/newc without unpacking the archive
    # or allocating the complete initramfs on the test host.
    with gzip.open(initramfs, "rb") as source:
        while True:
            header = source.read(110)
            if len(header) != 110 or header[:6] not in (b"070701", b"070702"):
                raise RuntimeError("Unsupported candidate initramfs cpio format")
            size, namesize = int(header[54:62], 16), int(header[94:102], 16)
            if not 0 < namesize <= 4096:
                raise RuntimeError("Invalid candidate initramfs filename")
            name = source.read(namesize).rstrip(b"\x00").decode()
            source.read(-(110 + namesize) % 4)
            if name == "TRAILER!!!":
                raise RuntimeError("Candidate initramfs has no trusted OCI migration manifest")
            if name.removeprefix("./") == "usr/local/lib/yougori-boot/oci-runtime.files":
                if not stat.S_ISREG(int(header[14:22], 16)) or not 0 < size <= 4096:
                    raise RuntimeError("Invalid trusted OCI migration manifest")
                entries = {}
                for line in source.read(size).decode().splitlines():
                    digest, length, path = line.split()
                    if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
                        raise RuntimeError("Invalid trusted OCI file digest")
                    if path in entries or not 0 < int(length) <= 96 * 1024 * 1024:
                        raise RuntimeError("Invalid trusted OCI file size/path")
                    entries[path] = {"sha256": digest, "bytes": int(length)}
                if set(entries) != set(VENDOR_FILES):
                    raise RuntimeError("Trusted OCI manifest does not contain the complete runtime set")
                return entries
            remaining = size
            while remaining:
                chunk = source.read(min(remaining, 1024 * 1024))
                if not chunk:
                    raise RuntimeError("Truncated candidate initramfs")
                remaining -= len(chunk)
            source.read(-size % 4)


def vendor_hashes(vm):
    output = vm.execute("sha256sum " + " ".join("/" + name for name in VENDOR_FILES))
    values = {}
    for line in output.splitlines():
        digest, name = line.split()
        values[name.lstrip("/")] = digest
    assert set(values) == set(VENDOR_FILES), output
    return values


def unused_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class ProjectFiles(BaseHTTPRequestHandler):
    token = ""

    def log_message(self, *_):
        pass

    def reply(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.reply({"localHostService": True})

    def do_POST(self):
        if self.path != "/files" or self.headers.get("Authorization") != "Bearer " + self.token:
            return self.reply({}, 403)
        request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        path = request.get("path", "")
        operation = request.get("operation")
        info = {"name": "project.txt", "size": len(PROJECT), "directory": False, "modified": 1}
        if operation == "stat" and path in ("", "."):
            return self.reply({"info": {"directory": True, "modified": 1}})
        if operation == "stat" and path == "project.txt":
            return self.reply({"info": info})
        if operation == "list" and path in ("", "."):
            return self.reply({"entries": [info]})
        if operation == "read" and path == "project.txt":
            offset, length = request["offset"], min(request["length"], 131072)
            return self.reply({"data": base64.b64encode(PROJECT[offset:offset + length]).decode()})
        self.reply({}, 404)


class VM:
    def __init__(self, args, media, stage):
        self.token = secrets.token_hex(32)
        self.port = unused_port()
        self.serial = args.workdir / (stage + "-serial.log")
        # A repeated candidate phase must not interpret a previous boot's
        # retained panic log before QEMU opens/truncates its serial output.
        self.serial.unlink(missing_ok=True)
        self.log = (args.workdir / (stage + "-qemu.log")).open("wb")
        command = [args.qemu, "-machine", "q35", "-accel", args.accel, "-cpu", "max" if args.accel == "tcg" else "host",
                   "-m", "512", "-smp", "2", "-nodefaults", "-display", "none", "-monitor", "none",
                   "-serial", "file:" + str(self.serial), "-no-reboot", "-kernel", str(media / "vmlinuz-virt"),
                   "-initrd", str(media / "initramfs-virt"), "-append",
                   "root=/dev/vda rw rootfstype=ext4 console=ttyS0 quiet modules=virtio_pci,virtio_blk,virtio_net,ext4 softlevel=microvm opendock.mode=microvm opendock.token=" + self.token,
                   "-drive", "file=" + str(args.workdir / "legacy-overlay.qcow2") + ",if=virtio,format=qcow2",
                   "-netdev", f"user,id=net0,hostfwd=tcp:127.0.0.1:{self.port}-:7443",
                   "-device", "virtio-net-pci,netdev=net0"]
        self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT)

    def request(self, path, body=None, timeout=300):
        data = None if body is None else json.dumps(body).encode()
        request = urllib.request.Request(f"http://127.0.0.1:{self.port}" + path, data=data,
                                         headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            raise RuntimeError(f"{path}: HTTP {error.code}: {error.read().decode()}") from error

    def wait(self):
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"QEMU exited {self.process.returncode}; inspect {self.serial}")
            if self.serial.exists() and "Kernel panic" in self.serial.read_text(errors="replace"):
                raise RuntimeError(f"Guest kernel panic; inspect {self.serial}")
            try:
                if self.request("/v1/health", timeout=2)["status"] == "ready":
                    return
            except (OSError, ValueError, RuntimeError):
                pass
            time.sleep(0.5)
        raise RuntimeError(f"Guest boot timed out; inspect {self.serial}")

    def execute(self, command):
        reply = self.request("/v1/system/exec", {"command": command})
        if reply["exitCode"] != 0:
            raise RuntimeError(f"Guest command failed ({reply['exitCode']}): {command}\n{reply}")
        return reply["stdout"]

    def close(self):
        if self.process.poll() is None:
            try:
                self.request("/v1/system/shutdown", {}, timeout=5)
                self.process.wait(timeout=30)
            except (OSError, RuntimeError, subprocess.TimeoutExpired):
                self.process.terminate()
                try:
                    self.process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait()
        self.log.close()


def mount_project(vm, server):
    vm.request("/v1/workloads/mount", {"id": ENVIRONMENT, "slot": ENVIRONMENT + "-0", "endpoint": f"http://10.0.2.2:{server.server_port}",
                                         "token": ProjectFiles.token, "readOnly": True})
    contents = vm.execute(f"cat /var/lib/opendock/workload-mounts/{ENVIRONMENT}-0/project.txt")
    assert contents == PROJECT.decode(), contents


def start_runtime(vm):
    vm.execute("rc-service containerd start; i=0; while [ ! -S /run/containerd/containerd.sock ]; do i=$((i+1)); [ $i -lt 100 ] || exit 1; sleep 0.1; done")


def legacy_stage(args, server, report):
    overlay = args.workdir / "legacy-overlay.qcow2"
    if overlay.exists():
        raise RuntimeError("Legacy overlay already exists; use a fresh workdir or run only the candidate phase")
    subprocess.run([args.qemu_img, "create", "-f", "qcow2", "-F", "qcow2", "-b", str((args.legacy / "appliance-base.qcow2").resolve()), str(overlay)], check=True)
    vm = VM(args, args.legacy, "legacy")
    try:
        vm.wait()
        report["legacyKernel"] = vm.execute("uname -r").strip()
        report["legacyVendorSHA256"] = vendor_hashes(vm)
        vm.execute(f"mkdir -p /var/lib/opendock/migration-fixture-data; printf '%s' '{MARKER}' > /var/lib/opendock/migration-fixture-data/marker")
        start_runtime(vm)
        mount_project(vm, server)
        vm.request("/v1/microvm/workload", {"image": args.image, "options": MICRO_OPTIONS})
        vm.execute(f"nerdctl --namespace yougori-workload exec app /bin/sh -c \"printf '%s' '{MARKER}' > /legacy-marker\"")
        vm.execute("nerdctl --namespace yougori-workload stop --time 10 app")
        vm.execute("sync")
        report["legacyPrepared"] = True
        print("Legacy kernel/container/real FUSE share prepared", flush=True)
    finally:
        vm.close()


def candidate_stage(args, server, report):
    if not report.get("legacyPrepared"):
        raise RuntimeError("Prepare the same overlay with the legacy phase first")
    vm = VM(args, args.candidate, "candidate")
    try:
        vm.wait()
        kernel = vm.execute("uname -r").strip()
        report["candidateKernel"] = kernel
        assert kernel != report["legacyKernel"], "Fixture must exercise a real kernel/module version upgrade"
        trusted = trusted_vendor_manifest(args.candidate / "initramfs-virt")
        actual = vendor_hashes(vm)
        assert actual == {name: entry["sha256"] for name, entry in trusted.items()}, "Preserved disk retained an old or untrusted OCI executable"
        assert all(actual[name] != report["legacyVendorSHA256"][name] for name in VENDOR_FILES), "Fixture must replace every old OCI/CNI executable"
        for name, entry in trusted.items():
            assert vm.execute(f"stat -c '%s %a' /{name}").strip() == f"{entry['bytes']} 755", name
        report["trustedVendorManifest"] = trusted
        report["candidateVendorSHA256"] = actual
        assert vm.execute("cat /var/lib/opendock/migration-fixture-data/marker") == MARKER
        modules = vm.execute("test -d /lib/modules/$(uname -r); modprobe fuse; modprobe br_netfilter; modprobe nf_conntrack; grep -E '^(fuse|br_netfilter|nf_conntrack) ' /proc/modules")
        report["moduleLoadEvidence"] = modules
        start_runtime(vm)
        mount_project(vm, server)
        vm.request("/v1/microvm/workload", {"image": args.image, "options": MICRO_OPTIONS})
        app_command = "nerdctl --namespace yougori-workload exec app /bin/sh -c "
        assert vm.execute(app_command + "'cat /legacy-marker'") == MARKER
        status = vm.execute(app_command + "'grep -E \"^(NoNewPrivs|Seccomp|CapEff):\" /proc/self/status; cat /sys/fs/cgroup/pids.max'")
        assert "NoNewPrivs:\t1" in status and "Seccomp:\t2" in status and "4096" in status, status
        cap_effective = int(next(line.split()[1] for line in status.splitlines() if line.startswith("CapEff:")), 16)
        assert not cap_effective & (1 << 13), "NET_RAW capability survived migration"
        # Exercise the real managed CNI path too. A dedicated microVM does not
        # use shared-store quotas, so create this disposable network probe with
        # nerdctl and ask the authenticated agent to attach its managed uplink.
        image = shlex.quote(args.image)
        vm.execute(f"nerdctl --namespace opendock pull {image}; nerdctl --namespace opendock create --name {ENVIRONMENT} --network none "
                   f"--cpus 0.5 --memory 128m --pids-limit 4096 --cap-drop ALL --security-opt no-new-privileges=true "
                   f"--security-opt seccomp=builtin --volume /var/lib/opendock/workload-mounts/{ENVIRONMENT}-0:/project:ro "
                   f"--entrypoint /bin/sh {image} -c 'sleep 2147483647'; nerdctl --namespace opendock start {ENVIRONMENT}")
        vm.request("/v1/containers/internet", {"id": ENVIRONMENT, "networkAccess": True})
        command = f"nerdctl --namespace opendock exec {ENVIRONMENT} /bin/sh -c "
        assert vm.execute(command + "'cat /project/project.txt'") == PROJECT.decode()
        vm.execute(command + "'wget -q -T 20 -O /tmp/internet-result http://example.com; test -s /tmp/internet-result'")
        vm.execute(command + f"\"if wget -q -T 2 -O /tmp/private-host http://10.0.2.2:{server.server_port}/; then exit 1; fi\"")
        report.update({"status": "passed", "memoryMiB": 512, "sameOverlay": True, "filesPreserved": True, "fuseRead": True,
                       "internetCNI": True, "privateHostBlocked": True, "securityStatus": status,
                       "vendorExecutablesUpdated": True,
                       "candidateInitramfsBytes": (args.candidate / "initramfs-virt").stat().st_size})
        vm.execute(f"nerdctl --namespace opendock stop --time 10 {ENVIRONMENT}; nerdctl --namespace yougori-workload stop --time 10 app")
        vm.execute("sync")
        print("512 MiB same-overlay kernel upgrade, preserved data, CNI and FUSE passed", flush=True)
    finally:
        vm.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legacy", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--phase", choices=("legacy", "candidate", "both"), default="both")
    parser.add_argument("--image", default="docker.io/library/alpine:3.24")
    parser.add_argument("--qemu", default="qemu-system-x86_64")
    parser.add_argument("--qemu-img", default="qemu-img")
    parser.add_argument("--accel", choices=("kvm", "tcg"), default="tcg")
    args = parser.parse_args()
    args.legacy, args.candidate, args.workdir = args.legacy.resolve(), args.candidate.resolve(), args.workdir.resolve()
    args.workdir.mkdir(parents=True, exist_ok=True)
    report_path = args.workdir / "migration-report.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    report["status"] = "running"
    base = args.legacy / "appliance-base.qcow2"
    before = hashlib.sha256(base.read_bytes()).hexdigest()
    ProjectFiles.token = secrets.token_hex(32)
    server = ThreadingHTTPServer(("127.0.0.1", 0), ProjectFiles)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        if args.phase in ("legacy", "both"):
            legacy_stage(args, server, report)
        if args.phase in ("candidate", "both"):
            candidate_stage(args, server, report)
    except Exception as error:
        report["status"] = "failed"
        report["error"] = str(error)
        raise
    finally:
        server.shutdown()
        server.server_close()
        report["immutableBaseSHA256"] = before
        assert hashlib.sha256(base.read_bytes()).hexdigest() == before, "Immutable legacy backing image was modified"
        report_path.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
