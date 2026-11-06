"""Local experimental HCS GPU-PV probe. Default is a read-only access check.

--run explicitly creates two temporary VMs, sequentially: GPU denied and GPU
enabled. It needs an administrator-approved launch. It installs no service,
changes no Windows features, and never opens or stops an existing compute system.
"""
import argparse
import ctypes as C
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import sys
import time
import uuid

SERVICE = "0000bfff-facb-11e6-bd58-64006a7986d3"
OWNER = "yougori-disposable-gpu-probe"


def verify_bundle(directory):
    manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("version") != 1 or manifest.get("localOnly") is not True or set(manifest.get("files", {})) != {"kernel", "initrd"}:
        raise ValueError("not a local GPU probe bundle")
    for name, expected in manifest["files"].items():
        path = directory / name
        if not path.is_file() or path.is_symlink():
            raise ValueError(f"missing or redirected bundle file: {name}")
        with path.open("rb") as f:
            if hashlib.file_digest(f, "sha256").hexdigest() != expected:
                raise ValueError(f"bundle checksum mismatch: {name}")
    return manifest


def configuration(directory):
    # Empty default ACLs; one result channel limited to SYSTEM/Administrators.
    # In particular, no physical disk, host share, NIC or management guest service.
    # HvSocket uses file access rights, as in Microsoft's WSL configuration.
    # Grant those rights only to SYSTEM and elevated Administrators on this one
    # service; keep the default ACLs empty and wildcard binding disabled.
    access = "D:P(A;;FA;;;SY)(A;;FA;;;BA)"
    return {
        "SchemaVersion": {"Major": 2, "Minor": 2},
        "Owner": OWNER,
        "ShouldTerminateOnLastHandleClosed": True,
        "VirtualMachine": {
            "StopOnReset": True,
            "Chipset": {"LinuxKernelDirect": {
                "KernelFilePath": str(directory / "kernel"),
                "InitRdPath": str(directory / "initrd"),
                "KernelCmdLine": "init=/init rdinit=/init panic=-1 quiet",
            }},
            "ComputeTopology": {
                "Memory": {"SizeInMB": 4096, "AllowOvercommit": True},
                "Processor": {"Count": 2, "ExposeVirtualizationExtensions": False},
            },
            "Devices": {"HvSocket": {"HvSocketConfig": {
                "DefaultBindSecurityDescriptor": "D:P",
                "DefaultConnectSecurityDescriptor": "D:P",
                "ServiceTable": {SERVICE: {"BindSecurityDescriptor": access, "ConnectSecurityDescriptor": access, "AllowWildcardBinds": False}},
            }}},
        },
    }


class Hcs:
    def __init__(self):
        if os.name != "nt":
            raise RuntimeError("HCS is Windows-only")
        # Absolute system paths prevent DLL lookup from the checkout/output folder.
        system = Path(os.environ["SystemRoot"]) / "System32"
        self.dll = C.WinDLL(str(system / "computecore.dll"))
        self.kernel = C.WinDLL(str(system / "kernel32.dll"))
        self.kernel.LocalFree.argtypes = [C.c_void_p]
        self.kernel.LocalFree.restype = C.c_void_p
        P, W, I = C.c_void_p, C.c_wchar_p, C.c_int32
        self.bind("HcsGetServiceProperties", [W, C.POINTER(P)], I)
        self.bind("HcsCreateOperation", [P, P], P)
        self.bind("HcsCloseOperation", [P], None)
        self.bind("HcsWaitForOperationResult", [P, C.c_uint32, C.POINTER(P)], I)
        self.bind("HcsCreateComputeSystem", [W, W, P, P, C.POINTER(P)], I)
        self.bind("HcsStartComputeSystem", [P, P, W], I)
        self.bind("HcsTerminateComputeSystem", [P, P, W], I)
        self.bind("HcsCloseComputeSystem", [P], None)
        self.bind("HcsGetComputeSystemProperties", [P, P, W], I)
        self.bind("HcsModifyComputeSystem", [P, P, W, P], I)
        self.bind("HcsEnumerateComputeSystems", [W, P], I)

    def bind(self, name, args, result):
        method = getattr(self.dll, name)
        method.argtypes, method.restype = args, result

    def document(self, pointer):
        try:
            return C.wstring_at(pointer) if pointer.value else ""
        finally:
            if pointer.value:
                self.kernel.LocalFree(pointer)

    @staticmethod
    def check(code, name, detail=""):
        if code < 0:
            raise RuntimeError(f"{name}: 0x{code & 0xffffffff:08X} {detail[:1500]}")

    def access(self):
        pointer = C.c_void_p()
        code = self.dll.HcsGetServiceProperties('{"PropertyTypes":["Basic"]}', C.byref(pointer))
        detail = self.document(pointer)
        self.check(code, "HCS access", detail)
        return json.loads(detail)

    def operation(self, name, start):
        op = self.dll.HcsCreateOperation(None, None)
        if not op:
            raise RuntimeError("cannot allocate HCS operation")
        try:
            self.check(start(op), name)
            pointer = C.c_void_p()
            code = self.dll.HcsWaitForOperationResult(op, 30000, C.byref(pointer))
            detail = self.document(pointer)
            self.check(code, name, detail)
            return json.loads(detail) if detail else {}
        finally:
            self.dll.HcsCloseOperation(op)

    def owned(self):
        return self.operation("enumerate probe VMs", lambda op: self.dll.HcsEnumerateComputeSystems(json.dumps({"Owners": [OWNER]}), op))


def one_vm(hcs, directory, gpu, record):
    identity = str(uuid.uuid4())
    handle = C.c_void_p()
    config = configuration(directory)
    record.update({"id": identity, "gpuRequested": gpu, "configuration": config})
    listener = None
    try:
        record["stage"] = "create"
        hcs.operation("create VM", lambda op: hcs.dll.HcsCreateComputeSystem(identity, json.dumps(config), op, None, C.byref(handle)))
        record["stage"] = "identity"
        properties = hcs.operation("VM identity", lambda op: hcs.dll.HcsGetComputeSystemProperties(handle, op, "{}"))
        if properties.get("SystemType") != "VirtualMachine" or not properties.get("RuntimeId"):
            raise RuntimeError("HCS did not confirm a separate VM with a runtime identity")
        record["properties"] = properties
        record["stage"] = "open result socket"
        listener = socket.socket(socket.AF_HYPERV, socket.SOCK_STREAM, socket.HV_PROTOCOL_RAW)
        listener.settimeout(75)
        record["stage"] = "bind result socket"
        listener.bind((str(uuid.UUID(properties["RuntimeId"])), SERVICE))
        listener.listen(1)
        record["stage"] = "start"
        hcs.operation("start VM", lambda op: hcs.dll.HcsStartComputeSystem(handle, op, None))
        if gpu:
            # Mirror is Microsoft's WSL GPU-PV configuration. This controlled
            # probe uses only the fixed kernel test; it isn't a tenant GPU policy.
            update = {"ResourcePath": "VirtualMachine/ComputeTopology/Gpu", "RequestType": "Update", "Settings": {"AssignmentMode": "Mirror", "AllowVendorExtension": True}}
            record["stage"] = "attach GPU"
            hcs.operation("attach GPU-PV", lambda op: hcs.dll.HcsModifyComputeSystem(handle, op, json.dumps(update), None))
            record["gpuUpdate"] = update
        record["stage"] = "await guest"
        peer, address = listener.accept()
        with peer:
            if uuid.UUID(address[0]) != uuid.UUID(properties["RuntimeId"]):
                raise RuntimeError("result socket is not from the created VM")
            peer.settimeout(90)
            nonce = secrets.token_hex(32)
            peer.sendall((json.dumps({"nonce": nonce, "gpu": gpu}) + "\n").encode())
            with peer.makefile("rb") as stream:
                line = stream.readline(65537)
            if len(line) > 65536 or not line.endswith(b"\n"):
                raise RuntimeError("guest report missing or oversized")
            guest = json.loads(line)
        if guest.pop("nonce", None) != nonce:
            raise RuntimeError("wrong guest probe challenge")
        record["guest"] = guest
        if set(guest.get("networkInterfaces", [])) - {"lo"}:
            raise RuntimeError("unexpected network interface in the probe VM")
        if any(m in guest.get("mounts", "") for m in [" 9p ", " virtiofs ", " drvfs ", " cifs "]):
            raise RuntimeError("unexpected host filesystem mount")
        if not guest.get("bootId"):
            raise RuntimeError("guest did not report its independent kernel boot")
        if gpu and (not guest.get("dxg") or not guest.get("cudaPassed")):
            raise RuntimeError("CUDA computation failed inside the GPU VM")
        if not gpu and guest.get("cudaPassed"):
            raise RuntimeError("GPU-off VM unexpectedly has GPU access")
        record["passed"] = True
        record["stage"] = "passed"
    finally:
        if listener is not None:
            listener.close()
        if handle.value:
            try:
                hcs.operation("terminate probe VM", lambda op: hcs.dll.HcsTerminateComputeSystem(handle, op, None))
                record["terminateConfirmed"] = True
            except RuntimeError as error:
                record["terminationNote"] = str(error)
            finally:
                hcs.dll.HcsCloseComputeSystem(handle)
        # Never sweep other systems. Last-handle-close is enabled for this VM.
        for attempt in range(20):
            remaining = hcs.owned()
            record["absentAfterClose"] = not any(v.get("Id") == identity for v in remaining)
            if record["absentAfterClose"]:
                break
            time.sleep(0.25)
        if not record["absentAfterClose"]:
            raise RuntimeError(f"probe VM still present: {identity}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    report = {"experimental": True, "productionEnabled": False, "runs": []}
    code = 1
    try:
        if args.bundle:
            args.bundle = args.bundle.resolve()
            report["bundle"] = verify_bundle(args.bundle)
            report["proposedConfiguration"] = configuration(args.bundle)
        hcs = Hcs()
        report["service"] = hcs.access()
        if args.run:
            if args.bundle is None:
                raise ValueError("--run requires --bundle")
            for gpu in [False, True]:
                record = {}
                report["runs"].append(record)
                one_vm(hcs, args.bundle, gpu, record)
            if report["runs"][0]["guest"]["bootId"] == report["runs"][1]["guest"]["bootId"]:
                raise RuntimeError("the two probes reported the same kernel boot")
            report["gpuValidated"] = True
        code = 0
    except Exception as error:
        report["error"] = str(error)
    finally:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(args.output), "gpuValidated": report.get("gpuValidated", False), "error": report.get("error")}))
    return code


if __name__ == "__main__":
    sys.exit(main())
