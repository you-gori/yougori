"""Exercise the bundled software TPM using only new disposable state files.

Windows only. No host TPM, existing VM or user disk is used. The QEMU cleanup
test uses a temporary loopback-only QMP port; the TPM uses anonymous pipes.
"""
import ctypes
from ctypes import wintypes as W
import json
import os
from pathlib import Path
import queue
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
RUNTIME = Path(os.environ.get("YOUGORI_TEST_SECURE_RUNTIME", ROOT / "src-tauri/resources/runtime/qemu-secure"))
MAGIC = 0x5954504D
STARTUP = "80010000000c000001440000"
NV_READ = "8002000000230000014e40000001015000200000000940000009000000000000100000"
NV_VALUE = bytes.fromhex("00112233445566778899aabbccddeeff")


def hidden(command, **kwargs):
    return subprocess.Popen(command, creationflags=subprocess.CREATE_NO_WINDOW,
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, **kwargs)


class Worker:
    def __init__(self):
        self.process = hidden([str(RUNTIME / "yougori-tpm-worker.exe")])
        self.responses = queue.Queue()
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()

    def read(self):
        try:
            while header := self.process.stdout.read(16):
                if len(header) != 16:
                    raise ValueError("Truncated worker response")
                magic, status, length, abi = struct.unpack("<IiII", header)
                if magic != MAGIC or abi != 1 or length > 4096:
                    raise ValueError("Invalid worker response")
                payload = self.process.stdout.read(length)
                if len(payload) != length:
                    raise ValueError("Truncated TPM response")
                self.responses.put((status, payload))
        except Exception as error:
            self.responses.put(error)

    def call(self, operation, argument=0, data=b""):
        self.process.stdin.write(struct.pack("<IIII", MAGIC, operation, argument, len(data)) + data)
        self.process.stdin.flush()
        response = self.responses.get(timeout=15)
        if isinstance(response, Exception):
            raise response
        return response

    def command(self, hex_bytes):
        status, data = self.call(3, data=bytes.fromhex(hex_bytes))
        if status or len(data) < 10 or data[6:10] != bytes(4):
            raise AssertionError(f"TPM command failed: status={status}, response={data.hex()}")
        return data

    def stop(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


@unittest.skipUnless(os.name == "nt", "Windows runtime")
class TpmWorkerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="yougori-tpm-worker-test-")
        self.addCleanup(self.temporary.cleanup)
        self.state = Path(self.temporary.name) / "test identity.nv"

    def worker(self):
        worker = Worker()
        self.addCleanup(worker.stop)
        return worker

    def test_crypto_nv_persistence_and_identity_protection(self):
        worker = self.worker()
        path = str(self.state).encode()
        self.assertNotEqual(worker.call(1, data=path)[0], 0, "missing identity must not be manufactured")
        self.assertEqual(worker.call(1, 1, path), (0, b""))
        self.assertEqual(worker.call(2), (0, b""))
        worker.command(STARTUP)
        worker.command("80010000000b0000014301")  # Full crypto self-test.
        random = worker.command("80010000000c0000017b0020")
        self.assertEqual(len(random), 44)
        self.assertNotEqual(random[12:], worker.command("80010000000c0000017b0020")[12:])
        competitor = self.worker()
        self.assertNotEqual(competitor.call(1, data=path)[0], 0, "live identity must remain exclusively locked")
        worker.command("80020000002d0000012a40000001000000094000000900000000000000000e01500020000b0202000200000010")
        worker.command("80020000003300000137400000010150002000000009400000090000000000001000112233445566778899aabbccddeeff0000")
        worker.command("80010000000c000001450000")
        self.assertEqual(worker.call(4), (0, b""))
        self.assertEqual(worker.process.wait(timeout=5), 0)
        reopened = self.worker()
        self.assertNotEqual(reopened.call(1, 1, path)[0], 0, "existing identity must never be replaced")
        self.assertEqual(reopened.call(1, data=path), (0, b""))
        self.assertEqual(reopened.call(2), (0, b""))
        reopened.command(STARTUP)
        self.assertEqual(reopened.command(NV_READ)[16:32], NV_VALUE)
        # EOF also closes the state cleanly, allowing a later worker to reopen it.
        reopened.process.stdin.close()
        self.assertEqual(reopened.process.wait(timeout=5), 0)
        self.assertEqual(competitor.call(1, data=path), (0, b""))

    def test_invalid_commands_do_not_break_the_live_tpm(self):
        worker = self.worker()
        self.assertEqual(worker.call(1, 1, str(self.state).encode())[0], 0)
        self.assertEqual(worker.call(2)[0], 0)
        worker.command(STARTUP)
        self.assertNotEqual(worker.call(3, 5, bytes.fromhex(STARTUP))[0], 0)
        self.assertNotEqual(worker.call(3, data=bytes.fromhex("8001ffffffff0000017b"))[0], 0)
        self.assertEqual(len(worker.command("80010000000c0000017b0020")), 44)

    def test_oversized_or_unknown_frames_exit_without_opening_state(self):
        for header in ((MAGIC, 1, 1, 32768), (MAGIC, 3, 0, 4097), (MAGIC, 99, 0, 0), (0, 1, 1, 0)):
            with self.subTest(header=header):
                worker = self.worker()
                worker.process.stdin.write(struct.pack("<IIII", *header))
                worker.process.stdin.flush()
                self.assertEqual(worker.process.wait(timeout=5), 2)
        self.assertFalse(self.state.exists())

    def test_qemu_worker_exits_after_both_normal_and_forced_vm_exit(self):
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        class ProcessEntry(ctypes.Structure):
            _fields_ = [("size", W.DWORD), ("usage", W.DWORD), ("pid", W.DWORD),
                        ("heap", ctypes.c_size_t), ("module", W.DWORD), ("threads", W.DWORD),
                        ("parent", W.DWORD), ("priority", W.LONG), ("flags", W.DWORD), ("name", W.WCHAR * 260)]
        kernel.CreateToolhelp32Snapshot.restype = W.HANDLE
        kernel.OpenProcess.restype = W.HANDLE
        kernel.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
        kernel.Process32FirstW.argtypes = [W.HANDLE, ctypes.POINTER(ProcessEntry)]
        kernel.Process32NextW.argtypes = [W.HANDLE, ctypes.POINTER(ProcessEntry)]
        kernel.CloseHandle.argtypes = [W.HANDLE]
        kernel.WaitForSingleObject.argtypes = [W.HANDLE, W.DWORD]

        def worker_handle(parent):
            snapshot = kernel.CreateToolhelp32Snapshot(2, 0)
            entry = ProcessEntry()
            entry.size = ctypes.sizeof(entry)
            try:
                found = kernel.Process32FirstW(snapshot, ctypes.byref(entry))
                while found:
                    if entry.parent == parent and entry.name == "yougori-tpm-worker.exe":
                        return kernel.OpenProcess(0x100000, False, entry.pid)
                    found = kernel.Process32NextW(snapshot, ctypes.byref(entry))
            finally:
                kernel.CloseHandle(snapshot)
            return None

        for forced in (False, True):
            with self.subTest(forced=forced):
                path = Path(self.temporary.name) / f"qemu-{forced}.nv"
                with socket.socket() as reservation:
                    reservation.bind(("127.0.0.1", 0))
                    port = reservation.getsockname()[1]
                process = hidden([str(RUNTIME / "qemu-system-x86_64.exe"), "-machine", "q35,accel=tcg",
                    "-S", "-m", "128", "-nodefaults", "-display", "none", "-monitor", "none",
                    "-bios", str(ROOT / "src-tauri/resources/runtime/qemu/share/bios-256k.bin"),
                    "-qmp", f"tcp:127.0.0.1:{port},server=on,wait=off", "-tpmdev", f"yougori,id=tpm0,state={path},create=on", "-device", "tpm-tis,tpmdev=tpm0"])
                handle = None
                try:
                    deadline = time.monotonic() + 15
                    while not handle and process.poll() is None and time.monotonic() < deadline:
                        handle = worker_handle(process.pid)
                        time.sleep(0.05)
                    self.assertIsNotNone(handle, "QEMU must own one private TPM worker")
                    connection = None
                    while connection is None and time.monotonic() < deadline:
                        try:
                            connection = socket.create_connection(("127.0.0.1", port), timeout=5)
                        except ConnectionRefusedError:
                            time.sleep(0.05)
                    self.assertIsNotNone(connection, "QEMU must reach its monitor")
                    with connection, connection.makefile("rb") as monitor:
                        self.assertIn("QMP", json.loads(monitor.readline()))
                        connection.sendall(b'{"execute":"qmp_capabilities"}\n')
                        self.assertIn("return", json.loads(monitor.readline()))
                        if forced:
                            process.kill()
                        else:
                            connection.sendall(b'{"execute":"quit"}\n')
                            while line := monitor.readline():
                                if "return" in json.loads(line):
                                    break
                    output, errors = process.communicate(timeout=15)
                    if not forced:
                        self.assertEqual(process.returncode, 0, errors.decode(errors="replace"))
                    self.assertEqual(kernel.WaitForSingleObject(handle, 5000), 0, "TPM worker must never outlive its QEMU parent")
                finally:
                    if process.poll() is None:
                        process.kill()
                    process.communicate(timeout=5)
                    if handle:
                        kernel.CloseHandle(handle)


if __name__ == "__main__":
    unittest.main(verbosity=2)
