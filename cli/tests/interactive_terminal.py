"""Windows ConPTY acceptance for the real menu, with no workload mutations.

Requires pywinpty. Run: python cli/tests/interactive_terminal.py PATH_TO_YOUGORI
Add --engine to exercise the VM launch questions against a running engine, cancelling
at final review. The default test works offline; nothing is launched or stopped.
"""
import os
import re
import socket
import sys
import time
from winpty import PtyProcess

ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07))")


class Menu:
    def __init__(self, exe):
        env = dict(os.environ, YOUGORI_NO_UPDATE_CHECK="1", TERM="xterm-256color")
        env.pop("YOUGORI_HUB_CONSOLE", None)
        self.proc = PtyProcess.spawn([exe], env=env, dimensions=(40, 130))
        self.proc.fileobj.settimeout(0.2)
        self.buffer = ""
        self.transcript = ""

    def expect(self, text, timeout=20):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if text in ANSI.sub("", self.buffer):
                return
            try:
                chunk = self.proc.read(65536)
                self.buffer += chunk
                self.transcript += chunk
            except socket.timeout:
                pass
            except EOFError:
                break
        raise AssertionError(f"Missing {text!r}; terminal tail: {ANSI.sub('', self.transcript)[-1800:]}")

    def send(self, keys):
        # Let the completed prompt settle before sending the next intentional input.
        time.sleep(0.25)
        self.buffer = ""
        self.proc.write(keys)

    def down(self, count):
        self.send("\x1b[B" * count + "\r")

    def finish(self):
        self.expect("Menu closed. Your workloads keep running.")
        deadline = time.monotonic() + 10
        while self.proc.isalive() and time.monotonic() < deadline:
            time.sleep(0.1)
        assert not self.proc.isalive(), "Menu did not exit"
        assert self.proc.exitstatus == 0, self.proc.exitstatus

    def close(self):
        if self.proc.isalive():
            self.proc.terminate(force=True)


def exercise(exe, engine):
    menu = Menu(exe)
    try:
        menu.expect("Leave workloads running")
        menu.down(3)
        menu.expect("Run a model")
        menu.send("\r")
        menu.expect("OWNER/MODEL")
        menu.send("\x03")
        menu.expect("Run a model")
        menu.send("\x1b")
        menu.expect("Leave workloads running")
        menu.down(4)
        menu.expect("Run a template")
        menu.send("\r")
        menu.expect("Template folder or Hub reference")
        menu.send("\x1b")
        menu.expect("Run a template")
        menu.send("\x1b")
        menu.expect("Leave workloads running")

        # A real child CLI prints help and exits. The parent must regain its input/painter.
        menu.down(6)
        menu.expect("Command reference")
        menu.down(5)
        menu.expect("Public commands:")
        menu.expect("Command reference")
        menu.send("\x1b")
        menu.expect("Leave workloads running")
        menu.down(1)
        menu.expect("Import OCI image")
        menu.send("\x03")
        menu.expect("Leave workloads running")

        if engine:
            menu.send("\r")
            menu.expect("Choose a Sandbox VM image")
            menu.send("\r")
            menu.expect("CPU cores")
            menu.send("\x15" + "3\r")
            menu.expect("Memory in GB")
            menu.send("\x1b")  # Back retains the previous CPU answer.
            menu.expect("CPU cores")
            assert "3" in ANSI.sub("", menu.buffer)
            menu.send("\r")
            menu.expect("Memory in GB")
            menu.send("\r")
            menu.expect("Folder to copy into the VM")
            menu.send("\r")
            menu.expect("Show this computer's file tree?")
            menu.send("\r")  # Off.
            menu.expect("Allow the VM to request host-file access?")
            menu.send("\r")  # Off.
            menu.expect("Network routes JSON file")
            menu.send("\r")  # None.
            menu.expect("Add Grid Hosting")
            menu.send("\r")  # Optional tools remain off.
            menu.expect("Launch this Sandbox VM?")
            menu.expect("network: off")
            menu.send("\r")  # Cancel is the default; never boots a VM.
            menu.expect("Leave workloads running")

        menu.send("\x1b")
        menu.finish()
    finally:
        menu.close()
    print("PASS: home, nested menus, cancellation, interactive child, child command and clean exit"
          + (", VM wizard back/defaults/final cancellation" if engine else ""))


if __name__ == "__main__":
    exercise(sys.argv[1], "--engine" in sys.argv[2:])
