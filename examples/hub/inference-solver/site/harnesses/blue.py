"""Blue terminal accents, retaining neutral text, backgrounds and controls."""
import os
import re
import select
import signal
import sys

BLUE = b"38;2;82;151;255"


class Blue:
    def __init__(self):
        self.pending = b""

    def feed(self, data, final=False):
        data = self.pending + data
        self.pending = b""
        # Hold an incomplete terminal escape across reads.
        last = data.rfind(b"\x1b")
        if not final and last >= 0 and re.fullmatch(rb"\x1b(?:\[[0-9;:]*)?", data[last:]):
            self.pending, data = data[last:], data[:last]

        def color(match):
            raw = match[1].decode().replace(":", ";")
            codes = [int(c) if c else 0 for c in raw.split(";")]
            out, index = [], 0
            while index < len(codes):
                value = codes[index]
                if value in (38, 48, 58) and index + 1 < len(codes):
                    length = 5 if codes[index + 1] == 2 else 3 if codes[index + 1] == 5 else 1
                    group = codes[index:index + length]
                    neutral = (len(group) == 5 and max(group[2:]) - min(group[2:]) < 20) or (
                        len(group) == 3 and (group[2] in (0, 7, 8, 15) or group[2] >= 232))
                    out.append(BLUE.decode() if value == 38 and not neutral else ";".join(map(str, group)))
                    index += len(group) - 1
                elif 31 <= value <= 36 or 91 <= value <= 96:
                    out.append(BLUE.decode())
                else:
                    out.append(str(value))
                index += 1
            return b"\x1b[" + ";".join(out).encode() + b"m"
        return re.sub(rb"\x1b\[([0-9;:]*)m", color, data)


def run(argv, environment):
    import fcntl
    import pty
    import termios
    import tty
    child, master = pty.fork()
    if child == 0:
        os.execvpe(argv[0], argv, environment)
    original = termios.tcgetattr(0) if os.isatty(0) else None

    def resize(*_):
        if os.isatty(0):
            fcntl.ioctl(master, termios.TIOCSWINSZ, fcntl.ioctl(0, termios.TIOCGWINSZ, b"\0" * 8))
    signal.signal(signal.SIGWINCH, resize)
    resize()
    parser = Blue()
    stdin_open = True
    try:
        if original:
            tty.setraw(0)
        while True:
            reads, _, _ = select.select([master, 0] if stdin_open else [master], [], [])
            if master in reads:
                try:
                    block = os.read(master, 65536)
                except OSError:
                    break
                if not block:
                    break
                os.write(1, parser.feed(block))
            if stdin_open and 0 in reads:
                block = os.read(0, 65536)
                if block:
                    os.write(master, block)
                else:
                    stdin_open = False
                    if original:
                        os.write(master, b"\x04")
    finally:
        if original:
            termios.tcsetattr(0, termios.TCSADRAIN, original)
        os.write(1, parser.feed(b"", final=True) + b"\x1b[0m")
        os.close(master)
    return os.waitstatus_to_exitcode(os.waitpid(child, 0)[1])
