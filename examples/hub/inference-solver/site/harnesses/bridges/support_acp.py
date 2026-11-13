"""What Yougori's coding bridges share (aider_acp, interpreter_acp, swe_acp, plandex_acp).

Each bridge runs one harness's real engine behind the Yougori screen and reports through
bridges.acp.Bridge. prepare() runs first: the protocol's input moves off descriptor 0 (which becomes
/dev/null, so no command the engine runs can read the protocol) and the process gives up the
screen's controlling terminal (so nothing it starts can draw on the screen or stop waiting for its
keyboard). QueuedBridge writes every protocol message from one thread, so a cancel that
interrupts the engine never cuts a message in half. MainThread runs the engine's work on the
main thread, where a cancel interrupts it the way Ctrl+C does in the harness's own terminal, even
inside a blocking network read. serve() ties them together and ends the process cleanly when the
client goes away or the screen stops it.
"""
import argparse
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
import traceback

from bridges.acp import Bridge, unblock_signals  # noqa: F401  (unblock_signals: for the bridges' own threads)

# Child process groups the bridge started, stopped when it ends however it ends.
_groups = set()
_groups_lock = threading.Lock()
_on_exit = []


def prepare():
    """Takes the protocol's input off descriptor 0 and leaves the controlling terminal. Returns the
    protocol's input stream. Call before the engine is imported or started."""
    protocol = os.dup(0)
    null = os.open(os.devnull, os.O_RDONLY)
    os.dup2(null, 0)
    os.close(null)
    detach_terminal()
    return os.fdopen(protocol, "rb")


def detach_terminal():
    """Gives up the controlling terminal (the Yougori screen's PTY), so no child (a sudo prompt,
    getpass, an editor) writes on the screen or stops on SIGTTIN reading it. Linux; a no-op
    elsewhere or when there is none."""
    try:
        import fcntl
        import termios
    except ImportError:
        return False
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError:
        return False
    try:
        fcntl.ioctl(fd, termios.TIOCNOTTY)
        return True
    except OSError:
        return False
    finally:
        os.close(fd)


def quiet_signals():
    """Keeps SIGINT and SIGTERM away from the calling thread, so they reach the main thread (where
    Python handles them) and never interrupt a protocol read or write. Threads it starts inherit
    this; one that starts commands calls unblock_signals() first."""
    if hasattr(signal, "pthread_sigmask"):
        signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT, signal.SIGTERM})


class _Input:
    """The protocol's input; tells the bridge the moment the client goes away, before Bridge.run
    waits for the turn, so the engine can be stopped first."""

    def __init__(self, stream, on_eof):
        self.stream, self.on_eof = stream, on_eof

    def readline(self):
        line = self.stream.readline()
        if not line:
            self.on_eof()
        return line

    def close(self):
        self.stream.close()


class QueuedBridge(Bridge):
    """A Bridge whose messages are written by one thread, in order. Subclasses override closing()
    to stop their engine when the client goes away."""

    def __init__(self, name, version, stdin, **options):
        super().__init__(name, version, stdin=_Input(stdin, self._client_gone), **options)
        self.closing_event = threading.Event()
        self._outbox = queue.SimpleQueue()
        self._connected = True
        self._writer = threading.Thread(target=self._write_all, name="acp-writer", daemon=True)
        self._writer.start()

    def send(self, value):
        if self._connected:
            self._outbox.put(value)

    def _write_all(self):
        quiet_signals()
        while True:
            value = self._outbox.get()
            if value is None:
                return
            try:
                Bridge.send(self, value)
            except (OSError, ValueError):
                # The client went away; what is still queued has nowhere to go.
                self._connected = False
                return

    def flush(self, timeout=5.0):
        """Writes what is queued, then stops the writer."""
        self._outbox.put(None)
        self._writer.join(timeout)

    def _client_gone(self):
        if not self.closing_event.is_set():
            self.closing_event.set()
            self.cancel_event.set()
            try:
                self.closing()
            except Exception:
                traceback.print_exc()

    def closing(self):
        """The client went away: stop the engine's work now."""


class Job:
    def __init__(self, fn, args):
        self.fn, self.args = fn, args
        self.done = threading.Event()
        self.result = self.error = None
        self.interrupted = False
        self.started = False

    def outcome(self):
        if self.error is not None:
            raise self.error
        return self.result


class MainThread:
    """Runs jobs on the main thread. interrupt() raises KeyboardInterrupt in the job running now,
    once, as Ctrl+C does: a blocking read is interrupted too. Create it on the main thread."""

    def __init__(self):
        self._jobs = queue.SimpleQueue()
        self._lock = threading.Lock()
        self._job = None
        self._armed = False
        # True only while a job's own code runs: an interrupt never lands in the bookkeeping
        # around it, which must always finish the job (or its caller would wait for ever).
        self._in_job = False
        self._stopping = False
        signal.signal(signal.SIGINT, self._on_interrupt)

    def _on_interrupt(self, signum, frame):
        # Only an interrupt we asked for, only once, and only inside the job: one that arrives
        # after its job's code returned is dropped instead of landing elsewhere.
        if self._armed and self._in_job:
            self._armed = False
            raise KeyboardInterrupt

    def submit(self, fn, *args):
        job = Job(fn, args)
        self._jobs.put(job)
        return job

    def call(self, fn, *args):
        """Runs fn on the main thread and waits for it (from another thread)."""
        job = self.submit(fn, *args)
        job.done.wait()
        return job.outcome()

    @property
    def busy(self):
        return self._job is not None

    @property
    def current(self):
        """The job running now, if any."""
        return self._job

    def interrupt(self, only=None):
        """Interrupts the running job (only if it is `only`, when given). A job `only` still waiting
        behind another never runs: it ends at once as interrupted."""
        with self._lock:
            job = self._job
            if only is not None and job is not only:
                if only.started or only.interrupted or only.done.is_set():
                    return False
                only.interrupted = True
                return True
            if job is None or job.interrupted or self._armed:
                return False
            job.interrupted = True
            self._armed = True
        if hasattr(signal, "pthread_kill"):
            signal.pthread_kill(threading.main_thread().ident, signal.SIGINT)
        return True

    def stop(self):
        """Interrupts the running job and ends serve() after it."""
        self._stopping = True
        self.interrupt()
        self._jobs.put(None)

    def serve(self):
        while True:
            try:
                job = self._jobs.get()
                if job is None:
                    return
                if self._stopping:
                    job.interrupted = True
                    job.error = KeyboardInterrupt()
                    job.done.set()
                    continue
                self._run(job)
            except KeyboardInterrupt:
                continue

    def _run(self, job):
        # interrupt() can arm only once the job is current (under the lock), and from then until
        # its code has returned, whatever the interrupt raises is caught here: the job always ends.
        try:
            with self._lock:
                if job.interrupted:
                    # Interrupted while it waited: it ends as if Ctrl+C had stopped it at its start.
                    raise KeyboardInterrupt
                job.started = True
                self._job = job
                self._in_job = True
            try:
                job.result = job.fn(*job.args)
            finally:
                self._in_job = False
        except BaseException as error:  # the caller sees it, KeyboardInterrupt included
            job.error = error
        with self._lock:
            self._job = None
            self._armed = False
            self._in_job = False
        job.done.set()


def remember_group(pid):
    with _groups_lock:
        _groups.add(pid)


def forget_group(pid):
    with _groups_lock:
        _groups.discard(pid)


def signal_group(pid, sig):
    """Signals a process group (POSIX; elsewhere the process alone is ended)."""
    try:
        if hasattr(os, "killpg"):
            os.killpg(pid, sig)
        else:
            os.kill(pid, sig)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def stop_group(process, grace=3.0, first=None):
    """Stops a process started with start_new_session=True and everything it started: `first`
    (SIGINT by default), then SIGTERM, then SIGKILL, waiting `grace` seconds between them."""
    first = signal.SIGINT if first is None else first
    for sig in (first, signal.SIGTERM, getattr(signal, "SIGKILL", signal.SIGTERM)):
        if process.poll() is not None and not _group_alive(process.pid):
            break
        signal_group(process.pid, sig)
        deadline = time.monotonic() + grace
        while time.monotonic() < deadline:
            if process.poll() is not None and not _group_alive(process.pid):
                break
            time.sleep(0.05)
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass
    forget_group(process.pid)


def _group_alive(pgid):
    if not hasattr(os, "killpg"):
        return False
    try:
        os.killpg(pgid, 0)
        return True
    except (ProcessLookupError, PermissionError, OSError):
        return False


def descendants(pid):
    """Every live process below `pid` (Linux /proc), children first."""
    parents = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return []
    for name in names:
        if not name.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % name, "rb") as stat:
                fields = stat.read().rsplit(b")", 1)[1].split()
            parents.setdefault(int(fields[1]), []).append(int(name))
        except (OSError, IndexError, ValueError):
            continue
    found, todo = [], list(parents.get(pid, []))
    while todo:
        child = todo.pop(0)
        found.append(child)
        todo.extend(parents.get(child, []))
    return found


def interrupt_tree(pid, grace=2.0):
    """Interrupts the work running below `pid` (not `pid` itself): SIGINT, then SIGKILL for what
    is still there after `grace` seconds."""
    children = descendants(pid)
    for child in children:
        try:
            os.kill(child, signal.SIGINT)
        except OSError:
            pass
    deadline = time.monotonic() + grace
    while children and time.monotonic() < deadline:
        children = [c for c in children if _alive(c)]
        time.sleep(0.05)
    for child in children:
        try:
            os.kill(child, getattr(signal, "SIGKILL", signal.SIGTERM))
        except OSError:
            pass


def _alive(pid):
    try:
        with open("/proc/%d/stat" % pid, "rb") as stat:
            return stat.read().rsplit(b")", 1)[1].split()[0] != b"Z"
    except (OSError, IndexError):
        return False


def on_exit(fn):
    """Runs fn when the bridge ends (the client went away, or SIGTERM)."""
    _on_exit.append(fn)


def _cleanup():
    while _on_exit:
        fn = _on_exit.pop()
        try:
            fn()
        except Exception:
            traceback.print_exc()
    with _groups_lock:
        groups = list(_groups)
        _groups.clear()
    for pid in groups:
        signal_group(pid, signal.SIGTERM)
    if groups:
        time.sleep(0.3)
        for pid in groups:
            signal_group(pid, getattr(signal, "SIGKILL", signal.SIGTERM))


def arguments(argv, description):
    """The bridge's own options (before `--`) and the engine's arguments (after it)."""
    argv = list(argv)
    engine = []
    if "--" in argv:
        index = argv.index("--")
        argv, engine = argv[:index], argv[index + 1:]
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--model", required=True, help="This inference's model to start on.")
    parser.add_argument("--models", type=json.loads, default=[], help="This inference's models (JSON list).")
    parser.add_argument("--context-window", type=int, default=32768)
    parser.add_argument("--max-output", type=int, default=4096)
    args = parser.parse_args(argv)
    models = [m for m in args.models if isinstance(m, str) and m]
    if args.model not in models:
        models.insert(0, args.model)
    args.models = models
    args.engine = engine
    return args


def serve(bridge, main=None):
    """Serves the client: the protocol on its own thread, the engine's jobs (if `main`) on this
    one. Ends the process when the client goes away or on SIGTERM, after the bridge's cleanup."""

    def terminate(signum, frame):
        _cleanup()
        os._exit(128 + signum)

    signal.signal(signal.SIGTERM, terminate)
    gone = threading.Event()

    def protocol():
        quiet_signals()
        try:
            bridge.run()
        except BaseException:
            traceback.print_exc()
        finally:
            gone.set()
            if main is not None:
                main.stop()

    threading.Thread(target=protocol, name="acp-reader", daemon=True).start()
    code = 0
    try:
        if main is not None:
            main.serve()
        else:
            while not gone.wait(0.5):
                pass
    except SystemExit as stop:
        code = stop.code if isinstance(stop.code, int) else 1
    except BaseException:
        traceback.print_exc()
        code = 1
    _cleanup()
    bridge.flush()
    sys.stderr.flush()
    os._exit(code)


def exit_now(bridge, code, message=None):
    """The engine cannot go on: say why on stderr (the screen shows it with the exit), end."""
    if message:
        sys.stderr.write(message.rstrip() + "\n")
    _cleanup()
    bridge.flush()
    sys.stderr.flush()
    os._exit(code)


def first_line(text, limit=200):
    line = (text or "").strip().splitlines()[0] if (text or "").strip() else ""
    return line if len(line) <= limit else line[: limit - 1] + "…"


def read_text(path, limit=8 * 1024 * 1024):
    """A file's text for a diff, or None when it is missing, binary or too large."""
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "rb") as stream:
            raw = stream.read()
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace")


def answers(home=None):
    """The chosen harness's setup answers (written by the VM's launcher), if any."""
    home = home or os.environ.get("HOME") or os.path.expanduser("~")
    try:
        with open(os.path.join(home, ".yougori", "answers.json"), encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}
