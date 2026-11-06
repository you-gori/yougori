"""A small fixed concurrency ceiling for the stdlib HTTP servers."""
import signal
import sys
import threading
from http.server import ThreadingHTTPServer


def exit_on_stop():
    """As a container's first process, Python ignores SIGTERM unless it handles it, so every stop
    would wait for the runtime's kill 30 seconds later. Exits cleanly instead."""
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            try:
                request.settimeout(2)
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, *args):
        try:
            super().process_request_thread(*args)
        finally:
            self.slots.release()
