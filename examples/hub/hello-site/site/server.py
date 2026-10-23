"""Serves one page. The title comes from the SITE_TITLE answer given when the template ran."""
import html
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TITLE = os.environ.get("SITE_TITLE") or "Hello from Yougori"
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html"), encoding="utf-8") as page:
    BODY = page.read().replace("%TITLE%", html.escape(TITLE)).encode("utf-8")


class Page(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(BODY)))
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *args):
        pass


ThreadingHTTPServer(("0.0.0.0", 8080), Page).serve_forever()
