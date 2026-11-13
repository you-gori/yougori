"""A deliberately vulnerable practice app for trying security harnesses safely.

It runs only inside the harness's own Yougori Sandbox VM, on loopback, when the person chooses
"A practice app inside the VM" as the target. Nothing in it is real: the data is made up at each
start and lives in memory. Its flaws are classic, so a security harness has something true to find:

- /login      SQL injection in the sign-in query (string-built SQL)
- /search     SQL injection in the product search
- /hello      reflected cross-site scripting (the name is echoed unescaped)
- /account    broken access control: any account by its number, signed in or not
- /robots.txt points at /backup, which shows made-up configuration secrets
- alice's password is "alice" (a weak password)

Never expose it outside the VM: it binds to 127.0.0.1 only.
"""
import argparse
import html
import secrets
import sqlite3
import threading
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Practice shop</title></head>
<body><h1>Practice shop</h1><p><a href="/">Home</a> | <a href="/login">Sign in</a> |
<a href="/search?q=">Search</a> | <a href="/hello?name=guest">Hello</a> |
<a href="/account?id=2">My account</a></p>{body}</body></html>"""


def database():
    connection = sqlite3.connect(":memory:", check_same_thread=False)
    connection.executescript("""
        CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT, email TEXT, role TEXT);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        INSERT INTO products (name, price) VALUES ('Blue mug', 9.5), ('Notebook', 4.0), ('Desk lamp', 31.0);
    """)
    connection.executemany("INSERT INTO users (id, name, password, email, role) VALUES (?, ?, ?, ?, ?)", [
        (1, "admin", secrets.token_urlsafe(18), "admin@practice.invalid", "admin"),
        (2, "alice", "alice", "alice@practice.invalid", "customer"),
        (3, "bob", secrets.token_urlsafe(12), "bob@practice.invalid", "customer"),
    ])
    return connection


class Handler(BaseHTTPRequestHandler):
    server_version = "PracticeShop/1.0"

    def log_message(self, *_):
        pass

    def send_page(self, body, status=200, headers=()):
        raw = PAGE.format(body=body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def query(self, sql):
        with self.server.lock:
            return self.server.db.execute(sql).fetchall()

    def user(self):
        cookie = SimpleCookie(self.headers.get("Cookie", ""))
        token = cookie["session"].value if "session" in cookie else None
        return self.server.sessions.get(token)

    def do_GET(self):
        parts = urlsplit(self.path)
        args = {k: v[0] for k, v in parse_qs(parts.query, keep_blank_values=True).items()}
        try:
            if parts.path == "/":
                who = self.user()
                return self.send_page("<p>Welcome%s.</p>" % (", " + html.escape(who) if who else ""))
            if parts.path == "/robots.txt":
                raw = b"User-agent: *\nDisallow: /backup\n"
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                return self.wfile.write(raw)
            if parts.path == "/backup":
                return self.send_page("<pre>DATABASE_PASSWORD=practice-only-%s\nAPI_KEY=practice-only-%s</pre>"
                                      % (self.server.fake[0], self.server.fake[1]))
            if parts.path == "/login":
                return self.send_page('<form method="post" action="/login"><input name="user"> '
                                      '<input name="password" type="password"> <button>Sign in</button></form>')
            if parts.path == "/search":
                # Flaw: string-built SQL.
                rows = self.query("SELECT name, price FROM products WHERE name LIKE '%" + args.get("q", "") + "%'")
                items = "".join("<li>%s: %s</li>" % (html.escape(str(r[0])), html.escape(str(r[1]))) for r in rows)
                return self.send_page("<ul>%s</ul>" % items)
            if parts.path == "/hello":
                # Flaw: the name is echoed unescaped.
                return self.send_page("<p>Hello %s!</p>" % args.get("name", "guest"))
            if parts.path == "/account":
                # Flaw: no check that the account is the signed-in person's.
                rows = self.query("SELECT id, name, email, role FROM users WHERE id = %d" % int(args.get("id", "0")))
                if not rows:
                    return self.send_page("<p>No such account.</p>", 404)
                row = rows[0]
                return self.send_page("<p>Account %d: %s, %s, %s</p>" % (row[0], html.escape(row[1]), html.escape(row[2]), html.escape(row[3])))
            return self.send_page("<p>Not found.</p>", 404)
        except (sqlite3.Error, ValueError) as error:
            # Flaw: database errors are shown to the visitor.
            return self.send_page("<p>Error: %s</p>" % html.escape(str(error)), 500)

    def do_POST(self):
        if urlsplit(self.path).path != "/login":
            return self.send_page("<p>Not found.</p>", 404)
        size = int(self.headers.get("Content-Length") or 0)
        if size > 65536:
            return self.send_page("<p>Too large.</p>", 413)
        form = {k: v[0] for k, v in parse_qs(self.rfile.read(size).decode("utf-8", "replace")).items()}
        try:
            # Flaw: string-built SQL in the sign-in check.
            rows = self.query("SELECT name FROM users WHERE name = '" + form.get("user", "") +
                              "' AND password = '" + form.get("password", "") + "'")
        except sqlite3.Error as error:
            return self.send_page("<p>Error: %s</p>" % html.escape(str(error)), 500)
        if not rows:
            return self.send_page("<p>Wrong name or password.</p>", 401)
        token = secrets.token_hex(16)
        self.server.sessions[token] = rows[0][0]
        # Flaw: the session cookie is readable by scripts.
        return self.send_page("<p>Signed in as %s.</p>" % html.escape(rows[0][0]), 200,
                              [("Set-Cookie", "session=" + token + "; Path=/")])


def serve(port):
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.db = database()
    server.lock = threading.Lock()
    server.sessions = {}
    server.fake = (secrets.token_hex(6), secrets.token_hex(10))
    return server


def main():
    parser = argparse.ArgumentParser(description="A deliberately vulnerable practice app, on loopback only.")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    if not 1024 <= args.port <= 65535:
        raise SystemExit("Choose a port from 1024 to 65535.")
    server = serve(args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
