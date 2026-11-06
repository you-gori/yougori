"""Allowed inference paths and fixed-origin validation shared by VM and host."""
import re
from urllib.parse import urlsplit
from transport import local_hostname

LIMIT = 4 * 1024 * 1024


def allowed(method, target):
    if not isinstance(target, str) or len(target) > 2048 or any(ord(c) < 33 for c in target):
        return False
    if method == "GET":
        return target == "/v1/models"
    if method != "POST":
        return False
    return target in ("/v1/chat/completions", "/v1/responses", "/v1/messages", "/v1/messages?beta=true") or bool(re.fullmatch(
        r"/v1(?:beta)?/models/[A-Za-z0-9_.:%/\-]+:(?:generateContent|streamGenerateContent)(?:\?alt=sse)?", target))


def server_url(value):
    p = urlsplit(value)
    if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password or p.query or p.fragment or p.path not in ("", "/"):
        raise ValueError("Use the Inference Solver website URL without a path, credentials or query.")
    if p.scheme == "http" and not local_hostname(p.hostname):
        raise ValueError("Use HTTPS for a remote Inference Solver website.")
    if not 1 <= (p.port or 443) <= 65535:
        raise ValueError("Invalid server port.")
    return p
