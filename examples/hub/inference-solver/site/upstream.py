"""Bounded transport to administrator-enrolled model servers, never through proxies."""
import http.client
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlsplit


class UpstreamError(Exception):
    def __init__(self, message, status=503, code=""):
        super().__init__(message)
        self.status = status
        # The model server's own code where it gave one (a media route's job_unknown, media_input).
        self.code = code


def address(value):
    if not isinstance(value, str) or len(value) > 512 or any(ord(c) < 33 for c in value):
        raise ValueError("Enter a model API URL, including /v1.")
    parsed = urlsplit(value)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Use an HTTP or HTTPS model URL without credentials, a query, or a fragment.")
    if parsed.path.rstrip("/") != "/v1":
        raise ValueError("The model API base address must end in /v1.")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError:
        raise ValueError("The model API port is invalid.") from None
    if not 1 <= port <= 65535:
        raise ValueError("The model API port is invalid.")
    return value.rstrip("/")


def connect(base, secret, path, payload=None, timeout=30, expect=(200,), method=None):
    """One request to a model server: GET without a payload, POST with one (or `method`); the
    connection and response, when the status is one of `expect`. A media route's own refusals
    (400, 404, 409, 410, 429) are raised with their words and code."""
    parsed = urlsplit(address(base))
    if not isinstance(secret, str) or len(secret) > 1024 or any(ord(c) < 33 or ord(c) > 126 for c in secret):
        raise ValueError("The model API key is invalid.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        addresses = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
        candidates = []
        for item in addresses:
            ip = ipaddress.ip_address(item[4][0])
            inspected = ip.ipv4_mapped if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped else ip
            if (inspected.is_link_local or inspected.is_multicast or inspected.is_unspecified or inspected.is_reserved
                    or inspected == ipaddress.ip_address("fd00:ec2::254")):
                continue
            if parsed.scheme == "http" and not (inspected.is_private or inspected.is_loopback):
                continue
            candidates.append(item[4][0])
        if not candidates:
            raise UpstreamError("Use HTTPS for a public server; metadata and special network addresses are not allowed.", 400)
        # Connect to the checked address once. TLS still verifies the original hostname.
        conn = http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)
        sock = socket.create_connection((candidates[0], port), timeout=timeout)
        try:
            if parsed.scheme == "https":
                sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
            conn.sock = sock
            body = None if payload is None else json.dumps(payload, allow_nan=False).encode()
            headers = {"Accept": "application/json", "Content-Type": "application/json", "Connection": "close"}
            if secret:
                headers["Authorization"] = "Bearer " + secret
            conn.request(method or ("GET" if body is None else "POST"), parsed.path.rstrip("/") + path, body=body, headers=headers)
            response = conn.getresponse()
            if response.status not in expect:
                if path != "/chat/completions" and response.status in (400, 404, 409, 410, 429, 503):
                    # A media route answers in its own words, with a code the caller can act on.
                    raw = response.read(65536)
                    response.close()
                    conn.close()
                    try:
                        detail = json.loads(raw)["error"]
                        message, code = str(detail.get("message", ""))[:300], str(detail.get("code", ""))[:40]
                    except (ValueError, KeyError, TypeError, AttributeError):
                        message, code = "", ""
                    raise UpstreamError(message or "The model server refused this request.", response.status, code)
                # The response may own the socket (a closing server); close both.
                response.close()
                conn.close()
                if response.status == 400:
                    # The request itself (its length or parameters); another server would refuse it too.
                    raise UpstreamError("The model server refused this request. Check its context length and parameters.", 400)
                message = "The model server rejected its credential." if response.status in (401, 403) else "The model server is not ready or refused the request."
                raise UpstreamError(message, 429 if response.status == 429 else 502)
            return conn, response
        except BaseException:
            sock.close()
            raise
    except UpstreamError:
        raise
    except (OSError, ValueError, http.client.HTTPException):
        raise UpstreamError("The model server could not be reached securely.") from None


def discover_catalog(base, secret):
    """The server's models, each with what it says it enforces: (name, {"json": True|False|None}),
    sorted by name. Yougori's model server lists capabilities.structuredOutput; a server that
    lists nothing leaves it unknown (None)."""
    conn, response = connect(base, secret, "/models", timeout=5)
    try:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError()
        data = json.loads(raw)["data"]
        if not isinstance(data, list) or not 1 <= len(data) <= 100:
            raise ValueError()
        catalog = {}
        for item in data:
            name = item["id"]
            if not isinstance(name, str) or not 1 <= len(name) <= 200 or any(ord(c) < 33 for c in name):
                raise ValueError()
            capabilities = item.get("capabilities") if isinstance(item, dict) else None
            enforced = capabilities.get("structuredOutput") if isinstance(capabilities, dict) else None
            # The kind of model (text-generation, or a media task) as Yougori's model server lists it.
            task = item.get("task") if isinstance(item, dict) else None
            catalog[name] = {"json": enforced if isinstance(enforced, bool) else None,
                             "task": task if isinstance(task, str) and re.fullmatch(r"[a-z][a-z-]{0,39}", task) else None}
        return sorted(catalog.items())
    except (ValueError, KeyError, TypeError, OSError, http.client.HTTPException):
        raise UpstreamError("The server did not return a valid model catalog.", 502) from None
    finally:
        conn.close()


def discover(base, secret):
    """The names of the server's models, sorted."""
    return [name for name, _ in discover_catalog(base, secret)]
