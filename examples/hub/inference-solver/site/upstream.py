"""Bounded transport to administrator-enrolled model servers, never through proxies."""
import http.client
import ipaddress
import json
import socket
import ssl
from urllib.parse import urlsplit


class UpstreamError(Exception):
    def __init__(self, message, status=503):
        super().__init__(message)
        self.status = status


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


def connect(base, secret, path, payload=None, timeout=30):
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
            conn.request("GET" if body is None else "POST", parsed.path.rstrip("/") + path, body=body, headers=headers)
            response = conn.getresponse()
            if response.status != 200:
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


def discover(base, secret):
    conn, response = connect(base, secret, "/models", timeout=5)
    try:
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError()
        data = json.loads(raw)["data"]
        if not isinstance(data, list) or not 1 <= len(data) <= 100:
            raise ValueError()
        ids = [m["id"] for m in data]
        if any(not isinstance(m, str) or not 1 <= len(m) <= 200 or any(ord(c) < 33 for c in m) for m in ids):
            raise ValueError()
        return sorted(set(ids))
    except (ValueError, KeyError, TypeError, OSError, http.client.HTTPException):
        raise UpstreamError("The server did not return a valid model catalog.", 502) from None
    finally:
        conn.close()
