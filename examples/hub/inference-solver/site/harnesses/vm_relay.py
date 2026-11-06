"""Host-side fixed-origin relay. Guest-selected destinations/headers are never used."""
import base64
import http.client
import ssl
from relay import LIMIT, allowed, server_url
from transport import LocalConnection


def forward(server, secret, request, deliver):
    connection = None
    try:
        method, path = request.get("method"), request.get("path")
        if not allowed(method, path):
            raise ValueError("Only this server's model API is allowed.")
        encoded = request.get("body", "")
        if not isinstance(encoded, str) or len(encoded) > (LIMIT + 2) // 3 * 4:
            raise ValueError("Request too large.")
        body = base64.b64decode(encoded, validate=True)
        if len(body) > LIMIT or (method == "GET" and body):
            raise ValueError("Invalid request body.")
        p = server_url(server)
        connection = (http.client.HTTPSConnection(p.hostname, p.port or 443, timeout=180,
            context=ssl.create_default_context()) if p.scheme == "https" else
            LocalConnection(p.hostname, p.port or 80, timeout=180))
        connection.request(method, path, body=body or None, headers={"Authorization": "Bearer " + secret,
            "Content-Type": "application/json", "Accept": "application/json, text/event-stream", "Connection": "close"})
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise ValueError("Redirects are refused.")
        deliver({"status": response.status, "content_type": response.getheader("Content-Type", "application/json")})
        total = 0
        while block := response.read1(32768):
            total += len(block)
            if total > 32 * 1024 * 1024:
                raise ValueError("Response too large.")
            deliver({"data": base64.b64encode(block).decode()})
        deliver({"done": True})
    except (OSError, ValueError, http.client.HTTPException):
        deliver({"error": "The request was refused or the inference server could not answer.", "done": True})
    finally:
        if connection:
            connection.close()
