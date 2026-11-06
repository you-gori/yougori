"""Bounded JSON HTTP transport. Never forward credentials through redirects or proxies."""
import json
import urllib.error
import urllib.request


class Failure(Exception):
    def __init__(self, status, message, code="upstream_error"):
        super().__init__(message)
        self.status, self.code = status, code


# Refusals the bridge makes itself, in this site's own words. Only these codes pass through, each
# with a fixed message: a provider's own text is never forwarded, so it can't leak an account detail.
BRIDGE_REFUSALS = {
    "no_longer_free": (409, "This model is no longer free, so it was taken off sale. The admin can set a selling price once the catalogue refreshes."),
    "model_unavailable": (404, "That model is not available from its provider right now. It comes back by itself when the provider lists it again."),
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def request(url, payload=None, headers=None, timeout=30):
    call = urllib.request.Request(url, data=None if payload is None else json.dumps(payload, allow_nan=False).encode(),
                                  headers={"content-type": "application/json", **(headers or {})})
    try:
        with urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect()).open(call, timeout=timeout) as response:
            data = response.read(4 * 1024 * 1024 + 1)
            if len(data) > 4 * 1024 * 1024:
                raise Failure(502, "Provider response was too large.")
            result = json.loads(data)
            if not isinstance(result, dict):
                raise ValueError("Expected object")
            return result
    except urllib.error.HTTPError as error:
        # Provider responses can contain credentials or account details. Return only classified errors.
        raw = error.read(8192).decode("utf-8", "replace").lower()
        try:
            code = json.loads(raw).get("error", {}).get("code")
        except (ValueError, AttributeError):
            code = None
        if code in BRIDGE_REFUSALS:
            status, message = BRIDGE_REFUSALS[code]
            raise Failure(status, message, code) from None
        if error.code == 402 or error.code == 429 and any(word in raw for word in ("insufficient_quota", "quota_exceeded", "quota_exhausted", "insufficient balance")):
            raise Failure(429, "Provider quota or balance is exhausted.", "quota_exhausted") from None
        if error.code == 429:
            raise Failure(429, "Provider rate limit reached. Try again later.", "rate_limit") from None
        if error.code in (401, 403):
            raise Failure(502, "Provider authorization failed. The admin must check its API key.", "provider_auth") from None
        raise Failure(502 if error.code >= 500 or error.code < 400 else error.code,
                      "Provider rejected the request.") from None
    except (urllib.error.URLError, OSError, ValueError) as error:
        raise Failure(503, "Provider unavailable or returned invalid JSON.", "provider_unavailable") from None
