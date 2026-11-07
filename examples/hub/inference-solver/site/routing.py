"""One model name across every computer that serves it, and which computer serves each request.

A model name is published once, however many connected computers or model servers serve it.
Each of them is a replica. A conversation keeps to the replica that served its previous turn
while that replica has a free slot: its model server still holds the conversation's prompt
prefix in its KV cache, so the repeated history is not computed again. Otherwise the least busy
replica serves it, chosen by a hash of the conversation so that new conversations spread out.
A replica that failed to answer is tried last for a short while, and a request that could not
reach one replica goes to the next before anything is sent to the caller.
"""
import hashlib
import json
from collections import OrderedDict
import threading
import time

DEFAULT_SLOTS = 8          # Requests one model server generates together (Yougori's vLLM default).
REMEMBER_SECONDS = 1800    # How long a conversation's replica is remembered between turns.
REMEMBER_LIMIT = 20000     # Conversations remembered at most; the oldest are forgotten first.
COOL_SECONDS = 30          # A replica that failed is tried after the others for this long.
ATTEMPTS = 3               # Replicas tried for one request before it fails.
FRESH_SECONDS = 90         # The catalog's staleness window: older health checks do not count.


def _text(value):
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, ensure_ascii=False)


def session_key(key, payload, headers):
    """The conversation a request belongs to, as a short hash; never stored.

    A client's own identity wins: the X-Session-ID header, OpenAI's prompt_cache_key (Codex
    sends its conversation there) or user, or Anthropic's metadata.user_id, which the Messages
    adapter passes as prompt_cache_key (Claude Code names its session there). prompt_cache_key
    is a routing hint only and is removed before the request goes to a model server. Without
    one, the opening of the conversation identifies it: every later turn repeats the system
    prompt and the first user message.
    """
    hint = payload.pop("prompt_cache_key", None)
    explicit = headers.get("X-Session-ID") or hint or payload.get("user")
    if isinstance(explicit, str) and explicit.strip():
        source = "explicit\0" + str(key.get("id", "")) + "\0" + explicit.strip()[:512]
    else:
        opening = []
        for message in payload.get("messages", []):
            if not isinstance(message, dict):
                continue
            role = message.get("role")
            if role in ("system", "developer") and not opening:
                opening.append(("system", _text(message.get("content"))[:8192]))
            elif role == "user":
                opening.append(("user", _text(message.get("content"))[:8192]))
                break
        source = "opening\0" + json.dumps(opening, ensure_ascii=False)
    return hashlib.sha256((str(payload.get("model", "")) + "\0" + source).encode()).hexdigest()[:32]


def cached_tokens(usage, timings=None):
    """Prompt tokens the model server reused from its cache, or None when it did not say.

    OpenAI-compatible servers (vLLM with --enable-prompt-tokens-details, Yougori's model server)
    report usage.prompt_tokens_details.cached_tokens; llama.cpp also reports timings.cache_n.
    """
    if not isinstance(usage, dict):
        return None
    prompt = usage.get("prompt_tokens")
    details = usage.get("prompt_tokens_details")
    value = details.get("cached_tokens") if isinstance(details, dict) else None
    if value is None and isinstance(timings, dict):
        value = timings.get("cache_n")
    if type(value) is not int or value < 0:
        return None
    return min(value, prompt) if type(prompt) is int and prompt >= 0 else value


class Router:
    """In-memory routing state. Losing it on a restart only costs one cold turn per conversation."""

    def __init__(self):
        self.lock = threading.Lock()
        self.active = {}                   # replica id -> requests in flight
        self.slots = {}                    # replica id -> slots its computer reported
        self.groups = {}                   # replica id -> (computer, requests it serves at once in total)
        self.remembered = OrderedDict()    # conversation -> (replica id, last use)
        self.cooling = {}                  # replica id -> time after which it is tried normally
        self.served = {}                   # replica id -> {"requests", "same", "failed"} since start

    @staticmethod
    def replicas(store, model):
        """Every replica of a model name, ready or not, with the connection each one uses."""
        with store.db() as db:
            rows = db.execute("SELECT m.id,m.upstream,e.id AS endpoint,e.name AS source,e.url,e.secret,e.state,e.checked "
                              "FROM models m JOIN endpoints e ON e.id=m.endpoint_id WHERE m.upstream=? ORDER BY m.id", (model,)).fetchall()
        return [dict(row) for row in rows]

    def report_slots(self, replica, slots):
        if type(slots) is int and 1 <= slots <= 256:
            with self.lock:
                self.slots[replica] = slots

    def report_group(self, replica, group, capacity):
        """A connector serves `capacity` requests at once across every model it shares: its
        replicas are full together, whatever each model server's own slots."""
        if type(capacity) is int and 1 <= capacity <= 256:
            with self.lock:
                self.groups[replica] = (group, capacity)

    def order(self, replicas, session):
        """The ready replicas to try for one request, best first (at most ATTEMPTS)."""
        now, clock = time.time(), time.monotonic()
        ready = [r for r in replicas if r["state"] == "ready" and r["checked"] > now - FRESH_SECONDS]
        if not ready:
            return []
        with self.lock:
            load = {}
            for member, (group, _) in self.groups.items():
                load[group] = load.get(group, 0) + self.active.get(member, 0)

            def busy(replica):
                return self.active.get(replica["id"], 0)

            def share(replica):
                """The replica's load as a share of what it can take: its own slots, or its
                computer's capacity across models when that is the tighter limit."""
                own = busy(replica) / self.slots.get(replica["id"], DEFAULT_SLOTS)
                group = self.groups.get(replica["id"])
                return max(own, load.get(group[0], 0) / group[1]) if group else own

            def full(replica):
                return share(replica) >= 1

            def cool(replica):
                return self.cooling.get(replica["id"], 0) > clock

            def spread(replica):
                return hashlib.sha256((session + "\0" + replica["id"]).encode()).digest()

            first = None
            previous = self.remembered.get(session)
            if previous and previous[1] > clock - REMEMBER_SECONDS:
                first = next((r for r in ready if r["id"] == previous[0] and not cool(r)), None)
                # A full replica keeps its conversations only when every other one is full too.
                if first and full(first) and any(not full(r) and not cool(r) for r in ready if r is not first):
                    first = None
            rest = sorted((r for r in ready if r is not first),
                          key=lambda r: (cool(r), full(r), share(r), spread(r)))
            chosen = ([first] if first else []) + rest
            return [dict(r, same=r is first) for r in chosen[:ATTEMPTS]]

    def begin(self, replica):
        with self.lock:
            self.active[replica] = self.active.get(replica, 0) + 1

    def end(self, replica, failed=False, cool=True):
        with self.lock:
            left = self.active.get(replica, 0) - 1
            if left > 0:
                self.active[replica] = left
            else:
                self.active.pop(replica, None)
            if failed:
                self.served.setdefault(replica, {"requests": 0, "same": 0, "failed": 0})["failed"] += 1
                if cool:
                    self.cooling[replica] = time.monotonic() + COOL_SECONDS

    def remember(self, session, replica, same):
        clock = time.monotonic()
        with self.lock:
            self.cooling.pop(replica["id"], None)
            self.remembered[session] = (replica["id"], clock)
            self.remembered.move_to_end(session)
            while len(self.remembered) > REMEMBER_LIMIT or (self.remembered and next(iter(self.remembered.values()))[1] < clock - REMEMBER_SECONDS):
                self.remembered.popitem(last=False)
            counts = self.served.setdefault(replica["id"], {"requests": 0, "same": 0, "failed": 0})
            counts["requests"] += 1
            counts["same"] += bool(same)

    def snapshot(self):
        """Live routing state for the administrator: no conversation identities."""
        clock = time.monotonic()
        with self.lock:
            replicas = set(self.active) | set(self.served) | set(self.slots) | set(self.cooling)
            return {replica: {"active": self.active.get(replica, 0), "slots": self.slots.get(replica, DEFAULT_SLOTS),
                              "cooling": self.cooling.get(replica, 0) > clock, **self.served.get(replica, {"requests": 0, "same": 0, "failed": 0})}
                    for replica in replicas}
