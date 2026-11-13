"""Private Chat Completions relay. Authentication and model scopes apply before I/O.

A request names a model; the router picks which of that model's replicas serves it (routing.py).
"""
import http.client
import json
import re
import secrets
import time

import routing
from upstream import UpstreamError, connect


# The longest reply Yougori's model server takes (its max_tokens limit).
REPLY_TOKENS = 4096
# The codes of a Yougori model server's refusals of a request's size (src-tauri/src/model_server.py
# RequestLimit) and of a conversation too long for the model's context (ContextRefusal).
REQUEST_LIMIT, CONTEXT_WINDOW = "yougori_request_limit", "yougori_context_window"
# A Yougori model server's refusal of a request's tools names how many it takes: "Agent tools
# require the GGUF or vLLM runner and 1 to 32 function definitions". A request within that number
# was refused because the model's runner calls no tools.
TOOL_COUNT = re.compile(r"\b1 to ([0-9]+) function definitions\b")
# What the relay says of a refusal that gives no words of its own (as upstream.connect).
REFUSED = "The model server refused this request. Check its context length and parameters."
# What a model is told when its request goes on without tools, so that it never acts as if one ran.
NO_TOOLS = ("No tools are available for this reply. Nothing you write runs. Answer in plain text. Never write a "
            "tool call, and never say that a command ran or show output that no tool returned.")


def asked(payload):
    """The request with its instructions as the user's turn when no message is the user's: Yougori's
    model server, like many chat templates, takes no chat without one, and Plandex names each plan
    with a system message alone. Its system and developer messages then become user messages,
    those in a row one message. The same request when a message is the user's."""
    messages = payload["messages"]
    if any(message.get("role") == "user" for message in messages):
        return payload
    turned = []
    for message in messages:
        if message.get("role") not in ("system", "developer"):
            turned.append(message)
            continue
        entry, last = {**message, "role": "user"}, turned[-1] if turned else {}
        if last.get("role") == "user" and set(last) == set(entry) == {"role", "content"} \
                and all(isinstance(m["content"], (str, list)) for m in (last, entry)):
            # Many chat templates want the roles to alternate: text joins text, other content goes
            # on part after part.
            first, then = last["content"], entry["content"]
            last["content"] = first + "\n\n" + then if isinstance(first, str) and isinstance(then, str) else [*parts(first), *parts(then)]
        else:
            turned.append(entry)
    return {**payload, "messages": turned} if turned != messages else payload


def parts(content):
    """A message's content as a list of parts: text as one text part."""
    return [{"type": "text", "text": content}] if isinstance(content, str) else content


def capped(payload):
    """The request with a reply limit (max_tokens, max_completion_tokens) of at most REPLY_TOKENS:
    harnesses ask up to 32,768 of a model they do not know, which Yougori's model server refuses.
    Its tools stay. The same request when it asks no more."""
    over = {key: REPLY_TOKENS for key in ("max_tokens", "max_completion_tokens")
            if type(payload.get(key)) is int and payload[key] > REPLY_TOKENS}
    return {**payload, **over} if over else payload


def plain(payload):
    """The request as plain chat, for a model server that refused it as it was and may take no
    tools: without them, so a model on a runtime that calls none still answers any harness, in
    text; earlier tool calls and their results written into the conversation as text; the model
    told that no tools are available and that nothing it writes runs (NO_TOOLS); and a reply
    limit of at most 4,096 tokens. The same request when there is nothing to change."""
    body = {key: value for key, value in payload.items() if key not in ("tools", "tool_choice", "parallel_tool_calls")}
    dropped = len(body) < len(payload) or any(message.get("role") == "tool" or "tool_calls" in message
                                              for message in payload["messages"])
    names, messages = {}, []
    for message in payload["messages"]:
        content = message.get("content")
        text = content if isinstance(content, str) else "\n".join(
            part["text"] for part in content if isinstance(part, dict) and isinstance(part.get("text"), str)) if isinstance(content, list) else ""
        if message.get("role") == "tool":
            entry = {"role": "user", "content": "Result of " + names.get(str(message.get("tool_call_id")), "a tool") + ":\n" + text}
        elif message.get("role") == "assistant" and isinstance(message.get("tool_calls"), list):
            calls = []
            for call in message["tool_calls"]:
                function = call.get("function") if isinstance(call, dict) and isinstance(call.get("function"), dict) else {}
                name = str(function.get("name") or "a tool")
                names[str(call.get("id")) if isinstance(call, dict) else ""] = name
                calls.append("Called " + name + " with " + str(function.get("arguments") or "{}"))
            entry = {"role": "assistant", "content": "\n\n".join(part for part in (text, *calls) if part)}
        else:
            entry = {key: value for key, value in message.items() if key not in ("tool_calls", "tool_call_id")}
            if entry.get("role") == "assistant" and entry.get("content") is None:
                entry["content"] = ""
        # Results in a row (or a result and the next question) become one message, since many
        # chat templates want the roles to alternate.
        last = messages[-1] if messages else {}
        if set(entry) == set(last) == {"role", "content"} and entry["role"] == last["role"] and all(isinstance(m["content"], str) for m in (entry, last)):
            last["content"] += "\n\n" + entry["content"]
        else:
            messages.append(entry)
    if dropped:
        # After the harness's own instructions, which may say to use tools.
        first = messages[0] if messages else {}
        if first.get("role") in ("system", "developer") and isinstance(first.get("content"), str):
            first["content"] = (first["content"] + "\n\n" if first["content"] else "") + NO_TOOLS
        elif first.get("role") in ("system", "developer") and isinstance(first.get("content"), list):
            first["content"] = [*first["content"], {"type": "text", "text": NO_TOOLS}]
        else:
            messages.insert(0, {"role": "system", "content": NO_TOOLS})
    body["messages"] = messages
    return capped(body)


def tool_sizes(payload):
    """(count, bytes) of the request's tool definitions, measured as Yougori's model server measures
    them: the length of the list as JSON."""
    tools = payload.get("tools")
    return (len(tools), len(json.dumps(tools))) if isinstance(tools, list) else (0, 0)


def too_large(error, payload):
    """Whether a refusal is of the request's size: a Yougori model server's own limit on its tools,
    conversation, messages, body or reply length. One exception: a refusal of tools that are within
    the number that server takes says its runner calls no tools at all."""
    if error.code != REQUEST_LIMIT:
        return False
    most = TOOL_COUNT.search(str(error))
    return not (most and tool_sizes(payload)[0] <= int(most.group(1)))


def explained(error, payload):
    """A size refusal of a request with tools, with what the request sent, so a person sees what to
    cut: an agent believes it has the tools it sent, and the model would see none of them."""
    count, size = tool_sizes(payload)
    if not count:
        return error
    messages = len(payload["messages"])
    return UpstreamError(f"{str(error).rstrip('. ')}. This request sent {count} tool definition{'s' * (count != 1)} "
                         f"({size:,} bytes) and {messages} message{'s' * (messages != 1)}. Nothing reached the model.",
                         error.status, error.code)


def refusal(connection, response, secret=""):
    """A model server's refusal (400) as an UpstreamError, its connection closed. It keeps the
    server's own words, as a contributing computer's refusal does (compute.py): its error message
    on one line of printable ASCII, at most 300 characters, and its code when that is a lower-case
    name. The server's key (`secret`) never passes, should the server echo it. The relay's own words
    (REFUSED) only when the server gave none."""
    try:
        raw = response.read(65536)
    except (OSError, http.client.HTTPException):
        raw = b""
    finally:
        response.close()
        connection.close()
    try:
        value = json.loads(raw)
    except ValueError:
        value = None
    # {"error": {"message", "code"}} as OpenAI and Yougori write it, {"error": "..."}, or the
    # message at the top as older vLLM writes it.
    detail = value.get("error", value) if isinstance(value, dict) else None
    detail = {"message": detail} if isinstance(detail, str) else detail if isinstance(detail, dict) else {}
    message = re.sub(r"[^ -~]", "", " ".join(str(detail.get("message") or "").split()))
    message = (message.replace(secret, "[hidden]") if secret else message)[:300].strip()
    code = str(detail.get("code", ""))
    return UpstreamError(message or REFUSED, 400, code if re.fullmatch(r"[a-z_]{1,40}", code) else "")


def dispatch(service, order, payload, session):
    """Opens the first replica in `order` that answers, with a chat that has no user message sent
    with its instructions as the user's (asked()). A replica that could not take the request is
    skipped before anything reaches the caller. A refusal (400) is tried on the other replicas
    too, since replicas of one name can differ in context length; it never counts against a
    replica. When every replica refuses, the request goes again to those that refused it. First,
    when its reply limit may be what was refused, it goes with a reply limit of at most
    REPLY_TOKENS and its tools kept. Then, when plain chat changes it, it goes once as plain chat
    (plain()), which tells the model that no tools are available and that nothing it writes runs.
    Plain chat follows every refusal but two: a Yougori model server's refusal of the request's
    size (its limit on tools, conversation, messages, reply length or body) and a refusal of a
    conversation too long for the context. Those two are the caller's answer, in words that say
    what was too large. Any other refusal may mean that the model's server takes no tools, but
    need not: a refusal without a Yougori code can come from any server for any reason, and a
    Yougori refusal of tools within the number it takes says that its runner calls none. The last
    refusal is the caller's answer, in the server's own words (refusal())."""
    payload = asked(payload)
    last, refused, relaxed = None, [], False
    while True:
        for replica in order:
            service.router.begin(replica["id"])
            try:
                body = {**payload, "model": replica["upstream"]}
                if replica["url"].startswith("compute://"):
                    if relaxed:
                        # Yougori's model server drops the oldest turns of a long chat instead of refusing it.
                        body["truncate"] = True
                    connection, response = service.compute.connect(replica["url"], body)
                else:
                    connection, response = connect(replica["url"], replica["secret"], "/chat/completions", body, timeout=120,
                                                   expect=(200, 400))
                    if response.status == 400:
                        raise refusal(connection, response, replica["secret"])
            except UpstreamError as error:
                service.router.end(replica["id"], failed=error.status != 400, cool=error.status not in (400, 429))
                if error.status == 400:
                    refused.append(replica)
                if error.status == 400 or last is None or last.status != 400:
                    last = error
                continue
            except BaseException:
                service.router.end(replica["id"], failed=True)
                raise
            service.router.remember(session, replica, replica["same"])
            return connection, response, replica
        if relaxed or not refused or last.code == CONTEXT_WINDOW:
            break
        shorter = capped(payload)
        # A Yougori model server names its limit; any other server's refusal may be the reply limit.
        if shorter is not payload and (last.code != REQUEST_LIMIT or "max_tokens" in str(last)):
            payload, order, refused = shorter, refused, []
            continue
        if too_large(last, payload):
            last = explained(last, payload)
            break
        simpler = plain(payload)
        if simpler == payload:
            break
        payload, order, refused, relaxed = simpler, refused, [], True
    raise last or UpstreamError("The model server is not currently available.", 503)


def read_stream(response, answering):
    """The chunks of an upstream event stream, each a dict, until its [DONE]. The stream must
    finish within the service limits and may not carry an error or end early."""
    total = 0
    while True:
        if time.time() - answering > 240:
            raise UpstreamError('The request exceeded the service time limit.', 504)
        line = response.readline(1024 * 1024 + 1)
        if not line:
            raise UpstreamError("The model stream ended before completion.", 502)
        total += len(line)
        if len(line) > 1024 * 1024 or total > 16 * 1024 * 1024:
            raise UpstreamError("The model response exceeded the service limit.", 502)
        if not line.startswith(b"data:"):
            continue
        data = line[5:].strip()
        if data == b"[DONE]":
            return
        chunk = json.loads(data)
        if not isinstance(chunk, dict) or "error" in chunk:
            raise UpstreamError("The model server could not finish the response.", 502)
        yield chunk


def assemble(chunks, model):
    """One chat completion from a stream's chunks: the first choice's text fields joined, its
    tool calls merged by index, the last finish reason and the final usage and timings."""
    message, calls, finish, usage, timings, identity, created = {"role": "assistant", "content": None}, {}, None, None, None, None, None
    for chunk in chunks:
        if isinstance(chunk.get("usage"), dict):
            usage = chunk["usage"]
        if isinstance(chunk.get("timings"), dict):
            timings = chunk["timings"]
        identity, created = chunk.get("id", identity), chunk.get("created", created)
        for choice in chunk.get("choices") or []:
            if not isinstance(choice, dict) or choice.get("index", 0) != 0:
                continue
            if choice.get("finish_reason"):
                finish = choice["finish_reason"]
            delta = choice.get("delta") if isinstance(choice.get("delta"), dict) else {}
            for field, value in delta.items():
                if field == "tool_calls" and isinstance(value, list):
                    for call in value:
                        if not isinstance(call, dict) or type(call.get("index")) is not int:
                            continue
                        entry = calls.setdefault(call["index"], {"id": None, "type": "function", "function": {"name": "", "arguments": ""}})
                        if isinstance(call.get("id"), str):
                            entry["id"] = call["id"]
                        function = call.get("function") if isinstance(call.get("function"), dict) else {}
                        for part in ("name", "arguments"):
                            if isinstance(function.get(part), str):
                                entry["function"][part] += function[part]
                elif field == "role":
                    message["role"] = value if isinstance(value, str) else message["role"]
                elif isinstance(value, str):
                    message[field] = (message.get(field) or "") + value  # content, reasoning_content, refusal
                elif value is not None and message.get(field) is None:
                    message[field] = value
    if calls:
        message["tool_calls"] = [calls[index] for index in sorted(calls)]
    return {"id": identity if isinstance(identity, str) else "chatcmpl-" + secrets.token_hex(12), "object": "chat.completion",
            "created": created if type(created) is int else int(time.time()), "model": model,
            "choices": [{"index": 0, "message": message, "finish_reason": finish or "stop", "logprobs": None}],
            **({"usage": usage} if usage else {}), **({"timings": timings} if timings else {})}


def complete(handler, key, payload):
    service = handler.server.service
    model = payload.get("model")
    if not isinstance(model, str) or not model or ("*" not in key["scopes"] and model not in key["scopes"]):
        return handler.error(403, "This API key cannot use that model.")
    messages = payload.get("messages")
    if not isinstance(messages, list) or not messages or len(messages) > 1000 or any(not isinstance(m, dict) for m in messages):
        return handler.error(400, "Provide a nonempty messages array.")
    if type(payload.get("stream", False)) is not bool:
        return handler.error(400, "stream must be true or false.")
    if payload.get("n", 1) != 1:
        return handler.error(400, "This endpoint supports one completion per request.")
    for name in ("max_tokens", "max_completion_tokens"):
        if name in payload and (type(payload[name]) is not int or not 1 <= payload[name] <= 131072):
            return handler.error(400, name + " must be an integer from 1 to 131072.")
    session = routing.session_key(key, payload, handler.headers)
    replicas = service.router.replicas(service.store, model)
    if not replicas:
        return handler.error(404, "This model is no longer in the catalog.")
    # A media model (its server generates images, video or sound) takes jobs, not conversation.
    chat = service.router.chat_replicas(replicas)
    if not chat:
        return handler.json(404, {"error": {"code": "task_mismatch", "message": "This model generates " + str(replicas[0].get("task")) + "; use /v1/jobs, or the images, audio/speech or videos endpoint."}})
    replicas = chat
    # A JSON reply format (OpenAI's response_format) goes only to a replica whose server enforces
    # it, so a caller never gets free text where it asked for a schema. The format itself is
    # passed through as given; the model server checks its shape.
    wanted = payload.get("response_format")
    if isinstance(wanted, dict) and wanted.get("type") in ("json_object", "json_schema"):
        replicas = service.router.enforcing_json(replicas)
        if not replicas:
            return handler.error(400, "No connected server of this model enforces JSON output (response_format). Serve it with vLLM or llama.cpp.")
    order = service.router.order(replicas, session)
    if not order:
        # A model a computer is still downloading or loading answers once it has loaded: the
        # caller learns that at once, with how far it has got, rather than after a time limit.
        now = time.time()
        starting = next((r for r in replicas if r["state"] == "loading" and r["checked"] > now - routing.FRESH_SECONDS), None)
        if starting:
            return handler.error(503, f"{model} is still {starting.get('detail') or 'starting its model server'} on the computer that serves it. "
                                      "It answers once it has loaded; try again then.")
        return handler.error(503, "The model server is not currently available.")
    if not service.inference_slots.acquire(blocking=False):
        return handler.error(429, "This service is at capacity. Retry shortly.", retry=True)
    request_id, started, status, usage, timings = secrets.token_hex(16), time.time(), "failed", None, None
    connection = response = replica = None
    sent = False
    try:
        if not service.payments.reserve(key['user_id'],model,request_id,payload):
            return handler.error(402, service.payments.refusal(key['user_id'], model))
        service.control.presence(key['user_id'],api=True)
        with service.control.lock:
            service.control.active.add(request_id)
        options = payload.get('stream_options', {})
        if not isinstance(options, dict):
            return handler.error(400, 'stream_options must be an object.')
        # The model server always streams, with its usage in the last chunk: a caller who asked
        # for a stream gets it as it comes; the others get the completion assembled from it, so
        # a long answer is cut off only when the model stalls, not by the socket's timeout.
        streaming = payload.get("stream") is True
        payload = {**payload, "stream": True, "stream_options": {**options, "include_usage": True}}
        connection, response, replica = dispatch(service, order, payload, session)
        # The reply's time limit starts when a replica answers, after any failed replicas and queue time.
        answering = time.time()
        if "text/event-stream" not in response.getheader("Content-Type", "").lower():
            raise UpstreamError("The model server did not return an event stream.", 502)
        if streaming:
            handler.begin(200, "text/event-stream; charset=utf-8")
            sent = True
            for chunk in read_stream(response, answering):
                if "model" in chunk:
                    chunk["model"] = model
                if isinstance(chunk.get("usage"), dict):
                    usage = chunk["usage"]
                if isinstance(chunk.get("timings"), dict):
                    timings = chunk["timings"]
                handler.wfile.write(b"data: " + json.dumps(chunk, allow_nan=False).encode() + b"\n\n")
                handler.wfile.flush()
            handler.wfile.write(b"data: [DONE]\n\n")
            handler.wfile.flush()
        else:
            result = assemble(read_stream(response, answering), model)
            usage, timings = result.get("usage"), result.get("timings")
            handler.json(200, result)
        status = "completed"
    except (BrokenPipeError, ConnectionResetError):
        status = "cancelled"
    except (UpstreamError, OSError, ValueError, http.client.HTTPException) as error:
        message = str(error) if isinstance(error, UpstreamError) else "The model server returned an incomplete response."
        if sent:
            try:
                handler.wfile.write(b"event: error\ndata: " + json.dumps({"error": {"message": message}}).encode() + b"\n\n")
                handler.wfile.flush()
            except OSError:
                status = "cancelled"
        else:
            handler.error(error.status if isinstance(error, UpstreamError) else 502, message)
    finally:
        with service.control.lock:
            service.control.active.discard(request_id)
        if response is not None:
            # A stream ends at [DONE], before the end of the body: a closing server's socket
            # belongs to the response, so it is closed here as well as the connection.
            response.close()
        if connection:
            connection.close()
        if replica:
            service.router.end(replica["id"])
        service.inference_slots.release()
        cached = routing.cached_tokens(usage, timings)
        service.payments.finish(request_id,status == 'completed',usage,cached=cached,
            record=lambda db:service.store.request_done(request_id,key,model,started,status,usage,db=db,replica=replica,cached=cached))
