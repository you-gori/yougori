"""Private Chat Completions relay. Authentication and model scopes apply before I/O.

A request names a model; the router picks which of that model's replicas serves it (routing.py).
"""
import http.client
import json
import secrets
import time

import routing
from upstream import UpstreamError, connect


def dispatch(service, order, payload, session):
    """Opens the first replica in `order` that answers. A replica that could not take the request
    is skipped before anything reaches the caller. A refusal (400) is tried on the other replicas
    too, since replicas of one name can differ in context length; it is the caller's answer only
    when every replica refuses, and it never counts against a replica."""
    last = None
    for replica in order:
        service.router.begin(replica["id"])
        try:
            body = {**payload, "model": replica["upstream"]}
            if replica["url"].startswith("compute://"):
                connection, response = service.compute.connect(replica["url"], body)
            else:
                connection, response = connect(replica["url"], replica["secret"], "/chat/completions", body, timeout=120)
        except UpstreamError as error:
            service.router.end(replica["id"], failed=error.status != 400, cool=error.status not in (400, 429))
            if error.status == 400 or last is None or last.status != 400:
                last = error
            continue
        except BaseException:
            service.router.end(replica["id"], failed=True)
            raise
        service.router.remember(session, replica, replica["same"])
        return connection, response, replica
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
    order = service.router.order(replicas, session)
    if not order:
        return handler.error(503, "The model server is not currently available.")
    if not service.inference_slots.acquire(blocking=False):
        return handler.error(429, "This service is at capacity. Retry shortly.", retry=True)
    request_id, started, status, usage, timings = secrets.token_hex(16), time.time(), "failed", None, None
    connection = response = replica = None
    sent = False
    try:
        if not service.payments.reserve(key['user_id'],model,request_id,payload):
            return handler.error(402, 'Balance is below the temporary request reservation. Top up in Usage or lower the output token limit.')
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
