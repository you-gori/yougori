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
    is skipped before anything reaches the caller; a refused request (400) is not retried."""
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
            if error.status == 400:
                raise
            last = error
            continue
        except BaseException:
            service.router.end(replica["id"], failed=True)
            raise
        service.router.remember(session, replica, replica["same"])
        return connection, response, replica
    raise last or UpstreamError("The model server is not currently available.", 503)


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
        if payload.get('stream'):
            options=payload.get('stream_options',{})
            if not isinstance(options,dict):
                return handler.error(400,'stream_options must be an object.')
            payload['stream_options']={**options,'include_usage':True}
        connection, response, replica = dispatch(service, order, payload, session)
        if payload.get("stream"):
            if "text/event-stream" not in response.getheader("Content-Type", "").lower():
                raise UpstreamError("The model server did not return an event stream.", 502)
            handler.begin(200, "text/event-stream; charset=utf-8")
            sent, total, finished = True, 0, False
            while True:
                if time.time() - started > 240:
                    raise UpstreamError('The request exceeded the service time limit.', 504)
                line = response.readline(1024 * 1024 + 1)
                if not line:
                    break
                total += len(line)
                if len(line) > 1024 * 1024 or total > 16 * 1024 * 1024:
                    raise UpstreamError("The model response exceeded the service limit.", 502)
                if line.startswith(b"data:"):
                    data = line[5:].strip()
                    if data == b"[DONE]":
                        finished = True
                    else:
                        chunk = json.loads(data)
                        if not isinstance(chunk, dict) or "error" in chunk:
                            raise UpstreamError("The model server could not finish the response.", 502)
                        if "model" in chunk:
                            chunk["model"] = model
                        if isinstance(chunk.get("usage"), dict):
                            usage = chunk["usage"]
                        if isinstance(chunk.get("timings"), dict):
                            timings = chunk["timings"]
                        line = b"data: " + json.dumps(chunk, allow_nan=False).encode() + b"\n"
                handler.wfile.write(line)
                handler.wfile.flush()
                if finished:
                    handler.wfile.write(b"\n")
                    handler.wfile.flush()
                    break
            if not finished:
                raise UpstreamError("The model stream ended before completion.", 502)
        else:
            raw = response.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise UpstreamError("The model response exceeded the service limit.", 502)
            result = json.loads(raw)
            if not isinstance(result, dict) or not isinstance(result.get("choices"), list) or "error" in result:
                raise UpstreamError("The model server returned an invalid completion.", 502)
            result["model"] = model
            usage = result.get("usage") if isinstance(result.get("usage"), dict) else None
            timings = result.get("timings") if isinstance(result.get("timings"), dict) else None
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
