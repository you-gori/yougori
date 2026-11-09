"""Stateless text/tool adapters to the same authenticated Chat Completions relay.

Converted streams emit protocol events after the upstream completion finishes;
they are buffered, not native token streaming. Unsupported features fail closed.
"""
import json
import hashlib
import secrets
import time

import gateway
import routing


def tool_name(name, namespace=None):
    if not isinstance(name, str) or not name:
        raise ValueError("Invalid tool name.")
    return "ns_" + hashlib.sha256((namespace + "\0" + name).encode()).hexdigest()[:48] if namespace else name


def response_tools(data):
    tools, names = [], {}
    for group in data.get("tools", []):
        namespace = group.get("name") if group.get("type") == "namespace" else None
        for entry in group.get("tools", []) if namespace else [group]:
            if entry.get("type") != "function":
                raise ValueError("This adapter supports function tools and function namespaces only.")
            name = tool_name(entry["name"], namespace)
            if name in names:
                raise ValueError("Duplicate tool name.")
            names[name] = {"name": entry["name"], **({"namespace": namespace} if namespace else {})}
            tools.append({"type": "function", "function": {"name": name, "description": entry.get("description", ""),
                "parameters": entry.get("parameters", {"type": "object", "properties": {}})}})
    return tools, names


def text_content(value):
    if isinstance(value, str):
        return value
    if isinstance(value, list):
        if any(not isinstance(p, dict) or p.get("type") not in ("text", "input_text", "output_text") or not isinstance(p.get("text"), str) for p in value):
            raise ValueError("This adapter supports text and function tools; media is not enabled.")
        return "\n".join(p["text"] for p in value)
    raise ValueError("Invalid text content.")


def from_responses(data):
    if data.get("previous_response_id") or data.get("background"):
        raise ValueError("Send full stateless history; stored/background responses are not supported.")
    messages = []
    if data.get("instructions"):
        messages.append({"role": "system", "content": text_content(data["instructions"])})
    items = data.get("input", [])
    if isinstance(items, str):
        items = [{"role": "user", "content": items}]
    if not isinstance(items, list):
        raise ValueError("input must be text or a message list.")
    for item in items:
        kind = item.get("type", "message")
        if kind == "message":
            role = item.get("role", "user")
            if role not in ("user", "assistant", "system", "developer"):
                raise ValueError("Unsupported message role.")
            messages.append({"role": role, "content": text_content(item.get("content", ""))})
        elif kind == "function_call":
            messages.append({"role": "assistant", "content": None, "tool_calls": [{"id": item["call_id"], "type": "function",
                             "function": {"name": tool_name(item["name"], item.get("namespace")), "arguments": item["arguments"]}}]})
        elif kind == "function_call_output":
            messages.append({"role": "tool", "tool_call_id": item["call_id"], "content": text_content(item["output"])})
        else:
            raise ValueError("Unsupported Responses input item: " + str(kind)[:50])
    result = {"model": data.get("model"), "messages": messages, "stream": False}
    # Codex names its conversation here; the router keeps the conversation on one computer.
    if isinstance(data.get("prompt_cache_key"), str):
        result["prompt_cache_key"] = data["prompt_cache_key"]
    if data.get("tools"):
        result["tools"] = response_tools(data)[0]
    for field in ("temperature", "top_p", "parallel_tool_calls"):
        if field in data:
            result[field] = data[field]
    if "max_output_tokens" in data:
        result["max_tokens"] = data["max_output_tokens"]
    choice = data.get("tool_choice")
    if choice:
        result["tool_choice"] = {"type": "function", "function": {"name": tool_name(choice["name"], choice.get("namespace"))}} if isinstance(choice, dict) else choice
    # The Responses API asks for JSON in text.format; Chat Completions calls it response_format.
    text = data.get("text")
    layout = text.get("format") if isinstance(text, dict) else None
    if isinstance(layout, dict) and layout.get("type") == "json_schema":
        result["response_format"] = {"type": "json_schema", "json_schema": {field: layout[field] for field in ("name", "schema", "strict", "description") if field in layout}}
    elif isinstance(layout, dict) and layout.get("type") == "json_object":
        result["response_format"] = {"type": "json_object"}
    return result


def from_messages(data):
    if (data.get("thinking") or {}).get("type") not in (None, "disabled"):
        raise ValueError("Extended thinking is not provided by this adapter.")
    messages = []
    if data.get("system"):
        messages.append({"role": "system", "content": text_content(data["system"])})
    for item in data.get("messages", []):
        role, content = item["role"], item["content"]
        if role not in ("user", "assistant", "system", "developer"):
            raise ValueError("Unsupported message role.")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
            continue
        plain, calls, results = [], [], []
        for part in content:
            kind = part.get("type")
            if kind == "text":
                plain.append(part["text"])
            elif kind == "tool_use" and role == "assistant":
                calls.append({"id": part["id"], "type": "function", "function": {"name": part["name"], "arguments": json.dumps(part["input"])}})
            elif kind == "tool_result" and role == "user":
                results.append({"role": "tool", "tool_call_id": part["tool_use_id"], "content": text_content(part.get("content", ""))})
            else:
                raise ValueError("This Messages adapter supports text and function tools only.")
        messages.extend(results)
        if plain or calls:
            message = {"role": role, "content": "\n".join(plain) or None}
            if calls:
                message["tool_calls"] = calls
            messages.append(message)
    result = {"model": data.get("model"), "messages": messages, "stream": False, "max_tokens": data.get("max_tokens", 4096)}
    # Claude Code names its session in metadata.user_id; the router keeps it on one computer.
    if isinstance(data.get("metadata"), dict) and isinstance(data["metadata"].get("user_id"), str):
        result["prompt_cache_key"] = data["metadata"]["user_id"]
    if data.get("tools"):
        if any(t.get("type") not in (None, "custom") for t in data["tools"]):
            raise ValueError("Hosted provider tools are not supported.")
        result["tools"] = [{"type": "function", "function": {"name": t["name"], "description": t.get("description", ""), "parameters": t["input_schema"]}} for t in data["tools"]]
    for field in ("temperature", "top_p"):
        if field in data:
            result[field] = data[field]
    if data.get("stop_sequences"):
        result["stop"] = data["stop_sequences"]
    choice = data.get("tool_choice", {})
    if choice.get("type") == "tool":
        result["tool_choice"] = {"type": "function", "function": {"name": choice["name"]}}
    elif choice.get("type") in ("auto", "any", "none"):
        result["tool_choice"] = "required" if choice["type"] == "any" else choice["type"]
    return result


def response_value(raw, model, kind):
    choice = raw["choices"][0]
    message = choice["message"]
    content = message.get("content") or ""
    if not isinstance(content, str):
        raise ValueError("The server returned non-text content.")
    calls = message.get("tool_calls", [])
    usage = raw.get("usage")
    cached = routing.cached_tokens(usage, raw.get("timings"))
    if kind == "responses":
        output = []
        if content:
            output.append({"id": "msg_" + secrets.token_hex(12), "type": "message", "role": "assistant", "status": "completed",
                           "content": [{"type": "output_text", "text": content, "annotations": []}]})
        for call in calls:
            output.append({"id": "fc_" + secrets.token_hex(12), "type": "function_call", "status": "completed",
                           "call_id": call["id"], "name": call["function"]["name"], "arguments": call["function"]["arguments"]})
        return {"id": "resp_" + secrets.token_hex(12), "object": "response", "created_at": int(time.time()),
                "status": "incomplete" if choice.get("finish_reason") == "length" else "completed", "model": model,
                "output": output, "error": None, "incomplete_details": {"reason": "max_output_tokens"} if choice.get("finish_reason") == "length" else None,
                "usage": {"input_tokens": usage["prompt_tokens"], "output_tokens": usage["completion_tokens"],
                          "total_tokens": usage["prompt_tokens"] + usage["completion_tokens"],
                          **({"input_tokens_details": {"cached_tokens": cached}} if cached is not None else {})} if usage else None}
    if not usage or not all(type(usage.get(k)) is int for k in ("prompt_tokens", "completion_tokens")):
        raise ValueError("Messages requires token usage from the upstream model server.")
    blocks = [{"type": "text", "text": content}] if content else []
    for call in calls:
        blocks.append({"type": "tool_use", "id": call["id"], "name": call["function"]["name"], "input": json.loads(call["function"]["arguments"])})
    # Anthropic counts cache reads apart from input_tokens; together they are the whole prompt.
    counted = {"input_tokens": usage["prompt_tokens"] - cached, "cache_read_input_tokens": cached, "cache_creation_input_tokens": 0} \
        if cached is not None else {"input_tokens": usage["prompt_tokens"]}
    return {"id": "msg_" + secrets.token_hex(12), "type": "message", "role": "assistant", "model": model, "content": blocks,
            "stop_reason": "tool_use" if calls else "max_tokens" if choice.get("finish_reason") == "length" else "end_turn",
            "stop_sequence": None, "usage": {**counted, "output_tokens": usage["completion_tokens"]}}


def events(value, kind):
    if kind == "messages":
        yield "message_start", {"type": "message_start", "message": {**value, "content": [], "stop_reason": None, "usage": {**value["usage"], "output_tokens": 0}}}
        for index, part in enumerate(value["content"]):
            initial = {**part, "text": ""} if part["type"] == "text" else {**part, "input": {}}
            yield "content_block_start", {"type": "content_block_start", "index": index, "content_block": initial}
            delta = {"type": "text_delta", "text": part["text"]} if part["type"] == "text" else {"type": "input_json_delta", "partial_json": json.dumps(part["input"])}
            yield "content_block_delta", {"type": "content_block_delta", "index": index, "delta": delta}
            yield "content_block_stop", {"type": "content_block_stop", "index": index}
        yield "message_delta", {"type": "message_delta", "delta": {"stop_reason": value["stop_reason"], "stop_sequence": None}, "usage": {"output_tokens": value["usage"]["output_tokens"]}}
        yield "message_stop", {"type": "message_stop"}
        return
    pending = {**value, "status": "in_progress", "output": [], "usage": None}
    yield "response.created", {"response": pending}
    yield "response.in_progress", {"response": pending}
    for index, item in enumerate(value["output"]):
        initial = {**item, "status": "in_progress"}
        initial["content" if item["type"] == "message" else "arguments"] = [] if item["type"] == "message" else ""
        yield "response.output_item.added", {"output_index": index, "item": initial}
        base = {"item_id": item["id"], "output_index": index}
        if item["type"] == "message":
            for ci, part in enumerate(item["content"]):
                pos = {**base, "content_index": ci}
                yield "response.content_part.added", {**pos, "part": {**part, "text": ""}}
                yield "response.output_text.delta", {**pos, "delta": part["text"]}
                yield "response.output_text.done", {**pos, "text": part["text"]}
                yield "response.content_part.done", {**pos, "part": part}
        else:
            yield "response.function_call_arguments.delta", {**base, "delta": item["arguments"]}
            yield "response.function_call_arguments.done", {**base, "arguments": item["arguments"]}
        yield "response.output_item.done", {"output_index": index, "item": item}
    yield "response." + value["status"], {"response": value}


class Output:
    def __init__(self, handler, model, kind, stream, names=None):
        self.handler, self.model, self.kind, self.stream = handler, model, kind, stream
        self.names = names or {}
        self.server = handler.server
        self.headers = handler.headers

    def error(self, *args, **kwargs):
        return self.handler.error(*args, **kwargs)

    def json(self, status, raw):
        value = response_value(raw, self.model, self.kind)
        if self.kind == "responses":
            for item in value["output"]:
                if item["type"] == "function_call" and item["name"] in self.names:
                    item.update(self.names[item["name"]])
        if not self.stream:
            return self.handler.json(status, value)
        self.handler.begin(200, "text/event-stream; charset=utf-8")
        for sequence, (event, payload) in enumerate(events(value, self.kind)):
            if self.kind == "responses":
                payload = {"type": event, "sequence_number": sequence, **payload}
            self.handler.wfile.write(("event: " + event + "\ndata: " + json.dumps(payload, allow_nan=False) + "\n\n").encode())
            self.handler.wfile.flush()


def complete(handler, key, data, kind):
    if type(data.get("stream", False)) is not bool:
        return handler.error(400, "stream must be true or false.")
    try:
        payload = from_responses(data) if kind == "responses" else from_messages(data)
        names = response_tools(data)[1] if kind == "responses" else {}
    except ValueError as error:
        return handler.error(400, str(error))
    except (TypeError, KeyError, AttributeError):
        return handler.error(400, "Invalid text/function request structure.")
    return gateway.complete(Output(handler, data.get("model"), kind, data.get("stream", False), names), key, payload)
