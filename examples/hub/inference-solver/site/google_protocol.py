"""Gemini CLI text/function adapter; uses the same auth, scope and usage relay."""
import json
import re
from urllib.parse import unquote, urlsplit

import gateway
import routing


def route(target):
    p = urlsplit(target)
    if p.scheme or p.netloc or p.fragment or p.query not in ("", "alt=sse"):
        return None
    match = re.fullmatch(r"/v1(?:beta)?/models/(.+):(generateContent|streamGenerateContent)", p.path)
    if not match:
        return None
    model = unquote(match[1])
    if not model or len(model) > 512 or any(ord(c) < 32 for c in model):
        return None
    return model, match[2] == "streamGenerateContent"


def schema(value):
    if isinstance(value, list):
        return [schema(v) for v in value]
    if not isinstance(value, dict):
        return value
    return {k: v.lower() if k == "type" and isinstance(v, str) else schema(v) for k, v in value.items()}


def convert(data, model):
    messages, pending, serial = [], {}, 0
    if data.get("systemInstruction"):
        parts = data["systemInstruction"].get("parts", [])
        if any(set(p) != {"text"} for p in parts):
            raise ValueError("System instructions must be text.")
        messages.append({"role": "system", "content": "\n".join(p["text"] for p in parts)})
    for item in data.get("contents", []):
        role = item.get("role", "user")
        if role not in ("user", "model"):
            raise ValueError("Unsupported Gemini role.")
        texts, calls, outputs = [], [], []
        for part in item.get("parts", []):
            if "text" in part:
                texts.append(part["text"])
            elif "functionCall" in part and role == "model":
                call = part["functionCall"]
                serial += 1
                identity = call.get("id") or "gemini_call_" + str(serial)
                pending.setdefault(call["name"], []).append(identity)
                calls.append({"id": identity, "type": "function", "function": {"name": call["name"], "arguments": json.dumps(call.get("args", {}))}})
            elif "functionResponse" in part and role == "user":
                response = part["functionResponse"]
                ids = pending.get(response["name"], [])
                identity = response.get("id") or (ids.pop(0) if ids else None)
                if not identity:
                    raise ValueError("Function response has no preceding call.")
                outputs.append({"role": "tool", "tool_call_id": identity, "content": json.dumps(response.get("response", {}))})
            else:
                raise ValueError("This Gemini adapter supports text and function tools only.")
        messages.extend(outputs)
        if texts or calls:
            message = {"role": "assistant" if role == "model" else "user", "content": "\n".join(texts) or None}
            if calls:
                message["tool_calls"] = calls
            messages.append(message)
    payload = {"model": model, "messages": messages, "stream": False}
    tools = []
    for group in data.get("tools", []):
        if any(k != "functionDeclarations" for k in group):
            raise ValueError("Hosted search and execution tools are disabled.")
        for function in group.get("functionDeclarations", []):
            tools.append({"type": "function", "function": {"name": function["name"],
                "description": function.get("description", ""), "parameters": schema(function.get("parametersJsonSchema", function.get("parameters", {"type": "object", "properties": {}})))}})
    if tools:
        payload["tools"] = tools
    config = data.get("generationConfig", {})
    for source, dest in (("temperature", "temperature"), ("topP", "top_p"), ("maxOutputTokens", "max_tokens"), ("stopSequences", "stop")):
        if source in config:
            payload[dest] = config[source]
    return payload


class Output:
    def __init__(self, handler, model, stream):
        self.handler, self.model, self.stream, self.server = handler, model, stream, handler.server
        self.headers = handler.headers

    def error(self, *args, **kwargs):
        return self.handler.error(*args, **kwargs)

    def json(self, status, value):
        choice = value["choices"][0]
        message, parts = choice["message"], []
        if message.get("content"):
            parts.append({"text": message["content"]})
        for tool in message.get("tool_calls", []):
            parts.append({"functionCall": {"id": tool["id"], "name": tool["function"]["name"], "args": json.loads(tool["function"]["arguments"])}})
        result = {"candidates": [{"content": {"role": "model", "parts": parts}, "index": 0,
                                 "finishReason": "MAX_TOKENS" if choice.get("finish_reason") == "length" else "STOP"}], "modelVersion": self.model}
        usage = value.get("usage")
        if usage:
            cached = routing.cached_tokens(usage, value.get("timings"))
            result["usageMetadata"] = {"promptTokenCount": usage["prompt_tokens"], "candidatesTokenCount": usage["completion_tokens"],
                "totalTokenCount": usage["prompt_tokens"] + usage["completion_tokens"],
                **({"cachedContentTokenCount": cached} if cached is not None else {})}
        if self.stream:
            self.handler.begin(200, "text/event-stream; charset=utf-8")
            self.handler.wfile.write(("data: " + json.dumps(result) + "\n\n").encode())
            self.handler.wfile.flush()
        else:
            self.handler.json(status, result)


def complete(handler, key, data, model, stream):
    try:
        payload = convert(data, model)
    except ValueError as error:
        return handler.error(400, str(error))
    except (TypeError, KeyError, AttributeError):
        return handler.error(400, "Invalid Gemini text/function request structure.")
    return gateway.complete(Output(handler, model, stream), key, payload)
