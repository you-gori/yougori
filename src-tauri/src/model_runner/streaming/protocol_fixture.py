"""Disposable real HTTP relay; only preparation and inference are synthetic."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
from unittest.mock import Mock


def main():
    ready, cache = map(Path, sys.argv[1:])
    os.environ.update(YOUGORI_MODEL="fixture/model", YOUGORI_MODEL_TOKEN="fixture-model-token",
                      YOUGORI_MODEL_FORMAT="gguf", YOUGORI_GPU_OPTIMIZER="0", HF_HOME=str(cache))
    source = Path(__file__).resolve().parents[2] / "model_server.py"
    spec = importlib.util.spec_from_file_location("serving_fixture_runner", source)
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)
    model.NETWORK = object()
    model.STATE.update(status="ready")
    model.prepare_gguf = lambda messages, *args: (messages, 1, 0)

    def inference(path, body, **kwargs):
        if body.get("tools"):
            pieces = [{"tool_calls": [{"index": 0, "id": "fixture-call", "type": "function",
                       "function": {"name": "lookup", "arguments": '{"id":'}}]},
                      {"tool_calls": [{"index": 0, "function": {"arguments": "1}"}}]}]
            reason = "tool_calls"
        else:
            pieces, reason = [{"content": "fixture output"}], "stop"
        if not body.get("stream"):
            message = {"role": "assistant", "content": "fixture output"}
            if body.get("tools"):
                message["tool_calls"] = [{"id": "fixture-call", "type": "function",
                    "function": {"name": "lookup", "arguments": '{"id":1}'}}]
            if body["messages"][0].get("content") == "fixture-truncated": reason = "length"
            if body["messages"][0].get("content") == "fixture-invalid":
                message["tool_calls"][0]["function"]["arguments"] = '{"id":"invalid"}'
            payload = {"choices": [{"index": 0, "message": message, "finish_reason": reason}],
                       "usage": {"completion_tokens": 2}}
            return Mock(), Mock(status=200, read=Mock(return_value=json.dumps(payload).encode()))
        frames = [{"choices": [{"index": 0, "delta": piece, "finish_reason": None}]} for piece in pieces]
        frames.append({"choices": [{"index": 0, "delta": {}, "finish_reason": reason}],
                       "usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}})
        lines = [b"data: " + json.dumps(frame).encode() + b"\n" for frame in frames]
        return Mock(), Mock(status=200, readline=Mock(side_effect=[*lines, b"data: [DONE]\n"]))

    model.llama = inference
    server = model.Server(("127.0.0.1", 0), model.Handler)
    worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    worker.start()
    ready.write_text(json.dumps({"port": server.server_port}), encoding="utf-8")
    try:
        sys.stdin.read()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(2)


if __name__ == "__main__":
    main()
