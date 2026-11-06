"""Real private timing HTTP protocol, synthetic model only; owned by native tests."""
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
from unittest.mock import Mock


def main():
    ready, cache, session = Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3]
    cache.mkdir(exist_ok=True)
    os.environ.update(YOUGORI_MODEL="fixture/measurement", YOUGORI_MODEL_TOKEN="fixture-model-token",
                      YOUGORI_MODEL_ADMIN_TOKEN="fixture-admin-token", YOUGORI_MEASUREMENT_SESSION=session,
                      YOUGORI_MODEL_FORMAT="gguf", YOUGORI_GPU_OPTIMIZER="0", HF_HOME=str(cache))
    source = Path(__file__).resolve().parents[2] / "model_server.py"
    spec = importlib.util.spec_from_file_location("measurement_fixture_runner", source)
    model = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(model)

    @model.timed_load
    def load():
        model.NETWORK = object()
        model.STATE.update(status="ready", weightsVerified=True, precision="original")
    if len(sys.argv) > 4 and sys.argv[4] == "demand":
        model.STATE["status"] = "idle"
        enter = model.gpu_enter
        def demand_enter(handler):
            # Real request boundaries and GPU admission; only loading is synthetic.
            if model.STATE["status"] != "ready":
                loader = threading.Thread(target=load)
                loader.start(); loader.join(3)
                assert not loader.is_alive()
            return enter(handler)
        model.gpu_enter = demand_enter
    else:
        load()

    # Exercise actual generation-lock admission, buffered reply and flush. Only
    # model preparation/inference are synthetic; no model/runtime is downloaded.
    model.prepare_gguf = lambda *args: ([], 1, 0)
    def inference(*args, **kwargs):
        if args[1].get("stream"):
            # A GGUF runner asks llama.cpp for one alternative: it streams no token entries otherwise.
            assert args[1]["logprobs"] and args[1]["top_logprobs"] == 1
            events = [{"choices": [{"index": 0, "delta": {"content": text},
                       "logprobs": {"content": [{"bytes": list(text.encode())}]}}]}
                      for text in ("fixture", " output")]
            events.extend([{"choices": [{"delta": {}, "finish_reason": "stop"}]},
                           {"choices": [], "usage": {"completion_tokens": 2}}])
            lines = [b"data: " + json.dumps(event).encode() + b"\n" for event in events]
            return Mock(), Mock(status=200, readline=Mock(side_effect=[*lines, b"data: [DONE]\n"]))
        payload = {"choices": [{"index": 0, "message": {"role": "assistant", "content": "synthetic response"}, "finish_reason": "stop"}]}
        return Mock(), Mock(status=200, read=Mock(return_value=json.dumps(payload).encode()))
    model.llama = inference
    server = model.Server(("127.0.0.1", 0), model.Handler)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": .01}, daemon=True)
    thread.start()
    ready.write_text(json.dumps({"port": server.server_port}), encoding="utf-8")
    try:
        sys.stdin.read()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


if __name__ == "__main__":
    main()
