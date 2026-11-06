"""Two real HTTP runners for native integration tests; all model/GPU work is fake."""
import base64
import importlib.util
import json
import os
from pathlib import Path
import sys
import threading
import zlib


def main():
    ready = Path(sys.argv[1])
    source = Path(__file__).resolve().parents[2]
    servers, threads = [], []
    for index in range(2):
        cache = ready.parent / ("cache-" + str(index))
        cache.mkdir()
        os.environ.update(
            YOUGORI_MODEL="fixture/model-" + str(index),
            YOUGORI_MODEL_TOKEN="fixture-model-token",
            YOUGORI_GPU_CONTROL_TOKEN="fixture-control-token",
            YOUGORI_GPU_OPTIMIZER="1",
            YOUGORI_MODEL_FORMAT="gguf", HF_HOME=str(cache),
            YOUGORI_PUBLISHER_SOURCE=base64.b64encode(zlib.compress(
                (source / "model_runner/publisher_artifacts.py").read_bytes())).decode(),
        )
        spec = importlib.util.spec_from_file_location("fixture_runner_" + str(index), source / "model_server.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.STATE.update(status="ready" if index == 0 else "idle",
                            weightsVerified=True, precision="original")
        module.NETWORK = object() if index == 0 else None
        module.TORCH = None

        def load(target=module):
            try:
                target.gpu_before_load()
                with target.GPU_LOCK:
                    target.NETWORK = object()
                    target.STATE["status"] = "ready"
            except Exception:
                target.STATE.update(status="error", error="Synthetic load failed")
            finally:
                target.gpu_after_load()

        def generate(body, handler, meter, target=module):
            if not target.GENERATION.acquire(blocking=False):
                return 429, {"error": {"message": "Synthetic generation busy"}}
            try:
                meter["outcome"] = "ok"
                return 200, {"choices": [{"message": {"content": "synthetic complete reply"}}]}
            finally:
                target.GENERATION.release()

        module.load_model = load
        module.generate = generate
        server = module.Server(("127.0.0.1", 0), module.Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        servers.append(server)
        threads.append(thread)
    ready.write_text(json.dumps({"ports": [server.server_port for server in servers]}), encoding="utf-8")
    try:
        # The owning native test closes stdin on teardown. No control test hook
        # is added to the production HTTP handler or runner module.
        sys.stdin.read()
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(2)


if __name__ == "__main__":
    main()
