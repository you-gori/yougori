"""Two real runner HTTP servers, synthetic weights; never touches the user's GPUs."""
import http.client
import base64
import zlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch


class HttpOptimizerTests(unittest.TestCase):
    def test_demand_switching_active_protection_and_private_control(self):
        with tempfile.TemporaryDirectory() as cache, patch.dict(os.environ, {
            "YOUGORI_MODEL_TOKEN":"synthetic-model-token", "HF_HOME":cache,
            "YOUGORI_GPU_CONTROL_TOKEN":"synthetic-private-control", "YOUGORI_GPU_OPTIMIZER":"1",
            "YOUGORI_GPU_SOURCE":base64.b64encode(zlib.compress(Path(__file__).with_name("model_runner").joinpath("gpu_optimizer.py").read_bytes())).decode(),
            "YOUGORI_PUBLISHER_SOURCE":base64.b64encode(zlib.compress(Path(__file__).with_name("model_runner").joinpath("publisher_artifacts.py").read_bytes())).decode(),
        }):
            modules, servers = [], []
            for name in ("first", "second"):
                os.environ["YOUGORI_MODEL"] = "test/" + name
                spec = importlib.util.spec_from_file_location("synthetic_"+name, Path(__file__).with_name("model_server.py"))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                module.STATE.update(status="ready" if name=="first" else "idle",weightsVerified=True,precision="original")
                module.NETWORK = object() if name=="first" else None
                module.TORCH = None
                def load(target=module):
                    target.gpu_before_load()
                    target.NETWORK=object()
                    target.STATE["status"]="ready"
                    target.gpu_after_load()
                module.load_model=load
                server=module.Server(("127.0.0.1",0),module.Handler)
                threading.Thread(target=server.serve_forever,daemon=True).start()
                modules.append(module); servers.append(server)
            first,second=modules
            entered,finish=threading.Event(),threading.Event()
            def generate(body,handler,meter):
                self.assertTrue(second.GENERATION.acquire(blocking=False))
                try:
                    entered.set()
                    self.assertTrue(finish.wait(5))
                    meter["outcome"]="ok"
                    return 200,{"choices":[{"message":{"content":"Synthetic complete reply"}}]}
                finally: second.GENERATION.release()
            second.generate=generate
            def request(index,path,body=None,control=False):
                connection=http.client.HTTPConnection("127.0.0.1",servers[index].server_port,timeout=10)
                headers={"Authorization":"Bearer synthetic-model-token","Content-Type":"application/json"}
                if control: headers["X-Yougori-GPU-Control"]="synthetic-private-control"
                connection.request("POST" if body is not None else "GET",path,None if body is None else json.dumps(body),headers)
                response=connection.getresponse()
                value=json.loads(response.read()); code=response.status;connection.close()
                return code,value
            result=[]
            thread=threading.Thread(target=lambda:result.append(request(1,"/v1/chat/completions",{"messages":[{"role":"user","content":"Synthetic test"}]})))
            try:
                self.assertEqual(request(1,"/v1/yougori/optimizer",{"action":"grant"})[0],403)
                self.assertFalse(second.GPU_GRANTED.is_set())
                thread.start()
                for _ in range(100):
                    if second.gpu_snapshot()["pending"]: break
                    time.sleep(.01)
                health=request(1,"/health")[1]
                self.assertEqual(health["status"],"queued")
                self.assertGreater(health["optimizer"]["pending"],0)
                self.assertTrue(request(0,"/v1/yougori/optimizer",{"action":"unload"},True)[1]["unloaded"])
                self.assertIsNone(first.NETWORK)
                self.assertEqual(request(1,"/v1/yougori/optimizer",{"action":"grant"},True)[0],200)
                self.assertTrue(entered.wait(5))
                self.assertFalse(request(1,"/v1/yougori/optimizer",{"action":"unload"},True)[1]["unloaded"])
                finish.set();thread.join(5)
                self.assertFalse(thread.is_alive())
                self.assertEqual(result[0][0],200)
                self.assertEqual(result[0][1]["choices"][0]["message"]["content"],"Synthetic complete reply")
                request(1,"/v1/yougori/optimizer",{"action":"configure","enabled":True,"pinned":True},True)
                self.assertFalse(request(1,"/v1/yougori/optimizer",{"action":"unload"},True)[1]["unloaded"])
            finally:
                finish.set()
                if thread.ident: thread.join(5)
                for server in servers: server.shutdown();server.server_close()


if __name__ == "__main__": unittest.main()
