"""Terminal companion for the official HexStrike MCP server, inside a Sandbox VM."""
import argparse
import asyncio
import json
import os
from pathlib import Path
import subprocess
import socket
import sys
import time
import urllib.request

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


def completion(model, messages, tools):
    request = urllib.request.Request("http://127.0.0.1:8080/v1/chat/completions",
        data=json.dumps({"model":model,"messages":messages,"tools":tools,"stream":False}).encode(),
        headers={"Authorization":"Bearer solver-local-relay","Content-Type":"application/json"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request,timeout=180) as response:
        raw = response.read(4*1024*1024+1)
    if len(raw)>4*1024*1024:
        raise ValueError("Model response exceeded the size limit.")
    return json.loads(raw)["choices"][0]["message"]


async def chat(args):
    source = Path("/opt/solver/source")
    with (Path.home()/"hexstrike-server.log").open("w") as log:
        server = subprocess.Popen([sys.executable,str(source/"hexstrike_server.py"),"--port","8888"],stdout=log,stderr=log)
        try:
            for _ in range(60):
                if server.poll() is not None:
                    raise ValueError("HexStrike server stopped. See ~/hexstrike-server.log inside the VM.")
                try:
                    with socket.create_connection(("127.0.0.1",8888),timeout=1):
                        break
                except OSError: time.sleep(.25)
            else: raise ValueError("HexStrike did not become ready.")
            params = StdioServerParameters(command=sys.executable,args=[str(source/"hexstrike_mcp.py"),"--server","http://127.0.0.1:8888"],env=dict(os.environ))
            async with stdio_client(params) as (read,write):
                async with ClientSession(read,write) as session:
                    await session.initialize()
                    listed = await session.list_tools()
                    tools = [{"type":"function","function":{"name":t.name,"description":(t.description or "")[:3000],"parameters":t.inputSchema}} for t in listed.tools]
                    if args.list_tools:
                        print("\n".join(t.name for t in listed.tools)); return
                    messages = [{"role":"system","content":"You are the HexStrike terminal companion. Use the available tools only on the user's authorized workspace inside this VM. External networking is unavailable. Never claim a tool ran if it returned an error."}]
                    print("HexStrike · Inference Solver · /exit to leave",flush=True)
                    while True:
                        prompt = args.prompt or await asyncio.to_thread(input,"hexstrike > ")
                        if prompt.strip() in ("/exit","/quit"): return
                        messages.append({"role":"user","content":prompt})
                        for _ in range(24):
                            reply = await asyncio.to_thread(completion,args.model,messages,tools)
                            messages.append(reply)
                            if reply.get("content"): print(reply["content"],flush=True)
                            calls = reply.get("tool_calls") or []
                            if not calls: break
                            if len(calls)>8: raise ValueError("Too many tool calls in one response.")
                            for call in calls:
                                name = call["function"]["name"]
                                if name not in {t.name for t in listed.tools}: raise ValueError("The model requested an unknown tool.")
                                arguments = json.loads(call["function"]["arguments"])
                                print("Running " + name,flush=True)
                                result = await asyncio.wait_for(session.call_tool(name,arguments),timeout=120)
                                messages.append({"role":"tool","tool_call_id":call["id"],"content":result.model_dump_json()[:48000]})
                        else: print("Stopped after 24 tool rounds. Enter another instruction to continue.",flush=True)
                        if args.prompt: return
        finally:
            server.terminate()
            try: server.wait(timeout=5)
            except subprocess.TimeoutExpired: server.kill(); server.wait()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HexStrike MCP terminal, using only Inference Solver.")
    parser.add_argument("--model",required=True)
    parser.add_argument("--print",dest="prompt")
    parser.add_argument("--list-tools",action="store_true")
    asyncio.run(chat(parser.parse_args()))
