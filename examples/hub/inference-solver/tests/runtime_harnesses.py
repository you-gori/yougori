"""Opt-in real Yougori VM/CLI validation against a disposable HTTP model fixture.

This tests actual clients and network isolation, not model quality or a GPU.
Run: python -I -B tests/runtime_harnesses.py pi --root SCRATCH
"""
import argparse
import json
import os
import re
import secrets
from pathlib import Path
import subprocess
import sys
import tempfile
import threading

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from test_service import Flow, Model, UPSTREAM_KEY
sys.path.insert(0, str(HERE.parent / "site/harnesses"))
import solver
import protocols


class TextModel(Model):
    def do_POST(self):
        assert self.headers.get("Authorization") == "Bearer " + UPSTREAM_KEY
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.calls.append(data)
        if getattr(self.server, 'harness', '') in ('pi', 'shannon'):
            # These clients used to pass this permissive fixture while sending
            # OpenAI-only fields and an output budget rejected by the real runner.
            allowed = {'model', 'messages', 'max_tokens', 'max_completion_tokens',
                       'temperature', 'stream', 'stream_options', 'tools', 'tool_choice',
                       'parallel_tool_calls', 'top_p', 'stop'}
            self.server.contract_checked = not (set(data) - allowed) and 1 <= data.get('max_tokens', 0) <= 4096
            if not self.server.contract_checked:
                return self.reply(400, {'error': {'message': 'Request is outside the local chat contract.'}})
        names=tuple(t.get('function',{}).get('name',t.get('type')) for t in data.get('tools',[]))
        seen=getattr(self.server,'tool_sets',set())
        if names not in seen:
            seen.add(names);self.server.tool_sets=seen
            print('Client tools:',names,flush=True)
        usage = {"prompt_tokens": 12, "completion_tokens": 2, "total_tokens": 14}
        complete_tool = next((t["function"] for t in data.get("tools", []) if t.get("function", {}).get("name", "").endswith(("attempt_completion", "submit_and_exit", "submit", "finish_scan"))), None)
        completed = complete_tool["name"] if complete_tool else None
        content = {"role": "assistant", "content": "SOLVER_OK"}
        if getattr(self.server,"harness","") == "hexstrike":
            results = [m for m in data["messages"] if m.get("role") == "tool"]
            if not results:
                completed = "create_file"
                content = {"role":"assistant","content":None,"tool_calls":[{"id":"fixture-file","type":"function",
                    "function":{"name":"create_file","arguments":json.dumps({"filename":"solver-check.txt","content":"SOLVER_OK"})}}]}
            else:
                mcp = json.loads(results[-1]["content"])
                value = json.loads(next(c["text"] for c in mcp["content"] if c.get("type") == "text"))
                assert value.get("success") is True, value
                self.server.tool_checked = True
        if complete_tool:
            if len(self.server.calls) == 1:
                print("Completion tool schema:", complete_tool.get("parameters"), flush=True)
            arguments = {name: True if schema.get("type") == "boolean" else "SOLVER_OK completed successfully"
                         for name, schema in complete_tool.get("parameters", {}).get("properties", {}).items()}
            content = {"role": "assistant", "content": "SOLVER_OK", "tool_calls": [{"id": "call_fixture", "type": "function",
                "function": {"name": completed, "arguments": json.dumps(arguments)}}]}
        if getattr(self.server,'harness','') == 'strix':
            results = [str(m.get('content','')) for m in data['messages'] if m.get('role') == 'tool']
            if any('SOLVER_TOOL_OK' in result for result in results): self.server.tool_checked=True
            execute = next((t['function'] for t in data.get('tools',[]) if t.get('function',{}).get('name','').endswith('exec_command')),None)
            if execute and not getattr(self.server,'tool_checked',False):
                props=execute['parameters']['properties']
                print('Guest execution schema:',execute['parameters'],flush=True)
                field='cmd' if 'cmd' in props else 'command'
                content={'role':'assistant','content':None,'tool_calls':[{'id':'fixture-exec','type':'function',
                    'function':{'name':execute['name'],'arguments':json.dumps({field:"printf 'SOLVER_'; printf 'TOOL_OK'"})}}]}
                completed=execute['name']
        if getattr(self.server,'harness','') == 'pentagi':
            tools={t['function']['name']:t['function'] for t in data.get('tools',[]) if 'function' in t}
            results=[str(m.get('content','')) for m in data['messages'] if m.get('role')=='tool']
            if any('SOLVER_TOOL_OK' in result for result in results): self.server.tool_checked=True
            chosen=None;args={}
            if 'get_number' in tools:chosen='get_number';args={'value':7}
            elif 'submit_pattern' in tools:chosen='submit_pattern';args={'template':'call_{r:24:x}'}
            elif 'subtask_list' in tools:
                chosen='subtask_list';args={'subtasks':[{'title':'Local command check','description':'Run a local command, then report completion. No network access.'}],'message':'One local fixture task.'}
            elif 'terminal' in tools and not getattr(self.server,'tool_checked',False):
                chosen='terminal';args={'input':"printf 'SOLVER_' > solver-check.txt; printf 'TOOL_OK' >> solver-check.txt; cat solver-check.txt",'cwd':'/work','detach':False,'timeout':10,'message':'Check guest command execution and a file read.'}
            else:
                chosen=next((name for name in ('done','report_result','subtask_patch') if name in tools),None)
                args={'success':True,'result':'SOLVER_OK local fixture completed.','message':'Local fixture completed.'} if chosen!='subtask_patch' else {'operations':[],'message':'No changes.'}
            if chosen:
                completed=chosen
                content={'role':'assistant','content':None,'tool_calls':[{'id':'call_'+secrets.token_hex(12),'type':'function',
                    'function':{'name':completed,'arguments':json.dumps(args)}}]}
        value = {"id": "chatcmpl-fixture", "object": "chat.completion", "created": 1,
                 "model": data["model"], "choices": [{"index": 0, "message": content,
                 "finish_reason": "tool_calls" if completed else "stop"}], "usage": usage}
        if not data.get("stream"):
            return self.reply(200, value)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        chunks = [{**value, "object": "chat.completion.chunk", "choices": [{"index": 0,
                    "delta": {**content, **({"tool_calls": [{**content["tool_calls"][0], "index": 0}]} if completed else {})}, "finish_reason": None}]},
                  {**value, "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls" if completed else "stop"}]}]
        chunks[0].pop('usage',None) # Usage is final, not an early end-of-stream signal.
        for chunk in chunks:
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
        self.wfile.write(b"data: [DONE]\n\n")


PROMPTS = {
    "shannon": ["--validate-model"],
    "pentagi": ["--print", "Read only the local workspace and report SOLVER_OK. Do not use the network."],
    "strix": ["--print", "Inspect only README.md. Return a completed report saying SOLVER_OK; do not create subagents or use the network."],
    "plandex": ["--print", "Say SOLVER_OK. Do not change any files."],
    "hexstrike": ["--print", "Create solver-check.txt containing SOLVER_OK, then report completion."],
    "pi": ["--print", "Say SOLVER_OK. Do not call tools."],
    "opencode": ["run", "Say SOLVER_OK. Do not call tools."],
    "kilo": ["run", "Say SOLVER_OK. Do not call tools."],
    "codex": ["exec", "--skip-git-repo-check", "Say SOLVER_OK. Do not call tools."],
    "claude": ["--print", "Say SOLVER_OK. Do not call tools."],
    "qwen": ["--prompt", "Say SOLVER_OK. Do not call tools."],
    "gemini": ["--skip-trust", "--prompt", "Say SOLVER_OK. Do not call tools."],
    "grok": ["--print", "Say SOLVER_OK. Do not call tools."],
    "deepseek": ["--print", "Say SOLVER_OK. Do not call tools."],
    "interpreter": ["--print", "Say SOLVER_OK. Do not call tools."],
    "pentestgpt": ["--print", "Say SOLVER_OK. Do not call tools."],
    "swe": ["--problem_statement.text", "Say SOLVER_OK and submit. Do not modify any files."],
    "aider": ["--yes-always", "--no-git", "--message", "Say SOLVER_OK. Do not call tools."],
    "goose": ["run", "--text", "Say SOLVER_OK. Do not call tools."],
    "cline": ["--yolo", "Say SOLVER_OK. Do not call tools."],
    "openhands": ["--headless", "--task", "Say SOLVER_OK. Do not call tools."],
}


def main():
    parser = argparse.ArgumentParser(description="Actual Yougori VM harness check, using a disposable inference fixture.")
    parser.add_argument("harness", choices=sorted(PROMPTS))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--draft", action="store_true")
    args = parser.parse_args()
    args.root.mkdir(parents=True, exist_ok=True)
    os.environ["TMP"] = os.environ["TEMP"] = str(args.root)
    tempfile.tempdir = str(args.root)
    fixture = Flow()
    fixture.setUp()
    # A real server refreshes endpoint health continuously. Image installation
    # can take longer than the 90s health lease; do not expire the test fixture.
    refresh=threading.Thread(target=fixture.service.watch,daemon=True)
    refresh.start()
    if args.draft:
        import harness_download
        original_catalog = harness_download.catalog
        specs = original_catalog()
        specs[args.harness].pop("blocked", None)
        harness_download.catalog = lambda: specs
    fixture.model.RequestHandlerClass = TextModel
    fixture.model.harness = args.harness
    try:
        fixture.endpoint()
        key = fixture.key()["key"]
        key_path = args.root / "api-key"
        key_path.write_text(key)
        model = fixture.call("/api/models")[1]["models"][0]["id"]
        status = solver.launch(args.harness, fixture.url, key_path, model, None, PROMPTS[args.harness], interactive=False)
        assert status == 0, status
        assert fixture.model.calls, "The real harness made no inference request."
        if args.harness in ('pi', 'shannon'):
            assert getattr(fixture.model, 'contract_checked', False), 'Client did not use the local chat contract.'
        if args.harness == "hexstrike": assert getattr(fixture.model,"tool_checked",False), "MCP file tool did not complete."
        if args.harness == "strix": assert getattr(fixture.model,"tool_checked",False), "The real Strix guest command did not return its output to the model."
        if args.harness == "pentagi": assert getattr(fixture.model,"tool_checked",False), "The real PentAGI guest command did not return its output to the model."
        print("VM_HARNESS_OK: " + args.harness, flush=True)
    finally:
        fixture.tearDown()


if __name__ == "__main__":
    main()
