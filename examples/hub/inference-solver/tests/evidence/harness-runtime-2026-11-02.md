# Harness runtime checks — 2026-11-02

Historical container evidence. The current launcher uses Yougori Sandbox VMs;
see [the separate native results](native-harnesses-2026-11-04.md). The matrix below
must not be presented as native VM validation.

## Scope

Sixteen of the 21 catalog entries have server-bound, downloadable profiles.
The tests start the actual pinned third-party clients in Linux containers on
Docker Desktop 28.5.2 on Windows. A disposable Inference Solver HTTP server
forwards requests to a disposable HTTP model fixture. No live provider key,
GPU model, external target, account signup or payment is used.

These checks establish launch, API compatibility, isolation and cleanup for the
exercised paths. They do **not** establish model quality, every tool's behavior,
macOS/native Linux compatibility, or complete compatibility with each vendor API.

**Final matrix: 16 passed, 0 failed.** Each profile ran the boundary probe and
cleanup assertions below against the same source revision (`29ab1f922613`).
[Machine-readable results and source hashes](harness-runtime-2026-11-02.json)
and [client transcripts](harness-runtime-2026-11-02.txt) are retained. Build logs
were excluded from the transcripts; the JSON includes their full-file hashes.

## Tested profiles

| Profile | Pinned version / revision | Mode checked |
| --- | --- | --- |
| OpenCode | 1.19.5 | Native `run` |
| Kilo Code | 7.8.18 | Native `run` |
| Codex | 0.166.0 | Native `exec`, stateless Responses adapter |
| Pi | 0.73.1 | Native print mode |
| Qwen Code | 0.26.6 | Native prompt mode |
| Cline | 3.0.74 | Native CLI, valid completion tool call |
| Claude Code | 2.1.316 | Native print mode, Messages adapter |
| Aider | 0.86.2 | Native message mode |
| Open Interpreter | 0.4.3 | Its Python client through the print adapter |
| Goose | 1.57.0 | Native `run` |
| DeepSeek Harness | 0.2.1-rc.5 | Official headless profile |
| Gemini CLI | 0.66.0 | Native prompt mode, generateContent adapter |
| OpenHands | 1.16.0 | Native headless local execution |
| Grok Build | 1.0.70 | Native print mode, Linux amd64 release |
| SWE-agent | 3ea751c087f32b16e039a2233dd6eefecef325d5 | Local backend, empty Git workspace, successful submission |
| PentestGPT | e8b1bb77d1ac00329675cec3b060aba971ec1ac8 | Maintained interactive client's own Python model client |

## Boundary and acceptance assertions

`tests/runtime_harnesses.py` uses the same container arguments as the downloadable
launcher, then starts the actual client. The final matrix asserts:

- UID 1000, zero effective capabilities, no-new-privileges, read-only runtime.
- No mounted service key or host Docker socket in the client.
- Direct public-IP and host-bridge TCP connections fail.
- The loopback relay can fetch this server's authenticated model catalog.
- Admin paths, arbitrary URL parameters, proxy CONNECT and absolute external
  request URLs are refused with HTTP 403.
- The actual client reaches the server with the selected model, displays the
  fixture's answer and exits successfully. The real service key appears in
  neither client arguments nor captured client output.
- Cline completes without abort/error. SWE-agent successfully submits within
  three model requests; a call-limit exit does not qualify as success.
- The exact client, relay and private socket volume disappear after launch exits.

The network policy is enforced by `--network=none`, not merely by provider
settings. All client subprocesses inherit that boundary. The trusted relay alone
has network access; its fixed-origin allowlist permits only model API routes and
refuses redirects. This is container isolation, not VM isolation or a guarantee
against host-kernel vulnerabilities. Installation downloads dependencies before
the runtime workspace or service credential is attached to an image.

## Defects found during actual client runs

- Responses tool namespaces and function-call histories needed conversion for
  Codex. Its catalog now contains only the authenticated server models.
- Claude sends system-role messages and nullable thinking options that the
  initial adapter rejected. Gemini required a generateContent adapter.
- Cline's package did not expose the expected executable symlink. Closing the
  headless PTY input also aborted it before its answer; both were corrected.
- DeepSeek required its official provider overlay and packaged native addon;
  the fresh-home native cache path was incompatible with the first runtime.
- Open Interpreter needed its declared compatibility dependency for
  `pkg_resources`. Grok required the official binary rather than an assumed npm
  package. Downloaded release binaries are checksum checked.
- SWE-agent needed its own tool dependencies and writable tool staging path.
  Its workspace must be a preexisting Git repository without reset. Empty
  sessions now initialize only their disposable workspace. The earlier run that
  exhausted 51 model calls is **not** accepted as a pass; the corrected run
  submitted in two calls, and the harness now asserts successful submission.

## Other checks and limitations

The HTTP contract suite covers authorization/model scope on all three adapters,
malformed requests, function history, final SSE events, the relay allowlist,
fragmented terminal colors and credential-free ZIP contents. Browser checks cover
guest-first browsing, setup/download, unavailable profiles, accounts, scoped keys,
invitations, themes and narrow layouts. Root lint and UI build passed.

Responses, Messages and Gemini SSE are buffered until upstream completion. Only
text and function tools are implemented; media, hosted tools and stored Responses
state are rejected. Native Chat Completions streaming remains available. Top-level
versions/revisions are pinned; transitive package dependencies are not locked.
Grok is currently Linux amd64 only. PentestGPT uses its maintained interactive
client, not its separate autonomous Docker/CTF deployment.

## Unfinished profiles — 5 / 21

These are unfinished integrations, not completed features or external blockers.
Their download controls remain disabled:

- **Plandex:** package its self-hosted server and PostgreSQL, with the selected
  server model configured for every model role.
- **Strix:** provide an isolated worker backend. Its default Docker backend asks
  for Docker access, network capabilities and a host gateway; none is exposed by
  this launcher.
- **Shannon:** package its worker and Temporal services inside the same external
  network restriction, without exposing the host Docker socket.
- **PentAGI:** package its database and tool/worker services within that boundary.
- **HexStrike:** package the MCP/tool server and an explicitly configured companion
  inference agent. It is not itself a model-serving client.

The live preview had no connected model at verification time. Connect a model
before trying real inference; fixture success must not be presented as a live
GPU run or as completion of all 21 integrations.
