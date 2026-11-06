# Routing, cached input and the connector stream on yougori.com — live check, 6 Nov 2026

This template at 1b7abf56 on the demo instance `https://yougori-demo-inference.yougori.com/`. Every
request went through the public address (Cloudflare, then the website's server). Compute came from a
disposable Yougori engine on one Windows PC (RTX 5090 Laptop GPU) serving Qwen2.5-Coder-7B-Instruct on
vLLM 0.29.0 (compiled launch, 8 slots), with app commit 6f77999f. The connectors were staged from git:
1b7abf56 (streaming) and 2ba0603a (polling, the protocol of CLI 1.2.0).

| Step | Result |
|---|---|
| Two streaming connectors on the PC, each contributing the model, approved through `/api/compute/pair/approve` | `/api/models` lists one model, `Qwen/Qwen2.5-Coder-7B-Instruct`, with two ready replicas |
| Four streamed conversations of three turns each, sharing a long system prompt | Each conversation stayed on one replica for all three turns: three on the first replica, one on the second. The routing counters showed 9 and 3 requests, of which 6 and 2 kept a conversation on its replica; none failed |
| Cached input | Later turns reported cached prompt tokens in their usage (314 in / 0 cached, then 344 / 320, then 374 / 352), and `/api/usage` recorded `cached_tokens` for each request |
| Time to the first token, 12 short streamed requests per connector, a new HTTPS connection each | Streaming connector: median 595 ms (564–732). Polling connector, same PC and model: median 1,102 ms (766–2,615) |
| Polling connector (2ba0603a) against the new server | Connected and served all 12 requests |

Not covered:
- **Separate computers.** Both replicas ran on one PC and shared one vLLM, so routing was checked but not cache locality across computers.
- **Failover.** Failover before the first byte and the 30-second cooling were not triggered.
- **Harnesses.** Harness installs on hosted instances still wait for published VM images.

Afterwards the test key was revoked and every contributor was disconnected, including this PC's connection from 5 Nov 2026. The demo instance keeps running with no compute connected.
