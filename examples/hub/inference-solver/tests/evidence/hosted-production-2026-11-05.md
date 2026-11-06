# Website-hosted instance on yougori.com — live check, 5 Nov 2026

The first production inference created through https://yougori.com/create-inference, with this
template running on the website's server (`site/managed.py`, Python 3.12, Amazon Linux 2023).

| Step | Result |
|---|---|
| Create inference on yougori.com (company, internal access, Neo Grid compute) | Setup saved, address `https://yougori-demo-inference.yougori.com/`, "Your inference is live" after about 3 s |
| Open the address through Cloudflare and the server's wildcard nginx block | Instance page with the chosen name; `/health` → `{"status": "ok"}` |
| Administrator sign-in with the password chosen on yougori.com (`/api/login`) | 200, session cookie `Secure; HttpOnly; SameSite=Strict` |
| `yougori inference connect https://yougori-demo-inference.yougori.com` from a Windows PC with Yougori 1.2.0 and a running Qwen2.5-0.5B-Instruct container | Computer code shown; administrator approved it (`/api/compute/pair/approve`); connector reported "Connected" |
| API key created by the administrator (`/api/keys`, scopes `["*"]`) | 201 |
| `GET /v1/models` with the key, through the public address | The contributed model listed |
| `POST /v1/chat/completions` with `stream: true` through the public address | 200 `text/event-stream`, 3 chunks in 4.2 s, answer "Hello There! Welcome aboard." |
| Stop and start from yougori.com (checked in the browser test with the same template) | Stopped address answers 503 with an explanation; started again, it answers |

Not covered: harness one-command installs on hosted instances (they show "Setup not available yet"
until harness artifacts are published for them) and cloud rental from the hosted Admin panel
(no engine on the website's server; compute comes from connected computers). The test key was
revoked and the connector stopped afterwards; the demo inference was left running for the owner.
