---
name: yougori-grid
description: Build a grid-backed application in this Sandbox VM using its installed Yougori grid tools.
---

# Grid hosting in this VM

Run `yougori grid status` to inspect the controller. Start it with `yougori grid serve`.
If an OCI image already supplies its own `yougori`, use `/run/yougori/bin/yougori grid` for these guest tools.
Tools are built into the guest: no Docker, package manager or downloaded executable.
The creation checkboxes select GPU, CPU and memory resource accounting. They do not
allocate contributor hardware, combine machines' RAM into one address space, grant
host access, rent a cloud server or enable GPU passthrough.

Configuration is private at `$WORKSPACE/.yougori-grid/config.json`. It contains the
administrator token. Never include that file in an application response, source
repository or prompt. Only the VM's owner/application should administer this grid.

## Build an application

The controller listens on `127.0.0.1:8787`. Its JSON API requires a bearer token.
Use the administrator token for `GET /status`, `POST /invites`, `POST /jobs`,
`GET /jobs/ID`, `DELETE /jobs/ID`, and `DELETE /workers/ID`.
No browser CORS is enabled; put your application's authenticated backend in front.

Create a job with `yougori grid submit`, passing JSON on stdin:

    {"kind":"chat","model":"my-model","resources":{"cpu":0,"memoryGb":0,"gpu":1},"payload":{"messages":[{"role":"user","content":"Hello"}],"max_tokens":32}}

Use only selected resources. CPU/memory jobs may carry your own JSON payload and
kind. Implement the corresponding worker; the controller never executes payloads.
One job is leased per worker, only when its offered resources and model match.
Your application must enforce its own user quotas and authorization before submitting.

## Contributors, including rented NeoCloud machines

Create a one-use invitation: `yougori grid invite > invite.json`. Transfer it
privately to the intended contributor. Publish the VM's `grid=8787` service through
Yougori with HTTPS before accepting remote machines. For a local owner publication,
select application mode so worker authorization headers reach the controller.
The existing VM publication response budget still applies; these checkboxes do not
remove publication limits. Never expose plaintext HTTP
off loopback. Cloud rental remains an explicit owner action through Yougori.

From a machine/VM with these tools and a running OpenAI-compatible model server:

    yougori grid contribute --server https://grid.example.com --join-file invite.json --model-url http://127.0.0.1:8000/v1 --model my-model --gpu 1

Use `--cpu` and `--memory` for selected CPU/memory capacity; `--model-key-file`
reads an optional model-server credential from a file. The worker checks model
discovery before joining. It accepts chat jobs only and contacts only the configured
loopback model server. It never runs arbitrary submitted commands on the contributor.
A model already running inside this VM may contribute the same way over loopback.
GPU counts are contributor-reported, not hardware attestation. Check the actual
backend/device and run inference before claiming CUDA support. This Windows
QEMU/WHPX guest has no GPU passthrough; CPU inference or external GPU contributors
are the available paths. These tools do not install a model runtime or model weights.

## Custom workers

`POST /worker/join` with the invitation bearer and
`{"name":"worker","capacity":{"cpu":4,"memoryGb":8,"gpu":0},"models":[],"kinds":["my-task"]}`
returns a worker ID and private bearer token. Use it for `POST /worker/claim`,
`POST /worker/heartbeat` (every 30 seconds during work), and
`POST /worker/complete` with `{"id":"job-id","result":{},"error":""}`.
Claim returns `{"job":null}` when no compatible work is queued. Execute custom
work only inside the contributor's Sandbox VM with explicit resource limits.
Do not execute arbitrary grid payloads on the host. Removed or expired workers
cannot finish a job. Expired work fails rather than being replayed automatically.

## Limits and recovery

The initial toolkit is a bounded controller: 128 workers, 128 unused invitations,
256 retained jobs, 1 MiB payload/result, one active job per worker, 90-second
renewable job leases. Delete finished jobs after collecting results.
Settings and this skill persist in the VM workspace; invitations, memberships and
jobs live for the controller process. Restart requires fresh worker invitations;
your application must persist business results and reconcile interrupted work.
It is not a durable enterprise job service or a distributed GPU execution runtime.
Nothing has a four-hour runtime limit. Stop the controller or VM explicitly.
