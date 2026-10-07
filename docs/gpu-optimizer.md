# Automatic GPU memory

New local Yougori GPU model environments use automatic residency management.
The container and verified downloads stay available while weights are unloaded.
After 120 seconds without work, an unpinned model releases GPU allocations.
Requests load the cached checkpoint again and keep its previously served precision.
Old running model servers need a restart with the updated engine to enable it.

The first scheduler conservatively switches one resident model at a time across
this computer's managed GPU containers. It never evicts an active generation,
a prepared request lease, a stalled worker that still owns the generation lock,
or a pinned model. It does not stop containers, remove files, manage unrelated
GPU applications, or control Neocloud pods. CPU/RAM/disk capacity still applies.
PyTorch may retain a small CUDA context after unloading; weights and its unused
allocation cache are released. This is not unlimited simultaneous inference.
The network permits up to 128 registered models per provider account.

```powershell
yougori model optimize MODEL_ENV
yougori model optimize MODEL_ENV --on --idle 120
yougori model optimize MODEL_ENV --pin
yougori model optimize MODEL_ENV --unpin
yougori model optimize MODEL_ENV --off
```

The App's model API access panel has the same settings, queue counts and
allocated GPU memory. Changes survive restarts. A pinned model can prevent other
models from loading until it is unpinned. Request waiting is bounded; failure and
cancellation release reservations and charge no tokens for unfinished attempts.

## Yougori API and website chat

Standard OpenAI-compatible requests wait for an available model. Default total
wait is 600 seconds. Set `X-Yougori-Wait-Seconds` to an integer from 10 to 1800
and give your HTTP client at least that timeout. Missing providers return
`no_provider`; busy providers have a bounded queue (64 waiting per gateway,
two per key). Queues and preparation leases expire or cancel; prompts and replies
are not added to scheduler records.

For `stream: true`, opt into named SSE progress events with
`X-Yougori-Progress: true`. Use a raw SSE client to handle `event: yougori.status`
separately from normal OpenAI completion chunks:

```text
event: yougori.status
data: {"type":"yougori.status","request_id":"req_example","state":"loading_model","elapsed_seconds":18,"provider":"nd_example"}
```

States are `queued`, `freeing_memory`, `loading_model`, `generating`, and
`retrying`. A gateway queue event may include `queue_position`; this is the
gateway's waiting queue position, not a time estimate. Website chat enables
these events automatically and shows elapsed waiting time and cancellation.
Standard streams receive keepalive comments without extra progress data.

Loading time is not billed or included in generation speed. The gateway buffers
and verifies complete replies before delivery, so provider failover never exposes
or charges an abandoned partial answer. Provider control uses a separate local
credential; public model keys can prepare/release a lease but cannot unload,
grant GPU admission or change provider settings.
