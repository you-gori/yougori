# Closed Neo Grid

A company's private model grid on its own network. One computer, run by the admin, is the hub. The company's other computers join it with the company password. The admin decides which models run, on what share of the computers, in which hours and after how long without keyboard or mouse input. Company apps call the hub's OpenAI-compatible API with keys the admin creates.

Unlike the public Neo Grid, nothing passes through yougori.com, there is no pricing or wallet, and prompts and replies are never recorded. Computers outside the office can join through a Cloudflare Tunnel, which relays only the grid's own encrypted traffic.

## Set up the hub (admin)

Pick a computer that stays on and has a fixed LAN or VPN address, then run:

```text
yougori create grid
```

It asks, one question at a time (Esc goes back):
- the company name;
- which computers can join: **this network**, or also computers anywhere through a **Quick public link** or **your own Cloudflare domain** (see [Computers outside the network](#computers-outside-the-network));
- the company password, twice. Use a long passphrase of at least 10 characters.

It ends with an **invite**, a code that starts with `grid-invite:`, and copies it to the clipboard. Send the invite to the company, and the password separately. `yougori grid` shows the invite again.

- The hub listens on port 7460 on this computer's network address. The admin's computer joins its own grid, so its GPU can serve too.
- For scripts: `yougori grid create ACME --ip 10.0.0.5 [--tunnel quick|DOMAIN] --yes`. Use `--port` to change the port, and `--hostname grid.acme.internal` to add a DNS name to the hub's certificate.

## Join a computer

On each company computer, with Yougori installed:

```text
yougori join grid
```

Paste the invite, then type the company password. That is all.

- The invite names the company, the hub's address and the hub's certificate fingerprint, so the computer can only join the real hub. It holds no secret: the password is still needed.
- For IT deployment scripts, send the password as one line on stdin: `yougori grid join --invite grid-invite:… --password - < password.txt`. The password is never accepted as a command argument.
- Without an invite, a computer on the network can join with `yougori ACME --neogrid --ip 10.0.0.5`; add `--fingerprint AB:CD:…` to make sure it talks to the real hub.

**How joining stays safe:**
- The password is never sent over the network. The computer and the hub each prove they know it, and the proofs are tied to the hub's TLS certificate.
- The computer only trusts that certificate after the hub has proven it too.
- A wrong company name, password or fingerprint stops the join before anything is saved.
- Ten wrong passwords from one address lock that address out for 10 minutes.

A computer can run models when it has an NVIDIA GPU (Windows with WSL 2) or Apple silicon. Other computers can join, but plans never pick them.

## Computers outside the network

A grid can also be reached through a Cloudflare Tunnel, so computers at home or in another office can join. Choose it when creating the grid:

| Choice | Address | When the hub computer restarts |
|---|---|---|
| Quick public link (`--tunnel quick`) | a temporary `trycloudflare.com` address; no account needed | the address changes: share the new invite from `yougori grid`; computers paste it with `yougori join grid`, without the password |
| Your own domain (`--tunnel DOMAIN`) | a fixed address on a domain you manage in Cloudflare | the address stays the same |

For your own domain, the setup asks for the domain and the tunnel token, and the tunnel's public hostname route must point to `http://127.0.0.1:7461` (the hub's tunnel port). A domain already serving an environment can't also serve the grid.

- The hub keeps its address on the company network, so company apps and office computers keep using it. The tunnel adds computers elsewhere.
- The hub reconnects the tunnel by itself after a restart or a dropped connection. `yougori grid` shows **Anywhere** with the address, or why it is not connected.
- Company apps call the API on the hub's network address only, not through the tunnel.

## Decide what runs (admin)

```text
yougori grid add-plan --model hf.co/Qwen/Qwen3-8B --percent 50 --schedule "Mon-Fri 18:00-08:00; Sat,Sun" --idle-after 15
yougori grid change-plan PLAN_ID --percent 75
yougori grid remove-plan PLAN_ID --yes
yougori grid
```

**Which computers run a plan:**
- `--percent` is the share of computers that can run models, rounded up. `--scope remaining` counts only the computers nobody picked by hand.
- `yougori grid exclude MEMBER_ID --yes` leaves a computer out of the grid's work: it gets no model and no work, so it drops the model the grid gave it, and a download in progress stops. It stays a member; `yougori grid include MEMBER_ID` brings it back. In the app, use **Leave out** and **Bring back** on the computer's row.
- `--computers '["MEMBER_ID"]'` runs the model on exactly those computers instead of a share. In the app, tick computers in the list and choose **The selected computers**. A pick always wins over a share, and picking a computer for another model moves it there.
- Plans are filled in the order they were created. If plans ask for more than 100%, later plans get fewer computers.
- Computers stay on their plan when others join or leave, so they don't download a new model each time.

**When a computer serves:**
- `--schedule` sets weekly windows in each computer's local time.
  - A window that ends before it starts runs past midnight: `Fri 18:00-08:00` lasts until Saturday morning.
  - `daily`, `weekdays` and `weekends` also work.
  - Without a schedule, the computer may serve at any time.
- `--idle-after` is the number of minutes without keyboard or mouse input before a computer serves.
  - The default is 10; `0` ignores activity.
  - On Linux this uses logind's idle hint, and remote SSH sessions don't count as someone at the computer.
  - If a computer can't read its user activity, it doesn't serve unless `--idle-after` is 0.
- The model is checked for compatibility before the plan is saved.

**What each assigned computer does:**
- It downloads and starts the model, or reuses an environment that already runs it.
- It asks the hub for work only while the plan allows it.
- When its person comes back, it finishes the reply in progress and takes no new work. If the grid was the last to use the model, it also unloads it from the GPU.
- After 10 minutes outside the plan's hours, it stops the model environment if the grid started it, but only once nobody has used the model for 10 minutes. It starts the environment again when the hours begin.
- If the person stops a grid-started environment themselves, the grid leaves it stopped until Yougori restarts.
- A model environment that the person already had running is never stopped. When a plan change or `grid leave` would stop a grid-started environment that answered a request in the last minute, it is left running instead.
- When a computer stops running a model (its plan changes model or is removed, it is moved to another model, or it leaves), an environment the grid **created** for that model is deleted with the weights it downloaded, once no request is in flight on it, so it stops taking disk space. One the grid only started from what the person already had is stopped, never deleted.

## Swarms: one call, several computers (admin)

A swarm harness is a team of models that company apps call as the model `swarm/NAME`, exactly like any other model. One call then runs on several computers at once.

```text
yougori grid add-swarm --name research --lead hf.co/Qwen/Qwen3-32B --workers '["hf.co/Qwen/Qwen3-8B"]' --computers 5 [--strategy plan|mixture] [--rounds 2]
yougori grid run-swarm research --prompt "Compare three ways to cut our cloud bill"
yougori grid remove-swarm research --yes
```

In the app: **Neo Grid → Swarms**. Name it, pick the lead model and the worker models from the ones the grid runs, and choose how many computers work on one call. The chevron on a swarm's row opens a box to try it and shows which computer did each task.

**Two ways of working:**
- **Plan & delegate** (default). The lead model splits the request into independent tasks. Each task gets a brief saying what to produce and where to stop, so no two workers repeat each other. The workers solve the tasks at the same time, each in its own context, and the lead combines the results. With 2 or 3 rounds, the lead can send another round to fill gaps it finds. A request that doesn't split stays one task.
- **Mixture** (Mixture-of-Agents). The workers each answer the whole request, at different temperatures, and the lead writes one answer from all of them. Combining answers this way does better than picking the best one. A second layer first lets the workers improve on each other's answers; a third tends to over-correct, so 2 is the limit.

**How many computers:** every computer serves one request at a time, so `--computers N` (requests in flight) is how many computers work on one call. More tasks than that wait for the next free computer. `--tasks` caps tasks per round (or answers per layer) and defaults to `--computers`. With several `--workers` models, tasks take them in turn.

**What apps get:** an ordinary chat completion (`stream: true` works, with keep-alive comments while the team works), plus `yougori_swarm`: the plan, which computer did each task and how long it took. `GET /v1/models` lists the swarm and whether all its models have a computer ready. The team's work counts against the calling app's key and its 32-request limit. If a model has no computer, the call fails at once with HTTP 503.

**Choosing models:** use the strongest model you run as the lead, since it plans and writes the final answer. Workers can be smaller and faster. The lead and workers must run on the grid through plans; `add-swarm` lists in `missing` any that no plan runs yet.

## Connect company apps (admin)

```text
yougori grid add-key --name Analytics
yougori grid revoke-key KEY_ID --yes
```

`add-key` returns three things:
- the API key, shown once (the hub keeps only a hash of it)
- the base URL, such as `https://10.0.0.5:7460/v1`
- the hub's certificate

Save the certificate as `grid.pem` and make apps trust it:
- curl: `curl --cacert grid.pem`
- Python: `SSL_CERT_FILE=grid.pem` or `REQUESTS_CA_BUNDLE=grid.pem`
- Node.js: `NODE_EXTRA_CA_CERTS=grid.pem`

```text
curl --cacert grid.pem https://10.0.0.5:7460/v1/chat/completions \
  -H "Authorization: Bearer ygrid_…" -H "Content-Type: application/json" \
  -d '{"model":"Qwen/Qwen3-8B","messages":[{"role":"user","content":"Hello"}]}'
```

**The API:**
- `POST /v1/chat/completions` supports streaming.
- `GET /v1/models` lists the models the computers run and how many are ready.

**How requests are handled:**
- A request waits up to 60 seconds for an idle computer.
- If a computer's model is busy, for example with its person's own chat, it hands the request to another computer.
- If no computer can serve, the hub answers HTTP 503 with the reason, such as "2 in use by their person, 1 outside the plan's hours", and a `Retry-After` header.

**Limits:** requests up to 64 KiB, replies up to 16 MiB, and 32 requests waiting or running per key.

## Manage computers

```text
yougori grid remove MEMBER_ID --yes     # admin: the computer must join again with the password
yougori grid password --yes             # admin: computers that already joined stay members
yougori grid leave --yes                # on a member computer
yougori grid delete --yes               # admin: paused for three days, then deleted
yougori grid restore                    # admin: within the three days, everything comes back
yougori grid delete --when now --yes    # admin: deleted at once
```

**Deleting a grid** pauses it first, for three days: no API key works, nobody joins, and computers stop serving and stop the model environment the grid started, keeping it and its weights. `grid restore` within those days brings everything back. Deleted (with `--when now`, or after the three days), each computer is told at its next check-in: it leaves, deletes the model environment the grid created (one its person already had is only stopped) and says so. Computers that are off hear it when they come back; the hub keeps answering for up to 30 days, then removes itself (`--when forget` removes it at once). A Sandbox Grid is deleted the same way (`desks delete`, `desks restore`): paused, its desks stop and are unshared but keep their data; deleted, every computer deletes the desks it hosted.

`yougori grid` on the hub shows:
- each computer: whether it's online, its plan, the state of its model and how many requests it served
- each plan: computers assigned, the target and how many are ready
- each API key: its usage

On a member, `yougori grid` shows its assignment and state:

| State | Meaning |
|---|---|
| `available` | Ready and allowed to serve |
| `busy` | Answering a request |
| `person_active` | Someone is using the computer |
| `outside_schedule` | Outside the plan's hours |
| `preparing` | Downloading or creating the model environment |
| `loading` | Loading the model |
| `stopped` | The model environment is stopped |
| `locked` | The environment is locked down |
| `error` | Something failed; the reason is shown |

## Security

- The hub serves only private LAN and VPN addresses (RFC 1918, link-local, IPv6 ULA) and refuses connections from any other address. Its tunnel entry, when it has one, listens on `127.0.0.1` only, where `cloudflared` forwards to it.
- Through a tunnel, Cloudflare relays only WebSocket frames. Inside them runs the same TLS as on the network, pinned to the hub's own certificate, so Cloudflare never sees prompts or replies, and the password proofs stay bound to the hub. Cloudflare names each caller, so ten wrong passwords lock out only the address they came from. A tunnel does make the hub's join and member endpoints reachable from the internet; they still require the password, a member token or an API key.
- Members open no ports. They ask the hub for work over TLS that trusts only the hub's own certificate.
- Members always run requests on `/v1/chat/completions` of their local model server, with that server's own API key. The hub can't reach anything else on a member.
- Prompts and replies pass through memory only. They are never written to disk or logs, and nothing is sent to yougori.com.
- These are stored on the computers:
  - In the OS credential vault: the hub's private key, the key derived from the company password, and each member's token.
  - On disk: API keys and member tokens, as hashes only, and how the tunnel is set up (`grid/tunnel.json`).
- Locked-down environments never serve.
- Joins, refused joins, plans, keys, assignments and model starts and stops are written to the tamper-evident audit log (`yougori audit`).
- **Limits of this design:**
  - The person at a member computer could read prompts that computer serves, as with any machine that runs a model. Give plans only to computers you trust with that data.
  - Someone who can pretend to be the hub's address on your network could guess the password offline from one failed join. Use a long passphrase, or share the fingerprint so computers join with `--fingerprint`.

## Sandbox Grid: a desk for each person, on the company's computers

The Sandbox Grid is a second, separate grid built with the same hub technology: its own hub (port 7463), password, invite (`desk-invite:…`) and membership. Joining it never makes a computer part of the Closed Neo Grid, and vice versa. It hosts **desks**: sandboxes the admin orders for named people, built on the company's computers within the share of each that the admin allows, like an outsourced team's virtual machines but on the computers the company already has.

- **Host and join.** `yougori desks create Acme --ip 10.0.0.5 --yes` hosts it (the admin's computer joins too); each company computer runs `yougori desks join --invite INVITE` with the password. Add `--tunnel quick` or `--tunnel DOMAIN` for computers outside the network: the same Cloudflare tunnel as the Closed Neo Grid, relaying only the grid's own pinned TLS, with the desk hub's tunnel on port 7464. Every member reports what it has and is using with each check-in: cores and how busy they are, memory used of total, free disk, whether it has a usable GPU and how busy that is, and whether someone used its keyboard or mouse in the last 10 minutes.
- **Each computer's share.** `yougori desks share MEMBER_ID --cpu 2 --memory-gb 4 --disk-gb 50 [--gpu true]` sets what the grid may take from a computer for desks, whether or not its person is using it: a computer in use still hosts desks within its share. Until the admin decides, a suggested share applies (half the cores, half the memory with 2 GB kept back, half the free disk, the GPU if there is one; `--suggested true` returns to it). `--idle-only true` limits a share to the time nobody is using the computer. A share is capped by what the computer actually has, and shrinking it never evicts desks already there. A computer the admin removed, offline, or on battery takes no new desk.
- **Order a desk.** `yougori desks add-desk --name "Design desk" --person ada.lovelace --kind container|microvm|vm --cpu 2 --memory-gb 4 --disk-gb 20 [--gpu true] [--image IMG]`. The hub places it on the computer with the most memory left in its share that fits all of it; that computer creates the sandbox with exactly that allocation, starts it, shares it with full control over pinned TLS on its LAN or VPN address, and reports the invitation. A desk that cannot be built reports why; `retry-desk` tries again.
- **People sign in.** `desks add-person --username ada.lovelace --name "Ada Lovelace" --cpu 2 --memory-gb 4 --disk-gb 20 [--gpu true]` asks for the password twice (10–256 characters) and orders the person's desk with that size in the same step (the desktop form does the same; without a size, only the person is added). The person runs `yougori desk login --invite INVITE --username ada.lovelace` on their own computer; the hub's certificate is pinned from the invite before anything is sent. The password's scrypt-derived key crosses that pinned connection and the hub compares its hash; a wrong name or password gets the same answer, unknown names get a decoy salt, and ten wrong tries lock the address out for 10 minutes. Every ready desk becomes a shared environment in the person's sandbox list.
- **A desk is sticky.** It belongs to its person, on the computer that holds its data, until the admin removes it (which deletes the sandbox and its data) or hands it to someone else. Removing a person keeps their desks. If a computer leaves the grid or loses the sandbox, the desk goes back to waiting and is built again, going first to a computer that held its data before.
- **Stored and audited.** The hub's record is `grid/desks-hub.json` (secrets as hashes; keys in the OS vault); a member's membership is `grid/desks-member.json`. Only which desk is which sandbox is saved on a host (`grid/desks.json`); share tokens stay in memory and are minted again after a restart. The person's sign-in is saved without the password (`grid/desk-login.json`), and the invite in the OS vault. People added, removed and signed in, refused sign-ins, computers' shares set, desks added, built, shared, dropped and removed are in `yougori audit`.
- **A desk moves with its data.** A computer gives its desks up when Yougori closes on it, its battery falls below 30%, it has under 5 GB of disk left, or its person returns and the admin lent only its idle time. The hub hands each desk to another computer: the old one stops it, packs its disk into one checksummed file and sends it to the hub; the new one fetches it, checks the checksum and unpacks it. Nothing is deleted before the hub has the whole copy and nothing is unpacked unless the checksum matches. The person sees "Moving your desk to another computer". With no computer free the data waits, packed, and lands on the next computer with room — including a cloud computer you attach. Closing Yougori waits up to 15 minutes for copies to finish. Desks with disks over 64 GB are not moved, since the copy passes through the hub.
- **Parking and a cloud computer, with the company's own credentials.** With a bucket set (`parkingSet`: Amazon S3 or any S3-compatible store), a moving desk is packed straight into the bucket and fetched from it, so the 64 GB limit falls away and the hub never holds the data; the keys live in the hub computer's vault and reach only the two computers moving that desk. With cloud fallback set (`cloudFallbackSet`: AWS, Google Cloud or Azure), a desk that has waited an hour with no room anywhere gets a virtual machine the hub computer creates with the admin's own signed-in `aws`, `gcloud` or `az`, installs Yougori on over SSH and admits with a ready-made membership; it is deleted again after an hour of hosting nothing.
- **Sign-in.** Two-step sign-in is each person's own (an authenticator app; the admin can only reset it). Company sign-in (`ssoSet`) is any OpenID Connect provider: a public native app with PKCE, the browser opening on the provider and coming back to the person's computer, the hub checking the token against keys it fetched from the issuer itself and matching the email claim to the person's email. Passwords can be switched off.
- **Connectors.** A company workspace (Citrix, Azure Virtual Desktop, Windows 365, Omnissa Horizon) given a credential on the hub computer becomes a connector: the admin assigns a person at the provider from Yougori, a removed person is taken back, and every outcome is in the record. The secret stays in the hub computer's vault. Details in `docs/sandbox-grid-enterprise.md`.
