# Closed Neo Grid

A company's private model grid on its own network. One computer, run by the admin, is the hub. The company's other computers join it with the company password. The admin decides which models run, on what share of the computers, in which hours and after how long without keyboard or mouse input. Company apps call the hub's OpenAI-compatible API with keys the admin creates.

Unlike the public Neo Grid, nothing passes through yougori.com, there is no pricing or wallet, and prompts and replies are never recorded.

## Set up the hub (admin)

Pick a computer that stays on and has a fixed LAN or VPN address, then run:

```text
yougori grid create ACME --ip 10.0.0.5 --yes
```

- It asks for the company password twice. Use a long passphrase of at least 10 characters.
- The hub listens on port 7460. Use `--port` to change it, and `--hostname grid.acme.internal` to add a DNS name to the hub's certificate.
- The admin's computer joins its own grid, so its GPU can serve too.

`yougori grid` shows the hub's address and its certificate fingerprint. Share both with the company.

## Join a computer

On each company computer, with Yougori installed:

```text
yougori ACME --neogrid --ip 10.0.0.5
```

- It asks for the company password.
- For IT deployment scripts, send the password as one line on stdin: `... --password - < password.txt`. The password is never accepted as a command argument.
- Add `--fingerprint AB:CD:…` to make sure the computer talks to the real hub.

**How joining stays safe:**
- The password is never sent over the network. The computer and the hub each prove they know it, and the proofs are tied to the hub's TLS certificate.
- The computer only trusts that certificate after the hub has proven it too.
- A wrong company name, password or fingerprint stops the join before anything is saved.
- Ten wrong passwords from one address lock that address out for 10 minutes.

A computer can run models when it has an NVIDIA GPU (Windows with WSL 2) or Apple silicon. Other computers can join, but plans never pick them.

## Decide what runs (admin)

```text
yougori grid add-plan --model hf.co/Qwen/Qwen3-8B --percent 50 --schedule "Mon-Fri 18:00-08:00; Sat,Sun" --idle-after 15
yougori grid change-plan PLAN_ID --percent 75
yougori grid remove-plan PLAN_ID --yes
yougori grid
```

**Which computers run a plan:**
- `--percent` is the share of computers that can run models, rounded up.
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
yougori grid delete --yes               # admin: closes the grid and its API keys
```

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

- The hub serves only private LAN and VPN addresses (RFC 1918, link-local, IPv6 ULA) and refuses connections from any other address.
- Members open no ports. They ask the hub for work over TLS that trusts only the hub's own certificate.
- Members always run requests on `/v1/chat/completions` of their local model server, with that server's own API key. The hub can't reach anything else on a member.
- Prompts and replies pass through memory only. They are never written to disk or logs, and nothing is sent to yougori.com.
- These are stored on the computers:
  - In the OS credential vault: the hub's private key, the key derived from the company password, and each member's token.
  - On disk: API keys and member tokens, as hashes only.
- Locked-down environments never serve.
- Joins, refused joins, plans, keys, assignments and model starts and stops are written to the tamper-evident audit log (`yougori audit`).
- **Limits of this design:**
  - The person at a member computer could read prompts that computer serves, as with any machine that runs a model. Give plans only to computers you trust with that data.
  - Someone who can pretend to be the hub's address on your network could guess the password offline from one failed join. Use a long passphrase, or share the fingerprint so computers join with `--fingerprint`.
