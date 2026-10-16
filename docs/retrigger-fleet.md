# Retrigger fleet — capacity from many providers, a month per signup

Companion to [retrigger-plan.md](retrigger-plan.md). Written 2026-10-14. Plan only.

## 1. The logic

**Avoid one VM per user.** A user who "has a sandbox for a month" uses it for perhaps
30–100 of that month's 720 hours. A VM per user pays for all 720.

**Sell availability, pay for awake hours.**
- What Retrigger sells is *availability*: the user's sandbox is there whenever they open
  the app, wakes in seconds, and keeps their files and sign-in for the whole month.
- What Retrigger pays for is *awake hours*: a sandbox runs only while its user is using
  it, and sleeps on disk or in object storage the rest of the time.
- Awake sandboxes from many users are packed onto whichever machines are cheapest at
  that moment, from any provider.

**Three levers:**
1. **Sleep.** Stop idle sandboxes after a few minutes and store them cheaply.
2. **Pack.** Run many small awake sandboxes on big machines. Harnesses mostly wait on
   remote models, so CPU can be shared about 4×; RAM is the real limit.
3. **Spread.** Buy capacity wherever it is cheapest: monthly dedicated servers for the
   baseline, hourly cloud for peaks, and the developer's own machines. Move sleeping
   users freely between them.

**Correction to the single-machine plan.** "16 sandboxes on a 16-thread machine" is a
limit of today's code (`resource_admission.rs:94` reserves a whole CPU per microVM),
not real capacity. With CPU sharing and sleep, one 64 GB server serves about 250
registered active users.

## 2. Numbers

Assumptions (replace with the Phase 0 measurements):
- An awake sandbox uses 1 GB RAM and 0.25 of a host CPU.
- A typical active user is awake 2 h/day (use plus the idle tail). That is 60 h/month,
  or 8% of the month.
- In the peak hour, 20% of active users are awake at once.
- Signups who never come back cost storage only.

| Option | What you pay | Per active user per month |
|---|---|---|
| One small cloud VM per user | Hetzner CX23 €5.49 + IPv4 €0.50 (currently not orderable); DigitalOcean and Vultr similar | ~€6 |
| Managed sandboxes (E2B, Daytona) | $0.0504 per vCPU-hour + $0.0162 per GiB-hour; 1 vCPU, 1 GiB, 60 h | ~$4 (heavy users at 8 h/day: ~$16) |
| Packed on an auction 64 GB dedicated server (~€46/month) | ~50 awake at once → ~250 users | ~€0.20 |
| Packed on a new Hetzner AX102 (128 GB, €257 + €129 setup) | ~100 awake → ~500 users | ~€0.55 |
| Packed on hourly cloud with nested virtualization (AWS C8i/M8i/R8i since Feb 2026) | Used only during peaks | Priced live with `yougori neocloud prices` |

Sleeping users take about 0.1–0.5 GB each, compressed, in object storage. At Cloudflare
R2's $0.015 per GB-month with no egress fees, that is about €0.01 per user.

**Result:**
- Packing is about 10–30× cheaper than a VM per user, and about 7–20× cheaper than
  managed sandboxes.
- RAM is the expensive part in 2026: Hetzner cites DRAM costs up to 500% higher since
  September 2025 and has repriced three times this year. That makes sleeping and small
  RAM sizes the main levers.

**Sensitivity:**
- Heavy users (8 h/day, 50% awake at peak) cost about 4× more.
- A fair-use allowance per lease (section 4) stops a few around-the-clock agents from
  breaking the average.

## 3. Architecture

```
                   developer backend / iOS app
                              │  HTTPS, the same /v1 API
                 ┌────────────▼─────────────┐
                 │ Retrigger control plane  │  registry · API gateway · scheduler
                 │ always on, small VM      │  autoscaler · leases · webhooks · costs
                 └──┬──────────┬──────────┬─┘
      nodes dial out│          │          │  (no inbound ports on nodes)
   ┌────────────────▼┐ ┌───────▼───────┐ ┌▼────────────────────┐
   │ node: dedicated │ │ node: AWS M8i │ │ node: developer's   │  each node: Linux + KVM
   │ server, EU      │ │ hourly, US    │ │ own server          │  + yougori-engine (node mode)
   │ ~50 awake       │ │ peak only     │ │                     │  + cached base image
   └────────┬────────┘ └───────┬───────┘ └──────────┬──────────┘
            └────────── object storage (R2) ────────┘
                sleeping users (encrypted overlays) · base images
```

### 3.1 Nodes

**What can be a node.** Any Linux machine with KVM:
- dedicated or bare-metal servers from any provider;
- cloud VMs with nested virtualization (AWS C8i/M8i/R8i, Google Cloud, Azure);
- the developer's own servers.

Each node runs the standalone `yougori-engine` in node mode: no GUI and no keyring,
configured by the control plane.

**Joining:**
- Cloud-init, or `yougori retrigger node join TOKEN` over SSH, installs the engine.
- It checks `/dev/kvm` and pulls the base image from object storage.
- It dials the control plane with a single-use join token.
- From then on it reports capacity every 10 s: RAM budget, CPU, disk, base versions and
  awake sandboxes.

**What can never be a node.** Machines the developer doesn't control. Whoever controls a
host can read its guests' memory and disks, including users' sign-ins. Yougori Network
peers are excluded for this reason.

**Machines without KVM** (most cheap VPSs) cannot host microVMs. They serve only the
dedicated tier (section 5): one user per VM, where the VM itself is the boundary.

### 3.2 Sleeping users live in object storage

A user's state is their overlay disk: files, harness config and sign-in, about 0.1–0.5 GB.
The base image is shared and already on every node.

| Moment | What happens |
|---|---|
| Sleep | Stop the microVM. Compress the overlay (zstd), encrypt it with a per-user key (AES-256-GCM, the key wrapped by the control plane's master key) and upload it. Keep the local copy as a cache. |
| Awake | Upload a fresh copy every 30 min if it changed, so a node failure loses at most 30 min of work. |
| Wake | Prefer the node that still has the user's cache: no download. Otherwise any node with room downloads the overlay (about 1–3 s for 200 MB inside a data centre) and boots. |

The result: nodes are disposable and providers are interchangeable. When a node fails
or is drained, its users wake somewhere else.

### 3.3 Scheduler: where a user wakes

1. On the node holding the user's cache, if it has room.
2. Otherwise on the cheapest node with room that is in the app's region and has the
   user's base version. Regions are pinned per app (EU, US or any) for data residency.
3. Otherwise ask the autoscaler. Return `capacity_full` with `Retry-After` only if
   nothing is ready within 60 s. Baseline headroom keeps this rare.

Packing is by RAM, with a CPU weight per sandbox. No anti-affinity is needed, because
users are independent.

### 3.4 Autoscaler: where capacity comes from

**Target:** keep free awake capacity at 15% or more of the current peak.

**Order of capacity:**
1. the developer's own nodes;
2. monthly dedicated nodes (cheapest per GB, already paid for);
3. hourly nodes from whichever provider has the lowest live price (reusing the Neocloud
   price ranking);
4. spot or preemptible machines, later, and only with more frequent uploads.

**Scaling down:**
- When free capacity stays above 40% for 30 min, drain hourly nodes: stop placing wakes
  there, put their awake users to sleep at their next idle moment (or move them with
  sleep → wake elsewhere, a 5–10 s pause), then release the machine.
- Monthly nodes are kept until the end of their billing period. The autoscaler suggests
  cancelling the ones that were under-used.

**Monthly servers are suggested, never ordered automatically** (setup fees, contracts).
The GUI shows lines like "Add a 64 GB dedicated node: saves €X/month at current usage".

**Provider adapters:**
- First: Hetzner (dedicated and cloud), AWS (nested-virtualization instance types) and
  "own server over SSH".
- Then: OVH, Google Cloud, Azure, Vultr and DigitalOcean (the last two for the dedicated
  tier only).

### 3.5 Control plane

- **Always on and small** (2 vCPU and 4 GB is plenty). It is not a sandbox node, because
  nodes get drained and replaced.
- **Holds** apps, users, leases, keys, webhooks, nodes, placement and costs. At fleet
  scale the registry moves from JSON files to SQLite in WAL mode, continuously backed up
  to object storage (Litestream-style). Postgres comes later if it needs high
  availability.
- **Serves the same `/v1` API** as the main plan. Calls that touch a sandbox go to that
  user's node over the node's persistent connection. Run streams and the sign-in
  terminal travel back the same way.
- **Uses the same desktop GUI and CLI**, pointed at the control plane instead of a local
  registry. A one-machine setup is a control plane plus one node on the same machine,
  which is exactly Phases 1–3 of the main plan.

## 4. Leases: a month per signup

Each user has a lease. It is the unit the developer pays for and the user experiences.

```jsonc
"lease": {
  "plan": "small",                                    // size + allowance
  "startsAt": "…", "endsAt": "…",                     // default: signup + trialDays
  "awakeHours": { "included": 100, "used": 12.4 },    // fair use
  "state": "active"                                   // active | grace | expired | archived
}
```

**Per-app settings:** `trialDays` (e.g. 30), `awakeHoursPerMonth` (e.g. 100),
`graceDays` (7) and `archiveDays` (60).

**Renewal:**
- The developer extends a lease when their customer pays, with
  `POST /v1/users/{id}/lease {until | days | plan}`, typically from their App Store,
  RevenueCat or Stripe webhook.
- Alternatively, `autoRenew: true`.

**Over the allowance:** the sandbox keeps working at a lower CPU weight, and the
developer receives `lease.allowance_exceeded`. They can upgrade the plan or move the
user to the dedicated tier.

**Expiry**, with a webhook at each step:
1. `grace`: runs are refused with `lease_expired`, data is kept, and the product can
   still renew.
2. `archived`: the sandbox exists only as a sleeping copy in object storage.
3. Deleted after `archiveDays`.

**Plans:**

| Plan | Where it runs | Sleeps | Notes |
|---|---|---|---|
| `small` | Shared nodes | Yes | The default |
| `always-on` | Shared nodes | Never | Counts its full RAM around the clock, and is priced that way |
| `dedicated` | Its own VM | — | Section 5 |

## 5. Dedicated tier: a real VM per user, when it's worth it

For users who keep agents running all day, or who need more isolation or resources:
- Retrigger creates one small cloud VM per user from any provider (no KVM needed).
  Cloud-init installs the guest agent and the harness, and the harness runs directly in
  that VM, which is the boundary.
- The API, sign-in and runs are the same; only the lease plan says `dedicated`.
- The cost passes through (about €6/month per user on the cheapest plans), so this is a
  paid upgrade, not the default.
- Moving a user between tiers: sleep → copy the overlay's files → wake in the new place.

## 6. Cutting RAM further

RAM is the expensive part, so:
- **Measured sizes per harness** (main plan, section 6).
- **Short idle stop**, 5–10 min; waking is fast.
- **KSM** (kernel same-page merging) on Linux nodes. Many guests running the same base
  and harness share identical memory pages. Measure the saving before counting on it.
- **Free page reporting** through virtio-balloon. Guests hand unused memory back to the
  host, which allows mild RAM overcommit (for example 1.2×) behind a hard host-level
  guard.
- **Later: memory snapshots** (save and restore the whole running VM) for sub-second
  wake. They cost RAM-sized storage per user, so use them only for `always-on` plans.

## 7. Who runs the control plane (business decision)

- **A. Yougori runs it**, as a managed service in the private yougori.com backend.
  - Developers sign up, get keys, and pay per active user-month.
  - Yougori owns the fleet and its margin. Cost is about €0.20–0.55, and the price could
    be, for example, $1–2 per active user-month for `small`.
  - Developers can still attach their own nodes.
- **B. Self-hosted.**
  - The control plane ships in the open-source engine.
  - The developer brings their own provider accounts and pays providers directly.

Both use the same node engine and protocol. **Recommended:** build B first, because it
is the same code and it is how everything gets tested, then launch A as the product.

## 8. Changes to the main plan's phases

| Phase | Content |
|---|---|
| 0–3 | Unchanged. They build a one-machine control plane plus node: engine core, public API, runs. |
| 4 — Node mode and object storage | Linux engine verified on KVM. Node join. Overlay sleep and wake to R2 with per-user encryption. Base image distribution. CPU weight. |
| 5 — Scheduler and multiple nodes | Placement. Forwarding API calls, runs and the sign-in terminal to nodes. Moving users by sleep → wake. Node failure handling. Load test across 2–3 nodes. |
| 6 — Autoscaler and providers | Hetzner, AWS nested virtualization and own SSH servers. Live prices. Drain and release. Nodes and Costs views. |
| 7 — Leases, plans and the dedicated tier | Leases, allowance, grace, archive, renewal API, `always-on` and `dedicated` plans. |
| 8 — Hardening, terms, release | The former Phase 5, plus provider acceptable-use reviews. |

The old Phase 4 (base image, CPU weight, load test) is split between the new Phases 4
and 5, and runs per node.

## 9. GUI additions

- **Nodes:** each node's provider, region, price, awake and sleeping users, RAM use, and
  state (joining, ready, draining), with Drain and Remove. "Add node" takes a provider
  and size, or gives a join command for your own server.
- **Costs:** this month's spend by provider, cost per active user, unused capacity, and
  the autoscaler's suggestions.
- **Users table:** new Lease (end date, awake hours used) and Node columns.

## 10. Risks

- **Build effort.** This is a small cloud platform: scheduler, storage and autoscaling.
  Phases 1–3 deliver value on one machine first; the fleet comes after.
- **The Linux engine on KVM is unverified today.** It becomes the main production target.
- **Wake latency** when a user's cache is on another node. Measure it, and keep affinity
  high.
- **Provider terms.** Some providers restrict reselling compute or running other people's
  code. Check each provider's acceptable-use policy before adding it, as with the
  harness vendors' terms.
- **Abuse.** Users' code runs from your providers' IP addresses. Use egress rules, the
  strict-internet option, and an abuse contact per provider.
- **Prices move fast in 2026**, especially RAM. Keep prices live through the Neocloud
  price checks, never hardcoded.

## 11. Decisions

1. **Who runs the control plane:** Yougori-managed (recommended as the product) or
   self-hosted only.
2. **Default lease:** 30 days, 100 awake hours, 7 days of grace and 60 days of archive,
   or other numbers.
3. **First providers:** Hetzner dedicated, AWS nested-virtualization hourly, and your own
   servers (recommended).
4. **Object storage:** Cloudflare R2 (recommended; Yougori already depends on Cloudflare,
   and there are no egress fees).

Sources: Hetzner 2026 pricing ([agentdeals](https://agentdeals.dev/hetzner-pricing-2026),
[webhosting.today](https://webhosting.today/2026/05/29/hetzner-has-now-raised-prices-three-times-in-2026-this-one-is-different/),
[cloudhim CX23](https://www.cloudhim.com/cloud-costs/hetzner-cx22-pricing-2026)),
[AWS nested virtualization](https://aws.amazon.com/about-aws/whats-new/2026/02/amazon-ec2-nested-virtualization-on-virtual),
[E2B pricing](https://docs.e2b.dev/faq/calculate-sandbox-price). Check live prices before
budgeting; several of these figures come from third-party trackers.
