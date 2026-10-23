# ADR 0001 — One Grid Core, four capability profiles

**Status:** accepted, 18 October 2026. Supersedes nothing; it sets the direction for the four
grid products.

## Context

Yougori ships four products that are, underneath, the same kind of thing: a company runs a hub on
one computer, other computers enrol with a password and a pinned certificate, the hub decides what
each may do, and everything it does is audited.

| Product | Hub implementation | Port | Record | Vault keys |
| --- | --- | ---: | --- | --- |
| Closed Neo Grid | `grid/src/hub.rs` | 7460 (tunnel 7461) | `grid/hub.json` | `yougori-grid-*` |
| Sandbox Grid | the same `grid/src/hub.rs` | 7463 (tunnel 7464) | `grid/desks-hub.json` | `yougori-desks-*` |
| Access Grid | `grid/src/access/hub.rs` | 7465 (tunnel 7466) | its own record | `yougori-access-*` |
| Swarm Mining | `grid/src/bounty.rs` | 7462 | `bounty/host.json` | `yougori-bounty-*` |

So there are three hub implementations, four records, four ports, four background loops in the
engine, four command groups and four tabs. The low-level pieces are already shared: identity and
pinning (`net.rs`), invitations (`invite.rs`), the password proof (`password.rs`), the tunnel
(`tunnel.rs`) and the session relay (`relay.rs`).

Two things follow. Security work has to be done three or four times, and a customer has to
understand four products to use one. Both get worse as enterprise features arrive, because every
one of them — identity federation, attestation, provisioning connectors, audit export — belongs to
all four.

## Decision

Build **one Grid Core** and express the four products as **capability profiles** on top of it.

- **Grid Core** owns realms, principals, devices, hosts, enrolment, role bindings, policy
  evaluation, resource pools, leases, the workload lifecycle, capability tokens, the audit chain,
  backup and restore, and the versioned protocol.
- **Profiles** own what is particular to each product: model serving, workspaces, credential
  brokering, authorised research.
- **Realms** are the trust boundary. A primary realm may enable the model, workspace and
  credential profiles. Research runs in a separate realm — the same compiled core, its own keys,
  its own store, its own network zone, no inherited credentials, and no token that the primary
  realm will accept.

One backend technology, one protocol, one security model, one UI. Separate keys, separate data,
separate runtime permissions.

## Why a separate realm rather than a fourth profile on the primary realm

Authorised research handles source that is not ours, runs tooling we did not write, and produces
artefacts we must retain for review. Putting it in the same trust boundary as the credential
broker would mean a defect in the research runtime is a defect in the company's credentials. The
separation is by construction: different key hierarchy, different store, different network zone,
and tokens that fail closed across realms.

It also keeps that subject matter in its own part of the tree, which is a practical benefit when
working on the rest of the product. It is a code and trust separation and nothing more: it does
not change how any model behaves, and no mode that tries to influence a model's safety behaviour
will be built. Where a model declines to work on something, that stands.

## Corrections to the source plan

The plan this ADR implements maps some existing files onto core responsibilities. Two of those
mappings are wrong and the work must be sized accordingly:

- `grid/src/policy.rs` is **not** a general policy engine. It decides when a member computer may
  serve: an idle threshold and a weekly schedule. The core's policy engine is new code.
- `grid/src/activity.rs` is **not** an audit primitive. It reports whether someone is using the
  keyboard and mouse. The audit pieces that exist are `hub::Events` (a callback that records a
  dotted kind and a JSON detail), `enterprise::Audit` (a bounded list in the record) and the
  Access Grid's own tamper-evident log. The core's hash-chained audit is new code, informed by the
  Access Grid's.

Two more notes on sizing:

- Neo Grid and Sandbox Grid already share one hub implementation. Merging them is mostly a data
  and lifecycle question, not a rewrite.
- The adapter matrix in the plan lists more than a hundred integrations. Four exist today, and
  they are tested against mock servers rather than live tenants. The matrix is a roadmap; this
  ADR commits only to the adapter interface and to keeping what exists honest about its status.

## Layers

| Layer | Responsibility |
| --- | --- |
| Grid Core | Realms, identity, enrolment, devices, roles, policy, pools, leases, workloads, capability tokens, audit, backup, protocol |
| Profiles | Model serving, workspaces, credential brokering, authorised research |
| Runtime | Containers, microVMs, VMs, GPU workloads, remote hosts, desktop sessions |
| Adapters | Identity providers, desktop platforms, hypervisors, clouds, orchestrators, storage, hardware management |
| Clients | Desktop UI, CLI, MCP, the OpenAI-compatible model API |

## Storage, decided in Phase 2

**One SQLite database per realm**, in write-ahead logging mode with every commit flushed, bundled
with the build rather than relying on anything on the computer.

*Per realm, not one for everything*, because the trust boundary between a company realm and a
research realm should be a boundary a query cannot cross. Separate files mean a research realm
holds nothing of the company's, is backed up and deleted on its own, and cannot be joined to the
company's tables by any mistake in a later query.

*A database rather than one JSON record*, because the record had to be written whole on every
change. A decision and the standing allowance it creates must land together; which single-use
permissions have been spent must survive a restart; an event must be impossible to change after it
is written. All three are transactions and constraints, not conventions.

*The shape a realm travels in stays JSON.* A backup, an export and a record written by an earlier
build are all the same portable shape, which is also what an admin view reads. The database is how
a realm is kept, not how it is carried.

**Rejected.** PostgreSQL now: it is a server to install, back up and secure for a product that
runs on one desktop. It stays the answer for a multi-node control plane, behind its own flag,
reading the same shape. Keeping the JSON record and adding locking: it cannot give a transaction
across two changes, and every write would still rewrite the whole realm.

## Consequences

**Good.** One place to harden, one conformance suite every profile inherits, one audit format, one
backup story, one tab. Enterprise features are written once.

**Costly.** The core must land behind a flag beside the running products, every record needs a
migration with a rollback, and 1.0.20 is already released, so compatibility aliases must stay for
at least one major release.

**Risky.** Storage is the sharpest edge: moving from JSON records to a database touches every
product's durability. It comes after the core model is proven, and a multi-node store stays behind
its own flag.

## Alternatives rejected

- **Leave the four as they are.** Rejected: every enterprise feature is then written four times.
- **One realm for everything, including research.** Rejected: it puts unreviewed source and company
  credentials in one trust boundary.
- **A fork of the whole repository for research.** Rejected: the fork stops receiving core
  security fixes within weeks.
