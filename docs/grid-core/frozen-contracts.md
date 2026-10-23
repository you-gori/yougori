# The legacy data contracts, frozen

Everything in [the rollout](rollout.md) rests on this one thing. A rehearsal is worth running only
if the record it rehearsed is the record the product will still be writing on the day of the move.
A backup is worth taking only if what comes back is what went in. A bridge can be trusted only
against a shape that is not moving under it.

So the shape of every record the four shipped products write is pinned here, in code, with a
fixture per shape, and a test fails if any of them changes.

The tables below are **rendered from `grid/src/core/compat/frozen.rs`**, the way
[adapters.md](adapters.md) is rendered from the connector registry. The table in the code is the
only place any of this is written down; `the_frozen_contracts_in_the_documentation_are_the_ones_in_the_code`
fails when the two stop agreeing, and `cargo test rewrite_the_frozen_contracts -- --ignored` puts
the document back.

## What a forward-compatibility state means

| State | Means |
| --- | --- |
| **Gated** | the loader reads the version first and refuses anything above this build's, saying so |
| **Dropped** | an older build reads it, ignores what it does not know, and loses those fields the next time it saves |
| **Refused** | an older build refuses the whole file, because a type inside it refuses an unknown field |

## The frozen records

| Record | Where | Type | Version | Forward | Bridge |
| --- | --- | --- | --- | --- | --- |
| The Closed Neo Grid hub's record | `grid/hub.json` | `crate::hub::Record` | 1 | Gated | compat::neo, with rehearse, import, roll back and compare |
| The Sandbox Grid hub's record | `grid/desks-hub.json` | `crate::hub::Record` | 1 | Gated | compat::desks, with rehearse, import, roll back and compare |
| The closed bounty host's record | `bounty/host.json` | `crate::bounty::Record` | 1 | Gated | compat::bounty, with rehearse, import, roll back and compare, into a research realm of its own |
| The Access Grid hub's record | `grid/access-hub.json` | `crate::access::hub::Record` | 1 | Dropped | compat::access, with rehearse, import, roll back and compare; no credential value is carried |

## The fixture that pins each one

| Record | Fixture | SHA-256 |
| --- | --- | --- |
| The Closed Neo Grid hub's record | `grid/src/core/compat/frozen/neo-hub-v1.json` | `7e140c48f0c1b2b407de572b458c414931a2a18c5b397df394b910ac932e36b1` |
| The Sandbox Grid hub's record | `grid/src/core/compat/frozen/sandbox-hub-v1.json` | `97877f7c2426662587a7b5b6977ee73caf15a5794e6ecfa47fbd4b368fd56f99` |
| The closed bounty host's record | `grid/src/core/compat/frozen/bounty-host-v1.json` | `112d54e920682fd8d4848db9ad3e50bf038b422f942833f5e3310e892658d78d` |
| The Access Grid hub's record | `grid/src/core/compat/frozen/access-hub-v1.json` | `cfc45b783a3a738cb13c1fb0a87e0b4c360fc5571f82832c665b1bd021396f39` |

## The vault entries each record cannot be used without

Names only. No value of any of these is in this repository, in a fixture, in a backup manifest or in a survey.

| Record | Entries |
| --- | --- |
| The Closed Neo Grid hub's record | `yougori-grid-hub-key`, `yougori-grid-hub-password`, `yougori-grid-member-token` |
| The Sandbox Grid hub's record | `yougori-desks-hub-key`, `yougori-desks-hub-password`, `yougori-desks-member-token`, `yougori-desks-parking`, `yougori-desks-connection-<connection-id>`, `yougori-desks-person-session`, `yougori-grid-desk-invite` |
| The closed bounty host's record | `yougori-bounty-hub-key`, `yougori-bounty-hub-password` |
| The Access Grid hub's record | `yougori-access-hub-key`, `yougori-access-hub-seal`, `yougori-access-device` |

## What is deliberately not frozen

| Files | Why not |
| --- | --- |
| `grid/member.json, grid/desks-member.json, grid/access-member.json` | written by the application, not by this crate: their types are in src-tauri and a fixture here could not read one |
| `grid/desks.json, grid/desk-login.json` | the same: a person's desk session on their own computer, kept by the application |
| `grid/tunnel.json, grid/desks-tunnel.json, grid/access-tunnel.json` | the same, and they hold a tunnel this crate never reads back |
| `swarm/workers.json, swarm/events/, swarm/receipts/<worker-id>/` | a worker's own files, written by the application. The product deletes receipts with the worker on purpose, so freezing them would promise something the product does not do |
| `bounty/imports/*.json` | a published bounty's source, which src-tauri/src/bounty.rs deletes after a day on purpose, for the same reason |
| `grid/core/<realm-id>.json` | Grid Core's own portable shape, which no shipped product writes. It already reads its own version and refuses a record from a newer build (`store::legacy::read`), and it is what a backup carries rather than what a customer's product keeps |

## What a change to a frozen contract has to do

Six steps. There is no shortcut, and the first of them is not re-running the fixture writer.

1. **Raise the record's `version` and leave the old fixture alone.** `hub::VERSION` and
   `bounty::VERSION` are the numbers a build writes. A fixture is written once and is never edited
   and never deleted.
2. **Add a new fixture at the new version**, from a maximal value in
   `grid/src/core/compat/frozen.rs`. `FIXTURES` rises.
3. **Write the step that brings an older record forward**, on a copy, in the product's own module,
   in the shape of `store::legacy::step`. Never in place.
4. **Re-render this document** with `cargo test rewrite_the_frozen_contracts -- --ignored`, and put
   the new fixture's SHA-256 into `contracts()`.
5. **Teach the bridge both versions**, in `grid/src/core/compat/`, with a test per version.
6. **Name the stage of the rollout it lands in**, in [rollout.md](rollout.md). A frozen contract
   changing part-way through a rollout invalidates every rehearsal report already taken and every
   backup manifest's record version, and somebody has to decide what to do about that rather than
   find out later.

## Two facts about forward compatibility

`enterprise::Image`, `enterprise::WorkspaceRole` and `enterprise::Connection` carry
`deny_unknown_fields`. Adding a field to any of the three makes the **whole** Sandbox Grid record
unreadable by every older build, which the person at the computer sees as "The grid hub's settings
are damaged". That is a hard break, not a degradation.

Everything else tolerates a field it does not know and loses it the next time it saves. That is
quieter than a refusal and worse for it. Both behaviours are asserted by
`three_enterprise_types_refuse_an_unknown_field_and_the_rest_drop_it`, so this page cannot drift
from what the code does.

## The version gate, and what it cannot do

Before this phase, `hub::load` and `bounty::load` were a bare `serde_json::from_slice` and no
caller anywhere read `record.version`. A build therefore read a record from any future version and
dropped what it did not know the next time it saved. Both loaders now read the version first and
refuse anything above their own, in a sentence that names the version.

Those two cover three of the four products: the Closed Neo Grid and the Sandbox Grid keep one type
and one loader, and Swarm Mining has its own. **The Access Grid's loader has no gate**, which is
what its forward-compatibility state in the table above says, and those files belong to another
part of this work. An older build reads a newer Access record, loses what it does not know, and
nothing in the rollout notices except the rehearsal, which compares the version it found against
this register.

What that cannot do is repair a record a newer build has already written and an older build has
already saved over. The gate stops the next read, and that is all it stops, which is why it is the
first stage of the rollout and why no later stage is allowed to depend on anybody knowing that a
deployment exists.

## What this freeze does not cover

Said plainly, because a freeze that is read as wider than it is would be worse than none.

- **A type nobody wrote a fixture for is not frozen.** Nothing in Rust can notice a struct that was
  never named in the register. The freeze is exactly as wide as the fixture set.
- **The freeze begins here.** The fixtures are written from the working tree, so they say what this
  build writes and say nothing about what 1.0.20 and earlier wrote. Two things narrow the gap and
  neither closes it: every record this product has ever shipped is at version 1, and the exhaustive
  destructuring tests in `crate::hub` and `crate::bounty` stop compiling when a field is added.
- **A new optional field that is skipped when empty is invisible to the bytes.** It deserialises out
  of the old fixture in its empty state and serialises back identically. Only the destructuring
  tests see that one, and they live inside the modules that own the records because several of the
  fields are private to them. Those two tests name every type either record is made of, down
  through the desks, the people and the enterprise settings, with one exception they name and do
  not open: `bounty::Record::coordination` carries `skip_serializing`, so no byte of it is in the
  record and its fields belong to the module that keeps it in a file of its own.
- **The vault entries are names and never a value.** This crate cannot read the operating system's
  vault at all. Proving that an entry is present is the application's half, and the runbook's step
  is to prove it before a migration rather than discover its absence afterwards.
- **No fixture is anybody's bytes.** Every one was made up in this repository: the certificates say
  so in their own text, the salts and hashes are counting patterns, every address is in `10.0.0.0/8`
  and every name is under `.invalid`, which is reserved and resolves nowhere.
