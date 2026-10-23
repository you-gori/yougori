# Bringing a Sandbox Grid's desks onto Grid Core

The runbook for the Phase 4 record move. The plan says that every phase moving a record ships with
a dry run, a backup, a rollback and a runbook, or it does not ship. This is that runbook, and the
four things it names all exist in code and are tested.

The bridge is `grid/src/core/compat/desks.rs`. It is built the same way the model grid's bridge in
`grid/src/core/compat/neo.rs` is built, and for the same reason: the hub keeps running and owning
the desks while the realm beside it is built, checked and, if it was a mistake, taken out again.

**Nothing here touches a desk's data.** Every function takes the hub's record by reference. A desk
that is packed up arrives as a key, a size and a checksum; the packed file stays exactly where the
hub put it, and no byte of anybody's work is read, copied or written anywhere by this move.

## Before you start

- The realm must be a company realm that does workspaces, and it must hold no workspaces and no
  images of its own. A Sandbox Grid is brought across into a grid of its own.
- Whoever runs it needs both `ManagePeople` and `ManageWorkspaces`.
- The hub's own record is not changed, so the hub is still the grid that is serving. Nobody loses
  a desk while this runs, and nobody gains one either.

## 1. The dry run

```
let rehearsal = compat::desks::rehearse(&record, now)?;
println!("{}", rehearsal.describe());
```

`rehearse` writes nothing, here or on the hub, and the test asserts that by comparing the hub's
record before and after. It reports the counts a person can check against what they can see in the
product: accounts, computers, commitments, images, workspaces, how many are owned, how many are on
a computer now, and how many have their data packed up and waiting.

It also reports what will be different afterwards. A rehearsal that passes is an import that will
run; a rehearsal whose notes you have not read is not a reason to run one.

## 2. The backup

```
let backup = core.backup(now)?;        // write this somewhere off this computer
```

A backup carries no key and restores only with the realm's own key. Take it before the import, not
after. The hub's own record is the other half of the backup and is not touched by any of this, so
if the realm is thrown away entirely the Sandbox Grid is still exactly where it was.

## 3. Running it

```
let imported = compat::desks::import(&mut core, by, &record, now)?;
```

What it writes, in the order it writes it:

- one account that stands for the grid's computers, as the model bridge names it too;
- one account per person who signs in, with the roles their hub role maps to;
- one computer and one offer per member, reusing any that another bridge already brought in;
- one commitment per computer, carrying the share the admin set and the admin's "only while
  nobody is using it" where that was set. The sentence beside it is this grid's own standard
  wording for a shared computer, written here at import, because the hub records a share as
  numbers and a flag and keeps no agreed text to carry. It is recorded against the account that
  stands for the grid's computers, not against a person;
- the image catalogue, plus one image for every desk that was ordered without one;
- one workspace per desk, with its owner, its state, its placement and its packed copy.

Keep `imported`. It is what a rollback needs, and it records only what this import actually
created, so taking it back out takes out exactly what it put in.

## 4. Checking it

- `core.workspaces()` has one row per desk, each owned by the person it belonged to.
- `core.workspace_trail(id)` leads back to the computers that have held that desk's data.
- `core.commitments(host_id)` reads back the share that came across, under this grid's standard
  wording for it. Those words are this grid's, not the hub's.
- `core.verify_audit()` passes, and the history holds a `grid.desks.imported` event.

## 5. The rollback

```
compat::desks::roll_back(&mut core, by, &imported, now)?;
```

What the import created goes. What happened stays, because the history is never rewritten: both
the import and the undoing of it are events in the sealed chain.

It refuses rather than taking anything else with it, and says which:

- somebody is in one of the workspaces it brought in;
- work has been placed from a computer or an account it brought in;
- somebody has enrolled a computer of their own against an account it brought in.

Close the sessions, or decide that the realm is now the grid, and run it again.

## What is deliberately left with the hub

Said here rather than discovered later.

- **Workspace roles.** A desk ordered from a role arrives with the image and the access that role
  resolved to, which is everything the desk actually uses. The role itself stays with the hub.
  Version 4 has no roles; a later version takes them.
- **Creating a cloud computer when nothing has room.** `grid/src/desks.rs::needs_computer` and
  `CLOUD_AFTER` are a shipped hub behaviour and are not in version 4.
- **Passwords and two-step sign-in.** Nobody's sign-in secret comes across. An account in a realm
  holds no sign-in secret at all; people still sign in to the hub.
- **The secret for the company's bucket.** A packed copy records which bucket it is in, because the
  computer taking the workspace over has to find it. What opens the bucket stays in the hub
  computer's vault and is not in the realm's database.
- **Each computer's room is not reserved.** The hub still holds these desks, so the realm records
  where each one is without reserving the computer's room for it. A realm that takes the desks over
  places them itself.
- **The agreed wording.** The hub records what a computer offers as numbers and an "only while
  nobody is using it", and never as a sentence, so there is none to bring. A computer that enrols
  in the realm commits there, and that commitment records the words its person is shown.

## Two differences worth knowing before you run it

- **Generations start at one.** A desk's generation starts at zero on the hub and at one in the
  realm, so every workspace arrives one above the number its desk had. Nothing the hub handed out
  is a permission in the realm anyway, so this costs nobody anything and keeps the rule that a
  generation only ever rises.
- **A Sandbox Grid administrator does not become the realm's owner.** They become a workspace
  administrator and an operator, which is everything they could do on the hub. Adding people to a
  realm is a wider permission than the hub ever gave, and a migration does not hand it out. The
  realm's owner grants it if they mean to.

## Where the tests are

`grid/src/core/compat/tests.rs`: `a_sandbox_grid_is_rehearsed_brought_across_and_taken_back_out`
runs the whole of this runbook against a record in the shape a hub actually writes, and
`an_import_that_somebody_is_already_using_cannot_be_taken_back_out` proves the two refusals.
