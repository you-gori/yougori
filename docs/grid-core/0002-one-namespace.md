# ADR 0002: one command namespace over the four grids

Status: accepted, 19 October 2026. Supersedes nothing. See [ADR 0001](0001-architecture.md) for
the architecture this sits on and [plan.md](plan.md) for the staged plan.

## The decision

One namespace, `grids`, with twelve wire methods and one CLI group, over all four products:
the Closed Neo Grid (models), the Sandbox Grid (desks), the Access Grid (credentials) and
Swarm Mining (research).

```
yougori grids NOUN VERB [TARGET] [--grid NAME]
```

The noun is the wire method and the verb is `request.do`:

| noun | method | what it is about |
| --- | --- | --- |
| realm | `grids_realm` | the grid itself: list, status, address, new, join, password, leave, delete, restore, backup, restore-backup, settings, manage |
| people | `grids_people` | accounts, passwords, two-step sign-in, the identity provider |
| computers | `grids_computers` | which computers belong, and which are forgotten |
| share | `grids_share` | what an enrolled computer gives the grid |
| models | `grids_models` | model plans, teams of models, API keys |
| desks | `grids_desks` | desks, their sizes, their images and a person's own desk |
| credentials | `grids_credentials` | credentials, who may use them, using and revealing |
| requests | `grids_requests` | what waits for somebody to agree, and the deciding of it |
| research | `grids_research` | Swarm Mining workers, read and steered |
| connectors | `grids_connectors` | the systems a grid reaches that somebody else runs |
| work | `grids_work` | the engine's own journal of what a command queued |
| log | `grids_log` | what a grid recorded, and whether it is whole |

## Why `grids` and not `grid`

`yougori grid` is the Closed Neo Grid and stays exactly as it is. The plural is the umbrella, and
it is the word the committed plan already uses for Phase 9. The one-letter neighbour is a real
hazard, so it is handled rather than hoped away: `grid::requested` claims any command line with
`--neogrid` anywhere in it, so the order in `cli/src/main.rs` decides, and a test reads that file
and refuses to pass unless `grids` is matched first.

## Why new onto old, and never old onto new

The old wire methods keep their own handlers, untouched. `grids_models do:add` calls
`crate::grid::grid_plan_add`, the function that exists today. Forwarding the old methods through
the new one would change what a shipped 1.0.20 client does on the day this lands, which the plan
forbids. As each product moves onto Grid Core in Phases 4 to 6, one arm of
`cli/src/grids/alias.rs::product_call` changes and not one word anybody types changes with it.

## One table, not three

`cli/src/grids/mod.rs::VERBS` is the single source of truth for what the namespace is. It is what
the terminal parses with, what `yougori grids NOUN --help` prints, what the catalog's
`confirmation_for` reads, what the engine refuses with and what the launcher's submenu is built
from. A test asserts the catalog and the table give the same confirmation sentence for every verb,
so the three places that used to be able to disagree cannot.

## What this adds that the old doors do not have

- **One answer.** `cli/src/grids/answer.rs::Answer` is the only shape, read or write, rehearsed
  or committed.
- **Capability validation before the command runs.** The grid is found, then what it is allowed
  to do is checked, and only then is one argument of the command read. A credential command sent
  to a models-only grid is refused without the credential ever being deserialised.
- **A code beside a sentence, never instead of one.** `cli/src/grids/fault.rs` carries both. The
  queue takes the code off the front of the message and puts it in `errorDetails`, which is the
  arrangement `YOUGORI_BUSY` and `YOUGORI_QUIESCING` already use; the sentence is what is left and
  is the only thing a terminal prints. `--explain` adds one line with the code under it.
- **A dry run that meets the real grid.** `--dry-run` on a `grids_*` method is no longer
  short-circuited to syntax-only. It finds the grid on this computer, reads what that grid is
  allowed to do, builds the call the product handler would receive and validates it against the
  engine's own contract, and then writes nothing.
- **A name per command.** Grid Core's audit carries the name of the command that caused each
  event, from version 7 of the realm database.

## The honest limits, written down rather than implied

1. **A rehearsal does not run the product handler.** The four product hubs have no rollback
   wrapper, so running the whole path against them inside a rehearsal would write. What a
   rehearsal checks is real and is named above; what it does not do is call the handler. When a
   product moves onto Grid Core its rehearsal becomes a transaction that is rolled back, and the
   answer will say so by itself rather than by a promise made here.
2. **Audit correlation reaches the core, not yet the products.** `Event.command` and
   `Core::history_for` are real and tested. No product hub writes a command's name against an
   event yet, so an answer from this door reports no events, says `correlated: false`, and
   `grids log show --command NAME` refuses in words rather than answering with everything.
3. **A structured error code cannot travel as a second value.** Every handler in the chain returns
   `Result<Value, String>`. Rather than claim otherwise, the code travels in front of the sentence
   and the queue strips it, which is honest about the wire and is the shape the wire already has.
4. **Starting a research worker is not on this door.** `yougori start bounty` keeps its own guided
   setup; a worker is started in one place. There is deliberately no `grids research start`, and a
   test asserts there is not.
5. **Publishing a closed bounty is not on this door.** It carries its source files with it and no
   option here can hold them, so `yougori bounty host` keeps it and the refusal says so.
6. **No desktop command and no page.** The twelve methods are on the wire, which is what the CLI
   and agents speak. The Grids tab, its `AppPage` value and the TypeScript client are Phase 9.

## Deprecation

`cli/src/grids/alias.rs::SAY_OLD_IS_OLD` is `false` and a test asserts it. No old command says it
is old. Turning it on needs three things, all checkable:

1. Every row of `ALIASES` passes `a_new_spelling_reaches_the_same_product_call_as_the_old_one`.
2. The namespace has shipped in a release that has been the current release for thirty days with
   no issue traced to an alias.
3. `yougori help` and `skills/yougori/references/cli.txt` describe every route, which
   `cli/src/help_coverage.rs` already forces.

Removal is not scheduled. The plan commits to keeping the old words for at least one major
release and nothing here shortens that.
