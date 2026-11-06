# Dev Workspace

A development sandbox on this computer, with your project folder kept in step with it both ways.
Edit your code in your usual editor on this computer, or in a terminal inside the sandbox — both
sides stay the same. Your coding tools are installed in the sandbox, not on this computer.

Your folder is yours. Yougori never chooses it: you pick it when you set this up, and you are
asked again, in plain words, before the sandbox is allowed to change anything in it.

## What you choose

| Question | What it does |
| --- | --- |
| Which folder holds your project? | The folder on this computer that is kept in step with the sandbox's copy at `/workspace`. You pick it with a folder picker (or `--binding project=PATH` from the command line). |
| A folder the sandbox may read | Optional. Mounted at `/reference`, read only. The sandbox can never change anything in it. |
| Which container image should the sandbox run? | Any image you pin. `ubuntu:24.04`, `node:22.11-bookworm`, `python:3.12-slim-bookworm` and `rust:1.83-bookworm` all suit this well. |
| Which coding tools should it install? | Codex, Claude Code, Gemini CLI, OpenCode, or none. Each is installed inside the sandbox; you sign in to it there. |
| Cores, memory, disk | What the sandbox gets. The disk is its own: your project folder does not use it. |
| How should port 3000 be reachable? | Only this computer, or a quick link anyone with the address can open. |

## What it creates

- **`dev`** — the sandbox, with your project's copy at `/workspace`, its own disk at `/root`, and
  your chosen tools installed.
- **`storage`** — the volume holding `/root`, so what the tools install survives a restart.
- A quick link to port 3000, only if you chose one.

## What is synced, and what is not

**Synced, both ways**, between your folder and `/workspace`: every ordinary file, including ones
your `.gitignore` lists. New files, edits and deletions travel in both directions.

**Never synced**, because each side manages its own: `.git`, `.hg`, `.svn`, `node_modules`,
`.venv`, `venv` and `__pycache__`. The sandbox installs its own dependencies there; your
computer keeps its own. This also means a branch you check out on this computer does not change
the sandbox's `.git` — but it does change every file in your folder, and those travel.

Also left alone: symbolic links and junctions (they are never followed, so nothing outside your
folder is ever read or written), and names this computer cannot store.

## What happens when both sides change the same file

Nothing is ever replaced silently.

- A file changed on **one** side travels to the other.
- A file changed on **both** sides since they last matched is a conflict. Your copy is left
  exactly as it is, and the sandbox's copy is written beside it as `NAME.from-sandbox`. The setup
  says which file it is. That file stops syncing until only one version is left: delete the
  `.from-sandbox` copy, or replace your file with it, and syncing goes on by itself.
- The same rule covers deletions. A file you deleted is deleted in the sandbox only if the
  sandbox had not changed it; a file the sandbox deleted is deleted here only if you had not
  changed it. Otherwise it is a conflict and both are kept.
- If Yougori cannot read its own record of what the two copies last shared, it cannot tell which
  side is newer, so every file that differs keeps both copies until they match again. It never
  guesses.

The same rules run `yougori launch`'s two-way sync; both read them from one place in the code, so
they behave identically.

## Lifecycle

- **Stopping** the setup stops the sandbox and stops syncing. Both copies stay as they are.
- **Starting** it again syncs once at the start, then keeps syncing while it runs.
- **Removing** it deletes the sandbox and its volume. **Your folder and every file in it are left
  completely alone** — removing a setup never deletes anything in a folder you chose.

## Permissions

- The sandbox reaches exactly two folders of this computer: the one you chose for your project
  (it can change files there, which you agree to when applying) and the optional reference folder
  (read only, never changed).
- Nothing else on this computer is reachable from it.
- Your tools sign in inside the sandbox. This setup never copies a sign-in from this computer.

## Known limits

- **One sandbox per synced folder.** A folder can be kept in step with one sandbox only; two
  copies of the same folder would each mistake the other's changes for edits.
- **Conflicts are resolved by you**, by hand. There is no merge, and no three-way diff view: both
  versions are kept as whole files and you choose.
- **Syncing is by file, not by byte.** A changed file is copied whole, so very large files cost
  more than a small edit to them suggests.
- **SQLite databases are copied as ordinary files.** `yougori launch` snapshots them row by row;
  this setup does not. If your project has a live database inside the synced folder, stop what is
  writing to it before a sync pass, or keep it outside the folder.
- **No `.env` question yet.** `.env` files are synced like any other file here, where `yougori
  launch` asks first. Keep secrets out of the folder if that matters to you.
- **Port 3000 only.** The quick link opens port 3000 in the sandbox; run your app on that port.
- **One reference folder**, read only.

## Commands

```
yougori template run hub/yougori/dev-workspace --name my-project
yougori template status my-project
yougori template logs my-project
yougori terminal <sandbox>          # a shell in the sandbox, at /workspace
yougori template stop my-project    # stops the sandbox and the syncing
yougori template rm my-project --yes  # removes the sandbox; your folder is untouched
```

Scripted, the folders are given by their bindings:

```
yougori template run hub/yougori/dev-workspace --name my-project --yes \
  --allow-pc-access \
  --binding project=/home/you/code/my-project \
  --binding reference=/home/you/notes
```
