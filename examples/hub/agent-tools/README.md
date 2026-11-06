# Agent Tools

A coding agent with exactly the tools and folders you grant it, and nothing else.

Agent Tools runs a coding agent in its own sandbox. You choose which tools it has, which folder it
works on, whether it may change that folder, whether it reaches the internet, and nothing else is
there. When the sandbox starts, Yougori writes the agent's instructions from the access the setup
really has, so what the agent is told and what it can do are the same thing.

```text
yougori template run ./examples/hub/agent-tools
```

From the Hub, search for "Agent Tools", or run `yougori run hub/PUBLISHER/agent-tools@1.0.0` with
the publisher shown on its Hub page.

## Questions it asks

| Input | Type | Default | Notes |
| --- | --- | --- | --- |
| `image` | text | `ubuntu:24.04` | The container the agent works in; pin a version |
| `tools` | multiple choice | Claude Code | Codex, Claude Code, Gemini CLI, OpenCode, Kilo |
| `*_signin_source` | choice | new | Copy that tool's sign-in from this computer, or sign in fresh |
| `project_writable` | yes/no | no | May the agent change your project? With no, the folder is mounted read only; with yes, it is synced both ways |
| `reference_path` | text | `/reference` | Where the optional reading folder appears |
| `internet` | yes/no | yes | May the agent reach the internet? |
| `cpu`, `memory_gb`, `storage_gb` | number | 4, 8, 40 | The sandbox's size |

Setup also asks which folder holds your project, and optionally one folder to read. Those choices
belong to your computer and are never part of the template.

Example answers are in [`answers/`](answers).

## What it creates

- One container sandbox with only the tools you picked, installed by Yougori's own installer.
- A copy of your project at `/workspace`, kept in step with your folder. Your folder is never
  mounted into the sandbox, so nothing in the sandbox can reach the rest of your disk through it.
- The reading folder you chose, if any, mounted read only.
- `AGENTS.md` in the project, written at every start from the grants above.

## The custom tool that travels with it

[`tools/repo-map`](tools/repo-map) is a tool bundled in this template: a small command that lists
a project's files and their sizes. It is installed from this folder, runs no network calls, and
is covered by the same check Yougori runs for any tool. It is always installed: a bundled tool
takes no options, so it cannot be made conditional. A tool published on the Hub cannot be
installed by a setup yet (see Known limits), so a template that needs its own tool bundles it
like this one.

## The instructions the agent is given

`AGENTS.md` is generated, not written by hand. Each line is there only because Yougori granted
that thing: the tools listed are the ones actually on the path, the folders listed are the ones
actually mounted or synced, and the network line says what the sandbox can actually reach. A
grant you take away disappears from the file at the next start. The file ends by telling the
agent to stop and say so when something is refused, rather than looking for another route.

## What is refused

- **Tools you did not pick are not installed.** The sandbox has no package of them to run.
- **Folders you did not grant are not reachable.** There is no mount and no path to them.
- **With the internet off, nothing leaves the sandbox**, including a tool trying to sign in.
- **With the project read only, changes stay in the sandbox** and are never copied back.
- **There is no credential anywhere in the sandbox**, so an agent cannot use one, leak one, or be
  talked into fetching one.

## Known limits

- **Scoped credentials from an Access Grid cannot reach a sandbox yet, so this template gives the
  agent none.** An Access Grid exists so that a credential's value never reaches an agent or its
  model provider: the hub holds the secret, applies your rules and sends the request itself. Today
  it will only do that for a signed-in person's computer, and there is no way for a sandbox to ask
  it. Giving the agent a key instead would be the very thing the Access Grid prevents, so this
  template does not. An agent that needs a credentialled call makes it through you, outside the
  sandbox, until that path exists.
- **Tools published on the Hub are refused at setup.** Use a built-in tool or bundle one in the
  template, as `tools/repo-map` does.
- **A tool's own sign-in is that tool's business.** Copying a sign-in from this computer happens
  once, only for the tool it belongs to, and only after you choose it when applying. The agent can
  then use that tool's account; if you do not want that, choose a fresh sign-in or leave the tool
  out.
- **The instructions are advice, not a fence.** The fence is the sandbox: the missing tools, the
  missing folders and the missing network. `AGENTS.md` tells the agent what the fence is so it
  stops asking, but a tool that ignores it still cannot get past the sandbox.
- **One agent per setup.** Run it again for a second agent, with its own folders.
- **The bundled file-map tool is always installed.** Yougori's tool options apply to built-in
  tools only, so a template's own tool cannot be switched off by an answer. Remove it from the
  template if you do not want it.
- **Changing the project between read only and writable changes which folder question you are
  asked**, because the two are different grants: a read-only mount and a two-way sync.
- **The sandbox does not start by itself.** Start it from My setups or with
  `yougori start NAME`, so an agent never runs unattended after a restart.
- **The Health and logs view is planned.** It is listed as planned in setup and can't be turned on
  yet; `yougori template status NAME` and `yougori template logs NAME` show the setup's state and
  activity meanwhile.

## Files

| File | Purpose |
| --- | --- |
| `yougori-template.yaml` | Questions, bindings, tools, steps and outputs |
| `yougori.yaml` | The sandbox, its folders and its tool list |
| `rules/write-instructions.sh` | Writes `AGENTS.md` from the live grants at every start |
| `tools/repo-map/` | The bundled custom tool |
| `answers/` | Example answers |
| `TESTING.md` | What maintainers check before publishing a version |
| `CHANGELOG.md` | Version history |
| `LICENSE` | MIT |
