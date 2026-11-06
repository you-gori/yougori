# Agent Tools: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or
blocked checks are recorded as such. Use a disposable Yougori state directory, a throwaway project
folder and a throwaway reading folder.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| AG-P01 | `yougori template check ./examples/hub/agent-tools --format text` with a 1.2.0 candidate | No errors |
| AG-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| AG-P03 | Publish scan; the package names no folder, key or setup id | Clean |
| AG-P04 | `tools/repo-map/yougori-tool.yaml` read as a tool | Checks clean, no network in its install lines |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| AG-L01 | `answers/read-only.json` | One sandbox; Claude Code and `repo-map` only; project mounted read only; `permissions.edit` false |
| AG-L02 | `answers/offline-editor.json` | `internet` false and `permissions.edit` true in the plan |
| AG-L03 | A tool named `hub/PUBLISHER/NAME` | Refused at review: Hub tools are not installed by a setup |
| AG-L04 | Same answers twice | Same plan digest |
| AG-L05 | `reference` binding left empty | Plans without the reading folder; no `/reference` mount |
| AG-L06 | `project_writable: false` | The project is a read-only mount and `permissions.edit` is false; no sync entry |
| AG-L07 | `project_writable: true` | The project is a two-way sync and `permissions.edit` is true |

## 3. Runtime acceptance (plan 15)

| ID | Scenario | Pass when |
| --- | --- | --- |
| AG-R01 | Apply `answers/read-only.json`, start the sandbox | Only Claude Code and `repo-map` are on the path; no other chosen tool exists |
| AG-R02 | Read `/workspace/AGENTS.md` | It lists exactly the installed tools, the granted folders and the real network state, and says there are no credentials |
| AG-R03 | Turn the internet off and start again | `AGENTS.md` says there is no internet, and a network call from inside fails |
| AG-R04 | Drop a tool and start again | That tool is gone from `AGENTS.md` and from the path |
| AG-R05 | Read-only project: change a file in `/workspace` | The owner's folder is unchanged |
| AG-R06 | Writable project: change a file in `/workspace` | The change appears in the owner's folder |
| AG-R07 | From inside, try to read a path outside the granted folders | Refused; nothing outside them is visible |
| AG-R08 | From inside, try to reach the Access Grid or any Yougori engine API | Refused; there is no route and no credential |
| AG-R09 | `repo-map` on the project | Lists the project's files and sizes, and nothing outside it |
| AG-R10 | Copy a tool's sign-in from this computer when asked | Only that tool's own sign-in file arrives; no other credential is present |
| AG-R11 | Remove the setup | The sandbox and its disk go; the owner's project folder and reading folder are untouched |
