# Dev Workspace: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or
blocked checks are recorded as such. Use a disposable Yougori state directory and a throwaway
project folder — never a folder you keep work in, since section 3 edits files in it.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| DW-P01 | `yougori template check ./examples/hub/dev-workspace --format text` with a 1.2.0 candidate | No errors; both folder bindings listed with their access |
| DW-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| DW-P03 | Publish scan | Clean; the published review holds no path of this computer |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| DW-L01 | `answers/with-tools.json` with both bindings | `dev`, `storage`, `public_dev`; `sync[0].path` is the chosen folder, `read_only: false` |
| DW-L02 | `answers/plain.json` with only `project` | No `pc_access` entry; `public_dev` with access `none` |
| DW-L03 | No folder given for `project` | Refused with `awaiting_binding` |
| DW-L04 | `project` given as a relative path (`./code`) | Refused with `invalid_answer` |
| DW-L05 | Same answers twice | Same plan digest; the lock holds no folder |
| DW-L06 | The review | Names both folders, says which is writable, and warns about each |

## 3. Runtime acceptance (plan 15: dev-workspace)

Each needs a real sandbox, so each is run on a supported runtime with a throwaway folder.

| ID | Scenario | Pass when |
| --- | --- | --- |
| DW-R01 | Apply without agreeing to the writable-folder consent | Refused before anything is created, saying the agreement is needed |
| DW-R02 | Apply with the consent; look in the sandbox | Every file of the folder is at `/workspace`; `.git` and `node_modules` are not |
| DW-R03 | Edit a file on this computer, then sync | The sandbox's copy matches |
| DW-R04 | Edit a different file in the sandbox, then sync | This computer's copy matches; the file edited in DW-R03 is untouched |
| DW-R05 | Edit the same file on both sides, then sync | Both copies kept; `NAME.from-sandbox` appears beside yours; yours is unchanged; the setup says which file |
| DW-R06 | Delete the `.from-sandbox` copy and make the two match | That file syncs again by itself |
| DW-R07 | Delete a file on one side only, then sync | It is deleted on the other side |
| DW-R08 | Delete a file on one side and edit it on the other | Both kept; nothing is deleted |
| DW-R09 | Stop the setup, edit both sides, start it again | Both edits survive; only genuine conflicts are kept twice |
| DW-R10 | Remove the setup | The sandbox and its volume go; the folder and every file in it are untouched |
| DW-R11 | Put a symlink in the folder that points outside it | It is not followed; nothing outside the folder is read or written |
| DW-R12 | A reference folder: try to write to `/reference` in the sandbox | Refused; the folder on this computer is unchanged |
| DW-R13 | Run an app on port 3000 with access `quick` | Its quick link opens it |
| DW-R14 | Install a tool, sign in inside the sandbox | The sign-in is in the sandbox; nothing on this computer was read |
