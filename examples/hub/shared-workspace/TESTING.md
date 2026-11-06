# Shared Workspace: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or blocked checks are recorded as such. Use a disposable Yougori state directory, a disposable test sandbox and a synthetic recipient on a second test computer or account.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| SW-P01 | `yougori template check ./examples/hub/shared-workspace --format text` with a 1.2.0 candidate | No errors |
| SW-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| SW-P03 | Publish scan; the package names no sandbox or setup id | Clean |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| SW-L01 | `answers/view-folder.json` | One share entry, view on `/workspace`, 24 hours |
| SW-L02 | `permission: edit` with an empty folder | Refused: edit needs a folder |
| SW-L03 | `expires_hours` empty | Share without expiry; the review says "until it is revoked" |
| SW-L04 | Same answers twice | Same plan digest |

## 3. Runtime acceptance (plan 14)

| ID | Scenario | Pass when |
| --- | --- | --- |
| SW-R01 | Owner shares a test sandbox with view on `/workspace` | Recipient lists and reads files there; no terminal; nothing outside the folder |
| SW-R02 | Edit permission | Recipient changes a file in the folder; paths outside it and links are refused |
| SW-R03 | Control permission | Recipient opens a terminal; owner's workload keeps running |
| SW-R04 | Revoke while the recipient is connected | Their sessions close at once; the owner's sandbox keeps running |
| SW-R05 | Expiry passes | Access ends without action |
| SW-R06 | Wrong password | Refused, and repeated failures are rate-limited |
| SW-R07 | Remove the setup | Share removed; the sandbox untouched |
