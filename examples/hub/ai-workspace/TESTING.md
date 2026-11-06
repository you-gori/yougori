# AI Workspace: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or blocked checks are recorded as such. Use a disposable Yougori state directory and test accounts or test API keys created for the purpose; never a person's real sign-in.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| AW-P01 | `yougori template check ./examples/hub/ai-workspace --format text` with a 1.2.0 candidate | No errors |
| AW-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| AW-P03 | Publish scan and manual read | No keys or sign-in files |
| AW-P04 | Every question is used; sign-in sources are `computer`/`new` choices | Lint and parser agree |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| AW-L01 | `answers/codex-subscription.json` | One sandbox; Codex installed with a sign-in window; no API key asked |
| AW-L02 | Codex with `codex_access: api` | API key asked; no sign-in window; `OPENAI_API_KEY` bound |
| AW-L03 | `answers/several-tools.json` | Only the picked tools' questions asked and only those tools installed |
| AW-L04 | Ollama only | No sign-in or key questions |
| AW-L05 | Same answers twice | Same plan digest |

## 3. Runtime acceptance (plan 14)

| ID | Scenario | Pass when |
| --- | --- | --- |
| AW-R01 | One tool, subscription | Separate login window; setup terminal stays usable; "needs sign-in" until the tool reports signed in |
| AW-R02 | Several tools, mixed access | Each tool installed once; only API-key tools receive their variable |
| AW-R03 | Copy sign-in declined | No sign-in file on this computer is read |
| AW-R04 | Retry after an interrupted install | No duplicate sandbox; installed tools not reinstalled needlessly |
| AW-R05 | File in `/workspace`, restart, update | The file survives |
| AW-R06 | `yougori codex --environment NAME` after setup | Opens this sandbox; no second sandbox |
| AW-R07 | Remove the setup | Sandbox removed; `/workspace` volume kept until deleted separately |
| AW-R08 | Published download through the desktop app and the CLI | Both produce a working sandbox |
