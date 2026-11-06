# My API: maintainer test specification

Record each result with its evidence level (static review, compile, unit or contract test, mocked integration, isolated runtime acceptance, publication and download verification), the command, the commit, the platform and the outcome. Skipped or blocked checks are recorded as such.

Use a disposable Yougori state directory, test provider accounts or none, and a wallet address you control on a test network or none. Never test against a site people use, a real buyer or a real payment.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| MA-P01 | `yougori template check ./examples/hub/my-api --format text` with a 1.2.0 candidate | No errors |
| MA-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0"; nothing created |
| MA-P03 | `setup/tests/packages.rs` over a copy including this package (`YOUGORI_EXAMPLES`) | Checks clean, plans `answers/*.json` deterministically, review accepted |
| MA-P04 | Publish scan and manual read | No secrets, real wallets, real domains or personal paths |
| MA-P05 | Every question is used | No unused input |
| MA-P06 | The Hub's 1.6.0 | Unchanged: same digest as before this version |

## 2. Offline suites

| ID | Command (from the repository root) | Pass when |
| --- | --- | --- |
| MA-O01 | `python -B examples/hub/my-api/tests/test_service.py` | All tests pass with no network access beyond loopback |
| MA-O02 | `python -B examples/hub/my-api/tests/test_prices.py` | All tests pass |
| MA-O03 | `python -B examples/hub/my-api/tests/test_tool_models.py` | All tests pass |
| MA-O04 | `node examples/hub/my-api/tests/models-ui.cjs` | Prints "Models UI passed" |
| MA-O05 | `node examples/hub/my-api/tests/theme-ui.cjs` | Prints "Theme UI passed" |
| MA-O07 | `python -B examples/hub/my-api/tests/test_models_sandbox.py` | Selected services use separate ports; a crashed process restarts without restarting its neighbour; stop reaps all children |
| MA-O06 | MA-O01 with provider variables exported in the shell (`SELECTED_PROVIDERS`, `OPENCODE_*`, `KILO_*`) | Same result; no outbound request |

## 3. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| MA-L01 | `answers/paid-and-free.json` | `web`, `models`, the publication and one `web_to_models` connection on ports 8080, 8081 and 11434 |
| MA-L02 | `answers/claude-only.json` | The same two sandboxes; only the paid bridge starts in `models` |
| MA-L03 | `answers/ollama-only.json` | The same two sandboxes (GPU optional); only Ollama starts in `models` |
| MA-L04 | `web_access: domain` without a saved domain | Refused with a pointer to `yougori domain add` |
| MA-L05 | `codex_access: subscription` | The sign-in source is asked with no preset answer |
| MA-L06 | Same answers twice | Same plan digest |
| MA-L07 | `answers/all-tools.json` | Two sandboxes; all five tools install in `models`, with Codex using computer credentials and Gemini opening a new sign-in |

## 4. Runtime acceptance (plan 14)

| ID | Scenario | Pass when |
| --- | --- | --- |
| MA-R01 | Run MA-L02 with a test Anthropic key | The admin signs in; the model list fills by itself; a key answers a chat request and the usage is billed |
| MA-R02 | Configure: add Ollama, then remove it | Only selected services/tools change inside `models`; the two sandboxes and website data remain |
| MA-R03 | Save a wallet with a mistyped checksum, then a correct one with a token | The first is refused with a plain message; buyers see the address, token and check note |
| MA-R04 | A buyer asks for credits six times | The sixth is refused; cancelling one allows another |
| MA-R05 | Confirm two requests with the same transaction id | The second is refused naming the first; credits added once |
| MA-R06 | Reject a request | No credits move; the buyer sees Rejected |
| MA-R07 | Start 2.0.0 on a copy of a 1.6.0 `my-api-data` volume | A checked copy appears in `/data/backups`; accounts, balances, keys, prices and the wallet are intact |
| MA-R08 | Same with `/data/backups` made unwritable | The website stops with the plain message; the database is unchanged |
| MA-R09 | Sign out of a provider while a key is in use | The provider's models leave the list at the next failed request; Provider connections shows the fix |
| MA-R10 | Stop the gateway bridge for over three minutes | Free-only models are refused with the reason; they return when discovery runs again |
| MA-R11 | Remove the setup | Sandboxes removed; `my-api-data` and `my-api-models` kept until deleted separately |
| MA-R12 | A 1.6.0 instance on the same computer | Keeps running on 1.6.0; untouched by the 2.0.0 setup |
| MA-R13 | Run the published download through the desktop app and the CLI | Both reach a working website |
