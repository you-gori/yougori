# Operations Dashboard: maintainer test specification

Record each result with its evidence level (static review, compile, unit or contract test, mocked
integration, isolated runtime acceptance, publication and download verification), the command, the
commit, the platform and the outcome. Skipped or blocked checks are recorded as such.

Use a disposable Yougori state directory with two or three throwaway setups. The redaction rows
below are the point of this recipe: run them against setups deliberately named and configured
with values a person would mind seeing.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| OD-P01 | `yougori template check ./examples/hub/operations-dashboard --format text` with a 1.2.0 candidate | No errors |
| OD-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0"; nothing created |
| OD-P03 | Publish scan and manual read | No secrets, real domains or personal paths |
| OD-P04 | Every question is used | No unused input |
| OD-P05 | `cargo test --locked --manifest-path setup/Cargo.toml --test packages` | Checks clean, plans for both answer files, review accepted by the website's rules |
| OD-P06 | Read `yougori.yaml` | No `service_publication`, `internet: false` on `board`, and no resource that could reach the engine |

## 2. Plan and format checks

| ID | Answers | Expected |
| --- | --- | --- |
| OD-L01 | `answers/private.json` | `readings` volume and `board` sandbox only; port 8477; no publication |
| OD-L02 | `answers/long-history.json` | Port 9120, `KEEP_READINGS: "180"`, 1 GB |
| OD-L03 | `viewer_port: 80` | Refused: 1024 to 65535 |
| OD-L04 | `keep_readings: 0` or `501` | Refused: 1 to 500 |
| OD-L05 | Same answers twice | Same plan digest |
| OD-L06 | The review a publisher uploads | Two resources, two capabilities, no public access |

## 3. Telemetry API checks (engine; `src-tauri/src/setups/telemetry.rs`)

These do not need the package. They are the guarantees the README makes.

| ID | Check | Pass when |
| --- | --- | --- |
| OD-T01 | `cargo test --manifest-path src-tauri/Cargo.toml --lib -- --skip swarm:: setups::telemetry` | All pass |
| OD-T02 | A setup named with a person's name, an answer holding an email, a secret binding, an output holding a URL, a resource with a runtime name and an image reference, and a drift sentence naming a container | None of those strings appears anywhere in the reading, at any depth (`the_reading_holds_no_secret_no_path_no_address_and_no_name`) |
| OD-T03 | A failed operation whose refusal sentence names an image | The reading shows `errorCode` only; the sentence and the image are absent |
| OD-T04 | An operation completed 180 days ago | Not counted; `windowDays` says 30 |
| OD-T05 | `--limit 300` | Brought back to 50; `page.maxLimit` says 50 |
| OD-T06 | `--limit 0` | Brought up to 1 rather than refused |
| OD-T07 | More setups than one page | `page.next` gives the cursor; asking again with it returns the rest and no overlap |
| OD-T08 | A setup id the caller may not read | The same refusal `yougori template status` gives for it; no partial reading |
| OD-T09 | Read the answer with no setups at all | A valid, empty reading with its bounds and `notShown` still present |
| OD-T10 | `notShown` and `retention.words` | Present in every answer, including the empty one |

## 4. Runtime acceptance (plan 15, row `operations-dashboard`)

| ID | Scenario | Pass when |
| --- | --- | --- |
| OD-R01 | Run `answers/private.json` | `board` healthy; `readings` created and empty; the folder listing answers on the chosen port |
| OD-R02 | `yougori setup telemetry --format json` with three setups | A reading naming three setup ids, with states, health and counts |
| OD-R03 | Copy a reading in and reload the board | The file is listed and opens as JSON |
| OD-R04 | Watch the board's network while it runs | No outbound connection at all; `internet: false` holds |
| OD-R05 | Stop one setup, take a new reading | That setup reads `stopped`; its backup schedule reads paused |
| OD-R06 | Break a setup (remove its container outside Yougori), refresh it, take a reading | The resource id appears under `drifting`; no sentence about it appears |
| OD-R07 | Fail an operation on a setup, take a reading | `operations.failed` goes up; `last.errorCode` is the code; no sentence |
| OD-R08 | A setup with a backup schedule | `backups.volumes`, `kept` and `nextInSeconds` are right; no clock time and no path |
| OD-R09 | Stop the dashboard setup | The board stops; the readings volume and its files stay |
| OD-R10 | Remove the dashboard setup | The volume and the readings stay until deleted separately, and the removal review says so |
| OD-R11 | Run the housekeeping command with more readings than `keep_readings` | Exactly the newest `keep_readings` remain; nothing outside `/readings` is touched |
| OD-R12 | Search the whole board folder for any of the planted values from OD-T02 | None found |

## 5. Not tested here, and why

- **Notifications.** There are none, so there is nothing to test. A row will be added when, and
  only when, a destination a person configures by hand exists.
- **Per-setup resource usage.** Not measured by the engine; not shown; nothing to check.
- **Trends over time.** The board keeps files; it does not compare them.
