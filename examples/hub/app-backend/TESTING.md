# App Backend: maintainer test specification

Record each result with its evidence level, command, commit, platform and outcome. Skipped or blocked checks are recorded as such. Use a disposable Yougori state directory and a small test app image that reads the variables in the README, creates one table and answers `/health`.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| AB-P01 | `yougori template check ./examples/hub/app-backend --format text` with a 1.2.0 candidate | No errors |
| AB-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0" |
| AB-P03 | Publish scan | Clean |

## 2. Plan checks

| ID | Answers | Expected |
| --- | --- | --- |
| AB-L01 | `answers/with-cache.json` | `app`, `db`, `cache`, both connections, `web` |
| AB-L02 | `answers/database-only.json` | No `cache` or `app_to_cache`; `REDIS_HOST` left out |
| AB-L03 | `db_password` shorter than 16 characters | Refused |
| AB-L04 | Same answers twice | Same plan digest |

## 3. Runtime acceptance (plan 15: app-backend)

| ID | Scenario | Pass when |
| --- | --- | --- |
| AB-R01 | Run `answers/with-cache.json` with the test image | App healthy; it writes and reads a row and a cache key |
| AB-R02 | From the database or cache sandbox, try to reach the app | Refused (one-way) |
| AB-R03 | From this computer's network, try the database port | Not reachable |
| AB-R04 | Restart everything; update to a new app image | Rows and cache data survive |
| AB-R05 | Turn the cache off | Cache container removed; its volume kept |
| AB-R06 | Remove the setup | Containers removed; three volumes kept until deleted separately |
| AB-R07 | Run twice on one computer | Separate containers, volumes, secrets and hosts |
