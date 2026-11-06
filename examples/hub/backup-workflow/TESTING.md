# Backup Workflow: maintainer test specification

Record each result with its evidence level (static review, compile, unit or contract test, mocked
integration, isolated runtime acceptance, publication and download verification), the command, the
commit, the platform and the outcome. Skipped or blocked checks are recorded as such.

Use a disposable Yougori state directory and a small public test image that listens on 8080 and
writes a file into its data path. Never test against data someone uses. Every restore check below
is done on test data that can be lost.

## 1. Package checks

| ID | Check | Pass when |
| --- | --- | --- |
| BW-P01 | `yougori template check ./examples/hub/backup-workflow --format text` with a 1.2.0 candidate | No errors |
| BW-P02 | Same with a 1.1.x CLI | Early "requires Yougori 1.2.0"; nothing created |
| BW-P03 | Publish scan and manual read | No secrets, real domains or personal paths |
| BW-P04 | Every question is used | No unused input |
| BW-P05 | `cargo test --locked --manifest-path setup/Cargo.toml --test packages` | Checks clean, plans for both answer files, review accepted by the website's rules |

## 2. Plan and format checks

| ID | Answers | Expected |
| --- | --- | --- |
| BW-L01 | `answers/nightly.json` | `app`, `backup`, `app-data` with `backupSchedule: daily 02:00`, `backupKeep: 7` as a number, `backupThrough: {resource: backup}`; no `web` |
| BW-L02 | `answers/weekdays-live.json` | `backupConsistency: live`, `backupTimezone: Europe/London`, `backupOverlap: queue`; `web` with a quick link |
| BW-L03 | `backup_schedule: nightly` | Refused: a schedule names its days and a time |
| BW-L04 | `backup_schedule: daily 25:00` | Refused: not a time |
| BW-L05 | `backup_timezone: Mars/Olympus` | Refused, naming `local`, UTC, an offset and example zones |
| BW-L06 | `backup_keep: 0` or `91` | Refused: 1 to 90 |
| BW-L07 | A `backup_through` naming a sandbox that does not mount the volume | Refused before anything is created |
| BW-L08 | `backup_consistency: stop` with only the reading sandbox mounting the volume | Refused: nothing would be stopped; use its own sandbox or say `live` |
| BW-L09 | Same answers twice | Same plan digest |
| BW-L10 | The review a publisher uploads | Shows the schedule, the zone, the retention and the consistency as scalars |

## 3. Runtime acceptance (plan 15, row `backup-workflow`)

| ID | Scenario | Pass when |
| --- | --- | --- |
| BW-R01 | Run `answers/nightly.json` with the test image | App healthy; `backup` running; the setup page shows the next backup time in this computer's own time |
| BW-R02 | Write files to the data path, then force the schedule's time to pass | One backup appears, with the file count and a checksum; the app was stopped and started again |
| BW-R03 | **Restore drill.** Back up, change and delete files, restore into a copy | The copy holds exactly what was backed up; the volume is unchanged |
| BW-R04 | **Restore drill.** Then restore over the original after the review | The volume holds exactly what the backup held; a fresh backup gives the same checksum |
| BW-R05 | Close Yougori over two scheduled times, start it again, `run_once` | Exactly one catch-up backup, not one per missed time |
| BW-R06 | The same with `skip` | No catch-up; the setup page says the backup was left out and when the next is |
| BW-R07 | A backup slower than its gap, overlap `skip` | The second is left out and noted; with `queue`, exactly one runs after |
| BW-R08 | Make a backup fail (stop the `backup` sandbox mid-copy) | Retried up to the limit, then recorded as failed; no half-made backup is kept; the app is running again |
| BW-R09 | Stop the setup | The schedule pauses and keeps its place; nothing runs; starting it resumes |
| BW-R10 | Remove the setup | The schedule goes; the backups taken stay until deleted separately, and the setup says so |
| BW-R11 | Edit a file inside a kept backup, then restore | Refused: the backup's files have changed since it was made; the volume is untouched |
| BW-R12 | Take `backup_keep + 2` backups | Only `backup_keep` remain; the oldest were deleted after the newest was complete |
| BW-R13 | A schedule crossing the night the clocks go forward (`Europe/London`, `daily 01:30`, 29 March) | One backup that night, at 01:30 UTC, which the clocks show as 02:30 |
| BW-R14 | The same for the night they go back (25 October) | One backup, not two |
| BW-R15 | `backup_consistency: live` with a database on the volume | The review warns before the run; the restored copy is checked by hand and the limitation is confirmed in the README |
| BW-R16 | Close Yougori while a backup is running | The run stops; nothing half-made is kept; the app is started again; the next time is unchanged |
| BW-R17 | Run the published download through the desktop app and the CLI | Both back up and restore |

## 4. What is deliberately not claimed

- No copy of a backup to another computer, no cloud destination, no encryption at rest.
- No recovery if this computer or its disk is lost (BW-R17 does not test it; the README says so).
- Nothing sealed in the credential store is in a backup, so a restored setup asks for it again.
- The schedule runs only while Yougori runs; it is not a system service.
