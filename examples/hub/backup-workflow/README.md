# Backup Workflow

Your app, its data on a volume, and that volume backed up on a schedule you choose.

Yougori takes the backups itself: it does not run a backup tool inside your app's sandbox and it
does not need your app to know anything about backups. Each backup is a copy of every file on the
volume, with a checksum of each file and of the whole set, kept in Yougori's own data folder on
this computer.

## What it creates

| Resource | What it is |
| --- | --- |
| `app` | Your container image, listening on port 8080, with its data on the `app-data` volume at the path you choose. |
| `app-data` | The named volume your data lives on. This is what is backed up. |
| `backup` | A small Alpine sandbox that mounts the same volume and runs nothing else, with no internet access. Yougori reads backups out through it and puts restores back through it. |
| `web` | A public address for the app, only if you ask for one. |

## What is backed up, and what is not

**Backed up:** everything under the data path on the `app-data` volume, as files.

**Not backed up:**

- Anything your app keeps outside that volume. Files written to the sandbox's own disk are not on
  the volume and are not in the backup.
- Anything sealed to this computer. Passwords, API keys and other values in Yougori's credential
  store stay here; a setup restored from a backup asks for them again. A backup cannot carry them,
  and nothing here pretends it can.
- The app's image. A backup holds data, not the program. You need the same image to use it.

A backup is kept on this computer's own disk, in Yougori's data folder. **That is not disaster
recovery.** If this computer or its disk is lost, the backups go with it. Copy that folder to
another disk or another machine if you need to survive losing this one. This template does not do
that for you, and does not claim to.

## The schedule

You write the times in words. Examples:

```text
daily 02:00
weekdays 01:30
Mon-Fri 01:30; Sun 04:00
daily 02:00,14:00
```

Days can be `daily`, `weekdays`, `weekends`, a day (`Mon`), a range (`Mon-Fri`, which may wrap as
`Sat-Mon`) or a list (`Mon,Thu`). Times are 24-hour.

**Time zone.** `local` follows this computer's clock, including its summer-time changes. You can
also name a zone such as `Europe/London` or `America/New_York`, or a fixed offset such as
`UTC+02:00`, which never changes for summer time. Yougori keeps the times in UTC internally and
works out each run in the zone you named, so a schedule means the same thing wherever the records
are read.

**When the clocks change.** On the night the clocks go forward, a time that does not exist that
day runs with the offset in force before the change: 02:30 runs when the clocks show 03:30. On the
night they go back, a time that happens twice runs once, the first time. This is the rule
calendars use (RFC 5545), so a nightly backup happens once a night either way.

**A backup Yougori was not running for.** With *Make one as soon as it can*, one backup catches up
however many times were missed — not one per missed night. With *Wait for the next time*, nothing
catches up.

**A backup that is due while the one before is still running.** With *Leave it out* (the default),
it is skipped and noted, so a backup that takes longer than its gap never piles up. With *Run it
straight after*, at most one waits.

**A backup that fails** is tried again up to the number of retries you set, waiting longer each
time, and then waits for its next time. Every attempt is written down and shown on the setup page.

Stopping the setup pauses its schedule and keeps its place. Starting it resumes. Removing the
setup drops the schedule; **the backups already taken stay** until you delete them, as data always
does here.

## How the copy is taken

You choose between two, and the review says plainly which you picked.

**Stop the app while it is copied (the default).** Before each backup, the app sandbox is stopped,
the volume is copied through the `backup` sandbox, and the app is started again. Nothing is writing
to the files while they are read, so the backup is of a consistent moment. Your app is unavailable
for the length of the copy.

**Keep the app running.** Nothing is stopped. This has no downtime, but a file being written at
that moment can be copied half-written. **A database kept on the volume may not open from such a
copy.** If your app keeps a database there, either use *Stop the app*, or have your app write its
own consistent dump into the volume on a schedule and accept that the live copy may be behind.

## Restoring

Restoring has two forms, and the first is the default.

**Into a copy.** The backup's files are put into a new folder inside the `backup` sandbox. Nothing
on the volume is touched. You look at the files, and copy across what you need. This is also how
you practise a restore without risk — do it once now, not on the day you need it.

**Over the data itself.** Yougori first checks the backup against its own record: every file still
there, the same size, the same contents. A backup that does not match is refused, not restored.
Then it shows you exactly what will happen — which backup, from when, how many files, and that
everything written since then will be gone — and only goes ahead when you confirm. The sandboxes
that write to the volume are stopped, the old contents are moved aside, the backup's files are put
in place, and the sandboxes start again. The old contents are deleted only once the new ones are
in place: if it stops halfway, nothing has been deleted and the setup page says where the previous
contents are.

Restoring puts files back. It does not undo anything your app did elsewhere — a message it sent,
a payment it took, a row it wrote in someone else's database.

## Known limits

- One volume is backed up. An app with data in two places needs two setups, or one volume.
- Backups are kept on this computer only. There is no copy to another machine, no cloud
  destination and no encryption of the kept copy. The folder has Yougori's own permissions and
  nothing more.
- Container sandboxes only. A microVM or a VM cannot be backed up this way.
- A backup must fit on this computer's disk: at most 200,000 files and 200 GB.
- Values in the credential store are not in a backup (above).
- The schedule runs only while Yougori is running. It is not a system service; closing Yougori
  stops the backups until it starts again, and the missed-run policy decides what happens then.
- The named time zones carry the summer-time rules in force when this version was built. A country
  that changes its rules needs a newer Yougori; `local` follows the operating system instead and
  is unaffected.
- There is no notification when a backup fails. The setup page shows it; nothing emails you.

## Example answers

See `answers/`. `nightly.json` is a quiet nightly backup of `/data`, keeping seven.
`weekdays-live.json` backs up on weekdays and Sunday in `Europe/London`, keeping the app running.
