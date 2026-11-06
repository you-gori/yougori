# Example answers

Non-sensitive answers for a scripted run. The image name is an example; use your own.

```text
yougori template run ./examples/hub/backup-workflow --inputs answers/nightly.json --secrets - --yes
```

This template asks for no secrets, so pass `{}` on standard input.

- `nightly.json` — a quiet backup of `/data` every night at 02:00 in this computer's own time,
  keeping the last seven. The app is stopped while its data is copied.
- `weekdays-live.json` — `/var/lib/app` backed up on weekdays at 01:30 and on Sunday at 04:00 in
  `Europe/London`, keeping fourteen, with the app left running. The copy may catch a file
  half-written; see the README.
