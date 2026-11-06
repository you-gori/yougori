# Operations Dashboard

A private board showing how your setups are doing: each one's state and health, what its
resources are doing, how its recent operations went and whether its backups are being taken.

Everything it shows comes from one command, `yougori setup telemetry`, which works the reading
out when you ask for it and answers. **Nothing is collected in the background, nothing is stored
for it, and nothing is sent anywhere.**

## What it creates

| Resource | What it is |
| --- | --- |
| `readings` | A named volume holding the readings you take. One small JSON file each. |
| `board` | A container that serves that folder on this computer and does nothing else. No internet, no publication, and no way to reach the setup engine. |

## What the reading shows

Per setup:

- its id, its state (`running`, `stopped`, `creating`, …) and its health (`ready`, `degraded`,
  `needs_sign_in`, `not_checked`, …);
- how many resources it owns and borrows, counted by kind, by observed state and by cost, how
  many are keeping data, and the ids of any that are no longer what the setup asked for;
- its operations in the last 30 days: how many, how many failed, counted by state and by kind,
  and the last one's kind, state, step count, how long it took, how long ago it finished and its
  refusal **code** if it failed;
- its backup volumes: how many copies are kept, how many schedules are paused, how many are
  failing, how the last run went and how many seconds until the next one is due.

Plus the bounds and the list of omissions, in the answer itself.

## What it deliberately does not show

This is the part worth reading twice. The reading is redacted at the source, and there is no
setting, flag or mode that turns any of it back on.

- **No names.** Not the setup's name, not the template's, not a resource's runtime name. The
  reading carries nothing a person typed — no questions and no answers either.
- **No secrets.** No credential name, no secret binding name, no token, no API key, no password.
  Sign-in state appears only as the word `needs_sign_in`.
- **No addresses.** No URL, link, domain, port, IP address or share link.
- **No paths.** No filesystem path, folder name, drive, image name or account name.
- **No prose.** No log lines, no step messages and no refusal sentences. A failed operation shows
  its code — `image_not_found` — and nothing else, because a sentence is written about the world
  and can carry anything in it.
- **No wider view.** The reading covers exactly the setups you can already list, and refuses a
  setup you may not read in the same words `yougori setup show` would. There is no administrator
  mode and no "everything on this computer" mode. It cannot show you more than you could already
  see; that is the whole point of it being read-only.
- **No history.** Operations finished more than **30 days** ago are not counted, and at most 50
  are counted per setup. The reading is a picture of now, not a record.
- **No notifications.** Nothing emails, messages or posts anywhere when something fails. This is
  deliberate: a dashboard that quietly phones somewhere is the opposite of what this is for. If
  notifications are ever added, they will need a destination you configure by hand and will be
  off until you do.
- **No usage figures.** There is no CPU, memory, disk or network measurement here. The engine does
  not observe those per setup, and this board does not guess.

Ids do appear: setup ids, resource ids, capability ids and kind names. Each one is checked before
it leaves the engine, and anything that is not a short plain id — anything with a space, a slash,
an `@` or a colon in it — is replaced with `(hidden)` rather than shown.

## Bounds

| Bound | Value |
| --- | --- |
| Setups per page | 20 by default, 50 at most. The answer gives the cursor for the next page. |
| Operations counted | Finished within 30 days, at most 50 per setup. |
| Readings kept | However many you choose (default 30). The housekeeping command below deletes the oldest; nothing is deleted for you. |

## Using it

Take a reading:

```text
yougori setup telemetry --format json
```

Keep it on the board:

```text
yougori setup telemetry --format json > reading.json
yougori cp reading.json {{instance}}/board:/readings/
```

Read one setup on its own, or ask for the next page:

```text
yougori setup telemetry SETUP
yougori setup telemetry --limit 50 --cursor 50
```

Open the board:

```text
yougori open {{instance}}
```

The board lists the folder, newest file last. Each file is plain JSON; the terminal view is often
easier, and `yougori setup telemetry` on its own gives you that without the board at all.

Housekeeping, when you have more readings than you want to keep:

```text
yougori exec {{instance}}/board -- sh -c 'ls -1t /readings | tail -n +$((KEEP_READINGS+1)) | sed "s|^|/readings/|" | xargs -r rm --'
```

## Known limits

- **The board cannot take its own readings.** It is a file server with no internet and no access
  to the setup engine, by design. You run the command; the board only shows what you put there.
  Nothing refreshes on its own, and a board you have not fed shows an empty folder.
- **It is a folder of JSON, not a chart.** There are no graphs, no trends over time and no
  alerting. Comparing two readings means reading two files.
- **No per-setup resource usage.** See above: the figures do not exist to show.
- **Health is as fresh as the last observation.** The engine records what it last saw; a setup
  that has not been refreshed shows `not_checked` rather than a guess. `yougori template status`
  refreshes it.
- **Removed setups disappear.** Once a setup is gone it is not in any later reading, and the
  readings you already took are the only trace. They are files; back them up or do not.
- **Container sandboxes only**, like every file-serving recipe here.
- **One board per computer is the sensible number.** Nothing stops you running two; they will
  show the same readings if you feed them the same files, and nothing synchronises them.
- **This is not an audit log.** It is bounded, redacted and recomputed. If you need a record of
  who did what, the setup's own operation history is the place, not this.

## Example answers

See `answers/`. `private.json` is the defaults; `long-history.json` keeps more readings on a
different port. Neither publishes anything, and no answer here can.
