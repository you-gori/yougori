# Shannon command prompt — 2026-11-04

The owner's second installation succeeded, but the normal command performed
only model validation and exited. Running it again created another VM and copied
the 388 MiB tool package again. That was a launcher workflow error, not a failed
model check. The earlier installer evidence remains historical.

The default command now opens `shannon>` inside the VM and waits for commands:
`check`, `shell`, `scan URL`, `logs`, `help`, `exit`. It never starts a scan by
itself. Checks and the shell return to the same prepared VM. One-shot flags still
work. `--no-tty` without a task is refused rather than hanging at a prompt.
Worker diagnostics are saved in `~/shannon-worker.log`, and errors keep their exit
codes. The website hint, installed help, and launcher README describe this flow.

## Evidence

- The real normal Windows/QEMU VM completed two model checks against the user's
  existing Qwen2.5-0.5B-Instruct server, with a real guest shell command between
  them. Both checks returned to the same prompt. Only one package preparation ran.
  The second check completed 4.6 seconds after the first, including the shell step.
- `exit` stopped the VM; the normal engine then reported zero active image guests.
- No Temporal task tokens or webpack output appeared in the session output.
- Six focused Linux tests passed, including repeated commands, explicit scan
  selection, refusal of an external target or missing project, EOF, and real
  subprocess success/failure exit codes with separate logs. Two final cleanup/error
  branch corrections were covered by these tests after the real session run.
- The harness Python suite passed 22 tests; the service suite passed 12 tests.
  Browser checks, frontend lint, and build passed (existing bundle-size warning).
- The published Shannon boot image was refreshed with the final runtime helpers;
  its pinned upstream tool package is unchanged. The installed Windows command
  was updated and its help was checked.

An initial test paused during image import because C: was low on space. Moved
the old publisher cache from
`C:/YougoriBuildCache/scratch/solver/solver-vm-images` to
`D:/YougoriBuildCache/scratch/solver-image-cache-from-c`, preserving it. The live
server uses the separate `D:/YougoriBuildCache/scratch/solver-vm-images` directory.
The repeated test succeeded after space was freed.

Full local logs: `C:/YougoriBuildCache/scratch/solver/shannon-session-real2.log`,
`shannon-session-unit.log`, `shannon-session-service.log`,
`shannon-session-browser.log`, `shannon-session-lint.log`,
`shannon-session-build.log`. `runtime_shannon_session.py --local --root PATH`
repeats the real connection/shell check; without `--local`, it uses disposable
service accounts and an HTTP model fixture.

## Limits

A new VM still needs its own tool preparation after exiting. This change keeps
one VM open across commands; it does not persist guest disks across shutdowns.
No penetration test was run. Connection success does not establish the selected
model's tool-calling support or its ability to complete a security task.
