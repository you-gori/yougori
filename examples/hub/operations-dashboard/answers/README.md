# Example answers

Non-sensitive answers for a scripted run.

```text
yougori template run ./examples/hub/operations-dashboard --inputs answers/private.json --secrets - --yes
```

This template asks for no secrets, so pass `{}` on standard input.

- `private.json` — the defaults: the board on port 8477, keeping the last 30 readings.
- `long-history.json` — a longer run of readings (180) on port 9120, with a little more memory.

Neither publishes anything. There is no answer that does: the board has no publication and no
internet, and the template offers no way to give it either.
