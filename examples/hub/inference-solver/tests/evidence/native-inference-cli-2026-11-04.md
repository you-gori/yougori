# Native Yougori inference commands and owner-managed runtime

The website now shows `yougori inference connect URL` for contributors and
`yougori inference run HARNESS --server URL` for harnesses. Yougori bundles the
host client source, prepares its checksum-pinned private Python runtime on Windows,
and starts directly. It does not download host scripts from the website or install
separate solver commands. The previous installer endpoints remain available to
explicit callers; the website no longer advertises them.

Inference harness VMs, contributed VMs and the development website opt out of
idle and absolute expiry. Zero selects this behavior for the launch timers,
command deadline and owner-publication duration. Finite defaults/public exposure
limits remain bounded. Stop, revoke, engine supervision, connector disconnect,
workspace isolation and owner resource allocations remain enforced.

Validated on Windows:

- CLI library: 672 passed, 2 ignored. Includes guide, help coverage and new inference
  parsing/bundled-client checks. CLI command-line integration: 25 passed.
- Lease tests: 8 passed, including time advanced through a year without idle or
  absolute expiry, plus preservation of an explicitly retained idle timer.
- New owner-managed VM service test: passed. The freshly built engine test binary
  then passed all 34 VM service tests, including stop/revoke, audience controls,
  finite expiry, command cancellation and cleanup. A redundant Cargo recompilation
  after CLI documentation edits was cancelled; the tested binary already contained
  the final engine implementation and the new owner-managed test.
- `npm run check:native`: passed, 9 existing warnings. Engine and CLI built.
- Template infrastructure: 34 passed, including no four-hour inventory shutdown.
  Hosted/download checks: 6 passed. Native website command-generation test passed.
- Website server tests: 10 passed; TypeScript and Vite production build passed.
  The build used the shared scratch output because the checkout's existing `dist`
  junction points to a missing release directory.
- Real engine: a new VM launched with both timers disabled, executed an untimed
  command, published an owner endpoint without expiry, and stopped explicitly.
- Development website restored with retained data using the new engine and timers.
- Actual installed Yougori CLI: both bundled clients started, and
  `yougori inference install pi --server URL` downloaded, verified and imported
  the live website's real Pi image. No resources were contributed and PATH stayed
  unchanged. Four checks are recorded in
  `D:/YougoriBuildCache/scratch/website-restart/native-inference-acceptance/result.json`.

Installed CLI was backed up before updating. The running development engine is
`D:/YougoriBuildCache/target/debug/yougori-engine.exe`; the packaged desktop app was
not rebuilt or replaced. The website received a new local publication address on
restart. No production deployment, paid resource, commit or push was performed.
