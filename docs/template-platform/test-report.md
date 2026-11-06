# Template platform test report

Started 2026-10-26T19:46:28.306Z; finished 2026-10-26T19:54:00.565Z. Times are UTC.

Source: `da2b00c2eafa8ca7353eba2232e6e350ac328fbd` **with uncommitted changes**.
Machine: win32 x64; 24 logical processors; 63.43 GiB RAM.
Evidence is assigned per suite: mocked integration suites also contain unit/contract tests. No row proves real-runtime acceptance or publication/download verification.

The working tree is mutable while other agents work. This is not a frozen-source release acceptance report. Source identities are recorded before and after the run.

| Suite | Exact command | Evidence level | Result | Seconds | Passed | Failed | Ignored/skipped | Filtered |
| --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| setup | `cargo test --manifest-path setup/Cargo.toml` | pure unit/contract test | passed | 42.48 | 159 | 0 | 0 | 0 |
| cli | `cargo test --manifest-path cli/Cargo.toml -- --skip swarm --skip bounty` | mocked integration | passed | 173.66 | 1009 | 0 | 10 | 85 |
| grid | `cargo test --manifest-path grid/Cargo.toml -- --skip bounty` | mocked integration | passed | 145.39 | 570 | 0 | 6 | 15 |

## Policy and interpretation

- Swarm Mining/bounty execution is excluded under `.claude/codex-board.md`. The exact Rust skip filters are in each command and in JSON. Pure setup-format fixtures do not run workers.
- Ignored tests are not passes. The suites retain their own runtime/hardware prerequisites; this runner never enables ignored tests.
- Filtered counts are Rust's aggregate counts; they do not identify individual skipped tests. No unexecuted test is reported as verified.
- A successful command without a recognizable test summary is incomplete, not passed. Compilation failure can leave counts unknown or partial.
- Cargo runs offline in `D:/tmp/codex-target` with four build jobs, incremental compilation off, and dev/test debug information disabled. It never uses the app's target directory. npm also runs offline.
- Duration includes compilation for Cargo suites. The first run in the isolated cache can take much longer than warm-cache tests.

## Fixture types

- **setup:** In-memory synthetic packages, temporary files and planner fixtures.
- **cli:** CLI unit/contract tests, temporary configuration and mocked services; no live engine.
- **grid:** Grid unit tests and synthetic/local mock-server fixtures; no live grid or bounty.

## Source at completion

Pending.

## Run interrupted

The coordinator replaced this task with the read-only removal audit. The owned runner was stopped during native-library compilation. Setup, CLI and grid results above are completed results; engine and desktop suites were not completed and have no pass claim.
