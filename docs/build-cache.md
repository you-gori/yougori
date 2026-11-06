# Development build storage

Cargo stores compiled dependencies and compiler state in `target` directories.
These are development files; running the packaged Yougori application does not
create Cargo caches. The repository's `.cargo/config.toml` disables incremental
compilation and uses line tables for development/test debug information. This
keeps useful backtrace locations without full variable/type debug information.
Local recompilation can take longer. Release settings are unchanged.

Run Cargo from this checkout or one of its subdirectories so it reads this
configuration. Explicit Cargo environment or command-line overrides can change
these defaults. See the [Cargo profile documentation](https://doc.rust-lang.org/cargo/reference/profiles.html).

## Inspect and reclaim existing caches on Windows

Requires PowerShell 7 (`pwsh`). Stop Rust builds first; the app may keep running.

```powershell
npm run cache:report
npm run cache:clean
```

If target directories have been moved to another drive using junctions, explicitly
include that build-cache root. For example:

```powershell
npm run cache:report -- -CacheRoot D:\YougoriBuildCache
npm run cache:clean -- -CacheRoot D:\YougoriBuildCache
```

The report shows reclaimable bytes. Cleanup removes only Cargo's `incremental`,
`deps`, `build`, and `.fingerprint` directories in recognized build profiles.
It verifies resolved paths, rejects links inside those directories, and holds
the Cargo profile lock during deletion. It preserves top-level executables,
runtime bundles, model downloads, VM disks, credentials, and backups. The next
Rust build recreates dependencies as needed. Files locked by another process
cause cleanup to stop with an error rather than terminating that process.

Disabling incremental compilation prevents that specific cache from growing;
Cargo can still retain older dependency outputs after toolchain, dependency, or
build-flag changes. Use the report and cleanup commands when changing these.
There is no automatic deletion of model or environment data.

## Release workspaces and WSL disks

Releases and agent sessions also leave data outside the checkout. Rust builds
should share one target, `D:\YougoriBuildCache\target`, rather than creating a
new `D:\*-target` folder per session.

```powershell
npm run disk:report      # list what would be removed, change nothing
npm run disk:clean       # remove it and compact the WSL disks
npm run disk:schedule    # run disk:clean every Sunday at 04:00 (asks for administrator once)
```

`scripts/disk-cleanup.ps1` keeps the two newest releases (`-KeepReleases`) and
removes:

- older `D:\yougori-X.Y.Z` release workspaces;
- older `/build/out-linux-X.Y.Z`, `/build/out-arm64-X.Y.Z` and
  `/build/yougori-X.Y.Z` inside `Yougori-Release-Build`, and its npm cache;
- compiler caches in `D:\YougoriBuildCache`, `D:\*-target` and
  `C:\tmp\*-target` (`-ScratchRoot`), through
  `build-cache.ps1` with the same protections;
- grid test folders holding `realm.db` or `minting.db` in the temp directory
  that are more than a day old;
- files in `.git\lfs\tmp` more than an hour old. Git LFS leaves a full copy of
  a modified LFS file there each time a `git diff` or `git status` is killed
  mid-filter, which tools that poll the repository every second do.

WSL disk files grow but never shrink. With `-Compact` the script trims each
`Yougori-*` distribution, shuts WSL down and compacts its `ext4.vhdx` with
`diskpart`. Compaction only runs from an administrator PowerShell and only when
no WSL distribution was running at start; otherwise it is skipped with a
warning. It never deletes data inside a distribution. Links are never followed,
and other folders on the drive are never read. The scheduled task logs to
`%LOCALAPPDATA%\Yougori\disk-cleanup.log`; remove it with
`npm run disk:schedule -- -Unregister`.
