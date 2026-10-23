# Private development and public source releases

The main development repository is `you-gori/yougori-private`. The laptop stays on its `main`
branch with `distribution.txt` set to `private`. Normal commits and pushes go there, including
the live-target option. `you-gori/yougori` receives separate public source snapshots.

The compiled policy is shared by the desktop, CLI, grid and engine. Public snapshots contain
`public` in `distribution.txt`: no live-URL choice, no CLI `--url`/`--health`, and no acceptance
of external-target policies for hosting, joining, starting or resuming workers. Old private
workers cannot resume external work in a public build; pause, removal and history remain
available. Source review and applications booted in isolated sandboxes remain available.
No user preference, environment variable or debug-build switch enables live targets.

## Prepare public source

Review and commit the complete version to private `main`, then:

```text
python scripts/prepare-public-source.py PATH/TO/NEW-PUBLIC-CHECKOUT
```

The exporter reads the committed tree, never local credentials, caches or uncommitted files.
It changes only the exported distribution profile, refuses existing destinations and copies
no Git history. LFS members remain pointers. Initialize this folder as a separate repository,
base its release commit on the public repository's `main`, and stage the complete snapshot,
including deletions. Never merge or push private `main` into the public repository.

The development checkout's `origin` is private; `public` is fetch-only. Public pushes happen
from the separate release checkout after review and checks. Retrieve required LFS payloads
before building bundled runtimes. Source publication does not publish binaries: signing,
matching-source archives, installation checks and packaging follow the existing release workflow.

## Verify both editions

Run these in both the private and exported public checkout. The tests use each checkout's
compiled profile; UI fixtures also check both editions. No worker or external target is started.

```text
python scripts/prepare-public-source.test.py
cargo test --manifest-path cli/Cargo.toml --lib closed_bounty::
cargo test --manifest-path grid/Cargo.toml --lib bounty
cargo test --manifest-path src-tauri/Cargo.toml --lib distribution_tests
npx vitest run src/components/closed-bounty-distribution.test.tsx src/lib/distribution.test.ts
npm run lint
npm run build
npm run check:native
```
