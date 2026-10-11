#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin ]]; then
  echo "Run this build on macOS. Windows cannot build/sign the macOS installer."
  exit 1
fi
if [[ "$(id -u)" == 0 ]]; then echo "Build as your normal user, not sudo."; exit 1; fi
xcode-select -p >/dev/null
command -v node >/dev/null
command -v cargo >/dev/null
python3 -c 'import tomllib' || { echo 'Install Python 3.11 or newer for dependency compliance checks.'; exit 1; }
export TMPDIR="$(mktemp -d /private/tmp/yougori-build-tests.XXXXXX)"
echo "Disposable test root: $TMPDIR"
node scripts/macos-setup.mjs
# With YOUGORI_MAC_SIGNING_IDENTITY ("Developer ID Application: ...") this is a release build:
# every executable is signed for notarization and the release checks apply. Without it, a
# preview with ad-hoc signatures that macOS will not open when downloaded.
identity=${YOUGORI_MAC_SIGNING_IDENTITY:--}
# The bundled QEMU runtime. A cached build of unchanged pinned inputs is reused; it is always
# re-signed with this build's identity, which also refreshes its SHA256SUMS.
if [[ ! -x build/macos-runtime/qemu/qemu-system-x86_64 ]]; then bash scripts/build-macos-runtime.sh; fi
bash scripts/sign-macos-runtime.sh build/macos-runtime/qemu "$identity"
# Fresh native packages: never copy Windows node_modules, target or CLI binaries.
npm ci
npm run lint
npm test
cargo test --locked --manifest-path cli/Cargo.toml
cargo check --locked --manifest-path src-tauri/Cargo.toml --all-targets
cargo test --locked --manifest-path src-tauri/Cargo.toml --lib
# Restore sources and verify that they match the reviewed candidate records.
python3 scripts/fetch-compliance-bundle.py
python3 -m zipfile -e build/compliance/corresponding-source.zip build/compliance
python3 -c 'from pathlib import Path; import shutil; [shutil.copy2(p, Path("build/compliance/bundle") / p.name) for p in Path("compliance/source-updates").glob("*.tar.gz")]'
python3 scripts/collect-compliance.py cache
npm run compliance:archives
if [[ "$identity" == - ]]; then
  npm run desktop:build -- --config src-tauri/tauri.preview.conf.json
  node scripts/verify-macos-bundle.mjs src-tauri/target/release/bundle/macos/Yougori.app
else
  # Tauri signs the app with APPLE_SIGNING_IDENTITY and notarizes it when the APPLE_API_*
  # notarization variables are set (see .github/workflows/macos.yml).
  APPLE_SIGNING_IDENTITY="$identity" npm run desktop:build
  node scripts/verify-macos-bundle.mjs --distribution src-tauri/target/release/bundle/macos/Yougori.app
fi
echo "Build finished. Installer: src-tauri/target/release/bundle/dmg/"
echo "Still required: npm run macos:test:runtime and the real-Mac checklist in docs/macos.md."
