#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
if [[ "$(uname -s)" != Darwin || "$(id -u)" == 0 ]]; then
  echo "Run these disposable runtime tests on macOS as a normal user."
  exit 1
fi
node scripts/macos-setup.mjs
# Test the QEMU runtime the app bundles, built and signed by npm run macos:runtime.
export YOUGORI_MACOS_QEMU_DIR="$PWD/build/macos-runtime/qemu"
if [[ ! -f "$YOUGORI_MACOS_QEMU_DIR/SHA256SUMS" ]]; then
  echo "Build the bundled runtime first: npm run macos:runtime"
  exit 1
fi
export TMPDIR="$(mktemp -d /private/tmp/yougori-runtime-tests.XXXXXX)"
echo "Disposable test root: $TMPDIR"
# These tests create their own temporary runtime roots. They do not use the
# installed app's data, select user folders, or publish anything to the internet.
for test in workspace_container_end_to_end workspace_microvm_end_to_end bundled_qemu_exposes_qmp_and_vnc_websocket workspace_fullvm_forwarding_and_viewers; do
  cargo test --locked --manifest-path src-tauri/Cargo.toml --lib "$test" -- --ignored --nocapture --test-threads=1
done
echo "Disposable runtime tests passed. Interactive GUI and real OS installs still need manual testing."
