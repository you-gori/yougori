#!/bin/bash
# Signs the runtime written by build-macos-runtime.sh and then records SHA256SUMS of the
# signed files, which the app verifies before starting QEMU. IDENTITY is a "Developer ID
# Application" identity in the keychain, or "-" for an ad-hoc signature (local testing
# only; macOS refuses to open such builds when downloaded).
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
runtime=${1:?usage: sign-macos-runtime.sh RUNTIME-DIRECTORY IDENTITY}
identity=${2:?usage: sign-macos-runtime.sh RUNTIME-DIRECTORY IDENTITY}
options=(--force --sign "$identity")
# Distribution needs the hardened runtime and a secure timestamp for notarization.
if [[ "$identity" != - ]]; then options+=(--options runtime --timestamp); fi
for library in "$runtime"/lib/*.dylib; do
  codesign "${options[@]}" "$library"
done
codesign "${options[@]}" "$runtime/qemu-img"
codesign "${options[@]}" "$runtime/yougori-supervise"
codesign "${options[@]}" --entitlements "$repo/scripts/macos-runtime/qemu.entitlements" "$runtime/qemu-system-x86_64"
for binary in "$runtime"/lib/*.dylib "$runtime/qemu-img" "$runtime/yougori-supervise" "$runtime/qemu-system-x86_64"; do
  codesign --verify --strict "$binary"
done
(cd "$runtime" && rm -f SHA256SUMS && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | sed 's#^\./##' |
  while IFS= read -r file; do shasum -a 256 "$file"; done > SHA256SUMS)
echo "Signed $runtime with ${identity/#-/an ad-hoc signature}"
