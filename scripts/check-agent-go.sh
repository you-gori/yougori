#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
module_minimum="$(awk '$1 == "go" { print $2; exit }' "$repo_root/appliance/agent/go.mod")"
# The module language version is not a security patch floor. The guest serves
# authenticated HTTP and must include the current patched standard library.
security_minimum="1.27.2"
required="$(printf '%s\n' "$module_minimum" "$security_minimum" | sort -V | tail -n1)"
message="Building the guest agent requires patched Go $required or newer. Install it from https://go.dev/dl/; the module language version alone is not sufficient."
if ! command -v go >/dev/null 2>&1; then
  echo "$message" >&2
  exit 1
fi
# Run inside the module so recent Go versions can select its required toolchain.
version="$(cd "$repo_root/appliance/agent" && go version)"
version="$(awk '{sub(/^go/, "", $3); print $3}' <<< "$version")"
if [[ "$(printf '%s\n' "$required" "$version" | sort -V | head -n1)" != "$required" ]]; then
  echo "$message Found Go $version." >&2
  exit 1
fi
