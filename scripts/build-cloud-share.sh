#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
bash "$repo_root/scripts/check-agent-go.sh"
source_dir="$repo_root/cloud-share-mount"
output_dir="$repo_root/src-tauri/resources/runtime/cloud"
mkdir -p "$output_dir"

(cd "$source_dir" && go mod verify && go test ./...)
for arch in amd64 arm64; do
  (cd "$source_dir" && CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build \
    -buildvcs=false -trimpath -ldflags='-s -w -buildid=' \
    -o "$output_dir/yougori-share-linux-$arch" .)
done
