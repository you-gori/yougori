#!/bin/bash
# Build only the separate CUDA payload; never replace a running QEMU appliance.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
output="${1:-$repo_root/src-tauri/resources/runtime/cuda}"
bash "$repo_root/scripts/check-agent-go.sh"
: "${YOUGORI_MUSL_TOOLCHAIN_MANIFEST:?Set the verified private musl native build manifest; no system compiler fallback is permitted.}"
command -v gcc >/dev/null
mkdir -p "$output"
vendor_name=yougori-oci-runtime-linux-amd64
nvidia_name=yougori-nvidia-cdi-linux-amd64
vendor_root="$repo_root/src-tauri/resources/runtime/cuda"
python3 "$repo_root/scripts/vendor-oci-build/verify.py" \
  --archive "$vendor_root/$vendor_name.tar.gz" \
  --manifest "$vendor_root/$vendor_name.manifest.json"
python3 "$repo_root/scripts/vendor-nvidia-build/verify.py" \
  --archive "$vendor_root/$nvidia_name.tar.gz" \
  --manifest "$vendor_root/$nvidia_name.manifest.json"
if [[ "$(realpath "$output")" != "$(realpath "$vendor_root")" ]]; then
  cp "$vendor_root/$vendor_name.tar.gz" "$output/$vendor_name.tar.gz"
  cp "$vendor_root/$vendor_name.manifest.json" "$output/$vendor_name.manifest.json"
  cp "$vendor_root/$nvidia_name.tar.gz" "$output/$nvidia_name.tar.gz"
  cp "$vendor_root/$nvidia_name.manifest.json" "$output/$nvidia_name.manifest.json"
fi
(cd "$repo_root/appliance/agent" && CGO_ENABLED=0 go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' -o "$output/opendock-agent" .)
python3 "$repo_root/scripts/vendor-oci-build/native-compiler.py" \
  --manifest "$YOUGORI_MUSL_TOOLCHAIN_MANIFEST" \
  --record "$repo_root/build/oci-runtime/records/mount-helper-cuda.build.json" \
  --source "$repo_root/appliance/mount-helper.c" -- \
  -static-pie -Os -s -fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wall -Wextra -Werror -o "$output/opendock-mount-helper" "$repo_root/appliance/mount-helper.c"
gcc -fPIE -pie -fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack \
  -Os -s -Wall -Wextra -Werror -o "$output/opendock-cuda-probe" "$repo_root/runtime/cuda/kernel-probe.c" -ldl
(cd "$output" && sha256sum opendock-agent opendock-mount-helper opendock-cuda-probe \
  "$vendor_name.tar.gz" "$vendor_name.manifest.json" \
  "$nvidia_name.tar.gz" "$nvidia_name.manifest.json" > SHA256SUMS)
echo 'CUDA payload built and checksummed. Rebuild the desktop to embed its checksums.'
