#!/bin/bash
# Run only inside the newly imported, Yougori-owned Ubuntu distribution.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
test "$(id -u)" = 0
test -f /etc/opendock-cuda-runtime
test -e /dev/dxg || { echo 'WSL GPU bridge missing. Update WSL and the Windows NVIDIA driver.' >&2; exit 1; }
if ! command -v python3 >/dev/null; then
  apt-get update
  apt-get install -y --no-install-recommends python3
fi
# Verify all files before replacing any executable. Existing owned disks need
# this update too, even when their dependency-ready marker already exists.
payload=/usr/local/share/yougori-oci-runtime
python3 /usr/local/sbin/opendock-cuda-install-oci.py \
  "$payload/yougori-oci-runtime-linux-amd64.tar.gz" \
  "$payload/yougori-oci-runtime-linux-amd64.manifest.json"
python3 /usr/local/sbin/opendock-cuda-install-oci.py \
  "$payload/yougori-nvidia-cdi-linux-amd64.tar.gz" \
  "$payload/yougori-nvidia-cdi-linux-amd64.manifest.json" nvidia-cdi
if [[ -f /etc/opendock-cuda-ready ]] && test -x /usr/local/bin/nvidia-ctk; then
  echo 'CUDA dependencies are already installed; verified runtime executables were updated.'
  exit 0
fi
apt-get update
apt-get install -y --no-install-recommends ca-certificates curl gnupg iproute2 iptables util-linux fuse3 e2fsprogs python3
work_dir=$(mktemp -d /tmp/opendock-cuda-setup.XXXXXXXX)
trap 'rm -rf -- "$work_dir"' EXIT
install -d /usr/local/bin /usr/local/libexec/cni /etc/containerd /etc/nerdctl
curl --fail --location --proto '=https' --tlsv1.2 https://nvidia.github.io/libnvidia-container/gpgkey -o "$work_dir/nvidia.asc"
gpg --batch --yes --dearmor --output /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg "$work_dir/nvidia.asc"
printf '%s\n' 'deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://nvidia.github.io/libnvidia-container/stable/deb/amd64 /' > /etc/apt/sources.list.d/nvidia-container-toolkit.list
apt-get update
# CDI needs only the base tools, never a Linux GPU driver or privileged runtime.
apt-get install -y --no-install-recommends nvidia-container-toolkit-base=1.20.0-1
printf '%s\n' 'version = 2' 'disabled_plugins = ["io.containerd.grpc.v1.cri"]' > /etc/containerd/config.toml
printf '%s\n' 'cgroup_manager = "cgroupfs"' > /etc/nerdctl/nerdctl.toml
apt-get clean
touch /etc/opendock-cuda-ready
echo 'Yougori CUDA runtime installed.'
