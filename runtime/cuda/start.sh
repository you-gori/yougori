#!/bin/bash
set -euo pipefail
test -f /etc/opendock-cuda-ready
test -f /etc/opendock-cuda-runtime
exec 9>/run/opendock-cuda.lock
flock -n 9 || { echo 'CUDA runtime is already owned by another Yougori process.' >&2; exit 1; }
read -r OPENDOCK_CUDA_TOKEN
read -r cuda_port
[[ "$OPENDOCK_CUDA_TOKEN" =~ ^[a-f0-9]{64}$ && "$cuda_port" =~ ^[0-9]{4,5}$ ]]
export OPENDOCK_CUDA_MODE=1 OPENDOCK_CUDA_TOKEN
export OPENDOCK_CUDA_LISTEN="127.0.0.1:$cuda_port"
mkdir -p /run/cdi
/usr/local/sbin/opendock-agent --prepare-container-storage
/usr/local/bin/nvidia-ctk cdi generate --nvidia-cdi-hook-path=/usr/local/bin/nvidia-cdi-hook --output=/run/cdi/nvidia.yaml
containerd --config /etc/containerd/config.toml &
containerd_pid=$!
agent_pid=''
cleanup() {
  trap - EXIT TERM INT
  if [[ -n "$agent_pid" ]]; then kill "$agent_pid" 2>/dev/null || true; fi
  kill "$containerd_pid" 2>/dev/null || true
  wait "$containerd_pid" 2>/dev/null || true
  sync
}
trap cleanup EXIT TERM INT
for attempt in $(seq 1 100); do
  [[ -S /run/containerd/containerd.sock ]] && break
  kill -0 "$containerd_pid"
  sleep 0.1
done
/usr/local/sbin/opendock-agent &
agent_pid=$!
wait "$agent_pid"
