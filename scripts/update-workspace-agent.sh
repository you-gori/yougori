#!/usr/bin/env bash
set -euo pipefail

# Update boot-time agent code without rebuilding/rebasing the immutable data disk.
repo_root="$(realpath "${1:?repository path required}")"
bash "$repo_root/scripts/check-agent-go.sh"
appliance="${2:-$repo_root/src-tauri/resources/runtime/appliance}"
storage_tools="$repo_root/build/appliance-cache/storage-tools"
if [ ! -x "$storage_tools/resize2fs" ]; then
  bash "$repo_root/scripts/build-storage-tools.sh" "$repo_root"
fi
task_directory="$(mktemp -d /tmp/yougori-agent-update.XXXXXX)"
cleanup() {
  case "$task_directory" in /tmp/yougori-agent-update.*) rm -rf -- "$task_directory" ;; esac
}
trap cleanup EXIT
mkdir "$task_directory/root"
(
  cd "$repo_root/appliance/agent"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -buildvcs=false -trimpath -ldflags='-s -w -buildid=' -o "$task_directory/yougori-agent-update" .
)
(
  cd "$task_directory/root"
  gzip -dc "$appliance/initramfs-virt" | cpio -idm --quiet
  install -m 0755 "$task_directory/yougori-agent-update" yougori-agent-update
  install -m 0755 "$repo_root/appliance/rootfs/etc/init.d/containerd" yougori-containerd-service
  mkdir -p yougori-storage-tools
  cp -a "$storage_tools/." yougori-storage-tools/
  # Idempotent: replace the existing updater block if this script ran before.
  sed '/# YOUGORI_AGENT_UPDATE_BEGIN/,/# YOUGORI_AGENT_UPDATE_END/d' init > init.clean
  awk '
    index($0, "cat \"$ROOT\"/proc/mounts") {
      print "# YOUGORI_AGENT_UPDATE_BEGIN"
      print "if [ -d /yougori-storage-tools ]; then"
      # Grow from initramfs before installing updates: the old root may be full.
      # The private tool and its libraries are already in RAM, outside that root.
      print "  if grep -q \"^/dev/vda $sysroot ext4 \" /proc/mounts; then"
      print "    mount -o remount,rw \"$sysroot\" && /yougori-storage-tools/ld-musl-x86_64.so.1 --library-path /yougori-storage-tools /yougori-storage-tools/resize2fs /dev/vda || echo \"Yougori early storage expansion failed\""
      print "  fi"
      print "  mount -o remount,rw \"$sysroot\" && mkdir -p \"$sysroot/usr/local/lib/yougori-storage\" && cp -a /yougori-storage-tools/. \"$sysroot/usr/local/lib/yougori-storage/\" || echo \"Yougori storage tools update failed\""
      print "fi"
      print "if [ -x /yougori-agent-update ]; then"
      print "  mkdir -p \"$sysroot/usr/local/sbin\""
      print "  if ! cmp -s /yougori-agent-update \"$sysroot/usr/local/sbin/yougori-agent\"; then"
      print "    mount -o remount,rw \"$sysroot\" && cp /yougori-agent-update \"$sysroot/usr/local/sbin/yougori-agent.new\" && chmod 755 \"$sysroot/usr/local/sbin/yougori-agent.new\" && mv \"$sysroot/usr/local/sbin/yougori-agent.new\" \"$sysroot/usr/local/sbin/yougori-agent\" || echo \"Yougori guest agent update failed\""
      print "  fi"
      print "fi"
      print "if [ -x /yougori-containerd-service ]; then"
      print "  cp /yougori-containerd-service \"$sysroot/etc/init.d/containerd\" && chmod 755 \"$sysroot/etc/init.d/containerd\" || echo \"Yougori container storage service update failed\""
      print "fi"
      print "# YOUGORI_AGENT_UPDATE_END"
    }
    { print }
  ' init.clean > init
  chmod 755 init
  rm init.clean
  find . -print0 | cpio --null -o -H newc --quiet | gzip -9 > "$task_directory/initramfs-virt"
)
install -m 0644 "$task_directory/initramfs-virt" "$appliance/initramfs-virt"
(
  cd "$appliance"
  sha256sum appliance-base.qcow2 vmlinuz-virt initramfs-virt > SHA256SUMS
)
echo "Workspace agent updated; the appliance base disk is unchanged."
