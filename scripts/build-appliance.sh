#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: build-appliance.sh <repository-root> <output-directory>" >&2
  exit 2
fi

repo_root="$(realpath "$1")"
bash "$repo_root/scripts/check-agent-go.sh"
output_directory="$(realpath -m "$2")"
cache_directory="$repo_root/build/appliance-cache"
alpine_version="3.24.1"
alpine_archive="alpine-minirootfs-${alpine_version}-x86_64.tar.gz"
alpine_url="https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/${alpine_archive}"
oci_archive="$repo_root/src-tauri/resources/runtime/cuda/yougori-oci-runtime-linux-amd64.tar.gz"
oci_manifest="$repo_root/src-tauri/resources/runtime/cuda/yougori-oci-runtime-linux-amd64.manifest.json"

work_directory="$(mktemp -d /tmp/yougori-appliance.XXXXXX)"
rootfs="$work_directory/rootfs"
nerdctl_root="$work_directory/nerdctl"
mountpoint="$work_directory/mount"
raw_image="$work_directory/yougori-appliance.raw"
artifact_directory="$work_directory/artifacts"

cleanup() {
  if mountpoint -q "$mountpoint" 2>/dev/null; then
    umount "$mountpoint"
  fi
  rm -rf -- "$work_directory"
}
trap cleanup EXIT

mkdir -p "$cache_directory" "$output_directory" "$rootfs" "$nerdctl_root" "$mountpoint" "$artifact_directory"

download_verified() {
  local url="$1"
  local destination="$2"
  local algorithm="$3"
  local checksum_url="$4"
  if [[ ! -f "$destination" ]]; then
    curl --fail --location --proto '=https' --tlsv1.2 --retry 4 --output "$destination.part" "$url"
    mv "$destination.part" "$destination"
  fi
  curl --fail --location --proto '=https' --tlsv1.2 --retry 4 --output "$destination.checksum" "$checksum_url"
  local expected
  expected="$(awk '{print $1}' "$destination.checksum" | head -n1)"
  local actual
  if [[ "$algorithm" == "sha256" ]]; then
    actual="$(sha256sum "$destination" | awk '{print $1}')"
  else
    actual="$(sha512sum "$destination" | awk '{print $1}')"
  fi
  if [[ "$actual" != "$expected" ]]; then
    echo "checksum mismatch for $destination" >&2
    exit 1
  fi
}

download_verified \
  "$alpine_url" \
  "$cache_directory/$alpine_archive" \
  sha256 \
  "$alpine_url.sha256"

# Vendor executables are rebuilt from pinned upstream commits with fixed module
# and native dependencies. Never fall back to the vulnerable full release tar.
python3 "$repo_root/scripts/vendor-oci-build/verify.py" \
  --archive "$oci_archive" --manifest "$oci_manifest" \
  --destination "$nerdctl_root"

if ! command -v qemu-img >/dev/null 2>&1; then
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends qemu-utils
fi

echo "Building Yougori appliance agent"
(
  cd "$repo_root/appliance/agent"
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
	-buildvcs=false \
    -trimpath \
    -ldflags='-s -w -buildid=' \
    -o "$work_directory/opendock-agent" .
)
: "${YOUGORI_MUSL_TOOLCHAIN_MANIFEST:?Set the verified private musl native build manifest; no system compiler fallback is permitted.}"
python3 "$repo_root/scripts/vendor-oci-build/native-compiler.py" \
  --manifest "$YOUGORI_MUSL_TOOLCHAIN_MANIFEST" \
  --record "$repo_root/build/oci-runtime/records/mount-helper-appliance.build.json" \
  --source "$repo_root/appliance/mount-helper.c" -- \
  -static-pie -Os -s -fstack-protector-strong -Wl,-z,relro,-z,now,-z,noexecstack \
  -Wall -Wextra -Werror \
  -o "$work_directory/opendock-mount-helper" \
  "$repo_root/appliance/mount-helper.c"

echo "Assembling Alpine root filesystem"
tar -xzf "$cache_directory/$alpine_archive" -C "$rootfs"
cp /etc/resolv.conf "$rootfs/etc/resolv.conf"
mkdir -p "$rootfs/usr/local/sbin" "$rootfs/etc/containerd" "$rootfs/etc/network" "$rootfs/sys/fs/cgroup" "$rootfs/var/lib/opendock/exports" "$rootfs/var/lib/opendock/shares" "$rootfs/var/lib/opendock/secrets"
install -m 0755 \
  "$nerdctl_root/bin/containerd" \
  "$nerdctl_root/bin/containerd-shim-runc-v2" \
  "$nerdctl_root/bin/nerdctl" \
  "$nerdctl_root/bin/runc" \
  "$rootfs/usr/local/bin/"
mkdir -p "$rootfs/usr/local/libexec/cni"
# nerdctl's bridge network uses only this small, explicit CNI chain. Shipping
# every CNI implementation added roughly 70 MiB of unused executables to the
# uncompressed appliance and expanded its attack surface.
for plugin in bridge firewall host-local loopback portmap tuning; do
  install -m 0755 \
    "$nerdctl_root/libexec/cni/$plugin" \
    "$rootfs/usr/local/libexec/cni/$plugin"
done
install -D -m 0644 "$repo_root/src-tauri/resources/RUNTIME_LICENSES.txt" \
  "$rootfs/usr/share/licenses/yougori-runtime/RUNTIME_LICENSES.txt"

chroot "$rootfs" /bin/sh -euxc '
  printf "%s\n" \
    "https://dl-cdn.alpinelinux.org/alpine/v3.24/main" \
    "https://dl-cdn.alpinelinux.org/alpine/v3.24/community" > /etc/apk/repositories
  apk update
  apk add --no-cache \
    busybox-mdev-openrc \
    ca-certificates \
    e2fsprogs \
    e2fsprogs-extra \
    iproute2-minimal \
    iptables \
    linux-virt \
    mount \
    openrc \
    umount \
    util-linux-misc
  update-ca-certificates
'

install -m 0755 "$work_directory/opendock-agent" "$rootfs/usr/local/sbin/opendock-agent"
ln -s /usr/local/sbin/opendock-agent "$rootfs/usr/local/bin/yougori"
install -m 0755 "$work_directory/opendock-mount-helper" "$rootfs/usr/local/sbin/opendock-mount-helper"
install -m 0755 "$repo_root/appliance/rootfs/etc/init.d/containerd" "$rootfs/etc/init.d/containerd"
install -m 0755 "$repo_root/appliance/rootfs/etc/init.d/opendock-agent" "$rootfs/etc/init.d/opendock-agent"
install -m 0644 "$repo_root/appliance/rootfs/etc/containerd/config.toml" "$rootfs/etc/containerd/config.toml"
install -D -m 0644 "$repo_root/appliance/rootfs/etc/sysctl.d/90-yougori-security.conf" "$rootfs/etc/sysctl.d/90-yougori-security.conf"
install -m 0755 "$repo_root/appliance/boot/upgrade-root.sh" "$rootfs/usr/local/sbin/yougori-upgrade-root"

# A preserved appliance overlay retains its old backing image. Ship the
# current agent/configs and matching kernel modules in the verified initramfs so the next boot updates
# product-owned files without rebasing or discarding any application data.
python3 "$repo_root/scripts/prepare-appliance-initramfs.py" "$rootfs" "$work_directory/initramfs-init"
install -m 0755 "$work_directory/initramfs-init" "$rootfs/usr/share/mkinitfs/yougori-init"
chroot "$rootfs" /bin/sh -euxc '
  . /etc/mkinitfs/mkinitfs.conf
  kernel=$(find /lib/modules -mindepth 1 -maxdepth 1 -type d -name "*-virt" | head -n 1)
  [ -n "$kernel" ]
  mkinitfs -F "$features yougori-security" -i /usr/share/mkinitfs/yougori-init "${kernel##*/}"
'

cat > "$rootfs/etc/network/interfaces" <<'EOF'
auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp
EOF

cat > "$rootfs/etc/fstab" <<'EOF'
/dev/vda / ext4 defaults,noatime 0 1
proc /proc proc nosuid,nodev,noexec 0 0
sysfs /sys sysfs nosuid,nodev,noexec 0 0
devpts /dev/pts devpts gid=5,mode=620 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime 0 0
EOF

printf 'yougori-appliance\n' > "$rootfs/etc/hostname"
printf '127.0.0.1 localhost yougori-appliance\n' > "$rootfs/etc/hosts"
chroot "$rootfs" /usr/bin/passwd -l root

chroot "$rootfs" /bin/sh -euxc '
  mkdir -p /etc/runlevels/microvm
  rc-update add devfs sysinit
  rc-update add mdev sysinit
  rc-update add hwdrivers sysinit
  rc-update add sysctl boot
  rc-update add hostname boot
  rc-update add bootmisc boot
  rc-update add networking boot
  rc-update add containerd default
  rc-update add opendock-agent default
  rc-update add networking microvm
  rc-update add opendock-agent microvm
'

rm -f "$rootfs/etc/resolv.conf"
printf 'nameserver 10.0.2.3\n' > "$rootfs/etc/resolv.conf"

# The appliance is always direct-kernel booted by Yougori, so a second copy
# of its kernel and initramfs inside the root filesystem can never be used.
install -m 0644 "$rootfs/boot/vmlinuz-virt" "$artifact_directory/vmlinuz-virt"
install -m 0644 "$rootfs/boot/initramfs-virt" "$artifact_directory/initramfs-virt"
rm -rf -- \
  "$rootfs/boot" \
  "$rootfs/usr/share/doc" \
  "$rootfs/usr/share/info" \
  "$rootfs/usr/share/man" \
  "$rootfs/usr/share/locale"
find "$rootfs/var/log" -type f -exec truncate -s 0 -- {} +

echo "Creating sparse copy-on-write base image"
truncate -s 6G "$raw_image"
mkfs.ext4 -F -m 0 -L opendock-root "$raw_image"
mount -o loop "$raw_image" "$mountpoint"
cp -a "$rootfs/." "$mountpoint/"
sync
umount "$mountpoint"

qemu-img convert -p -f raw -O qcow2 -c \
  -o compat=1.1,compression_type=zstd,lazy_refcounts=on \
  "$raw_image" "$artifact_directory/appliance-base.qcow2"

(
  cd "$artifact_directory"
  sha256sum appliance-base.qcow2 vmlinuz-virt initramfs-virt > SHA256SUMS
)

# Publish only a fully built and checksummed set. Each rename happens inside
# the destination filesystem, so a failed rebuild cannot leave a partial file
# at a path consumed by the desktop runtime.
for artifact in appliance-base.qcow2 vmlinuz-virt initramfs-virt SHA256SUMS; do
  temporary="$output_directory/.$artifact.part"
  rm -f -- "$temporary"
  cp "$artifact_directory/$artifact" "$temporary"
  mv -f -- "$temporary" "$output_directory/$artifact"
done

echo "Yougori appliance written to $output_directory"
