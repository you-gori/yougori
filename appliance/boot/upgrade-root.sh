#!/bin/sh
set -eu

# Runs from the verified initramfs before OpenRC, including when the disk uses
# an older preserved qcow2 backing image. Install only product-owned programs
# and configuration; never rebase the disk or change application data.
[ "$#" -ge 1 ] && [ "$#" -le 2 ] || exit 1
yougori_root=${1%/}
yougori_payload=${2:-/}
case "$yougori_root" in /*) ;; *) exit 1 ;; esac
[ -d "$yougori_root" ] && [ ! -L "$yougori_root" ] || exit 1
yougori_temp=
yougori_module_temp=
yougori_vendor_temp=
yougori_restore_read_only=0
cleanup() {
  yougori_status=$1
  if [ -n "$yougori_temp" ]; then
    rm -f "$yougori_temp" || { [ "$yougori_status" -ne 0 ] || yougori_status=1; }
  fi
  if [ -n "$yougori_module_temp" ]; then
    rm -rf "$yougori_module_temp" || { [ "$yougori_status" -ne 0 ] || yougori_status=1; }
  fi
  if [ -n "$yougori_vendor_temp" ]; then
    rm -rf "$yougori_vendor_temp" || { [ "$yougori_status" -ne 0 ] || yougori_status=1; }
  fi
  if [ "$yougori_restore_read_only" = 1 ]; then
    sync || { [ "$yougori_status" -ne 0 ] || yougori_status=1; }
    mount -t ext4 -o remount,ro none "$yougori_root" || { [ "$yougori_status" -ne 0 ] || yougori_status=1; }
  fi
  exit "$yougori_status"
}
trap 'cleanup $?' EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Alpine mounts the persistent root read-only until OpenRC checks/remounts it.
# /proc has already moved under sysroot at this hook. Use the trusted mount
# table there and remount only this known ext4 root while installing updates.
# The second argument is for the simulated-root test fixture, not a boot hook.
if [ "$#" = 1 ]; then
  [ -r "$yougori_root/proc/mounts" ] || exit 1
  root_options=$(awk -v root="$yougori_root" '$2 == root && $3 == "ext4" { print $4; exit }' "$yougori_root/proc/mounts")
  case ",$root_options," in
    *,ro,*)
      yougori_restore_read_only=1
      mount -t ext4 -o remount,rw none "$yougori_root"
      ;;
    *,rw,*) ;;
    *) exit 1 ;;
  esac
fi

install_boot_source() {
  mode=$1
  relative=$2
  source=$3
  destination=$yougori_root/$relative
  [ -f "$source" ] && [ ! -L "$source" ] || return 1
  directory=$yougori_root
  previous_ifs=$IFS
  IFS=/
  set -- ${relative%/*}
  IFS=$previous_ifs
  for component do
    [ "$component" != . ] && [ "$component" != .. ] || return 1
    directory=$directory/$component
    [ ! -L "$directory" ] || return 1
    if [ -e "$directory" ]; then
      [ -d "$directory" ] || return 1
    else
      mkdir -m 0755 "$directory"
    fi
  done
  # A symlink at the leaf is replaced atomically; its target is never written.
  [ ! -d "$destination" ] || return 1
  if [ ! -L "$destination" ] && [ -f "$destination" ] &&
     [ "$(stat -c %h "$destination")" = 1 ] && [ "$(stat -c %u "$destination")" = 0 ] &&
     cmp -s "$source" "$destination"; then
    chmod "$mode" "$destination"
    return 0
  fi
  yougori_temp=$(mktemp "$directory/.yougori-boot.XXXXXX")
  cp "$source" "$yougori_temp"
  chmod "$mode" "$yougori_temp"
  mv -f "$yougori_temp" "$destination"
  yougori_temp=
}

install_boot_file() {
  install_boot_source "$1" "$2" "${yougori_payload%/}/$2"
}

# Every executable used by the OCI runtime and its private CNI chain must be
# upgraded on preserved disks. Validate the complete trusted set before any
# replacement; extract to disk, keeping the minimum 512 MiB VM's initramfs
# from holding the expanded vendor binaries in RAM.
vendor_payload=${yougori_payload%/}/usr/local/lib/yougori-boot
vendor_archive=$vendor_payload/oci-runtime.tar.gz
vendor_manifest=$vendor_payload/oci-runtime.files
for vendor_file in "$vendor_archive" "$vendor_manifest" "$vendor_payload/oci-runtime.sha256"; do
  [ -f "$vendor_file" ] && [ ! -L "$vendor_file" ] || exit 1
done
[ "$(stat -c %s "$vendor_archive")" -le 100663296 ] || exit 1
[ "$(stat -c %s "$vendor_manifest")" -le 4096 ] || exit 1
vendor_digest=$(cat "$vendor_payload/oci-runtime.sha256")
[ "${#vendor_digest}" = 64 ] || exit 1
case "$vendor_digest" in *[!0-9a-f]*) exit 1 ;; esac
vendor_actual=$(sha256sum "$vendor_archive")
[ "${vendor_actual%% *}" = "$vendor_digest" ] || exit 1
vendor_expected=$(printf '%s\n' \
  usr/local/bin/containerd \
  usr/local/bin/containerd-shim-runc-v2 \
  usr/local/bin/nerdctl \
  usr/local/bin/runc \
  usr/local/libexec/cni/bridge \
  usr/local/libexec/cni/firewall \
  usr/local/libexec/cni/host-local \
  usr/local/libexec/cni/loopback \
  usr/local/libexec/cni/portmap \
  usr/local/libexec/cni/tuning | sort)
[ "$(awk '{print $3}' "$vendor_manifest" | sort)" = "$vendor_expected" ] || exit 1
vendor_count=0
vendor_total=0
while read -r digest size relative extra; do
  [ -z "$extra" ] && [ "${#digest}" = 64 ] && [ "${#size}" -le 9 ] || exit 1
  case "$digest" in *[!0-9a-f]*) exit 1 ;; esac
  case "$size" in ''|*[!0-9]*|0*) exit 1 ;; esac
  [ "$size" -le 100663296 ] || exit 1
  vendor_count=$((vendor_count + 1))
  vendor_total=$((vendor_total + size))
done < "$vendor_manifest"
[ "$vendor_count" = 10 ] && [ "$vendor_total" -le 268435456 ] || exit 1
vendor_names=$(tar -tzf "$vendor_archive")
[ "$(printf '%s\n' "$vendor_names" | sort)" = "$vendor_expected" ] || exit 1
# USTAR files generated by the trusted builder contain no directories,
# hardlinks or symlinks. Check types and advertised extraction size too.
tar -tvzf "$vendor_archive" | awk -v expected="$vendor_total" '
  substr($1, 1, 1) != "-" || $3 !~ /^[0-9]+$/ || $3 < 1 || $3 > 100663296 { invalid=1 }
  { count++; total += $3 }
  END { exit (invalid || count != 10 || total != expected || total > 268435456) }
'
yougori_vendor_temp=$(mktemp -d "$yougori_root/.yougori-oci.XXXXXX")
tar -xzf "$vendor_archive" -C "$yougori_vendor_temp"
while read -r digest size relative extra; do
  vendor_source=$yougori_vendor_temp/$relative
  [ -f "$vendor_source" ] && [ ! -L "$vendor_source" ] &&
    [ "$(stat -c %h "$vendor_source")" = 1 ] &&
    [ "$(stat -c %s "$vendor_source")" = "$size" ] || exit 1
  vendor_actual=$(sha256sum "$vendor_source")
  [ "${vendor_actual%% *}" = "$digest" ] || exit 1
  # Refuse every existing redirect before updating the first executable.
  directory=$yougori_root
  previous_ifs=$IFS
  IFS=/
  set -- ${relative%/*}
  IFS=$previous_ifs
  for component do
    directory=$directory/$component
    [ ! -L "$directory" ] || exit 1
    if [ -e "$directory" ]; then [ -d "$directory" ] || exit 1; fi
  done
  [ ! -d "$yougori_root/$relative" ] || exit 1
done < "$vendor_manifest"

# The host boots the current kernel even when the overlay keeps an older
# backing disk. Install its matching, verified module tree in a fresh version
# directory so CNI/netfilter/FUSE/GPU module autoload keeps working after boot.
module_payload=${yougori_payload%/}/usr/local/lib/yougori-boot
[ -f "$module_payload/kernel-version" ] && [ ! -L "$module_payload/kernel-version" ] || exit 1
kernel_version=$(cat "$module_payload/kernel-version")
[ "$kernel_version" = "$(uname -r)" ] || exit 1
case "$kernel_version" in ''|*[!a-zA-Z0-9._+-]*) exit 1 ;; esac
module_library=$yougori_root/lib
if [ -L "$module_library" ]; then
  case "$(readlink "$module_library")" in
    usr/lib|/usr/lib) module_library=$yougori_root/usr/lib ;;
    *) exit 1 ;;
  esac
  [ ! -L "$yougori_root/usr" ] || exit 1
  [ -d "$yougori_root/usr" ] || mkdir -m 0755 "$yougori_root/usr"
fi
for module_directory in "$module_library" "$module_library/modules"; do
  [ ! -L "$module_directory" ] || exit 1
  if [ -e "$module_directory" ]; then
    [ -d "$module_directory" ] || exit 1
  else
    mkdir -m 0755 "$module_directory"
  fi
done
module_destination=$module_library/modules/$kernel_version
[ ! -L "$module_destination" ] || exit 1
if [ ! -d "$module_destination" ]; then
  [ ! -e "$module_destination" ] || exit 1
  module_archive=$module_payload/kernel-modules.tar.gz
  [ -f "$module_archive" ] && [ ! -L "$module_archive" ] || exit 1
  [ -f "$module_payload/kernel-modules.sha256" ] && [ ! -L "$module_payload/kernel-modules.sha256" ] || exit 1
  expected_digest=$(cat "$module_payload/kernel-modules.sha256")
  actual_digest=$(sha256sum "$module_archive")
  [ "${actual_digest%% *}" = "$expected_digest" ] || exit 1
  yougori_module_temp=$(mktemp -d "$module_library/modules/.yougori-modules.XXXXXX")
  tar -xzf "$module_archive" -C "$yougori_module_temp"
  [ -d "$yougori_module_temp/$kernel_version" ] && [ ! -L "$yougori_module_temp/$kernel_version" ] || exit 1
  mv "$yougori_module_temp/$kernel_version" "$module_destination"
  rmdir "$yougori_module_temp"
  yougori_module_temp=
fi

while read -r digest size relative extra; do
  install_boot_source 0755 "$relative" "$yougori_vendor_temp/$relative"
done < "$vendor_manifest"
rm -rf "$yougori_vendor_temp"
yougori_vendor_temp=
install_boot_file 0755 usr/local/sbin/opendock-agent
install_boot_file 0755 usr/local/sbin/opendock-mount-helper
install_boot_file 0755 etc/init.d/opendock-agent
install_boot_file 0755 etc/init.d/containerd
install_boot_file 0644 etc/containerd/config.toml
install_boot_file 0644 etc/sysctl.d/90-yougori-security.conf
sync
if [ "$yougori_restore_read_only" = 1 ]; then
  mount -t ext4 -o remount,ro none "$yougori_root"
  yougori_restore_read_only=0
fi
