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
yougori_restore_read_only=0
cleanup() {
  [ -z "$yougori_temp" ] || rm -f "$yougori_temp"
  [ -z "$yougori_module_temp" ] || rm -rf "$yougori_module_temp"
  if [ "$yougori_restore_read_only" = 1 ]; then
    sync
    mount -t ext4 -o remount,ro none "$yougori_root" || true
  fi
}
trap cleanup EXIT HUP INT TERM

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

install_boot_file() {
  mode=$1
  relative=$2
  source=${yougori_payload%/}/$relative
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

install_boot_file 0755 usr/local/sbin/opendock-agent
install_boot_file 0755 etc/init.d/opendock-agent
install_boot_file 0755 etc/init.d/containerd
install_boot_file 0644 etc/containerd/config.toml
install_boot_file 0644 etc/sysctl.d/90-yougori-security.conf
sync
if [ "$yougori_restore_read_only" = 1 ]; then
  mount -t ext4 -o remount,ro none "$yougori_root"
  yougori_restore_read_only=0
fi
