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
trap '[ -z "$yougori_temp" ] || rm -f "$yougori_temp"' EXIT HUP INT TERM

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

install_boot_file 0755 usr/local/sbin/opendock-agent
install_boot_file 0755 etc/init.d/opendock-agent
install_boot_file 0755 etc/init.d/containerd
install_boot_file 0644 etc/containerd/config.toml
install_boot_file 0644 etc/sysctl.d/90-yougori-security.conf
sync
