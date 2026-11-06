#!/usr/bin/env bash
# Builds the minimal pinned sandbox guest (VM-W05, M01; the GUEST role's own build) from
# local pinned inputs only, in Linux (the WSL build distro): the pinned kernel unchanged,
# an initrd whose /init is yougori-sandbox-agent plus only the kernel modules
# guest/modules.list names (taken, with the kernel configuration, from the pinned
# appliance image), and a read-only squashfs root from the pinned Alpine minirootfs.
# Nothing is downloaded and no package manager runs; a missing or mismatched input stops
# the build. Outputs: vmlinuz, initrd, root.img, config-<release>, yougori-sandbox-agent
# and artifacts.json. See guest/README.md.
set -euo pipefail
umask 022

if [[ $# -ne 2 ]]; then
  echo "usage: build-guest.sh <repository-root> <output-directory>" >&2
  exit 2
fi

repo_root="$(realpath "$1")"
output_directory="$(realpath -m "$2")"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1792540800}"
export LC_ALL=C TZ=UTC
go_version_expected="go1.27.2"
kernel_sha256="17fbd3efd16f2e7cb1b945f06423b37399ba7d5ac8cdd3665e7f13f363500e85"
kernel_arguments="panic=-1 quiet"
runtime_directory="$repo_root/src-tauri/resources/runtime"
kernel="$runtime_directory/appliance/vmlinuz-virt"
base_image="$runtime_directory/appliance/appliance-base.qcow2"
alpine_archive="$repo_root/build/appliance-cache/alpine-minirootfs-3.24.1-x86_64.tar.gz"
helper="$repo_root/guest/guest_build.py"
module_list="$repo_root/guest/modules.list"

fail() {
  echo "build-guest: $*" >&2
  exit 1
}

for tool in go qemu-img debugfs cpio gzip mksquashfs python3 sha256sum tar find sort touch install; do
  command -v "$tool" >/dev/null 2>&1 || fail "missing tool: $tool"
done

work_directory="$(mktemp -d /tmp/yougori-guest.XXXXXX)"
cleanup() {
  rm -rf -- "$work_directory"
}
trap cleanup EXIT
commands="$work_directory/commands"
: > "$commands"

# Runs a command and records it for artifacts.json.
record() {
  printf '%s\n' "$*" >> "$commands"
  "$@"
}

pinned() {
  local relative="$1"
  local expected actual
  expected="$(awk -v name="$relative" '$2 == name { print $1 }' "$runtime_directory/SHA256SUMS")"
  [[ -n "$expected" ]] || fail "$relative is not pinned in src-tauri/resources/runtime/SHA256SUMS"
  actual="$(sha256sum "$runtime_directory/$relative" | awk '{ print $1 }')"
  [[ "$actual" == "$expected" ]] || fail "$relative does not match its pin"
}

echo "Verifying pinned inputs"
pinned appliance/vmlinuz-virt
pinned appliance/appliance-base.qcow2
[[ "$(sha256sum "$kernel" | awk '{ print $1 }')" == "$kernel_sha256" ]] || fail "the kernel is not $kernel_sha256"
[[ -f "$alpine_archive" && -f "$alpine_archive.checksum" ]] || fail "missing $alpine_archive or its checksum file"
[[ "$(sha256sum "$alpine_archive" | awk '{ print $1 }')" == "$(awk '{ print $1 }' "$alpine_archive.checksum" | sed -n 1p)" ]] ||
  fail "the Alpine minirootfs does not match its checksum file"
go_version="$(GOTOOLCHAIN=local go env GOVERSION)"
[[ "$go_version" == "$go_version_expected" ]] || fail "Go is $go_version, not $go_version_expected"
release="$(python3 -I "$helper" release "$kernel")"
echo "Kernel release $release"

echo "Taking the module set and kernel configuration from the pinned appliance image"
record qemu-img convert -f qcow2 -O raw "$base_image" "$work_directory/base.raw"
record debugfs -R "rdump /lib/modules/$release $work_directory" "$work_directory/base.raw" 2>/dev/null
rm -f -- "$work_directory/base.raw"
module_directory="$work_directory/$release"
[[ -f "$module_directory/modules.dep" ]] || fail "the pinned image has no module set for $release"
record python3 -I "$helper" ikconfig "$module_directory/kernel/kernel/configs.ko.gz" "$work_directory/config-$release"
python3 -I "$helper" resolve "$module_directory" "$module_list" > "$work_directory/modules.load"
printf '%s\n' "python3 -I $helper resolve $module_directory $module_list" >> "$commands"

echo "Building yougori-sandbox-agent"
(
  cd "$repo_root/appliance/agent"
  record env CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOFLAGS=-mod=readonly GOPROXY=off GOTOOLCHAIN=local \
    go build -trimpath -buildvcs=false -ldflags=-s\ -w\ -buildid= \
    -o "$work_directory/yougori-sandbox-agent" ./cmd/yougori-sandbox-agent
)

normalize_tree() {
  find "$1" -type d -exec chmod 0755 {} +
  find "$1" -depth -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
}

echo "Assembling the initrd"
initrd_root="$work_directory/initrd-root"
mkdir -p "$initrd_root/dev" "$initrd_root/proc" "$initrd_root/sys" "$initrd_root/newroot" "$initrd_root/etc/yougori"
install -m 0755 "$work_directory/yougori-sandbox-agent" "$initrd_root/init"
install -m 0644 "$work_directory/modules.load" "$initrd_root/etc/yougori/modules.load"
while IFS= read -r module; do
  install -D -m 0644 "$module_directory/$module" "$initrd_root/lib/modules/$release/$module"
done < "$work_directory/modules.load"
normalize_tree "$initrd_root"
# The tree, then its device nodes (/dev/console, /dev/null) as a second archive the kernel
# unpacks after the first: PID 1 opens them before it mounts devtmpfs over /dev.
printf '%s\n' "(cd initrd-root && find . -mindepth 1 -printf '%P\\n' | sort | cpio -o -H newc -R 0:0 --reproducible --quiet; python3 -I guest/guest_build.py devices $SOURCE_DATE_EPOCH) | gzip -n -9 > initrd" >> "$commands"
(
  cd "$initrd_root"
  find . -mindepth 1 -printf '%P\n' | sort | cpio -o -H newc -R 0:0 --reproducible --quiet
  python3 -I "$helper" devices "$SOURCE_DATE_EPOCH"
) | gzip -n -9 > "$work_directory/initrd"

echo "Assembling the read-only root image"
rootfs="$work_directory/rootfs"
mkdir -p "$rootfs"
record tar -xzf "$alpine_archive" --numeric-owner -C "$rootfs"
for directory in dev proc sys run tmp bin; do
  [[ -d "$rootfs/$directory" ]] || fail "the minirootfs lacks /$directory"
done
[[ -x "$rootfs/bin/sh" ]] || fail "the minirootfs lacks /bin/sh"
# A regular mount target for the per-VM DNS configuration.
rm -f -- "$rootfs/etc/resolv.conf"
: > "$rootfs/etc/resolv.conf"
# Empty read-only mount targets for the locally provisioned HCS GPU runtime.
mkdir -p "$rootfs/usr/lib/wsl" "$rootfs/lib/x86_64-linux-gnu" "$rootfs/lib64" "$rootfs/opt/yougori-gpu"
# The terminal user: uid and gid 1000, no password, home in the per-terminal tmpfs.
printf 'sandbox:x:1000:1000:sandbox:/run/yougori/terminal:/bin/sh\n' >> "$rootfs/etc/passwd"
printf 'sandbox:x:1000:\n' >> "$rootfs/etc/group"
printf 'sandbox:!::0:::::\n' >> "$rootfs/etc/shadow"
normalize_tree "$rootfs"
record env -u SOURCE_DATE_EPOCH mksquashfs "$rootfs" "$work_directory/root.img" \
  -comp xz -noappend -no-xattrs -all-root -no-progress \
  -mkfs-time "$SOURCE_DATE_EPOCH" -all-time "$SOURCE_DATE_EPOCH" >/dev/null

echo "Recording artifacts"
staging="$work_directory/out"
mkdir -p "$staging"
install -m 0644 "$kernel" "$staging/vmlinuz"
install -m 0644 "$work_directory/initrd" "$staging/initrd"
install -m 0444 "$work_directory/root.img" "$staging/root.img"
install -m 0644 "$work_directory/config-$release" "$staging/config-$release"
install -m 0755 "$work_directory/yougori-sandbox-agent" "$staging/yougori-sandbox-agent"
{
  echo "$go_version $(GOTOOLCHAIN=local go env GOOS)/$(GOTOOLCHAIN=local go env GOARCH)"
  gzip --version | sed -n 1p
  cpio --version | sed -n 1p
  mksquashfs -version 2>&1 | sed -n 1p
  tar --version | sed -n 1p
  qemu-img --version | sed -n 1p
  debugfs -V 2>&1 | sed -n 1p
  python3 --version
  echo "host: $(uname -srm)"
} > "$work_directory/toolchain"
# The record names the work and repository directories symbolically, so it is the same
# for every build of the same inputs.
sed -e "s|$work_directory|\$WORK|g" -e "s|$repo_root|\$REPO|g" "$commands" > "$commands.normalized"
mv -f -- "$commands.normalized" "$commands"
python3 -I "$helper" artifacts \
  --output-dir "$staging" --repo-root "$repo_root" --release "$release" --epoch "$SOURCE_DATE_EPOCH" \
  --kernel-arguments "$kernel_arguments" --modules-load "$work_directory/modules.load" \
  --modules-dir "$module_directory" --agent "$work_directory/yougori-sandbox-agent" \
  --go-version "$go_version" --toolchain "$work_directory/toolchain" --commands "$commands" \
  --json "$staging/artifacts.json"

# Publish only a complete set; each rename stays inside the destination directory.
mkdir -p "$output_directory"
for artifact in vmlinuz initrd root.img "config-$release" yougori-sandbox-agent artifacts.json; do
  temporary="$output_directory/.$artifact.part"
  rm -f -- "$temporary"
  cp "$staging/$artifact" "$temporary"
  mv -f -- "$temporary" "$output_directory/$artifact"
done
(cd "$output_directory" && sha256sum vmlinuz initrd root.img "config-$release" yougori-sandbox-agent artifacts.json)
echo "Sandbox guest written to $output_directory"
