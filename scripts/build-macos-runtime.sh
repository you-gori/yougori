#!/bin/bash
# Builds the QEMU runtime bundled in the macOS app from the pinned sources in
# scripts/macos-runtime/inputs.json: QEMU and the few libraries it needs, native for
# this Mac's CPU and macOS 14 or newer. Nothing from Homebrew or another prefix enters
# it. Writes OUTPUT (default build/macos-runtime/qemu):
#   qemu-system-x86_64, qemu-img, lib/*.dylib, share/ (firmware), licenses/, SOURCES.json
# and yougori-macos-runtime-sources-ARCH.tar beside OUTPUT with the exact sources used.
# Signing, which also writes SHA256SUMS, is a separate step (scripts/sign-macos-runtime.sh).
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
system=$(uname -s)
if [[ "$system" != Darwin && "${YOUGORI_MACOS_RUNTIME_TRIAL:-}" != 1 ]]; then
  echo "Build the macOS runtime on macOS (YOUGORI_MACOS_RUNTIME_TRIAL=1 checks the recipe elsewhere)." >&2
  exit 1
fi
if [[ "$(id -u)" == 0 && "$system" == Darwin ]]; then echo "Build as a normal user, not sudo." >&2; exit 1; fi
for tool in meson ninja pkg-config python3; do
  command -v "$tool" >/dev/null || { echo "Missing build tool: $tool" >&2; exit 1; }
done
output=${1:-$repo/build/macos-runtime/qemu}
work=${YOUGORI_MACOS_RUNTIME_WORK:-$repo/build/macos-runtime/work}
arch=$(uname -m)
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)
inputs="$repo/scripts/macos-runtime/inputs.json"
export MACOSX_DEPLOYMENT_TARGET
MACOSX_DEPLOYMENT_TARGET=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["deploymentTarget"])' "$inputs")

downloads=$work/downloads
sources=$work/sources
prefix=$work/prefix
stage=$work/stage
rm -rf -- "$sources" "$prefix" "$stage" "$output"
mkdir -p "$downloads" "$sources" "$prefix" "$stage" "$output"
python3 "$repo/scripts/macos-runtime/fetch.py" "$downloads"

# Only this build's prefix is visible to pkg-config and the compiler, so optional
# QEMU features can never pick up a Homebrew or system library by accident.
export PKG_CONFIG_LIBDIR="$prefix/lib/pkgconfig:$prefix/share/pkgconfig"
export PKG_CONFIG_PATH=
export CPPFLAGS="-I$prefix/include"
export LDFLAGS="-L$prefix/lib"
# Room to point library references inside the app bundle after the build.
if [[ "$system" == Darwin ]]; then LDFLAGS="$LDFLAGS -Wl,-headerpad_max_install_names"; fi
# Build paths stay out of the shipped binaries.
privacy="-ffile-prefix-map=$repo=/yougori -ffile-prefix-map=$work=/build"
export CFLAGS="-O2 $privacy"
export CXXFLAGS="-O2 $privacy"

unpack() {
  local archive
  archive=$(ls "$downloads/$1-"*.tar.*)
  mkdir -p "$sources/$1"
  tar -xf "$archive" -C "$sources/$1" --strip-components=1
}

meson_install() {
  local name=$1
  shift
  meson setup "$sources/$name/_build" "$sources/$name" --prefix="$prefix" --libdir=lib \
    --buildtype=release -Ddefault_library=shared -Db_ndebug=if-release "$@"
  meson compile -C "$sources/$name/_build"
  meson install -C "$sources/$name/_build"
}

echo "== zstd"
unpack zstd
make -C "$sources/zstd/lib" -j "$jobs" install-pc install-includes install-shared PREFIX="$prefix" LIBDIR="$prefix/lib"

echo "== pcre2"
unpack pcre2
(cd "$sources/pcre2" && ./configure --prefix="$prefix" --disable-static --enable-pcre2-8 \
  --disable-pcre2-16 --disable-pcre2-32 --disable-pcre2grep-libz --disable-pcre2grep-libbz2 \
  && make -j "$jobs" && make install)

echo "== libffi"
unpack libffi
(cd "$sources/libffi" && ./configure --prefix="$prefix" --disable-static --disable-docs \
  --disable-multi-os-directory && make -j "$jobs" && make install)

echo "== glib"
unpack glib
# libintl is not part of macOS; glib then builds its pinned proxy-libintl wrap.
meson_install glib -Dtests=false -Dinstalled_tests=false -Dintrospection=disabled \
  -Ddocumentation=false -Dman-pages=disabled -Dnls=disabled -Ddtrace=disabled \
  -Dsystemtap=disabled -Dsysprof=disabled -Dbsymbolic_functions=false -Dselinux=disabled \
  -Dlibmount=disabled -Dxattr=false -Dlibelf=disabled

echo "== pixman"
unpack pixman
meson_install pixman -Dtests=disabled -Ddemos=disabled -Dgtk=disabled -Dlibpng=disabled \
  -Dopenmp=disabled -Dtimers=false -Dgnuplot=false

echo "== libslirp"
unpack libslirp
meson_install libslirp

echo "== dtc (libfdt)"
unpack dtc
meson_install dtc -Dtools=false -Dyaml=disabled -Dvalgrind=disabled -Dpython=disabled -Dtests=false

echo "== nettle"
unpack nettle
# Ciphers and hashes only (VNC authentication and WebSocket); no public-key code or GMP.
(cd "$sources/nettle" && ./configure --prefix="$prefix" --libdir="$prefix/lib" --disable-static \
  --enable-shared --disable-public-key --disable-documentation --disable-openssl \
  && make -j "$jobs" && make install)

echo "== qemu"
unpack qemu
platform_options=(--disable-hvf)
if [[ "$system" == Darwin ]]; then platform_options=(--enable-hvf --audio-drv-list=coreaudio); fi
mkdir -p "$sources/qemu/_build"
(cd "$sources/qemu/_build" && ../configure --prefix="$stage" --target-list=x86_64-softmmu \
  --extra-cflags="$privacy $CPPFLAGS" --extra-ldflags="$LDFLAGS" "${platform_options[@]}" \
  --enable-slirp --enable-zstd --enable-nettle --enable-fdt=system --enable-vnc --enable-tools \
  --disable-gnutls --disable-gcrypt --disable-vnc-jpeg --disable-vnc-sasl --disable-png \
  --disable-docs --disable-guest-agent --disable-user --disable-werror --disable-debug-info --disable-rust \
  --disable-cocoa --disable-sdl --disable-gtk --disable-curses --disable-opengl --disable-virglrenderer \
  --disable-spice --disable-dbus-display --disable-libssh --disable-curl --disable-libusb \
  --disable-usb-redir --disable-smartcard --disable-capstone --disable-lzo --disable-snappy \
  --disable-bzip2 --disable-libiscsi --disable-libnfs --disable-rbd --disable-vde --disable-brlapi \
  --disable-tpm --disable-vmnet --disable-plugins --disable-replication \
  && make -j "$jobs" && make install)

echo "== collect runtime"
install -m 0755 "$stage/bin/qemu-system-x86_64" "$output/qemu-system-x86_64"
install -m 0755 "$stage/bin/qemu-img" "$output/qemu-img"
# The same firmware set the Windows runtime ships for these x86-64 machines.
mkdir -p "$output/share"
for file in bios.bin bios-256k.bin bios-microvm.bin edk2-i386-vars.fd edk2-licenses.txt \
  edk2-x86_64-code.fd efi-e1000e.rom efi-virtio.rom kvmvapic.bin linuxboot_dma.bin pvh.bin \
  qboot.rom vgabios.bin vgabios-bochs-display.bin vgabios-ramfb.bin vgabios-stdvga.bin vgabios-virtio.bin; do
  install -m 0644 "$stage/share/qemu/$file" "$output/share/$file"
done
cp -R "$stage/share/qemu/keymaps" "$output/share/keymaps"
if [[ "$system" == Darwin ]]; then
  python3 "$repo/scripts/macos-runtime/bundle_dylibs.py" "$output" "$prefix"
fi
python3 "$repo/scripts/macos-runtime/collect_notices.py" "$inputs" "$sources" "$output" "$arch"

echo "== corresponding sources"
bundle="$(dirname "$output")/yougori-macos-runtime-sources-$arch.tar"
rm -f -- "$bundle"
# The pinned archives, every wrap glib downloaded during its build, and this recipe.
(cd "$work" && tar -cf "$bundle" downloads)
if compgen -G "$sources/glib/subprojects/packagecache/*" >/dev/null; then
  (cd "$sources/glib/subprojects" && tar -rf "$bundle" packagecache)
fi
(cd "$repo" && tar -rf "$bundle" scripts/build-macos-runtime.sh scripts/sign-macos-runtime.sh scripts/macos-runtime)

echo "macOS runtime written to $output (sources: $bundle). Sign it with scripts/sign-macos-runtime.sh, which also writes its SHA256SUMS."
