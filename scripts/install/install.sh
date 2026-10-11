#!/bin/sh
# Yougori CLI and engine installer for macOS and Linux. Download the desktop app separately.
#   curl -fsSL https://yougori.com/install.sh | bash
# Downloads the current release, checks its SHA-256 (and on macOS the Apple signature of the
# release's Developer ID team), installs it for this user by default, or through apt for an
# explicit Debian/Ubuntu desktop install. Links `yougori` into ~/.local/bin, saves PATH for future
# shells and starts the engine. Linux packages have no publisher signature beyond the HTTPS
# manifest's SHA-256.
# Environment overrides: YOUGORI_ENGINE_ONLY=0 (opt into the desktop bundle),
# YOUGORI_RELEASES_URL (HTTPS manifest), YOUGORI_AUTOSTART=1, YOUGORI_START_ENGINE=0,
# YOUGORI_ALLOW_UNSIGNED=1 (macOS test builds only).
set -eu

# Developer ID team of the macOS release signer. scripts/release-manifest.mjs fills this in when
# it prepares the copy served by yougori.com.
apple_team='__YOUGORI_APPLE_TEAM_ID__'

fail() { printf 'Yougori install failed: %s\n' "$1" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || fail "this installer needs '$1'"; }
https_url() {
  case "$1" in https://*) ;; *) fail "$2 must use HTTPS without credentials" ;; esac
  authority=${1#https://}
  authority=${authority%%[/?#]*}
  case "$authority" in ''|*@*) fail "$2 must use HTTPS without credentials" ;; esac
}
need curl
need uname
need tar

manifest_url="${YOUGORI_RELEASES_URL:-https://yougori.com/releases/latest.json}"
https_url "$manifest_url" "YOUGORI_RELEASES_URL"
engine_only="${YOUGORI_ENGINE_ONLY:-1}"
start_engine="${YOUGORI_START_ENGINE:-1}"
case "$start_engine" in 0|1) ;; *) fail "YOUGORI_START_ENGINE must be 0 or 1" ;; esac
missing=""

os=$(uname -s)
arch=$(uname -m)
case "$arch" in x86_64|amd64) arch=x86_64 ;; arm64|aarch64) arch=aarch64 ;; *) fail "unsupported processor $arch" ;; esac
case "$os" in Darwin) platform="macos-$arch" ;; Linux) platform="linux-$arch" ;; *) fail "unsupported system $os (on Windows use: irm https://yougori.com/install.ps1 | iex)" ;; esac
[ "$engine_only" = "1" ] && platform="$platform-engine"

# Verifies an Apple signature from the pinned release team (extra arguments such as --deep come first).
mac_verify() {
  if [ "$apple_team" = "__YOUGORI_APPLE_""TEAM_ID__" ]; then
    [ "${YOUGORI_ALLOW_UNSIGNED:-}" = "1" ] || fail "this copy of the installer was not prepared for a macOS release (no Developer ID team pin). Use the one from https://yougori.com/install.sh."
    codesign --verify --strict "$@" 2>/dev/null
    return
  fi
  codesign --verify --strict -R="anchor apple generic and certificate leaf[subject.OU] = \"$apple_team\"" "$@" 2>/dev/null
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

echo "Finding the latest Yougori release..."
manifest=$(curl --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 90 -fsSL "$manifest_url") || fail "cannot read $manifest_url"
# Read one asset field without requiring jq: the manifest is small, flat JSON per asset.
field() {
  printf '%s' "$manifest" | tr -d '\n' | sed -n "s/.*\"$platform\"[[:space:]]*:[[:space:]]*{\([^}]*\)}.*/\1/p" | sed -n "s/.*\"$1\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}
version=$(printf '%s' "$manifest" | tr -d '\n' | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
url=$(field url)
sha=$(field sha256)
[ -n "$url" ] && [ -n "$sha" ] || fail "release $version has no download for $platform yet"
https_url "$url" "the release download"
[ "${#sha}" = 64 ] || fail "the release SHA-256 is invalid"
case "$sha" in *[!0-9a-fA-F]*) fail "the release SHA-256 is invalid" ;; esac

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
asset_url=${url%%#*}
asset_path=${asset_url%%\?*}
file="$work/$(basename "$asset_path")"
# The server saves aggregate command/app totals, without visitor identifiers.
case "$asset_url" in
  *\?*) download_url="${asset_url}&source=command" ;;
  *) download_url="${asset_url}?source=command" ;;
esac
echo "Downloading Yougori $version..."
curl --proto '=https' --proto-redir '=https' --connect-timeout 20 --max-time 900 -fL --progress-bar "$download_url" -o "$file" || fail "download failed"
[ "$(hash_file "$file")" = "$(printf '%s' "$sha" | tr 'A-F' 'a-f')" ] || fail "the download does not match the published SHA-256. Nothing was installed."

bin="$HOME/.local/bin"
mkdir -p "$bin"
case "$platform" in
  *-engine)
    # The engine and CLI without the desktop app. It needs no display; Linux uses the system QEMU.
    case "$file" in *.tar.gz) ;; *) fail "expected a .tar.gz engine archive" ;; esac
    staged="$work/unpacked"
    mkdir -p "$staged"
    tar -xzf "$file" -C "$staged" || fail "cannot unpack the engine archive. Nothing was installed."
    [ -f "$staged/yougori-engine" ] && [ -f "$staged/cli/yougori" ] || fail "the engine archive is incomplete. Nothing was installed."
    if [ "$os" = "Darwin" ]; then
      mac_verify "$staged/yougori-engine" || fail "the engine signature is not valid. Nothing was installed."
      mac_verify "$staged/cli/yougori" || fail "the CLI signature is not valid. Nothing was installed."
    fi
    target="$HOME/.local/opt/yougori-engine"
    if [ -x "$target/cli/yougori" ] && "$target/cli/yougori" app status >/dev/null 2>&1; then
      "$target/cli/yougori" app quit --yes >/dev/null 2>&1 || fail "the running engine refused to stop. Existing files were left untouched."
      attempts=0
      while "$target/cli/yougori" app status >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        [ "$attempts" -lt 60 ] || fail "the running engine did not stop. Existing files were left untouched."
        sleep 1
      done
    fi
    mkdir -p "$target"
    cp -R "$staged/." "$target/"
    chmod 755 "$target/yougori-engine" "$target/cli/yougori"
    ln -sf "$target/cli/yougori" "$bin/yougori"
    if [ "$os" = "Linux" ]; then
      missing=""
      command -v qemu-system-x86_64 >/dev/null 2>&1 || missing="$missing qemu-system-x86_64"
      command -v qemu-img >/dev/null 2>&1 || missing="$missing qemu-img"
      if command -v ldconfig >/dev/null 2>&1 && ! ldconfig -p 2>/dev/null | grep -q 'libgtk-3.so.0'; then missing="$missing libgtk-3"; fi
      [ -z "$missing" ] || echo "Also install:$missing  (Debian/Ubuntu: sudo apt-get install -y qemu-system-x86 qemu-utils ovmf libgtk-3-0)"
    fi
    ;;
  macos-*)
    case "$file" in *.dmg) ;; *) fail "expected a .dmg for macOS" ;; esac
    mount="$work/mount"
    mkdir -p "$mount"
    hdiutil attach -nobrowse -quiet -mountpoint "$mount" "$file" || fail "cannot open the disk image"
    app=$(find "$mount" -maxdepth 1 -name '*.app' | head -n 1)
    [ -n "$app" ] || { hdiutil detach -quiet "$mount"; fail "no app in the disk image"; }
    mac_verify --deep "$app" || { hdiutil detach -quiet "$mount"; fail "the app signature is not valid. Nothing was installed."; }
    mkdir -p "$HOME/Applications"
    rm -rf "$HOME/Applications/Yougori.app"
    cp -R "$app" "$HOME/Applications/Yougori.app"
    hdiutil detach -quiet "$mount"
    ln -sf "$HOME/Applications/Yougori.app/Contents/Resources/cli/yougori" "$bin/yougori"
    ;;
  linux-*)
    case "$file" in *.deb) ;; *) fail "expected a .deb installer for Linux" ;; esac
    need apt-get
    echo "Installing the Debian/Ubuntu package and its runtime dependencies (administrator access required)..."
    if [ "$(id -u)" = 0 ]; then
      apt-get install -y "$file" || fail "package installation failed"
    else
      need sudo
      sudo apt-get install -y "$file" || fail "package installation failed"
    fi
    # The package owns /usr/bin/yougori and the desktop runtime together.
    # Replace a previous per-user launcher so it cannot shadow the installed CLI.
    ln -sf /usr/bin/yougori "$bin/yougori"
    ;;
esac

# A piped installer cannot change its parent shell. Persist the setting without
# replacing the user's profiles, then give an exact command for this terminal.
save_path() {
  profile="$1"
  if [ -f "$profile" ] && grep -qF '# Yougori CLI PATH' "$profile"; then return; fi
  if ! cat >> "$profile" <<'PROFILE'

# Yougori CLI PATH
case ":$PATH:" in
  *":$HOME/.local/bin:"*) ;;
  *) export PATH="$HOME/.local/bin:$PATH" ;;
esac
PROFILE
  then printf 'Could not save PATH in %s; add ~/.local/bin to your shell PATH.\n' "$profile" >&2; fi
}
save_path "$HOME/.profile"
case "${SHELL:-/bin/bash}" in
  */bash)
    save_path "$HOME/.bashrc"
    for profile in "$HOME/.bash_profile" "$HOME/.bash_login"; do
      [ ! -f "$profile" ] || save_path "$profile"
    done
    ;;
  */zsh) save_path "$HOME/.zprofile"; save_path "$HOME/.zshrc" ;;
esac
case ":$PATH:" in
  *":$bin:"*) ;;
  *)
    echo 'PATH saved for future shells. In this terminal, run:'
    echo 'export PATH="$HOME/.local/bin:$PATH"'
    PATH="$bin:$PATH"
    export PATH
    ;;
esac
# Skill setup needs only the installed CLI, even when engine startup is skipped
# or runtime dependencies are missing. Use this install's executable, not a
# possibly older Yougori command elsewhere on PATH.
echo "Setting up the Yougori skill..."
if skill_output=$("$bin/yougori" skills install 2>&1); then
  echo "Yougori skill ready: $HOME/Yougori/Workspace/skills/yougori"
else
  printf '%s\n' "$skill_output" >&2
  echo 'Yougori is installed. Existing custom skills were preserved; retry skill setup with: yougori skills install' >&2
fi
[ "${YOUGORI_AUTOSTART:-}" = "1" ] && "$bin/yougori" app autostart on >/dev/null || true
if [ "$start_engine" = "1" ] && [ -z "$missing" ]; then
  echo "Starting the Yougori engine..."
  if "$bin/yougori" app start; then
    "$bin/yougori" doctor --format table || true
  else
    echo 'The files are installed, but engine startup failed. Check: yougori doctor --format table' >&2
  fi
elif [ -n "$missing" ]; then
  echo 'After installing the dependencies above, run: ~/.local/bin/yougori app start'
else
  echo 'Engine startup skipped. Start it with: ~/.local/bin/yougori app start'
fi
echo
if [ "$engine_only" = "1" ]; then echo "Yougori $version is installed (engine only, no desktop app). Try: yougori status"
else echo "Yougori $version is installed. Try: yougori status"; fi
[ "${YOUGORI_AUTOSTART:-}" = "1" ] || echo "Keep the engine ready at login with: yougori app autostart on"
