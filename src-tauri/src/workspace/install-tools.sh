# Executed inside the selected container or CLI MicroVM, never on the host.
set -eu
od_work=${0%/*}
od_locked=0
od_lock="${HOME:?This image needs a writable HOME}/.local/share/yougori/install.lock"
od_cleanup() {
  od_status=$?
  trap - EXIT HUP INT TERM
  if [ "$od_locked" = 1 ]; then rm -f "$od_lock/pid" "$od_lock/identity"; rmdir "$od_lock" 2>/dev/null || true; fi
  case "$od_work" in /tmp/yougori-install.*)
    rm -f "$od_work/install.sh" "$od_work/download" "$od_work/SHASUMS256.txt" "$od_work/node.tar.gz" "$od_work/ollama.tar.zst" "$od_work/ollama.tar" "$od_work/.curlrc"
    rmdir "$od_work" 2>/dev/null || true;;
  esac
  if [ "$od_status" != 0 ]; then
    printf '\nInstallation failed (exit %s). Read the error above, then click the tool button to retry.\n' "$od_status" >&2
    if [ "$od_status" = 137 ]; then printf '%s\n' 'The process was killed; it may have run out of memory. Increase this container’s memory in its Resources settings and retry.' >&2; fi
  fi
  exit "$od_status"
}
trap od_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
mkdir -p "$HOME/.local/bin" "$HOME/.local/share/yougori"
# Serialize current installers with a kernel lock when flock is available.
# The directory remains compatible with older installer scripts.
if command -v flock >/dev/null 2>&1; then
  exec 9>"$HOME/.local/share/yougori/install.guard"
  if ! flock -n 9; then
    printf '%s\n' 'Another coding-tool installer is still running in this environment. Wait for its install tab to finish, or cancel it there with Ctrl+C.' >&2
    exit 1
  fi
fi
od_process_identity() {
  [ -r "/proc/$1/stat" ] && [ -r /proc/sys/kernel/random/boot_id ] || return 1
  od_stat=$(cat "/proc/$1/stat") || return 1
  # Remove pid and comm (which may contain spaces); starttime is field 20 after them.
  od_start=$(printf '%s\n' "${od_stat##*) }" | awk '{print $20}')
  [ -n "$od_start" ] || return 1
  printf '%s:%s\n' "$(cat /proc/sys/kernel/random/boot_id)" "$od_start"
}
od_owner_live() {
  case "$od_pid" in ''|*[!0-9]*|0|1) return 1;; esac
  kill -0 "$od_pid" 2>/dev/null || return 1
  if [ -s "$od_lock/identity" ]; then
    od_current=$(od_process_identity "$od_pid") || return 0
    [ "$(cat "$od_lock/identity")" = "$od_current" ] || return 1
  fi
  # Also check legacy PID-only locks: PID reuse is not proof of a live installer.
  [ -r "/proc/$od_pid/cmdline" ] || return 0
  tr '\000' '\n' < "/proc/$od_pid/cmdline" | grep -Eq '^/tmp/yougori-install\.[^/]+/install\.sh$'
}
if [ -d "$od_lock" ]; then
  od_pid=$(cat "$od_lock/pid" 2>/dev/null || true)
  if [ -n "$od_pid" ]; then
    if ! od_owner_live; then
      rm -f "$od_lock/pid" "$od_lock/identity"
      rmdir "$od_lock" 2>/dev/null || true
    fi
  else
    # Allow an older installer to finish writing its PID before recovering an orphan.
    od_modified=$(stat -c %Y "$od_lock" 2>/dev/null || printf 0)
    if [ "$(( $(date +%s) - od_modified ))" -gt 30 ]; then
      rmdir "$od_lock" 2>/dev/null || true
    fi
  fi
fi
if ! mkdir "$od_lock" 2>/dev/null; then
  printf '%s\n' 'Another coding-tool installer is still running in this environment. Wait for its install tab to finish, or cancel it there with Ctrl+C.' >&2
  exit 1
fi
od_locked=1
printf '%s\n' "$$" > "$od_lock/pid"
od_process_identity "$$" > "$od_lock/identity" || rm -f "$od_lock/identity"
export PATH="$HOME/.local/bin:$PATH"
printf '\nInstalling %s inside this environment...\n' "$od_tool"
printf '%s\n' 'Downloads and package-manager progress appear below. Sign-in is separate after installation.'

od_root() {
  if [ "$(id -u)" = 0 ]; then "$@"
  elif command -v sudo >/dev/null 2>&1; then sudo "$@"
  elif command -v doas >/dev/null 2>&1; then doas "$@"
  else printf '%s\n' 'This image runs as a non-root user without sudo/doas. Install prerequisites as root inside the container, or use an Alpine, Ubuntu, Debian, or Node.js development image.' >&2; return 1
  fi
}
od_pm=none
for od_candidate in apk apt-get dnf microdnf yum zypper pacman swupd; do
  if command -v "$od_candidate" >/dev/null 2>&1; then od_pm=$od_candidate; break; fi
done
printf 'Detected package manager: %s\n' "$od_pm"
if [ "$od_pm" = apk ] && [ -r /etc/alpine-release ]; then
  od_alpine=$(cat /etc/alpine-release)
  od_major=$(printf '%s' "$od_alpine" | cut -d . -f 1)
  od_minor=$(printf '%s' "$od_alpine" | cut -d . -f 2)
  if [ "$od_major" = 3 ] && [ "$od_minor" -lt 19 ] 2>/dev/null; then
    printf '\nThis is legacy Alpine %s. Prefer a new Alpine 3.24 or Node.js container for current coding tools. Existing files have not been upgraded or removed.\n' "$od_alpine" >&2
    if [ "$od_tool" = claude ]; then
      printf '%s\n' 'Claude Code requires Alpine 3.19 or newer. No installer was downloaded.' >&2
      exit 1
    fi
  fi
fi
od_packages() {
  case "$od_pm" in
    apk) od_root apk add --no-cache "$@";;
    apt-get) od_root env DEBIAN_FRONTEND=noninteractive apt-get update; od_root env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@";;
    dnf|microdnf|yum) od_root "$od_pm" install -y "$@";;
    zypper) od_root zypper --non-interactive install --no-recommends "$@";;
    pacman) od_root pacman -Syu --needed --noconfirm "$@";;
    swupd) od_root swupd bundle-add "$@";;
    *) printf '%s\n' 'This minimal image has no supported package manager. Use a development image (Alpine, Ubuntu, Debian, or Node.js), or install the missing prerequisites in a custom image: curl, CA certificates, bash, git, tar, and gzip.' >&2; return 1;;
  esac
}
# Use the actual root filesystem, not mutable tags: MongoDB normally uses
# Ubuntu, and language/service images may be Debian, Alpine, or another base.
set -- ca-certificates
od_missing=0
for od_dep in curl bash git tar gzip; do
  if ! command -v "$od_dep" >/dev/null 2>&1; then set -- "$@" "$od_dep"; od_missing=1; fi
done
if [ ! -s /etc/ssl/certs/ca-certificates.crt ] && [ ! -s /etc/pki/tls/certs/ca-bundle.crt ]; then od_missing=1; fi
if [ "$od_missing" = 1 ]; then
  printf '%s\n' 'Installing download and shell prerequisites...'
  case "$od_pm" in swupd) od_packages sysadmin-basic git;; *) od_packages "$@";; esac
fi
if [ "$od_pm" = apk ]; then
  if [ "$od_tool" = claude ]; then od_packages libgcc libstdc++ ripgrep
  else od_packages libgcc libstdc++; fi
fi
# Large tools (Ollama is over a gigabyte) take as long as the connection needs: a download stops
# only when it stalls below 10 KB/s for two minutes, and transient failures are retried.
od_download() {
  curl --fail --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 20 --speed-limit 10240 --speed-time 120 --retry 3 --retry-delay 5 "$1" -o "$2"
}

# The tools' own install scripts download with curl too, often without any limit: a stalled
# download would hold the install lock forever. This file gives every curl here the same rule.
case "$od_work" in /tmp/yougori-install.*)
  printf '%s\n' 'connect-timeout = 20' 'speed-limit = 10240' 'speed-time = 120' > "$od_work/.curlrc"
  export CURL_HOME="$od_work";;
esac

case "$od_tool" in
  codex)
    od_download https://chatgpt.com/codex/install.sh "$od_work/download"
    CODEX_NON_INTERACTIVE=1 sh "$od_work/download"
    # The musl app-server daemon exits before Codex records its start time
    # (openai/codex#29186). Codex self-updates replace ~/.local/bin/codex, so
    # the wrapper lives in a directory that tool-env.sh puts ahead of it.
    mkdir -p "$HOME/.local/share/yougori/bin"
    # If Codex is later installed elsewhere, run the next codex on PATH instead.
    printf '%s\n' '#!/bin/sh' \
      '[ ! -x "$HOME/.local/bin/codex" ] || exec "$HOME/.local/bin/codex" --no-daemon "$@"' \
      'od_path=; od_ifs=$IFS; IFS=:' \
      'for od_dir in $PATH; do [ "$od_dir" = "$HOME/.local/share/yougori/bin" ] || od_path=${od_path:+$od_path:}$od_dir; done' \
      'IFS=$od_ifs; PATH=$od_path; export PATH' \
      'exec codex --no-daemon "$@"' > "$HOME/.local/share/yougori/bin/codex"
    chmod 755 "$HOME/.local/share/yougori/bin/codex"
    ;;
  claude)
    od_download https://claude.ai/install.sh "$od_work/download"
    bash "$od_work/download"
    ;;
  opencode)
    # The upstream installer selects musl/glibc and baseline CPU binaries.
    od_download https://opencode.ai/install "$od_work/download"
    bash "$od_work/download" --no-modify-path
    printf '%s\n' '#!/bin/sh' 'exec "$HOME/.opencode/bin/opencode" "$@"' > "$HOME/.local/bin/opencode"
    chmod 755 "$HOME/.local/bin/opencode"
    ;;
  openclaw)
    case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) printf '%s\n' 'Automatic OpenClaw installation supports x64 and ARM64 Linux containers. Use a 64-bit Ubuntu, Debian, or Node.js image.' >&2; exit 1;; esac
    if ! command -v sha256sum >/dev/null 2>&1; then od_packages coreutils; fi
    # Use upstream's private-runtime installer, not Gemini/Kilo's older Node.
    # Upstream verifies Node downloads and handles npm lifecycle requirements.
    od_download https://openclaw.ai/install-cli.sh "$od_work/download"
    if bash "$od_work/download" --prefix "$HOME/.local/share/yougori/openclaw" --install-method npm --version latest --no-onboard; then
      printf '%s\n' '#!/bin/sh' 'exec "$HOME/.local/share/yougori/openclaw/bin/openclaw" "$@"' > "$HOME/.local/bin/openclaw"
      chmod 755 "$HOME/.local/bin/openclaw"
    else
      od_install_status=$?
      if [ "$od_pm" = apk ]; then
        printf '%s\n' 'If OpenClaw rejected the Alpine Node/SQLite runtime, use an Ubuntu/Debian container or a current official node:26-alpine image. Do not bypass its runtime safety checks.' >&2
      fi
      exit "$od_install_status"
    fi
    ;;
  ollama)
    if [ "$od_pm" = apk ]; then
      # Alpine's signed package uses musl; do not inject glibc or GPU drivers.
      if ! od_packages ollama; then
        printf '%s\n' 'Ollama needs a current Alpine image with its matching community repository enabled, or an Ubuntu/Debian container. No repositories were changed.' >&2
        exit 1
      fi
      # Resolve the package binary independently of a previous managed wrapper.
      (PATH=/usr/bin:/bin command -v ollama) > "$HOME/.local/share/yougori/ollama-path"
      printf '%s\n' '#!/bin/sh' 'IFS= read -r od_binary < "$HOME/.local/share/yougori/ollama-path"' 'exec "$od_binary" "$@"' > "$HOME/.local/bin/ollama"
      printf '%s\n' 'The Alpine Ollama package uses CPU inference; this does not enable GPU/CUDA access.'
    else
      case "$(uname -m)" in x86_64) od_arch=amd64;; aarch64|arm64) od_arch=arm64;; *) printf '%s\n' 'Ollama downloads support x64 and ARM64 Linux images.' >&2; exit 1;; esac
      if ! command -v zstd >/dev/null 2>&1; then od_packages zstd; fi
      od_ollama="$HOME/.local/share/yougori/ollama"
      mkdir -p "$od_ollama"
      od_download "https://ollama.com/download/ollama-linux-$od_arch.tar.zst" "$od_work/ollama.tar.zst"
      # Stream extraction: an intermediate uncompressed tar can consume several
      # extra GB and fill an otherwise adequate container disk. Bash is already
      # a prerequisite; pipefail checks BOTH decompression and extraction so a
      # truncated archive cannot be reported as a successful installation.
      bash -o pipefail -c 'zstd -dc -- "$1" | tar -xf - -C "$2"' _ "$od_work/ollama.tar.zst" "$od_ollama"
      printf '%s\n' '#!/bin/sh' 'exec "$HOME/.local/share/yougori/ollama/bin/ollama" "$@"' > "$HOME/.local/bin/ollama"
    fi
    chmod 755 "$HOME/.local/bin/ollama"
    ;;
  gemini|kilo)
    # Reuse an adequate installed Node.js; Alpine needs its native musl build.
    # For other images, use a private official Node without replacing app Node.
    if ! command -v node >/dev/null 2>&1 || ! command -v npm >/dev/null 2>&1 || ! node -e 'process.exit(Number(process.versions.node.split(".")[0]) >= 20 ? 0 : 1)'; then
      if [ "$od_pm" = apk ]; then
        od_packages nodejs npm
      else
        case "$(uname -m)" in x86_64) od_arch=x64;; aarch64|arm64) od_arch=arm64;; *) printf '%s\n' 'Automatic Node setup supports x64 and ARM64 images.' >&2; exit 1;; esac
        if ! command -v sha256sum >/dev/null 2>&1; then od_packages coreutils; fi
        od_download https://nodejs.org/dist/latest-v22.x/SHASUMS256.txt "$od_work/SHASUMS256.txt"
        od_line=$(grep " node-v22\.[0-9][0-9]*\.[0-9][0-9]*-linux-$od_arch.tar.gz$" "$od_work/SHASUMS256.txt")
        od_hash=${od_line%% *}
        od_archive=${od_line##* }
        case "$od_hash" in *[!a-f0-9]*|'') printf '%s\n' 'Invalid Node.js checksum manifest.' >&2; exit 1;; esac
        [ "${#od_hash}" = 64 ] || exit 1
        od_version=${od_archive%-linux-*}
        od_version=${od_version#node-}
        od_download "https://nodejs.org/dist/$od_version/$od_archive" "$od_work/node.tar.gz"
        printf '%s  %s\n' "$od_hash" "$od_work/node.tar.gz" | sha256sum -c -
        od_node_dir="$HOME/.local/share/yougori/$od_version-$od_arch"
        mkdir -p "$od_node_dir"
        tar -xzf "$od_work/node.tar.gz" -C "$od_node_dir" --strip-components=1
        export PATH="$od_node_dir/bin:$PATH"
      fi
    fi
    node -e 'if (Number(process.versions.node.split(".")[0]) < 20) { console.error("This installer needs Node.js 20 or newer. Use a current Node.js or Alpine image."); process.exit(1); }'
    case "$od_tool" in gemini) od_package=@google/gemini-cli;; kilo) od_package=@kilocode/cli;; esac
    od_prefix="$HOME/.local/share/yougori/$od_tool"
    npm install --global --prefix "$od_prefix" "$od_package"
    command -v node > "$od_prefix/node-path"
    # Record Node as data, not interpolated shell code. Keep system Node intact.
    printf '%s\n' '#!/bin/sh' "od_tool='$od_tool'" 'od_base="$HOME/.local/share/yougori/$od_tool"' 'IFS= read -r od_node < "$od_base/node-path"' 'export PATH="${od_node%/*}:$PATH"' 'exec "$od_base/bin/$od_tool" "$@"' > "$HOME/.local/bin/$od_tool"
    chmod 755 "$HOME/.local/bin/$od_tool"
    ;;
  *) printf '%s\n' 'Unknown coding tool.' >&2; exit 1;;
esac

# Append a managed hook; never replace user profiles or host environment vars.
od_env="$HOME/.local/share/yougori/tool-env.sh"
printf '%s\n' 'export PATH="$HOME/.local/share/yougori/bin:$HOME/.local/bin:$PATH"' > "$od_env"
if [ "$od_pm" = apk ]; then printf '%s\n' 'export USE_BUILTIN_RIPGREP=0' >> "$od_env"; fi
set -- "$HOME/.profile" "$HOME/.bashrc"
for od_login in "$HOME/.bash_profile" "$HOME/.bash_login"; do
  if [ -f "$od_login" ]; then set -- "$@" "$od_login"; fi
done
for od_profile in "$@"; do
  if ! grep -Fq '.local/share/yougori/tool-env.sh' "$od_profile" 2>/dev/null; then
    printf '\n%s\n' '[ ! -r "$HOME/.local/share/yougori/tool-env.sh" ] || . "$HOME/.local/share/yougori/tool-env.sh"' >> "$od_profile"
  fi
done
. "$od_env"
printf '\nVerifying %s...\n' "$od_tool"
"$HOME/.local/bin/$od_tool" --version
printf '\n%s installed.\n' "$od_tool"
case "$od_tool" in
  ollama) printf '%s\n' 'Open a new terminal and run: ollama serve' 'Keep it open. In another terminal, run: ollama run MODEL_NAME (replace MODEL_NAME with your chosen model).' 'No models were downloaded and no server was started. Models use additional disk space and memory. GPU use depends on the container runtime and drivers, not this installer.';;
  openclaw) printf '%s\n' 'Open a new terminal and run: openclaw onboard' 'Complete provider sign-in and review its permissions there. For a container without systemd, keep the gateway in a terminal with: openclaw gateway run' 'No onboarding was run and no port was published by Yougori. Only share folders and connect accounts that you intend OpenClaw to access.';;
  opencode|kilo) printf 'Open a new terminal, run %s, then use /connect to configure your provider.\n' "$od_tool";;
  *) printf 'Open a new terminal and run %s to sign in.\n' "$od_tool";;
esac
