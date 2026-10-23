#!/bin/sh
# Executed by the native owner before research, with installation networking.
# Runtime, interpreter and dependency lock remain root-owned and immutable to the agent.
set -eu
root=/srv/yougori-swarm
revision=4d04303818b61bf3aa09278af48356315515965b
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends python3 python3-venv git ca-certificates
python3 -m venv "$root/bootstrap"
"$root/bootstrap/bin/pip" install --disable-pip-version-check uv==0.11.21
export UV_PYTHON_INSTALL_DIR="$root/python"
export UV_CACHE_DIR="$root/cache"
export UV_LINK_MODE=copy
export UV_NO_CACHE=1
export HERMES_HOME="$root/install-home"
if [ ! -d "$root/hermes/.git" ]; then
    git init "$root/hermes"
    git -C "$root/hermes" remote add origin https://github.com/NousResearch/hermes-agent.git
fi
git -C "$root/hermes" fetch --depth 1 origin "$revision"
git -C "$root/hermes" checkout --detach "$revision"
test "$(git -C "$root/hermes" rev-parse HEAD)" = "$revision"
cd "$root/hermes"
"$root/bootstrap/bin/uv" sync --python 3.14 --frozen --no-dev
chmod -R a+rX "$root/hermes" "$root/python"
"$root/hermes/.venv/bin/python" -c 'from run_agent import AIAgent'
printf '%s' "$revision" > "$root/hermes-revision"
