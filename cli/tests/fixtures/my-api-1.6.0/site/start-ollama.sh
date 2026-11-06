#!/bin/sh
set -eu
# A stop reaches Ollama, so the sandbox stops at once rather than at the timeout.
child=
trap 'if [ -n "$child" ]; then kill -TERM "$child" 2>/dev/null || true; wait "$child" || true; fi; exit 0' TERM INT
if [ "${SELECTED_PROVIDERS+x}" = x ]; then
  case ",$SELECTED_PROVIDERS," in
    *,ollama,*) ;;
    *) echo 'Ollama is not selected. This reserved sandbox is idle.'; exec sleep 2147483647 ;;
  esac
fi
echo 'Waiting for the Hub Ollama installation.'
export PATH="$HOME/.local/share/yougori/bin:$HOME/.local/bin:/usr/local/bin:$PATH"
while :; do
  if [ -r "$HOME/.local/share/yougori/tool-env.sh" ]; then
    . "$HOME/.local/share/yougori/tool-env.sh"
  fi
  if command -v ollama >/dev/null 2>&1; then break; fi
  sleep 3
done
export OLLAMA_HOST=0.0.0.0:11434
export OLLAMA_MODELS=/models
# The sandbox has no restart policy, so Ollama is started again here if it stops.
while :; do
  ollama serve &
  child=$!
  wait "$child" || true
  child=
  echo 'Ollama stopped. Starting it again in 5 seconds.'
  sleep 5
done
