#!/bin/sh
# Writes the agent's instructions from the grants this setup actually made, every time the
# sandbox starts. Nothing here is a wish list: each line is written only when Yougori really
# granted that thing, so an agent reading the file sees exactly what it has.
#
# Yougori passes the grants in as environment variables when it creates the sandbox. The file is
# rewritten on every start, so a grant that is taken away disappears from it.
set -eu

out="${AGENT_INSTRUCTIONS_PATH:-/workspace/AGENTS.md}"
mkdir -p "$(dirname "$out")"

say() { printf '%s\n' "$1" >>"$out.new"; }

: >"$out.new"
say "# What this agent may do here"
say ""
say "Yougori wrote this file when the sandbox started, from the access this setup actually has."
say "Anything not listed here was not granted. Do not try to work around it: it will fail, and"
say "the attempt is recorded in the setup's activity."
say ""

say "## Tools"
say ""
if [ -n "${AGENT_TOOLS:-}" ]; then
  echo "$AGENT_TOOLS" | tr ',' '\n' | while read -r tool; do
    [ -n "$tool" ] || continue
    if command -v "$tool" >/dev/null 2>&1; then
      say "- \`$tool\` — installed and ready."
    else
      say "- \`$tool\` — declared, but not on the path yet; it may still be installing."
    fi
  done
else
  say "- No coding tools were installed. Use the shell and the files below."
fi
say ""
say "No other tool is installed, and nothing here may install one that reaches the network"
say "unless internet access is granted below."
say ""

say "## Files"
say ""
if [ -n "${AGENT_PROJECT:-}" ]; then
  if [ "${AGENT_PROJECT_WRITABLE:-no}" = "yes" ]; then
    say "- \`$AGENT_PROJECT\` — the project. You may read and change it. Changes are copied back"
    say "  to the owner's own folder, so treat them as real edits to their work."
  else
    say "- \`$AGENT_PROJECT\` — the project, read only. Copy anything you need to change elsewhere."
  fi
fi
if [ -n "${AGENT_REFERENCE:-}" ]; then
  say "- \`$AGENT_REFERENCE\` — reference material, read only. Never write here."
fi
say "- \`\$HOME\` and the rest of this sandbox's own disk — yours to use freely."
say ""
say "No folder on the owner's computer is reachable except the ones named above."
say ""

say "## The network"
say ""
if [ "${AGENT_INTERNET:-no}" = "yes" ]; then
  say "- The internet is reachable. Anything you send leaves this computer, so do not send the"
  say "  owner's files or anything you read here to a service they did not ask for."
else
  say "- There is no internet access. Commands that try to reach the network will fail."
fi
say ""

say "## Credentials"
say ""
say "- You have none, and you cannot ask for any. There is no key, token or password in this"
say "  sandbox, and no way to borrow the owner's. If a task needs one, stop and say so."
say ""

say "## If something is refused"
say ""
say "Say what you were trying to do and what you would need. Do not look for another route to it."
mv "$out.new" "$out"
printf 'Wrote the agent instructions to %s\n' "$out"
