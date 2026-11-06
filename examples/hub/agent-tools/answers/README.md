# Example answers

No secrets are needed: this template gives the agent no credential of any kind.

```text
yougori template run ./examples/hub/agent-tools --inputs answers/read-only.json --yes
```

- `read-only.json`: Claude Code with the internet on, reading the project but not changing it.
- `offline-editor.json`: OpenCode with no internet at all, allowed to change the project.

Setup asks which folders to use; those choices belong to your computer and are never in a file
you publish.
