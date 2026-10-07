# Tool shortcuts in your terminal

```powershell
yougori codex
yougori claude
yougori gemini
yougori opencode
yougori kilo
yougori ollama
yougori openclaw
```

The first command creates a local Ubuntu 24.04 container, installs the selected
tool, and starts it in the terminal where you ran the command. Later calls reuse
the tool's container and installed binary. Files in `/workspace` and tool sign-in
stay in that container. The desktop terminal view does not open.
New containers default to 2 CPU cores, 4 GB memory and 20 GB storage.

Ollama runs `serve` by default. OpenClaw starts interactive `onboard`; complete its
own account setup and permissions there. Other shortcuts start the tool's usual
interactive interface. Yougori does not sign in or copy host credentials.

```powershell
yougori codex --new --memory 8GB
yougori claude --name writing
yougori gemini --environment EXISTING_CONTAINER
yougori codex -- --help
yougori ollama -- run MODEL
yougori openclaw -- gateway run
yougori kilo --dry-run
```

Creation options (`--image`, `--cpu`, `--memory`, `--storage`, `--storage-drive`,
`--gpu nvidia`, and `--mount`) need a new container. A default container has no
GPU access or shared PC folders. `--environment` explicitly installs/runs the
tool in a chosen local container instead. Put tool arguments after `--`.

Ctrl+] closes this terminal session and returns to your host terminal. The
container, files and sign-in remain; the attached program can stop when its
terminal closes. Exiting the tool also returns to the host terminal. Run the
shortcut again to reconnect, or `yougori stop ENV` to stop its container.
Noninteractive calls require `--dry-run`, which validates without creating,
installing or starting anything. `yougori TOOL --help` lists all options.
