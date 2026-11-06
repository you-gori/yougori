# Windows CLI installers — 2026-11-02

All **16 available harnesses** installed through their actual served PowerShell
scripts on Windows amd64, using Windows PowerShell 5.1. Each installed command
started its checksum-pinned, private Python runtime and reported the correct
harness version and server. No global Python install is needed.

[Transcript](windows-cli-install-2026-11-02.txt) ·
[Source hashes](windows-cli-install-2026-11-02.json)

The integration ran in a temporary portable install directory. It verified:

- Spaces, Unicode, apostrophes, percent signs and ampersands in the install path.
- Reinstallation of an identical release without damaging the working command.
- A second server gets a separate command; the first server's command is preserved.
- Wrong download checksums and ZIP path traversal are refused without replacing
  the working CLI. Failed staging directories are cleaned up.
- An installed `solver-pi` command, using the private Python runtime, ran the
  actual Pi client inside the existing Docker isolation and received the answer
  from a disposable Inference Solver/model HTTP fixture. No live GPU was used.
- No persistent user PATH change occurred in the test's portable mode.

The actual Windows runs found a PowerShell 5.1 null-string binding issue in
`File.Replace`; `[NullString]::Value` fixed atomic reinstallation. Hash calculation
uses .NET directly so it works without depending on an autoloaded `Get-FileHash`.

Also passed: 16 HTTP/contract scenarios, browser flows (including copyable
install commands and mobile layouts), root lint and root UI build. The build
retains its existing chunk-size/dynamic-import warnings.

CPython **3.14.10** amd64 and arm64 archive checksums were obtained from the
[official Windows distributions](https://www.python.org/downloads/windows/).
The amd64 runtime was executed; Windows ARM64 was not independently tested.
Default persistent PATH registration was reviewed but the integration deliberately
used portable mode. SHA-256 verification is not a separate publisher signature.

The five previously unavailable service integrations remain unavailable. This
change provides installable CLI commands for the 16 working profiles; it does not
claim those five integrations or public deployment are complete.
