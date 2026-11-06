# Harness delivery from a hosted development VM — 2026-11-04

The new website-created VM initially advertised zero available harnesses: its
staged source did not include the publisher's image directory. Copying multi-GB
archives into every guest would also exceed the website's response budget.

The website host now verifies each image/tool archive's version, size and SHA-256
and gives the guest a manifest. A read-only host endpoint serves only those public,
immutable artifacts. Accounts and model traffic remain on the instance's own VM
origin. The launcher allows the additional loopback destination only for package
bytes and checks their size/hash again; it never sends credentials there.
Python and PowerShell explicitly connect isolated `.localhost` origins to loopback
while preserving the publication's Host identity. Redirects remain refused.

## Results

- The running hosted instance reports **21/21 available**.
- All 21 image/tool downloads were fetched through that instance's manifest and
  matched their complete byte counts and hashes.
- A real PowerShell 5.1 installation installed Pi from the VM origin in a portable
  test directory. Its downloaded CLI started, retained the correct server binding,
  and downloaded/verified/imported the actual VM image. User PATH was not changed.
- All fifteen newly built clients passed model-call checks in real Yougori VMs:
  Codex, OpenCode, Kilo, Qwen Code, Cline, Claude Code, Aider, Open Interpreter,
  Goose, DeepSeek, Gemini, OpenHands, Grok, SWE-agent and PentestGPT.
- Pi was also rerun successfully in a real VM. Plandex, Strix, Shannon, PentAGI
  and HexStrike reused their existing packages; their earlier native validation
  is recorded in `native-harnesses-2026-11-04.md` and
  `shannon-session-2026-11-04.md`. They were not rerun here.
- The model for these checks was a disposable HTTP fixture, not a GPU benchmark
  or an external target. These checks exercise client/relay startup and model calls,
  not every tool command or the quality of a real model's work.
- Ten website server tests passed, plus the 21-test harness/service suite,
  artifact availability, three hosted-download boundary/recovery tests, two
  hosted-state tests, TypeScript compilation, JS syntax and diff checks.
- The test VMs are stopped. The development inference is running; the dedicated
  WSL package builder is stopped. No production deployment or paid resource was used.

The instance currently has no connected models. Installation is available;
running a harness needs a model connected by its administrator.

[Package identities and check records](hosted-harnesses-2026-11-04.json).
Full runtime logs and portable install results remain under
`D:/YougoriBuildCache/scratch/website-restart/`.

Contributor installer follow-up: the Admin contributor command had missed the
PowerShell `.localhost` fix. Both installation views now use `installCommand`.
The node bundle includes the shared loopback transport, and its pairing, polling
and relay requests preserve the website Host and Origin without DNS or proxies.
Redirects remain refused. The existing VM was updated and its website process
restarted at the same address, preserving accounts and data.

`runtime_contributor_install.py` passed all four checks against that running VM:
the actual displayed command installs with Windows PowerShell 5.1, the private
Python contributor starts, its server binding stays intact, and an invalid agent
credential reaches the real endpoint and receives HTTP 401. The portable check
does not change user PATH or contribute any resources. `test_hosted_downloads.py`
passed 4/4 (including extracted-bundle execution and Host/Origin/auth preservation);
`test_compute.py` passed 33/33. Records are in
`D:/YougoriBuildCache/scratch/website-restart/contributor-install/result.json`.
