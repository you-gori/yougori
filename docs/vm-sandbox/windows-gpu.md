# GPU acceleration in Windows Sandbox VMs

The Windows development backend uses a separate HCS Linux VM when a sandbox
requests GPU acceleration. CPU-only sandboxes continue to use QEMU/WHPX. The
GPU VM uses the same authenticated guest protocol, workspace staging and review,
credential relay, resource ledger, OCI workload support and lifetime supervisor.
It does not run the application in a shared WSL distribution or a host container.

## Using it

In **New environment → Sandbox VM**, enable **GPU acceleration**. The engine
reports whether this computer has the matching GPU guest bundle. Enabling the
switch raises the memory reservation to at least **4 GB**. Windows asks to approve
the VM's helper. Declining it fails that launch without creating a substitute VM.

```powershell
yougori sandbox capabilities --yes
yougori sandbox launch --gpu true --memory-gb 4 --cpu 2 --yes
```

`internet: true` gives the GPU VM an endpoint on an existing Windows NAT/ICS
network. Its DNS servers come from active Windows adapters. This creates no
Wi-Fi bridge, physical adapter, new virtual switch, host DNS setting, firewall
rule or host route. With outgoing internet off, the guest has no network adapter;
declared service connections still use the authenticated guest channel.

A network without the Hyper-V firewall is preferred. On Windows Home the usual
network is WSL's, which enforces the Hyper-V firewall: an endpoint there passes
traffic only under the rules of the VM creator it names. The GPU VM's endpoint names
WSL's creator, exactly as WSL tags its own endpoints, so the PC's existing WSL
firewall settings apply (by default outbound allowed, inbound blocked). Windows
creates that network when WSL starts; if no NAT network exists yet, the launch says so.

Templates preserve the GPU flag in `VmSandboxSpec`, and VM capture preserves it
when creating a template. Combining VMs retains requested GPU access and grids;
conflicting internet/route settings are refused in preview before either source
is stopped. Remote GPU VM creation is not supported by this local HCS backend.

## Isolation and resource accounting

- The app stays unelevated. An ordinary per-VM broker launches a narrow elevated
  helper, rather than a permanent privileged service or an elevated desktop.
- The helper creates nothing until the broker has recorded and acknowledged it. If
  the Windows prompt is not approved within 150 seconds, the engine ends the broker;
  a later approval then starts a helper that exits at once, so the engine can release
  the reservation knowing that no VM exists.
- The helper opens only the exact HCS runtime's Hyper-V socket. Default service
  ACLs deny access, wildcard binds are disabled, and local bootstrap connections
  require a random per-launch nonce. The production guest's existing authenticated
  link runs above that transport.
- The helper pins the checked kernel and initrd against modification and deletion
  for the VM's lifetime. The guest reports startup errors before it is admitted.
- Guest commands run as UID 1000 with the existing seccomp, capability and workspace
  restrictions. GPU access adds `/dev/dxg` and read-only driver libraries, without
  mounting host folders. OCI applications keep their own C runtime; CUDA software
  must be compatible with the image's libraries.
- CPU, RAM and available GPU memory are reserved in the shared host ledger. Normal
  stop releases the reservation only after HCS confirms that the VM is absent.
- HCS terminates the compute system when its last helper handle closes. Broker loss
  also triggers explicit VM and endpoint cleanup. Stale endpoints are reclaimed
  only when their recorded owner PID/creation time is dead and their exact VM is
  absent, so concurrent launches cannot delete each other's endpoints.

**GPU-PV shares the physical GPU with Windows.** This is not exclusive PCI
passthrough, a hardware-enforced VRAM quota or a claim of confidential GPU memory.
Admission is deliberately conservative: a VM reserves the currently available
VRAM, so another managed GPU workload may be refused while it runs. GPU context
snapshot/restore is not implemented. The currently validated host has one NVIDIA
GPU; multi-GPU and other-platform support must not be inferred from this result.

## Local runtime preparation

`scripts/build-guest.sh` produces the shared pinned guest. Its read-only root uses
XZ squashfs, supported by both the Alpine/QEMU and Windows GPU kernels. The older
Zstandard root was rejected by the Windows kernel. A 2 GB HCS reservation also
failed during live boot, so the product now requires the tested 4 GB minimum.

Run `scripts/build-hcs-guest.py` in the existing Linux builder, passing `--repo`,
`--guest` (the completed base guest directory) and a new `--output` directory. It
copies this PC's installed WSL kernel and NVIDIA driver, including `nvcubins.bin`,
and the repository's verified CUDA probe. The completed bundle belongs under
`%LOCALAPPDATA%\Yougori\runtime\hcs-guest`, or the explicit `YOUGORI_HCS_GUEST` path.
It records the base guest's build record and hashes of its own artifacts. Rebuild
the bundle when the base guest or the installed GPU driver changes.

The driver bundle is **local-only**. Do not commit it or include it in releases.
The builder needs no driver download and never exposes DriverStore as a share.
This development integration does not automatically install prerequisites on
other computers.

## Verification

`scripts/acceptance/hcs-gpu/integration.py` uses the real installed CLI and engine.
It checks GPU-off behavior, a CUDA kernel calculating 256 verified results as
UID 1000, distinct kernel boot IDs, workspace isolation, absence of host shares,
offline/optional outgoing networking, and reservation release. Its finally block
stops the test VMs and discards only their staged workspaces.

`scripts/acceptance/hcs-gpu/lifetime.py` terminates an exact owned process handle
and checks HCS removal. `--engine` additionally tests loss of the idle development
engine and restarts that same development executable. Both checks are opt-in;
they are not part of ordinary unit tests and can display Windows UAC prompts.

Live run records for this integration are under
`D:/YougoriBuildCache/scratch/hcs-integration-20261105-v5/`. The separate, earlier
feasibility probe remains documented in `scripts/acceptance/hcs-gpu/README.md`.
