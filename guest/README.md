# Minimal sandbox guest (VM-W05, M01; the GUEST role)

The smallest guest the sandbox profile (`src-tauri/src/sandbox/qemu/profile.rs`) boots: the
pinned kernel, an initrd whose PID 1 is `yougori-sandbox-agent`, and a read-only root.
Plan: docs/combined-gpu-memory-and-vm-sandbox-plan.md §3.2, §3.3, §8.3, §11.1 step 3.

## Internet access

Networking is off by default. The desktop's **Full internet access** switch (CLI:
`yougori sandbox launch --internet true --yes`) explicitly adds an outbound QEMU user-NAT
adapter. It supports IPv4 TCP/UDP and DNS, including reachable local-network services;
it does not provide IPv6, general ICMP, inbound forwarding or host-file access.
The host verifies the exact adapter, backend and public boot-mode arguments against
the opted-in profile. Offline launches still reject network devices.

The guest brings up `eth0` at `10.0.2.15/24`, with gateway `10.0.2.2` and DNS `10.0.2.3`,
only when the host supplies `opt/yougori/internet` with the exact value `1`. DNS is
mounted read-only into the built-in guest and OCI workload roots. Selected brokered
online requests and full internet are alternative launch modes. App publishing and
host-file grants remain separate controls.

For internet-enabled launches the protected workload declaration also supplies the
host's UTC time. The guest sets its clock before dropping privileges, allowing normal
TLS certificate-date checks even though this minimal machine has no RTC.

## Build

In the WSL build distro, offline: `bash scripts/build-guest.sh <repository-root> <output-directory>`.
Inputs are verified before use: the kernel and `appliance-base.qcow2` against
`src-tauri/resources/runtime/SHA256SUMS`, the Alpine minirootfs against its checksum file in
`build/appliance-cache/`, Go against `go1.27.2`. Outputs: `vmlinuz`, `initrd`, `root.img`,
`config-<release>`, `yougori-sandbox-agent` and `artifacts.json` (each artifact's role,
SHA-256, content key, length, version and source; the modules; the inputs' digests; the
toolchain; the build commands). `SOURCE_DATE_EPOCH` defaults to 1792540800 (the pinned
kernel's build day). Two builds of the same inputs are byte-identical.

## Layout

initrd (newc cpio, sorted, owner 0:0, then a second newc archive of the two device nodes,
gzip -n -9):

| path | what |
| --- | --- |
| `/init` | `yougori-sandbox-agent` (appliance/agent/cmd/yougori-sandbox-agent), static, 0755 |
| `/etc/yougori/modules.load` | module files to load, in order, relative to `/lib/modules/<release>/` |
| `/lib/modules/<release>/kernel/...` | only those modules, `.ko.gz` as shipped by the pinned kernel |
| `/dev`, `/proc`, `/sys`, `/newroot` | mount points |
| `/dev/console` (c 5:1, 0600), `/dev/null` (c 1:3, 0666) | written by `guest/guest_build.py devices` as a second archive the kernel unpacks after the first, so the builder needs no privilege: PID 1's standard descriptors, and the FUSE library's start, which opens `/dev/null` before the agent's own code runs and before devtmpfs is mounted (without it the agent panicked at start, 30 October 2026) |

`root.img`: the Alpine 3.24.1 minirootfs plus the terminal user `sandbox` (uid and gid 1000,
locked), as squashfs (XZ, supported by both the QEMU and Windows HCS kernels), attached as a read-only raw drive.

## Boot

The agent mounts `/proc` (hidepid), `/sys` (read-only) and devtmpfs, loads the modules
(`guest/modules.list`: virtio_blk, rng-core, virtio-rng, qemu_fw_cfg, squashfs, fuse; the kernel
decompresses no modules, so the agent does), mounts `/dev/vda` read-only, nosuid, nodev and
switches into it, mounts `/run` (tmpfs), finds the virtio-serial port named
`org.yougori.link`, reads the 77-byte bootstrap file from fw_cfg
`opt/yougori/link-secret`, reads the egress endpoint list from fw_cfg `opt/yougori/egress-endpoints` (one `name host
port` line per declared route; an absent list is an empty one, a malformed list ends the
boot), unloads `qemu_fw_cfg`, writes `/run/yougori/hosts` (localhost and each route's host at
`127.0.0.2` upward, in declaration order) and bind-mounts it read-only over `/etc/hosts`,
sets no_new_privs for every thread, applies the strict tool profile's inner confinement
(it empties the capability bounding set on every thread, sets Yama's `ptrace_scope` to 3,
installs one seccomp filter on every thread that refuses io_uring, bpf, userfaultfd,
perf_event_open, kexec, module loading, ptrace and AF_VSOCK sockets with EPERM and kills a
call of another architecture or the x32 ABI, and copies its own binary to a read-only
executable tmpfs as `/run/yougori/bin/yougori-probe`, the confinement probe a terminal runs
for `yougori sandbox confinement`), waits for the host to connect, and runs the link
(protocol version 3: the host's challenge binds the connection, then hello and welcome; the
ingress and egress channels are flow-controlled per stream, each stream opening with a 64 KiB
window each way, so a connection whose reader stops holds back only itself).
After the welcome the agent listens on `127.0.0.N:80` for each
endpoint: a guest program's connection becomes one egress stream (`OpenEgress` with the
endpoint's name), its bytes go to the host within the host's credit for that stream, the
host's bytes come back and are credited to their stream once written, the program's end of writing ends the guest's
direction, the host's end closes the program's read side, and a cancel, a refusal or a
revocation closes the connection. The agent parses nothing of the bytes; the host's relay
does. Before the handshake the agent mounts the staged workspace at `/run/yougori/workspace`
(FUSE, for every guest user, owned by 1000:1000; `workspace_linux.go`): each request becomes one
file-channel stream on the workspace grant (`GrantHandle` 1; `files_linux.go`: a JSON header
line, then content in numbered parts, the content key `yougori/content/v1` for creates and
writes), files move whole (read on first use, written back on flush or close), and until the
host attaches the grant every request is refused as not authorized (EACCES). The host serves
the grant from its staged copy of the user's folder (`src-tauri/src/sandbox_vm/workspace.rs`);
nothing of the workspace is stored in the guest. A lost link, a close or a completed
shutdown powers the guest off; nothing restarts. Kernel arguments: `panic=-1 quiet` (a
panic reboots, which `-action reboot=shutdown` turns into a QEMU exit). Terminal streams
run `/bin/sh` as 1000:1000 with only `PATH`, `HOME` and `WORKSPACE` (the mount) set, in a fresh 16 MiB tmpfs under
`/run/yougori/terminal/` that is also its home, without a pty; the profile's protected paths
(`.bashrc`, `.gitconfig`, `.config/git/`, `.git/` with `hooks/`) are root-owned read-only bind
mounts in it. Each terminal is a cgroup v2 of its own
(`/sys/fs/cgroup/terminal-<stream>`, entered at clone, `pids.max` 256): a cancel, a
revocation, a shutdown or the shell's exit writes `cgroup.kill`, so no descendant (not
even one started with `setsid`) outlives it; `RLIMIT_NPROC` 512 bounds uid 1000 as a whole.
Without cgroup v2 the agent starts no terminal.

## Known

- The profile's `virtio-serial-device,max_ports=1` cannot host the `virtserialport` on the
  pinned QEMU 11.1.0 (port 0 is reserved for a virtconsole); the smoke boots used
  `max_ports=2`. Manager 2 decides the profile change.
- A kernel panic does not reach `-action reboot=shutdown` on WHPX: the debug boot of 30
  October 2026 (an ISA serial console beside the pinned machine) showed the panic path stop
  on a CET `Missing ENDBR` kernel BUG ("Fixing recursive fault but reboot is needed!"), so the
  VM hangs and the host sees only its handshake or keep-alive timeout, then stops it.
- Open: V15's sealed guest policy (M07), the ingress channel, probes and init
  reports, a pty, signing the artifacts, the `guest_image` build record and manifest,
  retiring the appliance agent's control and boot tokens after parity. The egress channel
  is served (30 October 2026); TLS inside the guest is not: programs speak plain HTTP to
  the route's host name.
