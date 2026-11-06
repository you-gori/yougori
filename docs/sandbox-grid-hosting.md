# Sandbox VM grid-hosting tools

Implemented in the development checkout on 2026-11-04. The installed development
CLI and running development engine were updated. The packaged desktop installer
was not rebuilt or published; the desktop changes are in its development source.

## Creation

The existing Sandbox VM creation form and the interactive `yougori` wizard offer
two unchecked options under **Add Grid Hosting**:

- GPU Grid: accept model-serving workers, including other PCs and rented cloud machines.
- Sandbox Grid: match custom jobs to a worker's offered CPU and RAM capacity together.

The command-line equivalent is:

```text
yougori sandbox launch --grid-hosting gpu,sandbox --yes
```

The API field is `gridHosting: ["gpu", "sandbox"]`. Unknown and duplicate
entries are refused before creation. Omission preserves normal VM creation.

Selected VMs receive the native guest `yougori grid` command, private controller
settings in `$WORKSPACE/.yougori-grid`, and the skill file
`$WORKSPACE/.agents/skills/yougori-grid/SKILL.md`. An empty managed workspace is
created when the owner did not select a project. The owner's project is never
modified by installation. In OCI guests, installation completes before the image's
entrypoint starts. An installation failure stops the new VM and reports the failure.

The tool shares the verified guest binary and works without Python, npm or Docker.
An image's existing PATH takes priority; `/run/yougori/bin/yougori grid` always names
the built-in tool. The guest source verifier includes the grid code and embedded
skill, so an older guest cannot pass the packaging source check.

The `grid=8787` service is declared, but nothing is published or rented. Start the
controller inside the VM with `yougori grid serve`. Grid-enabled VMs default to
running until stopped; explicit owner-supplied idle/lifetime limits still apply.

## Changing grids in a running VM

Open **Configure → Grid hosting** to toggle GPU Grid and Sandbox Grid independently.
The desktop reads and writes settings through the bounded guest command, without
reading the administrator token. Both switches can be off. The settings and the
existing grid identity remain in the workspace.

Inside the VM, the equivalent commands are:

```text
yougori grid config
yougori grid configure --resources gpu,sandbox
yougori grid configure --resources sandbox
yougori grid configure --resources none
```

Enabling installs the tools and skill; the application (or `yougori grid serve`)
starts the controller. A running controller reads changes before each request.
Disabling a resource cancels its queued and leased jobs, rejects late results,
and refuses new work requiring it. This does not terminate a process already
executing on a contributor's computer. All-off also refuses zero-resource jobs.
Invalid or unreadable configuration pauses admission instead of retaining old
permissions. Sharing remains an explicit app-publication action; enabling tools
does not add an incoming network rule, rent hardware, or grant GPU passthrough.
New commands need the current guest build; already running VMs retain their
booted tools until relaunched. Stopped VMs cannot execute configuration commands.
For external contributors the VM must have declared the `grid=8787` app service
(selecting a grid during creation does this). Changing tools later does not add
a service to an existing VM's immutable launch policy; code-authored templates
declare the grid service for the recipient when installed.

Validated on 2026-11-05 with the rebuilt guest in a real Windows/WHPX VM:
controller publication, CPU/memory job completion, disabling a live resource,
refusing its late result, all-off including zero-resource requests, re-enabling
with the same credentials, and VM/workspace cleanup. The desktop/API selection
and configuration tests passed (59), as did lint and the frontend build. Guest
grid/setup/link/agent package tests passed; the broader Go run hit host-share
FUSE inode test I/O errors outside these packages. Race instrumentation could
not run in the builder because its C compiler is unavailable.

## Building a grid application

The toolkit provides authenticated invitations, workers, resource matching, job
submission/claim/completion, heartbeat leases, worker removal, and completed-job
removal. Custom workers interpret application-specific JSON inside their own
sandbox. The controller never executes submitted commands on the host.

A PC or cloud machine with an existing local OpenAI-compatible model server can run:

```text
yougori grid contribute --server https://grid.example.com --join-file invite.json --model-url http://127.0.0.1:8000/v1 --model MODEL --gpu 1
```

The native contributor verifies model discovery, accepts only chat jobs for that
model, and communicates only with the selected grid and loopback model endpoint.
Its model API key stays on the contributor and can be supplied with
`--model-key-file FILE`. Invitations are single-use. Worker credentials cannot
administer a grid or complete another worker's jobs. Redirects and proxy settings
cannot redirect these credentials. Development `.localhost` origins connect to
loopback without depending on Windows DNS.

Use application mode for an owner publication so worker Authorization headers reach
the controller. Remote contributions require HTTPS. Existing VM publication limits
still apply. Neither grid hosting nor an invitation grants host-file access.

## Current boundaries

- Windows QEMU/WHPX does **not** support GPU passthrough. This change does not add
  direct CUDA inside those VMs. The verified GPU path is a contributing model server
  outside the sandbox. Models may run on a VM's CPU when its image supplies a runtime.
- CPU/RAM/GPU capacities are contributor-reported scheduling limits, not hardware
  attestation, a distributed address space, or additional OS resource reservations.
- The built-in model worker is serial and accepts chat jobs. Other job types need
  application-specific workers, which must apply their own sandbox resource limits.
- Controller jobs, memberships and invitations live for the controller process.
  Settings and the skill persist in its workspace. Applications needing a durable
  queue must persist results and reconcile interrupted work. Expired jobs fail and
  are not automatically replayed.
- The bounded toolkit allows 128 workers, 128 unused invitations, 256 retained jobs,
  1 MiB request/result bodies and a 90-second renewable worker lease.
- No paid NeoCloud instance was rented for validation, and no public endpoint was
  created. This is a reusable toolkit, not a completed enterprise grid product.

## Validation

- Desktop creation tests: 10 passed; TypeScript, lint and production frontend build passed.
- CLI library: 673 passed, 2 ignored. The real Windows terminal wizard passed,
  including the optional grid question and cancellation without creating a VM.
- Engine: all-target check passed with existing warnings; focused grid selection
  test passed. The development engine and CLI were rebuilt successfully.
- Go: all four packages passed; final grid/guest focused rerun also passed.
- Guest source/checksum verification and stale-source detection tests passed.
- Real minimal VM: command and skill installed with all three resource selections.
- Real Alpine OCI VM: command and skill installed with memory selected alone.
- Real VM controller: authenticated requests through an isolated owner publication;
  a CPU/memory-matched custom job was claimed and completed.
- Real native PC contributor: model discovery and a Qwen2.5-0.5B-Instruct inference
  job completed for the VM grid. A separate inference/device check confirmed
  Transformers was ready on an NVIDIA GeForce RTX 5090 Laptop GPU (one GPU).
- Both disposable VMs were stopped, test workspaces and contributor credential files
  were removed, and the existing test model was returned to its stopped state.
  The development inference website was restored with its existing account/data.

Reproducible live harness: `scripts/acceptance/vm-grid-hosting.py`. The local result
record is `D:/YougoriBuildCache/scratch/grid-hosting-acceptance/result.json`.
Early live attempts were refused by Windows committed-memory admission while the
Rust test build was running. They were retried after the build released memory;
no capacity check was bypassed.
