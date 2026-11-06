# Direct CUDA in a separate Windows-hosted Linux VM: feasibility test

This file records the original **feasibility test**, which passed on 2026-11-05.
The subsequent development integration is documented in
[Windows GPU Sandbox VMs](../../../docs/vm-sandbox/windows-gpu.md). Its normal
engine/CLI checks are in `integration.py` and `lifetime.py`. QEMU/WHPX itself still
has no GPU passthrough; GPU launches select the separate HCS backend.

Microsoft's HCS schema distinguishes **GPU-PV** (paravirtualization) from the
server **GPU-P** partitioning/DDA requirements. WSL uses an HCS Linux VM with
`VirtualMachine/ComputeTopology/Gpu`, `AssignmentMode: Mirror`, and
`AllowVendorExtension: true`. This is a candidate for this Windows 11 Home laptop;
the source reference alone does not establish support for a third-party guest.

The normal app identity was checked on 2026-11-04 and again on 2026-11-05. `HcsGetServiceProperties`
returned `0x8037011B` (`HCS_E_ACCESS_DENIED`). An administrator-approved probe is
needed to run it. This probe does not install a privileged service, enable a
Windows feature, change group membership, stop WSL, or change existing VMs.

The local bundle built successfully on 2026-11-04. Its hashes verified, both
offline checks passed, and the PowerShell launch script parsed successfully. The
fixed CUDA probe also passed as UID 65534 in the existing WSL build environment:
**RTX 5090 Laptop GPU, 256 computed results verified**. This establishes that the
test workload and installed driver work; it is not evidence for the new HCS VM.
The separate-VM test subsequently passed on this Windows 11 Home laptop:

- GPU off: CUDA initialization failed with error 304, as required.
- GPU on: **RTX 5090 Laptop GPU, uid 65534, 256 calculated results verified**.
- The two guests had different kernel boot IDs, only loopback networking, no
  host filesystem mounts, and both HCS identities were absent after cleanup.
- This run used strace around the fixed probe. It is a computation correctness
  result, not a performance measurement or a model-serving validation.

Two defects in the original probe prevented that result:

1. Its HvSocket service ACL used generic `GA` rights. Binding failed with Windows
   error 10013. Concrete file `FA` rights, as used by WSL, work. Access remains
   restricted to SYSTEM/elevated administrators on one service in one VM;
   default service ACLs remain empty and wildcard binding remains disabled.
2. The image builder copied `.so` libraries but omitted NVIDIA's `nvcubins.bin`.
   The syscall trace showed that missing file immediately before a segmentation
   fault in `libcuda.so.1.1`. Including it made the GPU calculation pass.

The probe also prepares guest-only temporary/shared memory directories, records
the exact failure stage, and retains bounded kernel/driver traces on failure.
No host bridge, firewall rule, GPU driver installation or persistent privileged
service was created.

Local successful report:
`D:/YougoriBuildCache/scratch/hcs-gpu-probe/elevated-result-2026-11-05-cubins.json`.
Its local-only bundle is `bundle-20261105-cubins` in the same directory. The
earlier failed runs remain there with their cleanup results. Do not publish
these bundles; they contain copies of this computer's NVIDIA driver files.

## What the test actually does

1. Verify SHA-256 hashes of a locally built kernel/initrd bundle.
2. Create a distinct HCS Linux VM, with 2 vCPUs and 4 GiB RAM; no NIC, host folder
   shares, physical disk attachment, guest management service or nested virtualization.
3. Accept a nonce-bound report over a Hyper-V socket scoped to that VM's runtime ID.
4. Run the fixed CUDA kernel probe with GPU access **off**. CUDA computation must fail.
5. Stop/close that VM and verify its ID is absent.
6. Create a second independent VM and attach GPU-PV. CUDA must calculate and verify
   256 results as UID 65534. Merely finding `/dev/dxg` or listing a GPU does not pass.
7. Check different kernel boot IDs, guest network/mount reports, and cleanup.

The guest runs only the repository's existing `yougori-cuda-probe`. It accepts no
arbitrary commands or paths. `Mirror` permits the fixed test to see the host's
GPUs; this is **not** a resource-partition or tenant-isolation guarantee. A product
backend still needs explicit device selection, host-observed confinement, owned
lifecycle/recovery, guest transport integration, resource accounting and adversarial
cross-VM tests. Passing this probe is a feasibility result, not those guarantees.

## Build (no downloads)

Use the existing build distro, with Go, cpio, ldd, Python, installed WSL drivers,
and the repository's checksum-verified CUDA probe:

```powershell
wsl -d Yougori-Harness-Builder -u root -- python3 -I -B /mnt/c/Users/Argon/Desktop/yougori/scripts/acceptance/hcs-gpu/build.py --repo /mnt/c/Users/Argon/Desktop/yougori --output /mnt/d/YougoriBuildCache/scratch/hcs-gpu-probe/bundle
python -I -B scripts/acceptance/hcs-gpu/test_probe.py
```

The build copies driver libraries into the initrd; it does not expose DriverStore
as a share. These vendor files are **local test inputs**, not redistributable
artifacts. Do not commit or publish the bundle. Build staging lives in a temporary
directory on the Linux build filesystem; only the completed bundle enters the
existing Windows scratch directory.

Read-only HCS access and bundle check (creates no VM):

```powershell
python -I -B scripts/acceptance/hcs-gpu/probe.py --bundle D:/YougoriBuildCache/scratch/hcs-gpu-probe/bundle --output D:/YougoriBuildCache/scratch/hcs-gpu-probe/preflight.json
```

After explicit approval for the one-off administrator test:

```powershell
powershell -NoProfile -File scripts/acceptance/hcs-gpu/run-elevated.ps1
```

That raises one UAC prompt. Results go to
`D:/YougoriBuildCache/scratch/hcs-gpu-probe/elevated-result.json`.
Do not infer a pass if the report is absent, failed, or has `gpuValidated: false`.

## Primary references

- [Microsoft HCS GPU configuration schema](https://learn.microsoft.com/en-us/virtualization/api/hcs/schemareference#gpuconfiguration)
- [Microsoft HCS GPU update API](https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsmodifycomputesystem)
- [WSL GPU setup source](https://github.com/microsoft/WSL/blob/master/src/windows/service/exe/WslCoreVm.cpp)

No migration work is part of this test or the proposed GPU backend.
