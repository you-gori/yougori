# Windows backend decision: HCS desk study (29 October 2026)

Preparation for VM-W20 under recorded decision VM-D2 ([the plan](../combined-gpu-memory-and-vm-sandbox-plan.md), line 3196: run the HCS spike first, with QEMU/WHPX as the fallback). This study sets the Host Compute Service API (HCS: `computecore.dll`, the `vmcompute` service) against the existing QEMU/WHPX path, using Microsoft's public documentation, a few other public sources and the repository as it stood on 29 October 2026. It ends with a spike plan for the owner to approve or narrow (section 14).

**Nothing here was run.** No HCS or Windows Hypervisor Platform function was called, no VM or hypervisor was started, no Windows feature was enabled, nothing was installed, and no host setting was read or changed. The sources were read on 29 October 2026. A documented feature is not evidence that a configuration works on a given host (§7.1, line 2364), and the spike is a sample, not a product guarantee (VM-W20, line 2619).

## How to read the status marks

Every statement carries one mark:

- **[D]** documented: the cited source says it. Sources are listed in section 16 with URL and date. Where the source is a third party or Microsoft's open-source code rather than Microsoft documentation, that is stated.
- **[I]** inferred: reasoning from documented facts. The basis is named, and the spike should confirm it.
- **[U]** unknown: no public source was found. Each unknown becomes a spike step or an owner question.

Repository facts cite their file (R-numbers in section 16). They count as [D] for what the repository contains, not for how anything behaves at run time.

## 1. Decision context

- VM-D2 (line 3196) accepts option (a): the HCS spike first, QEMU/WHPX as the fallback. §7.3 (lines 2376–2386) asks the spike to test machine options, guest image, link device, low-privilege identity, Job limits, handle inheritance, cleanup and firewall scope. It notes that the HCS overview "does not establish every proposed custom utility-VM configuration on Windows Home" (line 2382). It also forbids retrying TCG or shared WSL as a production fallback (line 2386). [D, R1]
- VM-W20 (line 2619) is time-boxed. Its acceptance is to document supported provisioning, permissions, link, device and cleanup behavior. Nested virtualization is a separate experiment. VM-R103 (line 2968): HCS availability alone does not prove a chosen custom Linux VM works. [D, R1]
- Tracker M04: the pure half of the QEMU/WHPX profile exists in `sandbox/qemu/`. The HCS decision is open, and the carry-forward from H06 needs an HCS accelerator name and CORE-01 hypervisor kind. [D, R2]
- The repository already names HCS in two places: `BackendKind::Hcs` (tag `hcs`) in `sandbox/backend/contract.rs`, and `HypervisorKind::Hcs` (tag `hcs`) in `foundation/evidence/subject.rs`. VM-CP-01's accelerator set is still `{kvm, whpx, hvf, vz}` in the plan (line 3151) and in `sandbox/probes/expect.rs` (line 261). [D, R3, R4]

The two options differ in where the virtual machine monitor runs:

| | HCS | QEMU/WHPX |
| --- | --- | --- |
| What the application does | Submits a JSON compute-system document to the Host Compute Service and manages it through handles [D, M1, M3] | Starts QEMU, which uses the Windows Hypervisor Platform (WHP) API to create a partition and run virtual processors [D, M2, M18] |
| Where device emulation runs | In Windows' own virtualization stack. Microsoft describes one VM worker process (`vmwp.exe`) per VM, hosting virtual devices, integration components, and the vSMB and Plan9 servers [D, M28 (2019)] | In the QEMU process: guest memory is mapped from the virtualization-stack process, and its threads run the virtual processors [D, M18] |
| Who maintains that code | Microsoft, as part of Windows [I, from M2: "built in virtualization stack of Windows"] | The QEMU project, plus the repository's patches to the bundled build [D, R6] |

## 2. Findings in brief

1. Microsoft does not document who may call HCS. The calls take no access-control input: the create call's security descriptor is "Reserved for future use, must be NULL", and the open call's requested access must be `GENERIC_ALL` [D, M5, M6]. The one public HCS-based Linux VM tool found (Lima) requires membership of Hyper-V Administrators and an elevated shell [D for Lima, T1]. WSL gives VMs to ordinary users through a service that runs as SYSTEM [D, G3]. The likely consequence is that an HCS backend needs a privileged Windows component or an administrator grant [I]. This is the largest open question (section 4).
2. Windows Home is not a documented HCS target. Hyper-V cannot be installed on Home [D, M12]. WSL 2 runs on Home through the "Virtual Machine Platform" component, which Microsoft calls a subset of Hyper-V [D, M13], and WSL's service drives HCS [D, G1]. So HCS is probably present on Home with that component [I], but whether Microsoft supports third-party HCS VMs there is unknown [U].
3. HCS documents the provisioning options the sandbox needs: direct Linux kernel and initrd boot (schema 2.2 and later), a read-only root disk, an optional network adapter map, and transient guest state [D, M4]. Without an adapter entry the guest should have no NIC [I]. WSL uses this pattern on x64. On Arm64 it uses a UEFI boot path instead [D, G1].
4. The HCS link is Hyper-V sockets (AF_HYPERV on the host, AF_VSOCK in a Linux guest). Each VM's document carries SDDL bind and connect descriptors [D, M4, M11]. Access control then sits in the VM's own document rather than in a file ACL the launcher must set [I], provided wildcard listeners elsewhere on the host cannot reach the guest [U] (section 6).
5. The confinement model differs. Under QEMU/WHPX the launcher can put a restricted, low-integrity token and Job limits on the VMM process, as `sandbox/qemu/windows.rs` models [D, R5]. Under HCS the VMM is Microsoft's per-VM worker process, which runs under a per-VM account [D, M8] that the launcher does not create, so VM-CP-04's Windows clause (line 3154) cannot be applied as written [I] (section 11).
6. Microsoft services the Hyper-V guest VM boundary and pays bounties for Hyper-V guest-to-host escapes [D, M26, M27]. Neither page mentions third-party stacks on WHP [D, M26, M27]. QEMU's security policy names KVM and HVF as its examples of virtualization accelerators, not WHPX [D, T3].
7. Cleanup has documented primitives: terminate on last handle close, ephemeral compute systems, enumeration by owner tag, and revoking file grants [D, M1, M4, M7, M8]. Whether they hold when the launcher is killed is a spike step [U].
8. Licensing is simpler for HCS [I]. It is a Windows component, so the application redistributes no hypervisor binary [I]. The engine's existing `windows-sys` 0.61 dependency exposes the HCS functions [D, R7, T5]. QEMU is GPL-2.0, and the repository already ships the bundled build's sources, patches and modification notices [D, T4, R6].

## 3. Supported Windows editions and builds

| Item | HCS | QEMU/WHPX |
| --- | --- | --- |
| API minimum | Windows 10 1809 and Windows Server 2019 for every HCS function page read [D, M5–M9]. The overview's "Applies to" line lists Windows Server 2019 and 2022, Azure Stack HCI 20H2, Azure Stack 21H2 and the Windows 10 October 2018 Update. It names no edition and no Windows 11 release [D, M1] | WHP: Windows 10 1803 on x64; Windows 11 24H2 build 26100.3915 on Arm64 [D, M19, M20] |
| Schema features needed | `LinuxKernelDirect` arrived in schema 2.2. The schema map ties 2.2 to the Windows 10 SDK 1903, 2.3 to the 2004 SDK, 2.4 and 2.5 to Windows Server 2022 (build 20348.169), and 2.6 to the Windows 11 SDK 21H2 [D, M4]. The map lists SDK releases, not OS support, so a host must be checked at run time: `HcsGetServiceProperties` with the `Basic` query returns `SupportedSchemaVersions` [D, M4; I that this is the check] | QEMU tests the WHPX backend from Windows 10 2004 on x86_64, and from Windows 11 24H2 with the April or May 2025 updates on arm64 [D, T2] |
| Windows feature to enable | No Microsoft page states which optional feature provides HCS to third-party callers [U]. WSL's service checks for "Virtual Machine Platform" before it starts its HCS VM [D, G1] | The "Windows Hypervisor Platform" optional feature (`HypervisorPlatform`) [D, T2] |
| Pro and Enterprise | Hyper-V is available on Windows 10 and 11 Pro and Enterprise [D, M12]. Windows containers and Hyper-V isolation are documented for Pro and Enterprise [D, M21] | Not stated by edition in the pages read [U] |
| Home | Hyper-V "can't be installed" on Home [D, M12]. WSL 2 is available on Home through "Virtual Machine Platform", "a subset of Hyper-V" [D, M13]. HCS is therefore probably present on Home with that feature [I, from M13 and G1]. Microsoft support for a third-party HCS VM there is unknown [U] | Whether the WHP feature can be enabled on Home is not stated in Microsoft documentation found [U]. QEMU says only that client editions install it through Windows Features [D, T2] |
| Arm64 | WSL boots its Arm64 VM through UEFI with a `VmbFs` boot device rather than `LinuxKernelDirect` [D, G1]. Whether `LinuxKernelDirect` works on Arm64 is unknown [U] | WHP supports Arm64 from build 26100.3915 [D, M19]. The repository's QEMU profile refuses WHPX on non-x86 guests (`PlatformRefusal::WhpxNotOnArchitecture`) [D, R5]. That is stricter than QEMU's current documentation [I, from T2], which is a VM-W19 question rather than one for this study |
| Windows 10 | Windows 10 Home and Pro reached end of support on 14 October 2025, and 22H2 is the final version [D, M25]. Whether a new backend targets Windows 11 only is an owner decision [I] | The same [I] |
| Prior art | Lima's `hcs` VM type is marked experimental. Lima reports testing it only on Windows 11 x86_64 [D for Lima, T1] | The product runs QEMU/WHPX as the user today, and the baseline lists no Windows-specific confinement [D, R8]. The restricted token and Job profile is VM-W19 work [D, R1] |

## 4. Privileges and non-administrator use

| Question | HCS | QEMU/WHPX |
| --- | --- | --- |
| Documented caller requirement | None found. `HcsCreateComputeSystem` takes a `securityDescriptor` that is "Reserved for future use, must be NULL" [D, M5]. `HcsOpenComputeSystem` takes a `requestedAccess` that is reserved and "must be `GENERIC_ALL`" [D, M6]. No per-system access control is exposed to the caller [I, from M5 and M6] | None found in the WHP pages read (overview, `WHvCreatePartition`, `WHvGetCapability`) [D that none is stated, M18–M20] |
| Observed elsewhere | Lima requires the user to be in the Hyper-V Administrators group and to run its CLI from an elevated shell [D for Lima, T1]. WSL's service is "a session 0 service, running as SYSTEM" that clients reach through COM [D, G3] | The product starts QEMU as the user today [D, R8] |
| What membership grants | Hyper-V Administrators have "complete and unrestricted access to all the features in Hyper-V" (well-known SID S-1-5-32-578) [D, M22]. Adding the user to it for a sandbox is a broad, persistent grant [I] | Not applicable |
| Can a non-administrator create and run a utility VM? | Unknown [U]. The sources above suggest a standard user or a low-integrity token cannot call HCS directly [I, from T1 and G3] | Probably yes for a standard user [I, from R8]. Whether WHPX works under the restricted low-integrity token and Job that VM-W19 requires is unknown [U]; that question belongs to VM-W19 |
| AppContainer (§7.3, line 2380) | Unknown [U] | Unknown [U] |
| Cross-user isolation of control | Whether one HCS-privileged caller can open or terminate another user's compute systems is unknown [U]. The open call's access mask is fixed at `GENERIC_ALL` [D, M6], so the API itself offers no narrower open [I] | A QEMU process belongs to the user who started it, under ordinary Windows process access control [I] |

Consequence [I]: if the spike confirms that HCS needs administrator rights, an HCS backend needs one of three designs. The first is a narrow privileged service with a closed set of operations: create only from an approved document, start, terminate, and enumerate its own owner tag. That would be the Windows counterpart of VM-D15's Linux launcher (line 3209). The second is an elevation prompt per launch. The third is the Hyper-V Administrators grant. Each is an owner decision (section 15).

## 5. Guest provisioning

- Boot. The `Chipset` object offers `LinuxKernelDirect`, with `KernelFilePath`, `InitRdPath` and `KernelCmdLine` (schema 2.2), and `Uefi`, whose `BootThis` devices are `ScsiDrive`, `VmbFs`, `Network` and `File` [D, M4]. WSL on x64 builds its document at schema 2.3 with `LinuxKernelDirect`, `StopOnReset` and `ShouldTerminateOnLastHandleClosed` set [D, G1]. Direct kernel boot is the closest match to the sandbox's cold-boot model (kernel, initrd, read-only root) [I].
- Root disk. A SCSI attachment can be `VirtualDisk`, `Iso` or `PassThru`, with a `ReadOnly` flag [D, M4]. A virtual persistent-memory device takes a `HostPath`, a `ReadOnly` flag and an image format of `Vhdx` or `Vhd1` [D, M4]. Lima's HCS driver boots only from a `.vhdx` image and converts other formats [D for Lima, T1]. The repository's images are qcow2 for the appliance and raw in the sandbox QEMU profile [D, R2, R9], so an HCS path needs a VHD or VHDX image, built or converted at image-build time [I].
- File access. The VM runs under a per-VM account "based on an internal GUID that is derived from the compute system ID". `HcsGrantVmAccess` adds an ACL entry for that account to a file, and `HcsRevokeVmAccess` removes it [D, M3, M8]. WSL grants access to each disk it attaches [D, G1]. Every kernel, initrd and image file therefore needs a grant before start and a revoke after stop [I].
- Guest state. When `GuestState` is omitted, guest state is "transient and kept purely in memory" [D, M4]. `StopOnReset` treats a guest reset as a stop [D, M4].
- Guest kernel. Hyper-V sockets need `CONFIG_VSOCKET=y` and `CONFIG_HYPERV_VSOCKETS=y` in a Linux guest [D, M11]. The Hyper-V device drivers (Linux Integration Services) are in the upstream kernel [D, M23]. The sandbox guest kernel is to be built from pinned LTS source (§19, line 3225) [D, R1]. Today's appliance uses Alpine's `linux-virt` package (`scripts/build-appliance.sh`) [D, R9]. Whether either kernel has VMBus, storage and `hv_sock` support built in is unknown [U].
- Boot completion. If `GuestConnection` is set, start waits until a guest connection is established, which HCS uses to talk to a guest service [D, M4]. The HCS quick start notes that `HcsShutDownComputeSystem` cannot be used without that guest service and calls `HcsTerminateComputeSystem` instead [D, M10]. The sandbox would omit `GuestConnection`, use its own agent over Hyper-V sockets, and stop VMs by terminating them [I].
- Link secret. The QEMU profile delivers the link secret through fw_cfg [D, R5], which HCS does not offer [I, from M4]. The options are a small read-only disk holding the secret, the kernel command line (visible in the guest and in the host document, so rejected [I]), or relying on the HvSocket descriptors with a nonce exchanged at connect. This is a design question for the spike [U].
- Prior art. Microsoft's `hcsshim` (MIT) runs a Linux utility VM hosting containers (LCOW), with its own guest agent called the GCS [D, G5]. WSL's HCS code is MIT-licensed [D, G2]. Both can be read as references, not linked as dependencies [I].

QEMU/WHPX for comparison: the profile in `sandbox/qemu/` boots a microvm board with a kernel, a read-only raw root, declared volumes only, one entropy device, a virtio-serial link and the secret through fw_cfg [D, R5]. QEMU's security page lists `microvm`, `pc` and `q35` among the x86 machine types it treats as providing guest isolation in the virtualization use case [D, T3]. Its WHPX page shows only `pc`, `q35` and `virt` as examples [D, T2]. Whether microvm with WHPX is a tested combination is unknown [U], and VM-W19 owns that question.

## 6. Host–guest link

- Hyper-V sockets carry streams only. They use the address family `AF_HYPERV` on Windows and `AF_VSOCK` in a Linux guest, and the data does not cross the network stack [D, M11]. A Linux guest's vsock port maps to a host service GUID through the template `00000000-facb-11e6-bd58-64006a7986d3`, with the first field replaced by the port number [D, M11]. The Linux profiles already use a vsock link [D, R5], so the guest side should carry over [I].
- Per-VM access control. `HvSocketSystemConfig` holds `DefaultBindSecurityDescriptor` and `DefaultConnectSecurityDescriptor`, which are SDDL strings checked before a host process binds to, or connects to, an unlisted service for that VM. `ServiceTable` sets per-service descriptors and `AllowWildcardBinds` [D, M4]. WSL sets both defaults to an SDDL that allows only SYSTEM and the current user [D, G1]. A sandbox document can grant bind and connect to the launcher's identity alone [I].
- Wildcards. Listeners can bind to `HV_GUID_WILDCARD`, to `HV_GUID_CHILDREN` (connections from child partitions) or to a specific VM ID [D, M11]. Wildcard binds are processed for a VM and service only when `AllowWildcardBinds` is true, and their descriptors are kept in a registry key under `Virtualization\HvSocket\WildcardDescriptors` [D, M4]. The default of `AllowWildcardBinds`, and which listeners other software (WSL, integration services) runs on the host, are unknown [U]. If any such listener accepts our guest, the guest can reach a host service outside the sandbox's link [I], so the spike must test this (S4).
- Registration. For Hyper-V-managed VMs, an application registers its service GUID under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices`, and doing so must be run as administrator [D, M11]. WSL's visible HCS code sets default descriptors instead [D, G1], which suggests registration is not needed when the descriptors cover the service [I]. Unconfirmed [U].
- QEMU/WHPX for comparison: the link is a virtio-serial port to a host endpoint in the launcher's private directory [D, R5]. Access control is the ACL on that endpoint, which the launcher sets [I].

## 7. Devices and keeping them minimal

The HCS `Devices` object lists COM ports, virtio-serial, SCSI, virtual PMem, network adapters, video monitor, keyboard, mouse, HvSocket, enhanced-mode video, guest crash reporting, virtual SMB, Plan9, battery, flexible IoV, shared memory and virtual PCI, and the schema describes most of them as optional [D, M4]. A minimal sandbox document would declare only the following [I]:

| Declared | Why |
| --- | --- |
| `Chipset.LinuxKernelDirect` (x64) | kernel, initrd, fixed command line without consoles |
| one read-only root: `Scsi` with one `VirtualDisk` attachment and `ReadOnly: true`, or `VirtualPMem` with a read-only device | root image |
| declared data volumes only, as further SCSI attachments | VM-W24 volumes |
| `HvSocket.HvSocketConfig` with descriptors for the launcher's identity | the link |
| `ComputeTopology` memory size and processor count | resources (section 9) |
| `ExposeVirtualizationExtensions: false` | nested virtualization stays off (§3.4 line 2095; VM-W20) [D that the field exists, M4] |

It would never declare `NetworkAdapters`, `Plan9`, `VirtualSmb`, `ComPorts`, `VirtioSerial` named pipes, video, keyboard, mouse, battery, `SharedMemory`, `VirtualPci`, `FlexibleIov` or `GuestCrashReporting` [I, from VM-CP-02 and VM-CP-03, lines 3152–3153].

Unknowns:

- Which devices HCS adds whether or not they are requested (VMBus core channels, timers, a legacy interrupt controller) [U]. WSL's code carries the comment "Plan9 device is always added during serialization" [D, G1]. That probably refers to WSL's own serializer rather than HCS [I], but the spike must take a census from inside the guest (S3).
- Entropy. The schema has no entropy device [D, M4], whereas the QEMU profile has one [D, R5]. How a Linux guest seeds its RNG early under HCS is unknown [U].
- Integration services. Heartbeat, shutdown, time sync and key-value exchange are configurable from schema 2.5 [D, M4]. Whether any run by default for a Linux guest is unknown [U].

The attack surface matters here. Microsoft names the VM worker process as one of the largest attack surfaces in its virtualization stack, and lists vSMB, Plan9FS, integration components and device emulators as running in it [D, M28 (2019)]. Leaving Plan9 and vSMB out of the document removes the two file-sharing servers from the sandbox's exposure [I].

## 8. Networking off by default

- HCS does not set up host resources: the client must create disks, networking and Hyper-V sockets before creating the VM [D, M1]. A network adapter is a `NetworkAdapters` entry referring to a Host Compute Network endpoint (`EndpointId`) [D, M4]. A document without that entry should give the guest no NIC [I, from M1 and M4]. The guest census confirms it (S3).
- The Hyper-V firewall filters traffic per `VMCreatorId` for containers hosted by Windows, including WSL, from Windows 11 22H2 [D, M24]. It matters only if a later profile adds a NIC (VM-W15, M10) [I].
- Lima's HCS mode runs only one instance at a time because its HCN subnet is fixed [D for Lima, T1]. This does not apply to a document without a NIC [I].
- QEMU/WHPX for comparison: the profile declares no network device, and `-nodefaults` stops defaults from being added [D, R5].

## 9. Resource controls

- HCS takes the memory size, a processor count, a processor limit, weight and reservation, and storage limits on IOPS and bandwidth [D, M4]. `AllowOvercommit` backs memory with the pagefile [D, M4]. Whether the limits are enforced on client Windows as documented is unknown [U] (S5).
- Under HCS these settings replace the Job limits the QEMU profile places on its own process. The worker process is not the launcher's child, so a launcher Job does not contain it [I, from M8 and M28].
- QEMU/WHPX: Job limits on the QEMU process (`JobLimit::required()`: kill on job close, die on unhandled exception, active-process and job-memory limits; breakaway refused) [D, R5].

## 10. Cleanup and orphan reclamation

| Need | HCS primitive | Status |
| --- | --- | --- |
| VM ends when its owner dies | `ShouldTerminateOnLastHandleClosed`: the system is forcibly terminated when its last `HCS_SYSTEM` handle closes [D, M4]. WSL sets it [D, G1] | Whether handles are closed, and the VM terminated, when the launcher is killed rather than exiting cleanly is unknown [U] (S6) |
| Nothing persists after stop | Compute systems are ephemeral: once a VM stops it is cleaned up and only its exit status can be queried [D, M1]. Without `GuestState` the state is transient [D, M4] | Documented |
| Find orphans after a crash | `HcsEnumerateComputeSystems` takes a `SystemQuery` with `Ids`, `Names`, `Types` and `Owners`, and returns each system's properties, including `Owner`, `State` and `RuntimeId` [D, M4, M7]. Each document sets `Owner` [D, M4] | A supervisor could enumerate its own owner tag at start, compare with the CORE-03 ledger and terminate unknown systems [I] |
| Forced stop | `HcsTerminateComputeSystem` [D, M3]. `HcsWaitForComputeSystemExit` and exit callbacks [D, M3]. From schema 2.4 an attribution record carries the worker's exit code, type and initiator [D, M4] | Termination latency unknown [U] |
| File grants | `HcsRevokeVmAccess` removes the ACL entry [D, M3] | Whether entries survive a crash and must be swept is unknown [U]; the sweep lists every granted file [I] |
| Host restart, `vmcompute` restart | Not documented | Unknown [U]. Restarting the service changes host state and needs the owner's consent (S6) |

QEMU/WHPX for comparison: the VMM is the launcher's child in a kill-on-close Job [D, R5]. Cleanup is process termination plus deletion of the private directory, with no per-VM ACL entries [I].

## 11. Observability and the boundary checks VM-CP-01 to VM-CP-04

| Check (plan line) | HCS | QEMU/WHPX |
| --- | --- | --- |
| VM-CP-01 accelerator (3151) | No HCS emulation fallback is documented; an HCS VM is a Hyper-V partition [I, from M1 and M2]. Host evidence could combine `WHvGetCapability(WHvCapabilityCodeHypervisorPresent)` (whether the hypervisor runs [D, M20]), `HcsGetServiceProperties` `Basic` [D, M4] and the system's `SystemType: VirtualMachine` and `RuntimeId` [D, M4, M9]. The record would name `hcs` [I], which needs the plan's accelerator set and `VM_CP_01_ACCELERATORS` to gain `hcs` [D that it is absent, R1, R4] | The launch record names `whpx`, and the observed command line is parsed for TCG [D, R5] |
| VM-CP-02 configuration matches golden (3152) | The golden file would be the canonical HCS document plus the schema version and the Windows build [I]. `HcsGetComputeSystemProperties` always returns the ID and `SystemType`; its documented query types are `Memory`, `Statistics`, `ProcessList`, `TerminateOnLastHandleClosed`, `SharedMemoryRegion` and `GuestConnection` [D, M4, M9]. No documented call returns the effective device set [D that none was found in M3, M4, M9], so a host read-back of the configuration is unknown [U] | The observed QEMU command line from the process listing is compared with the golden vector [D, R5] |
| VM-CP-03 no share device, no management listener (3153) | The document has no `Plan9`, `VirtualSmb` or `ComPorts`, and no wildcard binds [I]. HCS management is local and goes through the HCS API, not a TCP listener [I, from M3]. Effective absence needs S3's census as corroboration, since guest reports cannot satisfy a host-only check (H06's rule [D, R2]) | Parsed from the command line: no 9p or virtiofs, QMP only on the private socket [D, R5] |
| VM-CP-04 hypervisor confinement (3154) | The Windows clause expects a restricted, low-integrity token and Job limits queried from the job object. Under HCS the VMM is the worker process, which runs under the per-VM account [D, M8]. Microsoft described it in 2019 as hardened with ACG, CIG and CFG and without `SeImpersonatePrivilege` [D, M28]. Its current state and whether a non-administrator can query it are unknown [U]. The clause needs an HCS form: worker identity, mitigation policies, the HCS resource limits read back, plus the launcher or broker's own confinement [I] | Token, integrity, Job limits, handles and mitigations compared by `check_windows` [D, R5] |

## 12. Licensing and redistribution

| Item | HCS | QEMU/WHPX |
| --- | --- | --- |
| Hypervisor and VMM | Part of Windows. The HCS functions live in `ComputeCore.dll` [D, M5]. Nothing is redistributed [I] | QEMU is GPL-2.0 [D, T4]. The repository ships a patched build with recorded sources and modification notices [D, R6] |
| Bindings | `windows-sys` is an existing dependency the plan reuses (§19, line 3217) [D, R1]. Version 0.61.2 exposes `Win32::System::HostComputeSystem` with the functions needed [D, T5]. The cargo feature name is not confirmed [U]. Enabling it changes `src-tauri/Cargo.toml` features, not crates [I]. No license file of `windows-sys` was checked in this study [U] | Existing |
| Windows SDK | The functions are declared in `ComputeCore.h` with the import library `ComputeCore.lib` [D, M5], which come from the Windows SDK [I]. Whether the build needs them (as opposed to `windows-sys`'s own linking) and the SDK's license terms were not checked [U] | Not applicable |
| Guest | The sandbox's own GPL-2.0 kernel, as for QEMU (§19) [D, R1] | The same |
| References | WSL is MIT [D, G2]; hcsshim is MIT [D, G5]. Copying code from either would need the MIT notice [I] | Not applicable |

## 13. Risks

| Risk | Status |
| --- | --- |
| HCS needs administrator rights or a SYSTEM service, adding a privileged component the QEMU path does not have | [I] from T1 and G3; confirmed or refuted by S1 |
| Home not supported for third-party HCS VMs, which would leave Home on QEMU/WHPX | [U]; S0 and S1 on a Home host |
| No documented host read-back of the effective HCS device set, which weakens VM-CP-02 and VM-CP-03 as host-observed checks | [D] that none was found (M4, M9); S3 |
| VM-CP-04 as written does not fit an HCS worker process | [I]; owner decision |
| Wildcard Hyper-V socket listeners from other software reachable from the guest | [U]; S4 |
| HCS adds devices that were not declared | [U]; S3 |
| HCS documentation is thin and old: concept pages are dated 2021 with updates to 2024–2026, parameters are "reserved", the schema map ends at 2.6 | [D] (M1, M4, M5) |
| The HCS schema and behavior change between Windows builds | [I] from the version map (M4); runtime check of `SupportedSchemaVersions` |
| Arm64 needs a different boot path (UEFI `VmbFs`) | [D] for WSL (G1); [U] for the sandbox |
| Coexistence with WSL, other Hyper-V users or security software | [U]; S8 |
| QEMU/WHPX: guest-to-VMM escape lands in a third-party process outside Microsoft's serviced Hyper-V boundary, confined only by the launcher's token and Job | [I] from M18, M26, T3 |
| QEMU/WHPX: the bundled build compiles TCG, VNC and OpenGL in; the profile, not the build, keeps them out of a sandbox launch | [D] R6; [I] that a build without them shrinks the surface; VM-W19 |
| QEMU/WHPX: current QEMU documentation says `kernel-irqchip` is "not expected to be manually set during normal operation" and remains a debugging option, while the profile sets `kernel-irqchip=off` for WHPX | [D] T2 and R5; impact on the bundled version [U]; VM-W19 |
| QEMU/WHPX: WHPX's "separate security domain" (`ssd`), a branch-target-buffer flush on guest entry and exit, can be turned off for MMIO speed | [D] T2; the profile must never set `ssd=off` [I] |

## 14. Spike plan (VM-W20)

The spike is Tier 2 work (line 2764): real VMs in an explicitly authorized, disposable test environment. Its code lives in `spikes/hcs/` and is not shipped (file map, line 3075). It needs the owner's authorization, the hosts below, and consent for any step that changes host state. It is time-boxed to five working days, with stop gates after S1 and after S2.

Hosts: H1, Windows 11 Pro x64 with Hyper-V enabled. H2, Windows 11 Home x64 with only "Virtual Machine Platform" enabled. H3, a Windows 11 Arm64 machine, if available, for S0 to S2 only. Each result becomes an evidence row in the §7.1 form (line 2360), labelled experimental until validated.

| Step | What it does | What it would show | Pass | Stop |
| --- | --- | --- | --- | --- |
| S0 Inventory | Record edition, build with revision, architecture, the states of the Hyper-V, Virtual Machine Platform and Hypervisor Platform features, WSL presence, `HcsGetServiceProperties` `Basic`, and `WHvGetCapability` hypervisor present. Read only | Which API generations exist on each edition and build (section 3) | `SupportedSchemaVersions` includes 2.2 or later (x64), or a UEFI boot path is usable (Arm64) | HCS absent or below 2.2 on a host: HCS is unavailable there; record it and continue on the other hosts |
| S1 Privilege matrix | Create, start, enumerate and terminate one minimal document (no devices, terminate on last handle close) as: elevated administrator; administrator with a filtered token; standard user; standard user in Hyper-V Administrators (on a disposable account); the VM-W19 restricted low-integrity token; an AppContainer; a LocalSystem service. Also test whether one identity can open or terminate another identity's system | The real permission model (section 4) | A path exists in which the interactive user is not an administrator: a standard user directly, or a service whose operations can be closed to the S2 document shape | Only an elevated administrator works, and the owner rejects a privileged service and the Hyper-V Administrators grant: stop HCS and continue with QEMU/WHPX under VM-D2 |
| S2 Boot and link | `LinuxKernelDirect` with the sandbox kernel and initrd, a read-only root (SCSI VHDX, then PMem), HvSocket descriptors for the launcher's identity only, no other device, `Owner` set, terminate on last handle close, `StopOnReset`, no `GuestState`, `ExposeVirtualizationExtensions: false`. The guest agent connects over AF_VSOCK to the mapped service GUID | Provisioning and link (sections 5 and 6) | 20 consecutive cold boots reach the agent's hello. Boot time median and spread are recorded | No boot on a host after one day of kernel configuration work (VMBus, storage, `hv_sock`): HCS is unavailable on that host and build |
| S3 Device census and golden | In the guest, list VMBus device classes, PCI, ACPI and platform devices, serial ports, input, block devices and network interfaces. On the host, try every documented property query and any Microsoft-documented read-back of the device set. Keep the canonical document digest. Positive control: add a Plan9 share and confirm both host and guest checks report it | VM-CP-02 and VM-CP-03 sources (sections 7 and 11) | The census equals the declared devices plus a fixed platform baseline recorded once per build. No NIC, no 9p or SMB | HCS adds an undeclared network or host-sharing device that cannot be removed |
| S4 Link access control | Another user and a low-integrity process try to bind and connect for the VM; the guest tries a bounded range of host service ports with WSL running; record `AllowWildcardBinds` behavior and whether registry registration is required | Link isolation (section 6) | Only the launcher's identity can bind or connect; the guest reaches only the sandbox listener; no registry change is needed, or it is a one-time install step the owner accepts | A guest connection to a non-sandbox host listener that the document cannot prevent |
| S5 Resource controls | Set memory, processor count and limit, and storage limits; run a guest load; observe host CPU, memory and I/O against the limits | Section 9 | Each limit holds within a tolerance fixed before the run | No documented control limits CPU or memory |
| S6 Lifecycle and cleanup | (a) normal terminate; (b) kill the launcher; (c) launcher holds no handle, then a sweep by owner tag; (d) host restart; (e) `vmcompute` restart, only with the owner's consent. After each: enumerate by owner, check file ACLs for the VM account, check leftover files, measure time | Section 10 | After every case, no system with the sandbox owner tag, no VM-account ACL entry and no sandbox file remain, within a bound recorded in advance | A VM outlives its launcher and cannot be removed through documented calls |
| S7 Boundary-check sources | VM-CP-01: record `hcs` with hypervisor present and `SystemType`; with Virtual Machine Platform disabled on a disposable host, or a test build in which create fails, confirm the launch is refused and nothing else starts (VM-CP-33, line 3183). VM-CP-04: find the worker process for the `RuntimeId`; read its user SID, integrity level and mitigation policies, and note whether that needs administrator rights; record the broker's token and Job | Section 11 | Each of VM-CP-01 to 04 has a host-observed source, or a named replacement the owner accepts | The worker process cannot be observed at all: VM-CP-04 has no host source under HCS (owner decision) |
| S8 Coexistence and host impact | Run with WSL 2, with QEMU/WHPX, and with the default security software active. Compare feature states, the `GuestCommunicationServices` key and firewall rules before and after | No silent host change (VM-W23); coexistence | No host setting changed by the backend; both runtimes work side by side | A host setting changes without an explicit step |
| S9 Fallback comparison | On the same hosts, boot the VM-W19 QEMU/WHPX profile under its token and Job, with the same census and timings | Whether QEMU/WHPX covers the editions where HCS fails | VM-W19's own acceptance (line 2618) | Not applicable (VM-W19 owns it) |

Result: one decision row per host edition, build and architecture: HCS supported (experimental until validated), QEMU/WHPX, or unavailable. M04 does not require every Windows option to ship [D, R2]. HCS on Pro and QEMU/WHPX on Home is an allowed result.

## 15. Decisions needed and open questions for the owner

1. Privilege model for HCS, if S1 shows it needs administrator rights: (a) a narrow privileged service with a closed operation set (the Windows counterpart of VM-D15); (b) an elevation prompt per launch; (c) the Hyper-V Administrators grant; or (d) stop HCS. The strict reading of §3.4 (line 2101, minimize privileges) favours (a) or (d) [I].
2. Target editions: must Home be supported by the backend that ships first? If yes and HCS fails on Home, Home uses QEMU/WHPX.
3. Windows 10: in or out of scope, given its end of support on 14 October 2025 [D, M25].
4. VM-CP-01: add `hcs` to the plan's accelerator set (line 3151) and to `VM_CP_01_ACCELERATORS`. CORE-01's `HypervisorKind::Hcs` already exists [D, R3]. Strict reading: a separate tag, not `whpx` [I].
5. VM-CP-04 for HCS: accept a replacement observation (worker identity and mitigations, HCS limits read back, broker confinement) or treat HCS as unable to meet the strict profile.
6. VM-CP-02 and VM-CP-03 for HCS: if no host read-back of the device set exists, accept "document submitted and accepted" plus guest census corroboration, or refuse.
7. Spike authorization: Tier 2 hosts (a Pro and a Home machine, optionally Arm64), disposable accounts and a test service for S1, and consent for S6 (e) and the S7 feature toggle. Each of these changes host state and is removed afterwards.
8. Link secret delivery under HCS: a read-only secret disk or descriptor-only authentication (section 5).
9. Out of scope here, for the record: Microsoft's WSL container API (`Microsoft.WSL.Containers`, WSL 2.9.3 or later) runs containers in a "session VM" [D, M16, M17], while WSL's own security model says it "is not a security sandbox for running untrusted code" and that one user's distributions can share a utility VM [D, G4]. Whether a WSL container session is a separate VM per sandbox is unknown [U]. §7.3 (line 2386) refuses shared WSL, so it is not proposed.

## 16. Sources

Read on 29 October 2026. "Updated" is the page's own update date where it showed one.

Microsoft documentation:

- M1 Host Compute System overview, https://learn.microsoft.com/en-us/virtualization/api/hcs/overview (updated 2024-10-17)
- M2 Hyper-V APIs, https://learn.microsoft.com/en-us/virtualization/api/ (updated 2025-08-11)
- M3 HCS API reference, https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/apioverview (updated 2024-10-17)
- M4 HCS schema reference, https://learn.microsoft.com/en-us/virtualization/api/hcs/schemareference (update date not shown in the copy read)
- M5 HcsCreateComputeSystem, https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcscreatecomputesystem (updated 2026-10-20)
- M6 HcsOpenComputeSystem, https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsopencomputesystem (updated 2026-10-20)
- M7 HcsEnumerateComputeSystems, https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsenumeratecomputesystems (updated 2024-10-17)
- M8 HcsGrantVmAccess, https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsgrantvmaccess (updated 2024-10-17)
- M9 HcsGetComputeSystemProperties, https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/hcsgetcomputesystemproperties (updated 2024-10-17)
- M10 HCS quick start, https://learn.microsoft.com/en-us/virtualization/api/hcs/reference/tutorial (updated 2024-10-17)
- M11 Make your own integration services (Hyper-V sockets), https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/make-integration-service (updated 2025-09-22)
- M12 Install Hyper-V in Windows and Windows Server, https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/get-started/install-hyper-v (updated 2026-02-16)
- M13 WSL FAQ, https://learn.microsoft.com/en-us/windows/wsl/faq (updated 2026-07-30)
- M14 WSL manual installation, https://learn.microsoft.com/en-us/windows/wsl/install-manual (updated 2026-06-02)
- M15 Open Source WSL, https://learn.microsoft.com/en-us/windows/wsl/opensource (updated 2026-06-02)
- M16 WSL container, https://learn.microsoft.com/en-us/windows/wsl/wsl-container (updated 2026-10-16)
- M17 WSL container settings, https://learn.microsoft.com/en-us/windows/wsl/wsl-container-settings (updated 2026-10-16)
- M18 Windows Hypervisor Platform API definitions, https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform (updated 2026-06-11)
- M19 WHvCreatePartition, https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvcreatepartition (updated 2026-06-11)
- M20 WHvGetCapability, https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/funcs/whvgetcapability (updated 2026-06-11)
- M21 Windows container requirements, https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/system-requirements (updated 2025-09-17)
- M22 Active Directory security groups (Hyper-V Administrators), https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups (updated 2025-09-22)
- M23 Supported Linux and FreeBSD virtual machines for Hyper-V, https://learn.microsoft.com/en-us/windows-server/virtualization/hyper-v/supported-linux-and-freebsd-virtual-machines-for-hyper-v-on-windows (updated 2026-02-16)
- M24 Hyper-V firewall, https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall (updated 2026-10-08)
- M25 Windows 10 Home and Pro lifecycle, https://learn.microsoft.com/en-us/lifecycle/products/windows-10-home-and-pro (updated 2024-09-17)
- M26 Microsoft Security Servicing Criteria for Windows, https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria (latest revision entry 2026-05-20)
- M27 Microsoft Hyper-V Bounty Program, https://www.microsoft.com/en-us/msrc/bounty-hyper-v (latest revision entry 2026-10-20)
- M28 MSRC blog, "Attacking the VM worker process", https://www.microsoft.com/en-us/msrc/blog/2019/09/attacking-the-vm-worker-process (published 2019-09-11)

Microsoft open-source code and project documentation (describes those projects, not Windows guarantees):

- G1 microsoft/WSL, `src/windows/service/exe/WslCoreVm.cpp` on the `master` branch, https://github.com/microsoft/WSL/blob/master/src/windows/service/exe/WslCoreVm.cpp (read 2026-10-29; `GenerateConfigJson`)
- G2 microsoft/WSL license (MIT), https://github.com/microsoft/WSL/blob/master/LICENSE
- G3 WSL documentation, wslservice.exe, https://wsl.dev/technical-documentation/wslservice.exe/
- G4 WSL documentation, security model, https://wsl.dev/technical-documentation/security/
- G5 microsoft/hcsshim README (MIT), https://github.com/microsoft/hcsshim

Third-party sources:

- T1 Lima, `hcs` VM type, https://lima-vm.io/docs/config/vmtype/hcs/ (last modified 2026-09-18)
- T2 QEMU documentation (master), Windows Hypervisor Platform, https://www.qemu.org/docs/master/system/whpx.html
- T3 QEMU documentation (master), Security, https://www.qemu.org/docs/master/system/security.html
- T4 QEMU documentation (master), License, https://www.qemu.org/docs/master/about/license.html
- T5 docs.rs, `windows-sys` 0.61.2, `Win32::System::HostComputeSystem`, https://docs.rs/windows-sys/0.61.2/windows_sys/Win32/System/HostComputeSystem/index.html

Repository (working tree, 29 October 2026):

- R1 `docs/combined-gpu-memory-and-vm-sandbox-plan.md`: §3.4 (2093–2101), §7.1 (2356–2364), §7.3 (2376–2386), VM-W19 and VM-W20 (2618–2619), Tier 2 (2764), VM-R103 (2968), file map (3075), VM-CP-01 to 04 (3151–3154), VM-CP-33 (3183), VM-D2 (3196), VM-D15 (3209), §19 (3215–3225)
- R2 `docs/combined-plan-leftover-tasks.md`, entries M04 and H06
- R3 `src-tauri/src/foundation/evidence/subject.rs` (`HypervisorKind::Hcs`), `src-tauri/src/sandbox/backend/contract.rs` (`BackendKind::Hcs`)
- R4 `src-tauri/src/sandbox/probes/expect.rs`, line 261 (`VM_CP_01_ACCELERATORS`)
- R5 `src-tauri/src/sandbox/qemu/` (`mod.rs`, `platform.rs`, `profile.rs`, `windows.rs`)
- R6 `docs/rebuilding-third-party.txt` (Windows QEMU build profile and patches), `docs/licensing.txt`
- R7 `src-tauri/Cargo.toml` (`windows-sys` 0.61)
- R8 `docs/vm-sandbox/baseline-2026-10-27.md` (QEMU runs as the user; WHPX on Windows)
- R9 `scripts/build-appliance.sh` (Alpine `linux-virt` kernel, qcow2 appliance image)

## Spike results on host H2 (29–30 October 2026)

Run on 29 October 2026 between 21:21 and 21:40 (UTC+1) with the spike code in `spikes/hcs/`, whose README has the exact commands. Only steps S0 and S1 of section 14 ran, as the session's non-elevated user and within the limits set for this run: no elevation; no change to a Windows feature, group, registry key, service or firewall rule; no compute system opened, queried beyond an owner-filtered enumeration, or terminated unless the spike created it. The only change outside log files was one ACL entry, for the spike's own AppContainer SID, on the spike's own output directory. In this section **[O]** marks what was observed on H2 in this run. An observation is evidence for this host only, labelled experimental, and not a product guarantee (VM-W20, line 2619). Times are local wall-clock times of the call. Durations are the probe's own measurements.

### Host and identity

| Item | Observed [O] | How it was read |
| --- | --- | --- |
| Edition | Windows 11 Home, EditionID `Core`. The registry's legacy `ProductName` still says "Windows 10 Home" | Registry `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion`; CIM `Win32_OperatingSystem` |
| Build | 10.0.26300.9818 (DisplayVersion 26H2), installation type Client | The same |
| Architecture | x64 (`OSArchitecture` 64-bit, `PROCESSOR_ARCHITECTURE` AMD64), Intel Core Ultra 9 275HX | CIM, environment |
| Hypervisor | Present | CIM `Win32_ComputerSystem.HypervisorPresent`; `WHvGetCapability` (below) |
| Features | Virtual Machine Platform enabled (`InstallState` 1). Windows Hypervisor Platform disabled (`InstallState` 2). WSL enabled (1). No Hyper-V entry and no Containers entry is listed | CIM `Win32_OptionalFeature`, readable without elevation (97 entries). The DISM API (`Get-WindowsOptionalFeature -Online`) refused with "The requested operation requires elevation", so DISM's feature states were not read |
| Services | `vmcompute` and `HvHost` running (manual start), `hns` running, `vmms` absent, the `vmic*` services present and stopped | `Get-Service` |
| Files | `computecore.dll` and `WinHvPlatform.dll` 10.0.26100.9818; `vmcompute.exe` and `vmwp.exe` 10.0.26100.1; `vmms.exe` absent | File versions |
| WSL | WSL package 2.7.11.0 installed, `WSLService` running (automatic start). `wsl.exe` was not run | `Get-AppxPackage`, `Get-Service` |
| Identity | The session user is a member of Administrators running with the UAC-filtered token: medium integrity, `BUILTIN\Administrators` and "Local account and member of Administrators group" deny-only, five privileges of which only `SeChangeNotifyPrivilege` is enabled, no Hyper-V Administrators membership. In section 14's S1 matrix this is the row "administrator with a filtered token", not "standard user" | `whoami /groups /priv`; the probe's own token query |
| Hyper-V Administrators | The group (S-1-5-32-578) exists on this Home host | `Get-LocalGroup -SID S-1-5-32-578` |

Section 14 defines H2 as "Windows 11 Home x64 with only Virtual Machine Platform enabled". This host matches as far as a non-elevated user can read it.

### Evidence rows (§7.1 form)

The S1 document was minimal: schema 2.1, `Owner` `yougori-hcs-spike-h1`, `ShouldTerminateOnLastHandleClosed`, `StopOnReset`, a UEFI chipset with no boot device, 256 MB, one processor with `ExposeVirtualizationExtensions: false`, and an empty `Devices` object. Each S1 identity ran in a fresh child process inside a kill-on-close job.

| Step | Host | Build | Identity | Call | Result [O] | Time |
| --- | --- | --- | --- | --- | --- | --- |
| S0 | H2 | 10.0.26300.9818 x64 | Filtered administrator, medium | `HcsGetServiceProperties`, query `{"PropertyTypes":["Basic"]}` | `0x8037011B` `HCS_E_ACCESS_DENIED`, no result document. `SupportedSchemaVersions` is not readable | 21:29:47.652, 5 ms |
| S0 | H2 | 10.0.26300.9818 x64 | The same | `WHvGetCapability(HypervisorPresent)` | `S_OK`, TRUE | 21:29:47.656, under 1 ms |
| S0 | H2 | 10.0.26300.9818 x64 | The same | `WHvGetCapability` for 16 further codes (0x0001–0x0006, 0x1000–0x1009) | All `S_OK`. Features `0x2FF`; extended VM exits `0x7FFF`; exception exit bitmap `0xF7DFB`; MSR exit bitmap `0x3F`; GPA range populate flags `0x3`; scheduler features 0; vendor Intel; processor features `0x3E1BFBCFE7F7859F` (two banks); XSAVE features `0x7C058381F`; cache line flush size 8; processor clock 3,072,000,431 Hz; interrupt clock 200,000,000 Hz; perfmon features 0 | 21:29:47.656 |
| S1 | H2 | 10.0.26300.9818 x64 | Filtered administrator, medium (the child's own primary token) | `HcsCreateComputeSystem` | Call `S_OK`, operation result `0x8037011B` `HCS_E_ACCESS_DENIED` within 1 ms. No system created, so `HcsStartComputeSystem` was not reached | 21:30:22.367 (run 1), 21:33:11.519 (run 2) |
| S1 | H2 | 10.0.26300.9818 x64 | The same | `HcsEnumerateComputeSystems` with `{"Owners":["yougori-hcs-spike-h1"]}`, before create, after create and after close | Operation result `0x8037011B` each time | 21:33:11.518–.519 |
| S1 | H2 | 10.0.26300.9818 x64 | The same | `HcsTerminateComputeSystem` on the handle the create call returned, then `HcsCloseComputeSystem` | Terminate: operation result `0x800706EF` (`RPC_X_SS_IN_NULL_CONTEXT`: no server-side system behind the handle). Close returned | 21:33:11.519 |
| S1 | H2 | 10.0.26300.9818 x64 | Low integrity, unrestricted, derived from the session token; impersonated, thread token checked (SecurityImpersonation, integrity 0x1000) | Service properties, enumeration, create | `0x8037011B` for all three. Start not reached. Terminate on the returned handle `0x800706EF` | 21:33:11.685–.688 |
| S1 | H2 | 10.0.26300.9818 x64 | Restricted low integrity in the VM-W19 shape of `sandbox/qemu/windows.rs` (`DISABLE_MAX_PRIVILEGE`, Administrators deny-only, restricting SIDs Users, RESTRICTED and the logon session); impersonated, checked (restricted, 0x1000) | The same | `0x800706D8` (`HRESULT_FROM_WIN32(EPT_S_CANT_PERFORM_OP)`, "The server endpoint cannot perform the operation") for all three. Start not reached. Terminate `0x800706EF` | 21:33:11.603–.605 |
| S1 | H2 | 10.0.26300.9818 x64 | AppContainer: a lowbox token from `NtCreateLowBoxToken` for the SID derived from `yougori.hcs.spike.h1`, no capabilities, no profile; impersonated, checked (AppContainer, 0x1000) | The same | `0x800706D8` for all three. Start not reached. Terminate `0x800706EF` | 21:33:11.764–.766 |
| S1 | H2 | 10.0.26300.9818 x64 | Filtered administrator, medium | Final owner-filtered enumeration | `0x8037011B` | 21:30:37.998 (run 1), 21:34:40.700 (run 2), 21:39:37.711 (closing check) |

What the rows mean:

- The Windows SDK 10.0.26100.0 header `shared/winerror.h` on this host gives `HCS_E_ACCESS_DENIED` the text "Insufficient privileges. Only administrators or users that are members of the Hyper-V Administrators user group are permitted to access virtual machines or containers." [D, for the text]. The refusal is the service's own check, made before the document mattered: it came back within 1 ms [I].
- For the restricted and AppContainer tokens, `EPT_S_CANT_PERFORM_OP` suggests the call was refused at the service's RPC endpoint, before HCS's own access check [I].
- Each derived token holds a subset of the session token's rights, so no identity this host offers without a change can use HCS directly [I, from the rows].
- Nothing of the spike remains, but an owner-filtered enumeration cannot show that here, because the enumeration itself was refused. The evidence instead: the service refused every create, and terminate on every returned handle reported that no server-side system was behind it [O].

### Attempts that failed, and why

1. The S0 schema check was refused (row above). So the S0 pass gate, whether `SupportedSchemaVersions` includes 2.2 or later, cannot be evaluated by a non-elevated caller on this host.
2. Reading feature states through the DISM API was refused without elevation. CIM was read instead.
3. Each derived token was also tried as the primary token of a child process (21:33:11–21:34:40), the shape a launcher would use. `whoami.exe /priv` ran under each token to separate harness failures from token failures:
   - Restricted low integrity: the probe and `whoami.exe` both exited with `0xC0000142` (`STATUS_DLL_INIT_FAILED`) before running any code of their own. They were started on the default desktop with `CREATE_NO_WINDOW`. The cause was not investigated. It also concerns VM-W19's token profile, so it is recorded here for that work item [O].
   - Low integrity, unrestricted: `whoami.exe` ran (exit 0). The .NET probe exited with `0x80131700` after 15 s in run 1 and 89 s in run 2, because the .NET Framework runtime did not load at low integrity. This is a limit of the probe harness, not an HCS result.
   - AppContainer: `CreateProcessW` with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` failed with Win32 error 2 for both programs. Without an AppContainer profile no process was created, and creating a profile writes to the user's registry hive, which this run may not do.

   Thread impersonation replaced these attempts (rows above). It tests the HCS access path under each token. It does not test a process whose primary token is that token.
4. The other identities of the S1 matrix were not run. Each needs a host change this run may not make: elevated administrator (elevation), standard user and standard user in Hyper-V Administrators (a disposable account and a group change), and a LocalSystem service (a service install). Opening or terminating another identity's system was not tried either: no identity created a system, and this run may not open systems it did not create.

### Not run

- The S1 rows named in item 4 above.
- S2 to S8, because S1 created and started no system as the non-elevated user, which is S2's precondition.
- S9, which VM-W19 owns.
- Hosts H1 and H3.
- `WHvCreatePartition`. CIM reports Windows Hypervisor Platform disabled, yet `WHvGetCapability` answered. Whether a partition can be created here is a VM-W19 question.

### Time spent

The work started at 21:21. S0 ran at 21:29 and S1 at 21:30 (run 1) and 21:33 (run 2). The stop gate was reached at 21:36, 15 minutes into the time box. The closing owner-filtered enumeration ran at 21:39, and this record was finished at about 21:41: roughly 20 minutes in total, well within the three-hour box.

### Decision for this host

| Host | Edition, build, architecture | Decision | Stop gate that decided it |
| --- | --- | --- | --- |
| H2 | Windows 11 Home (EditionID Core), build 10.0.26300.9818, x64 | QEMU/WHPX. HCS is unavailable here to every identity the host offers without a change. QEMU/WHPX remains experimental until VM-W19 validates it (S9 not run) | S1: `HcsCreateComputeSystem` was refused for all four identities (`0x8037011B`, `0x800706D8`), so no path exists in which the interactive user is not an administrator. The owner's answer to question 1 is still open. S0's schema check was also refused |

### Owner questions this answers (section 15)

- Question 1, the privilege model, is answered in part. On H2, HCS refuses every non-elevated identity, so the "standard user directly" path does not exist here. An HCS backend on this host needs (a), (b) or (c); otherwise the answer is (d). The Hyper-V Administrators group exists on this Home host, so (c) is technically possible on Home [O], but it was not tested.
- Question 2, the target editions: if the backend that ships first must support Home and the owner takes none of (a), (b) or (c), Home uses QEMU/WHPX. On H2 that branch rests on this result.
- Question 7, spike authorization: the S1 rows still missing on Home need exactly the Tier 2 changes question 7 lists: elevation, a disposable account, a Hyper-V Administrators grant and a test service.
- S0 and S1 do not answer questions 3, 4, 5, 6 and 8. They wait for S2 and later steps.

## Resolution for host H2 (31 October 2026, Agent 1)

VM-D2's order ran as recorded: the HCS spike first (above, stop gate S1), then the
QEMU/WHPX fallback, which is now the Windows profile the engine composes and runs on H2. This
resolves the decision for H2 only; it is not a claim about Pro, other builds or Arm64.

| Item | State on H2 | Evidence |
| --- | --- | --- |
| Decision | QEMU/WHPX (the pinned `qemu-secure` 11.1.0 build, the hardened WHPX profile of `sandbox/qemu`), shipped behind `yougori sandbox` and the desktop's VM sandboxes section; HCS not shipped | this record's S1 rows; `src-tauri/src/sandbox_vm/` |
| S9 (VM-W19 validation, not run by the spike) | Done for the strict profile's launch path: partitions are created (no `WHvCreatePartition` limit met), the restricted QEMU starts at low integrity on its own desktop in a kill-on-close job, its restrictions are read back before admission, the guest boots and completes the authenticated link, a stop and a revocation end the VM with the host's proof | `docs/manager-work-split/integration-queue-2026-10-30.md` (restricted launches); `docs/vm-sandbox/evidence/2026-10-30-guest-egress-path/`; `…/2026-10-30-security-to-production/` |
| Boundary checks read by the doctor on H2 | VM-CP-02 passed (golden comparison from sealed launch records); VM-CP-03 passed (the records' host-interface listing, and its positive control: a launch with a share device planted in the QEMU process was refused as failing the host interface check); VM-CP-05 inconclusive until a signed guest manifest exists; the other required checks are not tested until their host check runners exist. Label: `experimental` | `docs/vm-sandbox/evidence/2026-10-31-platforms-and-acceptance/` |
| Workflows on QEMU/WHPX | declared egress through the confined relay with brokered credentials; the strict tool profile; violation responses; lease revocation; one staged-workspace tool workflow with review, promotion and recovery | the three evidence folders above and `…/2026-10-31-staged-workspace/` |
| HCS on H2 | Unavailable to every identity the host offers without a change (`0x8037011B`, `0x800706D8`) | S1 rows above |

What stays open, each with the input it needs:

- **HCS anywhere.** The owner's answer to question 1 (privilege model: a narrow privileged
  service, an elevation prompt, the Hyper-V Administrators grant, or no HCS). With (a), (b)
  or (c), the spike continues at S1 on Tier 2 hosts (question 7's authorization: elevation,
  a disposable account, the group grant, a test service), then S2 to S8. Until then no
  `hcs` accelerator name or CORE-01 hypervisor kind is used, and the doctor keeps naming
  HCS `unavailable` with the VM-D2 basis.
- **Other Windows hosts.** Pro, other builds and Arm64 are not measured; the same QEMU/WHPX
  profile is expected to apply where the Windows Hypervisor Platform is enabled, and each
  needs its own run before it is called validated.
- **VM-CP-01 and VM-CP-33 on H2.** Their process-list observations (no TCG hypervisor, no
  fallback start after a refused launch) need a host check runner reading the process list;
  the records cannot decide them.
