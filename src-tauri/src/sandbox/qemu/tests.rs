//! Scenario tests of the QEMU profile on a real CORE-01 registry and a real CORE-03
//! ledger, both on a manual clock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    BackendVersion, Capability, ConfigurationFingerprint, HostSubject, HypervisorKind,
    HypervisorSubject, Observation, OsKind, ProbeRegistry, SourceClass, Subject, SupportDetail,
    UnsupportedReason,
};
use crate::foundation::ids::{
    digest, Digest, ExecutionId, GpuDeviceKey, ManualClock, OperationId, TenantId,
};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityDeclaration, CostPurpose, HostResource, Ledger, LedgerConfig,
    Priority, Provenance, QueueLimits, Requester, ReservationId, ReservationRequest,
    ReservationState, ResourceKey,
};
use crate::sandbox::backend::{
    Architecture, BackendIdentity, BackendKind, ConfinementControl, DeviceExposure, DeviceProfile,
    Feature, LaunchRefusal, LaunchRequest, OperatorConfidentiality, Persistence, PhysicalHost,
    PinnedArtifacts, RequiredProperties,
};

pub(super) const MIB: u64 = 1024 * 1024;
pub(super) const GIB: u64 = 1024 * MIB;
pub(super) const MINUTE: Duration = Duration::from_secs(60);

pub(super) type TestClock = Arc<ManualClock>;

pub(super) fn machine() -> Digest {
    digest("yougori/test/machine/v1", &[b"m"])
}

pub(super) fn config() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", "a")]).unwrap()
}

pub(super) fn artifact() -> Digest {
    digest("yougori/test/backend/v1", &[b"qemu-secure"])
}

pub(super) fn tenant() -> TenantId {
    TenantId::new("tenant-1").unwrap()
}

pub(super) fn hypervisor_of(os: OsKind) -> HypervisorKind {
    match os {
        OsKind::Windows => HypervisorKind::Whpx,
        OsKind::MacOs => HypervisorKind::Hvf,
        _ => HypervisorKind::Kvm,
    }
}

fn hypervisor_subject(hypervisor: HypervisorKind) -> Subject {
    Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor,
    })
}

/// A host: a manual clock, a CORE-01 registry with a host-probe hypervisor adapter, and
/// a CORE-03 ledger with 64 GiB of RAM.
pub(super) struct Host {
    pub(super) clock: TestClock,
    pub(super) registry: ProbeRegistry<TestClock>,
    pub(super) probe: Arc<FakeProbe>,
    pub(super) ledger: Ledger<TestClock>,
}

impl Host {
    pub(super) fn new(source: SourceClass) -> Self {
        let clock: TestClock = Arc::new(ManualClock::default());
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let probe = Arc::new(FakeProbe::new(Capability::HypervisorAvailable, source));
        registry.register(Box::new(Arc::clone(&probe))).unwrap();
        let mut ledger = Ledger::new(
            Arc::clone(&clock),
            HostSubject { machine: machine() },
            LedgerConfig {
                queue: QueueLimits {
                    max_entries: 8,
                    max_entries_per_tenant: 4,
                    max_wait: MINUTE,
                },
                grant_ttl: 300 * Duration::from_secs(1),
                unmanaged_usage_max_age: 1000 * MINUTE,
            },
        );
        let ram = ResourceKey::Host(HostResource::Ram);
        ledger
            .declare_capacity(
                ram,
                CapacityDeclaration {
                    total: 64 * GIB,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), ram, 64 * GIB).unwrap();
        Self {
            clock,
            registry,
            probe,
            ledger,
        }
    }

    pub(super) fn observe(&mut self, hypervisor: HypervisorKind, available: bool) {
        observe_hypervisor(&self.probe, &mut self.registry, hypervisor, available);
    }
}

/// The probe of `registry` observes `hypervisor` available or not, fresh for ten minutes,
/// and the registry stores it.
pub(super) fn observe_hypervisor(
    probe: &FakeProbe,
    registry: &mut ProbeRegistry<TestClock>,
    hypervisor: HypervisorKind,
    available: bool,
) {
    let observation = if available {
        Observation::supported(
            config(),
            Duration::from_secs(600),
            SupportDetail::Hypervisor { hypervisor },
        )
    } else {
        Observation::unsupported(
            config(),
            Duration::from_secs(600),
            UnsupportedReason::HypervisorUnavailable,
        )
    };
    probe.respond(&hypervisor_subject(hypervisor), observation);
    registry
        .refresh(
            Capability::HypervisorAvailable,
            &hypervisor_subject(hypervisor),
        )
        .unwrap();
}

impl Host {
    pub(super) fn reserve(&mut self, execution: &ExecutionId, ram_bytes: u64) -> ReservationId {
        let admission = self
            .ledger
            .reserve(ReservationRequest::new(
                Provenance {
                    requester: Requester::VmLifecycle,
                    execution: execution.clone(),
                    operation: OperationId::new("op-launch").unwrap(),
                    tenant: tenant(),
                    purpose: CostPurpose::VmResources,
                    retry_number: 0,
                },
                Priority::Foreground,
                Amounts::new().host_ram_bytes(ram_bytes),
            ))
            .unwrap();
        match admission {
            Admission::Granted(reservation) => reservation,
            Admission::Queued { .. } => panic!("the test ledger has room"),
        }
    }
}

pub(super) fn path(os: OsKind, unix: &str, windows: &str) -> HostPath {
    match os {
        OsKind::Windows => HostPath::new(PathStyle::Windows, windows).unwrap(),
        _ => HostPath::new(PathStyle::Unix, unix).unwrap(),
    }
}

pub(super) fn inputs(os: OsKind, architecture: Architecture, launch: &str) -> QemuLaunchInputs {
    QemuLaunchInputs {
        platform: QemuPlatform { os, architecture },
        resources: GuestResources::new(2, 2 * GIB).unwrap(),
        firmware_directory: path(
            os,
            "/opt/yougori/qemu/share",
            r"C:\Program Files\Yougori\qemu\share",
        ),
        kernel: path(
            os,
            "/var/lib/yougori/images/vmlinuz",
            r"C:\Yougori\images\vmlinuz",
        ),
        initrd: None,
        kernel_arguments: KernelArguments::parse("root=/dev/vda ro quiet").unwrap(),
        root_image: path(
            os,
            "/var/lib/yougori/images/root,v1.img",
            r"C:\Yougori\images\root,v1.img",
        ),
        volumes: BTreeMap::new(),
        control: PrivateDirectory::new(path(
            os,
            &format!("/run/yougori/{launch}"),
            &format!(r"C:\Yougori\vm\{launch}"),
        ))
        .unwrap(),
        vsock_cid: (os == OsKind::Linux && architecture == Architecture::Aarch64)
            .then(|| GuestCid::new(3).unwrap()),
        egress_endpoints: Vec::new(),
        workload_image: None,
        targets: None,
    }
}

/// A launch on one platform: evidence that the platform's hypervisor is available, a
/// reservation of 4 GiB, a request whose confinement is what the platform applies.
pub(super) struct Fixture {
    pub(super) host: Host,
    pub(super) request: LaunchRequest,
    pub(super) backend: BackendIdentity,
    pub(super) inputs: QemuLaunchInputs,
}

pub(super) fn fixture(os: OsKind, architecture: Architecture) -> Fixture {
    fixture_for("exe-1", os, architecture)
}

pub(super) fn fixture_for(execution: &str, os: OsKind, architecture: Architecture) -> Fixture {
    let hypervisor = hypervisor_of(os);
    let mut host = Host::new(SourceClass::HostProbe);
    host.observe(hypervisor, true);
    let execution = ExecutionId::new(execution).unwrap();
    let reservation = host.reserve(&execution, 4 * GIB);
    let inputs = inputs(os, architecture, "a1");
    let mut required = RequiredProperties::strictest(MINUTE);
    required.confinement = inputs
        .platform
        .profile()
        .map(|fixed| fixed.confinement_applied())
        .unwrap_or_default();
    let request = LaunchRequest {
        execution,
        tenant: tenant(),
        generations: SandboxGenerations::FIRST,
        machine: machine(),
        configuration: config(),
        contract: digest("yougori/test/contract/v1", &[b"c"]),
        pinned: PinnedArtifacts {
            guest_image: digest("yougori/test/image/v1", &[b"root"]),
            backend: artifact(),
        },
        device_profile: DeviceProfile {
            identity: digest("yougori/test/profile/v1", &[b"minimal"]),
            devices: DeviceExposure::cpu_only(),
        },
        required,
        reservation,
    };
    let backend = BackendIdentity::new(BackendKind::Qemu, "9.2.0", artifact(), hypervisor).unwrap();
    Fixture {
        host,
        request,
        backend,
        inputs,
    }
}

impl Fixture {
    pub(super) fn plan(&self) -> Result<QemuLaunchPlan, ProfileRefusal> {
        plan_launch(
            &self.request,
            &self.backend,
            &self.host.registry,
            &self.host.ledger,
            self.inputs.clone(),
        )
    }

    pub(super) fn profile(&self) -> QemuProfile {
        self.plan().unwrap().profile().clone()
    }
}

pub(super) fn windows() -> Fixture {
    fixture(OsKind::Windows, Architecture::X86_64)
}

pub(super) fn linux() -> Fixture {
    fixture(OsKind::Linux, Architecture::X86_64)
}

fn observed(arguments: Vec<String>) -> ObservedArgv {
    ObservedArgv::new("qemu-system-x86_64".into(), arguments).unwrap()
}

pub(super) fn strings(arguments: &[&str]) -> Vec<String> {
    arguments
        .iter()
        .map(|argument| (*argument).to_owned())
        .collect()
}

/// The profile's vector with `extra` appended.
fn with_extra(profile: &QemuProfile, extra: &[&str]) -> ObservedArgv {
    let mut arguments = profile.argv();
    arguments.extend(strings(extra));
    observed(arguments)
}

fn findings_of(observed: &ObservedArgv) -> Vec<ArgvFinding> {
    parse_observed(observed).unwrap_err().findings().to_vec()
}

#[test]
fn the_hardened_whpx_profile_is_this_exact_vector() {
    let profile = windows().profile();
    let name = profile.name().as_str().to_owned();
    let expected = strings(&[
        "-name",
        &name,
        "-machine",
        "microvm,acpi=on,pcie=off,usb=off,graphics=off,isa-serial=off,pic=off,pit=off,rtc=off",
        "-accel",
        "whpx,kernel-irqchip=off",
        "-cpu",
        "max,vmx=off,svm=off",
        "-smp",
        "cpus=2,maxcpus=2,sockets=1,cores=2,threads=1",
        "-m",
        "2048M",
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-L",
        r"C:\Program Files\Yougori\qemu\share",
        "-kernel",
        r"C:\Yougori\images\vmlinuz",
        "-append",
        "root=/dev/vda ro quiet",
        "-blockdev",
        r"driver=file,node-name=root-file,filename=C:\Yougori\images\root,,v1.img,read-only=on",
        "-blockdev",
        "driver=raw,node-name=root,file=root-file,read-only=on",
        "-device",
        "virtio-blk-device,id=root-disk,drive=root",
        "-device",
        "virtio-rng-device,id=rng",
        "-chardev",
        r"socket,id=link,path=C:\Yougori\vm\a1\link.sock,server=on,wait=off",
        "-device",
        "virtio-serial-device,id=link-bus,max_ports=2",
        "-device",
        "virtserialport,id=link-port,bus=link-bus.0,chardev=link,name=org.yougori.link",
        "-fw_cfg",
        r"name=opt/yougori/link-secret,file=C:\Yougori\vm\a1\link-secret",
        "-fw_cfg",
        r"name=opt/yougori/egress-endpoints,file=C:\Yougori\vm\a1\egress-endpoints",
        "-fw_cfg",
        r"name=opt/yougori/workload,file=C:\Yougori\vm\a1\workload",
        "-chardev",
        r"socket,id=qmp,path=C:\Yougori\vm\a1\qmp.sock,server=on,wait=off",
        "-mon",
        "chardev=qmp,mode=control",
        "-action",
        "reboot=shutdown,panic=exit-failure",
    ]);
    assert_eq!(profile.argv(), expected);
    assert_eq!(profile.hypervisor(), HypervisorKind::Whpx);
    assert_eq!(profile.fixed().kind, ProfileKind::HardenedWhpx);
    assert_eq!(profile.link(), LinkChannel::VirtioSerial);
    assert!(name.starts_with(INSTANCE_NAME_PREFIX));
}

#[test]
fn the_minimal_linux_profile_uses_the_guests_link_and_the_seccomp_sandbox() {
    let arm = fixture(OsKind::Linux, Architecture::Aarch64)
        .profile()
        .argv();
    assert!(arm
        .iter()
        .any(|argument| argument == "vhost-vsock-device,id=link,guest-cid=3"));
    let profile = linux().profile();
    let argv = profile.argv();
    assert_eq!(profile.fixed().kind, ProfileKind::MinimalLinuxKvm);
    let pairs: Vec<(String, String)> = argv
        .windows(2)
        .map(|pair| (pair[0].clone(), pair[1].clone()))
        .collect();
    for (option, value) in [
        ("-accel", "kvm"),
        ("-cpu", "host,vmx=off,svm=off"),
        (
            "-sandbox",
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
        ),
        (
            "-chardev",
            "socket,id=qmp,path=/run/yougori/a1/qmp.sock,server=on,wait=off",
        ),
    ] {
        assert!(
            pairs.contains(&(option.to_owned(), value.to_owned())),
            "{option} {value}"
        );
    }
    assert!(argv
        .iter()
        .any(|argument| argument.contains("name=org.yougori.link")));
    assert!(!argv.iter().any(|argument| argument.contains("vsock")));
    assert!(argv[3].contains("pic=on,pit=on,rtc=on"));
}

#[test]
fn the_hvf_profile_uses_the_arm_virt_board() {
    let profile = fixture(OsKind::MacOs, Architecture::Aarch64).profile();
    let argv = profile.argv();
    assert_eq!(profile.fixed().kind, ProfileKind::HardenedHvf);
    assert_eq!(
        argv[3],
        "virt,acpi=off,secure=off,virtualization=off,graphics=off"
    );
    assert_eq!(argv[5], "hvf");
    assert_eq!(argv[7], "host");
    assert!(!argv.iter().any(|argument| argument.starts_with("microvm")));
    assert!(!argv.iter().any(|argument| argument == "-sandbox"));
    let arm_linux = fixture(OsKind::Linux, Architecture::Aarch64).profile();
    assert_eq!(arm_linux.argv()[3].split(',').next(), Some("virt"));
}

#[test]
fn the_vector_is_deterministic_and_never_names_tcg() {
    for (os, architecture) in [
        (OsKind::Windows, Architecture::X86_64),
        (OsKind::Linux, Architecture::X86_64),
        (OsKind::Linux, Architecture::Aarch64),
        (OsKind::MacOs, Architecture::Aarch64),
    ] {
        let first = fixture(os, architecture).profile().argv();
        let second = fixture(os, architecture).profile().argv();
        assert_eq!(first, second);
        assert!(first
            .iter()
            .all(|argument| !argument.to_ascii_lowercase().contains("tcg")));
        assert_eq!(
            first
                .iter()
                .filter(|argument| *argument == "-accel")
                .count(),
            1
        );
        for absent in [
            "-netdev", "-nic", "-net", "-serial", "-vnc", "-spice", "-usb", "-qmp", "-monitor",
            "-gdb",
        ] {
            assert!(!first.iter().any(|argument| argument == absent), "{absent}");
        }
        assert!(!first.iter().any(|argument| argument.contains("balloon")
            || argument.contains("-pci")
            || argument.contains("9p")));
    }
}

#[test]
fn a_built_profile_round_trips_through_its_vector() {
    let mut cases = vec![
        windows(),
        linux(),
        fixture(OsKind::Linux, Architecture::Aarch64),
        fixture(OsKind::MacOs, Architecture::Aarch64),
    ];
    let mut with_parts = linux();
    let volume = digest("yougori/test/volume/v1", &[b"data"]);
    with_parts.request.required.persistence = Persistence::DeclaredDataVolumes {
        volumes: [volume].into_iter().collect(),
    };
    with_parts.inputs.volumes = [(
        volume,
        path(OsKind::Linux, "/var/lib/yougori/volumes/data.img", ""),
    )]
    .into_iter()
    .collect();
    with_parts.inputs.initrd = Some(path(OsKind::Linux, "/var/lib/yougori/images/initrd", ""));
    cases.push(with_parts);
    for case in cases {
        let profile = case.profile();
        let argv = observed(profile.argv());
        assert_eq!(parse_observed(&argv), Ok(profile.clone()));
        assert_eq!(check_observed(&argv, &profile), Ok(()));
    }
}

#[test]
fn a_tcg_argument_anywhere_refuses() {
    let profile = linux().profile();
    let base = profile.argv();
    let mut cases: Vec<Vec<String>> = vec![
        {
            let mut argv = base.clone();
            argv[5] = "tcg".into();
            argv
        },
        {
            let mut argv = base.clone();
            argv[5] = "tcg,thread=multi".into();
            argv
        },
        {
            let mut argv = base.clone();
            argv.extend(strings(&["-accel", "tcg,thread=multi"]));
            argv
        },
        {
            let mut argv = base.clone();
            argv[3] = format!("{},accel=kvm:tcg", argv[3]);
            argv
        },
        {
            let mut argv = base.clone();
            argv.extend(strings(&["-machine", "accel=TCG"]));
            argv
        },
    ];
    let append = base
        .iter()
        .position(|argument| argument == "-append")
        .unwrap()
        + 1;
    let mut in_kernel_line = base.clone();
    in_kernel_line[append] = "root=/dev/vda accel=tcg".into();
    cases.push(in_kernel_line);
    for argv in cases {
        let refusal = parse_observed(&observed(argv.clone())).unwrap_err();
        assert!(refusal.names_tcg(), "{argv:?}");
    }
}

#[test]
fn a_host_without_hardware_virtualization_gets_no_plan() {
    // No evidence at all: the hypervisor was never probed.
    let mut missing = windows();
    missing.host = Host::new(SourceClass::HostProbe);
    missing.request.reservation = missing.host.reserve(&missing.request.execution, 4 * GIB);
    assert!(matches!(
        missing.plan(),
        Err(ProfileRefusal::Launch {
            refusal: LaunchRefusal::Evidence { .. }
        })
    ));
    // Forced unavailable (VM-CP-01, VM-CP-33): refused, with nothing to start.
    let mut unavailable = windows();
    unavailable.host.observe(HypervisorKind::Whpx, false);
    assert!(matches!(
        unavailable.plan(),
        Err(ProfileRefusal::Launch {
            refusal: LaunchRefusal::Evidence { .. }
        })
    ));
    // A guest's word is not host evidence.
    let mut guest = windows();
    guest.host = Host::new(SourceClass::GuestReport);
    guest.host.observe(HypervisorKind::Whpx, true);
    guest.request.reservation = guest.host.reserve(&guest.request.execution, 4 * GIB);
    assert!(matches!(
        guest.plan(),
        Err(ProfileRefusal::Launch {
            refusal: LaunchRefusal::Evidence { .. }
        })
    ));
    // Evidence for KVM says nothing about WHPX.
    let mut other = windows();
    other.host = Host::new(SourceClass::HostProbe);
    other.host.observe(HypervisorKind::Kvm, true);
    other.request.reservation = other.host.reserve(&other.request.execution, 4 * GIB);
    assert!(other.plan().is_err());
    // Stale evidence is refused too.
    let stale = windows();
    stale.host.clock.advance(Duration::from_secs(601));
    assert!(matches!(
        stale.plan(),
        Err(ProfileRefusal::Launch {
            refusal: LaunchRefusal::Evidence { .. }
        })
    ));
    // The positive control: the same host with evidence gets a plan naming WHPX.
    let plan = windows().plan().unwrap();
    assert_eq!(plan.profile().hypervisor(), HypervisorKind::Whpx);
    assert_eq!(
        plan.evidence().capability(),
        Capability::HypervisorAvailable
    );
}

#[test]
fn the_backend_must_be_this_hosts_pinned_qemu_build() {
    let mut fake = windows();
    fake.backend.kind = BackendKind::Fake;
    assert_eq!(
        fake.plan(),
        Err(ProfileRefusal::NotQemuBackend {
            kind: BackendKind::Fake
        })
    );
    let mut mismatch = windows();
    mismatch.backend.hypervisor = HypervisorKind::Kvm;
    assert_eq!(
        mismatch.plan(),
        Err(ProfileRefusal::HypervisorMismatch {
            platform: HypervisorKind::Whpx,
            backend: HypervisorKind::Kvm
        })
    );
    let mut pinned = windows();
    pinned.request.pinned.backend = digest("yougori/test/backend/v1", &[b"other"]);
    assert!(matches!(
        pinned.plan(),
        Err(ProfileRefusal::Launch {
            refusal: LaunchRefusal::BackendArtifactMismatch { .. }
        })
    ));
}

#[test]
fn unsupported_hosts_are_refused() {
    for (os, architecture, refusal) in [
        (
            OsKind::Wsl2,
            Architecture::X86_64,
            PlatformRefusal::SharedKernel,
        ),
        (
            OsKind::Windows,
            Architecture::Aarch64,
            PlatformRefusal::WhpxNotOnArchitecture {
                architecture: Architecture::Aarch64,
            },
        ),
        (
            OsKind::MacOs,
            Architecture::X86_64,
            PlatformRefusal::NoMinimalMachineOnIntelMac,
        ),
    ] {
        let mut case = windows();
        case.inputs.platform = QemuPlatform { os, architecture };
        assert_eq!(case.plan(), Err(ProfileRefusal::Platform { refusal }));
    }
}

#[test]
fn every_feature_the_profile_lacks_is_refused_by_name() {
    let gpu = GpuDeviceKey {
        machine: machine(),
        device: digest("yougori/test/device/v1", &[b"gpu0"]),
    };
    let mut display = windows();
    display.request.device_profile.devices.display = true;
    let mut gpus = windows();
    gpus.request.device_profile.devices.gpus.insert(gpu);
    let mut confidential = windows();
    confidential.request.required.confidentiality =
        OperatorConfidentiality::VerifiedConfidentialVm {
            scope: digest("yougori/test/scope/v1", &[b"s"]),
        };
    let mut dedicated = windows();
    dedicated.request.required.isolation.physical_host = PhysicalHost::Dedicated;
    for (case, feature) in [
        (display, Feature::Display),
        (gpus, Feature::GpuAssignment),
        (confidential, Feature::ConfidentialVm),
        (dedicated, Feature::DedicatedHost),
    ] {
        assert_eq!(
            case.plan(),
            Err(ProfileRefusal::Launch {
                refusal: LaunchRefusal::Unsupported { feature }
            })
        );
    }
    assert!(qemu_features().supported.is_empty());
}

#[test]
fn required_confinement_the_platform_does_not_apply_is_refused() {
    let all = ConfinementControl::all();
    let mut strict_windows = windows();
    strict_windows.request.required.confinement = all.clone();
    assert_eq!(
        strict_windows.plan(),
        Err(ProfileRefusal::ConfinementNotProvided {
            missing: [
                ConfinementControl::AccountIdentity,
                ConfinementControl::SyscallRestrictions
            ]
            .into_iter()
            .collect()
        })
    );
    let mut strict_linux = linux();
    strict_linux.request.required.confinement = all.clone();
    let Err(ProfileRefusal::ConfinementNotProvided { missing }) = strict_linux.plan() else {
        panic!("Linux claims no filesystem limits");
    };
    assert_eq!(
        missing,
        [ConfinementControl::FilesystemLimits].into_iter().collect()
    );
    let mut mac = fixture(OsKind::MacOs, Architecture::Aarch64);
    mac.request.required.confinement = [ConfinementControl::ProcessIdentity].into_iter().collect();
    assert!(matches!(
        mac.plan(),
        Err(ProfileRefusal::ConfinementNotProvided { .. })
    ));
}

#[test]
fn only_declared_volumes_are_attached_and_only_they_are_writable() {
    let data = digest("yougori/test/volume/v1", &[b"data"]);
    let cache = digest("yougori/test/volume/v1", &[b"cache"]);
    let mut missing = windows();
    missing.request.required.persistence = Persistence::DeclaredDataVolumes {
        volumes: [data].into_iter().collect(),
    };
    assert_eq!(
        missing.plan(),
        Err(ProfileRefusal::VolumeNotProvided { volume: data })
    );
    let mut undeclared = windows();
    undeclared.inputs.volumes = [(
        cache,
        path(OsKind::Windows, "", r"C:\Yougori\volumes\cache.img"),
    )]
    .into_iter()
    .collect();
    assert_eq!(
        undeclared.plan(),
        Err(ProfileRefusal::UndeclaredVolume { volume: cache })
    );
    let mut declared = windows();
    declared.request.required.persistence = Persistence::ControlledServiceRenewal {
        volumes: [data].into_iter().collect(),
    };
    declared.inputs.volumes = [(
        data,
        path(OsKind::Windows, "", r"C:\Yougori\volumes\data.img"),
    )]
    .into_iter()
    .collect();
    let plan = declared.plan().unwrap();
    let argv = plan.profile().argv();
    assert!(argv.contains(
        &r"driver=file,node-name=vol0-file,filename=C:\Yougori\volumes\data.img,read-only=off"
            .to_owned()
    ));
    assert!(argv.contains(&"virtio-blk-device,id=vol0-disk,drive=vol0".to_owned()));
    let read_only: Vec<&String> = argv
        .iter()
        .filter(|argument| argument.contains("read-only=on"))
        .collect();
    assert_eq!(read_only.len(), 2);
    assert!(read_only.iter().all(|argument| argument.contains("root")));
    assert_eq!(
        plan.volumes().get(&data),
        Some(&plan.profile().volumes()[0])
    );
}

#[test]
fn the_guest_memory_must_fit_this_launchs_open_reservation() {
    let mut large = windows();
    large.inputs.resources = GuestResources::new(2, 8 * GIB).unwrap();
    assert_eq!(
        large.plan(),
        Err(ProfileRefusal::MemoryExceedsReservation {
            memory_bytes: 8 * GIB,
            reserved_bytes: 4 * GIB
        })
    );
    let mut unknown = windows();
    unknown.request.reservation = serde_json::from_value(999.into()).unwrap();
    assert!(matches!(
        unknown.plan(),
        Err(ProfileRefusal::ReservationNotFound { .. })
    ));
    let mut foreign = windows();
    let other = ExecutionId::new("exe-other").unwrap();
    foreign.request.reservation = foreign.host.reserve(&other, 4 * GIB);
    assert!(matches!(
        foreign.plan(),
        Err(ProfileRefusal::ReservationOfOtherExecution { .. })
    ));
    let mut releasing = windows();
    let reservation = releasing.request.reservation;
    releasing.host.ledger.begin_create(reservation).unwrap();
    releasing.host.ledger.cancel(reservation).unwrap();
    assert_eq!(
        releasing.plan(),
        Err(ProfileRefusal::ReservationNotUsable {
            reservation,
            state: ReservationState::Releasing
        })
    );
    let mut cancelled = windows();
    let reservation = cancelled.request.reservation;
    cancelled.host.ledger.cancel(reservation).unwrap();
    assert_eq!(
        cancelled.plan(),
        Err(ProfileRefusal::ReservationNotFound { reservation })
    );
    let exact = windows();
    let plan = exact.plan().unwrap();
    assert_eq!(plan.reserved_ram_bytes(), 4 * GIB);
    let view = exact
        .host
        .ledger
        .reserved_vm(exact.request.reservation)
        .unwrap();
    assert_eq!(view.state, ReservationState::Granted);
    assert_eq!(view.ram_bytes, 4 * GIB);
}

#[test]
fn paths_and_link_values_must_suit_the_platform() {
    let mut unix_on_windows = windows();
    unix_on_windows.inputs.kernel = path(OsKind::Linux, "/boot/vmlinuz", "");
    assert_eq!(
        unix_on_windows.plan(),
        Err(ProfileRefusal::PathStyle {
            role: PathRole::Kernel,
            expected: PathStyle::Windows,
            found: PathStyle::Unix
        })
    );
    let mut no_cid = fixture(OsKind::Linux, Architecture::Aarch64);
    no_cid.inputs.vsock_cid = None;
    assert_eq!(no_cid.plan(), Err(ProfileRefusal::GuestCidRequired));
    let mut cid_on_x86_linux = linux();
    cid_on_x86_linux.inputs.vsock_cid = Some(GuestCid::new(9).unwrap());
    assert_eq!(
        cid_on_x86_linux.plan(),
        Err(ProfileRefusal::GuestCidNotUsed)
    );
    let mut cid_on_windows = windows();
    cid_on_windows.inputs.vsock_cid = Some(GuestCid::new(9).unwrap());
    assert_eq!(cid_on_windows.plan(), Err(ProfileRefusal::GuestCidNotUsed));
}

#[test]
fn the_canonical_vector_replaces_every_per_launch_value() {
    let profile = linux().profile();
    let canonical = profile.canonical_argv();
    let text = canonical.join(" ");
    for placeholder in [
        "{instance}",
        "{vcpu_count}",
        "{memory}",
        "{firmware_directory}",
        "{kernel}",
        "{kernel_arguments}",
        "{root_image}",
        "{link_secret}",
        "{egress_endpoints}",
        "{qmp_socket}",
        "{link_socket}",
    ] {
        assert!(text.contains(placeholder), "{placeholder}");
    }
    // The Arm profile's vsock link names the context id as a placeholder too.
    let arm = fixture(OsKind::Linux, Architecture::Aarch64).profile();
    assert!(arm.canonical_argv().join(" ").contains("{guest_cid}"));
    assert!(!text.contains("/run/yougori"));
    assert!(!text.contains("/var/lib"));
    assert!(!text.contains(profile.name().as_str()));
    assert_eq!(canonical.len(), profile.argv().len());
}

fn golden_of(fixture: &Fixture) -> (QemuProfile, GoldenFile) {
    let profile = fixture.profile();
    let golden = GoldenFile::of(&profile, &fixture.backend).unwrap();
    (profile, golden)
}

#[test]
fn full_internet_is_an_explicit_checked_profile_variant() {
    use crate::sandbox::backend::NetworkChannel;
    for mut fixture in [windows(), linux()] {
        let offline = fixture.profile();
        let golden = GoldenFile::of(&offline, &fixture.backend).unwrap();
        assert!(!offline.internet());
        assert!(!offline.argv().iter().any(|arg| arg == "-netdev"));
        fixture.request.required.network.channels.insert(NetworkChannel::Internet);
        let online = fixture.profile();
        assert!(online.internet());
        assert!(check_observed(&observed(online.argv()), &online).is_ok());
        assert!(check_observed(&observed(online.argv()), &offline).is_err());
        assert!(check_observed(&observed(offline.argv()), &online).is_err());
        let approved = golden.compare_plan(&online, &fixture.backend).unwrap();
        assert_eq!(approved.golden, approved.observed);
        assert_ne!(approved.golden, golden.digest);
        let mut injected = online.argv();
        let backend = injected.iter_mut().find(|arg| *arg == super::profile::INTERNET_BACKEND).unwrap();
        backend.push_str(",hostfwd=tcp::2222-:22");
        assert!(check_observed(&observed(injected), &online).is_err());
        assert!(check_observed(&with_extra(&online, &["-device", "virtio-net-device,netdev=other"]), &online).is_err());
    }
}

/// A network card's every frame goes through the host's filter: its four sockets in the
/// private directory and the two redirectors are part of the profile, so a process running the
/// card without them, or with another filter, is not the profile. Targets ride on the plan to
/// the host's filter (the vector is the card's either way), need a card, and must be the
/// request's own.
#[test]
fn every_frame_of_a_network_card_passes_the_host_filter_and_targets_need_a_card() {
    use crate::sandbox::backend::{NetworkChannel, NetworkTarget};
    for mut fixture in [windows(), linux()] {
        fixture.request.required.network.channels.insert(NetworkChannel::Internet);
        let online = fixture.profile();
        let argv = online.argv();
        let text = argv.join(" ");
        for (index, socket) in online.control().network_sockets().iter().enumerate() {
            assert!(
                text.contains(&format!("socket,id=net{index},path={},server=on,wait=off", socket.as_str())),
                "{text}"
            );
        }
        assert!(text.contains("filter-redirector,id=net-rx,netdev=internet,queue=rx,outdev=net0,indev=net1"));
        assert!(text.contains("filter-redirector,id=net-tx,netdev=internet,queue=tx,outdev=net2,indev=net3"));
        let mut unfiltered = Vec::new();
        let mut tokens = argv.iter();
        while let Some(token) = tokens.next() {
            if token == "-object" {
                tokens.next();
            } else {
                unfiltered.push(token.clone());
            }
        }
        assert!(check_observed(&observed(unfiltered), &online).is_err(), "a card without the filter");
        assert!(
            check_observed(&with_extra(&online, &["-object", "filter-dump,id=dump,netdev=internet,file=x"]), &online).is_err(),
            "another filter on the card"
        );
        let target = NetworkTarget {
            host: "staging.example.com".into(),
            addresses: vec!["93.184.216.34".parse().unwrap()],
            ports: vec![443],
        };
        fixture.request.required.targets = Some(vec![target.clone()]);
        fixture.inputs.targets = Some(vec![target.clone()]);
        let plan = fixture.plan().unwrap();
        assert_eq!(plan.targets(), Some(&[target.clone()][..]));
        assert_eq!(plan.profile().argv(), argv, "the vector is the card's, whatever it reaches");
        fixture.inputs.targets = None;
        assert!(matches!(fixture.plan(), Err(ProfileRefusal::NetworkTargets { .. })));
        fixture.inputs.targets = Some(vec![target]);
        fixture.request.required.network.channels.remove(&NetworkChannel::Internet);
        assert!(matches!(fixture.plan(), Err(ProfileRefusal::NetworkTargets { .. })));
    }
}

#[test]
fn the_golden_file_matches_every_launch_of_its_profile() {
    let first = windows();
    let (profile, golden) = golden_of(&first);
    assert_eq!(golden.verify(), Ok(()));
    let comparison = golden
        .compare(&observed(profile.argv()), &profile, &first.backend)
        .unwrap();
    assert!(comparison.matches());
    assert!(comparison.differences.is_empty() && !comparison.reordered);
    // Another launch: another execution, directory and size, the same profile.
    let mut second = fixture_for("exe-2", OsKind::Windows, Architecture::X86_64);
    second.inputs.control =
        PrivateDirectory::new(path(OsKind::Windows, "", r"C:\Yougori\vm\b2")).unwrap();
    second.inputs.resources = GuestResources::new(4, 3 * GIB).unwrap();
    let other = second.profile();
    assert_ne!(other.argv(), profile.argv());
    assert_eq!(other.canonical_argv(), profile.canonical_argv());
    let comparison = golden
        .compare(&observed(other.argv()), &other, &second.backend)
        .unwrap();
    assert!(comparison.matches());
    // Canonicalized against the wrong launch, the per-launch values are changes.
    let comparison = golden
        .compare(&observed(other.argv()), &profile, &first.backend)
        .unwrap();
    assert!(!comparison.matches());
    assert!(comparison
        .differences
        .iter()
        .any(|difference| matches!(difference, ArgumentDifference::Changed { .. })));
}

#[test]
fn the_golden_digest_changes_with_any_argument_or_backend_version() {
    let fixture = linux();
    let (profile, golden) = golden_of(&fixture);
    let canonical = profile.canonical_argv();
    for index in 0..canonical.len() {
        let mut changed = canonical.clone();
        changed[index].push('x');
        assert_ne!(
            golden_digest(
                golden.backend_kind,
                &golden.backend_version,
                golden.os,
                golden.architecture,
                golden.profile,
                &changed
            ),
            golden.digest,
            "{index}"
        );
        let mut argv = profile.argv();
        argv[index].push('x');
        let comparison = golden
            .compare(&observed(argv), &profile, &fixture.backend)
            .unwrap();
        assert!(!comparison.matches(), "{index}");
        assert!(!comparison.differences.is_empty(), "{index}");
    }
    let mut swapped = profile.argv();
    let rng = swapped
        .iter()
        .position(|argument| argument == "virtio-rng-device,id=rng")
        .unwrap();
    let qmp = swapped
        .iter()
        .position(|argument| argument.starts_with("socket,id=qmp"))
        .unwrap();
    swapped.swap(rng, qmp);
    swapped.swap(rng - 1, qmp - 1);
    let comparison = golden
        .compare(&observed(swapped), &profile, &fixture.backend)
        .unwrap();
    assert!(!comparison.matches());
    assert!(comparison.reordered && comparison.differences.is_empty());
    let mut newer = fixture.backend.clone();
    newer.version = BackendVersion::new("9.2.1").unwrap();
    assert_ne!(
        GoldenFile::of(&profile, &newer).unwrap().digest,
        golden.digest
    );
    assert_eq!(
        golden.compare(&observed(profile.argv()), &profile, &newer),
        Err(GoldenRefusal::OtherBackendVersion {
            golden: fixture.backend.version.clone(),
            running: newer.version.clone()
        })
    );
}

#[test]
fn the_golden_comparison_names_unexpected_missing_and_changed_arguments() {
    let fixture = windows();
    let (profile, golden) = golden_of(&fixture);
    let mut argv = profile.argv();
    let nodefaults = argv
        .iter()
        .position(|argument| argument == "-nodefaults")
        .unwrap();
    argv.remove(nodefaults);
    argv[3] = argv[3].replace("isa-serial=off", "isa-serial=on");
    argv.extend(strings(&["-device", "virtio-balloon-device,id=balloon"]));
    let comparison = golden
        .compare(&observed(argv), &profile, &fixture.backend)
        .unwrap();
    assert_eq!(
        comparison.differences,
        vec![
            ArgumentDifference::Changed {
                expected: "-machine microvm,acpi=on,pcie=off,usb=off,graphics=off,isa-serial=off,pic=off,pit=off,rtc=off".into(),
                observed: "-machine microvm,acpi=on,pcie=off,usb=off,graphics=off,isa-serial=on,pic=off,pit=off,rtc=off".into(),
            },
            ArgumentDifference::Missing {
                argument: "-nodefaults".into()
            },
            ArgumentDifference::Unexpected {
                argument: "-device virtio-balloon-device,id=balloon".into()
            },
        ]
    );
}

#[test]
fn a_golden_file_is_checked_before_it_is_used() {
    let fixture = windows();
    let (profile, golden) = golden_of(&fixture);
    let json = serde_json::to_value(&golden).unwrap();
    assert_eq!(
        serde_json::from_value::<GoldenFile>(json.clone()).unwrap(),
        golden
    );
    let mut extra = json;
    extra["approved_by"] = "someone".into();
    assert!(serde_json::from_value::<GoldenFile>(extra).is_err());
    let mut tampered = golden.clone();
    tampered
        .arguments
        .retain(|argument| argument != "-nodefaults");
    assert!(matches!(
        tampered.compare(&observed(profile.argv()), &profile, &fixture.backend),
        Err(GoldenRefusal::DigestMismatch { .. })
    ));
    let mut format = golden.clone();
    format.format = 2;
    assert_eq!(
        format.verify(),
        Err(GoldenRefusal::UnsupportedFormat { format: 2 })
    );
    let linux_fixture = linux();
    let linux_profile = linux_fixture.profile();
    assert!(matches!(
        golden.compare(
            &observed(linux_profile.argv()),
            &linux_profile,
            &fixture.backend
        ),
        Err(GoldenRefusal::OtherProfile { .. })
    ));
    let mut fake = fixture.backend.clone();
    fake.kind = BackendKind::Fake;
    assert_eq!(
        GoldenFile::of(&profile, &fake),
        Err(GoldenRefusal::NotQemuBackend {
            kind: BackendKind::Fake
        })
    );
}

#[test]
fn share_devices_are_refused() {
    let profile = linux().profile();
    for (extra, kind) in [
        (
            vec!["-device", "virtio-9p-device,fsdev=f,mount_tag=host"],
            ShareKind::NineP,
        ),
        (
            vec![
                "-virtfs",
                "local,path=/home,mount_tag=host,security_model=none",
            ],
            ShareKind::NineP,
        ),
        (
            vec!["-fsdev", "local,id=f,path=/home,security_model=none"],
            ShareKind::NineP,
        ),
        (
            vec!["-device", "vhost-user-fs-device,chardev=fs,tag=host"],
            ShareKind::Virtiofs,
        ),
        (
            vec!["-drive", "file=fat:rw:/home,format=raw"],
            ShareKind::Vvfat,
        ),
        (
            vec!["-blockdev", "driver=vvfat,node-name=v,dir=/home"],
            ShareKind::Vvfat,
        ),
        (vec!["-netdev", "user,id=n,smb=/home"], ShareKind::Smb),
    ] {
        let findings = findings_of(&with_extra(&profile, &extra));
        assert!(
            findings
                .iter()
                .any(|finding| matches!(finding, ArgvFinding::ShareDevice { kind: found, .. } if *found == kind)),
            "{extra:?}: {findings:?}"
        );
    }
}

#[test]
fn network_management_listeners_are_refused() {
    let profile = windows().profile();
    for (extra, interface) in [
        (
            vec!["-qmp", "tcp:127.0.0.1:4444,server=on,wait=off"],
            ManagementInterface::Qmp,
        ),
        (
            vec!["-qmp-pretty", "websocket:0.0.0.0:4444"],
            ManagementInterface::Qmp,
        ),
        (
            vec!["-monitor", "telnet:127.0.0.1:4445,server,nowait"],
            ManagementInterface::Hmp,
        ),
        (
            vec![
                "-chardev",
                "socket,id=remote,host=127.0.0.1,port=4446,server=on,wait=off",
                "-mon",
                "chardev=remote,mode=control",
            ],
            ManagementInterface::Qmp,
        ),
        (
            vec![
                "-chardev",
                "udp,id=hmp,host=127.0.0.1,port=4447",
                "-mon",
                "chardev=hmp",
            ],
            ManagementInterface::Hmp,
        ),
    ] {
        let findings = findings_of(&with_extra(&profile, &extra));
        assert!(
            findings.iter().any(|finding| matches!(
                finding,
                ArgvFinding::ManagementListener { interface: found, .. } if *found == interface
            )),
            "{extra:?}: {findings:?}"
        );
    }
    let findings = findings_of(&with_extra(
        &profile,
        &["-chardev", "socket,id=other,host=127.0.0.1,port=5000"],
    ));
    assert!(findings
        .iter()
        .any(|finding| matches!(finding, ArgvFinding::NetworkChardev { .. })));
}

#[test]
fn qmp_must_be_in_this_launchs_private_directory() {
    let fixture = windows();
    let profile = fixture.profile();
    let moved = |from: &str, to: &str| {
        observed(
            profile
                .argv()
                .into_iter()
                .map(|argument| argument.replace(from, to))
                .collect(),
        )
    };
    // The QMP socket under another name in the directory is not the profile's.
    let renamed = moved(r"a1\qmp.sock", r"a1\control.sock");
    assert!(findings_of(&renamed)
        .iter()
        .any(|finding| matches!(finding, ArgvFinding::InvalidValue { .. })));
    // A QMP socket in another directory reads back, but not as this launch.
    let elsewhere = observed(
        profile
            .argv()
            .into_iter()
            .map(|argument| {
                argument.replace(r"C:\Yougori\vm\a1\qmp.sock", r"C:\Users\Public\qmp.sock")
            })
            .collect(),
    );
    let refusal = check_observed(&elsewhere, &profile).unwrap_err();
    assert!(refusal.findings().iter().any(|finding| matches!(
        finding,
        ArgvFinding::NotThisProfile { .. } | ArgvFinding::InvalidValue { .. }
    )));
    // A named pipe is QEMU's own creation, not the host's.
    let findings = findings_of(&with_extra(&profile, &["-chardev", "pipe,id=p,path=qmp"]));
    assert!(findings
        .iter()
        .any(|finding| matches!(finding, ArgvFinding::PipeEndpoint { .. })));
    assert_eq!(check_observed(&observed(profile.argv()), &profile), Ok(()));
    let other = fixture_for("exe-2", OsKind::Windows, Architecture::X86_64).profile();
    assert!(check_observed(&observed(other.argv()), &profile).is_err());
}

#[test]
fn a_forward_to_the_old_agent_port_is_refused() {
    let profile = windows().profile();
    for rule in [
        "user,id=net0,hostfwd=tcp:127.0.0.1:50123-:7443",
        "user,id=net0,hostfwd=tcp::50123-10.0.2.15:7443",
    ] {
        let findings = findings_of(&with_extra(
            &profile,
            &["-netdev", rule, "-device", "virtio-net-device,netdev=net0"],
        ));
        assert!(findings
            .iter()
            .any(|finding| matches!(finding, ArgvFinding::ForwardToOldAgentPort { .. })));
        assert!(findings
            .iter()
            .any(|finding| matches!(finding, ArgvFinding::NetworkDevice { .. })));
    }
    let findings = findings_of(&with_extra(
        &profile,
        &["-netdev", "user,id=net0,hostfwd=tcp:127.0.0.1:50123-:22"],
    ));
    assert!(!findings
        .iter()
        .any(|finding| matches!(finding, ArgvFinding::ForwardToOldAgentPort { .. })));
    assert!(findings
        .iter()
        .any(|finding| matches!(finding, ArgvFinding::NetworkDevice { .. })));
}

#[test]
fn undeclared_device_classes_are_refused_by_class() {
    let profile = windows().profile();
    let cases: Vec<(Vec<&str>, fn(&ArgvFinding) -> bool)> = vec![
        (vec!["-device", "virtio-net-device,netdev=n"], |f| {
            matches!(f, ArgvFinding::NetworkDevice { .. })
        }),
        (vec!["-nic", "user"], |f| {
            matches!(f, ArgvFinding::NetworkDevice { .. })
        }),
        (
            vec![
                "-blockdev",
                "driver=nbd,node-name=n,server.type=inet,server.host=h,server.port=1",
            ],
            |f| matches!(f, ArgvFinding::NetworkDevice { .. }),
        ),
        (vec!["-serial", "file:serial.log"], |f| {
            matches!(f, ArgvFinding::ConsoleDevice { .. })
        }),
        (vec!["-device", "virtconsole,chardev=c"], |f| {
            matches!(f, ArgvFinding::ConsoleDevice { .. })
        }),
        (vec!["-nographic"], |f| {
            matches!(f, ArgvFinding::ConsoleDevice { .. })
        }),
        (vec!["-device", "virtio-balloon-device"], |f| {
            matches!(f, ArgvFinding::BalloonDevice { .. })
        }),
        (vec!["-device", "virtio-rng-pci"], |f| {
            matches!(f, ArgvFinding::PciTransport { .. })
        }),
        (vec!["-device", "qemu-xhci"], |f| {
            matches!(f, ArgvFinding::UsbDevice { .. })
        }),
        (vec!["-usb"], |f| matches!(f, ArgvFinding::UsbDevice { .. })),
        (vec!["-vnc", "127.0.0.1:0"], |f| {
            matches!(f, ArgvFinding::DisplayDevice { .. })
        }),
        (vec!["-device", "virtio-gpu-device"], |f| {
            matches!(f, ArgvFinding::DisplayDevice { .. })
        }),
        (vec!["-gdb", "tcp::1234"], |f| {
            matches!(f, ArgvFinding::DebugInterface { .. })
        }),
        (vec!["-s"], |f| {
            matches!(f, ArgvFinding::DebugInterface { .. })
        }),
        (vec!["-chardev", "qemu-vdagent,id=v,clipboard=on"], |f| {
            matches!(f, ArgvFinding::ClipboardChannel { .. })
        }),
        (vec!["-device", "vfio-pci,host=01:00.0"], |f| {
            matches!(f, ArgvFinding::HostDeviceAssignment { .. })
        }),
        (vec!["-enable-kvm"], |f| {
            matches!(f, ArgvFinding::AcceleratorSelection { .. })
        }),
        (vec!["-accel", "whpx"], |f| {
            matches!(f, ArgvFinding::AcceleratorSelection { .. })
        }),
        (vec!["-accel", "xen"], |f| {
            matches!(f, ArgvFinding::UnsupportedAccelerator { .. })
        }),
        (vec!["-plugin-of-the-day", "x"], |f| {
            matches!(f, ArgvFinding::UnknownOption { .. })
        }),
        (vec!["disk.img"], |f| {
            matches!(f, ArgvFinding::PositionalArgument { .. })
        }),
        (vec!["-device", "virtio-mouse-device"], |f| {
            matches!(f, ArgvFinding::NotThisProfile { .. })
        }),
        (vec!["-serial", "none"], |f| {
            matches!(f, ArgvFinding::NotThisProfile { .. })
        }),
    ];
    for (extra, expected) in cases {
        let findings = findings_of(&with_extra(&profile, &extra));
        assert!(findings.iter().any(expected), "{extra:?}: {findings:?}");
        let refusal = parse_observed(&with_extra(&profile, &extra)).unwrap_err();
        assert!(!refusal.to_string().is_empty());
    }
    let mut machine = profile.argv();
    machine[3] = machine[3]
        .replace("pcie=off", "pcie=on")
        .replace("usb=off", "usb=on");
    let findings = findings_of(&observed(machine));
    assert!(findings
        .iter()
        .any(|f| matches!(f, ArgvFinding::PciTransport { .. })));
    assert!(findings
        .iter()
        .any(|f| matches!(f, ArgvFinding::UsbDevice { .. })));
}

#[test]
fn the_linux_seccomp_sandbox_cannot_be_dropped_or_weakened() {
    let profile = linux().profile();
    let argv = profile.argv();
    let at = argv
        .iter()
        .position(|argument| argument == "-sandbox")
        .unwrap();
    let mut dropped = argv.clone();
    dropped.drain(at..at + 2);
    let findings = findings_of(&observed(dropped));
    assert_eq!(findings, vec![ArgvFinding::SandboxMissing]);
    for weaker in [
        "off",
        "on,obsolete=deny,elevateprivileges=allow,spawn=deny,resourcecontrol=deny",
        "on,obsolete=deny,elevateprivileges=deny,spawn=deny",
    ] {
        let mut weakened = argv.clone();
        weakened[at + 1] = weaker.into();
        let findings = findings_of(&observed(weakened));
        assert!(
            findings
                .iter()
                .any(|finding| matches!(finding, ArgvFinding::SandboxWeakened { .. })),
            "{weaker}"
        );
    }
}

#[test]
fn todays_microvm_launch_is_refused_with_each_reason() {
    // The current launcher's vector (runtime/vm.rs, spawn_micro_vm, on Windows).
    let today = strings(&[
        "-name",
        "Yougori microVM vm1",
        "-machine",
        "microvm,kernel-irqchip=off,graphics=off,acpi=on,pcie=off,usb=off,pic=off,pit=off,rtc=off",
        "-accel",
        "whpx",
        "-smp",
        "cpus=2,maxcpus=2,sockets=1,cores=2,threads=1",
        "-m",
        "2048",
        "-no-user-config",
        "-nodefaults",
        "-kernel",
        r"C:\Yougori\runtime\vmlinuz",
        "-append",
        "root=/dev/vda rw console=ttyS0,115200n8 reboot=t panic=1",
        "-blockdev",
        r#"{"driver":"file","filename":"C:\\Yougori\\vm1\\disk.qcow2","node-name":"yougori-microvm-file"}"#,
        "-blockdev",
        r#"{"driver":"qcow2","file":"yougori-microvm-file","node-name":"yougori-microvm-disk"}"#,
        "-device",
        "virtio-blk-device,drive=yougori-microvm-disk",
        "-netdev",
        "user,id=net0,hostfwd=tcp:127.0.0.1:50123-:7443",
        "-device",
        "virtio-net-device,netdev=net0",
        "-device",
        "virtio-rng-device",
        "-device",
        "virtio-balloon-device,id=yougori-balloon",
        "-display",
        "none",
        "-serial",
        r"file:C:\Yougori\vm1\serial.log",
        "-qmp",
        r"unix:C:\Yougori\control\0123456789abcdef.qmp,server=on,wait=off",
        "-monitor",
        "none",
        "-action",
        "panic=exit-failure",
        "-no-reboot",
        "-fw_cfg",
        r"name=opt/yougori/control-token,file=C:\Yougori\vm1\token",
        "-cpu",
        "max,vmx=off,svm=off",
        "-L",
        r"C:\Yougori\runtime\share",
        "-netdev",
        "socket,id=odprivate,listen=127.0.0.1:50124",
        "-device",
        "virtio-net-device,netdev=odprivate,mac=52:54:00:12:34:56",
    ]);
    let findings = findings_of(&observed(today.clone()));
    for check in [
        |f: &ArgvFinding| matches!(f, ArgvFinding::ForwardToOldAgentPort { .. }),
        |f: &ArgvFinding| matches!(f, ArgvFinding::NetworkDevice { .. }),
        |f: &ArgvFinding| matches!(f, ArgvFinding::BalloonDevice { .. }),
        |f: &ArgvFinding| matches!(f, ArgvFinding::ConsoleDevice { .. }),
        |f: &ArgvFinding| matches!(f, ArgvFinding::InvalidValue { .. }),
    ] {
        assert!(findings.iter().any(check), "{findings:?}");
    }
    assert!(!findings
        .iter()
        .any(|finding| matches!(finding, ArgvFinding::TcgAccelerator { .. })));
    // Its fallback attempt after a WHPX failure runs the same vector under TCG.
    let mut fallback = today;
    fallback[5] = "tcg,thread=multi".into();
    assert!(parse_observed(&observed(fallback)).unwrap_err().names_tcg());
}

#[test]
fn a_reordered_vector_is_not_the_profile() {
    let profile = linux().profile();
    let mut argv = profile.argv();
    let nodefaults = argv
        .iter()
        .position(|argument| argument == "-nodefaults")
        .unwrap();
    let user_config = argv
        .iter()
        .position(|argument| argument == "-no-user-config")
        .unwrap();
    argv.swap(nodefaults, user_config);
    let findings = findings_of(&observed(argv));
    assert_eq!(findings, vec![ArgvFinding::Reordered]);
}

#[test]
fn the_windows_plan_carries_the_launchers_restrictions() {
    let data = digest("yougori/test/volume/v1", &[b"data"]);
    let mut fixture = windows();
    fixture.request.required.persistence = Persistence::DeclaredDataVolumes {
        volumes: [data].into_iter().collect(),
    };
    let volume = path(OsKind::Windows, "", r"C:\Yougori\volumes\data.img");
    fixture.inputs.volumes = [(data, volume.clone())].into_iter().collect();
    let plan = fixture.plan().unwrap();
    let restrictions = plan.windows().unwrap();
    assert_eq!(restrictions.job().job_memory_limit_bytes, 4 * GIB);
    assert_eq!(restrictions.integrity(), IntegrityLevel::Low);
    assert_eq!(
        restrictions.low_integrity_writable(),
        &[plan.profile().control().path().clone(), volume]
    );
    assert!(!restrictions
        .low_integrity_writable()
        .contains(plan.profile().root_image()));
    assert!(linux().plan().unwrap().windows().is_none());
    let expected: BTreeSet<ConfinementControl> = plan.profile().fixed().confinement_applied();
    assert_eq!(expected.len(), 4);
}

#[test]
fn the_link_secret_travels_by_file_and_never_in_the_arguments() {
    let profile = windows().profile();
    let argv = profile.argv();
    let fw_cfg = argv
        .iter()
        .position(|argument| argument == "-fw_cfg")
        .unwrap();
    assert_eq!(
        argv[fw_cfg + 1],
        format!(
            "name={LINK_SECRET_FW_CFG_NAME},file={}",
            profile.control().link_secret()
        )
    );
    assert!(!argv.iter().any(|argument| argument.contains("string=")));
    for extra in [
        ["-fw_cfg", "name=opt/yougori/other,string=s3cr3t-value"],
        ["-object", "secret,id=s,data=s3cr3t-value"],
    ] {
        let refusal = parse_observed(&with_extra(&profile, &extra)).unwrap_err();
        assert!(refusal
            .findings()
            .iter()
            .any(|finding| matches!(finding, ArgvFinding::SecretInArguments { .. })));
        assert!(!refusal.to_string().contains("s3cr3t"));
        assert!(!serde_json::to_string(&refusal).unwrap().contains("s3cr3t"));
    }
}

#[test]
fn at_most_eight_volumes_are_attached() {
    let volumes: Vec<(Digest, HostPath)> = (0..=MAX_VOLUMES)
        .map(|index| {
            (
                digest("yougori/test/volume/v1", &[&[index as u8]]),
                path(
                    OsKind::Linux,
                    &format!("/var/lib/yougori/volumes/{index}.img"),
                    "",
                ),
            )
        })
        .collect();
    let mut too_many = linux();
    too_many.request.required.persistence = Persistence::DeclaredDataVolumes {
        volumes: volumes.iter().map(|(volume, _)| *volume).collect(),
    };
    too_many.inputs.volumes = volumes.iter().cloned().collect();
    let refusal = too_many.plan().unwrap_err();
    assert_eq!(
        refusal,
        ProfileRefusal::TooManyVolumes {
            count: MAX_VOLUMES + 1,
            max: MAX_VOLUMES
        }
    );
    assert!(refusal.to_string().contains("more than 8"));
    let mut eight = linux();
    eight.request.required.persistence = Persistence::DeclaredDataVolumes {
        volumes: volumes[..MAX_VOLUMES]
            .iter()
            .map(|(volume, _)| *volume)
            .collect(),
    };
    eight.inputs.volumes = volumes[..MAX_VOLUMES].iter().cloned().collect();
    let profile = eight.profile();
    assert_eq!(profile.volumes().len(), MAX_VOLUMES);
    assert_eq!(parse_observed(&observed(profile.argv())), Ok(profile));
}
