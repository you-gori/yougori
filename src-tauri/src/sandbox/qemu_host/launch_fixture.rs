//! The launch the QEMU hosts' tests plan from, on a real clock (M02, M04): a CORE-01
//! registry whose host-probe adapter reports the platform's hypervisor available, a
//! CORE-03 ledger with a reservation for the launch, the request and the backend identity.
//! Shared by the Windows and Linux host tests; nothing here starts a process.

use std::sync::Arc;
use std::time::Duration;

use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, HostSubject, HypervisorKind, HypervisorSubject,
    Observation, OsKind, ProbeRegistry, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{digest, Digest, ExecutionId, OperationId, SystemClock, TenantId};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityDeclaration, CostPurpose, HostResource, Ledger, LedgerConfig,
    Priority, Provenance, QueueLimits, Requester, ReservationRequest, ResourceKey,
};
use crate::sandbox::backend::{
    Architecture, BackendIdentity, BackendKind, DeviceExposure, DeviceProfile, LaunchRequest,
    Persistence, PinnedArtifacts, RequiredProperties,
};
use crate::sandbox::qemu::QemuPlatform;

pub(crate) const GIB: u64 = 1 << 30;
pub(crate) const MINUTE: Duration = Duration::from_secs(60);

pub(crate) type Clocked = Arc<SystemClock>;

/// A launch on a real clock: a CORE-01 registry whose host-probe adapter reports the
/// platform's hypervisor available, a CORE-03 ledger with 64 GiB of RAM, a reservation for
/// the launch, the request and the backend identity.
pub(crate) struct Launch {
    pub(crate) registry: ProbeRegistry<Clocked>,
    pub(crate) ledger: Ledger<Clocked>,
    pub(crate) request: LaunchRequest,
    pub(crate) backend: BackendIdentity,
}

/// What a [`Launch`] is made of.
pub(crate) struct LaunchValues<'a> {
    pub(crate) os: OsKind,
    pub(crate) execution: &'a str,
    pub(crate) guest_image: Digest,
    pub(crate) artifact: Digest,
    pub(crate) version: &'a str,
    pub(crate) reserved_ram_bytes: u64,
    pub(crate) persistence: Persistence,
}

pub(crate) fn tenant() -> TenantId {
    TenantId::new("tenant-q1").unwrap()
}

/// This host, by its computer name (its host name on Linux).
pub(crate) fn machine() -> Digest {
    let name = std::env::var("COMPUTERNAME")
        .or_else(|_| std::fs::read_to_string("/proc/sys/kernel/hostname"))
        .unwrap_or_default();
    digest("yougori/q1/machine/v1", &[name.trim().as_bytes()])
}

pub(crate) fn configuration() -> ConfigurationFingerprint {
    let host = if cfg!(windows) { "windows" } else { "linux" };
    ConfigurationFingerprint::from_settings([("host", host), ("task", "q1")]).unwrap()
}

pub(crate) fn hypervisor_of(os: OsKind) -> HypervisorKind {
    match os {
        OsKind::Windows => HypervisorKind::Whpx,
        _ => HypervisorKind::Kvm,
    }
}

pub(crate) fn launch(values: LaunchValues<'_>) -> Launch {
    let clock: Clocked = Arc::new(SystemClock::new());
    let hypervisor = hypervisor_of(values.os);
    let mut registry = ProbeRegistry::new(Arc::clone(&clock));
    let probe = Arc::new(FakeProbe::new(
        Capability::HypervisorAvailable,
        SourceClass::HostProbe,
    ));
    registry.register(Box::new(Arc::clone(&probe))).unwrap();
    let subject = Subject::Hypervisor(HypervisorSubject {
        machine: machine(),
        hypervisor,
    });
    probe.respond(
        &subject,
        Observation::supported(
            configuration(),
            Duration::from_secs(600),
            SupportDetail::Hypervisor { hypervisor },
        ),
    );
    registry
        .refresh(Capability::HypervisorAvailable, &subject)
        .unwrap();
    let mut ledger = Ledger::new(
        Arc::clone(&clock),
        HostSubject { machine: machine() },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 8,
                max_entries_per_tenant: 4,
                max_wait: MINUTE,
            },
            grant_ttl: 30 * MINUTE,
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
    let execution = ExecutionId::new(values.execution).unwrap();
    let admission = ledger
        .reserve(ReservationRequest::new(
            Provenance {
                requester: Requester::VmLifecycle,
                execution: execution.clone(),
                operation: OperationId::new("op-q1-launch").unwrap(),
                tenant: tenant(),
                purpose: CostPurpose::VmResources,
                retry_number: 0,
            },
            Priority::Foreground,
            Amounts::new().host_ram_bytes(values.reserved_ram_bytes),
        ))
        .unwrap();
    let Admission::Granted(reservation) = admission else {
        panic!("the test ledger has room");
    };
    let mut required = RequiredProperties::strictest(MINUTE);
    required.confinement = QemuPlatform {
        os: values.os,
        architecture: Architecture::X86_64,
    }
    .profile()
    .map(|fixed| fixed.confinement_applied())
    .unwrap_or_default();
    required.persistence = values.persistence;
    let request = LaunchRequest {
        execution,
        tenant: tenant(),
        generations: SandboxGenerations::FIRST,
        machine: machine(),
        configuration: configuration(),
        contract: digest("yougori/q1/contract/v1", &[b"q1"]),
        pinned: PinnedArtifacts {
            guest_image: values.guest_image,
            backend: values.artifact,
        },
        device_profile: DeviceProfile {
            identity: digest("yougori/q1/device-profile/v1", &[b"cpu-only"]),
            devices: DeviceExposure::cpu_only(),
        },
        required,
        reservation,
    };
    let backend = BackendIdentity::new(
        BackendKind::Qemu,
        values.version,
        values.artifact,
        hypervisor,
    )
    .unwrap();
    Launch {
        registry,
        ledger,
        request,
        backend,
    }
}
