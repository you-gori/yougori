//! Shared test fixtures: a strict profile and one with a declared interface, host jail
//! settings, a pinned Firecracker row, a ledger reservation and a launch request.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use super::host::{HostOwner, IdRange, JailHost};
use super::names::{ApiId, CgroupPath, HostPath, InterfaceName, JailIdentity, MacAddress};
use super::plan::{LaunchPlan, PlanInputs, PlanRefusal};
use super::profile::{
    CpuLimit, FirecrackerProfile, JailLimits, MachineShape, NetworkInterfaceDeclaration, MIB_BYTES,
};
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::{HostSubject, OsKind, SourceClass};
use crate::foundation::ids::{
    digest, ContentKey, Digest, ExecutionId, ManualClock, OperationId, TenantId,
};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityDeclaration, CostPurpose, HostResource, Ledger, LedgerConfig,
    Priority, Provenance, QueueLimits, Requester, ReservationId, ReservationRequest, ResourceKey,
};
use crate::foundation::report::CommitHash;
use crate::sandbox::backend::{
    LaunchRequest, NetworkAuthority, NetworkChannel, PinnedArtifacts, RequiredProperties,
};
use crate::sandbox::trust::{
    Architecture, BootMethod, BuildInputs, ComponentKind, ComponentPin, ComponentVersion,
    ConfigurationKey, DeviceModel, PinnedConfiguration, SandboxBackend,
};

pub(super) const VERSION: &str = "1.10.1";

pub(super) fn profile() -> FirecrackerProfile {
    FirecrackerProfile {
        machine: MachineShape {
            vcpu_count: 2,
            guest_memory_mib: 1024,
        },
        network_interfaces: Vec::new(),
        entropy_device: true,
        limits: JailLimits {
            vmm_overhead_bytes: 64 * MIB_BYTES,
            cpu: CpuLimit {
                quota_micros: 200_000,
                period_micros: 100_000,
            },
            max_tasks: 16,
            max_open_descriptors: 128,
            max_file_bytes: 64 * MIB_BYTES,
        },
    }
}

pub(super) fn network_profile() -> FirecrackerProfile {
    FirecrackerProfile {
        network_interfaces: vec![NetworkInterfaceDeclaration {
            iface_id: ApiId::new("eth0").unwrap(),
            host_device: InterfaceName::new("tap0").unwrap(),
            guest_mac: MacAddress::parse("02:fc:00:00:00:01").unwrap(),
        }],
        ..profile()
    }
}

pub(super) fn host() -> JailHost {
    let path = |text: &str| HostPath::new(text).unwrap();
    JailHost {
        jailer: path("/opt/vm/jailer"),
        firecracker: path("/opt/vm/firecracker"),
        chroot_base: path("/srv/jailer"),
        netns_dir: path("/run/netns"),
        cgroup_root: path("/sys/fs/cgroup"),
        cgroup_parent: CgroupPath::new("yougori/firecracker").unwrap(),
        artifact_dir: path("/var/lib/yougori/artifacts"),
        owner: HostOwner {
            uid: 1000,
            gid: 1000,
        },
        jail_ids: IdRange {
            first: 64000,
            count: 1000,
        },
    }
}

pub(super) fn identity() -> JailIdentity {
    JailIdentity {
        uid: 64001,
        gid: 64001,
    }
}

pub(super) fn component(kind: ComponentKind, version: &str, bytes: &[u8]) -> ComponentPin {
    ComponentPin {
        kind,
        version: ComponentVersion::new(version).unwrap(),
        content_key: ContentKey::of(bytes),
        length_bytes: bytes.len() as u64,
        build: BuildInputs {
            source: CommitHash::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
            toolchain: digest("yougori/test/toolchain/v1", &[bytes]),
            configuration: digest("yougori/test/build-configuration/v1", &[bytes]),
            builder: digest("yougori/test/builder/v1", &[b"ci"]),
        },
    }
}

pub(super) fn configuration() -> PinnedConfiguration {
    let components: BTreeMap<ComponentKind, ComponentPin> = [
        component(ComponentKind::Runtime, VERSION, b"firecracker binary"),
        component(ComponentKind::Jailer, VERSION, b"jailer binary"),
        component(ComponentKind::GuestKernel, "6.1.155", b"guest kernel"),
        component(ComponentKind::GuestImage, "2026.10.1", b"guest root image"),
    ]
    .into_iter()
    .map(|pin| (pin.kind, pin))
    .collect();
    PinnedConfiguration {
        key: ConfigurationKey {
            os: OsKind::Linux,
            architecture: Architecture::X86_64,
            backend: SandboxBackend::Firecracker,
        },
        boot: BootMethod::DirectKernel,
        components,
        devices: [
            DeviceModel::VirtioBlk,
            DeviceModel::VirtioVsock,
            DeviceModel::VirtioRng,
            DeviceModel::VirtioNet,
        ]
        .into_iter()
        .collect(),
    }
}

pub(super) fn execution() -> ExecutionId {
    ExecutionId::new("exe-fc-1").unwrap()
}

pub(super) fn tenant() -> TenantId {
    TenantId::new("tenant-1").unwrap()
}

pub(super) fn machine() -> Digest {
    digest("yougori/test/machine/v1", &[b"host"])
}

/// The host demand a profile's plan has.
pub(super) fn demand(profile: &FirecrackerProfile) -> Amounts {
    Amounts::new()
        .host_ram_bytes(profile.memory_max_bytes().unwrap())
        .network_slots(profile.network_interfaces.len() as u64)
}

/// Everything one launch plan is built from, with the ledger that holds the reservation.
pub(super) struct Scenario {
    pub(super) ledger: Ledger<Arc<ManualClock>>,
    pub(super) request: LaunchRequest,
    pub(super) profile: FirecrackerProfile,
    pub(super) configuration: PinnedConfiguration,
    pub(super) host: JailHost,
    pub(super) identity: JailIdentity,
}

impl Scenario {
    /// A request for `profile` and a granted reservation of exactly its demand.
    pub(super) fn new(profile: FirecrackerProfile) -> Self {
        let demand = demand(&profile);
        Self::reserving(profile, demand)
    }

    /// A request for `profile` and a granted reservation of `demand`.
    pub(super) fn reserving(profile: FirecrackerProfile, demand: Amounts) -> Self {
        let mut ledger = Ledger::new(
            Arc::new(ManualClock::default()),
            HostSubject { machine: machine() },
            LedgerConfig {
                queue: QueueLimits {
                    max_entries: 4,
                    max_entries_per_tenant: 4,
                    max_wait: Duration::from_secs(60),
                },
                grant_ttl: Duration::from_secs(300),
                unmanaged_usage_max_age: Duration::from_secs(3600),
            },
        );
        for resource in [HostResource::Ram, HostResource::NetworkSlots] {
            let key = ResourceKey::Host(resource);
            ledger
                .declare_capacity(
                    key,
                    CapacityDeclaration {
                        total: 64 << 30,
                        supervisor_reserve: 0,
                        unmanaged_in_use: 0,
                        source: SourceClass::HostProbe,
                    },
                )
                .unwrap();
            for tenant in [tenant(), TenantId::new("tenant-2").unwrap()] {
                ledger.set_tenant_budget(tenant, key, u64::MAX).unwrap();
            }
        }
        let configuration = configuration();
        let reservation = reserve(&mut ledger, execution(), tenant(), demand);
        let network = if profile.declares_network() {
            NetworkAuthority::of([NetworkChannel::NamedTransportRoutes])
        } else {
            NetworkAuthority::offline()
        };
        let pinned = |kind: ComponentKind| *configuration.components[&kind].content_key.digest();
        let request = LaunchRequest {
            execution: execution(),
            tenant: tenant(),
            generations: SandboxGenerations::FIRST,
            machine: machine(),
            configuration: configuration.fingerprint().unwrap(),
            contract: digest("yougori/test/contract/v1", &[b"contract"]),
            pinned: PinnedArtifacts {
                guest_image: pinned(ComponentKind::GuestImage),
                backend: pinned(ComponentKind::Runtime),
            },
            device_profile: profile.device_profile(),
            required: RequiredProperties {
                network,
                ..RequiredProperties::strictest(Duration::from_secs(60))
            },
            reservation,
        };
        Self {
            ledger,
            request,
            profile,
            configuration,
            host: host(),
            identity: identity(),
        }
    }

    pub(super) fn inputs(&self) -> PlanInputs<'_> {
        PlanInputs {
            request: &self.request,
            profile: &self.profile,
            configuration: &self.configuration,
            host: &self.host,
            identity: self.identity,
            reservation: self.ledger.reservation(self.request.reservation).unwrap(),
        }
    }

    pub(super) fn build(&self) -> Result<LaunchPlan, PlanRefusal> {
        LaunchPlan::build(&self.inputs())
    }
}

/// Reserves `demand` for `execution` of `tenant` and returns the granted reservation.
pub(super) fn reserve(
    ledger: &mut Ledger<Arc<ManualClock>>,
    execution: ExecutionId,
    tenant: TenantId,
    demand: Amounts,
) -> ReservationId {
    let admission = ledger
        .reserve(ReservationRequest::new(
            Provenance {
                requester: Requester::VmLifecycle,
                execution,
                operation: OperationId::new("op-launch").unwrap(),
                tenant,
                purpose: CostPurpose::VmResources,
                retry_number: 0,
            },
            Priority::Foreground,
            demand,
        ))
        .unwrap();
    match admission {
        Admission::Granted(id) => id,
        other => panic!("the fixture reservation was not granted: {other:?}"),
    }
}

/// The plan of the strict fixture profile.
pub(super) fn plan() -> LaunchPlan {
    Scenario::new(profile()).build().unwrap()
}

/// The plan of the fixture profile with one declared interface.
pub(super) fn network_plan() -> LaunchPlan {
    Scenario::new(network_profile()).build().unwrap()
}
