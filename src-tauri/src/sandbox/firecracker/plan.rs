//! The launch plan: from a backend [`LaunchRequest`], the approved profile, the pinned
//! configuration row, the host's jail settings, the launch's jail identity and its CORE-03
//! reservation, the Firecracker API plan, the jailer plan, the privileged launcher's
//! closed set of operations and the VM-CP-04 expected state, or a typed refusal for
//! anything this backend cannot provide (VM-W16 line 2615: no fallback may weaken required
//! properties, unsupported features are explicit; VM-W17 line 2616; §3.4 line 2101: a
//! platform that cannot provide the required confinement is unsupported for that profile).
//!
//! Nothing here starts a process: a real backend executes the plan through the launcher
//! and reports what the host observes.

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::api::{ApiPlan, ApiRequest};
use super::host::{HostError, JailHost};
use super::jailer::{CgroupFile, CgroupLimit, JailerParts, JailerPlan, ResourceLimit};
use super::launcher::{LauncherInputs, LauncherPlan, StagedArtifact};
use super::layout;
use super::linux_state::ExpectedLinuxState;
use super::names::{ApiId, InterfaceName, JailId, JailIdentity, NameError};
use super::profile::{FirecrackerProfile, ProfileError};
use crate::foundation::evidence::{ConfigurationFingerprint, HypervisorKind, OsKind};
use crate::foundation::ids::{Digest, ExecutionId, TenantId};
use crate::foundation::ledger::{Amounts, ReservationId, ReservationRecord, ReservationState};
use crate::sandbox::backend::{
    BackendIdentity, BackendKind, Feature, LaunchRequest, NetworkChannel, OperatorConfidentiality,
    Persistence,
};
use crate::sandbox::trust::{
    BootMethod, ComponentKind, ComponentPin, ComponentVersion, ConfigurationKey, DeviceModel,
    PinRefusal, PinnedConfiguration, SandboxBackend,
};

/// Which pinned artifact of a launch request disagrees with the pinned configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinnedArtifact {
    Backend,
    GuestImage,
}

/// Why the launch's reservation does not cover the plan (S10: reserve before creating).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ReservationProblem {
    /// The record handed in is another reservation than the request's.
    OtherReservation {
        requested: ReservationId,
        record: ReservationId,
    },
    OtherExecution {
        requested: ExecutionId,
        record: ExecutionId,
    },
    OtherTenant {
        requested: TenantId,
        record: TenantId,
    },
    /// Only a granted reservation, before anything is created, admits a launch.
    NotGranted { state: ReservationState },
    /// What the plan needs beyond what the reservation holds.
    Insufficient { shortfall: Amounts },
}

/// Why no launch plan was made. Every variant is a refusal; none is a fallback.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PlanRefusal {
    WorkloadImageNotSupported,
    Profile {
        error: ProfileError,
    },
    Host {
        error: HostError,
    },
    Pin {
        refusal: PinRefusal,
    },
    /// The pinned row is not Firecracker on Linux.
    NotFirecrackerOnLinux {
        key: ConfigurationKey,
    },
    /// Firecracker boots its kernel directly; a firmware row is another backend's.
    FirmwareBoot {
        key: ConfigurationKey,
    },
    /// The row pins no official jailer (VM-D15).
    ComponentMissing {
        component: ComponentKind,
    },
    /// The jailer is from another release than Firecracker (VM-P23 line 2798).
    MixedVersions {
        runtime: ComponentVersion,
        jailer: ComponentVersion,
    },
    /// The row's configuration fingerprint cannot be computed.
    FingerprintUnavailable {
        detail: String,
    },
    /// The request's host configuration is not the pinned row's, so evidence bound to
    /// one does not apply to the other (CORE-01).
    ConfigurationMismatch {
        requested: ConfigurationFingerprint,
        pinned: ConfigurationFingerprint,
    },
    /// The pinned version cannot be recorded as the backend version.
    VersionNotRecordable {
        version: ComponentVersion,
        detail: String,
    },
    /// The request is pinned to other artifacts than the row.
    ArtifactMismatch {
        artifact: PinnedArtifact,
        requested: Digest,
        pinned: Digest,
    },
    /// The request names another device profile than this one.
    DeviceProfileMismatch {
        requested: Digest,
        profile: Digest,
    },
    /// A feature this backend does not offer; nothing is substituted.
    Unsupported {
        feature: Feature,
    },
    /// Only ephemeral task sandboxes are planned; data volumes are not attached.
    PersistenceNotSupported {
        persistence: &'static str,
    },
    /// A declared network interface without a declared transport route or published
    /// service: strict action mode and offline mode have no NIC (§4.1 lines 2107–2111).
    NetworkInterfaceNotAuthorized {
        interfaces: Vec<ApiId>,
    },
    /// The pinned row does not offer a device the plan needs.
    DeviceModelAbsent {
        device: DeviceModel,
    },
    Reservation {
        problem: ReservationProblem,
    },
    Name {
        error: NameError,
    },
}

impl fmt::Display for PlanRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkloadImageNotSupported => f.write_str("OCI image declarations require the QEMU guest bootstrap; this Firecracker backend does not provide it"),
            Self::Profile { error } => write!(f, "the Firecracker profile is refused: {error}"),
            Self::Host { error } => write!(f, "the host's jail settings are refused: {error}"),
            Self::Pin { refusal } => write!(f, "the pinned configuration is refused: {refusal}"),
            Self::NotFirecrackerOnLinux { key } => {
                write!(f, "configuration {key} is not Firecracker on Linux")
            }
            Self::FirmwareBoot { key } => write!(
                f,
                "configuration {key} boots through firmware; Firecracker boots its kernel \
                 directly"
            ),
            Self::ComponentMissing { component } => {
                write!(f, "the pinned configuration has no {component}")
            }
            Self::MixedVersions { runtime, jailer } => write!(
                f,
                "the jailer {jailer} is not from the Firecracker {runtime} release"
            ),
            Self::FingerprintUnavailable { detail } => {
                write!(f, "the pinned configuration has no fingerprint: {detail}")
            }
            Self::ConfigurationMismatch { .. } => f.write_str(
                "the request's host configuration is not the pinned configuration's fingerprint",
            ),
            Self::VersionNotRecordable { version, detail } => {
                write!(f, "version {version} cannot be recorded: {detail}")
            }
            Self::ArtifactMismatch {
                artifact,
                requested,
                pinned,
            } => write!(
                f,
                "the request pins {} {requested}, but the configuration pins {pinned}",
                match artifact {
                    PinnedArtifact::Backend => "backend",
                    PinnedArtifact::GuestImage => "guest image",
                }
            ),
            Self::DeviceProfileMismatch { requested, profile } => write!(
                f,
                "the request names device profile {requested}, not this profile {profile}"
            ),
            Self::Unsupported { feature } => {
                write!(f, "the Firecracker backend does not support {feature}")
            }
            Self::PersistenceNotSupported { persistence } => write!(
                f,
                "persistence {persistence} is not planned; only ephemeral task sandboxes are"
            ),
            Self::NetworkInterfaceNotAuthorized { interfaces } => write!(
                f,
                "{} declared network interface{} without a declared transport route or \
                 published service",
                interfaces.len(),
                if interfaces.len() == 1 { "" } else { "s" }
            ),
            Self::DeviceModelAbsent { device } => {
                write!(
                    f,
                    "the pinned configuration does not offer {}",
                    device.tag()
                )
            }
            Self::Reservation { problem } => {
                f.write_str("the launch's reservation does not cover the plan: ")?;
                match problem {
                    ReservationProblem::OtherReservation { requested, record } => {
                        write!(f, "the record is {record}, not {requested}")
                    }
                    ReservationProblem::OtherExecution { requested, record } => {
                        write!(f, "it belongs to {record}, not {requested}")
                    }
                    ReservationProblem::OtherTenant { requested, record } => {
                        write!(f, "it belongs to tenant {record}, not {requested}")
                    }
                    ReservationProblem::NotGranted { state } => {
                        write!(f, "it is {state:?}, not granted")
                    }
                    ReservationProblem::Insufficient { .. } => {
                        f.write_str("it holds less than the plan needs")
                    }
                }
            }
            Self::Name { error } => write!(f, "a planned name is refused: {error}"),
        }
    }
}

impl std::error::Error for PlanRefusal {}

impl From<NameError> for PlanRefusal {
    fn from(error: NameError) -> Self {
        Self::Name { error }
    }
}

/// What one launch plan is built from.
#[derive(Clone, Copy, Debug)]
pub struct PlanInputs<'a> {
    pub request: &'a LaunchRequest,
    pub profile: &'a FirecrackerProfile,
    /// The pinned configuration row for Firecracker on this host (VM-W46).
    pub configuration: &'a PinnedConfiguration,
    pub host: &'a JailHost,
    /// The jail identity allocated to this launch from the host's range.
    pub identity: JailIdentity,
    /// The CORE-03 reservation the request names, as the ledger holds it.
    pub reservation: &'a ReservationRecord,
}

/// The pins of one Firecracker row.
struct Pins<'a> {
    runtime: &'a ComponentPin,
    jailer: &'a ComponentPin,
    kernel: &'a ComponentPin,
    image: &'a ComponentPin,
}

fn pin(
    configuration: &PinnedConfiguration,
    component: ComponentKind,
) -> Result<&ComponentPin, PlanRefusal> {
    configuration
        .component(component)
        .ok_or(PlanRefusal::ComponentMissing { component })
}

fn check_configuration(configuration: &PinnedConfiguration) -> Result<Pins<'_>, PlanRefusal> {
    configuration
        .check()
        .map_err(|refusal| PlanRefusal::Pin { refusal })?;
    let key = configuration.key;
    if key.backend != SandboxBackend::Firecracker || key.os != OsKind::Linux {
        return Err(PlanRefusal::NotFirecrackerOnLinux { key });
    }
    if configuration.boot != BootMethod::DirectKernel {
        return Err(PlanRefusal::FirmwareBoot { key });
    }
    let pins = Pins {
        runtime: pin(configuration, ComponentKind::Runtime)?,
        jailer: pin(configuration, ComponentKind::Jailer)?,
        kernel: pin(configuration, ComponentKind::GuestKernel)?,
        image: pin(configuration, ComponentKind::GuestImage)?,
    };
    if pins.runtime.version != pins.jailer.version {
        return Err(PlanRefusal::MixedVersions {
            runtime: pins.runtime.version.clone(),
            jailer: pins.jailer.version.clone(),
        });
    }
    Ok(pins)
}

/// The backend identity a row's runtime pin gives: Firecracker at the pinned version and
/// artifact, on KVM.
fn backend_of(pins: &Pins<'_>) -> Result<BackendIdentity, PlanRefusal> {
    let version = &pins.runtime.version;
    BackendIdentity::new(
        BackendKind::Firecracker,
        version.as_str(),
        *pins.runtime.content_key.digest(),
        HypervisorKind::Kvm,
    )
    .map_err(|error| PlanRefusal::VersionNotRecordable {
        version: version.clone(),
        detail: error.to_string(),
    })
}

/// The backend identity of a pinned Firecracker row, with the same checks of the row as
/// [`LaunchPlan::build`], for a backend that is set up before any request arrives.
pub(super) fn pinned_backend(
    configuration: &PinnedConfiguration,
) -> Result<BackendIdentity, PlanRefusal> {
    backend_of(&check_configuration(configuration)?)
}

fn check_request(
    request: &LaunchRequest,
    profile: &FirecrackerProfile,
    pins: &Pins<'_>,
) -> Result<(), PlanRefusal> {
    for (artifact, requested, pinned) in [
        (
            PinnedArtifact::Backend,
            request.pinned.backend,
            *pins.runtime.content_key.digest(),
        ),
        (
            PinnedArtifact::GuestImage,
            request.pinned.guest_image,
            *pins.image.content_key.digest(),
        ),
    ] {
        if requested != pinned {
            return Err(PlanRefusal::ArtifactMismatch {
                artifact,
                requested,
                pinned,
            });
        }
    }
    let devices = &request.device_profile.devices;
    if request.required.workload_image.is_some() {
        return Err(PlanRefusal::WorkloadImageNotSupported);
    }
    if devices.display {
        return Err(PlanRefusal::Unsupported {
            feature: Feature::Display,
        });
    }
    if !devices.gpus.is_empty() {
        return Err(PlanRefusal::Unsupported {
            feature: Feature::GpuAssignment,
        });
    }
    if request.device_profile.identity != profile.identity() {
        return Err(PlanRefusal::DeviceProfileMismatch {
            requested: request.device_profile.identity,
            profile: profile.identity(),
        });
    }
    if let OperatorConfidentiality::VerifiedConfidentialVm { .. } = request.required.confidentiality
    {
        return Err(PlanRefusal::Unsupported {
            feature: Feature::ConfidentialVm,
        });
    }
    if request.required.persistence != Persistence::EphemeralTask {
        return Err(PlanRefusal::PersistenceNotSupported {
            persistence: request.required.persistence.tag(),
        });
    }
    let transport = request.required.network.channels.iter().any(|channel| {
        matches!(
            channel,
            NetworkChannel::NamedTransportRoutes | NetworkChannel::PublishedService
        )
    });
    if profile.declares_network() && !transport {
        return Err(PlanRefusal::NetworkInterfaceNotAuthorized {
            interfaces: profile
                .network_interfaces
                .iter()
                .map(|interface| interface.iface_id.clone())
                .collect(),
        });
    }
    Ok(())
}

fn check_device_models(
    configuration: &PinnedConfiguration,
    profile: &FirecrackerProfile,
) -> Result<(), PlanRefusal> {
    let mut needed = vec![DeviceModel::VirtioBlk, DeviceModel::VirtioVsock];
    if profile.entropy_device {
        needed.push(DeviceModel::VirtioRng);
    }
    if profile.declares_network() {
        needed.push(DeviceModel::VirtioNet);
    }
    match needed
        .into_iter()
        .find(|device| !configuration.devices.contains(device))
    {
        Some(device) => Err(PlanRefusal::DeviceModelAbsent { device }),
        None => Ok(()),
    }
}

fn check_reservation(
    request: &LaunchRequest,
    reservation: &ReservationRecord,
    demand: &Amounts,
) -> Result<(), PlanRefusal> {
    let refuse = |problem| Err(PlanRefusal::Reservation { problem });
    if reservation.id() != request.reservation {
        return refuse(ReservationProblem::OtherReservation {
            requested: request.reservation,
            record: reservation.id(),
        });
    }
    let provenance = reservation.provenance();
    if provenance.execution != request.execution {
        return refuse(ReservationProblem::OtherExecution {
            requested: request.execution.clone(),
            record: provenance.execution.clone(),
        });
    }
    if provenance.tenant != request.tenant {
        return refuse(ReservationProblem::OtherTenant {
            requested: request.tenant.clone(),
            record: provenance.tenant.clone(),
        });
    }
    if reservation.state() != ReservationState::Granted {
        return refuse(ReservationProblem::NotGranted {
            state: reservation.state(),
        });
    }
    let shortfall = demand.excess_over(reservation.current());
    if !shortfall.is_empty() {
        return refuse(ReservationProblem::Insufficient { shortfall });
    }
    Ok(())
}

fn api_plan(profile: &FirecrackerProfile) -> ApiPlan {
    let mut requests = vec![
        ApiRequest::Logger {
            log_path: layout::path(layout::LOG_SINK),
        },
        ApiRequest::Metrics {
            metrics_path: layout::path(layout::METRICS_SINK),
        },
        ApiRequest::MachineConfig {
            vcpu_count: profile.machine.vcpu_count,
            mem_size_mib: profile.machine.guest_memory_mib,
        },
        ApiRequest::BootSource {
            kernel_image_path: layout::path(layout::KERNEL_IMAGE),
        },
        ApiRequest::RootDrive {
            path_on_host: layout::path(layout::ROOT_IMAGE),
        },
    ];
    for interface in &profile.network_interfaces {
        requests.push(ApiRequest::NetworkInterface {
            iface_id: interface.iface_id.clone(),
            host_dev_name: interface.host_device.clone(),
            guest_mac: interface.guest_mac,
        });
    }
    requests.push(ApiRequest::Vsock {
        uds_path: layout::path(layout::LINK_SOCKET),
    });
    if profile.entropy_device {
        requests.push(ApiRequest::Entropy);
    }
    requests.push(ApiRequest::InstanceStart);
    ApiPlan::new(requests)
}

/// The plan of one Firecracker launch. Serialize only: a plan is always built, never
/// read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchPlan {
    backend: BackendIdentity,
    firecracker_version: ComponentVersion,
    profile: Digest,
    jail_id: JailId,
    api: ApiPlan,
    jailer: JailerPlan,
    launcher: LauncherPlan,
    expected: ExpectedLinuxState,
    host_demand: Amounts,
}

impl LaunchPlan {
    /// Builds the plan, or the first refusal in this order: profile, host settings and
    /// jail identity, pinned row, the request's configuration against the row's
    /// fingerprint, the request against the row and profile, device models of the row,
    /// reservation.
    pub fn build(inputs: &PlanInputs<'_>) -> Result<Self, PlanRefusal> {
        let PlanInputs {
            request,
            profile,
            configuration,
            host,
            identity,
            reservation,
        } = *inputs;
        profile
            .validate()
            .map_err(|error| PlanRefusal::Profile { error })?;
        host.validate()
            .and_then(|()| host.check_identity(identity))
            .map_err(|error| PlanRefusal::Host { error })?;
        let pins = check_configuration(configuration)?;
        let version = &pins.runtime.version;
        let backend = backend_of(&pins)?;
        let pinned =
            configuration
                .fingerprint()
                .map_err(|error| PlanRefusal::FingerprintUnavailable {
                    detail: error.to_string(),
                })?;
        if request.configuration != pinned {
            return Err(PlanRefusal::ConfigurationMismatch {
                requested: request.configuration,
                pinned,
            });
        }
        check_request(request, profile, &pins)?;
        check_device_models(configuration, profile)?;
        let memory_max_bytes = profile
            .memory_max_bytes()
            .map_err(|error| PlanRefusal::Profile { error })?;
        let host_demand = Amounts::new()
            .host_ram_bytes(memory_max_bytes)
            .network_slots(profile.network_interfaces.len() as u64);
        check_reservation(request, reservation, &host_demand)?;

        let jail_id = JailId::derive(
            &request.execution,
            &request.tenant,
            &request.machine,
            &request.generations,
        );
        let limits = profile.limits;
        let jailer = JailerPlan::new(JailerParts {
            jailer: host.jailer.clone(),
            id: jail_id.clone(),
            exec_file: host.firecracker.clone(),
            identity,
            chroot_base: host.chroot_base.clone(),
            netns: host.netns_dir.join(jail_id.as_str())?,
            parent_cgroup: host.cgroup_parent.clone(),
            cgroup_limits: vec![
                CgroupLimit {
                    file: CgroupFile::CpuMax,
                    value: format!("{} {}", limits.cpu.quota_micros, limits.cpu.period_micros),
                },
                CgroupLimit {
                    file: CgroupFile::MemoryMax,
                    value: memory_max_bytes.to_string(),
                },
                CgroupLimit {
                    file: CgroupFile::PidsMax,
                    value: limits.max_tasks.to_string(),
                },
            ],
            resource_limits: vec![
                ResourceLimit::FileSize {
                    max_bytes: limits.max_file_bytes,
                },
                ResourceLimit::OpenFiles {
                    max_count: limits.max_open_descriptors,
                },
            ],
        });
        let cgroup = jailer.cgroup()?;
        let staged = |pin: &ComponentPin| -> Result<StagedArtifact, NameError> {
            Ok(StagedArtifact {
                source: host.artifact_dir.join(&pin.content_key.to_string())?,
                content_key: pin.content_key,
                length_bytes: pin.length_bytes,
            })
        };
        let taps: Vec<InterfaceName> = profile
            .network_interfaces
            .iter()
            .map(|interface| interface.host_device.clone())
            .collect();
        let launcher = LauncherPlan::new(LauncherInputs {
            netns: jailer.netns().clone(),
            taps: taps.clone(),
            identity,
            owner: host.owner,
            jail_dir: jailer.jail_dir()?,
            chroot_dir: jailer.chroot_dir()?,
            kernel: staged(pins.kernel)?,
            root_image: staged(pins.image)?,
            argv: jailer.argv(),
            jailer_content_key: pins.jailer.content_key,
            exec_content_key: pins.runtime.content_key,
            cgroup: host.cgroup_root.join_relative(&cgroup)?,
        })?;
        let mut interfaces: BTreeSet<InterfaceName> = taps.into_iter().collect();
        interfaces.insert(InterfaceName::loopback());
        let expected = ExpectedLinuxState {
            identity,
            network_interfaces: interfaces,
            cgroup,
            cgroup_limits: jailer.cgroup_limits().to_vec(),
            max_open_descriptors: limits.max_open_descriptors,
        };
        Ok(Self {
            backend,
            firecracker_version: version.clone(),
            profile: profile.identity(),
            jail_id,
            api: api_plan(profile),
            jailer,
            launcher,
            expected,
            host_demand,
        })
    }

    /// The backend identity a launch record names: Firecracker at the pinned version and
    /// artifact, on KVM.
    pub fn backend(&self) -> &BackendIdentity {
        &self.backend
    }

    /// The pinned Firecracker version, which the golden file binds.
    pub fn firecracker_version(&self) -> &ComponentVersion {
        &self.firecracker_version
    }

    /// The identity of the profile the plan follows.
    pub fn profile(&self) -> Digest {
        self.profile
    }

    pub fn jail_id(&self) -> &JailId {
        &self.jail_id
    }

    pub fn api(&self) -> &ApiPlan {
        &self.api
    }

    pub fn jailer(&self) -> &JailerPlan {
        &self.jailer
    }

    pub fn launcher(&self) -> &LauncherPlan {
        &self.launcher
    }

    /// What VM-CP-04 expects the host to observe.
    pub fn expected_state(&self) -> &ExpectedLinuxState {
        &self.expected
    }

    /// The host capacity the launch's reservation must hold: the cgroup memory limit and
    /// one network slot per declared interface.
    pub fn host_demand(&self) -> &Amounts {
        &self.host_demand
    }
}
