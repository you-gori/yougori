//! What a VM service is built from (module docs in `mod.rs`): its ports and the host's
//! objects ([`VmServiceParts`]) and its settings ([`VmServiceConfig`]).

use std::fmt;
use std::time::Duration;

use crate::foundation::evidence::{
    ClockSession, ConfigurationFingerprint, HypervisorSubject, ProbeRegistry, RuntimeSubject,
};
use crate::foundation::ids::Digest;
use crate::sandbox::backend::{BackendIdentity, DeviceProfile, RequiredProperties};
use crate::sandbox::guest_files::BodyTransfers;
use crate::sandbox::guest_image::SelectedImage;
use crate::sandbox::integration::AuditSink;
use crate::sandbox::lifecycle::SupervisorConfig;
use crate::sandbox::link_transport::{DriverLimits, DriverLimitsError};
use crate::sandbox::qemu::QemuSettings;

use super::ports::VmPorts;

/// The guest image every launch of the service boots, and its configuration row: what
/// `SelectedImage::check_request` requires a launch request to name (the root image by its
/// catalog identity, and the row's configuration fingerprint as the host configuration in
/// force). Signing and selecting the image are outside the service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PinnedImage {
    pub guest_image: Digest,
    pub configuration: ConfigurationFingerprint,
}

impl PinnedImage {
    /// The image and row a verified selection chose.
    pub fn from_selected(selected: &SelectedImage) -> Self {
        Self {
            guest_image: selected.root_image(),
            configuration: selected.fingerprint(),
        }
    }
}

/// The CORE-01 subjects a launch refreshes its evidence for: the host's hardware
/// hypervisor (the backend's precheck needs it fresh and host-probed) and the runtime the
/// launch is admitted as a VM sandbox on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceSubjects {
    pub runtime: RuntimeSubject,
    pub hypervisor: HypervisorSubject,
}

/// How the transport drivers and the waiting calls run.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DriverSettings {
    /// The session pumps' bounded I/O.
    pub limits: DriverLimits,
    /// How long a driver sleeps after a pass that moved nothing: 10 ms.
    pub poll_interval: Duration,
    /// How often, on the host clock, the host is ticked (lease enforcement, revocations,
    /// link timeouts, command deadlines): 1 s.
    pub tick_interval: Duration,
    /// How long a waiting call sleeps before it looks again when nothing woke it: 50 ms.
    pub wait_slice: Duration,
    /// How long, in real time, a stop, a revocation or the shutdown waits for a driver to
    /// end before it leaves the thread detached, and the shutdown for a close frame to be
    /// written: 5 s.
    pub join_bound: Duration,
    /// How long, in real time, a stop waits for the guest to power off after the link's
    /// shutdown request before it revokes the sandbox and stops the VM through its handle:
    /// 5 s. Also the grace the request names to the guest, in whole seconds.
    pub shutdown_grace: Duration,
    /// How often, on the host clock, the host's probe observations of the hypervisor and
    /// the runtime are refreshed on the tick while the service runs, so the supervisor's
    /// readiness re-observation judges current evidence: 20 s, a third of the minute the
    /// launch's required properties allow (an observation older than that makes every
    /// command refused as "readiness unavailable", as the fifth acceptance run of
    /// 30 October 2026 showed 167 s after a launch).
    pub evidence_refresh_interval: Duration,
}

impl Default for DriverSettings {
    fn default() -> Self {
        Self {
            limits: DriverLimits::default(),
            poll_interval: Duration::from_millis(10),
            tick_interval: Duration::from_secs(1),
            wait_slice: Duration::from_millis(50),
            join_bound: Duration::from_secs(5),
            shutdown_grace: Duration::from_secs(5),
            evidence_refresh_interval: Duration::from_secs(20),
        }
    }
}

/// The service's settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VmServiceConfig {
    /// The supervisor's configuration (readiness age, revocation policy, death fallback,
    /// issuer).
    pub supervisor: SupervisorConfig,
    /// The host machine, by the identity digest its host adapter derives (CORE-01).
    pub machine: Digest,
    pub image: PinnedImage,
    /// The digest of the resolved contract the policy layer planned launches under.
    pub contract: Digest,
    pub device_profile: DeviceProfile,
    /// The §1.3 properties every launch requires; its confinement must be what the host's
    /// QEMU platform applies.
    pub required: RequiredProperties,
    pub evidence: EvidenceSubjects,
    pub driver: DriverSettings,
}

/// The ports and the host's objects a service is built from. The service owns them from
/// then on; the ledger handle is the host's one ledger, shared with its other clients.
pub struct VmServiceParts<P: VmPorts> {
    /// The host clock every lease, deadline and timeout is measured on.
    pub clock: P::Clock,
    /// The clock session of this run of the service.
    pub session: ClockSession,
    /// The host's CORE-01 registry, with the probe adapters for the hypervisor and the
    /// runtime category registered.
    pub registry: ProbeRegistry<P::Clock>,
    /// The QEMU build, by its identity; its artifact is the backend every launch pins.
    pub backend: BackendIdentity,
    /// The pinned executable, the observations' freshness and the release's golden file.
    pub qemu: QemuSettings,
    pub host: P::Host,
    pub monitor: P::Monitor,
    pub layout: P::Layout,
    pub ledger: P::Ledger,
    /// The supervisor's audit sink (durable and spooled in production).
    pub sink: AuditSink<P::Segments, P::Spool, P::Anchor, P::Clock>,
    pub connector: P::Connector,
    pub processes: P::Processes,
    /// The host's transfer key and ports, for the file channel each boot opens with no
    /// grant.
    pub transfers: BodyTransfers,
}

/// Why a service could not be built from its settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfigRefusal {
    DriverLimits(DriverLimitsError),
    /// A driver setting that must not be zero is.
    ZeroDuration {
        setting: &'static str,
    },
}

impl fmt::Display for ConfigRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DriverLimits(error) => write!(f, "the driver limits were refused: {error}"),
            Self::ZeroDuration { setting } => write!(f, "the driver's {setting} may not be zero"),
        }
    }
}

impl std::error::Error for ConfigRefusal {}

impl DriverSettings {
    /// Refuses limits the pump would refuse and zero intervals.
    pub(super) fn check(&self) -> Result<(), ConfigRefusal> {
        self.limits
            .validate()
            .map_err(ConfigRefusal::DriverLimits)?;
        for (setting, value) in [
            ("poll interval", self.poll_interval),
            ("tick interval", self.tick_interval),
            ("wait slice", self.wait_slice),
            ("join bound", self.join_bound),
            ("shutdown grace", self.shutdown_grace),
            ("evidence refresh interval", self.evidence_refresh_interval),
        ] {
            if value.is_zero() {
                return Err(ConfigRefusal::ZeroDuration { setting });
            }
        }
        Ok(())
    }
}
