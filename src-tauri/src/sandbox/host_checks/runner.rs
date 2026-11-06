//! The host check runner of VM-CP-31 on Linux (§17, line 3181; VM-W18, line 2617:
//! "complete group/reset evidence; no unsafe interrupts/ACS bypass; unsupported hardware
//! refused"; VM-W09, line 2594; VM-W23, line 2622).
//!
//! [`GpuAssignmentRunner`] is a `sandbox::probes` [`HostCheckRunner`]: the CORE-01
//! adapter `DeviceAssignmentIsolatedProbe` runs it live for one GPU and judges what it
//! returns. It answers only VM-CP-31's own observation part. For a GPU subject on this
//! machine whose device digest it was given a PCI address for, it [`assess`]es the four
//! guards through the sysfs port and reports exactly VM-CP-31's typed observations:
//!
//! - `cp31.incomplete-iommu-group` and `cp31.display-owning-gpu`, attempts: the
//!   expectations are written as a gate's tests ("an incomplete IOMMU group is
//!   refused"); for one GPU, the observation states whether assigning that GPU stays
//!   clear of the hazard. `refused: true` when its facts rule the hazard out,
//!   `refused: false` when they show it, so the expectation fails exactly when this GPU
//!   must not be assigned.
//! - `cp31.reset-capability-checked` and `cp31.acs-state-checked`, presences: present
//!   when the fact was read and is acceptable for assignment, absent when it was read and
//!   is not.
//! - The positive control `cp31.qualifying-device-assigns`: a qualifying device's facts
//!   were read in the same run and every guard was clear: the subject itself, or else the
//!   reference GPU the runner was given (the dedicated test GPU of VM-W18). It succeeds
//!   when one qualified; it is refused when the subject did not and the reference was
//!   read and did not either; it is not observed when the subject did not qualify and no
//!   reference was given. The plan's control also assigns the device and runs
//!   `nvidia-smi` in the guest; a read-only runner cannot, and this runner never claims
//!   it did.
//!
//! A guard that is undecided leaves its observation out, so the judge finds it missing
//! and the run is inconclusive, never a pass. A subject this runner cannot place (another
//! kind or machine, a device digest without an address, an address the host does not
//! have, a device that is not a display controller) is unreachable. On any host that is
//! not Linux the runner observes nothing and reads nothing; the probes catalog scopes
//! VM-CP-31 to Linux, so such a host reads the check not tested before any runner is
//! asked.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::address::PciAddress;
use super::assess::{assess, Assessment, Unassessable, Verdict};
use super::reader::SysfsReader;
use crate::foundation::evidence::{ConfigurationFingerprint, OsKind, Subject};
use crate::foundation::ids::Digest;
use crate::sandbox::probes::{
    expectation, CheckId, ExpectationId, HostCheckRunner, Observations, Observed, Part, Role,
    RunResult, RunnerInconclusive,
};

/// The §17 row this runner answers.
pub const GPU_ASSIGNMENT_CHECK_NUMBER: u8 = 31;

/// The most GPUs one runner may be given.
pub const MAX_GPUS: usize = 64;

/// VM-CP-31's expectations, by name: the four observations and the positive control.
pub const INCOMPLETE_GROUP: &str = "cp31.incomplete-iommu-group";
pub const DISPLAY_OWNING: &str = "cp31.display-owning-gpu";
pub const RESET_CHECKED: &str = "cp31.reset-capability-checked";
pub const ACS_CHECKED: &str = "cp31.acs-state-checked";
pub const QUALIFYING_ASSIGNS: &str = "cp31.qualifying-device-assigns";

/// What a runner is given.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RunnerSettings {
    /// The host's operating system; only Linux is observed.
    pub os: OsKind,
    /// The digest of this machine, as GPU subjects name it.
    pub machine: Digest,
    /// The configuration the observations depend on, such as the kernel and driver
    /// bindings in force.
    pub configuration: ConfigurationFingerprint,
    /// How long an observation stays fresh.
    pub fresh_for: Duration,
    /// The PCI address of each GPU, by the device digest its subjects carry.
    pub gpus: BTreeMap<Digest, PciAddress>,
    /// A GPU known to qualify, read in each run as the positive control when the subject
    /// does not qualify.
    pub reference: Option<PciAddress>,
}

/// Why settings were refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "settings", rename_all = "snake_case")]
pub enum SettingsError {
    /// Observations that are never fresh.
    ZeroFreshness,
    /// More GPUs than [`MAX_GPUS`].
    TooManyGpus,
    /// Two device digests name one address.
    RepeatedAddress { address: PciAddress },
    /// The probes catalog has no VM-CP-31, or lacks one of its expectations here.
    UnknownExpectation { name: &'static str },
}

impl fmt::Display for SettingsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroFreshness => f.write_str("observations must stay fresh for some time"),
            Self::TooManyGpus => write!(f, "more than {MAX_GPUS} GPUs were given"),
            Self::RepeatedAddress { address } => {
                write!(f, "two device digests name the PCI address {address}")
            }
            Self::UnknownExpectation { name } => {
                write!(f, "the probes catalog has no VM-CP-31 expectation {name}")
            }
        }
    }
}

impl std::error::Error for SettingsError {}

/// VM-CP-31 and the expectations this runner reports, looked up once.
#[derive(Clone, Copy, Debug)]
struct Cp31 {
    check: CheckId,
    group: ExpectationId,
    display: ExpectationId,
    reset: ExpectationId,
    acs: ExpectationId,
    control: ExpectationId,
}

impl Cp31 {
    fn resolve() -> Result<Self, SettingsError> {
        let check =
            CheckId::new(GPU_ASSIGNMENT_CHECK_NUMBER).ok_or(SettingsError::UnknownExpectation {
                name: INCOMPLETE_GROUP,
            })?;
        let id = |name: &'static str, role: Role| {
            ExpectationId::named(name)
                .filter(|id| {
                    expectation(*id).is_some_and(|entry| {
                        entry.check == check && entry.part == Part::Primary && entry.role == role
                    })
                })
                .ok_or(SettingsError::UnknownExpectation { name })
        };
        Ok(Self {
            check,
            group: id(INCOMPLETE_GROUP, Role::Observation)?,
            display: id(DISPLAY_OWNING, Role::Observation)?,
            reset: id(RESET_CHECKED, Role::Observation)?,
            acs: id(ACS_CHECKED, Role::Observation)?,
            control: id(QUALIFYING_ASSIGNS, Role::PositiveControl)?,
        })
    }
}

/// VM-CP-31's host part on Linux, read from sysfs through `R`.
pub struct GpuAssignmentRunner<R> {
    reader: R,
    settings: RunnerSettings,
    cp31: Cp31,
}

impl<R: SysfsReader> GpuAssignmentRunner<R> {
    pub fn new(reader: R, settings: RunnerSettings) -> Result<Self, SettingsError> {
        if settings.fresh_for.is_zero() {
            return Err(SettingsError::ZeroFreshness);
        }
        if settings.gpus.len() > MAX_GPUS {
            return Err(SettingsError::TooManyGpus);
        }
        let mut seen = std::collections::BTreeSet::new();
        for address in settings.gpus.values() {
            if !seen.insert(*address) {
                return Err(SettingsError::RepeatedAddress { address: *address });
            }
        }
        Ok(Self {
            reader,
            settings,
            cp31: Cp31::resolve()?,
        })
    }

    pub fn settings(&self) -> &RunnerSettings {
        &self.settings
    }

    /// The four guards of the GPU at `device`, read now; for a doctor that explains a
    /// refusal. On a host that is not Linux nothing is read.
    pub fn assess(&self, device: PciAddress) -> Option<Result<Assessment, Unassessable>> {
        (self.settings.os == OsKind::Linux).then(|| assess(&self.reader, device))
    }

    /// The PCI address of a GPU subject of this machine.
    pub fn address_of(&self, subject: &Subject) -> Option<PciAddress> {
        match subject {
            Subject::GpuDevice(gpu) if gpu.machine == self.settings.machine => {
                self.settings.gpus.get(&gpu.device).copied()
            }
            _ => None,
        }
    }

    /// VM-CP-31's observations for the assessed subject.
    fn observations(&self, subject: &Assessment) -> Observations {
        let mut observations = Observations::new();
        let attempts = [
            (self.cp31.group, &subject.group),
            (self.cp31.display, &subject.display),
        ];
        for (id, verdict) in attempts {
            if let Some(refused) = rules_out(verdict) {
                observations.insert(id, Observed::Attempt { refused });
            }
        }
        let presences = [
            (self.cp31.reset, &subject.reset),
            (self.cp31.acs, &subject.acs),
        ];
        for (id, verdict) in presences {
            if let Some(present) = rules_out(verdict) {
                observations.insert(id, Observed::Presence { present });
            }
        }
        if let Some(refused) = self.control_refused(subject) {
            observations.insert(self.cp31.control, Observed::Attempt { refused });
        }
        observations
    }

    /// The positive control: `Some(false)` when a qualifying device's facts were read in
    /// this run, `Some(true)` when the subject and the reference were read and neither
    /// qualified, `None` when the subject did not qualify and there is no reference.
    fn control_refused(&self, subject: &Assessment) -> Option<bool> {
        if subject.qualifies() {
            return Some(false);
        }
        let reference = self.settings.reference?;
        let qualified = assess(&self.reader, reference).is_ok_and(|found| found.qualifies());
        Some(!qualified)
    }
}

/// Whether a guard's facts rule its hazard out: `Some(true)` when clear, `Some(false)`
/// when the hazard is shown, `None` when undecided.
const fn rules_out(verdict: &Verdict) -> Option<bool> {
    match verdict {
        Verdict::Clear => Some(true),
        Verdict::Hazard { .. } => Some(false),
        Verdict::Undecided { .. } => None,
    }
}

impl<R: SysfsReader> HostCheckRunner for GpuAssignmentRunner<R> {
    fn configuration(&self) -> ConfigurationFingerprint {
        self.settings.configuration
    }

    fn fresh_for(&self) -> Duration {
        self.settings.fresh_for
    }

    fn os(&self) -> OsKind {
        self.settings.os
    }

    fn run(&self, check: CheckId, part: Part, subject: &Subject) -> RunResult {
        if check != self.cp31.check || part != Part::Primary || self.settings.os != OsKind::Linux {
            return RunResult::Observed {
                observations: Observations::new(),
            };
        }
        let unreachable = RunResult::Inconclusive {
            reason: RunnerInconclusive::Unreachable,
        };
        let Some(device) = self.address_of(subject) else {
            return unreachable;
        };
        match assess(&self.reader, device) {
            Ok(assessment) => RunResult::Observed {
                observations: self.observations(&assessment),
            },
            Err(Unassessable::Absent { .. } | Unassessable::NotAGpu { .. }) => unreachable,
        }
    }
}
