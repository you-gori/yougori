//! The evidence row of one combination (docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! §7.1, lines 2356–2364, "host OS/build + architecture + backend/version + guest image +
//! actual hardware accelerator + confinement profile + device set + network enforcement +
//! lifecycle behavior + test result. Until validated, label it experimental or
//! unavailable"; §8.1, lines 2433–2439).
//!
//! Every §7.1 element is one or more [`Field`]s, each with its own source and freshness.
//! The row's identity is its combination: a digest of every element but the test result,
//! with an unavailable element written as unavailable, so a row of a combination whose
//! accelerator nobody observed is never the row of one whose accelerator is known. The
//! row's [`Label`] is the doctor's ([`LabelBasis`] says when it is not).

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use super::field::{Field, RowField};
use crate::foundation::ids::{ContentKey, Digest};
use crate::sandbox::backend::{
    Accelerator, BackendIdentity, BackendKind, ConfinementControl, DeviceInventory, DeviceProfile,
    HostBuild, NetworkAuthority, ObservationProblem, PerimeterRequirement,
};
use crate::sandbox::doctor::{Candidate, CandidateReport, Label};
use crate::sandbox::guest_image::{ImageName, ReleaseNumber};
use crate::sandbox::probes::{Applicability, CheckId, CheckStatus};
use crate::sandbox::trust::Architecture;
use crate::sandbox_contract::confinement::{VerdictOutcome, WorkloadProfile};

/// The digest domain of a row's combination identity.
pub const COMBINATION_DOMAIN: &str = "yougori/sandbox/evidence-matrix/combination/v1";

/// What every row states about itself.
pub const ROW_NOTICE: &str = "An evidence row states which evidence exists for one combination at one reading; it is an evidence record, not a certificate, and it changes nothing on the host. A field nobody observed is unavailable and never assumed, and a stale fact is shown as not current. A combination is validated only when the doctor validated its backend on this host and every field of the row is known from current evidence; until then it is experimental or unavailable (section 7.1).";

/// The §17 checks whose subject is a lifecycle step: revocation through VM stop and
/// cleanup completion (VM-CP-14), the next generation booting the signed base
/// (VM-CP-17), expiry acted on by the supervisor's own timers (VM-CP-18), cleanup after
/// engine or supervisor death (VM-CP-19) and clones restored from one snapshot
/// (VM-CP-21). This list is this module's reading of §17.
pub const LIFECYCLE_CHECKS: [u8; 5] = [14, 17, 18, 19, 21];

/// How a launch came up (§7.1 line 2364: a successful ordinary boot does not prove a
/// snapshot path works).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchPath {
    /// A launch from the pinned image.
    ColdBoot,
    /// A restore from a snapshot into a fresh generation.
    Restore,
}

/// What the signed manifest of the guest image states about the release.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignedImage {
    pub image: ImageName,
    pub release: ReleaseNumber,
    /// The manifest's identity: the content key of its canonical bytes.
    pub manifest: ContentKey,
    /// The build record the manifest binds.
    pub build_record: ContentKey,
    /// The root image's identity, the value a launch pins.
    pub root_image: Digest,
    pub architecture: Architecture,
}

/// The guest's inner confinement as its V15 verdict states it (VM-CP-05). It is the
/// guest's confinement, kept apart from the hypervisor's (`sandbox_contract::confinement`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuestConfinement {
    pub workload: WorkloadProfile,
    /// The V15 confinement profile's digest.
    pub profile: Digest,
    pub outcome: VerdictOutcome,
}

/// The independent perimeter the launches asked for (§4.4; VM-CP-11) and how many block
/// rules have CORE-01 enforcement evidence bound in the freshest record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PerimeterEnforcement {
    pub requirement: PerimeterRequirement,
    pub evidenced_rules: usize,
}

/// One lifecycle check of the doctor's report.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LifecycleResult {
    pub check: CheckId,
    pub applicability: Applicability,
    pub status: CheckStatus,
}

/// The host: the build the doctor examined and the build the launch records observed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostPart {
    pub examined: Field<HostBuild>,
    pub observed: Field<HostBuild>,
}

/// The backend: the candidate the doctor examined and the build the records ran.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct BackendPart {
    pub candidate: Field<Candidate>,
    pub build: Field<BackendIdentity>,
}

/// The guest image: the signed release, the root image the launches pinned and the one
/// the host observed booted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ImagePart {
    pub manifest: Field<SignedImage>,
    pub pinned: Field<Digest>,
    pub booted: Field<Digest>,
}

/// The confinement profile: the hypervisor process's controls and the guest's inner
/// profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfinementPart {
    pub hypervisor: Field<BTreeSet<ConfinementControl>>,
    pub guest: Field<GuestConfinement>,
}

/// The device set: the approved profile and the inventory the host measured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DevicePart {
    pub profile: Field<DeviceProfile>,
    pub measured: Field<DeviceInventory>,
}

/// The network enforcement: the channels the host enforced and the independent
/// perimeter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NetworkPart {
    pub enforced: Field<NetworkAuthority>,
    pub perimeter: Field<PerimeterEnforcement>,
}

/// The lifecycle behaviour: the launch paths the records exercised and the doctor's
/// lifecycle checks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LifecyclePart {
    pub paths: Field<BTreeSet<LaunchPath>>,
    pub checks: Field<Vec<LifecycleResult>>,
}

/// Why a row's label is what it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum LabelBasis {
    /// The doctor's label, unchanged.
    Doctor,
    /// The doctor's report is not current at the reading, so nothing it found is, and the
    /// combination is unavailable, as the doctor's own judge reads stale evidence.
    ReportNotCurrent { problem: ObservationProblem },
    /// The doctor validated the backend on this host, and these fields are unavailable
    /// or not current, so the combination is not established and stays experimental.
    CombinationNotEstablished {
        unavailable: Vec<RowField>,
        not_current: Vec<RowField>,
    },
}

/// The state of one field, for labels and change reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum State {
    Current,
    NotCurrent,
    Unavailable,
}

fn state<T>(field: &Field<T>) -> State {
    if !field.is_known() {
        State::Unavailable
    } else if field.is_current() {
        State::Current
    } else {
        State::NotCurrent
    }
}

/// The evidence row of one combination. Serialize only: only [`super::assemble()`] builds
/// one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MatrixRow {
    pub(super) notice: &'static str,
    pub(super) combination: Digest,
    pub(super) label: Label,
    pub(super) basis: LabelBasis,
    pub(super) host: HostPart,
    pub(super) backend: BackendPart,
    pub(super) guest_image: ImagePart,
    pub(super) accelerator: Field<Accelerator>,
    pub(super) confinement: ConfinementPart,
    pub(super) devices: DevicePart,
    pub(super) network: NetworkPart,
    pub(super) lifecycle: LifecyclePart,
    pub(super) result: Field<CandidateReport>,
}

impl MatrixRow {
    /// The identity of the combination: every §7.1 element but the test result.
    pub fn combination(&self) -> Digest {
        self.combination
    }

    /// The row's §7.1 label.
    pub fn label(&self) -> Label {
        self.label
    }

    pub fn basis(&self) -> &LabelBasis {
        &self.basis
    }

    /// The host build the doctor examined, which every part of the row agrees with.
    pub fn host_build(&self) -> Option<&HostBuild> {
        self.host.examined.value()
    }

    /// The backend the doctor examined.
    pub fn backend_kind(&self) -> Option<BackendKind> {
        self.backend
            .candidate
            .value()
            .map(|candidate| candidate.backend)
    }

    pub fn host(&self) -> &HostPart {
        &self.host
    }

    pub fn backend(&self) -> &BackendPart {
        &self.backend
    }

    pub fn guest_image(&self) -> &ImagePart {
        &self.guest_image
    }

    pub fn accelerator(&self) -> &Field<Accelerator> {
        &self.accelerator
    }

    pub fn confinement(&self) -> &ConfinementPart {
        &self.confinement
    }

    pub fn devices(&self) -> &DevicePart {
        &self.devices
    }

    pub fn network(&self) -> &NetworkPart {
        &self.network
    }

    pub fn lifecycle(&self) -> &LifecyclePart {
        &self.lifecycle
    }

    /// The doctor's examination of the backend: its label, counts, blocking checks,
    /// results read from launch records and boundary report.
    pub fn result(&self) -> &Field<CandidateReport> {
        &self.result
    }

    /// The fields nobody observed, in row order.
    pub fn unavailable_fields(&self) -> Vec<RowField> {
        self.fields_in(State::Unavailable)
    }

    /// The fields known from evidence that is not current at the reading, in row order.
    pub fn not_current_fields(&self) -> Vec<RowField> {
        self.fields_in(State::NotCurrent)
    }

    fn fields_in(&self, wanted: State) -> Vec<RowField> {
        RowField::ALL
            .into_iter()
            .filter(|field| self.state(*field) == wanted)
            .collect()
    }

    pub(super) fn state(&self, field: RowField) -> State {
        match field {
            RowField::HostExamined => state(&self.host.examined),
            RowField::HostObserved => state(&self.host.observed),
            RowField::BackendCandidate => state(&self.backend.candidate),
            RowField::BackendBuild => state(&self.backend.build),
            RowField::ImageManifest => state(&self.guest_image.manifest),
            RowField::ImagePinned => state(&self.guest_image.pinned),
            RowField::ImageBooted => state(&self.guest_image.booted),
            RowField::Accelerator => state(&self.accelerator),
            RowField::HypervisorConfinement => state(&self.confinement.hypervisor),
            RowField::GuestConfinement => state(&self.confinement.guest),
            RowField::DeviceProfile => state(&self.devices.profile),
            RowField::DeviceInventory => state(&self.devices.measured),
            RowField::NetworkEnforcement => state(&self.network.enforced),
            RowField::Perimeter => state(&self.network.perimeter),
            RowField::LifecyclePaths => state(&self.lifecycle.paths),
            RowField::LifecycleChecks => state(&self.lifecycle.checks),
            RowField::TestResult => state(&self.result),
        }
    }

    /// Whether `field` states the same value, source and freshness in both rows.
    pub(super) fn same(&self, other: &Self, field: RowField) -> bool {
        match field {
            RowField::HostExamined => self.host.examined == other.host.examined,
            RowField::HostObserved => self.host.observed == other.host.observed,
            RowField::BackendCandidate => self.backend.candidate == other.backend.candidate,
            RowField::BackendBuild => self.backend.build == other.backend.build,
            RowField::ImageManifest => self.guest_image.manifest == other.guest_image.manifest,
            RowField::ImagePinned => self.guest_image.pinned == other.guest_image.pinned,
            RowField::ImageBooted => self.guest_image.booted == other.guest_image.booted,
            RowField::Accelerator => self.accelerator == other.accelerator,
            RowField::HypervisorConfinement => {
                self.confinement.hypervisor == other.confinement.hypervisor
            }
            RowField::GuestConfinement => self.confinement.guest == other.confinement.guest,
            RowField::DeviceProfile => self.devices.profile == other.devices.profile,
            RowField::DeviceInventory => self.devices.measured == other.devices.measured,
            RowField::NetworkEnforcement => self.network.enforced == other.network.enforced,
            RowField::Perimeter => self.network.perimeter == other.network.perimeter,
            RowField::LifecyclePaths => self.lifecycle.paths == other.lifecycle.paths,
            RowField::LifecycleChecks => self.lifecycle.checks == other.lifecycle.checks,
            RowField::TestResult => self.result == other.result,
        }
    }
}

/// The row's label from the doctor's label and the state of every field: the doctor's,
/// except that a report not current at the reading leaves the combination unavailable,
/// and a validated backend whose combination is not fully known from current evidence
/// is experimental.
pub(super) fn label_of(
    doctor: Label,
    report_problem: Option<ObservationProblem>,
    states: &[(RowField, State)],
) -> (Label, LabelBasis) {
    if let Some(problem) = report_problem {
        return (Label::Unavailable, LabelBasis::ReportNotCurrent { problem });
    }
    if doctor != Label::Validated {
        return (doctor, LabelBasis::Doctor);
    }
    let pick = |wanted: State| -> Vec<RowField> {
        states
            .iter()
            .filter(|(_, state)| *state == wanted)
            .map(|(field, _)| *field)
            .collect()
    };
    let (unavailable, not_current) = (pick(State::Unavailable), pick(State::NotCurrent));
    if unavailable.is_empty() && not_current.is_empty() {
        (Label::Validated, LabelBasis::Doctor)
    } else {
        (
            Label::Experimental,
            LabelBasis::CombinationNotEstablished {
                unavailable,
                not_current,
            },
        )
    }
}

impl fmt::Display for LaunchPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ColdBoot => "cold boot",
            Self::Restore => "restore from a snapshot",
        })
    }
}
