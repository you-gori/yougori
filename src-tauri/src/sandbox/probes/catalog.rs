//! The §17 controlled checks as data (plan lines 3145–3188): one [`ControlledCheck`] per
//! VM-CP row, with the VM-P families it serves (§12.2, lines 2770–2828), its side and
//! source, its positive control or the plan's note where it has none, and the profiles
//! that refuse to start on a failure ("must for"). The expected observations of each
//! check are its rows in the expectation table ([`super::expect`]).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Serialize, Serializer};

use super::expect::{expectation, Expectation, ExpectationId, Role};
use crate::foundation::evidence::{OsKind, SourceClass};
use crate::sandbox::backend::Facet;

/// One §17 check, `VM-CP-01` to `VM-CP-35` (lines 3151–3185). Every identifier names a
/// row: [`CheckId::new`] refuses any other number.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CheckId(u8);

impl CheckId {
    /// The first and last row of the §17 table.
    pub const FIRST: u8 = 1;
    pub const LAST: u8 = 35;

    /// The check numbered `number`, if the table has one.
    pub const fn new(number: u8) -> Option<Self> {
        if number >= Self::FIRST && number <= Self::LAST {
            Some(Self(number))
        } else {
            None
        }
    }

    /// A number written into this module's own tables; the catalog test checks every one
    /// is a row.
    pub(super) const fn of(number: u8) -> Self {
        Self(number)
    }

    pub const fn number(self) -> u8 {
        self.0
    }

    /// Every check, in table order.
    pub fn all() -> impl Iterator<Item = Self> {
        (Self::FIRST..=Self::LAST).map(Self)
    }
}

impl fmt::Display for CheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VM-CP-{:02}", self.0)
    }
}

impl fmt::Debug for CheckId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for CheckId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// A §12.2 scenario family, `VM-P01` to `VM-P50` (lines 2776–2825).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScenarioFamily(u8);

impl ScenarioFamily {
    pub const FIRST: u8 = 1;
    pub const LAST: u8 = 50;

    pub const fn new(number: u8) -> Option<Self> {
        if number >= Self::FIRST && number <= Self::LAST {
            Some(Self(number))
        } else {
            None
        }
    }

    pub const fn number(self) -> u8 {
        self.0
    }
}

impl fmt::Display for ScenarioFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VM-P{:02}", self.0)
    }
}

impl fmt::Debug for ScenarioFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl Serialize for ScenarioFamily {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// The host fact that corroborates a guest-reported check (§17 lines 3155, 3159 and
/// 2996). A guest-reported check is satisfied only with each of its facts observed by the
/// host (§8.1 line 2437: separate host-observed facts from guest assertions).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CorroboratingFact {
    /// VM-CP-05: the booted root image digest matches the signed manifest.
    BootedRootImage,
    /// VM-CP-05: the kernel build record (`CONFIG_IO_URING` absent) matches the signed
    /// manifest.
    KernelBuildRecord,
    /// VM-CP-09: the host observes no packet from the VM because no network device exists.
    NoGuestNetworkDevice,
    /// VM-CP-21: the two clones have distinct generation and boot ids, which the host
    /// assigns.
    CloneIdentities,
    /// VM-CP-21: an approval issued before the snapshot is refused in both clones, which
    /// the host's executor decides.
    PreSnapshotApprovalRefused,
}

impl fmt::Display for CorroboratingFact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::BootedRootImage => "the booted root image digest matching the signed manifest",
            Self::KernelBuildRecord => {
                "the kernel build record (CONFIG_IO_URING absent) matching the signed manifest"
            }
            Self::NoGuestNetworkDevice => "no packet from the VM, because it has no network device",
            Self::CloneIdentities => "distinct generation and boot ids of the two clones",
            Self::PreSnapshotApprovalRefused => {
                "a pre-snapshot approval refused in both clones by the host's executor"
            }
        })
    }
}

/// Which part of a check an outcome reports: the check's own observation, or one of the
/// host facts that corroborate a guest-reported check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "part", rename_all = "snake_case")]
pub enum Part {
    Primary,
    Corroboration { fact: CorroboratingFact },
}

impl fmt::Display for Part {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Primary => f.write_str("the check's own observation"),
            Self::Corroboration { fact } => write!(f, "the host corroboration ({fact})"),
        }
    }
}

/// Where an observation came from, as §17 distinguishes them (line 3147).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// The host observed it itself: host configuration or process state (§8.1 line 2437).
    Host,
    /// The guest reported it over the link: never sufficient alone (§17 line 3147).
    Guest,
    /// A controlled external observation: a listener or endpoint the test controls.
    ControlledExternal,
}

impl SourceKind {
    /// The CORE-01 source class of an observation of this kind. A controlled external
    /// observation is the host's own (§8.1 line 2437: host configuration, process state
    /// and controlled external observations carry boundary claims).
    pub const fn source_class(self) -> SourceClass {
        match self {
            Self::Host | Self::ControlledExternal => SourceClass::HostProbe,
            Self::Guest => SourceClass::GuestReport,
        }
    }

    /// Whether an observation of this kind may stand where `required` is asked for. A
    /// host-grade observation may stand for a guest report, the stronger source; nothing
    /// stands for a host observation except a host-grade one, and a controlled external
    /// check needs exactly that, since its positive control is what makes it conclusive.
    pub const fn may_stand_for(self, required: SourceKind) -> bool {
        match required {
            Self::Guest => true,
            Self::Host => matches!(self, Self::Host | Self::ControlledExternal),
            Self::ControlledExternal => matches!(self, Self::ControlledExternal),
        }
    }
}

impl fmt::Display for SourceKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Host => "host observation",
            Self::Guest => "guest report",
            Self::ControlledExternal => "controlled external observation",
        })
    }
}

/// A check's side and source (§17 "Side and source" column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "side", rename_all = "snake_case")]
pub enum Side {
    /// "host-observed".
    HostObserved,
    /// "host-observed with stated coverage" (VM-CP-12): the result states that it covers
    /// only the scanned locations.
    HostObservedWithStatedCoverage,
    /// "host-observed on GPU hardware" (VM-CP-31).
    HostObservedOnGpuHardware,
    /// "guest-reported plus host corroboration" (VM-CP-05), "guest-reported plus
    /// host-observed" (VM-CP-09) and "host-observed plus guest-reported" (VM-CP-21): the
    /// guest's report counts only with each named host fact.
    GuestReportedWithHostCorroboration {
        corroboration: &'static [CorroboratingFact],
    },
    /// "controlled external" (VM-CP-06).
    ControlledExternal,
    /// "remote and host" (VM-CP-32): the host's verifier observes the remote lease and the
    /// attestation fixtures; the remote side's own statement is never the source.
    RemoteAndHost,
    /// "research tier" (VM-CP-34), recorded by the host harness that ran it.
    ResearchTier,
    /// "end to end" (VM-CP-24), on the authorized disposable environment (§12.1 Tier 2).
    EndToEnd,
}

impl Side {
    /// The source a check's own observation must come from.
    pub const fn primary_source(self) -> SourceKind {
        match self {
            Self::GuestReportedWithHostCorroboration { .. } => SourceKind::Guest,
            Self::ControlledExternal => SourceKind::ControlledExternal,
            Self::HostObserved
            | Self::HostObservedWithStatedCoverage
            | Self::HostObservedOnGpuHardware
            | Self::RemoteAndHost
            | Self::ResearchTier
            | Self::EndToEnd => SourceKind::Host,
        }
    }

    /// The source `part` must come from; `None` for a corroboration the side does not
    /// name.
    pub fn required_source(self, part: Part) -> Option<SourceKind> {
        match part {
            Part::Primary => Some(self.primary_source()),
            Part::Corroboration { fact } => self
                .corroboration()
                .contains(&fact)
                .then_some(SourceKind::Host),
        }
    }

    /// The host facts a guest-reported check needs; empty for every other side.
    pub const fn corroboration(self) -> &'static [CorroboratingFact] {
        match self {
            Self::GuestReportedWithHostCorroboration { corroboration } => corroboration,
            _ => &[],
        }
    }

    /// Whether only a host-grade observation (host or controlled external) can satisfy
    /// the check's own observation.
    pub const fn is_host_only(self) -> bool {
        !matches!(self, Self::GuestReportedWithHostCorroboration { .. })
    }
}

/// A profile that refuses to start when a check fails (§17 "Must for" column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunProfile {
    Strict,
    Transport,
    Pool,
    GpuVm,
    Remote,
    Confidential,
    /// A revocation and recovery drill (VM-CP-14).
    Drill,
    Release,
    Research,
}

impl RunProfile {
    pub const ALL: [Self; 9] = [
        Self::Strict,
        Self::Transport,
        Self::Pool,
        Self::GpuVm,
        Self::Remote,
        Self::Confidential,
        Self::Drill,
        Self::Release,
        Self::Research,
    ];
}

impl fmt::Display for RunProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Strict => "strict",
            Self::Transport => "transport",
            Self::Pool => "pool",
            Self::GpuVm => "GPU VM",
            Self::Remote => "remote",
            Self::Confidential => "confidential",
            Self::Drill => "drill",
            Self::Release => "release",
            Self::Research => "research",
        })
    }
}

/// Which launches refuse to start on a failure of a check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "must_for", content = "profiles", rename_all = "snake_case")]
pub enum MustFor {
    /// "every VM sandbox".
    EveryVmSandbox,
    /// Each of these profiles.
    Profiles(&'static [RunProfile]),
}

impl MustFor {
    /// Whether a launch under `profiles` refuses to start when the check fails.
    pub fn applies_to(self, profiles: &BTreeSet<RunProfile>) -> bool {
        match self {
            Self::EveryVmSandbox => true,
            Self::Profiles(listed) => listed.iter().any(|profile| profiles.contains(profile)),
        }
    }
}

/// A remark of the "Positive control and notes" column that is not a positive control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PlanNote {
    /// VM-CP-02: "the golden file is versioned with the backend".
    GoldenFileVersionedWithBackend,
    /// VM-CP-14: "the engineering target of section 6.5 is reported as a target, not a
    /// guarantee".
    TargetNotGuarantee,
    /// VM-CP-21: "an unsupported reset falls back to cold boot and the record says so".
    UnsupportedResetFallsBackToColdBoot,
}

/// The control that makes a negative result conclusive (§17 line 3147, §4.4), or none.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "control", rename_all = "snake_case")]
pub enum PositiveControl {
    /// This expectation must hold in the same run; if it fails, or was not observed, the
    /// check's result is inconclusive.
    Expectation { id: ExpectationId },
    /// The plan lists no positive control ("—" or only a note).
    NotListed { note: Option<PlanNote> },
}

/// One §17 row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ControlledCheck {
    pub id: CheckId,
    pub families: &'static [ScenarioFamily],
    pub side: Side,
    pub positive_control: PositiveControl,
    pub must_for: MustFor,
    /// Whether the check's substance is per host operating system, so a host without any
    /// expectation of its own cannot run it and reads not tested (VM-CP-04 and VM-CP-33
    /// list per-platform observations; VM-CP-31's device assignment checks are stated for
    /// Linux, §7.5 lines 2398 and 2411).
    pub host_specific: bool,
    /// The §1.3 facets whose required value this check observes directly. Every required
    /// check that does not pass also leaves the evidence facet ("test results and
    /// freshness", line 1906) unsatisfied. The plan gives no such map; this is the
    /// module's reading.
    pub facets: &'static [Facet],
}

impl ControlledCheck {
    /// Every expectation of the check, in table order.
    pub fn expectations(&self) -> impl Iterator<Item = &'static Expectation> + '_ {
        super::expect::expectations()
            .iter()
            .filter(move |entry| entry.check == self.id)
    }

    /// The observations (not the positive control) of `part` that apply on `os`.
    pub fn observations_for(
        &self,
        part: Part,
        os: OsKind,
    ) -> impl Iterator<Item = &'static Expectation> + '_ {
        self.expectations().filter(move |entry| {
            entry.part == part && entry.role == Role::Observation && entry.scope.applies(os)
        })
    }

    /// The positive control's expectation, if the check has one.
    pub fn control(&self) -> Option<&'static Expectation> {
        match self.positive_control {
            PositiveControl::Expectation { id } => expectation(id),
            PositiveControl::NotListed { .. } => None,
        }
    }

    /// Whether a launch under `profiles` refuses to start when this check fails.
    pub fn required_for(&self, profiles: &BTreeSet<RunProfile>) -> bool {
        self.must_for.applies_to(profiles)
    }

    /// The parts an evaluation needs: the check's own observation and one host
    /// corroboration per named fact.
    pub fn parts(&self) -> Vec<Part> {
        std::iter::once(Part::Primary)
            .chain(
                self.side
                    .corroboration()
                    .iter()
                    .map(|fact| Part::Corroboration { fact: *fact }),
            )
            .collect()
    }

    /// Whether the check can run on a host of `os`: a host-specific check needs at least
    /// one observation scoped to that operating system.
    pub fn runs_on(&self, os: OsKind) -> bool {
        !self.host_specific
            || self
                .expectations()
                .any(|entry| entry.scope == super::expect::HostScope::Only(os))
    }
}

const fn families<const N: usize>(numbers: [u8; N]) -> [ScenarioFamily; N] {
    let mut out = [ScenarioFamily(0); N];
    let mut index = 0;
    while index < N {
        out[index] = ScenarioFamily(numbers[index]);
        index += 1;
    }
    out
}

const F01: [ScenarioFamily; 2] = families([1, 42]);
const F02: [ScenarioFamily; 1] = families([2]);
const F03: [ScenarioFamily; 1] = families([3]);
const F04: [ScenarioFamily; 1] = families([4]);
const F05: [ScenarioFamily; 1] = families([5]);
const F06: [ScenarioFamily; 1] = families([6]);
const F07: [ScenarioFamily; 1] = families([7]);
const F08: [ScenarioFamily; 1] = families([8]);
const F09: [ScenarioFamily; 1] = families([9]);
const F10: [ScenarioFamily; 1] = families([10]);
const F11: [ScenarioFamily; 3] = families([11, 26, 27]);
const F12: [ScenarioFamily; 1] = families([12]);
const F13: [ScenarioFamily; 1] = families([13]);
const F14: [ScenarioFamily; 2] = families([14, 24]);
const F15: [ScenarioFamily; 1] = families([15]);
const F16: [ScenarioFamily; 1] = families([16]);
const F17: [ScenarioFamily; 1] = families([17]);
const F18: [ScenarioFamily; 1] = families([18]);
const F19: [ScenarioFamily; 2] = families([19, 49]);
const F20: [ScenarioFamily; 2] = families([20, 32]);
const F21: [ScenarioFamily; 2] = families([21, 43]);
const F22: [ScenarioFamily; 1] = families([22]);
const F23: [ScenarioFamily; 2] = families([23, 48]);
const F24: [ScenarioFamily; 2] = families([25, 46]);
const F25: [ScenarioFamily; 2] = families([28, 29]);
const F26: [ScenarioFamily; 2] = families([30, 31]);
const F27: [ScenarioFamily; 1] = families([33]);
const F28: [ScenarioFamily; 2] = families([34, 35]);
const F29: [ScenarioFamily; 1] = families([36]);
const F30: [ScenarioFamily; 2] = families([37, 38]);
const F31: [ScenarioFamily; 1] = families([39]);
const F32: [ScenarioFamily; 2] = families([40, 41]);
const F33: [ScenarioFamily; 1] = families([42]);
const F34: [ScenarioFamily; 2] = families([44, 45]);
const F35: [ScenarioFamily; 2] = families([47, 50]);

const EVERY: MustFor = MustFor::EveryVmSandbox;
const STRICT: MustFor = MustFor::Profiles(&[RunProfile::Strict]);
const HOST: Side = Side::HostObserved;

const fn control(id: &'static str) -> PositiveControl {
    PositiveControl::Expectation {
        id: ExpectationId::of(id),
    }
}

const NO_CONTROL: PositiveControl = PositiveControl::NotListed { note: None };

const fn row(
    number: u8,
    families: &'static [ScenarioFamily],
    side: Side,
    positive_control: PositiveControl,
    must_for: MustFor,
    facets: &'static [Facet],
) -> ControlledCheck {
    ControlledCheck {
        id: CheckId(number),
        families,
        side,
        positive_control,
        must_for,
        host_specific: false,
        facets,
    }
}

const fn host_specific(mut check: ControlledCheck) -> ControlledCheck {
    check.host_specific = true;
    check
}

/// The §17 table, in row order (lines 3151–3185).
static CATALOG: [ControlledCheck; 35] = [
    row(
        1,
        &F01,
        HOST,
        control("cp01.normal-launch-records-accelerator"),
        EVERY,
        &[Facet::Isolation],
    ),
    row(
        2,
        &F02,
        HOST,
        PositiveControl::NotListed {
            note: Some(PlanNote::GoldenFileVersionedWithBackend),
        },
        EVERY,
        &[Facet::DeviceExposure],
    ),
    row(
        3,
        &F03,
        HOST,
        control("cp03.planted-share-device-detected"),
        EVERY,
        &[Facet::DeviceExposure, Facet::HypervisorConfinement],
    ),
    host_specific(row(
        4,
        &F04,
        HOST,
        control("cp04.unjailed-launch-difference-reported"),
        STRICT,
        &[Facet::HypervisorConfinement],
    )),
    row(
        5,
        &F05,
        Side::GuestReportedWithHostCorroboration {
            corroboration: &[
                CorroboratingFact::BootedRootImage,
                CorroboratingFact::KernelBuildRecord,
            ],
        },
        control("cp05.io-uring-image-fails-kernel-check"),
        STRICT,
        &[],
    ),
    row(
        6,
        &F06,
        Side::ControlledExternal,
        control("cp06.forbidden-listener-reachable-unconfined"),
        EVERY,
        &[Facet::NetworkAuthority],
    ),
    row(
        7,
        &F07,
        HOST,
        control("cp07.public-answer-connects"),
        MustFor::Profiles(&[RunProfile::Strict, RunProfile::Transport]),
        &[Facet::NetworkAuthority],
    ),
    row(
        8,
        &F08,
        HOST,
        control("cp08.public-test-address-passes"),
        EVERY,
        &[Facet::NetworkAuthority],
    ),
    row(
        9,
        &F09,
        Side::GuestReportedWithHostCorroboration {
            corroboration: &[CorroboratingFact::NoGuestNetworkDevice],
        },
        control("cp09.approved-route-succeeds"),
        STRICT,
        &[Facet::NetworkAuthority],
    ),
    row(
        10,
        &F10,
        HOST,
        control("cp10.well-formed-request-succeeds"),
        STRICT,
        &[Facet::NetworkAuthority],
    ),
    row(
        11,
        &F11,
        HOST,
        control("cp11.broker-reaches-allowed-endpoint"),
        STRICT,
        &[Facet::NetworkAuthority],
    ),
    row(
        12,
        &F12,
        Side::HostObservedWithStatedCoverage,
        NO_CONTROL,
        STRICT,
        &[Facet::CredentialExposure],
    ),
    row(
        13,
        &F13,
        HOST,
        control("cp13.valid-capability-succeeds"),
        EVERY,
        &[Facet::CredentialExposure],
    ),
    row(
        14,
        &F14,
        HOST,
        PositiveControl::NotListed {
            note: Some(PlanNote::TargetNotGuarantee),
        },
        MustFor::Profiles(&[RunProfile::Drill]),
        &[],
    ),
    row(
        15,
        &F15,
        HOST,
        control("cp15.in-root-relative-path-resolves"),
        EVERY,
        &[],
    ),
    row(
        16,
        &F16,
        HOST,
        control("cp16.unmodified-promotion-applies"),
        EVERY,
        &[],
    ),
    row(17, &F17, HOST, NO_CONTROL, EVERY, &[Facet::Persistence]),
    row(18, &F18, HOST, NO_CONTROL, EVERY, &[]),
    row(19, &F19, HOST, NO_CONTROL, EVERY, &[]),
    row(
        20,
        &F20,
        HOST,
        NO_CONTROL,
        STRICT,
        &[Facet::HypervisorConfinement],
    ),
    row(
        21,
        &F21,
        Side::GuestReportedWithHostCorroboration {
            corroboration: &[
                CorroboratingFact::CloneIdentities,
                CorroboratingFact::PreSnapshotApprovalRefused,
            ],
        },
        PositiveControl::NotListed {
            note: Some(PlanNote::UnsupportedResetFallsBackToColdBoot),
        },
        MustFor::Profiles(&[RunProfile::Pool]),
        &[Facet::Persistence],
    ),
    row(22, &F22, HOST, NO_CONTROL, EVERY, &[]),
    row(
        23,
        &F23,
        HOST,
        control("cp23.signed-set-launches"),
        EVERY,
        &[],
    ),
    row(
        24,
        &F24,
        Side::EndToEnd,
        NO_CONTROL,
        MustFor::Profiles(&[RunProfile::Release]),
        &[],
    ),
    row(25, &F25, HOST, NO_CONTROL, EVERY, &[]),
    row(
        26,
        &F26,
        HOST,
        control("cp26.unmodified-effect-dispatches-once"),
        STRICT,
        &[Facet::NetworkAuthority],
    ),
    row(
        27,
        &F27,
        HOST,
        NO_CONTROL,
        STRICT,
        &[Facet::NetworkAuthority],
    ),
    row(
        28,
        &F28,
        HOST,
        NO_CONTROL,
        EVERY,
        &[Facet::CredentialExposure],
    ),
    // The plan lists no positive control for VM-CP-29; its drill brings one (M08): the grant
    // from B to C passes in the same run, so A's refusal to reach C is no broken path.
    row(
        29,
        &F29,
        HOST,
        control("cp29.second-grant-passes"),
        EVERY,
        &[Facet::NetworkAuthority, Facet::Persistence],
    ),
    row(
        30,
        &F30,
        HOST,
        NO_CONTROL,
        MustFor::Profiles(&[RunProfile::Release]),
        &[],
    ),
    host_specific(row(
        31,
        &F31,
        Side::HostObservedOnGpuHardware,
        control("cp31.qualifying-device-assigns"),
        MustFor::Profiles(&[RunProfile::GpuVm]),
        &[Facet::DeviceExposure],
    )),
    row(
        32,
        &F32,
        Side::RemoteAndHost,
        control("cp32.valid-attestation-accepted"),
        MustFor::Profiles(&[RunProfile::Remote, RunProfile::Confidential]),
        &[Facet::OperatorConfidentiality],
    ),
    host_specific(row(33, &F33, HOST, NO_CONTROL, EVERY, &[Facet::Isolation])),
    row(
        34,
        &F34,
        Side::ResearchTier,
        NO_CONTROL,
        MustFor::Profiles(&[RunProfile::Research]),
        &[],
    ),
    row(35, &F35, HOST, NO_CONTROL, EVERY, &[]),
];

/// The §17 table, in row order.
pub fn catalog() -> &'static [ControlledCheck] {
    &CATALOG
}

/// The row of `id`. The table is in row order and `CheckId` is a row number by
/// construction; the catalog test checks both.
pub fn check(id: CheckId) -> &'static ControlledCheck {
    &CATALOG[usize::from(id.0.clamp(CheckId::FIRST, CheckId::LAST) - 1)]
}
