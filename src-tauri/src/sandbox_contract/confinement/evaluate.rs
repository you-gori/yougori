//! The VM-CP-05 evaluator: guest-reported probe results plus host corroboration, judged
//! check by check (VM-CP-05; §17 "guest-reported (never sufficient alone, section 8.1)";
//! §8.1 "Separate host-observed facts from guest assertions"; §3.4 "a configured boot
//! argument is not evidence the kernel enforced it"; VM-W09 "A lying guest cannot satisfy
//! host-only requirements; inconclusive results fail required checks").
//!
//! Inputs. A [`GuestReport`] is the guest's account of its probes inside the inner
//! container; it is always [`SourceClass::GuestReport`], and nothing here turns it into
//! host evidence. A [`HostCorroboration`] holds what the host observed itself: the digest
//! of the root image it booted and the build record bound to the kernel image it booted;
//! only host code constructs one, and it cannot be deserialized. A
//! [`ManifestExpectation`] carries the signed manifest's expected values as data; the
//! caller verified the signature (VM-W05, §8.3).
//!
//! Rules. A forbidden interface passes only when its probe failed with an errno a
//! declared mechanism produces; success or any other errno fails, and a missing result is
//! inconclusive, which fails a required check. The observed bounding capability set must
//! equal the profile's exactly. Host checks are required for the strict profile and for
//! any profile that relies on an absent kernel option or a kernel setting, and they read
//! only host and manifest data: the guest's own claims about its kernel options and root
//! image are kept but never consulted. A kernel setting passes only when the host's build
//! record, agreeing with the manifest, shows it forced at build time; a configured boot
//! argument or a guest claim never counts.
//!
//! A passing verdict is defense-in-depth evidence about inner controls at one time, never
//! a boundary claim ([`VerdictMeaning`]; see [`super::residue`]).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::capability::LinuxCapability;
use super::interfaces::{Errno, Interface, Mechanism};
use super::kernel::{
    KernelBuildRecord, KernelOption, KernelOptionEntry, KernelSetting, OptionState,
};
use super::profile::{ConfinementProfile, ProtectedPath, WorkloadProfile, MAX_PROTECTED_PATHS};
use super::responsibility::ForbiddenInterface;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::Digest;

/// Largest guest report read from JSON. A larger one is refused unread.
pub const MAX_GUEST_REPORT_BYTES: usize = 64 * 1024;

strict_confinement_enum! {
    /// What one probe observed, as the guest reports it (VM-CP-05).
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ProbeOutcome tag "outcome" {
        /// The call succeeded: the interface is available.
        Succeeded,
        /// The call failed with this errno.
        Failed { errno: Errno },
    }
}

/// One interface probe result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterfaceProbe {
    pub interface: Interface,
    pub outcome: ProbeOutcome,
}

/// One protected-path write probe result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathProbe {
    pub path: ProtectedPath,
    pub outcome: ProbeOutcome,
}

/// The capability sets of the probing process, from `/proc/self/status`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedCapabilities {
    /// `CapBnd`: what any process in the container could ever hold.
    pub bounding: Vec<LinuxCapability>,
    /// `CapPrm`.
    pub permitted: Vec<LinuxCapability>,
    /// `CapEff`.
    pub effective: Vec<LinuxCapability>,
}

/// The guest's probe report as it arrives (VM-CP-05 "inside the inner container"). Missing
/// results parse, and evaluate as inconclusive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestProbeDocument {
    /// The digest of the profile the guest says it applied.
    pub profile: Digest,
    #[serde(default)]
    pub interfaces: Vec<InterfaceProbe>,
    #[serde(default)]
    pub protected_paths: Vec<PathProbe>,
    pub capabilities: Option<ObservedCapabilities>,
    pub uid: Option<u32>,
    pub no_new_privs: Option<bool>,
    /// Kernel settings the guest says are active. Never accepted as enforced.
    #[serde(default)]
    pub kernel_settings: Vec<KernelSetting>,
    /// Kernel options the guest says it was built with, such as from
    /// `/proc/config.gz`. Never consulted: the build record is a host-only fact.
    #[serde(default)]
    pub kernel_options: Vec<KernelOptionEntry>,
    /// The root image digest the guest claims. Never consulted: the booted image is a
    /// host-only fact.
    pub root_image: Option<Digest>,
}

/// A list in a guest report, named in refusals.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReportList {
    Interfaces,
    ProtectedPaths,
    BoundingCapabilities,
    PermittedCapabilities,
    EffectiveCapabilities,
    KernelSettings,
    KernelOptions,
}

impl fmt::Display for ReportList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Interfaces => "interface results",
            Self::ProtectedPaths => "protected-path results",
            Self::BoundingCapabilities => "bounding capabilities",
            Self::PermittedCapabilities => "permitted capabilities",
            Self::EffectiveCapabilities => "effective capabilities",
            Self::KernelSettings => "kernel settings",
            Self::KernelOptions => "kernel options",
        })
    }
}

/// Why a guest report was refused. No variant carries guest text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GuestReportRefusal {
    TooLarge {
        bytes: usize,
        max: usize,
    },
    /// Not a well-formed report; only the position is kept, never the guest's text.
    Malformed {
        line: usize,
        column: usize,
    },
    TooMany {
        list: ReportList,
        count: usize,
        max: usize,
    },
    /// Two results for one probe, or one entry twice: ambiguous, so refused.
    Duplicate {
        list: ReportList,
    },
}

impl fmt::Display for GuestReportRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { bytes, max } => {
                write!(f, "the guest report has {bytes} bytes; at most {max}")
            }
            Self::Malformed { line, column } => {
                write!(
                    f,
                    "the guest report is malformed at line {line}, column {column}"
                )
            }
            Self::TooMany { list, count, max } => {
                write!(f, "the guest report has {count} {list}; at most {max}")
            }
            Self::Duplicate { list } => write!(f, "the guest report repeats one of its {list}"),
        }
    }
}

impl std::error::Error for GuestReportRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CapabilitySets {
    bounding: BTreeSet<LinuxCapability>,
    permitted: BTreeSet<LinuxCapability>,
    effective: BTreeSet<LinuxCapability>,
}

/// A received guest report, labelled [`SourceClass::GuestReport`] for good (§8.1: "A
/// hostile guest can report a plausible uname result, hide files or lie about
/// interfaces").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestReport {
    profile: Digest,
    interfaces: BTreeMap<Interface, ProbeOutcome>,
    paths: BTreeMap<ProtectedPath, ProbeOutcome>,
    capabilities: Option<CapabilitySets>,
    uid: Option<u32>,
    no_new_privs: Option<bool>,
    kernel_settings: BTreeSet<KernelSetting>,
    claimed_kernel_options: BTreeMap<KernelOption, OptionState>,
    claimed_root_image: Option<Digest>,
}

impl GuestReport {
    /// Receives a parsed report, refusing duplicates and over-long lists.
    pub fn receive(document: GuestProbeDocument) -> Result<Self, GuestReportRefusal> {
        if document.protected_paths.len() > MAX_PROTECTED_PATHS {
            return Err(GuestReportRefusal::TooMany {
                list: ReportList::ProtectedPaths,
                count: document.protected_paths.len(),
                max: MAX_PROTECTED_PATHS,
            });
        }
        let interfaces = unique_map(
            document
                .interfaces
                .iter()
                .map(|probe| (probe.interface, probe.outcome)),
            ReportList::Interfaces,
        )?;
        let paths = unique_map(
            document
                .protected_paths
                .into_iter()
                .map(|probe| (probe.path, probe.outcome)),
            ReportList::ProtectedPaths,
        )?;
        let capabilities = match document.capabilities {
            Some(observed) => Some(CapabilitySets {
                bounding: unique_set(&observed.bounding, ReportList::BoundingCapabilities)?,
                permitted: unique_set(&observed.permitted, ReportList::PermittedCapabilities)?,
                effective: unique_set(&observed.effective, ReportList::EffectiveCapabilities)?,
            }),
            None => None,
        };
        let kernel_settings = unique_set(&document.kernel_settings, ReportList::KernelSettings)?;
        let claimed_kernel_options = unique_map(
            document
                .kernel_options
                .iter()
                .map(|entry| (entry.option, entry.state)),
            ReportList::KernelOptions,
        )?;
        Ok(Self {
            profile: document.profile,
            interfaces,
            paths,
            capabilities,
            uid: document.uid,
            no_new_privs: document.no_new_privs,
            kernel_settings,
            claimed_kernel_options,
            claimed_root_image: document.root_image,
        })
    }

    /// Reads a report from JSON, refusing more than [`MAX_GUEST_REPORT_BYTES`] unread.
    pub fn from_json(text: &str) -> Result<Self, GuestReportRefusal> {
        if text.len() > MAX_GUEST_REPORT_BYTES {
            return Err(GuestReportRefusal::TooLarge {
                bytes: text.len(),
                max: MAX_GUEST_REPORT_BYTES,
            });
        }
        let document: GuestProbeDocument =
            serde_json::from_str(text).map_err(|error| GuestReportRefusal::Malformed {
                line: error.line(),
                column: error.column(),
            })?;
        Self::receive(document)
    }

    /// Always [`SourceClass::GuestReport`].
    pub const fn source(&self) -> SourceClass {
        SourceClass::GuestReport
    }

    /// The profile digest the guest names.
    pub const fn profile(&self) -> Digest {
        self.profile
    }

    /// The guest's result for `interface`, if it reported one.
    pub fn interface(&self, interface: Interface) -> Option<ProbeOutcome> {
        self.interfaces.get(&interface).copied()
    }

    /// The guest's result for a write to `path`, if it reported one.
    pub fn path(&self, path: &ProtectedPath) -> Option<ProbeOutcome> {
        self.paths.get(path).copied()
    }

    /// What the guest claims about a kernel option. Kept for the record; the evaluator
    /// never consults it.
    pub fn claimed_kernel_option(&self, option: KernelOption) -> Option<OptionState> {
        self.claimed_kernel_options.get(&option).copied()
    }

    /// The root image digest the guest claims. Kept for the record; never consulted.
    pub const fn claimed_root_image(&self) -> Option<Digest> {
        self.claimed_root_image
    }
}

fn unique_set<T: Ord + Copy>(
    items: &[T],
    list: ReportList,
) -> Result<BTreeSet<T>, GuestReportRefusal> {
    let set: BTreeSet<T> = items.iter().copied().collect();
    if set.len() != items.len() {
        return Err(GuestReportRefusal::Duplicate { list });
    }
    Ok(set)
}

fn unique_map<K: Ord, V>(
    entries: impl IntoIterator<Item = (K, V)>,
    list: ReportList,
) -> Result<BTreeMap<K, V>, GuestReportRefusal> {
    let mut map = BTreeMap::new();
    for (key, value) in entries {
        if map.insert(key, value).is_some() {
            return Err(GuestReportRefusal::Duplicate { list });
        }
    }
    Ok(map)
}

/// What the host observed itself (VM-CP-05 "Host corroboration"): the digest of the root
/// image it booted, the build record bound to the kernel image it booted, and the kernel
/// settings it configured as boot arguments (recorded, never accepted as enforced). Only
/// host code constructs one; it has no `Deserialize`, and nothing converts a guest report
/// into one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostCorroboration {
    root_image: Digest,
    kernel: KernelBuildRecord,
    boot_arguments: BTreeSet<KernelSetting>,
}

impl HostCorroboration {
    /// The host's own observation of what it booted.
    pub fn host_observed(
        booted_root_image: Digest,
        kernel: KernelBuildRecord,
        boot_arguments: impl IntoIterator<Item = KernelSetting>,
    ) -> Self {
        Self {
            root_image: booted_root_image,
            kernel,
            boot_arguments: boot_arguments.into_iter().collect(),
        }
    }

    /// Always [`SourceClass::HostProbe`].
    pub const fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }

    pub const fn root_image(&self) -> Digest {
        self.root_image
    }

    pub const fn kernel(&self) -> &KernelBuildRecord {
        &self.kernel
    }
}

/// The signed manifest's expected values (VM-CP-05 "match the signed manifest"), passed in
/// as data after the caller verified the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestExpectation {
    pub root_image: Digest,
    pub kernel: KernelBuildRecord,
}

/// One check of the verdict.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "check", rename_all = "snake_case")]
pub enum Check {
    /// The guest names the profile being evaluated.
    ReportProfile,
    /// A forbidden interface fails by a declared mechanism.
    ForbiddenInterface { interface: Interface },
    /// A write to a protected path fails by a declared mechanism.
    ProtectedPathWrite { path: ProtectedPath },
    /// The capability sets equal the profile's.
    CapabilitySet,
    /// The workload runs as an admitted non-root uid.
    NonRootUid,
    /// no_new_privs is set.
    NoNewPrivs,
    /// The booted root image matches the manifest (host).
    HostRootImage,
    /// The booted kernel image matches the manifest (host).
    HostKernelImage,
    /// The host's build record states every option the manifest lists as the manifest
    /// does (host).
    HostKernelRecord,
    /// An option the profile relies on is absent, by host record and manifest (host).
    HostKernelOptionAbsent { option: KernelOption },
    /// A required kernel setting is forced by the build (host).
    KernelSetting { setting: KernelSetting },
}

/// Why a check failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum FailureReason {
    /// The guest's report names another profile.
    ProfileMismatch {
        reported: Digest,
    },
    /// The probe succeeded.
    InterfaceAvailable,
    /// The probe failed with an errno no declared mechanism produces.
    UnexpectedErrno {
        errno: Errno,
        expected: Vec<Errno>,
    },
    /// The bounding set differs from the profile's capability set.
    CapabilitySetDiffers {
        missing: Vec<LinuxCapability>,
        extra: Vec<LinuxCapability>,
    },
    PermittedOutsideProfile {
        extra: Vec<LinuxCapability>,
    },
    EffectiveOutsidePermitted {
        extra: Vec<LinuxCapability>,
    },
    RootUid,
    UidDiffers {
        observed: u32,
    },
    NoNewPrivsOff,
    RootImageMismatch {
        observed: Digest,
        expected: Digest,
    },
    KernelImageMismatch {
        observed: Digest,
        expected: Digest,
    },
    /// The host's record states an option otherwise than the manifest; `None` when the
    /// host's record does not list it.
    KernelRecordDiffers {
        option: KernelOption,
        observed: Option<OptionState>,
        expected: OptionState,
    },
    /// The host's record does not show the option absent.
    KernelOptionNotAbsent {
        option: KernelOption,
        observed: Option<OptionState>,
    },
    /// The manifest does not promise the option absent.
    ManifestDoesNotPromiseAbsence {
        option: KernelOption,
        expected: Option<OptionState>,
    },
    /// No build option forcing the setting is built in; a boot argument or a guest claim
    /// is recorded but never accepted (§3.4).
    SettingNotForcedByBuild {
        setting: KernelSetting,
        boot_argument_configured: bool,
        guest_claimed: bool,
    },
}

/// Why a check could not be decided. Inconclusive fails a required check (VM-W09).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InconclusiveReason {
    NoGuestReport,
    /// The report has no result for this check.
    NoResult,
    NoHostCorroboration,
    NoManifest,
}

/// The outcome of one check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum CheckOutcome {
    Passed,
    /// A forbidden interface failed with an errno its declared mechanisms produce; the
    /// mechanisms that produce it are listed, primary first. A pass.
    RefusedByDeclaredMechanism {
        errno: Errno,
        mechanisms: Vec<Mechanism>,
    },
    Failed {
        reason: FailureReason,
    },
    Inconclusive {
        reason: InconclusiveReason,
    },
}

impl CheckOutcome {
    /// Whether the check passed.
    pub const fn passed(&self) -> bool {
        matches!(self, Self::Passed | Self::RefusedByDeclaredMechanism { .. })
    }
}

/// One check, where its evidence came from, and whether it is required. Serialized as
/// one flat record: the check's tag and fields, `source`, `required`, and the outcome's
/// tag and fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CheckVerdict {
    #[serde(flatten)]
    pub check: Check,
    /// [`SourceClass::GuestReport`] for every probe check, [`SourceClass::HostProbe`]
    /// for every host check; the label is never upgraded.
    pub source: SourceClass,
    pub required: bool,
    #[serde(flatten)]
    pub outcome: CheckOutcome,
}

impl CheckVerdict {
    pub const fn passed(&self) -> bool {
        self.outcome.passed()
    }
}

/// What a passing verdict means, stated in every verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictMeaning {
    /// The declared inner controls behaved as declared when probed. They are defense in
    /// depth (VM-R08): guest root or a guest kernel compromise can bypass them, and only
    /// host-side boundaries remain then ([`super::residue`]).
    InnerControlsDefenseInDepth,
}

/// The overall result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictOutcome {
    /// Every required check passed, and host checks ran and passed.
    Passed,
    /// Every required check passed, but no host check corroborated them: the profile does
    /// not require host corroboration and none was given. A guest report is never
    /// sufficient alone (§17, §8.1), so this is not a pass.
    GuestReportedOnly,
    /// A required check failed or was inconclusive.
    Failed,
}

/// The VM-CP-05 verdict for one profile.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConfinementVerdict {
    pub profile: Digest,
    pub workload: WorkloadProfile,
    pub meaning: VerdictMeaning,
    pub host_corroboration_required: bool,
    pub checks: Vec<CheckVerdict>,
    pub outcome: VerdictOutcome,
}

impl ConfinementVerdict {
    /// Every required check passed with host corroboration. A guest-reported-only verdict
    /// does not pass.
    pub const fn passed(&self) -> bool {
        matches!(self.outcome, VerdictOutcome::Passed)
    }

    /// The verdict for `check`, if evaluated.
    pub fn check(&self, check: &Check) -> Option<&CheckVerdict> {
        self.checks.iter().find(|verdict| &verdict.check == check)
    }

    /// The required checks that did not pass.
    pub fn failing(&self) -> impl Iterator<Item = &CheckVerdict> {
        self.checks
            .iter()
            .filter(|verdict| verdict.required && !verdict.passed())
    }

    /// Whether at least one host check ran and every host check passed.
    pub fn host_corroborated(&self) -> bool {
        let mut host = self
            .checks
            .iter()
            .filter(|verdict| verdict.source == SourceClass::HostProbe)
            .peekable();
        host.peek().is_some() && host.all(CheckVerdict::passed)
    }
}

fn failed(reason: FailureReason) -> CheckOutcome {
    CheckOutcome::Failed { reason }
}

fn inconclusive(reason: InconclusiveReason) -> CheckOutcome {
    CheckOutcome::Inconclusive { reason }
}

/// A forbidden interface passes only when it failed with a declared mechanism's errno.
fn judge_probe(entry: &ForbiddenInterface, outcome: ProbeOutcome) -> CheckOutcome {
    match outcome {
        ProbeOutcome::Succeeded => failed(FailureReason::InterfaceAvailable),
        ProbeOutcome::Failed { errno } => {
            let mechanisms = entry.attribute(errno);
            if mechanisms.is_empty() {
                failed(FailureReason::UnexpectedErrno {
                    errno,
                    expected: entry.expected_failures(),
                })
            } else {
                CheckOutcome::RefusedByDeclaredMechanism { errno, mechanisms }
            }
        }
    }
}

fn judge_capabilities(profile: &BTreeSet<LinuxCapability>, sets: &CapabilitySets) -> CheckOutcome {
    let missing: Vec<LinuxCapability> = profile.difference(&sets.bounding).copied().collect();
    let extra: Vec<LinuxCapability> = sets.bounding.difference(profile).copied().collect();
    if !missing.is_empty() || !extra.is_empty() {
        return failed(FailureReason::CapabilitySetDiffers { missing, extra });
    }
    let extra: Vec<LinuxCapability> = sets.permitted.difference(profile).copied().collect();
    if !extra.is_empty() {
        return failed(FailureReason::PermittedOutsideProfile { extra });
    }
    let extra: Vec<LinuxCapability> = sets
        .effective
        .difference(&sets.permitted)
        .copied()
        .collect();
    if !extra.is_empty() {
        return failed(FailureReason::EffectiveOutsidePermitted { extra });
    }
    CheckOutcome::Passed
}

fn judge_kernel_record(host: &KernelBuildRecord, manifest: &KernelBuildRecord) -> CheckOutcome {
    for (option, expected) in manifest.options() {
        let observed = host.state(option);
        if observed != Some(expected) {
            return failed(FailureReason::KernelRecordDiffers {
                option,
                observed,
                expected,
            });
        }
    }
    CheckOutcome::Passed
}

fn judge_absent(
    option: KernelOption,
    host: &KernelBuildRecord,
    manifest: &KernelBuildRecord,
) -> CheckOutcome {
    let observed = host.state(option);
    if !observed.is_some_and(OptionState::is_absent) {
        return failed(FailureReason::KernelOptionNotAbsent { option, observed });
    }
    let expected = manifest.state(option);
    if !expected.is_some_and(OptionState::is_absent) {
        return failed(FailureReason::ManifestDoesNotPromiseAbsence { option, expected });
    }
    CheckOutcome::Passed
}

/// Evaluates VM-CP-05 for `profile` from the guest's report and the host's corroboration
/// against the signed manifest's values. Every argument may be missing; what is missing
/// makes the checks that need it inconclusive.
pub fn evaluate(
    profile: &ConfinementProfile,
    guest: Option<&GuestReport>,
    host: Option<&HostCorroboration>,
    manifest: Option<&ManifestExpectation>,
) -> ConfinementVerdict {
    let mut checks = Vec::new();
    let guest_check = |check, outcome| CheckVerdict {
        check,
        source: SourceClass::GuestReport,
        required: true,
        outcome,
    };
    let from_guest = |judge: &dyn Fn(&GuestReport) -> CheckOutcome| match guest {
        Some(report) => judge(report),
        None => inconclusive(InconclusiveReason::NoGuestReport),
    };

    checks.push(guest_check(
        Check::ReportProfile,
        from_guest(&|report| {
            if report.profile == profile.digest() {
                CheckOutcome::Passed
            } else {
                failed(FailureReason::ProfileMismatch {
                    reported: report.profile,
                })
            }
        }),
    ));

    for entry in profile
        .forbidden()
        .iter()
        .filter(|entry| entry.interface != Interface::ProtectedPathWrite)
    {
        checks.push(guest_check(
            Check::ForbiddenInterface {
                interface: entry.interface,
            },
            from_guest(&|report| match report.interface(entry.interface) {
                Some(outcome) => judge_probe(entry, outcome),
                None => inconclusive(InconclusiveReason::NoResult),
            }),
        ));
    }

    if let Some(entry) = profile.assignment(Interface::ProtectedPathWrite) {
        for path in profile.protected_paths() {
            checks.push(guest_check(
                Check::ProtectedPathWrite { path: path.clone() },
                from_guest(&|report| match report.path(path) {
                    Some(outcome) => judge_probe(entry, outcome),
                    None => inconclusive(InconclusiveReason::NoResult),
                }),
            ));
        }
    }

    let capabilities = profile.capabilities();
    checks.push(guest_check(
        Check::CapabilitySet,
        from_guest(&|report| match &report.capabilities {
            Some(sets) => judge_capabilities(&capabilities, sets),
            None => inconclusive(InconclusiveReason::NoResult),
        }),
    ));

    let uid_policy = profile.uid();
    checks.push(guest_check(
        Check::NonRootUid,
        from_guest(&|report| match report.uid {
            None => inconclusive(InconclusiveReason::NoResult),
            Some(0) => failed(FailureReason::RootUid),
            Some(uid) if uid_policy.admits(uid) => CheckOutcome::Passed,
            Some(uid) => failed(FailureReason::UidDiffers { observed: uid }),
        }),
    ));

    if profile.no_new_privs() {
        checks.push(guest_check(
            Check::NoNewPrivs,
            from_guest(&|report| match report.no_new_privs {
                None => inconclusive(InconclusiveReason::NoResult),
                Some(true) => CheckOutcome::Passed,
                Some(false) => failed(FailureReason::NoNewPrivsOff),
            }),
        ));
    }

    // Host checks read only host and manifest data, never the guest's claims.
    let host_required = profile.requires_host_corroboration() || host.is_some();
    let inputs = match (host, manifest) {
        (Some(host), Some(manifest)) => Ok((host, manifest)),
        (None, _) => Err(InconclusiveReason::NoHostCorroboration),
        (Some(_), None) => Err(InconclusiveReason::NoManifest),
    };
    let host_check =
        |check, judge: &dyn Fn(&HostCorroboration, &ManifestExpectation) -> CheckOutcome| {
            CheckVerdict {
                check,
                source: SourceClass::HostProbe,
                required: host_required,
                outcome: match inputs {
                    Ok((host, manifest)) => judge(host, manifest),
                    Err(reason) => inconclusive(reason),
                },
            }
        };

    checks.push(host_check(Check::HostRootImage, &|host, manifest| {
        if host.root_image == manifest.root_image {
            CheckOutcome::Passed
        } else {
            failed(FailureReason::RootImageMismatch {
                observed: host.root_image,
                expected: manifest.root_image,
            })
        }
    }));
    checks.push(host_check(Check::HostKernelImage, &|host, manifest| {
        let observed = host.kernel.kernel_image();
        let expected = manifest.kernel.kernel_image();
        if observed == expected {
            CheckOutcome::Passed
        } else {
            failed(FailureReason::KernelImageMismatch { observed, expected })
        }
    }));
    checks.push(host_check(Check::HostKernelRecord, &|host, manifest| {
        judge_kernel_record(&host.kernel, &manifest.kernel)
    }));
    for option in profile.required_absent_options() {
        checks.push(host_check(
            Check::HostKernelOptionAbsent { option },
            &|host, manifest| judge_absent(option, &host.kernel, &manifest.kernel),
        ));
    }
    for setting in profile.kernel_settings() {
        let setting = *setting;
        checks.push(host_check(
            Check::KernelSetting { setting },
            &|host, manifest| {
                let forced = setting.forced_by().iter().any(|option| {
                    host.kernel.state(*option) == Some(OptionState::BuiltIn)
                        && manifest.kernel.state(*option) == Some(OptionState::BuiltIn)
                });
                if forced {
                    CheckOutcome::Passed
                } else {
                    failed(FailureReason::SettingNotForcedByBuild {
                        setting,
                        boot_argument_configured: host.boot_arguments.contains(&setting),
                        guest_claimed: guest
                            .is_some_and(|report| report.kernel_settings.contains(&setting)),
                    })
                }
            },
        ));
    }

    let required_pass = checks
        .iter()
        .all(|verdict| !verdict.required || verdict.passed());
    let mut verdict = ConfinementVerdict {
        profile: profile.digest(),
        workload: profile.workload(),
        meaning: VerdictMeaning::InnerControlsDefenseInDepth,
        host_corroboration_required: profile.requires_host_corroboration(),
        checks,
        outcome: VerdictOutcome::Failed,
    };
    verdict.outcome = match (required_pass, verdict.host_corroborated()) {
        (false, _) => VerdictOutcome::Failed,
        (true, true) => VerdictOutcome::Passed,
        (true, false) => VerdictOutcome::GuestReportedOnly,
    };
    verdict
}
