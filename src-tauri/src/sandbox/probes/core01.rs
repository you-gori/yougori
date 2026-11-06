//! CORE-01 adapters for the controlled checks whose host-observed parts state a CORE-01
//! fact (S2 CORE-01 row, line 210; §8.1, lines 2433–2439; VM-W09, line 2594; VM-W23,
//! line 2622; §17, lines 3145–3188).
//!
//! An adapter is a CORE-01 [`ProbeAdapter`]: the registry fixes its source class when it
//! is registered and stamps every envelope with its own clock when the probe starts, so
//! an adapter runs its checks live, through a [`HostCheckRunner`] port, and never replays
//! an earlier outcome. Every adapter here is a host probe that changes nothing on the
//! host, observes only its capability's subject kind and runs exactly the host parts the
//! coverage map ([`super::coverage`]) assigns to its capability, so a guest-reported part
//! never feeds one:
//!
//! - [`HypervisorAvailableProbe`]: VM-CP-01 as `Capability::HypervisorAvailable`;
//! - [`PerimeterRuleProbe`]: VM-CP-11 as `Capability::PerimeterRuleEnforced`;
//! - [`HypervisorConfigurationMatchesProbe`]: VM-CP-02 and VM-CP-03;
//! - [`HypervisorConfinedProbe`]: VM-CP-04;
//! - [`BootedImageMatchesManifestProbe`]: the host corroboration of VM-CP-05, VM-CP-17
//!   and VM-CP-23;
//! - [`DestinationPolicyEnforcedProbe`]: VM-CP-07 and VM-CP-08;
//! - [`NoGuestNetworkDeviceProbe`]: the host part of VM-CP-09;
//! - [`CredentialAbsentFromScannedLocationsProbe`]: VM-CP-12;
//! - [`CloneIdentityResetProbe`]: the host corroboration of VM-CP-21;
//! - [`DeviceAssignmentIsolatedProbe`]: VM-CP-31.
//!
//! Each judges its runs with the judge's own pieces ([`evaluate_observations`] and
//! [`control_in_observations`]), in the judge's order. A capability is supported only
//! when every applicable observation of every listed part held and each positive control
//! in a listed part held. A failed observation makes it unsupported with the capability's
//! own reason. A run that timed out, was interrupted or could not reach its subject, a
//! missing or ill-typed observation, an observation of another check or part, a missing
//! or failed positive control, or a check with nothing to observe on this host makes it
//! unknown. A conclusive failure of one check outweighs another check that could not
//! decide; neither is ever supported.

use std::time::Duration;

use super::catalog::{check, CheckId, Part};
use super::coverage::checks_for;
use super::expect::{expectation, ExpectationId, Observed};
use super::outcome::{Observations, RunResult, RunnerInconclusive};
use super::rules::{
    control_in_observations, evaluate_observations, InconclusiveReason, PartResult,
};
use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, HostChange, HypervisorKind, Observation, OsKind,
    ProbeAdapter, SourceClass, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};

/// The check behind `Capability::HypervisorAvailable`.
pub const HYPERVISOR_CHECK: CheckId = CheckId::of(1);

/// The check behind `Capability::PerimeterRuleEnforced`.
pub const PERIMETER_CHECK: CheckId = CheckId::of(11);

/// A host runner of controlled checks: it observes the host and reports typed values. It
/// never changes host state, and its only implementations in this module are test fakes.
pub trait HostCheckRunner: Send + Sync {
    /// The configuration the runner observes under.
    fn configuration(&self) -> ConfigurationFingerprint;
    /// How long its observations stay fresh.
    fn fresh_for(&self) -> Duration;
    /// The host operating system it runs on.
    fn os(&self) -> OsKind;
    /// Runs `part` of `check` about `subject`.
    fn run(&self, check: CheckId, part: Part, subject: &Subject) -> RunResult;
}

/// The hypervisor an accelerator name of VM-CP-01 stands for.
pub fn hypervisor_of(accelerator: &str) -> Option<HypervisorKind> {
    match accelerator {
        "kvm" => Some(HypervisorKind::Kvm),
        "whpx" => Some(HypervisorKind::Whpx),
        "hvf" => Some(HypervisorKind::Hvf),
        "vz" => Some(HypervisorKind::Vz),
        _ => None,
    }
}

/// Why the runs of a capability's parts do not support it.
enum Refuted {
    /// An observation failed in a run whose positive control held or did not apply.
    Failed,
    /// Nothing conclusive was shown.
    Unknown(UnknownReason),
}

/// The observations of every run part of a capability that held: check, part and
/// observations, in coverage order.
type Held = Vec<(CheckId, Part, Observations)>;

const fn unknown_of(reason: RunnerInconclusive) -> UnknownReason {
    match reason {
        RunnerInconclusive::Unreachable => UnknownReason::Unreachable,
        RunnerInconclusive::TimedOut | RunnerInconclusive::Interrupted => {
            UnknownReason::Inconclusive
        }
    }
}

/// Whether `id` is an expectation of `part` of `check_id`.
fn belongs(id: ExpectationId, check_id: CheckId, part: Part) -> bool {
    expectation(id).is_some_and(|entry| entry.check == check_id && entry.part == part)
}

/// Runs every host part the coverage map assigns to `capability`, live, about `subject`.
fn run_capability<R: HostCheckRunner>(
    runner: &R,
    capability: Capability,
    subject: &Subject,
) -> Result<Held, Refuted> {
    let os = runner.os();
    let mut held = Vec::new();
    let mut failed = false;
    let mut first_unknown = None;
    for (check_id, parts) in checks_for(capability) {
        match run_check(runner, os, check_id, parts, subject) {
            Ok(runs) => held.extend(
                runs.into_iter()
                    .map(|(part, observations)| (check_id, part, observations)),
            ),
            Err(Refuted::Failed) => failed = true,
            Err(Refuted::Unknown(reason)) => {
                first_unknown.get_or_insert(reason);
            }
        }
    }
    if failed {
        return Err(Refuted::Failed);
    }
    match first_unknown {
        Some(reason) => Err(Refuted::Unknown(reason)),
        None if held.is_empty() => Err(Refuted::Unknown(UnknownReason::NotTested)),
        None => Ok(held),
    }
}

/// Runs `parts` of `check_id` and judges them in the judge's order: a check with
/// nothing to observe on this host is not tested; a positive control in a part that ran
/// must have held; then a failed observation; then a run that did not finish, a missing,
/// ill-typed or misplaced observation.
fn run_check<R: HostCheckRunner>(
    runner: &R,
    os: OsKind,
    check_id: CheckId,
    parts: &[Part],
    subject: &Subject,
) -> Result<Vec<(Part, Observations)>, Refuted> {
    let row = check(check_id);
    let observable = row.runs_on(os)
        && parts
            .iter()
            .all(|part| row.observations_for(*part, os).next().is_some());
    if !observable {
        return Err(Refuted::Unknown(UnknownReason::NotTested));
    }
    let mut runs = Vec::with_capacity(parts.len());
    let mut first_unknown = None;
    for part in parts {
        match runner.run(check_id, *part, subject) {
            RunResult::Inconclusive { reason } => {
                first_unknown.get_or_insert(unknown_of(reason));
            }
            RunResult::Observed { observations } => {
                if observations.keys().all(|id| belongs(*id, check_id, *part)) {
                    runs.push((*part, observations));
                } else {
                    first_unknown.get_or_insert(UnknownReason::InconsistentReport);
                }
            }
        }
    }
    if let Some(control) = row.control() {
        let ran = runs.iter().find(|(part, _)| *part == control.part);
        if let Some((part, observations)) = ran {
            if control_in_observations(row, *part, observations) != Some(true) {
                return Err(Refuted::Unknown(UnknownReason::Inconclusive));
            }
        }
    }
    for (part, observations) in &runs {
        match evaluate_observations(row, *part, observations, os) {
            PartResult::Holds => {}
            PartResult::Fails { .. } => return Err(Refuted::Failed),
            PartResult::Inconclusive {
                reason: InconclusiveReason::InconsistentObservation { .. },
            } => {
                first_unknown.get_or_insert(UnknownReason::InconsistentReport);
            }
            PartResult::Inconclusive { .. } => {
                first_unknown.get_or_insert(UnknownReason::Inconclusive);
            }
            PartResult::NotTested { .. } => {
                first_unknown.get_or_insert(UnknownReason::NotTested);
            }
        }
    }
    match first_unknown {
        Some(reason) => Err(Refuted::Unknown(reason)),
        None => Ok(runs),
    }
}

/// Observes `capability` on `subject` through its checks: `detail` when supported,
/// `refusal` when an observation failed.
fn observe_fact<R: HostCheckRunner>(
    runner: &R,
    capability: Capability,
    refusal: UnsupportedReason,
    detail: SupportDetail,
    subject: &Subject,
) -> Observation {
    let configuration = runner.configuration();
    let fresh_for = runner.fresh_for();
    if subject.kind() != capability.subject_kind() {
        return Observation::unknown(configuration, fresh_for, UnknownReason::InconsistentReport);
    }
    match run_capability(runner, capability, subject) {
        Ok(_) => Observation::supported(configuration, fresh_for, detail),
        Err(Refuted::Failed) => Observation::unsupported(configuration, fresh_for, refusal),
        Err(Refuted::Unknown(reason)) => Observation::unknown(configuration, fresh_for, reason),
    }
}

/// VM-CP-01 as CORE-01 hypervisor availability. Supported only when the normal launch
/// (the positive control) succeeded, every applicable observation held, and the launch
/// record's accelerator is the subject's hypervisor. Any failed observation refuses the
/// capability, including a launch that was not refused with the accelerator forced
/// unavailable (fail closed); a run that could not decide is unknown.
pub struct HypervisorAvailableProbe<R> {
    runner: R,
}

impl<R: HostCheckRunner> HypervisorAvailableProbe<R> {
    pub fn new(runner: R) -> Self {
        Self { runner }
    }
}

impl<R: HostCheckRunner> ProbeAdapter for HypervisorAvailableProbe<R> {
    fn capability(&self) -> Capability {
        Capability::HypervisorAvailable
    }

    fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    fn observes(&self, subject: &Subject) -> bool {
        matches!(subject, Subject::Hypervisor(_))
    }

    fn observe(&self, subject: &Subject) -> Observation {
        let configuration = self.runner.configuration();
        let fresh_for = self.runner.fresh_for();
        let unknown = |reason| Observation::unknown(configuration, fresh_for, reason);
        let Subject::Hypervisor(target) = subject else {
            return unknown(UnknownReason::InconsistentReport);
        };
        match run_capability(&self.runner, Capability::HypervisorAvailable, subject) {
            Err(Refuted::Unknown(reason)) => unknown(reason),
            Err(Refuted::Failed) => Observation::unsupported(
                configuration,
                fresh_for,
                UnsupportedReason::HypervisorUnavailable,
            ),
            Ok(held) => {
                let accelerator = ExpectationId::named("cp01.accelerator")
                    .and_then(|id| {
                        held.iter()
                            .find(|(check_id, part, _)| {
                                *check_id == HYPERVISOR_CHECK && *part == Part::Primary
                            })
                            .and_then(|(_, _, observations)| observations.get(&id))
                    })
                    .and_then(|seen| match seen {
                        Observed::Value { value } => hypervisor_of(value),
                        _ => None,
                    });
                match accelerator {
                    Some(hypervisor) if hypervisor == target.hypervisor => Observation::supported(
                        configuration,
                        fresh_for,
                        SupportDetail::Hypervisor { hypervisor },
                    ),
                    _ => unknown(UnknownReason::InconsistentReport),
                }
            }
        }
    }
}

/// Defines a host-probe adapter for one capability whose support detail is fixed: it runs
/// the capability's checks through [`observe_fact`] and refuses with `$refusal`.
macro_rules! host_fact_probe {
    (
        $(#[$meta:meta])*
        $name:ident: $capability:ident, $refusal:ident, $detail:expr
    ) => {
        $(#[$meta])*
        pub struct $name<R> {
            runner: R,
        }

        impl<R: HostCheckRunner> $name<R> {
            pub fn new(runner: R) -> Self {
                Self { runner }
            }
        }

        impl<R: HostCheckRunner> ProbeAdapter for $name<R> {
            fn capability(&self) -> Capability {
                Capability::$capability
            }

            fn source(&self) -> SourceClass {
                SourceClass::HostProbe
            }

            fn host_changes(&self) -> Vec<HostChange> {
                Vec::new()
            }

            fn observes(&self, subject: &Subject) -> bool {
                subject.kind() == Capability::$capability.subject_kind()
            }

            fn observe(&self, subject: &Subject) -> Observation {
                observe_fact(
                    &self.runner,
                    Capability::$capability,
                    UnsupportedReason::$refusal,
                    $detail,
                    subject,
                )
            }
        }
    };
}

host_fact_probe! {
    /// VM-CP-11 as CORE-01 perimeter rule enforcement (§4.4, line 2153: a controlled
    /// endpoint, a reached positive control and evidence naming the rule; a timeout is
    /// inconclusive). Supported only when the broker reached the allowed endpoint and every
    /// applicable observation held; a failed observation means the rule is not enforced.
    PerimeterRuleProbe: PerimeterRuleEnforced, NotEnforced, SupportDetail::PerimeterRuleEnforced
}

host_fact_probe! {
    /// VM-CP-02 and VM-CP-03 (§17, lines 3152–3153) as
    /// `Capability::HypervisorConfigurationMatches` on one launch's hypervisor process:
    /// the configuration matches the golden file with no undeclared device, and with the
    /// planted share device detected (VM-CP-03's control) nothing shares or listens.
    HypervisorConfigurationMatchesProbe: HypervisorConfigurationMatches, ConfigurationNotApproved,
        SupportDetail::Plain
}

host_fact_probe! {
    /// VM-CP-04 (§17, line 3154) as `Capability::HypervisorConfined` on one launch's
    /// hypervisor process, with the observations of the runner's host operating system;
    /// the unjailed test launch's reported difference is the control. A host with no
    /// observation of its own, such as WSL2, is not tested.
    HypervisorConfinedProbe: HypervisorConfined, NotConfined, SupportDetail::Plain
}

host_fact_probe! {
    /// The host corroboration of VM-CP-05 (booted root image and kernel build record, with
    /// the io_uring test image's failed kernel check as the control), VM-CP-17 and
    /// VM-CP-23 (§17, lines 3155, 3167 and 3173) as
    /// `Capability::BootedImageMatchesManifest` on one boot of one sandbox. VM-CP-05's
    /// guest-reported part never runs here.
    BootedImageMatchesManifestProbe: BootedImageMatchesManifest, ImageNotAsSigned,
        SupportDetail::Plain
}

host_fact_probe! {
    /// VM-CP-07 and VM-CP-08 (§17, lines 3157–3158) as
    /// `Capability::DestinationPolicyEnforced` on one transport broker, each with its
    /// public positive control.
    DestinationPolicyEnforcedProbe: DestinationPolicyEnforced, DestinationNotRefused,
        SupportDetail::Plain
}

host_fact_probe! {
    /// The host part of VM-CP-09 (§17, line 3159) as `Capability::NoGuestNetworkDevice` on
    /// one boot of one sandbox. The guest's own refusals and their control belong to the
    /// guest-reported part, which never runs here.
    NoGuestNetworkDeviceProbe: NoGuestNetworkDevice, GuestNetworkPath, SupportDetail::Plain
}

host_fact_probe! {
    /// VM-CP-12 (§17, line 3162) as `Capability::CredentialAbsentFromScannedLocations` on
    /// one launch's credential scan; the scan must state its coverage, and the result
    /// covers only the locations the subject names (§8.1, line 2439).
    CredentialAbsentFromScannedLocationsProbe: CredentialAbsentFromScannedLocations,
        CredentialExposed, SupportDetail::Plain
}

host_fact_probe! {
    /// The host corroboration of VM-CP-21 (§17, line 3171) as
    /// `Capability::CloneIdentityReset` on a golden snapshot and its clones: distinct
    /// generation and boot ids, and a pre-snapshot approval refused in each clone. The
    /// guest-reported canary and application identities never run here.
    CloneIdentityResetProbe: CloneIdentityReset, CloneIdentityShared, SupportDetail::Plain
}

host_fact_probe! {
    /// VM-CP-31 (§17, line 3181) as `Capability::DeviceAssignmentIsolated` on one GPU, with
    /// a qualifying device's assignment as the control.
    DeviceAssignmentIsolatedProbe: DeviceAssignmentIsolated, DeviceNotIsolated,
        SupportDetail::Plain
}
