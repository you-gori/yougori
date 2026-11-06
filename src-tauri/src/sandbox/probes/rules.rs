//! The rules of §8.1 and VM-W09 (plan lines 2433–2439 and 2594), one function each, and
//! [`judge`], which applies them to the outcomes of one check:
//!
//! - [`source_accepted`]: a guest report never satisfies a host-only part, and a
//!   controlled external check needs a controlled external observation;
//! - [`current`]: an outcome under another configuration, on another clock or older than
//!   the shorter of the reader's and its own freshness is stale (CORE-01's rules, in
//!   CORE-01's order); an outcome read from launch records is judged by the stamp of every
//!   fact it was read from;
//! - [`evaluate_part`]: every applicable observation must have been made and must hold;
//!   a missing or ill-typed observation is inconclusive, never a pass;
//! - [`control_holds`]: a positive control that failed, or was not observed, makes the
//!   result inconclusive (§17 line 3147; §4.4);
//! - corroboration: a guest-reported check passes only with every named host fact
//!   observed by the host and holding (§17 lines 3155, 3159, 3171).
//!
//! Only [`CheckStatus::Passed`] passes. Inconclusive and not tested fail a required check
//! (VM-W09 acceptance: "inconclusive results fail required checks"; VM-CP-35: "a skipped
//! hardware test appears as 'not tested', never as a pass").

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::catalog::{ControlledCheck, CorroboratingFact, Part, SourceKind};
use super::expect::{ExpectationId, ObservationError};
use super::outcome::{
    Evidence, GuestRun, NotTestedReason, Observations, ProbeOutcome, RunResult, RunnerInconclusive,
};
use crate::foundation::evidence::{
    ClockReading, ClockSession, ConfigurationFingerprint, OsKind, Staleness,
};
use crate::foundation::ids::MonotonicTime;
use crate::sandbox::backend::ObservationProblem;
use crate::sandbox::link::ProbeOutcome as GuestVerdict;
use crate::sandbox_contract::confinement::Check as ConfinementCheck;

/// What the reader of the outcomes holds now: the evidence clock's reading, the
/// configuration in force, the oldest evidence it accepts and the host's operating
/// system.
#[derive(Clone, Copy, Debug)]
pub struct JudgeContext {
    pub now: ClockReading,
    pub configuration: ConfigurationFingerprint,
    pub max_age: Duration,
    pub os: OsKind,
}

/// The status of one check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum CheckStatus {
    /// Every applicable observation was made, current and from an accepted source, every
    /// one held, the corroboration held and the positive control held.
    Passed,
    /// An observation was made and did not hold.
    Failed {
        failure: Failure,
    },
    Inconclusive {
        reason: InconclusiveReason,
    },
    NotTested {
        reason: NotTestedReason,
    },
    /// The evidence cannot be used at all.
    Refused {
        refusal: CheckRefusal,
    },
}

impl CheckStatus {
    /// Whether the check passed; nothing else does.
    pub const fn passed(&self) -> bool {
        matches!(self, Self::Passed)
    }
}

impl fmt::Display for CheckStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Passed => f.write_str("passed"),
            Self::Failed {
                failure: Failure::Expectation { id, .. },
            } => match super::expect::expectation(*id) {
                Some(entry) => write!(f, "failed: expected that {}", entry.says),
                None => write!(f, "failed: {id}"),
            },
            Self::Failed {
                failure: Failure::Confinement { check },
            } => write!(f, "failed: the confinement check {check:?} did not pass"),
            Self::Inconclusive { reason } => write!(f, "inconclusive: {reason}"),
            Self::NotTested { reason } => write!(f, "not tested: {reason}"),
            Self::Refused { refusal } => write!(f, "evidence refused: {refusal}"),
        }
    }
}

/// What failed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "failed", rename_all = "snake_case")]
pub enum Failure {
    /// This expectation of this part did not hold.
    Expectation { id: ExpectationId, part: Part },
    /// A required check of the V15 VM-CP-05 verdict did not pass.
    Confinement { check: ConfinementCheck },
}

/// Why a check is inconclusive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "inconclusive", rename_all = "snake_case")]
pub enum InconclusiveReason {
    /// The runner could not finish this part.
    Runner {
        part: Part,
        reason: RunnerInconclusive,
    },
    /// An applicable observation was not made.
    MissingObservation { id: ExpectationId },
    /// An observation was of the wrong kind or could not be judged.
    InconsistentObservation {
        id: ExpectationId,
        error: ObservationError,
    },
    /// The guest said it skipped this observation.
    GuestSkipped { id: ExpectationId },
    /// The guest said this observation was inconclusive.
    GuestInconclusive { id: ExpectationId },
    /// The positive control was not observed in the run.
    NoPositiveControl { id: ExpectationId },
    /// The positive control did not hold, so nothing the run showed is attributable to
    /// the boundary.
    ControlFailed { id: ExpectationId },
    /// The V15 verdict could not decide this check.
    Confinement { check: ConfinementCheck },
    /// The V15 verdict says it failed but lists no failing required check.
    ConfinementVerdictInconsistent,
}

impl fmt::Display for InconclusiveReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Runner { part, reason } => write!(f, "{reason} ({part})"),
            Self::MissingObservation { id } => write!(f, "{id} was not observed"),
            Self::InconsistentObservation { id, error } => write!(f, "{id}: {error}"),
            Self::GuestSkipped { id } => write!(f, "the guest says it skipped {id}"),
            Self::GuestInconclusive { id } => write!(f, "the guest says {id} was inconclusive"),
            Self::NoPositiveControl { id } => {
                write!(f, "the positive control {id} was not observed")
            }
            Self::ControlFailed { id } => write!(
                f,
                "the positive control {id} failed, so the result is not attributable to the boundary"
            ),
            Self::Confinement { check } => write!(f, "the VM-CP-05 verdict left {check:?} open"),
            Self::ConfinementVerdictInconsistent => f.write_str(
                "the VM-CP-05 verdict says it failed but names no failing required check",
            ),
        }
    }
}

/// Why the evidence of a check cannot be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum CheckRefusal {
    /// The part needs `required`, and the outcome came from `found`; a guest report for a
    /// host-only part is this refusal.
    WrongSource {
        part: Part,
        required: SourceKind,
        found: SourceKind,
    },
    /// The outcome is not current for the reader.
    NotCurrent {
        part: Part,
        problem: ObservationProblem,
    },
    /// The guest-reported check lacks this host corroboration.
    Uncorroborated { fact: CorroboratingFact },
    /// An outcome of another check was handed in.
    OtherCheck,
    /// Two outcomes for one part.
    DuplicatePart { part: Part },
    /// The V15 VM-CP-05 verdict passed on guest reports alone.
    GuestReportedOnly,
}

impl fmt::Display for CheckRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongSource {
                part,
                required,
                found,
            } => write!(f, "{part} needs a {required}, and a {found} was given"),
            Self::NotCurrent { part, problem } => write!(f, "{part}: {problem}"),
            Self::Uncorroborated { fact } => write!(
                f,
                "a guest report is never sufficient alone, and the host did not corroborate it with {fact}"
            ),
            Self::OtherCheck => f.write_str("an outcome of another check was given"),
            Self::DuplicatePart { part } => write!(f, "two outcomes were given for {part}"),
            Self::GuestReportedOnly => f.write_str(
                "the confinement verdict rests on guest reports alone, which never suffice",
            ),
        }
    }
}

/// The result of one part on its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PartResult {
    Holds,
    Fails { id: ExpectationId },
    Inconclusive { reason: InconclusiveReason },
    NotTested { reason: NotTestedReason },
}

/// Rule 1: the outcome's source may stand for the source its part requires. A guest
/// report never stands for a host observation (VM-P29, VM-CP-25), and a controlled
/// external check needs a controlled external observation.
pub fn source_accepted(
    check: &ControlledCheck,
    outcome: &ProbeOutcome,
) -> Result<(), CheckRefusal> {
    let part = outcome.part();
    let Some(found) = outcome.source_kind() else {
        return Ok(());
    };
    let required = check.side.required_source(part).unwrap_or(SourceKind::Host);
    if found.may_stand_for(required) {
        Ok(())
    } else {
        Err(CheckRefusal::WrongSource {
            part,
            required,
            found,
        })
    }
}

/// Rule 2: the outcome is current for the reader: same configuration, same clock, not
/// observed after now, and no older than the shorter of the reader's maximum age and the
/// outcome's own freshness. An outcome read from launch records is current only while the
/// stamp of every fact it was read from is; the first that is not is named. A part not
/// tested has nothing to be stale.
pub fn current(outcome: &ProbeOutcome, context: &JudgeContext) -> Result<(), CheckRefusal> {
    let part = outcome.part();
    let problem = match outcome.evidence() {
        Evidence::Host { observed, .. } => observed
            .current_at(context.now, context.max_age, context.configuration)
            .err(),
        Evidence::Guest { run } => guest_current(run, context).err(),
        Evidence::Record { run } => run.stamps().find_map(|stamp| {
            stamp_current(
                stamp.configuration(),
                stamp.clock(),
                stamp.observed_at(),
                stamp.fresh_for(),
                context,
            )
            .err()
        }),
        Evidence::NotTested { .. } => None,
    };
    match problem {
        Some(problem) => Err(CheckRefusal::NotCurrent { part, problem }),
        None => Ok(()),
    }
}

/// The same rules as [`crate::sandbox::backend::HostObserved::current_at`], for a guest
/// run.
fn guest_current(run: &GuestRun, context: &JudgeContext) -> Result<(), ObservationProblem> {
    stamp_current(
        run.configuration(),
        run.clock(),
        run.collected_at(),
        run.fresh_for(),
        context,
    )
}

/// CORE-01's currency rules for any stamped value: the configuration, then the clock
/// session, then the age against the shorter of the reader's maximum age and the value's
/// own freshness.
pub(super) fn stamp_current(
    configuration: ConfigurationFingerprint,
    clock: ClockSession,
    at: MonotonicTime,
    fresh_for: Duration,
    context: &JudgeContext,
) -> Result<(), ObservationProblem> {
    if configuration != context.configuration {
        return Err(ObservationProblem::OtherConfiguration {
            observed_under: configuration,
            current: context.configuration,
        });
    }
    if clock != context.now.session() {
        return Err(ObservationProblem::Stale {
            staleness: Staleness::OtherClock,
        });
    }
    let Some(age) = context.now.at().checked_duration_since(at) else {
        return Err(ObservationProblem::Stale {
            staleness: Staleness::ObservedAfterNow,
        });
    };
    let limit = context.max_age.min(fresh_for);
    if age > limit {
        return Err(ObservationProblem::Stale {
            staleness: Staleness::TooOld { age, limit },
        });
    }
    Ok(())
}

/// Rule 3: every observation of the part that applies on the host was made and holds. A
/// conclusive failure is reported first, in table order; otherwise the first missing,
/// ill-typed, skipped or inconclusive observation makes the part inconclusive.
pub fn evaluate_part(check: &ControlledCheck, outcome: &ProbeOutcome, os: OsKind) -> PartResult {
    let part = outcome.part();
    let mut first_inconclusive = None;
    match outcome.evidence() {
        Evidence::NotTested { reason } => return PartResult::NotTested { reason: *reason },
        Evidence::Host { observed, .. } => match observed.value() {
            RunResult::Inconclusive { reason } => {
                return PartResult::Inconclusive {
                    reason: InconclusiveReason::Runner {
                        part,
                        reason: *reason,
                    },
                }
            }
            RunResult::Observed { observations } => {
                return evaluate_observations(check, part, observations, os)
            }
        },
        Evidence::Record { run } => {
            return evaluate_observations(check, part, run.observations(), os)
        }
        Evidence::Guest { run } => {
            for entry in check.observations_for(part, os) {
                match run.verdicts().get(&entry.id) {
                    Some(GuestVerdict::Passed) => {}
                    Some(GuestVerdict::Failed) => return PartResult::Fails { id: entry.id },
                    Some(GuestVerdict::Skipped) => {
                        first_inconclusive
                            .get_or_insert(InconclusiveReason::GuestSkipped { id: entry.id });
                    }
                    Some(GuestVerdict::Inconclusive) => {
                        first_inconclusive
                            .get_or_insert(InconclusiveReason::GuestInconclusive { id: entry.id });
                    }
                    None => {
                        first_inconclusive
                            .get_or_insert(InconclusiveReason::MissingObservation { id: entry.id });
                    }
                }
            }
        }
    }
    match first_inconclusive {
        Some(reason) => PartResult::Inconclusive { reason },
        None => PartResult::Holds,
    }
}

/// Rule 3 for a host run's observations alone, without the source and currency rules
/// (the CORE-01 registry applies its own when an adapter reports through it).
pub fn evaluate_observations(
    check: &ControlledCheck,
    part: Part,
    observations: &Observations,
    os: OsKind,
) -> PartResult {
    let mut first_inconclusive = None;
    for entry in check.observations_for(part, os) {
        match observations
            .get(&entry.id)
            .map(|seen| entry.expect.holds(seen))
        {
            Some(Ok(true)) => {}
            Some(Ok(false)) => return PartResult::Fails { id: entry.id },
            Some(Err(error)) => {
                first_inconclusive.get_or_insert(InconclusiveReason::InconsistentObservation {
                    id: entry.id,
                    error,
                });
            }
            None => {
                first_inconclusive
                    .get_or_insert(InconclusiveReason::MissingObservation { id: entry.id });
            }
        }
    }
    match first_inconclusive {
        Some(reason) => PartResult::Inconclusive { reason },
        None => PartResult::Holds,
    }
}

/// Whether a host run's observations show the check's positive control holding: `None`
/// when the check has a control in `part` and the run did not observe it.
pub fn control_in_observations(
    check: &ControlledCheck,
    part: Part,
    observations: &Observations,
) -> Option<bool> {
    match check.control() {
        None => Some(true),
        Some(control) if control.part != part => Some(true),
        Some(control) => observations
            .get(&control.id)
            .map(|seen| control.expect.holds(seen).unwrap_or(false)),
    }
}

/// Rule 4: the check's positive control, where it has one, was observed in the run of its
/// part and held. A check without a listed control passes this rule.
pub fn control_holds(
    check: &ControlledCheck,
    outcomes: &BTreeMap<Part, &ProbeOutcome>,
) -> Result<(), InconclusiveReason> {
    let Some(control) = check.control() else {
        return Ok(());
    };
    let id = control.id;
    let held = outcomes
        .get(&control.part)
        .and_then(|outcome| match outcome.evidence() {
            Evidence::Host { observed, .. } => match observed.value() {
                RunResult::Observed { observations } => observations
                    .get(&id)
                    .map(|seen| control.expect.holds(seen).unwrap_or(false)),
                RunResult::Inconclusive { .. } => None,
            },
            Evidence::Record { run } => run
                .observations()
                .get(&id)
                .map(|seen| control.expect.holds(seen).unwrap_or(false)),
            Evidence::Guest { run } => run.verdicts().get(&id).and_then(|verdict| match verdict {
                GuestVerdict::Passed => Some(true),
                GuestVerdict::Failed => Some(false),
                GuestVerdict::Skipped | GuestVerdict::Inconclusive => None,
            }),
            Evidence::NotTested { .. } => None,
        });
    match held {
        Some(true) => Ok(()),
        Some(false) => Err(InconclusiveReason::ControlFailed { id }),
        None => Err(InconclusiveReason::NoPositiveControl { id }),
    }
}

/// Judges one check from the outcomes of its parts. The order: outcomes of another check
/// or duplicate parts are refused; a check with nothing for this host is not tested; the
/// primary part must be present (otherwise not tested), from an accepted source and
/// current; each named corroboration must be present, host-observed, current and
/// holding; then a failed or missing positive control makes the result inconclusive;
/// then a conclusive failure, then an inconclusive part; otherwise the check passed.
pub fn judge(
    check: &ControlledCheck,
    outcomes: &[ProbeOutcome],
    context: &JudgeContext,
) -> CheckStatus {
    let mut by_part: BTreeMap<Part, &ProbeOutcome> = BTreeMap::new();
    for outcome in outcomes {
        if outcome.check() != check.id {
            return refused(CheckRefusal::OtherCheck);
        }
        if by_part.insert(outcome.part(), outcome).is_some() {
            return refused(CheckRefusal::DuplicatePart {
                part: outcome.part(),
            });
        }
    }
    if !check.runs_on(context.os) {
        return CheckStatus::NotTested {
            reason: NotTestedReason::NoObservationForHost { os: context.os },
        };
    }
    let Some(primary) = by_part.get(&Part::Primary).copied() else {
        return CheckStatus::NotTested {
            reason: NotTestedReason::NotRun,
        };
    };
    if let Err(refusal) = source_accepted(check, primary).and_then(|()| current(primary, context)) {
        return refused(refusal);
    }
    let primary_result = evaluate_part(check, primary, context.os);
    if let PartResult::NotTested { reason } = primary_result {
        return CheckStatus::NotTested { reason };
    }

    let mut results = vec![primary_result];
    for fact in check.side.corroboration() {
        let part = Part::Corroboration { fact: *fact };
        let Some(outcome) = by_part.get(&part).copied() else {
            return refused(CheckRefusal::Uncorroborated { fact: *fact });
        };
        if let Err(refusal) =
            source_accepted(check, outcome).and_then(|()| current(outcome, context))
        {
            return refused(refusal);
        }
        match evaluate_part(check, outcome, context.os) {
            PartResult::NotTested { .. } => {
                return refused(CheckRefusal::Uncorroborated { fact: *fact })
            }
            result => results.push(result),
        }
    }

    let runner_inconclusive = matches!(
        results.first(),
        Some(PartResult::Inconclusive {
            reason: InconclusiveReason::Runner { .. }
        })
    );
    if !runner_inconclusive {
        if let Err(reason) = control_holds(check, &by_part) {
            return CheckStatus::Inconclusive { reason };
        }
    }
    let mut first_inconclusive = None;
    for (result, part) in results.into_iter().zip(check.parts()) {
        match result {
            PartResult::Holds => {}
            PartResult::Fails { id } => {
                return CheckStatus::Failed {
                    failure: Failure::Expectation { id, part },
                }
            }
            PartResult::Inconclusive { reason } => {
                first_inconclusive.get_or_insert(reason);
            }
            PartResult::NotTested { reason } => return CheckStatus::NotTested { reason },
        }
    }
    match first_inconclusive {
        Some(reason) => CheckStatus::Inconclusive { reason },
        None => CheckStatus::Passed,
    }
}

const fn refused(refusal: CheckRefusal) -> CheckStatus {
    CheckStatus::Refused { refusal }
}
