//! VM-P50 evidence honesty and the VM-W52 assurance ledger.
//!
//! A skipped test, a stale probe, a guest-only observation, a fixture or a run on the fake
//! substrate never becomes a green assurance result (VM-P50; VM-W49 "guest self-report
//! alone never certifies host enforcement"; VM-W51 "unavailable hardware is 'not tested',
//! not a pass"). Source classes and staleness reuse CORE-01's [`SourceClass`] trust order
//! and [`Staleness`] rule, and substrates reuse CORE-08's [`RunSubstrate`].
//!
//! The ledger links each claim to its assumptions, its bounded model result, its
//! observations and its residual risks. A claim is supported only when the model holds
//! within complete bounds and every attached observation is green; stale evidence turns a
//! supported claim into a gap. There is no wall multiplier, secure badge or aggregate
//! probability (VM-W52): the summary counts claims by status and nothing else.

use std::time::Duration;

use serde::Serialize;

use super::contract::{Guard, InvariantId, ModelKind};
use super::explore::Exploration;
use super::ModelError;
use crate::foundation::evidence::{ClockSession, SourceClass, Staleness};
use crate::foundation::ids::{Digest, MonotonicTime};
use crate::foundation::report::RunSubstrate;

/// What happened to the test behind an observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TestExecution {
    Passed,
    Failed,
    Skipped,
    NotRun,
}

/// One observation offered as assurance evidence.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AssuranceObservation {
    pub source: SourceClass,
    pub execution: TestExecution,
    pub substrate: RunSubstrate,
    pub clock: ClockSession,
    pub observed_at: MonotonicTime,
    pub fresh_for: Duration,
}

/// What an observation must meet to count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct AssuranceRequirement {
    pub minimum_source: SourceClass,
    pub max_age: Duration,
}

impl AssuranceRequirement {
    /// Host enforcement is certified only by the host's own probe.
    pub fn host_enforcement(max_age: Duration) -> Self {
        Self {
            minimum_source: SourceClass::HostProbe,
            max_age,
        }
    }
}

/// Why an observation is not assurance.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum NotAssurance {
    Skipped,
    NotRun,
    Stale {
        staleness: Staleness,
    },
    /// A guest report offered for a property the host must observe.
    GuestOnly,
    SourceTooWeak {
        observed: SourceClass,
        required: SourceClass,
    },
    FakeSubstrate,
}

/// The assurance an observation gives.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum AssuranceStatus {
    Green,
    /// A failed test blocks the claim whatever its source (fail closed).
    Red,
    NotTested {
        reason: NotAssurance,
    },
    Inconclusive {
        reasons: Vec<NotAssurance>,
    },
}

impl AssuranceStatus {
    pub fn is_green(&self) -> bool {
        matches!(self, Self::Green)
    }
}

/// The honesty check (VM-P50): only a passed test from a sufficient source, fresh on the
/// current clock session and run on a real authorized substrate is green.
pub fn assess(
    observation: &AssuranceObservation,
    requirement: &AssuranceRequirement,
    now: MonotonicTime,
    session: ClockSession,
) -> AssuranceStatus {
    match observation.execution {
        TestExecution::Skipped => {
            return AssuranceStatus::NotTested {
                reason: NotAssurance::Skipped,
            }
        }
        TestExecution::NotRun => {
            return AssuranceStatus::NotTested {
                reason: NotAssurance::NotRun,
            }
        }
        TestExecution::Failed => return AssuranceStatus::Red,
        TestExecution::Passed => {}
    }
    let mut reasons = Vec::new();
    if observation.substrate == RunSubstrate::FakeTimeControlled {
        reasons.push(NotAssurance::FakeSubstrate);
    }
    let required = requirement.minimum_source;
    if !observation.source.satisfies(required) {
        reasons.push(if observation.source == SourceClass::GuestReport {
            NotAssurance::GuestOnly
        } else {
            NotAssurance::SourceTooWeak {
                observed: observation.source,
                required,
            }
        });
    }
    let limit = requirement.max_age.min(observation.fresh_for);
    let staleness = if observation.clock != session {
        Some(Staleness::OtherClock)
    } else {
        match now.checked_duration_since(observation.observed_at) {
            None => Some(Staleness::ObservedAfterNow),
            Some(age) => (age > limit).then_some(Staleness::TooOld { age, limit }),
        }
    };
    if let Some(staleness) = staleness {
        reasons.push(NotAssurance::Stale { staleness });
    }
    if reasons.is_empty() {
        AssuranceStatus::Green
    } else {
        AssuranceStatus::Inconclusive { reasons }
    }
}

/// A bounded model result for one invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ModelResult {
    pub model: ModelKind,
    pub invariant: InvariantId,
    pub holds: bool,
    pub complete: bool,
    pub states: usize,
}

impl ModelResult {
    pub fn from_exploration(exploration: &Exploration, invariant: InvariantId) -> Self {
        Self {
            model: exploration.model,
            invariant,
            holds: exploration.holds(invariant),
            complete: exploration.complete,
            states: exploration.states,
        }
    }
}

/// One release claim: an invariant under a configuration, with the enforcement
/// assumptions it rests on and its residual risks.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AssuranceClaim {
    pub invariant: InvariantId,
    pub configuration: Digest,
    pub assumptions: Vec<Guard>,
    pub residual_risks: Vec<String>,
}

/// Why a claim is not supported.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "gap", rename_all = "snake_case")]
pub enum GapReason {
    NoModelResult,
    /// The model result is for another invariant than the claim's.
    ModelForAnotherInvariant,
    /// The exploration was cut by its depth bound.
    ModelBounded,
    NoObservation,
    Observation {
        status: AssuranceStatus,
    },
}

/// The status of one claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ClaimStatus {
    Supported,
    RefutedByModel,
    RefutedByObservation,
    Gap { reasons: Vec<GapReason> },
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct ClaimRecord {
    claim: AssuranceClaim,
    model: Option<ModelResult>,
    observations: Vec<AssuranceObservation>,
}

/// Claim counts by status; deliberately nothing else.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct LedgerSummary {
    pub supported: usize,
    pub gaps: usize,
    pub refuted: usize,
}

/// The VM-W52 assurance ledger.
#[derive(Clone, Debug, Default, PartialEq, Serialize)]
pub struct AssuranceLedger {
    records: Vec<ClaimRecord>,
}

impl AssuranceLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a claim; refuses one without residual risks (no generic secure badge).
    pub fn record(
        &mut self,
        claim: AssuranceClaim,
        model: Option<ModelResult>,
        observations: Vec<AssuranceObservation>,
    ) -> Result<(), ModelError> {
        if claim
            .residual_risks
            .iter()
            .all(|risk| risk.trim().is_empty())
        {
            return Err(ModelError::MissingResidualAssumptions);
        }
        self.records.push(ClaimRecord {
            claim,
            model,
            observations,
        });
        Ok(())
    }

    /// The status of every claim at `now`.
    pub fn statuses(
        &self,
        requirement: &AssuranceRequirement,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Vec<(InvariantId, ClaimStatus)> {
        self.records
            .iter()
            .map(|record| {
                (
                    record.claim.invariant,
                    Self::status_of(record, requirement, now, session),
                )
            })
            .collect()
    }

    fn status_of(
        record: &ClaimRecord,
        requirement: &AssuranceRequirement,
        now: MonotonicTime,
        session: ClockSession,
    ) -> ClaimStatus {
        let mut reasons = Vec::new();
        match record.model {
            None => reasons.push(GapReason::NoModelResult),
            Some(model) if model.invariant != record.claim.invariant => {
                reasons.push(GapReason::ModelForAnotherInvariant)
            }
            Some(model) if !model.holds => return ClaimStatus::RefutedByModel,
            Some(model) if !model.complete => reasons.push(GapReason::ModelBounded),
            Some(_) => {}
        }
        if record.observations.is_empty() {
            reasons.push(GapReason::NoObservation);
        }
        for observation in &record.observations {
            match assess(observation, requirement, now, session) {
                AssuranceStatus::Green => {}
                AssuranceStatus::Red => return ClaimStatus::RefutedByObservation,
                status => reasons.push(GapReason::Observation { status }),
            }
        }
        if reasons.is_empty() {
            ClaimStatus::Supported
        } else {
            ClaimStatus::Gap { reasons }
        }
    }

    pub fn summary(
        &self,
        requirement: &AssuranceRequirement,
        now: MonotonicTime,
        session: ClockSession,
    ) -> LedgerSummary {
        let mut summary = LedgerSummary::default();
        for (_, status) in self.statuses(requirement, now, session) {
            match status {
                ClaimStatus::Supported => summary.supported += 1,
                ClaimStatus::Gap { .. } => summary.gaps += 1,
                ClaimStatus::RefutedByModel | ClaimStatus::RefutedByObservation => {
                    summary.refuted += 1
                }
            }
        }
        summary
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{digest, Clock, ManualClock};
    use crate::foundation::report::Label;
    use crate::sandbox_contract::models::contract::{check_model, ModelConfig};
    use crate::sandbox_contract::models::explore::Bounds;

    const MINUTE: Duration = Duration::from_secs(60);

    fn session() -> ClockSession {
        ClockSession::from_uuid(uuid::Uuid::from_u128(7))
    }

    fn real() -> RunSubstrate {
        RunSubstrate::AuthorizedDisposable {
            authorization: Label::new("disposable-vm-lab").unwrap(),
        }
    }

    fn observation(source: SourceClass, execution: TestExecution, at: u64) -> AssuranceObservation {
        AssuranceObservation {
            source,
            execution,
            substrate: real(),
            clock: session(),
            observed_at: MonotonicTime::from_nanos(at),
            fresh_for: 10 * MINUTE,
        }
    }

    fn requirement() -> AssuranceRequirement {
        AssuranceRequirement::host_enforcement(5 * MINUTE)
    }

    #[test]
    fn a_fresh_passed_host_probe_on_a_real_substrate_is_green() {
        let clock = ManualClock::new(MonotonicTime::from_nanos(1_000));
        let host = observation(SourceClass::HostProbe, TestExecution::Passed, 1_000);
        assert_eq!(
            assess(&host, &requirement(), clock.now(), session()),
            AssuranceStatus::Green
        );
    }

    #[test]
    fn skipped_and_unrun_tests_are_not_tested_never_green() {
        let now = MonotonicTime::from_nanos(0);
        for (execution, reason) in [
            (TestExecution::Skipped, NotAssurance::Skipped),
            (TestExecution::NotRun, NotAssurance::NotRun),
        ] {
            let status = assess(
                &observation(SourceClass::HostProbe, execution, 0),
                &requirement(),
                now,
                session(),
            );
            assert_eq!(status, AssuranceStatus::NotTested { reason });
        }
    }

    #[test]
    fn a_stale_probe_is_inconclusive() {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let probe = observation(SourceClass::HostProbe, TestExecution::Passed, 0);
        clock.advance(5 * MINUTE);
        assert!(assess(&probe, &requirement(), clock.now(), session()).is_green());
        clock.advance(Duration::from_nanos(1));
        let status = assess(&probe, &requirement(), clock.now(), session());
        assert!(matches!(
            status,
            AssuranceStatus::Inconclusive { ref reasons }
                if matches!(reasons[..], [NotAssurance::Stale { staleness: Staleness::TooOld { .. } }])
        ));
        // A probe from another clock session (before a restart) is stale too.
        let other = AssuranceObservation {
            clock: ClockSession::from_uuid(uuid::Uuid::from_u128(8)),
            ..probe
        };
        assert!(!assess(&other, &requirement(), MonotonicTime::ZERO, session()).is_green());
    }

    #[test]
    fn guest_only_fixture_and_fake_observations_never_certify_host_enforcement() {
        let now = MonotonicTime::ZERO;
        let guest = observation(SourceClass::GuestReport, TestExecution::Passed, 0);
        assert_eq!(
            assess(&guest, &requirement(), now, session()),
            AssuranceStatus::Inconclusive {
                reasons: vec![NotAssurance::GuestOnly]
            }
        );
        let fixture = observation(SourceClass::Fixture, TestExecution::Passed, 0);
        assert!(!assess(&fixture, &requirement(), now, session()).is_green());
        let fake = AssuranceObservation {
            substrate: RunSubstrate::FakeTimeControlled,
            ..observation(SourceClass::HostProbe, TestExecution::Passed, 0)
        };
        assert_eq!(
            assess(&fake, &requirement(), now, session()),
            AssuranceStatus::Inconclusive {
                reasons: vec![NotAssurance::FakeSubstrate]
            }
        );
        // A failure is red whatever its source.
        let failed = observation(SourceClass::GuestReport, TestExecution::Failed, 0);
        assert_eq!(
            assess(&failed, &requirement(), now, session()),
            AssuranceStatus::Red
        );
    }

    fn claim(invariant: InvariantId) -> AssuranceClaim {
        AssuranceClaim {
            invariant,
            configuration: digest("yougori/test/configuration/v1", &[b"profile"]),
            assumptions: vec![Guard::HostFirewall, Guard::RelayAddressCheck],
            residual_risks: vec!["timing channels are outside the release bound".to_string()],
        }
    }

    #[test]
    fn the_ledger_supports_only_complete_models_with_fresh_green_evidence() {
        let invariant = InvariantId::NoForbiddenEgress;
        let holds = check_model(
            ModelKind::Egress,
            &ModelConfig::threat_model(),
            Bounds::DEFAULT,
        )
        .unwrap();
        let model = ModelResult::from_exploration(&holds, invariant);
        let mut ledger = AssuranceLedger::new();
        ledger
            .record(
                claim(invariant),
                Some(model),
                vec![observation(
                    SourceClass::HostProbe,
                    TestExecution::Passed,
                    0,
                )],
            )
            .unwrap();
        // A model result alone is a gap: it does not prove the implementation.
        ledger
            .record(claim(invariant), Some(model), vec![])
            .unwrap();
        let broken = check_model(
            ModelKind::Egress,
            &ModelConfig::threat_model().without_guards([Guard::HostFirewall]),
            Bounds::DEFAULT,
        )
        .unwrap();
        ledger
            .record(
                claim(invariant),
                Some(ModelResult::from_exploration(&broken, invariant)),
                vec![observation(
                    SourceClass::HostProbe,
                    TestExecution::Passed,
                    0,
                )],
            )
            .unwrap();
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let statuses: Vec<ClaimStatus> = ledger
            .statuses(&requirement(), clock.now(), session())
            .into_iter()
            .map(|(_, status)| status)
            .collect();
        assert_eq!(statuses[0], ClaimStatus::Supported);
        assert_eq!(
            statuses[1],
            ClaimStatus::Gap {
                reasons: vec![GapReason::NoObservation]
            }
        );
        assert_eq!(statuses[2], ClaimStatus::RefutedByModel);
        assert_eq!(
            ledger.summary(&requirement(), clock.now(), session()),
            LedgerSummary {
                supported: 1,
                gaps: 1,
                refuted: 1
            }
        );
        // Stale evidence invalidates the supported claim.
        clock.advance(6 * MINUTE);
        let later = ledger.statuses(&requirement(), clock.now(), session());
        assert!(matches!(later[0].1, ClaimStatus::Gap { .. }));
    }

    #[test]
    fn the_ledger_refuses_badges_and_reports_no_aggregate_probability() {
        let mut ledger = AssuranceLedger::new();
        let badge = AssuranceClaim {
            residual_risks: vec![],
            ..claim(InvariantId::NoForbiddenEgress)
        };
        assert_eq!(
            ledger.record(badge, None, vec![]),
            Err(ModelError::MissingResidualAssumptions)
        );
        let json = serde_json::to_value(LedgerSummary::default()).unwrap();
        let keys: std::collections::BTreeSet<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys, ["gaps", "refuted", "supported"].into_iter().collect());
    }
}
