//! VM-CP-05 from the V15 confinement verdict (plan line 3155; VM-P05).
//!
//! `sandbox_contract::confinement::evaluate` already judges VM-CP-05: the guest's probe
//! results stay guest reports, the host's corroboration (the booted root image and the
//! kernel build record) is compared with the signed manifest, a missing result is
//! inconclusive, and a verdict resting on guest reports alone does not pass. This module
//! does not evaluate VM-CP-05 again. It stamps a verdict with the evidence clock and the
//! configuration it was evaluated under, so a stale verdict refuses like any other
//! outcome, and maps it onto a [`CheckStatus`].

use std::time::Duration;

use serde::Serialize;

use super::catalog::Part;
use super::rules::{
    stamp_current, CheckRefusal, CheckStatus, Failure, InconclusiveReason, JudgeContext,
};
use crate::foundation::evidence::{ClockReading, ClockSession, ConfigurationFingerprint};
use crate::foundation::ids::MonotonicTime;
use crate::sandbox_contract::confinement::{CheckOutcome, ConfinementVerdict, VerdictOutcome};

/// A V15 verdict for VM-CP-05, stamped when the host evaluated it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Vm05Evaluation {
    verdict: ConfinementVerdict,
    clock: ClockSession,
    evaluated_at: MonotonicTime,
    fresh_for: Duration,
    configuration: ConfigurationFingerprint,
}

impl Vm05Evaluation {
    /// Stamps `verdict`, evaluated now on the evidence clock under `configuration`.
    pub fn evaluated(
        verdict: ConfinementVerdict,
        now: ClockReading,
        fresh_for: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Self {
        Self {
            verdict,
            clock: now.session(),
            evaluated_at: now.at(),
            fresh_for,
            configuration,
        }
    }

    pub fn verdict(&self) -> &ConfinementVerdict {
        &self.verdict
    }

    /// The clock session the evaluation was stamped on.
    pub const fn clock(&self) -> ClockSession {
        self.clock
    }

    /// When the host evaluated the verdict, on that clock.
    pub const fn evaluated_at(&self) -> MonotonicTime {
        self.evaluated_at
    }

    /// How long the evaluation stands from [`Self::evaluated_at`].
    pub const fn fresh_for(&self) -> Duration {
        self.fresh_for
    }

    /// The configuration the verdict was evaluated under.
    pub const fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    /// The status of VM-CP-05 for a reader at `context`: refused when the evaluation is
    /// not current, otherwise [`status_of_verdict`].
    pub fn status(&self, context: &JudgeContext) -> CheckStatus {
        match stamp_current(
            self.configuration,
            self.clock,
            self.evaluated_at,
            self.fresh_for,
            context,
        ) {
            Err(problem) => CheckStatus::Refused {
                refusal: CheckRefusal::NotCurrent {
                    part: Part::Primary,
                    problem,
                },
            },
            Ok(()) => status_of_verdict(&self.verdict),
        }
    }
}

/// The status a V15 verdict gives VM-CP-05: a pass only when every required check passed
/// with host corroboration; a verdict on guest reports alone is refused; otherwise the
/// first required check that failed outright, or else the first that was inconclusive.
pub fn status_of_verdict(verdict: &ConfinementVerdict) -> CheckStatus {
    match verdict.outcome {
        VerdictOutcome::Passed => CheckStatus::Passed,
        VerdictOutcome::GuestReportedOnly => CheckStatus::Refused {
            refusal: CheckRefusal::GuestReportedOnly,
        },
        VerdictOutcome::Failed => {
            let mut first_inconclusive = None;
            for failing in verdict.failing() {
                match &failing.outcome {
                    CheckOutcome::Failed { .. } => {
                        return CheckStatus::Failed {
                            failure: Failure::Confinement {
                                check: failing.check.clone(),
                            },
                        }
                    }
                    CheckOutcome::Inconclusive { .. } => {
                        first_inconclusive.get_or_insert_with(|| failing.check.clone());
                    }
                    CheckOutcome::Passed | CheckOutcome::RefusedByDeclaredMechanism { .. } => {}
                }
            }
            CheckStatus::Inconclusive {
                reason: match first_inconclusive {
                    Some(check) => InconclusiveReason::Confinement { check },
                    None => InconclusiveReason::ConfinementVerdictInconsistent,
                },
            }
        }
    }
}
