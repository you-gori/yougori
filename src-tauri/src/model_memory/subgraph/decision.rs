//! The GPU-N3 pass/stop rule (GPU §4.16 line 900) and its claim record (§4.17 lines
//! 908–915).
//!
//! Line 900 requires the declared exactness checks, no unauthorized sharing, positive
//! net compute savings after keying and transfer costs, and realistic workload
//! incidence; "if useful eligible prefixes are rare, ship support only for explicitly
//! compatible families". The decision is computed in that order. A failed check stops
//! the mechanism even on fakes. Rare eligible prefixes in a recorded workload narrow it.
//! A pass needs a recorded workload and Yougori measurements; until both exist the
//! mechanism stays optional (§4.17 line 904), and the claim is at most inconclusive.

use std::fmt;

use crate::foundation::ids::Digest;
use crate::foundation::report::Provenance;

/// Why the decision inputs were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecisionError {
    /// An incidence needs at least one request and no more eligible than total.
    InvalidIncidence { eligible: u64, total: u64 },
    /// The minimum incidence is a fraction in (0, 1].
    InvalidMinimumIncidence,
    /// The net saving is NaN or infinite.
    NetSavingNotFinite,
}

impl fmt::Display for DecisionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIncidence { eligible, total } => write!(
                f,
                "an incidence of {eligible} eligible in {total} requests is not valid"
            ),
            Self::InvalidMinimumIncidence => {
                f.write_str("the minimum incidence must be a fraction above 0 and at most 1")
            }
            Self::NetSavingNotFinite => f.write_str("the net saving is not a finite number"),
        }
    }
}

impl std::error::Error for DecisionError {}

/// Workload incidence of eligible prefixes: requests whose prefix state was reused from
/// another variant, out of all requests (line 900).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incidence {
    eligible_requests: u64,
    total_requests: u64,
}

impl Incidence {
    pub fn new(eligible_requests: u64, total_requests: u64) -> Result<Self, DecisionError> {
        if total_requests == 0 || eligible_requests > total_requests {
            return Err(DecisionError::InvalidIncidence {
                eligible: eligible_requests,
                total: total_requests,
            });
        }
        Ok(Self {
            eligible_requests,
            total_requests,
        })
    }

    pub fn eligible_requests(&self) -> u64 {
        self.eligible_requests
    }

    pub fn total_requests(&self) -> u64 {
        self.total_requests
    }

    pub fn fraction(&self) -> f64 {
        self.eligible_requests as f64 / self.total_requests as f64
    }
}

/// The incidence below which eligible prefixes count as rare. Required configuration:
/// the plan gives no value, so there is no default.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MinimumIncidence(f64);

impl MinimumIncidence {
    pub fn new(fraction: f64) -> Result<Self, DecisionError> {
        if fraction.is_finite() && fraction > 0.0 && fraction <= 1.0 {
            Ok(Self(fraction))
        } else {
            Err(DecisionError::InvalidMinimumIncidence)
        }
    }

    pub fn get(self) -> f64 {
        self.0
    }
}

/// Whether eligible prefixes are common enough (line 900).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncidenceVerdict {
    /// At or above the minimum.
    Common,
    /// Below the minimum.
    Rare,
}

/// Compares the eligible fraction with the minimum without rounding: `eligible / total
/// >= minimum`.
pub fn judge_incidence(incidence: &Incidence, minimum: MinimumIncidence) -> IncidenceVerdict {
    if incidence.eligible_requests as f64 >= minimum.0 * incidence.total_requests as f64 {
        IncidenceVerdict::Common
    } else {
        IncidenceVerdict::Rare
    }
}

/// Where the requests behind an incidence came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkloadSource {
    /// Generated from a seed: says nothing about real users' workloads.
    Synthetic { seed: u64 },
    /// A recorded workload trace, by digest.
    Recorded { trace: Digest },
}

/// Everything line 900 decides on.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PassStopEvidence {
    /// Results that differed from the normal path.
    pub exactness_violations: u64,
    /// Reuses that no authorization covered.
    pub unauthorized_reuses: u64,
    /// Compute seconds of the strongest compatible baseline minus the candidate's, keying
    /// and handoff included.
    pub net_saving_seconds: f64,
    pub incidence: Incidence,
    pub minimum_incidence: MinimumIncidence,
    pub workload: WorkloadSource,
}

/// Why the mechanism stops.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StopReason {
    ExactnessViolated {
        violations: u64,
    },
    UnauthorizedSharing {
        reuses: u64,
    },
    /// No strictly positive net saving after keying and handoff costs.
    NoNetSaving {
        net_saving_seconds: f64,
    },
}

/// Evidence a pass needs and the run did not have.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MissingEvidence {
    /// Incidence measured on a recorded workload, not a synthetic one.
    RealisticWorkload,
    /// Yougori measurements on real hardware; fake-substrate runs back no performance
    /// claim (S12 G0).
    HardwareMeasurement,
    /// §4.13 line 792: the closest papers read in full and compared.
    LiteratureComparison,
}

/// The line 900 decision.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PassStopDecision {
    /// Every check holds on measurements over a recorded workload.
    Pass,
    /// Eligible prefixes are rare in a recorded workload: ship support only for
    /// explicitly compatible families.
    NarrowToExplicitFamilies {
        incidence: Incidence,
    },
    Stop(StopReason),
    /// No check failed, but the evidence for a pass is missing; GPU-N3 stays optional
    /// (§4.17 line 904). The incidence verdict is kept for information; it decides
    /// nothing until the workload is recorded and measured.
    RemainOptional {
        missing_workload: bool,
        missing_measurement: bool,
        incidence_verdict: IncidenceVerdict,
    },
}

impl PassStopDecision {
    /// The evidence a pass still needs, in order.
    pub fn missing(&self) -> Vec<MissingEvidence> {
        match self {
            Self::RemainOptional {
                missing_workload,
                missing_measurement,
                ..
            } => [
                (*missing_workload, MissingEvidence::RealisticWorkload),
                (*missing_measurement, MissingEvidence::HardwareMeasurement),
            ]
            .into_iter()
            .filter_map(|(missing, evidence)| missing.then_some(evidence))
            .collect(),
            _ => Vec::new(),
        }
    }
}

/// Line 900 on `evidence`, whose numbers come from runs with `provenance`. Only Yougori
/// evidence counts as a measurement; a fake-substrate run never passes.
pub fn decide_pass_stop(
    evidence: &PassStopEvidence,
    provenance: &Provenance,
) -> Result<PassStopDecision, DecisionError> {
    decide(evidence, provenance.yougori_evidence().is_ok())
}

fn decide(evidence: &PassStopEvidence, measured: bool) -> Result<PassStopDecision, DecisionError> {
    if !evidence.net_saving_seconds.is_finite() {
        return Err(DecisionError::NetSavingNotFinite);
    }
    if evidence.exactness_violations > 0 {
        return Ok(PassStopDecision::Stop(StopReason::ExactnessViolated {
            violations: evidence.exactness_violations,
        }));
    }
    if evidence.unauthorized_reuses > 0 {
        return Ok(PassStopDecision::Stop(StopReason::UnauthorizedSharing {
            reuses: evidence.unauthorized_reuses,
        }));
    }
    if evidence.net_saving_seconds <= 0.0 {
        return Ok(PassStopDecision::Stop(StopReason::NoNetSaving {
            net_saving_seconds: evidence.net_saving_seconds,
        }));
    }
    let verdict = judge_incidence(&evidence.incidence, evidence.minimum_incidence);
    let recorded = matches!(evidence.workload, WorkloadSource::Recorded { .. });
    if recorded && verdict == IncidenceVerdict::Rare {
        return Ok(PassStopDecision::NarrowToExplicitFamilies {
            incidence: evidence.incidence,
        });
    }
    if !recorded || !measured {
        return Ok(PassStopDecision::RemainOptional {
            missing_workload: !recorded,
            missing_measurement: !measured,
            incidence_verdict: verdict,
        });
    }
    Ok(PassStopDecision::Pass)
}

/// Whether the §4.13 literature comparison has been done.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LiteratureComparison {
    NotDone,
    /// The closest systems were compared and a difference shown; the digest names the
    /// comparison document.
    DifferenceDemonstrated {
        comparison: Digest,
    },
}

/// §4.17 item 6: useful integration, supported original contribution, inconclusive or
/// rejected, plus the narrowing of line 900.
#[derive(Clone, Debug, PartialEq)]
pub enum ClaimResult {
    UsefulIntegration,
    SupportedOriginalContribution,
    Inconclusive {
        missing: Vec<MissingEvidence>,
    },
    /// Support only explicitly compatible families (line 900).
    Narrowed {
        incidence: Incidence,
    },
    Rejected(StopReason),
}

/// The claim result a decision supports. A pass without the literature comparison is a
/// useful integration, not an original contribution.
pub fn claim_result(decision: &PassStopDecision, literature: LiteratureComparison) -> ClaimResult {
    match decision {
        PassStopDecision::Stop(reason) => ClaimResult::Rejected(*reason),
        PassStopDecision::NarrowToExplicitFamilies { incidence } => ClaimResult::Narrowed {
            incidence: *incidence,
        },
        PassStopDecision::RemainOptional { .. } => {
            let mut missing = decision.missing();
            if literature == LiteratureComparison::NotDone {
                missing.push(MissingEvidence::LiteratureComparison);
            }
            ClaimResult::Inconclusive { missing }
        }
        PassStopDecision::Pass => match literature {
            LiteratureComparison::NotDone => ClaimResult::UsefulIntegration,
            LiteratureComparison::DifferenceDemonstrated { .. } => {
                ClaimResult::SupportedOriginalContribution
            }
        },
    }
}

/// §4.17 item 1.
pub const CONTRIBUTION: &str = "Identity-based eligibility for reusing the exact output of \
a shared leading operator sequence across immutable variants of one model family: a typed \
state key over operator and kernel ABI, manifest-derived parameter identities, parent state \
keys, the exact input with its preceding context, attention and position semantics, \
dtype and layout, adapter effects, a deterministic execution profile, bound seeds or \
operator state and the trust scope, with caching only at profitable branch boundaries \
and sharing only under the producing authority or a scoped grant.";

/// §4.17 item 2.
pub const CLOSEST_PRIOR_WORK: &str = "Mainstream (USENIX ATC 2018) shares a common DNN stem \
across applications fine-tuned from one pre-trained model and chooses how many layers to \
share by an accuracy and throughput trade-off; ordinary per-model prefix caching reuses KV \
only under one full model identity.";

/// §4.17 item 3.
pub const DIFFERENCE_TESTED: &str = "Whether identity checks alone, without retraining or \
accuracy trade-offs, find the provably identical prefix of independently published \
variants and reuse it bit-identically across variants where per-model prefix caching \
misses, with keying and handoff costs counted.";

/// §4.17 item 4: the correctness assumptions.
pub const ASSUMPTIONS: [&str; 3] = [
    "Kernels are deterministic and batch-invariant under the declared execution profile.",
    "Equal manifest-derived parameter identities mean equal bytes with equal interpretation.",
    "An operator's output depends only on the components its state key binds.",
];

/// §4.17 item 4: the smallest counterexample that breaks them.
pub const SMALLEST_COUNTEREXAMPLE: &str = "One operator whose kernel picks a split-K \
reduction by batch size: the same prefix computed alone and in a batch of two differs in \
the last bit under an identical key. The profile therefore must declare batch \
invariance, and a batch-dependent profile always takes the normal path.";

/// §4.17 item 5.
pub const COMPARISON: &str = "Independent execution (ordinary workflow) and per-model \
prefix caching (strongest compatible baseline) against verified shared-subgraph \
execution, on the fake time-controlled substrate: a verified shared-prefix pair, a control \
pair differing in the first block and a pair with equal weights under another positional \
configuration, five or more independent trials of a seeded mixed trace.";

/// The §4.17 claim record of GPU-N3.
#[derive(Clone, Debug, PartialEq)]
pub struct ClaimRecord {
    pub contribution: &'static str,
    pub closest_prior_work: &'static str,
    pub difference_tested: &'static str,
    pub assumptions: [&'static str; 3],
    pub smallest_counterexample: &'static str,
    pub comparison: &'static str,
    pub result: ClaimResult,
}

/// The claim record with `result`.
pub fn claim_record(result: ClaimResult) -> ClaimRecord {
    ClaimRecord {
        contribution: CONTRIBUTION,
        closest_prior_work: CLOSEST_PRIOR_WORK,
        difference_tested: DIFFERENCE_TESTED,
        assumptions: ASSUMPTIONS,
        smallest_counterexample: SMALLEST_COUNTEREXAMPLE,
        comparison: COMPARISON,
        result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(workload: WorkloadSource, eligible: u64) -> PassStopEvidence {
        PassStopEvidence {
            exactness_violations: 0,
            unauthorized_reuses: 0,
            net_saving_seconds: 1.5,
            incidence: Incidence::new(eligible, 100).unwrap(),
            minimum_incidence: MinimumIncidence::new(0.05).unwrap(),
            workload,
        }
    }

    const RECORDED: WorkloadSource = WorkloadSource::Recorded {
        trace: Digest::from_bytes([7; 32]),
    };

    #[test]
    fn a_pass_needs_measurements_on_a_recorded_workload_with_common_prefixes() {
        assert_eq!(
            decide(&evidence(RECORDED, 30), true).unwrap(),
            PassStopDecision::Pass
        );
        assert_eq!(
            claim_result(&PassStopDecision::Pass, LiteratureComparison::NotDone),
            ClaimResult::UsefulIntegration
        );
        assert_eq!(
            claim_result(
                &PassStopDecision::Pass,
                LiteratureComparison::DifferenceDemonstrated {
                    comparison: Digest::from_bytes([1; 32])
                }
            ),
            ClaimResult::SupportedOriginalContribution
        );
    }

    #[test]
    fn rare_prefixes_in_a_recorded_workload_narrow_even_with_measurements() {
        let decision = decide(&evidence(RECORDED, 4), true).unwrap();
        assert_eq!(
            decision,
            PassStopDecision::NarrowToExplicitFamilies {
                incidence: Incidence::new(4, 100).unwrap()
            }
        );
        assert!(matches!(
            claim_result(&decision, LiteratureComparison::NotDone),
            ClaimResult::Narrowed { .. }
        ));
    }

    #[test]
    fn measurements_without_a_recorded_workload_remain_optional() {
        let decision = decide(&evidence(WorkloadSource::Synthetic { seed: 1 }, 30), true).unwrap();
        assert_eq!(decision.missing(), vec![MissingEvidence::RealisticWorkload]);
    }
}
