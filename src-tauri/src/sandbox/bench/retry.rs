//! Bounded retries of refused creates, each its own CORE-08 record linked to its first
//! attempt (S8 line 321; S10 line 351; S11 BENCH-05 line 369 and BENCH-13 line 377;
//! VM-W49 line 2672).
//!
//! S8: "A success rate has the denominator of every initial attempt" and "A successful
//! retry is a second result, not a rewrite of the failed first attempt." A plan's
//! [`RetryPolicy`] is off unless one is set. When it is on, a create refused with a
//! rejection kind the policy names is created again after the policy's delay, at most the
//! policy's number of times per first attempt. Never retried: a rejection the policy does
//! not name, a capacity refusal the ledger says cannot progress (S10 line 351: the output
//! identifies "whether a retry can make progress"), a rollback that stalled, and every
//! failure that is not a rejection (a timeout, deadline failure, command failure, early
//! termination or duplicate identity).
//!
//! A retry is its own attempt: its own operation and record, whose CORE-08 role names its
//! first attempt and its number, its own first-command clock from its own create, and its
//! own stream of the fake timing's variation, so it never shifts the draws of a later
//! first attempt. It creates the same sandbox again; the lifecycle relaunches it with a
//! new boot generation through the same authority checks. Success rates, the failure
//! taxonomy, first-command tails, burst windows and the saturation knee count first
//! attempts only; the [`RetryReport`] stands beside them.

use std::collections::{BTreeMap, BTreeSet};

use serde::Serialize;

use super::report::{AttemptSummary, RejectionKind};
use super::BenchError;
use crate::foundation::coordination::{LaunchFailure, RetryProspect};
use crate::foundation::ids::OperationId;
use crate::foundation::report::{
    AttemptLedger, ConfidenceLevel, RetryTally, SuccessRate, WilsonInterval,
};

/// The most retries a policy allows per first attempt. The plan names no number; the
/// bound keeps every run finite and small.
pub const MAX_RETRIES_PER_ATTEMPT: u32 = 5;

/// Which refused creates a plan creates again, how often and after what delay. Off by
/// default: an off policy names no kind and allows no retry.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct RetryPolicy {
    retry_on: BTreeSet<RejectionKind>,
    max_retries: u32,
    delay_nanos: u64,
}

impl RetryPolicy {
    /// No retries: every refused create stays one attempt.
    pub fn off() -> Self {
        Self::default()
    }

    /// Retries a create refused with one of `retry_on`, up to `max_retries` times per
    /// first attempt (one to [`MAX_RETRIES_PER_ATTEMPT`]), each `delay_nanos` (positive)
    /// after the refusal it follows. A rollback that stalled cannot be named.
    pub fn new(
        retry_on: impl IntoIterator<Item = RejectionKind>,
        max_retries: u32,
        delay_nanos: u64,
    ) -> Result<Self, BenchError> {
        let retry_on: BTreeSet<RejectionKind> = retry_on.into_iter().collect();
        if retry_on.is_empty() {
            return Err(BenchError::InvalidParameter {
                field: "retry_on",
                reason: "a retry policy names the rejection kinds it retries",
            });
        }
        if retry_on.contains(&RejectionKind::RollbackStalled) {
            return Err(BenchError::InvalidParameter {
                field: "retry_on",
                reason: "a rollback that stalled still holds its perimeter and reservation; \
                         it is reconciled, never retried",
            });
        }
        if max_retries == 0 || max_retries > MAX_RETRIES_PER_ATTEMPT {
            return Err(BenchError::InvalidParameter {
                field: "max_retries",
                reason: "from one retry per first attempt up to the bound",
            });
        }
        if delay_nanos == 0 {
            return Err(BenchError::InvalidParameter {
                field: "delay_nanos",
                reason: "a retry waits a declared, positive delay after the refusal",
            });
        }
        Ok(Self {
            retry_on,
            max_retries,
            delay_nanos,
        })
    }

    pub fn is_off(&self) -> bool {
        self.max_retries == 0
    }

    /// The rejection kinds the policy retries; empty when off.
    pub fn retry_on(&self) -> &BTreeSet<RejectionKind> {
        &self.retry_on
    }

    /// Whether the policy names `kind`.
    pub fn names(&self, kind: RejectionKind) -> bool {
        self.retry_on.contains(&kind)
    }

    /// Retries per first attempt at most; zero when off.
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// From the refusal to the retry's create.
    pub fn delay_nanos(&self) -> u64 {
        self.delay_nanos
    }

    /// Whether a create refused with `kind` is created again, when `retries_so_far`
    /// retries of its first attempt have run; `prospect` is the ledger's word on a
    /// capacity refusal. The kind is checked first, then the prospect, then the bound.
    pub fn decide(
        &self,
        kind: RejectionKind,
        prospect: Option<RetryProspect>,
        retries_so_far: u32,
    ) -> RetryDecision {
        if !self.names(kind) {
            return RetryDecision::Stop {
                reason: NoRetry::NotNamed,
            };
        }
        if prospect == Some(RetryProspect::CannotProgress) {
            return RetryDecision::Stop {
                reason: NoRetry::CannotProgress,
            };
        }
        if retries_so_far >= self.max_retries {
            return RetryDecision::Stop {
                reason: NoRetry::BudgetSpent,
            };
        }
        RetryDecision::Retry {
            retry_number: retries_so_far.saturating_add(1),
        }
    }

    /// The ledger's prospect for a launch that rolled back, when the ledger refused it.
    pub fn prospect(failure: &LaunchFailure) -> Option<RetryProspect> {
        match failure {
            LaunchFailure::Capacity { refusal } => Some(refusal.retry()),
            _ => None,
        }
    }
}

/// Whether a refused create is created again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum RetryDecision {
    /// Created again as retry `retry_number` of its first attempt, counted from one.
    Retry {
        retry_number: u32,
    },
    Stop {
        reason: NoRetry,
    },
}

/// Why a refused create was not created again.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NoRetry {
    /// The policy does not name the rejection kind; an off policy names none.
    NotNamed,
    /// The ledger says retrying cannot make progress: the request exceeds what the host,
    /// the tenant's budget or the parent can ever provide.
    CannotProgress,
    /// The first attempt's retries are used up.
    BudgetSpent,
}

impl NoRetry {
    pub const ALL: [Self; 3] = [Self::NotNamed, Self::CannotProgress, Self::BudgetSpent];
}

/// One retry as the runner saw it, beside its raw record.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RetrySummary {
    /// The first attempt's number, which `attempt.index` repeats.
    pub first_attempt: u32,
    /// The first attempt's operation, which the retry's record links to.
    pub first_operation: OperationId,
    /// Counted from one per first attempt.
    pub retry_number: u32,
    /// The rejection of the attempt this retry followed.
    pub after: RejectionKind,
    /// The retry itself: the same sandbox, its own operation, boot and outcome.
    pub attempt: AttemptSummary,
}

/// What the runner collected about retries during a run.
#[derive(Clone, Debug, Default, PartialEq)]
pub(crate) struct RetryOutcomes {
    pub retries: Vec<RetrySummary>,
    pub not_retried: BTreeMap<NoRetry, u64>,
}

/// The retries of a run, reported beside its first-attempt results and never folded into
/// them (S8 line 321; BENCH-10 line 374 reports first-attempt success with retries apart).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct RetryReport {
    pub policy: RetryPolicy,
    /// Every retry, in the order created.
    pub attempts: Vec<RetrySummary>,
    /// CORE-08's tally: retries, successful retries and first attempts a retry recovered.
    pub tally: RetryTally,
    /// First attempts that succeeded or that one of their retries completed, over every
    /// first attempt: success conditional on retries, never the first-attempt rate.
    pub success_with_retries: SuccessRate,
    pub success_with_retries_wilson: WilsonInterval,
    /// Rejected retries by kind; every kind is present, zero included.
    pub rejections: BTreeMap<RejectionKind, u64>,
    /// Rejected attempts, first attempts and retries, that were not created again, by
    /// reason; every reason is present, zero included.
    pub not_retried: BTreeMap<NoRetry, u64>,
}

impl RetryReport {
    pub(crate) fn new(
        policy: RetryPolicy,
        ledger: &AttemptLedger,
        outcomes: RetryOutcomes,
    ) -> Result<Self, BenchError> {
        let first_attempts = ledger.initial_attempts().count() as u64;
        let success_with_retries =
            SuccessRate::new(ledger.completed_valid_tasks(), first_attempts)?;
        let mut rejections: BTreeMap<RejectionKind, u64> =
            RejectionKind::ALL.iter().map(|kind| (*kind, 0)).collect();
        for kind in outcomes
            .retries
            .iter()
            .filter_map(|retry| retry.attempt.rejection)
        {
            *rejections.entry(kind).or_insert(0) += 1;
        }
        let mut not_retried: BTreeMap<NoRetry, u64> =
            NoRetry::ALL.iter().map(|reason| (*reason, 0)).collect();
        for (reason, count) in outcomes.not_retried {
            *not_retried.entry(reason).or_insert(0) += count;
        }
        Ok(Self {
            policy,
            attempts: outcomes.retries,
            tally: ledger.retry_tally(),
            success_with_retries_wilson: success_with_retries.wilson(ConfidenceLevel::NinetyFive),
            success_with_retries,
            rejections,
            not_retried,
        })
    }

    /// The retries of first attempt `first_attempt`, in order.
    pub fn of(&self, first_attempt: u32) -> impl Iterator<Item = &RetrySummary> + '_ {
        self.attempts
            .iter()
            .filter(move |retry| retry.first_attempt == first_attempt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::coordination::{CapacityLimit, CapacityRefusal, ResourceKind};

    const SECOND: u64 = 1_000_000_000;

    #[test]
    fn retries_are_off_by_default() {
        let off = RetryPolicy::default();
        assert_eq!(off, RetryPolicy::off());
        assert!(off.is_off());
        assert!(off.retry_on().is_empty());
        for kind in RejectionKind::ALL {
            assert_eq!(
                off.decide(kind, None, 0),
                RetryDecision::Stop {
                    reason: NoRetry::NotNamed
                }
            );
        }
    }

    #[test]
    fn a_policy_is_explicit_and_bounded() {
        for (kinds, max, delay, field) in [
            (vec![], 1, SECOND, "retry_on"),
            (vec![RejectionKind::RollbackStalled], 1, SECOND, "retry_on"),
            (vec![RejectionKind::HostCapacity], 0, SECOND, "max_retries"),
            (
                vec![RejectionKind::HostCapacity],
                MAX_RETRIES_PER_ATTEMPT + 1,
                SECOND,
                "max_retries",
            ),
            (vec![RejectionKind::HostCapacity], 1, 0, "delay_nanos"),
        ] {
            assert!(
                matches!(
                    RetryPolicy::new(kinds, max, delay),
                    Err(BenchError::InvalidParameter { field: found, .. }) if found == field
                ),
                "{field}"
            );
        }
        let policy = RetryPolicy::new(
            [RejectionKind::HostCapacity, RejectionKind::HostCapacity],
            MAX_RETRIES_PER_ATTEMPT,
            SECOND,
        )
        .unwrap();
        assert!(!policy.is_off());
        assert_eq!(policy.retry_on().len(), 1);
        assert_eq!(policy.delay_nanos(), SECOND);
    }

    #[test]
    fn only_a_named_rejection_that_can_progress_is_retried_within_the_bound() {
        let policy = RetryPolicy::new([RejectionKind::HostCapacity], 2, SECOND).unwrap();
        assert_eq!(
            policy.decide(RejectionKind::HostCapacity, None, 0),
            RetryDecision::Retry { retry_number: 1 }
        );
        assert_eq!(
            policy.decide(
                RejectionKind::HostCapacity,
                Some(RetryProspect::CanProgress),
                1
            ),
            RetryDecision::Retry { retry_number: 2 }
        );
        assert_eq!(
            policy.decide(RejectionKind::HostCapacity, None, 2),
            RetryDecision::Stop {
                reason: NoRetry::BudgetSpent
            }
        );
        assert_eq!(
            policy.decide(
                RejectionKind::HostCapacity,
                Some(RetryProspect::CannotProgress),
                0
            ),
            RetryDecision::Stop {
                reason: NoRetry::CannotProgress
            }
        );
        // Naming comes first: an unnamed kind is never retried, whatever its prospect.
        assert_eq!(
            policy.decide(
                RejectionKind::QueueFull,
                Some(RetryProspect::CanProgress),
                0
            ),
            RetryDecision::Stop {
                reason: NoRetry::NotNamed
            }
        );
        // The prospect is the ledger's, and only a capacity refusal has one.
        let beyond = LaunchFailure::Capacity {
            refusal: CapacityRefusal::Insufficient {
                resource: ResourceKind::HostMemoryBytes,
                limit: CapacityLimit::Host,
                requested: 8,
                available: 4,
                retry: RetryProspect::CannotProgress,
            },
        };
        assert_eq!(
            RetryPolicy::prospect(&beyond),
            Some(RetryProspect::CannotProgress)
        );
        let full = LaunchFailure::Capacity {
            refusal: CapacityRefusal::QueueFull {
                resource: ResourceKind::CpuInitializationSlots,
            },
        };
        assert_eq!(
            RetryPolicy::prospect(&full),
            Some(RetryProspect::CanProgress)
        );
        let not_ready = LaunchFailure::NotReady {
            detail: "injected".to_owned(),
        };
        assert_eq!(RetryPolicy::prospect(&not_ready), None);
    }
}
