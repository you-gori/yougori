//! Raw attempt outcomes and their denominators (S8: "A success rate has the denominator
//! of every initial attempt … A successful retry is a second result, not a rewrite of the
//! failed first attempt").

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use super::error::ReportError;
use super::record::{AttemptRole, FailureKind, RunRecord, RunSubstrate};
use super::stats::SuccessRate;
use crate::foundation::ids::OperationId;

/// The append-only raw attempts of one case variant and scenario. Results are never
/// replaced: a retry is added as its own record, linked to its first attempt.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct AttemptLedger {
    records: Vec<RunRecord>,
}

impl AttemptLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds every record in order, refusing as [`AttemptLedger::add`] does.
    pub fn from_records(records: impl IntoIterator<Item = RunRecord>) -> Result<Self, ReportError> {
        let mut ledger = Self::new();
        for record in records {
            ledger.add(record)?;
        }
        Ok(ledger)
    }

    /// Adds one validated attempt. Refuses a second record with the same operation; a
    /// record of another case, variant, scenario, execution category, start temperature
    /// (S8: "Run cold and warm states separately") or substrate (fake or real); a retry
    /// whose first attempt is unknown, is itself a retry or already succeeded; and a
    /// repeated retry number.
    pub fn add(&mut self, record: RunRecord) -> Result<(), ReportError> {
        record.validate()?;
        if let Some(first) = self.records.first() {
            let temperature = |run: &RunRecord| run.state.value().map(|state| state.temperature);
            let fake = |run: &RunRecord| run.substrate == RunSubstrate::FakeTimeControlled;
            if first.attempt.bench != record.attempt.bench
                || first.attempt.variant != record.attempt.variant
                || first.scenario != record.scenario
                || first.execution_category != record.execution_category
                || temperature(first) != temperature(&record)
                || fake(first) != fake(&record)
            {
                return Err(ReportError::MixedCases);
            }
        }
        if self.find(&record.attempt.operation).is_some() {
            return Err(ReportError::DuplicateAttempt);
        }
        if let AttemptRole::Retry {
            first_attempt,
            retry_number,
        } = &record.attempt.role
        {
            let first = self
                .find(first_attempt)
                .ok_or(ReportError::UnknownFirstAttempt)?;
            if !first.is_initial() {
                return Err(ReportError::RetryOfRetry);
            }
            let chain: Vec<&RunRecord> = std::iter::once(first)
                .chain(self.retries_of(first_attempt))
                .collect();
            if chain.iter().any(|attempt| attempt.is_success()) {
                return Err(ReportError::RetryAfterSuccess);
            }
            if self.retries_of(first_attempt).any(|retry| {
                matches!(&retry.attempt.role, AttemptRole::Retry { retry_number: number, .. } if number == retry_number)
            }) {
                return Err(ReportError::DuplicateRetryNumber);
            }
        }
        self.records.push(record);
        Ok(())
    }

    fn find(&self, operation: &OperationId) -> Option<&RunRecord> {
        self.records
            .iter()
            .find(|record| &record.attempt.operation == operation)
    }

    pub fn records(&self) -> &[RunRecord] {
        &self.records
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    pub fn initial_attempts(&self) -> impl Iterator<Item = &RunRecord> {
        self.records.iter().filter(|record| record.is_initial())
    }

    /// The retries linked to `first_attempt`.
    pub fn retries_of<'a>(
        &'a self,
        first_attempt: &'a OperationId,
    ) -> impl Iterator<Item = &'a RunRecord> + 'a {
        self.records.iter().filter(move |record| {
            matches!(&record.attempt.role, AttemptRole::Retry { first_attempt: first, .. } if first == first_attempt)
        })
    }

    /// Successful initial attempts over every initial attempt (S8). Retries change
    /// neither number.
    pub fn success_rate(&self) -> Result<SuccessRate, ReportError> {
        let attempts = self.initial_attempts().count() as u64;
        let successes = self
            .initial_attempts()
            .filter(|record| record.is_success())
            .count() as u64;
        SuccessRate::new(successes, attempts)
    }

    /// The failure taxonomy of the initial attempts (S8).
    pub fn failures(&self) -> FailureCounts {
        let mut counts = FailureCounts::default();
        for failure in self.initial_attempts().filter_map(RunRecord::failure) {
            counts.add(failure);
        }
        counts
    }

    /// Retry outcomes, reported beside the first-attempt rate (S8, BENCH-10).
    pub fn retry_tally(&self) -> RetryTally {
        let retries = self.records.iter().filter(|record| !record.is_initial());
        let (attempted, succeeded) =
            retries.fold((0u64, 0u64), |(attempted, succeeded), record| {
                (attempted + 1, succeeded + u64::from(record.is_success()))
            });
        let recovered = self
            .initial_attempts()
            .filter(|first| {
                !first.is_success()
                    && self
                        .retries_of(&first.attempt.operation)
                        .any(RunRecord::is_success)
            })
            .count() as u64;
        RetryTally {
            retries: attempted,
            successful_retries: succeeded,
            recovered_first_attempts: recovered,
        }
    }

    /// Tasks completed validly by an initial attempt or one of its retries; each task
    /// counts once (S8 `completed_valid_tasks`).
    pub fn completed_valid_tasks(&self) -> u64 {
        self.initial_attempts()
            .filter(|first| {
                first.is_success()
                    || self
                        .retries_of(&first.attempt.operation)
                        .any(RunRecord::is_success)
            })
            .count() as u64
    }

    /// Initial attempts per independent burst.
    pub fn bursts(&self) -> BTreeMap<u32, u64> {
        let mut bursts = BTreeMap::new();
        for record in self.initial_attempts() {
            *bursts.entry(record.attempt.burst).or_insert(0) += 1;
        }
        bursts
    }

    pub fn burst_ids(&self) -> BTreeSet<u32> {
        self.bursts().into_keys().collect()
    }
}

/// Counts of each failure kind among initial attempts (S8 failure taxonomy).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailureCounts {
    pub rejected: u64,
    pub timeout: u64,
    pub duplicate_identity: u64,
    pub command_failure: u64,
    pub early_termination: u64,
    pub deadline_failure: u64,
    pub invalid_result: u64,
}

impl FailureCounts {
    fn slot(&mut self, kind: FailureKind) -> &mut u64 {
        match kind {
            FailureKind::Rejected => &mut self.rejected,
            FailureKind::Timeout => &mut self.timeout,
            FailureKind::DuplicateIdentity => &mut self.duplicate_identity,
            FailureKind::CommandFailure => &mut self.command_failure,
            FailureKind::EarlyTermination => &mut self.early_termination,
            FailureKind::DeadlineFailure => &mut self.deadline_failure,
            FailureKind::InvalidResult => &mut self.invalid_result,
        }
    }

    pub fn add(&mut self, kind: FailureKind) {
        let slot = self.slot(kind);
        *slot = slot.saturating_add(1);
    }

    pub fn get(&self, kind: FailureKind) -> u64 {
        match kind {
            FailureKind::Rejected => self.rejected,
            FailureKind::Timeout => self.timeout,
            FailureKind::DuplicateIdentity => self.duplicate_identity,
            FailureKind::CommandFailure => self.command_failure,
            FailureKind::EarlyTermination => self.early_termination,
            FailureKind::DeadlineFailure => self.deadline_failure,
            FailureKind::InvalidResult => self.invalid_result,
        }
    }

    pub fn total(&self) -> u64 {
        FailureKind::ALL
            .iter()
            .fold(0u64, |total, kind| total.saturating_add(self.get(*kind)))
    }
}

/// Retries are separate results (S8).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryTally {
    pub retries: u64,
    pub successful_retries: u64,
    /// Failed initial attempts that a later retry completed.
    pub recovered_first_attempts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::ExecutionCategory;
    use crate::foundation::report::fixtures::{
        failed, golden_record, label, op, serving_record, vm_record,
    };
    use crate::foundation::report::measured::Measured;
    use crate::foundation::report::record::StartTemperature;

    fn retry_of(first: &str, number: u32, operation: &str, ttft_millis: u64) -> RunRecord {
        let mut record = serving_record(operation, ttft_millis);
        record.attempt.role = AttemptRole::Retry {
            first_attempt: op(first),
            retry_number: number,
        };
        record
    }

    fn rejected(operation: &str) -> RunRecord {
        let mut record = serving_record(operation, 100);
        record.outcome = failed(FailureKind::Rejected);
        record.events.truncate(1);
        record
    }

    #[test]
    fn a_rejected_attempt_lowers_the_success_rate() {
        let mut ledger = AttemptLedger::new();
        for operation in ["op-1", "op-2", "op-3"] {
            ledger.add(serving_record(operation, 100)).unwrap();
        }
        assert_eq!(ledger.success_rate().unwrap().rate(), 1.0);
        ledger.add(rejected("op-4")).unwrap();
        let rate = ledger.success_rate().unwrap();
        assert_eq!((rate.successes(), rate.attempts()), (3, 4));
        assert_eq!(rate.rate(), 0.75);
        assert_eq!(ledger.failures().rejected, 1);
        assert_eq!(ledger.failures().total(), 1);
    }

    #[test]
    fn a_successful_retry_does_not_erase_the_failed_first_attempt() {
        let mut ledger = AttemptLedger::new();
        ledger.add(serving_record("op-1", 100)).unwrap();
        ledger.add(rejected("op-2")).unwrap();
        ledger.add(retry_of("op-2", 1, "op-2r1", 90)).unwrap();
        let rate = ledger.success_rate().unwrap();
        assert_eq!((rate.successes(), rate.attempts()), (1, 2));
        assert_eq!(ledger.failures().rejected, 1);
        assert_eq!(
            ledger.retry_tally(),
            RetryTally {
                retries: 1,
                successful_retries: 1,
                recovered_first_attempts: 1,
            }
        );
        // Both tasks completed, each counted once.
        assert_eq!(ledger.completed_valid_tasks(), 2);
        // The raw failed attempt is still there.
        assert_eq!(ledger.records().len(), 3);
        assert!(!ledger.records()[1].is_success());
    }

    #[test]
    fn retries_are_linked_and_never_rewrite() {
        let mut ledger = AttemptLedger::new();
        ledger.add(rejected("op-1")).unwrap();
        assert_eq!(
            ledger.add(retry_of("op-9", 1, "op-1r1", 90)),
            Err(ReportError::UnknownFirstAttempt)
        );
        ledger.add(retry_of("op-1", 1, "op-1r1", 90)).unwrap();
        assert_eq!(
            ledger.add(retry_of("op-1r1", 1, "op-1r2", 90)),
            Err(ReportError::RetryOfRetry)
        );
        assert_eq!(
            ledger.add(retry_of("op-1", 2, "op-1r2", 90)),
            Err(ReportError::RetryAfterSuccess)
        );
        // The same operation cannot be added again, e.g. to replace a failure.
        assert_eq!(
            ledger.add(serving_record("op-1", 80)),
            Err(ReportError::DuplicateAttempt)
        );

        let mut repeated = AttemptLedger::new();
        repeated.add(rejected("op-1")).unwrap();
        let mut failed_retry = retry_of("op-1", 1, "op-1r1", 90);
        failed_retry.outcome = failed(FailureKind::Timeout);
        failed_retry.events.truncate(1);
        repeated.add(failed_retry).unwrap();
        assert_eq!(
            repeated.add(retry_of("op-1", 1, "op-1r2", 90)),
            Err(ReportError::DuplicateRetryNumber)
        );
        repeated.add(retry_of("op-1", 2, "op-1r2", 90)).unwrap();
        assert_eq!(repeated.success_rate().unwrap().successes(), 0);
    }

    #[test]
    fn every_failure_kind_stays_in_the_denominator() {
        let mut ledger = AttemptLedger::new();
        for (index, kind) in FailureKind::ALL.iter().enumerate() {
            let mut record = serving_record(&format!("op-{index}"), 100);
            record.outcome = failed(*kind);
            record.events.truncate(1);
            record.attempt.deadline_nanos = Measured::measured(50_000_000);
            ledger.add(record).unwrap();
        }
        ledger.add(serving_record("op-ok", 100)).unwrap();
        let rate = ledger.success_rate().unwrap();
        assert_eq!((rate.successes(), rate.attempts()), (1, 8));
        for kind in FailureKind::ALL {
            assert_eq!(ledger.failures().get(kind), 1, "{kind}");
        }
    }

    #[test]
    fn a_ledger_holds_one_case() {
        let mut ledger = AttemptLedger::new();
        ledger.add(serving_record("op-1", 100)).unwrap();
        let mut other_variant = serving_record("op-2", 100);
        other_variant.attempt.variant = label("load-32");
        assert_eq!(ledger.add(other_variant), Err(ReportError::MixedCases));
        assert_eq!(
            ledger.add(vm_record("op-3", 800)),
            Err(ReportError::MixedCases)
        );
        // Cold and warm runs are summarised separately (S8).
        // The golden record is the same case woken from sleep: valid, but warm.
        let warm = golden_record();
        warm.validate().unwrap();
        assert_eq!(
            warm.state.value().map(|state| state.temperature),
            Some(StartTemperature::Warm)
        );
        assert_eq!(ledger.add(warm), Err(ReportError::MixedCases));
        // Fake and real runs are not one population.
        let mut real = serving_record("op-5", 100);
        real.substrate = RunSubstrate::AuthorizedDisposable {
            authorization: label("disposable-gpu-host-7"),
        };
        assert_eq!(ledger.add(real), Err(ReportError::MixedCases));
        let mut other_category = serving_record("op-6", 100);
        other_category.execution_category = ExecutionCategory::HostProcessModelRuntime;
        assert_eq!(ledger.add(other_category), Err(ReportError::MixedCases));
        assert_eq!(
            AttemptLedger::new().success_rate(),
            Err(ReportError::NoAttempts)
        );
    }

    #[test]
    fn bursts_count_initial_attempts() {
        let mut ledger = AttemptLedger::new();
        for (index, burst) in [0u32, 0, 1, 2, 2, 2].iter().enumerate() {
            let mut record = serving_record(&format!("op-{index}"), 100);
            record.attempt.burst = *burst;
            ledger.add(record).unwrap();
        }
        assert_eq!(ledger.bursts(), BTreeMap::from([(0, 2), (1, 1), (2, 3)]));
        assert_eq!(ledger.burst_ids().len(), 3);
    }
}
