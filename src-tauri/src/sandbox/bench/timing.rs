//! The fake timing of a VM create and the faults injected into it (S7 line 296: "slot
//! reservation, storage clone contention, pool exhaustion and replenishment"; S8 line
//! 149 failure taxonomy).
//!
//! Durations are parameters of the fake, never measurements: the first command after a
//! cold boot or a warm restore takes its base time plus a contention term for every
//! other VM still booting when it starts, scaled by a seeded variation. The same seed
//! gives the same run.

use std::collections::BTreeMap;

use serde::Serialize;

use super::BenchError;
use crate::sandbox::lifecycle::BootPath;

/// A small deterministic generator (SplitMix64); the only source of variation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SeededRng {
    state: u64,
}

impl SeededRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.state;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    /// A value in `0..=bound`.
    pub fn up_to(&mut self, bound: u64) -> u64 {
        match bound.checked_add(1) {
            Some(span) => self.next_u64() % span,
            None => self.next_u64(),
        }
    }
}

/// The fake substrate's timing (S12 G0: a fake, time-controlled runner).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FakeVmTiming {
    /// Create initiated to the backend's acknowledgment; recorded apart and never the
    /// end of the first-command clock (S8 line 317).
    pub api_ack_nanos: u64,
    /// Create initiated to the first command after an uncontended cold boot.
    pub cold_first_command_nanos: u64,
    /// Create initiated to the first command after an uncontended warm restore.
    pub warm_first_command_nanos: u64,
    /// Added for every other VM still booting when a boot starts: slot and storage clone
    /// contention (S7 line 296).
    pub contention_nanos_per_booting_vm: u64,
    /// The seeded variation: each duration is scaled by a factor drawn uniformly from
    /// `1 ± jitter_per_mille / 1000`.
    pub jitter_per_mille: u32,
    /// Preparing one warm-pool clone, charged to the measured path (S10 line 353).
    pub clone_prepare_nanos: u64,
    pub seed: u64,
}

impl FakeVmTiming {
    /// The acknowledgment precedes every first command, both bases are positive and the
    /// variation stays below the duration.
    pub fn check(&self) -> Result<(), BenchError> {
        if self.cold_first_command_nanos == 0 || self.warm_first_command_nanos == 0 {
            return Err(BenchError::InvalidParameter {
                field: "first_command_nanos",
                reason: "a first command takes time",
            });
        }
        if self.api_ack_nanos > self.cold_first_command_nanos
            || self.api_ack_nanos > self.warm_first_command_nanos
        {
            return Err(BenchError::InvalidParameter {
                field: "api_ack_nanos",
                reason: "the acknowledgment comes no later than an uncontended first command",
            });
        }
        if self.jitter_per_mille >= 1000 {
            return Err(BenchError::InvalidParameter {
                field: "jitter_per_mille",
                reason: "below 1000, so no duration scales to zero",
            });
        }
        Ok(())
    }

    /// The base of a boot on `path`.
    pub fn base_nanos(&self, path: BootPath) -> u64 {
        match path {
            BootPath::Cold => self.cold_first_command_nanos,
            BootPath::WarmRestore => self.warm_first_command_nanos,
        }
    }

    /// Boot start to first command for a boot on `path` that starts while `booting`
    /// other VMs boot:
    /// `(base + contention × booting) × (1000 − jitter + u) / 1000`, with `u` drawn from
    /// `0..=2 × jitter`, and never before the acknowledgment.
    pub fn first_command_nanos(
        &self,
        path: BootPath,
        booting: u64,
        rng: &mut SeededRng,
    ) -> Result<u64, BenchError> {
        let jitter = u64::from(self.jitter_per_mille);
        let factor = 1000 - jitter + rng.up_to(2 * jitter);
        let contended = u128::from(self.contention_nanos_per_booting_vm)
            .checked_mul(u128::from(booting))
            .and_then(|contention| contention.checked_add(u128::from(self.base_nanos(path))))
            .ok_or(BenchError::Overflow)?;
        let scaled = contended
            .checked_mul(u128::from(factor))
            .ok_or(BenchError::Overflow)?
            / 1000;
        let nanos = u64::try_from(scaled).map_err(|_| BenchError::Overflow)?;
        Ok(nanos.max(self.api_ack_nanos))
    }

    /// The charge of preparing `clones` warm-pool clones.
    pub fn prepare_nanos(&self, clones: u64) -> Result<u64, BenchError> {
        self.clone_prepare_nanos
            .checked_mul(clones)
            .ok_or(BenchError::Overflow)
    }
}

/// A fault the fake injects into one attempt, each landing in the S8 failure taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "fault", rename_all = "snake_case")]
pub enum InjectedFault {
    /// The backend refuses to create the VM: a rejection by the backend.
    BackendRefusesCreate,
    /// The first command comes this much later: a deadline failure or a timeout.
    SlowFirstCommand { extra_nanos: u64 },
    /// The guest's first command fails: a command failure.
    GuestCommandFails,
    /// The VM exits this long after its boot starts, before any command: an early
    /// termination when it precedes the first command.
    VmExitsEarly { after_nanos: u64 },
    /// The guest presents an application identity another clone already has (S10 line
    /// 181): a duplicate identity.
    DuplicateGuestIdentity,
}

/// Faults by attempt number, counted from zero across every burst of a run, and faults
/// of retries by their first attempt's number and their retry number. A retry is its own
/// attempt: a first attempt's fault never carries over to its retries.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct FaultPlan {
    faults: BTreeMap<u32, InjectedFault>,
    retry_faults: BTreeMap<u32, BTreeMap<u32, InjectedFault>>,
}

impl FaultPlan {
    /// No faults.
    pub fn none() -> Self {
        Self::default()
    }

    /// Adds `fault` to attempt `attempt`, replacing an earlier one.
    pub fn with(mut self, attempt: u32, fault: InjectedFault) -> Self {
        self.faults.insert(attempt, fault);
        self
    }

    pub fn get(&self, attempt: u32) -> Option<InjectedFault> {
        self.faults.get(&attempt).copied()
    }

    /// Adds `fault` to retry `retry_number` (counted from one) of first attempt
    /// `first_attempt`, replacing an earlier one.
    pub fn with_retry(
        mut self,
        first_attempt: u32,
        retry_number: u32,
        fault: InjectedFault,
    ) -> Self {
        self.retry_faults
            .entry(first_attempt)
            .or_default()
            .insert(retry_number, fault);
        self
    }

    pub fn retry_fault(&self, first_attempt: u32, retry_number: u32) -> Option<InjectedFault> {
        self.retry_faults
            .get(&first_attempt)
            .and_then(|retries| retries.get(&retry_number))
            .copied()
    }

    /// Faults of first attempts and of retries.
    pub fn len(&self) -> usize {
        self.retry_faults
            .values()
            .map(BTreeMap::len)
            .fold(self.faults.len(), usize::saturating_add)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn timing(jitter_per_mille: u32) -> FakeVmTiming {
        FakeVmTiming {
            api_ack_nanos: 40_000_000,
            cold_first_command_nanos: 900_000_000,
            warm_first_command_nanos: 250_000_000,
            contention_nanos_per_booting_vm: 50_000_000,
            jitter_per_mille,
            clone_prepare_nanos: 600_000_000,
            seed: 7,
        }
    }

    #[test]
    fn the_first_command_formula_holds_without_variation() {
        let timing = timing(0);
        timing.check().unwrap();
        let mut rng = SeededRng::new(timing.seed);
        // 900 ms cold, plus 50 ms for each of three VMs still booting.
        assert_eq!(
            timing
                .first_command_nanos(BootPath::Cold, 3, &mut rng)
                .unwrap(),
            1_050_000_000
        );
        assert_eq!(
            timing
                .first_command_nanos(BootPath::WarmRestore, 0, &mut rng)
                .unwrap(),
            250_000_000
        );
        assert_eq!(timing.prepare_nanos(3).unwrap(), 1_800_000_000);
        assert_eq!(timing.prepare_nanos(u64::MAX), Err(BenchError::Overflow));
    }

    #[test]
    fn variation_is_bounded_and_seeded() {
        let timing = timing(100);
        let mut first = SeededRng::new(timing.seed);
        let mut second = SeededRng::new(timing.seed);
        for _ in 0..1_000 {
            let left = timing
                .first_command_nanos(BootPath::Cold, 0, &mut first)
                .unwrap();
            let right = timing
                .first_command_nanos(BootPath::Cold, 0, &mut second)
                .unwrap();
            assert_eq!(left, right, "the same seed gives the same run");
            assert!((810_000_000..=990_000_000).contains(&left), "{left}");
        }
        assert_ne!(
            SeededRng::new(1).next_u64(),
            SeededRng::new(2).next_u64(),
            "different seeds differ"
        );
    }

    #[test]
    fn invalid_timings_are_refused() {
        let mut slow_ack = timing(0);
        slow_ack.api_ack_nanos = slow_ack.warm_first_command_nanos + 1;
        let mut zero = timing(0);
        zero.cold_first_command_nanos = 0;
        let full_jitter = timing(1000);
        for (bad, field) in [
            (slow_ack, "api_ack_nanos"),
            (zero, "first_command_nanos"),
            (full_jitter, "jitter_per_mille"),
        ] {
            assert!(
                matches!(bad.check(), Err(BenchError::InvalidParameter { field: found, .. }) if found == field),
                "{field}"
            );
        }
    }

    #[test]
    fn the_acknowledgment_never_follows_the_first_command() {
        let mut timing = timing(999);
        timing.api_ack_nanos = timing.warm_first_command_nanos;
        let mut rng = SeededRng::new(3);
        for _ in 0..200 {
            assert!(
                timing
                    .first_command_nanos(BootPath::WarmRestore, 0, &mut rng)
                    .unwrap()
                    >= timing.api_ack_nanos
            );
        }
    }

    #[test]
    fn faults_are_kept_per_attempt() {
        let plan = FaultPlan::none()
            .with(2, InjectedFault::GuestCommandFails)
            .with(5, InjectedFault::BackendRefusesCreate);
        assert_eq!(plan.len(), 2);
        assert_eq!(plan.get(2), Some(InjectedFault::GuestCommandFails));
        assert_eq!(plan.get(3), None);
        assert!(FaultPlan::none().is_empty());
        // A retry's fault is its own; the first attempt's does not carry over.
        let retried = plan.with_retry(5, 2, InjectedFault::GuestCommandFails);
        assert_eq!(retried.len(), 3);
        assert_eq!(
            retried.retry_fault(5, 2),
            Some(InjectedFault::GuestCommandFails)
        );
        assert_eq!(retried.retry_fault(5, 1), None);
        assert_eq!(retried.retry_fault(2, 2), None);
        assert!(!FaultPlan::none()
            .with_retry(0, 1, InjectedFault::BackendRefusesCreate)
            .is_empty());
    }
}
