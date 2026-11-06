//! VM §2.2 measurable objectives and §2.5 release and post-revocation bounds.
//!
//! A reduction of one configured ceiling or one measured latency is a ratio of that
//! quantity only: 1 GiB → 1 MiB is a 1024× smaller byte ceiling, not 1024× stronger
//! isolation, and it does not make leaking a small API key acceptable. A latency
//! improvement needs both values measured under the same conditions.

use std::convert::Infallible;
use std::time::Duration;

use serde::Serialize;

use super::ModelError;
use crate::foundation::ids::Digest;
use crate::foundation::report::{Provenance, SuccessRate};

/// The §2.2 objectives, each with its measurement and interpretation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityObjective {
    VmOnlyExecution,
    CredentialMinimization,
    UnauthorizedEffects,
    AuthorityReduction,
    ReleaseBound,
    RevocationLatency,
    Persistence,
    FaultContainment,
}

impl SecurityObjective {
    pub const ALL: [Self; 8] = [
        Self::VmOnlyExecution,
        Self::CredentialMinimization,
        Self::UnauthorizedEffects,
        Self::AuthorityReduction,
        Self::ReleaseBound,
        Self::RevocationLatency,
        Self::Persistence,
        Self::FaultContainment,
    ];

    pub const fn measurement(self) -> &'static str {
        match self {
            Self::VmOnlyExecution => {
                "fraction of production sandbox launches using a verified hardware VM"
            }
            Self::CredentialMinimization => {
                "long-lived external credentials intentionally delivered to the guest"
            }
            Self::UnauthorizedEffects => {
                "effects outside the contract in a fixed adversarial test corpus"
            }
            Self::AuthorityReduction => "reachable operation/resource pairs before and after",
            Self::ReleaseBound => "maximum authorized outbound bytes/effects per generation",
            Self::RevocationLatency => {
                "revocation request to denial of new authorization; separately to \
                 closure/termination"
            }
            Self::Persistence => "state surviving task teardown or service renewal",
            Self::FaultContainment => {
                "invariants surviving specific failed guards or compromised components"
            }
        }
    }

    pub const fn interpretation(self) -> &'static str {
        match self {
            Self::VmOnlyExecution => "target 100%; a container fallback is a failure",
            Self::CredentialMinimization => "target zero in the external-credentials profile",
            Self::UnauthorizedEffects => "target zero observed; report corpus and coverage",
            Self::AuthorityReduction => "structural improvement, not escape probability",
            Self::ReleaseBound => "enforced budget with all channels declared",
            Self::RevocationLatency => "measured distribution and partition bound",
            Self::Persistence => {
                "explicit inventory, no claim that all persistent data is harmless"
            }
            Self::FaultContainment => "model/test evidence for named faults",
        }
    }
}

/// How one production sandbox launch ran.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchRecord {
    VerifiedHardwareVm,
    ContainerFallback,
    NativeProcess,
    SoftwareEmulation,
}

/// VM-only execution over every launch: only a verified hardware VM counts; a container
/// fallback, a native process or software emulation is a failure (§2.2, VM-P42).
pub fn vm_only_execution(launches: &[LaunchRecord]) -> Result<SuccessRate, ModelError> {
    let verified = launches
        .iter()
        .filter(|launch| **launch == LaunchRecord::VerifiedHardwareVm)
        .count() as u64;
    Ok(SuccessRate::new(verified, launches.len() as u64)?)
}

/// A reduction of one configured byte ceiling (§2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CeilingReduction {
    before_bytes: u64,
    after_bytes: u64,
}

impl CeilingReduction {
    /// Refuses zero ceilings.
    pub fn new(before_bytes: u64, after_bytes: u64) -> Result<Self, ModelError> {
        if before_bytes == 0 || after_bytes == 0 {
            return Err(ModelError::InvalidRatio);
        }
        Ok(Self {
            before_bytes,
            after_bytes,
        })
    }

    /// How many times smaller the ceiling became.
    pub fn factor(&self) -> f64 {
        self.before_bytes as f64 / self.after_bytes as f64
    }

    /// Whether a secret of `secret_bytes` still fits under the reduced ceiling; a smaller
    /// ceiling does not make leaking a small key acceptable.
    pub fn secret_still_fits(&self, secret_bytes: u64) -> bool {
        secret_bytes <= self.after_bytes
    }

    /// Always refused: a ceiling ratio is not an isolation-strength factor.
    pub fn isolation_strength(&self) -> Result<Infallible, ModelError> {
        Err(ModelError::NotAnIsolationClaim)
    }
}

/// One measured latency with the conditions it was measured under.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct LatencyMeasurement {
    pub duration: Duration,
    pub conditions: Digest,
    pub provenance: Provenance,
}

/// The ratio of two durations, as arithmetic only.
pub fn latency_ratio(before: Duration, after: Duration) -> Result<f64, ModelError> {
    if before.is_zero() || after.is_zero() {
        return Err(ModelError::InvalidRatio);
    }
    Ok(before.as_secs_f64() / after.as_secs_f64())
}

/// A latency improvement claim: both values Yougori measurements under the same
/// conditions (§2.2: "under those conditions"). Plan examples are not measurements.
pub fn latency_improvement(
    before: &LatencyMeasurement,
    after: &LatencyMeasurement,
) -> Result<f64, ModelError> {
    if before.conditions != after.conditions {
        return Err(ModelError::NotComparable);
    }
    before.provenance.yougori_evidence()?;
    after.provenance.yougori_evidence()?;
    latency_ratio(before.duration, after.duration)
}

/// `sum(channel_budget) + documented_reserved_in_flight_allowance` (§2.5).
pub fn release_ceiling(channel_budgets: &[u64], allowance: u64) -> Result<u64, ModelError> {
    channel_budgets
        .iter()
        .try_fold(allowance, |sum, budget| sum.checked_add(*budget))
        .ok_or(ModelError::InvalidRatio)
}

/// What a disconnected remote enforcement point does with leases (§2.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteEnforcement {
    pub checks_leases: bool,
    pub can_mint_renewals: bool,
}

/// Exposure after revocation of a disconnected remote execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ExposureBound {
    /// `lease_TTL + allowed_clock_uncertainty`.
    pub remaining_authorized_time: Duration,
    /// `outstanding_reserved_effects + valid_lease_budget`.
    pub remaining_effects: u64,
    /// Already committed external actions, which revocation cannot undo; they are not
    /// part of the remaining bound and stay counted.
    pub committed_irrevocable: u64,
}

/// The §2.5 bound, which applies only if the remote enforcement point checks leases and
/// cannot mint renewals.
pub fn post_revocation_exposure(
    enforcement: RemoteEnforcement,
    lease_ttl: Duration,
    clock_uncertainty: Duration,
    outstanding_reserved_effects: u64,
    valid_lease_budget: u64,
    committed_effects: u64,
) -> Result<ExposureBound, ModelError> {
    if !enforcement.checks_leases {
        return Err(ModelError::LeaseBoundDoesNotApply {
            reason: "the remote enforcement point does not check leases",
        });
    }
    if enforcement.can_mint_renewals {
        return Err(ModelError::LeaseBoundDoesNotApply {
            reason: "the remote enforcement point can mint renewals",
        });
    }
    Ok(ExposureBound {
        remaining_authorized_time: lease_ttl
            .checked_add(clock_uncertainty)
            .ok_or(ModelError::InvalidRatio)?,
        remaining_effects: outstanding_reserved_effects
            .checked_add(valid_lease_budget)
            .ok_or(ModelError::InvalidRatio)?,
        committed_irrevocable: committed_effects,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::foundation::report::{ReportError, RunRecord, RunSubstrate, RUN_RECORD_SAMPLE_JSON};

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    fn fake_provenance() -> Provenance {
        let mut record: RunRecord = serde_json::from_str(RUN_RECORD_SAMPLE_JSON).unwrap();
        record.substrate = RunSubstrate::FakeTimeControlled;
        Provenance::of_records(&[record]).unwrap()
    }

    #[test]
    fn the_objectives_table_has_eight_rows_with_their_interpretations() {
        assert_eq!(SecurityObjective::ALL.len(), 8);
        assert_eq!(
            SecurityObjective::AuthorityReduction.interpretation(),
            "structural improvement, not escape probability"
        );
        for objective in SecurityObjective::ALL {
            assert!(!objective.measurement().is_empty());
        }
    }

    #[test]
    fn a_container_fallback_counts_as_a_failure_of_vm_only_execution() {
        let rate = vm_only_execution(&[
            LaunchRecord::VerifiedHardwareVm,
            LaunchRecord::VerifiedHardwareVm,
            LaunchRecord::ContainerFallback,
            LaunchRecord::SoftwareEmulation,
        ])
        .unwrap();
        assert_eq!((rate.successes(), rate.attempts()), (2, 4));
        assert!(vm_only_execution(&[]).is_err());
    }

    #[test]
    fn one_gib_to_one_mib_is_a_1024_fold_smaller_ceiling_and_nothing_more() {
        let reduction = CeilingReduction::new(GIB, MIB).unwrap();
        assert_eq!(reduction.factor(), 1024.0);
        // A 40-byte API key still fits under the reduced ceiling.
        assert!(reduction.secret_still_fits(40));
        assert_eq!(
            reduction.isolation_strength(),
            Err(ModelError::NotAnIsolationClaim)
        );
        assert_eq!(CeilingReduction::new(GIB, 0), Err(ModelError::InvalidRatio));
    }

    #[test]
    fn two_thousand_seconds_to_two_is_a_thousandfold_ratio_but_no_measurement() {
        let before = Duration::from_secs(2_000);
        let after = Duration::from_secs(2);
        assert_eq!(latency_ratio(before, after).unwrap(), 1000.0);
        let conditions = digest("yougori/test/conditions/v1", &[b"load"]);
        let plan_example = |duration| LatencyMeasurement {
            duration,
            conditions,
            provenance: fake_provenance(),
        };
        assert_eq!(
            latency_improvement(&plan_example(before), &plan_example(after)),
            Err(ModelError::Report(ReportError::FakeSubstrateIsNotEvidence))
        );
        let elsewhere = LatencyMeasurement {
            conditions: digest("yougori/test/conditions/v1", &[b"other"]),
            ..plan_example(after)
        };
        assert_eq!(
            latency_improvement(&plan_example(before), &elsewhere),
            Err(ModelError::NotComparable)
        );
    }

    #[test]
    fn the_release_ceiling_sums_channel_budgets_and_the_allowance() {
        assert_eq!(release_ceiling(&[100, 250, 50], 16).unwrap(), 416);
        assert_eq!(release_ceiling(&[], 16).unwrap(), 16);
        assert_eq!(
            release_ceiling(&[u64::MAX], 1),
            Err(ModelError::InvalidRatio)
        );
    }

    #[test]
    fn the_lease_bound_needs_lease_checks_and_no_renewal_minting() {
        let checked = RemoteEnforcement {
            checks_leases: true,
            can_mint_renewals: false,
        };
        let bound = post_revocation_exposure(
            checked,
            Duration::from_secs(30),
            Duration::from_secs(2),
            3,
            5,
            7,
        )
        .unwrap();
        assert_eq!(bound.remaining_authorized_time, Duration::from_secs(32));
        assert_eq!(bound.remaining_effects, 8);
        // Committed actions are not revoked retroactively and are not subtracted.
        assert_eq!(bound.committed_irrevocable, 7);
        for enforcement in [
            RemoteEnforcement {
                checks_leases: false,
                can_mint_renewals: false,
            },
            RemoteEnforcement {
                checks_leases: true,
                can_mint_renewals: true,
            },
        ] {
            assert!(matches!(
                post_revocation_exposure(enforcement, Duration::ZERO, Duration::ZERO, 0, 0, 0),
                Err(ModelError::LeaseBoundDoesNotApply { .. })
            ));
        }
    }
}
