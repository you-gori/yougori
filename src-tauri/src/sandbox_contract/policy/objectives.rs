//! The §2.2 objectives as typed metric definitions, and the §2.3 zero-failure bound
//! (VM part lines 1758–1785).
//!
//! Each objective carries its measurement and interpretation from the §2.2 table. None
//! is an escape probability, and a reduction factor is scoped to the one metric and the
//! conditions it was computed under: it is never an isolation multiplier (§0.2: no
//! numerical multiplier from layer count).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::Digest;

/// One §2.2 objective.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Objective {
    VmOnlyExecution,
    CredentialMinimization,
    UnauthorizedEffects,
    AuthorityReduction,
    ReleaseBound,
    RevocationLatency,
    Persistence,
    FaultContainment,
}

/// How a measurement is read (the §2.2 interpretation column).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Interpretation {
    /// A fraction of production sandbox launches; a container fallback is a failure.
    LaunchFraction,
    /// A count of long-lived credentials delivered to the guest.
    DeliveredCredentialCount,
    /// Effects observed in a fixed adversarial corpus, reported with the corpus and its
    /// coverage.
    CorpusObservation,
    /// A structural improvement in reachable pairs.
    StructuralReduction,
    /// An enforced budget with all channels declared.
    EnforcedBudget,
    /// A measured distribution with a partition bound.
    MeasuredDistribution,
    /// An explicit inventory of what survives.
    Inventory,
    /// Model or test evidence for named faults.
    NamedFaultEvidence,
}

impl Interpretation {
    /// The interpretation column of the §2.2 table.
    pub const fn statement(self) -> &'static str {
        match self {
            Self::LaunchFraction => "Target 100%; a container fallback is a failure",
            Self::DeliveredCredentialCount => "Target zero in the external-credentials profile",
            Self::CorpusObservation => "Target zero observed; report corpus and coverage",
            Self::StructuralReduction => "Structural improvement, not escape probability",
            Self::EnforcedBudget => "Enforced budget with all channels declared",
            Self::MeasuredDistribution => "Measured distribution and partition bound",
            Self::Inventory => "Explicit inventory, no claim that all persistent data is harmless",
            Self::NamedFaultEvidence => "Model/test evidence for named faults",
        }
    }

    /// No §2.2 metric is an escape probability, so this is false for every one; a report
    /// that needs one has no source for it here (§2.2, §2.3).
    pub const fn supports_escape_probability(self) -> bool {
        false
    }
}

/// The target an objective states.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Target {
    /// 100% of production sandbox launches.
    AllLaunches,
    /// Zero, in the external-credentials profile.
    ZeroInProfile,
    /// Zero observed, with the corpus and coverage beside it.
    ZeroObservedWithCorpus,
    /// No numeric target; the measurement is reported as it is.
    Reported,
}

impl Target {
    /// The target as a percentage of launches, where it is one.
    pub const fn percent_of_launches(self) -> Option<u32> {
        match self {
            Self::AllLaunches => Some(100),
            Self::ZeroInProfile | Self::ZeroObservedWithCorpus | Self::Reported => None,
        }
    }
}

impl Objective {
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

    /// The measurement column of the §2.2 table.
    pub const fn measurement(self) -> &'static str {
        match self {
            Self::VmOnlyExecution => {
                "Fraction of production sandbox launches using a verified hardware VM"
            }
            Self::CredentialMinimization => {
                "Long-lived external credentials intentionally delivered to guest"
            }
            Self::UnauthorizedEffects => {
                "Effects outside contract in a fixed adversarial test corpus"
            }
            Self::AuthorityReduction => "Reachable operation/resource pairs before and after",
            Self::ReleaseBound => "Maximum authorized outbound bytes/effects per generation",
            Self::RevocationLatency => {
                "Revocation request → denial of new authorization; separately → \
                 closure/termination"
            }
            Self::Persistence => "State surviving task teardown or service renewal",
            Self::FaultContainment => {
                "Invariants surviving specific failed guards or compromised components"
            }
        }
    }

    pub const fn interpretation(self) -> Interpretation {
        match self {
            Self::VmOnlyExecution => Interpretation::LaunchFraction,
            Self::CredentialMinimization => Interpretation::DeliveredCredentialCount,
            Self::UnauthorizedEffects => Interpretation::CorpusObservation,
            Self::AuthorityReduction => Interpretation::StructuralReduction,
            Self::ReleaseBound => Interpretation::EnforcedBudget,
            Self::RevocationLatency => Interpretation::MeasuredDistribution,
            Self::Persistence => Interpretation::Inventory,
            Self::FaultContainment => Interpretation::NamedFaultEvidence,
        }
    }

    pub const fn target(self) -> Target {
        match self {
            Self::VmOnlyExecution => Target::AllLaunches,
            Self::CredentialMinimization => Target::ZeroInProfile,
            Self::UnauthorizedEffects => Target::ZeroObservedWithCorpus,
            Self::AuthorityReduction
            | Self::ReleaseBound
            | Self::RevocationLatency
            | Self::Persistence
            | Self::FaultContainment => Target::Reported,
        }
    }
}

/// Why a bound or a reduction could not be formed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundError {
    /// A zero-failure bound needs at least one independent trial.
    NoTrials,
    /// A reduction to zero has no finite factor.
    ZeroValue,
    /// The value did not go down.
    NotAReduction,
}

impl fmt::Display for BoundError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoTrials => "a zero-failure bound needs at least one independent trial",
            Self::ZeroValue => "a reduction to zero has no finite factor",
            Self::NotAReduction => "the value did not go down",
        })
    }
}

impl std::error::Error for BoundError {}

/// The unit both values of a reduction are in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReductionUnit {
    Bytes,
    Seconds,
}

strict_policy_enum! {
    /// Where the values of a reduction come from.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ValueProvenance tag "provenance" {
        /// Configured limits, such as a release budget.
        Configured,
        /// Illustrative values, measured by no one (§2.2 line 1775).
        Hypothetical,
        /// Values measured under the stated conditions.
        Measured { conditions: String },
    }
}

/// `before / after` in lowest terms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReductionFactor {
    pub numerator: u64,
    pub denominator: u64,
}

impl fmt::Display for ReductionFactor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.denominator == 1 {
            write!(f, "{}×", self.numerator)
        } else {
            write!(f, "{}/{}×", self.numerator, self.denominator)
        }
    }
}

/// A reduction in one metric under stated conditions (§2.2 lines 1773–1775). It says
/// how much one number went down and nothing else: not how much stronger isolation is,
/// not a risk reduction, and not an escape probability.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopedReduction {
    objective: Objective,
    unit: ReductionUnit,
    before: u64,
    after: u64,
    provenance: ValueProvenance,
}

impl ScopedReduction {
    /// A configured release byte ceiling lowered from `before_bytes` to `after_bytes`.
    pub fn release_ceiling(before_bytes: u64, after_bytes: u64) -> Result<Self, BoundError> {
        Self::new(
            Objective::ReleaseBound,
            ReductionUnit::Bytes,
            before_bytes,
            after_bytes,
            ValueProvenance::Configured,
        )
    }

    /// A revocation delay lowered from `before_seconds` to `after_seconds`.
    pub fn revocation_latency(
        before_seconds: u64,
        after_seconds: u64,
        provenance: ValueProvenance,
    ) -> Result<Self, BoundError> {
        Self::new(
            Objective::RevocationLatency,
            ReductionUnit::Seconds,
            before_seconds,
            after_seconds,
            provenance,
        )
    }

    fn new(
        objective: Objective,
        unit: ReductionUnit,
        before: u64,
        after: u64,
        provenance: ValueProvenance,
    ) -> Result<Self, BoundError> {
        if after == 0 {
            return Err(BoundError::ZeroValue);
        }
        if after >= before {
            return Err(BoundError::NotAReduction);
        }
        Ok(Self {
            objective,
            unit,
            before,
            after,
            provenance,
        })
    }

    pub fn objective(&self) -> Objective {
        self.objective
    }

    pub fn unit(&self) -> ReductionUnit {
        self.unit
    }

    pub fn before(&self) -> u64 {
        self.before
    }

    pub fn after(&self) -> u64 {
        self.after
    }

    pub fn provenance(&self) -> &ValueProvenance {
        &self.provenance
    }

    /// `before / after` in lowest terms.
    pub fn factor(&self) -> ReductionFactor {
        let divisor = gcd(self.before, self.after);
        ReductionFactor {
            numerator: self.before / divisor,
            denominator: self.after / divisor,
        }
    }

    /// Whether both values were measured; configured and illustrative values are not.
    pub fn is_measurement(&self) -> bool {
        matches!(self.provenance, ValueProvenance::Measured { .. })
    }

    /// Whether the lowered limit still admits `amount` in its unit; a lower byte
    /// ceiling still admits anything smaller than itself, such as a small API key.
    pub fn after_admits(&self, amount: u64) -> bool {
        amount <= self.after
    }

    /// The claim, worded with its scope.
    pub fn statement(&self) -> String {
        let factor = self.factor();
        let scope = match self.unit {
            ReductionUnit::Bytes => "reduction in that byte ceiling",
            ReductionUnit::Seconds => "latency improvement under those conditions",
        };
        let source = match &self.provenance {
            ValueProvenance::Configured => "configured values, not a measurement".to_owned(),
            ValueProvenance::Hypothetical => "illustrative values, not a measurement".to_owned(),
            ValueProvenance::Measured { conditions } => format!("measured under {conditions}"),
        };
        format!("{factor} {scope} ({source})")
    }
}

fn gcd(mut left: u64, mut right: u64) -> u64 {
    while right != 0 {
        let rest = left % right;
        left = right;
        right = rest;
    }
    left.max(1)
}

/// The one-sided 95% upper bound on failure probability after zero failures in N
/// independent Bernoulli trials from a fixed distribution: `1 - 0.05^(1/N)` (§2.3).
///
/// It bounds that distribution only. It does not bound unknown adversarial exploits,
/// and it is above zero for every N, so "zero escapes in our tests" never becomes
/// impossibility (§2.3 line 1785).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZeroFailureBound {
    independent_trials: u64,
}

impl ZeroFailureBound {
    /// From the identities of passing cases. Repeated cases count once: duplicated test
    /// cases are not independent evidence.
    pub fn from_cases(cases: impl IntoIterator<Item = Digest>) -> Result<Self, BoundError> {
        let distinct: BTreeSet<Digest> = cases.into_iter().collect();
        Self::from_independent_trials(distinct.len() as u64)
    }

    /// From a count the caller vouches are independent trials of one distribution.
    pub fn from_independent_trials(independent_trials: u64) -> Result<Self, BoundError> {
        if independent_trials == 0 {
            return Err(BoundError::NoTrials);
        }
        Ok(Self { independent_trials })
    }

    pub fn independent_trials(&self) -> u64 {
        self.independent_trials
    }

    /// `1 - 0.05^(1/N)`.
    pub fn upper_bound(&self) -> f64 {
        1.0 - 0.05_f64.powf(1.0 / self.independent_trials as f64)
    }

    /// What the bound covers.
    pub const fn scope(&self) -> &'static str {
        "the failure probability of the sampled fixed distribution, at 95% one-sided \
         confidence; not unknown adversarial exploits"
    }
}
