//! Profitability of caching exact intermediate state (GPU §4.16 line 890: "Cache only at
//! profitable branch boundaries; do not hash every large activation on every operation
//! if that costs more than recomputation").
//!
//! For a boundary after `k` operators, with `c` expected consumers:
//!
//! ```text
//! saving_seconds = c × recompute_seconds(k)
//! cost_seconds   = keying_seconds + c × (lookup_seconds + handoff_seconds)
//! handoff_seconds = 0                                          (in place)
//!                 = bytes / transfer_bps + bytes / hash_bps    (verified copy)
//! net_seconds    = saving_seconds − cost_seconds
//! ```
//!
//! State is cached only at the branch boundary of a discovered shared prefix and only
//! when the net saving is strictly positive (line 900: "positive net compute savings
//! after keying/transfer costs").

use std::fmt;

use crate::model_memory::math::{non_negative, positive, InputError};

use super::discovery::SharedPrefix;
use super::variant::VariantIdentity;

/// The fake or measured cost of one operator per token of input.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct OperatorCost {
    pub compute_seconds_per_token: f64,
    /// Bytes of the operator's output state per token.
    pub activation_bytes_per_token: u64,
    /// Bytes of KV the operator keeps per token for decoding.
    pub kv_bytes_per_token: u64,
}

/// How a consumer obtains a stored state.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StateHandoff {
    /// The consumer reads the state where it was produced.
    InPlace,
    /// The state crosses a device or process: it is transferred and its bytes are hashed
    /// against its content key on receipt.
    Verified {
        transfer_bytes_per_second: f64,
        hash_bytes_per_second: f64,
    },
}

/// Keying, lookup and handoff costs of a stored state.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HandoffCosts {
    /// Computing the state keys when the state is produced.
    pub keying_seconds: f64,
    /// Computing the keys and finding the state, per consumer.
    pub lookup_seconds: f64,
    pub handoff: StateHandoff,
}

/// The inputs of the line 890 cost model for one boundary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BoundaryEconomics {
    /// The boundary: how many leading operators the state covers.
    pub operators: usize,
    /// Seconds one consumer would spend recomputing those operators.
    pub recompute_seconds: f64,
    pub activation_bytes: u64,
    /// Consumers expected to use the state besides its producer.
    pub expected_consumers: f64,
    pub costs: HandoffCosts,
}

/// Why the cost model refused its inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProfitError {
    Input(InputError),
    /// The boundary is zero or beyond the operators costed.
    BoundaryOutOfRange {
        boundary: usize,
        operators: usize,
    },
}

impl fmt::Display for ProfitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::BoundaryOutOfRange {
                boundary,
                operators,
            } => write!(
                f,
                "boundary {boundary} is outside the {operators} operators costed"
            ),
        }
    }
}

impl std::error::Error for ProfitError {}

impl From<InputError> for ProfitError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

fn token_bytes(per_token: u64, tokens: u64, field: &'static str) -> Result<u64, InputError> {
    per_token
        .checked_mul(tokens)
        .ok_or(InputError::Overflow { field })
}

impl BoundaryEconomics {
    /// The economics of a boundary after `boundary` operators for a request of `tokens`
    /// tokens: the recomputation of those operators and the output size of the last.
    pub fn from_costs(
        costs: &[OperatorCost],
        boundary: usize,
        tokens: u64,
        expected_consumers: f64,
        handoff: HandoffCosts,
    ) -> Result<Self, ProfitError> {
        let last = boundary
            .checked_sub(1)
            .and_then(|index| costs.get(index))
            .ok_or(ProfitError::BoundaryOutOfRange {
                boundary,
                operators: costs.len(),
            })?;
        let mut recompute_seconds = 0.0;
        for cost in costs.iter().take(boundary) {
            recompute_seconds += non_negative(
                "OperatorCost.compute_seconds_per_token",
                cost.compute_seconds_per_token,
            )? * tokens as f64;
        }
        Ok(Self {
            operators: boundary,
            recompute_seconds,
            activation_bytes: token_bytes(
                last.activation_bytes_per_token,
                tokens,
                "activation bytes",
            )?,
            expected_consumers,
            costs: handoff,
        })
    }
}

/// The line 890 estimate for one boundary.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ProfitEstimate {
    pub saving_seconds: f64,
    pub cost_seconds: f64,
    pub net_seconds: f64,
}

impl ProfitEstimate {
    /// Line 900: only a strictly positive net saving counts.
    pub fn is_profitable(&self) -> bool {
        self.net_seconds > 0.0
    }
}

fn handoff_seconds(handoff: &StateHandoff, bytes: u64) -> Result<f64, InputError> {
    Ok(match handoff {
        StateHandoff::InPlace => 0.0,
        StateHandoff::Verified {
            transfer_bytes_per_second,
            hash_bytes_per_second,
        } => {
            bytes as f64 / positive("transfer_bytes_per_second", *transfer_bytes_per_second)?
                + bytes as f64 / positive("hash_bytes_per_second", *hash_bytes_per_second)?
        }
    })
}

/// The line 890 estimate; see the module formula.
pub fn estimate(economics: &BoundaryEconomics) -> Result<ProfitEstimate, InputError> {
    let consumers = non_negative("expected_consumers", economics.expected_consumers)?;
    let recompute = non_negative("recompute_seconds", economics.recompute_seconds)?;
    let keying = non_negative("keying_seconds", economics.costs.keying_seconds)?;
    let lookup = non_negative("lookup_seconds", economics.costs.lookup_seconds)?;
    let handoff = handoff_seconds(&economics.costs.handoff, economics.activation_bytes)?;
    let saving_seconds = consumers * recompute;
    let cost_seconds = keying + consumers * (lookup + handoff);
    Ok(ProfitEstimate {
        saving_seconds,
        cost_seconds,
        net_seconds: saving_seconds - cost_seconds,
    })
}

/// Why state may not be cached at a point.
#[derive(Clone, Debug, PartialEq)]
pub enum CacheRefusal {
    /// The variants share no operator.
    NothingShared,
    /// The variants never branch; whole-model caching is ordinary per-model caching.
    NoBranch,
    /// Line 890: only the branch boundary may hold cached state.
    NotABranchBoundary {
        requested: usize,
        branch: usize,
    },
    /// The economics describe another boundary than the one requested.
    EconomicsForAnotherBoundary {
        requested: usize,
        economics: usize,
    },
    /// Line 890: the keying, lookup and handoff cost at least what they save.
    Unprofitable(ProfitEstimate),
    Input(InputError),
}

impl fmt::Display for CacheRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NothingShared => f.write_str("the variants share no operator"),
            Self::NoBranch => f.write_str("the variants never branch"),
            Self::NotABranchBoundary { requested, branch } => write!(
                f,
                "state is cached only at the branch boundary {branch}, not at {requested}"
            ),
            Self::EconomicsForAnotherBoundary {
                requested,
                economics,
            } => write!(
                f,
                "the economics describe boundary {economics}, not {requested}"
            ),
            Self::Unprofitable(estimate) => write!(
                f,
                "caching costs {} s and saves {} s",
                estimate.cost_seconds, estimate.saving_seconds
            ),
            Self::Input(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for CacheRefusal {}

/// Proof that caching at one branch boundary of one pair of variants is profitable;
/// made only by [`plan_boundary`] and required to produce a state.
#[derive(Clone, Debug, PartialEq)]
pub struct ProfitableBoundary {
    variants: [VariantIdentity; 2],
    operators: usize,
    estimate: ProfitEstimate,
}

impl ProfitableBoundary {
    pub fn variants(&self) -> &[VariantIdentity; 2] {
        &self.variants
    }

    /// How many leading operators the cached state covers.
    pub fn operators(&self) -> usize {
        self.operators
    }

    pub fn estimate(&self) -> ProfitEstimate {
        self.estimate
    }
}

/// Line 890: allows caching after `at_operators` operators only when that is the branch
/// boundary of `prefix` and the estimate is strictly profitable.
pub fn plan_boundary(
    prefix: &SharedPrefix,
    at_operators: usize,
    economics: &BoundaryEconomics,
) -> Result<ProfitableBoundary, CacheRefusal> {
    if prefix.shared_operators() == 0 {
        return Err(CacheRefusal::NothingShared);
    }
    let branch = prefix.branch_boundary().ok_or(CacheRefusal::NoBranch)?;
    if at_operators != branch {
        return Err(CacheRefusal::NotABranchBoundary {
            requested: at_operators,
            branch,
        });
    }
    if economics.operators != at_operators {
        return Err(CacheRefusal::EconomicsForAnotherBoundary {
            requested: at_operators,
            economics: economics.operators,
        });
    }
    let estimate = estimate(economics).map_err(CacheRefusal::Input)?;
    if !estimate.is_profitable() {
        return Err(CacheRefusal::Unprofitable(estimate));
    }
    Ok(ProfitableBoundary {
        variants: *prefix.variants(),
        operators: at_operators,
        estimate,
    })
}

/// The estimate of the scheme line 890 warns against: keying and hashing every
/// operator's activation in the first `operators` operators, for one consumer that
/// would otherwise recompute them.
pub fn hash_every_operation(
    costs: &[OperatorCost],
    operators: usize,
    tokens: u64,
    hash_bytes_per_second: f64,
    keying_seconds_per_operation: f64,
) -> Result<ProfitEstimate, ProfitError> {
    if operators == 0 || operators > costs.len() {
        return Err(ProfitError::BoundaryOutOfRange {
            boundary: operators,
            operators: costs.len(),
        });
    }
    let hash = positive("hash_bytes_per_second", hash_bytes_per_second)?;
    let keying = non_negative("keying_seconds_per_operation", keying_seconds_per_operation)?;
    let mut saving_seconds = 0.0;
    let mut cost_seconds = 0.0;
    for cost in costs.iter().take(operators) {
        saving_seconds += non_negative(
            "OperatorCost.compute_seconds_per_token",
            cost.compute_seconds_per_token,
        )? * tokens as f64;
        let bytes = token_bytes(cost.activation_bytes_per_token, tokens, "activation bytes")?;
        cost_seconds += keying + bytes as f64 / hash;
    }
    Ok(ProfitEstimate {
        saving_seconds,
        cost_seconds,
        net_seconds: saving_seconds - cost_seconds,
    })
}
