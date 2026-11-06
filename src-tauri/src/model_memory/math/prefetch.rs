//! Prefetch as an investment (GPU §2.9).
//!
//! The score `p_i*saved_delay_i - (1-p_i)*waste_cost_i - interference_i -
//! retention_cost_i` is normalised into a declared objective while the raw
//! milliseconds, bytes, energy and currency stay beside it. Speculative bytes are
//! bounded and foreground capacity is reserved; candidates from queued work and explicit
//! user intent come before recency or Markov predictions. A transfer is cancelled only
//! at a safe block boundary, and promoting a speculative transfer to demand reuses it.

use std::collections::BTreeMap;
use std::fmt;

use super::calibration::SchedulingMode;
use super::{non_negative, probability, CandidateId, InputError};
use crate::foundation::ids::OperationId;

/// Raw quantities kept in telemetry beside a normalised score (GPU §2.9).
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct RawCost {
    pub milliseconds: f64,
    pub bytes: f64,
    pub energy_joules: f64,
    pub currency_units: f64,
}

/// The declared objective that turns raw quantities into one score (GPU §2.9).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Objective {
    score_per_millisecond: f64,
    score_per_byte: f64,
    score_per_joule: f64,
    score_per_currency_unit: f64,
}

impl Objective {
    /// Score per millisecond, byte, joule and currency unit (GPU §2.9); each must be zero or more.
    pub fn new(
        score_per_millisecond: f64,
        score_per_byte: f64,
        score_per_joule: f64,
        score_per_currency_unit: f64,
    ) -> Result<Self, PrefetchError> {
        Ok(Self {
            score_per_millisecond: non_negative("score_per_millisecond", score_per_millisecond)?,
            score_per_byte: non_negative("score_per_byte", score_per_byte)?,
            score_per_joule: non_negative("score_per_joule", score_per_joule)?,
            score_per_currency_unit: non_negative(
                "score_per_currency_unit",
                score_per_currency_unit,
            )?,
        })
    }

    /// The score of non-negative raw quantities.
    pub fn score(&self, raw: &RawCost) -> Result<f64, PrefetchError> {
        Ok(
            non_negative("RawCost.milliseconds", raw.milliseconds)? * self.score_per_millisecond
                + non_negative("RawCost.bytes", raw.bytes)? * self.score_per_byte
                + non_negative("RawCost.energy_joules", raw.energy_joules)? * self.score_per_joule
                + non_negative("RawCost.currency_units", raw.currency_units)?
                    * self.score_per_currency_unit,
        )
    }
}

/// Where a candidate came from (GPU §2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CandidateOrigin {
    QueuedWork,
    ExplicitUserIntent,
    Recency,
    Markov,
}

impl CandidateOrigin {
    /// 0 for queued work and explicit user intent, which come first; 1 for recency and
    /// Markov predictions, which are compared after them.
    pub const fn tier(self) -> u8 {
        match self {
            Self::QueuedWork | Self::ExplicitUserIntent => 0,
            Self::Recency | Self::Markov => 1,
        }
    }
}

/// Something that could be fetched before it is requested.
#[derive(Clone, Debug, PartialEq)]
pub struct PrefetchCandidate {
    pub id: CandidateId,
    pub origin: CandidateOrigin,
    /// Calibrated probability that the bytes are used.
    pub probability: f64,
    pub bytes: u64,
    pub saved_if_used: RawCost,
    pub waste_if_unused: RawCost,
    pub interference: RawCost,
    pub retention: RawCost,
}

/// A candidate's expected value with every term and its raw quantities.
#[derive(Clone, Debug, PartialEq)]
pub struct PrefetchValue {
    pub candidate: CandidateId,
    pub origin: CandidateOrigin,
    pub probability: f64,
    pub bytes: u64,
    /// `p*saved - (1-p)*waste - interference - retention`, in objective units.
    pub expected_value: f64,
    pub saved_score: f64,
    pub waste_score: f64,
    pub interference_score: f64,
    pub retention_score: f64,
    pub raw_saved: RawCost,
    pub raw_waste: RawCost,
    pub raw_interference: RawCost,
    pub raw_retention: RawCost,
}

/// The GPU §2.9 expected value of one candidate.
pub fn expected_value(
    candidate: &PrefetchCandidate,
    objective: &Objective,
) -> Result<PrefetchValue, PrefetchError> {
    let p = probability("probability", candidate.probability)?;
    let saved_score = objective.score(&candidate.saved_if_used)?;
    let waste_score = objective.score(&candidate.waste_if_unused)?;
    let interference_score = objective.score(&candidate.interference)?;
    let retention_score = objective.score(&candidate.retention)?;
    Ok(PrefetchValue {
        candidate: candidate.id.clone(),
        origin: candidate.origin,
        probability: p,
        bytes: candidate.bytes,
        expected_value: p * saved_score
            - (1.0 - p) * waste_score
            - interference_score
            - retention_score,
        saved_score,
        waste_score,
        interference_score,
        retention_score,
        raw_saved: candidate.saved_if_used,
        raw_waste: candidate.waste_if_unused,
        raw_interference: candidate.interference,
        raw_retention: candidate.retention,
    })
}

/// Candidates worth an investment, best first: positive expected value only; queued
/// work and explicit user intent before recency and Markov predictions; then by
/// expected value; then by id.
pub fn rank_candidates(
    candidates: &[PrefetchCandidate],
    objective: &Objective,
) -> Result<Vec<PrefetchValue>, PrefetchError> {
    let mut values = Vec::with_capacity(candidates.len());
    for (index, candidate) in candidates.iter().enumerate() {
        if candidates[..index]
            .iter()
            .any(|other| other.id == candidate.id)
        {
            return Err(InputError::Duplicate {
                field: "candidates",
                name: candidate.id.to_string(),
            }
            .into());
        }
        let value = expected_value(candidate, objective)?;
        if value.expected_value > 0.0 {
            values.push(value);
        }
    }
    values.sort_by(|a, b| {
        a.origin
            .tier()
            .cmp(&b.origin.tier())
            .then(b.expected_value.total_cmp(&a.expected_value))
            .then_with(|| a.candidate.cmp(&b.candidate))
    });
    Ok(values)
}

/// Bounds on speculative work (GPU §2.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrefetchBudget {
    /// Most bytes speculative transfers may hold, running or finished but unused.
    pub max_speculative_bytes: u64,
    /// Capacity shared by demand and speculative transfers, such as staging memory.
    pub capacity_bytes: u64,
    /// Capacity that speculative admissions always leave free for foreground demand.
    pub reserved_foreground_bytes: u64,
}

/// Why a speculative transfer was not admitted.
#[derive(Clone, Debug, PartialEq)]
pub enum AdmissionRefusal {
    /// Scheduling is demand-only (low confidence, overload or drift).
    DemandOnly,
    /// The expected value is not positive.
    NotWorthIt { expected_value: f64 },
    SpeculativeBudget {
        requested_bytes: u64,
        held_bytes: u64,
        limit_bytes: u64,
    },
    ForegroundReserve {
        requested_bytes: u64,
        free_bytes: u64,
        reserved_bytes: u64,
    },
}

/// Why a prefetch operation was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum PrefetchError {
    Input(InputError),
    Refused(AdmissionRefusal),
    InsufficientCapacity {
        requested_bytes: u64,
        free_bytes: u64,
    },
    UnknownTransfer {
        operation: OperationId,
    },
    DuplicateTransfer {
        operation: OperationId,
    },
    NotSpeculative {
        operation: OperationId,
    },
    AlreadyComplete {
        operation: OperationId,
    },
    NotComplete {
        operation: OperationId,
    },
}

impl From<InputError> for PrefetchError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for PrefetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::Refused(refusal) => write!(f, "speculative transfer refused: {refusal:?}"),
            Self::InsufficientCapacity {
                requested_bytes,
                free_bytes,
            } => write!(f, "{requested_bytes} bytes requested, {free_bytes} free"),
            Self::UnknownTransfer { operation } => write!(f, "no transfer {operation}"),
            Self::DuplicateTransfer { operation } => write!(f, "{operation} already exists"),
            Self::NotSpeculative { operation } => write!(f, "{operation} is not speculative"),
            Self::AlreadyComplete { operation } => write!(f, "{operation} is complete"),
            Self::NotComplete { operation } => write!(f, "{operation} is not complete"),
        }
    }
}

impl std::error::Error for PrefetchError {}

/// Whether a transfer serves a request now or a prediction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferClass {
    Speculative,
    Demand,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Where a tracked transfer is.
pub enum TransferState {
    Running,
    /// Cancellation was requested mid-block; the transfer stops at the next boundary.
    CancelRequested,
    Complete,
}

/// One transfer the scheduler holds capacity for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrackedTransfer {
    class: TransferClass,
    total_bytes: u64,
    block_bytes: u64,
    completed_bytes: u64,
    state: TransferState,
}

impl TrackedTransfer {
    /// Demand or speculative.
    pub fn class(&self) -> TransferClass {
        self.class
    }

    /// Bytes the transfer moves and holds capacity for.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// The cancellation unit: a transfer stops only at a multiple of it or at its end.
    pub fn block_bytes(&self) -> u64 {
        self.block_bytes
    }

    /// Bytes that have arrived.
    pub fn completed_bytes(&self) -> u64 {
        self.completed_bytes
    }

    /// Where the transfer is.
    pub fn state(&self) -> TransferState {
        self.state
    }

    /// The first block boundary after the bytes completed so far; the end counts as one.
    fn next_boundary(&self) -> u64 {
        let block_start = self.completed_bytes - self.completed_bytes % self.block_bytes;
        block_start
            .saturating_add(self.block_bytes)
            .min(self.total_bytes)
    }
}

/// What a cancellation request did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// The transfer was at a block boundary and stopped there; its capacity is free.
    Stopped { at_bytes: u64 },
    /// The transfer is mid-block and will stop at this boundary.
    Deferred { boundary_bytes: u64 },
}

/// What a progress report did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Progress {
    Running {
        completed_bytes: u64,
    },
    /// A pending cancellation took effect at a block boundary; bytes reported past it
    /// were not accepted.
    Cancelled {
        at_bytes: u64,
        accepted_bytes: u64,
    },
    Complete,
}

/// Admits demand and speculative transfers within a [`PrefetchBudget`] (GPU §2.9).
#[derive(Clone, Debug, PartialEq)]
pub struct PrefetchScheduler {
    budget: PrefetchBudget,
    mode: SchedulingMode,
    transfers: BTreeMap<OperationId, TrackedTransfer>,
    started: u64,
}

impl PrefetchScheduler {
    /// Starts speculative and empty (GPU §2.9); refuses a reserve larger than the capacity.
    pub fn new(budget: PrefetchBudget) -> Result<Self, PrefetchError> {
        if budget.reserved_foreground_bytes > budget.capacity_bytes {
            return Err(InputError::OutOfRange {
                field: "reserved_foreground_bytes",
            }
            .into());
        }
        Ok(Self {
            budget,
            mode: SchedulingMode::Speculative,
            transfers: BTreeMap::new(),
            started: 0,
        })
    }

    /// The scheduling mode in force.
    pub fn mode(&self) -> SchedulingMode {
        self.mode
    }

    fn held_bytes(&self, class: TransferClass) -> u64 {
        self.transfers
            .values()
            .filter(|transfer| transfer.class == class)
            .map(|transfer| transfer.total_bytes)
            .sum()
    }

    /// Bytes held by speculative transfers, running or finished but unused.
    pub fn speculative_bytes(&self) -> u64 {
        self.held_bytes(TransferClass::Speculative)
    }

    /// Bytes held by demand transfers.
    pub fn demand_bytes(&self) -> u64 {
        self.held_bytes(TransferClass::Demand)
    }

    /// Capacity not held by any transfer.
    pub fn free_bytes(&self) -> u64 {
        self.budget
            .capacity_bytes
            .saturating_sub(self.speculative_bytes() + self.demand_bytes())
    }

    /// A tracked transfer; `None` once cancelled or released.
    pub fn transfer(&self, operation: &OperationId) -> Option<&TrackedTransfer> {
        self.transfers.get(operation)
    }

    /// How many transfers were ever admitted; promotion does not start a new one.
    pub fn transfers_started(&self) -> u64 {
        self.started
    }

    fn insert(
        &mut self,
        operation: OperationId,
        class: TransferClass,
        total_bytes: u64,
        block_bytes: u64,
    ) -> Result<(), PrefetchError> {
        self.transfers.insert(
            operation,
            TrackedTransfer {
                class,
                total_bytes,
                block_bytes,
                completed_bytes: 0,
                state: TransferState::Running,
            },
        );
        self.started += 1;
        Ok(())
    }

    fn check_new(
        &self,
        operation: &OperationId,
        total_bytes: u64,
        block_bytes: u64,
    ) -> Result<(), PrefetchError> {
        if total_bytes == 0 {
            return Err(InputError::NotPositive {
                field: "total_bytes",
            }
            .into());
        }
        if block_bytes == 0 {
            return Err(InputError::NotPositive {
                field: "block_bytes",
            }
            .into());
        }
        if self.transfers.contains_key(operation) {
            return Err(PrefetchError::DuplicateTransfer {
                operation: operation.clone(),
            });
        }
        Ok(())
    }

    /// Starts a transfer a request is waiting for; it may use the foreground reserve.
    pub fn start_demand(
        &mut self,
        operation: OperationId,
        total_bytes: u64,
        block_bytes: u64,
    ) -> Result<(), PrefetchError> {
        self.check_new(&operation, total_bytes, block_bytes)?;
        let free_bytes = self.free_bytes();
        if total_bytes > free_bytes {
            return Err(PrefetchError::InsufficientCapacity {
                requested_bytes: total_bytes,
                free_bytes,
            });
        }
        self.insert(operation, TransferClass::Demand, total_bytes, block_bytes)
    }

    /// Starts a speculative transfer for a candidate with positive expected value, within
    /// the speculative budget and leaving the foreground reserve free.
    pub fn start_speculative(
        &mut self,
        operation: OperationId,
        value: &PrefetchValue,
        block_bytes: u64,
    ) -> Result<(), PrefetchError> {
        let refuse = |refusal| Err(PrefetchError::Refused(refusal));
        if self.mode == SchedulingMode::DemandOnly {
            return refuse(AdmissionRefusal::DemandOnly);
        }
        self.check_new(&operation, value.bytes, block_bytes)?;
        if value.expected_value.is_nan() || value.expected_value <= 0.0 {
            return refuse(AdmissionRefusal::NotWorthIt {
                expected_value: value.expected_value,
            });
        }
        let held_bytes = self.speculative_bytes();
        if held_bytes
            .checked_add(value.bytes)
            .is_none_or(|total| total > self.budget.max_speculative_bytes)
        {
            return refuse(AdmissionRefusal::SpeculativeBudget {
                requested_bytes: value.bytes,
                held_bytes,
                limit_bytes: self.budget.max_speculative_bytes,
            });
        }
        let free_bytes = self.free_bytes();
        if value
            .bytes
            .checked_add(self.budget.reserved_foreground_bytes)
            .is_none_or(|needed| needed > free_bytes)
        {
            return refuse(AdmissionRefusal::ForegroundReserve {
                requested_bytes: value.bytes,
                free_bytes,
                reserved_bytes: self.budget.reserved_foreground_bytes,
            });
        }
        self.insert(
            operation,
            TransferClass::Speculative,
            value.bytes,
            block_bytes,
        )
    }

    fn get_mut(&mut self, operation: &OperationId) -> Result<&mut TrackedTransfer, PrefetchError> {
        self.transfers
            .get_mut(operation)
            .ok_or_else(|| PrefetchError::UnknownTransfer {
                operation: operation.clone(),
            })
    }

    /// Turns a speculative transfer into demand in place: the same transfer, progress
    /// and capacity, with any pending cancellation withdrawn.
    pub fn promote(&mut self, operation: &OperationId) -> Result<(), PrefetchError> {
        let transfer = self.get_mut(operation)?;
        if transfer.class != TransferClass::Speculative {
            return Err(PrefetchError::NotSpeculative {
                operation: operation.clone(),
            });
        }
        transfer.class = TransferClass::Demand;
        if transfer.state == TransferState::CancelRequested {
            transfer.state = TransferState::Running;
        }
        Ok(())
    }

    /// Cancels at a safe block boundary: at once if the transfer is on one, otherwise
    /// at the next boundary its progress reaches.
    pub fn request_cancel(
        &mut self,
        operation: &OperationId,
    ) -> Result<CancelOutcome, PrefetchError> {
        let transfer = self.get_mut(operation)?;
        if transfer.state == TransferState::Complete {
            return Err(PrefetchError::AlreadyComplete {
                operation: operation.clone(),
            });
        }
        if transfer
            .completed_bytes
            .is_multiple_of(transfer.block_bytes)
        {
            let at_bytes = transfer.completed_bytes;
            self.transfers.remove(operation);
            return Ok(CancelOutcome::Stopped { at_bytes });
        }
        transfer.state = TransferState::CancelRequested;
        Ok(CancelOutcome::Deferred {
            boundary_bytes: transfer.next_boundary(),
        })
    }

    /// Records bytes that arrived. A pending cancellation stops the transfer at the next
    /// block boundary and frees its capacity.
    pub fn record_progress(
        &mut self,
        operation: &OperationId,
        bytes: u64,
    ) -> Result<Progress, PrefetchError> {
        let transfer = self.get_mut(operation)?;
        if transfer.state == TransferState::Complete {
            return Err(PrefetchError::AlreadyComplete {
                operation: operation.clone(),
            });
        }
        let completed = transfer
            .completed_bytes
            .checked_add(bytes)
            .filter(|total| *total <= transfer.total_bytes)
            .ok_or(InputError::OutOfRange {
                field: "progress bytes",
            })?;
        if transfer.state == TransferState::CancelRequested {
            let boundary = transfer.next_boundary();
            if completed >= boundary {
                let accepted_bytes = boundary - transfer.completed_bytes;
                self.transfers.remove(operation);
                return Ok(Progress::Cancelled {
                    at_bytes: boundary,
                    accepted_bytes,
                });
            }
            transfer.completed_bytes = completed;
            return Ok(Progress::Running {
                completed_bytes: completed,
            });
        }
        transfer.completed_bytes = completed;
        if completed == transfer.total_bytes {
            transfer.state = TransferState::Complete;
            return Ok(Progress::Complete);
        }
        Ok(Progress::Running {
            completed_bytes: completed,
        })
    }

    /// Frees a finished transfer once its bytes are used or dropped.
    pub fn release(&mut self, operation: &OperationId) -> Result<(), PrefetchError> {
        if self.get_mut(operation)?.state != TransferState::Complete {
            return Err(PrefetchError::NotComplete {
                operation: operation.clone(),
            });
        }
        self.transfers.remove(operation);
        Ok(())
    }

    /// Applies a scheduling mode. Entering demand-only cancels every unfinished
    /// speculative transfer at its next safe block boundary.
    pub fn set_mode(&mut self, mode: SchedulingMode) -> Vec<(OperationId, CancelOutcome)> {
        self.mode = mode;
        if mode != SchedulingMode::DemandOnly {
            return Vec::new();
        }
        let speculative: Vec<OperationId> = self
            .transfers
            .iter()
            .filter(|(_, transfer)| {
                transfer.class == TransferClass::Speculative
                    && transfer.state != TransferState::Complete
            })
            .map(|(operation, _)| operation.clone())
            .collect();
        speculative
            .into_iter()
            .filter_map(|operation| {
                self.request_cancel(&operation)
                    .ok()
                    .map(|outcome| (operation, outcome))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests;
