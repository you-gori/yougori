//! Chunk and batch sizing without false universal optimality (GPU §2.5).
//!
//! A path fitted as `t(c) = alpha + c/B`; the toy equal-stage model, used only as a
//! tuning seed; and a discrete search over measured per-stage service curves under
//! memory, alignment and non-preemptible limits, in idle and concurrent-serving
//! conditions.

use std::collections::BTreeMap;
use std::fmt;

use super::{non_negative, positive, InputError, StageId};

/// Why a chunking computation was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum ChunkingError {
    Input(InputError),
    /// A fit needs at least two different chunk sizes.
    TooFewDistinctSizes,
    /// The fitted time does not grow with chunk size, so no bandwidth follows.
    NonPositiveSlope {
        slope_seconds_per_byte: f64,
    },
    /// The fitted fixed cost is negative beyond rounding, so `t(c)=alpha+c/B` does not
    /// describe the samples.
    NegativeOverhead {
        overhead_seconds: f64,
    },
    /// Every candidate broke a limit or lacked a measurement.
    NoFeasibleBatch {
        outcomes: Vec<BatchOutcome>,
    },
}

impl From<InputError> for ChunkingError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for ChunkingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::TooFewDistinctSizes => f.write_str("the fit needs two different chunk sizes"),
            Self::NonPositiveSlope {
                slope_seconds_per_byte,
            } => write!(
                f,
                "time does not grow with chunk size (slope {slope_seconds_per_byte} s/byte)"
            ),
            Self::NegativeOverhead { overhead_seconds } => write!(
                f,
                "the fitted fixed cost is negative ({overhead_seconds} s); measure again"
            ),
            Self::NoFeasibleBatch { outcomes } => write!(
                f,
                "none of the {} candidate batch sizes meets the limits",
                outcomes.len()
            ),
        }
    }
}

impl std::error::Error for ChunkingError {}

/// One measurement: a chunk of `chunk_bytes` took `seconds` on one path.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ServiceSample {
    pub chunk_bytes: u64,
    pub seconds: f64,
}

/// `t(c) = alpha + c/B`, fitted to measurements by least squares (GPU §2.5).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LinearServiceFit {
    overhead_seconds: f64,
    bandwidth_bytes_per_second: f64,
    residual_rms_seconds: f64,
    samples: usize,
}

/// A negative fitted overhead smaller than this fraction of the longest sample is
/// rounding error and reads as zero; anything larger is refused.
const OVERHEAD_ROUNDING: f64 = 1e-9;

impl LinearServiceFit {
    /// Fits by least squares (GPU §2.5); refuses fewer than two distinct sizes, a slope that is not positive and a clearly negative fixed cost.
    pub fn fit(samples: &[ServiceSample]) -> Result<Self, ChunkingError> {
        if samples.is_empty() {
            return Err(InputError::Empty { field: "samples" }.into());
        }
        let mut longest_seconds: f64 = 0.0;
        for sample in samples {
            if sample.chunk_bytes == 0 {
                return Err(InputError::NotPositive {
                    field: "ServiceSample.chunk_bytes",
                }
                .into());
            }
            longest_seconds =
                longest_seconds.max(non_negative("ServiceSample.seconds", sample.seconds)?);
        }
        let count = samples.len() as f64;
        let mean_bytes = samples.iter().map(|s| s.chunk_bytes as f64).sum::<f64>() / count;
        let mean_seconds = samples.iter().map(|s| s.seconds).sum::<f64>() / count;
        let (mut sxx, mut sxy) = (0.0, 0.0);
        for sample in samples {
            let dx = sample.chunk_bytes as f64 - mean_bytes;
            sxx += dx * dx;
            sxy += dx * (sample.seconds - mean_seconds);
        }
        if sxx <= 0.0 {
            return Err(ChunkingError::TooFewDistinctSizes);
        }
        let slope = sxy / sxx;
        if !slope.is_finite() || slope <= 0.0 {
            return Err(ChunkingError::NonPositiveSlope {
                slope_seconds_per_byte: slope,
            });
        }
        let mut overhead_seconds = mean_seconds - slope * mean_bytes;
        if overhead_seconds < 0.0 {
            if -overhead_seconds > OVERHEAD_ROUNDING * longest_seconds {
                return Err(ChunkingError::NegativeOverhead { overhead_seconds });
            }
            overhead_seconds = 0.0;
        }
        let squared = samples
            .iter()
            .map(|s| {
                let residual = s.seconds - (overhead_seconds + slope * s.chunk_bytes as f64);
                residual * residual
            })
            .sum::<f64>();
        Ok(Self {
            overhead_seconds,
            bandwidth_bytes_per_second: 1.0 / slope,
            residual_rms_seconds: (squared / count).sqrt(),
            samples: samples.len(),
        })
    }

    /// `alpha`.
    pub fn overhead_seconds(&self) -> f64 {
        self.overhead_seconds
    }

    /// `B`.
    pub fn bandwidth_bytes_per_second(&self) -> f64 {
        self.bandwidth_bytes_per_second
    }

    /// Root-mean-square residual of the fit.
    pub fn residual_rms_seconds(&self) -> f64 {
        self.residual_rms_seconds
    }

    /// How many samples were fitted.
    pub fn samples(&self) -> usize {
        self.samples
    }

    /// `t(c) = alpha + c/B`.
    pub fn seconds_for(&self, chunk_bytes: u64) -> f64 {
        self.overhead_seconds + chunk_bytes as f64 / self.bandwidth_bytes_per_second
    }
}

/// The deliberately simplified equal-stage model of GPU §2.5: `B(c) = Bmax*c/(c+h)` and
/// `T(c) = (S+2c)/B(c)`, three equal stages whose per-chunk cost halves throughput at
/// `c = h`.
///
/// Its optimum `sqrt(S*h/2)` is a tuning seed for [`choose_batch_size`] candidates. It
/// proves nothing for unequal reading, verification, transfer and decoding stages.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ToyEqualStageModel {
    total_bytes: f64,
    max_bytes_per_second: f64,
    half_rate_chunk_bytes: f64,
}

impl ToyEqualStageModel {
    /// `S`, `Bmax` and `h` of GPU §2.5; each must be positive.
    pub fn new(
        total_bytes: u64,
        max_bytes_per_second: f64,
        half_rate_chunk_bytes: f64,
    ) -> Result<Self, ChunkingError> {
        if total_bytes == 0 {
            return Err(InputError::NotPositive {
                field: "total_bytes",
            }
            .into());
        }
        Ok(Self {
            total_bytes: total_bytes as f64,
            max_bytes_per_second: positive("max_bytes_per_second", max_bytes_per_second)?,
            half_rate_chunk_bytes: positive("half_rate_chunk_bytes", half_rate_chunk_bytes)?,
        })
    }

    /// `B(c) = Bmax*c/(c+h)`.
    pub fn bandwidth_bytes_per_second(&self, chunk_bytes: f64) -> Result<f64, ChunkingError> {
        let chunk_bytes = positive("chunk_bytes", chunk_bytes)?;
        Ok(self.max_bytes_per_second * chunk_bytes / (chunk_bytes + self.half_rate_chunk_bytes))
    }

    /// `T(c) = (S+2c)/B(c)`.
    pub fn completion_seconds(&self, chunk_bytes: f64) -> Result<f64, ChunkingError> {
        let bandwidth = self.bandwidth_bytes_per_second(chunk_bytes)?;
        Ok((self.total_bytes + 2.0 * chunk_bytes) / bandwidth)
    }

    /// `sqrt(S*h/2)`, the unconstrained optimum of this toy model: a seed only.
    pub fn seed_chunk_bytes(&self) -> f64 {
        (self.total_bytes * self.half_rate_chunk_bytes / 2.0).sqrt()
    }
}

/// One stage's measured service time per batch at each measured batch size (GPU §2.5).
#[derive(Clone, Debug, PartialEq)]
pub struct StageCurve {
    stage: StageId,
    non_preemptible: bool,
    seconds_per_batch: BTreeMap<u64, f64>,
}

impl StageCurve {
    /// `points` are `(batch_bytes, seconds_per_batch)` measurements. A non-preemptible
    /// stage, such as an issued DMA copy, holds its resource until the batch finishes.
    pub fn new(
        stage: StageId,
        non_preemptible: bool,
        points: &[(u64, f64)],
    ) -> Result<Self, ChunkingError> {
        if points.is_empty() {
            return Err(InputError::Empty {
                field: "StageCurve.points",
            }
            .into());
        }
        let mut seconds_per_batch = BTreeMap::new();
        for &(batch_bytes, seconds) in points {
            if batch_bytes == 0 {
                return Err(InputError::NotPositive {
                    field: "StageCurve.batch_bytes",
                }
                .into());
            }
            let seconds = positive("StageCurve.seconds_per_batch", seconds)?;
            if seconds_per_batch.insert(batch_bytes, seconds).is_some() {
                return Err(InputError::Duplicate {
                    field: "StageCurve.batch_bytes",
                    name: batch_bytes.to_string(),
                }
                .into());
            }
        }
        Ok(Self {
            stage,
            non_preemptible,
            seconds_per_batch,
        })
    }

    /// The stage measured.
    pub fn stage(&self) -> &StageId {
        &self.stage
    }

    /// Whether a batch holds this stage's resource until it finishes.
    pub fn is_non_preemptible(&self) -> bool {
        self.non_preemptible
    }

    /// The time measured at exactly this size. Sizes that were not measured are never
    /// interpolated or extrapolated.
    pub fn seconds_for(&self, batch_bytes: u64) -> Option<f64> {
        self.seconds_per_batch.get(&batch_bytes).copied()
    }
}

/// Limits every candidate batch must meet (GPU §2.5).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BatchLimits {
    /// Candidates must be multiples of this, such as a mapping unit or I/O alignment.
    pub alignment_bytes: u64,
    /// Staging memory available to the pipeline.
    pub staging_memory_bytes: u64,
    /// Batches held at once, for example one per stage plus one being filled.
    pub batches_in_memory: u64,
    /// Longest a non-preemptible stage may hold its resource for one batch.
    pub max_non_preemptible_seconds: f64,
}

/// Loading while requests are served (GPU §2.5): larger batches may raise throughput
/// and worsen p99 TTFT, so the search pays for the measured p99 TTFT.
#[derive(Clone, Debug, PartialEq)]
pub struct ConcurrentServing {
    p99_ttft_seconds: BTreeMap<u64, f64>,
    p99_ttft_limit_seconds: f64,
    completion_seconds_per_ttft_second: f64,
}

impl ConcurrentServing {
    /// `points` are `(batch_bytes, foreground p99 TTFT measured while loading with
    /// batches of that size)`. A candidate above `p99_ttft_limit_seconds` is rejected;
    /// the others score `completion + completion_seconds_per_ttft_second * p99 TTFT`.
    pub fn new(
        points: &[(u64, f64)],
        p99_ttft_limit_seconds: f64,
        completion_seconds_per_ttft_second: f64,
    ) -> Result<Self, ChunkingError> {
        if points.is_empty() {
            return Err(InputError::Empty {
                field: "ConcurrentServing.points",
            }
            .into());
        }
        let mut p99_ttft_seconds = BTreeMap::new();
        for &(batch_bytes, seconds) in points {
            let seconds = non_negative("ConcurrentServing.p99_ttft_seconds", seconds)?;
            if p99_ttft_seconds.insert(batch_bytes, seconds).is_some() {
                return Err(InputError::Duplicate {
                    field: "ConcurrentServing.batch_bytes",
                    name: batch_bytes.to_string(),
                }
                .into());
            }
        }
        Ok(Self {
            p99_ttft_seconds,
            p99_ttft_limit_seconds: positive("p99_ttft_limit_seconds", p99_ttft_limit_seconds)?,
            completion_seconds_per_ttft_second: non_negative(
                "completion_seconds_per_ttft_second",
                completion_seconds_per_ttft_second,
            )?,
        })
    }
}

/// The condition the stage curves were measured in (GPU §2.5). Pass curves measured in
/// the same condition.
#[derive(Clone, Debug, PartialEq)]
pub enum ServingCondition {
    /// No foreground requests: minimise completion time.
    Idle,
    ConcurrentServing(ConcurrentServing),
}

/// One feasible candidate.
#[derive(Clone, Debug, PartialEq)]
pub struct BatchEvaluation {
    pub batch_bytes: u64,
    pub batches: u64,
    /// The slowest stage's time per batch.
    pub bottleneck_seconds: f64,
    /// `sum_k s_k + (n - 1) * max_k s_k`; a final partial batch counts as a full one.
    pub completion_seconds: f64,
    pub throughput_bytes_per_second: f64,
    /// The measured foreground p99 TTFT when serving concurrently.
    pub p99_ttft_seconds: Option<f64>,
    /// What the search minimises: completion when idle, plus weighted p99 TTFT when
    /// serving.
    pub score_seconds: f64,
}

/// Why a candidate was rejected.
#[derive(Clone, Debug, PartialEq)]
pub enum BatchRejection {
    Zero,
    Misaligned {
        alignment_bytes: u64,
    },
    /// `required_bytes` is `None` when it does not fit in 64 bits.
    StagingMemory {
        required_bytes: Option<u64>,
        limit_bytes: u64,
    },
    Unmeasured {
        stage: StageId,
    },
    NonPreemptibleTooLong {
        stage: StageId,
        seconds: f64,
        limit_seconds: f64,
    },
    ServingImpactUnmeasured,
    P99TtftOverLimit {
        p99_ttft_seconds: f64,
        limit_seconds: f64,
    },
}

/// What happened to one candidate.
#[derive(Clone, Debug, PartialEq)]
pub enum BatchOutcome {
    Feasible(BatchEvaluation),
    Rejected {
        batch_bytes: u64,
        reason: BatchRejection,
    },
}

/// The chosen batch size and the outcome of every candidate, smallest first.
#[derive(Clone, Debug, PartialEq)]
pub struct BatchChoice {
    pub chosen: BatchEvaluation,
    pub outcomes: Vec<BatchOutcome>,
}

/// Searches a small discrete set of batch sizes (GPU §2.5). Ties go to the smaller
/// batch, which holds less memory and blocks foreground work for less time.
pub fn choose_batch_size(
    total_bytes: u64,
    candidates_bytes: &[u64],
    stages: &[StageCurve],
    limits: &BatchLimits,
    condition: &ServingCondition,
) -> Result<BatchChoice, ChunkingError> {
    if total_bytes == 0 {
        return Err(InputError::NotPositive {
            field: "total_bytes",
        }
        .into());
    }
    if candidates_bytes.is_empty() {
        return Err(InputError::Empty {
            field: "candidates_bytes",
        }
        .into());
    }
    if stages.is_empty() {
        return Err(InputError::Empty { field: "stages" }.into());
    }
    for (index, stage) in stages.iter().enumerate() {
        if stages[..index]
            .iter()
            .any(|other| other.stage == stage.stage)
        {
            return Err(InputError::Duplicate {
                field: "stages",
                name: stage.stage.to_string(),
            }
            .into());
        }
    }
    if limits.alignment_bytes == 0 {
        return Err(InputError::NotPositive {
            field: "alignment_bytes",
        }
        .into());
    }
    if limits.batches_in_memory == 0 {
        return Err(InputError::NotPositive {
            field: "batches_in_memory",
        }
        .into());
    }
    non_negative(
        "max_non_preemptible_seconds",
        limits.max_non_preemptible_seconds,
    )?;
    let mut sorted = candidates_bytes.to_vec();
    sorted.sort_unstable();
    for pair in sorted.windows(2) {
        if pair[0] == pair[1] {
            return Err(InputError::Duplicate {
                field: "candidates_bytes",
                name: pair[0].to_string(),
            }
            .into());
        }
    }

    let mut outcomes = Vec::with_capacity(sorted.len());
    let mut best: Option<BatchEvaluation> = None;
    for batch_bytes in sorted {
        match evaluate(total_bytes, batch_bytes, stages, limits, condition) {
            Ok(evaluation) => {
                if best
                    .as_ref()
                    .is_none_or(|current| evaluation.score_seconds < current.score_seconds)
                {
                    best = Some(evaluation.clone());
                }
                outcomes.push(BatchOutcome::Feasible(evaluation));
            }
            Err(reason) => outcomes.push(BatchOutcome::Rejected {
                batch_bytes,
                reason,
            }),
        }
    }
    match best {
        Some(chosen) => Ok(BatchChoice { chosen, outcomes }),
        None => Err(ChunkingError::NoFeasibleBatch { outcomes }),
    }
}

fn evaluate(
    total_bytes: u64,
    batch_bytes: u64,
    stages: &[StageCurve],
    limits: &BatchLimits,
    condition: &ServingCondition,
) -> Result<BatchEvaluation, BatchRejection> {
    if batch_bytes == 0 {
        return Err(BatchRejection::Zero);
    }
    if !batch_bytes.is_multiple_of(limits.alignment_bytes) {
        return Err(BatchRejection::Misaligned {
            alignment_bytes: limits.alignment_bytes,
        });
    }
    let required_bytes = batch_bytes.checked_mul(limits.batches_in_memory);
    if required_bytes.is_none_or(|bytes| bytes > limits.staging_memory_bytes) {
        return Err(BatchRejection::StagingMemory {
            required_bytes,
            limit_bytes: limits.staging_memory_bytes,
        });
    }
    let mut sum_seconds = 0.0;
    let mut bottleneck_seconds: f64 = 0.0;
    for stage in stages {
        let seconds = stage
            .seconds_for(batch_bytes)
            .ok_or_else(|| BatchRejection::Unmeasured {
                stage: stage.stage.clone(),
            })?;
        if stage.non_preemptible && seconds > limits.max_non_preemptible_seconds {
            return Err(BatchRejection::NonPreemptibleTooLong {
                stage: stage.stage.clone(),
                seconds,
                limit_seconds: limits.max_non_preemptible_seconds,
            });
        }
        sum_seconds += seconds;
        bottleneck_seconds = bottleneck_seconds.max(seconds);
    }
    let batches = (total_bytes - 1) / batch_bytes + 1;
    let completion_seconds = sum_seconds + (batches - 1) as f64 * bottleneck_seconds;
    let (p99_ttft_seconds, score_seconds) = match condition {
        ServingCondition::Idle => (None, completion_seconds),
        ServingCondition::ConcurrentServing(serving) => {
            let p99 = serving
                .p99_ttft_seconds
                .get(&batch_bytes)
                .copied()
                .ok_or(BatchRejection::ServingImpactUnmeasured)?;
            if p99 > serving.p99_ttft_limit_seconds {
                return Err(BatchRejection::P99TtftOverLimit {
                    p99_ttft_seconds: p99,
                    limit_seconds: serving.p99_ttft_limit_seconds,
                });
            }
            (
                Some(p99),
                completion_seconds + serving.completion_seconds_per_ttft_second * p99,
            )
        }
    };
    Ok(BatchEvaluation {
        batch_bytes,
        batches,
        bottleneck_seconds,
        completion_seconds,
        throughput_bytes_per_second: total_bytes as f64 / completion_seconds,
        p99_ttft_seconds,
        score_seconds,
    })
}

#[cfg(test)]
mod tests;
