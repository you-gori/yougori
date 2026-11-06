//! The coordinated barrier of a multi-rank activation (§3.6 line 599) over the per-rank
//! validation of step 3 and readiness checks of step 4. One ready rank is
//! insufficient: publication waits until every rank of the layout has validated and
//! passed readiness for this exact generation.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::fields::SupportedShape;
use super::keys::Rank;
use super::state::FailureReason;
use crate::foundation::ids::{Digest, ModelActivationGeneration};

/// The step-3 checks a rank reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationCheck {
    Weights,
    Buffers,
    Graphs,
}

impl fmt::Display for ValidationCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Weights => "weights",
            Self::Buffers => "buffers",
            Self::Graphs => "graphs",
        })
    }
}

/// One rank's step-3 validation of its required weights, buffers, graphs and rank
/// coordination.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationReport {
    pub generation: ModelActivationGeneration,
    pub rank: Rank,
    pub weights_verified: bool,
    pub buffers_ready: bool,
    pub graphs_compatible: bool,
    /// Digest of the rank coordination the rank joined, such as its communicator and
    /// peer set; every rank must report the same one.
    pub coordination: Digest,
}

/// One rank's step-4 readiness check for the declared request shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "readiness", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum ReadinessReport {
    Ready { supported: SupportedShape },
    NotReady,
}

crate::foundation::strict_serde::strict_tag!(ReadinessReport, "readiness");

/// Per-rank validation and readiness for one activation generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RankBarrier {
    generation: ModelActivationGeneration,
    ranks: BTreeSet<Rank>,
    declared: SupportedShape,
    coordination: Option<Digest>,
    validated: BTreeSet<Rank>,
    ready: BTreeSet<Rank>,
}

impl RankBarrier {
    /// A barrier over `ranks` for `generation`, whose readiness must cover `declared`.
    pub fn new(
        generation: ModelActivationGeneration,
        ranks: BTreeSet<Rank>,
        declared: SupportedShape,
    ) -> Self {
        Self {
            generation,
            ranks,
            declared,
            coordination: None,
            validated: BTreeSet::new(),
            ready: BTreeSet::new(),
        }
    }

    /// The activation generation every report must name.
    pub fn generation(&self) -> ModelActivationGeneration {
        self.generation
    }

    /// The request shape readiness must cover: the only shape the generation publishes.
    pub fn declared(&self) -> SupportedShape {
        self.declared
    }

    /// Records a rank's validation. A protocol error or a failed check leaves the
    /// barrier unchanged; a failed check is returned as the activation's failure reason.
    pub fn record_validation(&mut self, report: &ValidationReport) -> Result<(), BarrierError> {
        self.check_report(report.generation, report.rank)?;
        if self.validated.contains(&report.rank) {
            return Err(BarrierError::AlreadyReported { rank: report.rank });
        }
        for (passed, check) in [
            (report.weights_verified, ValidationCheck::Weights),
            (report.buffers_ready, ValidationCheck::Buffers),
            (report.graphs_compatible, ValidationCheck::Graphs),
        ] {
            if !passed {
                return Err(BarrierError::Failed(FailureReason::ValidationFailed {
                    rank: report.rank,
                    check,
                }));
            }
        }
        if let Some(coordination) = self.coordination {
            if coordination != report.coordination {
                return Err(BarrierError::Failed(
                    FailureReason::RankCoordinationMismatch { rank: report.rank },
                ));
            }
        }
        self.coordination = Some(report.coordination);
        self.validated.insert(report.rank);
        Ok(())
    }

    /// Records a rank's readiness. It must follow that rank's validation and cover the
    /// declared shape; anything less fails the activation rather than publishing a
    /// smaller promise.
    pub fn record_readiness(
        &mut self,
        generation: ModelActivationGeneration,
        rank: Rank,
        report: &ReadinessReport,
    ) -> Result<(), BarrierError> {
        self.check_report(generation, rank)?;
        if !self.validated.contains(&rank) {
            return Err(BarrierError::ReadinessBeforeValidation { rank });
        }
        if self.ready.contains(&rank) {
            return Err(BarrierError::AlreadyReported { rank });
        }
        match report {
            ReadinessReport::Ready { supported } if supported.covers(&self.declared) => {
                self.ready.insert(rank);
                Ok(())
            }
            _ => Err(BarrierError::Failed(FailureReason::NotReady { rank })),
        }
    }

    /// Step 3 is complete when every rank has validated.
    pub fn all_validated(&self) -> bool {
        self.validated == self.ranks
    }

    /// Step 4 is complete, and the barrier passes, when every rank is also ready.
    pub fn is_complete(&self) -> bool {
        self.all_validated() && self.ready == self.ranks
    }

    /// Ranks that have not yet passed both steps.
    pub fn waiting_for(&self) -> Vec<Rank> {
        self.ranks
            .iter()
            .filter(|rank| !self.ready.contains(rank))
            .copied()
            .collect()
    }

    fn check_report(
        &self,
        generation: ModelActivationGeneration,
        rank: Rank,
    ) -> Result<(), BarrierError> {
        if generation != self.generation {
            return Err(BarrierError::WrongGeneration {
                expected: self.generation,
                reported: generation,
            });
        }
        if !self.ranks.contains(&rank) {
            return Err(BarrierError::UnknownRank { rank });
        }
        Ok(())
    }
}

/// Why a rank report was not recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum BarrierError {
    /// A report for another generation never counts for this one.
    WrongGeneration {
        expected: ModelActivationGeneration,
        reported: ModelActivationGeneration,
    },
    UnknownRank {
        rank: Rank,
    },
    /// A rank reports each step once; a later report cannot overwrite an earlier one.
    AlreadyReported {
        rank: Rank,
    },
    ReadinessBeforeValidation {
        rank: Rank,
    },
    /// The report fails the activation for this reason.
    Failed(FailureReason),
}

crate::foundation::strict_serde::strict_tag!(BarrierError, "error");

impl fmt::Display for BarrierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongGeneration { expected, reported } => write!(
                f,
                "the report is for activation generation {reported}, not {expected}"
            ),
            Self::UnknownRank { rank } => write!(f, "rank {rank} is not part of this activation"),
            Self::AlreadyReported { rank } => {
                write!(f, "rank {rank} already reported this step")
            }
            Self::ReadinessBeforeValidation { rank } => {
                write!(f, "rank {rank} reported readiness before validation")
            }
            Self::Failed(reason) => write!(f, "the activation fails: {reason}"),
        }
    }
}

impl std::error::Error for BarrierError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    const SHAPE: SupportedShape = SupportedShape {
        max_context_tokens: 8_192,
        max_batch_sequences: 4,
    };

    fn generation() -> ModelActivationGeneration {
        ModelActivationGeneration::new(3)
    }

    fn two_ranks() -> RankBarrier {
        RankBarrier::new(
            generation(),
            [Rank::new(0), Rank::new(1)].into_iter().collect(),
            SHAPE,
        )
    }

    fn valid(rank: u64) -> ValidationReport {
        ValidationReport {
            generation: generation(),
            rank: Rank::new(rank),
            weights_verified: true,
            buffers_ready: true,
            graphs_compatible: true,
            coordination: digest("yougori/test/communicator/v1", &[b"nccl-1"]),
        }
    }

    fn ready() -> ReadinessReport {
        ReadinessReport::Ready { supported: SHAPE }
    }

    #[test]
    fn one_ready_rank_is_insufficient() {
        let mut barrier = two_ranks();
        barrier.record_validation(&valid(0)).unwrap();
        barrier
            .record_readiness(generation(), Rank::new(0), &ready())
            .unwrap();
        assert!(!barrier.is_complete());
        assert_eq!(barrier.waiting_for(), vec![Rank::new(1)]);

        barrier.record_validation(&valid(1)).unwrap();
        assert!(barrier.all_validated());
        assert!(!barrier.is_complete(), "validation alone is not readiness");
        barrier
            .record_readiness(generation(), Rank::new(1), &ready())
            .unwrap();
        assert!(barrier.is_complete());
        assert!(barrier.waiting_for().is_empty());
    }

    #[test]
    fn reports_for_another_generation_or_rank_never_count() {
        let mut barrier = two_ranks();
        let mut stale = valid(0);
        stale.generation = ModelActivationGeneration::new(2);
        assert_eq!(
            barrier.record_validation(&stale),
            Err(BarrierError::WrongGeneration {
                expected: generation(),
                reported: ModelActivationGeneration::new(2)
            })
        );
        assert_eq!(
            barrier.record_validation(&valid(2)),
            Err(BarrierError::UnknownRank { rank: Rank::new(2) })
        );
        barrier.record_validation(&valid(0)).unwrap();
        assert_eq!(
            barrier.record_readiness(ModelActivationGeneration::new(4), Rank::new(0), &ready()),
            Err(BarrierError::WrongGeneration {
                expected: generation(),
                reported: ModelActivationGeneration::new(4)
            })
        );
        assert_eq!(barrier.waiting_for(), vec![Rank::new(0), Rank::new(1)]);
    }

    #[test]
    fn steps_are_ordered_and_reported_once() {
        let mut barrier = two_ranks();
        assert_eq!(
            barrier.record_readiness(generation(), Rank::new(0), &ready()),
            Err(BarrierError::ReadinessBeforeValidation { rank: Rank::new(0) })
        );
        barrier.record_validation(&valid(0)).unwrap();
        assert_eq!(
            barrier.record_validation(&valid(0)),
            Err(BarrierError::AlreadyReported { rank: Rank::new(0) })
        );
        barrier
            .record_readiness(generation(), Rank::new(0), &ready())
            .unwrap();
        assert_eq!(
            barrier.record_readiness(generation(), Rank::new(0), &ReadinessReport::NotReady),
            Err(BarrierError::AlreadyReported { rank: Rank::new(0) }),
            "a later report cannot overwrite readiness"
        );
    }

    #[test]
    fn failed_checks_name_the_rank_and_check() {
        for (check, report) in [
            (
                ValidationCheck::Weights,
                ValidationReport {
                    weights_verified: false,
                    ..valid(1)
                },
            ),
            (
                ValidationCheck::Buffers,
                ValidationReport {
                    buffers_ready: false,
                    ..valid(1)
                },
            ),
            (
                ValidationCheck::Graphs,
                ValidationReport {
                    graphs_compatible: false,
                    ..valid(1)
                },
            ),
        ] {
            let mut barrier = two_ranks();
            assert_eq!(
                barrier.record_validation(&report),
                Err(BarrierError::Failed(FailureReason::ValidationFailed {
                    rank: Rank::new(1),
                    check
                }))
            );
            assert!(!barrier.all_validated());
        }
    }

    #[test]
    fn ranks_must_join_the_same_coordination() {
        let mut barrier = two_ranks();
        barrier.record_validation(&valid(0)).unwrap();
        let other = ValidationReport {
            coordination: digest("yougori/test/communicator/v1", &[b"nccl-2"]),
            ..valid(1)
        };
        assert_eq!(
            barrier.record_validation(&other),
            Err(BarrierError::Failed(
                FailureReason::RankCoordinationMismatch { rank: Rank::new(1) }
            ))
        );
    }

    #[test]
    fn readiness_must_cover_the_declared_shape() {
        let mut barrier = two_ranks();
        barrier.record_validation(&valid(0)).unwrap();
        let shorter = ReadinessReport::Ready {
            supported: SupportedShape {
                max_context_tokens: 4_096,
                ..SHAPE
            },
        };
        assert_eq!(
            barrier.record_readiness(generation(), Rank::new(0), &shorter),
            Err(BarrierError::Failed(FailureReason::NotReady {
                rank: Rank::new(0)
            }))
        );
        assert_eq!(
            barrier.record_readiness(generation(), Rank::new(0), &ReadinessReport::NotReady),
            Err(BarrierError::Failed(FailureReason::NotReady {
                rank: Rank::new(0)
            }))
        );
        let larger = ReadinessReport::Ready {
            supported: SupportedShape {
                max_context_tokens: 32_768,
                max_batch_sequences: 8,
            },
        };
        barrier
            .record_readiness(generation(), Rank::new(0), &larger)
            .unwrap();
        assert_eq!(
            barrier.declared(),
            SHAPE,
            "only the declared shape is promised"
        );
    }
}
