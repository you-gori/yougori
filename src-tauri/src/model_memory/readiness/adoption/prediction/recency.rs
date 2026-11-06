//! The recency predictor (GPU §2.9 line 642: "compare recency/Markov models"): the LRU
//! stack-distance model learned online.
//!
//! The predictor keeps the most recently requested distinct keys, most recent first, at
//! most `depth` of them, and a sliding window of the last `window` requests' reuse ranks:
//! the position the requested key held in that list (0 for a repeat of the last request),
//! or "beyond" when it was not in the list. The probability that the next request is the
//! key now at rank r is the posterior mean of rank r's share of the window under a
//! symmetric Dirichlet prior over the `depth + 1` outcomes; keys beyond the list share
//! the "beyond" outcome evenly. The window lets the model follow a phase change, and
//! memory is bounded by `depth + window`.

use std::collections::VecDeque;

use super::{posterior, Forecast, PredictionError, Predictor};
use crate::model_memory::math::prefetch::CandidateOrigin;

/// The largest list depth and window accepted.
pub const MAX_RECENCY_DEPTH: usize = 256;
pub const MAX_RECENCY_WINDOW: usize = 65_536;

/// How much the recency predictor remembers.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct RecencyConfig {
    /// Distinct recent keys ranked, at most [`MAX_RECENCY_DEPTH`].
    pub depth: usize,
    /// Recent requests whose reuse ranks are counted, at most [`MAX_RECENCY_WINDOW`].
    pub window: usize,
    /// Dirichlet prior per outcome: more than zero.
    pub prior: f64,
}

impl RecencyConfig {
    fn check(self) -> Result<Self, PredictionError> {
        let invalid = |field, reason| Err(PredictionError::InvalidConfig { field, reason });
        if self.depth == 0 || self.depth > MAX_RECENCY_DEPTH {
            return invalid("recency.depth", "between 1 and 256");
        }
        if self.window == 0 || self.window > MAX_RECENCY_WINDOW {
            return invalid("recency.window", "between 1 and 65536");
        }
        if !self.prior.is_finite() || self.prior <= 0.0 {
            return invalid("recency.prior", "a finite number more than zero");
        }
        Ok(self)
    }
}

/// The LRU stack-distance predictor (see the module documentation).
#[derive(Clone, Debug, PartialEq)]
pub struct RecencyPredictor<K> {
    config: RecencyConfig,
    /// Most recent first, distinct, at most `depth`.
    recent: VecDeque<K>,
    /// The window's reuse ranks, oldest first; `None` is "beyond".
    outcomes: VecDeque<Option<usize>>,
    /// Requests in the window at each rank.
    at_rank: Vec<u64>,
    beyond: u64,
}

impl<K: Clone + PartialEq> RecencyPredictor<K> {
    /// An empty predictor; refuses a zero or oversized depth or window.
    pub fn new(config: RecencyConfig) -> Result<Self, PredictionError> {
        let config = config.check()?;
        Ok(Self {
            config,
            recent: VecDeque::with_capacity(config.depth),
            outcomes: VecDeque::new(),
            at_rank: vec![0; config.depth],
            beyond: 0,
        })
    }

    pub fn config(&self) -> RecencyConfig {
        self.config
    }

    /// The rank `key` holds now: 0 is the last request.
    pub fn rank_of(&self, key: &K) -> Option<usize> {
        self.recent.iter().position(|recent| recent == key)
    }

    /// The window's count of `outcome`.
    fn tally(&mut self, outcome: Option<usize>) -> Option<&mut u64> {
        match outcome {
            Some(rank) => self.at_rank.get_mut(rank),
            None => Some(&mut self.beyond),
        }
    }
}

impl<K: Clone + PartialEq> Predictor<K> for RecencyPredictor<K> {
    fn origin(&self) -> CandidateOrigin {
        CandidateOrigin::Recency
    }

    fn observe(&mut self, key: &K) {
        let rank = self.rank_of(key);
        if self.outcomes.len() == self.config.window {
            if let Some(count) = self
                .outcomes
                .pop_front()
                .and_then(|oldest| self.tally(oldest))
            {
                *count = count.saturating_sub(1);
            }
        }
        self.outcomes.push_back(rank);
        if let Some(count) = self.tally(rank) {
            *count = count.saturating_add(1);
        }
        if let Some(rank) = rank {
            self.recent.remove(rank);
        }
        self.recent.push_front(key.clone());
        self.recent.truncate(self.config.depth);
    }

    fn forecast(&self, candidates: &[K]) -> Vec<Forecast<K>> {
        let total = u64::try_from(self.outcomes.len()).unwrap_or(u64::MAX);
        let categories = self.config.depth.saturating_add(1);
        let beyond_candidates = candidates
            .iter()
            .filter(|candidate| self.rank_of(candidate).is_none())
            .count()
            .max(1) as f64;
        candidates
            .iter()
            .map(|candidate| {
                let (probability, std_dev) = match self.rank_of(candidate) {
                    Some(rank) => posterior(
                        self.at_rank.get(rank).copied().unwrap_or(0),
                        total,
                        categories,
                        self.config.prior,
                    ),
                    None => {
                        let (mean, deviation) =
                            posterior(self.beyond, total, categories, self.config.prior);
                        (mean / beyond_candidates, deviation / beyond_candidates)
                    }
                };
                Forecast {
                    key: candidate.clone(),
                    origin: CandidateOrigin::Recency,
                    probability,
                    std_dev,
                    observations: total,
                }
            })
            .collect()
    }

    fn footprint(&self) -> usize {
        self.recent.len() + self.outcomes.len()
    }
}
