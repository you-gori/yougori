//! The first-order Markov predictor (GPU §2.9 line 642: "compare recency/Markov models"):
//! transition counts from each request's key to the next, learned online.
//!
//! The probability that the next request is a candidate is the posterior mean of its
//! transition count from the last request's key under a symmetric Dirichlet prior over
//! the candidates. Memory is bounded three ways: at most `max_states` source keys (the
//! least recently updated row is forgotten first), at most `max_successors` successors
//! per row (the smallest count is forgotten first, ties by age), and counts are halved
//! whenever a row's total reaches `halve_at`, so old evidence fades and a phase change is
//! learned within a bounded number of requests.

use std::collections::BTreeMap;

use super::{posterior, Forecast, PredictionError, Predictor};
use crate::model_memory::math::prefetch::CandidateOrigin;

/// The largest bounds accepted.
pub const MAX_MARKOV_STATES: usize = 4_096;
pub const MAX_MARKOV_SUCCESSORS: usize = 256;

/// How much the Markov predictor remembers.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct MarkovConfig {
    /// Source keys kept, at most [`MAX_MARKOV_STATES`].
    pub max_states: usize,
    /// Successors kept per source key, at most [`MAX_MARKOV_SUCCESSORS`].
    pub max_successors: usize,
    /// A row's counts are halved when its total reaches this; at least 2.
    pub halve_at: u64,
    /// Dirichlet prior per candidate: more than zero.
    pub prior: f64,
}

impl MarkovConfig {
    fn check(self) -> Result<Self, PredictionError> {
        let invalid = |field, reason| Err(PredictionError::InvalidConfig { field, reason });
        if self.max_states == 0 || self.max_states > MAX_MARKOV_STATES {
            return invalid("markov.max_states", "between 1 and 4096");
        }
        if self.max_successors == 0 || self.max_successors > MAX_MARKOV_SUCCESSORS {
            return invalid("markov.max_successors", "between 1 and 256");
        }
        if self.halve_at < 2 {
            return invalid("markov.halve_at", "at least 2");
        }
        if !self.prior.is_finite() || self.prior <= 0.0 {
            return invalid("markov.prior", "a finite number more than zero");
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, PartialEq)]
struct Successor {
    count: u64,
    /// When it was last counted, on the predictor's own request counter.
    seen: u64,
}

#[derive(Clone, Debug, PartialEq)]
struct Row<K> {
    successors: BTreeMap<K, Successor>,
    total: u64,
    updated: u64,
}

/// The first-order transition predictor (see the module documentation).
#[derive(Clone, Debug, PartialEq)]
pub struct MarkovPredictor<K> {
    config: MarkovConfig,
    rows: BTreeMap<K, Row<K>>,
    previous: Option<K>,
    requests: u64,
}

impl<K: Clone + Ord> MarkovPredictor<K> {
    /// An empty predictor; refuses zero or oversized bounds.
    pub fn new(config: MarkovConfig) -> Result<Self, PredictionError> {
        Ok(Self {
            config: config.check()?,
            rows: BTreeMap::new(),
            previous: None,
            requests: 0,
        })
    }

    pub fn config(&self) -> MarkovConfig {
        self.config
    }

    /// The key forecasts are conditioned on: the last request.
    pub fn previous(&self) -> Option<&K> {
        self.previous.as_ref()
    }

    /// Source keys held now.
    pub fn states(&self) -> usize {
        self.rows.len()
    }

    /// The transition count from `from` to `to` as held now.
    pub fn count(&self, from: &K, to: &K) -> u64 {
        self.rows
            .get(from)
            .and_then(|row| row.successors.get(to))
            .map_or(0, |successor| successor.count)
    }

    fn learn(&mut self, from: K, to: &K) {
        let now = self.requests;
        if !self.rows.contains_key(&from) && self.rows.len() >= self.config.max_states {
            let stalest = self
                .rows
                .iter()
                .min_by(|(a_key, a), (b_key, b)| a.updated.cmp(&b.updated).then(a_key.cmp(b_key)))
                .map(|(key, _)| key.clone());
            if let Some(stalest) = stalest {
                self.rows.remove(&stalest);
            }
        }
        let max_successors = self.config.max_successors;
        let halve_at = self.config.halve_at;
        let row = self.rows.entry(from).or_insert_with(|| Row {
            successors: BTreeMap::new(),
            total: 0,
            updated: now,
        });
        row.updated = now;
        if !row.successors.contains_key(to) && row.successors.len() >= max_successors {
            let weakest = row
                .successors
                .iter()
                .min_by(|(a_key, a), (b_key, b)| {
                    a.count
                        .cmp(&b.count)
                        .then(a.seen.cmp(&b.seen))
                        .then(a_key.cmp(b_key))
                })
                .map(|(key, _)| key.clone());
            if let Some(weakest) = weakest {
                if let Some(removed) = row.successors.remove(&weakest) {
                    row.total = row.total.saturating_sub(removed.count);
                }
            }
        }
        let successor = row.successors.entry(to.clone()).or_insert(Successor {
            count: 0,
            seen: now,
        });
        successor.count = successor.count.saturating_add(1);
        successor.seen = now;
        row.total = row.total.saturating_add(1);
        if row.total >= halve_at {
            for successor in row.successors.values_mut() {
                successor.count /= 2;
            }
            row.successors.retain(|_, successor| successor.count > 0);
            row.total = row.successors.values().fold(0u64, |total, successor| {
                total.saturating_add(successor.count)
            });
        }
    }
}

impl<K: Clone + Ord> Predictor<K> for MarkovPredictor<K> {
    fn origin(&self) -> CandidateOrigin {
        CandidateOrigin::Markov
    }

    fn observe(&mut self, key: &K) {
        self.requests = self.requests.saturating_add(1);
        if let Some(previous) = self.previous.take() {
            self.learn(previous, key);
        }
        self.previous = Some(key.clone());
    }

    fn forecast(&self, candidates: &[K]) -> Vec<Forecast<K>> {
        let row = self
            .previous
            .as_ref()
            .and_then(|previous| self.rows.get(previous));
        let total = row.map_or(0, |row| row.total);
        candidates
            .iter()
            .map(|candidate| {
                let count = row
                    .and_then(|row| row.successors.get(candidate))
                    .map_or(0, |successor| successor.count);
                let (probability, std_dev) =
                    posterior(count, total, candidates.len(), self.config.prior);
                Forecast {
                    key: candidate.clone(),
                    origin: CandidateOrigin::Markov,
                    probability,
                    std_dev,
                    observations: total,
                }
            })
            .collect()
    }

    fn footprint(&self) -> usize {
        self.rows
            .values()
            .map(|row| 1 + row.successors.len())
            .sum::<usize>()
            + usize::from(self.previous.is_some())
    }
}
