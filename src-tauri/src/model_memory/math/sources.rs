//! Multi-source loading (GPU §1.1, §2.5).
//!
//! Sources are chosen by predicted completion time, authorization and interference,
//! never by kind, so a congested LAN donor can lose to local NVMe. Startup costs count;
//! a network or storage cut shared by several sources keeps one measured capacity,
//! divided max-min fairly; advertised bandwidth is never used, so it is never summed.
//! Work then moves by bounded stealing with per-source concurrency caps and hysteresis.
//! Plan quality is measured, not guaranteed by a scheduling theorem.
//!
//! During a load a source can be excluded, for example when it is blacklisted, and a
//! failed batch can be queued again; both place the work on the usable source predicted
//! to finish it earliest. [`SharedSourceCaps`] holds per-source caps across several
//! loads.

use std::collections::BTreeMap;
use std::fmt;

use super::bounds::{BandwidthBasis, BandwidthRating, UnusableBandwidth};
use super::{non_negative, CutId, InputError, SourceId};

/// Whether this load may read from a source (GPU §1.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceAuthorization {
    Authorized,
    Unauthorized,
}

/// A source of the bytes being loaded (GPU §2.5).
#[derive(Clone, Debug, PartialEq)]
pub struct SourceSpec {
    pub id: SourceId,
    pub authorization: SourceAuthorization,
    /// Time before the first byte arrives: connection, handshake, open or seek.
    pub startup_seconds: f64,
    /// Measured usable rate under current conditions; a congested donor reports its
    /// congested rate.
    pub bandwidth: BandwidthRating,
    /// Shared cuts this source's bytes cross.
    pub cuts: Vec<CutId>,
    /// Most batches this source may have in flight at once.
    pub max_in_flight: u32,
    /// Interference cost, in seconds of the declared objective per byte read from this
    /// source, such as slowing a donor's own serving.
    pub interference_seconds_per_byte: f64,
}

/// A network or storage cut that several sources share; its capacity is counted once.
#[derive(Clone, Debug, PartialEq)]
pub struct CutSpec {
    pub id: CutId,
    pub bandwidth: BandwidthRating,
}

/// Hysteresis and bounds for work stealing (GPU §2.5).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct StealPolicy {
    /// A rebalance is kept only if it improves the objective by at least this much...
    pub min_gain_seconds: f64,
    /// ...and by at least this fraction of the objective before it.
    pub min_gain_fraction: f64,
    /// A batch moves at most this many times over the whole load.
    pub max_moves_per_batch: u32,
    /// At most this many batches move in one rebalance.
    pub max_moves_per_rebalance: u32,
}

/// Why a multi-source plan or step was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum SourcesError {
    Input(InputError),
    /// A source or cut has an advertised or aggregate figure; only measured directional
    /// bandwidth is used, so advertised figures are never summed (GPU §2.5).
    UnusableBandwidth {
        name: String,
        basis: BandwidthBasis,
    },
    /// No authorized source remains.
    NoAuthorizedSource,
    /// The source is excluded from this load: it is not authorized, or it was excluded
    /// during the load.
    SourceExcluded {
        source: SourceId,
    },
    /// The batch is not in flight (on the named source, where one is named), so it
    /// cannot complete or fail.
    BatchNotInFlight {
        batch: usize,
    },
}

impl From<InputError> for SourcesError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for SourcesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::UnusableBandwidth { name, basis } => write!(
                f,
                "{name} has a {basis:?} figure, not a measured usable directional bandwidth"
            ),
            Self::NoAuthorizedSource => f.write_str("no authorized source can supply the bytes"),
            Self::SourceExcluded { source } => {
                write!(f, "{source} is excluded from this load")
            }
            Self::BatchNotInFlight { batch } => write!(f, "batch {batch} is not in flight"),
        }
    }
}

impl std::error::Error for SourcesError {}

/// Where a batch is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchStatus {
    Queued,
    InFlight,
    Done,
}

/// A batch started on a source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispatch {
    pub batch: usize,
    pub source: SourceId,
}

/// A queued batch moved from one source to another.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Steal {
    pub batch: usize,
    pub from: SourceId,
    pub to: SourceId,
}

/// What a rebalance found and whether it was kept.
#[derive(Clone, Debug, PartialEq)]
pub struct Rebalance {
    /// The moves kept; empty when the gain stayed inside the hysteresis band.
    pub steals: Vec<Steal>,
    pub objective_before_seconds: f64,
    /// The objective the bounded moves would reach.
    pub objective_found_seconds: f64,
    pub committed: bool,
}

/// One cut's allocated rate beside its measured capacity.
#[derive(Clone, Debug, PartialEq)]
pub struct CutUsage {
    pub cut: CutId,
    pub allocated_bytes_per_second: f64,
    pub capacity_bytes_per_second: f64,
}

/// A batch and the source it is now assigned to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Placement {
    pub batch: usize,
    pub source: SourceId,
}

/// What excluding a source during a load did (GPU §1.1, §2.5).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SourceExclusion {
    /// False when the source was already excluded; nothing changed then.
    pub newly_excluded: bool,
    /// Batches that were in flight on the source. They are queued again; their transfers
    /// must be cancelled and their bytes discarded.
    pub withdrawn: Vec<usize>,
    /// Every unfinished batch the source held, and where it went.
    pub reassigned: Vec<Placement>,
    /// Unfinished batches that no usable source can take: the load cannot finish.
    pub stranded: Vec<usize>,
}

#[derive(Clone, Debug)]
struct Source {
    spec: SourceSpec,
    measured_bytes_per_second: f64,
    cut_indices: Vec<usize>,
    rate_bytes_per_second: f64,
    started: bool,
    in_flight: u32,
    excluded: bool,
}

#[derive(Clone, Debug)]
struct Batch {
    bytes: u64,
    /// `None` only for a stranded batch: no usable source remains for it.
    source: Option<usize>,
    status: BatchStatus,
    moves: u32,
    failures: u32,
}

/// A load spread over several sources (GPU §2.5).
#[derive(Clone, Debug)]
pub struct MultiSourceLoad {
    sources: Vec<Source>,
    excluded: Vec<SourceId>,
    cuts: Vec<CutSpec>,
    cut_capacity: Vec<f64>,
    batches: Vec<Batch>,
    policy: StealPolicy,
}

/// A constraint within this fraction of its limit counts as reached.
const TIGHT: f64 = 1e-12;

fn usable(name: &str, rating: &BandwidthRating) -> Result<f64, SourcesError> {
    rating
        .usable_bytes_per_second()
        .map_err(
            |UnusableBandwidth { basis }| SourcesError::UnusableBandwidth {
                name: name.to_string(),
                basis,
            },
        )
}

impl Batch {
    fn is_stranded(&self) -> bool {
        self.source.is_none() && self.status != BatchStatus::Done
    }
}

impl MultiSourceLoad {
    /// Validates the inputs, excludes unauthorized sources and assigns every batch, in
    /// order, to the source predicted to finish it earliest, counting startup, the
    /// source's share of each shared cut and its interference cost.
    pub fn plan(
        sources: Vec<SourceSpec>,
        cuts: Vec<CutSpec>,
        batches_bytes: &[u64],
        policy: StealPolicy,
    ) -> Result<Self, SourcesError> {
        if batches_bytes.is_empty() {
            return Err(InputError::Empty { field: "batches" }.into());
        }
        if batches_bytes.contains(&0) {
            return Err(InputError::NotPositive {
                field: "batch bytes",
            }
            .into());
        }
        batches_bytes
            .iter()
            .try_fold(0u64, |total, &bytes| total.checked_add(bytes))
            .ok_or(InputError::Overflow {
                field: "batch bytes",
            })?;
        non_negative("min_gain_seconds", policy.min_gain_seconds)?;
        non_negative("min_gain_fraction", policy.min_gain_fraction)?;
        let mut cut_capacity = Vec::with_capacity(cuts.len());
        for (index, cut) in cuts.iter().enumerate() {
            if cuts[..index].iter().any(|other| other.id == cut.id) {
                return Err(InputError::Duplicate {
                    field: "cuts",
                    name: cut.id.to_string(),
                }
                .into());
            }
            cut_capacity.push(usable(cut.id.as_str(), &cut.bandwidth)?);
        }
        if sources.is_empty() {
            return Err(InputError::Empty { field: "sources" }.into());
        }
        let mut admitted = Vec::new();
        let mut excluded = Vec::new();
        for (index, spec) in sources.iter().enumerate() {
            if sources[..index].iter().any(|other| other.id == spec.id) {
                return Err(InputError::Duplicate {
                    field: "sources",
                    name: spec.id.to_string(),
                }
                .into());
            }
            let source = Self::admit(spec.clone(), &cuts)?;
            match spec.authorization {
                SourceAuthorization::Authorized => admitted.push(source),
                SourceAuthorization::Unauthorized => excluded.push(spec.id.clone()),
            }
        }
        if admitted.is_empty() {
            return Err(SourcesError::NoAuthorizedSource);
        }
        let mut load = Self {
            sources: admitted,
            excluded,
            cuts,
            cut_capacity,
            batches: batches_bytes
                .iter()
                .map(|&bytes| Batch {
                    bytes,
                    source: None,
                    status: BatchStatus::Queued,
                    moves: 0,
                    failures: 0,
                })
                .collect(),
            policy,
        };
        let mut active = vec![true; load.sources.len()];
        for _ in 0..=load.sources.len() {
            let rates = load.allocate(&active);
            load.assign_greedily(&active, &rates);
            let used: Vec<bool> = (0..load.sources.len())
                .map(|source| {
                    load.batches
                        .iter()
                        .any(|batch| batch.source == Some(source))
                })
                .collect();
            if used == active {
                break;
            }
            active = used;
        }
        load.reallocate();
        Ok(load)
    }

    fn admit(spec: SourceSpec, cuts: &[CutSpec]) -> Result<Source, SourcesError> {
        non_negative("startup_seconds", spec.startup_seconds)?;
        non_negative(
            "interference_seconds_per_byte",
            spec.interference_seconds_per_byte,
        )?;
        if spec.max_in_flight == 0 {
            return Err(InputError::NotPositive {
                field: "max_in_flight",
            }
            .into());
        }
        let measured_bytes_per_second = usable(spec.id.as_str(), &spec.bandwidth)?;
        let mut cut_indices = Vec::with_capacity(spec.cuts.len());
        for cut in &spec.cuts {
            let index = cuts
                .iter()
                .position(|known| &known.id == cut)
                .ok_or_else(|| InputError::Unknown {
                    field: "SourceSpec.cuts",
                    name: cut.to_string(),
                })?;
            if cut_indices.contains(&index) {
                return Err(InputError::Duplicate {
                    field: "SourceSpec.cuts",
                    name: cut.to_string(),
                }
                .into());
            }
            cut_indices.push(index);
        }
        Ok(Source {
            spec,
            measured_bytes_per_second,
            cut_indices,
            rate_bytes_per_second: 0.0,
            started: false,
            in_flight: 0,
            excluded: false,
        })
    }

    /// Max-min fair rates for the active sources: each is capped by its own measured
    /// rate, and the sources crossing a cut never get more than its capacity together.
    fn allocate(&self, active: &[bool]) -> Vec<f64> {
        let count = self.sources.len();
        let mut rates = vec![0.0; count];
        let mut frozen: Vec<bool> = active.iter().map(|is_active| !is_active).collect();
        let mut remaining = self.cut_capacity.clone();
        for _ in 0..=count + remaining.len() {
            let mut users = vec![0usize; remaining.len()];
            for (index, source) in self.sources.iter().enumerate() {
                if !frozen[index] {
                    for &cut in &source.cut_indices {
                        users[cut] += 1;
                    }
                }
            }
            if frozen.iter().all(|done| *done) {
                break;
            }
            let mut delta = f64::INFINITY;
            for (index, source) in self.sources.iter().enumerate() {
                if !frozen[index] {
                    delta = delta.min(source.measured_bytes_per_second - rates[index]);
                }
            }
            for (cut, &sharing) in users.iter().enumerate() {
                if sharing > 0 {
                    delta = delta.min(remaining[cut] / sharing as f64);
                }
            }
            let delta = delta.max(0.0);
            for (index, rate) in rates.iter_mut().enumerate() {
                if !frozen[index] {
                    *rate += delta;
                }
            }
            for (cut, &sharing) in users.iter().enumerate() {
                remaining[cut] = (remaining[cut] - delta * sharing as f64).max(0.0);
            }
            for (index, source) in self.sources.iter().enumerate() {
                let own_full = source.measured_bytes_per_second - rates[index]
                    <= TIGHT * source.measured_bytes_per_second;
                let cut_full = source
                    .cut_indices
                    .iter()
                    .any(|&cut| remaining[cut] <= TIGHT * self.cut_capacity[cut]);
                if own_full || cut_full {
                    frozen[index] = true;
                }
            }
        }
        rates
    }

    fn assign_greedily(&mut self, active: &[bool], rates: &[f64]) {
        let mut assigned = vec![0.0f64; self.sources.len()];
        for batch in &mut self.batches {
            let bytes = batch.bytes as f64;
            let mut best: Option<(usize, f64)> = None;
            for (index, source) in self.sources.iter().enumerate() {
                if !active[index] || rates[index] <= 0.0 {
                    continue;
                }
                let finish = source.spec.startup_seconds + (assigned[index] + bytes) / rates[index];
                let score = finish + source.spec.interference_seconds_per_byte * bytes;
                if best.is_none_or(|(_, current)| score < current) {
                    best = Some((index, score));
                }
            }
            if let Some((index, _)) = best {
                batch.source = Some(index);
                assigned[index] += bytes;
            }
        }
    }

    fn remaining_bytes(&self, source: usize) -> u64 {
        self.batches
            .iter()
            .filter(|batch| batch.source == Some(source) && batch.status != BatchStatus::Done)
            .map(|batch| batch.bytes)
            .sum()
    }

    /// Recomputes the cut shares for the sources that still have work.
    fn reallocate(&mut self) {
        let active: Vec<bool> = (0..self.sources.len())
            .map(|source| self.remaining_bytes(source) > 0)
            .collect();
        let rates = self.allocate(&active);
        for (source, rate) in self.sources.iter_mut().zip(rates) {
            source.rate_bytes_per_second = rate;
        }
    }

    fn finish_seconds(&self, source: usize) -> f64 {
        let remaining = self.remaining_bytes(source);
        if remaining == 0 {
            return 0.0;
        }
        let state = &self.sources[source];
        if state.rate_bytes_per_second <= 0.0 {
            return f64::INFINITY;
        }
        let startup = if state.started {
            0.0
        } else {
            state.spec.startup_seconds
        };
        startup + remaining as f64 / state.rate_bytes_per_second
    }

    /// Predicted seconds from now until every batch is done; infinite while any batch
    /// is stranded.
    pub fn predicted_completion_seconds(&self) -> f64 {
        if self.batches.iter().any(Batch::is_stranded) {
            return f64::INFINITY;
        }
        (0..self.sources.len())
            .map(|source| self.finish_seconds(source))
            .fold(0.0, f64::max)
    }

    /// The stealing objective: predicted completion plus the interference cost of the
    /// bytes still to be read.
    pub fn objective_seconds(&self) -> f64 {
        self.predicted_completion_seconds()
            + self
                .sources
                .iter()
                .enumerate()
                .map(|(index, source)| {
                    source.spec.interference_seconds_per_byte * self.remaining_bytes(index) as f64
                })
                .sum::<f64>()
    }

    /// The index of a source that is still usable in this load.
    fn index_of(&self, source: &SourceId) -> Result<usize, SourcesError> {
        match self
            .sources
            .iter()
            .position(|known| &known.spec.id == source)
        {
            Some(index) if !self.sources[index].excluded => Ok(index),
            Some(_) => Err(SourcesError::SourceExcluded {
                source: source.clone(),
            }),
            None if self.excluded.contains(source) => Err(SourcesError::SourceExcluded {
                source: source.clone(),
            }),
            None => Err(InputError::Unknown {
                field: "source",
                name: source.to_string(),
            }
            .into()),
        }
    }

    fn usable_source(&self, source: &SourceId) -> Option<&Source> {
        self.sources
            .iter()
            .find(|known| &known.spec.id == source && !known.excluded)
    }

    /// Sources left out of this load: not authorized when it was planned, or excluded
    /// since.
    pub fn excluded(&self) -> &[SourceId] {
        &self.excluded
    }

    /// The source a batch is assigned to; `None` for an unknown or stranded batch.
    pub fn owner(&self, batch: usize) -> Option<&SourceId> {
        self.batches
            .get(batch)
            .and_then(|batch| batch.source)
            .and_then(|source| self.sources.get(source))
            .map(|source| &source.spec.id)
    }

    /// Where a batch is; `None` for an unknown batch.
    pub fn status(&self, batch: usize) -> Option<BatchStatus> {
        self.batches.get(batch).map(|batch| batch.status)
    }

    /// How many times a batch failed and was queued again; `None` for an unknown batch.
    pub fn failures(&self, batch: usize) -> Option<u32> {
        self.batches.get(batch).map(|batch| batch.failures)
    }

    /// Unfinished batches that no usable source can take; while any remain the load
    /// cannot finish.
    pub fn stranded(&self) -> Vec<usize> {
        self.batches
            .iter()
            .enumerate()
            .filter(|(_, batch)| batch.is_stranded())
            .map(|(index, _)| index)
            .collect()
    }

    /// Batches assigned to a source, in order.
    pub fn batches_of(&self, source: &SourceId) -> Vec<usize> {
        self.batches
            .iter()
            .enumerate()
            .filter(|(_, batch)| {
                batch
                    .source
                    .and_then(|owner| self.sources.get(owner))
                    .is_some_and(|owner| &owner.spec.id == source)
            })
            .map(|(index, _)| index)
            .collect()
    }

    /// A source's current share of bandwidth; `None` if it is not part of this load or
    /// was excluded.
    pub fn rate_bytes_per_second(&self, source: &SourceId) -> Option<f64> {
        self.usable_source(source)
            .map(|known| known.rate_bytes_per_second)
    }

    /// Batches a source has in flight; `None` if it is not part of this load or was
    /// excluded.
    pub fn in_flight(&self, source: &SourceId) -> Option<u32> {
        self.usable_source(source).map(|known| known.in_flight)
    }

    /// Every cut's allocated rate beside its capacity.
    pub fn cut_usage(&self) -> Vec<CutUsage> {
        self.cuts
            .iter()
            .enumerate()
            .map(|(cut, spec)| CutUsage {
                cut: spec.id.clone(),
                allocated_bytes_per_second: self
                    .sources
                    .iter()
                    .filter(|source| source.cut_indices.contains(&cut))
                    .map(|source| source.rate_bytes_per_second)
                    .sum(),
                capacity_bytes_per_second: self.cut_capacity[cut],
            })
            .collect()
    }

    /// Starts queued batches in order, never more than a source's cap in flight. Use
    /// [`SharedSourceCaps::dispatch`] when caps must also hold across loads.
    pub fn dispatch(&mut self) -> Vec<Dispatch> {
        self.dispatch_within(&mut BTreeMap::new())
    }

    /// [`Self::dispatch`], also taking one of `shared_free` for each batch started on a
    /// source listed there, and starting none there once it reaches zero.
    fn dispatch_within(&mut self, shared_free: &mut BTreeMap<SourceId, u32>) -> Vec<Dispatch> {
        let mut started = Vec::new();
        for (index, batch) in self.batches.iter_mut().enumerate() {
            if batch.status != BatchStatus::Queued {
                continue;
            }
            let Some(source) = batch.source.and_then(|owner| self.sources.get_mut(owner)) else {
                continue;
            };
            if source.excluded || source.in_flight >= source.spec.max_in_flight {
                continue;
            }
            if let Some(free) = shared_free.get_mut(&source.spec.id) {
                if *free == 0 {
                    continue;
                }
                *free -= 1;
            }
            batch.status = BatchStatus::InFlight;
            source.in_flight += 1;
            source.started = true;
            started.push(Dispatch {
                batch: index,
                source: source.spec.id.clone(),
            });
        }
        started
    }

    /// Records that an in-flight batch finished.
    pub fn complete(&mut self, batch: usize) -> Result<(), SourcesError> {
        let state = self
            .batches
            .get_mut(batch)
            .ok_or_else(|| InputError::Unknown {
                field: "batch",
                name: batch.to_string(),
            })?;
        if state.status != BatchStatus::InFlight {
            return Err(SourcesError::BatchNotInFlight { batch });
        }
        state.status = BatchStatus::Done;
        if let Some(source) = state.source.and_then(|owner| self.sources.get_mut(owner)) {
            source.in_flight = source.in_flight.saturating_sub(1);
        }
        self.reallocate();
        Ok(())
    }

    /// [`Self::complete`] for a batch that `source` reports finished. Refused unless the
    /// batch is in flight on that source, so a late report from a source the batch was
    /// taken back from, or from an excluded source, is never accepted.
    pub fn complete_from(&mut self, batch: usize, source: &SourceId) -> Result<(), SourcesError> {
        let index = self.index_of(source)?;
        self.check_in_flight_on(batch, index)?;
        self.complete(batch)
    }

    fn check_in_flight_on(&self, batch: usize, source: usize) -> Result<(), SourcesError> {
        let state = self.batches.get(batch).ok_or_else(|| InputError::Unknown {
            field: "batch",
            name: batch.to_string(),
        })?;
        if state.status != BatchStatus::InFlight || state.source != Some(source) {
            return Err(SourcesError::BatchNotInFlight { batch });
        }
        Ok(())
    }

    /// Queues a batch that failed on `source` again and assigns it to the usable source
    /// predicted to finish it earliest, which may be the same one (GPU §2.5). Refused
    /// unless the batch is in flight on that source. Each requeue counts in
    /// [`Self::failures`]; it is not a steal and does not use up `max_moves_per_batch`.
    pub fn requeue_failed(
        &mut self,
        batch: usize,
        source: &SourceId,
    ) -> Result<Placement, SourcesError> {
        let index = self.index_of(source)?;
        self.check_in_flight_on(batch, index)?;
        if let Some(state) = self.batches.get_mut(batch) {
            state.status = BatchStatus::Queued;
            state.failures = state.failures.saturating_add(1);
        }
        if let Some(owner) = self.sources.get_mut(index) {
            owner.in_flight = owner.in_flight.saturating_sub(1);
        }
        let placed = self.place(batch);
        self.reallocate();
        placed
            .map(|owner| Placement {
                batch,
                source: owner,
            })
            .ok_or(SourcesError::NoAuthorizedSource)
    }

    /// Excludes a source for the rest of the load, for example once it is blacklisted
    /// (GPU §1.1). Its in-flight batches are withdrawn and queued again, and each
    /// unfinished batch it held goes, in order, to the usable source predicted to finish
    /// it earliest; with none left the batch is stranded. The source never receives work
    /// again: dispatch, stealing and placement skip it, and its reports are refused.
    /// Batches it already finished stay finished. Excluding an excluded source, including
    /// one that was not authorized, changes nothing.
    pub fn exclude_source(&mut self, source: &SourceId) -> Result<SourceExclusion, SourcesError> {
        let index = match self
            .sources
            .iter()
            .position(|known| &known.spec.id == source)
        {
            Some(index) if !self.sources[index].excluded => index,
            Some(_) => return Ok(SourceExclusion::default()),
            None if self.excluded.contains(source) => return Ok(SourceExclusion::default()),
            None => {
                return Err(InputError::Unknown {
                    field: "source",
                    name: source.to_string(),
                }
                .into())
            }
        };
        if let Some(state) = self.sources.get_mut(index) {
            state.excluded = true;
            state.in_flight = 0;
            state.rate_bytes_per_second = 0.0;
        }
        self.excluded.push(source.clone());
        let mut withdrawn = Vec::new();
        let mut unfinished = Vec::new();
        for (position, batch) in self.batches.iter_mut().enumerate() {
            if batch.source == Some(index) && batch.status != BatchStatus::Done {
                if batch.status == BatchStatus::InFlight {
                    batch.status = BatchStatus::Queued;
                    withdrawn.push(position);
                }
                batch.source = None;
                unfinished.push(position);
            }
        }
        self.reallocate();
        let mut reassigned = Vec::new();
        let mut stranded = Vec::new();
        for batch in unfinished {
            match self.place(batch) {
                Some(owner) => reassigned.push(Placement {
                    batch,
                    source: owner,
                }),
                None => stranded.push(batch),
            }
        }
        self.reallocate();
        Ok(SourceExclusion {
            newly_excluded: true,
            withdrawn,
            reassigned,
            stranded,
        })
    }

    /// Assigns a queued batch to the usable source predicted to finish it earliest,
    /// counting startup, the cut shares with the batch added and interference, as
    /// [`Self::plan`] does; `None`, leaving it stranded, when no usable source remains.
    fn place(&mut self, batch: usize) -> Option<SourceId> {
        let bytes = self.batches.get(batch)?.bytes as f64;
        let mut best: Option<(f64, usize)> = None;
        for candidate in 0..self.sources.len() {
            if self.sources[candidate].excluded {
                continue;
            }
            let mut trial = self.clone();
            if let Some(state) = trial.batches.get_mut(batch) {
                state.source = Some(candidate);
            }
            trial.reallocate();
            let score = trial.finish_seconds(candidate)
                + trial.sources[candidate].spec.interference_seconds_per_byte * bytes;
            if best.is_none_or(|(current, _)| score < current) {
                best = Some((score, candidate));
            }
        }
        let chosen = best.map(|(_, candidate)| candidate);
        if let Some(state) = self.batches.get_mut(batch) {
            state.source = chosen;
        }
        chosen
            .and_then(|index| self.sources.get(index))
            .map(|owner| owner.spec.id.clone())
    }

    /// Replaces a source's measured rate, for example when a donor becomes congested.
    pub fn observe_rate(
        &mut self,
        source: &SourceId,
        measured: BandwidthRating,
    ) -> Result<(), SourcesError> {
        let index = self.index_of(source)?;
        self.sources[index].measured_bytes_per_second = usable(source.as_str(), &measured)?;
        self.reallocate();
        Ok(())
    }

    /// Bounded work stealing (GPU §2.5). The source predicted to finish last gives up
    /// its last queued batch to the source whose objective after the move is lowest,
    /// that is the one predicted to finish it earliest. In-flight batches never move,
    /// excluded sources never receive work, a batch moves at most `max_moves_per_batch`
    /// times, and the moves are kept only when their total gain clears the hysteresis
    /// band.
    pub fn rebalance(&mut self) -> Rebalance {
        let objective_before_seconds = self.objective_seconds();
        let mut trial = self.clone();
        let mut steals = Vec::new();
        while steals.len() < self.policy.max_moves_per_rebalance as usize {
            let current = trial.objective_seconds();
            let Some((victim, batch)) = trial.steal_candidate() else {
                break;
            };
            let mut best: Option<(f64, MultiSourceLoad, usize)> = None;
            for thief in 0..trial.sources.len() {
                if thief == victim || trial.sources[thief].excluded {
                    continue;
                }
                let mut moved = trial.clone();
                moved.batches[batch].source = Some(thief);
                moved.batches[batch].moves += 1;
                moved.reallocate();
                let objective = moved.objective_seconds();
                if best.as_ref().is_none_or(|(value, _, _)| objective < *value) {
                    best = Some((objective, moved, thief));
                }
            }
            match best {
                Some((objective, moved, thief)) if objective < current => {
                    steals.push(Steal {
                        batch,
                        from: trial.sources[victim].spec.id.clone(),
                        to: trial.sources[thief].spec.id.clone(),
                    });
                    trial = moved;
                }
                _ => break,
            }
        }
        let objective_found_seconds = trial.objective_seconds();
        let gain = objective_before_seconds - objective_found_seconds;
        let committed = !steals.is_empty()
            && gain >= self.policy.min_gain_seconds
            && gain >= self.policy.min_gain_fraction * objective_before_seconds;
        if committed {
            *self = trial;
        } else {
            steals.clear();
        }
        Rebalance {
            steals,
            objective_before_seconds,
            objective_found_seconds,
            committed,
        }
    }

    /// The latest-finishing source with a movable queued batch, and its last such batch.
    fn steal_candidate(&self) -> Option<(usize, usize)> {
        let mut best: Option<(f64, usize, usize)> = None;
        for source in 0..self.sources.len() {
            if self.sources[source].excluded {
                continue;
            }
            let movable = self.batches.iter().enumerate().rev().find(|(_, batch)| {
                batch.source == Some(source)
                    && batch.status == BatchStatus::Queued
                    && batch.moves < self.policy.max_moves_per_batch
            });
            if let Some((batch, _)) = movable {
                let finish = self.finish_seconds(source);
                if best.is_none_or(|(latest, _, _)| finish > latest) {
                    best = Some((finish, source, batch));
                }
            }
        }
        best.map(|(_, source, batch)| (source, batch))
    }
}

/// Per-source concurrency caps that hold across several loads (GPU §2.5): for example a
/// LAN donor that serves this host at most four batches at a time, whatever it is
/// loading. Usage is counted from the loads' own in-flight batches at every dispatch, so
/// a load that finishes, fails, excludes the source or is dropped frees its slots with
/// no bookkeeping. Each load's own `max_in_flight` still applies.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SharedSourceCaps {
    caps: BTreeMap<SourceId, u32>,
}

impl SharedSourceCaps {
    /// No shared caps yet: only each load's own caps apply.
    pub fn new() -> Self {
        Self::default()
    }

    /// Caps `source` across loads; the cap must be at least 1. A cap below the batches
    /// already in flight stops new dispatches there until enough finish.
    pub fn set_cap(&mut self, source: SourceId, max_in_flight: u32) -> Result<(), SourcesError> {
        if max_in_flight == 0 {
            return Err(InputError::NotPositive {
                field: "max_in_flight",
            }
            .into());
        }
        self.caps.insert(source, max_in_flight);
        Ok(())
    }

    /// Removes a source's shared cap and returns it.
    pub fn remove_cap(&mut self, source: &SourceId) -> Option<u32> {
        self.caps.remove(source)
    }

    /// The shared cap of a source, if it has one.
    pub fn cap(&self, source: &SourceId) -> Option<u32> {
        self.caps.get(source).copied()
    }

    /// Batches in flight on `source` across `loads`.
    pub fn in_flight_across(loads: &[&MultiSourceLoad], source: &SourceId) -> u32 {
        loads.iter().fold(0u32, |total, load| {
            total.saturating_add(load.in_flight(source).unwrap_or(0))
        })
    }

    /// Dispatches each load in turn, earlier loads first, within its own caps and the
    /// shared caps, counting the batches every load already has in flight. Returns each
    /// dispatch with the position of its load in `loads`. Shared caps hold only for
    /// dispatches made through this method.
    pub fn dispatch(&self, loads: &mut [&mut MultiSourceLoad]) -> Vec<(usize, Dispatch)> {
        let mut free: BTreeMap<SourceId, u32> = self
            .caps
            .iter()
            .map(|(source, &cap)| {
                let used = loads.iter().fold(0u32, |total, load| {
                    total.saturating_add(load.in_flight(source).unwrap_or(0))
                });
                (source.clone(), cap.saturating_sub(used))
            })
            .collect();
        let mut started = Vec::new();
        for (position, load) in loads.iter_mut().enumerate() {
            started.extend(
                load.dispatch_within(&mut free)
                    .into_iter()
                    .map(|dispatch| (position, dispatch)),
            );
        }
        started
    }
}

#[cfg(test)]
mod tests;
