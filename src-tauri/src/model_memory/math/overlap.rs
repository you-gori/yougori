//! Execute while loading (GPU §2.6).
//!
//! With `a_i` the time everything layer group `i` needs becomes usable and `t_i` its
//! compute time for the request, `f_0 = 0` and `f_i = max(a_i, f_(i-1)) + t_i`. Loading
//! never stalls after the first group exactly when `a_i <= a_1 + sum_(j<i) t_j` for
//! every `i >= 2`; comparing each group's own transfer with its own compute is not
//! enough.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use super::{non_negative, InputError};

/// Why an overlap computation or MoE step was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum OverlapError {
    Input(InputError),
    /// A handle for an expert the step does not need was offered; another expert never
    /// stands in for the one the router chose (GPU §2.6).
    ExpertNotRequired {
        expert: ExpertId,
    },
    ExpertAlreadyBound {
        expert: ExpertId,
    },
    /// The step cannot start: these exact experts are not bound yet.
    MissingExperts {
        experts: Vec<ExpertId>,
    },
}

impl From<InputError> for OverlapError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for OverlapError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Input(error) => error.fmt(f),
            Self::ExpertNotRequired { expert } => {
                write!(f, "{expert} is not an expert this step requires")
            }
            Self::ExpertAlreadyBound { expert } => write!(f, "{expert} is already bound"),
            Self::MissingExperts { experts } => {
                write!(f, "the step waits for {} exact expert(s)", experts.len())
            }
        }
    }
}

impl std::error::Error for OverlapError {}

/// One layer group: when everything it needs is usable (`a_i`) and its compute time
/// for this request (`t_i`).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct GroupTiming {
    pub usable_at_seconds: f64,
    pub compute_seconds: f64,
}

fn validate(groups: &[GroupTiming]) -> Result<f64, OverlapError> {
    let first = groups
        .first()
        .ok_or(InputError::Empty { field: "groups" })?;
    for group in groups {
        non_negative("usable_at_seconds", group.usable_at_seconds)?;
        non_negative("compute_seconds", group.compute_seconds)?;
    }
    Ok(first.usable_at_seconds)
}

/// One step of the GPU §2.6 recurrence: `f_i = max(a_i, f_(i-1)) + t_i` for `group`
/// after a predecessor that finished at `previous_finish_seconds` (`f_0 = 0` before the
/// first group). [`finish_times`] and [`first_token`] apply it group by group.
pub fn finish_after(previous_finish_seconds: f64, group: GroupTiming) -> Result<f64, OverlapError> {
    let previous = non_negative("previous_finish_seconds", previous_finish_seconds)?;
    let usable_at = non_negative("usable_at_seconds", group.usable_at_seconds)?;
    let compute = non_negative("compute_seconds", group.compute_seconds)?;
    Ok(usable_at.max(previous) + compute)
}

/// `f_1..f_n` of the GPU §2.6 recurrence `f_i = max(a_i, f_(i-1)) + t_i`, `f_0 = 0`.
pub fn finish_times(groups: &[GroupTiming]) -> Result<Vec<f64>, OverlapError> {
    validate(groups)?;
    let mut finish = 0.0f64;
    groups
        .iter()
        .map(|group| {
            finish = finish_after(finish, *group)?;
            Ok(finish)
        })
        .collect()
}

/// `a_1 + sum_i t_i`: the finish when no group waits for loading after the first.
pub fn ideal_finish_seconds(groups: &[GroupTiming]) -> Result<f64, OverlapError> {
    let first = validate(groups)?;
    Ok(groups
        .iter()
        .fold(first, |total, group| total + group.compute_seconds))
}

/// The GPU §2.6 cumulative no-stall condition.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum NoStall {
    Holds,
    /// Group `group` (1-based) becomes usable after the earlier groups' compute ends.
    Stalls {
        group: usize,
        usable_at_seconds: f64,
        deadline_seconds: f64,
    },
}

/// Checks `a_i <= a_1 + sum_(j<i) t_j` for every `i >= 2` and names the first group
/// that breaks it.
pub fn no_stall(groups: &[GroupTiming]) -> Result<NoStall, OverlapError> {
    let mut deadline_seconds = validate(groups)?;
    for (index, group) in groups.iter().enumerate() {
        if index > 0 && group.usable_at_seconds > deadline_seconds {
            return Ok(NoStall::Stalls {
                group: index + 1,
                usable_at_seconds: group.usable_at_seconds,
                deadline_seconds,
            });
        }
        deadline_seconds += group.compute_seconds;
    }
    Ok(NoStall::Holds)
}

/// A dependency beyond a group's own weights (GPU §2.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DependencyKind {
    TiedEmbeddings,
    RecurrentState,
    NonPersistentBuffers,
    MultimodalEncoder,
    GraphCapture,
}

/// When one extra dependency becomes usable.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Dependency {
    pub kind: DependencyKind,
    pub usable_at_seconds: f64,
}

/// One group of a dense autoregressive model with everything it waits for.
#[derive(Clone, Debug, PartialEq)]
pub struct GroupRequirement {
    pub weights_usable_at_seconds: f64,
    pub compute_seconds: f64,
    pub dependencies: Vec<Dependency>,
}

/// Which group an input belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GroupRef {
    /// A layer group, numbered from 1.
    Layer(usize),
    OutputHead,
}

/// What a group waited for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitCause {
    Weights,
    Dependency(DependencyKind),
}

/// The input whose arrival set the first-token time: execution waited for it and was
/// compute-bound afterwards.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct CriticalInput {
    pub group: GroupRef,
    pub cause: WaitCause,
    pub usable_at_seconds: f64,
}

/// When the first generated token exists (GPU §2.6).
#[derive(Clone, Debug, PartialEq)]
pub struct FirstToken {
    pub layers_finish_seconds: f64,
    /// When the output head finishes: the earliest the first token can be emitted.
    pub first_token_seconds: f64,
    /// `None` when nothing was waited for, as when everything was usable at time zero.
    pub critical_input: Option<CriticalInput>,
}

fn latest_input(group: &GroupRequirement) -> Result<(f64, WaitCause), OverlapError> {
    let mut latest = (
        non_negative("weights_usable_at_seconds", group.weights_usable_at_seconds)?,
        WaitCause::Weights,
    );
    for dependency in &group.dependencies {
        let at = non_negative("Dependency.usable_at_seconds", dependency.usable_at_seconds)?;
        if at > latest.0 {
            latest = (at, WaitCause::Dependency(dependency.kind));
        }
    }
    Ok(latest)
}

/// The first generated token of a dense autoregressive model needs every required layer
/// group and then the output head (GPU §2.6). Execute-while-load overlaps prefill with
/// loading, but the token cannot exist before those weights and every extra dependency
/// (tied embeddings, recurrent state, non-persistent buffers, multimodal encoders,
/// graph capture) are usable.
pub fn first_token(
    layers: &[GroupRequirement],
    output_head: &GroupRequirement,
) -> Result<FirstToken, OverlapError> {
    if layers.is_empty() {
        return Err(InputError::Empty { field: "layers" }.into());
    }
    let mut finish = 0.0f64;
    let mut layers_finish_seconds = 0.0;
    let mut critical_input = None;
    let groups = layers
        .iter()
        .enumerate()
        .map(|(index, group)| (GroupRef::Layer(index + 1), group))
        .chain(std::iter::once((GroupRef::OutputHead, output_head)));
    for (reference, group) in groups {
        let (usable_at_seconds, cause) = latest_input(group)?;
        let compute_seconds = non_negative("compute_seconds", group.compute_seconds)?;
        if usable_at_seconds > finish {
            critical_input = Some(CriticalInput {
                group: reference,
                cause,
                usable_at_seconds,
            });
        }
        finish = finish_after(
            finish,
            GroupTiming {
                usable_at_seconds,
                compute_seconds,
            },
        )?;
        if let GroupRef::Layer(_) = reference {
            layers_finish_seconds = finish;
        }
    }
    Ok(FirstToken {
        layers_finish_seconds,
        first_token_seconds: finish,
        critical_input,
    })
}

/// One expert of one MoE layer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpertId {
    pub layer: u32,
    pub expert: u32,
}

impl fmt::Display for ExpertId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "layer {} expert {}", self.layer, self.expert)
    }
}

/// Proof that one exact expert is usable, and from when, tied to the cache entry it
/// came from. Only an [`ExpertCache`] makes one, for the expert that was looked up or
/// loaded.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ExpertHandle {
    expert: ExpertId,
    usable_at_seconds: f64,
    residency: u64,
}

impl ExpertHandle {
    /// The exact expert this handle proves usable.
    pub fn expert(&self) -> ExpertId {
        self.expert
    }

    /// When the expert becomes usable.
    pub fn usable_at_seconds(&self) -> f64 {
        self.usable_at_seconds
    }
}

/// The load a prediction miss requires: exactly the expert the router chose
/// (GPU §2.6). Only [`ExpertCache::lookup`] makes one, so its expert cannot be changed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExactExpertLoad {
    expert: ExpertId,
}

impl ExactExpertLoad {
    /// The exact expert to load.
    pub fn expert(&self) -> ExpertId {
        self.expert
    }
}

/// Experts that are resident or arriving, with when each becomes usable. Every insert
/// opens a new residency, so a handle taken before an eviction or a re-insert is
/// recognisably stale.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ExpertCache {
    held: BTreeMap<ExpertId, (f64, u64)>,
    next_residency: u64,
}

impl ExpertCache {
    /// An empty cache.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records an expert that is resident, or prefetched and usable at the given time.
    pub fn insert(&mut self, expert: ExpertId, usable_at_seconds: f64) -> Result<(), OverlapError> {
        self.hold(expert, usable_at_seconds).map(|_| ())
    }

    fn hold(&mut self, expert: ExpertId, usable_at_seconds: f64) -> Result<u64, OverlapError> {
        let at = non_negative("usable_at_seconds", usable_at_seconds)?;
        let residency = self.next_residency;
        self.next_residency = residency.checked_add(1).ok_or(InputError::Overflow {
            field: "expert residency",
        })?;
        self.held.insert(expert, (at, residency));
        Ok(residency)
    }

    /// A handle for exactly `expert`, or the exact load a miss needs. No nearby or
    /// similar expert is ever offered instead.
    pub fn lookup(&self, expert: ExpertId) -> Result<ExpertHandle, ExactExpertLoad> {
        match self.held.get(&expert) {
            Some(&(usable_at_seconds, residency)) => Ok(ExpertHandle {
                expert,
                usable_at_seconds,
                residency,
            }),
            None => Err(ExactExpertLoad { expert }),
        }
    }

    /// Records that an exact load finished and returns the handle for that same expert.
    pub fn complete_load(
        &mut self,
        load: ExactExpertLoad,
        usable_at_seconds: f64,
    ) -> Result<ExpertHandle, OverlapError> {
        let residency = self.hold(load.expert, usable_at_seconds)?;
        Ok(ExpertHandle {
            expert: load.expert,
            usable_at_seconds,
            residency,
        })
    }

    /// Evicts an expert and reports whether it was held. Later lookups miss it, and a
    /// step that bound it before must load it again: [`MoeStep::resolve`] issues the
    /// exact load and [`MoeStep::start_seconds_in`] refuses to start without it.
    pub fn evict(&mut self, expert: ExpertId) -> bool {
        self.held.remove(&expert).is_some()
    }

    /// Whether `expert` is still held under the residency a handle came from.
    fn holds(&self, expert: ExpertId, residency: u64) -> bool {
        self.held
            .get(&expert)
            .is_some_and(|&(_, held)| held == residency)
    }
}

/// One MoE step (GPU §2.6): it may start only when every expert the router chose is
/// bound. A miss stalls the step until that exact expert is loaded.
#[derive(Clone, Debug, PartialEq)]
pub struct MoeStep {
    required: BTreeSet<ExpertId>,
    bound: BTreeMap<ExpertId, (f64, u64)>,
}

impl MoeStep {
    /// A step that needs exactly these experts; refuses an empty or repeated list.
    pub fn new(required: &[ExpertId]) -> Result<Self, OverlapError> {
        if required.is_empty() {
            return Err(InputError::Empty {
                field: "required experts",
            }
            .into());
        }
        let mut set = BTreeSet::new();
        for expert in required {
            if !set.insert(*expert) {
                return Err(InputError::Duplicate {
                    field: "required experts",
                    name: expert.to_string(),
                }
                .into());
            }
        }
        Ok(Self {
            required: set,
            bound: BTreeMap::new(),
        })
    }

    /// Binds every required expert the cache holds and returns the exact loads that the
    /// misses need. A binding the cache no longer holds, because the expert was evicted
    /// or inserted again, is dropped and resolved afresh.
    pub fn resolve(&mut self, cache: &ExpertCache) -> Vec<ExactExpertLoad> {
        let mut loads = Vec::new();
        for expert in &self.required {
            if let Some(&(_, residency)) = self.bound.get(expert) {
                if cache.holds(*expert, residency) {
                    continue;
                }
                self.bound.remove(expert);
            }
            match cache.lookup(*expert) {
                Ok(handle) => {
                    self.bound
                        .insert(*expert, (handle.usable_at_seconds, handle.residency));
                }
                Err(load) => loads.push(load),
            }
        }
        loads
    }

    /// Binds a handle; refused unless it is for a required expert not yet bound.
    pub fn bind(&mut self, handle: ExpertHandle) -> Result<(), OverlapError> {
        if !self.required.contains(&handle.expert) {
            return Err(OverlapError::ExpertNotRequired {
                expert: handle.expert,
            });
        }
        if self.bound.contains_key(&handle.expert) {
            return Err(OverlapError::ExpertAlreadyBound {
                expert: handle.expert,
            });
        }
        self.bound
            .insert(handle.expert, (handle.usable_at_seconds, handle.residency));
        Ok(())
    }

    /// Required experts not yet bound.
    pub fn missing(&self) -> Vec<ExpertId> {
        self.required
            .iter()
            .filter(|expert| !self.bound.contains_key(*expert))
            .copied()
            .collect()
    }

    /// The earliest start at or after `ready_seconds`, when the step's other inputs are
    /// ready. Refused while any required expert is unbound, so the step waits for the
    /// exact expert instead of running with a substitute.
    pub fn start_seconds(&self, ready_seconds: f64) -> Result<f64, OverlapError> {
        let ready_seconds = non_negative("ready_seconds", ready_seconds)?;
        let missing = self.missing();
        if !missing.is_empty() {
            return Err(OverlapError::MissingExperts { experts: missing });
        }
        Ok(self
            .bound
            .values()
            .fold(ready_seconds, |latest, &(at, _)| latest.max(at)))
    }

    /// [`Self::start_seconds`] checked against `cache`: an expert evicted or inserted
    /// again since it was bound counts as missing, so the step never starts on an expert
    /// the cache no longer holds. Use it whenever the cache can evict.
    pub fn start_seconds_in(
        &self,
        cache: &ExpertCache,
        ready_seconds: f64,
    ) -> Result<f64, OverlapError> {
        let ready_seconds = non_negative("ready_seconds", ready_seconds)?;
        let missing: Vec<ExpertId> = self
            .required
            .iter()
            .filter(|expert| {
                !self
                    .bound
                    .get(*expert)
                    .is_some_and(|&(_, residency)| cache.holds(**expert, residency))
            })
            .copied()
            .collect();
        if !missing.is_empty() {
            return Err(OverlapError::MissingExperts { experts: missing });
        }
        Ok(self
            .bound
            .values()
            .fold(ready_seconds, |latest, &(at, _)| latest.max(at)))
    }
}

#[cfg(test)]
mod tests;
