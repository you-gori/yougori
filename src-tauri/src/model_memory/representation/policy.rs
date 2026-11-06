//! Adaptive policy with a reliable baseline (GPU §4.12, plan lines 770–776; GPU-W12
//! "Adaptive policy selection under hard constraints").
//!
//! Hand-coded policies and a shadow evaluator come first ([`HandCodedPolicy`],
//! [`shadow_evaluate`]). The [`ConstrainedBandit`] tunes exactly one knob over a closed
//! set of admitted arms: an arm is a value of that knob and nothing else, so it cannot
//! install a kernel, alter model semantics or change a host security setting
//! ([`ArmSet::admit`] refuses those requests). Every choice, its predicted outcome and its
//! realized outcome are logged; a choice must fit the granted memory headroom and the
//! caller's authorizations; exploration stops when the window p99 or the memory reserve
//! crosses its bound; and a distribution shift reverts to the baseline arm. Both latch
//! until an operator resets the bandit.
//!
//! A bandit acts live only with a [`LiveApproval`], built from a [`ShadowReport`] alone:
//! the report's provenance comes from the run records [`shadow_evaluate`] writes for its
//! own runs, so it must be a Yougori measurement and show the bandit beating the
//! strongest baseline. A fake-substrate shadow run never qualifies, and no provenance
//! from another run can be attached.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fmt;

use crate::foundation::ids::{validate_identifier, IdError};
use crate::foundation::report::{
    percentile, BenchId, Label, PercentileMethod, Provenance, Quantile, ReportError, RunSubstrate,
};
use crate::model_memory::bench::rng::SeededRng;
use crate::model_memory::math::{non_negative, positive, probability, InputError};

use super::evidence::{trial_records, EvidenceError, Trial, TrialArm};

/// Why a policy operation was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum PolicyError {
    /// The request is not a value of a tunable knob.
    ForbiddenChange {
        change: &'static str,
    },
    /// The arm sets another knob than the one this policy tunes.
    KnobMismatch {
        expected: Knob,
        found: Knob,
    },
    DuplicateArm,
    UnknownArm {
        arm: usize,
    },
    /// No arm the policy may choose satisfies the hard constraints now; nothing acts.
    NoFeasibleArm,
    UnknownDecision {
        sequence: u64,
    },
    AlreadyObserved {
        sequence: u64,
    },
    EmptyTrace,
    NoHandCodedPolicies,
    /// Live use needs the bandit to beat the strongest baseline in shadow evaluation.
    BanditNotBetter {
        bandit_seconds: f64,
        baseline_seconds: f64,
    },
    Input(InputError),
    Id(IdError),
    Report(ReportError),
    Evidence(EvidenceError),
}

impl From<EvidenceError> for PolicyError {
    fn from(error: EvidenceError) -> Self {
        Self::Evidence(error)
    }
}

impl From<InputError> for PolicyError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<IdError> for PolicyError {
    fn from(error: IdError) -> Self {
        Self::Id(error)
    }
}

impl From<ReportError> for PolicyError {
    fn from(error: ReportError) -> Self {
        Self::Report(error)
    }
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ForbiddenChange { change } => {
                write!(f, "an adaptive policy may not {change}")
            }
            Self::KnobMismatch { expected, found } => {
                write!(f, "this policy tunes {expected:?}, not {found:?}")
            }
            Self::DuplicateArm => f.write_str("the arm is already admitted"),
            Self::UnknownArm { arm } => write!(f, "no arm {arm}"),
            Self::NoFeasibleArm => f.write_str("no arm satisfies the hard constraints"),
            Self::UnknownDecision { sequence } => write!(f, "no decision {sequence}"),
            Self::AlreadyObserved { sequence } => {
                write!(f, "decision {sequence} already has its outcome")
            }
            Self::EmptyTrace => f.write_str("the trace is empty"),
            Self::NoHandCodedPolicies => f.write_str("hand-coded policies come first"),
            Self::BanditNotBetter {
                bandit_seconds,
                baseline_seconds,
            } => write!(
                f,
                "the bandit's {bandit_seconds} s does not beat the baseline's {baseline_seconds} s"
            ),
            Self::Input(error) => error.fmt(f),
            Self::Id(error) => error.fmt(f),
            Self::Report(error) => error.fmt(f),
            Self::Evidence(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PolicyError {}

/// The knobs a bandit may tune, one per bandit (GPU §4.12 line 774).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Knob {
    BatchSize,
    PrefetchBudget,
    RetentionMode,
}

/// The retention policies of `residency::retention` a retention-mode arm may select.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RetentionMode {
    Lru,
    CostPerByte,
    MarginalSavedLatency,
    GreedyDualSize,
}

/// One value of one knob.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KnobValue {
    BatchSize(u32),
    PrefetchBudgetBytes(u64),
    Retention(RetentionMode),
}

impl KnobValue {
    /// The knob this value sets.
    pub const fn knob(&self) -> Knob {
        match self {
            Self::BatchSize(_) => Knob::BatchSize,
            Self::PrefetchBudgetBytes(_) => Knob::PrefetchBudget,
            Self::Retention(_) => Knob::RetentionMode,
        }
    }
}

/// What a caller may ask the policy layer to try. Only [`RequestedChange::SetKnob`] is
/// ever admitted; the others exist so that a configuration asking for them is refused
/// by name rather than ignored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequestedChange {
    SetKnob(KnobValue),
    InstallKernel { kernel: String },
    AlterModelSemantics { change: String },
    ChangeHostSecurity { setting: String },
}

/// An authorization an arm needs, such as a grant to prefetch another tenant's object.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorizationName(String);

impl AuthorizationName {
    /// A name in the shared identifier grammar.
    pub fn new(value: impl Into<String>) -> Result<Self, PolicyError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// The name as given.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// One admitted arm and what choosing it needs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Arm {
    pub value: KnobValue,
    /// Memory the arm adds while chosen; it must fit the granted headroom.
    pub memory_demand_bytes: u64,
    pub requires: Option<AuthorizationName>,
}

/// Index of an admitted arm; the baseline is always arm 0.
pub type ArmIndex = usize;

/// The closed set of arms of one knob, baseline first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArmSet {
    knob: Knob,
    arms: Vec<Arm>,
}

/// The state a decision is made in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionInput {
    /// The workload class: the bandit's context.
    pub context: u32,
    /// Memory headroom the CORE-03 ledger grants this policy now.
    pub granted_headroom_bytes: u64,
    /// The host's free memory reserve now.
    pub observed_reserve_bytes: u64,
    pub authorizations: BTreeSet<AuthorizationName>,
}

impl ArmSet {
    /// A set holding only `baseline`, the reliable arm every fallback returns to.
    pub fn new(baseline: Arm) -> Self {
        Self {
            knob: baseline.value.knob(),
            arms: vec![baseline],
        }
    }

    /// Admits a requested change as an arm. Kernels, model semantics and host security
    /// settings are refused, as is a value of another knob or a duplicate.
    pub fn admit(
        &mut self,
        change: RequestedChange,
        memory_demand_bytes: u64,
        requires: Option<AuthorizationName>,
    ) -> Result<ArmIndex, PolicyError> {
        let value = match change {
            RequestedChange::SetKnob(value) => value,
            RequestedChange::InstallKernel { .. } => {
                return Err(PolicyError::ForbiddenChange {
                    change: "install or invent a kernel",
                })
            }
            RequestedChange::AlterModelSemantics { .. } => {
                return Err(PolicyError::ForbiddenChange {
                    change: "alter model semantics",
                })
            }
            RequestedChange::ChangeHostSecurity { .. } => {
                return Err(PolicyError::ForbiddenChange {
                    change: "change host security settings",
                })
            }
        };
        if value.knob() != self.knob {
            return Err(PolicyError::KnobMismatch {
                expected: self.knob,
                found: value.knob(),
            });
        }
        if self.arms.iter().any(|arm| arm.value == value) {
            return Err(PolicyError::DuplicateArm);
        }
        self.arms.push(Arm {
            value,
            memory_demand_bytes,
            requires,
        });
        Ok(self.arms.len() - 1)
    }

    /// The one knob these arms set.
    pub fn knob(&self) -> Knob {
        self.knob
    }

    /// The admitted arms, baseline first.
    pub fn arms(&self) -> &[Arm] {
        &self.arms
    }

    /// Arm `index`; refused when unknown.
    pub fn arm(&self, index: ArmIndex) -> Result<&Arm, PolicyError> {
        self.arms
            .get(index)
            .ok_or(PolicyError::UnknownArm { arm: index })
    }

    /// Whether `index` satisfies the hard constraints for `input`.
    pub fn feasible(&self, index: ArmIndex, input: &DecisionInput) -> bool {
        self.arms.get(index).is_some_and(|arm| {
            arm.memory_demand_bytes <= input.granted_headroom_bytes
                && arm
                    .requires
                    .as_ref()
                    .is_none_or(|needed| input.authorizations.contains(needed))
        })
    }
}

/// A hand-coded policy: a fixed arm or a rule by context.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HandCodedPolicy {
    Fixed(ArmIndex),
    ByContext {
        rule: BTreeMap<u32, ArmIndex>,
        otherwise: ArmIndex,
    },
}

impl HandCodedPolicy {
    /// The arm for `input`; refused when it violates the hard constraints.
    pub fn choose(&self, arms: &ArmSet, input: &DecisionInput) -> Result<ArmIndex, PolicyError> {
        let arm = match self {
            Self::Fixed(arm) => *arm,
            Self::ByContext { rule, otherwise } => {
                rule.get(&input.context).copied().unwrap_or(*otherwise)
            }
        };
        arms.arm(arm)?;
        if arms.feasible(arm, input) {
            Ok(arm)
        } else {
            Err(PolicyError::NoFeasibleArm)
        }
    }
}

/// The bandit's bounds and seed. The plan gives no values, so all are required.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct BanditConfig {
    /// Probability of an exploratory choice while exploring.
    pub exploration_probability: f64,
    /// Samples of an arm in a context before it is exploited or predicts.
    pub min_samples: u32,
    pub p99_bound_seconds: f64,
    /// Realized outcomes the p99 is taken over.
    pub p99_window: usize,
    pub reserve_bound_bytes: u64,
    /// Predictions whose mean relative error detects a shift.
    pub shift_window: usize,
    pub shift_relative_error: f64,
    pub seed: u64,
}

/// Why exploration stopped.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StopReason {
    P99AboveBound { p99_seconds: f64 },
    ReserveBelowBound { reserve_bytes: u64 },
}

/// The bandit's mode.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum BanditMode {
    Exploring,
    /// Exploration stopped; known-best arms and the baseline only.
    ExplorationStopped(StopReason),
    /// A distribution shift was detected; the baseline arm only, learning discarded.
    Reverted {
        mean_relative_error: f64,
    },
}

/// How a choice was made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChoiceKind {
    Baseline,
    Explore,
    Exploit,
}

/// One logged decision (GPU §4.12: "Log choice, predicted outcome and realized outcome").
#[derive(Clone, Debug, PartialEq)]
pub struct Decision {
    pub sequence: u64,
    pub context: u32,
    pub arm: ArmIndex,
    pub kind: ChoiceKind,
    pub mode: BanditMode,
    pub predicted_seconds: Option<f64>,
    pub realized_seconds: Option<f64>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct ArmStats {
    count: u32,
    mean_seconds: f64,
}

/// An ε-greedy contextual bandit over one knob, constrained and guarded (GPU §4.12).
/// While exploring it first samples every feasible arm `min_samples` times in each
/// context, then explores with the configured probability and otherwise exploits the
/// feasible arm with the lowest mean outcome.
#[derive(Clone, Debug)]
pub struct ConstrainedBandit {
    arms: ArmSet,
    config: BanditConfig,
    rng: SeededRng,
    stats: BTreeMap<(u32, ArmIndex), ArmStats>,
    mode: BanditMode,
    log: Vec<Decision>,
    realized: VecDeque<f64>,
    errors: VecDeque<f64>,
}

impl ConstrainedBandit {
    /// A bandit over `arms`, exploring; invalid bounds are refused.
    pub fn new(arms: ArmSet, config: BanditConfig) -> Result<Self, PolicyError> {
        probability("exploration_probability", config.exploration_probability)?;
        positive("p99_bound_seconds", config.p99_bound_seconds)?;
        non_negative("shift_relative_error", config.shift_relative_error)?;
        if config.p99_window == 0 {
            return Err(InputError::NotPositive {
                field: "p99_window",
            }
            .into());
        }
        if config.shift_window == 0 {
            return Err(InputError::NotPositive {
                field: "shift_window",
            }
            .into());
        }
        if config.min_samples == 0 {
            return Err(InputError::NotPositive {
                field: "min_samples",
            }
            .into());
        }
        Ok(Self {
            arms,
            rng: SeededRng::new(config.seed),
            config,
            stats: BTreeMap::new(),
            mode: BanditMode::Exploring,
            log: Vec::new(),
            realized: VecDeque::new(),
            errors: VecDeque::new(),
        })
    }

    /// The arms it may choose.
    pub fn arms(&self) -> &ArmSet {
        &self.arms
    }

    /// Exploring, stopped or reverted.
    pub fn mode(&self) -> BanditMode {
        self.mode
    }

    /// Every decision so far, in order (§4.12: the decision log).
    pub fn log(&self) -> &[Decision] {
        &self.log
    }

    /// An operator's reset: learning discarded, exploration allowed again.
    pub fn reset(&mut self) {
        self.stats.clear();
        self.realized.clear();
        self.errors.clear();
        self.mode = BanditMode::Exploring;
    }

    fn known(&self, context: u32, arm: ArmIndex) -> Option<ArmStats> {
        self.stats
            .get(&(context, arm))
            .copied()
            .filter(|stats| stats.count >= self.config.min_samples)
    }

    fn baseline(&self, input: &DecisionInput) -> Result<(ArmIndex, ChoiceKind), PolicyError> {
        if self.arms.feasible(0, input) {
            Ok((0, ChoiceKind::Baseline))
        } else {
            Err(PolicyError::NoFeasibleArm)
        }
    }

    fn exploit(&self, input: &DecisionInput) -> Result<(ArmIndex, ChoiceKind), PolicyError> {
        let best = (0..self.arms.arms().len())
            .filter(|arm| self.arms.feasible(*arm, input))
            .filter_map(|arm| self.known(input.context, arm).map(|stats| (arm, stats)))
            .min_by(|(a, a_stats), (b, b_stats)| {
                a_stats
                    .mean_seconds
                    .total_cmp(&b_stats.mean_seconds)
                    .then(a.cmp(b))
            });
        match best {
            Some((arm, _)) => Ok((arm, ChoiceKind::Exploit)),
            None => self.baseline(input),
        }
    }

    /// Chooses an arm for `input` and logs it with its prediction. A reserve below its
    /// bound stops exploration before this choice.
    pub fn choose(&mut self, input: &DecisionInput) -> Result<Decision, PolicyError> {
        if self.mode == BanditMode::Exploring
            && input.observed_reserve_bytes < self.config.reserve_bound_bytes
        {
            self.mode = BanditMode::ExplorationStopped(StopReason::ReserveBelowBound {
                reserve_bytes: input.observed_reserve_bytes,
            });
        }
        let (arm, kind) = match self.mode {
            BanditMode::Reverted { .. } => self.baseline(input)?,
            BanditMode::ExplorationStopped(_) => self.exploit(input)?,
            BanditMode::Exploring => {
                let draw = self.rng.below(1_000_000) as f64 / 1_000_000.0;
                let feasible: Vec<ArmIndex> = (0..self.arms.arms().len())
                    .filter(|arm| self.arms.feasible(*arm, input))
                    .collect();
                let count = |arm: &ArmIndex| {
                    self.stats
                        .get(&(input.context, *arm))
                        .map_or(0, |stats| stats.count)
                };
                let under_sampled = feasible
                    .iter()
                    .filter(|arm| count(arm) < self.config.min_samples)
                    .min_by_key(|arm| (count(arm), **arm))
                    .copied();
                if let Some(arm) = under_sampled {
                    (arm, ChoiceKind::Explore)
                } else if draw < self.config.exploration_probability && !feasible.is_empty() {
                    let bound = u64::try_from(feasible.len()).unwrap_or(u64::MAX);
                    let pick = usize::try_from(self.rng.below(bound)).unwrap_or(usize::MAX);
                    let arm = feasible
                        .get(pick)
                        .copied()
                        .ok_or(PolicyError::NoFeasibleArm)?;
                    (arm, ChoiceKind::Explore)
                } else {
                    self.exploit(input)?
                }
            }
        };
        let decision = Decision {
            sequence: self.log.len() as u64,
            context: input.context,
            arm,
            kind,
            mode: self.mode,
            predicted_seconds: self
                .known(input.context, arm)
                .map(|stats| stats.mean_seconds),
            realized_seconds: None,
        };
        self.log.push(decision.clone());
        Ok(decision)
    }

    fn window_p99(&self) -> Result<f64, PolicyError> {
        let mut nanos: Vec<u64> = self
            .realized
            .iter()
            .map(|seconds| (seconds * 1e9).round() as u64)
            .collect();
        nanos.sort_unstable();
        Ok(percentile(&nanos, Quantile::P99, PercentileMethod::NearestRank)? / 1e9)
    }

    /// Records the realized outcome of decision `sequence`, updates the learned means,
    /// and applies the guards: a window p99 above its bound stops exploration, and a mean
    /// relative prediction error above its bound over a full window reverts.
    pub fn observe(&mut self, sequence: u64, realized_seconds: f64) -> Result<(), PolicyError> {
        let realized = non_negative("realized_seconds", realized_seconds)?;
        let entry = usize::try_from(sequence)
            .ok()
            .and_then(|index| self.log.get_mut(index))
            .ok_or(PolicyError::UnknownDecision { sequence })?;
        if entry.realized_seconds.is_some() {
            return Err(PolicyError::AlreadyObserved { sequence });
        }
        entry.realized_seconds = Some(realized);
        let (context, arm, predicted) = (entry.context, entry.arm, entry.predicted_seconds);
        if matches!(self.mode, BanditMode::Reverted { .. }) {
            return Ok(());
        }
        let stats = self.stats.entry((context, arm)).or_default();
        stats.count = stats.count.saturating_add(1);
        stats.mean_seconds += (realized - stats.mean_seconds) / f64::from(stats.count);
        self.realized.push_back(realized);
        while self.realized.len() > self.config.p99_window {
            self.realized.pop_front();
        }
        if self.mode == BanditMode::Exploring {
            let p99_seconds = self.window_p99()?;
            if p99_seconds > self.config.p99_bound_seconds {
                self.mode =
                    BanditMode::ExplorationStopped(StopReason::P99AboveBound { p99_seconds });
            }
        }
        if let Some(predicted) = predicted.filter(|predicted| *predicted > 0.0) {
            self.errors
                .push_back((realized - predicted).abs() / predicted);
            while self.errors.len() > self.config.shift_window {
                self.errors.pop_front();
            }
            if self.errors.len() == self.config.shift_window {
                let mean_relative_error =
                    self.errors.iter().sum::<f64>() / self.errors.len() as f64;
                if mean_relative_error > self.config.shift_relative_error {
                    self.mode = BanditMode::Reverted {
                        mean_relative_error,
                    };
                    self.stats.clear();
                    self.realized.clear();
                    self.errors.clear();
                }
            }
        }
        Ok(())
    }
}

/// Realized outcomes for the shadow evaluator; a simulator or a recorded trace.
pub trait OutcomeModel {
    /// The outcome, in seconds, of choosing `arm` at step `step` of the trace.
    fn realize(&mut self, step: u64, context: u32, arm: ArmIndex) -> Result<f64, PolicyError>;

    /// Where the outcomes come from: the fake substrate for a simulator, the recorded
    /// run's authorization for a replay. It becomes the substrate of the run records the
    /// shadow evaluator writes, and so their provenance, as a record's substrate does
    /// everywhere in CORE-08.
    fn substrate(&self) -> RunSubstrate;
}

/// Which policy a run evaluated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyName {
    Fixed(ArmIndex),
    HandCoded(usize),
    Bandit,
}

impl PolicyName {
    /// The variant name its run records carry.
    pub fn label(&self) -> String {
        match self {
            Self::Fixed(arm) => format!("fixed-{arm}"),
            Self::HandCoded(index) => format!("hand-coded-{index}"),
            Self::Bandit => "bandit".to_string(),
        }
    }
}

/// The experiment name of the shadow evaluator's run records.
pub const SHADOW_EXPERIMENT: &str = "policy-shadow";

/// One policy's outcomes over a trace.
#[derive(Clone, Debug, PartialEq)]
pub struct PolicyRun {
    pub policy: PolicyName,
    pub realized_seconds: Vec<f64>,
    pub mean_seconds: f64,
    pub p99_seconds: f64,
    /// Where its outcomes came from, as its outcome model declared.
    pub substrate: RunSubstrate,
}

impl PolicyRun {
    fn new(
        policy: PolicyName,
        realized_seconds: Vec<f64>,
        substrate: RunSubstrate,
    ) -> Result<Self, PolicyError> {
        if realized_seconds.is_empty() {
            return Err(PolicyError::EmptyTrace);
        }
        let mean_seconds = realized_seconds.iter().sum::<f64>() / realized_seconds.len() as f64;
        let mut nanos: Vec<u64> = realized_seconds
            .iter()
            .map(|seconds| (seconds * 1e9).round() as u64)
            .collect();
        nanos.sort_unstable();
        let p99_seconds = percentile(&nanos, Quantile::P99, PercentileMethod::NearestRank)? / 1e9;
        Ok(Self {
            policy,
            realized_seconds,
            mean_seconds,
            p99_seconds,
            substrate,
        })
    }
}

fn run_hand_coded(
    arms: &ArmSet,
    policy: &HandCodedPolicy,
    name: PolicyName,
    trace: &[DecisionInput],
    model: &mut dyn OutcomeModel,
) -> Result<PolicyRun, PolicyError> {
    let mut realized = Vec::with_capacity(trace.len());
    for (step, input) in trace.iter().enumerate() {
        let arm = policy.choose(arms, input)?;
        let outcome = model.realize(step as u64, input.context, arm)?;
        realized.push(non_negative("realized_seconds", outcome)?);
    }
    PolicyRun::new(name, realized, model.substrate())
}

/// Runs a bandit over `trace`, observing each outcome before the next choice.
pub fn run_bandit(
    bandit: &mut ConstrainedBandit,
    trace: &[DecisionInput],
    model: &mut dyn OutcomeModel,
) -> Result<PolicyRun, PolicyError> {
    let mut realized = Vec::with_capacity(trace.len());
    for (step, input) in trace.iter().enumerate() {
        let decision = bandit.choose(input)?;
        let outcome = model.realize(step as u64, input.context, decision.arm)?;
        bandit.observe(decision.sequence, outcome)?;
        realized.push(outcome);
    }
    PolicyRun::new(PolicyName::Bandit, realized, model.substrate())
}

/// Every policy of a shadow evaluation on one workload trace, with the provenance of the
/// run records it was computed from. Only [`shadow_evaluate`] builds one and nothing
/// changes it afterwards, so its provenance always belongs to its own runs.
#[derive(Clone, Debug, PartialEq)]
pub struct ShadowReport {
    fixed: Vec<PolicyRun>,
    hand_coded: Vec<PolicyRun>,
    bandit: PolicyRun,
    bandit_log: Vec<Decision>,
    provenance: Provenance,
}

impl ShadowReport {
    /// Every fixed arm that satisfied the hard constraints throughout the trace.
    pub fn fixed(&self) -> &[PolicyRun] {
        &self.fixed
    }

    /// The hand-coded policies, in the order given.
    pub fn hand_coded(&self) -> &[PolicyRun] {
        &self.hand_coded
    }

    /// The bandit's run.
    pub fn bandit(&self) -> &PolicyRun {
        &self.bandit
    }

    /// The bandit's decisions with predicted and realized outcomes.
    pub fn bandit_log(&self) -> &[Decision] {
        &self.bandit_log
    }

    /// The provenance of the run records of every policy evaluated: fake if any outcome
    /// came from a fake substrate.
    pub fn provenance(&self) -> &Provenance {
        &self.provenance
    }

    /// The best fixed policy by mean outcome (GPU §4.12: "not just the worst default").
    pub fn best_fixed(&self) -> Option<&PolicyRun> {
        self.fixed
            .iter()
            .min_by(|a, b| a.mean_seconds.total_cmp(&b.mean_seconds))
    }

    /// The strongest baseline: the best of the fixed and hand-coded policies.
    pub fn strongest_baseline(&self) -> Option<&PolicyRun> {
        self.fixed
            .iter()
            .chain(&self.hand_coded)
            .min_by(|a, b| a.mean_seconds.total_cmp(&b.mean_seconds))
    }
}

/// Replays `trace` for every feasible fixed arm, every hand-coded policy and a fresh
/// bandit, each against its own outcome model from `models` so that all see the same
/// outcomes for the same choice. Nothing acts: the live policy is unaffected. A fixed
/// arm that violates the hard constraints somewhere in the trace is not a compatible
/// baseline and is skipped.
pub fn shadow_evaluate(
    arms: &ArmSet,
    hand_coded: &[HandCodedPolicy],
    config: BanditConfig,
    trace: &[DecisionInput],
    models: &mut dyn FnMut() -> Box<dyn OutcomeModel>,
) -> Result<ShadowReport, PolicyError> {
    if trace.is_empty() {
        return Err(PolicyError::EmptyTrace);
    }
    if hand_coded.is_empty() {
        return Err(PolicyError::NoHandCodedPolicies);
    }
    let mut fixed = Vec::new();
    for arm in 0..arms.arms().len() {
        if trace.iter().all(|input| arms.feasible(arm, input)) {
            let mut model = models();
            fixed.push(run_hand_coded(
                arms,
                &HandCodedPolicy::Fixed(arm),
                PolicyName::Fixed(arm),
                trace,
                model.as_mut(),
            )?);
        }
    }
    let mut hand = Vec::new();
    for (index, policy) in hand_coded.iter().enumerate() {
        let mut model = models();
        hand.push(run_hand_coded(
            arms,
            policy,
            PolicyName::HandCoded(index),
            trace,
            model.as_mut(),
        )?);
    }
    let mut bandit = ConstrainedBandit::new(arms.clone(), config)?;
    let mut model = models();
    let run = run_bandit(&mut bandit, trace, model.as_mut())?;
    let experiment = Label::new(SHADOW_EXPERIMENT)?;
    let mut records = Vec::new();
    for policy in fixed.iter().chain(&hand).chain(std::iter::once(&run)) {
        let arm = TrialArm {
            name: Label::new(policy.policy.label())?,
            bursts: vec![policy
                .realized_seconds
                .iter()
                .map(|seconds| Trial {
                    weights_usable_seconds: 0.0,
                    first_token_seconds: *seconds,
                    transferred_bytes: 0,
                    storage_read_bytes: 0,
                })
                .collect()],
        };
        records.extend(trial_records(
            BenchId::Bench01,
            &experiment,
            policy.substrate.clone(),
            &arm,
        )?);
    }
    let provenance = Provenance::of_records(&records)?;
    Ok(ShadowReport {
        fixed,
        hand_coded: hand,
        bandit: run,
        bandit_log: bandit.log().to_vec(),
        provenance,
    })
}

/// Permission for a bandit to act live, after hand-coded policies and shadow
/// evaluation (GPU §4.12 line 774: "Begin with hand-coded policies and a shadow
/// evaluator").
#[derive(Clone, Debug, PartialEq)]
pub struct LiveApproval {
    evidence: crate::foundation::ids::Digest,
}

impl LiveApproval {
    /// Requires the shadow report's own provenance to be a Yougori measurement (a fake
    /// substrate is refused) and a bandit strictly better than the strongest baseline.
    /// No provenance is accepted from outside the report.
    pub fn from_shadow(report: &ShadowReport) -> Result<Self, PolicyError> {
        let evidence = report.provenance.yougori_evidence()?;
        if report.hand_coded.is_empty() {
            return Err(PolicyError::NoHandCodedPolicies);
        }
        let baseline = report
            .strongest_baseline()
            .ok_or(PolicyError::NoHandCodedPolicies)?;
        if report.bandit.mean_seconds >= baseline.mean_seconds {
            return Err(PolicyError::BanditNotBetter {
                bandit_seconds: report.bandit.mean_seconds,
                baseline_seconds: baseline.mean_seconds,
            });
        }
        Ok(Self { evidence })
    }

    /// The measured evidence the approval rests on.
    pub fn evidence(&self) -> crate::foundation::ids::Digest {
        self.evidence
    }
}
