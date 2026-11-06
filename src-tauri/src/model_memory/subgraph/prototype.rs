//! The first GPU-N3 prototype on the fake substrate (GPU §4.16 lines 898–900).
//!
//! Three pairs ([`PrototypePair`]) are each served under three strategies over the same
//! seeded mixed trace: independent execution (the ordinary workflow), ordinary
//! per-model prefix caching (the strongest compatible baseline) and verified
//! shared-subgraph execution, which is per-model caching plus this module's contract.
//! A trace item is one input sent to one or both variants; both variants of an item run
//! in one batch, so both see the batch's first-token time. Every attempt becomes a
//! CORE-08 run record on the fake, time-controlled substrate, so the comparison report
//! carries fake-substrate provenance: it validates the schema and the comparison and
//! backs no performance claim (S12 G0).
//!
//! Exactness is checked against a reference computation: every operator's fake output
//! is a digest of what it computes (ABI, parameters, semantics, format, adapter effects,
//! runtime, profile, input and parent output), and a reused prefix must lead to the same
//! final output as computing everything. Every reuse is audited for authorization.

use std::collections::BTreeSet;
use std::fmt;

use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, Digest, ExecutionCategory, ExecutionId, IdError,
    ManualClock, MonotonicTime, OperationId, TenantId, TrustScope,
};
use crate::foundation::report::{
    self, ArrivalMode, AttemptIdentity, AttemptLedger, AttemptRole, Baseline, BenchId,
    BuildIdentity, CacheTier, ClientDescription, ClientPlacement, ClockId, ColdProvenance,
    ComparisonReport, ComparisonSide, CpuDescription, Disclosure, EffectClass, EngineIdentity,
    EventKind, EventRecorder, ExperimentDesign, FixtureFamily, FixtureRef, GpuDescription,
    HostDescription, IntervalKind, LatencyObjective, LatencySummary, LaunchDescription,
    LoadDescription, MatchedConfiguration, Measured, ModeFidelity, ModelAtArrival, ModelIdentity,
    ModelRevision, NonNegative, NonceDisclosure, NotMeasuredReason, Objective, ObjectivePlan,
    ObjectiveVector, Outcome, PercentileMethod, Precision, PrefillMode, Provenance, Quantile,
    ReportError, RunMeasurements, RunRecord, RunSubstrate, Sampling, Scenario, SchemaVersion,
    StartState, StartTemperature, StateComparison, TracePattern, Workload,
};
use crate::model_memory::identity::{
    AuthorityBinding, Dtype, FidelityConfiguration, IdentityError, KvRepresentation, Quantization,
    SessionSpec, TokenPrefix, TokenState, VersionedName,
};
use crate::model_memory::math::InputError;

use super::canon::Canon;
use super::contract::{produce_state, reuse_state, SubgraphRequest, SubgraphState};
use super::decision::{
    claim_record, claim_result, decide_pass_stop, ClaimRecord, DecisionError, Incidence,
    LiteratureComparison, MinimumIncidence, PassStopDecision, PassStopEvidence, WorkloadSource,
};
use super::discovery::{discover_shared_prefix, SharedPrefix};
use super::eligibility::{ExactnessCriterion, ReuseMode, ReuseRefusal};
use super::key::{ExactInput, RuntimeChoices};
use super::profit::{plan_boundary, BoundaryEconomics, ProfitError};
use super::rng::SeededRng;
use super::synthetic::{prototype_family, PrototypeFamily, PrototypePair, SyntheticError};
use super::variant::{ImmutableVariant, SubgraphError};

/// Domain of the reference computation's fake activations.
pub const FAKE_ACTIVATION_DOMAIN: &str = "yougori/model-memory/subgraph/fake-activation/v1";
/// Domain of the digests that describe the fake setup in run records.
pub const FAKE_SETUP_DOMAIN: &str = "yougori/model-memory/subgraph/fake-setup/v1";
/// The one optimization the candidate adds to its strongest baseline.
pub const COMPONENT_LABEL: &str = "verified-shared-subgraph";

/// The three strategies of line 898.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Strategy {
    /// Every request computes every operator: the ordinary workflow.
    IndependentExecution,
    /// A request repeating an earlier input of the same variant, tenant and authority
    /// reuses that variant's whole prefill: the strongest compatible baseline.
    PerModelPrefixCaching,
    /// Per-model prefix caching plus verified shared-subgraph reuse across variants.
    VerifiedSharedSubgraph,
}

impl Strategy {
    pub const ALL: [Self; 3] = [
        Self::IndependentExecution,
        Self::PerModelPrefixCaching,
        Self::VerifiedSharedSubgraph,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::IndependentExecution => "independent-execution",
            Self::PerModelPrefixCaching => "per-model-prefix-caching",
            Self::VerifiedSharedSubgraph => COMPONENT_LABEL,
        }
    }
}

/// The seeded mixed trace and the fake timing of one prototype run.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct WorkloadConfig {
    pub seed: u64,
    /// Independent trials, each with its own trace; CORE-08 requires at least five.
    pub trials: u32,
    pub requests_per_trial: u32,
    /// Probability that an item sends its input to both variants.
    pub fan_out_probability: f64,
    /// Probability that an item repeats an earlier input of its trial.
    pub repeat_probability: f64,
    /// Probability that an item comes from the second tenant, which holds no grant.
    pub second_tenant_probability: f64,
    pub min_tokens: u64,
    pub max_tokens: u64,
    /// Items arrive at this interval; the server must be idle at each arrival.
    pub arrival_interval_seconds: f64,
    /// Each batch time is scaled by a factor drawn uniformly from 1 ± this fraction.
    pub jitter_fraction: f64,
    /// Consumers expected for a state produced by a single-variant request.
    pub expected_cross_request_consumers: f64,
}

impl WorkloadConfig {
    /// The configuration the tests use: five trials of 24 items.
    pub fn reference(seed: u64) -> Self {
        Self {
            seed,
            trials: 5,
            requests_per_trial: 24,
            fan_out_probability: 0.5,
            repeat_probability: 0.25,
            second_tenant_probability: 0.25,
            min_tokens: 64,
            max_tokens: 2048,
            arrival_interval_seconds: 1.0,
            jitter_fraction: 0.02,
            expected_cross_request_consumers: 0.25,
        }
    }

    fn check(&self) -> Result<(), PrototypeError> {
        let probability = |value: f64| value.is_finite() && (0.0..=1.0).contains(&value);
        let refuse = |field| Err(PrototypeError::InvalidWorkload { field });
        if self.trials == 0 {
            return refuse("trials");
        }
        if self.requests_per_trial == 0 {
            return refuse("requests_per_trial");
        }
        if !probability(self.fan_out_probability) {
            return refuse("fan_out_probability");
        }
        if !probability(self.repeat_probability) {
            return refuse("repeat_probability");
        }
        if !probability(self.second_tenant_probability) {
            return refuse("second_tenant_probability");
        }
        if self.min_tokens == 0 || self.max_tokens < self.min_tokens {
            return refuse("min_tokens");
        }
        if !(self.arrival_interval_seconds.is_finite() && self.arrival_interval_seconds > 0.0) {
            return refuse("arrival_interval_seconds");
        }
        if !(self.jitter_fraction.is_finite() && (0.0..1.0).contains(&self.jitter_fraction)) {
            return refuse("jitter_fraction");
        }
        if !(self.expected_cross_request_consumers.is_finite()
            && self.expected_cross_request_consumers >= 0.0)
        {
            return refuse("expected_cross_request_consumers");
        }
        Ok(())
    }
}

/// Why the prototype could not run.
#[derive(Clone, Debug, PartialEq)]
pub enum PrototypeError {
    InvalidWorkload {
        field: &'static str,
    },
    /// A batch was still running when the next item arrived; queueing is not modelled.
    ServerBusy {
        trial: u32,
        item: u32,
    },
    Report(ReportError),
    Id(IdError),
    Identity(IdentityError),
    Subgraph(SubgraphError),
    Synthetic(SyntheticError),
    Profit(ProfitError),
    Input(InputError),
    /// The contract refused a step the prototype requires, such as producing the state of
    /// a planned boundary.
    Refusal(ReuseRefusal),
    Decision(DecisionError),
}

impl fmt::Display for PrototypeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidWorkload { field } => write!(f, "workload field {field} is out of range"),
            Self::ServerBusy { trial, item } => write!(
                f,
                "item {item} of trial {trial} arrived while the previous batch was running"
            ),
            Self::Report(error) => write!(f, "{error}"),
            Self::Id(error) => error.fmt(f),
            Self::Identity(error) => write!(f, "{error:?}"),
            Self::Subgraph(error) => error.fmt(f),
            Self::Synthetic(error) => error.fmt(f),
            Self::Profit(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
            Self::Refusal(refusal) => refusal.fmt(f),
            Self::Decision(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for PrototypeError {}

crate::model_memory::from_error!(
    PrototypeError:
    ReportError => Report,
    IdError => Id,
    IdentityError => Identity,
    SubgraphError => Subgraph,
    SyntheticError => Synthetic,
    ProfitError => Profit,
    InputError => Input,
    ReuseRefusal => Refusal,
    DecisionError => Decision,
);

/// The fake output of operator `index` of `variant` for `input` after `parent`.
fn fake_output(
    variant: &ImmutableVariant,
    index: usize,
    input: &ExactInput,
    parent: Option<&Digest>,
) -> Option<Digest> {
    let operator = variant.operators().get(index)?;
    let canon = operator
        .abi()
        .write(Canon::new(FAKE_ACTIVATION_DOMAIN))
        .count(operator.parameters().len());
    let canon = operator
        .parameters()
        .iter()
        .fold(canon, |canon, parameter| canon.digest(parameter.digest()));
    let canon = variant
        .attention()
        .write(canon)
        .positional(variant.position());
    let canon = operator
        .output()
        .write(canon)
        .count(operator.adapter_effects().len());
    let canon = operator
        .adapter_effects()
        .iter()
        .fold(canon, |canon, effect| effect.write(canon));
    let canon = variant.profile().write(canon.tag(operator.runtime().tag()));
    Some(input.write(canon).optional_digest(parent).finish())
}

/// Runs operators `from..to` of `variant` from `start` (the output before `from`).
fn fake_chain(
    variant: &ImmutableVariant,
    input: &ExactInput,
    from: usize,
    to: usize,
    start: Option<Digest>,
) -> Option<Digest> {
    (from..to).try_fold(start, |parent, index| {
        fake_output(variant, index, input, parent.as_ref()).map(Some)
    })?
}

/// One item of a trace.
#[derive(Clone, Debug, PartialEq, Eq)]
struct TraceItem {
    input: u64,
    tokens: Vec<u32>,
    /// 0 for variant A, 1 for variant B.
    variants: Vec<usize>,
    tenant: usize,
}

fn trace(config: &WorkloadConfig, trial: u32) -> Vec<TraceItem> {
    let mut rng = SeededRng::derived(config.seed, &[u64::from(trial), 0x7472_6163]);
    let mut inputs: Vec<Vec<u32>> = Vec::new();
    (0..config.requests_per_trial)
        .map(|_| {
            let repeat = !inputs.is_empty() && rng.chance(config.repeat_probability);
            let input = if repeat {
                rng.below(inputs.len() as u64)
            } else {
                let count = rng.between(config.min_tokens, config.max_tokens);
                inputs.push((0..count).map(|_| rng.below(32_000) as u32).collect());
                inputs.len() as u64 - 1
            };
            let variants = if rng.chance(config.fan_out_probability) {
                vec![0, 1]
            } else {
                vec![rng.below(2) as usize]
            };
            let tenant = usize::from(rng.chance(config.second_tenant_probability));
            TraceItem {
                input,
                tokens: inputs.get(input as usize).cloned().unwrap_or_default(),
                variants,
                tenant,
            }
        })
        .collect()
}

/// How an attempt obtained its prefill.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reuse {
    Computed,
    PerModel,
    SharedPrefix,
}

#[derive(Clone, Copy, Debug)]
struct Served {
    variant: usize,
    reuse: Reuse,
}

struct Tenancy {
    tenant: TenantId,
    authority: AuthorityBinding,
}

struct StoredState {
    state: SubgraphState,
    output: Digest,
}

#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Tally {
    compute_seconds: f64,
    exactness_violations: u64,
    unauthorized_reuses: u64,
    cross_tenant_refusals: u64,
    eligible_attempts: u64,
    attempts: u64,
}

struct Simulation<'a> {
    family: &'a PrototypeFamily,
    prefix: &'a SharedPrefix,
    config: &'a WorkloadConfig,
    strategy: Strategy,
    tenants: &'a [Tenancy; 2],
    clock: &'a ManualClock,
    per_model: BTreeSet<(usize, usize, u64)>,
    store: Vec<StoredState>,
    cache_bytes: u64,
    peak_cache_bytes: u64,
    tally: Tally,
}

fn pick(family: &PrototypeFamily, index: usize) -> &ImmutableVariant {
    if index == 0 {
        &family.a
    } else {
        &family.b
    }
}

/// Whether the producing authority covers a reuse; no grants are issued here.
fn authorized(state: &SubgraphState, request: &SubgraphRequest) -> bool {
    state.owner() == &request.tenant && state.authority() == &request.authority
}

impl Simulation<'_> {
    fn variant(&self, index: usize) -> &ImmutableVariant {
        pick(self.family, index)
    }

    fn segment_seconds(&self, from: usize, to: usize, tokens: u64) -> f64 {
        self.family
            .costs
            .iter()
            .take(to)
            .skip(from)
            .map(|cost| cost.compute_seconds_per_token * tokens as f64)
            .sum()
    }

    fn operator_count(&self, index: usize) -> usize {
        self.variant(index).operators().len()
    }

    fn add_cache_bytes(&mut self, bytes: u64) {
        self.cache_bytes = self.cache_bytes.saturating_add(bytes);
        self.peak_cache_bytes = self.peak_cache_bytes.max(self.cache_bytes);
    }

    fn kv_bytes(&self, tokens: u64) -> u64 {
        self.family
            .costs
            .iter()
            .map(|cost| cost.kv_bytes_per_token.saturating_mul(tokens))
            .fold(0u64, u64::saturating_add)
    }

    fn request(
        &self,
        variant: usize,
        tenant: usize,
        tokens: &[u32],
    ) -> Result<SubgraphRequest, PrototypeError> {
        let target = self.variant(variant);
        let tenancy = &self.tenants[tenant.min(1)];
        Ok(SubgraphRequest {
            input: ExactInput::whole(tokens)?,
            runtime: RuntimeChoices::pinned(target.profile().kernels.clone()),
            exactness: ExactnessCriterion::BitIdentical,
            fidelity: FidelityConfiguration::exact_reuse(),
            tenant: tenancy.tenant.clone(),
            authority: tenancy.authority.clone(),
            trust_scope: *target.trust_scope(),
            session: SessionSpec {
                execution: target.execution(),
                state: TokenState::Prefix(TokenPrefix::from_token_ids(tokens)),
                adapter: target.adapter(),
                positional_encoding: target.position().clone(),
                kv: KvRepresentation::new(
                    Dtype::Float32,
                    Quantization::None,
                    16,
                    VersionedName::new("paged", "1")?,
                )?,
                tenant: tenancy.tenant.clone(),
                authority: tenancy.authority.clone(),
            },
        })
    }

    /// Counts a reuse that neither the producing authority nor a grant covered.
    fn audit(&mut self, authorized: bool) {
        if !authorized {
            self.tally.unauthorized_reuses += 1;
        }
    }

    /// Compares the final output reached from a reused prefix with the full reference.
    fn check_exact(&mut self, variant: usize, input: &ExactInput, boundary: usize, start: Digest) {
        let target = self.variant(variant);
        let operators = target.operators().len();
        let expected = fake_chain(target, input, 0, operators, None);
        let reached = fake_chain(target, input, boundary, operators, Some(start));
        if expected.is_none() || expected != reached {
            self.tally.exactness_violations += 1;
        }
    }

    fn store_state(&mut self, state: SubgraphState, output: Digest, tokens: u64, boundary: usize) {
        let bytes = self
            .family
            .costs
            .get(boundary.saturating_sub(1))
            .map_or(0, |cost| {
                cost.activation_bytes_per_token.saturating_mul(tokens)
            });
        self.add_cache_bytes(bytes);
        self.store.push(StoredState { state, output });
    }

    /// Both variants miss their per-model cache: compute the shared prefix once.
    fn fan_out(
        &mut self,
        item: &TraceItem,
        boundary: usize,
        attempts: &mut Vec<Served>,
    ) -> Result<f64, PrototypeError> {
        let tokens = item.tokens.len() as u64;
        let full = self.segment_seconds(0, self.operator_count(0), tokens)
            + self.segment_seconds(0, self.operator_count(1), tokens);
        let economics = BoundaryEconomics::from_costs(
            &self.family.costs,
            boundary,
            tokens,
            1.0,
            self.family.handoff,
        )?;
        let Ok(planned) = plan_boundary(self.prefix, boundary, &economics) else {
            attempts.extend([0, 1].map(|variant| Served {
                variant,
                reuse: Reuse::Computed,
            }));
            return Ok(full);
        };
        let producer_request = self.request(0, item.tenant, &item.tokens)?;
        let consumer_request = self.request(1, item.tenant, &item.tokens)?;
        let input = producer_request.input.clone();
        let output = fake_chain(self.variant(0), &input, 0, boundary, None)
            .ok_or(ReuseRefusal::NotAPlannedBoundary)?;
        let state = produce_state(
            self.variant(0),
            &producer_request,
            &planned,
            ContentKey::from_digest(output),
        )?;
        match reuse_state(&state, self.variant(1), &consumer_request, None, self.clock) {
            Ok(reuse) => {
                reuse.verify_received(&ContentKey::from_digest(output))?;
                self.audit(authorized(&state, &consumer_request));
                self.check_exact(1, &input, reuse.operators(), output);
                self.tally.eligible_attempts += 1;
                attempts.push(Served {
                    variant: 0,
                    reuse: Reuse::Computed,
                });
                attempts.push(Served {
                    variant: 1,
                    reuse: Reuse::SharedPrefix,
                });
                let seconds = self.segment_seconds(0, boundary, tokens)
                    + self.segment_seconds(boundary, self.operator_count(0), tokens)
                    + self.segment_seconds(boundary, self.operator_count(1), tokens)
                    + self.family.handoff.keying_seconds
                    + self.family.handoff.lookup_seconds;
                self.store_state(state, output, tokens, boundary);
                Ok(seconds)
            }
            Err(refusal) => {
                if matches!(refusal, ReuseRefusal::Unauthorized(_)) {
                    self.tally.cross_tenant_refusals += 1;
                }
                attempts.extend([0, 1].map(|variant| Served {
                    variant,
                    reuse: Reuse::Computed,
                }));
                Ok(full)
            }
        }
    }

    /// One variant misses its per-model cache: look for an authorized stored state.
    fn single(
        &mut self,
        item: &TraceItem,
        boundary: usize,
        variant: usize,
        attempts: &mut Vec<Served>,
    ) -> Result<f64, PrototypeError> {
        let tokens = item.tokens.len() as u64;
        let request = self.request(variant, item.tenant, &item.tokens)?;
        let mode = ReuseMode::new(&request.exactness, &request.fidelity)?;
        let family = self.family;
        let target = pick(family, variant);
        let keys = target.state_keys(&request.input, &request.runtime, &mode, boundary)?;
        let wanted = keys.last().copied();
        let identity = target.identity();
        let mut seconds = family.handoff.lookup_seconds;
        let mut found = None;
        for stored in &self.store {
            if stored.state.boundary_key() != wanted {
                continue;
            }
            match reuse_state(&stored.state, target, &request, None, self.clock) {
                Ok(reuse) => {
                    reuse.verify_received(&ContentKey::from_digest(stored.output))?;
                    found = Some((
                        stored.output,
                        stored.state.producer(),
                        authorized(&stored.state, &request),
                    ));
                    break;
                }
                Err(ReuseRefusal::Unauthorized(_)) => self.tally.cross_tenant_refusals += 1,
                Err(_) => {}
            }
        }
        if let Some((output, producer, covered)) = found {
            self.audit(covered);
            self.check_exact(variant, &request.input, boundary, output);
            if producer != identity {
                self.tally.eligible_attempts += 1;
            }
            attempts.push(Served {
                variant,
                reuse: Reuse::SharedPrefix,
            });
            return Ok(
                seconds + self.segment_seconds(boundary, self.operator_count(variant), tokens)
            );
        }
        seconds += self.segment_seconds(0, self.operator_count(variant), tokens);
        attempts.push(Served {
            variant,
            reuse: Reuse::Computed,
        });
        let economics = BoundaryEconomics::from_costs(
            &self.family.costs,
            boundary,
            tokens,
            self.config.expected_cross_request_consumers,
            self.family.handoff,
        )?;
        if let Ok(planned) = plan_boundary(self.prefix, boundary, &economics) {
            let output = fake_chain(self.variant(variant), &request.input, 0, boundary, None)
                .ok_or(ReuseRefusal::NotAPlannedBoundary)?;
            let state = produce_state(
                self.variant(variant),
                &request,
                &planned,
                ContentKey::from_digest(output),
            )?;
            seconds += self.family.handoff.keying_seconds;
            self.store_state(state, output, tokens, boundary);
        }
        Ok(seconds)
    }

    /// Serves one item; returns the batch's compute seconds and its attempts.
    fn serve(&mut self, item: &TraceItem) -> Result<(f64, Vec<Served>), PrototypeError> {
        let tokens = item.tokens.len() as u64;
        let mut seconds = 0.0;
        let mut attempts = Vec::new();
        let mut needs = Vec::new();
        for &variant in &item.variants {
            if self.strategy == Strategy::IndependentExecution {
                needs.push(variant);
                continue;
            }
            seconds += self.family.handoff.lookup_seconds;
            if self.per_model.contains(&(item.tenant, variant, item.input)) {
                attempts.push(Served {
                    variant,
                    reuse: Reuse::PerModel,
                });
            } else {
                needs.push(variant);
            }
        }
        let boundary = match self.strategy {
            Strategy::VerifiedSharedSubgraph => self.prefix.branch_boundary(),
            _ => None,
        };
        match (boundary, needs.as_slice()) {
            (Some(boundary), [_, _]) => seconds += self.fan_out(item, boundary, &mut attempts)?,
            (Some(boundary), [only]) => {
                seconds += self.single(item, boundary, *only, &mut attempts)?
            }
            _ => {
                for &variant in &needs {
                    seconds += self.segment_seconds(0, self.operator_count(variant), tokens);
                    attempts.push(Served {
                        variant,
                        reuse: Reuse::Computed,
                    });
                }
            }
        }
        if self.strategy != Strategy::IndependentExecution {
            for &variant in &needs {
                if self.per_model.insert((item.tenant, variant, item.input)) {
                    let bytes = self.kv_bytes(tokens);
                    self.add_cache_bytes(bytes);
                }
            }
        }
        attempts.sort_by_key(|served| served.variant);
        Ok((seconds, attempts))
    }
}

fn label(text: &str) -> Result<report::Label, ReportError> {
    report::Label::new(text)
}

fn setup_digest(part: &str) -> Digest {
    digest(FAKE_SETUP_DOMAIN, &[part.as_bytes()])
}

/// The parts of every run record that do not change between attempts.
struct RecordContext {
    model: ModelIdentity,
    precision: Precision,
    fixture: FixtureRef,
    host: HostDescription,
    client: ClientDescription,
    build: BuildIdentity,
    launch: LaunchDescription,
    load: LoadDescription,
    clock: ClockId,
}

impl RecordContext {
    fn new(family: &PrototypeFamily, config: &WorkloadConfig) -> Result<Self, PrototypeError> {
        let family_weights = Canon::new(FAKE_SETUP_DOMAIN)
            .tag("family")
            .digest(family.a.artifact().digest())
            .digest(family.b.artifact().digest())
            .finish();
        let trace_description = Canon::new(FAKE_SETUP_DOMAIN)
            .tag("trace")
            .u64(config.seed)
            .u64(config.requests_per_trial.into())
            .u64(config.fan_out_probability.to_bits())
            .u64(config.repeat_probability.to_bits())
            .u64(config.second_tenant_probability.to_bits())
            .u64(config.min_tokens)
            .u64(config.max_tokens)
            .finish();
        let interval_nanos = (config.arrival_interval_seconds * 1e9).round() as u64;
        Ok(Self {
            model: ModelIdentity {
                revision: ModelRevision::Tag {
                    name: label("synthetic-family")?,
                },
                licenses: vec![label("LicenseRef-synthetic")?],
                weights: family_weights,
                tokenizer: setup_digest("synthetic tokenizer"),
                chat_template: setup_digest("no chat template"),
            },
            precision: Precision {
                weight_dtype: label("f32")?,
                quantization: label("none")?,
                kv_cache_dtype: label("f32")?,
            },
            fixture: FixtureRef::new(
                label("p11-synthetic-trace")?,
                trace_description,
                Disclosure::PermittedSynthetic,
            ),
            host: HostDescription {
                os: label("fake-substrate")?,
                os_version: label("1")?,
                cpu: CpuDescription {
                    model: label("fake-cpu")?,
                    logical_cores: 8,
                },
                host_memory_bytes: 64 << 30,
                gpus: Measured::measured(vec![GpuDescription {
                    model: label("fake-gpu")?,
                    memory_bytes: 24 << 30,
                }]),
                gpu_driver: Measured::not_measured(NotMeasuredReason::NotApplicable),
                gpu_power_clock: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
                power_source: Measured::not_measured(NotMeasuredReason::NotApplicable),
                displays_on_gpu: Measured::not_measured(NotMeasuredReason::NotApplicable),
            },
            client: ClientDescription {
                name: label("p11-fake-load-generator")?,
                version: label("1")?,
                region: label("same-host")?,
                placement: ClientPlacement::SameHost,
            },
            build: BuildIdentity {
                plan: setup_digest("GPU-N3 section 4.16 first prototype"),
                runner_build: setup_digest("yougori-fake-subgraph"),
                runner_version: label("1")?,
            },
            launch: LaunchDescription {
                image: setup_digest("no image"),
                backend: label("yougori-fake-subgraph")?,
            },
            load: LoadDescription {
                concurrent_requests: 2,
                arrival: ArrivalMode::Staggered { interval_nanos },
            },
            clock: ClockId::new(label("fake-monotonic")?),
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn record(
        &self,
        strategy: Strategy,
        operation: OperationId,
        execution: &ExecutionId,
        trial: u32,
        served: Served,
        input_tokens: u64,
        seed: u64,
        cache_bytes: u64,
        events: Vec<report::RecordedEvent>,
    ) -> Result<RunRecord, PrototypeError> {
        let reused = served.reuse != Reuse::Computed;
        let record = RunRecord {
            schema_version: SchemaVersion,
            attempt: AttemptIdentity {
                bench: BenchId::Bench01,
                variant: label(strategy.label())?,
                execution: execution.clone(),
                operation,
                role: AttemptRole::Initial,
                burst: trial,
                deadline_nanos: Measured::not_measured(NotMeasuredReason::NotApplicable),
            },
            scenario: Scenario::Serving,
            substrate: RunSubstrate::FakeTimeControlled,
            build: self.build.clone(),
            execution_category: ExecutionCategory::SharedKernelGpuRuntime,
            model: Measured::measured(self.model.clone()),
            precision: Measured::measured(self.precision.clone()),
            engine: Measured::measured(EngineIdentity {
                name: label("yougori-fake-subgraph")?,
                version: label("1")?,
            }),
            host: self.host.clone(),
            workload: Measured::measured(Workload {
                fixture: self.fixture.clone(),
                family: FixtureFamily::Prose,
                input_tokens,
                max_output_tokens: 1,
                sampling: Sampling {
                    temperature: NonNegative::ZERO,
                    top_p: Measured::not_measured(NotMeasuredReason::NotApplicable),
                    top_k: Measured::not_measured(NotMeasuredReason::NotApplicable),
                    seed: Measured::measured(seed),
                },
                tool_schema: Measured::not_measured(NotMeasuredReason::NotApplicable),
                paired: false,
                cold_test_nonce: NonceDisclosure::NotUsed,
            }),
            client: self.client.clone(),
            load: self.load.clone(),
            state: Measured::measured(StartState {
                temperature: StartTemperature::Hot,
                model_at_arrival: ModelAtArrival::ReadyToServe,
                cache_tier: if reused {
                    CacheTier::GpuMemory
                } else {
                    CacheTier::NoReusableState
                },
                prefill: if reused {
                    PrefillMode::WarmPrefix
                } else {
                    PrefillMode::Fresh
                },
                cold_provenance: ColdProvenance::NotCold,
            }),
            launch: self.launch.clone(),
            price: Measured::not_measured(NotMeasuredReason::NotApplicable),
            measurements: RunMeasurements {
                output_tokens: Measured::measured(1),
                prefill_tokens_per_second: Measured::not_measured(NotMeasuredReason::NotRecorded),
                aggregate_decode_tokens_per_second: Measured::not_measured(
                    NotMeasuredReason::NotApplicable,
                ),
                speculative: Measured::not_measured(NotMeasuredReason::NotApplicable),
                peak_gpu_memory_bytes: Measured::measured(cache_bytes),
                retained_gpu_memory_bytes: Measured::measured(cache_bytes),
                peak_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
                retained_host_memory_bytes: Measured::not_measured(NotMeasuredReason::NotRecorded),
                peak_pinned_host_memory_bytes: Measured::not_measured(
                    NotMeasuredReason::NotRecorded,
                ),
                transferred_bytes: Measured::measured(0),
                storage_read_bytes: Measured::not_measured(NotMeasuredReason::NotApplicable),
                energy_joules: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
                offload: Measured::not_measured(NotMeasuredReason::NotApplicable),
                first_run: Measured::not_measured(NotMeasuredReason::NotApplicable),
                owner_return: Measured::not_measured(NotMeasuredReason::NotApplicable),
                reasoning: Measured::not_measured(NotMeasuredReason::NotApplicable),
            },
            events,
            outcome: Outcome::Succeeded,
        };
        record.validate()?;
        Ok(record)
    }
}

/// One strategy's run over every trial.
#[derive(Clone, Debug, PartialEq)]
pub struct StrategyRun {
    pub strategy: Strategy,
    /// One record per attempt, all on the fake substrate.
    pub records: Vec<RunRecord>,
    /// Batch compute seconds summed over every item, keying and lookups included.
    pub compute_seconds: f64,
    /// Fake cache bytes: the most held at any point, and the most held at a trial's end.
    pub peak_cache_bytes: u64,
    pub retained_cache_bytes: u64,
    pub exactness_violations: u64,
    pub unauthorized_reuses: u64,
    pub cross_tenant_refusals: u64,
    /// Attempts that reused prefix state produced by the other variant.
    pub eligible_attempts: u64,
    pub attempts: u64,
}

fn run_strategy(
    family: &PrototypeFamily,
    prefix: &SharedPrefix,
    config: &WorkloadConfig,
    strategy: Strategy,
    context: &RecordContext,
    tenants: &[Tenancy; 2],
) -> Result<StrategyRun, PrototypeError> {
    let interval_nanos = (config.arrival_interval_seconds * 1e9).round() as u64;
    let mut run = StrategyRun {
        strategy,
        records: Vec::new(),
        compute_seconds: 0.0,
        peak_cache_bytes: 0,
        retained_cache_bytes: 0,
        exactness_violations: 0,
        unauthorized_reuses: 0,
        cross_tenant_refusals: 0,
        eligible_attempts: 0,
        attempts: 0,
    };
    for trial in 0..config.trials {
        let clock = ManualClock::new(MonotonicTime::ZERO);
        let mut simulation = Simulation {
            family,
            prefix,
            config,
            strategy,
            tenants,
            clock: &clock,
            per_model: BTreeSet::new(),
            store: Vec::new(),
            cache_bytes: 0,
            peak_cache_bytes: 0,
            tally: Tally::default(),
        };
        let mut busy_until = 0u64;
        for (item_index, item) in trace(config, trial).iter().enumerate() {
            let item_number = u32::try_from(item_index).unwrap_or(u32::MAX);
            let arrival = u64::from(item_number).saturating_mul(interval_nanos);
            if arrival < busy_until {
                return Err(PrototypeError::ServerBusy {
                    trial,
                    item: item_number,
                });
            }
            let (seconds, attempts) = simulation.serve(item)?;
            let mut jitter_rng =
                SeededRng::derived(config.seed, &[u64::from(trial), item_index as u64, 0x6A69]);
            let factor = 1.0 + (jitter_rng.next_unit() * 2.0 - 1.0) * config.jitter_fraction;
            let batch_seconds = seconds * factor;
            simulation.tally.compute_seconds += batch_seconds;
            let batch_nanos = (batch_seconds * 1e9).round().max(1.0) as u64;
            busy_until = arrival.saturating_add(batch_nanos);
            let mut recorders = Vec::new();
            for served in &attempts {
                let tenancy = &tenants[item.tenant.min(1)];
                let operation = OperationId::new(format!(
                    "p11-{}-{}-t{trial}-r{item_index}-v{}",
                    family.pair.label(),
                    strategy.label(),
                    served.variant
                ))?;
                recorders.push((
                    *served,
                    tenancy.authority.parent().clone(),
                    EventRecorder::new(operation, context.clock.clone(), &clock),
                ));
            }
            clock.advance_to(MonotonicTime::from_nanos(arrival));
            for (_, _, recorder) in &mut recorders {
                recorder.record(EventKind::RequestAccepted);
                recorder.record(EventKind::RequestDequeued);
            }
            clock.advance_to(MonotonicTime::from_nanos(busy_until));
            for (_, _, recorder) in &mut recorders {
                recorder.record(EventKind::TokenEmitted);
                recorder.record(EventKind::RequestCompleted);
            }
            for (served, execution, recorder) in recorders {
                let events = recorder.into_events();
                let operation = events
                    .first()
                    .map(|event| event.operation.clone())
                    .ok_or(ReportError::NoAttempts)?;
                run.records.push(context.record(
                    strategy,
                    operation,
                    &execution,
                    trial,
                    served,
                    item.tokens.len() as u64,
                    config.seed,
                    simulation.cache_bytes,
                    events,
                )?);
                simulation.tally.attempts += 1;
            }
        }
        let tally = simulation.tally;
        run.compute_seconds += tally.compute_seconds;
        run.exactness_violations += tally.exactness_violations;
        run.unauthorized_reuses += tally.unauthorized_reuses;
        run.cross_tenant_refusals += tally.cross_tenant_refusals;
        run.eligible_attempts += tally.eligible_attempts;
        run.attempts += tally.attempts;
        run.peak_cache_bytes = run.peak_cache_bytes.max(simulation.peak_cache_bytes);
        run.retained_cache_bytes = run.retained_cache_bytes.max(simulation.cache_bytes);
    }
    Ok(run)
}

fn measured_bytes(bytes: u64) -> Result<Measured<NonNegative>, ReportError> {
    Ok(Measured::measured(NonNegative::new(bytes as f64)?))
}

/// The §1.3 objective vector of a run: first-token p50 over every successful attempt,
/// reliability, fake cache bytes and zero transferred bytes; everything else is not
/// measured, with its reason.
fn objectives(run: &StrategyRun) -> Result<ObjectiveVector, PrototypeError> {
    let ledger = AttemptLedger::from_records(run.records.iter().cloned())?;
    let summary = LatencySummary::from_ledger(
        &ledger,
        IntervalKind::TimeToFirstToken,
        PercentileMethod::NearestRank,
    )?;
    let p50 = summary
        .percentile(Quantile::P50)
        .and_then(|estimate| estimate.value_nanos.value().copied())
        .ok_or(ReportError::NoAttempts)?;
    let not = Measured::not_measured;
    Ok(ObjectiveVector {
        time_to_first_token_quantile: Quantile::P50,
        latency_objective: LatencyObjective {
            quantile: Quantile::P99,
            max_time_to_first_token_nanos: 1_000_000_000,
        },
        time_to_first_token_nanos: Measured::measured(NonNegative::new(p50)?),
        throughput_under_latency_objective_tokens_per_second: not(NotMeasuredReason::NotRecorded),
        peak_gpu_memory_bytes: measured_bytes(run.peak_cache_bytes)?,
        retained_gpu_memory_bytes: measured_bytes(run.retained_cache_bytes)?,
        peak_host_memory_bytes: not(NotMeasuredReason::NotRecorded),
        retained_host_memory_bytes: not(NotMeasuredReason::NotRecorded),
        transferred_bytes: measured_bytes(0)?,
        storage_read_bytes: not(NotMeasuredReason::NotApplicable),
        preparation_cost_usd: not(NotMeasuredReason::NotApplicable),
        cost_per_completed_request_usd: not(NotMeasuredReason::NotApplicable),
        energy_per_completed_request_joules: not(NotMeasuredReason::InstrumentUnavailable),
        reliability_success_rate: Measured::measured(NonNegative::new(
            summary.success_rate().rate(),
        )?),
    })
}

fn side(run: &StrategyRun) -> Result<ComparisonSide, PrototypeError> {
    let first = run.records.first().ok_or(ReportError::NoAttempts)?;
    Ok(ComparisonSide {
        name: label(run.strategy.label())?,
        provenance: Provenance::of_records(&run.records)?,
        configuration: MatchedConfiguration::from_record(first)?,
        temperature: StartTemperature::Hot,
        fidelity: ModeFidelity::BitIdentical,
        accuracy_evaluation: Measured::not_measured(NotMeasuredReason::NotApplicable),
        objectives: objectives(run)?,
    })
}

/// The outcome of one pair under all three strategies.
#[derive(Clone, Debug, PartialEq)]
pub struct PairOutcome {
    pub pair: PrototypePair,
    pub shared_operators: usize,
    /// In [`Strategy::ALL`] order.
    pub runs: Vec<StrategyRun>,
    /// The candidate against independent execution and per-model prefix caching.
    pub report: ComparisonReport,
    pub incidence: Incidence,
    /// Per-model caching's compute seconds minus the candidate's.
    pub net_saving_seconds: f64,
}

impl PairOutcome {
    pub fn run(&self, strategy: Strategy) -> Option<&StrategyRun> {
        self.runs.iter().find(|run| run.strategy == strategy)
    }

    pub fn exactness_violations(&self) -> u64 {
        self.runs.iter().map(|run| run.exactness_violations).sum()
    }

    pub fn unauthorized_reuses(&self) -> u64 {
        self.runs.iter().map(|run| run.unauthorized_reuses).sum()
    }
}

fn tenancy(name: &str, parent: &str) -> Result<Tenancy, PrototypeError> {
    Ok(Tenancy {
        tenant: TenantId::new(name)?,
        authority: AuthorityBinding::new(
            ExecutionId::new(parent)?,
            ExecutionCategory::SharedKernelGpuRuntime,
            Some(AuthorizationEpoch::FIRST),
        )?,
    })
}

/// Runs one family under all three strategies and builds its comparison report.
pub fn run_pair(
    family: &PrototypeFamily,
    config: &WorkloadConfig,
) -> Result<PairOutcome, PrototypeError> {
    config.check()?;
    let prefix = discover_shared_prefix(&family.a, &family.b);
    let context = RecordContext::new(family, config)?;
    let tenants = [
        tenancy("p11-tenant-a", "p11-parent-a")?,
        tenancy("p11-tenant-b", "p11-parent-b")?,
    ];
    let runs = Strategy::ALL
        .iter()
        .map(|strategy| run_strategy(family, &prefix, config, *strategy, &context, &tenants))
        .collect::<Result<Vec<_>, _>>()?;
    let [independent, per_model, candidate] = runs.as_slice() else {
        return Err(PrototypeError::Report(ReportError::NoAttempts));
    };
    let design = ExperimentDesign {
        effect: EffectClass::CacheOrPredictor,
        independent_trials: config.trials,
        trace: TracePattern::Mixed { seed: config.seed },
        components: vec![label(COMPONENT_LABEL)?],
        ablated_components: vec![label(COMPONENT_LABEL)?],
    };
    let report = ComparisonReport::new(
        ObjectivePlan::new(Objective::TimeToFirstToken, 0.1)?,
        StateComparison::HotDispatch,
        design,
        Vec::new(),
        side(candidate)?,
        Baseline::Measured {
            sides: vec![side(independent)?],
        },
        Baseline::Measured {
            sides: vec![side(per_model)?],
        },
    )?;
    let incidence = Incidence::new(candidate.eligible_attempts, candidate.attempts)?;
    let net_saving_seconds = per_model.compute_seconds - candidate.compute_seconds;
    Ok(PairOutcome {
        pair: family.pair,
        shared_operators: prefix.shared_operators(),
        runs,
        report,
        incidence,
        net_saving_seconds,
    })
}

/// The three pairs of line 898 and the workload they ran on.
#[derive(Clone, Debug, PartialEq)]
pub struct PrototypeOutcome {
    /// In [`PrototypePair::ALL`] order.
    pub pairs: Vec<PairOutcome>,
    pub workload: WorkloadSource,
}

impl PrototypeOutcome {
    pub fn pair(&self, pair: PrototypePair) -> Option<&PairOutcome> {
        self.pairs.iter().find(|outcome| outcome.pair == pair)
    }

    /// Line 900 evidence: exactness and authorization over every pair, net saving and
    /// incidence of the verified pair, and the provenance of its candidate's records.
    pub fn pass_stop_evidence(
        &self,
        minimum_incidence: MinimumIncidence,
    ) -> Result<(PassStopEvidence, Provenance), PrototypeError> {
        let verified = self
            .pair(PrototypePair::VerifiedSharedPrefix)
            .ok_or(ReportError::NoAttempts)?;
        let evidence = PassStopEvidence {
            exactness_violations: self
                .pairs
                .iter()
                .map(PairOutcome::exactness_violations)
                .sum(),
            unauthorized_reuses: self
                .pairs
                .iter()
                .map(PairOutcome::unauthorized_reuses)
                .sum(),
            net_saving_seconds: verified.net_saving_seconds,
            incidence: verified.incidence,
            minimum_incidence,
            workload: self.workload,
        };
        Ok((evidence, verified.report.candidate().provenance.clone()))
    }

    /// The line 900 decision and the §4.17 claim record of this run.
    pub fn decide(
        &self,
        minimum_incidence: MinimumIncidence,
        literature: LiteratureComparison,
    ) -> Result<(PassStopDecision, ClaimRecord), PrototypeError> {
        let (evidence, provenance) = self.pass_stop_evidence(minimum_incidence)?;
        let decision = decide_pass_stop(&evidence, &provenance)?;
        Ok((decision, claim_record(claim_result(&decision, literature))))
    }
}

/// Runs the first prototype: the three pairs of line 898 in `scope`.
pub fn run_prototype(
    config: &WorkloadConfig,
    scope: TrustScope,
) -> Result<PrototypeOutcome, PrototypeError> {
    let pairs = PrototypePair::ALL
        .iter()
        .map(|pair| run_pair(&prototype_family(*pair, scope)?, config))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PrototypeOutcome {
        pairs,
        workload: WorkloadSource::Synthetic { seed: config.seed },
    })
}
