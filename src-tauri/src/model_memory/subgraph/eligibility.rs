//! Eligibility of exact intermediate state for reuse (GPU §4.16 lines 888–892). Each rule
//! is refused with its own [`ReuseRefusal`], and every refusal sends the request to the
//! normal execution path:
//!
//! - parameter equality alone is insufficient: an operator whose parameters match but
//!   whose parent state differs is not reusable ([`ReuseRefusal::ParentStateDiffers`]);
//! - a matching fragment under a different preceding context is a different input
//!   ([`ReuseRefusal::PrecedingContextDiffers`]);
//! - runtime seeds and operator states enter the key or disqualify reuse
//!   ([`ReuseRefusal::UnboundRuntimeSeed`], [`ReuseRefusal::UnboundOperatorState`]);
//! - autoregressive reuse stops where token histories or ancestor states diverge
//!   ([`check_continuation`]);
//! - kernel or batching choices that break bit-identical results use the normal path;
//! - approximate reuse is a separate mode with its own quality contract and is refused
//!   here ([`ReuseRefusal::ApproximateReuseIsSeparateMode`]).

use std::fmt;

use crate::foundation::ids::Digest;
use crate::model_memory::identity::{
    FidelityCategory, FidelityConfiguration, GrantRefusal, Technique,
};

use super::key::{
    BoundRuntime, ExactInput, RuntimeChoices, StateKeyComponent, StateKeySpec, SubgraphStateKey,
};
use super::variant::{BatchDependence, ImmutableVariant, KernelDeterminism, OperatorRuntime};

/// The exactness a request asks for (line 892).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExactnessCriterion {
    /// Bit-identical to the normal path: the only criterion this contract serves.
    BitIdentical,
    /// Results within a declared quality contract. A separate mode (line 892, §1.3);
    /// always refused by this contract.
    Approximate { quality_contract: Digest },
}

/// Proof that a request asks for exact reuse under a fidelity configuration that allows
/// it (§1.3: exact reuse is its own category). Made only by [`ReuseMode::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReuseMode {
    category: FidelityCategory,
}

impl ReuseMode {
    /// Refuses an approximate criterion and a configuration limited to lossless
    /// representation.
    pub fn new(
        exactness: &ExactnessCriterion,
        fidelity: &FidelityConfiguration,
    ) -> Result<Self, ReuseRefusal> {
        if let ExactnessCriterion::Approximate { .. } = exactness {
            return Err(ReuseRefusal::ApproximateReuseIsSeparateMode);
        }
        let category = fidelity.category();
        if category < Technique::SharedSubgraphReuse.category() {
            return Err(ReuseRefusal::FidelityForbidsReuse {
                configured: category,
            });
        }
        Ok(Self { category })
    }

    /// The configured category, at least exact reuse.
    pub fn category(&self) -> FidelityCategory {
        self.category
    }
}

/// The session identity components of §3.9 that a shared-subgraph request must match
/// for the variant it runs (line 894).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionComponent {
    Execution,
    Adapter,
    PositionalEncoding,
    Tenant,
    Authority,
}

/// Why exact intermediate state may not be reused; the request then takes the normal
/// execution path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReuseRefusal {
    /// Line 892: approximate reuse is a separate mode with a separate quality contract.
    ApproximateReuseIsSeparateMode,
    /// §1.3: the configuration does not allow exact reuse.
    FidelityForbidsReuse { configured: FidelityCategory },
    /// Line 892: the kernels are not deterministic.
    NondeterministicKernels,
    /// Line 892: results depend on the batch the request runs in.
    BatchDependentKernels,
    /// Line 892: the runtime chose other kernels than the declared profile.
    KernelChoiceDiffers,
    /// Line 888: a seeded operator has no seed bound for this request.
    UnboundRuntimeSeed { operator: usize },
    /// Line 888: a stateful operator has no state bound for this request.
    UnboundOperatorState { operator: usize },
    /// A seed or state was bound to an operator that does not draw or keep one.
    UnexpectedRuntimeBinding { operator: usize },
    /// Line 888: the operator's parameters match but its parent state differs.
    ParentStateDiffers { operator: usize },
    /// Line 888: the same fragment under a different preceding context.
    PrecedingContextDiffers,
    /// The exact inputs differ.
    InputDiffers,
    /// Other key components differ.
    KeyMismatch {
        operator: usize,
        components: Vec<StateKeyComponent>,
    },
    /// Line 894: a state offered for more operators than its keys prove identical.
    ClaimsBeyondSharedPrefix {
        claimed: usize,
        provable: usize,
        first_mismatch: Box<ReuseRefusal>,
    },
    /// Line 892: token histories or ancestor states diverge at this position.
    HistoryDiverged { position: u64 },
    /// S3.3: state is shared only inside one trust scope.
    DifferentTrustScope,
    /// The producing parent execution's authority binding has changed since; nothing
    /// bound to an older binding is honoured (S3.1).
    AuthorityChanged,
    /// S3.3: sharing outside the producing parent execution needs a scoped grant.
    Unauthorized(GrantRefusal),
    /// §3.9: the request's session is not a session of the variant it runs.
    SessionMismatch { component: SessionComponent },
    /// Line 890: state is produced only at a profitable branch boundary of this variant.
    NotAPlannedBoundary,
    /// The received activation is not the one the state names.
    ActivationMismatch,
}

impl fmt::Display for ReuseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ApproximateReuseIsSeparateMode => f.write_str(
                "approximate reuse is a separate mode with its own quality contract",
            ),
            Self::FidelityForbidsReuse { configured } => {
                write!(f, "the configured fidelity ({configured}) does not allow exact reuse")
            }
            Self::NondeterministicKernels => f.write_str("the kernels are not deterministic"),
            Self::BatchDependentKernels => {
                f.write_str("results depend on the batch the request runs in")
            }
            Self::KernelChoiceDiffers => {
                f.write_str("the runtime chose other kernels than the declared profile")
            }
            Self::UnboundRuntimeSeed { operator } => {
                write!(f, "operator {operator} draws a runtime seed that is not bound")
            }
            Self::UnboundOperatorState { operator } => {
                write!(f, "operator {operator} keeps state that is not bound")
            }
            Self::UnexpectedRuntimeBinding { operator } => {
                write!(f, "operator {operator} neither draws a seed nor keeps state")
            }
            Self::ParentStateDiffers { operator } => write!(
                f,
                "operator {operator} has equal parameters but receives a different parent state"
            ),
            Self::PrecedingContextDiffers => {
                f.write_str("the same fragment follows a different preceding context")
            }
            Self::InputDiffers => f.write_str("the exact inputs differ"),
            Self::KeyMismatch {
                operator,
                components,
            } => write!(f, "operator {operator}'s state key differs in {components:?}"),
            Self::ClaimsBeyondSharedPrefix {
                claimed,
                provable,
                first_mismatch,
            } => write!(
                f,
                "the state claims {claimed} operators but only {provable} are provably identical: {first_mismatch}"
            ),
            Self::HistoryDiverged { position } => {
                write!(f, "the histories diverge at position {position}")
            }
            Self::DifferentTrustScope => {
                f.write_str("state is shared only inside one trust scope")
            }
            Self::AuthorityChanged => {
                f.write_str("the producing execution's authority has changed since")
            }
            Self::Unauthorized(refusal) => write!(f, "sharing is not authorized: {refusal}"),
            Self::SessionMismatch { component } => {
                write!(f, "the session differs from the variant in {component:?}")
            }
            Self::NotAPlannedBoundary => {
                f.write_str("state is produced only at a profitable branch boundary")
            }
            Self::ActivationMismatch => {
                f.write_str("the received activation is not the state's activation")
            }
        }
    }
}

impl std::error::Error for ReuseRefusal {}

/// Line 892: the profile must be deterministic and batch-invariant and the runtime must
/// run its declared kernels; otherwise the request uses the normal path.
pub fn check_exact_execution(
    variant: &ImmutableVariant,
    runtime: &RuntimeChoices,
) -> Result<(), ReuseRefusal> {
    let profile = variant.profile();
    if profile.determinism == KernelDeterminism::NonDeterministic {
        return Err(ReuseRefusal::NondeterministicKernels);
    }
    if profile.batching == BatchDependence::BatchDependent {
        return Err(ReuseRefusal::BatchDependentKernels);
    }
    if runtime.kernels != profile.kernels {
        return Err(ReuseRefusal::KernelChoiceDiffers);
    }
    let operators = variant.operators();
    let binds = |index: &usize, wanted: OperatorRuntime| {
        operators
            .get(*index)
            .is_some_and(|operator| operator.runtime() == wanted)
    };
    if let Some(index) = runtime
        .seeds
        .keys()
        .find(|index| !binds(index, OperatorRuntime::Seeded))
    {
        return Err(ReuseRefusal::UnexpectedRuntimeBinding { operator: *index });
    }
    if let Some(index) = runtime
        .operator_states
        .keys()
        .find(|index| !binds(index, OperatorRuntime::Stateful))
    {
        return Err(ReuseRefusal::UnexpectedRuntimeBinding { operator: *index });
    }
    Ok(())
}

fn bind_runtime(
    operator: usize,
    declared: OperatorRuntime,
    runtime: &RuntimeChoices,
) -> Result<BoundRuntime, ReuseRefusal> {
    match declared {
        OperatorRuntime::Stateless => Ok(BoundRuntime::Stateless),
        OperatorRuntime::Seeded => runtime
            .seeds
            .get(&operator)
            .map(|seed| BoundRuntime::Seed(*seed))
            .ok_or(ReuseRefusal::UnboundRuntimeSeed { operator }),
        OperatorRuntime::Stateful => runtime
            .operator_states
            .get(&operator)
            .map(|state| BoundRuntime::State(*state))
            .ok_or(ReuseRefusal::UnboundOperatorState { operator }),
    }
}

impl ImmutableVariant {
    /// The state key specs of the first `operators` operators (at most all of them) for
    /// one request, each bound to its parent's key (lines 882–888). Refused, for the
    /// normal path, when the execution is not exact or a seed or state is unbound.
    pub fn state_key_specs(
        &self,
        input: &ExactInput,
        runtime: &RuntimeChoices,
        _mode: &ReuseMode,
        operators: usize,
    ) -> Result<Vec<StateKeySpec>, ReuseRefusal> {
        check_exact_execution(self, runtime)?;
        let mut specs: Vec<StateKeySpec> = Vec::new();
        for (index, operator) in self.operators().iter().take(operators).enumerate() {
            let parents = specs.last().map(StateKeySpec::key).into_iter().collect();
            specs.push(StateKeySpec {
                operator: operator.abi().clone(),
                parameters: operator.parameters().to_vec(),
                parents,
                input: input.clone(),
                attention: self.attention().clone(),
                position: self.position().clone(),
                output: operator.output().clone(),
                adapter_effects: operator.adapter_effects().to_vec(),
                profile: self.profile().clone(),
                runtime: bind_runtime(index, operator.runtime(), runtime)?,
                trust_scope: *self.trust_scope(),
            });
        }
        Ok(specs)
    }

    /// The keys of [`Self::state_key_specs`].
    pub fn state_keys(
        &self,
        input: &ExactInput,
        runtime: &RuntimeChoices,
        mode: &ReuseMode,
        operators: usize,
    ) -> Result<Vec<SubgraphStateKey>, ReuseRefusal> {
        Ok(self
            .state_key_specs(input, runtime, mode, operators)?
            .iter()
            .map(StateKeySpec::key)
            .collect())
    }

    /// The state key at `boundary` (the output of operator `boundary - 1`) for every
    /// position of an autoregressive history: position `i` covers token `i` after the
    /// context `tokens[..i]` (line 892).
    pub fn boundary_history(
        &self,
        tokens: &[u32],
        boundary: usize,
        runtime: &RuntimeChoices,
        mode: &ReuseMode,
    ) -> Result<Vec<HistoryStep>, ReuseRefusal> {
        if boundary == 0 || boundary > self.operators().len() {
            return Err(ReuseRefusal::NotAPlannedBoundary);
        }
        tokens
            .iter()
            .enumerate()
            .map(|(position, token)| {
                let input = ExactInput::new(&tokens[..position], &[*token], None)
                    .map_err(|_| ReuseRefusal::InputDiffers)?;
                let keys = self.state_keys(&input, runtime, mode, boundary)?;
                let state = keys
                    .last()
                    .copied()
                    .ok_or(ReuseRefusal::NotAPlannedBoundary)?;
                Ok(HistoryStep {
                    token: *token,
                    state,
                })
            })
            .collect()
    }
}

/// Compares the state an operator stored with the state a request needs (line 888).
/// Equal keys are reusable. Otherwise the refusal names the rule: different inputs (with
/// equal fragments meaning a different preceding context), then a parent state that
/// differs under equal parameters, then any other differing component.
pub fn check_state_reuse(
    stored: &StateKeySpec,
    request: &StateKeySpec,
    operator: usize,
) -> Result<SubgraphStateKey, ReuseRefusal> {
    let key = stored.key();
    if key == request.key() {
        return Ok(key);
    }
    let components = stored.differences(request);
    if components.contains(&StateKeyComponent::Inputs) {
        return Err(
            if stored.input.span() == request.input.span()
                && stored.input.extra() == request.input.extra()
            {
                ReuseRefusal::PrecedingContextDiffers
            } else {
                ReuseRefusal::InputDiffers
            },
        );
    }
    if components.contains(&StateKeyComponent::ParentStates)
        && !components.contains(&StateKeyComponent::Parameters)
    {
        return Err(ReuseRefusal::ParentStateDiffers { operator });
    }
    Err(ReuseRefusal::KeyMismatch {
        operator,
        components,
    })
}

/// One position of an autoregressive history at a boundary: its token and the state
/// key there, which binds every earlier token and ancestor state (line 892).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HistoryStep {
    pub token: u32,
    pub state: SubgraphStateKey,
}

/// How many leading positions two histories share: reuse stops at the first position
/// where the tokens or the ancestor states differ, even if later positions match again
/// (line 892).
pub fn common_history_prefix(stored: &[HistoryStep], request: &[HistoryStep]) -> usize {
    stored
        .iter()
        .zip(request)
        .take_while(|(stored, request)| stored == request)
        .count()
}

/// Line 892: allows reuse of `claimed_positions` leading positions of `stored` for
/// `request` only up to their common prefix; returns the reusable count.
pub fn check_continuation(
    stored: &[HistoryStep],
    request: &[HistoryStep],
    claimed_positions: usize,
) -> Result<usize, ReuseRefusal> {
    let common = common_history_prefix(stored, request);
    if claimed_positions > common {
        return Err(ReuseRefusal::HistoryDiverged {
            position: u64::try_from(common).unwrap_or(u64::MAX),
        });
    }
    Ok(claimed_positions)
}
