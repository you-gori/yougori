//! GPU-N3: reuse exact intermediate computation across compatible variants (GPU §4.16 of
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, lines 874–900, with the claim record
//! of §4.17, lines 902–917; mapped to GPU-W07 and GPU-W10).
//!
//! - [`key`]: the state key of lines 882–886 (operator/kernel ABI, exact parameter
//!   identities, parent state identities, exact inputs, attention and position
//!   semantics, dtype/layout, adapter effects, deterministic execution profile, trust
//!   scope) plus the bound seed or operator state of line 888, as a domain-separated
//!   digest of typed fields.
//! - [`parameters`]: exact parameter identities derived from validated manifests
//!   ([`crate::model_memory::manifest`], §3.3).
//! - [`variant`]: immutable variants as operator chains; unmerged adapters pass the §3.9
//!   compatibility check ([`crate::model_memory::adapters::adapter`]) before they become
//!   adapter effects.
//! - [`eligibility`]: the rules of lines 888–892, each refused with its own reason, and
//!   autoregressive continuation that stops where histories diverge.
//! - [`discovery`]: the longest provably identical executable prefix of two variants,
//!   stopping at the first difference.
//! - [`profit`]: caching only at profitable branch boundaries (line 890).
//! - [`contract`]: the separately typed shared-subgraph state contract (line 894): the
//!   §3.9 session check, trust scopes and T07's scoped grants
//!   ([`crate::model_memory::identity`]), and no route to session KV reuse, which stays
//!   with [`crate::model_memory::adapters::kv::check_kv_reuse`].
//! - [`synthetic`], [`prototype`]: the first prototype of line 898 on the fake substrate,
//!   recorded through [`crate::foundation::report`] with fake-substrate provenance.
//! - [`decision`]: the pass/stop rule of line 900 and the §4.17 claim record.
//!
//! Everything is pure, synchronous and deterministic. Randomness comes only from
//! [`rng::SeededRng`]; time comes from [`crate::foundation::ids::Clock`]. Seconds are
//! `f64`, bytes `u64`, and invalid numbers are refused with
//! [`crate::model_memory::math::InputError`].
//!
//! # Claim record
//!
//! GPU §4.17 lines 908–915; the computed result is [`decision::claim_record`] over the
//! prototype's [`decision::PassStopDecision`], asserted by the tests.
//!
//! 1. **Contribution.** Identity-based eligibility for reusing the exact output of a
//!    shared leading operator sequence across immutable variants of one model family: a
//!    typed state key over operator and kernel ABI, manifest-derived parameter
//!    identities, parent state keys, the exact input with its preceding context,
//!    attention and position semantics, dtype and layout, adapter effects, a
//!    deterministic execution profile, bound seeds or operator state and the trust
//!    scope, with caching only at profitable branch boundaries and sharing only under
//!    the producing authority or a scoped grant.
//! 2. **Closest prior work.** Mainstream (USENIX ATC 2018, named in §4.13) shares a
//!    common DNN stem across applications fine-tuned from one pre-trained model and
//!    picks how many layers to share by an accuracy and throughput trade-off. Ordinary
//!    per-model prefix caching reuses KV only under one full model identity.
//! 3. **Difference tested.** Whether identity checks alone, without retraining or
//!    accuracy trade-offs, find the provably identical prefix of independently published
//!    variants and reuse it bit-identically across variants where per-model prefix
//!    caching misses, with keying and handoff costs counted.
//! 4. **Assumptions and smallest counterexample.** Kernels are deterministic and
//!    batch-invariant under the declared profile; equal manifest-derived parameter
//!    identities mean equal bytes read the same way; an operator's output depends only
//!    on what its key binds. Smallest counterexample: one operator whose kernel picks a
//!    split-K reduction by batch size, so the same prefix computed alone and in a batch
//!    of two differs in the last bit under an identical key. A batch-dependent profile
//!    therefore always takes the normal path.
//! 5. **Comparison.** Independent execution (ordinary workflow) and per-model prefix
//!    caching (strongest compatible baseline) against verified shared-subgraph
//!    execution, on the fake time-controlled substrate: the verified shared-prefix pair,
//!    the control pair differing in the first block and the pair with equal weights
//!    under another rotary base, over five independent trials of a seeded mixed trace.
//!    Fake-substrate figures (seed 11, not measurements): batch compute 1.81 s for the
//!    candidate against 2.55 s for per-model caching and 2.81 s for independent
//!    execution, keying and lookups included; first-token p50 14.8 ms against 19.7 ms;
//!    57 of 177 attempts reused another variant's prefix; the retained boundary states
//!    raise fake cache memory by 16 %, which the verdict reports as a regression. The
//!    two control pairs share nothing and match per-model caching exactly, no result
//!    differs from the normal path, and no reuse escapes authorization.
//! 6. **Result: inconclusive.** The comparison ran on fakes, the incidence comes from a
//!    synthetic trace, and the literature comparison of §4.13 line 792 has not been
//!    done. GPU-N3 stays optional (§4.17 line 904).

mod canon;
pub mod contract;
pub mod decision;
pub mod discovery;
pub mod eligibility;
pub mod key;
pub mod parameters;
pub mod profit;
pub mod prototype;
pub mod rng;
pub mod synthetic;
pub mod variant;

#[cfg(test)]
mod tests;

pub use contract::{
    check_session, produce_state, reuse_state, SharedPrefixReuse, SubgraphRequest, SubgraphState,
};
pub use decision::{
    claim_record, claim_result, decide_pass_stop, judge_incidence, ClaimRecord, ClaimResult,
    DecisionError, Incidence, IncidenceVerdict, LiteratureComparison, MinimumIncidence,
    MissingEvidence, PassStopDecision, PassStopEvidence, StopReason, WorkloadSource,
};
pub use discovery::{discover_shared_prefix, PrefixStop, SharedPrefix};
pub use eligibility::{
    check_continuation, check_exact_execution, check_state_reuse, common_history_prefix,
    ExactnessCriterion, HistoryStep, ReuseMode, ReuseRefusal, SessionComponent,
};
pub use key::{
    BoundRuntime, ExactInput, RuntimeChoices, StateKeyComponent, StateKeySpec, SubgraphStateKey,
};
pub use parameters::{ParameterError, ParameterIdentity};
pub use profit::{
    estimate, hash_every_operation, plan_boundary, BoundaryEconomics, CacheRefusal, HandoffCosts,
    OperatorCost, ProfitError, ProfitEstimate, ProfitableBoundary, StateHandoff,
};
pub use prototype::{
    run_pair, run_prototype, PairOutcome, PrototypeError, PrototypeOutcome, Strategy, StrategyRun,
    WorkloadConfig,
};
pub use variant::{
    AdapterAdmission, AdapterEffect, AttentionSemantics, BatchDependence, ExecutionProfile,
    ImmutableVariant, KernelDeterminism, Operator, OperatorAbi, OperatorDefinition,
    OperatorRuntime, SubgraphError, TensorFormat, VariantDefinition, VariantIdentity,
};
