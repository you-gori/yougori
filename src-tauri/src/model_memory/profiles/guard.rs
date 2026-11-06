//! The calls this module makes into other contracts, kept in one place: CORE-01's
//! admission of an evidenced runtime offer (INT-07) and plan-based S3.5 fallback guard,
//! CORE-04's authority record of what a parent execution may run, and the backend
//! technique gate of GPU part §3.8. Only this file follows changes to their signatures.

use crate::foundation::coordination::{CapacityPort, Coordinator, ModelId, ModelRefusal};
use crate::foundation::evidence::{
    guard_fallback, AdmittedRuntime, ApprovedFallback, CategoryRefusal, FallbackRefusal,
    LoaderGate, LoaderPlan, ProbeRegistry, RuntimeOffer, RuntimeRequirement, RuntimeSettings,
};
use crate::foundation::ids::{Clock, ExecutionId};
use crate::model_memory::backends::{
    AdmittedTechnique, BackendRuntime, ExperimentApproval, Technique, TechniqueRefusal,
};

/// Admits `offer` under `requirement`, or refuses it with its label and recorded
/// decision. The category is the one CORE-01 evidence confirmed for the runtime, never a
/// caller's label (INT-07; S13 line 252: a fast profile never turns a labelled runtime
/// into a VM sandbox).
pub(super) fn admit_runtime(
    requirement: &RuntimeRequirement,
    offer: &RuntimeOffer,
) -> Result<AdmittedRuntime, CategoryRefusal> {
    requirement.admit(offer)
}

/// The coordination authority's record of what a parent execution may run (CORE-04): the
/// only source of the settings a revert is judged against (S3.5; T01 review: never a
/// caller's settings). [`Coordinator`] is one.
pub trait AuthorityRecord {
    /// How the authority names a model under a parent execution.
    type Model;
    /// Why the authority holds no settings for it, such as a parent without current
    /// authority or a model never activated under it.
    type Refusal;

    /// The settings the record authorizes for `model` under `execution` now.
    fn authorized_settings(
        &self,
        execution: &ExecutionId,
        model: &Self::Model,
    ) -> Result<RuntimeSettings, Self::Refusal>;
}

/// T09's coordinator: its execution category, network grants, verified artifacts and
/// authority come from the parent's authority record, and its loader, batch size and
/// residency from the model's latest activation under it.
impl<C: Clock, P: CapacityPort> AuthorityRecord for Coordinator<C, P> {
    type Model = ModelId;
    type Refusal = ModelRefusal;

    fn authorized_settings(
        &self,
        execution: &ExecutionId,
        model: &ModelId,
    ) -> Result<RuntimeSettings, ModelRefusal> {
        Coordinator::authorized_settings(self, execution, *model)
    }
}

/// The authorized runtime a fallback must stay within: the optimization gate, the
/// registry its evidence lives in, the loader plan the gate approved for this runtime, and
/// the settings the coordination authority's record authorizes (S3.5; INT-06; CORE-04).
/// Built only by [`AuthorizedRuntime::from_authority`], so no caller supplies the
/// settings.
pub struct AuthorizedRuntime<'a, C: Clock> {
    gate: &'a LoaderGate,
    registry: &'a ProbeRegistry<C>,
    plan: &'a LoaderPlan,
    settings: RuntimeSettings,
}

impl<'a, C: Clock> AuthorizedRuntime<'a, C> {
    /// The authorized runtime of `model` under `execution`: the gate, the registry and
    /// the plan the gate approved, with the settings `authority` records for them now, or
    /// the authority's refusal.
    pub fn from_authority<A: AuthorityRecord>(
        gate: &'a LoaderGate,
        registry: &'a ProbeRegistry<C>,
        plan: &'a LoaderPlan,
        authority: &A,
        execution: &ExecutionId,
        model: &A::Model,
    ) -> Result<Self, A::Refusal> {
        let settings = authority.authorized_settings(execution, model)?;
        Ok(Self {
            gate,
            registry,
            plan,
            settings,
        })
    }

    /// The settings the authority record authorizes.
    pub fn settings(&self) -> &RuntimeSettings {
        &self.settings
    }

    /// The loader plan the gate approved for this runtime.
    pub fn plan(&self) -> &LoaderPlan {
        self.plan
    }
}

/// Approves `proposed` as a fallback from `authorized`, checking its loader against the
/// approved plan, or refuses it with every forbidden change (S3.5; FAST-02: a revert stays
/// in the same authorized execution category).
pub(super) fn approve_fallback<C: Clock>(
    authorized: &AuthorizedRuntime<'_, C>,
    proposed: RuntimeSettings,
) -> Result<ApprovedFallback, FallbackRefusal> {
    guard_fallback(
        authorized.gate,
        authorized.registry,
        authorized.plan,
        &authorized.settings,
        proposed,
    )
}

/// Admits `technique` on the exact `backend` runtime (GPU part §3.8: CUDA graphs and
/// concurrency are later experiments of the vLLM retained-process row, off unless approved
/// for the exact release; §1.1).
pub(super) fn admit_technique(
    backend: &BackendRuntime,
    technique: Technique,
    approvals: &[ExperimentApproval],
) -> Result<AdmittedTechnique, TechniqueRefusal> {
    backend.admit(technique, approvals)
}
