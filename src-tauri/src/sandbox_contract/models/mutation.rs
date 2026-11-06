//! VM-N3: adversarial tests generated from the security contract.
//!
//! For each prohibited action the contract declares its invariants, guards and
//! enforcement points. The generator produces named faults (guest policy ignored, stale
//! DNS answer, relay identity spoofed, firewall rule missing, ticket replayed, approval
//! payload changed, supervisor delayed, snapshot epoch restored, one broker
//! compromised), a common-cause fault per shared dependency and a single-guard failure per
//! guard. Each declared invariant is checked under each fault by exhaustive enumeration;
//! a broken invariant yields its shortest counterexample and the missing enforcement
//! assumption, a held one the minimal further guard failures that would break it.
//!
//! VM-P44: single-guard and common-cause predictions are compared with observed
//! containment; an observed breach the model did not predict means the model omits the
//! actual enforcement boundary, so no system verification is claimed.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::rc::Rc;

use serde::Serialize;

use super::assurance::{
    assess, AssuranceObservation, AssuranceRequirement, AssuranceStatus, NotAssurance,
};
use super::attack_graph::{MAX_SEARCH_UNITS, MAX_SET_SIZE};
use super::contract::{
    check_model, Defect, Dependency, EnforcementPoint, Guard, Injection, InvariantId, ModelConfig,
    ModelKind,
};
use super::explore::{subsets, Bounds, Exploration, Trace};
use super::ModelError;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Digest, DigestBuilder, MonotonicTime};

/// What a model result is about (§12.3).
pub const MODEL_SCOPE: &str = "a property of this bounded model under its stated assumptions; it \
    does not prove the Rust or Go code, the operating system, the hypervisor, external providers \
    or hardware (VM §12.3)";

/// Domain of [`Counterexample::digest`].
pub const COUNTEREXAMPLE_DOMAIN: &str = "yougori/sandbox/models/counterexample/v1";

/// The largest guard-failure combination the contract audit searches.
pub const MAX_FAILURE_SET: usize = 3;

/// Runs and caches explorations; equal configurations of one model are explored once.
pub struct Checker {
    bounds: Bounds,
    cache: HashMap<(ModelKind, ModelConfig), Rc<Exploration>>,
    states_explored: usize,
}

impl Checker {
    pub fn new(bounds: Bounds) -> Self {
        Self {
            bounds,
            cache: HashMap::new(),
            states_explored: 0,
        }
    }

    pub fn check(
        &mut self,
        kind: ModelKind,
        config: &ModelConfig,
    ) -> Result<Rc<Exploration>, ModelError> {
        let key = (kind, normalized(kind, config));
        if let Some(found) = self.cache.get(&key) {
            return Ok(Rc::clone(found));
        }
        let result = Rc::new(check_model(kind, &key.1, self.bounds)?);
        self.states_explored += result.states;
        self.cache.insert(key, Rc::clone(&result));
        Ok(result)
    }

    /// Distinct explorations run.
    pub fn explorations(&self) -> usize {
        self.cache.len()
    }

    /// States visited across all distinct explorations (the test cost).
    pub fn states_explored(&self) -> usize {
        self.states_explored
    }
}

/// The part of `config` that acts in model `kind`.
fn normalized(kind: ModelKind, config: &ModelConfig) -> ModelConfig {
    ModelConfig {
        disabled_guards: config
            .disabled_guards
            .iter()
            .copied()
            .filter(|guard| guard.model() == kind)
            .collect(),
        injections: config
            .injections
            .iter()
            .copied()
            .filter(|injection| injection.models().contains(&kind))
            .collect(),
        defects: config
            .defects
            .iter()
            .copied()
            .filter(|defect| defect.model() == kind)
            .collect(),
    }
}

/// A unit of failure in the contract: one guard, or a common dependency that fails every
/// guard depending on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "unit", content = "name", rename_all = "snake_case")]
pub enum ContractUnit {
    Guard(Guard),
    Dependency(Dependency),
}

impl ContractUnit {
    pub fn guards(self) -> Vec<Guard> {
        match self {
            Self::Guard(guard) => vec![guard],
            Self::Dependency(dependency) => dependency.dependents(),
        }
    }

    pub fn name(self) -> String {
        match self {
            Self::Guard(guard) => format!("{guard:?}"),
            Self::Dependency(dependency) => format!("{dependency:?}"),
        }
    }
}

/// Minimal failure sets per invariant.
pub type FailureSets = BTreeMap<InvariantId, Vec<BTreeSet<ContractUnit>>>;

/// The minimal sets of at most `max_size` units which, failed on top of `base`, violate
/// each invariant of model `kind`. An invariant `base` already violates gets the empty
/// set.
pub fn minimal_failure_sets(
    checker: &mut Checker,
    kind: ModelKind,
    base: &ModelConfig,
    units: &[ContractUnit],
    max_size: usize,
) -> Result<FailureSets, ModelError> {
    if units.len() > MAX_SEARCH_UNITS || max_size > MAX_SET_SIZE {
        return Err(ModelError::SearchBoundTooLarge {
            units: units.len(),
            max_size,
        });
    }
    let mut found: FailureSets = BTreeMap::new();
    for violation in &checker.check(kind, base)?.violations {
        found
            .entry(violation.invariant)
            .or_default()
            .push(BTreeSet::new());
    }
    for chosen in subsets(units.len(), max_size) {
        let candidate: BTreeSet<ContractUnit> = chosen.iter().map(|index| units[*index]).collect();
        let novel = kind.invariants().iter().any(|invariant| {
            found
                .get(invariant)
                .is_none_or(|sets| !sets.iter().any(|set| set.is_subset(&candidate)))
        });
        if !novel {
            continue;
        }
        let config = base
            .clone()
            .without_guards(candidate.iter().flat_map(|unit| unit.guards()));
        for violation in &checker.check(kind, &config)?.violations {
            let sets = found.entry(violation.invariant).or_default();
            if !sets.iter().any(|set| set.is_subset(&candidate)) {
                sets.push(candidate.clone());
            }
        }
    }
    Ok(found)
}

fn guard_sets(sets: &[BTreeSet<ContractUnit>]) -> Vec<BTreeSet<Guard>> {
    sets.iter()
        .map(|set| set.iter().flat_map(|unit| unit.guards()).collect())
        .collect()
}

/// A prohibited action of the contract (VM-N3 "for each prohibited action").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProhibitedAction {
    ForbiddenEgress,
    UnauthorizedDispatch,
    TicketMisuse,
    BlindRetry,
    PrematureAuthority,
    PostRevocationAuthorization,
    GenerationRevival,
    SnapshotResurrection,
    DirtyPoolSnapshot,
    BudgetOverrun,
    HostTargetSelection,
    ExecutorWidening,
    UnreviewedPromotion,
    CleanupEscape,
    WeakeningFallback,
}

impl ProhibitedAction {
    pub const ALL: [Self; 15] = [
        Self::ForbiddenEgress,
        Self::UnauthorizedDispatch,
        Self::TicketMisuse,
        Self::BlindRetry,
        Self::PrematureAuthority,
        Self::PostRevocationAuthorization,
        Self::GenerationRevival,
        Self::SnapshotResurrection,
        Self::DirtyPoolSnapshot,
        Self::BudgetOverrun,
        Self::HostTargetSelection,
        Self::ExecutorWidening,
        Self::UnreviewedPromotion,
        Self::CleanupEscape,
        Self::WeakeningFallback,
    ];

    /// The invariants that state the prohibition.
    pub const fn invariants(self) -> &'static [InvariantId] {
        use InvariantId::*;
        match self {
            Self::ForbiddenEgress => &[NoForbiddenEgress],
            Self::UnauthorizedDispatch => &[
                AuthorizationAndReservationPrecedeDispatch,
                FailedAuthorizationDenies,
            ],
            Self::TicketMisuse => &[TicketExactScope, EffectBindingFixed],
            Self::BlindRetry => &[UncertainOutcomeNotBlindlyRetried],
            Self::PrematureAuthority => &[NoAuthorityBeforeEnforcement, EntrypointAfterChecks],
            Self::PostRevocationAuthorization => &[NoAuthorizationAfterRevocationAck],
            Self::GenerationRevival => &[RevocationMonotonic, CleanupNeverRevivesGeneration],
            Self::SnapshotResurrection => &[
                SnapshotCannotRevive,
                RevokedIdentityNotResurrected,
                RestoredCloneUniqueGeneration,
                StaleApprovalsFail,
            ],
            Self::DirtyPoolSnapshot => &[OnlyGoldenSnapshotsPooled],
            Self::BudgetOverrun => &[ReleaseWithinCeiling, ReservationsWithinBudget],
            Self::HostTargetSelection => &[GuestCannotSelectHostTarget],
            Self::ExecutorWidening => &[ExecutorCannotWiden],
            Self::UnreviewedPromotion => &[PromotionAppliesReviewedBytes],
            Self::CleanupEscape => &[CleanupWithinManagedRoots],
            Self::WeakeningFallback => &[NoFallbackWeakening],
        }
    }

    /// The guards the contract declares for the action.
    pub const fn declared_guards(self) -> &'static [Guard] {
        use Guard::*;
        match self {
            Self::ForbiddenEgress => &[
                GuestEgressPolicy,
                HostFirewall,
                RelayChannelIdentity,
                RelayAddressCheck,
            ],
            // A replayed ticket after its authorization was withdrawn is stopped by the
            // binding, single use and reservation checks together.
            Self::UnauthorizedDispatch => &[
                FailClosedAuthorization,
                DispatchRequiresReservation,
                TicketBinding,
                SingleUseTicket,
            ],
            Self::TicketMisuse => &[TicketBinding, SingleUseTicket, DispatchRequiresReservation],
            Self::BlindRetry => &[NoBlindRetry],
            Self::PrematureAuthority => &[LaunchOrderCheck],
            // A redelivered activation after the acknowledgment is stopped by the
            // activation guards as well.
            Self::PostRevocationAuthorization => &[
                AuthoritativeEpochCheck,
                AckAfterEnforcerConfirms,
                DurableRevocation,
                LaunchOrderCheck,
                TransitionGenerationCheck,
            ],
            Self::GenerationRevival => &[
                TransitionGenerationCheck,
                DurableRevocation,
                LaunchOrderCheck,
            ],
            Self::SnapshotResurrection => &[
                DurableEpochOutsideSnapshot,
                TombstoneCheckOnRestore,
                UniqueGeneration,
                InvalidateApprovalsOnRestore,
                ApprovalBoundToGeneration,
                HostBudgetLedger,
            ],
            Self::DirtyPoolSnapshot => &[GoldenOnlyPool],
            Self::BudgetOverrun => &[
                CentralReservation,
                SenderEnforcesReservation,
                RetransmitFromAllowance,
            ],
            Self::HostTargetSelection => &[ClosedMessageSchema],
            Self::ExecutorWidening => &[
                ExecutorFixedOperation,
                CredentialSealed,
                ProviderScopedCredential,
            ],
            Self::UnreviewedPromotion => &[PromotionDigestRecheck, PromotionHostStaging],
            Self::CleanupEscape => &[HandleBasedCleanup],
            Self::WeakeningFallback => &[FallbackKeepsVmBoundary],
        }
    }

    pub fn model(self) -> ModelKind {
        self.invariants()
            .first()
            .map_or(ModelKind::Boundary, |invariant| invariant.model())
    }

    pub fn enforcement_points(self) -> BTreeSet<EnforcementPoint> {
        self.declared_guards()
            .iter()
            .map(|guard| guard.point())
            .collect()
    }
}

/// The contract audit of one prohibited action under the whole threat model.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ActionAudit {
    pub action: ProhibitedAction,
    pub enforcement_points: BTreeSet<EnforcementPoint>,
    /// Minimal sets of guard failures that violate each invariant.
    pub minimal_failures: BTreeMap<InvariantId, Vec<BTreeSet<Guard>>>,
    /// Guards whose failure alone violates an invariant.
    pub single_points: BTreeSet<Guard>,
    /// Declared guards in no minimal set: they are not counted as a wall (a guest-side
    /// guard against guest root, for example).
    pub not_counted: BTreeSet<Guard>,
    /// Guards in a minimal set that the contract does not declare for the action.
    pub undeclared: BTreeSet<Guard>,
}

/// Audits every prohibited action: which guards actually matter in the model, with
/// failure combinations of up to `max_size` guards.
pub fn audit_contract(
    checker: &mut Checker,
    max_size: usize,
) -> Result<Vec<ActionAudit>, ModelError> {
    let base = ModelConfig::threat_model();
    let mut per_model: BTreeMap<ModelKind, FailureSets> = BTreeMap::new();
    for kind in ModelKind::ALL {
        let units: Vec<ContractUnit> = kind.guards().into_iter().map(ContractUnit::Guard).collect();
        per_model.insert(
            kind,
            minimal_failure_sets(checker, kind, &base, &units, max_size)?,
        );
    }
    let mut audits = Vec::new();
    for action in ProhibitedAction::ALL {
        let sets = per_model.get(&action.model());
        let minimal_failures: BTreeMap<InvariantId, Vec<BTreeSet<Guard>>> = action
            .invariants()
            .iter()
            .map(|invariant| {
                let found = sets
                    .and_then(|sets| sets.get(invariant))
                    .map(|found| guard_sets(found))
                    .unwrap_or_default();
                (*invariant, found)
            })
            .collect();
        let required: BTreeSet<Guard> = minimal_failures
            .values()
            .flatten()
            .flatten()
            .copied()
            .collect();
        let single_points = minimal_failures
            .values()
            .flatten()
            .filter(|set| set.len() == 1)
            .flatten()
            .copied()
            .collect();
        let declared: BTreeSet<Guard> = action.declared_guards().iter().copied().collect();
        audits.push(ActionAudit {
            action,
            enforcement_points: action.enforcement_points(),
            not_counted: declared.difference(&required).copied().collect(),
            undeclared: required.difference(&declared).copied().collect(),
            single_points,
            minimal_failures,
        });
    }
    Ok(audits)
}

/// The faults VM-N3 names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NamedFault {
    GuestPolicyIgnored,
    StaleDnsAnswer,
    RelayIdentitySpoofed,
    FirewallRuleMissing,
    TicketReplayed,
    ApprovalPayloadChanged,
    SupervisorDelayed,
    SnapshotEpochRestored,
    OneBrokerCompromised,
}

impl NamedFault {
    pub const ALL: [Self; 9] = [
        Self::GuestPolicyIgnored,
        Self::StaleDnsAnswer,
        Self::RelayIdentitySpoofed,
        Self::FirewallRuleMissing,
        Self::TicketReplayed,
        Self::ApprovalPayloadChanged,
        Self::SupervisorDelayed,
        Self::SnapshotEpochRestored,
        Self::OneBrokerCompromised,
    ];
}

/// How a mutation was generated.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", content = "of", rename_all = "snake_case")]
pub enum MutationKind {
    Named(NamedFault),
    CommonCause(Dependency),
    SingleGuard(Guard),
}

/// One generated mutation: the configuration it runs under and the models it acts in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Mutation {
    pub kind: MutationKind,
    pub config: ModelConfig,
    pub models: Vec<ModelKind>,
}

impl Mutation {
    pub fn name(&self) -> String {
        match self.kind {
            MutationKind::Named(fault) => format!("{fault:?}"),
            MutationKind::CommonCause(dependency) => format!("common cause {dependency:?}"),
            MutationKind::SingleGuard(guard) => format!("guard off {guard:?}"),
        }
    }

    /// An attack input or condition on its own, with a hostile guest and every guard on;
    /// the verdicts name the guards that catch it.
    fn isolated(fault: NamedFault, injection: Injection) -> Self {
        Self {
            kind: MutationKind::Named(fault),
            config: ModelConfig::correct().with_injections([Injection::HostileGuest, injection]),
            models: injection.models().to_vec(),
        }
    }

    /// Guards failed under the whole threat model.
    fn failed_guards(kind: MutationKind, guards: Vec<Guard>) -> Self {
        let models: BTreeSet<ModelKind> = guards.iter().map(|guard| guard.model()).collect();
        Self {
            kind,
            config: ModelConfig::threat_model().without_guards(guards),
            models: models.into_iter().collect(),
        }
    }
}

/// The mutation for one named fault.
pub fn named_mutation(fault: NamedFault) -> Mutation {
    let named = MutationKind::Named(fault);
    match fault {
        NamedFault::GuestPolicyIgnored => {
            Mutation::failed_guards(named, vec![Guard::GuestEgressPolicy])
        }
        NamedFault::StaleDnsAnswer => Mutation::isolated(fault, Injection::StaleDnsAnswer),
        NamedFault::RelayIdentitySpoofed => {
            Mutation::isolated(fault, Injection::RelayIdentitySpoofed)
        }
        NamedFault::FirewallRuleMissing => {
            Mutation::failed_guards(named, vec![Guard::HostFirewall])
        }
        NamedFault::TicketReplayed => Mutation::isolated(fault, Injection::TicketReplayed),
        NamedFault::ApprovalPayloadChanged => {
            Mutation::isolated(fault, Injection::ApprovalPayloadChanged)
        }
        NamedFault::SupervisorDelayed => Mutation {
            kind: named,
            config: ModelConfig::threat_model().with_injections([Injection::SupervisorDelayed]),
            models: vec![ModelKind::Lifecycle],
        },
        NamedFault::SnapshotEpochRestored => {
            Mutation::isolated(fault, Injection::SnapshotEpochRestored)
        }
        NamedFault::OneBrokerCompromised => Mutation::failed_guards(
            named,
            Guard::ALL
                .into_iter()
                .filter(|guard| guard.point() == EnforcementPoint::Broker)
                .collect(),
        ),
    }
}

/// Every generated mutation: the named faults, one common-cause fault per dependency and
/// one single-guard failure per guard.
pub fn generate_mutations() -> Vec<Mutation> {
    let mut mutations: Vec<Mutation> = NamedFault::ALL.into_iter().map(named_mutation).collect();
    for dependency in Dependency::ALL {
        mutations.push(Mutation::failed_guards(
            MutationKind::CommonCause(dependency),
            dependency.dependents(),
        ));
    }
    for guard in Guard::ALL {
        mutations.push(Mutation::failed_guards(
            MutationKind::SingleGuard(guard),
            vec![guard],
        ));
    }
    mutations
}

/// An enforcement assumption whose absence explains a counterexample.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MissingAssumption {
    pub guard: Option<Guard>,
    pub point: Option<EnforcementPoint>,
    pub assumption: String,
}

impl MissingAssumption {
    fn of_guard(guard: Guard) -> Self {
        Self {
            guard: Some(guard),
            point: Some(guard.point()),
            assumption: guard.assumption().to_string(),
        }
    }
}

/// A shortest counterexample with the missing enforcement assumption; serialized, it is
/// the reproducible integration scenario VM-W50 exports.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Counterexample {
    pub model: ModelKind,
    pub invariant: InvariantId,
    pub statement: &'static str,
    pub mutation: String,
    pub config: ModelConfig,
    pub trace: Trace,
    /// Minimal sets of the mutation's own failures that suffice for the violation; the
    /// assumptions of one set are missing together.
    pub missing: Vec<Vec<MissingAssumption>>,
    pub scope: &'static str,
}

impl Counterexample {
    pub fn to_json(&self) -> Result<String, ModelError> {
        serde_json::to_string_pretty(self).map_err(|_| ModelError::Encoding)
    }

    pub fn digest(&self) -> Result<Digest, ModelError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ModelError::Encoding)?;
        Ok(DigestBuilder::new(COUNTEREXAMPLE_DOMAIN)
            .bytes(&bytes)
            .finish())
    }
}

/// The shortest counterexample for `invariant` of model `kind` under `config`, if any.
pub fn counterexample(
    checker: &mut Checker,
    kind: ModelKind,
    config: &ModelConfig,
    invariant: InvariantId,
    mutation: &str,
) -> Result<Option<Counterexample>, ModelError> {
    let result = checker.check(kind, config)?;
    let Some(violation) = result.violation(invariant) else {
        return Ok(None);
    };
    Ok(Some(Counterexample {
        model: kind,
        invariant,
        statement: invariant.statement(),
        mutation: mutation.to_string(),
        config: normalized(kind, config),
        trace: violation.trace.clone(),
        missing: missing_assumptions(checker, kind, config, invariant)?,
        scope: MODEL_SCOPE,
    }))
}

fn missing_assumptions(
    checker: &mut Checker,
    kind: ModelKind,
    config: &ModelConfig,
    invariant: InvariantId,
) -> Result<Vec<Vec<MissingAssumption>>, ModelError> {
    let disabled: Vec<Guard> = config
        .disabled_guards
        .iter()
        .copied()
        .filter(|guard| guard.model() == kind)
        .collect();
    let mut missing = Vec::new();
    if !disabled.is_empty() {
        let mut restored = config.clone();
        restored
            .disabled_guards
            .retain(|guard| !disabled.contains(guard));
        let units: Vec<ContractUnit> = disabled.iter().copied().map(ContractUnit::Guard).collect();
        let max_size = units.len().min(MAX_FAILURE_SET);
        let sets = minimal_failure_sets(checker, kind, &restored, &units, max_size)?;
        for set in sets.get(&invariant).into_iter().flatten() {
            if !set.is_empty() {
                missing.push(
                    set.iter()
                        .flat_map(|unit| unit.guards())
                        .map(MissingAssumption::of_guard)
                        .collect(),
                );
            }
        }
    }
    if missing.is_empty() {
        let defects: Vec<Defect> = config
            .defects
            .iter()
            .copied()
            .filter(|defect| defect.model() == kind)
            .collect();
        if defects.is_empty() {
            missing.push(vec![MissingAssumption {
                guard: None,
                point: None,
                assumption: format!(
                    "an enforcement point that stops {:?}; the model has none",
                    config.injections
                ),
            }]);
        } else {
            missing.push(
                defects
                    .iter()
                    .map(|defect| MissingAssumption {
                        guard: Some(defect.guard()),
                        point: Some(defect.guard().point()),
                        assumption: format!(
                            "{} (seeded defect {defect:?} breaks it)",
                            defect.guard().assumption()
                        ),
                    })
                    .collect(),
            );
        }
    }
    Ok(missing)
}

/// The verdict on one invariant under one mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "verdict", rename_all = "snake_case")]
pub enum Verdict {
    Violated {
        counterexample: Counterexample,
    },
    /// The invariant held; `contained_by` lists the minimal sets of further guard failures,
    /// of at most `searched` guards, that would break it. An empty list after a search
    /// means the mutation does not exercise the invariant.
    Holds {
        contained_by: Vec<BTreeSet<Guard>>,
        searched: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct InvariantVerdict {
    pub invariant: InvariantId,
    pub verdict: Verdict,
}

/// Every verdict of one mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MutationReport {
    pub mutation: String,
    pub kind: MutationKind,
    pub verdicts: Vec<InvariantVerdict>,
}

impl MutationReport {
    pub fn counterexamples(&self) -> Vec<&Counterexample> {
        self.verdicts
            .iter()
            .filter_map(|verdict| match &verdict.verdict {
                Verdict::Violated { counterexample } => Some(counterexample),
                Verdict::Holds { .. } => None,
            })
            .collect()
    }

    /// Every declared invariant held under the mutation.
    pub fn contained(&self) -> bool {
        self.counterexamples().is_empty()
    }

    pub fn verdict(&self, invariant: InvariantId) -> Option<&Verdict> {
        self.verdicts
            .iter()
            .find(|verdict| verdict.invariant == invariant)
            .map(|verdict| &verdict.verdict)
    }
}

/// Checks every invariant of every model the mutation acts in. With
/// `containment_depth > 0`, a held invariant also gets the minimal sets of up to that
/// many further guard failures that would break it.
pub fn check_mutation(
    checker: &mut Checker,
    mutation: &Mutation,
    containment_depth: usize,
) -> Result<MutationReport, ModelError> {
    let name = mutation.name();
    let mut verdicts = Vec::new();
    for kind in &mutation.models {
        let containment = if containment_depth > 0 {
            let units: Vec<ContractUnit> = kind
                .guards()
                .into_iter()
                .filter(|guard| !mutation.config.disabled_guards.contains(guard))
                .map(ContractUnit::Guard)
                .collect();
            minimal_failure_sets(checker, *kind, &mutation.config, &units, containment_depth)?
        } else {
            BTreeMap::new()
        };
        for invariant in kind.invariants() {
            let verdict = match counterexample(checker, *kind, &mutation.config, *invariant, &name)?
            {
                Some(counterexample) => Verdict::Violated { counterexample },
                None => Verdict::Holds {
                    contained_by: containment
                        .get(invariant)
                        .map(|sets| guard_sets(sets))
                        .unwrap_or_default(),
                    searched: containment_depth,
                },
            };
            verdicts.push(InvariantVerdict {
                invariant: *invariant,
                verdict,
            });
        }
    }
    Ok(MutationReport {
        mutation: name,
        kind: mutation.kind,
        verdicts,
    })
}

/// Whether an invariant survived a failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Containment {
    Contained,
    Breached,
}

/// The model's prediction for one failure and one invariant (VM-P44).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuardFailurePrediction {
    pub failure: ContractUnit,
    pub invariant: InvariantId,
    pub predicted: Containment,
    pub counterexample: Option<Counterexample>,
}

/// Predictions for disabling one guard at a time and for each common-cause failure,
/// under the whole threat model.
pub fn predict_guard_failures(
    checker: &mut Checker,
) -> Result<Vec<GuardFailurePrediction>, ModelError> {
    let failures: Vec<ContractUnit> = Guard::ALL
        .into_iter()
        .map(ContractUnit::Guard)
        .chain(Dependency::ALL.into_iter().map(ContractUnit::Dependency))
        .collect();
    let mut predictions = Vec::new();
    for failure in failures {
        let guards = failure.guards();
        let config = ModelConfig::threat_model().without_guards(guards.iter().copied());
        let models: BTreeSet<ModelKind> = guards.iter().map(|guard| guard.model()).collect();
        for kind in models {
            for invariant in kind.invariants() {
                let found = counterexample(checker, kind, &config, *invariant, &failure.name())?;
                predictions.push(GuardFailurePrediction {
                    failure,
                    invariant: *invariant,
                    predicted: if found.is_some() {
                        Containment::Breached
                    } else {
                        Containment::Contained
                    },
                    counterexample: found,
                });
            }
        }
    }
    Ok(predictions)
}

/// An observed result of disabling a guard in a test harness (VM-P44).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ContainmentObservation {
    pub failure: ContractUnit,
    pub invariant: InvariantId,
    pub observed: Containment,
    pub evidence: AssuranceObservation,
}

/// How an observation relates to the prediction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Agreement {
    Agrees,
    /// Observed breach the model predicted contained: the model omits the actual
    /// enforcement boundary.
    BreachNotPredicted,
    /// Observed containment where the model predicted a breach: an unmodelled guard or a
    /// blind spot of the test.
    ContainmentNotPredicted,
    NotObserved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PredictionComparison {
    pub failure: ContractUnit,
    pub invariant: InvariantId,
    pub predicted: Containment,
    pub observed: Option<Containment>,
    pub agreement: Agreement,
    /// Whether the observation counts at all (VM-P50).
    pub assurance: AssuranceStatus,
    /// The stop/narrow rule: no system verification is claimed, the generated tests stay
    /// scoped regression coverage while the model improves.
    pub narrow_claim: bool,
}

/// Compares predictions with observations; a prediction with no observation is "not
/// tested", never a pass.
pub fn compare_predictions(
    predictions: &[GuardFailurePrediction],
    observations: &[ContainmentObservation],
    requirement: &AssuranceRequirement,
    now: MonotonicTime,
    session: ClockSession,
) -> Vec<PredictionComparison> {
    predictions
        .iter()
        .map(|prediction| {
            let observation = observations.iter().find(|observation| {
                observation.failure == prediction.failure
                    && observation.invariant == prediction.invariant
            });
            let (observed, agreement, assurance) = match observation {
                None => (
                    None,
                    Agreement::NotObserved,
                    AssuranceStatus::NotTested {
                        reason: NotAssurance::NotRun,
                    },
                ),
                Some(observation) => {
                    let agreement = match (prediction.predicted, observation.observed) {
                        (predicted, observed) if predicted == observed => Agreement::Agrees,
                        (Containment::Contained, Containment::Breached) => {
                            Agreement::BreachNotPredicted
                        }
                        _ => Agreement::ContainmentNotPredicted,
                    };
                    (
                        Some(observation.observed),
                        agreement,
                        assess(&observation.evidence, requirement, now, session),
                    )
                }
            };
            PredictionComparison {
                failure: prediction.failure,
                invariant: prediction.invariant,
                predicted: prediction.predicted,
                observed,
                agreement,
                assurance,
                narrow_claim: agreement == Agreement::BreachNotPredicted,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::SourceClass;
    use crate::foundation::report::RunSubstrate;
    use crate::sandbox_contract::models::assurance::TestExecution;
    use crate::sandbox_contract::models::attack_graph::{AttackGraph, FailureUnit};
    use std::time::Duration;

    fn checker() -> Checker {
        Checker::new(Bounds::DEFAULT)
    }

    fn guards(list: &[Guard]) -> BTreeSet<Guard> {
        list.iter().copied().collect()
    }

    fn contained_by(report: &MutationReport, invariant: InvariantId) -> Vec<BTreeSet<Guard>> {
        match report.verdict(invariant) {
            Some(Verdict::Holds { contained_by, .. }) => contained_by.clone(),
            other => panic!("{invariant:?} did not hold: {other:?}"),
        }
    }

    #[test]
    fn every_invariant_belongs_to_one_prohibited_action() {
        for invariant in InvariantId::ALL {
            let actions = ProhibitedAction::ALL
                .into_iter()
                .filter(|action| action.invariants().contains(&invariant))
                .count();
            assert_eq!(actions, 1, "{invariant:?}");
        }
        for action in ProhibitedAction::ALL {
            for guard in action.declared_guards() {
                assert_eq!(guard.model(), action.model(), "{action:?} {guard:?}");
            }
            assert!(!action.enforcement_points().is_empty());
        }
    }

    #[test]
    fn the_contract_audit_matches_the_declared_guards() {
        let mut checker = checker();
        let audits = audit_contract(&mut checker, MAX_FAILURE_SET).unwrap();
        for audit in &audits {
            assert!(
                audit.undeclared.is_empty(),
                "{:?}: {:?}",
                audit.action,
                audit.undeclared
            );
            let expected_not_counted = if audit.action == ProhibitedAction::ForbiddenEgress {
                // The guest-side policy is no wall under guest root.
                guards(&[Guard::GuestEgressPolicy])
            } else {
                BTreeSet::new()
            };
            assert_eq!(
                audit.not_counted, expected_not_counted,
                "{:?}",
                audit.action
            );
        }
        let revocation = audits
            .iter()
            .find(|audit| audit.action == ProhibitedAction::PostRevocationAuthorization)
            .unwrap();
        // A crash that loses the revocation re-activates authority after the
        // acknowledgment; the two revocation guards back each other up; and a redelivered
        // activation needs both activation guards and the authoritative check to fail.
        assert_eq!(
            revocation.minimal_failures[&InvariantId::NoAuthorizationAfterRevocationAck],
            vec![
                guards(&[Guard::DurableRevocation]),
                guards(&[
                    Guard::AuthoritativeEpochCheck,
                    Guard::AckAfterEnforcerConfirms
                ]),
                guards(&[
                    Guard::LaunchOrderCheck,
                    Guard::AuthoritativeEpochCheck,
                    Guard::TransitionGenerationCheck
                ]),
            ]
        );
        assert_eq!(
            revocation.single_points,
            guards(&[Guard::DurableRevocation])
        );
    }

    #[test]
    fn the_generator_produces_named_common_cause_and_single_guard_faults() {
        let mutations = generate_mutations();
        assert_eq!(mutations.len(), 9 + 5 + Guard::ALL.len());
        let broker = named_mutation(NamedFault::OneBrokerCompromised);
        assert_eq!(
            broker.config.disabled_guards,
            guards(&[
                Guard::TicketBinding,
                Guard::SingleUseTicket,
                Guard::NoBlindRetry,
                Guard::ExecutorFixedOperation,
                Guard::CredentialSealed,
            ])
        );
        assert_eq!(broker.models, vec![ModelKind::Effect, ModelKind::Boundary]);
        assert_eq!(mutations[9].name(), "common cause SharedParser");
    }

    #[test]
    fn each_named_mutation_is_caught_or_yields_its_counterexample_and_assumption() {
        let mut checker = checker();
        for mutation in generate_mutations() {
            let report = check_mutation(&mut checker, &mutation, 0).unwrap();
            assert!(!report.verdicts.is_empty(), "{}", report.mutation);
            for counterexample in report.counterexamples() {
                assert!(!counterexample.trace.steps.is_empty());
                assert!(!counterexample.missing.is_empty(), "{}", report.mutation);
                assert!(counterexample
                    .missing
                    .iter()
                    .all(|set| !set.is_empty() && set.iter().all(|m| !m.assumption.is_empty())));
                assert_eq!(counterexample.scope, MODEL_SCOPE);
            }
        }
    }

    #[test]
    fn attack_inputs_are_caught_by_the_guards_the_contract_names() {
        let mut checker = checker();
        let mut report = |fault| check_mutation(&mut checker, &named_mutation(fault), 2).unwrap();
        let stale = report(NamedFault::StaleDnsAnswer);
        assert!(stale.contained());
        assert!(contained_by(&stale, InvariantId::NoForbiddenEgress)
            .contains(&guards(&[Guard::RelayAddressCheck])));
        let spoofed = report(NamedFault::RelayIdentitySpoofed);
        assert!(spoofed.contained());
        assert!(contained_by(&spoofed, InvariantId::TicketExactScope)
            .contains(&guards(&[Guard::TicketBinding])));
        assert!(contained_by(&spoofed, InvariantId::NoForbiddenEgress)
            .contains(&guards(&[Guard::RelayChannelIdentity])));
        let replayed = report(NamedFault::TicketReplayed);
        // Replay needs single use and the reservation check to fail together; the binding
        // alone also matters, since a revoked epoch's ticket would otherwise dispatch.
        assert_eq!(
            contained_by(&replayed, InvariantId::TicketExactScope),
            vec![
                guards(&[Guard::TicketBinding]),
                guards(&[Guard::SingleUseTicket, Guard::DispatchRequiresReservation])
            ]
        );

        let payload = report(NamedFault::ApprovalPayloadChanged);
        assert_eq!(
            contained_by(&payload, InvariantId::EffectBindingFixed),
            vec![guards(&[Guard::TicketBinding])]
        );
        let restored = report(NamedFault::SnapshotEpochRestored);
        assert_eq!(
            contained_by(&restored, InvariantId::RevokedIdentityNotResurrected),
            vec![guards(&[
                Guard::DurableEpochOutsideSnapshot,
                Guard::TombstoneCheckOnRestore
            ])]
        );
        let delayed = report(NamedFault::SupervisorDelayed);
        assert!(delayed.contained());
        assert!(
            contained_by(&delayed, InvariantId::NoAuthorizationAfterRevocationAck).contains(
                &guards(&[
                    Guard::AuthoritativeEpochCheck,
                    Guard::AckAfterEnforcerConfirms
                ])
            )
        );
        // The guest-side policy was never a wall: ignoring it changes nothing.
        let ignored = report(NamedFault::GuestPolicyIgnored);
        assert!(ignored.contained());
    }

    #[test]
    fn guard_failures_yield_shortest_counterexamples_with_the_missing_assumption() {
        let mut checker = checker();
        let firewall = check_mutation(
            &mut checker,
            &named_mutation(NamedFault::FirewallRuleMissing),
            0,
        )
        .unwrap();
        let counterexample = firewall.counterexamples()[0].clone();
        assert_eq!(
            counterexample.trace.steps,
            vec!["send other-tenant name directly"]
        );
        assert_eq!(counterexample.missing.len(), 1);
        assert_eq!(
            counterexample.missing[0][0].guard,
            Some(Guard::HostFirewall)
        );
        assert_eq!(
            counterexample.missing[0][0].point,
            Some(EnforcementPoint::HostPerimeter)
        );
        // The export is reproducible: same digest twice, different for another fault.
        assert_eq!(
            counterexample.digest().unwrap(),
            counterexample.digest().unwrap()
        );
        assert!(counterexample
            .to_json()
            .unwrap()
            .contains("\"invariant\": \"no_forbidden_egress\""));
        let broker = check_mutation(
            &mut checker,
            &named_mutation(NamedFault::OneBrokerCompromised),
            0,
        )
        .unwrap();
        let scope = broker
            .counterexamples()
            .into_iter()
            .find(|c| c.invariant == InvariantId::TicketExactScope)
            .cloned()
            .unwrap();
        assert_eq!(
            scope.missing,
            vec![vec![MissingAssumption::of_guard(Guard::TicketBinding)]]
        );
        assert_ne!(scope.digest().unwrap(), counterexample.digest().unwrap());
        // A compromised broker exposes its credential, but the provider-scoped
        // credential still contains widening beyond the fixed operation.
        let credential = broker
            .counterexamples()
            .into_iter()
            .find(|c| c.invariant == InvariantId::ExecutorCannotWiden)
            .cloned()
            .unwrap();
        assert_eq!(
            credential.trace.steps.last().map(String::as_str),
            Some("request the credential")
        );
        assert!(matches!(
            broker.verdict(InvariantId::FailedAuthorizationDenies),
            Some(Verdict::Holds { .. })
        ));
    }

    #[test]
    fn common_cause_faults_defeat_several_walls_at_once() {
        let mut checker = checker();
        let policy = check_mutation(
            &mut checker,
            &Mutation::failed_guards(
                MutationKind::CommonCause(Dependency::PolicyError),
                Dependency::PolicyError.dependents(),
            ),
            0,
        )
        .unwrap();
        let egress = policy
            .counterexamples()
            .into_iter()
            .find(|c| c.invariant == InvariantId::NoForbiddenEgress)
            .cloned()
            .unwrap();
        // Both the firewall and the relay address check fall to one policy error.
        let missing: Vec<Option<Guard>> = egress.missing.iter().map(|set| set[0].guard).collect();
        assert_eq!(
            missing,
            vec![Some(Guard::HostFirewall), Some(Guard::RelayAddressCheck)]
        );
        let fallback = policy.verdict(InvariantId::NoFallbackWeakening).unwrap();
        assert!(matches!(fallback, Verdict::Violated { .. }));
    }

    #[test]
    fn the_attack_graph_and_the_perimeter_model_agree_on_minimal_failures() {
        let graph = AttackGraph::egress_reference().unwrap();
        let from_graph: BTreeSet<Vec<String>> = graph
            .minimal_enabling_sets(2)
            .unwrap()
            .into_iter()
            .map(|set| {
                set.units
                    .iter()
                    .map(|unit| match unit {
                        FailureUnit::Control(id) => graph.control(*id).unwrap().name.clone(),
                        FailureUnit::Dependency(dependency) => format!("{dependency:?}"),
                    })
                    .collect()
            })
            .collect();
        let mut units: Vec<ContractUnit> = ModelKind::Egress
            .guards()
            .into_iter()
            .map(ContractUnit::Guard)
            .collect();
        units.extend(Dependency::ALL.into_iter().map(ContractUnit::Dependency));
        let mut checker = checker();
        let sets = minimal_failure_sets(
            &mut checker,
            ModelKind::Egress,
            &ModelConfig::threat_model(),
            &units,
            2,
        )
        .unwrap();
        let from_model: BTreeSet<Vec<String>> = sets[&InvariantId::NoForbiddenEgress]
            .iter()
            .map(|set| set.iter().map(|unit| unit.name()).collect())
            .collect();
        assert_eq!(from_graph, from_model);
        assert_eq!(from_model.len(), 7);
    }

    #[test]
    fn single_guard_predictions_separate_single_points_from_redundant_guards() {
        let mut checker = checker();
        let predictions = predict_guard_failures(&mut checker).unwrap();
        let breached: BTreeSet<Guard> = predictions
            .iter()
            .filter(|p| p.predicted == Containment::Breached)
            .filter_map(|p| match p.failure {
                ContractUnit::Guard(guard) => Some(guard),
                ContractUnit::Dependency(_) => None,
            })
            .collect();
        let redundant = guards(&[
            Guard::SingleUseTicket,
            Guard::AuthoritativeEpochCheck,
            Guard::AckAfterEnforcerConfirms,
            Guard::DurableEpochOutsideSnapshot,
            Guard::TombstoneCheckOnRestore,
            Guard::InvalidateApprovalsOnRestore,
            Guard::ApprovalBoundToGeneration,
            Guard::GuestEgressPolicy,
            Guard::ExecutorFixedOperation,
            Guard::ProviderScopedCredential,
            Guard::PromotionDigestRecheck,
            Guard::PromotionHostStaging,
        ]);
        let all: BTreeSet<Guard> = Guard::ALL.into_iter().collect();
        assert_eq!(breached, all.difference(&redundant).copied().collect());
        // Every common-cause failure breaches something; the update key breaks every model.
        for dependency in Dependency::ALL {
            assert!(predictions
                .iter()
                .any(|p| p.failure == ContractUnit::Dependency(dependency)
                    && p.predicted == Containment::Breached));
        }
        let update_models: BTreeSet<ModelKind> = predictions
            .iter()
            .filter(|p| {
                p.failure == ContractUnit::Dependency(Dependency::UpdateKey)
                    && p.predicted == Containment::Breached
            })
            .map(|p| p.invariant.model())
            .collect();
        assert_eq!(update_models.len(), ModelKind::ALL.len());
    }

    #[test]
    fn observations_are_compared_with_predictions_and_fakes_never_count() {
        let mut checker = checker();
        let predictions = predict_guard_failures(&mut checker).unwrap();
        let session = ClockSession::from_uuid(uuid::Uuid::from_u128(3));
        let fake = || AssuranceObservation {
            source: SourceClass::HostProbe,
            execution: TestExecution::Passed,
            substrate: RunSubstrate::FakeTimeControlled,
            clock: session,
            observed_at: MonotonicTime::ZERO,
            fresh_for: Duration::from_secs(600),
        };
        let observations = vec![
            // Agrees with the prediction, but only on a fake.
            ContainmentObservation {
                failure: ContractUnit::Guard(Guard::HostFirewall),
                invariant: InvariantId::NoForbiddenEgress,
                observed: Containment::Breached,
                evidence: fake(),
            },
            // A breach the model predicted contained.
            ContainmentObservation {
                failure: ContractUnit::Guard(Guard::SingleUseTicket),
                invariant: InvariantId::TicketExactScope,
                observed: Containment::Breached,
                evidence: fake(),
            },
        ];
        let requirement = AssuranceRequirement::host_enforcement(Duration::from_secs(300));
        let rows = compare_predictions(
            &predictions,
            &observations,
            &requirement,
            MonotonicTime::ZERO,
            session,
        );
        let row = |guard, invariant| {
            rows.iter()
                .find(|r| r.failure == ContractUnit::Guard(guard) && r.invariant == invariant)
                .unwrap()
        };
        let firewall = row(Guard::HostFirewall, InvariantId::NoForbiddenEgress);
        assert_eq!(firewall.agreement, Agreement::Agrees);
        assert!(!firewall.assurance.is_green());
        let replay = row(Guard::SingleUseTicket, InvariantId::TicketExactScope);
        assert_eq!(replay.agreement, Agreement::BreachNotPredicted);
        assert!(replay.narrow_claim);
        let unobserved = row(Guard::CentralReservation, InvariantId::ReleaseWithinCeiling);
        assert_eq!(unobserved.agreement, Agreement::NotObserved);
        assert!(matches!(
            unobserved.assurance,
            AssuranceStatus::NotTested { .. }
        ));
        assert!(rows.iter().all(|r| !r.assurance.is_green()));
    }

    #[test]
    fn the_checker_reuses_equal_configurations() {
        let mut checker = checker();
        let config = ModelConfig::threat_model();
        checker.check(ModelKind::Effect, &config).unwrap();
        // Guards and injections of other models do not change the effect model.
        let other = config.clone().without_guards([Guard::HostFirewall]);
        checker.check(ModelKind::Effect, &other).unwrap();
        assert_eq!(checker.explorations(), 1);
        assert!(minimal_failure_sets(
            &mut checker,
            ModelKind::Effect,
            &config,
            &[ContractUnit::Guard(Guard::TicketBinding)],
            MAX_SET_SIZE + 1
        )
        .is_err());
    }
}
