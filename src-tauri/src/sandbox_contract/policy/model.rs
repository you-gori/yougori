//! §12.3 model 1 by exhaustive small-state enumeration (VM part line 2658): allowed
//! actions are the intersection of independent authority limits, required protections
//! accumulate, and an unmet required capability causes refusal.
//!
//! Bounds. Tuple patterns: t0 = (main, read, file grant "inputs", analysis, every
//! epoch), t1 = t0's action at epoch 1 only, t2 = (main, release, channel "results",
//! publication, every epoch), t3 = (build, connect, route "registry", fetch, every
//! epoch). Ceilings and requests range over every subset of {t0, t2, t3} (only a
//! delegation may bind an epoch), dependencies over every subset of the request,
//! delegations over every subset of {t0, t1, t2, t3}. Product requirements are
//! `vm_sandbox` plus every subset of {`hardware_hypervisor_available`,
//! `dedicated_physical_host`}; workload requirements and the satisfied evidence range
//! over every subset of those three. That is 32 × 216 × 16 layer combinations and
//! 884,736 launch decisions. The specification is a brute-force denotation over the
//! generations {epoch 1, epoch 2, any other epoch}, written independently of the code.
//!
//! Further enumerations: runtime authorization of every universe action for both roles
//! at epochs 1 and 2 in every allowed state with only `vm_sandbox` required; every
//! contract constraint over every subset of eight single-operation tuples, with and
//! without lifetime budgets; approval accumulation over every subset of two rules per
//! layer; budget minima over three keys with values {absent, 1, 2} per layer.
//!
//! Assumptions: layers are validated; evidence is abstracted to one satisfied or
//! unsatisfied verdict per host predicate (CORE-01 evaluation is tested elsewhere). The
//! result proves this code and model within these bounds only (§12.3).

use std::collections::BTreeSet;
use std::time::Duration;

use super::evidence::{EvidenceReport, LaunchTargets, PredicateOutcome, PredicateVerdict};
use super::plan::decide;
use super::*;
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::{
    Backend, BackendRelease, ConfigurationFingerprint, HypervisorKind, HypervisorSubject,
    ProbeRegistry, RuntimeSubject, SourceClass, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
    PolicyEpoch, SandboxBootGeneration, TenantId,
};

/// How many states each enumeration covered.
#[derive(Debug, Default)]
pub(super) struct ModelReport {
    pub layer_combinations: u64,
    pub launch_decisions: u64,
    pub allowed_launches: u64,
    pub refused_for_authority_and_evidence: u64,
    pub authorizations: u64,
    pub contract_checks: u64,
    pub approval_states: u64,
    pub budget_states: u64,
}

type Outcome<T> = Result<T, String>;

const EPOCH_ONE: AuthorizationEpoch = AuthorizationEpoch::FIRST;
const EPOCH_TWO: AuthorizationEpoch = AuthorizationEpoch::new(2);
const ALL_GENERATIONS: u16 = 0b111;

fn named<T, E: std::fmt::Debug>(made: Result<T, E>) -> Outcome<T> {
    made.map_err(|error| format!("fixture name refused: {error:?}"))
}

fn tuple(
    role: &str,
    operation: Operation,
    kind: ResourceKind,
    name: &str,
    phase: Phase,
    generation: GenerationScope,
) -> Outcome<PermissionTuple> {
    Ok(PermissionTuple {
        principal: named(Principal::role(role))?,
        operation,
        resource: named(ResourceRef::new(kind, name))?,
        context: Context { phase },
        generation,
    })
}

/// A pattern and its denotation: three action slots of three generation bits each.
struct Pattern {
    tuple: PermissionTuple,
    denotation: u16,
}

fn patterns() -> Outcome<Vec<Pattern>> {
    let every = GenerationScope::EveryGeneration;
    let epoch_one = GenerationScope::Authorization { epoch: EPOCH_ONE };
    let read = |generation| {
        tuple(
            "main",
            Operation::FileRead,
            ResourceKind::FileGrant,
            "inputs",
            Phase::Analysis,
            generation,
        )
    };
    Ok(vec![
        Pattern {
            tuple: read(every)?,
            denotation: ALL_GENERATIONS,
        },
        Pattern {
            tuple: read(epoch_one)?,
            denotation: 0b001,
        },
        Pattern {
            tuple: tuple(
                "main",
                Operation::Release,
                ResourceKind::ReleaseChannel,
                "results",
                Phase::Publication,
                every,
            )?,
            denotation: ALL_GENERATIONS << 3,
        },
        Pattern {
            tuple: tuple(
                "build",
                Operation::TransportConnect,
                ResourceKind::Route,
                "registry",
                Phase::Fetch,
                every,
            )?,
            denotation: ALL_GENERATIONS << 6,
        },
    ])
}

/// The denotation of a set the code produced, read back through the pattern table.
fn denotation_of(set: &PermissionSet, patterns: &[Pattern]) -> Outcome<u16> {
    let mut bits = 0;
    for item in set.iter() {
        let slot = patterns
            .iter()
            .position(|pattern| pattern.tuple.action() == item.action())
            .ok_or_else(|| format!("the code produced a tuple outside the universe: {item}"))?;
        let base = patterns[slot].denotation.trailing_zeros();
        let generations = match item.generation {
            GenerationScope::EveryGeneration => ALL_GENERATIONS,
            GenerationScope::Authorization { epoch } if epoch == EPOCH_ONE => 0b001,
            GenerationScope::Authorization { epoch } if epoch == EPOCH_TWO => 0b010,
            GenerationScope::Authorization { .. } => {
                return Err(format!("the code produced an unknown epoch: {item}"))
            }
        };
        bits |= generations << base;
    }
    Ok(bits)
}

fn subset<T: Clone>(items: &[T], mask: usize) -> Vec<T> {
    items
        .iter()
        .enumerate()
        .filter(|(index, _)| mask & (1 << index) != 0)
        .map(|(_, item)| item.clone())
        .collect()
}

struct Product {
    layer: ProductPolicy,
    denotation: u16,
    requirements: BTreeSet<SecurityPredicate>,
    only_vm: bool,
}

struct Request {
    layer: WorkloadRequest,
    denotation: u16,
    requested: Vec<usize>,
    dependencies: Vec<usize>,
    requirements: BTreeSet<SecurityPredicate>,
}

struct Grant {
    layer: Delegation,
    denotation: u16,
}

const PREDICATES: [SecurityPredicate; 3] = [
    SecurityPredicate::VmSandbox,
    SecurityPredicate::HardwareHypervisorAvailable,
    SecurityPredicate::DedicatedPhysicalHost,
];

fn source() -> Outcome<RequestSource> {
    Ok(RequestSource {
        kind: SourceKind::Template,
        name: named(SourceName::new("model"))?,
    })
}

fn products(patterns: &[Pattern]) -> Outcome<Vec<Product>> {
    let every_slots = [0usize, 2, 3];
    let mut products = Vec::new();
    for ceiling_mask in 0..8 {
        let slots = subset(&every_slots, ceiling_mask);
        for extra_mask in 0..4 {
            let mut requirements = BTreeSet::from([SecurityPredicate::VmSandbox]);
            requirements.extend(subset(&PREDICATES[1..], extra_mask));
            let draft = ProductPolicyDraft {
                policy_epoch: PolicyEpoch::FIRST,
                ceiling: slots
                    .iter()
                    .map(|slot| patterns[*slot].tuple.clone())
                    .collect(),
                requirements: requirements.iter().copied().collect(),
                approvals: Vec::new(),
                budgets: BudgetSet::vm_d12_task_defaults().into(),
            };
            let layer = Validator::product(&draft).map_err(|refusal| refusal.to_string())?;
            products.push(Product {
                layer,
                denotation: slots
                    .iter()
                    .fold(0, |bits, slot| bits | patterns[*slot].denotation),
                requirements,
                only_vm: extra_mask == 0,
            });
        }
    }
    Ok(products)
}

fn requests(patterns: &[Pattern]) -> Outcome<Vec<Request>> {
    let every_slots = [0usize, 2, 3];
    let mut requests = Vec::new();
    for requested_mask in 0..8 {
        let requested = subset(&every_slots, requested_mask);
        for dependency_mask in 0..(1 << requested.len()) {
            let dependencies = subset(&requested, dependency_mask);
            for requirement_mask in 0..8 {
                let requirements: BTreeSet<SecurityPredicate> =
                    subset(&PREDICATES, requirement_mask).into_iter().collect();
                let document = RequestDocument {
                    schema_version: CONTRACT_SCHEMA_VERSION,
                    source: source()?,
                    requested: requested
                        .iter()
                        .map(|slot| patterns[*slot].tuple.clone())
                        .collect(),
                    dependencies: dependencies
                        .iter()
                        .map(|slot| patterns[*slot].tuple.clone())
                        .collect(),
                    requires: requirements
                        .iter()
                        .map(|predicate| predicate.name().to_owned())
                        .collect(),
                    legacy_tier: None,
                    approvals: Vec::new(),
                    budgets: Vec::new(),
                };
                let layer = Validator::request(&document).map_err(|refusal| refusal.to_string())?;
                requests.push(Request {
                    layer,
                    denotation: requested
                        .iter()
                        .fold(0, |bits, slot| bits | patterns[*slot].denotation),
                    requested: requested.clone(),
                    dependencies: dependencies.clone(),
                    requirements,
                });
            }
        }
    }
    Ok(requests)
}

fn grants(patterns: &[Pattern]) -> Outcome<Vec<Grant>> {
    let slots = [0usize, 1, 2, 3];
    let mut grants = Vec::new();
    for mask in 0..16 {
        let chosen = subset(&slots, mask);
        let draft = DelegationDraft {
            granted: chosen
                .iter()
                .map(|slot| patterns[*slot].tuple.clone())
                .collect(),
            approvals: Vec::new(),
            budgets: Vec::new(),
        };
        let layer = Validator::delegation(&draft).map_err(|refusal| refusal.to_string())?;
        grants.push(Grant {
            layer,
            denotation: chosen
                .iter()
                .fold(0, |bits, slot| bits | patterns[*slot].denotation),
        });
    }
    Ok(grants)
}

fn targets() -> Outcome<LaunchTargets> {
    let configuration = named(ConfigurationFingerprint::from_settings([("model", "1")]))?;
    Ok(LaunchTargets {
        runtime: RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: named(BackendRelease::new(Backend::Vllm, "0.31.0"))?,
            instance: digest("yougori/test/instance/v1", &[b"model"]),
        },
        runtime_configuration: configuration,
        hypervisor: HypervisorSubject {
            machine: digest("yougori/test/machine/v1", &[b"model"]),
            hypervisor: HypervisorKind::Kvm,
        },
        hypervisor_configuration: configuration,
        max_age: Duration::from_secs(60),
        perimeter: None,
    })
}

/// Checks every enumeration; the first disagreement with the specification is returned.
pub(super) fn check() -> Outcome<ModelReport> {
    let patterns = patterns()?;
    let products = products(&patterns)?;
    let requests = requests(&patterns)?;
    let grants = grants(&patterns)?;
    let registry = ProbeRegistry::new(ManualClock::new(MonotonicTime::from_nanos(1)));
    let targets = targets()?;
    let mut report = ModelReport::default();
    for product in &products {
        for request in &requests {
            for grant in &grants {
                report.layer_combinations += 1;
                check_state(
                    &patterns,
                    product,
                    request,
                    grant,
                    &registry,
                    &targets,
                    &mut report,
                )?;
            }
        }
    }
    check_contracts(&mut report)?;
    check_approvals(&patterns, &mut report)?;
    check_budgets(&patterns, &mut report)?;
    Ok(report)
}

fn check_state(
    patterns: &[Pattern],
    product: &Product,
    request: &Request,
    grant: &Grant,
    registry: &ProbeRegistry<ManualClock>,
    targets: &LaunchTargets,
    report: &mut ModelReport,
) -> Outcome<()> {
    let resolved = resolve(&product.layer, &request.layer, &grant.layer);
    let permitted = product.denotation & request.denotation & grant.denotation;
    let produced = denotation_of(resolved.permitted(), patterns)?;
    if produced != permitted {
        return Err(format!(
            "permitted {produced:#011b} is not ceiling ∩ request ∩ delegation \
             {permitted:#011b}"
        ));
    }
    let required: BTreeSet<SecurityPredicate> = product
        .requirements
        .union(&request.requirements)
        .copied()
        .collect();
    if resolved.requirements().iter().collect::<BTreeSet<_>>() != required {
        return Err("required properties are not product ∪ workload".to_owned());
    }
    let covered = |slot: usize| patterns[slot].denotation & !permitted == 0;
    let uncovered: Vec<usize> = request
        .requested
        .iter()
        .copied()
        .filter(|slot| !covered(*slot))
        .collect();
    if resolved.removed().len() != uncovered.len() {
        return Err("the removed list does not match the uncovered requests".to_owned());
    }
    for slot in &uncovered {
        let pattern = &patterns[*slot];
        let removed = resolved
            .removed()
            .iter()
            .find(|removed| removed.tuple == pattern.tuple)
            .ok_or_else(|| format!("{} was removed silently", pattern.tuple))?;
        let mut excluded = BTreeSet::new();
        if pattern.denotation & !product.denotation != 0 {
            excluded.insert(PolicyLayer::ProductCeiling);
        }
        if pattern.denotation & !grant.denotation != 0 {
            excluded.insert(PolicyLayer::Delegation);
        }
        if removed.excluded_by != excluded {
            return Err(format!("wrong excluding layers for {}", pattern.tuple));
        }
        if removed.essential != request.dependencies.contains(slot) {
            return Err(format!("wrong essential flag for {}", pattern.tuple));
        }
    }
    let missing: BTreeSet<PermissionTuple> = request
        .dependencies
        .iter()
        .filter(|slot| !covered(**slot))
        .map(|slot| patterns[*slot].tuple.clone())
        .collect();
    let contract = resolved.identity();
    let now = registry.now();
    for evidence_mask in 0..8 {
        let satisfied: BTreeSet<SecurityPredicate> =
            subset(&PREDICATES, evidence_mask).into_iter().collect();
        let verdicts = resolved
            .requirements()
            .iter()
            .map(|predicate| PredicateVerdict {
                predicate,
                outcome: if satisfied.contains(&predicate) {
                    PredicateOutcome::Verified {
                        source: SourceClass::HostProbe,
                        observed_at: now.at(),
                        fresh_until: MonotonicTime::from_nanos(u64::MAX),
                        detail: SupportDetail::Plain,
                    }
                } else {
                    PredicateOutcome::NoEvidenceCapability {
                        needed: "model".to_owned(),
                    }
                },
            })
            .collect();
        let evidence =
            EvidenceReport::from_verdicts(now.session(), now.at(), targets.clone(), verdicts);
        let unmet: BTreeSet<SecurityPredicate> = required.difference(&satisfied).copied().collect();
        let allowed = missing.is_empty() && unmet.is_empty();
        report.launch_decisions += 1;
        match decide(&resolved, contract, &evidence) {
            Ok(plan) => {
                if !allowed {
                    return Err("a launch was allowed with unmet requirements".to_owned());
                }
                report.allowed_launches += 1;
                if product.only_vm && request.requirements.is_empty() && evidence_mask == 0b111 {
                    check_authorization(patterns, &plan, permitted, registry, report)?;
                }
            }
            Err(refusal) => {
                if allowed {
                    return Err(format!("an allowed launch was refused: {refusal}"));
                }
                let mut removed = BTreeSet::new();
                let mut unmet_found = BTreeSet::new();
                for reason in &refusal.reasons {
                    match reason {
                        LaunchRefusalReason::RequiredAuthorityRemoved { tuple, .. } => {
                            removed.insert(tuple.clone());
                        }
                        LaunchRefusalReason::RequirementUnmet { predicate, .. } => {
                            unmet_found.insert(*predicate);
                        }
                        LaunchRefusalReason::NoHostEvidence => {
                            return Err("refused for lack of host evidence".to_owned())
                        }
                    }
                }
                if removed != missing || unmet_found != unmet {
                    return Err(format!("the refusal names the wrong reasons: {refusal}"));
                }
                if !removed.is_empty() && !unmet_found.is_empty() {
                    report.refused_for_authority_and_evidence += 1;
                }
            }
        }
    }
    Ok(())
}

fn check_authorization(
    patterns: &[Pattern],
    plan: &LaunchPlan,
    permitted: u16,
    registry: &ProbeRegistry<ManualClock>,
    report: &mut ModelReport,
) -> Outcome<()> {
    let tenant = named(TenantId::new("tenant-model"))?;
    let execution = named(ExecutionId::new("exe-model"))?;
    let roles: BTreeSet<RoleName> = plan
        .resolved()
        .permitted()
        .iter()
        .chain(plan.resolved().dependencies().iter())
        .map(|tuple| tuple.principal.role)
        .collect();
    for role in ["main", "build"] {
        let role = named(RoleName::new(role))?;
        for (epoch, bit) in [(EPOCH_ONE, 0u32), (EPOCH_TWO, 1)] {
            let generations = SandboxGenerations {
                boot: SandboxBootGeneration::FIRST,
                policy: PolicyEpoch::FIRST,
                authorization: epoch,
            };
            let binding = ActivationBinding {
                tenant: tenant.clone(),
                execution: execution.clone(),
                role: role.clone(),
                generations,
            };
            let active = match plan.activate(binding, registry.now()) {
                Ok(active) => active,
                Err(ActivationRefusal::UnknownRole { .. })
                    if !roles.is_empty() && !roles.contains(&role) =>
                {
                    continue
                }
                Err(refusal) => return Err(format!("activation refused: {refusal}")),
            };
            for pattern in patterns {
                let action = pattern.tuple.action();
                let request = AuthorizationRequest {
                    tenant: tenant.clone(),
                    execution: execution.clone(),
                    generations,
                    operation: action.operation.clone(),
                    resource: action.resource.clone(),
                    context: action.context,
                    charges: Charges {
                        release_bytes: Some(1),
                        release_effects: Some(1),
                        credential_effects: Some(1),
                    },
                    payload: None,
                };
                let spec = action.principal.role == role
                    && permitted & (1 << (pattern.denotation.trailing_zeros() + bit)) != 0;
                let mut evaluator = Evaluator::new(
                    active.clone(),
                    BudgetSpend::none(tenant.clone(), execution.clone()),
                )
                .map_err(|refusal| refusal.to_string())?;
                let outcome = evaluator.authorize(&request, generations);
                report.authorizations += 1;
                match (outcome, spec) {
                    (Ok(_), true) | (Err(AuthorizationRefusal::NotPermitted { .. }), false) => {}
                    (outcome, _) => {
                        return Err(format!(
                            "authorization of {action} at epoch {epoch} as {role}: {outcome:?}"
                        ))
                    }
                }
            }
        }
    }
    Ok(())
}

fn check_contracts(report: &mut ModelReport) -> Outcome<()> {
    let every = GenerationScope::EveryGeneration;
    let single = |operation: Operation, kind, name: &str| {
        tuple("main", operation, kind, name, Phase::Analysis, every)
    };
    let tuples = [
        single(Operation::FileRead, ResourceKind::FileGrant, "inputs")?,
        single(Operation::TransportConnect, ResourceKind::Route, "registry")?,
        single(
            Operation::ProviderOperation {
                name: named(OperationName::new("create-issue"))?,
            },
            ResourceKind::ProviderAccount,
            "tracker",
        )?,
        single(Operation::PublishService, ResourceKind::Service, "web")?,
        single(
            Operation::ReceiveExternalCredential,
            ResourceKind::Credential,
            "api-key",
        )?,
        single(Operation::VolumeWrite, ResourceKind::Volume, "data")?,
        single(Operation::DeviceUse, ResourceKind::Device, "gpu0")?,
        single(Operation::Release, ResourceKind::ReleaseChannel, "results")?,
    ];
    let forbidden = |constraint: ContractConstraint, index: usize| match constraint {
        ContractConstraint::NoNetworkAuthority => matches!(index, 1..=3),
        ContractConstraint::NoExternalCredentialDelivery => index == 4,
        ContractConstraint::NoVolumeWrite => index == 5,
        ContractConstraint::NoDeviceUse => index == 6,
        ContractConstraint::LifetimeBounded => false,
    };
    let constraints = [
        ContractConstraint::NoNetworkAuthority,
        ContractConstraint::NoExternalCredentialDelivery,
        ContractConstraint::NoVolumeWrite,
        ContractConstraint::NoDeviceUse,
        ContractConstraint::LifetimeBounded,
    ];
    for mask in 0..(1usize << tuples.len()) {
        let permitted = PermissionSet::new(subset(&tuples, mask));
        for with_lifetimes in [false, true] {
            let budgets = if with_lifetimes {
                BudgetSet::vm_d12_task_defaults()
            } else {
                BudgetSet::default()
            };
            for constraint in constraints {
                let violating: Vec<PermissionTuple> = (0..tuples.len())
                    .filter(|index| mask & (1 << index) != 0 && forbidden(constraint, *index))
                    .map(|index| tuples[index].clone())
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect();
                let expected = if !violating.is_empty() {
                    PredicateOutcome::ContractViolated { tuples: violating }
                } else if constraint == ContractConstraint::LifetimeBounded && !with_lifetimes {
                    PredicateOutcome::ContractBudgetMissing {
                        keys: constraint.required_budgets(),
                    }
                } else {
                    PredicateOutcome::ContractHolds
                };
                report.contract_checks += 1;
                if constraint.evaluate(&permitted, &budgets) != expected {
                    return Err(format!(
                        "{constraint:?} misjudged permitted set {mask:#010b}"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// A product with ceiling {t0} and only `vm_sandbox`, plus approvals and budgets.
fn small_layers(
    patterns: &[Pattern],
    approvals: [Vec<ApprovalRule>; 3],
    budgets: [Vec<Budget>; 3],
) -> Outcome<ResolvedPolicy> {
    let [product_approvals, request_approvals, delegation_approvals] = approvals;
    let [product_budgets, request_budgets, delegation_budgets] = budgets;
    let t0 = patterns[0].tuple.clone();
    let product = Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![t0.clone()],
        requirements: vec![SecurityPredicate::VmSandbox],
        approvals: product_approvals,
        budgets: product_budgets,
    })
    .map_err(|refusal| refusal.to_string())?;
    let request = Validator::request(&RequestDocument {
        schema_version: CONTRACT_SCHEMA_VERSION,
        source: source()?,
        requested: vec![t0.clone()],
        dependencies: Vec::new(),
        requires: Vec::new(),
        legacy_tier: None,
        approvals: request_approvals,
        budgets: request_budgets,
    })
    .map_err(|refusal| refusal.to_string())?;
    let delegation = Validator::delegation(&DelegationDraft {
        granted: vec![t0],
        approvals: delegation_approvals,
        budgets: delegation_budgets,
    })
    .map_err(|refusal| refusal.to_string())?;
    Ok(resolve(&product, &request, &delegation))
}

fn check_approvals(patterns: &[Pattern], report: &mut ModelReport) -> Outcome<()> {
    let rules = [
        ApprovalRule {
            kind: ApprovalKind::OngoingDelegation,
            operation: Operation::FileRead,
            resource: named(ResourceRef::new(ResourceKind::FileGrant, "inputs"))?,
        },
        ApprovalRule {
            kind: ApprovalKind::ExactRelease,
            operation: Operation::Release,
            resource: named(ResourceRef::new(ResourceKind::ReleaseChannel, "results"))?,
        },
    ];
    for product in 0..4 {
        for request in 0..4 {
            for delegation in 0..4 {
                let layers = [
                    subset(&rules, product),
                    subset(&rules, request),
                    subset(&rules, delegation),
                ];
                let union = ApprovalSet::new(layers.iter().flatten().cloned());
                let resolved = small_layers(
                    patterns,
                    layers.clone(),
                    [Vec::new(), Vec::new(), Vec::new()],
                )?;
                report.approval_states += 1;
                if *resolved.approvals() != union
                    || layers.iter().any(|layer| {
                        !ApprovalSet::new(layer.clone()).is_subset(resolved.approvals())
                    })
                {
                    return Err("a required approval was not accumulated".to_owned());
                }
            }
        }
    }
    Ok(())
}

fn check_budgets(patterns: &[Pattern], report: &mut ModelReport) -> Outcome<()> {
    let channel = named(ResourceRef::new(ResourceKind::ReleaseChannel, "results"))?;
    let keys = [
        BudgetKey {
            resource: BudgetResource::ReleaseBytes,
            scope: AccountingScope::Generation,
        },
        BudgetKey {
            resource: BudgetResource::ReleaseBytes,
            scope: AccountingScope::Channel { resource: channel },
        },
        BudgetKey {
            resource: BudgetResource::ReleaseEffects,
            scope: AccountingScope::Generation,
        },
    ];
    let layer = |code: usize| -> Vec<(usize, u64)> {
        (0..keys.len())
            .filter_map(|index| {
                let value = (code / 3usize.pow(index as u32)) % 3;
                (value > 0).then_some((index, value as u64))
            })
            .collect()
    };
    let budgets = |entries: &[(usize, u64)]| -> Vec<Budget> {
        entries
            .iter()
            .map(|(index, limit)| Budget {
                resource: keys[*index].resource,
                scope: keys[*index].scope.clone(),
                limit: *limit,
            })
            .collect()
    };
    for product in 0..27 {
        for request in 0..27 {
            for delegation in 0..27 {
                let entries = [layer(product), layer(request), layer(delegation)];
                let resolved = small_layers(
                    patterns,
                    [Vec::new(), Vec::new(), Vec::new()],
                    [
                        budgets(&entries[0]),
                        budgets(&entries[1]),
                        budgets(&entries[2]),
                    ],
                )?;
                report.budget_states += 1;
                for (index, key) in keys.iter().enumerate() {
                    let expected = entries
                        .iter()
                        .flatten()
                        .filter(|(slot, _)| *slot == index)
                        .map(|(_, limit)| *limit)
                        .min();
                    if resolved.budgets().limit(key) != expected {
                        return Err(format!("budget {key} is not the minimum within its scope"));
                    }
                }
                if resolved.budgets().len()
                    != (0..keys.len())
                        .filter(|index| entries.iter().flatten().any(|(slot, _)| slot == index))
                        .count()
                {
                    return Err("budgets of different scopes were merged".to_owned());
                }
            }
        }
    }
    Ok(())
}
