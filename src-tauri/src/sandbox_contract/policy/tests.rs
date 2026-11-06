//! Policy algebra, validation, evidence, planning and authorization on fake CORE-01
//! adapters driven by a manual clock.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::*;
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability, CategoryRefusal, ConfigurationFingerprint,
    EvidenceRefusal, HypervisorKind, HypervisorSubject, Observation, ProbeRegistry, Remedy,
    RuntimeSubject, SourceClass, Staleness, Subject, SupportDetail, UnknownReason,
    UnsupportedReason,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
    PolicyEpoch, SandboxBootGeneration, TenantId,
};
use crate::foundation::transfer::VM_D12_GENERAL_RELEASE_BUDGET_BYTES;

const MINUTE: Duration = Duration::from_secs(60);
const HOUR: Duration = Duration::from_secs(3_600);
const MIB: u64 = 1024 * 1024;
const GIB: u64 = 1024 * MIB;
const E1: AuthorizationEpoch = AuthorizationEpoch::FIRST;
const E2: AuthorizationEpoch = AuthorizationEpoch::new(2);

// ---- fixtures ----

fn tuple(
    role: &str,
    operation: Operation,
    kind: ResourceKind,
    name: &str,
    phase: Phase,
) -> PermissionTuple {
    PermissionTuple {
        principal: Principal::role(role).unwrap(),
        operation,
        resource: ResourceRef::new(kind, name).unwrap(),
        context: Context { phase },
        generation: GenerationScope::EveryGeneration,
    }
}

fn read_inputs() -> PermissionTuple {
    tuple(
        "main",
        Operation::FileRead,
        ResourceKind::FileGrant,
        "inputs",
        Phase::Analysis,
    )
}

fn write_outputs() -> PermissionTuple {
    tuple(
        "main",
        Operation::FileWrite,
        ResourceKind::FileGrant,
        "outputs",
        Phase::Analysis,
    )
}

fn release_results() -> PermissionTuple {
    tuple(
        "main",
        Operation::Release,
        ResourceKind::ReleaseChannel,
        "results",
        Phase::Publication,
    )
}

fn connect_registry() -> PermissionTuple {
    tuple(
        "main",
        Operation::TransportConnect,
        ResourceKind::Route,
        "registry",
        Phase::Fetch,
    )
}

fn receive_credential() -> PermissionTuple {
    tuple(
        "main",
        Operation::ReceiveExternalCredential,
        ResourceKind::Credential,
        "api-key",
        Phase::Analysis,
    )
}

fn at(mut tuple: PermissionTuple, epoch: AuthorizationEpoch) -> PermissionTuple {
    tuple.generation = GenerationScope::Authorization { epoch };
    tuple
}

fn set(tuples: &[PermissionTuple]) -> PermissionSet {
    PermissionSet::new(tuples.iter().cloned())
}

fn product_with(
    ceiling: &[PermissionTuple],
    requirements: &[SecurityPredicate],
    approvals: Vec<ApprovalRule>,
    budgets: Vec<Budget>,
) -> ProductPolicy {
    Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: ceiling.to_vec(),
        requirements: requirements.to_vec(),
        approvals,
        budgets,
    })
    .unwrap()
}

fn base_requirements() -> Vec<SecurityPredicate> {
    vec![
        SecurityPredicate::VmSandbox,
        SecurityPredicate::HardwareHypervisorAvailable,
    ]
}

fn product(ceiling: &[PermissionTuple]) -> ProductPolicy {
    product_with(
        ceiling,
        &base_requirements(),
        Vec::new(),
        BudgetSet::vm_d12_task_defaults().into(),
    )
}

fn document(
    requested: &[PermissionTuple],
    dependencies: &[PermissionTuple],
    requires: &[&str],
) -> RequestDocument {
    RequestDocument {
        schema_version: CONTRACT_SCHEMA_VERSION,
        source: RequestSource {
            kind: SourceKind::Template,
            name: SourceName::new("analysis-template").unwrap(),
        },
        requested: requested.to_vec(),
        dependencies: dependencies.to_vec(),
        requires: requires.iter().map(|name| (*name).to_owned()).collect(),
        legacy_tier: None,
        approvals: Vec::new(),
        budgets: Vec::new(),
    }
}

fn request(
    requested: &[PermissionTuple],
    dependencies: &[PermissionTuple],
    requires: &[&str],
) -> WorkloadRequest {
    Validator::request(&document(requested, dependencies, requires)).unwrap()
}

fn delegation(granted: &[PermissionTuple]) -> Delegation {
    Validator::delegation(&DelegationDraft {
        granted: granted.to_vec(),
        approvals: Vec::new(),
        budgets: Vec::new(),
    })
    .unwrap()
}

fn config() -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("kernel", "6.12"), ("profile", "strict")]).unwrap()
}

fn runtime(category: ExecutionCategory) -> RuntimeSubject {
    RuntimeSubject {
        category,
        release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
        instance: digest("yougori/test/instance/v1", &[b"sandbox-1"]),
    }
}

fn hypervisor() -> HypervisorSubject {
    HypervisorSubject {
        machine: digest("yougori/test/machine/v1", &[b"workstation"]),
        hypervisor: HypervisorKind::Whpx,
    }
}

/// A host with one runtime-category probe and one hypervisor probe of chosen sources.
struct Host {
    clock: Arc<ManualClock>,
    registry: ProbeRegistry<Arc<ManualClock>>,
    category: Arc<FakeProbe>,
    hypervisor: Arc<FakeProbe>,
    targets: LaunchTargets,
}

impl Host {
    fn with_sources(
        category: ExecutionCategory,
        category_source: SourceClass,
        hypervisor_source: SourceClass,
    ) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category_probe = Arc::new(FakeProbe::runtime_category(category_source));
        let hypervisor_probe = Arc::new(FakeProbe::new(
            Capability::HypervisorAvailable,
            hypervisor_source,
        ));
        registry
            .register(Box::new(Arc::clone(&category_probe)))
            .unwrap();
        registry
            .register(Box::new(Arc::clone(&hypervisor_probe)))
            .unwrap();
        Self {
            clock,
            registry,
            category: category_probe,
            hypervisor: hypervisor_probe,
            targets: LaunchTargets {
                runtime: runtime(category),
                runtime_configuration: config(),
                hypervisor: hypervisor(),
                hypervisor_configuration: config(),
                max_age: MINUTE,
                perimeter: None,
            },
        }
    }

    /// A VM-sandbox runtime and hypervisor, both observed supported by host probes.
    fn ready() -> Self {
        let mut host = Self::with_sources(
            ExecutionCategory::VmSandbox,
            SourceClass::HostProbe,
            SourceClass::HostProbe,
        );
        host.observe_category();
        host.observe_hypervisor(Observation::supported(
            config(),
            HOUR,
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Whpx,
            },
        ));
        host
    }

    fn observe_category(&mut self) {
        let subject = Subject::Runtime(self.targets.runtime.clone());
        self.category.respond(
            &subject,
            Observation::supported(
                config(),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: self.targets.runtime.category,
                },
            ),
        );
        self.registry
            .refresh(Capability::RuntimeCategory, &subject)
            .unwrap();
    }

    fn observe_hypervisor(&mut self, observation: Observation) {
        let subject = Subject::Hypervisor(self.targets.hypervisor);
        self.hypervisor.respond(&subject, observation);
        self.registry
            .refresh(Capability::HypervisorAvailable, &subject)
            .unwrap();
    }

    fn plan(&self, resolved: &ResolvedPolicy) -> Result<LaunchPlan, LaunchRefusal> {
        plan_launch(resolved, &self.registry, &self.targets)
    }
}

fn generations(epoch: AuthorizationEpoch) -> SandboxGenerations {
    SandboxGenerations {
        boot: SandboxBootGeneration::FIRST,
        policy: PolicyEpoch::FIRST,
        authorization: epoch,
    }
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn execution() -> ExecutionId {
    ExecutionId::new("exe-1").unwrap()
}

fn binding(role: &str, epoch: AuthorizationEpoch) -> ActivationBinding {
    ActivationBinding {
        tenant: tenant(),
        execution: execution(),
        role: RoleName::new(role).unwrap(),
        generations: generations(epoch),
    }
}

fn ask(tuple: &PermissionTuple, epoch: AuthorizationEpoch) -> AuthorizationRequest {
    AuthorizationRequest {
        tenant: tenant(),
        execution: execution(),
        generations: generations(epoch),
        operation: tuple.operation.clone(),
        resource: tuple.resource.clone(),
        context: tuple.context,
        charges: Charges::default(),
        payload: None,
    }
}

fn evaluator(plan: &LaunchPlan, host: &Host, epoch: AuthorizationEpoch) -> Evaluator {
    let active = plan
        .activate(binding("main", epoch), host.registry.now())
        .unwrap();
    Evaluator::new(active, BudgetSpend::none(tenant(), execution())).unwrap()
}

fn issues(refusal: ValidationRefusal) -> Vec<ValidationIssue> {
    refusal.issues
}

fn unmet(refusal: &LaunchRefusal) -> BTreeSet<SecurityPredicate> {
    refusal
        .reasons
        .iter()
        .filter_map(|reason| match reason {
            LaunchRefusalReason::RequirementUnmet { predicate, .. } => Some(*predicate),
            _ => None,
        })
        .collect()
}

fn outcome_of(refusal: &LaunchRefusal, wanted: SecurityPredicate) -> PredicateOutcome {
    refusal
        .reasons
        .iter()
        .find_map(|reason| match reason {
            LaunchRefusalReason::RequirementUnmet { predicate, outcome }
                if *predicate == wanted =>
            {
                Some(outcome.clone())
            }
            _ => None,
        })
        .unwrap()
}

// ---- the permission algebra (§2.4) ----

#[test]
fn intersection_and_union_obey_the_set_laws_on_worked_cases() {
    let a = set(&[read_inputs(), release_results()]);
    let b = set(&[release_results(), connect_registry()]);
    let c = set(&[at(read_inputs(), E1), connect_registry()]);
    let empty = PermissionSet::default();

    assert_eq!(a.intersection(&b), set(&[release_results()]));
    assert_eq!(
        a.union(&b),
        set(&[read_inputs(), release_results(), connect_registry()])
    );
    assert_eq!(a.intersection(&c), set(&[at(read_inputs(), E1)]));
    for (x, y) in [(&a, &b), (&a, &c), (&b, &c)] {
        assert_eq!(x.intersection(y), y.intersection(x));
        assert_eq!(x.union(y), y.union(x));
        assert_eq!(x.union(&x.intersection(y)), *x);
        assert_eq!(x.intersection(&x.union(y)), *x);
    }
    assert_eq!(
        a.intersection(&b).intersection(&c),
        a.intersection(&b.intersection(&c))
    );
    assert_eq!(a.union(&b).union(&c), a.union(&b.union(&c)));
    assert_eq!(
        a.intersection(&b.union(&c)),
        a.intersection(&b).union(&a.intersection(&c))
    );
    assert_eq!(
        a.union(&b.intersection(&c)),
        a.union(&b).intersection(&a.union(&c))
    );
    assert_eq!(a.intersection(&a), a);
    assert_eq!(a.union(&a), a);
    assert_eq!(a.union(&empty), a);
    assert!(a.intersection(&empty).is_empty());
    assert!(a.intersection(&b).is_subset(&a) && a.intersection(&b).is_subset(&b));
    assert!(a.is_subset(&a.union(&b)));
}

#[test]
fn generation_scopes_intersect_exactly() {
    let every = set(&[read_inputs()]);
    let first = set(&[at(read_inputs(), E1)]);
    let second = set(&[at(read_inputs(), E2)]);
    assert_eq!(every.intersection(&first), first);
    assert!(first.intersection(&second).is_empty());
    let both = first.union(&second);
    assert_eq!(both.len(), 2);
    assert_eq!(both.union(&every), every);
    assert_eq!(every.union(&first).len(), 1);
    // A list of epochs never covers "every generation".
    assert!(!both.covers(&read_inputs()));
    assert!(every.covers(&at(read_inputs(), E2)));
    assert!(first.covers(&at(read_inputs(), E1)));
    assert!(!first.covers(&at(read_inputs(), E2)));
    assert!(first.actions_at(E2).is_empty());
    assert_eq!(
        every.actions_at(E2),
        BTreeSet::from([read_inputs().action()])
    );
    assert!(first.permits_at(&read_inputs().action(), E1));
    assert!(!first.permits_at(&read_inputs().action(), E2));
}

#[test]
fn permission_sets_are_canonical_whatever_the_order() {
    let forward = set(&[read_inputs(), release_results(), at(connect_registry(), E1)]);
    let backward = set(&[
        at(connect_registry(), E1),
        release_results(),
        read_inputs(),
        read_inputs(),
        at(read_inputs(), E2),
    ]);
    assert_eq!(forward, backward);
    assert_eq!(forward.len(), 3);
    let json = serde_json::to_value(&backward).unwrap();
    assert_eq!(json.as_array().unwrap().len(), 3);
    let read: PermissionSet = serde_json::from_value(json).unwrap();
    assert_eq!(read, forward);
}

#[test]
fn permitted_is_the_intersection_of_ceiling_request_and_delegation() {
    let product = product(&[read_inputs(), write_outputs(), release_results()]);
    let request = request(
        &[read_inputs(), write_outputs(), connect_registry()],
        &[read_inputs()],
        &[],
    );
    let delegation = delegation(&[read_inputs(), connect_registry(), release_results()]);
    let resolved = resolve(&product, &request, &delegation);
    assert_eq!(*resolved.permitted(), set(&[read_inputs()]));

    let removed: Vec<(PermissionTuple, BTreeSet<PolicyLayer>, bool)> = resolved
        .removed()
        .iter()
        .map(|removed| {
            (
                removed.tuple.clone(),
                removed.excluded_by.clone(),
                removed.essential,
            )
        })
        .collect();
    assert_eq!(removed.len(), 2);
    assert!(removed.contains(&(
        write_outputs(),
        BTreeSet::from([PolicyLayer::Delegation]),
        false
    )));
    assert!(removed.contains(&(
        connect_registry(),
        BTreeSet::from([PolicyLayer::ProductCeiling]),
        false
    )));
    // Non-essential removals are reported, and the launch goes ahead without them.
    let plan = Host::ready().plan(&resolved).unwrap();
    assert_eq!(plan.resolved().removed().len(), 2);
}

#[test]
fn required_properties_are_the_union_of_product_and_workload() {
    let product = product(&[read_inputs()]);
    let request = request(&[read_inputs()], &[], &["contract_offline", "vm_sandbox"]);
    let resolved = resolve(&product, &request, &delegation(&[read_inputs()]));
    assert_eq!(
        resolved.requirements().iter().collect::<Vec<_>>(),
        vec![
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable,
            SecurityPredicate::ContractOffline,
        ]
    );
    assert!(product.requirements().is_subset(resolved.requirements()));
    assert!(request.requirements().is_subset(resolved.requirements()));
}

#[test]
fn a_required_authority_removed_by_intersection_refuses_planning_with_its_name() {
    let product = product(&[read_inputs(), write_outputs()]);
    let request = request(
        &[read_inputs(), write_outputs(), connect_registry()],
        &[write_outputs(), connect_registry()],
        &[],
    );
    let delegation = delegation(&[read_inputs(), connect_registry()]);
    let resolved = resolve(&product, &request, &delegation);
    assert_eq!(resolved.missing_dependencies().count(), 2);

    let refusal = Host::ready().plan(&resolved).unwrap_err();
    assert_eq!(refusal.contract, resolved.identity());
    assert_eq!(refusal.reasons.len(), 2);
    assert!(refusal
        .reasons
        .contains(&LaunchRefusalReason::RequiredAuthorityRemoved {
            tuple: connect_registry(),
            excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling]),
        }));
    assert!(refusal
        .reasons
        .contains(&LaunchRefusalReason::RequiredAuthorityRemoved {
            tuple: write_outputs(),
            excluded_by: BTreeSet::from([PolicyLayer::Delegation]),
        }));
    let text = refusal.to_string();
    assert!(text.contains("route \"registry\""), "{text}");
    assert!(text.contains("the product ceiling"), "{text}");
    assert!(text.contains("file grant \"outputs\""), "{text}");
    assert!(text.contains("rather than started without it"), "{text}");

    // The static validator reports the same containment problem before resolution.
    let static_issues =
        issues(Validator::combination(&product, &request, &delegation).unwrap_err());
    assert!(
        static_issues.contains(&ValidationIssue::DependencyOutsideLayer {
            layer: PolicyLayer::ProductCeiling,
            tuple: connect_registry(),
        })
    );
    assert!(
        static_issues.contains(&ValidationIssue::DependencyOutsideLayer {
            layer: PolicyLayer::Delegation,
            tuple: write_outputs(),
        })
    );
}

#[test]
fn launch_is_allowed_only_when_evidence_and_dependencies_both_hold() {
    let product = product(&[read_inputs(), release_results()]);
    let request = request(&[read_inputs()], &[read_inputs()], &[]);
    let resolved = resolve(&product, &request, &delegation(&[read_inputs()]));
    assert!(Validator::combination(&product, &request, &delegation(&[read_inputs()])).is_ok());

    let host = Host::ready();
    let plan = host.plan(&resolved).unwrap();
    assert_eq!(plan.contract(), resolved.identity());
    assert_eq!(plan.verdicts().len(), 2);
    assert!(plan
        .verdicts()
        .iter()
        .all(|verdict| verdict.outcome.is_satisfied()));
    let Some(PredicateVerdict {
        outcome: PredicateOutcome::Verified { source, detail, .. },
        ..
    }) = plan.verdicts().first()
    else {
        panic!("the VM sandbox predicate was not verified");
    };
    assert_eq!(*source, SourceClass::HostProbe);
    assert_eq!(
        *detail,
        SupportDetail::RuntimeCategory {
            category: ExecutionCategory::VmSandbox
        }
    );
    assert_eq!(
        plan.fresh_until(),
        MonotonicTime::from_nanos(1_000).saturating_add(MINUTE)
    );

    // Without the hypervisor evidence the same contract is refused.
    let mut bare = Host::with_sources(
        ExecutionCategory::VmSandbox,
        SourceClass::HostProbe,
        SourceClass::HostProbe,
    );
    bare.observe_category();
    let refusal = bare.plan(&resolved).unwrap_err();
    assert_eq!(
        unmet(&refusal),
        BTreeSet::from([SecurityPredicate::HardwareHypervisorAvailable])
    );
    assert_eq!(
        outcome_of(&refusal, SecurityPredicate::HardwareHypervisorAvailable),
        PredicateOutcome::EvidenceRefused {
            refusal: EvidenceRefusal::Missing {
                capability: Capability::HypervisorAvailable
            }
        }
    );
}

// ---- approvals (§2.4 line 1802; VM-P46) ----

fn rule(kind: ApprovalKind, tuple: &PermissionTuple) -> ApprovalRule {
    ApprovalRule {
        kind,
        operation: tuple.operation.clone(),
        resource: tuple.resource.clone(),
    }
}

#[test]
fn required_approvals_accumulate_and_are_never_intersected_away() {
    let private = rule(ApprovalKind::PrivateDataAccess, &read_inputs());
    let ongoing = rule(ApprovalKind::OngoingDelegation, &write_outputs());
    let exact = rule(ApprovalKind::ExactRelease, &release_results());
    let product = product_with(
        &[read_inputs(), write_outputs(), release_results()],
        &base_requirements(),
        vec![private.clone()],
        BudgetSet::vm_d12_task_defaults().into(),
    );
    let mut silent = document(
        &[read_inputs(), write_outputs(), release_results()],
        &[],
        &[],
    );
    let quiet = Validator::request(&silent).unwrap();
    silent.approvals = vec![ongoing.clone()];
    let asking = Validator::request(&silent).unwrap();
    let granted = Validator::delegation(&DelegationDraft {
        granted: vec![read_inputs(), write_outputs(), release_results()],
        approvals: vec![exact.clone()],
        budgets: Vec::new(),
    })
    .unwrap();

    // A request listing no approvals does not remove the product's.
    let resolved = resolve(&product, &quiet, &granted);
    assert_eq!(
        *resolved.approvals(),
        ApprovalSet::new([private.clone(), exact.clone()])
    );
    let resolved = resolve(&product, &asking, &granted);
    assert_eq!(
        *resolved.approvals(),
        ApprovalSet::new([private.clone(), ongoing.clone(), exact.clone()])
    );
    for layer in [product.approvals(), asking.approvals(), granted.approvals()] {
        assert!(layer.is_subset(resolved.approvals()));
    }
    // Two disjoint rule sets keep both, where an intersection would keep neither.
    let left = ApprovalSet::new([private.clone()]);
    let right = ApprovalSet::new([exact.clone()]);
    assert_eq!(left.union(&right).len(), 2);
}

#[test]
fn an_approval_rule_gates_runtime_use_until_a_valid_grant_exists() {
    let ongoing = rule(ApprovalKind::OngoingDelegation, &read_inputs());
    let exact = rule(ApprovalKind::ExactRelease, &release_results());
    let product = product_with(
        &[read_inputs(), release_results()],
        &base_requirements(),
        vec![ongoing.clone(), exact.clone()],
        BudgetSet::vm_d12_task_defaults().into(),
    );
    let request = request(&[read_inputs(), release_results()], &[], &[]);
    let resolved = resolve(
        &product,
        &request,
        &delegation(&[read_inputs(), release_results()]),
    );
    let host = Host::ready();
    let plan = host.plan(&resolved).unwrap();
    let mut evaluator = evaluator(&plan, &host, E1);

    assert_eq!(
        evaluator.authorize(&ask(&read_inputs(), E1), generations(E1)),
        Err(AuthorizationRefusal::ApprovalRequired {
            rule: ongoing.clone()
        })
    );
    assert_eq!(
        evaluator.record_approval(ApprovalGrant {
            rule: ongoing.clone(),
            epoch: E2,
            payload: None,
        }),
        Err(EvaluatorRefusal::ApprovalForOtherEpoch {
            grant: E2,
            bound: E1
        })
    );
    let unrelated = rule(ApprovalKind::PrivateDataAccess, &read_inputs());
    assert_eq!(
        evaluator.record_approval(ApprovalGrant {
            rule: unrelated.clone(),
            epoch: E1,
            payload: None,
        }),
        Err(EvaluatorRefusal::ApprovalNotRequired { rule: unrelated })
    );
    evaluator
        .record_approval(ApprovalGrant {
            rule: ongoing.clone(),
            epoch: E1,
            payload: None,
        })
        .unwrap();
    // A valid ongoing grant is not asked for again.
    for _ in 0..3 {
        let allowed = evaluator
            .authorize(&ask(&read_inputs(), E1), generations(E1))
            .unwrap();
        assert_eq!(allowed.approvals_used, vec![ongoing.clone()]);
    }

    // An exact release binds one payload and is used once.
    let payload = digest("yougori/test/payload/v1", &[b"report.pdf"]);
    let other = digest("yougori/test/payload/v1", &[b"secrets.txt"]);
    assert_eq!(
        evaluator.record_approval(ApprovalGrant {
            rule: exact.clone(),
            epoch: E1,
            payload: None,
        }),
        Err(EvaluatorRefusal::ApprovalMalformed {
            rule: exact.clone()
        })
    );
    evaluator
        .record_approval(ApprovalGrant {
            rule: exact.clone(),
            epoch: E1,
            payload: Some(payload),
        })
        .unwrap();
    let mut release = ask(&release_results(), E1);
    release.charges.release_bytes = Some(1_000);
    release.payload = Some(other);
    assert_eq!(
        evaluator.authorize(&release, generations(E1)),
        Err(AuthorizationRefusal::ApprovalRequired {
            rule: exact.clone()
        })
    );
    release.payload = Some(payload);
    evaluator.authorize(&release, generations(E1)).unwrap();
    assert_eq!(
        evaluator.authorize(&release, generations(E1)),
        Err(AuthorizationRefusal::ApprovalRequired { rule: exact })
    );
}

// ---- budgets (§2.4 line 1802; VM-D12) ----

fn budget(resource: BudgetResource, scope: AccountingScope, limit: u64) -> Budget {
    Budget {
        resource,
        scope,
        limit,
    }
}

fn channel(tuple: &PermissionTuple) -> AccountingScope {
    AccountingScope::Channel {
        resource: tuple.resource.clone(),
    }
}

fn key(resource: BudgetResource, scope: AccountingScope) -> BudgetKey {
    BudgetKey { resource, scope }
}

#[test]
fn budgets_take_minima_only_within_one_resource_and_scope() {
    let product = BudgetSet::new([
        budget(
            BudgetResource::ReleaseBytes,
            AccountingScope::Generation,
            8 * MIB,
        ),
        budget(
            BudgetResource::ReleaseEffects,
            AccountingScope::Generation,
            10,
        ),
    ])
    .unwrap();
    let request = BudgetSet::new([
        budget(
            BudgetResource::ReleaseBytes,
            AccountingScope::Generation,
            MIB,
        ),
        budget(
            BudgetResource::ReleaseBytes,
            channel(&release_results()),
            64 * 1024,
        ),
    ])
    .unwrap();
    let delegation = BudgetSet::new([budget(
        BudgetResource::ReleaseBytes,
        AccountingScope::Generation,
        2 * MIB,
    )])
    .unwrap();
    let composed = product.compose(&request).compose(&delegation);
    assert_eq!(composed.len(), 3);
    assert_eq!(
        composed.limit(&key(
            BudgetResource::ReleaseBytes,
            AccountingScope::Generation
        )),
        Some(MIB)
    );
    // The smaller channel budget does not lower the generation budget, nor the reverse.
    assert_eq!(
        composed.limit(&key(
            BudgetResource::ReleaseBytes,
            channel(&release_results())
        )),
        Some(64 * 1024)
    );
    assert_eq!(
        composed.limit(&key(
            BudgetResource::ReleaseEffects,
            AccountingScope::Generation
        )),
        Some(10)
    );
    assert_eq!(
        composed.limit(&key(
            BudgetResource::ReleaseEffects,
            AccountingScope::Execution
        )),
        None
    );
    assert_eq!(product.compose(&request), request.compose(&product));
}

#[test]
fn a_template_can_lower_a_budget_but_never_raise_it() {
    let product = product(&[read_inputs()]);
    let mut raising = document(&[read_inputs()], &[], &[]);
    raising.budgets = vec![budget(
        BudgetResource::ReleaseBytes,
        AccountingScope::Generation,
        16 * MIB,
    )];
    let resolved = resolve(
        &product,
        &Validator::request(&raising).unwrap(),
        &delegation(&[read_inputs()]),
    );
    let generation = key(BudgetResource::ReleaseBytes, AccountingScope::Generation);
    assert_eq!(
        resolved.budgets().limit(&generation),
        Some(VM_D12_GENERAL_RELEASE_BUDGET_BYTES)
    );
    raising.budgets[0].limit = MIB;
    let resolved = resolve(
        &product,
        &Validator::request(&raising).unwrap(),
        &delegation(&[read_inputs()]),
    );
    assert_eq!(resolved.budgets().limit(&generation), Some(MIB));
}

#[test]
fn a_layer_listing_one_budget_twice_is_refused() {
    let twice = vec![
        budget(
            BudgetResource::ReleaseBytes,
            AccountingScope::Generation,
            MIB,
        ),
        budget(
            BudgetResource::ReleaseBytes,
            AccountingScope::Generation,
            2 * MIB,
        ),
    ];
    let duplicate = key(BudgetResource::ReleaseBytes, AccountingScope::Generation);
    assert_eq!(
        BudgetSet::new(twice.clone()),
        Err(DuplicateBudget {
            key: duplicate.clone()
        })
    );
    assert!(serde_json::from_value::<BudgetSet>(serde_json::to_value(&twice).unwrap()).is_err());
    let mut doc = document(&[read_inputs()], &[], &[]);
    doc.budgets = twice;
    assert_eq!(
        issues(Validator::request(&doc).unwrap_err()),
        vec![ValidationIssue::DuplicateBudget {
            layer: PolicyLayer::Request,
            key: duplicate
        }]
    );
}

#[test]
fn vm_d12_defaults_are_the_recorded_starting_values() {
    assert_eq!(VM_D12_GENERAL_RELEASE_BUDGET_BYTES, 8_388_608);
    assert_eq!(VM_D12_IDLE_LIFETIME_SECONDS, 43_200);
    assert_eq!(VM_D12_TASK_ABSOLUTE_LIFETIME_SECONDS, 86_400);
    assert_eq!(VM_D12_SERVICE_RENEWAL_SECONDS, 604_800);
    let defaults = BudgetSet::vm_d12_task_defaults();
    assert_eq!(
        defaults.limit(&key(
            BudgetResource::ReleaseBytes,
            AccountingScope::Generation
        )),
        Some(8 * MIB)
    );
    assert_eq!(
        defaults.limit(&key(
            BudgetResource::IdleLifetimeSeconds,
            AccountingScope::Execution
        )),
        Some(12 * 3_600)
    );
    assert_eq!(
        defaults.limit(&key(
            BudgetResource::AbsoluteLifetimeSeconds,
            AccountingScope::Execution
        )),
        Some(24 * 3_600)
    );
    for resource in BudgetResource::ALL {
        assert_eq!(
            resource.is_spent_per_request(),
            resource.unit() != BudgetUnit::Seconds
        );
    }
}

// ---- evidence (VM-W02, VM-W09, CORE-01) ----

#[test]
fn a_guest_report_never_satisfies_a_host_only_predicate_or_lowers_it() {
    let mut host = Host::with_sources(
        ExecutionCategory::VmSandbox,
        SourceClass::HostProbe,
        SourceClass::GuestReport,
    );
    host.observe_category();
    host.observe_hypervisor(Observation::supported(
        config(),
        HOUR,
        SupportDetail::Hypervisor {
            hypervisor: HypervisorKind::Whpx,
        },
    ));
    let resolved = resolve(
        &product(&[read_inputs()]),
        &request(&[read_inputs()], &[], &[]),
        &delegation(&[read_inputs()]),
    );
    let before = resolved.requirements().clone();
    let report = EvidenceChecker::check(&host.registry, resolved.requirements(), &host.targets);
    assert_eq!(
        report.outcome(SecurityPredicate::HardwareHypervisorAvailable),
        Some(&PredicateOutcome::EvidenceRefused {
            refusal: EvidenceRefusal::SourceTooWeak {
                capability: Capability::HypervisorAvailable,
                observed: SourceClass::GuestReport,
                required: SourceClass::HostProbe,
            }
        })
    );
    let refusal = host.plan(&resolved).unwrap_err();
    assert_eq!(
        unmet(&refusal),
        BTreeSet::from([SecurityPredicate::HardwareHypervisorAvailable])
    );
    assert!(refusal.to_string().contains("never satisfies a host-only"));
    assert_eq!(*resolved.requirements(), before);
}

#[test]
fn a_guest_report_of_the_runtime_category_never_admits_a_vm() {
    let mut host = Host::with_sources(
        ExecutionCategory::VmSandbox,
        SourceClass::GuestReport,
        SourceClass::HostProbe,
    );
    host.observe_category();
    let resolved = resolve(
        &product_with(
            &[read_inputs()],
            &[SecurityPredicate::VmSandbox],
            Vec::new(),
            Vec::new(),
        ),
        &request(&[read_inputs()], &[], &[]),
        &delegation(&[read_inputs()]),
    );
    let refusal = host.plan(&resolved).unwrap_err();
    assert_eq!(
        outcome_of(&refusal, SecurityPredicate::VmSandbox),
        PredicateOutcome::EvidenceRefused {
            refusal: EvidenceRefusal::SourceTooWeak {
                capability: Capability::RuntimeCategory,
                observed: SourceClass::GuestReport,
                required: SourceClass::ProviderApi,
            }
        }
    );
}

#[test]
fn bad_host_evidence_refuses_and_never_lowers_requirements() {
    let resolved = resolve(
        &product(&[read_inputs()]),
        &request(&[read_inputs()], &[], &[]),
        &delegation(&[read_inputs()]),
    );
    let before = resolved.requirements().clone();
    let other_config = ConfigurationFingerprint::from_settings([("kernel", "6.13")]).unwrap();
    let cases = [
        (
            Observation::unsupported(config(), HOUR, UnsupportedReason::HypervisorUnavailable),
            Remedy::EnableHypervisorYourself,
        ),
        (
            Observation::unknown(config(), HOUR, UnknownReason::Inconclusive),
            Remedy::RunCheckAgain,
        ),
        (
            Observation::supported(
                other_config,
                HOUR,
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Whpx,
                },
            ),
            Remedy::RecheckCurrentConfiguration,
        ),
    ];
    for (observation, remedy) in cases {
        let mut host = Host::ready();
        host.observe_hypervisor(observation);
        let refusal = host.plan(&resolved).unwrap_err();
        let PredicateOutcome::EvidenceRefused { refusal: evidence } =
            outcome_of(&refusal, SecurityPredicate::HardwareHypervisorAvailable)
        else {
            panic!("expected an evidence refusal");
        };
        assert_eq!(evidence.remedy(), remedy);
        assert_eq!(*resolved.requirements(), before);
    }

    // Stale evidence (VM-P50): older than the launch's maximum age.
    let host = Host::ready();
    host.clock.advance(MINUTE + Duration::from_nanos(1));
    let refusal = host.plan(&resolved).unwrap_err();
    assert_eq!(unmet(&refusal).len(), 2);
    assert!(matches!(
        outcome_of(&refusal, SecurityPredicate::HardwareHypervisorAvailable),
        PredicateOutcome::EvidenceRefused {
            refusal: EvidenceRefusal::Stale {
                staleness: Staleness::TooOld { .. },
                ..
            }
        }
    ));
    assert_eq!(*resolved.requirements(), before);
}

#[test]
fn missing_hardware_acceleration_refuses_launch() {
    // VM-P01/VM-P42: without a usable hypervisor nothing starts as a compliant sandbox.
    let mut host = Host::ready();
    host.observe_hypervisor(Observation::unsupported(
        config(),
        HOUR,
        UnsupportedReason::HypervisorUnavailable,
    ));
    let resolved = resolve(
        &product(&[read_inputs()]),
        &request(&[read_inputs()], &[read_inputs()], &[]),
        &delegation(&[read_inputs()]),
    );
    let refusal = host.plan(&resolved).unwrap_err();
    assert_eq!(
        outcome_of(&refusal, SecurityPredicate::HardwareHypervisorAvailable),
        PredicateOutcome::EvidenceRefused {
            refusal: EvidenceRefusal::Unsupported {
                capability: Capability::HypervisorAvailable,
                reason: UnsupportedReason::HypervisorUnavailable,
            }
        }
    );
    assert!(refusal
        .to_string()
        .contains("Yougori does not change host settings"));
}

#[test]
fn a_labelled_runtime_never_satisfies_a_vm_required_launch() {
    let resolved = resolve(
        &product(&[read_inputs()]),
        &request(&[read_inputs()], &[], &[]),
        &delegation(&[read_inputs()]),
    );
    for category in ExecutionCategory::ALL
        .into_iter()
        .filter(|category| !category.is_vm_sandbox())
    {
        // Even with host-probe evidence that the runtime is its labelled category.
        let mut host = Host::with_sources(category, SourceClass::HostProbe, SourceClass::HostProbe);
        host.observe_category();
        host.observe_hypervisor(Observation::supported(
            config(),
            HOUR,
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Whpx,
            },
        ));
        let refusal = host.plan(&resolved).unwrap_err();
        let outcome = outcome_of(&refusal, SecurityPredicate::VmSandbox);
        assert_eq!(
            outcome,
            PredicateOutcome::CategoryRefused {
                refusal: CategoryRefusal::VmSandboxRequired { offered: category }
            }
        );
        let text = refusal.to_string();
        assert!(text.contains(category.label()), "{text}");
        assert!(text.contains(category.decision().unwrap()), "{text}");
        assert_eq!(
            unmet(&refusal),
            BTreeSet::from([SecurityPredicate::VmSandbox])
        );
    }
}

#[test]
fn an_unobservable_vm_requirement_refuses_with_a_typed_reason() {
    let resolved = resolve(
        &product(&[read_inputs()]),
        &request(&[read_inputs()], &[], &["dedicated_physical_host"]),
        &delegation(&[read_inputs()]),
    );
    let refusal = Host::ready().plan(&resolved).unwrap_err();
    assert_eq!(
        unmet(&refusal),
        BTreeSet::from([SecurityPredicate::DedicatedPhysicalHost])
    );
    let PredicateOutcome::NoEvidenceCapability { needed } =
        outcome_of(&refusal, SecurityPredicate::DedicatedPhysicalHost)
    else {
        panic!("expected a missing evidence capability");
    };
    assert!(needed.contains("dedicated"));
    assert!(refusal.to_string().contains("not assumed to hold"));
    // Every host predicate is either bound to CORE-01 evidence or explicitly unobservable.
    let observable: Vec<SecurityPredicate> = SecurityPredicate::ALL
        .into_iter()
        .filter(|predicate| {
            matches!(
                predicate.check(),
                PredicateCheck::HostEvidence(
                    EvidenceBinding::VmSandboxCategory
                        | EvidenceBinding::HypervisorAvailable
                        | EvidenceBinding::PerimeterRulesEnforced
                )
            )
        })
        .collect();
    assert_eq!(
        observable,
        vec![
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable,
            SecurityPredicate::IndependentPerimeter
        ]
    );
}

// ---- untrusted templates and tools (VM-P47) ----

#[test]
fn an_untrusted_template_cannot_widen_rights() {
    let product = product(&[read_inputs(), release_results()]);
    let greedy = request(
        &[read_inputs(), receive_credential(), connect_registry()],
        &[read_inputs()],
        &[],
    );
    let everything = delegation(&[read_inputs(), receive_credential(), connect_registry()]);
    let resolved = resolve(&product, &greedy, &everything);
    assert_eq!(*resolved.permitted(), set(&[read_inputs()]));
    assert!(resolved.permitted().is_subset(product.ceiling()));
    assert!(Host::ready().plan(&resolved).is_ok());

    // Claiming the broader right as essential refuses the launch instead.
    let insisting = request(
        &[read_inputs(), receive_credential()],
        &[receive_credential()],
        &[],
    );
    let refusal = Host::ready()
        .plan(&resolve(&product, &insisting, &everything))
        .unwrap_err();
    assert_eq!(
        refusal.reasons,
        vec![LaunchRefusalReason::RequiredAuthorityRemoved {
            tuple: receive_credential(),
            excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling]),
        }]
    );
}

#[test]
fn an_untrusted_template_cannot_drop_a_product_requirement() {
    let product = product_with(
        &[read_inputs()],
        &[
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable,
            SecurityPredicate::ContractNoExternalCredentials,
            SecurityPredicate::IndependentPerimeter,
        ],
        Vec::new(),
        BudgetSet::vm_d12_task_defaults().into(),
    );
    let silent = request(&[read_inputs()], &[], &[]);
    let resolved = resolve(&product, &silent, &delegation(&[read_inputs()]));
    assert!(product.requirements().is_subset(resolved.requirements()));
    let refusal = Host::ready().plan(&resolved).unwrap_err();
    assert_eq!(
        unmet(&refusal),
        BTreeSet::from([SecurityPredicate::IndependentPerimeter])
    );
}

#[test]
fn unknown_versions_requirements_and_fields_are_refused() {
    let mut doc = document(&[read_inputs()], &[], &["vm_sandbox", "teleport_shield"]);
    doc.schema_version = 2;
    assert_eq!(
        issues(Validator::request(&doc).unwrap_err()),
        vec![
            ValidationIssue::UnsupportedSchemaVersion { found: 2 },
            ValidationIssue::UnknownRequirement {
                name: "teleport_shield".to_owned()
            },
        ]
    );

    let mut value = serde_json::to_value(document(&[read_inputs()], &[], &[])).unwrap();
    assert!(Validator::request_json(&value.to_string()).is_ok());
    value["allow_everything"] = json!(true);
    let malformed = issues(Validator::request_json(&value.to_string()).unwrap_err());
    assert!(matches!(
        malformed.as_slice(),
        [ValidationIssue::Malformed { message }] if message.contains("allow_everything")
    ));

    let mut value = serde_json::to_value(document(&[read_inputs()], &[], &[])).unwrap();
    value["requested"][0]["operation"] = json!({"kind": "raw_socket"});
    assert!(matches!(
        issues(Validator::request_json(&value.to_string()).unwrap_err()).as_slice(),
        [ValidationIssue::Malformed { .. }]
    ));
    value["requested"][0]["operation"] = json!({"kind": "file_read", "path": "/"});
    assert!(matches!(
        issues(Validator::request_json(&value.to_string()).unwrap_err()).as_slice(),
        [ValidationIssue::Malformed { .. }]
    ));

    let bound = document(&[at(read_inputs(), E1)], &[], &[]);
    assert_eq!(
        issues(Validator::request(&bound).unwrap_err()),
        vec![ValidationIssue::GenerationBoundInLayer {
            layer: PolicyLayer::Request,
            tuple: at(read_inputs(), E1)
        }]
    );
    let unlisted = document(&[read_inputs()], &[write_outputs()], &[]);
    assert_eq!(
        issues(Validator::request(&unlisted).unwrap_err()),
        vec![ValidationIssue::DependencyNotRequested {
            tuple: write_outputs()
        }]
    );
    let mut mistyped = read_inputs();
    mistyped.resource.kind = ResourceKind::Route;
    assert_eq!(
        issues(Validator::request(&document(&[mistyped.clone()], &[], &[])).unwrap_err()),
        vec![ValidationIssue::OperationOnWrongResource {
            layer: PolicyLayer::Request,
            tuple: mistyped
        }]
    );
}

// ---- VM-W01: requirements, facets and old tiers ----

#[test]
fn old_tiers_migrate_to_predicates_or_refuse() {
    use SecurityPredicate as P;
    assert_eq!(
        LegacyTier::parse("T1").and_then(LegacyTier::migrate),
        Err(MigrationRefusal::SharedKernel)
    );
    let t2 = LegacyTier::T2.migrate().unwrap();
    assert_eq!(
        t2.iter().collect::<BTreeSet<_>>(),
        BTreeSet::from([
            P::VmSandbox,
            P::HardwareHypervisorAvailable,
            P::HardwareAcceleratedBoot,
            P::NoDirectGuestNetwork,
            P::ContractNoExternalCredentials,
            P::ContractBoundedLifetime,
        ])
    );
    let t3 = LegacyTier::T3.migrate().unwrap();
    assert!(t2.is_subset(&t3));
    assert_eq!(t3.len(), t2.len() + 5);
    for predicate in [
        P::HypervisorConfined,
        P::IndependentPerimeter,
        P::InnerGuestConfinement,
        P::BoundaryProbesPassed,
        P::InternalCanaries,
    ] {
        assert!(t3.contains(predicate));
    }
    assert_eq!(
        LegacyTier::T4.migrate(),
        Err(MigrationRefusal::AmbiguousOperator)
    );
    for unknown in ["t2", "T5", ""] {
        assert_eq!(
            LegacyTier::parse(unknown),
            Err(MigrationRefusal::Unknown {
                name: unknown.to_owned()
            })
        );
    }

    let mut old = document(&[read_inputs()], &[], &[]);
    old.legacy_tier = Some("T1".to_owned());
    assert_eq!(
        issues(Validator::request(&old).unwrap_err()),
        vec![ValidationIssue::LegacyTierRefused {
            refusal: MigrationRefusal::SharedKernel
        }]
    );
    // T2 is migrated, not weakened: the predicates without evidence refuse the launch.
    old.legacy_tier = Some("T2".to_owned());
    let migrated = Validator::request(&old).unwrap();
    assert!(t2.is_subset(migrated.requirements()));
    let resolved = resolve(
        &product(&[read_inputs()]),
        &migrated,
        &delegation(&[read_inputs()]),
    );
    let refusal = Host::ready().plan(&resolved).unwrap_err();
    assert_eq!(
        unmet(&refusal),
        BTreeSet::from([P::HardwareAcceleratedBoot, P::NoDirectGuestNetwork])
    );
}

#[test]
fn a_sandbox_product_policy_must_require_a_vm() {
    let refusal = Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![read_inputs()],
        requirements: vec![SecurityPredicate::HardwareHypervisorAvailable],
        approvals: Vec::new(),
        budgets: Vec::new(),
    })
    .unwrap_err();
    assert_eq!(
        refusal.issues,
        vec![ValidationIssue::ProductionSandboxWithoutVm]
    );
    assert!(refusal
        .to_string()
        .contains("no shared-kernel sandbox option"));
}

#[test]
fn facets_are_reported_separately_and_never_scored() {
    let product = product_with(
        &[read_inputs()],
        &[
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable,
            SecurityPredicate::ContractOffline,
            SecurityPredicate::ContractNoExternalCredentials,
        ],
        Vec::new(),
        BudgetSet::vm_d12_task_defaults().into(),
    );
    let resolved = resolve(
        &product,
        &request(&[read_inputs()], &[], &["contract_bounded_lifetime"]),
        &delegation(&[read_inputs()]),
    );
    let plan = Host::ready().plan(&resolved).unwrap();
    let facets = plan.facets();
    assert_eq!(
        facets.iter().map(|facet| facet.facet).collect::<Vec<_>>(),
        DeploymentFacet::ALL.to_vec()
    );
    let names = |facet: DeploymentFacet| -> Vec<SecurityPredicate> {
        facets
            .iter()
            .find(|report| report.facet == facet)
            .unwrap()
            .verdicts
            .iter()
            .map(|verdict| verdict.predicate)
            .collect()
    };
    assert_eq!(
        names(DeploymentFacet::Isolation),
        vec![
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable
        ]
    );
    assert_eq!(
        names(DeploymentFacet::NetworkAuthority),
        vec![SecurityPredicate::ContractOffline]
    );
    assert_eq!(
        names(DeploymentFacet::CredentialExposure),
        vec![SecurityPredicate::ContractNoExternalCredentials]
    );
    assert_eq!(
        names(DeploymentFacet::Persistence),
        vec![SecurityPredicate::ContractBoundedLifetime]
    );
    assert!(names(DeploymentFacet::OperatorConfidentiality).is_empty());
    assert!(names(DeploymentFacet::HypervisorConfinement).is_empty());
    for facet in DeploymentFacet::ALL {
        assert!(!facet.examples().is_empty());
    }
    // Every predicate has a stable name and lives in exactly one facet.
    for predicate in SecurityPredicate::ALL {
        assert_eq!(
            SecurityPredicate::from_name(predicate.name()),
            Some(predicate)
        );
        assert_eq!(
            serde_json::to_value(predicate).unwrap(),
            json!(predicate.name())
        );
        assert!(DeploymentFacet::ALL.contains(&predicate.facet()));
    }
}

// ---- contract predicates ----

#[test]
fn contract_predicates_describe_the_contract_and_refuse_violations() {
    let refusal = Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![read_inputs(), connect_registry()],
        requirements: vec![
            SecurityPredicate::VmSandbox,
            SecurityPredicate::ContractOffline,
        ],
        approvals: Vec::new(),
        budgets: BudgetSet::vm_d12_task_defaults().into(),
    })
    .unwrap_err();
    assert_eq!(
        refusal.issues,
        vec![ValidationIssue::ContractConflict {
            layer: PolicyLayer::ProductCeiling,
            predicate: SecurityPredicate::ContractOffline,
            tuple: connect_registry(),
        }]
    );
    let contradictory = document(&[connect_registry()], &[], &["contract_offline"]);
    assert_eq!(
        issues(Validator::request(&contradictory).unwrap_err()),
        vec![ValidationIssue::ContractConflict {
            layer: PolicyLayer::Request,
            predicate: SecurityPredicate::ContractOffline,
            tuple: connect_registry(),
        }]
    );

    let strict = product_with(
        &[read_inputs()],
        &[
            SecurityPredicate::VmSandbox,
            SecurityPredicate::ContractNoExternalCredentials,
        ],
        Vec::new(),
        Vec::new(),
    );
    let wants_key = request(&[receive_credential()], &[receive_credential()], &[]);
    let combination = issues(
        Validator::combination(&strict, &wants_key, &delegation(&[receive_credential()]))
            .unwrap_err(),
    );
    assert!(combination.contains(&ValidationIssue::ContractConflict {
        layer: PolicyLayer::Request,
        predicate: SecurityPredicate::ContractNoExternalCredentials,
        tuple: receive_credential(),
    }));

    // A request requiring bounded lifetime needs some layer to declare the budgets.
    let lifetime = request(&[read_inputs()], &[], &["contract_bounded_lifetime"]);
    let refusal = Host::ready()
        .plan(&resolve(&strict, &lifetime, &delegation(&[read_inputs()])))
        .unwrap_err();
    assert_eq!(
        outcome_of(&refusal, SecurityPredicate::ContractBoundedLifetime),
        PredicateOutcome::ContractBudgetMissing {
            keys: ContractConstraint::LifetimeBounded.required_budgets()
        }
    );
    let product = product(&[read_inputs()]);
    let plan = Host::ready()
        .plan(&resolve(&product, &lifetime, &delegation(&[read_inputs()])))
        .unwrap();
    assert!(plan.verdicts().contains(&PredicateVerdict {
        predicate: SecurityPredicate::ContractBoundedLifetime,
        outcome: PredicateOutcome::ContractHolds,
    }));
    // The product itself must declare the budgets of a contract predicate it requires.
    let refusal = Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![read_inputs()],
        requirements: vec![
            SecurityPredicate::VmSandbox,
            SecurityPredicate::ContractBoundedLifetime,
        ],
        approvals: Vec::new(),
        budgets: Vec::new(),
    })
    .unwrap_err();
    assert_eq!(refusal.issues.len(), 2);
}

#[test]
fn an_outbound_ceiling_needs_a_release_budget_and_rules_must_fit() {
    let refusal = Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![read_inputs(), release_results(), connect_registry()],
        requirements: vec![SecurityPredicate::VmSandbox],
        approvals: vec![rule(ApprovalKind::ExactRelease, &read_inputs())],
        budgets: Vec::new(),
    })
    .unwrap_err();
    assert_eq!(
        refusal.issues,
        vec![
            ValidationIssue::ApprovalDoesNotFit {
                layer: PolicyLayer::ProductCeiling,
                rule: rule(ApprovalKind::ExactRelease, &read_inputs()),
            },
            // Canonical tuple order, not the order the draft listed them in.
            ValidationIssue::OutboundWithoutReleaseBudget {
                tuple: connect_registry()
            },
            ValidationIssue::OutboundWithoutReleaseBudget {
                tuple: release_results()
            },
        ]
    );
}

// ---- canonical identity (§2.4 line 1804; VM-W02) ----

#[test]
fn the_contract_identity_is_canonical_and_order_independent() {
    let product = product(&[read_inputs(), write_outputs(), release_results()]);
    let approvals = vec![
        rule(ApprovalKind::PrivateDataAccess, &read_inputs()),
        rule(ApprovalKind::ExactRelease, &release_results()),
    ];
    let budgets = vec![
        budget(
            BudgetResource::ReleaseBytes,
            AccountingScope::Generation,
            MIB,
        ),
        budget(
            BudgetResource::ReleaseEffects,
            AccountingScope::Generation,
            3,
        ),
    ];
    let mut forward = document(
        &[read_inputs(), write_outputs(), release_results()],
        &[read_inputs(), write_outputs()],
        &["vm_sandbox", "contract_cpu_only"],
    );
    forward.approvals = approvals.clone();
    forward.budgets = budgets.clone();
    let mut backward = document(
        &[
            release_results(),
            write_outputs(),
            read_inputs(),
            read_inputs(),
        ],
        &[write_outputs(), read_inputs()],
        &["contract_cpu_only", "vm_sandbox", "vm_sandbox"],
    );
    backward.approvals = approvals.into_iter().rev().collect();
    backward.budgets = budgets.into_iter().rev().collect();
    let forward = Validator::request(&forward).unwrap();
    let backward = Validator::request(&backward).unwrap();
    assert_eq!(forward.identity(), backward.identity());
    let all = delegation(&[read_inputs(), write_outputs(), release_results()]);
    let left = resolve(&product, &forward, &all);
    let right = resolve(&product, &backward, &all);
    assert_eq!(left.identity(), right.identity());

    // Any change to what the contract says changes its identity.
    let narrower = resolve(
        &product,
        &forward,
        &delegation(&[read_inputs(), write_outputs()]),
    );
    assert_ne!(narrower.identity(), left.identity());
    let mut tighter = document(&[read_inputs()], &[], &[]);
    tighter.budgets = vec![budget(
        BudgetResource::ReleaseBytes,
        AccountingScope::Generation,
        MIB - 1,
    )];
    let base = resolve(
        &product,
        &request(&[read_inputs()], &[], &[]),
        &delegation(&[read_inputs()]),
    );
    let tightened = resolve(
        &product,
        &Validator::request(&tighter).unwrap(),
        &delegation(&[read_inputs()]),
    );
    assert_ne!(base.identity(), tightened.identity());
    let later = Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::new(2),
        ceiling: vec![read_inputs(), write_outputs(), release_results()],
        requirements: base_requirements(),
        approvals: Vec::new(),
        budgets: BudgetSet::vm_d12_task_defaults().into(),
    })
    .unwrap();
    let relaunched = resolve(
        &later,
        &request(&[read_inputs()], &[], &[]),
        &delegation(&[read_inputs()]),
    );
    assert_ne!(base.identity(), relaunched.identity());
    assert_eq!(
        ContractIdentity::DOMAIN,
        "yougori/sandbox-policy/contract/v1"
    );
}

#[test]
fn issuer_identity_is_separate_and_neither_is_evidence() {
    let product = product(&[read_inputs()]);
    let resolved = resolve(
        &product,
        &request(&[read_inputs()], &[], &[]),
        &delegation(&[read_inputs()]),
    );
    let first = IssuedContract {
        contract: resolved.identity(),
        issuer: IssuerIdentity::named("yougori-release"),
    };
    let second = IssuedContract {
        contract: resolved.identity(),
        issuer: IssuerIdentity::named("someone-else"),
    };
    assert_eq!(first.contract, second.contract);
    assert_ne!(first.issuer, second.issuer);
    assert_ne!(first.contract.digest(), first.issuer.digest());

    // The source of a request is provenance, not part of the contract.
    let mut renamed = document(&[read_inputs()], &[], &[]);
    renamed.source.name = SourceName::new("other-template").unwrap();
    let renamed = resolve(
        &product,
        &Validator::request(&renamed).unwrap(),
        &delegation(&[read_inputs()]),
    );
    assert_eq!(renamed.identity(), resolved.identity());

    // A well-identified, well-issued contract with no host evidence is still refused.
    let unobserved = Host::with_sources(
        ExecutionCategory::VmSandbox,
        SourceClass::HostProbe,
        SourceClass::HostProbe,
    );
    let refusal = unobserved.plan(&resolved).unwrap_err();
    assert_eq!(refusal.contract, first.contract);
    assert_eq!(unmet(&refusal).len(), 2);
}

// ---- runtime authorization (VM-W02; VM-P13) ----

#[test]
fn runtime_authorization_checks_principal_generation_epoch_and_endpoint() {
    let build_fetch = tuple(
        "build",
        Operation::TransportConnect,
        ResourceKind::Route,
        "registry",
        Phase::Fetch,
    );
    let product = product(&[read_inputs(), write_outputs(), build_fetch.clone()]);
    let request = request(
        &[read_inputs(), write_outputs(), build_fetch.clone()],
        &[read_inputs()],
        &[],
    );
    let resolved = resolve(
        &product,
        &request,
        &delegation(&[read_inputs(), write_outputs(), build_fetch.clone()]),
    );
    let host = Host::ready();
    let plan = host.plan(&resolved).unwrap();
    let mut evaluator = evaluator(&plan, &host, E1);
    let current = generations(E1);

    let allowed = evaluator
        .authorize(&ask(&read_inputs(), E1), current)
        .unwrap();
    assert_eq!(allowed.contract, plan.contract());
    assert_eq!(allowed.action, read_inputs().action());

    let mut stranger = ask(&read_inputs(), E1);
    stranger.execution = ExecutionId::new("exe-2").unwrap();
    assert!(matches!(
        evaluator.authorize(&stranger, current),
        Err(AuthorizationRefusal::WrongPrincipal { .. })
    ));
    let mut moved = current;
    moved.policy = PolicyEpoch::new(2);
    assert_eq!(
        evaluator.authorize(&ask(&read_inputs(), E1), moved),
        Err(AuthorizationRefusal::PolicyEpochChanged {
            bound: PolicyEpoch::FIRST,
            current: PolicyEpoch::new(2)
        })
    );
    assert_eq!(
        evaluator.authorize(&ask(&read_inputs(), E1), generations(E2)),
        Err(AuthorizationRefusal::AuthorizationRevoked {
            bound: E1,
            current: E2
        })
    );
    let mut rebooted = current;
    rebooted.boot = SandboxBootGeneration::new(2);
    assert!(matches!(
        evaluator.authorize(&ask(&read_inputs(), E1), rebooted),
        Err(AuthorizationRefusal::BootGenerationChanged { .. })
    ));
    let stale = ask(&read_inputs(), E2);
    assert_eq!(
        evaluator.authorize(&stale, current),
        Err(AuthorizationRefusal::StaleRequestGeneration {
            request: generations(E2),
            current
        })
    );
    let mut elsewhere = ask(&read_inputs(), E1);
    elsewhere.resource = ResourceRef::new(ResourceKind::FileGrant, "home").unwrap();
    assert!(matches!(
        evaluator.authorize(&elsewhere, current),
        Err(AuthorizationRefusal::NotPermitted { .. })
    ));
    let mut later = ask(&read_inputs(), E1);
    later.context.phase = Phase::Publication;
    assert!(matches!(
        evaluator.authorize(&later, current),
        Err(AuthorizationRefusal::NotPermitted { .. })
    ));
    // The build VM's route is not the main VM's, whatever the request says.
    assert!(matches!(
        evaluator.authorize(&ask(&build_fetch, E1), current),
        Err(AuthorizationRefusal::NotPermitted { .. })
    ));
    assert_eq!(
        plan.activate(binding("missing", E1), host.registry.now()),
        Err(ActivationRefusal::UnknownRole {
            role: RoleName::new("missing").unwrap()
        })
    );
}

#[test]
fn quota_is_checked_all_or_nothing_within_each_scope() {
    let product = product_with(
        &[read_inputs(), release_results()],
        &base_requirements(),
        Vec::new(),
        vec![
            budget(
                BudgetResource::ReleaseBytes,
                AccountingScope::Generation,
                100,
            ),
            budget(
                BudgetResource::ReleaseBytes,
                channel(&release_results()),
                60,
            ),
            budget(
                BudgetResource::ReleaseEffects,
                AccountingScope::Generation,
                2,
            ),
        ],
    );
    let resolved = resolve(
        &product,
        &request(&[read_inputs(), release_results()], &[], &[]),
        &delegation(&[read_inputs(), release_results()]),
    );
    let host = Host::ready();
    let plan = host.plan(&resolved).unwrap();
    let mut evaluator = evaluator(&plan, &host, E1);
    let generation = key(BudgetResource::ReleaseBytes, AccountingScope::Generation);
    let on_channel = key(BudgetResource::ReleaseBytes, channel(&release_results()));

    let mut release = ask(&release_results(), E1);
    assert_eq!(
        evaluator.authorize(&release, generations(E1)),
        Err(AuthorizationRefusal::ChargeMissing {
            resource: BudgetResource::ReleaseBytes
        })
    );
    release.charges.release_bytes = Some(50);
    assert_eq!(
        evaluator.authorize(&release, generations(E1)),
        Err(AuthorizationRefusal::ChargeMissing {
            resource: BudgetResource::ReleaseEffects
        })
    );
    release.charges.release_effects = Some(1);
    let allowed = evaluator.authorize(&release, generations(E1)).unwrap();
    assert_eq!(allowed.debits.len(), 3);
    assert_eq!(evaluator.remaining(&generation), Some(50));
    assert_eq!(evaluator.remaining(&on_channel), Some(10));

    release.charges.release_bytes = Some(20);
    assert_eq!(
        evaluator.authorize(&release, generations(E1)),
        Err(AuthorizationRefusal::QuotaExceeded {
            key: on_channel.clone(),
            remaining: 10,
            requested: 20
        })
    );
    // Nothing was charged by the refused request.
    assert_eq!(evaluator.remaining(&generation), Some(50));
    release.charges.release_bytes = Some(10);
    evaluator.authorize(&release, generations(E1)).unwrap();
    assert_eq!(
        evaluator.authorize(&release, generations(E1)),
        Err(AuthorizationRefusal::QuotaExceeded {
            key: on_channel,
            remaining: 0,
            requested: 10
        })
    );
    // Reading spends nothing.
    let read = evaluator
        .authorize(&ask(&read_inputs(), E1), generations(E1))
        .unwrap();
    assert!(read.debits.is_empty());
}

#[test]
fn execution_spending_carries_over_and_generation_spending_restarts() {
    let product = product_with(
        &[release_results()],
        &base_requirements(),
        Vec::new(),
        vec![
            budget(
                BudgetResource::ReleaseBytes,
                AccountingScope::Generation,
                80,
            ),
            budget(
                BudgetResource::ReleaseBytes,
                AccountingScope::Execution,
                100,
            ),
        ],
    );
    let resolved = resolve(
        &product,
        &request(&[release_results()], &[], &[]),
        &delegation(&[release_results()]),
    );
    let host = Host::ready();
    let plan = host.plan(&resolved).unwrap();
    let execution_key = key(BudgetResource::ReleaseBytes, AccountingScope::Execution);
    let generation_key = key(BudgetResource::ReleaseBytes, AccountingScope::Generation);

    let mut first = evaluator(&plan, &host, E1);
    let mut release = ask(&release_results(), E1);
    release.charges = Charges {
        release_bytes: Some(70),
        release_effects: Some(1),
        credential_effects: None,
    };
    first.authorize(&release, generations(E1)).unwrap();
    let carried = first.carried_spend();
    assert_eq!(carried.spent(&execution_key), 70);
    assert_eq!(carried.spent(&generation_key), 0);

    let active = plan
        .activate(binding("main", E2), host.registry.now())
        .unwrap();
    let mut second = Evaluator::new(active.clone(), carried).unwrap();
    assert_eq!(second.remaining(&generation_key), Some(80));
    assert_eq!(second.remaining(&execution_key), Some(30));
    let mut again = ask(&release_results(), E2);
    again.charges = release.charges;
    again.charges.release_bytes = Some(40);
    assert!(matches!(
        second.authorize(&again, generations(E2)),
        Err(AuthorizationRefusal::QuotaExceeded { remaining: 30, .. })
    ));

    let other = BudgetSpend::none(tenant(), ExecutionId::new("exe-9").unwrap());
    assert_eq!(
        Evaluator::new(active, other).unwrap_err(),
        EvaluatorRefusal::SpendForOtherExecution
    );
}

#[test]
fn a_delegation_bound_to_an_epoch_is_stale_at_any_other() {
    let product = product(&[read_inputs(), write_outputs()]);
    let host = Host::ready();
    let bound = delegation(&[at(read_inputs(), E1), write_outputs()]);

    // An epoch-bound grant cannot carry an essential dependency into a future launch.
    let essential = resolve(
        &product,
        &request(&[read_inputs(), write_outputs()], &[read_inputs()], &[]),
        &bound,
    );
    let refusal = host.plan(&essential).unwrap_err();
    assert_eq!(
        refusal.reasons,
        vec![LaunchRefusalReason::RequiredAuthorityRemoved {
            tuple: read_inputs(),
            excluded_by: BTreeSet::from([PolicyLayer::Delegation]),
        }]
    );

    let optional = resolve(
        &product,
        &request(&[read_inputs(), write_outputs()], &[write_outputs()], &[]),
        &bound,
    );
    let plan = host.plan(&optional).unwrap();
    let mut at_first = evaluator(&plan, &host, E1);
    assert!(at_first
        .authorize(&ask(&read_inputs(), E1), generations(E1))
        .is_ok());
    let mut at_second = evaluator(&plan, &host, E2);
    assert!(matches!(
        at_second.authorize(&ask(&read_inputs(), E2), generations(E2)),
        Err(AuthorizationRefusal::NotPermitted { .. })
    ));
    assert!(at_second
        .authorize(&ask(&write_outputs(), E2), generations(E2))
        .is_ok());
}

#[test]
fn activation_refuses_a_changed_policy_epoch_or_stale_evidence() {
    let resolved = resolve(
        &product(&[read_inputs()]),
        &request(&[read_inputs()], &[], &[]),
        &delegation(&[read_inputs()]),
    );
    let host = Host::ready();
    let plan = host.plan(&resolved).unwrap();
    let mut changed = binding("main", E1);
    changed.generations.policy = PolicyEpoch::new(2);
    assert_eq!(
        plan.activate(changed, host.registry.now()),
        Err(ActivationRefusal::PolicyEpochMismatch {
            planned: PolicyEpoch::FIRST,
            current: PolicyEpoch::new(2)
        })
    );
    let elsewhere = Host::ready();
    assert_eq!(
        plan.activate(binding("main", E1), elsewhere.registry.now()),
        Err(ActivationRefusal::EvidenceOtherClock)
    );
    host.clock.advance(MINUTE + Duration::from_nanos(1));
    assert!(matches!(
        plan.activate(binding("main", E1), host.registry.now()),
        Err(ActivationRefusal::EvidenceExpired { .. })
    ));
}

// ---- §12.3 model 1 ----

#[test]
fn model_one_holds_exhaustively_within_its_bounds() {
    let report = super::model::check().unwrap_or_else(|counterexample| panic!("{counterexample}"));
    assert_eq!(report.layer_combinations, 32 * 216 * 16);
    assert_eq!(report.launch_decisions, 884_736);
    // The enumeration is not vacuous: it reaches allowed launches and refusals that name
    // removed authority and unmet predicates together.
    assert!(report.allowed_launches > 0);
    assert!(report.refused_for_authority_and_evidence > 0);
    assert!(report.authorizations > 0);
    assert_eq!(report.contract_checks, 256 * 2 * 5);
    assert_eq!(report.approval_states, 64);
    assert_eq!(report.budget_states, 27 * 27 * 27);
}

// ---- §2.2 objectives and §2.3 bound ----

#[test]
fn objectives_keep_their_measurement_and_interpretation() {
    assert_eq!(Objective::ALL.len(), 8);
    for objective in Objective::ALL {
        assert!(!objective.measurement().is_empty());
        assert!(!objective.interpretation().supports_escape_probability());
    }
    assert_eq!(
        Objective::VmOnlyExecution.target().percent_of_launches(),
        Some(100)
    );
    assert_eq!(
        Objective::VmOnlyExecution.interpretation().statement(),
        "Target 100%; a container fallback is a failure"
    );
    assert_eq!(
        Objective::AuthorityReduction.interpretation().statement(),
        "Structural improvement, not escape probability"
    );
    assert_eq!(
        Objective::UnauthorizedEffects.target(),
        Target::ZeroObservedWithCorpus
    );
    assert_eq!(
        Objective::ReleaseBound.measurement(),
        "Maximum authorized outbound bytes/effects per generation"
    );
    assert_eq!(
        Objective::Persistence.interpretation().statement(),
        "Explicit inventory, no claim that all persistent data is harmless"
    );
}

#[test]
fn a_1_gib_to_1_mib_release_ceiling_is_1024x_in_that_ceiling_only() {
    let reduction = ScopedReduction::release_ceiling(GIB, MIB).unwrap();
    assert_eq!(
        reduction.factor(),
        ReductionFactor {
            numerator: 1024,
            denominator: 1
        }
    );
    assert_eq!(
        reduction.statement(),
        "1024× reduction in that byte ceiling (configured values, not a measurement)"
    );
    assert!(!reduction.is_measurement());
    assert_eq!(reduction.objective(), Objective::ReleaseBound);
    assert_eq!(
        reduction.objective().interpretation(),
        Interpretation::EnforcedBudget
    );
    assert!(!reduction
        .objective()
        .interpretation()
        .supports_escape_probability());
    // A 40-byte API key still fits under the lowered ceiling: leaking it stays possible.
    assert!(reduction.after_admits(40));
    assert!(!reduction.after_admits(MIB + 1));
}

#[test]
fn a_2000_s_to_2_s_revocation_delay_is_1000x_under_those_conditions_only() {
    let reduction =
        ScopedReduction::revocation_latency(2_000, 2, ValueProvenance::Hypothetical).unwrap();
    assert_eq!(reduction.factor().numerator, 1000);
    assert_eq!(reduction.factor().denominator, 1);
    assert!(!reduction.is_measurement());
    assert_eq!(
        reduction.statement(),
        "1000× latency improvement under those conditions (illustrative values, not a \
         measurement)"
    );
    let measured = ScopedReduction::revocation_latency(
        2_000,
        2,
        ValueProvenance::Measured {
            conditions: "the INT-02 drill".to_owned(),
        },
    )
    .unwrap();
    assert!(measured.is_measurement());
    assert!(measured
        .statement()
        .ends_with("(measured under the INT-02 drill)"));
    assert_eq!(
        ScopedReduction::release_ceiling(MIB, 0),
        Err(BoundError::ZeroValue)
    );
    assert_eq!(
        ScopedReduction::release_ceiling(MIB, GIB),
        Err(BoundError::NotAReduction)
    );
    assert_eq!(
        ScopedReduction::release_ceiling(3, 2)
            .unwrap()
            .factor()
            .to_string(),
        "3/2×"
    );
}

#[test]
fn the_zero_failure_bound_is_scoped_to_its_distribution() {
    let three_thousand = ZeroFailureBound::from_independent_trials(3_000).unwrap();
    let bound = three_thousand.upper_bound();
    assert!((bound - 0.000_998_08).abs() < 1e-7, "{bound}");
    assert!((bound - 0.001).abs() < 0.000_01);
    let one = ZeroFailureBound::from_independent_trials(1).unwrap();
    assert!((one.upper_bound() - 0.95).abs() < 1e-12);
    // Above zero for every N: zero failures never become impossibility.
    assert!(
        ZeroFailureBound::from_independent_trials(1_000_000_000)
            .unwrap()
            .upper_bound()
            > 0.0
    );
    // Duplicated cases are not independent evidence.
    let cases: Vec<_> = (0..3_000u64)
        .map(|case| digest("yougori/test/case/v1", &[&case.to_be_bytes()]))
        .collect();
    let doubled = ZeroFailureBound::from_cases(cases.iter().chain(cases.iter()).copied()).unwrap();
    assert_eq!(doubled.independent_trials(), 3_000);
    assert_eq!(doubled, three_thousand);
    assert_eq!(
        ZeroFailureBound::from_cases(Vec::new()),
        Err(BoundError::NoTrials)
    );
    assert!(three_thousand
        .scope()
        .contains("not unknown adversarial exploits"));
}

// ---- strict reading ----

#[test]
fn strict_enums_refuse_unknown_fields_and_refusals_round_trip() {
    assert!(serde_json::from_value::<Operation>(json!({"kind": "release", "to": "x"})).is_err());
    assert!(serde_json::from_value::<GenerationScope>(
        json!({"scope": "every_generation", "epoch": 1})
    )
    .is_err());
    assert!(serde_json::from_value::<AccountingScope>(json!({"scope": "tenant", "x": 0})).is_err());
    assert_eq!(
        serde_json::from_value::<Operation>(json!({"kind": "provider_operation", "name": "merge"}))
            .unwrap(),
        Operation::ProviderOperation {
            name: OperationName::new("merge").unwrap()
        }
    );
    assert!(serde_json::from_value::<ContractSchemaVersion>(json!(2)).is_err());
    assert_eq!(
        serde_json::from_value::<ContractSchemaVersion>(json!(1)).unwrap(),
        ContractSchemaVersion::CURRENT
    );

    let refusal = Host::ready()
        .plan(&resolve(
            &product(&[read_inputs()]),
            &request(&[read_inputs()], &[read_inputs()], &["internal_canaries"]),
            &delegation(&[]),
        ))
        .unwrap_err();
    let json = serde_json::to_value(&refusal).unwrap();
    assert_eq!(
        serde_json::from_value::<LaunchRefusal>(json).unwrap(),
        refusal
    );
    let issue = ValidationIssue::UnknownRequirement {
        name: "x".to_owned(),
    };
    let json = serde_json::to_value(&issue).unwrap();
    assert_eq!(json["issue"], "unknown_requirement");
    assert_eq!(
        serde_json::from_value::<ValidationIssue>(json).unwrap(),
        issue
    );
}

// ---- the independent perimeter through CORE-01 (VM §4.4 line 1989) ----

mod perimeter {
    use super::*;
    use crate::foundation::coordination::PerimeterId;
    use crate::foundation::evidence::PerimeterRuleSubject;
    use crate::foundation::ids::Digest;
    use crate::sandbox_contract::destinations::{
        DestinationPort, IpPrefix, PerimeterOptions, PerimeterPlatform, PerimeterProfile,
        PerimeterRule, PerimeterTarget, PortSelector, RuleAction,
    };

    fn broker_principal() -> Digest {
        digest("yougori/test/principal/v1", &[b"transport-broker"])
    }

    fn block(prefix: &str, length: u8) -> PerimeterRule {
        PerimeterRule {
            action: RuleAction::Block,
            prefix: IpPrefix::new(prefix.parse().unwrap(), length).unwrap(),
            ports: PortSelector::All,
        }
    }

    fn launch_perimeter(rules: Vec<PerimeterRule>) -> LaunchPerimeter {
        let options = PerimeterOptions::default();
        LaunchPerimeter {
            target: PerimeterTarget {
                machine: digest("yougori/test/machine/v1", &[b"host"]),
                perimeter: PerimeterId::new(digest("yougori/test/perimeter/v1", &[b"strict"])),
            },
            profile: PerimeterProfile::declare(
                PerimeterPlatform::Linux,
                options,
                PerimeterPlatform::Linux.required_properties(options),
                None,
                broker_principal(),
                rules,
            )
            .unwrap(),
            configuration: config(),
        }
    }

    /// A ready host behind `perimeter`, with a perimeter probe adapter of `source`.
    fn perimeter_host(perimeter: LaunchPerimeter, source: SourceClass) -> (Host, Arc<FakeProbe>) {
        let mut host = Host::ready();
        let probe = Arc::new(FakeProbe::new(Capability::PerimeterRuleEnforced, source));
        host.registry
            .register(Box::new(Arc::clone(&probe)))
            .unwrap();
        host.targets.perimeter = Some(perimeter);
        (host, probe)
    }

    fn observe(
        host: &mut Host,
        probe: &FakeProbe,
        subject: PerimeterRuleSubject,
        observation: Observation,
    ) {
        let subject = Subject::PerimeterRule(subject);
        probe.respond(&subject, observation);
        host.registry
            .refresh(Capability::PerimeterRuleEnforced, &subject)
            .unwrap();
    }

    fn enforced() -> Observation {
        Observation::supported(config(), HOUR, SupportDetail::PerimeterRuleEnforced)
    }

    fn subjects(host: &Host) -> Vec<(PerimeterRule, PerimeterRuleSubject)> {
        let perimeter = host.targets.perimeter.as_ref().unwrap();
        perimeter.profile.block_rule_subjects(perimeter.target)
    }

    fn perimeter_required() -> ResolvedPolicy {
        let product = product_with(
            &[read_inputs()],
            &[
                SecurityPredicate::VmSandbox,
                SecurityPredicate::HardwareHypervisorAvailable,
                SecurityPredicate::IndependentPerimeter,
            ],
            Vec::new(),
            BudgetSet::vm_d12_task_defaults().into(),
        );
        resolve(
            &product,
            &request(&[read_inputs()], &[], &[]),
            &delegation(&[read_inputs()]),
        )
    }

    fn missing() -> EvidenceRefusal {
        EvidenceRefusal::Missing {
            capability: Capability::PerimeterRuleEnforced,
        }
    }

    fn refused_rules(host: &Host) -> Vec<PerimeterRuleRefusal> {
        let refusal = host.plan(&perimeter_required()).unwrap_err();
        match outcome_of(&refusal, SecurityPredicate::IndependentPerimeter) {
            PredicateOutcome::PerimeterRulesRefused { refused } => refused,
            other => panic!("expected refused perimeter rules, got {other:?}"),
        }
    }

    #[test]
    fn the_independent_perimeter_is_verified_when_every_block_rule_is_enforced() {
        let rules = vec![block("10.0.0.0", 8), block("169.254.0.0", 16)];
        let (mut host, probe) = perimeter_host(launch_perimeter(rules), SourceClass::HostProbe);
        for (_, subject) in subjects(&host) {
            observe(&mut host, &probe, subject, enforced());
        }
        let plan = host.plan(&perimeter_required()).unwrap();
        let verdict = plan
            .verdicts()
            .iter()
            .find(|verdict| verdict.predicate == SecurityPredicate::IndependentPerimeter)
            .unwrap();
        assert!(matches!(
            verdict.outcome,
            PredicateOutcome::Verified {
                source: SourceClass::HostProbe,
                detail: SupportDetail::PerimeterRuleEnforced,
                ..
            }
        ));
    }

    #[test]
    fn one_unsatisfied_block_rule_fails_the_perimeter_predicate() {
        let lan = block("10.0.0.0", 8);
        let link_local = block("169.254.0.0", 16);
        let (mut host, probe) = perimeter_host(
            launch_perimeter(vec![lan, link_local]),
            SourceClass::HostProbe,
        );
        let (_, first) = subjects(&host)[0];
        observe(&mut host, &probe, first, enforced());
        let refusal = host.plan(&perimeter_required()).unwrap_err();
        assert_eq!(
            unmet(&refusal),
            BTreeSet::from([SecurityPredicate::IndependentPerimeter])
        );
        assert_eq!(
            refused_rules(&host),
            vec![PerimeterRuleRefusal {
                rule: link_local.digest(),
                refusal: missing(),
            }]
        );
        assert!(
            refusal.to_string().contains("not shown enforced"),
            "{refusal}"
        );
    }

    #[test]
    fn a_timeout_or_inconclusive_perimeter_probe_never_passes() {
        for reason in [
            UnknownReason::Inconclusive,
            UnknownReason::Unreachable,
            UnknownReason::NotTested,
        ] {
            let (mut host, probe) = perimeter_host(
                launch_perimeter(vec![block("10.0.0.0", 8)]),
                SourceClass::HostProbe,
            );
            let (_, subject) = subjects(&host)[0];
            observe(
                &mut host,
                &probe,
                subject,
                Observation::unknown(config(), HOUR, reason),
            );
            assert_eq!(
                refused_rules(&host)[0].refusal,
                EvidenceRefusal::Unknown {
                    capability: Capability::PerimeterRuleEnforced,
                    reason,
                }
            );
        }
        let (mut host, probe) = perimeter_host(
            launch_perimeter(vec![block("10.0.0.0", 8)]),
            SourceClass::HostProbe,
        );
        let (_, subject) = subjects(&host)[0];
        observe(
            &mut host,
            &probe,
            subject,
            Observation::unsupported(config(), HOUR, UnsupportedReason::NotEnforced),
        );
        assert_eq!(
            refused_rules(&host)[0].refusal.remedy(),
            Remedy::RepairPerimeter
        );
    }

    #[test]
    fn perimeter_evidence_for_another_rule_or_principal_does_not_count() {
        let lan = block("10.0.0.0", 8);
        let (mut host, probe) = perimeter_host(launch_perimeter(vec![lan]), SourceClass::HostProbe);
        let (_, subject) = subjects(&host)[0];
        let other_principal = PerimeterRuleSubject {
            principal: digest("yougori/test/principal/v1", &[b"test-runner"]),
            ..subject
        };
        let other_rule = PerimeterRuleSubject {
            rule: block("172.16.0.0", 12).digest(),
            ..subject
        };
        observe(&mut host, &probe, other_principal, enforced());
        observe(&mut host, &probe, other_rule, enforced());
        assert_eq!(
            refused_rules(&host),
            vec![PerimeterRuleRefusal {
                rule: lan.digest(),
                refusal: missing(),
            }]
        );
    }

    #[test]
    fn a_guest_reported_or_stale_perimeter_check_is_refused() {
        let (mut guest, probe) = perimeter_host(
            launch_perimeter(vec![block("10.0.0.0", 8)]),
            SourceClass::GuestReport,
        );
        let (_, subject) = subjects(&guest)[0];
        observe(&mut guest, &probe, subject, enforced());
        assert_eq!(
            refused_rules(&guest)[0].refusal,
            EvidenceRefusal::SourceTooWeak {
                capability: Capability::PerimeterRuleEnforced,
                observed: SourceClass::GuestReport,
                required: SourceClass::HostProbe,
            }
        );
        let (mut host, probe) = perimeter_host(
            launch_perimeter(vec![block("10.0.0.0", 8)]),
            SourceClass::HostProbe,
        );
        let (_, subject) = subjects(&host)[0];
        observe(&mut host, &probe, subject, enforced());
        host.clock.advance(MINUTE + Duration::from_nanos(1));
        assert!(matches!(
            refused_rules(&host)[0].refusal,
            EvidenceRefusal::Stale { .. }
        ));
    }

    #[test]
    fn no_declared_perimeter_or_no_block_rules_leaves_the_predicate_unmet() {
        let refusal = Host::ready().plan(&perimeter_required()).unwrap_err();
        assert_eq!(
            outcome_of(&refusal, SecurityPredicate::IndependentPerimeter),
            PredicateOutcome::NoPerimeterRules
        );
        let allow_only = PerimeterRule {
            action: RuleAction::Allow,
            prefix: IpPrefix::host("93.184.216.34".parse().unwrap()),
            ports: PortSelector::Only(DestinationPort::new(443).unwrap()),
        };
        let (host, _) = perimeter_host(launch_perimeter(vec![allow_only]), SourceClass::HostProbe);
        let refusal = host.plan(&perimeter_required()).unwrap_err();
        assert_eq!(
            outcome_of(&refusal, SecurityPredicate::IndependentPerimeter),
            PredicateOutcome::NoPerimeterRules
        );
        assert!(
            refusal.to_string().contains("no perimeter block rules"),
            "{refusal}"
        );
    }

    #[test]
    fn launch_targets_read_with_or_without_a_perimeter() {
        let (host, _) = perimeter_host(
            launch_perimeter(vec![block("10.0.0.0", 8)]),
            SourceClass::HostProbe,
        );
        let value = serde_json::to_value(&host.targets).unwrap();
        assert_eq!(
            serde_json::from_value::<LaunchTargets>(value.clone()).unwrap(),
            host.targets
        );
        let mut without = value.clone();
        without.as_object_mut().unwrap().remove("perimeter");
        assert_eq!(
            serde_json::from_value::<LaunchTargets>(without)
                .unwrap()
                .perimeter,
            None
        );
        let mut unknown = value;
        unknown["perimeter"]["extra"] = json!(true);
        assert!(serde_json::from_value::<LaunchTargets>(unknown).is_err());
    }
}

// ---- follow-up: user-authored requests, shared route names, credential budgets ----

fn user_document(
    requested: &[PermissionTuple],
    dependencies: &[PermissionTuple],
    requires: &[&str],
) -> RequestDocument {
    let mut document = document(requested, dependencies, requires);
    document.source.kind = SourceKind::User;
    document
}

#[test]
fn a_user_authored_request_is_validated_and_resolved_like_any_other_and_never_widens() {
    let product = product(&[read_inputs(), release_results()]);
    let everything = delegation(&[read_inputs(), receive_credential(), connect_registry()]);
    let greedy = Validator::request(&user_document(
        &[read_inputs(), receive_credential(), connect_registry()],
        &[read_inputs()],
        &[],
    ))
    .unwrap();
    assert_eq!(greedy.source().kind, SourceKind::User);
    let resolved = resolve(&product, &greedy, &everything);
    assert_eq!(*resolved.permitted(), set(&[read_inputs()]));
    assert!(resolved.permitted().is_subset(product.ceiling()));
    assert!(product.requirements().is_subset(resolved.requirements()));
    assert_eq!(resolved.source().kind, SourceKind::User);
    // Insisting on the broader right refuses the launch, exactly as for a template.
    let insisting = Validator::request(&user_document(
        &[read_inputs(), receive_credential()],
        &[receive_credential()],
        &[],
    ))
    .unwrap();
    assert_eq!(
        Host::ready()
            .plan(&resolve(&product, &insisting, &everything))
            .unwrap_err()
            .reasons,
        vec![LaunchRefusalReason::RequiredAuthorityRemoved {
            tuple: receive_credential(),
            excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling]),
        }]
    );
    // The same validation rules: unknown requirements, versions and epoch-bound tuples.
    let mut unknown = user_document(&[read_inputs()], &[], &["trust_me"]);
    unknown.schema_version = 2;
    unknown.requested.push(at(write_outputs(), E1));
    let found = issues(Validator::request(&unknown).unwrap_err());
    assert!(found.contains(&ValidationIssue::UnsupportedSchemaVersion { found: 2 }));
    assert!(found.contains(&ValidationIssue::UnknownRequirement {
        name: "trust_me".to_owned()
    }));
    assert!(found.contains(&ValidationIssue::GenerationBoundInLayer {
        layer: PolicyLayer::Request,
        tuple: at(write_outputs(), E1),
    }));
    // The source kind is provenance: it changes the request identity, never the contract.
    let as_template = Validator::request(&document(&[read_inputs()], &[], &[])).unwrap();
    let as_user = Validator::request(&user_document(&[read_inputs()], &[], &[])).unwrap();
    assert_ne!(as_template.identity(), as_user.identity());
    let delegated = delegation(&[read_inputs()]);
    assert_eq!(
        resolve(&product, &as_template, &delegated).identity(),
        resolve(&product, &as_user, &delegated).identity()
    );
    assert_eq!(
        serde_json::to_value(SourceKind::User).unwrap(),
        json!("user")
    );
    assert_eq!(SourceKind::User.tag(), "user");
}

#[test]
fn route_resources_are_named_by_the_shared_route_reference() {
    use crate::sandbox_contract::destinations::{route_reference, Authority, DestinationPort};
    let authority = |text: &str| Authority::parse(text, DestinationPort::HTTPS).unwrap();
    let canonical = ResourceRef::new(ResourceKind::Route, "registry.example.com:443").unwrap();
    for spelling in [
        "registry.example.com",
        "Registry.Example.COM",
        "registry.example.com:443",
    ] {
        let route = ResourceRef::route(&authority(spelling)).unwrap();
        assert_eq!(route, canonical);
        assert_eq!(route.name.as_str(), route_reference(&authority(spelling)));
    }
    assert_eq!(
        ResourceRef::route(&authority("registry.example.com:8443"))
            .unwrap()
            .name
            .as_str(),
        "registry.example.com:8443"
    );
    // A reference outside the identifier grammar is refused, never rewritten.
    assert!(ResourceRef::route(&authority("[2001:db8::1]:443")).is_err());
    // A ceiling and a request that name one destination differently still meet.
    let connect = |spelling: &str| PermissionTuple {
        resource: ResourceRef::route(&authority(spelling)).unwrap(),
        ..connect_registry()
    };
    let product = product(&[connect("REGISTRY.example.com")]);
    let resolved = resolve(
        &product,
        &request(&[connect("registry.example.com:443")], &[], &[]),
        &delegation(&[connect("registry.example.com")]),
    );
    assert_eq!(resolved.permitted().len(), 1);
}

#[test]
fn a_short_lived_credential_budget_takes_minima_and_is_charged_per_delivery() {
    let resource = BudgetResource::ShortLivedCredentialEffects;
    assert_eq!(resource.unit(), BudgetUnit::Effects);
    assert!(resource.is_spent_per_request());
    assert_eq!(resource.tag(), "short_lived_credential_effects");
    for operation in [
        Operation::ReceiveExternalCredential,
        Operation::Release,
        Operation::FileRead,
    ] {
        assert_eq!(
            operation.consumes(resource),
            operation == Operation::ReceiveExternalCredential
        );
    }
    let on_key = channel(&receive_credential());
    let product_budget = budget(resource, on_key.clone(), 10);
    let mut budgets: Vec<Budget> = BudgetSet::vm_d12_task_defaults().into();
    budgets.push(product_budget);
    let product = product_with(
        &[receive_credential()],
        &base_requirements(),
        Vec::new(),
        budgets,
    );
    let everything = delegation(&[receive_credential()]);
    let credential_key = key(resource, on_key.clone());
    // A request can lower the limit but never raise it; another scope is a separate limit.
    for (asked, effective) in [(1_000, 10), (3, 3)] {
        let mut asking = document(&[receive_credential()], &[], &[]);
        asking.budgets = vec![
            budget(resource, on_key.clone(), asked),
            budget(resource, AccountingScope::Generation, 50),
        ];
        let resolved = resolve(&product, &Validator::request(&asking).unwrap(), &everything);
        assert_eq!(resolved.budgets().limit(&credential_key), Some(effective));
        assert_eq!(
            resolved
                .budgets()
                .limit(&key(resource, AccountingScope::Generation)),
            Some(50)
        );
    }
    // Listed twice in one layer, it is ambiguous and refused.
    let mut twice = document(&[receive_credential()], &[], &[]);
    twice.budgets = vec![
        budget(resource, on_key.clone(), 1),
        budget(resource, on_key, 2),
    ];
    assert!(Validator::request(&twice).is_err());

    // Each delivery is charged the effects the minted credential delegates.
    let resolved = resolve(
        &product,
        &request(&[receive_credential()], &[], &[]),
        &everything,
    );
    let host = Host::ready();
    let plan = host.plan(&resolved).unwrap();
    let mut evaluator = evaluator(&plan, &host, E1);
    let mut deliver = ask(&receive_credential(), E1);
    assert_eq!(
        evaluator.authorize(&deliver, generations(E1)),
        Err(AuthorizationRefusal::ChargeMissing { resource })
    );
    deliver.charges.credential_effects = Some(7);
    evaluator.authorize(&deliver, generations(E1)).unwrap();
    assert_eq!(evaluator.remaining(&credential_key), Some(3));
    deliver.charges.credential_effects = Some(4);
    assert_eq!(
        evaluator.authorize(&deliver, generations(E1)),
        Err(AuthorizationRefusal::QuotaExceeded {
            key: credential_key.clone(),
            remaining: 3,
            requested: 4
        })
    );
    assert_eq!(evaluator.remaining(&credential_key), Some(3));
}

// ---- §4.5: a ceiling that grants credential receipt names its delegated budget ----

fn credential_product(budgets: Vec<Budget>) -> Result<ProductPolicy, ValidationRefusal> {
    let mut all: Vec<Budget> = BudgetSet::vm_d12_task_defaults().into();
    all.extend(budgets);
    Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![read_inputs(), receive_credential()],
        requirements: base_requirements(),
        approvals: Vec::new(),
        budgets: all,
    })
}

#[test]
fn a_ceiling_granting_credential_receipt_without_a_delegated_budget_is_refused() {
    let missing = ValidationIssue::CredentialWithoutDelegatedBudget {
        tuple: receive_credential(),
    };
    // No budget at all, a budget of another resource, or a channel budget on another
    // credential: none bounds this credential.
    let other_credential = ResourceRef::new(ResourceKind::Credential, "weights-url").unwrap();
    for budgets in [
        Vec::new(),
        vec![budget(
            BudgetResource::ReleaseEffects,
            AccountingScope::Generation,
            5,
        )],
        vec![budget(
            BudgetResource::ShortLivedCredentialEffects,
            AccountingScope::Channel {
                resource: other_credential,
            },
            5,
        )],
    ] {
        assert_eq!(
            issues(credential_product(budgets).unwrap_err()),
            vec![missing.clone()]
        );
    }
    assert_eq!(
        missing.to_string(),
        format!(
            "the product ceiling permits delivering an external credential without a \
             delegated budget of short-lived credential effects that applies to it: {}",
            receive_credential()
        )
    );
    // Every credential tuple is checked on its own, signed download URLs included: they
    // are delivered by the same operation and are still credentials.
    let signed_url = tuple(
        "main",
        Operation::ReceiveExternalCredential,
        ResourceKind::Credential,
        "weights-url",
        Phase::Fetch,
    );
    let refusal = Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![receive_credential(), signed_url.clone()],
        requirements: base_requirements(),
        approvals: Vec::new(),
        budgets: vec![budget(
            BudgetResource::ShortLivedCredentialEffects,
            channel(&receive_credential()),
            5,
        )],
    })
    .unwrap_err();
    assert_eq!(
        issues(refusal),
        vec![ValidationIssue::CredentialWithoutDelegatedBudget { tuple: signed_url }]
    );
    // A ceiling without credential receipt needs no such budget.
    assert!(Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![read_inputs()],
        requirements: base_requirements(),
        approvals: Vec::new(),
        budgets: Vec::new(),
    })
    .is_ok());
}

#[test]
fn a_generation_scoped_delegated_budget_bounds_every_credential() {
    let product = credential_product(vec![budget(
        BudgetResource::ShortLivedCredentialEffects,
        AccountingScope::Generation,
        5,
    )])
    .unwrap();
    assert_eq!(
        product.budgets().limit(&key(
            BudgetResource::ShortLivedCredentialEffects,
            AccountingScope::Generation
        )),
        Some(5)
    );
}

#[test]
fn a_channel_budget_on_the_credential_bounds_it() {
    let product = credential_product(vec![budget(
        BudgetResource::ShortLivedCredentialEffects,
        channel(&receive_credential()),
        5,
    )])
    .unwrap();
    let resolved = resolve(
        &product,
        &request(&[receive_credential()], &[], &[]),
        &delegation(&[receive_credential()]),
    );
    assert_eq!(
        resolved.budgets().limit(&key(
            BudgetResource::ShortLivedCredentialEffects,
            channel(&receive_credential())
        )),
        Some(5)
    );
    assert!(Host::ready().plan(&resolved).is_ok());
}
