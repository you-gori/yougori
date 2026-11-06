//! Declarations, compilation, refusal codes and non-interactive runs, on V01's real
//! validator, resolver and planner with fake CORE-01 probes driven by a manual clock.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::*;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, Capability as ProbeCapability, ConfigurationFingerprint,
    HypervisorKind, HypervisorSubject, Observation, ProbeRegistry, RuntimeSubject, SourceClass,
    Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ExecutionCategory, ManualClock, MonotonicTime, PolicyEpoch,
};
use crate::sandbox_contract::policy::{
    plan_launch, resolve, AccountingScope, ApprovalGrant, ApprovalKind, ApprovalRule, Budget,
    BudgetKey, BudgetResource, BudgetSet, Context, Delegation, DelegationDraft, GenerationScope,
    LaunchPlan, LaunchRefusal, LaunchRefusalReason, LaunchTargets, MigrationRefusal, Operation,
    OperationName, PermissionTuple, Phase, PolicyLayer, PredicateOutcome, Principal, ProductPolicy,
    ProductPolicyDraft, ResolvedPolicy, ResourceKind, ResourceName, ResourceRef, RoleName,
    SecurityPredicate, SourceKind, ValidationIssue, Validator, CONTRACT_SCHEMA_VERSION,
};

pub(super) const HOUR: Duration = Duration::from_secs(3_600);
pub(super) const MINUTE: Duration = Duration::from_secs(60);
pub(super) const MIB: u64 = 1024 * 1024;
pub(super) const E1: AuthorizationEpoch = AuthorizationEpoch::FIRST;
pub(super) const E2: AuthorizationEpoch = AuthorizationEpoch::new(2);

// ---- fixtures ----

pub(super) fn tuple(
    operation: Operation,
    kind: ResourceKind,
    name: &str,
    phase: Phase,
) -> PermissionTuple {
    PermissionTuple {
        principal: Principal::role("main").unwrap(),
        operation,
        resource: ResourceRef::new(kind, name).unwrap(),
        context: Context { phase },
        generation: GenerationScope::EveryGeneration,
    }
}

pub(super) fn read_inputs() -> PermissionTuple {
    tuple(
        Operation::FileRead,
        ResourceKind::FileGrant,
        "inputs",
        Phase::Analysis,
    )
}

pub(super) fn write_outputs() -> PermissionTuple {
    tuple(
        Operation::FileWrite,
        ResourceKind::FileGrant,
        "outputs",
        Phase::Analysis,
    )
}

pub(super) fn connect_registry() -> PermissionTuple {
    tuple(
        Operation::TransportConnect,
        ResourceKind::Route,
        "registry.example.com:443",
        Phase::Fetch,
    )
}

pub(super) fn release_results() -> PermissionTuple {
    tuple(
        Operation::Release,
        ResourceKind::ReleaseChannel,
        "results",
        Phase::Publication,
    )
}

pub(super) fn create_issue() -> PermissionTuple {
    tuple(
        Operation::ProviderOperation {
            name: OperationName::new("issues.create").unwrap(),
        },
        ResourceKind::ProviderAccount,
        "forge",
        Phase::Analysis,
    )
}

pub(super) fn base_tuples() -> Vec<PermissionTuple> {
    vec![
        read_inputs(),
        write_outputs(),
        connect_registry(),
        release_results(),
        create_issue(),
    ]
}

pub(super) fn rule(kind: ApprovalKind, tuple: &PermissionTuple) -> ApprovalRule {
    ApprovalRule {
        kind,
        operation: tuple.operation.clone(),
        resource: tuple.resource.clone(),
    }
}

pub(super) fn product_with(
    ceiling: &[PermissionTuple],
    requirements: &[SecurityPredicate],
    approvals: Vec<ApprovalRule>,
) -> ProductPolicy {
    Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: ceiling.to_vec(),
        requirements: requirements.to_vec(),
        approvals,
        budgets: host_budgets(),
    })
    .unwrap()
}

/// The VM-D12 defaults plus a generation-wide delegated budget for short-lived
/// credentials, which V01 requires of any ceiling that grants credential receipt (§4.5).
pub(super) fn host_budgets() -> Vec<Budget> {
    let mut budgets: Vec<Budget> = BudgetSet::vm_d12_task_defaults().into();
    budgets.push(Budget {
        resource: BudgetResource::ShortLivedCredentialEffects,
        scope: AccountingScope::Generation,
        limit: HOST_CREDENTIAL_EFFECTS,
    });
    budgets
}

pub(super) const HOST_CREDENTIAL_EFFECTS: u64 = 100;

pub(super) fn product(ceiling: &[PermissionTuple]) -> ProductPolicy {
    product_with(
        ceiling,
        &[
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable,
        ],
        Vec::new(),
    )
}

pub(super) fn delegation(granted: &[PermissionTuple]) -> Delegation {
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

/// A host whose runtime-category and hypervisor probes are host probes.
pub(super) struct Host {
    pub(super) registry: ProbeRegistry<Arc<ManualClock>>,
    pub(super) targets: LaunchTargets,
}

impl Host {
    /// A host running `category`, observed by host probes, with a hypervisor available.
    pub(super) fn running(category: ExecutionCategory) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category_probe = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        let hypervisor_probe = Arc::new(FakeProbe::new(
            ProbeCapability::HypervisorAvailable,
            SourceClass::HostProbe,
        ));
        registry
            .register(Box::new(Arc::clone(&category_probe)))
            .unwrap();
        registry
            .register(Box::new(Arc::clone(&hypervisor_probe)))
            .unwrap();
        let targets = LaunchTargets {
            runtime: RuntimeSubject {
                category,
                release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                instance: digest("yougori/test/instance/v1", &[b"sandbox-1"]),
            },
            runtime_configuration: config(),
            hypervisor: HypervisorSubject {
                machine: digest("yougori/test/machine/v1", &[b"workstation"]),
                hypervisor: HypervisorKind::Whpx,
            },
            hypervisor_configuration: config(),
            max_age: MINUTE,
            perimeter: None,
        };
        let runtime = Subject::Runtime(targets.runtime.clone());
        category_probe.respond(
            &runtime,
            Observation::supported(config(), HOUR, SupportDetail::RuntimeCategory { category }),
        );
        registry
            .refresh(ProbeCapability::RuntimeCategory, &runtime)
            .unwrap();
        let hypervisor = Subject::Hypervisor(targets.hypervisor);
        hypervisor_probe.respond(
            &hypervisor,
            Observation::supported(
                config(),
                HOUR,
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Whpx,
                },
            ),
        );
        registry
            .refresh(ProbeCapability::HypervisorAvailable, &hypervisor)
            .unwrap();
        Self { registry, targets }
    }

    pub(super) fn ready() -> Self {
        Self::running(ExecutionCategory::VmSandbox)
    }

    pub(super) fn evaluate(
        &self,
        text: &str,
        product: &ProductPolicy,
        delegation: &Delegation,
    ) -> Result<Evaluation, RefusalReport> {
        evaluate(text, product, delegation, &self.registry, &self.targets)
    }

    pub(super) fn plan(&self, resolved: &ResolvedPolicy) -> Result<LaunchPlan, LaunchRefusal> {
        plan_launch(resolved, &self.registry, &self.targets)
    }
}

pub(super) fn cap(need: &str, phase: &str, capability: Value) -> Value {
    json!({"need": need, "role": "main", "phase": phase, "capability": capability})
}

pub(super) fn base_capabilities() -> Vec<Value> {
    vec![
        cap(
            "required",
            "analysis",
            json!({"kind": "read_input", "grant": "inputs", "data_class": "user_private_content"}),
        ),
        cap(
            "required",
            "analysis",
            json!({"kind": "write_output", "grant": "outputs"}),
        ),
        cap(
            "optional",
            "fetch",
            json!({"kind": "connect", "destination": "registry.example.com"}),
        ),
        {
            let mut release = cap(
                "required",
                "publication",
                json!({"kind": "release", "channel": "results"}),
            );
            release["approval"] = json!("exact_release");
            release
        },
        {
            let mut operation = cap(
                "required",
                "analysis",
                json!({"kind": "provider_operation", "account": "forge", "operation": "issues.create"}),
            );
            operation["approval"] = json!("ongoing_delegation");
            operation
        },
    ]
}

pub(super) fn declaration(capabilities: Vec<Value>) -> Value {
    json!({
        "declaration_version": 1,
        "source": {"kind": "tool", "name": "report-writer"},
        "sandboxes": [{"role": "main", "profile": "task", "persistence": "ephemeral"}],
        "capabilities": capabilities,
    })
}

pub(super) fn base() -> Value {
    declaration(base_capabilities())
}

pub(super) fn text(value: &Value) -> String {
    serde_json::to_string(value).unwrap()
}

/// Reads and compiles; the compiled declaration or the refusal report.
pub(super) fn compile_value(value: &Value) -> Result<CompiledDeclaration, RefusalReport> {
    read_declaration(&text(value))?.compile()
}

pub(super) fn refusal_of(value: &Value) -> RefusalReport {
    match compile_value(value).and_then(|compiled| compiled.validate().map(|_| compiled)) {
        Ok(_) => panic!("expected a refusal for {value}"),
        Err(report) => report,
    }
}

pub(super) fn only(report: &RefusalReport) -> &RefusalDetail {
    assert_eq!(report.refusals().len(), 1, "{report}");
    &report.refusals()[0].detail
}

/// One example detail per code (VM-W54: "help, error codes and examples match"). The
/// match is exhaustive, so a new code without an example does not compile.
pub(super) fn example(code: RefusalCode) -> RefusalDetail {
    use RefusalCode as C;
    use RefusalDetail as D;
    let role = RoleName::new("main").unwrap();
    let name = ResourceName::new("api-key").unwrap();
    let key = BudgetKey {
        resource: BudgetResource::ReleaseBytes,
        scope: AccountingScope::Generation,
    };
    match code {
        C::DeclarationNotJson => D::DeclarationNotJson {
            message: "expected value at line 1 column 1".to_owned(),
        },
        C::DeclarationNotObject => D::DeclarationNotObject,
        C::DeclarationVersionMissing => D::DeclarationVersionMissing,
        C::UnsupportedDeclarationVersion => D::UnsupportedDeclarationVersion {
            found: "2".to_owned(),
        },
        C::AuthorityField => D::AuthorityField {
            path: "$.delegation".to_owned(),
            field: "delegation".to_owned(),
        },
        C::UnknownCapability => D::UnknownCapability {
            path: "$.capabilities[0].capability.kind".to_owned(),
            name: "clipboard".to_owned(),
        },
        C::UnknownExtensionRuntime => D::UnknownExtensionRuntime {
            path: "$.extensions[0].runtime".to_owned(),
            name: "jvm".to_owned(),
        },
        C::UnknownField => D::UnknownField {
            field: "colour".to_owned(),
        },
        C::InvalidDeclaration => D::InvalidDeclaration {
            message: "missing field `sandboxes`".to_owned(),
        },
        C::NoSandbox => D::NoSandbox,
        C::DuplicateSandboxRole => D::DuplicateSandboxRole { role },
        C::UndeclaredSandboxRole => D::UndeclaredSandboxRole {
            role,
            path: "$.capabilities[0]".to_owned(),
        },
        C::DuplicateCapability => D::DuplicateCapability {
            tuple: read_inputs(),
        },
        C::DuplicateExtension => D::DuplicateExtension {
            name: ExtensionName::new("formatter").unwrap(),
        },
        C::WildcardDestination => D::WildcardDestination {
            destination: "*.example.com".to_owned(),
        },
        C::DestinationNotAName => D::DestinationNotAName {
            destination: "10.0.0.1".to_owned(),
        },
        C::InvalidDestination => D::InvalidDestination {
            destination: "localhost".to_owned(),
            reason: "a single label".to_owned(),
        },
        C::LabelledRuntime => D::LabelledRuntime {
            subject: "sandbox \"main\"".to_owned(),
            category: ExecutionCategory::SharedKernelGpuRuntime,
        },
        C::CredentialNeverDelivered => D::CredentialNeverDelivered { name },
        C::CanaryNotRequestable => D::CanaryNotRequestable { name },
        C::VolumeOnEphemeralSandbox => D::VolumeOnEphemeralSandbox {
            role,
            volume: ResourceName::new("cache").unwrap(),
        },
        C::ApprovalWithoutOperation => D::ApprovalWithoutOperation {
            path: "$.capabilities[0].approval".to_owned(),
        },
        C::RequestMalformed => D::RequestMalformed {
            message: "missing field `source`".to_owned(),
        },
        C::UnsupportedContractSchema => D::UnsupportedContractSchema { found: 9 },
        C::UnknownRequirement => D::UnknownRequirement {
            name: "quantum_shield".to_owned(),
        },
        C::LegacyTierRefused => D::LegacyTierRefused {
            refusal: MigrationRefusal::SharedKernel,
        },
        C::GenerationBoundInLayer => D::GenerationBoundInLayer {
            layer: PolicyLayer::Request,
            tuple: read_inputs(),
        },
        C::OperationOnWrongResource => D::OperationOnWrongResource {
            layer: PolicyLayer::Request,
            tuple: read_inputs(),
        },
        C::ApprovalDoesNotFit => D::ApprovalDoesNotFit {
            layer: PolicyLayer::Request,
            rule: rule(ApprovalKind::ExactRelease, &read_inputs()),
        },
        C::DuplicateBudget => D::DuplicateBudget {
            layer: PolicyLayer::Request,
            key,
        },
        C::DependencyNotRequested => D::DependencyNotRequested {
            tuple: read_inputs(),
        },
        C::ProductionSandboxWithoutVm => D::ProductionSandboxWithoutVm,
        C::OutboundWithoutReleaseBudget => D::OutboundWithoutReleaseBudget {
            tuple: release_results(),
        },
        C::CredentialWithoutDelegatedBudget => D::CredentialWithoutDelegatedBudget {
            tuple: tuple(
                Operation::ReceiveExternalCredential,
                ResourceKind::Credential,
                "upload-token",
                Phase::Analysis,
            ),
        },
        C::ContractConflict => D::ContractConflict {
            layer: PolicyLayer::Request,
            predicate: SecurityPredicate::ContractOffline,
            tuple: connect_registry(),
        },
        C::ContractBudgetMissing => D::ContractBudgetMissing {
            layer: PolicyLayer::ProductCeiling,
            predicate: SecurityPredicate::ContractBoundedLifetime,
            key,
        },
        C::DependencyOutsideLayer => D::DependencyOutsideLayer {
            layer: PolicyLayer::Delegation,
            tuple: release_results(),
        },
        C::RequiredAuthorityRemoved => D::RequiredAuthorityRemoved {
            tuple: release_results(),
            excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling, PolicyLayer::Delegation]),
        },
        C::RequirementUnmet => D::RequirementUnmet {
            predicate: SecurityPredicate::AssignedGpuIsolated,
            outcome: PredicateOutcome::NoEvidenceCapability {
                needed: "IOMMU group, reset and detach evidence".to_owned(),
            },
        },
        C::NoHostEvidence => D::NoHostEvidence,
        C::AuthorizationMissing => D::AuthorizationMissing {
            tuple: release_results(),
        },
        C::ApprovalRequired => D::ApprovalRequired {
            rule: rule(ApprovalKind::ExactRelease, &release_results()),
        },
        C::LaunchNotPlanned => D::LaunchNotPlanned,
    }
}

// ---- reading and compiling (VM-W37) ----

#[test]
fn a_declaration_compiles_to_a_v01_request_that_records_its_source() {
    let compiled = compile_value(&base()).unwrap();
    let document = compiled.document();
    assert_eq!(document.schema_version, CONTRACT_SCHEMA_VERSION);
    assert_eq!(document.source.kind, SourceKind::Tool);
    assert_eq!(document.source.name.as_str(), "report-writer");
    assert_eq!(compiled.context().source, document.source);
    assert_eq!(
        document.requested.iter().cloned().collect::<BTreeSet<_>>(),
        base_tuples().into_iter().collect::<BTreeSet<_>>()
    );
    // Required capabilities are V01 dependencies; the optional route is not.
    let dependencies: BTreeSet<_> = document.dependencies.iter().cloned().collect();
    assert!(!dependencies.contains(&connect_registry()));
    assert_eq!(dependencies.len(), 4);
    // Approvals are only added to the required set: private data for the private input,
    // and the two the declaration asked for.
    let approvals: BTreeSet<_> = document.approvals.iter().cloned().collect();
    assert_eq!(
        approvals,
        BTreeSet::from([
            rule(ApprovalKind::PrivateDataAccess, &read_inputs()),
            rule(ApprovalKind::ExactRelease, &release_results()),
            rule(ApprovalKind::OngoingDelegation, &create_issue()),
        ])
    );
    // Derived requirements: a VM always; the task profile's lifetimes; and the contract
    // properties of what it did not ask for. It asked for network authority, so not
    // offline.
    let requires: BTreeSet<&str> = document.requires.iter().map(String::as_str).collect();
    assert_eq!(
        requires,
        BTreeSet::from([
            "vm_sandbox",
            "contract_bounded_lifetime",
            "contract_no_external_credentials",
            "contract_ephemeral_state",
            "contract_cpu_only",
        ])
    );
    assert!(document.legacy_tier.is_none());
    assert!(document.budgets.is_empty());
}

#[test]
fn the_compiled_request_reads_back_through_v01_unchanged() {
    // One schema for every surface: the request a UI sends as JSON is validated by V01
    // into the same request the in-process path produces.
    let compiled = compile_value(&base()).unwrap();
    let json = serde_json::to_string(compiled.document()).unwrap();
    assert_eq!(
        Validator::request_json(&json).unwrap(),
        compiled.validate().unwrap()
    );
}

#[test]
fn unknown_or_missing_versions_refuse_before_anything_else() {
    for (version, found) in [
        (json!(2), "2"),
        (json!(0), "0"),
        (json!("1"), "\"1\""),
        (json!(1.5), "1.5"),
    ] {
        // A newer version's unknown fields and authority-looking keys are not judged:
        // this build does not read that version at all.
        let mut value = base();
        value["declaration_version"] = version;
        value["delegation"] = json!({"granted": []});
        value["future_field"] = json!(true);
        let report = read_declaration(&text(&value)).unwrap_err();
        assert_eq!(
            only(&report),
            &RefusalDetail::UnsupportedDeclarationVersion {
                found: found.to_owned()
            }
        );
    }
    let mut value = base();
    value.as_object_mut().unwrap().remove("declaration_version");
    let report = read_declaration(&text(&value)).unwrap_err();
    assert_eq!(only(&report), &RefusalDetail::DeclarationVersionMissing);
    assert_eq!(
        only(&read_declaration("[1]").unwrap_err()).code(),
        RefusalCode::DeclarationNotObject
    );
    assert_eq!(
        only(&read_declaration("{\"declaration_version\": 1,").unwrap_err()).code(),
        RefusalCode::DeclarationNotJson
    );
    assert_eq!(DeclarationVersion::CURRENT.get(), DECLARATION_VERSION);
    assert!(serde_json::from_str::<DeclarationVersion>("2").is_err());
}

#[test]
fn unknown_fields_refuse_with_their_name_at_every_level() {
    let mut top = base();
    top["colour"] = json!("blue");
    let mut sandbox = base();
    sandbox["sandboxes"][0]["network"] = json!("host");
    let mut capability = base();
    capability["capabilities"][1]["capability"]["mode"] = json!("append");
    let mut entry = base();
    entry["capabilities"][0]["comment"] = json!("x");
    let mut source = base();
    source["source"]["publisher_key"] = json!("abc");
    for (value, field) in [
        (top, "colour"),
        (sandbox, "network"),
        (capability, "mode"),
        (entry, "comment"),
        (source, "publisher_key"),
    ] {
        let report = read_declaration(&text(&value)).unwrap_err();
        // This pins serde's "unknown field `name`" wording; if it changes, the refusal
        // would silently become invalid_declaration, and this test fails instead.
        assert_eq!(
            only(&report),
            &RefusalDetail::UnknownField {
                field: field.to_owned()
            }
        );
    }
}

#[test]
fn a_key_repeated_in_one_object_is_refused_rather_than_resolved_either_way() {
    let compact = text(&base());
    // Another reader might keep the first of two equal keys; a parsed value keeps the
    // last. The strict reader refuses the document instead of picking either.
    for (from, to, why) in [
        (
            "\"need\":\"optional\"",
            "\"need\":\"optional\",\"need\":\"required\"",
            "duplicate field",
        ),
        (
            "\"kind\":\"connect\"",
            "\"kind\":\"connect\",\"destination\":\"evil.example.net\"",
            "duplicate field",
        ),
        (
            "\"name\":\"report-writer\"",
            "\"name\":\"report-writer\",\"name\":\"other-tool\"",
            "duplicate field",
        ),
        // Whichever copy is met first, the document is refused.
        (
            "\"declaration_version\":1",
            "\"declaration_version\":2,\"declaration_version\":1",
            "declaration version 2 is not supported",
        ),
    ] {
        assert!(compact.contains(from), "{from}");
        let report = read_declaration(&compact.replacen(from, to, 1)).unwrap_err();
        assert_eq!(
            only(&report).code(),
            RefusalCode::InvalidDeclaration,
            "{to}"
        );
        assert!(report.refusals()[0].message.contains(why), "{report}");
    }
}

#[test]
fn unknown_capability_kinds_are_refused_by_name_never_ignored() {
    // VM-P03: no undeclared host filesystem, clipboard, USB, agent socket, management
    // endpoint or shared appliance privilege. None is a capability kind, so a declaration
    // cannot even ask.
    let hazards = [
        "host_filesystem",
        "clipboard",
        "usb",
        "agent_socket",
        "management_endpoint",
        "appliance_privilege",
    ];
    let mut capabilities = base_capabilities();
    for kind in hazards {
        capabilities.push(cap("optional", "analysis", json!({"kind": kind})));
    }
    let report = read_declaration(&text(&declaration(capabilities))).unwrap_err();
    let names: BTreeSet<String> = report
        .refusals()
        .iter()
        .map(|refusal| match &refusal.detail {
            RefusalDetail::UnknownCapability { path, name } => {
                assert!(path.starts_with("$.capabilities[") && path.ends_with("].capability.kind"));
                name.clone()
            }
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    assert_eq!(names, hazards.iter().map(|kind| kind.to_string()).collect());
    for kind in Capability::KINDS {
        assert!(!hazards.contains(&kind));
    }
}

#[test]
fn unknown_extension_runtimes_are_refused() {
    let mut value = base();
    value["extensions"] = json!([{"name": "x", "role": "main", "runtime": "jvm"}]);
    let report = read_declaration(&text(&value)).unwrap_err();
    assert_eq!(
        only(&report),
        &RefusalDetail::UnknownExtensionRuntime {
            path: "$.extensions[0].runtime".to_owned(),
            name: "jvm".to_owned()
        }
    );
}

#[test]
fn a_declaration_cannot_grant_itself_authority_through_any_field() {
    // Every authority key, at the top level and inside a capability, refuses with its path;
    // nothing reaches compilation.
    for field in AUTHORITY_FIELDS {
        let mut top = base();
        top[*field] = json!(true);
        let report = read_declaration(&text(&top)).unwrap_err();
        assert_eq!(
            only(&report),
            &RefusalDetail::AuthorityField {
                path: format!("$.{field}"),
                field: (*field).to_owned()
            }
        );
        let mut nested = base();
        nested["capabilities"][0]["capability"][*field] = json!({"anything": 1});
        let report = read_declaration(&text(&nested)).unwrap_err();
        assert_eq!(
            only(&report),
            &RefusalDetail::AuthorityField {
                path: format!("$.capabilities[0].capability.{field}"),
                field: (*field).to_owned()
            }
        );
    }
    // A realistic attempt: its own ceiling, a delegation, granted approvals, satisfied
    // host predicates, an epoch-bound tuple and trust for its extension.
    let mut value = base();
    value["product_ceiling"] = json!([]);
    value["delegation"] = json!({"granted": []});
    value["approval_grants"] = json!([{"kind": "exact_release"}]);
    value["requires"] = json!([{"name": "vm_sandbox", "satisfied": true}]);
    value["capabilities"][0]["generation"] = json!({"scope": "authorization", "epoch": 1});
    value["extensions"] =
        json!([{"name": "fmt", "role": "main", "runtime": "wasm", "trusted": true}]);
    let report = read_declaration(&text(&value)).unwrap_err();
    let paths: Vec<String> = report
        .refusals()
        .iter()
        .map(|refusal| match &refusal.detail {
            RefusalDetail::AuthorityField { path, .. } => path.clone(),
            other => panic!("unexpected {other:?}"),
        })
        .collect();
    let mut sorted = paths.clone();
    sorted.sort();
    assert_eq!(paths, sorted, "refusals come in a deterministic order");
    assert_eq!(
        paths.into_iter().collect::<BTreeSet<_>>(),
        BTreeSet::from(
            [
                "$.approval_grants",
                "$.capabilities[0].generation",
                "$.delegation",
                "$.delegation.granted",
                "$.extensions[0].trusted",
                "$.product_ceiling",
                "$.requires[0].satisfied",
            ]
            .map(str::to_owned)
        )
    );
}

#[test]
fn wildcards_addresses_and_ambiguous_names_are_never_destinations() {
    let connect = |destination: &str| {
        declaration(vec![cap(
            "required",
            "fetch",
            json!({"kind": "connect", "destination": destination}),
        )])
    };
    for wildcard in ["*.example.com", "*", "a*.example.com", "*.com"] {
        assert_eq!(
            only(&refusal_of(&connect(wildcard))),
            &RefusalDetail::WildcardDestination {
                destination: wildcard.to_owned()
            }
        );
    }
    for address in [
        "10.0.0.1",
        "10.0.0.1:443",
        "[::1]:443",
        "127.1",
        "0x7f.0.0.1",
    ] {
        assert_eq!(
            only(&refusal_of(&connect(address))).code(),
            RefusalCode::DestinationNotAName,
            "{address}"
        );
    }
    for invalid in [
        "localhost",
        "registry.example.com.",
        "user@registry.example.com",
        "registry.example.com/path",
        "db.internal",
        "printer.local",
        "registry.example.com:0",
        "",
    ] {
        assert_eq!(
            only(&refusal_of(&connect(invalid))).code(),
            RefusalCode::InvalidDestination,
            "{invalid}"
        );
    }
    // Exact names elsewhere use the identifier grammar, which has no wildcard character.
    for capability in [
        json!({"kind": "read_input", "grant": "*", "data_class": "ordinary"}),
        json!({"kind": "provider_operation", "account": "forge", "operation": "*"}),
        json!({"kind": "release", "channel": "results/*"}),
    ] {
        assert_eq!(
            only(&refusal_of(&declaration(vec![cap(
                "required", "analysis", capability
            )])))
            .code(),
            RefusalCode::InvalidDeclaration
        );
    }
}

#[test]
fn destinations_are_named_by_their_canonical_authority() {
    let connect = |destination: &str| {
        cap(
            "required",
            "fetch",
            json!({"kind": "connect", "destination": destination}),
        )
    };
    let compiled = compile_value(&declaration(vec![connect("Registry.Example.COM:8443")])).unwrap();
    assert_eq!(
        compiled.document().requested[0].resource,
        ResourceRef::new(ResourceKind::Route, "registry.example.com:8443").unwrap()
    );
    // Two spellings of one authority are one capability, declared twice.
    let report = refusal_of(&declaration(vec![
        connect("registry.example.com"),
        connect("REGISTRY.example.com:443"),
    ]));
    assert_eq!(
        only(&report),
        &RefusalDetail::DuplicateCapability {
            tuple: connect_registry()
        }
    );
}

#[test]
fn credentials_follow_their_section_4_5_class() {
    let one = |capability: Value| declaration(vec![cap("required", "analysis", capability)]);
    // Long-lived provider credentials stay with the executor; canaries are the host's.
    assert_eq!(
        only(&refusal_of(&one(
            json!({"kind": "provider_credential", "name": "forge-token"})
        ))),
        &RefusalDetail::CredentialNeverDelivered {
            name: ResourceName::new("forge-token").unwrap()
        }
    );
    assert_eq!(
        only(&refusal_of(&one(
            json!({"kind": "fake_canary", "name": "canary-1"})
        )))
        .code(),
        RefusalCode::CanaryNotRequestable
    );
    // A short-lived capability is still a credential: explicit audience, scope and expiry.
    let short = compile_value(&one(json!({
        "kind": "short_lived_credential",
        "name": "upload-token",
        "audience": "uploads.example.com",
        "scope": "objects.put",
        "expires_in_seconds": 900,
        "delegated_effects": 20
    })))
    .unwrap();
    assert_eq!(
        short.document().requested[0].operation,
        Operation::ReceiveExternalCredential
    );
    assert!(!short
        .document()
        .requires
        .contains(&"contract_no_external_credentials".to_owned()));
    let terms = &short.context().credentials[0];
    assert_eq!(terms.class, CredentialClass::ShortLivedExternalCapability);
    assert_eq!(
        terms.audience.as_ref().unwrap().as_str(),
        "uploads.example.com"
    );
    assert_eq!(terms.expires_in_seconds.unwrap().get(), 900);
    assert_eq!(terms.delegated_effects.unwrap().get(), 20);
    for incomplete in [
        json!({"kind": "short_lived_credential", "name": "t", "scope": "objects.put", "expires_in_seconds": 900, "delegated_effects": 1}),
        json!({"kind": "short_lived_credential", "name": "t", "audience": "uploads.example.com", "expires_in_seconds": 900, "delegated_effects": 1}),
        json!({"kind": "short_lived_credential", "name": "t", "audience": "uploads.example.com", "scope": "objects.put", "delegated_effects": 1}),
        json!({"kind": "short_lived_credential", "name": "t", "audience": "uploads.example.com", "scope": "objects.put", "expires_in_seconds": 0, "delegated_effects": 1}),
        json!({"kind": "short_lived_credential", "name": "t", "audience": "*.example.com", "scope": "objects.put", "expires_in_seconds": 9, "delegated_effects": 1}),
        // The delegated budget is explicit and never zero (§4.5).
        json!({"kind": "short_lived_credential", "name": "t", "audience": "uploads.example.com", "scope": "objects.put", "expires_in_seconds": 9}),
        json!({"kind": "short_lived_credential", "name": "t", "audience": "uploads.example.com", "scope": "objects.put", "expires_in_seconds": 9, "delegated_effects": 0}),
    ] {
        assert_eq!(
            only(&refusal_of(&one(incomplete))).code(),
            RefusalCode::InvalidDeclaration
        );
    }
    // A signed download URL is a bearer capability, so it is a credential delivery.
    let signed = compile_value(&one(
        json!({"kind": "signed_download_url", "name": "weights-url"}),
    ))
    .unwrap();
    assert_eq!(
        signed.document().requested[0].operation,
        Operation::ReceiveExternalCredential
    );
    // A sandbox-local secret exists only in the guest: no host operation, no external
    // credential, and nothing to approve.
    let local = compile_value(&one(
        json!({"kind": "sandbox_local_secret", "name": "db-password"}),
    ))
    .unwrap();
    assert!(local.document().requested.is_empty());
    assert!(local
        .document()
        .requires
        .contains(&"contract_no_external_credentials".to_owned()));
    let mut approved = one(json!({"kind": "sandbox_local_secret", "name": "db-password"}));
    approved["capabilities"][0]["approval"] = json!("ongoing_delegation");
    assert_eq!(
        only(&refusal_of(&approved)),
        &RefusalDetail::ApprovalWithoutOperation {
            path: "$.capabilities[0].approval".to_owned()
        }
    );
    // User private content is data with a release policy, declared as an input.
    let private = compile_value(&one(
        json!({"kind": "read_input", "grant": "inputs", "data_class": "user_private_content"}),
    ))
    .unwrap();
    assert_eq!(
        private.document().approvals,
        vec![rule(ApprovalKind::PrivateDataAccess, &read_inputs())]
    );
    // The treatments are the §4.5 table's, and only three classes may be asked for in
    // the guest.
    let requestable: Vec<CredentialClass> = CredentialClass::ALL
        .into_iter()
        .filter(|class| class.may_be_requested_in_guest())
        .collect();
    assert_eq!(
        requestable,
        vec![
            CredentialClass::ShortLivedExternalCapability,
            CredentialClass::SignedDownloadUrl,
            CredentialClass::SandboxLocalSecret
        ]
    );
    assert_eq!(
        CredentialClass::LongLivedProviderCredential.treatment(),
        "Remains in vault/executor; never intentionally delivered to the workload"
    );
    assert_eq!(
        CredentialClass::SandboxLocalSecret.treatment(),
        "May exist in guest; cannot authorize host or external privileges"
    );
    assert_eq!(
        CredentialClass::FakeCanary.treatment(),
        "Detection artifact; never a genuine production credential"
    );
    assert!(!CredentialClass::SandboxLocalSecret.is_external_credential());
    assert!(CredentialClass::SignedDownloadUrl.is_external_credential());
}

#[test]
fn labelled_runtimes_never_stand_in_for_a_vm() {
    for category in ExecutionCategory::ALL {
        let mut sandbox = base();
        sandbox["sandboxes"][0]["execution_category"] = json!(category);
        let mut extension = base();
        extension["extensions"] = json!([{
            "name": "fmt", "role": "main", "runtime": "wasm", "execution_category": category
        }]);
        if category.is_vm_sandbox() {
            assert!(compile_value(&sandbox).is_ok());
            assert!(compile_value(&extension).is_ok());
            continue;
        }
        let report = compile_value(&sandbox).unwrap_err();
        assert_eq!(
            only(&report),
            &RefusalDetail::LabelledRuntime {
                subject: "sandbox \"main\"".to_owned(),
                category
            }
        );
        let decision = category.decision().unwrap();
        assert!(report.refusals()[0].message.contains(decision));
        assert!(report.refusals()[0].message.contains(category.label()));
        assert_eq!(
            only(&compile_value(&extension).unwrap_err()),
            &RefusalDetail::LabelledRuntime {
                subject: "extension executor \"fmt\"".to_owned(),
                category
            }
        );
    }
}

#[test]
fn every_extension_executor_requires_a_vm_that_no_labelled_runtime_satisfies() {
    let tuples = base_tuples();
    for runtime in ExtensionRuntime::ALL {
        let mut value = base();
        value["requires"] = json!([]);
        value["extensions"] = json!([{"name": "ext", "role": "main", "runtime": runtime.name()}]);
        let compiled = compile_value(&value).unwrap();
        assert!(compiled
            .document()
            .requires
            .contains(&"vm_sandbox".to_owned()));
        // On a labelled runtime the launch is refused for the VM requirement, whatever the
        // extension runtime is.
        for category in ExecutionCategory::ALL
            .into_iter()
            .filter(|category| !category.is_vm_sandbox())
        {
            let host = Host::running(category);
            let evaluation = host
                .evaluate(&text(&value), &product(&tuples), &delegation(&tuples))
                .unwrap();
            let refusal = evaluation.launch().as_ref().unwrap_err();
            assert!(refusal.reasons.iter().any(|reason| matches!(
                reason,
                LaunchRefusalReason::RequirementUnmet {
                    predicate: SecurityPredicate::VmSandbox,
                    outcome: PredicateOutcome::CategoryRefused { .. }
                }
            )));
        }
    }
}

#[test]
fn roles_duplicates_and_persistence_are_checked() {
    let mut empty = base();
    empty["sandboxes"] = json!([]);
    empty["capabilities"] = json!([]);
    assert_eq!(
        only(&compile_value(&empty).unwrap_err()),
        &RefusalDetail::NoSandbox
    );

    let mut twice = base();
    twice["sandboxes"] = json!([
        {"role": "main", "profile": "task", "persistence": "ephemeral"},
        {"role": "main", "profile": "service", "persistence": "declared_volumes"}
    ]);
    assert_eq!(
        only(&compile_value(&twice).unwrap_err()).code(),
        RefusalCode::DuplicateSandboxRole
    );

    let mut undeclared = base();
    undeclared["capabilities"][1]["role"] = json!("build");
    undeclared["extensions"] = json!([
        {"name": "fmt", "role": "publish", "runtime": "script"},
        {"name": "fmt", "role": "main", "runtime": "wasm"}
    ]);
    let report = compile_value(&undeclared).unwrap_err();
    assert_eq!(
        report.codes(),
        vec![
            RefusalCode::UndeclaredSandboxRole,
            RefusalCode::UndeclaredSandboxRole,
            RefusalCode::DuplicateExtension
        ]
    );

    let volume = cap(
        "required",
        "analysis",
        json!({"kind": "write_volume", "volume": "cache"}),
    );
    let ephemeral = declaration(vec![volume.clone()]);
    assert_eq!(
        only(&compile_value(&ephemeral).unwrap_err()),
        &RefusalDetail::VolumeOnEphemeralSandbox {
            role: RoleName::new("main").unwrap(),
            volume: ResourceName::new("cache").unwrap()
        }
    );
    let mut persistent = declaration(vec![volume]);
    persistent["sandboxes"][0]["persistence"] = json!("declared_volumes");
    let compiled = compile_value(&persistent).unwrap();
    assert!(!compiled
        .document()
        .requires
        .contains(&"contract_ephemeral_state".to_owned()));
    let mut service = persistent.clone();
    service["sandboxes"][0]["profile"] = json!("service");
    assert!(!compile_value(&service)
        .unwrap()
        .document()
        .requires
        .contains(&"contract_bounded_lifetime".to_owned()));

    let mut duplicate = base();
    duplicate["capabilities"][1]["need"] = json!("optional");
    let mut capabilities = base_capabilities();
    capabilities.push(duplicate["capabilities"][1].clone());
    assert_eq!(
        only(&compile_value(&declaration(capabilities)).unwrap_err()),
        &RefusalDetail::DuplicateCapability {
            tuple: write_outputs()
        }
    );
}

#[test]
fn a_gpu_adds_the_isolation_requirement_even_when_optional() {
    let gpu = cap(
        "optional",
        "analysis",
        json!({"kind": "gpu", "device": "gpu0"}),
    );
    let compiled = compile_value(&declaration(vec![gpu])).unwrap();
    let requires = &compiled.document().requires;
    assert!(requires.contains(&"assigned_gpu_isolated".to_owned()));
    assert!(!requires.contains(&"contract_cpu_only".to_owned()));
    assert!(compile_value(&base())
        .unwrap()
        .document()
        .requires
        .contains(&"contract_cpu_only".to_owned()));
}

// ---- V01 validation through declarations ----

#[test]
fn v01_validation_refusals_keep_their_reasons_under_stable_codes() {
    let mut unknown = base();
    unknown["requires"] = json!(["quantum_shield", "vm_sandbox"]);
    let report = refusal_of(&unknown);
    assert_eq!(
        only(&report),
        &RefusalDetail::UnknownRequirement {
            name: "quantum_shield".to_owned()
        }
    );
    assert_eq!(
        report.refusals()[0].message,
        ValidationIssue::UnknownRequirement {
            name: "quantum_shield".to_owned()
        }
        .to_string()
    );

    for (tier, refusal) in [
        ("T1", MigrationRefusal::SharedKernel),
        ("T4", MigrationRefusal::AmbiguousOperator),
        (
            "T9",
            MigrationRefusal::Unknown {
                name: "T9".to_owned(),
            },
        ),
    ] {
        let mut value = base();
        value["legacy_tier"] = json!(tier);
        assert_eq!(
            only(&refusal_of(&value)),
            &RefusalDetail::LegacyTierRefused { refusal }
        );
    }
    let mut t3 = base();
    t3["legacy_tier"] = json!("T3");
    let request = compile_value(&t3).unwrap().validate().unwrap();
    assert!(request
        .requirements()
        .contains(SecurityPredicate::IndependentPerimeter));

    let mut misfit = base();
    misfit["capabilities"][1]["approval"] = json!("exact_release");
    assert_eq!(
        only(&refusal_of(&misfit)),
        &RefusalDetail::ApprovalDoesNotFit {
            layer: PolicyLayer::Request,
            rule: rule(ApprovalKind::ExactRelease, &write_outputs())
        }
    );

    let mut offline = base();
    offline["requires"] = json!(["contract_offline"]);
    let report = refusal_of(&offline);
    assert!(report
        .refusals()
        .iter()
        .all(|refusal| refusal.code == RefusalCode::ContractConflict));
    // Network authority is the route and the provider operation; a release channel is
    // outbound but not network authority.
    assert_eq!(report.refusals().len(), 2);

    let mut budgets = base();
    let limit = json!({"resource": "release_bytes", "scope": {"scope": "generation"}, "limit": 1});
    budgets["budgets"] = json!([limit.clone(), limit]);
    assert_eq!(
        only(&refusal_of(&budgets)).code(),
        RefusalCode::DuplicateBudget
    );
}

#[test]
fn declared_budgets_can_lower_a_limit_but_never_raise_one() {
    let tuples = base_tuples();
    let host = Host::ready();
    let key = BudgetKey {
        resource: BudgetResource::ReleaseBytes,
        scope: AccountingScope::Generation,
    };
    let product_limit = BudgetSet::vm_d12_task_defaults().limit(&key).unwrap();
    assert_eq!(product_limit, 8 * MIB);
    for (asked, effective) in [(1 << 40, product_limit), (MIB, MIB)] {
        let mut value = base();
        value["budgets"] = json!([{
            "resource": "release_bytes", "scope": {"scope": "generation"}, "limit": asked
        }]);
        let evaluation = host
            .evaluate(&text(&value), &product(&tuples), &delegation(&tuples))
            .unwrap();
        assert_eq!(evaluation.resolved().budgets().limit(&key), Some(effective));
        let preview = evaluation.preview(&[], None, None);
        let line = preview.budgets.iter().find(|line| line.key == key).unwrap();
        assert_eq!((line.limit, line.declared), (effective, Some(asked)));
        let capped = preview.render_text().contains(&format!(
            "the declaration asked for {asked}, and the lower limit applies"
        ));
        assert_eq!(capped, asked > effective);
    }
}

#[test]
fn a_required_capability_removed_refuses_with_v01_reason_and_an_optional_one_is_dropped() {
    let host = Host::ready();
    let tuples = base_tuples();
    // The product does not permit the release the tool needs.
    let ceiling: Vec<_> = tuples
        .iter()
        .filter(|tuple| **tuple != release_results())
        .cloned()
        .collect();
    let evaluation = host
        .evaluate(&text(&base()), &product(&ceiling), &delegation(&tuples))
        .unwrap();
    let refusal = evaluation.launch().as_ref().unwrap_err();
    let expected = LaunchRefusalReason::RequiredAuthorityRemoved {
        tuple: release_results(),
        excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling]),
    };
    assert_eq!(refusal.reasons, vec![expected.clone()]);
    let preview = evaluation.preview(&[], None, None);
    assert_eq!(preview.refusals.len(), 1);
    assert_eq!(
        preview.refusals[0].code,
        RefusalCode::RequiredAuthorityRemoved
    );
    assert_eq!(preview.refusals[0].message, expected.to_string());

    // The delegation leaves out the optional route: dropped, listed, and the launch goes
    // ahead.
    let granted: Vec<_> = tuples
        .iter()
        .filter(|tuple| **tuple != connect_registry())
        .cloned()
        .collect();
    let evaluation = host
        .evaluate(&text(&base()), &product(&tuples), &delegation(&granted))
        .unwrap();
    assert!(evaluation.launch().is_ok());
    let preview = evaluation.preview(&[], None, None);
    assert!(matches!(preview.decision, PreviewDecision::Allowed { .. }));
    assert_eq!(
        preview.removed,
        vec![RemovedLine {
            tuple: connect_registry(),
            need: Need::Optional,
            excluded_by: BTreeSet::from([PolicyLayer::Delegation]),
            effect: RemovalEffect::Dropped,
        }]
    );
    assert!(preview
        .releases
        .iter()
        .all(|line| line.tuple != connect_registry()));
}

// ---- refusal codes (VM-W54) ----

#[test]
fn refusal_codes_are_unique_stable_and_round_trip_in_text_and_json() {
    let mut strings = BTreeSet::new();
    for code in RefusalCode::ALL.iter().copied() {
        let string = code.as_str();
        assert!(strings.insert(string), "duplicate code {string}");
        assert!(string
            .chars()
            .all(|character| character.is_ascii_lowercase() || character == '_'));
        assert_eq!(serde_json::to_value(code).unwrap(), json!(string));
        assert_eq!(
            serde_json::from_value::<RefusalCode>(json!(string)).unwrap(),
            code
        );
        assert!(!code.help().is_empty() && !code.help().contains('\n'));

        let detail = example(code);
        assert_eq!(detail.code(), code, "the example matches its code");
        let refusal = Refusal::new(detail.clone());
        assert_eq!(refusal.code, code);
        assert_eq!(refusal.refusal_version, RefusalSchemaVersion::CURRENT);
        assert!(!refusal.message.is_empty() && !refusal.message.contains('\n'));
        let text_form = refusal.render_text();
        assert!(text_form.starts_with(&format!("[{string}] ")));
        let json_form = serde_json::to_value(&refusal).unwrap();
        assert_eq!(json_form["code"], json!(string));
        assert_eq!(json_form["detail"]["code"], json!(string));
        assert_eq!(json_form["message"], json!(refusal.message));
        let back: Refusal = serde_json::from_value(json_form).unwrap();
        assert_eq!(back, refusal);
        assert_eq!(
            serde_json::from_value::<RefusalDetail>(serde_json::to_value(&detail).unwrap())
                .unwrap(),
            detail
        );
        // Validation and launch details use V01's own wording.
        if let Some(issue) = detail.validation_issue() {
            assert_eq!(code.stage(), RefusalStage::Validation);
            assert_eq!(refusal.message, issue.to_string());
            assert_eq!(RefusalDetail::from(issue), detail);
        }
        if let Some(reason) = detail.launch_reason() {
            assert_eq!(code.stage(), RefusalStage::Launch);
            assert_eq!(refusal.message, reason.to_string());
            assert_eq!(RefusalDetail::from(reason), detail);
        }
    }
    assert_eq!(strings.len(), RefusalCode::ALL.len());
    assert_eq!(RefusalCode::ALL.len(), 43);
    assert_eq!(REFUSAL_SCHEMA_VERSION, 1);
    // A report's text and JSON carry the same codes in the same order.
    let report =
        RefusalReport::from_details(RefusalCode::ALL.iter().copied().map(example)).unwrap();
    let lines: Vec<String> = report
        .render_text()
        .lines()
        .map(|line| {
            line.split(']')
                .next()
                .unwrap()
                .trim_start_matches('[')
                .to_owned()
        })
        .collect();
    let json_codes: Vec<String> = serde_json::to_value(&report).unwrap()["refusals"]
        .as_array()
        .unwrap()
        .iter()
        .map(|refusal| refusal["code"].as_str().unwrap().to_owned())
        .collect();
    assert_eq!(lines, json_codes);
    assert_eq!(
        RefusalReport::from_json(&report.to_json().unwrap()).unwrap(),
        report
    );
}

#[test]
fn a_tampered_or_foreign_refusal_is_refused_when_read() {
    let refusal = Refusal::new(example(RefusalCode::WildcardDestination));
    let good = serde_json::to_value(&refusal).unwrap();
    let mut code = good.clone();
    code["code"] = json!("unknown_field");
    let mut message = good.clone();
    message["message"] = json!("everything is fine");
    let mut version = good.clone();
    version["refusal_version"] = json!(2);
    let mut extra = good.clone();
    extra["severity"] = json!("low");
    let mut detail = good.clone();
    detail["detail"]["note"] = json!("x");
    let mut unit = serde_json::to_value(Refusal::new(RefusalDetail::NoSandbox)).unwrap();
    unit["detail"]["role"] = json!("main");
    for tampered in [code, message, version, extra, detail, unit] {
        assert!(serde_json::from_value::<Refusal>(tampered).is_err());
    }
    assert!(serde_json::from_value::<RefusalCode>(json!("made_up_code")).is_err());
    assert!(RefusalReport::from_json("{\"refusals\": []}").is_err());
    assert!(RefusalReport::from_details(Vec::new()).is_none());
}

#[test]
fn untrusted_text_stays_on_one_line_and_bounded() {
    let mut value = base();
    let hostile = format!("bad\nkey\u{202e}{}", "x".repeat(400));
    value[hostile.as_str()] = json!(1);
    let report = read_declaration(&text(&value)).unwrap_err();
    let refusal = &report.refusals()[0];
    assert_eq!(refusal.code, RefusalCode::UnknownField);
    assert!(!refusal.message.contains('\n'));
    assert!(!refusal.message.contains('\u{202e}'));
    assert!(refusal.message.contains("\\u{a}"));
    assert!(refusal.message.chars().count() < 400);
    assert!(!report.render_text().contains('\u{202e}'));
}

#[test]
fn refusal_text_escapes_what_the_shared_classification_marks_hazardous() {
    use super::refusal::{bounded, one_line};
    // Escaped as before: controls, bidirectional and zero-width characters.
    for character in [
        '\n', '\u{1b}', '\u{9b}', '\u{202e}', '\u{2066}', '\u{200b}', '\u{feff}',
    ] {
        let escaped = format!("a{}b", character.escape_unicode());
        assert_eq!(one_line(&format!("a{character}b")), escaped);
        assert_eq!(bounded(&format!("a{character}b")), escaped);
    }
    // Escaped now as well, decided by foundation::text: a line separator, a no-break
    // space, the Arabic letter mark, a soft hyphen, a tag character, a private-use code
    // point and an unassigned one.
    for character in [
        '\u{2028}',
        '\u{a0}',
        '\u{61c}',
        '\u{ad}',
        '\u{e0041}',
        '\u{e000}',
        '\u{378}',
    ] {
        let escaped = format!("a{}b", character.escape_unicode());
        assert_eq!(one_line(&format!("a{character}b")), escaped);
        assert_eq!(bounded(&format!("a{character}b")), escaped);
    }
    // Printable text and combining marks are kept as they were.
    let plain = "caf\u{e9} e\u{301} \u{5d0} \u{1f600}";
    assert_eq!(one_line(plain), plain);
    assert_eq!(bounded(plain), plain);
}

// ---- non-interactive runs (VM-W54) ----

fn grant(rule: ApprovalRule, epoch: AuthorizationEpoch) -> ApprovalGrant {
    let payload = (rule.kind == ApprovalKind::ExactRelease)
        .then(|| digest("yougori/test/payload/v1", &[b"report.pdf"]));
    ApprovalGrant {
        rule,
        epoch,
        payload,
    }
}

pub(super) fn all_grants(epoch: AuthorizationEpoch) -> Vec<ApprovalGrant> {
    vec![
        grant(rule(ApprovalKind::PrivateDataAccess, &read_inputs()), epoch),
        grant(rule(ApprovalKind::ExactRelease, &release_results()), epoch),
        grant(
            rule(ApprovalKind::OngoingDelegation, &create_issue()),
            epoch,
        ),
    ]
}

#[test]
fn a_non_interactive_run_refuses_without_authorization_and_never_prompts() {
    let host = Host::ready();
    let tuples = base_tuples();
    // No delegation at all: every required authority is missing.
    let evaluation = host
        .evaluate(&text(&base()), &product(&tuples), &delegation(&[]))
        .unwrap();
    let report = match evaluation.decide_non_interactive(&all_grants(E1), E1) {
        NonInteractiveDecision::Refuse { report } => report,
        NonInteractiveDecision::Proceed { .. } => panic!("must not proceed"),
    };
    let missing: Vec<_> = report
        .refusals()
        .iter()
        .filter(|refusal| refusal.code == RefusalCode::AuthorizationMissing)
        .collect();
    assert_eq!(
        missing.len(),
        4,
        "every required capability; not the optional route"
    );
    assert!(report.contains(RefusalCode::RequiredAuthorityRemoved));
    // Nothing is permitted, so no approval applies and none is reported.
    assert!(!report.contains(RefusalCode::ApprovalRequired));

    // Without a plan it never proceeds.
    let resolved = evaluation.resolved();
    assert_eq!(
        decide_non_interactive(LaunchOutcome::not_planned(resolved), &[], E1),
        NonInteractiveDecision::Refuse {
            report: RefusalReport::from_details([
                RefusalDetail::LaunchNotPlanned,
                RefusalDetail::AuthorizationMissing {
                    tuple: read_inputs()
                },
                RefusalDetail::AuthorizationMissing {
                    tuple: write_outputs()
                },
                RefusalDetail::AuthorizationMissing {
                    tuple: create_issue()
                },
                RefusalDetail::AuthorizationMissing {
                    tuple: release_results()
                },
            ])
            .unwrap()
        }
    );
}

#[test]
fn a_non_interactive_run_refuses_any_needed_approval_and_reuses_valid_grants() {
    let host = Host::ready();
    let tuples = base_tuples();
    let evaluation = host
        .evaluate(&text(&base()), &product(&tuples), &delegation(&tuples))
        .unwrap();
    assert!(evaluation.launch().is_ok());
    // Planned, but no approval given: one refusal per needed approval, of each kind.
    let NonInteractiveDecision::Refuse { report } = evaluation.decide_non_interactive(&[], E1)
    else {
        panic!("must refuse");
    };
    assert_eq!(report.codes(), vec![RefusalCode::ApprovalRequired; 3]);
    // Valid grants at the run's epoch are reused, not asked for again (VM-P46).
    let contract = evaluation.resolved().identity();
    assert_eq!(
        evaluation.decide_non_interactive(&all_grants(E1), E1),
        NonInteractiveDecision::Proceed { contract }
    );
    // Grants from another authorization epoch are not valid.
    let NonInteractiveDecision::Refuse { report } =
        evaluation.decide_non_interactive(&all_grants(E1), E2)
    else {
        panic!("stale grants must not count");
    };
    assert_eq!(report.codes(), vec![RefusalCode::ApprovalRequired; 3]);
    // An exact-release grant without a payload digest is malformed and does not count.
    let mut grants = all_grants(E1);
    grants[1].payload = None;
    let NonInteractiveDecision::Refuse { report } = evaluation.decide_non_interactive(&grants, E1)
    else {
        panic!("a malformed exact-release grant must not count");
    };
    assert_eq!(
        report.refusals()[0].detail,
        RefusalDetail::ApprovalRequired {
            rule: rule(ApprovalKind::ExactRelease, &release_results())
        }
    );
    // The decision has exactly two outcomes; there is no prompt.
    match evaluation.decide_non_interactive(&[], E1) {
        NonInteractiveDecision::Proceed { .. } | NonInteractiveDecision::Refuse { .. } => {}
    }
}

#[test]
fn a_launch_refusal_alone_refuses_a_non_interactive_run() {
    // Delegated and approved, but a GPU needs isolation evidence nothing observes yet.
    let host = Host::ready();
    let gpu = tuple(
        Operation::DeviceUse,
        ResourceKind::Device,
        "gpu0",
        Phase::Analysis,
    );
    let value = declaration(vec![cap(
        "required",
        "analysis",
        json!({"kind": "gpu", "device": "gpu0"}),
    )]);
    let evaluation = host
        .evaluate(
            &text(&value),
            &product(std::slice::from_ref(&gpu)),
            &delegation(&[gpu]),
        )
        .unwrap();
    let NonInteractiveDecision::Refuse { report } = evaluation.decide_non_interactive(&[], E1)
    else {
        panic!("must refuse");
    };
    assert_eq!(report.codes(), vec![RefusalCode::RequirementUnmet]);
    assert!(matches!(
        &report.refusals()[0].detail,
        RefusalDetail::RequirementUnmet {
            predicate: SecurityPredicate::AssignedGpuIsolated,
            outcome: PredicateOutcome::NoEvidenceCapability { .. }
        }
    ));
}

// ---- no declaration widens host policy (seeded exploration) ----

/// xorshift64*: a small explicit generator so the exploration is reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }

    fn coin(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

fn pool() -> Vec<(Value, PermissionTuple)> {
    let mut entries: Vec<(Value, PermissionTuple)> = base_capabilities()
        .into_iter()
        .zip(base_tuples())
        .map(|(mut value, tuple)| {
            value.as_object_mut().unwrap().remove("approval");
            (value, tuple)
        })
        .collect();
    entries.push((
        cap(
            "optional",
            "analysis",
            json!({"kind": "gpu", "device": "gpu0"}),
        ),
        tuple(
            Operation::DeviceUse,
            ResourceKind::Device,
            "gpu0",
            Phase::Analysis,
        ),
    ));
    entries.push((
        cap(
            "optional",
            "fetch",
            json!({"kind": "short_lived_credential", "name": "token", "audience": "api.example.com", "scope": "read", "expires_in_seconds": 60, "delegated_effects": 5}),
        ),
        tuple(
            Operation::ReceiveExternalCredential,
            ResourceKind::Credential,
            "token",
            Phase::Fetch,
        ),
    ));
    entries.push((
        cap(
            "optional",
            "publication",
            json!({"kind": "publish_service", "service": "web"}),
        ),
        tuple(
            Operation::PublishService,
            ResourceKind::Service,
            "web",
            Phase::Publication,
        ),
    ));
    entries
}

#[test]
fn seeded_random_declarations_never_widen_host_policy() {
    let host = Host::ready();
    let pool = pool();
    let mut rng = Rng(0x5eed_0000_0000_0001);
    let mut allowed = 0;
    for _ in 0..400 {
        let mut capabilities = Vec::new();
        for (value, _) in &pool {
            if rng.coin() {
                let mut value = value.clone();
                value["need"] = json!(if rng.coin() { "required" } else { "optional" });
                match rng.below(3) {
                    0 => {}
                    1 => value["approval"] = json!("ongoing_delegation"),
                    _ => value["approval"] = json!("private_data_access"),
                }
                capabilities.push(value);
            }
        }
        let mut value = declaration(capabilities);
        // Whoever wrote it, a declaration is a request (VM-W37).
        value["source"]["kind"] = json!(match rng.below(3) {
            0 => "template",
            1 => "tool",
            _ => "user",
        });
        value["budgets"] = json!([{
            "resource": "release_bytes", "scope": {"scope": "generation"},
            "limit": rng.below(1 << 40)
        }]);
        let ceiling: Vec<_> = pool
            .iter()
            .filter(|_| rng.coin())
            .map(|(_, tuple)| tuple.clone())
            .collect();
        let granted: Vec<_> = pool
            .iter()
            .filter(|_| rng.coin())
            .map(|(_, tuple)| tuple.clone())
            .collect();
        let mut requirements = vec![SecurityPredicate::VmSandbox];
        if rng.coin() {
            requirements.push(SecurityPredicate::HardwareHypervisorAvailable);
        }
        let product_approvals: Vec<_> = ceiling
            .iter()
            .filter(|_| rng.coin())
            .map(|tuple| rule(ApprovalKind::OngoingDelegation, tuple))
            .collect();
        let product = product_with(&ceiling, &requirements, product_approvals);
        let delegation = delegation(&granted);

        let evaluation = host.evaluate(&text(&value), &product, &delegation).unwrap();
        let resolved = evaluation.resolved();
        let bound = product.ceiling().intersection(delegation.granted());
        assert!(resolved.permitted().is_subset(&bound));
        assert!(resolved
            .permitted()
            .is_subset(evaluation.request().requested()));
        assert!(product.requirements().is_subset(resolved.requirements()));
        assert!(resolved
            .requirements()
            .contains(SecurityPredicate::VmSandbox));
        assert!(product.approvals().is_subset(resolved.approvals()));
        assert!(evaluation
            .request()
            .approvals()
            .is_subset(resolved.approvals()));
        assert!(delegation.approvals().is_subset(resolved.approvals()));
        assert!(evaluation
            .request()
            .requirements()
            .is_subset(resolved.requirements()));
        for (key, limit) in product.budgets().iter() {
            assert!(resolved
                .budgets()
                .limit(key)
                .is_some_and(|effective| effective <= limit));
        }
        if let Ok(plan) = evaluation.launch() {
            allowed += 1;
            for dependency in plan.resolved().dependencies().iter() {
                assert!(plan.resolved().permitted().covers(&dependency));
            }
            assert_eq!(plan.resolved(), resolved);
        }
        // The planner is V01's: planning again gives the same decision.
        assert_eq!(&host.plan(resolved), evaluation.launch());
    }
    assert!(allowed > 0, "the exploration reached allowed launches too");
}

#[test]
fn section_4_6_a_new_destination_needs_reauthorization_and_standing_grants_are_reused() {
    let host = Host::ready();
    let tuples = base_tuples();
    let mirror = tuple(
        Operation::TransportConnect,
        ResourceKind::Route,
        "mirror.example.org:443",
        Phase::Fetch,
    );
    let mut ceiling = tuples.clone();
    ceiling.push(mirror.clone());
    // The tool's next version adds a destination outside the standing delegation.
    let mut capabilities = base_capabilities();
    capabilities.push(cap(
        "required",
        "fetch",
        json!({"kind": "connect", "destination": "mirror.example.org"}),
    ));
    let evaluation = host
        .evaluate(
            &text(&declaration(capabilities)),
            &product(&ceiling),
            &delegation(&tuples),
        )
        .unwrap();
    let NonInteractiveDecision::Refuse { report } =
        evaluation.decide_non_interactive(&all_grants(E1), E1)
    else {
        panic!("a new destination needs reauthorization");
    };
    // Only the new destination is asked about; the approvals already given for this
    // authorization epoch are not asked for again.
    assert_eq!(
        report
            .refusals()
            .iter()
            .map(|refusal| refusal.detail.clone())
            .collect::<Vec<_>>(),
        vec![
            RefusalDetail::RequiredAuthorityRemoved {
                tuple: mirror.clone(),
                excluded_by: BTreeSet::from([PolicyLayer::Delegation]),
            },
            RefusalDetail::AuthorizationMissing { tuple: mirror },
        ]
    );
    // Intent is a typed operation, never an HTTP verb: a declaration has no verb field.
    let mut verb = base();
    verb["capabilities"][2]["capability"]["method"] = json!("GET");
    assert_eq!(
        only(&read_declaration(&text(&verb)).unwrap_err()),
        &RefusalDetail::UnknownField {
            field: "method".to_owned()
        }
    );
}

#[test]
fn resolution_is_v01_resolve_of_the_compiled_request() {
    let host = Host::ready();
    let tuples = base_tuples();
    let (product, delegation) = (product(&tuples), delegation(&tuples));
    let evaluation = host
        .evaluate(&text(&base()), &product, &delegation)
        .unwrap();
    let request = compile_value(&base()).unwrap().validate().unwrap();
    assert_eq!(evaluation.request(), &request);
    assert_eq!(
        evaluation.resolved(),
        &resolve(&product, &request, &delegation)
    );
    assert_eq!(
        evaluation.resolved().source().name.as_str(),
        "report-writer"
    );
}

// ---- follow-up: user sources, shared route names, credential budgets ----

#[test]
fn a_user_authored_declaration_is_recorded_as_such_and_still_cannot_widen_anything() {
    let host = Host::ready();
    let tuples = base_tuples();
    let mut value = base();
    value["source"]["kind"] = json!("user");
    // It asks for a route the product never permits, as a required capability.
    value["capabilities"].as_array_mut().unwrap().push(cap(
        "required",
        "fetch",
        json!({"kind": "connect", "destination": "exfil.example.net"}),
    ));
    let compiled = compile_value(&value).unwrap();
    assert_eq!(compiled.document().source.kind, SourceKind::User);
    assert_eq!(compiled.context().source.kind, SourceKind::User);
    let product = product(&tuples);
    let evaluation = host
        .evaluate(&text(&value), &product, &delegation(&tuples))
        .unwrap();
    assert_eq!(evaluation.resolved().source().kind, SourceKind::User);
    assert!(evaluation
        .resolved()
        .permitted()
        .is_subset(product.ceiling()));
    assert!(product
        .requirements()
        .is_subset(evaluation.resolved().requirements()));
    let refusal = evaluation.launch().as_ref().unwrap_err();
    assert!(matches!(
        &refusal.reasons[..],
        [LaunchRefusalReason::RequiredAuthorityRemoved { .. }]
    ));
    let preview = evaluation.preview(&[], None, None);
    assert!(preview
        .render_text()
        .contains("Source: \"report-writer\", declared by a user; a request, never a grant"));
    // Every authority field is refused for a user exactly as for a publisher.
    for field in AUTHORITY_FIELDS {
        let mut granting = value.clone();
        granting[*field] = json!(true);
        assert_eq!(
            only(&read_declaration(&text(&granting)).unwrap_err()).code(),
            RefusalCode::AuthorityField
        );
    }
    // The former separate author field is gone: it is an unknown field now.
    let mut author = base();
    author["author"] = json!("publisher");
    assert_eq!(
        only(&read_declaration(&text(&author)).unwrap_err()),
        &RefusalDetail::UnknownField {
            field: "author".to_owned()
        }
    );
    assert_eq!(
        only(
            &read_declaration(&text(&{
                let mut unknown = base();
                unknown["source"]["kind"] = json!("administrator");
                unknown
            }))
            .unwrap_err()
        )
        .code(),
        RefusalCode::InvalidDeclaration
    );
}

#[test]
fn route_names_from_v01_v02_and_v08_agree_for_equivalent_destinations() {
    use crate::sandbox_contract::destinations::{route_reference, Authority, DestinationPort};
    for (spelling, canonical) in [
        ("registry.example.com", "registry.example.com:443"),
        ("Registry.EXAMPLE.com", "registry.example.com:443"),
        ("registry.example.com:443", "registry.example.com:443"),
        ("REGISTRY.example.com:8443", "registry.example.com:8443"),
        ("xn--bcher-kva.example.com", "xn--bcher-kva.example.com:443"),
    ] {
        let authority = Authority::parse(spelling, DestinationPort::HTTPS).unwrap();
        let from_v02 = route_reference(&authority);
        let from_v01 = ResourceRef::route(&authority).unwrap();
        let compiled = compile_value(&declaration(vec![cap(
            "required",
            "fetch",
            json!({"kind": "connect", "destination": spelling}),
        )]))
        .unwrap();
        let from_v08 = &compiled.document().requested[0].resource;
        assert_eq!(from_v02, canonical);
        assert_eq!(from_v01.name.as_str(), canonical);
        assert_eq!(from_v08, &from_v01);
        assert_eq!(from_v08.kind, ResourceKind::Route);
    }
    // A ceiling written through V01 and a declaration written by hand meet on one route.
    let ceiling = PermissionTuple {
        resource: ResourceRef::route(
            &Authority::parse("REGISTRY.example.com:443", DestinationPort::HTTPS).unwrap(),
        )
        .unwrap(),
        ..connect_registry()
    };
    assert_eq!(ceiling, connect_registry());
    let value = declaration(vec![cap(
        "required",
        "fetch",
        json!({"kind": "connect", "destination": "registry.example.com"}),
    )]);
    let evaluation = Host::ready()
        .evaluate(
            &text(&value),
            &product(std::slice::from_ref(&ceiling)),
            &delegation(std::slice::from_ref(&ceiling)),
        )
        .unwrap();
    assert!(evaluation.resolved().permitted().covers(&ceiling));
    assert!(evaluation.launch().is_ok());
}

#[test]
fn a_declared_credential_budget_can_only_lower_the_hosts_limit() {
    let host = Host::ready();
    let token = tuple(
        Operation::ReceiveExternalCredential,
        ResourceKind::Credential,
        "upload-token",
        Phase::Analysis,
    );
    let scope = AccountingScope::Channel {
        resource: token.resource.clone(),
    };
    let key = BudgetKey {
        resource: BudgetResource::ShortLivedCredentialEffects,
        scope: scope.clone(),
    };
    let credential = |effects: u64| {
        declaration(vec![cap(
            "required",
            "analysis",
            json!({
                "kind": "short_lived_credential", "name": "upload-token",
                "audience": "uploads.example.com", "scope": "objects.put",
                "expires_in_seconds": 900, "delegated_effects": effects
            }),
        )])
    };
    let compiled = compile_value(&credential(20)).unwrap();
    assert_eq!(
        compiled.document().budgets,
        vec![Budget {
            resource: BudgetResource::ShortLivedCredentialEffects,
            scope: scope.clone(),
            limit: 20,
        }]
    );
    let mut budgets: Vec<Budget> = BudgetSet::vm_d12_task_defaults().into();
    budgets.push(Budget {
        resource: BudgetResource::ShortLivedCredentialEffects,
        scope: scope.clone(),
        limit: 10,
    });
    let product = Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![token.clone()],
        requirements: vec![
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable,
        ],
        approvals: Vec::new(),
        budgets,
    })
    .unwrap();
    for (asked, effective) in [(1_000_000, 10), (10, 10), (3, 3)] {
        let evaluation = host
            .evaluate(
                &text(&credential(asked)),
                &product,
                &delegation(std::slice::from_ref(&token)),
            )
            .unwrap();
        assert_eq!(evaluation.resolved().budgets().limit(&key), Some(effective));
        let preview = evaluation.preview(&[], None, None);
        let line = preview.budgets.iter().find(|line| line.key == key).unwrap();
        assert_eq!((line.limit, line.declared), (effective, Some(asked)));
        assert_eq!(
            preview.render_text().contains(&format!(
                "the declaration asked for {asked}, and the lower limit applies"
            )),
            asked > effective
        );
    }
    // A host limit in another scope does not hide the declaration's own channel limit:
    // both apply, and neither is raised.
    let unlimited = product_with(
        std::slice::from_ref(&token),
        &[SecurityPredicate::VmSandbox],
        Vec::new(),
    );
    let evaluation = host
        .evaluate(
            &text(&credential(4)),
            &unlimited,
            &delegation(std::slice::from_ref(&token)),
        )
        .unwrap();
    assert_eq!(evaluation.resolved().budgets().limit(&key), Some(4));
    assert_eq!(
        evaluation.resolved().budgets().limit(&BudgetKey {
            resource: BudgetResource::ShortLivedCredentialEffects,
            scope: AccountingScope::Generation,
        }),
        Some(HOST_CREDENTIAL_EFFECTS)
    );
    // The same key listed again under budgets is ambiguous, and V01 refuses it.
    let mut twice = credential(4);
    twice["budgets"] = json!([{
        "resource": "short_lived_credential_effects",
        "scope": {"scope": "channel", "resource": {"kind": "credential", "name": "upload-token"}},
        "limit": 1_000_000
    }]);
    assert_eq!(
        only(&refusal_of(&twice)).code(),
        RefusalCode::DuplicateBudget
    );
}

#[test]
fn a_host_ceiling_granting_a_short_lived_credential_without_a_delegated_budget_is_refused() {
    let token = tuple(
        Operation::ReceiveExternalCredential,
        ResourceKind::Credential,
        "upload-token",
        Phase::Analysis,
    );
    let declared = declaration(vec![cap(
        "required",
        "analysis",
        json!({
            "kind": "short_lived_credential", "name": "upload-token",
            "audience": "uploads.example.com", "scope": "objects.put",
            "expires_in_seconds": 900, "delegated_effects": 5
        }),
    )]);
    // The declaration carries its own budget, but that cannot stand in for the host's.
    assert!(compile_value(&declared).unwrap().validate().is_ok());
    let draft = |budgets: Vec<Budget>| ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: vec![token.clone()],
        requirements: vec![SecurityPredicate::VmSandbox],
        approvals: Vec::new(),
        budgets,
    };
    let refusal = Validator::product(&draft(BudgetSet::vm_d12_task_defaults().into())).unwrap_err();
    let report = RefusalReport::from(refusal.clone());
    assert_eq!(
        only(&report),
        &RefusalDetail::CredentialWithoutDelegatedBudget {
            tuple: token.clone()
        }
    );
    let code = RefusalCode::CredentialWithoutDelegatedBudget;
    assert!(RefusalCode::ALL.contains(&code));
    assert_eq!(code.as_str(), "credential_without_delegated_budget");
    assert_eq!(code.stage(), RefusalStage::Validation);
    assert_eq!(report.refusals()[0].message, refusal.issues[0].to_string());
    assert!(report
        .render_text()
        .starts_with("[credential_without_delegated_budget] "));
    // With the host's delegated budget in place, the same declaration plans.
    let product = Validator::product(&draft(host_budgets())).unwrap();
    let evaluation = Host::ready()
        .evaluate(
            &text(&declared),
            &product,
            &delegation(std::slice::from_ref(&token)),
        )
        .unwrap();
    assert!(evaluation.launch().is_ok());
}
