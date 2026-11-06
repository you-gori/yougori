//! Tests for V17, one file per area, on the real V01 resolver and planner, V08's
//! declarations and preview, and the `sandbox::backend` fake backend admitting a launch
//! against a CORE-01 registry with fake probes on a manual clock. Nothing here starts a
//! VM or probes a host.

mod labels;
mod record;
mod sections;
mod shown;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::*;
use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::evidence::fakes::FakeProbe;
use crate::foundation::evidence::{
    Backend, BackendRelease, BackendVersion, Capability as ProbeCapability, ClockReading,
    ConfigurationFingerprint, HypervisorKind, HypervisorSubject, Observation, OsKind,
    ProbeRegistry, RuntimeSubject, SourceClass, Subject, SupportDetail,
};
use crate::foundation::ids::{
    digest, AuthorizationEpoch, Digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime,
    PolicyEpoch, TenantId,
};
use crate::foundation::ledger::ReservationId;
use crate::sandbox::backend::{
    Accelerator, Architecture, BuildId, DeviceExposure, DeviceProfile, FakeBackend, HostBuild,
    HostScript, LaunchRecord, LaunchRequest, NetworkAuthority, NetworkChannel, PinnedArtifacts,
    RequiredProperties, VmBackend,
};
use crate::sandbox_contract::declarations::{evaluate, Evaluation, PolicyPreview};
use crate::sandbox_contract::destinations::NetworkMode;
use crate::sandbox_contract::policy::{
    AccountingScope, Budget, BudgetResource, BudgetSet, Context, Delegation, DelegationDraft,
    GenerationScope, LaunchTargets, Operation, OperationName, PermissionTuple, Phase, Principal,
    ProductPolicy, ProductPolicyDraft, ResourceKind, ResourceRef, SecurityPredicate, Validator,
};

pub(super) const MINUTE: Duration = Duration::from_secs(60);
pub(super) const HOUR: Duration = Duration::from_secs(3_600);
pub(super) const E1: AuthorizationEpoch = AuthorizationEpoch::FIRST;

// ---- host ----

pub(super) fn config(name: &str) -> ConfigurationFingerprint {
    ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
}

pub(super) fn machine() -> Digest {
    digest("yougori/test/views/machine/v1", &[b"workstation"])
}

pub(super) fn image() -> Digest {
    digest("yougori/test/views/image/v1", &[b"alpine"])
}

pub(super) fn artifact() -> Digest {
    digest("yougori/test/views/backend/v1", &[b"fake"])
}

pub(super) fn control() -> Digest {
    digest("yougori/test/views/control/v1", &[b"positive"])
}

pub(super) fn kvm() -> Accelerator {
    Accelerator::Hardware {
        hypervisor: HypervisorKind::Kvm,
    }
}

pub(super) fn host_build() -> HostBuild {
    HostBuild {
        os: OsKind::Linux,
        build: BuildId::new("6.12.0").unwrap(),
        architecture: Architecture::X86_64,
    }
}

pub(super) fn routes_and_operations() -> NetworkAuthority {
    NetworkAuthority::of([
        NetworkChannel::NamedTransportRoutes,
        NetworkChannel::TypedCredentialedOperations,
    ])
}

/// A manual clock and a CORE-01 registry whose runtime-category and hypervisor probes are
/// host probes, both observed under configuration "a" and fresh for an hour.
pub(super) struct Host {
    pub(super) clock: Arc<ManualClock>,
    pub(super) registry: ProbeRegistry<Arc<ManualClock>>,
    pub(super) targets: LaunchTargets,
}

impl Host {
    pub(super) fn new() -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
        let mut registry = ProbeRegistry::new(Arc::clone(&clock));
        let category = Arc::new(FakeProbe::runtime_category(SourceClass::HostProbe));
        let hypervisor = Arc::new(FakeProbe::hypervisor_availability());
        registry.register(Box::new(Arc::clone(&category))).unwrap();
        registry
            .register(Box::new(Arc::clone(&hypervisor)))
            .unwrap();
        let targets = LaunchTargets {
            runtime: RuntimeSubject {
                category: ExecutionCategory::VmSandbox,
                release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
                instance: digest("yougori/test/views/instance/v1", &[b"sandbox-1"]),
            },
            runtime_configuration: config("a"),
            hypervisor: HypervisorSubject {
                machine: machine(),
                hypervisor: HypervisorKind::Kvm,
            },
            hypervisor_configuration: config("a"),
            max_age: MINUTE,
            perimeter: None,
        };
        let runtime = Subject::Runtime(targets.runtime.clone());
        category.respond(
            &runtime,
            Observation::supported(
                config("a"),
                HOUR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
        );
        registry
            .refresh(ProbeCapability::RuntimeCategory, &runtime)
            .unwrap();
        let subject = Subject::Hypervisor(targets.hypervisor);
        hypervisor.respond(
            &subject,
            Observation::supported(
                config("a"),
                HOUR,
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Kvm,
                },
            ),
        );
        registry
            .refresh(ProbeCapability::HypervisorAvailable, &subject)
            .unwrap();
        Self {
            clock,
            registry,
            targets,
        }
    }

    pub(super) fn now(&self) -> ClockReading {
        self.registry.now()
    }

    pub(super) fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// A registry on the same clock after a restart: a new clock session.
    pub(super) fn restarted(&self) -> ProbeRegistry<Arc<ManualClock>> {
        ProbeRegistry::new(Arc::clone(&self.clock))
    }
}

// ---- contract ----

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

pub(super) fn product(ceiling: &[PermissionTuple]) -> ProductPolicy {
    let mut budgets: Vec<Budget> = BudgetSet::vm_d12_task_defaults().into();
    budgets.push(Budget {
        resource: BudgetResource::ShortLivedCredentialEffects,
        scope: AccountingScope::Generation,
        limit: 100,
    });
    Validator::product(&ProductPolicyDraft {
        policy_epoch: PolicyEpoch::FIRST,
        ceiling: ceiling.to_vec(),
        requirements: vec![
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable,
        ],
        approvals: Vec::new(),
        budgets,
    })
    .unwrap()
}

pub(super) fn delegation(granted: &[PermissionTuple]) -> Delegation {
    Validator::delegation(&DelegationDraft {
        granted: granted.to_vec(),
        approvals: Vec::new(),
        budgets: Vec::new(),
    })
    .unwrap()
}

pub(super) fn cap(need: &str, phase: &str, capability: Value) -> Value {
    json!({"need": need, "role": "main", "phase": phase, "capability": capability})
}

/// The report-writer tool: a private read, a write, an optional route, an exactly
/// approved release, a provider operation under ongoing delegation and a local secret.
pub(super) fn report_writer() -> Value {
    let mut release = cap(
        "required",
        "publication",
        json!({"kind": "release", "channel": "results"}),
    );
    release["approval"] = json!("exact_release");
    let mut operation = cap(
        "required",
        "analysis",
        json!({"kind": "provider_operation", "account": "forge", "operation": "issues.create"}),
    );
    operation["approval"] = json!("ongoing_delegation");
    json!({
        "declaration_version": 1,
        "source": {"kind": "tool", "name": "report-writer"},
        "sandboxes": [{"role": "main", "profile": "task", "persistence": "ephemeral"}],
        "extensions": [{"name": "fmt", "role": "main", "runtime": "wasm"}],
        "capabilities": [
            cap(
                "required",
                "analysis",
                json!({
                    "kind": "read_input",
                    "grant": "inputs",
                    "data_class": "user_private_content",
                }),
            ),
            cap("required", "analysis", json!({"kind": "write_output", "grant": "outputs"})),
            cap(
                "optional",
                "fetch",
                json!({"kind": "connect", "destination": "registry.example.com"}),
            ),
            release,
            operation,
            cap(
                "required",
                "analysis",
                json!({"kind": "sandbox_local_secret", "name": "db-password"}),
            ),
        ],
    })
}

/// A declaration that reads and writes files and has no network authority at all.
pub(super) fn offline_tool() -> Value {
    json!({
        "declaration_version": 1,
        "source": {"kind": "template", "name": "local-notes"},
        "sandboxes": [{"role": "main", "profile": "task", "persistence": "ephemeral"}],
        "capabilities": [
            cap(
                "required",
                "analysis",
                json!({"kind": "read_input", "grant": "inputs", "data_class": "ordinary"}),
            ),
            cap("required", "analysis", json!({"kind": "write_output", "grant": "outputs"})),
        ],
    })
}

// ---- launch ----

/// How a fixture is set up; the default is the report writer with the route withheld by
/// the delegation, planned and launched under configuration "a".
pub(super) struct Setup {
    pub(super) declaration: Value,
    pub(super) ceiling: Vec<PermissionTuple>,
    pub(super) granted: Vec<PermissionTuple>,
    /// The configuration V01 planning judges hypervisor evidence under.
    pub(super) planning_configuration: ConfigurationFingerprint,
    pub(super) execution: &'static str,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            declaration: report_writer(),
            ceiling: base_tuples(),
            granted: vec![
                read_inputs(),
                write_outputs(),
                release_results(),
                create_issue(),
            ],
            planning_configuration: config("a"),
            execution: "exe-1",
        }
    }
}

/// A planned and launched sandbox.
pub(super) struct Fixture {
    pub(super) host: Host,
    pub(super) evaluation: Evaluation,
    pub(super) preview: PolicyPreview,
    pub(super) record: LaunchRecord,
}

pub(super) fn script() -> HostScript {
    let mut script =
        HostScript::hardware_vm(HypervisorKind::Kvm, host_build(), image(), config("a"));
    script.network = crate::sandbox::backend::Scripted::HostObserved(routes_and_operations());
    script
}

pub(super) fn request(execution: &str, contract: Digest) -> LaunchRequest {
    let mut required = RequiredProperties::strictest(MINUTE);
    required.network = routes_and_operations();
    LaunchRequest {
        execution: ExecutionId::new(execution).unwrap(),
        tenant: TenantId::new("tenant-1").unwrap(),
        generations: SandboxGenerations::FIRST,
        machine: machine(),
        configuration: config("a"),
        contract,
        pinned: PinnedArtifacts {
            guest_image: image(),
            backend: artifact(),
        },
        device_profile: DeviceProfile {
            identity: digest("yougori/test/views/profile/v1", &[b"minimal"]),
            devices: DeviceExposure::cpu_only(),
        },
        required,
        reservation: serde_json::from_value::<ReservationId>(1.into()).unwrap(),
    }
}

pub(super) fn launch_with(setup: Setup, edit: impl FnOnce(&mut HostScript)) -> Fixture {
    let mut host = Host::new();
    host.targets.hypervisor_configuration = setup.planning_configuration;
    let evaluation = evaluate(
        &serde_json::to_string(&setup.declaration).unwrap(),
        &product(&setup.ceiling),
        &delegation(&setup.granted),
        &host.registry,
        &host.targets,
    )
    .unwrap();
    let preview = evaluation.preview(&[], Some(E1), None);
    let mut script = script();
    edit(&mut script);
    let mut backend = FakeBackend::new(
        HypervisorKind::Kvm,
        BackendVersion::new("0.1.0").unwrap(),
        artifact(),
        script,
    );
    let request = request(setup.execution, evaluation.resolved().identity().digest());
    let record = backend.launch(&request, &host.registry).unwrap().record;
    Fixture {
        host,
        evaluation,
        preview,
        record,
    }
}

pub(super) fn launch() -> Fixture {
    launch_with(Setup::default(), |_| {})
}

impl Fixture {
    pub(super) fn inputs(&self, network_mode: Option<NetworkMode>) -> ViewInputs<'_> {
        ViewInputs {
            record: &self.record,
            contract: self.evaluation.resolved(),
            preview: &self.preview,
            network_mode,
        }
    }

    /// The view with the declared transport mode the report writer's route needs.
    pub(super) fn view(&self) -> SandboxView {
        SandboxView::build(&self.inputs(Some(NetworkMode::DeclaredTransport))).unwrap()
    }

    pub(super) fn now(&self) -> ClockReading {
        self.host.now()
    }

    /// The view shown now under configuration "a".
    pub(super) fn shown(&self, view: &SandboxView) -> ShownView {
        view.status_at(self.now(), config("a"))
    }
}

// ---- helpers ----

/// The view's JSON after `edit`, read back.
pub(super) fn read_after(
    view: &SandboxView,
    edit: impl FnOnce(&mut Value),
) -> Result<SandboxView, ViewRefusal> {
    let mut json = serde_json::to_value(view).unwrap();
    edit(&mut json);
    SandboxView::from_json(&json.to_string())
}

/// A forger's view: the body edited and sealed again under a correct digest.
pub(super) fn resealed(view: &SandboxView, edit: impl FnOnce(&mut Value)) -> SandboxView {
    let mut json = serde_json::to_value(view.body()).unwrap();
    edit(&mut json);
    SandboxView::seal(serde_json::from_value::<ViewBody>(json).unwrap()).unwrap()
}

/// The index of the first fact `wanted` selects.
pub(super) fn index_of(view: &SandboxView, wanted: impl Fn(&ViewFact) -> bool) -> usize {
    view.facts().iter().position(wanted).unwrap()
}

/// Whether the fact is the host's (or the guest's) accelerator.
pub(super) fn is_accelerator(fact: &ViewFact) -> bool {
    matches!(fact.value, FactValue::Accelerator { .. })
}

pub(super) fn is_guest(fact: &ViewFact) -> bool {
    matches!(
        fact.basis,
        FactBasis::Asserted {
            by: AssertedBy::Guest,
            ..
        }
    )
}

/// The labels of every line whose fact `wanted` selects.
pub(super) fn labels_of(shown: &ShownView, wanted: impl Fn(&FactValue) -> bool) -> Vec<FactLabel> {
    shown
        .lines()
        .filter(|line| wanted(&line.fact))
        .map(|line| line.label.clone())
        .collect()
}

/// The facts of the launch record that are the host's own: observations and CORE-01
/// evidence.
pub(super) fn host_bases(view: &SandboxView) -> BTreeSet<usize> {
    view.facts()
        .iter()
        .enumerate()
        .filter(|(_, fact)| {
            matches!(
                fact.basis,
                FactBasis::HostObserved { .. }
                    | FactBasis::HostVerified { .. }
                    | FactBasis::Core01Evidence { .. }
            )
        })
        .map(|(index, _)| index)
        .collect()
}
