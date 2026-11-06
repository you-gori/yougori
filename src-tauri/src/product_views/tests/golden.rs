//! The current version's golden fixtures are exactly what the conversions produce from
//! typed sources, and each reads back as the same document; every version-1 fixture reads
//! back upgraded to what the conversions produce now. The endpoint fixture is built in
//! `endpoint`, the grant records fixture in `foundation::product`'s own tests.

use serde_json::Value;

use super::sandbox::shown_view;
use super::*;
use crate::foundation::events::Phase;
use crate::foundation::evidence::{ClockSession, RuntimeRequirement};
use crate::foundation::product::fixtures::GOLDEN_FIXTURES;
use crate::foundation::product::{
    read_view, CapabilityCheck, Execution, LegacyChoice, LegacySandboxType, MigrationItem,
    MigrationShown, MigrationStatus, ModelReadiness, ModelStatus, Preparation, ProductView,
    ProgressShown, Read, ReadPurpose, Refusal, SandboxEvidence, ShownAt, ViewSubject,
    ViewSubjectKind, PRODUCT_CONTRACT_VERSION,
};
use crate::model_memory::placement::{GpuResidency, PlacementState};
use crate::model_memory::readiness::intent::PrepareState;
use crate::model_memory::residency::host::{HostCopy, HostResidency};
use crate::product_views::from_models::residency;
use crate::product_views::from_sandbox::{permissions_of_view, tier_item};
use crate::product_views::from_setup::requested_permission;
use crate::sandbox_contract::policy::LegacyTier;
use yougori_setup::capability::Permission;

/// The clock session every fixture names, so fixtures do not depend on a random session.
fn fixed(mut view: ProductView) -> ProductView {
    view.shown_at.clock = ClockSession::from_uuid(uuid::Uuid::from_u128(
        0x0123_4567_89ab_4cde_8f01_2345_6789_abcd,
    ));
    view
}

fn subject(kind: ViewSubjectKind, id: &str) -> ViewSubject {
    ViewSubject::new(kind, id).unwrap()
}

/// A VM-required setup whose VM sandbox runs, with requested capabilities, V17's sandbox
/// view and the permissions it lists.
fn vm_sandbox_ready() -> ProductView {
    let mut probes = Probes::new(SourceClass::HostProbe);
    let guest = Arc::new(FakeProbe::guest_report(Capability::IoUring));
    probes
        .registry
        .register(Box::new(Arc::clone(&guest)))
        .unwrap();
    let vm = probes.offer(ExecutionCategory::VmSandbox);
    let io_subject = Subject::Runtime(runtime(ExecutionCategory::VmSandbox));
    guest.respond(
        &io_subject,
        Observation::supported(config(), HOUR, SupportDetail::Plain),
    );
    probes
        .registry
        .refresh(Capability::IoUring, &io_subject)
        .unwrap();
    probes.advance(Duration::from_secs(1));
    let now = probes.now();

    let category = Probes::requirement(ExecutionCategory::VmSandbox, SourceClass::HostProbe);
    let io_uring = Requirement::host_only(Capability::IoUring, io_subject, HOUR, config());
    let view = shown_view(now);
    let mut product = ProductView::new(
        subject(ViewSubjectKind::Setup, "web"),
        ShownAt::of(now, config()),
    );
    product.execution = Some(Execution::select(
        &RuntimeRequirement::VmSandbox,
        &[vm],
        now,
    ));
    product.capabilities = vec![
        CapabilityCheck::evaluate(&category, &probes.registry.evaluate(&category), now),
        CapabilityCheck::evaluate(&io_uring, &probes.registry.evaluate(&io_uring), now),
    ];
    product.sandbox = Some(SandboxEvidence::from(&view));
    product.permissions = std::iter::once(requested_permission(Permission::RunContainers))
        .chain(permissions_of_view(&view))
        .collect();
    fixed(product)
}

/// A VM-required setup offered only the shared-kernel GPU runtime: refused, with the
/// category matrix and the setup's requested permissions.
fn labelled_runtime_refused() -> ProductView {
    let mut probes = Probes::new(SourceClass::HostProbe);
    let gpu = probes.offer(ExecutionCategory::SharedKernelGpuRuntime);
    let now = probes.now();
    let mut product = ProductView::new(
        subject(ViewSubjectKind::Setup, "trainer"),
        ShownAt::of(now, config()),
    );
    let execution = Execution::select(&RuntimeRequirement::VmSandbox, &[gpu], now);
    product.refusals = execution
        .actual()
        .evidence()
        .refusal()
        .into_iter()
        .cloned()
        .collect();
    product.execution = Some(execution);
    product.permissions = vec![requested_permission(Permission::UseGpu)];
    fixed(product)
}

/// A model in an explicitly chosen provider-container runtime, observed by the provider's
/// API, preparing to keep ready and queued for GPU memory.
fn model_preparing() -> ProductView {
    let mut probes = Probes::new(SourceClass::ProviderApi);
    let requirement =
        RuntimeRequirement::explicit([ExecutionCategory::ProviderContainerRuntime]).unwrap();
    let pod = probes.offer(ExecutionCategory::ProviderContainerRuntime);
    let now = probes.now();
    let mut product = ProductView::new(
        subject(ViewSubjectKind::Model, "llama-3-8b"),
        ShownAt::of(now, config()),
    );
    product.execution = Some(Execution::select(&requirement, &[pod], now));
    product.model = Some(ModelStatus {
        readiness: ModelReadiness::from(&PlacementState::Preparing),
        preparation: Some(Preparation::from(&PrepareState::Running {
            started_at: now.at(),
        })),
        residency: residency(
            &GpuResidency::default(),
            Some(&HostCopy {
                bytes: 4_000_000_000,
                residency: HostResidency::Reclaimable {
                    mincore_resident_bytes: Some(1_000_000_000),
                },
            }),
        ),
        ready_for: None,
        memory: Vec::new(),
    });
    product.progress =
        vec![ProgressShown::of(&recorded(Phase::Queued, queued_for_memory())).unwrap()];
    fixed(product)
}

/// An old setup inventoried for migration: one item for each kind of recorded choice.
fn migration_needs_decision() -> ProductView {
    let probes = Probes::new(SourceClass::HostProbe);
    let now = probes.now();
    let items = vec![
        MigrationItem::new(
            "web",
            LegacyChoice::SandboxType {
                kind: LegacySandboxType::Vm,
                gpu: false,
            },
        )
        .unwrap(),
        MigrationItem::new(
            "api",
            LegacyChoice::SandboxType {
                kind: LegacySandboxType::Container,
                gpu: false,
            },
        )
        .unwrap(),
        MigrationItem::new(
            "trainer",
            LegacyChoice::SandboxType {
                kind: LegacySandboxType::Gpu,
                gpu: true,
            },
        )
        .unwrap(),
        MigrationItem::new(
            "pod",
            LegacyChoice::SandboxType {
                kind: LegacySandboxType::Cloud,
                gpu: false,
            },
        )
        .unwrap(),
        MigrationItem::new(
            "shared-db",
            LegacyChoice::SandboxType {
                kind: LegacySandboxType::Shared,
                gpu: false,
            },
        )
        .unwrap(),
        tier_item("analysis", LegacyTier::T2).unwrap(),
        tier_item("scratch", LegacyTier::T1).unwrap(),
        MigrationItem::new(
            "metal-runner",
            LegacyChoice::Category {
                category: ExecutionCategory::HostProcessModelRuntime,
            },
        )
        .unwrap(),
    ];
    let migration = MigrationShown::new(MigrationStatus::Pending, items, None).unwrap();
    let mut product = ProductView::new(
        subject(ViewSubjectKind::Setup, "legacy-lab"),
        ShownAt::of(now, config()),
    );
    product.refusals = migration.refusals();
    product.migration = Some(migration);
    fixed(product)
}

/// The current version's fixtures built here.
const BUILT_HERE: [&str; 4] = [
    "vm_sandbox_ready",
    "labelled_runtime_refused",
    "model_preparing",
    "migration_needs_decision",
];

/// The current version's fixtures built where their sources are: the declared agent
/// endpoint in `endpoint`, the grant records in `foundation::product`.
const BUILT_ELSEWHERE: [&str; 2] = ["agent_endpoint_declared", "execution_grants"];

/// The fixture `name`, built from typed sources.
pub(super) fn build(name: &str) -> ProductView {
    match name {
        "vm_sandbox_ready" => vm_sandbox_ready(),
        "labelled_runtime_refused" => labelled_runtime_refused(),
        "model_preparing" => model_preparing(),
        "migration_needs_decision" => migration_needs_decision(),
        other => panic!("no builder for fixture {other}"),
    }
}

#[test]
fn every_current_golden_fixture_is_what_the_conversions_produce() {
    let current: Vec<_> = GOLDEN_FIXTURES
        .iter()
        .filter(|fixture| fixture.version == PRODUCT_CONTRACT_VERSION)
        .collect();
    assert_eq!(current.len(), BUILT_HERE.len() + BUILT_ELSEWHERE.len());
    assert!(current.iter().all(|fixture| {
        BUILT_HERE.contains(&fixture.name) || BUILT_ELSEWHERE.contains(&fixture.name)
    }));
    for fixture in current
        .into_iter()
        .filter(|fixture| BUILT_HERE.contains(&fixture.name))
    {
        let built = build(fixture.name);
        let expected: Value = serde_json::from_str(fixture.json).unwrap();
        assert_eq!(
            serde_json::to_value(&built).unwrap(),
            expected,
            "fixture {} changed: a new field, code, remedy or category bumps \
             PRODUCT_CONTRACT_VERSION and adds fixtures; reworded text only rewrites this one",
            fixture.name
        );
        assert_eq!(built.to_json_pretty().unwrap() + "\n", fixture.json);
        match read_view(fixture.json, ReadPurpose::Act).unwrap() {
            Read::Current(read) => assert_eq!(read, built),
            other => panic!("{} read as {other:?}", fixture.name),
        }
    }
}

#[test]
fn every_version_1_fixture_upgrades_to_what_the_conversions_produce_now() {
    let older: Vec<_> = GOLDEN_FIXTURES
        .iter()
        .filter(|fixture| fixture.version == 1)
        .collect();
    assert_eq!(older.len(), BUILT_HERE.len());
    for fixture in older {
        match read_view(fixture.json, ReadPurpose::Act).unwrap() {
            Read::Upgraded { from: 1, document } => assert_eq!(document, build(fixture.name)),
            other => panic!("{} read as {other:?}", fixture.name),
        }
    }
}

#[test]
fn the_fixtures_show_what_ui_and_cli_need() {
    let ready = build("vm_sandbox_ready");
    let execution = ready.execution.as_ref().unwrap();
    assert!(execution.actual().evidence().is_verified());
    assert!(execution.actual().value().unwrap().category.is_sandbox());
    assert!(ready.capabilities[0].evidence().is_verified());
    assert_eq!(
        ready.capabilities[1]
            .evidence()
            .refusal()
            .unwrap()
            .code
            .as_str(),
        "evidence_source_too_weak"
    );
    assert_eq!(ready.permissions.len(), 3);

    let refused = build("labelled_runtime_refused");
    let refusal: &Refusal = &refused.refusals[0];
    assert_eq!(refusal.code.as_str(), "vm_sandbox_required");
    assert!(refused
        .execution
        .as_ref()
        .unwrap()
        .actual()
        .value()
        .is_none());

    let model = build("model_preparing");
    let actual = model.execution.as_ref().unwrap().actual();
    assert!(actual.evidence().is_observed());
    assert!(!actual.value().unwrap().category.is_sandbox());
    assert_eq!(
        model.progress[0].description().as_str(),
        "waiting for 4 GB of GPU memory"
    );

    let migration = build("migration_needs_decision");
    assert_eq!(migration.refusals.len(), 2);
    assert_eq!(migration.migration.as_ref().unwrap().items().len(), 8);
}
