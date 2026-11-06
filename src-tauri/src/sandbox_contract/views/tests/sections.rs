//! The VM-W53 answers: what will run, what it can read, write and keep, what it can
//! release and where, and why a capability is unavailable, in four fixed sections with
//! the existing preset names.

use super::*;
use crate::foundation::evidence::{HypervisorKind, Remedy};
use crate::foundation::ids::ExecutionCategory;
use crate::sandbox::backend::{BackendKind, Persistence};
use crate::sandbox_contract::declarations::{
    ApprovalStatus, CredentialClass, ExecutionProfile, Need, PersistenceClass, RefusalCode,
    RefusalDetail, RemovalEffect,
};
use crate::sandbox_contract::destinations::NetworkMode;
use crate::sandbox_contract::policy::{ApprovalKind, BudgetResource, PolicyLayer};

fn values(shown: &ShownView, section: Section) -> Vec<FactValue> {
    shown
        .section(section)
        .iter()
        .map(|line| line.fact.clone())
        .collect()
}

fn texts(shown: &ShownView, section: Section) -> Vec<String> {
    shown
        .section(section)
        .iter()
        .map(|line| line.to_string())
        .collect()
}

#[test]
fn the_sections_are_four_fixed_plain_language_titles() {
    assert_eq!(
        Section::ALL.map(Section::title),
        [
            "What will run",
            "What it can read, write and keep",
            "What it can release, and where",
            "What is unavailable, and why",
        ]
    );
    for section in Section::ALL {
        assert!(!section.title().to_ascii_lowercase().contains("security"));
        assert_eq!(section.to_string(), section.title());
        let json = serde_json::to_value(section).unwrap();
        assert_eq!(serde_json::from_value::<Section>(json).unwrap(), section);
    }
    // An empty section is still listed, so a UI or CLI shows a stable layout.
    let fixture = launch_with(
        Setup {
            declaration: offline_tool(),
            ceiling: vec![read_inputs(), write_outputs()],
            granted: vec![read_inputs(), write_outputs()],
            ..Setup::default()
        },
        |_| {},
    );
    let view = SandboxView::build(&fixture.inputs(None)).unwrap();
    let shown = fixture.shown(&view);
    assert_eq!(shown.sections.len(), 4);
    assert!(shown.section(Section::Unavailable).is_empty());
}

#[test]
fn what_will_run_names_the_backend_artifacts_accelerator_and_profile() {
    let fixture = launch();
    let view = fixture.view();
    let shown = fixture.shown(&view);
    let facts = values(&shown, Section::WhatRuns);
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::Backend { backend }
            if backend.kind == BackendKind::Fake && backend.hypervisor == HypervisorKind::Kvm
    )));
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::PinnedArtifacts { pinned } if pinned.guest_image == image()
    )));
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::GuestImage { image: booted } if *booted == image()
    )));
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::Accelerator { accelerator } if *accelerator == kvm()
    )));
    assert!(facts.iter().any(
        |fact| matches!(fact, FactValue::DeviceProfile { profile } if profile.devices.is_cpu_only())
    ));
    // The declared run: profile and persistence class, with the planning-time runtime
    // observation left out (the launch record's host facts say what runs).
    let runs: Vec<&FactValue> = facts
        .iter()
        .filter(|fact| matches!(fact, FactValue::Run { .. }))
        .collect();
    let [FactValue::Run { run }] = runs.as_slice() else {
        panic!("one declared run: {runs:?}");
    };
    assert_eq!(run.profile, ExecutionProfile::Task);
    assert_eq!(run.persistence, PersistenceClass::Ephemeral);
    assert_eq!(run.required_runtime, ExecutionCategory::VmSandbox);
    assert_eq!(run.observed_runtime, None);
    assert_eq!(
        fixture.preview.runs[0].observed_runtime,
        Some(ExecutionCategory::VmSandbox)
    );
    // The lifetime budgets bound how long it runs.
    let lifetime = BudgetResource::AbsoluteLifetimeSeconds;
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::Budget { budget } if budget.key.resource == lifetime
    )));
    let lines = texts(&shown, Section::WhatRuns);
    for expected in [
        "backend fake backend 0.1.0 on KVM",
        "runs on KVM (hardware virtualization): observed by a host probe",
        "a usable KVM hypervisor on the host: verified by hypervisor availability evidence",
        "sandbox \"main\": task profile, ephemeral state, requires a VM sandbox; extension \
         \"fmt\" (Wasm) runs inside it as untrusted code and adds no authority: asserted by \
         the declaration",
        "its own guest kernel, shared physical host: observed",
        "device profile",
    ] {
        assert!(
            lines.iter().any(|line| line.starts_with(expected)),
            "missing {expected:?} in {lines:#?}"
        );
    }
}

#[test]
fn what_it_can_read_write_and_keep_shows_private_data_credentials_and_persistence() {
    let fixture = launch();
    let view = fixture.view();
    let shown = fixture.shown(&view);
    let facts = values(&shown, Section::ReadsAndKeeps);
    let read = facts
        .iter()
        .find_map(|fact| match fact {
            FactValue::Access { access } if access.tuple == read_inputs() => Some(access),
            _ => None,
        })
        .unwrap();
    assert!(read.private_data);
    assert_eq!(read.need, Need::Required);
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::Access { access } if access.tuple == write_outputs()
    )));
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::LocalSecret { secret }
            if secret.name.as_str() == "db-password"
                && secret.class == CredentialClass::SandboxLocalSecret
    )));
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::Persistence {
            persistence: Persistence::EphemeralTask
        }
    )));
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::Credentials { exposure } if exposure.credentials.is_empty()
    )));
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::Approval { approval }
            if approval.rule.kind == ApprovalKind::PrivateDataAccess
                && approval.status == ApprovalStatus::Needed
    )));
    let lines = texts(&shown, Section::ReadsAndKeeps);
    assert!(lines.iter().any(|line| line.starts_with(&format!(
        "{} [required; private data]: asserted by the contract",
        read_inputs()
    ))));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("persistence: ephemeral task: observed by a host probe")));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("credentials in the guest: none: observed")));
}

#[test]
fn what_it_can_release_shows_where_the_network_mode_and_the_budgets() {
    let fixture = launch();
    let view = fixture.view();
    let shown = fixture.shown(&view);
    let facts = values(&shown, Section::Releases);
    let released: Vec<_> = facts
        .iter()
        .filter_map(|fact| match fact {
            FactValue::Access { access } => Some(access.tuple.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(released.len(), 2);
    assert!(released.contains(&release_results()) && released.contains(&create_issue()));
    assert!(facts.contains(&FactValue::NetworkMode {
        mode: NetworkMode::DeclaredTransport
    }));
    assert!(facts.contains(&FactValue::ContractNetwork { offline: false }));
    assert!(facts.contains(&FactValue::Network {
        authority: routes_and_operations()
    }));
    let approvals: Vec<ApprovalKind> = facts
        .iter()
        .filter_map(|fact| match fact {
            FactValue::Approval { approval } => Some(approval.rule.kind),
            _ => None,
        })
        .collect();
    assert_eq!(
        approvals,
        [ApprovalKind::OngoingDelegation, ApprovalKind::ExactRelease]
    );
    assert!(facts.iter().any(|fact| matches!(
        fact,
        FactValue::Budget { budget } if budget.key.resource == BudgetResource::ReleaseBytes
    )));
    let lines = texts(&shown, Section::Releases);
    for expected in [
        "network mode: declared transport mode; encrypted transport can conceal",
        "network channels: named_transport_routes, typed_credentialed_operations: observed",
        "the contract grants network authority; each route, operation and service is listed: \
         asserted by the contract",
        "sandbox \"main\" may perform operation \"issues.create\" on provider account \"forge\"",
        "sandbox \"main\" may release through release channel \"results\"",
    ] {
        assert!(
            lines.iter().any(|line| line.starts_with(expected)),
            "missing {expected:?} in {lines:#?}"
        );
    }
}

#[test]
fn the_offline_preset_uses_the_existing_mode_and_contract_names() {
    let fixture = launch_with(
        Setup {
            declaration: offline_tool(),
            ceiling: vec![read_inputs(), write_outputs()],
            granted: vec![read_inputs(), write_outputs()],
            ..Setup::default()
        },
        |script| {
            script.network = crate::sandbox::backend::Scripted::HostObserved(
                crate::sandbox::backend::NetworkAuthority::offline(),
            );
        },
    );
    let view = SandboxView::build(&fixture.inputs(Some(NetworkMode::Offline))).unwrap();
    let shown = fixture.shown(&view);
    let lines = texts(&shown, Section::Releases);
    let declared = "network mode: offline mode: asserted by the declaration; it states what \
                    was asked for or granted, not what the host observed";
    assert!(lines.iter().any(|line| line == declared), "{lines:#?}");
    assert!(lines
        .iter()
        .any(|line| line.starts_with("the contract grants no network authority: offline")));
    assert!(lines
        .iter()
        .any(|line| line.starts_with("network: offline: observed by a host probe")));
    for mode in [NetworkMode::StrictAction, NetworkMode::DeclaredTransport] {
        let text = FactValue::NetworkMode { mode }.to_string();
        assert!(text.contains(mode.label()), "{text}");
    }
    // Without a chosen mode, none is invented.
    let unnamed = SandboxView::build(&fixture.inputs(None)).unwrap();
    assert!(!unnamed
        .facts()
        .iter()
        .any(|fact| matches!(fact.value, FactValue::NetworkMode { .. })));
}

#[test]
fn an_optional_capability_the_delegation_withholds_is_unavailable_with_its_remedy() {
    let fixture = launch();
    let view = fixture.view();
    let shown = fixture.shown(&view);
    let [line] = shown.section(Section::Unavailable) else {
        panic!("one unavailable capability");
    };
    assert_eq!(
        line.fact,
        FactValue::Requested {
            tuple: connect_registry(),
            need: Need::Optional,
        }
    );
    assert!(matches!(
        &line.label,
        FactLabel::Unavailable {
            why: Unavailability::NotPermitted { excluded_by, effect: RemovalEffect::Dropped },
            remedy: WhatToDo::Refusal { code: RefusalCode::RequiredAuthorityRemoved },
        } if *excluded_by == BTreeSet::from([PolicyLayer::Delegation])
    ));
    let text = line.to_string();
    assert!(text.starts_with(&format!("[optional] {}", connect_registry())));
    assert!(text.contains("not permitted by the delegation; it was optional and is dropped"));
    assert!(text.ends_with(RefusalCode::RequiredAuthorityRemoved.help()));
}

#[test]
fn a_required_capability_removed_refuses_planning_with_its_code() {
    let fixture = launch_with(
        Setup {
            granted: vec![write_outputs(), release_results(), create_issue()],
            ..Setup::default()
        },
        |_| {},
    );
    assert!(fixture.evaluation.launch().is_err());
    let view = fixture.view();
    let shown = fixture.shown(&view);
    let unavailable = shown.section(Section::Unavailable);
    assert!(unavailable.iter().any(|line| line.fact
        == FactValue::Requested {
            tuple: read_inputs(),
            need: Need::Required,
        }
        && matches!(
            line.label,
            FactLabel::Unavailable {
                why: Unavailability::NotPermitted {
                    effect: RemovalEffect::LaunchRefused,
                    ..
                },
                ..
            }
        )));
    let refusal = unavailable
        .iter()
        .find(|line| matches!(line.fact, FactValue::Planning { .. }))
        .unwrap();
    let FactValue::Planning { refusal: planned } = &refusal.fact else {
        panic!("a planning refusal: {refusal}");
    };
    assert!(matches!(
        &planned.detail,
        RefusalDetail::RequiredAuthorityRemoved { tuple, .. } if *tuple == read_inputs()
    ));
    assert!(matches!(
        refusal.label,
        FactLabel::Unavailable {
            why: Unavailability::Refused {
                code: RefusalCode::RequiredAuthorityRemoved
            },
            remedy: WhatToDo::Refusal {
                code: RefusalCode::RequiredAuthorityRemoved
            },
        }
    ));
    assert!(refusal
        .to_string()
        .starts_with("[required_authority_removed] the workload needs"));
}

#[test]
fn refused_host_evidence_at_planning_carries_the_core01_remedy() {
    let fixture = launch_with(
        Setup {
            planning_configuration: config("b"),
            ..Setup::default()
        },
        |_| {},
    );
    assert!(fixture.evaluation.launch().is_err());
    let view = fixture.view();
    let shown = fixture.shown(&view);
    let refusal = shown
        .section(Section::Unavailable)
        .iter()
        .find(|line| matches!(line.fact, FactValue::Planning { .. }))
        .unwrap();
    assert!(matches!(
        refusal.label,
        FactLabel::Unavailable {
            why: Unavailability::Refused {
                code: RefusalCode::RequirementUnmet
            },
            remedy: WhatToDo::Evidence {
                remedy: Remedy::RecheckCurrentConfiguration
            },
        }
    ));
    // The launch record's own hypervisor evidence, under the configuration in force, is
    // still verified: the planning refusal is a past decision, not current evidence.
    let hypervisor = labels_of(&shown, |fact| {
        matches!(fact, FactValue::HypervisorAvailable { .. })
    });
    assert!(hypervisor[0].is_verified());
}

#[test]
fn every_built_fact_fits_its_basis_and_section() {
    for fixture in [
        launch(),
        launch_with(
            Setup {
                granted: vec![write_outputs(), release_results(), create_issue()],
                ..Setup::default()
            },
            |script| {
                script.guest.accelerator = Some(kvm());
                script.guest.persistence = Some(Persistence::EphemeralTask);
            },
        ),
    ] {
        let view = fixture.view();
        assert!(view.facts().iter().all(ViewFact::fits));
        let shown = fixture.shown(&view);
        for section in Section::ALL {
            let count = view
                .facts()
                .iter()
                .filter(|fact| fact.section() == section)
                .count();
            assert_eq!(shown.section(section).len(), count);
        }
    }
}
