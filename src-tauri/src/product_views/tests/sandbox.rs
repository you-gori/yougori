//! V17's shown view converted: one evidence state per fact, V17's sections, titles,
//! wording and notice kept, and the permissions it lists.

use std::collections::BTreeSet;

use serde_json::json;

use super::*;
use crate::foundation::evidence::{ClockSession, HypervisorKind, UnknownReason};
use crate::foundation::product::{
    Asserter, Evidence, EvidenceCode, Observer, PermissionLine, PermissionStatus, RefusalCode,
    Remedy, SandboxEvidence, SandboxSection, VerifiedBy, SANDBOX_NOTICE,
};
use crate::product_views::from_sandbox::{permissions_of_view, policy_code};
use crate::product_views::from_setup::requested_permission;
use crate::sandbox::backend::{
    Accelerator, FactName, NetworkAuthority, NetworkChannel, Persistence,
};
use crate::sandbox_contract::declarations::{
    AccessLine, ContractLine, ContractMeaning, Need, RefusalCode as PolicyCode, RemovalEffect,
};
use crate::sandbox_contract::destinations::NetworkMode;
use crate::sandbox_contract::policy::{
    Context, GenerationScope, Operation, PermissionTuple, Phase, PolicyLayer, Principal,
    ResourceKind, ResourceRef,
};
use crate::sandbox_contract::views::{
    AssertedBy, EvidenceStamp, FactBasis, FactValue, ObservationStamp, Section, ShownLine,
    ShownSection, ShownView, ViewNotice,
};

fn tuple(operation: Operation, kind: ResourceKind, name: &str) -> PermissionTuple {
    PermissionTuple {
        principal: Principal::role("main").unwrap(),
        operation,
        resource: ResourceRef::new(kind, name).unwrap(),
        context: Context {
            phase: Phase::Analysis,
        },
        generation: GenerationScope::EveryGeneration,
    }
}

/// A V17 shown view at `now`, each fact labelled by V17's own [`FactBasis::label_at`]:
/// a verified accelerator, current host-probe hypervisor evidence, a stale network
/// observation, a device fact only the guest asserted, a guest-asserted persistence, a
/// contract-granted read, a declared network mode and a requested write the contract does
/// not permit.
pub(super) fn shown_view(now: ClockReading) -> ShownView {
    let session: ClockSession = now.session();
    let at = now.at();
    let fresh = ObservationStamp {
        clock: session,
        observed_at: at,
        fresh_for: HOUR,
        configuration: config(),
    };
    let old = ObservationStamp {
        observed_at: MonotonicTime::ZERO,
        fresh_for: Duration::from_nanos(10),
        ..fresh
    };
    let hypervisor = EvidenceStamp {
        capability: Capability::HypervisorAvailable,
        subject: digest("yougori/test/product/machine/v1", &[b"m"]),
        source: SourceClass::HostProbe,
        configuration: config(),
        clock: session,
        observed_at: at,
        fresh_until: at.saturating_add(HOUR),
    };
    let facts = [
        (
            FactValue::Accelerator {
                accelerator: Accelerator::Hardware {
                    hypervisor: HypervisorKind::Kvm,
                },
            },
            FactBasis::HostVerified { stamp: fresh },
        ),
        (
            FactValue::HypervisorAvailable {
                hypervisor: HypervisorKind::Kvm,
            },
            FactBasis::Core01Evidence { stamp: hypervisor },
        ),
        (
            FactValue::Unobserved {
                fact: FactName::Devices,
            },
            FactBasis::NotObserved {
                reason: UnknownReason::NotTested,
                guest_asserted: true,
            },
        ),
        (
            FactValue::Persistence {
                persistence: Persistence::EphemeralTask,
            },
            FactBasis::Asserted {
                by: AssertedBy::Guest,
                received_at: Some(at),
            },
        ),
        (
            FactValue::Access {
                access: AccessLine {
                    tuple: tuple(Operation::FileRead, ResourceKind::FileGrant, "inputs"),
                    need: Need::Required,
                    private_data: false,
                },
            },
            FactBasis::Asserted {
                by: AssertedBy::Contract,
                received_at: None,
            },
        ),
        (
            FactValue::NetworkMode {
                mode: NetworkMode::Offline,
            },
            FactBasis::Asserted {
                by: AssertedBy::Declaration,
                received_at: None,
            },
        ),
        (
            FactValue::Network {
                authority: NetworkAuthority::of([NetworkChannel::NamedTransportRoutes]),
            },
            FactBasis::HostObserved { stamp: old },
        ),
        (
            FactValue::Requested {
                tuple: tuple(Operation::FileWrite, ResourceKind::FileGrant, "outputs"),
                need: Need::Optional,
            },
            FactBasis::NotPermitted {
                excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling]),
                effect: RemovalEffect::Dropped,
            },
        ),
    ];
    let sections = Section::ALL
        .into_iter()
        .map(|section| ShownSection {
            section,
            title: section.title(),
            lines: facts
                .iter()
                .filter(|(fact, _)| fact.section() == section)
                .map(|(fact, basis)| ShownLine {
                    fact: fact.clone(),
                    label: basis.label_at(now, config(), HOUR),
                })
                .collect(),
        })
        .collect();
    ShownView {
        view: digest("yougori/test/product/view/v1", &[b"view"]),
        launch_record: digest("yougori/test/product/launch/v1", &[b"launch"]),
        contract: ContractLine {
            digest: digest("yougori/test/product/contract/v1", &[b"contract"]),
            meaning: ContractMeaning,
        },
        clock: session,
        shown_at: at,
        configuration: config(),
        sections,
        notice: ViewNotice,
    }
}

#[test]
fn each_v17_label_becomes_the_same_one_evidence_state() {
    let probes = Probes::new(SourceClass::HostProbe);
    probes.advance(Duration::from_secs(1));
    let view = shown_view(probes.now());
    let sandbox = SandboxEvidence::from(&view);
    let by_kind = |kind: &str| {
        sandbox
            .lines()
            .find(|line| line.kind() == kind)
            .unwrap()
            .evidence()
            .clone()
    };
    assert!(matches!(
        by_kind("accelerator"),
        Evidence::Verified {
            by: VerifiedBy::ControlledCheck,
            ..
        }
    ));
    assert!(matches!(
        by_kind("hypervisor_available"),
        Evidence::Verified {
            by: VerifiedBy::HostProbe {
                capability: Capability::HypervisorAvailable
            },
            ..
        }
    ));
    let guest_only = by_kind("unobserved");
    let refusal = guest_only.refusal().unwrap();
    assert_eq!(
        refusal.code,
        RefusalCode::Evidence {
            code: EvidenceCode::OnlyGuestAsserted
        }
    );
    assert_eq!(
        by_kind("persistence"),
        Evidence::Asserted {
            by: Asserter::Guest,
            received_at: Some(probes.now().at()),
        }
    );
    assert_eq!(
        by_kind("access"),
        Evidence::Asserted {
            by: Asserter::Contract,
            received_at: None,
        }
    );
    assert_eq!(
        by_kind("network").refusal().unwrap().code,
        RefusalCode::Evidence {
            code: EvidenceCode::Stale
        }
    );
    let requested = by_kind("requested");
    let refusal = requested.refusal().unwrap();
    assert_eq!(
        refusal.code,
        RefusalCode::SandboxPolicy {
            code: policy_code(PolicyCode::RequiredAuthorityRemoved)
        }
    );
    assert_eq!(
        refusal.remedy(),
        &Remedy::SandboxPolicy {
            code: policy_code(PolicyCode::RequiredAuthorityRemoved)
        }
    );
    assert_eq!(
        refusal.remedy_text().as_str(),
        PolicyCode::RequiredAuthorityRemoved.help()
    );

    for (shown, converted) in view.lines().zip(sandbox.lines()) {
        assert_eq!(shown.label.name(), converted.evidence().name());
        assert_eq!(converted.text().as_str(), shown.fact.to_string());
    }
    assert!(!sandbox.lines().any(|line| matches!(
        line.evidence(),
        Evidence::Observed {
            by: Observer::ProviderApi,
            ..
        }
    )));
}

#[test]
fn sections_titles_and_notice_are_v17s_and_are_refused_when_altered() {
    let probes = Probes::new(SourceClass::HostProbe);
    let sandbox = SandboxEvidence::from(&shown_view(probes.now()));
    let order: Vec<SandboxSection> = sandbox.sections().iter().map(|s| s.section()).collect();
    assert_eq!(order, SandboxSection::ALL);
    for (section, shown) in Section::ALL.into_iter().zip(sandbox.sections()) {
        assert_eq!(shown.title(), section.title());
        assert_eq!(SandboxSection::from(section).title(), section.title());
    }
    assert_eq!(SANDBOX_NOTICE, ViewNotice::TEXT);
    assert_eq!(sandbox.section(SandboxSection::ReadsAndKeeps).len(), 2);
    assert_eq!(round_trip(&sandbox), sandbox);

    let json = serde_json::to_value(&sandbox).unwrap();
    let mut certificate = json.clone();
    certificate["notice"] = json!("Certified secure.");
    assert!(refused::<SandboxEvidence>(certificate).contains("standing notice"));
    let mut dropped = json.clone();
    dropped["sections"].as_array_mut().unwrap().pop();
    assert!(refused::<SandboxEvidence>(dropped).contains("four sections"));
    let mut retitled = json.clone();
    retitled["sections"][0]["title"] = json!("Verified");
    assert!(refused::<SandboxEvidence>(retitled).contains("is titled"));
    let mut promoted = json;
    promoted["sections"][1]["lines"][0]["evidence"] =
        json!({"state": "observed", "by": "guest", "observed_at": 1, "fresh_until": 2});
    assert!(refused::<SandboxEvidence>(promoted).contains("unknown variant"));
}

#[test]
fn permissions_are_requested_permitted_or_not_permitted_never_enforced() {
    let probes = Probes::new(SourceClass::HostProbe);
    let view = shown_view(probes.now());
    let permissions = permissions_of_view(&view);
    let statuses: Vec<(&str, &PermissionStatus)> = permissions
        .iter()
        .map(|line| (line.kind(), line.status()))
        .collect();
    assert_eq!(statuses.len(), 2);
    assert_eq!(
        statuses[0],
        ("access", &PermissionStatus::PermittedByContract)
    );
    let ("requested", PermissionStatus::NotPermitted { refusal }) = statuses[1] else {
        panic!("{statuses:?}");
    };
    assert_eq!(refusal.code.as_str(), "required_authority_removed");

    let gpu = requested_permission(yougori_setup::capability::Permission::UseGpu);
    assert_eq!(gpu.kind(), "use_gpu");
    assert_eq!(gpu.status(), &PermissionStatus::Requested);
    assert_eq!(gpu.text().as_str(), "Use this computer's GPU.");
    assert!(gpu.to_string().contains("asking does not grant it"));
    assert_eq!(round_trip(&gpu), gpu);

    let enforced = refused::<PermissionLine>(json!({
        "kind": "use_gpu", "text": "Use the GPU.", "status": {"status": "enforced"}
    }));
    assert!(enforced.contains("unknown variant"), "{enforced}");
    let bad_kind = refused::<PermissionLine>(json!({
        "kind": "use gpu!", "text": "Use the GPU.", "status": {"status": "requested"}
    }));
    assert!(bad_kind.contains("identifier"), "{bad_kind}");
}
