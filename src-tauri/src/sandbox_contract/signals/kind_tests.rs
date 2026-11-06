//! The adapters on V14's new kinds: the file service's foreign-scope grant as a file-root
//! escape, the broker's release overrun as a budget overrun, and a canary credential
//! refused at an executor as a canary use the executor observed, each fed through V14's
//! assessment and responder (VM part §5.1, §2.5, §4.5, §8.2; VM-W43; M17B).

use std::collections::{BTreeMap, BTreeSet};

use super::fixtures::*;
use super::*;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{digest, SandboxBootGeneration};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::canaries::{
    CanaryKind, CanaryRegistry, CanarySeed, HitMeaning, HoneyportPool, PlacementLocation,
    PlacementRequest, PlantOrigin, PlantingRequest, SandboxBinding,
};
use crate::sandbox_contract::destinations::{
    ChannelPolicy, DestinationRefusal, InFlightAllowance, ReleaseAccount, ReleaseChannel,
    ReleaseTrustClass, RouteId,
};
use crate::sandbox_contract::effects::{IssuerId, SandboxRef};
use crate::sandbox_contract::files::{
    DisclosureAcknowledgment, GrantMode, GrantRefusal, RootHandle, SandboxClass, ServiceRefusal,
    ViolationAction,
};
use crate::sandbox_contract::response::{
    DecisionReason, HostObserver, MonitoringSignal, ResponseAction, SignalClass, SignalSource,
    TargetRole, ViolationKind,
};

fn file_context(sandbox: &str, now: &crate::foundation::ids::ManualClock) -> FileServiceContext {
    FileServiceContext {
        observed: observed(sandbox, now),
        root: RootHandle::from_host(digest("yougori/test/root/v1", &[b"workspace"])),
        mode: GrantMode::LiveWorkspace {
            acknowledgment: DisclosureAcknowledgment::of_current_statement(),
        },
        grant: grant("files-workspace"),
    }
}

fn broker_context(sandbox: &str, now: &crate::foundation::ids::ManualClock) -> BrokerContext {
    BrokerContext {
        observed: observed(sandbox, now),
        route: RouteId::new("api-example").unwrap(),
    }
}

/// A release overrun: 30 bytes left on a 10-byte reservation, past a 5-byte allowance.
fn overrun() -> DestinationRefusal {
    let mut account = ReleaseAccount::new(
        BTreeMap::from([(
            ReleaseChannel::ProviderRequest,
            ChannelPolicy {
                budget_bytes: 1_000,
                trust_class: ReleaseTrustClass::External,
            },
        )]),
        GeneralReleaseBudget::with_limit(10_000),
        InFlightAllowance {
            bytes: 5,
            documented_reason: "TLS framing is sized when sent".into(),
        },
    )
    .unwrap();
    let reservation = account
        .reserve(ReleaseChannel::ProviderRequest, 10)
        .unwrap();
    DestinationRefusal::Release(account.commit(reservation, 30).unwrap_err())
}

fn binding(name: &str) -> SandboxBinding {
    SandboxBinding {
        sandbox: SandboxRef {
            issuer: IssuerId::new(digest("yougori/test/issuer/v1", &[b"host-1"])),
            execution: execution(name),
        },
        instance: VmInstanceId::new(digest("yougori/test/instance/v1", &[name.as_bytes()])),
        boot: SandboxBootGeneration::new(1),
    }
}

/// A registry with one fake credential planted in `sandbox`, and its value.
fn planted(sandbox: &str) -> (CanaryRegistry, String) {
    let mut registry = CanaryRegistry::new(&CanarySeed::from_bytes([7; 32]), HoneyportPool::none());
    let plan = registry
        .plan(PlantingRequest {
            binding: binding(sandbox),
            origin: PlantOrigin::FreshBoot,
            placements: vec![PlacementRequest {
                kind: CanaryKind::FakeCredential,
                location: PlacementLocation::home(".config/legacy-deploy/token").unwrap(),
            }],
        })
        .unwrap();
    let value = plan.instructions()[0]
        .value()
        .expose_for_planting()
        .to_owned();
    (registry, value)
}

#[test]
fn the_file_adapter_files_a_foreign_scope_grant_as_a_file_root_escape() {
    let now = clock();
    assert_eq!(FILE_VIOLATION_KIND, ViolationKind::FileRootEscape);
    let outcome = file_refusal_signal(
        &ServiceRefusal::Grant {
            refusal: GrantRefusal::WrongScope,
        },
        &file_context("exe-b", &now),
    );
    assert_eq!(outcome.cause(), Some(&FileViolation::ForeignScope));
    let draft = outcome.into_draft().unwrap();
    assert_eq!(
        draft.class,
        SignalClass::Violation {
            kind: ViolationKind::FileRootEscape
        }
    );
    // Only the supervisor can see it: the same draft under any other observer is refused.
    signal(draft.clone());
    for observer in [
        HostObserver::Broker,
        HostObserver::Perimeter,
        HostObserver::HypervisorCounters,
        HostObserver::Executor,
    ] {
        let mut relabelled = draft.clone();
        relabelled.source = SignalSource::HostObserved { observer };
        assert!(MonitoringSignal::new(relabelled).is_err(), "{observer:?}");
    }
    // The guest that presented the grant stops; a sandbox holding the grant loses it.
    let shared = grant("files-workspace");
    let assessment = assess(&[signal(draft)], &now);
    let mut responder = responder_with(
        &now,
        &[
            ("exe-b", SandboxClass::Task, &[]),
            ("exe-a", SandboxClass::Task, &[shared]),
        ],
    );
    let record = responded(responder.respond_to(&assessment).unwrap());
    let observed = record.observed().unwrap();
    assert_eq!(observed.actions, violation_actions(true));
    assert_eq!(observed.class_response, Some(ViolationAction::Stop));
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::FileRootEscape,
            observer: HostObserver::Supervisor,
            meaning: None
        }
    );
    assert_eq!(
        record.targets[1].role,
        TargetRole::SharesViolatedGrant { grant: shared }
    );
}

#[test]
fn the_broker_adapter_files_a_release_overrun_as_a_budget_overrun_naming_no_grant() {
    let now = clock();
    assert_eq!(
        BrokerViolation::ReleaseOverrun.kind(),
        ViolationKind::BudgetOverrun
    );
    assert_eq!(
        BrokerViolation::ReleaseOverrun.observer(),
        HostObserver::Broker
    );
    let outcome = destination_refusal_signal(&overrun(), &broker_context("exe-a", &now));
    assert_eq!(outcome.cause(), Some(&BrokerViolation::ReleaseOverrun));
    let draft = outcome.into_draft().unwrap();
    assert_eq!(
        draft.class,
        SignalClass::Violation {
            kind: ViolationKind::BudgetOverrun
        }
    );
    assert_eq!(draft.violated_grant, None);
    // The overrunning guest stops; another sandbox on the same route is not touched.
    let assessment = assess(&[signal(draft)], &now);
    let mut responder = responder_with(
        &now,
        &[
            ("exe-a", SandboxClass::Service, &[]),
            ("exe-b", SandboxClass::Task, &[]),
        ],
    );
    let record = responded(responder.respond_to(&assessment).unwrap());
    assert_eq!(record.targets.len(), 1);
    let observed = record.observed().unwrap();
    assert_eq!(observed.actions, violation_actions(true));
    assert_eq!(observed.class_response, Some(ViolationAction::LockDown));
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::BudgetOverrun,
            observer: HostObserver::Broker,
            meaning: None
        }
    );
    assert!(responder.applied(&execution("exe-b")).unwrap().is_empty());
}

#[test]
fn a_canary_credential_refused_at_an_executor_is_an_executor_observed_use_naming_its_grant() {
    let now = clock();
    let (registry, value) = planted("exe-a");
    let refusal = registry
        .refuse_credential_use(format!("Authorization: Bearer {value}").as_bytes())
        .unwrap_err();
    let presented_on = grant("operation-deploy");
    let outcome = canary_credential_signal(
        &refusal,
        CredentialCheckpoint::Executor,
        &observed("exe-a", &now),
        Some(presented_on),
    )
    .unwrap();
    assert_eq!(
        outcome.cause(),
        Some(&CanaryViolation::CredentialPresented {
            checkpoint: CredentialCheckpoint::Executor
        })
    );
    let draft = outcome.into_draft().unwrap();
    assert_eq!(
        draft.source,
        SignalSource::HostObserved {
            observer: HostObserver::Executor
        }
    );
    assert_eq!(draft.violated_grant, Some(presented_on));
    let assessment = assess(&[signal(draft.clone())], &now);
    let mut responder = responder_with(
        &now,
        &[
            ("exe-a", SandboxClass::Task, &[presented_on]),
            ("exe-b", SandboxClass::Task, &[presented_on]),
        ],
    );
    let record = responded(responder.respond_to(&assessment).unwrap());
    // A signal, not proof: isolate and revoke, never stop.
    assert_eq!(record.decision.actions, violation_actions(false));
    assert_eq!(record.decision.class_response, None);
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::CanaryUse,
            observer: HostObserver::Executor,
            meaning: Some(HitMeaning::SignalNotProof)
        }
    );
    assert_eq!(
        record.targets[1].actions,
        BTreeSet::from([ResponseAction::NotifyUser, ResponseAction::RevokeGrant])
    );

    // The same canary at the vault and at an executor is one incident, not a conflict.
    let vault = canary_credential_signal(
        &refusal,
        CredentialCheckpoint::Vault,
        &observed("exe-a", &now),
        Some(presented_on),
    )
    .unwrap()
    .into_draft()
    .unwrap();
    assert_eq!(vault.subject, draft.subject);
    let both = assess(&[signal(vault), signal(draft)], &now);
    assert!(both.freshness().is_fresh());
    assert_eq!(both.violated_grant(), Some(presented_on));
}
