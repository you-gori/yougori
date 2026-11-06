//! The canary adapter: V09 hits through V14's mapping and canary credentials refused on
//! presentation, fed through V14's assessment and responder (VM part §4.5, §8.2; VM-W10;
//! VM-W43).

use std::collections::BTreeSet;

use super::fixtures::*;
use super::*;
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::{digest, Clock, ManualClock, SandboxBootGeneration};
use crate::sandbox_contract::canaries::{
    self, CanaryHit, CanaryKind, CanaryRegistry, CanarySeed, HitMeaning, HoneyportPool,
    ObservedContent, PlacementLocation, PlacementRequest, PlantOrigin, PlantingRequest,
    SandboxBinding,
};
use crate::sandbox_contract::effects::{IssuerId, SandboxRef};
use crate::sandbox_contract::files::SandboxClass;
use crate::sandbox_contract::response::{
    DecisionReason, HostObserver, MonitoringSignal, ResponseAction, SignalClass, SignalSource,
    TargetRole, ViolationKind,
};

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

fn outbound(value: &str) -> ObservedContent {
    ObservedContent::OutboundBytes(
        format!("POST /deploy\r\nAuthorization: Bearer {value}\r\n").into_bytes(),
    )
}

/// The relay's host-observed hit of the planted credential leaving `sandbox`.
fn host_hit(registry: &CanaryRegistry, value: &str, sandbox: &str, now: &ManualClock) -> CanaryHit {
    let observation =
        canaries::Observation::host_observed(binding(sandbox), now.now(), outbound(value)).unwrap();
    let report = registry.match_observation(&observation, now);
    assert_eq!(report.hits.len(), 1);
    report.hits[0].clone()
}

#[test]
fn a_host_observed_canary_hit_isolates_and_revokes_and_never_stops() {
    let now = clock();
    let (registry, value) = planted("exe-a");
    let hit = host_hit(&registry, &value, "exe-a", &now);
    let outcome = canary_hit_signal(&hit, host_session());
    assert_eq!(outcome.cause(), Some(&CanaryViolation::Hit));
    let draft = outcome.into_draft().unwrap();
    // Exactly V14's own mapping of the hit.
    assert_eq!(
        signal(draft.clone()),
        MonitoringSignal::from_canary_hit(&hit, host_session())
    );
    assert_eq!(draft.sandbox, execution("exe-a"));
    assert_eq!(
        draft.class,
        SignalClass::Violation {
            kind: ViolationKind::CanaryUse
        }
    );
    assert_eq!(
        draft.source,
        SignalSource::HostObserved {
            observer: HostObserver::Perimeter
        }
    );
    assert_eq!(draft.subject, *hit.canary().digest());
    assert_eq!(draft.observed_at, now.now());
    let record = respond_alone(draft, &now);
    assert_eq!(record.decision.actions, violation_actions(false));
    assert!(!record.decision.actions.contains(&ResponseAction::Stop));
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::CanaryUse,
            observer: HostObserver::Perimeter,
            meaning: Some(HitMeaning::SignalNotProof)
        }
    );
}

#[test]
fn a_guest_reported_canary_hit_only_notifies_and_asks_for_corroboration() {
    let now = clock();
    let (registry, value) = planted("exe-a");
    let reported =
        canaries::Observation::guest_reported(binding("exe-a"), outbound(&value)).unwrap();
    let report = registry.match_observation(&reported, &now);
    let outcome = canary_hit_signal(&report.hits[0], host_session());
    assert!(outcome.is_violation());
    let draft = outcome.into_draft().unwrap();
    assert_eq!(draft.source, SignalSource::GuestReported);
    // Dated when the host matched it, never by the guest.
    assert_eq!(draft.observed_at, now.now());
    let record = respond_alone(draft, &now);
    assert_eq!(
        record.decision.actions,
        BTreeSet::from([
            ResponseAction::NotifyUser,
            ResponseAction::RequestHostCorroboration
        ])
    );
    assert_eq!(
        record.decision.reason,
        DecisionReason::GuestReportNeedsCorroboration {
            class: SignalClass::Violation {
                kind: ViolationKind::CanaryUse
            }
        }
    );
}

#[test]
fn a_canary_credential_refused_at_the_vault_is_a_broker_observed_use_naming_its_grant() {
    let now = clock();
    let (registry, value) = planted("exe-a");
    let refusal = registry
        .refuse_credential_use(format!("token={value}").as_bytes())
        .unwrap_err();
    let presented_on = grant("operation-deploy");
    let outcome = canary_credential_signal(
        &refusal,
        CredentialCheckpoint::Vault,
        &observed("exe-a", &now),
        Some(presented_on),
    )
    .unwrap();
    assert_eq!(
        outcome.cause(),
        Some(&CanaryViolation::CredentialPresented {
            checkpoint: CredentialCheckpoint::Vault
        })
    );
    let draft = outcome.into_draft().unwrap();
    assert_eq!(
        draft.source,
        SignalSource::HostObserved {
            observer: HostObserver::Broker
        }
    );
    assert_eq!(draft.violated_grant, Some(presented_on));
    // The grant the canary was presented on is compromised: a sandbox holding it loses
    // it, and nothing else.
    let assessment = assess(&[signal(draft.clone())], &now);
    let mut responder = responder_with(
        &now,
        &[
            ("exe-a", SandboxClass::Task, &[presented_on]),
            ("exe-b", SandboxClass::Task, &[presented_on]),
        ],
    );
    let record = responded(responder.respond_to(&assessment).unwrap());
    assert_eq!(record.decision.actions, violation_actions(false));
    assert_eq!(
        record.decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::CanaryUse,
            observer: HostObserver::Broker,
            meaning: Some(HitMeaning::SignalNotProof)
        }
    );
    assert_eq!(
        record.targets[1].role,
        TargetRole::SharesViolatedGrant {
            grant: presented_on
        }
    );
    assert_eq!(
        record.targets[1].actions,
        BTreeSet::from([ResponseAction::NotifyUser, ResponseAction::RevokeGrant])
    );

    // The hit and the presentation of one canary are one incident.
    let hit = canary_hit_signal(&host_hit(&registry, &value, "exe-a", &now), host_session())
        .into_draft()
        .unwrap();
    assert_eq!(hit.subject, draft.subject);
    let assessment = assess(&[signal(hit), signal(draft)], &now);
    assert!(assessment.freshness().is_fresh());
    let mut responder = responder_with(&now, &[("exe-a", SandboxClass::Service, &[])]);
    let record = responded(responder.respond_to(&assessment).unwrap());
    assert_eq!(record.key, assessment.key().clone());
    assert_eq!(responder.open_incidents(), 1);
}

#[test]
fn the_checkpoint_names_the_observer_and_v14_accepts_each_for_a_canary_use() {
    let now = clock();
    let (registry, value) = planted("exe-a");
    let refusal = registry
        .refuse_credential_use(value.as_bytes())
        .unwrap_err();
    let imported = canary_credential_signal(
        &refusal,
        CredentialCheckpoint::Import,
        &observed("exe-a", &now),
        None,
    )
    .unwrap();
    let draft = imported.into_draft().unwrap();
    assert_eq!(
        draft.source,
        SignalSource::HostObserved {
            observer: HostObserver::Broker
        }
    );
    assert_eq!(draft.violated_grant, None);
    let executed = canary_credential_signal(
        &refusal,
        CredentialCheckpoint::Executor,
        &observed("exe-a", &now),
        None,
    )
    .unwrap();
    assert_eq!(
        executed.into_draft().unwrap().source,
        SignalSource::HostObserved {
            observer: HostObserver::Executor
        }
    );
}
