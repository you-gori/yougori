//! Tests for bounded responses (VM-W43 "known violations trigger bounded responses"): one
//! response per incident, the escalation ladder, the per-sandbox repeat bound, the
//! user-only notification bound, reach through the violated grant only, and no widening of
//! authority. Everything runs on fakes.

use std::collections::BTreeSet;

use super::fakes::*;
use super::tests::assert_no_score;
use super::*;
use crate::foundation::events::AuditFailurePolicy;
use crate::foundation::ids::{Clock, ManualClock, OperationId};
use crate::sandbox_contract::files::{SandboxClass, ViolationAction};

fn responder(now: &ManualClock) -> Responder<&ManualClock> {
    let mut responder = Responder::new(now, policies(), bounds());
    responder
        .register_sandbox(execution("exe-a"), SandboxClass::Task, BTreeSet::new())
        .unwrap();
    responder
}

/// A guest report about a distinct subject: a new incident that only informs.
fn guest_incident(name: &str, now: &ManualClock) -> SignalAssessment {
    let mut signal = draft(
        "exe-a",
        violation(ViolationKind::PerimeterRule),
        SignalSource::GuestReported,
        Reading::ViolationObserved,
        now.now(),
    );
    signal.subject = subject(name);
    match assess_violation(
        &[MonitoringSignal::new(signal).unwrap()],
        &uncertain(),
        now,
        host_session(),
    )
    .unwrap()
    {
        Assessment::Signal(signal) => signal,
        other => panic!("{other:?}"),
    }
}

/// A stale host observation of `kind`: an uncertain result.
fn stale_host(kind: ViolationKind, now: &ManualClock) -> SignalAssessment {
    let stale = host_violation("exe-a", kind, at(now.now().as_nanos() / 1_000_000_000 - 31));
    match assess_violation(&[stale], &uncertain(), now, host_session()).unwrap() {
        Assessment::Signal(signal) => signal,
        other => panic!("{other:?}"),
    }
}

#[test]
fn one_response_per_incident() {
    let now = clock();
    let mut responder = responder(&now);
    let signal = fresh_host_assessment("exe-a", ViolationKind::CredentialReplay, &now);
    let first = responded(responder.respond_to(&signal).unwrap());
    assert_eq!(first.escalated_from, None);
    for _ in 0..10 {
        now.advance(SECOND);
        let again = fresh_host_assessment("exe-a", ViolationKind::CredentialReplay, &now);
        assert_eq!(
            responder.respond_to(&again).unwrap(),
            ResponseOutcome::Deduplicated {
                incident: first.incident,
                last_decision: first.id
            }
        );
    }
    assert_eq!(responder.totals().responded, 1);
    assert_eq!(responder.totals().deduplicated, 10);
    assert_eq!(
        responder.respond(&Assessment::NoViolationObserved).unwrap(),
        ResponseOutcome::NoViolationObserved
    );
}

#[test]
fn an_incident_only_climbs_the_ladder_once_per_rung() {
    let now = clock();
    let mut responder = responder(&now);
    let kind = ViolationKind::CapabilityReplay;
    let uncertain = responded(responder.respond_to(&stale_host(kind, &now)).unwrap());
    assert_eq!(uncertain.decision.rung, EscalationRung::DenyNewHighImpact);
    let fresh = responded(
        responder
            .respond_to(&fresh_host_assessment("exe-a", kind, &now))
            .unwrap(),
    );
    assert_eq!(fresh.incident, uncertain.incident);
    assert_eq!(
        fresh.escalated_from,
        Some(EscalationRung::DenyNewHighImpact)
    );
    assert_eq!(fresh.decision.rung, EscalationRung::Stop);
    assert_eq!(
        fresh.observed().unwrap().new_actions,
        [
            ResponseAction::Isolate,
            ResponseAction::Revoke,
            ResponseAction::Stop
        ]
        .into()
    );
    // Lower or equal evidence afterwards adds nothing.
    assert!(matches!(
        responder.respond_to(&stale_host(kind, &now)).unwrap(),
        ResponseOutcome::Deduplicated { .. }
    ));
    assert_eq!(responder.totals().escalations, 1);
    assert_eq!(
        responder.rung(&execution("exe-a")),
        Some(EscalationRung::Stop)
    );
    // However the signals interleave, an incident gets at most one response per rung.
    let now = clock();
    let mut responder = Responder::new(&now, policies(), bounds());
    responder
        .register_sandbox(execution("exe-a"), SandboxClass::Service, BTreeSet::new())
        .unwrap();
    let mut responses = 0;
    for step in 0..60 {
        now.advance(SECOND);
        let signal = match step % 3 {
            0 => stale_host(ViolationKind::PerimeterRule, &now),
            1 => fresh_host_assessment("exe-a", ViolationKind::PerimeterRule, &now),
            _ => guest_incident(ViolationKind::PerimeterRule.label(), &now),
        };
        if matches!(
            responder.respond_to(&signal).unwrap(),
            ResponseOutcome::Responded(_)
        ) {
            responses += 1;
        }
    }
    assert!(responses <= ESCALATION_LADDER.len(), "{responses}");
}

#[test]
fn repeats_are_rate_bounded_counted_and_folded_into_the_next_notification() {
    let now = clock();
    let mut responder = responder(&now);
    for name in ["s1", "s2"] {
        responded(responder.respond_to(&guest_incident(name, &now)).unwrap());
    }
    for (count, name) in ["s3", "s4", "s5"].iter().enumerate() {
        match responder.respond_to(&guest_incident(name, &now)).unwrap() {
            ResponseOutcome::RateBounded {
                retry_after,
                held_back,
                ..
            } => {
                assert_eq!(retry_after, MINUTE);
                assert_eq!(held_back, count as u64 + 1);
            }
            other => panic!("{other:?}"),
        }
    }
    assert_eq!(responder.totals().rate_bounded, 3);
    now.advance(MINUTE);
    let record = responded(responder.respond_to(&guest_incident("s6", &now)).unwrap());
    assert_eq!(
        record.observed().unwrap().notification,
        Some(NotificationOutcome::Sent {
            recipient: NotifyRecipient::User,
            folded_held_back: 3
        }),
        "the held-back responses are summarized, never silent"
    );
}

#[test]
fn a_restrictive_response_is_never_held_back() {
    let now = clock();
    let mut responder = responder(&now);
    for name in ["s1", "s2", "s3"] {
        let _ = responder.respond_to(&guest_incident(name, &now)).unwrap();
    }
    assert_eq!(responder.totals().rate_bounded, 1);
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::LaunchArtifactIntegrity,
                &now,
            ))
            .unwrap(),
    );
    assert!(record
        .observed()
        .unwrap()
        .new_actions
        .contains(&ResponseAction::Stop));
}

#[test]
fn notifications_go_to_the_user_only_within_their_bound() {
    let now = clock();
    let mut responder = responder(&now);
    let signals = [
        guest_incident("g", &now),
        stale_host(ViolationKind::PolicyEpochMismatch, &now),
        fresh_host_assessment("exe-a", ViolationKind::CanaryUse, &now),
        fresh_host_assessment("exe-a", ViolationKind::CredentialReplay, &now),
    ];
    let mut outcomes = Vec::new();
    for signal in &signals {
        let record = responded(responder.respond_to(signal).unwrap());
        outcomes.push(record.observed().unwrap().notification.unwrap());
        let json = serde_json::to_value(&record).unwrap();
        assert_no_score(&json);
        if let Some(recipient) = json["targets"][0]["notification"].get("recipient") {
            assert_eq!(recipient, &serde_json::json!("user"));
        }
    }
    for outcome in &outcomes[..3] {
        assert_eq!(
            *outcome,
            NotificationOutcome::Sent {
                recipient: NotifyRecipient::User,
                folded_held_back: 0
            }
        );
    }
    assert_eq!(
        outcomes[3],
        NotificationOutcome::HeldBack {
            retry_after: MINUTE,
            held_back: 1
        }
    );
    assert_eq!(responder.totals().notifications_sent, 3);
    assert_eq!(responder.totals().notifications_held_back, 1);
}

#[test]
fn a_response_reaches_another_sandbox_only_through_the_violated_grant() {
    let now = clock();
    let mut responder = Responder::new(&now, policies(), bounds());
    let shared = grant("deploy-credential");
    responder
        .register_sandbox(
            execution("exe-a"),
            SandboxClass::Task,
            BTreeSet::from([shared]),
        )
        .unwrap();
    responder
        .register_sandbox(
            execution("exe-b"),
            SandboxClass::Service,
            BTreeSet::from([shared]),
        )
        .unwrap();
    responder
        .register_sandbox(
            execution("exe-c"),
            SandboxClass::Task,
            BTreeSet::from([grant("other")]),
        )
        .unwrap();
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment_with_grant(
                "exe-a",
                ViolationKind::CredentialReplay,
                shared,
                &now,
            ))
            .unwrap(),
    );
    assert_eq!(record.targets.len(), 2);
    let observed = &record.targets[0];
    assert_eq!(observed.role, TargetRole::Observed);
    assert_eq!(observed.class_response, Some(ViolationAction::Stop));
    let sharing = &record.targets[1];
    assert_eq!(sharing.sandbox, execution("exe-b"));
    assert_eq!(
        sharing.role,
        TargetRole::SharesViolatedGrant { grant: shared }
    );
    assert_eq!(
        sharing.actions,
        [ResponseAction::NotifyUser, ResponseAction::RevokeGrant].into(),
        "the sharing sandbox loses the shared grant only: never its epoch, never isolated or stopped"
    );
    assert_eq!(sharing.new_actions, sharing.actions);
    assert_eq!(sharing.class_response, None);
    assert!(sharing.preserves.contains(&Preserved::VmState));
    assert_eq!(
        responder.rung(&execution("exe-b")),
        Some(EscalationRung::RevokeGrant)
    );
    assert!(record
        .observed()
        .unwrap()
        .actions
        .contains(&ResponseAction::Revoke));
    assert_eq!(
        responder.applied(&execution("exe-c")),
        Some(&BTreeSet::new())
    );

    // Without a named grant, or without a revocation, nothing reaches another sandbox.
    let now = clock();
    let mut responder = Responder::new(&now, policies(), bounds());
    for name in ["exe-a", "exe-b"] {
        responder
            .register_sandbox(
                execution(name),
                SandboxClass::Task,
                BTreeSet::from([shared]),
            )
            .unwrap();
    }
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::CredentialReplay,
                &now,
            ))
            .unwrap(),
    );
    assert_eq!(record.targets.len(), 1);
    let mut stale = draft(
        "exe-a",
        violation(ViolationKind::PerimeterRule),
        host(HostObserver::Perimeter),
        Reading::ViolationObserved,
        at(START_SECONDS - 31),
    );
    stale.violated_grant = Some(shared);
    let stale = match assess_violation(
        &[MonitoringSignal::new(stale).unwrap()],
        &uncertain(),
        &now,
        host_session(),
    )
    .unwrap()
    {
        Assessment::Signal(signal) => signal,
        other => panic!("{other:?}"),
    };
    let record = responded(responder.respond_to(&stale).unwrap());
    assert_eq!(
        record.targets.len(),
        1,
        "an uncertain result revokes nothing"
    );
    assert_eq!(
        responder.applied(&execution("exe-b")),
        Some(&BTreeSet::new())
    );
}

#[test]
fn applied_actions_only_grow_and_releasing_isolation_restores_no_authority() {
    let now = clock();
    let mut responder = responder(&now);
    assert_eq!(
        responder.release_isolation(&execution("exe-a")),
        Err(ResponderRefusal::NotIsolated {
            sandbox: execution("exe-a")
        })
    );
    assert_eq!(
        responder.release_isolation(&execution("exe-z")),
        Err(ResponderRefusal::UnknownSandbox {
            sandbox: execution("exe-z")
        })
    );
    let mut previous = BTreeSet::new();
    for kind in [
        ViolationKind::CanaryUse,
        ViolationKind::PerimeterRule,
        ViolationKind::AuthorizationEpochMismatch,
    ] {
        responder
            .respond_to(&fresh_host_assessment("exe-a", kind, &now))
            .unwrap();
        let applied = responder.applied(&execution("exe-a")).unwrap().clone();
        assert!(previous.is_subset(&applied));
        previous = applied;
    }
    let release = responder.release_isolation(&execution("exe-a")).unwrap();
    assert!(!release.still_applied.contains(&ResponseAction::Isolate));
    assert!(release.still_applied.contains(&ResponseAction::Revoke));
    assert!(release.still_applied.contains(&ResponseAction::Stop));
    // The same incidents never re-isolate; a new incident may.
    assert!(matches!(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::CanaryUse,
                &now
            ))
            .unwrap(),
        ResponseOutcome::Deduplicated { .. }
    ));
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::CapabilityReplay,
                &now,
            ))
            .unwrap(),
    );
    assert_eq!(
        record.observed().unwrap().new_actions,
        [ResponseAction::Isolate].into()
    );
}

#[test]
fn registration_is_checked_and_bounded() {
    let now = clock();
    let mut responder = Responder::new(
        &now,
        policies(),
        ResponseBounds::new(limit(2, MINUTE), 8, 1).unwrap(),
    );
    responder
        .register_sandbox(execution("exe-a"), SandboxClass::Task, BTreeSet::new())
        .unwrap();
    assert_eq!(
        responder.register_sandbox(execution("exe-a"), SandboxClass::Task, BTreeSet::new()),
        Err(ResponderRefusal::AlreadyRegistered {
            sandbox: execution("exe-a")
        })
    );
    assert_eq!(
        responder.register_sandbox(execution("exe-b"), SandboxClass::Task, BTreeSet::new()),
        Err(ResponderRefusal::TooManySandboxes { max_sandboxes: 1 })
    );
    assert_eq!(
        responder.respond_to(&fresh_host_assessment(
            "exe-b",
            ViolationKind::CanaryUse,
            &now
        )),
        Err(ResponderRefusal::UnknownSandbox {
            sandbox: execution("exe-b")
        })
    );
    responder
        .respond_to(&fresh_host_assessment(
            "exe-a",
            ViolationKind::CanaryUse,
            &now,
        ))
        .unwrap();
    assert!(responder.forget_sandbox(&execution("exe-a")));
    assert_eq!(responder.open_incidents(), 0);
    assert_eq!(
        ResponseBounds::new(limit(1, MINUTE), 0, 1),
        Err(BoundsProblem::ZeroIncidents)
    );
    assert_eq!(
        ResponseBounds::new(limit(1, MINUTE), 1, 0),
        Err(BoundsProblem::ZeroSandboxes)
    );
}

#[test]
fn incidents_past_the_bound_share_an_overflow_incident() {
    let now = clock();
    let mut responder = Responder::new(
        &now,
        policies(),
        ResponseBounds::new(limit(10, MINUTE), 2, 4).unwrap(),
    );
    responder
        .register_sandbox(execution("exe-a"), SandboxClass::Service, BTreeSet::new())
        .unwrap();
    let first = responded(responder.respond_to(&guest_incident("s1", &now)).unwrap());
    let second = responded(responder.respond_to(&guest_incident("s2", &now)).unwrap());
    assert_ne!(first.incident, second.incident);
    let third = responded(responder.respond_to(&guest_incident("s3", &now)).unwrap());
    assert_ne!(
        third.key.subject,
        subject("s3"),
        "filed under the overflow incident"
    );
    assert!(matches!(
        responder.respond_to(&guest_incident("s4", &now)).unwrap(),
        ResponseOutcome::Deduplicated { incident, .. } if incident == third.incident
    ));
    assert_eq!(responder.totals().overflowed, 2);
    assert_eq!(responder.open_incidents(), 3);
}

#[test]
fn a_closed_incident_can_respond_again() {
    let now = clock();
    let mut responder = responder(&now);
    let signal = guest_incident("s1", &now);
    let first = responded(responder.respond_to(&signal).unwrap());
    assert!(responder.close_incident(&first.key));
    assert!(!responder.close_incident(&first.key));
    let again = responded(responder.respond_to(&signal).unwrap());
    assert_eq!(again.incident, first.incident);
    assert_ne!(again.id, first.id);
    assert_eq!(again.escalated_from, None);
}

#[test]
fn a_response_record_is_a_bounded_metadata_audit_record() {
    let now = std::sync::Arc::new(clock());
    let mut responder = Responder::new(std::sync::Arc::clone(&now), policies(), bounds());
    responder
        .register_sandbox(execution("exe-a"), SandboxClass::Service, BTreeSet::new())
        .unwrap();
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment(
                "exe-a",
                ViolationKind::CredentialReplay,
                &now,
            ))
            .unwrap(),
    );
    let fields = record.audit_fields();
    assert!(fields.len() <= crate::foundation::events::RedactionPolicy::DEFAULT_MAX_FIELDS);
    let (mut journal, mut authority, store, _) =
        journal(&now, 4, AuditFailurePolicy::DenyHighImpact);
    let receipt = journal
        .append(
            &mut authority,
            crate::foundation::events::EventContext::new(
                OperationId::new("op-response").unwrap(),
                crate::foundation::events::Phase::Running,
            ),
            record.audit_draft(),
        )
        .unwrap();
    assert_eq!(
        receipt.durability,
        crate::foundation::events::Durability::Durable
    );
    let stored = store.records.borrow();
    match stored[0].event().payload() {
        crate::foundation::events::AuditEntry::HostFact { fact, fields } => {
            assert_eq!(
                *fact,
                crate::foundation::events::HostFact::AuthorizationDecision
            );
            assert_eq!(fields.omitted_fields(), 0);
            assert!(fields.get("action_stop").is_some());
            assert!(fields.get("class_response").is_some());
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_bystander_loses_each_shared_grant_once_and_keeps_the_rest() {
    let now = clock();
    let mut responder = Responder::new(&now, policies(), bounds());
    let first = grant("deploy-credential");
    let second = grant("registry-route");
    for name in ["exe-a", "exe-c"] {
        responder
            .register_sandbox(
                execution(name),
                SandboxClass::Task,
                BTreeSet::from([first, second]),
            )
            .unwrap();
    }
    responder
        .register_sandbox(
            execution("exe-b"),
            SandboxClass::Service,
            BTreeSet::from([first, second]),
        )
        .unwrap();
    let bystander = |record: &ResponseRecord, name: &str| {
        record
            .targets
            .iter()
            .find(|target| target.sandbox == execution(name))
            .cloned()
    };

    // A violation against the first grant: exe-b loses it.
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment_with_grant(
                "exe-a",
                ViolationKind::CredentialReplay,
                first,
                &now,
            ))
            .unwrap(),
    );
    let lost = bystander(&record, "exe-b").unwrap();
    assert_eq!(lost.role, TargetRole::SharesViolatedGrant { grant: first });
    assert!(lost.new_actions.contains(&ResponseAction::RevokeGrant));

    // Another sandbox violating the same grant does not take it from exe-b again.
    let record = responded(
        responder
            .respond_to(&fresh_host_assessment_with_grant(
                "exe-c",
                ViolationKind::CredentialReplay,
                first,
                &now,
            ))
            .unwrap(),
    );
    assert_eq!(bystander(&record, "exe-b"), None);

    // A violation against the second grant is a new grant revocation for exe-b, although
    // it already has a grant revocation applied.
    let mut responder_two = Responder::new(&now, policies(), bounds());
    for (name, class) in [
        ("exe-a", SandboxClass::Task),
        ("exe-b", SandboxClass::Service),
    ] {
        responder_two
            .register_sandbox(execution(name), class, BTreeSet::from([first, second]))
            .unwrap();
    }
    responded(
        responder_two
            .respond_to(&fresh_host_assessment_with_grant(
                "exe-a",
                ViolationKind::CredentialReplay,
                first,
                &now,
            ))
            .unwrap(),
    );
    // exe-a is already revoked; a fresh violator holds the second grant.
    responder_two
        .register_sandbox(
            execution("exe-d"),
            SandboxClass::Task,
            BTreeSet::from([second]),
        )
        .unwrap();
    let later =
        fresh_host_assessment_with_grant("exe-d", ViolationKind::PerimeterRule, second, &now);
    let record = responded(responder_two.respond_to(&later).unwrap());
    let lost = bystander(&record, "exe-b").unwrap();
    assert_eq!(lost.role, TargetRole::SharesViolatedGrant { grant: second });
    assert_eq!(
        lost.new_actions,
        BTreeSet::from([ResponseAction::RevokeGrant]),
        "the second grant is new; the notification is not"
    );
    assert!(!responder_two
        .applied(&execution("exe-b"))
        .unwrap()
        .contains(&ResponseAction::Revoke));
}
