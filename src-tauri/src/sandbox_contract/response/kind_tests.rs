//! Tests for the two violation kinds M17B adds, a file-root escape and a budget overrun,
//! and for the executor as an observer of canary use (VM part §8.2, §5.1, §2.5, §4.5;
//! VM-W43). Everything runs on fakes.

use std::collections::BTreeSet;

use super::fakes::*;
use super::*;
use crate::foundation::evidence::Staleness;
use crate::foundation::ids::Clock;
use crate::sandbox_contract::canaries::HitMeaning;
use crate::sandbox_contract::files::{SandboxClass, ViolationAction};

const NEW_KINDS: [ViolationKind; 2] = [ViolationKind::FileRootEscape, ViolationKind::BudgetOverrun];

/// Whether V14 accepts a host observation of `kind` by `observer`.
fn accepts(kind: ViolationKind, observer: HostObserver) -> Result<(), SignalRefusal> {
    MonitoringSignal::new(draft(
        "exe-a",
        violation(kind),
        host(observer),
        Reading::ViolationObserved,
        at(START_SECONDS),
    ))
    .map(|_| ())
}

/// The observers V14 accepts for `kind`, checked one by one against every observer.
fn accepted_observers(kind: ViolationKind) -> BTreeSet<HostObserver> {
    HostObserver::ALL
        .into_iter()
        .filter(|&observer| match accepts(kind, observer) {
            Ok(()) => true,
            Err(refusal) => {
                assert_eq!(
                    refusal,
                    SignalRefusal::MislabelledSource {
                        class: violation(kind),
                        observer
                    }
                );
                false
            }
        })
        .collect()
}

fn input(kind: ViolationKind, source: SignalSource, freshness: Freshness) -> DecisionInput {
    DecisionInput {
        class: violation(kind),
        source,
        freshness,
        sandbox_class: SandboxClass::Task,
    }
}

#[test]
fn the_new_kinds_are_known_violations_with_labels_and_strict_wire_names() {
    for kind in NEW_KINDS {
        assert!(ViolationKind::ALL.contains(&kind));
        assert!(SignalClass::all().contains(&violation(kind)));
        assert!(violation(kind).is_violation());
    }
    assert_eq!(ViolationKind::FileRootEscape.label(), "file_root_escape");
    assert_eq!(ViolationKind::BudgetOverrun.label(), "budget_overrun");
    // Every label names one kind.
    let labels: BTreeSet<&str> = ViolationKind::ALL.iter().map(|kind| kind.label()).collect();
    assert_eq!(labels.len(), ViolationKind::ALL.len());
    for kind in NEW_KINDS {
        let wire = serde_json::to_value(kind).unwrap();
        assert_eq!(wire, serde_json::json!(kind.label()));
        assert_eq!(serde_json::from_value::<ViolationKind>(wire).unwrap(), kind);
        // A signal of the kind reads back as written, its source checked again.
        let signal = host_violation("exe-a", kind, at(START_SECONDS));
        let text = serde_json::to_string(&signal).unwrap();
        assert_eq!(
            serde_json::from_str::<MonitoringSignal>(&text).unwrap(),
            signal
        );
    }
    // A file-root escape read back under the broker is refused, not relabelled.
    let mut wire = serde_json::to_value(host_violation(
        "exe-a",
        ViolationKind::FileRootEscape,
        at(1),
    ))
    .unwrap();
    wire["source"]["observer"] = serde_json::json!("broker");
    assert!(serde_json::from_value::<MonitoringSignal>(wire).is_err());
}

#[test]
fn only_the_supervisor_observes_a_file_root_escape() {
    assert_eq!(
        accepted_observers(ViolationKind::FileRootEscape),
        BTreeSet::from([HostObserver::Supervisor])
    );
    assert_eq!(
        ViolationKind::FileRootEscape.host_observers(),
        &[HostObserver::Supervisor]
    );
    // A guest may report one; it stays a guest report.
    let guest = guest_violation("exe-a", ViolationKind::FileRootEscape, at(START_SECONDS));
    assert_eq!(guest.source(), SignalSource::GuestReported);
}

#[test]
fn the_broker_and_the_executor_observe_a_budget_overrun() {
    assert_eq!(
        accepted_observers(ViolationKind::BudgetOverrun),
        BTreeSet::from([HostObserver::Broker, HostObserver::Executor])
    );
    // The same observers that measure the release budget it overruns.
    assert_eq!(
        ViolationKind::BudgetOverrun.host_observers(),
        MonitoredResource::ReleaseBudgetSpentBytes.host_observers()
    );
}

#[test]
fn the_executor_observes_a_canary_use_and_the_hypervisor_counters_still_do_not() {
    assert_eq!(
        accepted_observers(ViolationKind::CanaryUse),
        BTreeSet::from([
            HostObserver::Perimeter,
            HostObserver::Broker,
            HostObserver::Executor
        ])
    );
    // The relay stays the first observer, the one V09 hits map onto.
    assert_eq!(
        ViolationKind::CanaryUse.host_observers()[0],
        HostObserver::Perimeter
    );
    // An executor-observed canary use is a signal, not proof: it isolates and revokes and
    // never stops, whatever the sandbox class.
    let policies = policies();
    for sandbox_class in [SandboxClass::Task, SandboxClass::Service] {
        let decision = decide(
            &policies,
            &DecisionInput {
                sandbox_class,
                ..input(
                    ViolationKind::CanaryUse,
                    host(HostObserver::Executor),
                    Freshness::Fresh,
                )
            },
        );
        assert_eq!(
            decision.actions,
            BTreeSet::from([
                ResponseAction::NotifyUser,
                ResponseAction::DenyNewHighImpact,
                ResponseAction::Isolate,
                ResponseAction::Revoke,
            ])
        );
        assert_eq!(decision.class_response, None);
        assert_eq!(
            decision.reason,
            DecisionReason::KnownViolation {
                kind: ViolationKind::CanaryUse,
                observer: HostObserver::Executor,
                meaning: Some(HitMeaning::SignalNotProof),
            }
        );
    }
}

#[test]
fn a_fresh_host_observation_of_a_new_kind_isolates_revokes_and_takes_the_class_response() {
    let policies = policies();
    for kind in NEW_KINDS {
        assert!(policies.isolate().triggers().contains(&violation(kind)));
        assert!(policies.revoke().triggers().contains(&kind));
        assert!(policies.stop().triggers().contains(&kind));
        for &observer in kind.host_observers() {
            for sandbox_class in [SandboxClass::Task, SandboxClass::Service] {
                let decision = decide(
                    &policies,
                    &DecisionInput {
                        sandbox_class,
                        ..input(kind, host(observer), Freshness::Fresh)
                    },
                );
                assert_eq!(
                    decision.actions,
                    BTreeSet::from([
                        ResponseAction::NotifyUser,
                        ResponseAction::DenyNewHighImpact,
                        ResponseAction::Isolate,
                        ResponseAction::Revoke,
                        ResponseAction::Stop,
                    ])
                );
                assert_eq!(decision.rung, EscalationRung::Stop);
                assert_eq!(
                    decision.class_response,
                    Some(ViolationAction::for_class(sandbox_class))
                );
                assert_eq!(
                    decision.reason,
                    DecisionReason::KnownViolation {
                        kind,
                        observer,
                        meaning: None
                    }
                );
                assert_eq!(
                    decision.preserves.contains(&Preserved::VmState),
                    sandbox_class == SandboxClass::Service
                );
                assert!(decision.preserves.contains(&Preserved::HostWorkspaces));
            }
        }
    }
}

#[test]
fn a_stale_or_guest_reported_new_kind_never_stops() {
    let policies = policies();
    for kind in NEW_KINDS {
        let observer = kind.host_observers()[0];
        let stale = decide(
            &policies,
            &input(
                kind,
                host(observer),
                Freshness::Stale {
                    staleness: Staleness::OtherClock,
                },
            ),
        );
        assert_eq!(
            stale.actions,
            UncertainPolicy::ACTIONS
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        let guest = decide(
            &policies,
            &input(kind, SignalSource::GuestReported, Freshness::Fresh),
        );
        assert_eq!(
            guest.actions,
            BTreeSet::from([
                ResponseAction::NotifyUser,
                ResponseAction::RequestHostCorroboration
            ])
        );
        assert_eq!(guest.class_response, None);
    }
}

#[test]
fn policy_records_must_isolate_the_new_kinds_and_revoke_before_they_stop() {
    for kind in NEW_KINDS {
        let mut isolate = IsolatePolicy::default_triggers();
        isolate.remove(&violation(kind));
        assert_eq!(
            ResponsePolicies::new(
                IsolatePolicy::new(isolate),
                RevokePolicy::new(RevokePolicy::default_triggers()),
                StopPolicy::new(StopPolicy::default_triggers()),
                NotifyPolicy::new(limit(3, MINUTE)),
                uncertain(),
            ),
            Err(PolicyProblem::ViolationWithoutIsolation { kind })
        );
        let mut revoke = RevokePolicy::default_triggers();
        revoke.remove(&kind);
        assert_eq!(
            ResponsePolicies::new(
                IsolatePolicy::new(IsolatePolicy::default_triggers()),
                RevokePolicy::new(revoke),
                StopPolicy::new(StopPolicy::default_triggers()),
                NotifyPolicy::new(limit(3, MINUTE)),
                uncertain(),
            ),
            Err(PolicyProblem::StopWithoutRevoke { kind })
        );
    }
}

#[test]
fn a_new_kind_is_assessed_like_any_violation_and_a_check_by_another_observer_contradicts_it() {
    let now = clock();
    let observed = host_violation("exe-a", ViolationKind::BudgetOverrun, now.now());
    let checked = MonitoringSignal::new(draft(
        "exe-a",
        violation(ViolationKind::BudgetOverrun),
        host(HostObserver::Executor),
        Reading::CheckPassed,
        now.now(),
    ))
    .unwrap();
    let assessment =
        match assess_violation(&[observed.clone()], &uncertain(), &now, host_session()).unwrap() {
            Assessment::Signal(assessment) => assessment,
            other => panic!("{other:?}"),
        };
    assert!(assessment.freshness().is_fresh());
    assert_eq!(assessment.class(), violation(ViolationKind::BudgetOverrun));
    match assess_violation(&[observed, checked], &uncertain(), &now, host_session()).unwrap() {
        Assessment::Signal(assessment) => assert_eq!(
            assessment.freshness(),
            Freshness::Conflicting {
                conflict: Conflict {
                    reported_by: HostObserver::Broker,
                    contradicted_by: HostObserver::Executor
                }
            }
        ),
        other => panic!("{other:?}"),
    }
}
