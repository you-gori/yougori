//! The bounded collector, and every adapter feeding it and then V14's assessment and
//! responder end to end (VM part §8.2; VM-W43).

use std::collections::BTreeSet;

use super::fixtures::*;
use super::*;
use crate::foundation::coordination::{PerimeterId, VmInstanceId};
use crate::foundation::ids::{digest, Clock, Digest, ManualClock, SandboxBootGeneration};
use crate::sandbox_contract::canaries::{
    self, CanaryKind, CanaryRegistry, CanarySeed, HoneyportPool, ObservedContent,
    PlacementLocation, PlacementRequest, PlantOrigin, PlantingRequest, SandboxBinding,
};
use crate::sandbox_contract::destinations::{DestinationRefusal, ReleaseError, RouteId};
use crate::sandbox_contract::effects::{IssuerId, SandboxRef};
use crate::sandbox_contract::files::{
    DisclosureAcknowledgment, GrantMode, GrantRefusal, GuestName, LinkKind, ResolveRefusal,
    RootHandle, SandboxClass, ServiceRefusal, ViolationAction,
};
use crate::sandbox_contract::perimeter_install::{AbortCause, InstallError, VerificationFailure};
use crate::sandbox_contract::response::{
    assess_violation, Assessment, HostObserver, MonitoredResource, Reading, ResponseAction,
    ResponseOutcome, SignalClass, SignalDraft, SignalRefusal, SignalSource, ViolationKind,
    MAX_OBSERVATIONS_PER_ASSESSMENT,
};

fn subject(name: &str) -> Digest {
    digest("yougori/test/subject/v1", &[name.as_bytes()])
}

/// A draft of `kind` about `sandbox` from `source`, stamped now.
fn draft(
    sandbox: &str,
    kind: ViolationKind,
    source: SignalSource,
    about: &str,
    now: &ManualClock,
) -> SignalDraft {
    SignalDraft {
        sandbox: execution(sandbox),
        class: SignalClass::Violation { kind },
        source,
        subject: subject(about),
        reading: Reading::ViolationObserved,
        observed_at: now.now(),
        session: host_session(),
        violated_grant: None,
    }
}

fn perimeter_saw() -> SignalSource {
    SignalSource::HostObserved {
        observer: HostObserver::Perimeter,
    }
}

fn guest_report(sandbox: &str, about: &str, now: &ManualClock) -> SignalDraft {
    draft(
        sandbox,
        ViolationKind::CanaryUse,
        SignalSource::GuestReported,
        about,
        now,
    )
}

fn collector(per_sandbox: usize, guest_reports: usize, sandboxes: usize) -> SignalCollector {
    SignalCollector::new(CollectorBounds::new(per_sandbox, guest_reports, sandboxes).unwrap())
}

fn file_context(
    sandbox: &str,
    mode: GrantMode,
    grant_name: &str,
    now: &ManualClock,
) -> FileServiceContext {
    FileServiceContext {
        observed: observed(sandbox, now),
        root: RootHandle::from_host(subject("workspace")),
        mode,
        grant: grant(grant_name),
    }
}

fn foreign_scope() -> ServiceRefusal {
    ServiceRefusal::Grant {
        refusal: GrantRefusal::WrongScope,
    }
}

fn link(at: &str) -> ServiceRefusal {
    ServiceRefusal::Resolve {
        refusal: ResolveRefusal::LinkRefused {
            at: GuestName::parse(at).unwrap(),
            link: LinkKind::Symlink,
        },
    }
}

fn unvalidated_address(sandbox: &str, now: &ManualClock) -> SignalDraft {
    destination_refusal_signal(
        &DestinationRefusal::AddressNotValidated {
            address: "10.0.0.5".parse().unwrap(),
        },
        &BrokerContext {
            observed: observed(sandbox, now),
            route: RouteId::new("api").unwrap(),
        },
    )
    .into_draft()
    .unwrap()
}

#[test]
fn bounds_refuse_zero_and_batches_without_a_place_for_host_observations() {
    assert_eq!(
        CollectorBounds::new(0, 0, 1),
        Err(CollectorProblem::ZeroPerSandbox)
    );
    assert_eq!(
        CollectorBounds::new(MAX_OBSERVATIONS_PER_ASSESSMENT + 1, 1, 1),
        Err(CollectorProblem::PerSandboxAboveAssessment {
            given: MAX_OBSERVATIONS_PER_ASSESSMENT + 1,
            max: MAX_OBSERVATIONS_PER_ASSESSMENT
        })
    );
    assert_eq!(
        CollectorBounds::new(4, 4, 1),
        Err(CollectorProblem::NoPlaceForHostObservations {
            guest_reports: 4,
            per_sandbox: 4
        })
    );
    assert_eq!(
        CollectorBounds::new(1, 0, 0),
        Err(CollectorProblem::ZeroSandboxes)
    );
    let bounds = CollectorBounds::new(MAX_OBSERVATIONS_PER_ASSESSMENT, 16, 4).unwrap();
    assert_eq!(bounds.per_sandbox(), MAX_OBSERVATIONS_PER_ASSESSMENT);
    assert_eq!(bounds.guest_reports(), 16);
    assert_eq!(bounds.sandboxes(), 4);
}

#[test]
fn drafts_v14_refuses_and_resource_samples_are_refused_and_counted_never_kept() {
    let now = clock();
    let mut collector = collector(4, 2, 4);
    // The supervisor cannot see perimeter traffic itself.
    let mislabelled = draft(
        "exe-a",
        ViolationKind::PerimeterRule,
        SignalSource::HostObserved {
            observer: HostObserver::Supervisor,
        },
        "rule",
        &now,
    );
    assert_eq!(
        collector.collect(mislabelled),
        Err(CollectRefusal::Signal(SignalRefusal::MislabelledSource {
            class: SignalClass::Violation {
                kind: ViolationKind::PerimeterRule
            },
            observer: HostObserver::Supervisor
        }))
    );
    let mut sample = draft(
        "exe-a",
        ViolationKind::PerimeterRule,
        perimeter_saw(),
        "pps",
        &now,
    );
    sample.class = SignalClass::Resource {
        resource: MonitoredResource::PacketsPerSecond,
    };
    sample.reading = Reading::Amount { amount: 10 };
    assert_eq!(
        collector.collect(sample),
        Err(CollectRefusal::ResourceSample {
            resource: MonitoredResource::PacketsPerSecond
        })
    );
    assert_eq!(collector.totals().refused, 2);
    assert_eq!(collector.pending(&execution("exe-a")), 0);
    assert!(collector.take_all().is_empty());
}

#[test]
fn repeated_observations_of_one_incident_merge_and_keep_the_newest_time() {
    let now = clock();
    let mut collector = collector(2, 1, 4);
    let first = draft(
        "exe-a",
        ViolationKind::PerimeterRule,
        perimeter_saw(),
        "rule",
        &now,
    );
    assert_eq!(collector.collect(first.clone()), Ok(Collected::Kept));
    now.advance(3 * SECOND);
    for _ in 0..100 {
        let again = draft(
            "exe-a",
            ViolationKind::PerimeterRule,
            perimeter_saw(),
            "rule",
            &now,
        );
        assert_eq!(collector.collect(again), Ok(Collected::Merged));
    }
    // An older copy merges too and keeps the newer time.
    assert_eq!(collector.collect(first), Ok(Collected::Merged));
    // The same subject from the same observer with another reading is another
    // observation; a check at the violation's own time is superseded by it.
    let mut passed = draft(
        "exe-a",
        ViolationKind::PerimeterRule,
        perimeter_saw(),
        "rule",
        &now,
    );
    passed.reading = Reading::CheckPassed;
    assert_eq!(collector.collect(passed.clone()), Ok(Collected::Superseded));
    now.advance(SECOND);
    passed.observed_at = now.now();
    assert_eq!(collector.collect(passed), Ok(Collected::Kept));
    assert_eq!(collector.totals().merged, 101);
    assert_eq!(collector.totals().superseded, 1);
    assert_eq!(collector.totals().overflowed, 0);
    let batch = collector.take(&execution("exe-a")).unwrap();
    assert_eq!(batch.signals().len(), 2);
    assert_eq!(batch.signals()[0].observed_at(), at(START_SECONDS + 3));
    assert_eq!(batch.overflowed(), 0);
}

#[test]
fn a_full_batch_counts_every_drop_and_the_count_travels_with_the_batch() {
    let now = clock();
    let mut collector = collector(2, 1, 4);
    for about in ["one", "two"] {
        let kept = draft(
            "exe-a",
            ViolationKind::PerimeterRule,
            perimeter_saw(),
            about,
            &now,
        );
        assert_eq!(collector.collect(kept), Ok(Collected::Kept));
    }
    for (about, overflowed) in [("three", 1), ("four", 2)] {
        let dropped = draft(
            "exe-a",
            ViolationKind::PerimeterRule,
            perimeter_saw(),
            about,
            &now,
        );
        assert_eq!(
            collector.collect(dropped),
            Ok(Collected::Overflowed { overflowed })
        );
    }
    assert_eq!(collector.pending(&execution("exe-a")), 2);
    assert_eq!(collector.totals().overflowed, 2);
    let batch = collector.take(&execution("exe-a")).unwrap();
    assert_eq!(batch.overflowed(), 2);
    assert_eq!(batch.sandbox(), &execution("exe-a"));
    // A new batch starts with no drops; the totals keep them.
    let next = draft(
        "exe-a",
        ViolationKind::PerimeterRule,
        perimeter_saw(),
        "five",
        &now,
    );
    assert_eq!(collector.collect(next), Ok(Collected::Kept));
    assert_eq!(collector.take(&execution("exe-a")).unwrap().overflowed(), 0);
    assert_eq!(collector.totals().overflowed, 2);
}

#[test]
fn guest_reports_never_take_the_places_kept_for_host_observations() {
    let now = clock();
    let per_sandbox = MAX_OBSERVATIONS_PER_ASSESSMENT;
    let mut collector = collector(per_sandbox, per_sandbox / 2, 4);
    // A guest floods 64 distinct reports: half are kept, the rest counted.
    for index in 0..per_sandbox {
        let outcome = collector
            .collect(guest_report("exe-a", &format!("report-{index}"), &now))
            .unwrap();
        if index < per_sandbox / 2 {
            assert_eq!(outcome, Collected::Kept);
        } else {
            assert!(
                matches!(outcome, Collected::Overflowed { .. }),
                "{outcome:?}"
            );
        }
    }
    // A host violation still finds its place.
    assert_eq!(
        collector.collect(unvalidated_address("exe-a", &now)),
        Ok(Collected::Kept)
    );
    let batch = collector.take(&execution("exe-a")).unwrap();
    assert_eq!(u64::try_from(per_sandbox / 2).unwrap(), batch.overflowed());
    assert!(batch
        .signals()
        .iter()
        .any(|signal| signal.source().is_host_observed()));
}

#[test]
fn a_flood_of_distinct_link_names_never_crowds_out_a_host_violation() {
    let now = clock();
    let mut collector = collector(MAX_OBSERVATIONS_PER_ASSESSMENT, 16, 4);
    let live = GrantMode::LiveWorkspace {
        acknowledgment: DisclosureAcknowledgment::of_current_statement(),
    };
    for index in 0..64 {
        let at = format!("l{index}");
        // In a live workspace a link is ordinary: nothing to collect.
        let ordinary = file_refusal_signal(&link(&at), &file_context("exe-a", live, "f", &now));
        assert_eq!(collector.collect_outcome(ordinary), Ok(None));
        // Beneath quarantine output it is a host anomaly, kept beside the signals.
        let anomaly = file_refusal_signal(
            &link(&at),
            &file_context("exe-a", GrantMode::QuarantineOutput, "f", &now),
        );
        assert_eq!(
            collector.collect_outcome(anomaly),
            Ok(Some(Collected::Kept))
        );
    }
    assert_eq!(
        collector.collect(unvalidated_address("exe-a", &now)),
        Ok(Collected::Kept)
    );
    let batch = collector.take(&execution("exe-a")).unwrap();
    assert_eq!(batch.anomalies().len(), 64);
    assert_eq!(batch.signals().len(), 1);
    // A 65th anomaly would be counted, never kept in a signal's place.
    for index in 0..65 {
        let anomaly = file_refusal_signal(
            &link(&format!("m{index}")),
            &file_context("exe-b", GrantMode::QuarantineOutput, "f", &now),
        );
        collector.collect_outcome(anomaly).unwrap();
    }
    let batch = collector.take(&execution("exe-b")).unwrap();
    assert_eq!(batch.anomalies().len(), MAX_OBSERVATIONS_PER_ASSESSMENT);
    assert_eq!(batch.overflowed(), 1);
    assert!(batch
        .anomalies()
        .iter()
        .all(|notice| notice.actions() == uncertain_actions()));
}

#[test]
fn a_host_observation_displaces_the_oldest_guest_report_in_a_full_batch() {
    let now = clock();
    let mut collector = collector(3, 2, 4);
    for about in ["old-report", "new-report"] {
        assert_eq!(
            collector.collect(guest_report("exe-a", about, &now)),
            Ok(Collected::Kept)
        );
        now.advance(SECOND);
    }
    let first = draft(
        "exe-a",
        ViolationKind::CanaryUse,
        perimeter_saw(),
        "hit-1",
        &now,
    );
    assert_eq!(collector.collect(first), Ok(Collected::Kept));
    let second = draft(
        "exe-a",
        ViolationKind::CanaryUse,
        perimeter_saw(),
        "hit-2",
        &now,
    );
    assert_eq!(
        collector.collect(second),
        Ok(Collected::DisplacedGuestReport { overflowed: 1 })
    );
    // A guest report never displaces anything.
    assert_eq!(
        collector.collect(guest_report("exe-a", "late-report", &now)),
        Ok(Collected::Overflowed { overflowed: 2 })
    );
    let batch = collector.take(&execution("exe-a")).unwrap();
    let subjects: Vec<Digest> = batch.signals().iter().map(|s| *s.subject()).collect();
    assert_eq!(
        subjects,
        vec![subject("new-report"), subject("hit-1"), subject("hit-2")]
    );
    assert_eq!(batch.overflowed(), 2);
}

#[test]
fn a_guest_report_never_blocks_another_sandboxs_host_violation() {
    let now = clock();
    let mut collector = collector(4, 2, 1);
    assert_eq!(
        collector.collect(guest_report("exe-a", "x", &now)),
        Ok(Collected::Kept)
    );
    // exe-b's host violation takes the place of exe-a's batch of guest reports.
    assert_eq!(
        collector.collect(unvalidated_address("exe-b", &now)),
        Ok(Collected::DisplacedGuestBatch {
            sandbox: execution("exe-a"),
            dropped: 1
        })
    );
    assert_eq!(collector.totals().unbatched, 1);
    assert_eq!(collector.pending(&execution("exe-b")), 1);
    // A guest report never displaces a batch, and a batch holding a host observation is
    // never displaced.
    assert_eq!(
        collector.collect(guest_report("exe-a", "y", &now)),
        Ok(Collected::NoBatchFree { unbatched: 2 })
    );
    assert_eq!(
        collector.collect(unvalidated_address("exe-c", &now)),
        Ok(Collected::NoBatchFree { unbatched: 3 })
    );
    assert!(collector.take(&execution("exe-b")).is_some());
    assert_eq!(
        collector.collect(unvalidated_address("exe-c", &now)),
        Ok(Collected::Kept)
    );
}

#[test]
fn a_re_issued_grant_still_gets_a_response_that_names_no_grant() {
    let now = clock();
    let mut collector = collector(8, 4, 4);
    let live = GrantMode::LiveWorkspace {
        acknowledgment: DisclosureAcknowledgment::of_current_statement(),
    };
    for issued in ["f-1", "f-2"] {
        let outcome =
            file_refusal_signal(&foreign_scope(), &file_context("exe-a", live, issued, &now));
        assert_eq!(
            collector.collect_outcome(outcome),
            Ok(Some(Collected::Kept))
        );
    }
    let batch = collector.take(&execution("exe-a")).unwrap();
    let incidents = batch.incidents();
    assert_eq!(incidents.len(), 1);
    assert!(incidents[0]
        .1
        .iter()
        .all(|signal| signal.violated_grant().is_none()));
    let assessment = assess(&incidents[0].1, &now);
    assert_eq!(assessment.violated_grant(), None);
    let mut responder = responder_with(
        &now,
        &[
            ("exe-a", SandboxClass::Task, &[]),
            ("exe-b", SandboxClass::Task, &[grant("f-1"), grant("f-2")]),
        ],
    );
    let record = responded(responder.respond_to(&assessment).unwrap());
    assert_eq!(record.targets.len(), 1);
    assert_eq!(record.decision.actions, violation_actions(true));
    assert_eq!(
        responder.applied(&execution("exe-b")),
        Some(&BTreeSet::new())
    );
}

#[test]
fn ordinary_outcomes_are_not_collected() {
    let now = clock();
    let mut collector = collector(4, 2, 4);
    let missing = file_refusal_signal(
        &ServiceRefusal::Resolve {
            refusal: ResolveRefusal::NotFound {
                at: GuestName::parse("missing").unwrap(),
            },
        },
        &file_context("exe-a", GrantMode::QuarantineOutput, "files", &now),
    );
    assert_eq!(collector.collect_outcome(missing), Ok(None));
    assert_eq!(collector.totals(), CollectorTotals::default());
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

/// The relay's host-observed hit of a credential canary planted in `sandbox`.
fn canary_hit(sandbox: &str, now: &ManualClock) -> Classification<CanaryViolation> {
    let mut registry = CanaryRegistry::new(&CanarySeed::from_bytes([9; 32]), HoneyportPool::none());
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
    let value = plan.instructions()[0].value().expose_for_planting();
    let observation = canaries::Observation::host_observed(
        binding(sandbox),
        now.now(),
        ObservedContent::OutboundBytes(format!("Authorization: Bearer {value}").into_bytes()),
    )
    .unwrap();
    let report = registry.match_observation(&observation, now);
    canary_hit_signal(&report.hits[0], host_session())
}

#[test]
fn enforcement_points_feed_the_collector_and_the_responder_end_to_end() {
    let now = clock();
    let files = grant("files-exe-a");
    let mut collector = collector(16, 8, 4);
    let live = GrantMode::LiveWorkspace {
        acknowledgment: DisclosureAcknowledgment::of_current_statement(),
    };
    // exe-a presents a file grant from another scope, again and again: one incident.
    for _ in 0..5 {
        let outcome = file_refusal_signal(
            &foreign_scope(),
            &file_context("exe-a", live, "files-exe-a", &now),
        );
        assert!(collector.collect_outcome(outcome).unwrap().is_some());
    }
    // exe-b overruns its release budget; an ordinary refusal on the route adds nothing.
    let broker_context = BrokerContext {
        observed: observed("exe-b", &now),
        route: RouteId::new("api").unwrap(),
    };
    let overrun = destination_refusal_signal(
        &DestinationRefusal::Release(ReleaseError::AllowanceExceeded {
            excess_bytes: 100,
            allowance_bytes: 10,
        }),
        &broker_context,
    );
    assert_eq!(
        collector.collect_outcome(overrun),
        Ok(Some(Collected::Kept))
    );
    let expired = destination_refusal_signal(&DestinationRefusal::Expired, &broker_context);
    assert_eq!(collector.collect_outcome(expired), Ok(None));
    // exe-b's perimeter no longer isolates the broker.
    let mismatch = install_signal(
        &Err(InstallError::RolledBack {
            cause: AbortCause::Verification {
                failure: VerificationFailure::ScopeNotIsolated,
            },
        }),
        &PerimeterContext {
            observed: observed("exe-b", &now),
            perimeter: PerimeterId::new(subject("perimeter-exe-b")),
        },
    );
    assert_eq!(
        collector.collect_outcome(mismatch),
        Ok(Some(Collected::Kept))
    );
    // exe-c leaks a canary, and a link sits beneath its quarantine output.
    assert_eq!(
        collector.collect_outcome(canary_hit("exe-c", &now)),
        Ok(Some(Collected::Kept))
    );
    let anomaly = file_refusal_signal(
        &link("escape"),
        &file_context("exe-c", GrantMode::QuarantineOutput, "files-exe-c", &now),
    );
    assert_eq!(
        collector.collect_outcome(anomaly),
        Ok(Some(Collected::Kept))
    );
    assert_eq!(collector.totals().kept, 5);
    assert_eq!(collector.totals().merged, 4);

    let mut responder = responder_with(
        &now,
        &[
            ("exe-a", SandboxClass::Task, &[]),
            ("exe-b", SandboxClass::Service, &[]),
            ("exe-c", SandboxClass::Task, &[]),
            ("exe-d", SandboxClass::Task, &[files]),
        ],
    );
    let mut outcomes = Vec::new();
    let mut notices = Vec::new();
    for batch in collector.take_all() {
        assert_eq!(batch.overflowed(), 0);
        notices.extend(batch.anomalies().iter().cloned());
        for (key, signals) in batch.incidents() {
            let assessment =
                assess_violation(&signals, &uncertain(), &now, host_session()).unwrap();
            let Assessment::Signal(signal) = &assessment else {
                panic!("expected a signal for {key:?}");
            };
            assert!(signal.freshness().is_fresh());
            outcomes.push((key, responder.respond(&assessment).unwrap()));
        }
    }
    let summary: Vec<(String, &'static str, BTreeSet<ResponseAction>, usize)> = outcomes
        .iter()
        .map(|(key, outcome)| {
            let ResponseOutcome::Responded(record) = outcome else {
                panic!("expected a response for {key:?}, got {outcome:?}");
            };
            (
                key.sandbox.as_str().to_owned(),
                key.class.label(),
                record.observed().unwrap().new_actions.clone(),
                record.targets.len(),
            )
        })
        .collect();
    assert_eq!(
        summary,
        vec![
            // The compromised file grant is revoked in exe-d, which holds it.
            (
                "exe-a".to_owned(),
                "file_root_escape",
                violation_actions(true),
                2
            ),
            (
                "exe-b".to_owned(),
                "perimeter_rule",
                violation_actions(true),
                1
            ),
            // The overrun adds nothing exe-b does not already have.
            ("exe-b".to_owned(), "budget_overrun", BTreeSet::new(), 1),
            // A canary hit isolates and revokes and never stops.
            (
                "exe-c".to_owned(),
                "canary_use",
                violation_actions(false),
                1
            ),
        ]
    );
    let ResponseOutcome::Responded(first) = &outcomes[0].1 else {
        unreachable!()
    };
    assert_eq!(first.targets[1].sandbox, execution("exe-d"));
    assert_eq!(
        first.targets[1].actions,
        BTreeSet::from([ResponseAction::NotifyUser, ResponseAction::RevokeGrant])
    );
    let ResponseOutcome::Responded(lockdown) = &outcomes[1].1 else {
        unreachable!()
    };
    assert_eq!(
        lockdown.decision.class_response,
        Some(ViolationAction::LockDown)
    );
    // The host anomaly beside them is V14's uncertain result for exe-c, nothing more.
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].sandbox, execution("exe-c"));
    assert_eq!(notices[0].actions(), uncertain_actions());
    assert!(!responder
        .applied(&execution("exe-c"))
        .unwrap()
        .contains(&ResponseAction::Stop));
}
