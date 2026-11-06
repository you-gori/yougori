//! Tests for signals, freshness, assessment, sustained windows, the five policies and the
//! decision function (VM-W43; §8.2; §1.3). Everything runs on fakes.

use std::collections::BTreeMap;
use std::time::Duration;

use super::fakes::*;
use super::*;
use crate::foundation::events::{AuditDraft, HostFact};
use crate::foundation::evidence::{SourceClass, Staleness};
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::sandbox_contract::canaries::HitMeaning;
use crate::sandbox_contract::files::{
    ManagedObjectKind, SandboxClass, ViolationAction, VolumeClass,
};

/// Every JSON object key in `value`, recursively.
fn keys(value: &serde_json::Value, out: &mut Vec<String>) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, inner) in map {
                out.push(key.clone());
                keys(inner, out);
            }
        }
        serde_json::Value::Array(items) => items.iter().for_each(|item| keys(item, out)),
        _ => {}
    }
}

/// §1.3: no score, rank, severity or probability field anywhere.
pub fn assert_no_score(value: &serde_json::Value) {
    let mut found = Vec::new();
    keys(value, &mut found);
    for key in found {
        for banned in [
            "score",
            "severity",
            "risk",
            "probability",
            "confidence",
            "rank",
            "tier",
        ] {
            assert!(!key.contains(banned), "field {key} looks like a score");
        }
    }
}

// ---------------------------------------------------------------------------------------
// Signals and sources (§8.2 line 2268)

#[test]
fn every_class_names_its_host_observers_and_mislabelled_sources_are_refused() {
    for class in SignalClass::all() {
        assert!(!class.host_observers().is_empty(), "{class}");
        for observer in HostObserver::ALL {
            let result = MonitoringSignal::new(draft(
                "exe-a",
                class,
                host(observer),
                if class.is_violation() {
                    Reading::ViolationObserved
                } else {
                    Reading::Amount { amount: 1 }
                },
                at(START_SECONDS),
            ));
            if class.host_observers().contains(&observer) {
                assert!(result.is_ok(), "{class} by {observer:?}");
            } else {
                assert_eq!(
                    result.unwrap_err(),
                    SignalRefusal::MislabelledSource { class, observer }
                );
            }
        }
    }
    // Hypervisor counters are blind inside the guest: no credential replay, no canary use.
    for kind in [ViolationKind::CredentialReplay, ViolationKind::CanaryUse] {
        assert!(!violation(kind)
            .host_observers()
            .contains(&HostObserver::HypervisorCounters));
    }
    // Processes inside the guest are only ever guest-reported.
    assert_eq!(
        MonitoredResource::ProcessCount.host_observers(),
        &[HostObserver::Supervisor]
    );
    // Any class may be guest-reported, and stays so.
    let guest = guest_violation(
        "exe-a",
        ViolationKind::LaunchArtifactIntegrity,
        at(START_SECONDS),
    );
    assert_eq!(guest.source().source_class(), SourceClass::GuestReport);
    assert_eq!(guest.source().observer(), None);
}

#[test]
fn readings_must_fit_their_class_and_only_violations_name_a_grant() {
    let cpu = resource(MonitoredResource::CpuMillicores);
    let replay = violation(ViolationKind::CredentialReplay);
    assert_eq!(
        MonitoringSignal::new(draft(
            "exe-a",
            replay,
            host(HostObserver::Broker),
            Reading::Amount { amount: 3 },
            at(1)
        ))
        .unwrap_err(),
        SignalRefusal::ReadingDoesNotFitClass {
            class: replay,
            reading: Reading::Amount { amount: 3 }
        }
    );
    for reading in [Reading::ViolationObserved, Reading::CheckPassed] {
        assert_eq!(
            MonitoringSignal::new(draft(
                "exe-a",
                cpu,
                SignalSource::GuestReported,
                reading,
                at(1)
            ))
            .unwrap_err(),
            SignalRefusal::ReadingDoesNotFitClass {
                class: cpu,
                reading
            }
        );
    }
    let mut with_grant = draft(
        "exe-a",
        cpu,
        host(HostObserver::HypervisorCounters),
        Reading::Amount { amount: 3 },
        at(1),
    );
    with_grant.violated_grant = Some(grant("g"));
    assert_eq!(
        MonitoringSignal::new(with_grant).unwrap_err(),
        SignalRefusal::GrantOnResourceSignal { class: cpu }
    );
}

#[test]
fn signals_read_back_only_as_the_checks_allow() {
    let signal = host_violation("exe-a", ViolationKind::PerimeterRule, at(START_SECONDS));
    let json = serde_json::to_value(&signal).unwrap();
    assert_eq!(
        serde_json::from_value::<MonitoringSignal>(json.clone()).unwrap(),
        signal
    );
    // A host observer that cannot see the class is refused when read back too.
    let mut mislabelled = json.clone();
    mislabelled["source"] =
        serde_json::json!({"source": "host_observed", "observer": "hypervisor_counters"});
    assert!(serde_json::from_value::<MonitoringSignal>(mislabelled).is_err());
    let mut extra = json.clone();
    extra["verdict"] = serde_json::json!("malicious");
    assert!(serde_json::from_value::<MonitoringSignal>(extra).is_err());
    // Strict tagged enums: a unit variant with a smuggled field is refused.
    assert!(serde_json::from_value::<SignalSource>(
        serde_json::json!({"source": "guest_reported", "observer": "broker"})
    )
    .is_err());
    assert!(serde_json::from_value::<Reading>(
        serde_json::json!({"reading": "check_passed", "amount": 1})
    )
    .is_err());
    assert!(serde_json::from_value::<Freshness>(
        serde_json::json!({"freshness": "fresh", "age": 1})
    )
    .is_err());
}

#[test]
fn freshness_is_judged_on_the_host_clock_and_session() {
    let limit = 30 * SECOND;
    let now = at(START_SECONDS);
    let observed = at(START_SECONDS - 30);
    assert_eq!(
        judge_freshness(observed, host_session(), now, host_session(), limit),
        Freshness::Fresh,
        "an age of exactly the bound is fresh"
    );
    let older = MonotonicTime::from_nanos(observed.as_nanos() - 1);
    assert_eq!(
        judge_freshness(older, host_session(), now, host_session(), limit),
        Freshness::Stale {
            staleness: Staleness::TooOld {
                age: limit + Duration::from_nanos(1),
                limit
            }
        }
    );
    assert_eq!(
        judge_freshness(now, session(9), now, host_session(), limit),
        Freshness::Stale {
            staleness: Staleness::OtherClock
        }
    );
    assert_eq!(
        judge_freshness(
            at(START_SECONDS + 1),
            host_session(),
            now,
            host_session(),
            limit
        ),
        Freshness::Stale {
            staleness: Staleness::ObservedAfterNow
        }
    );
}

#[test]
fn audit_drafts_label_host_facts_and_guest_reports() {
    let host_signal = host_violation("exe-a", ViolationKind::CapabilityReplay, at(START_SECONDS));
    match host_signal.audit_draft() {
        AuditDraft::HostFact { fact, fields } => {
            assert_eq!(fact, HostFact::DetectionSignal);
            assert!(fields.iter().any(|field| field.name() == "observer"));
        }
        other => panic!("{other:?}"),
    }
    let guest = guest_violation("exe-a", ViolationKind::CapabilityReplay, at(START_SECONDS));
    assert!(matches!(
        guest.audit_draft(),
        AuditDraft::GuestObservation { .. }
    ));
}

// ---------------------------------------------------------------------------------------
// Assessment: stale or conflicting is uncertain, never a pass

fn assess(signals: &[MonitoringSignal], now: &impl Clock) -> Assessment {
    assess_violation(signals, &uncertain(), now, host_session()).unwrap()
}

fn signal_of(assessment: Assessment) -> SignalAssessment {
    match assessment {
        Assessment::Signal(signal) => signal,
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_fresh_host_observation_establishes_a_violation() {
    let now = clock();
    let signal = signal_of(assess(
        &[host_violation(
            "exe-a",
            ViolationKind::CredentialReplay,
            now.now(),
        )],
        &now,
    ));
    assert_eq!(signal.freshness(), Freshness::Fresh);
    assert_eq!(signal.source(), host(HostObserver::Broker));
    assert_eq!(signal.sandbox(), &execution("exe-a"));
    assert_eq!(signal.assessed_at(), now.now());
}

#[test]
fn a_fresh_host_check_that_found_nothing_makes_it_conflicting() {
    let now = clock();
    let kind = ViolationKind::CapabilityReplay;
    let signal = signal_of(assess(
        &[
            host_violation("exe-a", kind, now.now()),
            host_check_passed("exe-a", kind, HostObserver::Executor, now.now()),
        ],
        &now,
    ));
    assert_eq!(
        signal.freshness(),
        Freshness::Conflicting {
            conflict: Conflict {
                reported_by: HostObserver::Supervisor,
                contradicted_by: HostObserver::Executor
            }
        }
    );
}

#[test]
fn a_guest_report_never_contradicts_or_replaces_a_host_observation() {
    let now = clock();
    let kind = ViolationKind::PerimeterRule;
    let guest_pass = MonitoringSignal::new(draft(
        "exe-a",
        violation(kind),
        SignalSource::GuestReported,
        Reading::CheckPassed,
        now.now(),
    ))
    .unwrap();
    let signal = signal_of(assess(
        &[host_violation("exe-a", kind, now.now()), guest_pass],
        &now,
    ));
    assert_eq!(signal.freshness(), Freshness::Fresh);
    // A stale host observation stays the basis even beside a fresh guest report.
    let stale = host_violation("exe-a", kind, at(START_SECONDS - 31));
    let guest = guest_violation("exe-a", kind, now.now());
    let signal = signal_of(assess(&[stale, guest], &now));
    assert!(signal.source().is_host_observed());
    assert!(matches!(signal.freshness(), Freshness::Stale { .. }));
}

#[test]
fn stale_host_observations_are_uncertain_even_beside_a_fresh_pass() {
    let now = clock();
    let kind = ViolationKind::LaunchArtifactIntegrity;
    let stale = host_violation("exe-a", kind, at(START_SECONDS - 31));
    let pass = host_check_passed("exe-a", kind, HostObserver::Supervisor, now.now());
    let signal = signal_of(assess(&[stale, pass], &now));
    assert_eq!(
        signal.freshness(),
        Freshness::Stale {
            staleness: Staleness::TooOld {
                age: 31 * SECOND,
                limit: 30 * SECOND
            }
        }
    );
}

#[test]
fn guest_reports_alone_stand_as_guest_reports_and_passes_alone_are_no_signal() {
    let now = clock();
    let kind = ViolationKind::CanaryUse;
    let signal = signal_of(assess(&[guest_violation("exe-a", kind, now.now())], &now));
    assert_eq!(signal.source(), SignalSource::GuestReported);
    assert_eq!(assess(&[], &now), Assessment::NoViolationObserved);
    assert_eq!(
        assess(
            &[host_check_passed(
                "exe-a",
                kind,
                HostObserver::Perimeter,
                now.now()
            )],
            &now
        ),
        Assessment::NoViolationObserved
    );
}

#[test]
fn assessment_refuses_mixed_resource_oversized_and_conflicting_grant_inputs() {
    let now = clock();
    let a = host_violation("exe-a", ViolationKind::CanaryUse, now.now());
    let b = host_violation("exe-b", ViolationKind::CanaryUse, now.now());
    let policy = uncertain();
    assert_eq!(
        assess_violation(&[a.clone(), b], &policy, &now, host_session()),
        Err(AssessRefusal::MixedSubjects)
    );
    let cpu = sample(
        "exe-a",
        MonitoredResource::CpuMillicores,
        host(HostObserver::HypervisorCounters),
        1,
        now.now(),
    );
    assert_eq!(
        assess_violation(&[cpu], &policy, &now, host_session()),
        Err(AssessRefusal::ResourceClass {
            resource: MonitoredResource::CpuMillicores
        })
    );
    let many = vec![a.clone(); MAX_OBSERVATIONS_PER_ASSESSMENT + 1];
    assert_eq!(
        assess_violation(&many, &policy, &now, host_session()),
        Err(AssessRefusal::TooMany {
            given: MAX_OBSERVATIONS_PER_ASSESSMENT + 1,
            max: MAX_OBSERVATIONS_PER_ASSESSMENT
        })
    );
    let with = |name: &str| {
        let mut signal = draft(
            "exe-a",
            violation(ViolationKind::CredentialReplay),
            host(HostObserver::Broker),
            Reading::ViolationObserved,
            now.now(),
        );
        signal.violated_grant = Some(grant(name));
        MonitoringSignal::new(signal).unwrap()
    };
    assert_eq!(
        assess_violation(&[with("g1"), with("g2")], &policy, &now, host_session()),
        Err(AssessRefusal::ConflictingGrants)
    );
    assert_eq!(
        signal_of(assess(&[with("g1"), with("g1")], &now)).violated_grant(),
        Some(grant("g1"))
    );
}

// ---------------------------------------------------------------------------------------
// Sustained windows with hysteresis

/// CPU: over at 4,000 millicores, under at 3,000, 30 s to trigger, 60 s to clear, samples
/// at most 10 s apart.
fn cpu_window() -> SustainedWindow {
    SustainedWindow {
        high_mark: 4_000,
        low_mark: 3_000,
        sustain_seconds: 30,
        clear_seconds: 60,
        max_sample_gap_seconds: 10,
    }
}

fn packet_window() -> SustainedWindow {
    SustainedWindow {
        high_mark: 1_000,
        low_mark: 500,
        sustain_seconds: 30,
        clear_seconds: 60,
        max_sample_gap_seconds: 10,
    }
}

fn monitor() -> ResourceMonitor {
    ResourceMonitor::new(
        host_session(),
        &uncertain(),
        BTreeMap::from([
            (MonitoredResource::CpuMillicores, cpu_window()),
            (MonitoredResource::PacketsPerSecond, packet_window()),
        ]),
        64,
    )
    .unwrap()
}

const CPU: MonitoredResource = MonitoredResource::CpuMillicores;

fn cpu_source() -> SignalSource {
    host(HostObserver::HypervisorCounters)
}

/// Feeds one CPU sample at the clock's time.
fn feed(monitor: &mut ResourceMonitor, now: &impl Clock, amount: u64) -> ResourceObservation {
    monitor
        .observe(&sample("exe-a", CPU, cpu_source(), amount, now.now()), now)
        .unwrap()
}

fn cpu_state(monitor: &ResourceMonitor) -> Option<WindowState> {
    monitor.state(
        &execution("exe-a"),
        SeriesKey {
            resource: CPU,
            source: cpu_source(),
        },
    )
}

#[test]
fn windows_need_a_hysteresis_gap_and_positive_bounds() {
    assert_eq!(cpu_window().validate(), Ok(()));
    let mut window = cpu_window();
    window.low_mark = 4_000;
    assert_eq!(
        window.validate(),
        Err(WindowProblem::NoHysteresisGap {
            high_mark: 4_000,
            low_mark: 4_000
        })
    );
    for (mutate, problem) in [
        (
            (|w: &mut SustainedWindow| w.sustain_seconds = 0) as fn(&mut SustainedWindow),
            WindowProblem::ZeroSustain,
        ),
        (|w| w.clear_seconds = 0, WindowProblem::ZeroClear),
        (
            |w| w.max_sample_gap_seconds = 0,
            WindowProblem::ZeroSampleGap,
        ),
        (
            |w| w.max_sample_gap_seconds = 31,
            WindowProblem::SampleGapExceedsWindow {
                max_sample_gap_seconds: 31,
                window_seconds: 30,
            },
        ),
    ] {
        let mut window = cpu_window();
        mutate(&mut window);
        assert_eq!(window.validate(), Err(problem));
    }
    for max_series in [0, MAX_MONITORED_SERIES + 1] {
        assert_eq!(
            ResourceMonitor::new(host_session(), &uncertain(), BTreeMap::new(), max_series)
                .unwrap_err(),
            WindowProblem::SeriesBound { max_series }
        );
    }
    let mut bad = cpu_window();
    bad.sustain_seconds = 0;
    assert_eq!(
        ResourceMonitor::new(
            host_session(),
            &uncertain(),
            BTreeMap::from([(CPU, bad)]),
            4
        )
        .unwrap_err(),
        WindowProblem::ZeroSustain
    );
}

#[test]
fn a_series_triggers_only_after_the_whole_sustain_window() {
    let now = clock();
    let mut monitor = monitor();
    for _ in 0..3 {
        let observation = feed(&mut monitor, &now, 4_500);
        assert!(
            matches!(observation, ResourceObservation::Held { .. }),
            "{observation:?}"
        );
        now.advance(10 * SECOND);
    }
    // 1,000 s, 1,010 s, 1,020 s over; at 1,030 s the 30 s sustain window is complete.
    match feed(&mut monitor, &now, 4_500) {
        ResourceObservation::Triggered {
            over_since,
            assessment,
        } => {
            assert_eq!(over_since, at(START_SECONDS));
            assert_eq!(assessment.freshness(), Freshness::Fresh);
            assert_eq!(assessment.class(), resource(CPU));
            assert_eq!(assessment.key().subject, SeriesKey::subject(CPU));
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(
        cpu_state(&monitor),
        Some(WindowState::Exceeded {
            since: at(START_SECONDS + 30)
        })
    );
    // Exactly the high mark counts as over; staying over triggers nothing more.
    now.advance(10 * SECOND);
    assert!(matches!(
        feed(&mut monitor, &now, 4_000),
        ResourceObservation::Held { .. }
    ));
}

#[test]
fn a_signal_hovering_near_the_limit_cannot_flap_a_response() {
    let now = clock();
    let mut monitor = monitor();
    let mut triggers = 0;
    // Ten minutes alternating over and under every 5 s never completes a sustain window.
    for step in 0..120 {
        let amount = if step % 2 == 0 { 4_500 } else { 2_000 };
        if matches!(
            feed(&mut monitor, &now, amount),
            ResourceObservation::Triggered { .. }
        ) {
            triggers += 1;
        }
        now.advance(5 * SECOND);
    }
    assert_eq!(triggers, 0);
    // Between the marks nothing starts.
    for _ in 0..20 {
        assert!(matches!(
            feed(&mut monitor, &now, 3_500),
            ResourceObservation::Held { .. }
        ));
        now.advance(5 * SECOND);
    }
    assert_eq!(cpu_state(&monitor), Some(WindowState::Normal));
    // Sustained over: exactly one trigger.
    for _ in 0..7 {
        if matches!(
            feed(&mut monitor, &now, 5_000),
            ResourceObservation::Triggered { .. }
        ) {
            triggers += 1;
        }
        now.advance(5 * SECOND);
    }
    assert_eq!(triggers, 1);
    // Exceeded, then alternating or between the marks never clears it.
    let mut clears = 0;
    for step in 0..120 {
        let amount = [2_000, 4_500, 3_500][step % 3];
        match feed(&mut monitor, &now, amount) {
            ResourceObservation::Cleared { .. } => clears += 1,
            ResourceObservation::Triggered { .. } => triggers += 1,
            _ => {}
        }
        now.advance(5 * SECOND);
    }
    assert_eq!((triggers, clears), (1, 0));
    assert!(matches!(
        cpu_state(&monitor),
        Some(WindowState::Exceeded { .. })
    ));
}

#[test]
fn clearing_needs_the_whole_clear_window_and_retriggering_a_new_sustain() {
    let now = clock();
    let mut monitor = monitor();
    for _ in 0..4 {
        feed(&mut monitor, &now, 4_500);
        now.advance(10 * SECOND);
    }
    // Under from 1,040 s; cleared at 1,100 s, 60 s later.
    let mut cleared_at = None;
    for _ in 0..7 {
        if let ResourceObservation::Cleared { incident } = feed(&mut monitor, &now, 2_000) {
            assert_eq!(incident.class, resource(CPU));
            cleared_at = Some(now.now());
        }
        now.advance(10 * SECOND);
    }
    assert_eq!(cleared_at, Some(at(START_SECONDS + 100)));
    // Over again: a new trigger needs another full 30 s.
    let first_over = now.now();
    let mut triggered_at = None;
    for _ in 0..4 {
        if let ResourceObservation::Triggered { over_since, .. } = feed(&mut monitor, &now, 4_500) {
            assert_eq!(over_since, first_over);
            triggered_at = Some(now.now());
        }
        now.advance(10 * SECOND);
    }
    assert_eq!(
        triggered_at.map(|t| t.saturating_duration_since(first_over)),
        Some(30 * SECOND)
    );
}

#[test]
fn a_gap_in_samples_breaks_the_run_in_progress() {
    let now = clock();
    let mut monitor = monitor();
    feed(&mut monitor, &now, 4_500);
    now.advance(11 * SECOND);
    feed(&mut monitor, &now, 4_500);
    assert_eq!(
        cpu_state(&monitor),
        Some(WindowState::Rising {
            since: at(START_SECONDS + 11)
        }),
        "an 11 s gap restarts the rise"
    );
    for _ in 0..2 {
        now.advance(10 * SECOND);
        assert!(matches!(
            feed(&mut monitor, &now, 4_500),
            ResourceObservation::Held { .. }
        ));
    }
    now.advance(10 * SECOND);
    assert!(matches!(
        feed(&mut monitor, &now, 4_500),
        ResourceObservation::Triggered { over_since, .. } if over_since == at(START_SECONDS + 11)
    ));
    // Falling, then a gap: back to exceeded, and the clear window starts again.
    now.advance(10 * SECOND);
    feed(&mut monitor, &now, 2_000);
    assert!(matches!(
        cpu_state(&monitor),
        Some(WindowState::Falling { .. })
    ));
    now.advance(11 * SECOND);
    let restart = now.now();
    feed(&mut monitor, &now, 2_000);
    assert!(matches!(
        cpu_state(&monitor),
        Some(WindowState::Falling { since, .. }) if since == restart
    ));
}

#[test]
fn stale_and_out_of_order_samples_move_nothing() {
    let now = clock();
    let mut monitor = monitor();
    feed(&mut monitor, &now, 4_500);
    now.advance(5 * SECOND);
    let stale = sample("exe-a", CPU, cpu_source(), 9_000, at(START_SECONDS - 40));
    match monitor.observe(&stale, &now).unwrap() {
        ResourceObservation::Uncertain { assessment } => {
            assert!(matches!(assessment.freshness(), Freshness::Stale { .. }));
        }
        other => panic!("{other:?}"),
    }
    let other_clock = MonitoringSignal::new(SignalDraft {
        session: session(7),
        ..draft(
            "exe-a",
            resource(CPU),
            cpu_source(),
            Reading::Amount { amount: 1 },
            now.now(),
        )
    })
    .unwrap();
    assert!(matches!(
        monitor.observe(&other_clock, &now).unwrap(),
        ResourceObservation::Uncertain { .. }
    ));
    assert_eq!(
        cpu_state(&monitor),
        Some(WindowState::Rising {
            since: at(START_SECONDS)
        })
    );
    let repeated = sample("exe-a", CPU, cpu_source(), 4_500, at(START_SECONDS));
    assert_eq!(
        monitor.observe(&repeated, &now),
        Err(WindowRefusal::OutOfOrder {
            last: at(START_SECONDS),
            observed_at: at(START_SECONDS)
        })
    );
}

#[test]
fn host_and_guest_series_never_mix() {
    let now = clock();
    let mut monitor = monitor();
    let mut guest_trigger = None;
    for _ in 0..4 {
        let observation = monitor
            .observe(
                &sample("exe-a", CPU, SignalSource::GuestReported, 9_000, now.now()),
                &now,
            )
            .unwrap();
        if let ResourceObservation::Triggered { assessment, .. } = observation {
            guest_trigger = Some(assessment);
        }
        now.advance(10 * SECOND);
    }
    let assessment = guest_trigger.unwrap();
    assert_eq!(assessment.source(), SignalSource::GuestReported);
    let decision = decide(
        &policies(),
        &DecisionInput {
            class: assessment.class(),
            source: assessment.source(),
            freshness: assessment.freshness(),
            sandbox_class: SandboxClass::Task,
        },
    );
    assert_eq!(
        decision.actions,
        [
            ResponseAction::NotifyUser,
            ResponseAction::RequestHostCorroboration
        ]
        .into()
    );
    assert_eq!(cpu_state(&monitor), None, "the host series saw nothing");
}

#[test]
fn a_host_series_contradicted_by_another_observer_triggers_conflicting() {
    let now = clock();
    let mut monitor = monitor();
    let packets = MonitoredResource::PacketsPerSecond;
    let mut trigger = None;
    for step in 0..4 {
        monitor
            .observe(
                &sample(
                    "exe-a",
                    packets,
                    host(HostObserver::HypervisorCounters),
                    100,
                    now.now(),
                ),
                &now,
            )
            .unwrap();
        let observation = monitor
            .observe(
                &sample(
                    "exe-a",
                    packets,
                    host(HostObserver::Perimeter),
                    2_000,
                    now.now(),
                ),
                &now,
            )
            .unwrap();
        if let ResourceObservation::Triggered { assessment, .. } = observation {
            trigger = Some((step, assessment));
        }
        now.advance(10 * SECOND);
    }
    let (step, assessment) = trigger.unwrap();
    assert_eq!(step, 3);
    assert_eq!(
        assessment.freshness(),
        Freshness::Conflicting {
            conflict: Conflict {
                reported_by: HostObserver::Perimeter,
                contradicted_by: HostObserver::HypervisorCounters
            }
        }
    );
}

#[test]
fn a_silent_series_is_uncertain_once_per_silence() {
    let now = clock();
    let mut monitor = monitor();
    feed(&mut monitor, &now, 100);
    now.advance(10 * SECOND);
    assert!(
        monitor.poll(&now).is_empty(),
        "10 s is within the gap bound"
    );
    now.advance(SECOND);
    let silent = monitor.poll(&now);
    assert_eq!(silent.len(), 1);
    assert_eq!(
        silent[0].freshness(),
        Freshness::Stale {
            staleness: Staleness::TooOld {
                age: 11 * SECOND,
                limit: 10 * SECOND
            }
        }
    );
    assert!(monitor.poll(&now).is_empty());
    feed(&mut monitor, &now, 100);
    now.advance(11 * SECOND);
    assert_eq!(monitor.poll(&now).len(), 1);
}

#[test]
fn the_monitor_refuses_what_it_cannot_judge_and_bounds_its_series() {
    let now = clock();
    let mut monitor = ResourceMonitor::new(
        host_session(),
        &uncertain(),
        BTreeMap::from([(CPU, cpu_window())]),
        1,
    )
    .unwrap();
    assert_eq!(
        monitor.observe(
            &host_violation("exe-a", ViolationKind::PerimeterRule, now.now()),
            &now
        ),
        Err(WindowRefusal::NotAResourceSignal)
    );
    let disk = sample(
        "exe-a",
        MonitoredResource::DiskBytes,
        host(HostObserver::Supervisor),
        1,
        now.now(),
    );
    assert_eq!(
        monitor.observe(&disk, &now),
        Err(WindowRefusal::NoWindow {
            resource: MonitoredResource::DiskBytes
        })
    );
    feed(&mut monitor, &now, 1);
    let other = sample("exe-b", CPU, cpu_source(), 1, now.now());
    assert_eq!(
        monitor.observe(&other, &now),
        Err(WindowRefusal::TooManySeries { max_series: 1 })
    );
    assert_eq!(monitor.forget_sandbox(&execution("exe-a")), 1);
    assert!(monitor.observe(&other, &now).is_ok());
}

// ---------------------------------------------------------------------------------------
// The five policies

#[test]
fn the_default_policies_satisfy_every_rule() {
    let policies = policies();
    let rebuilt = ResponsePolicies::new(
        policies.isolate().clone(),
        policies.revoke().clone(),
        policies.stop().clone(),
        *policies.notify(),
        *policies.uncertain(),
    )
    .unwrap();
    assert_eq!(rebuilt, policies);
    assert!(!policies
        .stop()
        .triggers()
        .contains(&ViolationKind::CanaryUse));
    assert!(policies
        .stop()
        .triggers()
        .is_subset(policies.revoke().triggers()));
    assert_eq!(
        RevokePolicy::REASON,
        crate::foundation::events::RevocationReason::SecurityEvent
    );
    assert_eq!(NotifyPolicy::RECIPIENT, NotifyRecipient::User);
    assert!(IsolatePolicy::KEEPS_VM_STATE && IsolatePolicy::REVERSIBLE);
    assert_eq!(
        IsolatePolicy::CUTS,
        [IsolationCut::GuestChannels, IsolationCut::Network]
    );
}

#[test]
fn policies_that_break_a_rule_are_refused() {
    let base = policies();
    let notify = *base.notify();
    let uncertain = *base.uncertain();
    let mut isolate = IsolatePolicy::default_triggers();
    isolate.remove(&violation(ViolationKind::AuthorizationEpochMismatch));
    assert_eq!(
        ResponsePolicies::new(
            IsolatePolicy::new(isolate),
            base.revoke().clone(),
            base.stop().clone(),
            notify,
            uncertain
        ),
        Err(PolicyProblem::ViolationWithoutIsolation {
            kind: ViolationKind::AuthorizationEpochMismatch
        })
    );
    let mut stop = StopPolicy::default_triggers();
    stop.insert(ViolationKind::CanaryUse);
    assert_eq!(
        ResponsePolicies::new(
            base.isolate().clone(),
            base.revoke().clone(),
            StopPolicy::new(stop),
            notify,
            uncertain
        ),
        Err(PolicyProblem::CanaryStops)
    );
    let mut revoke = RevokePolicy::default_triggers();
    revoke.remove(&ViolationKind::PerimeterRule);
    assert_eq!(
        ResponsePolicies::new(
            base.isolate().clone(),
            RevokePolicy::new(revoke),
            base.stop().clone(),
            notify,
            uncertain
        ),
        Err(PolicyProblem::StopWithoutRevoke {
            kind: ViolationKind::PerimeterRule
        })
    );
    assert_eq!(
        UncertainPolicy::new(Duration::ZERO),
        Err(PolicyProblem::ZeroObservationAge)
    );
}

#[test]
fn notifications_have_one_recipient_the_user() {
    assert_eq!(
        serde_json::to_value(NotifyRecipient::User).unwrap(),
        serde_json::json!("user")
    );
    for other in ["third_party", "provider", "remote_peer"] {
        assert!(serde_json::from_value::<NotifyRecipient>(serde_json::json!(other)).is_err());
    }
}

#[test]
fn response_cleanup_never_targets_user_work() {
    for kind in [
        ManagedObjectKind::Overlay,
        ManagedObjectKind::ScratchDirectory,
        ManagedObjectKind::Snapshot,
        ManagedObjectKind::UserSourceData,
    ] {
        assert!(!response_cleanup_allows(kind), "{kind:?}");
    }
    for kind in RESPONSE_CLEANUP_KINDS {
        assert!(response_cleanup_allows(kind));
    }
}

// ---------------------------------------------------------------------------------------
// The decision function

fn freshness_cases() -> Vec<Freshness> {
    vec![
        Freshness::Fresh,
        Freshness::Stale {
            staleness: Staleness::TooOld {
                age: 31 * SECOND,
                limit: 30 * SECOND,
            },
        },
        Freshness::Stale {
            staleness: Staleness::OtherClock,
        },
        Freshness::Stale {
            staleness: Staleness::ObservedAfterNow,
        },
        Freshness::Conflicting {
            conflict: Conflict {
                reported_by: HostObserver::Perimeter,
                contradicted_by: HostObserver::Broker,
            },
        },
    ]
}

/// Every input the decision function can meet: each class with each of its sources, each
/// freshness and each sandbox class.
pub fn every_input() -> Vec<DecisionInput> {
    let mut inputs = Vec::new();
    for class in SignalClass::all() {
        let mut sources: Vec<SignalSource> = class
            .host_observers()
            .iter()
            .map(|&observer| host(observer))
            .collect();
        sources.push(SignalSource::GuestReported);
        for source in sources {
            for freshness in freshness_cases() {
                for sandbox_class in [SandboxClass::Task, SandboxClass::Service] {
                    inputs.push(DecisionInput {
                        class,
                        source,
                        freshness,
                        sandbox_class,
                    });
                }
            }
        }
    }
    inputs
}

#[test]
fn a_guest_report_alone_only_notifies_or_asks_for_corroboration() {
    let policies = policies();
    for input in every_input()
        .into_iter()
        .filter(|input| input.source == SignalSource::GuestReported)
    {
        let decision = decide(&policies, &input);
        assert_eq!(
            decision.actions,
            [
                ResponseAction::NotifyUser,
                ResponseAction::RequestHostCorroboration
            ]
            .into(),
            "{input:?}"
        );
        assert_eq!(decision.class_response, None);
        assert_eq!(decision.rung, EscalationRung::Notify);
        assert_eq!(
            decision.reason,
            DecisionReason::GuestReportNeedsCorroboration { class: input.class }
        );
    }
}

#[test]
fn uncertain_results_notify_and_deny_new_high_impact_and_never_more() {
    let policies = policies();
    for input in every_input()
        .into_iter()
        .filter(|input| input.source.is_host_observed() && !input.freshness.is_fresh())
    {
        let decision = decide(&policies, &input);
        assert_eq!(
            decision.actions,
            UncertainPolicy::ACTIONS.into_iter().collect(),
            "{input:?}"
        );
        assert!(!decision.actions.is_empty(), "never silent");
        assert!(matches!(decision.reason, DecisionReason::Uncertain { .. }));
        assert!(
            decision.preserves.contains(&Preserved::VmState),
            "never destructive"
        );
    }
}

#[test]
fn fresh_host_violations_take_the_policy_actions_and_vm_d10_through_v05() {
    let policies = policies();
    for input in every_input()
        .into_iter()
        .filter(|input| input.source.is_host_observed() && input.freshness.is_fresh())
    {
        let decision = decide(&policies, &input);
        match input.class {
            SignalClass::Violation { kind } => {
                for action in [
                    ResponseAction::NotifyUser,
                    ResponseAction::DenyNewHighImpact,
                    ResponseAction::Isolate,
                    ResponseAction::Revoke,
                ] {
                    assert!(decision.actions.contains(&action), "{input:?}");
                }
                let stops = kind != ViolationKind::CanaryUse;
                assert_eq!(decision.actions.contains(&ResponseAction::Stop), stops);
                assert_eq!(
                    decision.class_response,
                    stops.then(|| ViolationAction::for_class(input.sandbox_class))
                );
                assert!(!decision
                    .actions
                    .contains(&ResponseAction::RequestHostCorroboration));
            }
            SignalClass::Resource { resource } => {
                assert!(
                    !decision.actions.contains(&ResponseAction::Revoke),
                    "{input:?}"
                );
                assert!(!decision.actions.contains(&ResponseAction::Stop));
                assert_eq!(
                    decision
                        .actions
                        .contains(&ResponseAction::DenyNewHighImpact),
                    resource == MonitoredResource::ReleaseBudgetSpentBytes
                );
                assert_eq!(
                    decision.actions.contains(&ResponseAction::Isolate),
                    matches!(
                        resource,
                        MonitoredResource::PacketsPerSecond
                            | MonitoredResource::ConnectionsPerSecond
                    )
                );
            }
        }
    }
}

#[test]
fn every_decision_is_bounded_reasoned_preserving_and_score_free() {
    let policies = policies();
    for input in every_input() {
        let decision = decide(&policies, &input);
        assert!(
            !decision.actions.is_empty() && decision.actions.len() <= ResponseAction::ALL.len()
        );
        assert_eq!(
            decision.rung,
            decision
                .actions
                .iter()
                .map(|action| action.rung())
                .max()
                .unwrap()
        );
        assert_eq!(
            decision.class_response.is_some(),
            decision.actions.contains(&ResponseAction::Stop)
        );
        for class in VolumeClass::ALL {
            assert!(decision.preserves.contains(&Preserved::Volume { class }));
        }
        for kept in [
            Preserved::HostWorkspaces,
            Preserved::Artifacts,
            Preserved::Snapshots,
            Preserved::RootOverlayAndScratch,
        ] {
            assert!(decision.preserves.contains(&kept), "{input:?}");
        }
        let ends_vm = decision.class_response == Some(ViolationAction::Stop);
        assert_eq!(decision.preserves.contains(&Preserved::VmState), !ends_vm);
        assert_eq!(
            ends_vm,
            input.sandbox_class == SandboxClass::Task
                && decision.actions.contains(&ResponseAction::Stop)
        );
        assert_no_score(&serde_json::to_value(&decision).unwrap());
    }
}

#[test]
fn the_escalation_ladder_is_explicit_and_ordered() {
    assert_eq!(
        ESCALATION_LADDER,
        [
            EscalationRung::Notify,
            EscalationRung::DenyNewHighImpact,
            EscalationRung::Isolate,
            EscalationRung::RevokeGrant,
            EscalationRung::Revoke,
            EscalationRung::Stop
        ]
    );
    assert!(ESCALATION_LADDER.windows(2).all(|pair| pair[0] < pair[1]));
    for action in ResponseAction::ALL {
        assert!(ESCALATION_LADDER.contains(&action.rung()));
    }
}

#[test]
fn a_canary_decision_carries_signal_not_proof() {
    let decision = decide(
        &policies(),
        &DecisionInput {
            class: violation(ViolationKind::CanaryUse),
            source: host(HostObserver::Perimeter),
            freshness: Freshness::Fresh,
            sandbox_class: SandboxClass::Service,
        },
    );
    assert_eq!(
        decision.reason,
        DecisionReason::KnownViolation {
            kind: ViolationKind::CanaryUse,
            observer: HostObserver::Perimeter,
            meaning: Some(HitMeaning::SignalNotProof)
        }
    );
    assert!(!decision.actions.contains(&ResponseAction::Stop));
    let json = serde_json::to_value(&decision).unwrap();
    assert_eq!(
        json["reason"]["meaning"],
        serde_json::json!("signal_not_proof")
    );
    // Other violations carry no claim about intent.
    let replay = decide(
        &policies(),
        &DecisionInput {
            class: violation(ViolationKind::CredentialReplay),
            source: host(HostObserver::Broker),
            freshness: Freshness::Fresh,
            sandbox_class: SandboxClass::Task,
        },
    );
    assert!(serde_json::to_value(&replay).unwrap()["reason"]
        .get("meaning")
        .is_none());
}

// ---------------------------------------------------------------------------------------
// Emission bounds (§8.2 "bound ... emission rate")

#[test]
fn the_emission_gate_holds_back_and_counts_past_its_limit() {
    let mut gate = EmissionGate::new(limit(3, MINUTE));
    let start = at(START_SECONDS);
    for _ in 0..3 {
        assert_eq!(gate.admit(start), Ok(()));
    }
    assert_eq!(gate.admit(at(START_SECONDS + 20)), Err(40 * SECOND));
    assert_eq!(gate.admit(at(START_SECONDS + 59)), Err(SECOND));
    assert_eq!(gate.held_back(), 2);
    assert_eq!(gate.admit(at(START_SECONDS + 60)), Ok(()), "a new window");
    assert_eq!(gate.take_held_back(), 2);
    assert_eq!(gate.held_back(), 0);
}
