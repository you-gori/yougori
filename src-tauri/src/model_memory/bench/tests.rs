//! The T12 brief's tests across modules (deterministic replay, the saturation knee, both
//! switch clocks, leak trends, faults in the raw data and denominators, nonce disclosure,
//! the best run as a diagnostic) and a test for each rule of the plan lines they rest on.

use std::collections::BTreeSet;
use std::time::Duration;

use super::corpus::{conversation, Corpus, Fixture, SYSTEM_PROMPT};
use super::fast01::{check_prefill, run_fast01, Fast01Report, Fast01Spec};
use super::faults::{FaultKind, FaultRecord, RecycleCause, ScheduledFault};
use super::load::{
    run_bursts, run_context_growth, run_level, run_shapes, saturation_search, LevelReport,
    LoadSpec, OffsetFault, OutputLength, PromptLength, RunnerFactory, SaturationPolicy,
    SaturationStop, TurnReport,
};
use super::profile::{RunnerMode, RunnerProfile};
use super::resources::{ResourceSnapshot, TrendPolicy};
use super::rng::Variation;
use super::runner::{
    same_response, HostCopy, IdentityBasis, Residency, RetryPolicy, Script, UserScript,
};
use super::switching::{
    run_cell, short_repeated_switch_run, AbaSpec, CellOutcome, CellRefusal, CellReport,
    ReadinessComparison, SwitchCell, SwitchMatrix, TargetState,
};
use super::test_support::{
    clock, execution, label, one_user, plan, profile, release, rules, runner, GENEROUS_NANOS,
    MILLIS,
};
use super::BenchError;
use crate::foundation::evidence::ModeRefusal;
use crate::foundation::ids::{digest, Clock, ExecutionCategory};
use crate::foundation::report::{
    ArrivalMode, AttemptLedger, Baseline, BaselineOutcome, BaselineRole, BenchId, CacheTier,
    ClockReading, ColdProvenance, ComparisonReport, ComparisonSide, ConfigurationField,
    EffectClass, ExperimentDesign, FailureKind, ImprovementClaim, IntervalKind, Label,
    LatencyObjective, LatencySummary, LoadDescription, MatchedConfiguration, Measured,
    ModeFidelity, NoLeakClaim, NonNegative, NonceDisclosure, NoncePlacement, NotMeasuredReason,
    Objective, ObjectivePlan, Outcome, PrefillMode, Provenance, Quantile, ReportError, Resolution,
    RetryTally, RunRecord, RunSubstrate, Scenario, StartTemperature, StateComparison, SwitchMode,
    TracePattern, TrackedResource, VerdictStatus,
};
use crate::model_memory::math::bounds::{ReadinessDispatchSpeedup, SpeedupKind};
use crate::model_memory::math::overlap::NoStall;

use RunnerMode::{FullProcessRestart, RetainedProcess, VerifiedReload, VersionSupportedSleep};

const TOOL: &str = "fast01-tool-run-tests";

fn factory(profile: RunnerProfile, seed: u64) -> RunnerFactory {
    RunnerFactory {
        profile,
        rules: rules(),
        clock: clock(),
        seed,
        execution: execution(),
    }
}

fn corpus() -> Corpus {
    Corpus::fast01().unwrap()
}

fn fixture(id: &str) -> Fixture {
    corpus().get(id).unwrap().clone()
}

fn load_spec(variant: &str, id: &str, tokens: u32, requests: u32) -> LoadSpec {
    LoadSpec {
        variant: variant.into(),
        model: label("model-a"),
        fixture: fixture(id),
        placement: NoncePlacement::PromptPrefix,
        max_output_tokens: tokens,
        requests_per_user: requests,
        repetitions: 1,
        think_nanos: 0,
        deadline_nanos: GENEROUS_NANOS,
        timeout_nanos: GENEROUS_NANOS,
        retry: RetryPolicy::NONE,
        faults: Vec::new(),
    }
}

fn aba_spec(cycles: u32) -> AbaSpec {
    AbaSpec {
        model_a: label("model-a"),
        model_b: label("model-b"),
        fixture_a: fixture("fast01-code-parse-ranges"),
        fixture_b: fixture("fast01-prose-harrow-canal"),
        placement: NoncePlacement::PromptPrefix,
        max_output_tokens: 8,
        controlled_gap_nanos: 250 * MILLIS,
        cycles,
        trials: 1,
        deadline_nanos: GENEROUS_NANOS,
        timeout_nanos: GENEROUS_NANOS,
    }
}

/// Twelve sequences decode together at a small per-sequence cost, so throughput rises
/// nearly linearly up to twelve users and is flat beyond, where requests queue.
fn knee_profile() -> RunnerProfile {
    let mut profile = profile(VerifiedReload);
    profile.serving.max_num_seqs = 12;
    profile.serving.decode_step_per_sequence_nanos = 10_000;
    profile.serving.decode_nanos_per_kibitoken_context = 0;
    profile
}

fn fast01(seed: u64) -> (Corpus, Fast01Report) {
    let corpus = corpus();
    let report = run_fast01(
        &factory(profile(VerifiedReload), seed),
        &corpus,
        &Fast01Spec {
            model: label("model-a"),
            placement: NoncePlacement::PromptPrefix,
            repetitions: 2,
            max_output_tokens: 4,
        },
    )
    .unwrap();
    (corpus, report)
}

fn measured_cell(outcome: CellOutcome) -> Box<super::switching::CellReport> {
    match outcome {
        CellOutcome::Measured(report) => report,
        CellOutcome::NotRun { cell, reason } => panic!("{cell:?} not run: {reason:?}"),
    }
}

#[test]
fn a_run_replays_identically_from_its_seed() {
    let mut varied = profile(VerifiedReload);
    varied.variation = Variation::new(50_000).unwrap();
    let spec = load_spec("replay", TOOL, 8, 3);
    let level = |seed| run_level(&factory(varied.clone(), seed), &spec, 8, 1).unwrap();
    let first = level(42);
    let again = level(42);
    assert_eq!(first, again);
    let json = |report: &LevelReport| serde_json::to_string(report.ledger.records()).unwrap();
    assert_eq!(json(&first), json(&again));
    let other = level(43);
    assert_ne!(
        first.request_latency.samples(),
        other.request_latency.samples()
    );

    let mut sleepy = varied;
    sleepy.mode = VersionSupportedSleep;
    let cell = SwitchCell {
        mode: VersionSupportedSleep,
        state: TargetState::Sleep,
    };
    let run = |seed| run_cell(&factory(sleepy.clone(), seed), cell, &aba_spec(3)).unwrap();
    assert_eq!(run(9), run(9));
    assert_ne!(run(9), run(10));
}

#[test]
fn the_saturation_search_finds_the_knee_of_a_synthetic_curve() {
    let spec = load_spec("knee", TOOL, 16, 4);
    let policy = SaturationPolicy::new(0.05, 0.01, 256).unwrap();
    let report = saturation_search(&factory(knee_profile(), 3), &spec, policy).unwrap();
    let measured: Vec<u32> = report
        .levels
        .iter()
        .map(|level| level.concurrency)
        .collect();
    assert_eq!(&measured[..4], &[1, 8, 32, 64]);
    assert!(
        matches!(
            report.stop,
            SaturationStop::ThroughputPlateau {
                concurrency: 64,
                ..
            }
        ),
        "{:?}",
        report.stop
    );
    assert_eq!(report.knee_concurrency, Some(12), "measured {measured:?}");
    // Every measured level is kept with all its attempts.
    for level in &report.levels {
        assert_eq!(level.ledger.success_rate().unwrap().rate(), 1.0);
        assert_eq!(level.ledger.records().len() as u32, level.concurrency * 4);
    }
}

#[test]
fn the_saturation_search_stops_when_failures_pass_the_threshold() {
    let mut spec = load_spec("knee-timeouts", TOOL, 16, 4);
    spec.timeout_nanos = 450 * MILLIS;
    spec.deadline_nanos = 450 * MILLIS;
    let policy = SaturationPolicy::new(0.05, 0.01, 256).unwrap();
    let report = saturation_search(&factory(knee_profile(), 4), &spec, policy).unwrap();
    match report.stop {
        SaturationStop::FailureThreshold {
            concurrency,
            failure_fraction,
        } => {
            assert_eq!(concurrency, 32);
            assert!(failure_fraction > 0.01);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(report.knee_concurrency, Some(8));
    let failing = report
        .levels
        .iter()
        .find(|level| level.concurrency == 32)
        .unwrap();
    assert!(failing.ledger.failures().get(FailureKind::Timeout) > 0);
    assert!(SaturationPolicy::new(0.0, 0.01, 256).is_err());
    assert!(SaturationPolicy::new(0.05, 1.0, 256).is_err());
    assert!(SaturationPolicy::new(0.05, 0.01, 16).is_err());
}

#[test]
fn both_switch_clocks_decompose_in_every_measured_cell() {
    let matrix = SwitchMatrix::run(&factory(profile(VerifiedReload), 5), &aba_spec(2)).unwrap();
    let mut switches = 0;
    for report in matrix.measured() {
        for leg in [&report.to_b, &report.back_to_a] {
            for record in leg.ledger.records() {
                let ClockReading::Switching(clock) = record.clock_reading().unwrap() else {
                    panic!("not a switch");
                };
                assert_eq!(clock.declared_controlled_gap_nanos, 250 * MILLIS);
                assert_eq!(clock.measured_gap.elapsed_nanos(), 250 * MILLIS);
                assert_eq!(
                    clock.last_output_to_first_output.elapsed_nanos(),
                    clock.measured_gap.elapsed_nanos()
                        + clock.request.time_to_first_token.elapsed_nanos()
                );
                assert_eq!(clock.mode, leg.switch_mode);
                switches += 1;
            }
            assert_eq!(leg.status_at_arrival.len(), leg.ledger.records().len());
        }
    }
    assert_eq!(switches, 7 * 2 * 2);
}

#[test]
fn only_compatible_cells_run_and_the_rest_are_recorded_with_their_reason() {
    let matrix = SwitchMatrix::run(&factory(profile(VerifiedReload), 6), &aba_spec(1)).unwrap();
    assert_eq!(matrix.cells.len(), 20);
    let measured: BTreeSet<SwitchCell> = matrix.measured().map(|report| report.cell).collect();
    let cell = |mode, state| SwitchCell { mode, state };
    assert_eq!(
        measured,
        BTreeSet::from([
            cell(RetainedProcess, TargetState::Retained),
            cell(VersionSupportedSleep, TargetState::Sleep),
            cell(VerifiedReload, TargetState::Warm),
            cell(VerifiedReload, TargetState::Preload),
            cell(FullProcessRestart, TargetState::Warm),
            cell(FullProcessRestart, TargetState::Preload),
            cell(FullProcessRestart, TargetState::Cold),
        ])
    );
    // S7: on vLLM 0.31.0 zero-copy preloaded weights cannot use sleep weight offloading.
    assert!(matches!(
        matrix.outcome(cell(VersionSupportedSleep, TargetState::Preload)),
        Some(CellOutcome::NotRun {
            reason: CellRefusal::Mode(ModeRefusal::DocumentedConflict { .. }),
            ..
        })
    ));
    // S8 names a cold start only as a cold process start.
    assert!(matches!(
        matrix.outcome(cell(VerifiedReload, TargetState::Cold)),
        Some(CellOutcome::NotRun {
            reason: CellRefusal::NoSwitchLabel,
            ..
        })
    ));
    assert!(matches!(
        matrix.outcome(cell(RetainedProcess, TargetState::Sleep)),
        Some(CellOutcome::NotRun {
            reason: CellRefusal::StateNeedsOtherMode,
            ..
        })
    ));
    // The pinned vLLM 0.29.0 has no recorded rule: no sleep and no preload at all.
    let mut pinned = profile(VerifiedReload);
    pinned.release = release("0.29.0");
    let old = SwitchMatrix::run(&factory(pinned, 7), &aba_spec(1)).unwrap();
    for refused in [
        cell(VersionSupportedSleep, TargetState::Sleep),
        cell(VerifiedReload, TargetState::Preload),
    ] {
        assert!(matches!(
            old.outcome(refused),
            Some(CellOutcome::NotRun {
                reason: CellRefusal::Mode(ModeRefusal::UnknownRelease { .. }),
                ..
            })
        ));
    }
    assert!(old
        .measured()
        .any(|report| report.cell == cell(VerifiedReload, TargetState::Warm)));
}

#[test]
fn a_retained_cell_that_does_not_fit_names_its_limiting_resource() {
    let mut small = profile(RetainedProcess);
    small.host.vram_capacity_bytes = 12_000_000_000;
    let outcome = run_cell(
        &factory(small, 8),
        SwitchCell {
            mode: RetainedProcess,
            state: TargetState::Retained,
        },
        &aba_spec(1),
    )
    .unwrap();
    assert!(matches!(
        outcome,
        CellOutcome::NotRun {
            reason: CellRefusal::Capacity {
                resource: "vram",
                ..
            },
            ..
        }
    ));
}

#[test]
fn a_readiness_ratio_is_labelled_and_never_a_cold_load_improvement() {
    let matrix = SwitchMatrix::run(&factory(profile(VerifiedReload), 9), &aba_spec(2)).unwrap();
    let find = |mode, state| {
        matrix
            .measured()
            .find(|report| report.cell == SwitchCell { mode, state })
            .unwrap()
    };
    let cold = find(FullProcessRestart, TargetState::Cold);
    let retained = find(RetainedProcess, TargetState::Retained);
    let comparison = SwitchMatrix::readiness(cold, retained).unwrap();
    assert_eq!(comparison.states, StateComparison::WarmVersusCold);
    assert_eq!(comparison.kind(), SpeedupKind::ReadinessDispatch);
    assert!(comparison.speedup.ratio() > 100.0);
    // §2.2: the retained memory and preparation that enable dispatch come with it.
    assert_eq!(
        comparison.speedup.retained_memory_bytes(),
        retained.retained.vram_bytes
    );
    assert!(comparison.speedup.retained_memory_bytes() >= 6_000_000_000);
    assert!(comparison.speedup.preparation_seconds() > 0.0);
    assert_eq!(
        comparison.cold_load_improvement(),
        Err(BenchError::NotColdLoad)
    );
    assert_eq!(
        StateComparison::ColdLoad.check(StartTemperature::Hot, StartTemperature::Cold),
        Err(ReportError::WarmVersusColdMislabel)
    );
    assert_eq!(
        SwitchMatrix::readiness(cold, cold)
            .unwrap()
            .cold_load_improvement(),
        Ok(1.0)
    );
    // A hot candidate against a warm baseline has no CORE-08 state label.
    let ordinary = matrix.ordinary_workflow_baseline().unwrap();
    assert_eq!(
        ordinary.cell,
        SwitchCell {
            mode: FullProcessRestart,
            state: TargetState::Warm
        }
    );
    assert!(SwitchMatrix::readiness(ordinary, retained).is_err());
    assert_eq!(
        matrix
            .strongest_compatible_baseline()
            .map(|report| report.cell),
        Some(SwitchCell {
            mode: RetainedProcess,
            state: TargetState::Retained
        })
    );
}

#[test]
fn the_worked_readiness_numbers_hold() {
    // §2.2: a hypothetical 40 s recreation against a 40 ms dispatch is 1000× readiness
    // and dispatch, not generation throughput; at 95% of a workflow it bounds the whole
    // at 19.63×.
    let comparison = ReadinessComparison {
        baseline: SwitchCell {
            mode: FullProcessRestart,
            state: TargetState::Cold,
        },
        candidate: SwitchCell {
            mode: RetainedProcess,
            state: TargetState::Retained,
        },
        states: StateComparison::WarmVersusCold,
        speedup: ReadinessDispatchSpeedup::new(40.0, 0.04, 14_000_000_000, 120.0).unwrap(),
    };
    assert!((comparison.speedup.ratio() - 1000.0).abs() < 1e-9);
    assert_eq!(
        comparison.kind().label(),
        "readiness/dispatch speedup, not generation throughput"
    );
    let workflow = comparison.workflow_bound(0.95).unwrap();
    assert_eq!((workflow.ratio() * 100.0).round() / 100.0, 19.63);
    assert_eq!(
        comparison.cold_load_improvement(),
        Err(BenchError::NotColdLoad)
    );
}

fn leak_policy() -> TrendPolicy {
    TrendPolicy::new(
        4,
        ResourceSnapshot {
            vram_bytes: 1 << 20,
            pinned_host_bytes: 1 << 20,
            rss_bytes: 4 << 20,
            ..ResourceSnapshot::ZERO
        },
    )
    .unwrap()
}

const SLEEP_CELL: SwitchCell = SwitchCell {
    mode: VersionSupportedSleep,
    state: TargetState::Sleep,
};

#[test]
fn a_leaky_fake_is_flagged_and_a_clean_one_is_not() {
    let mut clean = profile(VersionSupportedSleep);
    clean.variation = Variation::new(20_000).unwrap();
    let mut leaky = clean.clone();
    leaky.leak_per_switch = ResourceSnapshot {
        pinned_host_bytes: 64 << 20,
        file_descriptors: 2,
        allocation_references: 1,
        ..ResourceSnapshot::ZERO
    };
    let run = |profile| {
        short_repeated_switch_run(
            &factory(profile, 10),
            SLEEP_CELL,
            &aba_spec(10),
            leak_policy(),
            None,
        )
        .unwrap()
    };
    let clean_run = run(clean);
    let leaky_run = run(leaky);
    assert_eq!(clean_run.switches, 20);
    assert_eq!(clean_run.samples.len(), 10);
    // Every attempt stays in the raw data (S8), the opening serving of A included.
    assert_eq!(clean_run.a_serving.records().len(), 1);
    assert_eq!(clean_run.to_b.records().len(), 10);
    assert_eq!(clean_run.back_to_a.records().len(), 10);
    assert!(clean_run.leaking().is_empty());
    assert_eq!(
        leaky_run.leaking(),
        BTreeSet::from([
            TrackedResource::PinnedHostMemory,
            TrackedResource::FileDescriptors,
            TrackedResource::PhysicalAllocationReferences,
        ])
    );
    // A short run shows trends; it never backs a no-leak claim (S7, BENCH-07).
    for report in [&clean_run, &leaky_run] {
        assert!(matches!(
            report.claim_no_leak(),
            Err(BenchError::NoLeakClaimFromFake { switches: 20, .. })
        ));
        assert_eq!(
            NoLeakClaim::new(label("version-supported-sleep"), report.soak_evidence()),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
    }
}

#[test]
fn even_days_of_simulated_time_on_a_fake_back_no_no_leak_claim() {
    let mut spec = aba_spec(2);
    spec.controlled_gap_nanos = 86_400 * 1_000 * MILLIS;
    spec.timeout_nanos = u64::MAX / 4;
    spec.deadline_nanos = u64::MAX / 4;
    let report = short_repeated_switch_run(
        &factory(profile(VersionSupportedSleep), 11),
        SLEEP_CELL,
        &spec,
        leak_policy(),
        None,
    )
    .unwrap();
    assert!(report.simulated_nanos >= 4 * 86_400 * 1_000 * MILLIS);
    assert!(matches!(
        report.claim_no_leak(),
        Err(BenchError::NoLeakClaimFromFake { .. })
    ));
    // CORE-08 refuses it as well: the soak evidence names the fake substrate.
    assert_eq!(
        NoLeakClaim::new(label("version-supported-sleep"), report.soak_evidence()),
        Err(ReportError::FakeSubstrateIsNotEvidence)
    );
}

#[test]
fn a_recycle_is_a_visible_recovery_event_and_does_not_hide_a_leak() {
    let mut leaky = profile(VersionSupportedSleep);
    leaky.leak_per_switch = ResourceSnapshot {
        pinned_host_bytes: 64 << 20,
        ..ResourceSnapshot::ZERO
    };
    let report = short_repeated_switch_run(
        &factory(leaky, 12),
        SLEEP_CELL,
        &aba_spec(15),
        leak_policy(),
        Some(10),
    )
    .unwrap();
    assert!(report.recycles.len() >= 2);
    for recycle in &report.recycles {
        assert_eq!(recycle.cause, RecycleCause::Scheduled);
        assert!(recycle.latency_nanos > 0);
        assert_eq!(recycle.cost.downtime_nanos, recycle.latency_nanos);
        assert!(recycle.cost.reloaded_bytes >= 14_000_000_000);
        // The recycle flattened the graph ...
        assert!(recycle.before.pinned_host_bytes > recycle.after.pinned_host_bytes);
        assert!(recycle.record.is_success());
        assert_eq!(
            recycle
                .record
                .interval(IntervalKind::Recycle)
                .unwrap()
                .elapsed_nanos(),
            recycle.latency_nanos
        );
    }
    // ... yet each segment between recycles still shows the rise.
    let segments: BTreeSet<u32> = report
        .trends
        .iter()
        .filter(|line| line.leaking && line.resource == TrackedResource::PinnedHostMemory)
        .map(|line| line.segment)
        .collect();
    assert!(segments.len() >= 2, "{segments:?}");
    assert_eq!(
        report.soak_evidence().recycles,
        report.recycles.len() as u64
    );
    // Every switch after a recycle is still a wake: the recycle restored the setup.
    assert!(report
        .to_b
        .records()
        .iter()
        .all(|record| record.is_success()));
}

fn ledgers_by_variant(records: &[RunRecord]) -> Vec<AttemptLedger> {
    let mut variants: Vec<Label> = Vec::new();
    for record in records {
        if !variants.contains(&record.attempt.variant) {
            variants.push(record.attempt.variant.clone());
        }
    }
    variants
        .iter()
        .map(|variant| {
            AttemptLedger::from_records(
                records
                    .iter()
                    .filter(|record| &record.attempt.variant == variant)
                    .cloned(),
            )
            .unwrap()
        })
        .collect()
}

fn assert_in_raw_data(fault: &FaultRecord, ledgers: &[AttemptLedger]) {
    assert!(
        fault.triggered_at.is_some(),
        "{:?} never took effect",
        fault.kind
    );
    assert!(
        !fault.affected.is_empty(),
        "{:?} ended no attempt",
        fault.kind
    );
    let class = fault.kind.classification();
    for operation in &fault.affected {
        let (ledger, record) = ledgers
            .iter()
            .find_map(|ledger| {
                ledger
                    .records()
                    .iter()
                    .find(|record| &record.attempt.operation == operation)
                    .map(|record| (ledger, record))
            })
            .unwrap_or_else(|| panic!("{operation} is not in the raw data"));
        let Outcome::Failed {
            failure,
            component,
            code,
        } = &record.outcome
        else {
            panic!("{operation} succeeded");
        };
        assert_eq!(component.as_str(), class.component);
        assert_eq!(code.as_str(), class.code);
        let expected = match fault.kind {
            FaultKind::StalledProvider { .. } => {
                vec![FailureKind::Timeout, FailureKind::DeadlineFailure]
            }
            _ => vec![class.failure],
        };
        assert!(expected.contains(failure), "{failure:?}");
        assert!(record.is_initial());
        assert!(ledger.failures().get(*failure) >= 1);
    }
}

#[test]
fn every_fault_appears_in_the_raw_data_and_the_denominators() {
    // Load faults and a lost completion, on A/B/A switches with verified reloads.
    let mut switching = runner(profile(VerifiedReload), 22);
    switching
        .start(&label("model-a"), BenchId::Bench02)
        .unwrap();
    switching.warm_host_copy(&label("model-b")).unwrap();
    let now = switching.clock().now();
    for kind in [
        FaultKind::LostEvent,
        FaultKind::DiskFull,
        FaultKind::OutOfMemory,
    ] {
        switching.inject(ScheduledFault { at: now, kind }).unwrap();
    }
    let mut requests = vec![plan("faults-a", "model-a", 1, 4)];
    for (index, (variant, model)) in [
        ("faults-to-b", "model-b"),
        ("faults-back-to-a", "model-a"),
        ("faults-to-b", "model-b"),
        ("faults-back-to-a", "model-a"),
    ]
    .into_iter()
    .enumerate()
    {
        let mut next = plan(variant, model, 10 + index as u64, 4);
        next.switch_from_previous = true;
        next.gap_before_nanos = 100 * MILLIS;
        requests.push(next);
    }
    for request in &mut requests {
        request.timeout_nanos = 30_000 * MILLIS;
    }
    let script = one_user(&switching, BenchId::Bench02, requests);
    let switched = switching.serve(&script).unwrap();

    // A crash and a stalled provider under serving load.
    let mut serving = runner(profile(VerifiedReload), 23);
    serving.start(&label("model-a"), BenchId::Bench01).unwrap();
    let now = serving.clock().now();
    let at = |millis| now.checked_add(Duration::from_millis(millis)).unwrap();
    serving
        .inject(ScheduledFault {
            at: at(200),
            kind: FaultKind::Crash,
        })
        .unwrap();
    serving
        .inject(ScheduledFault {
            at: at(4_000),
            kind: FaultKind::StalledProvider {
                stall_nanos: 60_000 * MILLIS,
            },
        })
        .unwrap();
    let users = (0..3)
        .map(|user| UserScript {
            start_at: now,
            requests: (0..3)
                .map(|index| {
                    let mut request =
                        plan("faults-serving", "model-a", 100 + user * 10 + index, 40);
                    request.gap_before_nanos = if index == 0 { 0 } else { 3_000 * MILLIS };
                    request.timeout_nanos = 30_000 * MILLIS;
                    request.deadline_nanos = 30_000 * MILLIS;
                    request
                })
                .collect(),
            retry: RetryPolicy::NONE,
        })
        .collect();
    let script = Script {
        bench: BenchId::Bench01,
        load: LoadDescription {
            concurrent_requests: 3,
            arrival: ArrivalMode::Sequential,
        },
        users,
        recycle_after_switches: None,
    };
    let served = serving.serve(&script).unwrap();

    let ledgers: Vec<AttemptLedger> = ledgers_by_variant(&switched.records)
        .into_iter()
        .chain(ledgers_by_variant(&served.records))
        .collect();
    let faults: Vec<&FaultRecord> = switching
        .fault_log()
        .iter()
        .chain(serving.fault_log())
        .collect();
    for fault in &faults {
        assert_in_raw_data(fault, &ledgers);
    }
    let kinds: BTreeSet<&str> = faults.iter().map(|fault| fault.kind.slug()).collect();
    assert_eq!(
        kinds,
        BTreeSet::from([
            "crash",
            "disk-full",
            "out-of-memory",
            "lost-event",
            "stalled"
        ])
    );
    // Every initial attempt is in its ledger's denominator, failures included.
    let mut attempts = 0;
    for ledger in &ledgers {
        let rate = ledger.success_rate().unwrap();
        assert_eq!(rate.attempts(), ledger.initial_attempts().count() as u64);
        assert_eq!(
            rate.successes() + ledger.failures().total(),
            rate.attempts()
        );
        attempts += rate.attempts();
    }
    assert_eq!(attempts, 5 + 9);
    // The crash recycled the runner: a visible recovery event with a latency and a cost.
    let recycle = &served.recycles[0];
    assert_eq!(recycle.cause, RecycleCause::Crash);
    assert_eq!(recycle.cost.failed_attempts, 3);
    assert!(recycle.latency_nanos >= 2_000 * MILLIS);
    assert_eq!(recycle.cost.reloaded_bytes, 8_000_000_000);
    assert!(recycle.record.is_success());
    assert_eq!(serving.fault_log()[0].recycle, Some(0));
}

#[test]
fn a_successful_retry_is_a_second_result() {
    let mut spec = load_spec("retries", TOOL, 40, 1);
    spec.retry = RetryPolicy {
        max_retries: 2,
        backoff_nanos: 3_000 * MILLIS,
    };
    spec.faults = vec![OffsetFault {
        after_start_nanos: 200 * MILLIS,
        kind: FaultKind::Crash,
    }];
    let level = run_level(&factory(profile(VerifiedReload), 18), &spec, 2, 1).unwrap();
    let ledger = &level.ledger;
    assert_eq!(ledger.records().len(), 4);
    let rate = ledger.success_rate().unwrap();
    assert_eq!((rate.successes(), rate.attempts()), (0, 2));
    assert_eq!(ledger.failures().get(FailureKind::EarlyTermination), 2);
    assert_eq!(
        ledger.retry_tally(),
        RetryTally {
            retries: 2,
            successful_retries: 2,
            recovered_first_attempts: 2,
        }
    );
    assert_eq!(level.recycles.len(), 1);
}

#[test]
fn nonce_disclosure_is_recorded_and_the_task_is_unchanged() {
    let (corpus, report) = fast01(12);
    let mut values = BTreeSet::new();
    for record in report.fresh.records() {
        assert!(record.is_success());
        let workload = record.workload.value().unwrap();
        match workload.cold_test_nonce {
            NonceDisclosure::Disclosed {
                value,
                placement,
                alters_task_semantics,
            } => {
                assert_eq!(placement, NoncePlacement::PromptPrefix);
                assert!(!alters_task_semantics);
                assert!(values.insert(value), "nonce {value} repeated");
            }
            NonceDisclosure::NotUsed => panic!("an undisclosed fresh prefill"),
        }
        assert!(workload.paired);
        let fixture = corpus.get(workload.fixture.id.as_str()).unwrap();
        assert_eq!(workload.fixture, fixture.reference());
    }
    assert_eq!(values.len(), corpus.fixtures().len() * 2);
    for record in report.warm.records() {
        assert_eq!(
            record.workload.value().unwrap().cold_test_nonce,
            NonceDisclosure::NotUsed
        );
    }
    // A nonce that altered a paired task's meaning is refused by the record schema.
    let mut altered = report.fresh.records()[0].clone();
    if let Measured::Measured { value } = &mut altered.workload {
        value.cold_test_nonce = NonceDisclosure::Disclosed {
            value: 1,
            placement: NoncePlacement::PromptPrefix,
            alters_task_semantics: true,
        };
    }
    assert_eq!(altered.validate(), Err(ReportError::NonceAltersPairedTask));
}

#[test]
fn fresh_prefill_and_warm_prefix_tests_are_kept_apart() {
    let (_, report) = fast01(13);
    let prefill = |record: &RunRecord| record.state.value().unwrap().prefill;
    assert!(report
        .fresh
        .records()
        .iter()
        .all(|record| prefill(record) == PrefillMode::Fresh));
    assert!(report
        .warm
        .records()
        .iter()
        .all(|record| prefill(record) == PrefillMode::WarmPrefix && record.is_success()));
    assert_eq!(report.priming.records().len(), 1);
    assert_eq!(prefill(&report.priming.records()[0]), PrefillMode::Fresh);
    let mut fresh = report.fresh.clone();
    assert_eq!(
        fresh.add(report.warm.records()[0].clone()),
        Err(ReportError::MixedCases)
    );
    assert_eq!(
        check_prefill(&report.warm, PrefillMode::Fresh),
        Err(BenchError::MixedPrefillModes)
    );
    // Reusing the shared prefix makes warm first tokens faster than a fresh prefill of a
    // document of the same length.
    let ttft = |record: &RunRecord| {
        record
            .interval(IntervalKind::TimeToFirstToken)
            .unwrap()
            .elapsed_nanos()
    };
    let fresh_long = report
        .fresh
        .records()
        .iter()
        .filter(|record| {
            record.workload.value().unwrap().fixture.id.as_str() == "fast01-long-context-8192"
        })
        .map(ttft)
        .min()
        .unwrap();
    let warm_slowest = report.warm.records().iter().map(ttft).max().unwrap();
    assert!(warm_slowest < fresh_long);
}

#[test]
fn the_best_run_is_only_a_diagnostic() {
    let mut varied = profile(VerifiedReload);
    varied.variation = Variation::new(100_000).unwrap();
    let mut spec = load_spec("best-run", TOOL, 8, 4);
    spec.repetitions = 3;
    let level = run_level(&factory(varied, 14), &spec, 8, 1).unwrap();
    let summary = &level.time_to_first_token;
    let fastest = summary
        .samples()
        .iter()
        .map(|sample| sample.nanos)
        .min()
        .unwrap();
    assert_eq!(
        summary.fastest_successful_nanos_diagnostic(),
        Measured::measured(fastest)
    );
    assert_eq!(level.claim_best_run(), Err(BenchError::BestRunIsDiagnostic));
    // A claim is a resolved percentile, carried with the success rate and deadline
    // failures of every attempt; one level's p99 is not resolved.
    let median = level
        .claim(IntervalKind::TimeToFirstToken, Quantile::P50)
        .unwrap();
    assert_eq!(median.success_rate().attempts(), 96);
    assert_eq!(median.deadline_failures(), 0);
    assert!(median.value_nanos() > fastest as f64);
    assert!(matches!(
        level.claim(IntervalKind::TimeToFirstToken, Quantile::P99),
        Err(BenchError::Report(ReportError::LowResolution { .. }))
    ));
}

#[test]
fn energy_and_power_are_not_measured_and_the_serving_label_is_kept() {
    let level = run_level(
        &factory(profile(VerifiedReload), 15),
        &load_spec("labels", TOOL, 4, 2),
        2,
        1,
    )
    .unwrap();
    for record in level.ledger.records().iter().chain(&level.starts) {
        assert_eq!(
            record.measurements.energy_joules.reason(),
            Some(NotMeasuredReason::InstrumentUnavailable)
        );
        assert_eq!(
            record.host.gpu_power_clock.reason(),
            Some(NotMeasuredReason::InstrumentUnavailable)
        );
        assert_eq!(
            record.host.power_source.reason(),
            Some(NotMeasuredReason::InstrumentUnavailable)
        );
        assert_eq!(
            record.measurements.speculative.reason(),
            Some(NotMeasuredReason::NotApplicable)
        );
        assert_eq!(
            record.price.reason(),
            Some(NotMeasuredReason::NotApplicable)
        );
        assert_eq!(record.substrate, RunSubstrate::FakeTimeControlled);
        assert_eq!(
            record.execution_category,
            ExecutionCategory::SharedKernelGpuRuntime
        );
        assert_eq!(
            record.category_label(),
            "GPU runtime (shared kernel), not a sandbox"
        );
    }
}

#[test]
fn records_carry_fixture_identities_never_prompts() {
    let (_, report) = fast01(16);
    let json = serde_json::to_string(report.fresh.records()).unwrap()
        + &serde_json::to_string(report.warm.records()).unwrap();
    for text in [
        "cold-test nonce",
        "parse_ranges",
        "Harrow",
        "north archive",
        SYSTEM_PROMPT,
    ] {
        assert!(!json.contains(text), "{text}");
    }
}

#[test]
fn a_cold_state_comes_from_a_fresh_fake_never_from_a_flushed_cache() {
    let mut used = runner(profile(FullProcessRestart), 17);
    used.start(&label("model-a"), BenchId::Bench02).unwrap();
    used.require_cold(&label("model-b")).unwrap();
    used.warm_host_copy(&label("model-b")).unwrap();
    assert_eq!(
        used.require_cold(&label("model-b")),
        Err(BenchError::ColdStateUnavailable {
            model: "model-b".into()
        })
    );
    let cell = SwitchCell {
        mode: FullProcessRestart,
        state: TargetState::Cold,
    };
    let report = measured_cell(
        run_cell(
            &factory(profile(FullProcessRestart), 18),
            cell,
            &aba_spec(3),
        )
        .unwrap(),
    );
    assert_eq!(report.starts.len(), 3);
    assert_eq!(report.to_b.switch_mode, SwitchMode::ColdProcessStart);
    for record in report.to_b.ledger.records() {
        let state = record.state.value().unwrap();
        assert_eq!(state.cold_provenance, ColdProvenance::DisposableEnvironment);
        assert_eq!(state.cache_tier, CacheTier::NoReusableState);
    }
    // The return finds A in the page cache: a warm reload, never a cold start.
    assert_eq!(report.back_to_a.switch_mode, SwitchMode::WarmReload);
    assert!(short_repeated_switch_run(
        &factory(profile(FullProcessRestart), 19),
        cell,
        &aba_spec(2),
        leak_policy(),
        None
    )
    .is_err());
}

#[test]
fn bench_01_covers_prompt_and_output_lengths_context_growth_and_bursts() {
    let factory = factory(profile(VerifiedReload), 20);
    let shapes = run_shapes(
        &factory,
        &load_spec("shapes", TOOL, 8, 2),
        &fixture(TOOL),
        &fixture("fast01-long-context-8192"),
        8,
        64,
    )
    .unwrap();
    assert_eq!(shapes.len(), 4);
    let p50 = |summary: &LatencySummary| {
        *summary
            .percentile(Quantile::P50)
            .unwrap()
            .value_nanos
            .value()
            .unwrap()
    };
    let level = |prompt, output, concurrency| {
        shapes
            .iter()
            .find(|shape| shape.prompt == prompt && shape.output == output)
            .unwrap()
            .levels
            .iter()
            .find(|level| level.concurrency == concurrency)
            .unwrap()
    };
    let short = level(PromptLength::Short, OutputLength::Short, 1);
    assert!(
        p50(&level(PromptLength::Long, OutputLength::Short, 1).time_to_first_token)
            > p50(&short.time_to_first_token)
    );
    assert!(
        p50(&level(PromptLength::Short, OutputLength::Long, 1).request_latency)
            > p50(&short.request_latency)
    );
    // Long prompts at 32 users fill KV memory: requests wait for admission.
    let crowded = level(PromptLength::Long, OutputLength::Long, 32);
    assert!(p50(&crowded.queue_wait) > 0.0);
    assert!(crowded.resource_peak.vram_bytes <= 24_000_000_000);
    assert_eq!(crowded.ledger.success_rate().unwrap().rate(), 1.0);

    // Context growth: every turn carries the transcript so far.
    let turns = conversation(6, 40).unwrap();
    let (ledger, reports) = run_context_growth(
        &factory,
        &label("model-a"),
        &turns,
        8,
        NoncePlacement::PromptPrefix,
    )
    .unwrap();
    assert_eq!(ledger.success_rate().unwrap().rate(), 1.0);
    let ttft = |turn: &TurnReport| {
        turn.record
            .interval(IntervalKind::TimeToFirstToken)
            .unwrap()
            .elapsed_nanos()
    };
    let peak = |turn: &TurnReport| {
        *turn
            .record
            .measurements
            .peak_gpu_memory_bytes
            .value()
            .unwrap()
    };
    for pair in reports.windows(2) {
        assert!(pair[1].input_tokens > pair[0].input_tokens);
        assert!(ttft(&pair[1]) > ttft(&pair[0]));
        assert!(peak(&pair[1]) > peak(&pair[0]));
    }

    // Bursts: one burst of 100 cannot resolve a p99; independent bursts give a spread.
    let spec = load_spec("bursts", TOOL, 8, 1);
    let one = run_bursts(&factory, &spec, 100, 1, 0).unwrap();
    let p99 = one.time_to_first_token.percentile(Quantile::P99).unwrap();
    assert!(matches!(p99.resolution, Resolution::LowResolution { .. }));
    assert_eq!(
        p99.per_burst_spread.reason(),
        Some(NotMeasuredReason::SingleBurst)
    );
    let three = run_bursts(&factory, &spec, 30, 3, 60_000 * MILLIS).unwrap();
    let median = three.time_to_first_token.percentile(Quantile::P50).unwrap();
    assert_eq!(median.resolution, Resolution::Resolved);
    assert!(median.per_burst_spread.is_measured());
    assert_eq!(
        three
            .ledger
            .records()
            .iter()
            .map(|record| record.attempt.burst)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([0, 1, 2])
    );
}

#[test]
fn temperature_zero_alone_does_not_establish_token_identity() {
    let expected = digest("yougori/test/v1", &[b"a"]);
    assert_eq!(
        same_response(&expected, &expected, IdentityBasis::TemperatureZeroOnly),
        Err(BenchError::TokenIdentityNotEstablished)
    );
    assert_eq!(
        same_response(
            &expected,
            &expected,
            IdentityBasis::DeclaredDeterministicFake
        ),
        Ok(true)
    );
    let mut loose = profile(VersionSupportedSleep);
    loose.deterministic_outputs = false;
    let report = measured_cell(run_cell(&factory(loose, 21), SLEEP_CELL, &aba_spec(3)).unwrap());
    for leg in [&report.to_b, &report.back_to_a] {
        assert_eq!(leg.canaries.passed, 0);
        assert_eq!(leg.canaries.not_comparable, 3);
        assert!(leg.ledger.records().iter().all(|record| {
            record.workload.value().unwrap().sampling.temperature == NonNegative::ZERO
        }));
    }
}

#[test]
fn state_corruption_canaries_catch_a_corrupting_fake() {
    let mut corrupting = profile(VersionSupportedSleep);
    corrupting.corrupt_state_after_switches = Some(3);
    let report =
        measured_cell(run_cell(&factory(corrupting, 22), SLEEP_CELL, &aba_spec(3)).unwrap());
    let passed = report.to_b.canaries.passed + report.back_to_a.canaries.passed;
    let failed = report.to_b.canaries.failed + report.back_to_a.canaries.failed;
    assert_eq!((passed, failed), (2, 4));
    let invalid = report
        .to_b
        .ledger
        .failures()
        .get(FailureKind::InvalidResult)
        + report
            .back_to_a
            .ledger
            .failures()
            .get(FailureKind::InvalidResult);
    assert_eq!(invalid, 4);
}

#[test]
fn execute_while_load_follows_the_gpu_2_6_recurrence() {
    let eager = |overlap: bool| {
        let mut profile = profile(VerifiedReload);
        profile.execute_while_load = overlap;
        profile.serving.decode_nanos_per_kibitoken_context = 0;
        for model in &mut profile.models {
            model.timings.graph_capture_nanos = 0;
            model.cuda_graphs = 0;
        }
        profile
    };
    let switch_to_b = |profile: RunnerProfile| {
        let mut runner = runner(profile, 23);
        runner.start(&label("model-a"), BenchId::Bench02).unwrap();
        runner.warm_host_copy(&label("model-b")).unwrap();
        let mut to_b = plan("ewl-to-b", "model-b", 2, 4);
        to_b.switch_from_previous = true;
        let script = one_user(
            &runner,
            BenchId::Bench02,
            vec![plan("ewl-a", "model-a", 1, 4), to_b],
        );
        let out = runner.serve(&script).unwrap();
        let record = out.records[1].clone();
        let status = out.statuses[&record.attempt.operation];
        (record, status)
    };
    let (record, status) = switch_to_b(eager(true));
    let overlap = status.overlap.unwrap();
    let step = 10_200_000 + record.workload.value().unwrap().input_tokens * 20_000;
    // Four groups usable at 75, 150, 225 and 300 ms of a 300 ms load: execution waits for
    // each, and the last finishes a quarter step after the load ends.
    let expected = 300 * MILLIS + step / 4;
    assert!(
        overlap
            .first_token_after_load_start_nanos
            .abs_diff(expected)
            <= 1
    );
    assert!(matches!(overlap.no_stall, NoStall::Stalls { group: 2, .. }));
    let ttft = |record: &RunRecord| {
        record
            .interval(IntervalKind::TimeToFirstToken)
            .unwrap()
            .elapsed_nanos()
    };
    assert!(ttft(&record).abs_diff(50 * MILLIS + expected) <= 1);
    // Without the overlap the step waits for every weight.
    let (sequential, _) = switch_to_b(eager(false));
    assert_eq!(ttft(&sequential), 50 * MILLIS + 300 * MILLIS + step);
    assert!(ttft(&record) < ttft(&sequential));
}

#[test]
fn bench_02_reports_weight_kv_and_graph_status() {
    let sleep = measured_cell(
        run_cell(
            &factory(profile(VersionSupportedSleep), 25),
            SLEEP_CELL,
            &aba_spec(2),
        )
        .unwrap(),
    );
    for status in &sleep.to_b.status_at_arrival {
        assert_eq!(status.residency, Residency::Asleep);
        assert!(!status.kv_allocated && !status.graphs_captured);
    }
    for status in &sleep.to_b.status_at_first_token {
        assert_eq!(status.residency, Residency::Resident);
        assert!(status.kv_allocated && status.graphs_captured);
    }
    let warm = measured_cell(
        run_cell(
            &factory(profile(VerifiedReload), 26),
            SwitchCell {
                mode: VerifiedReload,
                state: TargetState::Warm,
            },
            &aba_spec(2),
        )
        .unwrap(),
    );
    assert!(warm.to_b.status_at_arrival.iter().all(|status| {
        status.residency == Residency::NotLoaded && status.host_copy == HostCopy::PageCache
    }));
    assert_eq!(warm.to_b.status_at_first_token.len(), 2);
    assert_eq!(warm.to_b.canaries.passed, 2);
}

#[test]
fn fast01_records_carry_every_field_a_fake_can_measure() {
    let (_, report) = fast01(24);
    for record in report.fresh.records() {
        // Image and model digests.
        assert_eq!(record.launch.image, record.build.runner_build);
        assert!(record.model.is_measured());
        // Cache tier and prefill, first token, decode per user and aggregate.
        let state = record.state.value().unwrap();
        assert_eq!(state.cache_tier, CacheTier::GpuMemory);
        assert_eq!(state.prefill, PrefillMode::Fresh);
        let ClockReading::Serving(clock) = record.clock_reading().unwrap() else {
            panic!("not a serving reading");
        };
        assert!(clock.decode_tokens_per_second.is_measured());
        assert!(record
            .measurements
            .aggregate_decode_tokens_per_second
            .is_measured());
        assert!(record.measurements.prefill_tokens_per_second.is_measured());
        // Resource peaks; speculative decoding and energy are not measured by a fake.
        assert!(record.measurements.peak_gpu_memory_bytes.is_measured());
        assert!(record
            .measurements
            .peak_pinned_host_memory_bytes
            .is_measured());
        assert_eq!(
            record.measurements.speculative.reason(),
            Some(NotMeasuredReason::NotApplicable)
        );
        assert_eq!(
            record.measurements.energy_joules.reason(),
            Some(NotMeasuredReason::InstrumentUnavailable)
        );
    }
}

#[test]
fn faulty_runs_replay_identically_from_their_seed() {
    let mut spec = load_spec("faulty-replay", TOOL, 40, 3);
    spec.think_nanos = 3_000 * MILLIS;
    spec.timeout_nanos = 30_000 * MILLIS;
    spec.faults = vec![
        OffsetFault {
            after_start_nanos: 200 * MILLIS,
            kind: FaultKind::Crash,
        },
        OffsetFault {
            after_start_nanos: 4_000 * MILLIS,
            kind: FaultKind::StalledProvider {
                stall_nanos: 60_000 * MILLIS,
            },
        },
    ];
    let mut varied = profile(VerifiedReload);
    varied.variation = Variation::new(30_000).unwrap();
    let level = |seed| run_level(&factory(varied.clone(), seed), &spec, 3, 1).unwrap();
    let first = level(27);
    assert_eq!(first, level(27));
    assert!(first.ledger.failures().get(FailureKind::EarlyTermination) > 0);
    assert!(first.ledger.failures().get(FailureKind::Timeout) > 0);
    assert_eq!(first.recycles.len(), 1);
}

#[test]
fn switch_overhead_is_the_extra_latency_over_an_already_ready_execution() {
    // GPU §2.1: "Switch overhead: Extra latency versus an already-ready execution of the
    // same request". With fixed parameters it is exactly what a switch adds before the
    // first step: parking the serving model and making the other one ready.
    let matrix = SwitchMatrix::run(&factory(profile(VerifiedReload), 29), &aba_spec(2)).unwrap();
    let expected = |cell: SwitchCell| {
        let (to_b, back) = match (cell.mode, cell.state) {
            // Hot dispatch to a resident process.
            (RetainedProcess, _) => (2, 2),
            // The serving model sleeps, the other wakes.
            (VersionSupportedSleep, _) => (350 + 250, 250 + 350),
            // Unload, verified load from the host copy, graph capture.
            (VerifiedReload, _) => (50 + 300 + 250, 40 + 400 + 300),
            // Exit, engine startup, load from storage or the host copy, graph capture.
            (FullProcessRestart, TargetState::Cold) => {
                (100 + 2_000 + 1_000 + 250, 100 + 2_000 + 400 + 300)
            }
            (FullProcessRestart, _) => (100 + 2_000 + 300 + 250, 100 + 2_000 + 400 + 300),
        };
        (to_b * MILLIS, back * MILLIS)
    };
    let mut cells = 0;
    for report in matrix.measured() {
        let (to_b, back) = expected(report.cell);
        for (leg, nanos) in [(&report.to_b, to_b), (&report.back_to_a, back)] {
            assert_eq!(leg.switch_overheads.len(), 2, "{:?}", report.cell);
            for overhead in &leg.switch_overheads {
                assert_eq!(overhead.overhead_nanos, nanos as i64, "{:?}", report.cell);
                assert_eq!(overhead.switched_nanos - overhead.ready_nanos, nanos);
            }
            // The ready executions are hot serving attempts of the same fixture.
            let fixture = &leg.ledger.records()[0].workload.value().unwrap().fixture;
            assert_eq!(leg.ready.records().len(), 2);
            for record in leg.ready.records() {
                assert!(record.is_success());
                assert_eq!(record.scenario, Scenario::Serving);
                assert_eq!(
                    record.state.value().unwrap().temperature,
                    StartTemperature::Hot
                );
                assert_eq!(&record.workload.value().unwrap().fixture, fixture);
            }
        }
        cells += 1;
    }
    assert_eq!(cells, 7);
}

/// One side of a CORE-08 comparison: the switches to B of a BENCH-02 cell.
fn side(name: &str, report: &CellReport, objective: LatencyObjective) -> ComparisonSide {
    let records = report.to_b.ledger.records();
    ComparisonSide {
        name: label(name),
        provenance: Provenance::of_records(records).unwrap(),
        configuration: MatchedConfiguration::from_record(&records[0]).unwrap(),
        temperature: report.to_b.temperature,
        fidelity: ModeFidelity::BitIdentical,
        accuracy_evaluation: Measured::not_measured(NotMeasuredReason::NotApplicable),
        objectives: report.to_b.objectives(objective).unwrap(),
    }
}

#[test]
fn cpu_fixtures_validate_comparisons() {
    // FAST-01: "CPU fixtures validate schema and comparisons". Fake BENCH-02 cells of five
    // independent trials go through the CORE-08 discipline: matched configurations, one
    // start-state label, both §2.1 baselines and every §1.3 objective.
    let mut spec = aba_spec(4);
    spec.trials = 5;
    let run = |profile: RunnerProfile, state, spec: &AbaSpec| {
        let mode = profile.mode;
        measured_cell(run_cell(&factory(profile, 30), SwitchCell { mode, state }, spec).unwrap())
    };
    // The candidate executes while loading (GPU §2.6), which needs eager mode.
    let mut eager = profile(VerifiedReload);
    eager.execute_while_load = true;
    for model in &mut eager.models {
        model.timings.graph_capture_nanos = 0;
        model.cuda_graphs = 0;
    }
    let candidate = run(eager, TargetState::Warm, &spec);
    assert_eq!(candidate.to_b.ledger.burst_ids(), (0..5).collect());
    let ordinary = run(profile(FullProcessRestart), TargetState::Warm, &spec);
    let upstream = [
        (
            "verified-reload-warm",
            run(profile(VerifiedReload), TargetState::Warm, &spec),
        ),
        (
            "verified-reload-preload",
            run(profile(VerifiedReload), TargetState::Preload, &spec),
        ),
        (
            "version-supported-sleep",
            run(profile(VersionSupportedSleep), TargetState::Sleep, &spec),
        ),
    ];
    let objective = LatencyObjective {
        quantile: Quantile::P50,
        max_time_to_first_token_nanos: 10_000 * MILLIS,
    };
    let design = |effect, trials| ExperimentDesign {
        effect,
        independent_trials: trials,
        // An A/B/A script is predictable alternation (§1.1).
        trace: TracePattern::PredictableAlternation,
        components: vec![label("execute-while-load")],
        ablated_components: Vec::new(),
    };
    let compare = |states, design, ordinary: ComparisonSide| {
        ComparisonReport::new(
            ObjectivePlan::new(Objective::TimeToFirstToken, 0.05).unwrap(),
            states,
            design,
            Vec::new(),
            side("execute-while-load", &candidate, objective),
            Baseline::Measured {
                sides: vec![ordinary],
            },
            Baseline::Measured {
                sides: upstream
                    .iter()
                    .map(|(name, report)| side(name, report, objective))
                    .collect(),
            },
        )
    };
    let ordinary_side = || side("full-process-restart-warm", &ordinary, objective);
    let report = compare(
        StateComparison::WarmLoad,
        design(EffectClass::Other, spec.trials),
        ordinary_side(),
    )
    .unwrap();
    for (outcome, name) in [
        (report.ordinary_workflow(), "full-process-restart-warm"),
        (report.strongest_upstream(), "verified-reload-warm"),
    ] {
        let BaselineOutcome::Compared { baseline, verdict } = outcome else {
            panic!("{outcome:?}");
        };
        assert_eq!(baseline.name.as_str(), name);
        assert!(verdict.declared.candidate < verdict.declared.baseline);
        assert!(verdict.regressions.is_empty(), "{:?}", verdict.regressions);
        // What a fake cannot measure stays unmeasured, and the verdict says so.
        assert_eq!(
            verdict.status,
            VerdictStatus::ImprovedWithUnmeasuredObjectives
        );
        for objective in [
            Objective::ThroughputUnderLatencyObjective,
            Objective::PreparationCost,
            Objective::CostPerCompletedRequest,
            Objective::EnergyPerCompletedRequest,
        ] {
            assert!(verdict.unmeasured.contains(&objective), "{objective:?}");
        }
    }
    // S12 G0: a fake cell validates the comparison and backs no performance claim.
    assert_eq!(
        ImprovementClaim::from_report(&report, BaselineRole::OrdinaryWorkflow),
        Err(ReportError::FakeSubstrateIsNotEvidence)
    );

    // §1.1: fewer than five independent trials are refused, and predictable alternation
    // cannot support a cache or predictor effect.
    assert_eq!(
        compare(
            StateComparison::WarmLoad,
            design(EffectClass::Other, 3),
            ordinary_side()
        ),
        Err(ReportError::TooFewTrials {
            trials: 3,
            required: 5
        })
    );
    assert_eq!(
        compare(
            StateComparison::WarmLoad,
            design(EffectClass::CacheOrPredictor, 5),
            ordinary_side()
        ),
        Err(ReportError::PredictableTrace)
    );
    // S8: warm sides under another start-state label are refused.
    assert_eq!(
        compare(
            StateComparison::HotDispatch,
            design(EffectClass::Other, 5),
            ordinary_side()
        ),
        Err(ReportError::StateMismatch)
    );
    // S7: a baseline over another fixture is not comparable.
    let mut elsewhere = spec.clone();
    elsewhere.fixture_b = fixture("fast01-code-parse-ranges");
    let other_fixture = run(profile(FullProcessRestart), TargetState::Warm, &elsewhere);
    assert_eq!(
        compare(
            StateComparison::WarmLoad,
            design(EffectClass::Other, 5),
            side("other-fixture", &other_fixture, objective)
        ),
        Err(ReportError::NotComparable {
            fields: vec![ConfigurationField::Fixture]
        })
    );
    // A low-resolution percentile cannot feed a comparison (S8, S11).
    let short = run(profile(VerifiedReload), TargetState::Warm, &aba_spec(2));
    assert!(matches!(
        short.to_b.objectives(objective),
        Err(BenchError::Report(ReportError::LowResolution { .. }))
    ));
}
