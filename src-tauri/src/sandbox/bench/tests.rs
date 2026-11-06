//! The harness on the fake hosts: the three BENCH-05 modes on one clock, every attempt
//! in the denominator, the taxonomy, queueing and rejection by type, the resolution
//! rule of S11, the BENCH-13 record, claims a fake run never backs, the saturation knee,
//! the four BENCH-06 cases from the lifecycle's pool rules, and retries as separate
//! records linked to their first attempts.

use chrono::NaiveDate;

use super::test_support::{
    image, label, limits, runner_config, Capacity, ContractOptions, ContractWorld, Frozen,
    Misconfigured, ScriptedWorld, MILLI, SECOND,
};
use super::*;
use crate::foundation::coordination::{
    ResourceKind, RestoreAction, SnapshotManifest, SnapshotOrigin,
};
use crate::foundation::ids::SandboxBootGeneration;
use crate::foundation::report::{
    AttemptRole, BenchId, ClaimUnderTest, ConfidenceLevel, EventName, ExternalMethodScore,
    FailureKind, IntervalKind, LimitationKind, Outcome, Provenance, PublicUrl, Quantile,
    RecordStatistic, ReleaseRequirement, ReportError, ReproducibilityRecord, RetryTally, RunRecord,
    RunSubstrate, Scenario,
};
use crate::sandbox::backend::VmBackend as _;
use crate::sandbox::lifecycle::{
    BootPath, CheckoutDecision, ColdFallback, GoldenSnapshot, PoolRefusal, SandboxClass,
    SnapshotProvenance, StateReset, SupervisorError,
};
use pool::FallbackReason;

fn names(record: &RunRecord) -> Vec<EventName> {
    record
        .events
        .iter()
        .map(|event| event.event.name())
        .collect()
}

fn first_command_nanos(record: &RunRecord) -> u64 {
    record
        .interval(IntervalKind::VmFirstGuestCommand)
        .unwrap()
        .elapsed_nanos()
}

#[test]
fn the_three_modes_share_one_first_command_clock() {
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("modes")).unwrap();
    let plans = [
        Bench05Plan::sequential(6, 1, limits()).unwrap(),
        Bench05Plan::staggered(300 * MILLI, 6, 1, limits()).unwrap(),
        Bench05Plan::burst(6, 1, limits()).unwrap(),
    ];
    let mut reports = Vec::new();
    for plan in &plans {
        reports.push(runner.run_bench05(plan, &FaultPlan::none()).unwrap());
    }
    let clock = runner.config().clock.clone();
    for (plan, report) in plans.iter().zip(&reports) {
        assert_eq!(report.bench, BenchId::Bench05);
        assert_eq!(&report.load, &plan.spec().load());
        assert_eq!(report.success_rate().unwrap().attempts(), 6);
        assert_eq!(report.success_rate().unwrap().successes(), 6);
        assert_eq!(
            report.first_command.interval(),
            IntervalKind::VmFirstGuestCommand
        );
        for record in report.records() {
            assert_eq!(record.scenario, Scenario::VmProvisioning);
            assert_eq!(record.substrate, RunSubstrate::FakeTimeControlled);
            assert!(record.events.iter().all(|event| event.clock == clock));
            assert_eq!(
                names(record),
                vec![
                    EventName::VmCreateInitiated,
                    EventName::VmApiAcknowledged,
                    EventName::GuestCommandSucceeded
                ]
            );
            // The raw record reads back as itself.
            let text = serde_json::to_string(record).unwrap();
            assert_eq!(&RunRecord::from_json(&text).unwrap(), record);
        }
        // The lifecycle's first-command clock and the record's are one clock: no create
        // of these runs waited in a queue.
        assert_eq!(report.lifecycle_first_commands.len(), 6);
        for (attempt, record) in report.attempts.iter().zip(report.records()) {
            let sample = report
                .lifecycle_first_commands
                .iter()
                .find(|sample| sample.execution == attempt.execution)
                .unwrap();
            assert_eq!(sample.nanos, first_command_nanos(record));
            assert_eq!(attempt.first_command_nanos, Some(sample.nanos));
            assert_eq!(sample.path, BootPath::Cold);
        }
        // The API acknowledgment is recorded apart and is not the first command.
        let ack = report
            .api_acknowledgement
            .percentile(Quantile::P50)
            .unwrap()
            .value_nanos
            .value()
            .copied()
            .unwrap();
        assert_eq!(ack, 40.0 * MILLI as f64);
    }
    // One create at a time boots uncontended (900 ms ± 5 %); six at once contend, so
    // the burst's slowest first command is later than the sequential one's.
    let slowest = |report: &VmRunReport| {
        report
            .records()
            .iter()
            .map(first_command_nanos)
            .max()
            .unwrap()
    };
    assert!(slowest(&reports[0]) <= 945 * MILLI);
    assert!(slowest(&reports[2]) >= 1_100 * MILLI);
    // Each mode is its own variant and ledger.
    let variants: std::collections::BTreeSet<_> = reports
        .iter()
        .map(|report| report.variant.clone())
        .collect();
    assert_eq!(variants.len(), 3);
}

#[test]
fn every_attempt_counts_in_the_denominator_with_its_failure_kind() {
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("taxonomy")).unwrap();
    let plan = Bench05Plan::sequential(12, 1, limits()).unwrap();
    let faults = FaultPlan::none()
        .with(1, InjectedFault::BackendRefusesCreate)
        .with(
            3,
            InjectedFault::SlowFirstCommand {
                extra_nanos: 1_500 * MILLI,
            },
        )
        .with(
            5,
            InjectedFault::SlowFirstCommand {
                extra_nanos: 10_000 * MILLI,
            },
        )
        .with(7, InjectedFault::GuestCommandFails)
        .with(
            8,
            InjectedFault::VmExitsEarly {
                after_nanos: 100 * MILLI,
            },
        )
        .with(10, InjectedFault::DuplicateGuestIdentity);
    let report = runner.run_bench05(&plan, &faults).unwrap();
    let rate = report.success_rate().unwrap();
    assert_eq!((rate.successes(), rate.attempts()), (6, 12));
    let failures = report.failures();
    for kind in [
        FailureKind::Rejected,
        FailureKind::DeadlineFailure,
        FailureKind::Timeout,
        FailureKind::CommandFailure,
        FailureKind::EarlyTermination,
        FailureKind::DuplicateIdentity,
    ] {
        assert_eq!(failures.get(kind), 1, "{kind}");
    }
    assert_eq!(failures.total() + rate.successes(), rate.attempts());
    // The tails are conditional on success and carry the overall rate beside them.
    let summary = &report.first_command;
    assert_eq!(summary.samples().len(), 6);
    assert_eq!(summary.success_rate(), rate);
    assert_eq!(summary.deadline_failures(), 1);
    let by_index = |index: usize| &report.records()[index];
    // A rejected create never booted: only its create is recorded, with its type.
    assert_eq!(names(by_index(1)), vec![EventName::VmCreateInitiated]);
    assert_eq!(
        report.attempts[1].rejection,
        Some(RejectionKind::BackendRefused)
    );
    assert_eq!(report.rejections[&RejectionKind::BackendRefused], 1);
    assert!(matches!(
        &by_index(1).outcome,
        Outcome::Failed { component, code, .. }
            if component.as_str() == "backend" && code.as_str() == "backend-refused"
    ));
    // A first command after the deadline came, and is a deadline failure.
    assert!(names(by_index(3)).contains(&EventName::GuestCommandSucceeded));
    assert!(first_command_nanos(by_index(3)) > limits().deadline_nanos);
    // A timeout was acknowledged by the API and never reached a command: a fast
    // acknowledgment is not an interactive VM.
    assert_eq!(
        names(by_index(5)),
        vec![EventName::VmCreateInitiated, EventName::VmApiAcknowledged]
    );
    let mut claimed_success = by_index(5).clone();
    claimed_success.outcome = Outcome::Succeeded;
    assert_eq!(
        claimed_success.validate(),
        Err(ReportError::MissingEvent {
            event: EventName::GuestCommandSucceeded
        })
    );
    assert_eq!(report.attempts[5].failure, Some(FailureKind::Timeout));
    // Early exit and command failure end before any successful command.
    for index in [7, 8, 10] {
        assert!(!names(by_index(index)).contains(&EventName::GuestCommandSucceeded));
    }
    // A successful record cannot be rewritten into a failure that hides the deadline.
    let mut early = by_index(0).clone();
    early.outcome = Outcome::Failed {
        failure: FailureKind::DeadlineFailure,
        component: label("harness"),
        code: label("first-command-after-deadline"),
    };
    assert_eq!(early.validate(), Err(ReportError::InconsistentDeadline));
    // Every VM, failed or not, was stopped before the run ended.
    assert!(runner.host().backend.running().is_empty());
}

#[test]
fn a_burst_beyond_capacity_is_rejected_by_type_and_names_the_limiting_resource() {
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("over")).unwrap();
    // 64 GiB at 8 GiB per create: eight fit, the ledger refuses the rest at once.
    let report = runner
        .run_bench05(
            &Bench05Plan::burst(12, 2, limits()).unwrap(),
            &FaultPlan::none(),
        )
        .unwrap();
    let rate = report.success_rate().unwrap();
    assert_eq!((rate.successes(), rate.attempts()), (16, 24));
    assert_eq!(report.rejections[&RejectionKind::HostCapacity], 8);
    assert_eq!(report.failures().rejected, 8);
    for attempt in report
        .attempts
        .iter()
        .filter(|attempt| attempt.rejection.is_some())
    {
        assert_eq!(
            attempt.limiting_resource,
            Some(ResourceKind::HostMemoryBytes)
        );
        assert_eq!(attempt.vm, None);
    }
    // The two bursts are independent: each began with every VM of the last one stopped.
    assert_eq!(report.windows.len(), 2);
    assert!(report.windows.iter().all(|window| window.successes == 8));
}

#[test]
fn a_queued_create_keeps_its_clock_from_the_original_create() {
    let mut world = ContractWorld::with(ContractOptions {
        capacity: Capacity {
            memory_gib: 32,
            queue_wait: Some(60 * SECOND),
        },
        ..ContractOptions::default()
    });
    let mut runner = FakeVmRunner::new(&mut world, runner_config("queue")).unwrap();
    let mut relaxed = limits();
    relaxed.deadline_nanos = 4_000 * MILLI;
    // Four fit at once; the ledger queues four per tenant and refuses the rest.
    let report = runner
        .run_bench05(
            &Bench05Plan::burst(10, 1, relaxed).unwrap(),
            &FaultPlan::none(),
        )
        .unwrap();
    let queued: Vec<_> = report
        .attempts
        .iter()
        .filter(|attempt| attempt.queued_nanos.is_some() && attempt.failure.is_none())
        .collect();
    assert_eq!(queued.len(), 4);
    assert_eq!(report.rejections[&RejectionKind::QueueFull], 2);
    assert_eq!(report.success_rate().unwrap().successes(), 8);
    for attempt in queued {
        let waited = attempt.queued_nanos.unwrap();
        assert!(waited > 0);
        let sample = report
            .lifecycle_first_commands
            .iter()
            .find(|sample| sample.execution == attempt.execution)
            .unwrap();
        // The lifecycle's clock starts at the boot; the record's at the create.
        assert_eq!(attempt.first_command_nanos, Some(sample.nanos + waited));
    }
    // A queued create whose timeout passes first is withdrawn and recorded as a timeout.
    let mut world = ContractWorld::with(ContractOptions {
        capacity: Capacity {
            memory_gib: 32,
            queue_wait: Some(60 * SECOND),
        },
        ..ContractOptions::default()
    });
    let mut short = limits();
    short.timeout_nanos = short.deadline_nanos;
    short.hold_nanos = 5_000 * MILLI;
    let mut runner = FakeVmRunner::new(&mut world, runner_config("queue-timeout")).unwrap();
    let report = runner
        .run_bench05(
            &Bench05Plan::burst(8, 1, short).unwrap(),
            &FaultPlan::none(),
        )
        .unwrap();
    let timed_out: Vec<_> = report
        .records()
        .iter()
        .filter(|record| record.failure() == Some(FailureKind::Timeout))
        .collect();
    assert_eq!(timed_out.len(), 4);
    for record in timed_out {
        assert!(matches!(
            &record.outcome,
            Outcome::Failed { component, code, .. }
                if component.as_str() == "ledger" && code.as_str() == "queued-past-timeout"
        ));
        assert_eq!(names(record), vec![EventName::VmCreateInitiated]);
    }
    assert_eq!(report.success_rate().unwrap().attempts(), 8);
}

#[test]
fn a_create_the_supervisor_refuses_is_a_typed_rejection() {
    let mut host = Misconfigured(ScriptedWorld::new());
    let mut runner = FakeVmRunner::new(&mut host, runner_config("refused")).unwrap();
    let report = runner
        .run_bench05(
            &Bench05Plan::sequential(3, 1, limits()).unwrap(),
            &FaultPlan::none(),
        )
        .unwrap();
    assert_eq!(report.success_rate().unwrap().attempts(), 3);
    assert_eq!(report.rejections[&RejectionKind::Supervisor], 3);
    for attempt in &report.attempts {
        assert!(matches!(
            attempt.supervisor_refusal,
            Some(SupervisorError::WrongClass {
                expected: SandboxClass::Task,
                found: SandboxClass::Service,
                ..
            })
        ));
    }
    assert!(report.records().iter().all(|record| matches!(
        &record.outcome,
        Outcome::Failed { failure: FailureKind::Rejected, component, .. }
            if component.as_str() == "supervisor"
    )));
    assert_eq!(report.boot_calls, 0, "no boot ran");
}

#[test]
fn one_hundred_concurrent_creates_are_refused_on_the_fake() {
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("hundred")).unwrap();
    let plan = Bench05Plan::concurrent_100(3, limits()).unwrap();
    assert_eq!(
        runner.run_bench05(&plan, &FaultPlan::none()),
        Err(BenchError::NeedsAuthorizedSizedHost {
            concurrent_creates: 100
        })
    );
    assert_eq!(runner.host().supervisor.sandboxes().count(), 0);
    assert!(
        runner.host().backend.calls().is_empty(),
        "nothing was created"
    );
}

#[test]
fn a_p99_from_one_burst_of_100_has_weak_resolution() {
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("single")).unwrap();
    let report = runner
        .run_bench05(
            &Bench05Plan::sequential(100, 1, limits()).unwrap(),
            &FaultPlan::none(),
        )
        .unwrap();
    assert_eq!(report.first_command.samples().len(), 100);
    // p99 at rank 99 of 100 leaves one sample beyond it, from one burst.
    assert_eq!(
        report.tail(Quantile::P99).unwrap(),
        TailResolution::Weak {
            value_nanos: report
                .first_command
                .percentile(Quantile::P99)
                .unwrap()
                .value_nanos
                .clone(),
            reasons: vec![
                WeakResolution::SingleBurst,
                WeakResolution::FewTailSamples {
                    tail_samples: 1,
                    required: 10
                }
            ],
        }
    );
    // Even the median of one burst is weak.
    assert!(matches!(
        report.tail(Quantile::P50).unwrap(),
        TailResolution::Weak { reasons, .. } if reasons == vec![WeakResolution::SingleBurst]
    ));
    assert!(matches!(
        report.latency_claim(Quantile::P99),
        Err(BenchError::Report(ReportError::FakeSubstrateIsNotEvidence))
    ));
}

#[test]
fn independent_bursts_resolve_a_p95_and_the_distribution_stays_untrimmed() {
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("bursts")).unwrap();
    // The slowest create is far out, inside the deadline.
    let faults = FaultPlan::none().with(
        17,
        InjectedFault::SlowFirstCommand {
            extra_nanos: 900 * MILLI,
        },
    );
    let report = runner
        .run_bench05(&Bench05Plan::sequential(70, 3, limits()).unwrap(), &faults)
        .unwrap();
    // 210 samples over 3 bursts: p95 at rank 200 leaves 10 beyond it.
    assert!(matches!(
        report.tail(Quantile::P95).unwrap(),
        TailResolution::Resolved { .. }
    ));
    assert!(matches!(
        report.tail(Quantile::P99).unwrap(),
        TailResolution::Weak { reasons, .. }
            if reasons == vec![WeakResolution::FewTailSamples { tail_samples: 2, required: 10 }]
    ));
    // Uncertainty is reported as the spread across bursts.
    let p95 = report.first_command.percentile(Quantile::P95).unwrap();
    assert_eq!(p95.per_burst_spread.value().unwrap().bursts, 3);
    // Nothing is trimmed: the outlier is the largest sample.
    let samples = report.first_command.samples();
    assert_eq!(samples.len(), 210);
    let outlier = report.attempts[17].first_command_nanos.unwrap();
    assert_eq!(samples.last().unwrap().nanos, outlier);
    assert!(outlier >= 1_700 * MILLI);
    // A resolved percentile of a fake run still backs no claim.
    assert!(matches!(
        report.latency_claim(Quantile::P95),
        Err(BenchError::Report(ReportError::FakeSubstrateIsNotEvidence))
    ));
    // An external score that trims extremes is kept beside the untrimmed tails and is
    // never release evidence (S8 line 321).
    let external = ExternalMethodScore::new(
        label("computesdk-trimmed-score"),
        PublicUrl::new(
            "https://github.com/runloopai/computesdk-benchmarks/blob/master/METHODOLOGY.md",
        )
        .unwrap(),
        0.9,
        report.first_command.clone(),
    )
    .unwrap();
    assert_eq!(
        external.as_release_evidence(),
        Err(ReportError::TrimmedScoreNotReleaseEvidence)
    );
    assert_eq!(external.untrimmed().samples().len(), 210);
}

#[test]
fn a_fake_run_never_backs_a_claim_and_its_bench_13_record_says_why() {
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("claims")).unwrap();
    let report = runner
        .run_bench05(
            &Bench05Plan::burst(8, 3, limits()).unwrap(),
            &FaultPlan::none(),
        )
        .unwrap();
    let provenance = report.provenance().unwrap();
    assert!(provenance.is_fake_substrate());
    assert_eq!(
        provenance.yougori_evidence(),
        Err(ReportError::FakeSubstrateIsNotEvidence)
    );
    // Schema and comparison validation may use it.
    provenance.comparable_evidence().unwrap();
    assert_eq!(
        report.burst_scale_claim(8),
        Err(BenchError::Report(ReportError::FakeSubstrateIsNotEvidence))
    );
    let record = report
        .reproducibility(
            label("vm-burst-8-first-command"),
            NaiveDate::from_ymd_opt(2026, 10, 29).unwrap(),
            Vec::new(),
        )
        .unwrap();
    assert!(matches!(
        record.claim(),
        ClaimUnderTest::Yougori {
            bench: BenchId::Bench05,
            ..
        }
    ));
    // Raw events and failures, configuration hashes, method, distributions, limits.
    assert_eq!(record.raw_records().len(), 24);
    assert_eq!(record.configuration_digests().len(), 1);
    assert_eq!(
        record.method().intervals,
        vec![
            IntervalKind::VmFirstGuestCommand,
            IntervalKind::VmApiAcknowledgement
        ]
    );
    assert_eq!(record.distributions().len(), 2);
    let kinds: Vec<LimitationKind> = record
        .limitations()
        .iter()
        .map(|limitation| limitation.kind)
        .collect();
    assert!(kinds.contains(&LimitationKind::FakeRunner));
    assert!(kinds.contains(&LimitationKind::LowResolutionTail));
    assert!(Provenance::of_reproduction(&record)
        .unwrap()
        .is_fake_substrate());
    for statistic in [
        RecordStatistic::SuccessRate,
        RecordStatistic::Percentile {
            interval: IntervalKind::VmFirstGuestCommand,
            quantile: Quantile::P50,
        },
    ] {
        assert_eq!(
            ReleaseRequirement::from_reproduction(&record, statistic),
            Err(ReportError::FakeSubstrateIsNotEvidence)
        );
    }
    // The record reads back as itself, recomputed from its raw records.
    let text = serde_json::to_string(&record).unwrap();
    assert_eq!(ReproducibilityRecord::from_json(&text), Ok(record));
}

#[test]
fn the_same_seed_gives_the_same_run() {
    let run = || {
        let mut world = ContractWorld::new();
        let mut runner = FakeVmRunner::new(&mut world, runner_config("seeded")).unwrap();
        runner
            .run_bench05(
                &Bench05Plan::staggered(200 * MILLI, 8, 2, limits()).unwrap(),
                &FaultPlan::none().with(4, InjectedFault::GuestCommandFails),
            )
            .unwrap()
    };
    let (first, second) = (run(), run());
    assert_eq!(first.records(), second.records());
    let mut other = runner_config("seeded");
    other.timing.seed = 12;
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, other).unwrap();
    let third = runner
        .run_bench05(
            &Bench05Plan::staggered(200 * MILLI, 8, 2, limits()).unwrap(),
            &FaultPlan::none().with(4, InjectedFault::GuestCommandFails),
        )
        .unwrap();
    assert_ne!(first.records(), third.records());
}

#[test]
fn a_supervisor_off_the_manual_clock_is_refused() {
    let mut frozen = Frozen(ScriptedWorld::new());
    let mut runner = FakeVmRunner::new(&mut frozen, runner_config("frozen")).unwrap();
    assert!(matches!(
        runner.run_bench05(
            &Bench05Plan::sequential(2, 1, limits()).unwrap(),
            &FaultPlan::none()
        ),
        Err(BenchError::ClockNotControlled { .. })
    ));
    let mut world = ScriptedWorld::new();
    let mut bad = runner_config("bad prefix");
    assert!(matches!(
        FakeVmRunner::new(&mut world, bad.clone()),
        Err(BenchError::Id(_))
    ));
    bad.prefix = "fine".to_owned();
    bad.timing.api_ack_nanos = bad.timing.cold_first_command_nanos + 1;
    assert!(matches!(
        FakeVmRunner::new(&mut world, bad),
        Err(BenchError::InvalidParameter { .. })
    ));
}

#[test]
fn the_saturation_knee_is_measured_on_fresh_fakes() {
    let policy = KneePolicy::new(0.1, 0.05, 1, 64).unwrap();
    let report = saturation_search(
        || Ok(ContractWorld::new()),
        &runner_config("knee"),
        2,
        limits(),
        policy,
        &FaultPlan::none(),
    )
    .unwrap();
    // Throughput grows to eight concurrent creates; at sixteen half are refused.
    assert!(matches!(
        report.search.stop,
        KneeStop::FailureThreshold {
            concurrency: 16,
            failure_fraction
        } if failure_fraction == 0.5
    ));
    let knee = report.search.knee_concurrency.unwrap();
    assert!((5..=8).contains(&knee), "{knee}");
    assert_eq!(report.levels.len(), report.search.points.len());
    for (level, point) in report.levels.iter().zip(&report.search.points) {
        assert_eq!(level.load.concurrent_requests, point.concurrency);
        assert_eq!(level.bursts, 2);
        // Every level started on a fresh host: its first create's boot is the first.
        assert!(level
            .attempts
            .iter()
            .filter_map(|attempt| attempt.boot)
            .all(|boot| boot == SandboxBootGeneration::FIRST));
    }
    let sixteen = report
        .levels
        .iter()
        .find(|level| level.load.concurrent_requests == 16)
        .unwrap();
    assert_eq!(sixteen.rejections[&RejectionKind::HostCapacity], 16);
    // A search that would reach 100 concurrent creates needs an authorized host.
    assert_eq!(
        saturation_search(
            || Ok(ContractWorld::new()),
            &runner_config("knee"),
            2,
            limits(),
            KneePolicy::new(0.1, 0.05, 1, 128).unwrap(),
            &FaultPlan::none(),
        ),
        Err(BenchError::NeedsAuthorizedSizedHost {
            concurrent_creates: 128
        })
    );
}

fn snapshot_world() -> ContractWorld {
    ContractWorld::with(ContractOptions {
        snapshots: true,
        ..ContractOptions::default()
    })
}

#[test]
fn bench_06_cases_are_counted_from_the_lifecycle_pool_rules() {
    let mut world = snapshot_world();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("pool")).unwrap();
    let golden = runner.golden_snapshot().unwrap();
    let none = FaultPlan::none();

    let cold = runner
        .run_bench06(&Bench06Plan::cold_vm(4, 2, limits()).unwrap(), None, &none)
        .unwrap();
    assert_eq!(cold.counts.cold_boots, 8);
    assert_eq!(cold.counts.warm_restores, 0);
    assert!(
        cold.counts.cold_fallbacks.is_empty(),
        "new executions are cold by design"
    );
    assert_eq!(cold.replenishment.clones_prepared, 0);

    let limited = runner
        .run_bench06(
            &Bench06Plan::limited_warm_pool(2, 5, 2, limits()).unwrap(),
            Some(&golden),
            &none,
        )
        .unwrap();
    assert_eq!(limited.counts.warm_restores, 4);
    assert_eq!(limited.counts.cold_boots, 6);
    assert_eq!(
        limited.counts.cold_fallbacks,
        std::collections::BTreeMap::from([(FallbackReason::PoolDepleted, 6)])
    );
    // Two clones per burst are prepared and charged, 600 ms each.
    assert_eq!(limited.replenishment.clones_prepared, 4);
    assert_eq!(limited.replenishment.charged_nanos, 2_400 * MILLI);
    assert_eq!(
        limited.charge_per_warm_restore_nanos().value(),
        Some(600.0 * MILLI as f64)
    );

    let clean = runner
        .run_bench06(
            &Bench06Plan::clean_snapshot(4, 2, limits()).unwrap(),
            Some(&golden),
            &none,
        )
        .unwrap();
    assert_eq!(clean.counts.warm_restores, 8);
    assert!(clean
        .run
        .attempts
        .iter()
        .all(|attempt| attempt.decision == Some(CheckoutDecision::Restore)));
    // Every restore got a fresh boot generation of its slot and its own VM identity.
    assert_eq!(clean.counts.unique_vm_identities, 8);
    for attempt in &clean.run.attempts {
        assert!(attempt.boot.unwrap() > SandboxBootGeneration::FIRST);
    }

    let depletion = runner
        .run_bench06(
            &Bench06Plan::pool_depletion_replenishment(
                2,
                300 * MILLI,
                ReplenishmentSchedule {
                    every_nanos: 900 * MILLI,
                    clones: 1,
                },
                8,
                2,
                limits(),
            )
            .unwrap(),
            Some(&golden),
            &none,
        )
        .unwrap();
    let depleted = depletion
        .counts
        .cold_fallbacks
        .get(&FallbackReason::PoolDepleted)
        .copied()
        .unwrap_or(0);
    assert!(depleted > 0, "the pool ran out");
    assert!(
        depletion.counts.warm_restores > 4,
        "replenished clones were restored"
    );
    assert_eq!(depletion.counts.warm_restores + depleted, 16);
    // Every prepared clone is charged, whether a checkout used it or not.
    assert!(depletion.replenishment.clones_prepared >= depletion.counts.warm_restores);
    assert_eq!(
        depletion.replenishment.charged_nanos,
        depletion.replenishment.clones_prepared * 600 * MILLI
    );

    for case in [&cold, &limited, &clean, &depletion] {
        assert_eq!(case.run.bench, BenchId::Bench06);
        assert!(case.identical_authority_checks(), "{}", case.case);
        assert_eq!(case.lifecycle.authority_checks, case.counts.attempts);
        assert_eq!(case.lifecycle.warm_restores, case.counts.warm_restores);
        assert_eq!(case.counts.unique_vm_identities, case.counts.attempts);
        assert_eq!(case.counts.successful_first_commands, case.counts.attempts);
        assert_eq!(case.counts.failed_clone_cleanups, 0);
        assert_eq!(
            case.run.success_rate().unwrap().successes(),
            case.counts.attempts
        );
        assert!(!case.backend_memory_bytes.is_measured());
        assert!(!case.backend_cost_usd.is_measured());
        assert!(case.run.provenance().unwrap().is_fake_substrate());
    }
    // Warm and cold are reported apart, each with its own distribution.
    let warm = clean.path(BootPath::WarmRestore).unwrap();
    let cold_path = cold.path(BootPath::Cold).unwrap();
    let p50 = |distribution: &PathDistribution| {
        distribution
            .percentile(Quantile::P50)
            .unwrap()
            .value_nanos
            .value()
            .copied()
            .unwrap()
    };
    assert!(p50(warm) < 300.0 * MILLI as f64);
    assert!(p50(cold_path) > 850.0 * MILLI as f64);
    assert_eq!(clean.path(BootPath::Cold).unwrap().boots, 0);
}

#[test]
fn a_clone_that_fails_verification_is_cleaned_up_and_boots_cold() {
    let mut world = ScriptedWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("verify")).unwrap();
    let golden = runner.golden_snapshot().unwrap();
    // The restored clone does not reseed its randomness: verification refuses it.
    runner
        .host()
        .backend
        .omit_actions
        .insert(RestoreAction::REQUIRED[0]);
    let report = runner
        .run_bench06(
            &Bench06Plan::clean_snapshot(3, 1, limits()).unwrap(),
            Some(&golden),
            &FaultPlan::none(),
        )
        .unwrap();
    assert_eq!(report.counts.failed_clone_cleanups, 3);
    assert_eq!(report.counts.warm_restores, 0);
    assert_eq!(report.counts.cold_boots, 3);
    assert_eq!(
        report.counts.cold_fallbacks,
        std::collections::BTreeMap::from([(FallbackReason::CloneVerificationFailed, 3)])
    );
    assert_eq!(report.lifecycle.failed_clone_cleanups, 3);
    assert!(report.identical_authority_checks());
    // The cold fallback still reached its first command, on the cold path.
    assert_eq!(report.run.success_rate().unwrap().successes(), 3);
    assert!(report.run.attempts.iter().all(|attempt| attempt.decision
        == Some(CheckoutDecision::ColdBoot {
            fallback: ColdFallback::CloneVerificationFailed
        })));
}

#[test]
fn a_restore_the_backend_refuses_exposes_nothing_and_is_not_a_warm_restore() {
    let mut world = snapshot_world();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("refused")).unwrap();
    let golden = runner.golden_snapshot().unwrap();
    runner
        .host()
        .backend
        .script_mut()
        .restore_actions
        .remove(&RestoreAction::REQUIRED[0]);
    let report = runner
        .run_bench06(
            &Bench06Plan::clean_snapshot(2, 1, limits()).unwrap(),
            Some(&golden),
            &FaultPlan::none(),
        )
        .unwrap();
    assert_eq!(report.counts.restore_rollbacks, 2);
    assert_eq!(report.counts.warm_restores, 0);
    // The lifecycle's own counts agree with the receipts.
    assert_eq!(report.lifecycle.restore_rollbacks, 2);
    assert_eq!(report.lifecycle.warm_restores, 0);
    assert_eq!(report.counts.unique_vm_identities, 0);
    assert_eq!(report.run.success_rate().unwrap().successes(), 0);
    assert_eq!(report.run.rejections[&RejectionKind::BackendRefused], 2);
    assert!(runner.host().backend.running().is_empty());
}

#[test]
fn without_a_state_reset_every_checkout_boots_cold() {
    let mut world = ContractWorld::with(ContractOptions {
        snapshots: true,
        state_reset: StateReset::Unsupported {
            detail: "the guest's application state cannot be reset".to_owned(),
        },
        ..ContractOptions::default()
    });
    let mut runner = FakeVmRunner::new(&mut world, runner_config("no-reset")).unwrap();
    let golden = runner.golden_snapshot().unwrap();
    let report = runner
        .run_bench06(
            &Bench06Plan::clean_snapshot(3, 1, limits()).unwrap(),
            Some(&golden),
            &FaultPlan::none(),
        )
        .unwrap();
    assert_eq!(report.counts.warm_restores, 0);
    assert_eq!(
        report.counts.cold_fallbacks,
        std::collections::BTreeMap::from([(FallbackReason::StateResetUnsupported, 3)])
    );
    assert_eq!(report.run.success_rate().unwrap().successes(), 3);
}

#[test]
fn only_a_certified_golden_snapshot_reaches_a_pool() {
    let mut world = snapshot_world();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("dirty")).unwrap();
    let golden = runner.golden_snapshot().unwrap();
    // A dirty workload snapshot is never promoted to a shared base (§6.6 line 2338).
    let dirty = SnapshotManifest {
        origin: SnapshotOrigin::TenantWorkload,
        ..golden.manifest().clone()
    };
    let provenance = SnapshotProvenance {
        before_tenant_inputs: true,
        before_credentials: true,
        before_external_connections: true,
    };
    assert!(matches!(
        GoldenSnapshot::certify(dirty, provenance, image()),
        Err(PoolRefusal::NotGolden { .. })
    ));
    assert_eq!(
        GoldenSnapshot::certify(
            golden.manifest().clone(),
            SnapshotProvenance {
                before_credentials: false,
                ..provenance
            },
            image()
        ),
        Err(PoolRefusal::TakenAfterCredentials)
    );
    // A warm-pool case without a golden snapshot is refused before anything starts.
    assert!(matches!(
        runner.run_bench06(
            &Bench06Plan::limited_warm_pool(1, 3, 1, limits()).unwrap(),
            None,
            &FaultPlan::none()
        ),
        Err(BenchError::InvalidParameter {
            field: "golden",
            ..
        })
    ));
}

#[test]
fn a_backend_refusal_has_the_kind_the_run_reports_for_it() {
    use crate::foundation::evidence::UnknownReason;
    use crate::sandbox::backend::Scripted;
    use crate::sandbox::integration::LaunchProblem;
    // Refused after creation with nothing left: the backend's refusal. With its VM left
    // behind: a rollback that stalled, the boot's perimeter and reservation held.
    for (left, expected) in [
        (None, RejectionKind::BackendRefused),
        (
            Some("the VM did not exit".to_owned()),
            RejectionKind::RollbackStalled,
        ),
    ] {
        let mut world = ContractWorld::new();
        world.backend.script_mut().devices = Scripted::Unavailable {
            reason: UnknownReason::NotTested,
        };
        world.backend.script_mut().teardown_failure = left;
        let report = {
            let mut runner = FakeVmRunner::new(&mut world, runner_config("refusals")).unwrap();
            let plan = Bench05Plan::sequential(1, 1, limits()).unwrap();
            runner.run_bench05(&plan, &FaultPlan::none()).unwrap()
        };
        assert_eq!(report.attempts[0].rejection, Some(expected));
        assert_eq!(report.rejections[&expected], 1);
        let refused = world.table.refused();
        assert_eq!(refused.len(), 1);
        let LaunchProblem::Backend { refusal } = &refused[0].problem else {
            panic!("{:?}", refused[0]);
        };
        assert_eq!(RejectionKind::of_refusal(refusal), expected);
    }
}

/// When a record's create was initiated.
fn created_nanos(record: &RunRecord) -> u64 {
    record.events[0].at_nanos.as_nanos()
}

#[test]
fn a_retried_create_is_its_own_record_linked_to_its_first_attempt() {
    let run = || {
        let mut world = ContractWorld::new();
        let report = {
            let mut runner = FakeVmRunner::new(&mut world, runner_config("retry-link")).unwrap();
            let plan = Bench05Plan::sequential(6, 1, limits())
                .unwrap()
                .with_retries(
                    RetryPolicy::new([RejectionKind::BackendRefused], 2, 1_000 * MILLI).unwrap(),
                )
                .unwrap();
            let faults = FaultPlan::none()
                .with(2, InjectedFault::BackendRefusesCreate)
                .with(4, InjectedFault::BackendRefusesCreate)
                .with_retry(4, 1, InjectedFault::BackendRefusesCreate)
                .with_retry(4, 2, InjectedFault::BackendRefusesCreate)
                .with(5, InjectedFault::GuestCommandFails);
            runner.run_bench05(&plan, &faults).unwrap()
        };
        assert!(world.backend.running().is_empty(), "every VM was stopped");
        report
    };
    let report = run();
    assert_eq!(
        run().records(),
        report.records(),
        "the same seed, the same run"
    );
    // Six first attempts at their positions, then the retries in the order created:
    // attempt 2's first retry, and attempt 4's first and second.
    assert_eq!(report.attempts.len(), 6);
    let records = report.records();
    assert_eq!(records.len(), 9);
    assert!(records[..6]
        .iter()
        .all(|record| record.attempt.role == AttemptRole::Initial));
    let operation = |index: usize| records[index].attempt.operation.clone();
    for (retry, first, number) in [(6, 2, 1), (7, 4, 1), (8, 4, 2)] {
        let record = &records[retry];
        // The second retry names the first attempt, never the retry before it.
        assert_eq!(
            record.attempt.role,
            AttemptRole::Retry {
                first_attempt: operation(first),
                retry_number: number
            }
        );
        assert_ne!(record.attempt.operation, operation(first));
        assert_eq!(record.attempt.variant, records[first].attempt.variant);
        assert_eq!(record.attempt.burst, records[first].attempt.burst);
        assert!(record
            .events
            .iter()
            .all(|event| event.operation == record.attempt.operation));
        let text = serde_json::to_string(record).unwrap();
        assert_eq!(&RunRecord::from_json(&text).unwrap(), record);
    }
    assert_eq!(report.ledger.retries_of(&operation(2)).count(), 1);
    assert_eq!(report.ledger.retries_of(&operation(4)).count(), 2);
    assert_eq!(report.ledger.retries_of(&operation(7)).count(), 0);
    // The failed first attempt is kept as it was: one create, rejected by the backend.
    assert_eq!(names(&records[2]), vec![EventName::VmCreateInitiated]);
    assert_eq!(records[2].failure(), Some(FailureKind::Rejected));
    assert_eq!(report.attempts[2].vm, None);
    // The retry created the same sandbox again, the policy's delay after the refusal,
    // and its first command is timed from its own create.
    let retry = &report.retries.attempts[0];
    assert_eq!(
        (retry.first_attempt, retry.retry_number, retry.after),
        (2, 1, RejectionKind::BackendRefused)
    );
    assert_eq!(retry.first_operation, operation(2));
    assert_eq!(retry.attempt.index, 2);
    assert_eq!(retry.attempt.execution, report.attempts[2].execution);
    assert_eq!(retry.attempt.operation, operation(6));
    assert!(retry.attempt.vm.is_some());
    assert_eq!(retry.attempt.failure, None);
    assert_eq!(
        created_nanos(&records[6]),
        created_nanos(&records[2]) + 1_000 * MILLI
    );
    assert_eq!(
        retry.attempt.first_command_nanos,
        Some(first_command_nanos(&records[6]))
    );
    // One create at a time: the next first attempt starts once the retry is over.
    assert!(
        created_nanos(&records[3]) > created_nanos(&records[6]) + first_command_nanos(&records[6])
    );
    // A retry's fault is its own: both of attempt 4's retries were refused, and with the
    // bound of two spent, attempt 4 stays failed.
    assert_eq!(
        report
            .retries
            .of(4)
            .map(|retry| (retry.retry_number, retry.attempt.rejection))
            .collect::<Vec<_>>(),
        vec![
            (1, Some(RejectionKind::BackendRefused)),
            (2, Some(RejectionKind::BackendRefused))
        ]
    );
    assert_eq!(report.retries.not_retried[&NoRetry::BudgetSpent], 1);
    assert_eq!(report.retries.rejections[&RejectionKind::BackendRefused], 2);
    // A failure that is not a rejection is never retried.
    assert_eq!(report.failures().command_failure, 1);
    assert_eq!(report.ledger.retries_of(&operation(5)).count(), 0);
    // The supervisor answered every create and retry.
    assert_eq!(report.boot_calls, 9);
}

#[test]
fn success_with_retries_is_reported_beside_first_attempt_success() {
    let policy = RetryPolicy::new([RejectionKind::HostCapacity], 2, 2_000 * MILLI).unwrap();
    let run = |retries: RetryPolicy| {
        let mut world = ContractWorld::new();
        let mut runner = FakeVmRunner::new(&mut world, runner_config("beside")).unwrap();
        let plan = Bench05Plan::burst(12, 2, limits())
            .unwrap()
            .with_retries(retries)
            .unwrap();
        runner.run_bench05(&plan, &FaultPlan::none()).unwrap()
    };
    let without = run(RetryPolicy::off());
    let with = run(policy.clone());
    // First attempts: eight of twelve fit in each burst, as without retries.
    let rate = with.success_rate().unwrap();
    assert_eq!((rate.successes(), rate.attempts()), (16, 24));
    assert_eq!(rate, without.success_rate().unwrap());
    assert_eq!(with.failures(), without.failures());
    assert_eq!(with.failures().rejected, 8);
    assert_eq!(with.rejections, without.rejections);
    assert_eq!(with.failure_fraction(), without.failure_fraction());
    // The refused creates were retried 2 s later, once the first VMs had stopped, and all
    // completed: success with retries is reported apart, with its own interval.
    let retries = &with.retries;
    assert_eq!(retries.policy, policy);
    assert_eq!(
        retries.tally,
        RetryTally {
            retries: 8,
            successful_retries: 8,
            recovered_first_attempts: 8,
        }
    );
    let completed = with.success_with_retries();
    assert_eq!((completed.successes(), completed.attempts()), (24, 24));
    assert_eq!(
        retries.success_with_retries_wilson,
        completed.wilson(ConfidenceLevel::NinetyFive)
    );
    assert_ne!(completed, rate);
    assert!(retries.attempts.iter().all(|retry| retry.retry_number == 1
        && retry.after == RejectionKind::HostCapacity
        && retry.attempt.failure.is_none()));
    assert!(retries.not_retried.values().all(|count| *count == 0));
    // Without a policy nothing is retried, and the two rates are one.
    assert_eq!(without.retries.tally, RetryTally::default());
    assert_eq!(without.retries.not_retried[&NoRetry::NotNamed], 8);
    assert_eq!(
        without.success_with_retries(),
        without.success_rate().unwrap()
    );
    // The tails are the first attempts' alone, the same samples as without retries; the
    // summary carries the retry tally beside them.
    assert_eq!(
        with.first_command.samples(),
        without.first_command.samples()
    );
    assert_eq!(with.first_command.samples().len(), 16);
    assert_eq!(with.first_command.success_rate(), rate);
    assert_eq!(with.first_command.retries(), retries.tally);
    // The burst windows count first attempts only.
    for (left, right) in with.windows.iter().zip(&without.windows) {
        assert_eq!(
            (left.attempts, left.successes, left.elapsed_nanos()),
            (right.attempts, right.successes, right.elapsed_nanos())
        );
    }
    assert_eq!(
        with.mean_successes_per_second(),
        without.mean_successes_per_second()
    );
    // The variant says the run retried, so it is never one ledger with the run without.
    assert_eq!(with.variant.as_str(), "bench-05-burst-12-retry-2x");
    assert_ne!(with.variant, without.variant);
    // BENCH-13 keeps every raw record; its distributions are the first attempts'.
    let record = with
        .reproducibility(
            label("vm-burst-12-retried"),
            NaiveDate::from_ymd_opt(2026, 10, 29).unwrap(),
            Vec::new(),
        )
        .unwrap();
    assert_eq!(record.raw_records().len(), 32);
    for distribution in record.distributions() {
        assert_eq!(distribution.success_rate(), rate);
        assert_eq!(distribution.retries(), retries.tally);
    }
    let text = serde_json::to_string(&record).unwrap();
    assert_eq!(ReproducibilityRecord::from_json(&text), Ok(record));
}

#[test]
fn a_retry_never_follows_a_refusal_the_policy_does_not_name() {
    let mut world = ContractWorld::new();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("unnamed")).unwrap();
    let plan = Bench05Plan::burst(12, 1, limits())
        .unwrap()
        .with_retries(RetryPolicy::new([RejectionKind::BackendRefused], 2, 500 * MILLI).unwrap())
        .unwrap();
    let faults = FaultPlan::none()
        .with(0, InjectedFault::BackendRefusesCreate)
        .with(1, InjectedFault::GuestCommandFails)
        .with(
            2,
            InjectedFault::SlowFirstCommand {
                extra_nanos: 10_000 * MILLI,
            },
        );
    let report = runner.run_bench05(&plan, &faults).unwrap();
    // The backend refused attempt 0, which freed its reservation: attempts 1 to 8 fit
    // and the host refused 9 to 11.
    assert_eq!(report.rejections[&RejectionKind::BackendRefused], 1);
    assert_eq!(report.rejections[&RejectionKind::HostCapacity], 3);
    assert_eq!(report.failures().command_failure, 1);
    assert_eq!(report.failures().timeout, 1);
    // Only the named refusal was retried, 500 ms later while the host was still full, and
    // the host refused the retry.
    let retries = &report.retries;
    assert_eq!(retries.attempts.len(), 1);
    let retry = &retries.attempts[0];
    assert_eq!((retry.first_attempt, retry.retry_number), (0, 1));
    assert_eq!(retry.attempt.rejection, Some(RejectionKind::HostCapacity));
    assert_eq!(
        retry.attempt.limiting_resource,
        Some(ResourceKind::HostMemoryBytes)
    );
    assert_eq!(retries.rejections[&RejectionKind::HostCapacity], 1);
    // The host's refusal is not named, so neither the three first attempts it refused
    // nor the retry it refused was retried, although the bound allows a second retry.
    assert_eq!(retries.not_retried[&NoRetry::NotNamed], 4);
    assert_eq!(retries.not_retried[&NoRetry::BudgetSpent], 0);
    // Nor were the command failure and the timeout.
    for first in 1..12 {
        assert_eq!(retries.of(first).count(), 0, "{first}");
    }
    assert_eq!(report.records().len(), 13);
    assert_eq!(retries.tally.recovered_first_attempts, 0);
    assert_eq!(
        report.success_with_retries(),
        report.success_rate().unwrap()
    );

    // A named capacity refusal the ledger says cannot progress is not retried either:
    // each create asks for 8 GiB of a host with 4.
    let mut small = ContractWorld::with(ContractOptions {
        capacity: Capacity {
            memory_gib: 4,
            queue_wait: None,
        },
        ..ContractOptions::default()
    });
    let mut runner = FakeVmRunner::new(&mut small, runner_config("beyond")).unwrap();
    let plan = Bench05Plan::sequential(3, 1, limits())
        .unwrap()
        .with_retries(
            RetryPolicy::new(
                [RejectionKind::HostCapacity, RejectionKind::TenantBudget],
                2,
                500 * MILLI,
            )
            .unwrap(),
        )
        .unwrap();
    let report = runner.run_bench05(&plan, &FaultPlan::none()).unwrap();
    assert_eq!(report.failures().rejected, 3);
    assert!(report.retries.attempts.is_empty());
    assert_eq!(report.retries.not_retried[&NoRetry::CannotProgress], 3);
    assert_eq!(report.records().len(), 3);
}

#[test]
fn the_knee_search_ignores_retries() {
    let policy = KneePolicy::new(0.1, 0.05, 1, 64).unwrap();
    let retries = RetryPolicy::new([RejectionKind::HostCapacity], 1, 2_000 * MILLI).unwrap();
    let without = saturation_search(
        || Ok(ContractWorld::new()),
        &runner_config("knee"),
        2,
        limits(),
        policy,
        &FaultPlan::none(),
    )
    .unwrap();
    let with = saturation_search_with_retries(
        || Ok(ContractWorld::new()),
        &runner_config("knee"),
        2,
        limits(),
        policy,
        &retries,
        &FaultPlan::none(),
    )
    .unwrap();
    // The same points, stop and knee: the retries completed every refused create at
    // sixteen and changed none of them.
    assert_eq!(with.search, without.search);
    assert!(matches!(
        with.search.stop,
        KneeStop::FailureThreshold {
            concurrency: 16,
            failure_fraction
        } if failure_fraction == 0.5
    ));
    let sixteen = with
        .levels
        .iter()
        .find(|level| level.load.concurrent_requests == 16)
        .unwrap();
    assert_eq!(sixteen.retries.tally.recovered_first_attempts, 16);
    assert_eq!(sixteen.success_with_retries().rate(), 1.0);
    assert_eq!(sixteen.failure_fraction().unwrap(), 0.5);
    // The levels that refused nothing retried nothing.
    for level in &with.levels {
        if level.load.concurrent_requests <= 8 {
            assert!(level.retries.attempts.is_empty());
        }
    }
}

#[test]
fn a_retried_checkout_is_counted_apart_from_the_first_checkouts() {
    let mut world = snapshot_world();
    let mut runner = FakeVmRunner::new(&mut world, runner_config("pool-retry")).unwrap();
    let golden = runner.golden_snapshot().unwrap();
    let plan = Bench06Plan::limited_warm_pool(2, 5, 1, limits())
        .unwrap()
        .with_retries(RetryPolicy::new([RejectionKind::BackendRefused], 1, 1_000 * MILLI).unwrap())
        .unwrap();
    let report = runner
        .run_bench06(
            &plan,
            Some(&golden),
            &FaultPlan::none().with(0, InjectedFault::BackendRefusesCreate),
        )
        .unwrap();
    // The first checkout's restore was refused and rolled back; its clone is not reused.
    assert_eq!(report.counts.attempts, 5);
    assert_eq!(report.counts.restore_rollbacks, 1);
    // Its retry restored the pool's other clone, so the later checkouts found it empty.
    let retried = report.retry_counts();
    assert_eq!(retried.attempts, 1);
    assert_eq!(retried.warm_restores, 1);
    assert_eq!(retried.successful_first_commands, 1);
    assert_eq!(report.counts.warm_restores, 0);
    assert_eq!(
        report.counts.cold_fallbacks,
        std::collections::BTreeMap::from([(FallbackReason::PoolDepleted, 4)])
    );
    // The lifecycle counted both, and every boot went through the same authority checks.
    assert!(report.identical_authority_checks());
    assert_eq!(
        report.lifecycle.authority_checks,
        report.counts.attempts + retried.attempts
    );
    assert_eq!(
        report.lifecycle.warm_restores,
        report.counts.warm_restores + retried.warm_restores
    );
    assert_eq!(report.lifecycle.restore_rollbacks, 1);
    // First-attempt success and success with retries, apart; the path distributions are
    // the first attempts'.
    assert_eq!(report.run.success_rate().unwrap().successes(), 4);
    assert_eq!(report.run.success_with_retries().successes(), 5);
    assert_eq!(report.path(BootPath::WarmRestore).unwrap().boots, 0);
    assert_eq!(
        report.run.variant.as_str(),
        "bench-06-limited-warm-pool-k2-retry-1x"
    );
}
