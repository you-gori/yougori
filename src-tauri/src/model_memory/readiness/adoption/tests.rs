//! G05 on fakes and manual clocks: CORE-08 records as reload costs and resource inputs
//! with their fallbacks, and the governor's workflow intent, bounds, deadlines, leases,
//! promotion, shared prerequisites and demand-only rollback against the real CORE-03
//! ledger.

use std::sync::Arc;
use std::time::Duration;

use super::*;
use crate::foundation::coordination::{CancelCause, LeaseState};
use crate::foundation::evidence::{ClockSession, HostSubject, SourceClass};
use crate::foundation::ids::{
    digest, Clock, Digest, ExecutionCategory, ExecutionId, GpuDeviceKey, LeaseId, ManualClock,
    MonotonicTime, OperationId, TenantId,
};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityDeclaration, CostPurpose, Ledger, LedgerConfig, Priority,
    Provenance as LedgerProvenance, QueueFairness, QueueLimits, ReleaseOutcome, Requester,
    ReservationRequest, ResourceKey,
};
use crate::foundation::report::{
    ArrivalMode, AttemptIdentity, AttemptRole, BenchId, BuildIdentity, CacheTier,
    ClientDescription, ClientPlacement, ClockId, ColdProvenance, CpuDescription, EngineIdentity,
    EventKind, EventRecorder, GpuDescription, HostDescription, Label, LaunchDescription,
    LoadDescription, Measured, ModelAtArrival, ModelIdentity, ModelRevision, NotMeasuredReason,
    Outcome, PowerSource, Precision, PrefillMode, Provenance, RunMeasurements, RunRecord,
    RunSubstrate, Scenario, SchemaVersion, StartState, StartTemperature,
};
use crate::model_memory::boundaries::PreparationStep;
use crate::model_memory::graph::node::DurationEstimate;
use crate::model_memory::math::calibration::{
    DemandOnlyReason, ModeController, ModeSignals, ModeThresholds,
};
use crate::model_memory::math::chunking::ChunkingError;
use crate::model_memory::math::prefetch::Objective;
use crate::model_memory::readiness::intent::{
    CancelReason, PrepareBounds, PrepareOperation, PrepareRefusal, PrepareRequest, PrepareState,
    PrepareWork, ReleaseReason,
};
use crate::model_memory::readiness::test_support::{at, target, GB, SECOND};
use crate::model_memory::residency::retention::{
    CostPerByte, ObjectKind, ObjectView, RetentionPolicy,
};
use crate::model_memory::transitions::{LoadCurve, MeasuredCurves};

const MILLIS: u64 = 1_000_000;

fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

fn op(value: &str) -> OperationId {
    OperationId::new(value).unwrap()
}

fn test_digest(part: &str) -> Digest {
    digest("yougori/test/readiness/adoption/v1", &[part.as_bytes()])
}

fn seconds(value: f64) -> Duration {
    Duration::from_secs_f64(value)
}

// ---------------------------------------------------------------------------------------
// CORE-08 records as the runner adapter writes them.

fn unmeasured() -> RunMeasurements {
    let not = || Measured::not_measured(NotMeasuredReason::NotRecorded);
    RunMeasurements {
        output_tokens: not(),
        prefill_tokens_per_second: Measured::not_measured(NotMeasuredReason::NotRecorded),
        aggregate_decode_tokens_per_second: Measured::not_measured(NotMeasuredReason::NotRecorded),
        speculative: Measured::not_measured(NotMeasuredReason::NotRecorded),
        peak_gpu_memory_bytes: not(),
        retained_gpu_memory_bytes: not(),
        peak_host_memory_bytes: not(),
        retained_host_memory_bytes: not(),
        peak_pinned_host_memory_bytes: not(),
        transferred_bytes: not(),
        storage_read_bytes: not(),
        energy_joules: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        offload: Measured::not_measured(NotMeasuredReason::NotRecorded),
        first_run: Measured::not_measured(NotMeasuredReason::NotApplicable),
        owner_return: Measured::not_measured(NotMeasuredReason::NotApplicable),
        reasoning: Measured::not_measured(NotMeasuredReason::NotRecorded),
    }
}

fn events(
    operation: &str,
    steps: &[(u64, EventKind)],
) -> Vec<crate::foundation::report::RecordedEvent> {
    let clock = ManualClock::new(MonotonicTime::ZERO);
    let mut recorder = EventRecorder::new(
        op(operation),
        ClockId::new(label("runner-attempt-relative")),
        &clock,
    );
    for (after_millis, event) in steps {
        clock.advance(Duration::from_millis(*after_millis));
        recorder.record(event.clone());
    }
    recorder.into_events()
}

/// A successful load attempt of `model` that became ready after `millis`, measured in an
/// authorized disposable environment: what `measurement::report::adapt` writes for a
/// load call.
fn load_record(operation: &str, model: &str, millis: u64) -> RunRecord {
    RunRecord {
        schema_version: SchemaVersion,
        attempt: AttemptIdentity {
            bench: BenchId::Bench02,
            variant: label("load-call"),
            execution: ExecutionId::new("exe-measurement-job").unwrap(),
            operation: op(operation),
            role: AttemptRole::Initial,
            burst: 0,
            deadline_nanos: Measured::not_measured(NotMeasuredReason::NotApplicable),
        },
        scenario: Scenario::Stages {
            primary: crate::foundation::report::IntervalKind::ReadyLatency,
        },
        substrate: RunSubstrate::AuthorizedDisposable {
            authorization: label("disposable-bench-host"),
        },
        build: BuildIdentity {
            plan: test_digest("plan"),
            runner_build: test_digest("runner"),
            runner_version: label("1.1.2"),
        },
        execution_category: ExecutionCategory::SharedKernelGpuRuntime,
        model: Measured::measured(ModelIdentity {
            revision: ModelRevision::Tag {
                name: label("main"),
            },
            licenses: vec![label("Apache-2.0")],
            weights: test_digest(model),
            tokenizer: test_digest("tokenizer"),
            chat_template: test_digest("template"),
        }),
        precision: Measured::measured(Precision {
            weight_dtype: label("bf16"),
            quantization: label("none"),
            kv_cache_dtype: label("bf16"),
        }),
        engine: Measured::measured(EngineIdentity {
            name: label("vllm"),
            version: label("0.29.0"),
        }),
        host: HostDescription {
            os: label("linux"),
            os_version: label("6.6.87.2-microsoft-standard-WSL2"),
            cpu: CpuDescription {
                model: label("amd-ryzen-9-7950x"),
                logical_cores: 32,
            },
            host_memory_bytes: 68_719_476_736,
            gpus: Measured::measured(vec![GpuDescription {
                model: label("nvidia-geforce-rtx-4090"),
                memory_bytes: 25_757_220_864,
            }]),
            gpu_driver: Measured::measured(label("560.94")),
            gpu_power_clock: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
            power_source: Measured::measured(PowerSource::Ac),
            displays_on_gpu: Measured::measured(1),
        },
        workload: Measured::not_measured(NotMeasuredReason::NotApplicable),
        client: ClientDescription {
            name: label("yougori-runner-collector"),
            version: label("1.1.2"),
            region: label("local"),
            placement: ClientPlacement::SameHost,
        },
        load: LoadDescription {
            concurrent_requests: 1,
            arrival: ArrivalMode::Sequential,
        },
        state: Measured::not_measured(NotMeasuredReason::NotApplicable),
        launch: LaunchDescription {
            image: test_digest("image"),
            backend: label("wsl2-cuda"),
        },
        price: Measured::not_measured(NotMeasuredReason::NotApplicable),
        measurements: unmeasured(),
        events: events(
            operation,
            &[
                (0, EventKind::ActivationRequested),
                (millis, EventKind::EngineReadyForShape),
            ],
        ),
        outcome: Outcome::Succeeded,
    }
}

/// A successful request that waited for a demand load of `load_millis` inside its time
/// to first token.
fn demand_record(operation: &str, model: &str, load_millis: u64) -> RunRecord {
    RunRecord {
        scenario: Scenario::Serving,
        state: Measured::measured(StartState {
            temperature: StartTemperature::Warm,
            model_at_arrival: ModelAtArrival::NotLoaded,
            cache_tier: CacheTier::HostMemory,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        }),
        events: events(
            operation,
            &[
                (0, EventKind::RequestAccepted),
                (1, EventKind::LoadStarted),
                (load_millis, EventKind::LoadCompleted),
                (1, EventKind::RequestDequeued),
                (20, EventKind::TokenEmitted),
                (5, EventKind::RequestCompleted),
            ],
        ),
        ..load_record(operation, model, 1)
    }
}

fn configuration(model: &str) -> crate::foundation::evidence::ConfigurationFingerprint {
    ReloadConfiguration::of_record(&load_record("op-config", model, 1))
        .unwrap()
        .fingerprint()
        .unwrap()
}

fn policy() -> CostPolicy {
    CostPolicy {
        minimum_source: SourceClass::HostProbe,
        max_age: Duration::from_secs(600),
        min_samples: 3,
        max_samples_per_configuration: 8,
        max_configurations: 4,
        accept_fake_substrate: false,
    }
}

fn observation(
    record: RunRecord,
    attempt: u64,
    session: ClockSession,
    clock: &ManualClock,
) -> CostObservation {
    CostObservation {
        record,
        source: SourceClass::HostProbe,
        collected_in: session,
        collected_at: clock.now(),
        load: LoadAttemptKey::new("runner-instance-1", attempt),
    }
}

/// A store holding one fresh load sample of `model` per entry of `millis`.
fn store_with(
    model: &str,
    millis: &[u64],
    session: ClockSession,
    clock: &ManualClock,
) -> ObservedCosts {
    let mut store = ObservedCosts::new(policy(), session).unwrap();
    for (index, load) in millis.iter().enumerate() {
        let attempt = u64::try_from(index).unwrap() + 1;
        let record = load_record(&format!("op-load-{model}-{attempt}"), model, *load);
        store
            .ingest(observation(record, attempt, session, clock), clock)
            .unwrap();
    }
    store
}

fn declared(seconds_value: f64) -> DeclaredEstimate {
    DeclaredEstimate {
        load: DurationEstimate::new(
            seconds(seconds_value * 0.8),
            seconds(seconds_value),
            seconds(seconds_value * 1.5),
        )
        .unwrap(),
        source: label("catalog-bytes-over-nominal-bandwidth"),
    }
}

// ---------------------------------------------------------------------------------------
// Observed costs.

#[test]
fn fresh_trusted_samples_become_the_measured_reload_cost() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let store = store_with(
        "model-a",
        &[10_000, 11_000, 12_000, 13_000, 30_000],
        session,
        &clock,
    );
    let cost = store.reload_cost(configuration("model-a"), &declared(20.0), &clock);
    // Shortest, nearest-rank median and nearest-rank p95 of the five samples.
    assert_eq!(cost.value.low(), Duration::from_secs(10));
    assert_eq!(cost.value.expected(), Duration::from_secs(12));
    assert_eq!(cost.value.high(), Duration::from_secs(30));
    assert_eq!(cost.reload_seconds(), 12.0);
    assert_eq!(cost.admission_duration(), Duration::from_secs(30));
    let Basis::Measured {
        configurations,
        samples,
        provenance,
        ..
    } = &cost.basis
    else {
        panic!("fresh trusted samples are measured: {:?}", cost.basis);
    };
    assert_eq!(*samples, 5);
    assert_eq!(
        configurations.iter().copied().collect::<Vec<_>>(),
        vec![configuration("model-a")]
    );
    assert!(matches!(provenance, Provenance::YougoriMeasured(_)));
    assert!(cost.basis.evidence().is_some());

    // Fed to the §2.7 cost-per-byte baseline: with model A's measured 12 s against model
    // B's declared 20 s, A is the cheaper one to reload and is evicted first; with A's
    // declared 25 s, B would have been.
    let view = |key, reload_seconds| ObjectView {
        key,
        kind: ObjectKind::BaseWeights,
        bytes: 14 * GB,
        reload_seconds,
        last_use_step: 1,
        use_count: 1,
        protected: false,
        evictable: true,
    };
    let measured = [
        view("model-a", cost.reload_seconds()),
        view("model-b", 20.0),
    ];
    assert_eq!(CostPerByte.choose_victim(&measured, 2), Some(0));
    let declared_only = [view("model-a", 25.0), view("model-b", 20.0)];
    assert_eq!(CostPerByte.choose_victim(&declared_only, 2), Some(1));

    // Fed to readiness: a deadline 20 s ahead admits on the declared estimate's 15 s
    // pessimistic end, but not on the measured 30 s one.
    let bounds = PrepareBounds {
        max_lead: Duration::from_secs(600),
        max_retention_ttl: Duration::from_secs(60),
    };
    let request = || PrepareRequest {
        operation: op("op-prepare-a"),
        execution: ExecutionId::new("exe-workflow").unwrap(),
        tenant: TenantId::new("tenant-a").unwrap(),
        target: target("model-a"),
        origin: crate::model_memory::math::prefetch::CandidateOrigin::QueuedWork,
        deadline: at(1_020),
        retention_ttl: Duration::from_secs(30),
        cancellation: crate::model_memory::readiness::intent::CancellationToken::new(),
        work: vec![PrepareWork::Step {
            step: PreparationStep::InboundTransfer,
        }],
        assigned_request: None,
    };
    let estimate = store.reload_cost(configuration("model-a"), &declared(10.0), &clock);
    assert!(PrepareOperation::admit(request(), Duration::from_secs(15), &bounds, &clock).is_ok());
    assert!(matches!(
        PrepareOperation::admit(request(), estimate.admission_duration(), &bounds, &clock),
        Err(PrepareRefusal::CannotFinishByDeadline { .. })
    ));
}

#[test]
fn stale_samples_fall_back_to_the_labelled_estimate() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let store = store_with("model-a", &[10_000, 11_000, 12_000], session, &clock);
    clock.advance(Duration::from_secs(601));
    let cost = store.reload_cost(configuration("model-a"), &declared(20.0), &clock);
    assert_eq!(cost.value, declared(20.0).load);
    assert_eq!(
        cost.basis,
        Basis::Estimated {
            source: label("catalog-bytes-over-nominal-bandwidth"),
            reason: EstimateReason::Stale {
                newest_age: Duration::from_secs(601),
                max_age: Duration::from_secs(600),
            },
        }
    );
    assert!(cost.basis.evidence().is_none());
    // Fewer fresh samples than required are not enough either.
    let few = store_with("model-a", &[10_000, 11_000], session, &clock);
    assert!(matches!(
        few.reload_cost(configuration("model-a"), &declared(20.0), &clock)
            .basis,
        Basis::Estimated {
            reason: EstimateReason::TooFewSamples {
                fresh: 2,
                required: 3
            },
            ..
        }
    ));
}

#[test]
fn another_configurations_samples_never_become_this_ones() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let empty = ObservedCosts::new(policy(), session).unwrap();
    assert!(matches!(
        empty
            .reload_cost(configuration("model-a"), &declared(5.0), &clock)
            .basis,
        Basis::Estimated {
            reason: EstimateReason::NoObservations,
            ..
        }
    ));
    let store = store_with("model-a", &[10_000, 11_000, 12_000], session, &clock);
    let other = store.reload_cost(configuration("model-b"), &declared(5.0), &clock);
    assert_eq!(other.value, declared(5.0).load);
    assert!(matches!(
        other.basis,
        Basis::Estimated {
            reason: EstimateReason::OtherConfiguration {
                observed_configurations: 1
            },
            ..
        }
    ));
    // The same model on battery power is another configuration.
    let mut battery = load_record("op-battery", "model-a", 1);
    battery.host.power_source = Measured::measured(PowerSource::Battery);
    let battery = ReloadConfiguration::of_record(&battery)
        .unwrap()
        .fingerprint()
        .unwrap();
    assert_ne!(battery, configuration("model-a"));
    // Transient host readings are not part of it.
    let mut displays = load_record("op-displays", "model-a", 1);
    displays.host.displays_on_gpu = Measured::measured(3);
    assert_eq!(
        ReloadConfiguration::of_record(&displays)
            .unwrap()
            .fingerprint()
            .unwrap(),
        configuration("model-a")
    );
}

#[test]
fn untrusted_records_are_refused_and_labelled() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let mut store = ObservedCosts::new(policy(), session).unwrap();
    let fake = || {
        let mut record = load_record("op-fake", "model-a", 10_000);
        record.substrate = RunSubstrate::FakeTimeControlled;
        record
    };
    assert_eq!(
        store.ingest(observation(fake(), 1, session, &clock), &clock),
        Err(ObservationRefusal::Untrusted {
            configuration: configuration("model-a"),
            reason: UntrustedReason::FakeSubstrate,
        })
    );
    let guest = CostObservation {
        source: SourceClass::GuestReport,
        ..observation(
            load_record("op-guest", "model-a", 10_000),
            2,
            session,
            &clock,
        )
    };
    assert!(matches!(
        store.ingest(guest, &clock),
        Err(ObservationRefusal::Untrusted {
            reason: UntrustedReason::Source {
                source: SourceClass::GuestReport,
                minimum: SourceClass::HostProbe
            },
            ..
        })
    ));
    let restarted = observation(
        load_record("op-old", "model-a", 10_000),
        3,
        ClockSession::generate(),
        &clock,
    );
    assert!(matches!(
        store.ingest(restarted, &clock),
        Err(ObservationRefusal::Untrusted {
            reason: UntrustedReason::OtherClockSession,
            ..
        })
    ));
    let future = CostObservation {
        collected_at: at(1_001),
        ..observation(
            load_record("op-future", "model-a", 10_000),
            4,
            session,
            &clock,
        )
    };
    assert!(matches!(
        store.ingest(future, &clock),
        Err(ObservationRefusal::Untrusted {
            reason: UntrustedReason::CollectedInTheFuture { .. },
            ..
        })
    ));
    // The query says why it fell back: the latest refusal.
    let cost = store.reload_cost(configuration("model-a"), &declared(5.0), &clock);
    assert!(matches!(
        cost.basis,
        Basis::Estimated {
            reason: EstimateReason::Untrusted {
                reason: UntrustedReason::CollectedInTheFuture { .. }
            },
            ..
        }
    ));
    assert_eq!(store.samples(configuration("model-a")), 0);

    // A simulation may accept the fake substrate, and its provenance says so.
    let mut simulation = ObservedCosts::new(
        CostPolicy {
            accept_fake_substrate: true,
            ..policy()
        },
        session,
    )
    .unwrap();
    for attempt in 1..=3 {
        simulation
            .ingest(observation(fake(), attempt, session, &clock), &clock)
            .unwrap();
    }
    let simulated = simulation.reload_cost(configuration("model-a"), &declared(5.0), &clock);
    assert!(matches!(
        simulated.basis,
        Basis::Measured {
            provenance: Provenance::FakeSubstrate(_),
            ..
        }
    ));
}

#[test]
fn waiters_of_one_shared_load_count_once() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let mut store = ObservedCosts::new(policy(), session).unwrap();
    let load = load_record("op-load-7", "model-a", 9_000);
    let first = demand_record("op-request-1", "model-a", 9_000);
    let second = demand_record("op-request-2", "model-a", 9_000);
    assert!(matches!(
        store.ingest(observation(load, 7, session, &clock), &clock),
        Ok(Ingested::Stored { .. })
    ));
    for record in [first, second] {
        assert!(matches!(
            store.ingest(observation(record, 7, session, &clock), &clock),
            Ok(Ingested::SharedLoad { .. })
        ));
    }
    assert_eq!(store.samples(configuration("model-a")), 1);
    assert_eq!(store.shared_loads(), 2);
    // A request's own demand load is a sample too.
    store
        .ingest(
            observation(
                demand_record("op-request-3", "model-a", 8_000),
                8,
                session,
                &clock,
            ),
            &clock,
        )
        .unwrap();
    assert_eq!(store.samples(configuration("model-a")), 2);
    assert!(matches!(
        store
            .reload_cost(configuration("model-a"), &declared(5.0), &clock)
            .basis,
        Basis::Estimated {
            reason: EstimateReason::TooFewSamples {
                fresh: 2,
                required: 3
            },
            ..
        }
    ));
}

#[test]
fn records_that_measure_no_load_or_do_not_validate_are_refused() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let mut store = ObservedCosts::new(policy(), session).unwrap();
    let mut hot = demand_record("op-hot", "model-a", 1);
    hot.state = Measured::measured(StartState {
        temperature: StartTemperature::Hot,
        model_at_arrival: ModelAtArrival::ReadyToServe,
        cache_tier: CacheTier::GpuMemory,
        prefill: PrefillMode::Fresh,
        cold_provenance: ColdProvenance::NotCold,
    });
    hot.events = events(
        "op-hot",
        &[
            (0, EventKind::RequestAccepted),
            (1, EventKind::RequestDequeued),
            (20, EventKind::TokenEmitted),
            (5, EventKind::RequestCompleted),
        ],
    );
    assert_eq!(
        store.ingest(observation(hot, 1, session, &clock), &clock),
        Err(ObservationRefusal::NoLoadInterval)
    );
    let mut inconsistent = load_record("op-bad", "model-a", 1_000);
    inconsistent.measurements.peak_gpu_memory_bytes = Measured::measured(GB);
    inconsistent.measurements.retained_gpu_memory_bytes = Measured::measured(2 * GB);
    assert!(matches!(
        store.ingest(observation(inconsistent, 2, session, &clock), &clock),
        Err(ObservationRefusal::Invalid { .. })
    ));
    let mut unbound = load_record("op-unbound", "model-a", 1_000);
    unbound.engine = Measured::not_measured(NotMeasuredReason::NotRecorded);
    assert_eq!(
        store.ingest(observation(unbound, 3, session, &clock), &clock),
        Err(ObservationRefusal::Unbound { field: "engine" })
    );
    assert_eq!(
        ObservedCosts::new(
            CostPolicy {
                min_samples: 0,
                ..policy()
            },
            session
        ),
        Err(ObservationRefusal::InvalidPolicy {
            field: "min_samples"
        })
    );
}

#[test]
fn resource_inputs_are_the_largest_fresh_measurement_or_the_declared_figure() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let mut store = ObservedCosts::new(policy(), session).unwrap();
    for (attempt, retained) in [(1u64, 14 * GB), (2, 15 * GB), (3, 14 * GB)] {
        let mut record = load_record(&format!("op-load-{attempt}"), "model-a", 9_000);
        record.measurements.retained_gpu_memory_bytes = Measured::measured(retained);
        record.measurements.peak_gpu_memory_bytes = Measured::measured(retained + GB);
        store
            .ingest(observation(record, attempt, session, &clock), &clock)
            .unwrap();
    }
    let declared = DeclaredResources {
        retained_gpu_bytes: 13 * GB,
        peak_gpu_bytes: 16 * GB,
        peak_host_bytes: 2 * GB,
        peak_pinned_host_bytes: GB,
        source: label("catalog"),
    };
    let inputs = store.resources(configuration("model-a"), &declared, &clock);
    assert_eq!(inputs.retained_gpu_bytes.value, 15 * GB);
    assert!(inputs.retained_gpu_bytes.basis.is_measured());
    assert_eq!(inputs.peak_gpu_bytes.value, 16 * GB);
    assert!(inputs.peak_gpu_bytes.basis.is_measured());
    assert_eq!(inputs.peak_host_bytes.value, 2 * GB);
    assert!(matches!(
        inputs.peak_host_bytes.basis,
        Basis::Estimated {
            reason: EstimateReason::NotMeasured,
            ..
        }
    ));
    let elsewhere = store.resources(configuration("model-b"), &declared, &clock);
    assert_eq!(elsewhere.retained_gpu_bytes.value, 13 * GB);
    assert!(!elsewhere.retained_gpu_bytes.basis.is_measured());
}

#[test]
fn the_load_curve_is_fitted_across_configurations_and_falls_back_when_unfit() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let mut store = ObservedCosts::new(policy(), session).unwrap();
    // 2 s fixed plus 3.5 GB/s: 7 GB in 4 s, 14 GB in 6 s.
    let mut attempt = 0;
    for (model, millis) in [("model-7b", 4_000u64), ("model-14b", 6_000)] {
        for _ in 0..3 {
            attempt += 1;
            let record = load_record(&format!("op-load-{attempt}"), model, millis);
            store
                .ingest(observation(record, attempt, session, &clock), &clock)
                .unwrap();
        }
    }
    let declared_curve = LoadCurve {
        fixed_seconds: 1.0,
        bytes_per_second: 10e9,
    };
    let members = [
        (configuration("model-7b"), 7 * GB),
        (configuration("model-14b"), 14 * GB),
    ];
    let curve = store.load_curve(&members, declared_curve, &label("nominal"), &clock);
    assert!((curve.value.fixed_seconds - 2.0).abs() < 1e-9);
    assert!((curve.value.bytes_per_second - 3.5e9).abs() < 1.0);
    let Basis::Measured {
        configurations,
        samples,
        ..
    } = &curve.basis
    else {
        panic!("the curve is measured: {:?}", curve.basis);
    };
    assert_eq!((configurations.len(), *samples), (2, 6));
    // It is the transitions' measured host-to-device curve, with its evidence.
    let curves = MeasuredCurves {
        host_to_device: curve.value,
        device_to_host: declared_curve,
        relative_spread: 0.1,
        planning_seconds_per_work_unit: 1e-5,
        load_cancellation_interval_seconds: 0.5,
        evidence: curve.basis.evidence().unwrap(),
    };
    assert!((curves.host_to_device.seconds(14 * GB) - 6.0).abs() < 1e-6);
    // One size cannot be fitted, and a member without samples falls back.
    let single = store.load_curve(&members[..1], declared_curve, &label("nominal"), &clock);
    assert_eq!(single.value, declared_curve);
    assert!(matches!(
        single.basis,
        Basis::Estimated {
            reason: EstimateReason::CurveUnfit {
                error: ChunkingError::TooFewDistinctSizes
            },
            ..
        }
    ));
    let missing = store.load_curve(
        &[members[0], (configuration("model-70b"), 70 * GB)],
        declared_curve,
        &label("nominal"),
        &clock,
    );
    assert!(matches!(
        missing.basis,
        Basis::Estimated {
            reason: EstimateReason::OtherConfiguration { .. },
            ..
        }
    ));
}

#[test]
fn the_store_is_bounded() {
    let clock = ManualClock::new(at(1_000));
    let session = ClockSession::generate();
    let mut store = ObservedCosts::new(
        CostPolicy {
            max_samples_per_configuration: 3,
            max_configurations: 2,
            ..policy()
        },
        session,
    )
    .unwrap();
    let mut attempt = 0;
    let mut offer = |store: &mut ObservedCosts, model: &str| {
        attempt += 1;
        let record = load_record(&format!("op-load-{attempt}"), model, 5_000);
        store
            .ingest(observation(record, attempt, session, &clock), &clock)
            .unwrap();
        clock.advance(Duration::from_secs(1));
    };
    for _ in 0..5 {
        offer(&mut store, "model-a");
    }
    assert_eq!(store.samples(configuration("model-a")), 3);
    assert_eq!(store.dropped_samples(), 2);
    offer(&mut store, "model-b");
    offer(&mut store, "model-c");
    // Model A was observed least recently and was dropped for model C.
    assert_eq!(store.samples(configuration("model-a")), 0);
    assert_eq!(store.samples(configuration("model-c")), 1);
    assert_eq!(store.dropped_configurations(), 1);
}

// ---------------------------------------------------------------------------------------
// The governor against the CORE-03 ledger.

fn machine() -> Digest {
    test_digest("workstation")
}

fn gpu() -> GpuDeviceKey {
    GpuDeviceKey {
        machine: machine(),
        device: test_digest("gpu-0"),
    }
}

fn vram() -> ResourceKey {
    ResourceKey::vram(gpu())
}

fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

fn workflow() -> ExecutionId {
    ExecutionId::new("exe-workflow").unwrap()
}

fn ledger(clock: &Arc<ManualClock>, vram_gb: u64) -> Ledger<Arc<ManualClock>> {
    let mut ledger = Ledger::new(
        Arc::clone(clock),
        HostSubject { machine: machine() },
        LedgerConfig {
            queue: QueueLimits {
                max_entries: 16,
                max_entries_per_tenant: 16,
                max_wait: Duration::from_secs(600),
            },
            grant_ttl: Duration::from_secs(600),
            unmanaged_usage_max_age: Duration::from_secs(3_600),
        },
    );
    ledger
        .declare_capacity(
            vram(),
            CapacityDeclaration {
                total: vram_gb * GB,
                supervisor_reserve: 0,
                unmanaged_in_use: 0,
                source: SourceClass::HostProbe,
            },
        )
        .unwrap();
    ledger
        .set_tenant_budget(tenant(), vram(), u64::MAX)
        .unwrap();
    ledger
}

fn governor_config() -> GovernorConfig {
    GovernorConfig {
        execution: ExecutionId::new("exe-placement-governor").unwrap(),
        prepare: PrepareBounds {
            max_lead: Duration::from_secs(900),
            max_retention_ttl: Duration::from_secs(120),
        },
        max_active: 4,
        max_lookahead: 3,
        max_speculative_bytes: 30 * GB,
        max_outcomes: 32,
        promotion_wait: Duration::from_secs(60),
        // One per saved millisecond, one per wasted gigabyte.
        objective: Objective::new(1.0, 1e-9, 0.0, 0.0).unwrap(),
    }
}

fn governor() -> PreparationGovernor {
    let mut governor = PreparationGovernor::new(governor_config()).unwrap();
    governor.enable_workflow_intent();
    governor
}

fn estimated_cost(seconds_value: f64) -> ReloadCost {
    Labelled {
        value: declared(seconds_value).load,
        basis: Basis::Estimated {
            source: label("catalog-bytes-over-nominal-bandwidth"),
            reason: EstimateReason::NoObservations,
        },
    }
}

fn vram_gb(gb: u64) -> Amounts {
    Amounts::new().vram_bytes(gpu(), gb * GB)
}

fn base() -> PrerequisiteDemand {
    PrerequisiteDemand {
        key: PrerequisiteKey::new(test_digest("base-14b")),
        demand: vram_gb(14),
    }
}

/// A step preparing `model` by `deadline_seconds`, holding `own_gb` itself.
fn step(name: &str, model: &str, deadline_seconds: u64, own_gb: u64) -> DeclaredStep {
    DeclaredStep {
        operation: op(name),
        target: target(model),
        deadline: at(deadline_seconds),
        retention_ttl: Duration::from_secs(60),
        work: vec![
            PrepareWork::Step {
                step: PreparationStep::Reserve,
            },
            PrepareWork::Step {
                step: PreparationStep::InboundTransfer,
            },
            PrepareWork::Step {
                step: PreparationStep::Verify,
            },
        ],
        assigned_request: None,
        lease: LeaseId::new(7),
        probability: 1.0,
        cost: estimated_cost(4.0),
        demand: if own_gb == 0 {
            Amounts::new()
        } else {
            vram_gb(own_gb)
        },
        prerequisites: Vec::new(),
    }
}

fn intent(steps: Vec<DeclaredStep>) -> WorkflowIntent {
    WorkflowIntent {
        execution: workflow(),
        tenant: tenant(),
        steps,
    }
}

fn active(_: LeaseId) -> Option<LeaseState> {
    Some(LeaseState::Active)
}

fn admitted(report: &DeclarationReport, index: usize) -> bool {
    matches!(report.steps[index].outcome, StepOutcome::Admitted { .. })
}

fn declined(report: &DeclarationReport, index: usize) -> &DeclineReason {
    match &report.steps[index].outcome {
        StepOutcome::Declined { reason } => reason,
        other => panic!("step {index} was not declined: {other:?}"),
    }
}

fn other_provenance(execution: &str) -> LedgerProvenance {
    LedgerProvenance {
        requester: Requester::ModelPlacement,
        execution: ExecutionId::new(execution).unwrap(),
        operation: op(&format!("op-{execution}")),
        tenant: tenant(),
        purpose: CostPurpose::Compute,
        retry_number: 0,
    }
}

#[test]
fn demand_only_is_the_default_and_prepares_nothing() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let mut governor = PreparationGovernor::new(governor_config()).unwrap();
    assert_eq!(
        governor.mode(),
        PreparationMode::DemandOnly {
            cause: RollbackCause::Default
        }
    );
    let report = governor.declare(
        intent(vec![step("op-a", "model-a", 160, 4)]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert_eq!(
        declined(&report, 0),
        &DeclineReason::DemandOnly {
            cause: RollbackCause::Default
        }
    );
    assert_eq!(ledger.open_reservations().count(), 0);
    assert_eq!(governor.active().count(), 0);
    assert_eq!(
        PreparationGovernor::new(GovernorConfig {
            max_lookahead: 0,
            ..governor_config()
        })
        .unwrap_err(),
        GovernorError::InvalidConfig {
            field: "max_lookahead"
        }
    );
}

#[test]
fn declared_steps_are_prepared_within_the_lookahead_and_byte_bounds() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 48);
    let mut governor = governor();
    let steps = vec![
        step("op-a", "model-a", 160, 14),
        step("op-b", "model-b", 170, 14),
        step("op-c", "model-c", 180, 14),
        step("op-d", "model-d", 190, 1),
    ];
    let report = governor.declare(intent(steps.clone()), &mut ledger, &active, &*clock);
    assert!(admitted(&report, 0));
    assert!(admitted(&report, 1));
    // 28 GB held; another 14 GB would pass the 30 GB bound.
    assert_eq!(
        declined(&report, 2),
        &DeclineReason::SpeculativeBytes {
            requested: 14 * GB,
            held: 28 * GB,
            limit: 30 * GB
        }
    );
    assert_eq!(declined(&report, 3), &DeclineReason::BeyondLookahead);
    assert_eq!(ledger.reserved(vram()), 28 * GB);
    assert_eq!(governor.speculative_bytes(), 28 * GB);
    // Every reservation is background work of the placement governor under the workflow.
    for record in ledger.open_reservations() {
        assert_eq!(record.priority(), Priority::Background);
        assert_eq!(record.provenance().requester, Requester::ModelPlacement);
        assert_eq!(record.provenance().execution, workflow());
    }
    // Declaring the same steps again keeps what is being prepared.
    let again = governor.declare(intent(steps[..2].to_vec()), &mut ledger, &active, &*clock);
    assert_eq!(again.steps[0].outcome, StepOutcome::AlreadyPreparing);
    assert!(again.superseded.is_empty());
    let mut limited = PreparationGovernor::new(GovernorConfig {
        max_active: 1,
        ..governor_config()
    })
    .unwrap();
    limited.enable_workflow_intent();
    let report = limited.declare(
        intent(vec![
            step("op-e", "model-e", 160, 1),
            step("op-f", "model-f", 160, 1),
        ]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert_eq!(
        declined(&report, 1),
        &DeclineReason::ActiveLimit { max_active: 1 }
    );
    // Tenant budgets are the ledger's: a step past its tenant's budget is refused there.
    let small = TenantId::new("tenant-small").unwrap();
    ledger
        .set_tenant_budget(small.clone(), vram(), 2 * GB)
        .unwrap();
    let mut other = PreparationGovernor::new(governor_config()).unwrap();
    other.enable_workflow_intent();
    let report = other.declare(
        WorkflowIntent {
            execution: ExecutionId::new("exe-small").unwrap(),
            tenant: small,
            steps: vec![step("op-g", "model-g", 160, 4)],
        },
        &mut ledger,
        &active,
        &*clock,
    );
    assert!(matches!(declined(&report, 0), DeclineReason::Capacity(_)));
}

#[test]
fn the_expected_value_uses_the_measured_reload_cost() {
    let clock = Arc::new(ManualClock::new(at(1_000)));
    let session = ClockSession::generate();
    let store = store_with("model-a", &[30_000, 31_000, 32_000], session, &clock);
    let mut ledger = ledger(&clock, 48);
    let mut governor = governor();
    // A branch taken one time in ten, holding 8 GB: worth it only if loading on demand is
    // slow. The declared 50 ms says no; the measured 31 s says yes.
    let branch = |cost| DeclaredStep {
        probability: 0.1,
        cost,
        ..step("op-branch", "model-a", 1_100, 8)
    };
    let declared_cost = store.reload_cost(configuration("model-b"), &declared(0.05), &clock);
    assert!(!declared_cost.basis.is_measured());
    let report = governor.declare(
        intent(vec![branch(declared_cost)]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert!(matches!(
        declined(&report, 0),
        DeclineReason::NotWorthIt { expected_value } if *expected_value < 0.0
    ));
    let measured = store.reload_cost(configuration("model-a"), &declared(0.05), &clock);
    assert!(measured.basis.is_measured());
    let report = governor.declare(
        intent(vec![branch(measured)]),
        &mut ledger,
        &active,
        &*clock,
    );
    let StepOutcome::Admitted { expected_value, .. } = report.steps[0].outcome else {
        panic!("admitted: {:?}", report.steps[0].outcome);
    };
    // 0.1 × 31,000 ms − 0.9 × 8 GB.
    assert!((expected_value - (3_100.0 - 7.2)).abs() < 1e-6);
    // The pessimistic 32 s must fit before the deadline: 50 s ahead admits, 20 s does not.
    let late = DeclaredStep {
        operation: op("op-late"),
        deadline: at(1_020),
        ..branch(store.reload_cost(configuration("model-a"), &declared(0.05), &clock))
    };
    let report = governor.declare(
        intent(vec![step("op-branch", "model-a", 1_100, 8), late]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert!(matches!(
        declined(&report, 1),
        DeclineReason::Prepare(PrepareRefusal::CannotFinishByDeadline { .. })
    ));
}

#[test]
fn a_shared_base_is_reserved_once_and_released_by_its_last_holder() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let mut governor = governor();
    let adapter = |name: &str, model: &str| DeclaredStep {
        prerequisites: vec![base()],
        ..step(name, model, 200, 1)
    };
    let report = governor.declare(
        intent(vec![adapter("op-a", "model-a"), adapter("op-b", "model-b")]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert!(admitted(&report, 0) && admitted(&report, 1));
    // One base reservation for both, under the governor's own execution.
    assert_eq!(ledger.reserved(vram()), 16 * GB);
    assert_eq!(ledger.open_reservations().count(), 3);
    assert_eq!(governor.speculative_bytes(), 16 * GB);
    assert_eq!(governor.shared().holders(&tenant(), base().key), 2);
    let base_reservation = governor
        .shared()
        .holding(&tenant(), base().key)
        .and_then(Holding::reservation)
        .unwrap();
    assert_eq!(
        ledger
            .reservation(base_reservation)
            .unwrap()
            .provenance()
            .execution,
        governor_config().execution
    );
    let events = governor.poll(&mut ledger, &active, &*clock);
    assert_eq!(events.len(), 2);
    let grant_a = governor.begin_work(&op("op-a"), &mut ledger).unwrap();
    let grant_b = governor.begin_work(&op("op-b"), &mut ledger).unwrap();
    assert_eq!(grant_a.prerequisites, vec![base_reservation]);
    assert_eq!(grant_b.prerequisites, vec![base_reservation]);
    // The first holder leaves: the base stays for the second.
    assert_eq!(
        governor.finish(&op("op-a"), &mut ledger, &*clock),
        Err(GovernorError::NotUsed {
            operation: op("op-a")
        })
    );
    let first = governor
        .cancel(&op("op-a"), CancelReason::Requester, &mut ledger, &*clock)
        .unwrap();
    assert_eq!(
        first.released[1],
        LedgerRelease::StillShared {
            key: base().key,
            holders: 1
        }
    );
    assert!(ledger.reservation(base_reservation).is_some());
    // The second is used by its request and then finished: the base, in use, counts
    // until the host observes its release.
    governor.complete(&op("op-b"), 15 * GB, &*clock).unwrap();
    assert!(matches!(
        governor.request_arrived(&target("model-b"), &mut ledger, &*clock),
        ArrivalReport::Used {
            prepared_bytes,
            ..
        } if prepared_bytes == 15 * GB
    ));
    let last = governor.finish(&op("op-b"), &mut ledger, &*clock).unwrap();
    assert!(last.used);
    assert_eq!(last.wasted_bytes, 0);
    assert_eq!(
        last.released[1],
        LedgerRelease::AwaitingObservedRelease {
            reservation: base_reservation
        }
    );
    assert_eq!(governor.shared().holders(&tenant(), base().key), 0);
    assert_eq!(
        ledger
            .confirm_release(base_reservation, SourceClass::HostProbe)
            .unwrap(),
        ReleaseOutcome::Released {
            amounts: vram_gb(14)
        }
    );
    assert_eq!(governor.take_outcomes().len(), 2);
}

#[test]
fn a_waiting_shared_base_is_joined_and_followed_until_granted() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let Ok(Admission::Granted(chat)) = ledger.reserve(ReservationRequest::new(
        other_provenance("exe-chat"),
        Priority::Foreground,
        vram_gb(20),
    )) else {
        panic!("the chat model is granted");
    };
    let mut governor = governor();
    let adapter = |name: &str, model: &str| DeclaredStep {
        prerequisites: vec![base()],
        ..step(name, model, 300, 0)
    };
    let report = governor.declare(
        intent(vec![adapter("op-a", "model-a"), adapter("op-b", "model-b")]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert!(admitted(&report, 0) && admitted(&report, 1));
    // One waiting request for both.
    assert_eq!(ledger.queue_len(), 1);
    assert!(matches!(
        governor.shared().holding(&tenant(), base().key),
        Some(Holding::Queued {
            priority: Priority::Background,
            ..
        })
    ));
    assert!(governor.poll(&mut ledger, &active, &*clock).is_empty());
    assert_eq!(
        governor.begin_work(&op("op-a"), &mut ledger),
        Err(GovernorError::NotGranted {
            operation: op("op-a")
        })
    );
    ledger.cancel(chat).unwrap();
    let events = governor.poll(&mut ledger, &active, &*clock);
    assert_eq!(
        events,
        vec![
            GovernorEvent::Granted {
                operation: op("op-a")
            },
            GovernorEvent::Granted {
                operation: op("op-b")
            },
        ]
    );
    assert_eq!(ledger.reserved(vram()), 14 * GB);
}

#[test]
fn a_preparation_waits_in_the_queue_only_until_its_latest_start() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let Ok(Admission::Granted(_)) = ledger.reserve(ReservationRequest::new(
        other_provenance("exe-chat"),
        Priority::Foreground,
        vram_gb(20),
    )) else {
        panic!("the chat model is granted");
    };
    let mut governor = governor();
    // Ready by 130 s with a pessimistic 6 s load: it may start no later than 124 s.
    let report = governor.declare(
        intent(vec![step("op-a", "model-a", 130, 8)]),
        &mut ledger,
        &active,
        &*clock,
    );
    let StepOutcome::Admitted {
        own: Some(Holding::Queued { ticket, .. }),
        ..
    } = report.steps[0].outcome
    else {
        panic!("queued: {:?}", report.steps[0].outcome);
    };
    clock.advance_to(at(124));
    assert!(governor.poll(&mut ledger, &active, &*clock).is_empty());
    clock.advance_to(MonotonicTime::from_nanos(124 * SECOND + MILLIS));
    let events = governor.poll(&mut ledger, &active, &*clock);
    let [GovernorEvent::Ended { outcome }] = events.as_slice() else {
        panic!("ended: {events:?}");
    };
    assert_eq!(outcome.end, PreparationEnd::CapacityRefused { ticket });
    assert_eq!(outcome.released, vec![LedgerRelease::NotQueued { ticket }]);
    assert!(outcome.ended_at < at(130));
    assert_eq!(ledger.queue_len(), 0);
}

#[test]
fn a_lease_cancellation_cancels_the_preparation_and_returns_its_reservation() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let mut governor = governor();
    governor.declare(
        intent(vec![
            step("op-a", "model-a", 200, 4),
            DeclaredStep {
                lease: LeaseId::new(8),
                ..step("op-b", "model-b", 200, 4)
            },
        ]),
        &mut ledger,
        &active,
        &*clock,
    );
    let token = governor.token(&op("op-a")).unwrap();
    let revoked = |lease: LeaseId| {
        (lease == LeaseId::new(7)).then_some(LeaseState::Cancelling {
            cause: CancelCause::Revocation,
            requested_at: at(100),
            bound_at: at(101),
        })
    };
    let events = governor.poll(&mut ledger, &revoked, &*clock);
    let ended: Vec<&PreparationOutcome> = events
        .iter()
        .filter_map(|event| match event {
            GovernorEvent::Ended { outcome } => Some(outcome),
            GovernorEvent::Granted { .. } => None,
        })
        .collect();
    assert_eq!(ended.len(), 2);
    assert_eq!(
        ended[0].end,
        PreparationEnd::Released {
            reason: ReleaseReason::Cancelled {
                reason: CancelReason::Lease {
                    cause: CancelCause::Revocation
                }
            }
        }
    );
    assert!(matches!(
        ended[0].released[0],
        LedgerRelease::Returned { .. }
    ));
    assert_eq!(
        token.reason(),
        Some(CancelReason::Lease {
            cause: CancelCause::Revocation
        })
    );
    // A lease the coordinator no longer knows ends its preparation too.
    assert_eq!(
        ended[1].end,
        PreparationEnd::Released {
            reason: ReleaseReason::Cancelled {
                reason: CancelReason::LeaseEnded
            }
        }
    );
    assert_eq!(ledger.reserved(vram()), 0);
    // Work under a lease that is already cancelled is refused at admission.
    let report = governor.declare(
        intent(vec![step("op-c", "model-c", 200, 4)]),
        &mut ledger,
        &revoked,
        &*clock,
    );
    assert_eq!(
        declined(&report, 0),
        &DeclineReason::Prepare(PrepareRefusal::AlreadyCancelled {
            reason: CancelReason::Lease {
                cause: CancelCause::Revocation
            }
        })
    );
    assert_eq!(ledger.open_reservations().count(), 0);
}

#[test]
fn deadlines_and_retention_ttls_return_the_reservation() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let mut governor = governor();
    governor.declare(
        intent(vec![
            step("op-late", "model-a", 120, 4),
            step("op-unused", "model-b", 120, 4),
        ]),
        &mut ledger,
        &active,
        &*clock,
    );
    governor.poll(&mut ledger, &active, &*clock);
    let late = governor.begin_work(&op("op-late"), &mut ledger).unwrap();
    governor.begin_work(&op("op-unused"), &mut ledger).unwrap();
    clock.advance_to(at(110));
    assert!(matches!(
        governor
            .complete(&op("op-unused"), 4 * GB, &*clock)
            .unwrap(),
        PrepareState::Ready { .. }
    ));
    // The late work is still running at its deadline and is released past it; its
    // reservation is in use, so it counts until the host observes the release.
    clock.advance_to(MonotonicTime::from_nanos(120 * SECOND + 1));
    let events = governor.poll(&mut ledger, &active, &*clock);
    let [GovernorEvent::Ended { outcome }] = events.as_slice() else {
        panic!("one ended: {events:?}");
    };
    assert_eq!(
        outcome.end,
        PreparationEnd::Released {
            reason: ReleaseReason::DeadlineMissed
        }
    );
    assert_eq!(
        outcome.released,
        vec![LedgerRelease::AwaitingObservedRelease {
            reservation: late.own.unwrap()
        }]
    );
    // The ready state no request used expires after its 60 s TTL and was wasted.
    clock.advance_to(at(171));
    let events = governor.poll(&mut ledger, &active, &*clock);
    let [GovernorEvent::Ended { outcome }] = events.as_slice() else {
        panic!("one ended: {events:?}");
    };
    assert_eq!(
        outcome.end,
        PreparationEnd::Released {
            reason: ReleaseReason::Expired
        }
    );
    assert!(!outcome.used);
    assert_eq!(outcome.wasted_bytes, 4 * GB);
}

#[test]
fn promotion_refiles_a_waiting_preparation_ahead_of_background_work() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 10);
    ledger.set_queue_fairness(QueueFairness {
        foreground_first: true,
        ..QueueFairness::ARRIVAL_ORDER
    });
    let Ok(Admission::Granted(chat)) = ledger.reserve(ReservationRequest::new(
        other_provenance("exe-chat"),
        Priority::Foreground,
        vram_gb(8),
    )) else {
        panic!("the chat model is granted");
    };
    // A batch job queued earlier for 7 GB of background work.
    let Ok(Admission::Queued { ticket: batch, .. }) = ledger.reserve(
        ReservationRequest::new(
            other_provenance("exe-batch"),
            Priority::Background,
            vram_gb(7),
        )
        .wait_up_to(Duration::from_secs(300)),
    ) else {
        panic!("the batch job waits");
    };
    let mut governor = governor();
    let report = governor.declare(
        intent(vec![step("op-a", "model-a", 400, 4)]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert!(matches!(
        report.steps[0].outcome,
        StepOutcome::Admitted {
            own: Some(Holding::Queued {
                priority: Priority::Background,
                ..
            }),
            ..
        }
    ));
    // The request arrives while the preparation still waits: promoted, re-filed as
    // foreground.
    let ArrivalReport::Promoted {
        own: PromotionEffect::RefiledQueued { .. },
        prerequisites,
        ..
    } = governor.request_arrived(&target("model-a"), &mut ledger, &*clock)
    else {
        panic!("promoted");
    };
    assert!(prerequisites.is_empty());
    assert_eq!(ledger.queue_len(), 2);
    // Capacity returns: foreground first serves the promoted request before the batch
    // job that arrived earlier, which no longer fits.
    ledger.cancel(chat).unwrap();
    let events = governor.poll(&mut ledger, &active, &*clock);
    assert_eq!(
        events,
        vec![GovernorEvent::Granted {
            operation: op("op-a")
        }]
    );
    assert_eq!(ledger.queue_position(batch), Some(0));
    let grant = governor.begin_work(&op("op-a"), &mut ledger).unwrap();
    let reservation = grant.own.unwrap();
    assert_eq!(
        ledger.reservation(reservation).unwrap().priority(),
        Priority::Foreground
    );
    governor.complete(&op("op-a"), 4 * GB, &*clock).unwrap();
    let outcome = governor.finish(&op("op-a"), &mut ledger, &*clock).unwrap();
    assert!(outcome.used);
    assert_eq!(outcome.prepared_bytes, 4 * GB);
    ledger
        .confirm_release(reservation, SourceClass::HostProbe)
        .unwrap();
    assert_eq!(ledger.queue_len(), 0);
}

#[test]
fn rolling_back_cancels_speculative_preparations_and_keeps_demand_work() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let mut governor = governor();
    governor.declare(
        intent(vec![
            step("op-a", "model-a", 200, 4),
            step("op-b", "model-b", 200, 4),
        ]),
        &mut ledger,
        &active,
        &*clock,
    );
    governor.poll(&mut ledger, &active, &*clock);
    governor.begin_work(&op("op-a"), &mut ledger).unwrap();
    governor.complete(&op("op-a"), 4 * GB, &*clock).unwrap();
    assert!(matches!(
        governor.request_arrived(&target("model-a"), &mut ledger, &*clock),
        ArrivalReport::Used { .. }
    ));
    let outcomes = governor.roll_back(RollbackCause::Operator, &mut ledger, &*clock);
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].operation, op("op-b"));
    assert_eq!(
        outcomes[0].end,
        PreparationEnd::RolledBack {
            cause: RollbackCause::Operator
        }
    );
    assert!(matches!(
        outcomes[0].released[0],
        LedgerRelease::Returned { .. }
    ));
    // The served preparation stays; new steps are declined.
    assert_eq!(
        governor.active().cloned().collect::<Vec<_>>(),
        vec![op("op-a")]
    );
    assert_eq!(ledger.reserved(vram()), 4 * GB);
    let report = governor.declare(
        intent(vec![step("op-c", "model-c", 200, 1)]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert_eq!(
        declined(&report, 0),
        &DeclineReason::DemandOnly {
            cause: RollbackCause::Operator
        }
    );
}

#[test]
fn the_mode_controller_rolls_back_and_recovers() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let mut governor = governor();
    governor.declare(
        intent(vec![step("op-a", "model-a", 200, 4)]),
        &mut ledger,
        &active,
        &*clock,
    );
    let token = governor.token(&op("op-a")).unwrap();
    let mut controller = ModeController::new(ModeThresholds {
        enter_below_confidence: 0.3,
        exit_at_confidence: 0.5,
        enter_above_load_fraction: 0.9,
        exit_at_load_fraction: 0.7,
        enter_above_calibration_error: 0.2,
        exit_at_calibration_error: 0.1,
        recovery_dwell: Duration::from_secs(10),
    })
    .unwrap();
    let healthy = ModeSignals {
        confidence: 0.9,
        load_fraction: 0.5,
        calibration_error: 0.05,
    };
    controller
        .observe(
            at(100),
            ModeSignals {
                load_fraction: 1.2,
                ..healthy
            },
        )
        .unwrap();
    let outcomes = governor.follow(&controller, &mut ledger, &*clock);
    assert_eq!(
        outcomes[0].end,
        PreparationEnd::RolledBack {
            cause: RollbackCause::Controller {
                reason: DemandOnlyReason::Overload
            }
        }
    );
    assert_eq!(
        token.reason(),
        Some(CancelReason::DemandOnly {
            reason: DemandOnlyReason::Overload
        })
    );
    assert_eq!(ledger.reserved(vram()), 0);
    // The controller recovers after its dwell, and so does preparation.
    controller.observe(at(101), healthy).unwrap();
    controller.observe(at(111), healthy).unwrap();
    assert!(governor
        .follow(&controller, &mut ledger, &*clock)
        .is_empty());
    assert_eq!(governor.mode(), PreparationMode::WorkflowIntent);
    // An operator's rollback is not undone by the controller.
    governor.roll_back(RollbackCause::Operator, &mut ledger, &*clock);
    governor.follow(&controller, &mut ledger, &*clock);
    assert_eq!(
        governor.mode(),
        PreparationMode::DemandOnly {
            cause: RollbackCause::Operator
        }
    );
}

#[test]
fn a_redeclaration_supersedes_steps_it_no_longer_names() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let mut governor = governor();
    governor.declare(
        intent(vec![
            step("op-a", "model-a", 200, 4),
            step("op-b", "model-b", 200, 4),
        ]),
        &mut ledger,
        &active,
        &*clock,
    );
    let report = governor.declare(
        intent(vec![
            step("op-b", "model-b", 200, 4),
            step("op-c", "model-c", 200, 4),
        ]),
        &mut ledger,
        &active,
        &*clock,
    );
    assert_eq!(report.superseded.len(), 1);
    assert_eq!(report.superseded[0].operation, op("op-a"));
    assert_eq!(
        report.superseded[0].end,
        PreparationEnd::Released {
            reason: ReleaseReason::Cancelled {
                reason: CancelReason::Superseded
            }
        }
    );
    assert_eq!(report.steps[0].outcome, StepOutcome::AlreadyPreparing);
    assert!(admitted(&report, 1));
    assert_eq!(ledger.reserved(vram()), 8 * GB);
}

#[test]
fn a_revoked_workflow_ends_its_preparation_and_its_last_holder_returns_the_base() {
    let clock = Arc::new(ManualClock::new(at(100)));
    let mut ledger = ledger(&clock, 24);
    let mut governor = governor();
    governor.declare(
        intent(vec![
            DeclaredStep {
                prerequisites: vec![base()],
                ..step("op-a", "model-a", 200, 1)
            },
            DeclaredStep {
                prerequisites: vec![base()],
                ..step("op-b", "model-b", 200, 1)
            },
        ]),
        &mut ledger,
        &active,
        &*clock,
    );
    governor.poll(&mut ledger, &active, &*clock);
    let working = governor.begin_work(&op("op-a"), &mut ledger).unwrap();
    // Revocation cancels the workflow's own reservations, not the governor's base: the
    // one not yet created returns at once, the one in use starts releasing.
    let report = ledger.cancel_execution(&workflow());
    assert_eq!((report.released.len(), report.pending.len()), (1, 1));
    let events = governor.poll(&mut ledger, &active, &*clock);
    let ended: Vec<&PreparationOutcome> = events
        .iter()
        .filter_map(|event| match event {
            GovernorEvent::Ended { outcome } => Some(outcome),
            GovernorEvent::Granted { .. } => None,
        })
        .collect();
    assert_eq!(ended.len(), 2);
    assert_eq!(
        ended[0].end,
        PreparationEnd::ReservationLost {
            reservation: working.own.unwrap()
        }
    );
    assert_eq!(
        ended[0].released,
        vec![
            LedgerRelease::AwaitingObservedRelease {
                reservation: working.own.unwrap()
            },
            LedgerRelease::StillShared {
                key: base().key,
                holders: 1
            },
        ]
    );
    assert!(matches!(
        ended[1].released[0],
        LedgerRelease::AlreadyClosed { .. }
    ));
    // The last holder returns the base, which is in use until the host observes it.
    assert_eq!(
        ended[1].released[1],
        LedgerRelease::AwaitingObservedRelease {
            reservation: working.prerequisites[0]
        }
    );
    assert_eq!(governor.shared().holders(&tenant(), base().key), 0);
}
