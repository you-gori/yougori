//! Test fixtures: valid records built on a manual clock, and the golden record.

use std::time::Duration;

use chrono::{NaiveDate, TimeZone, Utc};

use super::bench::{BenchId, ClaimUnderTest, ReproducibilityRecord, StatisticalMethod};
use super::claims::{ClaimConfiguration, ThirdPartyClaim};
use super::cost::{PriceProvenance, PriceQuote, PriceUnit};
use super::error::ReportError;
use super::events::{EventKind, EventRecorder, IntervalKind, RecordedEvent, SwitchMode};
use super::measured::{Measured, NonNegative, NotMeasuredReason};
use super::record::{
    AnswerVerdict, ArrivalMode, AttemptIdentity, AttemptRole, BuildIdentity, CacheTier,
    ClientDescription, ClientPlacement, ColdProvenance, CpuDescription, EngineIdentity,
    FailureKind, FixtureFamily, GpuDescription, HostDescription, LaunchDescription,
    LoadDescription, ModelAtArrival, ModelIdentity, ModelRevision, NonceDisclosure, Offload,
    Outcome, PowerSource, Precision, PrefillMode, ReasoningCheck, ReasoningTrace, RunMeasurements,
    RunRecord, RunSubstrate, Sampling, Scenario, StartState, StartTemperature, Workload,
};
use super::stats::PercentileMethod;
use super::text::{ClockId, CommitHash, Disclosure, FixtureRef, Label, PublicUrl};
use super::SchemaVersion;
use crate::foundation::ids::{
    digest, ExecutionCategory, ExecutionId, ManualClock, MonotonicTime, OperationId,
    SandboxBootGeneration,
};

pub(crate) fn label(value: &str) -> Label {
    Label::new(value).unwrap()
}

pub(crate) fn op(value: &str) -> OperationId {
    OperationId::new(value).unwrap()
}

fn test_digest(part: &str) -> crate::foundation::ids::Digest {
    digest("yougori/test/v1", &[part.as_bytes()])
}

/// Records `steps` (milliseconds after the previous event) on one manual clock that
/// starts at 5 s.
pub(crate) fn events(operation: &str, steps: Vec<(u64, EventKind)>) -> Vec<RecordedEvent> {
    let clock = ManualClock::new(MonotonicTime::from_nanos(5_000_000_000));
    let mut recorder =
        EventRecorder::new(op(operation), ClockId::new(label("host-monotonic")), &clock);
    for (after_millis, event) in steps {
        clock.advance(Duration::from_millis(after_millis));
        recorder.record(event);
    }
    recorder.into_events()
}

pub(crate) fn failed(failure: FailureKind) -> Outcome {
    Outcome::Failed {
        failure,
        component: label("harness"),
        code: label("fixture-failure"),
    }
}

fn not(reason: NotMeasuredReason) -> Measured<u64> {
    Measured::not_measured(reason)
}

fn attempt(bench: BenchId, variant: &str, operation: &str) -> AttemptIdentity {
    AttemptIdentity {
        bench,
        variant: label(variant),
        execution: ExecutionId::new("exe-bench-run-1").unwrap(),
        operation: op(operation),
        role: AttemptRole::Initial,
        burst: 0,
        deadline_nanos: not(NotMeasuredReason::NotApplicable),
    }
}

fn build() -> BuildIdentity {
    BuildIdentity {
        plan: test_digest("plan"),
        runner_build: test_digest("runner"),
        runner_version: label("1.1.2"),
    }
}

fn host() -> HostDescription {
    HostDescription {
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
    }
}

fn client() -> ClientDescription {
    ClientDescription {
        name: label("yougori-bench-client"),
        version: label("1.1.2"),
        region: label("local"),
        placement: ClientPlacement::SameHost,
    }
}

fn model() -> Measured<ModelIdentity> {
    Measured::measured(ModelIdentity {
        revision: ModelRevision::Commit {
            hash: CommitHash::new("0123456789abcdef0123456789abcdef01234567").unwrap(),
        },
        licenses: vec![label("Apache-2.0")],
        weights: test_digest("weights"),
        tokenizer: test_digest("tokenizer"),
        chat_template: test_digest("template"),
    })
}

fn precision() -> Measured<Precision> {
    Measured::measured(Precision {
        weight_dtype: label("bf16"),
        quantization: label("none"),
        kv_cache_dtype: label("bf16"),
    })
}

fn engine() -> Measured<EngineIdentity> {
    Measured::measured(EngineIdentity {
        name: label("vllm"),
        version: label("0.29.0"),
    })
}

fn workload() -> Measured<Workload> {
    Measured::measured(Workload {
        fixture: FixtureRef::new(
            label("code-fixture-1"),
            test_digest("code-fixture-1"),
            Disclosure::PermittedSynthetic,
        ),
        family: FixtureFamily::Code,
        input_tokens: 512,
        max_output_tokens: 128,
        sampling: Sampling {
            temperature: NonNegative::ZERO,
            top_p: Measured::not_measured(NotMeasuredReason::NotApplicable),
            top_k: Measured::not_measured(NotMeasuredReason::NotApplicable),
            seed: Measured::measured(7),
        },
        tool_schema: Measured::not_measured(NotMeasuredReason::NotApplicable),
        paired: false,
        cold_test_nonce: NonceDisclosure::NotUsed,
    })
}

fn measurements(output_tokens: Measured<u64>) -> RunMeasurements {
    RunMeasurements {
        output_tokens,
        prefill_tokens_per_second: Measured::not_measured(NotMeasuredReason::NotRecorded),
        aggregate_decode_tokens_per_second: Measured::not_measured(NotMeasuredReason::NotRecorded),
        speculative: Measured::not_measured(NotMeasuredReason::NotApplicable),
        peak_gpu_memory_bytes: not(NotMeasuredReason::NotRecorded),
        retained_gpu_memory_bytes: not(NotMeasuredReason::NotRecorded),
        peak_host_memory_bytes: not(NotMeasuredReason::NotRecorded),
        retained_host_memory_bytes: not(NotMeasuredReason::NotRecorded),
        peak_pinned_host_memory_bytes: not(NotMeasuredReason::NotRecorded),
        transferred_bytes: not(NotMeasuredReason::NotRecorded),
        storage_read_bytes: not(NotMeasuredReason::NotRecorded),
        energy_joules: Measured::not_measured(NotMeasuredReason::InstrumentUnavailable),
        offload: Measured::measured(Offload::NoOffload),
        first_run: Measured::not_measured(NotMeasuredReason::NotApplicable),
        owner_return: Measured::not_measured(NotMeasuredReason::NotApplicable),
        reasoning: Measured::not_measured(NotMeasuredReason::NotApplicable),
    }
}

/// A successful reasoning request: [`serving_record`] on a reasoning fixture whose
/// 120-token trace preceded a correct final answer.
pub(crate) fn reasoning_record(operation: &str, ttft_millis: u64) -> RunRecord {
    let mut record = serving_record(operation, ttft_millis);
    if let Measured::Measured { value } = &mut record.workload {
        value.family = FixtureFamily::Reasoning;
        value.fixture = FixtureRef::new(
            label("gsm8k-style-item-7"),
            test_digest("gsm8k-style-item-7"),
            Disclosure::PermittedSynthetic,
        );
    }
    record.measurements.reasoning = Measured::measured(ReasoningCheck {
        answer_key: FixtureRef::new(
            label("gsm8k-style-answer-7"),
            test_digest("gsm8k-style-answer-7"),
            Disclosure::PermittedSynthetic,
        ),
        trace: ReasoningTrace::Present {
            tokens: Measured::measured(120),
        },
        final_answer: AnswerVerdict::Correct,
    });
    record
}

/// A successful hot BENCH-01 request: 5 ms queue wait, first token at `ttft_millis`,
/// then two more tokens 20 ms apart.
pub(crate) fn serving_record(operation: &str, ttft_millis: u64) -> RunRecord {
    RunRecord {
        schema_version: SchemaVersion,
        attempt: attempt(BenchId::Bench01, "load-8", operation),
        scenario: Scenario::Serving,
        substrate: RunSubstrate::FakeTimeControlled,
        build: build(),
        execution_category: ExecutionCategory::SharedKernelGpuRuntime,
        model: model(),
        precision: precision(),
        engine: engine(),
        host: host(),
        workload: workload(),
        client: client(),
        load: LoadDescription {
            concurrent_requests: 8,
            arrival: ArrivalMode::Sequential,
        },
        state: Measured::measured(StartState {
            temperature: StartTemperature::Hot,
            model_at_arrival: ModelAtArrival::ReadyToServe,
            cache_tier: CacheTier::GpuMemory,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        }),
        launch: LaunchDescription {
            image: test_digest("image"),
            backend: label("wsl2-cuda"),
        },
        price: Measured::not_measured(NotMeasuredReason::NotApplicable),
        measurements: measurements(Measured::measured(3)),
        events: events(
            operation,
            vec![
                (0, EventKind::RequestAccepted),
                (5, EventKind::RequestDequeued),
                (ttft_millis.saturating_sub(5), EventKind::TokenEmitted),
                (20, EventKind::TokenEmitted),
                (20, EventKind::TokenEmitted),
                (1, EventKind::RequestCompleted),
            ],
        ),
        outcome: Outcome::Succeeded,
    }
}

/// A successful BENCH-05 VM create whose first guest command succeeds after
/// `first_command_millis`.
pub(crate) fn vm_record(operation: &str, first_command_millis: u64) -> RunRecord {
    let guest = ExecutionId::new(format!("exe-vm-{operation}")).unwrap();
    let boot = SandboxBootGeneration::FIRST;
    let applicable = Measured::not_measured(NotMeasuredReason::NotApplicable);
    RunRecord {
        attempt: attempt(BenchId::Bench05, "burst-100", operation),
        scenario: Scenario::VmProvisioning,
        execution_category: ExecutionCategory::VmSandbox,
        model: Measured::not_measured(NotMeasuredReason::NotApplicable),
        precision: Measured::not_measured(NotMeasuredReason::NotApplicable),
        engine: Measured::not_measured(NotMeasuredReason::NotApplicable),
        workload: Measured::not_measured(NotMeasuredReason::NotApplicable),
        load: LoadDescription {
            concurrent_requests: 100,
            arrival: ArrivalMode::Burst { size: 100 },
        },
        state: Measured::not_measured(NotMeasuredReason::NotApplicable),
        launch: LaunchDescription {
            image: test_digest("guest-image"),
            backend: label("firecracker"),
        },
        measurements: RunMeasurements {
            offload: Measured::not_measured(NotMeasuredReason::NotApplicable),
            ..measurements(applicable)
        },
        events: events(
            operation,
            vec![
                (
                    0,
                    EventKind::VmCreateInitiated {
                        guest: guest.clone(),
                        boot,
                    },
                ),
                (40, EventKind::VmApiAcknowledged),
                (
                    first_command_millis.saturating_sub(40),
                    EventKind::GuestCommandSucceeded { guest, boot },
                ),
            ],
        ),
        ..serving_record(operation, 100)
    }
}

/// A successful BENCH-02 warm reload: model A's last output, a scripted `gap_millis`,
/// then B's request with a demand load of `load_millis`.
pub(crate) fn warm_switch_record(operation: &str, gap_millis: u64, load_millis: u64) -> RunRecord {
    RunRecord {
        attempt: attempt(BenchId::Bench02, "a-b-a-warm", operation),
        scenario: Scenario::Switching {
            mode: SwitchMode::WarmReload,
            controlled_gap_nanos: gap_millis * 1_000_000,
        },
        state: Measured::measured(StartState {
            temperature: StartTemperature::Warm,
            model_at_arrival: ModelAtArrival::NotLoaded,
            cache_tier: CacheTier::HostMemory,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        }),
        events: events(
            operation,
            vec![
                (0, EventKind::ModelAFinalOutput),
                (gap_millis, EventKind::RequestAccepted),
                (1, EventKind::RequestDequeued),
                (1, EventKind::LoadStarted),
                (load_millis, EventKind::LoadCompleted),
                (60, EventKind::TokenEmitted),
                (20, EventKind::TokenEmitted),
                (20, EventKind::TokenEmitted),
                (1, EventKind::RequestCompleted),
            ],
        ),
        ..serving_record(operation, 100)
    }
}

/// A published claim with no reproduction yet.
pub(crate) fn vendor_claim(configuration: ClaimConfiguration) -> ThirdPartyClaim {
    ThirdPartyClaim {
        source: PublicUrl::new("https://example.org/benchmarks/latency").unwrap(),
        published_on: NaiveDate::from_ymd_opt(2026, 3, 2).unwrap(),
        retrieved_on: NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
        configuration,
        metric: label("ttft-p50"),
        value: NonNegative::new(90.0).unwrap(),
        unit: label("ms"),
    }
}

/// `count` successful BENCH-01 attempts run in an authorized disposable environment over
/// three independent bursts, the first token of attempt `index` after
/// `ttft_millis(index)`. Thirty or more give a resolved p50.
pub(crate) fn real_serving_records(
    count: usize,
    ttft_millis: impl Fn(usize) -> u64,
) -> Vec<RunRecord> {
    (0..count)
        .map(|index| {
            let mut record = serving_record(&format!("op-{index}"), ttft_millis(index));
            record.attempt.burst = (index % 3) as u32;
            record.substrate = RunSubstrate::AuthorizedDisposable {
                authorization: label("disposable-test-host"),
            };
            record
        })
        .collect()
}

/// A BENCH-13 record of `claim` over `records`, summarising first-token time.
pub(crate) fn reproduction(
    claim: ClaimUnderTest,
    records: Vec<RunRecord>,
) -> Result<ReproducibilityRecord, ReportError> {
    ReproducibilityRecord::new(
        claim,
        StatisticalMethod::new(
            PercentileMethod::NearestRank,
            vec![IntervalKind::TimeToFirstToken],
        ),
        NaiveDate::from_ymd_opt(2026, 10, 27).unwrap(),
        digest("yougori/test/v1", &[b"harness"]),
        records,
        vec![],
    )
}

/// The record pinned by `golden_run_record_v3.json`: a BENCH-01 demand request that
/// wakes a sleeping engine, with measured, unmeasured and not-applicable cells.
pub(crate) fn golden_record() -> RunRecord {
    let operation = "op-golden-1";
    RunRecord {
        attempt: AttemptIdentity {
            deadline_nanos: Measured::measured(2_000_000_000),
            burst: 2,
            ..attempt(BenchId::Bench01, "load-8", operation)
        },
        workload: Measured::measured(Workload {
            fixture: FixtureRef::new(
                label("code-fixture-1"),
                test_digest("code-fixture-1"),
                Disclosure::PermittedSynthetic,
            ),
            family: FixtureFamily::Tool,
            input_tokens: 1024,
            max_output_tokens: 256,
            sampling: Sampling {
                temperature: NonNegative::new(0.5).unwrap(),
                top_p: Measured::measured(NonNegative::new(0.75).unwrap()),
                top_k: Measured::not_measured(NotMeasuredReason::UnsupportedByBackend),
                seed: Measured::measured(42),
            },
            tool_schema: Measured::measured(FixtureRef::new(
                label("tool-schema-1"),
                test_digest("tool-schema-1"),
                Disclosure::ApprovedFixture,
            )),
            paired: true,
            cold_test_nonce: NonceDisclosure::NotUsed,
        }),
        state: Measured::measured(StartState {
            temperature: StartTemperature::Warm,
            model_at_arrival: ModelAtArrival::Asleep,
            cache_tier: CacheTier::HostMemory,
            prefill: PrefillMode::Fresh,
            cold_provenance: ColdProvenance::NotCold,
        }),
        price: Measured::measured(PriceQuote {
            usd_per_unit: NonNegative::new(0.5).unwrap(),
            unit: PriceUnit::GpuHour,
            source: label("owner-electricity-rate"),
            provenance: PriceProvenance::OwnerDeclaredRate,
            observed_at: Utc
                .with_ymd_and_hms(2026, 10, 27, 0, 0, 0)
                .single()
                .unwrap(),
        }),
        measurements: RunMeasurements {
            prefill_tokens_per_second: Measured::measured(NonNegative::new(2048.0).unwrap()),
            aggregate_decode_tokens_per_second: Measured::measured(
                NonNegative::new(320.0).unwrap(),
            ),
            peak_gpu_memory_bytes: Measured::measured(21_474_836_480),
            retained_gpu_memory_bytes: Measured::measured(17_179_869_184),
            ..measurements(Measured::measured(3))
        },
        events: events(
            operation,
            vec![
                (0, EventKind::RequestAccepted),
                (1, EventKind::WakeStarted),
                (1, EventKind::RequestDequeued),
                (300, EventKind::WakeCompleted),
                (40, EventKind::TokenEmitted),
                (20, EventKind::TokenEmitted),
                (25, EventKind::TokenEmitted),
                (1, EventKind::RequestCompleted),
            ],
        ),
        ..serving_record(operation, 100)
    }
}
