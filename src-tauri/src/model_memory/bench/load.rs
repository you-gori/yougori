//! BENCH-01 on fake runners (S11 line 193; S7 line 122): loads 1, 8 and 32, then a
//! measured saturation search; long and short prompts and outputs, context growth and
//! burst arrivals. Every level is measured from its own CORE-08 records, with queue wait,
//! TTFT, decode per user, aggregate completed throughput, admission and failures,
//! p50/p95/p99 and resource peaks.

use std::sync::Arc;

use super::corpus::{Fixture, NonceSource, RenderedRequest};
use super::faults::{FaultKind, FaultRecord, RecycleEvent, ScheduledFault};
use super::profile::RunnerProfile;
use super::resources::ResourceSnapshot;
use super::rng::SeededRng;
use super::runner::{
    clock_id, FakeRunner, RequestPlan, RetryPolicy, Script, ServeOutcome, UserScript,
};
use super::BenchError;
use crate::foundation::evidence::BackendModeRules;
use crate::foundation::ids::{Clock, ExecutionId, ManualClock, MonotonicTime};
use crate::foundation::report::{
    completed_output_tokens_per_second, ArrivalMode, AttemptLedger, BenchId, ClockReading,
    IntervalKind, Label, LatencyClaim, LatencySummary, LoadDescription, NoncePlacement,
    ObservationWindow, PercentileMethod, Quantile, Quotient, RunRecord, UndefinedReason,
    BENCH_01_CONCURRENCY_LEVELS,
};

/// Makes identical fresh runners, one per measured level, so no level inherits another's
/// caches, leaks or faults. Each runner gets its own seed, so operation identities never
/// repeat across levels.
#[derive(Clone)]
pub struct RunnerFactory {
    pub profile: RunnerProfile,
    pub rules: BackendModeRules,
    pub clock: Arc<ManualClock>,
    pub seed: u64,
    pub execution: ExecutionId,
}

impl RunnerFactory {
    /// The seed of runner `stream`: a bijection of the stream, so streams never share one.
    pub fn stream_seed(&self, stream: u64) -> u64 {
        self.seed ^ stream.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(17)
    }

    /// A fresh runner for `stream`.
    pub fn fresh(&self, stream: u64) -> Result<FakeRunner, BenchError> {
        FakeRunner::new(
            self.profile.clone(),
            self.rules.clone(),
            Arc::clone(&self.clock),
            self.stream_seed(stream),
            self.execution.clone(),
        )
    }

    /// A fresh runner for `stream` with `model` started; the start is a recorded warm-up,
    /// never a measured attempt of the level.
    pub fn started(
        &self,
        stream: u64,
        model: &Label,
        bench: BenchId,
    ) -> Result<(FakeRunner, RunRecord), BenchError> {
        let mut runner = self.fresh(stream)?;
        let start = runner.start(model, bench)?;
        Ok((runner, start))
    }
}

/// What every user of a BENCH-01 level sends: closed-loop requests, each a fresh prefill
/// with its own disclosed cold-test nonce (S13 FAST-01).
#[derive(Clone, Debug, PartialEq)]
pub struct LoadSpec {
    /// The variant label's prefix; the level adds `-c<concurrency>`.
    pub variant: String,
    pub model: Label,
    pub fixture: Fixture,
    pub placement: NoncePlacement,
    pub max_output_tokens: u32,
    pub requests_per_user: u32,
    /// Independent repetitions of the level, each a fresh runner and its own burst, so
    /// percentiles can be resolved (S8, S11: several independent runs, not one).
    pub repetitions: u32,
    pub think_nanos: u64,
    pub deadline_nanos: u64,
    pub timeout_nanos: u64,
    pub retry: RetryPolicy,
    /// Faults injected into every repetition, at offsets from its start.
    pub faults: Vec<OffsetFault>,
}

/// A fault at an offset from the start of a repetition (S10 line 183).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OffsetFault {
    pub after_start_nanos: u64,
    pub kind: FaultKind,
}

/// One measured BENCH-01 level (S11 line 193).
#[derive(Clone, Debug, PartialEq)]
pub struct LevelReport {
    pub concurrency: u32,
    pub variant: Label,
    /// Each repetition's warm-up start, recorded apart from the measured attempts.
    pub starts: Vec<RunRecord>,
    /// Every attempt of the level, failures included (S8).
    pub ledger: AttemptLedger,
    pub queue_wait: LatencySummary,
    pub time_to_first_token: LatencySummary,
    pub request_latency: LatencySummary,
    /// Decode per user of each successful attempt: (tokens − 1) over first to last token.
    pub decode_tokens_per_second_per_user: Vec<f64>,
    /// Per repetition, from the first arrival to the end of the first user's last request:
    /// the window in which every user is still sending, which the saturation search
    /// compares.
    pub steady_windows: Vec<ObservationWindow>,
    pub steady_tokens_per_second: Vec<Quotient>,
    /// Per repetition, from the first arrival to the last end, reported beside it.
    pub full_windows: Vec<ObservationWindow>,
    pub full_tokens_per_second: Vec<Quotient>,
    /// Failed initial attempts over every initial attempt.
    pub failure_fraction: f64,
    pub resource_peak: ResourceSnapshot,
    pub recycles: Vec<RecycleEvent>,
    pub faults: Vec<FaultRecord>,
}

impl LevelReport {
    /// Mean aggregate completed throughput over the repetitions' steady windows; an
    /// undefined window counts as zero.
    pub fn throughput_tokens_per_second(&self) -> f64 {
        let count = self.steady_tokens_per_second.len().max(1) as f64;
        self.steady_tokens_per_second
            .iter()
            .map(|quotient| quotient.value().unwrap_or(0.0))
            .sum::<f64>()
            / count
    }

    /// A claim on one percentile of one interval, carried with the success rate and
    /// deadline failures; low-resolution percentiles are refused (S8, S11).
    pub fn claim(
        &self,
        interval: IntervalKind,
        quantile: Quantile,
    ) -> Result<LatencyClaim, BenchError> {
        let summary = match interval {
            IntervalKind::QueueWait => &self.queue_wait,
            IntervalKind::TimeToFirstToken => &self.time_to_first_token,
            IntervalKind::RequestLatency => &self.request_latency,
            _ => {
                return Err(BenchError::InvalidParameter {
                    field: "interval",
                    reason: "a BENCH-01 level summarises queue wait, TTFT and request latency",
                })
            }
        };
        Ok(LatencyClaim::from_summary(summary, quantile)?)
    }

    /// The best run is reported only as a diagnostic (S13 FAST-01): this always refuses.
    pub fn claim_best_run(&self) -> Result<LatencyClaim, BenchError> {
        Err(BenchError::BestRunIsDiagnostic)
    }
}

fn throughput(ledger: &AttemptLedger, window: &ObservationWindow) -> Result<Quotient, BenchError> {
    if window.end_nanos <= window.start_nanos {
        return Ok(Quotient::Undefined {
            reason: UndefinedReason::ZeroDenominator,
        });
    }
    Ok(completed_output_tokens_per_second(ledger, window)?)
}

/// Summaries of a level's repetitions: the three serving intervals over every attempt,
/// decode per user, throughput per repetition over both windows, failures and peaks.
pub(crate) fn level_report(
    concurrency: u32,
    variant: Label,
    runs: Vec<(RunRecord, ServeOutcome, Vec<FaultRecord>)>,
) -> Result<LevelReport, BenchError> {
    let mut starts = Vec::new();
    let mut records = Vec::new();
    let mut steady_windows = Vec::new();
    let mut full_windows = Vec::new();
    let mut steady_tokens_per_second = Vec::new();
    let mut full_tokens_per_second = Vec::new();
    let mut resource_peak = ResourceSnapshot::ZERO;
    let mut recycles = Vec::new();
    let mut faults = Vec::new();
    for (start, outcome, run_faults) in runs {
        let window = outcome.window.ok_or(BenchError::WrongState {
            operation: "level report",
            reason: "a repetition produced no attempt",
        })?;
        let ledger = AttemptLedger::from_records(outcome.records.iter().cloned())?;
        let steady = ObservationWindow {
            clock: clock_id()?,
            start_nanos: window.first_arrival,
            end_nanos: window.steady_end,
        };
        let full = ObservationWindow {
            clock: clock_id()?,
            start_nanos: window.first_arrival,
            end_nanos: window.last_end,
        };
        steady_tokens_per_second.push(throughput(&ledger, &steady)?);
        full_tokens_per_second.push(throughput(&ledger, &full)?);
        steady_windows.push(steady);
        full_windows.push(full);
        resource_peak = resource_peak.max(&outcome.peak);
        recycles.extend(outcome.recycles);
        faults.extend(run_faults);
        records.extend(outcome.records);
        starts.push(start);
    }
    let ledger = AttemptLedger::from_records(records)?;
    let method = PercentileMethod::NearestRank;
    let summary = |interval| LatencySummary::from_ledger(&ledger, interval, method);
    let queue_wait = summary(IntervalKind::QueueWait)?;
    let time_to_first_token = summary(IntervalKind::TimeToFirstToken)?;
    let request_latency = summary(IntervalKind::RequestLatency)?;
    let mut decode_tokens_per_second_per_user = Vec::new();
    for record in ledger
        .initial_attempts()
        .filter(|record| record.is_success())
    {
        if let ClockReading::Serving(clock) = record.clock_reading()? {
            if let Some(rate) = clock.decode_tokens_per_second.value() {
                decode_tokens_per_second_per_user.push(*rate);
            }
        }
    }
    let success = ledger.success_rate()?;
    Ok(LevelReport {
        concurrency,
        variant,
        starts,
        failure_fraction: 1.0 - success.rate(),
        queue_wait,
        time_to_first_token,
        request_latency,
        decode_tokens_per_second_per_user,
        steady_windows,
        steady_tokens_per_second,
        full_windows,
        full_tokens_per_second,
        resource_peak,
        recycles,
        faults,
        ledger,
    })
}

/// Runs one closed-loop level: `concurrency` users, each sending its requests in turn,
/// repeated on `spec.repetitions` fresh runners, each repetition its own burst.
pub fn run_level(
    factory: &RunnerFactory,
    spec: &LoadSpec,
    concurrency: u32,
    stream: u64,
) -> Result<LevelReport, BenchError> {
    if concurrency == 0 || spec.requests_per_user == 0 || spec.repetitions == 0 {
        return Err(BenchError::InvalidParameter {
            field: "concurrency",
            reason: "a level has at least one user, one request and one repetition",
        });
    }
    let variant = Label::new(format!("{}-c{concurrency}", spec.variant))?;
    let mut runs = Vec::new();
    for repetition in 0..spec.repetitions {
        let (mut runner, start) = factory.started(
            (stream << 16) | u64::from(repetition),
            &spec.model,
            BenchId::Bench01,
        )?;
        let mut nonces = NonceSource::new(SeededRng::new(runner.seed()).fork(), spec.placement);
        let now = runner.clock().now();
        for fault in &spec.faults {
            runner.inject(ScheduledFault {
                at: now
                    .checked_add(std::time::Duration::from_nanos(fault.after_start_nanos))
                    .ok_or(BenchError::Overflow)?,
                kind: fault.kind,
            })?;
        }
        let mut users = Vec::new();
        for _ in 0..concurrency {
            let mut requests = Vec::new();
            for index in 0..spec.requests_per_user {
                requests.push(RequestPlan {
                    variant: variant.clone(),
                    model: spec.model.clone(),
                    request: nonces.render(&spec.fixture)?,
                    max_output_tokens: spec.max_output_tokens,
                    deadline_nanos: spec.deadline_nanos,
                    timeout_nanos: spec.timeout_nanos,
                    gap_before_nanos: if index == 0 { 0 } else { spec.think_nanos },
                    switch_from_previous: false,
                    burst: repetition,
                    check_response: false,
                });
            }
            users.push(UserScript {
                start_at: now,
                requests,
                retry: spec.retry,
            });
        }
        let script = Script {
            bench: BenchId::Bench01,
            load: LoadDescription {
                concurrent_requests: concurrency,
                arrival: ArrivalMode::Sequential,
            },
            users,
            recycle_after_switches: None,
        };
        let outcome = runner.serve(&script)?;
        runs.push((start, outcome, runner.fault_log().to_vec()));
    }
    level_report(concurrency, variant, runs)
}

/// When the saturation search stops raising concurrency (S7: "a measured saturation
/// point").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SaturationPolicy {
    min_relative_gain: f64,
    max_failure_fraction: f64,
    max_concurrency: u32,
}

impl SaturationPolicy {
    /// `min_relative_gain` in (0, 1), `max_failure_fraction` in [0, 1) and a limit of at
    /// least 32, the last fixed level.
    pub fn new(
        min_relative_gain: f64,
        max_failure_fraction: f64,
        max_concurrency: u32,
    ) -> Result<Self, BenchError> {
        if !(min_relative_gain > 0.0 && min_relative_gain < 1.0) {
            return Err(BenchError::InvalidParameter {
                field: "min_relative_gain",
                reason: "between zero and one",
            });
        }
        if !(0.0..1.0).contains(&max_failure_fraction) {
            return Err(BenchError::InvalidParameter {
                field: "max_failure_fraction",
                reason: "at least zero and below one",
            });
        }
        if max_concurrency < 32 {
            return Err(BenchError::InvalidParameter {
                field: "max_concurrency",
                reason: "at least the fixed level 32",
            });
        }
        Ok(Self {
            min_relative_gain,
            max_failure_fraction,
            max_concurrency,
        })
    }
}

/// Why the search stopped raising concurrency.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SaturationStop {
    /// Doubling concurrency improved throughput by less than the minimum gain.
    ThroughputPlateau {
        concurrency: u32,
        relative_gain: f64,
    },
    /// Failures passed the threshold at this concurrency.
    FailureThreshold {
        concurrency: u32,
        failure_fraction: f64,
    },
    /// The limit was reached while throughput still improved.
    ConcurrencyLimit { concurrency: u32 },
}

/// The BENCH-01 levels and the measured saturation point.
#[derive(Clone, Debug, PartialEq)]
pub struct SaturationReport {
    /// Every measured level in the order measured: 1, 8, 32, the raising steps, then
    /// the refinement.
    pub levels: Vec<LevelReport>,
    pub stop: SaturationStop,
    /// The smallest measured concurrency, below the failure threshold, within the
    /// minimum gain of the best throughput of the raising steps; `None` when even one
    /// user fails beyond the threshold.
    pub knee_concurrency: Option<u32>,
    pub best_tokens_per_second: f64,
}

/// Measures 1, 8 and 32, then doubles concurrency until throughput stops improving or
/// failures pass the threshold, then bisects between the last level below the knee and
/// the first at it. Every level is a fresh runner measured from its records.
pub fn saturation_search(
    factory: &RunnerFactory,
    spec: &LoadSpec,
    policy: SaturationPolicy,
) -> Result<SaturationReport, BenchError> {
    let mut levels: Vec<LevelReport> = Vec::new();
    let mut stream = 0u64;
    let mut measure =
        |concurrency: u32, levels: &mut Vec<LevelReport>| -> Result<(f64, bool), BenchError> {
            stream += 1;
            let level = run_level(factory, spec, concurrency, stream)?;
            let result = (
                level.throughput_tokens_per_second(),
                level.failure_fraction <= policy.max_failure_fraction,
            );
            levels.push(level);
            Ok(result)
        };
    let mut stop = None;
    let mut current: Option<(u32, f64)> = None;
    for concurrency in BENCH_01_CONCURRENCY_LEVELS {
        let (throughput, acceptable) = measure(concurrency, &mut levels)?;
        if !acceptable {
            stop = Some(SaturationStop::FailureThreshold {
                concurrency,
                failure_fraction: levels.last().map_or(1.0, |level| level.failure_fraction),
            });
            break;
        }
        current = Some((concurrency, throughput));
    }
    if stop.is_none() {
        while let Some((concurrency, throughput)) = current {
            let next = concurrency.saturating_mul(2);
            if next > policy.max_concurrency {
                stop = Some(SaturationStop::ConcurrencyLimit { concurrency });
                break;
            }
            let (next_throughput, acceptable) = measure(next, &mut levels)?;
            if !acceptable {
                stop = Some(SaturationStop::FailureThreshold {
                    concurrency: next,
                    failure_fraction: levels.last().map_or(1.0, |level| level.failure_fraction),
                });
                break;
            }
            let relative_gain = if throughput > 0.0 {
                next_throughput / throughput - 1.0
            } else if next_throughput > 0.0 {
                f64::INFINITY
            } else {
                0.0
            };
            if relative_gain < policy.min_relative_gain {
                stop = Some(SaturationStop::ThroughputPlateau {
                    concurrency: next,
                    relative_gain,
                });
                break;
            }
            current = Some((next, next_throughput));
        }
    }
    let stop = stop.ok_or(BenchError::WrongState {
        operation: "saturation search",
        reason: "the search ended without a reason",
    })?;
    let acceptable: Vec<(u32, f64)> = levels
        .iter()
        .filter(|level| level.failure_fraction <= policy.max_failure_fraction)
        .map(|level| (level.concurrency, level.throughput_tokens_per_second()))
        .collect();
    let best_tokens_per_second = acceptable
        .iter()
        .map(|(_, throughput)| *throughput)
        .fold(0.0f64, f64::max);
    let threshold = best_tokens_per_second * (1.0 - policy.min_relative_gain);
    let mut knee = acceptable
        .iter()
        .filter(|(_, throughput)| *throughput >= threshold && *throughput > 0.0)
        .map(|(concurrency, _)| *concurrency)
        .min();
    if let Some(mut high) = knee {
        let mut low = acceptable
            .iter()
            .map(|(concurrency, _)| *concurrency)
            .filter(|concurrency| *concurrency < high)
            .max();
        while let Some(below) = low {
            if high - below <= 1 {
                break;
            }
            let middle = below + (high - below) / 2;
            let (throughput, acceptable) = measure(middle, &mut levels)?;
            if acceptable && throughput >= threshold {
                high = middle;
            } else {
                low = Some(middle);
            }
        }
        knee = Some(high);
    }
    Ok(SaturationReport {
        levels,
        stop,
        knee_concurrency: knee,
        best_tokens_per_second,
    })
}

/// Prompt length of a BENCH-01 shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PromptLength {
    Short,
    Long,
}

/// Output length of a BENCH-01 shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutputLength {
    Short,
    Long,
}

/// One prompt and output shape at loads 1, 8 and 32.
#[derive(Clone, Debug, PartialEq)]
pub struct ShapeReport {
    pub prompt: PromptLength,
    pub output: OutputLength,
    pub levels: Vec<LevelReport>,
}

/// BENCH-01's long and short prompts and outputs: each of the four shapes at loads 1, 8
/// and 32, as separate variants, since one percentile over mixed shapes hides each.
pub fn run_shapes(
    factory: &RunnerFactory,
    base: &LoadSpec,
    short_prompt: &Fixture,
    long_prompt: &Fixture,
    short_output_tokens: u32,
    long_output_tokens: u32,
) -> Result<Vec<ShapeReport>, BenchError> {
    let mut reports = Vec::new();
    let mut stream = 1_000u64;
    for (prompt, fixture) in [
        (PromptLength::Short, short_prompt),
        (PromptLength::Long, long_prompt),
    ] {
        for (output, tokens) in [
            (OutputLength::Short, short_output_tokens),
            (OutputLength::Long, long_output_tokens),
        ] {
            let spec = LoadSpec {
                variant: format!(
                    "{}-{}-prompt-{}-output",
                    base.variant,
                    if prompt == PromptLength::Short {
                        "short"
                    } else {
                        "long"
                    },
                    if output == OutputLength::Short {
                        "short"
                    } else {
                        "long"
                    },
                ),
                fixture: fixture.clone(),
                max_output_tokens: tokens,
                ..base.clone()
            };
            let mut levels = Vec::new();
            for concurrency in BENCH_01_CONCURRENCY_LEVELS {
                stream += 1;
                levels.push(run_level(factory, &spec, concurrency, stream)?);
            }
            reports.push(ShapeReport {
                prompt,
                output,
                levels,
            });
        }
    }
    Ok(reports)
}

/// One turn of a growing conversation.
#[derive(Clone, Debug, PartialEq)]
pub struct TurnReport {
    pub turn: u32,
    pub input_tokens: u64,
    pub record: RunRecord,
}

/// BENCH-01 context growth: one conversation whose every turn carries the transcript so
/// far, each a fresh prefill.
pub fn run_context_growth(
    factory: &RunnerFactory,
    model: &Label,
    turns: &[Fixture],
    max_output_tokens: u32,
    placement: NoncePlacement,
) -> Result<(AttemptLedger, Vec<TurnReport>), BenchError> {
    let (mut runner, _start) = factory.started(2_000, model, BenchId::Bench01)?;
    let mut nonces = NonceSource::new(SeededRng::new(runner.seed()).fork(), placement);
    let variant = Label::new("bench-01-context-growth")?;
    let mut requests = Vec::new();
    let mut rendered: Vec<RenderedRequest> = Vec::new();
    for fixture in turns {
        let request = nonces.render(fixture)?;
        rendered.push(request.clone());
        requests.push(RequestPlan {
            variant: variant.clone(),
            model: model.clone(),
            request,
            max_output_tokens,
            deadline_nanos: u64::MAX / 4,
            timeout_nanos: u64::MAX / 4,
            gap_before_nanos: 0,
            switch_from_previous: false,
            burst: 0,
            check_response: false,
        });
    }
    let script = Script {
        bench: BenchId::Bench01,
        load: LoadDescription {
            concurrent_requests: 1,
            arrival: ArrivalMode::Sequential,
        },
        users: vec![UserScript {
            start_at: runner.clock().now(),
            requests,
            retry: RetryPolicy::NONE,
        }],
        recycle_after_switches: None,
    };
    let outcome = runner.serve(&script)?;
    let turns = outcome
        .records
        .iter()
        .zip(&rendered)
        .zip(1u32..)
        .map(|((record, request), turn)| TurnReport {
            turn,
            input_tokens: request.input_tokens(),
            record: record.clone(),
        })
        .collect();
    Ok((AttemptLedger::from_records(outcome.records)?, turns))
}

/// Independent bursts (S7 burst mode; S8 "repeat independent bursts, report uncertainty
/// and avoid a universal p99 claim from one run").
#[derive(Clone, Debug, PartialEq)]
pub struct BurstReport {
    pub ledger: AttemptLedger,
    pub time_to_first_token: LatencySummary,
    pub request_latency: LatencySummary,
}

/// `bursts` independent bursts of `size` requests that arrive together, `interval_nanos`
/// apart, each request with its burst number.
pub fn run_bursts(
    factory: &RunnerFactory,
    spec: &LoadSpec,
    size: u32,
    bursts: u32,
    interval_nanos: u64,
) -> Result<BurstReport, BenchError> {
    let (mut runner, _start) = factory.started(3_000, &spec.model, BenchId::Bench01)?;
    let mut nonces = NonceSource::new(SeededRng::new(runner.seed()).fork(), spec.placement);
    let variant = Label::new(format!("{}-burst-{size}", spec.variant))?;
    let now = runner.clock().now();
    let mut users = Vec::new();
    for burst in 0..bursts {
        let offset = interval_nanos
            .checked_mul(u64::from(burst))
            .ok_or(BenchError::Overflow)?;
        let start_at = MonotonicTime::from_nanos(
            now.as_nanos()
                .checked_add(offset)
                .ok_or(BenchError::Overflow)?,
        );
        for _ in 0..size {
            users.push(UserScript {
                start_at,
                requests: vec![RequestPlan {
                    variant: variant.clone(),
                    model: spec.model.clone(),
                    request: nonces.render(&spec.fixture)?,
                    max_output_tokens: spec.max_output_tokens,
                    deadline_nanos: spec.deadline_nanos,
                    timeout_nanos: spec.timeout_nanos,
                    gap_before_nanos: 0,
                    switch_from_previous: false,
                    burst,
                    check_response: false,
                }],
                retry: RetryPolicy::NONE,
            });
        }
    }
    let script = Script {
        bench: BenchId::Bench01,
        load: LoadDescription {
            concurrent_requests: size,
            arrival: ArrivalMode::Burst { size },
        },
        users,
        recycle_after_switches: None,
    };
    let outcome = runner.serve(&script)?;
    let ledger = AttemptLedger::from_records(outcome.records)?;
    let method = PercentileMethod::NearestRank;
    Ok(BurstReport {
        time_to_first_token: LatencySummary::from_ledger(
            &ledger,
            IntervalKind::TimeToFirstToken,
            method,
        )?,
        request_latency: LatencySummary::from_ledger(
            &ledger,
            IntervalKind::RequestLatency,
            method,
        )?,
        ledger,
    })
}
