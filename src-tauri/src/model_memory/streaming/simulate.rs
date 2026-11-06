//! The fake substrate (plan S12 G0; GPU-W07 acceptance, lines 1085–1092).
//!
//! [`run_fake`] replays a planned load as discrete events on a
//! [`ManualClock`]: each read's duration, each buffer build and each group's compute vary
//! by a seeded spread ([`SeededRng`]), faults are injected on request (a late read, an
//! allocation failure at a group, a cancellation), and every action goes through
//! [`StreamingExecution`], so a fake run obeys the same refusals as a real one. The run
//! never evaluates the §2.6 recurrence: the stalls it observes are an independent check of
//! the stalls the recurrence predicted.
//!
//! [`ErrorBand::declared`] fixes the error band before a run: with every duration within
//! a relative spread `s` of its prediction, every finish time — a maximum of sums of
//! durations — is within `s` times the sum of all durations, and a stall, a difference of
//! two such times, within twice that.
//!
//! [`co_runner`] measures steady-generation interference: a decoding request on the same
//! device slows by a declared fraction while bytes occupy the read path.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::foundation::ids::{
    Clock, ManualClock, ModelActivationGeneration, MonotonicTime, OperationId,
};
use crate::model_memory::bench::rng::{SeededRng, Variation};

use super::architecture::PlannedRequest;
use super::deadline::{ReadCostModel, StreamingSchedule};
use super::execution::{ExecutionStatus, StreamingEvent, StreamingExecution};
use super::{non_negative, StreamingError};

/// The seeded fake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FakeSubstrate {
    pub seed: u64,
    pub variation: Variation,
}

/// A read that arrives late by `extra_seconds`, such as a slow source mid-prefill.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LateRead {
    pub request: usize,
    pub extra_seconds: f64,
}

/// Faults to inject.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct FaultPlan {
    pub late_read: Option<LateRead>,
    /// The allocation for this group fails with this many bytes requested.
    pub out_of_memory_at: Option<(usize, u64)>,
    pub cancel_at_seconds: Option<f64>,
}

/// How a fake run ended.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum FakeOutcome {
    FirstToken { at_seconds: f64 },
    Cancelled { at_seconds: f64 },
    OutOfMemory { group: usize },
}

/// What a fake run observed.
#[derive(Clone, Debug, PartialEq)]
pub struct FakeRun {
    pub outcome: FakeOutcome,
    pub tensor_usable_seconds: Vec<f64>,
    pub group_usable_seconds: Vec<Option<f64>>,
    pub group_started_seconds: Vec<Option<f64>>,
    pub group_finished_seconds: Vec<Option<f64>>,
    pub observed_waits_seconds: Vec<f64>,
    /// Windows in which bytes occupied the read path.
    pub busy_intervals: Vec<(f64, f64)>,
    /// When every first-token dependency was usable, if it became so.
    pub dependencies_usable_seconds: Option<f64>,
    pub load_complete_seconds: f64,
    pub transferred_bytes: u64,
    pub events: Vec<StreamingEvent>,
}

fn to_nanos(seconds: f64) -> Result<u64, StreamingError> {
    let seconds = non_negative("duration", seconds)?;
    let nanos = (seconds * 1e9).round();
    if nanos > u64::MAX as f64 {
        return Err(StreamingError::Invalid {
            field: "duration",
            reason: "too long for the fake clock",
        });
    }
    Ok(nanos as u64)
}

fn seconds(at: MonotonicTime) -> f64 {
    Duration::from_nanos(at.as_nanos()).as_secs_f64()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Event {
    Tensor(usize),
    Buffer(usize),
}

/// Runs a planned load on the fake substrate.
pub fn run_fake(
    planned: &PlannedRequest,
    schedule: &StreamingSchedule,
    cost: &ReadCostModel,
    substrate: FakeSubstrate,
    faults: FaultPlan,
) -> Result<FakeRun, StreamingError> {
    let mut rng = SeededRng::new(substrate.seed);
    let tensors = schedule.tensor_usable_seconds.len();
    let mut arrivals: BTreeMap<u64, Vec<Event>> = BTreeMap::new();
    let mut tensor_usable = vec![0u64; tensors];
    let mut busy_intervals = Vec::with_capacity(schedule.requests.len());
    let mut link_free = 0u64;
    for (index, request) in schedule.requests.iter().enumerate() {
        let planned_nanos = to_nanos(request.end_seconds - request.start_seconds)?;
        let varied = rng.vary_nanos(planned_nanos, substrate.variation);
        let ratio = if planned_nanos == 0 {
            1.0
        } else {
            varied as f64 / planned_nanos as f64
        };
        let late = match faults.late_read {
            Some(late) if late.request == index => to_nanos(late.extra_seconds)?,
            _ => 0,
        };
        let end = link_free.saturating_add(varied).saturating_add(late);
        let data = to_nanos(cost.data_seconds(request.range.length_bytes) * ratio)?.min(varied);
        busy_intervals.push((
            seconds(MonotonicTime::from_nanos(end - data)),
            seconds(MonotonicTime::from_nanos(end)),
        ));
        for tensor in &request.tensors {
            let slot = tensor_usable
                .get_mut(*tensor)
                .ok_or(StreamingError::Unknown {
                    field: "tensors",
                    index: *tensor,
                })?;
            *slot = end;
            arrivals
                .entry(end)
                .or_default()
                .push(Event::Tensor(*tensor));
        }
        link_free = end;
    }
    let mut init_end = 0u64;
    for (buffer, planned_buffer) in planned.buffers.iter().enumerate() {
        let varied = rng.vary_nanos(to_nanos(planned_buffer.init_seconds)?, substrate.variation);
        init_end = init_end.saturating_add(varied);
        arrivals
            .entry(init_end)
            .or_default()
            .push(Event::Buffer(buffer));
    }
    let compute: Vec<u64> = planned
        .groups
        .iter()
        .map(|group| {
            to_nanos(group.compute_seconds).map(|n| rng.vary_nanos(n, substrate.variation))
        })
        .collect::<Result<_, _>>()?;
    let cancel_at = faults.cancel_at_seconds.map(to_nanos).transpose()?;

    let clock = ManualClock::new(MonotonicTime::ZERO);
    let mut execution = StreamingExecution::new(
        &clock,
        OperationId::new("op-fake-streaming")?,
        ModelActivationGeneration::FIRST,
        planned,
        tensors,
    )?;
    let mut running_until: Option<u64> = None;
    let mut cancelled = false;
    let mut out_of_memory = None;
    loop {
        let now = clock.now().as_nanos();
        // Start the next group as soon as it may start.
        if running_until.is_none() && execution.can_start_next() {
            if let Some(group) = execution.next_group() {
                match faults.out_of_memory_at {
                    Some((failing, bytes)) if failing == group => {
                        execution.out_of_memory(group, bytes)?;
                        out_of_memory = Some(group);
                    }
                    _ => {
                        execution.start_group(group, planned.shape)?;
                        running_until = Some(now.saturating_add(compute[group]));
                    }
                }
            }
        }
        let stopped = !matches!(execution.status(), ExecutionStatus::Running);
        if stopped && running_until.is_none() {
            break;
        }
        let next_arrival = if stopped {
            None
        } else {
            arrivals.keys().next().copied()
        };
        let next_cancel = cancel_at.filter(|_| !cancelled && !stopped);
        let next = [next_arrival, running_until, next_cancel]
            .into_iter()
            .flatten()
            .min();
        let Some(next) = next else {
            return Err(StreamingError::Invalid {
                field: "fake run",
                reason: "the run waits for an input that never arrives",
            });
        };
        clock.advance_to(MonotonicTime::from_nanos(next));
        if next_arrival == Some(next) {
            for event in arrivals.remove(&next).unwrap_or_default() {
                match event {
                    Event::Tensor(tensor) => {
                        execution.tensor_usable(tensor, ModelActivationGeneration::FIRST)?
                    }
                    Event::Buffer(buffer) => execution.buffer_ready(buffer)?,
                }
            }
        }
        if running_until == Some(next) {
            if let Some(group) = execution.next_group() {
                execution.finish_group(group)?;
            }
            running_until = None;
        }
        if next_cancel == Some(next) && execution.status() == ExecutionStatus::Running {
            execution.cancel()?;
            cancelled = true;
        }
    }

    let outcome = match (execution.status(), out_of_memory) {
        (ExecutionStatus::Completed { at }, _) => FakeOutcome::FirstToken {
            at_seconds: seconds(at),
        },
        (ExecutionStatus::Cancelled { at }, _) => FakeOutcome::Cancelled {
            at_seconds: seconds(at),
        },
        (_, Some(group)) => FakeOutcome::OutOfMemory { group },
        (ExecutionStatus::OutOfMemory { group, .. }, None) => FakeOutcome::OutOfMemory { group },
        (ExecutionStatus::Running, None) => {
            return Err(StreamingError::Invalid {
                field: "fake run",
                reason: "ended while running",
            })
        }
    };
    let records = execution.records();
    let group_usable_seconds: Vec<Option<f64>> =
        records.iter().map(|r| r.usable_at.map(seconds)).collect();
    let dependencies_usable_seconds = group_usable_seconds
        .iter()
        .try_fold(0.0f64, |latest, at| at.map(|at| latest.max(at)));
    Ok(FakeRun {
        outcome,
        tensor_usable_seconds: tensor_usable
            .iter()
            .map(|n| seconds(MonotonicTime::from_nanos(*n)))
            .collect(),
        group_started_seconds: records.iter().map(|r| r.started_at.map(seconds)).collect(),
        group_finished_seconds: records.iter().map(|r| r.finished_at.map(seconds)).collect(),
        group_usable_seconds,
        observed_waits_seconds: execution.observed_waits_seconds(MonotonicTime::ZERO),
        busy_intervals,
        dependencies_usable_seconds,
        load_complete_seconds: seconds(MonotonicTime::from_nanos(link_free)),
        transferred_bytes: schedule.transferred_bytes,
        events: execution.events().to_vec(),
    })
}

/// The error band declared before a run (GPU-W07 acceptance).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ErrorBand {
    pub seconds: f64,
}

impl ErrorBand {
    /// `2 × s × (sum of every read, buffer build and compute duration)` for a relative
    /// spread `s`: a bound on the error of any predicted stall when every duration stays
    /// within `s` of its prediction.
    pub fn declared(
        planned: &PlannedRequest,
        schedule: &StreamingSchedule,
        variation: Variation,
    ) -> Self {
        let spread = f64::from(variation.spread_ppm()) / 1e6;
        let reads: f64 = schedule
            .requests
            .iter()
            .map(|request| request.end_seconds - request.start_seconds)
            .sum();
        let builds: f64 = planned
            .buffers
            .iter()
            .map(|buffer| buffer.init_seconds)
            .sum();
        let compute: f64 = planned
            .groups
            .iter()
            .map(|group| group.compute_seconds)
            .sum();
        Self {
            seconds: 2.0 * spread * (reads + builds + compute),
        }
    }
}

/// Whether the recurrence predicted the observed stalls.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum StallPrediction {
    WithinBand {
        max_error_seconds: f64,
    },
    OutsideBand {
        group: usize,
        predicted_wait_seconds: f64,
        observed_wait_seconds: f64,
    },
}

/// The waits before each group the §2.6 recurrence predicts: from time zero for the
/// first group, from the previous finish for the rest.
pub fn predicted_waits_seconds(schedule: &StreamingSchedule) -> Vec<f64> {
    let mut previous = 0.0;
    schedule
        .timings
        .iter()
        .zip(&schedule.finish_seconds)
        .map(|(timing, finish)| {
            let start = finish - timing.compute_seconds;
            let wait = start - previous;
            previous = *finish;
            wait
        })
        .collect()
}

/// Compares the predicted and observed wait before every group against `band`.
pub fn check_stall_prediction(
    schedule: &StreamingSchedule,
    run: &FakeRun,
    band: ErrorBand,
) -> Result<StallPrediction, StreamingError> {
    let predicted = predicted_waits_seconds(schedule);
    if run.observed_waits_seconds.len() != predicted.len() {
        return Err(StreamingError::Invalid {
            field: "fake run",
            reason: "the run did not compute every group",
        });
    }
    let mut max_error_seconds = 0.0f64;
    for (group, (predicted, observed)) in predicted
        .iter()
        .zip(&run.observed_waits_seconds)
        .enumerate()
    {
        let error = (predicted - observed).abs();
        if error > band.seconds {
            return Ok(StallPrediction::OutsideBand {
                group,
                predicted_wait_seconds: *predicted,
                observed_wait_seconds: *observed,
            });
        }
        max_error_seconds = max_error_seconds.max(error);
    }
    Ok(StallPrediction::WithinBand { max_error_seconds })
}

/// A decoding request sharing the device: one token per `decode_token_seconds` alone,
/// `slowdown_fraction` slower while bytes occupy the read path.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct InterferenceModel {
    pub decode_token_seconds: f64,
    pub slowdown_fraction: f64,
}

/// What the co-running request experienced.
#[derive(Clone, Debug, PartialEq)]
pub struct CoRunnerTrace {
    pub token_times_seconds: Vec<f64>,
    /// Decode progress lost to the load: busy overlap × s / (1 + s).
    pub lost_seconds: f64,
}

/// Steady-generation interference over `[0, until_seconds]` (GPU §4.4: "steady
/// generation interference").
pub fn co_runner(
    busy: &[(f64, f64)],
    until_seconds: f64,
    model: &InterferenceModel,
) -> Result<CoRunnerTrace, StreamingError> {
    let period = non_negative("decode_token_seconds", model.decode_token_seconds)?;
    if period <= 0.0 {
        return Err(StreamingError::Invalid {
            field: "decode_token_seconds",
            reason: "must be more than zero",
        });
    }
    let slowdown = non_negative("slowdown_fraction", model.slowdown_fraction)?;
    let until = non_negative("until_seconds", until_seconds)?;
    let mut intervals: Vec<(f64, f64)> = busy
        .iter()
        .map(|(start, end)| (start.max(0.0), end.min(until)))
        .filter(|(start, end)| end > start)
        .collect();
    intervals.sort_by(|a, b| a.0.total_cmp(&b.0));
    // Piecewise rates: 1 outside busy windows, 1 / (1 + s) inside.
    let mut segments: Vec<(f64, f64, f64)> = Vec::new();
    let mut at = 0.0;
    for (start, end) in intervals {
        let start = start.max(at);
        if end <= start {
            continue;
        }
        if start > at {
            segments.push((at, start, 1.0));
        }
        segments.push((start, end, 1.0 / (1.0 + slowdown)));
        at = end;
    }
    if until > at {
        segments.push((at, until, 1.0));
    }
    let mut token_times_seconds = Vec::new();
    let mut work = 0.0;
    let mut lost_seconds = 0.0;
    for (start, end, rate) in segments {
        lost_seconds += (end - start) * (1.0 - rate);
        let mut cursor = start;
        while cursor < end {
            let needed = period - work;
            let available = (end - cursor) * rate;
            if available >= needed {
                cursor += needed / rate;
                token_times_seconds.push(cursor);
                work = 0.0;
            } else {
                work += available;
                cursor = end;
            }
        }
    }
    Ok(CoRunnerTrace {
        token_times_seconds,
        lost_seconds,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model_memory::streaming::architecture::StreamingModel;
    use crate::model_memory::streaming::deadline::{plan_streaming, OrderPolicy};
    use crate::model_memory::streaming::test_support::*;

    fn planned() -> (PlannedRequest, StreamingSchedule, ReadCostModel) {
        let model =
            StreamingModel::new(dense_spec_with(12, 8 * MIB, Layout::Lexicographic)).unwrap();
        let request = model.plan_request(shape(64), None).unwrap();
        let path = read_path(0.000_05, 6e9);
        let schedule = plan_streaming(
            &model,
            &request,
            &path,
            &budget(64 * MIB),
            OrderPolicy::FileOrder,
        )
        .unwrap();
        (request, schedule, path)
    }

    fn substrate(spread_ppm: u32, seed: u64) -> FakeSubstrate {
        FakeSubstrate {
            seed,
            variation: Variation::new(spread_ppm).unwrap(),
        }
    }

    #[test]
    fn without_variation_the_run_matches_the_recurrence() {
        let (request, schedule, path) = planned();
        let run = run_fake(
            &request,
            &schedule,
            &path,
            substrate(0, 1),
            FaultPlan::default(),
        )
        .unwrap();
        let FakeOutcome::FirstToken { at_seconds } = run.outcome else {
            panic!("expected a first token, got {:?}", run.outcome);
        };
        let events = run.events.len() as f64;
        assert!((at_seconds - schedule.first_token.first_token_seconds).abs() <= events * 1e-9);
        let predicted = predicted_waits_seconds(&schedule);
        for (p, o) in predicted.iter().zip(&run.observed_waits_seconds) {
            assert!((p - o).abs() <= events * 1e-9);
        }
    }

    #[test]
    fn the_recurrence_predicts_stalls_within_the_declared_band() {
        let (request, schedule, path) = planned();
        let five_percent = Variation::new(50_000).unwrap();
        let band = ErrorBand::declared(&request, &schedule, five_percent);
        assert!(band.seconds > 0.0);
        for seed in 0..20 {
            let run = run_fake(
                &request,
                &schedule,
                &path,
                substrate(50_000, seed),
                FaultPlan::default(),
            )
            .unwrap();
            assert!(matches!(
                check_stall_prediction(&schedule, &run, band).unwrap(),
                StallPrediction::WithinBand { .. }
            ));
        }
        // A read that arrives 50 ms late mid-prefill falls outside the band.
        let late = FaultPlan {
            late_read: Some(LateRead {
                request: 1,
                extra_seconds: 0.05,
            }),
            ..FaultPlan::default()
        };
        let run = run_fake(&request, &schedule, &path, substrate(50_000, 3), late).unwrap();
        assert!(matches!(
            check_stall_prediction(&schedule, &run, band).unwrap(),
            StallPrediction::OutsideBand { .. }
        ));
        assert!(matches!(run.outcome, FakeOutcome::FirstToken { .. }));
    }

    #[test]
    fn cancellation_and_oom_mid_prefill_on_the_fake() {
        let (request, schedule, path) = planned();
        let middle = schedule.first_token.first_token_seconds / 2.0;
        let cancelled = run_fake(
            &request,
            &schedule,
            &path,
            substrate(0, 1),
            FaultPlan {
                cancel_at_seconds: Some(middle),
                ..FaultPlan::default()
            },
        )
        .unwrap();
        assert!(matches!(cancelled.outcome, FakeOutcome::Cancelled { .. }));
        assert!(cancelled.group_finished_seconds.iter().any(|f| f.is_none()));
        let failed = run_fake(
            &request,
            &schedule,
            &path,
            substrate(0, 1),
            FaultPlan {
                out_of_memory_at: Some((4, 64 * MIB)),
                ..FaultPlan::default()
            },
        )
        .unwrap();
        assert_eq!(failed.outcome, FakeOutcome::OutOfMemory { group: 4 });
        assert_eq!(failed.group_started_seconds[4], None);
        assert!(failed.group_finished_seconds[3].is_some());
    }

    #[test]
    fn interference_follows_the_busy_windows() {
        // Busy for 0.2 s of the first second at 25% slowdown: 0.04 s of progress lost.
        let model = InterferenceModel {
            decode_token_seconds: 0.01,
            slowdown_fraction: 0.25,
        };
        // Until just past one second, so the boundary token is not lost to rounding.
        let trace = co_runner(&[(0.1, 0.3)], 1.0005, &model).unwrap();
        assert!((trace.lost_seconds - 0.04).abs() < 1e-12);
        assert_eq!(trace.token_times_seconds.len(), 96);
        let idle = co_runner(&[], 1.0005, &model).unwrap();
        assert_eq!(idle.token_times_seconds.len(), 100);
        assert!(co_runner(
            &[],
            1.0,
            &InterferenceModel {
                decode_token_seconds: 0.0,
                slowdown_fraction: 0.1
            }
        )
        .is_err());
    }
}
