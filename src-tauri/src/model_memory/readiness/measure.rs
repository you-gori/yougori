//! CORE-08 measurement of fake-runner records, shared by the three experiments (S8, S12
//! G0; rollout decision "T12 → T02").
//!
//! Every experiment result goes through `foundation::report`. The records are split into
//! one [`AttemptLedger`] per S8 case, because a ledger holds one variant, scenario and
//! start temperature ("run cold and warm states separately"), and each case gets its own
//! time-to-first-token [`LatencySummary`]. A policy's foreground latency is the mix of
//! its cases; its percentiles use report's own [`percentile`] and [`resolution`] rules
//! and are always shown beside the per-case composition. The [`Provenance`] is built
//! from the records' own substrate (the fake substrate here, which backs no performance
//! claim), and a §1.3 [`ObjectiveVector`] summarizes the side. Anything the fakes cannot
//! measure is "not measured".

use std::collections::BTreeSet;

use serde::Serialize;

use super::ReadinessError;
use crate::foundation::report::{
    percentile, resolution, AttemptLedger, IntervalKind, LatencyObjective, LatencySummary,
    Measured, NonNegative, NotMeasuredReason, ObjectiveVector, PercentileMethod, Provenance,
    Quantile, ReportError, Resolution, RunRecord, SuccessRate,
};

/// Bytes an experiment moved or held outside the attempts' own records, such as
/// preparation work done before a request existed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct OutsideRecords {
    /// Bytes read and transferred by work outside any attempt.
    pub transferred_bytes: u64,
    /// The most host memory that work held at once.
    pub retained_host_bytes: u64,
}

/// One S8 case: its attempts and their TTFT summary.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct CaseMeasurement {
    #[serde(serialize_with = "super::wire::ledger")]
    pub ledger: AttemptLedger,
    pub ttft: LatencySummary,
}

/// A percentile of the foreground mix, by report's nearest-rank and resolution rules.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct MixPercentile {
    pub quantile: Quantile,
    pub value_nanos: Measured<f64>,
    pub resolution: Resolution,
    pub samples: u64,
    pub bursts: u64,
}

/// One side of a comparison, measured from its records.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct Measurement {
    /// One entry per S8 case, in the order the cases first appeared.
    pub cases: Vec<CaseMeasurement>,
    pub provenance: Provenance,
    /// Over every initial attempt of every case.
    pub success_rate: SuccessRate,
    /// p50, p95 and p99 of the foreground mix of successful initial attempts.
    pub mix: Vec<MixPercentile>,
    pub objectives: ObjectiveVector,
}

impl Measurement {
    /// Every attempt of every case.
    pub fn attempts(&self) -> usize {
        self.cases
            .iter()
            .map(|case| case.ledger.records().len())
            .sum()
    }

    /// The foreground-mix percentile `quantile`, with its resolution.
    pub fn ttft_percentile(&self, quantile: Quantile) -> Option<&MixPercentile> {
        self.mix
            .iter()
            .find(|estimate| estimate.quantile == quantile)
    }

    /// The value of `quantile`, whatever its resolution; `None` without a successful run.
    pub fn ttft_nanos(&self, quantile: Quantile) -> Option<f64> {
        self.ttft_percentile(quantile)
            .and_then(|estimate| estimate.value_nanos.value().copied())
    }

    /// The success rate over every initial attempt.
    pub fn success_rate(&self) -> f64 {
        self.success_rate.rate()
    }

    /// Every successful initial attempt's TTFT, ascending.
    pub fn ttft_samples(&self) -> Vec<u64> {
        let mut samples: Vec<u64> = self
            .cases
            .iter()
            .flat_map(|case| case.ttft.samples().iter().map(|sample| sample.nanos))
            .collect();
        samples.sort_unstable();
        samples
    }
}

/// Splits `records` into one ledger per S8 case, following the ledger's own rule.
fn cases(records: Vec<RunRecord>) -> Result<Vec<AttemptLedger>, ReadinessError> {
    let mut ledgers: Vec<AttemptLedger> = Vec::new();
    'records: for record in records {
        for ledger in &mut ledgers {
            match ledger.add(record.clone()) {
                Ok(()) => continue 'records,
                Err(ReportError::MixedCases) => {}
                Err(other) => return Err(other.into()),
            }
        }
        let mut ledger = AttemptLedger::new();
        ledger.add(record)?;
        ledgers.push(ledger);
    }
    Ok(ledgers)
}

/// Measures `records` (S8): one ledger and TTFT summary per case, the foreground mix's
/// nearest-rank percentiles with report's resolution rule, provenance from the records,
/// and the §1.3 objectives. TTFT in the vector is the mix at `latency_objective.quantile`
/// at any resolution; the mix keeps the resolution, and a fake-substrate vector backs no
/// claim anyway.
pub fn measure(
    records: Vec<RunRecord>,
    latency_objective: LatencyObjective,
    outside: OutsideRecords,
) -> Result<Measurement, ReadinessError> {
    let provenance = Provenance::of_records(&records)?;
    let attempts = records.len() as u64;
    let largest = |field: fn(&RunRecord) -> &Measured<u64>| -> u64 {
        records
            .iter()
            .filter_map(|record| field(record).value().copied())
            .max()
            .unwrap_or(0)
    };
    let total = |field: fn(&RunRecord) -> &Measured<u64>| -> u128 {
        records
            .iter()
            .filter_map(|record| field(record).value().copied())
            .map(u128::from)
            .sum()
    };
    let peak_gpu = largest(|record| &record.measurements.peak_gpu_memory_bytes);
    let retained_gpu = largest(|record| &record.measurements.retained_gpu_memory_bytes);
    let peak_host = largest(|record| &record.measurements.peak_host_memory_bytes);
    let retained_host = largest(|record| &record.measurements.retained_host_memory_bytes)
        .saturating_add(outside.retained_host_bytes);
    let transferred = total(|record| &record.measurements.transferred_bytes)
        + u128::from(outside.transferred_bytes);
    let storage = total(|record| &record.measurements.storage_read_bytes)
        + u128::from(outside.transferred_bytes);
    let mut measured_cases = Vec::new();
    let (mut successes, mut initial) = (0u64, 0u64);
    let mut samples = Vec::new();
    for ledger in cases(records)? {
        let ttft = LatencySummary::from_ledger(
            &ledger,
            IntervalKind::TimeToFirstToken,
            PercentileMethod::NearestRank,
        )?;
        successes += ttft.success_rate().successes();
        initial += ttft.success_rate().attempts();
        samples.extend(ttft.samples().iter().copied());
        measured_cases.push(CaseMeasurement { ledger, ttft });
    }
    let success_rate = SuccessRate::new(successes, initial)?;
    let mut sorted: Vec<u64> = samples.iter().map(|sample| sample.nanos).collect();
    sorted.sort_unstable();
    let bursts = samples
        .iter()
        .map(|sample| sample.burst)
        .collect::<BTreeSet<_>>()
        .len() as u64;
    let mut mix = Vec::new();
    for quantile in Quantile::REPORTED {
        let value_nanos = if sorted.is_empty() {
            Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns)
        } else {
            Measured::measured(percentile(
                &sorted,
                quantile,
                PercentileMethod::NearestRank,
            )?)
        };
        mix.push(MixPercentile {
            quantile,
            value_nanos,
            resolution: resolution(sorted.len() as u64, bursts, quantile),
            samples: sorted.len() as u64,
            bursts,
        });
    }
    let measured = |value: f64| -> Result<Measured<NonNegative>, ReadinessError> {
        Ok(Measured::measured(NonNegative::new(value)?))
    };
    let mean = |sum: u128| -> Result<Measured<NonNegative>, ReadinessError> {
        if attempts == 0 {
            return Ok(Measured::not_measured(NotMeasuredReason::NotRecorded));
        }
        measured(sum as f64 / attempts as f64)
    };
    let ttft_value = match mix
        .iter()
        .find(|estimate| estimate.quantile == latency_objective.quantile)
        .and_then(|estimate| estimate.value_nanos.value().copied())
    {
        Some(nanos) => measured(nanos)?,
        None => Measured::not_measured(NotMeasuredReason::NoSuccessfulRuns),
    };
    let objectives = ObjectiveVector {
        time_to_first_token_quantile: latency_objective.quantile,
        latency_objective,
        time_to_first_token_nanos: ttft_value,
        throughput_under_latency_objective_tokens_per_second: Measured::not_measured(
            NotMeasuredReason::NotApplicable,
        ),
        peak_gpu_memory_bytes: measured(peak_gpu as f64)?,
        retained_gpu_memory_bytes: measured(retained_gpu as f64)?,
        peak_host_memory_bytes: measured(peak_host as f64)?,
        retained_host_memory_bytes: measured(retained_host as f64)?,
        transferred_bytes: mean(transferred)?,
        storage_read_bytes: mean(storage)?,
        preparation_cost_usd: Measured::not_measured(NotMeasuredReason::NotApplicable),
        cost_per_completed_request_usd: Measured::not_measured(NotMeasuredReason::NotApplicable),
        energy_per_completed_request_joules: Measured::not_measured(
            NotMeasuredReason::InstrumentUnavailable,
        ),
        reliability_success_rate: measured(success_rate.rate())?,
    };
    Ok(Measurement {
        cases: measured_cases,
        provenance,
        success_rate,
        mix,
        objectives,
    })
}

/// Elapsed nanoseconds of `interval` in `record`, or `None` when the record lacks it.
pub fn interval_nanos(record: &RunRecord, interval: IntervalKind) -> Option<u64> {
    record
        .interval(interval)
        .ok()
        .map(|measured| measured.elapsed_nanos())
}
