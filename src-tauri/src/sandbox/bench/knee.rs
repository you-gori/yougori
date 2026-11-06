//! The saturation knee of BENCH-05 (S11 line 369 "saturation knee"; S7 line 294 "a
//! measured saturation point"; §12.4 line 2849 "saturation behavior").
//!
//! The search raises the burst size from a start, doubling it up to a limit, until the
//! successful creates per second stop growing by the minimum gain or the failures pass
//! the threshold. The knee is the smallest acceptable burst size whose throughput is
//! within the minimum gain of the best acceptable one, refined by bisection between it
//! and the largest acceptable size below it. Every level is measured on a fresh fake
//! host, so no level inherits another's VMs, queue or pool.
//!
//! The search ignores retries: a point's throughput and failures are its first attempts'
//! (S8 line 321). A level run under a retry policy keeps its retries in its report,
//! beside the point, and a retry that completes a refused create never lifts the
//! throughput or lowers the failures the search compares.

use serde::Serialize;

use super::host::FakeVmHost;
use super::plan::{AttemptLimits, Bench05Plan, AUTHORIZED_HOST_CONCURRENCY};
use super::report::VmRunReport;
use super::retry::RetryPolicy;
use super::runner::{FakeVmRunner, RunnerConfig};
use super::timing::FaultPlan;
use super::BenchError;

/// When the search stops raising the burst size.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct KneePolicy {
    min_relative_gain: f64,
    max_failure_fraction: f64,
    start_concurrency: u32,
    max_concurrency: u32,
}

impl KneePolicy {
    /// `min_relative_gain` in (0, 1), `max_failure_fraction` in [0, 1), and burst sizes
    /// from `start_concurrency` (at least one) to `max_concurrency`.
    pub fn new(
        min_relative_gain: f64,
        max_failure_fraction: f64,
        start_concurrency: u32,
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
        if start_concurrency == 0 || max_concurrency < start_concurrency {
            return Err(BenchError::InvalidParameter {
                field: "concurrency",
                reason: "the search starts at one create or more and ends at or above it",
            });
        }
        Ok(Self {
            min_relative_gain,
            max_failure_fraction,
            start_concurrency,
            max_concurrency,
        })
    }

    pub fn min_relative_gain(&self) -> f64 {
        self.min_relative_gain
    }

    pub fn max_failure_fraction(&self) -> f64 {
        self.max_failure_fraction
    }

    pub fn max_concurrency(&self) -> u32 {
        self.max_concurrency
    }

    fn acceptable(&self, point: &KneePoint) -> bool {
        point.failure_fraction <= self.max_failure_fraction
    }
}

/// One measured burst size.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct KneePoint {
    pub concurrency: u32,
    /// Successful first attempts per second of the bursts' windows.
    pub successes_per_second: f64,
    /// Failed initial attempts over every initial attempt.
    pub failure_fraction: f64,
}

/// Why the search stopped raising the burst size.
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(tag = "stop", rename_all = "snake_case")]
pub enum KneeStop {
    /// The next size improved throughput by less than the minimum gain.
    ThroughputPlateau {
        concurrency: u32,
        relative_gain: f64,
    },
    /// Failures passed the threshold at this size.
    FailureThreshold {
        concurrency: u32,
        failure_fraction: f64,
    },
    /// The limit was reached while throughput still grew.
    ConcurrencyLimit { concurrency: u32 },
}

/// The search's result.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct KneeSearch {
    /// Every measured size in the order measured: the raising steps, then the bisection.
    pub points: Vec<KneePoint>,
    pub stop: KneeStop,
    /// `None` when no acceptable size completed a create.
    pub knee_concurrency: Option<u32>,
    pub best_successes_per_second: f64,
}

/// The search over the fake runner, with every level's full report.
#[derive(Clone, Debug, PartialEq)]
pub struct KneeReport {
    pub search: KneeSearch,
    pub levels: Vec<VmRunReport>,
}

fn take<M>(
    measure: &mut M,
    points: &mut Vec<KneePoint>,
    concurrency: u32,
) -> Result<KneePoint, BenchError>
where
    M: FnMut(u32) -> Result<KneePoint, BenchError>,
{
    let point = measure(concurrency)?;
    if point.concurrency != concurrency
        || !point.successes_per_second.is_finite()
        || point.successes_per_second < 0.0
        || !(0.0..=1.0).contains(&point.failure_fraction)
    {
        return Err(BenchError::InvalidParameter {
            field: "point",
            reason: "a measured point names its size, a finite rate and a fraction",
        });
    }
    points.push(point);
    Ok(point)
}

fn relative_gain(before: f64, after: f64) -> f64 {
    if before > 0.0 {
        after / before - 1.0
    } else if after > 0.0 {
        f64::INFINITY
    } else {
        0.0
    }
}

/// The knee search over `measure`, which measures one burst size.
pub fn knee_search<M>(policy: KneePolicy, mut measure: M) -> Result<KneeSearch, BenchError>
where
    M: FnMut(u32) -> Result<KneePoint, BenchError>,
{
    let mut points = Vec::new();
    let mut previous: Option<KneePoint> = None;
    let mut concurrency = policy.start_concurrency;
    let stop = loop {
        let point = take(&mut measure, &mut points, concurrency)?;
        if !policy.acceptable(&point) {
            break KneeStop::FailureThreshold {
                concurrency,
                failure_fraction: point.failure_fraction,
            };
        }
        if let Some(before) = previous {
            let gain = relative_gain(before.successes_per_second, point.successes_per_second);
            if gain < policy.min_relative_gain {
                break KneeStop::ThroughputPlateau {
                    concurrency,
                    relative_gain: gain,
                };
            }
        }
        previous = Some(point);
        let next = concurrency.saturating_mul(2).min(policy.max_concurrency);
        if next == concurrency {
            break KneeStop::ConcurrencyLimit { concurrency };
        }
        concurrency = next;
    };
    let accepted: Vec<KneePoint> = points
        .iter()
        .filter(|point| policy.acceptable(point))
        .copied()
        .collect();
    let best = accepted
        .iter()
        .map(|point| point.successes_per_second)
        .fold(0.0f64, f64::max);
    let threshold = best * (1.0 - policy.min_relative_gain);
    let mut knee = accepted
        .iter()
        .filter(|point| point.successes_per_second >= threshold && point.successes_per_second > 0.0)
        .map(|point| point.concurrency)
        .min();
    if let Some(mut high) = knee {
        let mut low = accepted
            .iter()
            .map(|point| point.concurrency)
            .filter(|size| *size < high)
            .max();
        while let Some(below) = low {
            if high - below <= 1 {
                break;
            }
            let middle = below + (high - below) / 2;
            let point = take(&mut measure, &mut points, middle)?;
            if policy.acceptable(&point) && point.successes_per_second >= threshold {
                high = middle;
            } else {
                low = Some(middle);
            }
        }
        knee = Some(high);
    }
    Ok(KneeSearch {
        points,
        stop,
        knee_concurrency: knee,
        best_successes_per_second: best,
    })
}

/// The knee of BENCH-05 bursts on fresh fake hosts from `make_host`: every level is
/// `bursts` independent bursts of one size. A limit at or above
/// [`AUTHORIZED_HOST_CONCURRENCY`] is refused, since those sizes need an authorized,
/// sized host.
pub fn saturation_search<H, F>(
    make_host: F,
    config: &RunnerConfig,
    bursts: u32,
    limits: AttemptLimits,
    policy: KneePolicy,
    faults: &FaultPlan,
) -> Result<KneeReport, BenchError>
where
    H: FakeVmHost,
    F: FnMut() -> Result<H, BenchError>,
{
    saturation_search_with_retries(
        make_host,
        config,
        bursts,
        limits,
        policy,
        &RetryPolicy::off(),
        faults,
    )
}

/// [`saturation_search`] with every level's bursts run under `retries`. The points, the
/// stop and the knee come from first attempts only, so they are the ones the same search
/// finds without retries whenever the retries leave the first attempts as they were; the
/// retries stay in each level's report.
pub fn saturation_search_with_retries<H, F>(
    mut make_host: F,
    config: &RunnerConfig,
    bursts: u32,
    limits: AttemptLimits,
    policy: KneePolicy,
    retries: &RetryPolicy,
    faults: &FaultPlan,
) -> Result<KneeReport, BenchError>
where
    H: FakeVmHost,
    F: FnMut() -> Result<H, BenchError>,
{
    if policy.max_concurrency >= AUTHORIZED_HOST_CONCURRENCY {
        return Err(BenchError::NeedsAuthorizedSizedHost {
            concurrent_creates: policy.max_concurrency,
        });
    }
    let mut levels = Vec::new();
    let search = knee_search(policy, |concurrency| {
        let plan =
            Bench05Plan::burst(concurrency, bursts, limits)?.with_retries(retries.clone())?;
        let mut host = make_host()?;
        let mut level = config.clone();
        level.timing.seed =
            config.timing.seed ^ u64::from(concurrency).wrapping_mul(0x9E37_79B9_7F4A_7C15);
        let mut runner = FakeVmRunner::new(&mut host, level)?;
        let report = runner.run_bench05(&plan, faults)?;
        let point = KneePoint {
            concurrency,
            successes_per_second: report.mean_successes_per_second(),
            failure_fraction: report.failure_fraction()?,
        };
        levels.push(report);
        Ok(point)
    })?;
    Ok(KneeReport { search, levels })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic curve: ten creates per second per concurrent create up to twelve, then
    /// flat; half the creates fail from `failing_from` on.
    fn curve(failing_from: u32) -> impl FnMut(u32) -> Result<KneePoint, BenchError> {
        move |concurrency| {
            Ok(KneePoint {
                concurrency,
                successes_per_second: f64::from(concurrency.min(12)) * 10.0,
                failure_fraction: if concurrency >= failing_from {
                    0.5
                } else {
                    0.0
                },
            })
        }
    }

    fn sizes(search: &KneeSearch) -> Vec<u32> {
        search
            .points
            .iter()
            .map(|point| point.concurrency)
            .collect()
    }

    #[test]
    fn the_knee_of_a_synthetic_curve_is_found_by_doubling_then_bisection() {
        let policy = KneePolicy::new(0.1, 0.05, 1, 64).unwrap();
        let search = knee_search(policy, curve(32)).unwrap();
        // 1, 2, 4, 8, 16 grow; 32 fails half its creates.
        assert_eq!(
            search.stop,
            KneeStop::FailureThreshold {
                concurrency: 32,
                failure_fraction: 0.5
            }
        );
        assert_eq!(search.best_successes_per_second, 120.0);
        // Within 10 % of 120 means at least 108: 16 qualifies, 8 does not; bisection
        // measures 12 (120), 10 (100) and 11 (110).
        assert_eq!(sizes(&search), vec![1, 2, 4, 8, 16, 32, 12, 10, 11]);
        assert_eq!(search.knee_concurrency, Some(11));
    }

    #[test]
    fn a_plateau_stops_the_search() {
        let policy = KneePolicy::new(0.1, 0.05, 4, 64).unwrap();
        let search = knee_search(policy, curve(u32::MAX)).unwrap();
        // 4 → 40, 8 → 80, 16 → 120 (+50 %), 32 → 120 (+0 %).
        assert_eq!(
            search.stop,
            KneeStop::ThroughputPlateau {
                concurrency: 32,
                relative_gain: 0.0
            }
        );
        assert_eq!(search.knee_concurrency, Some(11));
    }

    #[test]
    fn the_limit_is_measured_and_named() {
        let policy = KneePolicy::new(0.1, 0.05, 1, 6).unwrap();
        let search = knee_search(policy, curve(u32::MAX)).unwrap();
        assert_eq!(sizes(&search)[..4], [1, 2, 4, 6]);
        assert_eq!(search.stop, KneeStop::ConcurrencyLimit { concurrency: 6 });
        // 60 is the best; within 10 % means 54 or more: only 6 itself.
        assert_eq!(search.knee_concurrency, Some(6));
    }

    #[test]
    fn no_knee_when_even_one_create_fails_too_often() {
        let policy = KneePolicy::new(0.1, 0.05, 1, 64).unwrap();
        let search = knee_search(policy, curve(1)).unwrap();
        assert_eq!(search.knee_concurrency, None);
        assert_eq!(sizes(&search), vec![1]);
        assert_eq!(search.best_successes_per_second, 0.0);
    }

    #[test]
    fn invalid_policies_and_points_are_refused() {
        for (gain, failures, start, max) in [
            (0.0, 0.05, 1, 8),
            (1.0, 0.05, 1, 8),
            (0.1, 1.0, 1, 8),
            (0.1, -0.1, 1, 8),
            (0.1, 0.05, 0, 8),
            (0.1, 0.05, 9, 8),
        ] {
            assert!(KneePolicy::new(gain, failures, start, max).is_err());
        }
        let policy = KneePolicy::new(0.1, 0.05, 1, 8).unwrap();
        let wrong_size = knee_search(policy, |concurrency| {
            Ok(KneePoint {
                concurrency: concurrency + 1,
                successes_per_second: 1.0,
                failure_fraction: 0.0,
            })
        });
        assert!(matches!(
            wrong_size,
            Err(BenchError::InvalidParameter { field: "point", .. })
        ));
        let not_a_rate = knee_search(policy, |concurrency| {
            Ok(KneePoint {
                concurrency,
                successes_per_second: f64::NAN,
                failure_fraction: 0.0,
            })
        });
        assert!(not_a_rate.is_err());
    }
}
