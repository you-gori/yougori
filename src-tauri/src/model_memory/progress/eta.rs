//! Estimated remaining time with confidence (§3.10 line 648), from measured throughput,
//! as CORE-06's [`EtaEstimate`]: a range of seconds and the confidence that the time
//! falls inside it.
//!
//! Only measured progress yields an estimate. Too few measured segments, a stall, or
//! samples out of order give none, never a guessed number.

use std::collections::VecDeque;

use crate::foundation::events::EtaEstimate;
use crate::foundation::ids::MonotonicTime;

/// Measured segments an estimate needs. With one, the range of segment rates is a single
/// rate, which one more segment matches with no confidence at all.
pub const MIN_SEGMENTS_FOR_ESTIMATE: usize = 2;

/// How many bytes were usable at one moment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ThroughputSample {
    pub at: MonotonicTime,
    pub usable_bytes: u64,
}

/// The confidence of a range from the slowest to the fastest of `segments` measured
/// segment rates: the chance that one more segment's rate falls inside it when segment
/// rates are exchangeable, `(n - 1) / (n + 1)`, in whole percent rounded down. Two
/// segments give 33%, three 50%, four 60% and 31 (a 32-sample window) 93%.
pub fn range_confidence_percent(segments: usize) -> u8 {
    let segments = u64::try_from(segments).unwrap_or(u64::MAX);
    let percent = segments.saturating_sub(1).saturating_mul(100) / segments.saturating_add(1);
    u8::try_from(percent).unwrap_or(100)
}

/// Estimates the remaining time from samples in time order (§3.10 line 648):
///
/// ```text
/// low        = floor(remaining / fastest segment rate)
/// high       = ceil(remaining / slowest segment rate)
/// confidence = (segments - 1) / (segments + 1)
/// ```
///
/// Fewer than [`MIN_SEGMENTS_FOR_ESTIMATE`] segments, a segment without progress (the
/// high end would be unbounded), samples out of time order, or usable bytes that fall
/// give no estimate. Nothing remaining is exactly zero seconds, with full confidence.
pub fn estimate_remaining_time(
    samples: &[ThroughputSample],
    remaining_bytes: u64,
) -> Option<EtaEstimate> {
    if remaining_bytes == 0 {
        return EtaEstimate::new(0, 0, 100).ok();
    }
    let mut fastest = 0.0_f64;
    let mut slowest = f64::INFINITY;
    let mut segments = 0_usize;
    for pair in samples.windows(2) {
        let [earlier, later] = pair else {
            return None;
        };
        let span_seconds = later.at.checked_duration_since(earlier.at)?.as_secs_f64();
        if span_seconds <= 0.0 || later.usable_bytes < earlier.usable_bytes {
            return None;
        }
        let rate = (later.usable_bytes - earlier.usable_bytes) as f64 / span_seconds;
        fastest = fastest.max(rate);
        slowest = slowest.min(rate);
        segments += 1;
    }
    if segments < MIN_SEGMENTS_FOR_ESTIMATE || slowest <= 0.0 {
        return None;
    }
    let remaining = remaining_bytes as f64;
    // Finite and non-negative here; `as` saturates.
    let low_seconds = (remaining / fastest).floor() as u64;
    let high_seconds = (remaining / slowest).ceil() as u64;
    EtaEstimate::new(
        low_seconds,
        high_seconds,
        range_confidence_percent(segments),
    )
    .ok()
}

/// The latest samples of one transfer, bounded to `capacity`. A sample at the same time
/// replaces the previous one; time or usable bytes going back restart the window.
#[derive(Clone, Debug)]
pub(super) struct ThroughputWindow {
    samples: VecDeque<ThroughputSample>,
    capacity: usize,
}

impl ThroughputWindow {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            samples: VecDeque::with_capacity(capacity),
            capacity,
        }
    }

    pub(super) fn record(&mut self, at: MonotonicTime, usable_bytes: u64) {
        if let Some(last) = self.samples.back().copied() {
            if at < last.at || usable_bytes < last.usable_bytes {
                self.samples.clear();
            } else if at == last.at {
                self.samples.pop_back();
            }
        }
        self.samples
            .push_back(ThroughputSample { at, usable_bytes });
        while self.samples.len() > self.capacity {
            self.samples.pop_front();
        }
    }

    pub(super) fn clear(&mut self) {
        self.samples.clear();
    }

    pub(super) fn estimate(&self, remaining_bytes: u64) -> Option<EtaEstimate> {
        let samples: Vec<ThroughputSample> = self.samples.iter().copied().collect();
        estimate_remaining_time(&samples, remaining_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MB: u64 = 1_000_000;

    fn samples(points: &[(u64, u64)]) -> Vec<ThroughputSample> {
        points
            .iter()
            .map(|&(seconds, megabytes)| ThroughputSample {
                at: MonotonicTime::from_nanos(seconds * 1_000_000_000),
                usable_bytes: megabytes * MB,
            })
            .collect()
    }

    fn range(estimate: Option<EtaEstimate>) -> (u64, u64, u8) {
        let estimate = estimate.expect("an estimate");
        (
            estimate.remaining_low_seconds(),
            estimate.remaining_high_seconds(),
            estimate.confidence_percent(),
        )
    }

    #[test]
    fn steady_throughput_gives_a_tight_range() {
        // Three segments at 100 MB/s; 700 MB remain, so exactly 7 s, at (3 - 1) / (3 + 1).
        let estimate =
            estimate_remaining_time(&samples(&[(0, 0), (1, 100), (2, 200), (3, 300)]), 700 * MB);
        assert_eq!(range(estimate), (7, 7, 50));
    }

    #[test]
    fn uneven_throughput_widens_the_range() {
        // Segments at 50, 150 and 100 MB/s: floor(700 / 150) = 4 s to 700 / 50 = 14 s.
        let estimate =
            estimate_remaining_time(&samples(&[(0, 0), (1, 50), (2, 200), (3, 300)]), 700 * MB);
        assert_eq!(range(estimate), (4, 14, 50));
    }

    #[test]
    fn confidence_grows_with_the_measured_segments() {
        let worked = [
            (0, 0),
            (1, 0),
            (2, 33),
            (3, 50),
            (4, 60),
            (9, 80),
            (19, 90),
            (31, 93),
        ];
        for (segments, percent) in worked {
            assert_eq!(range_confidence_percent(segments), percent, "{segments}");
        }
        assert!(range_confidence_percent(usize::MAX) <= 100);
        // A full 32-sample window at a steady 10 MB/s.
        let steady: Vec<(u64, u64)> = (0..32).map(|second| (second, second * 10)).collect();
        assert_eq!(
            range(estimate_remaining_time(&samples(&steady), 100 * MB)),
            (10, 10, 93)
        );
    }

    #[test]
    fn a_stall_gives_no_estimate() {
        // The slowest segment made no progress, so the range has no high end.
        assert_eq!(
            estimate_remaining_time(&samples(&[(0, 0), (1, 100), (2, 100), (3, 200)]), 700 * MB),
            None
        );
    }

    #[test]
    fn too_few_measurements_are_never_guessed() {
        assert_eq!(estimate_remaining_time(&[], 10), None);
        assert_eq!(estimate_remaining_time(&samples(&[(0, 5)]), 10), None);
        // One segment: a single rate, covered with no confidence.
        assert_eq!(
            estimate_remaining_time(&samples(&[(0, 0), (1, 100)]), 100 * MB),
            None
        );
        // Out of time order, or usable bytes falling.
        assert_eq!(
            estimate_remaining_time(&samples(&[(2, 0), (1, 5), (3, 9)]), 10),
            None
        );
        assert_eq!(
            estimate_remaining_time(&samples(&[(0, 5), (1, 4), (2, 9)]), 10),
            None
        );
        // Nothing remaining is zero seconds, whatever was measured.
        assert_eq!(range(estimate_remaining_time(&[], 0)), (0, 0, 100));
    }

    #[test]
    fn the_window_is_bounded_and_restarts_when_progress_goes_back() {
        let mut window = ThroughputWindow::new(3);
        for (seconds, megabytes) in [(0, 0), (1, 100), (2, 200), (3, 300), (4, 400)] {
            window.record(
                MonotonicTime::from_nanos(seconds * 1_000_000_000),
                megabytes * MB,
            );
        }
        assert_eq!(window.samples.len(), 3);
        window.record(MonotonicTime::from_nanos(4_000_000_000), 450 * MB);
        assert_eq!(window.samples.len(), 3);
        assert_eq!(
            window.samples.back().map(|sample| sample.usable_bytes),
            Some(450 * MB)
        );
        window.record(MonotonicTime::from_nanos(5_000_000_000), 10 * MB);
        assert_eq!(window.samples.len(), 1);
        assert_eq!(window.estimate(10 * MB), None);
    }
}
