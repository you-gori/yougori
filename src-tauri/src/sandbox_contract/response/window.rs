//! Resource signals judged over sustained windows with hysteresis (VM-W43 line 2491).
//!
//! A series is one resource of one sandbox from one source. It enters `exceeded` only after
//! every sample stayed at or above the high mark for the sustain window, and leaves it only
//! after every sample stayed at or below the low mark, strictly lower, for the clear window.
//! A sample between the marks restarts whichever run was under way. A gap longer than the
//! sample bound breaks the run in progress, so missing data never completes a trigger or a
//! clear, and a stale sample moves nothing and yields an uncertain result. A signal that
//! hovers near a limit therefore cannot flap a response on and off: after a trigger, a new
//! trigger needs a full clear window and then a full sustain window.
//!
//! Host and guest series never mix, so a guest cannot push a host series over a limit or
//! hold it under one. When a host series triggers while another host observer's series of
//! the same resource is fresh and at or below its low mark, the result is conflicting.

use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::assess::{IncidentKey, SignalAssessment};
use super::policy::UncertainPolicy;
use super::signal::{
    judge_freshness, Conflict, Freshness, MonitoredResource, MonitoringSignal, Reading,
    SignalClass, SignalSource,
};
use crate::foundation::evidence::{ClockSession, Staleness};
use crate::foundation::ids::{digest, Clock, Digest, ExecutionId, MonotonicTime};

const SERIES_SUBJECT_DOMAIN: &str = "yougori/sandbox/response/resource-series/v1";

/// The most series a monitor may track.
pub const MAX_MONITORED_SERIES: usize = 4_096;

/// The hysteresis window of one resource. Marks are in the resource's unit
/// ([`MonitoredResource::unit`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SustainedWindow {
    /// A sample at or above this amount is over the limit.
    pub high_mark: u64,
    /// A sample at or below this amount is under it; strictly below `high_mark`.
    pub low_mark: u64,
    /// How long samples must stay over before the series is exceeded.
    pub sustain_seconds: u64,
    /// How long samples must stay under before an exceeded series clears.
    pub clear_seconds: u64,
    /// The longest gap between two samples that keeps a run unbroken; at most the shorter
    /// of the two windows.
    pub max_sample_gap_seconds: u64,
}

impl SustainedWindow {
    /// Refuses marks without a gap and zero or oversized windows.
    pub fn validate(&self) -> Result<(), WindowProblem> {
        if self.low_mark >= self.high_mark {
            return Err(WindowProblem::NoHysteresisGap {
                high_mark: self.high_mark,
                low_mark: self.low_mark,
            });
        }
        if self.sustain_seconds == 0 {
            return Err(WindowProblem::ZeroSustain);
        }
        if self.clear_seconds == 0 {
            return Err(WindowProblem::ZeroClear);
        }
        if self.max_sample_gap_seconds == 0 {
            return Err(WindowProblem::ZeroSampleGap);
        }
        let shorter = self.sustain_seconds.min(self.clear_seconds);
        if self.max_sample_gap_seconds > shorter {
            return Err(WindowProblem::SampleGapExceedsWindow {
                max_sample_gap_seconds: self.max_sample_gap_seconds,
                window_seconds: shorter,
            });
        }
        Ok(())
    }

    fn sustain(&self) -> Duration {
        Duration::from_secs(self.sustain_seconds)
    }

    fn clear(&self) -> Duration {
        Duration::from_secs(self.clear_seconds)
    }

    fn max_gap(&self) -> Duration {
        Duration::from_secs(self.max_sample_gap_seconds)
    }
}

/// Why a window or a monitor was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowProblem {
    /// Without a gap between the marks a reading at the limit would flap.
    NoHysteresisGap {
        high_mark: u64,
        low_mark: u64,
    },
    ZeroSustain,
    ZeroClear,
    ZeroSampleGap,
    SampleGapExceedsWindow {
        max_sample_gap_seconds: u64,
        window_seconds: u64,
    },
    /// The series bound is zero or above [`MAX_MONITORED_SERIES`].
    SeriesBound {
        max_series: usize,
    },
}

impl fmt::Display for WindowProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoHysteresisGap {
                high_mark,
                low_mark,
            } => write!(
                f,
                "the low mark {low_mark} is not below the high mark {high_mark}"
            ),
            Self::ZeroSustain => f.write_str("the sustain window is zero"),
            Self::ZeroClear => f.write_str("the clear window is zero"),
            Self::ZeroSampleGap => f.write_str("the sample gap bound is zero"),
            Self::SampleGapExceedsWindow {
                max_sample_gap_seconds,
                window_seconds,
            } => write!(
                f,
                "a sample gap of {max_sample_gap_seconds} s exceeds the {window_seconds} s window"
            ),
            Self::SeriesBound { max_series } => write!(
                f,
                "the series bound {max_series} is not within 1–{MAX_MONITORED_SERIES}"
            ),
        }
    }
}

impl std::error::Error for WindowProblem {}

strict_response_enum! {
    /// Where one series stands.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WindowState tag "state" {
        Normal,
        /// Over the high mark since `since`, not yet for the sustain window.
        Rising {
            since: MonotonicTime,
        },
        /// Exceeded since `since`.
        Exceeded {
            since: MonotonicTime,
        },
        /// Exceeded since `exceeded_since`, under the low mark since `since`, not yet for
        /// the clear window.
        Falling {
            since: MonotonicTime,
            exceeded_since: MonotonicTime,
        },
    }
}

/// One series: a resource of a sandbox from one source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeriesKey {
    pub resource: MonitoredResource,
    pub source: SignalSource,
}

impl SeriesKey {
    /// The incident subject of a resource: one per resource, whichever source reports it.
    pub fn subject(resource: MonitoredResource) -> Digest {
        digest(SERIES_SUBJECT_DOMAIN, &[resource.label().as_bytes()])
    }
}

/// Why a sample was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowRefusal {
    /// Violations are assessed by [`assess_violation`](super::assess_violation).
    NotAResourceSignal,
    /// No window is configured for the resource.
    NoWindow {
        resource: MonitoredResource,
    },
    /// Not later than the series' last sample.
    OutOfOrder {
        last: MonotonicTime,
        observed_at: MonotonicTime,
    },
    TooManySeries {
        max_series: usize,
    },
}

impl fmt::Display for WindowRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotAResourceSignal => f.write_str("the signal is not a resource signal"),
            Self::NoWindow { resource } => {
                write!(f, "no window is configured for {}", resource.label())
            }
            Self::OutOfOrder { last, observed_at } => write!(
                f,
                "a sample at {} ns is not later than the last one at {} ns",
                observed_at.as_nanos(),
                last.as_nanos()
            ),
            Self::TooManySeries { max_series } => {
                write!(f, "the monitor already tracks {max_series} series")
            }
        }
    }
}

impl std::error::Error for WindowRefusal {}

/// What one sample did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceObservation {
    /// The series moved or held without a trigger or a clear.
    Held {
        sandbox: ExecutionId,
        series: SeriesKey,
        state: WindowState,
    },
    /// Over the high mark for the whole sustain window since `over_since`: a signal to
    /// decide on.
    Triggered {
        over_since: MonotonicTime,
        assessment: SignalAssessment,
    },
    /// Under the low mark for the whole clear window: the incident may close.
    Cleared { incident: IncidentKey },
    /// The sample was stale: nothing moved, and the result is uncertain.
    Uncertain { assessment: SignalAssessment },
}

#[derive(Clone, Copy, Debug)]
struct Series {
    window: SustainedWindow,
    state: WindowState,
    last: Option<(MonotonicTime, u64)>,
    reported_silent: bool,
}

/// The resource monitor of VM-W43: one hysteresis window per series.
#[derive(Clone, Debug)]
pub struct ResourceMonitor {
    session: ClockSession,
    max_observation_age: Duration,
    windows: BTreeMap<MonitoredResource, SustainedWindow>,
    series: BTreeMap<(ExecutionId, SeriesKey), Series>,
    max_series: usize,
}

impl ResourceMonitor {
    /// A monitor on the host's clock `session`, judging staleness by `uncertain`'s maximum
    /// observation age.
    pub fn new(
        session: ClockSession,
        uncertain: &UncertainPolicy,
        windows: BTreeMap<MonitoredResource, SustainedWindow>,
        max_series: usize,
    ) -> Result<Self, WindowProblem> {
        if max_series == 0 || max_series > MAX_MONITORED_SERIES {
            return Err(WindowProblem::SeriesBound { max_series });
        }
        for window in windows.values() {
            window.validate()?;
        }
        Ok(Self {
            session,
            max_observation_age: uncertain.max_observation_age(),
            windows,
            series: BTreeMap::new(),
            max_series,
        })
    }

    /// Where a series stands, if it is tracked.
    pub fn state(&self, sandbox: &ExecutionId, series: SeriesKey) -> Option<WindowState> {
        self.series
            .get(&(sandbox.clone(), series))
            .map(|tracked| tracked.state)
    }

    /// Feeds one sample into its series at `clock`'s time.
    pub fn observe(
        &mut self,
        signal: &MonitoringSignal,
        clock: &dyn Clock,
    ) -> Result<ResourceObservation, WindowRefusal> {
        let (SignalClass::Resource { resource }, Reading::Amount { amount }) =
            (signal.class(), signal.reading())
        else {
            return Err(WindowRefusal::NotAResourceSignal);
        };
        let window = *self
            .windows
            .get(&resource)
            .ok_or(WindowRefusal::NoWindow { resource })?;
        let series = SeriesKey {
            resource,
            source: signal.source(),
        };
        let key = (signal.sandbox().clone(), series);
        if !self.series.contains_key(&key) && self.series.len() >= self.max_series {
            return Err(WindowRefusal::TooManySeries {
                max_series: self.max_series,
            });
        }
        let now = clock.now();
        let incident = IncidentKey {
            sandbox: signal.sandbox().clone(),
            class: signal.class(),
            subject: SeriesKey::subject(resource),
        };
        let freshness = signal.freshness(now, self.session, self.max_observation_age);
        if !freshness.is_fresh() {
            return Ok(ResourceObservation::Uncertain {
                assessment: SignalAssessment::new(incident, signal.source(), freshness, None, now),
            });
        }
        let tracked = self.series.entry(key).or_insert(Series {
            window,
            state: WindowState::Normal,
            last: None,
            reported_silent: false,
        });
        let at = signal.observed_at();
        let mut state = tracked.state;
        if let Some((last, _)) = tracked.last {
            if at <= last {
                return Err(WindowRefusal::OutOfOrder {
                    last,
                    observed_at: at,
                });
            }
            if at.saturating_duration_since(last) > window.max_gap() {
                state = match state {
                    WindowState::Rising { .. } => WindowState::Normal,
                    WindowState::Falling { exceeded_since, .. } => WindowState::Exceeded {
                        since: exceeded_since,
                    },
                    other => other,
                };
            }
        }
        let over = amount >= window.high_mark;
        let under = amount <= window.low_mark;
        let mut triggered = None;
        let mut cleared = false;
        state = match state {
            WindowState::Normal if over => WindowState::Rising { since: at },
            WindowState::Normal => WindowState::Normal,
            WindowState::Rising { since } if over => {
                if at.saturating_duration_since(since) >= window.sustain() {
                    triggered = Some(since);
                    WindowState::Exceeded { since: at }
                } else {
                    WindowState::Rising { since }
                }
            }
            WindowState::Rising { .. } => WindowState::Normal,
            WindowState::Exceeded { since } if under => WindowState::Falling {
                since: at,
                exceeded_since: since,
            },
            WindowState::Exceeded { since } => WindowState::Exceeded { since },
            WindowState::Falling {
                since,
                exceeded_since,
            } if under => {
                if at.saturating_duration_since(since) >= window.clear() {
                    cleared = true;
                    WindowState::Normal
                } else {
                    WindowState::Falling {
                        since,
                        exceeded_since,
                    }
                }
            }
            WindowState::Falling { exceeded_since, .. } => WindowState::Exceeded {
                since: exceeded_since,
            },
        };
        tracked.state = state;
        tracked.last = Some((at, amount));
        tracked.reported_silent = false;
        if let Some(over_since) = triggered {
            let freshness = self.contradiction(signal.sandbox(), series, now);
            return Ok(ResourceObservation::Triggered {
                over_since,
                assessment: SignalAssessment::new(incident, signal.source(), freshness, None, now),
            });
        }
        if cleared {
            return Ok(ResourceObservation::Cleared { incident });
        }
        Ok(ResourceObservation::Held {
            sandbox: signal.sandbox().clone(),
            series,
            state,
        })
    }

    /// Whether another host observer contradicts a host series that just triggered: its
    /// own series of the same resource is normal, fresh and at or below its low mark.
    fn contradiction(
        &self,
        sandbox: &ExecutionId,
        series: SeriesKey,
        now: MonotonicTime,
    ) -> Freshness {
        let Some(reported_by) = series.source.observer() else {
            return Freshness::Fresh;
        };
        for ((owner, other), tracked) in &self.series {
            let Some(contradicted_by) = other.source.observer() else {
                continue;
            };
            if owner != sandbox || other.resource != series.resource || *other == series {
                continue;
            }
            let Some((at, amount)) = tracked.last else {
                continue;
            };
            let fresh = judge_freshness(
                at,
                self.session,
                now,
                self.session,
                self.max_observation_age,
            )
            .is_fresh();
            if fresh && tracked.state == WindowState::Normal && amount <= tracked.window.low_mark {
                return Freshness::Conflicting {
                    conflict: Conflict {
                        reported_by,
                        contradicted_by,
                    },
                };
            }
        }
        Freshness::Fresh
    }

    /// Series whose last sample is older than their sample gap bound: each yields one
    /// uncertain assessment per silence, never a pass (VM-W43). A later sample ends the
    /// silence.
    pub fn poll(&mut self, clock: &dyn Clock) -> Vec<SignalAssessment> {
        let now = clock.now();
        let mut silent = Vec::new();
        for ((sandbox, series), tracked) in &mut self.series {
            let Some((at, _)) = tracked.last else {
                continue;
            };
            let age = now.saturating_duration_since(at);
            let limit = tracked.window.max_gap();
            if tracked.reported_silent || age <= limit {
                continue;
            }
            tracked.reported_silent = true;
            silent.push(SignalAssessment::new(
                IncidentKey {
                    sandbox: sandbox.clone(),
                    class: SignalClass::Resource {
                        resource: series.resource,
                    },
                    subject: SeriesKey::subject(series.resource),
                },
                series.source,
                Freshness::Stale {
                    staleness: Staleness::TooOld { age, limit },
                },
                None,
                now,
            ));
        }
        silent
    }

    /// Stops tracking a sandbox's series; returns how many there were.
    pub fn forget_sandbox(&mut self, sandbox: &ExecutionId) -> usize {
        let before = self.series.len();
        self.series.retain(|(owner, _), _| owner != sandbox);
        before.saturating_sub(self.series.len())
    }
}
