//! What the observations of one violation subject establish (VM part §8.2 line 2268;
//! VM-W43 line 2491).
//!
//! A fresh host observation establishes a violation. A host check of the same subject that
//! found nothing contradicts it, and the result is uncertain; a guest report never
//! contradicts a host observation, so a guest cannot talk one away. Stale host
//! observations are uncertain too. Only when no host observer saw anything does a guest
//! report stand, and it stays a guest report. Nothing here yields a pass: observations
//! that saw no violation give [`Assessment::NoViolationObserved`], which is the absence of
//! a signal, not a verdict.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::policy::UncertainPolicy;
use super::signal::{
    Conflict, Freshness, GrantRef, HostObserver, MonitoredResource, MonitoringSignal, Reading,
    SignalClass, SignalSource,
};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, Digest, ExecutionId, MonotonicTime};

/// The most observations one assessment reads.
pub const MAX_OBSERVATIONS_PER_ASSESSMENT: usize = 64;

/// One incident: one subject of one class in one sandbox (VM-W43 "one response per
/// incident").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IncidentKey {
    pub sandbox: ExecutionId,
    pub class: SignalClass,
    pub subject: Digest,
}

/// A signal ready for a decision: whose, about what, from which source and how fresh. It is
/// made only by [`assess_violation`] and the [`ResourceMonitor`](super::ResourceMonitor),
/// so its source label is the one the observations carried.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SignalAssessment {
    key: IncidentKey,
    source: SignalSource,
    freshness: Freshness,
    #[serde(skip_serializing_if = "Option::is_none")]
    violated_grant: Option<GrantRef>,
    assessed_at: MonotonicTime,
}

impl SignalAssessment {
    pub(super) fn new(
        key: IncidentKey,
        source: SignalSource,
        freshness: Freshness,
        violated_grant: Option<GrantRef>,
        assessed_at: MonotonicTime,
    ) -> Self {
        Self {
            key,
            source,
            freshness,
            violated_grant,
            assessed_at,
        }
    }

    /// The incident the assessment is about.
    pub fn key(&self) -> &IncidentKey {
        &self.key
    }

    /// The sandbox the observations are about.
    pub fn sandbox(&self) -> &ExecutionId {
        &self.key.sandbox
    }

    /// The violation or resource class.
    pub const fn class(&self) -> SignalClass {
        self.key.class
    }

    /// The source of the observation the assessment rests on (§8.2 line 2268).
    pub const fn source(&self) -> SignalSource {
        self.source
    }

    /// Fresh, stale or conflicting; only fresh host observations act (VM-W43).
    pub const fn freshness(&self) -> Freshness {
        self.freshness
    }

    /// The grant the violation was against, if the observations named one.
    pub const fn violated_grant(&self) -> Option<GrantRef> {
        self.violated_grant
    }

    /// When the assessment was made, on the host clock.
    pub const fn assessed_at(&self) -> MonotonicTime {
        self.assessed_at
    }
}

/// The result of assessing observations.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "assessment", rename_all = "snake_case")]
pub enum Assessment {
    /// No observer saw a violation: no signal, and not a pass.
    NoViolationObserved,
    Signal(SignalAssessment),
}

/// Why observations could not be assessed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssessRefusal {
    TooMany {
        given: usize,
        max: usize,
    },
    /// The observations are not all about one sandbox, class and subject.
    MixedSubjects,
    /// Resource signals are judged over sustained windows by the
    /// [`ResourceMonitor`](super::ResourceMonitor).
    ResourceClass {
        resource: MonitoredResource,
    },
    /// The observations name different violated grants.
    ConflictingGrants,
}

impl fmt::Display for AssessRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooMany { given, max } => {
                write!(f, "{given} observations exceed the bound of {max}")
            }
            Self::MixedSubjects => {
                f.write_str("the observations are not about one sandbox, class and subject")
            }
            Self::ResourceClass { resource } => write!(
                f,
                "{} is judged over sustained windows, not as a violation",
                resource.label()
            ),
            Self::ConflictingGrants => f.write_str("the observations name different grants"),
        }
    }
}

impl std::error::Error for AssessRefusal {}

/// Assesses the observations of one violation subject at `clock`'s time on the host's
/// `session` (§8.2; VM-W43): fresh host observation, contradicted or not, then stale host
/// observation, then guest report.
pub fn assess_violation(
    signals: &[MonitoringSignal],
    policy: &UncertainPolicy,
    clock: &dyn Clock,
    session: ClockSession,
) -> Result<Assessment, AssessRefusal> {
    let Some(first) = signals.first() else {
        return Ok(Assessment::NoViolationObserved);
    };
    if signals.len() > MAX_OBSERVATIONS_PER_ASSESSMENT {
        return Err(AssessRefusal::TooMany {
            given: signals.len(),
            max: MAX_OBSERVATIONS_PER_ASSESSMENT,
        });
    }
    let key = IncidentKey {
        sandbox: first.sandbox().clone(),
        class: first.class(),
        subject: *first.subject(),
    };
    if let SignalClass::Resource { resource } = key.class {
        return Err(AssessRefusal::ResourceClass { resource });
    }
    if signals.iter().any(|signal| {
        signal.sandbox() != &key.sandbox
            || signal.class() != key.class
            || signal.subject() != &key.subject
    }) {
        return Err(AssessRefusal::MixedSubjects);
    }
    let grants: BTreeSet<GrantRef> = signals
        .iter()
        .filter(|signal| signal.reading() == Reading::ViolationObserved)
        .filter_map(MonitoringSignal::violated_grant)
        .collect();
    if grants.len() > 1 {
        return Err(AssessRefusal::ConflictingGrants);
    }
    let violated_grant = grants.into_iter().next();
    let now = clock.now();
    let max_age = policy.max_observation_age();
    let fresh = |signal: &MonitoringSignal| signal.freshness(now, session, max_age).is_fresh();
    let fresh_observed = newest(
        host_readings(signals, Reading::ViolationObserved).filter(|(_, signal)| fresh(signal)),
    );
    let assessment = |source: SignalSource, freshness: Freshness| {
        Assessment::Signal(SignalAssessment::new(
            key.clone(),
            source,
            freshness,
            violated_grant,
            now,
        ))
    };
    if let Some((observer, observed)) = fresh_observed {
        let contradicting = newest(
            host_readings(signals, Reading::CheckPassed).filter(|(_, signal)| fresh(signal)),
        );
        let freshness = match contradicting {
            Some((contradicted_by, _)) => Freshness::Conflicting {
                conflict: Conflict {
                    reported_by: observer,
                    contradicted_by,
                },
            },
            None => Freshness::Fresh,
        };
        return Ok(assessment(observed.source(), freshness));
    }
    if let Some((_, observed)) = newest(host_readings(signals, Reading::ViolationObserved)) {
        return Ok(assessment(
            observed.source(),
            observed.freshness(now, session, max_age),
        ));
    }
    let guest = signals
        .iter()
        .filter(|signal| {
            signal.source() == SignalSource::GuestReported
                && signal.reading() == Reading::ViolationObserved
        })
        .max_by_key(|signal| signal.observed_at());
    Ok(match guest {
        Some(report) => assessment(
            SignalSource::GuestReported,
            report.freshness(now, session, max_age),
        ),
        None => Assessment::NoViolationObserved,
    })
}

/// The host observations among `signals` with `reading`, each with its observer.
fn host_readings(
    signals: &[MonitoringSignal],
    reading: Reading,
) -> impl Iterator<Item = (HostObserver, &MonitoringSignal)> + '_ {
    signals.iter().filter_map(move |signal| {
        signal
            .source()
            .observer()
            .filter(|_| signal.reading() == reading)
            .map(|observer| (observer, signal))
    })
}

/// The newest observation, ties broken by observer order so the choice is deterministic.
fn newest<'a>(
    candidates: impl Iterator<Item = (HostObserver, &'a MonitoringSignal)>,
) -> Option<(HostObserver, &'a MonitoringSignal)> {
    candidates.max_by_key(|(observer, signal)| (signal.observed_at(), *observer))
}
