//! A sandbox's host-observed readiness after its launch (VM part §6.1
//! boot_evidence_checked, line 2289; §8.1 line 2439: re-evaluate relevant evidence;
//! leftover entries H01, S01, M02 and M08: launch-time confinement evidence must not remain
//! current indefinitely, and readiness stays unavailable until the required fresh evidence
//! exists).
//!
//! The launch transaction grants authority only after host-observed readiness, and the
//! supervisor asks the backend to observe the VM again later
//! ([`Supervisor::observe_readiness`](super::Supervisor::observe_readiness)). What the host
//! found the last time is kept with the sandbox: while it is unavailable, no new work is
//! authorized under the sandbox, until a later observation finds the VM ready.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::{Readiness, ReadinessReport};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::MonotonicTime;

/// The most characters of a backend's report kept with a sandbox.
pub const MAX_READINESS_DETAIL_CHARS: usize = 256;

/// What the supervisor last learned of a sandbox's readiness since its current boot.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "readiness", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
pub enum ObservedReadiness {
    /// Only the launch transaction's own host-observed readiness exists for this boot.
    /// State persisted before readiness was observed again reads as this.
    #[default]
    AtLaunch,
    /// The backend observed the VM again at `at`, and the host found it ready.
    Ready { at: MonotonicTime },
    /// The backend observed the VM again and the host did not find it ready, first at
    /// `since`; `detail` is the backend's report, bounded.
    Unavailable {
        since: MonotonicTime,
        detail: String,
    },
}

crate::foundation::strict_serde::strict_tag!(ObservedReadiness, "readiness");

impl ObservedReadiness {
    /// What a report made at `now` says, after `previous`: ready only when the host itself
    /// observed the VM ready; otherwise unavailable since the first report that was not.
    pub fn after(previous: &Self, report: &ReadinessReport, now: MonotonicTime) -> Self {
        let detail = match (&report.readiness, report.source) {
            (Readiness::Ready, SourceClass::HostProbe) => return Self::Ready { at: now },
            (Readiness::Ready, source) => {
                format!("readiness came from a {source}; only readiness the host observed counts")
            }
            (Readiness::NotReady { detail }, _) => detail.clone(),
        };
        let since = match previous {
            Self::Unavailable { since, .. } => *since,
            Self::AtLaunch | Self::Ready { .. } => now,
        };
        Self::Unavailable {
            since,
            detail: detail.chars().take(MAX_READINESS_DETAIL_CHARS).collect(),
        }
    }

    pub fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }
}

impl fmt::Display for ObservedReadiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AtLaunch => f.write_str("ready at launch; not observed again since"),
            Self::Ready { at } => write!(f, "observed ready again at {} ns", at.as_nanos()),
            Self::Unavailable { since, detail } => write!(
                f,
                "readiness unavailable since {} ns: {detail}",
                since.as_nanos()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(source: SourceClass, readiness: Readiness) -> ReadinessReport {
        ReadinessReport { source, readiness }
    }

    #[test]
    fn only_host_observed_readiness_renews_it_and_unavailability_keeps_its_start() {
        let t = MonotonicTime::from_nanos;
        let ready = report(SourceClass::HostProbe, Readiness::Ready);
        let stale = report(
            SourceClass::HostProbe,
            Readiness::NotReady {
                detail: "the record is not current".to_owned(),
            },
        );
        let guest = report(SourceClass::GuestReport, Readiness::Ready);
        let at_launch = ObservedReadiness::default();
        assert_eq!(at_launch, ObservedReadiness::AtLaunch);
        assert_eq!(
            ObservedReadiness::after(&at_launch, &ready, t(5)),
            ObservedReadiness::Ready { at: t(5) }
        );
        let first = ObservedReadiness::after(&at_launch, &stale, t(10));
        assert_eq!(
            first,
            ObservedReadiness::Unavailable {
                since: t(10),
                detail: "the record is not current".to_owned()
            }
        );
        assert!(first.is_unavailable());
        let later = ObservedReadiness::after(&first, &guest, t(20));
        assert!(matches!(
            &later,
            ObservedReadiness::Unavailable { since, detail }
                if *since == t(10) && detail.contains("guest report")
        ));
        assert_eq!(
            ObservedReadiness::after(&later, &ready, t(30)),
            ObservedReadiness::Ready { at: t(30) }
        );
        let long = report(
            SourceClass::HostProbe,
            Readiness::NotReady {
                detail: "x".repeat(1000),
            },
        );
        assert!(matches!(
            ObservedReadiness::after(&at_launch, &long, t(1)),
            ObservedReadiness::Unavailable { detail, .. }
                if detail.chars().count() == MAX_READINESS_DETAIL_CHARS
        ));
        assert!(first
            .to_string()
            .starts_with("readiness unavailable since 10 ns"));
    }

    #[test]
    fn observed_readiness_round_trips_and_refuses_unknown_fields() {
        let unavailable = ObservedReadiness::Unavailable {
            since: MonotonicTime::from_nanos(7),
            detail: "not running".to_owned(),
        };
        let json = serde_json::to_value(&unavailable).unwrap();
        assert_eq!(json["readiness"], "unavailable");
        assert_eq!(
            serde_json::from_value::<ObservedReadiness>(json.clone()).unwrap(),
            unavailable
        );
        let mut extra = json;
        extra["ready"] = true.into();
        assert!(serde_json::from_value::<ObservedReadiness>(extra).is_err());
        assert_eq!(
            serde_json::from_value::<ObservedReadiness>(serde_json::json!({
                "readiness": "at_launch"
            }))
            .unwrap(),
            ObservedReadiness::AtLaunch
        );
    }
}
