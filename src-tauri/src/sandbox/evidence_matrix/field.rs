//! One field of an evidence row: a value with the evidence it was read from and how fresh
//! that evidence is at the reading, or an explicit statement that nobody observed it
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md: §7.1, lines 2356–2364; §8.1, lines
//! 2433–2437, "observation source and timestamp"; VM-W04, line 2589, "Distinguish
//! observed, asserted, verified and unavailable facts").
//!
//! Freshness follows the CORE-01 rules in their order: a value observed under another
//! configuration does not apply, one stamped on another clock session has no known age,
//! one dated after the reading is not current, and one older than the shorter of the
//! reader's maximum age and its own bound is too old. A stale value keeps its value and
//! says it is not current; it is never presented as current.

use std::fmt;
use std::time::Duration;

use serde::Serialize;

use crate::foundation::evidence::{
    ClockSession, ConfigurationFingerprint, Staleness, UnknownReason,
};
use crate::foundation::ids::{ContentKey, Digest, MonotonicTime};
use crate::foundation::signing::RootKeyId;
use crate::sandbox::backend::{FactName, FactSource, ObservationProblem};
use crate::sandbox::probes::JudgeContext;
use crate::sandbox::trust::UnixSeconds;

/// A field of an evidence row, by name, in the order of §7.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RowField {
    /// The host build the doctor examined.
    HostExamined,
    /// The host build the launch records observed.
    HostObserved,
    /// The backend the doctor examined and why the plan names it.
    BackendCandidate,
    /// The backend build: kind, version, artifact and hypervisor interface.
    BackendBuild,
    /// The guest image's signed manifest.
    ImageManifest,
    /// The root image the launches pinned.
    ImagePinned,
    /// The root image the host observed booted.
    ImageBooted,
    /// The accelerator the host observed the VMs running on.
    Accelerator,
    /// The controls the hypervisor process ran under, as the host observed them.
    HypervisorConfinement,
    /// The guest's inner confinement profile and its V15 verdict.
    GuestConfinement,
    /// The approved device profile the launches were built with.
    DeviceProfile,
    /// The device inventory the host measured.
    DeviceInventory,
    /// The network channels the host enforced.
    NetworkEnforcement,
    /// The independent perimeter the launches asked for and its evidence.
    Perimeter,
    /// The launch paths the records exercised: cold boot, restore from a snapshot.
    LifecyclePaths,
    /// The doctor's results for the lifecycle checks.
    LifecycleChecks,
    /// The doctor's examination of the backend.
    TestResult,
}

impl RowField {
    pub const ALL: [Self; 17] = [
        Self::HostExamined,
        Self::HostObserved,
        Self::BackendCandidate,
        Self::BackendBuild,
        Self::ImageManifest,
        Self::ImagePinned,
        Self::ImageBooted,
        Self::Accelerator,
        Self::HypervisorConfinement,
        Self::GuestConfinement,
        Self::DeviceProfile,
        Self::DeviceInventory,
        Self::NetworkEnforcement,
        Self::Perimeter,
        Self::LifecyclePaths,
        Self::LifecycleChecks,
        Self::TestResult,
    ];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::HostExamined => "host_examined",
            Self::HostObserved => "host_observed",
            Self::BackendCandidate => "backend_candidate",
            Self::BackendBuild => "backend_build",
            Self::ImageManifest => "image_manifest",
            Self::ImagePinned => "image_pinned",
            Self::ImageBooted => "image_booted",
            Self::Accelerator => "accelerator",
            Self::HypervisorConfinement => "hypervisor_confinement",
            Self::GuestConfinement => "guest_confinement",
            Self::DeviceProfile => "device_profile",
            Self::DeviceInventory => "device_inventory",
            Self::NetworkEnforcement => "network_enforcement",
            Self::Perimeter => "perimeter",
            Self::LifecyclePaths => "lifecycle_paths",
            Self::LifecycleChecks => "lifecycle_checks",
            Self::TestResult => "test_result",
        }
    }
}

impl fmt::Display for RowField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HostExamined => "examined host build",
            Self::HostObserved => "observed host build",
            Self::BackendCandidate => "examined backend",
            Self::BackendBuild => "backend build",
            Self::ImageManifest => "signed guest image manifest",
            Self::ImagePinned => "pinned root image",
            Self::ImageBooted => "booted root image",
            Self::Accelerator => "accelerator",
            Self::HypervisorConfinement => "hypervisor confinement",
            Self::GuestConfinement => "guest confinement profile",
            Self::DeviceProfile => "device profile",
            Self::DeviceInventory => "measured device inventory",
            Self::NetworkEnforcement => "network enforcement",
            Self::Perimeter => "independent perimeter",
            Self::LifecyclePaths => "launch paths",
            Self::LifecycleChecks => "lifecycle checks",
            Self::TestResult => "test result",
        })
    }
}

/// Where a field's value was read from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum Source {
    /// The doctor's examination of the backend on this host, by its boundary report's
    /// identity.
    Doctor { report: Digest },
    /// Host observations of `fact` in sealed launch records, by record identity in the
    /// order given; `how` is how the freshest of them was made (host-observed, or verified
    /// by a controlled check). A guest assertion is never read.
    HostObserved {
        fact: FactName,
        how: FactSource,
        records: Vec<Digest>,
    },
    /// What sealed launch records bind at admission, by record identity in the order
    /// given: the backend build, the pinned image, the device profile, the perimeter
    /// requirement with its CORE-01 evidence, and whether the launch was a restore.
    SealedRecords { records: Vec<Digest> },
    /// The guest image's signed manifest, by content key, and the trust-root key that
    /// vouched for it.
    SignedManifest {
        manifest: ContentKey,
        key: RootKeyId,
    },
    /// The V15 confinement verdict stamped for VM-CP-05, for the profile `profile`.
    ConfinementVerdict { profile: Digest },
}

/// How fresh a field's evidence is at the reading.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "freshness", rename_all = "snake_case")]
pub enum Freshness {
    /// Current: made `age` before the reading, within `limit`, the shorter of the
    /// reader's maximum age and the evidence's own bound.
    Current { age: Duration, limit: Duration },
    /// Current at the reading by its source's own check; the source does not expose when
    /// it was made (the doctor's boundary report and the stamped V15 verdict).
    CurrentAgeNotExposed,
    /// Not current at the reading: another configuration, another clock session, dated
    /// after the reading, or too old.
    NotCurrent { problem: ObservationProblem },
    /// A signed manifest inside its validity at the reading's calendar time.
    WithinValidity {
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
    },
    /// A signed manifest issued after the reading's calendar time.
    IssuedAfterNow { issued_at: UnixSeconds },
    /// A signed manifest whose expiry has passed at the reading's calendar time.
    Expired { expires_at: UnixSeconds },
}

impl Freshness {
    /// Whether the evidence may be presented as current at the reading.
    pub const fn is_current(&self) -> bool {
        matches!(
            self,
            Self::Current { .. } | Self::CurrentAgeNotExposed | Self::WithinValidity { .. }
        )
    }

    /// The freshness of evidence stamped at `at` on `clock` under `configuration` and
    /// fresh for `fresh_for`, for a reader at `context`: CORE-01's rules in CORE-01's order.
    pub(super) fn of_stamp(
        configuration: ConfigurationFingerprint,
        clock: ClockSession,
        at: MonotonicTime,
        fresh_for: Duration,
        context: &JudgeContext,
    ) -> Self {
        if configuration != context.configuration {
            return Self::NotCurrent {
                problem: ObservationProblem::OtherConfiguration {
                    observed_under: configuration,
                    current: context.configuration,
                },
            };
        }
        if clock != context.now.session() {
            return Self::stale(Staleness::OtherClock);
        }
        let Some(age) = context.now.at().checked_duration_since(at) else {
            return Self::stale(Staleness::ObservedAfterNow);
        };
        let limit = context.max_age.min(fresh_for);
        if age > limit {
            return Self::stale(Staleness::TooOld { age, limit });
        }
        Self::Current { age, limit }
    }

    /// The freshness a source's own currency check gives, when it does not expose the
    /// evidence's age.
    pub(super) fn of_check(check: Result<(), ObservationProblem>) -> Self {
        match check {
            Ok(()) => Self::CurrentAgeNotExposed,
            Err(problem) => Self::NotCurrent { problem },
        }
    }

    /// The freshness of a signed manifest issued at `issued_at` and expiring at
    /// `expires_at` (exclusive), at the calendar time `now`.
    pub(super) fn of_validity(
        issued_at: UnixSeconds,
        expires_at: UnixSeconds,
        now: UnixSeconds,
    ) -> Self {
        if expires_at.is_expired_at(now) {
            Self::Expired { expires_at }
        } else if issued_at > now {
            Self::IssuedAfterNow { issued_at }
        } else {
            Self::WithinValidity {
                issued_at,
                expires_at,
            }
        }
    }

    fn stale(staleness: Staleness) -> Self {
        Self::NotCurrent {
            problem: ObservationProblem::Stale { staleness },
        }
    }

    /// Whether this freshness is to be preferred over `other` for a value both support: a
    /// current one over one that is not, the younger of two current ones, and otherwise
    /// the later one given.
    pub(super) fn preferred_over(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Current { age, .. }, Self::Current { age: other, .. }) => age <= other,
            (now, before) => now.is_current() || !before.is_current(),
        }
    }

    /// Whether this freshness is to be reported over `other` when both must hold: the one
    /// that is not current, or the older of two current ones.
    pub(super) fn worse_than(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Current { age, .. }, Self::Current { age: other, .. }) => age > other,
            (now, before) => !now.is_current() && before.is_current(),
        }
    }
}

/// Why a field has no value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "because", rename_all = "snake_case")]
pub enum Unavailable {
    /// No sealed launch record of this backend on this host was given.
    NoLaunchRecord,
    /// Launch records were given, and none had a host observation of `fact`; `reason` is
    /// what the last record without one stated.
    NotObserved {
        fact: FactName,
        reason: UnknownReason,
    },
    /// No verified guest image release was given.
    NoSignedManifest,
    /// No stamped V15 confinement verdict was given.
    NoConfinementVerdict,
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLaunchRecord => {
                f.write_str("no launch record of this backend on this host was given")
            }
            Self::NotObserved { fact, reason } => {
                write!(
                    f,
                    "no launch record has a host observation of the {fact}: {reason}"
                )
            }
            Self::NoSignedManifest => f.write_str("no verified guest image release was given"),
            Self::NoConfinementVerdict => f.write_str("no confinement verdict was given"),
        }
    }
}

/// One field of an evidence row. Serialize only: a row is never hand-written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Field<T> {
    /// A value, where it was read from and how fresh that evidence is.
    Known {
        value: T,
        source: Source,
        freshness: Freshness,
    },
    /// Nobody observed it.
    Unavailable { reason: Unavailable },
}

impl<T> Field<T> {
    pub(super) const fn unavailable(reason: Unavailable) -> Self {
        Self::Unavailable { reason }
    }

    pub fn value(&self) -> Option<&T> {
        match self {
            Self::Known { value, .. } => Some(value),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn source(&self) -> Option<&Source> {
        match self {
            Self::Known { source, .. } => Some(source),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn freshness(&self) -> Option<&Freshness> {
        match self {
            Self::Known { freshness, .. } => Some(freshness),
            Self::Unavailable { .. } => None,
        }
    }

    /// Why the field has no value, when it has none.
    pub fn unavailable_because(&self) -> Option<&Unavailable> {
        match self {
            Self::Known { .. } => None,
            Self::Unavailable { reason } => Some(reason),
        }
    }

    pub fn is_known(&self) -> bool {
        matches!(self, Self::Known { .. })
    }

    /// Whether the field has a value whose evidence is current at the reading.
    pub fn is_current(&self) -> bool {
        self.freshness().is_some_and(Freshness::is_current)
    }
}
