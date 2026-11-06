//! Facts about a VM, kept apart by who observed them (§8.1 lines 2433–2437; VM-W04 row,
//! line 2589: observed, asserted, verified and unavailable facts).
//!
//! A [`HostObserved`] fact was observed by the host itself, on the evidence clock, under
//! a configuration fingerprint and with a freshness bound, as CORE-01 envelopes are. A
//! [`GuestAsserted`] fact is what the guest said; it is a different type, so no reader
//! can take it for a host observation by ignoring a flag, and nothing in this module
//! satisfies a requirement with one (VM-W09, line 2594; VM-P29, line 2799). A
//! [`HostFact`] is a host observation or an explicit statement that none is available.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::facets::{
    ConfinementControl, CredentialExposure, DeviceInventory, IsolationObservation,
    NetworkAuthority, OperatorConfidentiality, Persistence,
};
use super::Accelerator;
use crate::foundation::evidence::{
    ClockReading, ClockSession, ConfigurationFingerprint, OsKind, Staleness, UnknownReason,
};
use crate::foundation::ids::{validate_identifier, Digest, IdError, MonotonicTime};

/// Who stands behind a fact (VM-W04 row, line 2589).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactSource {
    /// The host observed it: host configuration, process state or a controlled external
    /// observation (§8.1 line 2435).
    HostObserved,
    /// The host observed it and a controlled check corroborated it, such as a positive
    /// control against a reachable endpoint (§0.2 line 1842).
    Verified,
    /// The guest said so. A hostile guest can report a plausible result, hide files or lie
    /// about interfaces (§8.1 line 2435).
    GuestAsserted,
    /// No observation exists.
    Unavailable,
}

impl FactSource {
    /// Whether facts from this source may satisfy a requirement: only the host's own.
    pub const fn is_host(self) -> bool {
        matches!(self, Self::HostObserved | Self::Verified)
    }
}

impl fmt::Display for FactSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HostObserved => "host-observed",
            Self::Verified => "verified",
            Self::GuestAsserted => "guest-asserted",
            Self::Unavailable => "unavailable",
        })
    }
}

/// How the host came by an observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "how", rename_all = "snake_case")]
pub enum HostSource {
    Observed,
    /// Corroborated by the controlled check `control` names.
    Verified {
        control: Digest,
    },
}

/// A fact the host observed itself, stamped on the evidence clock with the configuration
/// it depends on and how long it stays fresh (CORE-01 vocabulary). Only a backend makes
/// one, from a [`ClockReading`] that only the evidence registry issues, so an observation
/// is always dated on the clock that judges its freshness. Serialize only: a record of an
/// observation is never hand-written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HostObserved<T> {
    value: T,
    source: HostSource,
    clock: ClockSession,
    observed_at: MonotonicTime,
    fresh_for: Duration,
    configuration: ConfigurationFingerprint,
}

impl<T> HostObserved<T> {
    /// Stamps a host observation made now.
    pub fn stamp(
        value: T,
        now: ClockReading,
        fresh_for: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Self {
        Self {
            value,
            source: HostSource::Observed,
            clock: now.session(),
            observed_at: now.at(),
            fresh_for,
            configuration,
        }
    }

    /// Stamps a host observation that a controlled check corroborated.
    pub fn verified(
        value: T,
        now: ClockReading,
        fresh_for: Duration,
        configuration: ConfigurationFingerprint,
        control: Digest,
    ) -> Self {
        Self {
            source: HostSource::Verified { control },
            ..Self::stamp(value, now, fresh_for, configuration)
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn source(&self) -> FactSource {
        match self.source {
            HostSource::Observed => FactSource::HostObserved,
            HostSource::Verified { .. } => FactSource::Verified,
        }
    }

    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    pub fn observed_at(&self) -> MonotonicTime {
        self.observed_at
    }

    pub fn fresh_for(&self) -> Duration {
        self.fresh_for
    }

    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    /// Whether the observation is current at `now` for a reader that accepts nothing
    /// older than `max_age` under `configuration`: the same rules as CORE-01, in the same
    /// order (configuration, then clock session, then age against the shorter of
    /// `max_age` and the observation's own bound).
    pub fn current_at(
        &self,
        now: ClockReading,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Result<(), ObservationProblem> {
        if self.configuration != configuration {
            return Err(ObservationProblem::OtherConfiguration {
                observed_under: self.configuration,
                current: configuration,
            });
        }
        if self.clock != now.session() {
            return Err(ObservationProblem::Stale {
                staleness: Staleness::OtherClock,
            });
        }
        let Some(age) = now.at().checked_duration_since(self.observed_at) else {
            return Err(ObservationProblem::Stale {
                staleness: Staleness::ObservedAfterNow,
            });
        };
        let limit = max_age.min(self.fresh_for);
        if age > limit {
            return Err(ObservationProblem::Stale {
                staleness: Staleness::TooOld { age, limit },
            });
        }
        Ok(())
    }
}

/// Why a host observation may not be presented as current (VM-W04 row, line 2589: stale
/// evidence is not presented as current; CORE-01: a changed configuration invalidates
/// evidence).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ObservationProblem {
    OtherConfiguration {
        observed_under: ConfigurationFingerprint,
        current: ConfigurationFingerprint,
    },
    Stale {
        staleness: Staleness,
    },
}

impl fmt::Display for ObservationProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherConfiguration { .. } => f.write_str(
                "the observation was made under another host configuration and no longer applies",
            ),
            Self::Stale {
                staleness: Staleness::TooOld { age, limit },
            } => write!(
                f,
                "the observation is {age:?} old, beyond its {limit:?} limit"
            ),
            Self::Stale {
                staleness: Staleness::OtherClock,
            } => f.write_str(
                "the observation was recorded on another clock, such as before a restart",
            ),
            Self::Stale {
                staleness: Staleness::ObservedAfterNow,
            } => f.write_str("the observation is dated after the current time"),
        }
    }
}

/// A fact the guest asserted. It is recorded and shown, never used to satisfy a
/// requirement (§8.1 line 2435; VM-P29).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuestAsserted<T> {
    value: T,
    clock: ClockSession,
    received_at: MonotonicTime,
}

impl<T> GuestAsserted<T> {
    /// Records what the guest asserted, received now.
    pub fn received(value: T, now: ClockReading) -> Self {
        Self {
            value,
            clock: now.session(),
            received_at: now.at(),
        }
    }

    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn received_at(&self) -> MonotonicTime {
        self.received_at
    }

    pub const fn source(&self) -> FactSource {
        FactSource::GuestAsserted
    }
}

/// A host fact: an observation, or an explicit statement that the host has none.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "fact", rename_all = "snake_case")]
pub enum HostFact<T> {
    Observed { observation: HostObserved<T> },
    Unavailable { reason: UnknownReason },
}

impl<T> HostFact<T> {
    pub fn observed(observation: HostObserved<T>) -> Self {
        Self::Observed { observation }
    }

    pub fn unavailable(reason: UnknownReason) -> Self {
        Self::Unavailable { reason }
    }

    pub fn source(&self) -> FactSource {
        match self {
            Self::Observed { observation } => observation.source(),
            Self::Unavailable { .. } => FactSource::Unavailable,
        }
    }

    /// The observation, if the host made one.
    pub fn observation(&self) -> Option<&HostObserved<T>> {
        match self {
            Self::Observed { observation } => Some(observation),
            Self::Unavailable { .. } => None,
        }
    }

    pub fn value(&self) -> Option<&T> {
        self.observation().map(HostObserved::value)
    }
}

/// The host operating system, build and architecture, as the host observed them (§7.1
/// line 2360; VM-W23 row, line 2622: the actual OS/build matrix).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostBuild {
    pub os: OsKind,
    pub build: BuildId,
    pub architecture: Architecture,
}

/// The host CPU architecture.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    X86_64,
    Aarch64,
}

impl Architecture {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::X86_64 => "x86_64",
            Self::Aarch64 => "aarch64",
        }
    }
}

/// An OS build identifier such as `26100.1234`, in the shared identifier grammar.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct BuildId(String);

impl BuildId {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for BuildId {
    type Error = IdError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<BuildId> for String {
    fn from(build: BuildId) -> Self {
        build.0
    }
}

impl fmt::Display for BuildId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Everything the host observed about one VM's boundary, one fact per §1.3 facet plus
/// the host build and the booted guest image (§8.1 "observed confinement"). The actual
/// accelerator is a separate fact of the launch record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ObservedProperties {
    pub host: HostFact<HostBuild>,
    pub guest_image: HostFact<Digest>,
    pub isolation: HostFact<IsolationObservation>,
    pub confinement: HostFact<BTreeSet<ConfinementControl>>,
    pub network: HostFact<NetworkAuthority>,
    pub credentials: HostFact<CredentialExposure>,
    pub persistence: HostFact<Persistence>,
    pub devices: HostFact<DeviceInventory>,
    pub confidentiality: HostFact<OperatorConfidentiality>,
}

/// What the guest asserted about itself, by facet. Every field is optional because a
/// guest may say nothing; none of them is ever used to satisfy a requirement.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct GuestAssertions {
    pub accelerator: Option<GuestAsserted<Accelerator>>,
    pub isolation: Option<GuestAsserted<IsolationObservation>>,
    pub confinement: Option<GuestAsserted<BTreeSet<ConfinementControl>>>,
    pub network: Option<GuestAsserted<NetworkAuthority>>,
    pub credentials: Option<GuestAsserted<CredentialExposure>>,
    pub persistence: Option<GuestAsserted<Persistence>>,
    pub devices: Option<GuestAsserted<DeviceInventory>>,
    pub confidentiality: Option<GuestAsserted<OperatorConfidentiality>>,
}

impl GuestAssertions {
    /// The guest asserted nothing.
    pub fn none() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::ProbeRegistry;
    use crate::foundation::ids::{digest, ManualClock};
    use std::sync::Arc;

    fn config(name: &str) -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("host", name)]).unwrap()
    }

    #[test]
    fn a_host_observation_is_current_within_its_bounds_and_configuration() {
        let clock = Arc::new(ManualClock::default());
        let registry = ProbeRegistry::new(Arc::clone(&clock));
        let observed =
            HostObserved::stamp(7u8, registry.now(), Duration::from_secs(60), config("a"));
        assert_eq!(observed.source(), FactSource::HostObserved);
        assert_eq!(*observed.value(), 7);
        assert_eq!(observed.clock(), registry.session());
        assert_eq!(observed.fresh_for(), Duration::from_secs(60));

        let minute = Duration::from_secs(60);
        assert_eq!(
            observed.current_at(registry.now(), minute, config("a")),
            Ok(())
        );
        clock.advance(Duration::from_secs(60));
        assert_eq!(
            observed.current_at(registry.now(), minute, config("a")),
            Ok(())
        );
        clock.advance(Duration::from_secs(1));
        assert_eq!(
            observed.current_at(registry.now(), minute, config("a")),
            Err(ObservationProblem::Stale {
                staleness: Staleness::TooOld {
                    age: Duration::from_secs(61),
                    limit: minute,
                }
            })
        );
        // A reader's tighter bound applies, and the observation's own bound caps a looser one.
        assert!(matches!(
            observed.current_at(registry.now(), Duration::from_secs(10), config("a")),
            Err(ObservationProblem::Stale {
                staleness: Staleness::TooOld { limit, .. }
            }) if limit == Duration::from_secs(10)
        ));
        assert!(matches!(
            observed.current_at(registry.now(), Duration::from_secs(3_600), config("a")),
            Err(ObservationProblem::Stale {
                staleness: Staleness::TooOld { limit, .. }
            }) if limit == minute
        ));
        // Configuration is judged first.
        assert_eq!(
            observed.current_at(registry.now(), minute, config("b")),
            Err(ObservationProblem::OtherConfiguration {
                observed_under: config("a"),
                current: config("b"),
            })
        );
    }

    #[test]
    fn another_clock_or_the_future_is_never_current() {
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(10)));
        let registry = ProbeRegistry::new(Arc::clone(&clock));
        let observed = HostObserved::stamp((), registry.now(), Duration::MAX, config("a"));
        let restarted = ProbeRegistry::new(Arc::clone(&clock));
        assert_eq!(
            observed.current_at(restarted.now(), Duration::MAX, config("a")),
            Err(ObservationProblem::Stale {
                staleness: Staleness::OtherClock
            })
        );
        // A manual clock never goes back, so a future-dated observation on the same
        // session is built directly.
        let future = HostObserved {
            value: (),
            source: HostSource::Observed,
            clock: registry.session(),
            observed_at: MonotonicTime::from_nanos(50),
            fresh_for: Duration::MAX,
            configuration: config("a"),
        };
        assert_eq!(
            future.current_at(registry.now(), Duration::MAX, config("a")),
            Err(ObservationProblem::Stale {
                staleness: Staleness::ObservedAfterNow
            })
        );
        assert!(ObservationProblem::Stale {
            staleness: Staleness::ObservedAfterNow
        }
        .to_string()
        .contains("after the current time"));
    }

    #[test]
    fn verified_and_guest_asserted_facts_name_their_source() {
        let registry = ProbeRegistry::new(ManualClock::default());
        let control = digest("yougori/test/control/v1", &[b"positive"]);
        let verified = HostObserved::verified(
            1u8,
            registry.now(),
            Duration::from_secs(1),
            config("a"),
            control,
        );
        assert_eq!(verified.source(), FactSource::Verified);
        assert!(FactSource::Verified.is_host());
        assert!(FactSource::HostObserved.is_host());
        assert!(!FactSource::GuestAsserted.is_host());
        assert!(!FactSource::Unavailable.is_host());

        let asserted = GuestAsserted::received(2u8, registry.now());
        assert_eq!(asserted.source(), FactSource::GuestAsserted);
        assert_eq!(*asserted.value(), 2);
        assert_eq!(asserted.received_at(), MonotonicTime::ZERO);

        let fact = HostFact::observed(verified.clone());
        assert_eq!(fact.source(), FactSource::Verified);
        assert_eq!(fact.value(), Some(&1));
        let missing: HostFact<u8> = HostFact::unavailable(UnknownReason::NotTested);
        assert_eq!(missing.source(), FactSource::Unavailable);
        assert_eq!(missing.value(), None);
        let json = serde_json::to_value(&missing).unwrap();
        assert_eq!(json["fact"], "unavailable");
        assert_eq!(json["reason"], "not_tested");
        let json = serde_json::to_value(&fact).unwrap();
        assert_eq!(json["fact"], "observed");
        assert_eq!(json["observation"]["source"]["how"], "verified");
        assert_eq!(json["observation"]["source"]["control"], control.to_hex());
    }

    #[test]
    fn build_ids_use_the_shared_identifier_grammar() {
        assert_eq!(BuildId::new("26100.1234").unwrap().as_str(), "26100.1234");
        assert_eq!(BuildId::new(""), Err(IdError::Empty));
        assert!(BuildId::new("build 1").is_err());
        assert!(serde_json::from_str::<BuildId>("\"6.6/1\"").is_err());
        let host = HostBuild {
            os: OsKind::Linux,
            build: BuildId::new("6.6.0-1").unwrap(),
            architecture: Architecture::X86_64,
        };
        let json = serde_json::to_value(&host).unwrap();
        assert_eq!(json["architecture"], "x86_64");
        assert_eq!(
            serde_json::from_value::<HostBuild>(json.clone()).unwrap(),
            host
        );
        let mut extra = json;
        extra["hostname"] = "pc".into();
        assert!(serde_json::from_value::<HostBuild>(extra).is_err());
    }
}
