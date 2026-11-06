//! Requirements and their evaluation against stored evidence (CORE-01).

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use super::envelope::{
    Capability, ClockReading, ConfigurationFingerprint, EvidenceEnvelope, ObservationResult,
    SourceClass, SupportDetail, UnknownReason, UnsupportedReason,
};
use super::remedy::Remedy;
use super::subject::Subject;
use crate::foundation::ids::{Digest, MonotonicTime};

/// What a decision needs to know (CORE-01): a capability of one subject, observed by at
/// least `minimum_source`, no older than `max_age`, under the configuration in force now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub capability: Capability,
    pub subject: Subject,
    pub minimum_source: SourceClass,
    pub max_age: Duration,
    /// The configuration fingerprint in force now; evidence observed under any other
    /// fingerprint no longer applies.
    pub configuration: ConfigurationFingerprint,
}

impl Requirement {
    /// A requirement; a `minimum_source` weaker than the capability's floor is raised to
    /// it when evaluated.
    pub fn new(
        capability: Capability,
        subject: Subject,
        minimum_source: SourceClass,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Self {
        Self {
            capability,
            subject,
            minimum_source,
            max_age,
            configuration,
        }
    }

    /// A host-only requirement: only a host probe satisfies it, and a guest report never
    /// does (CORE-01; VM-W09).
    pub fn host_only(
        capability: Capability,
        subject: Subject,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Self {
        Self::new(
            capability,
            subject,
            SourceClass::HostProbe,
            max_age,
            configuration,
        )
    }

    /// The minimum source after raising it to the capability's floor
    /// ([`Capability::weakest_source`]).
    pub fn effective_minimum(&self) -> SourceClass {
        self.minimum_source.max(self.capability.weakest_source())
    }

    /// Whether only a host probe can satisfy this requirement.
    pub fn is_host_only(&self) -> bool {
        self.effective_minimum() == SourceClass::HostProbe
    }
}

/// Evidence that met a requirement. Only evaluation in a
/// [`ProbeRegistry`](super::ProbeRegistry) makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Satisfied {
    capability: Capability,
    subject: Digest,
    source: SourceClass,
    configuration: ConfigurationFingerprint,
    observed_at: MonotonicTime,
    fresh_until: MonotonicTime,
    detail: SupportDetail,
}

impl Satisfied {
    /// The last moment, on the evaluating registry's clock, at which this evidence still
    /// met the requirement's maximum age and its own freshness bound.
    pub fn fresh_until(&self) -> MonotonicTime {
        self.fresh_until
    }

    pub fn capability(&self) -> Capability {
        self.capability
    }

    /// The identity of the subject the evidence is about.
    pub fn subject(&self) -> Digest {
        self.subject
    }

    pub fn source(&self) -> SourceClass {
        self.source
    }

    pub fn configuration(&self) -> ConfigurationFingerprint {
        self.configuration
    }

    pub fn observed_at(&self) -> MonotonicTime {
        self.observed_at
    }

    pub fn detail(&self) -> &SupportDetail {
        &self.detail
    }
}

strict_evidence_enum! {
    /// Why evidence is not fresh enough to use.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Staleness tag "kind" {
        /// Older than the requirement's maximum age or the observation's own freshness
        /// bound, whichever is shorter.
        TooOld { age: Duration, limit: Duration },
        /// Recorded on another clock session, such as before a restart; its age cannot be
        /// known.
        OtherClock,
        /// Dated after the current time on the same clock, which a monotonic clock never
        /// produces.
        ObservedAfterNow,
    }
}

strict_evidence_enum! {
    /// Why a requirement is not satisfied (CORE-01). Each refusal names a [`Remedy`].
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EvidenceRefusal tag "refusal" {
        /// No evidence about this capability of this subject.
        Missing { capability: Capability },
        /// The evidence comes from a weaker source than the requirement needs; a guest
        /// report never satisfies a host-only requirement.
        SourceTooWeak {
            capability: Capability,
            observed: SourceClass,
            required: SourceClass,
        },
        /// The configuration changed after the observation, which invalidates it.
        FingerprintChanged {
            capability: Capability,
            observed_under: ConfigurationFingerprint,
            current: ConfigurationFingerprint,
        },
        /// The evidence is not fresh on this clock.
        Stale {
            capability: Capability,
            staleness: Staleness,
        },
        /// The latest conclusive observation says the capability is unsupported.
        Unsupported {
            capability: Capability,
            reason: UnsupportedReason,
        },
        /// The check could not decide; inconclusive results fail required checks
        /// (VM-W09).
        Unknown {
            capability: Capability,
            reason: UnknownReason,
        },
    }
}

impl EvidenceRefusal {
    pub fn capability(&self) -> Capability {
        match self {
            Self::Missing { capability }
            | Self::SourceTooWeak { capability, .. }
            | Self::FingerprintChanged { capability, .. }
            | Self::Stale { capability, .. }
            | Self::Unsupported { capability, .. }
            | Self::Unknown { capability, .. } => *capability,
        }
    }

    /// What the user can do about this refusal.
    pub fn remedy(&self) -> Remedy {
        match self {
            Self::Missing { .. } => Remedy::RunCheck,
            Self::SourceTooWeak { required, .. } => Remedy::ObtainStrongerEvidence {
                required: *required,
            },
            Self::FingerprintChanged { .. } => Remedy::RecheckCurrentConfiguration,
            Self::Stale { .. } => Remedy::RunCheckAgain,
            Self::Unsupported { reason, .. } => reason.remedy(),
            Self::Unknown { reason, .. } => reason.remedy(),
        }
    }
}

impl fmt::Display for EvidenceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let remedy = self.remedy();
        match self {
            Self::Missing { capability } => {
                write!(
                    f,
                    "there is no {capability} evidence for this subject; {remedy}"
                )
            }
            Self::SourceTooWeak {
                capability,
                observed,
                required: SourceClass::HostProbe,
            } => write!(
                f,
                "{capability} needs a host probe, and a {observed} never satisfies a host-only \
                 requirement; {remedy}"
            ),
            Self::SourceTooWeak {
                capability,
                observed,
                required,
            } => write!(
                f,
                "{capability} needs evidence from a {required} or a stronger source, but this \
                 evidence is a {observed}; {remedy}"
            ),
            Self::FingerprintChanged { capability, .. } => write!(
                f,
                "the configuration changed after {capability} was checked, so that evidence no \
                 longer applies; {remedy}"
            ),
            Self::Stale {
                capability,
                staleness: Staleness::TooOld { age, limit },
            } => write!(
                f,
                "the {capability} evidence is {age:?} old, beyond its {limit:?} limit; {remedy}"
            ),
            Self::Stale {
                capability,
                staleness: Staleness::OtherClock,
            } => write!(
                f,
                "the {capability} evidence was recorded on another clock, such as before a \
                 restart; {remedy}"
            ),
            Self::Stale {
                capability,
                staleness: Staleness::ObservedAfterNow,
            } => write!(
                f,
                "the {capability} evidence is dated after the current time; {remedy}"
            ),
            Self::Unsupported { capability, reason } => {
                write!(f, "{capability} is not supported: {reason}; {remedy}")
            }
            Self::Unknown { capability, reason } => write!(
                f,
                "{capability} is unknown because {reason}, and an inconclusive check never \
                 passes; {remedy}"
            ),
        }
    }
}

impl std::error::Error for EvidenceRefusal {}

/// The latest envelope per capability and subject (CORE-01).
///
/// Only the [`ProbeRegistry`](super::ProbeRegistry) adds envelopes, from registered
/// adapters whose source class is fixed at registration. There is no way to insert an
/// envelope read from elsewhere.
#[derive(Clone, Debug, Default)]
pub struct EvidenceStore {
    latest: BTreeMap<(Capability, Digest), EvidenceEnvelope>,
}

impl EvidenceStore {
    /// The latest envelope for `capability` on `subject`, whatever its freshness.
    pub fn latest(&self, capability: Capability, subject: &Subject) -> Option<&EvidenceEnvelope> {
        self.latest.get(&(capability, subject.identity()))
    }

    /// Checks, in order: evidence exists, its source is strong enough, the check was
    /// conclusive, it was observed under the current configuration, it is fresh on this
    /// clock, and its result is supported. The first failure is the refusal. Callers go
    /// through [`ProbeRegistry::evaluate`](super::ProbeRegistry::evaluate), which supplies
    /// its own clock reading.
    pub(super) fn evaluate(
        &self,
        requirement: &Requirement,
        now: ClockReading,
    ) -> Result<Satisfied, EvidenceRefusal> {
        let envelope = self
            .latest(requirement.capability, &requirement.subject)
            .ok_or(EvidenceRefusal::Missing {
                capability: requirement.capability,
            })?;
        assess(requirement, envelope, now)
    }

    pub fn len(&self) -> usize {
        self.latest.len()
    }

    pub fn is_empty(&self) -> bool {
        self.latest.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &EvidenceEnvelope> {
        self.latest.values()
    }

    /// Keeps `envelope` as the latest for its capability and subject.
    pub(super) fn put(&mut self, envelope: EvidenceEnvelope) -> &EvidenceEnvelope {
        match self
            .latest
            .entry((envelope.capability(), envelope.subject_identity()))
        {
            Entry::Occupied(mut slot) => {
                slot.insert(envelope);
                slot.into_mut()
            }
            Entry::Vacant(slot) => slot.insert(envelope),
        }
    }

    pub(super) fn remove(
        &mut self,
        capability: Capability,
        subject: Digest,
    ) -> Option<EvidenceEnvelope> {
        self.latest.remove(&(capability, subject))
    }

    /// Removes every envelope `remove` selects and returns how many were removed.
    pub(super) fn remove_where(
        &mut self,
        mut remove: impl FnMut(&EvidenceEnvelope) -> bool,
    ) -> usize {
        let before = self.latest.len();
        self.latest.retain(|_, envelope| !remove(envelope));
        before - self.latest.len()
    }
}

fn assess(
    requirement: &Requirement,
    envelope: &EvidenceEnvelope,
    now: ClockReading,
) -> Result<Satisfied, EvidenceRefusal> {
    let capability = requirement.capability;
    if envelope.capability() != capability
        || envelope.subject_identity() != requirement.subject.identity()
    {
        return Err(EvidenceRefusal::Missing { capability });
    }
    let required = requirement.effective_minimum();
    if !envelope.source().satisfies(required) {
        return Err(EvidenceRefusal::SourceTooWeak {
            capability,
            observed: envelope.source(),
            required,
        });
    }
    if let ObservationResult::Unknown { reason } = envelope.result() {
        return Err(EvidenceRefusal::Unknown {
            capability,
            reason: *reason,
        });
    }
    if envelope.configuration() != requirement.configuration {
        return Err(EvidenceRefusal::FingerprintChanged {
            capability,
            observed_under: envelope.configuration(),
            current: requirement.configuration,
        });
    }
    let limit = requirement.max_age.min(envelope.fresh_for());
    if let Some(staleness) = staleness(envelope, limit, now) {
        return Err(EvidenceRefusal::Stale {
            capability,
            staleness,
        });
    }
    match envelope.result() {
        ObservationResult::Supported { detail } => Ok(Satisfied {
            capability,
            subject: envelope.subject_identity(),
            source: envelope.source(),
            configuration: envelope.configuration(),
            observed_at: envelope.observed_at(),
            fresh_until: envelope.observed_at().saturating_add(limit),
            detail: detail.clone(),
        }),
        ObservationResult::Unsupported { reason } => Err(EvidenceRefusal::Unsupported {
            capability,
            reason: *reason,
        }),
        ObservationResult::Unknown { reason } => Err(EvidenceRefusal::Unknown {
            capability,
            reason: *reason,
        }),
    }
}

/// Staleness against `limit`, the shorter of the requirement's maximum age and the
/// observation's own freshness bound.
fn staleness(envelope: &EvidenceEnvelope, limit: Duration, now: ClockReading) -> Option<Staleness> {
    if envelope.clock() != now.session() {
        return Some(Staleness::OtherClock);
    }
    let Some(age) = now.at().checked_duration_since(envelope.observed_at()) else {
        return Some(Staleness::ObservedAfterNow);
    };
    (age > limit).then_some(Staleness::TooOld { age, limit })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::envelope::{ClockSession, Observation};
    use crate::foundation::evidence::subject::{
        Backend, BackendRelease, HypervisorKind, HypervisorSubject, RuntimeSubject,
    };
    use crate::foundation::ids::{digest, ExecutionCategory};

    const MINUTE: Duration = Duration::from_secs(60);

    fn session() -> ClockSession {
        ClockSession::from_uuid(uuid::Uuid::from_u128(1))
    }

    fn at(seconds: u64) -> ClockReading {
        ClockReading::new(
            session(),
            MonotonicTime::from_nanos(seconds * 1_000_000_000),
        )
    }

    fn config(driver: &str) -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("driver", driver)]).unwrap()
    }

    fn hypervisor() -> Subject {
        Subject::Hypervisor(HypervisorSubject {
            machine: digest("yougori/test/machine/v1", &[b"m"]),
            hypervisor: HypervisorKind::Whpx,
        })
    }

    fn runtime() -> Subject {
        Subject::Runtime(RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            instance: digest("yougori/test/instance/v1", &[b"vm"]),
        })
    }

    fn hypervisor_available() -> Observation {
        Observation::supported(
            config("1"),
            MINUTE,
            SupportDetail::Hypervisor {
                hypervisor: HypervisorKind::Whpx,
            },
        )
    }

    fn store(
        capability: Capability,
        subject: Subject,
        source: SourceClass,
        observation: Observation,
        observed: ClockReading,
    ) -> EvidenceStore {
        let mut store = EvidenceStore::default();
        store.put(EvidenceEnvelope::stamp(
            capability,
            subject,
            source,
            observation,
            observed,
        ));
        store
    }

    fn host_only_hypervisor() -> Requirement {
        Requirement::host_only(
            Capability::HypervisorAvailable,
            hypervisor(),
            MINUTE,
            config("1"),
        )
    }

    #[test]
    fn a_guest_report_never_satisfies_a_host_only_requirement() {
        let requirement = host_only_hypervisor();
        assert!(requirement.is_host_only());
        let guest = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::GuestReport,
            hypervisor_available(),
            at(0),
        );
        let refusal = guest.evaluate(&requirement, at(1)).unwrap_err();
        assert_eq!(
            refusal,
            EvidenceRefusal::SourceTooWeak {
                capability: Capability::HypervisorAvailable,
                observed: SourceClass::GuestReport,
                required: SourceClass::HostProbe,
            }
        );
        assert_eq!(
            refusal.remedy(),
            Remedy::ObtainStrongerEvidence {
                required: SourceClass::HostProbe
            }
        );
        assert!(refusal.to_string().contains("never satisfies a host-only"));

        let host = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::HostProbe,
            hypervisor_available(),
            at(0),
        );
        let satisfied = host.evaluate(&requirement, at(1)).unwrap();
        assert_eq!(satisfied.source(), SourceClass::HostProbe);
        assert_eq!(satisfied.subject(), hypervisor().identity());
    }

    #[test]
    fn a_weaker_minimum_is_raised_to_the_capability_floor() {
        let requirement = Requirement::new(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::GuestReport,
            MINUTE,
            config("1"),
        );
        assert!(requirement.is_host_only());
        for source in [
            SourceClass::Fixture,
            SourceClass::RecordedDeclaration,
            SourceClass::GuestReport,
            SourceClass::ProviderApi,
        ] {
            let weak = store(
                Capability::HypervisorAvailable,
                hypervisor(),
                source,
                hypervisor_available(),
                at(0),
            );
            assert!(matches!(
                weak.evaluate(&requirement, at(0)),
                Err(EvidenceRefusal::SourceTooWeak {
                    required: SourceClass::HostProbe,
                    ..
                })
            ));
        }
    }

    #[test]
    fn fixtures_and_declarations_never_show_support() {
        let requirement = Requirement::new(
            Capability::IoUring,
            runtime(),
            SourceClass::Fixture,
            MINUTE,
            config("1"),
        );
        assert_eq!(requirement.effective_minimum(), SourceClass::GuestReport);
        for source in [SourceClass::Fixture, SourceClass::RecordedDeclaration] {
            let evidence = store(
                Capability::IoUring,
                runtime(),
                source,
                Observation::supported(config("1"), MINUTE, SupportDetail::Plain),
                at(0),
            );
            assert!(matches!(
                evidence.evaluate(&requirement, at(0)),
                Err(EvidenceRefusal::SourceTooWeak { .. })
            ));
        }
        let guest = store(
            Capability::IoUring,
            runtime(),
            SourceClass::GuestReport,
            Observation::supported(config("1"), MINUTE, SupportDetail::Plain),
            at(0),
        );
        assert!(guest.evaluate(&requirement, at(0)).is_ok());
    }

    #[test]
    fn a_changed_configuration_invalidates_evidence() {
        let evidence = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::HostProbe,
            hypervisor_available(),
            at(0),
        );
        let mut requirement = host_only_hypervisor();
        requirement.configuration = config("2");
        let refusal = evidence.evaluate(&requirement, at(1)).unwrap_err();
        assert_eq!(
            refusal,
            EvidenceRefusal::FingerprintChanged {
                capability: Capability::HypervisorAvailable,
                observed_under: config("1"),
                current: config("2"),
            }
        );
        assert_eq!(refusal.remedy(), Remedy::RecheckCurrentConfiguration);
    }

    #[test]
    fn stale_evidence_is_refused_at_the_shorter_bound() {
        let evidence = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::HostProbe,
            hypervisor_available(),
            at(10),
        );
        let requirement = host_only_hypervisor();
        assert!(evidence.evaluate(&requirement, at(70)).is_ok());
        let refusal = evidence.evaluate(&requirement, at(71)).unwrap_err();
        assert_eq!(
            refusal,
            EvidenceRefusal::Stale {
                capability: Capability::HypervisorAvailable,
                staleness: Staleness::TooOld {
                    age: Duration::from_secs(61),
                    limit: MINUTE,
                },
            }
        );
        assert_eq!(refusal.remedy(), Remedy::RunCheckAgain);

        let mut strict = host_only_hypervisor();
        strict.max_age = Duration::from_secs(5);
        assert!(evidence.evaluate(&strict, at(15)).is_ok());
        assert!(matches!(
            evidence.evaluate(&strict, at(16)),
            Err(EvidenceRefusal::Stale {
                staleness: Staleness::TooOld { limit, .. },
                ..
            }) if limit == Duration::from_secs(5)
        ));

        let mut lenient = host_only_hypervisor();
        lenient.max_age = Duration::from_secs(3_600);
        assert!(matches!(
            evidence.evaluate(&lenient, at(71)),
            Err(EvidenceRefusal::Stale {
                staleness: Staleness::TooOld { limit, .. },
                ..
            }) if limit == MINUTE
        ));
    }

    #[test]
    fn evidence_from_another_clock_or_the_future_is_not_fresh() {
        let evidence = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::HostProbe,
            hypervisor_available(),
            at(10),
        );
        let requirement = host_only_hypervisor();
        let restarted = ClockReading::new(
            ClockSession::from_uuid(uuid::Uuid::from_u128(2)),
            MonotonicTime::from_nanos(10_000_000_000),
        );
        assert!(matches!(
            evidence.evaluate(&requirement, restarted),
            Err(EvidenceRefusal::Stale {
                staleness: Staleness::OtherClock,
                ..
            })
        ));
        assert!(matches!(
            evidence.evaluate(&requirement, at(9)),
            Err(EvidenceRefusal::Stale {
                staleness: Staleness::ObservedAfterNow,
                ..
            })
        ));
    }

    #[test]
    fn missing_or_other_subject_evidence_is_refused() {
        let requirement = host_only_hypervisor();
        let empty = EvidenceStore::default();
        assert!(empty.is_empty());
        let refusal = empty.evaluate(&requirement, at(0)).unwrap_err();
        assert_eq!(
            refusal,
            EvidenceRefusal::Missing {
                capability: Capability::HypervisorAvailable
            }
        );
        assert_eq!(refusal.remedy(), Remedy::RunCheck);

        let other = Subject::Hypervisor(HypervisorSubject {
            machine: digest("yougori/test/machine/v1", &[b"m"]),
            hypervisor: HypervisorKind::Hcs,
        });
        let evidence = store(
            Capability::HypervisorAvailable,
            other,
            SourceClass::HostProbe,
            Observation::supported(
                config("1"),
                MINUTE,
                SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Hcs,
                },
            ),
            at(0),
        );
        assert_eq!(evidence.len(), 1);
        assert!(matches!(
            evidence.evaluate(&requirement, at(0)),
            Err(EvidenceRefusal::Missing { .. })
        ));
    }

    #[test]
    fn unsupported_and_unknown_results_are_refused_with_their_remedy() {
        let requirement = host_only_hypervisor();
        let unsupported = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::HostProbe,
            Observation::unsupported(
                config("1"),
                MINUTE,
                UnsupportedReason::HypervisorUnavailable,
            ),
            at(0),
        );
        let refusal = unsupported.evaluate(&requirement, at(0)).unwrap_err();
        assert_eq!(refusal.remedy(), Remedy::EnableHypervisorYourself);
        assert!(refusal.to_string().contains("no usable hypervisor"));

        let untested = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::HostProbe,
            Observation::unknown(config("1"), MINUTE, UnknownReason::NotTested),
            at(0),
        );
        let refusal = untested.evaluate(&requirement, at(0)).unwrap_err();
        assert_eq!(
            refusal,
            EvidenceRefusal::Unknown {
                capability: Capability::HypervisorAvailable,
                reason: UnknownReason::NotTested,
            }
        );
        assert!(refusal.to_string().contains("never passes"));
    }

    #[test]
    fn checks_run_in_a_fixed_order() {
        let evidence = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::GuestReport,
            Observation::unsupported(
                config("1"),
                MINUTE,
                UnsupportedReason::HypervisorUnavailable,
            ),
            at(0),
        );
        let mut requirement = host_only_hypervisor();
        requirement.configuration = config("2");
        assert!(matches!(
            evidence.evaluate(&requirement, at(1_000)),
            Err(EvidenceRefusal::SourceTooWeak { .. })
        ));
        let host = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::HostProbe,
            Observation::unsupported(
                config("1"),
                MINUTE,
                UnsupportedReason::HypervisorUnavailable,
            ),
            at(0),
        );
        assert!(matches!(
            host.evaluate(&requirement, at(1_000)),
            Err(EvidenceRefusal::FingerprintChanged { .. })
        ));
        requirement.configuration = config("1");
        assert!(matches!(
            host.evaluate(&requirement, at(1_000)),
            Err(EvidenceRefusal::Stale { .. })
        ));
        assert!(matches!(
            host.evaluate(&requirement, at(1)),
            Err(EvidenceRefusal::Unsupported { .. })
        ));

        let untested = store(
            Capability::HypervisorAvailable,
            hypervisor(),
            SourceClass::HostProbe,
            Observation::unknown(config("old"), Duration::ZERO, UnknownReason::NotTested),
            at(0),
        );
        assert_eq!(
            untested.evaluate(&requirement, at(1_000)),
            Err(EvidenceRefusal::Unknown {
                capability: Capability::HypervisorAvailable,
                reason: UnknownReason::NotTested,
            })
        );
    }

    #[test]
    fn refusals_round_trip_through_serde() {
        let refusal = EvidenceRefusal::Stale {
            capability: Capability::ZeroCopyPreload,
            staleness: Staleness::TooOld {
                age: Duration::from_secs(2),
                limit: Duration::from_secs(1),
            },
        };
        let json = serde_json::to_value(&refusal).unwrap();
        assert_eq!(json["refusal"], "stale");
        assert_eq!(json["staleness"]["kind"], "too_old");
        assert_eq!(
            serde_json::from_value::<EvidenceRefusal>(json).unwrap(),
            refusal
        );
        let requirement = host_only_hypervisor();
        let json = serde_json::to_string(&requirement).unwrap();
        assert_eq!(
            serde_json::from_str::<Requirement>(&json).unwrap(),
            requirement
        );
    }
}
