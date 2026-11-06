//! Fact labels (VM-W04 row: "Distinguish observed, asserted, verified and unavailable
//! facts"; acceptance "stale evidence not presented as current"; §8.1: separate
//! host-observed facts from guest assertions; CORE-01: freshness, configuration
//! fingerprint, source of observation and refusal reason).
//!
//! A view stores each fact's [`FactBasis`]: who stands behind it and, for a host fact,
//! when and under which configuration and clock session it was observed and how long the
//! observation stays fresh. The [`FactLabel`] a user sees is computed from the basis at
//! viewing time, against a [`ClockReading`] of the shared evidence clock and the
//! configuration fingerprint in force then. Labels are Serialize only and never stored,
//! so no stored view holds a "verified" that time or a configuration change has undone.
//!
//! The rules, in CORE-01's order (configuration, clock session, age against the shorter
//! of the reader's maximum age and the observation's own bound):
//!
//! - A host observation that is current is observed; one corroborated by a controlled
//!   check (the backend's `FactSource::Verified`) is verified. Either one stale, from
//!   another clock session or from another configuration is unavailable, with the
//!   problem, the time it was last observed and the CORE-01 [`Remedy`].
//! - CORE-01 evidence (a `Satisfied`) is verified only while current, from a host probe,
//!   under the configuration in force; otherwise it is unavailable with the CORE-01
//!   [`EvidenceRefusal`] it now earns and that refusal's remedy.
//! - An assertion is asserted, at every time and under every configuration, by whoever
//!   made it: the guest, the launch request, a declaration or the contract. A guest
//!   assertion never satisfies a host requirement and never becomes observed or verified.
//! - A host fact with no observation, a capability the contract does not permit and a
//!   planning refusal are unavailable, each with its reason and what the user can do.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::{
    Capability, ClockReading, ClockSession, ConfigurationFingerprint, EvidenceRefusal, Remedy,
    Satisfied, SourceClass, Staleness, UnknownReason,
};
use crate::foundation::ids::{Digest, MonotonicTime};
use crate::sandbox::backend::{FactSource, HostObserved, ObservationProblem};
use crate::sandbox_contract::declarations::{RefusalCode, RemovalEffect};
use crate::sandbox_contract::policy::PolicyLayer;

/// When, on which clock session and under which configuration the host observed a fact,
/// and how long the observation stays fresh (CORE-01 vocabulary; §8.1 "observation source
/// and timestamp").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservationStamp {
    pub clock: ClockSession,
    pub observed_at: MonotonicTime,
    pub fresh_for: Duration,
    pub configuration: ConfigurationFingerprint,
}

impl ObservationStamp {
    /// The stamp of a host observation from a launch record.
    pub fn of<T>(observation: &HostObserved<T>) -> Self {
        Self {
            clock: observation.clock(),
            observed_at: observation.observed_at(),
            fresh_for: observation.fresh_for(),
            configuration: observation.configuration(),
        }
    }

    /// Whether the observation is current at `now` for a reader that accepts nothing
    /// older than `max_age` under `configuration`, by the rules and in the order of
    /// `HostObserved::current_at`: configuration, then clock session, then age against
    /// the shorter of `max_age` and the observation's own bound. When current, the last
    /// moment it stays current.
    pub fn current_at(
        &self,
        now: ClockReading,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Result<MonotonicTime, ObservationProblem> {
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
        Ok(self.observed_at.saturating_add(limit))
    }
}

/// CORE-01 evidence that met a requirement when the launch was admitted: the fields of a
/// `Satisfied`, with the evidence clock session the record was made on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceStamp {
    pub capability: Capability,
    /// The identity of the subject the evidence is about.
    pub subject: Digest,
    pub source: SourceClass,
    pub configuration: ConfigurationFingerprint,
    pub clock: ClockSession,
    pub observed_at: MonotonicTime,
    /// The last moment the evidence met the requirement it satisfied.
    pub fresh_until: MonotonicTime,
}

impl EvidenceStamp {
    /// The stamp of `evidence`, judged on the clock session `clock`.
    pub fn of(evidence: &Satisfied, clock: ClockSession) -> Self {
        Self {
            capability: evidence.capability(),
            subject: evidence.subject(),
            source: evidence.source(),
            configuration: evidence.configuration(),
            clock,
            observed_at: evidence.observed_at(),
            fresh_until: evidence.fresh_until(),
        }
    }

    /// Whether the evidence still verifies its capability at `now` under
    /// `configuration`, for a reader that accepts nothing older than `max_age`, in
    /// CORE-01's order: the source must be a host probe (a guest report never satisfies a
    /// host-only requirement), then the configuration, then the clock session and age.
    /// When current, the last moment it stays current; otherwise the CORE-01 refusal.
    pub fn current_at(
        &self,
        now: ClockReading,
        max_age: Duration,
        configuration: ConfigurationFingerprint,
    ) -> Result<MonotonicTime, EvidenceRefusal> {
        let capability = self.capability;
        if !self.source.satisfies(SourceClass::HostProbe) {
            return Err(EvidenceRefusal::SourceTooWeak {
                capability,
                observed: self.source,
                required: SourceClass::HostProbe,
            });
        }
        if self.configuration != configuration {
            return Err(EvidenceRefusal::FingerprintChanged {
                capability,
                observed_under: self.configuration,
                current: configuration,
            });
        }
        let stale = |staleness| EvidenceRefusal::Stale {
            capability,
            staleness,
        };
        if self.clock != now.session() {
            return Err(stale(Staleness::OtherClock));
        }
        let Some(age) = now.at().checked_duration_since(self.observed_at) else {
            return Err(stale(Staleness::ObservedAfterNow));
        };
        let limit = self
            .fresh_until
            .saturating_duration_since(self.observed_at)
            .min(max_age);
        if age > limit {
            return Err(stale(Staleness::TooOld { age, limit }));
        }
        Ok(self.observed_at.saturating_add(limit))
    }
}

/// Who asserted a fact that no host observation stands behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssertedBy {
    /// The guest. A hostile guest can report a plausible result, hide files or lie about
    /// interfaces (§8.1); its assertions never satisfy a host requirement.
    Guest,
    /// The host's launch request: the backend build, artifacts and device profile it
    /// pinned. What was asked for, not an observation.
    LaunchRequest,
    /// A template, tool or user declaration (V08), or the setup's chosen network mode.
    Declaration,
    /// The resolved V01 contract: what it grants, never that anything enforces it (§2.4
    /// line 1804).
    Contract,
}

impl AssertedBy {
    /// Whether facts asserted this way come from the launch record.
    pub const fn from_launch_record(self) -> bool {
        matches!(self, Self::Guest | Self::LaunchRequest)
    }
}

impl fmt::Display for AssertedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Guest => "the guest",
            Self::LaunchRequest => "the launch request",
            Self::Declaration => "the declaration",
            Self::Contract => "the contract",
        })
    }
}

strict_view_enum! {
    /// What the user can do about an unavailable fact or capability: a CORE-01 remedy for
    /// evidence, or the help of a V08 refusal code for the contract and planning (CORE-07
    /// "actionable refusal").
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum WhatToDo tag "kind" {
        Evidence { remedy: Remedy },
        Refusal { code: RefusalCode },
    }
}

impl fmt::Display for WhatToDo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence { remedy } => write!(f, "{remedy}"),
            Self::Refusal { code } => f.write_str(code.help()),
        }
    }
}

strict_view_enum! {
    /// Who or what stands behind a fact, as a view stores it. The label shown is computed
    /// from this at viewing time ([`FactBasis::label_at`]).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum FactBasis tag "basis" {
        /// The host observed it itself (§8.1: host configuration, process state or a
        /// controlled external observation).
        HostObserved { stamp: ObservationStamp },
        /// The host observed it and a controlled check corroborated it (§0.2).
        HostVerified { stamp: ObservationStamp },
        /// CORE-01 evidence that satisfied a requirement of the launch.
        Core01Evidence { stamp: EvidenceStamp },
        /// Someone other than the host asserted it. `received_at` is when a guest
        /// assertion arrived, on the launch's evidence clock.
        Asserted {
            by: AssertedBy,
            #[serde(default, skip_serializing_if = "Option::is_none")]
            received_at: Option<MonotonicTime>,
        },
        /// The host has no observation; `guest_asserted` says whether the guest asserted
        /// something in its place.
        NotObserved { reason: UnknownReason, guest_asserted: bool },
        /// A requested capability the resolved contract does not permit.
        NotPermitted {
            excluded_by: BTreeSet<PolicyLayer>,
            effect: RemovalEffect,
        },
        /// Planning refused; `remedy` is what the refusal asks of the user.
        Refused { code: RefusalCode, remedy: WhatToDo },
    }
}

impl FactBasis {
    /// Whether a fact on this basis comes from the launch record rather than the
    /// contract, the declaration or planning.
    pub fn from_launch_record(&self) -> bool {
        match self {
            Self::HostObserved { .. }
            | Self::HostVerified { .. }
            | Self::Core01Evidence { .. }
            | Self::NotObserved { .. } => true,
            Self::Asserted { by, .. } => by.from_launch_record(),
            Self::NotPermitted { .. } | Self::Refused { .. } => false,
        }
    }

    /// The label at `now` under `configuration`, for a reader that accepts nothing older
    /// than `max_age`. See the module notes for the rules.
    pub fn label_at(
        &self,
        now: ClockReading,
        configuration: ConfigurationFingerprint,
        max_age: Duration,
    ) -> FactLabel {
        match self {
            Self::HostObserved { stamp } => match stamp.current_at(now, max_age, configuration) {
                Ok(fresh_until) => FactLabel::Observed {
                    source: SourceClass::HostProbe,
                    observed_at: stamp.observed_at,
                    fresh_until,
                },
                Err(problem) => not_current(problem, stamp.observed_at),
            },
            Self::HostVerified { stamp } => match stamp.current_at(now, max_age, configuration) {
                Ok(fresh_until) => FactLabel::Verified {
                    by: VerifiedBy::ControlledCheck,
                    observed_at: stamp.observed_at,
                    fresh_until,
                },
                Err(problem) => not_current(problem, stamp.observed_at),
            },
            Self::Core01Evidence { stamp } => match stamp.current_at(now, max_age, configuration) {
                Ok(fresh_until) => FactLabel::Verified {
                    by: VerifiedBy::Evidence {
                        capability: stamp.capability,
                        source: stamp.source,
                    },
                    observed_at: stamp.observed_at,
                    fresh_until,
                },
                Err(refusal) => FactLabel::Unavailable {
                    remedy: WhatToDo::Evidence {
                        remedy: refusal.remedy(),
                    },
                    why: Unavailability::EvidenceRefused {
                        refusal,
                        last_observed_at: stamp.observed_at,
                    },
                },
            },
            Self::Asserted { by, received_at } => FactLabel::Asserted {
                by: *by,
                received_at: *received_at,
            },
            Self::NotObserved {
                reason,
                guest_asserted: false,
            } => FactLabel::Unavailable {
                why: Unavailability::NotObserved { reason: *reason },
                remedy: WhatToDo::Evidence {
                    remedy: reason.remedy(),
                },
            },
            Self::NotObserved {
                reason,
                guest_asserted: true,
            } => FactLabel::Unavailable {
                why: Unavailability::OnlyGuestAsserted { reason: *reason },
                remedy: WhatToDo::Evidence {
                    remedy: Remedy::ObtainStrongerEvidence {
                        required: SourceClass::HostProbe,
                    },
                },
            },
            Self::NotPermitted {
                excluded_by,
                effect,
            } => FactLabel::Unavailable {
                why: Unavailability::NotPermitted {
                    excluded_by: excluded_by.clone(),
                    effect: *effect,
                },
                remedy: WhatToDo::Refusal {
                    code: RefusalCode::RequiredAuthorityRemoved,
                },
            },
            Self::Refused { code, remedy } => FactLabel::Unavailable {
                why: Unavailability::Refused { code: *code },
                remedy: *remedy,
            },
        }
    }
}

/// The basis of a host observation from a launch record: verified when a controlled check
/// corroborated it, otherwise observed.
pub(super) fn host_basis<T>(observation: &HostObserved<T>) -> FactBasis {
    let stamp = ObservationStamp::of(observation);
    match observation.source() {
        FactSource::Verified => FactBasis::HostVerified { stamp },
        FactSource::HostObserved | FactSource::GuestAsserted | FactSource::Unavailable => {
            FactBasis::HostObserved { stamp }
        }
    }
}

fn not_current(problem: ObservationProblem, last_observed_at: MonotonicTime) -> FactLabel {
    let remedy = match problem {
        ObservationProblem::OtherConfiguration { .. } => Remedy::RecheckCurrentConfiguration,
        ObservationProblem::Stale { .. } => Remedy::RunCheckAgain,
    };
    FactLabel::Unavailable {
        why: Unavailability::NotCurrent {
            problem,
            last_observed_at,
        },
        remedy: WhatToDo::Evidence { remedy },
    }
}

/// What verified a fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "by", rename_all = "snake_case")]
pub enum VerifiedBy {
    /// A host observation corroborated by a controlled check (§0.2), such as a positive
    /// control against a reachable endpoint.
    ControlledCheck,
    /// CORE-01 evidence of `capability` from `source`.
    Evidence {
        capability: Capability,
        source: SourceClass,
    },
}

impl fmt::Display for VerifiedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ControlledCheck => {
                f.write_str("a host observation corroborated by a controlled check")
            }
            Self::Evidence { capability, source } => {
                write!(f, "{capability} evidence from a {source}")
            }
        }
    }
}

/// Why a fact or capability is unavailable, computed at viewing time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "why", rename_all = "snake_case")]
pub enum Unavailability {
    /// The host has no observation.
    NotObserved { reason: UnknownReason },
    /// Only the guest asserted it; a guest assertion never satisfies a host requirement.
    OnlyGuestAsserted { reason: UnknownReason },
    /// A host observation that is stale, from another clock session or from another
    /// configuration, so it is not presented as current.
    NotCurrent {
        problem: ObservationProblem,
        last_observed_at: MonotonicTime,
    },
    /// CORE-01 would refuse the evidence now.
    EvidenceRefused {
        refusal: EvidenceRefusal,
        last_observed_at: MonotonicTime,
    },
    /// The resolved contract does not permit the requested capability.
    NotPermitted {
        excluded_by: BTreeSet<PolicyLayer>,
        effect: RemovalEffect,
    },
    /// Planning refused with this code.
    Refused { code: RefusalCode },
}

impl Unavailability {
    /// Whether the text of this reason already names what the user can do (CORE-01's
    /// evidence refusals do).
    pub const fn names_remedy(&self) -> bool {
        matches!(self, Self::EvidenceRefused { .. })
    }
}

impl fmt::Display for Unavailability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotObserved { reason } => write!(f, "the host has no observation: {reason}"),
            Self::OnlyGuestAsserted { reason } => write!(
                f,
                "only the guest asserted it and the host has no observation ({reason}); a \
                 guest assertion never satisfies a host requirement"
            ),
            Self::NotCurrent {
                problem,
                last_observed_at,
            } => write!(
                f,
                "{problem}; last observed at {} ns on the evidence clock",
                last_observed_at.as_nanos()
            ),
            Self::EvidenceRefused { refusal, .. } => write!(f, "{refusal}"),
            Self::NotPermitted {
                excluded_by,
                effect,
            } => {
                f.write_str("not permitted by ")?;
                for (index, layer) in excluded_by.iter().enumerate() {
                    if index > 0 {
                        f.write_str(" or ")?;
                    }
                    write!(f, "{layer}")?;
                }
                f.write_str(match effect {
                    RemovalEffect::LaunchRefused => "; it is required, so the launch is refused",
                    RemovalEffect::Dropped => "; it was optional and is dropped",
                })
            }
            Self::Refused { code } => write!(f, "planning refused it [{code}]"),
        }
    }
}

/// The label of one fact at one viewing time (VM-W04 row). Computed, never stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "label", rename_all = "snake_case")]
pub enum FactLabel {
    /// The host observed it, and the observation is current.
    Observed {
        source: SourceClass,
        observed_at: MonotonicTime,
        fresh_until: MonotonicTime,
    },
    /// Asserted, not observed; never satisfies a host requirement.
    Asserted {
        by: AssertedBy,
        #[serde(skip_serializing_if = "Option::is_none")]
        received_at: Option<MonotonicTime>,
    },
    /// Verified and current under the configuration in force.
    Verified {
        by: VerifiedBy,
        observed_at: MonotonicTime,
        fresh_until: MonotonicTime,
    },
    /// Not available as a current fact: why, and what the user can do.
    Unavailable {
        why: Unavailability,
        remedy: WhatToDo,
    },
}

impl FactLabel {
    pub const fn is_observed(&self) -> bool {
        matches!(self, Self::Observed { .. })
    }

    pub const fn is_asserted(&self) -> bool {
        matches!(self, Self::Asserted { .. })
    }

    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }

    /// The stable name of the label.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Observed { .. } => "observed",
            Self::Asserted { .. } => "asserted",
            Self::Verified { .. } => "verified",
            Self::Unavailable { .. } => "unavailable",
        }
    }
}

impl fmt::Display for FactLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Observed {
                source,
                observed_at,
                fresh_until,
            } => write!(
                f,
                "observed by a {source} at {} ns, current until {} ns on the evidence clock",
                observed_at.as_nanos(),
                fresh_until.as_nanos()
            ),
            Self::Asserted {
                by: AssertedBy::Guest,
                received_at,
            } => {
                f.write_str("asserted by the guest")?;
                if let Some(at) = received_at {
                    write!(f, " at {} ns", at.as_nanos())?;
                }
                f.write_str("; a guest assertion never satisfies a host requirement")
            }
            Self::Asserted { by, .. } => write!(
                f,
                "asserted by {by}; it states what was asked for or granted, not what the host \
                 observed"
            ),
            Self::Verified {
                by,
                observed_at,
                fresh_until,
            } => write!(
                f,
                "verified by {by}, observed at {} ns, current until {} ns on the evidence clock",
                observed_at.as_nanos(),
                fresh_until.as_nanos()
            ),
            Self::Unavailable { why, .. } if why.names_remedy() => {
                write!(f, "unavailable: {why}")
            }
            Self::Unavailable { why, remedy } => {
                write!(f, "unavailable: {why}; what you can do: {remedy}")
            }
        }
    }
}
