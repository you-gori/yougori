//! The evidence state of a shown value (VM-W04: "Distinguish observed, asserted, verified
//! and unavailable facts"; acceptance "stale evidence not presented as current"; §8.1:
//! evidence records, not certificates; CORE-01: source of observation, freshness and
//! refusal reason).
//!
//! Every shown value carries exactly one [`Evidence`] state, so one field never mixes
//! states. The types make the rule structural: only a host stands behind a verified value
//! ([`VerifiedBy`]), only the host or a provider's control-plane API behind an observed one
//! ([`Observer`]), and everything weaker is an assertion ([`Asserter`]). CORE-01 evidence
//! takes its state from its source ([`Evidence::from_satisfied`]): a host probe verifies,
//! a provider API observes, and a guest report, a recorded declaration or a fixture
//! asserts, so an assertion is never shown as verified. A [`Fact`] holds a value only
//! while its state is not unavailable, so no unavailable fact shows a value as if it were
//! current. [`Evidence::as_of`] demotes a verified or observed state that is no longer
//! current when a stored document is shown again.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::refusal::{EvidenceCode, Refusal, RefusalCode, Remedy};
use super::view::ShownAt;
use crate::foundation::evidence::{
    Capability, ClockReading, ConfigurationFingerprint, Remedy as EvidenceRemedy, Satisfied,
    SourceClass,
};
use crate::foundation::ids::MonotonicTime;

strict_product_enum! {
    /// What verified a value. Only the host does.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum VerifiedBy tag "kind" {
        /// CORE-01 host-probe evidence of this capability.
        HostProbe { capability: Capability },
        /// A host observation corroborated by a controlled check (VM §0.2), such as a
        /// positive control against a reachable endpoint.
        ControlledCheck,
    }
}

impl fmt::Display for VerifiedBy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostProbe { capability } => write!(f, "{capability} evidence from a host probe"),
            Self::ControlledCheck => {
                f.write_str("a host observation corroborated by a controlled check")
            }
        }
    }
}

/// Who observed a value: the host itself, or a provider's control-plane API (CORE-01's two
/// strongest sources).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Observer {
    Host,
    ProviderApi,
}

impl Observer {
    /// The CORE-01 source class of the observation.
    pub const fn source(self) -> SourceClass {
        match self {
            Self::Host => SourceClass::HostProbe,
            Self::ProviderApi => SourceClass::ProviderApi,
        }
    }
}

/// Who asserted a value that no host or provider observation stands behind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Asserter {
    /// The guest; a hostile guest can report anything plausible (§8.1).
    Guest,
    /// The request: what was asked for, not what runs.
    Request,
    /// A template, tool or user declaration, or a recorded statement.
    Declaration,
    /// The resolved contract: what it grants, never that anything enforces it.
    Contract,
    /// Test or CI fixture data, which never certifies a real backend (S2).
    Fixture,
    /// A record an old setup wrote before this contract.
    LegacyRecord,
}

impl Asserter {
    /// The CORE-01 source class an assertion counts as.
    pub const fn source(self) -> SourceClass {
        match self {
            Self::Guest => SourceClass::GuestReport,
            Self::Fixture => SourceClass::Fixture,
            Self::Request | Self::Declaration | Self::Contract | Self::LegacyRecord => {
                SourceClass::RecordedDeclaration
            }
        }
    }
}

impl fmt::Display for Asserter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Guest => "the guest",
            Self::Request => "the request",
            Self::Declaration => "a declaration",
            Self::Contract => "the contract",
            Self::Fixture => "a test fixture",
            Self::LegacyRecord => "an old setup record",
        })
    }
}

/// The one evidence state of a shown value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Evidence {
    /// Verified by the host and current when shown.
    Verified {
        by: VerifiedBy,
        observed_at: MonotonicTime,
        fresh_until: MonotonicTime,
    },
    /// Observed by the host or a provider API and current when shown.
    Observed {
        by: Observer,
        observed_at: MonotonicTime,
        fresh_until: MonotonicTime,
    },
    /// Asserted, not observed; it never satisfies a host requirement.
    Asserted {
        by: Asserter,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        received_at: Option<MonotonicTime>,
    },
    /// Not available as a current fact: why, and what the user can do.
    Unavailable { refusal: Refusal },
}

impl Evidence {
    /// The state of CORE-01 evidence at `now`, a reading of the registry that evaluated
    /// it: a host probe verifies, a provider API observes, a guest report, recorded
    /// declaration or fixture asserts. Evidence past its freshness bound, or dated after
    /// `now`, is unavailable with a reason and remedy.
    pub fn from_satisfied(satisfied: &Satisfied, now: ClockReading) -> Self {
        let observed_at = satisfied.observed_at();
        let fresh_until = satisfied.fresh_until();
        if now.at() < observed_at || now.at() > fresh_until {
            return Self::not_current(
                satisfied.capability().name(),
                observed_at,
                fresh_until,
                now.at(),
            );
        }
        match satisfied.source() {
            SourceClass::HostProbe => Self::Verified {
                by: VerifiedBy::HostProbe {
                    capability: satisfied.capability(),
                },
                observed_at,
                fresh_until,
            },
            SourceClass::ProviderApi => Self::Observed {
                by: Observer::ProviderApi,
                observed_at,
                fresh_until,
            },
            weaker => Self::Asserted {
                by: asserter_of(weaker),
                received_at: Some(observed_at),
            },
        }
    }

    /// A current observation by its CORE-01 source: the host's is observed by the host, a
    /// provider API's by the provider, and anything weaker is an assertion by the party it
    /// came from. Nothing becomes verified here: only host-probe evidence or a controlled
    /// check verifies.
    pub fn observed_by(
        source: SourceClass,
        observed_at: MonotonicTime,
        fresh_until: MonotonicTime,
    ) -> Self {
        match source {
            SourceClass::HostProbe => Self::Observed {
                by: Observer::Host,
                observed_at,
                fresh_until,
            },
            SourceClass::ProviderApi => Self::Observed {
                by: Observer::ProviderApi,
                observed_at,
                fresh_until,
            },
            weaker => Self::Asserted {
                by: asserter_of(weaker),
                received_at: Some(observed_at),
            },
        }
    }

    /// Unavailable, with `refusal`.
    pub fn unavailable(refusal: Refusal) -> Self {
        Self::Unavailable { refusal }
    }

    /// The stable name of the state.
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Verified { .. } => "verified",
            Self::Observed { .. } => "observed",
            Self::Asserted { .. } => "asserted",
            Self::Unavailable { .. } => "unavailable",
        }
    }

    pub const fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    pub const fn is_observed(&self) -> bool {
        matches!(self, Self::Observed { .. })
    }

    pub const fn is_asserted(&self) -> bool {
        matches!(self, Self::Asserted { .. })
    }

    pub const fn is_unavailable(&self) -> bool {
        matches!(self, Self::Unavailable { .. })
    }

    /// The refusal of an unavailable state.
    pub fn refusal(&self) -> Option<&Refusal> {
        match self {
            Self::Unavailable { refusal } => Some(refusal),
            _ => None,
        }
    }

    /// The CORE-01 source class standing behind the state; `None` when unavailable.
    pub fn source(&self) -> Option<SourceClass> {
        match self {
            Self::Verified { .. } => Some(SourceClass::HostProbe),
            Self::Observed { by, .. } => Some(by.source()),
            Self::Asserted { by, .. } => Some(by.source()),
            Self::Unavailable { .. } => None,
        }
    }

    /// The state when a document shown at `shown` is shown again at `now` under
    /// `configuration`: a verified or observed state stays only while it is current, on the
    /// same clock session and under the same configuration; otherwise it is unavailable
    /// with the reason and the CORE-01 remedy. Assertions and unavailable states are
    /// unchanged.
    pub fn as_of(
        &self,
        shown: &ShownAt,
        now: ClockReading,
        configuration: ConfigurationFingerprint,
    ) -> Self {
        let (observed_at, fresh_until, what) = match self {
            Self::Verified {
                observed_at,
                fresh_until,
                ..
            } => (*observed_at, *fresh_until, "verified"),
            Self::Observed {
                observed_at,
                fresh_until,
                ..
            } => (*observed_at, *fresh_until, "observed"),
            Self::Asserted { .. } | Self::Unavailable { .. } => return self.clone(),
        };
        if configuration != shown.configuration {
            return Self::Unavailable {
                refusal: Refusal::new(
                    RefusalCode::Evidence {
                        code: EvidenceCode::ConfigurationChanged,
                    },
                    &format!(
                        "this was {what} under another host configuration and no longer applies"
                    ),
                    Remedy::Evidence {
                        step: EvidenceRemedy::RecheckCurrentConfiguration,
                    },
                ),
            };
        }
        if now.session() != shown.clock {
            return Self::Unavailable {
                refusal: Refusal::new(
                    RefusalCode::Evidence {
                        code: EvidenceCode::Stale,
                    },
                    &format!(
                        "this was {what} on another clock, such as before a restart, so its age \
                         cannot be known"
                    ),
                    Remedy::Evidence {
                        step: EvidenceRemedy::RunCheckAgain,
                    },
                ),
            };
        }
        if now.at() < observed_at || now.at() > fresh_until {
            return Self::not_current(what, observed_at, fresh_until, now.at());
        }
        self.clone()
    }

    fn not_current(
        what: &str,
        observed_at: MonotonicTime,
        fresh_until: MonotonicTime,
        now: MonotonicTime,
    ) -> Self {
        let reason = if now < observed_at {
            format!(
                "the {what} observation at {} ns is dated after the current time",
                observed_at.as_nanos()
            )
        } else {
            format!(
                "the {what} observation at {} ns was current until {} ns on the evidence clock, \
                 and it is now {} ns",
                observed_at.as_nanos(),
                fresh_until.as_nanos(),
                now.as_nanos()
            )
        };
        Self::Unavailable {
            refusal: Refusal::new(
                RefusalCode::Evidence {
                    code: EvidenceCode::Stale,
                },
                &reason,
                Remedy::Evidence {
                    step: EvidenceRemedy::RunCheckAgain,
                },
            ),
        }
    }

    /// Checks the state's own consistency: an observation is not current after its
    /// freshness bound.
    pub fn check(&self) -> Result<(), FactError> {
        match self {
            Self::Verified {
                observed_at,
                fresh_until,
                ..
            }
            | Self::Observed {
                observed_at,
                fresh_until,
                ..
            } if fresh_until < observed_at => Err(FactError::FreshBeforeObserved),
            _ => Ok(()),
        }
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verified {
                by, fresh_until, ..
            } => write!(
                f,
                "verified by {by}, current until {} ns on the evidence clock",
                fresh_until.as_nanos()
            ),
            Self::Observed {
                by: Observer::Host,
                fresh_until,
                ..
            } => write!(
                f,
                "observed by the host, current until {} ns on the evidence clock",
                fresh_until.as_nanos()
            ),
            Self::Observed {
                by: Observer::ProviderApi,
                fresh_until,
                ..
            } => write!(
                f,
                "reported by the provider's API, not verified by the host, current until {} ns \
                 on the evidence clock",
                fresh_until.as_nanos()
            ),
            Self::Asserted { by, .. } => write!(
                f,
                "asserted by {by}; an assertion is not an observation and never satisfies a host \
                 requirement"
            ),
            Self::Unavailable { refusal } => write!(f, "unavailable: {refusal}"),
        }
    }
}

/// The wire form of [`Evidence`]: every variant is a struct variant, so serde's
/// `deny_unknown_fields` holds for each.
#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
#[serde(remote = "Self")]
enum EvidenceWire {
    Verified {
        by: VerifiedBy,
        observed_at: MonotonicTime,
        fresh_until: MonotonicTime,
    },
    Observed {
        by: Observer,
        observed_at: MonotonicTime,
        fresh_until: MonotonicTime,
    },
    Asserted {
        by: Asserter,
        #[serde(default)]
        received_at: Option<MonotonicTime>,
    },
    Unavailable {
        refusal: Refusal,
    },
}

crate::foundation::strict_serde::strict_tag!(EvidenceWire, "state", deserialize);

impl<'de> Deserialize<'de> for Evidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let evidence = match <EvidenceWire as Deserialize>::deserialize(deserializer)? {
            EvidenceWire::Verified {
                by,
                observed_at,
                fresh_until,
            } => Self::Verified {
                by,
                observed_at,
                fresh_until,
            },
            EvidenceWire::Observed {
                by,
                observed_at,
                fresh_until,
            } => Self::Observed {
                by,
                observed_at,
                fresh_until,
            },
            EvidenceWire::Asserted { by, received_at } => Self::Asserted { by, received_at },
            EvidenceWire::Unavailable { refusal } => Self::Unavailable { refusal },
        };
        evidence.check().map_err(serde::de::Error::custom)?;
        Ok(evidence)
    }
}

/// The asserter a CORE-01 source weaker than a provider API counts as. Callers pass only
/// such sources; a stronger one is never upgraded here and counts as a declaration.
fn asserter_of(source: SourceClass) -> Asserter {
    match source {
        SourceClass::GuestReport => Asserter::Guest,
        SourceClass::Fixture => Asserter::Fixture,
        SourceClass::RecordedDeclaration | SourceClass::ProviderApi | SourceClass::HostProbe => {
            Asserter::Declaration
        }
    }
}

/// A shown value and its one evidence state. The value is present exactly when the state
/// is not unavailable.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Fact<T> {
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<T>,
    evidence: Evidence,
}

impl<T> Fact<T> {
    /// `value` standing on `evidence`; refused when `evidence` is unavailable or
    /// inconsistent.
    pub fn new(value: T, evidence: Evidence) -> Result<Self, FactError> {
        if evidence.is_unavailable() {
            return Err(FactError::UnavailableWithValue);
        }
        evidence.check()?;
        Ok(Self {
            value: Some(value),
            evidence,
        })
    }

    /// `value` asserted by `by`, received at `received_at` if that is known. An assertion
    /// is never inconsistent, and it never satisfies a host requirement.
    pub fn asserted(value: T, by: Asserter, received_at: Option<MonotonicTime>) -> Self {
        Self {
            value: Some(value),
            evidence: Evidence::Asserted { by, received_at },
        }
    }

    /// No current value, with why and what the user can do.
    pub fn unavailable(refusal: Refusal) -> Self {
        Self {
            value: None,
            evidence: Evidence::Unavailable { refusal },
        }
    }

    /// `value` on CORE-01 evidence at `now` ([`Evidence::from_satisfied`]); unavailable,
    /// without the value, when the evidence is no longer current.
    pub fn from_satisfied(value: T, satisfied: &Satisfied, now: ClockReading) -> Self {
        match Evidence::from_satisfied(satisfied, now) {
            Evidence::Unavailable { refusal } => Self::unavailable(refusal),
            evidence => Self {
                value: Some(value),
                evidence,
            },
        }
    }

    /// The value, while the state is not unavailable.
    pub fn value(&self) -> Option<&T> {
        self.value.as_ref()
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The fact when shown again ([`Evidence::as_of`]); a value whose evidence is no longer
    /// current is dropped.
    pub fn as_of(
        &self,
        shown: &ShownAt,
        now: ClockReading,
        configuration: ConfigurationFingerprint,
    ) -> Self
    where
        T: Clone,
    {
        match self.evidence.as_of(shown, now, configuration) {
            Evidence::Unavailable { refusal } => Self::unavailable(refusal),
            evidence => Self {
                value: self.value.clone(),
                evidence,
            },
        }
    }
}

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Fact<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire<U> {
            #[serde(default = "Option::default")]
            value: Option<U>,
            evidence: Evidence,
        }
        let wire = Wire::<T>::deserialize(deserializer)?;
        match (wire.value, wire.evidence) {
            (None, Evidence::Unavailable { refusal }) => Ok(Self::unavailable(refusal)),
            (Some(_), Evidence::Unavailable { .. }) => {
                Err(serde::de::Error::custom(FactError::UnavailableWithValue))
            }
            (None, _) => Err(serde::de::Error::custom(FactError::MissingValue)),
            (Some(value), evidence) => Self::new(value, evidence).map_err(serde::de::Error::custom),
        }
    }
}

/// Why a fact is inconsistent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FactError {
    /// An unavailable fact holds a value, which could be shown as if it were current.
    UnavailableWithValue,
    /// A verified, observed or asserted fact holds no value.
    MissingValue,
    /// The freshness bound lies before the observation.
    FreshBeforeObserved,
}

impl fmt::Display for FactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UnavailableWithValue => {
                "an unavailable fact holds no value, so none is shown as current"
            }
            Self::MissingValue => "a verified, observed or asserted fact needs its value",
            Self::FreshBeforeObserved => "the freshness bound lies before the observation",
        })
    }
}

impl std::error::Error for FactError {}
