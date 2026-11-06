//! References from rollout decisions to their CORE-08 evidence, by identity (G08: "record
//! rollout decisions with CORE-08 evidence"; S2 CORE-08, line 217: "Signed component
//! identity ... reported consistently"; GPU-W11, line 1321: "authenticated pinned artifact
//! identity").
//!
//! An [`EvidenceReference`] names the evidence of one trial: the CORE-08 digest of its run
//! records (`Provenance::comparable_evidence`), CORE-08's judgement whether they are a
//! Yougori measurement, and the [`SignedComponent`] of the helper bundle the trial ran,
//! the verification of its publisher's signature as recorded beside the runs
//! ([`SignedBuildIdentity`](crate::foundation::signing::SignedBuildIdentity)).
//!
//! A reference is built only from a provenance in hand ([`EvidenceReference::of`]) and is
//! never read back. The rollout journal keeps the identity it names; a decision that needs
//! evidence, a promotion or the removal of source injection, takes a reference built again
//! from the run records themselves (`Provenance::of_records`), and it must name exactly
//! the records the journal holds for that decision. A digest written down never becomes a
//! measurement (CORE-08's own rule for `Provenance`).
//!
//! [`check_component`] is the check that a component is a helper version's: the
//! `model_helper` class, the pin's publisher and the content statement of the pin's bundle
//! ([`pin_statement`], the statement [`bundle_statement`](super::bundle_statement) gives for
//! its bytes). A pass, a promotion and a removal need it verified by a trust-root key as
//! well; failure evidence does not, so a revoked key never holds a rollback up.

use std::fmt;

use super::admission::HELPER_CLASS;
use super::identity::{HelperPin, HelperPinId};
use super::rollout::RolloutStage;
use crate::foundation::catalog::{ArtifactClass, PublisherId};
use crate::foundation::ids::Digest;
use crate::foundation::report::{Provenance, ReportError};
use crate::foundation::signing::{content_statement, ComponentVerification, SignedComponent};

/// The content statement `pin`'s publisher signed for its bundle: what its
/// [`SignedComponent`] must name.
pub fn pin_statement(pin: &HelperPin) -> Digest {
    content_statement(&pin.publisher, HELPER_CLASS, &pin.bundle, pin.length_bytes)
}

/// Why a signed component is not that of a helper version's bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BundleMismatch {
    /// The component is of another artifact class.
    Class { found: ArtifactClass },
    /// Another publisher's key signed it.
    Publisher {
        expected: PublisherId,
        found: PublisherId,
    },
    /// It covers another statement: another bundle, or another length.
    Statement { expected: Digest, found: Digest },
    /// No trust-root key vouched for the signature when it was checked.
    NotVerified { verification: ComponentVerification },
}

impl fmt::Display for BundleMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Class { found } => {
                write!(
                    f,
                    "the signed component is a {found} artifact, not a helper"
                )
            }
            Self::Publisher { .. } => {
                f.write_str("another publisher signed the component than the helper version's")
            }
            Self::Statement { .. } => {
                f.write_str("the signed component covers another bundle than the helper version's")
            }
            Self::NotVerified { .. } => {
                f.write_str("no trust-root key vouched for the helper bundle's signature")
            }
        }
    }
}

impl std::error::Error for BundleMismatch {}

/// Checks that `component` is the signature of `pin`'s bundle: its class, publisher and
/// statement; with `verified`, also that a trust-root key vouched for it.
pub fn check_component(
    component: &SignedComponent,
    pin: &HelperPin,
    verified: bool,
) -> Result<(), BundleMismatch> {
    if component.class() != HELPER_CLASS {
        return Err(BundleMismatch::Class {
            found: component.class(),
        });
    }
    if component.publisher() != &pin.publisher {
        return Err(BundleMismatch::Publisher {
            expected: pin.publisher,
            found: *component.publisher(),
        });
    }
    let expected = pin_statement(pin);
    if component.statement() != &expected {
        return Err(BundleMismatch::Statement {
            expected,
            found: *component.statement(),
        });
    }
    if verified && !component.is_verified() {
        return Err(BundleMismatch::NotVerified {
            verification: component.verification().clone(),
        });
    }
    Ok(())
}

/// The identity of one trial's CORE-08 evidence: its run records and the helper bundle's
/// signed component. Built only from a provenance in hand.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceReference {
    records: Digest,
    measured: bool,
    component: SignedComponent,
}

impl EvidenceReference {
    /// The reference to the run records behind `provenance`, with the signed component of
    /// the helper bundle the runs used. Refuses a provenance that names no records (an
    /// unreproduced third-party claim), as the rollout does.
    pub fn of(provenance: &Provenance, component: SignedComponent) -> Result<Self, ReportError> {
        Ok(Self {
            records: provenance.comparable_evidence()?,
            measured: provenance.yougori_evidence().is_ok(),
            component,
        })
    }

    /// The CORE-08 evidence digest of the run records.
    pub fn records(&self) -> Digest {
        self.records
    }

    /// Whether CORE-08 judged the records a Yougori measurement.
    pub fn is_measured(&self) -> bool {
        self.measured
    }

    pub fn component(&self) -> &SignedComponent {
        &self.component
    }
}

/// Why the evidence reference of a decision was refused. Nothing was decided or recorded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceRefusal {
    /// The track holds no measured pass of `pin` at `stage` for the decision to rest on.
    Missing {
        pin: HelperPinId,
        stage: RolloutStage,
    },
    /// The reference names other run records than the measured pass the track holds.
    Mismatch {
        pin: HelperPinId,
        stage: RolloutStage,
        recorded: Digest,
        found: Digest,
    },
    /// A fake-substrate run or an unreproduced claim: it decides nothing.
    NotMeasured,
    /// The signed component is not that of the helper version's bundle.
    Bundle {
        pin: HelperPinId,
        mismatch: BundleMismatch,
    },
}

impl fmt::Display for EvidenceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Missing { stage, .. } => write!(
                f,
                "no measured pass of the helper version was recorded at the {stage} stage"
            ),
            Self::Mismatch { stage, .. } => write!(
                f,
                "the evidence names other run records than the measured pass recorded at the \
                 {stage} stage"
            ),
            Self::NotMeasured => f.write_str("the evidence is not a Yougori measurement"),
            Self::Bundle { mismatch, .. } => mismatch.fmt(f),
        }
    }
}

impl std::error::Error for EvidenceRefusal {}

/// Checks that `reference` is measured, names the run records `recorded` and the verified
/// signature of `pin`'s bundle: the evidence a decision about `pin` at `stage` rests on.
pub(super) fn check_decision(
    reference: &EvidenceReference,
    pin: &HelperPin,
    stage: RolloutStage,
    recorded: Option<Digest>,
) -> Result<(), EvidenceRefusal> {
    let id = pin.id();
    let recorded = recorded.ok_or(EvidenceRefusal::Missing { pin: id, stage })?;
    if !reference.measured {
        return Err(EvidenceRefusal::NotMeasured);
    }
    if reference.records != recorded {
        return Err(EvidenceRefusal::Mismatch {
            pin: id,
            stage,
            recorded,
            found: reference.records,
        });
    }
    check_component(&reference.component, pin, true)
        .map_err(|mismatch| EvidenceRefusal::Bundle { pin: id, mismatch })
}
