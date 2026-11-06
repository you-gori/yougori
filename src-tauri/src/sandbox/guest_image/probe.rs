//! The booted-image facts as `sandbox::probes` observations, so a host check runner can
//! feed `Capability::BootedImageMatchesManifest` (`BootedImageMatchesManifestProbe`:
//! the host corroboration of VM-CP-05 and the host-observed VM-CP-17 and VM-CP-23,
//! lines 3155, 3167 and 3173; §17, line 3147: a positive control must hold in the same
//! run). Nothing here runs a check: a runner hands [`observations`] what the host
//! observed and returns the result as its `RunResult::Observed`.
//!
//! - VM-CP-05, the booted root image: `cp05.booted-root-image` compares the root image
//!   the host booted with the signed manifest's.
//! - VM-CP-05, the kernel build record: `cp05.kernel-build-record` compares the
//!   [`kernel_record_digest`] of the record bound to the booted kernel with the signed
//!   manifest's; its control `cp05.io-uring-image-fails-kernel-check` is the
//!   [`KernelControl`] of the same run.
//! - VM-CP-17: `cp17.next-generation-signed-base` compares the root image the next
//!   generation booted with the signed manifest's. The check's other observation, the
//!   persisted volume inventory, is not this module's; the runner adds it.
//! - VM-CP-23: one observation per [`BoundaryCase`], from the outcome of that attempt at
//!   the launch boundary ([`admit_launch`](super::admit_launch)). An attempt admitted
//!   is not refused; one refused for the case's own reason is refused; one refused for
//!   any other reason did not test the case, so its observation is left out and the part
//!   is inconclusive. The signed set is the control: it must launch.
//!
//! Evidence the runner does not have is left out, never invented: no host corroboration
//! means no comparison, and a missing observation makes the part inconclusive.

use std::collections::BTreeMap;

use serde::Serialize;

use super::boot::BootRefusal;
use super::gate::LaunchRefusal;
use super::kernel::{kernel_record_digest, KernelControl};
use super::record::ArtifactRole;
use super::select::SelectionRefusal;
use super::signed::VerifyRefusal;
use crate::foundation::signing::ComponentVerification;
use crate::sandbox::probes::{
    CheckId, CorroboratingFact, ExpectationId, Observations, Observed, Part,
};
use crate::sandbox_contract::confinement::{HostCorroboration, ManifestExpectation};

/// One VM-CP-23 attempt at the launch boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum BoundaryCase {
    /// The root image with one byte changed.
    RootImageByteChange,
    /// The manifest without a signature a trust-root key vouches for.
    UnsignedManifest,
    /// The manifest after its expiry.
    ExpiredMetadata,
    /// An older release than the host's floor.
    RolledBackVersion,
    /// Components of different releases in one set.
    MixedVersionSet,
    /// The signed set as released: the positive control.
    SignedSet,
}

impl BoundaryCase {
    pub const ALL: [Self; 6] = [
        Self::RootImageByteChange,
        Self::UnsignedManifest,
        Self::ExpiredMetadata,
        Self::RolledBackVersion,
        Self::MixedVersionSet,
        Self::SignedSet,
    ];

    /// The `sandbox::probes` expectation this case observes.
    pub const fn expectation(self) -> &'static str {
        match self {
            Self::RootImageByteChange => "cp23.root-image-byte-change",
            Self::UnsignedManifest => "cp23.unsigned-manifest",
            Self::ExpiredMetadata => "cp23.expired-metadata",
            Self::RolledBackVersion => "cp23.rolled-back-version",
            Self::MixedVersionSet => "cp23.mixed-version-set",
            Self::SignedSet => "cp23.signed-set-launches",
        }
    }

    /// Whether `refusal` is the refusal this case tests. The control has none.
    pub fn refused_as_intended(self, refusal: &LaunchRefusal) -> bool {
        match (self, refusal) {
            (
                Self::RootImageByteChange,
                LaunchRefusal::Boot {
                    refusal: BootRefusal::Differs { role, .. },
                },
            ) => *role == ArtifactRole::RootImage,
            (
                Self::UnsignedManifest,
                LaunchRefusal::Verify {
                    refusal: VerifyRefusal::Unsigned,
                },
            ) => true,
            (
                Self::UnsignedManifest,
                LaunchRefusal::Verify {
                    refusal: VerifyRefusal::Signature { component },
                },
            ) => matches!(
                component.verification(),
                ComponentVerification::BadSignature { .. }
                    | ComponentVerification::UnknownPublisher {}
            ),
            (
                Self::ExpiredMetadata,
                LaunchRefusal::Select {
                    refusal: SelectionRefusal::Expired { .. },
                },
            )
            | (
                Self::RolledBackVersion,
                LaunchRefusal::Select {
                    refusal: SelectionRefusal::RolledBack { .. },
                },
            )
            | (
                Self::MixedVersionSet,
                LaunchRefusal::Select {
                    refusal: SelectionRefusal::PinMismatch { .. },
                },
            ) => true,
            (
                Self::MixedVersionSet,
                LaunchRefusal::Boot {
                    refusal: BootRefusal::Differs { role, .. },
                },
            ) => *role != ArtifactRole::RootImage,
            _ => false,
        }
    }

    /// The observation of one attempt, `None` when it was refused for another reason
    /// than the one this case tests.
    pub fn observe(self, refusal: Option<&LaunchRefusal>) -> Option<Observed> {
        match (self, refusal) {
            (_, None) => Some(Observed::Attempt { refused: false }),
            (Self::SignedSet, Some(_)) => Some(Observed::Attempt { refused: true }),
            (case, Some(refusal)) => case
                .refused_as_intended(refusal)
                .then_some(Observed::Attempt { refused: true }),
        }
    }
}

/// What the host observed about one boot and one boundary drill.
#[derive(Clone, Copy, Debug)]
pub struct BootEvidence<'a> {
    /// The signed manifest's expected values ([`SelectedImage::expectation`](super::SelectedImage::expectation)).
    pub expectation: &'a ManifestExpectation,
    /// The host's corroboration of the boot under test: for VM-CP-17, the next
    /// generation's boot.
    pub booted: Option<&'a HostCorroboration>,
    /// The io_uring control of the same run.
    pub kernel_control: Option<KernelControl>,
    /// The outcome of each VM-CP-23 attempt: `None` when it was admitted, the refusal
    /// otherwise.
    pub boundary: &'a BTreeMap<BoundaryCase, Option<LaunchRefusal>>,
}

fn put(observations: &mut Observations, name: &str, observed: Observed) {
    if let Some(id) = ExpectationId::named(name) {
        observations.insert(id, observed);
    }
}

fn root_image(observations: &mut Observations, name: &str, evidence: &BootEvidence<'_>) {
    if let Some(booted) = evidence.booted {
        put(
            observations,
            name,
            Observed::Comparison {
                observed: booted.root_image(),
                reference: evidence.expectation.root_image,
            },
        );
    }
}

/// The observations this module feeds for `part` of `check`, or `None` for a check or
/// part it does not feed.
pub fn observations(
    check: CheckId,
    part: Part,
    evidence: &BootEvidence<'_>,
) -> Option<Observations> {
    let mut observations = Observations::new();
    match (check.number(), part) {
        (
            5,
            Part::Corroboration {
                fact: CorroboratingFact::BootedRootImage,
            },
        ) => root_image(&mut observations, "cp05.booted-root-image", evidence),
        (
            5,
            Part::Corroboration {
                fact: CorroboratingFact::KernelBuildRecord,
            },
        ) => {
            if let Some(booted) = evidence.booted {
                put(
                    &mut observations,
                    "cp05.kernel-build-record",
                    Observed::Comparison {
                        observed: kernel_record_digest(booted.kernel()),
                        reference: kernel_record_digest(&evidence.expectation.kernel),
                    },
                );
            }
            if let Some(control) = evidence.kernel_control {
                put(
                    &mut observations,
                    "cp05.io-uring-image-fails-kernel-check",
                    Observed::Event {
                        happened: control.happened(),
                    },
                );
            }
        }
        (17, Part::Primary) => root_image(
            &mut observations,
            "cp17.next-generation-signed-base",
            evidence,
        ),
        (23, Part::Primary) => {
            for (case, refusal) in evidence.boundary {
                if let Some(observed) = case.observe(refusal.as_ref()) {
                    put(&mut observations, case.expectation(), observed);
                }
            }
        }
        _ => return None,
    }
    Some(observations)
}
