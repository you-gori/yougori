//! The launch boundary in one call (VM-P23, line 2798: "corrupted, unsigned, revoked,
//! expired, replayed and mixed-version components fail verification at the actual
//! execution boundary"; VM-CP-23, line 3173).
//!
//! [`admit_launch`] reads the time once from the shared clock and runs
//! [`verify_release`], [`select`] and [`SelectedImage::admit_boot`] in that order, so a
//! launch boots exactly one verified, selected image or gets the first refusal as a
//! [`LaunchRefusal`]. Each stage can also be called alone.
//!
//! [`SelectedImage::admit_boot`]: super::SelectedImage::admit_boot

use std::fmt;

use serde::Serialize;

use super::boot::{AdmittedBoot, BootRefusal, BootSet};
use super::select::{select, ReleaseFloor, Selection, SelectionRefusal};
use super::signed::{verify_release, ManifestSignature, VerifyRefusal};
use crate::foundation::signing::TrustRoots;
use crate::sandbox::trust::{PinnedConfiguration, TrustClock};
use crate::sandbox_contract::confinement::ConfinementProfile;

/// Everything one launch of a guest image is decided on.
#[derive(Clone, Copy, Debug)]
pub struct LaunchInputs<'a> {
    /// The feature manifest's canonical bytes.
    pub manifest: &'a [u8],
    /// The build record's canonical bytes.
    pub record: &'a [u8],
    pub signature: &'a ManifestSignature,
    /// The trust roots in force (`foundation::signing::SharedTrustRoots::current`).
    pub roots: &'a TrustRoots,
    pub row: &'a PinnedConfiguration,
    pub profile: &'a ConfinementProfile,
    pub floor: Option<&'a ReleaseFloor>,
    /// What the host is about to hand the hypervisor.
    pub boot: &'a BootSet,
}

/// Why a launch was refused at the boundary, by stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "stage", rename_all = "snake_case")]
pub enum LaunchRefusal {
    Verify { refusal: VerifyRefusal },
    Select { refusal: SelectionRefusal },
    Boot { refusal: BootRefusal },
}

impl fmt::Display for LaunchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Verify { refusal } => write!(f, "the release is not verified: {refusal}"),
            Self::Select { refusal } => write!(f, "the image is not selected: {refusal}"),
            Self::Boot { refusal } => write!(f, "the boot set is refused: {refusal}"),
        }
    }
}

impl std::error::Error for LaunchRefusal {}

/// Verifies, selects and admits one launch at the time `clock` reads now.
pub fn admit_launch(
    inputs: &LaunchInputs<'_>,
    clock: &TrustClock,
) -> Result<AdmittedBoot, LaunchRefusal> {
    let now = clock.now();
    let verified = verify_release(
        inputs.manifest,
        inputs.record,
        inputs.signature,
        inputs.roots,
        now,
    )
    .map_err(|refusal| LaunchRefusal::Verify { refusal })?;
    let selected = select(
        verified,
        Selection {
            row: inputs.row,
            profile: inputs.profile,
            floor: inputs.floor,
            now,
        },
    )
    .map_err(|refusal| LaunchRefusal::Select { refusal })?;
    selected
        .admit_boot(inputs.boot)
        .map_err(|refusal| LaunchRefusal::Boot { refusal })
}
