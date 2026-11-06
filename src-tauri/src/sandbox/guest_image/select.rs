//! Selecting the one image a launch boots (leftover entry M01: "Boot the selected image
//! rather than accepting an arbitrary declared image"; VM-W46, line 2669: pinned
//! configurations per OS, architecture and backend, "unsupported devices are absent";
//! §8.3, line 2455: expiry and rollback protection; VM-P23, line 2798: "expired,
//! replayed and mixed-version components fail verification").
//!
//! [`select`] turns a [`VerifiedImage`] into the [`SelectedImage`] of one launch, or a
//! typed [`SelectionRefusal`], in this order:
//!
//! 1. the manifest has not expired at the given time;
//! 2. its release is not older than the release floor the host keeps for the image
//!    line ([`ReleaseFloor`]), and an equal release is the same manifest;
//! 3. the `sandbox::trust` pinned configuration row is valid, for the manifest's
//!    architecture and boot method, and pins the guest kernel, the guest image, (for
//!    firmware boot) the firmware, and the initrd and the profile when the manifest
//!    names them, each at exactly the manifest's version, content key, length and build
//!    inputs ([`BuildRecord::build_inputs`]); the row pins nothing the manifest does not
//!    list, and offers every device the image expects. A row written before
//!    `sandbox::trust` had initrd and profile kinds pins neither, so it selects only a
//!    release that ships neither;
//! 4. the image's agent speaks this host's link protocol (`sandbox::link::PROTOCOL_VERSION`);
//! 5. the image installs the launch's confinement profile, by its V15 digest, and the
//!    kernel's build record meets that profile's kernel requirements.
//!
//! The selection names one manifest, one row and one profile. A launch request then
//! names exactly its root image and the row's configuration fingerprint
//! ([`SelectedImage::check_request`]), and the boot set handed to the hypervisor is
//! exactly its artifacts ([`SelectedImage::admit_boot`]); anything else is refused.
//! After a launch the host keeps [`SelectedImage::floor`] as the line's new floor.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::kernel::{KernelRequirementFailure, KernelRequirements};
use super::manifest::ReleaseNumber;
use super::record::{ArtifactRole, BuildRecord};
use super::signed::VerifiedImage;
use super::text::ImageName;
use crate::foundation::evidence::ConfigurationFingerprint;
use crate::foundation::ids::{ContentKey, Digest};
use crate::foundation::signing::{RootKeyId, SignedComponent};
use crate::sandbox::backend::LaunchRequest;
use crate::sandbox::link::PROTOCOL_VERSION;
use crate::sandbox::trust::{
    Architecture, BootMethod, ComponentKind, ConfigurationKey, DeviceModel, PinRefusal,
    PinnedConfiguration, UnixSeconds,
};
use crate::sandbox_contract::confinement::{
    ConfinementProfile, ManifestExpectation, WorkloadProfile,
};

/// The newest release of one image line a host has admitted, kept by the host between
/// launches. A manifest of an older release is refused; one of the same release must be
/// the same manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFloor {
    pub image: ImageName,
    pub release: ReleaseNumber,
    pub manifest: ContentKey,
}

/// What one selection is made against.
#[derive(Clone, Copy, Debug)]
pub struct Selection<'a> {
    /// The pinned configuration row for this host's OS, architecture and backend.
    pub row: &'a PinnedConfiguration,
    /// The confinement profile of the launch's workload.
    pub profile: &'a ConfinementProfile,
    /// The host's floor for the image line, if it admitted a release of it before.
    pub floor: Option<&'a ReleaseFloor>,
    /// The time, from the shared clock through `sandbox::trust::TrustClock`.
    pub now: UnixSeconds,
}

/// Which part of a pin disagrees with the manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PinField {
    Version,
    ContentKey,
    Length,
    BuildInputs,
}

impl PinField {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::ContentKey => "content key",
            Self::Length => "length",
            Self::BuildInputs => "build inputs",
        }
    }
}

/// Why a verified image was not selected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SelectionRefusal {
    /// The manifest expired.
    Expired {
        expires_at: UnixSeconds,
        now: UnixSeconds,
    },
    /// The floor given is for another image line.
    FloorOfOtherImage { floor: ImageName, image: ImageName },
    /// The release is older than one the host already admitted.
    RolledBack {
        release: ReleaseNumber,
        floor: ReleaseNumber,
    },
    /// The release number the host admitted names another manifest.
    ReleaseReused {
        release: ReleaseNumber,
        admitted: ContentKey,
        presented: ContentKey,
    },
    /// The pinned row is not a valid row.
    Row { refusal: PinRefusal },
    ArchitectureDiffers {
        row: Architecture,
        manifest: Architecture,
    },
    BootMethodDiffers {
        row: BootMethod,
        manifest: BootMethod,
    },
    /// The row pins a component of this release differently.
    PinMismatch {
        component: ComponentKind,
        field: PinField,
    },
    /// The row does not pin a component the release has: the initrd or the profile the
    /// manifest names. For the kernel, the root image and the firmware this does not
    /// happen with a row that `PinnedConfiguration::check` accepts for the release's boot
    /// method; the check is kept so that no listed component is ever skipped.
    NotPinned { component: ComponentKind },
    /// The row pins a component the release does not have: an initrd or a profile the
    /// manifest does not name (for the other guest components, as unreachable as
    /// [`Self::NotPinned`] with a valid row, and kept for the same reason).
    PinnedNotInRelease { component: ComponentKind },
    /// The image expects a device the row does not offer.
    DeviceAbsent { device: DeviceModel },
    /// The image's agent speaks another link protocol than this host.
    LinkProtocol { image: u8, host: u8 },
    /// The image does not install this confinement profile.
    ProfileNotInstalled {
        workload: WorkloadProfile,
        profile: Digest,
    },
    /// The kernel's build record does not meet the profile's kernel requirements.
    KernelRequirement { failure: KernelRequirementFailure },
    /// The row's configuration fingerprint cannot be computed.
    Fingerprint { detail: String },
}

impl fmt::Display for SelectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Expired { expires_at, now } => {
                write!(f, "the manifest expired at {expires_at}; it is {now}")
            }
            Self::FloorOfOtherImage { floor, image } => {
                write!(f, "the release floor is for image {floor}, not {image}")
            }
            Self::RolledBack { release, floor } => write!(
                f,
                "release {release} is older than release {floor}, which this host admitted"
            ),
            Self::ReleaseReused {
                release,
                admitted,
                presented,
            } => write!(
                f,
                "release {release} was admitted as manifest {admitted}, not {presented}"
            ),
            Self::Row { refusal } => write!(f, "the pinned configuration is refused: {refusal}"),
            Self::ArchitectureDiffers { row, manifest } => write!(
                f,
                "the configuration is pinned for {row} and the image is for {manifest}"
            ),
            Self::BootMethodDiffers { row, manifest } => write!(
                f,
                "the configuration boots by {} and the image by {}",
                row.tag(),
                manifest.tag()
            ),
            Self::PinMismatch { component, field } => write!(
                f,
                "the configuration pins another {component} {} than the release",
                field.tag()
            ),
            Self::NotPinned { component } => {
                write!(f, "the configuration pins no {component} for the release")
            }
            Self::PinnedNotInRelease { component } => write!(
                f,
                "the configuration pins a {component} the release does not have"
            ),
            Self::DeviceAbsent { device } => write!(
                f,
                "the image expects {}, which the configuration does not offer",
                device.tag()
            ),
            Self::LinkProtocol { image, host } => write!(
                f,
                "the image's agent speaks link protocol {image}; this host speaks {host}"
            ),
            Self::ProfileNotInstalled { workload, profile } => write!(
                f,
                "the image does not install the {} profile {profile}",
                workload.label()
            ),
            Self::KernelRequirement { failure } => write!(f, "{failure}"),
            Self::Fingerprint { detail } => {
                write!(f, "the configuration has no fingerprint: {detail}")
            }
        }
    }
}

impl std::error::Error for SelectionRefusal {}

/// Why a launch request does not name the selected image.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "mismatch", rename_all = "snake_case")]
pub enum RequestMismatch {
    GuestImage {
        requested: Digest,
        selected: Digest,
    },
    Configuration {
        requested: ConfigurationFingerprint,
        selected: ConfigurationFingerprint,
    },
}

impl fmt::Display for RequestMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GuestImage {
                requested,
                selected,
            } => write!(
                f,
                "the launch request names guest image {requested}; the selected image is \
                 {selected}"
            ),
            Self::Configuration { .. } => f.write_str(
                "the launch request names another configuration than the selected image's row",
            ),
        }
    }
}

impl std::error::Error for RequestMismatch {}

/// The image one launch boots. Built only by [`select`]; Serialize only, as the launch's
/// record of what was selected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SelectedImage {
    #[serde(skip)]
    verified: VerifiedImage,
    image: ImageName,
    release: ReleaseNumber,
    manifest: ContentKey,
    build_record: ContentKey,
    root_image: Digest,
    configuration: ConfigurationKey,
    fingerprint: ConfigurationFingerprint,
    workload: WorkloadProfile,
    confinement_profile: Digest,
    signed: SignedComponent,
    selected_at: UnixSeconds,
}

impl SelectedImage {
    pub fn verified(&self) -> &VerifiedImage {
        &self.verified
    }

    pub fn image(&self) -> &ImageName {
        &self.image
    }

    pub fn release(&self) -> ReleaseNumber {
        self.release
    }

    /// The manifest's content key.
    pub fn manifest(&self) -> ContentKey {
        self.manifest
    }

    pub fn record(&self) -> &BuildRecord {
        self.verified.record()
    }

    /// The root image's identity, the value a launch request pins.
    pub fn root_image(&self) -> Digest {
        self.root_image
    }

    pub fn configuration(&self) -> ConfigurationKey {
        self.configuration
    }

    /// The pinned row's CORE-01 configuration fingerprint.
    pub fn fingerprint(&self) -> ConfigurationFingerprint {
        self.fingerprint
    }

    pub fn workload(&self) -> WorkloadProfile {
        self.workload
    }

    /// The trust-root key that vouched for the manifest.
    pub fn key(&self) -> &RootKeyId {
        self.verified.key()
    }

    /// The signed manifest's expected values for VM-CP-05's evaluator.
    pub fn expectation(&self) -> ManifestExpectation {
        self.verified.manifest().expectation()
    }

    /// The floor the host keeps for the image line once this image launched.
    pub fn floor(&self) -> ReleaseFloor {
        ReleaseFloor {
            image: self.image.clone(),
            release: self.release,
            manifest: self.manifest,
        }
    }

    /// Whether `request` names exactly this image's root image and its row's
    /// configuration.
    pub fn check_request(&self, request: &LaunchRequest) -> Result<(), RequestMismatch> {
        if request.pinned.guest_image != self.root_image {
            return Err(RequestMismatch::GuestImage {
                requested: request.pinned.guest_image,
                selected: self.root_image,
            });
        }
        if request.configuration != self.fingerprint {
            return Err(RequestMismatch::Configuration {
                requested: request.configuration,
                selected: self.fingerprint,
            });
        }
        Ok(())
    }
}

fn check_floor(
    image: &VerifiedImage,
    floor: Option<&ReleaseFloor>,
) -> Result<(), SelectionRefusal> {
    let Some(floor) = floor else {
        return Ok(());
    };
    let manifest = image.manifest();
    if &floor.image != manifest.image() {
        return Err(SelectionRefusal::FloorOfOtherImage {
            floor: floor.image.clone(),
            image: manifest.image().clone(),
        });
    }
    if manifest.release() < floor.release {
        return Err(SelectionRefusal::RolledBack {
            release: manifest.release(),
            floor: floor.release,
        });
    }
    if manifest.release() == floor.release && manifest.content_key() != floor.manifest {
        return Err(SelectionRefusal::ReleaseReused {
            release: manifest.release(),
            admitted: floor.manifest,
            presented: manifest.content_key(),
        });
    }
    Ok(())
}

fn check_row(image: &VerifiedImage, row: &PinnedConfiguration) -> Result<(), SelectionRefusal> {
    row.check()
        .map_err(|refusal| SelectionRefusal::Row { refusal })?;
    let manifest = image.manifest().document();
    if row.key.architecture != manifest.architecture {
        return Err(SelectionRefusal::ArchitectureDiffers {
            row: row.key.architecture,
            manifest: manifest.architecture,
        });
    }
    if row.boot != manifest.boot {
        return Err(SelectionRefusal::BootMethodDiffers {
            row: row.boot,
            manifest: manifest.boot,
        });
    }
    let inputs = image.record().build_inputs();
    for role in ArtifactRole::ALL {
        let component = role.pinned_kind();
        match (manifest.artifacts.get(&role), row.component(component)) {
            (None, None) => {}
            (Some(_), None) => return Err(SelectionRefusal::NotPinned { component }),
            (None, Some(_)) => return Err(SelectionRefusal::PinnedNotInRelease { component }),
            (Some(artifact), Some(pin)) => {
                let field = if pin.version != artifact.version {
                    Some(PinField::Version)
                } else if pin.content_key != artifact.content_key {
                    Some(PinField::ContentKey)
                } else if pin.length_bytes != artifact.length_bytes {
                    Some(PinField::Length)
                } else if pin.build != inputs {
                    Some(PinField::BuildInputs)
                } else {
                    None
                };
                if let Some(field) = field {
                    return Err(SelectionRefusal::PinMismatch { component, field });
                }
            }
        }
    }
    if let Some(device) = manifest
        .devices
        .iter()
        .find(|device| !row.devices.contains(device))
    {
        return Err(SelectionRefusal::DeviceAbsent { device: *device });
    }
    Ok(())
}

/// Selects `image` for one launch against `selection`, in the order the module
/// documentation gives.
pub fn select(
    image: VerifiedImage,
    selection: Selection<'_>,
) -> Result<SelectedImage, SelectionRefusal> {
    let manifest = image.manifest();
    let expires_at = manifest.document().expires_at;
    if expires_at.is_expired_at(selection.now) {
        return Err(SelectionRefusal::Expired {
            expires_at,
            now: selection.now,
        });
    }
    check_floor(&image, selection.floor)?;
    check_row(&image, selection.row)?;
    let link_protocol = manifest.agent().link_protocol;
    if link_protocol != PROTOCOL_VERSION {
        return Err(SelectionRefusal::LinkProtocol {
            image: link_protocol,
            host: PROTOCOL_VERSION,
        });
    }
    let profile = selection.profile;
    let workload = profile.workload();
    let installed = manifest
        .workload(workload)
        .is_some_and(|feature| feature.confinement_profile == profile.digest());
    if !installed {
        return Err(SelectionRefusal::ProfileNotInstalled {
            workload,
            profile: profile.digest(),
        });
    }
    KernelRequirements::of_profile(profile)
        .check(manifest.kernel())
        .map_err(|failure| SelectionRefusal::KernelRequirement { failure })?;
    let fingerprint =
        selection
            .row
            .fingerprint()
            .map_err(|error| SelectionRefusal::Fingerprint {
                detail: error.to_string(),
            })?;
    Ok(SelectedImage {
        image: manifest.image().clone(),
        release: manifest.release(),
        manifest: manifest.content_key(),
        build_record: image.record().content_key(),
        root_image: manifest.root_image(),
        configuration: selection.row.key,
        fingerprint,
        workload,
        confinement_profile: profile.digest(),
        signed: image.component().clone(),
        selected_at: selection.now,
        verified: image,
    })
}
