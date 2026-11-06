//! Guest images: the kernel, initrd, root image, firmware and profile of a release, each
//! admitted only as an artifact its signed feature manifest names by content key and
//! length (VM-W48, line 2671; VM-W05, line 2590: "signed artifacts from the first
//! release"; §8.3, line 2453: "verify signed artifact metadata before execution"; the Pi
//! session's `sandbox::guest_image`).
//!
//! The publisher signs one statement per release: `foundation::signing`'s content
//! statement about the feature manifest's canonical bytes as a `guest_image` artifact
//! ([`signing_statement`](crate::sandbox::guest_image::signing_statement)). The manifest
//! binds the build record by content key, and both bind every artifact by version,
//! content key and length, so the one signature covers the release. No artifact is signed
//! on its own, so the catalog's shared signed verifier, which authenticates a statement
//! about the object itself, would admit the manifest and never a kernel. The class
//! therefore has its own verifier, [`GuestImageVerifier`], registered as
//! `OfferedClass::Local`: it authenticates the release with
//! [`verify_release`](crate::sandbox::guest_image::verify_release) under the `guest_image`
//! keys of the trust roots in force (key, class, window and revocation), and then admits
//! the object only if it is the manifest, its build record, or an artifact the manifest
//! names with exactly this content key and length. No signature format or domain is new.
//!
//! [`GuestInstaller::install`] is the install path. It verifies the release first, then
//! reads every artifact the manifest lists from the caller's files once, streaming,
//! declaring its extents and refusing any file whose length or content key is not the
//! signed one (VM-W48's corrupted local file) before anything is published. Then it
//! publishes, in the host scope, each artifact, the build record and, last, the
//! manifest, so a published manifest marks an install whose artifacts were all
//! published. The catalog checks the claim again through [`GuestImageVerifier`] for every
//! object, and every byte against the declaration. As in V10's importer, a catalog
//! failure after the first object (quota, storage) can leave the earlier objects of the
//! release published; they are originals, which the collector keeps.
//!
//! **The attestation is never evidence.** A [`GuestReleaseAttestation`] is an unsigned
//! container: it carries the signed manifest, its build record and the signature to the
//! verifier, which checks the signature itself. The catalog records only the publisher of
//! an admitted object, never the attestation. The evidence of the signature is the CORE-08
//! `SignedComponent` that `verify_release` keeps (`VerifiedImage::component`), which names
//! the manifest's own content statement, and nothing records or shows the container as
//! signed.
//!
//! There is no structure check of kernel, initrd, root image or firmware binaries in the
//! tree: their identity is the signed content key and length, which the catalog checks
//! extent by extent at import, on every read and on re-verification. The manifest's
//! expiry, rollback floor and pinned row are judged at launch by `guest_image::select`,
//! not here: admission is identity, never permission to launch.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use super::publish::{publish, MemorySource, PublishFailure};
use crate::foundation::catalog::{
    ArtifactClass, ArtifactVerifier, Catalog, ContentDescriptor, ImportControl, ImportManifest,
    ImportRequest, ImportSource, ManifestBuilder, ObjectBytes, ObjectId, ObjectMetadata,
    ObjectRole, PublisherId, Scope, SourceIdentity, TrustClaim, VerifierRejection,
};
use crate::foundation::ids::{ContentKey, ExecutionId, OperationId};
use crate::foundation::signing::{SharedTrustRoots, TrustCalendar};
use crate::sandbox::guest_image::{
    verify_release, ArtifactRole, ManifestSignature, ProducedArtifact, VerifiedImage,
    VerifyRefusal, MANIFEST_CLASS, MAX_MANIFEST_BYTES, MAX_RECORD_BYTES,
};
use crate::sandbox::trust::{HexBytes, ProvenanceRefusal, UnixSeconds};

/// The format tag of a guest release attestation.
pub const GUEST_ATTESTATION_FORMAT: &str = "yougori.guest-image.release-attestation.v1";

/// Largest guest release attestation read: the largest manifest and build record in
/// hexadecimal, a signature and the JSON around them.
pub const MAX_GUEST_ATTESTATION_BYTES: usize = 2 * (MAX_MANIFEST_BYTES + MAX_RECORD_BYTES) + 4096;

/// Extent length of guest image objects in the catalog.
pub const GUEST_EXTENT_BYTES: NonZeroU64 = match NonZeroU64::new(4 << 20) {
    Some(bytes) => bytes,
    None => NonZeroU64::MIN,
};

/// The catalog source kind of a release's manifest and build record; the locator is
/// the content key.
pub const GUEST_SOURCE_KIND: &str = "guest-image-release";

/// Private label naming the image line.
pub const GUEST_IMAGE_LABEL: &str = "yougori.guest-image.image";
/// Private label naming the release number.
pub const GUEST_RELEASE_LABEL: &str = "yougori.guest-image.release";
/// Private label naming the part of the release an object is.
pub const GUEST_PART_LABEL: &str = "yougori.guest-image.part";

/// Which part of a release an object is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(tag = "part", rename_all = "snake_case")]
pub enum ReleasePart {
    /// The signed feature manifest itself.
    Manifest,
    /// The build record the manifest binds.
    BuildRecord,
    /// An artifact the manifest lists.
    Artifact { role: ArtifactRole },
}

impl ReleasePart {
    /// The stable tag written into the part label.
    pub fn tag(self) -> &'static str {
        match self {
            Self::Manifest => "manifest",
            Self::BuildRecord => "build_record",
            Self::Artifact { role } => role.tag(),
        }
    }
}

/// The release a claim stands on: the manifest's and build record's canonical bytes and
/// the publisher's signature over the manifest. The publisher is the catalog claim's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestReleaseAttestation {
    pub manifest: Vec<u8>,
    pub record: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireAttestation {
    format: String,
    manifest: HexBytes,
    record: HexBytes,
    signature: HexBytes,
}

/// Why the guest image verifier did not authenticate a claim.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
pub enum GuestAttestationRefusal {
    /// The object is of another class; guest image attestations admit `guest_image` only.
    WrongClass { class: ArtifactClass },
    /// The attestation is not a guest release attestation within the bound.
    Malformed { detail: String },
    /// The calendar time cannot be written as Unix seconds.
    TimeOutOfRange,
    /// The release does not verify under the trust roots in force as the claimed
    /// publisher's: unsigned, a key that may not vouch now, a bad signature, or a
    /// manifest and record that are malformed or not bound.
    Release { refusal: Box<VerifyRefusal> },
    /// The object is not the manifest, its build record or an artifact the manifest
    /// names with this content key and length.
    NotInRelease,
}

impl fmt::Display for GuestAttestationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongClass { class } => {
                write!(f, "a guest release attestation cannot admit a {class}")
            }
            Self::Malformed { detail } => {
                write!(f, "the guest release attestation is malformed: {detail}")
            }
            Self::TimeOutOfRange => f.write_str("the calendar time is before 1970"),
            Self::Release { refusal } => write!(f, "the release does not verify: {refusal}"),
            Self::NotInRelease => f.write_str(
                "the object is not the manifest, its build record or an artifact the manifest \
                 names with this content key and length",
            ),
        }
    }
}

impl std::error::Error for GuestAttestationRefusal {}

fn malformed(detail: impl fmt::Display) -> GuestAttestationRefusal {
    GuestAttestationRefusal::Malformed {
        detail: detail.to_string(),
    }
}

impl GuestReleaseAttestation {
    /// The wire form carried in a catalog trust claim: strict JSON with the bytes in
    /// hexadecimal.
    pub fn encode(&self) -> Vec<u8> {
        let wire = WireAttestation {
            format: GUEST_ATTESTATION_FORMAT.to_owned(),
            manifest: HexBytes::new(self.manifest.clone()),
            record: HexBytes::new(self.record.clone()),
            signature: HexBytes::new(self.signature.clone()),
        };
        // Strings and hexadecimal only: serialization cannot fail, and an empty claim
        // would be refused anyway.
        serde_json::to_vec(&wire).unwrap_or_default()
    }

    /// Parses the wire form, refusing more than [`MAX_GUEST_ATTESTATION_BYTES`], an
    /// unknown field and another format.
    pub fn decode(bytes: &[u8]) -> Result<Self, GuestAttestationRefusal> {
        if bytes.len() > MAX_GUEST_ATTESTATION_BYTES {
            return Err(malformed(format!(
                "{} bytes; at most {MAX_GUEST_ATTESTATION_BYTES}",
                bytes.len()
            )));
        }
        let wire: WireAttestation = serde_json::from_slice(bytes).map_err(malformed)?;
        if wire.format != GUEST_ATTESTATION_FORMAT {
            return Err(malformed("another attestation format"));
        }
        Ok(Self {
            manifest: wire.manifest.as_bytes().to_vec(),
            record: wire.record.as_bytes().to_vec(),
            signature: wire.signature.as_bytes().to_vec(),
        })
    }
}

/// The calendar's time as the trust client's Unix seconds; `None` before 1970.
pub(super) fn unix_now(calendar: &dyn TrustCalendar) -> Option<UnixSeconds> {
    u64::try_from(calendar.now().timestamp())
        .ok()
        .map(UnixSeconds::new)
}

fn len_u64(length: usize) -> u64 {
    u64::try_from(length).unwrap_or(u64::MAX)
}

/// The part of `image` that is `content_key` with `length_bytes`, if any.
fn part_of(
    image: &VerifiedImage,
    content_key: ContentKey,
    length_bytes: u64,
) -> Option<ReleasePart> {
    let manifest = image.manifest();
    let is =
        |key: ContentKey, bytes: &[u8]| key == content_key && len_u64(bytes.len()) == length_bytes;
    if is(manifest.content_key(), manifest.canonical_bytes()) {
        return Some(ReleasePart::Manifest);
    }
    if is(
        image.record().content_key(),
        image.record().canonical_bytes(),
    ) {
        return Some(ReleasePart::BuildRecord);
    }
    manifest
        .artifacts()
        .iter()
        .find(|(_, artifact)| {
            artifact.content_key == content_key && artifact.length_bytes == length_bytes
        })
        .map(|(role, _)| ReleasePart::Artifact { role: *role })
}

/// The catalog verifier of [`ArtifactClass::GuestImage`]: a signed release, then the
/// object's place in it. See the module documentation.
#[derive(Clone)]
pub struct GuestImageVerifier {
    roots: SharedTrustRoots,
    calendar: Arc<dyn TrustCalendar>,
}

impl fmt::Debug for GuestImageVerifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestImageVerifier").finish_non_exhaustive()
    }
}

impl GuestImageVerifier {
    /// A verifier judging releases under the roots in force in `roots` (a reload applies
    /// to the next check) at `calendar`'s time.
    pub fn new(roots: SharedTrustRoots, calendar: Arc<dyn TrustCalendar>) -> Self {
        Self { roots, calendar }
    }

    /// The release `attestation` carries, verified as `publisher`'s under the roots in
    /// force now, and the part of it `content` is; or the typed reason it is refused.
    pub fn check(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(VerifiedImage, ReleasePart), GuestAttestationRefusal> {
        if content.class != MANIFEST_CLASS {
            return Err(GuestAttestationRefusal::WrongClass {
                class: content.class,
            });
        }
        let claim = GuestReleaseAttestation::decode(attestation)?;
        let now =
            unix_now(self.calendar.as_ref()).ok_or(GuestAttestationRefusal::TimeOutOfRange)?;
        let signature = ManifestSignature {
            publisher: *publisher,
            signature: HexBytes::new(claim.signature),
        };
        let image = verify_release(
            &claim.manifest,
            &claim.record,
            &signature,
            &self.roots.current(),
            now,
        )
        .map_err(|refusal| GuestAttestationRefusal::Release {
            refusal: Box::new(refusal),
        })?;
        let part = part_of(&image, content.content_key, content.length_bytes)
            .ok_or(GuestAttestationRefusal::NotInRelease)?;
        Ok((image, part))
    }
}

impl ArtifactVerifier for GuestImageVerifier {
    fn class(&self) -> ArtifactClass {
        MANIFEST_CLASS
    }

    fn authenticate(
        &self,
        content: &ContentDescriptor,
        publisher: &PublisherId,
        attestation: &[u8],
    ) -> Result<(), VerifierRejection> {
        self.check(content, publisher, attestation)
            .map(drop)
            .map_err(|_| VerifierRejection::AttestationInvalid)
    }

    /// No structure check of guest binaries exists; the object must be of this class and
    /// as long as declared, and the catalog checks its bytes against the content key.
    fn validate(
        &self,
        content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        if content.class != MANIFEST_CLASS {
            return Err(VerifierRejection::WrongFormat {
                detail: format!("a {} is not a guest image object", content.class),
            });
        }
        if bytes.length_bytes() != content.length_bytes {
            return Err(VerifierRejection::CorruptStructure {
                detail: format!(
                    "{} bytes stored; {} declared",
                    bytes.length_bytes(),
                    content.length_bytes
                ),
            });
        }
        Ok(())
    }
}

/// A signed release as the install path receives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestRelease {
    /// The feature manifest's canonical bytes.
    pub manifest: Vec<u8>,
    /// The build record's canonical bytes.
    pub record: Vec<u8>,
    pub signature: ManifestSignature,
}

impl GuestRelease {
    /// The claim every object of this release is imported with.
    pub fn trust_claim(&self) -> TrustClaim {
        TrustClaim::Publisher {
            publisher: self.signature.publisher,
            attestation: GuestReleaseAttestation {
                manifest: self.manifest.clone(),
                record: self.record.clone(),
                signature: self.signature.signature.as_bytes().to_vec(),
            }
            .encode(),
        }
    }
}

/// Where the install reads each artifact's bytes, such as the bundled runtime directory.
pub trait ArtifactFiles {
    /// The source of the artifact `role`; `None` when there is none.
    fn source(&mut self, role: ArtifactRole) -> Option<&mut dyn ImportSource>;
}

impl<S: ImportSource> ArtifactFiles for BTreeMap<ArtifactRole, S> {
    fn source(&mut self, role: ArtifactRole) -> Option<&mut dyn ImportSource> {
        self.get_mut(&role)
            .map(|source| source as &mut dyn ImportSource)
    }
}

/// One install as its caller declares it.
#[derive(Clone, Debug)]
pub struct GuestInstall<'a> {
    pub operation: OperationId,
    /// The installing execution; it binds the catalog's records of the install.
    pub execution: ExecutionId,
    pub release: &'a GuestRelease,
}

/// Why an install was refused or stopped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuestInstallError {
    /// The calendar time cannot be written as Unix seconds.
    TimeOutOfRange,
    /// The release does not verify under the trust roots in force. Nothing was read or
    /// published.
    Release { refusal: Box<VerifyRefusal> },
    /// No file was given for an artifact the manifest lists. Nothing was published.
    MissingArtifact { role: ArtifactRole },
    /// The file's length is not the signed length. Nothing was published.
    LengthDiffers {
        role: ArtifactRole,
        expected_bytes: u64,
        found_bytes: u64,
    },
    /// The file's bytes are not the signed bytes (VM-W48's corrupted local file). Nothing
    /// was published.
    CorruptedLocalFile {
        role: ArtifactRole,
        refusal: ProvenanceRefusal,
    },
    /// The file could not be read to its end. Nothing was published.
    Unreadable { role: ArtifactRole, detail: String },
    /// The catalog did not publish this part; the parts before it may be published.
    Catalog {
        part: ReleasePart,
        failure: PublishFailure,
    },
}

impl fmt::Display for GuestInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TimeOutOfRange => f.write_str("the calendar time is before 1970"),
            Self::Release { refusal } => write!(f, "the release does not verify: {refusal}"),
            Self::MissingArtifact { role } => {
                write!(f, "no file was given for the manifest's {role}")
            }
            Self::LengthDiffers {
                role,
                expected_bytes,
                found_bytes,
            } => write!(
                f,
                "the {role} file is {found_bytes} bytes; the release signs {expected_bytes}"
            ),
            Self::CorruptedLocalFile { role, refusal } => write!(f, "the {role} file: {refusal}"),
            Self::Unreadable { role, detail } => {
                write!(f, "the {role} file could not be read: {detail}")
            }
            Self::Catalog { part, failure } => write!(f, "{}: {failure}", part.tag()),
        }
    }
}

impl std::error::Error for GuestInstallError {}

/// An installed release: what verified and where each part is in the host scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InstalledRelease {
    pub image: VerifiedImage,
    pub manifest: ObjectId,
    pub record: ObjectId,
    pub artifacts: BTreeMap<ArtifactRole, ObjectId>,
}

/// Reads `source` once and declares it in [`GUEST_EXTENT_BYTES`] extents, refusing a
/// length or content key other than the signed `artifact`'s.
fn declare(
    role: ArtifactRole,
    source: &mut dyn ImportSource,
    artifact: &ProducedArtifact,
) -> Result<ImportManifest, GuestInstallError> {
    let unreadable = |detail: String| GuestInstallError::Unreadable { role, detail };
    let found_bytes = source
        .length_bytes()
        .map_err(|error| unreadable(error.to_string()))?;
    if found_bytes != artifact.length_bytes {
        return Err(GuestInstallError::LengthDiffers {
            role,
            expected_bytes: artifact.length_bytes,
            found_bytes,
        });
    }
    let chunk = usize::try_from(GUEST_EXTENT_BYTES.get())
        .map_err(|_| unreadable("the extent does not fit in memory".to_owned()))?;
    let mut builder = ManifestBuilder::new(found_bytes, GUEST_EXTENT_BYTES);
    let mut buffer = vec![0u8; chunk];
    let mut offset_bytes = 0u64;
    while offset_bytes < found_bytes {
        let wanted = usize::try_from(found_bytes.saturating_sub(offset_bytes))
            .unwrap_or(usize::MAX)
            .min(chunk);
        let window = buffer.get_mut(..wanted).unwrap_or_default();
        let read = source
            .read_at(offset_bytes, window)
            .map_err(|error| unreadable(error.to_string()))?;
        let delivered = window.get(..read).unwrap_or_default();
        if delivered.is_empty() {
            return Err(unreadable(format!(
                "the file ended at {offset_bytes} of {found_bytes} bytes"
            )));
        }
        builder
            .update(delivered)
            .map_err(|error| unreadable(error.to_string()))?;
        offset_bytes = offset_bytes.saturating_add(len_u64(delivered.len()));
    }
    let manifest = builder
        .finish()
        .map_err(|error| unreadable(error.to_string()))?;
    if manifest.content_key != artifact.content_key {
        return Err(GuestInstallError::CorruptedLocalFile {
            role,
            refusal: ProvenanceRefusal::CorruptedLocalFile {
                expected: artifact.content_key,
                found: manifest.content_key,
            },
        });
    }
    Ok(manifest)
}

/// The install path of guest image releases, and the class verifier it shares its trust
/// roots and calendar with.
#[derive(Clone)]
pub struct GuestInstaller {
    roots: SharedTrustRoots,
    calendar: Arc<dyn TrustCalendar>,
}

impl fmt::Debug for GuestInstaller {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestInstaller").finish_non_exhaustive()
    }
}

impl GuestInstaller {
    /// An installer judging releases under the roots in force in `roots` at `calendar`'s
    /// time.
    pub fn new(roots: SharedTrustRoots, calendar: Arc<dyn TrustCalendar>) -> Self {
        Self { roots, calendar }
    }

    /// The catalog verifier for guest image objects, to register when the catalog opens.
    pub fn verifier(&self) -> GuestImageVerifier {
        GuestImageVerifier::new(self.roots.clone(), Arc::clone(&self.calendar))
    }

    /// Verifies `release` under the trust roots in force now.
    pub fn verify(&self, release: &GuestRelease) -> Result<VerifiedImage, GuestInstallError> {
        let now = unix_now(self.calendar.as_ref()).ok_or(GuestInstallError::TimeOutOfRange)?;
        verify_release(
            &release.manifest,
            &release.record,
            &release.signature,
            &self.roots.current(),
            now,
        )
        .map_err(|refusal| GuestInstallError::Release {
            refusal: Box::new(refusal),
        })
    }

    /// Installs `install.release` into `catalog`'s host scope, reading each artifact the
    /// manifest lists from `files`. See the module documentation for the order of checks.
    pub fn install(
        &self,
        catalog: &mut Catalog,
        install: GuestInstall<'_>,
        files: &mut dyn ArtifactFiles,
        control: &mut dyn ImportControl,
    ) -> Result<InstalledRelease, GuestInstallError> {
        let image = self.verify(install.release)?;
        let mut declared = BTreeMap::new();
        for (role, artifact) in image.manifest().artifacts() {
            let source = files
                .source(*role)
                .ok_or(GuestInstallError::MissingArtifact { role: *role })?;
            declared.insert(*role, declare(*role, source, artifact)?);
        }
        let trust = install.release.trust_claim();
        let metadata = |part: ReleasePart| {
            ObjectMetadata::new()
                .with_label(GUEST_IMAGE_LABEL, image.manifest().image().as_str())
                .with_label(GUEST_RELEASE_LABEL, image.manifest().release().to_string())
                .with_label(GUEST_PART_LABEL, part.tag())
        };
        let request = |part: ReleasePart, manifest: ImportManifest| ImportRequest {
            operation: install.operation.clone(),
            execution: install.execution.clone(),
            scope: Scope::Host,
            class: MANIFEST_CLASS,
            role: ObjectRole::Original,
            manifest,
            trust: trust.clone(),
            depends_on: BTreeSet::new(),
            metadata: metadata(part),
        };
        let mut artifacts = BTreeMap::new();
        for (role, manifest) in declared {
            let part = ReleasePart::Artifact { role };
            let source = files
                .source(role)
                .ok_or(GuestInstallError::MissingArtifact { role })?;
            let published = publish(catalog, request(part, manifest), source, control)
                .map_err(|failure| GuestInstallError::Catalog { part, failure })?;
            artifacts.insert(role, published.object);
        }
        let mut document = |part: ReleasePart, bytes: &[u8]| {
            let manifest = ImportManifest::describe(bytes, GUEST_EXTENT_BYTES);
            let mut source = MemorySource {
                identity: SourceIdentity::describe(
                    GUEST_SOURCE_KIND,
                    &manifest.content_key.to_string(),
                ),
                bytes,
            };
            publish(catalog, request(part, manifest), &mut source, control)
                .map(|published| published.object)
                .map_err(|failure| GuestInstallError::Catalog { part, failure })
        };
        let record = document(ReleasePart::BuildRecord, image.record().canonical_bytes())?;
        let manifest = document(ReleasePart::Manifest, image.manifest().canonical_bytes())?;
        Ok(InstalledRelease {
            image,
            manifest,
            record,
            artifacts,
        })
    }
}
