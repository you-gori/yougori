//! Admission of helper bundles through the catalog under their own artifact class, with
//! trust from the configured trust roots (GPU-W11, line 1321; S2 CORE-08, line 217:
//! "signed component identity ... An unauthenticated checksum is not a release trust
//! root"; VM-W45, line 2668: "Do not create a parallel model-helper updater").
//!
//! A bundle is one catalog object of class [`ArtifactClass::ModelHelper`] in the host
//! scope. Its publisher signs the CORE-08 content statement of the encoded bundle
//! ([`bundle_statement`]); the class's responsible verifier is the shared
//! [`SignedArtifactVerifier`] over the trust roots in force ([`helper_verifier`]), its
//! policy is [`TrustRoots::policy_for`] the class ([`helper_policy`]), and its structure
//! check decodes the bundle and every file against its manifest
//! ([`HelperBundleStructure`]). Nothing here verifies a signature itself.
//!
//! [`HelperAdmission::admit`] refuses, each with a typed reason and before anything is
//! published: a malformed bundle, a file that differs from its pinned digest, an ABI this
//! host's loader does not provide, an unsigned bundle (the catalog's own refusal of a
//! checksum), and a signature an unknown, revoked, expired or wrong-class key made or
//! that does not verify. Whatever a key admitted is quarantined by the catalog once the
//! owner revokes the key and the class policy is set from the reloaded roots;
//! [`HelperAdmission::check_pin`] and [`HelperAdmission::open`] then refuse it with the
//! catalog's reason.

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::Arc;
use std::time::Duration;

use super::abi::{HelperAbiRefusal, HostHelperAbi};
use super::bundle::{BundleError, HelperBundle, MAX_BUNDLE_BYTES};
use super::identity::{HelperPin, PinAdmissibility, PinRefusal};
use super::manifest::{HelperManifest, HelperPath};
use crate::foundation::catalog::{
    ArtifactClass, Catalog, ContentDescriptor, FailureRecord, ImportControl, ImportError,
    ImportManifest, ImportRefusal, ImportRequest, ImportSource, ImportStart, ImportStatus,
    IntegrityFailure, ObjectBytes, ObjectId, ObjectMetadata, ObjectRole, ObjectStatus, PublisherId,
    ReadError, ReadRefusal, Scope, SourceError, SourceIdentity, TrustClaim, TrustPolicy,
    TrustRefusal, VerifierRejection,
};
use crate::foundation::ids::{ContentKey, Digest, ExecutionId, OperationId};
use crate::foundation::signing::{
    content_statement, KeyRefusal, RootKeyId, SharedTrustRoots, SignedArtifactVerifier,
    StatementBinding, StructureValidator, TrustCalendar, TrustRoots,
};

/// The artifact class of helper bundles.
pub const HELPER_CLASS: ArtifactClass = ArtifactClass::ModelHelper;

/// Extent size of a helper bundle in the catalog.
pub const HELPER_EXTENT_BYTES: NonZeroU64 = match NonZeroU64::new(1 << 20) {
    Some(bytes) => bytes,
    None => NonZeroU64::MIN,
};

/// The catalog source kind of a helper bundle; its locator is the content key.
pub const HELPER_SOURCE_KIND: &str = "model-helper-bundle";

/// Private label holding the helper id.
pub const HELPER_LABEL: &str = "yougori.model-memory.helper";

/// Private label holding the helper version.
pub const HELPER_VERSION_LABEL: &str = "yougori.model-memory.helper-version";

/// What a helper publisher signs for an encoded bundle: the CORE-08 content statement of
/// its bytes as a [`HELPER_CLASS`] artifact.
pub fn bundle_statement(publisher: &PublisherId, bundle: &[u8]) -> Digest {
    content_statement(
        publisher,
        HELPER_CLASS,
        &ContentKey::of(bundle),
        u64::try_from(bundle.len()).unwrap_or(u64::MAX),
    )
}

/// The catalog trust policy of helper bundles from the trust roots: every non-revoked
/// key allowed to sign `model_helper`.
pub fn helper_policy(roots: &TrustRoots) -> TrustPolicy {
    roots.policy_for(HELPER_CLASS)
}

/// The responsible catalog verifier of [`HELPER_CLASS`]: Ed25519 over the content
/// statement under the roots in force, then [`HelperBundleStructure`].
pub fn helper_verifier(
    roots: SharedTrustRoots,
    calendar: Arc<dyn TrustCalendar>,
) -> SignedArtifactVerifier {
    SignedArtifactVerifier::new(
        HELPER_CLASS,
        StatementBinding::Content,
        roots,
        calendar,
        Box::new(HelperBundleStructure),
    )
}

/// The structure check of a helper bundle before commit: it decodes, and every file
/// matches its manifest.
#[derive(Clone, Copy, Debug, Default)]
pub struct HelperBundleStructure;

impl StructureValidator for HelperBundleStructure {
    fn validate(
        &self,
        _content: &ContentDescriptor,
        bytes: &mut ObjectBytes,
    ) -> Result<(), VerifierRejection> {
        let length_bytes = bytes.length_bytes();
        if length_bytes > MAX_BUNDLE_BYTES {
            return Err(VerifierRejection::CorruptStructure {
                detail: format!("{length_bytes} bytes exceed the helper bundle bound"),
            });
        }
        let length = usize::try_from(length_bytes).map_err(|_| VerifierRejection::Unreadable {
            detail: "the helper bundle does not fit in memory".to_owned(),
        })?;
        let mut bundle = vec![0u8; length];
        bytes
            .read_exact_at(0, &mut bundle)
            .map_err(|error| VerifierRejection::Unreadable {
                detail: error.to_string(),
            })?;
        HelperBundle::decode(&bundle).map(drop).map_err(|error| {
            VerifierRejection::CorruptStructure {
                detail: error.to_string(),
            }
        })
    }
}

/// A publisher's signature over [`bundle_statement`].
#[derive(Clone, PartialEq, Eq)]
pub struct HelperSignature {
    pub publisher: PublisherId,
    pub signature: Vec<u8>,
}

impl fmt::Debug for HelperSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelperSignature")
            .field("publisher", &self.publisher)
            .finish_non_exhaustive()
    }
}

/// A bundle offered for admission.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HelperOffer {
    /// The encoded bundle.
    pub bundle: Vec<u8>,
    /// `None` offers only the bytes, which the catalog refuses: a checksum is not trust.
    pub signature: Option<HelperSignature>,
    /// Correlates the import's records (CORE-06).
    pub operation: OperationId,
    /// The execution importing.
    pub execution: ExecutionId,
}

/// An admitted helper version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AdmittedHelper {
    pub pin: HelperPin,
    /// The trust-root key that vouched for it.
    pub key: RootKeyId,
    pub manifest: HelperManifest,
    /// `false` when the same bundle was already published; the trust claim was checked
    /// again either way.
    pub newly_published: bool,
}

/// Why a helper bundle was not admitted or opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HelperRefusal {
    /// Not a well-formed helper bundle.
    Malformed { error: BundleError },
    /// A file's bytes differ from the content key its manifest pins.
    Tampered {
        path: HelperPath,
        expected: ContentKey,
        found: ContentKey,
    },
    /// This host's loader does not provide the helper's ABI.
    IncompatibleAbi { refusal: HelperAbiRefusal },
    /// No publisher signature: the catalog refuses a checksum as trust.
    Unsigned,
    /// No key of the trust roots in force vouches for the bundle: unknown publisher,
    /// revoked or expired key, a key not allowed to sign helpers, or a bad signature.
    Signature { refusal: KeyRefusal },
    /// The catalog refused the import: its class policy, the scope's quota or storage.
    Catalog { refusal: ImportRefusal },
    /// The import ended without publishing.
    ImportFailed { failure: Box<FailureRecord> },
    /// The import was used wrongly; nothing was published.
    ImportMisuse { error: ImportError },
    /// The import was interrupted by its control, or paused after repeated source
    /// failures; its verified extents stay staged for a resume, and nothing was published.
    Interrupted,
    /// The catalog quarantined the bundle; it is kept and never served.
    Quarantined { reason: IntegrityFailure },
    /// No such helper is published in the host scope.
    NotPublished,
    /// The catalog refused the read.
    Read { refusal: ReadRefusal },
    /// The read failed verification or storage.
    ReadFailed { error: ReadError },
    /// What the object holds is not what the pin names.
    PinMismatch,
}

impl fmt::Display for HelperRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { error } => error.fmt(f),
            Self::Tampered { path, .. } => write!(
                f,
                "helper file {path} differs from the digest its manifest pins"
            ),
            Self::IncompatibleAbi { refusal } => refusal.fmt(f),
            Self::Unsigned => f.write_str(
                "the helper bundle is unsigned; a checksum establishes integrity, not trust",
            ),
            Self::Signature { refusal } => refusal.fmt(f),
            Self::Catalog { refusal } => refusal.fmt(f),
            Self::ImportFailed { failure } => {
                write!(f, "the helper import failed: {}", failure.reason.code())
            }
            Self::ImportMisuse { error } => error.fmt(f),
            Self::Interrupted => f.write_str("the helper import was interrupted"),
            Self::Quarantined { .. } => f.write_str("the helper bundle is quarantined"),
            Self::NotPublished => f.write_str("the helper bundle is not published"),
            Self::Read { refusal } => refusal.fmt(f),
            Self::ReadFailed { error } => error.fmt(f),
            Self::PinMismatch => f.write_str("the helper bundle is not the pinned version"),
        }
    }
}

impl std::error::Error for HelperRefusal {}

impl From<BundleError> for HelperRefusal {
    fn from(error: BundleError) -> Self {
        match error {
            BundleError::FileDigestMismatch {
                path,
                expected,
                found,
            } => Self::Tampered {
                path,
                expected,
                found,
            },
            error => Self::Malformed { error },
        }
    }
}

impl From<PinRefusal> for HelperRefusal {
    fn from(refusal: PinRefusal) -> Self {
        match refusal {
            PinRefusal::Quarantined { reason } => Self::Quarantined { reason },
            PinRefusal::NotPublished => Self::NotPublished,
            PinRefusal::Inconsistent => Self::PinMismatch,
            PinRefusal::IncompatibleAbi { refusal } => Self::IncompatibleAbi { refusal },
        }
    }
}

/// The bundle bytes as the catalog's import source.
struct BundleSource<'a> {
    identity: SourceIdentity,
    bytes: &'a [u8],
}

impl ImportSource for BundleSource<'_> {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(u64::try_from(self.bytes.len()).unwrap_or(u64::MAX))
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes)
            .unwrap_or(usize::MAX)
            .min(self.bytes.len());
        let available = self.bytes.get(start..).unwrap_or_default();
        let count = available.len().min(buffer.len());
        if let (Some(target), Some(source)) = (buffer.get_mut(..count), available.get(..count)) {
            target.copy_from_slice(source);
        }
        Ok(count)
    }
}

/// Admits helper bundles into the catalog and opens pinned ones for this host's loader.
pub struct HelperAdmission {
    host_abi: HostHelperAbi,
    verifier: SignedArtifactVerifier,
}

impl fmt::Debug for HelperAdmission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelperAdmission")
            .field("host_abi", &self.host_abi)
            .finish_non_exhaustive()
    }
}

impl HelperAdmission {
    /// Admission for a loader providing `host_abi`, judging signatures under `roots` and
    /// `calendar`: the same values the catalog's [`helper_verifier`] was built with.
    pub fn new(
        host_abi: HostHelperAbi,
        roots: SharedTrustRoots,
        calendar: Arc<dyn TrustCalendar>,
    ) -> Self {
        Self {
            host_abi,
            verifier: helper_verifier(roots, calendar),
        }
    }

    pub fn host_abi(&self) -> &HostHelperAbi {
        &self.host_abi
    }

    /// Admits `offer` through the catalog, or refuses it with a typed reason before
    /// anything is published. The catalog runs its own trust and structure checks again.
    pub fn admit(
        &self,
        catalog: &mut Catalog,
        offer: HelperOffer,
        control: &mut dyn ImportControl,
    ) -> Result<AdmittedHelper, HelperRefusal> {
        let HelperOffer {
            bundle: bytes,
            signature,
            operation,
            execution,
        } = offer;
        let manifest = HelperBundle::decode(&bytes)?.manifest().clone();
        self.host_abi
            .check(manifest.abi())
            .map_err(|refusal| HelperRefusal::IncompatibleAbi { refusal })?;
        let described = ImportManifest::describe(&bytes, HELPER_EXTENT_BYTES);
        let content = ContentDescriptor {
            scope: Scope::Host,
            class: HELPER_CLASS,
            content_key: described.content_key,
            length_bytes: described.true_length_bytes,
            manifest_digest: described.digest(),
        };
        let (trust, signed) = match signature {
            None => (TrustClaim::ChecksumOnly, None),
            Some(HelperSignature {
                publisher,
                signature,
            }) => {
                let key = self
                    .verifier
                    .check(&content, &publisher, &signature)
                    .map_err(|refusal| HelperRefusal::Signature { refusal })?;
                let claim = TrustClaim::Publisher {
                    publisher,
                    attestation: signature,
                };
                (claim, Some((publisher, key)))
            }
        };
        let request = ImportRequest {
            operation,
            execution,
            scope: Scope::Host,
            class: HELPER_CLASS,
            role: ObjectRole::Original,
            manifest: described.clone(),
            trust,
            depends_on: BTreeSet::new(),
            metadata: ObjectMetadata::new()
                .with_label(HELPER_LABEL, manifest.helper().as_str())
                .with_label(HELPER_VERSION_LABEL, manifest.version().to_string()),
        };
        let mut source = BundleSource {
            identity: SourceIdentity::describe(
                HELPER_SOURCE_KIND,
                &described.content_key.to_string(),
            ),
            bytes: &bytes,
        };
        let start = catalog
            .begin_import(request, source.identity())
            .map_err(|refusal| match refusal {
                ImportRefusal::Trust {
                    refusal: TrustRefusal::ChecksumIsNotTrust { .. },
                } => HelperRefusal::Unsigned,
                refusal => HelperRefusal::Catalog { refusal },
            })?;
        let Some((publisher, key)) = signed else {
            // The catalog refuses a checksum for every class; were it ever to accept one,
            // nothing unsigned is published from here.
            if let ImportStart::Started(ticket) | ImportStart::Attached(ticket) = start {
                catalog.cancel_import(ticket);
            }
            return Err(HelperRefusal::Unsigned);
        };
        let (object, newly_published) = match start {
            ImportStart::AlreadyPublished(object) => (object, false),
            ImportStart::Started(ticket) | ImportStart::Attached(ticket) => {
                let status = catalog.drive_import(&ticket, &mut source, control);
                // Detach: a finished import's status is not kept for this ticket, and an
                // unfinished one keeps its verified extents staged for a resume.
                catalog.cancel_import(ticket);
                match status.map_err(|error| HelperRefusal::ImportMisuse { error })? {
                    ImportStatus::Published { object, .. } => (object, true),
                    ImportStatus::Failed { failure } => {
                        return Err(HelperRefusal::ImportFailed {
                            failure: Box::new(failure),
                        })
                    }
                    ImportStatus::Pending { .. } => return Err(HelperRefusal::Interrupted),
                }
            }
        };
        let pin = HelperPin {
            helper: manifest.helper().clone(),
            version: manifest.version(),
            abi: manifest.abi(),
            runners: manifest.runners().iter().cloned().collect(),
            object,
            bundle: described.content_key,
            length_bytes: described.true_length_bytes,
            publisher,
        };
        if object != ObjectId::new(&Scope::Host, HELPER_CLASS, pin.bundle) {
            return Err(HelperRefusal::PinMismatch);
        }
        Ok(AdmittedHelper {
            pin,
            key,
            manifest,
            newly_published,
        })
    }

    /// Whether a new runner may load `pin` now: its bundle is a published, unquarantined
    /// host helper and this host's loader provides its ABI. The bytes are checked again
    /// when it is opened.
    pub fn check_pin(&self, catalog: &Catalog, pin: &HelperPin) -> Result<(), PinRefusal> {
        if pin.object != ObjectId::new(&Scope::Host, HELPER_CLASS, pin.bundle) {
            return Err(PinRefusal::Inconsistent);
        }
        match catalog.status(&Scope::Host, pin.object) {
            ObjectStatus::Published => {}
            ObjectStatus::Quarantined { reason } => return Err(PinRefusal::Quarantined { reason }),
            ObjectStatus::Absent => return Err(PinRefusal::NotPublished),
        }
        self.host_abi
            .check(pin.abi)
            .map_err(|refusal| PinRefusal::IncompatibleAbi { refusal })
    }

    /// [`Self::check_pin`] over `catalog`, for the rollout.
    pub fn admissibility<'a>(&'a self, catalog: &'a Catalog) -> CatalogPins<'a> {
        CatalogPins {
            admission: self,
            catalog,
        }
    }

    /// Reads the pinned bundle under a lease of `lease` and returns its verified files:
    /// the object must still be admissible, its bytes must be the pinned content key and
    /// decode to a manifest naming the pinned helper, version, ABI and runners. The lease
    /// is released before returning; the loader writes exactly these bytes.
    pub fn open(
        &self,
        catalog: &mut Catalog,
        pin: &HelperPin,
        execution: &ExecutionId,
        lease: Duration,
    ) -> Result<HelperBundle, HelperRefusal> {
        self.check_pin(catalog, pin)?;
        let reader = Scope::Host;
        let held = catalog
            .acquire_lease(&reader, execution, pin.object, lease)
            .map_err(|refusal| HelperRefusal::Read { refusal })?;
        let read = catalog
            .open_read(&reader, execution, held)
            .map_err(|refusal| HelperRefusal::Read { refusal })
            .and_then(|mut handle| {
                handle
                    .read_all()
                    .map_err(|error| HelperRefusal::ReadFailed { error })
            });
        let released = catalog.release_lease(&reader, execution, held);
        let bytes = read?;
        released.map_err(|refusal| HelperRefusal::Read { refusal })?;
        let length_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if ContentKey::of(&bytes) != pin.bundle || length_bytes != pin.length_bytes {
            return Err(HelperRefusal::PinMismatch);
        }
        let bundle = HelperBundle::decode(&bytes)?;
        let manifest = bundle.manifest();
        let named = manifest.helper() == &pin.helper
            && manifest.version() == pin.version
            && manifest.abi() == pin.abi
            && manifest.runners().iter().eq(pin.runners.iter());
        if !named {
            return Err(HelperRefusal::PinMismatch);
        }
        Ok(bundle)
    }
}

/// The catalog-backed [`PinAdmissibility`] of one admission.
#[derive(Debug)]
pub struct CatalogPins<'a> {
    admission: &'a HelperAdmission,
    catalog: &'a Catalog,
}

impl PinAdmissibility for CatalogPins<'_> {
    fn check(&self, pin: &HelperPin) -> Result<(), PinRefusal> {
        self.admission.check_pin(self.catalog, pin)
    }
}
