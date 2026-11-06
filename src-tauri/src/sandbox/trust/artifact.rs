//! The verified artifact, and the rule that the opened artifact is the verified artifact
//! (line 2278: "Bind the exact opened artifact to the verified identity to avoid
//! replacement between verification and launch"; VM-W45, line 2493; VM-P23, line 2623:
//! components "fail verification at the actual execution boundary").
//!
//! Verification yields a [`VerifiedTarget`], a handle bound to the content key and
//! length the signed metadata declares. The only way to get bytes to launch is
//! [`VerifiedTarget::open`], which recomputes the content key of the bytes it is handed
//! and refuses any other bytes; the resulting [`OpenedArtifact`] owns those bytes, so
//! what is launched is what was checked.

use std::fmt;
use std::io::Read;

use serde::Serialize;

use super::metadata::{MetadataVersion, ReleaseVersion, TargetEntry, TargetName};
use super::profile::{AssuranceProfile, ResolvedProfile};
use super::time::UnixSeconds;
use crate::foundation::catalog::{ArtifactClass, ObjectId, Scope};
use crate::foundation::ids::ContentKey;

/// What a verification rested on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "basis", rename_all = "snake_case")]
pub enum VerificationBasis {
    /// Signed metadata at these versions.
    Signed {
        root_version: MetadataVersion,
        timestamp_version: MetadataVersion,
        snapshot_version: MetadataVersion,
        targets_version: MetadataVersion,
    },
    /// A developer build the host chose without any signature (line 2282).
    DeveloperUnsigned,
}

/// A target whose identity was verified: the handle the opener must re-check the bytes
/// against. Serialize only; it is never read back from data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedTarget {
    name: TargetName,
    class: ArtifactClass,
    content_key: ContentKey,
    length_bytes: u64,
    release: ReleaseVersion,
    assurance: AssuranceProfile,
    basis: VerificationBasis,
    verified_at: UnixSeconds,
}

/// The profile does not allow what was asked of it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum AssuranceRefusal {
    /// A developer build or test-signed target is not a production release (line
    /// 2282: it never activates production credential grants).
    NotProduction { assurance: AssuranceProfile },
    /// Only the developer profile admits an unsigned build.
    NotDeveloper { assurance: AssuranceProfile },
}

impl fmt::Display for AssuranceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotProduction { assurance } => write!(
                f,
                "a target verified under the {assurance} profile is not a production release"
            ),
            Self::NotDeveloper { assurance } => write!(
                f,
                "an unsigned developer build is not admitted under the {assurance} profile"
            ),
        }
    }
}

impl std::error::Error for AssuranceRefusal {}

/// Why bytes were not accepted as the verified artifact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum OpenRefusal {
    LengthDiffers {
        expected_bytes: u64,
        found_bytes: u64,
    },
    /// The bytes are not the verified bytes: replaced between verification and launch,
    /// or corrupted.
    BytesDiffer {
        expected: ContentKey,
        found: ContentKey,
    },
    Unreadable {
        detail: String,
    },
}

impl fmt::Display for OpenRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LengthDiffers {
                expected_bytes,
                found_bytes,
            } => write!(
                f,
                "the artifact is {found_bytes} bytes, not the verified {expected_bytes}"
            ),
            Self::BytesDiffer { expected, found } => write!(
                f,
                "the artifact's content key {found} is not the verified {expected}"
            ),
            Self::Unreadable { detail } => write!(f, "the artifact could not be read: {detail}"),
        }
    }
}

impl std::error::Error for OpenRefusal {}

impl VerifiedTarget {
    pub(super) fn signed(
        name: TargetName,
        entry: &TargetEntry,
        assurance: AssuranceProfile,
        basis: VerificationBasis,
        verified_at: UnixSeconds,
    ) -> Self {
        Self {
            name,
            class: entry.class,
            content_key: entry.content_key,
            length_bytes: entry.length_bytes,
            release: entry.release.clone(),
            assurance,
            basis,
            verified_at,
        }
    }

    /// An unsigned developer build, admitted only under a resolved developer profile
    /// (line 2282). It opens like any other target, so even a developer build launches
    /// only the bytes it was declared with.
    pub fn developer_unsigned(
        profile: ResolvedProfile,
        name: TargetName,
        class: ArtifactClass,
        content_key: ContentKey,
        length_bytes: u64,
        release: ReleaseVersion,
        now: UnixSeconds,
    ) -> Result<Self, AssuranceRefusal> {
        if profile.profile() != AssuranceProfile::Developer {
            return Err(AssuranceRefusal::NotDeveloper {
                assurance: profile.profile(),
            });
        }
        Ok(Self {
            name,
            class,
            content_key,
            length_bytes,
            release,
            assurance: AssuranceProfile::Developer,
            basis: VerificationBasis::DeveloperUnsigned,
            verified_at: now,
        })
    }

    pub fn name(&self) -> &TargetName {
        &self.name
    }

    pub fn class(&self) -> ArtifactClass {
        self.class
    }

    pub fn content_key(&self) -> ContentKey {
        self.content_key
    }

    pub fn length_bytes(&self) -> u64 {
        self.length_bytes
    }

    pub fn release(&self) -> &ReleaseVersion {
        &self.release
    }

    pub fn assurance(&self) -> AssuranceProfile {
        self.assurance
    }

    pub fn basis(&self) -> &VerificationBasis {
        &self.basis
    }

    pub fn verified_at(&self) -> UnixSeconds {
        self.verified_at
    }

    /// The catalog identity of this artifact in `scope` (S2 CORE-02 scoped identity).
    pub fn object_id(&self, scope: &Scope) -> ObjectId {
        ObjectId::new(scope, self.class, self.content_key)
    }

    /// Accepts `bytes` as this artifact only if their length and content key are the
    /// verified ones; the opened artifact then owns exactly those bytes.
    pub fn open(&self, bytes: Vec<u8>) -> Result<OpenedArtifact, OpenRefusal> {
        let found_bytes = bytes.len() as u64;
        if found_bytes != self.length_bytes {
            return Err(OpenRefusal::LengthDiffers {
                expected_bytes: self.length_bytes,
                found_bytes,
            });
        }
        let found = ContentKey::of(&bytes);
        if found != self.content_key {
            return Err(OpenRefusal::BytesDiffer {
                expected: self.content_key,
                found,
            });
        }
        Ok(OpenedArtifact {
            target: self.clone(),
            bytes,
        })
    }

    /// Reads at most one byte more than the verified length from `reader` and opens
    /// what it read, so a longer stream is refused without being read to its end.
    pub fn open_reader(&self, reader: &mut dyn Read) -> Result<OpenedArtifact, OpenRefusal> {
        let limit = self.length_bytes.saturating_add(1);
        let mut bytes = Vec::new();
        reader
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(|error| OpenRefusal::Unreadable {
                detail: error.to_string(),
            })?;
        self.open(bytes)
    }

    /// This target as a production release: refused for anything verified under the
    /// developer profile, so developer mode never reaches production credential grants
    /// (line 2282).
    pub fn production_release(&self) -> Result<ProductionRelease, AssuranceRefusal> {
        if self.assurance != AssuranceProfile::Production {
            return Err(AssuranceRefusal::NotProduction {
                assurance: self.assurance,
            });
        }
        Ok(ProductionRelease {
            name: self.name.clone(),
            class: self.class,
            content_key: self.content_key,
            length_bytes: self.length_bytes,
            release: self.release.clone(),
        })
    }
}

/// The bytes of a verified target, checked against it. Launch code takes this, never
/// loose bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct OpenedArtifact {
    target: VerifiedTarget,
    bytes: Vec<u8>,
}

impl OpenedArtifact {
    pub fn target(&self) -> &VerifiedTarget {
        &self.target
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn content_key(&self) -> ContentKey {
        self.target.content_key
    }
}

impl fmt::Debug for OpenedArtifact {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenedArtifact")
            .field("target", &self.target)
            .field("length_bytes", &self.bytes.len())
            .finish()
    }
}

/// A release verified under the production profile: what production credential grants
/// may be bound to. Built only by [`VerifiedTarget::production_release`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProductionRelease {
    name: TargetName,
    class: ArtifactClass,
    content_key: ContentKey,
    length_bytes: u64,
    release: ReleaseVersion,
}

impl ProductionRelease {
    pub fn name(&self) -> &TargetName {
        &self.name
    }

    pub fn class(&self) -> ArtifactClass {
        self.class
    }

    pub fn content_key(&self) -> ContentKey {
        self.content_key
    }

    pub fn length_bytes(&self) -> u64 {
        self.length_bytes
    }

    pub fn release(&self) -> &ReleaseVersion {
        &self.release
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::trust::profile::{ProfileRequest, RequestOrigin};

    fn developer() -> ResolvedProfile {
        ResolvedProfile::resolve(&ProfileRequest {
            profile: AssuranceProfile::Developer,
            origin: RequestOrigin::OperatorCommand,
        })
        .unwrap()
    }

    fn target(bytes: &[u8]) -> VerifiedTarget {
        VerifiedTarget::signed(
            TargetName::new("kernel").unwrap(),
            &TargetEntry {
                class: ArtifactClass::GuestImage,
                length_bytes: bytes.len() as u64,
                content_key: ContentKey::of(bytes),
                release: ReleaseVersion::new("1.0").unwrap(),
            },
            AssuranceProfile::Production,
            VerificationBasis::Signed {
                root_version: MetadataVersion::FIRST,
                timestamp_version: MetadataVersion::FIRST,
                snapshot_version: MetadataVersion::FIRST,
                targets_version: MetadataVersion::FIRST,
            },
            UnixSeconds::new(10),
        )
    }

    #[test]
    fn only_the_verified_bytes_open() {
        let verified = target(b"vmlinuz-bytes");
        let opened = verified.open(b"vmlinuz-bytes".to_vec()).unwrap();
        assert_eq!(opened.bytes(), b"vmlinuz-bytes");
        assert_eq!(opened.content_key(), ContentKey::of(b"vmlinuz-bytes"));
        assert_eq!(opened.target(), &verified);

        assert_eq!(
            verified.open(b"vmlinuz-bytez".to_vec()),
            Err(OpenRefusal::BytesDiffer {
                expected: ContentKey::of(b"vmlinuz-bytes"),
                found: ContentKey::of(b"vmlinuz-bytez"),
            })
        );
        assert_eq!(
            verified.open(b"vmlinuz-bytes!".to_vec()),
            Err(OpenRefusal::LengthDiffers {
                expected_bytes: 13,
                found_bytes: 14,
            })
        );
        assert_eq!(
            verified.object_id(&Scope::Host),
            ObjectId::new(
                &Scope::Host,
                ArtifactClass::GuestImage,
                ContentKey::of(b"vmlinuz-bytes")
            )
        );
    }

    #[test]
    fn a_stream_is_bounded_and_checked() {
        let verified = target(b"abc");
        let mut good: &[u8] = b"abc";
        assert_eq!(verified.open_reader(&mut good).unwrap().bytes(), b"abc");
        let mut long: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
        assert_eq!(
            verified.open_reader(&mut long),
            Err(OpenRefusal::LengthDiffers {
                expected_bytes: 3,
                found_bytes: 4,
            })
        );
        let mut short: &[u8] = b"ab";
        assert!(matches!(
            verified.open_reader(&mut short),
            Err(OpenRefusal::LengthDiffers { found_bytes: 2, .. })
        ));
        struct Broken;
        impl Read for Broken {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("disk gone"))
            }
        }
        assert_eq!(
            verified.open_reader(&mut Broken),
            Err(OpenRefusal::Unreadable {
                detail: "disk gone".to_owned()
            })
        );
    }

    #[test]
    fn developer_builds_are_never_production_releases() {
        let unsigned = VerifiedTarget::developer_unsigned(
            developer(),
            TargetName::new("local-kernel").unwrap(),
            ArtifactClass::GuestImage,
            ContentKey::of(b"dev"),
            3,
            ReleaseVersion::new("dev").unwrap(),
            UnixSeconds::new(1),
        )
        .unwrap();
        assert_eq!(unsigned.basis(), &VerificationBasis::DeveloperUnsigned);
        assert_eq!(
            unsigned.production_release(),
            Err(AssuranceRefusal::NotProduction {
                assurance: AssuranceProfile::Developer
            })
        );
        // Even a developer build opens only its declared bytes.
        assert!(matches!(
            unsigned.open(b"other".to_vec()),
            Err(OpenRefusal::LengthDiffers { .. })
        ));
        assert!(unsigned.open(b"dev".to_vec()).is_ok());

        // The production profile cannot admit an unsigned build at all.
        assert_eq!(
            VerifiedTarget::developer_unsigned(
                ResolvedProfile::PRODUCTION,
                TargetName::new("x").unwrap(),
                ArtifactClass::GuestImage,
                ContentKey::of(b"dev"),
                3,
                ReleaseVersion::new("dev").unwrap(),
                UnixSeconds::new(1),
            )
            .map(|_| ()),
            Err(AssuranceRefusal::NotDeveloper {
                assurance: AssuranceProfile::Production
            })
        );

        let production = target(b"signed").production_release().unwrap();
        assert_eq!(production.name().as_str(), "kernel");
        assert_eq!(production.class(), ArtifactClass::GuestImage);
        assert_eq!(production.length_bytes(), 6);
        assert_eq!(production.release().as_str(), "1.0");
        assert_eq!(production.content_key(), ContentKey::of(b"signed"));
    }
}
