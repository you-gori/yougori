//! The helper bundle: one immutable object holding a canonical manifest and the files it
//! lists, so one publisher signature and one catalog object pin the whole helper
//! (GPU-W11, line 1321; S2 CORE-08).
//!
//! The encoding is a fixed header, the manifest and the files back to back:
//!
//! ```text
//! "YGHELPER"  manifest length (u32, big-endian)  manifest  file 1  file 2  ...
//! ```
//!
//! Files follow in the manifest's path order, each exactly its declared length, and
//! nothing follows the last one. Decoding checks every bound before reading and every
//! file against the content key its manifest pins: a file whose bytes differ is reported
//! as [`BundleError::FileDigestMismatch`], never loaded.

use std::fmt;

use serde::Serialize;

use super::abi::HelperAbi;
use super::manifest::{
    HelperFile, HelperId, HelperManifest, HelperPath, HelperVersion, ManifestError,
    MAX_HELPER_FILES_BYTES, MAX_MANIFEST_BYTES,
};
use crate::foundation::evidence::BackendRelease;
use crate::foundation::ids::ContentKey;

/// The first bytes of every bundle.
pub const BUNDLE_MAGIC: [u8; 8] = *b"YGHELPER";

/// The magic and the manifest length.
pub const BUNDLE_HEADER_BYTES: usize = 12;

/// Largest bundle: the header, the largest manifest and the largest set of files.
pub const MAX_BUNDLE_BYTES: u64 =
    (BUNDLE_HEADER_BYTES + MAX_MANIFEST_BYTES) as u64 + MAX_HELPER_FILES_BYTES;

/// Why bytes are not a helper bundle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "bundle", rename_all = "snake_case")]
pub enum BundleError {
    /// Larger than [`MAX_BUNDLE_BYTES`].
    TooLarge {
        max_bytes: u64,
    },
    /// Shorter than its header or its declared manifest.
    Truncated,
    /// Not a helper bundle.
    BadMagic,
    Manifest {
        error: ManifestError,
    },
    /// The bundle is not exactly the header, the manifest and the declared files.
    LengthMismatch {
        expected_bytes: u64,
        found_bytes: u64,
    },
    /// A file's bytes differ from the content key its manifest pins.
    FileDigestMismatch {
        path: HelperPath,
        expected: ContentKey,
        found: ContentKey,
    },
}

impl fmt::Display for BundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max_bytes } => {
                write!(f, "the helper bundle is larger than {max_bytes} bytes")
            }
            Self::Truncated => f.write_str("the helper bundle is truncated"),
            Self::BadMagic => f.write_str("the bytes are not a helper bundle"),
            Self::Manifest { error } => write!(f, "the helper manifest is refused: {error}"),
            Self::LengthMismatch {
                expected_bytes,
                found_bytes,
            } => write!(
                f,
                "the helper bundle declares {expected_bytes} bytes but holds {found_bytes}"
            ),
            Self::FileDigestMismatch { path, .. } => write!(
                f,
                "helper file {path} differs from the content key its manifest pins"
            ),
        }
    }
}

impl std::error::Error for BundleError {}

impl From<ManifestError> for BundleError {
    fn from(error: ManifestError) -> Self {
        Self::Manifest { error }
    }
}

/// A checked bundle: its manifest and each listed file's verified bytes.
#[derive(Clone, PartialEq, Eq)]
pub struct HelperBundle {
    manifest: HelperManifest,
    /// In the manifest's file order.
    contents: Vec<Vec<u8>>,
}

impl fmt::Debug for HelperBundle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelperBundle")
            .field("manifest", &self.manifest)
            .finish_non_exhaustive()
    }
}

impl HelperBundle {
    /// Builds a bundle from files on hand, describing each one.
    pub fn build(
        helper: HelperId,
        version: HelperVersion,
        abi: HelperAbi,
        runners: Vec<BackendRelease>,
        entry: HelperPath,
        files: Vec<(HelperPath, Vec<u8>)>,
    ) -> Result<Self, BundleError> {
        let described = files
            .iter()
            .map(|(path, bytes)| HelperFile::describe(path.clone(), bytes))
            .collect();
        let manifest = HelperManifest::new(helper, version, abi, runners, entry, described)?;
        let mut files = files;
        files.sort_by(|left, right| left.0.cmp(&right.0));
        let contents = files.into_iter().map(|(_, bytes)| bytes).collect();
        Ok(Self { manifest, contents })
    }

    /// The bundle's one encoding.
    pub fn encode(&self) -> Result<Vec<u8>, BundleError> {
        let manifest = self.manifest.to_bytes()?;
        let length = u32::try_from(manifest.len()).map_err(|_| ManifestError::TooLarge {
            max_bytes: MAX_MANIFEST_BYTES,
        })?;
        let mut bytes = Vec::with_capacity(
            BUNDLE_HEADER_BYTES
                .saturating_add(manifest.len())
                .saturating_add(self.contents.iter().map(Vec::len).sum()),
        );
        bytes.extend_from_slice(&BUNDLE_MAGIC);
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(&manifest);
        for content in &self.contents {
            bytes.extend_from_slice(content);
        }
        Ok(bytes)
    }

    /// Reads a bundle, checking its bounds, its manifest and every file's content key.
    pub fn decode(bytes: &[u8]) -> Result<Self, BundleError> {
        let found_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if found_bytes > MAX_BUNDLE_BYTES {
            return Err(BundleError::TooLarge {
                max_bytes: MAX_BUNDLE_BYTES,
            });
        }
        if bytes.get(..BUNDLE_MAGIC.len()) != Some(BUNDLE_MAGIC.as_slice()) {
            return Err(if bytes.len() < BUNDLE_HEADER_BYTES {
                BundleError::Truncated
            } else {
                BundleError::BadMagic
            });
        }
        let length: [u8; 4] = bytes
            .get(BUNDLE_MAGIC.len()..BUNDLE_HEADER_BYTES)
            .and_then(|field| field.try_into().ok())
            .ok_or(BundleError::Truncated)?;
        let length = usize::try_from(u32::from_be_bytes(length)).unwrap_or(usize::MAX);
        if length > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge {
                max_bytes: MAX_MANIFEST_BYTES,
            }
            .into());
        }
        let manifest_end = BUNDLE_HEADER_BYTES.saturating_add(length);
        let manifest = bytes
            .get(BUNDLE_HEADER_BYTES..manifest_end)
            .ok_or(BundleError::Truncated)?;
        let manifest = HelperManifest::from_bytes(manifest)?;
        let expected_bytes = u64::try_from(manifest_end)
            .unwrap_or(u64::MAX)
            .saturating_add(manifest.files_bytes());
        if expected_bytes != found_bytes {
            return Err(BundleError::LengthMismatch {
                expected_bytes,
                found_bytes,
            });
        }
        let mut offset = manifest_end;
        let mut contents = Vec::with_capacity(manifest.files().len());
        for file in manifest.files() {
            let end = usize::try_from(file.length_bytes)
                .ok()
                .and_then(|length| offset.checked_add(length))
                .ok_or(BundleError::Truncated)?;
            let content = bytes.get(offset..end).ok_or(BundleError::Truncated)?;
            let found = ContentKey::of(content);
            if found != file.content_key {
                return Err(BundleError::FileDigestMismatch {
                    path: file.path.clone(),
                    expected: file.content_key,
                    found,
                });
            }
            contents.push(content.to_vec());
            offset = end;
        }
        Ok(Self { manifest, contents })
    }

    pub fn manifest(&self) -> &HelperManifest {
        &self.manifest
    }

    /// Each file with its verified bytes, in path order.
    pub fn files(&self) -> impl Iterator<Item = (&HelperFile, &[u8])> {
        self.manifest
            .files()
            .iter()
            .zip(self.contents.iter().map(Vec::as_slice))
    }

    /// The verified bytes of the file at `path`.
    pub fn file(&self, path: &HelperPath) -> Option<&[u8]> {
        self.files()
            .find(|(file, _)| file.path == *path)
            .map(|(_, bytes)| bytes)
    }

    /// The verified bytes of the entry point; always present in a checked bundle.
    pub fn entry(&self) -> Option<&[u8]> {
        self.file(self.manifest.entry())
    }
}
