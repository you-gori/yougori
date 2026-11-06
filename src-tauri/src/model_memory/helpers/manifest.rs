//! The helper bundle manifest (GPU-W11, line 1321): which helper and version a bundle
//! is, the helper ABI it was built for, the runners it supports and the content key of
//! every file it carries.
//!
//! The manifest is read strictly: an unknown field, another format version, a malformed
//! id, version, path or key, an empty or duplicate list or a bound exceeded is refused
//! with a typed error, never skipped. It is also canonical: [`HelperManifest::to_bytes`]
//! is its only encoding (compact JSON, files sorted by path and runners in order), and
//! [`HelperManifest::from_bytes`] refuses any other encoding of the same content, so one
//! manifest has exactly one content key and one pinned identity.
//!
//! Runners are named as the model manifest's execution ABI names them: a backend at an
//! exact version ([`BackendRelease`]). Versions are compared exactly, never as ranges
//! (GPU part §1.1: "unless a tested version").

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::abi::HelperAbi;
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::{validate_identifier, ContentKey, IdError};

/// The manifest format this build reads. Another version is refused, never
/// reinterpreted.
pub const HELPER_MANIFEST_FORMAT: u64 = 1;

/// Largest encoded manifest.
pub const MAX_MANIFEST_BYTES: usize = 64 << 10;

/// Most files one bundle may carry.
pub const MAX_HELPER_FILES: usize = 64;

/// Most runners one bundle may declare.
pub const MAX_HELPER_RUNNERS: usize = 64;

/// Longest file path inside a bundle.
pub const MAX_HELPER_PATH_BYTES: usize = 128;

/// Largest single file of a bundle.
pub const MAX_HELPER_FILE_BYTES: u64 = 4 << 20;

/// Largest total of a bundle's files.
pub const MAX_HELPER_FILES_BYTES: u64 = 16 << 20;

/// A helper's stable id, such as `gpu-optimizer`: the shared identifier rule (1–128
/// letters, digits, '.', '_', ':' or '-', starting with a letter or digit).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct HelperId(String);

impl HelperId {
    /// Checks `value` against the shared identifier rule.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HelperId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HelperId({})", self.0)
    }
}

impl fmt::Display for HelperId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HelperId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Why a helper version text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HelperVersionError;

impl fmt::Display for HelperVersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "a helper version is major.minor.patch in decimal without leading zeros, each \
             part at most 4294967295",
        )
    }
}

impl std::error::Error for HelperVersionError {}

/// A helper release version, `major.minor.patch`, ordered numerically. A rollout only
/// moves to a newer version; going back is a rollback to a pinned version.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HelperVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl HelperVersion {
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    /// Reads `major.minor.patch`: three decimal parts, no sign, no leading zero.
    pub fn parse(text: &str) -> Result<Self, HelperVersionError> {
        let mut parts = text.split('.');
        let mut next = || -> Result<u32, HelperVersionError> {
            let part = parts.next().ok_or(HelperVersionError)?;
            let digits = !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit());
            if !digits || (part.len() > 1 && part.starts_with('0')) {
                return Err(HelperVersionError);
            }
            part.parse().map_err(|_| HelperVersionError)
        };
        let version = Self::new(next()?, next()?, next()?);
        if parts.next().is_some() {
            return Err(HelperVersionError);
        }
        Ok(version)
    }

    pub const fn major(self) -> u32 {
        self.major
    }

    pub const fn minor(self) -> u32 {
        self.minor
    }

    pub const fn patch(self) -> u32 {
        self.patch
    }
}

impl fmt::Display for HelperVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl fmt::Debug for HelperVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HelperVersion({self})")
    }
}

impl Serialize for HelperVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for HelperVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Why a file path inside a bundle was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HelperPathError {
    Empty,
    TooLong {
        max: usize,
    },
    InvalidCharacter {
        character: char,
    },
    /// An empty component (a leading, trailing or doubled '/'), or one that does not
    /// start with a letter, digit or '_' (so never `.` or `..`).
    InvalidComponent,
}

impl fmt::Display for HelperPathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the helper file path is empty"),
            Self::TooLong { max } => write!(f, "the helper file path is longer than {max} bytes"),
            Self::InvalidCharacter { character } => write!(
                f,
                "the helper file path contains {character:?}; use letters, digits, '.', '_', \
                 '-' and '/' between components"
            ),
            Self::InvalidComponent => f.write_str(
                "every helper path component is non-empty and starts with a letter, digit or '_'",
            ),
        }
    }
}

impl std::error::Error for HelperPathError {}

/// A relative file path inside a bundle, such as `gpu_optimizer.py`: '/'-separated
/// components of ASCII letters, digits, '.', '_' or '-', each starting with a letter,
/// digit or '_'. It can name no parent directory, absolute path or hidden file, so a
/// loader writing the files under one directory stays inside it.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct HelperPath(String);

impl HelperPath {
    pub fn new(value: impl Into<String>) -> Result<Self, HelperPathError> {
        let value = value.into();
        if value.is_empty() {
            return Err(HelperPathError::Empty);
        }
        if value.len() > MAX_HELPER_PATH_BYTES {
            return Err(HelperPathError::TooLong {
                max: MAX_HELPER_PATH_BYTES,
            });
        }
        if let Some(character) = value.chars().find(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | '/'))
        }) {
            return Err(HelperPathError::InvalidCharacter { character });
        }
        let components_valid = value.split('/').all(|component| {
            component
                .chars()
                .next()
                .is_some_and(|first| first.is_ascii_alphanumeric() || first == '_')
        });
        if !components_valid {
            return Err(HelperPathError::InvalidComponent);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HelperPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HelperPath({})", self.0)
    }
}

impl fmt::Display for HelperPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for HelperPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// One file of a bundle: its path and the content key and length of its bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperFile {
    pub path: HelperPath,
    pub content_key: ContentKey,
    pub length_bytes: u64,
}

impl HelperFile {
    /// The entry for `bytes` at `path`.
    pub fn describe(path: HelperPath, bytes: &[u8]) -> Self {
        Self {
            path,
            content_key: ContentKey::of(bytes),
            length_bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        }
    }
}

/// Why a helper manifest was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ManifestError {
    /// The encoded manifest is larger than [`MAX_MANIFEST_BYTES`].
    TooLarge {
        max_bytes: usize,
    },
    /// Not a helper manifest: bad JSON, an unknown or missing field, a malformed id,
    /// version, path, ABI, runner or content key. Located, never quoted.
    Malformed {
        line: usize,
        column: usize,
    },
    /// The manifest is in another format version.
    UnsupportedFormat {
        found: u64,
    },
    NoFiles,
    TooManyFiles {
        max: usize,
    },
    /// Two files share a path, compared without case so that no file system merges them.
    DuplicateFile {
        path: HelperPath,
    },
    FileTooLarge {
        path: HelperPath,
        max_bytes: u64,
    },
    FilesTooLarge {
        max_bytes: u64,
    },
    /// The entry point is not one of the files.
    EntryNotListed {
        entry: HelperPath,
    },
    NoRunners,
    TooManyRunners {
        max: usize,
    },
    DuplicateRunner {
        runner: BackendRelease,
    },
    /// The bytes are a valid manifest, but not its one canonical encoding.
    NotCanonical,
    /// The manifest could not be encoded.
    Encoding,
}

impl fmt::Display for ManifestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge { max_bytes } => {
                write!(f, "the helper manifest is larger than {max_bytes} bytes")
            }
            Self::Malformed { line, column } => write!(
                f,
                "the helper manifest is malformed at line {line}, column {column}"
            ),
            Self::UnsupportedFormat { found } => write!(
                f,
                "helper manifest format {found} is not supported; this build reads format \
                 {HELPER_MANIFEST_FORMAT}"
            ),
            Self::NoFiles => f.write_str("the helper manifest lists no file"),
            Self::TooManyFiles { max } => {
                write!(f, "the helper manifest lists more than {max} files")
            }
            Self::DuplicateFile { path } => write!(f, "helper file {path} is listed twice"),
            Self::FileTooLarge { path, max_bytes } => {
                write!(f, "helper file {path} is larger than {max_bytes} bytes")
            }
            Self::FilesTooLarge { max_bytes } => {
                write!(f, "the helper files total more than {max_bytes} bytes")
            }
            Self::EntryNotListed { entry } => {
                write!(f, "the helper entry point {entry} is not one of its files")
            }
            Self::NoRunners => f.write_str("the helper manifest supports no runner"),
            Self::TooManyRunners { max } => {
                write!(f, "the helper manifest lists more than {max} runners")
            }
            Self::DuplicateRunner { runner } => write!(f, "runner {runner} is listed twice"),
            Self::NotCanonical => {
                f.write_str("the helper manifest is not in its canonical encoding")
            }
            Self::Encoding => f.write_str("the helper manifest could not be encoded"),
        }
    }
}

impl std::error::Error for ManifestError {}

/// A checked helper manifest in canonical order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct HelperManifest {
    format: u64,
    helper: HelperId,
    version: HelperVersion,
    abi: HelperAbi,
    runners: Vec<BackendRelease>,
    entry: HelperPath,
    files: Vec<HelperFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestWire {
    format: u64,
    helper: HelperId,
    version: HelperVersion,
    abi: HelperAbi,
    runners: Vec<BackendRelease>,
    entry: HelperPath,
    files: Vec<HelperFile>,
}

impl HelperManifest {
    /// Checks a manifest and puts it in canonical order: files by path, runners by
    /// backend and version.
    pub fn new(
        helper: HelperId,
        version: HelperVersion,
        abi: HelperAbi,
        mut runners: Vec<BackendRelease>,
        entry: HelperPath,
        mut files: Vec<HelperFile>,
    ) -> Result<Self, ManifestError> {
        if files.is_empty() {
            return Err(ManifestError::NoFiles);
        }
        if files.len() > MAX_HELPER_FILES {
            return Err(ManifestError::TooManyFiles {
                max: MAX_HELPER_FILES,
            });
        }
        let mut total = 0u64;
        let mut seen = BTreeSet::new();
        for file in &files {
            if file.length_bytes > MAX_HELPER_FILE_BYTES {
                return Err(ManifestError::FileTooLarge {
                    path: file.path.clone(),
                    max_bytes: MAX_HELPER_FILE_BYTES,
                });
            }
            total = total
                .checked_add(file.length_bytes)
                .filter(|total| *total <= MAX_HELPER_FILES_BYTES)
                .ok_or(ManifestError::FilesTooLarge {
                    max_bytes: MAX_HELPER_FILES_BYTES,
                })?;
            if !seen.insert(file.path.as_str().to_ascii_lowercase()) {
                return Err(ManifestError::DuplicateFile {
                    path: file.path.clone(),
                });
            }
        }
        if !files.iter().any(|file| file.path == entry) {
            return Err(ManifestError::EntryNotListed { entry });
        }
        if runners.is_empty() {
            return Err(ManifestError::NoRunners);
        }
        if runners.len() > MAX_HELPER_RUNNERS {
            return Err(ManifestError::TooManyRunners {
                max: MAX_HELPER_RUNNERS,
            });
        }
        let mut distinct = BTreeSet::new();
        for runner in &runners {
            if !distinct.insert(runner) {
                return Err(ManifestError::DuplicateRunner {
                    runner: runner.clone(),
                });
            }
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        runners.sort();
        Ok(Self {
            format: HELPER_MANIFEST_FORMAT,
            helper,
            version,
            abi,
            runners,
            entry,
            files,
        })
    }

    /// Reads a manifest strictly and refuses any encoding but the canonical one.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ManifestError> {
        #[derive(Deserialize)]
        struct Versioned {
            format: u64,
        }
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge {
                max_bytes: MAX_MANIFEST_BYTES,
            });
        }
        let wire: ManifestWire = serde_json::from_slice(bytes).map_err(|error| {
            match serde_json::from_slice::<Versioned>(bytes) {
                Ok(Versioned { format }) if format != HELPER_MANIFEST_FORMAT => {
                    ManifestError::UnsupportedFormat { found: format }
                }
                _ => ManifestError::Malformed {
                    line: error.line(),
                    column: error.column(),
                },
            }
        })?;
        if wire.format != HELPER_MANIFEST_FORMAT {
            return Err(ManifestError::UnsupportedFormat { found: wire.format });
        }
        let manifest = Self::new(
            wire.helper,
            wire.version,
            wire.abi,
            wire.runners,
            wire.entry,
            wire.files,
        )?;
        if manifest.to_bytes()? != bytes {
            return Err(ManifestError::NotCanonical);
        }
        Ok(manifest)
    }

    /// The one canonical encoding: compact JSON in field and canonical list order.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ManifestError> {
        let bytes = serde_json::to_vec(self).map_err(|_| ManifestError::Encoding)?;
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(ManifestError::TooLarge {
                max_bytes: MAX_MANIFEST_BYTES,
            });
        }
        Ok(bytes)
    }

    pub fn helper(&self) -> &HelperId {
        &self.helper
    }

    pub fn version(&self) -> HelperVersion {
        self.version
    }

    pub fn abi(&self) -> HelperAbi {
        self.abi
    }

    /// The supported runners, in order.
    pub fn runners(&self) -> &[BackendRelease] {
        &self.runners
    }

    /// Whether the helper supports `runner` exactly.
    pub fn supports(&self, runner: &BackendRelease) -> bool {
        self.runners.contains(runner)
    }

    /// The backends of the supported runners.
    pub fn backends(&self) -> BTreeSet<Backend> {
        self.runners.iter().map(|runner| runner.backend).collect()
    }

    /// The file the loader starts the helper from.
    pub fn entry(&self) -> &HelperPath {
        &self.entry
    }

    /// The files, by path.
    pub fn files(&self) -> &[HelperFile] {
        &self.files
    }

    pub fn file(&self, path: &HelperPath) -> Option<&HelperFile> {
        self.files.iter().find(|file| file.path == *path)
    }

    /// The total length of the files; within [`MAX_HELPER_FILES_BYTES`].
    pub fn files_bytes(&self) -> u64 {
        self.files
            .iter()
            .fold(0u64, |total, file| total.saturating_add(file.length_bytes))
    }
}
