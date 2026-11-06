//! The update client's own configuration, read alongside the trust-root file (VM-W45,
//! plan line 2668: "trust roots, key rotation"; §8.3, line 2455; M18 in
//! docs/combined-plan-leftover-tasks.md, line 106: "configured roots and release
//! metadata").
//!
//! The foundation's trust-root file lists keys and the classes each may sign. It says
//! neither how many root keys must sign the update client's first root nor where the
//! release metadata is published, so [`UpdateTrustConfig`] carries those two, in a
//! strict, versioned document:
//!
//! ```json
//! {
//!   "format": 1,
//!   "root_threshold": 2,
//!   "metadata_location": "https://yougori.com/releases/sandbox/trust"
//! }
//! ```
//!
//! Unknown, missing and repeated fields are refused; a document of another format
//! version is refused for its version, never for contents that version may define
//! differently; the threshold is at least 1; the location is a [`PublicUrl`] (`https` to
//! a public host, no credentials, query or port). The plan names no minimum threshold,
//! so the production profile accepts 1; requiring more is the owner's decision. Like the
//! rest of this module it reads no file: the caller passes the text.

use std::fmt;
use std::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use crate::foundation::report::PublicUrl;

/// The one format version of the update trust configuration.
pub const UPDATE_TRUST_FORMAT: u64 = 1;

/// Largest update trust configuration read, in bytes.
pub const MAX_UPDATE_TRUST_BYTES: usize = 4096;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigWire {
    format: u64,
    root_threshold: u32,
    metadata_location: PublicUrl,
}

/// The update client's root threshold and release-metadata location.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpdateTrustConfig {
    root_threshold: NonZeroU32,
    metadata_location: PublicUrl,
}

/// Why an update trust configuration was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum UpdateTrustConfigError {
    /// Longer than [`MAX_UPDATE_TRUST_BYTES`].
    TooLarge {
        found_bytes: usize,
        max_bytes: usize,
    },
    /// Not a document of this format: bad JSON, a missing, unknown or repeated field, or
    /// a location that is not a [`PublicUrl`].
    Malformed {
        line: usize,
        column: usize,
    },
    /// A format version other than [`UPDATE_TRUST_FORMAT`].
    UnsupportedFormat {
        found: u64,
    },
    ZeroThreshold,
}

impl fmt::Display for UpdateTrustConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                found_bytes,
                max_bytes,
            } => write!(
                f,
                "the update trust configuration is {found_bytes} bytes; at most {max_bytes}"
            ),
            Self::Malformed { line, column } => write!(
                f,
                "the update trust configuration is malformed at line {line}, column {column}"
            ),
            Self::UnsupportedFormat { found } => write!(
                f,
                "the update trust configuration is format {found}; only {UPDATE_TRUST_FORMAT} is read"
            ),
            Self::ZeroThreshold => f.write_str("the root threshold is 0"),
        }
    }
}

impl std::error::Error for UpdateTrustConfigError {}

impl UpdateTrustConfig {
    pub fn new(root_threshold: NonZeroU32, metadata_location: PublicUrl) -> Self {
        Self {
            root_threshold,
            metadata_location,
        }
    }

    /// Checks an update trust configuration document.
    pub fn from_json(text: &str) -> Result<Self, UpdateTrustConfigError> {
        #[derive(Deserialize)]
        struct Versioned {
            format: u64,
        }
        if text.len() > MAX_UPDATE_TRUST_BYTES {
            return Err(UpdateTrustConfigError::TooLarge {
                found_bytes: text.len(),
                max_bytes: MAX_UPDATE_TRUST_BYTES,
            });
        }
        let wire: ConfigWire = serde_json::from_str(text).map_err(|error| {
            match serde_json::from_str::<Versioned>(text) {
                Ok(Versioned { format }) if format != UPDATE_TRUST_FORMAT => {
                    UpdateTrustConfigError::UnsupportedFormat { found: format }
                }
                _ => UpdateTrustConfigError::Malformed {
                    line: error.line(),
                    column: error.column(),
                },
            }
        })?;
        if wire.format != UPDATE_TRUST_FORMAT {
            return Err(UpdateTrustConfigError::UnsupportedFormat { found: wire.format });
        }
        let root_threshold =
            NonZeroU32::new(wire.root_threshold).ok_or(UpdateTrustConfigError::ZeroThreshold)?;
        Ok(Self::new(root_threshold, wire.metadata_location))
    }

    /// How many pinned root keys must sign the root the update client starts from.
    pub fn root_threshold(&self) -> NonZeroU32 {
        self.root_threshold
    }

    /// Where the release metadata is published.
    pub fn metadata_location(&self) -> &PublicUrl {
        &self.metadata_location
    }
}
