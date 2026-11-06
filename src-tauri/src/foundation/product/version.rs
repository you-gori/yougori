//! The contract version and the compatibility rule (CORE-07; CORE-01 "versioned"; VM-CP-35:
//! an unknown schema version is governed by host policy; VM part §11.4: "do not delete
//! migration readers before users can recover their data").
//!
//! Every [`ProductView`] names its [`ContractVersion`]. [`read_view`] looks at that version
//! before it interprets anything else:
//!
//! - The current version is read strictly: unknown fields and values are refused.
//! - A newer version, written by a newer Yougori, is never reinterpreted. Anything that
//!   acts on a document ([`ReadPurpose::Act`]: apply, launch, migrate, answer) refuses it.
//!   A reader that only shows it ([`ReadPurpose::Display`]) gets an explicit
//!   [`Downgraded`] notice instead: the version found and a refusal with its remedy, and
//!   nothing else from the document.
//! - An older version is read by that version's own reader and upgraded, reported as
//!   [`Read::Upgraded`]. Version 2 added a model's declared agent endpoint and the CORE-04
//!   grants an execution holds, and changed nothing else; version 1's reader reads exactly
//!   version 1's fields, strictly, and upgrades the document with neither part, which
//!   version 1 could not carry. When the version is bumped again, the previous version's
//!   reader is added here, its golden fixtures stay, and the tests read every fixture of
//!   every version.
//! - A version older than [`OLDEST_READABLE_VERSION`], or none at all, is refused.
//!
//! Records written before this contract existed, such as an old setup's sandbox types and
//! isolation tiers, are read by the migration conversions instead (`migration`), which
//! never refuse a record for being old.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::execution::{CapabilityCheck, Execution};
use super::migration::MigrationShown;
use super::model::ModelStatus;
use super::permissions::PermissionLine;
use super::progress::ProgressShown;
use super::refusal::{ContractCode, Refusal, RefusalCode, Remedy};
use super::sandbox_evidence::SandboxEvidence;
use super::view::{ProductView, ShownAt, ViewSubject};

/// The product contract version this build writes and reads. Bump it on any change to
/// the serialized form, including a new code, remedy, category or field, and add golden
/// fixtures for the new version beside the old ones. Version 2 added the `endpoint` and
/// `grants` parts.
pub const PRODUCT_CONTRACT_VERSION: u32 = 2;

/// The oldest version this build still reads.
pub const OLDEST_READABLE_VERSION: u32 = 1;

/// The first contract version, read by its own reader ([`read_version_1`]).
const VERSION_1: u32 = 1;

/// The `contract_version` field: written as [`PRODUCT_CONTRACT_VERSION`], and read
/// strictly only when it is that version; [`read_view`] handles every other version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ContractVersion(u32);

impl ContractVersion {
    pub const CURRENT: Self = Self(PRODUCT_CONTRACT_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ContractVersion {
    type Error = ContractReadError;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == PRODUCT_CONTRACT_VERSION {
            Ok(Self(found))
        } else {
            Err(ContractReadError::NotCurrent { found })
        }
    }
}

impl From<ContractVersion> for u32 {
    fn from(version: ContractVersion) -> Self {
        version.0
    }
}

/// What the reader will do with a document, which decides how a newer version is handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ReadPurpose {
    /// Apply, launch, migrate, answer or otherwise act on it: a newer version is refused.
    Act,
    /// Only show it: a newer version is downgraded to an explicit notice.
    Display,
}

/// A newer document shown as a notice: nothing in it was interpreted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Downgraded {
    pub found: u32,
    pub supported: u32,
    pub refusal: Refusal,
}

/// What [`read_view`] read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Read<T> {
    /// Written under the current version and read strictly.
    Current(T),
    /// Written under an older readable version and upgraded by that version's reader.
    Upgraded { from: u32, document: T },
    /// Written by a newer Yougori and, for display only, shown as a notice.
    Downgraded(Downgraded),
}

impl<T> Read<T> {
    /// The document, when one was read; `None` for a downgraded notice.
    pub fn document(&self) -> Option<&T> {
        match self {
            Self::Current(document) | Self::Upgraded { document, .. } => Some(document),
            Self::Downgraded(_) => None,
        }
    }
}

/// Reads a product document by the compatibility rule (see the module notes).
pub fn read_view(json: &str, purpose: ReadPurpose) -> Result<Read<ProductView>, ContractReadError> {
    let found = version_of(json)?;
    if found == PRODUCT_CONTRACT_VERSION {
        return serde_json::from_str(json)
            .map(Read::Current)
            .map_err(|error| ContractReadError::Invalid {
                message: error.to_string(),
            });
    }
    if found > PRODUCT_CONTRACT_VERSION {
        let refusal = ContractReadError::Newer { found }.refusal();
        return match purpose {
            ReadPurpose::Act => Err(ContractReadError::Newer { found }),
            ReadPurpose::Display => Ok(Read::Downgraded(Downgraded {
                found,
                supported: PRODUCT_CONTRACT_VERSION,
                refusal,
            })),
        };
    }
    // An older version is read by its own reader; below OLDEST_READABLE_VERSION, or with
    // no reader, it is refused.
    if found == VERSION_1 {
        return read_version_1(json).map(|document| Read::Upgraded {
            from: found,
            document,
        });
    }
    Err(ContractReadError::Unsupported { found })
}

/// Version 1's reader: exactly the fields version 1 wrote, read strictly with the types
/// version 2 kept unchanged, and upgraded to the current version with no agent endpoint
/// and no grant records. A field version 1 did not have is refused, so a document naming
/// version 1 is never read as anything else.
fn read_version_1(json: &str) -> Result<ProductView, ContractReadError> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Version1 {
        contract_version: u32,
        subject: ViewSubject,
        shown_at: ShownAt,
        #[serde(default)]
        execution: Option<Execution>,
        #[serde(default)]
        capabilities: Vec<CapabilityCheck>,
        #[serde(default)]
        sandbox: Option<SandboxEvidence>,
        #[serde(default)]
        model: Option<ModelStatus>,
        #[serde(default)]
        permissions: Vec<PermissionLine>,
        #[serde(default)]
        progress: Vec<ProgressShown>,
        #[serde(default)]
        refusals: Vec<Refusal>,
        #[serde(default)]
        migration: Option<MigrationShown>,
    }
    let wire: Version1 =
        serde_json::from_str(json).map_err(|error| ContractReadError::Invalid {
            message: error.to_string(),
        })?;
    if wire.contract_version != VERSION_1 {
        return Err(ContractReadError::Unsupported {
            found: wire.contract_version,
        });
    }
    let mut view = ProductView::new(wire.subject, wire.shown_at);
    view.execution = wire.execution;
    view.capabilities = wire.capabilities;
    view.sandbox = wire.sandbox;
    view.model = wire.model;
    view.permissions = wire.permissions;
    view.progress = wire.progress;
    view.refusals = wire.refusals;
    view.migration = wire.migration;
    view.check().map_err(|error| ContractReadError::Invalid {
        message: error.to_string(),
    })?;
    Ok(view)
}

/// The `contract_version` of a JSON document, read before anything else in it.
fn version_of(json: &str) -> Result<u32, ContractReadError> {
    #[derive(Deserialize)]
    struct Versioned {
        #[serde(default)]
        contract_version: Option<serde_json::Value>,
    }
    let versioned: Versioned =
        serde_json::from_str(json).map_err(|error| ContractReadError::Invalid {
            message: error.to_string(),
        })?;
    let value = versioned
        .contract_version
        .ok_or(ContractReadError::VersionMissing)?;
    value
        .as_u64()
        .and_then(|version| u32::try_from(version).ok())
        .ok_or(ContractReadError::Invalid {
            message: format!("contract_version {value} is not a version number"),
        })
}

/// Why a product document was not read as it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractReadError {
    /// A newer Yougori wrote it, and the reader would act on it.
    Newer { found: u32 },
    /// This build has no reader for that older version.
    Unsupported { found: u32 },
    /// It names no contract version.
    VersionMissing,
    /// It is not a valid document of its version.
    Invalid { message: String },
    /// A strict read met another version than the current one.
    NotCurrent { found: u32 },
}

impl ContractReadError {
    /// The refusal to show: the stable code, the reason and the remedy.
    pub fn refusal(&self) -> Refusal {
        let (code, remedy) = match self {
            Self::Newer { .. } => (ContractCode::NewerContractVersion, Remedy::UpdateYougori),
            Self::Unsupported { .. } | Self::NotCurrent { .. } => (
                ContractCode::UnsupportedContractVersion,
                Remedy::UpdateYougori,
            ),
            Self::VersionMissing => (
                ContractCode::ContractVersionMissing,
                Remedy::CorrectDocument,
            ),
            Self::Invalid { .. } => (
                ContractCode::InvalidProductDocument,
                Remedy::CorrectDocument,
            ),
        };
        Refusal::new(RefusalCode::Contract { code }, &self.to_string(), remedy)
    }
}

impl fmt::Display for ContractReadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Newer { found } => write!(
                f,
                "a newer Yougori wrote this document with contract version {found}; this build \
                 reads version {PRODUCT_CONTRACT_VERSION} and does not reinterpret a newer one"
            ),
            Self::Unsupported { found } => write!(
                f,
                "contract version {found} is not one this build reads; it reads versions \
                 {OLDEST_READABLE_VERSION} to {PRODUCT_CONTRACT_VERSION}"
            ),
            Self::VersionMissing => f.write_str("the document names no contract_version"),
            Self::Invalid { message } => write!(f, "the document is not valid: {message}"),
            Self::NotCurrent { found } => write!(
                f,
                "contract version {found} is not version {PRODUCT_CONTRACT_VERSION}"
            ),
        }
    }
}

impl std::error::Error for ContractReadError {}
