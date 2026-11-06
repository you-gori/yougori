//! The pinned, authenticated identity of one admitted helper version (GPU-W11, line
//! 1321: "authenticated pinned artifact identity").
//!
//! A [`HelperPin`] names exactly one catalog object of class `model_helper`: its object
//! id and content key, the publisher whose key vouched for it, and what its manifest
//! declares (helper, version, ABI and runners). Runners start from a pin, rollouts move
//! between pins and rollbacks return to one; [`HelperPinId`] is its digest. A pin read
//! back proves nothing about bytes on hand: opening it reads the object under a lease
//! and checks the bytes against every field again.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::abi::{HelperAbi, HelperAbiRefusal};
use super::manifest::{HelperId, HelperVersion};
use crate::foundation::catalog::{IntegrityFailure, ObjectId, PublisherId};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder};

/// Domain of [`HelperPin::id`].
pub const HELPER_PIN_DOMAIN: &str = "yougori/model-memory/helpers/pin/v1";

/// One admitted helper version, exactly.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelperPin {
    pub helper: HelperId,
    pub version: HelperVersion,
    pub abi: HelperAbi,
    /// The runners the manifest supports.
    pub runners: BTreeSet<BackendRelease>,
    /// The catalog object holding the bundle.
    pub object: ObjectId,
    /// The bundle's content key.
    pub bundle: ContentKey,
    pub length_bytes: u64,
    /// The publisher whose trust-root key signed the bundle.
    pub publisher: PublisherId,
}

impl HelperPin {
    /// The digest of every field under [`HELPER_PIN_DOMAIN`].
    pub fn id(&self) -> HelperPinId {
        let builder = DigestBuilder::new(HELPER_PIN_DOMAIN)
            .str(self.helper.as_str())
            .str(&self.version.to_string())
            .u64(u64::from(self.abi.major))
            .u64(u64::from(self.abi.minor))
            .u64(u64::try_from(self.runners.len()).unwrap_or(u64::MAX));
        let builder = self.runners.iter().fold(builder, |builder, runner| {
            builder
                .str(runner.backend.tag())
                .str(runner.version.as_str())
        });
        HelperPinId(
            builder
                .digest(&self.object.digest())
                .digest(self.bundle.digest())
                .u64(self.length_bytes)
                .digest(&self.publisher.digest())
                .finish(),
        )
    }

    /// Whether the helper supports `runner` exactly.
    pub fn supports(&self, runner: &BackendRelease) -> bool {
        self.runners.contains(runner)
    }

    /// Whether the helper supports some runner of `backend`.
    pub fn supports_backend(&self, backend: Backend) -> bool {
        self.runners.iter().any(|runner| runner.backend == backend)
    }
}

/// The identity of one [`HelperPin`].
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HelperPinId(Digest);

impl HelperPinId {
    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Debug for HelperPinId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HelperPinId({})", self.0.to_hex())
    }
}

impl fmt::Display for HelperPinId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0.to_hex())
    }
}

/// Why a pinned helper may not be loaded by a new runner now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "pin", rename_all = "snake_case")]
pub enum PinRefusal {
    /// The catalog quarantined the bundle: its trust was withdrawn (a revoked key) or it
    /// failed verification. It is kept, never served.
    Quarantined { reason: IntegrityFailure },
    /// No such helper object is published in the host scope.
    NotPublished,
    /// The pin's object is not the identity of its bundle as a host helper.
    Inconsistent,
    /// This host's loader no longer provides the helper's ABI.
    IncompatibleAbi { refusal: HelperAbiRefusal },
}

impl fmt::Display for PinRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Quarantined { .. } => f.write_str("the helper bundle is quarantined"),
            Self::NotPublished => f.write_str("the helper bundle is not published"),
            Self::Inconsistent => f.write_str("the helper pin does not name its own bundle"),
            Self::IncompatibleAbi { refusal } => refusal.fmt(f),
        }
    }
}

impl std::error::Error for PinRefusal {}

/// Whether a pinned helper may be loaded by a new runner now. The catalog-backed check is
/// [`HelperAdmission::admissibility`](super::HelperAdmission::admissibility); runner
/// support is checked from the pin itself.
pub trait PinAdmissibility {
    fn check(&self, pin: &HelperPin) -> Result<(), PinRefusal>;
}
