//! XOR delta versions against a pinned base (GPU §4.2 line 679; GPU-W12 "Exact checkpoint
//! delta representations").
//!
//! A version is stored as the zstd-encoded XOR of its bytes with its parent's, where the
//! parent is the pinned base or another stored version. Every version is reconstructed
//! bit-exactly and checked against its content key before it is stored, chains are
//! bounded by a configured depth, reconstruction needs the base, and a base cannot be
//! unpinned or removed while a version depends on it; deltas are made only against a
//! pinned base. [`DeltaStore::decide`] compares
//! each version with independent compression and abandons a chain that makes cold
//! recovery slower or fragile.

use std::collections::BTreeMap;
use std::fmt;

use crate::foundation::ids::ContentKey;
use crate::model_memory::math::{positive, InputError};

use super::codec::{decode_bounded, encode, CodecError};

/// Why a delta operation was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum DeltaError {
    /// The depth bound must allow at least one delta.
    ZeroDepthBound,
    UnknownBase {
        base: ContentKey,
    },
    UnknownVersion {
        version: ContentKey,
    },
    /// The bytes are already stored as a base or a version.
    AlreadyStored {
        key: ContentKey,
    },
    /// XOR needs equal lengths; nothing is padded.
    LengthMismatch {
        parent_bytes: u64,
        version_bytes: u64,
    },
    DepthExceeded {
        depth: u32,
        max_depth: u32,
    },
    /// Reconstruction needs the base, and it is not available.
    BaseUnavailable {
        base: ContentKey,
    },
    /// Deltas are made only against a pinned base.
    BaseNotPinned {
        base: ContentKey,
    },
    /// A pinned base with dependents is neither unpinned nor removed.
    BaseHasDependents {
        base: ContentKey,
        dependents: usize,
    },
    /// A stored object decoded to bytes with another content key.
    ReconstructionMismatch {
        key: ContentKey,
    },
    Codec(CodecError),
    Input(InputError),
}

impl From<CodecError> for DeltaError {
    fn from(error: CodecError) -> Self {
        Self::Codec(error)
    }
}

impl From<InputError> for DeltaError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl fmt::Display for DeltaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroDepthBound => f.write_str("the delta depth bound must be at least 1"),
            Self::UnknownBase { base } => write!(f, "no base {base}"),
            Self::UnknownVersion { version } => write!(f, "no version {version}"),
            Self::AlreadyStored { key } => write!(f, "{key} is already stored"),
            Self::LengthMismatch {
                parent_bytes,
                version_bytes,
            } => write!(
                f,
                "a {version_bytes}-byte version cannot be a delta of a {parent_bytes}-byte parent"
            ),
            Self::DepthExceeded { depth, max_depth } => {
                write!(f, "delta depth {depth} exceeds the bound {max_depth}")
            }
            Self::BaseUnavailable { base } => write!(f, "base {base} is not available"),
            Self::BaseNotPinned { base } => write!(f, "base {base} is not pinned"),
            Self::BaseHasDependents { base, dependents } => {
                write!(f, "base {base} still has {dependents} dependent versions")
            }
            Self::ReconstructionMismatch { key } => {
                write!(f, "reconstruction of {key} produced other bytes")
            }
            Self::Codec(error) => error.fmt(f),
            Self::Input(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for DeltaError {}

/// The configured bounds of a delta store. The plan gives no depth, so it is required
/// configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeltaLimits {
    max_depth: u32,
    level: i32,
}

impl DeltaLimits {
    /// `max_depth` deltas at most between a version and its base; zero is refused.
    pub fn new(max_depth: u32, level: i32) -> Result<Self, DeltaError> {
        if max_depth == 0 {
            return Err(DeltaError::ZeroDepthBound);
        }
        Ok(Self { max_depth, level })
    }

    /// The most deltas between a version and its base (§4.2: bounded dependency depth).
    pub const fn max_depth(&self) -> u32 {
        self.max_depth
    }
}

/// What a version is a delta of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Parent {
    Base(ContentKey),
    Version(ContentKey),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BaseObject {
    length_bytes: u64,
    stored: Vec<u8>,
    pinned: bool,
    available: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct DeltaObject {
    parent: Parent,
    base: ContentKey,
    depth: u32,
    length_bytes: u64,
    delta: Vec<u8>,
    independent_stored_bytes: u64,
}

/// Rates of a cold recovery: nothing resident, every object read from storage.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ColdRecoveryCost {
    pub read_bytes_per_second: f64,
    pub decode_raw_bytes_per_second: f64,
    pub xor_bytes_per_second: f64,
}

/// One version as a delta chain and as independent compression.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct DeltaComparison {
    pub version_bytes: u64,
    pub depth: u32,
    /// What keeping this version as a delta adds to storage.
    pub delta_stored_bytes: u64,
    /// What keeping it independently compressed would add.
    pub independent_stored_bytes: u64,
    /// The base and every delta of the chain, all read in a cold recovery.
    pub chain_read_bytes: u64,
    /// Objects that must all be readable to recover it: depth + 1.
    pub objects_needed: u32,
    /// `chain_read/read + (depth+1)·S/decode + depth·S/xor`.
    pub delta_recovery_seconds: f64,
    /// `independent/read + S/decode`.
    pub independent_recovery_seconds: f64,
}

/// Why a delta chain is abandoned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AbandonReason {
    /// The delta is not strictly smaller than independent compression.
    NoStorageSaving,
    /// Cold recovery through the chain is slower than independent decompression.
    SlowerColdRecovery,
    /// The base cannot be read now, so every version of the chain is unrecoverable.
    BaseUnavailable,
}

/// Whether a version stays a delta (GPU §4.2: "abandon delta chains that make cold
/// recovery slower or fragile").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DeltaDecision {
    Keep,
    Abandon(Vec<AbandonReason>),
}

/// Bases and XOR delta versions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeltaStore {
    limits: DeltaLimits,
    bases: BTreeMap<ContentKey, BaseObject>,
    versions: BTreeMap<ContentKey, DeltaObject>,
}

fn xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter().zip(right).map(|(a, b)| a ^ b).collect()
}

impl DeltaStore {
    /// An empty store under `limits`.
    pub fn new(limits: DeltaLimits) -> Self {
        Self {
            limits,
            bases: BTreeMap::new(),
            versions: BTreeMap::new(),
        }
    }

    fn known(&self, key: &ContentKey) -> bool {
        self.bases.contains_key(key) || self.versions.contains_key(key)
    }

    /// Stores and pins a base, compressed independently.
    pub fn add_base(&mut self, bytes: &[u8]) -> Result<ContentKey, DeltaError> {
        let key = ContentKey::of(bytes);
        if self.known(&key) {
            return Err(DeltaError::AlreadyStored { key });
        }
        let stored = encode(bytes, self.limits.level, None)?;
        if decode_bounded(&stored, None, bytes.len() as u64)? != bytes {
            return Err(DeltaError::ReconstructionMismatch { key });
        }
        self.bases.insert(
            key,
            BaseObject {
                length_bytes: bytes.len() as u64,
                stored,
                pinned: true,
                available: true,
            },
        );
        Ok(key)
    }

    /// Versions whose chain ends at `base`.
    pub fn dependents(&self, base: &ContentKey) -> usize {
        self.versions
            .values()
            .filter(|version| &version.base == base)
            .count()
    }

    fn base(&self, base: &ContentKey) -> Result<&BaseObject, DeltaError> {
        self.bases
            .get(base)
            .ok_or(DeltaError::UnknownBase { base: *base })
    }

    fn refuse_with_dependents(&self, base: &ContentKey) -> Result<(), DeltaError> {
        self.base(base)?;
        match self.dependents(base) {
            0 => Ok(()),
            dependents => Err(DeltaError::BaseHasDependents {
                base: *base,
                dependents,
            }),
        }
    }

    /// Unpins a base; refused while any version depends on it.
    pub fn unpin_base(&mut self, base: &ContentKey) -> Result<(), DeltaError> {
        self.refuse_with_dependents(base)?;
        if let Some(object) = self.bases.get_mut(base) {
            object.pinned = false;
        }
        Ok(())
    }

    /// Removes a base; refused while any version depends on it.
    pub fn remove_base(&mut self, base: &ContentKey) -> Result<(), DeltaError> {
        self.refuse_with_dependents(base)?;
        self.bases.remove(base);
        Ok(())
    }

    /// Records whether the base's storage can be read now, as a catalog or storage
    /// probe reports it.
    pub fn set_base_available(
        &mut self,
        base: &ContentKey,
        available: bool,
    ) -> Result<(), DeltaError> {
        let object = self
            .bases
            .get_mut(base)
            .ok_or(DeltaError::UnknownBase { base: *base })?;
        object.available = available;
        Ok(())
    }

    /// Whether `base` is pinned; `None` for an unknown base.
    pub fn is_pinned(&self, base: &ContentKey) -> Option<bool> {
        self.bases.get(base).map(|object| object.pinned)
    }

    /// The chain depth of `version`: 1 for a delta of the base.
    pub fn depth(&self, version: &ContentKey) -> Option<u32> {
        self.versions.get(version).map(|object| object.depth)
    }

    fn base_bytes(&self, base: &ContentKey) -> Result<Vec<u8>, DeltaError> {
        let object = self.base(base)?;
        if !object.available {
            return Err(DeltaError::BaseUnavailable { base: *base });
        }
        let bytes = decode_bounded(&object.stored, None, object.length_bytes)?;
        if ContentKey::of(&bytes) != *base {
            return Err(DeltaError::ReconstructionMismatch { key: *base });
        }
        Ok(bytes)
    }

    fn parent_bytes(&self, parent: &Parent) -> Result<(Vec<u8>, u32, ContentKey), DeltaError> {
        match parent {
            Parent::Base(base) => {
                if !self.base(base)?.pinned {
                    return Err(DeltaError::BaseNotPinned { base: *base });
                }
                Ok((self.base_bytes(base)?, 0, *base))
            }
            Parent::Version(version) => {
                let object = self
                    .versions
                    .get(version)
                    .ok_or(DeltaError::UnknownVersion { version: *version })?;
                Ok((self.reconstruct(version)?, object.depth, object.base))
            }
        }
    }

    /// Stores `bytes` as a delta of `parent`. The delta is decoded and checked against
    /// the version's content key before it is stored, so only bit-exact versions enter.
    pub fn add_version(&mut self, parent: Parent, bytes: &[u8]) -> Result<ContentKey, DeltaError> {
        let key = ContentKey::of(bytes);
        if self.known(&key) {
            return Err(DeltaError::AlreadyStored { key });
        }
        let (parent_bytes, parent_depth, base) = self.parent_bytes(&parent)?;
        if parent_bytes.len() != bytes.len() {
            return Err(DeltaError::LengthMismatch {
                parent_bytes: parent_bytes.len() as u64,
                version_bytes: bytes.len() as u64,
            });
        }
        let depth = parent_depth.saturating_add(1);
        if depth > self.limits.max_depth {
            return Err(DeltaError::DepthExceeded {
                depth,
                max_depth: self.limits.max_depth,
            });
        }
        let delta = encode(&xor(&parent_bytes, bytes), self.limits.level, None)?;
        let decoded = decode_bounded(&delta, None, bytes.len() as u64)?;
        if ContentKey::of(&xor(&parent_bytes, &decoded)) != key {
            return Err(DeltaError::ReconstructionMismatch { key });
        }
        let independent_stored_bytes = encode(bytes, self.limits.level, None)?.len() as u64;
        self.versions.insert(
            key,
            DeltaObject {
                parent,
                base,
                depth,
                length_bytes: bytes.len() as u64,
                delta,
                independent_stored_bytes,
            },
        );
        Ok(key)
    }

    /// The chain from the version nearest the base down to `version`.
    fn chain(&self, version: &ContentKey) -> Result<Vec<(ContentKey, &DeltaObject)>, DeltaError> {
        let mut chain = Vec::new();
        let mut current = *version;
        loop {
            let object = self
                .versions
                .get(&current)
                .ok_or(DeltaError::UnknownVersion { version: current })?;
            chain.push((current, object));
            match object.parent {
                Parent::Base(_) => break,
                Parent::Version(parent) => current = parent,
            }
            let depth = u32::try_from(chain.len()).unwrap_or(u32::MAX);
            if depth > self.limits.max_depth {
                return Err(DeltaError::DepthExceeded {
                    depth,
                    max_depth: self.limits.max_depth,
                });
            }
        }
        chain.reverse();
        Ok(chain)
    }

    /// Rebuilds `version` from its base and every delta of its chain, checking each
    /// intermediate version's content key. Refused without the base.
    pub fn reconstruct(&self, version: &ContentKey) -> Result<Vec<u8>, DeltaError> {
        let chain = self.chain(version)?;
        let base = chain
            .first()
            .map(|(_, object)| object.base)
            .ok_or(DeltaError::UnknownVersion { version: *version })?;
        let mut bytes = self.base_bytes(&base)?;
        for (key, object) in chain {
            let delta = decode_bounded(&object.delta, None, object.length_bytes)?;
            if delta.len() != bytes.len() {
                return Err(DeltaError::ReconstructionMismatch { key });
            }
            bytes = xor(&bytes, &delta);
            if ContentKey::of(&bytes) != key {
                return Err(DeltaError::ReconstructionMismatch { key });
            }
        }
        Ok(bytes)
    }

    /// Compares `version` as a delta chain with independent compression.
    pub fn compare(
        &self,
        version: &ContentKey,
        cost: &ColdRecoveryCost,
    ) -> Result<DeltaComparison, DeltaError> {
        let read = positive("read_bytes_per_second", cost.read_bytes_per_second)?;
        let decode = positive(
            "decode_raw_bytes_per_second",
            cost.decode_raw_bytes_per_second,
        )?;
        let xor_rate = positive("xor_bytes_per_second", cost.xor_bytes_per_second)?;
        let chain = self.chain(version)?;
        let (_, last) = chain
            .last()
            .ok_or(DeltaError::UnknownVersion { version: *version })?;
        let base = self.base(&last.base)?;
        let chain_read_bytes = chain
            .iter()
            .fold(base.stored.len() as u64, |total, (_, object)| {
                total.saturating_add(object.delta.len() as u64)
            });
        let size = last.length_bytes as f64;
        let depth = last.depth;
        Ok(DeltaComparison {
            version_bytes: last.length_bytes,
            depth,
            delta_stored_bytes: last.delta.len() as u64,
            independent_stored_bytes: last.independent_stored_bytes,
            chain_read_bytes,
            objects_needed: depth.saturating_add(1),
            delta_recovery_seconds: chain_read_bytes as f64 / read
                + f64::from(depth.saturating_add(1)) * size / decode
                + f64::from(depth) * size / xor_rate,
            independent_recovery_seconds: last.independent_stored_bytes as f64 / read
                + size / decode,
        })
    }

    /// Keeps `version` as a delta only when it is strictly smaller than independent
    /// compression, its cold recovery is not slower, and its base is available. (Its base
    /// is pinned: deltas are made only against pinned bases, which stay pinned while
    /// they have dependents.)
    pub fn decide(
        &self,
        version: &ContentKey,
        cost: &ColdRecoveryCost,
    ) -> Result<DeltaDecision, DeltaError> {
        let comparison = self.compare(version, cost)?;
        let base_key = self
            .versions
            .get(version)
            .map(|object| object.base)
            .ok_or(DeltaError::UnknownVersion { version: *version })?;
        let base = self.base(&base_key)?;
        let mut reasons = Vec::new();
        if comparison.delta_stored_bytes >= comparison.independent_stored_bytes {
            reasons.push(AbandonReason::NoStorageSaving);
        }
        if comparison.delta_recovery_seconds > comparison.independent_recovery_seconds {
            reasons.push(AbandonReason::SlowerColdRecovery);
        }
        if !base.available {
            reasons.push(AbandonReason::BaseUnavailable);
        }
        Ok(if reasons.is_empty() {
            DeltaDecision::Keep
        } else {
            DeltaDecision::Abandon(reasons)
        })
    }
}
