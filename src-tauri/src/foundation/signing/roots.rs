//! The trust-root configuration (S2 CORE-08, line 206; VM part §8.3, line 2444: "offline
//! roots, delegated online keys, expiry, rollback protection, revoked releases and key
//! rotation. A single permanent signing key plus hashes is insufficient"; VM-W45, line
//! 2657: "trust roots, key rotation, expiry/version checks ... emergency revocation").
//!
//! The owner writes the trust roots as one JSON file, read strictly: an unknown field, an
//! unknown format version, algorithm or artifact class, a malformed key, an empty set or
//! a duplicate is refused with a typed error, never skipped. No key ships in code; which
//! keys are release roots is the owner's choice. Every key has:
//!
//! - an `id`, unique in the file, and an `algorithm`; only `ed25519` is known;
//! - its `public_key` in hexadecimal, unique in the file, so one key is one publisher;
//! - the artifact `classes` it may sign. Artifact classes keep distinct trust policies
//!   (S2 CORE-08), so a key signs nothing outside its classes;
//! - a validity window from `valid_from` (inclusive) to `valid_until` (exclusive). Every
//!   key expires: there is no permanent key;
//! - optionally `replaces`: the earlier key this one rotates from. A rotation starts
//!   after its predecessor started, no later than the predecessor ends (no gap) and ends
//!   after it. Each key is replaced at most once, and rotations never form a cycle. Both
//!   keys verify during the overlap; the predecessor stops at its own `valid_until`;
//! - optionally `revoked`, with a short reason (emergency revocation). A revoked key
//!   verifies nothing at any time, because a signature carries no trustworthy signing
//!   time, and [`TrustRoots::policy_for`] no longer trusts it, so the catalog quarantines
//!   what it admitted once the new policy is set.
//!
//! What this narrower design leaves out, as line 2444 asks to record: the file is trusted
//! because the owner placed it; it is neither signed nor threshold-signed, and it carries
//! no version counter, so a rollback of the file itself is not detected. The sandbox
//! update client (VM-W45) keeps its own signed, versioned and threshold-checked root
//! metadata for updates and can take its initial keys from this file.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, PoisonError, RwLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::ed25519::{Ed25519Error, Ed25519PublicKey};
use crate::foundation::catalog::{ArtifactClass, PublisherId, TrustPolicy};
use crate::foundation::ids::{validate_identifier, Digest, IdError};
use crate::foundation::report::Label;

/// The trust-root file format this build reads. Another version is refused, never
/// reinterpreted.
pub const TRUST_ROOTS_FORMAT: u64 = 1;

/// Largest trust-root file read.
pub const MAX_TRUST_ROOTS_BYTES: u64 = 1 << 20;

/// Most keys one trust-root file may hold.
pub const MAX_TRUST_ROOT_KEYS: usize = 256;

/// The id of one key in the trust roots: 1–128 letters, digits, '.', '_', ':' or '-',
/// starting with a letter or digit (the shared identifier rule).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RootKeyId(String);

impl RootKeyId {
    /// Checks `value` against the shared identifier rule.
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for RootKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RootKeyId({})", self.0)
    }
}

impl fmt::Display for RootKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A signature algorithm a trust root may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyAlgorithm {
    /// Ed25519 (RFC 8032), verified by [`super::verify_ed25519`].
    Ed25519,
}

impl KeyAlgorithm {
    /// Every known algorithm.
    pub const ALL: [Self; 1] = [Self::Ed25519];

    /// The tag written in the trust-root file.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
        }
    }

    /// The algorithm written as `tag`, if it is known.
    pub fn from_tag(tag: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.tag() == tag)
    }
}

impl fmt::Display for KeyAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// An emergency revocation of one key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct KeyRevocation {
    /// Why it was revoked, such as `key-compromise`.
    pub reason: Label,
}

/// One key of the trust roots, checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedKey {
    id: RootKeyId,
    algorithm: KeyAlgorithm,
    public_key: Ed25519PublicKey,
    classes: BTreeSet<ArtifactClass>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    replaces: Option<RootKeyId>,
    revocation: Option<KeyRevocation>,
}

impl TrustedKey {
    pub fn id(&self) -> &RootKeyId {
        &self.id
    }

    pub fn algorithm(&self) -> KeyAlgorithm {
        self.algorithm
    }

    pub fn public_key(&self) -> &Ed25519PublicKey {
        &self.public_key
    }

    /// The catalog's publisher identity for this key ([`Ed25519PublicKey::publisher_id`]).
    pub fn publisher_id(&self) -> PublisherId {
        self.public_key.publisher_id()
    }

    /// The artifact classes this key may sign; never empty.
    pub fn classes(&self) -> &BTreeSet<ArtifactClass> {
        &self.classes
    }

    /// The first instant the key is valid.
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }

    /// The first instant the key is no longer valid; always after [`Self::valid_from`].
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }

    /// The key this one rotates from.
    pub fn replaces(&self) -> Option<&RootKeyId> {
        self.replaces.as_ref()
    }

    pub fn revocation(&self) -> Option<&KeyRevocation> {
        self.revocation.as_ref()
    }

    pub fn is_revoked(&self) -> bool {
        self.revocation.is_some()
    }

    /// Whether this key may vouch for `class` at `at`: not revoked, allowed the class, and
    /// inside its validity window. Revocation is checked first, so a revoked key is
    /// always reported as revoked.
    pub fn check(&self, class: ArtifactClass, at: DateTime<Utc>) -> Result<(), KeyRefusal> {
        if let Some(revocation) = &self.revocation {
            return Err(KeyRefusal::Revoked {
                key: self.id.clone(),
                reason: revocation.reason.clone(),
            });
        }
        if !self.classes.contains(&class) {
            return Err(KeyRefusal::ClassNotAllowed {
                key: self.id.clone(),
                class,
            });
        }
        if at < self.valid_from {
            return Err(KeyRefusal::NotYetValid {
                key: self.id.clone(),
                valid_from: self.valid_from,
            });
        }
        if at >= self.valid_until {
            return Err(KeyRefusal::Expired {
                key: self.id.clone(),
                valid_until: self.valid_until,
            });
        }
        Ok(())
    }
}

/// Why a key did not vouch for a statement.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum KeyRefusal {
    /// No key of the trust roots is this publisher's.
    UnknownPublisher { publisher: PublisherId },
    /// The key was revoked; it verifies nothing.
    Revoked { key: RootKeyId, reason: Label },
    /// The key may not sign this artifact class.
    ClassNotAllowed {
        key: RootKeyId,
        class: ArtifactClass,
    },
    /// The key's validity window has not started.
    NotYetValid {
        key: RootKeyId,
        valid_from: DateTime<Utc>,
    },
    /// The key's validity window has ended.
    Expired {
        key: RootKeyId,
        valid_until: DateTime<Utc>,
    },
    /// The signature does not verify under the key.
    Signature { key: RootKeyId, error: Ed25519Error },
}

impl fmt::Display for KeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownPublisher { publisher } => {
                write!(f, "no trust-root key belongs to publisher {publisher}")
            }
            Self::Revoked { key, reason } => {
                write!(f, "trust-root key {key} is revoked ({})", reason.as_str())
            }
            Self::ClassNotAllowed { key, class } => {
                write!(f, "trust-root key {key} may not sign {class}")
            }
            Self::NotYetValid { key, valid_from } => write!(
                f,
                "trust-root key {key} is valid only from {}",
                valid_from.to_rfc3339()
            ),
            Self::Expired { key, valid_until } => write!(
                f,
                "trust-root key {key} expired at {}",
                valid_until.to_rfc3339()
            ),
            Self::Signature { key, error } => {
                write!(
                    f,
                    "the signature by trust-root key {key} is refused: {error}"
                )
            }
        }
    }
}

impl std::error::Error for KeyRefusal {}

/// Why a trust-root file was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TrustRootError {
    /// The file could not be read.
    Unreadable {
        detail: String,
    },
    /// The file is larger than [`MAX_TRUST_ROOTS_BYTES`].
    TooLarge {
        max_bytes: u64,
    },
    /// The text is not a trust-root document: bad JSON, an unknown or missing field, an
    /// unknown artifact class, a bad time or reason. Located, never quoted.
    Malformed {
        line: usize,
        column: usize,
    },
    /// The document is in another format version.
    UnsupportedFormat {
        found: u64,
    },
    /// The document lists no key: an empty trust root would trust nothing silently.
    NoKeys,
    /// More than [`MAX_TRUST_ROOT_KEYS`] keys.
    TooManyKeys {
        max: usize,
    },
    /// The key at `index` (from zero) has an id that breaks the identifier rule.
    InvalidKeyId {
        index: usize,
        error: IdError,
    },
    DuplicateKeyId {
        id: RootKeyId,
    },
    UnknownAlgorithm {
        id: RootKeyId,
    },
    MalformedPublicKey {
        id: RootKeyId,
        error: Ed25519Error,
    },
    /// Two ids name the same public key.
    DuplicatePublicKey {
        id: RootKeyId,
        same_as: RootKeyId,
    },
    NoClasses {
        id: RootKeyId,
    },
    DuplicateClass {
        id: RootKeyId,
        class: ArtifactClass,
    },
    /// `valid_until` is not after `valid_from`.
    EmptyValidity {
        id: RootKeyId,
    },
    /// `replaces` names no key of the file.
    UnknownPredecessor {
        id: RootKeyId,
    },
    /// Two keys replace the same key.
    ForkedRotation {
        replaced: RootKeyId,
        first: RootKeyId,
        second: RootKeyId,
    },
    /// Following `replaces` from this key comes back to it.
    RotationCycle {
        id: RootKeyId,
    },
    /// The rotation's window does not start after the predecessor's start and no later
    /// than its end, or does not end after it.
    RotationWindow {
        id: RootKeyId,
        replaces: RootKeyId,
    },
}

impl fmt::Display for TrustRootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreadable { detail } => write!(f, "the trust roots could not be read: {detail}"),
            Self::TooLarge { max_bytes } => {
                write!(f, "the trust-root file is larger than {max_bytes} bytes")
            }
            Self::Malformed { line, column } => write!(
                f,
                "the trust roots are malformed at line {line}, column {column}"
            ),
            Self::UnsupportedFormat { found } => write!(
                f,
                "trust-root format {found} is not supported; this build reads format \
                 {TRUST_ROOTS_FORMAT}"
            ),
            Self::NoKeys => f.write_str("the trust roots list no key"),
            Self::TooManyKeys { max } => write!(f, "the trust roots list more than {max} keys"),
            Self::InvalidKeyId { index, error } => {
                write!(f, "trust-root key {index} has an invalid id: {error}")
            }
            Self::DuplicateKeyId { id } => write!(f, "trust-root key id {id} appears twice"),
            Self::UnknownAlgorithm { id } => {
                write!(f, "trust-root key {id} uses an unknown algorithm")
            }
            Self::MalformedPublicKey { id, error } => {
                write!(f, "trust-root key {id} has a malformed public key: {error}")
            }
            Self::DuplicatePublicKey { id, same_as } => write!(
                f,
                "trust-root key {id} has the same public key as {same_as}"
            ),
            Self::NoClasses { id } => write!(f, "trust-root key {id} may sign no class"),
            Self::DuplicateClass { id, class } => {
                write!(f, "trust-root key {id} lists {class} twice")
            }
            Self::EmptyValidity { id } => write!(
                f,
                "trust-root key {id} has a validity window that ends before it starts"
            ),
            Self::UnknownPredecessor { id } => {
                write!(
                    f,
                    "trust-root key {id} replaces a key the file does not list"
                )
            }
            Self::ForkedRotation {
                replaced,
                first,
                second,
            } => write!(
                f,
                "trust-root keys {first} and {second} both replace {replaced}"
            ),
            Self::RotationCycle { id } => {
                write!(f, "the rotations from trust-root key {id} form a cycle")
            }
            Self::RotationWindow { id, replaces } => write!(
                f,
                "trust-root key {id} must start after {replaces} starts, no later than it \
                 ends, and end after it"
            ),
        }
    }
}

impl std::error::Error for TrustRootError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RootsWire {
    format: u64,
    keys: Vec<KeyWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyWire {
    id: String,
    algorithm: String,
    public_key: String,
    classes: Vec<ArtifactClass>,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
    replaces: Option<String>,
    revoked: Option<RevocationWire>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RevocationWire {
    reason: Label,
}

/// The configured trust roots: checked keys, each found by id and by publisher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustRoots {
    keys: BTreeMap<RootKeyId, TrustedKey>,
    publishers: BTreeMap<PublisherId, RootKeyId>,
}

impl TrustRoots {
    /// Reads and checks the trust-root file at `path`.
    pub fn load(path: &Path) -> Result<Self, TrustRootError> {
        let unreadable = |error: std::io::Error| TrustRootError::Unreadable {
            detail: error.to_string(),
        };
        let mut text = String::new();
        File::open(path)
            .map_err(unreadable)?
            .take(MAX_TRUST_ROOTS_BYTES.saturating_add(1))
            .read_to_string(&mut text)
            .map_err(unreadable)?;
        if u64::try_from(text.len()).unwrap_or(u64::MAX) > MAX_TRUST_ROOTS_BYTES {
            return Err(TrustRootError::TooLarge {
                max_bytes: MAX_TRUST_ROOTS_BYTES,
            });
        }
        Self::from_json(&text)
    }

    /// Checks a trust-root document. A document of another format version is refused for
    /// its version, never for contents that version may define differently.
    pub fn from_json(text: &str) -> Result<Self, TrustRootError> {
        #[derive(Deserialize)]
        struct Versioned {
            format: u64,
        }
        let wire: RootsWire =
            serde_json::from_str(text).map_err(|error| {
                match serde_json::from_str::<Versioned>(text) {
                    Ok(Versioned { format }) if format != TRUST_ROOTS_FORMAT => {
                        TrustRootError::UnsupportedFormat { found: format }
                    }
                    _ => malformed(error),
                }
            })?;
        if wire.format != TRUST_ROOTS_FORMAT {
            return Err(TrustRootError::UnsupportedFormat { found: wire.format });
        }
        Self::check(wire.keys)
    }

    fn check(listed: Vec<KeyWire>) -> Result<Self, TrustRootError> {
        if listed.is_empty() {
            return Err(TrustRootError::NoKeys);
        }
        if listed.len() > MAX_TRUST_ROOT_KEYS {
            return Err(TrustRootError::TooManyKeys {
                max: MAX_TRUST_ROOT_KEYS,
            });
        }
        let mut keys = BTreeMap::new();
        let mut publishers = BTreeMap::new();
        let mut predecessors = Vec::new();
        for (index, wire) in listed.into_iter().enumerate() {
            let (key, replaces) = check_key(index, wire)?;
            if keys.contains_key(&key.id) {
                return Err(TrustRootError::DuplicateKeyId { id: key.id });
            }
            if let Some(same_as) = publishers.insert(key.publisher_id(), key.id.clone()) {
                return Err(TrustRootError::DuplicatePublicKey {
                    id: key.id.clone(),
                    same_as,
                });
            }
            predecessors.push((key.id.clone(), replaces));
            keys.insert(key.id.clone(), key);
        }
        for (id, replaces) in predecessors {
            if let Some(replaces) = replaces {
                let predecessor = RootKeyId::new(replaces)
                    .ok()
                    .filter(|predecessor| keys.contains_key(predecessor))
                    .ok_or_else(|| TrustRootError::UnknownPredecessor { id: id.clone() })?;
                if let Some(key) = keys.get_mut(&id) {
                    key.replaces = Some(predecessor);
                }
            }
        }
        check_rotations(&keys)?;
        Ok(Self { keys, publishers })
    }

    /// Every key, in id order.
    pub fn keys(&self) -> impl Iterator<Item = &TrustedKey> {
        self.keys.values()
    }

    /// The key with this id.
    pub fn key(&self, id: &RootKeyId) -> Option<&TrustedKey> {
        self.keys.get(id)
    }

    /// The key this publisher identity is the fingerprint of.
    pub fn key_for(&self, publisher: &PublisherId) -> Option<&TrustedKey> {
        self.publishers
            .get(publisher)
            .and_then(|id| self.keys.get(id))
    }

    /// The catalog trust policy for `class` (S2 CORE-08): it trusts every key that may
    /// sign the class and is not revoked, whatever its window, so objects admitted before
    /// a key expired keep their trust, and objects a revoked key admitted lose it when the
    /// catalog's policy is replaced (`Catalog::set_trust_policy`). Admitting a new object
    /// also needs the key's window, which [`Self::verify_statement`] checks. User-selected
    /// originals are the caller's to add.
    pub fn policy_for(&self, class: ArtifactClass) -> TrustPolicy {
        self.keys
            .values()
            .filter(|key| !key.is_revoked() && key.classes.contains(&class))
            .fold(TrustPolicy::new(), |policy, key| {
                policy.trust_publisher(key.publisher_id())
            })
    }

    /// The key of `publisher`, if it may vouch for `class` at `at` ([`TrustedKey::check`]).
    pub fn check_key(
        &self,
        publisher: &PublisherId,
        class: ArtifactClass,
        at: DateTime<Utc>,
    ) -> Result<&TrustedKey, KeyRefusal> {
        let key = self
            .key_for(publisher)
            .ok_or(KeyRefusal::UnknownPublisher {
                publisher: *publisher,
            })?;
        key.check(class, at)?;
        Ok(key)
    }

    /// Verifies `signature` as `publisher`'s signature over the domain-separated
    /// `statement` about an artifact of `class`, at calendar time `at`, and returns the key
    /// that vouched for it.
    pub fn verify_statement(
        &self,
        publisher: &PublisherId,
        class: ArtifactClass,
        statement: &Digest,
        signature: &[u8],
        at: DateTime<Utc>,
    ) -> Result<&TrustedKey, KeyRefusal> {
        let key = self.check_key(publisher, class, at)?;
        key.public_key
            .verify(statement.as_bytes(), signature)
            .map_err(|error| KeyRefusal::Signature {
                key: key.id.clone(),
                error,
            })?;
        Ok(key)
    }
}

fn malformed(error: serde_json::Error) -> TrustRootError {
    TrustRootError::Malformed {
        line: error.line(),
        column: error.column(),
    }
}

/// Checks one listed key; its predecessor is resolved once every key is known.
fn check_key(index: usize, wire: KeyWire) -> Result<(TrustedKey, Option<String>), TrustRootError> {
    let id =
        RootKeyId::new(wire.id).map_err(|error| TrustRootError::InvalidKeyId { index, error })?;
    let algorithm = KeyAlgorithm::from_tag(&wire.algorithm)
        .ok_or_else(|| TrustRootError::UnknownAlgorithm { id: id.clone() })?;
    let public_key = match algorithm {
        KeyAlgorithm::Ed25519 => Ed25519PublicKey::from_hex(&wire.public_key),
    }
    .map_err(|error| TrustRootError::MalformedPublicKey {
        id: id.clone(),
        error,
    })?;
    if wire.classes.is_empty() {
        return Err(TrustRootError::NoClasses { id });
    }
    let mut classes = BTreeSet::new();
    for class in wire.classes {
        if !classes.insert(class) {
            return Err(TrustRootError::DuplicateClass { id, class });
        }
    }
    if wire.valid_until <= wire.valid_from {
        return Err(TrustRootError::EmptyValidity { id });
    }
    let key = TrustedKey {
        id,
        algorithm,
        public_key,
        classes,
        valid_from: wire.valid_from,
        valid_until: wire.valid_until,
        replaces: None,
        revocation: wire.revoked.map(|revoked| KeyRevocation {
            reason: revoked.reason,
        }),
    };
    Ok((key, wire.replaces))
}

/// Refuses forks, cycles and rotation windows with a gap or going backwards.
fn check_rotations(keys: &BTreeMap<RootKeyId, TrustedKey>) -> Result<(), TrustRootError> {
    let mut successors: BTreeMap<&RootKeyId, &RootKeyId> = BTreeMap::new();
    for key in keys.values() {
        if let Some(replaced) = &key.replaces {
            if let Some(first) = successors.insert(replaced, &key.id) {
                return Err(TrustRootError::ForkedRotation {
                    replaced: replaced.clone(),
                    first: first.clone(),
                    second: key.id.clone(),
                });
            }
        }
    }
    for start in keys.values() {
        let mut current = start;
        for _ in 0..keys.len() {
            let Some(next) = current.replaces.as_ref().and_then(|id| keys.get(id)) else {
                break;
            };
            if next.id == start.id {
                return Err(TrustRootError::RotationCycle {
                    id: start.id.clone(),
                });
            }
            current = next;
        }
    }
    for key in keys.values() {
        let Some(predecessor) = key.replaces.as_ref().and_then(|id| keys.get(id)) else {
            continue;
        };
        let ordered = key.valid_from > predecessor.valid_from
            && key.valid_from <= predecessor.valid_until
            && key.valid_until > predecessor.valid_until;
        if !ordered {
            return Err(TrustRootError::RotationWindow {
                id: key.id.clone(),
                replaces: predecessor.id.clone(),
            });
        }
    }
    Ok(())
}

/// The trust roots in force, shared by the verifiers that read them and the owner action
/// that reloads them, so a rotation or revocation reaches every verifier at once.
#[derive(Clone, Debug)]
pub struct SharedTrustRoots {
    current: Arc<RwLock<Arc<TrustRoots>>>,
}

impl SharedTrustRoots {
    pub fn new(roots: TrustRoots) -> Self {
        Self {
            current: Arc::new(RwLock::new(Arc::new(roots))),
        }
    }

    /// The roots in force now. A writer only ever swaps one complete value in, so a
    /// poisoned lock still holds a complete value and is read through.
    pub fn current(&self) -> Arc<TrustRoots> {
        let guard = self.current.read().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(&guard)
    }

    /// Puts `roots` in force and returns the roots they replace. The caller then sets
    /// the catalog's policies from the new roots ([`TrustRoots::policy_for`]).
    pub fn replace(&self, roots: TrustRoots) -> Arc<TrustRoots> {
        let mut guard = self.current.write().unwrap_or_else(PoisonError::into_inner);
        std::mem::replace(&mut *guard, Arc::new(roots))
    }
}
