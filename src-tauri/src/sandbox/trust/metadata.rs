//! The narrow TUF-style metadata of VM-D13 (line 3032: "TUF-style narrow design"),
//! documented here as the plan asks (line 2280: "reuse a supported implementation or
//! explicitly document the narrower verified design").
//!
//! Five roles, each with its own keys and threshold in the root:
//!
//! - **root** (offline keys): lists every key and every role's keys and threshold. A new
//!   root is accepted only when signed by the threshold of the previous root's root keys
//!   *and* the threshold of its own root keys (key rotation), and only at the next
//!   version (no gap, no rollback).
//! - **timestamp** (online key, short expiry): names the exact snapshot file by version,
//!   length and digest. A stale timestamp is a freeze; an older one is a rollback.
//! - **snapshot** (online key): names the exact targets file by version, length and
//!   digest, so targets and snapshot cannot be mixed from different releases.
//! - **targets** (online key): names each release artifact by class, length and content
//!   key. Nothing is delegated further; this is the narrow part.
//! - **revocation** (offline emergency keys): a version-numbered list of revoked content
//!   keys that applies without a fresh timestamp and is never undone by omission.
//!
//! Every file has a version and, except the revocation list, an expiry; a client refuses
//! any version lower than the one it trusts, and expired metadata is a refusal also when
//! offline. Signatures are over the digest of the canonical form of the signed payload,
//! and a file is referenced by the digest of its whole canonical form, so a file that was
//! altered anywhere no longer matches its reference (lines 2493, 2502, 2623).
//!
//! The canonical form is compact JSON with object keys in sorted order, which is what
//! `serde_json` writes for a [`serde_json::Value`]. Signing tooling must produce the
//! same form; a signature over any other serialization of the same payload does not
//! verify, which is intended.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use super::signature::{KeyId, PublicKey, SchemeRegistry, Signature, SignatureRejection};
use super::time::UnixSeconds;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::ids::{
    digest, validate_identifier, ContentKey, Digest, DigestBuilder, IdError,
};

/// Domain of the message a signature covers: the role and the canonical signed payload.
pub const METADATA_DOMAIN: &str = "yougori/sandbox/trust/metadata/v1";
/// Domain of a file reference: the whole canonical file, signatures included.
pub const FILE_DOMAIN: &str = "yougori/sandbox/trust/metadata-file/v1";
/// Longest accepted revocation reason.
pub const MAX_REASON_BYTES: usize = 256;

/// The five roles of the narrow design.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Root,
    Timestamp,
    Snapshot,
    Targets,
    Revocation,
}

impl Role {
    pub const ALL: [Self; 5] = [
        Self::Root,
        Self::Timestamp,
        Self::Snapshot,
        Self::Targets,
        Self::Revocation,
    ];

    /// The stable tag hashed into signed messages.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Root => "root",
            Self::Timestamp => "timestamp",
            Self::Snapshot => "snapshot",
            Self::Targets => "targets",
            Self::Revocation => "revocation",
        }
    }

    /// Whether the role's keys are delegated online keys (line 2280 "delegated online
    /// keys"); root and revocation keys stay offline.
    pub const fn is_online(self) -> bool {
        matches!(self, Self::Timestamp | Self::Snapshot | Self::Targets)
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.tag())
    }
}

/// A metadata version; versions start at 1 and only rise.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct MetadataVersion(u64);

impl MetadataVersion {
    pub const FIRST: Self = Self(1);

    pub const fn new(version: u64) -> Self {
        Self(version)
    }

    pub const fn get(self) -> u64 {
        self.0
    }

    /// The following version; `None` at `u64::MAX`.
    pub fn next(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }
}

impl fmt::Display for MetadataVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// The keys of one role and how many of them must sign.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleKeys {
    pub key_ids: BTreeSet<KeyId>,
    pub threshold: u32,
}

impl RoleKeys {
    pub fn new(key_ids: impl IntoIterator<Item = KeyId>, threshold: u32) -> Self {
        Self {
            key_ids: key_ids.into_iter().collect(),
            threshold,
        }
    }
}

/// A name of a target or release: the shared identifier grammar.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct TargetName(String);

impl TargetName {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TargetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TargetName({})", self.0)
    }
}

impl fmt::Display for TargetName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for TargetName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// An exact release version label, such as `2026.10.3`; compared exactly, never ordered.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct ReleaseVersion(String);

impl ReleaseVersion {
    pub fn new(value: impl Into<String>) -> Result<Self, IdError> {
        let value = value.into();
        validate_identifier(&value)?;
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ReleaseVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ReleaseVersion({})", self.0)
    }
}

impl fmt::Display for ReleaseVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ReleaseVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Why a metadata payload is malformed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum MetadataError {
    /// The payload declares another role than the one it is used as.
    WrongRole {
        expected: Role,
        found: Role,
    },
    ZeroVersion {
        role: Role,
    },
    /// A listed key id is not the digest of the key beside it.
    KeyIdMismatch {
        claimed: KeyId,
        computed: KeyId,
    },
    MissingRole {
        role: Role,
    },
    ZeroThreshold {
        role: Role,
    },
    ThresholdAboveKeys {
        role: Role,
        threshold: u32,
        keys: u32,
    },
    /// A role names a key the root does not list.
    UnknownKey {
        role: Role,
        key_id: KeyId,
    },
    /// An online role would use an offline root key (line 2280).
    OnlineRoleUsesRootKey {
        role: Role,
        key_id: KeyId,
    },
    /// The payload does not parse as the role's schema.
    Malformed {
        detail: String,
    },
    /// The payload could not be written in canonical form.
    Unencodable {
        detail: String,
    },
    /// A revocation names no reason, or one longer than [`MAX_REASON_BYTES`].
    BadReason {
        content_key: ContentKey,
    },
    NoRoleField,
}

impl fmt::Display for MetadataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongRole { expected, found } => {
                write!(f, "the payload is {found} metadata, not {expected}")
            }
            Self::ZeroVersion { role } => write!(f, "{role} metadata version 0 is not valid"),
            Self::KeyIdMismatch { claimed, computed } => write!(
                f,
                "key id {claimed} does not match the key it names, whose id is {computed}"
            ),
            Self::MissingRole { role } => write!(f, "the root lists no keys for {role}"),
            Self::ZeroThreshold { role } => write!(f, "the {role} threshold is 0"),
            Self::ThresholdAboveKeys {
                role,
                threshold,
                keys,
            } => write!(
                f,
                "the {role} threshold {threshold} exceeds its {keys} listed keys"
            ),
            Self::UnknownKey { role, key_id } => {
                write!(f, "{role} names key {key_id}, which the root does not list")
            }
            Self::OnlineRoleUsesRootKey { role, key_id } => write!(
                f,
                "the online {role} role uses root key {key_id}; root keys stay offline"
            ),
            Self::Malformed { detail } => write!(f, "the payload is malformed: {detail}"),
            Self::Unencodable { detail } => {
                write!(f, "the payload has no canonical form: {detail}")
            }
            Self::BadReason { content_key } => write!(
                f,
                "the revocation of {content_key} needs a reason of 1 to {MAX_REASON_BYTES} bytes"
            ),
            Self::NoRoleField => f.write_str("the signed payload has no role field"),
        }
    }
}

impl std::error::Error for MetadataError {}

/// Root metadata: every key and every role's keys and threshold (line 2493 "trust
/// roots, key rotation").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootMetadata {
    pub role: Role,
    pub version: MetadataVersion,
    pub expires: UnixSeconds,
    pub keys: BTreeMap<KeyId, PublicKey>,
    pub roles: BTreeMap<Role, RoleKeys>,
}

impl RootMetadata {
    /// Checks the root's internal consistency: role tag, version, key ids, every role
    /// present with a reachable threshold, and no online role on a root key.
    pub fn check(&self) -> Result<(), MetadataError> {
        expect_role(Role::Root, self.role)?;
        nonzero_version(Role::Root, self.version)?;
        for (claimed, key) in &self.keys {
            let computed = key.key_id();
            if *claimed != computed {
                return Err(MetadataError::KeyIdMismatch {
                    claimed: *claimed,
                    computed,
                });
            }
        }
        for role in Role::ALL {
            let keys = self
                .roles
                .get(&role)
                .ok_or(MetadataError::MissingRole { role })?;
            if keys.threshold == 0 {
                return Err(MetadataError::ZeroThreshold { role });
            }
            let listed = u32::try_from(keys.key_ids.len()).unwrap_or(u32::MAX);
            if keys.threshold > listed {
                return Err(MetadataError::ThresholdAboveKeys {
                    role,
                    threshold: keys.threshold,
                    keys: listed,
                });
            }
            for key_id in &keys.key_ids {
                if !self.keys.contains_key(key_id) {
                    return Err(MetadataError::UnknownKey {
                        role,
                        key_id: *key_id,
                    });
                }
            }
        }
        let root_keys = self.role_keys(Role::Root)?;
        for role in Role::ALL.into_iter().filter(|role| role.is_online()) {
            let keys = self.role_keys(role)?;
            if let Some(key_id) = keys.key_ids.intersection(&root_keys.key_ids).next() {
                return Err(MetadataError::OnlineRoleUsesRootKey {
                    role,
                    key_id: *key_id,
                });
            }
        }
        Ok(())
    }

    /// The keys and threshold of `role`.
    pub fn role_keys(&self, role: Role) -> Result<&RoleKeys, MetadataError> {
        self.roles
            .get(&role)
            .ok_or(MetadataError::MissingRole { role })
    }
}

/// A reference to one exact metadata file: its version, canonical length and digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetaRef {
    pub version: MetadataVersion,
    pub length_bytes: u64,
    pub digest: Digest,
}

/// Timestamp metadata: the freshness signal that names the exact snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimestampMetadata {
    pub role: Role,
    pub version: MetadataVersion,
    pub expires: UnixSeconds,
    pub snapshot: MetaRef,
}

impl TimestampMetadata {
    pub fn check(&self) -> Result<(), MetadataError> {
        expect_role(Role::Timestamp, self.role)?;
        nonzero_version(Role::Timestamp, self.version)
    }
}

/// Snapshot metadata: binds the exact targets file, so the set of target versions a
/// client sees is the set the snapshot signer saw (line 2502 "mix-and-match").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMetadata {
    pub role: Role,
    pub version: MetadataVersion,
    pub expires: UnixSeconds,
    pub targets: MetaRef,
}

impl SnapshotMetadata {
    pub fn check(&self) -> Result<(), MetadataError> {
        expect_role(Role::Snapshot, self.role)?;
        nonzero_version(Role::Snapshot, self.version)
    }
}

/// One release artifact as the targets role describes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetEntry {
    pub class: ArtifactClass,
    pub length_bytes: u64,
    pub content_key: ContentKey,
    pub release: ReleaseVersion,
}

/// Targets metadata: the release artifacts by name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetsMetadata {
    pub role: Role,
    pub version: MetadataVersion,
    pub expires: UnixSeconds,
    pub targets: BTreeMap<TargetName, TargetEntry>,
}

impl TargetsMetadata {
    pub fn check(&self) -> Result<(), MetadataError> {
        expect_role(Role::Targets, self.role)?;
        nonzero_version(Role::Targets, self.version)
    }
}

/// Revocation metadata: revoked releases by content key, with a reason each (line
/// 2493 "emergency revocation"). It has a version but no expiry: a revocation must work
/// offline and stays in force.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationMetadata {
    pub role: Role,
    pub version: MetadataVersion,
    pub issued: UnixSeconds,
    pub revoked: BTreeMap<ContentKey, String>,
}

impl RevocationMetadata {
    pub fn check(&self) -> Result<(), MetadataError> {
        expect_role(Role::Revocation, self.role)?;
        nonzero_version(Role::Revocation, self.version)?;
        for (content_key, reason) in &self.revoked {
            if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
                return Err(MetadataError::BadReason {
                    content_key: *content_key,
                });
            }
        }
        Ok(())
    }
}

fn expect_role(expected: Role, found: Role) -> Result<(), MetadataError> {
    if expected == found {
        Ok(())
    } else {
        Err(MetadataError::WrongRole { expected, found })
    }
}

fn nonzero_version(role: Role, version: MetadataVersion) -> Result<(), MetadataError> {
    if version.get() == 0 {
        Err(MetadataError::ZeroVersion { role })
    } else {
        Ok(())
    }
}

/// A signed metadata file: the payload as it was signed, and the signatures over it.
/// The payload stays a JSON value so the signed bytes are exactly what is verified; a
/// typed view is parsed from it afterwards.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetadataFile {
    signed: Value,
    signatures: Vec<Signature>,
}

impl MetadataFile {
    pub fn new(signed: Value, signatures: Vec<Signature>) -> Self {
        Self { signed, signatures }
    }

    /// The file for `payload` with no signatures yet.
    pub fn unsigned<T: Serialize>(payload: &T) -> Result<Self, MetadataError> {
        let signed = serde_json::to_value(payload).map_err(|error| MetadataError::Unencodable {
            detail: error.to_string(),
        })?;
        Ok(Self {
            signed,
            signatures: Vec::new(),
        })
    }

    pub fn signed(&self) -> &Value {
        &self.signed
    }

    pub fn signatures(&self) -> &[Signature] {
        &self.signatures
    }

    pub fn add_signature(&mut self, signature: Signature) {
        self.signatures.push(signature);
    }

    /// The canonical bytes of the signed payload: compact JSON with sorted keys.
    pub fn canonical_signed_bytes(&self) -> Result<Vec<u8>, MetadataError> {
        serde_json::to_vec(&self.signed).map_err(|error| MetadataError::Unencodable {
            detail: error.to_string(),
        })
    }

    /// The 32-byte message a `role` signature covers: the digest of the role tag and the
    /// canonical payload under [`METADATA_DOMAIN`]. Binding the role means a targets
    /// file signed by a targets key cannot be presented as a snapshot.
    pub fn message(&self, role: Role) -> Result<[u8; 32], MetadataError> {
        let canonical = self.canonical_signed_bytes()?;
        Ok(*DigestBuilder::new(METADATA_DOMAIN)
            .str(role.tag())
            .bytes(&canonical)
            .finish()
            .as_bytes())
    }

    /// The reference another role records for this file at `version`: the length and
    /// digest of the whole canonical file, signatures included.
    pub fn file_reference(&self, version: MetadataVersion) -> Result<MetaRef, MetadataError> {
        let bytes = serde_json::to_vec(self).map_err(|error| MetadataError::Unencodable {
            detail: error.to_string(),
        })?;
        Ok(MetaRef {
            version,
            length_bytes: bytes.len() as u64,
            digest: digest(FILE_DOMAIN, &[&bytes]),
        })
    }

    /// The role the signed payload declares.
    pub fn declared_role(&self) -> Result<Role, MetadataError> {
        let value = self.signed.get("role").ok_or(MetadataError::NoRoleField)?;
        serde_json::from_value(value.clone()).map_err(|error| MetadataError::Malformed {
            detail: error.to_string(),
        })
    }

    /// The typed view of the signed payload; unknown fields are refused.
    pub fn parse<T: DeserializeOwned>(&self) -> Result<T, MetadataError> {
        serde_json::from_value(self.signed.clone()).map_err(|error| MetadataError::Malformed {
            detail: error.to_string(),
        })
    }
}

/// Who signed a file validly, for the record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ThresholdWitness {
    pub role: Role,
    pub threshold: u32,
    pub signers: BTreeSet<KeyId>,
}

/// Why a file's signatures do not reach the role's threshold.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "failure", rename_all = "snake_case")]
pub enum SignatureFailure {
    /// Fewer distinct role keys signed validly than the threshold requires. `invalid`
    /// are role keys whose signature does not verify (a tampered payload makes every
    /// signature invalid); `unknown` are signatures by keys outside the role, ignored.
    ThresholdNotMet {
        role: Role,
        required: u32,
        valid: BTreeSet<KeyId>,
        invalid: BTreeSet<KeyId>,
        unknown: BTreeSet<KeyId>,
    },
    /// A role key's scheme has no registered verifier, so the file cannot be judged.
    SchemeUnavailable {
        role: Role,
        key_id: KeyId,
        rejection: SignatureRejection,
    },
    Metadata {
        error: MetadataError,
    },
}

impl fmt::Display for SignatureFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ThresholdNotMet {
                role,
                required,
                valid,
                invalid,
                unknown,
            } => write!(
                f,
                "{role} needs {required} valid signatures; {} verified, {} did not, {} were by keys outside the role",
                valid.len(),
                invalid.len(),
                unknown.len()
            ),
            Self::SchemeUnavailable {
                role,
                key_id,
                rejection,
            } => write!(f, "{role} key {key_id} cannot be checked: {rejection}"),
            Self::Metadata { error } => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for SignatureFailure {}

/// Checks that `file` carries valid signatures from at least `role_keys.threshold`
/// distinct keys of `role`, each key as `keys` lists it. A key counts once however many
/// times it signed; a signature by a key outside the role is ignored, not counted.
pub fn verify_threshold(
    file: &MetadataFile,
    role: Role,
    keys: &BTreeMap<KeyId, PublicKey>,
    role_keys: &RoleKeys,
    schemes: &SchemeRegistry,
) -> Result<ThresholdWitness, SignatureFailure> {
    let message = file
        .message(role)
        .map_err(|error| SignatureFailure::Metadata { error })?;
    let mut valid = BTreeSet::new();
    let mut invalid = BTreeSet::new();
    let mut unknown = BTreeSet::new();
    for signature in file.signatures() {
        let key_id = signature.key_id;
        let key = match keys.get(&key_id) {
            Some(key) if role_keys.key_ids.contains(&key_id) => key,
            _ => {
                unknown.insert(key_id);
                continue;
            }
        };
        if valid.contains(&key_id) {
            continue;
        }
        match schemes.verify(key, &message, signature.signature.as_bytes()) {
            Ok(()) => {
                valid.insert(key_id);
                invalid.remove(&key_id);
            }
            Err(rejection @ SignatureRejection::SchemeUnavailable { .. }) => {
                return Err(SignatureFailure::SchemeUnavailable {
                    role,
                    key_id,
                    rejection,
                });
            }
            Err(_) => {
                invalid.insert(key_id);
            }
        }
    }
    let count = u32::try_from(valid.len()).unwrap_or(u32::MAX);
    if count >= role_keys.threshold {
        Ok(ThresholdWitness {
            role,
            threshold: role_keys.threshold,
            signers: valid,
        })
    } else {
        Err(SignatureFailure::ThresholdNotMet {
            role,
            required: role_keys.threshold,
            valid,
            invalid,
            unknown,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::catalog::ArtifactClass;
    use crate::foundation::ids::ContentKey;
    use crate::sandbox::trust::signature::{
        HexBytes, HmacSha256TestScheme, PublicKey, SchemeKind, SchemeRegistry,
    };

    fn key(secret: &str) -> PublicKey {
        PublicKey::new(SchemeKind::HmacSha256Test, secret.as_bytes().to_vec())
    }

    fn registry() -> SchemeRegistry {
        let mut registry = SchemeRegistry::new();
        registry.register(Box::new(HmacSha256TestScheme)).unwrap();
        registry
    }

    fn sign(file: &mut MetadataFile, role: Role, secret: &str) {
        let message = file.message(role).unwrap();
        file.add_signature(Signature {
            key_id: key(secret).key_id(),
            signature: HexBytes::new(HmacSha256TestScheme::sign(secret.as_bytes(), &message)),
        });
    }

    fn root(secrets: &[&str], threshold: u32) -> RootMetadata {
        let keys: BTreeMap<KeyId, PublicKey> = secrets
            .iter()
            .chain(["ts", "snap", "targets", "revoke"].iter())
            .map(|secret| (key(secret).key_id(), key(secret)))
            .collect();
        let mut roles = BTreeMap::new();
        roles.insert(
            Role::Root,
            RoleKeys::new(secrets.iter().map(|secret| key(secret).key_id()), threshold),
        );
        for (role, secret) in [
            (Role::Timestamp, "ts"),
            (Role::Snapshot, "snap"),
            (Role::Targets, "targets"),
            (Role::Revocation, "revoke"),
        ] {
            roles.insert(role, RoleKeys::new([key(secret).key_id()], 1));
        }
        RootMetadata {
            role: Role::Root,
            version: MetadataVersion::FIRST,
            expires: UnixSeconds::new(1_000),
            keys,
            roles,
        }
    }

    #[test]
    fn a_consistent_root_passes_and_each_rule_is_checked() {
        let good = root(&["r1", "r2", "r3"], 2);
        assert_eq!(good.check(), Ok(()));

        let mut wrong_role = good.clone();
        wrong_role.role = Role::Targets;
        assert_eq!(
            wrong_role.check(),
            Err(MetadataError::WrongRole {
                expected: Role::Root,
                found: Role::Targets
            })
        );

        let mut zero = good.clone();
        zero.version = MetadataVersion::new(0);
        assert_eq!(
            zero.check(),
            Err(MetadataError::ZeroVersion { role: Role::Root })
        );

        let mut mismatch = good.clone();
        let wrong_id = key("impostor").key_id();
        mismatch.keys.insert(wrong_id, key("r9"));
        assert_eq!(
            mismatch.check(),
            Err(MetadataError::KeyIdMismatch {
                claimed: wrong_id,
                computed: key("r9").key_id()
            })
        );

        let mut missing = good.clone();
        missing.roles.remove(&Role::Snapshot);
        assert_eq!(
            missing.check(),
            Err(MetadataError::MissingRole {
                role: Role::Snapshot
            })
        );

        let mut zero_threshold = good.clone();
        zero_threshold
            .roles
            .insert(Role::Targets, RoleKeys::new([key("targets").key_id()], 0));
        assert_eq!(
            zero_threshold.check(),
            Err(MetadataError::ZeroThreshold {
                role: Role::Targets
            })
        );

        let mut too_high = good.clone();
        too_high.roles.insert(
            Role::Root,
            RoleKeys::new(["r1", "r2", "r3"].map(|secret| key(secret).key_id()), 4),
        );
        assert_eq!(
            too_high.check(),
            Err(MetadataError::ThresholdAboveKeys {
                role: Role::Root,
                threshold: 4,
                keys: 3
            })
        );

        let mut unknown = good.clone();
        unknown
            .roles
            .insert(Role::Timestamp, RoleKeys::new([key("ghost").key_id()], 1));
        assert_eq!(
            unknown.check(),
            Err(MetadataError::UnknownKey {
                role: Role::Timestamp,
                key_id: key("ghost").key_id()
            })
        );

        let mut online_root = good.clone();
        online_root
            .roles
            .insert(Role::Timestamp, RoleKeys::new([key("r1").key_id()], 1));
        assert_eq!(
            online_root.check(),
            Err(MetadataError::OnlineRoleUsesRootKey {
                role: Role::Timestamp,
                key_id: key("r1").key_id()
            })
        );
        // The revocation role is offline, so it may share root keys.
        let mut shared_revocation = good;
        shared_revocation
            .roles
            .insert(Role::Revocation, RoleKeys::new([key("r1").key_id()], 1));
        assert_eq!(shared_revocation.check(), Ok(()));
    }

    #[test]
    fn canonical_form_is_independent_of_field_order_and_whitespace() {
        let a = MetadataFile::new(
            serde_json::from_str("{\"b\": 1, \"a\": {\"z\": true, \"y\": \"x\"}}").unwrap(),
            Vec::new(),
        );
        let b = MetadataFile::new(
            serde_json::from_str("{\"a\":{\"y\":\"x\",\"z\":true},\"b\":1}").unwrap(),
            Vec::new(),
        );
        assert_eq!(
            a.canonical_signed_bytes().unwrap(),
            b"{\"a\":{\"y\":\"x\",\"z\":true},\"b\":1}".to_vec()
        );
        assert_eq!(
            a.message(Role::Root).unwrap(),
            b.message(Role::Root).unwrap()
        );
        assert_ne!(
            a.message(Role::Root).unwrap(),
            a.message(Role::Targets).unwrap()
        );
        assert_eq!(
            a.file_reference(MetadataVersion::FIRST).unwrap(),
            b.file_reference(MetadataVersion::FIRST).unwrap()
        );
        assert_eq!(a.declared_role(), Err(MetadataError::NoRoleField));
    }

    #[test]
    fn thresholds_count_distinct_role_keys_only() {
        let root = root(&["r1", "r2", "r3"], 2);
        let registry = registry();
        let role_keys = root.role_keys(Role::Root).unwrap();
        let mut file = MetadataFile::unsigned(&root).unwrap();
        assert_eq!(file.declared_role(), Ok(Role::Root));

        // One signature: below threshold.
        sign(&mut file, Role::Root, "r1");
        assert!(matches!(
            verify_threshold(&file, Role::Root, &root.keys, role_keys, &registry),
            Err(SignatureFailure::ThresholdNotMet { required: 2, ref valid, .. }) if valid.len() == 1
        ));
        // The same key twice still counts once.
        sign(&mut file, Role::Root, "r1");
        assert!(matches!(
            verify_threshold(&file, Role::Root, &root.keys, role_keys, &registry),
            Err(SignatureFailure::ThresholdNotMet { ref valid, .. }) if valid.len() == 1
        ));
        // A key outside the role is ignored.
        sign(&mut file, Role::Root, "ts");
        let failure = verify_threshold(&file, Role::Root, &root.keys, role_keys, &registry);
        assert!(matches!(
            failure,
            Err(SignatureFailure::ThresholdNotMet { ref unknown, .. })
                if unknown == &BTreeSet::from([key("ts").key_id()])
        ));
        // A second root key reaches it.
        sign(&mut file, Role::Root, "r3");
        let witness =
            verify_threshold(&file, Role::Root, &root.keys, role_keys, &registry).unwrap();
        assert_eq!(
            witness.signers,
            BTreeSet::from([key("r1").key_id(), key("r3").key_id()])
        );
        assert_eq!(witness.threshold, 2);
    }

    #[test]
    fn a_tampered_payload_invalidates_every_signature() {
        let root = root(&["r1", "r2"], 2);
        let registry = registry();
        let mut file = MetadataFile::unsigned(&root).unwrap();
        sign(&mut file, Role::Root, "r1");
        sign(&mut file, Role::Root, "r2");
        let role_keys = root.role_keys(Role::Root).unwrap();
        assert!(verify_threshold(&file, Role::Root, &root.keys, role_keys, &registry).is_ok());

        let mut tampered = file.signed().clone();
        tampered["expires"] = serde_json::json!(9_999_999);
        let tampered = MetadataFile::new(tampered, file.signatures().to_vec());
        assert_eq!(
            verify_threshold(&tampered, Role::Root, &root.keys, role_keys, &registry),
            Err(SignatureFailure::ThresholdNotMet {
                role: Role::Root,
                required: 2,
                valid: BTreeSet::new(),
                invalid: BTreeSet::from([key("r1").key_id(), key("r2").key_id()]),
                unknown: BTreeSet::new(),
            })
        );
        assert_ne!(
            tampered.file_reference(MetadataVersion::FIRST).unwrap(),
            file.file_reference(MetadataVersion::FIRST).unwrap()
        );
    }

    #[test]
    fn an_unavailable_scheme_stops_verification_explicitly() {
        let mut root = root(&["r1"], 1);
        let ed = PublicKey::new(SchemeKind::Ed25519, vec![1; 32]);
        root.keys.insert(ed.key_id(), ed.clone());
        root.roles
            .insert(Role::Root, RoleKeys::new([ed.key_id()], 1));
        let mut file = MetadataFile::unsigned(&root).unwrap();
        file.add_signature(Signature {
            key_id: ed.key_id(),
            signature: HexBytes::new(vec![0; 64]),
        });
        let failure = verify_threshold(
            &file,
            Role::Root,
            &root.keys,
            root.role_keys(Role::Root).unwrap(),
            &registry(),
        );
        assert_eq!(
            failure,
            Err(SignatureFailure::SchemeUnavailable {
                role: Role::Root,
                key_id: ed.key_id(),
                rejection: SignatureRejection::SchemeUnavailable {
                    scheme: SchemeKind::Ed25519
                }
            })
        );
    }

    #[test]
    fn payloads_refuse_unknown_fields_and_wrong_roles() {
        let targets = TargetsMetadata {
            role: Role::Targets,
            version: MetadataVersion::FIRST,
            expires: UnixSeconds::new(10),
            targets: BTreeMap::from([(
                TargetName::new("guest-kernel").unwrap(),
                TargetEntry {
                    class: ArtifactClass::GuestImage,
                    length_bytes: 3,
                    content_key: ContentKey::of(b"abc"),
                    release: ReleaseVersion::new("2026.10.1").unwrap(),
                },
            )]),
        };
        let file = MetadataFile::unsigned(&targets).unwrap();
        assert_eq!(file.parse::<TargetsMetadata>().unwrap(), targets);
        assert!(matches!(
            file.parse::<SnapshotMetadata>(),
            Err(MetadataError::Malformed { .. })
        ));
        let mut extra = file.signed().clone();
        extra["delegations"] = serde_json::json!([]);
        assert!(matches!(
            MetadataFile::new(extra, Vec::new()).parse::<TargetsMetadata>(),
            Err(MetadataError::Malformed { .. })
        ));
        let mut as_snapshot = targets.clone();
        as_snapshot.role = Role::Snapshot;
        assert_eq!(
            as_snapshot.check(),
            Err(MetadataError::WrongRole {
                expected: Role::Targets,
                found: Role::Snapshot
            })
        );
        assert!(TargetName::new("bad name").is_err());
        assert!(ReleaseVersion::new("").is_err());
        assert!(serde_json::from_str::<TargetName>("\"a/b\"").is_err());

        let revocation = RevocationMetadata {
            role: Role::Revocation,
            version: MetadataVersion::FIRST,
            issued: UnixSeconds::new(5),
            revoked: BTreeMap::from([(ContentKey::of(b"x"), String::new())]),
        };
        assert_eq!(
            revocation.check(),
            Err(MetadataError::BadReason {
                content_key: ContentKey::of(b"x")
            })
        );
        let file_json = serde_json::to_string(&file).unwrap();
        assert_eq!(
            serde_json::from_str::<MetadataFile>(&file_json).unwrap(),
            file
        );
        assert!(serde_json::from_str::<MetadataFile>(
            "{\"signed\":{},\"signatures\":[],\"note\":1}"
        )
        .is_err());
    }
}
