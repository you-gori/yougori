//! Configured roots for the trust client (VM-W45, plan line 2668: "trust roots, key
//! rotation ... emergency revocation"; §8.3, line 2455: "offline roots, delegated online
//! keys ... revoked releases and key rotation"; VM-D13, line 3207: "update trust design
//! and key custody"; M18 in docs/combined-plan-leftover-tasks.md, line 106: "configured
//! roots and release metadata").
//!
//! The roots come from the foundation's trust-root file, held as the
//! [`SharedTrustRoots`] in force, and the update client's own [`UpdateTrustConfig`]
//! (root threshold and release-metadata location); this module defines no key format.
//! [`PinnedRoots`] holds both and derives the root set when it is used, never earlier:
//!
//! - **One class.** Only keys allowed [`UPDATE_ROOT_CLASS`] are update roots: runtime
//!   updates (VM-W45, line 2668: "the sandbox runtime/image update policy"; INT-09,
//!   line 277: "runtime update"). The class is fixed here, not chosen by the caller, so a
//!   publisher key for OCI layers, models or any other class never becomes an update
//!   root.
//! - **One key per rotation chain.** A key and the keys it replaces (`replaces` in the
//!   file) are one custodian's, so a chain counts once towards the threshold: only its
//!   newest key that may vouch now is pinned. Refusing files with overlapping rotations
//!   was the alternative, but the file format requires a successor's window to start no
//!   later than its predecessor's end, so that would refuse every rotation in progress.
//!   The cost: during an overlap, a root signed with the old key alone fails closed; the
//!   custodian signs with the new key.
//! - **Checked when used.** [`PinnedRoots::bootstrap`] derives the set at its `now` from
//!   the roots in force at that moment: a key that has expired, is not yet valid, or was
//!   revoked in a reloaded file ([`SharedTrustRoots::replace`]) is dropped, the threshold
//!   is checked against what remains, and an unreachable threshold refuses the bootstrap.
//!   [`PinnedRoots::at`] shows the set a bootstrap at a given time would use, each key
//!   with its validity window.
//!
//! Each pinned key becomes the trust client's own [`PublicKey`]. Its [`KeyId`] is the
//! foundation's key fingerprint, so its publisher identity is the same in the catalog and
//! in the trust client. The file's algorithms map onto the client's schemes exhaustively
//! ([`scheme_for`]); under the production profile only production-grade schemes are
//! pinned, and in every profile the same key material is pinned at most once, whatever
//! its scheme.
//!
//! The bootstrap then starts the [`UpdateClient`] from a root metadata file the threshold
//! of the pinned keys signed; the client's own checks follow (consistent, signed by its
//! own root threshold, unexpired, production-grade keys under production). A root
//! rotated since the pinned keys signed it is reached by bootstrapping from the root they
//! signed and applying [`UpdateClient::update_root`] one version at a time.
//!
//! Out of scope: a running client trusts its own root metadata from then on, so a
//! revocation in a reloaded trust-root file reaches the next bootstrap, not a client
//! already started.

use std::collections::btree_map::Entry;
use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU32;

use chrono::{DateTime, Utc};
use serde::Serialize;

use super::config::UpdateTrustConfig;
use super::registry::check_production_registry;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::report::PublicUrl;
use crate::foundation::signing::{
    KeyAlgorithm, RootKeyId, SharedTrustRoots, TrustRoots, TrustedKey, MAX_TRUST_ROOT_KEYS,
};
use crate::sandbox::trust::{
    verify_threshold, AssuranceProfile, KeyId, MetadataFile, PublicKey, ResolvedProfile, Role,
    RoleKeys, SchemeKind, SchemeRegistry, SignatureFailure, UnixSeconds, UpdateClient,
    UpdateRefusal,
};

/// The artifact class whose trust-root keys may be update roots.
pub const UPDATE_ROOT_CLASS: ArtifactClass = ArtifactClass::RuntimeUpdate;

/// Why no root set was pinned.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RootsRefusal {
    /// The production profile accepts production-grade schemes only (§8.3, line 2457).
    TestSchemeInProduction { key_id: KeyId, scheme: SchemeKind },
    /// Two keys have the same material, under one scheme or two.
    DuplicateKey { key_id: KeyId, same_as: KeyId },
    /// No key may be an update root now: none is allowed [`UPDATE_ROOT_CLASS`], or every
    /// such key is revoked or outside its validity window.
    NoRootKeys,
    /// Fewer usable root keys, one per rotation chain, than the threshold.
    ThresholdAboveKeys { threshold: u32, keys: u32 },
    /// The time has no calendar date the trust-root file can be checked at.
    TimeOutOfRange { at: UnixSeconds },
}

impl fmt::Display for RootsRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TestSchemeInProduction { key_id, scheme } => write!(
                f,
                "root key {key_id} uses the {scheme} scheme, which the production profile does not accept"
            ),
            Self::DuplicateKey { key_id, same_as } => {
                write!(f, "root key {key_id} has the material of root key {same_as}")
            }
            Self::NoRootKeys => f.write_str("no trust-root key may be an update root now"),
            Self::ThresholdAboveKeys { threshold, keys } => write!(
                f,
                "the root threshold {threshold} exceeds the {keys} usable root keys"
            ),
            Self::TimeOutOfRange { at } => {
                write!(f, "the trust roots cannot be checked at {at}")
            }
        }
    }
}

impl std::error::Error for RootsRefusal {}

/// Why the update client was not started from the pinned roots.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum BootstrapRefusal {
    /// The production profile was offered a registry with a verifier for a scheme that
    /// is not production grade.
    TestSchemeRegistered { scheme: SchemeKind },
    /// No root set could be pinned at the bootstrap's time.
    Roots { reason: RootsRefusal },
    /// The root file lacks valid signatures from the threshold of the pinned keys.
    NotSignedByPinnedRoots { failure: SignatureFailure },
    /// The update client refused the root file.
    Client { reason: UpdateRefusal },
}

impl fmt::Display for BootstrapRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TestSchemeRegistered { scheme } => write!(
                f,
                "the registry holds a verifier for the {scheme} scheme, which the production profile does not accept"
            ),
            Self::Roots { reason } => write!(f, "no update roots: {reason}"),
            Self::NotSignedByPinnedRoots { failure } => {
                write!(f, "the root is not signed by the configured root keys: {failure}")
            }
            Self::Client { reason } => write!(f, "{reason}"),
        }
    }
}

impl std::error::Error for BootstrapRefusal {}

/// One pinned root key: the trust client's key, with the trust-root entry it came from
/// and that entry's validity window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedKey {
    root_key: RootKeyId,
    key: PublicKey,
    valid_from: DateTime<Utc>,
    valid_until: DateTime<Utc>,
}

impl PinnedKey {
    pub(super) fn new(
        root_key: RootKeyId,
        key: PublicKey,
        valid_from: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> Self {
        Self {
            root_key,
            key,
            valid_from,
            valid_until,
        }
    }

    fn from_trusted(trusted: &TrustedKey) -> Self {
        Self::new(
            trusted.id().clone(),
            PublicKey::new(
                scheme_for(trusted.algorithm()),
                trusted.public_key().as_bytes().to_vec(),
            ),
            trusted.valid_from(),
            trusted.valid_until(),
        )
    }

    /// The trust-root entry's id.
    pub fn root_key(&self) -> &RootKeyId {
        &self.root_key
    }

    pub fn key(&self) -> &PublicKey {
        &self.key
    }

    /// The first instant the entry is valid.
    pub fn valid_from(&self) -> DateTime<Utc> {
        self.valid_from
    }

    /// The first instant the entry is no longer valid.
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}

/// The root keys pinned at one time, by the trust client's identity, and the root role
/// they form with the configured threshold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootSet {
    keys: BTreeMap<KeyId, PinnedKey>,
    root_role: RoleKeys,
}

impl RootSet {
    pub fn keys(&self) -> &BTreeMap<KeyId, PinnedKey> {
        &self.keys
    }

    /// The pinned keys' identities and the threshold.
    pub fn root_role(&self) -> &RoleKeys {
        &self.root_role
    }

    /// The pinned keys as the trust client verifies with them.
    pub fn public_keys(&self) -> BTreeMap<KeyId, PublicKey> {
        self.keys
            .iter()
            .map(|(key_id, pinned)| (*key_id, pinned.key.clone()))
            .collect()
    }
}

/// The configured update roots: the trust roots in force and the update configuration,
/// pinned into a [`RootSet`] whenever they are used.
#[derive(Clone, Debug)]
pub struct PinnedRoots {
    profile: ResolvedProfile,
    roots: SharedTrustRoots,
    config: UpdateTrustConfig,
}

impl PinnedRoots {
    /// Update roots from `roots` (a reload through [`SharedTrustRoots::replace`] applies
    /// to the next use) and `config`, under `profile`.
    pub fn new(
        roots: SharedTrustRoots,
        config: UpdateTrustConfig,
        profile: ResolvedProfile,
    ) -> Self {
        Self {
            profile,
            roots,
            config,
        }
    }

    /// The profile the client is started under.
    pub fn profile(&self) -> AssuranceProfile {
        self.profile.profile()
    }

    pub fn config(&self) -> &UpdateTrustConfig {
        &self.config
    }

    /// Where the release metadata is published.
    pub fn metadata_location(&self) -> &PublicUrl {
        self.config.metadata_location()
    }

    /// The root set a bootstrap at `now` would use, from the trust roots in force now:
    /// the newest key of each rotation chain that may vouch for [`UPDATE_ROOT_CLASS`] at
    /// `now`, if they reach the threshold.
    pub fn at(&self, now: UnixSeconds) -> Result<RootSet, RootsRefusal> {
        root_set(
            &self.roots.current(),
            self.config.root_threshold(),
            now,
            self.profile,
        )
    }

    /// Starts the update client from `trusted_root` at `now`. Under production, `schemes`
    /// must hold no verifier for a scheme that is not production grade. The root set is
    /// derived at `now` ([`Self::at`]); the file must carry valid signatures from its
    /// threshold; then [`UpdateClient::new`] applies its own checks.
    pub fn bootstrap(
        &self,
        schemes: SchemeRegistry,
        trusted_root: &MetadataFile,
        now: UnixSeconds,
    ) -> Result<UpdateClient, BootstrapRefusal> {
        if self.profile.is_production() {
            check_production_registry(&schemes).map_err(|refused| {
                BootstrapRefusal::TestSchemeRegistered {
                    scheme: refused.scheme,
                }
            })?;
        }
        let set = self
            .at(now)
            .map_err(|reason| BootstrapRefusal::Roots { reason })?;
        verify_threshold(
            trusted_root,
            Role::Root,
            &set.public_keys(),
            set.root_role(),
            &schemes,
        )
        .map_err(|failure| BootstrapRefusal::NotSignedByPinnedRoots { failure })?;
        UpdateClient::new(schemes, self.profile, trusted_root, now)
            .map_err(|reason| BootstrapRefusal::Client { reason })
    }
}

/// The trust client's scheme for a trust-root key algorithm. Exhaustive: an algorithm
/// added to the file format must be mapped here before this compiles.
pub const fn scheme_for(algorithm: KeyAlgorithm) -> SchemeKind {
    match algorithm {
        KeyAlgorithm::Ed25519 => SchemeKind::Ed25519,
    }
}

/// The root set of `roots` at `at`.
fn root_set(
    roots: &TrustRoots,
    threshold: NonZeroU32,
    at: UnixSeconds,
    profile: ResolvedProfile,
) -> Result<RootSet, RootsRefusal> {
    let calendar = i64::try_from(at.get())
        .ok()
        .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
        .ok_or(RootsRefusal::TimeOutOfRange { at })?;
    let candidates = newest_per_chain(roots, calendar)
        .into_iter()
        .map(PinnedKey::from_trusted);
    pin(candidates, threshold, profile)
}

/// The newest key of each rotation chain of `roots` that may vouch for
/// [`UPDATE_ROOT_CLASS`] at `at`.
fn newest_per_chain(roots: &TrustRoots, at: DateTime<Utc>) -> Vec<&TrustedKey> {
    let mut newest: BTreeMap<&RootKeyId, (usize, &TrustedKey)> = BTreeMap::new();
    for key in roots.keys() {
        if key.check(UPDATE_ROOT_CLASS, at).is_err() {
            continue;
        }
        let (first, rotations) = chain_origin(roots, key);
        match newest.entry(first.id()) {
            Entry::Vacant(slot) => {
                slot.insert((rotations, key));
            }
            Entry::Occupied(mut slot) => {
                if slot.get().0 < rotations {
                    slot.insert((rotations, key));
                }
            }
        }
    }
    newest.into_values().map(|(_, key)| key).collect()
}

/// The first key of `key`'s rotation chain, and how many rotations `key` is from it.
fn chain_origin<'a>(roots: &'a TrustRoots, key: &'a TrustedKey) -> (&'a TrustedKey, usize) {
    let mut current = key;
    let mut rotations = 0;
    // The file refuses cycles and forks; the bound keeps the walk finite regardless.
    while rotations < MAX_TRUST_ROOT_KEYS {
        let Some(predecessor) = current.replaces().and_then(|id| roots.key(id)) else {
            break;
        };
        current = predecessor;
        rotations += 1;
    }
    (current, rotations)
}

/// Pins `candidates` as the root keys, of which `threshold` must sign. Under the
/// production profile every key must use a production-grade scheme; in every profile no
/// two keys may share material, under one scheme or two (a public key must not double as
/// another scheme's secret); and the threshold must not exceed the number of keys.
pub(super) fn pin(
    candidates: impl IntoIterator<Item = PinnedKey>,
    threshold: NonZeroU32,
    profile: ResolvedProfile,
) -> Result<RootSet, RootsRefusal> {
    let mut keys = BTreeMap::new();
    let mut materials: BTreeMap<Vec<u8>, KeyId> = BTreeMap::new();
    for pinned in candidates {
        let key_id = pinned.key.key_id();
        if profile.is_production() && !pinned.key.scheme.production_grade() {
            return Err(RootsRefusal::TestSchemeInProduction {
                key_id,
                scheme: pinned.key.scheme,
            });
        }
        if let Some(same_as) = materials.insert(pinned.key.material.as_bytes().to_vec(), key_id) {
            return Err(RootsRefusal::DuplicateKey { key_id, same_as });
        }
        keys.insert(key_id, pinned);
    }
    if keys.is_empty() {
        return Err(RootsRefusal::NoRootKeys);
    }
    let listed = u32::try_from(keys.len()).unwrap_or(u32::MAX);
    if threshold.get() > listed {
        return Err(RootsRefusal::ThresholdAboveKeys {
            threshold: threshold.get(),
            keys: listed,
        });
    }
    Ok(RootSet {
        root_role: RoleKeys::new(keys.keys().copied(), threshold.get()),
        keys,
    })
}
