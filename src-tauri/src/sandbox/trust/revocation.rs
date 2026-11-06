//! Revocations the host decides, reaching clients that are already running (VM-W45,
//! line 2668: "emergency revocation"; §8.3, line 2455: "revoked releases and key
//! rotation"; VM-P23, line 2798: revoked components "fail verification at the actual
//! execution boundary"; VM-P48, line 2823; §8.2, line 2445: "never block the revocation
//! channel").
//!
//! The signed revocation list revokes releases by content key and is fetched like other
//! metadata. Keys and artifact classes are revoked by the host: the operator's trust
//! roots revoke a key, or the operator stops trusting a whole class. A
//! [`RevocationFeed`] is the shared handle for that: the host revokes on it once, and
//! every [`UpdateClient`] that holds a clone of it applies the revocation at its next
//! check (every verification, launch admission, update and refresh reads the feed), with
//! no restart and no rebuild. A revoked key's signatures no longer count towards any
//! role's threshold, so trusted metadata whose threshold rested on it stops serving, and
//! a handle verified under it before is refused at the launch boundary; a revoked class
//! refuses every target of that class, signed or developer-built.
//!
//! Host revocations only accumulate: the feed has no way to withdraw one, a client keeps
//! every one it has seen, and its persisted state carries them, so a restart, or a trust-
//! root file rolled back to before the revocation, does not restore the key or class.
//! Undoing one means starting the trust state anew.
//!
//! The feed is a lock around plain maps, taken for reading at each check and never held
//! across a call into other code; a poisoned lock is read as it stands, since an insert
//! leaves no invariant half-made.
//!
//! [`UpdateClient`]: super::UpdateClient

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, PoisonError, RwLock};

use serde::{Deserialize, Serialize};

use super::metadata::MAX_REASON_BYTES;
use super::signature::KeyId;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::ids::ContentKey;

/// What the host revoked, each with its reason. Written by the client into its persisted
/// state and read back from there.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostRevocations {
    /// Keys whose signatures count for no role.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub keys: BTreeMap<KeyId, String>,
    /// Artifact classes none of whose targets verifies or launches.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub classes: BTreeMap<ArtifactClass, String>,
    /// Releases revoked by content key, as the signed list revokes them.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub releases: BTreeMap<ContentKey, String>,
}

impl HostRevocations {
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty() && self.classes.is_empty() && self.releases.is_empty()
    }

    /// Whether every revocation in `other` is also here.
    pub fn covers(&self, other: &Self) -> bool {
        other.keys.keys().all(|key| self.keys.contains_key(key))
            && other
                .classes
                .keys()
                .all(|class| self.classes.contains_key(class))
            && other
                .releases
                .keys()
                .all(|release| self.releases.contains_key(release))
    }

    /// Checks every reason: 1 to [`MAX_REASON_BYTES`] bytes.
    pub fn check(&self) -> Result<(), BadRevocationReason> {
        for (key_id, reason) in &self.keys {
            check_reason(Revoked::Key { key_id: *key_id }, reason)?;
        }
        for (class, reason) in &self.classes {
            check_reason(Revoked::Class { class: *class }, reason)?;
        }
        for (content_key, reason) in &self.releases {
            check_reason(
                Revoked::Release {
                    content_key: *content_key,
                },
                reason,
            )?;
        }
        Ok(())
    }

    /// Adds every revocation of `other` not here yet; a reason already recorded stays.
    pub(super) fn absorb(&mut self, other: &Self) {
        for (key_id, reason) in &other.keys {
            self.keys.entry(*key_id).or_insert_with(|| reason.clone());
        }
        for (class, reason) in &other.classes {
            self.classes.entry(*class).or_insert_with(|| reason.clone());
        }
        for (content_key, reason) in &other.releases {
            self.releases
                .entry(*content_key)
                .or_insert_with(|| reason.clone());
        }
    }
}

/// What one host revocation names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "revoked", rename_all = "snake_case")]
pub enum Revoked {
    Key { key_id: KeyId },
    Class { class: ArtifactClass },
    Release { content_key: ContentKey },
}

impl fmt::Display for Revoked {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key { key_id } => write!(f, "key {key_id}"),
            Self::Class { class } => write!(f, "artifact class {class}"),
            Self::Release { content_key } => write!(f, "release {content_key}"),
        }
    }
}

/// A revocation with no reason, or one longer than [`MAX_REASON_BYTES`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BadRevocationReason {
    pub revoked: Revoked,
}

impl fmt::Display for BadRevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the revocation of {} needs a reason of 1 to {MAX_REASON_BYTES} bytes",
            self.revoked
        )
    }
}

impl std::error::Error for BadRevocationReason {}

fn check_reason(revoked: Revoked, reason: &str) -> Result<(), BadRevocationReason> {
    if reason.is_empty() || reason.len() > MAX_REASON_BYTES {
        Err(BadRevocationReason { revoked })
    } else {
        Ok(())
    }
}

/// The host's revocations, shared by every client that holds a clone.
#[derive(Clone, Default)]
pub struct RevocationFeed {
    revocations: Arc<RwLock<HostRevocations>>,
}

impl RevocationFeed {
    /// A feed with nothing revoked.
    pub fn new() -> Self {
        Self::default()
    }

    /// Revokes `key_id` for every role. Returns whether it was newly revoked; a key
    /// revoked before keeps its first reason.
    pub fn revoke_key(&self, key_id: KeyId, reason: &str) -> Result<bool, BadRevocationReason> {
        check_reason(Revoked::Key { key_id }, reason)?;
        Ok(self.write(|revocations| insert(&mut revocations.keys, key_id, reason)))
    }

    /// Revokes every target of `class`.
    pub fn revoke_class(
        &self,
        class: ArtifactClass,
        reason: &str,
    ) -> Result<bool, BadRevocationReason> {
        check_reason(Revoked::Class { class }, reason)?;
        Ok(self.write(|revocations| insert(&mut revocations.classes, class, reason)))
    }

    /// Revokes the release with `content_key`.
    pub fn revoke_release(
        &self,
        content_key: ContentKey,
        reason: &str,
    ) -> Result<bool, BadRevocationReason> {
        check_reason(Revoked::Release { content_key }, reason)?;
        Ok(self.write(|revocations| insert(&mut revocations.releases, content_key, reason)))
    }

    /// Everything revoked on the feed now.
    pub fn current(&self) -> HostRevocations {
        self.read(Clone::clone)
    }

    pub(super) fn key(&self, key_id: &KeyId) -> Option<String> {
        self.read(|revocations| revocations.keys.get(key_id).cloned())
    }

    pub(super) fn class(&self, class: ArtifactClass) -> Option<String> {
        self.read(|revocations| revocations.classes.get(&class).cloned())
    }

    pub(super) fn release(&self, content_key: &ContentKey) -> Option<String> {
        self.read(|revocations| revocations.releases.get(content_key).cloned())
    }

    fn read<T>(&self, read: impl FnOnce(&HostRevocations) -> T) -> T {
        let guard = self
            .revocations
            .read()
            .unwrap_or_else(PoisonError::into_inner);
        read(&guard)
    }

    fn write<T>(&self, write: impl FnOnce(&mut HostRevocations) -> T) -> T {
        let mut guard = self
            .revocations
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        write(&mut guard)
    }
}

impl fmt::Debug for RevocationFeed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.read(|revocations| {
            f.debug_struct("RevocationFeed")
                .field("keys", &revocations.keys.len())
                .field("classes", &revocations.classes.len())
                .field("releases", &revocations.releases.len())
                .finish()
        })
    }
}

fn insert<K: Ord>(map: &mut BTreeMap<K, String>, key: K, reason: &str) -> bool {
    match map.entry(key) {
        std::collections::btree_map::Entry::Occupied(_) => false,
        std::collections::btree_map::Entry::Vacant(entry) => {
            entry.insert(reason.to_owned());
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::trust::signature::{PublicKey, SchemeKind};

    fn key_id(name: &str) -> KeyId {
        PublicKey::new(SchemeKind::Ed25519, name.as_bytes().to_vec()).key_id()
    }

    #[test]
    fn the_feed_is_shared_and_only_accumulates() {
        let feed = RevocationFeed::new();
        let clone = feed.clone();
        assert_eq!(feed.revoke_key(key_id("a"), "compromised"), Ok(true));
        assert_eq!(clone.revoke_key(key_id("a"), "again"), Ok(false));
        assert_eq!(clone.key(&key_id("a")).as_deref(), Some("compromised"));
        assert_eq!(
            feed.revoke_class(ArtifactClass::GuestImage, "image line halted"),
            Ok(true)
        );
        assert_eq!(
            clone.class(ArtifactClass::GuestImage).as_deref(),
            Some("image line halted")
        );
        assert_eq!(clone.class(ArtifactClass::OciLayer), None);
        assert_eq!(
            feed.revoke_release(ContentKey::of(b"x"), "known bad"),
            Ok(true)
        );
        assert!(clone.release(&ContentKey::of(b"x")).is_some());
        let current = clone.current();
        assert_eq!(current.keys.len(), 1);
        assert_eq!(current.classes.len(), 1);
        assert_eq!(current.releases.len(), 1);
        assert_eq!(
            format!("{feed:?}"),
            "RevocationFeed { keys: 1, classes: 1, releases: 1 }"
        );
    }

    #[test]
    fn reasons_are_bounded() {
        let feed = RevocationFeed::new();
        assert_eq!(
            feed.revoke_key(key_id("a"), ""),
            Err(BadRevocationReason {
                revoked: Revoked::Key {
                    key_id: key_id("a")
                }
            })
        );
        let long = "x".repeat(MAX_REASON_BYTES + 1);
        assert!(feed.revoke_class(ArtifactClass::OciLayer, &long).is_err());
        assert!(feed
            .revoke_class(ArtifactClass::OciLayer, &long[..MAX_REASON_BYTES])
            .is_ok());
        assert!(feed.current().keys.is_empty());

        let mut stored = HostRevocations::default();
        stored.releases.insert(ContentKey::of(b"y"), String::new());
        assert_eq!(
            stored.check(),
            Err(BadRevocationReason {
                revoked: Revoked::Release {
                    content_key: ContentKey::of(b"y")
                }
            })
        );
        assert!(BadRevocationReason {
            revoked: Revoked::Class {
                class: ArtifactClass::GuestImage
            }
        }
        .to_string()
        .contains("artifact class guest_image"));
    }

    #[test]
    fn absorb_keeps_first_reasons_and_covers_compares() {
        let mut held = HostRevocations::default();
        held.keys.insert(key_id("a"), "first".to_owned());
        let mut more = HostRevocations::default();
        more.keys.insert(key_id("a"), "second".to_owned());
        more.classes
            .insert(ArtifactClass::GuestImage, "halted".to_owned());
        assert!(!held.covers(&more));
        held.absorb(&more);
        assert!(held.covers(&more));
        assert_eq!(held.keys[&key_id("a")], "first");
        assert!(!more.covers(&HostRevocations {
            releases: BTreeMap::from([(ContentKey::of(b"z"), "r".to_owned())]),
            ..HostRevocations::default()
        }));
        let json = serde_json::to_value(&HostRevocations::default()).unwrap();
        assert_eq!(json, serde_json::json!({}));
        assert!(serde_json::from_value::<HostRevocations>(serde_json::json!({"note": 1})).is_err());
    }
}
