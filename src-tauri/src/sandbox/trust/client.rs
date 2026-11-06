//! The update client: trusted metadata state and the checks every update passes
//! (VM-W45, line 2668: "trust roots, key rotation, expiry/version checks, rollback
//! resistance, offline behavior and emergency revocation"; line 2677: "freeze, rollback
//! and mix-and-match attacks"; VM-P23, line 2798; VM-P48, line 2823).
//!
//! The client starts from a trusted root the caller supplies as data (this module ships
//! no key) and accepts metadata only in order: root rotations one version at a time,
//! then timestamp, snapshot and targets, each signed by its role's threshold, each at a
//! version no lower than the trusted one, each unexpired, and each exactly the file the
//! previous role referenced. A revocation list needs only the revocation role, so it
//! applies offline and without a fresh timestamp. Verification and launch admission
//! re-check expiry at the time asked, so metadata that expired since it was fetched is
//! a refusal, not a pass.
//!
//! Three things hold beyond the files the client trusts now:
//!
//! - **Floors.** Each role keeps the highest version the client accepted while the role's
//!   keys stayed the same. A rotation that changes online keys drops the online files, and
//!   the floor of each role whose keys changed lapses with them (recovery from a key that
//!   signed versions far ahead); the floors of the other roles stay, so their files are
//!   fetched again at no lower version.
//! - **The time floor.** The latest calendar time the client acted at. A call whose clock
//!   reads earlier is refused ([`UpdateRefusal::ClockBehind`]): an expiry once reached
//!   stays reached, also across a restart that took a calendar anchor behind it.
//! - **Revoked keys and classes.** Signatures by a key the host revoked count for no
//!   role, at the next check and without a restart: a trusted file whose threshold rested
//!   on such a key no longer serves, and nothing verified under it before launches
//!   ([`UpdateRefusal::RevokedKey`]); a revoked artifact class refuses every target of
//!   it ([`UpdateRefusal::RevokedClass`]). The `revocation` module has the feed.
//!
//! The `state` module persists all of this and restores it; the `fetch` module takes
//! metadata and artifacts through a bounded port in the order above.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::artifact::{OpenedArtifact, VerificationBasis, VerifiedTarget};
use super::metadata::{
    verify_threshold, MetaRef, MetadataError, MetadataFile, MetadataVersion, RevocationMetadata,
    Role, RootMetadata, SignatureFailure, SnapshotMetadata, TargetName, TargetsMetadata,
    TimestampMetadata,
};
use super::profile::{AssuranceProfile, ResolvedProfile};
use super::revocation::{HostRevocations, RevocationFeed};
use super::signature::{KeyId, SchemeKind, SchemeRegistry};
use super::time::UnixSeconds;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::ids::ContentKey;

/// Most roots a client keeps: the root it started from and every rotation since. They
/// are what ties the root in force to the pinned root after a restart; pinning a newer
/// root lets a restored client drop the ones before it.
pub const MAX_TRUSTED_ROOTS: usize = 1_024;

/// Why the client refused metadata, a target or a launch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum UpdateRefusal {
    Metadata {
        error: MetadataError,
    },
    /// The role's threshold was not reached: tampered, unsigned or wrongly signed.
    Signatures {
        failure: SignatureFailure,
    },
    /// The production profile accepts production-grade schemes only (line 2457).
    NonProductionScheme {
        key_id: KeyId,
        scheme: SchemeKind,
    },
    /// Expired at the time asked: a freeze, or offline past the expiry.
    Expired {
        role: Role,
        expires: UnixSeconds,
        now: UnixSeconds,
    },
    /// The version already trusted was offered again.
    Replayed {
        role: Role,
        version: MetadataVersion,
    },
    /// A version lower than the trusted one, or than the floor the role keeps after its
    /// file was dropped.
    RolledBack {
        role: Role,
        trusted: MetadataVersion,
        offered: MetadataVersion,
    },
    /// A root more than one version ahead; rotations are applied one by one.
    VersionGap {
        role: Role,
        trusted: MetadataVersion,
        offered: MetadataVersion,
    },
    /// The role that must reference this file is not trusted yet.
    MissingPrerequisite {
        needed: Role,
    },
    /// The file is not the one the referencing role bound: mixed versions or an altered
    /// file (line 2677 "mix-and-match").
    DoesNotMatchReference {
        role: Role,
        referenced_by: Role,
        expected: MetaRef,
        found: MetaRef,
    },
    UnknownTarget {
        name: TargetName,
    },
    /// The caller opens the target as one class and the metadata declares another.
    ClassMismatch {
        name: TargetName,
        declared: ArtifactClass,
        expected: ArtifactClass,
    },
    RevokedRelease {
        content_key: ContentKey,
        reason: String,
    },
    /// The trusted targets now name other bytes for this target than were verified.
    Superseded {
        name: TargetName,
        verified: ContentKey,
        current: ContentKey,
    },
    /// A target verified outside the production profile cannot launch under it.
    NotProduction {
        name: TargetName,
        assurance: AssuranceProfile,
    },
    /// The clock reads earlier than a time the client already acted at: it was set back,
    /// or a restart anchored the calendar behind the stored time. Expiry cannot be judged,
    /// so nothing is (a freeze).
    ClockBehind {
        floor: UnixSeconds,
        now: UnixSeconds,
    },
    /// The role's threshold is reached only with the signature of a revoked key, so the
    /// file counts no longer: nothing verified under that key is trusted afterwards.
    RevokedKey {
        role: Role,
        key_id: KeyId,
        reason: String,
    },
    /// Every target of the artifact class is revoked.
    RevokedClass {
        name: TargetName,
        class: ArtifactClass,
        reason: String,
    },
    /// The client keeps [`MAX_TRUSTED_ROOTS`] roots and rotates no further until a newer
    /// root is pinned.
    RootChainFull {
        limit: usize,
    },
}

impl fmt::Display for UpdateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata { error } => write!(f, "{error}"),
            Self::Signatures { failure } => write!(f, "{failure}"),
            Self::NonProductionScheme { key_id, scheme } => write!(
                f,
                "key {key_id} uses the {scheme} scheme, which the production profile does not accept"
            ),
            Self::Expired { role, expires, now } => {
                write!(f, "{role} metadata expired at {expires}; it is {now}")
            }
            Self::Replayed { role, version } => {
                write!(f, "{role} version {version} is already trusted")
            }
            Self::RolledBack {
                role,
                trusted,
                offered,
            } => write!(
                f,
                "{role} version {offered} is older than the trusted {trusted}"
            ),
            Self::VersionGap {
                role,
                trusted,
                offered,
            } => write!(
                f,
                "{role} version {offered} skips versions after the trusted {trusted}"
            ),
            Self::MissingPrerequisite { needed } => {
                write!(f, "no trusted {needed} metadata references this file")
            }
            Self::DoesNotMatchReference {
                role,
                referenced_by,
                expected,
                found,
            } => write!(
                f,
                "the {role} file (version {}, {} bytes, {}) is not the one {referenced_by} references (version {}, {} bytes, {})",
                found.version,
                found.length_bytes,
                found.digest,
                expected.version,
                expected.length_bytes,
                expected.digest
            ),
            Self::UnknownTarget { name } => write!(f, "no target is named {name}"),
            Self::ClassMismatch {
                name,
                declared,
                expected,
            } => write!(
                f,
                "target {name} is declared as {declared}, not {expected}"
            ),
            Self::RevokedRelease {
                content_key,
                reason,
            } => write!(f, "release {content_key} is revoked: {reason}"),
            Self::Superseded {
                name,
                verified,
                current,
            } => write!(
                f,
                "target {name} was verified as {verified} but is now {current}"
            ),
            Self::NotProduction { name, assurance } => write!(
                f,
                "target {name} was verified under the {assurance} profile and cannot launch under production"
            ),
            Self::ClockBehind { floor, now } => write!(
                f,
                "the clock reads {now}, earlier than {floor}, when the client last acted; expiry cannot be judged"
            ),
            Self::RevokedKey {
                role,
                key_id,
                reason,
            } => write!(
                f,
                "{role} metadata reaches its threshold only with key {key_id}, which is revoked: {reason}"
            ),
            Self::RevokedClass {
                name,
                class,
                reason,
            } => write!(
                f,
                "target {name} is of the artifact class {class}, which is revoked: {reason}"
            ),
            Self::RootChainFull { limit } => write!(
                f,
                "the client keeps {limit} roots, the most it holds; pin a newer root to rotate further"
            ),
        }
    }
}

impl std::error::Error for UpdateRefusal {}

/// What a root rotation did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RootRotation {
    pub from: MetadataVersion,
    pub to: MetadataVersion,
    /// Online metadata dropped because its role's keys changed; it must be fetched and
    /// verified again under the new root.
    pub cleared: BTreeSet<Role>,
}

/// What applying a revocation list did.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RevocationApplied {
    pub version: MetadataVersion,
    pub newly_revoked: BTreeSet<ContentKey>,
    pub total_revoked: usize,
}

/// The versions the client trusts now.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TrustedVersions {
    pub root: MetadataVersion,
    pub timestamp: Option<MetadataVersion>,
    pub snapshot: Option<MetadataVersion>,
    pub targets: Option<MetadataVersion>,
    pub revocation: Option<MetadataVersion>,
}

/// A launch the client admitted at the execution boundary.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LaunchAdmission {
    pub name: TargetName,
    pub class: ArtifactClass,
    pub content_key: ContentKey,
    pub assurance: AssuranceProfile,
    pub admitted_at: UnixSeconds,
}

/// A metadata file the client trusts: its typed view, the file exactly as verified, its
/// reference, and the role keys whose valid signatures reached the threshold.
#[derive(Clone, Debug)]
pub(super) struct Held<T> {
    pub(super) metadata: T,
    pub(super) file: MetadataFile,
    pub(super) reference: MetaRef,
    pub(super) signers: BTreeSet<KeyId>,
}

/// Everything the client trusts and keeps, apart from its schemes, profile and feed.
#[derive(Clone, Debug)]
pub(super) struct Trusted {
    /// Every root trusted, oldest first; the last is in force.
    pub(super) roots: Vec<MetadataFile>,
    pub(super) root: RootMetadata,
    /// The keys whose signatures reached the root's own threshold.
    pub(super) root_signers: BTreeSet<KeyId>,
    pub(super) timestamp: Option<Held<TimestampMetadata>>,
    pub(super) snapshot: Option<Held<SnapshotMetadata>>,
    pub(super) targets: Option<Held<TargetsMetadata>>,
    pub(super) revocation_version: Option<MetadataVersion>,
    /// Releases the signed revocation lists revoked.
    pub(super) revoked: BTreeMap<ContentKey, String>,
    /// What the host revoked, as far as the client has seen it.
    pub(super) host: HostRevocations,
    pub(super) floors: BTreeMap<Role, MetadataVersion>,
    pub(super) time_floor: UnixSeconds,
}

impl Trusted {
    fn new(
        file: MetadataFile,
        root: RootMetadata,
        signers: BTreeSet<KeyId>,
        now: UnixSeconds,
    ) -> Self {
        Self {
            roots: vec![file],
            floors: BTreeMap::from([(Role::Root, root.version)]),
            root,
            root_signers: signers,
            timestamp: None,
            snapshot: None,
            targets: None,
            revocation_version: None,
            revoked: BTreeMap::new(),
            host: HostRevocations::default(),
            time_floor: now,
        }
    }

    /// Raises the floor of `role` to `version`.
    fn settle(&mut self, role: Role, version: MetadataVersion) {
        let floor = self.floors.entry(role).or_insert(version);
        if *floor < version {
            *floor = version;
        }
    }

    pub(super) fn raise_time(&mut self, now: UnixSeconds) {
        if now > self.time_floor {
            self.time_floor = now;
        }
    }
}

/// The client's trusted state.
pub struct UpdateClient {
    pub(super) schemes: SchemeRegistry,
    pub(super) profile: ResolvedProfile,
    pub(super) feed: Option<RevocationFeed>,
    pub(super) trusted: Trusted,
}

impl fmt::Debug for UpdateClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UpdateClient")
            .field("profile", &self.profile)
            .field("versions", &self.trusted_versions())
            .field("floors", &self.trusted.floors)
            .field("time_floor", &self.trusted.time_floor)
            .field("revoked", &self.trusted.revoked.len())
            .field("feed", &self.feed)
            .finish()
    }
}

impl UpdateClient {
    /// Starts from `trusted_root`, which the caller obtained out of band: it must check
    /// out, be signed by its own root threshold and be unexpired, and under the
    /// production profile every key must use a production-grade scheme.
    pub fn new(
        schemes: SchemeRegistry,
        profile: ResolvedProfile,
        trusted_root: &MetadataFile,
        now: UnixSeconds,
    ) -> Result<Self, UpdateRefusal> {
        let client = Self::start(schemes, profile, trusted_root, now)?;
        check_unexpired(Role::Root, client.trusted.root.expires, now)?;
        Ok(client)
    }

    /// [`Self::new`] without the expiry check: a restore judges the expiry of the root in
    /// force when it is used, not of the root it starts from.
    pub(super) fn start(
        schemes: SchemeRegistry,
        profile: ResolvedProfile,
        trusted_root: &MetadataFile,
        now: UnixSeconds,
    ) -> Result<Self, UpdateRefusal> {
        let root: RootMetadata = parse(trusted_root)?;
        root.check().map_err(metadata)?;
        let role_keys = root.role_keys(Role::Root).map_err(metadata)?;
        let witness = verify_threshold(trusted_root, Role::Root, &root.keys, role_keys, &schemes)
            .map_err(signatures)?;
        check_schemes(profile, &root)?;
        Ok(Self {
            schemes,
            profile,
            feed: None,
            trusted: Trusted::new(trusted_root.clone(), root, witness.signers, now),
        })
    }

    /// Reads the host's revocations from `feed` at every check from now on. A feed
    /// attached before is replaced; what it revoked stays revoked.
    pub fn attach_revocations(&mut self, feed: RevocationFeed) {
        if let Some(previous) = self.feed.replace(feed) {
            self.trusted.host.absorb(&previous.current());
        }
    }

    pub fn root(&self) -> &RootMetadata {
        &self.trusted.root
    }

    pub fn profile(&self) -> AssuranceProfile {
        self.profile.profile()
    }

    pub fn trusted_versions(&self) -> TrustedVersions {
        let trusted = &self.trusted;
        TrustedVersions {
            root: trusted.root.version,
            timestamp: trusted.timestamp.as_ref().map(|held| held.metadata.version),
            snapshot: trusted.snapshot.as_ref().map(|held| held.metadata.version),
            targets: trusted.targets.as_ref().map(|held| held.metadata.version),
            revocation: trusted.revocation_version,
        }
    }

    /// Revoked releases by content key, with their reasons, as the signed lists revoked
    /// them.
    pub fn revoked(&self) -> &BTreeMap<ContentKey, String> {
        &self.trusted.revoked
    }

    /// Everything the host revoked that the client has seen or now sees on its feed.
    pub fn host_revocations(&self) -> HostRevocations {
        let mut revocations = self.trusted.host.clone();
        if let Some(feed) = &self.feed {
            revocations.absorb(&feed.current());
        }
        revocations
    }

    /// The highest version accepted per role while the role's keys stayed the same.
    pub fn floors(&self) -> &BTreeMap<Role, MetadataVersion> {
        &self.trusted.floors
    }

    /// The latest calendar time the client acted at.
    pub fn time_floor(&self) -> UnixSeconds {
        self.trusted.time_floor
    }

    /// Records that the client acted at `now`, so a later clock behind it is refused.
    /// Refuses a clock already behind.
    pub fn observe_time(&mut self, now: UnixSeconds) -> Result<(), UpdateRefusal> {
        self.check_clock(now)?;
        self.trusted.raise_time(now);
        Ok(())
    }

    /// Rotates to `candidate`: exactly the next root version, signed by the threshold of
    /// the trusted root's root keys and by the threshold of its own (line 2668 "key
    /// rotation"; VM-P48, line 2823). Online metadata whose role keys changed is
    /// dropped. Revocations stay in force across rotations.
    pub fn update_root(
        &mut self,
        candidate: &MetadataFile,
        now: UnixSeconds,
    ) -> Result<RootRotation, UpdateRefusal> {
        self.check_clock(now)?;
        let rotation = self.rotate(candidate, Some(now))?;
        self.trusted.raise_time(now);
        Ok(rotation)
    }

    /// The rotation itself; the new root's expiry is checked at `expiry_at` when given.
    /// A restore passes none, since it re-verifies roots that were accepted unexpired.
    pub(super) fn rotate(
        &mut self,
        candidate: &MetadataFile,
        expiry_at: Option<UnixSeconds>,
    ) -> Result<RootRotation, UpdateRefusal> {
        let new: RootMetadata = parse(candidate)?;
        new.check().map_err(metadata)?;
        let trusted = self.trusted.root.version;
        if new.version <= trusted {
            return Err(if new.version == trusted {
                UpdateRefusal::Replayed {
                    role: Role::Root,
                    version: new.version,
                }
            } else {
                UpdateRefusal::RolledBack {
                    role: Role::Root,
                    trusted,
                    offered: new.version,
                }
            });
        }
        if Some(new.version) != trusted.next() {
            return Err(UpdateRefusal::VersionGap {
                role: Role::Root,
                trusted,
                offered: new.version,
            });
        }
        if self.trusted.roots.len() >= MAX_TRUSTED_ROOTS {
            return Err(UpdateRefusal::RootChainFull {
                limit: MAX_TRUSTED_ROOTS,
            });
        }
        let old_keys = self.trusted.root.role_keys(Role::Root).map_err(metadata)?;
        let old = verify_threshold(
            candidate,
            Role::Root,
            &self.trusted.root.keys,
            old_keys,
            &self.schemes,
        )
        .map_err(signatures)?;
        self.counted(Role::Root, &old.signers, old_keys.threshold)?;
        let new_keys = new.role_keys(Role::Root).map_err(metadata)?;
        let own = verify_threshold(candidate, Role::Root, &new.keys, new_keys, &self.schemes)
            .map_err(signatures)?;
        self.counted(Role::Root, &own.signers, new_keys.threshold)?;
        check_schemes(self.profile, &new)?;
        if let Some(now) = expiry_at {
            check_unexpired(Role::Root, new.expires, now)?;
        }

        let changed: BTreeSet<Role> = Role::ALL
            .into_iter()
            .filter(|role| role.is_online())
            .filter(|role| self.trusted.root.roles.get(role) != new.roles.get(role))
            .collect();
        let mut cleared = BTreeSet::new();
        if !changed.is_empty() {
            if self.trusted.timestamp.take().is_some() {
                cleared.insert(Role::Timestamp);
            }
            if self.trusted.snapshot.take().is_some() {
                cleared.insert(Role::Snapshot);
            }
            if self.trusted.targets.take().is_some() {
                cleared.insert(Role::Targets);
            }
            for role in &changed {
                self.trusted.floors.remove(role);
            }
        }
        self.trusted.roots.push(candidate.clone());
        self.trusted.settle(Role::Root, new.version);
        self.trusted.root = new;
        self.trusted.root_signers = own.signers;
        Ok(RootRotation {
            from: trusted,
            to: self.trusted.root.version,
            cleared,
        })
    }

    /// Trusts a new timestamp: signed by the timestamp threshold, newer than the trusted
    /// one, referencing a snapshot no older than the trusted one or the snapshot floor,
    /// and unexpired.
    pub fn update_timestamp(
        &mut self,
        file: &MetadataFile,
        now: UnixSeconds,
    ) -> Result<(), UpdateRefusal> {
        self.check_clock(now)?;
        let signers = self.verify_role(file, Role::Timestamp)?;
        let new: TimestampMetadata = parse(file)?;
        new.check().map_err(metadata)?;
        if let Some(current) = &self.trusted.timestamp {
            check_newer(Role::Timestamp, current.metadata.version, new.version)?;
            if new.snapshot.version < current.metadata.snapshot.version {
                return Err(UpdateRefusal::RolledBack {
                    role: Role::Snapshot,
                    trusted: current.metadata.snapshot.version,
                    offered: new.snapshot.version,
                });
            }
        }
        self.check_floor(Role::Timestamp, new.version)?;
        self.check_floor(Role::Snapshot, new.snapshot.version)?;
        check_unexpired(Role::Timestamp, new.expires, now)?;
        let reference = file.file_reference(new.version).map_err(metadata)?;
        let version = new.version;
        self.trusted.timestamp = Some(Held {
            metadata: new,
            file: file.clone(),
            reference,
            signers,
        });
        self.trusted.settle(Role::Timestamp, version);
        self.trusted.raise_time(now);
        Ok(())
    }

    /// Trusts a new snapshot: exactly the file the trusted timestamp references, signed
    /// by the snapshot threshold, referencing targets no older than before, unexpired.
    pub fn update_snapshot(
        &mut self,
        file: &MetadataFile,
        now: UnixSeconds,
    ) -> Result<(), UpdateRefusal> {
        self.check_clock(now)?;
        let expected = self
            .trusted
            .timestamp
            .as_ref()
            .map(|timestamp| timestamp.metadata.snapshot)
            .ok_or(UpdateRefusal::MissingPrerequisite {
                needed: Role::Timestamp,
            })?;
        let new: SnapshotMetadata = parse(file)?;
        new.check().map_err(metadata)?;
        let found = file.file_reference(new.version).map_err(metadata)?;
        if found != expected {
            return Err(UpdateRefusal::DoesNotMatchReference {
                role: Role::Snapshot,
                referenced_by: Role::Timestamp,
                expected,
                found,
            });
        }
        let signers = self.verify_role(file, Role::Snapshot)?;
        if let Some(current) = &self.trusted.snapshot {
            if new.version < current.metadata.version {
                return Err(UpdateRefusal::RolledBack {
                    role: Role::Snapshot,
                    trusted: current.metadata.version,
                    offered: new.version,
                });
            }
            if new.targets.version < current.metadata.targets.version {
                return Err(UpdateRefusal::RolledBack {
                    role: Role::Targets,
                    trusted: current.metadata.targets.version,
                    offered: new.targets.version,
                });
            }
        }
        self.check_floor(Role::Snapshot, new.version)?;
        self.check_floor(Role::Targets, new.targets.version)?;
        check_unexpired(Role::Snapshot, new.expires, now)?;
        let version = new.version;
        self.trusted.snapshot = Some(Held {
            metadata: new,
            file: file.clone(),
            reference: found,
            signers,
        });
        self.trusted.settle(Role::Snapshot, version);
        self.trusted.raise_time(now);
        Ok(())
    }

    /// Trusts new targets: exactly the file the trusted snapshot references, signed by
    /// the targets threshold, unexpired.
    pub fn update_targets(
        &mut self,
        file: &MetadataFile,
        now: UnixSeconds,
    ) -> Result<(), UpdateRefusal> {
        self.check_clock(now)?;
        let expected = self
            .trusted
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.metadata.targets)
            .ok_or(UpdateRefusal::MissingPrerequisite {
                needed: Role::Snapshot,
            })?;
        let new: TargetsMetadata = parse(file)?;
        new.check().map_err(metadata)?;
        let found = file.file_reference(new.version).map_err(metadata)?;
        if found != expected {
            return Err(UpdateRefusal::DoesNotMatchReference {
                role: Role::Targets,
                referenced_by: Role::Snapshot,
                expected,
                found,
            });
        }
        let signers = self.verify_role(file, Role::Targets)?;
        self.check_floor(Role::Targets, new.version)?;
        check_unexpired(Role::Targets, new.expires, now)?;
        let version = new.version;
        self.trusted.targets = Some(Held {
            metadata: new,
            file: file.clone(),
            reference: found,
            signers,
        });
        self.trusted.settle(Role::Targets, version);
        self.trusted.raise_time(now);
        Ok(())
    }

    /// Applies a revocation list signed by the revocation threshold (line 2668
    /// "emergency revocation"). It needs no timestamp and no snapshot, so it works
    /// offline; its version must rise; and revocations only accumulate, so a later
    /// list that omits a release does not restore it.
    pub fn update_revocation(
        &mut self,
        file: &MetadataFile,
    ) -> Result<RevocationApplied, UpdateRefusal> {
        self.verify_role(file, Role::Revocation)?;
        let new: RevocationMetadata = parse(file)?;
        new.check().map_err(metadata)?;
        if let Some(current) = self.trusted.revocation_version {
            check_newer(Role::Revocation, current, new.version)?;
        }
        let mut newly_revoked = BTreeSet::new();
        for (content_key, reason) in new.revoked {
            if !self.trusted.revoked.contains_key(&content_key) {
                newly_revoked.insert(content_key);
                self.trusted.revoked.insert(content_key, reason);
            }
        }
        self.trusted.revocation_version = Some(new.version);
        self.trusted.settle(Role::Revocation, new.version);
        Ok(RevocationApplied {
            version: new.version,
            newly_revoked,
            total_revoked: self.trusted.revoked.len(),
        })
    }

    /// The verified handle for target `name` of `class`, if every trusted file is
    /// unexpired at `now` (offline behaviour: an expiry reached since the fetch is a
    /// refusal), rests on no revoked key, and neither the release nor its class is
    /// revoked.
    pub fn verify_target(
        &self,
        name: &TargetName,
        class: ArtifactClass,
        now: UnixSeconds,
    ) -> Result<VerifiedTarget, UpdateRefusal> {
        self.check_clock(now)?;
        let (timestamp, snapshot, targets) = self.fresh(now)?;
        let entry = targets
            .targets
            .get(name)
            .ok_or_else(|| UpdateRefusal::UnknownTarget { name: name.clone() })?;
        if entry.class != class {
            return Err(UpdateRefusal::ClassMismatch {
                name: name.clone(),
                declared: entry.class,
                expected: class,
            });
        }
        self.check_not_revoked(entry.content_key)?;
        self.check_class(name, entry.class)?;
        Ok(VerifiedTarget::signed(
            name.clone(),
            entry,
            self.profile.profile(),
            VerificationBasis::Signed {
                root_version: self.trusted.root.version,
                timestamp_version: timestamp.version,
                snapshot_version: snapshot.version,
                targets_version: targets.version,
            },
            now,
        ))
    }

    /// The check at the execution boundary (VM-P23, line 2798): the opened artifact's
    /// release and class are not revoked, the metadata is still unexpired and rests on no
    /// revoked key, the trusted targets still name these bytes, and the profile admits
    /// the target's assurance.
    pub fn admit_launch(
        &self,
        opened: &OpenedArtifact,
        now: UnixSeconds,
    ) -> Result<LaunchAdmission, UpdateRefusal> {
        let target = opened.target();
        self.check_not_revoked(opened.content_key())?;
        self.check_class(target.name(), target.class())?;
        self.check_clock(now)?;
        if self.profile.is_production() && target.assurance() != AssuranceProfile::Production {
            return Err(UpdateRefusal::NotProduction {
                name: target.name().clone(),
                assurance: target.assurance(),
            });
        }
        if let VerificationBasis::Signed { .. } = target.basis() {
            let (_, _, targets) = self.fresh(now)?;
            let entry =
                targets
                    .targets
                    .get(target.name())
                    .ok_or_else(|| UpdateRefusal::UnknownTarget {
                        name: target.name().clone(),
                    })?;
            if entry.content_key != opened.content_key() {
                return Err(UpdateRefusal::Superseded {
                    name: target.name().clone(),
                    verified: opened.content_key(),
                    current: entry.content_key,
                });
            }
        }
        Ok(LaunchAdmission {
            name: target.name().clone(),
            class: target.class(),
            content_key: opened.content_key(),
            assurance: target.assurance(),
            admitted_at: now,
        })
    }

    /// The signers of `file` as `role`, if they reach the role's threshold without a
    /// revoked key.
    fn verify_role(
        &self,
        file: &MetadataFile,
        role: Role,
    ) -> Result<BTreeSet<KeyId>, UpdateRefusal> {
        let role_keys = self.trusted.root.role_keys(role).map_err(metadata)?;
        let witness = verify_threshold(
            file,
            role,
            &self.trusted.root.keys,
            role_keys,
            &self.schemes,
        )
        .map_err(signatures)?;
        self.counted(role, &witness.signers, role_keys.threshold)?;
        Ok(witness.signers)
    }

    /// The trusted chain if it is complete, consistent, unexpired at `now` and resting on
    /// no revoked key. The previous snapshot and targets stay trusted after a newer
    /// timestamp arrives, as the rollback baseline for what follows, but they serve
    /// nothing until the files the timestamp and snapshot reference have been fetched and
    /// verified.
    fn fresh(
        &self,
        now: UnixSeconds,
    ) -> Result<(&TimestampMetadata, &SnapshotMetadata, &TargetsMetadata), UpdateRefusal> {
        let trusted = &self.trusted;
        check_unexpired(Role::Root, trusted.root.expires, now)?;
        self.counted(
            Role::Root,
            &trusted.root_signers,
            self.threshold(Role::Root)?,
        )?;
        let timestamp = trusted
            .timestamp
            .as_ref()
            .ok_or(UpdateRefusal::MissingPrerequisite {
                needed: Role::Timestamp,
            })?;
        check_unexpired(Role::Timestamp, timestamp.metadata.expires, now)?;
        self.counted(
            Role::Timestamp,
            &timestamp.signers,
            self.threshold(Role::Timestamp)?,
        )?;
        let snapshot = trusted
            .snapshot
            .as_ref()
            .filter(|snapshot| snapshot.reference == timestamp.metadata.snapshot)
            .ok_or(UpdateRefusal::MissingPrerequisite {
                needed: Role::Snapshot,
            })?;
        check_unexpired(Role::Snapshot, snapshot.metadata.expires, now)?;
        self.counted(
            Role::Snapshot,
            &snapshot.signers,
            self.threshold(Role::Snapshot)?,
        )?;
        let targets = trusted
            .targets
            .as_ref()
            .filter(|targets| targets.reference == snapshot.metadata.targets)
            .ok_or(UpdateRefusal::MissingPrerequisite {
                needed: Role::Targets,
            })?;
        check_unexpired(Role::Targets, targets.metadata.expires, now)?;
        self.counted(
            Role::Targets,
            &targets.signers,
            self.threshold(Role::Targets)?,
        )?;
        Ok((&timestamp.metadata, &snapshot.metadata, &targets.metadata))
    }

    fn threshold(&self, role: Role) -> Result<u32, UpdateRefusal> {
        self.trusted
            .root
            .role_keys(role)
            .map(|keys| keys.threshold)
            .map_err(metadata)
    }

    /// Whether `signers` still reach `threshold` once revoked keys are left out; the
    /// first revoked signer is named when they do not.
    fn counted(
        &self,
        role: Role,
        signers: &BTreeSet<KeyId>,
        threshold: u32,
    ) -> Result<(), UpdateRefusal> {
        let mut first_revoked = None;
        let mut remaining: u32 = 0;
        for key_id in signers {
            match self.key_revocation(key_id) {
                Some(reason) => {
                    if first_revoked.is_none() {
                        first_revoked = Some((*key_id, reason));
                    }
                }
                None => remaining = remaining.saturating_add(1),
            }
        }
        match first_revoked {
            Some((key_id, reason)) if remaining < threshold => Err(UpdateRefusal::RevokedKey {
                role,
                key_id,
                reason,
            }),
            _ => Ok(()),
        }
    }

    pub(super) fn check_clock(&self, now: UnixSeconds) -> Result<(), UpdateRefusal> {
        if now < self.trusted.time_floor {
            Err(UpdateRefusal::ClockBehind {
                floor: self.trusted.time_floor,
                now,
            })
        } else {
            Ok(())
        }
    }

    /// Refuses `offered` below the floor of `role`.
    fn check_floor(&self, role: Role, offered: MetadataVersion) -> Result<(), UpdateRefusal> {
        match self.trusted.floors.get(&role) {
            Some(floor) if offered < *floor => Err(UpdateRefusal::RolledBack {
                role,
                trusted: *floor,
                offered,
            }),
            _ => Ok(()),
        }
    }

    fn check_not_revoked(&self, content_key: ContentKey) -> Result<(), UpdateRefusal> {
        let reason = self
            .trusted
            .revoked
            .get(&content_key)
            .or_else(|| self.trusted.host.releases.get(&content_key))
            .cloned()
            .or_else(|| {
                self.feed
                    .as_ref()
                    .and_then(|feed| feed.release(&content_key))
            });
        match reason {
            Some(reason) => Err(UpdateRefusal::RevokedRelease {
                content_key,
                reason,
            }),
            None => Ok(()),
        }
    }

    fn check_class(&self, name: &TargetName, class: ArtifactClass) -> Result<(), UpdateRefusal> {
        let reason = self
            .trusted
            .host
            .classes
            .get(&class)
            .cloned()
            .or_else(|| self.feed.as_ref().and_then(|feed| feed.class(class)));
        match reason {
            Some(reason) => Err(UpdateRefusal::RevokedClass {
                name: name.clone(),
                class,
                reason,
            }),
            None => Ok(()),
        }
    }

    fn key_revocation(&self, key_id: &KeyId) -> Option<String> {
        self.trusted
            .host
            .keys
            .get(key_id)
            .cloned()
            .or_else(|| self.feed.as_ref().and_then(|feed| feed.key(key_id)))
    }
}

pub(super) fn parse<T: serde::de::DeserializeOwned>(
    file: &MetadataFile,
) -> Result<T, UpdateRefusal> {
    file.parse().map_err(metadata)
}

pub(super) fn metadata(error: MetadataError) -> UpdateRefusal {
    UpdateRefusal::Metadata { error }
}

pub(super) fn signatures(failure: SignatureFailure) -> UpdateRefusal {
    UpdateRefusal::Signatures { failure }
}

fn check_schemes(profile: ResolvedProfile, root: &RootMetadata) -> Result<(), UpdateRefusal> {
    if !profile.is_production() {
        return Ok(());
    }
    for (key_id, key) in &root.keys {
        if !key.scheme.production_grade() {
            return Err(UpdateRefusal::NonProductionScheme {
                key_id: *key_id,
                scheme: key.scheme,
            });
        }
    }
    Ok(())
}

pub(super) fn check_unexpired(
    role: Role,
    expires: UnixSeconds,
    now: UnixSeconds,
) -> Result<(), UpdateRefusal> {
    if expires.is_expired_at(now) {
        Err(UpdateRefusal::Expired { role, expires, now })
    } else {
        Ok(())
    }
}

fn check_newer(
    role: Role,
    trusted: MetadataVersion,
    offered: MetadataVersion,
) -> Result<(), UpdateRefusal> {
    if offered == trusted {
        Err(UpdateRefusal::Replayed {
            role,
            version: offered,
        })
    } else if offered < trusted {
        Err(UpdateRefusal::RolledBack {
            role,
            trusted,
            offered,
        })
    } else {
        Ok(())
    }
}
