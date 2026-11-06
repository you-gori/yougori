//! The client's trusted state as a record, and its restore after a restart (VM-W45, line
//! 2668: "rollback resistance, offline behavior"; line 2677: "freeze, rollback and
//! mix-and-match attacks"; VM-P48, line 2823: recovery paths for "interrupted trust-root
//! rotation, expired offline metadata and emergency revocation").
//!
//! An [`UpdateClient`] holds its trust in memory; [`UpdateClient::state`] writes it out as
//! a [`TrustState`] and [`UpdateClient::restore`] rebuilds the client from one, so a
//! restart continues where the client stood instead of starting from the pinned root
//! again, which would be a rollback. The state holds:
//!
//! - the signed files exactly as verified: every root since the one the client started
//!   from (the chain that ties the root in force to the pinned root), and the trusted
//!   timestamp, snapshot and targets;
//! - the versions and expiries trusted, recorded beside the files;
//! - the floors: the highest version accepted per role while its keys stayed the same;
//! - the time floor: the latest calendar time the client acted at;
//! - every revocation: the releases the signed lists revoked, the list version, and what
//!   the host revoked (keys, classes, releases).
//!
//! **Restore re-verifies what grants trust and keeps what only restricts.** The chain is
//! verified from the pinned root the caller supplies, which must be one of the stored
//! roots (the operator may pin a newer one; the roots before it are then dropped): each
//! next root needs both thresholds, one version at a time, as when it was accepted. The
//! online files are verified under the root in force. A file that no longer verifies, a
//! chain that does not reach the stored root in force, or a pinned root the state does
//! not hold refuses the restore ([`RestoreRefusal`]); nothing is reset silently. Expiry
//! is not re-judged at restore, since an expired file is still the rollback baseline: it
//! is judged where it is used, at the time asked, and the time floor keeps that time from
//! going back. Floors, the time floor and revocations are taken as stored (a lower floor
//! or a dropped revocation is a weakening only someone able to rewrite the store can make,
//! and that person can delete it too); they are checked for consistency with the files,
//! and a recorded version or expiry that differs from its file refuses the restore.
//!
//! What a restore cannot detect, by design of local storage (§8.2, line 2447: "a
//! same-user local log is not WORM"): a store replaced as a whole by an older consistent
//! copy, or deleted. The `store` module detects torn, truncated and rewritten records.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::client::{
    metadata, parse, signatures, Held, Trusted, UpdateClient, UpdateRefusal, MAX_TRUSTED_ROOTS,
};
use super::metadata::{
    verify_threshold, MetadataFile, MetadataVersion, Role, SnapshotMetadata, TargetsMetadata,
    TimestampMetadata, MAX_REASON_BYTES,
};
use super::profile::{AssuranceProfile, ResolvedProfile};
use super::revocation::{BadRevocationReason, HostRevocations};
use super::signature::SchemeRegistry;
use super::time::UnixSeconds;
use crate::foundation::ids::ContentKey;

/// The trust-state format this build writes and reads. Another is refused, never
/// reinterpreted.
pub const TRUST_STATE_FORMAT: u32 = 1;

/// One role as the state records it: the version trusted and its expiry (the revocation
/// list has none).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleRecord {
    pub version: MetadataVersion,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires: Option<UnixSeconds>,
}

/// The update client's trusted state, as [`UpdateClient::state`] writes it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustState {
    /// [`TRUST_STATE_FORMAT`].
    pub format: u32,
    pub profile: AssuranceProfile,
    /// Every root trusted, oldest first: the root the client started from, then each
    /// rotation. The last is in force.
    pub roots: Vec<MetadataFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<MetadataFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<MetadataFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub targets: Option<MetadataFile>,
    /// The version and expiry of each role trusted now, checked against the files.
    pub trusted: BTreeMap<Role, RoleRecord>,
    /// The highest version accepted per role while its keys stayed the same.
    pub floors: BTreeMap<Role, MetadataVersion>,
    /// The latest calendar time the client acted at.
    pub time_floor: UnixSeconds,
    /// Releases the signed revocation lists revoked.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub revoked: BTreeMap<ContentKey, String>,
    /// What the host revoked.
    #[serde(default)]
    pub host: HostRevocations,
}

impl TrustState {
    /// The recorded version of `role`, if it is trusted.
    pub fn version(&self, role: Role) -> Option<MetadataVersion> {
        self.trusted.get(&role).map(|record| record.version)
    }
}

/// How the parts of a state fail to fit together.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "inconsistency", rename_all = "snake_case")]
pub enum Inconsistency {
    /// The file is held without the file that must reference it.
    WithoutPrerequisite { needed: Role },
    /// The held file is newer than the version the referencing file names.
    AheadOfReference {
        held: MetadataVersion,
        referenced: MetadataVersion,
    },
    /// The recorded version or expiry is not the file's.
    Recorded {
        recorded: Option<RoleRecord>,
        found: Option<RoleRecord>,
    },
    /// The floor is missing or lower than the version trusted, or, for the root, not
    /// the version in force.
    Floor {
        floor: Option<MetadataVersion>,
        trusted: MetadataVersion,
    },
    /// A revocation reason is empty or longer than [`MAX_REASON_BYTES`].
    Reason,
}

impl fmt::Display for Inconsistency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WithoutPrerequisite { needed } => {
                write!(f, "it is held without the {needed} file that references it")
            }
            Self::AheadOfReference { held, referenced } => write!(
                f,
                "version {held} is held, newer than the referenced version {referenced}"
            ),
            Self::Recorded { recorded, found } => write!(
                f,
                "the state records {} but its file is {}",
                describe(recorded),
                describe(found)
            ),
            Self::Floor {
                floor: Some(floor),
                trusted,
            } => write!(
                f,
                "its floor {floor} does not fit the trusted version {trusted}"
            ),
            Self::Floor {
                floor: None,
                trusted,
            } => write!(f, "it has no floor though version {trusted} is trusted"),
            Self::Reason => write!(
                f,
                "a revocation reason is empty or longer than {MAX_REASON_BYTES} bytes"
            ),
        }
    }
}

fn describe(record: &Option<RoleRecord>) -> String {
    match record {
        None => "nothing".to_owned(),
        Some(RoleRecord {
            version,
            expires: Some(expires),
        }) => format!("version {version} expiring at {expires}"),
        Some(RoleRecord {
            version,
            expires: None,
        }) => format!("version {version}"),
    }
}

/// Why a client was not restored from a state. Every case returns no client.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum RestoreRefusal {
    /// Another state format.
    Format { found: u32, expected: u32 },
    /// The state was kept under another assurance profile.
    ProfileChanged {
        stored: AssuranceProfile,
        requested: AssuranceProfile,
    },
    /// The state holds no root, or more than [`MAX_TRUSTED_ROOTS`].
    RootCount { roots: usize, limit: usize },
    /// The pinned root is none of the roots the state holds: the trust roots were
    /// provisioned anew, or the state belongs to another client. Recovery is a new state
    /// started from the pinned root.
    NotFromPinnedRoot,
    /// A stored file no longer verifies, or the chain does not continue.
    Refused { role: Role, reason: UpdateRefusal },
    /// The state's parts do not fit together.
    Inconsistent {
        role: Role,
        inconsistency: Inconsistency,
    },
    /// The clock reads earlier than the stored time floor.
    ClockBehind {
        floor: UnixSeconds,
        now: UnixSeconds,
    },
}

impl fmt::Display for RestoreRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Format { found, expected } => write!(
                f,
                "the trust state has format {found}; this build reads format {expected}"
            ),
            Self::ProfileChanged { stored, requested } => write!(
                f,
                "the trust state was kept under the {stored} profile, not {requested}"
            ),
            Self::RootCount { roots, limit } => write!(
                f,
                "the trust state holds {roots} roots; it must hold 1 to {limit}"
            ),
            Self::NotFromPinnedRoot => f.write_str(
                "the pinned root is not among the roots the trust state holds; start a new trust state from it",
            ),
            Self::Refused { role, reason } => {
                write!(f, "the stored {role} metadata does not verify: {reason}")
            }
            Self::Inconsistent {
                role,
                inconsistency,
            } => write!(f, "the stored {role} state is inconsistent: {inconsistency}"),
            Self::ClockBehind { floor, now } => write!(
                f,
                "the clock reads {now}, earlier than {floor}, when the client last acted"
            ),
        }
    }
}

impl std::error::Error for RestoreRefusal {}

impl UpdateClient {
    /// The client's trusted state, for [`Self::restore`] after a restart. What the host
    /// revoked includes the attached feed's revocations now.
    pub fn state(&self) -> TrustState {
        let trusted = &self.trusted;
        TrustState {
            format: TRUST_STATE_FORMAT,
            profile: self.profile(),
            roots: trusted.roots.clone(),
            timestamp: trusted.timestamp.as_ref().map(|held| held.file.clone()),
            snapshot: trusted.snapshot.as_ref().map(|held| held.file.clone()),
            targets: trusted.targets.as_ref().map(|held| held.file.clone()),
            trusted: records(trusted),
            floors: trusted.floors.clone(),
            time_floor: trusted.time_floor,
            revoked: trusted.revoked.clone(),
            host: self.host_revocations(),
        }
    }

    /// Rebuilds the client `state` describes, as the module documentation explains:
    /// the chain verified from `pinned_root` (one of the stored roots), the online files
    /// verified under the root in force, records, floors and revocations checked against
    /// them, and `now` no earlier than the stored time floor. The restored client has no
    /// revocation feed attached; attach it again.
    pub fn restore(
        schemes: SchemeRegistry,
        profile: ResolvedProfile,
        pinned_root: &MetadataFile,
        state: &TrustState,
        now: UnixSeconds,
    ) -> Result<Self, RestoreRefusal> {
        if state.format != TRUST_STATE_FORMAT {
            return Err(RestoreRefusal::Format {
                found: state.format,
                expected: TRUST_STATE_FORMAT,
            });
        }
        if state.profile != profile.profile() {
            return Err(RestoreRefusal::ProfileChanged {
                stored: state.profile,
                requested: profile.profile(),
            });
        }
        if state.roots.is_empty() || state.roots.len() > MAX_TRUSTED_ROOTS {
            return Err(RestoreRefusal::RootCount {
                roots: state.roots.len(),
                limit: MAX_TRUSTED_ROOTS,
            });
        }
        if now < state.time_floor {
            return Err(RestoreRefusal::ClockBehind {
                floor: state.time_floor,
                now,
            });
        }
        let anchor = state
            .roots
            .iter()
            .position(|root| root == pinned_root)
            .ok_or(RestoreRefusal::NotFromPinnedRoot)?;
        let refused = |role| move |reason| RestoreRefusal::Refused { role, reason };
        let mut client =
            Self::start(schemes, profile, pinned_root, now).map_err(refused(Role::Root))?;
        for root in &state.roots[anchor + 1..] {
            client.rotate(root, None).map_err(refused(Role::Root))?;
        }

        client.trusted.timestamp =
            held::<TimestampMetadata>(&client, Role::Timestamp, &state.timestamp)?;
        client.trusted.snapshot =
            held::<SnapshotMetadata>(&client, Role::Snapshot, &state.snapshot)?;
        client.trusted.targets = held::<TargetsMetadata>(&client, Role::Targets, &state.targets)?;
        check_chain(&client)?;

        client.trusted.revocation_version = state.version(Role::Revocation);
        let found = records(&client.trusted);
        for role in Role::ALL {
            let recorded = state.trusted.get(&role).copied();
            let file = found.get(&role).copied();
            if recorded != file {
                return Err(RestoreRefusal::Inconsistent {
                    role,
                    inconsistency: Inconsistency::Recorded {
                        recorded,
                        found: file,
                    },
                });
            }
            if let Some(record) = file {
                let floor = state.floors.get(&role).copied();
                let fits = match floor {
                    None => false,
                    Some(floor) if role == Role::Root => floor == record.version,
                    Some(floor) => floor >= record.version,
                };
                if !fits {
                    return Err(RestoreRefusal::Inconsistent {
                        role,
                        inconsistency: Inconsistency::Floor {
                            floor,
                            trusted: record.version,
                        },
                    });
                }
            }
        }
        if state.revoked.values().any(|reason| bad_reason(reason)) {
            return Err(RestoreRefusal::Inconsistent {
                role: Role::Revocation,
                inconsistency: Inconsistency::Reason,
            });
        }
        state
            .host
            .check()
            .map_err(|_: BadRevocationReason| RestoreRefusal::Inconsistent {
                role: Role::Revocation,
                inconsistency: Inconsistency::Reason,
            })?;
        let trusted = &mut client.trusted;
        // The chain verified above started the root floor at the pinned root; the stored
        // floors hold what the client had accepted.
        trusted.floors = state.floors.clone();
        trusted.revoked = state.revoked.clone();
        trusted.host = state.host.clone();
        trusted.time_floor = now;
        Ok(client)
    }
}

/// The version and expiry of each role `trusted` holds.
fn records(trusted: &Trusted) -> BTreeMap<Role, RoleRecord> {
    let expiring = |version, expires| RoleRecord {
        version,
        expires: Some(expires),
    };
    let mut records = BTreeMap::from([(
        Role::Root,
        expiring(trusted.root.version, trusted.root.expires),
    )]);
    if let Some(held) = &trusted.timestamp {
        records.insert(
            Role::Timestamp,
            expiring(held.metadata.version, held.metadata.expires),
        );
    }
    if let Some(held) = &trusted.snapshot {
        records.insert(
            Role::Snapshot,
            expiring(held.metadata.version, held.metadata.expires),
        );
    }
    if let Some(held) = &trusted.targets {
        records.insert(
            Role::Targets,
            expiring(held.metadata.version, held.metadata.expires),
        );
    }
    if let Some(version) = trusted.revocation_version {
        records.insert(
            Role::Revocation,
            RoleRecord {
                version,
                expires: None,
            },
        );
    }
    records
}

fn bad_reason(reason: &str) -> bool {
    reason.is_empty() || reason.len() > MAX_REASON_BYTES
}

/// The stored online file of `role`, verified under the root in force.
fn held<T>(
    client: &UpdateClient,
    role: Role,
    file: &Option<MetadataFile>,
) -> Result<Option<Held<T>>, RestoreRefusal>
where
    T: serde::de::DeserializeOwned + Versioned,
{
    let Some(file) = file else {
        return Ok(None);
    };
    let refused = |reason| RestoreRefusal::Refused { role, reason };
    let metadata_view: T = parse(file).map_err(refused)?;
    metadata_view.check_role().map_err(refused)?;
    let root = &client.trusted.root;
    let role_keys = root.role_keys(role).map_err(metadata).map_err(refused)?;
    let witness = verify_threshold(file, role, &root.keys, role_keys, &client.schemes)
        .map_err(signatures)
        .map_err(refused)?;
    let reference = file
        .file_reference(metadata_view.version())
        .map_err(metadata)
        .map_err(refused)?;
    Ok(Some(Held {
        metadata: metadata_view,
        file: file.clone(),
        reference,
        signers: witness.signers,
    }))
}

/// The online files fit together as the client leaves them: a snapshot only under a
/// timestamp and targets only under a snapshot, each no newer than the version the file
/// above it references.
fn check_chain(client: &UpdateClient) -> Result<(), RestoreRefusal> {
    let trusted = &client.trusted;
    match (&trusted.timestamp, &trusted.snapshot) {
        (None, Some(_)) => {
            return Err(RestoreRefusal::Inconsistent {
                role: Role::Snapshot,
                inconsistency: Inconsistency::WithoutPrerequisite {
                    needed: Role::Timestamp,
                },
            })
        }
        (Some(timestamp), Some(snapshot))
            if snapshot.metadata.version > timestamp.metadata.snapshot.version =>
        {
            return Err(RestoreRefusal::Inconsistent {
                role: Role::Snapshot,
                inconsistency: Inconsistency::AheadOfReference {
                    held: snapshot.metadata.version,
                    referenced: timestamp.metadata.snapshot.version,
                },
            })
        }
        _ => {}
    }
    match (&trusted.snapshot, &trusted.targets) {
        (None, Some(_)) => Err(RestoreRefusal::Inconsistent {
            role: Role::Targets,
            inconsistency: Inconsistency::WithoutPrerequisite {
                needed: Role::Snapshot,
            },
        }),
        (Some(snapshot), Some(targets))
            if targets.metadata.version > snapshot.metadata.targets.version =>
        {
            Err(RestoreRefusal::Inconsistent {
                role: Role::Targets,
                inconsistency: Inconsistency::AheadOfReference {
                    held: targets.metadata.version,
                    referenced: snapshot.metadata.targets.version,
                },
            })
        }
        _ => Ok(()),
    }
}

/// What restore needs of an online role's typed view.
trait Versioned {
    fn version(&self) -> MetadataVersion;
    fn check_role(&self) -> Result<(), UpdateRefusal>;
}

impl Versioned for TimestampMetadata {
    fn version(&self) -> MetadataVersion {
        self.version
    }

    fn check_role(&self) -> Result<(), UpdateRefusal> {
        self.check().map_err(metadata)
    }
}

impl Versioned for SnapshotMetadata {
    fn version(&self) -> MetadataVersion {
        self.version
    }

    fn check_role(&self) -> Result<(), UpdateRefusal> {
        self.check().map_err(metadata)
    }
}

impl Versioned for TargetsMetadata {
    fn version(&self) -> MetadataVersion {
        self.version
    }

    fn check_role(&self) -> Result<(), UpdateRefusal> {
        self.check().map_err(metadata)
    }
}
