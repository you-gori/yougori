//! Metadata and artifacts through a bounded fetch port, and the update flow over it
//! (VM-D13, line 3207: "TUF-style narrow design"; VM-W45, line 2668; the update
//! threat-model paragraph, line 2677; §8.3, lines 2453–2455; VM-P23, line 2798; VM-P48,
//! line 2823).
//!
//! The client opens no connection and reads no file: a [`FetchPort`] the caller supplies
//! opens each item for reading, and the client reads at most the item's bound and one
//! byte more, so a longer item is refused without being read to its end and the port
//! need not be trusted to enforce anything. A snapshot or targets file is read up to
//! exactly the length its referencing file names (the repository serves the canonical
//! form), within a ceiling; a root, timestamp or revocation list up to a configured
//! bound ([`FetchLimits`]); an artifact up to the length the targets declare, within a
//! ceiling, and then only through [`VerifiedTarget::open_reader`], so the bytes opened
//! are the bytes verified.
//!
//! [`UpdateClient::refresh`] is the update flow, in the narrow order of VM-D13 with the
//! revocation list placed right after the root:
//!
//! 1. **Clock.** A clock behind the time floor refuses the refresh.
//! 2. **Root.** The next root version is fetched and applied, one version at a time, until
//!    the source has none (at most [`FetchLimits::max_root_rotations`] per refresh).
//! 3. **Revocation.** The newest list is fetched and applied when its version is not the
//!    one trusted (a lower one is refused as a rollback). A source with no list while
//!    the client trusts one is refused: a withdrawn list is a freeze of revocation. This
//!    step runs even when the root step failed, and before the root's expiry is judged
//!    (§8.2, line 2445: "never block the revocation channel"), so a revoked release is in
//!    force whatever else the refresh meets. The root step's failure, if any, is then
//!    reported, and the root in force must be unexpired: an expired root is a freeze.
//! 4. **Timestamp.** The newest timestamp is fetched; the version trusted again is no
//!    change but must still be unexpired, a newer one is applied, an older one refused.
//! 5. **Snapshot, then targets.** Each is fetched at the version the file above it
//!    references, unless the client already holds exactly that file, which must then
//!    still be unexpired.
//!
//! Every step is kept through the [`StateKeeper`] before the next one runs
//! ([`UpdateClient::keep_update`]), and the time floor last, so a refresh that fails
//! keeps the steps before the failure and the report says which. A refusal anywhere is
//! typed ([`RefreshFailure`]); nothing is retried here.

use std::collections::BTreeSet;
use std::fmt;
use std::io::Read;

use super::artifact::{OpenRefusal, OpenedArtifact, VerifiedTarget};
use super::client::{
    check_unexpired, parse, RevocationApplied, RootRotation, TrustedVersions, UpdateClient,
    UpdateRefusal,
};
use super::metadata::{
    MetaRef, MetadataFile, MetadataVersion, RevocationMetadata, Role, TargetName, TimestampMetadata,
};
use super::store::{KeptRefusal, StateKeeper, StoreRefusal};
use super::time::UnixSeconds;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::ids::ContentKey;

/// What the client asks the port for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchItem {
    /// A metadata file of `role`: the newest when `version` is `None` (timestamp and
    /// revocation list), else that exact version (roots, snapshot and targets).
    Metadata {
        role: Role,
        version: Option<MetadataVersion>,
    },
    /// The bytes of a verified target.
    Artifact {
        name: TargetName,
        content_key: ContentKey,
    },
}

impl fmt::Display for FetchItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Metadata {
                role,
                version: Some(version),
            } => write!(f, "{role} metadata version {version}"),
            Self::Metadata {
                role,
                version: None,
            } => write!(f, "the newest {role} metadata"),
            Self::Artifact { name, content_key } => {
                write!(f, "artifact {name} ({content_key})")
            }
        }
    }
}

/// One item and the most bytes the client will read of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FetchRequest {
    pub item: FetchItem,
    pub max_bytes: u64,
}

/// Why the port could not open an item.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchError {
    /// The source has no such item, such as a root version not published yet.
    NotFound,
    /// The source could not be reached or read: offline, or failing.
    Unavailable { detail: String },
}

impl fmt::Display for FetchError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => f.write_str("the source has no such item"),
            Self::Unavailable { detail } => write!(f, "the source is unavailable: {detail}"),
        }
    }
}

impl std::error::Error for FetchError {}

/// The port through which metadata and artifacts arrive. Implementations open the item
/// from wherever the caller keeps releases (a mirror, a local directory, a test double);
/// the client bounds and checks everything it reads.
pub trait FetchPort {
    /// Opens `request`'s item for reading. The client reads at most
    /// `request.max_bytes` and one byte more.
    fn open(&mut self, request: &FetchRequest) -> Result<Box<dyn Read + '_>, FetchError>;
}

/// How much the client reads of each kind of item.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FetchLimits {
    pub root_bytes: u64,
    pub timestamp_bytes: u64,
    pub revocation_bytes: u64,
    /// The longest snapshot a timestamp may reference.
    pub snapshot_bytes: u64,
    /// The longest targets file a snapshot may reference.
    pub targets_bytes: u64,
    /// The longest artifact fetched; the opened artifact holds it in memory.
    pub artifact_bytes: u64,
    /// Root versions applied in one refresh at most.
    pub max_root_rotations: u32,
}

impl FetchLimits {
    pub const DEFAULT: Self = Self {
        root_bytes: 1 << 20,
        timestamp_bytes: 16 << 10,
        revocation_bytes: 1 << 20,
        snapshot_bytes: 64 << 10,
        targets_bytes: 16 << 20,
        artifact_bytes: 1 << 30,
        max_root_rotations: 64,
    };
}

impl Default for FetchLimits {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Why an item fetched was not taken.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FetchRefusal {
    /// The port could not open it.
    Fetch { item: FetchItem, error: FetchError },
    /// More than `limit` bytes arrived; the rest was not read.
    TooLarge { item: FetchItem, limit: u64 },
    /// The referencing file names a file longer than the ceiling, so it is not fetched.
    ReferenceTooLarge {
        role: Role,
        length_bytes: u64,
        limit: u64,
    },
    /// Reading failed part way.
    Unreadable { item: FetchItem, detail: String },
    /// The bytes are not a metadata file.
    Malformed { item: FetchItem, detail: String },
}

impl fmt::Display for FetchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch { item, error } => write!(f, "{item} could not be fetched: {error}"),
            Self::TooLarge { item, limit } => {
                write!(f, "{item} is longer than the {limit} bytes read of it")
            }
            Self::ReferenceTooLarge {
                role,
                length_bytes,
                limit,
            } => write!(
                f,
                "the referenced {role} file is {length_bytes} bytes; at most {limit} are fetched"
            ),
            Self::Unreadable { item, detail } => {
                write!(f, "{item} could not be read: {detail}")
            }
            Self::Malformed { item, detail } => {
                write!(f, "{item} is not a metadata file: {detail}")
            }
        }
    }
}

impl std::error::Error for FetchRefusal {}

/// A step of the refresh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefreshStep {
    Clock,
    Root,
    Revocation,
    Timestamp,
    Snapshot,
    Targets,
    /// Keeping the time floor at the end.
    TimeFloor,
}

impl fmt::Display for RefreshStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Clock => "the clock check",
            Self::Root => "the root step",
            Self::Revocation => "the revocation step",
            Self::Timestamp => "the timestamp step",
            Self::Snapshot => "the snapshot step",
            Self::Targets => "the targets step",
            Self::TimeFloor => "keeping the time floor",
        })
    }
}

/// Why a refresh step failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshRefusal {
    Fetch(FetchRefusal),
    /// The client refused what arrived, or what it holds is expired.
    Refused(UpdateRefusal),
    /// The step was accepted but not kept, so it was undone.
    NotKept(StoreRefusal),
    /// The source has no revocation list though the client trusts version `trusted`.
    RevocationWithdrawn {
        trusted: MetadataVersion,
    },
}

impl fmt::Display for RefreshRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fetch(refusal) => write!(f, "{refusal}"),
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::NotKept(refusal) => write!(
                f,
                "the step was accepted but its state was not kept, so it was undone: {refusal}"
            ),
            Self::RevocationWithdrawn { trusted } => write!(
                f,
                "the source has no revocation list, though version {trusted} is trusted"
            ),
        }
    }
}

impl std::error::Error for RefreshRefusal {}

impl From<KeptRefusal> for RefreshRefusal {
    fn from(refusal: KeptRefusal) -> Self {
        match refusal {
            KeptRefusal::Refused(refusal) => Self::Refused(refusal),
            KeptRefusal::NotKept(refusal) => Self::NotKept(refusal),
        }
    }
}

/// What a refresh did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshReport {
    pub before: TrustedVersions,
    pub after: TrustedVersions,
    pub rotations: Vec<RootRotation>,
    /// The refresh stopped at [`FetchLimits::max_root_rotations`]; more roots may follow.
    pub rotation_limit_reached: bool,
    pub revocation: Option<RevocationApplied>,
    /// Roles whose files this refresh fetched, trusted and kept.
    pub updated: BTreeSet<Role>,
}

/// A refresh that stopped at `step`. Steps before it are in force and kept, as `report`
/// shows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefreshFailure {
    pub step: RefreshStep,
    pub refusal: RefreshRefusal,
    pub report: RefreshReport,
}

impl fmt::Display for RefreshFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the refresh stopped at {}: {}", self.step, self.refusal)
    }
}

impl std::error::Error for RefreshFailure {}

/// Why an artifact was not fetched and opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ArtifactFetchRefusal {
    /// The client does not verify the target now.
    Refused(UpdateRefusal),
    /// The target is longer than [`FetchLimits::artifact_bytes`].
    TooLarge {
        length_bytes: u64,
        limit: u64,
    },
    Fetch(FetchError),
    /// The bytes are not the verified bytes, or could not be read.
    Open(OpenRefusal),
}

impl fmt::Display for ArtifactFetchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(refusal) => write!(f, "{refusal}"),
            Self::TooLarge {
                length_bytes,
                limit,
            } => write!(
                f,
                "the target is {length_bytes} bytes; at most {limit} are fetched"
            ),
            Self::Fetch(error) => write!(f, "the artifact could not be fetched: {error}"),
            Self::Open(refusal) => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for ArtifactFetchRefusal {}

type StepResult<T> = Result<T, (RefreshStep, RefreshRefusal)>;

impl UpdateClient {
    /// Fetches and applies new metadata through `port` in the order the module
    /// documentation gives, keeping each step through `keeper`.
    pub fn refresh(
        &mut self,
        port: &mut dyn FetchPort,
        keeper: &mut dyn StateKeeper,
        limits: &FetchLimits,
        now: UnixSeconds,
    ) -> Result<RefreshReport, RefreshFailure> {
        let mut report = RefreshReport {
            before: self.trusted_versions(),
            after: self.trusted_versions(),
            rotations: Vec::new(),
            rotation_limit_reached: false,
            revocation: None,
            updated: BTreeSet::new(),
        };
        let result = self.run_refresh(port, keeper, limits, now, &mut report);
        report.after = self.trusted_versions();
        match result {
            Ok(()) => Ok(report),
            Err((step, refusal)) => Err(RefreshFailure {
                step,
                refusal,
                report,
            }),
        }
    }

    fn run_refresh(
        &mut self,
        port: &mut dyn FetchPort,
        keeper: &mut dyn StateKeeper,
        limits: &FetchLimits,
        now: UnixSeconds,
        report: &mut RefreshReport,
    ) -> StepResult<()> {
        self.check_clock(now)
            .map_err(|refusal| (RefreshStep::Clock, RefreshRefusal::Refused(refusal)))?;
        let root = self.refresh_root(port, keeper, limits, now, report);
        let revocation = self.refresh_revocation(port, keeper, limits, report);
        root?;
        revocation?;
        check_unexpired(Role::Root, self.trusted.root.expires, now)
            .map_err(|refusal| (RefreshStep::Root, RefreshRefusal::Refused(refusal)))?;
        self.refresh_timestamp(port, keeper, limits, now, report)?;
        self.refresh_snapshot(port, keeper, limits, now, report)?;
        self.refresh_targets(port, keeper, limits, now, report)?;
        if now > self.trusted.time_floor {
            self.keep_update(keeper, |client| client.observe_time(now))
                .map_err(|refusal| (RefreshStep::TimeFloor, refusal.into()))?;
        }
        Ok(())
    }

    fn refresh_root(
        &mut self,
        port: &mut dyn FetchPort,
        keeper: &mut dyn StateKeeper,
        limits: &FetchLimits,
        now: UnixSeconds,
        report: &mut RefreshReport,
    ) -> StepResult<()> {
        let step = RefreshStep::Root;
        let mut applied = 0;
        while let Some(next) = self.trusted.root.version.next() {
            if applied >= limits.max_root_rotations {
                report.rotation_limit_reached = true;
                break;
            }
            let file = match fetch_metadata(port, Role::Root, Some(next), limits.root_bytes) {
                Ok(file) => file,
                Err(FetchRefusal::Fetch {
                    error: FetchError::NotFound,
                    ..
                }) => break,
                Err(refusal) => return Err((step, RefreshRefusal::Fetch(refusal))),
            };
            let rotation = self
                .keep_update(keeper, |client| client.update_root(&file, now))
                .map_err(|refusal| (step, refusal.into()))?;
            report.rotations.push(rotation);
            report.updated.insert(Role::Root);
            applied += 1;
        }
        Ok(())
    }

    fn refresh_revocation(
        &mut self,
        port: &mut dyn FetchPort,
        keeper: &mut dyn StateKeeper,
        limits: &FetchLimits,
        report: &mut RefreshReport,
    ) -> StepResult<()> {
        let step = RefreshStep::Revocation;
        let file = match fetch_metadata(port, Role::Revocation, None, limits.revocation_bytes) {
            Ok(file) => file,
            Err(FetchRefusal::Fetch {
                error: FetchError::NotFound,
                ..
            }) => {
                return match self.trusted.revocation_version {
                    Some(trusted) => Err((step, RefreshRefusal::RevocationWithdrawn { trusted })),
                    None => Ok(()),
                }
            }
            Err(refusal) => return Err((step, RefreshRefusal::Fetch(refusal))),
        };
        let offered = parse::<RevocationMetadata>(&file)
            .map_err(|refusal| (step, RefreshRefusal::Refused(refusal)))?
            .version;
        if Some(offered) == self.trusted.revocation_version {
            return Ok(());
        }
        let applied = self
            .keep_update(keeper, |client| client.update_revocation(&file))
            .map_err(|refusal| (step, refusal.into()))?;
        report.revocation = Some(applied);
        report.updated.insert(Role::Revocation);
        Ok(())
    }

    fn refresh_timestamp(
        &mut self,
        port: &mut dyn FetchPort,
        keeper: &mut dyn StateKeeper,
        limits: &FetchLimits,
        now: UnixSeconds,
        report: &mut RefreshReport,
    ) -> StepResult<()> {
        let step = RefreshStep::Timestamp;
        let file = fetch_metadata(port, Role::Timestamp, None, limits.timestamp_bytes)
            .map_err(|refusal| (step, RefreshRefusal::Fetch(refusal)))?;
        let offered = parse::<TimestampMetadata>(&file)
            .map_err(|refusal| (step, RefreshRefusal::Refused(refusal)))?
            .version;
        let held = self
            .trusted
            .timestamp
            .as_ref()
            .map(|held| (held.metadata.version, held.metadata.expires));
        match held {
            // The timestamp trusted, served again: no change, but a freeze once expired.
            Some((version, expires)) if version == offered => {
                check_unexpired(Role::Timestamp, expires, now)
                    .map_err(|refusal| (step, RefreshRefusal::Refused(refusal)))
            }
            _ => {
                self.keep_update(keeper, |client| client.update_timestamp(&file, now))
                    .map_err(|refusal| (step, refusal.into()))?;
                report.updated.insert(Role::Timestamp);
                Ok(())
            }
        }
    }

    fn refresh_snapshot(
        &mut self,
        port: &mut dyn FetchPort,
        keeper: &mut dyn StateKeeper,
        limits: &FetchLimits,
        now: UnixSeconds,
        report: &mut RefreshReport,
    ) -> StepResult<()> {
        let step = RefreshStep::Snapshot;
        let expected = self
            .trusted
            .timestamp
            .as_ref()
            .map(|held| held.metadata.snapshot)
            .ok_or((
                step,
                RefreshRefusal::Refused(UpdateRefusal::MissingPrerequisite {
                    needed: Role::Timestamp,
                }),
            ))?;
        let held = self
            .trusted
            .snapshot
            .as_ref()
            .filter(|held| held.reference == expected)
            .map(|held| held.metadata.expires);
        if let Some(expires) = held {
            return check_unexpired(Role::Snapshot, expires, now)
                .map_err(|refusal| (step, RefreshRefusal::Refused(refusal)));
        }
        let file = fetch_referenced(port, Role::Snapshot, expected, limits.snapshot_bytes)
            .map_err(|refusal| (step, RefreshRefusal::Fetch(refusal)))?;
        self.keep_update(keeper, |client| client.update_snapshot(&file, now))
            .map_err(|refusal| (step, refusal.into()))?;
        report.updated.insert(Role::Snapshot);
        Ok(())
    }

    fn refresh_targets(
        &mut self,
        port: &mut dyn FetchPort,
        keeper: &mut dyn StateKeeper,
        limits: &FetchLimits,
        now: UnixSeconds,
        report: &mut RefreshReport,
    ) -> StepResult<()> {
        let step = RefreshStep::Targets;
        let expected = self
            .trusted
            .snapshot
            .as_ref()
            .map(|held| held.metadata.targets)
            .ok_or((
                step,
                RefreshRefusal::Refused(UpdateRefusal::MissingPrerequisite {
                    needed: Role::Snapshot,
                }),
            ))?;
        let held = self
            .trusted
            .targets
            .as_ref()
            .filter(|held| held.reference == expected)
            .map(|held| held.metadata.expires);
        if let Some(expires) = held {
            return check_unexpired(Role::Targets, expires, now)
                .map_err(|refusal| (step, RefreshRefusal::Refused(refusal)));
        }
        let file = fetch_referenced(port, Role::Targets, expected, limits.targets_bytes)
            .map_err(|refusal| (step, RefreshRefusal::Fetch(refusal)))?;
        self.keep_update(keeper, |client| client.update_targets(&file, now))
            .map_err(|refusal| (step, refusal.into()))?;
        report.updated.insert(Role::Targets);
        Ok(())
    }

    /// Verifies target `name` of `class` at `now`, fetches its bytes through `port` up
    /// to the declared length, and opens them only if they are the verified bytes. The
    /// launch still passes [`UpdateClient::admit_launch`].
    pub fn fetch_artifact(
        &self,
        port: &mut dyn FetchPort,
        name: &TargetName,
        class: ArtifactClass,
        limits: &FetchLimits,
        now: UnixSeconds,
    ) -> Result<OpenedArtifact, ArtifactFetchRefusal> {
        let verified: VerifiedTarget = self
            .verify_target(name, class, now)
            .map_err(ArtifactFetchRefusal::Refused)?;
        if verified.length_bytes() > limits.artifact_bytes {
            return Err(ArtifactFetchRefusal::TooLarge {
                length_bytes: verified.length_bytes(),
                limit: limits.artifact_bytes,
            });
        }
        let request = FetchRequest {
            item: FetchItem::Artifact {
                name: name.clone(),
                content_key: verified.content_key(),
            },
            max_bytes: verified.length_bytes(),
        };
        let mut reader = port.open(&request).map_err(ArtifactFetchRefusal::Fetch)?;
        verified
            .open_reader(&mut reader)
            .map_err(ArtifactFetchRefusal::Open)
    }
}

/// Reads at most `max_bytes` of `item`, refusing more.
fn read_bounded(
    port: &mut dyn FetchPort,
    item: FetchItem,
    max_bytes: u64,
) -> Result<Vec<u8>, FetchRefusal> {
    let request = FetchRequest { item, max_bytes };
    let mut reader = port.open(&request).map_err(|error| FetchRefusal::Fetch {
        item: request.item.clone(),
        error,
    })?;
    let mut bytes = Vec::new();
    reader
        .by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| FetchRefusal::Unreadable {
            item: request.item.clone(),
            detail: error.to_string(),
        })?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
        return Err(FetchRefusal::TooLarge {
            item: request.item,
            limit: max_bytes,
        });
    }
    Ok(bytes)
}

fn fetch_metadata(
    port: &mut dyn FetchPort,
    role: Role,
    version: Option<MetadataVersion>,
    max_bytes: u64,
) -> Result<MetadataFile, FetchRefusal> {
    let item = FetchItem::Metadata { role, version };
    let bytes = read_bounded(port, item.clone(), max_bytes)?;
    serde_json::from_slice(&bytes).map_err(|error| FetchRefusal::Malformed {
        item,
        detail: error.to_string(),
    })
}

/// Fetches the file `reference` names, reading exactly up to its length.
fn fetch_referenced(
    port: &mut dyn FetchPort,
    role: Role,
    reference: MetaRef,
    ceiling: u64,
) -> Result<MetadataFile, FetchRefusal> {
    if reference.length_bytes > ceiling {
        return Err(FetchRefusal::ReferenceTooLarge {
            role,
            length_bytes: reference.length_bytes,
            limit: ceiling,
        });
    }
    fetch_metadata(port, role, Some(reference.version), reference.length_bytes)
}
