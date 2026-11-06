//! Replaying the trust stream through the update client, and the floors that stored files
//! the client no longer holds leave (VM-W45, plan line 2668: "expiry/version checks,
//! rollback resistance, offline behavior and emergency revocation"; the update
//! threat-model paragraph, line 2677: "freeze, rollback and mix-and-match attacks";
//! VM-P48, line 2823: "interrupted trust-root rotation, expired offline metadata and
//! emergency revocation have documented secure recovery paths").
//!
//! The replay rebuilds the state the client had, through the client's own update calls,
//! in the order the stream holds the files:
//!
//! - **Every root**, through [`UpdateClient::update_root`], one version at a time.
//! - **Every revocation list**, through [`UpdateClient::update_revocation`], at its place
//!   between the roots, so each list is verified under the root it was accepted under
//!   (a list signed before a rotation of the revocation keys still verifies), and the
//!   revoked releases accumulate exactly as they did: the newest list alone may omit an
//!   earlier revocation, which the client never undoes.
//! - **The newest timestamp, snapshot and targets**, each with the files it was accepted
//!   under: the timestamp in force when the newest snapshot was accepted, and the
//!   snapshot (with its timestamp) in force when the newest targets were. So an update
//!   cycle interrupted after its timestamp restarts to the newest timestamp beside the
//!   previous snapshot and targets, as the client held them. Superseded online files are
//!   skipped, and a rotation that changed the online keys drops what came before it, as
//!   the client does when it applies the rotation again.
//!
//! **Expiry.** Replay checks expiry at the time it runs. A timestamp, snapshot or targets
//! file the client refuses only as expired is not loaded, nor is any file accepted under
//! it, nor any older file of its role, since the client never holds a file its role
//! superseded. The replay starts over without them; each keeps its version as a
//! [`Floors`] entry.
//!
//! **Distrusted keys.** Signatures by the distrusted keys (update-root keys an earlier
//! bootstrap pinned and the trust roots no longer pin) are left off every root and
//! revocation file before the client sees it, so a file that needed one of them no longer
//! reaches its threshold. Root keys never sign the online roles (the client refuses such a
//! root), and the snapshot and targets are referenced by the digest of the whole file, so
//! the online files are presented as stored. A root refused once such signatures were
//! left off is not trusted, nor is any root after it until the chain reaches its version
//! again (the custodians signed it anew); it keeps a floor. A revocation list refused
//! with such signatures left off, or while the chain is short of a root left out, keeps
//! its version as a floor and its revoked releases revoked. An online file refused while
//! the chain is short is left out as an expired one is. If the replay ends with the chain
//! short of the newest stored root, no online file is loaded at all: the older root the
//! client holds may list online keys a later rotation retired.
//!
//! Any other refusal, and an expired root, ends the replay with
//! [`RecoveryRefusal::Replay`]: every later file was verified under that root, so nothing
//! starts from part of the chain.

use std::collections::{BTreeMap, BTreeSet};

use super::persisted::{
    AcceptedMetadata, RecordProblem, RecoveryRefusal, TornTailPastMark, TrustRecord,
};
use crate::foundation::events::{
    DurableLog, EventSequence, GapReason, LogEntry, LogMarker, ReadItem, SequenceRange,
};
use crate::foundation::ids::ContentKey;
use crate::sandbox::trust::{
    KeyId, MetadataError, MetadataFile, MetadataVersion, RevocationMetadata, Role, RoleKeys,
    RootMetadata, SnapshotMetadata, TargetsMetadata, TimestampMetadata, TrustedVersions,
    UnixSeconds, UpdateClient, UpdateRefusal,
};

/// Items one read of the replay asks for; the replay reads until it is caught up.
const REPLAY_BATCH_ITEMS: usize = 1_024;

/// The typed view of a metadata file used as one role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum View {
    Root(RootMetadata),
    Timestamp(TimestampMetadata),
    Snapshot(SnapshotMetadata),
    Targets(TargetsMetadata),
    Revocation(RevocationMetadata),
}

impl View {
    /// The payload of `file` as `role`'s schema, declaring `role`. The client's own checks
    /// follow when the file reaches it.
    pub(super) fn parse(role: Role, file: &MetadataFile) -> Result<Self, MetadataError> {
        let view = match role {
            Role::Root => Self::Root(file.parse()?),
            Role::Timestamp => Self::Timestamp(file.parse()?),
            Role::Snapshot => Self::Snapshot(file.parse()?),
            Role::Targets => Self::Targets(file.parse()?),
            Role::Revocation => Self::Revocation(file.parse()?),
        };
        let found = view.role();
        if found != role {
            return Err(MetadataError::WrongRole {
                expected: role,
                found,
            });
        }
        Ok(view)
    }

    fn role(&self) -> Role {
        match self {
            Self::Root(metadata) => metadata.role,
            Self::Timestamp(metadata) => metadata.role,
            Self::Snapshot(metadata) => metadata.role,
            Self::Targets(metadata) => metadata.role,
            Self::Revocation(metadata) => metadata.role,
        }
    }

    pub(super) fn version(&self) -> MetadataVersion {
        match self {
            Self::Root(metadata) => metadata.version,
            Self::Timestamp(metadata) => metadata.version,
            Self::Snapshot(metadata) => metadata.version,
            Self::Targets(metadata) => metadata.version,
            Self::Revocation(metadata) => metadata.version,
        }
    }
}

/// `file` as the client is shown it: for a root or a revocation list, without the
/// signatures of `distrusted` keys. Returns whether any was left off.
pub(super) fn present(
    role: Role,
    file: &MetadataFile,
    distrusted: &BTreeSet<KeyId>,
) -> (MetadataFile, bool) {
    let signs = matches!(role, Role::Root | Role::Revocation);
    if !signs
        || !file
            .signatures()
            .iter()
            .any(|signature| distrusted.contains(&signature.key_id))
    {
        return (file.clone(), false);
    }
    let kept = file
        .signatures()
        .iter()
        .filter(|signature| !distrusted.contains(&signature.key_id))
        .cloned()
        .collect();
    (MetadataFile::new(file.signed().clone(), kept), true)
}

/// The online role keys of `root`, which decide whether a rotation drops the client's
/// online metadata.
pub(super) fn online_roles(root: &RootMetadata) -> BTreeMap<Role, RoleKeys> {
    root.roles
        .iter()
        .filter(|(role, _)| role.is_online())
        .map(|(role, keys)| (*role, keys.clone()))
        .collect()
}

/// An online floor: the stored file's view, and the online keys of the root it was
/// accepted under.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Kept<M> {
    metadata: M,
    online: BTreeMap<Role, RoleKeys>,
}

/// The versions below which the persisted client refuses a file before the client sees
/// it, kept from stored files the client no longer holds: expired, no longer verifying,
/// or accepted under one of those. Each online floor is the stored file's own view, so the
/// comparisons are the client's own for the role it would have held:
///
/// - a timestamp must be newer than the floor (an equal version is a replay) and must
///   reference a snapshot no older than the floor's;
/// - a snapshot must be no older than the floor and reference targets no older than the
///   floor's;
/// - targets must be no older than the floor;
/// - a revocation list must be newer than the floor.
///
/// The root floor is the newest stored root the client no longer trusts. Roots are not
/// held to it, since the client applies them one version at a time from the root it holds
/// and the chain is rebuilt from there; the online roles wait until the client's root
/// reaches it, so that online keys a later rotation retired are not trusted again
/// meanwhile.
///
/// A floor lapses once the client holds its role at or above it. An online floor also
/// lapses when the client rotates to a root whose online keys are not those the floor's
/// file was accepted under, as the client then drops its own online metadata; a root
/// signed anew with the same online keys keeps it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Floors {
    root: Option<MetadataVersion>,
    timestamp: Option<Kept<TimestampMetadata>>,
    snapshot: Option<Kept<SnapshotMetadata>>,
    targets: Option<Kept<TargetsMetadata>>,
    revocation: Option<MetadataVersion>,
}

impl Floors {
    /// Keeps `view`, accepted under a root with the `online` keys, as its role's floor if
    /// it is above the one held.
    fn raise(&mut self, view: &View, online: &BTreeMap<Role, RoleKeys>) {
        /// Keeps `metadata` in `held` unless `held` is at its version or above.
        fn keep<M: Clone>(
            held: &mut Option<Kept<M>>,
            metadata: &M,
            version: fn(&M) -> MetadataVersion,
            online: &BTreeMap<Role, RoleKeys>,
        ) {
            if held
                .as_ref()
                .is_none_or(|floor| version(metadata) > version(&floor.metadata))
            {
                *held = Some(Kept {
                    metadata: metadata.clone(),
                    online: online.clone(),
                });
            }
        }
        match view {
            View::Root(metadata) => {
                if self.root.is_none_or(|floor| metadata.version > floor) {
                    self.root = Some(metadata.version);
                }
            }
            View::Timestamp(metadata) => {
                keep(&mut self.timestamp, metadata, |held| held.version, online);
            }
            View::Snapshot(metadata) => {
                keep(&mut self.snapshot, metadata, |held| held.version, online);
            }
            View::Targets(metadata) => {
                keep(&mut self.targets, metadata, |held| held.version, online);
            }
            View::Revocation(metadata) => {
                if self.revocation.is_none_or(|floor| metadata.version > floor) {
                    self.revocation = Some(metadata.version);
                }
            }
        }
    }

    /// The client rotated to `root`: drops the online floors kept under other online keys.
    pub(super) fn rotated(&mut self, root: &RootMetadata) {
        let online = online_roles(root);
        if self
            .timestamp
            .as_ref()
            .is_some_and(|floor| floor.online != online)
        {
            self.timestamp = None;
        }
        if self
            .snapshot
            .as_ref()
            .is_some_and(|floor| floor.online != online)
        {
            self.snapshot = None;
        }
        if self
            .targets
            .as_ref()
            .is_some_and(|floor| floor.online != online)
        {
            self.targets = None;
        }
    }

    /// Drops the floors of the roles the client holds at or above them.
    pub(super) fn settle(&mut self, trusted: &TrustedVersions) {
        let held = |floor: MetadataVersion, version: Option<MetadataVersion>| {
            version.is_some_and(|version| version >= floor)
        };
        if self
            .root
            .is_some_and(|floor| held(floor, Some(trusted.root)))
        {
            self.root = None;
        }
        if self
            .timestamp
            .as_ref()
            .is_some_and(|floor| held(floor.metadata.version, trusted.timestamp))
        {
            self.timestamp = None;
        }
        if self
            .snapshot
            .as_ref()
            .is_some_and(|floor| held(floor.metadata.version, trusted.snapshot))
        {
            self.snapshot = None;
        }
        if self
            .targets
            .as_ref()
            .is_some_and(|floor| held(floor.metadata.version, trusted.targets))
        {
            self.targets = None;
        }
        if self
            .revocation
            .is_some_and(|floor| held(floor, trusted.revocation))
        {
            self.revocation = None;
        }
    }

    /// Refuses `view` if it is below its role's floor, with the refusal the client gives
    /// for the same comparison; an online file while the client's `root` is below the root
    /// floor is refused as wanting its root.
    pub(super) fn check(&self, view: &View, root: MetadataVersion) -> Result<(), UpdateRefusal> {
        let online = matches!(
            view,
            View::Timestamp(_) | View::Snapshot(_) | View::Targets(_)
        );
        if online && self.root.is_some_and(|floor| root < floor) {
            return Err(UpdateRefusal::MissingPrerequisite { needed: Role::Root });
        }
        match view {
            View::Timestamp(new) => {
                let Some(floor) = &self.timestamp else {
                    return Ok(());
                };
                newer(Role::Timestamp, floor.metadata.version, new.version)?;
                below(
                    Role::Snapshot,
                    floor.metadata.snapshot.version,
                    new.snapshot.version,
                )
            }
            View::Snapshot(new) => {
                let Some(floor) = &self.snapshot else {
                    return Ok(());
                };
                below(Role::Snapshot, floor.metadata.version, new.version)?;
                below(
                    Role::Targets,
                    floor.metadata.targets.version,
                    new.targets.version,
                )
            }
            View::Targets(new) => match &self.targets {
                Some(floor) => below(Role::Targets, floor.metadata.version, new.version),
                None => Ok(()),
            },
            View::Revocation(new) => match self.revocation {
                Some(floor) => newer(Role::Revocation, floor, new.version),
                None => Ok(()),
            },
            View::Root(_) => Ok(()),
        }
    }

    /// The floors in force, by role.
    pub(super) fn versions(&self) -> BTreeMap<Role, MetadataVersion> {
        [
            (Role::Root, self.root),
            (
                Role::Timestamp,
                self.timestamp.as_ref().map(|floor| floor.metadata.version),
            ),
            (
                Role::Snapshot,
                self.snapshot.as_ref().map(|floor| floor.metadata.version),
            ),
            (
                Role::Targets,
                self.targets.as_ref().map(|floor| floor.metadata.version),
            ),
            (Role::Revocation, self.revocation),
        ]
        .into_iter()
        .filter_map(|(role, floor)| floor.map(|floor| (role, floor)))
        .collect()
    }
}

/// Refuses `offered` below `trusted`, as the client refuses a rollback.
fn below(
    role: Role,
    trusted: MetadataVersion,
    offered: MetadataVersion,
) -> Result<(), UpdateRefusal> {
    if offered < trusted {
        Err(UpdateRefusal::RolledBack {
            role,
            trusted,
            offered,
        })
    } else {
        Ok(())
    }
}

/// Refuses `offered` unless it is newer than `trusted`, as the client refuses a replay or
/// a rollback.
fn newer(
    role: Role,
    trusted: MetadataVersion,
    offered: MetadataVersion,
) -> Result<(), UpdateRefusal> {
    if offered == trusted {
        return Err(UpdateRefusal::Replayed {
            role,
            version: offered,
        });
    }
    below(role, trusted, offered)
}

/// One accepted file of the stream with its typed view.
pub(super) struct Stored {
    pub(super) sequence: EventSequence,
    pub(super) accepted: AcceptedMetadata,
    pub(super) view: View,
}

/// What the stream holds: its accepted files in order, every key a bootstrap pinned, the
/// markers owners left, and the torn tails past the synced mark opens recorded.
pub(super) struct StreamContents {
    pub(super) records: Vec<Stored>,
    pub(super) pinned: BTreeSet<KeyId>,
    pub(super) markers: Vec<(EventSequence, LogMarker)>,
    pub(super) torn_tails: Vec<TornTailPastMark>,
}

impl StreamContents {
    /// Whether the gap `missing` is a torn tail's burned sequence that lay past the synced
    /// mark: a record says so, and the log's truncation and torn-tail entries it names are
    /// in the stream.
    fn resumed(&self, missing: SequenceRange, reason: GapReason) -> bool {
        reason == GapReason::Truncated
            && self.torn_tails.iter().any(|torn| {
                torn.missing == missing
                    && self.markers.iter().any(|(_, marker)| {
                        matches!(marker, LogMarker::Truncated { missing: found } if *found == missing)
                    })
                    && self.markers.iter().any(|(sequence, marker)| {
                        *sequence == torn.marker && matches!(marker, LogMarker::TornTail { .. })
                    })
            })
    }
}

/// Reads the whole stream. Any sequence it lost refuses it, the first such gap once the
/// whole stream is read: the versions trusted there are unknown, so a replay without them
/// could roll back. The one exception is the sequence a torn tail past the synced mark
/// burned, which held nothing acknowledged ([`StreamContents::resumed`]).
pub(super) fn read_stream(
    log: &DurableLog<TrustRecord>,
) -> Result<StreamContents, RecoveryRefusal> {
    let mut contents = StreamContents {
        records: Vec::new(),
        pinned: BTreeSet::new(),
        markers: Vec::new(),
        torn_tails: Vec::new(),
    };
    let mut gaps = Vec::new();
    let mut cursor = log.start();
    loop {
        let batch = log
            .read(&cursor, REPLAY_BATCH_ITEMS)
            .map_err(RecoveryRefusal::Log)?;
        let finished = batch.caught_up || batch.items.is_empty();
        for item in batch.items {
            match item {
                ReadItem::Gap { missing, reason } => gaps.push((missing, reason)),
                ReadItem::Entry {
                    sequence,
                    entry: LogEntry::Marker(marker),
                    ..
                } => contents.markers.push((sequence, marker)),
                ReadItem::Entry {
                    sequence,
                    entry: LogEntry::Record(TrustRecord::Accepted(accepted)),
                    ..
                } => contents.records.push(typed(sequence, accepted)?),
                ReadItem::Entry {
                    entry: LogEntry::Record(TrustRecord::Pinned(pinned)),
                    ..
                } => contents.pinned.extend(pinned.keys),
                ReadItem::Entry {
                    entry: LogEntry::Record(TrustRecord::TornTailPastMark(torn)),
                    ..
                } => contents.torn_tails.push(torn),
            }
        }
        cursor = batch.cursor;
        if finished {
            return match gaps
                .into_iter()
                .find(|(missing, reason)| !contents.resumed(*missing, *reason))
            {
                Some((missing, reason)) => Err(RecoveryRefusal::Lost { missing, reason }),
                None => Ok(contents),
            };
        }
    }
}

/// The record with its view; its file must parse as its role at its version.
fn typed(sequence: EventSequence, accepted: AcceptedMetadata) -> Result<Stored, RecoveryRefusal> {
    let bad = |problem| RecoveryRefusal::BadRecord {
        sequence,
        role: accepted.role,
        problem,
    };
    let view = View::parse(accepted.role, &accepted.file)
        .map_err(|error| bad(RecordProblem::Payload { error }))?;
    if view.version() != accepted.version {
        return Err(bad(RecordProblem::Version {
            stored: accepted.version,
            file: view.version(),
        }));
    }
    Ok(Stored {
        sequence,
        accepted,
        view,
    })
}

/// The online records a replay loads, by position in the stream.
struct Plan {
    /// Each with the position of the record it was accepted under, if any.
    load: BTreeMap<usize, Option<usize>>,
    /// The newest record of each online role.
    newest: BTreeMap<Role, usize>,
    /// The newest stored root.
    newest_root: Option<MetadataVersion>,
}

impl Plan {
    /// The newest timestamp, snapshot and targets and the files each was accepted under:
    /// the client accepts a snapshot only as its trusted timestamp references it and
    /// targets only as its trusted snapshot does, and that is the latest one accepted
    /// before, since a rotation that drops them leaves none until the next.
    fn of(records: &[Stored]) -> Self {
        let last_before = |role: Role, end: usize| {
            records
                .get(..end)
                .unwrap_or_default()
                .iter()
                .rposition(|stored| stored.accepted.role == role)
        };
        let newest_of = |role: Role| last_before(role, records.len());
        let mut plan = Self {
            load: BTreeMap::new(),
            newest: BTreeMap::new(),
            newest_root: records
                .iter()
                .filter(|stored| stored.accepted.role == Role::Root)
                .map(|stored| stored.accepted.version)
                .max(),
        };
        let with_timestamp = |plan: &mut Self, snapshot: usize| {
            let timestamp = last_before(Role::Timestamp, snapshot);
            plan.load.insert(snapshot, timestamp);
            if let Some(timestamp) = timestamp {
                plan.load.insert(timestamp, None);
            }
        };
        if let Some(targets) = newest_of(Role::Targets) {
            plan.newest.insert(Role::Targets, targets);
            let snapshot = last_before(Role::Snapshot, targets);
            plan.load.insert(targets, snapshot);
            if let Some(snapshot) = snapshot {
                with_timestamp(&mut plan, snapshot);
            }
        }
        if let Some(snapshot) = newest_of(Role::Snapshot) {
            plan.newest.insert(Role::Snapshot, snapshot);
            with_timestamp(&mut plan, snapshot);
        }
        if let Some(timestamp) = newest_of(Role::Timestamp) {
            plan.newest.insert(Role::Timestamp, timestamp);
            plan.load.insert(timestamp, None);
        }
        plan
    }

    /// Leaves out the record at `position`; every record of its role if it is the newest,
    /// since the client must not hold a superseded one; and every record accepted under
    /// one left out. Returns whether anything was added.
    fn exclude(&self, records: &[Stored], excluded: &mut BTreeSet<usize>, position: usize) -> bool {
        let before = excluded.len();
        excluded.insert(position);
        let role = records.get(position).map(|stored| stored.accepted.role);
        if role.and_then(|role| self.newest.get(&role)) == Some(&position) {
            for planned in self.load.keys() {
                if records.get(*planned).map(|stored| stored.accepted.role) == role {
                    excluded.insert(*planned);
                }
            }
        }
        loop {
            let dependents: Vec<usize> = self
                .load
                .iter()
                .filter(|(planned, under)| {
                    !excluded.contains(planned)
                        && under.is_some_and(|under| excluded.contains(&under))
                })
                .map(|(planned, _)| *planned)
                .collect();
            if dependents.is_empty() {
                break;
            }
            excluded.extend(dependents);
        }
        excluded.len() > before
    }
}

/// The client rebuilt from the stream, the floors it left, and the releases that stay
/// revoked though no list the client verifies revokes them.
pub(super) struct Replayed {
    pub(super) client: UpdateClient,
    pub(super) floors: Floors,
    pub(super) kept_revoked: BTreeMap<ContentKey, String>,
}

enum Attempt {
    Done(Replayed),
    /// The online record at `position` was refused as expired, or while the chain was
    /// short of a root left out; `refusal` is what it ends the replay with if it cannot be
    /// left out.
    LeaveOut {
        position: usize,
        refusal: RecoveryRefusal,
    },
    /// The chain ended short of the newest stored root while online records were loaded.
    ChainShort,
}

/// Replays `records` into a client from `start`, at `now`, without the signatures of
/// `distrusted` keys, as the module documentation describes. The replay starts over each
/// time it leaves an online file out: at most once per planned file, plus once for a
/// short chain and once more.
pub(super) fn replay(
    records: &[Stored],
    start: &dyn Fn() -> Result<UpdateClient, RecoveryRefusal>,
    distrusted: &BTreeSet<KeyId>,
    now: UnixSeconds,
) -> Result<Replayed, RecoveryRefusal> {
    let plan = Plan::of(records);
    let mut excluded = BTreeSet::new();
    loop {
        match attempt(records, &plan, &excluded, start, distrusted, now)? {
            Attempt::Done(replayed) => return Ok(replayed),
            Attempt::LeaveOut { position, refusal } => {
                // A record already left out is never offered again, so this always adds
                // one; should it not, the refusal ends the replay instead of looping.
                if !plan.exclude(records, &mut excluded, position) {
                    return Err(refusal);
                }
            }
            // The next attempt leaves every online record out, so it meets this no more.
            Attempt::ChainShort => excluded.extend(plan.load.keys().copied()),
        }
    }
}

fn attempt(
    records: &[Stored],
    plan: &Plan,
    excluded: &BTreeSet<usize>,
    start: &dyn Fn() -> Result<UpdateClient, RecoveryRefusal>,
    distrusted: &BTreeSet<KeyId>,
    now: UnixSeconds,
) -> Result<Attempt, RecoveryRefusal> {
    let mut client = start()?;
    let mut floors = Floors::default();
    let mut kept_revoked = BTreeMap::new();
    // The newest stored root left out, and the online keys of the root each file was
    // accepted under, as the stream holds them.
    let mut left_out_root: Option<MetadataVersion> = None;
    let mut stream_online = online_roles(client.root());
    for (position, stored) in records.iter().enumerate() {
        let (file, stripped) = present(stored.accepted.role, &stored.accepted.file, distrusted);
        let short = left_out_root.is_some_and(|root| client.root().version < root);
        let tainted = stripped || short;
        let refused = |reason| RecoveryRefusal::Replay {
            sequence: stored.sequence,
            role: stored.accepted.role,
            version: stored.accepted.version,
            reason,
        };
        let no_longer_verifies = |reason: &UpdateRefusal| {
            tainted
                && matches!(
                    reason,
                    UpdateRefusal::Signatures { .. } | UpdateRefusal::VersionGap { .. }
                )
        };
        let planned = plan.load.contains_key(&position);
        let online = match &stored.view {
            View::Root(root) => {
                match client.update_root(&file, now) {
                    Ok(_) => floors.rotated(client.root()),
                    Err(reason) if no_longer_verifies(&reason) => {
                        left_out_root = left_out_root.max(Some(root.version));
                        floors.raise(&stored.view, &stream_online);
                    }
                    Err(reason) => return Err(refused(reason)),
                }
                stream_online = online_roles(root);
                None
            }
            View::Revocation(list) => {
                match client.update_revocation(&file) {
                    Ok(_) => {}
                    Err(reason) if no_longer_verifies(&reason) => {
                        floors.raise(&stored.view, &stream_online);
                        for (content_key, reason) in &list.revoked {
                            kept_revoked
                                .entry(*content_key)
                                .or_insert_with(|| reason.clone());
                        }
                    }
                    Err(reason) => return Err(refused(reason)),
                }
                None
            }
            View::Timestamp(_) | View::Snapshot(_) | View::Targets(_) if !planned => None,
            View::Timestamp(_) | View::Snapshot(_) | View::Targets(_)
                if excluded.contains(&position) =>
            {
                floors.raise(&stored.view, &stream_online);
                None
            }
            View::Timestamp(_) => Some(client.update_timestamp(&file, now)),
            View::Snapshot(_) => Some(client.update_snapshot(&file, now)),
            View::Targets(_) => Some(client.update_targets(&file, now)),
        };
        match online {
            Some(Err(reason))
                if matches!(reason, UpdateRefusal::Expired { .. })
                    || no_longer_verifies(&reason) =>
            {
                return Ok(Attempt::LeaveOut {
                    position,
                    refusal: refused(reason),
                })
            }
            Some(Err(reason)) => return Err(refused(reason)),
            Some(Ok(())) | None => {}
        }
    }
    let short = plan
        .newest_root
        .is_some_and(|newest| client.root().version < newest);
    if short && plan.load.keys().any(|planned| !excluded.contains(planned)) {
        return Ok(Attempt::ChainShort);
    }
    floors.settle(&client.trusted_versions());
    kept_revoked.retain(|content_key, _| !client.revoked().contains_key(content_key));
    Ok(Attempt::Done(Replayed {
        client,
        floors,
        kept_revoked,
    }))
}
