//! The persisted update client, revocation reaching running launches, and reloaded trust
//! roots reaching a running client (VM-W45, plan line 2668; VM-P23, line 2798; VM-P48,
//! line 2823; M18B in docs/combined-plan-leftover-tasks.md, lines 214–218): metadata
//! signed in the test with the fixture's Ed25519 keys, as `tests` and `tests_roots` sign
//! it, kept on a durable stream in a temporary directory, replayed on restart and on
//! reload, with time from a manual clock. The helpers are shared with `tests_launch_set`.
//! Torn tails are made by editing segment files, since the log's own fault injection is
//! private to `foundation::events`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde_json::json;

use super::tests::{config as update_config, trust_roots, Fixture, Signer, DAY, NOW};
use super::*;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::events::{
    DurableLog, DurableStreamId, EventSequence, GapReason, LogConfig, LogDamage, LogError,
    LogMarker, OwnerError, ProducerId, SequenceRange, TornTailFound,
};
use crate::foundation::ids::{ContentKey, ExecutionId, ManualClock, MonotonicTime};
use crate::foundation::signing::SharedTrustRoots;
use crate::sandbox::trust::{
    CalendarAnchor, MetadataFile, MetadataVersion, OpenedArtifact, ReleaseVersion, ResolvedProfile,
    RevocationMetadata, Role, RoleKeys, RootMetadata, SignatureFailure, SnapshotMetadata,
    TargetEntry, TargetName, TargetsMetadata, TimestampMetadata, TrustClock, UnixSeconds,
    UpdateRefusal,
};

pub(super) const KERNEL: &[u8] = b"vmlinuz-6.6.52-yougori";
pub(super) const IMAGE: &[u8] = b"rootfs-2026.10.1-yougori";
pub(super) const OTHER: &[u8] = b"vmlinuz-6.1.0-retired";
/// Online metadata expires before the pinned root (seven days).
const SIX_DAYS: u64 = 6 * DAY;

/// The online keys a root lists.
pub(super) struct Online {
    timestamp: Signer,
    snapshot: Signer,
    targets: Signer,
    revocation: Signer,
}

impl Online {
    /// The keys `Fixture::root_file` lists.
    fn fixture() -> Self {
        Self::from_seeds([40, 50, 60, 70])
    }

    /// Other keys, for a rotation that replaces the online and revocation roles.
    pub(super) fn rotated() -> Self {
        Self::from_seeds([41, 51, 61, 71])
    }

    fn from_seeds([timestamp, snapshot, targets, revocation]: [u8; 4]) -> Self {
        Self {
            timestamp: Signer::from_seed(timestamp),
            snapshot: Signer::from_seed(snapshot),
            targets: Signer::from_seed(targets),
            revocation: Signer::from_seed(revocation),
        }
    }
}

#[derive(Clone, Copy)]
struct Expiries {
    timestamp: UnixSeconds,
    snapshot: UnixSeconds,
    targets: UnixSeconds,
}

impl Expiries {
    fn all(at: UnixSeconds) -> Self {
        Self {
            timestamp: at,
            snapshot: at,
            targets: at,
        }
    }
}

fn long() -> Expiries {
    Expiries::all(NOW.plus_seconds(SIX_DAYS))
}

/// One release: timestamp, snapshot and targets at one version.
pub(super) struct Chain {
    pub(super) timestamp: MetadataFile,
    pub(super) snapshot: MetadataFile,
    pub(super) targets: MetadataFile,
}

fn v(version: u64) -> MetadataVersion {
    MetadataVersion::new(version)
}

fn signed<T: serde::Serialize>(payload: &T, signer: &Signer, role: Role) -> MetadataFile {
    let mut file = MetadataFile::unsigned(payload).unwrap();
    signer.sign(&mut file, role);
    file
}

pub(super) fn targets_file(
    online: &Online,
    version: u64,
    expires: UnixSeconds,
    artifacts: &[(&str, &[u8])],
) -> MetadataFile {
    let targets = artifacts
        .iter()
        .map(|(name, bytes)| {
            (
                TargetName::new(*name).unwrap(),
                TargetEntry {
                    class: ArtifactClass::GuestImage,
                    length_bytes: u64::try_from(bytes.len()).unwrap(),
                    content_key: ContentKey::of(bytes),
                    release: ReleaseVersion::new(format!("2026.10.{version}")).unwrap(),
                },
            )
        })
        .collect();
    let metadata = TargetsMetadata {
        role: Role::Targets,
        version: v(version),
        expires,
        targets,
    };
    signed(&metadata, &online.targets, Role::Targets)
}

pub(super) fn snapshot_file(
    online: &Online,
    version: u64,
    expires: UnixSeconds,
    targets: &MetadataFile,
    targets_version: u64,
) -> MetadataFile {
    let metadata = SnapshotMetadata {
        role: Role::Snapshot,
        version: v(version),
        expires,
        targets: targets.file_reference(v(targets_version)).unwrap(),
    };
    signed(&metadata, &online.snapshot, Role::Snapshot)
}

pub(super) fn timestamp_file(
    online: &Online,
    version: u64,
    expires: UnixSeconds,
    snapshot: &MetadataFile,
    snapshot_version: u64,
) -> MetadataFile {
    let metadata = TimestampMetadata {
        role: Role::Timestamp,
        version: v(version),
        expires,
        snapshot: snapshot.file_reference(v(snapshot_version)).unwrap(),
    };
    signed(&metadata, &online.timestamp, Role::Timestamp)
}

fn chain(online: &Online, version: u64, expiries: Expiries) -> Chain {
    let targets = targets_file(
        online,
        version,
        expiries.targets,
        &[("guest-kernel", KERNEL), ("guest-image", IMAGE)],
    );
    let snapshot = snapshot_file(online, version, expiries.snapshot, &targets, version);
    let timestamp = timestamp_file(online, version, expiries.timestamp, &snapshot, version);
    Chain {
        timestamp,
        snapshot,
        targets,
    }
}

pub(super) fn revocation_file(
    online: &Online,
    version: u64,
    revoked: &[(&[u8], &str)],
) -> MetadataFile {
    let metadata = RevocationMetadata {
        role: Role::Revocation,
        version: v(version),
        issued: NOW,
        revoked: revoked
            .iter()
            .map(|(bytes, reason)| (ContentKey::of(bytes), (*reason).to_owned()))
            .collect(),
    };
    signed(&metadata, &online.revocation, Role::Revocation)
}

/// The root at `version` with the fixture's root keys (threshold 2) and `online`, signed
/// by all three root keys, so it is a valid rotation from any of these roots.
fn root_file(fixture: &Fixture, online: &Online, version: u64) -> MetadataFile {
    root_signed_by(fixture, online, version, &[0, 1, 2])
}

/// As [`root_file`], signed by the root keys at `signers` (indices).
pub(super) fn root_signed_by(
    fixture: &Fixture,
    online: &Online,
    version: u64,
    signers: &[usize],
) -> MetadataFile {
    let mut keys = BTreeMap::new();
    for signer in fixture.roots.iter().chain([
        &online.timestamp,
        &online.snapshot,
        &online.targets,
        &online.revocation,
    ]) {
        keys.insert(signer.key_id(), signer.key.clone());
    }
    let one = |signer: &Signer| RoleKeys::new([signer.key_id()], 1);
    let metadata = RootMetadata {
        role: Role::Root,
        version: v(version),
        expires: NOW.plus_seconds(30 * DAY),
        keys,
        roles: BTreeMap::from([
            (
                Role::Root,
                RoleKeys::new(fixture.roots.iter().map(Signer::key_id), 2),
            ),
            (Role::Timestamp, one(&online.timestamp)),
            (Role::Snapshot, one(&online.snapshot)),
            (Role::Targets, one(&online.targets)),
            (Role::Revocation, one(&online.revocation)),
        ]),
    };
    let mut file = MetadataFile::unsigned(&metadata).unwrap();
    for index in signers {
        fixture.roots[*index].sign(&mut file, Role::Root);
    }
    file
}

pub(super) fn kernel() -> TargetName {
    TargetName::new("guest-kernel").unwrap()
}

pub(super) fn image() -> TargetName {
    TargetName::new("guest-image").unwrap()
}

pub(super) fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

fn config() -> LogConfig {
    LogConfig {
        max_entries: 1_000,
        max_bytes: 1 << 22,
        segment_entries: 4,
        segment_bytes: 1 << 16,
    }
}

/// The fixture's roots as update roots with threshold 2 under production, over a
/// trust-root file the test can reload, a stream directory and a manual clock at `NOW`.
pub(super) struct Env {
    pub(super) fixture: Fixture,
    pub(super) online: Online,
    shared: SharedTrustRoots,
    pinned: PinnedRoots,
    clock: Arc<ManualClock>,
    trust_clock: TrustClock,
    directory: tempfile::TempDir,
    config: LogConfig,
}

impl Env {
    pub(super) fn new() -> Self {
        Self::with_config(config())
    }

    fn with_config(config: LogConfig) -> Self {
        let start = MonotonicTime::from_nanos(1_000);
        let clock = Arc::new(ManualClock::new(start));
        let trust_clock = TrustClock::new(
            clock.clone(),
            CalendarAnchor {
                monotonic: start,
                unix_seconds: NOW,
            },
        )
        .unwrap();
        let fixture = Fixture::new();
        let shared = SharedTrustRoots::new(trust_roots(&fixture.root_entries()));
        let pinned = PinnedRoots::new(
            shared.clone(),
            update_config(2),
            ResolvedProfile::PRODUCTION,
        );
        Self {
            fixture,
            online: Online::fixture(),
            shared,
            pinned,
            clock,
            trust_clock,
            directory: tempfile::tempdir().unwrap(),
            config,
        }
    }

    fn stream(&self) -> TrustStream {
        TrustStream {
            directory: self.directory.path().to_path_buf(),
            stream: DurableStreamId::new("sandbox.update-trust").unwrap(),
            owner: ProducerId::new("engine.update-trust").unwrap(),
            config: self.config,
        }
    }

    fn try_open(&self) -> Result<(PersistedUpdateClient, RecoveredTrust), RecoveryRefusal> {
        PersistedUpdateClient::open(
            &self.stream(),
            &self.pinned,
            &production_registry,
            &self.fixture.root_file(1),
            self.trust_clock.clone(),
        )
    }

    pub(super) fn open(&self) -> PersistedUpdateClient {
        self.try_open().unwrap().0
    }

    pub(super) fn reload(
        &self,
        client: &mut PersistedUpdateClient,
    ) -> Result<ReloadReport, RecoveryRefusal> {
        client.reload(
            &self.pinned,
            &production_registry,
            &self.fixture.root_file(1),
        )
    }

    /// Reloads the trust-root file with the fixture's root keys at `revoked` revoked.
    pub(super) fn revoke_root_keys(&self, revoked: &[usize]) {
        let mut entries = self.fixture.root_entries();
        for index in revoked {
            entries[*index].revoked = true;
        }
        self.shared.replace(trust_roots(&entries));
    }

    fn chain(&self, version: u64, expiries: Expiries) -> Chain {
        chain(&self.online, version, expiries)
    }

    fn advance(&self, seconds: u64) {
        self.clock.advance(Duration::from_secs(seconds));
    }

    /// The stream's segment files, in sequence order.
    fn segments(&self) -> Vec<PathBuf> {
        let mut segments: Vec<PathBuf> = fs::read_dir(self.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("segment-")
            })
            .collect();
        segments.sort();
        segments
    }
}

pub(super) fn load(client: &mut PersistedUpdateClient, chain: &Chain) {
    client.update_timestamp(&chain.timestamp).unwrap();
    client.update_snapshot(&chain.snapshot).unwrap();
    client.update_targets(&chain.targets).unwrap();
}

/// Root, timestamp, snapshot, targets and revocation versions the client trusts.
type Versions = (u64, Option<u64>, Option<u64>, Option<u64>, Option<u64>);

fn versions(client: &PersistedUpdateClient) -> Versions {
    let trusted = client.client().trusted_versions();
    let get = |version: Option<MetadataVersion>| version.map(MetadataVersion::get);
    (
        trusted.root.get(),
        get(trusted.timestamp),
        get(trusted.snapshot),
        get(trusted.targets),
        get(trusted.revocation),
    )
}

fn revoked(client: &PersistedUpdateClient) -> BTreeMap<ContentKey, String> {
    client.revoked()
}

fn last(client: &PersistedUpdateClient) -> Option<u64> {
    client.log().last().map(EventSequence::get)
}

fn opened(client: &PersistedUpdateClient, name: &TargetName, bytes: &[u8]) -> OpenedArtifact {
    client
        .verify_target(name, ArtifactClass::GuestImage)
        .unwrap()
        .open(bytes.to_vec())
        .unwrap()
}

fn sequence(value: u64) -> EventSequence {
    EventSequence::new(value).unwrap()
}

#[test]
fn persisted_metadata_restarts_to_the_same_trusted_versions_and_revocations() {
    let env = Env::new();
    let (mut client, recovered) = env.try_open().unwrap();
    assert!(recovered.report.created);
    assert_eq!(recovered.records, 0);
    assert_eq!(versions(&client), (1, None, None, None, None));
    load(&mut client, &env.chain(1, long()));
    // The second list omits the first one's release, which stays revoked.
    client
        .update_revocation(&revocation_file(
            &env.online,
            1,
            &[(OTHER, "CVE-2026-0001")],
        ))
        .unwrap();
    client
        .update_revocation(&revocation_file(
            &env.online,
            2,
            &[(b"vmlinuz-5.4.0", "CVE-2026-0002")],
        ))
        .unwrap();
    // An update cycle interrupted after its timestamp, which references a snapshot not
    // fetched yet: the client serves nothing until it is.
    let second = env.chain(2, long());
    client.update_timestamp(&second.timestamp).unwrap();
    let before = (versions(&client), revoked(&client));
    assert_eq!(before.0, (1, Some(2), Some(1), Some(1), Some(2)));
    assert_eq!(before.1.len(), 2);
    let missing_snapshot = Err(TrustRefusal::Refused {
        reason: UpdateRefusal::MissingPrerequisite {
            needed: Role::Snapshot,
        },
    });
    assert_eq!(
        client
            .verify_target(&kernel(), ArtifactClass::GuestImage)
            .map(|_| ()),
        missing_snapshot
    );
    // The first open recorded the pinned keys first.
    assert_eq!(last(&client), Some(7));
    client.close().unwrap();

    let (mut client, recovered) = env.try_open().unwrap();
    assert!(!recovered.report.created);
    assert_eq!(recovered.records, 6);
    assert!(recovered.markers.is_empty());
    assert!(recovered.floors.is_empty());
    assert_eq!((versions(&client), revoked(&client)), before);
    assert_eq!(
        client
            .verify_target(&kernel(), ArtifactClass::GuestImage)
            .map(|_| ()),
        missing_snapshot
    );
    // The cycle completes after the restart, against the restored timestamp.
    client.update_snapshot(&second.snapshot).unwrap();
    client.update_targets(&second.targets).unwrap();
    let verified = client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();
    assert_eq!(verified.content_key(), ContentKey::of(KERNEL));
    // Dropping releases the stream as closing does.
    drop(client);

    let client = env.open();
    assert_eq!(versions(&client), (1, Some(2), Some(2), Some(2), Some(2)));
    assert_eq!(revoked(&client), before.1);
}

#[test]
fn a_rollback_is_refused_after_a_restart() {
    let env = Env::new();
    let mut client = env.open();
    let first = env.chain(1, long());
    load(&mut client, &first);
    load(&mut client, &env.chain(2, long()));
    let first_list = revocation_file(&env.online, 1, &[(OTHER, "CVE-2026-0001")]);
    client
        .update_revocation(&revocation_file(
            &env.online,
            2,
            &[(OTHER, "CVE-2026-0001")],
        ))
        .unwrap();
    client.close().unwrap();

    let mut client = env.open();
    let kept = last(&client);
    assert_eq!(
        client.update_timestamp(&first.timestamp),
        Err(PersistedUpdateError::Refused {
            reason: UpdateRefusal::RolledBack {
                role: Role::Timestamp,
                trusted: v(2),
                offered: v(1),
            }
        })
    );
    assert_eq!(
        client.update_revocation(&first_list),
        Err(PersistedUpdateError::Refused {
            reason: UpdateRefusal::RolledBack {
                role: Role::Revocation,
                trusted: v(2),
                offered: v(1),
            }
        })
    );
    assert_eq!(
        client.update_root(&env.fixture.root_file(1)),
        Err(PersistedUpdateError::Refused {
            reason: UpdateRefusal::Replayed {
                role: Role::Root,
                version: v(1),
            }
        })
    );
    // Nothing refused was kept, and the trusted versions are those before.
    assert_eq!(last(&client), kept);
    assert_eq!(versions(&client), (1, Some(2), Some(2), Some(2), Some(2)));
}

#[test]
fn truncation_is_detected_and_fails_closed() {
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    load(&mut client, &env.chain(2, long()));
    // The pinned keys, then six metadata files.
    assert_eq!(last(&client), Some(7));
    client.close().unwrap();

    // The last record cut off the end of the stream, at a line boundary: the segments
    // alone read as a shorter, older stream, and the high-water mark exposes the loss.
    let tail = env.segments().pop().unwrap();
    let bytes = fs::read(&tail).unwrap();
    let cut = bytes[..bytes.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |at| at + 1);
    fs::OpenOptions::new()
        .write(true)
        .open(&tail)
        .unwrap()
        .set_len(u64::try_from(cut).unwrap())
        .unwrap();
    let lost = Some(RecoveryRefusal::Lost {
        missing: SequenceRange::single(sequence(7)),
        reason: GapReason::Truncated,
    });
    assert_eq!(env.try_open().err(), lost);
    // The stream records the loss, so every later open refuses too.
    assert_eq!(env.try_open().err(), lost);

    // Every segment removed, and the high-water mark removed with them.
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    client.close().unwrap();
    for segment in env.segments() {
        fs::remove_file(segment).unwrap();
    }
    assert_eq!(
        env.try_open().err(),
        Some(RecoveryRefusal::Lost {
            missing: SequenceRange::new(sequence(1), sequence(4)).unwrap(),
            reason: GapReason::Truncated,
        })
    );
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    client.close().unwrap();
    fs::remove_file(env.directory.path().join("high-water.bin")).unwrap();
    assert_eq!(
        env.try_open().err(),
        Some(RecoveryRefusal::Log(LogError::Damaged(
            LogDamage::HighWaterMissing
        )))
    );
}

#[test]
fn an_expired_stored_timestamp_is_a_floor() {
    let env = Env::new();
    let mut client = env.open();
    let first = env.chain(1, long());
    let second = env.chain(
        2,
        Expiries {
            timestamp: NOW.plus_seconds(DAY),
            ..long()
        },
    );
    load(&mut client, &first);
    load(&mut client, &second);
    client.close().unwrap();

    // Two days later the stored timestamp has expired. The snapshot and targets were
    // accepted under it, so none of the three is loaded; each keeps its version.
    env.advance(2 * DAY);
    let (mut client, recovered) = env.try_open().unwrap();
    let floors = BTreeMap::from([
        (Role::Timestamp, v(2)),
        (Role::Snapshot, v(2)),
        (Role::Targets, v(2)),
    ]);
    assert_eq!(recovered.floors, floors);
    assert_eq!(client.floors(), floors);
    assert_eq!(versions(&client), (1, None, None, None, None));

    // A client without the floor takes the older release's timestamp: a rollback.
    let now = env.trust_clock.now();
    let mut bare = env
        .fixture
        .pinned()
        .bootstrap(production_registry(), &env.fixture.root_file(1), now)
        .unwrap();
    assert_eq!(bare.update_timestamp(&first.timestamp, now), Ok(()));
    // The floor refuses it before the client sees it: lower, equal, or naming an older
    // snapshot than the floor's.
    assert_eq!(
        client.update_timestamp(&first.timestamp),
        Err(PersistedUpdateError::BelowFloor {
            reason: UpdateRefusal::RolledBack {
                role: Role::Timestamp,
                trusted: v(2),
                offered: v(1),
            }
        })
    );
    let other_second = timestamp_file(
        &env.online,
        2,
        NOW.plus_seconds(SIX_DAYS),
        &second.snapshot,
        2,
    );
    assert_eq!(
        client.update_timestamp(&other_second),
        Err(PersistedUpdateError::BelowFloor {
            reason: UpdateRefusal::Replayed {
                role: Role::Timestamp,
                version: v(2),
            }
        })
    );
    let older_snapshot = timestamp_file(
        &env.online,
        3,
        NOW.plus_seconds(SIX_DAYS),
        &first.snapshot,
        1,
    );
    assert_eq!(
        client.update_timestamp(&older_snapshot),
        Err(PersistedUpdateError::BelowFloor {
            reason: UpdateRefusal::RolledBack {
                role: Role::Snapshot,
                trusted: v(2),
                offered: v(1),
            }
        })
    );
    assert_eq!(last(&client), Some(7));

    // A newer timestamp for the stored release passes; the stored snapshot and targets
    // are offered again, and an older snapshot is still refused by its floor.
    let third = timestamp_file(
        &env.online,
        3,
        NOW.plus_seconds(SIX_DAYS),
        &second.snapshot,
        2,
    );
    client.update_timestamp(&third).unwrap();
    assert_eq!(
        client.floors(),
        BTreeMap::from([(Role::Snapshot, v(2)), (Role::Targets, v(2))])
    );
    assert_eq!(
        client.update_snapshot(&first.snapshot),
        Err(PersistedUpdateError::BelowFloor {
            reason: UpdateRefusal::RolledBack {
                role: Role::Snapshot,
                trusted: v(2),
                offered: v(1),
            }
        })
    );
    client.update_snapshot(&second.snapshot).unwrap();
    client.update_targets(&second.targets).unwrap();
    assert!(client.floors().is_empty());
    client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();
    client.close().unwrap();

    let client = env.open();
    assert_eq!(versions(&client), (1, Some(3), Some(2), Some(2), None));
    assert!(client.floors().is_empty());
}

#[test]
fn an_expired_stored_targets_file_is_a_floor_beside_the_rest() {
    let env = Env::new();
    let mut client = env.open();
    let first = env.chain(
        1,
        Expiries {
            targets: NOW.plus_seconds(DAY),
            ..long()
        },
    );
    load(&mut client, &first);
    client.close().unwrap();

    env.advance(2 * DAY);
    let (mut client, recovered) = env.try_open().unwrap();
    assert_eq!(recovered.floors, BTreeMap::from([(Role::Targets, v(1))]));
    assert_eq!(versions(&client), (1, Some(1), Some(1), None, None));
    // The stored targets pass the floor and reach the client, which refuses them as
    // expired, as it refused them on replay.
    assert!(matches!(
        client.update_targets(&first.targets),
        Err(PersistedUpdateError::Refused {
            reason: UpdateRefusal::Expired {
                role: Role::Targets,
                ..
            }
        })
    ));
    load(&mut client, &env.chain(2, long()));
    assert!(client.floors().is_empty());
    client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();
}

#[test]
fn an_expired_file_takes_what_was_accepted_under_it_and_leaves_nothing_superseded() {
    // The timestamp the stored targets were accepted under expired, the newer one not.
    let env = Env::new();
    let mut client = env.open();
    load(
        &mut client,
        &env.chain(
            1,
            Expiries {
                timestamp: NOW.plus_seconds(DAY),
                ..long()
            },
        ),
    );
    let second = env.chain(2, long());
    client.update_timestamp(&second.timestamp).unwrap();
    client.update_snapshot(&second.snapshot).unwrap();
    client.close().unwrap();
    env.advance(2 * DAY);
    let (mut client, recovered) = env.try_open().unwrap();
    assert_eq!(versions(&client), (1, Some(2), Some(2), None, None));
    assert_eq!(recovered.floors, BTreeMap::from([(Role::Targets, v(1))]));
    client.update_targets(&second.targets).unwrap();
    assert!(client.floors().is_empty());
    client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();

    // The newest snapshot expired: the snapshot before it is not loaded in its place, and
    // neither are the targets accepted under that one.
    let env = Env::new();
    let mut client = env.open();
    let first = env.chain(1, long());
    load(&mut client, &first);
    let second = env.chain(
        2,
        Expiries {
            snapshot: NOW.plus_seconds(DAY),
            ..long()
        },
    );
    client.update_timestamp(&second.timestamp).unwrap();
    client.update_snapshot(&second.snapshot).unwrap();
    client.close().unwrap();
    env.advance(2 * DAY);
    let (mut client, recovered) = env.try_open().unwrap();
    assert_eq!(versions(&client), (1, Some(2), None, None, None));
    assert_eq!(
        recovered.floors,
        BTreeMap::from([(Role::Snapshot, v(2)), (Role::Targets, v(1))])
    );
    assert_eq!(
        client.update_snapshot(&first.snapshot),
        Err(PersistedUpdateError::BelowFloor {
            reason: UpdateRefusal::RolledBack {
                role: Role::Snapshot,
                trusted: v(2),
                offered: v(1),
            }
        })
    );
    load(&mut client, &env.chain(3, long()));
    assert!(client.floors().is_empty());
    assert_eq!(versions(&client), (1, Some(3), Some(3), Some(3), None));
}

#[test]
fn a_tampered_record_fails_closed() {
    // A byte changed on disk: the line no longer verifies, and it is not the last line.
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    client.close().unwrap();
    let segment = env.segments().remove(0);
    let mut bytes = fs::read(&segment).unwrap();
    bytes[80] ^= 0x01;
    fs::write(&segment, bytes).unwrap();
    assert!(matches!(
        env.try_open().err(),
        Some(RecoveryRefusal::Log(LogError::Damaged(LogDamage::Line {
            line: 1,
            ..
        })))
    ));

    // A record the stream verifies whose file was altered after signing: the client
    // refuses it on replay.
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    client.close().unwrap();
    let genuine = env.chain(2, long()).timestamp;
    let mut payload = genuine.signed().clone();
    payload["expires"] = json!(9_999_999_999u64);
    let altered = MetadataFile::new(payload, genuine.signatures().to_vec());
    let stream = env.stream();
    let (mut raw, _) = DurableLog::<TrustRecord>::open(
        &stream.directory,
        stream.stream.clone(),
        stream.owner.clone(),
        stream.config,
    )
    .unwrap();
    raw.append(TrustRecord::Accepted(AcceptedMetadata {
        role: Role::Timestamp,
        version: v(2),
        accepted_at: NOW,
        file: altered,
    }))
    .unwrap();
    raw.close().unwrap();
    match env.try_open().err() {
        Some(RecoveryRefusal::Replay {
            sequence: at,
            role: Role::Timestamp,
            version,
            reason: UpdateRefusal::Signatures { .. },
        }) => assert_eq!((at, version), (sequence(5), v(2))),
        other => panic!("expected a replay refusal, got {other:?}"),
    }

    // A record whose version is not its file's.
    let env = Env::new();
    env.open().close().unwrap();
    let stream = env.stream();
    let (mut raw, _) = DurableLog::<TrustRecord>::open(
        &stream.directory,
        stream.stream.clone(),
        stream.owner.clone(),
        stream.config,
    )
    .unwrap();
    raw.append(TrustRecord::Accepted(AcceptedMetadata {
        role: Role::Timestamp,
        version: v(3),
        accepted_at: NOW,
        file: env.chain(2, long()).timestamp,
    }))
    .unwrap();
    raw.close().unwrap();
    assert_eq!(
        env.try_open().err(),
        Some(RecoveryRefusal::BadRecord {
            sequence: sequence(2),
            role: Role::Timestamp,
            problem: RecordProblem::Version {
                stored: v(3),
                file: v(2),
            },
        })
    );
}

#[test]
fn a_failed_append_stops_further_updates_until_reopened() {
    // One entry per segment, so each record starts a segment file.
    let env = Env::with_config(LogConfig {
        segment_entries: 1,
        ..config()
    });
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    let kernel_artifact = opened(&client, &kernel(), KERNEL);
    client
        .admit_launch(execution("exe-1"), &kernel_artifact)
        .unwrap();
    // Something else holds the name of the next record's segment, so the append fails.
    let next = client.log().last().unwrap().get() + 1;
    let blocker = env
        .directory
        .path()
        .join(format!("segment-{next:020}.jsonl"));
    fs::create_dir(&blocker).unwrap();
    let list = revocation_file(&env.online, 1, &[(KERNEL, "CVE-2026-0001")]);
    match client.update_revocation(&list) {
        Err(PersistedUpdateError::NotPersisted {
            error: LogError::Io { .. },
            applied,
        }) => {
            // In force in this process, and the running launch is still reported.
            assert_eq!(
                applied.running.keys().collect::<Vec<_>>(),
                [&execution("exe-1")]
            );
        }
        other => panic!("expected an update not kept, got {other:?}"),
    }
    assert!(client
        .client()
        .revoked()
        .contains_key(&ContentKey::of(KERNEL)));
    assert!(matches!(client.halt(), Some(Halt::NotKept { .. })));
    // No further update is taken, so the stream never holds a file after a hole.
    let second = env.chain(2, long());
    assert!(matches!(
        client.update_timestamp(&second.timestamp),
        Err(PersistedUpdateError::Halted {
            halt: Halt::NotKept { .. }
        })
    ));
    assert_eq!(versions(&client), (1, Some(1), Some(1), Some(1), Some(1)));
    assert_eq!(last(&client), Some(4));
    client.close().unwrap();
    fs::remove_dir(&blocker).unwrap();

    // Opened again from the stream, which does not hold the list: it is offered again.
    let mut client = env.open();
    assert_eq!(client.halt(), None);
    assert!(client.revoked().is_empty());
    assert_eq!(versions(&client), (1, Some(1), Some(1), Some(1), None));
    client.update_revocation(&list).unwrap();
    load(&mut client, &second);
    client.close().unwrap();
    let client = env.open();
    assert_eq!(versions(&client), (1, Some(2), Some(2), Some(2), Some(1)));
    assert!(client
        .client()
        .revoked()
        .contains_key(&ContentKey::of(KERNEL)));
}

#[test]
fn root_rotation_is_replayed() {
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    client
        .update_revocation(&revocation_file(
            &env.online,
            1,
            &[(OTHER, "CVE-2026-0001")],
        ))
        .unwrap();
    // A rotation that keeps the online keys keeps the online metadata.
    let rotation = client
        .update_root(&root_file(&env.fixture, &env.online, 2))
        .unwrap();
    assert!(rotation.cleared.is_empty());
    client.close().unwrap();

    let mut client = env.open();
    assert_eq!(versions(&client), (2, Some(1), Some(1), Some(1), Some(1)));
    client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();
    // One that replaces the online and revocation keys drops the online metadata.
    let rotated = Online::rotated();
    let rotation = client
        .update_root(&root_file(&env.fixture, &rotated, 3))
        .unwrap();
    assert_eq!(
        rotation.cleared,
        BTreeSet::from([Role::Timestamp, Role::Snapshot, Role::Targets])
    );
    // A list signed with the new revocation key adds to the first; under the new online
    // keys the versions start over.
    client
        .update_revocation(&revocation_file(&rotated, 2, &[(IMAGE, "CVE-2026-0002")]))
        .unwrap();
    load(&mut client, &chain(&rotated, 1, long()));
    let before = (versions(&client), revoked(&client));
    assert_eq!(before.0, (3, Some(1), Some(1), Some(1), Some(2)));
    client.close().unwrap();

    // The replay rotates through both roots again; the first list, signed with the key
    // root 3 replaced, still verifies at its place before the rotation.
    let (client, recovered) = env.try_open().unwrap();
    assert_eq!(recovered.records, 10);
    assert_eq!((versions(&client), revoked(&client)), before);
    assert_eq!(
        revoked(&client).keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([ContentKey::of(OTHER), ContentKey::of(IMAGE)])
    );
    assert!(client.floors().is_empty());
    client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();
}

#[test]
fn a_revocation_names_exactly_the_running_launches_it_revokes() {
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    let kernel_artifact = opened(&client, &kernel(), KERNEL);
    let image_artifact = opened(&client, &image(), IMAGE);
    let first = client
        .admit_launch(execution("exe-1"), &kernel_artifact)
        .unwrap();
    let second = client
        .admit_launch(execution("exe-2"), &image_artifact)
        .unwrap();
    client
        .admit_launch(execution("exe-3"), &kernel_artifact)
        .unwrap();
    assert_eq!(
        client.admit_launch(execution("exe-1"), &image_artifact),
        Err(TrustRefusal::AlreadyRunning {
            execution: execution("exe-1")
        })
    );
    assert_eq!(client.running().len(), 3);
    // The third launch ends before the revocation.
    assert!(client.end_launch(&execution("exe-3")).is_some());

    let report = client
        .update_revocation(&revocation_file(
            &env.online,
            1,
            &[(KERNEL, "CVE-2026-0001"), (OTHER, "CVE-2026-0003")],
        ))
        .unwrap();
    assert_eq!(
        report.applied.newly_revoked,
        BTreeSet::from([ContentKey::of(KERNEL), ContentKey::of(OTHER)])
    );
    assert_eq!(
        report.running,
        BTreeMap::from([(
            execution("exe-1"),
            RevokedLaunch {
                admission: first.clone(),
                reason: "CVE-2026-0001".to_owned(),
            }
        )])
    );
    // The report stops nothing; the lifecycle ends the launch. No new launch of the
    // revoked release is admitted.
    assert_eq!(client.running().len(), 2);
    assert_eq!(
        client.admit_launch(execution("exe-4"), &kernel_artifact),
        Err(TrustRefusal::Refused {
            reason: UpdateRefusal::RevokedRelease {
                content_key: ContentKey::of(KERNEL),
                reason: "CVE-2026-0001".to_owned(),
            }
        })
    );
    assert!(client.running().get(&execution("exe-4")).is_none());

    // A later list naming the kernel again reaches only what it newly revokes.
    let report = client
        .update_revocation(&revocation_file(
            &env.online,
            2,
            &[(KERNEL, "CVE-2026-0001"), (IMAGE, "CVE-2026-0002")],
        ))
        .unwrap();
    assert_eq!(
        report.applied.newly_revoked,
        BTreeSet::from([ContentKey::of(IMAGE)])
    );
    assert_eq!(
        report.running,
        BTreeMap::from([(
            execution("exe-2"),
            RevokedLaunch {
                admission: second.clone(),
                reason: "CVE-2026-0002".to_owned(),
            }
        )])
    );
    assert_eq!(client.end_launch(&execution("exe-1")), Some(first));
    assert_eq!(client.end_launch(&execution("exe-2")), Some(second));
    assert!(client.running().is_empty());
    let report = client
        .update_revocation(&revocation_file(
            &env.online,
            3,
            &[(b"vmlinuz-5.4.0", "CVE-2026-0004")],
        ))
        .unwrap();
    assert!(report.running.is_empty());
}

#[test]
fn a_full_stream_refuses_before_the_client_sees_the_update() {
    // Nine entries, four kept free for the markers of later opens: the pinned keys and
    // four metadata files fit.
    let env = Env::with_config(LogConfig {
        max_entries: 9,
        ..config()
    });
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    client
        .update_revocation(&revocation_file(
            &env.online,
            1,
            &[(OTHER, "CVE-2026-0001")],
        ))
        .unwrap();
    let second = env.chain(2, long());
    assert!(matches!(
        client.update_timestamp(&second.timestamp),
        Err(PersistedUpdateError::NoRoom(NoRoom::Bounds {
            entries: 10,
            max_entries: 9,
            ..
        }))
    ));
    assert_eq!(versions(&client), (1, Some(1), Some(1), Some(1), Some(1)));
    assert_eq!(last(&client), Some(5));
    assert_eq!(client.halt(), None);
    assert_eq!(client.log().retention().dropped_entries, 0);
}

#[test]
fn one_owner_per_stream_and_records_are_read_strictly() {
    let env = Env::new();
    let client = env.open();
    assert!(matches!(
        env.try_open().err(),
        Some(RecoveryRefusal::Log(LogError::Owner(
            OwnerError::HeldInProcess { .. }
        )))
    ));
    client.close().unwrap();

    let record = TrustRecord::Accepted(AcceptedMetadata {
        role: Role::Root,
        version: v(1),
        accepted_at: NOW,
        file: env.fixture.root_file(1),
    });
    let json = serde_json::to_value(&record).unwrap();
    assert_eq!(
        serde_json::from_value::<TrustRecord>(json.clone()).unwrap(),
        record
    );
    let mut extra = json.clone();
    extra["accepted"]["trusted"] = json!(true);
    assert!(serde_json::from_value::<TrustRecord>(extra).is_err());
    let mut in_file = json.clone();
    in_file["accepted"]["file"]["note"] = json!("x");
    assert!(serde_json::from_value::<TrustRecord>(in_file).is_err());
    let other = json!({ "rejected": json["accepted"].clone() });
    assert!(serde_json::from_value::<TrustRecord>(other).is_err());
    let pinned = TrustRecord::Pinned(PinnedKeys {
        keys: BTreeSet::from([env.fixture.roots[0].key_id()]),
        at: NOW,
    });
    let json = serde_json::to_value(&pinned).unwrap();
    assert_eq!(
        serde_json::from_value::<TrustRecord>(json.clone()).unwrap(),
        pinned
    );
    let mut extra = json;
    extra["pinned"]["threshold"] = json!(2);
    assert!(serde_json::from_value::<TrustRecord>(extra).is_err());
}

#[test]
fn a_reloaded_key_revocation_reaches_the_running_client() {
    let env = Env::new();
    let mut client = env.open();
    // Root 2 replaces the online and revocation keys, signed by root-0 and root-1 only;
    // the release and a revocation list are signed with root 2's keys.
    let rotated = Online::rotated();
    client
        .update_root(&root_signed_by(&env.fixture, &rotated, 2, &[0, 1]))
        .unwrap();
    let first = chain(&rotated, 1, long());
    load(&mut client, &first);
    client
        .update_revocation(&revocation_file(&rotated, 1, &[(OTHER, "CVE-2026-0001")]))
        .unwrap();
    let kernel_artifact = opened(&client, &kernel(), KERNEL);
    client
        .admit_launch(execution("exe-1"), &kernel_artifact)
        .unwrap();
    assert_eq!(versions(&client), (2, Some(1), Some(1), Some(1), Some(1)));

    // The owner revokes root-0 and reloads the trust-root file; the running client
    // follows without a restart.
    env.revoke_root_keys(&[0]);
    let report = env.reload(&mut client).unwrap();
    assert_eq!(
        report.distrusted,
        BTreeSet::from([env.fixture.roots[0].key_id()])
    );
    // Root 2 needed root-0's signature, so it is no longer trusted; the online metadata
    // goes with it, and so does the list signed with root 2's revocation key.
    let everything = BTreeMap::from([
        (Role::Root, v(2)),
        (Role::Timestamp, v(1)),
        (Role::Snapshot, v(1)),
        (Role::Targets, v(1)),
        (Role::Revocation, v(1)),
    ]);
    assert_eq!(report.dropped, everything);
    assert_eq!(report.floors, everything);
    assert_eq!(report.kept_revoked, BTreeSet::from([ContentKey::of(OTHER)]));
    assert_eq!(client.halt(), None);
    assert_eq!(versions(&client), (1, None, None, None, None));
    // The target root 2's keys vouched for is no longer verified or admitted.
    let no_timestamp = Err(TrustRefusal::Refused {
        reason: UpdateRefusal::MissingPrerequisite {
            needed: Role::Timestamp,
        },
    });
    assert_eq!(
        client
            .verify_target(&kernel(), ArtifactClass::GuestImage)
            .map(|_| ()),
        no_timestamp
    );
    assert_eq!(
        client
            .admit_launch(execution("exe-2"), &kernel_artifact)
            .map(|_| ()),
        no_timestamp
    );
    // The earlier revocation is kept, and the running launch stays registered.
    assert_eq!(
        revoked(&client).keys().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([ContentKey::of(OTHER)])
    );
    assert!(client.running().get(&execution("exe-1")).is_some());

    // The floors still refuse rollback: online metadata waits for root 2, even metadata
    // signed with the online keys root 1 lists, and the dropped list's version is spent.
    assert_eq!(
        client.update_timestamp(&env.chain(1, long()).timestamp),
        Err(PersistedUpdateError::BelowFloor {
            reason: UpdateRefusal::MissingPrerequisite { needed: Role::Root }
        })
    );
    assert_eq!(
        client.update_revocation(&revocation_file(
            &env.online,
            1,
            &[(IMAGE, "CVE-2026-0002")]
        )),
        Err(PersistedUpdateError::BelowFloor {
            reason: UpdateRefusal::Replayed {
                role: Role::Revocation,
                version: v(1),
            }
        })
    );
    // Root-0's signature counts for nothing in later updates either.
    assert!(matches!(
        client.update_root(&root_signed_by(&env.fixture, &rotated, 2, &[0, 1])),
        Err(PersistedUpdateError::Refused {
            reason: UpdateRefusal::Signatures {
                failure: SignatureFailure::ThresholdNotMet { .. }
            }
        })
    ));

    // The distrust holds across a restart: the stream recorded root-0 as pinned once.
    client.close().unwrap();
    let (mut client, recovered) = env.try_open().unwrap();
    assert_eq!(
        recovered.distrusted,
        BTreeSet::from([env.fixture.roots[0].key_id()])
    );
    assert_eq!(recovered.floors, everything);
    assert_eq!(
        recovered.kept_revoked,
        BTreeSet::from([ContentKey::of(OTHER)])
    );
    assert_eq!(versions(&client), (1, None, None, None, None));

    // Root-1 and root-2 sign root 2 anew. It lists the online keys the floors were kept
    // under, so they still refuse the dropped release; a newer one is trusted.
    client
        .update_root(&root_signed_by(&env.fixture, &rotated, 2, &[1, 2]))
        .unwrap();
    assert_eq!(
        client.update_timestamp(&first.timestamp),
        Err(PersistedUpdateError::BelowFloor {
            reason: UpdateRefusal::Replayed {
                role: Role::Timestamp,
                version: v(1),
            }
        })
    );
    load(&mut client, &chain(&rotated, 2, long()));
    client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();
    assert_eq!(client.floors(), BTreeMap::from([(Role::Revocation, v(1))]));
    let before = (versions(&client), revoked(&client));
    assert_eq!(before.0, (2, Some(2), Some(2), Some(2), None));
    client.close().unwrap();
    let client = env.open();
    assert_eq!((versions(&client), revoked(&client)), before);
    assert_eq!(client.floors(), BTreeMap::from([(Role::Revocation, v(1))]));
}

#[test]
fn a_reload_that_cannot_complete_leaves_the_client_trusted_for_nothing() {
    let env = Env::new();
    let mut client = env.open();
    let first = env.chain(1, long());
    load(&mut client, &first);
    let kernel_artifact = opened(&client, &kernel(), KERNEL);
    client
        .admit_launch(execution("exe-1"), &kernel_artifact)
        .unwrap();

    // Two of the three root keys revoked: the threshold of two is out of reach.
    env.revoke_root_keys(&[0, 1]);
    let refusal = RecoveryRefusal::Bootstrap(BootstrapRefusal::Roots {
        reason: RootsRefusal::ThresholdAboveKeys {
            threshold: 2,
            keys: 1,
        },
    });
    assert_eq!(env.reload(&mut client), Err(refusal.clone()));
    let halt = Halt::ReloadFailed { refusal };
    assert_eq!(client.halt(), Some(&halt));
    // The old client stays, trusted for nothing.
    assert_eq!(versions(&client), (1, Some(1), Some(1), Some(1), None));
    let halted = Err(TrustRefusal::Halted { halt: halt.clone() });
    assert_eq!(
        client
            .verify_target(&kernel(), ArtifactClass::GuestImage)
            .map(|_| ()),
        halted
    );
    assert_eq!(
        client
            .admit_launch(execution("exe-2"), &kernel_artifact)
            .map(|_| ()),
        halted
    );
    assert_eq!(
        client.update_timestamp(&env.chain(2, long()).timestamp),
        Err(PersistedUpdateError::Halted { halt })
    );
    // The lifecycle can still end what runs.
    assert!(client.end_launch(&execution("exe-1")).is_some());

    // With the keys back in the file, a reload succeeds and lifts the halt.
    env.revoke_root_keys(&[]);
    let report = env.reload(&mut client).unwrap();
    assert!(report.distrusted.is_empty() && report.dropped.is_empty());
    assert_eq!(client.halt(), None);
    client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();

    // A restart while the threshold is out of reach fails closed as well.
    env.revoke_root_keys(&[0, 1]);
    client.close().unwrap();
    assert!(matches!(
        env.try_open().err(),
        Some(RecoveryRefusal::Bootstrap(BootstrapRefusal::Roots { .. }))
    ));
}

/// Half a line of the next record, as an append that stopped part way leaves it.
const TORN: &[u8] = b"5f3a {\"sequence\":5,\"owner\":1,\"entry\":{\"rec";

fn append_bytes(path: &Path, bytes: &[u8]) {
    fs::OpenOptions::new()
        .append(true)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

#[test]
fn a_torn_tail_past_the_synced_mark_resumes_from_the_records_before_it() {
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    // The pinned keys, then three metadata files.
    assert_eq!(last(&client), Some(4));
    let before = (versions(&client), revoked(&client));
    client.close().unwrap();
    // The next append stopped part way: half a line past the synced mark, which no append
    // acknowledged.
    append_bytes(&env.segments().pop().unwrap(), TORN);

    let (mut client, recovered) = env.try_open().unwrap();
    assert_eq!(
        recovered.report.torn_tail,
        Some(TornTailFound {
            marker: sequence(7),
            synced_through: Some(sequence(4)),
            past_synced_mark: true,
        })
    );
    let torn = TornTailPastMark {
        missing: SequenceRange::single(sequence(5)),
        marker: sequence(7),
        synced_through: Some(sequence(4)),
        at: NOW,
    };
    assert_eq!(recovered.torn_tails, [torn.clone()]);
    assert!(matches!(
        recovered.markers.as_slice(),
        [
            (truncated, LogMarker::Truncated { missing }),
            (quarantined, LogMarker::TornTail { .. }),
        ] if *truncated == sequence(6)
            && *missing == torn.missing
            && *quarantined == sequence(7)
    ));
    // The client resumed from the records before it; the record of the torn tail follows
    // the log's markers.
    assert_eq!((versions(&client), revoked(&client)), before);
    assert_eq!(last(&client), Some(8));
    client
        .verify_target(&kernel(), ArtifactClass::GuestImage)
        .unwrap();
    // The update the torn line held was never reported kept, so it is offered again.
    load(&mut client, &env.chain(2, long()));
    let after = versions(&client);
    assert_eq!(after, (1, Some(2), Some(2), Some(2), None));
    client.close().unwrap();

    // Every later open resumes past it as well, from the record.
    let (client, recovered) = env.try_open().unwrap();
    assert_eq!(recovered.report.torn_tail, None);
    assert_eq!(recovered.torn_tails, [torn]);
    assert_eq!(versions(&client), after);
}

#[test]
fn a_torn_tail_that_may_have_been_acknowledged_fails_closed() {
    // The last line, which an append acknowledged, damaged since: the torn line may be that
    // entry, so its gap refuses the open, then and on every later open.
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    client.close().unwrap();
    let tail = env.segments().pop().unwrap();
    let mut bytes = fs::read(&tail).unwrap();
    let body = bytes.len() - 1;
    let start = bytes[..body]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |at| at + 1);
    bytes[(start + body) / 2] ^= 0x01;
    fs::write(&tail, bytes).unwrap();
    let lost = Some(RecoveryRefusal::Lost {
        missing: SequenceRange::new(sequence(4), sequence(5)).unwrap(),
        reason: GapReason::Truncated,
    });
    assert_eq!(env.try_open().err(), lost);
    assert_eq!(env.try_open().err(), lost);

    // A torn tail past the mark that another opener of the stream found, so the stream
    // holds no record of it: its gap refuses the open as well.
    let env = Env::new();
    let mut client = env.open();
    load(&mut client, &env.chain(1, long()));
    client.close().unwrap();
    append_bytes(&env.segments().pop().unwrap(), TORN);
    let stream = env.stream();
    let (raw, report) = DurableLog::<TrustRecord>::open(
        &stream.directory,
        stream.stream.clone(),
        stream.owner.clone(),
        stream.config,
    )
    .unwrap();
    assert!(report.torn_tail.is_some_and(|torn| torn.past_synced_mark));
    raw.close().unwrap();
    assert_eq!(
        env.try_open().err(),
        Some(RecoveryRefusal::Lost {
            missing: SequenceRange::single(sequence(5)),
            reason: GapReason::Truncated,
        })
    );
}
