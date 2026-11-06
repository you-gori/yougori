//! The client's durable state, the bounded fetch port with the update flow over it, and
//! revocations reaching a running client (VM-W45, line 2668; the update threat-model
//! paragraph, line 2677; VM-P23, line 2798; VM-P48, line 2823; VM-D13, line 3207).
//! Each test drives the client as a caller would: a repository double behind the fetch
//! port, a real CORE-06 store in a temporary directory, and a restart as a new open.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Cursor, Read};
use std::path::{Path, PathBuf};

use super::tests::{
    developer_profile, kernel_entry, kernel_name, schemes, Chain, Fixture, Signer, DAY,
    KERNEL_BYTES, NOW,
};
use super::*;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::events::{DurableStreamId, LogConfig, LogDamage, LogError, ProducerId};
use crate::foundation::ids::ContentKey;

const KERNEL_V2: &[u8] = b"vmlinuz-6.6.53-yougori";

// A repository behind the fetch port.

/// Serves what was published, records every request, and can be taken offline.
#[derive(Default)]
struct Repository {
    metadata: BTreeMap<(Role, Option<u64>), Vec<u8>>,
    artifacts: BTreeMap<TargetName, Vec<u8>>,
    offline: bool,
    requests: Vec<FetchRequest>,
}

impl Repository {
    fn put(&mut self, role: Role, version: Option<u64>, file: &MetadataFile) {
        self.metadata
            .insert((role, version), serde_json::to_vec(file).unwrap());
    }

    /// Publishes `chain` at `version`: the newest timestamp, and the snapshot and targets
    /// by version.
    fn publish(&mut self, chain: &Chain, version: u64) {
        self.put(Role::Timestamp, None, &chain.timestamp);
        self.put(Role::Snapshot, Some(version), &chain.snapshot);
        self.put(Role::Targets, Some(version), &chain.targets);
    }

    fn items(&self) -> Vec<FetchItem> {
        self.requests
            .iter()
            .map(|request| request.item.clone())
            .collect()
    }
}

impl FetchPort for Repository {
    fn open(&mut self, request: &FetchRequest) -> Result<Box<dyn Read + '_>, FetchError> {
        self.requests.push(request.clone());
        if self.offline {
            return Err(FetchError::Unavailable {
                detail: "no route to the mirror".to_owned(),
            });
        }
        let bytes = match &request.item {
            FetchItem::Metadata { role, version } => self
                .metadata
                .get(&(*role, version.map(MetadataVersion::get)))
                .cloned(),
            FetchItem::Artifact { name, .. } => self.artifacts.get(name).cloned(),
        };
        bytes
            .map(|bytes| Box::new(Cursor::new(bytes)) as Box<dyn Read>)
            .ok_or(FetchError::NotFound)
    }
}

/// Serves an endless stream for every item, counting what the client read.
struct Endless {
    read: u64,
}

impl FetchPort for Endless {
    fn open(&mut self, _request: &FetchRequest) -> Result<Box<dyn Read + '_>, FetchError> {
        Ok(Box::new(Counting {
            read: &mut self.read,
        }))
    }
}

struct Counting<'a> {
    read: &'a mut u64,
}

impl Read for Counting<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        buf.fill(b' ');
        *self.read += buf.len() as u64;
        Ok(buf.len())
    }
}

/// A keeper whose storage always fails.
struct Failing;

impl StateKeeper for Failing {
    fn keep(&mut self, _state: &TrustState) -> Result<(), StoreRefusal> {
        Err(StoreRefusal::Log(LogError::Io {
            action: "append to the trust store",
            kind: std::io::ErrorKind::StorageFull,
            message: "disk full".to_owned(),
        }))
    }
}

// Store and restart.

fn store_config(directory: &Path) -> TrustStoreConfig {
    TrustStoreConfig {
        directory: directory.to_path_buf(),
        stream: DurableStreamId::new("sandbox.update-trust").unwrap(),
        owner: ProducerId::new("engine.update-trust").unwrap(),
        log: LogConfig {
            max_entries: 1_000,
            max_bytes: 1 << 24,
            segment_entries: 64,
            segment_bytes: 1 << 20,
        },
    }
}

fn open_store(directory: &Path) -> (TrustStore, Option<TrustState>) {
    let (store, state, _) = TrustStore::open(&store_config(directory)).unwrap();
    (store, state)
}

fn restore(fixture: &Fixture, state: &TrustState, now: UnixSeconds) -> UpdateClient {
    UpdateClient::restore(
        schemes(),
        ResolvedProfile::PRODUCTION,
        &fixture.root_file(1),
        state,
        now,
    )
    .unwrap()
}

/// Closes `store` and opens it again as a restarted process would, restoring the client.
fn restart(
    fixture: &Fixture,
    store: TrustStore,
    directory: &Path,
    now: UnixSeconds,
) -> (TrustStore, UpdateClient) {
    store.close().unwrap();
    let (store, state) = open_store(directory);
    let client = restore(fixture, &state.unwrap(), now);
    (store, client)
}

fn segments(directory: &Path) -> Vec<PathBuf> {
    let mut segments: Vec<PathBuf> = fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "jsonl")
        })
        .collect();
    segments.sort();
    segments
}

fn v(version: u64) -> MetadataVersion {
    MetadataVersion::new(version)
}

/// `fixture` with other online keys where named.
fn with_online(fixture: &Fixture, timestamp: Option<&str>, targets: Option<&str>) -> Fixture {
    let signer = |name: Option<&str>, kept: &Signer| {
        name.map_or_else(
            || kept.clone(),
            |name| Signer::new(name, SchemeKind::Ed25519),
        )
    };
    Fixture {
        roots: fixture.roots.clone(),
        timestamp: signer(timestamp, &fixture.timestamp),
        snapshot: fixture.snapshot.clone(),
        targets: signer(targets, &fixture.targets),
        revocation: fixture.revocation.clone(),
        expires: fixture.expires,
    }
}

/// Root `version` of `next`, signed by the root keys of `signers` (the same root keys
/// throughout these tests, so both thresholds are met).
fn rotation_to(next: &Fixture, signers: &Fixture, version: u64) -> MetadataFile {
    let mut file = MetadataFile::unsigned(&next.root_metadata(version)).unwrap();
    for signer in &signers.roots {
        signer.sign(&mut file, Role::Root);
    }
    file
}

fn verifies(client: &UpdateClient, now: UnixSeconds) -> Result<ContentKey, UpdateRefusal> {
    client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, now)
        .map(|verified| verified.content_key())
}

// Durable state.

#[test]
fn a_restart_continues_from_the_kept_state_and_never_accepts_older_metadata() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let (mut store, state) = open_store(directory.path());
    assert_eq!(state, None);
    let mut repository = Repository::default();
    let v1 = fixture.chain(1, KERNEL_BYTES, "2026.10.1");
    repository.publish(&v1, 1);
    let mut client = fixture.client();
    client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, NOW)
        .unwrap();
    let v2 = fixture.chain(2, KERNEL_V2, "2026.10.2");
    repository.publish(&v2, 2);
    repository.put(Role::Root, Some(2), &fixture.root_file(2));
    client
        .refresh(
            &mut repository,
            &mut store,
            &FetchLimits::DEFAULT,
            NOW.plus_seconds(60),
        )
        .unwrap();
    let before = client.trusted_versions();
    assert_eq!(before.root, v(2));
    assert_eq!(before.targets, Some(v(2)));

    let (_store, mut restarted) = restart(&fixture, store, directory.path(), NOW.plus_seconds(120));
    assert_eq!(restarted.trusted_versions(), before);
    assert_eq!(restarted.floors(), client.floors());
    assert_eq!(
        verifies(&restarted, NOW.plus_seconds(120)),
        Ok(ContentKey::of(KERNEL_V2))
    );
    // Older metadata is refused after the restart as before it.
    assert_eq!(
        restarted.update_timestamp(&v1.timestamp, NOW.plus_seconds(120)),
        Err(UpdateRefusal::RolledBack {
            role: Role::Timestamp,
            trusted: v(2),
            offered: v(1),
        })
    );
    assert_eq!(
        restarted
            .update_root(&fixture.root_file(1), NOW.plus_seconds(120))
            .map(|_| ()),
        Err(UpdateRefusal::RolledBack {
            role: Role::Root,
            trusted: v(2),
            offered: v(1),
        })
    );
    // A mirror rolled back to the first release is refused through the fetch port too.
    let mut rolled_back = Repository::default();
    rolled_back.publish(&v1, 1);
    let failure = restarted
        .refresh(
            &mut rolled_back,
            &mut MemoryOnly,
            &FetchLimits::DEFAULT,
            NOW.plus_seconds(120),
        )
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Timestamp);
    assert_eq!(
        failure.refusal,
        RefreshRefusal::Refused(UpdateRefusal::RolledBack {
            role: Role::Timestamp,
            trusted: v(2),
            offered: v(1),
        })
    );
    // A restart from nothing would have trusted it: the kept state is what refuses it.
    let mut fresh = fixture.client();
    assert!(fresh
        .refresh(
            &mut rolled_back,
            &mut MemoryOnly,
            &FetchLimits::DEFAULT,
            NOW
        )
        .is_ok());
}

#[test]
fn a_restart_refuses_an_expired_role_and_a_clock_set_back() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let (mut store, _) = open_store(directory.path());
    let soon = NOW.plus_seconds(600);
    let mut repository = Repository::default();
    repository.publish(
        &fixture.chain_expiring(1, KERNEL_BYTES, "2026.10.1", soon),
        1,
    );
    let mut client = fixture.client();
    client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, NOW)
        .unwrap();
    // A later refresh with nothing new still keeps the time it ran at.
    let report = client
        .refresh(
            &mut repository,
            &mut store,
            &FetchLimits::DEFAULT,
            NOW.plus_seconds(300),
        )
        .unwrap();
    assert!(report.updated.is_empty());
    assert_eq!(client.time_floor(), NOW.plus_seconds(300));
    store.close().unwrap();

    // The restarted process anchored its calendar behind the stored time: refused, so
    // a clock set back cannot make the timestamp fresh again.
    let (store, state) = open_store(directory.path());
    let state = state.unwrap();
    assert_eq!(state.time_floor, NOW.plus_seconds(300));
    assert_eq!(
        UpdateClient::restore(
            schemes(),
            ResolvedProfile::PRODUCTION,
            &fixture.root_file(1),
            &state,
            NOW.plus_seconds(200),
        )
        .map(|_| ()),
        Err(RestoreRefusal::ClockBehind {
            floor: NOW.plus_seconds(300),
            now: NOW.plus_seconds(200),
        })
    );
    // Restored at the expiry, the expired role is refused, and so is a mirror that keeps
    // serving it (a freeze).
    let mut client = restore(&fixture, &state, soon);
    let expired = UpdateRefusal::Expired {
        role: Role::Timestamp,
        expires: soon,
        now: soon,
    };
    assert_eq!(verifies(&client, soon), Err(expired.clone()));
    let mut store = store;
    let failure = client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, soon)
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Timestamp);
    assert_eq!(failure.refusal, RefreshRefusal::Refused(expired));
    // Checks with the clock behind the restored time are refused too.
    assert_eq!(
        verifies(&client, NOW.plus_seconds(100)),
        Err(UpdateRefusal::ClockBehind {
            floor: soon,
            now: NOW.plus_seconds(100),
        })
    );
    // A fresh release recovers it.
    repository.publish(&fixture.chain(2, KERNEL_V2, "2026.10.2"), 2);
    client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, soon)
        .unwrap();
    assert_eq!(verifies(&client, soon), Ok(ContentKey::of(KERNEL_V2)));
}

#[test]
fn a_frozen_snapshot_the_client_moved_past_stays_refused_after_its_file_is_dropped_and_a_restart() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let (mut store, _) = open_store(directory.path());
    let v1 = fixture.chain(1, KERNEL_BYTES, "2026.10.1");
    let v2 = fixture.chain(2, KERNEL_V2, "2026.10.2");
    let mut client = fixture.client();
    for chain in [&v1, &v2] {
        client
            .keep_update(&mut store, |client| chain.load(client, NOW))
            .unwrap();
    }
    // Only the timestamp key rotates. All online files are dropped; the timestamp floor
    // lapses with its key, the snapshot and targets floors stay.
    let rotated = with_online(&fixture, Some("timestamp-2"), None);
    let rotation = client
        .keep_update(&mut store, |client| {
            client.update_root(&rotation_to(&rotated, &fixture, 2), NOW)
        })
        .unwrap();
    assert_eq!(
        rotation.cleared,
        BTreeSet::from([Role::Timestamp, Role::Snapshot, Role::Targets])
    );
    let floors = BTreeMap::from([
        (Role::Root, v(2)),
        (Role::Snapshot, v(2)),
        (Role::Targets, v(2)),
    ]);
    assert_eq!(client.floors(), &floors);

    let (_store, mut client) = restart(&fixture, store, directory.path(), NOW);
    assert_eq!(client.floors(), &floors);
    assert_eq!(client.trusted_versions().snapshot, None);
    // A timestamp under the new key that points at the old snapshot: the old snapshot is
    // still validly signed by the unchanged snapshot key, so only the floor refuses it.
    let frozen = rotated.timestamp_file(1, &v1.snapshot, 1, fixture.expires);
    assert_eq!(
        client.update_timestamp(&frozen, NOW),
        Err(UpdateRefusal::RolledBack {
            role: Role::Snapshot,
            trusted: v(2),
            offered: v(1),
        })
    );
    // The current snapshot under a timestamp from the new key is accepted.
    let current = rotated.timestamp_file(1, &v2.snapshot, 2, fixture.expires);
    client.update_timestamp(&current, NOW).unwrap();
    client.update_snapshot(&v2.snapshot, NOW).unwrap();
    client.update_targets(&v2.targets, NOW).unwrap();
    assert_eq!(verifies(&client, NOW), Ok(ContentKey::of(KERNEL_V2)));

    // A rotated targets key lapses the targets floor: a repository recovering from a
    // compromised key may restart its numbering.
    let mut client = fixture.loaded();
    fixture
        .chain(2, KERNEL_V2, "2026.10.2")
        .load(&mut client, NOW)
        .unwrap();
    let new_targets = with_online(&fixture, None, Some("targets-2"));
    client
        .update_root(&rotation_to(&new_targets, &fixture, 2), NOW)
        .unwrap();
    assert_eq!(client.floors().get(&Role::Targets), None);
    assert_eq!(client.floors().get(&Role::Snapshot), Some(&v(2)));
    let targets = new_targets.targets_file(
        1,
        super::tests::kernel_targets(KERNEL_V2, "2026.10.2"),
        fixture.expires,
    );
    let snapshot = fixture.snapshot_file(3, &targets, 1, fixture.expires);
    let timestamp = fixture.timestamp_file(3, &snapshot, 3, fixture.expires);
    client.update_timestamp(&timestamp, NOW).unwrap();
    client.update_snapshot(&snapshot, NOW).unwrap();
    client.update_targets(&targets, NOW).unwrap();
    assert_eq!(verifies(&client, NOW), Ok(ContentKey::of(KERNEL_V2)));
}

#[test]
fn torn_truncated_and_rewritten_stores_are_refused_never_reset() {
    let fixture = Fixture::new();
    let keep_three = |directory: &Path| {
        let (mut store, _) = open_store(directory);
        let mut client = fixture.client();
        for (version, bytes) in [(1, KERNEL_BYTES), (2, KERNEL_V2)] {
            client
                .keep_update(&mut store, |client| {
                    fixture
                        .chain(version, bytes, "2026.10.1")
                        .load(client, NOW.plus_seconds(version))
                })
                .unwrap();
        }
        client
            .keep_update(&mut store, |client| {
                client.observe_time(NOW.plus_seconds(9))
            })
            .unwrap();
        store.close().unwrap();
    };

    // A torn tail: a last line that never completed. The log cannot show it was never
    // acknowledged, so the store refuses, and keeps refusing.
    let torn = tempfile::tempdir().unwrap();
    keep_three(torn.path());
    let segment = segments(torn.path()).pop().unwrap();
    let mut bytes = fs::read(&segment).unwrap();
    bytes.extend_from_slice(b"3f2a {\"sequence\":");
    fs::write(&segment, &bytes).unwrap();
    for _ in 0..2 {
        assert!(matches!(
            TrustStore::open(&store_config(torn.path())).map(|_| ()),
            Err(StoreRefusal::Lost { .. })
        ));
    }

    // A truncated stream: the last state cut off its end.
    let truncated = tempfile::tempdir().unwrap();
    keep_three(truncated.path());
    let segment = segments(truncated.path()).pop().unwrap();
    let bytes = fs::read(&segment).unwrap();
    let last_line = bytes[..bytes.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .unwrap()
        + 1;
    fs::write(&segment, &bytes[..last_line]).unwrap();
    assert_eq!(
        TrustStore::open(&store_config(truncated.path())).map(|_| ()),
        Err(StoreRefusal::LastStateLost)
    );

    // A rewritten record: the first state's time floor changed in place.
    let rewritten = tempfile::tempdir().unwrap();
    keep_three(rewritten.path());
    let segment = segments(rewritten.path()).pop().unwrap();
    let text = fs::read_to_string(&segment).unwrap();
    let first_end = text.find('\n').unwrap();
    let stamp = format!("\"time_floor\":{}", NOW.plus_seconds(1).get());
    assert!(text[..first_end].contains(&stamp));
    let forged = format!(
        "{}{}",
        text[..first_end].replacen(&stamp, "\"time_floor\":1", 1),
        &text[first_end..]
    );
    fs::write(&segment, forged).unwrap();
    assert!(matches!(
        TrustStore::open(&store_config(rewritten.path())).map(|_| ()),
        Err(StoreRefusal::Log(LogError::Damaged(LogDamage::Line { .. })))
    ));

    // Untouched, the same store opens with its newest state.
    let intact = tempfile::tempdir().unwrap();
    keep_three(intact.path());
    let (store, state, opened) = TrustStore::open(&store_config(intact.path())).unwrap();
    assert_eq!(opened.states, 3);
    let state = state.unwrap();
    assert_eq!(state.time_floor, NOW.plus_seconds(9));
    assert_eq!(state.version(Role::Targets), Some(v(2)));
    // A state that trusts less than the last one kept is refused before it is written.
    let mut older = state.clone();
    older.time_floor = NOW;
    let mut store = store;
    assert_eq!(
        store.keep_state(&older),
        Err(StoreRefusal::Regressed {
            sequence: None,
            regression: Regression::TimeFloor,
        })
    );
    let mut fewer = state.clone();
    fewer.floors.insert(Role::Snapshot, v(1));
    assert_eq!(
        store.keep_state(&fewer),
        Err(StoreRefusal::Regressed {
            sequence: None,
            regression: Regression::Floor {
                role: Role::Snapshot
            },
        })
    );
    store.close().unwrap();
    // One owner: a second open while the first holds the stream is refused.
    let (held, _) = open_store(intact.path());
    assert!(matches!(
        TrustStore::open(&store_config(intact.path())).map(|_| ()),
        Err(StoreRefusal::Log(LogError::Owner(_)))
    ));
    held.close().unwrap();
}

#[test]
fn restore_reverifies_the_signed_files_and_refuses_what_does_not_fit() {
    let fixture = Fixture::new();
    let mut client = fixture.loaded();
    client.update_root(&fixture.root_file(2), NOW).unwrap();
    client
        .update_revocation(&fixture.revocation_file(1, &[(b"old", "superseded")]))
        .unwrap();
    let state = client.state();
    assert_eq!(state.format, TRUST_STATE_FORMAT);
    assert_eq!(state.roots.len(), 2);
    let json = serde_json::to_value(&state).unwrap();
    assert_eq!(
        serde_json::from_value::<TrustState>(json.clone()).unwrap(),
        state
    );
    let mut unknown = json;
    unknown["note"] = serde_json::json!("hand-written");
    assert!(serde_json::from_value::<TrustState>(unknown).is_err());

    let restored = restore(&fixture, &state, NOW);
    assert_eq!(restored.trusted_versions(), client.trusted_versions());
    assert_eq!(restored.revoked(), client.revoked());
    // The operator pinned the newer root: the chain before it is dropped.
    let repinned = UpdateClient::restore(
        schemes(),
        ResolvedProfile::PRODUCTION,
        &fixture.root_file(2),
        &state,
        NOW,
    )
    .unwrap();
    assert_eq!(repinned.state().roots, vec![fixture.root_file(2)]);
    assert_eq!(verifies(&repinned, NOW), Ok(ContentKey::of(KERNEL_BYTES)));

    let refusal = |state: &TrustState| {
        UpdateClient::restore(
            schemes(),
            ResolvedProfile::PRODUCTION,
            &fixture.root_file(1),
            state,
            NOW,
        )
        .map(|_| ())
        .unwrap_err()
    };
    // A pinned root the state does not hold: the same keys, provisioned anew with
    // another expiry.
    let mut other_roots = fixture.root_metadata(1);
    other_roots.expires = NOW.plus_seconds(DAY);
    let mut other_root = MetadataFile::unsigned(&other_roots).unwrap();
    for signer in &fixture.roots {
        signer.sign(&mut other_root, Role::Root);
    }
    assert_eq!(
        UpdateClient::restore(
            schemes(),
            ResolvedProfile::PRODUCTION,
            &other_root,
            &state,
            NOW
        )
        .map(|_| ()),
        Err(RestoreRefusal::NotFromPinnedRoot)
    );
    // A targets file altered in the store no longer verifies.
    let mut altered = state.clone();
    let targets = altered.targets.take().unwrap();
    let mut signed = targets.signed().clone();
    signed["targets"]["guest-kernel"]["content_key"] =
        serde_json::json!(ContentKey::of(b"evil").to_string());
    altered.targets = Some(MetadataFile::new(signed, targets.signatures().to_vec()));
    assert!(matches!(
        refusal(&altered),
        RestoreRefusal::Refused {
            role: Role::Targets,
            reason: UpdateRefusal::Signatures { .. }
        }
    ));
    // A root slipped into the chain by someone without the root keys.
    let mut forged = state.clone();
    let attacker = Fixture {
        roots: ["mallory-1", "mallory-2"]
            .iter()
            .map(|name| Signer::new(name, SchemeKind::Ed25519))
            .collect(),
        ..with_online(&fixture, None, None)
    };
    forged.roots.push(rotation_to(&attacker, &attacker, 3));
    assert!(matches!(
        refusal(&forged),
        RestoreRefusal::Refused {
            role: Role::Root,
            reason: UpdateRefusal::Signatures { .. }
        }
    ));
    // A record that is not its file, a floor below a trusted version, a snapshot without
    // its timestamp, a bad reason, another format or profile.
    let mut recorded = state.clone();
    recorded.trusted.insert(
        Role::Targets,
        RoleRecord {
            version: v(9),
            expires: Some(fixture.expires),
        },
    );
    assert!(matches!(
        refusal(&recorded),
        RestoreRefusal::Inconsistent {
            role: Role::Targets,
            inconsistency: Inconsistency::Recorded { .. }
        }
    ));
    let mut floor = state.clone();
    floor.floors.insert(Role::Snapshot, v(0));
    assert_eq!(
        refusal(&floor),
        RestoreRefusal::Inconsistent {
            role: Role::Snapshot,
            inconsistency: Inconsistency::Floor {
                floor: Some(v(0)),
                trusted: v(1),
            }
        }
    );
    let mut orphan = state.clone();
    orphan.timestamp = None;
    assert_eq!(
        refusal(&orphan),
        RestoreRefusal::Inconsistent {
            role: Role::Snapshot,
            inconsistency: Inconsistency::WithoutPrerequisite {
                needed: Role::Timestamp
            }
        }
    );
    let mut reason = state.clone();
    reason
        .host
        .classes
        .insert(ArtifactClass::GuestImage, String::new());
    assert_eq!(
        refusal(&reason),
        RestoreRefusal::Inconsistent {
            role: Role::Revocation,
            inconsistency: Inconsistency::Reason
        }
    );
    let mut format = state.clone();
    format.format = TRUST_STATE_FORMAT + 1;
    assert_eq!(
        refusal(&format),
        RestoreRefusal::Format {
            found: TRUST_STATE_FORMAT + 1,
            expected: TRUST_STATE_FORMAT
        }
    );
    assert_eq!(
        UpdateClient::restore(
            schemes(),
            developer_profile(),
            &fixture.root_file(1),
            &state,
            NOW
        )
        .map(|_| ()),
        Err(RestoreRefusal::ProfileChanged {
            stored: AssuranceProfile::Production,
            requested: AssuranceProfile::Developer,
        })
    );
    let mut empty = state;
    empty.roots.clear();
    assert!(matches!(
        refusal(&empty),
        RestoreRefusal::RootCount { roots: 0, .. }
    ));
}

// The fetch port and the update flow.

#[test]
fn refresh_runs_the_narrow_order_and_keeps_each_step() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let (mut store, _) = open_store(directory.path());
    let mut repository = Repository::default();
    repository.put(Role::Root, Some(2), &fixture.root_file(2));
    repository.put(
        Role::Revocation,
        None,
        &fixture.revocation_file(1, &[(b"old", "superseded")]),
    );
    repository.publish(&fixture.chain(1, KERNEL_BYTES, "2026.10.1"), 1);

    let mut client = fixture.client();
    let report = client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, NOW)
        .unwrap();
    let metadata = |role, version: Option<u64>| FetchItem::Metadata {
        role,
        version: version.map(v),
    };
    assert_eq!(
        repository.items(),
        [
            metadata(Role::Root, Some(2)),
            metadata(Role::Root, Some(3)),
            metadata(Role::Revocation, None),
            metadata(Role::Timestamp, None),
            metadata(Role::Snapshot, Some(1)),
            metadata(Role::Targets, Some(1)),
        ]
    );
    // Snapshot and targets are read up to exactly the length their reference names.
    let chain = fixture.chain(1, KERNEL_BYTES, "2026.10.1");
    assert_eq!(
        repository.requests[4].max_bytes,
        chain.snapshot.file_reference(v(1)).unwrap().length_bytes
    );
    assert_eq!(
        repository.requests[3].max_bytes,
        FetchLimits::DEFAULT.timestamp_bytes
    );
    assert_eq!(report.before.root, v(1));
    assert_eq!(
        report.after,
        TrustedVersions {
            root: v(2),
            timestamp: Some(v(1)),
            snapshot: Some(v(1)),
            targets: Some(v(1)),
            revocation: Some(v(1)),
        }
    );
    assert_eq!(report.rotations.len(), 1);
    assert_eq!(
        report.revocation.as_ref().map(|applied| applied.version),
        Some(v(1))
    );
    assert_eq!(
        report.updated,
        BTreeSet::from([
            Role::Root,
            Role::Revocation,
            Role::Timestamp,
            Role::Snapshot,
            Role::Targets
        ])
    );
    // Every step was kept: one state per step.
    assert_eq!(store.log().totals().records, 5);

    // Nothing new: only the next root, the list and the timestamp are asked for.
    repository.requests.clear();
    let report = client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, NOW)
        .unwrap();
    assert!(report.updated.is_empty());
    assert_eq!(
        repository.items(),
        [
            metadata(Role::Root, Some(3)),
            metadata(Role::Revocation, None),
            metadata(Role::Timestamp, None),
        ]
    );

    // A step that is accepted but not kept is undone.
    let mut unkept = fixture.client();
    let failure = unkept
        .refresh(&mut repository, &mut Failing, &FetchLimits::DEFAULT, NOW)
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Root);
    assert!(matches!(failure.refusal, RefreshRefusal::NotKept(_)));
    assert_eq!(unkept.trusted_versions().root, v(1));
    assert!(failure.report.rotations.is_empty());

    // A withdrawn revocation list, and an older one, are refused.
    let mut withdrawn = Repository {
        metadata: repository.metadata.clone(),
        ..Repository::default()
    };
    withdrawn.metadata.remove(&(Role::Revocation, None));
    let failure = client
        .refresh(&mut withdrawn, &mut store, &FetchLimits::DEFAULT, NOW)
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Revocation);
    assert_eq!(
        failure.refusal,
        RefreshRefusal::RevocationWithdrawn { trusted: v(1) }
    );
    client
        .update_revocation(&fixture.revocation_file(2, &[]))
        .unwrap();
    let failure = client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, NOW)
        .unwrap_err();
    assert_eq!(
        failure.refusal,
        RefreshRefusal::Refused(UpdateRefusal::RolledBack {
            role: Role::Revocation,
            trusted: v(2),
            offered: v(1),
        })
    );

    // At most the configured rotations per refresh; the rest follow at the next one.
    let mut rotations = Repository::default();
    rotations.put(Role::Root, Some(2), &fixture.root_file(2));
    rotations.put(Role::Root, Some(3), &fixture.root_file(3));
    rotations.publish(&fixture.chain(1, KERNEL_BYTES, "2026.10.1"), 1);
    let limits = FetchLimits {
        max_root_rotations: 1,
        ..FetchLimits::DEFAULT
    };
    let mut client = fixture.client();
    let report = client
        .refresh(&mut rotations, &mut MemoryOnly, &limits, NOW)
        .unwrap();
    assert!(report.rotation_limit_reached);
    assert_eq!(client.root().version, v(2));
    client
        .refresh(&mut rotations, &mut MemoryOnly, &limits, NOW)
        .unwrap();
    assert_eq!(client.root().version, v(3));
}

#[test]
fn everything_fetched_is_bounded() {
    let fixture = Fixture::new();
    let chain = fixture.chain(1, KERNEL_BYTES, "2026.10.1");

    // An endless stream is cut one byte past the bound, never read to its end.
    let mut endless = Endless { read: 0 };
    let failure = fixture
        .client()
        .refresh(&mut endless, &mut MemoryOnly, &FetchLimits::DEFAULT, NOW)
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Root);
    assert_eq!(
        failure.refusal,
        RefreshRefusal::Fetch(FetchRefusal::TooLarge {
            item: FetchItem::Metadata {
                role: Role::Root,
                version: Some(v(2)),
            },
            limit: FetchLimits::DEFAULT.root_bytes,
        })
    );
    // The revocation step still ran after the failed root step, and was cut too: one
    // byte past each bound was read, nothing more.
    assert_eq!(
        endless.read,
        FetchLimits::DEFAULT.root_bytes + 1 + FetchLimits::DEFAULT.revocation_bytes + 1
    );

    // A timestamp longer than its bound.
    let mut repository = Repository::default();
    repository.publish(&chain, 1);
    let small = FetchLimits {
        timestamp_bytes: 64,
        ..FetchLimits::DEFAULT
    };
    let failure = fixture
        .client()
        .refresh(&mut repository, &mut MemoryOnly, &small, NOW)
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Timestamp);
    assert!(matches!(
        failure.refusal,
        RefreshRefusal::Fetch(FetchRefusal::TooLarge { limit: 64, .. })
    ));

    // A referenced snapshot beyond the ceiling is not even asked for.
    repository.requests.clear();
    let ceiling = FetchLimits {
        snapshot_bytes: 10,
        ..FetchLimits::DEFAULT
    };
    let failure = fixture
        .client()
        .refresh(&mut repository, &mut MemoryOnly, &ceiling, NOW)
        .unwrap_err();
    assert!(matches!(
        failure.refusal,
        RefreshRefusal::Fetch(FetchRefusal::ReferenceTooLarge {
            role: Role::Snapshot,
            limit: 10,
            ..
        })
    ));
    assert!(!repository.items().iter().any(|item| matches!(
        item,
        FetchItem::Metadata {
            role: Role::Snapshot,
            ..
        }
    )));

    // A snapshot padded past the referenced length, and bytes that are not metadata.
    let mut padded = serde_json::to_vec(&chain.snapshot).unwrap();
    padded.extend_from_slice(b"  ");
    repository
        .metadata
        .insert((Role::Snapshot, Some(1)), padded);
    let failure = fixture
        .client()
        .refresh(&mut repository, &mut MemoryOnly, &FetchLimits::DEFAULT, NOW)
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Snapshot);
    assert!(matches!(
        failure.refusal,
        RefreshRefusal::Fetch(FetchRefusal::TooLarge { .. })
    ));
    repository
        .metadata
        .insert((Role::Timestamp, None), b"not metadata".to_vec());
    let failure = fixture
        .client()
        .refresh(&mut repository, &mut MemoryOnly, &FetchLimits::DEFAULT, NOW)
        .unwrap_err();
    assert!(matches!(
        failure.refusal,
        RefreshRefusal::Fetch(FetchRefusal::Malformed { .. })
    ));

    // Offline: the refresh fails and changes nothing; what is trusted keeps verifying
    // until it expires.
    let mut client = fixture.loaded();
    let before = client.trusted_versions();
    let mut offline = Repository {
        offline: true,
        ..Repository::default()
    };
    let failure = client
        .refresh(&mut offline, &mut MemoryOnly, &FetchLimits::DEFAULT, NOW)
        .unwrap_err();
    assert!(matches!(
        failure.refusal,
        RefreshRefusal::Fetch(FetchRefusal::Fetch {
            error: FetchError::Unavailable { .. },
            ..
        })
    ));
    assert_eq!(client.trusted_versions(), before);
    assert!(verifies(&client, NOW.plus_seconds(DAY)).is_ok());
}

#[test]
fn an_artifact_is_fetched_within_its_declared_length_and_opens_only_as_verified() {
    let fixture = Fixture::new();
    let client = fixture.loaded();
    let mut repository = Repository::default();
    repository
        .artifacts
        .insert(kernel_name(), KERNEL_BYTES.to_vec());
    let fetch = |repository: &mut Repository, limits: &FetchLimits| {
        client.fetch_artifact(
            repository,
            &kernel_name(),
            ArtifactClass::GuestImage,
            limits,
            NOW,
        )
    };
    let opened = fetch(&mut repository, &FetchLimits::DEFAULT).unwrap();
    assert_eq!(opened.bytes(), KERNEL_BYTES);
    assert!(client.admit_launch(&opened, NOW).is_ok());
    assert_eq!(
        repository.requests.last().unwrap(),
        &FetchRequest {
            item: FetchItem::Artifact {
                name: kernel_name(),
                content_key: ContentKey::of(KERNEL_BYTES),
            },
            max_bytes: KERNEL_BYTES.len() as u64,
        }
    );
    // Replaced, longer or missing bytes.
    let replaced = KERNEL_BYTES
        .iter()
        .map(|byte| byte ^ 1)
        .collect::<Vec<u8>>();
    repository.artifacts.insert(kernel_name(), replaced.clone());
    assert_eq!(
        fetch(&mut repository, &FetchLimits::DEFAULT).map(|_| ()),
        Err(ArtifactFetchRefusal::Open(OpenRefusal::BytesDiffer {
            expected: ContentKey::of(KERNEL_BYTES),
            found: ContentKey::of(&replaced),
        }))
    );
    let mut longer = KERNEL_BYTES.to_vec();
    longer.extend_from_slice(&[0; 4096]);
    repository.artifacts.insert(kernel_name(), longer);
    assert_eq!(
        fetch(&mut repository, &FetchLimits::DEFAULT).map(|_| ()),
        Err(ArtifactFetchRefusal::Open(OpenRefusal::LengthDiffers {
            expected_bytes: KERNEL_BYTES.len() as u64,
            found_bytes: KERNEL_BYTES.len() as u64 + 1,
        }))
    );
    repository.artifacts.clear();
    assert_eq!(
        fetch(&mut repository, &FetchLimits::DEFAULT).map(|_| ()),
        Err(ArtifactFetchRefusal::Fetch(FetchError::NotFound))
    );
    let tiny = FetchLimits {
        artifact_bytes: 4,
        ..FetchLimits::DEFAULT
    };
    assert_eq!(
        fetch(&mut repository, &tiny).map(|_| ()),
        Err(ArtifactFetchRefusal::TooLarge {
            length_bytes: KERNEL_BYTES.len() as u64,
            limit: 4,
        })
    );
    // A target the client does not verify is never asked for.
    repository.requests.clear();
    assert!(matches!(
        client.fetch_artifact(
            &mut repository,
            &kernel_name(),
            ArtifactClass::OciLayer,
            &FetchLimits::DEFAULT,
            NOW,
        ),
        Err(ArtifactFetchRefusal::Refused(
            UpdateRefusal::ClassMismatch { .. }
        ))
    ));
    assert!(repository.requests.is_empty());
}

// Revocation reaching a running client.

#[test]
fn a_revoked_key_reaches_running_clients_at_their_next_check() {
    let fixture = Fixture::new();
    let feed = RevocationFeed::new();
    let mut client = fixture.loaded();
    client.attach_revocations(feed.clone());
    let mut other = fixture.loaded();
    other.attach_revocations(feed.clone());
    let opened = client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap()
        .open(KERNEL_BYTES.to_vec())
        .unwrap();
    assert!(client.admit_launch(&opened, NOW).is_ok());

    // The host revokes the online targets key; neither client restarts.
    assert_eq!(
        feed.revoke_key(fixture.targets.key_id(), "targets key compromised"),
        Ok(true)
    );
    let revoked = UpdateRefusal::RevokedKey {
        role: Role::Targets,
        key_id: fixture.targets.key_id(),
        reason: "targets key compromised".to_owned(),
    };
    assert_eq!(verifies(&client, NOW), Err(revoked.clone()));
    assert_eq!(verifies(&other, NOW), Err(revoked.clone()));
    // The revocation is part of the state, so it survives a restart without the feed.
    let state = other.state();
    assert!(state.host.keys.contains_key(&fixture.targets.key_id()));
    assert_eq!(
        verifies(&restore(&fixture, &state, NOW), NOW),
        Err(revoked.clone())
    );
    // What was verified under the key before is refused at the launch boundary.
    assert_eq!(
        client.admit_launch(&opened, NOW).map(|_| ()),
        Err(revoked.clone())
    );
    // New targets signed by the revoked key are refused.
    let v2 = fixture.chain(2, KERNEL_V2, "2026.10.2");
    client.update_timestamp(&v2.timestamp, NOW).unwrap();
    client.update_snapshot(&v2.snapshot, NOW).unwrap();
    assert_eq!(
        client.update_targets(&v2.targets, NOW),
        Err(revoked.clone())
    );
    // Recovery: the root custodians rotate the targets key.
    let recovered = with_online(&fixture, None, Some("targets-2"));
    client
        .update_root(&rotation_to(&recovered, &fixture, 2), NOW)
        .unwrap();
    let fresh = recovered.chain(3, KERNEL_V2, "2026.10.2");
    fresh.load(&mut client, NOW).unwrap();
    assert_eq!(verifies(&client, NOW), Ok(ContentKey::of(KERNEL_V2)));

    // Root keys count one by one: with two of three root keys left the root holds; with
    // one left it no longer does.
    feed.revoke_key(fixture.roots[0].key_id(), "custodian left")
        .unwrap();
    assert!(verifies(&client, NOW).is_ok());
    feed.revoke_key(fixture.roots[1].key_id(), "custodian left")
        .unwrap();
    assert_eq!(
        verifies(&client, NOW),
        Err(UpdateRefusal::RevokedKey {
            role: Role::Root,
            key_id: fixture.roots[0].key_id().min(fixture.roots[1].key_id()),
            reason: "custodian left".to_owned(),
        })
    );
    assert!(matches!(
        verifies(&other, NOW),
        Err(UpdateRefusal::RevokedKey {
            role: Role::Root,
            ..
        })
    ));

    // A feed attached later, then replaced, still leaves its revocations in force.
    let mut client = fixture.loaded();
    let first = RevocationFeed::new();
    client.attach_revocations(first.clone());
    first
        .revoke_key(fixture.timestamp.key_id(), "timestamp key compromised")
        .unwrap();
    client.attach_revocations(RevocationFeed::new());
    assert!(matches!(
        verifies(&client, NOW),
        Err(UpdateRefusal::RevokedKey {
            role: Role::Timestamp,
            ..
        })
    ));
}

#[test]
fn a_revoked_artifact_class_reaches_a_running_client_at_its_next_check() {
    let fixture = Fixture::new();
    let layer = TargetName::new("base-layer").unwrap();
    let mut targets = BTreeMap::from([(kernel_name(), kernel_entry(KERNEL_BYTES, "2026.10.1"))]);
    targets.insert(
        layer.clone(),
        TargetEntry {
            class: ArtifactClass::OciLayer,
            length_bytes: 5,
            content_key: ContentKey::of(b"layer"),
            release: ReleaseVersion::new("2026.10.1").unwrap(),
        },
    );
    let targets = fixture.targets_file(1, targets, fixture.expires);
    let snapshot = fixture.snapshot_file(1, &targets, 1, fixture.expires);
    let timestamp = fixture.timestamp_file(1, &snapshot, 1, fixture.expires);
    let mut client = fixture.client();
    Chain {
        timestamp,
        snapshot,
        targets,
    }
    .load(&mut client, NOW)
    .unwrap();
    let feed = RevocationFeed::new();
    client.attach_revocations(feed.clone());
    let opened = client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap()
        .open(KERNEL_BYTES.to_vec())
        .unwrap();

    feed.revoke_class(ArtifactClass::GuestImage, "guest images withdrawn")
        .unwrap();
    let revoked = UpdateRefusal::RevokedClass {
        name: kernel_name(),
        class: ArtifactClass::GuestImage,
        reason: "guest images withdrawn".to_owned(),
    };
    assert_eq!(verifies(&client, NOW), Err(revoked.clone()));
    assert_eq!(client.admit_launch(&opened, NOW).map(|_| ()), Err(revoked));
    // Another class is untouched.
    assert!(client
        .verify_target(&layer, ArtifactClass::OciLayer, NOW)
        .is_ok());

    // An unsigned developer build of the class is refused too.
    let test_keys = Fixture::with_scheme(SchemeKind::HmacSha256Test);
    let mut developer =
        UpdateClient::new(schemes(), developer_profile(), &test_keys.root_file(1), NOW).unwrap();
    developer.attach_revocations(feed);
    let unsigned = VerifiedTarget::developer_unsigned(
        developer_profile(),
        TargetName::new("local-kernel").unwrap(),
        ArtifactClass::GuestImage,
        ContentKey::of(b"local"),
        5,
        ReleaseVersion::new("dev").unwrap(),
        NOW,
    )
    .unwrap()
    .open(b"local".to_vec())
    .unwrap();
    assert!(matches!(
        developer.admit_launch(&unsigned, NOW),
        Err(UpdateRefusal::RevokedClass {
            class: ArtifactClass::GuestImage,
            ..
        })
    ));
}

#[test]
fn a_signed_revocation_reaches_a_running_client_at_its_next_refresh_and_is_kept() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let (mut store, _) = open_store(directory.path());
    let mut repository = Repository::default();
    repository.publish(&fixture.chain(1, KERNEL_BYTES, "2026.10.1"), 1);
    let mut client = fixture.client();
    client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, NOW)
        .unwrap();
    let opened = client
        .verify_target(&kernel_name(), ArtifactClass::GuestImage, NOW)
        .unwrap()
        .open(KERNEL_BYTES.to_vec())
        .unwrap();
    assert!(client.admit_launch(&opened, NOW).is_ok());

    // The release is revoked and the mirror's timestamp is unreachable: the list still
    // applies, because it comes before the online roles.
    repository.put(
        Role::Revocation,
        None,
        &fixture.revocation_file(1, &[(KERNEL_BYTES, "signing pipeline compromised")]),
    );
    repository.metadata.remove(&(Role::Timestamp, None));
    let failure = client
        .refresh(&mut repository, &mut store, &FetchLimits::DEFAULT, NOW)
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Timestamp);
    assert_eq!(
        failure
            .report
            .revocation
            .as_ref()
            .map(|applied| applied.newly_revoked.clone()),
        Some(BTreeSet::from([ContentKey::of(KERNEL_BYTES)]))
    );
    let revoked = UpdateRefusal::RevokedRelease {
        content_key: ContentKey::of(KERNEL_BYTES),
        reason: "signing pipeline compromised".to_owned(),
    };
    assert_eq!(
        client.admit_launch(&opened, NOW).map(|_| ()),
        Err(revoked.clone())
    );

    // Kept: the restarted client refuses it too.
    let (_store, mut restarted) = restart(&fixture, store, directory.path(), NOW);
    assert_eq!(restarted.trusted_versions().revocation, Some(v(1)));
    assert_eq!(
        restarted.admit_launch(&opened, NOW).map(|_| ()),
        Err(revoked)
    );

    // Neither an expired root nor a failed root step holds a revocation back.
    repository.put(
        Role::Revocation,
        None,
        &fixture.revocation_file(2, &[(KERNEL_V2, "never released")]),
    );
    let failure = restarted
        .refresh(
            &mut repository,
            &mut MemoryOnly,
            &FetchLimits::DEFAULT,
            fixture.expires,
        )
        .unwrap_err();
    assert_eq!(failure.step, RefreshStep::Root);
    assert_eq!(
        failure.refusal,
        RefreshRefusal::Refused(UpdateRefusal::Expired {
            role: Role::Root,
            expires: fixture.expires,
            now: fixture.expires,
        })
    );
    assert_eq!(restarted.trusted_versions().revocation, Some(v(2)));
    repository.put(
        Role::Revocation,
        None,
        &fixture.revocation_file(3, &[(b"other", "withdrawn")]),
    );
    repository
        .metadata
        .insert((Role::Root, Some(2)), b"{}".to_vec());
    let failure = restarted
        .refresh(
            &mut repository,
            &mut MemoryOnly,
            &FetchLimits::DEFAULT,
            fixture.expires,
        )
        .unwrap_err();
    assert!(matches!(
        failure.refusal,
        RefreshRefusal::Fetch(FetchRefusal::Malformed { .. })
    ));
    assert_eq!(restarted.trusted_versions().revocation, Some(v(3)));
}

#[test]
fn a_store_whose_every_state_retention_dropped_is_refused() {
    let fixture = Fixture::new();
    let directory = tempfile::tempdir().unwrap();
    let config = TrustStoreConfig {
        log: LogConfig {
            max_entries: 2,
            max_bytes: 1 << 24,
            segment_entries: 1,
            segment_bytes: 1 << 20,
        },
        ..store_config(directory.path())
    };
    let (mut store, _, _) = TrustStore::open(&config).unwrap();
    let mut client = fixture.client();
    client
        .keep_update(&mut store, |client| {
            fixture
                .chain(1, KERNEL_BYTES, "2026.10.1")
                .load(client, NOW)
        })
        .unwrap();
    store.close().unwrap();
    // Each open without the owner record appends a marker; the second pushes the state's
    // segment out of retention.
    fs::remove_file(directory.path().join("owner.json")).unwrap();
    let (store, state, opened) = TrustStore::open(&config).unwrap();
    assert!(state.is_some());
    assert_eq!(opened.markers.len(), 1);
    store.close().unwrap();
    fs::remove_file(directory.path().join("owner.json")).unwrap();
    assert_eq!(
        TrustStore::open(&config).map(|_| ()),
        Err(StoreRefusal::LastStateLost)
    );
}
