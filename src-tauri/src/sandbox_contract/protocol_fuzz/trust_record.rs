//! The trust stream's record reader under the fuzzer (M18B; VM-W45, VM-CP-22; VM-W50):
//! `serde_json` reading [`TrustRecord`] from mutated records, as the persisted update
//! client reads each record of its durable stream when it opens or reloads. Host state,
//! not guest input; the stream's line digests and the client's own checks on replay stand
//! behind it, but a record the reader accepts is what the replay is given.
//!
//! The seeds are records of every role, of pinned keys and of torn tails past the synced
//! mark, with metadata signed by Ed25519 keys made from fixed seeds, the way the module's
//! own tests (`trust_adapter::tests`) sign it.
//!
//! Properties, beside no panic and the same result twice:
//!
//! - An accepted record writes back to JSON that reads as the same record and writes
//!   again to the same bytes, and the input denotes exactly that record
//!   (`strict_json::denotes`): nothing in it was ignored, defaulted or changed.
//! - Each seed, and one in eight accepted records that is no seed's, is refused with an
//!   unknown member in any of its objects and with a value of another JSON type at any of
//!   its leaves, outside the signed payload, which a record keeps as the JSON it was
//!   offered (the client checks its signatures and parses it on replay).
//!
//! Finding, kept in [`FINDINGS`] as a regression, fixed in `79206ee` (`SequenceRange`
//! reads back through its constructor): a torn tail's missing range that ran backward was
//! read (see [`FINDINGS`]); the main run only counts such records (`:backward_range`).

use std::collections::{BTreeMap, BTreeSet};

use ring::signature::{Ed25519KeyPair, KeyPair};
use serde_json::Value;

use super::driver::{fuzz, Regression, Run, Verdict};
use super::mutate::{decimal_fields, variant, Grammar};
use super::rng::SplitMix64;
use super::strict_json::{denotes, refusal_label, refuses_edits};
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::events::{EventSequence, SequenceRange};
use crate::foundation::ids::ContentKey;
use crate::sandbox::trust::{
    HexBytes, MetadataFile, MetadataVersion, PublicKey, ReleaseVersion, RevocationMetadata, Role,
    RoleKeys, RootMetadata, SchemeKind, Signature, SnapshotMetadata, TargetEntry, TargetName,
    TargetsMetadata, TimestampMetadata, UnixSeconds,
};
use crate::sandbox_contract::trust_adapter::{
    AcceptedMetadata, PinnedKeys, TornTailPastMark, TrustRecord,
};

/// Mutated records per run.
const ITERATIONS: u64 = 25_000;
/// The members whose values a record keeps as the JSON it was given.
const FREE: &[&str] = &["signed"];
/// The trust clock's time of the seeds.
const NOW: UnixSeconds = UnixSeconds::new(1_700_000_000);
const DAY: u64 = 86_400;

/// Refusal kinds by the text of the message.
const KINDS: &[(&str, &str)] = &[
    ("unknown field", "unknown_field"),
    ("missing field", "missing_field"),
    ("unknown variant", "unknown_variant"),
    ("duplicate field", "duplicate_field"),
    ("invalid type", "invalid_type"),
    ("hexadecimal", "hex"),
];

/// An Ed25519 key made from a fixed seed, as the module's tests make theirs.
struct Signer {
    pair: Ed25519KeyPair,
    key: PublicKey,
}

impl Signer {
    fn from_seed(seed: u8) -> Self {
        let pair = Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).unwrap();
        let key = PublicKey::new(SchemeKind::Ed25519, pair.public_key().as_ref().to_vec());
        Self { pair, key }
    }

    /// `payload` as a metadata file for `role`, signed by `signers`.
    fn file<T: serde::Serialize>(payload: &T, role: Role, signers: &[&Signer]) -> MetadataFile {
        let mut file = MetadataFile::unsigned(payload).unwrap();
        for signer in signers {
            let message = file.message(role).unwrap();
            file.add_signature(Signature {
                key_id: signer.key.key_id(),
                signature: HexBytes::new(signer.pair.sign(&message).as_ref().to_vec()),
            });
        }
        file
    }
}

fn accepted(role: Role, version: u64, file: MetadataFile) -> TrustRecord {
    TrustRecord::Accepted(AcceptedMetadata {
        role,
        version: MetadataVersion::new(version),
        accepted_at: NOW,
        file,
    })
}

fn records() -> Vec<TrustRecord> {
    let roots: Vec<Signer> = [1, 2, 3].into_iter().map(Signer::from_seed).collect();
    let [timestamp, snapshot, targets, revocation] = [40, 50, 60, 70].map(Signer::from_seed);
    let expires = NOW.plus_seconds(7 * DAY);
    let mut keys = BTreeMap::new();
    for signer in roots
        .iter()
        .chain([&timestamp, &snapshot, &targets, &revocation])
    {
        keys.insert(signer.key.key_id(), signer.key.clone());
    }
    let one = |signer: &Signer| RoleKeys::new([signer.key.key_id()], 1);
    let root = RootMetadata {
        role: Role::Root,
        version: MetadataVersion::new(1),
        expires: NOW.plus_seconds(30 * DAY),
        keys,
        roles: BTreeMap::from([
            (
                Role::Root,
                RoleKeys::new(roots.iter().map(|signer| signer.key.key_id()), 2),
            ),
            (Role::Timestamp, one(&timestamp)),
            (Role::Snapshot, one(&snapshot)),
            (Role::Targets, one(&targets)),
            (Role::Revocation, one(&revocation)),
        ]),
    };
    let artifact = |name: &str, bytes: &[u8]| {
        (
            TargetName::new(name).unwrap(),
            TargetEntry {
                class: ArtifactClass::GuestImage,
                length_bytes: u64::try_from(bytes.len()).unwrap(),
                content_key: ContentKey::of(bytes),
                release: ReleaseVersion::new("2026.10.3").unwrap(),
            },
        )
    };
    let targets_file = Signer::file(
        &TargetsMetadata {
            role: Role::Targets,
            version: MetadataVersion::new(3),
            expires,
            targets: BTreeMap::from([
                artifact("guest-kernel", b"vmlinuz-6.6.52-yougori"),
                artifact("guest-image", b"rootfs-2026.10.1-yougori"),
            ]),
        },
        Role::Targets,
        &[&targets],
    );
    let snapshot_file = Signer::file(
        &SnapshotMetadata {
            role: Role::Snapshot,
            version: MetadataVersion::new(3),
            expires,
            targets: targets_file
                .file_reference(MetadataVersion::new(3))
                .unwrap(),
        },
        Role::Snapshot,
        &[&snapshot],
    );
    let timestamp_payload = TimestampMetadata {
        role: Role::Timestamp,
        version: MetadataVersion::new(3),
        expires,
        snapshot: snapshot_file
            .file_reference(MetadataVersion::new(3))
            .unwrap(),
    };
    let revocation_file = Signer::file(
        &RevocationMetadata {
            role: Role::Revocation,
            version: MetadataVersion::new(2),
            issued: NOW,
            revoked: BTreeMap::from([(
                ContentKey::of(b"vmlinuz-6.1.0-retired"),
                "CVE-2026-0001: guest escape".to_owned(),
            )]),
        },
        Role::Revocation,
        &[&revocation],
    );
    vec![
        accepted(
            Role::Root,
            1,
            Signer::file(&root, Role::Root, &[&roots[0], &roots[1]]),
        ),
        accepted(
            Role::Timestamp,
            3,
            Signer::file(&timestamp_payload, Role::Timestamp, &[&timestamp]),
        ),
        accepted(Role::Snapshot, 3, snapshot_file),
        accepted(Role::Targets, 3, targets_file),
        accepted(Role::Revocation, 2, revocation_file),
        // A file is kept exactly as offered, without signatures too.
        accepted(
            Role::Timestamp,
            3,
            MetadataFile::unsigned(&timestamp_payload).unwrap(),
        ),
        TrustRecord::Pinned(PinnedKeys {
            keys: roots.iter().map(|signer| signer.key.key_id()).collect(),
            at: NOW,
        }),
        TrustRecord::Pinned(PinnedKeys {
            keys: BTreeSet::new(),
            at: NOW,
        }),
        TrustRecord::TornTailPastMark(TornTailPastMark {
            missing: SequenceRange::single(sequence(5)),
            marker: sequence(7),
            synced_through: Some(sequence(4)),
            at: NOW,
        }),
        TrustRecord::TornTailPastMark(TornTailPastMark {
            missing: SequenceRange::new(sequence(1), sequence(2)).unwrap(),
            marker: sequence(4),
            synced_through: None,
            at: NOW,
        }),
    ]
}

fn sequence(value: u64) -> EventSequence {
    EventSequence::new(value).unwrap()
}

/// Fails unless an accepted record keeps what its types' constructors check: a torn
/// tail's missing range runs forward, as `SequenceRange::new` requires.
fn record_invariants(record: &TrustRecord) -> Result<(), String> {
    if let TrustRecord::TornTailPastMark(torn) = record {
        let missing = torn.missing;
        ensure!(
            SequenceRange::new(missing.first(), missing.last()) == Some(missing),
            "a torn tail's missing range {missing} that runs backward was read"
        );
    }
    Ok(())
}

fn read(input: &[u8]) -> Result<TrustRecord, serde_json::Error> {
    serde_json::from_slice(input)
}

/// The seeds and the records they hold.
struct Corpus {
    seeds: Vec<Vec<u8>>,
    records: Vec<TrustRecord>,
}

fn corpus() -> Corpus {
    let records = records();
    let mut seeds: Vec<Vec<u8>> = records
        .iter()
        .map(|record| serde_json::to_vec(record).unwrap())
        .collect();
    seeds.push(serde_json::to_vec_pretty(&records[2]).unwrap());
    Corpus { seeds, records }
}

fn grammar(corpus: &Corpus) -> Grammar {
    let tokens: [&[u8]; 22] = [
        b"{",
        b"}",
        b"[",
        b"]",
        b",",
        b":",
        b"\"",
        b"null",
        b"true",
        b"-1",
        b"0.5",
        b"\"accepted\":",
        b"\"pinned\":",
        b"\"role\":\"root\",",
        b"\"role\":\"revocation\",",
        b"\"trusted\":true,",
        b"\"signatures\":[],",
        b"\"keys\":[],",
        b"\"version\":18446744073709551616,",
        b"\\u0000",
        b"1e3",
        b"A",
    ];
    let longest = corpus.seeds.iter().map(Vec::len).max().unwrap_or(0);
    Grammar {
        seeds: corpus.seeds.clone(),
        dictionary: tokens.iter().map(|token| token.to_vec()).collect(),
        limits: vec![0, 1, 2, 3, u64::from(u32::MAX), u64::MAX],
        fields: decimal_fields,
        max_len: longest + 512,
    }
}

fn check(input: &[u8], corpus: &Corpus) -> Verdict {
    let first = read(input);
    let same = match (&first, &read(input)) {
        (Ok(one), Ok(other)) => one == other,
        (Err(one), Err(other)) => one.to_string() == other.to_string(),
        _ => false,
    };
    ensure!(same, "two readings of one record differ");
    let record = match first {
        Ok(record) => record,
        Err(error) => return Ok(refusal_label(&error, KINDS)),
    };
    let written = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
    let again =
        read(&written).map_err(|error| format!("a written record does not read back: {error}"))?;
    ensure!(
        again == record,
        "a written record reads back as another record"
    );
    ensure!(
        serde_json::to_vec(&again).map_err(|error| error.to_string())? == written,
        "a written record does not write back to the same bytes"
    );
    let given: Value = serde_json::from_slice(input)
        .map_err(|error| format!("an accepted record is not JSON: {error}"))?;
    let kept = serde_json::to_value(&record).map_err(|error| error.to_string())?;
    ensure!(
        denotes(&given, &kept),
        "the record read is not what its JSON says; it writes back as {}",
        String::from_utf8_lossy(&written)
    );
    let seed = corpus.seeds.iter().any(|seed| seed.as_slice() == input);
    let deep =
        seed || (!corpus.records.contains(&record) && SplitMix64::for_input(input).one_in(8));
    if deep {
        refuses_edits(&kept, FREE, read)?;
    }
    let mut label = match &record {
        TrustRecord::Accepted(metadata) => format!("accepted:Accepted:{:?}", metadata.role),
        other => format!("accepted:{}", variant(&format!("{other:?}"))),
    };
    // The open finding below: counted here, failed only by its regression test.
    if record_invariants(&record).is_err() {
        label.push_str(":backward_range");
    }
    Ok(label)
}

/// Records that reach the refusal kinds of serde_json and the edges of acceptance.
const REGRESSIONS: &[Regression] = &[
    Regression {
        expect: "refused:Eof",
        input: b"",
    },
    Regression {
        expect: "refused:Syntax",
        input: b"{]",
    },
    Regression {
        expect: "refused:Syntax",
        input: b"null",
    },
    Regression {
        expect: "refused:Data:unknown_variant",
        input: b"{\"rejected\":{\"keys\":[],\"at\":1}}",
    },
    Regression {
        expect: "accepted:Pinned",
        input: b"{\"pinned\":{\"keys\":[],\"at\":1700000000}}",
    },
    Regression {
        expect: "refused:Data:unknown_field",
        input: b"{\"pinned\":{\"keys\":[],\"at\":1700000000,\"threshold\":2}}",
    },
    Regression {
        expect: "refused:Data:missing_field",
        input: b"{\"pinned\":{\"keys\":[]}}",
    },
    Regression {
        expect: "refused:Data:duplicate_field",
        input: b"{\"pinned\":{\"keys\":[],\"at\":1,\"at\":2}}",
    },
    Regression {
        expect: "refused:Data:invalid_type",
        input: b"{\"pinned\":{\"keys\":[],\"at\":1.5}}",
    },
    Regression {
        expect: "accepted:Accepted:Root",
        input: b"{\"accepted\":{\"role\":\"root\",\"version\":1,\"accepted_at\":1,\
                 \"file\":{\"signed\":{\"anything\":[1,2.5,null]},\"signatures\":[]}}}",
    },
    Regression {
        expect: "refused:Data:hex",
        input: b"{\"accepted\":{\"role\":\"root\",\"version\":1,\"accepted_at\":1,\
                 \"file\":{\"signed\":{},\"signatures\":[{\"key_id\":\
                 \"0000000000000000000000000000000000000000000000000000000000000000\",\
                 \"signature\":\"0g\"}]}}}",
    },
];

#[test]
fn mutated_trust_records_are_read_strictly() {
    let corpus = corpus();
    let run = Run {
        target: "trust_adapter::TrustRecord",
        seed: 0x00E0_1A00_0000_0005,
        iterations: ITERATIONS,
        regressions: REGRESSIONS,
    };
    let report = fuzz(run, &grammar(&corpus), |input| check(input, &corpus));
    assert_eq!(report.iterations, ITERATIONS);
    report.assert_reached(
        "trust_adapter::TrustRecord",
        &[
            "accepted:Accepted",
            "accepted:Pinned",
            "accepted:TornTailPastMark",
            "refused:Syntax",
            "refused:Data",
            "refused:Eof",
        ],
    );
}

/// Finding (E01Y), fixed in `79206ee`: `SequenceRange` derived its reader without the check
/// `SequenceRange::new` makes, so a torn tail whose missing range ran backward was read as
/// a valid record. No writer makes one, and the replay only compares the range with the
/// log's own gaps, which never run backward, so nothing is resumed from it; but the
/// strict reader keeps a value its type refuses. A fixed reader refuses the input.
const FINDINGS: &[Regression] = &[Regression {
    expect: "refused:Data",
    input: b"{\"torn_tail_past_mark\":{\"missing\":{\"first\":7,\"last\":5},\"marker\":8,\
             \"synced_through\":4,\"at\":0}}",
}];

#[test]
fn finding_a_backward_sequence_range_is_refused() {
    let corpus = corpus();
    let run = Run {
        target: "trust_adapter::TrustRecord finding",
        seed: 0x00E0_1A00_0000_0015,
        iterations: 0,
        regressions: FINDINGS,
    };
    fuzz(run, &grammar(&corpus), |input| {
        let label = check(input, &corpus)?;
        if let Ok(record) = read(input) {
            record_invariants(&record)?;
        }
        Ok(label)
    });
}
