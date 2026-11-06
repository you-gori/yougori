//! Tests for the revocation floor: revocations kept across restarts, written before the
//! file that carries them is put in force, a torn, edited or unreadable floor failing
//! closed, a missing floor as a first run, revocations accumulating over files and
//! restarts whatever the trust-root file's location, and the floor in the status.

use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use super::tests_service::{
    at, document, id, key, publisher, revoked, standard_keys, FixedCalendar, RootsFile, UPDATES,
};
use super::*;
use crate::foundation::catalog::{ArtifactClass, PublisherId};
use crate::foundation::ids::{Digest, DigestBuilder};
use crate::foundation::report::Label;

/// A floor directory inside a temporary one, not created until the first revocation.
struct FloorDir {
    dir: tempfile::TempDir,
}

impl FloorDir {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn directory(&self) -> PathBuf {
        self.dir.path().join("data").join("trust")
    }

    fn path(&self) -> PathBuf {
        self.directory().join(REVOCATION_FLOOR_FILE)
    }

    fn open(&self) -> RevocationFloor {
        RevocationFloor::open(&self.directory())
    }

    fn bytes(&self) -> Vec<u8> {
        fs::read(self.path()).unwrap()
    }

    fn write(&self, bytes: &[u8]) {
        fs::create_dir_all(self.directory()).unwrap();
        fs::write(self.path(), bytes).unwrap();
    }
}

/// A service over `file`, written with `keys` first, with the floor in `floor`, at `when`:
/// one engine start.
fn start(file: &RootsFile, floor: &FloorDir, keys: Vec<Value>, when: &str) -> TrustRootService {
    file.write(&document(keys));
    TrustRootService::open_with_floor(file.location(), FixedCalendar::at(when), floor.open())
}

/// `standard_keys` with key 4 listed unrevoked, as before its revocation.
fn before_revocation() -> Vec<Value> {
    let mut keys = standard_keys();
    keys[3] = key(
        "compromised",
        4,
        &["runtime_update"],
        "2026-01-01",
        "2027-01-01",
    );
    keys
}

fn withdrawn(listed_as: &str, seed: u8, revoked_as: &str) -> LoadRefusal {
    LoadRefusal::RevocationWithdrawn {
        key: id(listed_as),
        publisher: publisher(seed),
        revoked_as: id(revoked_as),
    }
}

fn label(text: &str) -> Label {
    Label::new(text).unwrap()
}

/// Nothing is trusted: no roots in force and every class refusing.
fn assert_nothing_trusted(service: &TrustRootService) {
    assert_eq!(service.generation(), None);
    assert!(service.shared().is_none());
    let status = service.status();
    assert!(status
        .classes
        .iter()
        .all(|class| class.trust == ClassTrust::NoTrustRoots));
    for class in ArtifactClass::ALL {
        assert_eq!(
            service.policy(class),
            Err(ClassRefusal::NoTrustRoots { class })
        );
    }
}

fn replace(bytes: &[u8], from: &str, to: &str) -> Vec<u8> {
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains(from), "{from} not in {text}");
    text.replacen(from, to, 1).into_bytes()
}

/// A floor file with `body` under a header computed here, which pins the file's shape
/// and the digest's domain.
fn floor_file(body: &Value) -> Vec<u8> {
    let body = serde_json::to_vec_pretty(body).unwrap();
    let digest = DigestBuilder::new("yougori/signing/revocation-floor/v1")
        .str("revocation_floor")
        .u64(1)
        .bytes(&body)
        .finish();
    let mut bytes =
        serde_json::to_vec(&json!({ "file": "revocation_floor", "format": 1, "digest": digest }))
            .unwrap();
    bytes.push(b'\n');
    bytes.extend_from_slice(&body);
    bytes
}

fn entry(publisher: PublisherId, revoked_as: &str) -> Value {
    json!({
        "publisher": publisher,
        "revoked_as": revoked_as,
        "reason": "key-compromise",
        "first_seen": "2026-06-01T00:00:00Z",
    })
}

// Across restarts.

#[test]
fn a_revocation_kept_in_the_floor_refuses_an_older_file_after_a_restart() {
    let file = RootsFile::new();
    let floor = FloorDir::new();
    let service = start(&file, &floor, standard_keys(), "2026-06-01T00:00:00Z");
    assert_eq!(service.generation(), Some(1));
    let kept = service.floor().unwrap();
    assert_eq!(kept.len(), 1);
    assert_eq!(
        kept.revocation(&publisher(4)),
        Some(&FloorRevocation {
            publisher: publisher(4),
            revoked_as: id("compromised"),
            reason: label("key-compromise"),
            first_seen: at("2026-06-01T00:00:00Z"),
        })
    );
    // The floor on disk holds it.
    let on_disk = floor.open();
    assert_eq!(on_disk.problem(), None);
    assert_eq!(
        on_disk.revocations().collect::<Vec<_>>(),
        kept.revocations().collect::<Vec<_>>()
    );
    drop(service);

    // After a restart, an older file (a restored backup, an attacker's copy) that lists
    // key 4 unrevoked, under its own id or another, is refused, and nothing is trusted.
    let mut renamed = standard_keys();
    renamed[3] = key(
        "fresh-name",
        4,
        &["guest_image"],
        "2026-01-01",
        "2027-01-01",
    );
    for (keys, listed_as) in [
        (before_revocation(), "compromised"),
        (renamed, "fresh-name"),
    ] {
        let mut service = start(&file, &floor, keys, "2026-07-01T00:00:00Z");
        assert_nothing_trusted(&service);
        let refusal = withdrawn(listed_as, 4, "compromised");
        assert_eq!(service.status().last_refusal, Some(refusal.clone()));
        assert_eq!(
            service.reload(),
            ReloadOutcome::Refused {
                refusal,
                kept: None
            }
        );
        let shown = serde_json::to_value(service.status()).unwrap();
        assert_eq!(shown["last_refusal"]["refusal"], "revocation_withdrawn");
        let detail = shown["last_refusal"]["detail"].as_str().unwrap();
        assert!(detail.contains("while the engine is stopped"), "{detail}");
        assert!(!detail.contains("restart the engine"), "{detail}");
    }

    // A service without a floor keeps today's behaviour: its revocations hold for its
    // life only, so the same older file is accepted after a restart.
    file.write(&document(before_revocation()));
    let forgetful =
        TrustRootService::open(file.location(), FixedCalendar::at("2026-07-01T00:00:00Z"));
    assert_eq!(forgetful.generation(), Some(1));

    // A file that drops the key altogether is accepted; the floor is unchanged.
    let mut dropped = standard_keys();
    dropped.pop();
    let service = start(&file, &floor, dropped, "2026-07-01T00:00:00Z");
    assert_eq!(service.generation(), Some(1));
    assert_eq!(floor.open().len(), 1);
}

#[test]
fn the_floor_is_written_before_new_roots_are_in_force_and_a_failed_write_keeps_the_old_roots() {
    let file = RootsFile::new();
    let floor = FloorDir::new();
    let calendar = FixedCalendar::at("2026-06-01T00:00:00Z");
    file.write(&document(standard_keys()));
    let mut service =
        TrustRootService::open_with_floor(file.location(), calendar.clone(), floor.open());
    assert_eq!(service.generation(), Some(1));
    let in_force = service.shared().unwrap().current();
    let before = floor.bytes();

    // The owner revokes release-2026, but the floor cannot be written: the atomic write's
    // temporary name is taken by a directory.
    let blocker = floor.directory().join("revocation-floor.tmp");
    fs::create_dir(&blocker).unwrap();
    let mut keys = standard_keys();
    keys[0] = revoked(keys[0].clone(), "key-compromise");
    file.write(&document(keys));
    calendar.set("2026-06-02T00:00:00Z");
    let ReloadOutcome::Refused { refusal, kept } = service.reload() else {
        panic!("expected the reload refused");
    };
    assert_eq!(kept, Some(1));
    assert!(
        matches!(
            &refusal,
            LoadRefusal::Floor {
                error: FloorError::Io { action: "write", path, .. }
            } if *path == floor.path()
        ),
        "{refusal:?}"
    );
    // The roots in force stay, release-2026 still vouches, and the floor is as it was, in
    // memory and on disk.
    assert_eq!(service.generation(), Some(1));
    assert_eq!(service.shared().unwrap().current(), in_force);
    assert!(service
        .policy(ArtifactClass::RuntimeUpdate)
        .unwrap()
        .trusts(&publisher(1)));
    assert_eq!(service.floor().unwrap().len(), 1);
    assert_eq!(floor.bytes(), before);
    let status = service.status();
    assert_eq!(status.last_refusal, Some(refusal));
    let shown = serde_json::to_value(&status).unwrap();
    assert_eq!(shown["last_refusal"]["refusal"], "revocation_floor");

    // Once the floor can be written, the same file is accepted, and the floor on disk
    // holds the new revocation by the time the reload returns.
    fs::remove_dir(&blocker).unwrap();
    calendar.set("2026-06-03T00:00:00Z");
    assert!(matches!(
        service.reload(),
        ReloadOutcome::Applied { generation: 2, .. }
    ));
    assert!(!service
        .policy(ArtifactClass::RuntimeUpdate)
        .unwrap()
        .trusts(&publisher(1)));
    let on_disk = floor.open();
    assert_eq!(on_disk.len(), 2);
    assert_eq!(
        on_disk
            .revocation(&publisher(1))
            .map(|kept| kept.first_seen),
        Some(at("2026-06-03T00:00:00Z"))
    );
    assert_eq!(service.status().last_refusal, None);
}

// Failing closed.

#[test]
fn a_torn_edited_or_unreadable_floor_trusts_nothing_and_is_left_as_it_is() {
    let file = RootsFile::new();
    let floor = FloorDir::new();
    drop(start(
        &file,
        &floor,
        standard_keys(),
        "2026-06-01T00:00:00Z",
    ));
    let valid = floor.bytes();
    let newline = valid.iter().position(|byte| *byte == b'\n').unwrap();
    let header: Value = serde_json::from_slice(&valid[..newline]).unwrap();
    let mut other_digest = header.clone();
    other_digest["digest"] = json!(Digest::from_bytes([7; 32]));
    let mut forged = serde_json::to_vec(&other_digest).unwrap();
    forged.extend_from_slice(&valid[newline..]);

    let cases: Vec<(&str, Vec<u8>, Option<FloorProblem>)> = vec![
        ("empty", Vec::new(), None),
        ("torn in the header", valid[..newline / 2].to_vec(), None),
        (
            "torn in the body",
            valid[..valid.len() - 10].to_vec(),
            Some(FloorProblem::Digest),
        ),
        (
            "edited body",
            replace(&valid, "\"compromised\"", "\"compromisee\""),
            Some(FloorProblem::Digest),
        ),
        ("edited digest", forged, Some(FloorProblem::Digest)),
        (
            "another format",
            replace(&valid, "\"format\":1", "\"format\":2"),
            Some(FloorProblem::Format { found: 2 }),
        ),
        (
            "another file",
            replace(
                &valid,
                "\"file\":\"revocation_floor\"",
                "\"file\":\"floor\"",
            ),
            Some(FloorProblem::OtherFile),
        ),
    ];
    for (case, bytes, expected) in cases {
        floor.write(&bytes);
        let mut service = start(&file, &floor, standard_keys(), "2026-06-01T00:00:00Z");
        assert_nothing_trusted(&service);
        let Some(LoadRefusal::Floor {
            error: FloorError::Unusable { path, problem },
        }) = service.status().last_refusal
        else {
            panic!(
                "{case}: expected an unusable floor, got {:?}",
                service.status()
            );
        };
        assert_eq!(path, floor.path(), "{case}");
        match expected {
            Some(expected) => assert_eq!(problem, expected, "{case}"),
            None => assert!(
                matches!(problem, FloorProblem::Header { .. }),
                "{case}: {problem:?}"
            ),
        }
        // The status names the file and the remedy, and the roots' state points at it.
        let status = service.status();
        assert_eq!(
            status.floor.location,
            Some(floor.path().display().to_string())
        );
        let FloorState::Unusable { remedy, .. } = &status.floor.state else {
            panic!("{case}: expected an unusable floor state");
        };
        assert!(
            remedy.contains(&floor.path().display().to_string()),
            "{remedy}"
        );
        assert!(remedy.contains("while the engine is stopped"), "{remedy}");
        assert!(
            matches!(&status.roots, RootsState::NotLoaded { remedy: shown, .. } if shown == remedy),
            "{:?}",
            status.roots
        );
        // A reload is refused the same way; the file is never replaced, though the
        // trust-root file carries a revocation the floor would otherwise record.
        assert!(matches!(
            service.reload(),
            ReloadOutcome::Refused {
                refusal: LoadRefusal::Floor { .. },
                kept: None
            }
        ));
        assert_eq!(floor.bytes(), bytes, "{case}");
    }

    // A floor that cannot be read at all, here a directory under its name, fails closed
    // too, and so does a floor whose directory the caller could not name.
    fs::remove_file(floor.path()).unwrap();
    fs::create_dir(floor.path()).unwrap();
    let service = start(&file, &floor, standard_keys(), "2026-06-01T00:00:00Z");
    assert_nothing_trusted(&service);
    assert!(
        matches!(
            service.status().last_refusal,
            Some(LoadRefusal::Floor {
                error: FloorError::Io { action: "read", .. }
            })
        ),
        "{:?}",
        service.status().last_refusal
    );
    assert!(floor.path().is_dir());
    let service = TrustRootService::open_with_floor(
        file.location(),
        FixedCalendar::at("2026-06-01T00:00:00Z"),
        RevocationFloor::unavailable("the data folder is not known"),
    );
    assert_nothing_trusted(&service);
    let status = service.status();
    assert_eq!(status.floor.location, None);
    assert!(matches!(
        status.last_refusal,
        Some(LoadRefusal::Floor {
            error: FloorError::NoDirectory { .. }
        })
    ));
    assert!(matches!(status.floor.state, FloorState::Unusable { .. }));
}

#[test]
fn the_floor_file_is_read_strictly() {
    let floor = FloorDir::new();
    // A file of this exact shape reads: the header and digest are pinned here.
    floor.write(&floor_file(&json!({
        "revocations": [entry(publisher(4), "compromised")]
    })));
    let read = floor.open();
    assert_eq!(read.problem(), None);
    assert_eq!(
        read.revocations().collect::<Vec<_>>(),
        vec![&FloorRevocation {
            publisher: publisher(4),
            revoked_as: id("compromised"),
            reason: label("key-compromise"),
            first_seen: at("2026-06-01T00:00:00Z"),
        }]
    );
    assert_eq!(read.status().state, FloorState::Kept);

    // A body that matches its digest but breaks the rules is refused, typed.
    let mut unknown_field = entry(publisher(4), "compromised");
    unknown_field["note"] = json!("extra");
    let header_field = replace(
        &floor_file(&json!({ "revocations": [] })),
        "\"format\":1",
        "\"format\":1,\"extra\":1",
    );
    // Each case's exact problem, or the variant its debug form starts with when the
    // problem carries serde's message.
    let cases: Vec<(&str, Vec<u8>, Result<FloorProblem, &str>)> = vec![
        (
            "an unknown field",
            floor_file(&json!({ "revocations": [unknown_field] })),
            Err("Body"),
        ),
        ("an unknown header field", header_field, Err("Header")),
        (
            "the same key twice",
            floor_file(&json!({ "revocations": [
                entry(publisher(4), "compromised"),
                entry(publisher(4), "again"),
            ] })),
            Ok(FloorProblem::DuplicateKey {
                publisher: publisher(4),
            }),
        ),
        (
            "a bad key id",
            floor_file(&json!({ "revocations": [entry(publisher(4), "-bad")] })),
            Ok(FloorProblem::InvalidKeyId { index: 0 }),
        ),
        (
            "a bad reason",
            floor_file(&json!({ "revocations": [{
                "publisher": publisher(4),
                "revoked_as": "compromised",
                "reason": "C:/path",
                "first_seen": "2026-06-01T00:00:00Z",
            }] })),
            Err("Body"),
        ),
        ("no revocations list", floor_file(&json!({})), Err("Body")),
    ];
    for (case, bytes, expected) in cases {
        floor.write(&bytes);
        let read = floor.open();
        let Some(FloorError::Unusable { problem, .. }) = read.problem() else {
            panic!("{case}: expected an unusable floor, got {read:?}");
        };
        match expected {
            Ok(expected) => assert_eq!(problem, &expected, "{case}"),
            Err(variant) => assert!(
                format!("{problem:?}").starts_with(variant),
                "{case}: {problem:?}"
            ),
        }
        assert!(read.is_empty());
    }
}

#[test]
fn a_full_floor_refuses_a_file_with_a_new_revocation_and_keeps_the_roots() {
    let file = RootsFile::new();
    let floor = FloorDir::new();
    let filler: Vec<Value> = (0..MAX_FLOOR_REVOCATIONS)
        .map(|index| {
            let mut bytes = [0xee; 32];
            bytes[..8].copy_from_slice(&u64::try_from(index).unwrap().to_be_bytes());
            entry(
                PublisherId::from_key_fingerprint(Digest::from_bytes(bytes)),
                &format!("old-{index}"),
            )
        })
        .collect();
    floor.write(&floor_file(&json!({ "revocations": filler })));
    let mut dropped = standard_keys();
    dropped.pop();
    let mut service = start(&file, &floor, dropped, "2026-06-01T00:00:00Z");
    assert_eq!(service.generation(), Some(1));
    assert_eq!(service.status().floor.revocations, MAX_FLOOR_REVOCATIONS);

    file.write(&document(standard_keys()));
    assert_eq!(
        service.reload(),
        ReloadOutcome::Refused {
            refusal: LoadRefusal::Floor {
                error: FloorError::Full {
                    max: MAX_FLOOR_REVOCATIONS
                }
            },
            kept: Some(1)
        }
    );
    assert_eq!(floor.open().len(), MAX_FLOOR_REVOCATIONS);
}

// First run and accumulation.

#[test]
fn a_missing_floor_is_a_first_run() {
    let file = RootsFile::new();
    let floor = FloorDir::new();
    let mut without_revocations = standard_keys();
    without_revocations.pop();
    let mut service = start(&file, &floor, without_revocations, "2026-06-01T00:00:00Z");
    assert_eq!(service.generation(), Some(1));
    let status = service.status();
    assert_eq!(status.last_refusal, None);
    assert_eq!(
        status.floor,
        FloorStatus {
            location: Some(floor.path().display().to_string()),
            revocations: 0,
            state: FloorState::FirstRun,
        }
    );
    // Nothing is written, not even the directory, until there is a revocation.
    assert!(!floor.directory().exists());

    file.write(&document(standard_keys()));
    assert!(matches!(
        service.reload(),
        ReloadOutcome::Applied { generation: 2, .. }
    ));
    assert!(floor.path().is_file());
    let status = service.status();
    assert_eq!(status.floor.revocations, 1);
    assert_eq!(status.floor.state, FloorState::Kept);
}

#[test]
fn revocations_accumulate_across_files_and_restarts() {
    let file = RootsFile::new();
    let floor = FloorDir::new();

    // First run: key 4 is revoked.
    drop(start(
        &file,
        &floor,
        standard_keys(),
        "2026-06-01T00:00:00Z",
    ));

    // Second run: the file drops key 4 and retires the models key.
    let mut second = standard_keys();
    second.pop();
    second[2] = revoked(second[2].clone(), "retired");
    let service = start(&file, &floor, second.clone(), "2026-07-01T00:00:00Z");
    assert_eq!(service.generation(), Some(1));
    drop(service);

    // Third run: release-2026 is revoked too, and the models key is listed revoked under
    // another id; the floor keeps the id and time it first saw.
    let mut third = second;
    third[0] = revoked(third[0].clone(), "key-compromise");
    third[2]["id"] = json!("models-old");
    let service = start(&file, &floor, third.clone(), "2026-08-01T00:00:00Z");
    assert_eq!(service.generation(), Some(1));
    drop(service);

    let kept = floor.open();
    let seen: Vec<(PublisherId, &str, &str, DateTime<Utc>)> = kept
        .revocations()
        .map(|revocation| {
            (
                revocation.publisher,
                revocation.revoked_as.as_str(),
                revocation.reason.as_str(),
                revocation.first_seen,
            )
        })
        .collect();
    let mut expected = vec![
        (
            publisher(4),
            "compromised",
            "key-compromise",
            at("2026-06-01T00:00:00Z"),
        ),
        (
            publisher(3),
            "models",
            "retired",
            at("2026-07-01T00:00:00Z"),
        ),
        (
            publisher(1),
            "release-2026",
            "key-compromise",
            at("2026-08-01T00:00:00Z"),
        ),
    ];
    expected.sort_by_key(|entry| entry.0);
    assert_eq!(seen, expected);

    // Any later run refuses a file that lists any of the three unrevoked, from any of the
    // earlier runs, and accepts one that keeps them revoked.
    for (seed, listed_as, revoked_as, keys) in [
        (4, "compromised", "compromised", before_revocation()),
        (3, "models", "models", {
            let mut keys = third.clone();
            keys[2] = key("models", 3, &["model_weights"], "2026-01-01", "2027-01-01");
            keys
        }),
        (1, "release-2026", "release-2026", {
            let mut keys = third.clone();
            keys[0] = key("release-2026", 1, UPDATES, "2026-01-01", "2027-01-01");
            keys
        }),
    ] {
        let service = start(&file, &floor, keys, "2026-09-01T00:00:00Z");
        assert_nothing_trusted(&service);
        assert_eq!(
            service.status().last_refusal,
            Some(withdrawn(listed_as, seed, revoked_as))
        );
    }
    let service = start(&file, &floor, third, "2026-09-01T00:00:00Z");
    assert_eq!(service.generation(), Some(1));
    assert_eq!(floor.open().revocations().count(), 3);
}

#[test]
fn the_floor_applies_to_key_material_wherever_the_trust_root_file_is() {
    let floor = FloorDir::new();
    let first = RootsFile::new();
    drop(start(
        &first,
        &floor,
        standard_keys(),
        "2026-06-01T00:00:00Z",
    ));

    // The owner moves the trust roots to another location, and the file there lists the
    // revoked key 4 unrevoked under a new id for another class: refused.
    let elsewhere = RootsFile::new();
    assert_ne!(first.path(), elsewhere.path());
    let mut keys = standard_keys();
    keys[3] = key(
        "fresh-name",
        4,
        &["guest_image"],
        "2026-01-01",
        "2027-01-01",
    );
    let service = start(&elsewhere, &floor, keys, "2026-06-02T00:00:00Z");
    assert_nothing_trusted(&service);
    assert_eq!(
        service.status().last_refusal,
        Some(withdrawn("fresh-name", 4, "compromised"))
    );
}

// Status.

#[test]
fn the_status_shows_the_floor() {
    let file = RootsFile::new();
    let floor = FloorDir::new();
    let service = start(&file, &floor, standard_keys(), "2026-06-01T00:00:00Z");
    let status = service.status();
    assert_eq!(
        status.floor,
        FloorStatus {
            location: Some(floor.path().display().to_string()),
            revocations: 1,
            state: FloorState::Kept,
        }
    );
    let shown = serde_json::to_value(&status).unwrap();
    assert_eq!(
        shown["floor"],
        json!({
            "location": floor.path().display().to_string(),
            "revocations": 1,
            "state": "kept",
        })
    );

    // Without a floor the status says the revocations are not kept, and counts those
    // held in memory.
    let (service, _) = file.service(standard_keys(), "2026-06-01T00:00:00Z");
    let shown = serde_json::to_value(service.status()).unwrap();
    assert_eq!(
        shown["floor"],
        json!({ "location": null, "revocations": 1, "state": "not_kept" })
    );

    // A first run, and an unusable floor with its problem and remedy.
    let fresh = FloorDir::new();
    let mut without_revocations = standard_keys();
    without_revocations.pop();
    let service = start(&file, &fresh, without_revocations, "2026-06-01T00:00:00Z");
    assert_eq!(
        serde_json::to_value(service.status()).unwrap()["floor"]["state"],
        "first_run"
    );
    floor.write(b"not a floor");
    let service = start(&file, &floor, standard_keys(), "2026-06-01T00:00:00Z");
    let shown = serde_json::to_value(service.status()).unwrap();
    assert_eq!(shown["floor"]["state"], "unusable");
    assert_eq!(shown["floor"]["revocations"], 0);
    assert!(shown["floor"]["problem"]
        .as_str()
        .unwrap()
        .contains(&floor.path().display().to_string()));
    assert!(shown["floor"]["remedy"].as_str().unwrap().len() > 20);
    assert_eq!(shown["last_refusal"]["refusal"], "revocation_floor");
}
