//! Update roots from the foundation's trust-root file and the strict update
//! configuration: one class, one key per rotation chain, derived when used (VM-W45, plan
//! line 2668; §8.3, line 2455; VM-D13, line 3207). Two tests are the review's R18 scratch
//! cases, now refused.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use chrono::{DateTime, Utc};

use super::roots::pin;
use super::tests::{
    config, developer_profile, location, pinned_roots, trust_roots, trust_roots_json, Fixture,
    RootEntry, Signer, DAY, NOW,
};
use super::*;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::signing::{
    Ed25519PublicKey, KeyAlgorithm, RootKeyId, SharedTrustRoots, TrustRootError, TrustRoots,
};
use crate::sandbox::trust::{
    AssuranceProfile, KeyId, MetadataFile, MetadataVersion, PublicKey, ResolvedProfile, Role,
    RoleKeys, SchemeKind, SignatureFailure, UnixSeconds, UpdateClient,
};

fn before(seconds: u64) -> UnixSeconds {
    UnixSeconds::new(NOW.get() - seconds)
}

fn time(at: UnixSeconds) -> DateTime<Utc> {
    DateTime::from_timestamp(i64::try_from(at.get()).unwrap(), 0).unwrap()
}

fn ids(set: &RootSet) -> BTreeSet<KeyId> {
    set.keys().keys().copied().collect()
}

fn threshold(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

/// The three fixture roots, usable for runtime updates (`root-2` from exactly now),
/// beside keys that are not: revoked (seed 21), expired at exactly now (22), not yet
/// valid (23) and allowed OCI layers only (24).
fn mixed_trust_roots(fixture: &Fixture) -> TrustRoots {
    let mut entries = fixture.root_entries();
    entries[2].valid_from = NOW;
    let mut revoked = RootEntry::usable("revoked", &Signer::from_seed(21));
    revoked.revoked = true;
    let mut expired = RootEntry::usable("expired", &Signer::from_seed(22));
    expired.valid_until = NOW;
    let mut not_yet = RootEntry::usable("not-yet", &Signer::from_seed(23));
    not_yet.valid_from = NOW.plus_seconds(1);
    let mut oci = RootEntry::usable("oci-publisher", &Signer::from_seed(24));
    oci.classes = vec![ArtifactClass::OciLayer];
    entries.extend([revoked, expired, not_yet, oci]);
    trust_roots(&entries)
}

/// Custodian A's key `a` (fixture root 0) and its overlapping successor `a2` (root 1),
/// and custodian B's key `b` (root 2).
fn rotation_entries(fixture: &Fixture) -> Vec<RootEntry> {
    let mut a = RootEntry::usable("a", &fixture.roots[0]);
    a.valid_from = before(10 * DAY);
    a.valid_until = NOW.plus_seconds(DAY);
    let mut a2 = RootEntry::usable("a2", &fixture.roots[1]);
    a2.valid_until = NOW.plus_seconds(300 * DAY);
    a2.replaces = Some("a".to_owned());
    let mut b = RootEntry::usable("b", &fixture.roots[2]);
    b.valid_from = before(10 * DAY);
    vec![a, a2, b]
}

fn not_signed_by_pinned_roots(
    refused: Result<UpdateClient, BootstrapRefusal>,
) -> (BTreeSet<KeyId>, BTreeSet<KeyId>) {
    match refused {
        Err(BootstrapRefusal::NotSignedByPinnedRoots {
            failure: SignatureFailure::ThresholdNotMet { valid, unknown, .. },
        }) => (valid, unknown),
        other => panic!(
            "expected a pinned-threshold refusal, got {:?}",
            other.map(|_| ())
        ),
    }
}

#[test]
fn update_roots_are_the_runtime_update_keys_usable_now() {
    let fixture = Fixture::new();
    let pinned = pinned_roots(mixed_trust_roots(&fixture), 2, ResolvedProfile::PRODUCTION);
    assert_eq!(pinned.profile(), AssuranceProfile::Production);
    assert_eq!(pinned.config(), &config(2));
    assert_eq!(pinned.metadata_location(), &location());

    let set = pinned.at(NOW).unwrap();
    assert_eq!(
        set.public_keys(),
        fixture
            .roots
            .iter()
            .map(|signer| (signer.key_id(), signer.key.clone()))
            .collect::<BTreeMap<_, _>>()
    );
    assert_eq!(
        set.root_role(),
        &RoleKeys::new(fixture.roots.iter().map(Signer::key_id), 2)
    );
    // Each pinned key keeps its trust-root entry and validity window.
    let first = &set.keys()[&fixture.roots[0].key_id()];
    assert_eq!(first.root_key(), &RootKeyId::new("root-0").unwrap());
    assert_eq!(first.key(), &fixture.roots[0].key);
    assert_eq!(first.valid_from(), time(before(DAY)));
    assert_eq!(first.valid_until(), time(NOW.plus_seconds(365 * DAY)));
    // The pinned identities are the trust client's own, as the root metadata lists them.
    let root = fixture.root_metadata(1, fixture.expires);
    assert_eq!(root.role_keys(Role::Root).unwrap(), set.root_role());
    let client = pinned
        .bootstrap(production_registry(), &fixture.root_file(1), NOW)
        .unwrap();
    assert_eq!(client.trusted_versions().root, MetadataVersion::new(1));

    // A second earlier, the key expiring at now is usable and the one starting now is not.
    let earlier = pinned.at(before(1)).unwrap();
    assert_eq!(
        ids(&earlier),
        BTreeSet::from([
            fixture.roots[0].key_id(),
            fixture.roots[1].key_id(),
            Signer::from_seed(22).key_id(),
        ])
    );
}

#[test]
fn keys_of_other_classes_are_never_update_roots() {
    assert_eq!(UPDATE_ROOT_CLASS, ArtifactClass::RuntimeUpdate);
    let fixture = Fixture::new();
    let others: Vec<ArtifactClass> = ArtifactClass::ALL
        .into_iter()
        .filter(|class| *class != UPDATE_ROOT_CLASS)
        .collect();
    // A key for each other class, and one allowed every other class.
    let mut entries: Vec<RootEntry> = others
        .iter()
        .enumerate()
        .map(|(index, class)| {
            let seed = 100 + u8::try_from(index).unwrap();
            let mut entry = RootEntry::usable(&format!("other-{index}"), &Signer::from_seed(seed));
            entry.classes = vec![*class];
            entry
        })
        .collect();
    let mut every_other = RootEntry::usable("every-other", &fixture.roots[0]);
    every_other.classes = others;
    entries.push(every_other);
    let pinned = pinned_roots(trust_roots(&entries), 1, ResolvedProfile::PRODUCTION);
    assert_eq!(pinned.at(NOW), Err(RootsRefusal::NoRootKeys));
    // A root one of those keys signed does not start a client.
    assert_eq!(
        pinned
            .bootstrap(production_registry(), &fixture.root_file(1), NOW)
            .map(|_| ()),
        Err(BootstrapRefusal::Roots {
            reason: RootsRefusal::NoRootKeys
        })
    );

    // Beside them, only the keys allowed runtime updates are pinned, alone or with
    // other classes.
    let mut with_oci = RootEntry::usable("update-and-oci", &fixture.roots[1]);
    with_oci.classes = vec![ArtifactClass::OciLayer, ArtifactClass::RuntimeUpdate];
    entries.extend([with_oci, RootEntry::usable("update", &fixture.roots[2])]);
    let set = pinned_roots(trust_roots(&entries), 1, ResolvedProfile::PRODUCTION)
        .at(NOW)
        .unwrap();
    assert_eq!(
        ids(&set),
        BTreeSet::from([fixture.roots[1].key_id(), fixture.roots[2].key_id()])
    );
}

#[test]
fn a_rotation_pair_cannot_meet_the_threshold_alone() {
    // R18: custodian A's key and its overlapping successor met threshold 2 without B.
    let fixture = Fixture::new();
    let (a, a2, b) = (&fixture.roots[0], &fixture.roots[1], &fixture.roots[2]);
    let pinned = pinned_roots(
        trust_roots(&rotation_entries(&fixture)),
        2,
        ResolvedProfile::PRODUCTION,
    );
    // One key per chain: the newest usable one.
    assert_eq!(
        ids(&pinned.at(NOW).unwrap()),
        BTreeSet::from([a2.key_id(), b.key_id()])
    );

    // The review's root: naming a2 alone, signed by a and a2.
    let mut file =
        MetadataFile::unsigned(&fixture.root_metadata_with(&[a2], 1, 1, fixture.expires)).unwrap();
    a.sign(&mut file, Role::Root);
    a2.sign(&mut file, Role::Root);
    let (valid, unknown) =
        not_signed_by_pinned_roots(pinned.bootstrap(production_registry(), &file, NOW));
    assert_eq!(valid, BTreeSet::from([a2.key_id()]));
    assert_eq!(unknown, BTreeSet::from([a.key_id()]));

    // A root listing all three: a with a2 is one custodian; a2 with b is two.
    let (valid, _) = not_signed_by_pinned_roots(pinned.bootstrap(
        production_registry(),
        &fixture.root_signed_by(1, &[0, 1]),
        NOW,
    ));
    assert_eq!(valid, BTreeSet::from([a2.key_id()]));
    assert!(pinned
        .bootstrap(
            production_registry(),
            &fixture.root_signed_by(1, &[1, 2]),
            NOW
        )
        .is_ok());
    // During the overlap the old key no longer counts, so a with b fails closed.
    let (valid, _) = not_signed_by_pinned_roots(pinned.bootstrap(
        production_registry(),
        &fixture.root_signed_by(1, &[0, 2]),
        NOW,
    ));
    assert_eq!(valid, BTreeSet::from([b.key_id()]));
    // Before a2's window opens, a is the chain's key and a with b suffices.
    let earlier = before(2 * DAY);
    assert_eq!(
        ids(&pinned.at(earlier).unwrap()),
        BTreeSet::from([a.key_id(), b.key_id()])
    );
    assert!(pinned
        .bootstrap(
            production_registry(),
            &fixture.root_signed_by(1, &[0, 2]),
            earlier
        )
        .is_ok());
}

#[test]
fn a_rotation_chain_pins_its_newest_usable_key() {
    let fixture = Fixture::new();
    let (a, a2, b) = (&fixture.roots[0], &fixture.roots[1], &fixture.roots[2]);
    let a3 = Signer::from_seed(31);
    let mut entries = rotation_entries(&fixture);
    let mut third = RootEntry::usable("a3", &a3);
    third.valid_from = NOW.plus_seconds(10 * DAY);
    third.valid_until = NOW.plus_seconds(400 * DAY);
    third.replaces = Some("a2".to_owned());
    entries.push(third);
    let pinned = pinned_roots(trust_roots(&entries), 2, ResolvedProfile::PRODUCTION);
    for (at, expected) in [
        (before(5 * DAY), a.key_id()),
        (NOW, a2.key_id()),
        (NOW.plus_seconds(10 * DAY), a3.key_id()),
    ] {
        assert_eq!(
            ids(&pinned.at(at).unwrap()),
            BTreeSet::from([expected, b.key_id()])
        );
    }
    // Three valid keys now, but two custodians.
    assert_eq!(
        pinned_roots(trust_roots(&entries), 3, ResolvedProfile::PRODUCTION).at(NOW),
        Err(RootsRefusal::ThresholdAboveKeys {
            threshold: 3,
            keys: 2
        })
    );
    // A revoked newest key leaves the chain's newest key that may still vouch.
    entries[1].revoked = true;
    let pinned = pinned_roots(trust_roots(&entries), 2, ResolvedProfile::PRODUCTION);
    assert_eq!(
        ids(&pinned.at(NOW).unwrap()),
        BTreeSet::from([a.key_id(), b.key_id()])
    );
}

#[test]
fn a_pinned_key_stops_vouching_once_it_expires() {
    // R18: a key read while valid kept starting clients after it expired.
    let fixture = Fixture::new();
    let a = &fixture.roots[0];
    let mut entry = RootEntry::usable("a", a);
    entry.valid_until = NOW.plus_seconds(10);
    let pinned = pinned_roots(trust_roots(&[entry]), 1, ResolvedProfile::PRODUCTION);
    let mut file =
        MetadataFile::unsigned(&fixture.root_metadata_with(&[a], 1, 1, fixture.expires)).unwrap();
    a.sign(&mut file, Role::Root);
    assert!(pinned.bootstrap(production_registry(), &file, NOW).is_ok());
    for later in [NOW.plus_seconds(10), NOW.plus_seconds(DAY)] {
        assert_eq!(
            pinned
                .bootstrap(production_registry(), &file, later)
                .map(|_| ()),
            Err(BootstrapRefusal::Roots {
                reason: RootsRefusal::NoRootKeys
            })
        );
    }

    // Keys that lapse are dropped and the threshold is checked against the rest.
    let mut entries = fixture.root_entries();
    for entry in &mut entries[..2] {
        entry.valid_until = NOW.plus_seconds(10);
    }
    let pinned = pinned_roots(trust_roots(&entries), 2, ResolvedProfile::PRODUCTION);
    assert!(pinned
        .bootstrap(production_registry(), &fixture.root_file(1), NOW)
        .is_ok());
    assert_eq!(
        pinned
            .bootstrap(
                production_registry(),
                &fixture.root_file(1),
                NOW.plus_seconds(DAY)
            )
            .map(|_| ()),
        Err(BootstrapRefusal::Roots {
            reason: RootsRefusal::ThresholdAboveKeys {
                threshold: 2,
                keys: 1
            }
        })
    );
}

#[test]
fn a_reloaded_trust_root_file_reaches_the_next_bootstrap() {
    let fixture = Fixture::new();
    let shared = SharedTrustRoots::new(trust_roots(&fixture.root_entries()));
    let pinned = PinnedRoots::new(shared.clone(), config(2), ResolvedProfile::PRODUCTION);
    let copy = pinned.clone();
    assert!(pinned
        .bootstrap(
            production_registry(),
            &fixture.root_signed_by(1, &[0, 1]),
            NOW
        )
        .is_ok());

    // The owner revokes root-0 and reloads the file.
    let mut entries = fixture.root_entries();
    entries[0].revoked = true;
    shared.replace(trust_roots(&entries));
    let (valid, unknown) = not_signed_by_pinned_roots(pinned.bootstrap(
        production_registry(),
        &fixture.root_signed_by(1, &[0, 1]),
        NOW,
    ));
    assert_eq!(valid, BTreeSet::from([fixture.roots[1].key_id()]));
    assert_eq!(unknown, BTreeSet::from([fixture.roots[0].key_id()]));
    assert!(pinned
        .bootstrap(
            production_registry(),
            &fixture.root_signed_by(1, &[1, 2]),
            NOW
        )
        .is_ok());

    // A second revocation leaves the threshold unreachable, for every holder.
    entries[1].revoked = true;
    shared.replace(trust_roots(&entries));
    for roots in [&pinned, &copy] {
        assert_eq!(
            roots
                .bootstrap(
                    production_registry(),
                    &fixture.root_signed_by(1, &[1, 2]),
                    NOW
                )
                .map(|_| ()),
            Err(BootstrapRefusal::Roots {
                reason: RootsRefusal::ThresholdAboveKeys {
                    threshold: 2,
                    keys: 1
                }
            })
        );
    }
}

#[test]
fn a_pinned_key_has_the_catalogs_publisher_identity() {
    // One key is one publisher: the trust client's key id is the foundation's key
    // fingerprint, so the catalog and the update client name a key alike.
    let fixture = Fixture::new();
    let roots = mixed_trust_roots(&fixture);
    for trusted in roots.keys() {
        let key = PublicKey::new(
            scheme_for(trusted.algorithm()),
            trusted.public_key().as_bytes().to_vec(),
        );
        assert_eq!(key.key_id().digest(), trusted.public_key().fingerprint());
        assert_eq!(key.publisher_id(), trusted.publisher_id());
        assert_eq!(
            roots.key_for(&key.publisher_id()).map(|found| found.id()),
            Some(trusted.id())
        );
    }
    let set = fixture.pinned().at(NOW).unwrap();
    for (key_id, pinned) in set.keys() {
        let foundation = Ed25519PublicKey::from_bytes(pinned.key().material.as_bytes()).unwrap();
        assert_eq!(key_id.digest(), foundation.fingerprint());
        assert_eq!(pinned.key().publisher_id(), foundation.publisher_id());
    }
}

#[test]
fn the_trust_root_file_refuses_what_it_cannot_pin() {
    // The file format refuses an empty set, an unknown algorithm (the HMAC test scheme
    // included), one public key under two ids and a weak key before anything is pinned.
    let fixture = Fixture::new();
    assert_eq!(
        TrustRoots::from_json(r#"{"format": 1, "keys": []}"#),
        Err(TrustRootError::NoKeys)
    );
    let usable = RootEntry::usable("root-0", &fixture.roots[0]);
    for algorithm in ["hmac-sha256-test", "hmac_sha256_test", "ed448", "Ed25519"] {
        let json = trust_roots_json(std::slice::from_ref(&usable))
            .replace("\"ed25519\"", &format!("{algorithm:?}"));
        assert!(matches!(
            TrustRoots::from_json(&json),
            Err(TrustRootError::UnknownAlgorithm { .. })
        ));
    }
    let twice = [
        RootEntry::usable("x", &fixture.roots[0]),
        RootEntry::usable("y", &fixture.roots[0]),
    ];
    assert!(matches!(
        TrustRoots::from_json(&trust_roots_json(&twice)),
        Err(TrustRootError::DuplicatePublicKey { .. })
    ));
    let mut identity = [0u8; 32];
    identity[0] = 1;
    let weak = RootEntry {
        key: PublicKey::new(SchemeKind::Ed25519, identity.to_vec()),
        ..RootEntry::usable("weak", &fixture.roots[0])
    };
    assert!(matches!(
        TrustRoots::from_json(&trust_roots_json(&[weak])),
        Err(TrustRootError::MalformedPublicKey { .. })
    ));
}

#[test]
fn every_trust_root_algorithm_is_a_production_scheme() {
    assert_eq!(scheme_for(KeyAlgorithm::Ed25519), SchemeKind::Ed25519);
    for algorithm in KeyAlgorithm::ALL {
        let scheme = scheme_for(algorithm);
        assert!(scheme.production_grade());
        assert_eq!(scheme.tag(), algorithm.tag());
    }
}

#[test]
fn pinning_refuses_shared_material_and_test_schemes() {
    let fixture = Fixture::new();
    let entry = |id: &str, key: &PublicKey| {
        PinnedKey::new(
            RootKeyId::new(id).unwrap(),
            key.clone(),
            time(before(DAY)),
            time(NOW.plus_seconds(DAY)),
        )
    };
    let ed25519 = fixture.roots[0].key.clone();
    let as_hmac = PublicKey::new(
        SchemeKind::HmacSha256Test,
        ed25519.material.as_bytes().to_vec(),
    );
    // In every profile, a public Ed25519 key cannot double as an HMAC secret.
    assert_eq!(
        pin(
            [entry("ed", &ed25519), entry("hmac", &as_hmac)],
            threshold(1),
            developer_profile()
        ),
        Err(RootsRefusal::DuplicateKey {
            key_id: as_hmac.key_id(),
            same_as: ed25519.key_id(),
        })
    );
    assert_eq!(
        pin(
            [entry("ed", &ed25519), entry("hmac", &as_hmac)],
            threshold(1),
            ResolvedProfile::PRODUCTION
        ),
        Err(RootsRefusal::TestSchemeInProduction {
            key_id: as_hmac.key_id(),
            scheme: SchemeKind::HmacSha256Test,
        })
    );
    assert_eq!(
        pin(
            [entry("a", &ed25519), entry("b", &ed25519)],
            threshold(1),
            ResolvedProfile::PRODUCTION
        ),
        Err(RootsRefusal::DuplicateKey {
            key_id: ed25519.key_id(),
            same_as: ed25519.key_id(),
        })
    );
    // A distinct test-scheme key is pinned under the developer profile only.
    let hmac = PublicKey::new(SchemeKind::HmacSha256Test, b"shared-secret".to_vec());
    assert!(pin(
        [entry("ed", &ed25519), entry("hmac", &hmac)],
        threshold(2),
        developer_profile()
    )
    .is_ok());
    assert_eq!(
        pin(
            [entry("hmac", &hmac)],
            threshold(1),
            ResolvedProfile::PRODUCTION
        ),
        Err(RootsRefusal::TestSchemeInProduction {
            key_id: hmac.key_id(),
            scheme: SchemeKind::HmacSha256Test,
        })
    );
    // Nothing to pin, or too few keys for the threshold.
    assert_eq!(
        pin(Vec::new(), threshold(1), ResolvedProfile::PRODUCTION),
        Err(RootsRefusal::NoRootKeys)
    );
    assert_eq!(
        pin(
            [entry("ed", &ed25519)],
            threshold(2),
            ResolvedProfile::PRODUCTION
        ),
        Err(RootsRefusal::ThresholdAboveKeys {
            threshold: 2,
            keys: 1
        })
    );
}

#[test]
fn the_threshold_must_be_reachable_at_a_calendar_time() {
    let fixture = Fixture::new();
    let pinned = pinned_roots(mixed_trust_roots(&fixture), 4, ResolvedProfile::PRODUCTION);
    // Unusable keys do not count towards the threshold.
    assert_eq!(
        pinned.at(NOW),
        Err(RootsRefusal::ThresholdAboveKeys {
            threshold: 4,
            keys: 3
        })
    );
    // A time with no calendar date is refused, not read as some other time.
    let far = UnixSeconds::new(u64::MAX);
    assert_eq!(
        pinned.at(far),
        Err(RootsRefusal::TimeOutOfRange { at: far })
    );
}

#[test]
fn the_update_configuration_is_strict_and_versioned() {
    const LOCATION: &str = "https://yougori.com/releases/sandbox/trust";
    let document = |threshold: &str, location: &str| {
        format!(
            r#"{{"format": 1, "root_threshold": {threshold}, "metadata_location": "{location}"}}"#
        )
    };
    let parsed = UpdateTrustConfig::from_json(&document("2", LOCATION)).unwrap();
    assert_eq!(parsed, config(2));
    assert_eq!(parsed.root_threshold().get(), 2);
    assert_eq!(parsed.metadata_location(), &location());
    // The plan names no minimum, so 1 is read; requiring more is the owner's decision.
    assert_eq!(
        UpdateTrustConfig::from_json(&document("1", LOCATION)),
        Ok(config(1))
    );

    assert_eq!(
        UpdateTrustConfig::from_json(&document("0", LOCATION)),
        Err(UpdateTrustConfigError::ZeroThreshold)
    );
    let malformed = |text: &str| {
        assert!(
            matches!(
                UpdateTrustConfig::from_json(text),
                Err(UpdateTrustConfigError::Malformed { .. })
            ),
            "{text}"
        );
    };
    for threshold in ["-1", "2.5", "\"2\"", "4294967296", "null"] {
        malformed(&document(threshold, LOCATION));
    }
    for location in [
        "http://yougori.com/releases",
        "https://user:secret@yougori.com/releases",
        "https://yougori.com/releases?token=1",
        "https://yougori.com:8443/releases",
        "https://127.0.0.1/releases",
        "",
    ] {
        malformed(&document("2", location));
    }
    // Unknown, missing and repeated fields.
    malformed(&format!(
        r#"{{"format": 1, "root_threshold": 2, "metadata_location": "{LOCATION}", "minimum": 1}}"#
    ));
    malformed(r#"{"format": 1, "root_threshold": 2}"#);
    malformed(&format!(
        r#"{{"format": 1, "metadata_location": "{LOCATION}"}}"#
    ));
    malformed(&format!(
        r#"{{"root_threshold": 2, "metadata_location": "{LOCATION}"}}"#
    ));
    malformed(&format!(
        r#"{{"format": 1, "root_threshold": 1, "root_threshold": 2, "metadata_location": "{LOCATION}"}}"#
    ));
    malformed("[]");
    malformed("");
    // Another format version is refused for its version, whatever it contains.
    for text in [
        document("2", LOCATION).replace("\"format\": 1", "\"format\": 2"),
        r#"{"format": 2, "anything": true}"#.to_owned(),
    ] {
        assert_eq!(
            UpdateTrustConfig::from_json(&text),
            Err(UpdateTrustConfigError::UnsupportedFormat { found: 2 })
        );
    }
    let padded = format!(
        "{}{}",
        document("2", LOCATION),
        " ".repeat(MAX_UPDATE_TRUST_BYTES)
    );
    assert_eq!(
        UpdateTrustConfig::from_json(&padded),
        Err(UpdateTrustConfigError::TooLarge {
            found_bytes: padded.len(),
            max_bytes: MAX_UPDATE_TRUST_BYTES,
        })
    );
    assert_eq!(UPDATE_TRUST_FORMAT, 1);
}

#[test]
fn refusals_are_typed_and_explained() {
    let refusal = RootsRefusal::ThresholdAboveKeys {
        threshold: 4,
        keys: 3,
    };
    assert_eq!(
        serde_json::to_value(&refusal).unwrap(),
        serde_json::json!({"refusal": "threshold_above_keys", "threshold": 4, "keys": 3})
    );
    assert_eq!(
        refusal.to_string(),
        "the root threshold 4 exceeds the 3 usable root keys"
    );
    let bootstrap = BootstrapRefusal::Roots {
        reason: RootsRefusal::NoRootKeys,
    };
    assert_eq!(
        serde_json::to_value(&bootstrap).unwrap(),
        serde_json::json!({"refusal": "roots", "reason": {"refusal": "no_root_keys"}})
    );
    assert_eq!(
        bootstrap.to_string(),
        "no update roots: no trust-root key may be an update root now"
    );
    let registry = BootstrapRefusal::TestSchemeRegistered {
        scheme: SchemeKind::HmacSha256Test,
    };
    assert_eq!(
        serde_json::to_value(&registry).unwrap(),
        serde_json::json!({"refusal": "test_scheme_registered", "scheme": "hmac_sha256_test"})
    );
    assert!(registry.to_string().contains("production profile"));
    let config_error = UpdateTrustConfigError::UnsupportedFormat { found: 2 };
    assert_eq!(
        serde_json::to_value(&config_error).unwrap(),
        serde_json::json!({"refusal": "unsupported_format", "found": 2})
    );
    assert!(config_error.to_string().contains("format 2"));
}
