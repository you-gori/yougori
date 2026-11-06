//! Tests for CORE-08 signed component identity: every outcome comes from a verification,
//! is recorded with its typed reason, reads back strictly, and joins a run record by its
//! build while the version-3 run records stay readable.

use serde_json::{json, Value};

use super::tests_service::{at, document, id, publisher, revoked, sign, standard_keys, RootsFile};
use super::*;
use crate::foundation::catalog::ArtifactClass;
use crate::foundation::ids::{digest, ContentKey, Digest};
use crate::foundation::report::{
    BuildIdentity, Label, ReportError, RunRecord, RUN_RECORD_SAMPLE_JSON, SCHEMA_VERSION,
};

fn update_statement(seed: u8, bytes: &[u8]) -> Digest {
    content_statement(
        &publisher(seed),
        ArtifactClass::RuntimeUpdate,
        &ContentKey::of(bytes),
        u64::try_from(bytes.len()).unwrap(),
    )
}

fn roots() -> TrustRoots {
    TrustRoots::from_json(&document(standard_keys())).unwrap()
}

fn sample_build() -> BuildIdentity {
    RunRecord::from_json(RUN_RECORD_SAMPLE_JSON).unwrap().build
}

#[test]
fn a_signed_component_records_the_verification_it_ran() {
    let class = ArtifactClass::RuntimeUpdate;
    let statement = update_statement(1, b"update");
    let signature = sign(1, statement.as_bytes());
    let when = at("2026-06-01T00:00:00Z");
    let component =
        SignedComponent::check(&roots(), class, &publisher(1), statement, &signature, when);
    assert!(component.is_verified());
    assert_eq!(component.class(), class);
    assert_eq!(component.publisher(), &publisher(1));
    assert_eq!(component.statement(), &statement);
    assert_eq!(component.checked_at(), when);
    assert_eq!(
        component.verification(),
        &ComponentVerification::Verified {
            key: id("release-2026")
        }
    );
    assert_eq!(component.verification().key(), Some(&id("release-2026")));

    // The kept statement verifies again with the signature, and only with it.
    assert_eq!(component.reverify(&roots(), &signature, when), component);
    let mut tampered = signature.clone();
    tampered[0] ^= 0x01;
    assert_eq!(
        component.reverify(&roots(), &tampered, when).verification(),
        &ComponentVerification::BadSignature {
            key: id("release-2026")
        }
    );
    // A signature over the raw bytes, not the statement, is refused.
    assert!(!SignedComponent::check(
        &roots(),
        class,
        &publisher(1),
        statement,
        &sign(1, b"update"),
        when
    )
    .is_verified());
}

#[test]
fn every_refusal_is_recorded_with_its_typed_reason() {
    let class = ArtifactClass::RuntimeUpdate;
    let when = at("2026-06-01T00:00:00Z");
    let check = |seed: u8, class: ArtifactClass, when| {
        let statement = content_statement(&publisher(seed), class, &ContentKey::of(b"c"), 1);
        SignedComponent::check(
            &roots(),
            class,
            &publisher(seed),
            statement,
            &sign(seed, statement.as_bytes()),
            when,
        )
        .verification()
        .clone()
    };
    assert_eq!(
        check(9, class, when),
        ComponentVerification::UnknownPublisher {}
    );
    assert_eq!(
        check(4, class, when),
        ComponentVerification::Revoked {
            key: id("compromised"),
            reason: Label::new("key-compromise").unwrap()
        }
    );
    // The model-weights key 3 may not sign updates, which other keys may.
    assert_eq!(
        check(3, class, when),
        ComponentVerification::ClassNotAllowed { key: id("models") }
    );
    assert_eq!(
        check(2, class, when),
        ComponentVerification::NotYetValid {
            key: id("release-2027"),
            valid_from: at("2026-12-01T00:00:00Z")
        }
    );
    assert_eq!(
        check(1, class, at("2027-01-01T00:00:00Z")),
        ComponentVerification::Expired {
            key: id("release-2026"),
            valid_until: at("2027-01-01T00:00:00Z")
        }
    );
    // No key of the roots may sign model helpers at all.
    assert_eq!(
        check(1, ArtifactClass::ModelHelper, when),
        ComponentVerification::NoKeysForClass {}
    );
    for refused in [
        ComponentVerification::UnknownPublisher {},
        ComponentVerification::NoKeysForClass {},
        ComponentVerification::NoTrustRoots {},
    ] {
        assert!(!refused.is_verified());
        assert_eq!(refused.key(), None);
    }
}

#[test]
fn the_service_identifies_under_the_roots_in_force() {
    let file = RootsFile::new();
    let (mut service, calendar) = file.service(standard_keys(), "2026-06-01T00:00:00Z");
    let class = ArtifactClass::RuntimeUpdate;
    let bytes = b"runtime update";
    let manifest = crate::foundation::catalog::ImportManifest::describe(
        bytes,
        std::num::NonZeroU64::new(8).unwrap(),
    );
    let content = crate::foundation::catalog::ContentDescriptor {
        scope: crate::foundation::catalog::Scope::Host,
        class,
        content_key: manifest.content_key,
        length_bytes: manifest.true_length_bytes,
        manifest_digest: manifest.digest(),
    };
    let statement = manifest_statement(&publisher(1), class, &content.manifest_digest);
    let signature = sign(1, statement.as_bytes());
    let component = service.identify_content(
        StatementBinding::Manifest,
        &content,
        &publisher(1),
        &signature,
    );
    assert!(component.is_verified());
    assert_eq!(component.statement(), &statement);
    assert_eq!(component.checked_at(), at("2026-06-01T00:00:00Z"));
    // The content statement is another statement: the manifest signature does not cover it.
    assert!(!service
        .identify_content(
            StatementBinding::Content,
            &content,
            &publisher(1),
            &signature
        )
        .is_verified());

    // After the owner revokes the key, the same signature is recorded as refused.
    let mut keys = standard_keys();
    keys[0] = revoked(keys[0].clone(), "key-compromise");
    file.write(&document(keys));
    assert!(matches!(service.reload(), ReloadOutcome::Applied { .. }));
    calendar.set("2026-07-01T00:00:00Z");
    let later = service.identify(class, &publisher(1), statement, &signature);
    assert!(matches!(
        later.verification(),
        ComponentVerification::Revoked { key, .. } if *key == id("release-2026")
    ));
    assert_eq!(later.checked_at(), at("2026-07-01T00:00:00Z"));
}

#[test]
fn components_read_back_strictly() {
    let when = at("2026-06-01T00:00:00Z");
    let statement = update_statement(1, b"update");
    let verified = SignedComponent::check(
        &roots(),
        ArtifactClass::RuntimeUpdate,
        &publisher(1),
        statement,
        &sign(1, statement.as_bytes()),
        when,
    );
    let refused = SignedComponent::check(
        &roots(),
        ArtifactClass::RuntimeUpdate,
        &publisher(4),
        statement,
        &sign(4, statement.as_bytes()),
        when,
    );
    for component in [&verified, &refused] {
        let text = serde_json::to_string(component).unwrap();
        assert_eq!(
            &serde_json::from_str::<SignedComponent>(&text).unwrap(),
            component
        );
    }
    let shown = serde_json::to_value(&verified).unwrap();
    assert_eq!(
        shown,
        json!({
            "class": "runtime_update",
            "publisher": publisher(1).to_string(),
            "statement": statement.to_hex(),
            "checked_at": "2026-06-01T00:00:00Z",
            "verification": { "outcome": "verified", "key": "release-2026" }
        })
    );
    let refused_shown = serde_json::to_value(&refused).unwrap();
    assert_eq!(
        refused_shown["verification"],
        json!({ "outcome": "revoked", "key": "compromised", "reason": "key-compromise" })
    );
    let empty = serde_json::to_value(ComponentVerification::NoTrustRoots {}).unwrap();
    assert_eq!(empty, json!({ "outcome": "no_trust_roots" }));

    // Unknown fields, unknown outcomes and malformed key ids are refused.
    let refuse = |value: Value| {
        assert!(
            serde_json::from_value::<SignedComponent>(value.clone()).is_err(),
            "{value}"
        )
    };
    let mut extra = shown.clone();
    extra["signature"] = json!("00");
    refuse(extra);
    let mut extra_in_outcome = shown.clone();
    extra_in_outcome["verification"]["trusted"] = json!(true);
    refuse(extra_in_outcome);
    let mut extra_in_empty = shown.clone();
    extra_in_empty["verification"] = json!({ "outcome": "no_trust_roots", "key": "release-2026" });
    refuse(extra_in_empty);
    let mut unknown_outcome = shown.clone();
    unknown_outcome["verification"] = json!({ "outcome": "trusted_anyway" });
    refuse(unknown_outcome);
    let mut bad_key = shown.clone();
    bad_key["verification"]["key"] = json!("../release");
    refuse(bad_key);
    let mut missing = shown.clone();
    missing.as_object_mut().unwrap().remove("checked_at");
    refuse(missing);
}

#[test]
fn the_signed_build_identity_joins_its_run_and_reads_only_its_schema_version() {
    let when = at("2026-06-01T00:00:00Z");
    let build = sample_build();
    let statements = [
        update_statement(1, b"runtime"),
        update_statement(1, b"kernel"),
    ];
    let components: Vec<SignedComponent> = statements
        .iter()
        .map(|statement| {
            SignedComponent::check(
                &roots(),
                ArtifactClass::RuntimeUpdate,
                &publisher(1),
                *statement,
                &sign(1, statement.as_bytes()),
                when,
            )
        })
        .collect();
    let record = SignedBuildIdentity::new(build.clone(), components.clone()).unwrap();
    assert!(record.all_verified());
    assert_eq!(record.verified().count(), 2);
    assert_eq!(record.build(), &build);
    assert_eq!(record.components(), components.as_slice());

    // The version-3 run records stay readable, unchanged, and the record joins them by
    // their build.
    let run = RunRecord::from_json(RUN_RECORD_SAMPLE_JSON).unwrap();
    assert!(record.describes(&run));
    let mut other_run = run.clone();
    other_run.build.runner_version = Label::new("another-build").unwrap();
    assert!(!record.describes(&other_run));

    let text = serde_json::to_string(&record).unwrap();
    assert_eq!(SignedBuildIdentity::from_json(&text), Ok(record.clone()));
    assert_eq!(
        serde_json::from_str::<SignedBuildIdentity>(&text).unwrap(),
        record
    );
    let json: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(json["schema_version"], SCHEMA_VERSION);

    // Another version is refused for its version, typed, before its body is read.
    for other in [u64::from(SCHEMA_VERSION) - 1, u64::from(SCHEMA_VERSION) + 1] {
        let mut versioned = json.clone();
        versioned["schema_version"] = other.into();
        versioned.as_object_mut().unwrap().remove("components");
        assert_eq!(
            SignedBuildIdentity::from_json(&versioned.to_string()),
            Err(SignedBuildError::Report(
                ReportError::UnsupportedSchemaVersion { found: other }
            ))
        );
    }
    // Text that is not a record is located, never quoted.
    let error = SignedBuildIdentity::from_json("a private prompt").unwrap_err();
    assert!(matches!(
        error,
        SignedBuildError::Report(ReportError::Malformed { line: 1, .. })
    ));
    assert!(!error.to_string().contains("prompt"));
    let mut extra = json.clone();
    extra["trusted"] = json!(true);
    assert!(matches!(
        SignedBuildIdentity::from_json(&extra.to_string()),
        Err(SignedBuildError::Report(ReportError::Malformed { .. }))
    ));

    // One component per class and statement, and a bounded number of them; the same
    // checks apply when read back.
    let duplicate = vec![components[0].clone(), components[0].clone()];
    let refusal = SignedBuildError::DuplicateComponent {
        class: ArtifactClass::RuntimeUpdate,
        statement: statements[0],
    };
    assert_eq!(
        SignedBuildIdentity::new(build.clone(), duplicate),
        Err(refusal.clone())
    );
    let mut doubled = json.clone();
    doubled["components"] = json!([json["components"][0], json["components"][0]]);
    assert_eq!(
        SignedBuildIdentity::from_json(&doubled.to_string()),
        Err(refusal)
    );
    assert!(serde_json::from_value::<SignedBuildIdentity>(doubled).is_err());
    let many: Vec<SignedComponent> = (0..=MAX_SIGNED_COMPONENTS)
        .map(|index| {
            let statement = update_statement(1, format!("component {index}").as_bytes());
            SignedComponent::check(
                &roots(),
                ArtifactClass::RuntimeUpdate,
                &publisher(1),
                statement,
                &[],
                when,
            )
        })
        .collect();
    assert_eq!(
        SignedBuildIdentity::new(build.clone(), many),
        Err(SignedBuildError::TooManyComponents {
            found: MAX_SIGNED_COMPONENTS + 1,
            max: MAX_SIGNED_COMPONENTS
        })
    );

    // A refused component is listed as refused, never dropped.
    let unsigned = SignedComponent::check(
        &roots(),
        ArtifactClass::RuntimeUpdate,
        &publisher(1),
        update_statement(1, b"unsigned"),
        &[],
        when,
    );
    let mixed = SignedBuildIdentity::new(build, vec![components[0].clone(), unsigned]).unwrap();
    assert!(!mixed.all_verified());
    assert_eq!(mixed.verified().count(), 1);
    assert_eq!(mixed.components().len(), 2);
}

/// The schema version and the digest of a signed build identity's compact JSON, so its
/// format cannot drift silently: a change bumps the report's schema version.
const PINNED_SIGNED_BUILD: (u32, &str) = (
    3,
    "124be7154bc2a959e8c022a56bad393b99ccec7437745c7c59b051cb05a2d8e7",
);

#[test]
fn the_signed_build_identity_format_is_pinned_to_the_schema_version() {
    let when = at("2026-06-01T00:00:00Z");
    let statement = update_statement(1, b"runtime");
    let verified = SignedComponent::check(
        &roots(),
        ArtifactClass::RuntimeUpdate,
        &publisher(1),
        statement,
        &sign(1, statement.as_bytes()),
        when,
    );
    let refused = SignedComponent::check(
        &roots(),
        ArtifactClass::GuestImage,
        &publisher(2),
        statement,
        &sign(2, statement.as_bytes()),
        when,
    );
    let record = SignedBuildIdentity::new(sample_build(), vec![verified, refused]).unwrap();
    let compact = serde_json::to_vec(&record).unwrap();
    let pinned = digest("yougori/report/golden/v1", &[&compact]).to_hex();
    assert_eq!(
        (SCHEMA_VERSION, pinned.as_str()),
        PINNED_SIGNED_BUILD,
        "the signed build identity format changed: bump SCHEMA_VERSION and re-pin"
    );
}
