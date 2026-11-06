//! Tests for `identify_build` and `verify_build`: CORE-08 records of a build's signed
//! components through the real signer, trust-root loader and verifiers, with disposable
//! keys and files in temporary directories.

use super::*;
use crate::foundation::report::{RunRecord, RUN_RECORD_SAMPLE_JSON};
use crate::foundation::signing::ComponentVerification;
use ring::signature::Ed25519KeyPair;
use std::io::Cursor;

/// The fixed calendar time of the build operations in these tests.
const NOW: &str = "2026-06-01T00:00:00Z";

struct Fixed(DateTime<Utc>);

impl TrustCalendar for Fixed {
    fn now(&self) -> DateTime<Utc> {
        self.0
    }
}

fn at(text: &str) -> DateTime<Utc> {
    text.parse().unwrap()
}

fn id(text: &str) -> RootKeyId {
    RootKeyId::new(text).unwrap()
}

fn parse(value: &Value) -> Result<Request> {
    serde_json::from_slice(&serde_json::to_vec(value).unwrap()).map_err(|error| error.to_string())
}

/// Runs a public request at [`NOW`] with no private input at all.
fn public(value: Value, directory: &Path) -> Result<Value> {
    execute_at(parse(&value)?, directory, &mut io::empty(), &Fixed(at(NOW)))
}

/// A disposable signing key and its publisher identity.
struct Signer {
    private: Vec<u8>,
    publisher: PublisherId,
}

impl Signer {
    fn new() -> Self {
        let private = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
            .unwrap()
            .as_ref()
            .to_vec();
        let publisher = SigningKey::from_pkcs8(&private)
            .unwrap()
            .public_key()
            .publisher_id();
        Self { private, publisher }
    }

    fn with_key(&self, value: Value, directory: &Path) -> Value {
        execute(
            parse(&value).unwrap(),
            directory,
            &mut Cursor::new(&self.private),
        )
        .unwrap()
    }

    /// This key's trust-root entry as `trust_roots` writes it, valid through 2026.
    fn root(&self, id: &str, classes: &[&str]) -> Value {
        let document = self.with_key(
            json!({"operation":"trust_roots","id":id,"classes":classes,
            "valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z"}),
            Path::new("."),
        );
        document["keys"][0].clone()
    }

    /// Writes `bytes` to `name` and this key's detached signature over it as `class` to
    /// `name.sig`, and returns the `identify_build` component naming both.
    fn component(&self, directory: &Path, name: &str, class: &str, bytes: &[u8]) -> Value {
        std::fs::write(directory.join(name), bytes).unwrap();
        let signature = self.with_key(
            json!({"operation":"sign_artifact","class":class,"artifact":name}),
            directory,
        );
        std::fs::write(directory.join(format!("{name}.sig")), signature.to_string()).unwrap();
        json!({"class":class, "publisher":self.publisher, "artifact":name,
            "signature_file":format!("{name}.sig")})
    }
}

fn revoked(mut root: Value, reason: &str) -> Value {
    root["revoked"] = json!({ "reason": reason });
    root
}

fn write_roots(directory: &Path, name: &str, keys: Vec<Value>) {
    std::fs::write(
        directory.join(name),
        json!({"format":1,"keys":keys}).to_string(),
    )
    .unwrap();
}

fn sample_run() -> RunRecord {
    RunRecord::from_json(RUN_RECORD_SAMPLE_JSON).unwrap()
}

fn build_of(run: &RunRecord) -> Value {
    json!({"plan":run.build.plan, "runner_build":run.build.runner_build,
        "runner_version":run.build.runner_version})
}

fn identify_request(roots: &str, build: &Value, components: Vec<Value>) -> Value {
    json!({"operation":"identify_build", "trust_roots_file":roots, "build":build,
        "components":components})
}

fn verify_request(roots: &str, record: &str, signatures: &[&str]) -> Value {
    let artifacts: Vec<&str> = signatures
        .iter()
        .map(|name| name.strip_suffix(".sig").unwrap_or(name))
        .collect();
    json!({"operation":"verify_build", "trust_roots_file":roots, "record_file":record,
        "artifact_files":artifacts, "signature_files":signatures})
}

#[test]
fn a_build_of_two_signed_classes_is_recorded_verified_and_joins_its_run() {
    let dir = tempfile::tempdir().unwrap();
    let (guest, helper) = (Signer::new(), Signer::new());
    write_roots(
        dir.path(),
        "roots.json",
        vec![
            guest.root("guest-2026", &["guest_image"]),
            helper.root("helper-2026", &["model_helper"]),
        ],
    );
    let components = vec![
        guest.component(
            dir.path(),
            "manifest.json",
            "guest_image",
            b"guest manifest",
        ),
        helper.component(
            dir.path(),
            "helper.bundle",
            "model_helper",
            b"helper bundle",
        ),
    ];
    let run = sample_run();
    let output = public(
        identify_request("roots.json", &build_of(&run), components),
        dir.path(),
    )
    .unwrap();

    // The output is the record itself, read back strictly, and joins the run record of
    // the same build only.
    let record = SignedBuildIdentity::from_json(&output.to_string()).unwrap();
    assert!(record.all_verified());
    assert!(record.describes(&run));
    let mut other = run.clone();
    other.build.runner_version = Label::new("another-build").unwrap();
    assert!(!record.describes(&other));

    // Each statement is the one the class's own verifier checks.
    let [manifest, bundle] = record.components() else {
        panic!("expected two components");
    };
    assert_eq!(
        manifest.statement(),
        &crate::sandbox::guest_image::signing_statement(&guest.publisher, b"guest manifest")
    );
    assert_eq!(
        bundle.statement(),
        &crate::model_memory::helpers::bundle_statement(&helper.publisher, b"helper bundle")
    );
    assert_eq!(
        (manifest.class(), bundle.class()),
        (ArtifactClass::GuestImage, ArtifactClass::ModelHelper)
    );
    assert_eq!(
        manifest.verification(),
        &ComponentVerification::Verified {
            key: id("guest-2026")
        }
    );
    assert_eq!(
        bundle.verification(),
        &ComponentVerification::Verified {
            key: id("helper-2026")
        }
    );
    assert!(record
        .components()
        .iter()
        .all(|component| component.checked_at() == at(NOW)));

    // Stored, it verifies again with the same signature files.
    std::fs::write(dir.path().join("build.json"), output.to_string()).unwrap();
    let report = public(
        verify_request(
            "roots.json",
            "build.json",
            &["manifest.json.sig", "helper.bundle.sig"],
        ),
        dir.path(),
    )
    .unwrap();
    assert_eq!(report["verification"], "signed_build_reverified");
    assert_eq!(report["all_verified"], true);
    assert_eq!(report["artifact_files_checked"], true);
    assert_eq!(report["build_authenticated"], false);
    assert_eq!(report["build"], json!(run.build));
    assert_eq!(report["checked_at"], json!(at(NOW)));
    let shown = report["components"].as_array().unwrap();
    assert_eq!(shown.len(), 2);
    for (component, shown) in record.components().iter().zip(shown) {
        assert_eq!(shown["statement"], json!(component.statement()));
        assert_eq!(shown["recorded"], json!(component.verification()));
        assert_eq!(shown["reverified"], shown["recorded"]);
    }
}

#[test]
fn refused_components_are_recorded_with_their_typed_outcomes_never_dropped() {
    let dir = tempfile::tempdir().unwrap();
    let (guest, helper, retired) = (Signer::new(), Signer::new(), Signer::new());
    let keys = |guest_root: Value| {
        vec![
            guest_root,
            helper.root("helper-2026", &["model_helper"]),
            revoked(retired.root("retired", &["model_helper"]), "key-compromise"),
        ]
    };
    write_roots(
        dir.path(),
        "roots.json",
        keys(guest.root("guest-2026", &["guest_image"])),
    );
    let components = vec![
        guest.component(
            dir.path(),
            "manifest.json",
            "guest_image",
            b"guest manifest",
        ),
        retired.component(dir.path(), "old.bundle", "model_helper", b"old bundle"),
        // The guest image key may not sign helper bundles.
        guest.component(dir.path(), "cross.bundle", "model_helper", b"cross bundle"),
        guest.component(
            dir.path(),
            "tampered.json",
            "guest_image",
            b"signed manifest",
        ),
    ];
    std::fs::write(dir.path().join("tampered.json"), b"edited manifest").unwrap();
    let build = build_of(&sample_run());
    let output = public(
        identify_request("roots.json", &build, components),
        dir.path(),
    )
    .unwrap();
    let record = SignedBuildIdentity::from_json(&output.to_string()).unwrap();
    let outcomes: Vec<_> = record
        .components()
        .iter()
        .map(|component| component.verification().clone())
        .collect();
    assert_eq!(
        outcomes,
        vec![
            ComponentVerification::Verified {
                key: id("guest-2026")
            },
            ComponentVerification::Revoked {
                key: id("retired"),
                reason: Label::new("key-compromise").unwrap()
            },
            ComponentVerification::ClassNotAllowed {
                key: id("guest-2026")
            },
            ComponentVerification::BadSignature {
                key: id("guest-2026")
            },
        ]
    );
    assert!(!record.all_verified());
    assert_eq!(record.verified().count(), 1);

    // A class no key of the roots may sign.
    write_roots(
        dir.path(),
        "guest-only.json",
        vec![guest.root("guest-2026", &["guest_image"])],
    );
    let bundle = helper.component(
        dir.path(),
        "helper.bundle",
        "model_helper",
        b"helper bundle",
    );
    let only = public(
        identify_request("guest-only.json", &build, vec![bundle]),
        dir.path(),
    )
    .unwrap();
    assert_eq!(
        SignedBuildIdentity::from_json(&only.to_string())
            .unwrap()
            .components()[0]
            .verification(),
        &ComponentVerification::NoKeysForClass {}
    );

    // After the owner revokes the guest image key, re-verification reports the change
    // beside the recorded outcome.
    write_roots(
        dir.path(),
        "revoked.json",
        keys(revoked(
            guest.root("guest-2026", &["guest_image"]),
            "rotated-out",
        )),
    );
    std::fs::write(dir.path().join("build.json"), output.to_string()).unwrap();
    let report = public(
        verify_request(
            "revoked.json",
            "build.json",
            &[
                "manifest.json.sig",
                "old.bundle.sig",
                "cross.bundle.sig",
                "tampered.json.sig",
            ],
        ),
        dir.path(),
    )
    .unwrap();
    assert_eq!(report["all_verified"], false);
    let shown = &report["components"];
    assert_eq!(
        shown[0]["recorded"],
        json!({"outcome":"verified","key":"guest-2026"})
    );
    assert_eq!(
        shown[0]["reverified"],
        json!({"outcome":"revoked","key":"guest-2026","reason":"rotated-out"})
    );
    assert_eq!(shown[1]["reverified"], shown[1]["recorded"]);
}

#[test]
fn duplicates_other_classes_and_inconsistent_input_refuse_the_request() {
    let dir = tempfile::tempdir().unwrap();
    let (guest, other) = (Signer::new(), Signer::new());
    write_roots(
        dir.path(),
        "roots.json",
        vec![guest.root("guest-2026", &["guest_image", "oci_layer"])],
    );
    let component = guest.component(dir.path(), "manifest.json", "guest_image", b"manifest");
    let build = build_of(&sample_run());
    let identify = |components: Vec<Value>| {
        public(
            identify_request("roots.json", &build, components),
            dir.path(),
        )
    };
    let output = identify(vec![component.clone()]).unwrap();

    // The same component twice, also as a copy of the same bytes, is refused.
    std::fs::copy(
        dir.path().join("manifest.json"),
        dir.path().join("copy.json"),
    )
    .unwrap();
    let mut copy = component.clone();
    copy["artifact"] = json!("copy.json");
    for duplicate in [component.clone(), copy] {
        let error = identify(vec![component.clone(), duplicate]).unwrap_err();
        assert!(error.contains("listed twice"), "{error}");
    }
    assert!(identify(vec![]).is_err());
    // A class whose verifier checks no content statement.
    let layer = guest.component(dir.path(), "layer", "oci_layer", b"layer");
    assert!(identify(vec![layer]).is_err());
    for (field, value) in [
        ("publisher", json!(other.publisher)),
        ("artifact", json!("missing")),
        ("signature_file", json!("manifest.json")),
        ("class", json!(3)),
        ("class", json!("unknown")),
        ("signature", json!("00")),
    ] {
        let mut bad = component.clone();
        bad[field] = value;
        assert!(identify(vec![bad]).is_err(), "{field}");
    }
    // Exactly one runner build source, and the trust roots must load.
    let mut both = build.clone();
    both["runner_build_file"] = json!("manifest.json");
    let mut neither = build.clone();
    neither.as_object_mut().unwrap().remove("runner_build");
    let mut extra = build.clone();
    extra["model"] = json!("another");
    for bad in [both, neither, extra] {
        let request = identify_request("roots.json", &bad, vec![component.clone()]);
        assert!(public(request, dir.path()).is_err());
    }
    let request = identify_request("missing.json", &build, vec![component.clone()]);
    assert!(public(request, dir.path()).is_err());

    // Re-verification takes one signature file per component, in order, by the recorded
    // publisher, and reads the record strictly.
    std::fs::write(dir.path().join("build.json"), output.to_string()).unwrap();
    let verify = |record: &str, signatures: &[&str]| {
        public(verify_request("roots.json", record, signatures), dir.path())
    };
    assert!(verify("build.json", &["manifest.json.sig"]).is_ok());
    assert!(verify("build.json", &[]).is_err());
    assert!(verify("build.json", &["manifest.json.sig", "manifest.json.sig"]).is_err());
    other.component(dir.path(), "other.json", "guest_image", b"manifest");
    assert!(verify("build.json", &["other.json.sig"]).is_err());
    let mut versioned = output.clone();
    versioned["schema_version"] = json!(2);
    let mut trusted = output.clone();
    trusted["trusted"] = json!(true);
    let mut doubled = output.clone();
    doubled["components"] = json!([output["components"][0], output["components"][0]]);
    let mut empty = output.clone();
    empty["components"] = json!([]);
    for (name, record, signatures) in [
        ("v2.json", versioned, vec!["manifest.json.sig"]),
        ("trusted.json", trusted, vec!["manifest.json.sig"]),
        (
            "doubled.json",
            doubled,
            vec!["manifest.json.sig", "manifest.json.sig"],
        ),
        ("empty.json", empty, vec![]),
    ] {
        std::fs::write(dir.path().join(name), record.to_string()).unwrap();
        assert!(verify(name, &signatures).is_err(), "{name}");
    }
}

#[test]
fn the_runner_build_can_be_the_sha256_of_an_actual_file() {
    let dir = tempfile::tempdir().unwrap();
    let guest = Signer::new();
    write_roots(
        dir.path(),
        "roots.json",
        vec![guest.root("guest-2026", &["guest_image"])],
    );
    let component = guest.component(dir.path(), "manifest.json", "guest_image", b"manifest");
    std::fs::write(dir.path().join("runner.exe"), b"abc").unwrap();
    let mut run = sample_run();
    let mut build = build_of(&run);
    build.as_object_mut().unwrap().remove("runner_build");
    build["runner_build_file"] = json!("runner.exe");
    let output = public(
        identify_request("roots.json", &build, vec![component]),
        dir.path(),
    )
    .unwrap();
    let record = SignedBuildIdentity::from_json(&output.to_string()).unwrap();
    // The FIPS 180-2 known answer for "abc".
    let expected =
        Digest::from_hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
            .unwrap();
    assert_eq!(record.build().runner_build, expected);
    assert!(!record.describes(&run));
    run.build.runner_build = expected;
    assert!(record.describes(&run));

    // Streamed in several buffers; a directory or a missing file is refused.
    let large = vec![7u8; 200_003];
    std::fs::write(dir.path().join("large"), &large).unwrap();
    assert_eq!(
        sha256_file(&dir.path().join("large")).unwrap(),
        Digest::from_bytes(<Sha256 as sha2::Digest>::digest(&large).into())
    );
    assert!(sha256_file(dir.path()).is_err());
    assert!(sha256_file(&dir.path().join("missing")).is_err());
}

#[test]
fn the_command_identifies_at_the_current_time_without_reading_private_input() {
    let dir = tempfile::tempdir().unwrap();
    let guest = Signer::new();
    let mut root = guest.root("guest", &["guest_image"]);
    root["valid_from"] = json!("2000-01-01T00:00:00Z");
    root["valid_until"] = json!("2100-01-01T00:00:00Z");
    write_roots(dir.path(), "roots.json", vec![root]);
    let component = guest.component(dir.path(), "manifest.json", "guest_image", b"manifest");
    let path = dir.path().join("request.json");
    let request = identify_request("roots.json", &build_of(&sample_run()), vec![component]);
    std::fs::write(&path, request.to_string()).unwrap();
    let mut input = Cursor::new(b"never read".to_vec());
    let mut output = Vec::new();
    let before = Utc::now();
    run(
        vec!["--request".into(), path.into_os_string()],
        &mut input,
        &mut output,
    )
    .unwrap();
    let after = Utc::now();
    assert_eq!(input.position(), 0);
    let record = SignedBuildIdentity::from_json(std::str::from_utf8(&output).unwrap()).unwrap();
    assert!(record.all_verified());
    let checked = record.components()[0].checked_at();
    assert!(before <= checked && checked <= after);
}

#[test]
fn rechecking_binds_the_file_and_class_but_does_not_authenticate_build_labels() {
    let dir = tempfile::tempdir().unwrap();
    let signer = Signer::new();
    // One publisher allowed in both classes must not let an edited record relabel
    // a guest-image signature as a helper-bundle signature.
    write_roots(
        dir.path(),
        "roots.json",
        vec![signer.root("both", &["guest_image", "model_helper"])],
    );
    let component = signer.component(dir.path(), "manifest.json", "guest_image", b"manifest");
    let original = public(
        identify_request("roots.json", &build_of(&sample_run()), vec![component]),
        dir.path(),
    )
    .unwrap();
    let request = verify_request("roots.json", "build.json", &["manifest.json.sig"]);
    std::fs::write(dir.path().join("build.json"), original.to_string()).unwrap();
    assert_eq!(
        public(request.clone(), dir.path()).unwrap()["all_verified"],
        true
    );

    let mut relabelled = original.clone();
    relabelled["components"][0]["class"] = json!("model_helper");
    std::fs::write(dir.path().join("build.json"), relabelled.to_string()).unwrap();
    assert!(public(request.clone(), dir.path())
        .unwrap_err()
        .contains("do not match"));

    std::fs::write(dir.path().join("build.json"), original.to_string()).unwrap();
    std::fs::write(dir.path().join("manifest.json"), b"MANIFEST").unwrap();
    assert!(public(request.clone(), dir.path())
        .unwrap_err()
        .contains("do not match"));
    std::fs::write(dir.path().join("manifest.json"), b"manifest").unwrap();

    let mut no_files = request.clone();
    no_files.as_object_mut().unwrap().remove("artifact_files");
    assert!(public(no_files, dir.path()).is_err());
    let mut too_few = request.clone();
    too_few["artifact_files"] = json!([]);
    assert!(public(too_few, dir.path()).is_err());

    let mut edited_build = original;
    edited_build["build"]["runner_version"] = json!("unsigned-label-change");
    std::fs::write(dir.path().join("build.json"), edited_build.to_string()).unwrap();
    let checked = public(request, dir.path()).unwrap();
    assert_eq!(checked["all_verified"], true);
    assert_eq!(checked["artifact_files_checked"], true);
    assert_eq!(checked["build_authenticated"], false);
}
