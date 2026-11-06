use super::*;
use crate::sandbox::trust::{MetadataVersion, RoleKeys};
use ring::signature::Ed25519KeyPair;
use std::collections::BTreeMap;
use std::io::Cursor;

fn key() -> Vec<u8> {
    Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
        .unwrap()
        .as_ref()
        .to_vec()
}

fn request(value: Value, directory: &Path, key: &[u8]) -> Result<Value> {
    let encoded = serde_json::to_vec(&value).unwrap();
    let request =
        serde_json::from_slice::<Request>(&encoded).map_err(|_| "invalid request".to_owned())?;
    execute(request, directory, &mut Cursor::new(key))
}

fn roots(key: &[u8]) -> Value {
    request(json!({"operation":"trust_roots","id":"release-2026", "classes":["model_helper","guest_image"],
        "valid_from":"2026-01-01T00:00:00Z", "valid_until":"2027-01-01T00:00:00Z"}), Path::new("."), key).unwrap()
}

fn artifact_verification(attestation: Value, roots: Value) -> Value {
    json!({"operation":"verify_artifact","artifact":"bundle", "class":"model_helper",
        "attestation":attestation, "trust_roots":roots, "at":"2026-06-01T00:00:00Z"})
}

#[test]
fn actual_artifact_bytes_key_class_window_and_revocation_are_checked() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bundle"), b"signed artifact").unwrap();
    let private = key();
    let root = roots(&private);
    let signature = request(
        json!({"operation":"sign_artifact","artifact":"bundle","class":"model_helper"}),
        dir.path(),
        &private,
    )
    .unwrap();
    // Exactly the detached envelope the guest manifest reader already accepts.
    let _: crate::sandbox::guest_image::ManifestSignature =
        serde_json::from_value(signature.clone()).unwrap();
    let valid = artifact_verification(signature, root);
    let verified = request(valid.clone(), dir.path(), &[]).unwrap();
    assert_eq!(
        verified["content_key"],
        json!(ContentKey::of(b"signed artifact"))
    );
    assert_eq!(verified["length_bytes"], 15);
    for (pointer, value) in [
        ("/class", json!("guest_image")),
        ("/at", json!("2027-01-01T00:00:00Z")),
        ("/at", json!("2025-12-31T00:00:00Z")),
        ("/trust_roots", roots(&key())),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(request(bad, dir.path(), &[]).is_err(), "{pointer}");
    }
    let mut revoked = valid.clone();
    revoked["trust_roots"]["keys"][0]["revoked"] = json!({"reason":"retired"});
    assert!(request(revoked, dir.path(), &[]).is_err());
    std::fs::write(dir.path().join("bundle"), b"SIGNED artifact").unwrap();
    assert!(request(valid, dir.path(), &[]).is_err());
}

#[test]
fn streaming_identity_matches_the_canonical_key_for_empty_and_large_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("artifact");
    for data in [vec![], vec![42; 200_003]] {
        std::fs::write(&path, &data).unwrap();
        assert_eq!(
            identify(&path).unwrap(),
            (ContentKey::of(&data), data.len() as u64)
        );
    }
    assert!(identify(dir.path()).is_err());
    assert!(identify(&dir.path().join("missing")).is_err());
}

#[test]
fn trust_root_authoring_and_pkcs8_v1_work_without_private_output() {
    // Standard PKCS#8 v1 Ed25519 seed-only representation (also used by OpenSSL).
    let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
    der.extend_from_slice(&[73; 32]);
    let public = request(json!({"operation":"public_key"}), Path::new("."), &der).unwrap();
    assert_eq!(public["algorithm"], "ed25519");
    assert_eq!(public["publisher"], public["metadata_key_id"]);
    assert!(!public.to_string().contains(&hex::encode(&der)));
    let root = roots(&der);
    assert!(TrustRoots::from_json(&root.to_string()).is_ok());
    for classes in [
        json!([]),
        json!(["unknown"]),
        json!(["model_helper", "model_helper"]),
    ] {
        assert!(request(
            json!({"operation":"trust_roots","id":"release-2026","classes":classes,
            "valid_from":"2026-01-01T00:00:00Z","valid_until":"2027-01-01T00:00:00Z"}),
            Path::new("."),
            &der
        )
        .is_err());
    }
}

fn metadata_root(offline: &[Vec<u8>], online: &[Vec<u8>]) -> RootMetadata {
    let public = |key: &Vec<u8>| {
        PublicKey::new(
            SchemeKind::Ed25519,
            SigningKey::from_pkcs8(key)
                .unwrap()
                .public_key()
                .as_bytes()
                .to_vec(),
        )
    };
    let keys: BTreeMap<_, _> = offline
        .iter()
        .chain(online)
        .map(public)
        .map(|p| (p.key_id(), p))
        .collect();
    let roles = Role::ALL
        .into_iter()
        .map(|role| {
            let selected = if role.is_online() { online } else { offline };
            (
                role,
                RoleKeys::new(
                    selected.iter().map(public).map(|k| k.key_id()),
                    selected.len() as u32,
                ),
            )
        })
        .collect();
    RootMetadata {
        role: Role::Root,
        version: MetadataVersion::FIRST,
        expires: UnixSeconds::new(1000),
        keys,
        roles,
    }
}

fn sign_metadata(document: Value, role: &str, key: &[u8]) -> Result<Value> {
    request(
        json!({"operation":"sign_metadata","role":role,"document":document,"at":100}),
        Path::new("."),
        key,
    )
}

#[test]
fn existing_metadata_threshold_checks_accept_each_role_and_distinct_cosigners() {
    let offline = vec![key(), key()];
    let online = vec![key(), key()];
    let root = metadata_root(&offline, &online);
    let reference = json!({"version":1,"length_bytes":12,"digest":Digest::from_bytes([42;32])});
    let bodies = [
        json!(root),
        json!({"role":"timestamp","version":1,"expires":900,"snapshot":reference}),
        json!({"role":"snapshot","version":1,"expires":900,"targets":reference}),
        json!({"role":"targets","version":1,"expires":900,"targets":{}}),
        json!({"role":"revocation","version":1,"issued":100,"revoked":{}}),
    ];
    for body in bodies {
        let name = body["role"].as_str().unwrap();
        let keys = if role(name).unwrap().is_online() {
            &online
        } else {
            &offline
        };
        let unsigned = json!({"signed":body,"signatures":[]});
        let once = sign_metadata(unsigned.clone(), name, &keys[0]).unwrap();
        let verify = |document: Value| {
            request(
                json!({"operation":"verify_metadata","role":name,
            "document":document,"trusted_root":root,"at":100}),
                Path::new("."),
                &[],
            )
        };
        assert!(
            verify(once.clone()).is_err(),
            "one key must not satisfy a threshold of two"
        );
        assert!(
            sign_metadata(once.clone(), name, &keys[0]).is_err(),
            "duplicate signer refused"
        );
        let twice = sign_metadata(once, name, &keys[1]).unwrap();
        assert_eq!(twice["signed"], unsigned["signed"]);
        assert_eq!(
            verify(twice.clone()).unwrap()["verification"],
            "metadata_threshold_only"
        );
        let mut tampered = twice;
        tampered["signed"]["version"] = json!(2);
        assert!(verify(tampered).is_err());
    }
}

#[test]
fn metadata_authoring_refuses_wrong_role_expiry_bad_version_and_test_roots() {
    let private = key();
    let valid =
        json!({"signed":{"role":"targets","version":1,"expires":200,"targets":{}},"signatures":[]});
    assert!(sign_metadata(valid.clone(), "snapshot", &private).is_err());
    for (field, value) in [
        ("expires", json!(100)),
        ("version", json!(0)),
        ("extra", json!(true)),
    ] {
        let mut bad = valid.clone();
        bad["signed"][field] = value;
        assert!(sign_metadata(bad, "targets", &private).is_err());
    }
    let mut root = json!(metadata_root(&[key()], &[key()]));
    let first = root["keys"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap()
        .clone();
    root["keys"][first]["scheme"] = json!("hmac_sha256_test");
    assert!(request(
        json!({"operation":"verify_metadata","role":"targets","document":valid,
        "trusted_root":root,"at":100}),
        Path::new("."),
        &[]
    )
    .is_err());
}

#[test]
fn command_rejects_malformed_input_without_echoing_secrets_or_writing_output() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("request.json");
    for text in [
        r#"{"operation":0}"#,
        r#"{"operation":"public_key","operation":"public_key"}"#,
        r#"{"operation":"public_key","secret":"do-not-echo-this"}"#,
        r#"{"operation":"sign_artifact","class":0,"artifact":"missing"}"#,
        r#"{"operation":"sign_metadata","role":"targets","at":100,"document":{"signed":{"role":"targets","version":1,"version":2},"signatures":[]}}"#,
    ] {
        std::fs::write(&path, text).unwrap();
        let mut output = Vec::new();
        let err = run(
            vec!["--request".into(), path.as_os_str().to_owned()],
            &mut Cursor::new(b"do-not-echo-this"),
            &mut output,
        )
        .unwrap_err();
        assert!(!err.contains("do-not-echo-this"));
        assert!(output.is_empty());
    }
    std::fs::write(&path, r#"{"operation":"public_key"}"#).unwrap();
    assert!(run(
        vec!["--request".into(), path.into_os_string()],
        &mut Cursor::new(vec![42; MAX_PRIVATE_KEY_BYTES + 1]),
        &mut Vec::new()
    )
    .is_err());
}

#[test]
fn command_resolves_artifact_relative_to_request_and_writes_consumer_envelope() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bundle"), b"guest manifest bytes").unwrap();
    let path = dir.path().join("request.json");
    std::fs::write(
        &path,
        r#"{"operation":"sign_artifact","class":"guest_image","artifact":"bundle"}"#,
    )
    .unwrap();
    let mut output = Vec::new();
    run(
        vec!["--request".into(), path.into_os_string()],
        &mut Cursor::new(key()),
        &mut output,
    )
    .unwrap();
    let _: crate::sandbox::guest_image::ManifestSignature =
        serde_json::from_slice(&output).unwrap();
    assert_eq!(output.last(), Some(&b'\n'));
}

#[test]
fn a_helper_bundle_is_built_from_public_inputs_and_signs_as_a_model_helper() {
    use crate::model_memory::helpers::HelperBundle;
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("src")).unwrap();
    std::fs::write(
        dir.path().join("src/gpu_optimizer.py"),
        b"VERSION = '1.0.0'\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("src/util.py"), b"def f(): pass\n").unwrap();
    let build = json!({"operation":"build_helper_bundle","helper":"gpu-optimizer","version":"1.0.0",
        "abi":{"major":1,"minor":0},"runners":[{"backend":"transformers","version":"5.18.0"}],
        "entry":"gpu_optimizer.py","output":"gpu-optimizer.yghelper",
        "files":[{"path":"gpu_optimizer.py","source":"src/gpu_optimizer.py"},{"path":"util.py","source":"src/util.py"}]});
    // No private input is read: an empty key is fine.
    let built = request(build.clone(), dir.path(), &[]).unwrap();
    assert_eq!(built["built"], "helper_bundle");
    assert_eq!(built["files"], 2);
    let bytes = std::fs::read(dir.path().join("gpu-optimizer.yghelper")).unwrap();
    assert_eq!(built["length_bytes"], bytes.len());
    assert_eq!(built["content_key"], json!(ContentKey::of(&bytes)));
    let bundle = HelperBundle::decode(&bytes).unwrap();
    assert_eq!(bundle.manifest().helper().as_str(), "gpu-optimizer");
    assert_eq!(bundle.manifest().entry().as_str(), "gpu_optimizer.py");
    assert_eq!(bundle.manifest().runners().len(), 1);
    assert_eq!(bundle.entry().unwrap(), b"VERSION = '1.0.0'\n");

    // The bundle signs and verifies as any model_helper artifact.
    let private = key();
    let root = roots(&private);
    let signature = request(
        json!({"operation":"sign_artifact","artifact":"gpu-optimizer.yghelper","class":"model_helper"}),
        dir.path(),
        &private,
    )
    .unwrap();
    let mut verification = artifact_verification(signature, root);
    verification["artifact"] = json!("gpu-optimizer.yghelper");
    assert_eq!(
        request(verification, dir.path(), &[]).unwrap()["length_bytes"],
        bytes.len()
    );

    // Refusals: an unknown backend, an entry the files do not hold, a missing source, an
    // unknown field.
    for (pointer, value) in [
        ("/runners/0/backend", json!("cuda")),
        ("/entry", json!("missing.py")),
        ("/files/1/source", json!("src/absent.py")),
    ] {
        let mut bad = build.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(request(bad, dir.path(), &[]).is_err(), "{pointer}");
    }
    let mut extra = build.clone();
    extra["signing_key"] = json!("never");
    assert!(request(extra, dir.path(), &[]).is_err());
}
