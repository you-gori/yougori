//! The canonical encoding (§3.2; §3.3, line 529): domain separation between layers,
//! length-prefixed parts, and pinned digests so an accidental change of encoding fails.

use std::collections::BTreeSet;

use crate::foundation::ids::Digest;

use super::super::encoding::{Encoding, ALL_DOMAINS, ARTIFACT_DOMAIN, SOURCE_DOMAIN};
use super::super::layers::artifact_encoding;
use super::super::*;
use super::support::*;

#[test]
fn every_layer_has_its_own_well_formed_domain() {
    let unique: BTreeSet<&str> = ALL_DOMAINS.iter().copied().collect();
    assert_eq!(unique.len(), ALL_DOMAINS.len());
    for domain in ALL_DOMAINS {
        assert!(domain.starts_with("yougori/model-memory/identity/"));
        assert!(domain.ends_with("/v1"));
        assert!(domain.bytes().all(|byte| byte.is_ascii_lowercase()
            || byte.is_ascii_digit()
            || matches!(byte, b'/' | b'-' | b'_' | b'.')));
    }
}

#[test]
fn the_same_bytes_in_two_layers_give_different_digests() {
    let mut shared = Encoding::new();
    shared.item(&d("shared-part")).text("shared-text").u64(7);
    let digests: Vec<(&str, Digest)> = ALL_DOMAINS
        .iter()
        .map(|domain| (*domain, shared.finish(domain)))
        .collect();
    assert_all_distinct(&digests);

    // A real layer's canonical bytes give its identity only under its own domain.
    let canonical = source_spec().canonical().unwrap();
    assert_eq!(canonical.finish(SOURCE_DOMAIN), *source().digest());
    for domain in ALL_DOMAINS
        .iter()
        .filter(|domain| **domain != SOURCE_DOMAIN)
    {
        assert_ne!(canonical.finish(domain), *source().digest(), "{domain}");
    }

    // The artifact identity binds the manifest digest under its own domain, so it is
    // neither the bare manifest digest nor any other layer's digest of the same bytes.
    let manifest = d("manifest");
    let bound = artifact_encoding(&manifest);
    assert_eq!(bound.finish(ARTIFACT_DOMAIN), *artifact().digest());
    assert_ne!(*artifact().digest(), manifest);
    for domain in ALL_DOMAINS
        .iter()
        .filter(|domain| **domain != ARTIFACT_DOMAIN)
    {
        assert_ne!(bound.finish(domain), *artifact().digest(), "{domain}");
    }
}

#[test]
fn equal_inputs_give_equal_encodings() {
    assert_eq!(
        source_spec().canonical().unwrap(),
        source_spec().canonical().unwrap()
    );
    assert_eq!(logical_spec().canonical(), logical_spec().canonical());
    assert_eq!(
        execution_spec().canonical().unwrap(),
        execution_spec().canonical().unwrap()
    );
    assert_eq!(placement_spec().canonical(), placement_spec().canonical());
    assert_eq!(session_spec().canonical(), session_spec().canonical());
    assert_eq!(
        adapter_spec("org/a").canonical(),
        adapter_spec("org/a").canonical()
    );
    assert_eq!(kv_scope_spec().canonical(), kv_scope_spec().canonical());
    assert_eq!(
        graph_spec().canonical().unwrap(),
        graph_spec().canonical().unwrap()
    );
}

#[test]
fn adjacent_fields_never_run_together() {
    // Length prefixes keep ("vllm0", "29.0") apart from ("vllm", "029.0").
    let left = ExecutionSpec {
        runner: versioned("vllm0", "29.0"),
        ..execution_spec()
    };
    let right = ExecutionSpec {
        runner: versioned("vllm", "029.0"),
        ..execution_spec()
    };
    assert_ne!(left.identity().unwrap(), right.identity().unwrap());

    let joined = SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co/example-org"),
            repository: label("example-8b"),
        },
        ..source_spec()
    };
    let split = SourceSpec {
        location: SourceLocation::Repository {
            host: label("huggingface.co"),
            repository: label("example-org/example-8b"),
        },
        ..source_spec()
    };
    assert_ne!(joined.identity().unwrap(), split.identity().unwrap());
}

#[test]
fn identities_serialize_as_their_hexadecimal_digest() {
    let json = serde_json::to_string(&artifact()).unwrap();
    assert_eq!(json, format!("\"{}\"", artifact().digest().to_hex()));
    assert_eq!(artifact().to_string(), artifact().digest().to_hex());
    assert!(format!("{:?}", artifact()).starts_with("ArtifactIdentity("));
}

#[test]
fn encodings_are_pinned() {
    // Changing the encoding changes every stored identity; these values pin it.
    assert_eq!(
        TokenPrefix::from_token_ids(&[1, 2, 3]).digest().to_hex(),
        "f4e5d87df4fe82ba9dc35b7fee46187bbaaf14ca019b3e60f6ce86441b0018a8"
    );
    assert_eq!(
        artifact().to_string(),
        "18717e3da86b9705e0fb8a1d067f8e469650e0e7b476ea0226e847aa46f0fd29"
    );
    assert_eq!(
        source().to_string(),
        "6f6759986dd23c43f7d1743995db5154c6a57abcd806ab54cc5bc8733869f460"
    );
    assert_eq!(
        session_spec().identity().to_string(),
        "d4437a8440ac9acf1dd9c5a50bfc3eac9762328e92ebd5165e90fea67d494465"
    );
    // Device key digests and execution lease ids written as their u64 values.
    assert_eq!(
        placement_spec().identity().to_string(),
        "356c94ccc572179e9b7c7058ca07251275a6c08fef40e189eb4aaa7b6d64d9ed"
    );
}
