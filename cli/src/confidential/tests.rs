use super::*;

#[test]
fn shipped_policy_rejects_before_any_network_or_prompt_encryption() {
    assert!(Policy::load(None, now())
        .err()
        .unwrap()
        .contains("No prompt was sent"));
}

#[test]
fn encrypted_round_trip_excludes_plaintext_and_authenticates_both_directions() {
    let keys = RunnerKeys::generate().unwrap();
    let d = keys.descriptor(
        "nd_test".into(),
        "test/model".into(),
        "a".repeat(40),
        random().unwrap(),
        100,
    );
    // Only this private cfg(test) module constructs a VerifiedPeer without evidence.
    let peer = VerifiedPeer { descriptor: d };
    let (envelope,pending)=peer.prepare(json!({"model":"test/model","messages":[{"role":"user","content":"VERY PRIVATE PROMPT"}],"max_tokens":20}),101).unwrap();
    let wire = serde_json::to_string(&envelope).unwrap();
    assert!(!wire.contains("VERY PRIVATE PROMPT"));
    assert!(
        !String::from_utf8_lossy(&STANDARD.decode(&envelope.ciphertext).unwrap())
            .contains("VERY PRIVATE PROMPT")
    );
    assert_eq!(
        keys.open(&envelope, 102).unwrap()["messages"][0]["content"],
        "VERY PRIVATE PROMPT"
    );
    let other = RunnerKeys::generate().unwrap();
    assert!(other.open(&envelope, 102).is_err());
    let response = json!({"choices":[{"message":{"content":"VERY PRIVATE REPLY"}}]});
    let answer = keys.reply(&envelope, response.clone(), 10, 4).unwrap();
    assert!(!serde_json::to_string(&answer)
        .unwrap()
        .contains("VERY PRIVATE REPLY"));
    assert_eq!(pending.finish(answer).unwrap(), response);
}

#[test]
fn envelope_and_reply_cannot_be_swapped_tampered_or_replayed_after_expiry() {
    let keys = RunnerKeys::generate().unwrap();
    let peer = VerifiedPeer {
        descriptor: keys.descriptor(
            "nd_test".into(),
            "test/model".into(),
            "a".repeat(40),
            random().unwrap(),
            100,
        ),
    };
    let (mut envelope, pending) = peer
        .prepare(
            json!({"model":"test/model","messages":[{"role":"user","content":"secret"}]}),
            101,
        )
        .unwrap();
    envelope.reply_recipient = RunnerKeys::generate()
        .unwrap()
        .identity
        .to_public()
        .to_string();
    assert!(keys.open(&envelope, 102).is_err());
    assert!(keys.open(&envelope, 222).is_err());
    let mut reply = keys.reply(&envelope, json!({}), 0, 0).unwrap();
    reply.receipt.tokens_out = 100;
    assert!(pending.finish(reply).is_err());
}

#[test]
fn synthetic_signed_fixtures_require_nonce_images_key_binding_and_every_gpu() {
    // Public test JWTs are intentionally signed by a generated test-only RSA key.
    // No private key or test trust anchor ships in the production policy.
    let fixtures: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let policy: Policy = serde_json::from_value(fixtures["policy"].clone()).unwrap();
    let policy = VerifiedPolicy {
        policy,
        checked_at: fixtures["now"].as_u64().unwrap(),
    };
    let proof: Proof = serde_json::from_value(fixtures["good"].clone()).unwrap();
    let challenge = || Challenge {
        nonce: proof.descriptor.nonce.clone(),
        node: proof.descriptor.node_id.clone(),
        model: proof.descriptor.model.clone(),
    };
    let time = fixtures["now"].as_u64().unwrap();
    assert!(challenge()
        .verify(
            serde_json::from_value(fixtures["good"].clone()).unwrap(),
            &policy,
            time
        )
        .is_ok());
    for invalid in fixtures["bad"].as_array().unwrap() {
        assert!(
            challenge()
                .verify(
                    serde_json::from_value(invalid["proof"].clone()).unwrap(),
                    &policy,
                    time
                )
                .is_err(),
            "accepted {}",
            invalid["name"]
        );
    }
    let mut revoked = policy.clone();
    revoked
        .policy
        .revoked_kids
        .push(policy.policy.keys[0].kid.clone());
    assert!(challenge()
        .verify(
            serde_json::from_value(fixtures["good"].clone()).unwrap(),
            &revoked,
            time
        )
        .is_err());
    assert!(challenge()
        .verify(
            serde_json::from_value(fixtures["good"].clone()).unwrap(),
            &policy,
            time + 301
        )
        .is_err());
}

#[test]
fn operator_keys_cannot_substitute_for_the_independent_vendor_key_catalog() {
    let fixtures: Value = serde_json::from_str(include_str!("fixtures.json")).unwrap();
    let mut policy: Policy = serde_json::from_value(fixtures["policy"].clone()).unwrap();
    let key = &policy.keys[0];
    let catalog =
        json!({"keys":[{"kid":key.kid,"alg":key.alg,"use":"sig","kty":"RSA","n":key.n,"e":key.e}]});
    assert!(policy.retain_published_keys(&catalog).is_ok());
    let mut replaced = catalog;
    replaced["keys"][0]["n"] = json!("operator-controlled-key");
    assert!(policy.retain_published_keys(&replaced).is_err());
}
