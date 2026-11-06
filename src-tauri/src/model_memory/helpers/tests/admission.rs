//! G08 item 2: bundles are admitted only through the catalog under the `model_helper`
//! class, trusted only through the configured roots; unsigned, tampered, revoked-key and
//! incompatible bundles are refused or quarantined with a typed reason. The last test
//! connects admission, rollout and runner pins over one catalog.

use super::*;
use crate::foundation::catalog::{
    Checkpoint, FailureReason, ImportManifest, ImportRefusal, ImportRequest, ImportSource,
    ImportStart, ImportStatus, IntegrityFailure, ObjectMetadata, ObjectRole, ObjectStatus, Proceed,
    SourceError, SourceIdentity, TrustBasis, TrustClaim, TrustRefusal,
};
use crate::foundation::signing::{content_statement, Ed25519Error, KeyRefusal, RootKeyId};

fn key_id(text: &str) -> RootKeyId {
    RootKeyId::new(text).unwrap()
}

fn v120() -> Vec<u8> {
    encoded(version(1, 2, 0), HelperAbi::new(1, 0))
}

fn signature_refusal(result: Result<AdmittedHelper, HelperRefusal>) -> KeyRefusal {
    match result {
        Err(HelperRefusal::Signature { refusal }) => refusal,
        other => panic!("expected a signature refusal, got {other:?}"),
    }
}

struct MemorySource {
    identity: SourceIdentity,
    bytes: Vec<u8>,
}

impl ImportSource for MemorySource {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        Ok(u64::try_from(self.bytes.len()).unwrap())
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes).unwrap().min(self.bytes.len());
        let available = &self.bytes[start..];
        let count = available.len().min(buffer.len());
        buffer[..count].copy_from_slice(&available[..count]);
        Ok(count)
    }
}

/// Interrupts an import before its first extent is fetched.
struct InterruptFirstExtent;

impl ImportControl for InterruptFirstExtent {
    fn proceed(&mut self, at: Checkpoint) -> Proceed {
        match at {
            Checkpoint::Extent { .. } => Proceed::Interrupt,
            Checkpoint::Stage { .. } => Proceed::Continue,
        }
    }
}

#[test]
fn a_signed_compatible_bundle_is_admitted_pinned_and_opened() {
    let mut fixture = Fixture::new();
    let bytes = v120();
    let admitted = fixture.admit(&bytes, Some(1)).unwrap();
    assert!(admitted.newly_published);
    assert_eq!(admitted.key, key_id("helpers-2026"));
    assert_eq!(admitted.manifest.version(), version(1, 2, 0));
    let pin = &admitted.pin;
    assert_eq!(pin.helper, helper_id());
    assert_eq!(pin.version, version(1, 2, 0));
    assert_eq!(pin.abi, HelperAbi::new(1, 0));
    assert_eq!(pin.runners, BTreeSet::from([vllm(), llama()]));
    assert_eq!(pin.bundle, ContentKey::of(&bytes));
    assert_eq!(pin.length_bytes, u64::try_from(bytes.len()).unwrap());
    assert_eq!(pin.publisher, publisher(1));
    assert_eq!(
        pin.object,
        ObjectId::new(&Scope::Host, ArtifactClass::ModelHelper, pin.bundle)
    );

    // One catalog object of the helper class, trusted for its publisher.
    let catalog = &fixture.catalog;
    assert_eq!(
        catalog.status(&Scope::Host, pin.object),
        ObjectStatus::Published
    );
    assert_eq!(
        catalog.find(&Scope::Host, HELPER_CLASS, pin.bundle),
        Some(pin.object)
    );
    assert_eq!(
        catalog.find(&Scope::Host, ArtifactClass::RuntimeUpdate, pin.bundle),
        None
    );
    let metadata = catalog.private_metadata(&Scope::Host, pin.object).unwrap();
    assert_eq!(metadata.class, HELPER_CLASS);
    assert_eq!(metadata.role, ObjectRole::Original);
    assert_eq!(
        metadata.trust,
        TrustBasis::Publisher {
            publisher: publisher(1)
        }
    );
    assert_eq!(fixture.admission.check_pin(catalog, pin), Ok(()));

    // The loader gets exactly the pinned files.
    let opened = fixture.open(pin).unwrap();
    assert_eq!(opened, bundle_at(version(1, 2, 0), HelperAbi::new(1, 0)));
    assert_eq!(opened.entry(), Some(ENTRY_SOURCE));

    // The same bundle again pins the same version; its claim was checked again.
    let again = fixture.admit(&bytes, Some(1)).unwrap();
    assert!(!again.newly_published);
    assert_eq!(again.pin, admitted.pin);

    // A pin reads back strictly, and every field is part of its identity.
    let text = serde_json::to_string(pin).unwrap();
    let read: HelperPin = serde_json::from_str(&text).unwrap();
    assert_eq!(read.id(), pin.id());
    let mut extra: Value = serde_json::from_str(&text).unwrap();
    extra["extra"] = json!(1);
    assert!(serde_json::from_value::<HelperPin>(extra).is_err());
    let mut other_version = pin.clone();
    other_version.version = version(1, 2, 1);
    let mut other_runners = pin.clone();
    other_runners.runners.remove(&llama());
    let mut other_publisher = pin.clone();
    other_publisher.publisher = publisher(4);
    for other in [other_version, other_runners, other_publisher] {
        assert_ne!(other.id(), pin.id());
    }
}

#[test]
fn the_helper_policy_is_the_trust_roots_policy_for_the_class() {
    // Helpers have their own catalog class, which the trust-root file names.
    assert_eq!(HELPER_CLASS.tag(), "model_helper");
    assert_eq!(
        serde_json::to_value(HELPER_CLASS).unwrap(),
        json!("model_helper")
    );
    assert!(ArtifactClass::ALL.contains(&HELPER_CLASS));
    let fixture = Fixture::new();
    let policy = helper_policy(&fixture.roots.current());
    assert!(policy.trusts(&publisher(1)));
    assert!(policy.trusts(&publisher(4)));
    assert!(!policy.trusts(&publisher(2)), "a runtime-update key");
    assert!(!policy.trusts(&publisher(3)), "a revoked key");
    assert!(!policy.accepts_user_selected());
    assert_eq!(
        fixture.catalog.config().trust.get(&HELPER_CLASS),
        Some(&policy)
    );
}

#[test]
fn an_unsigned_bundle_is_refused_by_the_catalog() {
    let mut fixture = Fixture::new();
    let bytes = v120();
    assert_eq!(fixture.admit(&bytes, None), Err(HelperRefusal::Unsigned));
    assert!(fixture.catalog.objects(&Scope::Host).is_empty());
    // The refusal is the catalog's own: a checksum is never trust.
    let checksum = FailureReason::Refused {
        refusal: ImportRefusal::Trust {
            refusal: TrustRefusal::ChecksumIsNotTrust {
                class: HELPER_CLASS,
            },
        },
    };
    assert!(fixture
        .catalog
        .failures()
        .any(|failure| failure.class == HELPER_CLASS && failure.reason == checksum));
}

#[test]
fn a_tampered_bundle_or_signature_is_refused_before_anything_is_published() {
    let mut fixture = Fixture::new();
    let bytes = v120();

    // A file changed after its manifest pinned it.
    let mut tampered = bytes.clone();
    let last = tampered.len() - 2;
    tampered[last] ^= 0x20;
    match fixture.admit(&tampered, Some(1)) {
        Err(HelperRefusal::Tampered {
            path: changed,
            expected,
            found,
        }) => {
            assert_eq!(changed, path("lib/util.py"));
            assert_eq!(expected, ContentKey::of(UTIL_SOURCE));
            assert_ne!(found, expected);
        }
        other => panic!("expected a tampered file, got {other:?}"),
    }

    let bad = |error| KeyRefusal::Signature {
        key: key_id("helpers-2026"),
        error,
    };
    let mut admit_signed = |bundle: &[u8], signature: Vec<u8>| {
        signature_refusal(fixture.admit_with(
            bundle,
            Some((publisher(1), signature)),
            &mut Uninterrupted,
        ))
    };
    // A consistent bundle of other content under the original's signature.
    let other = encoded(version(1, 2, 1), HelperAbi::new(1, 0));
    assert_eq!(
        admit_signed(&other, signature(1, &bytes)),
        bad(Ed25519Error::BadSignature)
    );
    // A flipped signature bit, another key's signature, and a truncated signature.
    let mut flipped = signature(1, &bytes);
    flipped[3] ^= 0x01;
    assert_eq!(
        admit_signed(&bytes, flipped),
        bad(Ed25519Error::BadSignature)
    );
    assert_eq!(
        admit_signed(&bytes, signature(2, &bytes)),
        bad(Ed25519Error::BadSignature)
    );
    assert_eq!(
        admit_signed(&bytes, signature(1, &bytes)[..63].to_vec()),
        bad(Ed25519Error::SignatureLength { found_bytes: 63 })
    );
    // The raw bytes, or the same bytes as another class, signed by the right key.
    let raw = pair(1).sign(&bytes).as_ref().to_vec();
    assert_eq!(admit_signed(&bytes, raw), bad(Ed25519Error::BadSignature));
    let as_update = content_statement(
        &publisher(1),
        ArtifactClass::RuntimeUpdate,
        &ContentKey::of(&bytes),
        u64::try_from(bytes.len()).unwrap(),
    );
    let replayed = pair(1).sign(as_update.as_bytes()).as_ref().to_vec();
    assert_eq!(
        admit_signed(&bytes, replayed),
        bad(Ed25519Error::BadSignature)
    );

    // Not a bundle at all.
    assert_eq!(
        fixture.admit(b"#!/usr/bin/env python\n", Some(1)),
        Err(HelperRefusal::Malformed {
            error: BundleError::BadMagic
        })
    );
    assert!(fixture.catalog.objects(&Scope::Host).is_empty());
}

#[test]
fn only_live_helper_keys_of_the_trust_roots_vouch_for_a_bundle() {
    let mut fixture = Fixture::new();
    let bytes = v120();
    assert_eq!(
        signature_refusal(fixture.admit(&bytes, Some(9))),
        KeyRefusal::UnknownPublisher {
            publisher: publisher(9)
        }
    );
    assert_eq!(
        signature_refusal(fixture.admit(&bytes, Some(2))),
        KeyRefusal::ClassNotAllowed {
            key: key_id("release-2026"),
            class: HELPER_CLASS
        }
    );
    assert_eq!(
        signature_refusal(fixture.admit(&bytes, Some(3))),
        KeyRefusal::Revoked {
            key: key_id("helpers-compromised"),
            reason: label("key-compromise")
        }
    );
    assert_eq!(
        signature_refusal(fixture.admit(&bytes, Some(4))),
        KeyRefusal::NotYetValid {
            key: key_id("helpers-2027"),
            valid_from: at("2026-12-01T00:00:00Z")
        }
    );
    fixture.calendar.set("2027-02-01T00:00:00Z");
    assert_eq!(
        signature_refusal(fixture.admit(&bytes, Some(1))),
        KeyRefusal::Expired {
            key: key_id("helpers-2026"),
            valid_until: at("2027-01-01T00:00:00Z")
        }
    );
    assert!(fixture.catalog.objects(&Scope::Host).is_empty());
    // The rotated key vouches inside its window.
    let admitted = fixture.admit(&bytes, Some(4)).unwrap();
    assert_eq!(admitted.key, key_id("helpers-2027"));
    assert_eq!(admitted.pin.publisher, publisher(4));
}

#[test]
fn revoking_a_key_quarantines_what_it_admitted_and_keeps_it() {
    let mut fixture = Fixture::new();
    fixture.calendar.set("2026-12-15T00:00:00Z");
    let first = fixture.admit(&v120(), Some(1)).unwrap().pin;
    let rotated = fixture
        .admit(&encoded(version(1, 3, 0), HelperAbi::new(1, 0)), Some(4))
        .unwrap()
        .pin;

    let revision = fixture.revoke_key_one();
    assert_eq!(revision.quarantined, vec![first.object]);
    match fixture.admission.check_pin(&fixture.catalog, &first) {
        Err(PinRefusal::Quarantined {
            reason: IntegrityFailure::TrustWithdrawn { refusal },
        }) => assert_eq!(
            refusal,
            TrustRefusal::PublisherNotTrusted {
                class: HELPER_CLASS,
                publisher: publisher(1)
            }
        ),
        other => panic!("expected a quarantine, got {other:?}"),
    }
    assert!(matches!(
        fixture.open(&first),
        Err(HelperRefusal::Quarantined {
            reason: IntegrityFailure::TrustWithdrawn { .. }
        })
    ));
    // Quarantined objects are kept, never deleted; the other key's bundle still serves.
    assert!(fixture
        .catalog
        .objects(&Scope::Host)
        .contains(&first.object));
    assert_eq!(
        fixture.admission.check_pin(&fixture.catalog, &rotated),
        Ok(())
    );
    assert!(fixture.open(&rotated).is_ok());
    // Nothing new is admitted under the revoked key.
    assert_eq!(
        signature_refusal(fixture.admit(&encoded(version(1, 4, 0), HelperAbi::new(1, 0)), Some(1))),
        KeyRefusal::Revoked {
            key: key_id("helpers-2026"),
            reason: label("key-compromise")
        }
    );
}

#[test]
fn an_incompatible_abi_is_refused_before_import() {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture.admit(&encoded(version(1, 2, 0), HelperAbi::new(1, 1)), Some(1)),
        Err(HelperRefusal::IncompatibleAbi {
            refusal: HelperAbiRefusal::MinorTooNew {
                required: HelperAbi::new(1, 1),
                provided: HelperAbi::new(1, 0)
            }
        })
    );
    assert!(matches!(
        fixture.admit(&encoded(version(2, 0, 0), HelperAbi::new(2, 0)), Some(1)),
        Err(HelperRefusal::IncompatibleAbi {
            refusal: HelperAbiRefusal::MajorNotProvided { .. }
        })
    ));
    assert!(fixture.catalog.objects(&Scope::Host).is_empty());

    let host = HostHelperAbi::new([HelperAbi::new(1, 1), HelperAbi::new(2, 0)]).unwrap();
    let mut migrating = Fixture::with_abi(host);
    assert!(migrating
        .admit(&encoded(version(1, 2, 0), HelperAbi::new(1, 1)), Some(1))
        .is_ok());
    assert!(migrating
        .admit(&encoded(version(2, 0, 0), HelperAbi::new(2, 0)), Some(1))
        .is_ok());
}

#[test]
fn opening_checks_the_pin_against_the_catalog_and_the_bytes_again() {
    let mut fixture = Fixture::new();
    let pin = fixture.admit(&v120(), Some(1)).unwrap().pin;

    let mut renamed = pin.clone();
    renamed.version = version(9, 0, 0);
    let mut narrowed = pin.clone();
    narrowed.runners.remove(&llama());
    let mut longer = pin.clone();
    longer.length_bytes += 1;
    for wrong in [renamed, narrowed, longer] {
        assert_eq!(fixture.open(&wrong), Err(HelperRefusal::PinMismatch));
    }
    let mut forged = pin.clone();
    forged.bundle = ContentKey::of(b"other bytes");
    assert_eq!(
        fixture.admission.check_pin(&fixture.catalog, &forged),
        Err(PinRefusal::Inconsistent)
    );
    assert_eq!(fixture.open(&forged), Err(HelperRefusal::PinMismatch));
    let absent = fake_pin_at(1, 2, 0);
    assert_eq!(fixture.open(&absent), Err(HelperRefusal::NotPublished));

    // A loader that no longer provides the helper's ABI refuses it.
    let upgraded = HelperAdmission::new(
        HostHelperAbi::single(HelperAbi::new(2, 0)),
        fixture.roots.clone(),
        fixture.calendar.clone(),
    );
    assert!(matches!(
        upgraded.check_pin(&fixture.catalog, &pin),
        Err(PinRefusal::IncompatibleAbi { .. })
    ));
    assert!(matches!(
        upgraded.open(
            &mut fixture.catalog,
            &pin,
            &execution(),
            Duration::from_secs(30)
        ),
        Err(HelperRefusal::IncompatibleAbi { .. })
    ));
    // The true pin still opens, and opens again: no lease is left held.
    assert!(fixture.open(&pin).is_ok());
    assert!(fixture.open(&pin).is_ok());
}

#[test]
fn the_catalog_runs_the_bundle_structure_check_itself() {
    // A correctly signed helper-class object that is not a bundle, imported around the
    // admission, is never published.
    let mut fixture = Fixture::new();
    let bytes = b"print('not a bundle')\n".to_vec();
    let request = ImportRequest {
        operation: OperationId::new("op-raw-import").unwrap(),
        execution: execution(),
        scope: Scope::Host,
        class: HELPER_CLASS,
        role: ObjectRole::Original,
        manifest: ImportManifest::describe(&bytes, HELPER_EXTENT_BYTES),
        trust: TrustClaim::Publisher {
            publisher: publisher(1),
            attestation: signature(1, &bytes),
        },
        depends_on: BTreeSet::new(),
        metadata: ObjectMetadata::new(),
    };
    let mut source = MemorySource {
        identity: SourceIdentity::describe("test", "raw"),
        bytes: bytes.clone(),
    };
    let status = match fixture
        .catalog
        .begin_import(request, source.identity())
        .unwrap()
    {
        ImportStart::Started(ticket) => fixture
            .catalog
            .drive_import(&ticket, &mut source, &mut Uninterrupted)
            .unwrap(),
        other => panic!("expected a new import, got {other:?}"),
    };
    assert!(
        !matches!(status, ImportStatus::Published { .. }),
        "{status:?}"
    );
    assert!(fixture.catalog.objects(&Scope::Host).is_empty());
}

#[test]
fn an_interrupted_admission_publishes_nothing_and_can_be_retried() {
    let mut fixture = Fixture::new();
    let bytes = v120();
    let signed = Some((publisher(1), signature(1, &bytes)));
    assert_eq!(
        fixture.admit_with(&bytes, signed, &mut InterruptFirstExtent),
        Err(HelperRefusal::Interrupted)
    );
    assert_eq!(
        fixture
            .catalog
            .find(&Scope::Host, HELPER_CLASS, ContentKey::of(&bytes)),
        None
    );
    let admitted = fixture.admit(&bytes, Some(1)).unwrap();
    assert!(admitted.newly_published);
}

#[test]
fn admitted_versions_roll_out_and_a_revoked_default_falls_back_to_source_injection() {
    let mut fixture = Fixture::new();
    let first = fixture.admit(&v120(), Some(1)).unwrap().pin;
    let mut rollouts = HelperRollouts::new();
    make_default(
        &mut rollouts,
        &first,
        &fixture.admission.admissibility(&fixture.catalog),
    );
    let selected = rollouts
        .select(
            &helper_id(),
            &vllm(),
            false,
            &fixture.admission.admissibility(&fixture.catalog),
        )
        .unwrap();
    assert_eq!(selected.serve, ServingHelper::Bundle { pin: first.clone() });
    // The runner loads exactly the pinned bytes, then is recorded as running on them.
    let opened = fixture.open(&first).unwrap();
    assert_eq!(opened.entry(), Some(ENTRY_SOURCE));
    let mut runners = RunnerPins::new();
    let runner = RunnerInstance::new("env-1").unwrap();
    runners
        .start(runner.clone(), vllm(), vec![selected])
        .unwrap();

    // The owner revokes the key: new runners fall back to source injection, with why;
    // the running runner keeps what it loaded and is listed for the host to restart.
    fixture.revoke_key_one();
    let fallback = rollouts
        .select(
            &helper_id(),
            &vllm(),
            false,
            &fixture.admission.admissibility(&fixture.catalog),
        )
        .unwrap();
    assert_eq!(fallback.serve, ServingHelper::SourceInjection);
    assert!(matches!(
        fallback.fallback,
        Some(FallbackReason::NotAdmissible {
            refusal: PinRefusal::Quarantined { .. },
            ..
        })
    ));
    assert_eq!(
        runners.running_on_object(first.object),
        vec![runner.clone()]
    );
    assert_eq!(
        runners.serving(&runner, &helper_id()),
        Some(&ServingHelper::Bundle { pin: first.clone() })
    );
    // A quarantined version is never proposed.
    let mut fresh = HelperRollouts::new();
    assert!(matches!(
        fresh.propose(
            first.clone(),
            Backend::Vllm,
            &fixture.admission.admissibility(&fixture.catalog)
        ),
        Err(RolloutRefusal::NotAdmissible {
            refusal: PinRefusal::Quarantined { .. },
            ..
        })
    ));
}
