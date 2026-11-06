//! Tests of the sandbox vault over a fake store (run by default) and, on request, over the
//! real Windows Credential Manager under a test-only service name.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use super::*;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{digest, Digest, ManualClock, MonotonicTime};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::destinations::{Authority, DestinationPort, HttpMethod};
use crate::sandbox_contract::effects::{
    AccountRef, ExecutorName, OperationKey, OperationName, ProviderId, SecretClass,
};
use crate::sandbox_contract::provider::fakes::{FakeTransport, ReplyMode};
use crate::sandbox_contract::provider::{
    CredentialVault, DestinationBinding, GrantWidening, ScanEncoding, SecretValue, UpstreamReply,
    UpstreamRequest, VaultGrant, VaultRefusal, VaultScope,
};
use crate::sandbox_contract::relay_broker::HeaderVault;
use crate::sandbox_contract::remote_provider::{key_text, ApiKeySource, KeyUnavailable};

const START: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000_000);
const SECRET: &[u8] = b"sk-live-fixture-0123456789";

fn test_digest(name: &str) -> Digest {
    digest("yougori/test/vault/v1", &[name.as_bytes()])
}

fn credential() -> CredentialRef {
    CredentialRef::from_digest(test_digest("credential-a"))
}

fn other_credential() -> CredentialRef {
    CredentialRef::from_digest(test_digest("credential-b"))
}

fn executor() -> ExecutorName {
    ExecutorName::new("relay-broker").unwrap()
}

fn operation(name: &str) -> OperationKey {
    OperationKey {
        provider: ProviderId::new("forge").unwrap(),
        operation: OperationName::new(name).unwrap(),
        contract_version: 1,
    }
}

fn authority() -> Authority {
    Authority::parse("api.example.com", DestinationPort::HTTPS).unwrap()
}

fn account() -> AccountRef {
    AccountRef::new(test_digest("org-a"))
}

fn scope_of(credential: CredentialRef) -> VaultScope {
    VaultScope {
        credential,
        executor: executor(),
        operation: operation("create-job"),
        route: DestinationBinding::route_ref_for(&authority()),
        account: account(),
    }
}

fn scope() -> VaultScope {
    scope_of(credential())
}

fn grant_for(credential: CredentialRef, session: ClockSession, class: SecretClass) -> VaultGrant {
    VaultGrant {
        credential,
        class,
        executor: executor(),
        operations: BTreeSet::from([operation("create-job")]),
        routes: BTreeSet::from([DestinationBinding::route_ref_for(&authority())]),
        accounts: BTreeSet::from([account()]),
        clock: session,
        expires_at: START.saturating_add(Duration::from_secs(3_600)),
    }
}

/// An in-memory store that counts its reads and can be made unavailable.
#[derive(Default)]
struct FakeStore {
    entries: Mutex<BTreeMap<String, (SecretClass, ValueForm, u32, Vec<u8>)>>,
    reads: AtomicU64,
    unavailable: AtomicBool,
}

impl std::fmt::Debug for FakeStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeStore")
            .field(
                "entries",
                &self
                    .entries
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .len(),
            )
            .finish()
    }
}

impl SecretStore for FakeStore {
    fn read(&self, name: &EntryName) -> Result<Option<StoredSecret>, StoreError> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        if self.unavailable.load(Ordering::Relaxed) {
            return Err(StoreError::Unavailable {
                detail: "fake store offline".to_owned(),
            });
        }
        let entries = self.entries.lock().unwrap_or_else(PoisonError::into_inner);
        Ok(entries
            .get(name.as_str())
            .map(|(class, form, version, bytes)| StoredSecret {
                class: *class,
                form: *form,
                version: *version,
                secret: SecretValue::new(bytes.clone()),
            }))
    }

    fn write(&mut self, name: &EntryName, secret: &StoredSecret) -> Result<(), StoreError> {
        if self.unavailable.load(Ordering::Relaxed) {
            return Err(StoreError::Unavailable {
                detail: "fake store offline".to_owned(),
            });
        }
        self.entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                name.as_str().to_owned(),
                (
                    secret.class,
                    secret.form,
                    secret.version,
                    secret.secret.expose_to_transport().to_vec(),
                ),
            );
        Ok(())
    }

    fn remove(&mut self, name: &EntryName) -> Result<bool, StoreError> {
        Ok(self
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name.as_str())
            .is_some())
    }
}

/// A vault over a fake store holding the fixture under a Bearer form, granted.
fn vault() -> (SandboxVault<Arc<FakeStore>>, Arc<FakeStore>, ClockSession) {
    let store = Arc::new(FakeStore::default());
    let session = ClockSession::generate();
    let mut vault = SandboxVault::new(Arc::clone(&store), session);
    let version = vault
        .enroll(
            credential(),
            SecretClass::LongLivedProviderCredential,
            ValueForm::Bearer,
            SecretValue::new(SECRET.to_vec()),
        )
        .unwrap();
    assert_eq!(version, 1);
    vault
        .grant(grant_for(
            credential(),
            session,
            SecretClass::LongLivedProviderCredential,
        ))
        .unwrap();
    store.reads.store(0, Ordering::Relaxed);
    (vault, store, session)
}

impl SecretStore for Arc<FakeStore> {
    fn read(&self, name: &EntryName) -> Result<Option<StoredSecret>, StoreError> {
        FakeStore::read(self, name)
    }

    fn write(&mut self, name: &EntryName, secret: &StoredSecret) -> Result<(), StoreError> {
        // The fake is shared; writes go through its interior lock.
        let shared: &FakeStore = self;
        if shared.unavailable.load(Ordering::Relaxed) {
            return Err(StoreError::Unavailable {
                detail: "fake store offline".to_owned(),
            });
        }
        shared
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                name.as_str().to_owned(),
                (
                    secret.class,
                    secret.form,
                    secret.version,
                    secret.secret.expose_to_transport().to_vec(),
                ),
            );
        Ok(())
    }

    fn remove(&mut self, name: &EntryName) -> Result<bool, StoreError> {
        let shared: &FakeStore = self;
        Ok(shared
            .entries
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(name.as_str())
            .is_some())
    }
}

fn bearer() -> Vec<u8> {
    [b"Bearer ".as_slice(), SECRET].concat()
}

#[test]
fn a_refused_expired_or_revoked_grant_reads_nothing_from_the_store() {
    let (mut vault, store, _session) = vault();
    // Unknown credential: no grant at all.
    assert_eq!(
        HeaderVault::header_value(&vault, &scope_of(other_credential()), START).unwrap_err(),
        VaultRefusal::UnknownCredential
    );
    // Another executor.
    let mut foreign = scope();
    foreign.executor = ExecutorName::new("someone-else").unwrap();
    assert_eq!(
        HeaderVault::header_value(&vault, &foreign, START).unwrap_err(),
        VaultRefusal::OtherExecutor
    );
    // An operation the grant does not cover.
    let mut other_operation = scope();
    other_operation.operation = operation("delete-everything");
    assert_eq!(
        HeaderVault::header_value(&vault, &other_operation, START).unwrap_err(),
        VaultRefusal::OperationNotGranted
    );
    // Expired.
    let late = START.saturating_add(Duration::from_secs(3_600));
    assert!(matches!(
        HeaderVault::header_value(&vault, &scope(), late).unwrap_err(),
        VaultRefusal::Expired { .. }
    ));
    assert_eq!(
        store.reads.load(Ordering::Relaxed),
        0,
        "a refusal asked the store"
    );
    // Revoked: the grant was good, the revocation ends it.
    assert!(vault.revoke(credential(), START));
    assert_eq!(
        HeaderVault::header_value(&vault, &scope(), START).unwrap_err(),
        VaultRefusal::Revoked
    );
    assert_eq!(store.reads.load(Ordering::Relaxed), 0);
    assert!(CredentialVault::facts(&vault, &scope(), START).is_err());
    assert_eq!(store.reads.load(Ordering::Relaxed), 0);
}

#[test]
fn a_granted_read_composes_the_header_value_as_the_entry_was_enrolled() {
    let (mut vault, store, session) = vault();
    let value = HeaderVault::header_value(&vault, &scope(), START).unwrap();
    assert_eq!(value.expose_to_transport(), bearer().as_slice());
    let facts = HeaderVault::facts(&vault, &scope(), START).unwrap();
    assert_eq!(facts.class, SecretClass::LongLivedProviderCredential);
    assert_eq!(facts.authorization_header_bytes, bearer().len() as u64);
    assert_eq!(store.reads.load(Ordering::Relaxed), 2);
    // A raw-form entry is the value itself.
    vault
        .enroll(
            other_credential(),
            SecretClass::ShortLivedCapability,
            ValueForm::Raw,
            SecretValue::new(b"raw-key-0123456789".to_vec()),
        )
        .unwrap();
    vault
        .grant(grant_for(
            other_credential(),
            session,
            SecretClass::ShortLivedCapability,
        ))
        .unwrap();
    let raw = HeaderVault::header_value(&vault, &scope_of(other_credential()), START).unwrap();
    assert_eq!(raw.expose_to_transport(), b"raw-key-0123456789");
    // The vault holds no plaintext between calls: the store is read every time.
    let before = store.reads.load(Ordering::Relaxed);
    let _ = HeaderVault::header_value(&vault, &scope(), START).unwrap();
    assert_eq!(store.reads.load(Ordering::Relaxed), before + 1);
}

#[test]
fn a_grant_whose_class_is_not_the_entrys_is_refused() {
    let store = Arc::new(FakeStore::default());
    let session = ClockSession::generate();
    let mut vault = SandboxVault::new(Arc::clone(&store), session);
    vault
        .enroll(
            credential(),
            SecretClass::LongLivedProviderCredential,
            ValueForm::Bearer,
            SecretValue::new(SECRET.to_vec()),
        )
        .unwrap();
    vault
        .grant(grant_for(
            credential(),
            session,
            SecretClass::ShortLivedCapability,
        ))
        .unwrap();
    assert_eq!(
        HeaderVault::header_value(&vault, &scope(), START).unwrap_err(),
        VaultRefusal::WouldWiden {
            widenings: vec![GrantWidening::OtherClass]
        }
    );
    // A grant on another clock session is refused before the table sees it.
    assert_eq!(
        vault
            .grant(grant_for(
                other_credential(),
                ClockSession::generate(),
                SecretClass::LongLivedProviderCredential
            ))
            .unwrap_err(),
        VaultRefusal::OtherClock
    );
}

#[test]
fn rotation_replaces_the_value_and_removal_leaves_none() {
    let (mut vault, _store, _session) = vault();
    let version = vault
        .enroll(
            credential(),
            SecretClass::LongLivedProviderCredential,
            ValueForm::Bearer,
            SecretValue::new(b"sk-live-rotated-9876543210".to_vec()),
        )
        .unwrap();
    assert_eq!(version, 2);
    let value = HeaderVault::header_value(&vault, &scope(), START).unwrap();
    assert_eq!(
        value.expose_to_transport(),
        b"Bearer sk-live-rotated-9876543210"
    );
    // The old value is gone: the scan no longer finds it.
    assert_eq!(
        HeaderVault::reflects_secret(&vault, &scope(), &bearer()),
        None
    );
    assert_eq!(
        HeaderVault::reflects_secret(&vault, &scope(), b"Bearer sk-live-rotated-9876543210"),
        Some(ScanEncoding::Verbatim)
    );
    assert!(vault.holds(credential()).unwrap());
    assert!(vault.remove(credential()).unwrap());
    assert!(!vault.holds(credential()).unwrap());
    assert_eq!(
        HeaderVault::header_value(&vault, &scope(), START).unwrap_err(),
        VaultRefusal::UnknownCredential
    );
    assert!(!vault.remove(credential()).unwrap());
}

#[test]
fn a_secret_outside_the_bounds_is_refused_before_it_is_stored() {
    let (mut vault, store, _session) = vault();
    assert_eq!(
        vault
            .enroll(
                other_credential(),
                SecretClass::LongLivedProviderCredential,
                ValueForm::Raw,
                SecretValue::new(Vec::new())
            )
            .unwrap_err(),
        StoreError::OutOfBounds { bytes: 0 }
    );
    assert_eq!(
        vault
            .enroll(
                other_credential(),
                SecretClass::LongLivedProviderCredential,
                ValueForm::Raw,
                SecretValue::new(vec![b'k'; MAX_SECRET_BYTES + 1])
            )
            .unwrap_err(),
        StoreError::OutOfBounds {
            bytes: MAX_SECRET_BYTES + 1
        }
    );
    assert!(!store
        .entries
        .lock()
        .unwrap()
        .contains_key(EntryName::of(other_credential()).as_str()));
}

#[test]
fn the_scan_finds_the_value_in_the_encodings_v07_names() {
    let (vault, _store, _session) = vault();
    assert_eq!(
        HeaderVault::reflects_secret(&vault, &scope(), b"nothing here"),
        None
    );
    assert_eq!(
        HeaderVault::reflects_secret(&vault, &scope(), &[b"prefix ", SECRET, b" suffix"].concat()),
        Some(ScanEncoding::Verbatim)
    );
    let hex_value = hex::encode(bearer());
    assert_eq!(
        HeaderVault::reflects_secret(&vault, &scope(), hex_value.as_bytes()),
        Some(ScanEncoding::Hexadecimal)
    );
    // The V07 port scans the same way.
    assert_eq!(
        CredentialVault::reflects_secret(&vault, &scope(), SECRET),
        Some(ScanEncoding::Verbatim)
    );
}

#[test]
fn a_store_that_cannot_be_reached_refuses_and_counts() {
    let (vault, store, _session) = vault();
    store.unavailable.store(true, Ordering::Relaxed);
    assert_eq!(
        HeaderVault::header_value(&vault, &scope(), START).unwrap_err(),
        VaultRefusal::UnknownCredential
    );
    assert_eq!(vault.store_failures(), 1);
    assert!(matches!(
        vault.holds(credential()),
        Err(StoreError::Unavailable { .. })
    ));
}

#[test]
fn nothing_secret_appears_in_debug_or_errors() {
    let (vault, _store, _session) = vault();
    let debug = format!("{vault:?}");
    assert!(debug.contains("SandboxVault"), "{debug}");
    assert!(!debug.contains("fixture"), "{debug}");
    let stored = StoredSecret {
        class: SecretClass::LongLivedProviderCredential,
        form: ValueForm::Bearer,
        version: 3,
        secret: SecretValue::new(SECRET.to_vec()),
    };
    let debug = format!("{stored:?}");
    assert!(debug.contains("version: 3"), "{debug}");
    assert!(!debug.contains("fixture"), "{debug}");
    let encoded = store::encode(&stored).unwrap();
    assert!(encoded.contains("\"envelope\":1"));
    assert!(
        !encoded.contains("sk-live"),
        "the envelope carries the value only in hex"
    );
    let decoded = store::decode(encoded).unwrap();
    assert_eq!(decoded.secret.expose_to_transport(), SECRET);
    assert_eq!(decoded.version, 3);
    assert_eq!(
        store::decode("{\"envelope\":2}".to_owned()).unwrap_err(),
        StoreError::Malformed
    );
    assert_eq!(
        store::decode("not json".to_owned()).unwrap_err(),
        StoreError::Malformed
    );
    for error in [
        StoreError::Unavailable {
            detail: "x".to_owned(),
        },
        StoreError::Malformed,
        StoreError::OutOfBounds { bytes: 9 },
        StoreError::ReadOnly,
    ] {
        assert!(!error.to_string().contains("fixture"));
    }
}

#[test]
fn the_key_source_hands_the_raw_value_only_under_the_grant() {
    let store = Arc::new(FakeStore::default());
    let session = ClockSession::generate();
    let mut vault = SandboxVault::new(Arc::clone(&store), session);
    vault
        .enroll(
            credential(),
            SecretClass::LongLivedProviderCredential,
            ValueForm::Raw,
            SecretValue::new(b"rp_live_0123456789abcdef".to_vec()),
        )
        .unwrap();
    vault
        .grant(grant_for(
            credential(),
            session,
            SecretClass::LongLivedProviderCredential,
        ))
        .unwrap();
    let clock = Arc::new(ManualClock::new(START));
    let vault = Arc::new(Mutex::new(vault));
    let mut source = ScopedKeySource::new(
        Arc::clone(&vault),
        scope(),
        Arc::clone(&clock) as Arc<dyn crate::foundation::ids::Clock>,
    );
    let key = source.api_key().unwrap();
    assert_eq!(key_text(&key), Some("rp_live_0123456789abcdef"));
    // A scope the grant does not cover.
    let mut refused = ScopedKeySource::new(
        Arc::clone(&vault),
        scope_of(other_credential()),
        Arc::clone(&clock) as Arc<dyn crate::foundation::ids::Clock>,
    );
    assert_eq!(refused.api_key().unwrap_err(), KeyUnavailable::Refused);
    // Granted but never enrolled.
    vault
        .lock()
        .unwrap()
        .grant(grant_for(
            other_credential(),
            session,
            SecretClass::LongLivedProviderCredential,
        ))
        .unwrap();
    assert_eq!(
        refused.api_key().unwrap_err(),
        KeyUnavailable::NotConfigured
    );
    // The store gone.
    store.unavailable.store(true, Ordering::Relaxed);
    assert_eq!(
        source.api_key().unwrap_err(),
        KeyUnavailable::StoreUnavailable
    );
    store.unavailable.store(false, Ordering::Relaxed);
    // Expired by the clock.
    clock.advance(Duration::from_secs(7_200));
    assert_eq!(source.api_key().unwrap_err(), KeyUnavailable::Refused);
    assert!(!format!("{source:?}").contains("rp_live"));
}

#[test]
fn the_credential_vault_sends_the_composed_value_only_under_the_grant() {
    let (mut vault, _store, _session) = vault();
    let request = UpstreamRequest {
        method: HttpMethod::Post,
        authority: authority(),
        target: "/v1/jobs".to_owned(),
        headers: BTreeMap::from([("content-type".to_owned(), "application/json".to_owned())]),
        body: b"{}".to_vec(),
    };
    let mut transport = FakeTransport::new(ReplyMode::Fixed(UpstreamReply {
        status: 200,
        headers: Vec::new(),
        body: b"{\"ok\":true}".to_vec(),
    }));
    let result = vault
        .send(&scope(), &request, &mut transport, START)
        .unwrap();
    assert!(matches!(
        result,
        crate::sandbox_contract::provider::TransportResult::Reply(_)
    ));
    {
        let state = transport.0.lock().unwrap();
        assert_eq!(state.sent.len(), 1);
        assert_eq!(state.sent[0].1, bearer());
    }
    let late = START.saturating_add(Duration::from_secs(7_200));
    assert!(vault
        .send(&scope(), &request, &mut transport, late)
        .is_err());
    assert_eq!(
        transport.0.lock().unwrap().sent.len(),
        1,
        "a refused send reached the wire"
    );
}

/// Writes, reads, rotates and removes one entry in the user's Windows Credential Manager
/// under a test-only service name.
#[test]
#[ignore = "writes to and removes an entry from the user's Windows Credential Manager; run with --ignored"]
fn the_credential_manager_round_trips_an_entry() {
    let mut store = KeyringStore::with_service("Yougori.SandboxVault.test.v1");
    let credential = CredentialRef::from_digest(test_digest(&format!(
        "credential-manager-{}",
        std::process::id()
    )));
    let name = EntryName::of(credential);
    let _ = store.remove(&name);
    assert!(store.read(&name).unwrap().is_none());
    store
        .write(
            &name,
            &StoredSecret {
                class: SecretClass::LongLivedProviderCredential,
                form: ValueForm::Bearer,
                version: 1,
                secret: SecretValue::new(SECRET.to_vec()),
            },
        )
        .unwrap();
    let read = store.read(&name).unwrap().unwrap();
    assert_eq!(read.version, 1);
    assert_eq!(read.form, ValueForm::Bearer);
    assert_eq!(read.secret.expose_to_transport(), SECRET);
    let session = ClockSession::generate();
    let mut vault = SandboxVault::new(store, session);
    let version = vault
        .enroll(
            credential,
            SecretClass::LongLivedProviderCredential,
            ValueForm::Bearer,
            SecretValue::new(b"sk-live-rotated-9876543210".to_vec()),
        )
        .unwrap();
    assert_eq!(version, 2);
    vault
        .grant(grant_for(
            credential,
            session,
            SecretClass::LongLivedProviderCredential,
        ))
        .unwrap();
    let value = HeaderVault::header_value(&vault, &scope_of(credential), START).unwrap();
    assert_eq!(
        value.expose_to_transport(),
        b"Bearer sk-live-rotated-9876543210"
    );
    assert!(vault.remove(credential).unwrap());
    assert!(!vault.holds(credential).unwrap());
}
