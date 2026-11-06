//! The sandbox vault over a store, behind V07's grants (module docs in `mod.rs`).

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};

use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::effects::SecretClass;
use crate::sandbox_contract::provider::{
    find_encoded, AuthenticatedRequest, CredentialVault, GrantTable, GrantWidening, LookupResult,
    ScanEncoding, SecretValue, TransportResult, UpstreamRequest, UpstreamTransport, VaultFacts,
    VaultGrant, VaultRefusal, VaultScope,
};
use crate::sandbox_contract::relay_broker::HeaderVault;
use crate::sandbox_contract::remote_provider::{ApiKeySource, KeyUnavailable};

use super::store::{check_bounds, EntryName, SecretStore, StoreError, StoredSecret, ValueForm};

/// One vault over a store and V07's grant table (module notes).
pub struct SandboxVault<S: SecretStore> {
    store: S,
    grants: GrantTable,
    session: ClockSession,
    store_failures: AtomicU64,
}

impl<S: SecretStore + fmt::Debug> fmt::Debug for SandboxVault<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SandboxVault")
            .field("store", &self.store)
            .field("session", &self.session)
            .field(
                "store_failures",
                &self.store_failures.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl<S: SecretStore> SandboxVault<S> {
    /// A vault over `store`, whose grants are judged on `session`'s clock.
    pub fn new(store: S, session: ClockSession) -> Self {
        Self {
            store,
            grants: GrantTable::new(),
            session,
            store_failures: AtomicU64::new(0),
        }
    }

    pub fn session(&self) -> ClockSession {
        self.session
    }

    /// How many granted reads the store could not serve (each answered as an unknown
    /// credential, module notes).
    pub fn store_failures(&self) -> u64 {
        self.store_failures.load(Ordering::Relaxed)
    }

    /// Adds or narrows a grant through V07's table; a grant on another clock session is
    /// refused before the table sees it.
    pub fn grant(&mut self, grant: VaultGrant) -> Result<(), VaultRefusal> {
        if grant.clock != self.session {
            return Err(VaultRefusal::OtherClock);
        }
        self.grants.grant(grant)
    }

    /// Revokes a credential's grant; every later read refuses.
    pub fn revoke(&mut self, credential: CredentialRef, now: MonotonicTime) -> bool {
        self.grants.revoke(credential, now)
    }

    pub fn grant_of(&self, credential: CredentialRef) -> Option<&VaultGrant> {
        self.grants.grant_of(credential)
    }

    /// Stores `secret` for `credential`, or rotates it: the version counts up from the
    /// entry's and the old value is replaced. Host side only. Returns the new version.
    pub fn enroll(
        &mut self,
        credential: CredentialRef,
        class: SecretClass,
        form: ValueForm,
        secret: SecretValue,
    ) -> Result<u32, StoreError> {
        check_bounds(&secret)?;
        let name = EntryName::of(credential);
        let version = self
            .store
            .read(&name)?
            .map_or(1, |previous| previous.version.saturating_add(1));
        self.store.write(
            &name,
            &StoredSecret {
                class,
                form,
                version,
                secret,
            },
        )?;
        Ok(version)
    }

    /// Removes a credential's value; `false` when the store held none.
    pub fn remove(&mut self, credential: CredentialRef) -> Result<bool, StoreError> {
        self.store.remove(&EntryName::of(credential))
    }

    /// Whether the store holds a value for `credential`, without reading it out.
    pub fn holds(&self, credential: CredentialRef) -> Result<bool, StoreError> {
        Ok(self.store.read(&EntryName::of(credential))?.is_some())
    }

    /// The header value of `form` over `secret`.
    pub fn compose(form: ValueForm, secret: &SecretValue) -> SecretValue {
        match form {
            ValueForm::Raw => SecretValue::new(secret.expose_to_transport().to_vec()),
            ValueForm::Bearer => {
                SecretValue::new([b"Bearer ".as_slice(), secret.expose_to_transport()].concat())
            }
        }
    }

    /// The grant first, then the store: a refused, expired or revoked grant asks the store
    /// nothing. The entry's class must be the grant's.
    fn read_under_grant(
        &self,
        scope: &VaultScope,
        now: MonotonicTime,
    ) -> Result<(SecretClass, StoredSecret), VaultRefusal> {
        let class = self.grants.permits(scope, now, self.session)?;
        let stored = match self.store.read(&EntryName::of(scope.credential)) {
            Ok(Some(stored)) => stored,
            Ok(None) => return Err(VaultRefusal::UnknownCredential),
            Err(_) => {
                self.store_failures.fetch_add(1, Ordering::Relaxed);
                return Err(VaultRefusal::UnknownCredential);
            }
        };
        if stored.class != class {
            return Err(VaultRefusal::WouldWiden {
                widenings: vec![GrantWidening::OtherClass],
            });
        }
        Ok((class, stored))
    }

    /// The composed header value under the grant.
    fn header(
        &self,
        scope: &VaultScope,
        now: MonotonicTime,
    ) -> Result<(SecretClass, SecretValue), VaultRefusal> {
        let (class, stored) = self.read_under_grant(scope, now)?;
        Ok((class, Self::compose(stored.form, &stored.secret)))
    }

    /// The scan compares, it discloses nothing: the value is read whatever the grant's
    /// state, so a leak of a revoked credential is still found.
    fn scan(&self, scope: &VaultScope, bytes: &[u8]) -> Option<ScanEncoding> {
        let stored = self
            .store
            .read(&EntryName::of(scope.credential))
            .ok()
            .flatten()?;
        let raw = stored.secret.expose_to_transport();
        find_encoded(bytes, raw).or_else(|| {
            let composed = Self::compose(stored.form, &stored.secret);
            find_encoded(bytes, composed.expose_to_transport())
        })
    }
}

impl<S: SecretStore> CredentialVault for SandboxVault<S> {
    fn facts(&self, scope: &VaultScope, now: MonotonicTime) -> Result<VaultFacts, VaultRefusal> {
        let (class, value) = self.header(scope, now)?;
        Ok(VaultFacts {
            class,
            authorization_header_bytes: value.len_bytes(),
        })
    }

    fn send(
        &mut self,
        scope: &VaultScope,
        request: &UpstreamRequest,
        transport: &mut dyn UpstreamTransport,
        now: MonotonicTime,
    ) -> Result<TransportResult, VaultRefusal> {
        let (_, value) = self.header(scope, now)?;
        Ok(transport.exchange(&AuthenticatedRequest::new(request, &value)))
    }

    fn lookup(
        &mut self,
        scope: &VaultScope,
        request: &UpstreamRequest,
        transport: &mut dyn UpstreamTransport,
        now: MonotonicTime,
    ) -> Result<LookupResult, VaultRefusal> {
        let (_, value) = self.header(scope, now)?;
        Ok(transport.lookup(&AuthenticatedRequest::new(request, &value)))
    }

    fn reflects_secret(&self, scope: &VaultScope, bytes: &[u8]) -> Option<ScanEncoding> {
        self.scan(scope, bytes)
    }
}

impl<S: SecretStore> HeaderVault for SandboxVault<S> {
    fn facts(&self, scope: &VaultScope, now: MonotonicTime) -> Result<VaultFacts, VaultRefusal> {
        CredentialVault::facts(self, scope, now)
    }

    fn header_value(
        &self,
        scope: &VaultScope,
        now: MonotonicTime,
    ) -> Result<SecretValue, VaultRefusal> {
        self.header(scope, now).map(|(_, value)| value)
    }

    fn reflects_secret(&self, scope: &VaultScope, bytes: &[u8]) -> Option<ScanEncoding> {
        self.scan(scope, bytes)
    }
}

/// The vault as one fixed scope's [`ApiKeySource`]: the raw value, under the grant at the
/// clock's time. A refused grant is `Refused`, a store without the entry `NotConfigured`,
/// a store that cannot be reached `StoreUnavailable`.
pub struct ScopedKeySource<S: SecretStore> {
    vault: Arc<Mutex<SandboxVault<S>>>,
    scope: VaultScope,
    clock: Arc<dyn Clock>,
}

impl<S: SecretStore> ScopedKeySource<S> {
    pub fn new(
        vault: Arc<Mutex<SandboxVault<S>>>,
        scope: VaultScope,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            vault,
            scope,
            clock,
        }
    }

    pub fn scope(&self) -> &VaultScope {
        &self.scope
    }
}

impl<S: SecretStore + fmt::Debug> fmt::Debug for ScopedKeySource<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScopedKeySource")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl<S: SecretStore> ApiKeySource for ScopedKeySource<S> {
    fn api_key(&mut self) -> Result<SecretValue, KeyUnavailable> {
        let vault = self.vault.lock().unwrap_or_else(PoisonError::into_inner);
        let now = self.clock.now();
        vault
            .grants
            .permits(&self.scope, now, vault.session)
            .map_err(|_| KeyUnavailable::Refused)?;
        match vault.store.read(&EntryName::of(self.scope.credential)) {
            Ok(Some(stored)) => Ok(stored.secret),
            Ok(None) => Err(KeyUnavailable::NotConfigured),
            Err(_) => {
                vault.store_failures.fetch_add(1, Ordering::Relaxed);
                Err(KeyUnavailable::StoreUnavailable)
            }
        }
    }
}
