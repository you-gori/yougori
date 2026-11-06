//! The vault boundary (VM part §4.5 lines 2004–2006; VM-W28).
//!
//! The executor never holds a credential. It names one by [`CredentialRef`] inside a
//! [`VaultScope`] (executor, operation, route and account), and the vault composes the
//! authenticated request and hands it straight to the transport: a direct
//! vault-to-executor operation, with no copy relayed through the engine. A
//! [`GrantTable`] keeps each credential's grant; a grant can be narrowed or revoked but
//! never widened, so an executor's scope cannot grow after it is granted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::request::UpstreamRequest;
use super::scan::ScanEncoding;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::MonotonicTime;
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::effects::{
    AccountRef, ExecutorName, OperationKey, RouteRef, SecretClass,
};

/// Everything one use of a credential is scoped to (VM-W28: scoped to operations and
/// existing delegation).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultScope {
    pub credential: CredentialRef,
    pub executor: ExecutorName,
    pub operation: OperationKey,
    pub route: RouteRef,
    pub account: AccountRef,
}

/// What a credential may be used for.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultGrant {
    pub credential: CredentialRef,
    pub class: SecretClass,
    pub executor: ExecutorName,
    pub operations: BTreeSet<OperationKey>,
    pub routes: BTreeSet<RouteRef>,
    pub accounts: BTreeSet<AccountRef>,
    pub clock: ClockSession,
    pub expires_at: MonotonicTime,
}

/// One way a proposed grant is broader than the current one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantWidening {
    OtherCredential,
    OtherClass,
    OtherExecutor,
    NewOperation,
    NewRoute,
    NewAccount,
    OtherClock,
    LaterExpiry,
}

impl VaultGrant {
    /// Whether the grant covers `scope` at `now` on `session`.
    pub fn permits(
        &self,
        scope: &VaultScope,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), VaultRefusal> {
        if scope.credential != self.credential {
            return Err(VaultRefusal::UnknownCredential);
        }
        if scope.executor != self.executor {
            return Err(VaultRefusal::OtherExecutor);
        }
        if !self.operations.contains(&scope.operation) {
            return Err(VaultRefusal::OperationNotGranted);
        }
        if !self.routes.contains(&scope.route) {
            return Err(VaultRefusal::RouteNotGranted);
        }
        if !self.accounts.contains(&scope.account) {
            return Err(VaultRefusal::AccountNotGranted);
        }
        if session != self.clock {
            return Err(VaultRefusal::OtherClock);
        }
        if now >= self.expires_at {
            return Err(VaultRefusal::Expired {
                expires_at: self.expires_at,
            });
        }
        Ok(())
    }

    /// Every way `proposed` is broader than this grant; empty when it is the same or
    /// narrower.
    pub fn widenings(&self, proposed: &VaultGrant) -> BTreeSet<GrantWidening> {
        let mut out = BTreeSet::new();
        if proposed.credential != self.credential {
            out.insert(GrantWidening::OtherCredential);
        }
        if proposed.class != self.class {
            out.insert(GrantWidening::OtherClass);
        }
        if proposed.executor != self.executor {
            out.insert(GrantWidening::OtherExecutor);
        }
        if !proposed.operations.is_subset(&self.operations) {
            out.insert(GrantWidening::NewOperation);
        }
        if !proposed.routes.is_subset(&self.routes) {
            out.insert(GrantWidening::NewRoute);
        }
        if !proposed.accounts.is_subset(&self.accounts) {
            out.insert(GrantWidening::NewAccount);
        }
        if proposed.clock != self.clock {
            out.insert(GrantWidening::OtherClock);
        }
        if proposed.expires_at > self.expires_at {
            out.insert(GrantWidening::LaterExpiry);
        }
        out
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GrantEntry {
    grant: VaultGrant,
    revoked_at: Option<MonotonicTime>,
}

/// The grants of one vault (VM-W28: executor scope cannot widen).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantTable {
    grants: BTreeMap<CredentialRef, GrantEntry>,
}

impl GrantTable {
    /// A table with no grants.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a grant. A new reference needs an external credential class; a grant for
    /// a reference already granted may only narrow it, and a revoked reference is never
    /// granted again (a new credential needs a new reference).
    pub fn grant(&mut self, grant: VaultGrant) -> Result<(), VaultRefusal> {
        if !grant.class.is_external_credential() {
            return Err(VaultRefusal::NotAnExternalCredential { class: grant.class });
        }
        match self.grants.get(&grant.credential) {
            Some(entry) if entry.revoked_at.is_some() => Err(VaultRefusal::Revoked),
            Some(entry) => {
                let widenings = entry.grant.widenings(&grant);
                if !widenings.is_empty() {
                    return Err(VaultRefusal::WouldWiden {
                        widenings: widenings.into_iter().collect(),
                    });
                }
                self.grants.insert(
                    grant.credential,
                    GrantEntry {
                        grant,
                        revoked_at: None,
                    },
                );
                Ok(())
            }
            None => {
                self.grants.insert(
                    grant.credential,
                    GrantEntry {
                        grant,
                        revoked_at: None,
                    },
                );
                Ok(())
            }
        }
    }

    /// Revokes a reference; nothing is sent with it again.
    pub fn revoke(&mut self, credential: CredentialRef, now: MonotonicTime) -> bool {
        match self.grants.get_mut(&credential) {
            Some(entry) => {
                entry.revoked_at.get_or_insert(now);
                true
            }
            None => false,
        }
    }

    /// The reference's current grant, revoked or not.
    pub fn grant_of(&self, credential: CredentialRef) -> Option<&VaultGrant> {
        self.grants.get(&credential).map(|entry| &entry.grant)
    }

    /// The class of the credential `scope` names, if its grant covers the scope now.
    pub fn permits(
        &self,
        scope: &VaultScope,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<SecretClass, VaultRefusal> {
        let entry = self
            .grants
            .get(&scope.credential)
            .ok_or(VaultRefusal::UnknownCredential)?;
        if entry.revoked_at.is_some() {
            return Err(VaultRefusal::Revoked);
        }
        entry.grant.permits(scope, now, session)?;
        Ok(entry.grant.class)
    }
}

/// Secret bytes inside the vault boundary. It is never serialized, has no `Display`, and
/// its `Debug` output is redacted; only a transport reads it, to put it on the wire.
pub struct SecretValue(Vec<u8>);

impl SecretValue {
    /// Wraps secret bytes inside the vault boundary.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// The bytes, for the transport that writes them on the wire and for nothing else.
    pub fn expose_to_transport(&self) -> &[u8] {
        &self.0
    }

    /// The length, which is not secret.
    pub fn len_bytes(&self) -> u64 {
        u64::try_from(self.0.len()).unwrap_or(u64::MAX)
    }
}

impl fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretValue(redacted)")
    }
}

/// A request and the authorization value the vault composed for it. The vault builds
/// it and hands it to the transport; the executor never sees one.
pub struct AuthenticatedRequest<'a> {
    request: &'a UpstreamRequest,
    authorization: &'a SecretValue,
}

impl<'a> AuthenticatedRequest<'a> {
    /// Pairs a request with its authorization value; built inside the vault.
    pub fn new(request: &'a UpstreamRequest, authorization: &'a SecretValue) -> Self {
        Self {
            request,
            authorization,
        }
    }

    /// The request without its authorization.
    pub fn request(&self) -> &UpstreamRequest {
        self.request
    }

    /// The authorization header value, for the transport alone.
    pub fn authorization_for_transport(&self) -> &[u8] {
        self.authorization.expose_to_transport()
    }
}

impl fmt::Debug for AuthenticatedRequest<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedRequest")
            .field("request", self.request)
            .field("authorization", self.authorization)
            .finish()
    }
}

/// A provider's raw answer. Untrusted until the response policy accepts it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamReply {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// What became of one send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportResult {
    Reply(UpstreamReply),
    /// The request left and nothing came back.
    Lost,
    /// The request certainly never left.
    NotSent,
}

/// What a reconciliation lookup found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LookupResult {
    Committed(UpstreamReply),
    NotCommitted,
    Unknown,
}

/// The network side of the vault: it writes an authenticated request on the wire.
pub trait UpstreamTransport {
    fn exchange(&mut self, request: &AuthenticatedRequest<'_>) -> TransportResult;

    /// Asks whether the operation `request` stands for committed, by idempotency key or
    /// resource state.
    fn lookup(&mut self, request: &AuthenticatedRequest<'_>) -> LookupResult;
}

/// What the vault discloses about a credential: its class and the wire bytes its
/// authorization header adds, never its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VaultFacts {
    pub class: SecretClass,
    pub authorization_header_bytes: u64,
}

/// The host vault as an executor uses it (§4.5 line 2004: the executor uses the narrow
/// credential; it does not receive it).
pub trait CredentialVault {
    /// The credential's facts, if its grant covers `scope` at `now`.
    fn facts(&self, scope: &VaultScope, now: MonotonicTime) -> Result<VaultFacts, VaultRefusal>;

    /// Authenticates `request` with the credential `scope` names and sends it through
    /// `transport`, if the grant covers the scope at `now`. On refusal nothing is sent.
    fn send(
        &mut self,
        scope: &VaultScope,
        request: &UpstreamRequest,
        transport: &mut dyn UpstreamTransport,
        now: MonotonicTime,
    ) -> Result<TransportResult, VaultRefusal>;

    /// As [`CredentialVault::send`], for a reconciliation lookup.
    fn lookup(
        &mut self,
        scope: &VaultScope,
        request: &UpstreamRequest,
        transport: &mut dyn UpstreamTransport,
        now: MonotonicTime,
    ) -> Result<LookupResult, VaultRefusal>;

    /// Whether `bytes` contain the credential `scope` names or the authorization value
    /// composed from it, in a scanned encoding, without revealing either.
    fn reflects_secret(&self, scope: &VaultScope, bytes: &[u8]) -> Option<ScanEncoding>;
}

strict_provider_enum! {
    /// Why the vault refused a use or a grant.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum VaultRefusal tag "refusal" {
        UnknownCredential,
        Revoked,
        OtherExecutor,
        OperationNotGranted,
        RouteNotGranted,
        AccountNotGranted,
        OtherClock,
        Expired { expires_at: MonotonicTime },
        WouldWiden { widenings: Vec<GrantWidening> },
        NotAnExternalCredential { class: SecretClass },
    }
}

impl VaultRefusal {
    /// A stable short name, used in rejection codes.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::UnknownCredential => "unknown_credential",
            Self::Revoked => "revoked",
            Self::OtherExecutor => "other_executor",
            Self::OperationNotGranted => "operation_not_granted",
            Self::RouteNotGranted => "route_not_granted",
            Self::AccountNotGranted => "account_not_granted",
            Self::OtherClock => "other_clock",
            Self::Expired { .. } => "expired",
            Self::WouldWiden { .. } => "would_widen",
            Self::NotAnExternalCredential { .. } => "not_an_external_credential",
        }
    }
}

impl fmt::Display for VaultRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownCredential => f.write_str("the vault holds no grant for this reference"),
            Self::Revoked => f.write_str("the credential's grant was revoked"),
            Self::OtherExecutor => f.write_str("the grant is for another executor"),
            Self::OperationNotGranted => f.write_str("the grant does not cover this operation"),
            Self::RouteNotGranted => f.write_str("the grant does not cover this route"),
            Self::AccountNotGranted => f.write_str("the grant does not cover this account"),
            Self::OtherClock => f.write_str("the grant's expiry is on another clock session"),
            Self::Expired { expires_at } => {
                write!(f, "the grant expired at {} ns", expires_at.as_nanos())
            }
            Self::WouldWiden { widenings } => write!(
                f,
                "a grant cannot be widened ({widenings:?}); revoke it and grant a new reference"
            ),
            Self::NotAnExternalCredential { class } => {
                write!(f, "a {class:?} cannot be granted to an executor")
            }
        }
    }
}

impl std::error::Error for VaultRefusal {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::sandbox_contract::effects::{OperationName, ProviderId};

    const SESSION: ClockSession = ClockSession::from_uuid(uuid::Uuid::from_u128(0x77));

    fn reference(name: &str) -> CredentialRef {
        CredentialRef::from_digest(digest("yougori/test/vault/v1", &[name.as_bytes()]))
    }

    fn operation(name: &str) -> OperationKey {
        OperationKey {
            provider: ProviderId::new("forge").unwrap(),
            operation: OperationName::new(name).unwrap(),
            contract_version: 1,
        }
    }

    fn route(name: &str) -> RouteRef {
        RouteRef::new(digest("yougori/test/route/v1", &[name.as_bytes()]))
    }

    fn account(name: &str) -> AccountRef {
        AccountRef::new(digest("yougori/test/account/v1", &[name.as_bytes()]))
    }

    fn grant() -> VaultGrant {
        VaultGrant {
            credential: reference("key"),
            class: SecretClass::LongLivedProviderCredential,
            executor: ExecutorName::new("forge-writer").unwrap(),
            operations: BTreeSet::from([operation("open_pull_request")]),
            routes: BTreeSet::from([route("forge")]),
            accounts: BTreeSet::from([account("org-a")]),
            clock: SESSION,
            expires_at: MonotonicTime::from_nanos(1_000),
        }
    }

    fn scope() -> VaultScope {
        VaultScope {
            credential: reference("key"),
            executor: ExecutorName::new("forge-writer").unwrap(),
            operation: operation("open_pull_request"),
            route: route("forge"),
            account: account("org-a"),
        }
    }

    #[test]
    fn a_grant_covers_exactly_its_scope() {
        let mut table = GrantTable::new();
        table.grant(grant()).unwrap();
        let now = MonotonicTime::from_nanos(10);
        assert_eq!(
            table.permits(&scope(), now, SESSION),
            Ok(SecretClass::LongLivedProviderCredential)
        );
        let cases: Vec<(VaultScope, VaultRefusal)> = vec![
            (
                VaultScope {
                    operation: operation("delete_repository"),
                    ..scope()
                },
                VaultRefusal::OperationNotGranted,
            ),
            (
                VaultScope {
                    route: route("elsewhere"),
                    ..scope()
                },
                VaultRefusal::RouteNotGranted,
            ),
            (
                VaultScope {
                    account: account("org-b"),
                    ..scope()
                },
                VaultRefusal::AccountNotGranted,
            ),
            (
                VaultScope {
                    executor: ExecutorName::new("other").unwrap(),
                    ..scope()
                },
                VaultRefusal::OtherExecutor,
            ),
            (
                VaultScope {
                    credential: reference("other"),
                    ..scope()
                },
                VaultRefusal::UnknownCredential,
            ),
        ];
        for (scope, refusal) in cases {
            assert_eq!(table.permits(&scope, now, SESSION), Err(refusal));
        }
        assert_eq!(
            table.permits(&scope(), MonotonicTime::from_nanos(1_000), SESSION),
            Err(VaultRefusal::Expired {
                expires_at: MonotonicTime::from_nanos(1_000)
            })
        );
        assert_eq!(
            table.permits(
                &scope(),
                now,
                ClockSession::from_uuid(uuid::Uuid::from_u128(1))
            ),
            Err(VaultRefusal::OtherClock)
        );
    }

    #[test]
    fn executor_scope_cannot_widen_only_narrow() {
        let mut table = GrantTable::new();
        table.grant(grant()).unwrap();
        let mut wider = grant();
        wider.operations.insert(operation("delete_repository"));
        wider.accounts.insert(account("org-b"));
        wider.expires_at = MonotonicTime::from_nanos(5_000);
        assert_eq!(
            table.grant(wider),
            Err(VaultRefusal::WouldWiden {
                widenings: vec![
                    GrantWidening::NewOperation,
                    GrantWidening::NewAccount,
                    GrantWidening::LaterExpiry
                ]
            })
        );
        let mut other_executor = grant();
        other_executor.executor = ExecutorName::new("other").unwrap();
        assert!(matches!(
            table.grant(other_executor),
            Err(VaultRefusal::WouldWiden { .. })
        ));
        // Narrowing is allowed and takes effect.
        let mut narrower = grant();
        narrower.expires_at = MonotonicTime::from_nanos(100);
        table.grant(narrower).unwrap();
        assert!(matches!(
            table.permits(&scope(), MonotonicTime::from_nanos(200), SESSION),
            Err(VaultRefusal::Expired { .. })
        ));
        // Revocation is final for the reference.
        assert!(table.revoke(reference("key"), MonotonicTime::from_nanos(20)));
        assert_eq!(
            table.permits(&scope(), MonotonicTime::from_nanos(30), SESSION),
            Err(VaultRefusal::Revoked)
        );
        assert_eq!(table.grant(grant()), Err(VaultRefusal::Revoked));
        assert!(!table.revoke(reference("never"), MonotonicTime::from_nanos(20)));
    }

    #[test]
    fn only_external_credentials_are_granted() {
        let mut table = GrantTable::new();
        for class in [
            SecretClass::SandboxLocalSecret,
            SecretClass::UserPrivateContent,
            SecretClass::FakeCanary,
        ] {
            let mut grant = grant();
            grant.class = class;
            assert_eq!(
                table.grant(grant),
                Err(VaultRefusal::NotAnExternalCredential { class })
            );
        }
    }

    #[test]
    fn secret_values_never_show_in_debug() {
        let secret = SecretValue::new(b"Bearer sk-live-fixture-0001".to_vec());
        assert_eq!(format!("{secret:?}"), "SecretValue(redacted)");
        assert_eq!(secret.len_bytes(), 27);
        let refusal = VaultRefusal::WouldWiden {
            widenings: vec![GrantWidening::NewRoute],
        };
        let json = serde_json::to_string(&refusal).unwrap();
        assert_eq!(
            serde_json::from_str::<VaultRefusal>(&json).unwrap(),
            refusal
        );
        assert!(
            serde_json::from_str::<VaultRefusal>(r#"{"refusal":"revoked","extra":true}"#).is_err()
        );
    }
}
