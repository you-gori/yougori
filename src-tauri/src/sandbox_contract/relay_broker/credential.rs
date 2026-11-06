//! The executor's credential on a relay exchange, and the echo scan of the response (VM
//! part §4.5: the executor fetches or uses the narrow credential and constructs the
//! upstream request; response-header stripping alone does not stop a provider from
//! reflecting a credential, line 2008; VM-W28: no credential in the relay, scoped to
//! operations and existing delegation).
//!
//! The relay never holds a credential. On a credentialed route the broker's
//! [`CredentialInjector`] adds exactly one header after the broker's own relay step: the
//! [`CredentialHeader`] the route's [`CredentialAudience`] names, one of V02's
//! [`RESERVED_CREDENTIAL_HEADERS`](crate::sandbox_contract::destinations::RESERVED_CREDENTIAL_HEADERS),
//! which V02 refuses from the guest on such a route. The
//! use is scoped with V07's [`VaultScope`] (the route's credential, this executor, the
//! bound operation's contract, the route reference of the bound authority and the
//! audience's account) and checked through V07's [`GrantTable::permits`] before the vault
//! is asked, and again before the value is written. The vault is the narrow
//! [`HeaderVault`] port; S04/S05 own the real one.
//!
//! The header value lives in V07's [`SecretValue`] and in [`UpstreamBytes`], whose
//! `Debug` shows only lengths and whose buffer is overwritten when dropped (best effort;
//! copies in TLS libraries and the OS are outside this, §4.5 line 2006). No refusal, no
//! report and no link message has a field that could hold it.
//!
//! [`EchoScan`] scans the whole rebuilt guest response, its head, its body and both
//! together, with V07's scanner ([`find_encoded`], [`KnownSecrets`]) for the injected
//! header value, for what the vault recognizes as its credential
//! ([`HeaderVault::reflects_secret`]) and for every known fixture secret and canary. Its
//! coverage is V07's [`SCAN_COVERAGE`](crate::sandbox_contract::provider::SCAN_COVERAGE).

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};

use serde::{Deserialize, Serialize};

use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::destinations::{BoundRequest, OperationRoute, RouteId};
use crate::sandbox_contract::effects::{
    AccountRef, ExecutorName, OperationKey, OperationName as ContractName, ProviderId, SecretClass,
};
use crate::sandbox_contract::provider::{
    find_encoded, DestinationBinding, GrantTable, KnownSecrets, LeakSource, ScanEncoding,
    SecretValue, VaultFacts, VaultGrant, VaultRefusal, VaultScope,
};

/// The end of an HTTP head.
const HEAD_END: &[u8] = b"\r\n\r\n";

/// Bytes a header line adds around its value: `: ` and the line end.
const HEADER_LINE_OVERHEAD: u64 = 4;

/// The header a credential is written in: one of V02's
/// [`RESERVED_CREDENTIAL_HEADERS`](crate::sandbox_contract::destinations::RESERVED_CREDENTIAL_HEADERS),
/// which a guest may never send on a credentialed route,
/// so the injected header can never meet a copy from the guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialHeader {
    Authorization,
    ProxyAuthorization,
    Cookie,
}

impl CredentialHeader {
    /// The header's name as written on the wire.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Authorization => "authorization",
            Self::ProxyAuthorization => "proxy-authorization",
            Self::Cookie => "cookie",
        }
    }

    fn name_bytes(self) -> u64 {
        u64::try_from(self.name().len()).unwrap_or(u64::MAX)
    }
}

/// What a credentialed route's audience is granted: the header the credential goes in,
/// and the provider contract and account a use of it is scoped to (VM-W28).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialAudience {
    pub header: CredentialHeader,
    /// The provider whose contract the route's operations are.
    pub provider: ProviderId,
    pub contract_version: u32,
    pub account: AccountRef,
}

/// The vault as the relay broker's executor uses it (§4.5 line 2004). S04/S05 own the real
/// one; the tests use a fake.
pub trait HeaderVault: Send + Sync {
    /// The credential's facts (its class and the length of the header value the vault
    /// composes), if the vault's own grant covers `scope` at `now`.
    fn facts(&self, scope: &VaultScope, now: MonotonicTime) -> Result<VaultFacts, VaultRefusal>;

    /// The header value composed from the credential `scope` names, such as
    /// `Bearer <token>`, for the injector to write on the wire and for nothing else.
    fn header_value(
        &self,
        scope: &VaultScope,
        now: MonotonicTime,
    ) -> Result<SecretValue, VaultRefusal>;

    /// Whether `bytes` contain the credential `scope` names, or a value composed from it,
    /// in a scanned encoding, without revealing either (as V07's
    /// [`CredentialVault::reflects_secret`](crate::sandbox_contract::provider::CredentialVault::reflects_secret)).
    fn reflects_secret(&self, scope: &VaultScope, bytes: &[u8]) -> Option<ScanEncoding>;
}

/// Why the credential could not be added. Nothing here holds the credential.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InjectionRefusal {
    /// The route is credentialed but no audience is configured for it.
    NoAudience { route: RouteId },
    /// The bound operation's name is not a provider contract name.
    OperationNotContract { operation: String },
    /// The grant table does not cover the use.
    Grant(VaultRefusal),
    /// The vault refused the use.
    Vault(VaultRefusal),
    /// The vault reports another class than the grant.
    ClassMismatch {
        granted: SecretClass,
        vault: SecretClass,
    },
    /// The vault's value cannot be written as a header value.
    InvalidHeaderValue,
    /// The header is longer than the vault's facts said, so it would overrun the send
    /// reservation.
    OverAllowance { allowance: u64, bytes: u64 },
    /// The request already carries the credential header.
    GuestCredentialHeader { header: CredentialHeader },
    /// The request has no complete head to add the header to.
    MalformedHead,
}

impl fmt::Display for InjectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoAudience { route } => {
                write!(f, "route {route} has no credential audience configured")
            }
            Self::OperationNotContract { operation } => {
                write!(f, "operation {operation:?} is not a provider contract name")
            }
            Self::Grant(refusal) => write!(f, "the grant table refused: {refusal}"),
            Self::Vault(refusal) => write!(f, "the vault refused: {refusal}"),
            Self::ClassMismatch { granted, vault } => write!(
                f,
                "the grant is for a {granted:?} but the vault holds a {vault:?}"
            ),
            Self::InvalidHeaderValue => {
                f.write_str("the vault's value cannot be written as a header value")
            }
            Self::OverAllowance { allowance, bytes } => write!(
                f,
                "the {bytes}-byte credential header is over its {allowance}-byte allowance"
            ),
            Self::GuestCredentialHeader { header } => write!(
                f,
                "the request already carries the {} header",
                header.name()
            ),
            Self::MalformedHead => f.write_str("the request has no complete head"),
        }
    }
}

impl std::error::Error for InjectionRefusal {}

/// The bytes sent upstream: the forward decision's bytes plus, on a credentialed route,
/// the credential header. `Debug` shows only the length, only the transport reads the
/// bytes, and the buffer is overwritten when dropped (best effort).
pub struct UpstreamBytes(Vec<u8>);

impl UpstreamBytes {
    pub(super) fn new(bytes: Vec<u8>) -> Self {
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

impl fmt::Debug for UpstreamBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "UpstreamBytes({} bytes)", self.0.len())
    }
}

impl Drop for UpstreamBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// One use of the credential, planned before any reservation: its scope, its header and
/// the bytes the header line will take.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CredentialPlan {
    scope: VaultScope,
    header: CredentialHeader,
    allowance: u64,
}

impl CredentialPlan {
    pub fn scope(&self) -> &VaultScope {
        &self.scope
    }

    pub const fn header(&self) -> CredentialHeader {
        self.header
    }

    /// The bytes of the header line, `name: value` and the line end, which the relay step
    /// reserves as the credential allowance.
    pub const fn allowance(&self) -> u64 {
        self.allowance
    }
}

/// The upstream bytes with the credential added, and the scan that looks for it.
#[derive(Debug)]
pub(super) struct Injected {
    pub(super) bytes: UpstreamBytes,
    pub(super) echo: EchoScan,
}

/// Adds the credential the route's audience is granted, and nothing else (see the module
/// notes).
pub struct CredentialInjector {
    executor: ExecutorName,
    session: ClockSession,
    clock: Arc<dyn Clock>,
    grants: Mutex<GrantTable>,
    vault: Arc<dyn HeaderVault>,
    audiences: BTreeMap<RouteId, CredentialAudience>,
}

impl fmt::Debug for CredentialInjector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialInjector")
            .field("executor", &self.executor)
            .field("session", &self.session)
            .field("audiences", &self.audiences.len())
            .finish_non_exhaustive()
    }
}

impl CredentialInjector {
    /// An injector for `executor`, with no grants and no audiences. Grant expiry is judged
    /// on `clock`, which must be the clock of `session`.
    pub fn new(
        executor: ExecutorName,
        session: ClockSession,
        clock: Arc<dyn Clock>,
        vault: Arc<dyn HeaderVault>,
    ) -> Self {
        Self {
            executor,
            session,
            clock,
            grants: Mutex::new(GrantTable::new()),
            vault,
            audiences: BTreeMap::new(),
        }
    }

    /// Configures the audience of the credentialed route `route`.
    pub fn with_audience(mut self, route: RouteId, audience: CredentialAudience) -> Self {
        self.audiences.insert(route, audience);
        self
    }

    pub fn executor(&self) -> &ExecutorName {
        &self.executor
    }

    /// Records a grant in the table (V07: a grant may narrow but never widen).
    pub fn grant(&self, grant: VaultGrant) -> Result<(), VaultRefusal> {
        self.table().grant(grant)
    }

    /// Revokes a credential reference now; nothing is sent with it again.
    pub fn revoke(&self, credential: CredentialRef) -> bool {
        let now = self.clock.now();
        self.table().revoke(credential, now)
    }

    fn table(&self) -> std::sync::MutexGuard<'_, GrantTable> {
        self.grants.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Plans the credential for `bound` on `route_id`: `None` on a route without a
    /// credential. The grant table and the vault's facts are checked now, before anything
    /// is reserved.
    pub fn plan(
        &self,
        route_id: &RouteId,
        route: &OperationRoute,
        bound: &BoundRequest,
    ) -> Result<Option<CredentialPlan>, InjectionRefusal> {
        let Some(credential) = route.credential() else {
            return Ok(None);
        };
        let audience =
            self.audiences
                .get(route_id)
                .ok_or_else(|| InjectionRefusal::NoAudience {
                    route: route_id.clone(),
                })?;
        let operation = ContractName::new(bound.operation.as_str()).map_err(|_| {
            InjectionRefusal::OperationNotContract {
                operation: bound.operation.as_str().to_owned(),
            }
        })?;
        let scope = VaultScope {
            credential,
            executor: self.executor.clone(),
            operation: OperationKey {
                provider: audience.provider.clone(),
                operation,
                contract_version: audience.contract_version,
            },
            route: DestinationBinding::route_ref_for(&bound.authority),
            account: audience.account,
        };
        let now = self.clock.now();
        let granted = self
            .table()
            .permits(&scope, now, self.session)
            .map_err(InjectionRefusal::Grant)?;
        let facts = self
            .vault
            .facts(&scope, now)
            .map_err(InjectionRefusal::Vault)?;
        if facts.class != granted {
            return Err(InjectionRefusal::ClassMismatch {
                granted,
                vault: facts.class,
            });
        }
        let allowance = audience
            .header
            .name_bytes()
            .saturating_add(HEADER_LINE_OVERHEAD)
            .saturating_add(facts.authorization_header_bytes);
        Ok(Some(CredentialPlan {
            scope,
            header: audience.header,
            allowance,
        }))
    }

    /// Adds the planned header to `request`, the forward decision's bytes, just before
    /// the end of its head, after checking the grant again. `known` are the fixture
    /// secrets and canaries the echo scan also looks for.
    pub(super) fn inject(
        &self,
        plan: &CredentialPlan,
        request: &[u8],
        known: Arc<KnownSecrets>,
    ) -> Result<Injected, InjectionRefusal> {
        let head_end = find(request, HEAD_END).ok_or(InjectionRefusal::MalformedHead)?;
        let head = request.get(..head_end).unwrap_or_default();
        if carries_header(head, plan.header) {
            return Err(InjectionRefusal::GuestCredentialHeader {
                header: plan.header,
            });
        }
        let now = self.clock.now();
        self.table()
            .permits(&plan.scope, now, self.session)
            .map_err(InjectionRefusal::Grant)?;
        let value = self
            .vault
            .header_value(&plan.scope, now)
            .map_err(InjectionRefusal::Vault)?;
        if !is_header_value(value.expose_to_transport()) {
            return Err(InjectionRefusal::InvalidHeaderValue);
        }
        let line = plan
            .header
            .name_bytes()
            .saturating_add(HEADER_LINE_OVERHEAD)
            .saturating_add(value.len_bytes());
        if line > plan.allowance {
            return Err(InjectionRefusal::OverAllowance {
                allowance: plan.allowance,
                bytes: line,
            });
        }
        // The head ends with its last header line's CRLF, then the empty line's CRLF; the
        // credential line goes between them.
        let split = head_end.saturating_add(2);
        let capacity = request
            .len()
            .saturating_add(value.expose_to_transport().len());
        let mut bytes = Vec::with_capacity(capacity);
        bytes.extend_from_slice(request.get(..split).unwrap_or_default());
        bytes.extend_from_slice(plan.header.name().as_bytes());
        bytes.extend_from_slice(b": ");
        bytes.extend_from_slice(value.expose_to_transport());
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(request.get(split..).unwrap_or_default());
        Ok(Injected {
            bytes: UpstreamBytes::new(bytes),
            echo: EchoScan {
                known,
                credential: Some(InjectedCredential {
                    scope: plan.scope.clone(),
                    value,
                    vault: Arc::clone(&self.vault),
                }),
            },
        })
    }
}

/// Whether a header value is visible ASCII with inner spaces or tabs only: no control
/// byte, no line break, no surrounding whitespace, not empty.
fn is_header_value(value: &[u8]) -> bool {
    let inner = |byte: &u8| byte.is_ascii_graphic() || *byte == b' ' || *byte == b'\t';
    let edge = |byte: Option<&u8>| byte.is_some_and(u8::is_ascii_graphic);
    value.iter().all(inner) && edge(value.first()) && edge(value.last())
}

/// Whether some line of `head` after the request line is the header `header`.
fn carries_header(head: &[u8], header: CredentialHeader) -> bool {
    let name = header.name().as_bytes();
    head.split(|byte| *byte == b'\n').skip(1).any(|line| {
        line.len() > name.len()
            && line
                .get(..name.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(name))
            && line.get(name.len()) == Some(&b':')
    })
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The part of a guest response a secret was found in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponsePart {
    /// The status line and the header fields.
    Head,
    Body,
    /// Only the whole response, head and body together.
    Whole,
}

/// Where and how a secret was found in a response; never what.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EchoFinding {
    pub part: ResponsePart,
    pub source: LeakSource,
    pub encoding: ScanEncoding,
}

impl fmt::Display for EchoFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the response's {:?} reflects a {:?} ({:?})",
            self.part, self.source, self.encoding
        )
    }
}

struct InjectedCredential {
    scope: VaultScope,
    value: SecretValue,
    vault: Arc<dyn HeaderVault>,
}

/// The scan of one exchange's response (see the module notes). `Debug` shows no secret.
pub struct EchoScan {
    known: Arc<KnownSecrets>,
    credential: Option<InjectedCredential>,
}

impl fmt::Debug for EchoScan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EchoScan")
            .field("known", &self.known)
            .field("credential", &self.credential.is_some())
            .finish()
    }
}

impl EchoScan {
    /// A scan for the known fixture secrets and canaries alone, for a route without a
    /// credential.
    pub fn known_only(known: Arc<KnownSecrets>) -> Self {
        Self {
            known,
            credential: None,
        }
    }

    /// The first secret found in `response`: in its head, then its body, then the whole.
    pub fn scan(&self, response: &[u8]) -> Option<EchoFinding> {
        let (head, body) = match find(response, HEAD_END) {
            Some(end) => {
                let split = end.saturating_add(HEAD_END.len());
                (
                    response.get(..split).unwrap_or_default(),
                    response.get(split..).unwrap_or_default(),
                )
            }
            None => (response, &[][..]),
        };
        [
            (ResponsePart::Head, head),
            (ResponsePart::Body, body),
            (ResponsePart::Whole, response),
        ]
        .into_iter()
        .find_map(|(part, bytes)| {
            self.find(bytes).map(|(source, encoding)| EchoFinding {
                part,
                source,
                encoding,
            })
        })
    }

    fn find(&self, bytes: &[u8]) -> Option<(LeakSource, ScanEncoding)> {
        if let Some(credential) = &self.credential {
            let found = find_encoded(bytes, credential.value.expose_to_transport())
                .or_else(|| credential.vault.reflects_secret(&credential.scope, bytes));
            if let Some(encoding) = found {
                return Some((LeakSource::VaultCredential, encoding));
            }
        }
        self.known.find(bytes)
    }
}
