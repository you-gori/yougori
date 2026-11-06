//! The FAST-03 KV-reuse scope key (S13, line 243: "Bind reusable blocks to exact
//! model/tokenizer/adapter/prefix/position/cache representation and tenant/session
//! authority; verify that the backend enforces this scope before enabling cross-request
//! reuse"), and the sharing of §3.9 line 636: "Sessions remain tenant-scoped unless
//! explicitly configured for public-prefix sharing".
//!
//! Reuse across requests needs every component to match and CORE-01 evidence that the
//! backend enforces the scope. If the backend cannot enforce it, the tier stays
//! disabled. A block is tenant-scoped unless [`PublicPrefixSharing`] lists its prefix as
//! public in its trust scope; then any tenant in that trust scope may reuse it, provided
//! every component but the tenant and session authority matches and the block holds
//! nothing beyond the public prefix. KV never crosses a trust scope (S3.3).
//!
//! Every public prefix is allowed under an authority, and every block is made and
//! requested under one. A [`RevocationPort`] answers whether each still stands, so a
//! revocation by the coordination authority (T09) ends the allowance, and the reuse of
//! anything its revoked authority made or asks for, at the next check.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::evidence::Satisfied;
use crate::foundation::ids::{Digest, MonotonicTime, TenantId, TrustScope};

use super::adapter::AdapterIdentity;
use super::encoding::{identity_type, Encoding, KV_REUSE_DOMAIN, KV_SCOPE_DOMAIN};
use super::fields::{AuthorityBinding, KvRepresentation, PositionalEncoding, TokenPrefix};
use super::layers::ExecutionIdentity;
use super::revocation::RevocationPort;

identity_type!(
    /// The scope a reusable KV block is bound to (FAST-03). Built only by
    /// [`KvScopeSpec::key`].
    KvScopeKey
);

identity_type!(
    /// The key a stored KV block is reused under: its FAST-03 components, its trust scope
    /// and its sharing (§3.9 line 636). A tenant-scoped key binds the tenant and session
    /// authority; a public-prefix key binds the public prefix instead. Built only by
    /// [`KvReuseScope::key`].
    KvReuseKey
);

/// Where the reused tokens sit: the positional encoding and the first position
/// (FAST-03 "position").
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KvPosition {
    pub encoding: PositionalEncoding,
    pub first_position: u64,
}

/// Whose KV this is (FAST-03 "tenant/session authority"): the tenant and the session's
/// S3.1 authority binding, both bound.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KvAuthority {
    pub tenant: TenantId,
    pub session: AuthorityBinding,
}

/// The components a reusable KV block is bound to (FAST-03).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvScopeSpec {
    /// The exact model as executed.
    pub model: ExecutionIdentity,
    /// The tokenizer digest, bound explicitly as FAST-03 lists it.
    pub tokenizer: Digest,
    pub adapter: Option<AdapterIdentity>,
    /// Every token up to the end of the reused block.
    pub prefix: TokenPrefix,
    pub position: KvPosition,
    pub cache: KvRepresentation,
    pub authority: KvAuthority,
}

/// One component of a [`KvScopeSpec`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KvScopeComponent {
    Model,
    Tokenizer,
    Adapter,
    Prefix,
    Position,
    CacheRepresentation,
    Tenant,
    SessionAuthority,
}

impl KvScopeComponent {
    pub const ALL: [Self; 8] = [
        Self::Model,
        Self::Tokenizer,
        Self::Adapter,
        Self::Prefix,
        Self::Position,
        Self::CacheRepresentation,
        Self::Tenant,
        Self::SessionAuthority,
    ];

    /// Whether the component names whose KV it is: the tenant or the session authority.
    /// Public-prefix sharing is the one case that ignores them (§3.9 line 636).
    pub const fn is_authority(self) -> bool {
        matches!(self, Self::Tenant | Self::SessionAuthority)
    }
}

/// Whether the pinned backend is verified to enforce the KV scope (FAST-03).
///
/// Verification is CORE-01 evidence, and only a probe registry's evaluation makes a
/// [`Satisfied`], so no claim can be written by hand. CORE-01 has no capability for KV
/// scope enforcement yet, so until the batched evidence additions add one, the caller
/// decides which evaluated requirement shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeEnforcement {
    /// The backend enforces the scope, as of this evidence.
    Verified { evidence: Satisfied },
    /// No evidence, so the tier stays disabled.
    NotVerified,
}

impl ScopeEnforcement {
    /// Whether the backend is verified to enforce the scope, at any time.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// The evidence, if the backend is verified and the evidence is fresh at `now`: no
    /// later than [`Satisfied::fresh_until`] on the registry's clock, which the caller
    /// shares.
    pub fn fresh_at(&self, now: MonotonicTime) -> Result<&Satisfied, KvReuseRefusal> {
        match self {
            Self::NotVerified => Err(KvReuseRefusal::BackendDoesNotEnforceScope),
            Self::Verified { evidence } if now > evidence.fresh_until() => {
                Err(KvReuseRefusal::EnforcementEvidenceStale {
                    fresh_until: evidence.fresh_until(),
                    now,
                })
            }
            Self::Verified { evidence } => Ok(evidence),
        }
    }
}

/// Why a stored KV block may not be reused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvReuseRefusal {
    /// The backend is not verified to enforce the scope, so the tier stays disabled.
    BackendDoesNotEnforceScope,
    /// The evidence that the backend enforces the scope is no longer fresh.
    EnforcementEvidenceStale {
        fresh_until: MonotonicTime,
        now: MonotonicTime,
    },
    /// At least one component differs.
    ScopeMismatch { components: Vec<KvScopeComponent> },
    /// The block lives in another trust scope; KV never crosses one (S3.3).
    OtherTrustScope,
    /// The block claims a public prefix that the configuration does not list for its
    /// trust scope.
    PublicPrefixNotConfigured,
    /// The block holds more than its public prefix, so it may carry tenant state.
    BeyondPublicPrefix,
    /// Every authority that allowed the public prefix was revoked (T09).
    PublicPrefixRevoked,
    /// The block was made under an authority since revoked, so nothing it made is
    /// reused (S3.1).
    ProducerRevoked,
    /// The request runs under a revoked authority, which is granted nothing (S3.1).
    RequesterRevoked,
}

impl fmt::Display for KvReuseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BackendDoesNotEnforceScope => f.write_str(
                "the KV backend is not verified to enforce the reuse scope; the tier stays disabled",
            ),
            Self::EnforcementEvidenceStale { fresh_until, now } => write!(
                f,
                "the evidence that the KV backend enforces the reuse scope was fresh until {} ns; it is now {} ns",
                fresh_until.as_nanos(),
                now.as_nanos()
            ),
            Self::ScopeMismatch { components } => {
                write!(f, "the KV scope differs in {components:?}")
            }
            Self::OtherTrustScope => f.write_str("the KV belongs to another trust scope"),
            Self::PublicPrefixNotConfigured => {
                f.write_str("the prefix is not configured for public sharing in this trust scope")
            }
            Self::BeyondPublicPrefix => f.write_str("the KV extends beyond its public prefix"),
            Self::PublicPrefixRevoked => {
                f.write_str("every authority that allowed the public prefix was revoked")
            }
            Self::ProducerRevoked => {
                f.write_str("the KV was made under an authority that has since been revoked")
            }
            Self::RequesterRevoked => f.write_str("the request runs under a revoked authority"),
        }
    }
}

impl std::error::Error for KvReuseRefusal {}

impl KvScopeSpec {
    /// FAST-03: the key over every scope component.
    pub fn key(&self) -> KvScopeKey {
        KvScopeKey(self.canonical().finish(KV_SCOPE_DOMAIN))
    }

    /// Every component in which `self` and `other` differ.
    pub fn mismatches(&self, other: &Self) -> Vec<KvScopeComponent> {
        [
            (KvScopeComponent::Model, self.model != other.model),
            (
                KvScopeComponent::Tokenizer,
                self.tokenizer != other.tokenizer,
            ),
            (KvScopeComponent::Adapter, self.adapter != other.adapter),
            (KvScopeComponent::Prefix, self.prefix != other.prefix),
            (KvScopeComponent::Position, self.position != other.position),
            (
                KvScopeComponent::CacheRepresentation,
                self.cache != other.cache,
            ),
            (
                KvScopeComponent::Tenant,
                self.authority.tenant != other.authority.tenant,
            ),
            (
                KvScopeComponent::SessionAuthority,
                self.authority.session != other.authority.session,
            ),
        ]
        .into_iter()
        .filter_map(|(component, differs)| differs.then_some(component))
        .collect()
    }

    pub(crate) fn canonical(&self) -> Encoding {
        let mut out = Encoding::new();
        self.encode_components(&mut out);
        out.item(&self.authority.tenant)
            .item(&self.authority.session);
        out
    }

    /// Every component except the tenant and session authority.
    fn encode_components(&self, out: &mut Encoding) {
        out.item(&self.model)
            .item(&self.tokenizer)
            .option(self.adapter.as_ref())
            .item(&self.prefix)
            .item(&self.position.encoding)
            .u64(self.position.first_position)
            .item(&self.cache);
    }
}

/// FAST-03: a block stored under `stored` may serve `request` only when the backend is
/// verified to enforce the scope and the two keys are equal, that is, every component
/// matches. Returns the shared key.
///
/// This check has no clock, so it does not judge the evidence's freshness and knows no
/// trust scope or sharing; [`check_scoped_kv_reuse`] does both.
pub fn check_kv_reuse(
    stored: &KvScopeSpec,
    request: &KvScopeSpec,
    enforcement: &ScopeEnforcement,
) -> Result<KvScopeKey, KvReuseRefusal> {
    if !enforcement.is_verified() {
        return Err(KvReuseRefusal::BackendDoesNotEnforceScope);
    }
    let key = stored.key();
    if key == request.key() {
        return Ok(key);
    }
    Err(KvReuseRefusal::ScopeMismatch {
        components: stored.mismatches(request),
    })
}

/// Who besides its own tenant and session may reuse a stored KV block (§3.9 line 636).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KvSharing {
    /// The default: only the tenant and session authority in the block's scope (FAST-03).
    TenantScoped,
    /// Any tenant in the block's trust scope, while [`PublicPrefixSharing`] lists
    /// `prefix` as public there. The block holds exactly this prefix.
    PublicPrefix { prefix: TokenPrefix },
}

/// One prefix configured as public in one trust scope (§3.9 line 636).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicPrefixScope {
    pub prefix: TokenPrefix,
    pub trust_scope: TrustScope,
}

/// The explicit configuration of public prefixes (§3.9 line 636: "unless explicitly
/// configured for public-prefix sharing"). Empty by default, so nothing is shared across
/// tenants unless configured.
///
/// Each allowance is made under an authority and lasts while that authority stands: a
/// revocation by the coordination authority (T09) ends it at the next check, and
/// [`PublicPrefixSharing::revoke`] ends every allowance of a prefix at once.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PublicPrefixSharing {
    allowed: BTreeMap<PublicPrefixScope, BTreeSet<AuthorityBinding>>,
}

impl PublicPrefixSharing {
    /// No prefix is shared.
    pub fn none() -> Self {
        Self::default()
    }

    /// Configures one prefix as public within one trust scope, under `authority`, such as
    /// the sandbox whose sessions publish it. The allowance ends when that authority is
    /// revoked.
    pub fn allow(&mut self, scope: PublicPrefixScope, authority: AuthorityBinding) {
        self.allowed.entry(scope).or_default().insert(authority);
    }

    /// Stops sharing one prefix in one trust scope, under every authority; true if it was
    /// configured.
    pub fn revoke(&mut self, scope: &PublicPrefixScope) -> bool {
        self.allowed.remove(scope).is_some()
    }

    /// Whether exactly this prefix is configured as public in exactly this trust scope,
    /// whether or not its authorities still stand.
    pub fn is_configured(&self, scope: &PublicPrefixScope) -> bool {
        self.allowed.contains_key(scope)
    }

    /// Whether exactly this prefix is public in exactly this trust scope now: allowed
    /// under at least one authority `revocations` has not revoked.
    pub fn allows(&self, scope: &PublicPrefixScope, revocations: &dyn RevocationPort) -> bool {
        self.allowed.get(scope).is_some_and(|authorities| {
            authorities
                .iter()
                .any(|authority| !revocations.is_revoked(authority))
        })
    }
}

/// A stored KV block's reuse scope: its FAST-03 components, the trust scope it lives in
/// and how it is shared (§3.9 line 636).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvReuseScope {
    pub spec: KvScopeSpec,
    pub trust_scope: TrustScope,
    pub sharing: KvSharing,
}

impl KvReuseScope {
    /// The key the block is reused under, in its own domain. A tenant-scoped key binds
    /// every FAST-03 component; a public-prefix key binds every component but the tenant
    /// and session authority, plus the public prefix, so tenants reusing one public block
    /// share one key. Both bind the trust scope and the sharing.
    pub fn key(&self) -> KvReuseKey {
        let mut out = Encoding::new();
        out.item(&self.trust_scope);
        match &self.sharing {
            KvSharing::TenantScoped => {
                out.tag("tenant_scoped");
                self.spec.encode_components(&mut out);
                out.item(&self.spec.authority.tenant)
                    .item(&self.spec.authority.session);
            }
            KvSharing::PublicPrefix { prefix } => {
                out.tag("public_prefix").item(prefix);
                self.spec.encode_components(&mut out);
            }
        }
        KvReuseKey(out.finish(KV_REUSE_DOMAIN))
    }
}

/// The KV a request needs, under the requester's own authority and trust scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvReuseRequest {
    pub spec: KvScopeSpec,
    pub trust_scope: TrustScope,
}

/// §3.9 line 636 and FAST-03: whether `request` may reuse the block stored under
/// `stored`, at `now`. Returns the block's [`KvReuseKey`].
///
/// In order: the trust scopes must be equal; neither the request's nor the block's
/// session authority may be revoked (`revocations`, T09); the backend must be verified
/// to enforce the scope by evidence still fresh at `now`; a public-prefix block needs
/// its prefix allowed in `sharing` for its trust scope under an authority that still
/// stands, and nothing stored beyond that prefix; then every component must match,
/// except the tenant and session authority for a public-prefix block.
pub fn check_scoped_kv_reuse(
    stored: &KvReuseScope,
    request: &KvReuseRequest,
    sharing: &PublicPrefixSharing,
    revocations: &dyn RevocationPort,
    enforcement: &ScopeEnforcement,
    now: MonotonicTime,
) -> Result<KvReuseKey, KvReuseRefusal> {
    if stored.trust_scope != request.trust_scope {
        return Err(KvReuseRefusal::OtherTrustScope);
    }
    if revocations.is_revoked(&request.spec.authority.session) {
        return Err(KvReuseRefusal::RequesterRevoked);
    }
    if revocations.is_revoked(&stored.spec.authority.session) {
        return Err(KvReuseRefusal::ProducerRevoked);
    }
    enforcement.fresh_at(now)?;
    let mismatches = stored.spec.mismatches(&request.spec);
    let components: Vec<KvScopeComponent> = match stored.sharing {
        KvSharing::TenantScoped => mismatches,
        KvSharing::PublicPrefix { prefix } => {
            let configured = PublicPrefixScope {
                prefix,
                trust_scope: stored.trust_scope,
            };
            if !sharing.is_configured(&configured) {
                return Err(KvReuseRefusal::PublicPrefixNotConfigured);
            }
            if !sharing.allows(&configured, revocations) {
                return Err(KvReuseRefusal::PublicPrefixRevoked);
            }
            if stored.spec.prefix != prefix {
                return Err(KvReuseRefusal::BeyondPublicPrefix);
            }
            mismatches
                .into_iter()
                .filter(|component| !component.is_authority())
                .collect()
        }
    };
    if !components.is_empty() {
        return Err(KvReuseRefusal::ScopeMismatch { components });
    }
    Ok(stored.key())
}
