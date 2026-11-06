//! KV reuse keys and tenant scope (GPU §3.9 line 636; FAST-03 at line 243).
//!
//! Line 636 binds model, adapter, token prefix, tokenizer, positional encoding,
//! attention semantics, KV dtype and layout, and rank. T07's FAST-03 [`KvScopeSpec`]
//! binds all of these except attention semantics and the rank position, together with
//! the tenant and session authority; [`KvReuseSpec`] adds the two. Neither is covered
//! by T07's `ExecutionIdentity`, which binds the rank topology (how many ranks) but not
//! which rank's shard the KV is, and no runtime attention options.
//!
//! The trust scope, the tenant-scoped default, explicitly configured public-prefix
//! sharing ([`PublicPrefixSharing`]), revocation of the authorities involved and the
//! backend's scope enforcement are all T07's: [`check_kv_reuse`] asks
//! [`identity::check_scoped_kv_reuse`] first and adds only the attention semantics and
//! the rank position. A successful check returns a [`KvReuseGrant`], the only way to
//! offer stored KV to [`super::placement::decide_kv_placement`].

use std::fmt;

use crate::foundation::ids::{Digest, DigestBuilder, MonotonicTime, TrustScope};
use crate::model_memory::identity::{
    self, ExecutionIdentity, KvRepresentation, KvReuseRequest, KvReuseScope, KvScopeSpec,
    PositionalEncoding, RevocationPort, ScopeEnforcement,
};

/// T07's sharing vocabulary, which stored KV and the check below use.
pub use crate::model_memory::identity::{KvSharing, PublicPrefixScope, PublicPrefixSharing};

/// Which shard of a parallel rank topology a KV state belongs to (line 636).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RankPosition {
    index: u32,
    world_size: u32,
}

impl RankPosition {
    /// Rank `index` of `world_size`; refused unless `index < world_size`.
    pub fn new(index: u32, world_size: u32) -> Option<Self> {
        (index < world_size).then_some(Self { index, world_size })
    }

    pub fn index(self) -> u32 {
        self.index
    }

    pub fn world_size(self) -> u32 {
        self.world_size
    }
}

/// Every component line 636 binds: T07's scope spec plus the attention semantics and
/// the rank position.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvReuseSpec {
    pub scope: KvScopeSpec,
    /// Digest of the attention semantics: masking, windows, sink tokens and any runtime
    /// attention option.
    pub attention_semantics: Digest,
    pub rank: RankPosition,
}

/// A KV state as stored (line 636).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredKv {
    pub spec: KvReuseSpec,
    pub trust_scope: TrustScope,
    pub sharing: KvSharing,
}

impl StoredKv {
    /// The state's reuse scope in T07's terms: its FAST-03 components, trust scope and
    /// sharing.
    pub fn reuse_scope(&self) -> KvReuseScope {
        KvReuseScope {
            spec: self.spec.scope.clone(),
            trust_scope: self.trust_scope,
            sharing: self.sharing,
        }
    }
}

/// The KV a request needs, under the requester's own authority and trust scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvRequest {
    pub spec: KvReuseSpec,
    pub trust_scope: TrustScope,
}

impl KvRequest {
    /// The request in T07's terms.
    pub fn reuse_request(&self) -> KvReuseRequest {
        KvReuseRequest {
            spec: self.spec.scope.clone(),
            trust_scope: self.trust_scope,
        }
    }
}

/// Domain of [`kv_state_key`].
pub const KV_STATE_DOMAIN: &str = "yougori/model-memory/adapters/kv-state/v2";

/// The identity of a stored KV state (line 636): T07's FAST-03 scope key, which names the
/// session that made it, T07's reuse key, which binds the trust scope and the sharing,
/// the attention semantics and the rank position. The restore requirement of
/// [`crate::model_memory::math::recompute`] names this key as its state.
pub fn kv_state_key(stored: &StoredKv) -> Digest {
    DigestBuilder::new(KV_STATE_DOMAIN)
        .digest(stored.spec.scope.key().digest())
        .digest(stored.reuse_scope().key().digest())
        .digest(&stored.spec.attention_semantics)
        .u64(u64::from(stored.spec.rank.index()))
        .u64(u64::from(stored.spec.rank.world_size()))
        .finish()
}

/// Why stored KV may not be reused (line 636).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KvReuseRefusal {
    /// T07 refused: another trust scope, a revoked authority, a backend that does not
    /// enforce the scope, public-prefix sharing that is not configured or no longer
    /// stands, KV beyond its public prefix, or differing scope components.
    Scope(identity::KvReuseRefusal),
    AttentionSemanticsMismatch,
    RankMismatch,
}

impl fmt::Display for KvReuseRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Scope(refusal) => refusal.fmt(f),
            Self::AttentionSemanticsMismatch => {
                f.write_str("the KV was computed with other attention semantics")
            }
            Self::RankMismatch => f.write_str("the KV belongs to another rank"),
        }
    }
}

impl std::error::Error for KvReuseRefusal {}

/// Proof that one stored KV state may serve one request; made only by
/// [`check_kv_reuse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KvReuseGrant {
    key: Digest,
}

impl KvReuseGrant {
    /// The stored KV state's key ([`kv_state_key`]).
    pub fn key(&self) -> Digest {
        self.key
    }
}

/// Checks that `request` may reuse `stored` at `now` (line 636). T07's check comes
/// first ([`identity::check_scoped_kv_reuse`]): one trust scope, no revoked authority
/// (`revocations`), a backend verified to enforce the scope by fresh evidence, and every
/// scope component equal; for public-prefix KV, the prefix allowed in `sharing` under an
/// authority that still stands, nothing stored beyond it and every component but the
/// tenant and session authority equal. Attention semantics and the rank position must
/// then match.
pub fn check_kv_reuse(
    stored: &StoredKv,
    request: &KvRequest,
    sharing: &PublicPrefixSharing,
    revocations: &dyn RevocationPort,
    enforcement: &ScopeEnforcement,
    now: MonotonicTime,
) -> Result<KvReuseGrant, KvReuseRefusal> {
    identity::check_scoped_kv_reuse(
        &stored.reuse_scope(),
        &request.reuse_request(),
        sharing,
        revocations,
        enforcement,
        now,
    )
    .map_err(KvReuseRefusal::Scope)?;
    if stored.spec.attention_semantics != request.spec.attention_semantics {
        return Err(KvReuseRefusal::AttentionSemanticsMismatch);
    }
    if stored.spec.rank != request.spec.rank {
        return Err(KvReuseRefusal::RankMismatch);
    }
    Ok(KvReuseGrant {
        key: kv_state_key(stored),
    })
}

/// What a resident engine can reuse (line 642, "its engine can use it").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EngineKvProfile {
    pub model: ExecutionIdentity,
    pub tokenizer: Digest,
    pub positional_encoding: PositionalEncoding,
    pub cache: KvRepresentation,
    pub attention_semantics: Digest,
    pub rank: RankPosition,
    /// Whether the engine reuses stored prefix KV at all.
    pub reuses_prefix_kv: bool,
    /// Whether its backend is verified to enforce the KV scope (FAST-03).
    pub enforcement: ScopeEnforcement,
}

impl EngineKvProfile {
    /// True when the engine reuses prefix KV under a verified scope and matches every
    /// engine-side component of the KV. The prefix and adapter belong to the request;
    /// the graph keeps the adapter resident while KV depends on it.
    pub fn can_use(&self, kv: &KvReuseSpec) -> bool {
        self.reuses_prefix_kv
            && self.enforcement.is_verified()
            && self.model == kv.scope.model
            && self.tokenizer == kv.scope.tokenizer
            && self.positional_encoding == kv.scope.position.encoding
            && self.cache == kv.scope.cache
            && self.attention_semantics == kv.attention_semantics
            && self.rank == kv.rank
    }
}

#[cfg(test)]
mod tests;
