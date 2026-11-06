//! Who reads and what is read, in the catalog's terms (CORE-02, T05; S3.3).
//!
//! An [`ObjectRef`] names a catalog object by the parts its [`ObjectId`] binds: the
//! owning scope, the artifact class and the content key. Tiers that hold bytes outside
//! the catalog (a peer, a remote, host RAM) describe them this way, so the scope is
//! never inferred from content and equal content in another scope stays another object.
//! A [`Consumer`] is a tenant's execution and the trust scope it runs in. An
//! [`ObjectCopy`] is a copy a tier holds, with the object it copies.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::foundation::catalog::{ArtifactClass, ObjectId, Scope};
use crate::foundation::ids::{ContentKey, ExecutionId, TenantId, TrustScope};
use crate::model_memory::residency::eviction::ReconstructibleCopy;

/// A catalog object named by its parts (CORE-02 scoped content identity).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectRef {
    /// The scope that owns the object.
    pub scope: Scope,
    pub class: ArtifactClass,
    pub content: ContentKey,
}

impl ObjectRef {
    /// The catalog identity these parts bind.
    pub fn id(&self) -> ObjectId {
        ObjectId::new(&self.scope, self.class, self.content)
    }

    /// The owning tenant; `None` for Yougori's own host scope.
    pub fn tenant(&self) -> Option<&TenantId> {
        self.scope.tenant_id()
    }
}

impl fmt::Display for ObjectRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} of {}", self.class, self.content, self.scope)
    }
}

/// A tenant's execution that reads and holds bytes, and the trust scope it runs in
/// (line 546; S3.3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Consumer {
    pub tenant: TenantId,
    pub execution: ExecutionId,
    pub trust: TrustScope,
}

impl Consumer {
    /// The catalog scope the consumer reads for: its tenant's.
    pub fn scope(&self) -> Scope {
        Scope::tenant(self.tenant.clone())
    }

    /// Whether `other` runs for the same tenant in the same trust scope, the only case in
    /// which processed weights or state may be shared (S3.3).
    pub fn shares_trust_with(&self, other: &Consumer) -> bool {
        self.tenant == other.tenant && self.trust == other.trust
    }
}

/// A copy a tier holds outside the GPU, with the object it copies (§1.1 line 307; S3.3).
///
/// T08's [`ReconstructibleCopy`] names content only. The object travels beside it, so a
/// copy of equal content in another scope never stands in for this scope's object when a
/// clean GPU copy is dropped. A copy in a runtime's own memory also names that runtime's
/// consumer, so it never stands in for memory of another tenant or trust scope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectCopy {
    pub object: ObjectRef,
    /// The consumer whose memory holds the copy (pinned or host RAM); `None` for stored,
    /// peer and remote copies, which are read under their own authorization.
    pub holder: Option<Consumer>,
    pub copy: ReconstructibleCopy,
}

impl ObjectCopy {
    /// Whether this copy may stand in for `object` held by `owner`: a copy of exactly that
    /// object, and, if it is in a runtime's memory, one in the owner's tenant and trust
    /// scope.
    pub fn may_rebuild(&self, object: &ObjectRef, owner: &Consumer) -> bool {
        self.object == *object
            && self
                .holder
                .as_ref()
                .is_none_or(|holder| holder.shares_trust_with(owner))
    }
}
