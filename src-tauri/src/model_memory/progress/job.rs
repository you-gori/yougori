//! What the journal persists for a job and what the loader receives (§3.10 line 652):
//! job intent, artifact commits, resumable verified extents and the import state they
//! belong to, named by the CORE-02 catalog (T05): objects by [`ObjectId`], extents by
//! [`ExtentEntry`], import state by [`Checkpoint`] and [`ImportProgress`].
//!
//! None of these types has a field for a device pointer, an allocation handle, a GPU
//! lease, a prompt or a path, and reading the journal refuses fields it does not name.

use serde::{Deserialize, Serialize};

use crate::foundation::catalog::{
    ArtifactClass, Checkpoint, ExtentEntry, ImportProgress, ObjectId, Scope,
};
use crate::foundation::ids::{ContentKey, ExecutionId, Incarnation, OperationId, TenantId};

/// Why a job exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    /// Load for a waiting request. The request itself, with its prompt, is never
    /// journaled: after a restart only the load resumes, and the client retries.
    Load,
    /// Prepare ahead of demand (GPU-W11 "prepare next model").
    Prepare,
}

/// §3.10 "job intent": what to make ready, never how it was placed.
///
/// The operation ID keys the intent, so submitting the same intent again is idempotent
/// and a different intent under the same ID is refused.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JobIntent {
    pub operation: OperationId,
    /// The parent execution the job runs under (S3.1).
    pub execution: ExecutionId,
    /// The tenant whose catalog scope owns the artifact (T05: equal bytes in another
    /// scope are another object).
    pub tenant: TenantId,
    pub kind: JobKind,
    pub class: ArtifactClass,
    /// The content identity of the representation to load.
    pub content: ContentKey,
    pub total_bytes: u64,
}

impl JobIntent {
    /// The catalog scope that owns the artifact.
    pub fn scope(&self) -> Scope {
        Scope::tenant(self.tenant.clone())
    }

    /// The catalog object to load: the tenant's scope, the class and the content key.
    pub fn object(&self) -> ObjectId {
        ObjectId::new(&self.scope(), self.class, self.content)
    }
}

/// §3.10 "artifact commits": the catalog published the job's whole object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactCommit {
    pub object: ObjectId,
    pub total_bytes: u64,
}

/// §3.10 "resumable verified extents": one extent of the object, numbered as the
/// catalog numbers it, whose bytes were verified against the entry's digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedExtent {
    pub extent: u32,
    pub entry: ExtentEntry,
}

impl VerifiedExtent {
    /// The first byte after the extent; `None` on overflow.
    pub fn end_bytes(&self) -> Option<u64> {
        self.entry.offset_bytes.checked_add(self.entry.length_bytes)
    }
}

/// Where an interrupted import stood, as the catalog reported it (T05).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportState {
    /// The last checkpoint the import reached.
    pub reached: Checkpoint,
    pub progress: ImportProgress,
}

/// How a job ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobOutcome {
    Completed,
    Cancelled,
    Failed,
}

/// Where a job resumes. Nothing comes from GPU memory (line 652), and nothing journaled
/// is trusted as it stands.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ResumePoint {
    /// The catalog publishes the whole object now, so only placement remains.
    pub artifact_committed: bool,
    /// Extents the journal recorded as verified. They are claims, not trust: the
    /// catalog's resumed import re-verifies every staged extent before reusing it and
    /// fetches a failed one again (T05). Empty when the artifact is committed.
    pub journaled_extents: Vec<VerifiedExtent>,
    /// Where the interrupted import stood. Empty when the artifact is committed.
    pub import: Option<ImportState>,
}

impl ResumePoint {
    /// Nothing to reuse.
    pub fn fresh() -> Self {
        Self::default()
    }
}

/// One submission to the normal loader (line 652). It has no lease, generation, device
/// pointer or allocation handle: the loader obtains fresh ones from the CORE-04
/// coordinator, which revived no lease and retired every GPU allocation at the restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoadRequest {
    pub intent: JobIntent,
    pub resume: ResumePoint,
    /// The daemon incarnation that submits; work from an earlier one is stale.
    pub incarnation: Incarnation,
}
