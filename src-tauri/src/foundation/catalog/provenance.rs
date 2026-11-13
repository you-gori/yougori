//! Failure provenance as plain typed records (S2 CORE-02 failure cases; S2 CORE-08
//! "failure provenance", "raw attempt outcomes").
//!
//! Every refused, interrupted, cancelled or failed import leaves one [`FailureRecord`]
//! naming the operation, execution, scope, class, source, object, protocol stage and a
//! typed reason. The catalog-specific detail stays in these serializable records; for a
//! CORE-08 run record, [`FailureRecord::outcome`] gives the report module's own failure
//! entry ([`Outcome::Failed`] with an S8 [`FailureKind`], the `catalog` component and a
//! reason code), so failures are counted in one taxonomy.

use std::collections::VecDeque;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::identity::{ArtifactClass, ObjectId, Scope, SourceIdentity};
use super::import::{Checkpoint, ImportRefusal, ImportStage};
use super::trust::VerifierRejection;
use crate::foundation::ids::{ContentKey, ExecutionId, MonotonicTime, OperationId};
use crate::foundation::report::{FailureKind, Label, Outcome, ReportError};

/// Longest free-text detail kept in a record, so records stay bounded.
pub const MAX_DETAIL_BYTES: usize = 512;

/// The component label catalog failures carry in a CORE-08 run record.
pub const FAILURE_COMPONENT: &str = "catalog";

/// A filesystem step under the catalog root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StorageOperation {
    CreateDirectory,
    List,
    Open,
    Read,
    Write,
    Sync,
    Rename,
    Remove,
    Permissions,
    Parse,
    Serialize,
    /// A file is larger than the bound for its kind and was not read.
    TooLarge,
    /// A record is in a format this build does not read, newer or unknown; it is kept
    /// untouched.
    Format,
    /// The root's exclusive lock could not be taken for a reason other than another holder
    /// (the file system refused the lock itself).
    Lock,
}

/// A failed filesystem step; the path is relative to the catalog root.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageFailure {
    pub operation: StorageOperation,
    pub path: String,
    pub detail: String,
}

impl fmt::Display for StorageFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "catalog storage step {:?} failed for {}: {}",
            self.operation, self.path, self.detail
        )
    }
}

impl std::error::Error for StorageFailure {}

/// Why an import did not publish, at the stage where it stopped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case")]
#[serde(remote = "Self")]
pub enum FailureReason {
    /// Refused before anything was allocated (manifest bounds, trust, quota, request).
    Refused { refusal: ImportRefusal },
    /// The caller's control interrupted the import at this checkpoint.
    Interrupted { at: Checkpoint },
    /// Every party detached; nothing was published.
    Cancelled,
    /// The source failed or ended early.
    SourceFailed { extent: Option<u32>, detail: String },
    /// The source's length differs from the declared true length.
    SourceLengthMismatch {
        declared_bytes: u64,
        source_bytes: u64,
    },
    /// The source kept delivering bytes that do not match the extent digest.
    ExtentDigestMismatch { extent: u32, attempts: u32 },
    /// The temporary representation did not read back as written.
    ReadBackMismatch { extent: Option<u32> },
    /// Every extent matched, but the whole object does not match the content key: the
    /// declaration contradicts itself.
    ContentKeyMismatch {
        expected: ContentKey,
        found: ContentKey,
    },
    /// The class's responsible verifier rejected the object.
    VerifierRejected { rejection: VerifierRejection },
    /// A filesystem step failed.
    Storage { failure: StorageFailure },
}

crate::foundation::strict_serde::strict_tag!(FailureReason, "reason");

impl FailureReason {
    /// The S8 failure-taxonomy class (CORE-08): refusals are rejected requests, a
    /// conflicting declaration of the same key is a duplicate identity, interruption and
    /// cancellation are early terminations, source and storage failures are command
    /// failures, and data that fails verification is an invalid result.
    pub fn kind(&self) -> FailureKind {
        match self {
            Self::Refused {
                refusal:
                    ImportRefusal::ConflictingFlight { .. }
                    | ImportRefusal::ConflictsWithPublished { .. },
            } => FailureKind::DuplicateIdentity,
            Self::Refused {
                refusal: ImportRefusal::Storage { .. },
            }
            | Self::SourceFailed { .. }
            | Self::Storage { .. } => FailureKind::CommandFailure,
            Self::Refused { .. } => FailureKind::Rejected,
            Self::Interrupted { .. } | Self::Cancelled => FailureKind::EarlyTermination,
            Self::SourceLengthMismatch { .. }
            | Self::ExtentDigestMismatch { .. }
            | Self::ReadBackMismatch { .. }
            | Self::ContentKeyMismatch { .. }
            | Self::VerifierRejected { .. } => FailureKind::InvalidResult,
        }
    }

    /// A stable code naming the reason; every code is a valid report label.
    pub fn code(&self) -> &'static str {
        match self {
            Self::Refused { refusal } => match refusal {
                ImportRefusal::Manifest { .. } => "manifest_rejected",
                ImportRefusal::Metadata { .. } => "metadata_rejected",
                ImportRefusal::Trust { .. } => "trust_refused",
                ImportRefusal::Quota { .. } => "quota_refused",
                ImportRefusal::NoDerivation => "no_derivation",
                ImportRefusal::TooManyReferences { .. } => "too_many_references",
                ImportRefusal::UnknownReference { .. } => "unknown_reference",
                ImportRefusal::ConflictingFlight { .. } => "conflicting_flight",
                ImportRefusal::ConflictsWithPublished { .. } => "conflicts_with_published",
                ImportRefusal::Storage { .. } => "admission_storage_failed",
            },
            Self::Interrupted { .. } => "interrupted",
            Self::Cancelled => "cancelled",
            Self::SourceFailed { .. } => "source_failed",
            Self::SourceLengthMismatch { .. } => "source_length_mismatch",
            Self::ExtentDigestMismatch { .. } => "extent_digest_mismatch",
            Self::ReadBackMismatch { .. } => "read_back_mismatch",
            Self::ContentKeyMismatch { .. } => "content_key_mismatch",
            Self::VerifierRejected { .. } => "verifier_rejected",
            Self::Storage { .. } => "storage_failed",
        }
    }
}

/// One failure, with its provenance (S2 CORE-08).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureRecord {
    pub operation: OperationId,
    pub execution: ExecutionId,
    pub scope: Scope,
    pub class: ArtifactClass,
    pub source: SourceIdentity,
    pub object: ObjectId,
    pub stage: ImportStage,
    pub reason: FailureReason,
    pub observed_at: MonotonicTime,
}

impl FailureRecord {
    /// This failure as a CORE-08 run-record outcome, the report module's failure
    /// provenance entry: S8 kind, `catalog` component and reason code.
    pub fn outcome(&self) -> Result<Outcome, ReportError> {
        Ok(Outcome::Failed {
            failure: self.reason.kind(),
            component: Label::new(FAILURE_COMPONENT)?,
            code: Label::new(self.reason.code())?,
        })
    }
}

/// A bounded log of failure records; the oldest are dropped first and counted.
#[derive(Debug)]
pub(super) struct FailureLog {
    records: VecDeque<FailureRecord>,
    capacity: usize,
    dropped: u64,
}

impl FailureLog {
    pub(super) fn new(capacity: usize) -> Self {
        Self {
            records: VecDeque::new(),
            capacity,
            dropped: 0,
        }
    }

    pub(super) fn push(&mut self, record: FailureRecord) {
        if self.capacity == 0 {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        while self.records.len() >= self.capacity {
            self.records.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.records.push_back(record);
    }

    pub(super) fn records(&self) -> impl Iterator<Item = &FailureRecord> {
        self.records.iter()
    }

    pub(super) fn dropped(&self) -> u64 {
        self.dropped
    }
}

/// `text`, cut to at most [`MAX_DETAIL_BYTES`] at a character boundary.
pub(super) fn bounded_detail(text: impl fmt::Display) -> String {
    let mut text = text.to_string();
    if text.len() > MAX_DETAIL_BYTES {
        let mut end = MAX_DETAIL_BYTES;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_are_bounded_at_a_character_boundary() {
        assert_eq!(bounded_detail("short"), "short");
        let long = "é".repeat(MAX_DETAIL_BYTES);
        let cut = bounded_detail(&long);
        assert!(cut.len() <= MAX_DETAIL_BYTES);
        assert!(cut.chars().all(|character| character == 'é'));
    }
}
