//! One catalog publication for this module's import entries: admission, the drive and the
//! detach (S2 CORE-02, line 211: "atomic publication"). The catalog decides trust through
//! the class's verifier and policy and checks every byte against the declaration; this
//! module only carries the outcome back as a typed failure.

use std::fmt;

use crate::foundation::catalog::{
    Catalog, FailureRecord, ImportControl, ImportError, ImportRefusal, ImportRequest, ImportSource,
    ImportStart, ImportStatus, ObjectId, SourceError, SourceIdentity,
};

/// Why the catalog did not publish an object. Nothing of it was published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PublishFailure {
    /// Refused before anything was written: trust, quota, bounds or metadata.
    Refused { refusal: ImportRefusal },
    /// The import ended without publishing, as when the source's bytes did not match the
    /// declaration or the class verifier rejected the object.
    Failed { failure: Box<FailureRecord> },
    /// The caller's control paused the import: nothing was published, and its verified
    /// extents stay staged for a resume.
    Interrupted {
        last_failure: Option<Box<FailureRecord>>,
    },
    /// The catalog refused the call itself.
    Misuse { error: ImportError },
}

impl fmt::Display for PublishFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused { refusal } => write!(f, "the catalog refused the import: {refusal}"),
            Self::Failed { failure } => write!(
                f,
                "the catalog import failed at {:?}: {}",
                failure.stage,
                failure.reason.code()
            ),
            Self::Interrupted { .. } => f.write_str("the catalog import was interrupted"),
            Self::Misuse { error } => write!(f, "the catalog refused the call: {error}"),
        }
    }
}

impl std::error::Error for PublishFailure {}

/// A published object, and whether the scope held it already (its claim was checked
/// again against the class's current verifier and policy either way).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Published {
    pub object: ObjectId,
    pub cache_hit: bool,
}

/// Bytes in memory as a catalog import source.
pub(super) struct MemorySource<'a> {
    pub identity: SourceIdentity,
    pub bytes: &'a [u8],
}

impl ImportSource for MemorySource<'_> {
    fn identity(&self) -> SourceIdentity {
        self.identity
    }

    fn length_bytes(&mut self) -> Result<u64, SourceError> {
        u64::try_from(self.bytes.len()).map_err(|_| SourceError {
            detail: "the source is longer than a catalog object may be".to_owned(),
        })
    }

    fn read_at(&mut self, offset_bytes: u64, buffer: &mut [u8]) -> Result<usize, SourceError> {
        let start = usize::try_from(offset_bytes)
            .unwrap_or(usize::MAX)
            .min(self.bytes.len());
        let rest = self.bytes.get(start..).unwrap_or_default();
        let count = rest.len().min(buffer.len());
        if let (Some(target), Some(source)) = (buffer.get_mut(..count), rest.get(..count)) {
            target.copy_from_slice(source);
        }
        Ok(count)
    }
}

/// Admits `request` and drives it from `source` under `control`, then detaches. The
/// object is published only if the catalog's trust check, every extent, the content key
/// and the class verifier's structure check pass.
pub(super) fn publish(
    catalog: &mut Catalog,
    request: ImportRequest,
    source: &mut dyn ImportSource,
    control: &mut dyn ImportControl,
) -> Result<Published, PublishFailure> {
    let start = catalog
        .begin_import(request, source.identity())
        .map_err(|refusal| PublishFailure::Refused { refusal })?;
    let ticket = match start {
        ImportStart::AlreadyPublished(object) => {
            return Ok(Published {
                object,
                cache_hit: true,
            })
        }
        ImportStart::Started(ticket) | ImportStart::Attached(ticket) => ticket,
    };
    let status = catalog.drive_import(&ticket, source, control);
    // Detach: a finished import keeps no status for this ticket, and an unfinished one
    // keeps its verified extents staged for a resume.
    catalog.cancel_import(ticket);
    match status.map_err(|error| PublishFailure::Misuse { error })? {
        ImportStatus::Published { object, .. } => Ok(Published {
            object,
            cache_hit: false,
        }),
        ImportStatus::Failed { failure } => Err(PublishFailure::Failed {
            failure: Box::new(failure),
        }),
        ImportStatus::Pending { last_failure, .. } => Err(PublishFailure::Interrupted {
            last_failure: last_failure.map(Box::new),
        }),
    }
}
