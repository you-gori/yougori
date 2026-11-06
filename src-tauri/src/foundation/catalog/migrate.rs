//! Versioned records and layout migration (GPU-W03: catalog schema migration without
//! rewriting or deleting original model files).
//!
//! Every persisted record declares its format. Each reader checks that declaration
//! before it interprets anything else: a known older format migrates forward, and a newer
//! or unknown one is refused with a [`FormatRefusal`] and kept untouched, never
//! downgraded. Grants and leases are never persisted, so they need no reader.
//!
//! The layout marker `format.json` at the root records the layout format. Layout 1 (no
//! marker) keyed staging by tenant scope, source and parent execution; layout 2 keys it
//! by tenant scope, source and model execution identity (line 533). Migration on open
//! re-keys each interrupted import from layout 1, so it resumes its verified extents,
//! then writes the marker. Each step is one atomic write-then-rename or one directory
//! rename, and the state after any step describes itself, so a crash at any point
//! resumes on the next open. Migration reads one small record at a time, and it never
//! touches a published object: no original's data file is rewritten, moved or deleted.

use std::path::Path;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::identity::{ArtifactClass, ModelExecutionKey, Scope, SourceIdentity};
use super::import::flight_key;
use super::provenance::{StorageFailure, StorageOperation};
use super::store::{Layout, Listed, StagingRecord, MAX_SMALL_RECORD_BYTES, STAGING_FORMAT};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId};

/// The layout format this build writes and reads.
pub const CATALOG_FORMAT: u32 = 2;
/// The marker recording the layout format, at the catalog root.
pub(super) const LAYOUT_FILE: &str = "format.json";
/// The staging declaration in each staging directory.
pub(super) const FLIGHT_FILE: &str = "flight.json";
/// Domain of the layout 1 single-flight key, which bound the parent execution.
const FLIGHT_DOMAIN_V1: &str = "yougori/catalog/flight/v1";
const MAX_MARKER_BYTES: u64 = 4096;

/// A kind of persisted record.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    /// The layout marker at the root.
    Layout,
    /// A publication record.
    ObjectRecord,
    /// A committed or staged object's complete index.
    ObjectIndex,
    Root,
    /// A staging declaration.
    Staging,
    /// A staging journal of verified extents.
    Journal,
}

impl RecordKind {
    /// The stable tag used in refusals.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Layout => "layout",
            Self::ObjectRecord => "object_record",
            Self::ObjectIndex => "object_index",
            Self::Root => "root",
            Self::Staging => "staging",
            Self::Journal => "journal",
        }
    }
}

/// A record this build will not read: its format is newer than the newest it knows, or
/// one it never wrote. Such a record is kept untouched, never downgraded or collected.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatRefusal {
    pub kind: RecordKind,
    /// Relative to the catalog root.
    pub path: String,
    pub found: u32,
    /// The newest format of this kind this build reads.
    pub supported: u32,
}

impl FormatRefusal {
    /// Written by a newer build, rather than in a format no build wrote.
    pub fn is_newer(&self) -> bool {
        self.found > self.supported
    }

    /// The refusal as a storage failure of the format step.
    pub fn to_failure(&self) -> StorageFailure {
        StorageFailure {
            operation: StorageOperation::Format,
            path: self.path.clone(),
            detail: self.to_string(),
        }
    }
}

impl std::fmt::Display for FormatRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the {} record is in format {}; this build reads up to format {} and never \
             rewrites a newer or unknown one",
            self.kind.tag(),
            self.found,
            self.supported
        )
    }
}

impl std::error::Error for FormatRefusal {}

/// An interrupted import moved from its layout 1 key to its layout 2 key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rekeyed {
    /// The staging directory's layout 1 name.
    pub from: String,
    /// Its layout 2 key: tenant scope, source and no model execution identity, since
    /// layout 1 recorded none.
    pub to: Digest,
    pub scope: Scope,
    pub source: SourceIdentity,
}

/// Why an interrupted layout 1 import cannot resume under layout 2. Its bytes stay until
/// the usual grace period, then the collector removes them like any abandoned staging.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UnresumableReason {
    /// Another interrupted import of the same tenant and source already holds the layout
    /// 2 key. Layout 1 kept one import per parent execution; layout 2 keeps one per
    /// tenant, source and model execution identity, so only one of them can carry it.
    KeyTaken { key: Digest },
    /// The declaration's key does not match its fields or its directory's name, so the
    /// record cannot be trusted to name its import.
    Inconsistent,
}

/// An interrupted import that cannot resume under layout 2.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Unresumable {
    /// The staging directory's name.
    pub staging: String,
    pub reason: UnresumableReason,
}

/// What migration did when the catalog opened.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MigrationReport {
    /// The layout format found; 1 when the root had no marker.
    pub from_format: u32,
    /// The layout format after the open.
    pub to_format: u32,
    /// Interrupted imports re-keyed to layout 2; each resumes its verified extents.
    pub rekeyed: Vec<Rekeyed>,
    /// Staging declarations already under their layout 2 key, rewritten in place in the
    /// current format.
    pub upgraded: usize,
    pub unresumable: Vec<Unresumable>,
}

/// A migration step, offered to the control before it runs (tests inject crashes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum MigrationStep {
    /// Rewrite one staging declaration in the current format.
    RewriteStaging { staging: String },
    /// Rename one staging directory to the key its declaration names.
    MoveStaging { staging: String },
    /// Record the layout format in the marker.
    WriteMarker,
}

#[derive(Deserialize)]
struct FormatProbe {
    format: u32,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LayoutMarker {
    format: u32,
}

/// A staging declaration in format 1. It named either the parent execution (layout 1) or,
/// from builds that already keyed by model execution identity, that identity.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StagingV1 {
    format: u32,
    flight: Digest,
    scope: Scope,
    class: ArtifactClass,
    source: SourceIdentity,
    #[serde(default)]
    execution: Option<ExecutionId>,
    #[serde(default)]
    model_execution: Option<ModelExecutionKey>,
    manifest_digest: Digest,
    true_length_bytes: u64,
}

/// A staging declaration as read, by format.
#[derive(Debug)]
pub(super) enum StagingRead {
    /// The current format.
    Current(StagingRecord),
    /// Format 1 keyed by the parent execution, from layout 1.
    ParentKeyed {
        record: StagingRecord,
        execution: ExecutionId,
    },
    /// Format 1 already under its layout 2 key.
    Unversioned(StagingRecord),
    Refused(FormatRefusal),
}

impl StagingRead {
    /// The declaration's scope, when the record could be read.
    pub(super) fn scope(&self) -> Option<&Scope> {
        match self {
            Self::Current(record)
            | Self::ParentKeyed { record, .. }
            | Self::Unversioned(record) => Some(&record.scope),
            Self::Refused(_) => None,
        }
    }
}

/// The layout 1 single-flight key: tenant scope, source and parent execution.
pub(super) fn flight_key_v1(
    scope: &Scope,
    source: &SourceIdentity,
    execution: &ExecutionId,
) -> Digest {
    scope
        .bind(DigestBuilder::new(FLIGHT_DOMAIN_V1))
        .digest(&source.digest())
        .str(execution.as_str())
        .finish()
}

fn probe(layout: &Layout, path: &Path, bytes: &[u8]) -> Result<u32, StorageFailure> {
    serde_json::from_slice::<FormatProbe>(bytes)
        .map(|probe| probe.format)
        .map_err(|error| layout.failure(StorageOperation::Parse, path, error))
}

fn refusal(
    layout: &Layout,
    path: &Path,
    kind: RecordKind,
    found: u32,
    supported: u32,
) -> FormatRefusal {
    FormatRefusal {
        kind,
        path: layout.relative(path),
        found,
        supported,
    }
}

/// Reads a record of a kind whose only format is `supported`, refusing any other before
/// its fields are interpreted. A record that cannot be parsed is a storage failure, as
/// before.
pub(super) fn read_versioned<T: DeserializeOwned>(
    layout: &Layout,
    path: &Path,
    max_bytes: u64,
    kind: RecordKind,
    supported: u32,
) -> Result<Result<T, FormatRefusal>, StorageFailure> {
    let bytes = layout.read_bounded(path, max_bytes)?;
    let found = probe(layout, path, &bytes)?;
    if found != supported {
        return Ok(Err(refusal(layout, path, kind, found, supported)));
    }
    serde_json::from_slice(&bytes)
        .map(Ok)
        .map_err(|error| layout.failure(StorageOperation::Parse, path, error))
}

/// Reads a staging declaration in any format this build knows.
pub(super) fn read_staging(layout: &Layout, path: &Path) -> Result<StagingRead, StorageFailure> {
    let bytes = layout.read_bounded(path, MAX_SMALL_RECORD_BYTES)?;
    let parse = |error: serde_json::Error| layout.failure(StorageOperation::Parse, path, error);
    match probe(layout, path, &bytes)? {
        STAGING_FORMAT => serde_json::from_slice(&bytes)
            .map(StagingRead::Current)
            .map_err(parse),
        1 => {
            let legacy: StagingV1 = serde_json::from_slice(&bytes).map_err(parse)?;
            let record = StagingRecord {
                format: legacy.format,
                flight: legacy.flight,
                scope: legacy.scope,
                class: legacy.class,
                source: legacy.source,
                model_execution: legacy.model_execution,
                manifest_digest: legacy.manifest_digest,
                true_length_bytes: legacy.true_length_bytes,
            };
            match legacy.execution {
                Some(execution) if record.model_execution.is_none() => {
                    Ok(StagingRead::ParentKeyed { record, execution })
                }
                Some(_) => Err(layout.failure(
                    StorageOperation::Parse,
                    path,
                    "a format 1 declaration names both a parent execution and a model \
                     execution identity",
                )),
                None => Ok(StagingRead::Unversioned(record)),
            }
        }
        found => Ok(StagingRead::Refused(refusal(
            layout,
            path,
            RecordKind::Staging,
            found,
            STAGING_FORMAT,
        ))),
    }
}

/// The layout format the marker records; 1 when there is none. A newer, unknown or
/// unreadable marker refuses the whole catalog, so nothing written by a newer build is
/// ever rewritten in an older layout.
pub(super) fn read_layout(layout: &Layout) -> Result<u32, StorageFailure> {
    let path = layout.root_path().join(LAYOUT_FILE);
    if !layout.exists(&path) {
        return Ok(1);
    }
    match read_versioned::<LayoutMarker>(
        layout,
        &path,
        MAX_MARKER_BYTES,
        RecordKind::Layout,
        CATALOG_FORMAT,
    )? {
        Ok(marker) => Ok(marker.format),
        Err(refused) if refused.found == 1 => Ok(1),
        Err(refused) => Err(refused.to_failure()),
    }
}

/// Migrates the layout found at `from_format` to [`CATALOG_FORMAT`]: every staging
/// declaration first, then the marker. `None` when the control stopped it before a step;
/// the next run resumes where it stopped.
pub(super) fn migrate(
    layout: &Layout,
    from_format: u32,
    control: &mut dyn FnMut(&MigrationStep) -> bool,
) -> Result<Option<MigrationReport>, StorageFailure> {
    let mut report = MigrationReport {
        from_format,
        to_format: CATALOG_FORMAT,
        ..MigrationReport::default()
    };
    for listed in layout.list(&layout.staging())? {
        if listed.is_dir && !migrate_staging(layout, &listed, &mut report, control)? {
            return Ok(None);
        }
    }
    if from_format < CATALOG_FORMAT {
        if !control(&MigrationStep::WriteMarker) {
            return Ok(None);
        }
        let marker = LayoutMarker {
            format: CATALOG_FORMAT,
        };
        layout.write_json_atomic(&layout.root_path().join(LAYOUT_FILE), &marker)?;
    }
    Ok(Some(report))
}

/// Migrates one staging directory; `false` when the control stopped before a step.
/// Unreadable and refused declarations are left exactly as they are.
fn migrate_staging(
    layout: &Layout,
    listed: &Listed,
    report: &mut MigrationReport,
    control: &mut dyn FnMut(&MigrationStep) -> bool,
) -> Result<bool, StorageFailure> {
    let path = listed.path.join(FLIGHT_FILE);
    let Ok(read) = read_staging(layout, &path) else {
        return Ok(true);
    };
    let unresumable = |report: &mut MigrationReport, reason| {
        report.unresumable.push(Unresumable {
            staging: listed.name.clone(),
            reason,
        });
        Ok(true)
    };
    match read {
        StagingRead::Refused(_) => Ok(true),
        StagingRead::Current(record) => {
            if record.flight.to_hex() == listed.name {
                return Ok(true);
            }
            if record.flight
                != flight_key(
                    &record.scope,
                    &record.source,
                    record.model_execution.as_ref(),
                )
            {
                return unresumable(report, UnresumableReason::Inconsistent);
            }
            // A crash between the rewrite and the rename: finish the move.
            move_staging(layout, listed, record, report, control)
        }
        StagingRead::Unversioned(record) => {
            let key = flight_key(
                &record.scope,
                &record.source,
                record.model_execution.as_ref(),
            );
            if record.flight != key || key.to_hex() != listed.name {
                return unresumable(report, UnresumableReason::Inconsistent);
            }
            if !control(&MigrationStep::RewriteStaging {
                staging: listed.name.clone(),
            }) {
                return Ok(false);
            }
            layout.write_json_atomic(
                &path,
                &StagingRecord {
                    format: STAGING_FORMAT,
                    ..record
                },
            )?;
            report.upgraded += 1;
            Ok(true)
        }
        StagingRead::ParentKeyed { record, execution } => {
            let old = flight_key_v1(&record.scope, &record.source, &execution);
            if record.flight != old || old.to_hex() != listed.name {
                return unresumable(report, UnresumableReason::Inconsistent);
            }
            let key = flight_key(&record.scope, &record.source, None);
            if layout.exists(&layout.flight_dir(&key)) {
                return unresumable(report, UnresumableReason::KeyTaken { key });
            }
            if !control(&MigrationStep::RewriteStaging {
                staging: listed.name.clone(),
            }) {
                return Ok(false);
            }
            let record = StagingRecord {
                format: STAGING_FORMAT,
                flight: key,
                model_execution: None,
                ..record
            };
            layout.write_json_atomic(&path, &record)?;
            move_staging(layout, listed, record, report, control)
        }
    }
}

/// Renames a staging directory to the key its current declaration names.
fn move_staging(
    layout: &Layout,
    listed: &Listed,
    record: StagingRecord,
    report: &mut MigrationReport,
    control: &mut dyn FnMut(&MigrationStep) -> bool,
) -> Result<bool, StorageFailure> {
    let target = layout.flight_dir(&record.flight);
    if layout.exists(&target) {
        report.unresumable.push(Unresumable {
            staging: listed.name.clone(),
            reason: UnresumableReason::KeyTaken { key: record.flight },
        });
        return Ok(true);
    }
    if !control(&MigrationStep::MoveStaging {
        staging: listed.name.clone(),
    }) {
        return Ok(false);
    }
    layout.rename(&listed.path, &target)?;
    layout.sync_dir(&layout.staging())?;
    report.rekeyed.push(Rekeyed {
        from: listed.name.clone(),
        to: record.flight,
        scope: record.scope,
        source: record.source,
    });
    Ok(true)
}
