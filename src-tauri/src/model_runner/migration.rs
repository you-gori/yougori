//! The model runner's migration owner (INT-11 in docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! "Model runner migration while old model data/setups exist: one migration owner preserves
//! artifacts and recorded runtime choices"; U05 "Preserve existing setups, storage and user data
//! with resumable migration"; VM-W56 "Interrupted migration is resumable; user data remains
//! intact"; remaining-only §8 "Keep migration preview, interrupted migration/rollback").
//!
//! Two generations of model environments exist beside the current one. Those made before the
//! import-into-volume policy (IM1, `1415787`) read their folder through the read-only mount on
//! every load, at the mount's speed; those made before the catalog path (`d4cf3ef`) bind the
//! folder itself rather than the catalog's view. Neither is wrong, and both keep working: this
//! module changes a stopped environment's recorded workload only when asked, one step at a time,
//! against a durable record under the engine's data directory, so that
//!
//! - `preview` says, for every model environment, how its files reach the runner today
//!   ([`Source`]) and which steps it would get ([`Step`]), or why it gets none now;
//! - `apply` runs the pending steps in order and checkpoints the record after each, so an
//!   interrupted migration resumes after its completed steps and never repeats one;
//! - `rollback` restores every migrated environment's saved workload options from the record,
//!   whose digest over them is the backup the migration rests on ([`BackupRef`]: nothing is
//!   applied unless the record reads back verified).
//!
//! The user's folder and its files are never written. The catalog's published copies are never
//! deleted here: a rollback ends the environment's leases and removes its view, and the catalog's
//! own collector decides the rest. A running model is deferred, never changed underneath.

mod recovery;

use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use yougori_cli::workload::{Options, Volume};

use super::catalog_binding::{
    self, Binding, EXECUTION_OPTION, MODEL_TARGET, REGISTRY_RECORD, RUNNER_MANIFEST,
};
use crate::foundation::ids::{digest, Digest, ExecutionId};
use crate::foundation::product::{BackupRef, MigrationStatus};

/// Where the record lives under the engine's data directory.
pub(crate) const DIRECTORY: &str = "model-migration";
const RECORD_FILE: &str = "record.json";
const RECORD_VERSION: u32 = 2;
/// A record larger than this is refused unread; a few hundred environments fit many times over.
const RECORD_LIMIT: u64 = 16 << 20;
/// The domain of the digest over every item's saved options.
const BACKUP_DOMAIN: &str = "yougori/model-migration/backup/v1";
/// A registry record larger than this is not parsed.
const REGISTRY_RECORD_LIMIT: u64 = 4 << 20;
/// Where a model environment keeps its own model files (model_runner.rs, `MODEL_CACHE`).
const MODEL_CACHE: &str = "/root/.cache/huggingface";

/// How a model environment's files reach its runner, as its workload options record it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Source {
    /// Downloaded from Hugging Face into the environment's own volume.
    HuggingFace,
    /// Read through the read-only mount of a folder on every load (before IM1, or a CPU runner).
    MountRead,
    /// Imported once from the mount into the environment's own volume (IM1).
    ImportedVolume,
    /// The folder's files are published in the catalog; the view is the import source.
    Catalog,
    /// A source-only publication serves files from its folder; no model runs.
    SourceOnly,
}

/// One change a migration makes to an environment's workload.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "step", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum Step {
    /// Give the environment its own model volume, so the runner imports the folder once at the
    /// next start and reads only the copy (IM1's policy for new environments).
    OwnVolume {
        volume: String,
        bytes: u64,
        storage_gb_needed: u64,
    },
    /// Publish the bound folder's files into the catalog and bind the read-only view as the
    /// import source (the catalog path for new environments).
    CatalogPublish { folder: String, registry: bool },
}

impl Step {
    fn name(&self) -> &'static str {
        match self {
            Self::OwnVolume { .. } => "own_volume",
            Self::CatalogPublish { .. } => "catalog_publish",
        }
    }
}

/// Where one step is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum StepState {
    Pending,
    Done,
    /// The last attempt failed; a resume tries it again.
    Failed {
        error: String,
    },
    /// Undone by a rollback.
    RolledBack,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PlannedStep {
    pub step: Step,
    pub state: StepState,
}

/// One environment the migration changes.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Item {
    pub environment: String,
    pub runtime_id: String,
    pub name: String,
    pub source: Source,
    pub steps: Vec<PlannedStep>,
    /// The workload options before any step: what a rollback restores.
    pub before: Options,
    /// The options after the last completed step, while any step is done.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<Options>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    intent: Option<Intent>,
}

/// Durable before publication/configuration. `after` is persisted before installing it.
/// A missing step means restoration to the original workload, not an apply operation.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Intent {
    step: Option<usize>,
    before: Options,
    after: Option<Options>,
    execution: Option<ExecutionId>,
}

impl Item {
    /// The options the next step starts from.
    pub(crate) fn current(&self) -> &Options {
        self.after.as_ref().unwrap_or(&self.before)
    }

    fn done(&self) -> usize {
        self.steps
            .iter()
            .filter(|planned| planned.state == StepState::Done)
            .count()
    }
}

/// What the preview says about one model environment.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "disposition", rename_all = "snake_case")]
pub(crate) enum Disposition {
    /// Nothing to change: the environment is on the current path for its kind.
    UpToDate {
        environment: String,
        name: String,
        source: Source,
    },
    /// Not now, for a reason the user can act on.
    Deferred {
        environment: String,
        name: String,
        source: Source,
        reason: String,
    },
    /// Not possible as the environment is; the remedy says what to change first.
    Refused {
        environment: String,
        name: String,
        source: Source,
        reason: String,
        remedy: String,
    },
    Migrate(Item),
}

/// What the preview knows about one environment, as the engine's store and runtime say it.
#[derive(Clone, Debug)]
pub(crate) struct Candidate {
    pub id: String,
    pub runtime_id: String,
    pub name: String,
    pub stopped: bool,
    /// A local CUDA workload (the runner imports; a CPU runner reads the mount by design).
    pub cuda: bool,
    pub storage_limit_gb: Option<f64>,
    pub options: Options,
}

/// The model bind of `options`, if any.
fn model_bind(options: &Options) -> Option<&Volume> {
    options
        .binds
        .iter()
        .find(|bind| bind.target == MODEL_TARGET)
}

/// Whether `options` carry an environment's own model cache volume (model_runner.rs,
/// `model_cache_volume`; `runtime/workload.rs::model_cache_names` recognises the same names).
fn has_own_volume(options: &Options) -> bool {
    options.volumes.iter().any(|volume| {
        !volume.read_only
            && volume.target == MODEL_CACHE
            && volume
                .source
                .strip_prefix("model-")
                .and_then(|rest| rest.strip_suffix("-models"))
                .is_some_and(|id| id.len() == 8 && id.bytes().all(|b| b.is_ascii_hexdigit()))
    })
}

/// How `options` reach their files today.
pub(crate) fn source_of(options: &Options) -> Source {
    if options
        .environment
        .get("YOUGORI_MODEL_FORMAT")
        .is_some_and(|format| format == "source")
    {
        return Source::SourceOnly;
    }
    if model_bind(options).is_none() {
        return Source::HuggingFace;
    }
    if options.environment.contains_key(EXECUTION_OPTION) {
        return Source::Catalog;
    }
    if has_own_volume(options)
        && options
            .environment
            .get("YOUGORI_MODEL_IMPORT")
            .is_some_and(|flag| flag == "1")
    {
        return Source::ImportedVolume;
    }
    Source::MountRead
}

/// The bytes of the files a mounted folder's manifest lists: the runner manifest a folder
/// environment carries, or, for a registry environment, the registry's own record in the
/// folder, read through `registry_record`.
fn listed_bytes(
    options: &Options,
    folder: &Path,
    registry_record: &dyn Fn(&Path) -> Option<Value>,
) -> Option<u64> {
    let manifest: Value = match options.environment.get(RUNNER_MANIFEST) {
        Some(text) => serde_json::from_str(text).ok()?,
        None => registry_record(folder)?,
    };
    let files = manifest["files"].as_array()?;
    Some(
        files
            .iter()
            .filter_map(|file| file["size"].as_u64())
            .fold(0u64, u64::saturating_add),
    )
}

/// Reads the registry's record of a cached version folder (`.yougori-verified-files.json`),
/// bounded; `None` when it is missing, too large or not the record's shape.
pub(crate) fn registry_record(folder: &Path) -> Option<Value> {
    let file = fs::File::open(folder.join(REGISTRY_RECORD)).ok()?;
    let mut text = String::new();
    file.take(REGISTRY_RECORD_LIMIT + 1)
        .read_to_string(&mut text)
        .ok()?;
    if text.len() as u64 > REGISTRY_RECORD_LIMIT {
        return None;
    }
    let record: Value = serde_json::from_str(&text).ok()?;
    record["files"].is_array().then_some(record)
}

/// What `candidate` gets, or why nothing now. `catalog_open` says whether the engine's catalog
/// is open; `registry_record` reads a registry folder's record (injected for the tests).
/// `volume` names a new environment's own model volume. `None` for a workload that runs no
/// model.
pub(crate) fn classify(
    candidate: &Candidate,
    catalog_open: bool,
    registry_record: &dyn Fn(&Path) -> Option<Value>,
    volume: &dyn Fn() -> String,
) -> Option<Disposition> {
    let options = &candidate.options;
    options.environment.get("YOUGORI_MODEL")?;
    let source = source_of(options);
    let up_to_date = || Disposition::UpToDate {
        environment: candidate.id.clone(),
        name: candidate.name.clone(),
        source,
    };
    let Some(bind) = model_bind(options) else {
        return Some(up_to_date());
    };
    if source == Source::SourceOnly {
        return Some(up_to_date());
    }
    let folder = PathBuf::from(&bind.source);
    let registry = !options.environment.contains_key(RUNNER_MANIFEST)
        || options.environment.contains_key("YOUGORI_REGISTRY_VERSION");
    let mut steps = Vec::new();
    if candidate.cuda && source == Source::MountRead {
        let Some(bytes) = listed_bytes(options, &folder, registry_record) else {
            return Some(Disposition::Refused {
                environment: candidate.id.clone(),
                name: candidate.name.clone(),
                source,
                reason: "the sizes of its model files are not recorded, so the storage its own volume needs cannot be worked out".into(),
                remedy: "run the model again from its folder or published version, which records them".into(),
            });
        };
        let needed = super::import_storage_gb(bytes);
        let limit = candidate.storage_limit_gb.unwrap_or(0.0);
        if (limit.floor() as u64) < needed {
            return Some(Disposition::Refused {
                environment: candidate.id.clone(),
                name: candidate.name.clone(),
                source,
                reason: format!(
                    "its storage of {limit:.0} GB cannot hold the imported model files ({needed} GB with the runtime)"
                ),
                remedy: format!(
                    "increase the environment's storage to at least {needed} GB, then run the migration again"
                ),
            });
        }
        steps.push(Step::OwnVolume {
            volume: volume(),
            bytes,
            storage_gb_needed: needed,
        });
    }
    if catalog_open && source != Source::Catalog {
        steps.push(Step::CatalogPublish {
            folder: bind.source.clone(),
            registry,
        });
    }
    if steps.is_empty() {
        return Some(up_to_date());
    }
    if !candidate.stopped {
        return Some(Disposition::Deferred {
            environment: candidate.id.clone(),
            name: candidate.name.clone(),
            source,
            reason: "the model is running or paused; stop it first, since the migration changes its workload while it is stopped".into(),
        });
    }
    Some(Disposition::Migrate(Item {
        environment: candidate.id.clone(),
        runtime_id: candidate.runtime_id.clone(),
        name: candidate.name.clone(),
        source,
        steps: steps
            .into_iter()
            .map(|step| PlannedStep {
                step,
                state: StepState::Pending,
            })
            .collect(),
        before: options.clone(),
        after: None,
        intent: None,
    }))
}

/// The options after [`Step::OwnVolume`]: the volume at the runner's cache and the import
/// flag the runner acts on at its next start.
pub(crate) fn with_own_volume(options: &Options, volume: &str) -> Options {
    let mut next = options.clone();
    if !next
        .volumes
        .iter()
        .any(|existing| existing.source == volume)
    {
        next.volumes.push(Volume {
            source: volume.to_owned(),
            target: MODEL_CACHE.to_owned(),
            read_only: false,
        });
    }
    next.environment
        .insert("YOUGORI_MODEL_IMPORT".to_owned(), "1".to_owned());
    next
}

/// The options after [`Step::CatalogPublish`] bound `folder` as `binding`: the model bind
/// follows the view and the workload carries the catalog's variables. `runner_manifest` is
/// the folder environment's own manifest, kept as it is; a registry environment carries none.
pub(super) fn with_catalog(
    options: &Options,
    folder: &str,
    binding: &Binding,
    runner_manifest: Option<&Value>,
) -> Options {
    let mut next = options.clone();
    let source = binding.bind_source(folder);
    for bind in next
        .binds
        .iter_mut()
        .filter(|bind| bind.target == MODEL_TARGET)
    {
        bind.source = source.clone();
        bind.read_only = true;
    }
    for (name, value) in catalog_binding::workload_variables(runner_manifest, binding) {
        next.environment.insert(name.to_owned(), value);
    }
    next
}

/// The migration record, as kept under the engine's data directory.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Record {
    version: u32,
    status: MigrationStatus,
    items: Vec<Item>,
    /// The digest over every item's saved options: the backup the migration rests on.
    backup: BackupRef,
    created_at: i64,
    updated_at: i64,
    #[serde(default)]
    rolling_back: bool,
    #[serde(default)]
    rolled_back: bool,
    /// The format this record was read from when it was not [`RECORD_VERSION`]: set by
    /// [`read`] for a version 1 record until [`Record::pin_runtimes`] completes the upgrade.
    /// Never written.
    #[serde(skip)]
    upgraded_from: Option<u32>,
}

/// The first record format (version 1, written by engines built between `98fe2fe` and
/// `965dacc`): items without a runtime id or a recovery intent, no rollback flags, and a
/// backup digest over each environment and its saved options only. Read in full, strictly,
/// then upgraded ([`read`], [`Record::pin_runtimes`]).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecordV1 {
    version: u32,
    status: MigrationStatus,
    items: Vec<ItemV1>,
    backup: BackupRef,
    created_at: i64,
    updated_at: i64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ItemV1 {
    environment: String,
    name: String,
    source: Source,
    steps: Vec<PlannedStep>,
    before: Options,
    #[serde(default)]
    after: Option<Options>,
}

impl RecordV1 {
    /// The version 2 record this one becomes: every item still unpinned (an empty runtime id),
    /// no intent, and `rolled_back` set when a version 1 rollback undid every step (version 1
    /// left such a record "pending" with nothing to do). The backup is verified under version
    /// 1's digest, over each environment and its saved options.
    fn upgrade(self) -> Record {
        let items: Vec<Item> = self
            .items
            .into_iter()
            .map(|item| Item {
                environment: item.environment,
                runtime_id: String::new(),
                name: item.name,
                source: item.source,
                steps: item.steps,
                before: item.before,
                after: item.after,
                intent: None,
            })
            .collect();
        let rolled_back = !items.is_empty()
            && items.iter().all(|item| {
                item.steps
                    .iter()
                    .all(|planned| planned.state == StepState::RolledBack)
            });
        let mut record = Record {
            version: RECORD_VERSION,
            status: self.status,
            items,
            backup: self.backup,
            created_at: self.created_at,
            updated_at: self.updated_at,
            rolling_back: false,
            rolled_back,
            upgraded_from: Some(self.version),
        };
        record.backup.verified = backup_digest_v1(&record.items) == record.backup.manifest_sha256;
        record
    }
}

/// Version 1's digest over every item's saved options: the environment and the options.
fn backup_digest_v1(items: &[Item]) -> Digest {
    let encoded: Vec<Vec<u8>> = items
        .iter()
        .map(|item| {
            let mut bytes = item.environment.as_bytes().to_vec();
            bytes.push(0);
            bytes.extend(serde_json::to_vec(&item.before).unwrap_or_default());
            bytes
        })
        .collect();
    let parts: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
    digest(BACKUP_DOMAIN, &parts)
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// The digest over every item's saved options, in order.
fn backup_digest(items: &[Item]) -> Digest {
    let encoded: Vec<Vec<u8>> = items
        .iter()
        .map(|item| {
            let mut bytes = item.environment.as_bytes().to_vec();
            bytes.push(0);
            bytes.extend(item.runtime_id.as_bytes());
            bytes.push(0);
            bytes.extend(serde_json::to_vec(&item.before).unwrap_or_default());
            bytes
        })
        .collect();
    let parts: Vec<&[u8]> = encoded.iter().map(Vec::as_slice).collect();
    digest(BACKUP_DOMAIN, &parts)
}

/// Why a record was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RecordError {
    /// Nothing is applied before the record reads back with every saved option intact.
    BackupNotVerified,
    /// A rollback with nothing done, or an apply with nothing pending, changes nothing.
    NothingToDo,
    Storage {
        detail: String,
    },
    Malformed {
        detail: String,
    },
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackupNotVerified => f.write_str(
                "the migration record does not read back with every saved workload intact; nothing is applied without that backup",
            ),
            Self::NothingToDo => f.write_str("nothing to do"),
            Self::Storage { detail } => write!(f, "the migration record could not be stored: {detail}"),
            Self::Malformed { detail } => write!(f, "the migration record is not readable: {detail}"),
        }
    }
}

impl std::error::Error for RecordError {}

/// The next step to run: the item's index, the step's index and the options it starts from.
pub(crate) struct NextStep<'a> {
    pub item: usize,
    pub step: usize,
    pub planned: &'a Step,
    pub current: &'a Options,
    pub environment: &'a str,
}

impl Record {
    /// A new record of `items`, pending, resting on the digest over their saved options.
    pub(crate) fn new(items: Vec<Item>) -> Self {
        let backup = BackupRef {
            manifest_sha256: backup_digest(&items),
            verified: true,
        };
        let at = now();
        Self {
            version: RECORD_VERSION,
            status: if items.is_empty() {
                MigrationStatus::NotNeeded
            } else {
                MigrationStatus::Pending
            },
            items,
            backup,
            created_at: at,
            updated_at: at,
            rolling_back: false,
            rolled_back: false,
            upgraded_from: None,
        }
    }

    /// Completes the upgrade of a record [`read`] found in an earlier format: every item is
    /// pinned to its environment's current runtime (`runtimes`, by environment id), and a
    /// verified backup is digested again over the current fields, so the record then reads
    /// as [`RECORD_VERSION`]. `Ok(false)` when the record needed no upgrade. Refused, changing
    /// nothing, when an environment the record names no longer exists: the record cannot be
    /// applied or rolled back against an environment that is gone, and says so.
    pub(crate) fn pin_runtimes(
        &mut self,
        runtimes: &dyn Fn(&str) -> Option<String>,
    ) -> Result<bool, RecordError> {
        let Some(from) = self.upgraded_from else {
            return Ok(false);
        };
        let mut pinned = Vec::with_capacity(self.items.len());
        for item in &self.items {
            let runtime_id = runtimes(&item.environment).ok_or_else(|| RecordError::Malformed {
                detail: format!(
                    "the version {from} record names the environment {} ({}), which no longer \
                     exists; remove the record to start over",
                    item.environment, item.name
                ),
            })?;
            pinned.push(runtime_id);
        }
        for (item, runtime_id) in self.items.iter_mut().zip(pinned) {
            item.runtime_id = runtime_id;
        }
        if self.backup.verified {
            self.backup.manifest_sha256 = backup_digest(&self.items);
        }
        self.updated_at = now();
        Ok(true)
    }

    /// The format the record was read from, when it was not the current one.
    pub(crate) fn upgraded_from(&self) -> Option<u32> {
        self.upgraded_from
    }

    pub(crate) fn status(&self) -> MigrationStatus {
        if self.rolling_back || self.items.iter().any(|item| item.intent.is_some()) {
            MigrationStatus::Interrupted {
                completed: self.completed(),
                total: self.total(),
            }
        } else {
            self.status
        }
    }

    pub(crate) fn items(&self) -> &[Item] {
        &self.items
    }

    pub(crate) fn backup(&self) -> BackupRef {
        self.backup
    }

    fn total(&self) -> u32 {
        self.items.iter().map(|item| item.steps.len() as u32).sum()
    }

    fn completed(&self) -> u32 {
        self.items.iter().map(|item| item.done() as u32).sum()
    }

    /// Recomputes the backup digest and records whether the saved options are intact.
    pub(crate) fn verify(&mut self) -> bool {
        self.backup.verified = backup_digest(&self.items) == self.backup.manifest_sha256;
        self.backup.verified
    }

    /// The next pending or failed step, in item order, or `None` when every step is done.
    pub(crate) fn next(&self) -> Option<NextStep<'_>> {
        self.items.iter().enumerate().find_map(|(index, item)| {
            item.steps
                .iter()
                .position(|planned| {
                    matches!(planned.state, StepState::Pending | StepState::Failed { .. })
                })
                .map(|step| NextStep {
                    item: index,
                    step,
                    planned: &item.steps[step].step,
                    current: item.current(),
                    environment: &item.environment,
                })
        })
    }

    /// Refuses an apply that would change anything without the verified backup or with
    /// nothing pending.
    pub(crate) fn begin(&mut self) -> Result<(), RecordError> {
        if !self.backup.verified {
            return Err(RecordError::BackupNotVerified);
        }
        if self.next().is_none() {
            return Err(RecordError::NothingToDo);
        }
        Ok(())
    }

    /// Records that step `step` of item `item` produced `after`.
    pub(crate) fn complete(&mut self, item: usize, step: usize, after: Options) {
        if let Some(planned) = self
            .items
            .get_mut(item)
            .and_then(|item| item.steps.get_mut(step))
        {
            planned.state = StepState::Done;
        }
        if let Some(item) = self.items.get_mut(item) {
            item.after = Some(after);
            item.intent = None;
        }
        self.status = if self.next().is_none() {
            MigrationStatus::Completed
        } else {
            MigrationStatus::InProgress {
                completed: self.completed(),
                total: self.total(),
            }
        };
        self.updated_at = now();
    }

    /// Records that step `step` of item `item` failed with `error`; the migration is
    /// interrupted and resumes at this step.
    pub(crate) fn fail(&mut self, item: usize, step: usize, error: String) {
        if let Some(planned) = self
            .items
            .get_mut(item)
            .and_then(|item| item.steps.get_mut(step))
        {
            planned.state = StepState::Failed { error };
        }
        self.status = MigrationStatus::Interrupted {
            completed: self.completed(),
            total: self.total(),
        };
        self.updated_at = now();
    }

    /// The items with a completed step, newest first: what a rollback restores.
    pub(crate) fn rollback_order(&self) -> Vec<usize> {
        self.items
            .iter()
            .enumerate()
            .rev()
            .filter(|(_, item)| item.done() > 0 || item.intent.is_some())
            .map(|(index, _)| index)
            .collect()
    }

    /// Records that item `item` was restored to its saved options.
    pub(crate) fn restored(&mut self, item: usize) {
        if let Some(item) = self.items.get_mut(item) {
            for planned in &mut item.steps {
                if planned.state == StepState::Done {
                    planned.state = StepState::RolledBack;
                }
            }
            item.after = None;
            item.intent = None;
        }
        self.status = if self.items.iter().any(|item| item.done() > 0) {
            MigrationStatus::Interrupted {
                completed: self.completed(),
                total: self.total(),
            }
        } else {
            MigrationStatus::Pending
        };
        self.updated_at = now();
    }

    /// The record for the status reply.
    pub(crate) fn view(&self) -> Value {
        json!({
            "status": self.status(),
            "rollingBack": self.rolling_back,
            "rolledBack": self.rolled_back,
            "backup": self.backup,
            "steps": { "completed": self.completed(), "total": self.total() },
            "createdAt": self.created_at,
            "updatedAt": self.updated_at,
            "items": self.items.iter().map(|item| json!({
                "environment": item.environment,
                "name": item.name,
                "source": item.source,
                "recoveryPending": item.intent.is_some(),
                "steps": item.steps.iter().map(|planned| json!({
                    "step": planned.step.name(),
                    "detail": planned.step,
                    "state": planned.state,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
        })
    }
}

/// Reads the record in `directory`, verifying its backup; `None` when there is none.
pub(crate) fn read(directory: &Path) -> Result<Option<Record>, RecordError> {
    let path = directory.join(RECORD_FILE);
    let file = match fs::File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(RecordError::Storage {
                detail: error.to_string(),
            })
        }
    };
    let mut text = String::new();
    file.take(RECORD_LIMIT + 1)
        .read_to_string(&mut text)
        .map_err(|error| RecordError::Storage {
            detail: error.to_string(),
        })?;
    if text.len() as u64 > RECORD_LIMIT {
        return Err(RecordError::Malformed {
            detail: format!("larger than {RECORD_LIMIT} bytes"),
        });
    }
    let version = serde_json::from_str::<Value>(&text)
        .map_err(|error| RecordError::Malformed {
            detail: error.to_string(),
        })?
        .get("version")
        .and_then(Value::as_u64);
    match version {
        Some(1) => {
            let record: RecordV1 =
                serde_json::from_str(&text).map_err(|error| RecordError::Malformed {
                    detail: format!("version 1: {error}"),
                })?;
            Ok(Some(record.upgrade()))
        }
        Some(found) if found == u64::from(RECORD_VERSION) => {
            let mut record: Record =
                serde_json::from_str(&text).map_err(|error| RecordError::Malformed {
                    detail: error.to_string(),
                })?;
            record.verify();
            Ok(Some(record))
        }
        Some(found) => Err(RecordError::Malformed {
            detail: format!("version {found} is not {RECORD_VERSION} or 1"),
        }),
        None => Err(RecordError::Malformed {
            detail: "no version".to_owned(),
        }),
    }
}

/// Reads the engine's record and completes the upgrade of an earlier format at once: the
/// items pinned to their environments' current runtimes and the record written back as
/// [`RECORD_VERSION`], before any step runs against it. The format it was read from is
/// returned beside it.
fn read_current(app: &crate::AppHandle) -> Result<(Option<Record>, Option<u32>), String> {
    use tauri::Manager;
    let directory = directory(app);
    let Some(mut record) = read(&directory).map_err(|error| error.to_string())? else {
        return Ok((None, None));
    };
    let Some(from) = record.upgraded_from() else {
        return Ok((Some(record), None));
    };
    let state = app.state::<crate::store::PlatformStore>().snapshot()?;
    let runtimes = |environment: &str| {
        state
            .environments
            .iter()
            .find(|env| env.id == environment)
            .map(|env| env.runtime_id.clone().unwrap_or_else(|| env.id.clone()))
    };
    record
        .pin_runtimes(&runtimes)
        .map_err(|error| error.to_string())?;
    write(&directory, &record).map_err(|error| error.to_string())?;
    Ok((Some(record), Some(from)))
}

/// Writes `record` into `directory` atomically.
pub(crate) fn write(directory: &Path, record: &Record) -> Result<(), RecordError> {
    let storage = |error: io::Error| RecordError::Storage {
        detail: error.to_string(),
    };
    fs::create_dir_all(directory).map_err(storage)?;
    let bytes = serde_json::to_vec_pretty(record).map_err(|error| RecordError::Storage {
        detail: error.to_string(),
    })?;
    if bytes.len() as u64 > RECORD_LIMIT {
        return Err(RecordError::Storage {
            detail: format!(
                "record exceeds the {RECORD_LIMIT}-byte recovery limit; previous record kept"
            ),
        });
    }
    let mut file = tempfile::NamedTempFile::new_in(directory).map_err(storage)?;
    io::Write::write_all(&mut file, &bytes).map_err(storage)?;
    file.as_file().sync_all().map_err(storage)?;
    file.persist(directory.join(RECORD_FILE))
        .map_err(|error| storage(error.error))?;
    Ok(())
}

/// Removes a completed record, so the next preview starts afresh.
#[cfg(test)]
pub(crate) fn clear(directory: &Path) -> Result<(), RecordError> {
    match fs::remove_file(directory.join(RECORD_FILE)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(RecordError::Storage {
            detail: error.to_string(),
        }),
    }
}

/// The preview reply over `dispositions`, beside the record `record` when one exists.
pub(crate) fn preview_view(
    dispositions: &[Disposition],
    catalog_open: bool,
    record: Option<&Record>,
) -> Value {
    let migrate = dispositions
        .iter()
        .filter(|disposition| matches!(disposition, Disposition::Migrate(_)))
        .count();
    json!({
        "catalogOpen": catalog_open,
        "environments": dispositions,
        "toMigrate": migrate,
        "record": record.map(Record::view),
        "status": record.map(Record::status).unwrap_or(if migrate == 0 { MigrationStatus::NotNeeded } else { MigrationStatus::Pending }),
    })
}

// ---- The engine's glue ------------------------------------------------------------------

/// The `model_migration` automation method: `preview` (the default), `apply`, `rollback`,
/// `status`.
pub(crate) async fn dispatch(
    app: crate::AppHandle,
    action: Option<String>,
) -> Result<Value, String> {
    match action.as_deref().unwrap_or("preview") {
        "preview" => preview(&app).await,
        "status" => status(&app),
        "apply" => apply(&app).await,
        "rollback" => rollback(&app).await,
        other => Err(format!(
            "Unknown model_migration action '{other}'. Use preview, status, apply or rollback."
        )),
    }
}

fn directory(app: &crate::AppHandle) -> PathBuf {
    use tauri::Manager;
    app.state::<crate::store::PlatformStore>()
        .data_folder(DIRECTORY)
}

/// Every model environment with its saved options.
fn candidates(app: &crate::AppHandle) -> Result<Vec<Candidate>, String> {
    use crate::models::{EnvironmentKind, EnvironmentStatus, RuntimeProviderKind};
    use tauri::Manager;
    let store = app.state::<crate::store::PlatformStore>();
    let runtime = app.state::<crate::runtime::RuntimeManager>();
    let state = store.snapshot()?;
    let mut candidates = Vec::new();
    for env in state.environments.iter().filter(|env| {
        env.kind == EnvironmentKind::Container && env.description.starts_with("Hugging Face · ")
    }) {
        let options = runtime.workload_options(env.runtime_id.as_deref().unwrap_or(&env.id))?;
        candidates.push(Candidate {
            id: env.id.clone(),
            runtime_id: env.runtime_id.as_deref().unwrap_or(&env.id).to_owned(),
            name: env.name.clone(),
            stopped: env.status == EnvironmentStatus::Stopped,
            cuda: env.gpu_access && env.provider == Some(RuntimeProviderKind::YougoriCuda),
            storage_limit_gb: env.storage_limit_gb,
            options,
        });
    }
    Ok(candidates)
}

async fn catalog_open() -> Result<bool, String> {
    tokio::task::spawn_blocking(|| {
        matches!(
            crate::catalog_service::engine(),
            crate::catalog_service::EngineCatalog::Open { .. }
        )
    })
    .await
    .map_err(|error| error.to_string())
}

fn dispositions(candidates: &[Candidate], catalog_open: bool) -> Vec<Disposition> {
    candidates
        .iter()
        .filter_map(|candidate| {
            classify(
                candidate,
                catalog_open,
                &registry_record,
                &super::model_cache_volume,
            )
        })
        .collect()
}

async fn preview(app: &crate::AppHandle) -> Result<Value, String> {
    let catalog_open = catalog_open().await?;
    let candidates = candidates(app)?;
    let dispositions = dispositions(&candidates, catalog_open);
    let (record, _) = read_current(app)?;
    Ok(preview_view(&dispositions, catalog_open, record.as_ref()))
}

fn status(app: &crate::AppHandle) -> Result<Value, String> {
    let (record, upgraded_from) = read_current(app)?;
    Ok(json!({
        "directory": directory(app).display().to_string(),
        "status": record.as_ref().map(Record::status).unwrap_or(MigrationStatus::NotNeeded),
        "record": record.as_ref().map(Record::view),
        "upgradedFrom": upgraded_from,
    }))
}

/// Prepares a target under a previously journaled execution identity; no workload is installed.
async fn prepare(
    step: &Step,
    current: &Options,
    execution: Option<ExecutionId>,
) -> Result<Options, String> {
    match step {
        Step::OwnVolume { volume, .. } => {
            let next = with_own_volume(current, volume);
            Ok(next)
        }
        Step::CatalogPublish { folder, registry } => {
            let model = current
                .environment
                .get("YOUGORI_MODEL")
                .cloned()
                .ok_or("the workload names no model")?;
            let quant = current.environment.get("YOUGORI_MODEL_QUANT").cloned();
            let format = current.environment.get("YOUGORI_MODEL_FORMAT").cloned();
            let execution =
                execution.ok_or("catalog migration has no durable execution identity")?;
            let folder_path = PathBuf::from(folder);
            let (binding, manifest) = if *registry {
                let record = registry_record(&folder_path).ok_or(
                    "the registry's record of the cached version is missing or unreadable",
                )?;
                let files = record["files"].as_array().cloned().unwrap_or_default();
                let check = json!({"format": format.unwrap_or_else(|| "safetensors".into()), "quant": quant});
                let binding = tokio::task::spawn_blocking(move || {
                    catalog_binding::bind_registry_for_execution(
                        crate::catalog_service::engine(),
                        crate::catalog_service::engine_views(),
                        &folder_path,
                        &check,
                        &files,
                        &crate::model_memory::manifest::CancellationToken::new(),
                        execution,
                    )
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
                (binding, None)
            } else {
                let folder_text = folder.clone();
                let (check, manifest, contents) = tokio::task::spawn_blocking(move || {
                    super::local::inspect_verified(&model, &folder_text, quant.as_deref())
                })
                .await
                .map_err(|error| error.to_string())??;
                let files = manifest["files"].as_array().cloned().unwrap_or_default();
                let binding = tokio::task::spawn_blocking(move || {
                    catalog_binding::bind_for_execution(
                        crate::catalog_service::engine(),
                        crate::catalog_service::engine_views(),
                        &folder_path,
                        &check,
                        &files,
                        Some(&contents),
                        &crate::model_memory::manifest::CancellationToken::new(),
                        execution,
                    )
                })
                .await
                .map_err(|error| error.to_string())?
                .map_err(|error| error.to_string())?;
                (binding, Some(manifest))
            };
            if !matches!(binding, Binding::Catalog(_)) {
                return Err("the engine's catalog is not open; set YOUGORI_CATALOG_ROOT and YOUGORI_CATALOG_QUOTA_BYTES and restart the engine".into());
            }
            let next = with_catalog(current, folder, &binding, manifest.as_ref());
            Ok(next)
        }
    }
}

struct EnginePort<'a> {
    app: &'a crate::AppHandle,
    environment: String,
    options: crate::runtime::WorkloadOptionsLease,
}
impl recovery::Port for EnginePort<'_> {
    async fn ready(&mut self, after: &Options) -> Result<(), String> {
        let after = after.clone();
        tokio::task::spawn_blocking(move || {
            let mut refreshed = after.clone();
            catalog_binding::refresh_engine(&mut refreshed).map_err(|e| e.to_string())?;
            if refreshed != after { return Err("YOUGORI_MIGRATION_CONFLICT: the catalog view moved; rollback before replanning".into()); }
            Ok(())
        }).await.map_err(|e| e.to_string())?
    }
    fn current(&self) -> Result<(String, Options), String> {
        use tauri::Manager;
        let env = self
            .app
            .state::<crate::store::PlatformStore>()
            .environment(&self.environment)?;
        if env.status != crate::models::EnvironmentStatus::Stopped {
            return Err("YOUGORI_MIGRATION_CONFLICT: stop the model before migrating it".into());
        }
        let id = env.runtime_id.as_deref().unwrap_or(&env.id).to_owned();
        let options = self
            .app
            .state::<crate::runtime::RuntimeManager>()
            .workload_options(&id)?;
        Ok((id, options))
    }
    async fn prepare(
        &mut self,
        step: &Step,
        before: &Options,
        execution: Option<ExecutionId>,
    ) -> Result<Options, String> {
        let after = prepare(step, before, execution).await?;
        #[cfg(feature = "acceptance")]
        if matches!(step, Step::CatalogPublish { .. }) {
            acceptance_pause("catalog-prepared").await?;
        }
        Ok(after)
    }
    async fn install(&mut self, before: &Options, after: &Options) -> Result<(), String> {
        use tauri::Manager;
        let env = self
            .app
            .state::<crate::store::PlatformStore>()
            .environment(&self.environment)?;
        self.options.install(before, after)?;
        #[cfg(feature = "acceptance")]
        acceptance_pause("options-installed").await?;
        // Intent remains durable on failure; never silently restore over a later writer.
        self.app
            .state::<crate::runtime::RuntimeManager>()
            .update_workload_configuration(&env)
            .await?;
        #[cfg(feature = "acceptance")]
        acceptance_pause("runtime-configured").await?;
        Ok(())
    }
    async fn release(&mut self, execution: ExecutionId) -> Result<(), String> {
        tokio::task::spawn_blocking(move || {
            crate::catalog_service::release_model_view(
                crate::catalog_service::engine(),
                crate::catalog_service::engine_views(),
                &execution,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        })
        .await
        .map_err(|e| e.to_string())?
    }
}

/// Acceptance builds only: an external harness kills its own disposable engine at an
/// observed side-effect boundary. Releases contain neither the switch nor the pause.
#[cfg(feature = "acceptance")]
async fn acceptance_pause(phase: &str) -> Result<(), String> {
    if std::env::var("YOUGORI_ACCEPTANCE_MIGRATION_PAUSE").as_deref() != Ok(phase) {
        return Ok(());
    }
    let root = crate::acceptance::data_directory()
        .ok_or("migration pause requires a disposable acceptance data directory")?;
    let marker = root.join(DIRECTORY).join("acceptance-pause.json");
    let bytes = serde_json::to_vec(&json!({"phase": phase, "pid": std::process::id()}))
        .map_err(|e| e.to_string())?;
    let mut file =
        tempfile::NamedTempFile::new_in(marker.parent().unwrap()).map_err(|e| e.to_string())?;
    io::Write::write_all(&mut file, &bytes).map_err(|e| e.to_string())?;
    file.as_file().sync_all().map_err(|e| e.to_string())?;
    file.persist(marker).map_err(|e| e.to_string())?;
    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
    Err("acceptance migration pause expired without external termination".into())
}

async fn apply(app: &crate::AppHandle) -> Result<Value, String> {
    use tauri::Manager;
    let directory = directory(app);
    let (previous, _) = read_current(app)?;
    let needs_plan = previous
        .as_ref()
        .is_none_or(|r| r.rolled_back || r.status() == MigrationStatus::Completed);
    // Discovery may fail; the prior record remains untouched.
    let items = if needs_plan {
        dispositions(&candidates(app)?, catalog_open().await?)
            .into_iter()
            .filter_map(|d| match d {
                Disposition::Migrate(item) => Some(item),
                _ => None,
            })
            .collect()
    } else {
        Vec::new()
    };
    let Some(mut record) = recovery::begin_apply(&directory, previous, items)? else {
        return Ok(
            json!({"status": MigrationStatus::NotNeeded, "detail": "No new migration is needed; the previous recovery record was preserved."}),
        );
    };
    record.begin().map_err(|e| e.to_string())?;
    let mut done = Vec::new();
    while let Some(next) = record.next() {
        let (item, step, environment, runtime_id) = (
            next.item,
            next.step,
            next.environment.to_owned(),
            record.items[next.item].runtime_id.clone(),
        );
        // Same lock/order as start, delete, factory reset and network changes. The options
        // reservation additionally excludes background writers that do not use that lock.
        let lock = crate::commands::environment_network_lock(&environment).await;
        let _lifecycle = lock.lock().await;
        let runtime = app.state::<crate::runtime::RuntimeManager>();
        let env = app
            .state::<crate::store::PlatformStore>()
            .environment(&environment)?;
        let _configuration =
            crate::commands::environment_container_policy_guard(&runtime, &env).await?;
        let options = runtime.reserve_workload_options(&runtime_id)?;
        let mut port = EnginePort {
            app,
            environment: environment.clone(),
            options,
        };
        recovery::apply_step(&mut port, &directory, &mut record, item, step).await?;
        done.push(
            json!({"environment": environment, "step": record.items[item].steps[step].step.name()}),
        );
    }
    Ok(json!({"status": record.status(), "done": done, "failed": null, "record": record.view()}))
}

async fn rollback(app: &crate::AppHandle) -> Result<Value, String> {
    use tauri::Manager;
    let directory = directory(app);
    let (record, _) = read_current(app)?;
    let Some(mut record) = record else {
        return Err("no migration record exists; nothing to roll back".into());
    };
    if !record.backup.verified {
        return Err(RecordError::BackupNotVerified.to_string());
    }
    record.rolling_back = true;
    write(&directory, &record).map_err(|e| e.to_string())?;
    let mut restored = Vec::new();
    for index in record.rollback_order() {
        let environment = record.items[index].environment.clone();
        let lock = crate::commands::environment_network_lock(&environment).await;
        let _lifecycle = lock.lock().await;
        let runtime = app.state::<crate::runtime::RuntimeManager>();
        let env = app
            .state::<crate::store::PlatformStore>()
            .environment(&environment)?;
        let _configuration =
            crate::commands::environment_container_policy_guard(&runtime, &env).await?;
        let options = runtime.reserve_workload_options(&record.items[index].runtime_id)?;
        let mut port = EnginePort {
            app,
            environment: environment.clone(),
            options,
        };
        recovery::restore_item(&mut port, &directory, &mut record, index).await?;
        restored.push(environment);
    }
    record.rolling_back = false;
    record.rolled_back = true;
    write(&directory, &record).map_err(|e| e.to_string())?;
    Ok(
        json!({"status": record.status(), "rolledBack": true, "restored": restored, "record": record.view()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(pairs: &[(&str, &str)], bind: Option<&str>, volume: Option<&str>) -> Options {
        let mut options = Options::default();
        options
            .environment
            .insert("YOUGORI_MODEL".into(), "acme/model".into());
        for (name, value) in pairs {
            options
                .environment
                .insert((*name).to_owned(), (*value).to_owned());
        }
        if let Some(source) = bind {
            options.binds.push(Volume {
                source: source.to_owned(),
                target: MODEL_TARGET.to_owned(),
                read_only: true,
            });
        }
        if let Some(name) = volume {
            options.volumes.push(Volume {
                source: name.to_owned(),
                target: MODEL_CACHE.to_owned(),
                read_only: false,
            });
        }
        options
    }

    fn manifest(bytes: u64) -> String {
        json!({"revision": "a".repeat(64), "files": [{"name": "model.safetensors", "size": bytes, "sha256": "b".repeat(64)}, {"name": "config.json", "size": 700, "sha256": "c".repeat(64)}]}).to_string()
    }

    fn candidate(options: Options) -> Candidate {
        Candidate {
            id: "env-one".into(),
            runtime_id: "runtime-one".into(),
            name: "Model One".into(),
            stopped: true,
            cuda: true,
            storage_limit_gb: Some(40.0),
            options,
        }
    }

    fn no_record(_: &Path) -> Option<Value> {
        None
    }

    fn fixed_volume() -> String {
        "model-0123abcd-models".into()
    }

    fn classify_with(candidate: &Candidate, catalog_open: bool) -> Option<Disposition> {
        classify(candidate, catalog_open, &no_record, &fixed_volume)
    }

    #[test]
    fn each_environment_is_read_for_how_its_files_reach_the_runner() {
        assert_eq!(
            source_of(&options(&[], None, Some("model-0123abcd-models"))),
            Source::HuggingFace
        );
        assert_eq!(
            source_of(&options(
                &[("YOUGORI_MODEL_PATH", "/yougori-model")],
                Some("D:/models/one"),
                None
            )),
            Source::MountRead
        );
        assert_eq!(
            source_of(&options(
                &[("YOUGORI_MODEL_IMPORT", "1")],
                Some("D:/models/one"),
                Some("model-0123abcd-models")
            )),
            Source::ImportedVolume
        );
        // The import flag without the environment's own volume is the mount path still.
        assert_eq!(
            source_of(&options(
                &[("YOUGORI_MODEL_IMPORT", "1")],
                Some("D:/models/one"),
                Some("my-own-data")
            )),
            Source::MountRead
        );
        assert_eq!(
            source_of(&options(
                &[(EXECUTION_OPTION, "exe-1")],
                Some("D:/catalog/views/exe-1"),
                Some("model-0123abcd-models")
            )),
            Source::Catalog
        );
        assert_eq!(
            source_of(&options(
                &[("YOUGORI_MODEL_FORMAT", "source")],
                Some("D:/models/src"),
                None
            )),
            Source::SourceOnly
        );
    }

    #[test]
    fn a_mount_read_cuda_environment_gets_its_own_volume_and_the_catalog_when_the_catalog_is_open()
    {
        let mount = candidate(options(
            &[(RUNNER_MANIFEST, &manifest(9 << 30))],
            Some("D:/models/one"),
            None,
        ));
        let Some(Disposition::Migrate(item)) = classify_with(&mount, false) else {
            panic!()
        };
        assert_eq!(item.source, Source::MountRead);
        assert_eq!(item.steps.len(), 1);
        assert_eq!(
            item.steps[0].step,
            Step::OwnVolume {
                volume: fixed_volume(),
                bytes: (9 << 30) + 700,
                storage_gb_needed: 23
            }
        );
        assert_eq!(item.before, mount.options);
        let Some(Disposition::Migrate(both)) = classify_with(&mount, true) else {
            panic!()
        };
        assert_eq!(both.steps.len(), 2);
        assert_eq!(
            both.steps[1].step,
            Step::CatalogPublish {
                folder: "D:/models/one".into(),
                registry: false
            }
        );
        // Already imported: only the catalog is left, and only when it is open.
        let imported = candidate(options(
            &[
                (RUNNER_MANIFEST, &manifest(1 << 30)),
                ("YOUGORI_MODEL_IMPORT", "1"),
            ],
            Some("D:/models/one"),
            Some("model-0123abcd-models"),
        ));
        assert!(matches!(
            classify_with(&imported, false),
            Some(Disposition::UpToDate {
                source: Source::ImportedVolume,
                ..
            })
        ));
        let Some(Disposition::Migrate(catalog_only)) = classify_with(&imported, true) else {
            panic!()
        };
        assert_eq!(catalog_only.steps.len(), 1);
        assert!(matches!(
            catalog_only.steps[0].step,
            Step::CatalogPublish {
                registry: false,
                ..
            }
        ));
        // On the catalog path already, or a Hugging Face download, or source only: nothing.
        for (options, source) in [
            (
                options(
                    &[(EXECUTION_OPTION, "exe-1")],
                    Some("D:/catalog/views/exe-1"),
                    Some("model-0123abcd-models"),
                ),
                Source::Catalog,
            ),
            (
                options(&[], None, Some("model-0123abcd-models")),
                Source::HuggingFace,
            ),
            (
                options(
                    &[("YOUGORI_MODEL_FORMAT", "source")],
                    Some("D:/models/src"),
                    None,
                ),
                Source::SourceOnly,
            ),
        ] {
            assert!(
                matches!(classify_with(&candidate(options), true), Some(Disposition::UpToDate { source: found, .. }) if found == source),
                "{source:?}"
            );
        }
        // A workload that runs no model is not a candidate at all.
        let mut other = options(&[], Some("D:/x"), None);
        other.environment.remove("YOUGORI_MODEL");
        assert!(classify_with(&candidate(other), true).is_none());
    }

    #[test]
    fn a_cpu_runner_reads_the_mount_by_design_and_a_registry_version_reads_its_record() {
        let mut cpu = candidate(options(
            &[
                (RUNNER_MANIFEST, &manifest(1 << 30)),
                ("YOUGORI_MODEL_CPU", "1"),
            ],
            Some("D:/models/one"),
            None,
        ));
        cpu.cuda = false;
        assert!(matches!(
            classify_with(&cpu, false),
            Some(Disposition::UpToDate {
                source: Source::MountRead,
                ..
            })
        ));
        let Some(Disposition::Migrate(catalog)) = classify_with(&cpu, true) else {
            panic!()
        };
        assert_eq!(catalog.steps.len(), 1);
        // A registry version carries no runner manifest: the record in its folder gives the sizes.
        let registry = candidate(options(
            &[("YOUGORI_REGISTRY_VERSION", "v1")],
            Some("D:/pool/model-registry/abcd"),
            None,
        ));
        let record = |folder: &Path| {
            (folder == Path::new("D:/pool/model-registry/abcd")).then(|| json!({"revision": "r", "files": [{"name": "model.safetensors", "size": 2u64 << 30, "sha256": "x"}]}))
        };
        let Some(Disposition::Migrate(item)) = classify(&registry, true, &record, &fixed_volume)
        else {
            panic!()
        };
        assert_eq!(
            item.steps[0].step,
            Step::OwnVolume {
                volume: fixed_volume(),
                bytes: 2 << 30,
                storage_gb_needed: 20
            }
        );
        assert_eq!(
            item.steps[1].step,
            Step::CatalogPublish {
                folder: "D:/pool/model-registry/abcd".into(),
                registry: true
            }
        );
        // Without the record the sizes are unknown: refused with what records them.
        assert!(
            matches!(classify(&registry, true, &no_record, &fixed_volume), Some(Disposition::Refused { remedy, .. }) if remedy.contains("run the model again"))
        );
    }

    #[test]
    fn too_little_storage_is_refused_with_the_size_to_set_and_a_running_model_is_deferred() {
        let mut small = candidate(options(
            &[(RUNNER_MANIFEST, &manifest(9 << 30))],
            Some("D:/models/one"),
            None,
        ));
        small.storage_limit_gb = Some(20.0);
        let Some(Disposition::Refused { reason, remedy, .. }) = classify_with(&small, false) else {
            panic!()
        };
        assert!(
            reason.contains("20 GB") && reason.contains("23 GB"),
            "{reason}"
        );
        assert!(remedy.contains("at least 23 GB"), "{remedy}");
        let mut running = candidate(options(
            &[(RUNNER_MANIFEST, &manifest(1 << 30))],
            Some("D:/models/one"),
            None,
        ));
        running.stopped = false;
        assert!(
            matches!(classify_with(&running, false), Some(Disposition::Deferred { reason, .. }) if reason.contains("stop it first"))
        );
    }

    #[test]
    fn the_own_volume_step_adds_exactly_the_volume_and_the_import_flag_once() {
        let before = options(
            &[(RUNNER_MANIFEST, &manifest(1))],
            Some("D:/models/one"),
            None,
        );
        let after = with_own_volume(&before, "model-0123abcd-models");
        assert_eq!(
            after.volumes,
            vec![Volume {
                source: "model-0123abcd-models".into(),
                target: MODEL_CACHE.into(),
                read_only: false
            }]
        );
        assert_eq!(
            after
                .environment
                .get("YOUGORI_MODEL_IMPORT")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(after.binds, before.binds);
        assert_eq!(
            with_own_volume(&after, "model-0123abcd-models"),
            after,
            "idempotent"
        );
        assert_eq!(source_of(&after), Source::ImportedVolume);
    }

    #[test]
    fn the_record_resumes_after_its_completed_steps_and_rolls_back_to_the_saved_options() {
        let dir = tempfile::tempdir().unwrap();
        let one = candidate(options(
            &[(RUNNER_MANIFEST, &manifest(1 << 30))],
            Some("D:/models/one"),
            None,
        ));
        let mut two = candidate(options(
            &[(RUNNER_MANIFEST, &manifest(2 << 30))],
            Some("D:/models/two"),
            None,
        ));
        two.id = "env-two".into();
        let items: Vec<Item> = [&one, &two]
            .iter()
            .filter_map(|candidate| match classify_with(candidate, true) {
                Some(Disposition::Migrate(item)) => Some(item),
                _ => None,
            })
            .collect();
        assert_eq!(items.len(), 2);
        let mut record = Record::new(items);
        assert_eq!(record.status(), MigrationStatus::Pending);
        assert!(record.backup().verified);
        write(dir.path(), &record).unwrap();
        let mut read_back = read(dir.path()).unwrap().unwrap();
        assert!(read_back.backup().verified);
        assert_eq!(read_back, record);
        read_back.begin().unwrap();

        // A performer that fails the second environment's first step: one item done, interrupted.
        let perform =
            |step: &Step, current: &Options, environment: &str| -> Result<Options, String> {
                if environment == "env-two" {
                    return Err("the model is running or paused; stop it first".into());
                }
                Ok(match step {
                    Step::OwnVolume { volume, .. } => with_own_volume(current, volume),
                    Step::CatalogPublish { .. } => {
                        let mut next = current.clone();
                        next.environment
                            .insert(EXECUTION_OPTION.into(), "exe-1".into());
                        next
                    }
                })
            };
        let run = |record: &mut Record| {
            while let Some(next) = record.next() {
                let (item, step, planned, current, environment) = (
                    next.item,
                    next.step,
                    next.planned.clone(),
                    next.current.clone(),
                    next.environment.to_owned(),
                );
                match perform(&planned, &current, &environment) {
                    Ok(after) => record.complete(item, step, after),
                    Err(error) => {
                        record.fail(item, step, error);
                        write(dir.path(), record).unwrap();
                        break;
                    }
                }
                write(dir.path(), record).unwrap();
            }
        };
        run(&mut record);
        assert_eq!(
            record.status(),
            MigrationStatus::Interrupted {
                completed: 2,
                total: 4
            }
        );
        assert!(matches!(
            record.items()[1].steps[0].state,
            StepState::Failed { .. }
        ));
        assert_eq!(
            record.items()[0]
                .steps
                .iter()
                .filter(|planned| planned.state == StepState::Done)
                .count(),
            2
        );
        assert_eq!(source_of(record.items()[0].current()), Source::Catalog);
        // After a restart the record reads back as it was and resumes at the failed step.
        let mut resumed = read(dir.path()).unwrap().unwrap();
        assert_eq!(
            resumed.status(),
            MigrationStatus::Interrupted {
                completed: 2,
                total: 4
            }
        );
        let next = resumed.next().unwrap();
        assert_eq!((next.item, next.step), (1, 0));
        resumed.begin().unwrap();
        // The second environment was stopped meanwhile: the resume completes.
        let perform_all = |step: &Step, current: &Options| match step {
            Step::OwnVolume { volume, .. } => with_own_volume(current, volume),
            Step::CatalogPublish { .. } => {
                let mut next = current.clone();
                next.environment
                    .insert(EXECUTION_OPTION.into(), "exe-2".into());
                next
            }
        };
        while let Some(next) = resumed.next() {
            let (item, step, planned, current) = (
                next.item,
                next.step,
                next.planned.clone(),
                next.current.clone(),
            );
            resumed.complete(item, step, perform_all(&planned, &current));
        }
        assert_eq!(resumed.status(), MigrationStatus::Completed);
        assert!(resumed.begin().is_err(), "nothing pending");
        // Rollback restores the saved options, newest item first, and leaves the record pending.
        assert_eq!(resumed.rollback_order(), vec![1, 0]);
        for index in resumed.rollback_order() {
            let item = &resumed.items()[index];
            assert_eq!(item.before, [&one, &two][index].options);
            resumed.restored(index);
        }
        assert_eq!(resumed.status(), MigrationStatus::Pending);
        assert!(resumed.items().iter().all(|item| item.after.is_none()
            && item
                .steps
                .iter()
                .all(|planned| planned.state == StepState::RolledBack)));
        assert!(resumed.rollback_order().is_empty());
        // A partial rollback leaves the migration interrupted, since done steps remain.
        let mut partial = record.clone();
        partial.restored(0);
        assert!(matches!(
            partial.status(),
            MigrationStatus::Pending | MigrationStatus::Interrupted { .. }
        ));
    }

    /// `record` as an engine of version 1 wrote it: no runtime ids, intents or rollback
    /// flags, and the backup digested over each environment and its saved options only.
    fn as_version_1(record: &Record) -> Value {
        let mut value = serde_json::to_value(record).unwrap();
        value["version"] = json!(1);
        value["backup"]["manifest_sha256"] = json!(backup_digest_v1(&record.items));
        value["backup"]["verified"] = json!(true);
        let object = value.as_object_mut().unwrap();
        object.remove("rolling_back");
        object.remove("rolled_back");
        for item in value["items"].as_array_mut().unwrap() {
            let item = item.as_object_mut().unwrap();
            item.remove("runtime_id");
            item.remove("intent");
        }
        value
    }

    #[test]
    fn a_version_1_record_is_read_pinned_to_its_runtimes_and_written_back_as_version_2() {
        let dir = tempfile::tempdir().unwrap();
        let mut one = candidate(options(
            &[(RUNNER_MANIFEST, &manifest(1 << 30))],
            Some("D:/models/one"),
            None,
        ));
        one.id = "env-one".into();
        let mut two = candidate(options(
            &[(RUNNER_MANIFEST, &manifest(2 << 30))],
            Some("D:/models/two"),
            None,
        ));
        two.id = "env-two".into();
        let items: Vec<Item> = [&one, &two]
            .iter()
            .filter_map(|candidate| match classify_with(candidate, true) {
                Some(Disposition::Migrate(item)) => Some(item),
                _ => None,
            })
            .collect();
        let record = Record::new(items);
        fs::write(
            dir.path().join(RECORD_FILE),
            serde_json::to_vec_pretty(&as_version_1(&record)).unwrap(),
        )
        .unwrap();

        // Read: a version 1 record, verified under its own digest, every item unpinned.
        let mut upgraded = read(dir.path()).unwrap().unwrap();
        assert_eq!(upgraded.upgraded_from(), Some(1));
        assert!(upgraded.backup().verified);
        assert!(!upgraded.rolled_back && !upgraded.rolling_back);
        assert!(upgraded
            .items
            .iter()
            .all(|item| item.runtime_id.is_empty() && item.intent.is_none()));
        assert_eq!(upgraded.status(), MigrationStatus::Pending);
        // A plain version 2 record it is not yet: pinning needs every environment.
        let refused = upgraded
            .pin_runtimes(&|environment| (environment == "env-one").then(|| "rt-one".to_owned()))
            .unwrap_err();
        assert!(
            matches!(&refused, RecordError::Malformed { detail }
                if detail.starts_with("the version 1 record names the environment env-two (")
                    && detail.ends_with("), which no longer exists; remove the record to start over")),
            "{refused:?}"
        );
        assert!(upgraded.items.iter().all(|item| item.runtime_id.is_empty()));
        // Pinned: the runtime ids are the environments' current ones and the backup is the
        // version 2 digest; written back, it reads as any version 2 record.
        assert_eq!(
            upgraded.pin_runtimes(&|environment| Some(format!("rt-{environment}"))),
            Ok(true)
        );
        assert_eq!(upgraded.items[0].runtime_id, "rt-env-one");
        assert_eq!(upgraded.items[1].runtime_id, "rt-env-two");
        assert!(upgraded.backup().verified);
        assert_eq!(
            upgraded.backup().manifest_sha256,
            backup_digest(&upgraded.items)
        );
        write(dir.path(), &upgraded).unwrap();
        let mut again = read(dir.path()).unwrap().unwrap();
        assert_eq!(again.upgraded_from(), None);
        assert_eq!(again.version, RECORD_VERSION);
        assert!(again.backup().verified);
        assert_eq!(again.pin_runtimes(&|_| None), Ok(false));
        assert_eq!(again.items, upgraded.items);

        // A version 1 record whose rollback undid every step was left "pending" with
        // nothing to do (the review's R7); upgraded, it is a rolled-back record a later
        // apply replans from.
        let mut rolled = record.clone();
        for item in &mut rolled.items {
            for planned in &mut item.steps {
                planned.state = StepState::RolledBack;
            }
        }
        fs::write(
            dir.path().join(RECORD_FILE),
            serde_json::to_vec_pretty(&as_version_1(&rolled)).unwrap(),
        )
        .unwrap();
        let rolled = read(dir.path()).unwrap().unwrap();
        assert!(rolled.rolled_back && rolled.upgraded_from() == Some(1));

        // A version 1 record whose saved options changed does not verify, like any other;
        // one in an unknown version is refused with both versions named.
        let mut tampered = as_version_1(&record);
        tampered["items"][0]["before"]["environment"]["YOUGORI_MODEL_IMPORT"] = json!("1");
        fs::write(
            dir.path().join(RECORD_FILE),
            serde_json::to_vec_pretty(&tampered).unwrap(),
        )
        .unwrap();
        assert!(!read(dir.path()).unwrap().unwrap().backup().verified);
        let mut future = as_version_1(&record);
        future["version"] = json!(3);
        fs::write(
            dir.path().join(RECORD_FILE),
            serde_json::to_vec_pretty(&future).unwrap(),
        )
        .unwrap();
        assert_eq!(
            read(dir.path()).unwrap_err(),
            RecordError::Malformed {
                detail: "version 3 is not 2 or 1".to_owned()
            }
        );
    }

    #[test]
    fn a_record_whose_saved_options_changed_is_not_applied_and_unknown_records_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let one = candidate(options(
            &[(RUNNER_MANIFEST, &manifest(1 << 30))],
            Some("D:/models/one"),
            None,
        ));
        let Some(Disposition::Migrate(item)) = classify_with(&one, false) else {
            panic!()
        };
        let record = Record::new(vec![item]);
        write(dir.path(), &record).unwrap();
        // Someone edits a saved option in the record: the backup no longer verifies.
        let path = dir.path().join(RECORD_FILE);
        let text = fs::read_to_string(&path)
            .unwrap()
            .replace("D:/models/one", "D:/models/other");
        fs::write(&path, text).unwrap();
        let mut tampered = read(dir.path()).unwrap().unwrap();
        assert!(!tampered.backup().verified);
        assert_eq!(tampered.begin(), Err(RecordError::BackupNotVerified));
        // A record of another version, or with a field this build does not know, is refused.
        fs::write(
            &path,
            serde_json::to_string(&record)
                .unwrap()
                .replace("\"version\":2", "\"version\":999"),
        )
        .unwrap();
        assert!(matches!(
            read(dir.path()),
            Err(RecordError::Malformed { .. })
        ));
        fs::write(
            &path,
            serde_json::to_string(&record)
                .unwrap()
                .replacen("{", "{\"extra\":1,", 1),
        )
        .unwrap();
        assert!(matches!(
            read(dir.path()),
            Err(RecordError::Malformed { .. })
        ));
        clear(dir.path()).unwrap();
        assert_eq!(read(dir.path()).unwrap(), None);
        clear(dir.path()).unwrap();
        // The preview says what the record and the dispositions amount to.
        let empty = preview_view(&[], false, None);
        assert_eq!(empty["status"], json!(MigrationStatus::NotNeeded));
        let pending = preview_view(&[classify_with(&one, false).unwrap()], false, None);
        assert_eq!(pending["toMigrate"], 1);
        assert_eq!(pending["status"], json!(MigrationStatus::Pending));
        let view = record.view();
        assert_eq!(view["steps"]["total"], 1);
        assert_eq!(view["items"][0]["steps"][0]["step"], "own_volume");
    }
}
