//! The engine's CORE-02 catalog and its automation method `catalog_status` (S02 in
//! docs/combined-plan-leftover-tasks.md: "Connect model files ... to the existing scoped
//! catalog, publication, importer coordination, leases, quota, recovery and garbage
//! collection. Preserve originals; apply the existing trust policy for each artifact
//! class"; the S08 note "catalog wiring once the engine opens a catalog").
//!
//! The owner names the catalog directory with the environment variable
//! [`CATALOG_ROOT_SETTING`], an absolute path, and the space budget of each scope the
//! engine imports into with [`CATALOG_QUOTA_SETTING`], in bytes; both are read once, when
//! the catalog is first used. Nothing has a default: without the directory the status says
//! the catalog is not opened and how to open it, and nothing is imported; without a budget
//! the catalog opens and refuses every import with its typed `no_budget` reason. Where the
//! catalog lives, its budget and whether settings keys should replace the variables are the
//! owner's decisions.
//!
//! A disposable acceptance engine (the `acceptance` build feature, scripts/acceptance/README.md)
//! never uses [`CATALOG_ROOT_SETTING`], which it inherits from the owner's environment: its
//! directory is [`ACCEPTANCE_ROOT_SETTING`], or [`DEFAULT_ROOT_FOLDER`] in its own data folder.
//! It fails closed like the feature's other variables: a relative path, or a root of the
//! installed engine's (the one [`CATALOG_ROOT_SETTING`] names, or anything in the installed
//! engine's data folder, its default root included), opens no catalog, and nothing falls back
//! to another root ([`Settings::for_acceptance`]). A test binary reads none of the catalog's
//! variables ([`engine`]).
//!
//! One engine at a time owns a catalog root: the catalog's open takes the root's exclusive
//! lock (`catalog.lock`, an operating-system file lock released when its process ends), and an
//! engine that finds it held opens nothing there, changes nothing and says which root is in
//! use and what to do ([`OpenRefusal::InUse`]).
//!
//! On open the catalog recovers what an interrupted run left, and registers its classes
//! through the engine's trust-root service (`trust_roots.rs`): model files
//! (`model_weights`) and their sidecars (`model_sidecar`) accept the owner's own originals;
//! model helper bundles (`model_helper`) need a key of the trust roots. OCI layers,
//! guest images and runtime updates (`oci_layer`, `guest_image`, `runtime_update`) get
//! their own verifiers from `sandbox_contract::artifact_policy` (M18F), with the trust
//! roots as their policy source, when a trust-root file is in force at open; without one
//! they wait for the engine's restart. Document manifests and dependency packages have
//! no structure check yet and refuse every publication (O04). A trust-root reload sets
//! the catalog's class policies from the new roots ([`on_trust_roots_reloaded`]).
//!
//! Opening and reloading obey one lock order (review finding R4,
//! docs/manager-work-split/reviewer-findings.md): the catalog is opened and published
//! under the trust-root service's lock ([`publish`]), and a reload holds that same lock
//! while it looks for a published catalog. So a reload either precedes the open, whose
//! catalog then reads the new roots, or follows the publication, which it reaches. No
//! window remains in which a catalog opened under old roots is published after a reload
//! that could not see it. Nothing may open the catalog while already holding the service.
//!
//! `status` (the default) shows every class with its verifier and policy, the objects per
//! scope, class and state with their bytes, quota charges, leases, the model views held
//! beside them, the last recovery and the last collection, reading nothing. `gc` runs the
//! lease-aware garbage collection once. [`import_model_files`] is the model runner's entry
//! for a model folder (see `model_files`); `model_runner::catalog_binding` calls it from
//! the local-folder and registry paths (G04/S02) and then holds a read-only **view** of
//! the published copies ([`hold_model_view`]): `<root>/views/<execution>/<relative path>`,
//! each entry a read-only copy of the committed original the execution leases, which the
//! runner binds at `/yougori-model` instead of the owner's folder (GPU-W03 "Keep consumer
//! mounts read-only"). A copy, not a hard link: the host folder server that serves a bind to
//! the container refuses hard-linked files (`host_files.rs`, "Hard-linked or unavailable files
//! cannot be shared"), as the first run against a real environment showed, and the runner's
//! verifier refuses two manifest entries that are one file. The view costs the model's size
//! on the catalog's volume while the execution holds its leases; a release removes it, and
//! the environment's own volume, not the view, is the hot path (IM1). Views exist only while
//! their execution holds the leases: a release removes the view, and opening the catalog
//! removes every view whose execution holds no live lease (leases are never persisted, so
//! after a restart that is every view; the runner leases and copies again before the next
//! start, [`refresh_model_view`]).

mod model_files;

#[cfg(test)]
mod tests;

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::Duration;

use serde::Serialize;
use serde_json::{json, Value};

use crate::foundation::catalog::{ArtifactClass, Catalog, ObjectId, ReadRefusal, Scope};
use crate::foundation::catalog_service::{
    CatalogLocation, CatalogService, CatalogServiceConfig, LocationProblem, OfferedClass,
    OpenRefusal, TrustApplied,
};
use crate::foundation::ids::{Clock, ContentKey, ExecutionId, SystemClock, TenantId};
use crate::foundation::signing::{
    ClassVerification, StatementBinding, SystemCalendar, TrustCalendar, TrustRootService,
};
use crate::model_memory::helpers::HelperBundleStructure;
use crate::model_memory::manifest::{
    CancellationToken, ImportLimits, ReadBackChannel, RelativePath, SidecarVerifier,
};
use crate::sandbox_contract::artifact_policy::{awaiting_reopen, PolicyClasses};
use crate::sandbox_contract::oci::ImportLimits as OciImportLimits;

use model_files::HeldLease;
pub(crate) use model_files::{
    FolderIdentities, ImportedModel, ModelFileBytes, ModelFileImport, ModelFileRefusal, ModelFiles,
    PublisherClaim, TiledExtents, ORIGINAL_EXTENT_BYTES,
};

/// The environment variable naming the catalog directory.
pub(crate) const CATALOG_ROOT_SETTING: &str = "YOUGORI_CATALOG_ROOT";

/// The value of [`CATALOG_ROOT_SETTING`] that turns the catalog off, overriding the default.
pub(crate) const CATALOG_OFF: &str = "off";

/// The catalog's default root when [`CATALOG_ROOT_SETTING`] is unset: this folder under the
/// engine's data folder ([`use_data_folder`]), taken only when the data folder's volume has at
/// least [`DEFAULT_MIN_FREE_BYTES`] free, with [`DEFAULT_QUOTA_BYTES`] per scope as the budget
/// unless [`CATALOG_QUOTA_SETTING`] says otherwise (S02 "the configured root/budget policy").
pub(crate) const DEFAULT_ROOT_FOLDER: &str = "catalog";
pub(crate) const DEFAULT_MIN_FREE_BYTES: u64 = 64 << 30;
pub(crate) const DEFAULT_QUOTA_BYTES: u64 = 32 << 30;
/// The setting name the default root is reported under.
pub(crate) const DEFAULT_ROOT_SETTING: &str =
    "YOUGORI_CATALOG_ROOT (default: the engine's data folder)";

/// The environment variable giving each scope's space budget, in bytes.
pub(crate) const CATALOG_QUOTA_SETTING: &str = "YOUGORI_CATALOG_QUOTA_BYTES";

/// The environment variable naming a disposable acceptance engine's catalog directory (the
/// `acceptance` build feature). Such an engine never uses [`CATALOG_ROOT_SETTING`]: it inherits
/// the owner's environment, where that variable names the installed engine's catalog.
pub(crate) const ACCEPTANCE_ROOT_SETTING: &str = "YOUGORI_ACCEPTANCE_CATALOG_ROOT";

/// The setting name an acceptance engine's default root is reported under.
pub(crate) const ACCEPTANCE_DEFAULT_ROOT_SETTING: &str =
    "YOUGORI_ACCEPTANCE_CATALOG_ROOT (default: the acceptance data folder)";

/// The variable this build takes the catalog directory from, as its remedies name it.
pub(crate) const ROOT_SETTING: &str = if cfg!(feature = "acceptance") {
    ACCEPTANCE_ROOT_SETTING
} else {
    CATALOG_ROOT_SETTING
};

/// The tenant the engine's owner imports into: their own model folders.
pub(crate) const OWNER_TENANT: &str = "owner";

/// How long unreachable, unleased garbage stays: long enough for an interrupted import of
/// a large model to resume from its verified extents the next day.
pub(crate) const GC_GRACE: Duration = Duration::from_secs(24 * 60 * 60);

/// The space budget as configured.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum QuotaSetting {
    NotConfigured,
    /// Not a whole number of bytes: no budget is given.
    Invalid {
        value: String,
    },
    /// The budget of each scope the engine imports into.
    Bytes(u64),
}

impl QuotaSetting {
    /// The budget configured as `value` under [`CATALOG_QUOTA_SETTING`]; absent or empty
    /// is not configured.
    pub(crate) fn from_setting(value: Option<&OsStr>) -> Self {
        match value.filter(|value| !value.is_empty()) {
            None => Self::NotConfigured,
            Some(value) => {
                let text = value.to_string_lossy();
                text.trim().parse::<u64>().map_or_else(
                    |_| Self::Invalid {
                        value: text.into_owned(),
                    },
                    Self::Bytes,
                )
            }
        }
    }

    fn view(&self) -> Value {
        let scopes = budgeted_scopes()
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>();
        match self {
            Self::NotConfigured => json!({
                "setting": CATALOG_QUOTA_SETTING,
                "state": "not_configured",
                "remedy": format!(
                    "No space budget is configured, so every import is refused. Set \
                     {CATALOG_QUOTA_SETTING} to the bytes each of {} may store.",
                    scopes.join(" and ")
                ),
            }),
            Self::Invalid { value } => json!({
                "setting": CATALOG_QUOTA_SETTING,
                "state": "invalid",
                "value": value,
                "remedy": format!(
                    "{CATALOG_QUOTA_SETTING} must be a whole number of bytes; every import is \
                     refused until it is."
                ),
            }),
            Self::Bytes(bytes) => json!({
                "setting": CATALOG_QUOTA_SETTING,
                "state": "configured",
                "bytes": bytes,
                "scopes": scopes,
            }),
        }
    }
}

/// What the engine reads to open its catalog.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Settings {
    pub location: CatalogLocation,
    pub quota: QuotaSetting,
}

/// Why the default root was or was not taken, for the status.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DefaultPolicy {
    /// The owner set the root; the default did not apply.
    Configured,
    /// The owner turned the catalog off ([`CATALOG_OFF`]).
    Off,
    /// The default root under the data folder, with the free bytes seen.
    Taken { root: PathBuf, free_bytes: u64 },
    /// The data folder's volume has too little free space for the default.
    TooLittleFree { free_bytes: u64 },
    /// The engine's data folder was not handed over, or its volume could not be read.
    NoDataFolder,
    /// A disposable acceptance engine without a data folder of its own
    /// (YOUGORI_ACCEPTANCE_DATA_DIR is unset): it has no default root.
    NoAcceptanceDataFolder,
    /// A disposable acceptance engine's root would be the installed engine's catalog, which it
    /// never opens.
    InstalledEngineRoot { root: PathBuf },
}

impl DefaultPolicy {
    fn view(&self) -> Value {
        match self {
            Self::Configured => {
                json!({ "state": "configured", "detail": format!("{ROOT_SETTING} is set; the default root did not apply") })
            }
            Self::Off => {
                json!({ "state": "off", "detail": format!("{ROOT_SETTING} is {CATALOG_OFF}: no catalog, by the owner's choice") })
            }
            Self::Taken { root, free_bytes } => {
                json!({ "state": "default", "root": root.display().to_string(), "free_bytes": free_bytes,
                "detail": format!("{ROOT_SETTING} is unset; the catalog lives under the engine's data folder with {DEFAULT_QUOTA_BYTES} bytes per scope unless {CATALOG_QUOTA_SETTING} says otherwise; set {ROOT_SETTING} to a directory, or to {CATALOG_OFF}, to change that") })
            }
            Self::TooLittleFree { free_bytes } => {
                json!({ "state": "declined", "free_bytes": free_bytes, "needed_bytes": DEFAULT_MIN_FREE_BYTES,
                "detail": format!("{ROOT_SETTING} is unset and the data folder's volume has {free_bytes} bytes free, less than the {DEFAULT_MIN_FREE_BYTES} the default needs; set {ROOT_SETTING} to a directory on a drive with room") })
            }
            Self::NoDataFolder => {
                json!({ "state": "declined", "detail": "the engine's data folder or its volume could not be read; set the root explicitly" })
            }
            Self::NoAcceptanceDataFolder => {
                json!({ "state": "declined", "detail": format!("this disposable acceptance engine has no data folder of its own (YOUGORI_ACCEPTANCE_DATA_DIR is unset), so it has no default root and never takes the installed engine's; set {ACCEPTANCE_ROOT_SETTING} to a folder of its own") })
            }
            Self::InstalledEngineRoot { root } => {
                json!({ "state": "refused", "root": root.display().to_string(),
                "detail": format!("{} is the installed engine's catalog, which this disposable acceptance engine never opens; set {ACCEPTANCE_ROOT_SETTING} to a folder of its own", root.display()) })
            }
        }
    }
}

/// What a disposable acceptance engine knows of the installed engine on the same computer:
/// where that engine's catalog is, so that it is never opened from here.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct InstalledEngine {
    /// The installed engine's data folder. Its default root is [`DEFAULT_ROOT_FOLDER`] there,
    /// and nothing in it is a disposable engine's.
    pub data_folder: Option<PathBuf>,
    /// The value of [`CATALOG_ROOT_SETTING`] in this engine's environment, inherited from the
    /// owner's: the root the installed engine is configured with.
    pub configured_root: Option<OsString>,
}

impl InstalledEngine {
    /// Whether `path` is the installed engine's catalog: the root [`CATALOG_ROOT_SETTING`]
    /// names, or anything in its data folder, its default root included. Paths are compared
    /// by name (on Windows in any case, with either separator) and again with the links of
    /// their existing part resolved, so another spelling of the same folder is caught too.
    fn claims(&self, path: &Path) -> bool {
        let configured = self
            .configured_root
            .as_deref()
            .filter(|value| !value.is_empty() && !is_off(value))
            .map(Path::new)
            .filter(|root| root.is_absolute());
        let data = self.data_folder.as_deref();
        let claimed_in = |form: &dyn Fn(&Path) -> Option<PathBuf>| {
            let Some(candidate) = form(path) else {
                return false;
            };
            configured
                .and_then(form)
                .is_some_and(|root| root == candidate)
                || data
                    .and_then(form)
                    .is_some_and(|folder| candidate.starts_with(folder))
        };
        claimed_in(&|path: &Path| Some(comparable(path))) || claimed_in(&resolved)
    }
}

/// Whether `value` is [`CATALOG_OFF`].
fn is_off(value: &OsStr) -> bool {
    value
        .to_string_lossy()
        .trim()
        .eq_ignore_ascii_case(CATALOG_OFF)
}

/// `path` with `.` and `..` resolved by name; on Windows also without a verbatim prefix, with
/// one separator and in one case, as the file system compares names there.
fn comparable(path: &Path) -> PathBuf {
    #[cfg(windows)]
    let path = &{
        let text = path.as_os_str().to_string_lossy().replace('/', "\\");
        let text = match text.strip_prefix(r"\\?\UNC\") {
            Some(share) => format!(r"\\{share}"),
            None => text.strip_prefix(r"\\?\").unwrap_or(&text).to_owned(),
        };
        PathBuf::from(text.to_lowercase())
    };
    let mut normal = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normal.pop();
            }
            other => normal.push(other.as_os_str()),
        }
    }
    normal
}

/// `path` as [`comparable`], with its longest existing part resolved by the system (links,
/// junctions, short names); `None` when no part of it exists. Reads path metadata only.
fn resolved(path: &Path) -> Option<PathBuf> {
    let named = comparable(path);
    let mut existing = named.as_path();
    let mut rest = Vec::new();
    loop {
        if let Ok(canonical) = fs::canonicalize(existing) {
            let mut full = canonical;
            full.extend(rest.iter().rev());
            return Some(comparable(&full));
        }
        rest.push(existing.file_name()?);
        existing = existing.parent()?;
    }
}

impl Settings {
    /// The settings from the values of [`CATALOG_ROOT_SETTING`] and
    /// [`CATALOG_QUOTA_SETTING`]. Nothing is read here.
    pub(crate) fn from_values(root: Option<&OsStr>, quota: Option<&OsStr>) -> Self {
        Self {
            location: CatalogLocation::from_setting(CATALOG_ROOT_SETTING, root),
            quota: QuotaSetting::from_setting(quota),
        }
    }

    /// The engine's settings with the default policy applied: an explicit root (or
    /// [`CATALOG_OFF`]) is the owner's word; an unset root takes the default under
    /// `data_folder` when `free_bytes` (the volume's free space) is at least
    /// [`DEFAULT_MIN_FREE_BYTES`], and the budget defaults to [`DEFAULT_QUOTA_BYTES`] per
    /// scope when the quota is unset. Nothing is read here.
    pub(crate) fn with_defaults(
        root: Option<&OsStr>,
        quota: Option<&OsStr>,
        data_folder: Option<&Path>,
        free_bytes: Option<u64>,
    ) -> (Self, DefaultPolicy) {
        let explicit = root.filter(|value| !value.is_empty());
        if explicit.is_some_and(is_off) {
            return (
                Self {
                    location: CatalogLocation::from_setting(CATALOG_ROOT_SETTING, None),
                    quota: QuotaSetting::from_setting(quota),
                },
                DefaultPolicy::Off,
            );
        }
        if explicit.is_some() {
            return (Self::from_values(root, quota), DefaultPolicy::Configured);
        }
        Self::default_root(
            (CATALOG_ROOT_SETTING, DEFAULT_ROOT_SETTING),
            quota,
            data_folder,
            free_bytes,
        )
    }

    /// A disposable acceptance engine's settings (the `acceptance` build feature). It never
    /// uses [`CATALOG_ROOT_SETTING`], which it inherits from the owner's environment: `root`,
    /// the value of [`ACCEPTANCE_ROOT_SETTING`], is its directory when given ([`CATALOG_OFF`]
    /// turns the catalog off), and otherwise [`DEFAULT_ROOT_FOLDER`] in `data_folder`, its own
    /// data folder (YOUGORI_ACCEPTANCE_DATA_DIR), under the installed engine's default policy:
    /// room on its volume, and [`DEFAULT_QUOTA_BYTES`] per scope unless `quota` says otherwise.
    ///
    /// It fails closed, like the feature's other variables: a relative path, no data folder
    /// of its own, or a root of the `installed` engine's ([`InstalledEngine::claims`]) leaves
    /// the catalog unopened with the reason in the status, and nothing falls back to another
    /// root. Only path metadata is read, to see through links.
    pub(crate) fn for_acceptance(
        root: Option<&OsStr>,
        quota: Option<&OsStr>,
        data_folder: Option<&Path>,
        free_bytes: Option<u64>,
        installed: &InstalledEngine,
    ) -> (Self, DefaultPolicy) {
        let unset = |policy| {
            (
                Self {
                    location: CatalogLocation::from_setting(ACCEPTANCE_ROOT_SETTING, None),
                    quota: QuotaSetting::from_setting(quota),
                },
                policy,
            )
        };
        let (settings, policy) = match root.filter(|value| !value.is_empty()) {
            Some(value) if is_off(value) => return unset(DefaultPolicy::Off),
            Some(value) => (
                Self {
                    location: CatalogLocation::from_setting(ACCEPTANCE_ROOT_SETTING, Some(value)),
                    quota: QuotaSetting::from_setting(quota),
                },
                DefaultPolicy::Configured,
            ),
            None if data_folder.is_none() => return unset(DefaultPolicy::NoAcceptanceDataFolder),
            None => Self::default_root(
                (ACCEPTANCE_ROOT_SETTING, ACCEPTANCE_DEFAULT_ROOT_SETTING),
                quota,
                data_folder,
                free_bytes,
            ),
        };
        match settings.location {
            CatalogLocation::Directory { path, .. } if installed.claims(&path) => (
                Self {
                    location: CatalogLocation::Invalid {
                        setting: ACCEPTANCE_ROOT_SETTING,
                        problem: LocationProblem::InstalledEngine { root: path.clone() },
                    },
                    quota: settings.quota,
                },
                DefaultPolicy::InstalledEngineRoot { root: path },
            ),
            location => (
                Self {
                    location,
                    quota: settings.quota,
                },
                policy,
            ),
        }
    }

    /// [`DEFAULT_ROOT_FOLDER`] in `data_folder` when `free_bytes` (its volume's free space) is
    /// at least [`DEFAULT_MIN_FREE_BYTES`], reported under the second of `settings`, with
    /// [`DEFAULT_QUOTA_BYTES`] per scope unless `quota` says otherwise; declined, it is not
    /// configured under the first.
    fn default_root(
        (setting, default_setting): (&'static str, &'static str),
        quota: Option<&OsStr>,
        data_folder: Option<&Path>,
        free_bytes: Option<u64>,
    ) -> (Self, DefaultPolicy) {
        let declined = |policy| {
            (
                Self {
                    location: CatalogLocation::from_setting(setting, None),
                    quota: QuotaSetting::from_setting(quota),
                },
                policy,
            )
        };
        let (Some(data_folder), Some(free_bytes)) = (data_folder, free_bytes) else {
            return declined(DefaultPolicy::NoDataFolder);
        };
        if free_bytes < DEFAULT_MIN_FREE_BYTES {
            return declined(DefaultPolicy::TooLittleFree { free_bytes });
        }
        let path = data_folder.join(DEFAULT_ROOT_FOLDER);
        let quota = match QuotaSetting::from_setting(quota) {
            QuotaSetting::NotConfigured => QuotaSetting::Bytes(DEFAULT_QUOTA_BYTES),
            configured => configured,
        };
        (
            Self {
                location: CatalogLocation::from_setting(default_setting, Some(path.as_os_str())),
                quota,
            },
            DefaultPolicy::Taken {
                root: path,
                free_bytes,
            },
        )
    }
}

/// The engine's data folder, handed over at start-up ([`use_data_folder`]): where the default
/// catalog root lives.
static DATA_FOLDER: OnceLock<PathBuf> = OnceLock::new();

/// The installed engine's data folder, handed over at start-up ([`use_data_folder`]): where a
/// disposable acceptance engine's catalog never is.
static INSTALLED_DATA_FOLDER: OnceLock<PathBuf> = OnceLock::new();

/// The default policy the engine's catalog was opened with, for the status.
static POLICY: OnceLock<DefaultPolicy> = OnceLock::new();

/// Hands the catalog, before it opens, the engine's data folder, where its default root lives,
/// and the installed engine's data folder: the same one, except in a disposable acceptance
/// engine, which never opens a catalog there. Only the first call counts.
pub(crate) fn use_data_folder(app_directory: &Path, installed_directory: Option<&Path>) {
    let _ = DATA_FOLDER.set(app_directory.to_path_buf());
    if let Some(installed) = installed_directory {
        let _ = INSTALLED_DATA_FOLDER.set(installed.to_path_buf());
    }
}

/// The free bytes of the volume holding `path`: the longest mount point that is a prefix of
/// it, as the host reports it; `None` when no volume matches.
pub(crate) fn free_bytes_of(path: &Path) -> Option<u64> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    crate::runtime::storage::runtime_disk(&disks, path).map(|disk| disk.available_space())
}

/// The owner's tenant scope.
pub(crate) fn owner_scope() -> Option<Scope> {
    TenantId::new(OWNER_TENANT).ok().map(Scope::tenant)
}

/// The scopes the budget applies to: the host's (signed artifacts such as helper
/// bundles) and the owner's.
fn budgeted_scopes() -> Vec<Scope> {
    std::iter::once(Scope::Host).chain(owner_scope()).collect()
}

/// The catalog configuration the engine opens with: the budget for each scope it imports
/// into, and the classes that accept the owner's own originals.
pub(crate) fn engine_config(quota: &QuotaSetting) -> CatalogServiceConfig {
    let config = CatalogServiceConfig::new(GC_GRACE)
        .accept_user_selected(ArtifactClass::ModelWeights)
        .accept_user_selected(ArtifactClass::OciLayer)
        .accept_user_selected(ArtifactClass::ModelSidecar);
    match quota {
        QuotaSetting::Bytes(bytes) => budgeted_scopes()
            .into_iter()
            .fold(config, |config, scope| config.with_quota(scope, *bytes)),
        QuotaSetting::NotConfigured | QuotaSetting::Invalid { .. } => config,
    }
}

/// The classes the engine has structure checks for: model files, their sidecars (whose
/// verifier hands its read-back to the adapter through `read_back`) and helper bundles.
pub(crate) fn engine_classes(
    read_back: &ReadBackChannel,
    limits: &ImportLimits,
) -> Vec<OfferedClass> {
    vec![
        OfferedClass::Signed(ClassVerification {
            class: ArtifactClass::ModelWeights,
            binding: StatementBinding::Content,
            structure: Box::new(ModelFileBytes),
        }),
        OfferedClass::Local(Box::new(SidecarVerifier::new(
            read_back.clone(),
            limits.max_sidecar_bytes,
        ))),
        OfferedClass::Signed(ClassVerification {
            class: ArtifactClass::ModelHelper,
            binding: StatementBinding::Content,
            structure: Box::new(HelperBundleStructure),
        }),
    ]
}

/// The engine's model-file importer over its catalog, keyed by the folder's listing (see
/// [`FolderIdentities`]).
pub(crate) type EngineModels = ModelFiles<FolderIdentities, TiledExtents>;

/// The engine's catalog, opened or not.
pub(crate) enum EngineCatalog {
    /// No usable location is configured.
    NotOpened {
        location: CatalogLocation,
        quota: QuotaSetting,
    },
    /// A location is configured, but the catalog could not be opened there.
    Refused {
        root: PathBuf,
        refusal: OpenRefusal,
        quota: QuotaSetting,
    },
    Open {
        service: Box<CatalogService>,
        models: Arc<EngineModels>,
        /// The OCI layer, guest image and runtime update classes and their import entries
        /// (M18F); `None` when no trust-root file was in force at open.
        policy: Option<PolicyClasses>,
        quota: QuotaSetting,
    },
}

/// Opens the engine's catalog as `settings` say, registering its classes through
/// `trust`.
pub(crate) fn open(
    settings: &Settings,
    trust: &mut TrustRootService,
    clock: Arc<dyn Clock>,
    calendar: Arc<dyn TrustCalendar>,
) -> EngineCatalog {
    let quota = settings.quota.clone();
    let CatalogLocation::Directory { path, .. } = &settings.location else {
        return EngineCatalog::NotOpened {
            location: settings.location.clone(),
            quota,
        };
    };
    let limits = ImportLimits::DEFAULT;
    let read_back = ReadBackChannel::new();
    let policy = PolicyClasses::new(trust, Arc::clone(&calendar), OciImportLimits::default()).ok();
    let mut offered = engine_classes(&read_back, &limits);
    offered.extend(policy.iter().flat_map(PolicyClasses::offered));
    if policy.is_none() {
        if let Ok(importer) =
            crate::sandbox_contract::oci::OciImporter::local_owner(OciImportLimits::default())
        {
            offered.push(OfferedClass::Local(Box::new(importer.boundary_verifier())));
        }
    }
    let opened = CatalogService::open(
        path,
        engine_config(&quota),
        offered,
        trust,
        clock,
        calendar,
        |catalog| ModelFiles::new(catalog, read_back, FolderIdentities, TiledExtents, limits),
    );
    match opened {
        Ok((service, models)) => EngineCatalog::Open {
            service: Box::new(service),
            models,
            policy,
            quota,
        },
        Err(refusal) => EngineCatalog::Refused {
            root: path.clone(),
            refusal,
            quota,
        },
    }
}

static CATALOG: OnceLock<EngineCatalog> = OnceLock::new();

/// The catalog published in `cell`, opening it with `open` on first use. A published
/// catalog is returned without taking any lock. Otherwise the trust-root service in
/// `trust` is locked first and held until the opened catalog is published, so a reload,
/// which holds the service while it looks for the catalog ([`reload_reaches`]), runs
/// either before the open, whose catalog then reads the new roots, or after the
/// publication, which it reaches (module documentation; review finding R4). `open` runs
/// at most once per cell, with the locked service, and must not lock it again.
pub(crate) fn publish<'a>(
    cell: &'a OnceLock<EngineCatalog>,
    trust: &Mutex<TrustRootService>,
    open: impl FnOnce(&mut TrustRootService) -> EngineCatalog,
) -> &'a EngineCatalog {
    if let Some(catalog) = cell.get() {
        return catalog;
    }
    let mut service = trust.lock().unwrap_or_else(PoisonError::into_inner);
    let catalog = cell.get_or_init(|| open(&mut service));
    drop(service);
    catalog
}

/// Sets the class policies of the catalog published in `cell`, if any is open, from the
/// trust roots in force in `trust`, which just reloaded. The caller holds the trust-root
/// service's lock, which [`publish`] also holds from open to publication, so a catalog
/// this finds unpublished has not opened yet and reads the new roots when it opens.
/// `None` when no catalog is open.
pub(crate) fn reload_reaches(
    cell: &OnceLock<EngineCatalog>,
    trust: &TrustRootService,
) -> Option<TrustApplied> {
    match cell.get() {
        Some(EngineCatalog::Open {
            service, policy, ..
        }) => {
            let mut applied = service.apply_trust_roots(trust);
            applied.needs_reopen.extend(awaiting_reopen(service, trust));
            // The no-roots OCI verifier deliberately rejects every publisher. A
            // reload cannot silently turn that immutable port into a signing port.
            if policy.is_none()
                && trust.shared().is_some()
                && !applied.needs_reopen.contains(&ArtifactClass::OciLayer)
            {
                applied.needs_reopen.push(ArtifactClass::OciLayer);
            }
            Some(applied)
        }
        _ => None,
    }
}

/// The models the engine's executions hold (see [`ViewRegistry`]).
static ENGINE_VIEWS: ViewRegistry = ViewRegistry::new();

/// A registry nothing holds a model in, for callers that show a catalog without views.
static NO_VIEWS: ViewRegistry = ViewRegistry::new();

/// The value of the engine's environment variable `name`. A test binary reads none of the
/// catalog's: it inherits the owner's environment, YOUGORI_CATALOG_ROOT included, and a test
/// never opens the owner's catalog.
fn engine_variable(name: &str) -> Option<OsString> {
    if cfg!(test) {
        None
    } else {
        std::env::var_os(name)
    }
}

/// The engine's catalog settings from its variables, read through `variable`, and the data
/// folders handed over ([`use_data_folder`]): a disposable acceptance engine's in an acceptance
/// build ([`Settings::for_acceptance`]), the installed engine's otherwise
/// ([`Settings::with_defaults`], under `data_folder`). `free_bytes` is the data folder's volume's
/// free space.
///
/// A disposable engine's own data folder is the one handed over (YOUGORI_ACCEPTANCE_DATA_DIR)
/// unless that is the installed engine's, as it is when that variable is unset.
fn engine_settings(
    variable: impl Fn(&str) -> Option<OsString>,
    data_folder: Option<&Path>,
    free_bytes: Option<u64>,
) -> (Settings, DefaultPolicy) {
    let quota = variable(CATALOG_QUOTA_SETTING);
    if cfg!(feature = "acceptance") {
        let installed = InstalledEngine {
            data_folder: INSTALLED_DATA_FOLDER.get().cloned(),
            configured_root: variable(CATALOG_ROOT_SETTING),
        };
        let own_data_folder =
            data_folder.filter(|folder| installed.data_folder.as_deref() != Some(*folder));
        Settings::for_acceptance(
            variable(ACCEPTANCE_ROOT_SETTING).as_deref(),
            quota.as_deref(),
            own_data_folder,
            free_bytes,
            &installed,
        )
    } else {
        Settings::with_defaults(
            variable(CATALOG_ROOT_SETTING).as_deref(),
            quota.as_deref(),
            data_folder,
            free_bytes,
        )
    }
}

/// The engine's one catalog, opened on first use with the trust-root service's roots and
/// published under that service's lock ([`publish`]); on open, every view whose execution
/// holds no live lease is removed ([`open_with_views`]). Its root is where the engine's
/// variables put it ([`engine_settings`]); another engine that holds that root leaves this
/// one without a catalog, refused with [`OpenRefusal::InUse`].
pub(crate) fn engine() -> &'static EngineCatalog {
    publish(&CATALOG, crate::trust_roots::service_lock(), |trust| {
        let data_folder = DATA_FOLDER.get().map(PathBuf::as_path);
        let free = data_folder.and_then(free_bytes_of);
        let (settings, policy) = engine_settings(engine_variable, data_folder, free);
        let _ = POLICY.set(policy);
        // No sweep here: the engine restores the views of its running environments first
        // (`restore_views`, from the scheduler's start) and sweeps the rest then.
        let catalog = open(
            &settings,
            trust,
            Arc::new(SystemClock::new()),
            Arc::new(SystemCalendar),
        );
        allow_views(&catalog);
        catalog
    })
}

/// The bytes of the owner's published original with `content` in the engine's catalog, at
/// most `limit` of them (a larger object is refused before it is read), read under a short
/// lease of a fresh execution (a model's `config.json` for its execution identity,
/// `model_prepare`).
pub(crate) fn read_owner_original(content: ContentKey, limit: usize) -> Result<Vec<u8>, String> {
    let EngineCatalog::Open { service, .. } = engine() else {
        return Err(not_open_detail(engine()));
    };
    let scope = owner_scope().ok_or("the owner's catalog scope is unavailable")?;
    let mut catalog = service.catalog();
    let object = catalog
        .find(&scope, ArtifactClass::ModelWeights, content)
        .ok_or("the catalog holds no published copy of that file")?;
    let execution = ExecutionId::generate();
    let lease = catalog
        .acquire_lease(&scope, &execution, object, Duration::from_secs(60))
        .map_err(|refusal| format!("{refusal:?}"))?;
    let bytes = catalog
        .open_read(&scope, &execution, lease)
        .map_err(|refusal| format!("{refusal:?}"))
        .and_then(|mut handle| {
            if handle.length_bytes() > limit as u64 {
                return Err(format!(
                    "the file holds {} bytes, more than {limit}",
                    handle.length_bytes()
                ));
            }
            handle.read_all().map_err(|error| format!("{error:?}"))
        });
    let _ = catalog.release_lease(&scope, &execution, lease);
    bytes
}

/// The default policy the engine's catalog opened with, for the status; `None` before the
/// catalog was published.
pub(crate) fn engine_policy() -> Option<&'static DefaultPolicy> {
    POLICY.get()
}

/// The registry of the models the engine's executions hold.
pub(crate) fn engine_views() -> &'static ViewRegistry {
    &ENGINE_VIEWS
}

/// [`open`], then the sweep of stale views the engine runs on open ([`sweep_stale_views`]);
/// what the sweep did or could not do is shown by the status.
/// Registers the open catalog's views directory as an engine guest folder, so a model's view is
/// bindable wherever the catalog root lies (under the data folder by default).
fn allow_views(catalog: &EngineCatalog) {
    if let EngineCatalog::Open { service, .. } = catalog {
        crate::host_files::allow_engine_guest_folder(&views_dir(service));
    }
}

pub(crate) fn open_with_views(
    settings: &Settings,
    trust: &mut TrustRootService,
    clock: Arc<dyn Clock>,
    calendar: Arc<dyn TrustCalendar>,
    views: &ViewRegistry,
) -> EngineCatalog {
    let catalog = open(settings, trust, clock, calendar);
    if let EngineCatalog::Open { .. } = &catalog {
        // A refusal here is a listing failure of the views directory; it is recorded in the
        // registry's last sweep for the status, and the catalog stays usable.
        let _recorded = sweep_stale_views(&catalog, views);
    }
    catalog
}

fn encoded(value: impl serde::Serialize) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| error.to_string())
}

/// Why the catalog is not open, for refusals; for a root another engine holds, also what to
/// do about it.
pub(crate) fn not_open_detail(catalog: &EngineCatalog) -> String {
    match catalog {
        EngineCatalog::NotOpened { location, .. } => location.remedy().unwrap_or_default(),
        EngineCatalog::Refused {
            root,
            refusal: refusal @ OpenRefusal::InUse { .. },
            ..
        } => refused_remedy(root, refusal),
        EngineCatalog::Refused { refusal, .. } => refusal.to_string(),
        EngineCatalog::Open { .. } => String::new(),
    }
}

/// What the owner does about the catalog `refusal` kept this engine from opening at `root`.
fn refused_remedy(root: &Path, refusal: &OpenRefusal) -> String {
    match refusal {
        OpenRefusal::InUse { .. } => format!(
            "The catalog at {} is in use by another Yougori engine, so this engine left it \
             untouched and runs without a catalog. Quit the engine that uses it, or set \
             {ROOT_SETTING} to a folder of this engine's own, then restart this engine.",
            root.display()
        ),
        _ => format!(
            "The catalog could not be opened at {}: {refusal}. Make the directory writable, or \
             set {ROOT_SETTING} to another one, and restart the engine.",
            root.display()
        ),
    }
}

/// The setting `location` was configured under.
fn location_setting(location: &CatalogLocation) -> &'static str {
    match location {
        CatalogLocation::NotConfigured { setting }
        | CatalogLocation::Invalid { setting, .. }
        | CatalogLocation::Directory { setting, .. } => setting,
    }
}

/// The status of `catalog` with the model views held in `views`, reading nothing from
/// disk.
pub(crate) fn status_with_views(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
) -> Result<Value, String> {
    let mut value = status(catalog)?;
    if let EngineCatalog::Open { .. } = catalog {
        value["views"] = views_status(views);
    }
    if let Some(policy) = engine_policy() {
        value["policy"] = policy.view();
    }
    Ok(value)
}

/// The status of `catalog`, reading nothing from disk.
pub(crate) fn status(catalog: &EngineCatalog) -> Result<Value, String> {
    match catalog {
        EngineCatalog::NotOpened { location, quota } => Ok(json!({
            "state": "not_opened",
            "setting": location_setting(location),
            "remedy": location.remedy(),
            "quota": quota.view(),
        })),
        EngineCatalog::Refused {
            root,
            refusal,
            quota,
        } => Ok(json!({
            "state": "refused",
            "root": root.display().to_string(),
            "refusal": encoded(refusal)?,
            "remedy": refused_remedy(root, refusal),
            "quota": quota.view(),
        })),
        EngineCatalog::Open { service, quota, .. } => {
            let mut value = encoded(service.status())?;
            value["state"] = json!("open");
            value["quota"] = quota.view();
            Ok(value)
        }
    }
}

/// The `catalog_status` method on `catalog` with the views held in `views`: `status` (the
/// default) or `gc`.
pub(crate) fn respond_with_views(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    action: Option<&str>,
) -> Result<Value, String> {
    match action.unwrap_or("status") {
        "status" => status_with_views(catalog, views),
        "gc" => {
            let gc = match catalog {
                EngineCatalog::Open { service, .. } => encoded(service.collect_garbage())?,
                other => json!({ "outcome": "not_opened", "detail": not_open_detail(other) }),
            };
            Ok(json!({ "gc": gc, "status": status_with_views(catalog, views)? }))
        }
        other => Err(format!(
            "Unknown catalog action '{other}'. Use status or gc."
        )),
    }
}

/// The `catalog_status` method on `catalog` without model views: `status` (the default)
/// or `gc`.
pub(crate) fn respond(catalog: &EngineCatalog, action: Option<&str>) -> Result<Value, String> {
    respond_with_views(catalog, &NO_VIEWS, action)
}

/// The `catalog_status` automation method: `status` (the default) or `gc`.
pub(crate) fn dispatch(action: Option<String>) -> Result<Value, String> {
    respond_with_views(engine(), engine_views(), action.as_deref())
}

/// Sets the engine catalog's class policies from the trust roots in force in `trust`,
/// which just reloaded ([`reload_reaches`] on the engine's cell). `trust_roots` calls
/// this while it holds the trust-root service, so it never opens the catalog (opening
/// waits for that service, and publication completes under it): a catalog not opened yet
/// reads the new roots when it opens. `None` when no catalog is open.
pub(crate) fn on_trust_roots_reloaded(trust: &TrustRootService) -> Option<TrustApplied> {
    reload_reaches(&CATALOG, trust)
}

/// The model runner's entry for a model folder the owner chose: verifies every listed
/// file, publishes each as the owner's original, indexes the sidecar from the published
/// copies and leases them all for `request`'s execution (see `model_files`). Opens the
/// catalog on first use.
pub(crate) fn import_model_files(
    request: &ModelFileImport<()>,
    cancel: &CancellationToken,
) -> Result<ImportedModel, ModelFileRefusal> {
    import_model(engine(), request, cancel)
}

/// [`import_model_files`] on `catalog`.
pub(crate) fn import_model(
    catalog: &EngineCatalog,
    request: &ModelFileImport<()>,
    cancel: &CancellationToken,
) -> Result<ImportedModel, ModelFileRefusal> {
    match catalog {
        EngineCatalog::Open { models, .. } => models.import(request, cancel),
        other => Err(ModelFileRefusal::NotOpened {
            detail: not_open_detail(other),
        }),
    }
}

/// Ends the leases [`import_model_files`] took.
pub(crate) fn release_model_files(imported: &ImportedModel) -> Result<(), ModelFileRefusal> {
    release_model(engine(), imported)
}

/// [`release_model_files`] on `catalog`.
pub(crate) fn release_model(
    catalog: &EngineCatalog,
    imported: &ImportedModel,
) -> Result<(), ModelFileRefusal> {
    match catalog {
        EngineCatalog::Open { models, .. } => models.release(imported),
        other => Err(ModelFileRefusal::NotOpened {
            detail: not_open_detail(other),
        }),
    }
}

// ---- Model views -----------------------------------------------------------------------

/// The directory under the catalog root holding the model views, one per execution.
pub(crate) const VIEWS_DIR: &str = "views";

/// A read-only view of a published model folder: `<root>/views/<execution>/<relative
/// path>`, each entry a read-only copy of the committed `data` file of the original the
/// execution leases (plan §3.3 "Consumers mount artifacts read-only"; GPU-W03 "Keep
/// consumer mounts read-only"). The runner binds `path` at `/yougori-model` instead of the
/// owner's folder. A link shares the committed file's bytes and read-only attribute and
/// costs no space; a second path with the same bytes gets its own read-only copy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct ModelView {
    pub execution: ExecutionId,
    /// The model's sidecar object: the catalog identity of the model the view serves.
    pub sidecar: ObjectId,
    /// The view directory, the folder the runner binds.
    pub path: PathBuf,
    pub files: u64,
    pub bytes: u64,
}

/// A model an execution holds in the catalog: its leases and its view.
#[derive(Debug)]
struct HeldModel {
    scope: Scope,
    /// Every listed file, in path order, with the published original it reads.
    originals: Vec<(RelativePath, ObjectId)>,
    leases: Vec<HeldLease>,
    view: ModelView,
}

/// What one sweep of the views directory did ([`sweep_stale_views`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct SweptViews {
    /// Views removed because their execution holds no live lease.
    pub removed: Vec<String>,
    /// Views kept: their execution holds a live lease.
    pub kept: u64,
    /// Entries that could not be removed, each with the error; tried again next time.
    pub failures: Vec<String>,
}

/// The models the engine's executions hold now, keyed by execution. Leases live only as
/// long as the catalog (they are never persisted), so this registry does too; after a
/// restart it is empty and the runner leases and links again before a start.
#[derive(Debug)]
pub(crate) struct ViewRegistry {
    held: Mutex<BTreeMap<ExecutionId, HeldModel>>,
    last_sweep: Mutex<Option<SweptViews>>,
    /// What the engine's start restored ([`restore_views`]), for the status.
    last_restore: Mutex<Option<RestoredViews>>,
}

/// What a restore at the engine's start did ([`restore_views`]): the running environments
/// whose views and leases were taken again (their copies kept, nothing re-copied that was
/// there), those that could not be, and the sweep of everything else.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub(crate) struct RestoredViews {
    pub restored: Vec<String>,
    pub failures: Vec<String>,
    pub swept: SweptViews,
}

impl ViewRegistry {
    /// An empty registry.
    pub(crate) const fn new() -> Self {
        Self {
            held: Mutex::new(BTreeMap::new()),
            last_sweep: Mutex::new(None),
            last_restore: Mutex::new(None),
        }
    }

    /// The view `execution` holds, if any.
    pub(crate) fn view(&self, execution: &ExecutionId) -> Option<ModelView> {
        lock(&self.held)
            .get(execution)
            .map(|model| model.view.clone())
    }
}

impl Default for ViewRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Why a model view was not made, refreshed or released.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ViewRefusal {
    /// The engine has no catalog open.
    NotOpened { detail: String },
    /// An object of the model could not be leased (not published in the owner's scope,
    /// quarantined, or its lease ended); nothing of the view was made.
    Lease {
        object: ObjectId,
        refusal: ReadRefusal,
    },
    /// A filesystem step of the view failed under the catalog root.
    Storage {
        operation: &'static str,
        path: String,
        detail: String,
    },
}

impl fmt::Display for ViewRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotOpened { detail } => write!(f, "the engine has no catalog open: {detail}"),
            Self::Lease { object, refusal } => write!(f, "no lease on {object}: {refusal}"),
            Self::Storage {
                operation,
                path,
                detail,
            } => write!(
                f,
                "the model view could not be {operation} at {path}: {detail}"
            ),
        }
    }
}

impl std::error::Error for ViewRefusal {}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn opened(catalog: &EngineCatalog) -> Result<(&CatalogService, &EngineModels), ViewRefusal> {
    match catalog {
        EngineCatalog::Open {
            service, models, ..
        } => Ok((service, models)),
        other => Err(ViewRefusal::NotOpened {
            detail: not_open_detail(other),
        }),
    }
}

fn storage(operation: &'static str, path: &Path, error: impl fmt::Display) -> ViewRefusal {
    ViewRefusal::Storage {
        operation,
        path: path.display().to_string(),
        detail: error.to_string(),
    }
}

/// The views directory of `service`'s catalog.
pub(crate) fn views_dir(service: &CatalogService) -> PathBuf {
    service.root().join(VIEWS_DIR)
}

fn view_dir(service: &CatalogService, execution: &ExecutionId) -> PathBuf {
    views_dir(service).join(execution.as_str())
}

/// Removes a view directory; a missing one is already removed.
fn remove_view_dir(path: &Path) -> Result<(), ViewRefusal> {
    match fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(storage("removed", path, error)),
    }
}

/// Makes `target` a read-only copy of `source`.
fn copy_read_only(source: &Path, target: &Path, cancel: &CancellationToken) -> Result<(), ViewRefusal> {
    use std::io::{Read, Write};
    let result = (|| -> io::Result<()> {
        let mut source = fs::File::open(source)?;
        let mut output = fs::OpenOptions::new().write(true).create_new(true).open(target)?;
        let mut buffer = vec![0; 1024 * 1024];
        loop {
            if cancel.is_cancelled() { return Err(io::Error::new(io::ErrorKind::Interrupted, "model preparation cancelled")); }
            let count = match source.read(&mut buffer) {
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            if count == 0 { break; }
            output.write_all(&buffer[..count])?;
        }
        Ok(())
    })();
    result.map_err(|error| storage("copied", target, error))?;
    let mut permissions = fs::metadata(target)
        .map_err(|error| storage("copied", target, error))?
        .permissions();
    permissions.set_readonly(true);
    fs::set_permissions(target, permissions).map_err(|error| storage("copied", target, error))
}

/// Copies every original of a held model into its view (entries already there stay), each
/// through the lease the execution holds on it, and counts the view. Copies, never hard
/// links: the host folder server refuses hard-linked files, and the runner's verifier refuses
/// two manifest entries that are one file (`model_runner/registry_snapshot.py`, the
/// device-and-inode check). The catalog is held locked by the caller, so no lease ends
/// between the check and the copy.
fn link_view(
    catalog: &Catalog,
    service: &CatalogService,
    scope: &Scope,
    execution: &ExecutionId,
    sidecar: ObjectId,
    originals: &[(RelativePath, ObjectId)],
    leases: &[HeldLease],
    cancel: &CancellationToken,
) -> Result<ModelView, ViewRefusal> {
    let root = view_dir(service, execution);
    if cancel.is_cancelled() { return Err(storage("copied", &root, "model preparation cancelled")); }
    fs::create_dir_all(&root).map_err(|error| storage("created", &root, error))?;
    let mut view = ModelView {
        execution: execution.clone(),
        sidecar,
        path: root.clone(),
        files: 0,
        bytes: 0,
    };
    for (path, object) in originals {
        let lease =
            leases
                .iter()
                .find(|held| held.object == *object)
                .ok_or(ViewRefusal::Lease {
                    object: *object,
                    refusal: ReadRefusal::UnknownLease,
                })?;
        let source = catalog
            .leased_path(scope, execution, lease.lease)
            .map_err(|refusal| ViewRefusal::Lease {
                object: *object,
                refusal,
            })?;
        let target = path
            .components()
            .fold(root.clone(), |target, part| target.join(part));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| storage("created", parent, error))?;
        }
        let present = match fs::symlink_metadata(&target) {
            Ok(metadata) if metadata.is_file() => Some(metadata.len()),
            Ok(_) => {
                remove_view_dir(&target)?;
                None
            }
            Err(_) => None,
        };
        let length_bytes = match present {
            Some(length_bytes) => length_bytes,
            None => {
                copy_read_only(&source, &target, cancel)?;
                fs::metadata(&target)
                    .map_err(|error| storage("copied", &target, error))?
                    .len()
            }
        };
        view.files = view.files.saturating_add(1);
        view.bytes = view.bytes.saturating_add(length_bytes);
    }
    Ok(view)
}

/// Ends every lease in `leases` for `execution`; one already ended changes nothing.
fn end_leases(catalog: &mut Catalog, scope: &Scope, execution: &ExecutionId, leases: &[HeldLease]) {
    for held in leases {
        let _already_ended = catalog.release_lease(scope, execution, held.lease);
    }
}

/// Holds `imported` for its execution: links its view from the leases the import took and
/// registers it in `views`. On a refusal the leases are released and the partial view
/// removed, so nothing is held. A model this execution already held is released first.
pub(crate) fn hold_model_view(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    imported: ImportedModel,
) -> Result<ModelView, ViewRefusal> {
    hold_model_view_cancellable(catalog, views, imported, &CancellationToken::new())
}

pub(crate) fn hold_model_view_cancellable(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    imported: ImportedModel,
    cancel: &CancellationToken,
) -> Result<ModelView, ViewRefusal> {
    let (service, _) = opened(catalog)?;
    let originals: Vec<(RelativePath, ObjectId)> = imported
        .originals
        .iter()
        .map(|original| (original.path.clone(), original.object))
        .collect();
    let mut held = lock(&views.held);
    let mut locked = service.catalog();
    if let Some(previous) = held.remove(&imported.execution) {
        end_leases(
            &mut locked,
            &previous.scope,
            &imported.execution,
            &previous.leases,
        );
    }
    let linked = link_view(
        &locked,
        service,
        &imported.scope,
        &imported.execution,
        imported.sidecar,
        &originals,
        &imported.leases,
        cancel,
    );
    match linked {
        Ok(view) => {
            held.insert(
                imported.execution.clone(),
                HeldModel {
                    scope: imported.scope,
                    originals,
                    leases: imported.leases,
                    view: view.clone(),
                },
            );
            Ok(view)
        }
        Err(refusal) => {
            end_leases(
                &mut locked,
                &imported.scope,
                &imported.execution,
                &imported.leases,
            );
            let _partial = remove_view_dir(&view_dir(service, &imported.execution));
            Err(refusal)
        }
    }
}

/// Makes sure `execution` holds `sidecar` and every original of `originals` under a lease
/// of `lease` and that its view is complete: held leases are renewed, ended or missing ones
/// taken again (after a restart, when nothing is held), and missing view entries linked.
/// On a refusal nothing is held for the execution.
pub(crate) fn refresh_model_view(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    scope: &Scope,
    execution: &ExecutionId,
    sidecar: ObjectId,
    originals: Vec<(RelativePath, ObjectId)>,
    lease: Duration,
) -> Result<ModelView, ViewRefusal> {
    let (service, _) = opened(catalog)?;
    let mut held = lock(&views.held);
    let mut locked = service.catalog();
    let mut leases = Vec::new();
    if let Some(previous) = held.remove(execution) {
        for held_lease in previous.leases {
            match locked.renew_lease(&previous.scope, execution, held_lease.lease, lease) {
                Ok(_) if previous.scope == *scope => leases.push(held_lease),
                // Ended, or held for another scope: replaced below.
                _ => {}
            }
        }
    }
    let missing: BTreeSet<ObjectId> = std::iter::once(sidecar)
        .chain(originals.iter().map(|(_, object)| *object))
        .filter(|object| !leases.iter().any(|held| held.object == *object))
        .collect();
    let outcome = missing
        .into_iter()
        .try_for_each(|object| {
            let id = locked
                .acquire_lease(scope, execution, object, lease)
                .map_err(|refusal| ViewRefusal::Lease { object, refusal })?;
            leases.push(HeldLease { object, lease: id });
            Ok(())
        })
        .and_then(|()| {
            link_view(
                &locked, service, scope, execution, sidecar, &originals, &leases, &CancellationToken::new(),
            )
        });
    match outcome {
        Ok(view) => {
            held.insert(
                execution.clone(),
                HeldModel {
                    scope: scope.clone(),
                    originals,
                    leases,
                    view: view.clone(),
                },
            );
            Ok(view)
        }
        Err(refusal) => {
            end_leases(&mut locked, scope, execution, &leases);
            Err(refusal)
        }
    }
}

/// Ends `execution`'s leases and removes its view, then removes every other view whose
/// execution holds no live lease ([`sweep_stale_views`]). An execution that holds nothing
/// only has its view directory removed, if one is left.
pub(crate) fn release_model_view(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    execution: &ExecutionId,
) -> Result<SweptViews, ViewRefusal> {
    let (service, _) = opened(catalog)?;
    {
        let mut held = lock(&views.held);
        if let Some(model) = held.remove(execution) {
            let mut locked = service.catalog();
            end_leases(&mut locked, &model.scope, execution, &model.leases);
        }
    }
    remove_view_dir(&view_dir(service, execution))?;
    sweep_stale_views(catalog, views)
}

/// Removes every entry of the views directory whose execution holds no live lease in
/// this catalog, and forgets such executions. On open that is every view, since leases
/// never survive a reopen. Nothing else under the root is touched: the catalog's own
/// recovery and collector never look at `views/`, and this never looks outside it.
pub(crate) fn sweep_stale_views(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
) -> Result<SweptViews, ViewRefusal> {
    let (service, _) = opened(catalog)?;
    let dir = views_dir(service);
    let mut swept = SweptViews::default();
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            *lock(&views.last_sweep) = Some(swept.clone());
            return Ok(swept);
        }
        Err(error) => return Err(storage("listed", &dir, error)),
    };
    let mut held = lock(&views.held);
    let locked = service.catalog();
    let mut forgotten = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| storage("listed", &dir, error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let execution = ExecutionId::new(name.as_str()).ok();
        let live = execution.as_ref().is_some_and(|execution| {
            held.get(execution).is_some_and(|model| {
                model.leases.iter().any(|held_lease| {
                    locked
                        .lease_expires_at(&model.scope, execution, held_lease.lease)
                        .is_ok()
                })
            })
        });
        if live {
            swept.kept = swept.kept.saturating_add(1);
            continue;
        }
        match fs::remove_dir_all(entry.path()) {
            Ok(()) => {
                swept.removed.push(name);
                forgotten.extend(execution);
            }
            Err(error) => swept.failures.push(format!("{name}: {error}")),
        }
    }
    drop(locked);
    for execution in forgotten {
        held.remove(&execution);
    }
    drop(held);
    *lock(&views.last_sweep) = Some(swept.clone());
    Ok(swept)
}

/// The views held in `views`, for the status: their count, and each with its execution,
/// model, path, files and bytes, beside the last sweep. Reads nothing from disk.
pub(crate) fn views_status(views: &ViewRegistry) -> Value {
    let held = lock(&views.held);
    let listed: Vec<Value> = held
        .values()
        .map(|model| {
            json!({
                "execution": model.view.execution,
                "model": model.view.sidecar.to_string(),
                "path": model.view.path.display().to_string(),
                "files": model.view.files,
                "bytes": model.view.bytes,
                "leases": model.leases.len(),
            })
        })
        .collect();
    json!({
        "count": listed.len(),
        "held": listed,
        "last_sweep": lock(&views.last_sweep).clone(),
        "last_restore": lock(&views.last_restore).clone(),
    })
}

/// A model an environment that is running holds through the catalog, as its workload options
/// name it: what [`restore_views`] leases and keeps across an engine restart.
#[derive(Clone, Debug)]
pub(crate) struct RunningModel {
    pub environment: String,
    pub execution: ExecutionId,
    pub sidecar: ObjectId,
    pub originals: Vec<(RelativePath, ObjectId)>,
}

/// At the engine's start, before any sweep: every running environment on the catalog path
/// leases its model again and its view is completed in place (entries already there stay, so a
/// view a running container has bound is never removed under it and nothing is copied twice);
/// then every other view is swept, as [`sweep_stale_views`] does (S02 "restart-safe views and
/// leases"). An environment whose lease cannot be taken is reported; its view goes with the
/// sweep, as before. Nothing without an open catalog.
pub(crate) fn restore_views(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    scope: &Scope,
    running: &[RunningModel],
    lease: Duration,
) -> Result<RestoredViews, ViewRefusal> {
    let mut outcome = RestoredViews::default();
    for model in running {
        match refresh_model_view(
            catalog,
            views,
            scope,
            &model.execution,
            model.sidecar,
            model.originals.clone(),
            lease,
        ) {
            Ok(_) => outcome.restored.push(model.environment.clone()),
            Err(refusal) => outcome
                .failures
                .push(format!("{}: {refusal}", model.environment)),
        }
    }
    outcome.swept = sweep_stale_views(catalog, views)?;
    *lock(&views.last_restore) = Some(outcome.clone());
    Ok(outcome)
}
