//! The catalog on the real local-folder and registry model paths (G04/S02 in
//! docs/combined-plan-remaining-only.md; GPU-W03 "Integrate CORE-02 publication,
//! interrupted-import recovery, quotas and lease-aware garbage collection" and "Keep
//! consumer mounts read-only"; plan §3.3–3.4 "Only the importer can write committed cache
//! content. Consumers mount artifacts read-only", "Never delete a user's original model
//! merely to meet a cache budget"; Appendix C, local folders).
//!
//! Pure functions, no Tauri types. Given a model folder, its files (name, size and the
//! SHA-256 a verified listing records), their catalog content keys (from
//! `local::inspect_verified`'s one read of every file, or read here once when a caller has
//! none) and the preflight check, [`bind`] decides and performs the catalog path:
//!
//! - **the listing** ([`listing`]): every file as a `ListedFile` with its length, content
//!   key and role (weights by extension, `config.json`, tokenizer files, other);
//! - **the import** through `catalog_service::import_model` under the owner scope, keyed
//!   by the listing and the artifact description ([`description`]), for a fresh
//!   per-environment execution with a bounded lease ([`MODEL_LEASE`]). The import verifies
//!   every file before publishing any, copies each original once (a file already published
//!   in the owner's scope is not copied again), indexes the sidecar from the copies and
//!   leases them all;
//! - **the view** (`catalog_service::hold_model_view`): `<catalog root>/views/<execution>/`
//!   holds a read-only copy of every published original (the host folder server refuses
//!   hard-linked files, `host_files.rs`), and that directory is what the
//!   runner binds at [`MODEL_TARGET`] instead of the owner's folder.
//!
//! The runner's own manifest ([`RUNNER_MANIFEST`]) is never extended: its verifier
//! (`model_runner/registry_snapshot.py`) accepts exactly `{"revision", "files"}` with files
//! of exactly `{"name", "size", "sha256"}`, so [`workload_variables`] passes it unchanged on
//! the local-folder path and the registry path passes none (the runner then verifies the
//! registry's record in the mount, which a registry view holds, [`bind_registry`]). The
//! catalog's environment keeps its execution in [`EXECUTION_OPTION`], its model's sidecar
//! object in [`MODEL_OPTION`] and every file's content key in [`CONTENT_OPTION`], so reusing
//! an environment compares catalog identity and revision rather than folder paths; before
//! each start, [`refresh`] renews the execution's leases (or takes them again after a
//! restart, from [`CONTENT_OPTION`], reading no folder) and completes the view, and
//! [`release`] ends them when the environment is deleted. Without a configured catalog the
//! folder itself is bound, as before, and the run result says so in
//! `catalog_service::status`'s words; a configured catalog that refuses ends the run with
//! the typed refusal, never with a silent fallback to the folder. A source-only folder (no
//! weights to index) stays on the folder path.
//!
//! The view is bound like any PC folder (`runtime/workload.rs::prepare_workload_binds`):
//! served read-only by `host_files::HostFolderServer` and mounted by the agent. That path
//! refuses folders inside Yougori's own data, storage pools and program directory
//! (`host_files::ensure_shareable_folder`), so the catalog root the owner configures must
//! lie outside them.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::de::{Deserialize, Deserializer, Error as _, MapAccess, Visitor};
use serde_json::{json, Value};
use sha2::{Digest as _, Sha256};
use yougori_cli::workload::Options;

use crate::catalog_service::{
    self, EngineCatalog, FolderIdentities, ModelFileImport, ModelFileRefusal, ModelView,
    PublisherClaim, ViewRefusal, ViewRegistry, CATALOG_ROOT_SETTING, ORIGINAL_EXTENT_BYTES,
};
use crate::foundation::catalog::{
    ArtifactClass, ImportManifest, ManifestBuilder, ObjectId, PublisherId, Scope, TrustClaim,
};
use crate::foundation::evidence::{Backend, BackendRelease};
use crate::foundation::ids::{ContentKey, ContentLengthError, Digest, ExecutionId, OperationId};
use crate::model_memory::manifest::{
    ArtifactDescription, CancellationToken, CatalogContext, Distribution, ElementType,
    ExecutionAbi, FileRole, HardwareRestriction, ImportRequest, ListedFile, ManifestBounds,
    Quantization, RelativePath, SourceListing, SourceOrigin, StateGroup, Token, VersionedName,
    WeightFormat,
};

/// The workload option naming the catalog execution that holds the environment's leases.
pub(super) const EXECUTION_OPTION: &str = "YOUGORI_CATALOG_EXECUTION";
/// The workload option naming the environment's model: its sidecar object in the catalog.
pub(super) const MODEL_OPTION: &str = "YOUGORI_CATALOG_MODEL";
/// The workload option carrying the content key of every file of the environment's catalog
/// model: a JSON object of relative path to 64 hexadecimal digits, written only on the
/// catalog path, from which [`refresh`] takes the leases again after a restart. The runner
/// never reads it.
pub(super) const CONTENT_OPTION: &str = "YOUGORI_CATALOG_CONTENT";
/// The runner's manifest of a local folder. `model_runner/registry_snapshot.py` prefers it
/// to the mount's record (line 22) and accepts exactly `{"revision", "files"}` (line 35)
/// with every file exactly `{"name", "size", "sha256"}` (line 45): the catalog never adds to
/// it.
pub(super) const RUNNER_MANIFEST: &str = "YOUGORI_LOCAL_MANIFEST";
/// The registry's verified-files record in its cached folder, which the runner verifies
/// the mount against when [`RUNNER_MANIFEST`] is absent (registry_snapshot.py, lines
/// 22–30). A registry view holds it beside the model's files.
pub(super) const REGISTRY_RECORD: &str = ".yougori-verified-files.json";
/// The most files a content option names: the most a model folder lists
/// (`model_registry::model_files`) and the runner's manifest holds.
pub(super) const MAX_CONTENT_FILES: usize = 512;
/// The longest content option: one workload variable's limit (`Options::validate`).
pub(super) const MAX_CONTENT_OPTION_BYTES: usize = 65536;
/// Where the container sees the model files.
pub(super) const MODEL_TARGET: &str = "/yougori-model";
/// How long an environment's leases last: the catalog's maximum, renewed before each start
/// ([`refresh`]). The copied view keeps serving after expiry; the lease only tells the
/// collector and the deletion paths that the model is in use.
pub(super) const MODEL_LEASE: Duration = Duration::from_secs(24 * 60 * 60);
/// The sidecar's integrity extent (§2.4 g_h) over the folder's files.
pub(super) const INTEGRITY_EXTENT_BYTES: u64 = 32 << 20;
/// The operation every model run imports under.
const OPERATION: &str = "model-run";
/// The runner releases the preflight pins (`preflight.rs`, `vllm.rs`, `model_server.py`).
const TRANSFORMERS_RELEASE: &str = "5.18.0";
const LLAMA_CPP_RELEASE: &str = "b11425";
const VLLM_RELEASE: &str = "0.29.0";

/// The catalog content key of each file of a folder, by the file's relative name.
pub(super) type ContentKeys = BTreeMap<String, FileHashes>;

/// How many files [`content_keys_cancellable`] reads at once: enough to overlap one file's hashing
/// with another's read on a solid-state disk, few enough not to thrash a spinning one.
const MAX_CONCURRENT_READS: usize = 2;

/// Why a folder was not bound through the catalog. Nothing of the folder changes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum BindingError {
    /// A file could not be read, changed while it was read, or no longer matches the
    /// SHA-256 it was verified with.
    Read {
        path: String,
        detail: String,
    },
    /// The folder's files lack what a catalog listing needs (a name, size or content key).
    Listing {
        detail: String,
    },
    /// The preflight check names something the artifact description cannot carry.
    Description {
        detail: String,
    },
    /// The environment's catalog options are missing, malformed or out of bounds.
    Options {
        detail: String,
    },
    Import(ModelFileRefusal),
    View(ViewRefusal),
}

impl fmt::Display for BindingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read { path, detail } => write!(f, "reading {path}: {detail}"),
            Self::Listing { detail } => write!(
                f,
                "the model folder cannot be listed for the catalog: {detail}"
            ),
            Self::Description { detail } => {
                write!(f, "the model cannot be described for the catalog: {detail}")
            }
            Self::Options { detail } => {
                write!(f, "the environment's catalog options are invalid: {detail}")
            }
            Self::Import(refusal) => write!(f, "the model catalog refused this folder: {refusal}"),
            Self::View(refusal) => refusal.fmt(f),
        }
    }
}

impl std::error::Error for BindingError {}

fn listing_error(detail: impl fmt::Display) -> BindingError {
    BindingError::Listing {
        detail: detail.to_string(),
    }
}

fn description_error(detail: impl fmt::Display) -> BindingError {
    BindingError::Description {
        detail: detail.to_string(),
    }
}

fn options_error(detail: impl fmt::Display) -> BindingError {
    BindingError::Options {
        detail: detail.to_string(),
    }
}

/// What one read of a model file yields: the SHA-256 the runner's manifest records, the
/// catalog's content key and the catalog declaration of the file's extents, which the import
/// takes in place of its own verifying read ([`ModelFileImport::declared`]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct FileHashes {
    pub sha256: String,
    pub content: ContentKey,
    pub manifest: ImportManifest,
}

/// Reads `path` once, front to back, hashing it for both the runner's manifest and the
/// catalog. `length_bytes` is the listed length; a file that is longer or shorter changed
/// since it was listed and is refused.
pub(super) fn hash_file_cancellable(path: &Path, length_bytes: u64, cancel: &CancellationToken) -> Result<FileHashes, BindingError> {
    let read = |error: io::Error| BindingError::Read {
        path: path.display().to_string(),
        detail: error.to_string(),
    };
    let changed = |error: ContentLengthError| BindingError::Read {
        path: path.display().to_string(),
        detail: format!(
            "the file changed while it was read: {} bytes were listed, {} were read",
            error.declared, error.seen
        ),
    };
    let mut file = File::open(path).map_err(read)?;
    let mut sha256 = Sha256::new();
    let mut content = ManifestBuilder::new(length_bytes, ORIGINAL_EXTENT_BYTES);
    let mut buffer = vec![0u8; 4 << 20];
    loop {
        if cancel.is_cancelled() { return Err(BindingError::Import(ModelFileRefusal::Cancelled { path: None })); }
        let read_bytes = match file.read(&mut buffer) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => result.map_err(read)?,
        };
        if read_bytes == 0 {
            break;
        }
        let chunk = buffer
            .get(..read_bytes)
            .ok_or_else(|| read(io::Error::other("a read returned more than the buffer")))?;
        sha256.update(chunk);
        content.update(chunk).map_err(changed)?;
    }
    let manifest = content.finish().map_err(changed)?;
    Ok(FileHashes {
        sha256: format!("{:x}", sha256.finalize()),
        content: manifest.content_key,
        manifest,
    })
}

/// One file entry's relative path and length.
fn listed_file(file: &Value) -> Result<(RelativePath, u64), BindingError> {
    let name = file["name"]
        .as_str()
        .ok_or_else(|| listing_error("a listed file has no name"))?;
    // The path rules of the listing refuse anything that could leave the folder.
    let path =
        RelativePath::new(name).map_err(|error| listing_error(format!("{name}: {error}")))?;
    let length_bytes = file["size"]
        .as_u64()
        .ok_or_else(|| listing_error(format!("{name} has no size")))?;
    Ok((path, length_bytes))
}

/// The content key and catalog declaration of every file of `files` (entries naming `name`
/// and `size`, and the `sha256` a verified listing records) under `folder`, each read once,
/// [`MAX_CONCURRENT_READS`] files at a time; the first refusal stops the rest. A file whose
/// length, or 64-digit SHA-256, is not the listed one changed since it was verified and is
/// refused.
fn content_keys_cancellable(folder: &Path, files: &[Value], cancel: &CancellationToken) -> Result<ContentKeys, BindingError> {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Mutex, PoisonError};
    let listed: Vec<(RelativePath, u64, Option<String>)> = files
        .iter()
        .map(|file| {
            listed_file(file).map(|(path, length_bytes)| {
                let verified = file["sha256"]
                    .as_str()
                    .filter(|digest| digest.len() == 64)
                    .map(str::to_owned);
                (path, length_bytes, verified)
            })
        })
        .collect::<Result<_, _>>()?;
    let results: Vec<Mutex<Option<Result<FileHashes, BindingError>>>> =
        listed.iter().map(|_| Mutex::new(None)).collect();
    let next = AtomicUsize::new(0);
    let stopped = AtomicBool::new(false);
    let workers = MAX_CONCURRENT_READS.min(listed.len());
    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some((path, length_bytes, verified)) = listed.get(index) else {
                    break;
                };
                if stopped.load(Ordering::Relaxed) {
                    break;
                }
                let full = path
                    .components()
                    .fold(folder.to_path_buf(), |full, part| full.join(part));
                let result = hash_file_cancellable(&full, *length_bytes, cancel).and_then(|hashed| {
                    if verified
                        .as_deref()
                        .is_some_and(|digest| !digest.eq_ignore_ascii_case(&hashed.sha256))
                    {
                        return Err(BindingError::Read {
                            path: full.display().to_string(),
                            detail: "the file no longer matches the SHA-256 it was verified with"
                                .to_owned(),
                        });
                    }
                    Ok(hashed)
                });
                if result.is_err() {
                    stopped.store(true, Ordering::Relaxed);
                }
                *results[index]
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner) = Some(result);
            });
        }
    });
    let mut keys = ContentKeys::new();
    for ((path, _, _), result) in listed.into_iter().zip(results) {
        let hashed = result
            .into_inner()
            .unwrap_or_else(PoisonError::into_inner)
            .ok_or_else(|| BindingError::Read {
                path: path.as_str().to_owned(),
                detail: "the file was not read because an earlier file was refused".to_owned(),
            })??;
        keys.insert(path.as_str().to_owned(), hashed);
    }
    Ok(keys)
}

/// The per-file publisher claims of `files`: an entry naming `publisher` (the publisher id)
/// and `attestation` (the hex signature over the file's content statement) is published
/// under that publisher's key, checked by the catalog's signed verifier for model files
/// under the trust roots in force; a file without them is the owner's own selection.
pub(super) fn claims_of(
    files: &[Value],
) -> Result<BTreeMap<RelativePath, PublisherClaim>, BindingError> {
    let mut claims = BTreeMap::new();
    for file in files {
        if file["publisher"].is_null() && file["attestation"].is_null() {
            continue;
        }
        let (path, _) = listed_file(file)?;
        let publisher: PublisherId =
            serde_json::from_value(file["publisher"].clone()).map_err(|error| {
                listing_error(format!("{path}: the publisher does not read: {error}"))
            })?;
        let hex = file["attestation"]
            .as_str()
            .ok_or_else(|| listing_error(format!("{path}: the attestation is not a hex string")))?;
        let attestation = super::helpers::decode_hex(hex)
            .map_err(|error| listing_error(format!("{path}: the attestation: {error}")))?;
        claims.insert(
            path,
            PublisherClaim {
                publisher,
                attestation,
            },
        );
    }
    Ok(claims)
}

/// What a listed file is for, from its name: weights by extension, the model
/// configuration, tokenizer files (`tokenizer*`, the vocabulary, merges and special-token
/// files, `.tiktoken` and SentencePiece `.model` files), and anything else as other. The
/// sidecar importer indexes weights headers and treats the rest as opaque bytes.
pub(super) fn role_of(name: &str) -> FileRole {
    let file = name.rsplit('/').next().unwrap_or(name).to_ascii_lowercase();
    if file.ends_with(".safetensors") {
        FileRole::Weights {
            format: WeightFormat::Safetensors,
            rank: None,
        }
    } else if file.ends_with(".gguf") {
        FileRole::Weights {
            format: WeightFormat::Gguf,
            rank: None,
        }
    } else if file == "config.json" {
        FileRole::Configuration
    } else if file.starts_with("tokenizer")
        || matches!(
            file.as_str(),
            "special_tokens_map.json" | "vocab.json" | "merges.txt" | "added_tokens.json"
        )
        || file.ends_with(".tiktoken")
        || file.ends_with(".model")
    {
        FileRole::Tokenizer
    } else {
        FileRole::Other
    }
}

/// The catalog listing of `files` (entries naming `name` and `size`) with their content
/// keys from `contents`: every file with its length, content key and role, under the
/// content revision of the listing.
pub(super) fn listing(
    files: &[Value],
    contents: &ContentKeys,
) -> Result<SourceListing, BindingError> {
    if files.is_empty() {
        return Err(listing_error("the folder lists no files"));
    }
    let mut listed = Vec::with_capacity(files.len());
    for file in files {
        let (path, length_bytes) = listed_file(file)?;
        let content = contents
            .get(path.as_str())
            .map(|hashed| hashed.content)
            .ok_or_else(|| {
                listing_error(format!(
                    "{path} has no content key; the folder was not verified"
                ))
            })?;
        let role = role_of(path.as_str());
        listed.push(ListedFile {
            path,
            length_bytes,
            content,
            role,
        });
    }
    Ok(SourceListing {
        origin: SourceOrigin::LocalFolder,
        revision: SourceListing::content_revision(&listed),
        files: listed,
    })
}

/// The [`CONTENT_OPTION`] of `listing`: every listed file's path and content key, within
/// [`MAX_CONTENT_FILES`] and [`MAX_CONTENT_OPTION_BYTES`].
pub(super) fn content_option(listing: &SourceListing) -> Result<String, BindingError> {
    if listing.files.len() > MAX_CONTENT_FILES {
        return Err(options_error(format!(
            "{CONTENT_OPTION} would name {} files; at most {MAX_CONTENT_FILES} are kept",
            listing.files.len()
        )));
    }
    let entries: BTreeMap<&str, String> = listing
        .files
        .iter()
        .map(|file| (file.path.as_str(), file.content.digest().to_hex()))
        .collect();
    let text = serde_json::to_string(&entries)
        .map_err(|error| options_error(format!("{CONTENT_OPTION}: {error}")))?;
    if text.len() > MAX_CONTENT_OPTION_BYTES {
        return Err(options_error(format!(
            "{CONTENT_OPTION} would be {} bytes; at most {MAX_CONTENT_OPTION_BYTES} are kept",
            text.len()
        )));
    }
    Ok(text)
}

/// A JSON object read strictly: a key given twice is refused rather than overwritten, and
/// no more than [`MAX_CONTENT_FILES`] entries are read.
struct UniqueEntries(Vec<(String, String)>);

struct UniqueEntriesVisitor;

impl<'de> Visitor<'de> for UniqueEntriesVisitor {
    type Value = UniqueEntries;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an object of relative paths and content keys")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<UniqueEntries, A::Error> {
        let mut seen = BTreeSet::new();
        let mut entries = Vec::new();
        while let Some((path, content)) = map.next_entry::<String, String>()? {
            if entries.len() >= MAX_CONTENT_FILES {
                return Err(A::Error::custom(format!(
                    "more than {MAX_CONTENT_FILES} files"
                )));
            }
            if !seen.insert(path.clone()) {
                return Err(A::Error::custom(format!("{path} is named twice")));
            }
            entries.push((path, content));
        }
        Ok(UniqueEntries(entries))
    }
}

impl<'de> Deserialize<'de> for UniqueEntries {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(UniqueEntriesVisitor)
    }
}

/// The files and content keys a [`CONTENT_OPTION`] names, checked: within its bounds, at
/// least one file, every path a relative path named once, every key 64 hexadecimal digits.
pub(super) fn parse_content_option(
    text: &str,
) -> Result<Vec<(RelativePath, ContentKey)>, BindingError> {
    if text.len() > MAX_CONTENT_OPTION_BYTES {
        return Err(options_error(format!(
            "{CONTENT_OPTION} is longer than {MAX_CONTENT_OPTION_BYTES} bytes"
        )));
    }
    let UniqueEntries(entries) = serde_json::from_str(text)
        .map_err(|error| options_error(format!("{CONTENT_OPTION}: {error}")))?;
    if entries.is_empty() {
        return Err(options_error(format!("{CONTENT_OPTION} names no files")));
    }
    entries
        .into_iter()
        .map(|(path, content)| {
            let path = RelativePath::new(path.as_str())
                .map_err(|error| options_error(format!("{CONTENT_OPTION} {path}: {error}")))?;
            let content = Digest::from_hex(&content)
                .map(ContentKey::from_digest)
                .map_err(|error| options_error(format!("{CONTENT_OPTION} {path}: {error}")))?;
            Ok((path, content))
        })
        .collect()
}

/// The artifact description of a folder's sidecar, from the preflight check: the runner
/// release the folder runs on (format `gguf` runs on llama.cpp, `vllm` on vLLM, anything
/// else on Transformers, each at the release the preflight pins), the architecture adapter
/// (the first declared architecture, else the model type) at that release, the compute
/// dtype (half precision for GGUF, bfloat16 otherwise), the exact quantization (a GGUF
/// quant label), one rank, the unprocessed layout, no kernels, no hardware restriction and
/// [`INTEGRITY_EXTENT_BYTES`] integrity extents.
pub(super) fn description(check: &Value) -> Result<ArtifactDescription, BindingError> {
    let token = |text: &str, field: &str| {
        Token::new(text).map_err(|error| description_error(format!("{field} {text:?}: {error}")))
    };
    let format = check["format"].as_str().unwrap_or("safetensors");
    let (backend, release, compute_dtype) = match format {
        "gguf" => (Backend::LlamaCpp, LLAMA_CPP_RELEASE, ElementType::F16),
        "vllm" => (Backend::Vllm, VLLM_RELEASE, ElementType::Bf16),
        _ => (
            Backend::Transformers,
            TRANSFORMERS_RELEASE,
            ElementType::Bf16,
        ),
    };
    let architecture = check["architectures"][0]
        .as_str()
        .or_else(|| check["modelType"].as_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("unknown");
    let quantization = match check["quant"].as_str().filter(|quant| !quant.is_empty()) {
        Some(quant) if format == "gguf" => Quantization::Method {
            method: token("gguf", "the quantization method")?,
            parameters: vec![(
                token("type", "the quantization parameter")?,
                token(quant, "the quantization type")?,
            )],
        },
        _ => Quantization::None,
    };
    Ok(ArtifactDescription {
        bounds: ManifestBounds::DEFAULT,
        compute_dtype,
        quantization,
        adapters: Vec::new(),
        execution_abi: ExecutionAbi {
            runner: BackendRelease::new(backend, release)
                .map_err(|error| description_error(format!("the runner release: {error}")))?,
            architecture_adapter: VersionedName {
                name: token(architecture, "the architecture")?,
                version: token(release, "the runner release")?,
            },
            layout: token("original", "the layout")?,
            kernels: Vec::new(),
            hardware: HardwareRestriction::Unrestricted,
        },
        distribution: Distribution::SINGLE,
        integrity_extent_bytes: INTEGRITY_EXTENT_BYTES,
    })
}

fn owner_scope() -> Result<Scope, BindingError> {
    catalog_service::owner_scope()
        .ok_or_else(|| description_error("the owner scope is unavailable"))
}

/// The import of `folder` for `execution`: `listing` built for `description` under the
/// owner scope, keyed as the engine's identity port keys it, with a bounded lease.
pub(super) fn import_request(
    folder: &Path,
    listing: SourceListing,
    description: ArtifactDescription,
    execution: ExecutionId,
    contents: &ContentKeys,
    claims: BTreeMap<RelativePath, PublisherClaim>,
) -> Result<ModelFileImport<()>, BindingError> {
    let scope = owner_scope()?;
    let operation = OperationId::new(OPERATION)
        .map_err(|error| description_error(format!("the operation name: {error}")))?;
    let key = FolderIdentities::import_key(&listing, &description);
    let declared = contents
        .iter()
        .filter_map(|(name, hashed)| {
            RelativePath::new(name.as_str())
                .ok()
                .map(|path| (path, hashed.manifest.clone()))
        })
        .collect();
    Ok(ModelFileImport {
        declared,
        claims,
        folder: folder.to_path_buf(),
        request: ImportRequest {
            key,
            listing,
            description,
            state: StateGroup::default(),
            aliases: Vec::new(),
            owners: Vec::new(),
            identity: (),
            catalog: CatalogContext {
                scope,
                execution,
                operation,
                trust: TrustClaim::UserSelected,
                dependencies: BTreeMap::new(),
            },
        },
        lease: MODEL_LEASE,
    })
}

/// A model folder bound through the catalog: the execution holding its leases, its model
/// (the sidecar object), the view the workload binds, its [`CONTENT_OPTION`] and what the
/// import did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CatalogBind {
    pub execution: ExecutionId,
    pub model: ObjectId,
    pub view: PathBuf,
    pub files: u64,
    pub bytes: u64,
    /// The [`CONTENT_OPTION`] value: every listed file's content key.
    pub content: String,
    /// This import copied at least one file into the catalog.
    pub copied: bool,
    /// The sidecar was already published; nothing was indexed again.
    pub reused: bool,
    /// Prepared representations the import evicted to make room, and their bytes.
    pub evicted: usize,
    pub evicted_bytes: u64,
}

impl CatalogBind {
    /// The options a catalog environment carries: its execution, its model and its files'
    /// content keys.
    pub(super) fn environment(&self) -> [(&'static str, String); 3] {
        [
            (EXECUTION_OPTION, self.execution.to_string()),
            (MODEL_OPTION, self.model.to_string()),
            (CONTENT_OPTION, self.content.clone()),
        ]
    }

    /// The run result's `catalog` entry.
    pub(super) fn result(&self) -> Value {
        json!({
            "state": "catalog",
            "execution": self.execution,
            "model": self.model.to_string(),
            "view": self.view.display().to_string(),
            "files": self.files,
            "bytes": self.bytes,
            "copied": self.copied,
            "reused": self.reused,
            "evicted": { "objects": self.evicted, "bytes": self.evicted_bytes },
        })
    }
}

/// How a model folder is bound into its workload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Binding {
    /// The catalog path: the workload binds the view.
    Catalog(CatalogBind),
    /// The folder itself is bound, read-only; `catalog` says why in the run result.
    Folder { catalog: Value },
}

impl Binding {
    /// The bind source of the workload: the view, or `folder` itself.
    pub(super) fn bind_source(&self, folder: &str) -> String {
        match self {
            Self::Catalog(bound) => bound.view.to_string_lossy().into_owned(),
            Self::Folder { .. } => folder.to_owned(),
        }
    }

    /// The run result's `catalog` entry.
    pub(super) fn result(&self) -> Value {
        match self {
            Self::Catalog(bound) => bound.result(),
            Self::Folder { catalog } => catalog.clone(),
        }
    }
}

/// The workload variables naming a model's files for `binding`: the runner's manifest,
/// unchanged, when the path has one (the local-folder path: `registry_snapshot.py` accepts
/// exactly `{"revision", "files"}`, line 35, with files of exactly `{"name", "size",
/// "sha256"}`, line 45), and on the catalog path the execution, model and content options.
/// The registry path passes no manifest: the runner verifies the registry's own record in
/// the mount.
pub(super) fn workload_variables(
    runner_manifest: Option<&Value>,
    binding: &Binding,
) -> Vec<(&'static str, String)> {
    let mut variables = Vec::new();
    if let Some(manifest) = runner_manifest {
        variables.push((RUNNER_MANIFEST, manifest.to_string()));
    }
    if let Binding::Catalog(bound) = binding {
        variables.extend(bound.environment());
    }
    variables
}

/// The folder path, when it applies: a source-only folder, or no catalog configured.
fn folder_binding(catalog: &EngineCatalog, check: &Value) -> Option<Binding> {
    if check["sourceOnly"] == true {
        return Some(Binding::Folder {
            catalog: json!({
                "state": "source_only",
                "detail": "A source-only folder has no model weights to index, so it is served \
                           read-only from the folder itself.",
            }),
        });
    }
    match catalog {
        EngineCatalog::NotOpened { location, .. } => Some(Binding::Folder {
            catalog: json!({
                "state": "not_configured",
                "setting": CATALOG_ROOT_SETTING,
                "remedy": location.remedy(),
            }),
        }),
        _ => None,
    }
}

/// Decides and performs the catalog path for `folder`, whose files (entries naming `name`,
/// `size` and the verified `sha256`) and preflight check are given, with their content keys
/// when the caller read them already (see the module documentation); without them each file
/// is read once here, on the catalog path only. A source-only folder and a not-configured
/// catalog bind the folder itself and read nothing; a configured catalog that is not open,
/// or refuses the import, is an error that leaves the folder untouched.
pub(super) fn bind(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    folder: &Path,
    check: &Value,
    files: &[Value],
    contents: Option<&ContentKeys>,
    cancel: &CancellationToken,
) -> Result<Binding, BindingError> {
    bind_for_execution(
        catalog,
        views,
        folder,
        check,
        files,
        contents,
        cancel,
        ExecutionId::generate(),
    )
}

/// Migration records this identity before publication, so interrupted work can be released
/// and retried without creating an unidentifiable view.
pub(super) fn bind_for_execution(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    folder: &Path,
    check: &Value,
    files: &[Value],
    contents: Option<&ContentKeys>,
    cancel: &CancellationToken,
    execution: ExecutionId,
) -> Result<Binding, BindingError> {
    if let Some(binding) = folder_binding(catalog, check) {
        return Ok(binding);
    }
    let read;
    let contents = match contents {
        Some(contents) => contents,
        None => {
            read = content_keys_cancellable(folder, files, cancel)?;
            &read
        }
    };
    let listing = listing(files, contents)?;
    let content = content_option(&listing)?;
    let description = description(check)?;
    let request = import_request(
        folder,
        listing,
        description,
        execution,
        contents,
        claims_of(files)?,
    )?;
    let imported =
        catalog_service::import_model(catalog, &request, cancel).map_err(BindingError::Import)?;
    let copied = imported.originals.iter().any(|original| original.copied);
    let reused = imported.reused;
    let evicted = imported
        .evictions
        .iter()
        .map(|eviction| eviction.evicted.len())
        .sum();
    let evicted_bytes = imported.evictions.iter().fold(0u64, |sum, eviction| {
        sum.saturating_add(eviction.freed_bytes)
    });
    let view =
        catalog_service::hold_model_view_cancellable(catalog, views, imported, cancel).map_err(BindingError::View)?;
    Ok(Binding::Catalog(CatalogBind {
        execution: view.execution,
        model: view.sidecar,
        view: view.path,
        files: view.files,
        bytes: view.bytes,
        content,
        copied,
        reused,
        evicted,
        evicted_bytes,
    }))
}

/// [`bind`] on the engine's catalog.
pub(super) fn bind_engine(
    folder: &Path,
    check: &Value,
    files: &[Value],
    contents: Option<&ContentKeys>,
    cancel: &CancellationToken,
) -> Result<Binding, BindingError> {
    bind(
        catalog_service::engine(),
        catalog_service::engine_views(),
        folder,
        check,
        files,
        contents,
        cancel,
    )
}

/// [`bind`] for the registry's verified cache folder, whose `files` the registry verified
/// (name, size and SHA-256). The runner verifies the mount against the folder's own record
/// ([`REGISTRY_RECORD`]), so on the catalog path the record joins the files in the listing
/// and the view; every file is read once for its content key and checked against its
/// SHA-256. A folder without the record is refused on the catalog path.
pub(super) fn bind_registry(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    folder: &Path,
    check: &Value,
    files: &[Value],
    cancel: &CancellationToken,
) -> Result<Binding, BindingError> {
    bind_registry_for_execution(
        catalog,
        views,
        folder,
        check,
        files,
        cancel,
        ExecutionId::generate(),
    )
}

pub(super) fn bind_registry_for_execution(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    folder: &Path,
    check: &Value,
    files: &[Value],
    cancel: &CancellationToken,
    execution: ExecutionId,
) -> Result<Binding, BindingError> {
    if let Some(binding) = folder_binding(catalog, check) {
        return Ok(binding);
    }
    let record = folder.join(REGISTRY_RECORD);
    let record_bytes = fs::symlink_metadata(&record)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
        .ok_or_else(|| listing_error(format!("the registry folder has no {REGISTRY_RECORD}")))?;
    let listed: Vec<Value> = files
        .iter()
        .filter(|file| file["name"] != REGISTRY_RECORD)
        .cloned()
        .chain(std::iter::once(
            json!({ "name": REGISTRY_RECORD, "size": record_bytes }),
        ))
        .collect();
    bind_for_execution(
        catalog, views, folder, check, &listed, None, cancel, execution,
    )
}

/// [`bind_registry`] on the engine's catalog.
pub(super) fn bind_registry_engine(
    folder: &Path,
    check: &Value,
    files: &[Value],
    cancel: &CancellationToken,
) -> Result<Binding, BindingError> {
    bind_registry(
        catalog_service::engine(),
        catalog_service::engine_views(),
        folder,
        check,
        files,
        cancel,
    )
}

/// Whether `options` belong to an environment of the same catalog model as `bound`.
pub(super) fn same_model(options: &Options, bound: &CatalogBind) -> bool {
    options
        .environment
        .get(MODEL_OPTION)
        .is_some_and(|model| *model == bound.model.to_string())
}

/// The catalog model an environment's options name.
struct NamedModel {
    execution: ExecutionId,
    sidecar: ObjectId,
    originals: Vec<(RelativePath, ObjectId)>,
}

/// The catalog model `options` name, its files from [`CONTENT_OPTION`]; `None` for an
/// environment not on the catalog path.
fn named_model(options: &Options) -> Result<Option<NamedModel>, BindingError> {
    let Some(execution) = options.environment.get(EXECUTION_OPTION) else {
        return Ok(None);
    };
    let execution = ExecutionId::new(execution.as_str())
        .map_err(|error| options_error(format!("{EXECUTION_OPTION}: {error}")))?;
    let sidecar = options
        .environment
        .get(MODEL_OPTION)
        .ok_or_else(|| options_error(format!("{MODEL_OPTION} is missing")))?;
    let sidecar: ObjectId = serde_json::from_value(Value::String(sidecar.clone()))
        .map_err(|error| options_error(format!("{MODEL_OPTION}: {error}")))?;
    let content = options
        .environment
        .get(CONTENT_OPTION)
        .ok_or_else(|| options_error(format!("{CONTENT_OPTION} is missing")))?;
    let scope = owner_scope()?;
    let originals = parse_content_option(content)?
        .into_iter()
        .map(|(path, content)| {
            let object = ObjectId::new(&scope, ArtifactClass::ModelWeights, content);
            (path, object)
        })
        .collect();
    Ok(Some(NamedModel {
        execution,
        sidecar,
        originals,
    }))
}

/// Before an environment starts: renews its execution's leases, or takes them again when
/// they ended or the engine restarted (from [`CONTENT_OPTION`], reading no folder),
/// completes its view, and points its model bind at the view (which moves with the catalog
/// root). `Ok(None)` for an environment not on the catalog path.
pub(super) fn refresh(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    options: &mut Options,
) -> Result<Option<ModelView>, BindingError> {
    let Some(named) = named_model(options)? else {
        return Ok(None);
    };
    let scope = owner_scope()?;
    let view = catalog_service::refresh_model_view(
        catalog,
        views,
        &scope,
        &named.execution,
        named.sidecar,
        named.originals,
        MODEL_LEASE,
    )
    .map_err(BindingError::View)?;
    let source = view.path.to_string_lossy().into_owned();
    for bind in options
        .binds
        .iter_mut()
        .filter(|bind| bind.target == MODEL_TARGET)
    {
        bind.source = source.clone();
        bind.read_only = true;
    }
    Ok(Some(view))
}

/// The model the environment `environment` holds through the catalog, from its options, for
/// [`catalog_service::restore_views`]; `None` for one not on the catalog path.
pub(super) fn running_model(
    environment: &str,
    options: &Options,
) -> Result<Option<catalog_service::RunningModel>, BindingError> {
    Ok(
        named_model(options)?.map(|named| catalog_service::RunningModel {
            environment: environment.to_owned(),
            execution: named.execution,
            sidecar: named.sidecar,
            originals: named.originals,
        }),
    )
}

/// At the engine's start: the running environments' models lease again and keep their views,
/// everything else under `views/` is swept ([`catalog_service::restore_views`]). `Ok(None)`
/// when no catalog is open.
pub(crate) fn restore_engine(
    running: &[catalog_service::RunningModel],
) -> Result<Option<catalog_service::RestoredViews>, BindingError> {
    let catalog = catalog_service::engine();
    if !matches!(catalog, EngineCatalog::Open { .. }) {
        return Ok(None);
    }
    let scope = owner_scope()?;
    catalog_service::restore_views(
        catalog,
        catalog_service::engine_views(),
        &scope,
        running,
        MODEL_LEASE,
    )
    .map(Some)
    .map_err(BindingError::View)
}

/// [`refresh`] on the engine's catalog.
pub(super) fn refresh_engine(options: &mut Options) -> Result<Option<ModelView>, BindingError> {
    refresh(
        catalog_service::engine(),
        catalog_service::engine_views(),
        options,
    )
}

/// Ends the leases and removes the view of the environment `options` describe, for the
/// moment it is deleted. `Ok(false)` for an environment not on the catalog path.
pub(super) fn release(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    options: &Options,
) -> Result<bool, BindingError> {
    let Some(execution) = options.environment.get(EXECUTION_OPTION) else {
        return Ok(false);
    };
    let execution = ExecutionId::new(execution.as_str())
        .map_err(|error| options_error(format!("{EXECUTION_OPTION}: {error}")))?;
    catalog_service::release_model_view(catalog, views, &execution).map_err(BindingError::View)?;
    Ok(true)
}

/// [`release`] on the engine's catalog.
pub(super) fn release_engine(options: &Options) -> Result<bool, BindingError> {
    release(
        catalog_service::engine(),
        catalog_service::engine_views(),
        options,
    )
}

/// Ends a binding no environment holds: its execution's leases and its view.
pub(super) fn release_bound(
    catalog: &EngineCatalog,
    views: &ViewRegistry,
    bound: &CatalogBind,
) -> Result<(), BindingError> {
    catalog_service::release_model_view(catalog, views, &bound.execution)
        .map(|_swept| ())
        .map_err(BindingError::View)
}

/// [`release_bound`] on the engine's catalog.
pub(super) fn release_bound_engine(bound: &CatalogBind) -> Result<(), BindingError> {
    release_bound(
        catalog_service::engine(),
        catalog_service::engine_views(),
        bound,
    )
}

/// Return a newly published binding which no environment adopted. Both folder and
/// registry launch paths use this after any refusal, including errors before workload
/// creation. Published originals stay; only this execution's view and leases end.
pub(super) async fn release_unadopted(binding: &Binding) {
    let Binding::Catalog(bound) = binding else { return };
    let bound = bound.clone();
    match tokio::task::spawn_blocking(move || release_bound_engine(&bound)).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => eprintln!("Model catalog leases were not released: {error}"),
        Err(error) => eprintln!("Model catalog leases were not released: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::catalog_service::{respond_with_views, Settings, GC_GRACE};
    use crate::foundation::catalog::{ImportRefusal, QuotaRefusal};
    use crate::foundation::catalog_service::GcOutcome;
    use crate::foundation::ids::{ManualClock, MonotonicTime};
    use crate::foundation::signing::{SystemCalendar, TrustRootLocation, TrustRootService};
    use crate::model_runner::local::{inspect_folder, inspect_verified};

    fn untrusted() -> TrustRootService {
        TrustRootService::open(
            TrustRootLocation::from_setting("YOUGORI_TEST_BINDING_TRUST_ROOTS", None),
            Arc::new(SystemCalendar),
        )
    }

    fn make_tree_writable(path: &Path) {
        if let Ok(entries) = fs::read_dir(path) {
            for entry in entries.flatten() {
                make_tree_writable(&entry.path());
            }
        }
        if let Ok(metadata) = fs::metadata(path) {
            let mut permissions = metadata.permissions();
            if permissions.readonly() {
                permissions.set_readonly(false);
                let _ = fs::set_permissions(path, permissions);
            }
        }
    }

    fn not_configured() -> EngineCatalog {
        catalog_service::open(
            &Settings::from_values(None, None),
            &mut untrusted(),
            Arc::new(ManualClock::new(MonotonicTime::from_nanos(1))),
            Arc::new(SystemCalendar),
        )
    }

    /// The files of a manifest, as `run_checked` hands them to [`bind`].
    fn files_of(manifest: &Value) -> Vec<Value> {
        manifest["files"].as_array().cloned().unwrap_or_default()
    }

    /// A catalog in a temporary root, with the registry its views are held in.
    struct Engine {
        dir: tempfile::TempDir,
        root: PathBuf,
        clock: Arc<ManualClock>,
        views: ViewRegistry,
        catalog: Option<EngineCatalog>,
    }

    impl Engine {
        fn with_quota(quota: &str) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().join("catalog");
            let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1)));
            let views = ViewRegistry::new();
            let settings =
                Settings::from_values(Some(root.as_os_str()), Some(std::ffi::OsStr::new(quota)));
            let catalog = catalog_service::open_with_views(
                &settings,
                &mut untrusted(),
                clock.clone(),
                Arc::new(SystemCalendar),
                &views,
            );
            Self {
                dir,
                root,
                clock,
                views,
                catalog: Some(catalog),
            }
        }

        fn new() -> Self {
            Self::with_quota("1048576")
        }

        fn catalog(&self) -> &EngineCatalog {
            self.catalog.as_ref().unwrap()
        }

        /// Drops the catalog, as a restart would, and opens the root again; the views
        /// registry starts empty, as the engine's does after a restart.
        fn reopen(&mut self) {
            self.catalog = None;
            self.views = ViewRegistry::new();
            let settings = Settings::from_values(
                Some(self.root.as_os_str()),
                Some(std::ffi::OsStr::new("1048576")),
            );
            self.catalog = Some(catalog_service::open_with_views(
                &settings,
                &mut untrusted(),
                self.clock.clone(),
                Arc::new(SystemCalendar),
                &self.views,
            ));
        }

        /// The local-folder path as `run` takes it: the content keys of the one read.
        fn bind(&self, folder: &ModelFolder) -> Result<Binding, BindingError> {
            let (check, manifest, contents) = folder.inspect();
            bind(
                self.catalog(),
                &self.views,
                &folder.root,
                &check,
                &files_of(&manifest),
                Some(&contents),
                &CancellationToken::new(),
            )
        }

        fn status(&self) -> Value {
            respond_with_views(self.catalog(), &self.views, None).unwrap()
        }

        fn gc(&self) -> GcOutcome {
            match self.catalog() {
                EngineCatalog::Open { service, .. } => service.collect_garbage().outcome,
                _ => panic!("not open"),
            }
        }

        fn object_dirs(&self) -> Vec<PathBuf> {
            let mut dirs: Vec<PathBuf> = fs::read_dir(self.root.join("objects"))
                .unwrap()
                .flatten()
                .map(|entry| entry.path())
                .collect();
            dirs.sort();
            dirs
        }

        fn views_dir(&self) -> PathBuf {
            self.root.join("views")
        }

        fn view_dirs(&self) -> Vec<PathBuf> {
            fs::read_dir(self.views_dir())
                .map(|entries| entries.flatten().map(|entry| entry.path()).collect())
                .unwrap_or_default()
        }
    }

    impl Drop for Engine {
        fn drop(&mut self) {
            self.catalog = None;
            make_tree_writable(self.dir.path());
        }
    }

    /// A safetensors file holding `tensors` (name, dtype, shape, bytes) in order.
    fn safetensors(tensors: &[(&str, ElementType, &[u64], &[u8])]) -> Vec<u8> {
        let mut header = serde_json::Map::new();
        header.insert("__metadata__".to_owned(), json!({ "format": "pt" }));
        let mut data = Vec::new();
        for (tensor, dtype, shape, bytes) in tensors {
            let begin = data.len();
            data.extend_from_slice(bytes);
            header.insert(
                (*tensor).to_owned(),
                json!({
                    "dtype": dtype.safetensors_name(),
                    "shape": shape,
                    "data_offsets": [begin, data.len()],
                }),
            );
        }
        let mut header = serde_json::to_vec(&header).unwrap();
        while !header.len().is_multiple_of(8) {
            header.push(b' ');
        }
        let mut file = (header.len() as u64).to_le_bytes().to_vec();
        file.extend_from_slice(&header);
        file.extend_from_slice(&data);
        file
    }

    /// The owner's model folder: a Llama configuration, a tokenizer and one safetensors
    /// file whose bytes follow `seed`.
    struct ModelFolder {
        _dir: tempfile::TempDir,
        root: PathBuf,
        names: Vec<&'static str>,
    }

    impl ModelFolder {
        fn new(seed: u8) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let root = dir.path().canonicalize().unwrap();
            let embed: Vec<u8> = (0..16u8)
                .flat_map(|value| f32::from(value.wrapping_add(seed)).to_le_bytes())
                .collect();
            let norm: Vec<u8> = (0..8u8).map(|value| value ^ seed).collect();
            fs::write(
                root.join("config.json"),
                r#"{"model_type":"llama","architectures":["LlamaForCausalLM"]}"#,
            )
            .unwrap();
            fs::write(
                root.join("tokenizer.json"),
                br#"{"model":{"type":"BPE","vocab":{}}}"#,
            )
            .unwrap();
            fs::write(
                root.join("model.safetensors"),
                safetensors(&[
                    (
                        "model.embed_tokens.weight",
                        ElementType::F32,
                        &[4, 4],
                        &embed,
                    ),
                    ("model.norm.weight", ElementType::Bf16, &[4], &norm),
                ]),
            )
            .unwrap();
            Self {
                _dir: dir,
                root,
                names: vec!["config.json", "model.safetensors", "tokenizer.json"],
            }
        }

        fn inspect(&self) -> (Value, Value, ContentKeys) {
            inspect_verified("local/model", self.root.to_str().unwrap(), None).unwrap()
        }

        /// Every file's bytes and modification time, to show the folder is untouched.
        fn snapshot(&self) -> Vec<(Vec<u8>, std::time::SystemTime)> {
            self.names
                .iter()
                .map(|name| {
                    let path = self.root.join(name);
                    (
                        fs::read(&path).unwrap(),
                        fs::metadata(&path).unwrap().modified().unwrap(),
                    )
                })
                .collect()
        }

        fn total_bytes(&self) -> u64 {
            self.names
                .iter()
                .map(|name| fs::metadata(self.root.join(name)).unwrap().len())
                .sum()
        }
    }

    fn bound(binding: Binding) -> CatalogBind {
        match binding {
            Binding::Catalog(bound) => bound,
            Binding::Folder { catalog } => panic!("the folder was bound: {catalog}"),
        }
    }

    /// The environment's options as `run_checked` writes them for `bound` and `manifest`.
    fn options_for(bound: &CatalogBind, manifest: &Value) -> Options {
        let mut options = Options::default();
        for (name, value) in workload_variables(Some(manifest), &Binding::Catalog(bound.clone())) {
            options.environment.insert(name.into(), value);
        }
        options.binds.push(yougori_cli::workload::Volume {
            source: bound.view.to_string_lossy().into_owned(),
            target: MODEL_TARGET.into(),
            read_only: true,
        });
        options
    }

    /// The keys of a JSON object, sorted.
    fn keys(value: &Value) -> Vec<&str> {
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// The runner's manifest among `variables`, checked for the exact shape its verifier
    /// accepts: registry_snapshot.py:35 `set(record) != {"revision", "files"}` and :45
    /// `set(item) != {"name", "size", "sha256"}` refuse anything else.
    fn runner_manifest(variables: &[(&'static str, String)]) -> Value {
        let manifests: Vec<&String> = variables
            .iter()
            .filter(|(name, _)| *name == RUNNER_MANIFEST)
            .map(|(_, value)| value)
            .collect();
        assert_eq!(manifests.len(), 1, "{variables:?}");
        let record: Value = serde_json::from_str(manifests[0]).unwrap();
        assert_eq!(keys(&record), ["files", "revision"]);
        for file in record["files"].as_array().unwrap() {
            assert_eq!(keys(file), ["name", "sha256", "size"], "{file}");
        }
        record
    }

    /// The view promises the committed bytes behind the read-only attribute, as a separate
    /// file: the host folder server refuses hard links.
    fn same_file(a: &Path, b: &Path) -> bool {
        fs::read(a).unwrap() == fs::read(b).unwrap()
            && fs::metadata(a).unwrap().permissions().readonly()
            && fs::metadata(b).unwrap().permissions().readonly()
    }

    #[test]
    fn roles_follow_the_file_name_and_the_description_follows_the_check() {
        assert_eq!(
            role_of("model-00001-of-00002.safetensors"),
            FileRole::Weights {
                format: WeightFormat::Safetensors,
                rank: None
            }
        );
        assert_eq!(
            role_of("quants/Model-Q4_K_M.gguf"),
            FileRole::Weights {
                format: WeightFormat::Gguf,
                rank: None
            }
        );
        assert_eq!(role_of("config.json"), FileRole::Configuration);
        for name in [
            "tokenizer.json",
            "tokenizer_config.json",
            "tokenizer.model",
            "special_tokens_map.json",
            "vocab.json",
            "merges.txt",
            "cl100k_base.tiktoken",
        ] {
            assert_eq!(role_of(name), FileRole::Tokenizer, "{name}");
        }
        for name in [
            "generation_config.json",
            "README.md",
            "modeling_x.py",
            "LICENSE",
            REGISTRY_RECORD,
        ] {
            assert_eq!(role_of(name), FileRole::Other, "{name}");
        }

        let transformers = description(&json!({
            "format": "safetensors",
            "architectures": ["LlamaForCausalLM"],
            "modelType": "llama",
        }))
        .unwrap();
        assert_eq!(
            transformers.execution_abi.runner.backend,
            Backend::Transformers
        );
        assert_eq!(
            transformers.execution_abi.runner.version.as_str(),
            TRANSFORMERS_RELEASE
        );
        assert_eq!(
            transformers
                .execution_abi
                .architecture_adapter
                .name
                .as_str(),
            "LlamaForCausalLM"
        );
        assert_eq!(transformers.compute_dtype, ElementType::Bf16);
        assert_eq!(transformers.quantization, Quantization::None);
        assert_eq!(transformers.distribution, Distribution::SINGLE);
        let gguf =
            description(&json!({ "format": "gguf", "modelType": "gguf", "quant": "Q4_K_M" }))
                .unwrap();
        assert_eq!(gguf.execution_abi.runner.backend, Backend::LlamaCpp);
        assert_eq!(
            gguf.execution_abi.architecture_adapter.name.as_str(),
            "gguf"
        );
        assert_eq!(gguf.compute_dtype, ElementType::F16);
        assert!(
            matches!(&gguf.quantization, Quantization::Method { method, parameters }
            if method.as_str() == "gguf" && parameters.len() == 1 && parameters[0].1.as_str() == "Q4_K_M")
        );
        // A check naming something no token can carry is refused, not guessed.
        assert!(matches!(
            description(&json!({ "format": "gguf", "quant": "Q4 K M" })),
            Err(BindingError::Description { .. })
        ));

        // The import key is a function of the listing and the description alone.
        let folder = ModelFolder::new(1);
        let (check, manifest, contents) = folder.inspect();
        let listing_a = listing(&files_of(&manifest), &contents).unwrap();
        assert_eq!(listing_a.files.len(), 3);
        assert_eq!(
            listing_a.files[1].role,
            FileRole::Weights {
                format: WeightFormat::Safetensors,
                rank: None
            }
        );
        let key = FolderIdentities::import_key(&listing_a, &description(&check).unwrap());
        assert_eq!(
            key,
            FolderIdentities::import_key(
                &listing(&files_of(&manifest), &contents).unwrap(),
                &description(&check).unwrap()
            )
        );
        let mut other = check.clone();
        other["quant"] = json!("Q8_0");
        other["format"] = json!("gguf");
        let other_key = FolderIdentities::import_key(&listing_a, &description(&other).unwrap());
        assert_eq!(other_key.source, key.source);
        assert_ne!(other_key.execution, key.execution);
        // Files without content keys cannot be listed for the catalog.
        assert!(matches!(
            listing(&files_of(&manifest), &ContentKeys::new()),
            Err(BindingError::Listing { .. })
        ));
    }

    #[test]
    fn the_runner_manifest_keeps_its_exact_shape_with_and_without_a_catalog() {
        // registry_snapshot.py:35 accepts exactly {"revision", "files"}, :45 every file
        // exactly {"name", "size", "sha256"}, and :22 prefers YOUGORI_LOCAL_MANIFEST to the
        // mount: what `run_checked` passes (`workload_variables`) must keep that shape.
        let folder = ModelFolder::new(15);
        let (check, manifest, contents) = folder.inspect();

        // Without a catalog: the folder is bound and only the runner's manifest is passed.
        let unconfigured = not_configured();
        let views = ViewRegistry::new();
        let binding = bind(
            &unconfigured,
            &views,
            &folder.root,
            &check,
            &files_of(&manifest),
            Some(&contents),
            &CancellationToken::new(),
        )
        .unwrap();
        assert!(matches!(binding, Binding::Folder { .. }));
        let variables = workload_variables(Some(&manifest), &binding);
        assert_eq!(variables.len(), 1);
        let without = runner_manifest(&variables);
        assert_eq!(without, manifest);
        assert_eq!(without["revision"], check["revision"]);

        // With a catalog: the very same manifest, and the catalog's own options beside it.
        let engine = Engine::new();
        let binding = engine.bind(&folder).unwrap();
        let variables = workload_variables(Some(&manifest), &binding);
        assert_eq!(runner_manifest(&variables), without);
        let names: Vec<&str> = variables.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                RUNNER_MANIFEST,
                EXECUTION_OPTION,
                MODEL_OPTION,
                CONTENT_OPTION
            ]
        );
        let content = &variables[3].1;
        let named: Vec<(String, ContentKey)> = parse_content_option(content)
            .unwrap()
            .into_iter()
            .map(|(path, key)| (path.as_str().to_owned(), key))
            .collect();
        assert_eq!(
            named,
            contents
                .iter()
                .map(|(name, hashed)| (name.clone(), hashed.content))
                .collect::<Vec<_>>()
        );

        // `run_verified` has no content keys: the binding reads each file once on the
        // catalog path, checks its SHA-256, and names the same keys; the manifest is untouched.
        let read = bound(
            bind(
                engine.catalog(),
                &engine.views,
                &folder.root,
                &check,
                &files_of(&manifest),
                None,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        assert_eq!(&read.content, content);
        let read_variables = workload_variables(Some(&manifest), &Binding::Catalog(read));
        assert_eq!(runner_manifest(&read_variables), without);
        let mut tampered = files_of(&manifest);
        tampered[0]["sha256"] = json!("0".repeat(64));
        assert!(matches!(
            bind(
                engine.catalog(),
                &engine.views,
                &folder.root,
                &check,
                &tampered,
                None,
                &CancellationToken::new(),
            ),
            Err(BindingError::Read { .. })
        ));
    }

    #[test]
    fn a_folder_imports_once_into_a_read_only_view_and_a_second_run_copies_nothing() {
        let engine = Engine::new();
        let folder = ModelFolder::new(1);
        let before = folder.snapshot();

        let first = bound(engine.bind(&folder).unwrap());
        assert!(first.copied && !first.reused);
        assert_eq!(first.files, 3);
        assert_eq!(first.bytes, folder.total_bytes());
        assert_eq!(
            first.view,
            engine.views_dir().join(first.execution.as_str())
        );
        // The view holds a read-only copy of each published original; the originals and the
        // sidecar are the only objects.
        let objects = engine.object_dirs();
        assert_eq!(objects.len(), 4);
        for name in &folder.names {
            let link = first.view.join(name);
            let metadata = fs::metadata(&link).unwrap();
            assert!(
                metadata.is_file() && metadata.permissions().readonly(),
                "{name}"
            );
            assert_eq!(
                fs::read(&link).unwrap(),
                fs::read(folder.root.join(name)).unwrap()
            );
            let data = objects
                .iter()
                .map(|dir| dir.join("data"))
                .find(|data| fs::read(data).unwrap() == fs::read(&link).unwrap())
                .unwrap();
            assert!(same_file(&link, &data), "{name}");
            assert!(
                fs::OpenOptions::new().write(true).open(&link).is_err(),
                "{name} is writable"
            );
        }
        // The owner's folder is exactly as it was.
        assert_eq!(folder.snapshot(), before);
        let status = engine.status();
        assert_eq!(status["views"]["count"], 1);
        assert_eq!(
            status["views"]["held"][0]["execution"],
            first.execution.as_str()
        );
        assert_eq!(status["views"]["held"][0]["files"], 3);
        assert_eq!(status["views"]["held"][0]["bytes"], folder.total_bytes());
        assert_eq!(status["catalog"]["live_leases"], 4);
        let charged = status["catalog"]["scopes"][1]["quota"]["charged_bytes"].clone();

        // Running the same folder again copies nothing and makes no second object; the model
        // is the same sidecar, so an environment carrying it is the same model.
        let second = bound(engine.bind(&folder).unwrap());
        assert!(!second.copied && second.reused);
        assert_eq!(second.model, first.model);
        assert_ne!(second.execution, first.execution);
        assert_eq!(engine.object_dirs(), objects);
        assert_eq!(engine.view_dirs().len(), 2);
        let status = engine.status();
        assert_eq!(
            status["catalog"]["scopes"][1]["quota"]["charged_bytes"],
            charged
        );
        assert_eq!(status["catalog"]["live_leases"], 8);
        let (_, manifest, _) = folder.inspect();
        assert!(same_model(&options_for(&first, &manifest), &second));
        assert!(!same_model(&Options::default(), &second));
        assert_eq!(folder.snapshot(), before);
    }

    #[test]
    fn a_file_with_another_files_bytes_gets_its_own_read_only_copy_in_the_view() {
        // The runner's verifier refuses two manifest entries that are one file (its
        // device-and-inode check), so the second path of the same bytes is a copy.
        let engine = Engine::new();
        let folder = ModelFolder::new(16);
        let tokenizer = fs::read(folder.root.join("tokenizer.json")).unwrap();
        fs::write(folder.root.join("added_tokens.json"), &tokenizer).unwrap();
        let first = bound(engine.bind(&folder).unwrap());
        assert_eq!(first.files, 4);
        // One object serves both paths; "added_tokens.json" comes first and is the link.
        assert_eq!(engine.object_dirs().len(), 4);
        let link = first.view.join("added_tokens.json");
        let copy = first.view.join("tokenizer.json");
        for path in [&link, &copy] {
            assert_eq!(fs::read(path).unwrap(), tokenizer);
            assert!(fs::metadata(path).unwrap().permissions().readonly());
        }
        let data = engine
            .object_dirs()
            .into_iter()
            .map(|dir| dir.join("data"))
            .find(|data| fs::read(data).unwrap() == tokenizer)
            .unwrap();
        assert!(same_file(&link, &data));
        // The copy is its own file: changing it changes neither the link nor the published
        // original.
        make_tree_writable(&copy);
        fs::write(&copy, b"changed").unwrap();
        assert_eq!(fs::read(&link).unwrap(), tokenizer);
        assert_eq!(fs::read(&data).unwrap(), tokenizer);
        assert!(fs::metadata(&data).unwrap().permissions().readonly());
    }

    #[test]
    fn a_second_folder_with_one_identical_file_shares_that_object() {
        let engine = Engine::new();
        let first = ModelFolder::new(2);
        let second = ModelFolder::new(3);
        bound(engine.bind(&first).unwrap());
        let objects = engine.object_dirs().len();
        // The configuration and tokenizer are identical; only the weights differ.
        let (check, manifest, contents) = second.inspect();
        let request = import_request(
            &second.root,
            listing(&files_of(&manifest), &contents).unwrap(),
            description(&check).unwrap(),
            ExecutionId::generate(),
            &contents,
            BTreeMap::new(),
        )
        .unwrap();
        let imported =
            catalog_service::import_model(engine.catalog(), &request, &CancellationToken::new())
                .unwrap();
        assert_eq!(
            imported
                .originals
                .iter()
                .map(|original| (original.path.as_str(), original.copied))
                .collect::<Vec<_>>(),
            vec![
                ("config.json", false),
                ("model.safetensors", true),
                ("tokenizer.json", false)
            ]
        );
        // One new original and one new sidecar.
        assert_eq!(engine.object_dirs().len(), objects + 2);
        let view =
            catalog_service::hold_model_view(engine.catalog(), &engine.views, imported).unwrap();
        assert_eq!(view.files, 3);
    }

    #[test]
    fn cancellation_leaves_the_folder_untouched_and_a_retry_imports() {
        let engine = Engine::new();
        let folder = ModelFolder::new(4);
        let before = folder.snapshot();
        let (check, manifest, contents) = folder.inspect();
        let cancel = CancellationToken::new();
        cancel.cancel();
        let refused = bind(
            engine.catalog(),
            &engine.views,
            &folder.root,
            &check,
            &files_of(&manifest),
            Some(&contents),
            &cancel,
        )
        .unwrap_err();
        assert!(
            matches!(
                refused,
                BindingError::Import(ModelFileRefusal::Cancelled { .. })
            ),
            "{refused:?}"
        );
        assert!(engine.object_dirs().is_empty());
        assert!(engine.view_dirs().is_empty());
        assert_eq!(folder.snapshot(), before);
        let retried = bound(engine.bind(&folder).unwrap());
        assert!(retried.copied);
        assert_eq!(engine.object_dirs().len(), 4);
    }

    #[test]
    fn a_folder_over_the_budget_is_refused_with_the_catalog_reason_and_nothing_is_published_or_viewed(
    ) {
        let engine = Engine::with_quota("8");
        let folder = ModelFolder::new(5);
        let before = folder.snapshot();
        let refused = engine.bind(&folder).unwrap_err();
        let BindingError::Import(ModelFileRefusal::Admission { path, refusal }) = &refused else {
            panic!("{refused:?}");
        };
        assert_eq!(path.as_str(), "config.json");
        assert!(matches!(
            refusal.as_ref(),
            ImportRefusal::Quota {
                refusal: QuotaRefusal::Exceeded { limit_bytes: 8, .. }
            }
        ));
        assert!(refused.to_string().contains("config.json"), "{refused}");
        assert!(engine.object_dirs().is_empty());
        assert!(engine.view_dirs().is_empty());
        assert_eq!(engine.status()["views"]["count"], 0);
        assert_eq!(engine.status()["catalog"]["live_leases"], 0);
        assert_eq!(folder.snapshot(), before);
    }

    #[test]
    fn release_ends_the_leases_and_removes_the_view_and_the_collector_keeps_the_originals() {
        let engine = Engine::new();
        let folder = ModelFolder::new(6);
        let (_, manifest, _) = folder.inspect();
        let first = bound(engine.bind(&folder).unwrap());
        let objects = engine.object_dirs();
        // Leased and rooted: the collector removes nothing.
        assert!(
            matches!(engine.gc(), GcOutcome::Collected { removed, removed_unpublished, .. }
            if removed.is_empty() && removed_unpublished.is_empty())
        );

        let options = options_for(&first, &manifest);
        assert_eq!(release(engine.catalog(), &engine.views, &options), Ok(true));
        assert_eq!(
            release(engine.catalog(), &engine.views, &Options::default()),
            Ok(false)
        );
        assert!(!first.view.exists());
        assert!(engine.view_dirs().is_empty());
        let status = engine.status();
        assert_eq!(status["catalog"]["live_leases"], 0);
        assert_eq!(status["views"]["count"], 0);
        // The published copies stay read-only in place.
        assert_eq!(engine.object_dirs(), objects);
        for dir in &objects {
            assert!(fs::metadata(dir.join("data"))
                .unwrap()
                .permissions()
                .readonly());
        }
        // After the grace period the unleased originals are still there: the sidecar's root
        // keeps it and, through it, the originals reachable, and the catalog never removes an
        // original anyway (plan line 552: only source-file deletion does).
        engine.clock.advance(GC_GRACE * 2);
        let outcome = engine.gc();
        let GcOutcome::Collected {
            removed,
            removed_unpublished,
            kept_leased,
            ..
        } = &outcome
        else {
            panic!("{outcome:?}");
        };
        assert!(
            removed.is_empty() && removed_unpublished.is_empty() && kept_leased.is_empty(),
            "{outcome:?}"
        );
        assert_eq!(engine.object_dirs(), objects);
        let status = engine.status();
        assert_eq!(
            status["catalog"]["scopes"][1]["classes"][0]["originals"]["objects"],
            3
        );
        assert_eq!(
            status["catalog"]["scopes"][1]["classes"][1]["originals"]["objects"],
            0
        );
        // Releasing again is harmless: nothing is held and no view is left.
        assert_eq!(release(engine.catalog(), &engine.views, &options), Ok(true));
    }

    #[test]
    fn migration_execution_identity_survives_retry_and_restart_without_orphan_views() {
        let mut engine = Engine::new();
        let folder = ModelFolder::new(19);
        let (check, manifest, contents) = folder.inspect();
        let execution = ExecutionId::generate();
        let first = bound(
            bind_for_execution(
                engine.catalog(),
                &engine.views,
                &folder.root,
                &check,
                &files_of(&manifest),
                Some(&contents),
                &CancellationToken::new(),
                execution.clone(),
            )
            .unwrap(),
        );
        assert_eq!(first.execution, execution);
        // Publication happened but its completion checkpoint was lost: release by the
        // identity durably recorded before import, then retry under exactly that identity.
        catalog_service::release_model_view(engine.catalog(), &engine.views, &execution).unwrap();
        let second = bound(
            bind_for_execution(
                engine.catalog(),
                &engine.views,
                &folder.root,
                &check,
                &files_of(&manifest),
                Some(&contents),
                &CancellationToken::new(),
                execution.clone(),
            )
            .unwrap(),
        );
        assert_eq!(second.view, first.view);
        assert_eq!(engine.view_dirs().len(), 1);
        assert_eq!(engine.status()["catalog"]["live_leases"], 4);
        let mut options = options_for(&second, &manifest);
        let recorded = options.clone();
        engine.reopen();
        refresh(engine.catalog(), &engine.views, &mut options).unwrap();
        assert_eq!(
            options, recorded,
            "recovered intent must keep its exact target options"
        );
        assert_eq!(engine.view_dirs().len(), 1);
        release(engine.catalog(), &engine.views, &options).unwrap();
        assert!(engine.view_dirs().is_empty());
        assert_eq!(engine.status()["catalog"]["live_leases"], 0);
    }

    #[test]
    fn refresh_renews_the_leases_and_after_a_restart_takes_them_again_and_copies_the_view_again() {
        let mut engine = Engine::new();
        let folder = ModelFolder::new(7);
        let (_, manifest, _) = folder.inspect();
        let first = bound(engine.bind(&folder).unwrap());
        let mut options = options_for(&first, &manifest);

        // Held: the leases are renewed and the view kept.
        let view = refresh(engine.catalog(), &engine.views, &mut options)
            .unwrap()
            .unwrap();
        assert_eq!((view.files, &view.path), (3, &first.view));
        assert_eq!(engine.status()["catalog"]["live_leases"], 4);
        assert_eq!(
            refresh(engine.catalog(), &engine.views, &mut Options::default()),
            Ok(None)
        );

        // A restart: leases never survive a reopen, so the open removes the stale view and
        // quarantines nothing; the refresh before the next start takes the leases again from
        // YOUGORI_CATALOG_CONTENT and links the view again, reading no folder.
        engine.reopen();
        assert!(engine.view_dirs().is_empty());
        let status = engine.status();
        assert_eq!(
            status["recovery"]["quarantined"].as_array().unwrap().len(),
            0
        );
        assert_eq!(status["recovery"]["published"], 4);
        assert_eq!(
            status["views"]["last_sweep"]["removed"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(status["catalog"]["live_leases"], 0);
        fs::remove_dir_all(&folder.root).unwrap();
        // The runner's manifest names no content key: the keys come from the catalog option.
        let carried: Value = serde_json::from_str(&options.environment[RUNNER_MANIFEST]).unwrap();
        assert!(carried["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|file| file.get("content").is_none()));
        let view = refresh(engine.catalog(), &engine.views, &mut options)
            .unwrap()
            .unwrap();
        assert_eq!(view.files, 3);
        assert_eq!(view.path, first.view);
        assert_eq!(view.sidecar, first.model);
        assert_eq!(options.binds[0].source, first.view.to_string_lossy());
        assert!(options.binds[0].read_only);
        for name in &folder.names {
            assert!(fs::metadata(first.view.join(name))
                .unwrap()
                .permissions()
                .readonly());
        }
        assert_eq!(engine.status()["catalog"]["live_leases"], 4);

        // Options naming a model the catalog does not hold are refused, and nothing is held.
        let mut foreign = options.clone();
        foreign.environment.insert(
            MODEL_OPTION.into(),
            ObjectId::new(
                &owner_scope().unwrap(),
                ArtifactClass::ModelSidecar,
                ContentKey::of(b"elsewhere"),
            )
            .to_string(),
        );
        let refused = refresh(engine.catalog(), &engine.views, &mut foreign).unwrap_err();
        assert!(
            matches!(refused, BindingError::View(ViewRefusal::Lease { .. })),
            "{refused:?}"
        );
        // Without the content option the runner's manifest is not enough: refused.
        let mut incomplete = options.clone();
        incomplete.environment.remove(CONTENT_OPTION);
        assert!(incomplete.environment.contains_key(RUNNER_MANIFEST));
        assert!(matches!(
            refresh(engine.catalog(), &engine.views, &mut incomplete),
            Err(BindingError::Options { .. })
        ));
        // A content option out of its bounds or malformed is refused before anything is leased.
        let key = "a".repeat(64);
        let too_many: BTreeMap<String, &str> = (0..=MAX_CONTENT_FILES)
            .map(|index| (format!("f{index}.json"), key.as_str()))
            .collect();
        for content in [
            String::new(),
            "{}".to_owned(),
            format!(r#"{{"config.json":"{key}","config.json":"{key}"}}"#),
            r#"{"config.json":"not-hex"}"#.to_owned(),
            format!(r#"{{"../outside.json":"{key}"}}"#),
            serde_json::to_string(&too_many).unwrap(),
            "x".repeat(MAX_CONTENT_OPTION_BYTES + 1),
        ] {
            let mut malformed = options.clone();
            malformed
                .environment
                .insert(CONTENT_OPTION.into(), content.clone());
            assert!(
                matches!(
                    refresh(engine.catalog(), &engine.views, &mut malformed),
                    Err(BindingError::Options { .. })
                ),
                "{}",
                &content[..content.len().min(80)]
            );
        }
    }

    #[test]
    fn without_a_catalog_the_folder_itself_is_bound_and_a_refused_catalog_fails_the_run() {
        let folder = ModelFolder::new(8);
        let (check, manifest, contents) = folder.inspect();
        let views = ViewRegistry::new();
        let unconfigured = not_configured();
        let binding = bind(
            &unconfigured,
            &views,
            &folder.root,
            &check,
            &files_of(&manifest),
            Some(&contents),
            &CancellationToken::new(),
        )
        .unwrap();
        let Binding::Folder { catalog } = &binding else {
            panic!("{binding:?}");
        };
        assert_eq!(catalog["state"], "not_configured");
        assert_eq!(catalog["setting"], CATALOG_ROOT_SETTING);
        assert_eq!(
            catalog["remedy"],
            catalog_service::status(&unconfigured).unwrap()["remedy"]
        );
        assert_eq!(
            binding.bind_source(folder.root.to_str().unwrap()),
            folder.root.to_str().unwrap()
        );
        assert_eq!(binding.result()["state"], "not_configured");
        // Without content keys nothing is read either: a missing file does not matter.
        let missing = vec![json!({ "name": "absent.safetensors", "size": 1, "sha256": "0" })];
        assert!(matches!(
            bind(
                &unconfigured,
                &views,
                &folder.root,
                &check,
                &missing,
                None,
                &CancellationToken::new()
            ),
            Ok(Binding::Folder { .. })
        ));

        // A source-only folder stays on the folder path whatever the catalog.
        let engine = Engine::new();
        let mut source_only = check.clone();
        source_only["sourceOnly"] = json!(true);
        let binding = bind(
            engine.catalog(),
            &engine.views,
            &folder.root,
            &source_only,
            &files_of(&manifest),
            Some(&contents),
            &CancellationToken::new(),
        )
        .unwrap();
        assert_eq!(binding.result()["state"], "source_only");
        assert!(engine.object_dirs().is_empty());

        // A configured catalog that could not be opened refuses: no silent fallback.
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("not-a-directory");
        fs::write(&file, b"x").unwrap();
        let refused = catalog_service::open(
            &Settings::from_values(Some(file.as_os_str()), None),
            &mut untrusted(),
            Arc::new(ManualClock::new(MonotonicTime::from_nanos(1))),
            Arc::new(SystemCalendar),
        );
        let error = bind(
            &refused,
            &views,
            &folder.root,
            &check,
            &files_of(&manifest),
            Some(&contents),
            &CancellationToken::new(),
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                BindingError::Import(ModelFileRefusal::NotOpened { .. })
            ),
            "{error:?}"
        );
        assert!(matches!(
            release(
                &refused,
                &views,
                &options_for(
                    &CatalogBind {
                        execution: ExecutionId::generate(),
                        model: ObjectId::new(
                            &owner_scope().unwrap(),
                            ArtifactClass::ModelSidecar,
                            ContentKey::of(b"x")
                        ),
                        view: PathBuf::new(),
                        files: 0,
                        bytes: 0,
                        content: String::new(),
                        copied: false,
                        reused: false,
                        evicted: 0,
                        evicted_bytes: 0,
                    },
                    &manifest
                )
            ),
            Err(BindingError::View(ViewRefusal::NotOpened { .. }))
        ));
    }

    #[test]
    fn the_view_is_bound_like_a_pc_folder_so_the_catalog_root_must_lie_outside_yougori_data() {
        let engine = Engine::new();
        let folder = ModelFolder::new(9);
        let first = bound(engine.bind(&folder).unwrap());
        let view = first.view.canonicalize().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        // A catalog root beside Yougori's data is a bindable PC folder.
        assert!(crate::host_files::ensure_shareable_folder(
            &view,
            &[elsewhere.path().to_path_buf()],
            false
        )
        .is_ok());
        // One inside Yougori's own data (or containing it) is refused by the bind path.
        assert!(
            crate::host_files::ensure_shareable_folder(&view, &[engine.root.clone()], false)
                .is_err()
        );
        assert!(crate::host_files::ensure_shareable_folder(
            &view,
            &[engine.dir.path().to_path_buf()],
            false
        )
        .is_err());
    }

    #[test]
    fn a_registry_folder_is_viewed_with_its_verified_files_record_and_no_runner_manifest() {
        let engine = Engine::new();
        let folder = ModelFolder::new(10);
        let (check, _, _) = folder.inspect();
        // The registry's verified files and its record, as `download_version` writes them.
        let files: Vec<Value> = folder
            .names
            .iter()
            .map(|name| {
                let bytes = fs::read(folder.root.join(name)).unwrap();
                json!({ "name": name, "size": bytes.len(), "sha256": format!("{:x}", Sha256::digest(&bytes)) })
            })
            .collect();
        let record = json!({ "revision": "c".repeat(64), "files": files }).to_string();
        // Without the record the catalog path refuses: the runner could not verify the view.
        assert!(matches!(
            bind_registry(
                engine.catalog(),
                &engine.views,
                &folder.root,
                &check,
                &files,
                &CancellationToken::new()
            ),
            Err(BindingError::Listing { .. })
        ));
        fs::write(folder.root.join(REGISTRY_RECORD), &record).unwrap();
        let registry = bound(
            bind_registry(
                engine.catalog(),
                &engine.views,
                &folder.root,
                &check,
                &files,
                &CancellationToken::new(),
            )
            .unwrap(),
        );
        // The view holds the model's files and the record the runner verifies them against.
        assert_eq!(registry.files, 4);
        assert_eq!(
            fs::read_to_string(registry.view.join(REGISTRY_RECORD)).unwrap(),
            record
        );
        for name in &folder.names {
            assert_eq!(
                fs::read(registry.view.join(name)).unwrap(),
                fs::read(folder.root.join(name)).unwrap()
            );
        }
        assert_eq!(parse_content_option(&registry.content).unwrap().len(), 4);
        // The registry path passes no runner manifest, only the catalog's options.
        let binding = Binding::Catalog(registry);
        let variables = workload_variables(None, &binding);
        assert!(variables.iter().all(|(name, _)| *name != RUNNER_MANIFEST));
        assert_eq!(variables.len(), 3);
        // A file that no longer matches its verified SHA-256 is refused before any import.
        let mut wrong = files.clone();
        wrong[0]["sha256"] = json!("0".repeat(64));
        let objects = engine.object_dirs().len();
        assert!(matches!(
            bind_registry(
                engine.catalog(),
                &engine.views,
                &folder.root,
                &check,
                &wrong,
                &CancellationToken::new()
            ),
            Err(BindingError::Read { .. })
        ));
        assert!(matches!(
            bind_registry(
                engine.catalog(),
                &engine.views,
                &folder.root,
                &check,
                &[json!({ "name": "../outside.json", "size": 1 })],
                &CancellationToken::new()
            ),
            Err(BindingError::Listing { .. })
        ));
        assert_eq!(engine.object_dirs().len(), objects);
        // Without a catalog the cached folder itself is bound and nothing is read.
        assert!(matches!(
            bind_registry(
                &not_configured(),
                &ViewRegistry::new(),
                &folder.root,
                &check,
                &wrong,
                &CancellationToken::new()
            ),
            Ok(Binding::Folder { .. })
        ));
        // An unverified listing (the preflight) still has the plain shape.
        let (_, unverified) =
            inspect_folder("local/model", folder.root.to_str().unwrap(), None, false).unwrap();
        for file in unverified["files"].as_array().unwrap() {
            assert_eq!(keys(file), ["name", "sha256", "size"]);
        }
    }
}
