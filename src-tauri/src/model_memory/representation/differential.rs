//! Exact differential materialization (GPU §4.2, plan lines 671–679).
//!
//! A model switch is set reconciliation: the required decoded extent set R of the target
//! manifest, the compatible resident set A, and a load of only R minus A, verified
//! against the target manifest. Extents are matched by their decoded content key (§3.3),
//! never by name or size, so tensor aliases and unchanged adapter bases keep their
//! identities across artifacts and across encodings.
//!
//! The full loader stays the baseline: [`choose_loader`] keeps it whenever indexing and
//! hashing cost at least the transfer they save, by the strict inequality of
//! [`ImportAmortization`] (§3.4 line 550). Sharing is measured, never assumed:
//! [`measure_sharing`] hashes tensors and compares extent keys, and a dense fine-tune
//! that changed every tensor shares nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use crate::foundation::catalog::{AmortizationError, ImportAmortization};
use crate::foundation::ids::{
    Clock, ContentKey, Digest, DigestBuilder, GpuDeviceKey, MonotonicTime, TrustScope,
};
use crate::model_memory::manifest::{
    DictionaryId, Distribution, ExtentDecoder, ExtentEncoding, ExtentError, ManifestDigest,
    RankRefusal, RelativePath, TensorDtype, TensorEntry, TensorLayout, ValidatedManifest,
};
use crate::model_memory::math::{non_negative, positive, InputError};

/// Why a differential plan, load or cost decision was refused.
#[derive(Clone, Debug, PartialEq)]
pub enum DifferentialError {
    UnknownTensor {
        name: String,
    },
    Rank(RankRefusal),
    /// A plan or required set is used with a manifest it was not made from.
    PlanForAnotherManifest,
    NoSuchExtent {
        extent_index: usize,
    },
    /// The stored bytes of a missing extent could not be read.
    StoredUnavailable {
        extent_index: usize,
    },
    DictionaryUnavailable {
        extent_index: usize,
    },
    /// Stored bytes failed verification against the target manifest; they are never
    /// used.
    Verification {
        extent_index: usize,
        error: ExtentError,
    },
    /// A planned reuse is no longer readable; the caller replans without it.
    ResidentUnavailable {
        key: ContentKey,
    },
    /// The resident copy a plan bound has expired since; the caller replans.
    ResidentExpired {
        key: ContentKey,
        expired_at: MonotonicTime,
    },
    /// The resident port served bytes from another trust scope or device than the copy
    /// the plan bound; equal bytes elsewhere are not permission (S3.3).
    ResidentOutsideBinding {
        key: ContentKey,
    },
    /// Resident bytes do not hash to the target manifest's content key; never used.
    ResidentMismatch {
        key: ContentKey,
    },
    FileUnavailable {
        path: RelativePath,
    },
    TensorOutOfFile {
        name: String,
    },
    Input(InputError),
    Amortization(AmortizationError),
    Overflow {
        field: &'static str,
    },
}

impl From<InputError> for DifferentialError {
    fn from(error: InputError) -> Self {
        Self::Input(error)
    }
}

impl From<AmortizationError> for DifferentialError {
    fn from(error: AmortizationError) -> Self {
        Self::Amortization(error)
    }
}

impl fmt::Display for DifferentialError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownTensor { name } => write!(f, "the manifest has no tensor {name:?}"),
            Self::Rank(refusal) => refusal.fmt(f),
            Self::PlanForAnotherManifest => f.write_str("the plan belongs to another manifest"),
            Self::NoSuchExtent { extent_index } => write!(f, "no extent {extent_index}"),
            Self::StoredUnavailable { extent_index } => {
                write!(
                    f,
                    "the stored bytes of extent {extent_index} are unavailable"
                )
            }
            Self::DictionaryUnavailable { extent_index } => {
                write!(f, "the dictionary of extent {extent_index} is unavailable")
            }
            Self::Verification {
                extent_index,
                error,
            } => write!(f, "extent {extent_index} failed verification: {error}"),
            Self::ResidentUnavailable { key } => write!(f, "resident extent {key} is gone"),
            Self::ResidentExpired { key, expired_at } => write!(
                f,
                "resident extent {key} expired at {} ns",
                expired_at.as_nanos()
            ),
            Self::ResidentOutsideBinding { key } => write!(
                f,
                "resident bytes of {key} came from another scope or device than planned"
            ),
            Self::ResidentMismatch { key } => {
                write!(f, "resident bytes do not match content key {key}")
            }
            Self::FileUnavailable { path } => write!(f, "file {path} is unavailable"),
            Self::TensorOutOfFile { name } => write!(f, "tensor {name:?} lies outside its file"),
            Self::Input(error) => error.fmt(f),
            Self::Amortization(error) => error.fmt(f),
            Self::Overflow { field } => write!(f, "{field} does not fit in 64 bits"),
        }
    }
}

impl std::error::Error for DifferentialError {}

fn checked_sum(
    values: impl IntoIterator<Item = u64>,
    field: &'static str,
) -> Result<u64, DifferentialError> {
    values.into_iter().try_fold(0u64, |total, value| {
        total
            .checked_add(value)
            .ok_or(DifferentialError::Overflow { field })
    })
}

/// One element of R: a decoded extent the target needs, named by its content key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequiredExtent {
    pub key: ContentKey,
    pub true_length_bytes: u64,
    /// Bytes read from storage to load it: its true length when raw, its encoded length
    /// otherwise.
    pub stored_bytes: u64,
    /// The first extent of the target manifest with this key.
    pub extent_index: usize,
}

/// The required decoded extent set R of one target manifest (GPU §4.2). Extents with
/// equal content keys are one element, so a tied or aliased tensor costs nothing extra.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequiredSet {
    manifest: ManifestDigest,
    extents: BTreeMap<ContentKey, RequiredExtent>,
}

impl RequiredSet {
    fn from_indices(
        manifest: &ValidatedManifest,
        indices: impl IntoIterator<Item = usize>,
    ) -> Result<Self, DifferentialError> {
        let all = &manifest.manifest().extents.extents;
        let mut extents = BTreeMap::new();
        let unique: BTreeSet<usize> = indices.into_iter().collect();
        for extent_index in unique {
            let extent = all
                .get(extent_index)
                .ok_or(DifferentialError::NoSuchExtent { extent_index })?;
            let stored_bytes = match &extent.encoding {
                ExtentEncoding::Raw => extent.true_length_bytes,
                ExtentEncoding::Encoded(encoded) => encoded.location.length_bytes,
            };
            extents.entry(extent.content_key).or_insert(RequiredExtent {
                key: extent.content_key,
                true_length_bytes: extent.true_length_bytes,
                stored_bytes,
                extent_index,
            });
        }
        Ok(Self {
            manifest: manifest.digest(),
            extents,
        })
    }

    fn tensor_extents(manifest: &ValidatedManifest, tensor: &TensorEntry) -> Vec<usize> {
        manifest
            .extents_covering(tensor.file, tensor.offset_bytes, tensor.true_length_bytes)
            .collect()
    }

    /// R for the named tensors; an alias resolves to its target, so it adds nothing.
    pub fn for_tensors(
        manifest: &ValidatedManifest,
        names: &[&str],
    ) -> Result<Self, DifferentialError> {
        let mut indices = Vec::new();
        for name in names {
            let tensor = manifest
                .tensor(name)
                .ok_or_else(|| DifferentialError::UnknownTensor {
                    name: (*name).to_string(),
                })?;
            indices.extend(Self::tensor_extents(manifest, tensor));
        }
        Self::from_indices(manifest, indices)
    }

    /// R for every tensor of the manifest.
    pub fn for_all_tensors(manifest: &ValidatedManifest) -> Result<Self, DifferentialError> {
        let indices: Vec<usize> = manifest
            .manifest()
            .tensor_index
            .tensors
            .iter()
            .flat_map(|tensor| Self::tensor_extents(manifest, tensor))
            .collect();
        Self::from_indices(manifest, indices)
    }

    /// R for one rank of the artifact's own layout; a wrong layout or rank is refused.
    pub fn for_rank(
        manifest: &ValidatedManifest,
        layout: &Distribution,
        rank: u32,
    ) -> Result<Self, DifferentialError> {
        let plan = manifest
            .rank_plan(layout, rank)
            .map_err(DifferentialError::Rank)?;
        Self::from_indices(manifest, plan.extents)
    }

    /// The target manifest this set or plan belongs to.
    pub fn manifest(&self) -> ManifestDigest {
        self.manifest
    }

    /// The elements of R, in content-key order.
    pub fn extents(&self) -> impl Iterator<Item = &RequiredExtent> {
        self.extents.values()
    }

    /// Whether R holds the decoded extent `key`.
    pub fn contains(&self, key: &ContentKey) -> bool {
        self.extents.contains_key(key)
    }

    /// Distinct decoded extents in R.
    pub fn len(&self) -> usize {
        self.extents.len()
    }

    /// Whether R is empty.
    pub fn is_empty(&self) -> bool {
        self.extents.is_empty()
    }

    /// The decoded bytes of R.
    pub fn decoded_bytes(&self) -> Result<u64, DifferentialError> {
        checked_sum(
            self.extents.values().map(|extent| extent.true_length_bytes),
            "required decoded bytes",
        )
    }

    /// The stored bytes the full loader reads for R.
    pub fn stored_bytes(&self) -> Result<u64, DifferentialError> {
        checked_sum(
            self.extents.values().map(|extent| extent.stored_bytes),
            "required stored bytes",
        )
    }
}

/// An advertisement that a decoded extent is resident: a hint with an expiry, not
/// authority (GPU §3.2). Equal bytes are not permission (S3.3), so it is usable only in
/// the consumer's own trust scope and on the consumer's device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResidentExtent {
    pub key: ContentKey,
    pub true_length_bytes: u64,
    pub scope: TrustScope,
    pub device: GpuDeviceKey,
    pub expires_at: MonotonicTime,
}

/// Who would reuse resident extents: a trust scope and the placement's device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Consumer {
    pub scope: TrustScope,
    pub device: GpuDeviceKey,
}

/// Why a resident extent with a required key is not in A.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResidentRejection {
    /// The advertisement had expired when the plan was made.
    Expired,
    /// The bytes live in another trust scope.
    OtherTrustScope,
    /// The bytes live on another device; reaching them is a transfer, not a reuse.
    OtherDevice,
    /// The advertised length contradicts the key, which binds the true length.
    LengthMismatch,
}

/// One element of A ∩ R with the resident copy that satisfied it. Materialization
/// reads exactly that copy and rechecks its expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReusedExtent {
    pub extent: RequiredExtent,
    /// The advertisement the plan accepted: its scope, device and expiry bind the reuse.
    pub resident: ResidentExtent,
}

/// R split into the compatible resident part (A ∩ R) and the part to load (R \ A).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DifferentialPlan {
    manifest: ManifestDigest,
    planned_at: MonotonicTime,
    reused: Vec<ReusedExtent>,
    missing: Vec<RequiredExtent>,
    rejections: Vec<(ContentKey, ResidentRejection)>,
}

impl DifferentialPlan {
    /// The target manifest this set or plan belongs to.
    pub fn manifest(&self) -> ManifestDigest {
        self.manifest
    }

    /// The clock reading resident expiries were judged at.
    pub fn planned_at(&self) -> MonotonicTime {
        self.planned_at
    }

    /// A ∩ R: required extents a compatible resident copy satisfies, each bound to it.
    pub fn reused(&self) -> &[ReusedExtent] {
        &self.reused
    }

    /// R \ A: required extents to load.
    pub fn missing(&self) -> &[RequiredExtent] {
        &self.missing
    }

    /// Resident advertisements with a required key that were not compatible.
    pub fn rejections(&self) -> &[(ContentKey, ResidentRejection)] {
        &self.rejections
    }

    /// Decoded bytes of A ∩ R.
    pub fn reused_decoded_bytes(&self) -> Result<u64, DifferentialError> {
        checked_sum(
            self.reused
                .iter()
                .map(|reused| reused.extent.true_length_bytes),
            "reused decoded bytes",
        )
    }

    /// Stored bytes the reuse saves reading.
    pub fn reused_stored_bytes(&self) -> Result<u64, DifferentialError> {
        checked_sum(
            self.reused.iter().map(|reused| reused.extent.stored_bytes),
            "reused stored bytes",
        )
    }

    /// Stored bytes of R \ A, the only bytes loaded.
    pub fn missing_stored_bytes(&self) -> Result<u64, DifferentialError> {
        checked_sum(
            self.missing.iter().map(|extent| extent.stored_bytes),
            "missing stored bytes",
        )
    }

    /// Decoded bytes of R \ A.
    pub fn missing_decoded_bytes(&self) -> Result<u64, DifferentialError> {
        checked_sum(
            self.missing.iter().map(|extent| extent.true_length_bytes),
            "missing decoded bytes",
        )
    }

    /// What the full loader would read: every element of R.
    pub fn required_stored_bytes(&self) -> Result<u64, DifferentialError> {
        checked_sum(
            [self.reused_stored_bytes()?, self.missing_stored_bytes()?],
            "required stored bytes",
        )
    }
}

fn rejection(
    resident: &ResidentExtent,
    required: &RequiredExtent,
    consumer: &Consumer,
    now: MonotonicTime,
) -> Option<ResidentRejection> {
    if resident.expires_at <= now {
        Some(ResidentRejection::Expired)
    } else if resident.scope != consumer.scope {
        Some(ResidentRejection::OtherTrustScope)
    } else if resident.device != consumer.device {
        Some(ResidentRejection::OtherDevice)
    } else if resident.true_length_bytes != required.true_length_bytes {
        Some(ResidentRejection::LengthMismatch)
    } else {
        None
    }
}

/// Splits R into A ∩ R and R \ A at `clock.now()` (GPU §4.2: "Load only R minus A").
/// Of several compatible copies of one extent, the one that expires last is bound.
pub fn plan(
    required: &RequiredSet,
    residents: &[ResidentExtent],
    consumer: &Consumer,
    clock: &dyn Clock,
) -> DifferentialPlan {
    let now = clock.now();
    let mut reused = Vec::new();
    let mut missing = Vec::new();
    let mut rejections = Vec::new();
    for extent in required.extents() {
        let mut bound: Option<ResidentExtent> = None;
        let mut refused = Vec::new();
        for resident in residents
            .iter()
            .filter(|resident| resident.key == extent.key)
        {
            match rejection(resident, extent, consumer, now) {
                None => {
                    if bound.is_none_or(|current| resident.expires_at > current.expires_at) {
                        bound = Some(*resident);
                    }
                }
                Some(reason) => refused.push((extent.key, reason)),
            }
        }
        if let Some(resident) = bound {
            reused.push(ReusedExtent {
                extent: *extent,
                resident,
            });
        } else {
            missing.push(*extent);
            rejections.extend(refused);
        }
    }
    DifferentialPlan {
        manifest: required.manifest(),
        planned_at: now,
        reused,
        missing,
        rejections,
    }
}

/// Reads the stored bytes of a target manifest's extents.
pub trait StoredExtents {
    /// The stored bytes of extent `extent_index` (encoded bytes when it is encoded).
    fn stored(&self, extent_index: usize) -> Option<Vec<u8>>;
    fn dictionary(&self, dictionary: &DictionaryId) -> Option<Vec<u8>>;
}

/// Bytes a resident port read, with the scope and device it read them from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResidentRead {
    pub scope: TrustScope,
    pub device: GpuDeviceKey,
    pub bytes: Vec<u8>,
}

/// Reads resident decoded bytes for verification before reuse.
pub trait ResidentBytes {
    /// Reads exactly the copy `resident` names; `None` when that copy is gone. A copy of
    /// the same key in another scope or on another device is not that copy.
    fn resident(&self, resident: &ResidentExtent) -> Option<ResidentRead>;
}

/// The verified decoded extents of R and what producing them cost.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Materialized {
    manifest: ManifestDigest,
    extents: BTreeMap<ContentKey, Vec<u8>>,
    /// Stored bytes read from the source.
    pub transferred_stored_bytes: u64,
    /// Decoded bytes reused from resident copies.
    pub reused_decoded_bytes: u64,
    /// Decoded bytes hashed against the target manifest, loaded and reused alike.
    pub verified_decoded_bytes: u64,
}

impl Materialized {
    /// The verified decoded bytes of `key`.
    pub fn extent(&self, key: &ContentKey) -> Option<&[u8]> {
        self.extents.get(key).map(Vec::as_slice)
    }

    /// Verified decoded extents held.
    pub fn extent_count(&self) -> usize {
        self.extents.len()
    }

    /// Reassembles tensor `name` from its verified extents.
    pub fn tensor_bytes(
        &self,
        manifest: &ValidatedManifest,
        name: &str,
    ) -> Result<Vec<u8>, DifferentialError> {
        if manifest.digest() != self.manifest {
            return Err(DifferentialError::PlanForAnotherManifest);
        }
        let tensor = manifest
            .tensor(name)
            .ok_or_else(|| DifferentialError::UnknownTensor {
                name: name.to_string(),
            })?;
        let all = &manifest.manifest().extents.extents;
        let start = tensor.offset_bytes;
        let end =
            start
                .checked_add(tensor.true_length_bytes)
                .ok_or(DifferentialError::Overflow {
                    field: "tensor range",
                })?;
        let mut bytes = Vec::new();
        for extent_index in
            manifest.extents_covering(tensor.file, tensor.offset_bytes, tensor.true_length_bytes)
        {
            let extent = all
                .get(extent_index)
                .ok_or(DifferentialError::NoSuchExtent { extent_index })?;
            let decoded =
                self.extent(&extent.content_key)
                    .ok_or(DifferentialError::ResidentUnavailable {
                        key: extent.content_key,
                    })?;
            let extent_start = extent.logical_offset_bytes;
            let from = start.max(extent_start).saturating_sub(extent_start);
            let to = end
                .min(extent_start.saturating_add(extent.true_length_bytes))
                .saturating_sub(extent_start);
            let piece = usize::try_from(from)
                .ok()
                .zip(usize::try_from(to).ok())
                .and_then(|(from, to)| decoded.get(from..to))
                .ok_or_else(|| DifferentialError::TensorOutOfFile {
                    name: name.to_string(),
                })?;
            bytes.extend_from_slice(piece);
        }
        if bytes.len() as u64 != tensor.true_length_bytes {
            return Err(DifferentialError::TensorOutOfFile {
                name: name.to_string(),
            });
        }
        Ok(bytes)
    }
}

fn load_verified(
    manifest: &ValidatedManifest,
    extent: &RequiredExtent,
    stored: &dyn StoredExtents,
    decoders: &[&dyn ExtentDecoder],
) -> Result<Vec<u8>, DifferentialError> {
    let extent_index = extent.extent_index;
    let entry = manifest
        .manifest()
        .extents
        .extents
        .get(extent_index)
        .ok_or(DifferentialError::NoSuchExtent { extent_index })?;
    let dictionary = match &entry.encoding {
        ExtentEncoding::Encoded(encoded) => match &encoded.dictionary {
            Some(id) => Some(
                stored
                    .dictionary(id)
                    .ok_or(DifferentialError::DictionaryUnavailable { extent_index })?,
            ),
            None => None,
        },
        ExtentEncoding::Raw => None,
    };
    let bytes = stored
        .stored(extent_index)
        .ok_or(DifferentialError::StoredUnavailable { extent_index })?;
    manifest
        .verify_extent(extent_index, &bytes, dictionary.as_deref(), decoders)
        .map_err(|error| DifferentialError::Verification {
            extent_index,
            error,
        })
}

/// Loads exactly R \ A and verifies every element of R against the target manifest:
/// loaded extents through [`ValidatedManifest::verify_extent`], reused ones by rehashing
/// the bytes of the bound resident copy. Before anything is read, every bound copy must
/// still be unexpired at `clock.now()`. A reuse is a scope and device rule as well as a
/// content rule, so bytes served from another copy are refused. Every refusal asks the
/// caller to replan; nothing is silently loaded instead, because the loader choice was
/// made on the plan.
pub fn materialize(
    manifest: &ValidatedManifest,
    plan: &DifferentialPlan,
    stored: &dyn StoredExtents,
    resident: &dyn ResidentBytes,
    decoders: &[&dyn ExtentDecoder],
    clock: &dyn Clock,
) -> Result<Materialized, DifferentialError> {
    if manifest.digest() != plan.manifest() {
        return Err(DifferentialError::PlanForAnotherManifest);
    }
    let now = clock.now();
    if let Some(expired) = plan
        .reused()
        .iter()
        .find(|reused| reused.resident.expires_at <= now)
    {
        return Err(DifferentialError::ResidentExpired {
            key: expired.extent.key,
            expired_at: expired.resident.expires_at,
        });
    }
    let mut extents = BTreeMap::new();
    let mut transferred_stored_bytes = 0u64;
    let mut reused_decoded_bytes = 0u64;
    let mut verified_decoded_bytes = 0u64;
    let add = |total: u64, value: u64, field| {
        total
            .checked_add(value)
            .ok_or(DifferentialError::Overflow { field })
    };
    for reused in plan.reused() {
        let extent = &reused.extent;
        let read = resident
            .resident(&reused.resident)
            .ok_or(DifferentialError::ResidentUnavailable { key: extent.key })?;
        if read.scope != reused.resident.scope || read.device != reused.resident.device {
            return Err(DifferentialError::ResidentOutsideBinding { key: extent.key });
        }
        let bytes = read.bytes;
        if bytes.len() as u64 != extent.true_length_bytes || ContentKey::of(&bytes) != extent.key {
            return Err(DifferentialError::ResidentMismatch { key: extent.key });
        }
        reused_decoded_bytes = add(reused_decoded_bytes, extent.true_length_bytes, "reused")?;
        verified_decoded_bytes = add(verified_decoded_bytes, extent.true_length_bytes, "verified")?;
        extents.insert(extent.key, bytes);
    }
    for extent in plan.missing() {
        let bytes = load_verified(manifest, extent, stored, decoders)?;
        transferred_stored_bytes = add(transferred_stored_bytes, extent.stored_bytes, "loaded")?;
        verified_decoded_bytes = add(verified_decoded_bytes, extent.true_length_bytes, "verified")?;
        extents.insert(extent.key, bytes);
    }
    Ok(Materialized {
        manifest: manifest.digest(),
        extents,
        transferred_stored_bytes,
        reused_decoded_bytes,
        verified_decoded_bytes,
    })
}

/// The baseline: loads and verifies every element of R, ignoring resident copies.
pub fn full_load(
    manifest: &ValidatedManifest,
    required: &RequiredSet,
    stored: &dyn StoredExtents,
    decoders: &[&dyn ExtentDecoder],
) -> Result<Materialized, DifferentialError> {
    if manifest.digest() != required.manifest() {
        return Err(DifferentialError::PlanForAnotherManifest);
    }
    let mut extents = BTreeMap::new();
    let mut transferred_stored_bytes = 0u64;
    let mut verified_decoded_bytes = 0u64;
    for extent in required.extents() {
        let bytes = load_verified(manifest, extent, stored, decoders)?;
        transferred_stored_bytes = transferred_stored_bytes
            .checked_add(extent.stored_bytes)
            .ok_or(DifferentialError::Overflow { field: "loaded" })?;
        verified_decoded_bytes = verified_decoded_bytes
            .checked_add(extent.true_length_bytes)
            .ok_or(DifferentialError::Overflow { field: "verified" })?;
        extents.insert(extent.key, bytes);
    }
    Ok(Materialized {
        manifest: manifest.digest(),
        extents,
        transferred_stored_bytes,
        reused_decoded_bytes: 0,
        verified_decoded_bytes,
    })
}

/// The extra work the differential path does before it saves anything: indexing (such
/// as building the target's extent index from its source files) and hashing beyond the
/// verification both paths perform on loaded bytes.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct IndexHashCost {
    pub index_seconds: f64,
    pub hashed_bytes: u64,
    pub hash_bytes_per_second: f64,
}

impl IndexHashCost {
    /// `index_seconds + hashed_bytes / hash_bytes_per_second`.
    pub fn seconds(&self) -> Result<f64, DifferentialError> {
        let index = non_negative("index_seconds", self.index_seconds)?;
        let rate = positive("hash_bytes_per_second", self.hash_bytes_per_second)?;
        Ok(index + self.hashed_bytes as f64 / rate)
    }
}

/// Which loader a switch uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoaderChoice {
    Differential,
    FullLoader,
}

/// The full-loader cutoff with its terms (GPU §4.2: "Use the full loader when
/// indexing/hash cost exceeds saved transfer").
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LoaderDecision {
    pub choice: LoaderChoice,
    /// Reused stored bytes over the link rate.
    pub saved_transfer_seconds: f64,
    pub index_hash_seconds: f64,
    /// Missing stored bytes over the link rate, plus indexing and hashing.
    pub differential_seconds: f64,
    /// Required stored bytes over the link rate.
    pub full_loader_seconds: f64,
}

/// Chooses the differential path only when the transfer it saves strictly exceeds its
/// indexing and hashing cost for this switch: [`ImportAmortization`] with one use and no
/// retention penalty. Equality keeps the full loader.
pub fn choose_loader(
    plan: &DifferentialPlan,
    link_bytes_per_second: f64,
    cost: &IndexHashCost,
) -> Result<LoaderDecision, DifferentialError> {
    let link = positive("link_bytes_per_second", link_bytes_per_second)?;
    let index_hash_seconds = cost.seconds()?;
    let saved_transfer_seconds = plan.reused_stored_bytes()? as f64 / link;
    let full_loader_seconds = plan.required_stored_bytes()? as f64 / link;
    let differential_seconds = plan.missing_stored_bytes()? as f64 / link + index_hash_seconds;
    let amortizes = ImportAmortization {
        expected_uses: 1.0,
        per_use_saving_seconds: saved_transfer_seconds,
        preparation_cost_seconds: index_hash_seconds,
        retention_penalty_seconds: 0.0,
    }
    .amortizes()?;
    Ok(LoaderDecision {
        choice: if amortizes {
            LoaderChoice::Differential
        } else {
            LoaderChoice::FullLoader
        },
        saved_transfer_seconds,
        index_hash_seconds,
        differential_seconds,
        full_loader_seconds,
    })
}

/// The digest domain of [`TensorIdentity`].
pub const TENSOR_IDENTITY_DOMAIN: &str = "yougori/model-memory/representation/tensor/v1";

/// A tensor's decoded identity: its interpretation (dtype, layout, shape) bound to the
/// content key of its exact bytes. Names play no part, so an unchanged tensor keeps its
/// identity under any name in any artifact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TensorIdentity(Digest);

fn dtype_tag(dtype: TensorDtype) -> String {
    match dtype {
        TensorDtype::Element(element) => format!("element:{}", element.safetensors_name()),
        TensorDtype::Ggml(ggml) => format!("ggml:{}", ggml.id()),
    }
}

fn layout_tag(layout: TensorLayout) -> &'static str {
    match layout {
        TensorLayout::RowMajor => "row-major",
        TensorLayout::GgmlInnermostFirst => "ggml-innermost-first",
    }
}

impl TensorIdentity {
    /// The identity of `entry` holding exactly `bytes`.
    pub fn of(entry: &TensorEntry, bytes: &[u8]) -> Self {
        let mut builder = DigestBuilder::new(TENSOR_IDENTITY_DOMAIN)
            .str(&dtype_tag(entry.dtype))
            .str(layout_tag(entry.layout))
            .u64(entry.shape.len() as u64);
        for dimension in &entry.shape {
            builder = builder.u64(*dimension);
        }
        Self(builder.digest(ContentKey::of(bytes).digest()).finish())
    }

    /// The identity as a digest.
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

/// Whole source files by path, for hashing tensors.
pub trait SourceBytes {
    fn file(&self, path: &RelativePath) -> Option<&[u8]>;
}

fn tensor_slice<'a>(
    manifest: &ValidatedManifest,
    files: &'a dyn SourceBytes,
    tensor: &TensorEntry,
) -> Result<&'a [u8], DifferentialError> {
    let file = manifest
        .manifest()
        .provenance
        .files
        .get(tensor.file.index())
        .ok_or_else(|| DifferentialError::TensorOutOfFile {
            name: tensor.name.to_string(),
        })?;
    let bytes = files
        .file(&file.path)
        .ok_or_else(|| DifferentialError::FileUnavailable {
            path: file.path.clone(),
        })?;
    let start = usize::try_from(tensor.offset_bytes).ok();
    let length = usize::try_from(tensor.true_length_bytes).ok();
    start
        .zip(length)
        .and_then(|(start, length)| bytes.get(start..start.checked_add(length)?))
        .ok_or_else(|| DifferentialError::TensorOutOfFile {
            name: tensor.name.to_string(),
        })
}

fn tensor_identities(
    manifest: &ValidatedManifest,
    files: &dyn SourceBytes,
) -> Result<Vec<(TensorIdentity, u64)>, DifferentialError> {
    manifest
        .manifest()
        .tensor_index
        .tensors
        .iter()
        .map(|tensor| {
            let bytes = tensor_slice(manifest, files, tensor)?;
            Ok((TensorIdentity::of(tensor, bytes), tensor.true_length_bytes))
        })
        .collect()
}

/// Sharing between a resident base and a target, measured at tensor granularity and at
/// the manifest's smaller extent granularity (GPU §4.2: "Measure sharing at tensor and
/// smaller-extent granularities").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SharingReport {
    pub base_tensors: usize,
    /// Base tensors whose identity appears unchanged in the target.
    pub base_tensors_kept: usize,
    pub target_tensors: usize,
    pub target_tensor_bytes: u64,
    /// Target tensors whose identity appears in the base.
    pub shared_tensors: usize,
    pub shared_tensor_bytes: u64,
    /// R of all target tensors, in decoded bytes.
    pub target_extent_bytes: u64,
    /// Elements of that R whose content key the base also has.
    pub shared_extent_bytes: u64,
    /// Tensor bytes hashed to measure tensor sharing, base and target together.
    pub hashed_bytes: u64,
}

/// Measures sharing by hashing every tensor of both artifacts and comparing extent keys.
pub fn measure_sharing(
    base: &ValidatedManifest,
    base_files: &dyn SourceBytes,
    target: &ValidatedManifest,
    target_files: &dyn SourceBytes,
) -> Result<SharingReport, DifferentialError> {
    let base_identities = tensor_identities(base, base_files)?;
    let target_identities = tensor_identities(target, target_files)?;
    let base_set: BTreeSet<TensorIdentity> = base_identities
        .iter()
        .map(|(identity, _)| *identity)
        .collect();
    let target_set: BTreeSet<TensorIdentity> = target_identities
        .iter()
        .map(|(identity, _)| *identity)
        .collect();
    let shared: Vec<u64> = target_identities
        .iter()
        .filter(|(identity, _)| base_set.contains(identity))
        .map(|(_, bytes)| *bytes)
        .collect();
    let base_extent_keys: BTreeSet<ContentKey> = base
        .manifest()
        .extents
        .extents
        .iter()
        .map(|extent| extent.content_key)
        .collect();
    let required = RequiredSet::for_all_tensors(target)?;
    let shared_extent_bytes = checked_sum(
        required
            .extents()
            .filter(|extent| base_extent_keys.contains(&extent.key))
            .map(|extent| extent.true_length_bytes),
        "shared extent bytes",
    )?;
    let base_tensor_bytes = checked_sum(
        base_identities.iter().map(|(_, bytes)| *bytes),
        "base tensor bytes",
    )?;
    let target_tensor_bytes = checked_sum(
        target_identities.iter().map(|(_, bytes)| *bytes),
        "target tensor bytes",
    )?;
    Ok(SharingReport {
        base_tensors: base_identities.len(),
        base_tensors_kept: base_identities
            .iter()
            .filter(|(identity, _)| target_set.contains(identity))
            .count(),
        target_tensors: target_identities.len(),
        target_tensor_bytes,
        shared_tensors: shared.len(),
        shared_tensor_bytes: checked_sum(shared, "shared tensor bytes")?,
        target_extent_bytes: required.decoded_bytes()?,
        shared_extent_bytes,
        hashed_bytes: checked_sum([base_tensor_bytes, target_tensor_bytes], "hashed bytes")?,
    })
}

/// How two artifacts relate, judged only from measured tensor identities (GPU §4.2: no
/// assumed sparse delta; names and declared lineage play no part).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FamilyRelation {
    /// Every tensor is identical.
    Identical,
    /// Every base tensor is kept unchanged and the target adds tensors, as an adapter
    /// over an unchanged base does.
    AdapterFamily,
    /// Some tensors are byte-identical, others changed.
    CheckpointFamily,
    /// No tensor is shared, as with a dense fine-tune that changed virtually every byte.
    Unrelated,
}

impl SharingReport {
    /// The family relation these measurements show (§4.2).
    pub fn relation(&self) -> FamilyRelation {
        if self.shared_tensors == 0 {
            FamilyRelation::Unrelated
        } else if self.base_tensors_kept == self.base_tensors
            && self.shared_tensors == self.target_tensors
            && self.base_tensors == self.target_tensors
        {
            FamilyRelation::Identical
        } else if self.base_tensors_kept == self.base_tensors
            && self.target_tensors > self.shared_tensors
        {
            FamilyRelation::AdapterFamily
        } else {
            FamilyRelation::CheckpointFamily
        }
    }
}
