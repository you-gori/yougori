//! Checks made before anything is reserved: the resolved manifest, the job's
//! dependencies, its destination, and every batch plan the batching port returns.

use std::collections::{BTreeMap, BTreeSet};

use super::error::{BatchPlanError, DependencyError, ManifestError, SubmitError};
use super::job::{DependencySpec, TransferRequest};
use super::model::{Destination, ManifestExtent, StoredForm};
use super::ports::{BatchLimits, BatchPlan, ExtentSpan, ResolvedManifest};

/// A job's dependencies, checked and ordered.
pub(super) struct JobShape {
    /// Extents in the order the dependencies first name them.
    pub(super) needed: Vec<ManifestExtent>,
    /// Dependencies with every prerequisite before its dependents.
    pub(super) ordered: Vec<DependencySpec>,
}

/// The manifest describes the requested artifact and stored object, its extents are
/// non-empty and inside the stored object, a raw extent's lengths agree, and extents
/// overlap neither stored nor decoded.
pub(super) fn check_manifest(
    request: &TransferRequest,
    manifest: &ResolvedManifest,
) -> Result<(), ManifestError> {
    if manifest.artifact != request.artifact {
        return Err(ManifestError::WrongArtifact {
            requested: request.artifact,
            resolved: manifest.artifact,
        });
    }
    if manifest.representation != request.representation {
        return Err(ManifestError::WrongRepresentation {
            requested: request.representation,
            resolved: manifest.representation,
        });
    }
    if manifest.extents.is_empty() {
        return Err(ManifestError::NoExtents);
    }
    let mut seen = BTreeSet::new();
    for extent in &manifest.extents {
        let index = extent.index;
        if !seen.insert(index) {
            return Err(ManifestError::DuplicateIndex { index });
        }
        if extent.stored_length_bytes == 0 || extent.decoded_length_bytes == 0 {
            return Err(ManifestError::EmptyExtent { index });
        }
        let stored_end = extent
            .stored_end_bytes()
            .ok_or(ManifestError::Overflow { index })?;
        extent
            .decoded_end_bytes()
            .ok_or(ManifestError::Overflow { index })?;
        if stored_end > manifest.object_length_bytes {
            return Err(ManifestError::StoredOutsideObject { index });
        }
        if extent.stored == StoredForm::Raw
            && extent.stored_length_bytes != extent.decoded_length_bytes
        {
            return Err(ManifestError::RawLengthMismatch { index });
        }
    }
    let mut by_stored: Vec<&ManifestExtent> = manifest.extents.iter().collect();
    by_stored.sort_by_key(|extent| extent.stored_offset_bytes);
    if let Some(index) = first_overlap(&by_stored, |extent| {
        (extent.stored_offset_bytes, extent.stored_end_bytes())
    }) {
        return Err(ManifestError::StoredOverlap { index });
    }
    let mut by_decoded: Vec<&ManifestExtent> = manifest.extents.iter().collect();
    by_decoded.sort_by_key(|extent| extent.decoded_offset_bytes);
    if let Some(index) = first_overlap(&by_decoded, |extent| {
        (extent.decoded_offset_bytes, extent.decoded_end_bytes())
    }) {
        return Err(ManifestError::DecodedOverlap { index });
    }
    Ok(())
}

/// The first extent, in sorted order, that starts before the previous one ends.
fn first_overlap(
    sorted: &[&ManifestExtent],
    range: impl Fn(&ManifestExtent) -> (u64, Option<u64>),
) -> Option<u64> {
    sorted.windows(2).find_map(|pair| {
        let [previous, next] = pair else {
            return None;
        };
        let (_, previous_end) = range(previous);
        let (start, _) = range(next);
        previous_end
            .is_none_or(|end| end > start)
            .then_some(next.index)
    })
}

/// Checks the dependencies against the manifest and orders them.
pub(super) fn shape_job(
    dependencies: &[DependencySpec],
    manifest: &ResolvedManifest,
) -> Result<JobShape, DependencyError> {
    if dependencies.is_empty() {
        return Err(DependencyError::NoDependencies);
    }
    let extents: BTreeMap<u64, ManifestExtent> = manifest
        .extents
        .iter()
        .map(|extent| (extent.index, *extent))
        .collect();
    let mut ids = BTreeSet::new();
    for dependency in dependencies {
        if !ids.insert(dependency.id) {
            return Err(DependencyError::DuplicateId { id: dependency.id });
        }
    }
    let mut needed = Vec::new();
    let mut named = BTreeSet::new();
    for dependency in dependencies {
        let id = dependency.id;
        if dependency.extents.is_empty() {
            return Err(DependencyError::Empty { id });
        }
        let mut own = BTreeSet::new();
        for &index in &dependency.extents {
            if !own.insert(index) {
                return Err(DependencyError::RepeatedExtent { id, index });
            }
            let extent = extents
                .get(&index)
                .ok_or(DependencyError::UnknownExtent { id, index })?;
            if named.insert(index) {
                needed.push(*extent);
            }
        }
        for &requires in &dependency.requires {
            if requires == id {
                return Err(DependencyError::Cycle { id });
            }
            if !ids.contains(&requires) {
                return Err(DependencyError::UnknownPrerequisite { id, requires });
            }
        }
    }
    let mut ordered: Vec<DependencySpec> = Vec::with_capacity(dependencies.len());
    let mut placed = BTreeSet::new();
    let mut remaining: Vec<&DependencySpec> = dependencies.iter().collect();
    while !remaining.is_empty() {
        let before = remaining.len();
        let mut index = 0;
        while let Some(dependency) = remaining.get(index) {
            if dependency
                .requires
                .iter()
                .all(|requires| placed.contains(requires))
            {
                placed.insert(dependency.id);
                ordered.push((*dependency).clone());
                remaining.remove(index);
            } else {
                index += 1;
            }
        }
        if remaining.len() == before {
            if let Some(dependency) = remaining.first() {
                return Err(DependencyError::Cycle { id: dependency.id });
            }
        }
    }
    Ok(JobShape { needed, ordered })
}

/// Every needed extent lands inside the job's destination.
pub(super) fn check_destination(
    destination: &Destination,
    needed: &[ManifestExtent],
) -> Result<(), SubmitError> {
    for extent in needed {
        let index = extent.index;
        let inside = extent
            .decoded_end_bytes()
            .is_some_and(|end| end <= destination.capacity_bytes)
            && destination
                .base_offset_bytes
                .checked_add(destination.capacity_bytes)
                .is_some();
        if !inside {
            return Err(SubmitError::DestinationOutOfBounds { index });
        }
    }
    Ok(())
}

/// `value` rounded down to a multiple of `alignment`, a power of two.
pub(super) fn align_down(value: u64, alignment: u64) -> u64 {
    value & !(alignment - 1)
}

/// `value` rounded up to a multiple of `alignment`, a power of two; `None` on overflow.
pub(super) fn align_up(value: u64, alignment: u64) -> Option<u64> {
    value
        .checked_add(alignment - 1)
        .map(|value| value & !(alignment - 1))
}

/// The aligned range covering `[offset, offset + length)`, as (offset, length).
pub(super) fn aligned_cover(offset: u64, length: u64, alignment: u64) -> Option<(u64, u64)> {
    let start = align_down(offset, alignment);
    let end = align_up(offset.checked_add(length)?, alignment)?;
    Some((start, end - start))
}

/// Checks batch plans against the spans offered: each span in exactly one batch;
/// members adjacent and in offset order; the read range exactly the members' range
/// rounded out to the alignment (the canonical padding rule); and the batch within one
/// staging slot, with its encoded members' decoded bytes within one decode slot.
pub(super) fn check_batch_plans(
    plans: &[BatchPlan],
    spans: &[ExtentSpan],
    limits: &BatchLimits,
) -> Result<(), BatchPlanError> {
    let by_index: BTreeMap<u64, &ExtentSpan> =
        spans.iter().map(|span| (span.index, span)).collect();
    let mut covered = BTreeSet::new();
    for plan in plans {
        let mut previous: Option<&ExtentSpan> = None;
        let mut first: Option<&ExtentSpan> = None;
        let mut decoded_bytes: u64 = 0;
        for &index in &plan.members {
            let span = by_index
                .get(&index)
                .copied()
                .ok_or(BatchPlanError::UnknownExtent { index })?;
            if !covered.insert(index) {
                return Err(BatchPlanError::RepeatedExtent { index });
            }
            if let Some(previous) = previous {
                if previous.offset_bytes.checked_add(previous.length_bytes)
                    != Some(span.offset_bytes)
                {
                    return Err(BatchPlanError::NotAdjacent { index });
                }
            }
            decoded_bytes = decoded_bytes.checked_add(span.decode_bytes).ok_or(
                BatchPlanError::DecodedTooLarge {
                    decoded_bytes: u64::MAX,
                    limit_bytes: limits.max_decoded_bytes,
                },
            )?;
            first.get_or_insert(span);
            previous = Some(span);
        }
        let (Some(first), Some(last)) = (first, previous) else {
            return Err(BatchPlanError::Empty);
        };
        let members_length = last
            .offset_bytes
            .checked_add(last.length_bytes)
            .map(|end| end - first.offset_bytes);
        let expected = members_length
            .and_then(|length| aligned_cover(first.offset_bytes, length, limits.alignment_bytes));
        let Some((expected_offset_bytes, expected_length_bytes)) = expected else {
            return Err(BatchPlanError::TooLarge {
                read_length_bytes: plan.read_length_bytes,
                limit_bytes: limits.max_read_bytes,
            });
        };
        if plan.read_offset_bytes != expected_offset_bytes
            || plan.read_length_bytes != expected_length_bytes
        {
            return Err(BatchPlanError::NotCanonical {
                read_offset_bytes: plan.read_offset_bytes,
                read_length_bytes: plan.read_length_bytes,
                expected_offset_bytes,
                expected_length_bytes,
            });
        }
        if plan.read_length_bytes > limits.max_read_bytes {
            return Err(BatchPlanError::TooLarge {
                read_length_bytes: plan.read_length_bytes,
                limit_bytes: limits.max_read_bytes,
            });
        }
        if decoded_bytes > limits.max_decoded_bytes {
            return Err(BatchPlanError::DecodedTooLarge {
                decoded_bytes,
                limit_bytes: limits.max_decoded_bytes,
            });
        }
    }
    if let Some(span) = spans.iter().find(|span| !covered.contains(&span.index)) {
        return Err(BatchPlanError::Uncovered { index: span.index });
    }
    Ok(())
}
