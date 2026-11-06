//! The four independent granularities of GPU §2.4, which replace fixed 2 MiB pages for
//! hashing, transport, compression and GPU mapping (§1.1): integrity extents g_h,
//! independently decodable codec blocks g_c, GPU mapping units g_v and transport batches
//! g_t. All four are recorded. The benchmark ranges are candidates, not format
//! constants, g_v exists only as a driver report for given allocation properties, and
//! padding follows one canonical rule.

use serde::Serialize;

use crate::foundation::ids::{Digest, DigestBuilder};

use super::GranularityError;

/// One kibibyte, in bytes.
pub const KIB: u64 = 1024;
/// One mebibyte, in bytes.
pub const MIB: u64 = 1024 * KIB;

/// A benchmark candidate range (GPU §2.4). It says what to measure, not what a format
/// allows: a layout may record any positive size, inside the range or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRange {
    min_bytes: u64,
    max_bytes: u64,
}

impl CandidateRange {
    /// Hash extents: 256 KiB–4 MiB.
    pub const INTEGRITY_EXTENT: Self = Self {
        min_bytes: 256 * KIB,
        max_bytes: 4 * MIB,
    };
    /// Codec blocks: 32–256 KiB.
    pub const CODEC_BLOCK: Self = Self {
        min_bytes: 32 * KIB,
        max_bytes: 256 * KIB,
    };
    /// Transport batches: 1–64 MiB.
    pub const TRANSPORT_BATCH: Self = Self {
        min_bytes: MIB,
        max_bytes: 64 * MIB,
    };

    /// The smallest candidate, in bytes.
    pub const fn min_bytes(&self) -> u64 {
        self.min_bytes
    }

    /// The largest candidate, in bytes.
    pub const fn max_bytes(&self) -> u64 {
        self.max_bytes
    }

    /// Whether `bytes` lies in the range, ends included.
    pub const fn contains(&self, bytes: u64) -> bool {
        self.min_bytes <= bytes && bytes <= self.max_bytes
    }

    /// The powers of two in the range: a small discrete set to benchmark (§2.5).
    pub fn powers_of_two(&self) -> Vec<u64> {
        (0..u64::BITS)
            .map(|shift| 1u64 << shift)
            .filter(|&bytes| self.contains(bytes))
            .collect()
    }
}

/// g_v as the driver reported it for one set of allocation properties (GPU §2.4: "obtain
/// g_v from the driver for the allocation properties"). There is no default or constant
/// mapping unit; a driver report is the only way to obtain one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct MappingUnitReport {
    allocation_properties: Digest,
    granularity_bytes: u64,
}

impl MappingUnitReport {
    /// What the driver returned for the allocation properties with this digest.
    pub fn from_driver(
        allocation_properties: Digest,
        granularity_bytes: u64,
    ) -> Result<Self, GranularityError> {
        if granularity_bytes == 0 {
            return Err(GranularityError::Zero {
                field: "mapping unit",
            });
        }
        Ok(Self {
            allocation_properties,
            granularity_bytes,
        })
    }

    /// The digest of the allocation properties the driver was asked about.
    pub const fn allocation_properties(&self) -> &Digest {
        &self.allocation_properties
    }

    /// g_v, in bytes.
    pub const fn granularity_bytes(&self) -> u64 {
        self.granularity_bytes
    }
}

/// The four granularities, recorded together (GPU §2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Granularities {
    integrity_extent_bytes: u64,
    codec_block_bytes: u64,
    mapping_unit: MappingUnitReport,
    transport_batch_bytes: u64,
}

impl Granularities {
    /// g_h, g_c (decoded bytes per independently decodable block), the driver's g_v
    /// report and g_t. Each must be more than zero; none needs to lie in its candidate
    /// range.
    pub fn new(
        integrity_extent_bytes: u64,
        codec_block_bytes: u64,
        mapping_unit: MappingUnitReport,
        transport_batch_bytes: u64,
    ) -> Result<Self, GranularityError> {
        for (field, value) in [
            ("integrity extent", integrity_extent_bytes),
            ("codec block", codec_block_bytes),
            ("transport batch", transport_batch_bytes),
        ] {
            if value == 0 {
                return Err(GranularityError::Zero { field });
            }
        }
        Ok(Self {
            integrity_extent_bytes,
            codec_block_bytes,
            mapping_unit,
            transport_batch_bytes,
        })
    }

    /// g_h.
    pub const fn integrity_extent_bytes(&self) -> u64 {
        self.integrity_extent_bytes
    }

    /// g_c, in decoded bytes.
    pub const fn codec_block_bytes(&self) -> u64 {
        self.codec_block_bytes
    }

    /// The driver report g_v comes from.
    pub const fn mapping_unit(&self) -> &MappingUnitReport {
        &self.mapping_unit
    }

    /// g_v.
    pub const fn mapping_unit_bytes(&self) -> u64 {
        self.mapping_unit.granularity_bytes
    }

    /// g_t.
    pub const fn transport_batch_bytes(&self) -> u64 {
        self.transport_batch_bytes
    }

    /// Whether g_h, g_c and g_t lie in their benchmark candidate ranges. g_v has no
    /// range: it is whatever the driver reports.
    pub const fn within_candidate_ranges(&self) -> bool {
        CandidateRange::INTEGRITY_EXTENT.contains(self.integrity_extent_bytes)
            && CandidateRange::CODEC_BLOCK.contains(self.codec_block_bytes)
            && CandidateRange::TRANSPORT_BATCH.contains(self.transport_batch_bytes)
    }

    /// A digest binding all four granularities and the allocation properties g_v was
    /// reported for.
    pub fn record_digest(&self) -> Digest {
        DigestBuilder::new("yougori/model-memory/granularities/v1")
            .u64(self.integrity_extent_bytes)
            .u64(self.codec_block_bytes)
            .digest(&self.mapping_unit.allocation_properties)
            .u64(self.mapping_unit.granularity_bytes)
            .u64(self.transport_batch_bytes)
            .finish()
    }
}

pub(crate) fn length_of(bytes: &[u8]) -> Result<u64, GranularityError> {
    u64::try_from(bytes.len()).map_err(|_| GranularityError::Overflow { field: "length" })
}

pub(crate) fn index(value: u64) -> Result<usize, GranularityError> {
    usize::try_from(value).map_err(|_| GranularityError::Overflow { field: "offset" })
}

/// The canonical padded length (GPU §2.4): the true length rounded up to the next
/// multiple of `unit_bytes`, so padding is always fewer than one unit.
pub fn padded_length_bytes(
    true_length_bytes: u64,
    unit_bytes: u64,
) -> Result<u64, GranularityError> {
    if unit_bytes == 0 {
        return Err(GranularityError::Zero { field: "unit" });
    }
    true_length_bytes
        .div_ceil(unit_bytes)
        .checked_mul(unit_bytes)
        .ok_or(GranularityError::Overflow {
            field: "padded length",
        })
}

/// Applies the canonical padding rule (GPU §2.4): `data` keeps its true length and is
/// followed by zero bytes up to the next multiple of `unit_bytes`. Padding is never
/// hashed and never part of an identity; the true length is recorded beside it.
pub fn pad_canonically(data: &[u8], unit_bytes: u64) -> Result<Vec<u8>, GranularityError> {
    let padded = index(padded_length_bytes(length_of(data)?, unit_bytes)?)?;
    let mut out = Vec::with_capacity(padded);
    out.extend_from_slice(data);
    out.resize(padded, 0);
    Ok(out)
}

/// Recovers the true-length bytes, refusing any padding the canonical rule would not
/// have produced: a length other than the true length rounded up to the next unit, or a
/// non-zero padding byte.
pub fn strip_canonical_padding(
    padded: &[u8],
    true_length_bytes: u64,
    unit_bytes: u64,
) -> Result<&[u8], GranularityError> {
    if length_of(padded)? != padded_length_bytes(true_length_bytes, unit_bytes)? {
        return Err(GranularityError::NonCanonicalPadding {
            reason: "the padded length is not the true length rounded up to the next unit",
        });
    }
    let (data, padding) = padded.split_at(index(true_length_bytes)?);
    if padding.iter().any(|&byte| byte != 0) {
        return Err(GranularityError::NonCanonicalPadding {
            reason: "padding bytes must be zero",
        });
    }
    Ok(data)
}
