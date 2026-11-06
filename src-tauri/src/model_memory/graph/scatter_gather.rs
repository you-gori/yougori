//! The scatter/gather map relating the four granularities of one artifact (GPU §2.4).
//!
//! Integrity extents (g_h) and transport batches (g_t) partition the encoded bytes. Codec
//! blocks (g_c) pair each encoded range with the decoded range it decodes to on its own.
//! GPU mapping units (g_v) partition the decoded bytes as placed in device memory. Final
//! extents, blocks and batches keep their true lengths; only mapping units are padded,
//! by the canonical rule.
//!
//! Each extent's identity is the [`ContentKey`] of exactly its true-length bytes, so it
//! never depends on padding, batching or position. A transport batch coalesces whole
//! adjacent extents up to g_t, so every extent keeps its identity and is verified on its
//! own, and a batch boundary is always a place to
//! cancel, switch source or start computing. An extent longer than g_t travels alone,
//! split at multiples of g_t within it.

use crate::foundation::ids::{ContentKey, Digest, DigestBuilder};

use super::granularity::{
    index, length_of, pad_canonically, padded_length_bytes, strip_canonical_padding, Granularities,
};
use super::GranularityError;

/// A half-open byte range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub offset_bytes: u64,
    pub length_bytes: u64,
}

impl ByteRange {
    /// The first offset after the range.
    pub const fn end_bytes(&self) -> u64 {
        self.offset_bytes.saturating_add(self.length_bytes)
    }
}

/// Part of one unit of another granularity: the unit's index, where the part starts
/// within it, and its length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Piece {
    pub unit: usize,
    pub offset_in_unit_bytes: u64,
    pub length_bytes: u64,
}

/// One integrity extent: its encoded range and the content identity of exactly those
/// bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IntegrityExtent {
    pub range: ByteRange,
    pub identity: ContentKey,
}

/// One independently decodable codec block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CodecBlock {
    pub encoded: ByteRange,
    pub decoded: ByteRange,
}

/// One transport batch: its encoded range and the extent parts it carries, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportBatch {
    pub range: ByteRange,
    pub extents: Vec<Piece>,
}

/// What the codec produced: the decoded length and the encoded length of each g_c block.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CodecLayout {
    decoded_length_bytes: u64,
    encoded_block_lengths_bytes: Vec<u64>,
}

impl CodecLayout {
    /// The decoded length and the encoded length of each g_c block, in order.
    pub fn new(decoded_length_bytes: u64, encoded_block_lengths_bytes: Vec<u64>) -> Self {
        Self {
            decoded_length_bytes,
            encoded_block_lengths_bytes,
        }
    }

    /// Stored without compression: every block encodes to its own decoded length.
    pub fn stored(
        decoded_length_bytes: u64,
        codec_block_bytes: u64,
    ) -> Result<Self, GranularityError> {
        if codec_block_bytes == 0 {
            return Err(GranularityError::Zero {
                field: "codec block",
            });
        }
        let mut lengths = Vec::new();
        let mut offset = 0u64;
        while offset < decoded_length_bytes {
            let length = codec_block_bytes.min(decoded_length_bytes - offset);
            lengths.push(length);
            offset += length;
        }
        Ok(Self::new(decoded_length_bytes, lengths))
    }
}

/// Where one encoded byte lies in each encoded-side granularity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EncodedLocation {
    pub extent: usize,
    pub offset_in_extent_bytes: u64,
    pub batch: usize,
    pub offset_in_batch_bytes: u64,
    pub codec_block: usize,
    pub offset_in_block_bytes: u64,
}

/// Where one decoded byte lies in its codec block and in GPU mapping units.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DecodedLocation {
    pub codec_block: usize,
    pub offset_in_block_bytes: u64,
    pub mapping_unit: usize,
    pub offset_in_unit_bytes: u64,
}

/// The scatter/gather map of one artifact (GPU §2.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScatterGatherMap {
    granularities: Granularities,
    encoded_length_bytes: u64,
    decoded_length_bytes: u64,
    padded_length_bytes: u64,
    extents: Vec<IntegrityExtent>,
    blocks: Vec<CodecBlock>,
    batches: Vec<TransportBatch>,
}

impl ScatterGatherMap {
    /// Maps `encoded`, whose codec output is `codec`, for an allocation with the given
    /// properties. g_v must have been reported for exactly those properties.
    pub fn build(
        granularities: Granularities,
        allocation_properties: &Digest,
        encoded: &[u8],
        codec: &CodecLayout,
    ) -> Result<Self, GranularityError> {
        let reported = *granularities.mapping_unit().allocation_properties();
        if reported != *allocation_properties {
            return Err(GranularityError::MappingUnitForOtherProperties {
                reported,
                requested: *allocation_properties,
            });
        }
        let decoded_length = codec.decoded_length_bytes;
        if decoded_length == 0 {
            return Err(GranularityError::EmptyArtifact);
        }
        let block_bytes = granularities.codec_block_bytes();
        let expected_blocks = decoded_length.div_ceil(block_bytes);
        let actual_blocks = codec.encoded_block_lengths_bytes.len();
        if u64::try_from(actual_blocks).ok() != Some(expected_blocks) {
            return Err(GranularityError::CodecBlockCount {
                expected: expected_blocks,
                actual: actual_blocks,
            });
        }
        let mut blocks = Vec::with_capacity(actual_blocks);
        let (mut encoded_offset, mut decoded_offset) = (0u64, 0u64);
        for (block, &length) in codec.encoded_block_lengths_bytes.iter().enumerate() {
            if length == 0 {
                return Err(GranularityError::EmptyEncodedBlock { block });
            }
            let decoded = block_bytes.min(decoded_length - decoded_offset);
            blocks.push(CodecBlock {
                encoded: ByteRange {
                    offset_bytes: encoded_offset,
                    length_bytes: length,
                },
                decoded: ByteRange {
                    offset_bytes: decoded_offset,
                    length_bytes: decoded,
                },
            });
            encoded_offset =
                encoded_offset
                    .checked_add(length)
                    .ok_or(GranularityError::Overflow {
                        field: "encoded length",
                    })?;
            decoded_offset += decoded;
        }
        let encoded_length = length_of(encoded)?;
        if encoded_length != encoded_offset {
            return Err(GranularityError::LengthMismatch {
                field: "encoded artifact",
                expected: encoded_offset,
                actual: encoded_length,
            });
        }

        let extent_bytes = granularities.integrity_extent_bytes();
        let mut extents = Vec::new();
        let mut offset = 0u64;
        while offset < encoded_length {
            let length = extent_bytes.min(encoded_length - offset);
            let bytes = &encoded[index(offset)?..index(offset + length)?];
            extents.push(IntegrityExtent {
                range: ByteRange {
                    offset_bytes: offset,
                    length_bytes: length,
                },
                identity: ContentKey::of(bytes),
            });
            offset += length;
        }
        let batches = coalesce(&extents, granularities.transport_batch_bytes());
        Ok(Self {
            padded_length_bytes: padded_length_bytes(
                decoded_length,
                granularities.mapping_unit_bytes(),
            )?,
            granularities,
            encoded_length_bytes: encoded_length,
            decoded_length_bytes: decoded_length,
            extents,
            blocks,
            batches,
        })
    }

    /// The four granularities the map was built with.
    pub fn granularities(&self) -> &Granularities {
        &self.granularities
    }

    /// The true encoded length.
    pub fn encoded_length_bytes(&self) -> u64 {
        self.encoded_length_bytes
    }

    /// The true decoded length; the padding after it is not part of the artifact.
    pub fn decoded_length_bytes(&self) -> u64 {
        self.decoded_length_bytes
    }

    /// The decoded length rounded up to whole mapping units by the canonical rule.
    pub fn padded_length_bytes(&self) -> u64 {
        self.padded_length_bytes
    }

    /// The integrity extents, in order; the last keeps its true length.
    pub fn extents(&self) -> &[IntegrityExtent] {
        &self.extents
    }

    /// The codec blocks, in order.
    pub fn codec_blocks(&self) -> &[CodecBlock] {
        &self.blocks
    }

    /// The transport batches, in order.
    pub fn batches(&self) -> &[TransportBatch] {
        &self.batches
    }

    /// Whole mapping units covering the padded length.
    pub fn mapping_unit_count(&self) -> u64 {
        self.padded_length_bytes / self.granularities.mapping_unit_bytes()
    }

    /// The extent parts to gather, in order, to obtain a codec block's encoded bytes.
    pub fn extent_pieces_for_codec_block(
        &self,
        block: usize,
    ) -> Result<Vec<Piece>, GranularityError> {
        let block = self.block(block)?;
        let ranges: Vec<ByteRange> = self.extents.iter().map(|extent| extent.range).collect();
        Ok(pieces(&ranges, block.encoded))
    }

    /// The batch parts that carry an extent, in order.
    pub fn batch_pieces_for_extent(&self, extent: usize) -> Result<Vec<Piece>, GranularityError> {
        let range = self
            .extents
            .get(extent)
            .ok_or(GranularityError::IndexOutOfRange {
                field: "extent",
                index: extent,
                count: self.extents.len(),
            })?
            .range;
        let ranges: Vec<ByteRange> = self.batches.iter().map(|batch| batch.range).collect();
        Ok(pieces(&ranges, range))
    }

    /// The mapping-unit parts a codec block's decoded bytes scatter to, in order.
    pub fn mapping_pieces_for_codec_block(
        &self,
        block: usize,
    ) -> Result<Vec<Piece>, GranularityError> {
        let decoded = self.block(block)?.decoded;
        let unit = self.granularities.mapping_unit_bytes();
        let mut out = Vec::new();
        let mut offset = decoded.offset_bytes;
        while offset < decoded.end_bytes() {
            let number = offset / unit;
            let unit_end = (number + 1).saturating_mul(unit);
            let end = unit_end.min(decoded.end_bytes());
            out.push(Piece {
                unit: index(number)?,
                offset_in_unit_bytes: offset - number * unit,
                length_bytes: end - offset,
            });
            offset = end;
        }
        Ok(out)
    }

    /// The extent, batch and codec block holding one encoded byte.
    pub fn locate_encoded(&self, offset_bytes: u64) -> Result<EncodedLocation, GranularityError> {
        if offset_bytes >= self.encoded_length_bytes {
            return Err(GranularityError::OffsetOutOfRange {
                offset: offset_bytes,
                length: self.encoded_length_bytes,
            });
        }
        let extent = self
            .extents
            .partition_point(|extent| extent.range.end_bytes() <= offset_bytes);
        let batch = self
            .batches
            .partition_point(|batch| batch.range.end_bytes() <= offset_bytes);
        let codec_block = self
            .blocks
            .partition_point(|block| block.encoded.end_bytes() <= offset_bytes);
        Ok(EncodedLocation {
            extent,
            offset_in_extent_bytes: offset_bytes - self.extents[extent].range.offset_bytes,
            batch,
            offset_in_batch_bytes: offset_bytes - self.batches[batch].range.offset_bytes,
            codec_block,
            offset_in_block_bytes: offset_bytes - self.blocks[codec_block].encoded.offset_bytes,
        })
    }

    /// The codec block and mapping unit holding one decoded byte.
    pub fn locate_decoded(&self, offset_bytes: u64) -> Result<DecodedLocation, GranularityError> {
        if offset_bytes >= self.decoded_length_bytes {
            return Err(GranularityError::OffsetOutOfRange {
                offset: offset_bytes,
                length: self.decoded_length_bytes,
            });
        }
        let codec_block = self
            .blocks
            .partition_point(|block| block.decoded.end_bytes() <= offset_bytes);
        let unit = self.granularities.mapping_unit_bytes();
        Ok(DecodedLocation {
            codec_block,
            offset_in_block_bytes: offset_bytes - self.blocks[codec_block].decoded.offset_bytes,
            mapping_unit: index(offset_bytes / unit)?,
            offset_in_unit_bytes: offset_bytes % unit,
        })
    }

    /// Scatters the encoded artifact into transport batches.
    pub fn scatter_batches(&self, encoded: &[u8]) -> Result<Vec<Vec<u8>>, GranularityError> {
        self.check_length("encoded artifact", self.encoded_length_bytes, encoded)?;
        self.batches
            .iter()
            .map(|batch| {
                let range = index(batch.range.offset_bytes)?..index(batch.range.end_bytes())?;
                Ok(encoded[range].to_vec())
            })
            .collect()
    }

    /// Gathers transport batches back into the encoded artifact, verifying every extent
    /// against its own identity and naming the first that fails.
    pub fn gather_batches(&self, batches: &[Vec<u8>]) -> Result<Vec<u8>, GranularityError> {
        if batches.len() != self.batches.len() {
            return Err(GranularityError::PieceCount {
                field: "transport batch",
                expected: self.batches.len(),
                actual: batches.len(),
            });
        }
        let mut encoded = Vec::with_capacity(index(self.encoded_length_bytes)?);
        for (number, (batch, bytes)) in self.batches.iter().zip(batches).enumerate() {
            let actual = length_of(bytes)?;
            if actual != batch.range.length_bytes {
                return Err(GranularityError::PieceLength {
                    field: "transport batch",
                    index: number,
                    expected: batch.range.length_bytes,
                    actual,
                });
            }
            encoded.extend_from_slice(bytes);
        }
        for (number, extent) in self.extents.iter().enumerate() {
            let range = index(extent.range.offset_bytes)?..index(extent.range.end_bytes())?;
            if ContentKey::of(&encoded[range]) != extent.identity {
                return Err(GranularityError::ExtentMismatch { extent: number });
            }
        }
        Ok(encoded)
    }

    /// Scatters the decoded artifact into whole mapping units, padding the last one by
    /// the canonical rule.
    pub fn scatter_mapping_units(&self, decoded: &[u8]) -> Result<Vec<Vec<u8>>, GranularityError> {
        self.check_length("decoded artifact", self.decoded_length_bytes, decoded)?;
        let padded = pad_canonically(decoded, self.granularities.mapping_unit_bytes())?;
        Ok(padded
            .chunks(index(self.granularities.mapping_unit_bytes())?)
            .map(<[u8]>::to_vec)
            .collect())
    }

    /// Gathers mapping units back into the true-length decoded artifact, refusing
    /// non-canonical padding.
    pub fn gather_mapping_units(&self, units: &[Vec<u8>]) -> Result<Vec<u8>, GranularityError> {
        let expected = index(self.mapping_unit_count())?;
        if units.len() != expected {
            return Err(GranularityError::PieceCount {
                field: "mapping unit",
                expected,
                actual: units.len(),
            });
        }
        let unit = self.granularities.mapping_unit_bytes();
        let mut padded = Vec::with_capacity(index(self.padded_length_bytes)?);
        for (number, bytes) in units.iter().enumerate() {
            let actual = length_of(bytes)?;
            if actual != unit {
                return Err(GranularityError::PieceLength {
                    field: "mapping unit",
                    index: number,
                    expected: unit,
                    actual,
                });
            }
            padded.extend_from_slice(bytes);
        }
        Ok(strip_canonical_padding(&padded, self.decoded_length_bytes, unit)?.to_vec())
    }

    /// A digest binding the four granularities, the true and padded lengths, every
    /// extent's range and identity, every codec block and every batch range.
    pub fn record_digest(&self) -> Digest {
        let mut builder = DigestBuilder::new("yougori/model-memory/scatter-gather/v1")
            .digest(&self.granularities.record_digest())
            .u64(self.encoded_length_bytes)
            .u64(self.decoded_length_bytes)
            .u64(self.padded_length_bytes)
            .u64(self.extents.len() as u64);
        for extent in &self.extents {
            builder = builder
                .u64(extent.range.offset_bytes)
                .u64(extent.range.length_bytes)
                .digest(extent.identity.digest());
        }
        builder = builder.u64(self.blocks.len() as u64);
        for block in &self.blocks {
            builder = builder
                .u64(block.encoded.offset_bytes)
                .u64(block.encoded.length_bytes)
                .u64(block.decoded.offset_bytes)
                .u64(block.decoded.length_bytes);
        }
        builder = builder.u64(self.batches.len() as u64);
        for batch in &self.batches {
            builder = builder
                .u64(batch.range.offset_bytes)
                .u64(batch.range.length_bytes);
        }
        builder.finish()
    }

    fn block(&self, block: usize) -> Result<&CodecBlock, GranularityError> {
        self.blocks
            .get(block)
            .ok_or(GranularityError::IndexOutOfRange {
                field: "codec block",
                index: block,
                count: self.blocks.len(),
            })
    }

    fn check_length(
        &self,
        field: &'static str,
        expected: u64,
        bytes: &[u8],
    ) -> Result<(), GranularityError> {
        let actual = length_of(bytes)?;
        if actual != expected {
            return Err(GranularityError::LengthMismatch {
                field,
                expected,
                actual,
            });
        }
        Ok(())
    }
}

/// Coalesces whole adjacent extents into batches of at most `batch_bytes`; an extent
/// longer than that travels alone, split at multiples of `batch_bytes` within it.
fn coalesce(extents: &[IntegrityExtent], batch_bytes: u64) -> Vec<TransportBatch> {
    let mut batches = Vec::new();
    let mut current: Option<TransportBatch> = None;
    for (number, extent) in extents.iter().enumerate() {
        let length = extent.range.length_bytes;
        if length > batch_bytes {
            batches.extend(current.take());
            let mut offset = 0u64;
            while offset < length {
                let part = batch_bytes.min(length - offset);
                batches.push(TransportBatch {
                    range: ByteRange {
                        offset_bytes: extent.range.offset_bytes + offset,
                        length_bytes: part,
                    },
                    extents: vec![Piece {
                        unit: number,
                        offset_in_unit_bytes: offset,
                        length_bytes: part,
                    }],
                });
                offset += part;
            }
            continue;
        }
        let whole = Piece {
            unit: number,
            offset_in_unit_bytes: 0,
            length_bytes: length,
        };
        match current.as_mut() {
            Some(batch) if batch.range.length_bytes.saturating_add(length) <= batch_bytes => {
                batch.range.length_bytes += length;
                batch.extents.push(whole);
            }
            _ => {
                batches.extend(current.take());
                current = Some(TransportBatch {
                    range: extent.range,
                    extents: vec![whole],
                });
            }
        }
    }
    batches.extend(current);
    batches
}

/// The parts of contiguous ascending `units` that cover `query`.
fn pieces(units: &[ByteRange], query: ByteRange) -> Vec<Piece> {
    let first = units.partition_point(|unit| unit.end_bytes() <= query.offset_bytes);
    units
        .iter()
        .enumerate()
        .skip(first)
        .take_while(|(_, unit)| unit.offset_bytes < query.end_bytes())
        .map(|(number, unit)| {
            let start = unit.offset_bytes.max(query.offset_bytes);
            let end = unit.end_bytes().min(query.end_bytes());
            Piece {
                unit: number,
                offset_in_unit_bytes: start - unit.offset_bytes,
                length_bytes: end - start,
            }
        })
        .collect()
}
