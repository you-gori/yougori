//! The gate of the later custom entropy-decoder branch (GPU §4.9 plan line 748, GPU-W08
//! "Add a custom GPU codec only if a specific measured gap remains").
//!
//! No custom decoder is built. Before any GPU implementation, its specification must
//! state bitstream length bounds, real per-lane offsets, endianness, incomplete blocks,
//! the maximum code length, checksums and every BF16 bit pattern.
//! [`check_specification`] refuses a specification with any gap, including the two
//! contradictions line 748 names: a five-bit bit-position field cannot locate arbitrary
//! variable-length lane streams without byte or word offsets, and a maximum 12-bit code
//! scheme must not depend on codes longer than 12 bits.

use crate::model_memory::manifest::GatedNonGoal;

/// The custom entropy decoder is a later research branch (line 748), gated on a
/// specification [`check_specification`] accepts and on a measured gap that the existing
/// codec leaves (GPU-W08).
pub const CUSTOM_ENTROPY_DECODER: GatedNonGoal = GatedNonGoal {
    name: "custom BF16 entropy decoder",
    clause: "GPU §4.9 (plan line 748); GPU-W08",
    gate: "a complete specification (check_specification) and a measured gap the existing \
           lossless codec leaves",
};

/// BF16 bit patterns: every one must be specified (line 748) and round-trip (GPU-T34).
pub const BF16_PATTERNS: u32 = 1 << 16;

/// Symbols of an 8-bit BF16 exponent alphabet.
pub const EXPONENT_SYMBOLS: usize = 256;

/// Byte order of the coded stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamByteOrder {
    LittleEndian,
    BigEndian,
}

/// How a block with fewer values than a full block is coded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IncompleteBlockRule {
    /// The final block carries its value count.
    ExplicitValueCount,
    /// The final block is padded with a declared value that the true length strips.
    PaddedToFullBlock,
}

/// How coded data is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChecksumRule {
    PerBlock,
    PerExtentContentKey,
}

/// Where each lane's variable-length stream starts: a byte (or word) offset field and a
/// bit-position field, widths in bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LaneOffsets {
    pub byte_offset_bits: u32,
    pub bit_position_bits: u32,
}

/// A proposed exponent-coder specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntropyCodeSpec {
    pub max_code_length_bits: u32,
    /// Code length per exponent symbol; zero means the symbol has no code and must be
    /// escaped.
    pub code_lengths: Vec<u32>,
    /// The length of the escape code that introduces a verbatim value, if any.
    pub escape_code_length_bits: Option<u32>,
    /// Sign and mantissa bits kept verbatim per value.
    pub verbatim_bits_per_value: u32,
    /// Bits an escaped value carries after its escape code.
    pub escape_payload_bits: u32,
    pub values_per_block: u32,
    pub lanes: u32,
    pub lane_offsets: LaneOffsets,
    /// The declared bound on one block's coded length.
    pub max_block_bitstream_bytes: u64,
    pub byte_order: Option<StreamByteOrder>,
    pub incomplete_blocks: Option<IncompleteBlockRule>,
    pub checksum: Option<ChecksumRule>,
    /// BF16 patterns the CPU reference round-tripped bit-exactly.
    pub bf16_patterns_round_tripped: u32,
}

/// One gap or contradiction in a specification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SpecGap {
    NoByteOrder,
    NoIncompleteBlockRule,
    NoChecksum,
    NoCodes,
    WrongAlphabet {
        symbols: usize,
    },
    /// A code is longer than the declared maximum.
    CodeLongerThanMaximum {
        symbol: usize,
        length_bits: u32,
        max_bits: u32,
    },
    /// The escape code is longer than the declared maximum.
    EscapeLongerThanMaximum {
        length_bits: u32,
        max_bits: u32,
    },
    /// The code lengths do not form a prefix code: Kraft's sum exceeds 1.
    KraftViolated,
    /// An exponent has neither a code nor an escape.
    SymbolWithoutCode {
        symbol: usize,
    },
    /// An escape code of length zero.
    EmptyEscapeCode,
    NoLanes,
    /// The offset fields cannot address every bit position a lane stream may start at.
    LaneOffsetsCannotLocateStreams {
        addressable_bits: u64,
        stream_bits: u64,
    },
    /// The declared block bound is below the worst case the code allows.
    BitstreamBoundTooSmall {
        declared_bytes: u64,
        worst_case_bytes: u64,
    },
    Bf16PatternsNotCovered {
        round_tripped: u32,
    },
}

fn checked_pow2(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        1u64 << bits
    }
}

/// Every gap of `spec`; the gate opens only on an empty list.
pub fn check_specification(spec: &EntropyCodeSpec) -> Vec<SpecGap> {
    let mut gaps = Vec::new();
    if spec.byte_order.is_none() {
        gaps.push(SpecGap::NoByteOrder);
    }
    if spec.incomplete_blocks.is_none() {
        gaps.push(SpecGap::NoIncompleteBlockRule);
    }
    if spec.checksum.is_none() {
        gaps.push(SpecGap::NoChecksum);
    }
    if spec.code_lengths.len() != EXPONENT_SYMBOLS {
        gaps.push(SpecGap::WrongAlphabet {
            symbols: spec.code_lengths.len(),
        });
    }
    if spec.code_lengths.iter().all(|length| *length == 0) {
        gaps.push(SpecGap::NoCodes);
    }
    let max = spec.max_code_length_bits;
    for (symbol, length) in spec.code_lengths.iter().enumerate() {
        if *length > max {
            gaps.push(SpecGap::CodeLongerThanMaximum {
                symbol,
                length_bits: *length,
                max_bits: max,
            });
        }
    }
    let escape = spec.escape_code_length_bits;
    match escape {
        Some(0) => gaps.push(SpecGap::EmptyEscapeCode),
        Some(length) if length > max => gaps.push(SpecGap::EscapeLongerThanMaximum {
            length_bits: length,
            max_bits: max,
        }),
        _ => {}
    }
    // Kraft: the sum of 2^(L-l) over every code, the escape included, is at most 2^L,
    // with L the longest code.
    let lengths: Vec<u32> = spec
        .code_lengths
        .iter()
        .copied()
        .chain(escape)
        .filter(|length| *length > 0)
        .collect();
    let longest = lengths.iter().copied().max().unwrap_or(0).min(120);
    let kraft = lengths.iter().fold(0u128, |total, length| {
        total.saturating_add(1u128 << longest.saturating_sub((*length).min(longest)))
    });
    if kraft > 1u128 << longest {
        gaps.push(SpecGap::KraftViolated);
    }
    let escape_coded = escape.is_some_and(|length| length > 0);
    if !escape_coded {
        for (symbol, length) in spec.code_lengths.iter().enumerate() {
            if *length == 0 {
                gaps.push(SpecGap::SymbolWithoutCode { symbol });
            }
        }
    }
    if spec.lanes == 0 {
        gaps.push(SpecGap::NoLanes);
    }
    // Worst case: every value takes the longest code, its verbatim bits and, when an
    // escape exists, an escape payload.
    let escape_bits = if escape_coded {
        spec.escape_payload_bits
    } else {
        0
    };
    let worst_bits_per_value = u64::from(max)
        .saturating_add(u64::from(spec.verbatim_bits_per_value))
        .saturating_add(u64::from(escape_bits));
    let worst_case_bits = worst_bits_per_value.saturating_mul(u64::from(spec.values_per_block));
    let worst_case_bytes = worst_case_bits.div_ceil(8);
    if spec.max_block_bitstream_bytes < worst_case_bytes {
        gaps.push(SpecGap::BitstreamBoundTooSmall {
            declared_bytes: spec.max_block_bitstream_bytes,
            worst_case_bytes,
        });
    }
    let stream_bits = spec.max_block_bitstream_bytes.saturating_mul(8);
    let offsets = spec.lane_offsets;
    let addressable_bits = if offsets.byte_offset_bits == 0 {
        checked_pow2(offsets.bit_position_bits)
    } else if offsets.bit_position_bits >= 3 {
        checked_pow2(offsets.byte_offset_bits).saturating_mul(8)
    } else {
        // Byte offsets without a full bit position locate only byte-aligned starts.
        0
    };
    if addressable_bits < stream_bits {
        gaps.push(SpecGap::LaneOffsetsCannotLocateStreams {
            addressable_bits,
            stream_bits,
        });
    }
    if spec.bf16_patterns_round_tripped != BF16_PATTERNS {
        gaps.push(SpecGap::Bf16PatternsNotCovered {
            round_tripped: spec.bf16_patterns_round_tripped,
        });
    }
    gaps
}
