//! The custom entropy-decoder gate (§4.9 line 748): each obligation tried and refused.

use super::super::entropy::*;

/// A complete exponent coder: 128 exponents with 8-bit codes, 64 with 9-bit codes and
/// 64 escaped (Kraft sum 1/2 + 1/8 = 5/8, plus the escape's 1/16), 32 values per block in
/// 4 lanes, 16-bit byte offsets with 3-bit positions.
fn complete() -> EntropyCodeSpec {
    let mut code_lengths = vec![8u32; 128];
    code_lengths.extend(vec![9u32; 64]);
    code_lengths.extend(vec![0u32; 64]);
    EntropyCodeSpec {
        max_code_length_bits: 12,
        code_lengths,
        escape_code_length_bits: Some(4),
        verbatim_bits_per_value: 8,
        escape_payload_bits: 8,
        values_per_block: 32,
        lanes: 4,
        lane_offsets: LaneOffsets {
            byte_offset_bits: 16,
            bit_position_bits: 3,
        },
        max_block_bitstream_bytes: 128,
        byte_order: Some(StreamByteOrder::LittleEndian),
        incomplete_blocks: Some(IncompleteBlockRule::ExplicitValueCount),
        checksum: Some(ChecksumRule::PerBlock),
        bf16_patterns_round_tripped: BF16_PATTERNS,
    }
}

#[test]
fn a_complete_specification_passes_the_gate() {
    assert_eq!(check_specification(&complete()), Vec::new());
    assert_eq!(BF16_PATTERNS, 65_536);
    assert!(CUSTOM_ENTROPY_DECODER.clause.contains("line 748"));
}

#[test]
fn a_five_bit_bit_position_field_cannot_locate_lane_streams() {
    let spec = EntropyCodeSpec {
        lane_offsets: LaneOffsets {
            byte_offset_bits: 0,
            bit_position_bits: 5,
        },
        ..complete()
    };
    assert_eq!(
        check_specification(&spec),
        vec![SpecGap::LaneOffsetsCannotLocateStreams {
            addressable_bits: 32,
            stream_bits: 1024
        }]
    );
    // Byte offsets without a full bit position locate only byte-aligned starts.
    let spec = EntropyCodeSpec {
        lane_offsets: LaneOffsets {
            byte_offset_bits: 16,
            bit_position_bits: 2,
        },
        ..complete()
    };
    assert!(matches!(
        check_specification(&spec).as_slice(),
        [SpecGap::LaneOffsetsCannotLocateStreams { .. }]
    ));
}

#[test]
fn a_twelve_bit_maximum_cannot_rely_on_longer_codes() {
    let mut spec = complete();
    spec.code_lengths[0] = 13;
    let gaps = check_specification(&spec);
    assert!(gaps.contains(&SpecGap::CodeLongerThanMaximum {
        symbol: 0,
        length_bits: 13,
        max_bits: 12
    }));
    let spec = EntropyCodeSpec {
        escape_code_length_bits: Some(13),
        ..complete()
    };
    assert!(
        check_specification(&spec).contains(&SpecGap::EscapeLongerThanMaximum {
            length_bits: 13,
            max_bits: 12
        })
    );
}

#[test]
fn code_tables_must_be_prefix_codes_covering_every_exponent() {
    // Too many short codes: Kraft's sum exceeds one.
    let spec = EntropyCodeSpec {
        code_lengths: vec![7u32; 256],
        ..complete()
    };
    assert!(check_specification(&spec).contains(&SpecGap::KraftViolated));
    // Without an escape, uncoded exponents cannot be represented.
    let spec = EntropyCodeSpec {
        escape_code_length_bits: None,
        ..complete()
    };
    let gaps = check_specification(&spec);
    assert!(gaps.contains(&SpecGap::SymbolWithoutCode { symbol: 192 }));
    assert_eq!(
        gaps.iter()
            .filter(|gap| matches!(gap, SpecGap::SymbolWithoutCode { .. }))
            .count(),
        64
    );
    let spec = EntropyCodeSpec {
        escape_code_length_bits: Some(0),
        ..complete()
    };
    assert!(check_specification(&spec).contains(&SpecGap::EmptyEscapeCode));
    let spec = EntropyCodeSpec {
        code_lengths: vec![8; 255],
        ..complete()
    };
    assert!(check_specification(&spec).contains(&SpecGap::WrongAlphabet { symbols: 255 }));
    let spec = EntropyCodeSpec {
        code_lengths: vec![0; 256],
        ..complete()
    };
    assert!(check_specification(&spec).contains(&SpecGap::NoCodes));
}

#[test]
fn bounds_endianness_incomplete_blocks_checksums_and_bf16_coverage_are_required() {
    let spec = EntropyCodeSpec {
        byte_order: None,
        incomplete_blocks: None,
        checksum: None,
        lanes: 0,
        bf16_patterns_round_tripped: 65_535,
        ..complete()
    };
    let gaps = check_specification(&spec);
    for gap in [
        SpecGap::NoByteOrder,
        SpecGap::NoIncompleteBlockRule,
        SpecGap::NoChecksum,
        SpecGap::NoLanes,
        SpecGap::Bf16PatternsNotCovered {
            round_tripped: 65_535,
        },
    ] {
        assert!(gaps.contains(&gap), "{gap:?}");
    }
    // Worst case: 32 values x (12 + 8 + 8) bits = 112 bytes; a 100-byte bound is short.
    let spec = EntropyCodeSpec {
        max_block_bitstream_bytes: 100,
        ..complete()
    };
    assert!(
        check_specification(&spec).contains(&SpecGap::BitstreamBoundTooSmall {
            declared_bytes: 100,
            worst_case_bytes: 112
        })
    );
}
