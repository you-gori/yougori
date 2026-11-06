//! GPU §2.4 and §1.1: four independent granularities, all recorded; benchmark ranges are
//! candidates, not format constants; g_v comes from the driver for the allocation
//! properties; padding has one canonical rule and never touches an identity.

use crate::foundation::ids::{digest, ContentKey, Digest};

use super::super::granularity::{
    pad_canonically, padded_length_bytes, strip_canonical_padding, CandidateRange, Granularities,
    MappingUnitReport, KIB, MIB,
};
use super::super::scatter_gather::{CodecLayout, ScatterGatherMap};
use super::super::GranularityError;
use super::support::SeededRng;

fn properties(name: &str) -> Digest {
    digest(
        "yougori/test/graph/allocation-properties/v1",
        &[name.as_bytes()],
    )
}

fn report(bytes: u64) -> MappingUnitReport {
    MappingUnitReport::from_driver(properties("device0-pinned"), bytes).unwrap()
}

#[test]
fn the_benchmark_ranges_are_candidate_sets() {
    assert_eq!(
        CandidateRange::INTEGRITY_EXTENT.powers_of_two(),
        vec![256 * KIB, 512 * KIB, MIB, 2 * MIB, 4 * MIB]
    );
    assert_eq!(
        CandidateRange::CODEC_BLOCK.powers_of_two(),
        vec![32 * KIB, 64 * KIB, 128 * KIB, 256 * KIB]
    );
    assert_eq!(
        CandidateRange::TRANSPORT_BATCH.powers_of_two(),
        vec![MIB, 2 * MIB, 4 * MIB, 8 * MIB, 16 * MIB, 32 * MIB, 64 * MIB]
    );
    assert_eq!(
        (
            CandidateRange::TRANSPORT_BATCH.min_bytes(),
            CandidateRange::TRANSPORT_BATCH.max_bytes()
        ),
        (MIB, 64 * MIB)
    );
}

#[test]
fn sizes_outside_the_candidate_ranges_are_still_valid_formats() {
    let inside = Granularities::new(MIB, 64 * KIB, report(2 * MIB), 16 * MIB).unwrap();
    assert!(inside.within_candidate_ranges());
    let outside = Granularities::new(8 * MIB, MIB, report(2 * MIB), 128 * MIB).unwrap();
    assert!(!outside.within_candidate_ranges());
    assert_eq!(outside.integrity_extent_bytes(), 8 * MIB);
    for (h, c, t, field) in [
        (0, 1, 1, "integrity extent"),
        (1, 0, 1, "codec block"),
        (1, 1, 0, "transport batch"),
    ] {
        assert_eq!(
            Granularities::new(h, c, report(1), t).unwrap_err(),
            GranularityError::Zero { field }
        );
    }
}

#[test]
fn the_mapping_unit_comes_only_from_the_driver_for_the_mapped_properties() {
    assert_eq!(
        MappingUnitReport::from_driver(properties("device0-pinned"), 0).unwrap_err(),
        GranularityError::Zero {
            field: "mapping unit"
        }
    );
    let bytes = SeededRng::new(6).bytes(10_000);
    let codec = CodecLayout::stored(10_000, 700).unwrap();
    let map_with = |unit_bytes: u64| {
        let granularities = Granularities::new(1024, 700, report(unit_bytes), 3000).unwrap();
        ScatterGatherMap::build(granularities, &properties("device0-pinned"), &bytes, &codec)
    };
    let small = map_with(4096).unwrap();
    assert_eq!(
        (small.padded_length_bytes(), small.mapping_unit_count()),
        (12_288, 3)
    );
    let large = map_with(64 * KIB).unwrap();
    assert_eq!(
        (large.padded_length_bytes(), large.mapping_unit_count()),
        (64 * KIB, 1)
    );
    assert_eq!(small.extents(), large.extents());

    let granularities = Granularities::new(1024, 700, report(4096), 3000).unwrap();
    assert_eq!(
        ScatterGatherMap::build(
            granularities,
            &properties("device1-managed"),
            &bytes,
            &codec
        )
        .unwrap_err(),
        GranularityError::MappingUnitForOtherProperties {
            reported: properties("device0-pinned"),
            requested: properties("device1-managed"),
        }
    );
}

#[test]
fn all_four_granularities_are_recorded() {
    let base = Granularities::new(MIB, 64 * KIB, report(2 * MIB), 16 * MIB).unwrap();
    let json = serde_json::to_value(base).unwrap();
    assert_eq!(json["integrity_extent_bytes"], MIB);
    assert_eq!(json["codec_block_bytes"], 64 * KIB);
    assert_eq!(json["mapping_unit"]["granularity_bytes"], 2 * MIB);
    assert_eq!(
        json["mapping_unit"]["allocation_properties"],
        properties("device0-pinned").to_hex()
    );
    assert_eq!(json["transport_batch_bytes"], 16 * MIB);

    let variants = [
        Granularities::new(2 * MIB, 64 * KIB, report(2 * MIB), 16 * MIB).unwrap(),
        Granularities::new(MIB, 128 * KIB, report(2 * MIB), 16 * MIB).unwrap(),
        Granularities::new(MIB, 64 * KIB, report(64 * KIB), 16 * MIB).unwrap(),
        Granularities::new(MIB, 64 * KIB, report(2 * MIB), 32 * MIB).unwrap(),
        Granularities::new(
            MIB,
            64 * KIB,
            MappingUnitReport::from_driver(properties("device1"), 2 * MIB).unwrap(),
            16 * MIB,
        )
        .unwrap(),
    ];
    for variant in variants {
        assert_ne!(variant.record_digest(), base.record_digest(), "{variant:?}");
    }
    assert_eq!(base.record_digest(), base.record_digest());
}

#[test]
fn padding_rounds_up_to_the_next_unit_with_zero_bytes() {
    assert_eq!(padded_length_bytes(10, 4), Ok(12));
    assert_eq!(padded_length_bytes(12, 4), Ok(12));
    assert_eq!(padded_length_bytes(1, 4), Ok(4));
    assert_eq!(padded_length_bytes(0, 4), Ok(0));
    assert_eq!(
        padded_length_bytes(10, 0),
        Err(GranularityError::Zero { field: "unit" })
    );
    assert_eq!(
        padded_length_bytes(u64::MAX, 2),
        Err(GranularityError::Overflow {
            field: "padded length"
        })
    );
    assert_eq!(
        pad_canonically(b"abcdefghij", 4).unwrap(),
        b"abcdefghij\0\0".to_vec()
    );
    assert_eq!(pad_canonically(b"abcd", 4).unwrap(), b"abcd".to_vec());
}

#[test]
fn the_padding_rule_is_canonical() {
    let padded = pad_canonically(b"abcdefghij", 4).unwrap();
    assert_eq!(
        strip_canonical_padding(&padded, 10, 4).unwrap(),
        b"abcdefghij"
    );

    let mut dirty = padded.clone();
    dirty[11] = 1;
    assert_eq!(
        strip_canonical_padding(&dirty, 10, 4).unwrap_err(),
        GranularityError::NonCanonicalPadding {
            reason: "padding bytes must be zero"
        }
    );
    let mut extra_unit = padded.clone();
    extra_unit.extend_from_slice(&[0; 4]);
    let too_long = strip_canonical_padding(&extra_unit, 10, 4).unwrap_err();
    assert!(matches!(
        too_long,
        GranularityError::NonCanonicalPadding { .. }
    ));
    assert!(strip_canonical_padding(b"abcdefghij", 10, 4).is_err());
    // The same padded bytes cannot claim another true length.
    assert!(strip_canonical_padding(&padded, 9, 4).is_err());

    let mut rng = SeededRng::new(0x7406);
    for _ in 0..200 {
        let length = rng.between(0, 300) as usize;
        let unit = rng.between(1, 64);
        let data = rng.bytes(length);
        let padded = pad_canonically(&data, unit).unwrap();
        assert_eq!(
            padded.len() as u64,
            padded_length_bytes(length as u64, unit).unwrap()
        );
        assert!((padded.len() - length) < unit as usize);
        assert_eq!(
            strip_canonical_padding(&padded, length as u64, unit).unwrap(),
            &data[..]
        );
        assert_eq!(pad_canonically(&data, unit).unwrap(), padded);
    }
}

#[test]
fn padding_never_enters_an_identity() {
    let data = b"final extent of 10";
    let padded = pad_canonically(data, 16).unwrap();
    assert_ne!(padded.len(), data.len());
    assert_ne!(ContentKey::of(data), ContentKey::of(&padded));
    assert_eq!(ContentKey::of(data), ContentKey::of(&padded[..data.len()]));
}
