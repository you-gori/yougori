//! GPU §2.4: the scatter/gather map relating g_h, g_c, g_v and g_t round-trips; adjacent
//! extents coalesce into batches without changing their identities; final extents keep
//! their true lengths.

use crate::foundation::ids::{digest, ContentKey, Digest};

use super::super::granularity::{Granularities, MappingUnitReport};
use super::super::scatter_gather::{CodecLayout, Piece, ScatterGatherMap};
use super::super::GranularityError;
use super::support::SeededRng;

fn properties() -> Digest {
    digest("yougori/test/graph/allocation-properties/v1", &[b"device0"])
}

fn granularities(h: u64, c: u64, v: u64, t: u64) -> Granularities {
    Granularities::new(
        h,
        c,
        MappingUnitReport::from_driver(properties(), v).unwrap(),
        t,
    )
    .unwrap()
}

/// An uncompressed artifact: the encoded bytes are the decoded bytes.
fn stored(bytes: &[u8], h: u64, c: u64, v: u64, t: u64) -> ScatterGatherMap {
    let codec = CodecLayout::stored(bytes.len() as u64, c).unwrap();
    ScatterGatherMap::build(granularities(h, c, v, t), &properties(), bytes, &codec).unwrap()
}

fn slice(bytes: &[u8], offset: u64, length: u64) -> &[u8] {
    &bytes[offset as usize..(offset + length) as usize]
}

fn gather_pieces(units: &[&[u8]], pieces: &[Piece]) -> Vec<u8> {
    pieces
        .iter()
        .flat_map(|piece| {
            slice(
                units[piece.unit],
                piece.offset_in_unit_bytes,
                piece.length_bytes,
            )
            .to_vec()
        })
        .collect()
}

#[test]
fn the_scatter_gather_map_round_trips() {
    let mut rng = SeededRng::new(0x7506);
    // g_h, g_c, g_v, g_t, including batches smaller than extents.
    let shapes = [
        (1024, 700, 4096, 3000),
        (1024, 512, 512, 1024),
        (4096, 300, 1000, 1000),
        (333, 1000, 64, 10_000),
    ];
    for (h, c, v, t) in shapes {
        let length = rng.between(1, 12_000) as usize;
        let bytes = rng.bytes(length);
        let map = stored(&bytes, h, c, v, t);

        let batches = map.scatter_batches(&bytes).unwrap();
        assert_eq!(map.gather_batches(&batches).unwrap(), bytes);
        let units = map.scatter_mapping_units(&bytes).unwrap();
        assert_eq!(units.len() as u64, map.mapping_unit_count());
        assert!(units.iter().all(|unit| unit.len() as u64 == v));
        assert_eq!(map.gather_mapping_units(&units).unwrap(), bytes);

        for offset in 0..length as u64 {
            let at = map.locate_encoded(offset).unwrap();
            assert_eq!(
                map.extents()[at.extent].range.offset_bytes + at.offset_in_extent_bytes,
                offset
            );
            assert_eq!(
                map.batches()[at.batch].range.offset_bytes + at.offset_in_batch_bytes,
                offset
            );
            assert_eq!(
                map.codec_blocks()[at.codec_block].encoded.offset_bytes + at.offset_in_block_bytes,
                offset
            );
            let decoded = map.locate_decoded(offset).unwrap();
            assert_eq!(
                decoded.mapping_unit as u64 * v + decoded.offset_in_unit_bytes,
                offset
            );
            assert_eq!(
                map.codec_blocks()[decoded.codec_block].decoded.offset_bytes
                    + decoded.offset_in_block_bytes,
                offset
            );
        }
        assert!(map.locate_encoded(length as u64).is_err());
        assert!(map.locate_decoded(length as u64).is_err());

        let extents: Vec<&[u8]> = map
            .extents()
            .iter()
            .map(|extent| slice(&bytes, extent.range.offset_bytes, extent.range.length_bytes))
            .collect();
        let batch_slices: Vec<&[u8]> = batches.iter().map(Vec::as_slice).collect();
        for (number, block) in map.codec_blocks().iter().enumerate() {
            let pieces = map.extent_pieces_for_codec_block(number).unwrap();
            assert_eq!(
                gather_pieces(&extents, &pieces),
                slice(
                    &bytes,
                    block.encoded.offset_bytes,
                    block.encoded.length_bytes
                )
            );
            let unit_slices: Vec<&[u8]> = units.iter().map(Vec::as_slice).collect();
            let scattered = map.mapping_pieces_for_codec_block(number).unwrap();
            assert_eq!(
                gather_pieces(&unit_slices, &scattered),
                slice(
                    &bytes,
                    block.decoded.offset_bytes,
                    block.decoded.length_bytes
                )
            );
        }
        for (number, extent) in map.extents().iter().enumerate() {
            let pieces = map.batch_pieces_for_extent(number).unwrap();
            assert_eq!(gather_pieces(&batch_slices, &pieces), extents[number]);
            assert_eq!(extent.identity, ContentKey::of(extents[number]));
        }
    }
}

#[test]
fn adjacent_extents_coalesce_without_changing_identities_or_true_lengths() {
    let bytes = SeededRng::new(0x7606).bytes(10 * 1024 + 300);
    let three_per_batch = stored(&bytes, 1024, 512, 4096, 3 * 1024);
    let extents = three_per_batch.extents();
    assert_eq!(extents.len(), 11);
    assert_eq!(extents[10].range.length_bytes, 300);
    assert_eq!(
        extents[10].identity,
        ContentKey::of(slice(&bytes, 10 * 1024, 300))
    );

    let batches = three_per_batch.batches();
    let groups: Vec<Vec<usize>> = batches
        .iter()
        .map(|batch| batch.extents.iter().map(|piece| piece.unit).collect())
        .collect();
    assert_eq!(
        groups,
        vec![vec![0, 1, 2], vec![3, 4, 5], vec![6, 7, 8], vec![9, 10]]
    );
    for batch in batches {
        let mut next = batch.range.offset_bytes;
        for piece in &batch.extents {
            let extent = &extents[piece.unit];
            assert_eq!(piece.offset_in_unit_bytes, 0);
            assert_eq!(piece.length_bytes, extent.range.length_bytes);
            assert_eq!(extent.range.offset_bytes, next);
            next += piece.length_bytes;
        }
        assert_eq!(next, batch.range.end_bytes());
        assert!(batch.range.length_bytes <= 3 * 1024);
    }
    assert_eq!(batches[3].range.length_bytes, 1024 + 300);

    // Other batch sizes move batch boundaries, never extent identities.
    let one_batch = stored(&bytes, 1024, 512, 4096, 1 << 20);
    let one_each = stored(&bytes, 1024, 512, 4096, 1024);
    let odd = stored(&bytes, 1024, 512, 4096, 2047);
    assert_eq!(one_batch.batches().len(), 1);
    assert_eq!(one_each.batches().len(), 11);
    assert_eq!(odd.batches().len(), 10);
    for other in [&one_batch, &one_each, &odd] {
        assert_eq!(other.extents(), three_per_batch.extents());
        assert_ne!(other.record_digest(), three_per_batch.record_digest());
    }
}

#[test]
fn an_extent_longer_than_a_batch_travels_alone_in_pieces() {
    let bytes = SeededRng::new(0x7706).bytes(9000);
    let map = stored(&bytes, 4096, 1000, 4096, 1000);
    let lengths: Vec<u64> = map.extents().iter().map(|e| e.range.length_bytes).collect();
    assert_eq!(lengths, vec![4096, 4096, 808]);
    assert_eq!(map.batches().len(), 11);
    let pieces = map.batch_pieces_for_extent(0).unwrap();
    assert_eq!(
        pieces
            .iter()
            .map(|piece| piece.length_bytes)
            .collect::<Vec<_>>(),
        vec![1000, 1000, 1000, 1000, 96]
    );
    for batch in map.batches() {
        assert_eq!(batch.extents.len(), 1);
    }
    let batches = map.scatter_batches(&bytes).unwrap();
    assert_eq!(map.gather_batches(&batches).unwrap(), bytes);
}

#[test]
fn a_corrupted_batch_names_the_extent_that_fails() {
    let bytes = SeededRng::new(0x7806).bytes(10 * 1024 + 300);
    let map = stored(&bytes, 1024, 512, 4096, 3 * 1024);
    let mut batches = map.scatter_batches(&bytes).unwrap();
    // Batch 1 holds extents 3, 4 and 5; byte 1500 of it lies in extent 4.
    batches[1][1500] ^= 0x01;
    assert_eq!(
        map.gather_batches(&batches).unwrap_err(),
        GranularityError::ExtentMismatch { extent: 4 }
    );
}

#[test]
fn malformed_pieces_are_refused() {
    let bytes = SeededRng::new(0x7906).bytes(5000);
    let map = stored(&bytes, 1024, 512, 4096, 2048);
    let mut batches = map.scatter_batches(&bytes).unwrap();
    assert!(matches!(
        map.gather_batches(&batches[1..]).unwrap_err(),
        GranularityError::PieceCount {
            field: "transport batch",
            ..
        }
    ));
    batches[0].pop();
    assert!(matches!(
        map.gather_batches(&batches).unwrap_err(),
        GranularityError::PieceLength {
            field: "transport batch",
            index: 0,
            ..
        }
    ));
    assert!(matches!(
        map.scatter_batches(&bytes[1..]).unwrap_err(),
        GranularityError::LengthMismatch {
            field: "encoded artifact",
            ..
        }
    ));

    let mut units = map.scatter_mapping_units(&bytes).unwrap();
    assert_eq!(units.len(), 2);
    assert!(matches!(
        map.gather_mapping_units(&units[..1]).unwrap_err(),
        GranularityError::PieceCount {
            field: "mapping unit",
            ..
        }
    ));
    let last = units.len() - 1;
    let end = units[last].len() - 1;
    units[last][end] = 7;
    assert_eq!(
        map.gather_mapping_units(&units).unwrap_err(),
        GranularityError::NonCanonicalPadding {
            reason: "padding bytes must be zero"
        }
    );
    units[last].pop();
    assert!(matches!(
        map.gather_mapping_units(&units).unwrap_err(),
        GranularityError::PieceLength {
            field: "mapping unit",
            ..
        }
    ));
    assert!(matches!(
        map.extent_pieces_for_codec_block(99).unwrap_err(),
        GranularityError::IndexOutOfRange {
            field: "codec block",
            ..
        }
    ));
    assert!(map.batch_pieces_for_extent(99).is_err());
}

#[test]
fn codec_blocks_relate_encoded_and_decoded_ranges() {
    // 1000 decoded bytes in 256-byte blocks that encode to 100, 300, 50 and 7 bytes.
    let encoded = SeededRng::new(0x7a06).bytes(457);
    let codec = CodecLayout::new(1000, vec![100, 300, 50, 7]);
    let map = ScatterGatherMap::build(
        granularities(128, 256, 512, 256),
        &properties(),
        &encoded,
        &codec,
    )
    .unwrap();
    assert_eq!(
        (map.encoded_length_bytes(), map.decoded_length_bytes()),
        (457, 1000)
    );
    assert_eq!(
        (map.padded_length_bytes(), map.mapping_unit_count()),
        (1024, 2)
    );
    let last = map.codec_blocks()[3];
    assert_eq!(
        (last.decoded.offset_bytes, last.decoded.length_bytes),
        (768, 232)
    );
    assert_eq!(
        (last.encoded.offset_bytes, last.encoded.length_bytes),
        (450, 7)
    );

    let pieces = map.extent_pieces_for_codec_block(1).unwrap();
    let spans: Vec<(usize, u64, u64)> = pieces
        .iter()
        .map(|piece| (piece.unit, piece.offset_in_unit_bytes, piece.length_bytes))
        .collect();
    assert_eq!(
        spans,
        vec![(0, 100, 28), (1, 0, 128), (2, 0, 128), (3, 0, 16)]
    );
    let scatter = map.mapping_pieces_for_codec_block(3).unwrap();
    assert_eq!(
        scatter,
        vec![Piece {
            unit: 1,
            offset_in_unit_bytes: 256,
            length_bytes: 232
        }]
    );
}

#[test]
fn inconsistent_codec_output_is_refused() {
    let encoded = vec![1u8; 457];
    let build = |codec: CodecLayout, bytes: &[u8]| {
        ScatterGatherMap::build(
            granularities(128, 256, 512, 256),
            &properties(),
            bytes,
            &codec,
        )
    };
    assert_eq!(
        build(CodecLayout::new(1000, vec![100, 300, 57]), &encoded).unwrap_err(),
        GranularityError::CodecBlockCount {
            expected: 4,
            actual: 3
        }
    );
    assert_eq!(
        build(CodecLayout::new(1000, vec![100, 0, 350, 7]), &encoded).unwrap_err(),
        GranularityError::EmptyEncodedBlock { block: 1 }
    );
    assert_eq!(
        build(CodecLayout::new(1000, vec![100, 300, 50, 8]), &encoded).unwrap_err(),
        GranularityError::LengthMismatch {
            field: "encoded artifact",
            expected: 458,
            actual: 457
        }
    );
    assert_eq!(
        build(CodecLayout::new(0, vec![]), &[]).unwrap_err(),
        GranularityError::EmptyArtifact
    );
    assert!(CodecLayout::stored(10, 0).is_err());
}
