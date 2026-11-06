//! The existing lossless codec on real bytes: every BF16 pattern round-trips (GPU-T34),
//! malformed lengths, tables, windows and dictionaries are refused within bounds
//! (GPU-T35), and blocks that do not pay for their metadata escape raw.

use super::super::codec::*;
use super::*;
use crate::foundation::ids::ContentKey;
use crate::model_memory::manifest::{
    CodecFormat, CodecVersion, DecodeError, ExtentDecoder, ExtentError, ZstdFrameParameters,
};

#[test]
fn every_bf16_bit_pattern_round_trips_through_zstd_exactly() {
    let patterns = all_bf16_patterns();
    assert_eq!(patterns.len(), 131_072);
    // The special classes are present: signed zeros, infinities, NaNs with payloads and
    // subnormals.
    let has = |bits: u16| {
        patterns
            .chunks(2)
            .any(|pair| u16::from_le_bytes([pair[0], pair[1]]) == bits)
    };
    for bits in [
        0x0000u16, 0x8000, 0x7F80, 0xFF80, 0x7FC0, 0xFFC1, 0x7F81, 0x0001, 0x807F,
    ] {
        assert!(has(bits), "{bits:#06x}");
    }
    assert!(bf16_value(0x8000) == 0.0 && bf16_value(0x8000).is_sign_negative());
    assert!(bf16_value(0x7F80).is_infinite() && bf16_value(0xFF80).is_infinite());
    assert!(bf16_value(0x7FC0).is_nan() && bf16_value(0x7F81).is_nan());
    assert!(bf16_value(0x0001).is_subnormal() && bf16_value(0x807F).is_subnormal());
    for level in [1, DEFAULT_LEVEL, 19] {
        let encoded = encode(&patterns, level, None).unwrap();
        let decoded = decode_bounded(&encoded, None, patterns.len() as u64).unwrap();
        assert_eq!(decoded, patterns, "level {level}");
        assert_eq!(ContentKey::of(&decoded), ContentKey::of(&patterns));
    }
}

#[test]
fn every_bf16_bit_pattern_round_trips_through_the_manifest_and_raw_escapes() {
    let patterns = all_bf16_patterns();
    // Once with zstd blocks, once with every block forced to escape raw.
    let forced_escape = Storage::Zstd(EscapePolicy {
        level: 3,
        metadata_bytes_per_encoded_block: u64::MAX / 2,
    });
    for storage in [ZSTD, forced_escape] {
        let mut spec = ModelSpec::single(vec![("all.patterns", patterns.clone())]);
        spec.storage = storage;
        let model = build_model(&spec);
        let decoded = model.decoded_extents();
        let required =
            super::super::differential::RequiredSet::for_all_tensors(&model.manifest).unwrap();
        let decoder = ZstdDecoder;
        let loaded = super::super::differential::full_load(
            &model.manifest,
            &required,
            &model,
            &[&decoder as &dyn ExtentDecoder],
        )
        .unwrap();
        assert_eq!(
            loaded
                .tensor_bytes(&model.manifest, "all.patterns")
                .unwrap(),
            patterns
        );
        assert!(decoded.len() > 1);
    }
}

#[test]
fn real_frames_pass_the_header_check_at_their_exact_length() {
    for length in [1usize, 100, 1024, 1025, 4096, 65_536, 200_000] {
        let data = bf16_weights(length as u64, length.div_ceil(2), 0.02);
        let data = &data[..length];
        let encoded = encode(data, DEFAULT_LEVEL, None).unwrap();
        let header = inspect_frame_header(&encoded, length as u64, None).unwrap();
        assert_eq!(header.content_bytes, Some(length as u64));
        assert!(header.window_bytes <= allowed_window_bytes(length as u64));
        assert_eq!(decode_bounded(&encoded, None, length as u64).unwrap(), data);
    }
    assert_eq!(allowed_window_bytes(0), 1024);
    assert_eq!(allowed_window_bytes(1025), 2048);
    assert_eq!(allowed_window_bytes(u64::MAX), 1 << MAX_WINDOW_LOG);
}

/// A frame header without a content size and with a 1 KiB window, then `blocks` RLE
/// blocks of 1024 copies of 0xAB: about 1 MiB from a few hundred bytes.
fn rle_bomb(blocks: usize) -> Vec<u8> {
    let mut frame = ZSTD_MAGIC.to_le_bytes().to_vec();
    frame.push(0x00); // no content size, not single segment, no checksum, no dictionary
    frame.push(0x00); // window 2^10
    for index in 0..blocks {
        let last = u32::from(index + 1 == blocks);
        let header = last | (1 << 1) | (1024 << 3);
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.push(0xAB);
    }
    frame
}

#[test]
fn a_decompression_bomb_stops_at_the_declared_length() {
    let bomb = rle_bomb(1024);
    assert!(bomb.len() < 5_000);
    // Under a generous bound it decodes, proving the frame is valid.
    assert_eq!(
        decode_bounded(&bomb, None, 1024 * 1024).unwrap().len(),
        1024 * 1024
    );
    // Under a 4 KiB bound the sink never receives more than the bound.
    let mut received = 0usize;
    let result = decode_frame(&bomb, None, 4096, |piece| {
        received += piece.len();
        assert!(received <= 4096);
        Ok(())
    });
    assert_eq!(
        result,
        Err(DecodeError::BoundExceeded { limit_bytes: 4096 })
    );
    assert!(received <= 4096);
}

#[test]
fn malformed_lengths_windows_and_tables_are_refused_before_decoding() {
    let data = bf16_weights(7, 2048, 0.02);
    let encoded = encode(&data, DEFAULT_LEVEL, None).unwrap();
    let length = data.len() as u64;
    // A declared length below the frame's content size: the bound is exceeded.
    assert_eq!(
        decode_bounded(&encoded, None, length - 1),
        Err(CodecError::Decode(DecodeError::BoundExceeded {
            limit_bytes: length - 1
        }))
    );
    // Above it: the frame can never fill the extent.
    assert_eq!(
        decode_bounded(&encoded, None, length + 1),
        Err(CodecError::Decode(DecodeError::Corrupt))
    );
    // Truncation anywhere, header or body.
    for cut in [0, 3, 4, 5, 7, encoded.len() / 2, encoded.len() - 1] {
        assert!(
            decode_bounded(&encoded[..cut], None, length).is_err(),
            "cut at {cut}"
        );
    }
    // Trailing bytes after the one frame, including a second valid frame.
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        decode_bounded(&trailing, None, length),
        Err(CodecError::Decode(DecodeError::Corrupt))
    );
    let mut doubled = encoded.clone();
    doubled.extend_from_slice(&encoded);
    assert!(decode_bounded(&doubled, None, length).is_err());
    // A wrong magic number, a skippable frame and a reserved descriptor bit.
    let mut magic = encoded.clone();
    magic[0] ^= 0xFF;
    assert_eq!(
        inspect_frame_header(&magic, length, None),
        Err(DecodeError::Corrupt)
    );
    let mut skippable = 0x184D_2A50u32.to_le_bytes().to_vec();
    skippable.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(
        inspect_frame_header(&skippable, 0, None),
        Err(DecodeError::Corrupt)
    );
    let mut reserved = encoded.clone();
    reserved[4] |= 0x08;
    assert_eq!(
        inspect_frame_header(&reserved, length, None),
        Err(DecodeError::Corrupt)
    );
    // A corrupted entropy table or sequence section inside the body.
    let mut flipped = 0;
    for position in 8..encoded.len().min(64) {
        let mut corrupt = encoded.clone();
        corrupt[position] ^= 0x5A;
        if decode_bounded(&corrupt, None, length).is_err() {
            flipped += 1;
        }
    }
    assert!(flipped > 0);
}

#[test]
fn a_window_larger_than_the_output_is_refused_before_any_allocation() {
    // Window descriptor 0x88: 2^27 bytes, for a 3-byte raw block.
    let mut frame = ZSTD_MAGIC.to_le_bytes().to_vec();
    frame.extend_from_slice(&[0x00, 0x88]);
    let header = 1u32 | (3 << 3);
    frame.extend_from_slice(&header.to_le_bytes()[..3]);
    frame.extend_from_slice(b"abc");
    assert_eq!(
        inspect_frame_header(&frame, 3, None),
        Err(DecodeError::BoundExceeded { limit_bytes: 3 })
    );
    assert_eq!(
        decode_bounded(&frame, None, 3),
        Err(CodecError::Decode(DecodeError::BoundExceeded {
            limit_bytes: 3
        }))
    );
    // The same block under a 1 KiB window decodes.
    frame[5] = 0x00;
    assert_eq!(decode_bounded(&frame, None, 3).unwrap(), b"abc");
}

#[test]
fn dictionaries_are_required_matched_and_never_guessed() {
    // A header naming dictionary 7 without a dictionary.
    let mut frame = ZSTD_MAGIC.to_le_bytes().to_vec();
    frame.extend_from_slice(&[0x01, 0x00, 0x07]);
    assert_eq!(
        inspect_frame_header(&frame, 3, None),
        Err(DecodeError::DictionaryRequired)
    );
    // A frame encoded with a raw-content dictionary is unreadable without it.
    let dictionary = bf16_weights(11, 4096, 0.02);
    let data = fine_tune(&dictionary[..2048], 12, 0.01);
    let encoded = encode(&data, DEFAULT_LEVEL, Some(&dictionary)).unwrap();
    assert_eq!(
        decode_bounded(&encoded, Some(&dictionary), data.len() as u64).unwrap(),
        data
    );
    assert!(
        decode_bounded(&encoded, None, data.len() as u64).map_or(true, |decoded| decoded != data)
    );
    // Through the manifest: a declared dictionary must be supplied and match.
    let model = build_model(&ModelSpec::single(vec![("w", data.clone())]));
    let index = 1; // the first weight extent, raw: no dictionary accepted
    let stored = super::StoredExtents::stored(&model, index).unwrap();
    let decoder = ZstdDecoder;
    assert_eq!(
        model.manifest.verify_extent(
            index,
            &stored,
            Some(&dictionary),
            &[&decoder as &dyn ExtentDecoder]
        ),
        Err(ExtentError::UnexpectedDictionary)
    );
}

#[test]
fn an_extent_whose_bytes_fail_verification_is_never_decoded_or_used() {
    let model = build_model(&ModelSpec {
        storage: ZSTD,
        ..ModelSpec::single(vec![("w", bf16_weights(3, 1024, 0.02))])
    });
    let decoder = ZstdDecoder;
    let decoders = [&decoder as &dyn ExtentDecoder];
    let encoded_index = model
        .manifest
        .manifest()
        .extents
        .extents
        .iter()
        .position(|extent| matches!(extent.encoding, ExtentEncoding::Encoded(_)))
        .unwrap();
    let mut stored = super::StoredExtents::stored(&model, encoded_index).unwrap();
    let middle = stored.len() / 2;
    stored[middle] ^= 1;
    assert_eq!(
        model
            .manifest
            .verify_extent(encoded_index, &stored, None, &decoders),
        Err(ExtentError::EncodedDigestMismatch)
    );
    // Without a zstd decoder the extent is refused, not passed through.
    let stored = super::StoredExtents::stored(&model, encoded_index).unwrap();
    assert!(matches!(
        model
            .manifest
            .verify_extent(encoded_index, &stored, None, &[]),
        Err(ExtentError::DecoderUnavailable { .. })
    ));
}

#[test]
fn incompressible_blocks_escape_raw_and_compressible_ones_are_encoded() {
    let policy = EscapePolicy {
        level: DEFAULT_LEVEL,
        metadata_bytes_per_encoded_block: 0,
    };
    // Already-quantized stand-in: random bytes do not compress.
    let quantized = random_bytes(5, 4096);
    assert_eq!(
        choose_block(&quantized, &policy).unwrap(),
        BlockEncoding::Raw
    );
    // A run of zeros compresses far below its length.
    let zeros = vec![0u8; 4096];
    let BlockEncoding::Zstd { encoded } = choose_block(&zeros, &policy).unwrap() else {
        panic!("zeros should be encoded");
    };
    assert!(encoded.len() < 64);
    // Metadata decides at the margin: a block saving s bytes escapes once the metadata
    // reaches s.
    let saving = zeros.len() as u64 - encoded.len() as u64;
    let at = |metadata| EscapePolicy {
        level: DEFAULT_LEVEL,
        metadata_bytes_per_encoded_block: metadata,
    };
    assert!(matches!(
        choose_block(&zeros, &at(saving - 1)).unwrap(),
        BlockEncoding::Zstd { .. }
    ));
    assert_eq!(
        choose_block(&zeros, &at(saving)).unwrap(),
        BlockEncoding::Raw
    );
}

#[test]
fn a_prepared_file_mixes_raw_escapes_with_encoded_blocks() {
    let mut bytes = random_bytes(9, 2 * G as usize);
    bytes.extend(vec![0u8; 2 * G as usize]);
    let file = path("mixed.bin");
    let prepared = prepare_file(
        &file,
        &bytes,
        G,
        &path("prepared/mixed.zst"),
        &EscapePolicy {
            level: DEFAULT_LEVEL,
            metadata_bytes_per_encoded_block: 0,
        },
    )
    .unwrap();
    assert_eq!(prepared.escaped_blocks, 2);
    assert_eq!(prepared.encoded_blocks, 2);
    assert_eq!(prepared.codec_block_bytes, Some(G));
    let kinds: Vec<bool> = prepared
        .extents
        .iter()
        .map(|extent| matches!(extent.encoding, EncodingInput::Raw))
        .collect();
    assert_eq!(kinds, vec![true, true, false, false]);
    // All raw: no prepared file and no codec block size, which the manifest requires.
    let raw = prepare_file(
        &file,
        &random_bytes(10, G as usize),
        G,
        &path("prepared/raw.zst"),
        &EscapePolicy {
            level: DEFAULT_LEVEL,
            metadata_bytes_per_encoded_block: 0,
        },
    )
    .unwrap();
    assert_eq!(raw.prepared, None);
    assert_eq!(raw.codec_block_bytes, None);
    assert_eq!(
        prepare_file(
            &file,
            &bytes,
            0,
            &path("p.zst"),
            &EscapePolicy {
                level: 3,
                metadata_bytes_per_encoded_block: 0
            }
        ),
        Err(CodecError::ZeroBlockSize)
    );
}

#[test]
fn the_manifest_metadata_of_an_encoded_block_is_measured_from_the_sidecar() {
    // Two artifacts differing only in one more encoded block: the sidecar grows by that
    // block's manifest entry, which an escape decision must charge.
    let block = |count: usize| {
        let mut data = vec![0u8; count * G as usize];
        data.truncate(count * G as usize);
        data
    };
    let model = |blocks: usize| {
        build_model(&ModelSpec {
            storage: ZSTD,
            ..ModelSpec::single(vec![("w", block(blocks))])
        })
    };
    let one = model(1).manifest.sidecar_bytes().len() as u64;
    let two = model(2).manifest.sidecar_bytes().len() as u64;
    let per_block = two - one;
    // At least the 32-byte encoded digest and the content key per block.
    assert!(per_block > 64, "{per_block}");
    // With that metadata charged, a block saving less escapes raw.
    let zeros = vec![0u8; G as usize];
    let encoded = encode(&zeros, DEFAULT_LEVEL, None).unwrap();
    let saving = zeros.len() as u64 - encoded.len() as u64;
    let policy = EscapePolicy {
        level: DEFAULT_LEVEL,
        metadata_bytes_per_encoded_block: per_block,
    };
    let expected = if saving > per_block {
        BlockEncoding::Zstd { encoded }
    } else {
        BlockEncoding::Raw
    };
    assert_eq!(choose_block(&zeros, &policy).unwrap(), expected);
}

#[test]
fn the_zstd_decoder_delivers_nothing_beyond_its_bound() {
    let decoder = ZstdDecoder;
    assert_eq!(decoder.codec(), crate::model_memory::manifest::Codec::Zstd);
    // A frame holding 600 bytes against a 256-byte extent: refused at the header, so the
    // sink receives nothing at all.
    let encoded = encode(&[7u8; 600], DEFAULT_LEVEL, None).unwrap();
    let mut received = 0usize;
    let result = decode_frame(&encoded, None, 256, |piece| {
        received += piece.len();
        Ok(())
    });
    assert_eq!(result, Err(DecodeError::BoundExceeded { limit_bytes: 256 }));
    assert_eq!(received, 0);
}

#[test]
fn a_frame_must_agree_with_the_frame_parameters_its_extent_declares() {
    // GPU-W08: the decoder declares the RFC 8878 version, and a frame from `encode`
    // agrees with the format `prepare_file` declares for its blocks.
    assert_eq!(ZstdDecoder.versions(), [CodecVersion::ZstdRfc8878]);
    let data = [7u8; 200];
    let frame = encode(&data, DEFAULT_LEVEL, None).unwrap();
    let header = inspect_frame_header(&frame, data.len() as u64, None).unwrap();
    let CodecFormat::ZstdRfc8878(declared) = zstd_format(G);
    assert_eq!(check_frame_parameters(&header, &declared), Ok(()));
    for (field, changed) in [
        (
            "dictionary_id",
            ZstdFrameParameters {
                dictionary_id: 7,
                ..declared
            },
        ),
        (
            "content_checksum",
            ZstdFrameParameters {
                content_checksum: true,
                ..declared
            },
        ),
        (
            "max_window_bytes",
            ZstdFrameParameters {
                max_window_bytes: header.window_bytes - 1,
                ..declared
            },
        ),
    ] {
        assert_eq!(
            check_frame_parameters(&header, &changed),
            Err(DecodeError::FormatMismatch { field })
        );
    }
}

#[test]
fn ratios_are_measured_per_tensor_class_and_throughput_is_not() {
    let weights = bf16_weights(40, 32_768, 0.02);
    let quantized = random_bytes(41, 65_536);
    let sparse = {
        let mut bytes = vec![0u8; 65_536];
        for index in (0..bytes.len()).step_by(64) {
            bytes[index] = (index / 64) as u8;
        }
        bytes
    };
    let profiles = class_profiles(
        &[
            ("bf16-weights", &weights),
            ("already-quantized", &quantized),
            ("sparse", &sparse),
        ],
        DEFAULT_LEVEL,
    )
    .unwrap();
    let fraction = |class: &str| {
        profiles
            .iter()
            .find(|profile| profile.class == class)
            .unwrap()
            .compressed_fraction
    };
    // BF16 weights compress somewhat (the exponent byte), quantized bytes not at all.
    assert!(fraction("bf16-weights") < 0.9 && fraction("bf16-weights") > 0.5);
    assert!(fraction("already-quantized") >= 1.0);
    assert!(fraction("sparse") < 0.1);
    assert!(profiles
        .iter()
        .all(|profile| !profile.decode_raw_bytes_per_second.is_measured()));
}
