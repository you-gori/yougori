//! Codec versions (GPU-W08: "Include codec versions/dictionaries and encoded/decoded
//! identities in manifests"): every field of a codec format is bound by the digests, an
//! unknown codec or version is refused before anything after it is read, an earlier
//! schema needs a re-import, and a decoder decodes only the versions it declares.

use std::sync::atomic::Ordering;

use super::super::*;
use super::fakes::{RunLengthStandIn, VersionlessDecoder};
use super::manifest_tests::{
    chunks, encoded_sample, encoded_sample_with, reseal, revalidate_from, sample, weights_bytes, G,
    WEIGHTS,
};
use super::ZSTD_FORMAT;

/// Where the codec table starts in a body: after the magic, the two versions, the byte
/// order and the bounds.
const TABLE: usize = 8 + 2 + 2 + 1 + 6 * 4 + 2 * 8;
/// The first table entry, after the table's u64 count.
const ENTRY: usize = TABLE + 8;
/// A zstd entry: codec code, version number, dictionary id, checksum flag, window bound.
const ENTRY_BYTES: usize = 1 + 2 + 4 + 1 + 8;
const CODEC: usize = ENTRY;
const VERSION: usize = ENTRY + 1;
const DICTIONARY_ID: usize = ENTRY + 3;
const CHECKSUM: usize = ENTRY + 7;
const WINDOW: usize = ENTRY + 8;

fn body_of(manifest: &ValidatedManifest) -> Vec<u8> {
    let sidecar = manifest.sidecar_bytes();
    sidecar[..sidecar.len() - SIDECAR_DIGEST_BYTES].to_vec()
}

/// `body` with `bytes` written at `offset`.
fn with(body: &[u8], offset: usize, bytes: &[u8]) -> Vec<u8> {
    let mut changed = body.to_vec();
    changed[offset..offset + bytes.len()].copy_from_slice(bytes);
    changed
}

/// Reads `body` sealed under its own digest, as a writer of it would have sealed it.
fn read(body: &[u8]) -> Result<ValidatedManifest, ManifestError> {
    ValidatedManifest::from_sidecar_bytes(&reseal(body))
}

fn zstd(frame: ZstdFrameParameters) -> CodecFormat {
    CodecFormat::ZstdRfc8878(frame)
}

fn set_format(manifest: &mut Manifest, format: CodecFormat) {
    for extent in &mut manifest.extents.extents {
        if let ExtentEncoding::Encoded(encoded) = &mut extent.encoding {
            encoded.format = format;
        }
    }
}

#[test]
fn every_codec_format_field_is_bound_by_the_digests() {
    let dictionary: Option<&[u8]> = Some(b"dictionary");
    let dictionary_id = dictionary.map(DictionaryId::of);
    let (encoded, stored) = encoded_sample(dictionary);
    let body = body_of(&encoded);
    assert_eq!(
        &body[TABLE..ENTRY],
        &1u64.to_be_bytes(),
        "one format is listed"
    );
    let CodecFormat::ZstdRfc8878(frame) = ZSTD_FORMAT;
    let changes: [(&str, ZstdFrameParameters, usize, Vec<u8>); 3] = [
        (
            "dictionary_id",
            ZstdFrameParameters {
                dictionary_id: 7,
                ..frame
            },
            DICTIONARY_ID,
            7u32.to_be_bytes().to_vec(),
        ),
        (
            "content_checksum",
            ZstdFrameParameters {
                content_checksum: true,
                ..frame
            },
            CHECKSUM,
            vec![1],
        ),
        (
            "max_window_bytes",
            ZstdFrameParameters {
                max_window_bytes: 512,
                ..frame
            },
            WINDOW,
            512u64.to_be_bytes().to_vec(),
        ),
    ];
    for (field, changed, offset, bytes) in changes {
        let changed = zstd(changed);
        // The encoded identity binds the field: the same stored bytes under another
        // format are another representation.
        assert_ne!(
            EncodedDigest::of(changed, dictionary_id, &stored[2]),
            EncodedDigest::of(ZSTD_FORMAT, dictionary_id, &stored[2]),
            "{field}"
        );
        // Built with the field changed: another manifest digest and weights root over
        // the same decoded content.
        let (rebuilt, _) = encoded_sample_with(dictionary, |_| changed);
        let rebuilt = rebuilt.unwrap();
        assert_ne!(rebuilt.digest(), encoded.digest(), "{field}");
        assert_ne!(
            rebuilt.extent_root(SourceFileId(WEIGHTS)),
            encoded.extent_root(SourceFileId(WEIGHTS)),
            "{field}"
        );
        assert_eq!(
            rebuilt.manifest().integrity.decoded_content_identity,
            encoded.manifest().integrity.decoded_content_identity
        );
        // Changed in memory alone: the stored trees no longer match the leaves.
        let mut relabelled = encoded.manifest().clone();
        set_format(&mut relabelled, changed);
        assert_eq!(
            relabelled.validate().map(|_| ()),
            Err(ManifestError::TreeRootMismatch { file: WEIGHTS }),
            "{field}: the leaves bind the format"
        );
        // Changed in the sidecar: the seal breaks, and resealed, the trees refuse it.
        let tampered = with(&body, offset, &bytes);
        let mut sidecar = tampered.clone();
        sidecar.extend_from_slice(encoded.digest().digest().as_bytes());
        assert_eq!(
            ValidatedManifest::from_sidecar_bytes(&sidecar),
            Err(ManifestError::DigestMismatch),
            "{field}"
        );
        assert_eq!(
            read(&tampered).map(|_| ()),
            Err(ManifestError::TreeRootMismatch { file: WEIGHTS }),
            "{field}"
        );
    }
    // The codec and the version are bound as codes: any other is unknown and refused.
    assert_eq!(
        read(&with(&body, CODEC, &[9])).map(|_| ()),
        Err(ManifestError::UnknownCodec { code: 9 })
    );
    assert_eq!(
        read(&with(&body, VERSION, &9u16.to_be_bytes())).map(|_| ()),
        Err(ManifestError::UnknownCodecVersion {
            codec: Codec::Zstd,
            version: 9
        })
    );
    assert_eq!(
        read(&with(&body, CHECKSUM, &[2])).map(|_| ()),
        Err(ManifestError::UnknownTag {
            field: "content checksum flag",
            tag: 2
        })
    );
    // Unchanged, the sidecar reads back as itself.
    assert_eq!(read(&body), Ok(encoded));
}

#[test]
fn an_unknown_codec_or_version_is_refused_before_anything_after_it_is_read() {
    let (encoded, _) = encoded_sample(None);
    let body = body_of(&encoded);
    let table_end = ENTRY + ENTRY_BYTES;
    // Cut right after the codec table, the body is truncated for a reader that reads on.
    assert_eq!(
        read(&body[..table_end]).map(|_| ()),
        Err(ManifestError::Truncated)
    );
    // An unknown version or codec is refused first: nothing after the table is read.
    let unknown_version = with(&body, VERSION, &2u16.to_be_bytes());
    assert_eq!(
        read(&unknown_version[..table_end]).map(|_| ()),
        Err(ManifestError::UnknownCodecVersion {
            codec: Codec::Zstd,
            version: 2
        })
    );
    let unknown_codec = with(&body, CODEC, &[0]);
    assert_eq!(
        read(&unknown_codec[..table_end]).map(|_| ()),
        Err(ManifestError::UnknownCodec { code: 0 })
    );
    // An unknown second entry is refused before the table is allocated and before the
    // first entry is used, even when the body ends right after it.
    let mut two = body[..table_end].to_vec();
    two[TABLE..ENTRY].copy_from_slice(&2u64.to_be_bytes());
    let mut second = body[ENTRY..table_end].to_vec();
    second[1..3].copy_from_slice(&7u16.to_be_bytes());
    two.extend_from_slice(&second);
    assert_eq!(
        read(&two).map(|_| ()),
        Err(ManifestError::UnknownCodecVersion {
            codec: Codec::Zstd,
            version: 7
        })
    );
    // A count above the declared bounds is refused before any entry is read.
    assert!(matches!(
        read(&with(&body, TABLE, &u64::MAX.to_be_bytes())),
        Err(ManifestError::BoundExceeded {
            bound: "max_extents",
            ..
        })
    ));
    // This build knows one codec with one version; nothing else can be held in memory.
    assert_eq!(Codec::ALL, [Codec::Zstd]);
    assert_eq!(CodecVersion::ALL, [CodecVersion::ZstdRfc8878]);
    assert_eq!(CodecVersion::ZstdRfc8878.codec(), Codec::Zstd);
    assert_eq!(ZSTD_FORMAT.version().to_string(), "zstd/rfc8878");
}

#[test]
fn an_earlier_schema_needs_a_reimport_and_is_never_migrated() {
    let (encoded, _) = encoded_sample(None);
    let body = body_of(&encoded);
    assert_eq!(MANIFEST_SCHEMA_VERSION, 3);
    for earlier in FIRST_MANIFEST_SCHEMA_VERSION..MANIFEST_SCHEMA_VERSION {
        let old = with(&body, 8, &earlier.to_be_bytes());
        assert_eq!(
            read(&old).map(|_| ()),
            Err(ManifestError::NeedsReimport {
                schema_version: earlier
            })
        );
        // Refused right after its version: nothing else in it is read or allocated.
        assert_eq!(
            read(&old[..10]).map(|_| ()),
            Err(ManifestError::NeedsReimport {
                schema_version: earlier
            })
        );
        // A manifest held in memory under an earlier schema is refused the same way.
        assert_eq!(
            revalidate_from(&encoded, |m| m.schema.schema_version = earlier).map(|_| ()),
            Err(ManifestError::NeedsReimport {
                schema_version: earlier
            })
        );
    }
    for unknown in [0, MANIFEST_SCHEMA_VERSION + 1] {
        assert_eq!(
            read(&with(&body, 8, &unknown.to_be_bytes())).map(|_| ()),
            Err(ManifestError::UnsupportedSchemaVersion { found: unknown })
        );
    }
    assert!(ManifestError::NeedsReimport { schema_version: 2 }
        .to_string()
        .contains("import the model again"));
}

#[test]
fn a_decoder_must_declare_the_codec_version_of_the_extent() {
    let (encoded, stored) = encoded_sample(None);
    let weights = weights_bytes();
    let versionless = VersionlessDecoder::default();
    assert_eq!(
        encoded.verify_extent(2, &stored[2], None, &[&versionless]),
        Err(ExtentError::DecoderVersionMismatch {
            version: CodecVersion::ZstdRfc8878
        })
    );
    assert_eq!(
        versionless.calls.load(Ordering::SeqCst),
        0,
        "never handed an extent of a version it does not declare"
    );
    assert_eq!(
        encoded.check_decoders(&[&versionless]),
        Err(ExtentError::DecoderVersionMismatch {
            version: CodecVersion::ZstdRfc8878
        })
    );
    // A decoder that declares the version is chosen over one that does not, and is given
    // the extent's declared format.
    let stand_in = RunLengthStandIn::default();
    assert_eq!(
        encoded.verify_extent(2, &stored[2], None, &[&versionless, &stand_in]),
        Ok(chunks(&weights)[0].clone())
    );
    assert_eq!(*stand_in.formats.lock().unwrap(), vec![ZSTD_FORMAT]);
    assert_eq!(encoded.check_decoders(&[&versionless, &stand_in]), Ok(()));
    // No decoder of the codec at all.
    assert_eq!(
        encoded.verify_extent(2, &stored[2], None, &[]),
        Err(ExtentError::DecoderUnavailable { codec: Codec::Zstd })
    );
    assert_eq!(
        encoded.check_decoders(&[]),
        Err(ExtentError::DecoderUnavailable { codec: Codec::Zstd })
    );
    // Raw extents need no decoder.
    assert_eq!(sample().check_decoders(&[]), Ok(()));
    // Each extent's own format reaches the decoder.
    let CodecFormat::ZstdRfc8878(frame) = ZSTD_FORMAT;
    let narrow = zstd(ZstdFrameParameters {
        max_window_bytes: 512,
        ..frame
    });
    let (mixed, stored) = encoded_sample_with(None, |index| match index {
        1 => narrow,
        _ => ZSTD_FORMAT,
    });
    let mixed = mixed.unwrap();
    let stand_in = RunLengthStandIn::default();
    for index in 2..5 {
        mixed
            .verify_extent(index, &stored[index], None, &[&stand_in])
            .unwrap();
    }
    assert_eq!(
        *stand_in.formats.lock().unwrap(),
        vec![ZSTD_FORMAT, narrow, ZSTD_FORMAT]
    );
}

#[test]
fn raw_extents_are_codec_free_and_each_format_is_listed_once() {
    let raw = sample();
    assert!(raw.codec_formats().is_empty());
    assert_eq!(&body_of(&raw)[TABLE..ENTRY], &0u64.to_be_bytes());
    let (encoded, _) = encoded_sample(None);
    assert_eq!(encoded.codec_formats(), vec![ZSTD_FORMAT]);

    let CodecFormat::ZstdRfc8878(frame) = ZSTD_FORMAT;
    let narrow = zstd(ZstdFrameParameters {
        max_window_bytes: 512,
        ..frame
    });
    let (mixed, _) = encoded_sample_with(None, |index| match index {
        1 => narrow,
        _ => ZSTD_FORMAT,
    });
    let mixed = mixed.unwrap();
    assert_eq!(mixed.codec_formats(), vec![narrow, ZSTD_FORMAT]);
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&mixed.sidecar_bytes()),
        Ok(mixed.clone())
    );
    let body = body_of(&mixed);
    assert_eq!(&body[TABLE..ENTRY], &2u64.to_be_bytes());
    let first = body[ENTRY..ENTRY + ENTRY_BYTES].to_vec();
    let second = body[ENTRY + ENTRY_BYTES..ENTRY + 2 * ENTRY_BYTES].to_vec();
    let not_canonical = Err(ManifestError::NotCanonical {
        collection: "codec formats",
    });
    for (case, entries) in [
        ("descending", [second.clone(), first.clone()]),
        ("repeated", [first.clone(), first.clone()]),
    ] {
        let mut changed = body.clone();
        changed[ENTRY..ENTRY + 2 * ENTRY_BYTES].copy_from_slice(&entries.concat());
        assert_eq!(read(&changed).map(|_| ()), not_canonical, "{case}");
    }
    // An entry no extent names would be a second encoding of the same manifest.
    let (single, _) = encoded_sample(None);
    let body = body_of(&single);
    let mut unused = body[..ENTRY + ENTRY_BYTES].to_vec();
    unused[TABLE..ENTRY].copy_from_slice(&2u64.to_be_bytes());
    let mut extra = body[ENTRY..ENTRY + ENTRY_BYTES].to_vec();
    extra[CHECKSUM - ENTRY] = 1;
    unused.extend_from_slice(&extra);
    unused.extend_from_slice(&body[ENTRY + ENTRY_BYTES..]);
    assert_eq!(read(&unused).map(|_| ()), not_canonical);
    // An extent naming an entry the table does not have.
    let key = single.manifest().extents.extents[2].content_key;
    let at = body
        .windows(32)
        .position(|window| window == key.digest().as_bytes())
        .unwrap();
    assert_eq!(body[at + 32], 2, "the encoded tag follows the content key");
    assert_eq!(&body[at + 33..at + 37], &0u32.to_be_bytes());
    assert_eq!(
        read(&with(&body, at + 33, &5u32.to_be_bytes())).map(|_| ()),
        Err(ManifestError::MissingCodecFormat { index: 5 })
    );
}

#[test]
fn codec_format_parameters_are_checked_before_any_decoder_runs() {
    let CodecFormat::ZstdRfc8878(frame) = ZSTD_FORMAT;
    let built = |frame: ZstdFrameParameters, dictionary: Option<&[u8]>| {
        encoded_sample_with(dictionary, |_| zstd(frame))
            .0
            .map(|_| ())
    };
    let ceiling = zstd_window_ceiling_bytes(G);
    assert_eq!(ceiling, ZSTD_MIN_WINDOW_BYTES);
    for declared_bytes in [0, ceiling + 1, u64::MAX] {
        assert_eq!(
            built(
                ZstdFrameParameters {
                    max_window_bytes: declared_bytes,
                    ..frame
                },
                None
            ),
            Err(ManifestError::InvalidWindowBound {
                declared_bytes,
                max_bytes: ceiling
            })
        );
    }
    for max_window_bytes in [1, G, ceiling] {
        assert_eq!(
            built(
                ZstdFrameParameters {
                    max_window_bytes,
                    ..frame
                },
                None
            ),
            Ok(())
        );
    }
    // A frame dictionary id needs a dictionary; a dictionary needs no id (raw content).
    let named = ZstdFrameParameters {
        dictionary_id: 7,
        ..frame
    };
    assert_eq!(
        built(named, None),
        Err(ManifestError::UndeclaredDictionary { dictionary_id: 7 })
    );
    assert_eq!(built(named, Some(b"dictionary")), Ok(()));
    assert_eq!(built(frame, Some(b"dictionary")), Ok(()));
    // The window ceiling follows the codec block size, never below 1 KiB.
    assert_eq!(zstd_window_ceiling_bytes(0), 1 << 10);
    assert_eq!(zstd_window_ceiling_bytes(1 << 10), 1 << 10);
    assert_eq!(zstd_window_ceiling_bytes((1 << 10) + 1), 1 << 11);
    assert_eq!(zstd_window_ceiling_bytes(64 << 20), 64 << 20);
    assert_eq!(zstd_window_ceiling_bytes(u64::MAX), u64::MAX);
}
