//! The bounded GGUF indexer on synthetic files.

use std::fs::File;
use std::io::Cursor;

use super::super::*;
use super::{f32_bytes, pattern, GgufFile};

const F32: u32 = 0;
const Q4_0: u32 = 2;
const BF16: u32 = 30;

fn index_with(bytes: &[u8], bounds: &IndexerBounds) -> Result<IndexedFile, IndexError> {
    index_gguf(&mut Cursor::new(bytes), bytes.len() as u64, bounds)
}

fn index(bytes: &[u8]) -> Result<IndexedFile, IndexError> {
    index_with(bytes, &IndexerBounds::DEFAULT)
}

fn model() -> GgufFile {
    GgufFile::new()
        .kv_string("general.architecture", "llama")
        .kv_alignment(64)
        .kv_strings("tokenizer.ggml.tokens", &["<s>", "</s>", "hello"])
        .kv_f32s("tokenizer.ggml.scores", &[0.0, 0.0, -1.5])
        .tensor("token_embd.weight", &[4, 2], F32, f32_bytes(&[0.5; 8]))
        .tensor("blk.0.attn_q.weight", &[64, 2], Q4_0, pattern(72, 1))
        .tensor("output_norm.weight", &[3], BF16, pattern(6, 9))
}

fn metadata_digest(file: &IndexedFile) -> crate::foundation::ids::Digest {
    match file.format {
        FileFormat::Gguf {
            metadata_digest, ..
        } => metadata_digest,
        other => panic!("not GGUF: {other:?}"),
    }
}

/// A file with one Q4_0 tensor of 32 elements (18 bytes).
fn base() -> GgufFile {
    GgufFile::new()
        .kv_string("general.architecture", "llama")
        .tensor("w", &[32], Q4_0, pattern(18, 0))
}

#[test]
fn a_synthetic_gguf_file_is_indexed() {
    let dir = tempfile::tempdir().unwrap();
    let (bytes, data_start) = model().build();
    let path = dir.path().join("model.gguf");
    std::fs::write(&path, &bytes).unwrap();
    let indexed = index_gguf(
        &mut File::open(&path).unwrap(),
        bytes.len() as u64,
        &IndexerBounds::DEFAULT,
    )
    .unwrap();
    let FileFormat::Gguf {
        version,
        alignment_bytes,
        data_offset_bytes,
        ..
    } = indexed.format
    else {
        panic!("{:?}", indexed.format);
    };
    assert_eq!((version, alignment_bytes), (3, 64));
    assert_eq!(data_offset_bytes, data_start);
    assert_eq!(data_start % 64, 0);
    // Offsets are relative to the aligned data section, each tensor padded to 64 bytes:
    // 32 bytes at 0, 72 bytes at 64 (padded to 128), 6 bytes at 192.
    let expected = [
        (
            "token_embd.weight",
            TensorDtype::Element(ElementType::F32),
            vec![4, 2],
            0,
            32,
        ),
        (
            "blk.0.attn_q.weight",
            TensorDtype::Ggml(GgmlType::Q4_0),
            vec![64, 2],
            64,
            72,
        ),
        (
            "output_norm.weight",
            TensorDtype::Element(ElementType::Bf16),
            vec![3],
            192,
            6,
        ),
    ];
    assert_eq!(indexed.tensors.len(), expected.len());
    for (tensor, (name, dtype, shape, offset, length)) in indexed.tensors.iter().zip(expected) {
        assert_eq!(tensor.name.as_str(), name);
        assert_eq!(tensor.dtype, dtype);
        assert_eq!(tensor.shape, shape);
        assert_eq!(tensor.layout, TensorLayout::GgmlInnermostFirst);
        assert_eq!(tensor.offset_bytes, data_start + offset);
        assert_eq!(tensor.true_length_bytes, length);
    }
    assert_eq!(bytes.len() as u64, data_start + 256);
    assert_eq!(
        &bytes[(data_start + 64) as usize..][..72],
        &pattern(72, 1)[..]
    );

    // The metadata digest covers the metadata alone.
    let renamed = model().kv_string("general.name", "tiny");
    assert_ne!(
        metadata_digest(&index(&renamed.bytes()).unwrap()),
        metadata_digest(&indexed)
    );
    let mut other_data = model();
    other_data.tensors[0].data = f32_bytes(&[1.5; 8]);
    assert_eq!(
        metadata_digest(&index(&other_data.bytes()).unwrap()),
        metadata_digest(&indexed)
    );
}

#[test]
fn gguf_version_2_and_the_default_alignment_are_read() {
    let mut file = GgufFile::new()
        .kv_string("general.architecture", "llama")
        .tensor("w", &[8], F32, f32_bytes(&[1.0; 8]));
    file.version = 2;
    let (bytes, data_start) = file.build();
    let indexed = index(&bytes).unwrap();
    assert_eq!(
        indexed.format,
        FileFormat::Gguf {
            version: 2,
            alignment_bytes: GGUF_DEFAULT_ALIGNMENT_BYTES,
            data_offset_bytes: data_start,
            metadata_digest: metadata_digest(&indexed),
        }
    );
    // A vocabulary-only file has metadata and no tensors.
    let vocabulary = GgufFile::new().kv_strings("tokenizer.ggml.tokens", &["a", "b"]);
    assert!(index(&vocabulary.bytes()).unwrap().tensors.is_empty());
}

#[test]
fn malformed_gguf_headers_are_refused() {
    let mut file = base();
    file.magic = *b"GGML";
    assert_eq!(index(&file.bytes()), Err(IndexError::BadMagic));
    let mut file = base();
    file.version = 3u32.swap_bytes();
    assert_eq!(index(&file.bytes()), Err(IndexError::BigEndian));
    file.version = 1;
    assert_eq!(
        index(&file.bytes()),
        Err(IndexError::UnsupportedVersion { version: 1 })
    );

    let nested = {
        let mut value = 9u32.to_le_bytes().to_vec();
        value.extend_from_slice(&1u64.to_le_bytes());
        value
    };
    assert_eq!(
        index(&base().raw_kv("x", 9, nested).bytes()),
        Err(IndexError::NestedArray)
    );
    assert_eq!(
        index(&base().raw_kv("x", 13, Vec::new()).bytes()),
        Err(IndexError::InvalidValueType { value_type: 13 })
    );
    let bad_elements = {
        let mut value = 13u32.to_le_bytes().to_vec();
        value.extend_from_slice(&0u64.to_le_bytes());
        value
    };
    assert_eq!(
        index(&base().raw_kv("x", 9, bad_elements).bytes()),
        Err(IndexError::InvalidValueType { value_type: 13 })
    );
    assert_eq!(
        index(
            &base()
                .raw_kv("general.alignment", 10, 32u64.to_le_bytes().to_vec())
                .bytes()
        ),
        Err(IndexError::AlignmentType)
    );
    for alignment in [0u32, 48] {
        assert_eq!(
            index(&base().kv_u32("general.alignment", alignment).bytes()),
            Err(IndexError::InvalidAlignment {
                alignment: alignment.into()
            })
        );
    }
    assert_eq!(
        index(&base().kv_string("general.architecture", "qwen2").bytes()),
        Err(IndexError::DuplicateMetadataKey {
            key: "general.architecture".to_owned()
        })
    );
    // Keys are not restricted to a character set (ggml does not restrict them either),
    // but they must be UTF-8.
    assert!(index(
        &base()
            .raw_kv("bad\u{0}", 4, 1u32.to_le_bytes().to_vec())
            .bytes()
    )
    .is_ok());
    let mut bad_key = base();
    bad_key.metadata[0].0 = vec![0xff, 0xfe];
    assert!(matches!(
        index(&bad_key.bytes()),
        Err(IndexError::MalformedHeader { .. })
    ));
}

#[test]
fn malformed_gguf_tensor_infos_are_refused() {
    assert_eq!(
        index(&base().tensor("w", &[32], Q4_0, pattern(18, 0)).bytes()),
        Err(IndexError::DuplicateTensor {
            name: "w".to_owned()
        })
    );
    assert_eq!(
        index(
            &base()
                .tensor(&"n".repeat(64), &[8], F32, f32_bytes(&[0.0; 8]))
                .bytes()
        ),
        Err(IndexError::NameTooLong {
            found_bytes: 64,
            max_bytes: GGUF_MAX_TENSOR_NAME_BYTES
        })
    );
    assert!(index(
        &base()
            .tensor(&"n".repeat(63), &[8], F32, f32_bytes(&[0.0; 8]))
            .bytes()
    )
    .is_ok());
    assert_eq!(
        index(
            &base()
                .tensor("five", &[1, 1, 1, 1, 8], F32, f32_bytes(&[0.0; 8]))
                .bytes()
        ),
        Err(IndexError::TooManyDimensions { found: 5, max: 4 })
    );
    assert_eq!(
        index(&base().tensor("removed", &[32], 4, pattern(20, 0)).bytes()),
        Err(IndexError::UnsupportedGgmlType { id: 4 })
    );
    assert_eq!(
        index(
            &base()
                .tensor("partial", &[48], Q4_0, pattern(27, 0))
                .bytes()
        ),
        Err(IndexError::Shape {
            name: "partial".to_owned(),
            error: ShapeError::PartialBlock { block_elements: 32 }
        })
    );
    assert_eq!(
        index(&base().tensor("huge", &[1 << 63], F32, Vec::new()).bytes()),
        Err(IndexError::Shape {
            name: "huge".to_owned(),
            error: ShapeError::Overflow
        })
    );
}

#[test]
fn gguf_data_must_be_contiguous_in_bounds_and_end_at_the_padding() {
    let mut moved = base();
    moved.tensors[0].offset = Some(32);
    assert_eq!(
        index(&moved.bytes()),
        Err(IndexError::UnexpectedOffset {
            name: "w".to_owned(),
            offset_bytes: 32,
            expected_bytes: 0
        })
    );
    let mut overlapping = base().tensor("v", &[32], Q4_0, pattern(18, 5));
    overlapping.tensors[1].offset = Some(0);
    assert_eq!(
        index(&overlapping.bytes()),
        Err(IndexError::UnexpectedOffset {
            name: "v".to_owned(),
            offset_bytes: 0,
            expected_bytes: 32
        })
    );
    let (bytes, data_start) = base().build();
    let cut = (data_start + 10) as usize;
    assert_eq!(
        index(&bytes[..cut]),
        Err(IndexError::OutOfBounds {
            name: "w".to_owned()
        })
    );
    // The final padding may be absent, but nothing may follow it.
    assert!(index(&bytes[..(data_start + 18) as usize]).is_ok());
    let mut trailing = base();
    trailing.trailing = vec![0; 32];
    assert_eq!(
        index(&trailing.bytes()),
        Err(IndexError::TrailingBytes {
            data_end_bytes: data_start + 32,
            file_length_bytes: data_start + 64
        })
    );
}

#[test]
fn gguf_bounds_are_enforced_before_allocating() {
    let bytes = model().bytes();
    let bound = |bounds: IndexerBounds| index_with(&bytes, &bounds);
    assert_eq!(
        bound(IndexerBounds {
            max_tensors: 2,
            ..IndexerBounds::DEFAULT
        }),
        Err(IndexError::TooManyTensors { max: 2 })
    );
    assert_eq!(
        bound(IndexerBounds {
            max_metadata_entries: 3,
            ..IndexerBounds::DEFAULT
        }),
        Err(IndexError::TooManyMetadataEntries { found: 4, max: 3 })
    );
    assert_eq!(
        bound(IndexerBounds {
            max_string_bytes: 4,
            ..IndexerBounds::DEFAULT
        }),
        Err(IndexError::StringTooLong { found: 5, max: 4 })
    );
    assert_eq!(
        bound(IndexerBounds {
            max_array_elements: 2,
            ..IndexerBounds::DEFAULT
        }),
        Err(IndexError::ArrayTooLong { found: 3, max: 2 })
    );
    assert!(matches!(
        bound(IndexerBounds {
            max_header_bytes: 40,
            ..IndexerBounds::DEFAULT
        }),
        Err(IndexError::HeaderTooLarge { max_bytes: 40, .. })
    ));
    assert_eq!(index(&bytes[..30]), Err(IndexError::Truncated));

    // Lengths claiming far more than the file holds fail before any buffer is made.
    let mut claim = 1u64 << 60;
    let huge_string = base().raw_kv("x", 8, claim.to_le_bytes().to_vec());
    assert_eq!(
        index(&huge_string.bytes()),
        Err(IndexError::StringTooLong {
            found: claim,
            max: IndexerBounds::DEFAULT.max_string_bytes
        })
    );
    // Under the widest bounds an indexer accepts, claims within them but beyond the file
    // are still refused before any buffer is made.
    let widest = IndexerBounds::CEILING;
    claim = 1 << 29;
    let large_string = base().raw_kv("x", 8, claim.to_le_bytes().to_vec());
    assert_eq!(
        index_with(&large_string.bytes(), &widest),
        Err(IndexError::Truncated)
    );
    let mut large_array = 0u32.to_le_bytes().to_vec();
    large_array.extend_from_slice(&claim.to_le_bytes());
    assert_eq!(
        index_with(&base().raw_kv("x", 9, large_array).bytes(), &widest),
        Err(IndexError::Truncated)
    );
}
