//! The bounded safetensors indexer on synthetic files.

use std::fs::File;
use std::io::Cursor;

use super::super::*;
use super::{f32_bytes, pattern, raw_safetensors, safetensors_bytes, safetensors_data_start};

fn index_with(bytes: &[u8], bounds: &IndexerBounds) -> Result<IndexedFile, IndexError> {
    index_safetensors(&mut Cursor::new(bytes), bytes.len() as u64, bounds)
}

fn index(bytes: &[u8]) -> Result<IndexedFile, IndexError> {
    index_with(bytes, &IndexerBounds::DEFAULT)
}

/// A one-file header from raw JSON over an 8-byte data buffer.
fn with_header(json: &str) -> Result<IndexedFile, IndexError> {
    index(&raw_safetensors(json.as_bytes(), &[0u8; 8]))
}

fn malformed(result: Result<IndexedFile, IndexError>) -> bool {
    matches!(result, Err(IndexError::MalformedHeader { .. }))
}

#[test]
fn safetensors_offsets_are_relative_to_the_data_buffer() {
    let dir = tempfile::tempdir().unwrap();
    let first = f32_bytes(&[1.0, 2.0, 3.0, 4.0, 5.0, 6.0]);
    let second = pattern(10, 200);
    let bytes = safetensors_bytes(&[
        ("first", ElementType::F32, &[2, 3], &first),
        ("second", ElementType::U8, &[10], &second),
    ]);
    let file = dir.path().join("model.safetensors");
    std::fs::write(&file, &bytes).unwrap();
    let indexed = index_safetensors(
        &mut File::open(&file).unwrap(),
        bytes.len() as u64,
        &IndexerBounds::DEFAULT,
    )
    .unwrap();

    let data_start = safetensors_data_start(&bytes);
    assert_eq!(
        indexed.format,
        FileFormat::Safetensors {
            header_length_bytes: data_start - SAFETENSORS_PREFIX_BYTES
        }
    );
    let tensor = |wanted: &str| {
        indexed
            .tensors
            .iter()
            .find(|tensor| tensor.name.as_str() == wanted)
            .unwrap()
    };
    // The header says data_offsets [0, 24] and [24, 34]: offsets into the data buffer.
    let first_tensor = tensor("first");
    assert_eq!(first_tensor.offset_bytes, data_start);
    assert_eq!(first_tensor.true_length_bytes, 24);
    assert_eq!(first_tensor.shape, vec![2, 3]);
    assert_eq!(first_tensor.layout, TensorLayout::RowMajor);
    assert_eq!(&bytes[data_start as usize..][..24], &first[..]);
    let second_tensor = tensor("second");
    assert_eq!(second_tensor.offset_bytes, data_start + 24);
    assert_eq!(&bytes[(data_start + 24) as usize..][..10], &second[..]);
    // Read from the start of the file, the same offsets would land in the header.
    assert_ne!(&bytes[..24], &first[..]);
}

#[test]
fn safetensors_header_bounds_are_enforced_before_allocating() {
    let bytes = safetensors_bytes(&[("x", ElementType::U8, &[4], &[1, 2, 3, 4])]);
    let header_length = safetensors_data_start(&bytes) - 8;
    let tight = IndexerBounds {
        max_header_bytes: header_length - 1,
        ..IndexerBounds::DEFAULT
    };
    assert_eq!(
        index_with(&bytes, &tight),
        Err(IndexError::HeaderTooLarge {
            length_bytes: header_length,
            max_bytes: header_length - 1
        })
    );
    // A declared length of u64::MAX is refused from the prefix alone.
    let mut huge = u64::MAX.to_le_bytes().to_vec();
    huge.extend_from_slice(b"{}");
    assert_eq!(
        index(&huge),
        Err(IndexError::HeaderTooLarge {
            length_bytes: u64::MAX,
            max_bytes: IndexerBounds::DEFAULT.max_header_bytes
        })
    );
    let mut past_end = 1_000u64.to_le_bytes().to_vec();
    past_end.extend_from_slice(b"{}      ");
    assert_eq!(
        index(&past_end),
        Err(IndexError::HeaderPastEnd {
            header_end_bytes: 1_008,
            file_length_bytes: 16
        })
    );
    assert_eq!(index(&[1, 2, 3]), Err(IndexError::Truncated));
    assert_eq!(
        index_safetensors(
            &mut Cursor::new(&bytes[..20]),
            bytes.len() as u64,
            &IndexerBounds::DEFAULT
        ),
        Err(IndexError::Truncated)
    );
}

#[test]
fn malformed_safetensors_headers_are_refused() {
    let one = r#"{"x":{"dtype":"U8","shape":[8],"data_offsets":[0,8]}}"#;
    assert!(with_header(one).is_ok());
    assert_eq!(
        index(&raw_safetensors(b" {}", &[])),
        Err(IndexError::BadPadding)
    );
    assert_eq!(
        index(&raw_safetensors(b"{}\n", &[])),
        Err(IndexError::BadPadding)
    );
    assert_eq!(
        index(&raw_safetensors(b"[]", &[])),
        Err(IndexError::BadPadding)
    );
    assert!(malformed(with_header(r#"{"x":}"#)));
    assert!(malformed(with_header(r#"{} {}"#)));
    assert_eq!(
        with_header(
            r#"{"x":{"dtype":"U8","shape":[4],"data_offsets":[0,4]},"x":{"dtype":"U8","shape":[4],"data_offsets":[4,8]}}"#
        ),
        Err(IndexError::DuplicateTensor {
            name: "x".to_owned()
        })
    );
    assert_eq!(
        index(&raw_safetensors(
            br#"{"__metadata__":{"format":"pt","format":"np"}}"#,
            &[]
        )),
        Err(IndexError::DuplicateMetadataKey {
            key: "format".to_owned()
        })
    );
    assert!(malformed(index(&raw_safetensors(
        br#"{"__metadata__":{"format":1}}"#,
        &[]
    ))));
    assert_eq!(
        with_header(r#"{"x":{"dtype":"C64","shape":[1],"data_offsets":[0,8]}}"#),
        Err(IndexError::UnknownDtype {
            dtype: "C64".to_owned()
        })
    );
    assert!(malformed(with_header(
        r#"{"x":{"dtype":"U8","shape":[8],"data_offsets":[0,8],"extra":1}}"#
    )));
    assert!(malformed(with_header(
        r#"{"x":{"dtype":"U8","shape":[8],"data_offsets":[0,4,8]}}"#
    )));
    assert!(malformed(with_header(
        r#"{"x":{"dtype":"U8","shape":[-8],"data_offsets":[0,8]}}"#
    )));
    assert_eq!(
        with_header(r#"{"x":{"dtype":"U8","shape":[8],"data_offsets":[8,0]}}"#),
        Err(IndexError::OffsetsReversed {
            name: "x".to_owned()
        })
    );
    assert_eq!(
        with_header(r#"{"x":{"dtype":"U8","shape":[16],"data_offsets":[0,16]}}"#),
        Err(IndexError::OutOfBounds {
            name: "x".to_owned()
        })
    );
    assert_eq!(
        with_header(r#"{"x":{"dtype":"U8","shape":[4],"data_offsets":[0,8]}}"#),
        Err(IndexError::LengthMismatch {
            name: "x".to_owned(),
            declared_bytes: 8,
            expected_bytes: 4
        })
    );
    assert_eq!(
        with_header(r#"{"x":{"dtype":"F4","shape":[3],"data_offsets":[0,1]}}"#),
        Err(IndexError::Shape {
            name: "x".to_owned(),
            error: ShapeError::NotWholeBytes
        })
    );
}

#[test]
fn the_data_buffer_is_indexed_entirely_without_holes_or_overlaps() {
    assert_eq!(
        with_header(r#"{"x":{"dtype":"U8","shape":[4],"data_offsets":[4,8]}}"#),
        Err(IndexError::Hole { at_bytes: 0 })
    );
    assert_eq!(
        with_header(r#"{"x":{"dtype":"U8","shape":[4],"data_offsets":[0,4]}}"#),
        Err(IndexError::Hole { at_bytes: 4 })
    );
    assert_eq!(
        with_header(
            r#"{"x":{"dtype":"U8","shape":[8],"data_offsets":[0,8]},"y":{"dtype":"U8","shape":[4],"data_offsets":[4,8]}}"#
        ),
        Err(IndexError::Overlap { at_bytes: 4 })
    );
    // An empty tensor takes no bytes and may sit at a boundary.
    let with_empty = with_header(
        r#"{"empty":{"dtype":"F32","shape":[0,3],"data_offsets":[8,8]},"x":{"dtype":"U8","shape":[8],"data_offsets":[0,8]}}"#,
    )
    .unwrap();
    assert_eq!(with_empty.tensors.len(), 2);
    assert_eq!(with_empty.tensors[0].true_length_bytes, 0);
    assert_eq!(
        index(&raw_safetensors(b"{}", &[])).unwrap().tensors,
        Vec::new()
    );
    assert_eq!(
        index(&raw_safetensors(b"{}", &[0])),
        Err(IndexError::Hole { at_bytes: 0 })
    );
}

#[test]
fn safetensors_header_limits_are_enforced() {
    let two = r#"{"x":{"dtype":"U8","shape":[4],"data_offsets":[0,4]},"y":{"dtype":"U8","shape":[1,1,4],"data_offsets":[4,8]}}"#;
    let bytes = raw_safetensors(two.as_bytes(), &[0u8; 8]);
    assert_eq!(
        index_with(
            &bytes,
            &IndexerBounds {
                max_tensors: 1,
                ..IndexerBounds::DEFAULT
            }
        ),
        Err(IndexError::TooManyTensors { max: 1 })
    );
    assert_eq!(
        index_with(
            &bytes,
            &IndexerBounds {
                max_dimensions: 2,
                ..IndexerBounds::DEFAULT
            }
        ),
        Err(IndexError::TooManyDimensions { found: 3, max: 2 })
    );
    let long = r#"{"long":{"dtype":"U8","shape":[8],"data_offsets":[0,8]}}"#;
    assert_eq!(
        index_with(
            &raw_safetensors(long.as_bytes(), &[0u8; 8]),
            &IndexerBounds {
                max_name_bytes: 3,
                ..IndexerBounds::DEFAULT
            }
        ),
        Err(IndexError::NameTooLong {
            found_bytes: 4,
            max_bytes: 3
        })
    );
    assert_eq!(
        with_header(r#"{"a\u0001b":{"dtype":"U8","shape":[8],"data_offsets":[0,8]}}"#),
        Err(IndexError::InvalidName {
            error: NameError::InvalidCharacter { character: '\u{1}' }
        })
    );
}
