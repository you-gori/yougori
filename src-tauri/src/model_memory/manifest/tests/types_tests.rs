//! Names, paths, revisions and tensor sizes.

use super::super::*;
use super::ZSTD_FORMAT;

#[test]
fn relative_paths_cannot_name_anything_outside_their_root() {
    for good in [
        "model-00001-of-00002.safetensors",
        "sub/dir/config.json",
        "COM10.txt",
        "console.json",
        "weights/ünïcode.bin",
    ] {
        assert_eq!(RelativePath::new(good).unwrap().as_str(), good);
    }
    for (bad, error) in [
        ("", NameError::Empty),
        ("../model.safetensors", NameError::InvalidComponent),
        ("a/../../b", NameError::InvalidComponent),
        ("/etc/passwd", NameError::InvalidComponent),
        ("a//b", NameError::InvalidComponent),
        ("a/./b", NameError::InvalidComponent),
        ("trailing/", NameError::InvalidComponent),
        ("dot.", NameError::InvalidComponent),
        ("space ", NameError::InvalidComponent),
        ("con.txt", NameError::InvalidComponent),
        ("a/NUL", NameError::InvalidComponent),
        ("lpt1", NameError::InvalidComponent),
        ("a\\b", NameError::InvalidCharacter { character: '\\' }),
        ("C:model", NameError::InvalidCharacter { character: ':' }),
        (
            "a\u{0}b",
            NameError::InvalidCharacter { character: '\u{0}' },
        ),
        ("what?", NameError::InvalidCharacter { character: '?' }),
    ] {
        assert_eq!(RelativePath::new(bad), Err(error), "{bad:?}");
    }
    assert_eq!(
        RelativePath::new("a".repeat(MAX_PATH_BYTES + 1)),
        Err(NameError::TooLong {
            max_bytes: MAX_PATH_BYTES
        })
    );
    assert_eq!(
        RelativePath::new("a".repeat(MAX_PATH_COMPONENT_BYTES + 1)),
        Err(NameError::InvalidComponent)
    );
    assert_eq!(
        RelativePath::new("Model.safetensors").unwrap().folded(),
        RelativePath::new("model.SAFETENSORS").unwrap().folded()
    );
}

#[test]
fn tokens_names_and_revisions_are_checked() {
    assert!(Token::new("0.31.0+cu129").is_ok());
    assert_eq!(Token::new(""), Err(NameError::Empty));
    assert_eq!(
        Token::new("two words"),
        Err(NameError::InvalidCharacter { character: ' ' })
    );
    assert_eq!(
        Token::new("é"),
        Err(NameError::InvalidCharacter { character: 'é' })
    );
    assert!(TensorName::new("model.layers.0.self_attn.q_proj.weight").is_ok());
    assert_eq!(
        TensorName::new("a\nb"),
        Err(NameError::InvalidCharacter { character: '\n' })
    );
    let commit = "0123456789abcdef0123456789abcdef01234567";
    assert_eq!(GitCommit::from_hex(commit).unwrap().to_hex(), commit);
    for movable in ["main", "v1.0", "refs/heads/main", &commit[..39]] {
        assert_eq!(GitCommit::from_hex(movable), Err(NameError::NotACommit));
    }
}

#[test]
fn element_sizes_follow_their_bit_widths() {
    let bytes = |element, shape: &[u64]| {
        tensor_bytes(TensorDtype::Element(element), TensorLayout::RowMajor, shape)
    };
    assert_eq!(bytes(ElementType::F32, &[2, 3]), Ok(24));
    assert_eq!(bytes(ElementType::Bf16, &[4_096, 4_096]), Ok(33_554_432));
    assert_eq!(bytes(ElementType::Bool, &[5]), Ok(5));
    assert_eq!(bytes(ElementType::F8E4m3, &[7]), Ok(7));
    assert_eq!(bytes(ElementType::U64, &[3]), Ok(24));
    assert_eq!(bytes(ElementType::F4, &[4]), Ok(2));
    assert_eq!(bytes(ElementType::F4, &[3]), Err(ShapeError::NotWholeBytes));
    assert_eq!(bytes(ElementType::F6E2m3, &[4]), Ok(3));
    assert_eq!(bytes(ElementType::F32, &[]), Ok(4));
    assert_eq!(bytes(ElementType::F32, &[0, u64::MAX]), Ok(0));
    assert_eq!(bytes(ElementType::F32, &[u64::MAX, 0]), Ok(0));
    assert_eq!(
        bytes(ElementType::F32, &[u64::MAX, 2]),
        Err(ShapeError::Overflow)
    );
    assert_eq!(
        bytes(ElementType::F32, &[1 << 62]),
        Err(ShapeError::Overflow)
    );
    for element in ElementType::ALL {
        assert_eq!(
            ElementType::from_safetensors_name(element.safetensors_name()),
            Some(element)
        );
    }
    assert_eq!(ElementType::from_safetensors_name("C64"), None);
}

#[test]
fn ggml_block_sizes_follow_ggml_common() {
    let bytes = |ggml, shape: &[u64]| {
        tensor_bytes(
            TensorDtype::Ggml(ggml),
            TensorLayout::GgmlInnermostFirst,
            shape,
        )
    };
    // Q4_0: 32 elements in 18 bytes (an f16 scale and 16 bytes of nibbles).
    assert_eq!(bytes(GgmlType::Q4_0, &[64, 2]), Ok(72));
    // Q8_0: 32 elements in 34 bytes.
    assert_eq!(bytes(GgmlType::Q8_0, &[4_096, 4_096]), Ok(128 * 34 * 4_096));
    // Q4_K: 256 elements in 144 bytes.
    assert_eq!(bytes(GgmlType::Q4_K, &[256, 4_096]), Ok(589_824));
    assert_eq!(bytes(GgmlType::Q6_K, &[512]), Ok(420));
    assert_eq!(bytes(GgmlType::MXFP4, &[32, 3]), Ok(51));
    assert_eq!(
        bytes(GgmlType::Q4_0, &[48]),
        Err(ShapeError::PartialBlock { block_elements: 32 })
    );
    assert_eq!(
        tensor_bytes(
            TensorDtype::Ggml(GgmlType::Q4_0),
            TensorLayout::RowMajor,
            &[64]
        ),
        Err(ShapeError::LayoutMismatch)
    );
    assert_eq!(
        bytes(GgmlType::Q4_K, &[256, u64::MAX]),
        Err(ShapeError::Overflow)
    );
    for ggml in GgmlType::ALL {
        assert_eq!(GgmlType::from_id(ggml.id()), Some(ggml));
        assert_eq!(
            TensorDtype::from_ggml_id(ggml.id()),
            Some(TensorDtype::Ggml(ggml))
        );
    }
    assert_eq!(
        TensorDtype::from_ggml_id(0),
        Some(TensorDtype::Element(ElementType::F32))
    );
    assert_eq!(
        TensorDtype::from_ggml_id(30),
        Some(TensorDtype::Element(ElementType::Bf16))
    );
    // Removed (4, 5, 31-33, 36-38) and unknown ids are refused rather than guessed.
    for removed in [4, 5, 31, 32, 33, 36, 37, 38, 40, u32::MAX] {
        assert_eq!(TensorDtype::from_ggml_id(removed), None, "{removed}");
    }
}

#[test]
fn source_files_and_extents_share_the_content_key_of_ids() {
    let bytes = b"weights";
    // Whole files and decoded extents are named by the shared content identity, so a
    // source file's key is the key the catalog and the identity layers use.
    let key = ContentKey::of(bytes);
    assert_eq!(key, crate::foundation::ids::ContentKey::of(bytes));
    let mut streamed = crate::foundation::ids::ContentHasher::new(7);
    streamed.update(b"wei").unwrap();
    streamed.update(b"ghts").unwrap();
    assert_eq!(streamed.finish().unwrap(), key);
    assert_ne!(ContentKey::of(b"weight"), key);
    // Encoded representations have their own digest under their own domain.
    assert_ne!(
        *key.digest(),
        EncodedDigest::of(ZSTD_FORMAT, None, bytes).digest()
    );
    assert_ne!(
        EncodedDigest::of(ZSTD_FORMAT, None, bytes),
        EncodedDigest::of(ZSTD_FORMAT, Some(DictionaryId::of(b"d")), bytes)
    );
    // A content revision binds every path, length and content key.
    let file = |content: &[u8]| ListedFile {
        path: RelativePath::new("model.safetensors").unwrap(),
        length_bytes: content.len() as u64,
        content: ContentKey::of(content),
        role: FileRole::Other,
    };
    assert_eq!(
        SourceListing::content_revision(&[file(b"a")]),
        SourceListing::content_revision(&[file(b"a")])
    );
    assert_ne!(
        SourceListing::content_revision(&[file(b"a")]),
        SourceListing::content_revision(&[file(b"b")])
    );
}

#[test]
fn the_sidecar_converter_identity_is_valid() {
    let converter = sidecar_converter().unwrap();
    assert_eq!(converter.name.as_str(), SIDECAR_CONVERTER_NAME);
    assert_eq!(converter.version.as_str(), SIDECAR_CONVERTER_VERSION);
}
