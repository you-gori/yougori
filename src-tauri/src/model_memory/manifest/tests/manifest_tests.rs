//! The manifest: canonical encoding, authentication of shape, offset and codec, and every
//! validation rule of §3.3 tried and refused.

use super::super::*;
use super::fakes::{BombDecoder, RunLengthStandIn, ShortDecoder};
use super::{
    description, name, path, pattern, tensor_parallel, token, SAFETENSORS_WEIGHTS, ZSTD_FORMAT,
};
use crate::foundation::ids::{digest, DigestBuilder};

/// Integrity-extent size g_h of these manifests.
pub(super) const G: u64 = 64;
const CONFIG: u32 = 0;
pub(super) const WEIGHTS: u32 = 1;
const SAFETENSORS_HEADER: FileFormat = FileFormat::Safetensors {
    header_length_bytes: 56,
};

fn config_bytes() -> Vec<u8> {
    pattern(100, 3)
}

/// 192 bytes: an 8-byte prefix and 56-byte header region, then two 64-byte tensors.
pub(super) fn weights_bytes() -> Vec<u8> {
    (0..192u32).map(|index| (index / 16) as u8).collect()
}

pub(super) fn chunks(bytes: &[u8]) -> Vec<Vec<u8>> {
    bytes.chunks(G as usize).map(<[u8]>::to_vec).collect()
}

fn new_builder(description: ArtifactDescription) -> ManifestBuilder {
    ManifestBuilder::new(
        SourceOrigin::LocalFolder,
        sidecar_converter().unwrap(),
        description,
    )
}

fn source_file(file: &str, bytes: &[u8], role: FileRole, format: FileFormat) -> SourceFileInput {
    SourceFileInput {
        path: path(file),
        length_bytes: bytes.len() as u64,
        content: ContentKey::of(bytes),
        role,
        format,
    }
}

/// Adds a file and its raw extents of `G` bytes; returns the extents' stored bytes.
fn add_raw_file(
    builder: &mut ManifestBuilder,
    file: &str,
    bytes: &[u8],
    role: FileRole,
    format: FileFormat,
) -> Vec<Vec<u8>> {
    builder
        .add_source_file(source_file(file, bytes, role, format))
        .unwrap();
    let stored = chunks(bytes);
    for (index, chunk) in stored.iter().enumerate() {
        builder.add_extent(ExtentInput {
            file: path(file),
            logical_offset_bytes: index as u64 * G,
            true_length_bytes: chunk.len() as u64,
            content_key: ContentKey::of(chunk),
            encoding: EncodingInput::Raw,
        });
    }
    stored
}

/// Adds a file whose extents are stored encoded in `prepared`, extent `i` declaring
/// `format(i)`; returns the encoded bytes.
fn add_encoded_file(
    builder: &mut ManifestBuilder,
    file: &str,
    bytes: &[u8],
    prepared: &str,
    dictionary: Option<&[u8]>,
    format: impl Fn(usize) -> CodecFormat,
) -> Vec<Vec<u8>> {
    builder
        .add_source_file(source_file(
            file,
            bytes,
            SAFETENSORS_WEIGHTS,
            SAFETENSORS_HEADER,
        ))
        .unwrap();
    let dictionary = dictionary.map(DictionaryId::of);
    let encoded: Vec<Vec<u8>> = chunks(bytes)
        .iter()
        .map(|chunk| RunLengthStandIn::encode(chunk))
        .collect();
    let total: usize = encoded.iter().map(Vec::len).sum();
    builder
        .add_prepared_file(path(prepared), total as u64)
        .unwrap();
    builder.set_codec_block_bytes(G);
    let mut offset_bytes = 0u64;
    for (index, (chunk, stored)) in chunks(bytes).iter().zip(&encoded).enumerate() {
        builder.add_extent(ExtentInput {
            file: path(file),
            logical_offset_bytes: index as u64 * G,
            true_length_bytes: chunk.len() as u64,
            content_key: ContentKey::of(chunk),
            encoding: EncodingInput::Encoded {
                format: format(index),
                dictionary,
                prepared_file: path(prepared),
                offset_bytes,
                length_bytes: stored.len() as u64,
                digest: EncodedDigest::of(format(index), dictionary, stored),
            },
        });
        offset_bytes += stored.len() as u64;
    }
    encoded
}

fn tensor(
    tensor: &str,
    file: &str,
    offset_bytes: u64,
    shape: &[u64],
    owner: TensorOwner,
) -> TensorInput {
    let dtype = TensorDtype::Element(ElementType::F32);
    TensorInput {
        name: name(tensor),
        file: path(file),
        offset_bytes,
        true_length_bytes: tensor_bytes(dtype, TensorLayout::RowMajor, shape).unwrap(),
        dtype,
        shape: shape.to_vec(),
        layout: TensorLayout::RowMajor,
        owner,
    }
}

fn add_tensors(builder: &mut ManifestBuilder) {
    builder
        .add_tensor(tensor(
            "a",
            "model.safetensors",
            64,
            &[4, 4],
            TensorOwner::Replicated,
        ))
        .unwrap();
    builder
        .add_tensor(tensor(
            "b",
            "model.safetensors",
            128,
            &[16],
            TensorOwner::Replicated,
        ))
        .unwrap();
}

/// config.json (100 bytes, two extents) and model.safetensors (192 bytes, three extents)
/// holding tensors `a` (F32 4×4 at 64) and `b` (F32 16 at 128).
fn sample_builder() -> ManifestBuilder {
    let mut builder = new_builder(description(Distribution::SINGLE, G));
    add_raw_file(
        &mut builder,
        "config.json",
        &config_bytes(),
        FileRole::Configuration,
        FileFormat::Opaque,
    );
    add_raw_file(
        &mut builder,
        "model.safetensors",
        &weights_bytes(),
        SAFETENSORS_WEIGHTS,
        SAFETENSORS_HEADER,
    );
    add_tensors(&mut builder);
    builder
}

pub(super) fn sample() -> ValidatedManifest {
    sample_builder().finish().unwrap()
}

/// The sample with the weights stored encoded under [`ZSTD_FORMAT`]; returns every
/// extent's stored bytes in extent order.
pub(super) fn encoded_sample(dictionary: Option<&[u8]>) -> (ValidatedManifest, Vec<Vec<u8>>) {
    let (manifest, stored) = encoded_sample_with(dictionary, |_| ZSTD_FORMAT);
    (manifest.unwrap(), stored)
}

/// The sample with the weights stored encoded, extent `i` of the weights declaring
/// `format(i)`; the built manifest or its refusal, and every extent's stored bytes.
pub(super) fn encoded_sample_with(
    dictionary: Option<&[u8]>,
    format: impl Fn(usize) -> CodecFormat,
) -> (Result<ValidatedManifest, ManifestError>, Vec<Vec<u8>>) {
    let mut builder = new_builder(description(Distribution::SINGLE, G));
    let mut stored = add_raw_file(
        &mut builder,
        "config.json",
        &config_bytes(),
        FileRole::Configuration,
        FileFormat::Opaque,
    );
    stored.extend(add_encoded_file(
        &mut builder,
        "model.safetensors",
        &weights_bytes(),
        "prepared/model.zst",
        dictionary,
        format,
    ));
    add_tensors(&mut builder);
    (builder.finish(), stored)
}

pub(super) fn revalidate_from(
    manifest: &ValidatedManifest,
    change: impl FnOnce(&mut Manifest),
) -> Result<ValidatedManifest, ManifestError> {
    let mut manifest = manifest.manifest().clone();
    change(&mut manifest);
    manifest.validate()
}

fn revalidate(change: impl FnOnce(&mut Manifest)) -> Result<ValidatedManifest, ManifestError> {
    revalidate_from(&sample(), change)
}

pub(super) fn reseal(body: &[u8]) -> Vec<u8> {
    let mut sidecar = body.to_vec();
    sidecar.extend_from_slice(
        DigestBuilder::new(MANIFEST_DOMAIN)
            .bytes(body)
            .finish()
            .as_bytes(),
    );
    sidecar
}

#[test]
fn the_manifest_carries_the_ten_field_groups() {
    let manifest = sample();
    let m = manifest.manifest();
    assert_eq!(m.schema, SchemaGroup::current(ManifestBounds::DEFAULT));
    assert_eq!(m.schema.byte_order, ByteOrder::BigEndian);
    assert_eq!(m.provenance.files.len(), 2);
    assert_eq!(m.provenance.converter.name.as_str(), SIDECAR_CONVERTER_NAME);
    assert!(matches!(
        m.provenance.revision,
        SourceRevision::ContentListing(_)
    ));
    assert_eq!(m.semantics.compute_dtype, ElementType::Bf16);
    assert_eq!(m.execution_abi.runner.to_string(), "vLLM 0.31.0");
    assert_eq!(m.distribution, Distribution::SINGLE);
    assert_eq!(m.tensor_index.tensors.len(), 2);
    assert_eq!(m.state, StateGroup::default());
    assert_eq!(m.extents.extents.len(), 5);
    assert_eq!(
        m.extents.extents[1].true_length_bytes, 36,
        "true-length tail"
    );
    assert_eq!(m.integrity.extent_roots.len(), 2);
    assert_eq!(
        m.lifecycle.storage,
        StorageAccounting {
            referenced_source_bytes: 292,
            owned_representation_bytes: 0,
        }
    );
    assert_eq!(
        m.lifecycle.migration,
        MigrationRequirement::ReindexFromSources
    );
    assert!(manifest.tensor("missing").is_none());
    assert_eq!(manifest.tensor("b").unwrap().offset_bytes, 128);
}

#[test]
fn canonical_encoding_is_independent_of_build_order() {
    let forward = sample();

    let mut abi = super::abi();
    abi.kernels = vec![token("marlin"), token("cutlass")];
    abi.hardware = HardwareRestriction::ComputeCapabilities(vec![
        ComputeCapability { major: 9, minor: 0 },
        ComputeCapability { major: 8, minor: 9 },
    ]);
    let quantization = |parameters: &[(&str, &str)]| Quantization::Method {
        method: token("awq"),
        parameters: parameters
            .iter()
            .map(|(key, value)| (token(key), token(value)))
            .collect(),
    };
    let ordered = |reverse: bool| {
        let mut description = description(Distribution::SINGLE, G);
        description.execution_abi = abi.clone();
        if reverse {
            description.execution_abi.kernels.reverse();
            if let HardwareRestriction::ComputeCapabilities(list) =
                &mut description.execution_abi.hardware
            {
                list.reverse();
            }
            description.quantization = quantization(&[("zero_point", "true"), ("bits", "4")]);
        } else {
            description.quantization = quantization(&[("bits", "4"), ("zero_point", "true")]);
        }
        description
    };

    let mut first = new_builder(ordered(false));
    add_raw_file(
        &mut first,
        "config.json",
        &config_bytes(),
        FileRole::Configuration,
        FileFormat::Opaque,
    );
    add_raw_file(
        &mut first,
        "model.safetensors",
        &weights_bytes(),
        SAFETENSORS_WEIGHTS,
        SAFETENSORS_HEADER,
    );
    add_tensors(&mut first);
    first
        .add_alias(TensorAlias {
            name: name("lm_head.weight"),
            target: name("a"),
        })
        .unwrap();
    first.add_persistent_buffer(name("b")).unwrap();

    let mut second = new_builder(ordered(true));
    second.add_persistent_buffer(name("b")).unwrap();
    second
        .add_tensor(tensor(
            "b",
            "model.safetensors",
            128,
            &[16],
            TensorOwner::Replicated,
        ))
        .unwrap();
    second
        .add_alias(TensorAlias {
            name: name("lm_head.weight"),
            target: name("a"),
        })
        .unwrap();
    for (file, bytes, role, format) in [
        (
            "model.safetensors",
            weights_bytes(),
            SAFETENSORS_WEIGHTS,
            SAFETENSORS_HEADER,
        ),
        (
            "config.json",
            config_bytes(),
            FileRole::Configuration,
            FileFormat::Opaque,
        ),
    ] {
        second
            .add_source_file(source_file(file, &bytes, role, format))
            .unwrap();
        for (index, chunk) in chunks(&bytes).iter().enumerate().rev() {
            second.add_extent(ExtentInput {
                file: path(file),
                logical_offset_bytes: index as u64 * G,
                true_length_bytes: chunk.len() as u64,
                content_key: ContentKey::of(chunk),
                encoding: EncodingInput::Raw,
            });
        }
    }
    second
        .add_tensor(tensor(
            "a",
            "model.safetensors",
            64,
            &[4, 4],
            TensorOwner::Replicated,
        ))
        .unwrap();

    let (first, second) = (first.finish().unwrap(), second.finish().unwrap());
    assert_eq!(first.sidecar_bytes(), second.sidecar_bytes());
    assert_eq!(first.digest(), second.digest());
    assert_ne!(first.digest(), forward.digest());
    assert_eq!(first.tensor("lm_head.weight").unwrap().name, name("a"));
}

#[test]
fn the_sidecar_round_trips_and_has_one_encoding() {
    let manifest = sample();
    let sidecar = manifest.sidecar_bytes();
    assert_eq!(&sidecar[..8], &MANIFEST_MAGIC);
    let body = &sidecar[..sidecar.len() - SIDECAR_DIGEST_BYTES];
    assert_eq!(
        &sidecar[sidecar.len() - SIDECAR_DIGEST_BYTES..],
        manifest.digest().digest().as_bytes()
    );
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&sidecar),
        Ok(manifest.clone())
    );
    let (encoded, _) = encoded_sample(Some(b"dictionary"));
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&encoded.sidecar_bytes()),
        Ok(encoded.clone())
    );

    let mut flipped = sidecar.clone();
    flipped[40] ^= 1;
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&flipped),
        Err(ManifestError::DigestMismatch)
    );
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&sidecar[..10]),
        Err(ManifestError::Truncated)
    );
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&sidecar[..200]),
        Err(ManifestError::DigestMismatch)
    );

    let tampered = |offset: usize, bytes: &[u8]| {
        let mut body = body.to_vec();
        body[offset..offset + bytes.len()].copy_from_slice(bytes);
        ValidatedManifest::from_sidecar_bytes(&reseal(&body))
    };
    assert_eq!(tampered(0, b"X"), Err(ManifestError::BadMagic));
    // Versions 1 and 2 bound source files or codecs otherwise; they need a re-import and
    // are never reread. Any other version is unknown.
    assert_eq!(MANIFEST_SCHEMA_VERSION, 3);
    for earlier in [1u16, 2] {
        assert_eq!(
            tampered(8, &earlier.to_be_bytes()),
            Err(ManifestError::NeedsReimport {
                schema_version: earlier
            })
        );
    }
    for unknown in [0u16, 4, u16::MAX] {
        assert_eq!(
            tampered(8, &unknown.to_be_bytes()),
            Err(ManifestError::UnsupportedSchemaVersion { found: unknown })
        );
    }
    assert_eq!(
        tampered(10, &9u16.to_be_bytes()),
        Err(ManifestError::UnsupportedEncodingVersion { found: 9 })
    );
    assert_eq!(
        tampered(12, &[2]),
        Err(ManifestError::UnsupportedByteOrder { code: 2 })
    );
    assert_eq!(
        tampered(13, &u32::MAX.to_be_bytes()),
        Err(ManifestError::BoundsAboveCeiling {
            bound: "max_files",
            declared: u32::MAX.into(),
            ceiling: ManifestBounds::CEILING.max_files.into(),
        })
    );
    // After the bounds, the empty codec table of a manifest without encoded extents.
    let origin_tag = 8 + 2 + 2 + 1 + 6 * 4 + 2 * 8 + 8;
    assert_eq!(
        tampered(origin_tag, &[9]),
        Err(ManifestError::UnknownTag {
            field: "origin",
            tag: 9
        })
    );
    let mut trailing = body.to_vec();
    trailing.push(0);
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&reseal(&trailing)),
        Err(ManifestError::TrailingBytes)
    );
    assert_eq!(
        ValidatedManifest::from_sidecar_bytes(&reseal(&body[..body.len() - 1])),
        Err(ManifestError::Truncated)
    );
    let strict = ManifestBounds {
        max_files: 1,
        ..ManifestBounds::DEFAULT
    };
    assert!(matches!(
        ValidatedManifest::from_sidecar_bytes_within(&sidecar, &strict),
        Err(ManifestError::BoundsAboveCeiling {
            bound: "max_files",
            ..
        })
    ));
}

#[test]
fn shape_offset_or_codec_changes_the_digest_at_identical_payload() {
    let original = sample();
    let payload = original.manifest().integrity.decoded_content_identity;

    let reshaped = revalidate(|m| m.tensor_index.tensors[0].shape = vec![2, 8]).unwrap();
    let moved = revalidate(|m| {
        let tensors = &mut m.tensor_index.tensors;
        let (a, b) = (tensors[0].offset_bytes, tensors[1].offset_bytes);
        tensors[0].offset_bytes = b;
        tensors[1].offset_bytes = a;
    })
    .unwrap();
    let (encoded, _) = encoded_sample(None);
    let (with_dictionary, _) = encoded_sample(Some(b"dictionary"));

    let changed = [&reshaped, &moved, &encoded, &with_dictionary];
    for (index, manifest) in changed.iter().enumerate() {
        assert_ne!(manifest.digest(), original.digest(), "change {index}");
        // A payload-only identity cannot tell any of them apart.
        assert_eq!(
            manifest.manifest().integrity.decoded_content_identity,
            payload,
            "change {index}"
        );
        for other in &changed[index + 1..] {
            assert_ne!(manifest.digest(), other.digest());
        }
    }
    let weights_root = |manifest: &ValidatedManifest| manifest.extent_root(SourceFileId(WEIGHTS));
    assert_ne!(weights_root(&encoded), weights_root(&original));
    assert_ne!(weights_root(&encoded), weights_root(&with_dictionary));
    assert_eq!(weights_root(&reshaped), weights_root(&original));
}

#[test]
fn overlapping_ranges_are_refused() {
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[1].offset_bytes = 100).unwrap_err(),
        ManifestError::OverlappingRanges {
            ranges: "tensors",
            file: WEIGHTS,
            offset_bytes: 100,
        }
    );
    assert_eq!(
        revalidate(|m| {
            let duplicate = m.extents.extents[3];
            m.extents.extents.insert(3, duplicate);
        })
        .unwrap_err(),
        ManifestError::OverlappingRanges {
            ranges: "extents",
            file: WEIGHTS,
            offset_bytes: 64,
        }
    );
    let (encoded, _) = encoded_sample(None);
    let overlapped = revalidate_from(&encoded, |m| {
        if let ExtentEncoding::Encoded(representation) = &mut m.extents.extents[3].encoding {
            representation.location.offset_bytes -= 1;
        }
    });
    assert!(matches!(
        overlapped,
        Err(ManifestError::OverlappingRanges {
            ranges: "encoded extents",
            file: 0,
            ..
        })
    ));
}

#[test]
fn duplicate_names_are_refused() {
    let mut builder = sample_builder();
    assert_eq!(
        builder.add_tensor(tensor(
            "a",
            "model.safetensors",
            64,
            &[16],
            TensorOwner::Replicated
        )),
        Err(ManifestError::DuplicateName {
            name: "a".to_owned()
        })
    );
    assert_eq!(
        revalidate(|m| {
            let duplicate = m.tensor_index.tensors[1].clone();
            m.tensor_index.tensors.push(duplicate);
        })
        .unwrap_err(),
        ManifestError::DuplicateName {
            name: "b".to_owned()
        }
    );
    assert_eq!(
        revalidate(|m| m.tensor_index.aliases.push(TensorAlias {
            name: name("a"),
            target: name("b"),
        }))
        .unwrap_err(),
        ManifestError::DuplicateName {
            name: "a".to_owned()
        }
    );
    assert_eq!(
        revalidate(
            |m| m.state.rematerialized_buffers.push(RematerializedBuffer {
                name: name("b"),
                dtype: TensorDtype::Element(ElementType::F32),
                shape: vec![2],
                reconstruction: VersionedName {
                    name: token("rotary"),
                    version: token("1"),
                },
            })
        )
        .unwrap_err(),
        ManifestError::DuplicateName {
            name: "b".to_owned()
        }
    );
    let adapter = digest("yougori/test/adapter/v1", &[b"lora"]);
    assert!(matches!(
        revalidate(|m| {
            m.semantics.adapters = vec![adapter, adapter];
            m.lifecycle.dependency_roots = vec![DependencyRoot::Adapter(adapter)];
        }),
        Err(ManifestError::DuplicateName { .. })
    ));

    let mut case_twins = sample_builder();
    case_twins
        .add_source_file(source_file(
            "Config.json",
            b"{}",
            FileRole::Other,
            FileFormat::Opaque,
        ))
        .unwrap();
    case_twins.add_extent(ExtentInput {
        file: path("Config.json"),
        logical_offset_bytes: 0,
        true_length_bytes: 2,
        content_key: ContentKey::of(b"{}"),
        encoding: EncodingInput::Raw,
    });
    assert_eq!(
        case_twins.finish().unwrap_err(),
        ManifestError::DuplicateFile {
            path: path("config.json")
        }
    );
}

/// TP=2: a shared file with replicated `norm`, and one processed-rank file per rank.
fn sharded_builder(distribution: Distribution, expert: bool) -> ManifestBuilder {
    let mut builder = new_builder(description(distribution, G));
    add_raw_file(
        &mut builder,
        "config.json",
        &config_bytes(),
        FileRole::Configuration,
        FileFormat::Opaque,
    );
    for rank in 0..2u32 {
        let file = format!("model-rank-{rank}.safetensors");
        add_raw_file(
            &mut builder,
            &file,
            &weights_bytes(),
            FileRole::Weights {
                format: WeightFormat::Safetensors,
                rank: Some(rank),
            },
            SAFETENSORS_HEADER,
        );
        let owner = if expert {
            TensorOwner::Expert { expert: rank, rank }
        } else {
            TensorOwner::Rank(rank)
        };
        builder
            .add_tensor(tensor(&format!("q.{rank}"), &file, 64, &[16], owner))
            .unwrap();
        builder
            .add_tensor(tensor(&format!("k.{rank}"), &file, 128, &[16], owner))
            .unwrap();
    }
    add_raw_file(
        &mut builder,
        "shared.safetensors",
        &weights_bytes(),
        SAFETENSORS_WEIGHTS,
        SAFETENSORS_HEADER,
    );
    builder
        .add_tensor(tensor(
            "norm",
            "shared.safetensors",
            64,
            &[16],
            TensorOwner::Replicated,
        ))
        .unwrap();
    builder
}

#[test]
fn rank_coverage_is_checked_and_a_missing_rank_is_refused() {
    let sharded = sharded_builder(tensor_parallel(2), false).finish().unwrap();
    assert_eq!(
        revalidate_from(&sharded, |m| m
            .tensor_index
            .tensors
            .retain(|tensor| tensor.owner != TensorOwner::Rank(1)))
        .unwrap_err(),
        ManifestError::MissingRank { rank: 1 }
    );
    assert_eq!(
        revalidate_from(&sharded, |m| m.distribution = tensor_parallel(4)).unwrap_err(),
        ManifestError::MissingRank { rank: 2 }
    );
    assert_eq!(
        revalidate_from(&sharded, |m| m.distribution = Distribution::SINGLE).unwrap_err(),
        ManifestError::RankOutOfRange {
            rank: 1,
            rank_count: 1
        }
    );
    assert_eq!(
        revalidate_from(&sharded, |m| m.tensor_index.tensors[0].owner =
            TensorOwner::Rank(1))
        .unwrap_err(),
        ManifestError::OwnerOffFileRank { name: name("k.0") }
    );
    assert_eq!(
        revalidate_from(&sharded, |m| m.distribution.tensor_parallel_size = 0).unwrap_err(),
        ManifestError::InvalidParallelLayout
    );
}

#[test]
fn rank_plans_refuse_a_wrong_rank_or_layout() {
    let sharded = sharded_builder(tensor_parallel(2), false).finish().unwrap();
    let layout = tensor_parallel(2);
    let rank0 = sharded.rank_plan(&layout, 0).unwrap();
    assert_eq!(rank0.tensors, vec![name("k.0"), name("norm"), name("q.0")]);
    assert_eq!(rank0.tensor_bytes, 192);
    // config.json holds extents 0–1, rank 0's file 2–4, rank 1's 5–7, shared 8–10.
    assert_eq!(rank0.extents, vec![3, 4, 9]);
    assert_eq!(
        sharded.rank_plan(&layout, 1).unwrap().extents,
        vec![6, 7, 9]
    );
    assert_eq!(
        sharded.rank_plan(&layout, 2),
        Err(RankRefusal::RankOutOfRange {
            rank: 2,
            rank_count: 2
        })
    );
    for wrong in [Distribution::SINGLE, tensor_parallel(4)] {
        assert_eq!(
            sharded.rank_plan(&wrong, 0),
            Err(RankRefusal::LayoutMismatch {
                manifest: layout,
                requested: wrong,
            })
        );
    }
    let single = sample();
    let plan = single.rank_plan(&Distribution::SINGLE, 0).unwrap();
    assert_eq!(plan.tensors, vec![name("a"), name("b")]);
    assert_eq!(plan.extents, vec![3, 4]);
    assert_eq!(
        single.extents_covering(SourceFileId(WEIGHTS), 100, 40),
        3..5
    );
    assert_eq!(single.extents_covering(SourceFileId(WEIGHTS), 128, 0), 2..2);
}

#[test]
fn expert_ownership_is_checked() {
    let layout = Distribution {
        tensor_parallel_size: 2,
        pipeline_parallel_size: 1,
        expert_parallel_size: 2,
        expert_count: 2,
    };
    let experts = sharded_builder(layout, true).finish().unwrap();
    assert_eq!(experts.rank_plan(&layout, 1).unwrap().tensors.len(), 3);
    assert_eq!(
        revalidate_from(&experts, |m| m.distribution.expert_count = 3).unwrap_err(),
        ManifestError::MissingExpert { expert: 2 }
    );
    assert_eq!(
        revalidate_from(&experts, |m| m.tensor_index.tensors[1].owner =
            TensorOwner::Expert { expert: 0, rank: 1 })
        .unwrap_err(),
        ManifestError::ExpertSplitAcrossRanks { expert: 0 }
    );
    assert_eq!(
        revalidate_from(&experts, |m| m.tensor_index.tensors[1].owner =
            TensorOwner::Expert { expert: 5, rank: 1 })
        .unwrap_err(),
        ManifestError::ExpertOutOfRange {
            expert: 5,
            expert_count: 2
        }
    );
    assert_eq!(
        revalidate_from(&experts, |m| m.distribution.expert_parallel_size = 3).unwrap_err(),
        ManifestError::InvalidParallelLayout
    );
    let no_experts = Distribution {
        expert_count: 0,
        ..layout
    };
    assert_eq!(
        sharded_builder(no_experts, false).finish().unwrap_err(),
        ManifestError::InvalidParallelLayout
    );
}

#[test]
fn missing_files_are_refused() {
    let mut builder = sample_builder();
    builder
        .add_tensor(tensor(
            "c",
            "missing.safetensors",
            64,
            &[16],
            TensorOwner::Replicated,
        ))
        .unwrap();
    assert_eq!(
        builder.finish().unwrap_err(),
        ManifestError::UnknownFilePath {
            path: path("missing.safetensors")
        }
    );
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[0].file = SourceFileId(9)).unwrap_err(),
        ManifestError::MissingFile { file: 9 }
    );
    assert_eq!(
        revalidate(|m| m.extents.extents[4].file = SourceFileId(9)).unwrap_err(),
        ManifestError::MissingFile { file: 9 }
    );
    let (encoded, _) = encoded_sample(None);
    assert_eq!(
        revalidate_from(&encoded, |m| {
            if let ExtentEncoding::Encoded(representation) = &mut m.extents.extents[2].encoding {
                representation.location.file = PreparedFileId(7);
            }
        })
        .unwrap_err(),
        ManifestError::MissingPreparedFile { file: 7 }
    );
}

#[test]
fn integer_overflow_is_refused() {
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[0].offset_bytes = u64::MAX - 10).unwrap_err(),
        ManifestError::Overflow {
            field: "tensor range"
        }
    );
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[0].shape = vec![u64::MAX, 2]).unwrap_err(),
        ManifestError::TensorShape {
            name: name("a"),
            error: ShapeError::Overflow
        }
    );
    assert_eq!(
        revalidate(|m| m.distribution.tensor_parallel_size = u32::MAX).unwrap_err(),
        ManifestError::BoundExceeded {
            bound: "max_ranks",
            found: u32::MAX.into(),
            max: ManifestBounds::DEFAULT.max_ranks.into(),
        }
    );
    assert_eq!(
        revalidate(|m| {
            m.distribution.tensor_parallel_size = u32::MAX;
            m.distribution.pipeline_parallel_size = 2;
        })
        .unwrap_err(),
        ManifestError::Overflow {
            field: "rank count"
        }
    );
    assert_eq!(
        revalidate(|m| {
            for file in &mut m.provenance.files {
                file.length_bytes = u64::MAX / 2 + 1;
            }
        })
        .unwrap_err(),
        ManifestError::Overflow {
            field: "source bytes"
        }
    );
    assert_eq!(
        revalidate(|m| m.extents.extents[4].logical_offset_bytes = u64::MAX - 5).unwrap_err(),
        ManifestError::Overflow {
            field: "extent range"
        }
    );
}

#[test]
fn extents_must_tile_every_file() {
    assert_eq!(
        revalidate(|m| {
            m.extents.extents.remove(3);
        })
        .unwrap_err(),
        ManifestError::ExtentGap {
            file: WEIGHTS,
            offset_bytes: 64
        }
    );
    assert_eq!(
        revalidate(|m| {
            m.extents.extents.pop();
        })
        .unwrap_err(),
        ManifestError::ExtentCoverage {
            file: WEIGHTS,
            covered_bytes: 128,
            length_bytes: 192
        }
    );
    assert_eq!(
        revalidate(|m| {
            m.extents.extents.drain(0..2);
        })
        .unwrap_err(),
        ManifestError::ExtentCoverage {
            file: CONFIG,
            covered_bytes: 0,
            length_bytes: 100
        }
    );
    assert_eq!(
        revalidate(|m| m.extents.extents[2].true_length_bytes = 0).unwrap_err(),
        ManifestError::EmptyExtent {
            file: WEIGHTS,
            offset_bytes: 0
        }
    );
    // Out of order, the earlier file is found incomplete first.
    assert_eq!(
        revalidate(|m| m.extents.extents.swap(1, 2)).unwrap_err(),
        ManifestError::ExtentCoverage {
            file: CONFIG,
            covered_bytes: 64,
            length_bytes: 100
        }
    );
    assert_eq!(
        revalidate(|m| {
            let first = m.extents.extents[0];
            m.extents.extents.push(first);
        })
        .unwrap_err(),
        ManifestError::NotCanonical {
            collection: "extents"
        }
    );
    assert_eq!(
        revalidate(|m| m.extents.integrity_extent_bytes = 0).unwrap_err(),
        ManifestError::InvalidGranularity
    );
    assert_eq!(
        revalidate(|m| m.extents.codec_block_bytes = Some(G)).unwrap_err(),
        ManifestError::CodecBlockMismatch
    );
    // The declared g_h must be within the per-extent bound, and so must every extent.
    assert_eq!(
        revalidate(|m| m.schema.bounds.max_extent_bytes = 32).unwrap_err(),
        ManifestError::InvalidGranularity
    );
    assert_eq!(
        revalidate(|m| {
            m.schema.bounds.max_extent_bytes = 32;
            m.extents.integrity_extent_bytes = 32;
        })
        .unwrap_err(),
        ManifestError::BoundExceeded {
            bound: "max_extent_bytes",
            found: 64,
            max: 32
        }
    );
}

#[test]
fn the_decompression_bound_is_enforced() {
    let (encoded, stored) = encoded_sample(Some(b"dictionary"));
    // Declared: an encoded extent may not claim more decoded bytes than the bound.
    assert_eq!(
        revalidate_from(&encoded, |m| m.extents.extents[2].true_length_bytes =
            1 << 40)
        .unwrap_err(),
        ManifestError::DecompressionBound {
            declared_bytes: 1 << 40,
            max_bytes: ManifestBounds::DEFAULT.max_extent_bytes,
        }
    );
    assert_eq!(
        revalidate_from(&encoded, |m| m.schema.bounds.max_extent_bytes =
            ManifestBounds::CEILING.max_extent_bytes + 1)
        .unwrap_err(),
        ManifestError::BoundsAboveCeiling {
            bound: "max_extent_bytes",
            declared: ManifestBounds::CEILING.max_extent_bytes + 1,
            ceiling: ManifestBounds::CEILING.max_extent_bytes,
        }
    );
    // Decoded: a decoder can never write past the declared true length.
    let bomb = BombDecoder::default();
    assert_eq!(
        encoded.verify_extent(2, &stored[2], Some(b"dictionary"), &[&bomb]),
        Err(ExtentError::Decode(DecodeError::BoundExceeded {
            limit_bytes: 64
        }))
    );
    // Nine 7-byte pieces fit in the 64-byte extent; the tenth is refused.
    assert_eq!(
        bomb.written_bytes.load(std::sync::atomic::Ordering::SeqCst),
        63
    );
    assert_eq!(
        encoded.verify_extent(2, &stored[2], Some(b"dictionary"), &[&ShortDecoder]),
        Err(ExtentError::DecodedLength {
            expected_bytes: 64,
            found_bytes: 1
        })
    );
}

#[test]
fn encoded_extents_are_verified_before_and_after_decoding() {
    let (encoded, stored) = encoded_sample(Some(b"dictionary"));
    let decoder = RunLengthStandIn::default();
    let weights = weights_bytes();
    for index in 2..5 {
        let decoded = encoded
            .verify_extent(index, &stored[index], Some(b"dictionary"), &[&decoder])
            .unwrap();
        assert_eq!(decoded, weights[(index - 2) * 64..(index - 1) * 64]);
    }
    let calls = || decoder.calls.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(calls(), 3);

    let mut tampered = stored[2].clone();
    tampered[1] ^= 1;
    assert_eq!(
        encoded.verify_extent(2, &tampered, Some(b"dictionary"), &[&decoder]),
        Err(ExtentError::EncodedDigestMismatch)
    );
    assert_eq!(calls(), 3, "a hash mismatch is never decoded");
    assert_eq!(
        encoded.verify_extent(2, &stored[2], Some(b"other"), &[&decoder]),
        Err(ExtentError::DictionaryMismatch)
    );
    assert_eq!(
        encoded.verify_extent(2, &stored[2], None, &[&decoder]),
        Err(ExtentError::DictionaryMissing)
    );
    assert_eq!(
        encoded.verify_extent(2, &stored[2], Some(b"dictionary"), &[]),
        Err(ExtentError::DecoderUnavailable { codec: Codec::Zstd })
    );
    assert_eq!(
        encoded.verify_extent(2, &stored[2][..2], Some(b"dictionary"), &[&decoder]),
        Err(ExtentError::StoredLength {
            expected_bytes: stored[2].len() as u64,
            found_bytes: 2
        })
    );
    assert_eq!(
        encoded.verify_extent(0, &stored[0], None, &[]),
        Ok(stored[0].clone())
    );
    let mut wrong = stored[0].clone();
    wrong[0] ^= 1;
    assert_eq!(
        encoded.verify_extent(0, &wrong, None, &[]),
        Err(ExtentError::ContentKeyMismatch)
    );
    assert_eq!(
        encoded.verify_extent(0, &stored[0], Some(b"dictionary"), &[]),
        Err(ExtentError::UnexpectedDictionary)
    );
    assert_eq!(
        encoded.verify_extent(99, &stored[0], None, &[]),
        Err(ExtentError::NoSuchExtent)
    );
    let (plain, plain_stored) = encoded_sample(None);
    assert_eq!(
        plain.verify_extent(2, &plain_stored[2], Some(b"dictionary"), &[&decoder]),
        Err(ExtentError::UnexpectedDictionary)
    );
    let m = encoded.manifest();
    assert_eq!(m.extents.prepared_files.len(), 1);
    assert_eq!(
        m.lifecycle.migration,
        MigrationRequirement::RebuildPreparedFromSources
    );
    assert_eq!(
        m.lifecycle.storage.owned_representation_bytes,
        stored[2..]
            .iter()
            .map(|bytes| bytes.len() as u64)
            .sum::<u64>()
    );
    assert_eq!(
        m.lifecycle.dependency_roots,
        vec![DependencyRoot::Dictionary(DictionaryId::of(b"dictionary"))]
    );
}

#[test]
fn encoded_storage_must_be_accounted_exactly() {
    let (encoded, _) = encoded_sample(None);
    assert_eq!(
        revalidate_from(&encoded, |m| {
            m.extents.prepared_files[0].length_bytes += 1;
            m.lifecycle.storage.owned_representation_bytes += 1;
        })
        .unwrap_err(),
        ManifestError::PreparedCoverage { file: 0 }
    );
    assert_eq!(
        revalidate_from(&encoded, |m| {
            if let ExtentEncoding::Encoded(representation) = &mut m.extents.extents[4].encoding {
                representation.location.length_bytes += 1;
            }
        })
        .unwrap_err(),
        ManifestError::EncodedOutOfBounds { file: 0 }
    );
    assert_eq!(
        revalidate_from(&encoded, |m| m.extents.codec_block_bytes = None).unwrap_err(),
        ManifestError::CodecBlockMismatch
    );
    assert_eq!(
        revalidate_from(&encoded, |m| m.extents.codec_block_bytes = Some(32)).unwrap_err(),
        ManifestError::CodecBlockMismatch
    );
}

#[test]
fn derived_fields_and_trees_are_authenticated() {
    let other = digest("yougori/test/other/v1", &[b"x"]);
    assert_eq!(
        revalidate(|m| m.semantics.configuration_digest = other).unwrap_err(),
        ManifestError::DerivedMismatch {
            field: "configuration digest"
        }
    );
    assert_eq!(
        revalidate(|m| m.semantics.tokenizer_digest = other).unwrap_err(),
        ManifestError::DerivedMismatch {
            field: "tokenizer digest"
        }
    );
    assert_eq!(
        revalidate(|m| m.integrity.extent_roots[1] = other).unwrap_err(),
        ManifestError::TreeRootMismatch { file: WEIGHTS }
    );
    assert_eq!(
        revalidate(|m| {
            m.integrity.extent_roots.pop();
        })
        .unwrap_err(),
        ManifestError::DerivedMismatch {
            field: "extent roots"
        }
    );
    assert_eq!(
        revalidate(|m| m.integrity.decoded_content_identity = other).unwrap_err(),
        ManifestError::DerivedMismatch {
            field: "decoded content identity"
        }
    );
    assert_eq!(
        revalidate(|m| m.extents.extents[3].content_key = ContentKey::of(b"other")).unwrap_err(),
        ManifestError::TreeRootMismatch { file: WEIGHTS }
    );
    assert_eq!(
        revalidate(|m| m.lifecycle.storage.referenced_source_bytes += 1).unwrap_err(),
        ManifestError::DerivedMismatch {
            field: "storage accounting"
        }
    );
    assert_eq!(
        revalidate(|m| m.lifecycle.migration = MigrationRequirement::RebuildPreparedFromSources)
            .unwrap_err(),
        ManifestError::DerivedMismatch {
            field: "migration requirement"
        }
    );
    assert_eq!(
        revalidate(|m| m.provenance.revision = SourceRevision::ContentListing(other)).unwrap_err(),
        ManifestError::DerivedMismatch {
            field: "content listing revision"
        }
    );
    let commit = GitCommit::from_hex("0123456789abcdef0123456789abcdef01234567").unwrap();
    assert!(revalidate(|m| m.provenance.revision = SourceRevision::GitCommit(commit)).is_ok());
    let adapter = digest("yougori/test/adapter/v1", &[b"lora"]);
    assert_eq!(
        revalidate(|m| m.semantics.adapters.push(adapter)).unwrap_err(),
        ManifestError::MissingDependencyRoot {
            root: DependencyRoot::Adapter(adapter)
        }
    );
    let (encoded, _) = encoded_sample(Some(b"dictionary"));
    assert_eq!(
        revalidate_from(&encoded, |m| m.lifecycle.dependency_roots.clear()).unwrap_err(),
        ManifestError::MissingDependencyRoot {
            root: DependencyRoot::Dictionary(DictionaryId::of(b"dictionary"))
        }
    );
}

#[test]
fn collections_must_be_in_canonical_order() {
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors.swap(0, 1)).unwrap_err(),
        ManifestError::NotCanonical {
            collection: "tensors"
        }
    );
    assert_eq!(
        revalidate(|m| m.provenance.files.swap(0, 1)).unwrap_err(),
        ManifestError::NotCanonical {
            collection: "source files"
        }
    );
    assert_eq!(
        revalidate(|m| m.execution_abi.kernels = vec![token("b"), token("a")]).unwrap_err(),
        ManifestError::NotCanonical {
            collection: "kernels"
        }
    );
    assert_eq!(
        revalidate(|m| m.execution_abi.kernels = vec![token("a"), token("a")]).unwrap_err(),
        ManifestError::DuplicateName {
            name: "a".to_owned()
        }
    );
    assert_eq!(
        revalidate(|m| m.semantics.quantization = Quantization::Method {
            method: token("gptq"),
            parameters: vec![
                (token("group_size"), token("128")),
                (token("bits"), token("4"))
            ],
        })
        .unwrap_err(),
        ManifestError::NotCanonical {
            collection: "quantization parameters"
        }
    );
    assert_eq!(
        revalidate(
            |m| m.execution_abi.hardware = HardwareRestriction::ComputeCapabilities(Vec::new())
        )
        .unwrap_err(),
        ManifestError::EmptyHardwareRestriction
    );
    let first = digest("yougori/test/adapter/v1", &[b"1"]);
    let second = digest("yougori/test/adapter/v1", &[b"2"]);
    let (low, high) = if first < second {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!(
        revalidate(|m| m.lifecycle.dependency_roots =
            vec![DependencyRoot::Adapter(high), DependencyRoot::Adapter(low)])
        .unwrap_err(),
        ManifestError::NotCanonical {
            collection: "dependency roots"
        }
    );
}

#[test]
fn file_roles_formats_and_tensor_ranges_must_agree() {
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[0].file = SourceFileId(CONFIG)).unwrap_err(),
        ManifestError::FormatMismatch {
            path: path("config.json")
        }
    );
    assert_eq!(
        revalidate(|m| m.provenance.files[1].format = FileFormat::Opaque).unwrap_err(),
        ManifestError::FormatMismatch {
            path: path("model.safetensors")
        }
    );
    assert_eq!(
        revalidate(|m| m.provenance.files[1].format = FileFormat::Safetensors {
            header_length_bytes: 1_000
        })
        .unwrap_err(),
        ManifestError::FormatMismatch {
            path: path("model.safetensors")
        }
    );
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[0].offset_bytes = 8).unwrap_err(),
        ManifestError::TensorOutOfBounds { name: name("a") }
    );
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[1].offset_bytes = 160).unwrap_err(),
        ManifestError::TensorOutOfBounds { name: name("b") }
    );
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[0].true_length_bytes = 60).unwrap_err(),
        ManifestError::TensorLength {
            name: name("a"),
            declared_bytes: 60,
            expected_bytes: 64
        }
    );
    assert_eq!(
        revalidate(|m| m.tensor_index.tensors[0].layout = TensorLayout::GgmlInnermostFirst)
            .unwrap_err(),
        ManifestError::TensorShape {
            name: name("a"),
            error: ShapeError::LayoutMismatch
        }
    );

    let gguf_format = |alignment_bytes| FileFormat::Gguf {
        version: 3,
        alignment_bytes,
        data_offset_bytes: 64,
        metadata_digest: digest("yougori/test/metadata/v1", &[b"m"]),
    };
    let gguf = |alignment_bytes, offset_bytes| {
        let mut builder = new_builder(description(Distribution::SINGLE, G));
        add_raw_file(
            &mut builder,
            "model.gguf",
            &weights_bytes(),
            super::GGUF_WEIGHTS,
            gguf_format(alignment_bytes),
        );
        let dtype = TensorDtype::Ggml(GgmlType::Q4_0);
        builder
            .add_tensor(TensorInput {
                name: name("blk.0.attn_q.weight"),
                file: path("model.gguf"),
                offset_bytes,
                true_length_bytes: 36,
                dtype,
                shape: vec![64],
                layout: TensorLayout::GgmlInnermostFirst,
                owner: TensorOwner::Replicated,
            })
            .unwrap();
        builder.finish()
    };
    assert!(gguf(32, 96).is_ok());
    assert_eq!(
        gguf(32, 80).unwrap_err(),
        ManifestError::TensorMisaligned {
            name: name("blk.0.attn_q.weight"),
            alignment_bytes: 32
        }
    );
    assert_eq!(
        gguf(3, 96).unwrap_err(),
        ManifestError::FormatMismatch {
            path: path("model.gguf")
        }
    );
}

#[test]
fn a_model_needs_a_configuration() {
    let mut builder = new_builder(description(Distribution::SINGLE, G));
    add_raw_file(
        &mut builder,
        "model.safetensors",
        &weights_bytes(),
        SAFETENSORS_WEIGHTS,
        SAFETENSORS_HEADER,
    );
    add_tensors(&mut builder);
    assert_eq!(
        builder.finish().unwrap_err(),
        ManifestError::MissingConfiguration
    );
}

#[test]
fn state_buffers_and_aliases_are_checked() {
    let mut builder = sample_builder();
    builder.add_persistent_buffer(name("b")).unwrap();
    builder
        .add_rematerialized_buffer(RematerializedBuffer {
            name: name("rotary.inv_freq"),
            dtype: TensorDtype::Element(ElementType::F32),
            shape: vec![32],
            reconstruction: VersionedName {
                name: token("rotary-embedding"),
                version: token("1"),
            },
        })
        .unwrap();
    builder
        .add_alias(TensorAlias {
            name: name("lm_head.weight"),
            target: name("a"),
        })
        .unwrap();
    let manifest = builder.finish().unwrap();
    assert_eq!(manifest.tensor("lm_head.weight").unwrap().name, name("a"));
    assert_eq!(
        revalidate_from(&manifest, |m| m
            .state
            .persistent_buffers
            .push(name("missing")))
        .unwrap_err(),
        ManifestError::MissingTensor {
            name: name("missing")
        }
    );
    assert_eq!(
        revalidate_from(&manifest, |m| m.tensor_index.aliases[0].target =
            name("missing"))
        .unwrap_err(),
        ManifestError::MissingAliasTarget {
            alias: name("lm_head.weight")
        }
    );
    assert_eq!(
        revalidate_from(&manifest, |m| m.state.rematerialized_buffers[0].shape =
            vec![u64::MAX, 2])
        .unwrap_err(),
        ManifestError::TensorShape {
            name: name("rotary.inv_freq"),
            error: ShapeError::Overflow
        }
    );
    let mut bounded = manifest.into_manifest();
    bounded.schema.bounds.max_name_bytes = 4;
    assert_eq!(
        bounded.validate().unwrap_err(),
        ManifestError::BoundExceeded {
            bound: "max_name_bytes",
            found: 14,
            max: 4
        }
    );
}

#[test]
fn extent_proofs_verify_against_the_file_roots() {
    let (encoded, _) = encoded_sample(Some(b"dictionary"));
    let extents = &encoded.manifest().extents.extents;
    for (index, extent) in extents.iter().enumerate() {
        let proof = encoded.extent_proof(index).unwrap();
        let root = encoded.extent_root(extent.file).unwrap();
        assert!(proof.verify(&root, extent), "extent {index}");
        let other_root = encoded
            .extent_root(SourceFileId(1 - extent.file.0))
            .unwrap();
        assert!(!proof.verify(&other_root, extent));
        let mut moved = *extent;
        moved.logical_offset_bytes += 1;
        assert!(!proof.verify(&root, &moved));
        let mut recoded = *extent;
        recoded.encoding = match extent.encoding {
            ExtentEncoding::Raw => ExtentEncoding::Encoded(EncodedRepresentation {
                format: ZSTD_FORMAT,
                dictionary: None,
                location: EncodedLocation {
                    file: PreparedFileId(0),
                    offset_bytes: 0,
                    length_bytes: 1,
                },
                digest: EncodedDigest::of(ZSTD_FORMAT, None, b"x"),
            }),
            ExtentEncoding::Encoded(_) => ExtentEncoding::Raw,
        };
        assert!(!proof.verify(&root, &recoded));
    }
    assert!(encoded.extent_proof(extents.len()).is_none());
}

#[test]
fn the_packaged_format_is_a_gated_non_goal() {
    assert_eq!(PACKAGED_FORMAT.name, ".ywi packaged representation");
    assert!(PACKAGED_FORMAT.gate.starts_with("measured gains"));
    // A sidecar owns no copy of the model: originals are referenced, never stored.
    let manifest = sample();
    assert!(manifest.manifest().extents.prepared_files.is_empty());
    assert!(manifest
        .manifest()
        .extents
        .extents
        .iter()
        .all(|extent| extent.encoding == ExtentEncoding::Raw));
}
