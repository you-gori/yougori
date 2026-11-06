//! Order-independent assembly of a manifest (GPU part §3.3: canonical encodings; the
//! importer's "complete index/proofs" step).
//!
//! Entries may be added in any order. [`ManifestBuilder::finish`] sorts every collection
//! whose order carries no meaning, assigns file indices in path order, derives the
//! configuration and tokenizer digests, extent-tree roots, decoded content identity,
//! required dependency roots, storage accounting and migration requirement, and then
//! validates. The same content therefore always yields the same bytes and digest.

use std::collections::{BTreeMap, BTreeSet};

use crate::foundation::ids::Digest;

use super::codec::CodecFormat;
use super::derive;
use super::digests::{ContentKey, DictionaryId, EncodedDigest};
use super::groups::{
    ConverterIdentity, DependencyRoot, Distribution, EncodedLocation, EncodedRepresentation,
    ExecutionAbi, Extent, ExtentEncoding, ExtentGroup, FileFormat, FileRole, HardwareRestriction,
    IntegrityGroup, Lifecycle, Manifest, ManifestBounds, PreparedFile, PreparedFileId, Provenance,
    Quantization, RematerializedBuffer, SchemaGroup, Semantics, SourceFile, SourceFileId,
    SourceOrigin, SourceRevision, StateGroup, TensorAlias, TensorEntry, TensorIndex, TensorOwner,
};
use super::types::{ElementType, RelativePath, TensorDtype, TensorLayout, TensorName};
use super::validate::{ManifestError, ValidatedManifest};

/// The choices an artifact is built for: bounds, exact dtype and quantization, adapters,
/// execution ABI, rank layout and the integrity-extent size g_h (§2.4, §3.2 layers 2–3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactDescription {
    pub bounds: ManifestBounds,
    pub compute_dtype: ElementType,
    pub quantization: Quantization,
    pub adapters: Vec<Digest>,
    pub execution_abi: ExecutionAbi,
    pub distribution: Distribution,
    pub integrity_extent_bytes: u64,
}

/// A source file to add, with the content key of the whole file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFileInput {
    pub path: RelativePath,
    pub length_bytes: u64,
    pub content: ContentKey,
    pub role: FileRole,
    pub format: FileFormat,
}

/// A tensor to add; its file is named by path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TensorInput {
    pub name: TensorName,
    pub file: RelativePath,
    pub offset_bytes: u64,
    pub true_length_bytes: u64,
    pub dtype: TensorDtype,
    pub shape: Vec<u64>,
    pub layout: TensorLayout,
    pub owner: TensorOwner,
}

/// How an added extent is stored. A raw extent has no codec; an encoded one names its
/// codec format, whose version and frame parameters its encoded digest binds (GPU-W08).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EncodingInput {
    Raw,
    Encoded {
        format: CodecFormat,
        dictionary: Option<DictionaryId>,
        prepared_file: RelativePath,
        offset_bytes: u64,
        length_bytes: u64,
        digest: EncodedDigest,
    },
}

/// An extent to add; its files are named by path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExtentInput {
    pub file: RelativePath,
    pub logical_offset_bytes: u64,
    pub true_length_bytes: u64,
    pub content_key: ContentKey,
    pub encoding: EncodingInput,
}

/// Collects a manifest's entries in any order.
#[derive(Clone, Debug)]
pub struct ManifestBuilder {
    description: ArtifactDescription,
    origin: SourceOrigin,
    revision: Option<SourceRevision>,
    converter: ConverterIdentity,
    files: BTreeMap<RelativePath, SourceFileInput>,
    tensors: BTreeMap<TensorName, TensorInput>,
    aliases: BTreeMap<TensorName, TensorName>,
    persistent: BTreeSet<TensorName>,
    rematerialized: BTreeMap<TensorName, RematerializedBuffer>,
    prepared: BTreeMap<RelativePath, u64>,
    extents: Vec<ExtentInput>,
    codec_block_bytes: Option<u64>,
    roots: BTreeSet<DependencyRoot>,
}

impl ManifestBuilder {
    pub fn new(
        origin: SourceOrigin,
        converter: ConverterIdentity,
        description: ArtifactDescription,
    ) -> Self {
        Self {
            description,
            origin,
            revision: None,
            converter,
            files: BTreeMap::new(),
            tensors: BTreeMap::new(),
            aliases: BTreeMap::new(),
            persistent: BTreeSet::new(),
            rematerialized: BTreeMap::new(),
            prepared: BTreeMap::new(),
            extents: Vec::new(),
            codec_block_bytes: None,
            roots: BTreeSet::new(),
        }
    }

    /// Sets an immutable revision; without one, the content listing is the revision.
    pub fn set_revision(&mut self, revision: SourceRevision) {
        self.revision = Some(revision);
    }

    pub fn add_source_file(&mut self, file: SourceFileInput) -> Result<(), ManifestError> {
        if self.files.contains_key(&file.path) {
            return Err(ManifestError::DuplicateFile { path: file.path });
        }
        self.files.insert(file.path.clone(), file);
        Ok(())
    }

    pub fn add_tensor(&mut self, tensor: TensorInput) -> Result<(), ManifestError> {
        if self.tensors.contains_key(&tensor.name) {
            return Err(ManifestError::DuplicateName {
                name: tensor.name.to_string(),
            });
        }
        self.tensors.insert(tensor.name.clone(), tensor);
        Ok(())
    }

    /// Reassigns an added tensor, such as an expert's weights, to `owner`.
    pub fn set_owner(
        &mut self,
        name: &TensorName,
        owner: TensorOwner,
    ) -> Result<(), ManifestError> {
        let tensor = self
            .tensors
            .get_mut(name)
            .ok_or_else(|| ManifestError::MissingTensor { name: name.clone() })?;
        tensor.owner = owner;
        Ok(())
    }

    pub fn add_alias(&mut self, alias: TensorAlias) -> Result<(), ManifestError> {
        if self.aliases.contains_key(&alias.name) {
            return Err(ManifestError::DuplicateName {
                name: alias.name.to_string(),
            });
        }
        self.aliases.insert(alias.name, alias.target);
        Ok(())
    }

    pub fn add_persistent_buffer(&mut self, name: TensorName) -> Result<(), ManifestError> {
        if !self.persistent.insert(name.clone()) {
            return Err(ManifestError::DuplicateName {
                name: name.to_string(),
            });
        }
        Ok(())
    }

    pub fn add_rematerialized_buffer(
        &mut self,
        buffer: RematerializedBuffer,
    ) -> Result<(), ManifestError> {
        if self.rematerialized.contains_key(&buffer.name) {
            return Err(ManifestError::DuplicateName {
                name: buffer.name.to_string(),
            });
        }
        self.rematerialized.insert(buffer.name.clone(), buffer);
        Ok(())
    }

    pub fn add_prepared_file(
        &mut self,
        path: RelativePath,
        length_bytes: u64,
    ) -> Result<(), ManifestError> {
        if self.prepared.contains_key(&path) {
            return Err(ManifestError::DuplicateFile { path });
        }
        self.prepared.insert(path, length_bytes);
        Ok(())
    }

    /// Adds an extent. Overlaps, gaps and duplicates are refused by validation.
    pub fn add_extent(&mut self, extent: ExtentInput) {
        self.extents.push(extent);
    }

    /// Sets the codec block size g_c of encoded extents (§2.4).
    pub fn set_codec_block_bytes(&mut self, codec_block_bytes: u64) {
        self.codec_block_bytes = Some(codec_block_bytes);
    }

    /// Records another artifact or object this one keeps reachable. Adapters and
    /// dictionaries the content uses are added by [`Self::finish`].
    pub fn add_dependency_root(&mut self, root: DependencyRoot) {
        self.roots.insert(root);
    }

    /// Sorts, derives and validates.
    pub fn finish(self) -> Result<ValidatedManifest, ManifestError> {
        let files: Vec<SourceFile> = self
            .files
            .into_iter()
            .map(|(path, input)| SourceFile {
                path,
                length_bytes: input.length_bytes,
                content: input.content,
                role: input.role,
                format: input.format,
            })
            .collect();
        let prepared_files: Vec<PreparedFile> = self
            .prepared
            .into_iter()
            .map(|(path, length_bytes)| PreparedFile { path, length_bytes })
            .collect();
        let source_id = |path: &RelativePath| {
            files
                .binary_search_by(|file| file.path.cmp(path))
                .map(|index| SourceFileId(index as u32))
                .map_err(|_| ManifestError::UnknownFilePath { path: path.clone() })
        };
        let prepared_id = |path: &RelativePath| {
            prepared_files
                .binary_search_by(|file| file.path.cmp(path))
                .map(|index| PreparedFileId(index as u32))
                .map_err(|_| ManifestError::UnknownFilePath { path: path.clone() })
        };

        let tensors = self
            .tensors
            .into_values()
            .map(|tensor| {
                Ok(TensorEntry {
                    file: source_id(&tensor.file)?,
                    name: tensor.name,
                    offset_bytes: tensor.offset_bytes,
                    true_length_bytes: tensor.true_length_bytes,
                    dtype: tensor.dtype,
                    shape: tensor.shape,
                    layout: tensor.layout,
                    owner: tensor.owner,
                })
            })
            .collect::<Result<Vec<_>, ManifestError>>()?;
        let mut extents = self
            .extents
            .into_iter()
            .map(|extent| {
                let encoding = match extent.encoding {
                    EncodingInput::Raw => ExtentEncoding::Raw,
                    EncodingInput::Encoded {
                        format,
                        dictionary,
                        prepared_file,
                        offset_bytes,
                        length_bytes,
                        digest,
                    } => ExtentEncoding::Encoded(EncodedRepresentation {
                        format,
                        dictionary,
                        location: EncodedLocation {
                            file: prepared_id(&prepared_file)?,
                            offset_bytes,
                            length_bytes,
                        },
                        digest,
                    }),
                };
                Ok(Extent {
                    file: source_id(&extent.file)?,
                    logical_offset_bytes: extent.logical_offset_bytes,
                    true_length_bytes: extent.true_length_bytes,
                    content_key: extent.content_key,
                    encoding,
                })
            })
            .collect::<Result<Vec<_>, ManifestError>>()?;
        extents.sort_by_key(|extent| (extent.file, extent.logical_offset_bytes));

        let description = self.description;
        let mut quantization = description.quantization;
        if let Quantization::Method { parameters, .. } = &mut quantization {
            parameters.sort();
        }
        let mut execution_abi = description.execution_abi;
        execution_abi.kernels.sort();
        if let HardwareRestriction::ComputeCapabilities(capabilities) = &mut execution_abi.hardware
        {
            capabilities.sort();
        }
        let semantics = Semantics {
            configuration_digest: derive::configuration_digest(&files),
            tokenizer_digest: derive::tokenizer_digest(&files),
            compute_dtype: description.compute_dtype,
            quantization,
            adapters: description.adapters,
        };
        let mut roots = self.roots;
        roots.extend(derive::required_roots(&semantics.adapters, &extents));
        let revision = self.revision.unwrap_or_else(|| {
            SourceRevision::ContentListing(derive::source_listing_digest(&files))
        });
        let integrity = IntegrityGroup {
            extent_roots: derive::extent_roots(files.len(), &extents),
            decoded_content_identity: derive::decoded_content_identity(&files, &extents),
        };
        let storage = derive::storage(&files, &prepared_files)
            .ok_or(ManifestError::Overflow { field: "storage" })?;
        let migration = derive::migration(&prepared_files);
        Manifest {
            schema: SchemaGroup::current(description.bounds),
            provenance: Provenance {
                origin: self.origin,
                revision,
                files,
                converter: self.converter,
            },
            semantics,
            execution_abi,
            distribution: description.distribution,
            tensor_index: TensorIndex {
                tensors,
                aliases: self
                    .aliases
                    .into_iter()
                    .map(|(name, target)| TensorAlias { name, target })
                    .collect(),
            },
            state: StateGroup {
                persistent_buffers: self.persistent.into_iter().collect(),
                rematerialized_buffers: self.rematerialized.into_values().collect(),
            },
            extents: ExtentGroup {
                integrity_extent_bytes: description.integrity_extent_bytes,
                codec_block_bytes: self.codec_block_bytes,
                prepared_files,
                extents,
            },
            integrity,
            lifecycle: Lifecycle {
                dependency_roots: roots.into_iter().collect(),
                storage,
                migration,
            },
        }
        .validate()
    }
}
