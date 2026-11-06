//! Values the manifest derives from its own content. The builder fills them in and
//! validation recomputes them, so a manifest whose derived fields disagree with its
//! content is refused (GPU part §3.3: "Authenticate the manifest and its referenced
//! trees").

use crate::foundation::ids::{Digest, DigestBuilder};

use super::digests::{
    ContentKey, CONFIGURATION_DOMAIN, DECODED_CONTENT_DOMAIN, SOURCE_LISTING_DOMAIN,
    TOKENIZER_DOMAIN,
};
use super::groups::{
    DependencyRoot, Extent, ExtentEncoding, FileFormat, FileRole, MigrationRequirement,
    PreparedFile, SourceFile, StorageAccounting,
};
use super::tree::{extent_leaf, tree_root};
use super::types::RelativePath;

/// The content-derived revision of a source without a commit: its listing of paths,
/// lengths and whole-file content keys in path order.
pub fn listing_digest<'a>(
    files: impl ExactSizeIterator<Item = (&'a RelativePath, u64, ContentKey)>,
) -> Digest {
    let builder = DigestBuilder::new(SOURCE_LISTING_DOMAIN).u64(files.len() as u64);
    files
        .fold(builder, |builder, (path, length_bytes, content)| {
            builder
                .str(path.as_str())
                .u64(length_bytes)
                .digest(content.digest())
        })
        .finish()
}

pub(super) fn source_listing_digest(files: &[SourceFile]) -> Digest {
    listing_digest(
        files
            .iter()
            .map(|file| (&file.path, file.length_bytes, file.content)),
    )
}

/// Digest over the files of `role` and every GGUF file's metadata, which carries both
/// configuration and tokenizer.
fn role_digest(domain: &str, files: &[SourceFile], role: FileRole) -> Digest {
    let named: Vec<&SourceFile> = files.iter().filter(|file| file.role == role).collect();
    let gguf: Vec<(&SourceFile, Digest)> = files
        .iter()
        .filter_map(|file| match file.format {
            FileFormat::Gguf {
                metadata_digest, ..
            } => Some((file, metadata_digest)),
            _ => None,
        })
        .collect();
    let builder = DigestBuilder::new(domain).u64(named.len() as u64);
    let builder = named.iter().fold(builder, |builder, file| {
        builder
            .str(file.path.as_str())
            .digest(file.content.digest())
    });
    let builder = builder.u64(gguf.len() as u64);
    gguf.iter()
        .fold(builder, |builder, (file, metadata)| {
            builder.str(file.path.as_str()).digest(metadata)
        })
        .finish()
}

pub(super) fn configuration_digest(files: &[SourceFile]) -> Digest {
    role_digest(CONFIGURATION_DOMAIN, files, FileRole::Configuration)
}

pub(super) fn tokenizer_digest(files: &[SourceFile]) -> Digest {
    role_digest(TOKENIZER_DOMAIN, files, FileRole::Tokenizer)
}

/// Whether some file configures the model: a configuration file or GGUF metadata.
pub(super) fn has_configuration(files: &[SourceFile]) -> bool {
    files.iter().any(|file| {
        file.role == FileRole::Configuration || matches!(file.format, FileFormat::Gguf { .. })
    })
}

/// The extents of each file, by file index; extents naming a missing file are dropped
/// (validation refuses them first).
fn extents_by_file(file_count: usize, extents: &[Extent]) -> Vec<Vec<&Extent>> {
    let mut grouped: Vec<Vec<&Extent>> = vec![Vec::new(); file_count];
    for extent in extents {
        if let Some(group) = grouped.get_mut(extent.file.index()) {
            group.push(extent);
        }
    }
    grouped
}

pub(super) fn extent_roots(file_count: usize, extents: &[Extent]) -> Vec<Digest> {
    extents_by_file(file_count, extents)
        .iter()
        .map(|group| {
            let leaves: Vec<Digest> = group.iter().map(|extent| extent_leaf(extent)).collect();
            tree_root(&leaves)
        })
        .collect()
}

/// Every file's path, length and decoded content keys in order, without encodings.
pub(super) fn decoded_content_identity(files: &[SourceFile], extents: &[Extent]) -> Digest {
    let grouped = extents_by_file(files.len(), extents);
    let builder = DigestBuilder::new(DECODED_CONTENT_DOMAIN).u64(files.len() as u64);
    files
        .iter()
        .zip(grouped.iter())
        .fold(builder, |builder, (file, group)| {
            let builder = builder
                .str(file.path.as_str())
                .u64(file.length_bytes)
                .u64(group.len() as u64);
            group.iter().fold(builder, |builder, extent| {
                builder
                    .u64(extent.logical_offset_bytes)
                    .u64(extent.true_length_bytes)
                    .digest(extent.content_key.digest())
            })
        })
        .finish()
}

/// Referenced source bytes and owned prepared bytes; `None` on overflow.
pub(super) fn storage(
    files: &[SourceFile],
    prepared: &[PreparedFile],
) -> Option<StorageAccounting> {
    Some(StorageAccounting {
        referenced_source_bytes: files
            .iter()
            .try_fold(0u64, |total, file| total.checked_add(file.length_bytes))?,
        owned_representation_bytes: prepared
            .iter()
            .try_fold(0u64, |total, file| total.checked_add(file.length_bytes))?,
    })
}

pub(super) fn migration(prepared: &[PreparedFile]) -> MigrationRequirement {
    if prepared.is_empty() {
        MigrationRequirement::ReindexFromSources
    } else {
        MigrationRequirement::RebuildPreparedFromSources
    }
}

/// The roots the content requires: every adapter and every dictionary an extent uses.
pub(super) fn required_roots(adapters: &[Digest], extents: &[Extent]) -> Vec<DependencyRoot> {
    let mut roots: Vec<DependencyRoot> = adapters
        .iter()
        .map(|adapter| DependencyRoot::Adapter(*adapter))
        .chain(extents.iter().filter_map(|extent| match extent.encoding {
            ExtentEncoding::Encoded(encoded) => encoded.dictionary.map(DependencyRoot::Dictionary),
            ExtentEncoding::Raw => None,
        }))
        .collect();
    roots.sort();
    roots.dedup();
    roots
}
