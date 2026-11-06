//! Import bounds (VM-P37 "archive bombs"; §5.3 "verify image identity, provenance and
//! layout"). Every document, layer and tree is held to these before or while it is read.

use std::fmt;

use serde::Serialize;

use crate::sandbox_contract::files::ArchiveLimits;

/// Bounds on everything the importer reads (VM-P37). Sizes are checked against declared
/// values before anything is read and against produced bytes while streaming.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ImportLimits {
    /// Largest image index, manifest or config document.
    pub max_document_bytes: u64,
    /// Most manifests one index may list.
    pub max_index_manifests: usize,
    /// Most layers one manifest may list.
    pub max_layers: usize,
    /// Most annotations or labels on one document, descriptor or config.
    pub max_annotations: usize,
    pub max_annotation_key_bytes: usize,
    pub max_annotation_value_bytes: usize,
    /// Keys and values of one annotation or label map together.
    pub max_annotation_total_bytes: usize,
    /// Longest platform field (os, architecture, variant, os.version, a feature).
    pub max_platform_field_bytes: usize,
    /// Most items in one config list (env, entrypoint, cmd, onbuild, shell, history).
    pub max_config_items: usize,
    /// Longest config string.
    pub max_config_string_bytes: usize,
    /// Largest compressed layer blob.
    pub max_layer_compressed_bytes: u64,
    /// Largest expanded tar stream of one layer, headers and padding included.
    pub max_layer_expanded_bytes: u64,
    /// Largest sum of compressed layer blobs in one image.
    pub max_image_compressed_bytes: u64,
    /// Largest sum of expanded layer streams in one image.
    pub max_image_expanded_bytes: u64,
    /// Largest expanded-to-compressed ratio of a layer, metered while streaming.
    pub max_ratio: u64,
    /// Most tar entries in one layer.
    pub max_entries_per_layer: usize,
    /// Most tar entries across the image, and most nodes in the resulting tree.
    pub max_image_entries: usize,
    /// Largest single regular file.
    pub max_file_bytes: u64,
    /// Largest PAX extended header of one entry.
    pub max_pax_bytes: u64,
    /// Most PAX records in one extended header.
    pub max_pax_records: usize,
    /// Most allowlisted extended attributes on one entry.
    pub max_xattrs_per_entry: usize,
    /// Largest extended attribute value.
    pub max_xattr_value_bytes: usize,
    /// Largest zstd window, as a power of two; a frame asking for more is refused before
    /// the decoder allocates it.
    pub max_zstd_window_log: u32,
    /// Extent length of published envelopes (CORE-02 resumable verified data).
    pub extent_bytes: u64,
    /// Largest attestation a trust claim may carry.
    pub max_attestation_bytes: u64,
    /// Largest published tree index object.
    pub max_tree_object_bytes: u64,
}

impl Default for ImportLimits {
    fn default() -> Self {
        Self {
            max_document_bytes: 4 << 20,
            max_index_manifests: 256,
            max_layers: 128,
            max_annotations: 128,
            max_annotation_key_bytes: 256,
            max_annotation_value_bytes: 8 << 10,
            max_annotation_total_bytes: 256 << 10,
            max_platform_field_bytes: 128,
            max_config_items: 1024,
            max_config_string_bytes: 32 << 10,
            max_layer_compressed_bytes: 4 << 30,
            max_layer_expanded_bytes: 16 << 30,
            max_image_compressed_bytes: 16 << 30,
            max_image_expanded_bytes: 64 << 30,
            max_ratio: 200,
            max_entries_per_layer: 500_000,
            max_image_entries: 1_000_000,
            max_file_bytes: 8 << 30,
            max_pax_bytes: 64 << 10,
            max_pax_records: 64,
            max_xattrs_per_entry: 16,
            max_xattr_value_bytes: 4 << 10,
            max_zstd_window_log: 27,
            extent_bytes: 4 << 20,
            max_attestation_bytes: 16 << 20,
            max_tree_object_bytes: 512 << 20,
        }
    }
}

/// A limit set that cannot be enforced as written.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum LimitsProblem {
    /// A ratio below 1 would refuse every stored byte.
    RatioBelowOne,
    ZeroExtent,
    /// zstd accepts window logs from 10 to 31.
    ZstdWindowLog {
        log: u32,
    },
    /// A per-layer bound larger than its image-wide bound.
    LayerAboveImage {
        field: &'static str,
    },
}

impl fmt::Display for LimitsProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RatioBelowOne => f.write_str("the expansion ratio must be at least 1"),
            Self::ZeroExtent => f.write_str("the extent length must be positive"),
            Self::ZstdWindowLog { log } => {
                write!(f, "zstd window log {log} is outside 10 to 31")
            }
            Self::LayerAboveImage { field } => {
                write!(f, "{field} per layer exceeds its image-wide bound")
            }
        }
    }
}

impl std::error::Error for LimitsProblem {}

impl ImportLimits {
    /// Checks that the limits can be enforced together.
    pub fn validate(&self) -> Result<(), LimitsProblem> {
        if self.max_ratio < 1 {
            return Err(LimitsProblem::RatioBelowOne);
        }
        if self.extent_bytes == 0 {
            return Err(LimitsProblem::ZeroExtent);
        }
        if !(10..=31).contains(&self.max_zstd_window_log) {
            return Err(LimitsProblem::ZstdWindowLog {
                log: self.max_zstd_window_log,
            });
        }
        if self.max_layer_compressed_bytes > self.max_image_compressed_bytes {
            return Err(LimitsProblem::LayerAboveImage {
                field: "compressed bytes",
            });
        }
        if self.max_layer_expanded_bytes > self.max_image_expanded_bytes {
            return Err(LimitsProblem::LayerAboveImage {
                field: "expanded bytes",
            });
        }
        if self.max_entries_per_layer > self.max_image_entries {
            return Err(LimitsProblem::LayerAboveImage { field: "entries" });
        }
        Ok(())
    }

    /// V05's archive bounds for one layer's entry list.
    pub(crate) fn layer_archive_limits(&self) -> ArchiveLimits {
        ArchiveLimits {
            max_entries: self.max_entries_per_layer,
            max_entry_uncompressed_bytes: self.max_file_bytes,
            max_total_uncompressed_bytes: self.max_layer_expanded_bytes,
            max_ratio: self.max_ratio,
        }
    }

    /// V05's archive bounds for the merged tree, whose entries are declared stored.
    pub(crate) fn tree_archive_limits(&self) -> ArchiveLimits {
        ArchiveLimits {
            max_entries: self.max_image_entries,
            max_entry_uncompressed_bytes: self.max_file_bytes,
            max_total_uncompressed_bytes: self.max_image_expanded_bytes,
            max_ratio: self.max_ratio,
        }
    }
}

/// `n` as u64; lengths of in-memory values always fit.
pub(crate) fn len_u64(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `text` cut to at most `max_bytes` on a character boundary, for refusal details.
pub(crate) fn bounded_text(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_owned();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    text.get(..end).unwrap_or("").to_owned()
}

/// Longest free text kept in a refusal.
pub(crate) const MAX_DETAIL_BYTES: usize = 256;

/// A refusal detail: `text` bounded to [`MAX_DETAIL_BYTES`].
pub(crate) fn detail(text: impl fmt::Display) -> String {
    bounded_text(&text.to_string(), MAX_DETAIL_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_limits_are_enforceable() {
        assert_eq!(ImportLimits::default().validate(), Ok(()));
    }

    #[test]
    fn unenforceable_limits_are_refused() {
        let base = ImportLimits::default();
        assert_eq!(
            ImportLimits {
                max_ratio: 0,
                ..base
            }
            .validate(),
            Err(LimitsProblem::RatioBelowOne)
        );
        assert_eq!(
            ImportLimits {
                extent_bytes: 0,
                ..base
            }
            .validate(),
            Err(LimitsProblem::ZeroExtent)
        );
        assert_eq!(
            ImportLimits {
                max_zstd_window_log: 32,
                ..base
            }
            .validate(),
            Err(LimitsProblem::ZstdWindowLog { log: 32 })
        );
        assert_eq!(
            ImportLimits {
                max_layer_expanded_bytes: base.max_image_expanded_bytes + 1,
                ..base
            }
            .validate(),
            Err(LimitsProblem::LayerAboveImage {
                field: "expanded bytes"
            })
        );
        assert_eq!(
            ImportLimits {
                max_entries_per_layer: base.max_image_entries + 1,
                ..base
            }
            .validate(),
            Err(LimitsProblem::LayerAboveImage { field: "entries" })
        );
    }

    #[test]
    fn details_are_bounded_on_a_character_boundary() {
        assert_eq!(bounded_text("abc", 2), "ab");
        assert_eq!(bounded_text("é", 1), "");
        assert_eq!(detail("x".repeat(1000)).len(), MAX_DETAIL_BYTES);
    }
}
