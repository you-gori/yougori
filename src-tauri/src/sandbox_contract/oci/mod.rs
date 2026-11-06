//! V10: the OCI/application importer's pure half (docs/combined-gpu-memory-and-vm-sandbox-plan.md,
//! VM-W33 line 2474, §5.1–§5.3 lines 2043–2082, §8.3 line 2278, VM-P37 line 2637, VM-CP-15
//! line 2990, VM-CP-30 line 3005). Tier 0 only (§12.1 line 2587): pure, synchronous,
//! deterministic library code over in-memory blobs.
//!
//! It is the specialized importer that the CORE-02 catalog names: it supplies
//! [`ImportSource`](crate::foundation::catalog::ImportSource)s and the
//! [`ArtifactVerifier`](crate::foundation::catalog::ArtifactVerifier) for
//! [`ArtifactClass::OciLayer`](crate::foundation::catalog::ArtifactClass::OciLayer).
//!
//! - **Documents** ([`parse_index`], [`parse_manifest`], [`parse_config`]): schema version 2
//!   and OCI/Docker schema-2 image media types, unknown fields and duplicate keys refused, descriptors with
//!   `urls` refused (§5.3 "prohibit undeclared backing files"), bounded annotations, and an
//!   exact platform choice that never falls back to another platform.
//! - **Blobs** ([`VerifiedBlob`]): every blob is checked against its descriptor's sha256
//!   digest and size before anything parses it, and the parser reads exactly the bytes
//!   that were hashed, which binds the opened artifact to its verified identity (§8.3).
//! - **Layers** ([`read_layer`]): tar, tar+gzip or tar+zstd exactly as the media type says,
//!   never sniffed. Expansion is metered while streaming and stops at the first limit, so a
//!   bomb never fully expands; the expanded stream must match the config's diff_id. Every
//!   entry goes through V05's [`check_archive`](crate::sandbox_contract::files::check_archive)
//!   and image-specific [`ImageName`](crate::sandbox_contract::files::ImageName) checks; this module adds
//!   only the OCI-specific checks (tar framing, PAX and xattr records, whiteouts, setuid and
//!   setgid bits, diff_ids).
//! - **Whiteouts and the tree** ([`TreeBuilder`]): `.wh.<name>` and `.wh..wh..opq` applied
//!   across the layer stack into one read-only [`TreeIndex`], checked again as a whole by
//!   the shared archive checks for names, links and exact-name collisions.
//! - **Publication** ([`OciImporter`]): each verified layer and the tree index are
//!   published as content-addressed read-only catalog objects. Trust comes only from the
//!   catalog's [`TrustPolicy`](crate::foundation::catalog::TrustPolicy) through
//!   [`OciVerifier`]; a digest names content and is never trust (§5.3).
//! - **Overlays** ([`OverlayRegistry`]): a consumer gets an overlay bound to one sandbox and
//!   boot generation over the read-only bases, never shared; shared mutable caches are
//!   refused.
//! - **Config is data** ([`ImageConfigRecord`]): entrypoint, cmd, env, user, labels,
//!   healthcheck, onbuild and shell are recorded as bounded data. This module has no
//!   process API at all: the host never runs image hooks or entrypoints (VM-W33).
//!
//! What this does not claim:
//!
//! - The host never materializes the image tree on its filesystem. The catalog stores
//!   enveloped blobs and a tree index; extraction happens inside the VM later, which
//!   checks each file against the index's sha256 as it writes it.
//! - It is not the race-proof runtime resolver of line 2047. Names pass the bounded image-name filter, which
//!   is a first filter only; handle-relative resolution beneath an opened root is runtime
//!   work. Junctions, reparse points, alternate data streams on disk and rename races
//!   cannot be expressed in a tar stream and stay with the file broker (VM-CP-15).
//! - A verified digest is not publisher trust, and Tier 0 does not verify real signatures:
//!   [`PublisherSignatures`] is a port, and the tests use a keyed-digest fake.
//! - Archive parsing is an attack surface (§5.2 line 2073). This is the parser a
//!   constrained helper or the importer VM runs; the caller declares where it runs and a
//!   host process or host mount is refused, but Tier 0 cannot enforce the placement.

/// Declares an internally tagged enum whose deserializer refuses unknown fields on every
/// variant, unit variants included (serde ignores fields next to the tag of a unit
/// variant even with `deny_unknown_fields`). Copied from `sandbox_contract/policy` so this
/// module depends on no other module's macros.
macro_rules! strict_oci_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident tag $tag:literal {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident $({
                    $(
                        $(#[$field_meta:meta])*
                        $field:ident : $ty:ty
                    ),* $(,)?
                })?
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(serde::Serialize)]
        #[serde(tag = $tag, rename_all = "snake_case")]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant $({ $($(#[$field_meta])* $field : $ty),* })?
            ),*
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                #[derive(serde::Deserialize)]
                #[serde(tag = $tag, rename_all = "snake_case", deny_unknown_fields)]
                enum Strict {
                    $($variant { $($($field : $ty),*)? }),*
                }
                let record = crate::foundation::strict_serde::read_tagged(deserializer, $tag)?;
                let strict = <Strict as serde::Deserialize>::deserialize(record)
                    .map_err(serde::de::Error::custom)?;
                Ok(match strict {
                    $(Strict::$variant { $($($field),*)? } => Self::$variant $({ $($field),* })?),*
                })
            }
        }
    };
}

mod archive;
mod config;
mod digest;
mod document;
mod envelope;
mod import;
mod layer;
mod limits;
mod overlay;
mod tar;
mod tree;
mod verifier;
mod workload;

pub use workload::{workload_file, WorkloadImage, WorkloadLayer, WorkloadObject, WorkloadProcess};

#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod tests;

pub use config::{
    parse_config, ConfigRefusal, HealthcheckData, HistoryRecord, HookData, ImageConfigRecord,
    ProcessData,
};
pub use digest::{
    BlobReference, BlobRefusal, DigestRefusal, LayerCodec, MediaType, OciDigest, VerifiedBlob,
};
pub use document::{
    parse_index, parse_manifest, select_platform, AnnotationRefusal, Annotations, Descriptor,
    DescriptorAt, DocumentRefusal, ImageIndex, ImageManifest, Platform,
};
pub use envelope::{EnvelopeKind, EnvelopeRefusal, LAYER_MAGIC, TREE_MAGIC};
pub use import::{
    BlobAt, BlobSource, BlobSourceError, CatalogStep, ImportedImage, ImportedLayer, ImportedTree,
    MemoryBlobs, OciImportError, OciImportRequest, OciImporter, OciTrust, PreparedImage,
    ProvenanceRefusal, ReadLayers,
};
pub use layer::{
    read_layer, ImageBudget, LayerEntry, LayerEntryKind, LayerRefusal, LayerReport, StreamRefusal,
    WhiteoutRefusal,
};
pub use limits::{ImportLimits, LimitsProblem};
pub use overlay::{
    ImageObjects, Materialization, OverlayDescriptor, OverlayId, OverlayRefusal, OverlayRegistry,
    OverlayRequest, UpperLayer, WritableCache,
};
pub use tar::TarRefusal;
pub use tree::{
    FileContent, TreeBuilder, TreeEntry, TreeIndex, TreeNode, TreeRefusal, TreeSummary,
};
pub use verifier::{
    manifest_statement, OciAttestation, OciVerifier, PublisherSignatures, SignatureRefusal,
    STATEMENT_DOMAIN,
};
