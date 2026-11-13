//! Fixtures for the OCI importer tests: tar streams built in memory with the tar crate,
//! hand-written headers for what the crate refuses to write, gzip and zstd encodings,
//! images assembled into [`MemoryBlobs`], a keyed-digest signature fake and a catalog
//! whose only file system use is a temporary root.

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};

use super::digest::{BlobReference, LayerCodec, MediaType, OciDigest, VerifiedBlob};
use super::document::Platform;
use super::import::{
    ImportedImage, MemoryBlobs, OciImportError, OciImportRequest, OciImporter, OciTrust,
};
use super::limits::ImportLimits;
use super::verifier::{manifest_statement, PublisherSignatures, SignatureRefusal};
use crate::foundation::catalog::{
    ArtifactClass, Catalog, CatalogConfig, PublisherId, Scope, TrustPolicy, VerifierRegistry,
};
use crate::foundation::ids::{
    digest, Digest, ExecutionId, ManualClock, MonotonicTime, OperationId, TenantId,
};
use crate::sandbox_contract::files::InspectionMethod;

/// One entry for the tar crate builder.
#[derive(Clone, Debug)]
pub enum Fx {
    File {
        name: String,
        data: Vec<u8>,
        mode: u32,
    },
    Dir {
        name: String,
        mode: u32,
    },
    Symlink {
        name: String,
        target: String,
    },
    HardLink {
        name: String,
        target: String,
    },
    Fifo {
        name: String,
    },
    CharDevice {
        name: String,
    },
    BlockDevice {
        name: String,
    },
    /// A PAX extended header for the next entry.
    Pax {
        records: Vec<(String, Vec<u8>)>,
    },
}

pub fn file(name: &str, data: &[u8]) -> Fx {
    Fx::File {
        name: name.into(),
        data: data.to_vec(),
        mode: 0o644,
    }
}

pub fn file_mode(name: &str, data: &[u8], mode: u32) -> Fx {
    Fx::File {
        name: name.into(),
        data: data.to_vec(),
        mode,
    }
}

pub fn dir(name: &str) -> Fx {
    Fx::Dir {
        name: name.into(),
        mode: 0o755,
    }
}

pub fn symlink(name: &str, target: &str) -> Fx {
    Fx::Symlink {
        name: name.into(),
        target: target.into(),
    }
}

pub fn hardlink(name: &str, target: &str) -> Fx {
    Fx::HardLink {
        name: name.into(),
        target: target.into(),
    }
}

pub fn pax(records: &[(&str, &[u8])]) -> Fx {
    Fx::Pax {
        records: records
            .iter()
            .map(|(key, value)| ((*key).to_owned(), value.to_vec()))
            .collect(),
    }
}

/// A PAX record set's bytes: each record is "<length> <key>=<value>\n", the length
/// counting itself.
pub fn pax_bytes(records: &[(String, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (key, value) in records {
        let body = key.len() + value.len() + 3;
        let mut length = body + 1;
        while (body + length.to_string().len()) != length {
            length = body + length.to_string().len();
        }
        out.extend_from_slice(format!("{length} {key}=").as_bytes());
        out.extend_from_slice(value);
        out.push(b'\n');
    }
    out
}

fn header(kind: tar::EntryType, size: u64, mode: u32) -> tar::Header {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(kind);
    header.set_size(size);
    header.set_mode(mode);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(1_700_000_000);
    header
}

/// A tar stream built by the tar crate, ending with its two zero blocks.
pub fn tar_of(entries: &[Fx]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for entry in entries {
        match entry {
            Fx::File { name, data, mode } => {
                let mut h = header(tar::EntryType::Regular, data.len() as u64, *mode);
                builder.append_data(&mut h, name, &data[..]).unwrap();
            }
            Fx::Dir { name, mode } => {
                let mut h = header(tar::EntryType::Directory, 0, *mode);
                builder.append_data(&mut h, name, &[][..]).unwrap();
            }
            Fx::Symlink { name, target } => {
                let mut h = header(tar::EntryType::Symlink, 0, 0o777);
                h.set_path(name).unwrap();
                h.set_link_name_literal(target).unwrap();
                h.set_cksum();
                builder.append(&h, &[][..]).unwrap();
            }
            Fx::HardLink { name, target } => {
                let mut h = header(tar::EntryType::Link, 0, 0o644);
                h.set_path(name).unwrap();
                h.set_link_name_literal(target).unwrap();
                h.set_cksum();
                builder.append(&h, &[][..]).unwrap();
            }
            Fx::Fifo { name } => {
                let mut h = header(tar::EntryType::Fifo, 0, 0o644);
                builder.append_data(&mut h, name, &[][..]).unwrap();
            }
            Fx::CharDevice { name } => {
                let mut h = header(tar::EntryType::Char, 0, 0o644);
                builder.append_data(&mut h, name, &[][..]).unwrap();
            }
            Fx::BlockDevice { name } => {
                let mut h = header(tar::EntryType::Block, 0, 0o644);
                builder.append_data(&mut h, name, &[][..]).unwrap();
            }
            Fx::Pax { records } => {
                let data = pax_bytes(records);
                let mut h = tar::Header::new_ustar();
                h.set_entry_type(tar::EntryType::XHeader);
                h.set_size(data.len() as u64);
                h.set_mode(0o644);
                h.set_mtime(0);
                h.set_path("PaxHeaders/entry").unwrap();
                h.set_cksum();
                builder.append(&h, &data[..]).unwrap();
            }
        }
    }
    builder.into_inner().unwrap()
}

/// A hand-written ustar header, for what the tar crate refuses to write.
#[derive(Clone, Debug)]
pub struct Raw {
    pub name: Vec<u8>,
    pub flag: u8,
    pub data: Vec<u8>,
    /// The size field text; the data length when `None`.
    pub size_field: Option<Vec<u8>>,
    pub mode_field: Vec<u8>,
    pub link: Vec<u8>,
    pub magic: [u8; 8],
    pub break_checksum: bool,
}

pub const POSIX_MAGIC: [u8; 8] = *b"ustar\x0000";
pub const GNU_MAGIC: [u8; 8] = *b"ustar  \x00";

pub fn raw(name: &str, flag: u8, data: &[u8]) -> Raw {
    Raw {
        name: name.as_bytes().to_vec(),
        flag,
        data: data.to_vec(),
        size_field: None,
        mode_field: b"0000644\0".to_vec(),
        link: Vec::new(),
        magic: POSIX_MAGIC,
        break_checksum: false,
    }
}

pub fn raw_file(name: &str, data: &[u8]) -> Raw {
    raw(name, b'0', data)
}

pub fn raw_link(name: &str, flag: u8, target: &str) -> Raw {
    Raw {
        link: target.as_bytes().to_vec(),
        ..raw(name, flag, b"")
    }
}

fn put(block: &mut [u8; 512], start: usize, bytes: &[u8]) {
    block[start..start + bytes.len()].copy_from_slice(bytes);
}

pub fn raw_header(entry: &Raw) -> [u8; 512] {
    let mut block = [0u8; 512];
    put(&mut block, 0, &entry.name[..entry.name.len().min(100)]);
    put(&mut block, 100, &entry.mode_field);
    put(&mut block, 108, b"0000000\0");
    put(&mut block, 116, b"0000000\0");
    let size = entry
        .size_field
        .clone()
        .unwrap_or_else(|| format!("{:011o}\0", entry.data.len()).into_bytes());
    put(&mut block, 124, &size);
    put(&mut block, 136, b"14544320000\0");
    block[156] = entry.flag;
    put(&mut block, 157, &entry.link[..entry.link.len().min(100)]);
    put(&mut block, 257, &entry.magic);
    put(&mut block, 148, b"        ");
    let sum: u64 = block.iter().map(|byte| u64::from(*byte)).sum();
    let sum = if entry.break_checksum { sum + 1 } else { sum };
    put(&mut block, 148, format!("{sum:06o}\0 ").as_bytes());
    block
}

/// The header, the data and zero padding to the next block.
pub fn raw_entry(entry: &Raw) -> Vec<u8> {
    let mut out = raw_header(entry).to_vec();
    out.extend_from_slice(&entry.data);
    out.resize(out.len().div_ceil(512) * 512, 0);
    out
}

/// Entries followed by the two zero blocks.
pub fn raw_tar(entries: &[Raw]) -> Vec<u8> {
    let mut out: Vec<u8> = entries.iter().flat_map(raw_entry).collect();
    out.extend_from_slice(&[0u8; 1024]);
    out
}

/// `count` pseudo-random bytes from a xorshift64 generator seeded with `seed`: the same
/// bytes on every run, and hardly compressible.
pub fn seeded_bytes(count: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..count)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect()
}

pub fn gzip(bytes: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(bytes).unwrap();
    encoder.finish().unwrap()
}

pub fn zstd(bytes: &[u8]) -> Vec<u8> {
    zstd::stream::encode_all(bytes, 3).unwrap()
}

/// `tar` encoded as `codec`, and its media type.
pub fn encode(tar: &[u8], codec: LayerCodec) -> (Vec<u8>, MediaType) {
    match codec {
        LayerCodec::Uncompressed => (tar.to_vec(), MediaType::LayerTar),
        LayerCodec::Gzip => (gzip(tar), MediaType::LayerTarGzip),
        LayerCodec::Zstd => (zstd(tar), MediaType::LayerTarZstd),
    }
}

/// A verified blob of `bytes` declared as `media_type`, whatever the bytes are.
pub fn verified(bytes: Vec<u8>, media_type: MediaType) -> VerifiedBlob {
    VerifiedBlob::verify(
        BlobReference {
            media_type,
            digest: OciDigest::of(&bytes),
            size_bytes: bytes.len() as u64,
        },
        bytes,
    )
    .unwrap()
}

/// A layer blob of `tar` as `codec`, and the tar stream's diff_id.
pub fn layer(tar: &[u8], codec: LayerCodec) -> (VerifiedBlob, OciDigest) {
    let (bytes, media_type) = encode(tar, codec);
    (verified(bytes, media_type), OciDigest::of(tar))
}

/// An image in a blob store.
pub struct ImageFx {
    pub blobs: MemoryBlobs,
    pub manifest: BlobReference,
    pub manifest_bytes: Vec<u8>,
    pub config_bytes: Vec<u8>,
    pub layers: Vec<BlobReference>,
    pub layer_bytes: Vec<Vec<u8>>,
    /// The root a request pins: the manifest, or the index after [`ImageFx::indexed`].
    pub root: BlobReference,
}

pub fn config_json(diff_ids: &[OciDigest]) -> Value {
    json!({
        "created": "2026-10-01T12:00:00Z",
        "architecture": "amd64",
        "os": "linux",
        "config": {"Env": ["PATH=/usr/bin"], "Cmd": ["/bin/app"]},
        "rootfs": {"type": "layers", "diff_ids": diff_ids.iter().map(|d| d.to_string()).collect::<Vec<_>>()}
    })
}

fn document(
    blobs: &mut MemoryBlobs,
    media_type: MediaType,
    value: &Value,
) -> (BlobReference, Vec<u8>) {
    let bytes = serde_json::to_vec(value).unwrap();
    let digest = blobs.insert(bytes.clone());
    (
        BlobReference {
            media_type,
            digest,
            size_bytes: bytes.len() as u64,
        },
        bytes,
    )
}

/// An image of `layers` (tar streams and codecs) with the config and manifest edited.
pub fn image_with(
    layers: &[(Vec<u8>, LayerCodec)],
    edit_config: impl FnOnce(&mut Value),
    edit_manifest: impl FnOnce(&mut Value),
) -> ImageFx {
    let mut blobs = MemoryBlobs::new();
    let mut references = Vec::new();
    let mut layer_bytes = Vec::new();
    let mut diff_ids = Vec::new();
    for (tar, codec) in layers {
        let (bytes, media_type) = encode(tar, *codec);
        let digest = blobs.insert(bytes.clone());
        references.push(BlobReference {
            media_type,
            digest,
            size_bytes: bytes.len() as u64,
        });
        layer_bytes.push(bytes);
        diff_ids.push(OciDigest::of(tar));
    }
    let mut config = config_json(&diff_ids);
    edit_config(&mut config);
    let (config_ref, config_bytes) = document(&mut blobs, MediaType::ImageConfig, &config);
    let mut manifest = json!({
        "schemaVersion": 2,
        "mediaType": MediaType::ImageManifest.as_str(),
        "config": {"mediaType": MediaType::ImageConfig.as_str(), "digest": config_ref.digest.to_string(), "size": config_ref.size_bytes},
        "layers": references.iter().map(|r| json!({"mediaType": r.media_type.as_str(), "digest": r.digest.to_string(), "size": r.size_bytes})).collect::<Vec<_>>()
    });
    edit_manifest(&mut manifest);
    let (manifest_ref, manifest_bytes) = document(&mut blobs, MediaType::ImageManifest, &manifest);
    ImageFx {
        blobs,
        manifest: manifest_ref,
        manifest_bytes,
        config_bytes,
        layers: references,
        layer_bytes,
        root: manifest_ref,
    }
}

pub fn image(layers: &[(Vec<u8>, LayerCodec)]) -> ImageFx {
    image_with(layers, |_| {}, |_| {})
}

/// The usual two-layer image: a gzip base and a zstd layer on top.
pub fn two_layer_image() -> ImageFx {
    image(&[
        (
            tar_of(&[
                dir("app"),
                file("app/main", b"#!/bin/sh\necho hi\n"),
                file("app/old", b"old"),
            ]),
            LayerCodec::Gzip,
        ),
        (
            tar_of(&[
                dir("app"),
                file("app/.wh.old", b""),
                file("app/new", b"new"),
            ]),
            LayerCodec::Zstd,
        ),
    ])
}

impl ImageFx {
    /// Puts an index in front of the manifest, listing it for `platform` beside a decoy for
    /// another platform, and pins the index as the root.
    pub fn indexed(mut self, platform: Value) -> Self {
        let index = json!({
            "schemaVersion": 2,
            "mediaType": MediaType::ImageIndex.as_str(),
            "manifests": [
                {"mediaType": MediaType::ImageManifest.as_str(), "digest": OciDigest::of(b"decoy").to_string(), "size": 5, "platform": {"os": "linux", "architecture": "arm64", "variant": "v8"}},
                {"mediaType": MediaType::ImageManifest.as_str(), "digest": self.manifest.digest.to_string(), "size": self.manifest.size_bytes, "platform": platform}
            ]
        });
        let (root, _) = document(&mut self.blobs, MediaType::ImageIndex, &index);
        self.root = root;
        self
    }
}

/// A keyed-digest stand-in for publisher signatures. Not cryptographic signing: Tier 0
/// only needs a verifier that accepts what the matching key made and nothing else.
#[derive(Default)]
pub struct FakeSignatures {
    keys: BTreeMap<PublisherId, Vec<u8>>,
}

pub fn publisher_of(secret: &[u8]) -> PublisherId {
    PublisherId::from_key_fingerprint(digest("yougori/test/fake-key/v1", &[secret]))
}

fn keyed(secret: &[u8], statement: &Digest) -> Vec<u8> {
    digest(
        "yougori/test/fake-signature/v1",
        &[secret, statement.as_bytes()],
    )
    .as_bytes()
    .to_vec()
}

pub fn sign(secret: &[u8], manifest: &OciDigest) -> Vec<u8> {
    keyed(secret, &manifest_statement(manifest))
}

impl FakeSignatures {
    pub fn with_keys(secrets: &[&[u8]]) -> Self {
        Self {
            keys: secrets
                .iter()
                .map(|secret| (publisher_of(secret), secret.to_vec()))
                .collect(),
        }
    }
}

impl PublisherSignatures for FakeSignatures {
    fn verify(
        &self,
        publisher: &PublisherId,
        statement: &Digest,
        signature: &[u8],
    ) -> Result<(), SignatureRefusal> {
        let secret = self
            .keys
            .get(publisher)
            .ok_or(SignatureRefusal::UnknownPublisher)?;
        if keyed(secret, statement) == signature {
            Ok(())
        } else {
            Err(SignatureRefusal::BadSignature)
        }
    }
}

pub const TRUSTED_KEY: &[u8] = b"trusted publisher key";
pub const ROGUE_KEY: &[u8] = b"rogue publisher key";

pub fn tenant(name: &str) -> Scope {
    Scope::tenant(TenantId::new(name).unwrap())
}

pub fn execution(name: &str) -> ExecutionId {
    ExecutionId::new(name).unwrap()
}

/// A catalog in a temporary root with the OCI verifier registered, quotas for the host and
/// tenants a and b, and a policy trusting [`TRUSTED_KEY`]'s publisher and user selections.
pub struct Harness {
    pub dir: tempfile::TempDir,
    pub catalog: Catalog,
    pub clock: Arc<ManualClock>,
    pub importer: OciImporter,
    pub publisher: PublisherId,
}

pub fn catalog_config(publisher: PublisherId) -> CatalogConfig {
    CatalogConfig::new(Duration::from_secs(60))
        .with_quota(Scope::Host, 1 << 30)
        .with_quota(tenant("a"), 1 << 30)
        .with_quota(tenant("b"), 1 << 30)
        .with_trust(
            ArtifactClass::OciLayer,
            TrustPolicy::new()
                .trust_publisher(publisher)
                .accept_user_selected(),
        )
}

impl Harness {
    pub fn new() -> Self {
        Self::with_limits(ImportLimits::default())
    }

    pub fn with_limits(limits: ImportLimits) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(ManualClock::new(MonotonicTime::from_nanos(1_000)));
        let signatures = Arc::new(FakeSignatures::with_keys(&[TRUSTED_KEY, ROGUE_KEY]));
        let importer = OciImporter::new(limits, signatures).unwrap();
        let publisher = publisher_of(TRUSTED_KEY);
        let mut registry = VerifierRegistry::new();
        registry.register(Box::new(importer.verifier())).unwrap();
        let (catalog, _) = Catalog::open(
            dir.path(),
            catalog_config(publisher),
            registry,
            clock.clone(),
        )
        .unwrap();
        Self {
            dir,
            catalog,
            clock,
            importer,
            publisher,
        }
    }

    /// Reopens the catalog from its root with a fresh verifier, as a restart would: the open
    /// catalog is closed first, since one catalog at a time holds a root.
    pub fn reopen(self) -> Self {
        let config = self.catalog.config().clone();
        let Self {
            dir,
            catalog,
            clock,
            importer,
            publisher,
        } = self;
        drop(catalog);
        let mut registry = VerifierRegistry::new();
        registry.register(Box::new(importer.verifier())).unwrap();
        let (catalog, _) = Catalog::open(dir.path(), config, registry, clock.clone()).unwrap();
        Self {
            dir,
            catalog,
            clock,
            importer,
            publisher,
        }
    }

    /// A request for `fx` into `scope`, signed by the trusted publisher.
    pub fn request(&self, fx: &ImageFx, scope: Scope) -> OciImportRequest {
        OciImportRequest {
            operation: OperationId::new("op-import").unwrap(),
            importer: execution("importer-1"),
            scope,
            root: fx.root,
            platform: Platform::new("linux", "amd64"),
            trust: OciTrust::Publisher {
                publisher: self.publisher,
                signature: sign(TRUSTED_KEY, &fx.manifest.digest),
            },
            inspection: InspectionMethod::SeparateVm,
        }
    }

    pub fn import_request(
        &mut self,
        fx: &mut ImageFx,
        request: &OciImportRequest,
    ) -> Result<ImportedImage, OciImportError> {
        self.importer
            .import(&mut self.catalog, &mut fx.blobs, request)
    }

    pub fn import(
        &mut self,
        fx: &mut ImageFx,
        scope: Scope,
    ) -> Result<ImportedImage, OciImportError> {
        let request = self.request(fx, scope);
        self.import_request(fx, &request)
    }
}
