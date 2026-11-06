//! The image declaration bound into a VM launch and delivered through fw_cfg.
//! Filenames are flat, host-owned names in read-only grant 2, never host paths.
use super::{MediaType, OciDigest};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const WORKLOAD_FORMAT: &str = "yougori-workload/v1";
pub const MAX_WORKLOAD_BYTES: usize = 256 << 10;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadObject {
    pub file: String,
    pub size_bytes: u64,
    pub digest: OciDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadLayer {
    pub file: String,
    pub media_type: MediaType,
    pub size_bytes: u64,
    pub digest: OciDigest,
    pub diff_id: OciDigest,
    pub expanded_bytes: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadProcess {
    pub entrypoint: Vec<String>,
    pub cmd: Vec<String>,
    pub env: Vec<String>,
    pub working_dir: String,
    pub user: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkloadImage {
    pub manifest: OciDigest,
    pub tree: WorkloadObject,
    pub layers: Vec<WorkloadLayer>,
    pub root_bytes: u64,
    pub process: WorkloadProcess,
}

impl WorkloadImage {
    /// Check the envelope-to-launch binding before exposing its body on grant 2.
    /// No archive is parsed here: consumers repeat hash and layout checks inside VMs.
    pub fn object_body<'a>(&self, index: usize, envelope: &'a [u8]) -> Result<&'a [u8], String> {
        use super::envelope::{parse_fixed, parse_prefix, EnvelopeHeader};
        let (_, length) = parse_fixed(envelope).map_err(|e| e.to_string())?;
        let end = 12usize
            .checked_add(length)
            .ok_or("Envelope length overflow")?;
        let prefix = envelope.get(..end).ok_or("Truncated image envelope")?;
        let header = parse_prefix(prefix).map_err(|e| e.to_string())?;
        let (size, hash) = if index == 0 {
            match header {
                EnvelopeHeader::Tree(h)
                    if h.manifest == self.manifest
                        && h.layers == self.layers.iter().map(|l| l.digest).collect::<Vec<_>>()
                        && h.diff_ids
                            == self.layers.iter().map(|l| l.diff_id).collect::<Vec<_>>() => {}
                _ => return Err("The catalog tree does not belong to this image".into()),
            }
            (self.tree.size_bytes, self.tree.digest)
        } else {
            let layer = self.layers.get(index - 1).ok_or("Unknown image layer")?;
            match header {
                EnvelopeHeader::Layer(h)
                    if h.layer.digest == layer.digest
                        && h.layer.media_type == layer.media_type
                        && h.layer.size_bytes == layer.size_bytes
                        && h.diff_id == layer.diff_id => {}
                _ => return Err("The catalog layer does not belong to this image".into()),
            }
            (layer.size_bytes, layer.digest)
        };
        let body = envelope.get(end..).ok_or("Truncated image object")?;
        if body.len() as u64 != size || OciDigest::of(body) != hash {
            return Err("The image object differs from its launch declaration".into());
        }
        Ok(body)
    }

    pub fn validate(&self) -> Result<(), String> {
        let flat = |name: &str| {
            !name.is_empty()
                && name.len() <= 128
                && name != "."
                && name != ".."
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
        };
        if self.layers.is_empty()
            || self.layers.len() > 128
            || self.root_bytes == 0
            || self.root_bytes > 64 << 30
            || self.tree.size_bytes == 0
            || self.tree.size_bytes > 512 << 20
            || !flat(&self.tree.file)
        {
            return Err("The image declaration has invalid object or root bounds.".into());
        }
        let mut names = BTreeSet::from([self.tree.file.to_ascii_lowercase()]);
        let mut expanded = 0u64;
        for layer in &self.layers {
            if !flat(&layer.file)
                || !names.insert(layer.file.to_ascii_lowercase())
                || layer.media_type.layer_codec().is_none()
                || layer.size_bytes == 0
                || layer.size_bytes > 4 << 30
                || layer.expanded_bytes == 0
                || layer.expanded_bytes > 16 << 30
                || layer.expanded_bytes > layer.size_bytes.saturating_mul(200)
            {
                return Err("An image layer has an unsupported codec, name or extent.".into());
            }
            expanded = expanded
                .checked_add(layer.expanded_bytes)
                .ok_or("Image extent overflow.")?;
        }
        if expanded > 64 << 30 {
            return Err("The image's expanded extent exceeds 64 GiB.".into());
        }
        let p = &self.process;
        if p.entrypoint.len() > 256
            || p.cmd.len() > 256
            || p.env.len() > 256
            || p.entrypoint
                .iter()
                .chain(&p.cmd)
                .chain(&p.env)
                .any(|s| s.len() > 8192 || s.contains('\0'))
            || p.working_dir.len() > 4096
            || p.working_dir.contains('\0')
            || (!p.working_dir.is_empty() && !p.working_dir.starts_with('/'))
            || p.env
                .iter()
                .any(|s| s.split_once('=').is_none_or(|(k, _)| k.is_empty()))
            || !matches!(p.user.as_str(), "" | "1000" | "1000:1000")
        {
            return Err(
                "Unsupported image process configuration; this sandbox runs as uid/gid 1000."
                    .into(),
            );
        }
        if workload_file(Some(self))?.len() > MAX_WORKLOAD_BYTES {
            return Err("The image declaration exceeds its boot bound.".into());
        }
        Ok(())
    }
}

pub fn workload_file(image: Option<&WorkloadImage>) -> Result<Vec<u8>, String> {
    #[derive(Serialize)]
    struct Declaration<'a> {
        format: &'static str,
        image: Option<&'a WorkloadImage>,
    }
    serde_json::to_vec(&Declaration {
        format: WORKLOAD_FORMAT,
        image,
    })
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::super::envelope::{layer_envelope, tree_envelope, TreeHeader};
    use super::super::{BlobReference, ImportLimits, TreeBuilder, VerifiedBlob};
    use super::*;

    #[test]
    fn a_launch_is_bound_to_the_catalog_envelope_and_body() {
        let blob = VerifiedBlob::verify(
            BlobReference {
                media_type: MediaType::LayerTar,
                digest: OciDigest::of(b"payload"),
                size_bytes: 7,
            },
            b"payload".to_vec(),
        )
        .unwrap();
        let diff = OciDigest::of(b"expanded");
        let layer = layer_envelope(&blob, diff).unwrap();
        let tree = TreeBuilder::new(&ImportLimits::default()).finish().unwrap();
        let body = tree.body_bytes().unwrap();
        let manifest = OciDigest::of(b"manifest");
        let tree_object = tree_envelope(
            &TreeHeader {
                manifest,
                config: OciDigest::of(b"config"),
                layers: vec![blob.reference().digest],
                diff_ids: vec![diff],
            },
            &tree,
        )
        .unwrap();
        let mut image = WorkloadImage {
            manifest,
            root_bytes: 64 << 20,
            tree: WorkloadObject {
                file: "tree.json".into(),
                size_bytes: body.len() as u64,
                digest: OciDigest::of(&body),
            },
            layers: vec![WorkloadLayer {
                file: "layer-000".into(),
                media_type: MediaType::LayerTar,
                size_bytes: 7,
                digest: blob.reference().digest,
                diff_id: diff,
                expanded_bytes: 7,
            }],
            process: WorkloadProcess::default(),
        };
        image.validate().unwrap();
        assert_eq!(image.object_body(0, &tree_object.bytes).unwrap(), body);
        assert_eq!(image.object_body(1, &layer.bytes).unwrap(), b"payload");
        assert!(image.object_body(0, &layer.bytes).is_err());
        let mut corrupt = layer.bytes.clone();
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(image.object_body(1, &corrupt).is_err());
        image.manifest = OciDigest::of(b"another-image");
        assert!(image.object_body(0, &tree_object.bytes).is_err());
        image.layers[0].file = "TREE.JSON".into();
        assert!(image.validate().is_err());
    }
}
