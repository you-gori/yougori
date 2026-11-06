//! Reusable compile artifacts under an exact ABI key, with no live device pointer in any
//! persisted record (GPU §4.5 line 705: "Store reusable compile artifacts under an exact
//! ABI key, but do not persist arbitrary live device pointers"; §1.1 line 305; §3.7).
//!
//! An [`AbiKey`] is a domain-separated digest of every field that decides whether a
//! compiled artifact can run: the execution identity, the exact backend release, the
//! native ABI version, the driver and CUDA runtime versions, the GPU architecture and the
//! compiler. Lookups match the whole key, so any differing field misses.
//!
//! A [`DevicePointer`] has no serde and a redacting `Debug`, so no persisted record can
//! carry one. A captured CUDA graph embeds live addresses and is never persisted (graph
//! reuse is validated against its execution key and resources instead); compiled kernels
//! and autotune tables are persisted only when their producer reports no embedded device
//! pointer. A [`PersistedArtifact`] holds the key, the kind, the content key of the
//! artifact's bytes and their length, and nothing else.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::retention::Component;
use crate::foundation::evidence::BackendRelease;
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder};
use crate::model_memory::boundaries::NativeAbiVersion;
use crate::model_memory::identity::{ExecutionIdentity, Label};

/// Domain of [`AbiKeySpec::key`].
pub const ABI_KEY_DOMAIN: &str = "yougori/readiness/abi-key/v1";

/// The fields an exact ABI key binds (GPU §4.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AbiKeySpec {
    pub execution: ExecutionIdentity,
    pub release: BackendRelease,
    pub native_abi: NativeAbiVersion,
    pub driver_version: Label,
    pub cuda_runtime: Label,
    pub gpu_architecture: Label,
    pub compiler: Label,
}

impl AbiKeySpec {
    /// The exact key: every field, length-prefixed, under [`ABI_KEY_DOMAIN`].
    pub fn key(&self) -> AbiKey {
        AbiKey(
            DigestBuilder::new(ABI_KEY_DOMAIN)
                .digest(self.execution.digest())
                .str(&self.release.to_string())
                .u64(u64::from(self.native_abi.major))
                .u64(u64::from(self.native_abi.minor))
                .str(self.driver_version.as_str())
                .str(self.cuda_runtime.as_str())
                .str(self.gpu_architecture.as_str())
                .str(self.compiler.as_str())
                .finish(),
        )
    }
}

/// An exact ABI key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AbiKey(Digest);

impl AbiKey {
    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

/// What a compile step produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// Compiled kernels, such as a compiler cache.
    CompiledKernels,
    /// Kernel tuning results.
    AutotuneTable,
    /// A captured CUDA graph, which embeds live device addresses.
    CapturedGraph,
}

impl ArtifactKind {
    /// The execution-state component a persisted artifact of this kind speeds up.
    pub const fn speeds_up(self) -> Component {
        match self {
            Self::CompiledKernels | Self::AutotuneTable | Self::CapturedGraph => Component::Graphs,
        }
    }
}

/// A live device address. It has no serde and its `Debug` redacts the value, so it
/// cannot reach a persisted record.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct DevicePointer(u64);

impl DevicePointer {
    pub const fn new(address: u64) -> Self {
        Self(address)
    }
}

impl fmt::Debug for DevicePointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DevicePointer(..)")
    }
}

/// The output of one compile step, as its producer reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompileOutput {
    pub kind: ArtifactKind,
    pub bytes: Vec<u8>,
    /// Device addresses baked into the bytes; must be empty to persist.
    pub embedded_device_pointers: Vec<DevicePointer>,
}

/// What is persisted for one artifact: its exact key, kind, content and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedArtifact {
    pub abi: AbiKey,
    pub kind: ArtifactKind,
    pub content: ContentKey,
    pub length_bytes: u64,
}

/// Why an artifact was not persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum PersistRefusal {
    /// A captured graph holds live device addresses (GPU §4.5, §3.7).
    CapturedGraphHoldsLiveAddresses,
    /// The producer reported device addresses inside the bytes.
    EmbedsDevicePointers {
        count: usize,
    },
    Empty,
    /// The exact key already holds different content for this kind.
    ConflictingContent {
        kind: ArtifactKind,
        stored: ContentKey,
        offered: ContentKey,
    },
}

impl fmt::Display for PersistRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapturedGraphHoldsLiveAddresses => {
                f.write_str("a captured graph embeds live device addresses and is never persisted")
            }
            Self::EmbedsDevicePointers { count } => write!(
                f,
                "the artifact embeds {count} live device pointer(s) and is not persisted"
            ),
            Self::Empty => f.write_str("the artifact is empty"),
            Self::ConflictingContent { kind, .. } => write!(
                f,
                "the exact ABI key already holds different {kind:?} content"
            ),
        }
    }
}

impl std::error::Error for PersistRefusal {}

/// Persisted compile artifacts by exact ABI key and kind.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct CompileArtifactStore {
    entries: BTreeMap<(AbiKey, ArtifactKind), PersistedArtifact>,
}

impl CompileArtifactStore {
    pub fn new() -> Self {
        Self::default()
    }

    /// Persists `output` under `abi`, refusing a captured graph, any embedded device
    /// pointer, empty bytes and different content under the same key and kind.
    pub fn persist(
        &mut self,
        abi: AbiKey,
        output: &CompileOutput,
    ) -> Result<PersistedArtifact, PersistRefusal> {
        if output.kind == ArtifactKind::CapturedGraph {
            return Err(PersistRefusal::CapturedGraphHoldsLiveAddresses);
        }
        if !output.embedded_device_pointers.is_empty() {
            return Err(PersistRefusal::EmbedsDevicePointers {
                count: output.embedded_device_pointers.len(),
            });
        }
        if output.bytes.is_empty() {
            return Err(PersistRefusal::Empty);
        }
        let artifact = PersistedArtifact {
            abi,
            kind: output.kind,
            content: ContentKey::of(&output.bytes),
            length_bytes: output.bytes.len() as u64,
        };
        if let Some(stored) = self.entries.get(&(abi, output.kind)) {
            if stored.content != artifact.content {
                return Err(PersistRefusal::ConflictingContent {
                    kind: output.kind,
                    stored: stored.content,
                    offered: artifact.content,
                });
            }
        }
        self.entries.insert((abi, output.kind), artifact);
        Ok(artifact)
    }

    /// The artifact of `kind` under exactly `abi`.
    pub fn lookup(&self, abi: &AbiKey, kind: ArtifactKind) -> Option<&PersistedArtifact> {
        self.entries.get(&(*abi, kind))
    }

    /// Every persisted record.
    pub fn records(&self) -> Vec<PersistedArtifact> {
        self.entries.values().copied().collect()
    }

    /// The components whose recreation a persisted artifact under exactly `abi` speeds up.
    pub fn components_with_artifacts(&self, abi: &AbiKey) -> BTreeSet<Component> {
        self.entries
            .values()
            .filter(|artifact| artifact.abi == *abi)
            .map(|artifact| artifact.kind.speeds_up())
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::Backend;
    use crate::model_memory::boundaries::NATIVE_ABI_VERSION;
    use crate::model_memory::readiness::test_support::execution_identity;

    fn label(value: &str) -> Label {
        Label::new(value).unwrap()
    }

    fn spec() -> AbiKeySpec {
        AbiKeySpec {
            execution: execution_identity("model-a"),
            release: BackendRelease::new(Backend::Vllm, "0.31.0").unwrap(),
            native_abi: NATIVE_ABI_VERSION,
            driver_version: label("580.65"),
            cuda_runtime: label("13.0"),
            gpu_architecture: label("sm_90"),
            compiler: label("triton-3.4"),
        }
    }

    fn kernels(bytes: &[u8]) -> CompileOutput {
        CompileOutput {
            kind: ArtifactKind::CompiledKernels,
            bytes: bytes.to_vec(),
            embedded_device_pointers: Vec::new(),
        }
    }

    #[test]
    fn artifacts_are_found_only_under_the_exact_abi_key() {
        let mut store = CompileArtifactStore::new();
        let key = spec().key();
        store.persist(key, &kernels(b"cubin")).unwrap();
        assert!(store.lookup(&key, ArtifactKind::CompiledKernels).is_some());
        assert!(store.lookup(&key, ArtifactKind::AutotuneTable).is_none());
        let variants = [
            AbiKeySpec {
                execution: execution_identity("model-b"),
                ..spec()
            },
            AbiKeySpec {
                release: BackendRelease::new(Backend::Vllm, "0.31.1").unwrap(),
                ..spec()
            },
            AbiKeySpec {
                native_abi: NativeAbiVersion { major: 1, minor: 1 },
                ..spec()
            },
            AbiKeySpec {
                driver_version: label("580.66"),
                ..spec()
            },
            AbiKeySpec {
                cuda_runtime: label("13.1"),
                ..spec()
            },
            AbiKeySpec {
                gpu_architecture: label("sm_89"),
                ..spec()
            },
            AbiKeySpec {
                compiler: label("triton-3.5"),
                ..spec()
            },
        ];
        for variant in variants {
            let other = variant.key();
            assert_ne!(other, key);
            assert!(store
                .lookup(&other, ArtifactKind::CompiledKernels)
                .is_none());
            assert!(store.components_with_artifacts(&other).is_empty());
        }
        assert_eq!(
            store.components_with_artifacts(&key),
            BTreeSet::from([Component::Graphs])
        );
        // The same key holds one content per kind.
        assert!(matches!(
            store.persist(key, &kernels(b"other cubin")),
            Err(PersistRefusal::ConflictingContent { .. })
        ));
        assert!(store.persist(key, &kernels(b"cubin")).is_ok());
    }

    #[test]
    fn no_device_pointer_reaches_a_persisted_record() {
        let mut store = CompileArtifactStore::new();
        let key = spec().key();
        let pointer = DevicePointer::new(0x7f3a_dead_beef);
        let graph = CompileOutput {
            kind: ArtifactKind::CapturedGraph,
            bytes: b"graph exec".to_vec(),
            embedded_device_pointers: vec![pointer],
        };
        assert_eq!(
            store.persist(key, &graph),
            Err(PersistRefusal::CapturedGraphHoldsLiveAddresses)
        );
        let tainted = CompileOutput {
            embedded_device_pointers: vec![pointer, pointer],
            ..kernels(b"cubin with a baked address")
        };
        assert_eq!(
            store.persist(key, &tainted),
            Err(PersistRefusal::EmbedsDevicePointers { count: 2 })
        );
        assert_eq!(
            store.persist(key, &kernels(b"")),
            Err(PersistRefusal::Empty)
        );
        store.persist(key, &kernels(b"cubin")).unwrap();
        store
            .persist(
                key,
                &CompileOutput {
                    kind: ArtifactKind::AutotuneTable,
                    bytes: b"tuning".to_vec(),
                    embedded_device_pointers: Vec::new(),
                },
            )
            .unwrap();
        let records = store.records();
        assert_eq!(records.len(), 2);
        let json = serde_json::to_string(&records).unwrap();
        // Neither the address nor any pointer-shaped field appears.
        for needle in [
            "7f3adeadbeef",
            &0x7f3a_dead_beef_u64.to_string(),
            "pointer",
            "address",
            "graph",
        ] {
            assert!(!json.contains(needle), "{needle} in {json}");
        }
        for record in &records {
            let value = serde_json::to_value(record).unwrap();
            let fields: BTreeSet<&str> = value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            assert_eq!(
                fields,
                BTreeSet::from(["abi", "kind", "content", "length_bytes"])
            );
        }
        let read: Vec<PersistedArtifact> = serde_json::from_str(&json).unwrap();
        assert_eq!(read, records);
        assert_eq!(format!("{pointer:?}"), "DevicePointer(..)");
        // An extra field is refused when read back.
        let mut value = serde_json::to_value(records[0]).unwrap();
        value["device_pointer"] = 1.into();
        assert!(serde_json::from_value::<PersistedArtifact>(value).is_err());
    }
}
