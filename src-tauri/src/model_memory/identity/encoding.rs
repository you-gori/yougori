//! The canonical encoding behind every identity here (§3.2; §3.3, line 529: "Use
//! domain-separated hashes and canonical encodings").
//!
//! An identity is the ids.rs digest of an ordered list of parts under the identity's own
//! domain. The digest builder length-prefixes the domain and every part. A list writes
//! its count first, an enum writes a fixed tag before its fields, an optional value
//! writes `none` or `some` first, and a set is written in sorted order. A domain names
//! one fixed layout, so a change of layout or meaning needs a new domain version.

use crate::foundation::ids::{
    AuthorizationEpoch, ContentKey, Digest, DigestBuilder, ExecutionCategory, ExecutionId,
    GpuAllocationGeneration, GpuDeviceKey, LeaseId, ModelActivationGeneration, TenantId,
    TrustScope,
};

pub(crate) const SOURCE_DOMAIN: &str = "yougori/model-memory/identity/source/v1";
pub(crate) const LOGICAL_DOMAIN: &str = "yougori/model-memory/identity/logical-model/v1";
pub(crate) const EXECUTION_DOMAIN: &str = "yougori/model-memory/identity/execution/v1";
pub(crate) const ARTIFACT_DOMAIN: &str = "yougori/model-memory/identity/artifact/v1";
pub(crate) const PLACEMENT_DOMAIN: &str = "yougori/model-memory/identity/placement/v1";
pub(crate) const SESSION_DOMAIN: &str = "yougori/model-memory/identity/session/v1";
pub(crate) const ADAPTER_DOMAIN: &str = "yougori/model-memory/identity/adapter/v1";
pub(crate) const GRAPH_DOMAIN: &str = "yougori/model-memory/identity/cuda-graph/v1";
pub(crate) const KV_SCOPE_DOMAIN: &str = "yougori/model-memory/identity/kv-scope/v1";
pub(crate) const KV_REUSE_DOMAIN: &str = "yougori/model-memory/identity/kv-reuse/v1";
pub(crate) const TOKEN_PREFIX_DOMAIN: &str = "yougori/model-memory/identity/token-prefix/v1";

#[cfg(test)]
pub(crate) const ALL_DOMAINS: [&str; 11] = [
    SOURCE_DOMAIN,
    LOGICAL_DOMAIN,
    EXECUTION_DOMAIN,
    ARTIFACT_DOMAIN,
    PLACEMENT_DOMAIN,
    SESSION_DOMAIN,
    ADAPTER_DOMAIN,
    GRAPH_DOMAIN,
    KV_SCOPE_DOMAIN,
    KV_REUSE_DOMAIN,
    TOKEN_PREFIX_DOMAIN,
];

/// The parts of one canonical encoding, before they are hashed under a domain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Encoding {
    parts: Vec<Vec<u8>>,
}

impl Encoding {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn bytes(&mut self, part: &[u8]) -> &mut Self {
        self.parts.push(part.to_vec());
        self
    }

    pub(crate) fn tag(&mut self, tag: &'static str) -> &mut Self {
        self.bytes(tag.as_bytes())
    }

    pub(crate) fn text(&mut self, text: &str) -> &mut Self {
        self.bytes(text.as_bytes())
    }

    pub(crate) fn u64(&mut self, value: u64) -> &mut Self {
        self.bytes(&value.to_be_bytes())
    }

    pub(crate) fn count(&mut self, count: usize) -> &mut Self {
        self.u64(u64::try_from(count).unwrap_or(u64::MAX))
    }

    pub(crate) fn item<T: Encode + ?Sized>(&mut self, item: &T) -> &mut Self {
        item.encode(self);
        self
    }

    pub(crate) fn option<T: Encode>(&mut self, value: Option<&T>) -> &mut Self {
        match value {
            None => self.tag("none"),
            Some(value) => self.tag("some").item(value),
        }
    }

    /// Writes the count, then each item in the iterator's order. Callers pass sets in
    /// sorted order and sequences in their meaningful order.
    pub(crate) fn list<'a, T, I>(&mut self, items: I) -> &mut Self
    where
        T: Encode + 'a,
        I: IntoIterator<Item = &'a T>,
        I::IntoIter: ExactSizeIterator,
    {
        let items = items.into_iter();
        self.count(items.len());
        for item in items {
            item.encode(self);
        }
        self
    }

    pub(crate) fn finish(&self, domain: &str) -> Digest {
        self.parts
            .iter()
            .fold(DigestBuilder::new(domain), |builder, part| {
                builder.bytes(part)
            })
            .finish()
    }
}

/// A typed field with one canonical encoding.
pub(crate) trait Encode {
    fn encode(&self, out: &mut Encoding);
}

impl Encode for u64 {
    fn encode(&self, out: &mut Encoding) {
        out.u64(*self);
    }
}

impl Encode for Digest {
    fn encode(&self, out: &mut Encoding) {
        out.bytes(self.as_bytes());
    }
}

impl Encode for ContentKey {
    fn encode(&self, out: &mut Encoding) {
        out.item(self.digest());
    }
}

impl Encode for GpuDeviceKey {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.machine).item(&self.device);
    }
}

impl Encode for TenantId {
    fn encode(&self, out: &mut Encoding) {
        out.text(self.as_str());
    }
}

impl Encode for ExecutionId {
    fn encode(&self, out: &mut Encoding) {
        out.text(self.as_str());
    }
}

impl Encode for AuthorizationEpoch {
    fn encode(&self, out: &mut Encoding) {
        out.u64(self.get());
    }
}

impl Encode for ModelActivationGeneration {
    fn encode(&self, out: &mut Encoding) {
        out.u64(self.get());
    }
}

impl Encode for GpuAllocationGeneration {
    fn encode(&self, out: &mut Encoding) {
        out.u64(self.get());
    }
}

impl Encode for LeaseId {
    fn encode(&self, out: &mut Encoding) {
        out.u64(self.get());
    }
}

impl Encode for ExecutionCategory {
    fn encode(&self, out: &mut Encoding) {
        out.tag(match self {
            Self::VmSandbox => "vm_sandbox",
            Self::SharedKernelGpuRuntime => "shared_kernel_gpu_runtime",
            Self::ProviderContainerRuntime => "provider_container_runtime",
            Self::HostProcessModelRuntime => "host_process_model_runtime",
        });
    }
}

impl Encode for TrustScope {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.category).item(&self.domain);
    }
}

/// Defines an identity: a digest that only this module's specs can make, compared as a
/// whole and printed as hexadecimal.
macro_rules! identity_type {
    ($(#[$doc:meta])* $name:ident) => {
        $(#[$doc])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
        #[serde(transparent)]
        pub struct $name($crate::foundation::ids::Digest);

        impl $name {
            /// The digest this identity is. Identities are compared as wholes, never by
            /// name or size (§3.2, line 504).
            pub const fn digest(&self) -> &$crate::foundation::ids::Digest {
                &self.0
            }
        }

        impl std::fmt::Debug for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0.to_hex())
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0.to_hex())
            }
        }

        impl super::encoding::Encode for $name {
            fn encode(&self, out: &mut super::encoding::Encoding) {
                out.item(&self.0);
            }
        }
    };
}

pub(crate) use identity_type;
