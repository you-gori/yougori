//! The canonical encoding behind every digest of this module (GPU §3.3 line 529: "Use
//! domain-separated hashes and canonical encodings"; §4.16 lines 882–886).
//!
//! A digest is the ids.rs [`DigestBuilder`] over an ordered list of parts under one
//! domain; the builder length-prefixes every part. Enumerations write a fixed tag before
//! their fields, optional values write `none` or `some` first and lists write their
//! count first, so two different typed inputs never share an encoding.

use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory, TrustScope};
use crate::model_memory::identity::{Dtype, PositionalEncoding, VersionedName};

/// Parts of one canonical encoding, hashed under a domain by [`Canon::finish`].
pub(super) struct Canon(DigestBuilder);

impl Canon {
    pub(super) fn new(domain: &str) -> Self {
        Self(DigestBuilder::new(domain))
    }

    pub(super) fn tag(self, tag: &str) -> Self {
        Self(self.0.str(tag))
    }

    pub(super) fn text(self, text: &str) -> Self {
        Self(self.0.str(text))
    }

    pub(super) fn u64(self, value: u64) -> Self {
        Self(self.0.u64(value))
    }

    pub(super) fn count(self, count: usize) -> Self {
        self.u64(u64::try_from(count).unwrap_or(u64::MAX))
    }

    pub(super) fn digest(self, part: &Digest) -> Self {
        Self(self.0.digest(part))
    }

    pub(super) fn optional_digest(self, part: Option<&Digest>) -> Self {
        match part {
            None => self.tag("none"),
            Some(part) => self.tag("some").digest(part),
        }
    }

    pub(super) fn versioned(self, name: &VersionedName) -> Self {
        self.text(name.name.as_str()).text(name.version.as_str())
    }

    pub(super) fn dtype(self, dtype: Dtype) -> Self {
        self.tag(dtype.tag())
    }

    pub(super) fn positional(self, encoding: &PositionalEncoding) -> Self {
        self.versioned(&encoding.scheme)
            .digest(&encoding.parameters)
    }

    pub(super) fn scope(self, scope: &TrustScope) -> Self {
        self.tag(category_code(scope.category))
            .digest(&scope.domain)
    }

    pub(super) fn finish(self) -> Digest {
        self.0.finish()
    }
}

/// The stable code of an execution category inside a digest; labels are for people.
pub(super) fn category_code(category: ExecutionCategory) -> &'static str {
    match category {
        ExecutionCategory::VmSandbox => "vm_sandbox",
        ExecutionCategory::SharedKernelGpuRuntime => "shared_kernel_gpu_runtime",
        ExecutionCategory::ProviderContainerRuntime => "provider_container_runtime",
        ExecutionCategory::HostProcessModelRuntime => "host_process_model_runtime",
    }
}
