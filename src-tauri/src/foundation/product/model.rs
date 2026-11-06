//! Model readiness, keep-ready preparation, residency and memory fit (S2 CORE-07
//! "memory/readiness"; GPU-W11 "Supply model readiness/residency fields and commands
//! through CORE-07"; GPU §2.7, §3.6, §4.1; INT-11: "readiness and sandbox evidence remain
//! distinct and accurate").
//!
//! These are the contract's own shapes. The engine's `product_views` module converts into
//! them from the model-memory types that own each field: the placement state, a keep-ready
//! preparation, the GPU extents a placement holds, a host copy and what may be relied on
//! staying in RAM, a device's memory demand against its usable memory and the request shape
//! readiness checks covered. These are the engine's own records of its own placements, not
//! evidence about a sandbox, so none carries an evidence state and none can stand in for
//! one. A ready model never implies anything about the sandbox it runs in.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::text::ShownText;
use crate::foundation::events::format_bytes;
use crate::foundation::ids::MonotonicTime;

/// Where a model is (the placement states of GPU §3.6, in a person's words).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Readiness {
    NotLoaded,
    Preparing,
    /// Loaded and verified, not yet serving.
    Loaded,
    Activating,
    /// Serving requests.
    Ready,
    /// Finishing the requests it admitted before it stops serving.
    Draining,
    Parked,
    Failed,
}

impl Readiness {
    /// The words a person reads, the same in the desktop and the CLI.
    pub const fn label(self) -> &'static str {
        match self {
            Self::NotLoaded => "Not loaded",
            Self::Preparing => "Preparing",
            Self::Loaded => "Loaded, not serving yet",
            Self::Activating => "Activating",
            Self::Ready => "Ready",
            Self::Draining => "Finishing current requests",
            Self::Parked => "Parked",
            Self::Failed => "Failed",
        }
    }

    /// Whether the model serves new requests now.
    pub const fn serves_requests(self) -> bool {
        matches!(self, Self::Ready)
    }
}

impl fmt::Display for Readiness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// A model's readiness with its words and, when it failed, why.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModelReadiness {
    state: Readiness,
    label: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    failure: Option<ShownText>,
}

impl ModelReadiness {
    pub fn state(&self) -> Readiness {
        self.state
    }

    /// The words a person reads.
    pub fn label(&self) -> &'static str {
        self.label
    }

    /// Why it failed; only a failed model has a failure.
    pub fn failure(&self) -> Option<&ShownText> {
        self.failure.as_ref()
    }
}

impl ModelReadiness {
    /// A failed model, with why it failed.
    pub fn failed(why: &str) -> Self {
        Self {
            state: Readiness::Failed,
            label: Readiness::Failed.label(),
            failure: Some(ShownText::new(why)),
        }
    }

    /// A model in `state`. A failed state given here, without its reason, says that no
    /// reason was recorded rather than show a failure without words.
    pub fn in_state(state: Readiness) -> Self {
        if state == Readiness::Failed {
            return Self::failed("no reason was recorded");
        }
        Self {
            state,
            label: state.label(),
            failure: None,
        }
    }
}

impl<'de> Deserialize<'de> for ModelReadiness {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            state: Readiness,
            label: String,
            #[serde(default)]
            failure: Option<ShownText>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.label != wire.state.label() {
            return Err(serde::de::Error::custom(format!(
                "readiness {:?} reads \"{}\"",
                wire.state,
                wire.state.label()
            )));
        }
        if wire.failure.is_some() != (wire.state == Readiness::Failed) {
            return Err(serde::de::Error::custom(
                "a failed model says why, and only a failed model has a failure",
            ));
        }
        Ok(Self {
            state: wire.state,
            label: wire.state.label(),
            failure: wire.failure,
        })
    }
}

strict_product_enum! {
    /// A keep-ready preparation (GPU §4.1): a bounded preparation with a deadline and a
    /// retention time, kept ready until a request uses it or the time runs out.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum Preparation tag "preparation" {
        Running { started_at: MonotonicTime },
        /// Ready, and kept ready until `expires_at`.
        Ready { ready_at: MonotonicTime, expires_at: MonotonicTime },
        /// A request used the prepared state.
        Used { at: MonotonicTime },
        /// Released before a request used it.
        Released { at: MonotonicTime, reason: ShownText },
    }
}

/// A host copy of model bytes and what may be relied on staying in RAM (GPU §2.7, §3.4):
/// all of a pinned copy and none of a reclaimable one, whatever an advisory estimate says.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct HostCopyShown {
    bytes: u64,
    guaranteed_resident_bytes: u64,
    /// For diagnostics only: it may be stale as soon as it is read.
    #[serde(skip_serializing_if = "Option::is_none")]
    advisory_resident_bytes: Option<u64>,
}

impl HostCopyShown {
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    pub fn guaranteed_resident_bytes(&self) -> u64 {
        self.guaranteed_resident_bytes
    }

    pub fn advisory_resident_bytes(&self) -> Option<u64> {
        self.advisory_resident_bytes
    }
}

impl HostCopyShown {
    /// A page-locked copy held by its runtime: all of it stays in RAM while held.
    pub fn pinned(bytes: u64) -> Self {
        Self {
            bytes,
            guaranteed_resident_bytes: bytes,
            advisory_resident_bytes: Some(bytes),
        }
    }

    /// A copy the kernel or a cache budget may reclaim: none of it is guaranteed, and an
    /// advisory estimate, if any, is capped at the copy's size.
    pub fn reclaimable(bytes: u64, advisory_resident_bytes: Option<u64>) -> Self {
        Self {
            bytes,
            guaranteed_resident_bytes: 0,
            advisory_resident_bytes: advisory_resident_bytes.map(|advisory| advisory.min(bytes)),
        }
    }
}

impl<'de> Deserialize<'de> for HostCopyShown {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            bytes: u64,
            guaranteed_resident_bytes: u64,
            #[serde(default)]
            advisory_resident_bytes: Option<u64>,
        }
        let wire = Wire::deserialize(deserializer)?;
        let guaranteed = wire.guaranteed_resident_bytes;
        if guaranteed != 0 && guaranteed != wire.bytes {
            return Err(serde::de::Error::custom(
                "a host copy is guaranteed resident whole, when pinned, or not at all",
            ));
        }
        if wire
            .advisory_resident_bytes
            .is_some_and(|advisory| advisory > wire.bytes)
        {
            return Err(serde::de::Error::custom(
                "an advisory resident estimate exceeds the copy",
            ));
        }
        Ok(Self {
            bytes: wire.bytes,
            guaranteed_resident_bytes: guaranteed,
            advisory_resident_bytes: wire.advisory_resident_bytes,
        })
    }
}

/// What a placement holds on GPUs, and its host copy if any.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Residency {
    gpu_extents: u64,
    gpu_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<HostCopyShown>,
}

impl Residency {
    /// `gpu_extents` GPU extents holding `gpu_bytes`, and a host copy, if any. Bytes are
    /// held only in extents, so no extent means no GPU bytes.
    pub fn new(gpu_extents: u64, gpu_bytes: u64, host: Option<HostCopyShown>) -> Self {
        Self {
            gpu_extents,
            gpu_bytes: if gpu_extents == 0 { 0 } else { gpu_bytes },
            host,
        }
    }

    pub fn gpu_extents(&self) -> u64 {
        self.gpu_extents
    }

    pub fn gpu_bytes(&self) -> u64 {
        self.gpu_bytes
    }

    pub fn host(&self) -> Option<&HostCopyShown> {
        self.host.as_ref()
    }

    /// Whether any GPU extent is held.
    pub fn is_on_gpu(&self) -> bool {
        self.gpu_extents > 0
    }
}

impl<'de> Deserialize<'de> for Residency {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            gpu_extents: u64,
            gpu_bytes: u64,
            #[serde(default)]
            host: Option<HostCopyShown>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.gpu_extents == 0 && wire.gpu_bytes != 0 {
            return Err(serde::de::Error::custom(
                "GPU bytes are held only in GPU extents",
            ));
        }
        Ok(Self {
            gpu_extents: wire.gpu_extents,
            gpu_bytes: wire.gpu_bytes,
            host: wire.host,
        })
    }
}

/// One device's peak memory demand against its usable memory (GPU §2.7: checked on every
/// piece of time, never on the mean).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemoryFit {
    device: ShownText,
    usable_bytes: u64,
    peak_bytes: u64,
    fits: bool,
}

impl MemoryFit {
    pub fn device(&self) -> &ShownText {
        &self.device
    }

    pub fn usable_bytes(&self) -> u64 {
        self.usable_bytes
    }

    pub fn peak_bytes(&self) -> u64 {
        self.peak_bytes
    }

    pub fn fits(&self) -> bool {
        self.fits
    }
}

impl MemoryFit {
    /// `device`'s peak demand against its usable memory; it fits exactly when the peak is
    /// within the usable memory.
    pub fn new(device: &str, usable_bytes: u64, peak_bytes: u64) -> Self {
        Self {
            device: ShownText::new(device),
            usable_bytes,
            peak_bytes,
            fits: peak_bytes <= usable_bytes,
        }
    }
}

impl fmt::Display for MemoryFit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: needs {} at its peak of {} usable{}",
            self.device,
            format_bytes(self.peak_bytes),
            format_bytes(self.usable_bytes),
            if self.fits { "" } else { "; it does not fit" }
        )
    }
}

impl<'de> Deserialize<'de> for MemoryFit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            device: ShownText,
            usable_bytes: u64,
            peak_bytes: u64,
            fits: bool,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.fits != (wire.peak_bytes <= wire.usable_bytes) {
            return Err(serde::de::Error::custom(
                "a device fits exactly when its peak demand is within its usable memory",
            ));
        }
        Ok(Self {
            device: wire.device,
            usable_bytes: wire.usable_bytes,
            peak_bytes: wire.peak_bytes,
            fits: wire.fits,
        })
    }
}

/// The request shape a model's readiness checks covered (GPU §3.6 step 4): the longest
/// context and the most sequences per request; a larger request is refused, never routed
/// to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyFor {
    pub max_context_tokens: u64,
    pub max_batch_sequences: u32,
}

/// A model's readiness, preparation, residency, the request shape its readiness checks
/// covered and its memory fit per device.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelStatus {
    pub readiness: ModelReadiness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preparation: Option<Preparation>,
    pub residency: Residency,
    /// The longest context and most sequences its readiness checks covered (§3.6 step 4);
    /// a larger request is refused, never routed to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ready_for: Option<ReadyFor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub memory: Vec<MemoryFit>,
}
