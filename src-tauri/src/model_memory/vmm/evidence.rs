//! Granularity and handle-type support come from CORE-01 evidence and are never assumed
//! (GPU part §3.7: "probe allocation granularity and support for the exact handle type and
//! device"; §1.1 row 309; Appendix E steps 1, 7 and 8).
//!
//! CORE-01's `CudaVmmAllocation` capability carries the granularity reported for one
//! `CudaAllocation` subject: the exact runtime, device ordinal and requested handle type.
//! That evidence is the only source of a granularity, and of support for allocating with a
//! handle type: it must be fresh, from a strong enough source and observed under the
//! current configuration, by CORE-01's own rules. The process's own driver answer at
//! Appendix E step 1 is still asked, because the protocol's order needs it, but it is only
//! cross-checked against the evidence and never trusted on its own. Support for sharing
//! is the `CudaIpcVmmShareableHandle` and `CudaIpcLegacy` evidence, which never stand in
//! for each other.

use std::fmt;
use std::num::NonZeroU64;
use std::time::Duration;

use serde::Serialize;

use super::error::VmmError;
use super::types::{AllocationProperties, DeviceOrdinal, ProcessId};
use crate::foundation::evidence::{
    Capability, ClockReading, ClockSession, ConfigurationFingerprint, CudaAllocationSubject,
    EvidencePolicy, EvidenceRefusal, ProbeRegistry, Requirement, RuntimeSubject, Satisfied,
    ShareableHandle, SourceClass, Staleness, Subject, SupportDetail, UnknownReason,
};
use crate::foundation::ids::{Clock, Digest, MonotonicTime};

/// An allocation granularity reported for exact allocation properties: g_v of §2.4
/// (Appendix E step 1).
///
/// There is no public constructor and no deserializer: a value exists only as fresh
/// CORE-01 evidence, so 2 MiB, or any other size, is never assumed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Granularity(NonZeroU64);

impl Granularity {
    /// A reported value; `None` for zero, which no driver may report.
    pub(super) fn reported(bytes: u64) -> Option<Self> {
        NonZeroU64::new(bytes).map(Self)
    }

    pub const fn bytes(self) -> u64 {
        self.0.get()
    }

    /// Whether `bytes` is a whole number of granules.
    pub fn is_multiple(self, bytes: u64) -> bool {
        bytes.is_multiple_of(self.0.get())
    }

    /// `bytes` rounded up to whole granules; `None` past `u64::MAX`.
    pub fn align_up(self, bytes: u64) -> Option<u64> {
        match bytes % self.0.get() {
            0 => Some(bytes),
            remainder => bytes.checked_add(self.0.get() - remainder),
        }
    }
}

/// What Appendix E step 1 established for one set of allocation properties.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum GranularityResult {
    /// CUDA VMM allocations with these properties are supported at this granularity.
    Reported { granularity: Granularity },
    /// CUDA VMM is unsupported for these properties (`CUDA_ERROR_NOT_SUPPORTED`); the
    /// fallback of Appendix E step 9 applies.
    NotSupported,
}

/// One process, and how the evidence it relies on is judged.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessContext {
    pub process: ProcessId,
    /// Device k of Appendix E.
    pub device: DeviceOrdinal,
    /// The exact runtime the process runs in. Evidence about another runtime never
    /// applies, and memory is never shared across runtimes.
    pub runtime: RuntimeSubject,
    /// The configuration in force now, such as driver and launch settings; evidence
    /// observed under another fingerprint no longer applies (CORE-01).
    pub configuration: ConfigurationFingerprint,
    /// Where the process's own driver answers come from. They are recorded with each
    /// Appendix E step-1 query but only cross-checked against CORE-01 evidence, whose
    /// source the registered probe fixes; they are never trusted on their own.
    pub reports_from: SourceClass,
    /// The source and age every piece of CORE-01 evidence this process relies on must
    /// meet.
    pub evidence_policy: EvidencePolicy,
}

/// What the process's driver answered at Appendix E step 1 for exact allocation
/// properties, and when. It keeps the protocol's order and is cross-checked against
/// CORE-01 evidence; it is never a granularity on its own. Only
/// [`VmmModel::probe_granularity`](super::VmmModel::probe_granularity) makes one.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DriverGranularityReport {
    properties: AllocationProperties,
    source: SourceClass,
    clock: ClockSession,
    observed_at: MonotonicTime,
    fresh_for: Duration,
    answer: GranularityResult,
}

impl DriverGranularityReport {
    pub(super) fn stamp(
        context: &ProcessContext,
        properties: AllocationProperties,
        fresh_for: Duration,
        answer: GranularityResult,
        reading: ClockReading,
    ) -> Self {
        Self {
            properties,
            source: context.reports_from,
            clock: reading.session(),
            observed_at: reading.at(),
            fresh_for,
            answer,
        }
    }

    pub fn properties(&self) -> AllocationProperties {
        self.properties
    }

    pub fn source(&self) -> SourceClass {
        self.source
    }

    pub fn clock(&self) -> ClockSession {
        self.clock
    }

    pub fn observed_at(&self) -> MonotonicTime {
        self.observed_at
    }

    /// How long the answer may be relied on before step 1 is asked again.
    pub fn fresh_for(&self) -> Duration {
        self.fresh_for
    }

    pub fn answer(&self) -> GranularityResult {
        self.answer
    }

    /// Why the answer may no longer be relied on at `now`, if it may not.
    pub(super) fn staleness(&self, now: ClockReading) -> Option<Staleness> {
        if self.clock != now.session() {
            return Some(Staleness::OtherClock);
        }
        let Some(age) = now.at().checked_duration_since(self.observed_at) else {
            return Some(Staleness::ObservedAfterNow);
        };
        (age > self.fresh_for).then_some(Staleness::TooOld {
            age,
            limit: self.fresh_for,
        })
    }
}

/// Why no granularity can be used.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum GranularityRefusal {
    /// No usable CORE-01 `CudaVmmAllocation` evidence for exactly these properties: it is
    /// missing, from a weaker source, inconclusive, observed under another configuration,
    /// stale, or unsupported. CORE-01's own refusal says which.
    Evidence {
        properties: AllocationProperties,
        cause: EvidenceRefusal,
    },
    /// Appendix E step 1 was never asked in this process for these properties.
    NotQueried { properties: AllocationProperties },
    /// The step-1 answer is older than its freshness bound, or from another clock.
    QueryStale {
        properties: AllocationProperties,
        staleness: Staleness,
    },
    /// The driver's step-1 answer contradicts the evidence; `None` means unsupported.
    DriverContradicts {
        properties: AllocationProperties,
        evidence_bytes: Option<u64>,
        driver_bytes: Option<u64>,
    },
    /// The evidence now reports another granularity than the reservation was laid out
    /// with, so the size in use no longer fits.
    Changed {
        laid_out_bytes: u64,
        reported_bytes: u64,
    },
}

impl fmt::Display for GranularityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Evidence { properties, cause } => write!(
                f,
                "no usable CUDA VMM allocation evidence for device {} with handle type {:?}: \
                 {cause}; the granularity is never assumed",
                properties.device, properties.requested_handle
            ),
            Self::NotQueried { properties } => write!(
                f,
                "Appendix E step 1 was never asked for device {} with handle type {:?} in this \
                 process; probe the granularity first",
                properties.device, properties.requested_handle
            ),
            Self::QueryStale {
                properties,
                staleness,
            } => write!(
                f,
                "the step-1 answer for device {} with handle type {:?} is not fresh \
                 ({staleness:?}); probe the granularity again",
                properties.device, properties.requested_handle
            ),
            Self::DriverContradicts {
                properties,
                evidence_bytes,
                driver_bytes,
            } => write!(
                f,
                "for device {} with handle type {:?} the driver answered {} but the evidence \
                 shows {}; neither is used until they agree",
                properties.device,
                properties.requested_handle,
                describe(*driver_bytes),
                describe(*evidence_bytes)
            ),
            Self::Changed {
                laid_out_bytes,
                reported_bytes,
            } => write!(
                f,
                "the evidence now reports a {reported_bytes}-byte granularity, but the \
                 reservation was laid out for {laid_out_bytes} bytes; map the artifact again \
                 from a new plan"
            ),
        }
    }
}

fn describe(bytes: Option<u64>) -> String {
    match bytes {
        Some(bytes) => format!("a {bytes}-byte granularity"),
        None => "no CUDA VMM support".to_owned(),
    }
}

/// The identity of the runtime subject that evidence about `runtime` is keyed by.
pub(super) fn runtime_identity(runtime: &RuntimeSubject) -> Digest {
    Subject::Runtime(runtime.clone()).identity()
}

/// The CORE-01 subject of CUDA VMM allocation with exactly `properties` in the process's
/// runtime.
pub(super) fn allocation_subject(
    context: &ProcessContext,
    properties: AllocationProperties,
) -> Subject {
    Subject::CudaAllocation(CudaAllocationSubject {
        runtime: context.runtime.clone(),
        device_ordinal: properties.device.0,
        requested_handle: properties.requested_handle,
    })
}

/// The granularity fresh CORE-01 evidence shows for CUDA VMM allocation with exactly
/// `properties` in the process's runtime, under the process's evidence policy and current
/// configuration; otherwise CORE-01's refusal.
pub(super) fn evidenced_granularity<C: Clock>(
    registry: &ProbeRegistry<C>,
    context: &ProcessContext,
    properties: AllocationProperties,
) -> Result<Granularity, EvidenceRefusal> {
    let satisfied = registry.evaluate(&Requirement::new(
        Capability::CudaVmmAllocation,
        allocation_subject(context, properties),
        context.evidence_policy.minimum_source,
        context.evidence_policy.max_age,
        context.configuration,
    ))?;
    match satisfied.detail() {
        SupportDetail::CudaVmmAllocation { granularity_bytes } => {
            Ok(Granularity(*granularity_bytes))
        }
        // CORE-01 records a detail that does not fit its capability as unknown.
        _ => Err(EvidenceRefusal::Unknown {
            capability: Capability::CudaVmmAllocation,
            reason: UnknownReason::InconsistentReport,
        }),
    }
}

/// Fresh CORE-01 evidence that CUDA VMM export and import work with exactly `handle` in
/// the process's runtime (Appendix E step 7). Evidence for another handle type, or for
/// legacy IPC, never stands in.
pub(super) fn require_shareable_handle<C: Clock>(
    registry: &ProbeRegistry<C>,
    context: &ProcessContext,
    handle: ShareableHandle,
) -> Result<Satisfied, VmmError> {
    let satisfied =
        registry.evaluate(&requirement(Capability::CudaIpcVmmShareableHandle, context))?;
    match satisfied.detail() {
        SupportDetail::CudaIpcVmmShareableHandle { handle: shown } if *shown == handle => {
            Ok(satisfied)
        }
        shown => Err(VmmError::HandleTypeNotShown {
            requested: handle,
            shown: shown.clone(),
        }),
    }
}

/// Fresh CORE-01 evidence that legacy CUDA IPC works in the process's runtime (Appendix E
/// step 8). Evidence for CUDA VMM shareable handles never stands in.
pub(super) fn require_legacy_ipc<C: Clock>(
    registry: &ProbeRegistry<C>,
    context: &ProcessContext,
) -> Result<Satisfied, VmmError> {
    Ok(registry.evaluate(&requirement(Capability::CudaIpcLegacy, context))?)
}

fn requirement(capability: Capability, context: &ProcessContext) -> Requirement {
    Requirement::new(
        capability,
        Subject::Runtime(context.runtime.clone()),
        context.evidence_policy.minimum_source,
        context.evidence_policy.max_age,
        context.configuration,
    )
}
