//! M11A: CORE-01 evidence from the provider's control-plane API (M11, carry-forward from
//! S01; docs/combined-plan-leftover-tasks.md, M11;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md, S2 CORE-01, VM part §1.3 and §7.6;
//! VM-W39; VM-D5).
//!
//! What a provider runs for us is the provider's report, never the pod's and never a
//! caller's label. This module turns those reports into CORE-01 observations of the
//! `ProviderApi` source class, registered beside `host_evidence`'s host probes:
//!
//! - `report`: [`ProviderReports`], a typed store of what the provider's API reported
//!   about each instance it runs for us, each with when the call that produced it
//!   started. [`ReportingPort`] fills it through V12's
//!   [`RemoteProviderPort`](crate::sandbox_contract::remote::RemoteProviderPort), taking
//!   the time before each call; the provider transport (M16 (a)) records richer reports
//!   with [`ProviderReports::record`].
//! - `adapters`: the adapters for `ProviderContainer`, `RuntimeCategory` and
//!   `ComputePlatform`, and [`register_provider_adapters`].
//!
//! Each subject has exactly one adapter. These observe only remote subjects: a provider
//! resource the provider reported, and a VM sandbox or provider container whose instance
//! is a reported provider instance. `host_evidence`'s host probes observe GPU devices and
//! the local runtimes the engine binds, which are never one of those two categories, so
//! the two sets never meet. A per-sandbox VM on a remote host is not a provider instance:
//! the provider API never sees it, and V12 confirms it from management evidence instead.
//!
//! An observation derives only from fields the provider reported. A field it did not
//! report reads not tested, and a report that does not fit its subject reads as an
//! inconsistent report; nothing is guessed. A provider container is never a VM sandbox
//! (VM-D5). Freshness counts from when the call started, so a stale report reads not
//! tested, and the configuration fingerprint covers every reported field, so a changed
//! report invalidates evidence observed under the old one.
//!
//! Tier 0: nothing here calls a provider or opens a connection; the tests drive V12's
//! fake provider and prove nothing about a real provider API.

mod adapters;
mod report;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_lifecycle;

pub use adapters::{
    register_provider_adapters, NotProviderObserved, ProviderCapability,
    PROVIDER_CATEGORY_FRESH_FOR, PROVIDER_COMPUTE_FRESH_FOR, PROVIDER_CONTAINER_FRESH_FOR,
};
pub use report::{
    CudaVersion, PortRecord, ProviderReport, ProviderReports, RecordOutcome, RecordedReport,
    ReportError, ReportedAccelerators, ReportingPort,
};
