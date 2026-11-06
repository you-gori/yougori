//! M17B: resource-type signals from the host sources that count something today, a slice
//! of VM-W43 over VM-W42 (docs/combined-gpu-memory-and-vm-sandbox-plan.md: the VM-W42 and
//! VM-W43 rows; VM part §8.2 "Detection and audit": "Keep authorization decisions,
//! operation IDs, budgets, lease events, launch facts and termination receipts outside the
//! guest ... label telemetry sources correctly"). Tier 0 only (§12.1): pure, synchronous
//! library code over fakes.
//!
//! V14 judges a resource over sustained windows
//! ([`ResourceMonitor`](crate::sandbox_contract::response::ResourceMonitor)): one series per
//! sandbox, resource and source, each sample an amount in the resource's unit. Four host
//! sources count a resource of a sandbox today, and an adapter turns each count into such a
//! sample ([`MEASURED_RESOURCES`]):
//!
//! - [`release`](super::release): the V02 release account's counted bytes,
//!   [`MonitoredResource::ReleaseBudgetSpentBytes`] by the [`HostObserver::Broker`];
//! - [`connection_rate`](super::connection_rate): the connections gate's outgoing
//!   connections, [`MonitoredResource::ConnectionsPerSecond`] by the
//!   [`HostObserver::Perimeter`];
//! - [`disk`](super::disk): the file service's usage counts,
//!   [`MonitoredResource::DiskBytes`] by the [`HostObserver::Supervisor`];
//! - [`job`](super::job) (M17C): the job of a VM's host process,
//!   [`MonitoredResource::CpuMillicores`] and [`MonitoredResource::MemoryBytes`] by the
//!   [`HostObserver::HypervisorCounters`] and [`MonitoredResource::ProcessCount`] by the
//!   [`HostObserver::Supervisor`].
//!
//! Each outcome is classified as the violation adapters classify theirs
//! ([`ResourceReading`]): a reading with its V14 draft, or an ordinary outcome with its
//! typed reason ([`Ordinary`]) and no draft. A reading is host-observed by the observer V14
//! accepts for the resource, about the sandbox the host knows the count belongs to, with
//! V14's own subject of the resource series ([`SeriesKey::subject`]) and the observation
//! time on the shared host clock ([`Observed`]); it names no grant, which V14 refuses on a
//! resource signal. A count the host cannot complete is never a reading: a partial count
//! reads low, and low samples can clear a series that should stay exceeded. Without a
//! reading, V14 reports the series' silence as uncertain, never as a pass.
//!
//! What a sustained reading does is V14's policy: notify the user, deny new high-impact
//! operations when the release budget is spent, isolate when the isolate record names the
//! resource (connection and packet rates by default), and never revoke or stop.
//!
//! One resource has no committed host source and stays open ([`OPEN_RESOURCES`]); no
//! reading is invented for it: [`MonitoredResource::PacketsPerSecond`], the packet
//! counters of the perimeter or the hypervisor, which neither exposes and no committed
//! source counts of the guest's packets.

use crate::sandbox_contract::response::{
    HostObserver, MonitoredResource, Reading, SeriesKey, SignalClass, SignalDraft, SignalSource,
};

use super::connection_rate::CONNECTION_RATE_OBSERVER;
use super::disk::DISK_OBSERVER;
use super::job::{CPU_OBSERVER, MEMORY_OBSERVER, PROCESS_COUNT_OBSERVER};
use super::observed::{Observed, Ordinary};
use super::release::RELEASE_OBSERVER;

/// The resources a committed host source measures, each with the observer its readings
/// name.
pub const MEASURED_RESOURCES: [(MonitoredResource, HostObserver); 6] = [
    (MonitoredResource::ReleaseBudgetSpentBytes, RELEASE_OBSERVER),
    (
        MonitoredResource::ConnectionsPerSecond,
        CONNECTION_RATE_OBSERVER,
    ),
    (MonitoredResource::DiskBytes, DISK_OBSERVER),
    (MonitoredResource::CpuMillicores, CPU_OBSERVER),
    (MonitoredResource::MemoryBytes, MEMORY_OBSERVER),
    (MonitoredResource::ProcessCount, PROCESS_COUNT_OBSERVER),
];

/// The resources no committed host source counts yet: open work, never a made-up reading.
pub const OPEN_RESOURCES: [MonitoredResource; 1] = [MonitoredResource::PacketsPerSecond];

/// What one host source's count is to V14's resource monitor (VM-W43): a reading with its
/// draft, or why there is none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResourceReading {
    /// The source counted the resource: the V14 draft of the amount, a sample for
    /// [`ResourceMonitor::observe`](crate::sandbox_contract::response::ResourceMonitor::observe).
    Measured { draft: SignalDraft },
    /// No reading, and why.
    Ordinary { reason: Ordinary },
}

impl ResourceReading {
    /// The draft to feed V14's resource monitor, if the source made a reading.
    pub fn draft(&self) -> Option<&SignalDraft> {
        match self {
            Self::Measured { draft } => Some(draft),
            Self::Ordinary { .. } => None,
        }
    }

    /// The draft, taken.
    pub fn into_draft(self) -> Option<SignalDraft> {
        match self {
            Self::Measured { draft } => Some(draft),
            Self::Ordinary { .. } => None,
        }
    }

    /// The amount read, in the resource's unit, if the source made a reading.
    pub fn amount(&self) -> Option<u64> {
        match self {
            Self::Measured { draft } => match draft.reading {
                Reading::Amount { amount } => Some(amount),
                Reading::ViolationObserved | Reading::CheckPassed => None,
            },
            Self::Ordinary { .. } => None,
        }
    }

    /// Why the source made no reading, if it made none.
    pub fn ordinary(&self) -> Option<Ordinary> {
        match self {
            Self::Ordinary { reason } => Some(*reason),
            Self::Measured { .. } => None,
        }
    }
}

/// The reading of `amount` of `resource` that `observer` counted at `observed`.
pub(super) fn measured(
    observed: &Observed,
    resource: MonitoredResource,
    observer: HostObserver,
    amount: u64,
) -> ResourceReading {
    ResourceReading::Measured {
        draft: SignalDraft {
            sandbox: observed.sandbox.clone(),
            class: SignalClass::Resource { resource },
            source: SignalSource::HostObserved { observer },
            subject: SeriesKey::subject(resource),
            reading: Reading::Amount { amount },
            observed_at: observed.at,
            session: observed.session,
            violated_grant: None,
        },
    }
}
