//! The file service's usage counts as disk readings (M12
//! [`FileService`]; VM part §5.1 "Capability-rooted access": a grant binds a quota;
//! VM-W14; VM-W43).
//!
//! Each file service counts what its root holds against the grant's quota
//! ([`FileService::usage`]): its entries and the bytes of its regular files. V14 measures
//! [`MonitoredResource::DiskBytes`] by the hypervisor counters and the
//! [`HostObserver::Supervisor`], and the file service is the supervisor's
//! ([`FILE_SERVICE_OBSERVER`]).
//!
//! V14 keeps one series per sandbox, resource and source, so a sandbox's roots make one
//! reading: the bytes in the roots its guest can change, those whose grant permits an
//! operation that changes the tree. A read-only snapshot holds the host's input, which the
//! guest cannot change, and is left out. A live workspace is written by the user too, and
//! its bytes count whoever wrote them. The reading covers what the file service holds, not
//! the VM's own disks (its root overlay and scratch directories), which no committed source
//! counts.
//!
//! No reading is made when a root's grant binds another trust scope than the sandbox's or
//! one root is given twice (the host called inconsistently,
//! [`Ordinary::HostConfiguration`]); when the sandbox has no root its guest can change
//! ([`Ordinary::NothingObserved`]); or when such a root could not be counted within its
//! quota ([`Ordinary::HostFault`]), since a sum without it would read low.
//!
//! A service counts as it serves. A live workspace the user changed outside the service
//! counts again only when the host recounts it ([`FileService::recount`]), which the host
//! does before it reads.

use std::collections::BTreeSet;

use crate::foundation::ids::TrustScope;
use crate::sandbox_contract::files::{FileService, QuotaUsage, RootHandle};
use crate::sandbox_contract::response::{HostObserver, MonitoredResource};

use super::file::FILE_SERVICE_OBSERVER;
use super::observed::{Observed, Ordinary};
use super::resource::{measured, ResourceReading};

/// The observer every disk reading names: the file service's.
pub const DISK_OBSERVER: HostObserver = FILE_SERVICE_OBSERVER;

/// What one file service counted of its root, as the host read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootUsage {
    /// The root the service's grant binds.
    pub root: RootHandle,
    /// The trust scope the grant binds.
    pub scope: TrustScope,
    /// Whether the grant permits the guest an operation that changes the tree.
    pub guest_can_change: bool,
    /// What the root holds as the service counted it; `None` when it could not be counted
    /// within the grant's quota.
    pub usage: Option<QuotaUsage>,
}

impl RootUsage {
    /// What `service` counted of its root.
    pub fn of(service: &FileService) -> Self {
        let grant = service.grant();
        Self {
            root: grant.root(),
            scope: grant.scope(),
            guest_can_change: grant
                .operations()
                .iter()
                .any(|operation| operation.mutates()),
            usage: service.usage(),
        }
    }
}

/// The disk reading of the roots of the sandbox `observed` names, whose host-assigned
/// trust scope is `sandbox_scope`, at `observed`'s time (pure): the bytes in the roots its
/// guest can change; or why there is none.
pub fn disk_reading(
    roots: &[RootUsage],
    sandbox_scope: TrustScope,
    observed: &Observed,
) -> ResourceReading {
    let mut seen = BTreeSet::new();
    for root in roots {
        if root.scope != sandbox_scope || !seen.insert(root.root) {
            return ResourceReading::Ordinary {
                reason: Ordinary::HostConfiguration,
            };
        }
    }
    let mut changeable = roots.iter().filter(|root| root.guest_can_change).peekable();
    if changeable.peek().is_none() {
        return ResourceReading::Ordinary {
            reason: Ordinary::NothingObserved,
        };
    }
    let mut total: u64 = 0;
    for root in changeable {
        let Some(usage) = root.usage else {
            return ResourceReading::Ordinary {
                reason: Ordinary::HostFault,
            };
        };
        total = total.saturating_add(usage.total_bytes);
    }
    measured(observed, MonitoredResource::DiskBytes, DISK_OBSERVER, total)
}
