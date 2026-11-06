//! The capacity port over the CORE-03 host admission and reservation ledger (S2 CORE-03,
//! CORE-04; S10).
//!
//! A coordination reservation's key doubles as the operation identity of the reservation
//! in the ledger's provenance, so the adapter finds its reservations in the ledger's own
//! records, after a restart too; it keeps only its queued tickets and holds. The adapter
//! owns the ledger, or charges the host's one ledger through the [`SharedLedger`] handle
//! the transfer byte budget and the executor's reservations hold too (CORE-03: one
//! capacity authority). Every ledger
//! refusal becomes a typed port refusal that names the limiting resource and whether a
//! retry can make progress.

use std::collections::{BTreeMap, BTreeSet};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::capacity::{
    CapacityLimit, CapacityPort, CapacityRefusal, ExecutionCancellation, ReconcileReport,
    ReleaseOutcome, ReservationKey, ReservationPriority, ReservationPurpose, ReservationRequest,
    ReserveOutcome, ResourceKind, RetryProspect, ReturnHold,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, Digest, ExecutionId, OperationId};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityError, CostPurpose, HoldId, HostResource, Ledger, LedgerError,
    Limit, Priority, Provenance, QueueRefusal, QueueTicket, ReleaseOutcome as LedgerRelease,
    Requester, ReservationId, ReservationRecord, ReservationRequest as LedgerRequest,
    ReservationState, ResourceKey,
};

/// The prefix of the operation identity a coordination reservation carries.
const OPERATION_PREFIX: &str = "rsv-";

/// The operation identity of the reservation under `key`.
fn operation_of(key: &ReservationKey) -> Result<OperationId, CapacityRefusal> {
    OperationId::new(format!("{OPERATION_PREFIX}{}", key.digest().to_hex())).map_err(|error| {
        CapacityRefusal::Refused {
            reason: error.to_string(),
        }
    })
}

/// The key a coordination reservation's operation identity names.
fn key_of(record: &ReservationRecord) -> Option<ReservationKey> {
    let provenance = record.provenance();
    if provenance.requester != Requester::Coordination {
        return None;
    }
    let hex = provenance
        .operation
        .as_str()
        .strip_prefix(OPERATION_PREFIX)?;
    Digest::from_hex(hex).ok().map(ReservationKey::from_digest)
}

/// The ledger's key for a port resource.
pub(super) fn ledger_resource(kind: ResourceKind) -> ResourceKey {
    match kind {
        ResourceKind::HostMemoryBytes => ResourceKey::Host(HostResource::Ram),
        ResourceKind::PinnedHostMemoryBytes => ResourceKey::Host(HostResource::PinnedRam),
        ResourceKind::StorageBytes => ResourceKey::Host(HostResource::StorageQuota),
        ResourceKind::StorageIoBytesPerSecond => ResourceKey::Host(HostResource::StorageIo),
        ResourceKind::NetworkSlots => ResourceKey::Host(HostResource::NetworkSlots),
        ResourceKind::CpuInitializationSlots => {
            ResourceKey::Host(HostResource::CpuInitializationSlots)
        }
        ResourceKind::BurstVmRoots => ResourceKey::Host(HostResource::BurstVmRoots),
        ResourceKind::SnapshotPages => ResourceKey::Host(HostResource::SnapshotPages),
        ResourceKind::GpuMemoryBytes { device } => ResourceKey::vram(device),
        ResourceKind::GpuLoadSlots { device } => ResourceKey::gpu_load_slots(device),
    }
}

/// The port resource for a ledger key.
fn port_resource(key: ResourceKey) -> ResourceKind {
    match key {
        ResourceKey::Host(HostResource::Ram) => ResourceKind::HostMemoryBytes,
        ResourceKey::Host(HostResource::PinnedRam) => ResourceKind::PinnedHostMemoryBytes,
        ResourceKey::Host(HostResource::StorageQuota) => ResourceKind::StorageBytes,
        ResourceKey::Host(HostResource::StorageIo) => ResourceKind::StorageIoBytesPerSecond,
        ResourceKey::Host(HostResource::NetworkSlots) => ResourceKind::NetworkSlots,
        ResourceKey::Host(HostResource::CpuInitializationSlots) => {
            ResourceKind::CpuInitializationSlots
        }
        ResourceKey::Host(HostResource::BurstVmRoots) => ResourceKind::BurstVmRoots,
        ResourceKey::Host(HostResource::SnapshotPages) => ResourceKind::SnapshotPages,
        ResourceKey::Vram(device) => ResourceKind::GpuMemoryBytes {
            device: device.key(),
        },
        ResourceKey::GpuLoadSlots(device) => ResourceKind::GpuLoadSlots {
            device: device.key(),
        },
    }
}

fn amounts(demand: &BTreeMap<ResourceKind, u64>) -> Amounts {
    demand
        .iter()
        .fold(Amounts::new(), |amounts, (resource, amount)| {
            amounts.with(ledger_resource(*resource), *amount)
        })
}

const fn ledger_priority(priority: ReservationPriority) -> Priority {
    match priority {
        ReservationPriority::Background => Priority::Background,
        ReservationPriority::Foreground => Priority::Foreground,
    }
}

const fn cost_purpose(purpose: &ReservationPurpose) -> CostPurpose {
    match purpose {
        ReservationPurpose::Sandbox { .. } => CostPurpose::VmResources,
        ReservationPurpose::ModelGpu { .. } | ReservationPurpose::ModelHost { .. } => {
            CostPurpose::Compute
        }
    }
}

/// A capacity error as a port refusal: the limiting shortfall decides it.
fn capacity_refusal(error: &CapacityError, parent: Option<ReservationKey>) -> CapacityRefusal {
    let limiting = error.limiting();
    let resource = port_resource(limiting.resource);
    if matches!(
        error.queue_refusal(),
        Some(QueueRefusal::Full { .. } | QueueRefusal::TenantFull { .. })
    ) {
        return CapacityRefusal::QueueFull { resource };
    }
    let retry = if limiting.prospect.can_progress() {
        RetryProspect::CanProgress
    } else {
        RetryProspect::CannotProgress
    };
    let (requested, available) = (limiting.requested, limiting.available);
    match (&limiting.limit, parent) {
        (Limit::PhysicalCapacity, _) => CapacityRefusal::Insufficient {
            resource,
            limit: CapacityLimit::Host,
            requested,
            available,
            retry,
        },
        (Limit::TenantBudget { .. }, _) => CapacityRefusal::Insufficient {
            resource,
            limit: CapacityLimit::TenantBudget,
            requested,
            available,
            retry,
        },
        (Limit::ParentReservation { .. }, Some(parent)) => CapacityRefusal::ExceedsParentBudget {
            parent,
            resource,
            requested,
            remaining: available,
            retry,
        },
        (Limit::ParentReservation { .. }, None) => CapacityRefusal::Refused {
            reason: error.to_string(),
        },
        (Limit::CapacityNotObserved | Limit::StaleHostObservation { .. }, _) => {
            CapacityRefusal::NotObserved { resource }
        }
        (Limit::OwnerReturnHold { .. }, _) => CapacityRefusal::OwnerReturnHold { resource },
    }
}

fn refusal(error: LedgerError, parent: Option<ReservationKey>) -> CapacityRefusal {
    match error {
        LedgerError::Capacity(capacity) => capacity_refusal(&capacity, parent),
        LedgerError::SourceNotAuthoritative { source, required } => {
            CapacityRefusal::SourceTooWeak { source, required }
        }
        other => CapacityRefusal::Refused {
            reason: other.to_string(),
        },
    }
}

/// The host's one ledger, shared by every client that charges it: the coordinator's
/// capacity port, the transfer byte budget and the executor's reservations (CORE-03: one
/// capacity authority, so nothing is granted twice).
pub type SharedLedger<C> = Arc<Mutex<Ledger<C>>>;

/// How [`LedgerCapacity`] reaches the ledger: owning it, or through the [`SharedLedger`]
/// handle its other clients hold too.
pub trait LedgerHandle<C: Clock> {
    /// Runs `read` on the ledger.
    fn read<R>(&self, read: impl FnOnce(&Ledger<C>) -> R) -> R;
    /// Runs `write` on the ledger.
    fn write<R>(&mut self, write: impl FnOnce(&mut Ledger<C>) -> R) -> R;
}

impl<C: Clock> LedgerHandle<C> for Ledger<C> {
    fn read<R>(&self, read: impl FnOnce(&Ledger<C>) -> R) -> R {
        read(self)
    }

    fn write<R>(&mut self, write: impl FnOnce(&mut Ledger<C>) -> R) -> R {
        write(self)
    }
}

impl<C: Clock> LedgerHandle<C> for SharedLedger<C> {
    fn read<R>(&self, read: impl FnOnce(&Ledger<C>) -> R) -> R {
        read(&lock(self))
    }

    fn write<R>(&mut self, write: impl FnOnce(&mut Ledger<C>) -> R) -> R {
        write(&mut lock(self))
    }
}

/// The shared ledger, locked as its other clients lock it.
fn lock<C>(ledger: &SharedLedger<C>) -> MutexGuard<'_, Ledger<C>> {
    ledger.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The CORE-03 ledger as the coordination protocol's [`CapacityPort`]. By default it owns
/// the ledger; [`LedgerCapacity::shared`] charges the host's one ledger through the handle
/// the transfer byte budget and the executor's reservations hold too.
pub struct LedgerCapacity<C: Clock, L: LedgerHandle<C> = Ledger<C>> {
    ledger: L,
    queue_wait: Option<Duration>,
    queued: BTreeMap<ReservationKey, (ExecutionId, QueueTicket)>,
    holds: BTreeMap<ReturnHold, HoldId>,
    next_hold: u64,
    clock: PhantomData<fn() -> C>,
}

impl<C: Clock> LedgerCapacity<C> {
    /// The port over `ledger`, which it owns. A request that does not fit is refused at
    /// once.
    pub fn new(ledger: Ledger<C>) -> Self {
        Self::over(ledger)
    }

    /// The ledger itself.
    pub fn ledger(&self) -> &Ledger<C> {
        &self.ledger
    }

    /// The ledger itself, for host observations and budgets.
    pub fn ledger_mut(&mut self) -> &mut Ledger<C> {
        &mut self.ledger
    }

    /// The open reservation `key` names.
    pub fn record(&self, key: &ReservationKey) -> Option<&ReservationRecord> {
        self.ledger
            .open_reservations()
            .find(|record| key_of(record).as_ref() == Some(key))
    }

    /// The same port over the same ledger, from now on shared through a handle its other
    /// clients can hold ([`LedgerCapacity::handle`]).
    pub fn into_shared(self) -> LedgerCapacity<C, SharedLedger<C>> {
        LedgerCapacity {
            ledger: Arc::new(Mutex::new(self.ledger)),
            queue_wait: self.queue_wait,
            queued: self.queued,
            holds: self.holds,
            next_hold: self.next_hold,
            clock: PhantomData,
        }
    }
}

impl<C: Clock> LedgerCapacity<C, SharedLedger<C>> {
    /// The port over the host's one ledger, shared with its other clients: hand the same
    /// handle to the transfer byte budget and the executor's reservations, so each
    /// resource is granted once (CORE-03). A request that does not fit is refused at once.
    pub fn shared(ledger: SharedLedger<C>) -> Self {
        Self::over(ledger)
    }

    /// The shared handle, for the ledger's other clients.
    pub fn handle(&self) -> SharedLedger<C> {
        Arc::clone(&self.ledger)
    }

    /// The ledger, locked while the guard lives.
    pub fn ledger(&self) -> MutexGuard<'_, Ledger<C>> {
        lock(&self.ledger)
    }

    /// The open reservation `key` names, as it stands now.
    pub fn record(&self, key: &ReservationKey) -> Option<ReservationRecord> {
        lock(&self.ledger)
            .open_reservations()
            .find(|record| key_of(record).as_ref() == Some(key))
            .cloned()
    }
}

impl<C: Clock, L: LedgerHandle<C>> LedgerCapacity<C, L> {
    fn over(ledger: L) -> Self {
        Self {
            ledger,
            queue_wait: None,
            queued: BTreeMap::new(),
            holds: BTreeMap::new(),
            next_hold: 0,
            clock: PhantomData,
        }
    }

    /// A request that does not fit yet waits in the ledger's bounded queue for at most
    /// `max_wait`, when waiting can help (S10 line 179).
    pub fn with_queue_wait(mut self, max_wait: Duration) -> Self {
        self.queue_wait = Some(max_wait);
        self
    }

    fn id(&self, key: &ReservationKey) -> Option<ReservationId> {
        self.ledger.read(|ledger| {
            ledger
                .open_reservations()
                .find(|record| key_of(record).as_ref() == Some(key))
                .map(ReservationRecord::id)
        })
    }

    /// For the open reservation `request` names, whether it is releasing and whether it
    /// was made by the same request.
    fn existing(
        &self,
        request: &ReservationRequest,
        parent: Option<ReservationId>,
    ) -> Option<(bool, bool)> {
        self.ledger.read(|ledger| {
            ledger
                .open_reservations()
                .find(|record| key_of(record).as_ref() == Some(&request.key))
                .map(|record| {
                    (
                        record.state() == ReservationState::Releasing,
                        Self::same_request(record, request, parent),
                    )
                })
        })
    }

    fn same_request(
        record: &ReservationRecord,
        request: &ReservationRequest,
        parent: Option<ReservationId>,
    ) -> bool {
        let provenance = record.provenance();
        provenance.tenant == request.tenant
            && provenance.execution == request.execution
            && record.priority() == ledger_priority(request.priority)
            && record.parent() == parent
            && *record.granted() == amounts(&request.demand)
    }
}

impl<C: Clock, L: LedgerHandle<C>> CapacityPort for LedgerCapacity<C, L> {
    fn reserve(&mut self, request: &ReservationRequest) -> Result<ReserveOutcome, CapacityRefusal> {
        let parent = match request.parent {
            None => None,
            Some(parent) => Some(
                self.id(&parent)
                    .ok_or(CapacityRefusal::UnknownParent { parent })?,
            ),
        };
        if let Some((releasing, same)) = self.existing(request, parent) {
            let outcome = if !releasing && same {
                Ok(ReserveOutcome::Granted)
            } else {
                Err(CapacityRefusal::KeyConflict { key: request.key })
            };
            self.queued.remove(&request.key);
            return outcome;
        }
        if let Some((_, ticket)) = self.queued.get(&request.key) {
            let ticket = *ticket;
            if let Some(ahead) = self.ledger.read(|ledger| ledger.queue_position(ticket)) {
                return Ok(ReserveOutcome::Queued {
                    position: u32::try_from(ahead).unwrap_or(u32::MAX).saturating_add(1),
                });
            }
            self.queued.remove(&request.key);
        }
        let provenance = Provenance {
            requester: Requester::Coordination,
            execution: request.execution.clone(),
            operation: operation_of(&request.key)?,
            tenant: request.tenant.clone(),
            purpose: cost_purpose(&request.purpose),
            retry_number: 0,
        };
        let mut ledger_request = LedgerRequest::new(
            provenance,
            ledger_priority(request.priority),
            amounts(&request.demand),
        );
        if let Some(parent) = parent {
            ledger_request = ledger_request.within(parent);
        }
        if let Some(max_wait) = self.queue_wait {
            ledger_request = ledger_request.wait_up_to(max_wait);
        }
        match self.ledger.write(|ledger| ledger.reserve(ledger_request)) {
            Ok(Admission::Granted(_)) => Ok(ReserveOutcome::Granted),
            Ok(Admission::Queued { ticket, ahead, .. }) => {
                self.queued
                    .insert(request.key, (request.execution.clone(), ticket));
                Ok(ReserveOutcome::Queued {
                    position: u32::try_from(ahead).unwrap_or(u32::MAX).saturating_add(1),
                })
            }
            Err(error) => Err(refusal(error, request.parent)),
        }
    }

    fn begin_create(&mut self, key: &ReservationKey) -> Result<(), CapacityRefusal> {
        let id = self
            .id(key)
            .ok_or(CapacityRefusal::UnknownReservation { key: *key })?;
        self.ledger
            .write(|ledger| ledger.begin_create(id))
            .map_err(|error| refusal(error, None))
    }

    fn release(&mut self, key: &ReservationKey) -> Result<ReleaseOutcome, CapacityRefusal> {
        let Some(id) = self.id(key) else {
            if let Some((_, ticket)) = self.queued.remove(key) {
                self.ledger
                    .write(|ledger| ledger.cancel_queued(ticket))
                    .map_err(|error| refusal(error, None))?;
            }
            return Ok(ReleaseOutcome::NotHeld);
        };
        match self
            .ledger
            .write(|ledger| ledger.cancel(id))
            .map_err(|error| refusal(error, None))?
        {
            LedgerRelease::Released { .. } => Ok(ReleaseOutcome::Released),
            LedgerRelease::Pending => Ok(ReleaseOutcome::Pending),
            LedgerRelease::AlreadyClosed => Ok(ReleaseOutcome::NotHeld),
        }
    }

    fn confirm_release(
        &mut self,
        key: &ReservationKey,
        source: SourceClass,
    ) -> Result<ReleaseOutcome, CapacityRefusal> {
        let Some(id) = self.id(key) else {
            return Ok(ReleaseOutcome::NotHeld);
        };
        match self
            .ledger
            .write(|ledger| ledger.confirm_release(id, source))
            .map_err(|error| refusal(error, None))?
        {
            LedgerRelease::Released { .. } => Ok(ReleaseOutcome::Released),
            LedgerRelease::Pending => Ok(ReleaseOutcome::Pending),
            LedgerRelease::AlreadyClosed => Ok(ReleaseOutcome::NotHeld),
        }
    }

    fn cancel_execution(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<ExecutionCancellation, CapacityRefusal> {
        let report = self
            .ledger
            .write(|ledger| ledger.cancel_execution(execution));
        self.queued.retain(|_, (owner, _)| owner != execution);
        Ok(ExecutionCancellation {
            released: report.released.len(),
            pending: report.pending.len(),
            dequeued: report.dequeued.len(),
        })
    }

    fn reconcile(
        &mut self,
        execution: &ExecutionId,
        expected: &BTreeSet<ReservationKey>,
    ) -> Result<ReconcileReport, CapacityRefusal> {
        let mine: BTreeMap<ReservationKey, (ReservationId, Option<ReservationId>)> =
            self.ledger.read(|ledger| {
                ledger
                    .open_reservations()
                    .filter(|record| &record.provenance().execution == execution)
                    .filter_map(|record| {
                        key_of(record).map(|key| (key, (record.id(), record.parent())))
                    })
                    .collect()
            });
        let keys: BTreeSet<ReservationKey> = mine.keys().copied().collect();
        let mut report = ReconcileReport {
            confirmed: keys.intersection(expected).copied().collect(),
            missing: expected.difference(&keys).copied().collect(),
            ..ReconcileReport::default()
        };
        let unexpected: BTreeMap<ReservationKey, (ReservationId, Option<ReservationId>)> = mine
            .into_iter()
            .filter(|(key, _)| !expected.contains(key))
            .collect();
        let unexpected_ids: BTreeSet<ReservationId> =
            unexpected.values().map(|(id, _)| *id).collect();
        for (id, parent) in unexpected.values() {
            if parent.is_some_and(|parent| unexpected_ids.contains(&parent)) {
                continue;
            }
            let id = *id;
            self.ledger
                .write(|ledger| ledger.cancel(id))
                .map_err(|error| refusal(error, None))?;
        }
        for key in unexpected.keys() {
            if self.id(key).is_some() {
                report.pending_orphans.insert(*key);
            } else {
                report.released_orphans.insert(*key);
            }
        }
        let stale: Vec<ReservationKey> = self
            .queued
            .iter()
            .filter(|(key, (owner, _))| owner == execution && !expected.contains(key))
            .map(|(key, _)| *key)
            .collect();
        for key in stale {
            if let Some((_, ticket)) = self.queued.remove(&key) {
                self.ledger
                    .write(|ledger| ledger.cancel_queued(ticket))
                    .map_err(|error| refusal(error, None))?;
            }
        }
        Ok(report)
    }

    fn begin_hold(
        &mut self,
        resources: &BTreeSet<ResourceKind>,
    ) -> Result<ReturnHold, CapacityRefusal> {
        let held = resources.iter().copied().map(ledger_resource).collect();
        let report = self
            .ledger
            .write(|ledger| ledger.begin_hold(held))
            .map_err(|error| refusal(error, None))?;
        self.next_hold = self.next_hold.saturating_add(1);
        let hold = ReturnHold::new(self.next_hold);
        self.holds.insert(hold, report.hold);
        Ok(hold)
    }

    fn end_hold(&mut self, hold: ReturnHold) -> Result<(), CapacityRefusal> {
        if let Some(id) = self.holds.remove(&hold) {
            self.ledger
                .write(|ledger| ledger.end_hold(id))
                .map_err(|error| refusal(error, None))?;
        }
        Ok(())
    }
}
