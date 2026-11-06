//! The byte-budget port over the CORE-03 ledger (T04), and the network slot every active
//! transfer holds in it (S10 line 179).
//!
//! A transfer's byte budget is one host-level ledger reservation (S3.7; CORE-03 reserve
//! before create). It is reserved when the transfer opens and created at once, since bytes
//! start moving right away. Each admitted chunk is charged as a host observation of the
//! bytes used, which leaves the reserved amount whole for the chunks still to come. When
//! the transfer ends the reservation is released; bytes of chunks that may still be
//! moving keep counting until their declared deadline has passed, so a stop never shows
//! false free capacity (CORE-03, INT-02).
//!
//! An adapter made with [`LedgerByteBudget::holding_network_slot`] puts one network slot
//! into that same reservation, so the slot is granted with the bytes or not at all, is
//! charged with their provenance, and is released with them, counting until the same
//! settle time. A direction without a byte resource (uploads and peer sends, which the
//! envelope's own budget bounds under the T14 follow-up decision) then holds the slot
//! alone. When no slot is free the ledger's answer is returned as an actionable refusal
//! that names network slots and whether a retry can progress; the adapter asks the ledger
//! not to queue, since a transfer session is opened or refused at once.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::endpoint::Direction;
use super::ports::{
    ByteBudgetPort, ByteBudgetRefusal, ByteReservation, ByteReservationRequest, NetworkSlotRefusal,
    ReservationRefusal, ReservationWithdrawn, SlotLimit,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{Clock, MonotonicTime};
use crate::foundation::ledger::{
    Admission, Amounts, CapacityError, CostPurpose, HostResource, Ledger, LedgerError, Limit,
    Priority, Provenance, Requester, ReservationId, ReservationRequest, ReservationState,
    ResourceKey, ResourceUnit, UsageObservation,
};

/// The ledger resource of the network slot every active transfer holds (S10 line 179;
/// the T04 decision counts network slots in slots).
pub const NETWORK_SLOT_RESOURCE: ResourceKey = ResourceKey::Host(HostResource::NetworkSlots);

/// A direction was mapped to a ledger resource not counted in bytes, which cannot hold a
/// byte budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NotCountedInBytes {
    pub direction: Direction,
    pub resource: ResourceKey,
}

impl fmt::Display for NotCountedInBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} transfers cannot be charged to {}, which is counted in {}, not bytes",
            self.direction,
            self.resource,
            self.resource.unit().name()
        )
    }
}

impl std::error::Error for NotCountedInBytes {}

/// [`ByteBudgetPort`] over the host's [`Ledger`], shared with its other clients.
///
/// Each direction's budget is charged to the ledger resource it is mapped to; a direction
/// without one is refused, never charged elsewhere, unless the adapter holds a network
/// slot, which such a direction then holds alone. Reservations carry the
/// [`Requester::Transfer`] and [`CostPurpose::Transfer`] provenance. Call
/// [`Self::settle_due`] periodically, as with [`Ledger::tick`], to close releases whose
/// chunks have settled; the next reservation does so too.
pub struct LedgerByteBudget<C> {
    ledger: Arc<Mutex<Ledger<C>>>,
    /// The clock the ledger reads.
    clock: Arc<dyn Clock>,
    resources: BTreeMap<Direction, ResourceKey>,
    priority: Priority,
    /// Whether every transfer's reservation also holds one network slot (S10 line 179).
    network_slot: bool,
    held: Mutex<BTreeMap<u64, Held>>,
}

struct Held {
    id: ReservationId,
    /// The byte resource charged; `None` when the reservation holds the slot alone.
    resource: Option<ResourceKey>,
    /// Whether the reservation holds a network slot.
    slot: bool,
    /// Set once released: when its last chunk is past its deadline.
    settles_at: Option<MonotonicTime>,
}

/// A refusal in both readings: in bytes for [`ByteBudgetPort::reserve`], and naming the
/// slot for [`ByteBudgetPort::reserve_transfer`] when network slots limit the request.
struct Refused {
    bytes: ByteBudgetRefusal,
    slot: Option<NetworkSlotRefusal>,
}

impl<C: Clock> LedgerByteBudget<C> {
    /// An adapter charging each direction's budgets to `resources`, at `priority`; an
    /// owner resource-return hold denies background reservations (S10 line 185). It holds
    /// no network slot; see [`Self::holding_network_slot`].
    pub fn new(
        ledger: Arc<Mutex<Ledger<C>>>,
        clock: Arc<dyn Clock>,
        resources: BTreeMap<Direction, ResourceKey>,
        priority: Priority,
    ) -> Result<Self, NotCountedInBytes> {
        if let Some((&direction, &resource)) = resources
            .iter()
            .find(|(_, resource)| resource.unit() != ResourceUnit::Bytes)
        {
            return Err(NotCountedInBytes {
                direction,
                resource,
            });
        }
        Ok(Self {
            ledger,
            clock,
            resources,
            priority,
            network_slot: false,
            held: Mutex::new(BTreeMap::new()),
        })
    }

    /// The same adapter holding one network slot in the ledger for every transfer, from
    /// its open until its terminal phase or until a continuation takes over (S10 line
    /// 179; the T14 integration item), reserved with the bytes as one all-or-nothing
    /// request. The host must have declared the [`NETWORK_SLOT_RESOURCE`] capacity and
    /// each tenant must have a slot budget, or the ledger refuses every transfer.
    pub fn holding_network_slot(mut self) -> Self {
        self.network_slot = true;
        self
    }

    /// The ledger reservation behind `reservation`, until its release is closed.
    pub fn ledger_reservation(&self, reservation: ByteReservation) -> Option<ReservationId> {
        lock(&self.held).get(&reservation.token).map(|held| held.id)
    }

    /// Closes every release whose chunks are all past their deadlines, as a host
    /// observation; returns how many closed.
    pub fn settle_due(&self) -> usize {
        let now = self.clock.now();
        let mut held = lock(&self.held);
        let due: Vec<u64> = held
            .iter()
            .filter(|(_, entry)| entry.settles_at.is_some_and(|at| at <= now))
            .map(|(token, _)| *token)
            .collect();
        if due.is_empty() {
            return 0;
        }
        let mut ledger = lock(&self.ledger);
        for token in &due {
            if let Some(entry) = held.remove(token) {
                let _ = ledger.confirm_release(entry.id, SourceClass::HostProbe);
            }
        }
        due.len()
    }

    /// One ledger request for the bytes of the direction's resource and, when held, the
    /// network slot, granted whole or refused (CORE-03; S10 line 179).
    fn reserve_in_ledger(
        &self,
        request: &ByteReservationRequest,
    ) -> Result<ByteReservation, Refused> {
        self.settle_due();
        let refuse = |available_bytes, retry_can_progress| Refused {
            bytes: ByteBudgetRefusal {
                requested_bytes: request.requested_bytes,
                available_bytes,
                retry_can_progress,
            },
            slot: None,
        };
        let resource = self.resources.get(&request.direction).copied();
        if resource.is_none() && !self.network_slot {
            return Err(refuse(0, false));
        }
        let mut demand = Amounts::new();
        if let Some(resource) = resource {
            demand = demand.with(resource, request.requested_bytes);
        }
        if self.network_slot {
            demand = demand.network_slots(1);
        }
        let ledger_request = ReservationRequest::new(
            Provenance {
                requester: Requester::Transfer,
                execution: request.parent.clone(),
                operation: request.operation.clone(),
                tenant: request.tenant.clone(),
                purpose: CostPurpose::Transfer,
                retry_number: request.retry_number,
            },
            self.priority,
            demand,
        );
        let mut held = lock(&self.held);
        let mut ledger = lock(&self.ledger);
        let id = match ledger.reserve(ledger_request) {
            Ok(Admission::Granted(id)) => id,
            Ok(Admission::Queued { ticket, .. }) => {
                let _ = ledger.cancel_queued(ticket);
                return Err(refuse(0, true));
            }
            Err(LedgerError::Capacity(error)) => return Err(self.capacity_refusal(request, &error)),
            Err(_) => return Err(refuse(0, false)),
        };
        if ledger.begin_create(id).is_err() {
            let _ = ledger.cancel(id);
            return Err(refuse(0, false));
        }
        held.insert(
            id.get(),
            Held {
                id,
                resource,
                slot: self.network_slot,
                settles_at: None,
            },
        );
        Ok(ByteReservation {
            token: id.get(),
            reserved_bytes: request.requested_bytes,
        })
    }

    /// The ledger's capacity error as the port's refusal (S10 line 179): the limiting
    /// shortfall names the resource, and the retry prospect covers every shortfall. In
    /// bytes, the available amount is the byte shortfall's, or the request's own count
    /// when only the slot was short.
    fn capacity_refusal(&self, request: &ByteReservationRequest, error: &CapacityError) -> Refused {
        let retry_can_progress = error.retry_can_progress();
        let limiting = error.limiting();
        let available_bytes = error
            .shortfalls()
            .find(|shortfall| shortfall.resource != NETWORK_SLOT_RESOURCE)
            .map_or(request.requested_bytes, |shortfall| shortfall.available);
        let slot = (self.network_slot && limiting.resource == NETWORK_SLOT_RESOURCE).then(|| {
            NetworkSlotRefusal {
                limit: slot_limit(&limiting.limit),
                retry_can_progress,
            }
        });
        Refused {
            bytes: ByteBudgetRefusal {
                requested_bytes: request.requested_bytes,
                available_bytes,
                retry_can_progress,
            },
            slot,
        }
    }
}

impl<C: Clock> ByteBudgetPort for LedgerByteBudget<C> {
    /// As [`Self::reserve_transfer`], read in bytes: when only the network slot is short
    /// the bytes are reported as available and the retry prospect covers both.
    fn reserve(
        &self,
        request: &ByteReservationRequest,
    ) -> Result<ByteReservation, ByteBudgetRefusal> {
        self.reserve_in_ledger(request)
            .map_err(|refused| refused.bytes)
    }

    fn reserve_transfer(
        &self,
        request: &ByteReservationRequest,
    ) -> Result<ByteReservation, ReservationRefusal> {
        self.reserve_in_ledger(request)
            .map_err(|refused| match refused.slot {
                Some(slot) => ReservationRefusal::NetworkSlot(slot),
                None => ReservationRefusal::Bytes(refused.bytes),
            })
    }

    fn holds_network_slot(&self) -> bool {
        self.network_slot
    }

    fn charge(
        &self,
        reservation: ByteReservation,
        used_bytes: u64,
    ) -> Result<(), ReservationWithdrawn> {
        let held = lock(&self.held);
        let Some(entry) = held
            .get(&reservation.token)
            .filter(|entry| entry.settles_at.is_none())
        else {
            return Err(ReservationWithdrawn);
        };
        let mut ledger = lock(&self.ledger);
        let state = ledger.reservation(entry.id).map(|record| record.state());
        if state != Some(ReservationState::InUse) {
            return Err(ReservationWithdrawn);
        }
        ledger
            .observe_usage(entry.id, usage(entry, used_bytes))
            .map_err(|_| ReservationWithdrawn)
    }

    fn release(&self, reservation: ByteReservation, used_bytes: u64, settled_by: MonotonicTime) {
        let mut held = lock(&self.held);
        let Some((id, used)) = held
            .get(&reservation.token)
            .map(|entry| (entry.id, usage(entry, used_bytes)))
        else {
            return;
        };
        let mut ledger = lock(&self.ledger);
        let _ = ledger.observe_usage(id, used);
        let _ = ledger.cancel(id);
        if settled_by <= self.clock.now() {
            let _ = ledger.confirm_release(id, SourceClass::HostProbe);
            held.remove(&reservation.token);
        } else if let Some(entry) = held.get_mut(&reservation.token) {
            entry.settles_at = Some(settled_by);
        }
    }
}

/// The host's own count of what the transfer uses: the bytes moved and, when held, its
/// network slot. The session that admits them runs on the host.
fn usage(entry: &Held, used_bytes: u64) -> UsageObservation {
    let mut in_use = Amounts::new();
    if let Some(resource) = entry.resource {
        in_use = in_use.with(resource, used_bytes);
    }
    if entry.slot {
        in_use = in_use.network_slots(1);
    }
    UsageObservation {
        source: SourceClass::HostProbe,
        in_use,
    }
}

/// The ledger's limit in the port's terms.
fn slot_limit(limit: &Limit) -> SlotLimit {
    match limit {
        Limit::PhysicalCapacity => SlotLimit::HostCapacity,
        Limit::CapacityNotObserved | Limit::StaleHostObservation { .. } => {
            SlotLimit::HostObservation
        }
        Limit::TenantBudget { .. } => SlotLimit::TenantBudget,
        Limit::ParentReservation { .. } => SlotLimit::ParentReservation,
        Limit::OwnerReturnHold { .. } => SlotLimit::OwnerReturnHold,
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::json;

    use super::*;
    use crate::foundation::evidence::HostSubject;
    use crate::foundation::ids::{digest, AuthorizationEpoch, ManualClock, TenantId};
    use crate::foundation::ledger::{
        CapacityDeclaration, CloseReason, HostResource, LedgerConfig, QueueLimits,
    };
    use crate::foundation::transfer::fakes::{
        at, connection_for, download_connection, download_fields, object, operation, parent, peer,
        range, tenant, test_key, upload_fields, World, EPOCH, GIB, HOUR, MIB, SECOND, SESSION,
    };
    use crate::foundation::transfer::{
        EnvelopeFields, ObjectGrant, StopReason, TransferGate, TransferPorts, TransferRefusal,
        TransferScope, TransferSession, TransferStatus,
    };

    const STORAGE: ResourceKey = ResourceKey::Host(HostResource::StorageQuota);
    const NETWORK: ResourceKey = NETWORK_SLOT_RESOURCE;
    const EPOCH_5: AuthorizationEpoch = AuthorizationEpoch::new(5);

    /// 10,000 bytes of storage quota, of which tenant-a may reserve 1,000.
    fn ledger_on(clock: Arc<ManualClock>) -> Arc<Mutex<Ledger<Arc<ManualClock>>>> {
        let mut ledger = Ledger::new(
            clock,
            HostSubject {
                machine: digest("yougori/test/machine/v1", &[b"workstation"]),
            },
            LedgerConfig {
                queue: QueueLimits {
                    max_entries: 4,
                    max_entries_per_tenant: 2,
                    max_wait: Duration::from_secs(60),
                },
                grant_ttl: Duration::from_secs(300),
                unmanaged_usage_max_age: Duration::from_secs(3_600),
            },
        );
        ledger
            .declare_capacity(
                STORAGE,
                CapacityDeclaration {
                    total: 10_000,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger.set_tenant_budget(tenant(), STORAGE, 1_000).unwrap();
        Arc::new(Mutex::new(ledger))
    }

    /// Downloads charged to the storage quota, through a gate over the world's other fakes.
    fn adapter_world() -> (
        World,
        Arc<Mutex<Ledger<Arc<ManualClock>>>>,
        Arc<LedgerByteBudget<Arc<ManualClock>>>,
        TransferGate,
    ) {
        let world = World::new();
        let ledger = ledger_on(world.clock.clone());
        let budget = Arc::new(
            LedgerByteBudget::new(
                ledger.clone(),
                world.clock.clone(),
                BTreeMap::from([(Direction::Download, STORAGE)]),
                Priority::Foreground,
            )
            .unwrap(),
        );
        let gate = TransferGate::new(
            test_key(),
            TransferPorts {
                clock: world.clock.clone(),
                clock_session: SESSION,
                authority: world.authority.clone(),
                budget: budget.clone(),
                extents: world.extents.clone(),
                progress: world.progress.clone(),
            },
        );
        (world, ledger, budget, gate)
    }

    fn ledger_id(
        budget: &LedgerByteBudget<Arc<ManualClock>>,
        session: &TransferSession,
    ) -> ReservationId {
        budget
            .ledger_reservation(session.reservation().unwrap())
            .unwrap()
    }

    /// The budget is reserved in the ledger when the transfer opens, charged per admitted
    /// chunk, and released at finish; a cancelled transfer's bytes count until its
    /// in-flight chunk is past its deadline.
    #[test]
    fn a_transfer_reserves_charges_and_releases_its_budget_in_the_ledger() {
        let (world, ledger, budget, gate) = adapter_world();
        let mut session = gate
            .open(&world.seal(download_fields()), &download_connection())
            .unwrap();
        let id = ledger_id(&budget, &session);
        {
            let ledger = lock(&ledger);
            assert_eq!(ledger.reserved(STORAGE), 150);
            assert_eq!(ledger.tenant_reserved(&tenant(), STORAGE), 150);
            assert_eq!(ledger.available(STORAGE), Some(10_000 - 150));
            let record = ledger.reservation(id).unwrap();
            assert_eq!(record.state(), ReservationState::InUse);
            assert_eq!(record.current().get(STORAGE), 150);
            let provenance = record.provenance();
            assert_eq!(provenance.requester, Requester::Transfer);
            assert_eq!(provenance.purpose, CostPurpose::Transfer);
            assert_eq!(provenance.operation, operation("op-download"));
            assert_eq!(provenance.execution, parent());
            assert_eq!(provenance.retry_number, 0);
        }

        for (start, end) in [(0, 40), (40, 80), (80, 100)] {
            let permit = session
                .admit(&object("weights"), range(start, end))
                .unwrap();
            {
                let ledger = lock(&ledger);
                let record = ledger.reservation(id).unwrap();
                let charged = record.observation_from(SourceClass::HostProbe).unwrap();
                assert_eq!(charged.in_use.get(STORAGE), end);
                assert_eq!(record.current().get(STORAGE), 150);
                assert_eq!(ledger.reserved(STORAGE), 150);
            }
            session.deliver(permit).unwrap();
            world.verify(
                session.envelope().fields(),
                &object("weights"),
                range(start, end),
            );
        }

        session.finish().unwrap();
        {
            let ledger = lock(&ledger);
            assert_eq!(ledger.reserved(STORAGE), 0);
            assert!(ledger.reservation(id).is_none());
            let closed = ledger
                .closed_records()
                .iter()
                .find(|record| record.id() == id)
                .unwrap();
            assert_eq!(
                closed.close_reason(),
                Some(CloseReason::ReleaseObserved {
                    source: SourceClass::HostProbe
                })
            );
            let used = closed.observation_from(SourceClass::HostProbe).unwrap();
            assert_eq!(used.in_use.get(STORAGE), 100);
        }

        let mut fields = download_fields();
        fields.operation = operation("op-cancelled");
        fields.scope = TransferScope::single(object("adapter"), ObjectGrant::whole(100).unwrap());
        let mut cancelled = gate
            .open(&world.seal(fields), &download_connection())
            .unwrap();
        let id = ledger_id(&budget, &cancelled);
        let _in_flight = cancelled.admit(&object("adapter"), range(0, 40)).unwrap();
        world.advance(SECOND);
        cancelled.cancel();
        {
            let ledger = lock(&ledger);
            assert_eq!(
                ledger.reservation(id).map(|record| record.state()),
                Some(ReservationState::Releasing)
            );
            assert_eq!(ledger.reserved(STORAGE), 150);
        }
        assert_eq!(budget.settle_due(), 0);
        world.advance(9 * SECOND);
        assert_eq!(budget.settle_due(), 1);
        let ledger = lock(&ledger);
        assert_eq!(ledger.reserved(STORAGE), 0);
        assert!(ledger.reservation(id).is_none());
        assert_eq!(ledger.open_reservations().count(), 0);
    }

    /// The ledger's refusals reach the transfer as reservation refusals, and a reservation
    /// the ledger withdraws, as on revocation, stops the transfer at its next chunk.
    #[test]
    fn ledger_refusals_and_withdrawals_stop_the_transfer() {
        let (world, ledger, budget, gate) = adapter_world();
        let mut oversized = download_fields();
        oversized.budget_bytes = 1_500;
        assert_eq!(
            gate.open(&world.seal(oversized), &download_connection())
                .unwrap_err(),
            TransferRefusal::ReservationRefused {
                refusal: ByteBudgetRefusal {
                    requested_bytes: 1_500,
                    available_bytes: 1_000,
                    retry_can_progress: false,
                }
            }
        );
        let upload = upload_fields();
        let connection = crate::foundation::transfer::fakes::connection_for(&upload);
        assert!(matches!(
            gate.open(&world.seal(upload), &connection),
            Err(TransferRefusal::ReservationRefused {
                refusal: ByteBudgetRefusal {
                    available_bytes: 0,
                    retry_can_progress: false,
                    ..
                }
            })
        ));
        assert_eq!(lock(&ledger).reserved(STORAGE), 0);

        let mut session = gate
            .open(&world.seal(download_fields()), &download_connection())
            .unwrap();
        let id = ledger_id(&budget, &session);
        lock(&ledger).cancel_execution(&parent());
        assert_eq!(
            session.admit(&object("weights"), range(0, 40)).unwrap_err(),
            TransferRefusal::Stopped {
                reason: StopReason::ReservationWithdrawn
            }
        );
        let ledger = lock(&ledger);
        assert!(ledger.reservation(id).is_none());
        assert_eq!(ledger.reserved(STORAGE), 0);

        let slots = BTreeMap::from([(
            Direction::Upload,
            ResourceKey::Host(HostResource::NetworkSlots),
        )]);
        assert!(matches!(
            LedgerByteBudget::new(
                ledger_on(world.clock.clone()),
                world.clock.clone(),
                slots,
                Priority::Foreground
            ),
            Err(NotCountedInBytes {
                direction: Direction::Upload,
                ..
            })
        ));
    }

    // -----------------------------------------------------------------------------------
    // One network slot per active transfer (S10 line 179; the T14 integration item).
    // -----------------------------------------------------------------------------------

    /// The host has `total` network slots, of which tenant-a may hold `tenant_budget`.
    fn declare_slots(ledger: &Mutex<Ledger<Arc<ManualClock>>>, total: u64, tenant_budget: u64) {
        let mut ledger = lock(ledger);
        ledger
            .declare_capacity(
                NETWORK,
                CapacityDeclaration {
                    total,
                    supervisor_reserve: 0,
                    unmanaged_in_use: 0,
                    source: SourceClass::HostProbe,
                },
            )
            .unwrap();
        ledger
            .set_tenant_budget(tenant(), NETWORK, tenant_budget)
            .unwrap();
    }

    fn gate_over(world: &World, budget: Arc<LedgerByteBudget<Arc<ManualClock>>>) -> TransferGate {
        TransferGate::new(
            test_key(),
            TransferPorts {
                clock: world.clock.clone(),
                clock_session: SESSION,
                authority: world.authority.clone(),
                budget,
                extents: world.extents.clone(),
                progress: world.progress.clone(),
            },
        )
    }

    /// Downloads charged to the storage quota, and every transfer holding one of the
    /// host's `slots` network slots, all of which tenant-a may hold.
    fn slot_world(
        slots: u64,
    ) -> (
        World,
        Arc<Mutex<Ledger<Arc<ManualClock>>>>,
        Arc<LedgerByteBudget<Arc<ManualClock>>>,
        TransferGate,
    ) {
        let world = World::new();
        let ledger = ledger_on(world.clock.clone());
        declare_slots(&ledger, slots, slots);
        let budget = Arc::new(
            LedgerByteBudget::new(
                ledger.clone(),
                world.clock.clone(),
                BTreeMap::from([(Direction::Download, STORAGE)]),
                Priority::Foreground,
            )
            .unwrap()
            .holding_network_slot(),
        );
        let gate = gate_over(&world, budget.clone());
        (world, ledger, budget, gate)
    }

    /// The download grant under `name`, for a 100-byte object of its own.
    fn download(name: &str) -> EnvelopeFields {
        let mut fields = download_fields();
        fields.operation = operation(name);
        fields.scope = TransferScope::single(object(name), ObjectGrant::whole(100).unwrap());
        fields
    }

    fn open_download(world: &World, gate: &TransferGate, name: &str) -> TransferSession {
        gate.open(&world.seal(download(name)), &download_connection())
            .unwrap()
    }

    fn slots_held(ledger: &Mutex<Ledger<Arc<ManualClock>>>) -> u64 {
        lock(ledger).reserved(NETWORK)
    }

    /// Admits and delivers `start..end` of the object of `name`; the catalog verifies it.
    fn move_verified(
        world: &World,
        session: &mut TransferSession,
        name: &str,
        start: u64,
        end: u64,
    ) {
        let permit = session.admit(&object(name), range(start, end)).unwrap();
        session.deliver(permit).unwrap();
        world.verify(
            session.envelope().fields(),
            &object(name),
            range(start, end),
        );
    }

    fn move_all(world: &World, session: &mut TransferSession, name: &str) {
        for (start, end) in [(0, 40), (40, 80), (80, 100)] {
            move_verified(world, session, name, start, end);
        }
    }

    fn slot_refusal(limit: SlotLimit, retry_can_progress: bool) -> TransferRefusal {
        TransferRefusal::NetworkSlotRefused {
            refusal: NetworkSlotRefusal {
                limit,
                retry_can_progress,
            },
        }
    }

    /// S10 line 179: a transfer holds one network slot in the same ledger reservation as
    /// its bytes, with the same provenance, from its open until its terminal phase:
    /// finished, cancelled, abandoned on drop, expired or revoked.
    #[test]
    fn every_transfer_holds_one_network_slot_from_open_to_its_terminal_phase() {
        let (world, ledger, budget, gate) = slot_world(4);
        let mut finished = open_download(&world, &gate, "op-finished");
        let id = ledger_id(&budget, &finished);
        {
            let ledger = lock(&ledger);
            assert_eq!(ledger.open_reservations().count(), 1);
            let record = ledger.reservation(id).unwrap();
            assert_eq!(
                record.current(),
                &Amounts::new().storage_quota_bytes(150).network_slots(1)
            );
            assert_eq!(record.provenance().requester, Requester::Transfer);
            assert_eq!(record.provenance().purpose, CostPurpose::Transfer);
            assert_eq!(record.provenance().operation, operation("op-finished"));
            assert_eq!(record.provenance().execution, parent());
            assert_eq!(record.parent(), None);
            assert_eq!(ledger.reserved(NETWORK), 1);
            assert_eq!(ledger.tenant_reserved(&tenant(), NETWORK), 1);
            assert_eq!(ledger.available(NETWORK), Some(3));
        }
        move_all(&world, &mut finished, "op-finished");
        {
            let ledger = lock(&ledger);
            let record = ledger.reservation(id).unwrap();
            let charged = record.observation_from(SourceClass::HostProbe).unwrap();
            assert_eq!(
                charged.in_use,
                Amounts::new().storage_quota_bytes(100).network_slots(1)
            );
        }
        finished.finish().unwrap();
        assert_eq!(finished.status(), &TransferStatus::Completed);
        assert_eq!(slots_held(&ledger), 0);
        assert!(lock(&ledger).reservation(id).is_none());

        let mut cancelled = open_download(&world, &gate, "op-cancelled");
        assert_eq!(slots_held(&ledger), 1);
        cancelled.cancel();
        assert_eq!(slots_held(&ledger), 0);

        {
            let _abandoned = open_download(&world, &gate, "op-abandoned");
            assert_eq!(slots_held(&ledger), 1);
        }
        assert_eq!(slots_held(&ledger), 0);

        let mut fields = download("op-expiring");
        fields.expires_at = at(10 * SECOND);
        let mut expiring = gate
            .open(&world.seal(fields), &download_connection())
            .unwrap();
        assert_eq!(slots_held(&ledger), 1);
        world.advance(10 * SECOND);
        assert!(matches!(
            expiring.poll(),
            TransferStatus::Stopped(record) if matches!(record.reason, StopReason::Expired { .. })
        ));
        assert_eq!(slots_held(&ledger), 0);

        let mut revoked = open_download(&world, &gate, "op-revoked");
        assert_eq!(slots_held(&ledger), 1);
        world.authority.revoke(&parent());
        assert!(matches!(
            revoked.poll(),
            TransferStatus::Stopped(record) if record.reason.is_revocation()
        ));
        let ledger = lock(&ledger);
        assert_eq!(ledger.reserved(NETWORK), 0);
        assert_eq!(ledger.reserved(STORAGE), 0);
        assert_eq!(ledger.open_reservations().count(), 0);
    }

    /// S10 line 179: with N network slots, N transfers open and the next is refused with
    /// an actionable error that names network slots as the limiting resource and says
    /// whether a retry can progress. The refused request reserves nothing, since bytes and
    /// slot are one request, and it opens once a slot frees. A tenant without a slot
    /// budget is told a retry cannot help; an undeclared slot capacity, that the host must
    /// observe it first.
    #[test]
    fn the_transfer_after_the_last_slot_is_refused_until_one_frees() {
        let (world, ledger, budget, gate) = slot_world(2);
        let mut first = open_download(&world, &gate, "op-first");
        let _second = open_download(&world, &gate, "op-second");
        let refused = gate
            .open(&world.seal(download("op-third")), &download_connection())
            .unwrap_err();
        assert_eq!(refused, slot_refusal(SlotLimit::HostCapacity, true));
        let text = refused.to_string();
        assert!(text.contains("no network slot is free"), "{text}");
        assert!(
            text.contains("every network slot of this host is held"),
            "{text}"
        );
        assert!(text.contains("retry once another transfer ends"), "{text}");
        {
            let ledger = lock(&ledger);
            assert_eq!(ledger.reserved(NETWORK), 2);
            assert_eq!(ledger.reserved(STORAGE), 300);
            assert_eq!(ledger.open_reservations().count(), 2);
            assert_eq!(ledger.queue_len(), 0);
        }
        assert_eq!(world.progress.events().len(), 2);

        // Read in bytes alone, the same answer says the bytes were free and a retry can
        // progress.
        let request = ByteReservationRequest {
            tenant: tenant(),
            parent: parent(),
            operation: operation("op-third"),
            direction: Direction::Download,
            requested_bytes: 150,
            retry_number: 0,
        };
        assert_eq!(
            budget.reserve(&request),
            Err(ByteBudgetRefusal {
                requested_bytes: 150,
                available_bytes: 150,
                retry_can_progress: true,
            })
        );
        assert_eq!(
            budget.reserve_transfer(&request),
            Err(ReservationRefusal::NetworkSlot(NetworkSlotRefusal {
                limit: SlotLimit::HostCapacity,
                retry_can_progress: true,
            }))
        );

        first.cancel();
        let third = gate
            .open(&world.seal(download("op-third")), &download_connection())
            .unwrap();
        assert_eq!(slots_held(&ledger), 2);
        drop(third);
        assert_eq!(slots_held(&ledger), 1);

        let other_tenant = TenantId::new("tenant-b").unwrap();
        lock(&ledger)
            .set_tenant_budget(other_tenant.clone(), STORAGE, 1_000)
            .unwrap();
        let mut fields = download("op-other-tenant");
        fields.tenant = other_tenant;
        let refused = gate
            .open(&world.seal(fields), &download_connection())
            .unwrap_err();
        assert_eq!(refused, slot_refusal(SlotLimit::TenantBudget, false));
        let text = refused.to_string();
        assert!(text.contains("tenant's network slot budget"), "{text}");
        assert!(text.contains("retrying will not help"), "{text}");
        assert_eq!(lock(&ledger).reserved(STORAGE), 150);

        let undeclared = ledger_on(world.clock.clone());
        lock(&undeclared)
            .set_tenant_budget(tenant(), NETWORK, 1)
            .unwrap();
        let unobserved = Arc::new(
            LedgerByteBudget::new(
                undeclared,
                world.clock.clone(),
                BTreeMap::from([(Direction::Download, STORAGE)]),
                Priority::Foreground,
            )
            .unwrap()
            .holding_network_slot(),
        );
        let gate = gate_over(&world, unobserved);
        let refused = gate
            .open(
                &world.seal(download("op-unobserved")),
                &download_connection(),
            )
            .unwrap_err();
        assert_eq!(refused, slot_refusal(SlotLimit::HostObservation, true));
        assert!(refused.to_string().contains("retry after a host probe"));
    }

    /// When bytes and the slot are both short, the ledger's ranking names the limiting
    /// resource: an exceeded limit before one that frees, and at equal rank the ledger's
    /// resource order, in which the byte budget comes first.
    #[test]
    fn the_ledgers_ranking_names_the_limiting_resource() {
        let (world, ledger, _budget, gate) = slot_world(1);
        let _holder = open_download(&world, &gate, "op-holder");
        let mut oversized = download("op-oversized");
        oversized.budget_bytes = 1_500;
        assert_eq!(
            gate.open(&world.seal(oversized), &download_connection())
                .unwrap_err(),
            TransferRefusal::ReservationRefused {
                refusal: ByteBudgetRefusal {
                    requested_bytes: 1_500,
                    available_bytes: 850,
                    retry_can_progress: false,
                }
            }
        );
        assert_eq!(slots_held(&ledger), 1);

        let (world, ledger, _budget, gate) = slot_world(6);
        let holders: Vec<TransferSession> = (0..6)
            .map(|index| open_download(&world, &gate, &format!("op-{index}")))
            .collect();
        assert_eq!(lock(&ledger).tenant_reserved(&tenant(), STORAGE), 900);
        assert_eq!(
            gate.open(&world.seal(download("op-seventh")), &download_connection())
                .unwrap_err(),
            TransferRefusal::ReservationRefused {
                refusal: ByteBudgetRefusal {
                    requested_bytes: 150,
                    available_bytes: 100,
                    retry_can_progress: true,
                }
            }
        );
        drop(holders);
        assert_eq!(slots_held(&ledger), 0);
    }

    /// INT-08 with the integration item: a continuation under a re-issued grant releases
    /// the old slot before holding its own, so one slot serves the whole transfer, whether
    /// it was stopped by revocation or interrupted; a refused continuation holds none.
    #[test]
    fn a_continuation_releases_the_old_slot_before_holding_its_own() {
        let (world, ledger, budget, gate) = slot_world(1);
        let fields = download("op-revoked");
        let mut session = gate
            .open(&world.seal(fields.clone()), &download_connection())
            .unwrap();
        let first = ledger_id(&budget, &session);
        move_verified(&world, &mut session, "op-revoked", 0, 40);
        world.authority.revoke(&parent());
        assert!(matches!(session.poll(), TransferStatus::Stopped(_)));
        assert_eq!(slots_held(&ledger), 0);

        world.authority.grant(&parent(), EPOCH_5, at(24 * HOUR));
        let mut wider = fields.clone();
        wider.epoch = EPOCH_5;
        wider.budget_bytes = 151;
        assert!(matches!(
            session.retry_with_grant(&world.seal(wider), &download_connection()),
            Err(TransferRefusal::RetryWidens { .. })
        ));
        assert_eq!(session.reservation(), None);
        assert_eq!(slots_held(&ledger), 0);

        let mut reissued = fields;
        reissued.epoch = EPOCH_5;
        session
            .retry_with_grant(&world.seal(reissued), &download_connection())
            .unwrap();
        let second = ledger_id(&budget, &session);
        assert_ne!(first, second);
        {
            let ledger = lock(&ledger);
            assert_eq!(ledger.open_reservations().count(), 1);
            let record = ledger.reservation(second).unwrap();
            assert_eq!(
                record.current(),
                &Amounts::new().storage_quota_bytes(110).network_slots(1)
            );
            assert_eq!(record.provenance().retry_number, 1);
            assert_eq!(record.provenance().operation, operation("op-revoked"));
            assert_eq!(ledger.reserved(NETWORK), 1);
        }
        move_verified(&world, &mut session, "op-revoked", 40, 80);
        move_verified(&world, &mut session, "op-revoked", 80, 100);
        session.finish().unwrap();
        assert_eq!(slots_held(&ledger), 0);

        // An interrupted transfer still holds its reservation; the continuation swaps it
        // for its own, which the one slot allows only because the old one goes first.
        let mut fields = download("op-interrupted");
        fields.epoch = EPOCH_5;
        let mut interrupted = gate
            .open(&world.seal(fields.clone()), &download_connection())
            .unwrap();
        let old = ledger_id(&budget, &interrupted);
        interrupted.interrupt().unwrap();
        assert_eq!(slots_held(&ledger), 1);
        let epoch_6 = EPOCH_5.next().unwrap();
        world.authority.grant(&parent(), epoch_6, at(24 * HOUR));
        let mut reissued = fields;
        reissued.epoch = epoch_6;
        interrupted
            .retry_with_grant(&world.seal(reissued), &download_connection())
            .unwrap();
        let new = ledger_id(&budget, &interrupted);
        assert_ne!(old, new);
        assert!(lock(&ledger).reservation(old).is_none());
        assert_eq!(slots_held(&ledger), 1);
        interrupted.cancel();
        assert_eq!(slots_held(&ledger), 0);
    }

    /// Decision: the slot is in the same reservation as the bytes, so after a stop it
    /// counts until the stop's settle time, when the last chunk that may still be moving
    /// is past its deadline (INT-02: no false free capacity). A continuation while those
    /// chunks settle gets the slot refusal and holds nothing; once they have settled it
    /// holds the slot.
    #[test]
    fn the_old_slot_counts_until_the_stops_settle_time() {
        let (world, ledger, budget, gate) = slot_world(1);
        let fields = download("op-revoked");
        let mut session = gate
            .open(&world.seal(fields.clone()), &download_connection())
            .unwrap();
        let old = ledger_id(&budget, &session);
        let _in_flight = session.admit(&object("op-revoked"), range(0, 40)).unwrap();
        world.advance(SECOND);
        world.authority.revoke(&parent());
        let settled_by = match session.poll() {
            TransferStatus::Stopped(record) => record.settled_by,
            other => panic!("{other:?}"),
        };
        assert_eq!(settled_by, at(10 * SECOND));
        {
            let ledger = lock(&ledger);
            assert_eq!(
                ledger.reservation(old).map(|record| record.state()),
                Some(ReservationState::Releasing)
            );
            assert_eq!(ledger.reserved(NETWORK), 1);
            assert_eq!(ledger.reserved(STORAGE), 150);
        }
        world.authority.grant(&parent(), EPOCH_5, at(24 * HOUR));
        let mut reissued = fields;
        reissued.epoch = EPOCH_5;
        let sealed = world.seal(reissued);
        assert_eq!(
            session.retry_with_grant(&sealed, &download_connection()),
            Err(slot_refusal(SlotLimit::HostCapacity, true))
        );
        assert!(matches!(session.status(), TransferStatus::Stopped(_)));
        assert_eq!(session.reservation(), None);
        assert_eq!(session.attempt(), 1);

        world.advance(10 * SECOND);
        assert_eq!(budget.settle_due(), 1);
        assert_eq!(slots_held(&ledger), 0);
        session
            .retry_with_grant(&sealed, &download_connection())
            .unwrap();
        assert_eq!(session.attempt(), 2);
        assert_eq!(slots_held(&ledger), 1);
        assert_eq!(
            session.reservation().map(|held| held.reserved_bytes),
            Some(110)
        );
    }

    /// An interrupted transfer whose continuation is refused for a slot holds nothing
    /// until a retry reserves again, and never moves a byte without a reservation: the
    /// re-issued grant is presented again once the slot frees, and a plain retry reserves
    /// too (shown with the fake authority reporting the original epoch again, which the
    /// coordinator never does).
    #[test]
    fn a_refused_continuation_holds_nothing_until_a_retry_reserves_again() {
        let (world, ledger, budget, gate) = slot_world(1);
        let fields = download("op-interrupted");
        let mut session = gate
            .open(&world.seal(fields.clone()), &download_connection())
            .unwrap();
        let old = ledger_id(&budget, &session);
        let _lost = session
            .admit(&object("op-interrupted"), range(0, 40))
            .unwrap();
        world.advance(SECOND);
        session.interrupt().unwrap();
        assert_eq!(slots_held(&ledger), 1);
        world.authority.grant(&parent(), EPOCH_5, at(24 * HOUR));
        let mut reissued = fields;
        reissued.epoch = EPOCH_5;
        let sealed = world.seal(reissued);
        assert_eq!(
            session.retry_with_grant(&sealed, &download_connection()),
            Err(slot_refusal(SlotLimit::HostCapacity, true))
        );
        assert_eq!(session.status(), &TransferStatus::Interrupted);
        assert_eq!(session.reservation(), None);
        assert_eq!(
            lock(&ledger).reservation(old).map(|record| record.state()),
            Some(ReservationState::Releasing)
        );
        world.advance(10 * SECOND);
        assert_eq!(budget.settle_due(), 1);
        session
            .retry_with_grant(&sealed, &download_connection())
            .unwrap();
        assert_eq!(session.status(), &TransferStatus::Active);
        assert_eq!(
            session.reservation().map(|held| held.reserved_bytes),
            Some(110)
        );
        assert_eq!(slots_held(&ledger), 1);
        let permit = session
            .admit(&object("op-interrupted"), range(40, 80))
            .unwrap();
        session.deliver(permit).unwrap();
        session.cancel();
        assert_eq!(slots_held(&ledger), 0);

        let fields = download("op-plain");
        let mut session = gate
            .open(
                &world.seal(EnvelopeFields {
                    epoch: EPOCH_5,
                    ..fields.clone()
                }),
                &download_connection(),
            )
            .unwrap();
        let _lost = session.admit(&object("op-plain"), range(0, 40)).unwrap();
        world.advance(SECOND);
        session.interrupt().unwrap();
        let epoch_6 = EPOCH_5.next().unwrap();
        world.authority.grant(&parent(), epoch_6, at(24 * HOUR));
        let sealed = world.seal(EnvelopeFields {
            epoch: epoch_6,
            ..fields
        });
        assert_eq!(
            session.retry_with_grant(&sealed, &download_connection()),
            Err(slot_refusal(SlotLimit::HostCapacity, true))
        );
        assert_eq!(session.reservation(), None);
        world.authority.grant(&parent(), EPOCH_5, at(24 * HOUR));
        assert_eq!(
            session.retry(&download_connection()),
            Err(slot_refusal(SlotLimit::HostCapacity, true))
        );
        assert_eq!(session.status(), &TransferStatus::Interrupted);
        world.advance(10 * SECOND);
        assert_eq!(budget.settle_due(), 1);
        session.retry(&download_connection()).unwrap();
        assert_eq!(session.attempt(), 2);
        let id = ledger_id(&budget, &session);
        {
            let ledger = lock(&ledger);
            let record = ledger.reservation(id).unwrap();
            assert_eq!(
                record.current(),
                &Amounts::new().storage_quota_bytes(110).network_slots(1)
            );
            assert_eq!(record.provenance().retry_number, 1);
        }
        let permit = session.admit(&object("op-plain"), range(40, 80)).unwrap();
        session.deliver(permit).unwrap();
        session.cancel();
        assert_eq!(slots_held(&ledger), 0);
    }

    /// INT-02: the parent's cancellation in the ledger withdraws the slot with the bytes,
    /// and the transfer stops at its next chunk, for a download and for an upload whose
    /// reservation holds the slot alone.
    #[test]
    fn the_parents_cancellation_withdraws_the_slot_and_stops_the_transfer() {
        let (world, ledger, _budget, gate) = slot_world(2);
        let mut download = open_download(&world, &gate, "op-download-2");
        let upload = upload_fields();
        let mut upload_session = gate
            .open(&world.seal(upload.clone()), &connection_for(&upload))
            .unwrap();
        assert_eq!(slots_held(&ledger), 2);
        let report = lock(&ledger).cancel_execution(&parent());
        assert_eq!(report.pending.len(), 2);
        assert_eq!(
            download
                .admit(&object("op-download-2"), range(0, 40))
                .unwrap_err(),
            TransferRefusal::Stopped {
                reason: StopReason::ReservationWithdrawn
            }
        );
        assert_eq!(
            upload_session
                .admit(&object("private-weights"), range(0, MIB))
                .unwrap_err(),
            TransferRefusal::Stopped {
                reason: StopReason::ReservationWithdrawn
            }
        );
        let ledger = lock(&ledger);
        assert_eq!(ledger.reserved(NETWORK), 0);
        assert_eq!(ledger.reserved(STORAGE), 0);
        assert_eq!(ledger.open_reservations().count(), 0);
    }

    /// The T14 follow-up decision with the integration item: uploads and peer sends
    /// reserve no ledger bytes, since the envelope's own budget bounds them, and hold
    /// their slot alone, charged with the transfer's provenance.
    #[test]
    fn uploads_and_peer_sends_hold_a_slot_and_reserve_no_ledger_bytes() {
        let (world, ledger, budget, gate) = slot_world(4);
        let upload = upload_fields();
        let mut session = gate
            .open(&world.seal(upload.clone()), &connection_for(&upload))
            .unwrap();
        let id = ledger_id(&budget, &session);
        {
            let ledger = lock(&ledger);
            let record = ledger.reservation(id).unwrap();
            assert_eq!(record.current(), &Amounts::new().network_slots(1));
            assert_eq!(record.provenance().requester, Requester::Transfer);
            assert_eq!(record.provenance().purpose, CostPurpose::Transfer);
            assert_eq!(record.provenance().operation, operation("op-upload"));
            assert_eq!(ledger.reserved(STORAGE), 0);
            assert_eq!(ledger.reserved(NETWORK), 1);
        }
        assert_eq!(
            session.reservation().map(|held| held.reserved_bytes),
            Some(2 * GIB)
        );
        let permit = session
            .admit(&object("private-weights"), range(0, MIB))
            .unwrap();
        session.deliver(permit).unwrap();
        {
            let ledger = lock(&ledger);
            let record = ledger.reservation(id).unwrap();
            let charged = record.observation_from(SourceClass::HostProbe).unwrap();
            assert_eq!(charged.in_use, Amounts::new().network_slots(1));
            assert_eq!(ledger.reserved(STORAGE), 0);
        }
        session.cancel();
        assert_eq!(slots_held(&ledger), 0);

        let peer_fields = EnvelopeFields {
            operation: operation("op-peer"),
            direction: Direction::Peer,
            source: peer("donor"),
            credential: None,
            ..download_fields()
        };
        let session = gate
            .open(
                &world.seal(peer_fields.clone()),
                &connection_for(&peer_fields),
            )
            .unwrap();
        let id = ledger_id(&budget, &session);
        {
            let ledger = lock(&ledger);
            assert_eq!(
                ledger.reservation(id).unwrap().current(),
                &Amounts::new().network_slots(1)
            );
            assert_eq!(ledger.reserved(STORAGE), 0);
        }
        drop(session);
        assert_eq!(slots_held(&ledger), 0);
    }

    /// A transfer that is not moving bytes still holds its slot: just opened, or
    /// interrupted and waiting for a retry, which continues under the same reservation.
    #[test]
    fn a_transfer_waiting_for_bytes_holds_its_slot() {
        let (world, ledger, budget, gate) = slot_world(1);
        let mut session = open_download(&world, &gate, "op-waiting");
        let id = ledger_id(&budget, &session);
        assert_eq!(session.in_flight_bytes(), 0);
        assert_eq!(slots_held(&ledger), 1);
        let next = || {
            gate.open(&world.seal(download("op-next")), &download_connection())
                .map(|_| ())
        };
        assert_eq!(next(), Err(slot_refusal(SlotLimit::HostCapacity, true)));

        let _lost = session.admit(&object("op-waiting"), range(0, 40)).unwrap();
        session.interrupt().unwrap();
        assert_eq!(session.status(), &TransferStatus::Interrupted);
        assert_eq!(ledger_id(&budget, &session), id);
        assert_eq!(slots_held(&ledger), 1);
        assert_eq!(next(), Err(slot_refusal(SlotLimit::HostCapacity, true)));

        world.advance(10 * SECOND);
        session.retry(&download_connection()).unwrap();
        assert_eq!(ledger_id(&budget, &session), id);
        assert_eq!(lock(&ledger).open_reservations().count(), 1);
        move_all(&world, &mut session, "op-waiting");
        session.finish().unwrap();
        assert_eq!(slots_held(&ledger), 0);
        assert_eq!(next(), Ok(()));
    }

    /// A continuation with no budget left still holds its slot: its reservation holds the
    /// slot alone, and bytes stay refused by the budget.
    #[test]
    fn a_continuation_with_no_budget_left_still_holds_its_slot() {
        let (world, ledger, budget, gate) = slot_world(1);
        let mut fields = download("op-spent");
        fields.budget_bytes = 100;
        let mut session = gate
            .open(&world.seal(fields.clone()), &download_connection())
            .unwrap();
        move_verified(&world, &mut session, "op-spent", 0, 40);
        let _lost = session.admit(&object("op-spent"), range(40, 80)).unwrap();
        session.interrupt().unwrap();
        world.advance(10 * SECOND);
        session.retry(&download_connection()).unwrap();
        let _lost = session.admit(&object("op-spent"), range(80, 100)).unwrap();
        session.interrupt().unwrap();
        assert_eq!(session.used_bytes(), 100);
        world.advance(10 * SECOND);
        world.authority.revoke(&parent());
        assert!(matches!(session.poll(), TransferStatus::Stopped(_)));
        assert_eq!(slots_held(&ledger), 0);

        world.authority.grant(&parent(), EPOCH_5, at(24 * HOUR));
        fields.epoch = EPOCH_5;
        session
            .retry_with_grant(&world.seal(fields), &download_connection())
            .unwrap();
        assert_eq!(session.remaining_budget_bytes(), 0);
        assert_eq!(
            session.reservation().map(|held| held.reserved_bytes),
            Some(0)
        );
        let id = ledger_id(&budget, &session);
        {
            let ledger = lock(&ledger);
            let record = ledger.reservation(id).unwrap();
            assert_eq!(record.current(), &Amounts::new().network_slots(1));
            assert_eq!(record.provenance().retry_number, 2);
            assert_eq!(ledger.reserved(NETWORK), 1);
            assert_eq!(ledger.reserved(STORAGE), 0);
        }
        assert!(matches!(
            session.admit(&object("op-spent"), range(40, 41)),
            Err(TransferRefusal::BudgetExhausted { .. })
        ));
        world.verify(
            session.envelope().fields(),
            &object("op-spent"),
            range(40, 100),
        );
        session.finish().unwrap();
        assert_eq!(slots_held(&ledger), 0);
    }

    /// `LedgerByteBudget::new` is unchanged: it holds no slot, reserves bytes alone and
    /// leaves the slot resource untouched, so existing callers see no change.
    #[test]
    fn the_adapter_without_the_slot_reserves_bytes_alone() {
        let (world, ledger, budget, gate) = adapter_world();
        assert!(!budget.holds_network_slot());
        let session = gate
            .open(&world.seal(download_fields()), &download_connection())
            .unwrap();
        let id = ledger_id(&budget, &session);
        {
            let ledger = lock(&ledger);
            assert_eq!(
                ledger.reservation(id).unwrap().current(),
                &Amounts::new().storage_quota_bytes(150)
            );
            assert_eq!(ledger.reserved(NETWORK), 0);
            assert_eq!(ledger.available(NETWORK), None);
        }
        drop(session);
        let (_, _, budget, _) = slot_world(1);
        assert!(budget.holds_network_slot());
        assert_eq!(EPOCH, AuthorizationEpoch::new(4));
    }

    /// Each slot refusal names network slots and its limit, says whether a retry can
    /// progress, and round-trips through serde with the resource that limited.
    #[test]
    fn slot_refusals_explain_themselves() {
        let cases = [
            (
                SlotLimit::HostCapacity,
                true,
                "retry once another transfer ends",
            ),
            (SlotLimit::HostObservation, true, "retry after a host probe"),
            (SlotLimit::TenantBudget, false, "retrying will not help"),
            (
                SlotLimit::ParentReservation,
                true,
                "retry once another transfer ends",
            ),
            (
                SlotLimit::OwnerReturnHold,
                true,
                "retry after the hold ends",
            ),
        ];
        for (limit, retry_can_progress, hint) in cases {
            let refusal = NetworkSlotRefusal {
                limit,
                retry_can_progress,
            };
            let text = refusal.to_string();
            assert!(
                text.starts_with("no network slot is free for the transfer: "),
                "{text}"
            );
            assert!(text.ends_with(hint), "{text}");
            assert_eq!(
                TransferRefusal::NetworkSlotRefused { refusal }.to_string(),
                text
            );
            assert_eq!(ReservationRefusal::NetworkSlot(refusal).to_string(), text);
        }
        let refusal = NetworkSlotRefusal {
            limit: SlotLimit::OwnerReturnHold,
            retry_can_progress: true,
        };
        let value = serde_json::to_value(ReservationRefusal::NetworkSlot(refusal)).unwrap();
        assert_eq!(
            value,
            json!({
                "resource": "network_slot",
                "refusal": { "limit": "owner_return_hold", "retry_can_progress": true }
            })
        );
        assert_eq!(
            serde_json::from_value::<ReservationRefusal>(value).unwrap(),
            ReservationRefusal::NetworkSlot(refusal)
        );
        let bytes = ByteBudgetRefusal {
            requested_bytes: 150,
            available_bytes: 100,
            retry_can_progress: true,
        };
        assert_eq!(
            ReservationRefusal::Bytes(bytes).to_string(),
            bytes.to_string()
        );
    }
}
