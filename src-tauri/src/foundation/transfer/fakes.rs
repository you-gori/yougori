//! Fake ports and fixtures for tests (CORE-05). The fakes keep their state in memory and
//! touch nothing on the host.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use super::endpoint::{Connection, CredentialRef, Direction, Endpoint};
use super::envelope::{EnvelopeFields, SealedEnvelope, StopBounds, TransferEnvelope, TransferKey};
use super::ports::{
    AuthorityPort, ByteBudgetPort, ByteBudgetRefusal, ByteReservation, ByteReservationRequest,
    ParentAuthority, ParentStatus, ProgressPort, ReservationWithdrawn, TransferPorts,
    TransferProgress, VerifiedExtentsPort,
};
use super::range::{ByteRange, RangeSet};
use super::scope::{ObjectGrant, TransferScope};
use super::session::TransferGate;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    digest, AuthorizationEpoch, ContentKey, ExecutionId, ManualClock, MonotonicTime, OperationId,
    TenantId,
};

pub const SECOND: Duration = Duration::from_secs(1);
pub const HOUR: Duration = Duration::from_secs(3_600);
pub const MIB: u64 = 1024 * 1024;
pub const GIB: u64 = 1024 * MIB;

/// The epoch the fake parent holds at the start.
pub const EPOCH: AuthorizationEpoch = AuthorizationEpoch::new(4);

/// The session of the test clock.
pub const SESSION: ClockSession = ClockSession::from_uuid(uuid::Uuid::from_u128(0x7140));

/// Another clock session, such as the one before a restart.
pub const OTHER_SESSION: ClockSession = ClockSession::from_uuid(uuid::Uuid::from_u128(0x7141));

pub fn at(since_start: Duration) -> MonotonicTime {
    MonotonicTime::ZERO.saturating_add(since_start)
}

pub fn object(name: &str) -> ContentKey {
    ContentKey::from_digest(digest("yougori/test/object/v1", &[name.as_bytes()]))
}

pub fn route(name: &str) -> Endpoint {
    Endpoint::NamedRoute {
        route: digest("yougori/test/route/v1", &[name.as_bytes()]),
    }
}

pub fn peer(name: &str) -> Endpoint {
    Endpoint::PeerHost {
        host: digest("yougori/test/peer/v1", &[name.as_bytes()]),
    }
}

pub fn credential(name: &str) -> CredentialRef {
    CredentialRef::from_digest(digest("yougori/test/credential/v1", &[name.as_bytes()]))
}

pub fn parent() -> ExecutionId {
    ExecutionId::new("exe-parent").unwrap()
}

pub fn tenant() -> TenantId {
    TenantId::new("tenant-a").unwrap()
}

pub fn operation(name: &str) -> OperationId {
    OperationId::new(name).unwrap()
}

pub fn range(start_bytes: u64, end_bytes: u64) -> ByteRange {
    ByteRange::new(start_bytes, end_bytes).unwrap()
}

pub fn test_key() -> TransferKey {
    TransferKey::from_bytes(&[7u8; 32]).unwrap()
}

/// A credentialed download of the 100-byte object "weights" from the route "model-hub"
/// into the host catalog under epoch 4: a 150-byte budget, 40 bytes in flight, 10 s per
/// chunk, expiring after an hour.
pub fn download_fields() -> EnvelopeFields {
    EnvelopeFields {
        operation: operation("op-download"),
        tenant: tenant(),
        parent: parent(),
        epoch: EPOCH,
        direction: Direction::Download,
        source: route("model-hub"),
        recipient: Endpoint::HostCatalog,
        credential: Some(credential("hub-token")),
        scope: TransferScope::single(object("weights"), ObjectGrant::whole(100).unwrap()),
        budget_bytes: 150,
        stop_bounds: StopBounds {
            max_in_flight_bytes: 40,
            max_chunk_duration: 10 * SECOND,
        },
        clock: SESSION,
        expires_at: at(HOUR),
    }
}

/// A private-weight upload of 2 GiB from the host catalog to the route
/// "partner-registry", with its own 2 GiB budget.
pub fn upload_fields() -> EnvelopeFields {
    EnvelopeFields {
        operation: operation("op-upload"),
        tenant: tenant(),
        parent: parent(),
        epoch: EPOCH,
        direction: Direction::Upload,
        source: Endpoint::HostCatalog,
        recipient: route("partner-registry"),
        credential: Some(credential("registry-token")),
        scope: TransferScope::single(
            object("private-weights"),
            ObjectGrant::whole(2 * GIB).unwrap(),
        ),
        budget_bytes: 2 * GIB,
        stop_bounds: StopBounds {
            max_in_flight_bytes: 256 * MIB,
            max_chunk_duration: 60 * SECOND,
        },
        clock: SESSION,
        expires_at: at(HOUR),
    }
}

pub fn download_connection() -> Connection {
    Connection {
        source: route("model-hub"),
        recipient: Endpoint::HostCatalog,
        credential: Some(credential("hub-token")),
    }
}

/// The connection that matches `fields` exactly.
pub fn connection_for(fields: &EnvelopeFields) -> Connection {
    Connection {
        source: fields.source.clone(),
        recipient: fields.recipient.clone(),
        credential: fields.credential,
    }
}

/// The coordinator's view of each parent (CORE-04). A parent it has no entry for is not
/// running.
#[derive(Default)]
pub struct FakeAuthority {
    statuses: Mutex<BTreeMap<ExecutionId, ParentStatus>>,
    calls: AtomicUsize,
}

impl FakeAuthority {
    /// The parent holds `epoch` until `expires_at` on the test clock session.
    pub fn grant(
        &self,
        parent: &ExecutionId,
        epoch: AuthorizationEpoch,
        expires_at: MonotonicTime,
    ) {
        self.set(
            parent,
            ParentAuthority {
                epoch,
                clock: SESSION,
                expires_at,
            },
        );
    }

    pub fn set(&self, parent: &ExecutionId, authority: ParentAuthority) {
        lock(&self.statuses).insert(parent.clone(), ParentStatus::Authorized { authority });
    }

    /// Revokes the parent as the coordinator does (S3.1, INT-02): its epoch advances and
    /// it holds no authority until granted again. Returns the new epoch.
    pub fn revoke(&self, parent: &ExecutionId) -> Option<AuthorizationEpoch> {
        let mut statuses = lock(&self.statuses);
        let status = statuses.get_mut(parent)?;
        let current = match *status {
            ParentStatus::Authorized { authority } => authority.epoch,
            ParentStatus::NoAuthority { current } => current,
            ParentStatus::NotRunning => return None,
        };
        let next = current.next()?;
        *status = ParentStatus::NoAuthority { current: next };
        Some(next)
    }

    /// The parent stops running.
    pub fn end(&self, parent: &ExecutionId) {
        lock(&self.statuses).remove(parent);
    }

    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl AuthorityPort for FakeAuthority {
    fn parent_status(&self, parent: &ExecutionId) -> ParentStatus {
        self.calls.fetch_add(1, Ordering::SeqCst);
        lock(&self.statuses)
            .get(parent)
            .copied()
            .unwrap_or(ParentStatus::NotRunning)
    }
}

/// A ledger with one capacity for transfer reservations (CORE-03).
pub struct FakeByteLedger {
    capacity_bytes: u64,
    state: Mutex<LedgerState>,
}

#[derive(Default)]
struct LedgerState {
    next_token: u64,
    held: BTreeMap<u64, u64>,
    withdrawn: Vec<u64>,
    requests: Vec<ByteReservationRequest>,
    charges: Vec<(u64, u64)>,
    releases: Vec<(ByteReservation, u64)>,
    settle_times: Vec<MonotonicTime>,
}

impl FakeByteLedger {
    pub fn new(capacity_bytes: u64) -> Self {
        Self {
            capacity_bytes,
            state: Mutex::new(LedgerState::default()),
        }
    }

    pub fn held_bytes(&self) -> u64 {
        lock(&self.state).held.values().sum()
    }

    pub fn requests(&self) -> Vec<ByteReservationRequest> {
        lock(&self.state).requests.clone()
    }

    /// Every release, with the bytes the transfer reported used.
    pub fn releases(&self) -> Vec<(ByteReservation, u64)> {
        lock(&self.state).releases.clone()
    }

    /// When each released reservation's chunks had all settled, in release order.
    pub fn settle_times(&self) -> Vec<MonotonicTime> {
        lock(&self.state).settle_times.clone()
    }

    /// Every charge: the reservation token and the bytes used under it.
    pub fn charges(&self) -> Vec<(u64, u64)> {
        lock(&self.state).charges.clone()
    }

    /// Withdraws a reservation, as the ledger does when it cancels the parent's
    /// reservations on revocation.
    pub fn withdraw(&self, token: u64) {
        lock(&self.state).withdrawn.push(token);
    }
}

impl ByteBudgetPort for FakeByteLedger {
    fn reserve(
        &self,
        request: &ByteReservationRequest,
    ) -> Result<ByteReservation, ByteBudgetRefusal> {
        let mut state = lock(&self.state);
        state.requests.push(request.clone());
        let held: u64 = state.held.values().sum();
        let available_bytes = self.capacity_bytes.saturating_sub(held);
        if request.requested_bytes > available_bytes {
            return Err(ByteBudgetRefusal {
                requested_bytes: request.requested_bytes,
                available_bytes,
                retry_can_progress: request.requested_bytes <= self.capacity_bytes,
            });
        }
        state.next_token += 1;
        let token = state.next_token;
        state.held.insert(token, request.requested_bytes);
        Ok(ByteReservation {
            token,
            reserved_bytes: request.requested_bytes,
        })
    }

    fn charge(
        &self,
        reservation: ByteReservation,
        used_bytes: u64,
    ) -> Result<(), ReservationWithdrawn> {
        let mut state = lock(&self.state);
        if state.withdrawn.contains(&reservation.token)
            || !state.held.contains_key(&reservation.token)
        {
            return Err(ReservationWithdrawn);
        }
        state.charges.push((reservation.token, used_bytes));
        Ok(())
    }

    fn release(&self, reservation: ByteReservation, used_bytes: u64, settled_by: MonotonicTime) {
        let mut state = lock(&self.state);
        state.held.remove(&reservation.token);
        state.releases.push((reservation, used_bytes));
        state.settle_times.push(settled_by);
    }
}

/// The catalog's verified extents per tenant, recipient and object (CORE-02).
#[derive(Default)]
pub struct FakeExtents {
    verified: Mutex<BTreeMap<(TenantId, Endpoint, ContentKey), RangeSet>>,
}

impl FakeExtents {
    /// The catalog verified `range` of `object` at `recipient` for `tenant`.
    pub fn mark_verified(
        &self,
        tenant: &TenantId,
        recipient: &Endpoint,
        object: &ContentKey,
        range: ByteRange,
    ) {
        lock(&self.verified)
            .entry((tenant.clone(), recipient.clone(), *object))
            .or_default()
            .insert(range);
    }
}

impl VerifiedExtentsPort for FakeExtents {
    fn verified(
        &self,
        tenant: &TenantId,
        _parent: &ExecutionId,
        recipient: &Endpoint,
        object: &ContentKey,
    ) -> RangeSet {
        lock(&self.verified)
            .get(&(tenant.clone(), recipient.clone(), *object))
            .cloned()
            .unwrap_or_default()
    }
}

/// Records every progress event (CORE-06).
#[derive(Default)]
pub struct FakeProgress {
    events: Mutex<Vec<TransferProgress>>,
}

impl FakeProgress {
    pub fn events(&self) -> Vec<TransferProgress> {
        lock(&self.events).clone()
    }

    pub fn last(&self) -> Option<TransferProgress> {
        lock(&self.events).last().cloned()
    }
}

impl ProgressPort for FakeProgress {
    fn emit(&self, event: TransferProgress) {
        lock(&self.events).push(event);
    }
}

/// A gate over fresh fakes: the parent holds epoch 4 for a day, the ledger has 1 TiB and
/// the clock starts at zero.
pub struct World {
    pub clock: Arc<ManualClock>,
    pub authority: Arc<FakeAuthority>,
    pub ledger: Arc<FakeByteLedger>,
    pub extents: Arc<FakeExtents>,
    pub progress: Arc<FakeProgress>,
    /// The host's transfer key; the gate was made from a clone of it.
    pub key: TransferKey,
    pub gate: TransferGate,
}

impl World {
    pub fn new() -> Self {
        Self::with_ledger(1024 * GIB)
    }

    pub fn with_ledger(capacity_bytes: u64) -> Self {
        let clock = Arc::new(ManualClock::new(MonotonicTime::ZERO));
        let authority = Arc::new(FakeAuthority::default());
        authority.grant(&parent(), EPOCH, at(24 * HOUR));
        let ledger = Arc::new(FakeByteLedger::new(capacity_bytes));
        let extents = Arc::new(FakeExtents::default());
        let progress = Arc::new(FakeProgress::default());
        let ports = TransferPorts {
            clock: clock.clone(),
            clock_session: SESSION,
            authority: authority.clone(),
            budget: ledger.clone(),
            extents: extents.clone(),
            progress: progress.clone(),
        };
        let key = test_key();
        Self {
            clock,
            authority,
            ledger,
            extents,
            progress,
            gate: TransferGate::new(key.clone(), ports),
            key,
        }
    }

    pub fn seal(&self, fields: EnvelopeFields) -> SealedEnvelope {
        test_key().seal(TransferEnvelope::new(fields).unwrap())
    }

    pub fn advance(&self, by: Duration) {
        self.clock.advance(by);
    }

    /// The catalog verifies `range` of `object` at the recipient of `fields`.
    pub fn verify(&self, fields: &EnvelopeFields, object: &ContentKey, range: ByteRange) {
        self.extents
            .mark_verified(&fields.tenant, &fields.recipient, object, range);
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
