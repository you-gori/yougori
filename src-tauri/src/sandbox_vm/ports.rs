//! The production ports of the VM service (module docs in `mod.rs`): the one bundle of
//! types the service is generic over, and the CORE-05 transfer ports of its file channels.
//!
//! - [`ProductionPorts`]: the host's clock (the ledger's own), the QEMU host of the
//!   platform (`WindowsQemuHost`, or `LinuxQemuHost` on Linux), QMP
//!   over the private socket, the runtime layout, the shared CORE-03 ledger, the durable
//!   spooled audit stream, the non-blocking link socket connector and the host's process
//!   table.
//! - [`GuestBodies`]: a guest create or write whose content does not fit one file-channel
//!   message is a body (`sandbox::guest_files`), and moves as a CORE-05 transfer. Its
//!   issuer grants exactly the declared body (object, length, guest end, parent) bound to
//!   the parent sandbox's current authorization epoch, never past its authority; the
//!   authority port answers from the VM service's own word on each sandbox
//!   (`VmService::authorities`, the CORE-04 coordinator's rule), refreshed by the engine
//!   after every launch, stop and revocation and every two seconds, since the gate runs
//!   inside the service and may not take its lock (a stopped or revoked sandbox's file
//!   channel is closed by the service itself, which ends its bodies); the byte budget holds
//!   each sandbox within [`BODY_BYTES_PER_SANDBOX`] reserved at once, counting a released
//!   reservation until its last chunk settles; the channel verifies extents itself, and
//!   progress is counted and dropped.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use ring::rand::{SecureRandom, SystemRandom};

use crate::foundation::coordination::SharedLedger;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    Clock, ContentKey, ExecutionId, MonotonicTime, SystemClock, TenantId,
};
use crate::foundation::transfer::{
    AuthorityPort, ByteBudgetPort, ByteBudgetRefusal, ByteReservation, ByteReservationRequest,
    Direction, Endpoint, EnvelopeFields, ObjectGrant, ParentStatus, ProgressPort, RangeSet,
    ReservationWithdrawn, SealedEnvelope, StopBounds, TransferEnvelope, TransferKey,
    TransferPorts, TransferProgress, TransferScope, VerifiedExtentsPort,
};
use crate::sandbox::audit::{DurableSegments, FileSpool, NoAnchor};
use crate::sandbox::guest_files::{AuthorityRefusal, BodyAuthority, BodyRequest, BodyTransfers};
#[cfg(target_os = "linux")]
use crate::sandbox::qemu_host::LinuxQemuHost as PlatformQemuHost;
#[cfg(windows)]
use crate::sandbox::qemu_host::WindowsQemuHost as PlatformQemuHost;
use crate::sandbox::qemu_host::{LinkSocketConnector, QmpMonitor, RuntimeLayout, UnixSocketConnect};
use crate::sandbox::vm_service::{HostProcessTable, VmPorts};

/// The ports of the production service.
pub struct ProductionPorts;

impl VmPorts for ProductionPorts {
    #[cfg(windows)]
    type Backend = crate::sandbox::hcs::runtime::Runtime;
    #[cfg(not(windows))]
    type Backend = crate::sandbox::qemu::QemuBackend<PlatformQemuHost, QmpMonitor<UnixSocketConnect>, RuntimeLayout, crate::sandbox::vm_service::SharedLedgerView<SystemClock>>;
    type Clock = SystemClock;
    type Host = PlatformQemuHost;
    type Monitor = QmpMonitor<UnixSocketConnect>;
    type Layout = RuntimeLayout;
    type Ledger = SharedLedger<SystemClock>;
    type Segments = DurableSegments;
    type Spool = FileSpool;
    type Anchor = NoAnchor;
    type Connector = LinkSocketConnector;
    type Processes = HostProcessTable;
}

/// The most bytes of guest bodies one sandbox may hold reserved at once: eight of the
/// largest the file channel carries (`file_protocol` `DEFAULT_MAX_BUFFERED_BYTES`).
pub const BODY_BYTES_PER_SANDBOX: u64 = 64 << 20;
/// How long a body grant lasts; the parent's own authority ends it earlier.
const BODY_GRANT_FOR: Duration = Duration::from_secs(10 * 60);
/// A body's stop bounds: bytes admitted and not yet delivered at once, and the longest one
/// chunk may take.
const BODY_IN_FLIGHT_BYTES: u64 = 1 << 20;
const BODY_CHUNK_WITHIN: Duration = Duration::from_secs(30);

/// The CORE-05 ports and the body issuer of the service's file channels (module notes).
pub struct GuestBodies {
    clock: SystemClock,
    session: ClockSession,
    key: TransferKey,
    /// Each sandbox's authority as the service last answered it.
    authorities: Mutex<BTreeMap<ExecutionId, ParentStatus>>,
    budget: Mutex<BodyBudget>,
    /// Progress events taken (dropped: nothing reads body progress yet).
    progress: AtomicU64,
}

/// The reservations of the byte budget, by token: their parent, their bytes and, once
/// released, when their last chunk settles.
#[derive(Default)]
struct BodyBudget {
    next: u64,
    held: BTreeMap<u64, Reserved>,
}

struct Reserved {
    parent: ExecutionId,
    bytes: u64,
    settles_at: Option<MonotonicTime>,
}

impl BodyBudget {
    /// Drops the reservations whose last chunk settled by `now`.
    fn settle(&mut self, now: MonotonicTime) {
        self.held
            .retain(|_, reserved| reserved.settles_at.is_none_or(|at| at > now));
    }

    /// What `parent`'s reservations hold now.
    fn held_by(&mut self, parent: &ExecutionId, now: MonotonicTime) -> u64 {
        self.settle(now);
        self.held
            .values()
            .filter(|reserved| reserved.parent == *parent)
            .map(|reserved| reserved.bytes)
            .sum()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl GuestBodies {
    /// The ports of one run of the service, on its clock and clock session, with a fresh
    /// transfer key from the OS generator (nothing of an earlier run is honoured). No
    /// sandbox holds authority until [`GuestBodies::refresh`] says so.
    pub fn new(clock: SystemClock, session: ClockSession) -> Result<Arc<Self>, String> {
        let mut secret = [0u8; 32];
        SystemRandom::new()
            .fill(&mut secret)
            .map_err(|_| "The OS random generator gave no transfer key.".to_owned())?;
        let key = TransferKey::from_bytes(&secret).map_err(|error| error.to_string())?;
        secret.fill(0);
        Ok(Arc::new(Self {
            clock,
            session,
            key,
            authorities: Mutex::new(BTreeMap::new()),
            budget: Mutex::new(BodyBudget::default()),
            progress: AtomicU64::new(0),
        }))
    }

    /// Replaces every sandbox's authority with the service's answer
    /// (`VmService::authorities`); a sandbox it does not name is not running.
    pub fn refresh(&self, authorities: Vec<(ExecutionId, ParentStatus)>) {
        *lock(&self.authorities) = authorities.into_iter().collect();
    }

    /// The body transfers the service's file channels move guest bodies with.
    pub fn transfers(self: &Arc<Self>) -> BodyTransfers {
        BodyTransfers {
            key: self.key.clone(),
            ports: TransferPorts {
                clock: Arc::new(self.clock) as Arc<dyn Clock>,
                clock_session: self.session,
                authority: Arc::clone(self) as Arc<dyn AuthorityPort>,
                budget: Arc::clone(self) as Arc<dyn ByteBudgetPort>,
                extents: Arc::clone(self) as Arc<dyn VerifiedExtentsPort>,
                progress: Arc::clone(self) as Arc<dyn ProgressPort>,
            },
            authority: Arc::clone(self) as Arc<dyn BodyAuthority>,
        }
    }

    /// The bytes reserved and the progress events taken, for the status.
    pub fn view(&self) -> serde_json::Value {
        let mut budget = lock(&self.budget);
        budget.settle(self.clock.now());
        serde_json::json!({
            "reservations": budget.held.len(),
            "reserved_bytes": budget.held.values().map(|reserved| reserved.bytes).sum::<u64>(),
            "per_sandbox_limit_bytes": BODY_BYTES_PER_SANDBOX,
            "progress_events": self.progress.load(Ordering::Relaxed),
        })
    }
}

impl fmt::Debug for GuestBodies {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GuestBodies")
            .field("session", &self.session)
            .finish_non_exhaustive()
    }
}

impl AuthorityPort for GuestBodies {
    fn parent_status(&self, parent: &ExecutionId) -> ParentStatus {
        lock(&self.authorities)
            .get(parent)
            .copied()
            .unwrap_or(ParentStatus::NotRunning)
    }
}

impl ByteBudgetPort for GuestBodies {
    /// Reserves within the parent's [`BODY_BYTES_PER_SANDBOX`], counting released
    /// reservations until their last chunk settles.
    fn reserve(
        &self,
        request: &ByteReservationRequest,
    ) -> Result<ByteReservation, ByteBudgetRefusal> {
        let now = self.clock.now();
        let mut budget = lock(&self.budget);
        let held = budget.held_by(&request.parent, now);
        let available = BODY_BYTES_PER_SANDBOX.saturating_sub(held);
        if request.requested_bytes > available {
            return Err(ByteBudgetRefusal {
                requested_bytes: request.requested_bytes,
                available_bytes: available,
                retry_can_progress: request.requested_bytes <= BODY_BYTES_PER_SANDBOX,
            });
        }
        budget.next = budget.next.saturating_add(1);
        let token = budget.next;
        budget.held.insert(
            token,
            Reserved {
                parent: request.parent.clone(),
                bytes: request.requested_bytes,
                settles_at: None,
            },
        );
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
        match lock(&self.budget).held.get(&reservation.token) {
            Some(reserved) if reserved.settles_at.is_none() && used_bytes <= reserved.bytes => {
                Ok(())
            }
            _ => Err(ReservationWithdrawn),
        }
    }

    fn release(&self, reservation: ByteReservation, _used_bytes: u64, settled_by: MonotonicTime) {
        if let Some(reserved) = lock(&self.budget).held.get_mut(&reservation.token) {
            reserved.settles_at = Some(settled_by);
        }
    }
}

/// The channel answers verified extents from its own record (`guest_files::body`); this
/// port is replaced there and verifies nothing itself.
impl VerifiedExtentsPort for GuestBodies {
    fn verified(
        &self,
        _tenant: &TenantId,
        _parent: &ExecutionId,
        _recipient: &Endpoint,
        _object: &ContentKey,
    ) -> RangeSet {
        RangeSet::default()
    }
}

impl ProgressPort for GuestBodies {
    fn emit(&self, _event: TransferProgress) {
        self.progress.fetch_add(1, Ordering::Relaxed);
    }
}

impl BodyAuthority for GuestBodies {
    /// A grant for exactly the declared body (its object, length, guest end and parent),
    /// bound to the parent's current authorization epoch and ending with its authority:
    /// a sandbox the service does not show authorized gets none.
    fn authorize(&self, request: &BodyRequest) -> Result<SealedEnvelope, AuthorityRefusal> {
        let ParentStatus::Authorized { authority } = self.parent_status(&request.parent) else {
            return Err(AuthorityRefusal::NotPermitted);
        };
        if authority.clock != self.session {
            return Err(AuthorityRefusal::Unavailable);
        }
        let grant = ObjectGrant::whole(request.length_bytes)
            .map_err(|_| AuthorityRefusal::NotPermitted)?;
        let fields = EnvelopeFields {
            operation: request.operation.clone(),
            tenant: request.tenant.clone(),
            parent: request.parent.clone(),
            epoch: authority.epoch,
            direction: Direction::Download,
            source: request.source.clone(),
            recipient: request.recipient.clone(),
            credential: None,
            scope: TransferScope::single(request.object, grant),
            budget_bytes: request.length_bytes,
            stop_bounds: StopBounds {
                max_in_flight_bytes: BODY_IN_FLIGHT_BYTES,
                max_chunk_duration: BODY_CHUNK_WITHIN,
            },
            clock: self.session,
            expires_at: self
                .clock
                .now()
                .saturating_add(BODY_GRANT_FOR)
                .min(authority.expires_at),
        };
        let envelope =
            TransferEnvelope::new(fields).map_err(|_| AuthorityRefusal::NotPermitted)?;
        Ok(self.key.seal(envelope))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::{AuthorizationEpoch, OperationId};
    use crate::foundation::transfer::ParentAuthority;

    fn request(parent: &ExecutionId, bytes: u64) -> ByteReservationRequest {
        ByteReservationRequest {
            tenant: TenantId::new("local").unwrap(),
            parent: parent.clone(),
            operation: OperationId::generate(),
            direction: Direction::Download,
            requested_bytes: bytes,
            retry_number: 0,
        }
    }

    /// PROVES the ports answer from the service's last word on each sandbox: none is
    /// running before a refresh, an authorized one is reported as the service said, and
    /// the byte budget holds each sandbox within its own limit, counting a released
    /// reservation until its last chunk settles.
    #[test]
    fn the_body_ports_follow_the_service_and_bound_each_sandbox() {
        let clock = SystemClock::new();
        let session = ClockSession::generate();
        let bodies = GuestBodies::new(clock, session).unwrap();
        let parent = ExecutionId::generate();
        let other = ExecutionId::generate();
        assert_eq!(bodies.parent_status(&parent), ParentStatus::NotRunning);
        let authority = ParentAuthority {
            epoch: AuthorizationEpoch::new(3),
            clock: session,
            expires_at: clock.now().saturating_add(Duration::from_secs(60)),
        };
        bodies.refresh(vec![(parent.clone(), ParentStatus::Authorized { authority })]);
        assert_eq!(
            bodies.parent_status(&parent),
            ParentStatus::Authorized { authority }
        );
        assert_eq!(bodies.parent_status(&other), ParentStatus::NotRunning);
        let first = bodies
            .reserve(&request(&parent, BODY_BYTES_PER_SANDBOX - 10))
            .unwrap();
        assert!(bodies.charge(first, 100).is_ok());
        let refused = bodies.reserve(&request(&parent, 11)).unwrap_err();
        assert_eq!(refused.available_bytes, 10);
        assert!(
            bodies.reserve(&request(&other, 11)).is_ok(),
            "another sandbox has its own budget"
        );
        // Released with chunks still moving: still counted until they settle.
        bodies.release(first, 100, clock.now().saturating_add(Duration::from_secs(3600)));
        assert!(bodies.reserve(&request(&parent, 11)).is_err());
        assert!(
            bodies.charge(first, 1).is_err(),
            "a released reservation is withdrawn"
        );
        let text = format!("{bodies:?}");
        assert!(!text.contains("secret"), "{text}");
        assert_eq!(bodies.view()["reservations"], 2);
        bodies.refresh(Vec::new());
        assert_eq!(bodies.parent_status(&parent), ParentStatus::NotRunning);
    }
}
