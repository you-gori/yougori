//! The ports the VM service runs over (module docs in `mod.rs`): the bundle of host ports
//! one service is generic over ([`VmPorts`]), what the service needs of the QEMU host
//! process port beyond `QemuHost` ([`VmHostPort`]), the host's one CORE-03 ledger as the
//! service reaches it ([`ServiceLedger`]), and the production process table of the link
//! socket's peer check ([`HostProcessTable`]).

use std::fmt;
use std::sync::{Arc, PoisonError};

use crate::foundation::coordination::{LedgerCapacity, LedgerHandle, SharedLedger};
use crate::foundation::events::AuditSpool;
use crate::foundation::ids::Clock;
use crate::foundation::ledger::ReservationId;
use crate::foundation::process::{HostProcess, ProcessError, ProcessIdentity, SharedHandles};
use crate::sandbox::audit::{HeadAnchor, SegmentStorage};
use crate::sandbox::integration::{LedgerReservations, ReservationResolver};
use crate::sandbox::link::BootstrapSecret;
use crate::sandbox::link_transport::{LinkConnector, ProcessTable, StreamShutdown};
use crate::sandbox::qemu::{
    LaunchLayout, ObserveFailure, PrivateDirectory, QemuHost, QemuMonitor, ReservationView,
    ReservedVm,
};

/// What the service needs of the QEMU host process port beyond [`QemuHost`]. The Windows
/// port (`sandbox::qemu_host`, agent Q1) keeps the bootstrap secret it wrote for each
/// process it started and the private directory it created for it; implementing this is
/// handing them out.
pub trait VmHostPort: QemuHost {
    /// The private directory `start` created for `process` (the launch plan's control
    /// directory, holding `qmp.sock`, `link.sock` and the bootstrap file), while the port
    /// knows the process; `None` for a process it never started.
    fn private_directory(&self, process: &ProcessIdentity) -> Option<PrivateDirectory>;

    /// The bootstrap secret `start` wrote into `process`'s bootstrap file, once: the first
    /// call returns it and every later call `None`, so only one link binding is ever made
    /// from it.
    fn take_secret(&mut self, process: &ProcessIdentity) -> Option<BootstrapSecret>;

    /// Whether `directory` is absent from the host now, as the host observes it (a lookup
    /// that follows no link). `terminate` removes it only after the host's proof that the
    /// process ended.
    fn directory_absent(&self, directory: &PrivateDirectory) -> Result<bool, ObserveFailure>;

    /// Duplicates the job and process handles of `process`, while the port holds it, into
    /// `holder` (VM-W26: the lifetime supervisor holds every VM beside the service). A
    /// port without host processes refuses.
    fn share_process(
        &self,
        process: &ProcessIdentity,
        holder: &HostProcess,
    ) -> Result<SharedHandles, String> {
        let _ = (process, holder);
        Err("this host port holds no host process it can share".to_owned())
    }
}

/// The host's one CORE-03 ledger as the service reaches it: a handle the coordinator's
/// capacity port charges, the reservation resolver of the backend port reads, and the QEMU
/// profile's reservation view reads, all the same ledger (CORE-03: one capacity
/// authority). The service never creates a ledger: it is handed one at construction.
/// Implemented for [`SharedLedger`]; another host-scope handle implements it the same way.
pub trait ServiceLedger<C: Clock>: LedgerHandle<C> + Clone + Send + Sized + 'static {
    /// The backend port's resolver of coordination reservation keys.
    type Resolver: ReservationResolver + Send + 'static;
    /// The QEMU profile's view of the reserved guest memory.
    type View: ReservationView + Send + 'static;

    /// The coordinator's capacity port over this handle. A request that does not fit is
    /// refused at once; the service does not queue launches.
    fn capacity(&self) -> LedgerCapacity<C, Self>;

    fn resolver(&self) -> Self::Resolver;

    fn view(&self) -> Self::View;
}

impl<C: Clock + 'static> ServiceLedger<C> for SharedLedger<C> {
    type Resolver = LedgerReservations<C>;
    type View = SharedLedgerView<C>;

    fn capacity(&self) -> LedgerCapacity<C, Self> {
        LedgerCapacity::shared(Arc::clone(self))
    }

    fn resolver(&self) -> LedgerReservations<C> {
        LedgerReservations::new(Arc::clone(self))
    }

    fn view(&self) -> SharedLedgerView<C> {
        SharedLedgerView {
            ledger: Arc::clone(self),
        }
    }
}

/// The ledger's own [`ReservationView`], read through the shared handle, locked as its
/// other clients lock it.
pub struct SharedLedgerView<C: Clock> {
    ledger: SharedLedger<C>,
}

impl<C: Clock> ReservationView for SharedLedgerView<C> {
    fn reserved_gpu_bytes(&self, reservation: ReservationId) -> u64 {
        self.ledger.lock().unwrap_or_else(PoisonError::into_inner).reserved_gpu_bytes(reservation)
    }
    fn reserved_vm(&self, reservation: ReservationId) -> Option<ReservedVm> {
        let ledger = self.ledger.lock().unwrap_or_else(PoisonError::into_inner);
        ledger.reserved_vm(reservation)
    }
}

impl<C: Clock> fmt::Debug for SharedLedgerView<C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedLedgerView(shared ledger)")
    }
}

/// The host's process table for the link socket's peer check: which process holds a
/// process id now, by its creation time (`ProcessIdentity::holder_of`; a typed
/// `Unsupported` where the host has no such lookup).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostProcessTable;

impl ProcessTable for HostProcessTable {
    fn holder_of(&self, pid: u32) -> Result<Option<ProcessIdentity>, ProcessError> {
        ProcessIdentity::holder_of(pid)
    }
}

/// The host ports one [`VmService`](super::VmService) runs over, as one bundle of types:
/// the clock; the QEMU backend's three ports (the host process port with
/// [`VmHostPort`], QMP and the launch layout); the host's ledger handle; the audit
/// stream's storage, spool and anchor; the link socket's connector, whose streams must not
/// block (see below); and the process table of the peer check.
///
/// The connector's streams are read and written while the service's mutex is held, so a
/// read must return within a short bound when nothing has arrived (`WouldBlock` or
/// `TimedOut`), and the stream must stay usable afterwards; a write that cannot proceed
/// returns the same. A stream that blocks stalls every call of the service.
pub trait VmPorts: 'static {
    type Backend: super::ServiceRuntime + From<crate::sandbox::qemu::QemuBackend<Self::Host, Self::Monitor, Self::Layout, <Self::Ledger as ServiceLedger<Self::Clock>>::View>>;
    type Clock: Clock + Clone + 'static;
    type Host: VmHostPort<Proof: Send + 'static> + Send + 'static;
    type Monitor: QemuMonitor + Send + 'static;
    type Layout: LaunchLayout + Send + 'static;
    type Ledger: ServiceLedger<Self::Clock>;
    type Segments: SegmentStorage + Send + 'static;
    type Spool: AuditSpool + Send + 'static;
    type Anchor: HeadAnchor + Send + 'static;
    type Connector: LinkConnector<Stream: StreamShutdown + Send + 'static> + Send + 'static;
    type Processes: ProcessTable + Send + 'static;
}
