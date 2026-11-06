//! The port the fake runner drives (S12 G0 line 383: fake, time-controlled runners
//! first): the lifecycle supervisor, a lifecycle backend port over a fake backend, the
//! CORE-01 registry its launches are admitted on, and a manual clock the runner moves.
//!
//! The runner never builds a VM or a backend itself. A host wires the committed pieces
//! together, for example the VB1 fake backend behind the integration module's
//! `BackendPort`, or the lifecycle's scripted backend in its tests, and hands them to the
//! runner one supervisor call at a time.

use crate::foundation::coordination::CapacityPort;
use crate::foundation::evidence::ProbeRegistry;
use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime};
use crate::foundation::report::{
    BuildIdentity, ClientDescription, HostDescription, LaunchDescription,
};
use crate::sandbox::lifecycle::{LaunchRequest, Supervisor, VmBackend};

use super::BenchError;

/// The parts of one supervisor call: the supervisor, the lifecycle backend port and the
/// registry, borrowed together.
pub struct Drive<'a, C: Clock + Clone, P: CapacityPort, R: Clock> {
    pub supervisor: &'a mut Supervisor<C, P>,
    pub backend: Box<dyn VmBackend + 'a>,
    pub registry: &'a ProbeRegistry<R>,
}

/// A fake substrate the runner can drive and whose time it controls.
pub trait FakeVmHost {
    /// The supervisor's clock; it must read the manual clock [`FakeVmHost::advance_to`]
    /// moves, which the runner checks after every move.
    type Clock: Clock + Clone;
    type Capacity: CapacityPort;
    type Evidence: Clock;

    /// The manual clock's reading.
    fn now(&self) -> MonotonicTime;

    /// Moves the manual clock forward to `at`, never back. The host's probes observe
    /// again as they would with time passing.
    fn advance_to(&mut self, at: MonotonicTime);

    /// The parts of one supervisor call.
    fn drive(&mut self) -> Drive<'_, Self::Clock, Self::Capacity, Self::Evidence>;

    /// A launch request for `execution`: its admitted runtime, demand, class and limits.
    fn request(&mut self, execution: &ExecutionId) -> Result<LaunchRequest, BenchError>;

    /// Makes the fake backend refuse every create and restore, or stop refusing (the
    /// fault of [`InjectedFault::BackendRefusesCreate`](super::InjectedFault)).
    fn refuse_creates(&mut self, refuse: bool);
}

/// The S8 fields every record of a run repeats: build identity, host, client and launch
/// image and backend. On the fake substrate the host fields describe the fake; the
/// record's substrate says so.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordTemplate {
    pub build: BuildIdentity,
    pub host: HostDescription,
    pub client: ClientDescription,
    pub launch: LaunchDescription,
}
