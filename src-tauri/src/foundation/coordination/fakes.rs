//! Fakes for the coordination ports (tests only). They keep their state in memory, log
//! every call in order and touch nothing on the host.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use super::capacity::{
    CapacityLimit, CapacityPort, CapacityRefusal, ExecutionCancellation, ReconcileReport,
    ReleaseOutcome, ReservationKey, ReservationPriority, ReservationRequest, ReserveOutcome,
    ResourceKind, RetryProspect, ReturnHold,
};
use super::identity::{PerimeterId, VmInstanceId};
use super::port::{
    BootRequest, ObservedVm, PortFailure, PortOperation, Readiness, ReadinessReport, SandboxPort,
};
use super::recovery::{RestoredVmReport, SnapshotManifest};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{digest, Digest, ExecutionId, PolicyEpoch, SandboxBootGeneration};

/// A ledger call, in the order the coordinator made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LedgerCall {
    Reserve(ReservationKey),
    BeginCreate(ReservationKey),
    Release(ReservationKey),
    ConfirmRelease(ReservationKey, SourceClass),
    CancelExecution(ExecutionId),
    Reconcile(ExecutionId),
    BeginHold(BTreeSet<ResourceKind>),
    EndHold(ReturnHold),
}

/// Where a reservation of the fake ledger stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FakeState {
    /// Granted before creation.
    Granted,
    /// Its workload is being created or runs.
    InUse,
    /// Cancelled after creation; still counted until its release is observed.
    Releasing,
}

#[derive(Clone, Debug)]
struct Entry {
    request: ReservationRequest,
    state: FakeState,
}

#[derive(Debug, Default)]
struct LedgerState {
    capacity: BTreeMap<ResourceKind, u64>,
    open: BTreeMap<ReservationKey, Entry>,
    queue_bound: usize,
    queued: Vec<(ReservationKey, ExecutionId)>,
    holds: BTreeMap<ReturnHold, BTreeSet<ResourceKind>>,
    next_hold: u64,
    calls: Vec<LedgerCall>,
}

/// A host reservation ledger with the CORE-03 semantics the port promises: physical
/// capacity counted once, children carved from their parent, a bounded queue, created
/// workloads counted until their release is observed, cancellation of whole trees and
/// owner-return holds. Clones share one ledger, so a test can hand it to a recovered
/// coordinator and still inspect it.
#[derive(Clone, Debug, Default)]
pub struct FakeLedger {
    state: Rc<RefCell<LedgerState>>,
}

impl FakeLedger {
    pub fn new(capacity: impl IntoIterator<Item = (ResourceKind, u64)>) -> Self {
        let ledger = Self::default();
        ledger.state.borrow_mut().capacity = capacity.into_iter().collect();
        ledger
    }

    /// Queues up to `bound` requests that could fit once others release.
    pub fn with_queue(self, bound: usize) -> Self {
        self.state.borrow_mut().queue_bound = bound;
        self
    }

    /// Whether the ledger still counts the reservation, in any state.
    pub fn is_held(&self, key: &ReservationKey) -> bool {
        self.state.borrow().open.contains_key(key)
    }

    pub fn state_of(&self, key: &ReservationKey) -> Option<FakeState> {
        self.state.borrow().open.get(key).map(|entry| entry.state)
    }

    pub fn held(&self) -> BTreeSet<ReservationKey> {
        self.state.borrow().open.keys().copied().collect()
    }

    pub fn calls(&self) -> Vec<LedgerCall> {
        self.state.borrow().calls.clone()
    }

    pub fn reserve_calls(&self) -> usize {
        self.calls()
            .iter()
            .filter(|call| matches!(call, LedgerCall::Reserve(_)))
            .count()
    }

    /// A reservation the ledger holds that the coordinator never recorded.
    pub fn insert_unrecorded(&self, request: ReservationRequest, state: FakeState) {
        self.state
            .borrow_mut()
            .open
            .insert(request.key, Entry { request, state });
    }

    /// Drops a reservation without the coordinator knowing, as a lost record would.
    pub fn forget(&self, key: &ReservationKey) {
        self.state.borrow_mut().open.remove(key);
    }
}

fn retry(requested: u64, limit: u64) -> RetryProspect {
    if requested <= limit {
        RetryProspect::CanProgress
    } else {
        RetryProspect::CannotProgress
    }
}

impl LedgerState {
    fn children(&self, parent: &ReservationKey) -> Vec<ReservationKey> {
        self.open
            .iter()
            .filter(|(_, entry)| entry.request.parent.as_ref() == Some(parent))
            .map(|(key, _)| *key)
            .collect()
    }

    /// `key` and every reservation below it, children after their parent.
    fn tree(&self, key: &ReservationKey) -> Vec<ReservationKey> {
        let mut tree = vec![*key];
        let mut index = 0;
        while let Some(current) = tree.get(index).copied() {
            tree.extend(self.children(&current));
            index += 1;
        }
        tree
    }

    fn used(&self, parent: Option<&ReservationKey>, resource: ResourceKind) -> u64 {
        self.open
            .values()
            .filter(|entry| entry.request.parent.as_ref() == parent)
            .filter_map(|entry| entry.request.demand.get(&resource))
            .sum()
    }

    fn admit(&mut self, request: &ReservationRequest) -> Result<ReserveOutcome, CapacityRefusal> {
        if let Some(existing) = self.open.get(&request.key) {
            return if existing.request == *request && existing.state != FakeState::Releasing {
                Ok(ReserveOutcome::Granted)
            } else {
                Err(CapacityRefusal::KeyConflict { key: request.key })
            };
        }
        if request.priority == ReservationPriority::Background {
            for held in self.holds.values() {
                if let Some(resource) = request
                    .demand
                    .keys()
                    .find(|resource| held.contains(resource))
                {
                    return Err(CapacityRefusal::OwnerReturnHold {
                        resource: *resource,
                    });
                }
            }
        }
        if let Some(parent) = request.parent {
            let budget = match self.open.get(&parent) {
                Some(entry) if entry.state != FakeState::Releasing => entry.request.demand.clone(),
                _ => return Err(CapacityRefusal::UnknownParent { parent }),
            };
            for (&resource, &requested) in &request.demand {
                let total = budget.get(&resource).copied().unwrap_or(0);
                let remaining = total.saturating_sub(self.used(Some(&parent), resource));
                if requested > remaining {
                    return Err(CapacityRefusal::ExceedsParentBudget {
                        parent,
                        resource,
                        requested,
                        remaining,
                        retry: retry(requested, total),
                    });
                }
            }
        } else {
            for (&resource, &requested) in &request.demand {
                let Some(total) = self.capacity.get(&resource).copied() else {
                    return Err(CapacityRefusal::NotObserved { resource });
                };
                let available = total.saturating_sub(self.used(None, resource));
                if requested <= available {
                    continue;
                }
                if requested <= total && self.queue_bound > 0 {
                    if let Some(index) = self.queued.iter().position(|(key, _)| *key == request.key)
                    {
                        return Ok(ReserveOutcome::Queued {
                            position: index as u32 + 1,
                        });
                    }
                    if self.queued.len() < self.queue_bound {
                        self.queued.push((request.key, request.execution.clone()));
                        return Ok(ReserveOutcome::Queued {
                            position: self.queued.len() as u32,
                        });
                    }
                    return Err(CapacityRefusal::QueueFull { resource });
                }
                return Err(CapacityRefusal::Insufficient {
                    resource,
                    limit: CapacityLimit::Host,
                    requested,
                    available,
                    retry: retry(requested, total),
                });
            }
        }
        self.queued.retain(|(key, _)| *key != request.key);
        self.open.insert(
            request.key,
            Entry {
                request: request.clone(),
                state: FakeState::Granted,
            },
        );
        Ok(ReserveOutcome::Granted)
    }

    fn begin_create(&mut self, key: &ReservationKey) -> Result<(), CapacityRefusal> {
        let entry = self
            .open
            .get(key)
            .ok_or(CapacityRefusal::UnknownReservation { key: *key })?;
        match entry.state {
            FakeState::InUse => return Ok(()),
            FakeState::Releasing => {
                return Err(CapacityRefusal::Refused {
                    reason: "the reservation is releasing".to_owned(),
                })
            }
            FakeState::Granted => {}
        }
        if let Some(parent) = entry.request.parent {
            if self.open.get(&parent).map(|parent| parent.state) != Some(FakeState::InUse) {
                return Err(CapacityRefusal::Refused {
                    reason: "a child is created only inside a created parent".to_owned(),
                });
            }
        }
        if let Some(entry) = self.open.get_mut(key) {
            entry.state = FakeState::InUse;
        }
        Ok(())
    }

    fn release(&mut self, key: &ReservationKey) -> ReleaseOutcome {
        if !self.open.contains_key(key) {
            return ReleaseOutcome::NotHeld;
        }
        for node in self.tree(key) {
            let created = self
                .open
                .get(&node)
                .is_some_and(|entry| entry.state != FakeState::Granted);
            if created {
                if let Some(entry) = self.open.get_mut(&node) {
                    entry.state = FakeState::Releasing;
                }
            } else {
                self.open.remove(&node);
            }
        }
        if self.open.contains_key(key) {
            ReleaseOutcome::Pending
        } else {
            ReleaseOutcome::Released
        }
    }

    fn confirm_release(
        &mut self,
        key: &ReservationKey,
        source: SourceClass,
    ) -> Result<ReleaseOutcome, CapacityRefusal> {
        let Some(entry) = self.open.get(key) else {
            return Ok(ReleaseOutcome::NotHeld);
        };
        let required = if entry.request.parent.is_some() {
            SourceClass::GuestReport
        } else {
            SourceClass::HostProbe
        };
        if !source.satisfies(required) {
            return Err(CapacityRefusal::SourceTooWeak { source, required });
        }
        for node in self.tree(key) {
            self.open.remove(&node);
        }
        Ok(ReleaseOutcome::Released)
    }
}

impl CapacityPort for FakeLedger {
    fn reserve(&mut self, request: &ReservationRequest) -> Result<ReserveOutcome, CapacityRefusal> {
        let mut state = self.state.borrow_mut();
        state.calls.push(LedgerCall::Reserve(request.key));
        state.admit(request)
    }

    fn begin_create(&mut self, key: &ReservationKey) -> Result<(), CapacityRefusal> {
        let mut state = self.state.borrow_mut();
        state.calls.push(LedgerCall::BeginCreate(*key));
        state.begin_create(key)
    }

    fn release(&mut self, key: &ReservationKey) -> Result<ReleaseOutcome, CapacityRefusal> {
        let mut state = self.state.borrow_mut();
        state.calls.push(LedgerCall::Release(*key));
        Ok(state.release(key))
    }

    fn confirm_release(
        &mut self,
        key: &ReservationKey,
        source: SourceClass,
    ) -> Result<ReleaseOutcome, CapacityRefusal> {
        let mut state = self.state.borrow_mut();
        state.calls.push(LedgerCall::ConfirmRelease(*key, source));
        state.confirm_release(key, source)
    }

    fn cancel_execution(
        &mut self,
        execution: &ExecutionId,
    ) -> Result<ExecutionCancellation, CapacityRefusal> {
        let mut state = self.state.borrow_mut();
        state
            .calls
            .push(LedgerCall::CancelExecution(execution.clone()));
        let roots: Vec<ReservationKey> = state
            .open
            .iter()
            .filter(|(_, entry)| {
                &entry.request.execution == execution && entry.request.parent.is_none()
            })
            .map(|(key, _)| *key)
            .collect();
        let mut cancellation = ExecutionCancellation::default();
        for root in roots {
            match state.release(&root) {
                ReleaseOutcome::Released => cancellation.released += 1,
                ReleaseOutcome::Pending => cancellation.pending += 1,
                ReleaseOutcome::NotHeld => {}
            }
        }
        let before = state.queued.len();
        state.queued.retain(|(_, owner)| owner != execution);
        cancellation.dequeued = before - state.queued.len();
        Ok(cancellation)
    }

    fn reconcile(
        &mut self,
        execution: &ExecutionId,
        expected: &BTreeSet<ReservationKey>,
    ) -> Result<ReconcileReport, CapacityRefusal> {
        let mut state = self.state.borrow_mut();
        state.calls.push(LedgerCall::Reconcile(execution.clone()));
        let mine: BTreeSet<ReservationKey> = state
            .open
            .iter()
            .filter(|(_, entry)| &entry.request.execution == execution)
            .map(|(key, _)| *key)
            .collect();
        let mut report = ReconcileReport {
            confirmed: mine.intersection(expected).copied().collect(),
            missing: expected.difference(&mine).copied().collect(),
            ..ReconcileReport::default()
        };
        for key in mine.difference(expected) {
            if !state.open.contains_key(key) {
                report.released_orphans.insert(*key);
                continue;
            }
            match state.release(key) {
                ReleaseOutcome::Pending => {
                    report.pending_orphans.insert(*key);
                }
                ReleaseOutcome::Released | ReleaseOutcome::NotHeld => {
                    report.released_orphans.insert(*key);
                }
            }
        }
        Ok(report)
    }

    fn begin_hold(
        &mut self,
        resources: &BTreeSet<ResourceKind>,
    ) -> Result<ReturnHold, CapacityRefusal> {
        let mut state = self.state.borrow_mut();
        state.calls.push(LedgerCall::BeginHold(resources.clone()));
        state.next_hold += 1;
        let hold = ReturnHold::new(state.next_hold);
        state.holds.insert(hold, resources.clone());
        Ok(hold)
    }

    fn end_hold(&mut self, hold: ReturnHold) -> Result<(), CapacityRefusal> {
        let mut state = self.state.borrow_mut();
        state.calls.push(LedgerCall::EndHold(hold));
        state.holds.remove(&hold);
        Ok(())
    }
}

/// A sandbox port call, in the order the coordinator made it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PortCall {
    PreparePerimeter(SandboxBootGeneration),
    CreateVm(SandboxBootGeneration),
    RestoreVm(SandboxBootGeneration),
    ObserveReadiness(VmInstanceId),
    InspectRestoredVm(VmInstanceId),
    TerminateVm(VmInstanceId),
    TeardownPerimeter(PerimeterId),
    ListVms,
}

type ReportScript = Box<dyn Fn(VmInstanceId, SandboxBootGeneration) -> RestoredVmReport>;

/// A VM backend that keeps its VMs and perimeters in memory. Creating the same boot again
/// returns the same VM.
pub struct FakeSandbox {
    pub calls: Vec<PortCall>,
    /// Operations that fail when called.
    pub failing: BTreeSet<PortOperation>,
    /// What readiness checks report.
    pub readiness: ReadinessReport,
    /// What inspecting a restored VM reports; without a script, a report that fails.
    pub restored: Option<ReportScript>,
    pub live: BTreeMap<VmInstanceId, ObservedVm>,
    pub perimeters: BTreeSet<PerimeterId>,
    /// A handle the backend hands out again instead of a fresh one, as a faulty backend
    /// would.
    pub reused: Option<VmInstanceId>,
}

impl FakeSandbox {
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            failing: BTreeSet::new(),
            readiness: ReadinessReport {
                source: SourceClass::HostProbe,
                readiness: Readiness::Ready,
            },
            restored: None,
            live: BTreeMap::new(),
            perimeters: BTreeSet::new(),
            reused: None,
        }
    }

    pub fn vm_for(
        execution: &ExecutionId,
        boot: SandboxBootGeneration,
        restored: bool,
    ) -> VmInstanceId {
        let mode: &[u8] = if restored { b"restored" } else { b"fresh" };
        VmInstanceId::new(digest(
            "yougori/test/vm/v1",
            &[
                execution.as_str().as_bytes(),
                &boot.get().to_be_bytes(),
                mode,
            ],
        ))
    }

    pub fn perimeter_for(execution: &ExecutionId, boot: SandboxBootGeneration) -> PerimeterId {
        PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[execution.as_str().as_bytes(), &boot.get().to_be_bytes()],
        ))
    }

    fn fail(&self, operation: PortOperation) -> Result<(), PortFailure> {
        if self.failing.contains(&operation) {
            return Err(PortFailure {
                operation,
                detail: "injected failure".to_owned(),
            });
        }
        Ok(())
    }

    fn boot(&mut self, request: &BootRequest, restored: bool) -> VmInstanceId {
        let vm = self.reused.unwrap_or_else(|| {
            Self::vm_for(&request.execution, request.generations.boot, restored)
        });
        self.live.entry(vm).or_insert_with(|| ObservedVm {
            vm,
            execution: request.execution.clone(),
            boot: request.generations.boot,
        });
        vm
    }
}

impl SandboxPort for FakeSandbox {
    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, PortFailure> {
        self.calls
            .push(PortCall::PreparePerimeter(request.generations.boot));
        self.fail(PortOperation::PreparePerimeter)?;
        let perimeter = Self::perimeter_for(&request.execution, request.generations.boot);
        self.perimeters.insert(perimeter);
        Ok(perimeter)
    }

    fn create_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmInstanceId, PortFailure> {
        self.calls
            .push(PortCall::CreateVm(request.generations.boot));
        self.fail(PortOperation::CreateVm)?;
        Ok(self.boot(request, false))
    }

    fn restore_vm(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
        _snapshot: &SnapshotManifest,
    ) -> Result<VmInstanceId, PortFailure> {
        self.calls
            .push(PortCall::RestoreVm(request.generations.boot));
        self.fail(PortOperation::RestoreVm)?;
        Ok(self.boot(request, true))
    }

    fn observe_readiness(
        &mut self,
        vm: &VmInstanceId,
        _boot: SandboxBootGeneration,
    ) -> ReadinessReport {
        self.calls.push(PortCall::ObserveReadiness(*vm));
        self.readiness.clone()
    }

    fn inspect_restored_vm(
        &mut self,
        vm: &VmInstanceId,
        boot: SandboxBootGeneration,
    ) -> RestoredVmReport {
        self.calls.push(PortCall::InspectRestoredVm(*vm));
        match &self.restored {
            Some(script) => script(*vm, boot),
            None => RestoredVmReport {
                vm: *vm,
                boot,
                snapshot: super::identity::SnapshotId::new(Digest::from_bytes([0; 32])),
                guest_identity: Digest::from_bytes([0; 32]),
                actions: BTreeSet::new(),
                attached_volumes: BTreeSet::new(),
                policy: PolicyEpoch::FIRST,
                image_profile: Digest::from_bytes([0; 32]),
                presented_epochs: BTreeSet::new(),
                source: SourceClass::Fixture,
            },
        }
    }

    fn terminate_vm(&mut self, vm: &VmInstanceId) -> Result<(), PortFailure> {
        self.calls.push(PortCall::TerminateVm(*vm));
        self.fail(PortOperation::TerminateVm)?;
        self.live.remove(vm);
        Ok(())
    }

    fn teardown_perimeter(&mut self, perimeter: &PerimeterId) -> Result<(), PortFailure> {
        self.calls.push(PortCall::TeardownPerimeter(*perimeter));
        self.fail(PortOperation::TeardownPerimeter)?;
        self.perimeters.remove(perimeter);
        Ok(())
    }

    fn list_vms(&mut self) -> Result<Vec<ObservedVm>, PortFailure> {
        self.calls.push(PortCall::ListVms);
        self.fail(PortOperation::ListVms)?;
        Ok(self.live.values().cloned().collect())
    }
}
