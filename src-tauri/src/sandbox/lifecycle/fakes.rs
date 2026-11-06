//! A scripted VM backend for tests: VMs and perimeters in memory, every call logged,
//! failures injected per operation, and underlying numbers that can be reused by a
//! foreign process the way a PID is (VM part §6.4).

use std::collections::{BTreeMap, BTreeSet};

use super::backend::{
    BackendCapabilities, BackendFailure, BackendOperation, HandleIdentity, StateReset, StopOutcome,
    VmBackend, VmHandle,
};
use crate::foundation::coordination::{
    BootRequest, PerimeterId, Readiness, ReadinessReport, RestoreAction, RestoredVmReport,
    SnapshotId, SnapshotManifest, SnapshotOrigin, VmInstanceId,
};
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{digest, Digest, ExecutionId, PolicyEpoch, SandboxBootGeneration};

/// One backend call, in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BackendCall {
    PreparePerimeter(SandboxBootGeneration),
    Launch(SandboxBootGeneration),
    Restore(SandboxBootGeneration),
    Readiness(VmInstanceId),
    Inspect(VmInstanceId),
    CheckHandle(VmInstanceId),
    Stop(VmInstanceId),
    Snapshot(VmInstanceId),
    Teardown(PerimeterId),
    List,
}

#[derive(Clone, Debug)]
struct LiveVm {
    handle: VmHandle,
    underlying: u64,
    policy: PolicyEpoch,
    restored_from: Option<SnapshotManifest>,
}

/// The scripted backend.
pub struct ScriptedBackend {
    pub calls: Vec<BackendCall>,
    pub failing: BTreeSet<BackendOperation>,
    pub readiness: ReadinessReport,
    pub capabilities: BackendCapabilities,
    pub image_profile: Digest,
    /// Volumes a restored VM reports attached.
    pub attached_volumes: BTreeSet<Digest>,
    /// Required restore actions the backend leaves out, to make verification fail.
    pub omit_actions: BTreeSet<RestoreAction>,
    /// Authorization epochs a restored VM presents, to make verification fail.
    pub presented_epochs: BTreeSet<crate::foundation::ids::AuthorizationEpoch>,
    pub perimeters: BTreeSet<PerimeterId>,
    pub snapshots: Vec<SnapshotManifest>,
    live: BTreeMap<VmInstanceId, LiveVm>,
    /// Every token issued, by the underlying number it was issued for.
    tokens: BTreeMap<Digest, u64>,
    /// Underlying numbers a foreign process holds now.
    foreign: BTreeSet<u64>,
    next_underlying: u64,
    stopped: Vec<VmInstanceId>,
    job_ended: bool,
}

impl Default for ScriptedBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptedBackend {
    pub fn new() -> Self {
        Self {
            calls: Vec::new(),
            failing: BTreeSet::new(),
            readiness: ReadinessReport {
                source: SourceClass::HostProbe,
                readiness: Readiness::Ready,
            },
            capabilities: BackendCapabilities {
                snapshot_restore: true,
                state_reset: StateReset::Supported,
            },
            image_profile: digest("yougori/test/image/v1", &[b"sandbox-image"]),
            attached_volumes: BTreeSet::new(),
            omit_actions: BTreeSet::new(),
            presented_epochs: BTreeSet::new(),
            perimeters: BTreeSet::new(),
            snapshots: Vec::new(),
            live: BTreeMap::new(),
            tokens: BTreeMap::new(),
            foreign: BTreeSet::new(),
            next_underlying: 1000,
            stopped: Vec::new(),
            job_ended: false,
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

    fn token(underlying: u64, vm: VmInstanceId) -> Digest {
        digest(
            "yougori/test/vm-token/v1",
            &[&underlying.to_be_bytes(), vm.digest().as_bytes()],
        )
    }

    fn fail(&self, operation: BackendOperation) -> Result<(), BackendFailure> {
        if self.failing.contains(&operation) {
            return Err(BackendFailure {
                operation,
                detail: "injected failure".to_owned(),
            });
        }
        Ok(())
    }

    fn boot(&mut self, request: &BootRequest, restored_from: Option<SnapshotManifest>) -> VmHandle {
        let vm = Self::vm_for(
            &request.execution,
            request.generations.boot,
            restored_from.is_some(),
        );
        if let Some(live) = self.live.get(&vm) {
            return live.handle.clone();
        }
        let underlying = self.next_underlying;
        self.next_underlying += 1;
        let token = Self::token(underlying, vm);
        let handle = VmHandle {
            vm,
            execution: request.execution.clone(),
            boot: request.generations.boot,
            token,
        };
        self.tokens.insert(token, underlying);
        self.live.insert(
            vm,
            LiveVm {
                handle: handle.clone(),
                underlying,
                policy: request.generations.policy,
                restored_from,
            },
        );
        handle
    }

    /// The VMs alive now.
    pub fn live(&self) -> Vec<VmInstanceId> {
        self.live.keys().copied().collect()
    }

    pub fn is_live(&self, vm: &VmInstanceId) -> bool {
        self.live.contains_key(vm)
    }

    /// VMs stopped through their handles, in order.
    pub fn stopped(&self) -> &[VmInstanceId] {
        &self.stopped
    }

    pub fn restore_count(&self) -> usize {
        self.calls
            .iter()
            .filter(|call| matches!(call, BackendCall::Restore(_)))
            .count()
    }

    /// The VM died on its own; no stop is recorded.
    pub fn kill(&mut self, vm: &VmInstanceId) -> Option<VmHandle> {
        self.live.remove(vm).map(|live| live.handle)
    }

    /// A foreign process now holds the underlying number behind `handle`, as a reused
    /// PID would. The VM behind the handle, if still alive, is gone.
    pub fn reuse_underlying(&mut self, handle: &VmHandle) {
        self.live.remove(&handle.vm);
        if let Some(underlying) = self.tokens.get(&handle.token) {
            self.foreign.insert(*underlying);
        }
    }

    /// Whether the foreign process behind `handle`'s underlying number is still alive.
    pub fn foreign_alive(&self, handle: &VmHandle) -> bool {
        self.tokens
            .get(&handle.token)
            .is_some_and(|underlying| self.foreign.contains(underlying))
    }

    /// The OS job ended with the supervisor: every VM is gone without a stop call.
    pub fn end_job(&mut self) {
        self.live.clear();
        self.job_ended = true;
    }

    pub fn job_ended(&self) -> bool {
        self.job_ended
    }
}

impl VmBackend for ScriptedBackend {
    fn capabilities(&self) -> BackendCapabilities {
        self.capabilities.clone()
    }

    fn prepare_perimeter(&mut self, request: &BootRequest) -> Result<PerimeterId, BackendFailure> {
        self.calls
            .push(BackendCall::PreparePerimeter(request.generations.boot));
        self.fail(BackendOperation::PreparePerimeter)?;
        let perimeter = PerimeterId::new(digest(
            "yougori/test/perimeter/v1",
            &[
                request.execution.as_str().as_bytes(),
                &request.generations.boot.get().to_be_bytes(),
            ],
        ));
        self.perimeters.insert(perimeter);
        Ok(perimeter)
    }

    fn launch(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
    ) -> Result<VmHandle, BackendFailure> {
        self.calls
            .push(BackendCall::Launch(request.generations.boot));
        self.fail(BackendOperation::Launch)?;
        Ok(self.boot(request, None))
    }

    fn restore(
        &mut self,
        request: &BootRequest,
        _perimeter: &PerimeterId,
        snapshot: &SnapshotManifest,
    ) -> Result<VmHandle, BackendFailure> {
        self.calls
            .push(BackendCall::Restore(request.generations.boot));
        self.fail(BackendOperation::Restore)?;
        Ok(self.boot(request, Some(snapshot.clone())))
    }

    fn observe_readiness(&mut self, handle: &VmHandle) -> ReadinessReport {
        self.calls.push(BackendCall::Readiness(handle.vm));
        self.readiness.clone()
    }

    fn inspect_restored(&mut self, handle: &VmHandle) -> RestoredVmReport {
        self.calls.push(BackendCall::Inspect(handle.vm));
        let (snapshot, policy) = match self.live.get(&handle.vm) {
            Some(live) => (live.restored_from.clone(), live.policy),
            None => (None, PolicyEpoch::FIRST),
        };
        let manifest = snapshot.unwrap_or_else(|| SnapshotManifest {
            snapshot: SnapshotId::new(Digest::from_bytes([0; 32])),
            origin: SnapshotOrigin::TenantWorkload,
            image_profile: Digest::from_bytes([0; 32]),
            contents: BTreeSet::new(),
            source_vm: handle.vm,
            guest_identity: Digest::from_bytes([0; 32]),
        });
        RestoredVmReport {
            vm: handle.vm,
            boot: handle.boot,
            snapshot: manifest.snapshot,
            guest_identity: digest(
                "yougori/test/guest/v1",
                &[
                    handle.vm.digest().as_bytes(),
                    &handle.boot.get().to_be_bytes(),
                ],
            ),
            actions: RestoreAction::REQUIRED
                .into_iter()
                .filter(|action| !self.omit_actions.contains(action))
                .collect(),
            attached_volumes: self.attached_volumes.clone(),
            policy,
            image_profile: manifest.image_profile,
            presented_epochs: self.presented_epochs.clone(),
            source: SourceClass::HostProbe,
        }
    }

    fn check_handle(&mut self, handle: &VmHandle) -> HandleIdentity {
        self.calls.push(BackendCall::CheckHandle(handle.vm));
        if self
            .live
            .get(&handle.vm)
            .is_some_and(|live| live.handle.token == handle.token)
        {
            return HandleIdentity::Matches;
        }
        let Some(underlying) = self.tokens.get(&handle.token).copied() else {
            return HandleIdentity::Gone;
        };
        if self.foreign.contains(&underlying) {
            return HandleIdentity::Reused { holder: None };
        }
        if let Some(other) = self
            .live
            .values()
            .find(|live| live.underlying == underlying)
        {
            return HandleIdentity::Reused {
                holder: Some(other.handle.execution.clone()),
            };
        }
        HandleIdentity::Gone
    }

    fn stop(&mut self, handle: &VmHandle) -> Result<StopOutcome, BackendFailure> {
        self.calls.push(BackendCall::Stop(handle.vm));
        self.fail(BackendOperation::Stop)?;
        match self.live.remove(&handle.vm) {
            Some(_) => {
                self.stopped.push(handle.vm);
                Ok(StopOutcome::Stopped)
            }
            None => Ok(StopOutcome::AlreadyGone),
        }
    }

    fn snapshot(
        &mut self,
        handle: &VmHandle,
        origin: SnapshotOrigin,
    ) -> Result<SnapshotManifest, BackendFailure> {
        self.calls.push(BackendCall::Snapshot(handle.vm));
        self.fail(BackendOperation::Snapshot)?;
        let number = self.snapshots.len() as u64;
        let manifest = SnapshotManifest {
            snapshot: SnapshotId::new(digest(
                "yougori/test/snapshot/v1",
                &[handle.vm.digest().as_bytes(), &number.to_be_bytes()],
            )),
            origin,
            image_profile: self.image_profile,
            contents: BTreeSet::new(),
            source_vm: handle.vm,
            guest_identity: digest("yougori/test/guest/v1", &[handle.vm.digest().as_bytes()]),
        };
        self.snapshots.push(manifest.clone());
        Ok(manifest)
    }

    fn teardown_perimeter(&mut self, perimeter: &PerimeterId) -> Result<(), BackendFailure> {
        self.calls.push(BackendCall::Teardown(*perimeter));
        self.fail(BackendOperation::TeardownPerimeter)?;
        self.perimeters.remove(perimeter);
        Ok(())
    }

    fn list(&mut self) -> Result<Vec<VmHandle>, BackendFailure> {
        self.calls.push(BackendCall::List);
        self.fail(BackendOperation::List)?;
        Ok(self.live.values().map(|live| live.handle.clone()).collect())
    }
}
