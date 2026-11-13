//! Remote control is a second gate on this same real VM, never another ledger or
//! lifecycle. The engine verifies V12 frames and owns all request timestamps; a
//! stdio bridge may forward them but cannot pause, replace or extend the clock.

use std::time::Duration;

use serde::Serialize;

use super::state::Core;
use super::{LaunchSpec, SandboxId, VmPorts, VmService, VmServiceError};
use crate::foundation::coordination::LeaseKind;
use crate::foundation::ids::{ExecutionId, LeaseId, MonotonicTime, OperationId};
use crate::sandbox::lifecycle::{CallTerms, LimitKind, RevocationCause};
use crate::sandbox_contract::remote::{
    ControlBody, ControlKey, ControlPeer, GrantRef, RemoteGrantBound, RemoteGrantWindow,
    SealedFrame,
};

pub const REMOTE_BOOTSTRAP: Duration = Duration::from_secs(30);
pub const MAX_REMOTE_TTL: Duration = Duration::from_secs(60);

fn error(detail: impl ToString) -> VmServiceError {
    VmServiceError::RemoteControl {
        detail: detail.to_string(),
    }
}

pub(super) fn earliest(a: Option<Duration>, b: Option<Duration>) -> Option<Duration> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

pub(super) struct RemoteControl {
    peer: Option<ControlPeer>,
    window: RemoteGrantWindow,
    pending: Option<(RemoteGrantWindow, RemoteGrantBound)>,
    lease: Option<LeaseId>,
    closed: bool,
}

impl RemoteControl {
    pub(super) fn remaining(&self, now: MonotonicTime) -> Duration {
        let current = self.window.remaining(now);
        self.pending
            .as_ref()
            .map_or(current, |(window, _)| current.min(window.remaining(now)))
    }
    pub(super) fn view(&self, now: MonotonicTime) -> RemoteControlView {
        RemoteControlView {
            connected: self.peer.is_some() && !self.closed,
            closed: self.closed,
            lease: self.lease,
            remaining_ms: self.remaining(now).as_millis(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteControlView {
    pub connected: bool,
    pub closed: bool,
    pub lease: Option<LeaseId>,
    pub remaining_ms: u128,
}

impl<P: VmPorts> VmService<P> {
    /// Bootstrap an empty VM under a short independently enforced bound. Its ID is
    /// not returned until the additional gate is armed. No workload, route, image,
    /// published service or connection is installed before delegation.
    pub fn launch_remote(&self, spec: LaunchSpec) -> Result<SandboxId, VmServiceError> {
        self.launch_remote_identified(spec, ExecutionId::generate())
    }

    pub(crate) fn launch_remote_identified(
        &self,
        spec: LaunchSpec,
        execution: ExecutionId,
    ) -> Result<SandboxId, VmServiceError> {
        if spec.workload_image.is_some()
            || spec.internet
            || spec.targets.is_some()
            || !spec.egress_endpoints.is_empty()
            || !spec.published.is_empty()
            || !spec.connect.is_empty()
        {
            return Err(error("remote bootstrap must be an empty VM"));
        }
        self.launch_identified(spec, execution, true)
    }

    pub fn remote_open(
        &self,
        sandbox: &SandboxId,
        key: ControlKey,
        opening: &SealedFrame,
    ) -> Result<SealedFrame, VmServiceError> {
        let mut core = self.shared.lock();
        let result = core.open_remote(sandbox, key, opening);
        if result.is_err() {
            core.end_remote(sandbox.execution());
        }
        self.shared.notify();
        result
    }

    pub fn remote_frame(
        &self,
        sandbox: &SandboxId,
        frame: &SealedFrame,
    ) -> Result<Option<RemoteGrantBound>, VmServiceError> {
        let mut core = self.shared.lock();
        let result = core.receive_remote(sandbox, frame);
        if result.is_err() {
            core.end_remote(sandbox.execution());
        }
        self.shared.notify();
        result
    }

    /// Complete a prepared grant only AFTER the native supervisor acknowledged
    /// its deadline. Until then the old window stays in force, and bootstrap has
    /// no workload authority. This is deliberately not an exposed IPC operation.
    pub fn commit_remote_grant(
        &self,
        sandbox: &SandboxId,
        bound: RemoteGrantBound,
    ) -> Result<(), VmServiceError> {
        let mut core = self.shared.lock();
        let result = core.commit_remote_grant(sandbox, bound);
        if result.is_err() {
            core.end_remote(sandbox.execution());
        }
        self.shared.notify();
        result
    }

    /// Called by the bridge at a bounded interval. This emits only a heartbeat or
    /// a request; it never locally renews the child lease.
    pub fn remote_poll(&self, sandbox: &SandboxId) -> Result<SealedFrame, VmServiceError> {
        let mut core = self.shared.lock();
        let result = core.poll_remote(sandbox);
        if result.is_err() {
            core.end_remote(sandbox.execution());
        }
        self.shared.notify();
        result
    }

    pub fn remote_close(&self, sandbox: &SandboxId) {
        self.shared.lock().end_remote(sandbox.execution());
        self.shared.notify();
    }

    pub fn remote_view(&self, sandbox: &SandboxId) -> Option<RemoteControlView> {
        let core = self.shared.lock();
        let now = core.now()?;
        let remote = core.boots.get(sandbox.execution())?.remote.as_ref()?;
        Some(remote.view(now))
    }
}

impl<P: VmPorts> Core<P> {
    pub(super) fn arm_remote(&mut self, sandbox: &SandboxId) -> Result<(), VmServiceError> {
        self.ready_boot(sandbox)?;
        let now = self.now().ok_or(VmServiceError::ShuttingDown)?;
        let window =
            RemoteGrantWindow::new(now, REMOTE_BOOTSTRAP, MAX_REMOTE_TTL).map_err(error)?;
        let boot = self
            .boots
            .get_mut(sandbox.execution())
            .ok_or_else(|| error("unknown boot"))?;
        if boot.remote.is_some() || !boot.running.is_empty() {
            return Err(error("boot already used"));
        }
        boot.remote = Some(RemoteControl {
            peer: None,
            window,
            pending: None,
            lease: None,
            closed: false,
        });
        Ok(())
    }

    fn remote_mut(&mut self, sandbox: &SandboxId) -> Result<&mut RemoteControl, VmServiceError> {
        self.boots
            .get_mut(sandbox.execution())
            .and_then(|boot| boot.remote.as_mut())
            .ok_or_else(|| error("this boot is not a remote bootstrap"))
    }

    fn open_remote(
        &mut self,
        sandbox: &SandboxId,
        key: ControlKey,
        opening: &SealedFrame,
    ) -> Result<SealedFrame, VmServiceError> {
        self.ready_boot(sandbox)?;
        let now = self.now().ok_or(VmServiceError::ShuttingDown)?;
        let remote = self.remote_mut(sandbox)?;
        remote.window.check(now).map_err(error)?;
        if remote.peer.is_some() {
            return Err(error("reconnect requires a new VM and delegation"));
        }
        let mut peer = ControlPeer::open(key, opening).map_err(error)?;
        let answer = peer.seal_outbound(ControlBody::Heartbeat).map_err(error)?;
        remote.peer = Some(peer);
        Ok(answer)
    }

    fn poll_remote(&mut self, sandbox: &SandboxId) -> Result<SealedFrame, VmServiceError> {
        self.ready_boot(sandbox)?;
        let now = self.now().ok_or(VmServiceError::ShuttingDown)?;
        self.check_remote_lease(sandbox)?;
        let remote = self.remote_mut(sandbox)?;
        let renewal = if remote.pending.is_some() {
            None
        } else {
            remote.window.request_if_due(now).map_err(error)?
        };
        let body = renewal.map_or(ControlBody::Heartbeat, |(authority, clock)| {
            ControlBody::RenewalRequest { authority, clock }
        });
        remote
            .peer
            .as_mut()
            .ok_or_else(|| error("control channel is not open"))?
            .seal_outbound(body)
            .map_err(error)
    }

    fn receive_remote(
        &mut self,
        sandbox: &SandboxId,
        frame: &SealedFrame,
    ) -> Result<Option<RemoteGrantBound>, VmServiceError> {
        self.ready_boot(sandbox)?;
        let now = self.now().ok_or(VmServiceError::ShuttingDown)?;
        self.check_remote_lease(sandbox)?;
        let remote = self.remote_mut(sandbox)?;
        remote.window.check(now).map_err(error)?;
        let body = remote
            .peer
            .as_mut()
            .ok_or_else(|| error("control channel is not open"))?
            .accept(frame)
            .map_err(error)?;
        match body {
            ControlBody::Heartbeat => Ok(None),
            ControlBody::Stop => {
                self.end_remote(sandbox.execution());
                Ok(None)
            }
            ControlBody::Grant { grant } => {
                if !matches!(grant.authority, GrantRef::Lease { .. }) {
                    return Err(error(
                        "a VM requires a parent-bound lease, not labelled runtime authority",
                    ));
                }
                if remote.pending.is_some() {
                    return Err(error("another grant is awaiting independent enforcement"));
                }
                let mut candidate = remote.window.clone();
                let bound = candidate.accept(grant, now).map_err(error)?;
                remote.pending = Some((candidate, bound));
                Ok(Some(bound))
            }
            _ => Err(error("the host sent a remote-only control message")),
        }
    }

    fn commit_remote_grant(
        &mut self,
        sandbox: &SandboxId,
        expected: RemoteGrantBound,
    ) -> Result<(), VmServiceError> {
        self.ready_boot(sandbox)?;
        let now = self.now().ok_or(VmServiceError::ShuttingDown)?;
        let remote = self.remote_mut(sandbox)?;
        remote.window.check(now).map_err(error)?;
        let (mut candidate, bound) = remote
            .pending
            .take()
            .ok_or_else(|| error("no grant awaits independent enforcement"))?;
        if bound != expected {
            return Err(error("the prepared delegation changed"));
        }
        candidate.check(now).map_err(error)?;
        self.apply_remote_grant(sandbox, bound)?;
        self.remote_mut(sandbox)?.window = candidate;
        Ok(())
    }

    fn apply_remote_grant(
        &mut self,
        sandbox: &SandboxId,
        bound: RemoteGrantBound,
    ) -> Result<(), VmServiceError> {
        let old = self.remote_mut(sandbox)?.lease;
        let host = self.host.as_mut().ok_or(VmServiceError::ShuttingDown)?;
        let next = host.with_supervisor(|supervisor, backend, _| {
            if let Some(old) = old {
                supervisor.coordinator().check_lease(old).map_err(error)?;
            }
            let lease = supervisor
                .authorize_observed_work_until(
                    sandbox.execution(),
                    OperationId::generate(),
                    LeaseKind::Service,
                    CallTerms {
                        per_call: MAX_REMOTE_TTL,
                        task: MAX_REMOTE_TTL,
                    },
                    Default::default(),
                    Some(bound.expires_at),
                    backend,
                )
                .map_err(error)?;
            let coordinator = supervisor.coordinator_mut();
            if let Some(old) = old {
                // A readiness probe can block. It must not bridge a gap in the old
                // authority while replacing its child lease.
                if let Err(refusal) = coordinator.check_lease(old) {
                    let _ = coordinator.release_lease(lease.id());
                    return Err(error(refusal));
                }
                if let Err(refusal) = coordinator.release_lease(old) {
                    let _ = coordinator.release_lease(lease.id());
                    return Err(error(refusal));
                }
            }
            Ok(lease.id())
        })?;
        self.remote_mut(sandbox)?.lease = Some(next);
        self.absorb_log();
        Ok(())
    }

    fn check_remote_lease(&self, sandbox: &SandboxId) -> Result<(), VmServiceError> {
        let lease = self
            .boots
            .get(sandbox.execution())
            .and_then(|boot| boot.remote.as_ref())
            .and_then(|remote| remote.lease);
        if let Some(lease) = lease {
            self.host
                .as_ref()
                .ok_or(VmServiceError::ShuttingDown)?
                .supervisor()
                .coordinator()
                .check_lease(lease)
                .map_err(error)?;
        }
        Ok(())
    }

    pub(super) fn authorize_remote(&mut self, sandbox: &SandboxId) -> Result<(), VmServiceError> {
        let now = self.now().ok_or(VmServiceError::ShuttingDown)?;
        let Some(remote) = self
            .boots
            .get_mut(sandbox.execution())
            .and_then(|boot| boot.remote.as_mut())
        else {
            return Ok(());
        };
        remote.window.authorize(now).map_err(error)?;
        if remote.lease.is_none() {
            return Err(error("no real VM delegation lease"));
        }
        self.check_remote_lease(sandbox)
    }

    pub(super) fn close_remote(&mut self, sandbox: &ExecutionId) {
        let lease = self
            .boots
            .get_mut(sandbox)
            .and_then(|boot| boot.remote.as_mut())
            .and_then(|remote| {
                remote.closed = true;
                remote.window.close();
                remote.pending = None;
                if let Some(peer) = remote.peer.as_mut() {
                    peer.close();
                }
                remote.lease.take()
            });
        if let (Some(lease), Some(host)) = (lease, self.host.as_mut()) {
            host.with_supervisor(|supervisor, _, _| {
                let _ = supervisor.coordinator_mut().release_lease(lease);
            });
        }
    }

    fn end_remote(&mut self, sandbox: &ExecutionId) {
        // Never let a malformed remote operation stop an unrelated ordinary VM.
        if self
            .boots
            .get(sandbox)
            .is_some_and(|boot| boot.remote.is_some())
        {
            let _ = self.end(
                sandbox,
                RevocationCause::LeaseExpired {
                    kind: LimitKind::ServiceRenewal,
                },
            );
        }
    }

    pub(super) fn tick_remote(&mut self) {
        let Some(now) = self.now() else {
            return;
        };
        let mut ended = Vec::new();
        for (id, boot) in &mut self.boots {
            if let Some(remote) = boot.remote.as_mut() {
                if !remote.closed
                    && (remote.window.check(now).is_err()
                        || remote
                            .pending
                            .as_mut()
                            .is_some_and(|(window, _)| window.check(now).is_err()))
                {
                    ended.push(id.clone());
                }
            }
        }
        for (id, boot) in &self.boots {
            if boot
                .remote
                .as_ref()
                .is_some_and(|remote| !remote.closed && remote.lease.is_some())
                && self
                    .check_remote_lease(&SandboxId::new(id.clone()))
                    .is_err()
                && !ended.contains(id)
            {
                ended.push(id.clone());
            }
        }
        for id in ended {
            self.end_remote(&id);
        }
    }
}
