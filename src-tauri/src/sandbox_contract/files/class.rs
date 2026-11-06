//! Per-class responses to engine death, GUI closure and clear violations (VM part §6.2
//! line 2127; VM-D7 and VM-D10, lines 3026 and 3029).
//!
//! VM-D7 (accepted: per class): when the engine dies, task sandboxes end with it and
//! service sandboxes continue under supervisor leases. Either way new privileged
//! authorizations are denied until reconciliation, existing operations follow their
//! bounded leases, and an engine death is not a security incident. Routine GUI closure
//! ends neither class.
//!
//! VM-D10 (accepted: the split): on a clear violation authority is revoked at once for
//! every class. Ephemeral sandboxes then stop; service sandboxes lock down, holding no
//! authority, with a one-click stop. VM-D10's "ephemeral" is read as the task class.
//! Revocation and termination run through the coordination protocol (CORE-04).

use serde::{Deserialize, Serialize};

use crate::foundation::coordination::{
    CapacityPort, CoordinationError, Coordinator, RevocationNotice, RevocationStatus, SandboxPort,
};
use crate::foundation::ids::{Clock, ExecutionId};

/// A sandbox's lifetime class (VM-D7, VM-D10, VM-D12).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxClass {
    /// A task sandbox; VM-D10's ephemeral sandbox.
    Task,
    Service,
}

/// What happens to a sandbox when the engine dies (VM-D7).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineDeathAction {
    EndWithEngine,
    ContinueUnderSupervisorLeases,
}

/// New privileged authorizations after an engine failure (line 2127).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NewAuthorizations {
    DeniedUntilReconciliation,
}

/// Existing operations after an engine failure (line 2127).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExistingOperations {
    /// They end with their sandbox, within their leases' declared cancel bounds.
    EndWithSandbox,
    /// They follow their bounded leases; nothing renews them before reconciliation.
    FollowBoundedLeases,
}

/// The VM-D7 response for one class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct EngineDeathResponse {
    pub class: SandboxClass,
    pub action: EngineDeathAction,
    pub new_privileged_authorizations: NewAuthorizations,
    pub existing_operations: ExistingOperations,
    /// An engine death is not a security incident (line 2127); never true.
    pub treated_as_violation: bool,
}

/// VM-D7: task sandboxes end with the engine, service sandboxes continue under
/// supervisor leases.
pub fn engine_death_response(class: SandboxClass) -> EngineDeathResponse {
    let (action, existing_operations) = match class {
        SandboxClass::Task => (
            EngineDeathAction::EndWithEngine,
            ExistingOperations::EndWithSandbox,
        ),
        SandboxClass::Service => (
            EngineDeathAction::ContinueUnderSupervisorLeases,
            ExistingOperations::FollowBoundedLeases,
        ),
    };
    EngineDeathResponse {
        class,
        action,
        new_privileged_authorizations: NewAuthorizations::DeniedUntilReconciliation,
        existing_operations,
        treated_as_violation: false,
    }
}

/// What closing the GUI does to a sandbox (line 2127).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GuiClosedResponse {
    pub class: SandboxClass,
    /// Routine GUI closure destroys no sandbox; the supervisor owns VM lifetimes.
    pub sandbox_continues: bool,
}

/// Routine GUI closure ends no sandbox of either class.
pub fn gui_closed_response(class: SandboxClass) -> GuiClosedResponse {
    GuiClosedResponse {
        class,
        sandbox_continues: true,
    }
}

/// The VM-D10 response to a clear violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationAction {
    /// Revoke, then stop and clean up.
    Stop,
    /// Revoke and keep the VM without authority until the user stops it.
    LockDown,
}

impl ViolationAction {
    /// VM-D10: ephemeral (task) sandboxes stop; service sandboxes lock down.
    pub const fn for_class(class: SandboxClass) -> Self {
        match class {
            SandboxClass::Task => Self::Stop,
            SandboxClass::Service => Self::LockDown,
        }
    }
}

/// The one action that stops a locked-down service sandbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OneClickStop {
    execution: ExecutionId,
}

impl OneClickStop {
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    /// Stops the sandbox: the revocation advances to termination and cleanup.
    pub fn stop<C: Clock, P: CapacityPort>(
        &self,
        coordinator: &mut Coordinator<C, P>,
        port: &mut dyn SandboxPort,
    ) -> Result<RevocationStatus, CoordinationError> {
        coordinator.advance_revocation(&self.execution, port)
    }
}

/// How the response to a violation went.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViolationOutcome {
    /// Authority revoked and the stop under way or done.
    Stopping {
        notice: RevocationNotice,
        status: RevocationStatus,
    },
    /// Authority revoked; the VM stays, locked down, until the one-click stop.
    LockedDown {
        notice: RevocationNotice,
        stop: OneClickStop,
    },
}

/// VM-D10: revokes `execution` at once, then stops a task sandbox or locks down a service
/// sandbox.
pub fn respond_to_violation<C: Clock, P: CapacityPort>(
    coordinator: &mut Coordinator<C, P>,
    execution: &ExecutionId,
    class: SandboxClass,
    port: &mut dyn SandboxPort,
) -> Result<ViolationOutcome, CoordinationError> {
    let notice = coordinator.revoke(execution)?;
    match ViolationAction::for_class(class) {
        ViolationAction::Stop => {
            let status = coordinator.advance_revocation(execution, port)?;
            Ok(ViolationOutcome::Stopping { notice, status })
        }
        ViolationAction::LockDown => Ok(ViolationOutcome::LockedDown {
            notice,
            stop: OneClickStop {
                execution: execution.clone(),
            },
        }),
    }
}
