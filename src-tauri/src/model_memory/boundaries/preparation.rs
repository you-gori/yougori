//! S3.6: preparing a model never authorizes a new external workflow action.
//!
//! A [`PreparationToken`] lets the flow reserve, transfer inbound, verify, reconstruct,
//! activate and compute ahead for one exact model and request ([`PreparationStep`]).
//! External workflow actions ([`ExternalAction`]) are a separate type. The declared
//! workflow's [`WorkflowPolicy`] (VM-N1) is the only issuer of a [`WorkflowActionGrant`]:
//! the grant has no public constructor, and the policy issues one only for an action the
//! workflow declares, for its own parent execution and authorization epoch, expiring a
//! fixed lifetime after the shared clock's now. The only way to an [`ActionAuthority`] is
//! [`WorkflowPolicy::authorize`], which reads the time from the clock as well, so no
//! caller supplies it. No boundary of the model-memory control plane receives a policy,
//! and a preparation token presented to one is always refused: it converts into neither a
//! grant nor an authority.

use std::collections::BTreeSet;
use std::fmt;
use std::time::Duration;

use serde::Serialize;

use super::governor::PlacementKey;
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, Digest, ExecutionId, MonotonicTime, OperationId, TenantId,
};
use crate::model_memory::identity::ExecutionIdentity;

/// The steps preparing a model consists of. None of them is an external action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PreparationStep {
    Reserve,
    InboundTransfer,
    Verify,
    Reconstruct,
    Activate,
    ComputeAhead,
}

impl PreparationStep {
    pub const ALL: [Self; 6] = [
        Self::Reserve,
        Self::InboundTransfer,
        Self::Verify,
        Self::Reconstruct,
        Self::Activate,
        Self::ComputeAhead,
    ];
}

/// Authority to prepare one exact model for one request, and nothing else (S3.6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparationToken {
    execution: ExecutionId,
    operation: OperationId,
    tenant: TenantId,
    epoch: AuthorizationEpoch,
    placement: PlacementKey,
}

impl PreparationToken {
    /// Issued by the flow after admission; nothing outside the boundaries issues one.
    pub(super) fn issue(
        execution: ExecutionId,
        operation: OperationId,
        tenant: TenantId,
        epoch: AuthorizationEpoch,
        placement: PlacementKey,
    ) -> Self {
        Self {
            execution,
            operation,
            tenant,
            epoch,
            placement,
        }
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn operation(&self) -> &OperationId {
        &self.operation
    }

    pub fn tenant(&self) -> &TenantId {
        &self.tenant
    }

    pub fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    pub fn placement(&self) -> &PlacementKey {
        &self.placement
    }

    /// The one model this token prepares.
    pub fn model(&self) -> ExecutionIdentity {
        self.placement.model
    }

    /// Every step of [`PreparationStep`]; the list holds no external action.
    pub fn steps(&self) -> &'static [PreparationStep] {
        &PreparationStep::ALL
    }
}

/// An effect outside model preparation, declared in a workflow (S3.6, VM-N1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum ExternalAction {
    OutboundNetwork { destination: Digest },
    WriteExternalStore { store: Digest },
    InvokeTool { tool: Digest },
    SendMessage { recipient: Digest },
    PublishOutput { recipient: Digest },
}

/// The external actions a declared workflow allows one parent execution under one
/// authorization epoch (S3.6, VM-N1), and the only issuer of [`WorkflowActionGrant`]s.
/// A policy of a later epoch, such as after a revocation, honours no grant of an earlier
/// one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowPolicy {
    execution: ExecutionId,
    epoch: AuthorizationEpoch,
    declared: BTreeSet<ExternalAction>,
    grant_lifetime: Duration,
}

impl WorkflowPolicy {
    /// The policy of a workflow that declares `declared` for `execution` under `epoch`;
    /// each grant lasts `grant_lifetime`. Crate-private: the workflow layer (VM-N1, not
    /// built yet, so only tests declare one now) declares it, and no boundary of the
    /// model-memory control plane receives a policy, so preparing a model never reaches
    /// an issuer.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn declare(
        execution: ExecutionId,
        epoch: AuthorizationEpoch,
        declared: BTreeSet<ExternalAction>,
        grant_lifetime: Duration,
    ) -> Self {
        Self {
            execution,
            epoch,
            declared,
            grant_lifetime,
        }
    }

    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    /// Whether the workflow declares `action`.
    pub fn declares(&self, action: &ExternalAction) -> bool {
        self.declared.contains(action)
    }

    /// A grant for one action the workflow declares, from the clock's now until the
    /// policy's grant lifetime has passed.
    pub fn issue(
        &self,
        action: ExternalAction,
        clock: &dyn Clock,
    ) -> Result<WorkflowActionGrant, ActionRefusal> {
        if !self.declares(&action) {
            return Err(ActionRefusal::NotDeclared);
        }
        let expires_at = clock
            .now()
            .checked_add(self.grant_lifetime)
            .ok_or(ActionRefusal::ExpiryOverflow)?;
        Ok(WorkflowActionGrant {
            execution: self.execution.clone(),
            epoch: self.epoch,
            action,
            expires_at,
        })
    }

    /// The only way to an [`ActionAuthority`] (S3.6): a grant for exactly the requested
    /// action and execution, of this policy's execution and epoch, for an action the
    /// workflow still declares, unexpired at the clock's now. A preparation token is
    /// always refused.
    pub fn authorize(
        &self,
        credential: ActionCredential<'_>,
        request: &ActionRequest,
        clock: &dyn Clock,
    ) -> Result<ActionAuthority, ActionRefusal> {
        let grant = match credential {
            ActionCredential::Preparation(_) => {
                return Err(ActionRefusal::PreparationIsNotActionAuthority)
            }
            ActionCredential::Workflow(grant) => grant,
        };
        if grant.action != request.action {
            return Err(ActionRefusal::ActionNotGranted);
        }
        if !self.declares(&grant.action) {
            return Err(ActionRefusal::NotDeclared);
        }
        if grant.execution != request.execution || grant.execution != self.execution {
            return Err(ActionRefusal::OtherExecution);
        }
        if grant.epoch != self.epoch {
            return Err(ActionRefusal::OtherEpoch);
        }
        if clock.now() >= grant.expires_at {
            return Err(ActionRefusal::Expired);
        }
        Ok(ActionAuthority {
            execution: grant.execution.clone(),
            epoch: grant.epoch,
            action: grant.action,
        })
    }
}

/// A grant for exactly one external action. Only [`WorkflowPolicy::issue`] makes one; it
/// has no public constructor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowActionGrant {
    execution: ExecutionId,
    epoch: AuthorizationEpoch,
    action: ExternalAction,
    expires_at: MonotonicTime,
}

impl WorkflowActionGrant {
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    pub fn action(&self) -> ExternalAction {
        self.action
    }

    /// When the grant ends, on the policy's clock.
    pub fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }
}

/// What a caller presents for an external action.
#[derive(Clone, Copy, Debug)]
pub enum ActionCredential<'a> {
    Preparation(&'a PreparationToken),
    Workflow(&'a WorkflowActionGrant),
}

/// One external action asked for. It carries no time and no epoch: the time is the
/// policy's clock and the epoch the policy's.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionRequest {
    pub execution: ExecutionId,
    pub action: ExternalAction,
}

/// Proof that a workflow grant authorized one external action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionAuthority {
    execution: ExecutionId,
    epoch: AuthorizationEpoch,
    action: ExternalAction,
}

impl ActionAuthority {
    pub fn execution(&self) -> &ExecutionId {
        &self.execution
    }

    pub fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    pub fn action(&self) -> ExternalAction {
        self.action
    }
}

/// Why an external action was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum ActionRefusal {
    /// Preparing a model never authorizes a new external workflow action (S3.6).
    PreparationIsNotActionAuthority,
    /// The workflow does not declare the action, so no grant for it is issued or
    /// honoured.
    NotDeclared,
    ActionNotGranted,
    OtherExecution,
    OtherEpoch,
    Expired,
    /// The grant's expiry does not fit on the clock.
    ExpiryOverflow,
}

impl fmt::Display for ActionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PreparationIsNotActionAuthority => {
                "preparing a model does not authorize an external workflow action"
            }
            Self::NotDeclared => "the workflow does not declare the action",
            Self::ActionNotGranted => "the workflow grant names another action",
            Self::OtherExecution => "the workflow grant belongs to another execution",
            Self::OtherEpoch => "the workflow grant belongs to another authorization epoch",
            Self::Expired => "the workflow grant has expired",
            Self::ExpiryOverflow => "the workflow grant's expiry does not fit on the clock",
        })
    }
}

impl std::error::Error for ActionRefusal {}
