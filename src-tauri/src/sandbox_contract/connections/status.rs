//! What the gate shows the host (VM-W13: "keep audiences and outgoing response budgets
//! visible").
//!
//! One status per publication, ended ones included: its audience and authentication
//! exactly as V02 recorded them, its expiry, its outgoing response budget and why it no
//! longer admits callers, if it does not; one per open session, with whom it was admitted
//! as and until when its proof holds; and one per open connection, with its budget each
//! way. A publication's state reads CORE-04 as it stands, so a revocation, a policy
//! change or a lost grant shows at once, before any sweep closes what it covers. These
//! views are the host's: an outside caller is never told why a service is not served.

use std::time::Duration;

use super::authority::ConnectionAuthority;
use super::broker::ConnectionBudget;
use super::gate::{standing, ConnectionGate, ConnectionId, GatePublicationId, SessionId};
use super::ingress::AdmittedAs;
use crate::foundation::ids::{ExecutionId, MonotonicTime};
use crate::sandbox_contract::destinations::{
    Audience, AuthenticationMode, DestinationPort, SandboxEndpoint, ServiceIdentity,
};

/// Whether a publication admits callers now, and why not if it does not.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PublicationState {
    Active,
    /// Its outgoing response budget is spent, so it answers no one.
    ResponseBudgetSpent,
    /// Its expiry passed on the shared clock.
    Expired,
    /// The host withdrew it.
    Withdrawn,
    /// The sandbox no longer holds the authorization epoch it was attached under.
    AuthorityEnded,
    /// The sandbox's policy epoch changed since it was attached.
    PolicyChanged,
    /// The sandbox's authority no longer holds the service's published-service grant.
    GrantRevoked,
}

/// A byte budget and its use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ByteBudgetView {
    pub limit_bytes: u64,
    pub used_bytes: u64,
    pub remaining_bytes: u64,
}

impl ByteBudgetView {
    fn of(limit_bytes: u64, used_bytes: u64) -> Self {
        Self {
            limit_bytes,
            used_bytes,
            remaining_bytes: limit_bytes.saturating_sub(used_bytes),
        }
    }
}

/// One publication as the gate shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationStatus {
    pub sandbox: ExecutionId,
    pub publication: GatePublicationId,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    /// Who may reach it, as published; never relabelled.
    pub audience: Audience,
    pub authentication: AuthenticationMode,
    pub expires_at: MonotonicTime,
    /// Time left before it expires, zero once it has.
    pub remaining_lifetime: Duration,
    pub state: PublicationState,
    /// The outgoing response budget, which guest responses spend.
    pub response_budget: ByteBudgetView,
    pub open_sessions: usize,
    pub sessions_admitted: u64,
}

/// One open ingress session as the gate shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStatus {
    pub session: SessionId,
    pub sandbox: ExecutionId,
    pub publication: GatePublicationId,
    pub service: ServiceIdentity,
    /// Whom it was admitted as: a private session always names its principal.
    pub admitted_as: AdmittedAs,
    /// When the proof it was admitted on stops holding, if it was admitted on one.
    pub proof_valid_until: Option<MonotonicTime>,
    pub request_bytes: u64,
    /// Guest response bytes sent, each charged first.
    pub response_bytes: u64,
}

/// One open sandbox connection as the gate shows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionStatus {
    pub connection: ConnectionId,
    pub caller: SandboxEndpoint,
    pub callee: SandboxEndpoint,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    pub caller_to_callee: ByteBudgetView,
    pub callee_to_caller: ByteBudgetView,
}

impl ConnectionGate {
    /// Every publication of `sandbox`'s current attachment, in publication order.
    pub fn publication_status(
        &self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
    ) -> Vec<PublicationStatus> {
        let now = self.peek_now(authority);
        let Some(entry) = self.sandboxes.get(sandbox) else {
            return Vec::new();
        };
        // What CORE-04 shows now, before any sweep acts on it.
        let lost = entry
            .ended
            .or_else(|| standing(authority, sandbox, entry))
            .map(|end| end.publication_state());
        entry
            .publications
            .iter()
            .filter_map(|(id, budget)| {
                let publication = entry.table.publication(budget.table_id)?;
                let state = if let Some(ended) = budget.ended_as {
                    ended
                } else if !entry.is_active(budget.table_id, now) {
                    if now >= publication.expires_at {
                        PublicationState::Expired
                    } else {
                        PublicationState::Withdrawn
                    }
                } else if let Some(lost) = lost {
                    lost
                } else if !authority.holds_network_grant(sandbox, &budget.grant) {
                    PublicationState::GrantRevoked
                } else if budget.remaining() == 0 {
                    PublicationState::ResponseBudgetSpent
                } else {
                    PublicationState::Active
                };
                Some(PublicationStatus {
                    sandbox: sandbox.clone(),
                    publication: *id,
                    service: publication.service.clone(),
                    port: publication.port,
                    audience: publication.audience.clone(),
                    authentication: publication.authentication,
                    expires_at: publication.expires_at,
                    remaining_lifetime: publication.expires_at.saturating_duration_since(now),
                    state,
                    response_budget: ByteBudgetView::of(
                        budget.response_budget_bytes,
                        budget.response_used_bytes,
                    ),
                    open_sessions: self
                        .sessions
                        .values()
                        .filter(|session| session.sandbox == *sandbox && session.publication == *id)
                        .count(),
                    sessions_admitted: budget.sessions_admitted,
                })
            })
            .collect()
    }

    /// Every open ingress session, in admission order.
    pub fn session_status(&self) -> Vec<SessionStatus> {
        self.sessions
            .iter()
            .map(|(id, entry)| SessionStatus {
                session: *id,
                sandbox: entry.sandbox.clone(),
                publication: entry.publication,
                service: entry.service.clone(),
                admitted_as: entry.admitted_as.clone(),
                proof_valid_until: entry.proof_valid_until,
                request_bytes: entry.request_bytes,
                response_bytes: entry.response_bytes,
            })
            .collect()
    }

    /// Every open connection, in connection order.
    pub fn connection_status(&self) -> Vec<ConnectionStatus> {
        self.connections
            .iter()
            .map(|(id, entry)| {
                let budget: ConnectionBudget = entry.budget;
                ConnectionStatus {
                    connection: *id,
                    caller: entry.authorization.caller.clone(),
                    callee: entry.authorization.callee.clone(),
                    service: entry.authorization.service.clone(),
                    port: entry.authorization.port,
                    caller_to_callee: ByteBudgetView::of(
                        budget.caller_to_callee_bytes,
                        entry.caller_to_callee_bytes,
                    ),
                    callee_to_caller: ByteBudgetView::of(
                        budget.callee_to_caller_bytes,
                        entry.callee_to_caller_bytes,
                    ),
                }
            })
            .collect()
    }
}
