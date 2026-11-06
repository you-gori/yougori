//! Revocation at the enforcement point (VM §6.3 step 2: "closes/invalidates eligible
//! existing channels"; VM-W13: "revocation closes existing sessions"; CORE-04).
//!
//! When CORE-04 revokes a sandbox, its authorization epoch advances and the gate's next
//! look at it finds the epoch it attached under gone: every publication of the sandbox
//! is withdrawn, every session to it and every connection at either end of it is closed,
//! its connection grants are revoked, and the entry ends for good. A policy change (a new
//! policy epoch) closes the same, until the host attaches the sandbox again with its new
//! registration. When the sandbox's authority no longer holds the published-service grant
//! of one service, because CORE-04 tombstoned it, that service's publications are
//! withdrawn and its sessions and inbound connections closed; the sandbox keeps everything
//! else. New sessions and connections are refused from then on, before any byte moves.
//! The gate notices at its next operation on the sandbox, or at once when the host calls
//! [`ConnectionGate::close_revoked`] after a revocation; its status views show it at once.
//!
//! Each closure is reported once, in a typed [`ClosureReport`] that only the gate makes,
//! bound to the sandbox, the authorization epoch and the gate's publication identities.
//! The report covers only what this gate carries: ingress sessions and sandbox
//! connections, the sockets of the selected transport, and the published-service response
//! channel. CORE-04's `SocketsClosed` means every network socket of the sandbox and
//! `AllChannelsClosed` every eligible release channel of §2.5, so the host acknowledges
//! them ([`acknowledge_closure`]) with two inputs: the gate's own proof, which the gate
//! checks again when acknowledging, and the host's observation of the sandbox's channels
//! outside the gate ([`OtherChannels`]). Only a revocation's report acknowledges anything:
//! a policy change or a grant tombstone has no CORE-04 revocation operation.
//!
//! Neither milestone can rest on the gate's record alone. That record is exact for what
//! the gate opened: every session and connection it admitted stays in its tables until it
//! is closed, and [`acknowledge_closure`] refuses while one of the sandbox's is open. But
//! of the release channels of §2.5 ([`ReleaseChannel`]) the gate carries only the
//! published-service responses it admitted itself, over the transport streams of its own
//! sessions and connections. Provider requests, DNS, the transport's other streams, files,
//! terminal output, logs, browser previews, user-approved transfers and any other gate's
//! sessions never pass through it, so only the host can observe them closed;
//! [`OtherChannels`] names exactly what that observation must cover.
//!
//! [`ReleaseChannel`]: crate::sandbox_contract::destinations::ReleaseChannel

use std::collections::BTreeSet;
use std::fmt;

use super::authority::ConnectionAuthority;
use super::gate::{standing, ConnectionGate, ConnectionId, EntryEnd, GatePublicationId, SessionId};
use super::status::PublicationState;
use crate::foundation::coordination::{
    network_grant_id, CapacityPort, CoordinationError, Coordinator, RevocationMilestone,
};
use crate::foundation::evidence::{NetworkGrant, SourceClass};
use crate::foundation::ids::{
    AuthorizationEpoch, Clock, ExecutionId, GrantId, MonotonicTime, PolicyEpoch,
};
use crate::sandbox_contract::destinations::{DestinationPort, SandboxEndpoint, ServiceIdentity};

/// What ended the channels of a report.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClosureCause {
    /// The sandbox no longer holds the authorization epoch it was attached under:
    /// CORE-04 revoked it, or it stopped or its authority expired.
    AuthorityEnded {
        sandbox: ExecutionId,
        epoch: AuthorizationEpoch,
    },
    /// The sandbox's policy epoch moved on from `policy`, the one it was attached under,
    /// within authorization epoch `epoch`.
    PolicyChanged {
        sandbox: ExecutionId,
        epoch: AuthorizationEpoch,
        policy: PolicyEpoch,
    },
    /// The sandbox's authority, at `epoch`, no longer holds the published-service grant of
    /// `service`: CORE-04 tombstoned it.
    GrantRevoked {
        sandbox: ExecutionId,
        epoch: AuthorizationEpoch,
        service: ServiceIdentity,
        grant: GrantId,
    },
}

impl ClosureCause {
    /// The sandbox whose authority, policy or grant ended.
    pub fn sandbox(&self) -> &ExecutionId {
        match self {
            Self::AuthorityEnded { sandbox, .. }
            | Self::PolicyChanged { sandbox, .. }
            | Self::GrantRevoked { sandbox, .. } => sandbox,
        }
    }

    /// The authorization epoch the sandbox was attached under.
    pub const fn epoch(&self) -> AuthorizationEpoch {
        match self {
            Self::AuthorityEnded { epoch, .. }
            | Self::PolicyChanged { epoch, .. }
            | Self::GrantRevoked { epoch, .. } => *epoch,
        }
    }
}

/// An ingress session the gate closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedSession {
    pub session: SessionId,
    pub publication: GatePublicationId,
    pub service: ServiceIdentity,
}

/// A sandbox connection the gate closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosedConnection {
    pub connection: ConnectionId,
    pub caller: SandboxEndpoint,
    pub callee: SandboxEndpoint,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
}

/// Everything one closure closed at this gate. By [`ClosureReport::at`], all of it was
/// closed: both stream ends of every session and connection listed, and no new one is
/// admitted. Only the gate makes one ([`ConnectionGate::close_revoked`]); its fields are
/// read through accessors.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClosureReport {
    cause: ClosureCause,
    at: MonotonicTime,
    withdrawn: Vec<GatePublicationId>,
    sessions: Vec<ClosedSession>,
    connections: Vec<ClosedConnection>,
}

/// The host's own observation of a revoked sandbox's channels outside this gate, the
/// host's input to [`acknowledge_closure`] beside the gate's proof. The gate cannot see
/// these channels and takes the host's word for them. It never needs to cover what the
/// gate's proof covers: the ingress sessions and sandbox connections this gate admitted,
/// with their published-service responses.
///
/// [`ReleaseChannel`]: crate::sandbox_contract::destinations::ReleaseChannel
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct OtherChannels {
    /// For `SocketsClosed`: the host observed closed every network socket of the sandbox
    /// that this gate did not open, its provider requests and destination routes, its DNS
    /// queries and its transport streams outside this gate ([`ReleaseChannel`]s
    /// `ProviderRequest`, `DnsQuery` and `TransportStream`), and every session and
    /// connection of any other gate or transport adapter serving the sandbox.
    pub sockets_closed: bool,
    /// For `AllChannelsClosed`, with `sockets_closed`: the host observed closed every other
    /// eligible release channel of §2.5 as well, the sandbox's files, terminal output,
    /// logs, browser previews and user-approved transfers ([`ReleaseChannel`]s `File`,
    /// `TerminalOutput`, `Log`, `BrowserPreview` and `UserApprovedTransfer`), and the
    /// published-service responses (`PublishedServiceResponse`) of any other gate.
    pub channels_closed: bool,
}

impl ClosureReport {
    /// What ended the channels.
    pub fn cause(&self) -> &ClosureCause {
        &self.cause
    }

    /// The sandbox the report is about.
    pub fn sandbox(&self) -> &ExecutionId {
        self.cause.sandbox()
    }

    /// The authorization epoch the sandbox was attached under.
    pub const fn epoch(&self) -> AuthorizationEpoch {
        self.cause.epoch()
    }

    /// When the gate found the authority, policy or grant gone and closed everything it
    /// covers.
    pub const fn at(&self) -> MonotonicTime {
        self.at
    }

    /// The publications it withdrew.
    pub fn withdrawn(&self) -> &[GatePublicationId] {
        &self.withdrawn
    }

    /// The sessions it closed.
    pub fn sessions(&self) -> &[ClosedSession] {
        &self.sessions
    }

    /// The connections it closed.
    pub fn connections(&self) -> &[ClosedConnection] {
        &self.connections
    }

    /// The CORE-04 milestones the report could support with the host's observation
    /// `others`: none but for a sandbox whose authority ended; then `SocketsClosed` once
    /// every other socket is closed too, and `AllChannelsClosed` once every other release
    /// channel is as well. [`acknowledge_closure`] checks the gate's part again first.
    pub fn acknowledgeable(&self, others: OtherChannels) -> Vec<RevocationMilestone> {
        if !matches!(self.cause, ClosureCause::AuthorityEnded { .. }) || !others.sockets_closed {
            return Vec::new();
        }
        let mut milestones = vec![RevocationMilestone::SocketsClosed];
        if others.channels_closed {
            milestones.push(RevocationMilestone::AllChannelsClosed);
        }
        milestones
    }
}

/// Why [`acknowledge_closure`] acknowledged nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AcknowledgeRefusal {
    /// The gate still holds sessions or connections of the sandbox open.
    ChannelsStillOpen {
        sandbox: ExecutionId,
        sessions: usize,
        connections: usize,
    },
    /// This gate never found the sandbox's authority at that epoch ended: the report is
    /// another gate's.
    NotClosedByThisGate {
        sandbox: ExecutionId,
        epoch: AuthorizationEpoch,
    },
    /// CORE-04 records no revocation of the sandbox: its authority expired, or it stopped
    /// or booted again.
    NoRevocation { sandbox: ExecutionId },
    /// The report is of an earlier epoch than the one the CORE-04 revocation ended.
    StaleEpoch {
        sandbox: ExecutionId,
        reported: AuthorizationEpoch,
        revoked: AuthorizationEpoch,
    },
    /// The coordinator refused the acknowledgment. Boxed: the coordinator's error is
    /// large and this one is rare.
    Coordination(Box<CoordinationError>),
}

impl fmt::Display for AcknowledgeRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChannelsStillOpen {
                sandbox,
                sessions,
                connections,
            } => write!(
                f,
                "the gate still holds {sessions} sessions and {connections} connections of \
                 sandbox {sandbox} open"
            ),
            Self::NotClosedByThisGate { sandbox, epoch } => write!(
                f,
                "this gate never closed sandbox {sandbox} at authorization epoch {epoch}"
            ),
            Self::NoRevocation { sandbox } => {
                write!(f, "CORE-04 records no revocation of sandbox {sandbox}")
            }
            Self::StaleEpoch {
                sandbox,
                reported,
                revoked,
            } => write!(
                f,
                "the report on sandbox {sandbox} is of authorization epoch {reported}, but \
                 the revocation ended epoch {revoked}"
            ),
            Self::Coordination(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for AcknowledgeRefusal {}

/// Acknowledges to CORE-04, as a host observation, what `report` supports with the
/// host's observation `others` ([`ClosureReport::acknowledgeable`]); returns each
/// milestone with when CORE-04 first recorded it. A report of a policy change or a grant
/// tombstone acknowledges nothing. For a revocation's report the gate's proof is checked
/// again first: `gate` holds no session or connection of the sandbox open, `gate` itself
/// closed the sandbox at the report's epoch, and that epoch is the one CORE-04's
/// revocation of the sandbox ended, so a report from an earlier epoch is refused.
pub fn acknowledge_closure<C: Clock, P: CapacityPort>(
    coordinator: &mut Coordinator<C, P>,
    gate: &ConnectionGate,
    report: &ClosureReport,
    others: OtherChannels,
) -> Result<Vec<(RevocationMilestone, MonotonicTime)>, AcknowledgeRefusal> {
    let ClosureCause::AuthorityEnded { sandbox, epoch } = &report.cause else {
        return Ok(Vec::new());
    };
    let (sessions, connections) = gate.open_channels_of(sandbox);
    if sessions > 0 || connections > 0 {
        return Err(AcknowledgeRefusal::ChannelsStillOpen {
            sandbox: sandbox.clone(),
            sessions,
            connections,
        });
    }
    if !gate.authority_closures.contains(&(sandbox.clone(), *epoch)) {
        return Err(AcknowledgeRefusal::NotClosedByThisGate {
            sandbox: sandbox.clone(),
            epoch: *epoch,
        });
    }
    let revoked = coordinator
        .revocation(sandbox)
        .map(|operation| operation.notice().revoked)
        .ok_or_else(|| AcknowledgeRefusal::NoRevocation {
            sandbox: sandbox.clone(),
        })?;
    if revoked != *epoch {
        return Err(AcknowledgeRefusal::StaleEpoch {
            sandbox: sandbox.clone(),
            reported: *epoch,
            revoked,
        });
    }
    report
        .acknowledgeable(others)
        .into_iter()
        .map(|milestone| {
            coordinator
                .acknowledge_revocation(sandbox, milestone, SourceClass::HostProbe)
                .map(|at| (milestone, at))
                .map_err(|error| AcknowledgeRefusal::Coordination(Box::new(error)))
        })
        .collect()
}

impl ConnectionGate {
    /// Closes everything whose sandbox lost its authority, changed its policy or lost a
    /// published-service grant, refuses them from now on, and hands over every closure
    /// report not handed over yet, those of closures found by earlier operations included.
    /// Call it after every CORE-04 revocation or policy change; calling it again reports
    /// nothing new.
    pub fn close_revoked(&mut self, authority: &dyn ConnectionAuthority) -> Vec<ClosureReport> {
        let now = self.tick(authority);
        let sandboxes: Vec<ExecutionId> = self.sandboxes.keys().cloned().collect();
        for sandbox in &sandboxes {
            self.sweep_sandbox(authority, sandbox, now);
        }
        std::mem::take(&mut self.reports)
    }

    /// Closes what `sandbox` lost, and keeps one report per cause.
    pub(super) fn sweep_sandbox(
        &mut self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
        now: MonotonicTime,
    ) {
        let Some(entry) = self.sandboxes.get_mut(sandbox) else {
            return;
        };
        if entry.ended.is_some() {
            return;
        }
        if let Some(end) = standing(authority, sandbox, entry) {
            entry.ended = Some(end);
            let (epoch, policy) = (entry.epoch, entry.policy);
            let withdrawn = entry.withdraw_where(now, |_| true, end.publication_state());
            let sessions = self.close_sessions(|session| session.sandbox == *sandbox);
            let connections = self.close_connections(|connection| connection.touches(sandbox));
            // Grants recorded under the ended entry never carry over to a later one.
            let pairs: Vec<(SandboxEndpoint, SandboxEndpoint)> = self
                .grant_pairs
                .iter()
                .filter(|(caller, callee)| {
                    caller.execution == *sandbox || callee.execution == *sandbox
                })
                .cloned()
                .collect();
            for (caller, callee) in pairs {
                self.grants.revoke(&caller, &callee);
                self.grant_pairs.remove(&(caller, callee));
            }
            let sandbox = sandbox.clone();
            let cause = match end {
                EntryEnd::AuthorityEnded => {
                    self.authority_closures.insert((sandbox.clone(), epoch));
                    ClosureCause::AuthorityEnded { sandbox, epoch }
                }
                EntryEnd::PolicyChanged => ClosureCause::PolicyChanged {
                    sandbox,
                    epoch,
                    policy,
                },
            };
            self.reports.push(ClosureReport {
                cause,
                at: now,
                withdrawn,
                sessions,
                connections,
            });
            return;
        }
        let epoch = entry.epoch;
        // Every service in use, with the grant it was published, admitted or connected
        // under.
        let mut in_use: BTreeSet<(ServiceIdentity, NetworkGrant)> = entry
            .publications
            .values()
            .filter(|publication| entry.is_active(publication.table_id, now))
            .filter_map(|publication| {
                entry
                    .table
                    .publication(publication.table_id)
                    .map(|found| (found.service.clone(), publication.grant))
            })
            .collect();
        in_use.extend(
            self.sessions
                .values()
                .filter(|session| session.sandbox == *sandbox)
                .map(|session| (session.service.clone(), session.grant)),
        );
        in_use.extend(
            self.connections
                .values()
                .filter(|connection| connection.authorization.callee.execution == *sandbox)
                .map(|connection| {
                    (
                        connection.authorization.service.clone(),
                        connection.callee_grant,
                    )
                }),
        );
        for (service, grant) in in_use {
            if authority.holds_network_grant(sandbox, &grant) {
                continue;
            }
            let withdrawn = self
                .sandboxes
                .get_mut(sandbox)
                .map(|entry| {
                    entry.withdraw_where(
                        now,
                        |offered| *offered == service,
                        PublicationState::GrantRevoked,
                    )
                })
                .unwrap_or_default();
            let sessions = self.close_sessions(|session| {
                session.sandbox == *sandbox && session.service == service
            });
            let connections = self.close_connections(|connection| {
                connection.authorization.callee.execution == *sandbox
                    && connection.authorization.service == service
            });
            self.reports.push(ClosureReport {
                cause: ClosureCause::GrantRevoked {
                    sandbox: sandbox.clone(),
                    epoch,
                    service,
                    grant: network_grant_id(&grant),
                },
                at: now,
                withdrawn,
                sessions,
                connections,
            });
        }
    }
}
