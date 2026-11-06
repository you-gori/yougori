//! The connection broker (VM §4.7: "connections between sandboxes require explicit grants
//! at both ends. Transitive access is not inferred").
//!
//! A connection runs only while V02's [`SandboxConnections`] holds an unexpired grant from
//! each end naming exactly this caller, callee (with the trust scope the host attached
//! it under), service and port. Grants are recorded under each end's own network mode,
//! and nothing is inferred from a chain of grants. Each connection carries a byte budget
//! in each direction; the callee's responses are charged to the callee's release account
//! too (V02: guest responses are outbound data). A connection to a callee's service is
//! covered by the callee's published-service grant for that service: the callee's
//! registration must name the service and its current authority must hold that grant, at
//! the grant, at the connection and at every pump, so tombstoning it closes the connection.
//!
//! [`SandboxConnections`]: crate::sandbox_contract::destinations::SandboxConnections

use super::authority::{ConnectionAuthority, ReleaseAccounts};
use super::gate::{
    byte_count, read_limit, CloseReason, ConnectionEntry, ConnectionGate, ConnectionId,
    GateRefusal, Pumped,
};
use super::ingress::{closed_after, overlong_read};
use super::stream::{SessionStream, StreamRead};
use crate::foundation::coordination::network_grant_id;
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{ExecutionId, MonotonicTime};
use crate::sandbox_contract::destinations::{
    ConnectionAuthorization, ConnectionGrant, ConnectionRefusal, DestinationPort, NetworkMode,
    SandboxConnections, SandboxEndpoint, ServiceIdentity,
};

/// One direction of a sandbox connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Direction {
    CallerToCallee,
    CalleeToCaller,
}

/// The most bytes a connection may carry each way.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionBudget {
    pub caller_to_callee_bytes: u64,
    pub callee_to_caller_bytes: u64,
}

impl ConnectionBudget {
    /// The limit of one direction.
    pub const fn limit(&self, direction: Direction) -> u64 {
        match direction {
            Direction::CallerToCallee => self.caller_to_callee_bytes,
            Direction::CalleeToCaller => self.callee_to_caller_bytes,
        }
    }
}

/// A request to connect two attached sandboxes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionRequest {
    pub caller: ExecutionId,
    pub callee: ExecutionId,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    pub budget: ConnectionBudget,
}

/// An open sandbox connection. It carries no route grants: the caller gains nothing of
/// the callee's own authority (V02).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionHandle {
    id: ConnectionId,
    authorization: ConnectionAuthorization,
    budget: ConnectionBudget,
}

impl ConnectionHandle {
    pub const fn id(&self) -> ConnectionId {
        self.id
    }

    pub fn authorization(&self) -> &ConnectionAuthorization {
        &self.authorization
    }

    pub const fn budget(&self) -> ConnectionBudget {
        self.budget
    }
}

impl ConnectionGate {
    /// Records the caller's copy of a connection grant, under the caller's network mode.
    /// The caller must be attached under exactly the grant's endpoint and hold its
    /// authority.
    pub fn grant_outbound(
        &mut self,
        authority: &dyn ConnectionAuthority,
        grant: ConnectionGrant,
    ) -> Result<(), GateRefusal> {
        let now = self.tick(authority);
        let caller = grant.caller.execution.clone();
        self.check_authority(authority, &caller, now)?;
        let mode = self.attached_mode(&grant.caller)?;
        let pair = (grant.caller.clone(), grant.callee.clone());
        self.grants
            .grant_outbound(mode, grant, now)
            .map_err(GateRefusal::Connection)?;
        self.grant_pairs.insert(pair);
        Ok(())
    }

    /// Records the callee's copy of a connection grant, under the callee's network mode.
    /// The callee must be attached under exactly the grant's endpoint, hold the epochs it
    /// was attached under and the service's published-service grant.
    pub fn grant_inbound(
        &mut self,
        authority: &dyn ConnectionAuthority,
        grant: ConnectionGrant,
    ) -> Result<(), GateRefusal> {
        let now = self.tick(authority);
        let callee = grant.callee.execution.clone();
        self.check_authority(authority, &callee, now)?;
        self.check_service(authority, &callee, &grant.service, now)?;
        let mode = self.attached_mode(&grant.callee)?;
        let pair = (grant.caller.clone(), grant.callee.clone());
        self.grants
            .grant_inbound(mode, grant, now)
            .map_err(GateRefusal::Connection)?;
        self.grant_pairs.insert(pair);
        Ok(())
    }

    /// Revokes both copies of the grant from `caller` to `callee` for `service` on `port`;
    /// its open connections close and are returned. Any other grant between them stands.
    pub fn revoke_connection_grant(
        &mut self,
        caller: &SandboxEndpoint,
        callee: &SandboxEndpoint,
        service: &ServiceIdentity,
        port: DestinationPort,
    ) -> Vec<ConnectionId> {
        self.grants.revoke_service(caller, callee, service, port);
        if !self.grants.any_between(caller, callee) {
            self.grant_pairs.remove(&(caller.clone(), callee.clone()));
        }
        self.close_connections(|entry| {
            entry.authorization.caller == *caller
                && entry.authorization.callee == *callee
                && entry.authorization.service == *service
                && entry.authorization.port == port
        })
        .into_iter()
        .map(|closed| closed.connection)
        .collect()
    }

    /// Revokes both copies of every grant from `caller` to `callee`; their open
    /// connections close. Returns them.
    pub fn revoke_connection_grants(
        &mut self,
        caller: &SandboxEndpoint,
        callee: &SandboxEndpoint,
    ) -> Vec<ConnectionId> {
        self.grants.revoke(caller, callee);
        self.grant_pairs.remove(&(caller.clone(), callee.clone()));
        self.close_connections(|entry| {
            entry.authorization.caller == *caller && entry.authorization.callee == *callee
        })
        .into_iter()
        .map(|closed| closed.connection)
        .collect()
    }

    /// Connects two attached sandboxes, joining the caller's stream end to the callee's.
    /// Both must hold the epochs they were attached under, the callee the service's
    /// published-service grant, and V02 must hold a grant from each end. On a refusal both
    /// ends are closed.
    pub fn connect(
        &mut self,
        authority: &dyn ConnectionAuthority,
        request: ConnectionRequest,
        mut caller: Box<dyn SessionStream>,
        mut callee: Box<dyn SessionStream>,
    ) -> Result<ConnectionHandle, GateRefusal> {
        let (authorization, callee_grant) = match self.connect_checked(authority, &request) {
            Ok(checked) => checked,
            Err(refusal) => {
                caller.close();
                callee.close();
                return Err(refusal);
            }
        };
        let id = self.next_connection_id();
        self.connections.insert(
            id,
            ConnectionEntry {
                authorization: authorization.clone(),
                callee_grant,
                budget: request.budget,
                caller_to_callee_bytes: 0,
                callee_to_caller_bytes: 0,
                caller,
                callee,
                caller_ended: false,
                callee_ended: false,
            },
        );
        Ok(ConnectionHandle {
            id,
            authorization,
            budget: request.budget,
        })
    }

    fn connect_checked(
        &mut self,
        authority: &dyn ConnectionAuthority,
        request: &ConnectionRequest,
    ) -> Result<(ConnectionAuthorization, NetworkGrant), GateRefusal> {
        let now = self.tick(authority);
        if request.budget.caller_to_callee_bytes == 0 || request.budget.callee_to_caller_bytes == 0
        {
            return Err(GateRefusal::ZeroBudget);
        }
        self.check_authority(authority, &request.caller, now)?;
        self.check_authority(authority, &request.callee, now)?;
        let grant = self.check_service(authority, &request.callee, &request.service, now)?;
        let endpoint = |sandbox: &ExecutionId| {
            self.sandboxes
                .get(sandbox)
                .map(|entry| entry.endpoint.clone())
                .ok_or_else(|| GateRefusal::UnknownSandbox {
                    sandbox: sandbox.clone(),
                })
        };
        let caller = endpoint(&request.caller)?;
        let callee = endpoint(&request.callee)?;
        let authorization = self
            .grants
            .connect(&caller, &callee, &request.service, request.port, now)
            .map_err(GateRefusal::Connection)?;
        Ok((authorization, grant))
    }

    /// Moves what is ready on one connection: caller bytes to the callee, then callee
    /// bytes to the caller, the latter charged to the callee's release account (lent by
    /// `releases`) before they are sent. Both grants are checked again for every move.
    /// The connection closes when either sandbox loses its authority or its policy
    /// changes, the callee's published-service grant is tombstoned or no longer held, a
    /// V02 grant is revoked or expires, either direction spends its budget, the release
    /// account refuses, either side fails, or both ended their writing: one end's end of
    /// writing ends the other's reading once it took every byte (a half close), so a caller
    /// that is done sending still gets its answer. A closed connection is forgotten.
    pub fn pump_connection(
        &mut self,
        authority: &dyn ConnectionAuthority,
        releases: &mut dyn ReleaseAccounts,
        connection: ConnectionId,
    ) -> Result<Pumped, GateRefusal> {
        let now = self.tick(authority);
        let (authorization, grant) = match self.connections.get(&connection) {
            Some(entry) => (entry.authorization.clone(), entry.callee_grant),
            None => return Err(GateRefusal::UnknownConnection { connection }),
        };
        let callee = &authorization.callee.execution;
        // Both ends are checked, so a sandbox that lost its standing closes everything.
        let caller_lost = self.authority_lost(authority, &authorization.caller.execution, now);
        let callee_lost = self.authority_lost(authority, callee, now);
        let mut lost = caller_lost.or(callee_lost);
        if lost.is_none()
            && self
                .check_grant(authority, callee, &authorization.service, &grant, now)
                .is_err()
        {
            lost = Some(CloseReason::GrantRevoked {
                grant: network_grant_id(&grant),
            });
        }
        if let Some(reason) = lost {
            self.close_connection_entry(connection);
            return Ok(Pumped::closed(reason));
        }
        let chunk = self.chunk_bytes;
        let pumped = match self.connections.get_mut(&connection) {
            Some(entry) => pump_link(entry, &self.grants, releases, chunk, now),
            None => return Err(GateRefusal::UnknownConnection { connection }),
        };
        if pumped.is_closed() {
            self.close_connection_entry(connection);
        }
        Ok(pumped)
    }

    /// Closes one connection at the host's request.
    pub fn close_connection(&mut self, connection: ConnectionId) -> Result<(), GateRefusal> {
        self.close_connection_entry(connection)
            .map(|_| ())
            .ok_or(GateRefusal::UnknownConnection { connection })
    }

    /// The network mode of the sandbox attached under exactly `named`.
    fn attached_mode(&self, named: &SandboxEndpoint) -> Result<NetworkMode, GateRefusal> {
        let entry =
            self.sandboxes
                .get(&named.execution)
                .ok_or_else(|| GateRefusal::UnknownSandbox {
                    sandbox: named.execution.clone(),
                })?;
        if entry.endpoint != *named {
            return Err(GateRefusal::EndpointMismatch {
                sandbox: named.execution.clone(),
                attached: entry.endpoint.scope,
                named: named.scope,
            });
        }
        Ok(entry.mode)
    }
}

/// One pump of an open connection whose sandboxes hold their epochs and grant.
fn pump_link(
    entry: &mut ConnectionEntry,
    grants: &SandboxConnections,
    releases: &mut dyn ReleaseAccounts,
    chunk: usize,
    now: MonotonicTime,
) -> Pumped {
    let mut pumped = Pumped::open();
    let authorization = &entry.authorization;
    if grants
        .connect(
            &authorization.caller,
            &authorization.callee,
            &authorization.service,
            authorization.port,
            now,
        )
        .is_err()
    {
        return closed_after(pumped, CloseReason::ConnectionGrantEnded);
    }
    let mut buffer = vec![0u8; chunk];

    // The caller's bytes toward the callee, until the caller ends its writing.
    let up = Direction::CallerToCallee;
    if !entry.caller_ended {
        let remaining = entry
            .budget
            .limit(up)
            .saturating_sub(entry.caller_to_callee_bytes);
        if remaining == 0 {
            return closed_after(pumped, CloseReason::ConnectionBudgetSpent { direction: up });
        }
        let limit = read_limit(chunk, remaining);
        let Some(window) = buffer.get_mut(..limit) else {
            return closed_after(pumped, CloseReason::ConnectionBudgetSpent { direction: up });
        };
        match entry.caller.read(window) {
            Ok(StreamRead::Bytes(read)) if read <= limit => {
                let Some(bytes) = buffer.get(..read) else {
                    return closed_after(pumped, overlong_read());
                };
                if let Err(error) = entry.callee.write(bytes) {
                    return closed_after(pumped, CloseReason::StreamFailed(error));
                }
                let counted = byte_count(read);
                entry.caller_to_callee_bytes =
                    entry.caller_to_callee_bytes.saturating_add(counted);
                pumped.request_bytes = counted;
                if entry.caller_to_callee_bytes >= entry.budget.limit(up) {
                    return closed_after(
                        pumped,
                        CloseReason::ConnectionBudgetSpent { direction: up },
                    );
                }
            }
            Ok(StreamRead::Bytes(_)) => return closed_after(pumped, overlong_read()),
            Ok(StreamRead::Idle) => {}
            // The caller is done writing: the callee reads to the end of what it was sent
            // and may still answer (a half close).
            Ok(StreamRead::Ended) => {
                entry.caller_ended = true;
                entry.callee.finish();
            }
            Err(error) => return closed_after(pumped, CloseReason::StreamFailed(error)),
        }
    }

    // The callee's response toward the caller, until the callee ends its writing: outbound
    // data of the callee, charged to its release account through V02, which checks both
    // grants again.
    let down = Direction::CalleeToCaller;
    if !entry.callee_ended {
        let remaining = entry
            .budget
            .limit(down)
            .saturating_sub(entry.callee_to_caller_bytes);
        if remaining == 0 {
            return closed_after(
                pumped,
                CloseReason::ConnectionBudgetSpent { direction: down },
            );
        }
        let limit = read_limit(chunk, remaining);
        let Some(window) = buffer.get_mut(..limit) else {
            return closed_after(
                pumped,
                CloseReason::ConnectionBudgetSpent { direction: down },
            );
        };
        match entry.callee.read(window) {
            Ok(StreamRead::Bytes(read)) if read <= limit => {
                pumped = respond(entry, grants, releases, &buffer, read, pumped, now);
                if pumped.is_closed() {
                    return pumped;
                }
            }
            Ok(StreamRead::Bytes(_)) => return closed_after(pumped, overlong_read()),
            Ok(StreamRead::Idle) => {}
            Ok(StreamRead::Ended) => {
                entry.callee_ended = true;
                entry.caller.finish();
            }
            Err(error) => return closed_after(pumped, CloseReason::StreamFailed(error)),
        }
    }
    if entry.caller_ended && entry.callee_ended {
        return closed_after(pumped, CloseReason::PeerEnded);
    }
    pumped
}

/// Charges `read` bytes of the callee's response to its release account and hands them to
/// the caller.
fn respond(
    entry: &mut ConnectionEntry,
    grants: &SandboxConnections,
    releases: &mut dyn ReleaseAccounts,
    buffer: &[u8],
    read: usize,
    mut pumped: Pumped,
    now: MonotonicTime,
) -> Pumped {
    let down = Direction::CalleeToCaller;
    let counted = byte_count(read);
    let Some(account) = releases.account(&entry.authorization.callee.execution) else {
        return closed_after(pumped, CloseReason::NoReleaseAccount);
    };
    if let Err(refusal) = grants.record_response(&entry.authorization, counted, account, now) {
        let reason = match refusal {
            ConnectionRefusal::Release(refused) => CloseReason::ReleaseRefused(refused),
            ConnectionRefusal::Mode(_)
            | ConnectionRefusal::MissingGrant { .. }
            | ConnectionRefusal::ExpiryNotInFuture => CloseReason::ConnectionGrantEnded,
        };
        return closed_after(pumped, reason);
    }
    let Some(bytes) = buffer.get(..read) else {
        return closed_after(pumped, overlong_read());
    };
    if let Err(error) = entry.caller.write(bytes) {
        return closed_after(pumped, CloseReason::StreamFailed(error));
    }
    entry.callee_to_caller_bytes = entry.callee_to_caller_bytes.saturating_add(counted);
    pumped.response_bytes = counted;
    if entry.callee_to_caller_bytes >= entry.budget.limit(down) {
        return closed_after(
            pumped,
            CloseReason::ConnectionBudgetSpent { direction: down },
        );
    }
    pumped
}
