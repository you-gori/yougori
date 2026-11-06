//! The host enforcement point itself (VM §4.7; VM-W13): the sandboxes it serves, the
//! handles of the channels it admitted, and the refusals and close reasons the ingress
//! gate (`ingress`), the connection broker (`broker`) and revocation (`closure`) share.
//!
//! A sandbox is attached under the authorization epoch and the policy epoch it holds
//! then, with the host's registration of its policy. From that moment every operation on
//! it checks both epochs against CORE-04. Once either changed, everything of the sandbox
//! closes and its entry ends for good: a revoked, expired or stopped authority needs a new
//! boot, and a policy change needs the host to attach the sandbox again with the new
//! registration. A new attachment starts with nothing published.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::num::NonZeroUsize;
use std::time::Duration;

use super::authority::ConnectionAuthority;
use super::broker::{ConnectionBudget, Direction};
use super::closure::{ClosedConnection, ClosedSession, ClosureReport};
use super::ingress::AdmittedAs;
use super::service_grant::published_service_grant;
use super::status::PublicationState;
use super::stream::{SessionStream, StreamError};
use super::verifier::{ProofBinding, ProofRefusal};
use crate::foundation::coordination::network_grant_id;
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{
    AuthorizationEpoch, ExecutionId, GrantId, MonotonicTime, PolicyEpoch, TrustScope,
};
use crate::sandbox_contract::destinations::{
    ConnectionAuthorization, ConnectionRefusal, IngressError, IngressSession, IngressTable,
    NetworkMode, PublicationId, ReleaseError, SandboxConnections, SandboxEndpoint, ServiceIdentity,
};

/// The most bytes one pump moves in each direction of a channel, unless the gate was
/// built with another figure ([`ConnectionGate::with_chunk_bytes`]).
pub const DEFAULT_CHUNK_BYTES: usize = 16 * 1024;

/// The handle of one admitted ingress session, unique within its gate, rising from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionId(u64);

impl SessionId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The handle of one sandbox-to-sandbox connection, unique within its gate, rising from 1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

impl ConnectionId {
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// The identity of one publication the gate made, unique for the gate's whole life and
/// rising from 1: one counter for every sandbox, never reset for a new attachment or
/// epoch. V02's [`PublicationId`] numbers the publications of one table only, and a new
/// attachment starts a new table, so its numbers repeat; proofs, sessions, statuses and
/// closure reports name this identity instead.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GatePublicationId(u64);

impl GatePublicationId {
    pub const fn get(self) -> u64 {
        self.0
    }

    /// A publication identity for a test of a caller of the gate (the gate alone numbers
    /// real ones).
    #[cfg(test)]
    pub(crate) const fn for_tests(number: u64) -> Self {
        Self(number)
    }
}

/// A sandbox the gate is to serve, as the host's policy for it stands.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SandboxRegistration {
    /// The sandbox and its trust scope. A connection grant must name exactly this
    /// endpoint; a caller never chooses its own scope.
    pub endpoint: SandboxEndpoint,
    /// The network mode its policy runs in. Publications and connections need one that
    /// permits them (V02).
    pub mode: NetworkMode,
    /// The longest a publication of this sandbox may last.
    pub max_publication_lifetime: Duration,
    /// Each service the sandbox may offer, inbound or to another sandbox. The gate derives
    /// the CORE-04 [`NetworkGrant::PublishedService`] that covers each
    /// ([`super::published_service_grant`]) and attaches the sandbox only while its launch
    /// settings hold every one of them. A service named here is published, admitted or
    /// connected to only while the sandbox's current authority still holds that grant; a
    /// service not named here, never.
    pub published_services: BTreeSet<ServiceIdentity>,
}

/// Why the gate refused an operation. Nothing was admitted, published or connected.
///
/// [`ConnectionGate::admit`] answers an outside caller, who learns nothing of the
/// sandbox's state: every refusal of a service that is not being served on that port
/// (unknown sandbox, ended authority, changed policy, revoked or missing grant,
/// unpublished, withdrawn, expired or out of response budget) reaches the caller as
/// [`IngressError::NotPublished`]. Only an authentication refusal of a service being
/// served passes as it is. The detailed reason is the host's, through
/// [`ConnectionGate::publication_status`] and the closure reports.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateRefusal {
    /// The sandbox is not attached.
    UnknownSandbox {
        sandbox: ExecutionId,
    },
    /// The sandbox is attached and still holds the authorization and policy epochs of its
    /// entry.
    AlreadyAttached {
        sandbox: ExecutionId,
    },
    /// The sandbox holds no authority now, or not the epoch it was attached under.
    AuthorityEnded {
        sandbox: ExecutionId,
    },
    /// The sandbox's policy epoch changed since it was attached; it must be attached
    /// again with the new registration.
    PolicyChanged {
        sandbox: ExecutionId,
    },
    /// The registration does not name `service`.
    ServiceNotRegistered {
        sandbox: ExecutionId,
        service: ServiceIdentity,
    },
    /// The sandbox's current authority does not hold the published-service grant derived
    /// for `service`: when attaching, its launch settings do not hold it, so the
    /// registration is refused; later, its authority no longer holds it.
    ServiceNotGranted {
        sandbox: ExecutionId,
        service: ServiceIdentity,
        grant: GrantId,
    },
    /// CORE-04 tombstoned the published-service grant of `service` under `sandbox`.
    GrantRevoked {
        sandbox: ExecutionId,
        service: ServiceIdentity,
        grant: GrantId,
    },
    /// A budget of zero bytes could carry nothing.
    ZeroBudget,
    /// A connection grant names `sandbox` in another trust scope than the one it was
    /// attached under.
    EndpointMismatch {
        sandbox: ExecutionId,
        attached: TrustScope,
        named: TrustScope,
    },
    /// The verifier refused the caller's proof, or the proof's validity had ended.
    Proof(ProofRefusal),
    /// V02 refused the publication or the admission.
    Ingress(IngressError),
    /// V02 refused the connection grant or the connection.
    Connection(ConnectionRefusal),
    UnknownSession {
        session: SessionId,
    },
    UnknownConnection {
        connection: ConnectionId,
    },
}

impl fmt::Display for GateRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownSandbox { sandbox } => write!(f, "sandbox {sandbox} is not attached"),
            Self::AlreadyAttached { sandbox } => {
                write!(f, "sandbox {sandbox} is attached and holds its authority")
            }
            Self::AuthorityEnded { sandbox } => write!(
                f,
                "sandbox {sandbox} no longer holds the authority it was attached under"
            ),
            Self::PolicyChanged { sandbox } => write!(
                f,
                "the policy of sandbox {sandbox} changed; attach it again with the new policy"
            ),
            Self::ServiceNotRegistered { sandbox, service } => {
                write!(
                    f,
                    "the registration of sandbox {sandbox} does not name {service}"
                )
            }
            Self::ServiceNotGranted {
                sandbox, service, ..
            } => write!(
                f,
                "the authority of sandbox {sandbox} does not hold the published-service grant \
                 of {service}"
            ),
            Self::GrantRevoked {
                sandbox, service, ..
            } => write!(
                f,
                "the published-service grant of {service} was revoked under sandbox {sandbox}"
            ),
            Self::ZeroBudget => f.write_str("a budget of zero bytes could carry nothing"),
            Self::EndpointMismatch {
                sandbox,
                attached,
                named,
            } => write!(
                f,
                "the grant names sandbox {sandbox} in scope {named:?}, but it was attached in \
                 scope {attached:?}"
            ),
            Self::Proof(refusal) => fmt::Display::fmt(refusal, f),
            Self::Ingress(error) => fmt::Display::fmt(error, f),
            Self::Connection(refusal) => fmt::Display::fmt(refusal, f),
            Self::UnknownSession { session } => {
                write!(f, "no open session {}", session.get())
            }
            Self::UnknownConnection { connection } => {
                write!(f, "no open connection {}", connection.get())
            }
        }
    }
}

impl std::error::Error for GateRefusal {}

/// Why a session or connection was closed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CloseReason {
    /// The sandbox at one end lost the authority it was attached under.
    AuthorityEnded,
    /// The policy epoch of the sandbox at one end changed.
    PolicyChanged,
    /// The published-service grant of the service was tombstoned, or the authority no
    /// longer holds it.
    GrantRevoked { grant: GrantId },
    /// The proof the session was admitted on expired.
    ProofExpired,
    /// The publication was withdrawn.
    PublicationWithdrawn,
    /// The publication expired on the shared clock.
    PublicationExpired,
    /// The publication's outgoing response budget is spent.
    ResponseBudgetSpent,
    /// One direction of a connection spent its budget.
    ConnectionBudgetSpent { direction: Direction },
    /// A V02 connection grant at one end was revoked or expired.
    ConnectionGrantEnded,
    /// The sandbox's release account refused the response; the bytes were not sent.
    ReleaseRefused(ReleaseError),
    /// The host lent no release account for the responding sandbox; nothing was sent.
    NoReleaseAccount,
    /// One side closed its stream.
    PeerEnded,
    /// A stream failed.
    StreamFailed(StreamError),
    /// The host closed it.
    ClosedByHost,
}

/// Whether a channel is still open after a pump.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelState {
    Open,
    Closed(CloseReason),
}

/// What one pump moved, and whether the channel is still open.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pumped {
    /// Bytes moved toward the guest service or the callee.
    pub request_bytes: u64,
    /// Bytes moved back to the caller: guest or callee responses, each charged first.
    pub response_bytes: u64,
    pub state: ChannelState,
}

impl Pumped {
    pub(super) const fn open() -> Self {
        Self {
            request_bytes: 0,
            response_bytes: 0,
            state: ChannelState::Open,
        }
    }

    pub(super) const fn closed(reason: CloseReason) -> Self {
        Self {
            request_bytes: 0,
            response_bytes: 0,
            state: ChannelState::Closed(reason),
        }
    }

    /// Whether the pump closed the channel.
    pub fn is_closed(&self) -> bool {
        matches!(self.state, ChannelState::Closed(_))
    }
}

/// What the gate keeps of one publication beside V02's table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PublicationEntry {
    /// Its number in the sandbox's V02 table.
    pub(super) table_id: PublicationId,
    /// The published-service grant it was published under.
    pub(super) grant: NetworkGrant,
    pub(super) response_budget_bytes: u64,
    pub(super) response_used_bytes: u64,
    pub(super) sessions_admitted: u64,
    /// Why it ended, when the host withdrew it or the gate ended it.
    pub(super) ended_as: Option<PublicationState>,
}

impl PublicationEntry {
    pub(super) const fn remaining(&self) -> u64 {
        self.response_budget_bytes
            .saturating_sub(self.response_used_bytes)
    }
}

/// Why an attached sandbox's entry ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum EntryEnd {
    /// It no longer holds the authorization epoch it was attached under.
    AuthorityEnded,
    /// Its policy epoch changed.
    PolicyChanged,
}

impl EntryEnd {
    pub(super) fn refusal(self, sandbox: &ExecutionId) -> GateRefusal {
        let sandbox = sandbox.clone();
        match self {
            Self::AuthorityEnded => GateRefusal::AuthorityEnded { sandbox },
            Self::PolicyChanged => GateRefusal::PolicyChanged { sandbox },
        }
    }

    pub(super) const fn close_reason(self) -> CloseReason {
        match self {
            Self::AuthorityEnded => CloseReason::AuthorityEnded,
            Self::PolicyChanged => CloseReason::PolicyChanged,
        }
    }

    pub(super) const fn publication_state(self) -> PublicationState {
        match self {
            Self::AuthorityEnded => PublicationState::AuthorityEnded,
            Self::PolicyChanged => PublicationState::PolicyChanged,
        }
    }
}

/// One attached sandbox.
#[derive(Clone, Debug)]
pub(super) struct SandboxEntry {
    pub(super) endpoint: SandboxEndpoint,
    pub(super) mode: NetworkMode,
    /// The authorization epoch it was attached under.
    pub(super) epoch: AuthorizationEpoch,
    /// The policy epoch it was attached under.
    pub(super) policy: PolicyEpoch,
    /// Each registered service with the published-service grant derived for it, which
    /// its launch settings held when it was attached.
    pub(super) published_services: BTreeMap<ServiceIdentity, NetworkGrant>,
    /// Set once either epoch is no longer in force; never cleared.
    pub(super) ended: Option<EntryEnd>,
    pub(super) table: IngressTable,
    pub(super) publications: BTreeMap<GatePublicationId, PublicationEntry>,
}

impl SandboxEntry {
    /// Whether the V02 publication `table_id` admits callers at `now`.
    pub(super) fn is_active(&self, table_id: PublicationId, now: MonotonicTime) -> bool {
        self.table
            .active(now)
            .iter()
            .any(|active| active.id == table_id)
    }

    /// Withdraws the active publications `pick` selects, recording them as `ended_as`;
    /// returns them.
    pub(super) fn withdraw_where(
        &mut self,
        now: MonotonicTime,
        pick: impl Fn(&ServiceIdentity) -> bool,
        ended_as: PublicationState,
    ) -> Vec<GatePublicationId> {
        let picked: Vec<(GatePublicationId, PublicationId)> = self
            .publications
            .iter()
            .filter(|(_, publication)| self.is_active(publication.table_id, now))
            .filter(|(_, publication)| {
                self.table
                    .publication(publication.table_id)
                    .is_some_and(|found| pick(&found.service))
            })
            .map(|(id, publication)| (*id, publication.table_id))
            .collect();
        let mut withdrawn = Vec::new();
        for (id, table_id) in picked {
            if self.table.withdraw(table_id).is_ok() {
                if let Some(publication) = self.publications.get_mut(&id) {
                    publication.ended_as = Some(ended_as);
                }
                withdrawn.push(id);
            }
        }
        withdrawn
    }

    /// Why `publication` no longer admits or answers, if it does not.
    pub(super) fn publication_ended(
        &self,
        publication: GatePublicationId,
        now: MonotonicTime,
    ) -> Option<CloseReason> {
        let Some(entry) = self.publications.get(&publication) else {
            return Some(CloseReason::PublicationWithdrawn);
        };
        if self.is_active(entry.table_id, now) {
            return None;
        }
        match self.table.publication(entry.table_id) {
            Some(found) if now >= found.expires_at => Some(CloseReason::PublicationExpired),
            _ => Some(CloseReason::PublicationWithdrawn),
        }
    }
}

/// One open ingress session: the V02 session, both stream ends and its counters.
pub(super) struct SessionEntry {
    pub(super) sandbox: ExecutionId,
    pub(super) publication: GatePublicationId,
    pub(super) session: IngressSession,
    pub(super) service: ServiceIdentity,
    /// The published-service grant it was admitted under.
    pub(super) grant: NetworkGrant,
    pub(super) admitted_as: AdmittedAs,
    /// When the proof it was admitted on stops holding, if it was admitted on one.
    pub(super) proof_valid_until: Option<MonotonicTime>,
    /// The outside caller's end.
    pub(super) outside: Box<dyn SessionStream>,
    /// The guest service's end.
    pub(super) guest: Box<dyn SessionStream>,
    pub(super) request_bytes: u64,
    pub(super) response_bytes: u64,
}

/// One open sandbox-to-sandbox connection.
pub(super) struct ConnectionEntry {
    pub(super) authorization: ConnectionAuthorization,
    /// The callee's published-service grant the connection was opened under.
    pub(super) callee_grant: NetworkGrant,
    pub(super) budget: ConnectionBudget,
    pub(super) caller_to_callee_bytes: u64,
    pub(super) callee_to_caller_bytes: u64,
    pub(super) caller: Box<dyn SessionStream>,
    pub(super) callee: Box<dyn SessionStream>,
    /// Each end ended its writing (a half close); the connection ends once both did.
    pub(super) caller_ended: bool,
    pub(super) callee_ended: bool,
}

impl ConnectionEntry {
    /// Whether `sandbox` is at either end.
    pub(super) fn touches(&self, sandbox: &ExecutionId) -> bool {
        self.authorization.caller.execution == *sandbox
            || self.authorization.callee.execution == *sandbox
    }
}

/// The host enforcement point for ingress sessions and sandbox-to-sandbox connections
/// (VM §4.7; VM-W13). It starts with no sandbox, so nothing is reachable.
///
/// - The ingress gate: [`ConnectionGate::publish`], [`ConnectionGate::admit`],
///   [`ConnectionGate::pump_session`] and [`ConnectionGate::withdraw`].
/// - The connection broker: [`ConnectionGate::grant_outbound`],
///   [`ConnectionGate::grant_inbound`], [`ConnectionGate::connect`] and
///   [`ConnectionGate::pump_connection`].
/// - Revocation: [`ConnectionGate::close_revoked`] and [`super::acknowledge_closure`].
/// - Status: [`ConnectionGate::publication_status`],
///   [`ConnectionGate::session_status`] and [`ConnectionGate::connection_status`].
pub struct ConnectionGate {
    pub(super) sandboxes: BTreeMap<ExecutionId, SandboxEntry>,
    pub(super) sessions: BTreeMap<SessionId, SessionEntry>,
    pub(super) connections: BTreeMap<ConnectionId, ConnectionEntry>,
    pub(super) grants: SandboxConnections,
    /// Every caller and callee pair a V02 grant was recorded for, so the grants of a
    /// sandbox whose entry ended can all be revoked.
    pub(super) grant_pairs: BTreeSet<(SandboxEndpoint, SandboxEndpoint)>,
    /// Closure reports not yet handed to the host.
    pub(super) reports: Vec<ClosureReport>,
    /// Every sandbox and authorization epoch whose authority this gate found ended and
    /// closed everything of; a closure report is acknowledged only against these.
    pub(super) authority_closures: BTreeSet<(ExecutionId, AuthorizationEpoch)>,
    /// The latest clock reading the gate used; its readings never go back.
    pub(super) high_water: MonotonicTime,
    pub(super) chunk_bytes: usize,
    next_session: u64,
    next_connection: u64,
    next_publication: u64,
}

impl Default for ConnectionGate {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for ConnectionGate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionGate")
            .field("sandboxes", &self.sandboxes.len())
            .field("sessions", &self.sessions.len())
            .field("connections", &self.connections.len())
            .field("pending_reports", &self.reports.len())
            .field("high_water", &self.high_water)
            .finish()
    }
}

impl ConnectionGate {
    /// An empty gate moving at most [`DEFAULT_CHUNK_BYTES`] per direction and pump.
    pub fn new() -> Self {
        Self {
            sandboxes: BTreeMap::new(),
            sessions: BTreeMap::new(),
            connections: BTreeMap::new(),
            grants: SandboxConnections::new(),
            grant_pairs: BTreeSet::new(),
            reports: Vec::new(),
            authority_closures: BTreeSet::new(),
            high_water: MonotonicTime::from_nanos(0),
            chunk_bytes: DEFAULT_CHUNK_BYTES,
            next_session: 0,
            next_connection: 0,
            next_publication: 0,
        }
    }

    /// An empty gate moving at most `chunk_bytes` per direction and pump.
    pub fn with_chunk_bytes(chunk_bytes: NonZeroUsize) -> Self {
        Self {
            chunk_bytes: chunk_bytes.get(),
            ..Self::new()
        }
    }

    /// Attaches a sandbox under the authorization and policy epochs it holds now, with
    /// `registration` as its policy stands; returns the authorization epoch. Nothing of
    /// it is published. A sandbox whose earlier entry ended, by a new epoch or a policy
    /// change, is attached afresh; one whose entry still holds both epochs is refused. So
    /// is a registration naming a service whose derived published-service grant the
    /// sandbox's current authority does not hold: [`GateRefusal::GrantRevoked`] once
    /// CORE-04 tombstoned it, [`GateRefusal::ServiceNotGranted`] when its launch settings
    /// never held it.
    pub fn attach(
        &mut self,
        authority: &dyn ConnectionAuthority,
        registration: SandboxRegistration,
    ) -> Result<AuthorizationEpoch, GateRefusal> {
        let now = self.tick(authority);
        let sandbox = registration.endpoint.execution.clone();
        if self.sandboxes.contains_key(&sandbox)
            && self.check_authority(authority, &sandbox, now).is_ok()
        {
            return Err(GateRefusal::AlreadyAttached { sandbox });
        }
        let ended = || GateRefusal::AuthorityEnded {
            sandbox: sandbox.clone(),
        };
        let epoch = authority.current_epoch(&sandbox).ok_or_else(ended)?;
        let policy = authority.current_policy(&sandbox).ok_or_else(ended)?;
        let published_services =
            granted_services(authority, &sandbox, &registration.published_services)?;
        self.sandboxes.insert(
            sandbox.clone(),
            SandboxEntry {
                table: IngressTable::new(
                    sandbox,
                    registration.mode,
                    registration.max_publication_lifetime,
                ),
                endpoint: registration.endpoint,
                mode: registration.mode,
                epoch,
                policy,
                published_services,
                ended: None,
                publications: BTreeMap::new(),
            },
        );
        Ok(epoch)
    }

    /// The authorization epoch `sandbox` was attached under, while its entry has not
    /// ended.
    pub fn attached_epoch(&self, sandbox: &ExecutionId) -> Option<AuthorizationEpoch> {
        self.sandboxes
            .get(sandbox)
            .filter(|entry| entry.ended.is_none())
            .map(|entry| entry.epoch)
    }

    /// What a proof for `publication` of `sandbox` must be bound to, while the sandbox's
    /// entry has not ended and the publication is its own.
    pub fn proof_binding(
        &self,
        sandbox: &ExecutionId,
        publication: GatePublicationId,
    ) -> Option<ProofBinding> {
        let entry = self
            .sandboxes
            .get(sandbox)
            .filter(|entry| entry.ended.is_none())?;
        entry
            .publications
            .contains_key(&publication)
            .then(|| ProofBinding {
                sandbox: sandbox.clone(),
                epoch: entry.epoch,
                publication,
            })
    }

    /// How many ingress sessions are open.
    pub fn open_sessions(&self) -> usize {
        self.sessions.len()
    }

    /// How many sandbox connections are open.
    pub fn open_connections(&self) -> usize {
        self.connections.len()
    }

    /// How many ingress sessions to `sandbox` and connections at either end of it are
    /// open.
    pub fn open_channels_of(&self, sandbox: &ExecutionId) -> (usize, usize) {
        (
            self.sessions
                .values()
                .filter(|session| session.sandbox == *sandbox)
                .count(),
            self.connections
                .values()
                .filter(|connection| connection.touches(sandbox))
                .count(),
        )
    }

    /// The clock now, never earlier than a reading the gate used before.
    pub(super) fn tick(&mut self, authority: &dyn ConnectionAuthority) -> MonotonicTime {
        self.high_water = self.high_water.max(authority.now());
        self.high_water
    }

    /// The same without recording it, for views.
    pub(super) fn peek_now(&self, authority: &dyn ConnectionAuthority) -> MonotonicTime {
        self.high_water.max(authority.now())
    }

    /// Ok while `sandbox` holds the authorization and policy epochs it was attached
    /// under. Otherwise everything of the sandbox closes first, with a closure report kept
    /// for [`ConnectionGate::close_revoked`].
    pub(super) fn check_authority(
        &mut self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
        now: MonotonicTime,
    ) -> Result<(), GateRefusal> {
        let entry = self
            .sandboxes
            .get(sandbox)
            .ok_or_else(|| GateRefusal::UnknownSandbox {
                sandbox: sandbox.clone(),
            })?;
        let end = match entry.ended.or_else(|| standing(authority, sandbox, entry)) {
            Some(end) => end,
            None => return Ok(()),
        };
        self.sweep_sandbox(authority, sandbox, now);
        Err(end.refusal(sandbox))
    }

    /// Why a channel of `sandbox` must close, once its entry no longer stands
    /// ([`ConnectionGate::check_authority`]).
    pub(super) fn authority_lost(
        &mut self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
        now: MonotonicTime,
    ) -> Option<CloseReason> {
        self.check_authority(authority, sandbox, now).err()?;
        Some(
            self.sandboxes
                .get(sandbox)
                .and_then(|entry| entry.ended)
                .map_or(CloseReason::AuthorityEnded, EntryEnd::close_reason),
        )
    }

    /// The published-service grant derived for `service`, which the registration of
    /// `sandbox` names, once [`ConnectionGate::check_grant`] found it held.
    pub(super) fn check_service(
        &mut self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
        service: &ServiceIdentity,
        now: MonotonicTime,
    ) -> Result<NetworkGrant, GateRefusal> {
        let grant = self
            .sandboxes
            .get(sandbox)
            .and_then(|entry| entry.published_services.get(service))
            .copied()
            .ok_or_else(|| GateRefusal::ServiceNotRegistered {
                sandbox: sandbox.clone(),
                service: service.clone(),
            })?;
        self.check_grant(authority, sandbox, service, &grant, now)?;
        Ok(grant)
    }

    /// Ok while the current authority of `sandbox` holds `grant`, the published-service
    /// grant of `service`. Otherwise everything that depends on a grant it lost closes
    /// first.
    pub(super) fn check_grant(
        &mut self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
        service: &ServiceIdentity,
        grant: &NetworkGrant,
        now: MonotonicTime,
    ) -> Result<(), GateRefusal> {
        let id = network_grant_id(grant);
        let tombstoned = authority.grant_revoked(sandbox, id);
        if !tombstoned && authority.holds_network_grant(sandbox, grant) {
            return Ok(());
        }
        self.sweep_sandbox(authority, sandbox, now);
        let (sandbox, service) = (sandbox.clone(), service.clone());
        Err(if tombstoned {
            GateRefusal::GrantRevoked {
                sandbox,
                service,
                grant: id,
            }
        } else {
            GateRefusal::ServiceNotGranted {
                sandbox,
                service,
                grant: id,
            }
        })
    }

    pub(super) fn next_session_id(&mut self) -> SessionId {
        self.next_session = self.next_session.wrapping_add(1);
        SessionId(self.next_session)
    }

    pub(super) fn next_connection_id(&mut self) -> ConnectionId {
        self.next_connection = self.next_connection.wrapping_add(1);
        ConnectionId(self.next_connection)
    }

    pub(super) fn next_publication_id(&mut self) -> GatePublicationId {
        self.next_publication = self.next_publication.wrapping_add(1);
        GatePublicationId(self.next_publication)
    }

    /// Closes and forgets every session `pick` selects; returns them.
    pub(super) fn close_sessions(
        &mut self,
        pick: impl Fn(&SessionEntry) -> bool,
    ) -> Vec<ClosedSession> {
        let picked: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|(_, entry)| pick(entry))
            .map(|(id, _)| *id)
            .collect();
        picked
            .into_iter()
            .filter_map(|id| self.close_session_entry(id))
            .collect()
    }

    /// Closes and forgets one session.
    pub(super) fn close_session_entry(&mut self, id: SessionId) -> Option<ClosedSession> {
        let mut entry = self.sessions.remove(&id)?;
        entry.outside.close();
        entry.guest.close();
        Some(ClosedSession {
            session: id,
            publication: entry.publication,
            service: entry.service,
        })
    }

    /// Closes and forgets every connection `pick` selects; returns them.
    pub(super) fn close_connections(
        &mut self,
        pick: impl Fn(&ConnectionEntry) -> bool,
    ) -> Vec<ClosedConnection> {
        let picked: Vec<ConnectionId> = self
            .connections
            .iter()
            .filter(|(_, entry)| pick(entry))
            .map(|(id, _)| *id)
            .collect();
        picked
            .into_iter()
            .filter_map(|id| self.close_connection_entry(id))
            .collect()
    }

    /// Closes and forgets one connection.
    pub(super) fn close_connection_entry(&mut self, id: ConnectionId) -> Option<ClosedConnection> {
        let mut entry = self.connections.remove(&id)?;
        entry.caller.close();
        entry.callee.close();
        Some(ClosedConnection {
            connection: id,
            caller: entry.authorization.caller,
            callee: entry.authorization.callee,
            service: entry.authorization.service,
            port: entry.authorization.port,
        })
    }
}

/// Why the entry of `sandbox` no longer stands, if it does not: CORE-04 no longer shows
/// the authorization epoch, or the policy epoch, it was attached under.
pub(super) fn standing(
    authority: &dyn ConnectionAuthority,
    sandbox: &ExecutionId,
    entry: &SandboxEntry,
) -> Option<EntryEnd> {
    if authority.current_epoch(sandbox) != Some(entry.epoch) {
        Some(EntryEnd::AuthorityEnded)
    } else if authority.current_policy(sandbox) != Some(entry.policy) {
        Some(EntryEnd::PolicyChanged)
    } else {
        None
    }
}

/// Each of `services` with the published-service grant derived for it, once the current
/// authority of `sandbox` holds every one; otherwise the first service it does not hold is
/// refused, as tombstoned or as never granted.
fn granted_services(
    authority: &dyn ConnectionAuthority,
    sandbox: &ExecutionId,
    services: &BTreeSet<ServiceIdentity>,
) -> Result<BTreeMap<ServiceIdentity, NetworkGrant>, GateRefusal> {
    services
        .iter()
        .map(|service| {
            let grant = published_service_grant(service);
            let id = network_grant_id(&grant);
            if authority.grant_revoked(sandbox, id) {
                return Err(GateRefusal::GrantRevoked {
                    sandbox: sandbox.clone(),
                    service: service.clone(),
                    grant: id,
                });
            }
            if !authority.holds_network_grant(sandbox, &grant) {
                return Err(GateRefusal::ServiceNotGranted {
                    sandbox: sandbox.clone(),
                    service: service.clone(),
                    grant: id,
                });
            }
            Ok((service.clone(), grant))
        })
        .collect()
}

/// `bytes` as a count of bytes.
pub(super) fn byte_count(bytes: usize) -> u64 {
    u64::try_from(bytes).unwrap_or(u64::MAX)
}

/// At most `chunk` bytes, and no more than `remaining`.
pub(super) fn read_limit(chunk: usize, remaining: u64) -> usize {
    usize::try_from(remaining).map_or(chunk, |remaining| remaining.min(chunk))
}
