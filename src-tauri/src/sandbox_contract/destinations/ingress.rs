//! Ingress, publications and connected sandboxes (VM §4.7; VM-W13; VM-P36).
//!
//! No service is published by default. A publication names its service identity, port,
//! audience, authentication mode and expiry; public stays public and private stays
//! private, because an audience is never changed in place. Guest responses are outbound
//! data and are charged to the release account. A connection between sandboxes needs a
//! grant from each end, and nothing is inferred transitively.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::time::Duration;

use super::budget::{ReleaseAccount, ReleaseChannel, ReleaseError};
use super::mode::{ModeRefusal, NetworkMode, RouteClass};
use super::name::DestinationPort;
use super::route::route_name;
use crate::foundation::ids::{ExecutionId, MonotonicTime, TrustScope};

route_name!(
    /// The identity of a service a sandbox offers.
    ServiceIdentity
);

route_name!(
    /// A principal that may be admitted to a private publication.
    PrincipalId
);

/// Who may reach a publication (VM §4.7).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Audience {
    /// Anyone; chosen explicitly by the user.
    Public,
    /// Only these principals, authenticated.
    Private { principals: BTreeSet<PrincipalId> },
}

/// How callers authenticate to a publication.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AuthenticationMode {
    /// No authentication; valid only for a public audience.
    None,
    PlatformSession,
    BearerToken,
    MutualTls,
}

/// A request to publish one service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicationRequest {
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    pub audience: Audience,
    pub authentication: AuthenticationMode,
    pub expires_at: MonotonicTime,
}

/// The handle of one publication in an [`IngressTable`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicationId(u64);

impl PublicationId {
    /// The number the table assigned, for binding one publication into an identity such
    /// as its preview origin (VM §4.7).
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// A published service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Publication {
    pub id: PublicationId,
    pub sandbox: ExecutionId,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    pub audience: Audience,
    pub authentication: AuthenticationMode,
    pub published_at: MonotonicTime,
    pub expires_at: MonotonicTime,
}

/// A caller of a published service, as the host authenticated it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InboundCaller {
    Anonymous,
    Authenticated {
        mode: AuthenticationMode,
        principal: PrincipalId,
    },
}

/// An admitted inbound session. It ends when its publication is withdrawn or expires.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressSession {
    publication: PublicationId,
    sequence: u64,
}

impl IngressSession {
    pub const fn publication(&self) -> PublicationId {
        self.publication
    }

    /// The session's number within its table, rising from 1.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }
}

/// Why an ingress action was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IngressError {
    Mode(ModeRefusal),
    ExpiryNotInFuture,
    ExpiryTooFar {
        max_lifetime: Duration,
    },
    /// A private audience needs authentication.
    PrivateNeedsAuthentication,
    PrivateNeedsPrincipals,
    AlreadyPublished {
        service: ServiceIdentity,
        port: DestinationPort,
    },
    UnknownPublication,
    /// The service is not published, so it is unreachable.
    NotPublished {
        service: ServiceIdentity,
        port: DestinationPort,
    },
    Expired,
    NotAuthenticated,
    WrongAuthentication {
        required: AuthenticationMode,
    },
    NotInAudience,
    /// An audience is never changed in place; withdraw and publish again, so a public
    /// exposure is never relabelled private (or the reverse).
    AudienceChangeRefused,
    /// The session's publication was withdrawn or expired.
    SessionClosed,
    Release(ReleaseError),
}

impl fmt::Display for IngressError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mode(refusal) => fmt::Display::fmt(refusal, f),
            Self::ExpiryNotInFuture => f.write_str("a publication must expire in the future"),
            Self::ExpiryTooFar { max_lifetime } => write!(
                f,
                "a publication may last at most {} s",
                max_lifetime.as_secs()
            ),
            Self::PrivateNeedsAuthentication => {
                f.write_str("a private publication needs an authentication mode")
            }
            Self::PrivateNeedsPrincipals => {
                f.write_str("a private publication must name its principals")
            }
            Self::AlreadyPublished { service, port } => {
                write!(f, "{service} on port {port} is already published")
            }
            Self::UnknownPublication => f.write_str("no such publication"),
            Self::NotPublished { service, port } => {
                write!(f, "{service} on port {port} is not published")
            }
            Self::Expired => f.write_str("the publication expired"),
            Self::NotAuthenticated => f.write_str("the caller is not authenticated"),
            Self::WrongAuthentication { required } => {
                write!(f, "the publication requires {required:?} authentication")
            }
            Self::NotInAudience => f.write_str("the caller is not in the audience"),
            Self::AudienceChangeRefused => f.write_str(
                "an audience cannot be changed in place; withdraw the publication and publish \
                 again",
            ),
            Self::SessionClosed => f.write_str("the session's publication has ended"),
            Self::Release(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for IngressError {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicationState {
    publication: Publication,
    withdrawn: bool,
}

/// The publications of one sandbox (VM §4.7). It starts empty.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressTable {
    sandbox: ExecutionId,
    mode: NetworkMode,
    max_lifetime: Duration,
    publications: BTreeMap<PublicationId, PublicationState>,
    next_id: u64,
    next_session: u64,
}

impl IngressTable {
    /// An empty table: nothing is published by default.
    pub fn new(sandbox: ExecutionId, mode: NetworkMode, max_lifetime: Duration) -> Self {
        Self {
            sandbox,
            mode,
            max_lifetime,
            publications: BTreeMap::new(),
            next_id: 0,
            next_session: 0,
        }
    }

    /// Publications that are neither withdrawn nor expired at `now`.
    pub fn active(&self, now: MonotonicTime) -> Vec<&Publication> {
        self.publications
            .values()
            .filter(|state| !state.withdrawn && now < state.publication.expires_at)
            .map(|state| &state.publication)
            .collect()
    }

    pub fn publication(&self, id: PublicationId) -> Option<&Publication> {
        self.publications.get(&id).map(|state| &state.publication)
    }

    /// Publishes a service. The mode must permit publications; the expiry must be in the
    /// future and within the maximum lifetime; a private audience needs principals and
    /// authentication.
    pub fn publish(
        &mut self,
        request: PublicationRequest,
        now: MonotonicTime,
    ) -> Result<PublicationId, IngressError> {
        self.mode
            .permits(RouteClass::Publication)
            .map_err(IngressError::Mode)?;
        if request.expires_at <= now {
            return Err(IngressError::ExpiryNotInFuture);
        }
        if request.expires_at.saturating_duration_since(now) > self.max_lifetime {
            return Err(IngressError::ExpiryTooFar {
                max_lifetime: self.max_lifetime,
            });
        }
        if let Audience::Private { principals } = &request.audience {
            if request.authentication == AuthenticationMode::None {
                return Err(IngressError::PrivateNeedsAuthentication);
            }
            if principals.is_empty() {
                return Err(IngressError::PrivateNeedsPrincipals);
            }
        }
        if self.active(now).iter().any(|publication| {
            publication.service == request.service && publication.port == request.port
        }) {
            return Err(IngressError::AlreadyPublished {
                service: request.service,
                port: request.port,
            });
        }
        self.next_id = self.next_id.wrapping_add(1);
        let id = PublicationId(self.next_id);
        self.publications.insert(
            id,
            PublicationState {
                publication: Publication {
                    id,
                    sandbox: self.sandbox.clone(),
                    service: request.service,
                    port: request.port,
                    audience: request.audience,
                    authentication: request.authentication,
                    published_at: now,
                    expires_at: request.expires_at,
                },
                withdrawn: false,
            },
        );
        Ok(id)
    }

    /// Withdraws a publication; its existing sessions close.
    pub fn withdraw(&mut self, id: PublicationId) -> Result<(), IngressError> {
        let state = self
            .publications
            .get_mut(&id)
            .ok_or(IngressError::UnknownPublication)?;
        state.withdrawn = true;
        Ok(())
    }

    /// Always refuses: an audience is never changed in place (line 2034).
    pub fn change_audience(
        &mut self,
        id: PublicationId,
        _audience: Audience,
    ) -> Result<(), IngressError> {
        if !self.publications.contains_key(&id) {
            return Err(IngressError::UnknownPublication);
        }
        Err(IngressError::AudienceChangeRefused)
    }

    fn live(&self, id: PublicationId, now: MonotonicTime) -> Result<&Publication, IngressError> {
        let state = self
            .publications
            .get(&id)
            .ok_or(IngressError::UnknownPublication)?;
        if state.withdrawn {
            return Err(IngressError::SessionClosed);
        }
        if now >= state.publication.expires_at {
            return Err(IngressError::Expired);
        }
        Ok(&state.publication)
    }

    /// Admits an inbound caller to `service` on `port`. An unpublished service is
    /// unreachable; a private audience needs the publication's authentication mode and a
    /// listed principal.
    pub fn admit(
        &mut self,
        service: &ServiceIdentity,
        port: DestinationPort,
        caller: &InboundCaller,
        now: MonotonicTime,
    ) -> Result<IngressSession, IngressError> {
        let matching: Vec<&PublicationState> = self
            .publications
            .values()
            .filter(|state| {
                !state.withdrawn
                    && state.publication.service == *service
                    && state.publication.port == port
            })
            .collect();
        let found = match matching
            .iter()
            .find(|state| now < state.publication.expires_at)
        {
            Some(state) => state.publication.id,
            None if !matching.is_empty() => return Err(IngressError::Expired),
            None => {
                return Err(IngressError::NotPublished {
                    service: service.clone(),
                    port,
                })
            }
        };
        let publication = self.live(found, now)?;
        let authenticated = match caller {
            InboundCaller::Anonymous => None,
            InboundCaller::Authenticated { mode, principal } => Some((*mode, principal)),
        };
        match (
            &publication.audience,
            publication.authentication,
            authenticated,
        ) {
            (Audience::Public, AuthenticationMode::None, _) => {}
            (_, required, None) if required != AuthenticationMode::None => {
                return Err(IngressError::NotAuthenticated)
            }
            (_, required, Some((mode, _))) if mode != required => {
                return Err(IngressError::WrongAuthentication { required })
            }
            (Audience::Private { principals }, _, Some((_, principal))) => {
                if !principals.contains(principal) {
                    return Err(IngressError::NotInAudience);
                }
            }
            _ => {}
        }
        self.next_session = self.next_session.wrapping_add(1);
        Ok(IngressSession {
            publication: found,
            sequence: self.next_session,
        })
    }

    /// Charges a guest response on `session` to the published-service release channel
    /// (VM §4.7: guest service responses are outbound data). A closed session sends
    /// nothing.
    pub fn respond(
        &self,
        session: &IngressSession,
        bytes: u64,
        release: &mut ReleaseAccount,
        now: MonotonicTime,
    ) -> Result<(), IngressError> {
        self.live(session.publication, now)?;
        release
            .charge(ReleaseChannel::PublishedServiceResponse, bytes)
            .map_err(IngressError::Release)
    }
}

/// One end of a sandbox-to-sandbox connection: the execution and its trust scope.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SandboxEndpoint {
    pub execution: ExecutionId,
    pub scope: TrustScope,
}

/// A grant for one directed connection (VM §4.7). The caller's policy issues the
/// outbound copy and the callee's policy the inbound copy; both are required.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionGrant {
    pub caller: SandboxEndpoint,
    pub callee: SandboxEndpoint,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    pub expires_at: MonotonicTime,
}

/// Which side of a connection lacks a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MissingSide {
    Caller,
    Callee,
    Both,
}

/// Why a sandbox connection was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionRefusal {
    Mode(ModeRefusal),
    /// Grants are missing; transitive grants never count.
    MissingGrant {
        side: MissingSide,
    },
    ExpiryNotInFuture,
    Release(ReleaseError),
}

impl fmt::Display for ConnectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mode(refusal) => fmt::Display::fmt(refusal, f),
            Self::MissingGrant { side } => write!(
                f,
                "a sandbox connection needs a grant at both ends; missing: {side:?}"
            ),
            Self::ExpiryNotInFuture => f.write_str("a connection grant must expire in the future"),
            Self::Release(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ConnectionRefusal {}

/// An authorized sandbox connection. It carries no route grants: the caller gains nothing
/// of the callee's own authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectionAuthorization {
    pub caller: SandboxEndpoint,
    pub callee: SandboxEndpoint,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
}

/// The connection grants between sandboxes on one host (VM §4.7).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SandboxConnections {
    outbound: BTreeSet<ConnectionGrant>,
    inbound: BTreeSet<ConnectionGrant>,
}

impl SandboxConnections {
    /// No grants: no sandbox can reach another.
    pub fn new() -> Self {
        Self::default()
    }

    fn check(
        mode: NetworkMode,
        grant: &ConnectionGrant,
        now: MonotonicTime,
    ) -> Result<(), ConnectionRefusal> {
        mode.permits(RouteClass::SandboxConnection)
            .map_err(ConnectionRefusal::Mode)?;
        if grant.expires_at <= now {
            return Err(ConnectionRefusal::ExpiryNotInFuture);
        }
        Ok(())
    }

    /// Records the caller's grant, issued under the caller's network mode.
    pub fn grant_outbound(
        &mut self,
        caller_mode: NetworkMode,
        grant: ConnectionGrant,
        now: MonotonicTime,
    ) -> Result<(), ConnectionRefusal> {
        Self::check(caller_mode, &grant, now)?;
        self.outbound.insert(grant);
        Ok(())
    }

    /// Records the callee's grant, issued under the callee's network mode.
    pub fn grant_inbound(
        &mut self,
        callee_mode: NetworkMode,
        grant: ConnectionGrant,
        now: MonotonicTime,
    ) -> Result<(), ConnectionRefusal> {
        Self::check(callee_mode, &grant, now)?;
        self.inbound.insert(grant);
        Ok(())
    }

    /// Revokes both copies of every grant from `caller` to `callee`.
    pub fn revoke(&mut self, caller: &SandboxEndpoint, callee: &SandboxEndpoint) {
        self.outbound
            .retain(|grant| !(grant.caller == *caller && grant.callee == *callee));
        self.inbound
            .retain(|grant| !(grant.caller == *caller && grant.callee == *callee));
    }

    /// Revokes both copies of the grants from `caller` to `callee` for `service` on `port`;
    /// any other grant between them stands.
    pub fn revoke_service(
        &mut self,
        caller: &SandboxEndpoint,
        callee: &SandboxEndpoint,
        service: &ServiceIdentity,
        port: DestinationPort,
    ) {
        let other = |grant: &ConnectionGrant| {
            !(grant.caller == *caller
                && grant.callee == *callee
                && grant.service == *service
                && grant.port == port)
        };
        self.outbound.retain(other);
        self.inbound.retain(other);
    }

    /// Whether any grant from `caller` to `callee` is recorded at either end, expired or not.
    pub fn any_between(&self, caller: &SandboxEndpoint, callee: &SandboxEndpoint) -> bool {
        self.outbound
            .iter()
            .chain(&self.inbound)
            .any(|grant| grant.caller == *caller && grant.callee == *callee)
    }

    fn holds(
        grants: &BTreeSet<ConnectionGrant>,
        caller: &SandboxEndpoint,
        callee: &SandboxEndpoint,
        service: &ServiceIdentity,
        port: DestinationPort,
        now: MonotonicTime,
    ) -> bool {
        grants.iter().any(|grant| {
            grant.caller == *caller
                && grant.callee == *callee
                && grant.service == *service
                && grant.port == port
                && now < grant.expires_at
        })
    }

    /// Authorizes a direct connection: both ends must hold an unexpired grant naming
    /// exactly this caller, callee (with trust scope), service and port.
    pub fn connect(
        &self,
        caller: &SandboxEndpoint,
        callee: &SandboxEndpoint,
        service: &ServiceIdentity,
        port: DestinationPort,
        now: MonotonicTime,
    ) -> Result<ConnectionAuthorization, ConnectionRefusal> {
        let outbound = Self::holds(&self.outbound, caller, callee, service, port, now);
        let inbound = Self::holds(&self.inbound, caller, callee, service, port, now);
        let side = match (outbound, inbound) {
            (true, true) => {
                return Ok(ConnectionAuthorization {
                    caller: caller.clone(),
                    callee: callee.clone(),
                    service: service.clone(),
                    port,
                })
            }
            (false, true) => MissingSide::Caller,
            (true, false) => MissingSide::Callee,
            (false, false) => MissingSide::Both,
        };
        Err(ConnectionRefusal::MissingGrant { side })
    }

    /// Charges the callee's response on an authorized connection to the callee's release
    /// account (VM §4.7: guest responses are outbound data).
    pub fn record_response(
        &self,
        authorization: &ConnectionAuthorization,
        bytes: u64,
        callee_release: &mut ReleaseAccount,
        now: MonotonicTime,
    ) -> Result<(), ConnectionRefusal> {
        self.connect(
            &authorization.caller,
            &authorization.callee,
            &authorization.service,
            authorization.port,
            now,
        )?;
        callee_release
            .charge(ReleaseChannel::PublishedServiceResponse, bytes)
            .map_err(ConnectionRefusal::Release)
    }
}
