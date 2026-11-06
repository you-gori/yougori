//! Publications of a sandbox's guest services (M14; VM part §4.7 "no inbound publication by
//! default", §2.5 "bound releases"; VM-W13): the service's half of controlled ingress over
//! the connection gate ([`ConnectionGate`]).
//!
//! A sandbox may publish only the services its launch declared ([`PublishedPort`]): the
//! launch holds CORE-04's `PublishedService` grant for each and runs in V02's declared-
//! transport mode, and the gate attaches it with them and a release account. A publication
//! is explicit, expires, has an audience (private to the computer's owner, authenticated, or
//! public on this computer, chosen as such) and a response budget; every guest response byte
//! is charged to it and to the sandbox's release account (the published-response channel and
//! VM-D12's general release budget) before it may leave. A caller is admitted only through a
//! live publication, its guest end opened on the link only once admitted
//! ([`GuestIngress`](super::GuestIngress)); the gate re-checks the sandbox's authority, its
//! policy, the grant and the publication on every pump, so a revocation, a withdrawal, an
//! expiry or a spent budget closes the session before anything more leaves. While a sandbox
//! has a session open, the host holds back its "channels closed" acknowledgment.
//!
//! The same gate carries sandbox-to-sandbox connections (module docs in `connect`): the
//! endpoints each launch declared, what the owner granted each, and the connections open.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::foundation::ids::{ExecutionCategory, ExecutionId, MonotonicTime, TrustScope};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::connections::{
    published_service_grant, AuthenticationProof, ChannelState, ConnectionAuthority,
    ConnectionBudget, ConnectionGate, ConnectionId, ConnectionRequest, GatePublicationId,
    GateRefusal, InboundRequest, ProofBinding, ProofVerifier, PublicationState,
    SandboxRegistration, SessionId, SessionStream,
};
use crate::sandbox_contract::destinations::{
    Audience, AuthenticationMode, ChannelPolicy, ConnectionGrant, DestinationPort,
    InFlightAllowance, IngressError, NetworkMode, PrincipalId, PublicationRequest,
    ReleaseAccount, ReleaseChannel, ReleaseTrustClass, SandboxEndpoint, ServiceIdentity,
};

use super::connect::{
    CallerView, ConnectionEndpoint, ConnectionsView, EndpointView, GrantView,
    MAX_CONNECTION_BUDGET_BYTES, MAX_CONNECTION_LIFETIME,
};
use super::ingress::GuestIngressWatch;

/// The most services one launch may declare.
pub const MAX_PUBLISHED_PORTS: usize = 8;

/// The longest one publication lasts.
pub const MAX_PUBLICATION_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The most a sandbox's publications release in all: the published-response channel of its
/// release account. VM-D12's general release budget (8 MiB) bounds every channel together,
/// so this never raises what may leave.
pub const PUBLISHED_RESPONSE_BYTES: u64 = 8 << 20;

/// The most an owner session releases in all (16 GiB): a VM its owner launched for an attended
/// session in their own terminal, such as an inference harness, whose prompts, replies and
/// terminal output pass through its owner publication for hours. Only its owner can reach
/// such a VM's publications (public ones are refused), so this larger account never raises
/// what may leave to anyone else; every other sandbox keeps VM-D12's 8 MiB.
pub const OWNER_SESSION_RELEASE_BYTES: u64 = 16 << 30;

/// The principal a private publication of this computer admits: its owner, who holds the
/// publication's token.
pub const OWNER_PRINCIPAL: &str = "owner";

/// A service a sandbox may publish, declared at its launch: its name and the guest port its
/// listener is on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishedPort {
    pub service: String,
    pub port: u16,
}

impl PublishedPort {
    pub fn identity(&self) -> Result<ServiceIdentity, String> {
        ServiceIdentity::new(self.service.as_str())
            .map_err(|error| format!("{} is not a service name: {error:?}", self.service))
    }

    fn destination(&self) -> Result<DestinationPort, String> {
        DestinationPort::new(self.port)
            .map_err(|error| format!("{} is not a guest port: {error:?}", self.port))
    }

    /// The guest agent's listener for this port (`port-N`).
    pub fn listener(&self) -> String {
        format!("port-{}", self.port)
    }
}

/// Checks a launch's declared services: at most [`MAX_PUBLISHED_PORTS`], names V02 takes,
/// ports from 1, neither repeated.
pub fn check_published(ports: &[PublishedPort]) -> Result<(), String> {
    if ports.len() > MAX_PUBLISHED_PORTS {
        return Err(format!(
            "at most {MAX_PUBLISHED_PORTS} services may be published, not {}",
            ports.len()
        ));
    }
    let mut names = BTreeSet::new();
    let mut numbers = BTreeSet::new();
    for port in ports {
        port.identity()?;
        port.destination()?;
        if !names.insert(port.service.as_str()) {
            return Err(format!("the service {} is declared twice", port.service));
        }
        if !numbers.insert(port.port) {
            return Err(format!("the guest port {} is declared twice", port.port));
        }
    }
    Ok(())
}

/// The CORE-04 grants a launch's settings hold for its declared services.
pub fn launch_grants(
    ports: &[PublishedPort],
) -> Result<BTreeSet<crate::foundation::evidence::NetworkGrant>, String> {
    ports
        .iter()
        .map(|port| port.identity().map(|identity| published_service_grant(&identity)))
        .collect()
}

/// A sandbox's release account for its publications (VM §2.5): the published-response
/// channel's budget and the general budget, both `limit_bytes` (VM-D12's 8 MiB, or an owner
/// session's [`OWNER_SESSION_RELEASE_BYTES`]), no in-flight allowance (every response is
/// charged before it leaves).
fn release_account(limit_bytes: u64) -> ReleaseAccount {
    ReleaseAccount::new(
        BTreeMap::from([(
            ReleaseChannel::PublishedServiceResponse,
            ChannelPolicy {
                budget_bytes: limit_bytes,
                trust_class: ReleaseTrustClass::PublishedAudience,
            },
        )]),
        GeneralReleaseBudget::with_limit(limit_bytes),
        InFlightAllowance {
            bytes: 0,
            documented_reason: "guest responses are charged exactly before they are sent"
                .to_owned(),
        },
    )
    .unwrap_or_else(|_| unreachable!("a published-response channel and a documented allowance"))
}

/// Who may reach a publication, as asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationAudience {
    /// The computer's owner, with the publication's bearer token.
    Owner,
    /// Anyone who reaches the address on this computer; chosen explicitly.
    Public,
}

/// A byte budget and its use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BudgetView {
    pub limit_bytes: u64,
    pub used_bytes: u64,
    pub remaining_bytes: u64,
}

/// One publication as the service shows it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PublicationView {
    pub publication: u64,
    pub service: String,
    pub port: u16,
    /// Exactly as published; never relabelled.
    pub audience: PublicationAudience,
    pub expires_in_seconds: u64,
    pub state: &'static str,
    pub response_budget: BudgetView,
    pub open_sessions: usize,
    pub sessions_admitted: u64,
}

/// The sandbox's publications state, for status.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct PublicationsView {
    /// The services the launch declared.
    pub declared: Vec<PublishedPort>,
    pub publications: Vec<PublicationView>,
    /// What the sandbox's publications released so far, of [`PUBLISHED_RESPONSE_BYTES`].
    pub released_bytes: u64,
}

/// What one pump of every session and connection did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SessionsPumped {
    /// Bytes moved each way.
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// Sessions still open.
    pub open: usize,
    /// Sessions this pump closed, with why.
    pub closed: Vec<(u64, String)>,
    /// Bytes sandbox connections moved, both ways together.
    pub connection_bytes: u64,
    /// Connections still open.
    pub open_connections: usize,
    /// Connections this pump closed, with why.
    pub closed_connections: Vec<(u64, String)>,
}

impl SessionsPumped {
    /// Whether nothing moved and nothing closed.
    pub fn is_idle(&self) -> bool {
        self.request_bytes == 0
            && self.response_bytes == 0
            && self.closed.is_empty()
            && self.connection_bytes == 0
            && self.closed_connections.is_empty()
    }
}

/// What one connection endpoint is granted: the callee's declared service, until when, each
/// connection's budget, and how many connections it opened.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Binding {
    pub(super) callee: ExecutionId,
    pub(super) service: PublishedPort,
    pub(super) expires_at: MonotonicTime,
    pub(super) budget_bytes: u64,
    pub(super) opened: u64,
}

/// A sandbox as an end of a connection: its execution in a trust scope of its own.
fn endpoint_of(sandbox: &ExecutionId) -> SandboxEndpoint {
    SandboxEndpoint {
        execution: sandbox.clone(),
        scope: TrustScope::named(ExecutionCategory::VmSandbox, sandbox.as_str()),
    }
}

fn state_name(state: PublicationState) -> &'static str {
    match state {
        PublicationState::Active => "active",
        PublicationState::ResponseBudgetSpent => "response_budget_spent",
        PublicationState::Expired => "expired",
        PublicationState::Withdrawn => "withdrawn",
        PublicationState::AuthorityEnded => "authority_ended",
        PublicationState::PolicyChanged => "policy_changed",
        PublicationState::GrantRevoked => "grant_revoked",
    }
}

/// The publications and connections of every sandbox of the service: the gate, the release
/// accounts, each attached sandbox's declared services and connection endpoints, and what
/// each endpoint is granted.
pub(super) struct Publications {
    gate: ConnectionGate,
    releases: BTreeMap<ExecutionId, ReleaseAccount>,
    /// Sandboxes launched as owner sessions: owner-only publications, a larger release account.
    owner_sessions: BTreeSet<ExecutionId>,
    declared: BTreeMap<ExecutionId, Vec<PublishedPort>>,
    endpoints: BTreeMap<ExecutionId, Vec<ConnectionEndpoint>>,
    /// What each endpoint is granted, by caller and endpoint name.
    bindings: BTreeMap<(ExecutionId, String), Binding>,
    /// Connections each caller's programs opened that the gate refused, and admitted.
    refused: BTreeMap<ExecutionId, u64>,
    admitted: BTreeMap<ExecutionId, u64>,
}

impl Publications {
    pub(super) fn new() -> Self {
        Self {
            // A session moves up to 64 KiB each way per pump.
            gate: ConnectionGate::with_chunk_bytes(
                std::num::NonZeroUsize::new(64 << 10).unwrap_or(std::num::NonZeroUsize::MIN),
            ),
            releases: BTreeMap::new(),
            owner_sessions: BTreeSet::new(),
            declared: BTreeMap::new(),
            endpoints: BTreeMap::new(),
            bindings: BTreeMap::new(),
            refused: BTreeMap::new(),
            admitted: BTreeMap::new(),
        }
    }

    /// Attaches a launched sandbox with its declared services and connection endpoints;
    /// nothing is published or connected yet.
    pub(super) fn attach(
        &mut self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
        ports: &[PublishedPort],
        endpoints: &[ConnectionEndpoint],
        owner_session: bool,
    ) -> Result<(), String> {
        let services = ports
            .iter()
            .map(PublishedPort::identity)
            .collect::<Result<BTreeSet<_>, _>>()?;
        self.gate
            .attach(
                authority,
                SandboxRegistration {
                    endpoint: endpoint_of(sandbox),
                    mode: NetworkMode::DeclaredTransport,
                    // Local owner publications may last until withdrawn. The
                    // service below keeps finite/public requests bounded.
                    max_publication_lifetime: Duration::MAX,
                    published_services: services,
                },
            )
            .map_err(|refusal| format!("the connection gate refused the sandbox: {refusal:?}"))?;
        let limit = if owner_session { OWNER_SESSION_RELEASE_BYTES } else { PUBLISHED_RESPONSE_BYTES };
        self.releases.insert(sandbox.clone(), release_account(limit));
        if owner_session {
            self.owner_sessions.insert(sandbox.clone());
        } else {
            self.owner_sessions.remove(sandbox);
        }
        self.declared.insert(sandbox.clone(), ports.to_vec());
        self.endpoints.insert(sandbox.clone(), endpoints.to_vec());
        Ok(())
    }

    /// Grants `caller`'s connection endpoint `endpoint` the declared `service` of `callee` for
    /// `lifetime`, each connection carrying at most `budget_bytes` each way: the gate records
    /// the caller's and the callee's copy of V02's grant, each under that sandbox's network
    /// mode. Returns when it expires.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn grant_connection(
        &mut self,
        authority: &dyn ConnectionAuthority,
        caller: &ExecutionId,
        endpoint: &str,
        callee: &ExecutionId,
        service: &str,
        lifetime: Duration,
        budget_bytes: u64,
    ) -> Result<MonotonicTime, String> {
        if caller == callee {
            return Err("a sandbox reaches its own services directly, not through a connection".to_owned());
        }
        let declared = self
            .endpoints
            .get(caller)
            .is_some_and(|endpoints| endpoints.iter().any(|declared| declared.name == endpoint));
        if !declared {
            return Err(format!(
                "the sandbox {caller} was not launched with the connection endpoint {endpoint} (launch --connect {endpoint}=PORT)"
            ));
        }
        let port = self.declared_port(callee, service).cloned().ok_or_else(|| {
            format!("the sandbox {callee} was not launched to serve {service} (launch --publish {service}=PORT)")
        })?;
        // An expired grant of the caller's stands in nothing's way.
        let now = authority.now();
        let expired: Vec<((ExecutionId, String), Binding)> = self
            .bindings
            .iter()
            .filter(|((other, _), binding)| other == caller && binding.expires_at <= now)
            .map(|(key, binding)| (key.clone(), binding.clone()))
            .collect();
        for (key, binding) in expired {
            self.bindings.remove(&key);
            self.revoke_binding(caller, &binding);
        }
        let key = (caller.clone(), endpoint.to_owned());
        if self.bindings.contains_key(&key) {
            return Err(format!(
                "the endpoint {endpoint} is connected already; disconnect it first"
            ));
        }
        if self.bindings.iter().any(|((other, _), binding)| {
            other == caller && binding.callee == *callee && binding.service.service == service
        }) {
            return Err(format!(
                "another endpoint of the sandbox reaches {service} of {callee} already"
            ));
        }
        if lifetime.is_zero() || lifetime > MAX_CONNECTION_LIFETIME {
            return Err(format!(
                "a connection grant lasts from one second to {} hours",
                MAX_CONNECTION_LIFETIME.as_secs() / 3600
            ));
        }
        if budget_bytes == 0 || budget_bytes > MAX_CONNECTION_BUDGET_BYTES {
            return Err(format!(
                "a connection carries from 1 byte to {MAX_CONNECTION_BUDGET_BYTES} bytes each way"
            ));
        }
        let expires_at = now.saturating_add(lifetime);
        let grant = ConnectionGrant {
            caller: endpoint_of(caller),
            callee: endpoint_of(callee),
            service: port.identity()?,
            port: port.destination()?,
            expires_at,
        };
        self.gate
            .grant_outbound(authority, grant.clone())
            .map_err(|refusal| format!("the caller's grant was refused: {refusal:?}"))?;
        if let Err(refusal) = self.gate.grant_inbound(authority, grant.clone()) {
            self.gate
                .revoke_connection_grant(&grant.caller, &grant.callee, &grant.service, grant.port);
            return Err(format!("the callee's grant was refused: {refusal:?}"));
        }
        self.bindings.insert(
            key,
            Binding {
                callee: callee.clone(),
                service: port,
                expires_at,
                budget_bytes,
                opened: 0,
            },
        );
        Ok(expires_at)
    }

    /// Withdraws what `caller`'s endpoint `endpoint` is granted: both copies of the grant go
    /// and its open connections close. Returns how many.
    pub(super) fn revoke_connection(
        &mut self,
        caller: &ExecutionId,
        endpoint: &str,
    ) -> Result<usize, String> {
        let binding = self
            .bindings
            .remove(&(caller.clone(), endpoint.to_owned()))
            .ok_or_else(|| format!("the endpoint {endpoint} is connected to nothing"))?;
        Ok(self.revoke_binding(caller, &binding))
    }

    fn revoke_binding(&mut self, caller: &ExecutionId, binding: &Binding) -> usize {
        match (binding.service.identity(), binding.service.destination()) {
            (Ok(service), Ok(port)) => self
                .gate
                .revoke_connection_grant(
                    &endpoint_of(caller),
                    &endpoint_of(&binding.callee),
                    &service,
                    port,
                )
                .len(),
            _ => 0,
        }
    }

    /// What `caller`'s endpoint `endpoint` is granted now, if anything.
    pub(super) fn binding(&self, caller: &ExecutionId, endpoint: &str) -> Option<Binding> {
        self.bindings
            .get(&(caller.clone(), endpoint.to_owned()))
            .cloned()
    }

    /// A connection `caller`'s program opened was refused before it reached the gate (its
    /// endpoint granted nothing, or the callee not ready).
    pub(super) fn refused_connection(&mut self, caller: &ExecutionId) {
        *self.refused.entry(caller.clone()).or_default() += 1;
    }

    /// Opens a connection for a stream `caller`'s program opened to its endpoint `endpoint`:
    /// `caller_end` is that stream, `callee_end` a stream of the callee's service the gate
    /// opens only once admitted (both closed on a refusal, which is counted).
    pub(super) fn connect(
        &mut self,
        authority: &dyn ConnectionAuthority,
        caller: &ExecutionId,
        endpoint: &str,
        mut caller_end: Box<dyn SessionStream>,
        mut callee_end: Box<dyn SessionStream>,
    ) -> Result<ConnectionId, GateRefusal> {
        let Self {
            gate,
            bindings,
            refused,
            admitted,
            ..
        } = self;
        let request = bindings
            .get(&(caller.clone(), endpoint.to_owned()))
            .and_then(|binding| {
                Some(ConnectionRequest {
                    caller: caller.clone(),
                    callee: binding.callee.clone(),
                    service: binding.service.identity().ok()?,
                    port: binding.service.destination().ok()?,
                    budget: ConnectionBudget {
                        caller_to_callee_bytes: binding.budget_bytes,
                        callee_to_caller_bytes: binding.budget_bytes,
                    },
                })
            });
        let result = match request {
            Some(request) => gate.connect(authority, request, caller_end, callee_end),
            None => {
                caller_end.close();
                callee_end.close();
                Err(GateRefusal::UnknownSandbox {
                    sandbox: caller.clone(),
                })
            }
        };
        match &result {
            Ok(_) => {
                if let Some(binding) = bindings.get_mut(&(caller.clone(), endpoint.to_owned())) {
                    binding.opened += 1;
                }
                *admitted.entry(caller.clone()).or_default() += 1;
            }
            Err(_) => *refused.entry(caller.clone()).or_default() += 1,
        }
        result.map(|handle| handle.id())
    }

    fn declared_port(&self, sandbox: &ExecutionId, service: &str) -> Option<&PublishedPort> {
        self.declared
            .get(sandbox)?
            .iter()
            .find(|port| port.service == service)
    }

    /// Publishes `service` of `sandbox` for `lifetime` with a response budget of
    /// `budget_bytes`.
    pub(super) fn publish(
        &mut self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
        service: &str,
        audience: PublicationAudience,
        lifetime: Duration,
        budget_bytes: u64,
    ) -> Result<GatePublicationId, String> {
        let port = self
            .declared_port(sandbox, service)
            .cloned()
            .ok_or_else(|| format!("the sandbox's launch did not declare the service {service}"))?;
        // An owner session's publications reach only its owner, each with the session's whole
        // release account rather than VM-D12's 8 MiB.
        let budget_bytes = match (self.owner_sessions.contains(sandbox), audience) {
            (true, PublicationAudience::Public) => {
                return Err("this VM runs an owner session: its publications reach only its owner".into())
            }
            (true, PublicationAudience::Owner) => OWNER_SESSION_RELEASE_BYTES,
            (false, _) => budget_bytes,
        };
        let until_stopped = lifetime == Duration::MAX && audience == PublicationAudience::Owner;
        if lifetime.is_zero() || (lifetime > MAX_PUBLICATION_LIFETIME && !until_stopped) {
            return Err(format!(
                "a publication lasts from one second to {} hours",
                MAX_PUBLICATION_LIFETIME.as_secs() / 3600
            ));
        }
        let (audience, authentication) = match audience {
            PublicationAudience::Owner => (
                Audience::Private {
                    principals: BTreeSet::from([PrincipalId::new(OWNER_PRINCIPAL)
                        .map_err(|error| format!("{error:?}"))?]),
                },
                AuthenticationMode::BearerToken,
            ),
            PublicationAudience::Public => (Audience::Public, AuthenticationMode::None),
        };
        let now = authority.now();
        self.gate
            .publish(
                authority,
                sandbox,
                PublicationRequest {
                    service: port.identity()?,
                    port: port.destination()?,
                    audience,
                    authentication,
                    expires_at: now.saturating_add(lifetime),
                },
                budget_bytes,
            )
            .map_err(|refusal| format!("the publication was refused: {refusal:?}"))
    }

    /// Withdraws a publication; its open sessions close. Returns how many.
    pub(super) fn withdraw(
        &mut self,
        sandbox: &ExecutionId,
        publication: GatePublicationId,
    ) -> Result<usize, String> {
        self.gate
            .withdraw(sandbox, publication)
            .map(|closed| closed.len())
            .map_err(|refusal| format!("the withdrawal was refused: {refusal:?}"))
    }

    /// The identities of `sandbox`'s publications in its current attachment.
    pub(super) fn gate_ids(
        &self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
    ) -> Vec<GatePublicationId> {
        self.gate
            .publication_status(authority, sandbox)
            .into_iter()
            .map(|status| status.publication)
            .collect()
    }

    /// What a proof for `publication` of `sandbox` must be bound to.
    pub(super) fn proof_binding(
        &self,
        sandbox: &ExecutionId,
        publication: GatePublicationId,
    ) -> Option<ProofBinding> {
        self.gate.proof_binding(sandbox, publication)
    }

    /// The guest port `service` of `sandbox` was declared on, and its listener.
    pub(super) fn service_port(&self, sandbox: &ExecutionId, service: &str) -> Option<PublishedPort> {
        self.declared_port(sandbox, service).cloned()
    }

    /// Admits a caller of `service` on `sandbox`: `outside` is the caller's end, `guest` the
    /// guest end the gate opens only for an admitted caller (both closed on a refusal).
    pub(super) fn admit(
        &mut self,
        authority: &dyn ConnectionAuthority,
        verifier: &dyn ProofVerifier,
        sandbox: &ExecutionId,
        port: &PublishedPort,
        proof: Option<AuthenticationProof>,
        outside: Box<dyn SessionStream>,
        guest: Box<dyn SessionStream>,
    ) -> Result<SessionId, GateRefusal> {
        let request = InboundRequest {
            sandbox: sandbox.clone(),
            service: port.identity().map_err(|_| unreachable_service(port))?,
            port: port.destination().map_err(|_| unreachable_service(port))?,
            proof,
        };
        self.gate
            .admit(authority, verifier, request, outside, guest)
            .map(|handle| handle.id())
    }

    /// Pumps every open session and connection once.
    pub(super) fn pump(&mut self, authority: &dyn ConnectionAuthority) -> SessionsPumped {
        let mut pumped = SessionsPumped::default();
        let connections: Vec<ConnectionId> = self
            .gate
            .connection_status()
            .into_iter()
            .map(|connection| connection.connection)
            .collect();
        for connection in connections {
            match self
                .gate
                .pump_connection(authority, &mut self.releases, connection)
            {
                Ok(moved) => {
                    pumped.connection_bytes += moved.request_bytes + moved.response_bytes;
                    if let ChannelState::Closed(reason) = &moved.state {
                        pumped
                            .closed_connections
                            .push((connection.get(), format!("{reason:?}")));
                    }
                }
                Err(refusal) => pumped
                    .closed_connections
                    .push((connection.get(), format!("{refusal:?}"))),
            }
        }
        pumped.open_connections = self.gate.open_connections();
        let sessions: Vec<SessionId> = self
            .gate
            .session_status()
            .into_iter()
            .map(|session| session.session)
            .collect();
        for session in sessions {
            match self.gate.pump_session(authority, &mut self.releases, session) {
                Ok(moved) => {
                    pumped.request_bytes += moved.request_bytes;
                    pumped.response_bytes += moved.response_bytes;
                    if let ChannelState::Closed(reason) = &moved.state {
                        pumped.closed.push((session.get(), format!("{reason:?}")));
                    }
                }
                Err(refusal) => pumped.closed.push((session.get(), format!("{refusal:?}"))),
            }
        }
        pumped.open = self.gate.open_sessions();
        pumped
    }

    /// Closes every open session of `sandbox` and every connection with it at either end,
    /// and withdraws every connection grant naming it (its revocation: nothing more may leave
    /// or reach it); returns how many sessions and connections closed.
    pub(super) fn close_channels_of(&mut self, sandbox: &ExecutionId) -> usize {
        let sessions: Vec<SessionId> = self
            .gate
            .session_status()
            .into_iter()
            .filter(|session| session.sandbox == *sandbox)
            .map(|session| session.session)
            .collect();
        let mut closed = sessions
            .into_iter()
            .filter(|session| self.gate.close_session(*session).is_ok())
            .count();
        let ended: Vec<((ExecutionId, String), Binding)> = self
            .bindings
            .iter()
            .filter(|((caller, _), binding)| caller == sandbox || binding.callee == *sandbox)
            .map(|(key, binding)| (key.clone(), binding.clone()))
            .collect();
        for (key, binding) in ended {
            self.bindings.remove(&key);
            closed += self.revoke_binding(&key.0, &binding);
        }
        let connections: Vec<ConnectionId> = self
            .gate
            .connection_status()
            .into_iter()
            .filter(|connection| {
                connection.caller.execution == *sandbox || connection.callee.execution == *sandbox
            })
            .map(|connection| connection.connection)
            .collect();
        closed += connections
            .into_iter()
            .filter(|connection| self.gate.close_connection(*connection).is_ok())
            .count();
        closed
    }

    /// The sandboxes with a session or a connection open now.
    pub(super) fn holding(&self) -> BTreeSet<ExecutionId> {
        let sessions = self
            .gate
            .session_status()
            .into_iter()
            .map(|session| session.sandbox);
        let connections = self
            .gate
            .connection_status()
            .into_iter()
            .flat_map(|connection| [connection.caller.execution, connection.callee.execution]);
        sessions.chain(connections).collect()
    }

    /// `sandbox`'s connections as status shows them.
    pub(super) fn connections_view(
        &self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
    ) -> ConnectionsView {
        let now = authority.now();
        let left = |expires_at: MonotonicTime| expires_at.saturating_duration_since(now).as_secs();
        let endpoints = self
            .endpoints
            .get(sandbox)
            .map(|endpoints| {
                endpoints
                    .iter()
                    .map(|endpoint| EndpointView {
                        name: endpoint.name.clone(),
                        port: endpoint.port,
                        granted: self
                            .bindings
                            .get(&(sandbox.clone(), endpoint.name.clone()))
                            .map(|binding| GrantView {
                                sandbox: binding.callee.as_str().to_owned(),
                                service: binding.service.service.clone(),
                                state: if binding.expires_at > now { "active" } else { "expired" },
                                expires_in_seconds: left(binding.expires_at),
                                budget_bytes: binding.budget_bytes,
                                connections_opened: binding.opened,
                            }),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let callers = self
            .bindings
            .iter()
            .filter(|(_, binding)| binding.callee == *sandbox)
            .map(|((caller, endpoint), binding)| CallerView {
                sandbox: caller.as_str().to_owned(),
                endpoint: endpoint.clone(),
                service: binding.service.service.clone(),
                expires_in_seconds: left(binding.expires_at),
            })
            .collect();
        let open_connections = self
            .gate
            .connection_status()
            .iter()
            .filter(|connection| {
                connection.caller.execution == *sandbox || connection.callee.execution == *sandbox
            })
            .count();
        ConnectionsView {
            endpoints,
            callers,
            open_connections,
            refused_connections: self.refused.get(sandbox).copied().unwrap_or(0),
            admitted_connections: self.admitted.get(sandbox).copied().unwrap_or(0),
        }
    }

    /// `sandbox`'s publications as status shows them.
    pub(super) fn view(
        &self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
    ) -> PublicationsView {
        let declared = self.declared.get(sandbox).cloned().unwrap_or_default();
        let publications = self
            .gate
            .publication_status(authority, sandbox)
            .into_iter()
            .map(|status| PublicationView {
                publication: status.publication.get(),
                service: status.service.as_str().to_owned(),
                port: status.port.get(),
                audience: match status.audience {
                    Audience::Public => PublicationAudience::Public,
                    Audience::Private { .. } => PublicationAudience::Owner,
                },
                expires_in_seconds: status.remaining_lifetime.as_secs(),
                state: state_name(status.state),
                response_budget: BudgetView {
                    limit_bytes: status.response_budget.limit_bytes,
                    used_bytes: status.response_budget.used_bytes,
                    remaining_bytes: status.response_budget.remaining_bytes,
                },
                open_sessions: status.open_sessions,
                sessions_admitted: status.sessions_admitted,
            })
            .collect();
        let released_bytes = self.releases.get(sandbox).map_or(0, |account| {
            account.used_bytes(ReleaseChannel::PublishedServiceResponse)
        });
        PublicationsView {
            declared,
            publications,
            released_bytes,
        }
    }
}

/// What a caller of `service` is told when it is not being served.
pub(super) fn not_published(service: &str) -> GateRefusal {
    GateRefusal::Ingress(IngressError::NotPublished {
        service: ServiceIdentity::new(service)
            .or_else(|_| ServiceIdentity::new("unknown"))
            .unwrap_or_else(|_| unreachable!("a valid name")),
        port: DestinationPort::HTTPS,
    })
}

fn unreachable_service(port: &PublishedPort) -> GateRefusal {
    GateRefusal::Ingress(IngressError::NotPublished {
        service: ServiceIdentity::new("unknown").unwrap_or_else(|_| unreachable!("a valid name")),
        port: DestinationPort::new(port.port.max(1))
            .unwrap_or_else(|_| unreachable!("a port from 1")),
    })
}

/// Keeps the guest end's room readable for the caller's side.
pub type GuestRoom = GuestIngressWatch;
