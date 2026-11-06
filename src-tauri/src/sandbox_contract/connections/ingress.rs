//! The ingress gate (VM §4.7: "no inbound publication by default"; VM-W13: "unpublished
//! service unreachable; public/private semantics preserved").
//!
//! An inbound caller reaches a sandbox's service only through a live V02 publication:
//! it exists, is unexpired on the shared clock, names the service and port, has response
//! budget left and admits the caller's audience, while the sandbox holds the epochs it was
//! attached under and its authority holds the service's published-service grant. A
//! publication that authenticates admits a caller only on a proof its verifier accepted
//! for exactly that publication, sandbox and epoch, and the session closes when the proof
//! expires; a private publication admits only a listed principal, so a private session is
//! never served as public; a public publication stays public, because V02 never changes
//! an audience in place. Every guest response byte is outbound data (§2.5): it is charged
//! to the publication's response budget and to the sandbox's release account before it is
//! sent, and the session closes once the budget is spent, before it forwards anything
//! more.
//!
//! An outside caller learns nothing of the sandbox's state: a service that is not being
//! served on that port is refused as [`IngressError::NotPublished`], whatever the reason
//! ([`GateRefusal`]).

use super::authority::{ConnectionAuthority, ReleaseAccounts};
use super::gate::{
    byte_count, read_limit, ChannelState, CloseReason, ConnectionGate, GatePublicationId,
    GateRefusal, PublicationEntry, Pumped, SandboxEntry, SessionEntry, SessionId,
};
use super::status::PublicationState;
use super::stream::{SessionStream, StreamError, StreamRead};
use super::verifier::{AuthenticationProof, ProofBinding, ProofRefusal, ProofVerifier};
use crate::foundation::coordination::network_grant_id;
use crate::foundation::evidence::NetworkGrant;
use crate::foundation::ids::{AuthorizationEpoch, ExecutionId, MonotonicTime};
use crate::sandbox_contract::destinations::{
    Audience, AuthenticationMode, DestinationPort, InboundCaller, IngressError, IngressSession,
    PrincipalId, PublicationRequest, ServiceIdentity,
};

/// An inbound request for a sandbox's service, as the transport adapter received it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InboundRequest {
    pub sandbox: ExecutionId,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    /// What the caller presented, if anything.
    pub proof: Option<AuthenticationProof>,
}

/// Whom a session was admitted as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdmittedAs {
    /// A caller of a public publication, with its principal when the publication also
    /// authenticates.
    Public { principal: Option<PrincipalId> },
    /// A listed principal of a private publication, authenticated in the publication's
    /// mode.
    Private {
        principal: PrincipalId,
        mode: AuthenticationMode,
    },
}

/// An admitted ingress session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IngressHandle {
    id: SessionId,
    sandbox: ExecutionId,
    epoch: AuthorizationEpoch,
    publication: GatePublicationId,
    admitted_as: AdmittedAs,
    proof_valid_until: Option<MonotonicTime>,
}

impl IngressHandle {
    pub const fn id(&self) -> SessionId {
        self.id
    }

    pub fn sandbox(&self) -> &ExecutionId {
        &self.sandbox
    }

    /// The authorization epoch the sandbox held when the session was admitted.
    pub const fn epoch(&self) -> AuthorizationEpoch {
        self.epoch
    }

    pub const fn publication(&self) -> GatePublicationId {
        self.publication
    }

    pub fn admitted_as(&self) -> &AdmittedAs {
        &self.admitted_as
    }

    /// When the proof the session was admitted on stops holding, if it was admitted on
    /// one; the session closes then.
    pub const fn proof_valid_until(&self) -> Option<MonotonicTime> {
        self.proof_valid_until
    }
}

/// What a successful admission check found.
struct Admitted {
    session: IngressSession,
    publication: GatePublicationId,
    epoch: AuthorizationEpoch,
    grant: NetworkGrant,
    admitted_as: AdmittedAs,
    proof_valid_until: Option<MonotonicTime>,
}

impl ConnectionGate {
    /// Publishes a service of an attached sandbox through V02, with an outgoing response
    /// budget of `response_budget_bytes`; returns its identity, unique for the gate's
    /// life. The sandbox must hold the epochs it was attached under, its registration must
    /// name the service, and its current authority must hold the published-service grant
    /// derived for it.
    pub fn publish(
        &mut self,
        authority: &dyn ConnectionAuthority,
        sandbox: &ExecutionId,
        request: PublicationRequest,
        response_budget_bytes: u64,
    ) -> Result<GatePublicationId, GateRefusal> {
        let now = self.tick(authority);
        if response_budget_bytes == 0 {
            return Err(GateRefusal::ZeroBudget);
        }
        self.check_authority(authority, sandbox, now)?;
        let grant = self.check_service(authority, sandbox, &request.service, now)?;
        let unknown = || GateRefusal::UnknownSandbox {
            sandbox: sandbox.clone(),
        };
        let table_id = self
            .sandboxes
            .get_mut(sandbox)
            .ok_or_else(unknown)?
            .table
            .publish(request, now)
            .map_err(GateRefusal::Ingress)?;
        let id = self.next_publication_id();
        self.sandboxes
            .get_mut(sandbox)
            .ok_or_else(unknown)?
            .publications
            .insert(
                id,
                PublicationEntry {
                    table_id,
                    grant,
                    response_budget_bytes,
                    response_used_bytes: 0,
                    sessions_admitted: 0,
                    ended_as: None,
                },
            );
        Ok(id)
    }

    /// Withdraws a publication; its open sessions close. Returns them.
    pub fn withdraw(
        &mut self,
        sandbox: &ExecutionId,
        publication: GatePublicationId,
    ) -> Result<Vec<SessionId>, GateRefusal> {
        let entry = self
            .sandboxes
            .get_mut(sandbox)
            .ok_or_else(|| GateRefusal::UnknownSandbox {
                sandbox: sandbox.clone(),
            })?;
        let found = entry
            .publications
            .get_mut(&publication)
            .ok_or(GateRefusal::Ingress(IngressError::UnknownPublication))?;
        entry
            .table
            .withdraw(found.table_id)
            .map_err(GateRefusal::Ingress)?;
        found.ended_as.get_or_insert(PublicationState::Withdrawn);
        Ok(self
            .close_sessions(|session| {
                session.sandbox == *sandbox && session.publication == publication
            })
            .into_iter()
            .map(|closed| closed.session)
            .collect())
    }

    /// Admits an inbound caller, joining the caller's stream end `outside` to the guest
    /// service's end `guest`. A service that is not being served on that port is
    /// unreachable, and the caller is told only [`IngressError::NotPublished`]; only an
    /// authentication refusal of a service being served says more ([`GateRefusal`]). On
    /// a refusal both ends are closed.
    pub fn admit(
        &mut self,
        authority: &dyn ConnectionAuthority,
        verifier: &dyn ProofVerifier,
        request: InboundRequest,
        mut outside: Box<dyn SessionStream>,
        mut guest: Box<dyn SessionStream>,
    ) -> Result<IngressHandle, GateRefusal> {
        let admitted = match self.admit_checked(authority, verifier, &request) {
            Ok(admitted) => admitted,
            Err(refusal) => {
                outside.close();
                guest.close();
                return Err(outsider_view(refusal, &request));
            }
        };
        let id = self.next_session_id();
        self.sessions.insert(
            id,
            SessionEntry {
                sandbox: request.sandbox.clone(),
                publication: admitted.publication,
                session: admitted.session,
                service: request.service,
                grant: admitted.grant,
                admitted_as: admitted.admitted_as.clone(),
                proof_valid_until: admitted.proof_valid_until,
                outside,
                guest,
                request_bytes: 0,
                response_bytes: 0,
            },
        );
        Ok(IngressHandle {
            id,
            sandbox: request.sandbox,
            epoch: admitted.epoch,
            publication: admitted.publication,
            admitted_as: admitted.admitted_as,
            proof_valid_until: admitted.proof_valid_until,
        })
    }

    fn admit_checked(
        &mut self,
        authority: &dyn ConnectionAuthority,
        verifier: &dyn ProofVerifier,
        request: &InboundRequest,
    ) -> Result<Admitted, GateRefusal> {
        let now = self.tick(authority);
        let unreachable = || not_published(request);
        self.check_authority(authority, &request.sandbox, now)?;
        let grant = self.check_service(authority, &request.sandbox, &request.service, now)?;
        let entry = self
            .sandboxes
            .get_mut(&request.sandbox)
            .ok_or_else(unreachable)?;
        let (table_id, authentication) = entry
            .table
            .active(now)
            .into_iter()
            .find(|active| active.service == request.service && active.port == request.port)
            .map(|active| (active.id, active.authentication))
            .ok_or_else(unreachable)?;
        let (publication, remaining) = entry
            .publications
            .iter()
            .find(|(_, publication)| publication.table_id == table_id)
            .map(|(id, publication)| (*id, publication.remaining()))
            .ok_or_else(unreachable)?;
        // A spent response budget could answer nothing: the service is not being served.
        if remaining == 0 {
            return Err(unreachable());
        }
        let binding = ProofBinding {
            sandbox: request.sandbox.clone(),
            epoch: entry.epoch,
            publication,
        };
        let (caller, proof_valid_until) = match &request.proof {
            Some(proof) if authentication != AuthenticationMode::None => {
                let verified = verifier
                    .verify(&binding, proof, now)
                    .map_err(GateRefusal::Proof)?;
                if verified.valid_until <= now {
                    return Err(GateRefusal::Proof(ProofRefusal::Expired));
                }
                (
                    InboundCaller::Authenticated {
                        mode: proof.mode(),
                        principal: verified.principal,
                    },
                    Some(verified.valid_until),
                )
            }
            _ => (InboundCaller::Anonymous, None),
        };
        let session = entry
            .table
            .admit(&request.service, request.port, &caller, now)
            .map_err(GateRefusal::Ingress)?;
        if session.publication() != table_id {
            return Err(unreachable());
        }
        let admitted = entry.table.publication(table_id).ok_or_else(unreachable)?;
        let admitted_as = match (&admitted.audience, caller) {
            (Audience::Public, InboundCaller::Anonymous) => AdmittedAs::Public { principal: None },
            (Audience::Public, InboundCaller::Authenticated { principal, .. }) => {
                AdmittedAs::Public {
                    principal: Some(principal),
                }
            }
            (Audience::Private { .. }, InboundCaller::Authenticated { mode, principal }) => {
                AdmittedAs::Private { principal, mode }
            }
            // V02 admits no anonymous caller to a private audience; never serve one.
            (Audience::Private { .. }, InboundCaller::Anonymous) => {
                return Err(GateRefusal::Ingress(IngressError::NotAuthenticated))
            }
        };
        let epoch = entry.epoch;
        let counted = entry
            .publications
            .get_mut(&publication)
            .ok_or_else(unreachable)?;
        counted.sessions_admitted = counted.sessions_admitted.saturating_add(1);
        Ok(Admitted {
            session,
            publication,
            epoch,
            grant,
            admitted_as,
            proof_valid_until,
        })
    }

    /// Moves what is ready on one session: request bytes from the caller to the guest,
    /// then guest response bytes to the caller, each response charged to the
    /// publication's budget and the sandbox's release account (lent by `releases`) before
    /// it is sent. The session closes when the sandbox loses its authority or its policy
    /// changes, when the service's grant is tombstoned or no longer held, when the proof
    /// it was admitted on expires, when the publication is withdrawn or expires, when the
    /// response budget is spent (before any further request is forwarded) or the release
    /// account refuses, and when either side ends. A closed session is forgotten.
    pub fn pump_session(
        &mut self,
        authority: &dyn ConnectionAuthority,
        releases: &mut dyn ReleaseAccounts,
        session: SessionId,
    ) -> Result<Pumped, GateRefusal> {
        let now = self.tick(authority);
        let (sandbox, service, grant, proof_valid_until) = match self.sessions.get(&session) {
            Some(entry) => (
                entry.sandbox.clone(),
                entry.service.clone(),
                entry.grant,
                entry.proof_valid_until,
            ),
            None => return Err(GateRefusal::UnknownSession { session }),
        };
        let lost = match self.authority_lost(authority, &sandbox, now) {
            Some(reason) => Some(reason),
            None => self
                .check_grant(authority, &sandbox, &service, &grant, now)
                .err()
                .map(|_| CloseReason::GrantRevoked {
                    grant: network_grant_id(&grant),
                }),
        };
        let lost = lost.or_else(|| {
            proof_valid_until
                .filter(|until| now >= *until)
                .map(|_| CloseReason::ProofExpired)
        });
        if let Some(reason) = lost {
            self.close_session_entry(session);
            return Ok(Pumped::closed(reason));
        }
        let chunk = self.chunk_bytes;
        let pumped = match (
            self.sessions.get_mut(&session),
            self.sandboxes.get_mut(&sandbox),
        ) {
            (Some(entry), Some(sandbox_entry)) => {
                pump_ingress(entry, sandbox_entry, releases, chunk, now)
            }
            _ => Pumped::closed(CloseReason::AuthorityEnded),
        };
        if pumped.is_closed() {
            self.close_session_entry(session);
        }
        Ok(pumped)
    }

    /// Closes one session at the host's request.
    pub fn close_session(&mut self, session: SessionId) -> Result<(), GateRefusal> {
        self.close_session_entry(session)
            .map(|_| ())
            .ok_or(GateRefusal::UnknownSession { session })
    }
}

/// The refusal an outside caller of `request` is told: an authentication refusal of a
/// service being served as it is, and otherwise only that the service is not published
/// on that port.
fn outsider_view(refusal: GateRefusal, request: &InboundRequest) -> GateRefusal {
    match refusal {
        GateRefusal::Proof(_)
        | GateRefusal::Ingress(
            IngressError::NotAuthenticated
            | IngressError::WrongAuthentication { .. }
            | IngressError::NotInAudience,
        ) => refusal,
        _ => not_published(request),
    }
}

fn not_published(request: &InboundRequest) -> GateRefusal {
    GateRefusal::Ingress(IngressError::NotPublished {
        service: request.service.clone(),
        port: request.port,
    })
}

/// One pump of an open session whose sandbox holds its epochs and grant.
fn pump_ingress(
    entry: &mut SessionEntry,
    sandbox: &mut SandboxEntry,
    releases: &mut dyn ReleaseAccounts,
    chunk: usize,
    now: MonotonicTime,
) -> Pumped {
    let publication = entry.publication;
    if let Some(reason) = sandbox.publication_ended(publication, now) {
        return Pumped::closed(reason);
    }
    // A spent response budget ends the session before anything more reaches the guest.
    let Some(budget) = sandbox.publications.get(&publication).copied() else {
        return Pumped::closed(CloseReason::PublicationWithdrawn);
    };
    if budget.remaining() == 0 {
        return Pumped::closed(CloseReason::ResponseBudgetSpent);
    }
    let mut pumped = Pumped::open();
    let mut buffer = vec![0u8; chunk];

    // The caller's request toward the guest.
    match entry.outside.read(&mut buffer) {
        Ok(StreamRead::Bytes(read)) => {
            let Some(bytes) = buffer.get(..read) else {
                return closed_after(pumped, overlong_read());
            };
            if let Err(error) = entry.guest.write(bytes) {
                return closed_after(pumped, CloseReason::StreamFailed(error));
            }
            entry.request_bytes = entry.request_bytes.saturating_add(byte_count(read));
            pumped.request_bytes = byte_count(read);
        }
        Ok(StreamRead::Idle) => {}
        Ok(StreamRead::Ended) => return closed_after(pumped, CloseReason::PeerEnded),
        Err(error) => return closed_after(pumped, CloseReason::StreamFailed(error)),
    }

    // The guest's response toward the caller: outbound data, charged before it is sent.
    let limit = read_limit(chunk, budget.remaining());
    let Some(window) = buffer.get_mut(..limit) else {
        return closed_after(pumped, CloseReason::ResponseBudgetSpent);
    };
    let read = match entry.guest.read(window) {
        Ok(StreamRead::Bytes(read)) if read <= limit => read,
        Ok(StreamRead::Bytes(_)) => return closed_after(pumped, overlong_read()),
        Ok(StreamRead::Idle) => return pumped,
        Ok(StreamRead::Ended) => return closed_after(pumped, CloseReason::PeerEnded),
        Err(error) => return closed_after(pumped, CloseReason::StreamFailed(error)),
    };
    let counted = byte_count(read);
    let Some(account) = releases.account(&entry.sandbox) else {
        return closed_after(pumped, CloseReason::NoReleaseAccount);
    };
    if let Err(error) = sandbox.table.respond(&entry.session, counted, account, now) {
        let reason = match error {
            IngressError::Release(refused) => CloseReason::ReleaseRefused(refused),
            IngressError::Expired => CloseReason::PublicationExpired,
            _ => CloseReason::PublicationWithdrawn,
        };
        return closed_after(pumped, reason);
    }
    let used = match sandbox.publications.get_mut(&publication) {
        Some(used) => {
            used.response_used_bytes = used.response_used_bytes.saturating_add(counted);
            *used
        }
        None => return closed_after(pumped, CloseReason::PublicationWithdrawn),
    };
    // Charged bytes that fail to leave stay counted: the bound is on what may leave.
    let Some(bytes) = buffer.get(..read) else {
        return closed_after(pumped, overlong_read());
    };
    if let Err(error) = entry.outside.write(bytes) {
        return closed_after(pumped, CloseReason::StreamFailed(error));
    }
    entry.response_bytes = entry.response_bytes.saturating_add(counted);
    pumped.response_bytes = counted;
    if used.remaining() == 0 {
        return closed_after(pumped, CloseReason::ResponseBudgetSpent);
    }
    pumped
}

/// `pumped`, with what it moved, closed for `reason`.
pub(super) fn closed_after(mut pumped: Pumped, reason: CloseReason) -> Pumped {
    pumped.state = ChannelState::Closed(reason);
    pumped
}

/// A stream claimed to read more than the buffer it was given; nothing it read is used.
pub(super) fn overlong_read() -> CloseReason {
    CloseReason::StreamFailed(StreamError::Failed {
        detail: "the stream reported more bytes than its buffer holds".to_owned(),
    })
}
