//! Large guest bodies as CORE-05 transfers (S2 CORE-05 row line 214: "object/range scope,
//! recipient, parent execution identity, expiry, byte reservations, cancellation and
//! progress"; S3 item 7 line 229; INT-02 line 270; INT-08 line 276; VM-W11 line 2603;
//! tracker S05: "byte/slot reservations, cancellation, resume and verification").
//!
//! A create or write whose content does not fit its first message is a body. Before any
//! later part is kept, the host's [`BodyAuthority`] is asked for a sealed grant naming
//! exactly the declared object, its declared length, the guest end of the grant on this
//! link as source and the parent execution as recipient. The envelope must be bound to
//! that request ([`check_binding`]); the channel's own gate then opens it, which checks the
//! seal, the clock session and expiry, a replay, the parent's authority and the
//! connection, and reserves the byte budget (and, through a port that holds one, the
//! network slot) before anything moves.
//!
//! Each part's content is then admitted as one chunk covering its exact byte range and
//! delivered once the dispatcher holds it, so the budget, the in-flight bound, the expiry
//! and the parent's authority are checked for every part. The content is hashed as it
//! arrives; the request reaches the file service only after the whole content matches the
//! declared key and the transfer completed. The channel's gate answers the
//! verified-extents question from what this channel verified itself ([`BodyExtents`]):
//! verification is the host's, and a guest's claim is never an answer.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::foundation::ids::{
    ContentHasher, ContentKey, ContentLengthError, ExecutionId, OperationId, TenantId,
};
use crate::foundation::transfer::{
    ByteRange, Connection, Direction, Endpoint, RangeSet, SealedEnvelope, TransferEnvelope,
    TransferKey, TransferPorts, TransferRefusal, TransferSession, VerifiedExtentsPort,
};
use crate::sandbox::link::{GrantHandle, StreamId};
use crate::sandbox_contract::file_protocol::RequestId;
use crate::sandbox_contract::files::GuestName;

use super::declaration::OperationKind;

/// What the host is asked to authorize before a guest body moves. Every field comes from
/// the host's identity of the channel or from the request the dispatcher took, never from
/// a guest claim about identity; `object` and `length_bytes` are the guest's declaration,
/// which the content is verified against.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BodyRequest {
    /// The CORE-05 operation the envelope must carry (`body_operation`).
    pub operation: OperationId,
    pub tenant: TenantId,
    pub parent: ExecutionId,
    /// The grant the body is written under.
    pub grant: GrantHandle,
    /// The file protocol request the body belongs to.
    pub request: RequestId,
    /// A create or a write.
    pub kind: OperationKind,
    /// The file the body is for, relative to the grant's root.
    pub name: GuestName,
    /// The declared content key.
    pub object: ContentKey,
    /// The declared content length.
    pub length_bytes: u64,
    /// The guest end of the grant on this link (`guest_route`).
    pub source: Endpoint,
    /// The parent execution.
    pub recipient: Endpoint,
}

impl BodyRequest {
    /// The connection the body's attempts make: the guest end to the host end, with no
    /// credential (no vault value crosses the link; VM-W11 line 2603).
    pub fn connection(&self) -> Connection {
        Connection {
            source: self.source.clone(),
            recipient: self.recipient.clone(),
            credential: None,
        }
    }
}

/// Why the host would not authorize a body.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthorityRefusal {
    /// The host does not let this body move under the grant.
    NotPermitted,
    /// The host cannot issue a grant now; a later request may succeed.
    Unavailable,
}

impl fmt::Display for AuthorityRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotPermitted => f.write_str("the host does not authorize this body"),
            Self::Unavailable => f.write_str("the host cannot authorize a body now"),
        }
    }
}

impl std::error::Error for AuthorityRefusal {}

/// The host's issuer of body grants: its policy decides whether a body may move and with
/// what budget, stop bounds and expiry, and seals the envelope with the host's transfer
/// key. It is the authority outside this module (S3.1 "issue bounded operation
/// capabilities", VM part line 2047).
pub trait BodyAuthority: Send + Sync {
    /// A sealed CORE-05 envelope for `request`, or why the host refuses it.
    fn authorize(&self, request: &BodyRequest) -> Result<SealedEnvelope, AuthorityRefusal>;
}

/// What the channel needs to move bodies: the host's transfer key (whose clones share its
/// replay registry), the host's transfer ports (clock and its session, the parent's
/// authority, the byte budget and progress) and the issuer of body grants. The ports'
/// verified-extents port is replaced by the channel's own.
#[derive(Clone)]
pub struct BodyTransfers {
    pub key: TransferKey,
    pub ports: TransferPorts,
    pub authority: Arc<dyn BodyAuthority>,
}

impl fmt::Debug for BodyTransfers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BodyTransfers")
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

/// The envelope field that does not bind a grant to the body it was asked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BindingField {
    /// Not the body's operation.
    Operation,
    Tenant,
    Parent,
    /// Not a download from the guest end into the host.
    Direction,
    /// Not the guest end of this grant on a link of this instance and boot.
    Source,
    /// Not the parent execution.
    Recipient,
    /// A credential, which no body over the link presents.
    Credential,
    /// Not exactly the declared object, whole, at the declared length.
    Scope,
    /// A budget smaller than the declared length.
    Budget,
    /// An in-flight bound smaller than one message.
    StopBounds,
}

impl fmt::Display for BindingField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Operation => "its operation is not the body's",
            Self::Tenant => "it is another tenant's",
            Self::Parent => "it belongs to another execution",
            Self::Direction => "it is not a download from the guest into the host",
            Self::Source => "its source is not this grant's guest end on this instance and boot",
            Self::Recipient => "its recipient is not the parent execution",
            Self::Credential => "it carries a credential",
            Self::Scope => "its scope is not exactly the declared object at its declared length",
            Self::Budget => "its byte budget is smaller than the declared length",
            Self::StopBounds => "its in-flight bound is smaller than one message",
        })
    }
}

/// The first field of `envelope` that does not bind it to `request`, on a channel whose
/// messages are at most `message_bytes`.
pub(super) fn check_binding(
    envelope: &TransferEnvelope,
    request: &BodyRequest,
    message_bytes: u64,
) -> Result<(), BindingField> {
    let fields = envelope.fields();
    if fields.operation != request.operation {
        return Err(BindingField::Operation);
    }
    if fields.tenant != request.tenant {
        return Err(BindingField::Tenant);
    }
    if fields.parent != request.parent {
        return Err(BindingField::Parent);
    }
    if fields.direction != Direction::Download {
        return Err(BindingField::Direction);
    }
    if fields.source != request.source {
        return Err(BindingField::Source);
    }
    if fields.recipient != request.recipient {
        return Err(BindingField::Recipient);
    }
    if fields.credential.is_some() {
        return Err(BindingField::Credential);
    }
    let objects = fields.scope.objects();
    let whole = ByteRange::new(0, request.length_bytes).map(RangeSet::single);
    let exact = objects.len() == 1
        && objects.get(&request.object).is_some_and(|grant| {
            grant.size_bytes() == request.length_bytes
                && whole.as_ref().is_ok_and(|whole| grant.granted() == whole)
        });
    if !exact {
        return Err(BindingField::Scope);
    }
    if fields.budget_bytes < request.length_bytes {
        return Err(BindingField::Budget);
    }
    if fields.stop_bounds.max_in_flight_bytes < message_bytes {
        return Err(BindingField::StopBounds);
    }
    Ok(())
}

/// The objects this channel verified, as its gate's verified-extents port: a body's whole
/// object, recorded only after its content matched the declared key and only while its
/// transfer completes. It answers for the channel's tenant, parent and host end alone.
pub(super) struct BodyExtents {
    tenant: TenantId,
    parent: ExecutionId,
    recipient: Endpoint,
    /// Each object's length and how many bodies are completing it now.
    verified: Mutex<BTreeMap<ContentKey, (u64, u32)>>,
}

impl BodyExtents {
    pub(super) fn new(tenant: TenantId, parent: ExecutionId, recipient: Endpoint) -> Self {
        Self {
            tenant,
            parent,
            recipient,
            verified: Mutex::new(BTreeMap::new()),
        }
    }

    pub(super) fn record(&self, object: ContentKey, length_bytes: u64) {
        let mut verified = lock(&self.verified);
        let entry = verified.entry(object).or_insert((length_bytes, 0));
        entry.1 = entry.1.saturating_add(1);
    }

    pub(super) fn forget(&self, object: &ContentKey) {
        let mut verified = lock(&self.verified);
        if let Some(entry) = verified.get_mut(object) {
            entry.1 = entry.1.saturating_sub(1);
            if entry.1 == 0 {
                verified.remove(object);
            }
        }
    }
}

impl VerifiedExtentsPort for BodyExtents {
    fn verified(
        &self,
        tenant: &TenantId,
        parent: &ExecutionId,
        recipient: &Endpoint,
        object: &ContentKey,
    ) -> RangeSet {
        if *tenant != self.tenant || *parent != self.parent || *recipient != self.recipient {
            return RangeSet::new();
        }
        lock(&self.verified)
            .get(object)
            .and_then(|(length_bytes, _)| ByteRange::new(0, *length_bytes).ok())
            .map(RangeSet::single)
            .unwrap_or_default()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Why a body could not keep a part.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum BodyFailure {
    /// The content runs past the declared length.
    Length(ContentLengthError),
    /// CORE-05 refused the chunk.
    Transfer(TransferRefusal),
}

/// One body: its declaration, its transfer and what the host holds of it.
pub(super) struct Body {
    pub(super) operation: OperationId,
    pub(super) object: ContentKey,
    pub(super) kind: OperationKind,
    pub(super) name: GuestName,
    pub(super) declared: u64,
    /// Content bytes the dispatcher holds.
    pub(super) held: u64,
    /// The next part the dispatcher awaits.
    pub(super) next_part: u32,
    pub(super) hasher: ContentHasher,
    pub(super) session: TransferSession,
    pub(super) connection: Connection,
    /// The stream carrying it, or `None` while it is interrupted.
    pub(super) stream: Option<StreamId>,
}

impl Body {
    /// Keeps `content`, the next bytes of the body, as part `part`: hashed, then admitted
    /// as one chunk covering exactly its range and delivered.
    pub(super) fn take(&mut self, part: u32, content: &[u8]) -> Result<(), BodyFailure> {
        if !content.is_empty() {
            self.hasher.update(content).map_err(BodyFailure::Length)?;
            let length = u64::try_from(content.len()).unwrap_or(u64::MAX);
            let range = ByteRange::starting_at(self.held, length).map_err(|_| {
                BodyFailure::Length(ContentLengthError {
                    declared: self.declared,
                    seen: u64::MAX,
                })
            })?;
            let permit = self
                .session
                .admit(&self.object, range)
                .map_err(BodyFailure::Transfer)?;
            self.session
                .deliver(permit)
                .map_err(BodyFailure::Transfer)?;
            self.held = self.held.saturating_add(length);
        }
        self.next_part = part.saturating_add(1);
        Ok(())
    }
}
