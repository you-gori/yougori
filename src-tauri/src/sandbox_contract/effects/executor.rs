//! Narrow executors and the provider port (VM part §4.5 line 2004; §4.6 lines 2016–2026;
//! §9.2 lines 2344 and 2353; VM-W28).
//!
//! A [`NarrowExecutor`] has one fixed operation contract and no way to widen it. It
//! receives a [`TypedOperation`]: the immutable description, the sealed capability and an
//! opaque [`CredentialHandle`], never the credential itself. It independently verifies
//! the seal, its own identity, every bound field, expiry, the contract, the credential's
//! audience and the payload bytes against their content keys; it consumes the nonce in
//! its own replay guard; then it reconstructs the outbound request from the description
//! alone and returns only the contract's permitted response fields. A redirect is never
//! followed and a failed request is never broadened: the executor has no input that
//! could change the request.
//!
//! The provider port receives the request, the payload and attachment bytes the executor
//! read and checked ([`RequestContent`]), the credential reference and the controller's
//! clock reading; it checks the bytes again against the request's content keys. A port
//! that refuses before sending answers [`ProviderReply::Refused`], which is recorded as the
//! executor's refusal, never as the provider's.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::budget::WireMeasure;
use super::canonical::{len_u64, ParamName, Parameters};
use super::capability::{
    CapabilityKey, CapabilityRefusal, ExecutorIdentity, OperationCapability, SealedCapability,
};
use super::contract::{ContractRefusal, OperationContract};
use super::description::{
    AttachmentName, EffectDescription, IdempotencyKey, IdempotencyRequirement, OperationKey,
    PayloadMismatch, PayloadRef, Precondition, ResourceRef, RouteRef,
};
use super::replay::{NonceRecord, ReplayGuard, ReplayRefusal};
use super::secrets::{CredentialHandle, CredentialRefusal};
use super::state::{Observation, ProviderResult};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder, MonotonicTime};
use crate::foundation::transfer::CredentialRef;

/// Bytes of an idempotency-key header: a 17-byte name and 64 hexadecimal digits.
pub const IDEMPOTENCY_HEADER_BYTES: u64 = 17 + 64;
/// Bytes of one precondition header: an 11-byte name and 64 hexadecimal digits.
pub const PRECONDITION_HEADER_BYTES: u64 = 11 + 64;

/// The host's immutable content store, by content key.
pub trait PayloadStore {
    fn bytes(&self, content: &ContentKey) -> Option<Vec<u8>>;
}

/// The request an executor sends, built from the description alone.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboundRequest {
    pub operation: OperationKey,
    pub route: RouteRef,
    pub resource: ResourceRef,
    pub parameters: Parameters,
    pub payload: Option<PayloadRef>,
    pub attachments: BTreeMap<AttachmentName, PayloadRef>,
    pub preconditions: BTreeSet<Precondition>,
    /// Sent only when the provider deduplicates by key and the description requires it.
    pub idempotency_key: Option<IdempotencyKey>,
    /// Every byte the request puts on the wire.
    pub wire: WireMeasure,
}

/// What a provider answered. Response fields are untrusted until the executor filters
/// them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderReply {
    Committed {
        response: BTreeMap<String, String>,
        spend_microunits: u64,
        volume_units: u64,
    },
    Rejected {
        code: String,
    },
    PreconditionFailed,
    Redirect {
        route: RouteRef,
    },
    PartialSuccess {
        response: BTreeMap<String, String>,
        spend_microunits: u64,
        volume_units: u64,
    },
    /// The request left and nothing came back.
    NoResponse,
    /// The port refused before anything was sent; recorded as the executor's refusal.
    Refused {
        refusal: ExecutorRefusal,
    },
}

/// What a provider lookup found, for reconciliation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProviderLookup {
    Committed {
        response: BTreeMap<String, String>,
        spend_microunits: u64,
        volume_units: u64,
    },
    NotCommitted,
    Unknown,
}

/// The payload and attachment bytes of one request, read from the content store and
/// checked against the description's content keys by the narrow executor. A provider
/// port checks them again with [`RequestContent::check`] before using them. `Debug` shows
/// lengths only: the bytes may be user private content.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct RequestContent {
    pub payload: Option<Vec<u8>>,
    pub attachments: BTreeMap<AttachmentName, Vec<u8>>,
}

impl fmt::Debug for RequestContent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RequestContent")
            .field("payload_bytes", &self.payload.as_ref().map(Vec::len))
            .field(
                "attachment_bytes",
                &self
                    .attachments
                    .iter()
                    .map(|(name, bytes)| (name.as_str(), bytes.len()))
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

fn check_part(reference: &PayloadRef, bytes: Option<&Vec<u8>>) -> Result<(), ExecutorRefusal> {
    let bytes = bytes.ok_or(ExecutorRefusal::PayloadMissing {
        content: reference.content,
    })?;
    let actual = ContentKey::of(bytes);
    if actual != reference.content || len_u64(bytes.len()) != reference.length_bytes {
        return Err(ExecutorRefusal::PayloadMismatch {
            mismatch: PayloadMismatch {
                expected: reference.content,
                actual,
            },
        });
    }
    Ok(())
}

impl RequestContent {
    /// The payload bytes, if the request has a payload.
    pub fn payload(&self) -> Option<&[u8]> {
        self.payload.as_deref()
    }

    /// Checks every part against the content key and length `request` binds, and that no
    /// part is missing or extra (§4.6 line 2022: the bytes that leave are the bytes
    /// described).
    pub fn check(&self, request: &OutboundRequest) -> Result<(), ExecutorRefusal> {
        match (&request.payload, &self.payload) {
            (Some(reference), bytes) => check_part(reference, bytes.as_ref())?,
            (None, Some(bytes)) => {
                return Err(ExecutorRefusal::PayloadMismatch {
                    mismatch: PayloadMismatch {
                        expected: ContentKey::of(&[]),
                        actual: ContentKey::of(bytes),
                    },
                })
            }
            (None, None) => {}
        }
        for (name, reference) in &request.attachments {
            check_part(reference, self.attachments.get(name))?;
        }
        if let Some((_, bytes)) = self
            .attachments
            .iter()
            .find(|(name, _)| !request.attachments.contains_key(*name))
        {
            return Err(ExecutorRefusal::PayloadMismatch {
                mismatch: PayloadMismatch {
                    expected: ContentKey::of(&[]),
                    actual: ContentKey::of(bytes),
                },
            });
        }
        Ok(())
    }
}

/// The provider behind a narrow executor. The credential arrives as a reference the
/// adapter resolves inside the vault boundary; `now` is the controller's clock reading,
/// against which the port decides every expiry it checks.
pub trait ProviderPort {
    /// Sends `request` with `content`, which the port checks against the request first.
    fn submit(
        &mut self,
        request: &OutboundRequest,
        content: &RequestContent,
        credential: CredentialRef,
        now: MonotonicTime,
    ) -> ProviderReply;

    /// Looks up whether `request` committed, by idempotency key or resource state.
    fn lookup(
        &mut self,
        request: &OutboundRequest,
        content: &RequestContent,
        credential: CredentialRef,
        now: MonotonicTime,
    ) -> ProviderLookup;
}

/// The response fields the contract permits, and nothing else (§4.5 lines 2004, 2008).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PermittedResponse(BTreeMap<ParamName, String>);

impl PermittedResponse {
    fn filter(response: &BTreeMap<String, String>, permitted: &BTreeSet<ParamName>) -> Self {
        Self(
            permitted
                .iter()
                .filter_map(|name| {
                    response
                        .get(name.as_str())
                        .map(|value| (name.clone(), value.clone()))
                })
                .collect(),
        )
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(key, _)| key.as_str() == name)
            .map(|(_, value)| value.as_str())
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn digest(&self) -> Digest {
        self.0
            .iter()
            .fold(
                DigestBuilder::new("yougori/sandbox/permitted-response/v1")
                    .u64(len_u64(self.0.len())),
                |b, (name, value)| b.str(name.as_str()).str(value),
            )
            .finish()
    }

    fn result(&self, spend_microunits: u64, volume_units: u64) -> ProviderResult {
        ProviderResult {
            result: self.digest(),
            spend_microunits,
            volume_units,
        }
    }
}

/// One operation as an executor receives it (§4.5 line 2004).
#[derive(Clone, Copy, Debug)]
pub struct TypedOperation<'a> {
    pub description: &'a EffectDescription,
    pub capability: &'a SealedCapability,
    pub credential: CredentialHandle,
}

strict_tagged_enum! {
    /// Why an executor refused before sending anything.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ExecutorRefusal (tag = "reason", wire = ExecutorRefusalWire, wire_name = "ExecutorRefusalWire") {
        Capability { refusal: CapabilityRefusal },
        Contract { refusal: ContractRefusal },
        Credential { refusal: CredentialRefusal },
        Replay { refusal: ReplayRefusal },
        PayloadMissing { content: ContentKey },
        PayloadMismatch { mismatch: PayloadMismatch },
        WireBytesAboveCeiling { measured_bytes: u64, max_wire_bytes_out: u64 },
        /// The executor sent nothing, for a reason of its own beyond the checks above:
        /// another check it makes, or a transport that could not send. `detail` is a
        /// short stable tag; the executor keeps the full detail.
        NotSent { detail: String },
    }
}

impl fmt::Display for ExecutorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Capability { refusal } => write!(f, "{refusal}"),
            Self::Contract { refusal } => write!(f, "{refusal}"),
            Self::Credential { refusal } => write!(f, "{refusal}"),
            Self::Replay { refusal } => write!(f, "{refusal}"),
            Self::PayloadMissing { content } => {
                write!(f, "the content store has no bytes for {content}")
            }
            Self::PayloadMismatch { mismatch } => write!(f, "{mismatch}"),
            Self::WireBytesAboveCeiling {
                measured_bytes,
                max_wire_bytes_out,
            } => write!(
                f,
                "the request would put {measured_bytes} bytes on the wire, above its \
                 {max_wire_bytes_out}-byte ceiling"
            ),
            Self::NotSent { detail } => write!(f, "the executor sent nothing: {detail}"),
        }
    }
}

impl std::error::Error for ExecutorRefusal {}

/// What an execution came to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecutorOutcome {
    /// Nothing was sent.
    Refused(ExecutorRefusal),
    Committed {
        result: ProviderResult,
        response: PermittedResponse,
    },
    /// The provider certainly did not commit.
    Rejected {
        code: String,
    },
    /// The provider redirected; the executor did not follow, and nothing committed.
    RedirectRefused {
        route: RouteRef,
    },
    PartialSuccess {
        partial: ProviderResult,
    },
    NoResponse,
}

/// An execution's outcome and the bytes that left, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutorReport {
    pub outcome: ExecutorOutcome,
    pub sent: Option<WireMeasure>,
}

/// An executor the controller dispatches to.
pub trait EffectExecutor {
    fn identity(&self) -> &ExecutorIdentity;

    /// Verifies and executes one typed operation at `now`.
    fn execute(&mut self, operation: TypedOperation<'_>, now: MonotonicTime) -> ExecutorReport;

    /// Asks the provider whether `description` committed, for reconciliation, at `now`,
    /// the controller's clock reading.
    fn lookup(
        &mut self,
        description: &EffectDescription,
        credential: CredentialHandle,
        now: MonotonicTime,
    ) -> Observation;
}

/// An executor with one fixed operation contract (§2.6 line 1830: no executor API
/// widens its fixed operation or reads its credential).
pub struct NarrowExecutor<P: ProviderPort, S: PayloadStore> {
    identity: ExecutorIdentity,
    contract: OperationContract,
    key: CapabilityKey,
    session: ClockSession,
    provider: P,
    store: S,
    replay: ReplayGuard,
}

impl<P: ProviderPort, S: PayloadStore> NarrowExecutor<P, S> {
    pub fn new(
        identity: ExecutorIdentity,
        contract: OperationContract,
        key: CapabilityKey,
        session: ClockSession,
        provider: P,
        store: S,
    ) -> Self {
        Self {
            identity,
            contract,
            key,
            session,
            provider,
            store,
            replay: ReplayGuard::new(),
        }
    }

    pub fn contract(&self) -> &OperationContract {
        &self.contract
    }

    pub fn provider(&self) -> &P {
        &self.provider
    }

    pub fn provider_mut(&mut self) -> &mut P {
        &mut self.provider
    }

    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    /// The request the description stands for, as this executor builds it.
    pub fn reconstruct(&self, description: &EffectDescription) -> OutboundRequest {
        build_request(&self.contract, description)
    }

    /// The payload and attachment bytes `description` binds, read from the content store
    /// and checked against their content keys and lengths.
    pub fn verified_content(
        &self,
        description: &EffectDescription,
    ) -> Result<RequestContent, ExecutorRefusal> {
        let read = |reference: PayloadRef| {
            let bytes =
                self.store
                    .bytes(&reference.content)
                    .ok_or(ExecutorRefusal::PayloadMissing {
                        content: reference.content,
                    })?;
            check_part(&reference, Some(&bytes))?;
            Ok::<Vec<u8>, ExecutorRefusal>(bytes)
        };
        let payload = description.payload().map(read).transpose()?;
        let mut attachments = BTreeMap::new();
        for (name, reference) in description.attachments() {
            attachments.insert(name.clone(), read(*reference)?);
        }
        Ok(RequestContent {
            payload,
            attachments,
        })
    }

    fn verify(
        &mut self,
        operation: &TypedOperation<'_>,
        now: MonotonicTime,
    ) -> Result<(OutboundRequest, RequestContent), ExecutorRefusal> {
        let capability: &OperationCapability = self
            .key
            .verify(operation.capability)
            .map_err(|refusal| ExecutorRefusal::Capability { refusal })?;
        if capability.executor != self.identity {
            return Err(ExecutorRefusal::Capability {
                refusal: CapabilityRefusal::WrongExecutor,
            });
        }
        let description = operation.description;
        capability
            .check_binding(description)
            .and_then(|()| capability.check_time(now, self.session))
            .map_err(|refusal| ExecutorRefusal::Capability { refusal })?;
        self.contract
            .validate(description)
            .map_err(|refusal| ExecutorRefusal::Contract { refusal })?;
        operation
            .credential
            .usable_for(description.destination().route, now, self.session)
            .map_err(|refusal| ExecutorRefusal::Credential { refusal })?;
        let content = self.verified_content(description)?;
        let request = build_request(&self.contract, description);
        let measured = request.wire.total_bytes();
        if measured > description.max_wire_bytes_out() {
            return Err(ExecutorRefusal::WireBytesAboveCeiling {
                measured_bytes: measured,
                max_wire_bytes_out: description.max_wire_bytes_out(),
            });
        }
        let epoch = capability.generations.authorization;
        self.replay
            .consume_presented(
                &capability.sandbox,
                capability.nonce,
                NonceRecord {
                    clock: capability.clock,
                    expires_at: capability.expires_at,
                    epoch,
                },
                now,
                self.session,
                epoch,
            )
            .map_err(|refusal| ExecutorRefusal::Replay { refusal })?;
        Ok((request, content))
    }
}

impl<P: ProviderPort, S: PayloadStore> EffectExecutor for NarrowExecutor<P, S> {
    fn identity(&self) -> &ExecutorIdentity {
        &self.identity
    }

    fn execute(&mut self, operation: TypedOperation<'_>, now: MonotonicTime) -> ExecutorReport {
        let (request, content) = match self.verify(&operation, now) {
            Ok(verified) => verified,
            Err(refusal) => {
                return ExecutorReport {
                    outcome: ExecutorOutcome::Refused(refusal),
                    sent: None,
                }
            }
        };
        let reply = self
            .provider
            .submit(&request, &content, operation.credential.reference(), now);
        if let ProviderReply::Refused { refusal } = reply {
            return ExecutorReport {
                outcome: ExecutorOutcome::Refused(refusal),
                sent: None,
            };
        }
        let permitted = &self.contract.response_fields;
        let outcome = match reply {
            ProviderReply::Committed {
                response,
                spend_microunits,
                volume_units,
            } => {
                let response = PermittedResponse::filter(&response, permitted);
                ExecutorOutcome::Committed {
                    result: response.result(spend_microunits, volume_units),
                    response,
                }
            }
            ProviderReply::Rejected { code } => ExecutorOutcome::Rejected {
                code: code.chars().take(64).collect(),
            },
            ProviderReply::PreconditionFailed => ExecutorOutcome::Rejected {
                code: "precondition_failed".to_owned(),
            },
            ProviderReply::Redirect { route } => ExecutorOutcome::RedirectRefused { route },
            ProviderReply::PartialSuccess {
                response,
                spend_microunits,
                volume_units,
            } => ExecutorOutcome::PartialSuccess {
                partial: PermittedResponse::filter(&response, permitted)
                    .result(spend_microunits, volume_units),
            },
            ProviderReply::NoResponse => ExecutorOutcome::NoResponse,
            // Answered above; kept for an exhaustive match.
            ProviderReply::Refused { refusal } => {
                return ExecutorReport {
                    outcome: ExecutorOutcome::Refused(refusal),
                    sent: None,
                }
            }
        };
        ExecutorReport {
            outcome,
            sent: Some(request.wire),
        }
    }

    /// A lookup needs a credential usable at `now` and the described content intact;
    /// without either the outcome stays unknown and nothing is asked.
    fn lookup(
        &mut self,
        description: &EffectDescription,
        credential: CredentialHandle,
        now: MonotonicTime,
    ) -> Observation {
        if credential
            .usable_for(description.destination().route, now, self.session)
            .is_err()
        {
            return Observation::StillUnknown;
        }
        let Ok(content) = self.verified_content(description) else {
            return Observation::StillUnknown;
        };
        let request = build_request(&self.contract, description);
        match self
            .provider
            .lookup(&request, &content, credential.reference(), now)
        {
            ProviderLookup::Committed {
                response,
                spend_microunits,
                volume_units,
            } => Observation::Committed {
                result: PermittedResponse::filter(&response, &self.contract.response_fields)
                    .result(spend_microunits, volume_units),
            },
            ProviderLookup::NotCommitted => Observation::NotCommitted,
            ProviderLookup::Unknown => Observation::StillUnknown,
        }
    }
}

/// Builds the outbound request from the description and the contract alone, and
/// measures every byte it puts on the wire.
fn build_request(contract: &OperationContract, description: &EffectDescription) -> OutboundRequest {
    let idempotency = description.idempotency();
    let idempotency_key = (contract.provider_key
        && idempotency.requirement == IdempotencyRequirement::ProviderKey)
        .then_some(idempotency.key);
    let operation = description.operation();
    let preconditions = description.preconditions().clone();
    let header_bytes = u64::from(contract.header_bytes)
        .saturating_add(if idempotency_key.is_some() {
            IDEMPOTENCY_HEADER_BYTES
        } else {
            0
        })
        .saturating_add(len_u64(preconditions.len()).saturating_mul(PRECONDITION_HEADER_BYTES));
    // "/{provider}/{operation}/v{version}/{account}/{object}"
    let url_bytes = len_u64(operation.provider.as_str().len())
        .saturating_add(len_u64(operation.operation.as_str().len()))
        .saturating_add(len_u64(operation.contract_version.to_string().len()))
        .saturating_add(64 + 64 + 6);
    let name_bytes = contract
        .routes
        .get(&description.destination().route)
        .map_or(0, |route| u64::from(route.name_bytes));
    let wire = WireMeasure {
        body_bytes: description
            .parameters()
            .encoded_bytes()
            .saturating_add(description.content_bytes()),
        header_bytes,
        url_bytes,
        name_bytes,
        framing_bytes: u64::from(contract.framing_bytes),
    };
    OutboundRequest {
        operation: operation.clone(),
        route: description.destination().route,
        resource: description.resource(),
        parameters: description.parameters().clone(),
        payload: description.payload(),
        attachments: description.attachments().clone(),
        preconditions,
        idempotency_key,
        wire,
    }
}
