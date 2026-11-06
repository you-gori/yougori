//! The typed provider executor (VM part §4.5 line 2004; §4.6 lines 2016–2026; §9.2
//! VM-N2; VM-W12; VM-W28).
//!
//! A [`ProviderExecutor`] has one fixed provider operation and implements the effects
//! [`EffectExecutor`] port. It receives a typed operation and an opaque credential
//! reference, never the credential. Before anything leaves it re-verifies, on its own:
//!
//! - the durable effect record: the presented capability is the one issued, and the
//!   effect is reserved or dispatched;
//! - the sandbox's generations and lease, from the CORE-04 authority;
//! - the authorization basis (standing delegation or individual approval), now;
//! - the budget hold and the cost model's conservative maximum;
//! - the credential's class and that it is the bound route's credential;
//! - the vault grant for exactly this executor, operation, route and account;
//! - the request it builds itself: no secret inside, and no more wire bytes than
//!   reserved;
//!
//! then consumes the central spend reservation once and hands the typed operation to the
//! effects [`NarrowExecutor`], which verifies the seal, every bound field, expiry, the
//! contract, the payload bytes and the nonce, and calls this module's vault-backed
//! provider port. The response policy decides what, if anything, returns. A redirect is
//! never followed and a failed request is never broadened: no input can change the
//! request. Spend settles by the outcome; an unknown outcome stays fully spent.
//!
//! A refusal before the spend reservation is consumed leaves it in place, since the
//! refused presentation may be a forgery against a legitimate reservation; the host
//! returns it when the effect fails. A reservation the executor consumed is returned by
//! the executor when nothing left.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::operation::{check_request_with, CredentialClaim, OperationRefusal, ProviderOperation};
use super::request::{build_upstream, RequestRefusal, UpstreamRequest};
use super::response::{evaluate_response, ResponseRefusal, ResponseVerdict};
use super::scan::{KnownSecrets, LeakFinding, LeakSource, ScanEncoding};
use super::spend::{SharedSpendLedger, SpendRefusal, SpendSettlement, SpendStatus};
use super::vault::{
    CredentialVault, LookupResult, TransportResult, UpstreamTransport, VaultRefusal, VaultScope,
};
use super::{operation::OperationCatalog, records::EffectRecordsPort};
use crate::foundation::coordination::{LeaseRefusal, SandboxGenerations};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{Digest, MonotonicTime};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::effects::{
    AuthorityPort, CapabilityKey, CapabilityRefusal, ContractRefusal, CostCeiling,
    CredentialHandle, EffectDescription, EffectExecutor, EffectId, EffectPhase, ExecutorIdentity,
    ExecutorName, ExecutorOutcome, ExecutorRefusal, ExecutorReport, ExposureProfile,
    NarrowExecutor, Observation, OperationKey, OutboundRequest, PayloadStore, ProviderLookup,
    ProviderPort, ProviderReply, RequestContent, RouteRef, SandboxStanding, ScopeViolation,
    SecretClass, TypedOperation,
};

/// Bytes of the authorization header line around the vault's value: `authorization: `
/// and the line end.
const AUTHORIZATION_LINE_BYTES: u64 = 17;

strict_provider_enum! {
    /// Why the executor refused before anything was sent.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ProviderRefusal tag "reason" {
        OperationMismatch,
        NoRecord,
        /// The presented capability is not the one the durable record holds.
        RecordMismatch,
        WrongPhase { phase: EffectPhase },
        NoAuthority,
        GenerationChanged { bound: SandboxGenerations, current: SandboxGenerations },
        LeaseRefused { refusal: LeaseRefusal },
        Delegation { violation: ScopeViolation },
        NoBudgetHold,
        BudgetHoldBelowCost { held_microunits: u64, required_microunits: u64 },
        Request { refusal: OperationRefusal },
        CredentialClassUnsupported { class: SecretClass },
        /// The credential reference is not the one the bound route declares.
        CredentialNotRouteCredential,
        Vault { refusal: VaultRefusal },
        Build { refusal: RequestRefusal },
        /// The request the executor built would carry a secret.
        RequestCarriesSecret { finding: LeakFinding },
        WireAboveReservation { measured_bytes: u64, reserved_bytes: u64 },
        Spend { refusal: SpendRefusal },
        Executor { refusal: ExecutorRefusal },
    }
}

impl ProviderRefusal {
    /// A stable short name, used in rejection codes.
    pub fn tag(&self) -> String {
        match self {
            Self::OperationMismatch => "operation_mismatch".to_owned(),
            Self::NoRecord => "no_record".to_owned(),
            Self::RecordMismatch => "record_mismatch".to_owned(),
            Self::WrongPhase { .. } => "wrong_phase".to_owned(),
            Self::NoAuthority => "no_authority".to_owned(),
            Self::GenerationChanged { .. } => "generation_changed".to_owned(),
            Self::LeaseRefused { .. } => "lease_refused".to_owned(),
            Self::Delegation { .. } => "delegation".to_owned(),
            Self::NoBudgetHold => "no_budget_hold".to_owned(),
            Self::BudgetHoldBelowCost { .. } => "budget_hold_below_cost".to_owned(),
            Self::Request { .. } => "request".to_owned(),
            Self::CredentialClassUnsupported { .. } => "credential_class_unsupported".to_owned(),
            Self::CredentialNotRouteCredential => "credential_not_route_credential".to_owned(),
            Self::Vault { refusal } => format!("vault:{}", refusal.tag()),
            Self::Build { refusal } => format!("build:{}", refusal.tag()),
            Self::RequestCarriesSecret { .. } => "request_carries_secret".to_owned(),
            Self::WireAboveReservation { .. } => "wire_above_reservation".to_owned(),
            Self::Spend { refusal } => format!("spend:{}", refusal.tag()),
            Self::Executor { .. } => "executor".to_owned(),
        }
    }
}

impl fmt::Display for ProviderRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OperationMismatch => f.write_str("the effect names another operation"),
            Self::NoRecord => f.write_str("the effect has no durable record"),
            Self::RecordMismatch => {
                f.write_str("the capability presented is not the one the record holds")
            }
            Self::WrongPhase { phase } => write!(f, "the effect is {}", phase.name()),
            Self::NoAuthority => f.write_str("the sandbox holds no authority now"),
            Self::GenerationChanged { bound, current } => write!(
                f,
                "the capability is bound to generations {bound}; the sandbox is at {current}"
            ),
            Self::LeaseRefused { refusal } => write!(f, "the lease is not honoured: {refusal:?}"),
            Self::Delegation { violation } => write!(f, "{violation}"),
            Self::NoBudgetHold => f.write_str("the effect holds no budget reservation"),
            Self::BudgetHoldBelowCost {
                held_microunits,
                required_microunits,
            } => write!(
                f,
                "{held_microunits} microunits are held; the effect may cost {required_microunits}"
            ),
            Self::Request { refusal } => write!(f, "{refusal}"),
            Self::CredentialClassUnsupported { class } => {
                write!(f, "the operation does not accept a {class:?}")
            }
            Self::CredentialNotRouteCredential => {
                f.write_str("the credential is not the bound route's credential")
            }
            Self::Vault { refusal } => write!(f, "{refusal}"),
            Self::Build { refusal } => write!(f, "{refusal}"),
            Self::RequestCarriesSecret { finding } => write!(
                f,
                "the request would carry a secret ({:?}, {:?}); nothing was sent",
                finding.location, finding.source
            ),
            Self::WireAboveReservation {
                measured_bytes,
                reserved_bytes,
            } => write!(
                f,
                "the request takes {measured_bytes} wire bytes; {reserved_bytes} are reserved"
            ),
            Self::Spend { refusal } => write!(f, "{refusal}"),
            Self::Executor { refusal } => write!(f, "{refusal}"),
        }
    }
}

impl std::error::Error for ProviderRefusal {}

strict_provider_enum! {
    /// Why an outcome is unknown (VM-P31).
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum UnknownReason tag "reason" {
        ResponseLost,
        PartialSuccess,
        /// A response came back but was refused: leaked, invalid or a server error.
        ResponseRefused { refusal: ResponseRefusal },
    }
}

strict_provider_enum! {
    /// What one execution came to.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ExecutionOutcome tag "outcome" {
        Refused { refusal: ProviderRefusal },
        /// Committed; `representation` is the digest of the permitted response.
        Committed { representation: Digest, reported_spend_microunits: Option<u64> },
        Rejected { status: u16 },
        NotSent,
        PreconditionFailed,
        /// Never followed; the target is kept only as a digest.
        RedirectRefused { target: Digest },
        Unknown { reason: UnknownReason },
    }
}

/// The executor's record of one execution. It holds no secret: findings name places, and
/// responses appear only as digests.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderExecution {
    pub effect: EffectId,
    pub operation: OperationKey,
    pub attempt: u32,
    pub outcome: ExecutionOutcome,
    /// Wire bytes the request took, the authorization header counted by length; `None`
    /// when nothing left.
    pub sent_bytes: Option<u64>,
    pub spend: Option<SpendSettlement>,
}

impl fmt::Display for ProviderExecution {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let outcome = match &self.outcome {
            ExecutionOutcome::Refused { refusal } => format!("refused: {refusal}"),
            ExecutionOutcome::Committed { .. } => "committed".to_owned(),
            ExecutionOutcome::Rejected { status } => format!("rejected with {status}"),
            ExecutionOutcome::NotSent => "not sent".to_owned(),
            ExecutionOutcome::PreconditionFailed => "precondition failed".to_owned(),
            ExecutionOutcome::RedirectRefused { .. } => "redirect refused".to_owned(),
            ExecutionOutcome::Unknown { reason } => format!("outcome unknown: {reason:?}"),
        };
        write!(
            f,
            "{}/{} attempt {}: {outcome}",
            self.operation.provider, self.operation.operation, self.attempt
        )
    }
}

/// What the provider port saw; a committed outcome takes its representation digest from
/// the effects result.
enum TraceOutcome {
    Committed,
    Other(ExecutionOutcome),
}

/// What an execution left behind inside the provider port.
struct Trace {
    left: bool,
    sent_bytes: Option<u64>,
    outcome: TraceOutcome,
    reported_spend_microunits: Option<u64>,
}

struct Prepared {
    upstream: UpstreamRequest,
    scope: VaultScope,
    measured_bytes: u64,
    class: SecretClass,
}

/// The effects provider port over the vault, the transport and the response policy.
struct VaultedProvider {
    operation: ProviderOperation,
    members: BTreeMap<OperationKey, ProviderOperation>,
    executor: ExecutorName,
    vault: Box<dyn CredentialVault>,
    transport: Box<dyn UpstreamTransport>,
    known: KnownSecrets,
    cost: CostCeiling,
    trace: Option<Trace>,
}

/// The effects refusal that carries `refusal` through the executor port: a native one
/// where effects has it, otherwise the executor's own `NotSent`. Either way the
/// controller records it as the executor's refusal.
fn executor_refusal(refusal: &ProviderRefusal) -> ExecutorRefusal {
    match refusal {
        ProviderRefusal::OperationMismatch => ExecutorRefusal::Contract {
            refusal: ContractRefusal::OperationMismatch,
        },
        ProviderRefusal::Request {
            refusal: OperationRefusal::Contract { refusal },
        } => ExecutorRefusal::Contract {
            refusal: refusal.clone(),
        },
        ProviderRefusal::Request {
            refusal: OperationRefusal::CostAboveDescription { .. },
        } => ExecutorRefusal::Contract {
            refusal: ContractRefusal::CostAboveContract,
        },
        ProviderRefusal::WireAboveReservation {
            measured_bytes,
            reserved_bytes,
        } => ExecutorRefusal::WireBytesAboveCeiling {
            measured_bytes: *measured_bytes,
            max_wire_bytes_out: *reserved_bytes,
        },
        ProviderRefusal::Executor { refusal } => refusal.clone(),
        other => ExecutorRefusal::NotSent {
            detail: other.tag(),
        },
    }
}

impl VaultedProvider {
    fn scan(&self, scope: &VaultScope, bytes: &[u8]) -> Option<(LeakSource, ScanEncoding)> {
        self.vault
            .reflects_secret(scope, bytes)
            .map(|encoding| (LeakSource::VaultCredential, encoding))
            .or_else(|| self.known.find(bytes))
    }

    /// Builds and checks the request `outbound` stands for with `content`, scoped to
    /// `credential`, at `now`. The content is checked against the bound content keys
    /// first, whoever passed it.
    fn prepare(
        &self,
        outbound: &OutboundRequest,
        content: &RequestContent,
        credential: CredentialRef,
        now: MonotonicTime,
        check_wire: bool,
    ) -> Result<Prepared, ProviderRefusal> {
        content
            .check(outbound)
            .map_err(|refusal| ProviderRefusal::Executor { refusal })?;
        let upstream = build_upstream(&self.operation, &self.members, outbound, content.payload())
            .map_err(|refusal| ProviderRefusal::Build { refusal })?;
        let scope = VaultScope {
            credential,
            executor: self.executor.clone(),
            operation: outbound.operation.clone(),
            route: outbound.route,
            account: outbound.resource.account,
        };
        let facts = self
            .vault
            .facts(&scope, now)
            .map_err(|refusal| ProviderRefusal::Vault { refusal })?;
        for (location, bytes) in upstream.scan_parts() {
            if let Some((source, encoding)) = self.scan(&scope, &bytes) {
                return Err(ProviderRefusal::RequestCarriesSecret {
                    finding: LeakFinding {
                        location,
                        source,
                        encoding,
                    },
                });
            }
        }
        let measured_bytes = upstream
            .wire_bytes()
            .saturating_add(facts.authorization_header_bytes)
            .saturating_add(AUTHORIZATION_LINE_BYTES);
        let reserved_bytes = outbound.wire.total_bytes();
        if check_wire && measured_bytes > reserved_bytes {
            return Err(ProviderRefusal::WireAboveReservation {
                measured_bytes,
                reserved_bytes,
            });
        }
        Ok(Prepared {
            upstream,
            scope,
            measured_bytes,
            class: facts.class,
        })
    }

    fn refuse(&mut self, refusal: ProviderRefusal) -> ProviderReply {
        let carried = executor_refusal(&refusal);
        self.trace = Some(Trace {
            left: false,
            sent_bytes: None,
            outcome: TraceOutcome::Other(ExecutionOutcome::Refused { refusal }),
            reported_spend_microunits: None,
        });
        ProviderReply::Refused { refusal: carried }
    }
}

impl ProviderPort for VaultedProvider {
    fn submit(
        &mut self,
        request: &OutboundRequest,
        content: &RequestContent,
        credential: CredentialRef,
        now: MonotonicTime,
    ) -> ProviderReply {
        let prepared = match self.prepare(request, content, credential, now, true) {
            Ok(prepared) => prepared,
            Err(refusal) => return self.refuse(refusal),
        };
        let sent = match self.vault.send(
            &prepared.scope,
            &prepared.upstream,
            self.transport.as_mut(),
            now,
        ) {
            Ok(sent) => sent,
            Err(refusal) => return self.refuse(ProviderRefusal::Vault { refusal }),
        };
        let sent_bytes = Some(prepared.measured_bytes);
        let reply = match sent {
            TransportResult::NotSent => {
                self.trace = Some(Trace {
                    left: false,
                    sent_bytes: None,
                    outcome: TraceOutcome::Other(ExecutionOutcome::NotSent),
                    reported_spend_microunits: None,
                });
                return ProviderReply::Refused {
                    refusal: ExecutorRefusal::NotSent {
                        detail: "transport_not_sent".to_owned(),
                    },
                };
            }
            TransportResult::Lost => {
                self.trace = Some(Trace {
                    left: true,
                    sent_bytes,
                    outcome: TraceOutcome::Other(ExecutionOutcome::Unknown {
                        reason: UnknownReason::ResponseLost,
                    }),
                    reported_spend_microunits: None,
                });
                return ProviderReply::NoResponse;
            }
            TransportResult::Reply(reply) => reply,
        };
        let scope = prepared.scope;
        let verdict = evaluate_response(self.operation.response(), &reply, &|bytes| {
            self.scan(&scope, bytes)
        });
        let (outcome, reported, provider_reply) = match verdict {
            ResponseVerdict::Accepted {
                representation,
                reported_spend_microunits,
            } => (
                TraceOutcome::Committed,
                reported_spend_microunits,
                ProviderReply::Committed {
                    response: representation,
                    spend_microunits: reported_spend_microunits
                        .unwrap_or(self.cost.max_spend_microunits),
                    volume_units: self.cost.max_volume_units,
                },
            ),
            ResponseVerdict::Rejected {
                status,
                reported_spend_microunits,
            } => (
                TraceOutcome::Other(ExecutionOutcome::Rejected { status }),
                reported_spend_microunits,
                ProviderReply::Rejected {
                    code: format!("http_{status}"),
                },
            ),
            ResponseVerdict::PreconditionFailed => (
                TraceOutcome::Other(ExecutionOutcome::PreconditionFailed),
                None,
                ProviderReply::PreconditionFailed,
            ),
            ResponseVerdict::Redirect { target } => (
                TraceOutcome::Other(ExecutionOutcome::RedirectRefused { target }),
                None,
                ProviderReply::Redirect {
                    route: RouteRef::new(target),
                },
            ),
            ResponseVerdict::PartialSuccess {
                reported_spend_microunits,
            } => (
                TraceOutcome::Other(ExecutionOutcome::Unknown {
                    reason: UnknownReason::PartialSuccess,
                }),
                reported_spend_microunits,
                ProviderReply::PartialSuccess {
                    response: BTreeMap::new(),
                    spend_microunits: reported_spend_microunits
                        .unwrap_or(self.cost.max_spend_microunits),
                    volume_units: self.cost.max_volume_units,
                },
            ),
            ResponseVerdict::Uncertain { refusal } => (
                TraceOutcome::Other(ExecutionOutcome::Unknown {
                    reason: UnknownReason::ResponseRefused { refusal },
                }),
                None,
                ProviderReply::NoResponse,
            ),
        };
        self.trace = Some(Trace {
            left: true,
            sent_bytes,
            outcome,
            reported_spend_microunits: reported,
        });
        provider_reply
    }

    fn lookup(
        &mut self,
        request: &OutboundRequest,
        content: &RequestContent,
        credential: CredentialRef,
        now: MonotonicTime,
    ) -> ProviderLookup {
        let prepared = match self.prepare(request, content, credential, now, false) {
            Ok(prepared) => prepared,
            Err(_) => return ProviderLookup::Unknown,
        };
        let found = match self.vault.lookup(
            &prepared.scope,
            &prepared.upstream,
            self.transport.as_mut(),
            now,
        ) {
            Ok(found) => found,
            Err(_) => return ProviderLookup::Unknown,
        };
        let scope = prepared.scope;
        match found {
            LookupResult::NotCommitted => ProviderLookup::NotCommitted,
            LookupResult::Unknown => ProviderLookup::Unknown,
            LookupResult::Committed(reply) => {
                let verdict = evaluate_response(self.operation.response(), &reply, &|bytes| {
                    self.scan(&scope, bytes)
                });
                match verdict {
                    ResponseVerdict::Accepted {
                        representation,
                        reported_spend_microunits,
                    } => {
                        self.trace = Some(Trace {
                            left: true,
                            sent_bytes: None,
                            outcome: TraceOutcome::Committed,
                            reported_spend_microunits,
                        });
                        ProviderLookup::Committed {
                            response: representation,
                            spend_microunits: reported_spend_microunits
                                .unwrap_or(self.cost.max_spend_microunits),
                            volume_units: self.cost.max_volume_units,
                        }
                    }
                    _ => ProviderLookup::Unknown,
                }
            }
        }
    }
}

/// Everything a [`ProviderExecutor`] is built from.
pub struct ExecutorParts<S: PayloadStore> {
    pub identity: ExecutorIdentity,
    /// The issuer's capability key, which verifies seals.
    pub key: CapabilityKey,
    pub session: ClockSession,
    /// The sandbox profile; the strict profile refuses a passthrough operation.
    pub profile: ExposureProfile,
    /// The separate explicit authorization a passthrough operation needs, by digest.
    pub passthrough_authorization: Option<Digest>,
    pub vault: Box<dyn CredentialVault>,
    pub transport: Box<dyn UpstreamTransport>,
    pub payloads: S,
    pub records: Box<dyn EffectRecordsPort>,
    pub authority: Box<dyn AuthorityPort>,
    pub spend: SharedSpendLedger,
    pub known: KnownSecrets,
}

/// The executor of one provider operation (§4.5 line 2004; VM-W12).
pub struct ProviderExecutor<S: PayloadStore> {
    narrow: NarrowExecutor<VaultedProvider, S>,
    operation: ProviderOperation,
    members: BTreeMap<OperationKey, ProviderOperation>,
    session: ClockSession,
    records: Box<dyn EffectRecordsPort>,
    authority: Box<dyn AuthorityPort>,
    spend: SharedSpendLedger,
    claim: CredentialClaim,
    last: Option<ProviderExecution>,
}

fn outcome_for(refusal: &ProviderRefusal) -> ExecutorOutcome {
    ExecutorOutcome::Refused(executor_refusal(refusal))
}

impl<S: PayloadStore> ProviderExecutor<S> {
    /// An executor for `operation` from `catalog`. The strict profile refuses a
    /// credentialed passthrough, and the standard profile accepts one only with a
    /// separate explicit authorization.
    pub fn new(
        catalog: &OperationCatalog,
        operation: &OperationKey,
        parts: ExecutorParts<S>,
    ) -> Result<Self, OperationRefusal> {
        let provider_operation = catalog.get(operation)?.clone();
        let members = catalog.members_of(operation)?;
        let claim = provider_operation.claim();
        if !claim.allowed_in(parts.profile) {
            return Err(OperationRefusal::PassthroughRefusedInStrictProfile);
        }
        if claim == CredentialClaim::WeakerPassthrough && parts.passthrough_authorization.is_none()
        {
            return Err(OperationRefusal::PassthroughNeedsSeparateAuthorization);
        }
        let provider = VaultedProvider {
            operation: provider_operation.clone(),
            members: members.clone(),
            executor: parts.identity.name.clone(),
            vault: parts.vault,
            transport: parts.transport,
            known: parts.known,
            cost: CostCeiling::default(),
            trace: None,
        };
        let narrow = NarrowExecutor::new(
            parts.identity,
            provider_operation.contract().clone(),
            parts.key,
            parts.session,
            provider,
            parts.payloads,
        );
        Ok(Self {
            narrow,
            operation: provider_operation,
            members,
            session: parts.session,
            records: parts.records,
            authority: parts.authority,
            spend: parts.spend,
            claim,
            last: None,
        })
    }

    /// The one operation this executor runs.
    pub fn operation(&self) -> &ProviderOperation {
        &self.operation
    }

    /// What the executor's credential handling supports claiming.
    pub const fn claim(&self) -> CredentialClaim {
        self.claim
    }

    /// The record of the most recent execution.
    pub fn last_execution(&self) -> Option<&ProviderExecution> {
        self.last.as_ref()
    }

    /// The upstream request a description stands for, as this executor would build it at
    /// `now`. It never carries the credential.
    pub fn upstream_request(
        &self,
        description: &EffectDescription,
        credential: CredentialRef,
        now: MonotonicTime,
    ) -> Result<UpstreamRequest, ProviderRefusal> {
        let outbound = self.narrow.reconstruct(description);
        let content = self
            .narrow
            .verified_content(description)
            .map_err(|refusal| ProviderRefusal::Executor { refusal })?;
        self.narrow
            .provider()
            .prepare(&outbound, &content, credential, now, false)
            .map(|prepared| prepared.upstream)
    }

    fn current_generations(
        &self,
        description: &EffectDescription,
        now: MonotonicTime,
    ) -> Result<SandboxGenerations, ProviderRefusal> {
        match self.authority.standing(&description.sandbox().execution) {
            SandboxStanding::Authorized {
                generations,
                clock,
                authority_expires_at,
            } if clock == self.session && now < authority_expires_at => Ok(generations),
            _ => Err(ProviderRefusal::NoAuthority),
        }
    }

    /// The independent checks before anything is sent; returns the conservative cost.
    fn precheck(
        &mut self,
        operation: &TypedOperation<'_>,
        now: MonotonicTime,
    ) -> Result<CostCeiling, ProviderRefusal> {
        let description = operation.description;
        let presented = operation.capability;
        let capability = presented.capability();
        if description.operation() != self.operation.key() {
            return Err(ProviderRefusal::OperationMismatch);
        }
        // Checked again by the narrow executor after the seal; checked here so that a
        // presentation that cannot succeed consumes nothing.
        if &capability.executor != EffectExecutor::identity(&self.narrow) {
            return Err(ProviderRefusal::Executor {
                refusal: ExecutorRefusal::Capability {
                    refusal: CapabilityRefusal::WrongExecutor,
                },
            });
        }
        capability
            .check_time(now, self.session)
            .map_err(|refusal| ProviderRefusal::Executor {
                refusal: ExecutorRefusal::Capability { refusal },
            })?;
        let effect = description.id();
        let record = self
            .records
            .record(&effect)
            .ok_or(ProviderRefusal::NoRecord)?;
        if record.id() != effect || record.state().capability() != Some(presented) {
            return Err(ProviderRefusal::RecordMismatch);
        }
        if !matches!(
            record.phase(),
            EffectPhase::Reserved | EffectPhase::Dispatched
        ) {
            return Err(ProviderRefusal::WrongPhase {
                phase: record.phase(),
            });
        }
        let current = self.current_generations(description, now)?;
        if capability.generations != current {
            return Err(ProviderRefusal::GenerationChanged {
                bound: capability.generations,
                current,
            });
        }
        let lease = self
            .authority
            .lease(capability.lease)
            .map_err(|refusal| ProviderRefusal::LeaseRefused { refusal })?;
        let lease_refusal =
            if lease.parent != description.sandbox().execution || lease.generations != current {
                Some(LeaseRefusal::UnknownLease {
                    lease: capability.lease,
                })
            } else if lease.clock != self.session {
                Some(LeaseRefusal::OtherClock)
            } else if now >= lease.expires_at {
                Some(LeaseRefusal::Expired {
                    expired_at: lease.expires_at,
                })
            } else {
                None
            };
        if let Some(refusal) = lease_refusal {
            return Err(ProviderRefusal::LeaseRefused { refusal });
        }
        self.records
            .check_basis(
                &capability.basis,
                description,
                &capability.executor,
                current.policy,
                now,
                self.session,
            )
            .map_err(|violation| ProviderRefusal::Delegation { violation })?;
        let hold = self
            .records
            .hold(&effect)
            .ok_or(ProviderRefusal::NoBudgetHold)?;
        let described = description.max_cost().max_spend_microunits;
        if hold.spend_microunits < described {
            return Err(ProviderRefusal::BudgetHoldBelowCost {
                held_microunits: hold.spend_microunits,
                required_microunits: described,
            });
        }
        let class = operation.credential.class();
        if !self.operation.credentials().contains(&class) {
            return Err(ProviderRefusal::CredentialClassUnsupported { class });
        }
        let route_credential = self
            .operation
            .binding()
            .operation_route()
            .and_then(|route| route.credential());
        if route_credential != Some(operation.credential.reference()) {
            return Err(ProviderRefusal::CredentialNotRouteCredential);
        }
        operation
            .credential
            .usable_for(description.destination().route, now, self.session)
            .map_err(|refusal| ProviderRefusal::Executor {
                refusal: ExecutorRefusal::Credential { refusal },
            })?;
        let outbound = self.narrow.reconstruct(description);
        let estimated_bytes = outbound.wire.total_bytes();
        if estimated_bytes > description.max_wire_bytes_out() {
            return Err(ProviderRefusal::Executor {
                refusal: ExecutorRefusal::WireBytesAboveCeiling {
                    measured_bytes: estimated_bytes,
                    max_wire_bytes_out: description.max_wire_bytes_out(),
                },
            });
        }
        let content = self
            .narrow
            .verified_content(description)
            .map_err(|refusal| ProviderRefusal::Executor { refusal })?;
        let cost = check_request_with(
            &self.operation,
            &self.members,
            description,
            content.payload(),
        )
        .map_err(|refusal| ProviderRefusal::Request { refusal })?;
        let prepared = self.narrow.provider().prepare(
            &outbound,
            &content,
            operation.credential.reference(),
            now,
            true,
        )?;
        if prepared.class != class {
            return Err(ProviderRefusal::CredentialClassUnsupported {
                class: prepared.class,
            });
        }
        Ok(cost)
    }

    fn record(&mut self, execution: ProviderExecution) {
        self.last = Some(execution);
    }

    /// Verifies and executes one typed operation at `now`.
    pub fn execute_typed(
        &mut self,
        operation: TypedOperation<'_>,
        now: MonotonicTime,
    ) -> ExecutorReport {
        let description = operation.description;
        let effect = description.id();
        let execution = |outcome, sent_bytes, spend| ProviderExecution {
            effect,
            operation: description.operation().clone(),
            attempt: operation.capability.capability().attempt,
            outcome,
            sent_bytes,
            spend,
        };
        let refused = |refusal: ProviderRefusal| {
            let report = ExecutorReport {
                outcome: outcome_for(&refusal),
                sent: None,
            };
            (
                report,
                execution(ExecutionOutcome::Refused { refusal }, None, None),
            )
        };
        let cost = match self.precheck(&operation, now) {
            Ok(cost) => cost,
            Err(refusal) => {
                let (report, record) = refused(refusal);
                self.record(record);
                return report;
            }
        };
        if let Err(refusal) = self
            .spend
            .with(|ledger| ledger.consume(&effect, cost.max_spend_microunits))
        {
            let (report, record) = refused(ProviderRefusal::Spend { refusal });
            self.record(record);
            return report;
        }
        {
            let provider = self.narrow.provider_mut();
            provider.cost = cost;
            provider.trace = None;
        }
        let report = self.narrow.execute(operation, now);
        let trace = self.narrow.provider_mut().trace.take();
        if let ExecutorOutcome::Refused(refusal) = &report.outcome {
            // Nothing left: the narrow executor or this port refused, or the transport
            // could not send. The reservation consumed above is returned.
            let _ = self.spend.with(|ledger| ledger.release(&effect));
            let outcome = match trace {
                Some(Trace {
                    outcome: TraceOutcome::Other(outcome),
                    ..
                }) => outcome,
                _ => ExecutionOutcome::Refused {
                    refusal: ProviderRefusal::Executor {
                        refusal: refusal.clone(),
                    },
                },
            };
            self.record(execution(outcome, None, None));
            return ExecutorReport {
                outcome: report.outcome,
                sent: None,
            };
        }
        let Some(trace) = trace else {
            // The narrow executor sent without the port recording it: count it unknown.
            let spend = self
                .spend
                .with(|ledger| ledger.settle(&effect, SpendStatus::Unknown, None))
                .ok();
            self.record(execution(
                ExecutionOutcome::Unknown {
                    reason: UnknownReason::ResponseLost,
                },
                None,
                spend,
            ));
            return report;
        };
        let spend = if !trace.left {
            let _ = self.spend.with(|ledger| ledger.release(&effect));
            None
        } else {
            let status = match &report.outcome {
                ExecutorOutcome::Committed { .. } => SpendStatus::Committed,
                ExecutorOutcome::Rejected { .. } | ExecutorOutcome::RedirectRefused { .. } => {
                    SpendStatus::NotCommitted
                }
                _ => SpendStatus::Unknown,
            };
            let reported = match status {
                SpendStatus::Unknown => None,
                _ => trace.reported_spend_microunits,
            };
            self.spend
                .with(|ledger| ledger.settle(&effect, status, reported))
                .ok()
        };
        let outcome = match (&report.outcome, trace.outcome) {
            (ExecutorOutcome::Committed { result, .. }, TraceOutcome::Committed) => {
                ExecutionOutcome::Committed {
                    representation: result.result,
                    reported_spend_microunits: trace.reported_spend_microunits,
                }
            }
            (_, TraceOutcome::Other(outcome)) => outcome,
            (_, TraceOutcome::Committed) => ExecutionOutcome::Unknown {
                reason: UnknownReason::ResponseLost,
            },
        };
        self.record(execution(outcome, trace.sent_bytes, spend));
        ExecutorReport {
            outcome: report.outcome,
            sent: if trace.left { report.sent } else { None },
        }
    }
}

impl<S: PayloadStore> EffectExecutor for ProviderExecutor<S> {
    fn identity(&self) -> &ExecutorIdentity {
        EffectExecutor::identity(&self.narrow)
    }

    fn execute(&mut self, operation: TypedOperation<'_>, now: MonotonicTime) -> ExecutorReport {
        self.execute_typed(operation, now)
    }

    /// Asks the provider, through the vault, whether `description` committed at `now`,
    /// the controller's clock reading, and reconciles an unknown spend reservation with
    /// the answer. Every expiry (credential, vault grant) is decided against `now`.
    fn lookup(
        &mut self,
        description: &EffectDescription,
        credential: CredentialHandle,
        now: MonotonicTime,
    ) -> Observation {
        let effect = description.id();
        let content = self.narrow.verified_content(description).ok();
        let cost = check_request_with(
            &self.operation,
            &self.members,
            description,
            content.as_ref().and_then(RequestContent::payload),
        )
        .unwrap_or_else(|_| description.max_cost());
        {
            let provider = self.narrow.provider_mut();
            provider.cost = cost;
            provider.trace = None;
        }
        let observation = EffectExecutor::lookup(&mut self.narrow, description, credential, now);
        let reported = self
            .narrow
            .provider_mut()
            .trace
            .take()
            .and_then(|trace| trace.reported_spend_microunits);
        let status = match observation {
            Observation::Committed { .. } => Some(SpendStatus::Committed),
            Observation::NotCommitted => Some(SpendStatus::NotCommitted),
            Observation::StillUnknown => None,
        };
        if let Some(status) = status {
            let _ = self
                .spend
                .with(|ledger| ledger.reconcile(&effect, status, reported));
        }
        observation
    }
}

#[cfg(test)]
mod tests {
    use super::super::fakes::*;
    use super::*;
    use crate::foundation::ids::{Clock, ContentKey};

    /// The port checks the bytes it is given against the content key the description
    /// binds; mismatched bytes are refused as the executor's refusal, before sending.
    #[test]
    fn a_payload_that_does_not_match_its_bound_digest_is_refused_by_the_port() {
        let mut world = World::new();
        let payload = b"model weights v1".to_vec();
        let description = world.describe(
            "upload_object",
            crate::sandbox_contract::effects::Parameters::new()
                .with(param("name"), text_value("weights.bin")),
            Some(&payload),
        );
        let mut executor = world.executor("upload_object");
        let outbound = executor.narrow.reconstruct(&description);
        let good = executor.narrow.verified_content(&description).unwrap();
        assert_eq!(good.payload(), Some(payload.as_slice()));
        let swapped = RequestContent {
            payload: Some(b"model weights v2".to_vec()),
            attachments: BTreeMap::new(),
        };
        let now = world.clock.now();
        let reply =
            executor
                .narrow
                .provider_mut()
                .submit(&outbound, &swapped, credential_ref(), now);
        assert_eq!(
            reply,
            ProviderReply::Refused {
                refusal: ExecutorRefusal::PayloadMismatch {
                    mismatch: crate::sandbox_contract::effects::PayloadMismatch {
                        expected: ContentKey::of(&payload),
                        actual: ContentKey::of(b"model weights v2"),
                    }
                }
            }
        );
        assert_eq!(
            executor
                .narrow
                .provider_mut()
                .lookup(&outbound, &swapped, credential_ref(), now),
            ProviderLookup::Unknown
        );
        let missing = executor.narrow.provider_mut().submit(
            &outbound,
            &RequestContent::default(),
            credential_ref(),
            now,
        );
        assert!(matches!(
            missing,
            ProviderReply::Refused {
                refusal: ExecutorRefusal::PayloadMissing { .. }
            }
        ));
        assert!(world.transport.sent().is_empty());
        assert_eq!(world.vault.sends(), 0);
        // The matching bytes go through, exactly as bound.
        world
            .transport
            .set(ReplyMode::Fixed(reply_with_etag(&payload)));
        let reply = executor
            .narrow
            .provider_mut()
            .submit(&outbound, &good, credential_ref(), now);
        assert!(matches!(reply, ProviderReply::Committed { .. }));
        assert_eq!(world.transport.sent()[0].0.body, payload);
    }

    fn reply_with_etag(payload: &[u8]) -> crate::sandbox_contract::provider::UpstreamReply {
        reply(
            200,
            &[],
            &format!(
                r#"{{"etag":"{}"}}"#,
                ContentKey::of(payload).digest().to_hex()
            ),
        )
    }
}
