//! Provider operation families as typed contracts (VM part §4.6 line 2024; §9.2 lines
//! 2344 and 2361; VM-W12).
//!
//! An HTTP verb is not intent: a POST may only read (inference, search), a GET may change
//! state, and GraphQL or batch endpoints carry many operations. A [`ProviderOperation`]
//! therefore declares its intent explicitly and binds it to the V02 operation route's
//! effect class; it has an effects [`OperationContract`] for its request schema, one V02
//! route, a body encoding, a cost model and a response policy. A GraphQL operation is one
//! registered document holding exactly one named operation; a batch lists every member's
//! typed contract. Nothing else is accepted.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::batch::{BatchDocument, BatchRefusal};
use super::graphql::{single_named_operation, GraphQlParsedKind, GraphQlRefusal};
use super::response::{ResponsePolicy, ResponseProfile, PASSTHROUGH_BODY_FIELD};
use crate::foundation::ids::{digest, Digest};
use crate::sandbox_contract::destinations::{
    route_reference, Authority, DestinationHost, EffectClass, HttpMethod,
    OperationName as RouteOperationName, OperationRoute, OperationSpec, OperationTls, PathSegment,
    RedirectPolicy, RouteKind,
};
use crate::sandbox_contract::effects::{
    ContractRefusal, ContractRegistry, CostCeiling, EffectDescription, ExposureProfile,
    OperationContract, OperationKey, ParamKind, ParamName, Parameters, PayloadRule, RawParameters,
    RouteRef, ScalarKind, SecretClass,
};

/// The digest domain of a provider route reference.
pub const PROVIDER_ROUTE_DOMAIN: &str = "yougori/sandbox/provider-route/v1";

const GRAPHQL_DOCUMENT_DOMAIN: &str = "yougori/sandbox/graphql-document/v1";

/// Whether an operation changes provider-side state. Declared, never derived from the
/// HTTP method (§4.6 line 2024).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationIntent {
    /// Reads only; it may still cost money, as inference does.
    ReadOnly,
    SideEffecting,
}

impl OperationIntent {
    /// The V02 effect class the bound route must declare for the operation.
    pub const fn effect_class(self) -> EffectClass {
        match self {
            Self::ReadOnly => EffectClass::ReadOnly,
            Self::SideEffecting => EffectClass::External,
        }
    }

    /// Whether the operation changes provider-side state.
    pub const fn changes_provider_state(self) -> bool {
        matches!(self, Self::SideEffecting)
    }
}

/// The kind of a registered GraphQL operation; subscriptions are not bounded operations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GraphQlKind {
    Query,
    Mutation,
}

impl GraphQlKind {
    const fn parsed(self) -> GraphQlParsedKind {
        match self {
            Self::Query => GraphQlParsedKind::Query,
            Self::Mutation => GraphQlParsedKind::Mutation,
        }
    }

    /// A query reads; a mutation changes state.
    pub const fn intent(self) -> OperationIntent {
        match self {
            Self::Query => OperationIntent::ReadOnly,
            Self::Mutation => OperationIntent::SideEffecting,
        }
    }
}

/// One registered GraphQL document with exactly one named operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GraphQlOperation {
    name: String,
    kind: GraphQlKind,
    document: String,
    digest: Digest,
}

fn document_digest(document: &str) -> Digest {
    digest(GRAPHQL_DOCUMENT_DOMAIN, &[document.as_bytes()])
}

impl GraphQlOperation {
    /// Registers `document`; it must hold exactly one operation, named `name`, of `kind`.
    pub fn new(document: &str, name: &str, kind: GraphQlKind) -> Result<Self, GraphQlRefusal> {
        let (parsed_kind, parsed_name) = single_named_operation(document)?;
        if parsed_kind != kind.parsed() || parsed_name != name {
            return Err(GraphQlRefusal::OperationMismatch);
        }
        Ok(Self {
            name: name.to_owned(),
            kind,
            document: document.to_owned(),
            digest: document_digest(document),
        })
    }

    /// Checks a document a guest or tool presents: exactly one named operation, the
    /// registered one, byte for byte. A differently formatted document is refused rather
    /// than normalized.
    pub fn check_document(
        &self,
        document: &str,
        operation_name: Option<&str>,
    ) -> Result<(), GraphQlRefusal> {
        let (kind, name) = single_named_operation(document)?;
        if kind != self.kind.parsed() || name != self.name {
            return Err(GraphQlRefusal::OperationMismatch);
        }
        if operation_name.is_some_and(|requested| requested != self.name) {
            return Err(GraphQlRefusal::OperationMismatch);
        }
        if document_digest(document) != self.digest {
            return Err(GraphQlRefusal::DocumentMismatch);
        }
        Ok(())
    }

    /// The registered operation name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Query or mutation.
    pub const fn kind(&self) -> GraphQlKind {
        self.kind
    }

    /// The registered document, sent as is.
    pub fn document(&self) -> &str {
        &self.document
    }

    /// The registered document's digest.
    pub const fn digest(&self) -> &Digest {
        &self.digest
    }
}

/// The members a batch operation may carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchSpec {
    pub members: BTreeSet<OperationKey>,
    pub max_members: u32,
}

/// An operation family (§4.6 line 2024).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationFamily {
    Inference,
    RepositoryWrite,
    ObjectUpload,
    ObjectRead,
    GraphQl(GraphQlOperation),
    Batch(BatchSpec),
    /// A generic credentialed passthrough: a separate, weaker profile (§4.5 line 2008).
    CredentialedPassthrough,
}

impl OperationFamily {
    /// Whether this is the weaker credentialed passthrough.
    pub const fn is_passthrough(&self) -> bool {
        matches!(self, Self::CredentialedPassthrough)
    }

    /// A stable short name of the family.
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::Inference => "inference",
            Self::RepositoryWrite => "repository_write",
            Self::ObjectUpload => "object_upload",
            Self::ObjectRead => "object_read",
            Self::GraphQl(_) => "graphql",
            Self::Batch(_) => "batch",
            Self::CredentialedPassthrough => "credentialed_passthrough",
        }
    }
}

/// How the executor encodes the request body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BodyEncoding {
    /// No body; parameters other than path parameters go in the query string.
    Query,
    /// Parameters other than path parameters as one JSON object.
    JsonParameters,
    /// The payload bytes; other parameters go in the query string.
    RawPayload,
    /// `{"operationName", "query", "variables"}` with the registered document.
    GraphQlEnvelope,
    /// The canonical batch document, which is the payload.
    BatchDocument,
}

/// The one V02 operation route an operation is bound to (VM-W12: destination binding).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DestinationBinding {
    pub authority: Authority,
    /// Must be a V02 operation route: a transport route cannot inspect or bind an
    /// operation.
    pub route: RouteKind,
    /// The route's operation this contract uses.
    pub spec: RouteOperationName,
    /// The parameters that fill the path template's `{}` segments, in order.
    pub path_params: Vec<ParamName>,
}

impl DestinationBinding {
    /// The effects route reference of the route registered for `authority`: a digest of
    /// the shared V02 route reference (canonical `host:port`), so provider routes name a
    /// destination the same way as V01 route resources and V08 declarations.
    pub fn route_ref_for(authority: &Authority) -> RouteRef {
        RouteRef::new(digest(
            PROVIDER_ROUTE_DOMAIN,
            &[route_reference(authority).as_bytes()],
        ))
    }

    /// The effects route reference of the bound route.
    pub fn route_ref(&self) -> RouteRef {
        Self::route_ref_for(&self.authority)
    }

    /// The V02 operation route, or `None` for a transport route.
    pub fn operation_route(&self) -> Option<&OperationRoute> {
        match &self.route {
            RouteKind::Operation(route) => Some(route),
            RouteKind::Transport(_) => None,
        }
    }

    /// The route's operation this binding names.
    pub fn spec(&self) -> Option<&OperationSpec> {
        self.operation_route()?
            .operations()
            .iter()
            .find(|spec| spec.name == self.spec)
    }

    /// Bytes of the host as it leaves in DNS and the TLS server name.
    pub fn host_wire_bytes(&self) -> u64 {
        match &self.authority.host {
            DestinationHost::Name(name) => name.wire_length_bytes(),
            DestinationHost::Address(address) => {
                u64::try_from(address.to_string().len()).unwrap_or(u64::MAX)
            }
        }
    }
}

/// A bounded integer parameter that caps metered usage, such as `max_output_tokens`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MeteredParam {
    pub param: ParamName,
    pub microunits_per_unit: u64,
}

/// The most an operation can cost (§2.5 line 1815: an explicit conservative reservation
/// where actual final cost is not known in advance):
///
/// ```text
/// max_spend = fixed + per_request_byte × request_bytes + per_unit × units
/// max_volume = units if metered, else 1 call
/// ```
///
/// `request_bytes` is the canonical parameter encoding plus payload and attachment bytes;
/// `units` is the metered parameter's value, or its declared maximum when absent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CostModel {
    pub fixed_microunits: u64,
    pub microunits_per_request_byte: u64,
    pub metered: Option<MeteredParam>,
}

strict_provider_enum! {
    /// Why a cost bound could not be computed.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum CostRefusal tag "refusal" {
        MeteredParamUndeclared { name: ParamName },
        /// The metered parameter is not a non-negative bounded integer, so no maximum
        /// exists.
        MeteredParamUnbounded { name: ParamName },
        NegativeUnits { name: ParamName },
        Overflow,
    }
}

impl fmt::Display for CostRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MeteredParamUndeclared { name } => {
                write!(f, "the metered parameter {name} is not in the contract")
            }
            Self::MeteredParamUnbounded { name } => write!(
                f,
                "{name} is not a bounded non-negative integer; an unbounded cost cannot be \
                 reserved"
            ),
            Self::NegativeUnits { name } => write!(f, "{name} is negative"),
            Self::Overflow => f.write_str("the cost bound overflows"),
        }
    }
}

impl std::error::Error for CostRefusal {}

impl CostModel {
    /// A model that costs nothing per call.
    pub const fn free() -> Self {
        Self {
            fixed_microunits: 0,
            microunits_per_request_byte: 0,
            metered: None,
        }
    }

    fn metered_bound(&self, contract: &OperationContract) -> Result<Option<u64>, CostRefusal> {
        let Some(metered) = &self.metered else {
            return Ok(None);
        };
        let spec = contract.parameters.get(&metered.param).ok_or_else(|| {
            CostRefusal::MeteredParamUndeclared {
                name: metered.param.clone(),
            }
        })?;
        match spec.kind {
            ParamKind::Scalar {
                kind: ScalarKind::Integer { min, max },
            } if min >= 0 && max >= min => {
                u64::try_from(max)
                    .map(Some)
                    .map_err(|_| CostRefusal::MeteredParamUnbounded {
                        name: metered.param.clone(),
                    })
            }
            _ => Err(CostRefusal::MeteredParamUnbounded {
                name: metered.param.clone(),
            }),
        }
    }

    /// The maximum cost of one call with `parameters` and `request_bytes`.
    pub fn max_cost(
        &self,
        contract: &OperationContract,
        parameters: &Parameters,
        request_bytes: u64,
    ) -> Result<CostCeiling, CostRefusal> {
        let declared_max = self.metered_bound(contract)?;
        let units = match (&self.metered, declared_max) {
            (Some(metered), Some(declared_max)) => match parameters.get(&metered.param) {
                Some(crate::sandbox_contract::effects::CanonicalValue::Integer(value)) => {
                    let value = u64::try_from(*value).map_err(|_| CostRefusal::NegativeUnits {
                        name: metered.param.clone(),
                    })?;
                    Some(value.min(declared_max))
                }
                Some(_) => {
                    return Err(CostRefusal::MeteredParamUnbounded {
                        name: metered.param.clone(),
                    })
                }
                None => Some(declared_max),
            },
            _ => None,
        };
        let per_unit = self
            .metered
            .as_ref()
            .map_or(0, |metered| metered.microunits_per_unit);
        let spend = self
            .microunits_per_request_byte
            .checked_mul(request_bytes)
            .and_then(|bytes| bytes.checked_add(self.fixed_microunits))
            .and_then(|sum| sum.checked_add(per_unit.checked_mul(units.unwrap_or(0))?))
            .ok_or(CostRefusal::Overflow)?;
        Ok(CostCeiling {
            max_spend_microunits: spend,
            max_volume_units: units.unwrap_or(1),
        })
    }
}

strict_provider_enum! {
    /// What an operation's credential handling lets the host claim (§4.5 lines
    /// 2006–2008).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum CredentialClaim tag "claim" {
        /// The contract never hands the credential to the guest, and responses that
        /// reflect it in a scanned encoding are refused. Nothing more: copies in TLS
        /// libraries, the OS, crash dumps or swap are outside it (§4.5 line 2006), the
        /// scan's coverage is limited, and Tier 0 fakes prove only the contract.
        NotDeliveredToGuest,
        /// The credential stays host-side, but the guest shapes requests and receives
        /// provider content without a schema. Never zero-exposure (§4.5 line 2008).
        WeakerPassthrough,
        /// The credential is inside the guest under a separate explicit authorization.
        GuestHeld { authorization: Digest },
    }
}

strict_provider_enum! {
    /// Why a claim cannot be made.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ClaimRefusal tag "refusal" {
        PassthroughIsNeverZeroExposure,
        GuestHoldsCredential,
    }
}

impl fmt::Display for ClaimRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PassthroughIsNeverZeroExposure => f.write_str(
                "a credentialed passthrough has a weaker claim and is never zero-exposure",
            ),
            Self::GuestHoldsCredential => f.write_str("the guest holds the credential"),
        }
    }
}

impl std::error::Error for ClaimRefusal {}

impl CredentialClaim {
    /// The zero-exposure label, with its limits, for the one claim that supports it.
    pub fn zero_exposure_label(&self) -> Result<&'static str, ClaimRefusal> {
        match self {
            Self::NotDeliveredToGuest => Ok(
                "zero-exposure mode: the contract does not deliver the credential to the \
                 guest; limited scan coverage; not a statement about TLS, OS or crash-dump \
                 copies",
            ),
            Self::WeakerPassthrough => Err(ClaimRefusal::PassthroughIsNeverZeroExposure),
            Self::GuestHeld { .. } => Err(ClaimRefusal::GuestHoldsCredential),
        }
    }

    /// Whether the claim is acceptable in `profile`; the strict profile keeps external
    /// credentials out of the guest and accepts only the typed claim.
    pub const fn allowed_in(&self, profile: ExposureProfile) -> bool {
        match profile {
            ExposureProfile::Strict => matches!(self, Self::NotDeliveredToGuest),
            ExposureProfile::Standard => true,
        }
    }
}

strict_provider_enum! {
    /// Why an operation, a catalog entry or a request was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum OperationRefusal tag "reason" {
        TransportRouteCannotBind,
        SpecNotOnRoute { spec: RouteOperationName },
        /// The route's effect class disagrees with the declared intent.
        IntentDisagreesWithRoute { intent: OperationIntent },
        RedirectsMustBeDisabled,
        TlsModeMismatch,
        RouteNotCredentialed,
        /// The contract must name exactly the bound route.
        ContractRouteMismatch,
        NameBytesUndercounted { declared_bytes: u32, required_bytes: u64 },
        PathParameterMismatch,
        PathParameterNotRequiredText { name: ParamName },
        EncodingMismatch { encoding: BodyEncoding },
        QueryKeyNotOnRoute { name: ParamName },
        FamilyMismatch,
        AttachmentsUnsupported,
        ResponseFieldsMismatch,
        ProfileMismatch,
        NoCredentialClasses,
        CredentialClassNotExternal { class: SecretClass },
        Cost { refusal: CostRefusal },
        GraphQl { refusal: GraphQlRefusal },
        BatchSpecInvalid,
        BatchMemberUnknown { member: OperationKey },
        /// A batch member must itself be a typed single operation.
        BatchMemberNotTyped { member: OperationKey },
        BatchMemberOtherProvider { member: OperationKey },
        /// A batch with a side-effecting member must be declared side-effecting.
        BatchIntentTooWeak,
        Batch { refusal: BatchRefusal },
        DuplicateOperation { operation: OperationKey },
        UnknownOperation { operation: OperationKey },
        Contract { refusal: ContractRefusal },
        /// The cost model's maximum is above the description's approved maximum.
        CostAboveDescription { model: CostCeiling, described: CostCeiling },
        PayloadMissing,
        /// A passthrough operation is refused in the strict profile.
        PassthroughRefusedInStrictProfile,
        /// A passthrough operation needs a separate explicit authorization.
        PassthroughNeedsSeparateAuthorization,
    }
}

impl fmt::Display for OperationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TransportRouteCannotBind => {
                f.write_str("a transport route cannot inspect or bind a provider operation")
            }
            Self::SpecNotOnRoute { spec } => write!(f, "the route has no operation {spec}"),
            Self::IntentDisagreesWithRoute { intent } => {
                write!(
                    f,
                    "the route's effect class disagrees with intent {intent:?}"
                )
            }
            Self::RedirectsMustBeDisabled => {
                f.write_str("a provider operation never follows redirects")
            }
            Self::TlsModeMismatch => f.write_str(
                "typed operations need executor-constructed requests; only a passthrough \
                 terminates guest TLS",
            ),
            Self::RouteNotCredentialed => f.write_str("the route names no executor credential"),
            Self::ContractRouteMismatch => {
                f.write_str("the contract must name exactly the bound route")
            }
            Self::NameBytesUndercounted {
                declared_bytes,
                required_bytes,
            } => write!(
                f,
                "the route declares {declared_bytes} name bytes; its host takes {required_bytes}"
            ),
            Self::PathParameterMismatch => {
                f.write_str("the path parameters do not match the path template")
            }
            Self::PathParameterNotRequiredText { name } => {
                write!(f, "path parameter {name} must be a required text parameter")
            }
            Self::EncodingMismatch { encoding } => {
                write!(f, "body encoding {encoding:?} does not fit this operation")
            }
            Self::QueryKeyNotOnRoute { name } => {
                write!(f, "the route does not accept query key {name}")
            }
            Self::FamilyMismatch => f.write_str("the operation family does not fit its binding"),
            Self::AttachmentsUnsupported => {
                f.write_str("provider operations here carry no attachment slots")
            }
            Self::ResponseFieldsMismatch => {
                f.write_str("the response schema and the contract's response fields differ")
            }
            Self::ProfileMismatch => f.write_str(
                "a passthrough needs the passthrough response profile and a typed operation \
                 a typed one",
            ),
            Self::NoCredentialClasses => f.write_str("the operation accepts no credential class"),
            Self::CredentialClassNotExternal { class } => {
                write!(f, "a {class:?} cannot authorize a provider operation")
            }
            Self::Cost { refusal } => write!(f, "{refusal}"),
            Self::GraphQl { refusal } => write!(f, "{refusal}"),
            Self::BatchSpecInvalid => f.write_str("a batch needs members and a positive maximum"),
            Self::BatchMemberUnknown { .. } => f.write_str("a batch member has no typed contract"),
            Self::BatchMemberNotTyped { .. } => {
                f.write_str("a batch member must be a typed single operation")
            }
            Self::BatchMemberOtherProvider { .. } => {
                f.write_str("a batch member belongs to another provider")
            }
            Self::BatchIntentTooWeak => {
                f.write_str("a batch with a side-effecting member must be side-effecting")
            }
            Self::Batch { refusal } => write!(f, "{refusal}"),
            Self::DuplicateOperation { .. } => f.write_str("the operation is already registered"),
            Self::UnknownOperation { .. } => {
                f.write_str("no typed contract exists for the operation")
            }
            Self::Contract { refusal } => write!(f, "{refusal}"),
            Self::CostAboveDescription { model, described } => write!(
                f,
                "the cost model allows up to {} microunits and {} units; the description \
                 approves {} and {}",
                model.max_spend_microunits,
                model.max_volume_units,
                described.max_spend_microunits,
                described.max_volume_units
            ),
            Self::PayloadMissing => f.write_str("the payload bytes are not available"),
            Self::PassthroughRefusedInStrictProfile => {
                f.write_str("the strict profile refuses a credentialed passthrough")
            }
            Self::PassthroughNeedsSeparateAuthorization => {
                f.write_str("a credentialed passthrough needs a separate explicit authorization")
            }
        }
    }
}

impl std::error::Error for OperationRefusal {}

/// The parts of a provider operation, checked by [`ProviderOperation::new`].
#[derive(Clone, Debug)]
pub struct OperationDraft {
    pub contract: OperationContract,
    pub family: OperationFamily,
    pub intent: OperationIntent,
    pub binding: DestinationBinding,
    pub encoding: BodyEncoding,
    pub cost: CostModel,
    pub response: ResponsePolicy,
    /// The external credential classes the operation may be executed with.
    pub credentials: BTreeSet<SecretClass>,
}

/// One provider operation as a typed contract (§4.6 line 2024; VM-W12).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProviderOperation {
    contract: OperationContract,
    family: OperationFamily,
    intent: OperationIntent,
    binding: DestinationBinding,
    encoding: BodyEncoding,
    cost: CostModel,
    response: ResponsePolicy,
    credentials: BTreeSet<SecretClass>,
}

fn is_required_text(contract: &OperationContract, name: &ParamName) -> bool {
    matches!(
        contract.parameters.get(name),
        Some(spec) if spec.required
            && matches!(spec.kind, ParamKind::Scalar { kind: ScalarKind::Text { .. } })
    )
}

impl ProviderOperation {
    /// Checks every part against the others and against the V02 route.
    pub fn new(draft: OperationDraft) -> Result<Self, OperationRefusal> {
        let OperationDraft {
            contract,
            family,
            intent,
            binding,
            encoding,
            cost,
            response,
            credentials,
        } = draft;
        let route = binding
            .operation_route()
            .ok_or(OperationRefusal::TransportRouteCannotBind)?;
        let spec = binding
            .spec()
            .ok_or_else(|| OperationRefusal::SpecNotOnRoute {
                spec: binding.spec.clone(),
            })?;
        if spec.effect != intent.effect_class() {
            return Err(OperationRefusal::IntentDisagreesWithRoute { intent });
        }
        if route.redirects() != RedirectPolicy::Disabled {
            return Err(OperationRefusal::RedirectsMustBeDisabled);
        }
        let expected_tls = if family.is_passthrough() {
            OperationTls::TerminatedAtExecutor
        } else {
            OperationTls::ConstructedByExecutor
        };
        if route.tls() != expected_tls {
            return Err(OperationRefusal::TlsModeMismatch);
        }
        if !route.is_credentialed() {
            return Err(OperationRefusal::RouteNotCredentialed);
        }
        let route_ref = binding.route_ref();
        let mut routes = contract.routes.iter();
        let (Some((contract_route, route_spec)), None) = (routes.next(), routes.next()) else {
            return Err(OperationRefusal::ContractRouteMismatch);
        };
        if *contract_route != route_ref {
            return Err(OperationRefusal::ContractRouteMismatch);
        }
        let required_bytes = binding.host_wire_bytes();
        if u64::from(route_spec.name_bytes) < required_bytes {
            return Err(OperationRefusal::NameBytesUndercounted {
                declared_bytes: route_spec.name_bytes,
                required_bytes,
            });
        }
        let template_params = spec
            .path
            .segments()
            .iter()
            .filter(|segment| matches!(segment, PathSegment::Parameter))
            .count();
        if template_params != binding.path_params.len() {
            return Err(OperationRefusal::PathParameterMismatch);
        }
        let distinct: BTreeSet<&ParamName> = binding.path_params.iter().collect();
        if distinct.len() != binding.path_params.len() {
            return Err(OperationRefusal::PathParameterMismatch);
        }
        if let Some(name) = binding
            .path_params
            .iter()
            .find(|name| !is_required_text(&contract, name))
        {
            return Err(OperationRefusal::PathParameterNotRequiredText { name: name.clone() });
        }
        if !contract.attachments.is_empty() {
            return Err(OperationRefusal::AttachmentsUnsupported);
        }
        check_encoding(&contract, &family, intent, spec, &binding, encoding)?;
        if let OperationFamily::Batch(batch) = &family {
            if batch.members.is_empty() || batch.max_members == 0 {
                return Err(OperationRefusal::BatchSpecInvalid);
            }
        }
        match (&family, &response.profile) {
            (
                OperationFamily::CredentialedPassthrough,
                ResponseProfile::CredentialedPassthrough { .. },
            ) => {
                let expected = ParamName::new(PASSTHROUGH_BODY_FIELD)
                    .map_err(|_| OperationRefusal::ResponseFieldsMismatch)?;
                if contract.response_fields != BTreeSet::from([expected]) {
                    return Err(OperationRefusal::ResponseFieldsMismatch);
                }
            }
            (OperationFamily::CredentialedPassthrough, _)
            | (_, ResponseProfile::CredentialedPassthrough { .. }) => {
                return Err(OperationRefusal::ProfileMismatch)
            }
            (_, ResponseProfile::Typed { schema }) => {
                let fields: BTreeSet<ParamName> = schema.fields.keys().cloned().collect();
                if fields != contract.response_fields {
                    return Err(OperationRefusal::ResponseFieldsMismatch);
                }
            }
        }
        if credentials.is_empty() {
            return Err(OperationRefusal::NoCredentialClasses);
        }
        if let Some(class) = credentials
            .iter()
            .find(|class| !class.is_external_credential())
        {
            return Err(OperationRefusal::CredentialClassNotExternal { class: *class });
        }
        cost.metered_bound(&contract)
            .map_err(|refusal| OperationRefusal::Cost { refusal })?;
        Ok(Self {
            contract,
            family,
            intent,
            binding,
            encoding,
            cost,
            response,
            credentials,
        })
    }

    /// The operation's effects key.
    pub fn key(&self) -> &OperationKey {
        &self.contract.operation
    }

    /// The request schema and per-effect ceiling, as an effects contract.
    pub fn contract(&self) -> &OperationContract {
        &self.contract
    }

    /// The operation family.
    pub fn family(&self) -> &OperationFamily {
        &self.family
    }

    /// The declared intent.
    pub const fn intent(&self) -> OperationIntent {
        self.intent
    }

    /// The one V02 route the operation is bound to.
    pub fn binding(&self) -> &DestinationBinding {
        &self.binding
    }

    /// The HTTP method on the wire: a transport detail, never the intent. Always present
    /// for a constructed operation.
    pub fn method(&self) -> Option<HttpMethod> {
        self.binding.spec().map(|spec| spec.method)
    }

    /// How the executor encodes the body.
    pub const fn encoding(&self) -> BodyEncoding {
        self.encoding
    }

    /// The conservative cost model.
    pub fn cost(&self) -> &CostModel {
        &self.cost
    }

    /// The response policy.
    pub fn response(&self) -> &ResponsePolicy {
        &self.response
    }

    /// The credential classes the operation accepts.
    pub fn credentials(&self) -> &BTreeSet<SecretClass> {
        &self.credentials
    }

    /// The effects route reference of the bound route.
    pub fn route_ref(&self) -> RouteRef {
        self.binding.route_ref()
    }

    /// What the operation's credential handling supports claiming.
    pub const fn claim(&self) -> CredentialClaim {
        if self.family.is_passthrough() {
            CredentialClaim::WeakerPassthrough
        } else {
            CredentialClaim::NotDeliveredToGuest
        }
    }

    /// Normalizes raw parameters under the request schema.
    pub fn normalize_parameters(
        &self,
        raw: &RawParameters,
    ) -> Result<Parameters, OperationRefusal> {
        self.contract
            .normalize(raw)
            .map_err(|refusal| OperationRefusal::Contract { refusal })
    }

    /// Checks a GraphQL document presented for this operation.
    pub fn check_graphql_document(
        &self,
        document: &str,
        operation_name: Option<&str>,
    ) -> Result<(), OperationRefusal> {
        match &self.family {
            OperationFamily::GraphQl(graphql) => graphql
                .check_document(document, operation_name)
                .map_err(|refusal| OperationRefusal::GraphQl { refusal }),
            _ => Err(OperationRefusal::FamilyMismatch),
        }
    }

    /// The bytes the cost model counts for `parameters` and `content_bytes`.
    pub fn request_bytes(parameters: &Parameters, content_bytes: u64) -> u64 {
        let encoded = serde_json::to_vec(parameters).map_or(u64::MAX, |bytes| {
            u64::try_from(bytes.len()).unwrap_or(u64::MAX)
        });
        encoded.saturating_add(content_bytes)
    }
}

fn check_encoding(
    contract: &OperationContract,
    family: &OperationFamily,
    intent: OperationIntent,
    spec: &OperationSpec,
    binding: &DestinationBinding,
    encoding: BodyEncoding,
) -> Result<(), OperationRefusal> {
    let mismatch = || OperationRefusal::EncodingMismatch { encoding };
    if spec.method.forbids_body() && encoding != BodyEncoding::Query {
        return Err(mismatch());
    }
    let payload_ok = match encoding {
        BodyEncoding::Query | BodyEncoding::JsonParameters | BodyEncoding::GraphQlEnvelope => {
            contract.payload == PayloadRule::Forbidden
        }
        BodyEncoding::RawPayload | BodyEncoding::BatchDocument => {
            contract.payload == PayloadRule::Required
        }
    };
    if !payload_ok {
        return Err(mismatch());
    }
    let family_ok = match (family, encoding) {
        (OperationFamily::GraphQl(graphql), BodyEncoding::GraphQlEnvelope) => {
            spec.method == HttpMethod::Post && graphql.kind.intent() == intent
        }
        (OperationFamily::GraphQl(_), _) | (_, BodyEncoding::GraphQlEnvelope) => false,
        (OperationFamily::Batch(_), BodyEncoding::BatchDocument) => true,
        (OperationFamily::Batch(_), _) | (_, BodyEncoding::BatchDocument) => false,
        _ => true,
    };
    if !family_ok {
        return Err(OperationRefusal::FamilyMismatch);
    }
    if matches!(encoding, BodyEncoding::Query | BodyEncoding::RawPayload) {
        let path: BTreeSet<&ParamName> = binding.path_params.iter().collect();
        if let Some(name) = contract
            .parameters
            .keys()
            .filter(|name| !path.contains(name))
            .find(|name| !spec.query_keys.contains(name.as_str()))
        {
            return Err(OperationRefusal::QueryKeyNotOnRoute { name: name.clone() });
        }
    }
    Ok(())
}

/// The registered provider operations; an operation without one is refused.
#[derive(Clone, Debug, Default)]
pub struct OperationCatalog {
    operations: BTreeMap<OperationKey, ProviderOperation>,
}

impl OperationCatalog {
    /// An empty catalog.
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers an operation. A batch's members must already be registered as typed
    /// single operations of the same provider, and a batch with a side-effecting member
    /// must be side-effecting.
    pub fn insert(&mut self, operation: ProviderOperation) -> Result<(), OperationRefusal> {
        let key = operation.key().clone();
        if self.operations.contains_key(&key) {
            return Err(OperationRefusal::DuplicateOperation { operation: key });
        }
        if let OperationFamily::Batch(batch) = operation.family() {
            for member in &batch.members {
                let found = self.operations.get(member).ok_or_else(|| {
                    OperationRefusal::BatchMemberUnknown {
                        member: member.clone(),
                    }
                })?;
                if matches!(
                    found.family(),
                    OperationFamily::Batch(_) | OperationFamily::CredentialedPassthrough
                ) {
                    return Err(OperationRefusal::BatchMemberNotTyped {
                        member: member.clone(),
                    });
                }
                if member.provider != key.provider {
                    return Err(OperationRefusal::BatchMemberOtherProvider {
                        member: member.clone(),
                    });
                }
                if found.intent().changes_provider_state()
                    && !operation.intent().changes_provider_state()
                {
                    return Err(OperationRefusal::BatchIntentTooWeak);
                }
            }
        }
        self.operations.insert(key, operation);
        Ok(())
    }

    /// The registered operation, or a refusal for an unknown one.
    pub fn get(&self, key: &OperationKey) -> Result<&ProviderOperation, OperationRefusal> {
        self.operations
            .get(key)
            .ok_or_else(|| OperationRefusal::UnknownOperation {
                operation: key.clone(),
            })
    }

    /// The effects contracts of every registered operation, for the effect controller.
    pub fn contracts(&self) -> ContractRegistry {
        self.operations
            .values()
            .fold(ContractRegistry::new(), |registry, operation| {
                registry.with(operation.contract.clone())
            })
    }

    /// The member operations of a batch, or none for any other family.
    pub fn members_of(
        &self,
        key: &OperationKey,
    ) -> Result<BTreeMap<OperationKey, ProviderOperation>, OperationRefusal> {
        let operation = self.get(key)?;
        let OperationFamily::Batch(batch) = operation.family() else {
            return Ok(BTreeMap::new());
        };
        batch
            .members
            .iter()
            .map(|member| Ok((member.clone(), self.get(member)?.clone())))
            .collect()
    }

    /// Checks a description and its payload against the operation's family and cost
    /// model, and returns the conservative maximum cost to reserve.
    pub fn check_request(
        &self,
        description: &EffectDescription,
        payload: Option<&[u8]>,
    ) -> Result<CostCeiling, OperationRefusal> {
        let operation = self.get(description.operation())?;
        let members = self.members_of(description.operation())?;
        check_request_with(operation, &members, description, payload)
    }
}

/// The request checks and conservative cost of [`OperationCatalog::check_request`], over
/// an operation and its batch members.
pub(super) fn check_request_with(
    operation: &ProviderOperation,
    members: &BTreeMap<OperationKey, ProviderOperation>,
    description: &EffectDescription,
    payload: Option<&[u8]>,
) -> Result<CostCeiling, OperationRefusal> {
    if description.operation() != operation.key() {
        return Err(OperationRefusal::Contract {
            refusal: ContractRefusal::OperationMismatch,
        });
    }
    operation
        .contract
        .validate(description)
        .map_err(|refusal| OperationRefusal::Contract { refusal })?;
    let request_bytes =
        ProviderOperation::request_bytes(description.parameters(), description.content_bytes());
    let mut total = operation
        .cost
        .max_cost(&operation.contract, description.parameters(), request_bytes)
        .map_err(|refusal| OperationRefusal::Cost { refusal })?;
    if let OperationFamily::Batch(spec) = operation.family() {
        let bytes = payload.ok_or(OperationRefusal::PayloadMissing)?;
        let document = BatchDocument::parse(bytes, spec, members)
            .map_err(|refusal| OperationRefusal::Batch { refusal })?;
        for member in document.members() {
            let member_operation = members.get(&member.operation).ok_or_else(|| {
                OperationRefusal::BatchMemberUnknown {
                    member: member.operation.clone(),
                }
            })?;
            let member_bytes = ProviderOperation::request_bytes(&member.parameters, 0);
            let cost = member_operation
                .cost
                .max_cost(&member_operation.contract, &member.parameters, member_bytes)
                .map_err(|refusal| OperationRefusal::Cost { refusal })?;
            total = CostCeiling {
                max_spend_microunits: total
                    .max_spend_microunits
                    .checked_add(cost.max_spend_microunits)
                    .ok_or(OperationRefusal::Cost {
                        refusal: CostRefusal::Overflow,
                    })?,
                max_volume_units: total
                    .max_volume_units
                    .checked_add(cost.max_volume_units)
                    .ok_or(OperationRefusal::Cost {
                        refusal: CostRefusal::Overflow,
                    })?,
            };
        }
    }
    if !total.within(&description.max_cost()) {
        return Err(OperationRefusal::CostAboveDescription {
            model: total,
            described: description.max_cost(),
        });
    }
    Ok(total)
}
