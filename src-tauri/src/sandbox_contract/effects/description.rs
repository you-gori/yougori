//! The immutable effect description (VM part §9.2 line 2344; §4.6 lines 2016–2024;
//! VM-W31).
//!
//! An [`EffectDescription`] names one external effect completely: provider operation,
//! destination resource and account, normalized parameters, payload and attachment
//! digests, preconditions, maximum spend, maximum wire bytes, deadline and idempotency
//! identity. Its canonical digest is the [`EffectId`]. Policy approves the description,
//! never a route or a mutable reference: a payload is named by its content key, so a
//! reviewed artifact whose bytes change afterwards no longer matches (§4.6 line 2022).
//!
//! Operations are named by their provider contract, never by an HTTP verb: POST may
//! perform inference and GET may have side effects (§4.6 line 2024), so a bare verb is
//! refused as an operation name.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::budget::TrustClass;
use super::canonical::{len_u64, Parameters};
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{
    validate_identifier, ContentKey, Digest, DigestBuilder, ExecutionId, IdError, MonotonicTime,
    TenantId,
};

/// The digest domain of an [`EffectDescription`]; a new field layout needs a new domain.
pub const DESCRIPTION_DOMAIN: &str = "yougori/sandbox/effect-description/v1";

/// Method names that are never operation names (§4.6 line 2024).
pub const HTTP_VERBS: [&str; 9] = [
    "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH",
];

digest_handle!(
    /// The host or issuer that scopes nonces and generations (§6.3 line 2143), by the
    /// digest of its stable identity.
    IssuerId
);
digest_handle!(
    /// A provider account, by the digest of its provider-side identity.
    AccountRef
);
digest_handle!(
    /// A destination route the host registered; there is no URL form.
    RouteRef
);
digest_handle!(
    /// The idempotency identity of one effect; every retry keeps it (§9.2 line 2351).
    IdempotencyKey
);
digest_handle!(
    /// The identity of one effect: the canonical digest of its description.
    EffectId
);

effect_name!(
    /// A provider, such as `github` or `stripe`.
    ProviderId
);
effect_name!(
    /// The name of one attachment slot of an operation contract.
    AttachmentName
);

/// A provider operation's contract name, such as `create_pull_request`. A bare HTTP verb
/// is refused, in any letter case (§4.6 line 2024).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct OperationName(String);

impl OperationName {
    pub fn new(value: impl Into<String>) -> Result<Self, OperationNameError> {
        let value = value.into();
        validate_identifier(&value).map_err(OperationNameError::Identifier)?;
        if HTTP_VERBS
            .iter()
            .any(|verb| verb.eq_ignore_ascii_case(&value))
        {
            return Err(OperationNameError::HttpVerb { verb: value });
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OperationName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OperationName({})", self.0)
    }
}

impl fmt::Display for OperationName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OperationName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Why an operation name was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OperationNameError {
    Identifier(IdError),
    /// An HTTP verb does not classify intent; name the operation contract instead.
    HttpVerb {
        verb: String,
    },
}

impl fmt::Display for OperationNameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identifier(error) => write!(f, "{error}"),
            Self::HttpVerb { verb } => write!(
                f,
                "{verb:?} is an HTTP verb, which does not say what an operation does; name \
                 the operation contract instead"
            ),
        }
    }
}

impl std::error::Error for OperationNameError {}

/// One sandbox, scoped by its issuer (§6.3 line 2143).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxRef {
    pub issuer: IssuerId,
    /// The sandbox's execution in the CORE-04 coordinator.
    pub execution: ExecutionId,
}

/// One operation contract of one provider.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationKey {
    pub provider: ProviderId,
    pub operation: OperationName,
    pub contract_version: u32,
}

/// The destination resource and the provider account it belongs to (VM-W31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceRef {
    pub account: AccountRef,
    /// The digest of the provider's canonical identity of the object.
    pub object: Digest,
}

/// Where the operation goes: a registered route and its trust class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    pub route: RouteRef,
    pub trust: TrustClass,
}

/// Immutable content by key and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadRef {
    pub content: ContentKey,
    pub length_bytes: u64,
}

strict_tagged_enum! {
    /// A provider-checkable precondition (§9.2 line 2344).
    #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub enum Precondition (tag = "precondition", wire = PreconditionWire, wire_name = "PreconditionWire") {
        /// The resource is at exactly this version, such as an entity tag.
        MatchesVersion { version: Digest },
        Absent,
        Present,
    }
}

impl Precondition {
    fn feed(&self, builder: DigestBuilder) -> DigestBuilder {
        match self {
            Self::MatchesVersion { version } => builder.str("matches_version").digest(version),
            Self::Absent => builder.str("absent"),
            Self::Present => builder.str("present"),
        }
    }
}

/// The price and volume ceiling of one effect (VM-W31). Zero allows nothing.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
#[serde(deny_unknown_fields)]
pub struct CostCeiling {
    /// Provider spend, in millionths of the account's currency unit.
    pub max_spend_microunits: u64,
    /// Provider volume units, such as tokens or API calls, as the contract defines them.
    pub max_volume_units: u64,
}

impl CostCeiling {
    /// Whether every part of `self` is at most the matching part of `ceiling`.
    pub fn within(&self, ceiling: &CostCeiling) -> bool {
        self.max_spend_microunits <= ceiling.max_spend_microunits
            && self.max_volume_units <= ceiling.max_volume_units
    }
}

/// An absolute deadline on one clock session; on another session it cannot be read, so
/// it is refused rather than compared.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deadline {
    pub clock: ClockSession,
    pub at: MonotonicTime,
}

/// What the requester requires of retries (§4.6 line 2026; §9.2 line 2361).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdempotencyRequirement {
    /// The provider must deduplicate by the idempotency key.
    ProviderKey,
    /// The provider must check the description's preconditions.
    Precondition,
    /// No exactly-once promise is asked for or given.
    NoExactlyOnce,
}

impl IdempotencyRequirement {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ProviderKey => "provider_key",
            Self::Precondition => "precondition",
            Self::NoExactlyOnce => "no_exactly_once",
        }
    }
}

/// The idempotency identity and requirement of one effect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Idempotency {
    pub key: IdempotencyKey,
    pub requirement: IdempotencyRequirement,
}

/// Every field of an effect description (§9.2 line 2344).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectFields {
    pub principal: TenantId,
    pub sandbox: SandboxRef,
    pub operation: OperationKey,
    pub resource: ResourceRef,
    pub destination: Destination,
    pub parameters: Parameters,
    pub payload: Option<PayloadRef>,
    pub attachments: BTreeMap<AttachmentName, PayloadRef>,
    pub preconditions: BTreeSet<Precondition>,
    pub max_cost: CostCeiling,
    /// Every byte the outbound operation may put on the wire, headers, URL, names and
    /// framing included (§2.5 line 1815).
    pub max_wire_bytes_out: u64,
    pub deadline: Deadline,
    pub idempotency: Idempotency,
}

/// Why effect fields were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DescriptionError {
    ZeroWireBudget,
    /// The wire budget cannot even carry the payload and attachments.
    WireBudgetBelowContent {
        content_bytes: u64,
        max_wire_bytes_out: u64,
    },
    ContentLengthOverflow,
    /// A precondition requirement with nothing to check.
    PreconditionRequirementWithoutPreconditions,
}

impl fmt::Display for DescriptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroWireBudget => f.write_str("an external operation needs a wire byte budget"),
            Self::WireBudgetBelowContent {
                content_bytes,
                max_wire_bytes_out,
            } => write!(
                f,
                "{max_wire_bytes_out} wire bytes cannot carry {content_bytes} bytes of content"
            ),
            Self::ContentLengthOverflow => f.write_str("the content lengths overflow 64 bits"),
            Self::PreconditionRequirementWithoutPreconditions => {
                f.write_str("the idempotency requirement names preconditions, but there are none")
            }
        }
    }
}

impl std::error::Error for DescriptionError {}

/// The immutable description of one external effect (§9.2 line 2344). It is built only
/// from checked fields, and reading one back recomputes its identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EffectFields", into = "EffectFields")]
pub struct EffectDescription {
    fields: EffectFields,
    id: EffectId,
}

impl TryFrom<EffectFields> for EffectDescription {
    type Error = DescriptionError;

    fn try_from(fields: EffectFields) -> Result<Self, Self::Error> {
        Self::new(fields)
    }
}

impl From<EffectDescription> for EffectFields {
    fn from(description: EffectDescription) -> Self {
        description.fields
    }
}

impl EffectDescription {
    /// Checks the fields and computes the identity.
    pub fn new(fields: EffectFields) -> Result<Self, DescriptionError> {
        if fields.max_wire_bytes_out == 0 {
            return Err(DescriptionError::ZeroWireBudget);
        }
        let content_bytes =
            content_bytes(&fields).ok_or(DescriptionError::ContentLengthOverflow)?;
        if content_bytes > fields.max_wire_bytes_out {
            return Err(DescriptionError::WireBudgetBelowContent {
                content_bytes,
                max_wire_bytes_out: fields.max_wire_bytes_out,
            });
        }
        if fields.idempotency.requirement == IdempotencyRequirement::Precondition
            && fields.preconditions.is_empty()
        {
            return Err(DescriptionError::PreconditionRequirementWithoutPreconditions);
        }
        let id = EffectId(description_digest(&fields));
        Ok(Self { fields, id })
    }

    pub fn id(&self) -> EffectId {
        self.id
    }

    /// The fields, read-only; a changed copy must go through [`EffectDescription::new`]
    /// and gets another identity.
    pub fn fields(&self) -> &EffectFields {
        &self.fields
    }

    pub fn principal(&self) -> &TenantId {
        &self.fields.principal
    }

    pub fn sandbox(&self) -> &SandboxRef {
        &self.fields.sandbox
    }

    pub fn operation(&self) -> &OperationKey {
        &self.fields.operation
    }

    pub fn resource(&self) -> ResourceRef {
        self.fields.resource
    }

    pub fn destination(&self) -> Destination {
        self.fields.destination
    }

    pub fn parameters(&self) -> &Parameters {
        &self.fields.parameters
    }

    pub fn payload(&self) -> Option<PayloadRef> {
        self.fields.payload
    }

    pub fn attachments(&self) -> &BTreeMap<AttachmentName, PayloadRef> {
        &self.fields.attachments
    }

    pub fn preconditions(&self) -> &BTreeSet<Precondition> {
        &self.fields.preconditions
    }

    pub fn max_cost(&self) -> CostCeiling {
        self.fields.max_cost
    }

    pub fn max_wire_bytes_out(&self) -> u64 {
        self.fields.max_wire_bytes_out
    }

    pub fn deadline(&self) -> Deadline {
        self.fields.deadline
    }

    pub fn idempotency(&self) -> Idempotency {
        self.fields.idempotency
    }

    /// The payload and attachment bytes together.
    pub fn content_bytes(&self) -> u64 {
        content_bytes(&self.fields).unwrap_or(u64::MAX)
    }

    /// The digest of the attachment set, which ignores the order attachments were added.
    pub fn attachments_digest(&self) -> Digest {
        attachments_feed(
            &self.fields.attachments,
            DigestBuilder::new("yougori/sandbox/effect-attachments/v1"),
        )
        .finish()
    }
}

fn content_bytes(fields: &EffectFields) -> Option<u64> {
    fields.attachments.values().try_fold(
        fields.payload.map_or(0, |payload| payload.length_bytes),
        |sum, attachment| sum.checked_add(attachment.length_bytes),
    )
}

fn payload_feed(payload: Option<PayloadRef>, builder: DigestBuilder) -> DigestBuilder {
    match payload {
        None => builder.u64(0),
        Some(payload) => builder
            .u64(1)
            .digest(payload.content.digest())
            .u64(payload.length_bytes),
    }
}

fn attachments_feed(
    attachments: &BTreeMap<AttachmentName, PayloadRef>,
    builder: DigestBuilder,
) -> DigestBuilder {
    attachments.iter().fold(
        builder.u64(len_u64(attachments.len())),
        |b, (name, attachment)| {
            b.str(name.as_str())
                .digest(attachment.content.digest())
                .u64(attachment.length_bytes)
        },
    )
}

fn description_digest(fields: &EffectFields) -> Digest {
    let builder = DigestBuilder::new(DESCRIPTION_DOMAIN)
        .str(fields.principal.as_str())
        .digest(fields.sandbox.issuer.digest())
        .str(fields.sandbox.execution.as_str())
        .str(fields.operation.provider.as_str())
        .str(fields.operation.operation.as_str())
        .u64(u64::from(fields.operation.contract_version))
        .digest(fields.resource.account.digest())
        .digest(&fields.resource.object)
        .digest(fields.destination.route.digest())
        .str(fields.destination.trust.tag());
    let builder = fields.parameters.feed(builder);
    let builder = payload_feed(fields.payload, builder);
    let builder = attachments_feed(&fields.attachments, builder);
    let builder = fields.preconditions.iter().fold(
        builder.u64(len_u64(fields.preconditions.len())),
        |b, precondition| precondition.feed(b),
    );
    builder
        .u64(fields.max_cost.max_spend_microunits)
        .u64(fields.max_cost.max_volume_units)
        .u64(fields.max_wire_bytes_out)
        .bytes(fields.deadline.clock.as_uuid().as_bytes())
        .u64(fields.deadline.at.as_nanos())
        .digest(fields.idempotency.key.digest())
        .str(fields.idempotency.requirement.tag())
        .finish()
}

/// The artifact a user reviewed, by the content key of the bytes displayed (§4.6 line
/// 2022). Approval covers these bytes, never a filename: the outbound payload must have
/// the same key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedArtifact {
    pub content: ContentKey,
    pub length_bytes: u64,
}

impl ReviewedArtifact {
    /// The artifact as displayed to the reviewer.
    pub fn of_displayed(bytes: &[u8]) -> Self {
        Self {
            content: ContentKey::of(bytes),
            length_bytes: len_u64(bytes.len()),
        }
    }

    /// The payload reference an effect description carries for this artifact.
    pub fn payload(&self) -> PayloadRef {
        PayloadRef {
            content: self.content,
            length_bytes: self.length_bytes,
        }
    }

    /// Whether `outbound` is exactly the reviewed bytes.
    pub fn check_outbound(&self, outbound: &[u8]) -> Result<(), PayloadMismatch> {
        let actual = ContentKey::of(outbound);
        if actual == self.content {
            Ok(())
        } else {
            Err(PayloadMismatch {
                expected: self.content,
                actual,
            })
        }
    }
}

/// The bytes about to leave differ from the reviewed or described bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadMismatch {
    pub expected: ContentKey,
    pub actual: ContentKey,
}

impl fmt::Display for PayloadMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the outbound bytes have content key {}, but {} was approved",
            self.actual, self.expected
        )
    }
}

impl std::error::Error for PayloadMismatch {}
