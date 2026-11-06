//! Operation-specific contracts (VM part §4.6 line 2024; §9.2 lines 2344 and 2361;
//! VM-W31).
//!
//! An HTTP verb does not classify intent, and GraphQL or batch endpoints carry many
//! operations, so each external operation has its own contract: its parameters and
//! their kinds, the routes it may reach, its payload and attachment slots, what the
//! provider guarantees about retries, the response fields an executor may return and
//! the per-effect ceiling. One description is one operation.
//!
//! A contract gives an exactly-once guarantee only when its provider deduplicates by
//! idempotency key or checks preconditions atomically; otherwise retries carry no such
//! promise (§9.2 line 2361).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::budget::TrustClass;
use super::canonical::{CanonicalValue, ParamName, Parameters, RawParameters, RawValue};
use super::description::{
    AttachmentName, CostCeiling, EffectDescription, IdempotencyRequirement, OperationKey, RouteRef,
};
use crate::foundation::ids::Digest;

strict_tagged_enum! {
    /// The kind of one scalar parameter.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ScalarKind (tag = "kind", wire = ScalarKindWire, wire_name = "ScalarKindWire") {
        /// UTF-8 text without control characters, at most `max_bytes` bytes.
        Text { max_bytes: u32 },
        Integer { min: i64, max: i64 },
        Bool,
        /// 64 hexadecimal characters in either case; both cases are one value.
        Digest,
    }
}

/// Whether a list's order carries meaning.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListOrder {
    Ordered,
    /// Normalized to a sorted set; duplicates are refused rather than merged.
    Unordered,
}

strict_tagged_enum! {
    /// The shape of one parameter.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub enum ParamKind (tag = "shape", wire = ParamKindWire, wire_name = "ParamKindWire") {
        Scalar { kind: ScalarKind },
        List { item: ScalarKind, max_items: u32, order: ListOrder },
    }
}

/// One declared parameter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParamSpec {
    pub kind: ParamKind,
    pub required: bool,
}

/// Whether the operation carries a payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PayloadRule {
    Forbidden,
    Optional,
    Required,
}

/// A route the operation may reach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RouteSpec {
    pub trust: TrustClass,
    /// Bytes of the route's host name, which leave in DNS and the TLS server name.
    pub name_bytes: u32,
}

/// What a contract can promise about retries (§9.2 line 2361).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeliveryGuarantee {
    /// The provider deduplicates by the idempotency key.
    ExactlyOnceByProviderKey,
    /// The provider checks preconditions atomically, so a repeat cannot apply twice.
    ExactlyOnceByPrecondition,
    /// No exactly-once promise: an uncertain outcome must be reconciled by observation.
    NoExactlyOnce,
}

impl DeliveryGuarantee {
    pub const fn promises_exactly_once(self) -> bool {
        !matches!(self, Self::NoExactlyOnce)
    }
}

/// The contract of one external operation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationContract {
    pub operation: OperationKey,
    pub parameters: BTreeMap<ParamName, ParamSpec>,
    pub routes: BTreeMap<RouteRef, RouteSpec>,
    pub payload: PayloadRule,
    pub attachments: BTreeSet<AttachmentName>,
    /// The provider deduplicates requests by idempotency key.
    pub provider_key: bool,
    /// The provider checks preconditions atomically with the change.
    pub checkable_preconditions: bool,
    /// The only response fields an executor returns (§4.5 line 2004).
    pub response_fields: BTreeSet<ParamName>,
    /// Fixed request header bytes the executor sends, excluding the idempotency header.
    pub header_bytes: u32,
    /// Protocol framing bytes per request.
    pub framing_bytes: u32,
    /// The most one effect under this contract may cost.
    pub max_cost: CostCeiling,
}

impl OperationContract {
    /// What the contract can promise for `requirement`, or why it cannot meet it.
    pub fn delivery(
        &self,
        requirement: IdempotencyRequirement,
    ) -> Result<DeliveryGuarantee, ContractRefusal> {
        match requirement {
            IdempotencyRequirement::ProviderKey if self.provider_key => {
                Ok(DeliveryGuarantee::ExactlyOnceByProviderKey)
            }
            IdempotencyRequirement::Precondition if self.checkable_preconditions => {
                Ok(DeliveryGuarantee::ExactlyOnceByPrecondition)
            }
            IdempotencyRequirement::NoExactlyOnce => Ok(DeliveryGuarantee::NoExactlyOnce),
            _ => Err(ContractRefusal::ExactlyOnceUnavailable { requirement }),
        }
    }

    /// Normalizes raw parameters: unknown names, missing required ones and values of the
    /// wrong kind are refused, and unordered lists become sorted sets.
    pub fn normalize(&self, raw: &RawParameters) -> Result<Parameters, ContractRefusal> {
        let mut parameters = Parameters::new();
        for (name, value) in raw.iter() {
            let param =
                ParamName::new(name.as_str()).map_err(|_| ContractRefusal::UnknownParameter {
                    name: bounded(name),
                })?;
            let spec =
                self.parameters
                    .get(&param)
                    .ok_or_else(|| ContractRefusal::UnknownParameter {
                        name: bounded(name),
                    })?;
            let canonical = normalize_value(&param, &spec.kind, value)?;
            parameters = parameters.with(param, canonical);
        }
        self.check_required(&parameters)?;
        Ok(parameters)
    }

    /// Checks a description against the contract and returns the delivery guarantee.
    pub fn validate(
        &self,
        description: &EffectDescription,
    ) -> Result<DeliveryGuarantee, ContractRefusal> {
        if description.operation() != &self.operation {
            return Err(ContractRefusal::OperationMismatch);
        }
        let destination = description.destination();
        let route = self
            .routes
            .get(&destination.route)
            .ok_or(ContractRefusal::RouteNotInContract)?;
        if route.trust != destination.trust {
            return Err(ContractRefusal::TrustClassMismatch);
        }
        for (name, value) in description.parameters().iter() {
            let spec =
                self.parameters
                    .get(name)
                    .ok_or_else(|| ContractRefusal::UnknownParameter {
                        name: name.as_str().to_owned(),
                    })?;
            check_value(name, &spec.kind, value)?;
        }
        self.check_required(description.parameters())?;
        match (self.payload, description.payload()) {
            (PayloadRule::Forbidden, Some(_)) => return Err(ContractRefusal::PayloadForbidden),
            (PayloadRule::Required, None) => return Err(ContractRefusal::PayloadRequired),
            _ => {}
        }
        if let Some(name) = description
            .attachments()
            .keys()
            .find(|name| !self.attachments.contains(*name))
        {
            return Err(ContractRefusal::UnknownAttachment { name: name.clone() });
        }
        if !description.preconditions().is_empty() && !self.checkable_preconditions {
            return Err(ContractRefusal::PreconditionsUncheckable);
        }
        if !description.max_cost().within(&self.max_cost) {
            return Err(ContractRefusal::CostAboveContract);
        }
        self.delivery(description.idempotency().requirement)
    }

    fn check_required(&self, parameters: &Parameters) -> Result<(), ContractRefusal> {
        match self
            .parameters
            .iter()
            .find(|(name, spec)| spec.required && parameters.get(name).is_none())
        {
            Some((name, _)) => Err(ContractRefusal::MissingParameter { name: name.clone() }),
            None => Ok(()),
        }
    }
}

fn bounded(name: &str) -> String {
    name.chars().take(128).collect()
}

fn normalize_scalar(
    name: &ParamName,
    kind: &ScalarKind,
    raw: &RawValue,
) -> Result<CanonicalValue, ContractRefusal> {
    let wrong = || ContractRefusal::WrongKind { name: name.clone() };
    let value = match (kind, raw) {
        (ScalarKind::Text { .. }, RawValue::Text(text)) => CanonicalValue::Text(text.clone()),
        (ScalarKind::Integer { .. }, RawValue::Integer(value)) => CanonicalValue::Integer(*value),
        (ScalarKind::Bool, RawValue::Bool(value)) => CanonicalValue::Bool(*value),
        (ScalarKind::Digest, RawValue::Text(text)) => CanonicalValue::Digest(
            Digest::from_hex(text)
                .map_err(|_| ContractRefusal::InvalidDigest { name: name.clone() })?,
        ),
        _ => return Err(wrong()),
    };
    check_scalar(name, kind, &value)?;
    Ok(value)
}

fn normalize_value(
    name: &ParamName,
    kind: &ParamKind,
    raw: &RawValue,
) -> Result<CanonicalValue, ContractRefusal> {
    match (kind, raw) {
        (ParamKind::Scalar { kind }, raw) => normalize_scalar(name, kind, raw),
        (
            ParamKind::List {
                item,
                max_items,
                order,
            },
            RawValue::List(items),
        ) => {
            if items.len() > *max_items as usize {
                return Err(ContractRefusal::TooManyItems {
                    name: name.clone(),
                    max_items: *max_items,
                });
            }
            let values = items
                .iter()
                .map(|value| normalize_scalar(name, item, value))
                .collect::<Result<Vec<_>, _>>()?;
            match order {
                ListOrder::Ordered => Ok(CanonicalValue::List(values)),
                ListOrder::Unordered => {
                    let count = values.len();
                    let set: BTreeSet<CanonicalValue> = values.into_iter().collect();
                    if set.len() != count {
                        return Err(ContractRefusal::DuplicateItem { name: name.clone() });
                    }
                    Ok(CanonicalValue::Set(set))
                }
            }
        }
        _ => Err(ContractRefusal::WrongKind { name: name.clone() }),
    }
}

fn check_scalar(
    name: &ParamName,
    kind: &ScalarKind,
    value: &CanonicalValue,
) -> Result<(), ContractRefusal> {
    match (kind, value) {
        (ScalarKind::Text { max_bytes }, CanonicalValue::Text(text)) => {
            if text.len() > *max_bytes as usize {
                return Err(ContractRefusal::TextTooLong {
                    name: name.clone(),
                    max_bytes: *max_bytes,
                });
            }
            if text.chars().any(char::is_control) {
                return Err(ContractRefusal::ControlCharacter { name: name.clone() });
            }
            Ok(())
        }
        (ScalarKind::Integer { min, max }, CanonicalValue::Integer(value)) => {
            if value < min || value > max {
                Err(ContractRefusal::IntegerOutOfRange { name: name.clone() })
            } else {
                Ok(())
            }
        }
        (ScalarKind::Bool, CanonicalValue::Bool(_))
        | (ScalarKind::Digest, CanonicalValue::Digest(_)) => Ok(()),
        _ => Err(ContractRefusal::WrongKind { name: name.clone() }),
    }
}

fn check_value(
    name: &ParamName,
    kind: &ParamKind,
    value: &CanonicalValue,
) -> Result<(), ContractRefusal> {
    let items: Vec<&CanonicalValue> = match (kind, value) {
        (ParamKind::Scalar { kind }, value) => return check_scalar(name, kind, value),
        (
            ParamKind::List {
                order: ListOrder::Ordered,
                ..
            },
            CanonicalValue::List(items),
        ) => items.iter().collect(),
        (
            ParamKind::List {
                order: ListOrder::Unordered,
                ..
            },
            CanonicalValue::Set(items),
        ) => items.iter().collect(),
        _ => return Err(ContractRefusal::WrongKind { name: name.clone() }),
    };
    if let ParamKind::List {
        item, max_items, ..
    } = kind
    {
        if items.len() > *max_items as usize {
            return Err(ContractRefusal::TooManyItems {
                name: name.clone(),
                max_items: *max_items,
            });
        }
        for value in items {
            check_scalar(name, item, value)?;
        }
    }
    Ok(())
}

strict_tagged_enum! {
    /// Why a request or description does not fit its operation contract.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ContractRefusal (tag = "refusal", wire = ContractRefusalWire, wire_name = "ContractRefusalWire") {
        UnknownOperation,
        OperationMismatch,
        UnknownParameter { name: String },
        MissingParameter { name: ParamName },
        WrongKind { name: ParamName },
        TextTooLong { name: ParamName, max_bytes: u32 },
        ControlCharacter { name: ParamName },
        IntegerOutOfRange { name: ParamName },
        TooManyItems { name: ParamName, max_items: u32 },
        DuplicateItem { name: ParamName },
        InvalidDigest { name: ParamName },
        RouteNotInContract,
        TrustClassMismatch,
        PayloadForbidden,
        PayloadRequired,
        UnknownAttachment { name: AttachmentName },
        PreconditionsUncheckable,
        /// The provider has neither idempotency keys nor checkable preconditions for this
        /// requirement, so no exactly-once promise is possible (§9.2 line 2361).
        ExactlyOnceUnavailable { requirement: IdempotencyRequirement },
        CostAboveContract,
    }
}

impl fmt::Display for ContractRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownOperation => f.write_str("no contract exists for this operation"),
            Self::OperationMismatch => f.write_str("the description names another operation"),
            Self::UnknownParameter { name } => {
                write!(f, "{name:?} is not a parameter of this operation")
            }
            Self::MissingParameter { name } => write!(f, "{name} is required"),
            Self::WrongKind { name } => write!(f, "{name} has the wrong kind of value"),
            Self::TextTooLong { name, max_bytes } => {
                write!(f, "{name} is longer than {max_bytes} bytes")
            }
            Self::ControlCharacter { name } => write!(f, "{name} contains a control character"),
            Self::IntegerOutOfRange { name } => write!(f, "{name} is out of range"),
            Self::TooManyItems { name, max_items } => {
                write!(f, "{name} has more than {max_items} items")
            }
            Self::DuplicateItem { name } => write!(f, "{name} lists an item twice"),
            Self::InvalidDigest { name } => write!(f, "{name} is not a 64-digit digest"),
            Self::RouteNotInContract => f.write_str("the operation may not reach this route"),
            Self::TrustClassMismatch => {
                f.write_str("the destination's trust class differs from the route's")
            }
            Self::PayloadForbidden => f.write_str("this operation carries no payload"),
            Self::PayloadRequired => f.write_str("this operation needs a payload"),
            Self::UnknownAttachment { name } => {
                write!(f, "{name} is not an attachment slot of this operation")
            }
            Self::PreconditionsUncheckable => {
                f.write_str("the provider cannot check preconditions for this operation")
            }
            Self::ExactlyOnceUnavailable { requirement } => write!(
                f,
                "the provider cannot meet {:?}; without idempotency keys or checkable \
                 preconditions there is no exactly-once promise",
                requirement.tag()
            ),
            Self::CostAboveContract => {
                f.write_str("the maximum cost is above the contract's ceiling")
            }
        }
    }
}

impl std::error::Error for ContractRefusal {}

/// The operation contracts the host knows; an operation without one is refused.
#[derive(Clone, Debug, Default)]
pub struct ContractRegistry {
    contracts: BTreeMap<OperationKey, OperationContract>,
}

impl ContractRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, contract: OperationContract) -> Self {
        self.contracts.insert(contract.operation.clone(), contract);
        self
    }

    pub fn get(&self, operation: &OperationKey) -> Result<&OperationContract, ContractRefusal> {
        self.contracts
            .get(operation)
            .ok_or(ContractRefusal::UnknownOperation)
    }
}
