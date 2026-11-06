//! Typed batches (VM part §4.6 line 2024: batch APIs can carry many operations).
//!
//! A batch is accepted only when every member names a registered typed operation that
//! the batch contract lists, and its parameters normalize under that member's request
//! schema. The canonical document is the effect's payload, so its content key binds every
//! member into the effect identity, and the executor sends exactly the reviewed bytes
//! after checking them again.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::operation::{BatchSpec, OperationFamily, ProviderOperation};
use crate::sandbox_contract::effects::{
    CanonicalValue, ContractRefusal, OperationKey, Parameters, RawParameters, RawValue,
};

/// One member as a guest or tool supplied it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawBatchMember {
    /// `None` is an untyped member and is refused.
    pub operation: Option<OperationKey>,
    pub parameters: RawParameters,
}

/// A batch as a guest or tool supplied it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RawBatch {
    pub members: Vec<RawBatchMember>,
}

/// One typed member with normalized parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchMember {
    pub operation: OperationKey,
    pub parameters: Parameters,
}

/// A batch whose every member is typed. Member order is kept: it can carry meaning.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchDocument {
    members: Vec<BatchMember>,
}

strict_provider_enum! {
    /// Why a batch was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum BatchRefusal tag "reason" {
        Empty,
        TooManyMembers { max_members: u32 },
        /// The member names no operation.
        UntypedMember { index: u64 },
        /// The member's operation is not one the batch contract lists.
        MemberNotInBatch { index: u64 },
        /// The member's operation is a batch or a passthrough, or has no contract here.
        MemberNotTyped { index: u64 },
        MemberInvalid { index: u64, refusal: ContractRefusal },
        /// The bytes are not the canonical encoding of a typed batch.
        NotCanonical,
    }
}

impl fmt::Display for BatchRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the batch has no members"),
            Self::TooManyMembers { max_members } => {
                write!(f, "the batch has more than {max_members} members")
            }
            Self::UntypedMember { index } => write!(f, "member {index} names no operation"),
            Self::MemberNotInBatch { index } => {
                write!(f, "member {index} is not an operation this batch carries")
            }
            Self::MemberNotTyped { index } => {
                write!(f, "member {index} is not a typed single operation")
            }
            Self::MemberInvalid { index, refusal } => write!(f, "member {index}: {refusal}"),
            Self::NotCanonical => f.write_str("the batch is not in its canonical typed encoding"),
        }
    }
}

impl std::error::Error for BatchRefusal {}

fn index_u64(index: usize) -> u64 {
    u64::try_from(index).unwrap_or(u64::MAX)
}

fn to_raw(value: &CanonicalValue) -> RawValue {
    match value {
        CanonicalValue::Text(text) => RawValue::Text(text.clone()),
        CanonicalValue::Integer(value) => RawValue::Integer(*value),
        CanonicalValue::Bool(value) => RawValue::Bool(*value),
        CanonicalValue::Digest(digest) => RawValue::Text(digest.to_hex()),
        CanonicalValue::List(items) => RawValue::List(items.iter().map(to_raw).collect()),
        CanonicalValue::Set(items) => RawValue::List(items.iter().map(to_raw).collect()),
    }
}

fn member_operation<'a>(
    index: usize,
    operation: &OperationKey,
    spec: &BatchSpec,
    members: &'a BTreeMap<OperationKey, ProviderOperation>,
) -> Result<&'a ProviderOperation, BatchRefusal> {
    if !spec.members.contains(operation) {
        return Err(BatchRefusal::MemberNotInBatch {
            index: index_u64(index),
        });
    }
    let found = members.get(operation).ok_or(BatchRefusal::MemberNotTyped {
        index: index_u64(index),
    })?;
    if matches!(
        found.family(),
        OperationFamily::Batch(_) | OperationFamily::CredentialedPassthrough
    ) {
        return Err(BatchRefusal::MemberNotTyped {
            index: index_u64(index),
        });
    }
    Ok(found)
}

fn check_count(count: usize, spec: &BatchSpec) -> Result<(), BatchRefusal> {
    if count == 0 {
        return Err(BatchRefusal::Empty);
    }
    if index_u64(count) > u64::from(spec.max_members) {
        return Err(BatchRefusal::TooManyMembers {
            max_members: spec.max_members,
        });
    }
    Ok(())
}

impl BatchDocument {
    /// Types a raw batch: every member must name a listed, typed operation and its
    /// parameters must normalize under that operation's schema.
    pub fn from_raw(
        raw: &RawBatch,
        spec: &BatchSpec,
        members: &BTreeMap<OperationKey, ProviderOperation>,
    ) -> Result<Self, BatchRefusal> {
        check_count(raw.members.len(), spec)?;
        let mut typed = Vec::new();
        for (index, member) in raw.members.iter().enumerate() {
            let operation = member
                .operation
                .as_ref()
                .ok_or(BatchRefusal::UntypedMember {
                    index: index_u64(index),
                })?;
            let found = member_operation(index, operation, spec, members)?;
            let parameters = found
                .contract()
                .normalize(&member.parameters)
                .map_err(|refusal| BatchRefusal::MemberInvalid {
                    index: index_u64(index),
                    refusal,
                })?;
            typed.push(BatchMember {
                operation: operation.clone(),
                parameters,
            });
        }
        Ok(Self { members: typed })
    }

    /// The canonical encoding, which is the effect's payload.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, BatchRefusal> {
        serde_json::to_vec(&self.members).map_err(|_| BatchRefusal::NotCanonical)
    }

    /// Reads canonical bytes back: they must decode to typed members that normalize to
    /// themselves and re-encode to the same bytes.
    pub fn parse(
        bytes: &[u8],
        spec: &BatchSpec,
        members: &BTreeMap<OperationKey, ProviderOperation>,
    ) -> Result<Self, BatchRefusal> {
        let decoded: Vec<BatchMember> =
            serde_json::from_slice(bytes).map_err(|_| BatchRefusal::NotCanonical)?;
        check_count(decoded.len(), spec)?;
        for (index, member) in decoded.iter().enumerate() {
            let found = member_operation(index, &member.operation, spec, members)?;
            let raw = member
                .parameters
                .iter()
                .fold(RawParameters::new(), |raw, (name, value)| {
                    raw.with(name.as_str(), to_raw(value))
                });
            let normalized = found.contract().normalize(&raw).map_err(|refusal| {
                BatchRefusal::MemberInvalid {
                    index: index_u64(index),
                    refusal,
                }
            })?;
            if normalized != member.parameters {
                return Err(BatchRefusal::NotCanonical);
            }
        }
        let document = Self { members: decoded };
        if document.canonical_bytes()? != bytes {
            return Err(BatchRefusal::NotCanonical);
        }
        Ok(document)
    }

    /// The typed members, in order.
    pub fn members(&self) -> &[BatchMember] {
        &self.members
    }
}
