//! Canonical contract identity, kept apart from issuer identity (VM part §2.4 line 1804;
//! VM-W02; §0.2: a signed policy digest is an integrity identifier, not a proof).
//!
//! A [`ContractIdentity`] is a domain-separated digest of the canonical encoding of a
//! resolved contract. Every collection in a contract is a set, so the encoding writes
//! each in its canonical order and the identity does not depend on the order a document
//! listed things in. An [`IssuerIdentity`] names who issued a contract and is not part
//! of the contract's identity. Neither proves that any implementation enforces the
//! contract, and no evidence input in this module accepts either.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::approval::ApprovalSet;
use super::budget::{AccountingScope, BudgetSet};
use super::layers::{ContractSchemaVersion, RequestSource};
use super::predicate::RequirementSet;
use super::tuple::{GenerationScope, Operation, PermissionSet, PermissionTuple, ResourceRef};
use crate::foundation::ids::{digest, Digest, DigestBuilder, PolicyEpoch};

/// The identity of a resolved contract: what it permits, requires, needs approved and
/// budgets, under which schema version and policy epoch. It identifies; it proves
/// nothing about enforcement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ContractIdentity(Digest);

impl ContractIdentity {
    /// Changing this or the encoding changes every contract identity.
    pub const DOMAIN: &'static str = "yougori/sandbox-policy/contract/v1";

    pub const fn digest(self) -> Digest {
        self.0
    }
}

impl fmt::Display for ContractIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The identity of a validated template or tool request, for display and caching.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RequestIdentity(Digest);

impl RequestIdentity {
    pub const DOMAIN: &'static str = "yougori/sandbox-policy/request/v1";

    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// Who issued a contract, such as the digest of the issuer's public key. A signature
/// identifies its issuer; it says nothing about whether the contract is enforced.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IssuerIdentity(Digest);

impl IssuerIdentity {
    pub const NAME_DOMAIN: &'static str = "yougori/sandbox-policy/issuer/v1";

    /// An issuer named by text, for tests and simple configurations.
    pub fn named(name: &str) -> Self {
        Self(digest(Self::NAME_DOMAIN, &[name.as_bytes()]))
    }

    pub const fn from_key_digest(key: Digest) -> Self {
        Self(key)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// A contract identity beside its issuer's identity: two separate facts, neither of
/// which is evidence that the contract is enforced (§2.4 line 1804).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedContract {
    pub contract: ContractIdentity,
    pub issuer: IssuerIdentity,
}

/// The parts of a resolved contract that its identity covers.
pub(super) struct ContractParts<'a> {
    pub schema_version: ContractSchemaVersion,
    pub policy_epoch: PolicyEpoch,
    pub permitted: &'a PermissionSet,
    pub dependencies: &'a PermissionSet,
    pub requirements: &'a RequirementSet,
    pub approvals: &'a ApprovalSet,
    pub budgets: &'a BudgetSet,
}

pub(super) fn contract_identity(parts: &ContractParts<'_>) -> ContractIdentity {
    let builder = DigestBuilder::new(ContractIdentity::DOMAIN)
        .u64(u64::from(parts.schema_version.get()))
        .u64(parts.policy_epoch.get());
    let builder = permissions(builder, parts.permitted);
    let builder = permissions(builder, parts.dependencies);
    let builder = requirements(builder, parts.requirements);
    let builder = approvals(builder, parts.approvals);
    ContractIdentity(budgets(builder, parts.budgets).finish())
}

pub(super) struct RequestParts<'a> {
    pub source: &'a RequestSource,
    pub requested: &'a PermissionSet,
    pub dependencies: &'a PermissionSet,
    pub requirements: &'a RequirementSet,
    pub approvals: &'a ApprovalSet,
    pub budgets: &'a BudgetSet,
}

pub(super) fn request_identity(parts: &RequestParts<'_>) -> RequestIdentity {
    let builder = DigestBuilder::new(RequestIdentity::DOMAIN)
        .str(parts.source.kind.tag())
        .str(parts.source.name.as_str());
    let builder = permissions(builder, parts.requested);
    let builder = permissions(builder, parts.dependencies);
    let builder = requirements(builder, parts.requirements);
    let builder = approvals(builder, parts.approvals);
    RequestIdentity(budgets(builder, parts.budgets).finish())
}

fn operation(builder: DigestBuilder, operation: &Operation) -> DigestBuilder {
    let builder = builder.str(operation.tag());
    match operation {
        Operation::ProviderOperation { name } => builder.str(name.as_str()),
        _ => builder,
    }
}

fn resource(builder: DigestBuilder, resource: &ResourceRef) -> DigestBuilder {
    builder.str(resource.kind.tag()).str(resource.name.as_str())
}

fn tuple(builder: DigestBuilder, tuple: &PermissionTuple) -> DigestBuilder {
    let builder = builder.str(tuple.principal.role.as_str());
    let builder = operation(builder, &tuple.operation);
    let builder = resource(builder, &tuple.resource).str(tuple.context.phase.tag());
    match tuple.generation {
        GenerationScope::EveryGeneration => builder.str("every"),
        GenerationScope::Authorization { epoch } => builder.str("authorization").u64(epoch.get()),
    }
}

fn permissions(builder: DigestBuilder, set: &PermissionSet) -> DigestBuilder {
    set.iter()
        .fold(builder.u64(set.len() as u64), |builder, item| {
            tuple(builder, &item)
        })
}

fn requirements(builder: DigestBuilder, set: &RequirementSet) -> DigestBuilder {
    set.iter()
        .fold(builder.u64(set.len() as u64), |builder, predicate| {
            builder.str(predicate.name())
        })
}

fn approvals(builder: DigestBuilder, set: &ApprovalSet) -> DigestBuilder {
    set.iter()
        .fold(builder.u64(set.len() as u64), |builder, rule| {
            let builder = operation(builder.str(rule.kind.tag()), &rule.operation);
            resource(builder, &rule.resource)
        })
}

fn budgets(builder: DigestBuilder, set: &BudgetSet) -> DigestBuilder {
    set.iter()
        .fold(builder.u64(set.len() as u64), |builder, (key, limit)| {
            let builder = builder.str(key.resource.tag()).str(key.scope.tag());
            let builder = match &key.scope {
                AccountingScope::Channel { resource: channel } => resource(builder, channel),
                AccountingScope::Generation
                | AccountingScope::Execution
                | AccountingScope::Tenant => builder,
            };
            builder.u64(limit)
        })
}
