//! The three independent authority layers (VM part §2.4): the product's ceiling and
//! requirements, the workload's request, and the delegation. Drafts are what callers
//! write; the validated layers are made only by the [`Validator`](super::Validator).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::approval::{ApprovalRule, ApprovalSet};
use super::budget::{Budget, BudgetSet};
use super::identity::{request_identity, RequestIdentity, RequestParts};
use super::predicate::{RequirementSet, SecurityPredicate};
use super::tuple::{PermissionSet, PermissionTuple, SourceName};
use crate::foundation::ids::PolicyEpoch;

/// The contract schema version this build reads and writes.
pub const CONTRACT_SCHEMA_VERSION: u32 = 1;

/// The pinned contract schema version. Only [`CONTRACT_SCHEMA_VERSION`] is
/// representable, so a document of any other version is refused, never reinterpreted
/// (VM-P47: an unknown version cannot override host policy).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct ContractSchemaVersion(u32);

impl ContractSchemaVersion {
    pub const CURRENT: Self = Self(CONTRACT_SCHEMA_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for ContractSchemaVersion {
    type Error = UnsupportedContractSchema;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == CONTRACT_SCHEMA_VERSION {
            Ok(Self(found))
        } else {
            Err(UnsupportedContractSchema { found })
        }
    }
}

impl From<ContractSchemaVersion> for u32 {
    fn from(version: ContractSchemaVersion) -> Self {
        version.0
    }
}

/// A document declared a contract schema version this build does not read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnsupportedContractSchema {
    pub found: u32,
}

impl fmt::Display for UnsupportedContractSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "contract schema version {} is not supported; this build reads only version \
             {CONTRACT_SCHEMA_VERSION}",
            self.found
        )
    }
}

impl std::error::Error for UnsupportedContractSchema {}

/// One of the independent limits whose intersection is the permitted set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyLayer {
    /// The host product's ceiling.
    ProductCeiling,
    /// The template's or tool's request.
    Request,
    /// The user's delegation.
    Delegation,
}

impl fmt::Display for PolicyLayer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ProductCeiling => "the product ceiling",
            Self::Request => "the request",
            Self::Delegation => "the delegation",
        })
    }
}

/// The host product's policy as written by the host (trusted input).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProductPolicyDraft {
    /// The policy epoch this policy is in force under (S3.1).
    pub policy_epoch: PolicyEpoch,
    pub ceiling: Vec<PermissionTuple>,
    pub requirements: Vec<SecurityPredicate>,
    #[serde(default)]
    pub approvals: Vec<ApprovalRule>,
    #[serde(default)]
    pub budgets: Vec<Budget>,
}

/// Whether a request came from a template, a tool or a user. All three are untrusted
/// requests that V01 validates and resolves alike: a request is never a grant, whoever
/// wrote it (VM-P47; VM-W37 "user-authored declarations cannot grant themselves
/// authority").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    Template,
    Tool,
    /// A request a user wrote, such as a user-authored template or tool declaration.
    User,
}

impl SourceKind {
    /// The stable tag in canonical encodings.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Template => "template",
            Self::Tool => "tool",
            Self::User => "user",
        }
    }
}

/// The template, tool or user that made a request; recorded for display, never trusted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestSource {
    pub kind: SourceKind,
    pub name: SourceName,
}

/// A template's or tool's policy request as read (untrusted input; VM-P47).
///
/// Requirement names and the legacy tier are text, so an unknown one is refused by the
/// validator with its name rather than ignored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestDocument {
    pub schema_version: u32,
    pub source: RequestSource,
    pub requested: Vec<PermissionTuple>,
    /// The essential subset of `requested`: planning refuses unless all are permitted.
    #[serde(default)]
    pub dependencies: Vec<PermissionTuple>,
    /// Required predicate names, such as `vm_sandbox`.
    #[serde(default)]
    pub requires: Vec<String>,
    /// An old manifest's isolation tier, `T1`–`T4`.
    #[serde(default)]
    pub legacy_tier: Option<String>,
    #[serde(default)]
    pub approvals: Vec<ApprovalRule>,
    #[serde(default)]
    pub budgets: Vec<Budget>,
}

/// A user's delegation as written by the host's delegation flow.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DelegationDraft {
    pub granted: Vec<PermissionTuple>,
    #[serde(default)]
    pub approvals: Vec<ApprovalRule>,
    #[serde(default)]
    pub budgets: Vec<Budget>,
}

/// A validated product policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProductPolicy {
    policy_epoch: PolicyEpoch,
    ceiling: PermissionSet,
    requirements: RequirementSet,
    approvals: ApprovalSet,
    budgets: BudgetSet,
}

impl ProductPolicy {
    pub(super) fn validated(
        policy_epoch: PolicyEpoch,
        ceiling: PermissionSet,
        requirements: RequirementSet,
        approvals: ApprovalSet,
        budgets: BudgetSet,
    ) -> Self {
        Self {
            policy_epoch,
            ceiling,
            requirements,
            approvals,
            budgets,
        }
    }

    pub fn policy_epoch(&self) -> PolicyEpoch {
        self.policy_epoch
    }

    pub fn ceiling(&self) -> &PermissionSet {
        &self.ceiling
    }

    pub fn requirements(&self) -> &RequirementSet {
        &self.requirements
    }

    pub fn approvals(&self) -> &ApprovalSet {
        &self.approvals
    }

    pub fn budgets(&self) -> &BudgetSet {
        &self.budgets
    }
}

/// A validated workload request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkloadRequest {
    source: RequestSource,
    requested: PermissionSet,
    dependencies: PermissionSet,
    requirements: RequirementSet,
    approvals: ApprovalSet,
    budgets: BudgetSet,
}

impl WorkloadRequest {
    pub(super) fn validated(
        source: RequestSource,
        requested: PermissionSet,
        dependencies: PermissionSet,
        requirements: RequirementSet,
        approvals: ApprovalSet,
        budgets: BudgetSet,
    ) -> Self {
        Self {
            source,
            requested,
            dependencies,
            requirements,
            approvals,
            budgets,
        }
    }

    pub fn source(&self) -> &RequestSource {
        &self.source
    }

    pub fn requested(&self) -> &PermissionSet {
        &self.requested
    }

    pub fn dependencies(&self) -> &PermissionSet {
        &self.dependencies
    }

    /// The request's own predicates, including those its legacy tier migrated to.
    pub fn requirements(&self) -> &RequirementSet {
        &self.requirements
    }

    pub fn approvals(&self) -> &ApprovalSet {
        &self.approvals
    }

    pub fn budgets(&self) -> &BudgetSet {
        &self.budgets
    }

    /// The canonical identity of the request; the order its document listed tuples,
    /// requirements, approvals or budgets in does not change it.
    pub fn identity(&self) -> RequestIdentity {
        request_identity(&RequestParts {
            source: &self.source,
            requested: &self.requested,
            dependencies: &self.dependencies,
            requirements: &self.requirements,
            approvals: &self.approvals,
            budgets: &self.budgets,
        })
    }
}

/// A validated delegation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Delegation {
    granted: PermissionSet,
    approvals: ApprovalSet,
    budgets: BudgetSet,
}

impl Delegation {
    pub(super) fn validated(
        granted: PermissionSet,
        approvals: ApprovalSet,
        budgets: BudgetSet,
    ) -> Self {
        Self {
            granted,
            approvals,
            budgets,
        }
    }

    pub fn granted(&self) -> &PermissionSet {
        &self.granted
    }

    pub fn approvals(&self) -> &ApprovalSet {
        &self.approvals
    }

    pub fn budgets(&self) -> &BudgetSet {
        &self.budgets
    }
}
