//! Required approvals (VM part §2.4 line 1802; VM-P46).
//!
//! Required approvals accumulate: every layer's rules are kept, because intersecting
//! approval-rule sets could remove a required approval. [`ApprovalSet`] therefore has a
//! union and no intersection. An existing scoped grant satisfies a rule for as long as it
//! is valid, so a valid narrow grant is not asked for again (§0.2; VM-P46).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::tuple::{Operation, ResourceRef};
use crate::foundation::ids::{AuthorizationEpoch, Digest};

/// What an approval is for; users can tell the three apart (VM-P46).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalKind {
    /// Access to private data.
    PrivateDataAccess,
    /// Ongoing delegation of an operation for the generation.
    OngoingDelegation,
    /// One exact release: bound to the payload digest and used once.
    ExactRelease,
}

impl ApprovalKind {
    /// The stable tag in canonical encodings.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::PrivateDataAccess => "private_data_access",
            Self::OngoingDelegation => "ongoing_delegation",
            Self::ExactRelease => "exact_release",
        }
    }

    /// Whether the kind can apply to `operation`: an exact release binds one payload, so
    /// it applies only to the operations with an exact external effect.
    pub fn fits(self, operation: &Operation) -> bool {
        match self {
            Self::ExactRelease => matches!(
                operation,
                Operation::Release | Operation::ProviderOperation { .. }
            ),
            Self::PrivateDataAccess | Self::OngoingDelegation => true,
        }
    }
}

impl fmt::Display for ApprovalKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PrivateDataAccess => "private-data access",
            Self::OngoingDelegation => "ongoing delegation",
            Self::ExactRelease => "exact release",
        })
    }
}

/// "This operation on this resource needs an approval of this kind."
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalRule {
    pub kind: ApprovalKind,
    pub operation: Operation,
    pub resource: ResourceRef,
}

impl ApprovalRule {
    /// Whether the kind fits the operation and the operation fits the resource.
    pub fn is_well_formed(&self) -> bool {
        self.kind.fits(&self.operation) && self.operation.resource_kind() == self.resource.kind
    }
}

impl fmt::Display for ApprovalRule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} approval to {} {}",
            self.kind, self.operation, self.resource
        )
    }
}

/// Required approval rules, accumulated across layers (VM §2.4).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "Vec<ApprovalRule>", into = "Vec<ApprovalRule>")]
pub struct ApprovalSet {
    rules: BTreeSet<ApprovalRule>,
}

impl ApprovalSet {
    pub fn new(rules: impl IntoIterator<Item = ApprovalRule>) -> Self {
        Self {
            rules: rules.into_iter().collect(),
        }
    }

    /// Every rule of both sets. This is the only way approval sets combine.
    pub fn union(&self, other: &Self) -> Self {
        Self {
            rules: self.rules.union(&other.rules).cloned().collect(),
        }
    }

    pub fn contains(&self, rule: &ApprovalRule) -> bool {
        self.rules.contains(rule)
    }

    pub fn is_subset(&self, other: &Self) -> bool {
        self.rules.is_subset(&other.rules)
    }

    /// The rules that apply to `operation` on `resource`.
    pub fn rules_for<'a>(
        &'a self,
        operation: &'a Operation,
        resource: &'a ResourceRef,
    ) -> impl Iterator<Item = &'a ApprovalRule> + 'a {
        self.rules
            .iter()
            .filter(move |rule| rule.operation == *operation && rule.resource == *resource)
    }

    pub fn iter(&self) -> impl Iterator<Item = &ApprovalRule> {
        self.rules.iter()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl From<Vec<ApprovalRule>> for ApprovalSet {
    fn from(rules: Vec<ApprovalRule>) -> Self {
        Self::new(rules)
    }
}

impl From<ApprovalSet> for Vec<ApprovalRule> {
    fn from(set: ApprovalSet) -> Self {
        set.rules.into_iter().collect()
    }
}

/// An approval the user gave, recorded by the host's approval flow, never by the guest.
///
/// It is valid only at its authorization epoch, so revocation, recovery or a new boot
/// ends it. An exact-release grant names the payload digest it approved and is used once.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalGrant {
    pub rule: ApprovalRule,
    pub epoch: AuthorizationEpoch,
    /// The approved payload; required for an exact release, absent otherwise.
    pub payload: Option<Digest>,
}

impl ApprovalGrant {
    /// Whether the grant has the shape its kind needs: a payload exactly when it approves
    /// an exact release.
    pub fn is_well_formed(&self) -> bool {
        self.rule.is_well_formed()
            && (self.rule.kind == ApprovalKind::ExactRelease) == self.payload.is_some()
    }

    /// Whether it satisfies `rule` at `epoch` for a request carrying `payload`.
    pub fn satisfies(
        &self,
        rule: &ApprovalRule,
        epoch: AuthorizationEpoch,
        payload: Option<&Digest>,
    ) -> bool {
        if self.rule != *rule || self.epoch != epoch || !self.is_well_formed() {
            return false;
        }
        match rule.kind {
            ApprovalKind::ExactRelease => self.payload.as_ref() == payload && payload.is_some(),
            ApprovalKind::PrivateDataAccess | ApprovalKind::OngoingDelegation => true,
        }
    }
}
