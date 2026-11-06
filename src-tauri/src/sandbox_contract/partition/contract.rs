//! Explicit release contracts (VM part §9.1: "data crossing a boundary uses an explicit
//! release contract"; line 2327 "an exact release operation"; line 2330: approval is not a
//! proof of confidentiality).

use std::fmt;

use serde::{Deserialize, Serialize};

use super::names::{ContractId, DataId, LabelTag, StepId};

strict_tagged_enum! {
/// Where a contract lets one item go.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContractDestination (tag = "destination", wire = ContractDestinationWire, wire_name = "ContractDestinationWire") {
    /// Into the compartment that runs this step, whichever the compiler chooses.
    Step { step: StepId },
    /// One specific external target, such as a repository and branch (line 2327).
    External { target: LabelTag },
    /// The unrestricted public output (§12.3 model 6): a declared broad release.
    Public,
}
}

impl fmt::Display for ContractDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Step { step } => write!(f, "step {step}"),
            Self::External { target } => write!(f, "external target {target}"),
            Self::Public => f.write_str("the public output"),
        }
    }
}

strict_tagged_enum! {
/// Who authorized a contract. Either way the approval authorizes the release; it never
/// shows that the released data is free of private content (line 2330).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Approval (tag = "approval", wire = ApprovalWire, wire_name = "ApprovalWire") {
    /// A rule of the user's or delegation policy authorized it in advance.
    PolicyPreauthorized { rule: LabelTag },
    /// An operator approved it: an operator-visible approval (line 2308).
    Operator { reviewer: LabelTag },
}
}

impl Approval {
    /// Whether it counts as an operator-visible approval in the §9.1 objective.
    pub fn is_operator(&self) -> bool {
        matches!(self, Self::Operator { .. })
    }

    /// What the approval says about confidentiality: nothing (line 2330).
    pub fn confidentiality(&self) -> ConfidentialityStatus {
        ConfidentialityStatus::NotProven
    }
}

impl fmt::Display for Approval {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PolicyPreauthorized { rule } => write!(f, "policy rule {rule}"),
            Self::Operator { reviewer } => write!(f, "operator {reviewer}"),
        }
    }
}

/// The confidentiality status of released data. There is deliberately no "proven"
/// variant: a release contract and a human approval authorize a release, and are never a
/// mathematical proof of confidentiality (line 2330).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfidentialityStatus {
    NotProven,
}

/// One explicit release contract: exactly one item, to exactly one destination, up to a
/// byte bound, under a named approval (line 2314, line 2327).
///
/// A contract moves an item; it never lowers the item's label, so private data stays
/// labelled private after crossing (line 2320). An external contract binds the exact
/// content of the immutable artifact when the release is approved
/// ([`super::PartitionRun::bind_release`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseContract {
    pub id: ContractId,
    pub item: DataId,
    pub destination: ContractDestination,
    pub approval: Approval,
    pub max_bytes: u64,
}

impl ReleaseContract {
    /// Whether the item leaves the host: to an external target or the public output.
    pub fn is_external(&self) -> bool {
        !matches!(self.destination, ContractDestination::Step { .. })
    }

    /// The consuming step of an internal contract.
    pub fn destination_step(&self) -> Option<&StepId> {
        match &self.destination {
            ContractDestination::Step { step } => Some(step),
            _ => None,
        }
    }
}
