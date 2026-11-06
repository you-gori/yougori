//! Policy resolution (VM part §2.4 lines 1795–1802; §12.3 model 1).
//!
//! ```text
//! permitted           = product_ceiling ∩ requested ∩ delegated
//! required_properties = product_requirements ∪ workload_requirements
//! required_approvals  = product ∪ request ∪ delegation approvals
//! budgets             = per (resource, scope): the minimum over the layers naming it
//! ```
//!
//! Resolution reads no evidence, so no observation can change what is required.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::approval::ApprovalSet;
use super::budget::BudgetSet;
use super::identity::{contract_identity, ContractIdentity, ContractParts};
use super::layers::{
    ContractSchemaVersion, Delegation, PolicyLayer, ProductPolicy, RequestSource, WorkloadRequest,
};
use super::predicate::RequirementSet;
use super::tuple::{PermissionSet, PermissionTuple};
use crate::foundation::ids::PolicyEpoch;

/// A requested tuple the intersection does not permit at every generation, with every
/// layer that does not cover it. A delegation bound to one epoch leaves the tuple here,
/// because a launch's authorization epoch is assigned only at boot (CORE-04).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedPermission {
    pub tuple: PermissionTuple,
    pub excluded_by: BTreeSet<PolicyLayer>,
    /// Whether the workload listed it as an essential dependency.
    pub essential: bool,
}

impl fmt::Display for RemovedPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} is not permitted by ", self.tuple)?;
        for (index, layer) in self.excluded_by.iter().enumerate() {
            if index > 0 {
                f.write_str(" or ")?;
            }
            write!(f, "{layer}")?;
        }
        Ok(())
    }
}

/// The resolved contract for one launch. Only [`resolve`] makes one; it cannot be read
/// back from untrusted data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ResolvedPolicy {
    schema_version: ContractSchemaVersion,
    policy_epoch: PolicyEpoch,
    source: RequestSource,
    permitted: PermissionSet,
    dependencies: PermissionSet,
    requirements: RequirementSet,
    approvals: ApprovalSet,
    budgets: BudgetSet,
    removed: Vec<RemovedPermission>,
}

/// Applies the §2.4 algebra to three validated layers.
pub fn resolve(
    product: &ProductPolicy,
    request: &WorkloadRequest,
    delegation: &Delegation,
) -> ResolvedPolicy {
    let permitted = product
        .ceiling()
        .intersection(request.requested())
        .intersection(delegation.granted());
    let removed = request
        .requested()
        .iter()
        .filter(|tuple| !permitted.covers(tuple))
        .map(|tuple| {
            let excluded_by = excluding_layers(&tuple, product, request, delegation);
            let essential = request.dependencies().covers(&tuple);
            RemovedPermission {
                tuple,
                excluded_by,
                essential,
            }
        })
        .collect();
    ResolvedPolicy {
        schema_version: ContractSchemaVersion::CURRENT,
        policy_epoch: product.policy_epoch(),
        source: request.source().clone(),
        requirements: product.requirements().union(request.requirements()),
        approvals: product
            .approvals()
            .union(request.approvals())
            .union(delegation.approvals()),
        budgets: product
            .budgets()
            .compose(request.budgets())
            .compose(delegation.budgets()),
        dependencies: request.dependencies().clone(),
        permitted,
        removed,
    }
}

fn excluding_layers(
    tuple: &PermissionTuple,
    product: &ProductPolicy,
    request: &WorkloadRequest,
    delegation: &Delegation,
) -> BTreeSet<PolicyLayer> {
    [
        (PolicyLayer::ProductCeiling, product.ceiling()),
        (PolicyLayer::Request, request.requested()),
        (PolicyLayer::Delegation, delegation.granted()),
    ]
    .into_iter()
    .filter(|(_, set)| !set.covers(tuple))
    .map(|(layer, _)| layer)
    .collect()
}

impl ResolvedPolicy {
    pub fn schema_version(&self) -> ContractSchemaVersion {
        self.schema_version
    }

    /// The product policy epoch the contract was resolved under.
    pub fn policy_epoch(&self) -> PolicyEpoch {
        self.policy_epoch
    }

    pub fn source(&self) -> &RequestSource {
        &self.source
    }

    /// `product_ceiling ∩ requested ∩ delegated`.
    pub fn permitted(&self) -> &PermissionSet {
        &self.permitted
    }

    /// The workload's essential dependencies.
    pub fn dependencies(&self) -> &PermissionSet {
        &self.dependencies
    }

    /// `product_requirements ∪ workload_requirements`.
    pub fn requirements(&self) -> &RequirementSet {
        &self.requirements
    }

    /// Every layer's required approvals.
    pub fn approvals(&self) -> &ApprovalSet {
        &self.approvals
    }

    /// Minima per resource and scope.
    pub fn budgets(&self) -> &BudgetSet {
        &self.budgets
    }

    /// Every requested tuple the intersection removed, essential or not, so nothing is
    /// dropped silently.
    pub fn removed(&self) -> &[RemovedPermission] {
        &self.removed
    }

    /// The essential dependencies the intersection removed; planning refuses while any
    /// remain (VM §2.4 line 1800).
    pub fn missing_dependencies(&self) -> impl Iterator<Item = &RemovedPermission> {
        self.removed.iter().filter(|removed| removed.essential)
    }

    /// The canonical identity of the contract; the request's source is provenance and
    /// is not part of it.
    pub fn identity(&self) -> ContractIdentity {
        contract_identity(&ContractParts {
            schema_version: self.schema_version,
            policy_epoch: self.policy_epoch,
            permitted: &self.permitted,
            dependencies: &self.dependencies,
            requirements: &self.requirements,
            approvals: &self.approvals,
            budgets: &self.budgets,
        })
    }
}
