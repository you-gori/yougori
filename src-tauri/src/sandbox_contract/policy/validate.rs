//! Static validation (VM part §2.4 line 1804; VM-W02): well-formedness, permission
//! containment and supported combinations. It runs before resolution and reads no
//! evidence; runtime authorization is a separate step ([`Evaluator`](super::Evaluator)).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::approval::{ApprovalRule, ApprovalSet};
use super::budget::{AccountingScope, Budget, BudgetKey, BudgetResource, BudgetSet};
use super::layers::{
    ContractSchemaVersion, Delegation, DelegationDraft, PolicyLayer, ProductPolicy,
    ProductPolicyDraft, RequestDocument, WorkloadRequest,
};
use super::predicate::{LegacyTier, MigrationRefusal, RequirementSet, SecurityPredicate};
use super::tuple::{GenerationScope, PermissionSet, PermissionTuple};

strict_policy_enum! {
    /// One reason a layer or a combination of layers is not valid.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ValidationIssue tag "issue" {
        /// The document could not be read, including any unknown field or operation kind.
        Malformed { message: String },
        /// The document's contract schema version is not the one this build reads.
        UnsupportedSchemaVersion { found: u32 },
        /// A required predicate this build does not know (VM-P47: unknown required
        /// capabilities fail).
        UnknownRequirement { name: String },
        /// The old isolation tier could not be migrated (VM-W01).
        LegacyTierRefused { refusal: MigrationRefusal },
        /// Only a delegation may bind an authorization epoch.
        GenerationBoundInLayer { layer: PolicyLayer, tuple: PermissionTuple },
        /// The operation does not apply to the resource's kind.
        OperationOnWrongResource { layer: PolicyLayer, tuple: PermissionTuple },
        /// The approval kind does not fit the operation, or the operation the resource.
        ApprovalDoesNotFit { layer: PolicyLayer, rule: ApprovalRule },
        /// One layer lists a budget key twice.
        DuplicateBudget { layer: PolicyLayer, key: BudgetKey },
        /// An essential dependency the request does not itself request.
        DependencyNotRequested { tuple: PermissionTuple },
        /// A product policy for sandboxes that does not require a VM sandbox (VM-W01: no
        /// shared-kernel production sandbox option).
        ProductionSandboxWithoutVm,
        /// The ceiling permits an outbound channel without a release-bytes budget per
        /// generation (§2.2: an enforced budget with all channels declared).
        OutboundWithoutReleaseBudget { tuple: PermissionTuple },
        /// The ceiling permits delivering an external credential into the guest, and no
        /// short-lived-credential effects budget applies to that credential (§4.5: a
        /// short-lived external capability has its "delegated budget explicit"). A budget
        /// applies when its accounting scope covers the credential: a channel on that
        /// credential, or the generation, execution or tenant. Signed download URLs are
        /// delivered by the same operation and are bounded the same way: they are bearer
        /// capabilities and still credentials.
        CredentialWithoutDelegatedBudget { tuple: PermissionTuple },
        /// A layer permits what one of its own, or the product's, contract predicates
        /// forbids.
        ContractConflict {
            layer: PolicyLayer,
            predicate: SecurityPredicate,
            tuple: PermissionTuple,
        },
        /// A layer requires a contract predicate whose budget it does not declare.
        ContractBudgetMissing {
            layer: PolicyLayer,
            predicate: SecurityPredicate,
            key: BudgetKey,
        },
        /// An essential dependency lies outside another layer (permission containment);
        /// planning would refuse it.
        DependencyOutsideLayer { layer: PolicyLayer, tuple: PermissionTuple },
    }
}

impl fmt::Display for ValidationIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { message } => write!(f, "the document is malformed: {message}"),
            Self::UnsupportedSchemaVersion { found } => write!(
                f,
                "contract schema version {found} is not supported; host policy stays in force"
            ),
            Self::UnknownRequirement { name } => write!(
                f,
                "required capability {name:?} is unknown, and an unknown requirement is never \
                 ignored"
            ),
            Self::LegacyTierRefused { refusal } => write!(f, "{refusal}"),
            Self::GenerationBoundInLayer { layer, tuple } => write!(
                f,
                "{layer} binds a generation ({tuple}); only a delegation may bind one"
            ),
            Self::OperationOnWrongResource { layer, tuple } => write!(
                f,
                "{layer} lists an operation that does not apply to its resource: {tuple}"
            ),
            Self::ApprovalDoesNotFit { layer, rule } => {
                write!(
                    f,
                    "{layer} lists an approval rule that cannot apply: {rule}"
                )
            }
            Self::DuplicateBudget { layer, key } => {
                write!(f, "{layer} lists the budget for {key} twice")
            }
            Self::DependencyNotRequested { tuple } => write!(
                f,
                "the request lists a dependency it does not request: {tuple}"
            ),
            Self::ProductionSandboxWithoutVm => f.write_str(
                "a sandbox product policy must require a VM sandbox; there is no shared-kernel \
                 sandbox option",
            ),
            Self::OutboundWithoutReleaseBudget { tuple } => write!(
                f,
                "the product ceiling permits an outbound channel without a release-bytes \
                 budget per generation: {tuple}"
            ),
            Self::CredentialWithoutDelegatedBudget { tuple } => write!(
                f,
                "the product ceiling permits delivering an external credential without a \
                 delegated budget of short-lived credential effects that applies to it: {tuple}"
            ),
            Self::ContractConflict {
                layer,
                predicate,
                tuple,
            } => write!(
                f,
                "{layer} permits {tuple}, which the required {predicate} forbids"
            ),
            Self::ContractBudgetMissing {
                layer,
                predicate,
                key,
            } => write!(
                f,
                "{layer} requires {predicate} but declares no budget for {key}"
            ),
            Self::DependencyOutsideLayer { layer, tuple } => write!(
                f,
                "the request depends on {tuple}, which {layer} does not permit"
            ),
        }
    }
}

/// Every issue found, in the order checked; never empty.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ValidationRefusal {
    pub issues: Vec<ValidationIssue>,
}

impl ValidationRefusal {
    fn check(issues: Vec<ValidationIssue>) -> Result<(), Self> {
        if issues.is_empty() {
            Ok(())
        } else {
            Err(Self { issues })
        }
    }
}

impl fmt::Display for ValidationRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, issue) in self.issues.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{issue}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ValidationRefusal {}

/// The static validator (VM-W02). It is separate from the evaluator and the evidence
/// checker, and the validated layer types can be made only through it.
pub struct Validator;

impl Validator {
    /// Validates the host product's policy.
    pub fn product(draft: &ProductPolicyDraft) -> Result<ProductPolicy, ValidationRefusal> {
        let layer = PolicyLayer::ProductCeiling;
        let mut issues = Vec::new();
        for tuple in &draft.ceiling {
            check_tuple(layer, tuple, false, &mut issues);
        }
        let requirements = RequirementSet::new(draft.requirements.iter().copied());
        if !requirements.contains(SecurityPredicate::VmSandbox) {
            issues.push(ValidationIssue::ProductionSandboxWithoutVm);
        }
        check_rules(layer, &draft.approvals, &mut issues);
        let budgets = budget_set(layer, &draft.budgets, &mut issues);
        let ceiling = PermissionSet::new(draft.ceiling.iter().cloned());
        let release = BudgetKey {
            resource: BudgetResource::ReleaseBytes,
            scope: AccountingScope::Generation,
        };
        if budgets.limit(&release).is_none() {
            for tuple in ceiling.iter().filter(|tuple| tuple.operation.is_outbound()) {
                issues.push(ValidationIssue::OutboundWithoutReleaseBudget { tuple });
            }
        }
        let delegated = BudgetResource::ShortLivedCredentialEffects;
        for tuple in ceiling
            .iter()
            .filter(|tuple| tuple.operation.consumes(delegated))
        {
            let bounded = budgets
                .iter()
                .any(|(key, _)| key.resource == delegated && key.scope.applies_to(&tuple.resource));
            if !bounded {
                issues.push(ValidationIssue::CredentialWithoutDelegatedBudget { tuple });
            }
        }
        contract_conflicts(layer, &requirements, &ceiling, &mut issues);
        for predicate in requirements.iter() {
            if let Some(constraint) = predicate.contract_constraint() {
                for key in constraint.required_budgets() {
                    if budgets.limit(&key).is_none() {
                        issues.push(ValidationIssue::ContractBudgetMissing {
                            layer,
                            predicate,
                            key,
                        });
                    }
                }
            }
        }
        ValidationRefusal::check(issues)?;
        Ok(ProductPolicy::validated(
            draft.policy_epoch,
            ceiling,
            requirements,
            ApprovalSet::new(draft.approvals.iter().cloned()),
            budgets,
        ))
    }

    /// Reads and validates an untrusted request (VM-P47).
    pub fn request_json(text: &str) -> Result<WorkloadRequest, ValidationRefusal> {
        let document: RequestDocument =
            serde_json::from_str(text).map_err(|error| ValidationRefusal {
                issues: vec![ValidationIssue::Malformed {
                    message: error.to_string(),
                }],
            })?;
        Self::request(&document)
    }

    /// Validates an untrusted request (VM-P47): an unknown schema version, requirement
    /// or tier is refused by name, and nothing in it can lower host policy, which is
    /// applied later by intersection and union.
    pub fn request(document: &RequestDocument) -> Result<WorkloadRequest, ValidationRefusal> {
        let layer = PolicyLayer::Request;
        let mut issues = Vec::new();
        if let Err(unsupported) = ContractSchemaVersion::try_from(document.schema_version) {
            issues.push(ValidationIssue::UnsupportedSchemaVersion {
                found: unsupported.found,
            });
        }
        let mut predicates = BTreeSet::new();
        for name in &document.requires {
            match SecurityPredicate::from_name(name) {
                Some(predicate) => {
                    predicates.insert(predicate);
                }
                None => issues.push(ValidationIssue::UnknownRequirement { name: name.clone() }),
            }
        }
        let mut requirements = RequirementSet::new(predicates);
        if let Some(name) = &document.legacy_tier {
            match LegacyTier::parse(name).and_then(LegacyTier::migrate) {
                Ok(migrated) => requirements = requirements.union(&migrated),
                Err(refusal) => issues.push(ValidationIssue::LegacyTierRefused { refusal }),
            }
        }
        for tuple in document.requested.iter().chain(&document.dependencies) {
            check_tuple(layer, tuple, false, &mut issues);
        }
        let requested = PermissionSet::new(document.requested.iter().cloned());
        let dependencies = PermissionSet::new(document.dependencies.iter().cloned());
        for tuple in dependencies.iter() {
            if !requested.covers(&tuple) {
                issues.push(ValidationIssue::DependencyNotRequested { tuple });
            }
        }
        check_rules(layer, &document.approvals, &mut issues);
        let budgets = budget_set(layer, &document.budgets, &mut issues);
        contract_conflicts(layer, &requirements, &requested, &mut issues);
        ValidationRefusal::check(issues)?;
        Ok(WorkloadRequest::validated(
            document.source.clone(),
            requested,
            dependencies,
            requirements,
            ApprovalSet::new(document.approvals.iter().cloned()),
            budgets,
        ))
    }

    /// Validates a delegation; only a delegation may bind an authorization epoch.
    pub fn delegation(draft: &DelegationDraft) -> Result<Delegation, ValidationRefusal> {
        let layer = PolicyLayer::Delegation;
        let mut issues = Vec::new();
        for tuple in &draft.granted {
            check_tuple(layer, tuple, true, &mut issues);
        }
        check_rules(layer, &draft.approvals, &mut issues);
        let budgets = budget_set(layer, &draft.budgets, &mut issues);
        ValidationRefusal::check(issues)?;
        Ok(Delegation::validated(
            PermissionSet::new(draft.granted.iter().cloned()),
            ApprovalSet::new(draft.approvals.iter().cloned()),
            budgets,
        ))
    }

    /// Cross-layer checks: every essential dependency lies inside the product ceiling
    /// and the delegation (permission containment), and none violates a product contract
    /// predicate (supported combinations). Planning reaches the same verdict; this
    /// reports it before anything is resolved.
    pub fn combination(
        product: &ProductPolicy,
        request: &WorkloadRequest,
        delegation: &Delegation,
    ) -> Result<(), ValidationRefusal> {
        let mut issues = Vec::new();
        for tuple in request.dependencies().iter() {
            if !product.ceiling().covers(&tuple) {
                issues.push(ValidationIssue::DependencyOutsideLayer {
                    layer: PolicyLayer::ProductCeiling,
                    tuple: tuple.clone(),
                });
            }
            if !delegation.granted().covers(&tuple) {
                issues.push(ValidationIssue::DependencyOutsideLayer {
                    layer: PolicyLayer::Delegation,
                    tuple,
                });
            }
        }
        contract_conflicts(
            PolicyLayer::Request,
            product.requirements(),
            request.dependencies(),
            &mut issues,
        );
        ValidationRefusal::check(issues)
    }
}

fn check_tuple(
    layer: PolicyLayer,
    tuple: &PermissionTuple,
    may_bind_generation: bool,
    issues: &mut Vec<ValidationIssue>,
) {
    if !may_bind_generation && tuple.generation != GenerationScope::EveryGeneration {
        issues.push(ValidationIssue::GenerationBoundInLayer {
            layer,
            tuple: tuple.clone(),
        });
    }
    if !tuple.is_well_typed() {
        issues.push(ValidationIssue::OperationOnWrongResource {
            layer,
            tuple: tuple.clone(),
        });
    }
}

fn check_rules(layer: PolicyLayer, rules: &[ApprovalRule], issues: &mut Vec<ValidationIssue>) {
    for rule in rules.iter().filter(|rule| !rule.is_well_formed()) {
        issues.push(ValidationIssue::ApprovalDoesNotFit {
            layer,
            rule: rule.clone(),
        });
    }
}

fn budget_set(
    layer: PolicyLayer,
    budgets: &[Budget],
    issues: &mut Vec<ValidationIssue>,
) -> BudgetSet {
    let mut seen = BTreeSet::new();
    let mut repeated = false;
    for budget in budgets {
        let key = budget.key();
        if !seen.insert(key.clone()) {
            repeated = true;
            issues.push(ValidationIssue::DuplicateBudget { layer, key });
        }
    }
    if repeated {
        return BudgetSet::default();
    }
    BudgetSet::new(budgets.iter().cloned()).unwrap_or_default()
}

fn contract_conflicts(
    layer: PolicyLayer,
    requirements: &RequirementSet,
    permitted: &PermissionSet,
    issues: &mut Vec<ValidationIssue>,
) {
    for predicate in requirements.iter() {
        let Some(constraint) = predicate.contract_constraint() else {
            continue;
        };
        for tuple in permitted
            .iter()
            .filter(|tuple| constraint.forbids(&tuple.operation))
        {
            issues.push(ValidationIssue::ContractConflict {
                layer,
                predicate,
                tuple,
            });
        }
    }
}
