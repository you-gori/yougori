//! Non-interactive runs (VM-W54 acceptance: "noninteractive runs fail safely on missing
//! authorization"; VM-P46).
//!
//! A non-interactive run cannot ask, so it proceeds only with a launch plan, every
//! required authority delegated and every applicable required approval already covered
//! by a valid grant at the run's authorization epoch. Anything else refuses with codes.
//! There is no prompt outcome. A valid narrow grant is reused rather than asked for
//! again (VM-P46). An exact-release grant covers only the payload digest it names; the
//! runtime evaluator still compares that digest with the actual release, so this check
//! does not approve any other payload.

use serde::{Deserialize, Serialize};

use super::pipeline::LaunchOutcome;
use super::preview::{ApprovalLine, ApprovalStatus};
use super::refusal::{RefusalDetail, RefusalReport};
use crate::foundation::ids::AuthorizationEpoch;
use crate::sandbox_contract::policy::{
    ApprovalGrant, ContractIdentity, PolicyLayer, ResolvedPolicy,
};

/// What a non-interactive run does: proceed or refuse. It never prompts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NonInteractiveDecision {
    Proceed { contract: ContractIdentity },
    Refuse { report: RefusalReport },
}

/// Each required approval of the resolved contract with its status: not applicable when
/// its operation and resource are not permitted, granted when a valid grant at `epoch`
/// covers it, needed otherwise. Shared by the preview and the non-interactive decision.
pub fn approval_status(
    resolved: &ResolvedPolicy,
    grants: &[ApprovalGrant],
    epoch: Option<AuthorizationEpoch>,
) -> Vec<ApprovalLine> {
    resolved
        .approvals()
        .iter()
        .map(|rule| {
            let applies = resolved
                .permitted()
                .iter()
                .any(|tuple| tuple.operation == rule.operation && tuple.resource == rule.resource);
            let granted = epoch.is_some_and(|epoch| {
                grants
                    .iter()
                    .any(|grant| grant.satisfies(rule, epoch, grant.payload.as_ref()))
            });
            let status = match (applies, granted) {
                (false, _) => ApprovalStatus::NotApplicable,
                (true, true) => ApprovalStatus::Granted,
                (true, false) => ApprovalStatus::Needed,
            };
            ApprovalLine {
                rule: rule.clone(),
                status,
            }
        })
        .collect()
}

/// Decides a non-interactive run. Refusals, in order: the launch refusal's own reasons
/// (or `launch_not_planned`), `authorization_missing` for each required authority the
/// delegation does not grant, and `approval_required` for each needed approval.
pub fn decide_non_interactive(
    outcome: LaunchOutcome<'_>,
    grants: &[ApprovalGrant],
    epoch: AuthorizationEpoch,
) -> NonInteractiveDecision {
    let resolved = outcome.resolved();
    let mut details = Vec::new();
    match (outcome.plan(), outcome.refusal()) {
        (Some(_), _) => {}
        (None, Some(refusal)) => {
            details.extend(refusal.reasons.iter().cloned().map(RefusalDetail::from))
        }
        (None, None) => details.push(RefusalDetail::LaunchNotPlanned),
    }
    for removed in resolved.missing_dependencies() {
        if removed.excluded_by.contains(&PolicyLayer::Delegation) {
            details.push(RefusalDetail::AuthorizationMissing {
                tuple: removed.tuple.clone(),
            });
        }
    }
    for line in approval_status(resolved, grants, Some(epoch)) {
        if line.status == ApprovalStatus::Needed {
            details.push(RefusalDetail::ApprovalRequired { rule: line.rule });
        }
    }
    match (RefusalReport::from_details(details), outcome.plan()) {
        (None, Some(plan)) => NonInteractiveDecision::Proceed {
            contract: plan.contract(),
        },
        (Some(report), _) => NonInteractiveDecision::Refuse { report },
        (None, None) => NonInteractiveDecision::Refuse {
            report: RefusalReport::single(RefusalDetail::LaunchNotPlanned),
        },
    }
}
