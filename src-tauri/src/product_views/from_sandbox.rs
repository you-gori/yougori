//! A launched sandbox's facts, permissions, policy refusals and isolation tiers in the
//! CORE-07 contract's shapes (VM-W04, VM-W53, VM-W54, VM-W01; VM part §1.3).
//!
//! V17 already labels each fact observed, asserted, verified or unavailable at the moment
//! a view is shown (`ShownView`, from `SandboxView::status_at`) and groups the facts into
//! four fixed sections. These conversions keep V17's sections, fact wording and remedies:
//! each label becomes the one contract [`Evidence`] state, each unavailable reason a
//! [`Refusal`] with V17's own CORE-01 remedy or V08 refusal code and V08's help as its
//! words. Nothing here relabels a fact. A V01 isolation tier is migrated by V01's own rule.

use crate::foundation::evidence::RuntimeRequirement;
use crate::foundation::evidence::SourceClass;
use crate::foundation::product::{
    Asserter, CapabilityLine, Evidence, EvidenceCode, IsolationTier, LegacyChoice, MigrationError,
    MigrationItem, MigrationOutcome, PermissionLine, PermissionStatus, PolicyCode, Refusal,
    RefusalCode, Remedy, SandboxEvidence, SandboxSection, ShownText, VerifiedBy,
};
use crate::sandbox::backend::ObservationProblem;
use crate::sandbox_contract::declarations::{ApprovalStatus, RefusalCode as V08Code};
use crate::sandbox_contract::policy::{LegacyTier, SecurityPredicate};
use crate::sandbox_contract::views::{
    AssertedBy, FactLabel, FactValue, Section, ShownLine, ShownView, Unavailability,
    VerifiedBy as ViewVerifiedBy, WhatToDo,
};

/// A V08 refusal code as the contract carries it. Every V08 code is snake_case and none
/// takes a product code, which the tests check; the fallback keeps the conversion total.
pub fn policy_code(code: V08Code) -> PolicyCode {
    PolicyCode::new(code.as_str()).unwrap_or_else(|_| PolicyCode::unrecognized())
}

/// A refusal with V08's code, `reason` and V08's help as the remedy's words.
pub fn policy_refusal(code: V08Code, reason: &str) -> Refusal {
    Refusal::with_words(
        RefusalCode::SandboxPolicy {
            code: policy_code(code),
        },
        reason,
        Remedy::SandboxPolicy {
            code: policy_code(code),
        },
        code.help(),
    )
}

impl From<Section> for SandboxSection {
    fn from(section: Section) -> Self {
        match section {
            Section::WhatRuns => Self::WhatRuns,
            Section::ReadsAndKeeps => Self::ReadsAndKeeps,
            Section::Releases => Self::Releases,
            Section::Unavailable => Self::Unavailable,
        }
    }
}

/// The evidence state of a V17 label: the host's current observation is observed, a
/// controlled check or host-probe evidence is verified, an assertion stays an assertion
/// by the same party, and an unavailable fact keeps V17's reason and remedy.
impl From<&FactLabel> for Evidence {
    fn from(label: &FactLabel) -> Self {
        match label {
            FactLabel::Observed {
                source,
                observed_at,
                fresh_until,
            } => Self::observed_by(*source, *observed_at, *fresh_until),
            FactLabel::Verified {
                by: ViewVerifiedBy::ControlledCheck,
                observed_at,
                fresh_until,
            } => Self::Verified {
                by: VerifiedBy::ControlledCheck,
                observed_at: *observed_at,
                fresh_until: *fresh_until,
            },
            FactLabel::Verified {
                by:
                    ViewVerifiedBy::Evidence {
                        capability,
                        source: SourceClass::HostProbe,
                    },
                observed_at,
                fresh_until,
            } => Self::Verified {
                by: VerifiedBy::HostProbe {
                    capability: *capability,
                },
                observed_at: *observed_at,
                fresh_until: *fresh_until,
            },
            FactLabel::Verified {
                by: ViewVerifiedBy::Evidence { source, .. },
                observed_at,
                fresh_until,
            } => Self::observed_by(*source, *observed_at, *fresh_until),
            FactLabel::Asserted { by, received_at } => Self::Asserted {
                by: asserter(*by),
                received_at: *received_at,
            },
            FactLabel::Unavailable { why, remedy } => Self::Unavailable {
                refusal: unavailable(why, remedy),
            },
        }
    }
}

fn asserter(by: AssertedBy) -> Asserter {
    match by {
        AssertedBy::Guest => Asserter::Guest,
        AssertedBy::LaunchRequest => Asserter::Request,
        AssertedBy::Declaration => Asserter::Declaration,
        AssertedBy::Contract => Asserter::Contract,
    }
}

/// V17's reason and remedy for an unavailable fact, as a refusal: V17's CORE-01 remedy, or
/// its V08 refusal code with V08's help as the words.
fn unavailable(why: &Unavailability, remedy: &WhatToDo) -> Refusal {
    let (remedy, words) = match *remedy {
        WhatToDo::Evidence { remedy } => {
            let remedy = Remedy::Evidence { step: remedy };
            let words = remedy.to_string();
            (remedy, words)
        }
        WhatToDo::Refusal { code } => (
            Remedy::SandboxPolicy {
                code: policy_code(code),
            },
            code.help().to_owned(),
        ),
    };
    let evidence = |code| RefusalCode::Evidence { code };
    let code = match why {
        Unavailability::NotObserved { .. } => evidence(EvidenceCode::NotObserved),
        Unavailability::OnlyGuestAsserted { .. } => evidence(EvidenceCode::OnlyGuestAsserted),
        Unavailability::NotCurrent {
            problem: ObservationProblem::OtherConfiguration { .. },
            ..
        } => evidence(EvidenceCode::ConfigurationChanged),
        Unavailability::NotCurrent {
            problem: ObservationProblem::Stale { .. },
            ..
        } => evidence(EvidenceCode::Stale),
        Unavailability::EvidenceRefused { refusal, .. } => Refusal::from(refusal).code,
        Unavailability::NotPermitted { .. } => match &remedy {
            Remedy::SandboxPolicy { code } => RefusalCode::SandboxPolicy { code: code.clone() },
            _ => RefusalCode::SandboxPolicy {
                code: policy_code(V08Code::RequiredAuthorityRemoved),
            },
        },
        Unavailability::Refused { code } => RefusalCode::SandboxPolicy {
            code: policy_code(*code),
        },
    };
    Refusal::with_words(code, &why.to_string(), remedy, &words)
}

impl From<&ShownLine> for CapabilityLine {
    fn from(line: &ShownLine) -> Self {
        Self::new(
            fact_kind(&line.fact),
            &line.fact.to_string(),
            Evidence::from(&line.label),
        )
    }
}

impl From<&ShownView> for SandboxEvidence {
    fn from(view: &ShownView) -> Self {
        let lines = |section: Section| {
            view.section(section)
                .iter()
                .map(CapabilityLine::from)
                .collect::<Vec<_>>()
        };
        Self::new(
            view.view,
            view.launch_record,
            [
                lines(Section::WhatRuns),
                lines(Section::ReadsAndKeeps),
                lines(Section::Releases),
                lines(Section::Unavailable),
            ],
        )
    }
}

/// The permission one V17 line shows, if it shows one: a permitted access or credential,
/// an approval that is needed or given, or a requested capability the contract does not
/// permit. An approval that cannot arise, because its operation is not permitted, is shown
/// by the requested capability's own line instead.
pub fn permission_of_view_line(line: &ShownLine) -> Option<PermissionLine> {
    let status = match (&line.fact, &line.label) {
        (FactValue::Access { .. } | FactValue::Credential { .. }, _) => {
            PermissionStatus::PermittedByContract
        }
        (FactValue::Approval { approval }, _) => match approval.status {
            ApprovalStatus::Needed => PermissionStatus::AwaitingApproval,
            ApprovalStatus::Granted => PermissionStatus::Approved,
            ApprovalStatus::NotApplicable => return None,
        },
        (FactValue::Requested { .. }, label @ FactLabel::Unavailable { .. }) => {
            match Evidence::from(label) {
                Evidence::Unavailable { refusal } => PermissionStatus::NotPermitted { refusal },
                _ => return None,
            }
        }
        _ => return None,
    };
    Some(PermissionLine::new(
        fact_kind(&line.fact),
        &line.fact.to_string(),
        status,
    ))
}

/// Every permission a V17 shown view lists, in its order.
pub fn permissions_of_view(view: &ShownView) -> Vec<PermissionLine> {
    view.lines().filter_map(permission_of_view_line).collect()
}

impl From<LegacyTier> for IsolationTier {
    fn from(tier: LegacyTier) -> Self {
        match tier {
            LegacyTier::T1 => Self::T1,
            LegacyTier::T2 => Self::T2,
            LegacyTier::T3 => Self::T3,
            LegacyTier::T4 => Self::T4,
        }
    }
}

impl From<IsolationTier> for LegacyTier {
    fn from(tier: IsolationTier) -> Self {
        match tier {
            IsolationTier::T1 => Self::T1,
            IsolationTier::T2 => Self::T2,
            IsolationTier::T3 => Self::T3,
            IsolationTier::T4 => Self::T4,
        }
    }
}

/// V01's migration of an old isolation tier (VM-W01; VM §1.3): T2 and T3 become their
/// requirement sets, starting with a VM sandbox; T1 and T4 are refused with V01's reason.
pub fn tier_outcome(tier: IsolationTier) -> MigrationOutcome {
    let legacy = LegacyTier::from(tier);
    match legacy.migrate() {
        Ok(set) if set.contains(SecurityPredicate::VmSandbox) => {
            let names: Vec<&str> = set.iter().map(SecurityPredicate::name).collect();
            MigrationOutcome::Strengthened {
                requirement: RuntimeRequirement::VmSandbox,
                reason: ShownText::new(&format!(
                    "isolation tier {tier:?} becomes its explicit requirements: {}",
                    names.join(", ")
                )),
            }
        }
        Ok(_) => MigrationOutcome::Refused {
            refusal: policy_refusal(
                V08Code::LegacyTierRefused,
                &format!("isolation tier {tier:?} has no requirement set with a VM sandbox"),
            ),
        },
        Err(refusal) => MigrationOutcome::Refused {
            refusal: policy_refusal(V08Code::LegacyTierRefused, &refusal.to_string()),
        },
    }
}

/// The migration item of an old manifest's isolation `tier` for `subject`.
pub fn tier_item(subject: &str, tier: LegacyTier) -> Result<MigrationItem, MigrationError> {
    let tier = IsolationTier::from(tier);
    MigrationItem::with_outcome(
        subject,
        LegacyChoice::IsolationTier { tier },
        tier_outcome(tier),
    )
}

/// V17's stable tag of a fact's kind (its serde tag).
pub fn fact_kind(fact: &FactValue) -> &'static str {
    match fact {
        FactValue::Backend { .. } => "backend",
        FactValue::PinnedArtifacts { .. } => "pinned_artifacts",
        FactValue::DeviceProfile { .. } => "device_profile",
        FactValue::HypervisorAvailable { .. } => "hypervisor_available",
        FactValue::Accelerator { .. } => "accelerator",
        FactValue::HostBuild { .. } => "host_build",
        FactValue::GuestImage { .. } => "guest_image",
        FactValue::Isolation { .. } => "isolation",
        FactValue::Confinement { .. } => "confinement",
        FactValue::Network { .. } => "network",
        FactValue::Credentials { .. } => "credentials",
        FactValue::Persistence { .. } => "persistence",
        FactValue::Devices { .. } => "devices",
        FactValue::Confidentiality { .. } => "confidentiality",
        FactValue::Unobserved { .. } => "unobserved",
        FactValue::NetworkMode { .. } => "network_mode",
        FactValue::ContractNetwork { .. } => "contract_network",
        FactValue::Run { .. } => "run",
        FactValue::Access { .. } => "access",
        FactValue::Credential { .. } => "credential",
        FactValue::LocalSecret { .. } => "local_secret",
        FactValue::Approval { .. } => "approval",
        FactValue::Budget { .. } => "budget",
        FactValue::Requested { .. } => "requested",
        FactValue::Planning { .. } => "planning",
    }
}
