//! The policy preview (VM-W37 "validate and preview the resolved policy"; VM-W53 "what
//! will run, what it can read/release and why a capability is unavailable"; VM-W54 "UI
//! and CLI resolve the same policy"; VM-P46; §1.3).
//!
//! One [`PolicyPreview`] value is built from V01's resolved policy and launch outcome,
//! the validated request (for the budgets it asked for) and the declaration's
//! descriptive context. Its text rendering and its JSON form are two encodings of that
//! value, so a UI reading the JSON and a CLI printing the text show the same policy.
//!
//! The preview shows facets one by one with each requirement's verdict and reason, never
//! a score (§1.3). Approvals are listed in three separate groups, private-data access,
//! ongoing delegation and exact release (VM-P46). It never claims enforcement: the
//! contract digest and any issuer are labelled as identification only (§2.4 line 1804),
//! and a fixed notice says the preview is not evidence of enforcement.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::compile::{CredentialTerms, DeclaredContext};
use super::noninteractive::approval_status;
use super::pipeline::LaunchOutcome;
use super::refusal::{one_line, Refusal, RefusalDetail};
use super::schema::{
    CredentialClass, ExecutionProfile, ExtensionDeclaration, Need, PersistenceClass,
};
use crate::foundation::ids::{
    AuthorizationEpoch, Digest, ExecutionCategory, MonotonicTime, PolicyEpoch,
};
use crate::sandbox_contract::policy::{
    ApprovalGrant, ApprovalKind, ApprovalRule, BudgetKey, BudgetUnit, DeploymentFacet,
    IssuerIdentity, LaunchRefusalReason, Operation, PermissionTuple, PolicyLayer, PredicateCheck,
    PredicateOutcome, RequestSource, RoleName, SecurityPredicate, SourceKind, WorkloadRequest,
};

/// The preview schema version this build writes and reads.
pub const PREVIEW_VERSION: u32 = 1;

/// The pinned preview version; any other is refused when read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u32", into = "u32")]
pub struct PreviewVersion(u32);

impl PreviewVersion {
    pub const CURRENT: Self = Self(PREVIEW_VERSION);

    pub const fn get(self) -> u32 {
        self.0
    }
}

impl TryFrom<u32> for PreviewVersion {
    type Error = String;

    fn try_from(found: u32) -> Result<Self, Self::Error> {
        if found == PREVIEW_VERSION {
            Ok(Self(found))
        } else {
            Err(format!(
                "preview version {found} is not supported; this build reads only version \
                 {PREVIEW_VERSION}"
            ))
        }
    }
}

impl From<PreviewVersion> for u32 {
    fn from(version: PreviewVersion) -> Self {
        version.0
    }
}

/// A field whose only value is one fixed sentence: written as that sentence, and read
/// only if it is exactly that sentence, so a stored preview cannot be edited into a
/// claim of enforcement.
macro_rules! fixed_text {
    ($(#[$doc:meta])* $name:ident = $text:literal) => {
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $name;

        impl $name {
            pub const TEXT: &'static str = $text;
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(Self::TEXT)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                if text == Self::TEXT {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::custom(concat!(
                        "this field holds only its fixed text: ",
                        $text
                    )))
                }
            }
        }
    };
}

fixed_text!(
    /// What a contract digest means (§2.4 line 1804).
    ContractMeaning = "identifies this contract; it is not evidence that anything enforces it"
);
fixed_text!(
    /// What an issuer identity means (§2.4 line 1804).
    IssuerMeaning =
        "identifies who issued the contract; it is not evidence that anything enforces it"
);
fixed_text!(
    /// The preview's standing notice.
    PreviewNotice = "This preview describes the resolved contract and the launch decision. \
                     It is not evidence that any mechanism enforces the contract. Contract \
                     requirements describe what the contract grants; host requirements are \
                     met only by host evidence."
);

/// The contract's identity, labelled as identification only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContractLine {
    pub digest: Digest,
    pub meaning: ContractMeaning,
}

/// An issuer's identity, labelled as identification only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuerLine {
    pub digest: Digest,
    pub meaning: IssuerMeaning,
}

strict_declaration_enum! {
    /// The launch decision.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum PreviewDecision tag "status" {
        /// Planned; the plan's host evidence is fresh until `fresh_until` on the
        /// registry's monotonic clock.
        Allowed { fresh_until: MonotonicTime },
        /// Refused; the preview's refusals say why.
        Refused,
        /// Resolved but not yet planned against host evidence.
        NotPlanned,
    }
}

/// One sandbox the setup runs, with its extension executors.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunLine {
    pub role: RoleName,
    pub profile: ExecutionProfile,
    pub persistence: PersistenceClass,
    /// The runtime category the launch requires: always a VM sandbox.
    pub required_runtime: ExecutionCategory,
    /// The runtime category host or provider evidence showed, when the launch was planned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_runtime: Option<ExecutionCategory>,
    pub extensions: Vec<ExtensionDeclaration>,
}

/// One permitted tuple.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLine {
    pub tuple: PermissionTuple,
    /// Required when the workload listed it as essential.
    pub need: Need,
    /// Whether a private-data access approval applies to it.
    pub private_data: bool,
}

/// A credential the guest would receive, with its §4.5 terms.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialLine {
    pub access: AccessLine,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms: Option<CredentialTerms>,
}

/// Whether a required approval still has to be given.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStatus {
    /// It applies and no valid grant covers it; an interactive run asks, a
    /// non-interactive run refuses.
    Needed,
    /// A valid grant at the authorization epoch covers it, so it is not asked again
    /// (VM-P46). An exact-release grant covers only the payload digest it names.
    Granted,
    /// Its operation and resource are not permitted, so it cannot arise.
    NotApplicable,
}

/// One required approval and its status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalLine {
    pub rule: ApprovalRule,
    pub status: ApprovalStatus,
}

/// Required approvals in the three groups users must be able to tell apart (VM-P46).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApprovalsView {
    pub private_data_access: Vec<ApprovalLine>,
    pub ongoing_delegation: Vec<ApprovalLine>,
    pub exact_release: Vec<ApprovalLine>,
}

/// One effective budget, with what the declaration asked for under the same key.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetLine {
    pub key: BudgetKey,
    pub limit: u64,
    pub unit: BudgetUnit,
    /// The declaration's own limit; when it is higher, the lower limit applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub declared: Option<u64>,
}

/// How a requirement is judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JudgedBy {
    /// Only CORE-01 host evidence; a declaration can never supply it.
    HostEvidence,
    /// The resolved contract; describes the contract, not enforcement.
    Contract,
}

/// A requirement's verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerdictStatus {
    Met,
    Unmet,
    /// Host evidence has not been checked yet.
    NotChecked,
}

/// One required predicate with its verdict and reason.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerdictLine {
    pub predicate: SecurityPredicate,
    pub judged_by: JudgedBy,
    pub status: VerdictStatus,
    pub reason: String,
}

/// One §1.3 facet with its requirements. Facets are never combined into a score.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FacetView {
    pub facet: DeploymentFacet,
    pub requirements: Vec<VerdictLine>,
}

/// What removing a requested tuple did.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalEffect {
    /// It was required, so planning refuses (§2.4 line 1800).
    LaunchRefused,
    /// It was optional and is dropped.
    Dropped,
}

/// One requested tuple the intersection removed, with the layers that removed it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemovedLine {
    pub tuple: PermissionTuple,
    pub need: Need,
    pub excluded_by: BTreeSet<PolicyLayer>,
    pub effect: RemovalEffect,
}

/// The inputs of one preview.
#[derive(Clone, Copy, Debug)]
pub struct PreviewInputs<'a> {
    pub context: &'a DeclaredContext,
    /// The validated request; only its budgets are read, to show what it asked for.
    pub request: &'a WorkloadRequest,
    pub outcome: LaunchOutcome<'a>,
    /// Approval grants the host recorded; they only mark approvals as already given.
    pub grants: &'a [ApprovalGrant],
    /// The authorization epoch grants are judged at; `None` judges none valid.
    pub epoch: Option<AuthorizationEpoch>,
    pub issuer: Option<IssuerIdentity>,
}

/// The shared preview (VM-W37, VM-W54). See the module notes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyPreview {
    pub preview_version: PreviewVersion,
    pub source: RequestSource,
    pub contract: ContractLine,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer: Option<IssuerLine>,
    pub policy_epoch: PolicyEpoch,
    pub decision: PreviewDecision,
    pub refusals: Vec<Refusal>,
    pub runs: Vec<RunLine>,
    pub reads: Vec<AccessLine>,
    pub writes: Vec<AccessLine>,
    /// Every outbound tuple: routes, provider operations, published services and
    /// release channels, each naming where.
    pub releases: Vec<AccessLine>,
    pub credentials: Vec<CredentialLine>,
    pub local_secrets: Vec<CredentialTerms>,
    pub devices: Vec<AccessLine>,
    pub approvals: ApprovalsView,
    pub budgets: Vec<BudgetLine>,
    pub facets: Vec<FacetView>,
    pub removed: Vec<RemovedLine>,
    pub notice: PreviewNotice,
}

impl PolicyPreview {
    /// Builds the preview from V01's resolved policy and launch outcome.
    pub fn build(inputs: &PreviewInputs<'_>) -> Self {
        let resolved = inputs.outcome.resolved();
        let plan = inputs.outcome.plan();
        let (decision, refusals) = match (plan, inputs.outcome.refusal()) {
            (Some(plan), _) => (
                PreviewDecision::Allowed {
                    fresh_until: plan.fresh_until(),
                },
                Vec::new(),
            ),
            (None, Some(refusal)) => (
                PreviewDecision::Refused,
                refusal
                    .reasons
                    .iter()
                    .cloned()
                    .map(|reason| Refusal::new(RefusalDetail::from(reason)))
                    .collect(),
            ),
            (None, None) => (PreviewDecision::NotPlanned, Vec::new()),
        };
        let observed_runtime = plan.map(|plan| plan.targets().runtime.category);
        let runs = inputs
            .context
            .sandboxes
            .iter()
            .map(|sandbox| RunLine {
                role: sandbox.role.clone(),
                profile: sandbox.profile,
                persistence: sandbox.persistence,
                required_runtime: ExecutionCategory::VmSandbox,
                observed_runtime,
                extensions: inputs
                    .context
                    .extensions
                    .iter()
                    .filter(|extension| extension.role == sandbox.role)
                    .cloned()
                    .collect(),
            })
            .collect();

        let access = |tuple: PermissionTuple| {
            let private_data = resolved
                .approvals()
                .rules_for(&tuple.operation, &tuple.resource)
                .any(|rule| rule.kind == ApprovalKind::PrivateDataAccess);
            AccessLine {
                need: if resolved.dependencies().covers(&tuple) {
                    Need::Required
                } else {
                    Need::Optional
                },
                private_data,
                tuple,
            }
        };
        let select = |wanted: fn(&Operation) -> bool| -> Vec<AccessLine> {
            resolved
                .permitted()
                .iter()
                .filter(|tuple| wanted(&tuple.operation))
                .map(access)
                .collect()
        };
        let reads = select(|operation| matches!(operation, Operation::FileRead));
        let writes =
            select(|operation| matches!(operation, Operation::FileWrite | Operation::VolumeWrite));
        let releases = select(Operation::is_outbound);
        let devices = select(|operation| matches!(operation, Operation::DeviceUse));
        let credentials =
            select(|operation| matches!(operation, Operation::ReceiveExternalCredential))
                .into_iter()
                .map(|access| CredentialLine {
                    terms: inputs
                        .context
                        .credentials
                        .iter()
                        .find(|terms| {
                            terms.role == access.tuple.principal.role
                                && terms.name == access.tuple.resource.name
                                && terms.class.is_external_credential()
                        })
                        .cloned(),
                    access,
                })
                .collect();
        let local_secrets = inputs
            .context
            .credentials
            .iter()
            .filter(|terms| terms.class == CredentialClass::SandboxLocalSecret)
            .cloned()
            .collect();

        let mut approvals = ApprovalsView::default();
        for line in approval_status(resolved, inputs.grants, inputs.epoch) {
            match line.rule.kind {
                ApprovalKind::PrivateDataAccess => approvals.private_data_access.push(line),
                ApprovalKind::OngoingDelegation => approvals.ongoing_delegation.push(line),
                ApprovalKind::ExactRelease => approvals.exact_release.push(line),
            }
        }

        let budgets = resolved
            .budgets()
            .iter()
            .map(|(key, limit)| BudgetLine {
                key: key.clone(),
                limit,
                unit: key.resource.unit(),
                declared: inputs.request.budgets().limit(key),
            })
            .collect();

        let verdicts = verdicts(&inputs.outcome);
        let facets = DeploymentFacet::ALL
            .into_iter()
            .map(|facet| FacetView {
                facet,
                requirements: verdicts
                    .iter()
                    .filter(|line| line.predicate.facet() == facet)
                    .cloned()
                    .collect(),
            })
            .collect();

        let removed = resolved
            .removed()
            .iter()
            .map(|removed| RemovedLine {
                tuple: removed.tuple.clone(),
                need: if removed.essential {
                    Need::Required
                } else {
                    Need::Optional
                },
                excluded_by: removed.excluded_by.clone(),
                effect: if removed.essential {
                    RemovalEffect::LaunchRefused
                } else {
                    RemovalEffect::Dropped
                },
            })
            .collect();

        Self {
            preview_version: PreviewVersion::CURRENT,
            source: inputs.context.source.clone(),
            contract: ContractLine {
                digest: resolved.identity().digest(),
                meaning: ContractMeaning,
            },
            issuer: inputs.issuer.map(|issuer| IssuerLine {
                digest: issuer.digest(),
                meaning: IssuerMeaning,
            }),
            policy_epoch: resolved.policy_epoch(),
            decision,
            refusals,
            runs,
            reads,
            writes,
            releases,
            credentials,
            local_secrets,
            devices,
            approvals,
            budgets,
            facets,
            removed,
            notice: PreviewNotice,
        }
    }

    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    pub fn from_json(text: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(text)
    }

    /// The deterministic plain-text rendering of this value.
    pub fn render_text(&self) -> String {
        let mut out = Text::default();
        let author = match self.source.kind {
            SourceKind::Template => "a template",
            SourceKind::Tool => "a tool",
            SourceKind::User => "a user",
        };
        out.line(
            0,
            &format!("Policy preview (version {})", self.preview_version.get()),
        );
        out.line(
            0,
            &format!(
                "Source: \"{}\", declared by {author}; a request, never a grant",
                self.source.name
            ),
        );
        out.line(0, &format!("Contract: {}", self.contract.digest));
        out.line(1, ContractMeaning::TEXT);
        if let Some(issuer) = &self.issuer {
            out.line(0, &format!("Issuer: {}", issuer.digest));
            out.line(1, IssuerMeaning::TEXT);
        }
        out.line(0, &format!("Policy epoch: {}", self.policy_epoch));
        out.line(
            0,
            &match self.decision {
                PreviewDecision::Allowed { fresh_until } => format!(
                    "Decision: allowed; host evidence is fresh until {} ns on the registry \
                     clock",
                    fresh_until.as_nanos()
                ),
                PreviewDecision::Refused => "Decision: refused".to_owned(),
                PreviewDecision::NotPlanned => {
                    "Decision: not planned; host evidence has not been checked".to_owned()
                }
            },
        );
        if !self.refusals.is_empty() {
            out.line(0, "Refusals:");
            for refusal in &self.refusals {
                out.line(1, &refusal.render_text());
            }
        }

        out.line(0, "What will run:");
        out.none_if(1, self.runs.is_empty());
        for run in &self.runs {
            let observed = match run.observed_runtime {
                Some(category) => format!("; host evidence shows: {}", category.label()),
                None => String::new(),
            };
            out.line(
                1,
                &format!(
                    "sandbox \"{}\": {} profile, {}, requires a {}{observed}",
                    run.role,
                    run.profile,
                    run.persistence,
                    run.required_runtime.label()
                ),
            );
            for extension in &run.extensions {
                out.line(
                    2,
                    &format!(
                        "extension \"{}\" ({}) runs inside this VM as untrusted code and adds \
                         no authority",
                        extension.name, extension.runtime
                    ),
                );
            }
        }

        out.access_section("What it can read:", &self.reads);
        out.access_section("What it can write:", &self.writes);
        out.access_section("What it can release, and where:", &self.releases);

        out.line(0, "Credentials in the guest:");
        out.none_if(1, self.credentials.is_empty());
        for credential in &self.credentials {
            let terms = match &credential.terms {
                Some(terms) => format!(" [{}]", describe_terms(terms)),
                None => String::new(),
            };
            out.line(
                1,
                &format!("- {}{terms}", describe_access(&credential.access)),
            );
        }
        out.line(0, "Sandbox-local secrets:");
        out.none_if(1, self.local_secrets.is_empty());
        for secret in &self.local_secrets {
            out.line(
                1,
                &format!(
                    "- \"{}\" in sandbox \"{}\": {}",
                    secret.name,
                    secret.role,
                    CredentialClass::SandboxLocalSecret.treatment()
                ),
            );
        }
        out.access_section("Devices:", &self.devices);

        out.line(0, "Approvals:");
        for (title, lines) in [
            ("Private-data access:", &self.approvals.private_data_access),
            ("Ongoing delegation:", &self.approvals.ongoing_delegation),
            (
                "Exact release (bound to one payload digest, used once):",
                &self.approvals.exact_release,
            ),
        ] {
            out.line(1, title);
            out.none_if(2, lines.is_empty());
            for line in lines {
                let status = match line.status {
                    ApprovalStatus::Needed => "needed",
                    ApprovalStatus::Granted => "already granted for this authorization epoch",
                    ApprovalStatus::NotApplicable => "not applicable; not permitted",
                };
                out.line(2, &format!("- {}: {status}", line.rule));
            }
        }

        out.line(0, "Budgets:");
        out.none_if(1, self.budgets.is_empty());
        for budget in &self.budgets {
            let declared = match budget.declared {
                Some(asked) if asked > budget.limit => {
                    format!("; the declaration asked for {asked}, and the lower limit applies")
                }
                Some(asked) => format!("; the declaration asked for {asked}"),
                None => String::new(),
            };
            out.line(
                1,
                &format!(
                    "- {}: {} {}{declared}",
                    budget.key,
                    budget.limit,
                    unit_name(budget.unit)
                ),
            );
        }

        out.line(
            0,
            "Requirements by facet (each judged on its own; never combined into a score):",
        );
        for facet in &self.facets {
            out.line(1, &format!("{}:", facet.facet));
            out.none_if(2, facet.requirements.is_empty());
            for line in &facet.requirements {
                let judged = match line.judged_by {
                    JudgedBy::HostEvidence => "host evidence",
                    JudgedBy::Contract => "contract",
                };
                let status = match line.status {
                    VerdictStatus::Met => "met",
                    VerdictStatus::Unmet => "unmet",
                    VerdictStatus::NotChecked => "not checked",
                };
                out.line(
                    2,
                    &format!(
                        "- {} ({judged}): {status}; {}",
                        line.predicate.name(),
                        line.reason
                    ),
                );
            }
        }

        out.line(0, "Removed or unavailable:");
        out.none_if(1, self.removed.is_empty());
        for removed in &self.removed {
            let layers: Vec<String> = removed
                .excluded_by
                .iter()
                .map(|layer| layer.to_string())
                .collect();
            let (need, effect) = match removed.effect {
                RemovalEffect::LaunchRefused => ("required", "the launch is refused"),
                RemovalEffect::Dropped => ("optional", "dropped; the run goes ahead without it"),
            };
            out.line(
                1,
                &format!(
                    "- [{need}] {} is not permitted by {}; {effect}",
                    removed.tuple,
                    layers.join(" or ")
                ),
            );
        }
        out.line(0, &format!("Notice: {}", PreviewNotice::TEXT));
        out.finish()
    }
}

impl fmt::Display for PolicyPreview {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render_text())
    }
}

/// One verdict per required predicate, in canonical predicate order.
fn verdicts(outcome: &LaunchOutcome<'_>) -> Vec<VerdictLine> {
    let resolved = outcome.resolved();
    let judged_by = |predicate: SecurityPredicate| match predicate.check() {
        PredicateCheck::HostEvidence(_) => JudgedBy::HostEvidence,
        PredicateCheck::Contract(_) => JudgedBy::Contract,
    };
    let from_outcome = |predicate: SecurityPredicate, outcome: &PredicateOutcome| VerdictLine {
        predicate,
        judged_by: judged_by(predicate),
        status: if outcome.is_satisfied() {
            VerdictStatus::Met
        } else {
            VerdictStatus::Unmet
        },
        reason: one_line(&outcome.to_string()),
    };
    if let Some(plan) = outcome.plan() {
        return plan
            .verdicts()
            .iter()
            .map(|verdict| from_outcome(verdict.predicate, &verdict.outcome))
            .collect();
    }
    let refusal = outcome.refusal();
    resolved
        .requirements()
        .iter()
        .map(|predicate| {
            if let Some(refusal) = refusal {
                let unmet = refusal.reasons.iter().find_map(|reason| match reason {
                    LaunchRefusalReason::RequirementUnmet {
                        predicate: unmet,
                        outcome,
                    } if *unmet == predicate => Some(outcome),
                    _ => None,
                });
                return match unmet {
                    Some(outcome) => from_outcome(predicate, outcome),
                    None => VerdictLine {
                        predicate,
                        judged_by: judged_by(predicate),
                        status: VerdictStatus::Met,
                        reason: match judged_by(predicate) {
                            JudgedBy::HostEvidence => {
                                "verified by host evidence when the launch was planned".to_owned()
                            }
                            JudgedBy::Contract => PredicateOutcome::ContractHolds.to_string(),
                        },
                    },
                };
            }
            match predicate.contract_constraint() {
                Some(constraint) => from_outcome(
                    predicate,
                    &constraint.evaluate(resolved.permitted(), resolved.budgets()),
                ),
                None => VerdictLine {
                    predicate,
                    judged_by: JudgedBy::HostEvidence,
                    status: VerdictStatus::NotChecked,
                    reason: "host evidence has not been checked yet; it is not assumed".to_owned(),
                },
            }
        })
        .collect()
}

fn describe_access(access: &AccessLine) -> String {
    let need = match access.need {
        Need::Required => "required",
        Need::Optional => "optional",
    };
    let private = if access.private_data {
        "; private data"
    } else {
        ""
    };
    format!("{} [{need}{private}]", access.tuple)
}

fn describe_terms(terms: &CredentialTerms) -> String {
    let mut parts = vec![terms.class.to_string()];
    if let Some(audience) = &terms.audience {
        parts.push(format!("audience {audience}"));
    }
    if let Some(scope) = &terms.scope {
        parts.push(format!("scope {scope}"));
    }
    if let Some(expires) = terms.expires_in_seconds {
        parts.push(format!("expires {} s after issue", expires.get()));
    }
    if let Some(effects) = terms.delegated_effects {
        parts.push(format!(
            "delegates at most {} external effects",
            effects.get()
        ));
    }
    parts.push(terms.class.treatment().to_owned());
    parts.join("; ")
}

fn unit_name(unit: BudgetUnit) -> &'static str {
    match unit {
        BudgetUnit::Bytes => "bytes",
        BudgetUnit::Effects => "effects",
        BudgetUnit::Seconds => "seconds",
    }
}

#[derive(Default)]
struct Text {
    lines: Vec<String>,
}

impl Text {
    fn line(&mut self, depth: usize, text: &str) {
        self.lines
            .push(format!("{}{}", "  ".repeat(depth), one_line(text)));
    }

    fn none_if(&mut self, depth: usize, empty: bool) {
        if empty {
            self.line(depth, "none");
        }
    }

    fn access_section(&mut self, title: &str, lines: &[AccessLine]) {
        self.line(0, title);
        self.none_if(1, lines.is_empty());
        for access in lines {
            self.line(1, &format!("- {}", describe_access(access)));
        }
    }

    fn finish(self) -> String {
        let mut text = self.lines.join("\n");
        text.push('\n');
        text
    }
}
