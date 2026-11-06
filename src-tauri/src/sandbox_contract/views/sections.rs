//! The VM-W53 answers in four fixed plain-language sections (VM-W53 row: "A user can
//! understand what will run, what it can read/release and why a capability is
//! unavailable; no new grid/security tab maze"; CORE-07: execution category, requested
//! capabilities, actual backend, permissions, evidence and actionable refusal).
//!
//! The facts come from three places, each kept to its own label:
//!
//! - the `sandbox::backend` launch record (§8.1): the backend build and artifacts the
//!   launch request pinned, the CORE-01 hypervisor evidence, every host-observed fact and,
//!   beside each, what the guest asserted about it;
//! - the V01 resolved contract, through the lines of V08's preview of it: what is
//!   permitted to be read, written, used and released, and where, the approvals and the
//!   budgets, all asserted by the contract, and every requested capability the contract
//!   does not permit;
//! - the declaration, through the same preview: the sandboxes it runs with their V08
//!   execution profiles and persistence classes, its sandbox-local secrets, and the V02
//!   network mode the setup chose.
//!
//! V08 already previews the contract; its lines are copied, not rebuilt. Two things are
//! not copied: the preview's host-evidence verdicts and its decision's freshness, which
//! carry no clock session or configuration and so could not be judged when viewed, and a
//! run line's runtime category as planning observed it, which the launch record's own
//! host facts replace.

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::facts::{FactValue, ViewFact};
use super::labels::{host_basis, AssertedBy, EvidenceStamp, FactBasis, WhatToDo};
use crate::sandbox::backend::{FactName, GuestAsserted, HostFact, LaunchRecord};
use crate::sandbox_contract::declarations::{
    AccessLine, ApprovalLine, PolicyPreview, Refusal, RefusalDetail, RunLine,
};
use crate::sandbox_contract::destinations::NetworkMode;
use crate::sandbox_contract::policy::{
    ContractConstraint, PermissionTuple, PredicateOutcome, ResolvedPolicy,
};

/// The four sections of a view, in the order they are shown. Their titles are plain
/// language; none of them is a separate security tab.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Section {
    /// The backend, artifacts, accelerator, isolation, devices and declared sandboxes.
    WhatRuns,
    /// File grants, private data, credentials, secrets and persistence.
    ReadsAndKeeps,
    /// Network mode and channels, routes, provider operations, publications, release
    /// channels, their approvals and budgets.
    Releases,
    /// Requested capabilities the contract does not permit and planning refusals, each
    /// with why and what the user can do.
    Unavailable,
}

impl Section {
    /// Every section, in display order.
    pub const ALL: [Self; 4] = [
        Self::WhatRuns,
        Self::ReadsAndKeeps,
        Self::Releases,
        Self::Unavailable,
    ];

    /// The plain-language title.
    pub const fn title(self) -> &'static str {
        match self {
            Self::WhatRuns => "What will run",
            Self::ReadsAndKeeps => "What it can read, write and keep",
            Self::Releases => "What it can release, and where",
            Self::Unavailable => "What is unavailable, and why",
        }
    }
}

impl fmt::Display for Section {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.title())
    }
}

/// What one view is built from.
#[derive(Clone, Copy, Debug)]
pub struct ViewInputs<'a> {
    /// The sealed §8.1 launch record.
    pub record: &'a LaunchRecord,
    /// The V01 contract the launch ran under; its identity must be the record's contract
    /// digest.
    pub contract: &'a ResolvedPolicy,
    /// V08's preview of that contract.
    pub preview: &'a PolicyPreview,
    /// The V02 network mode the setup chose for this sandbox, if it chose one.
    pub network_mode: Option<NetworkMode>,
}

/// One host fact with what the guest asserted about it: the host's observation (or its
/// absence) first, then the guest's assertion, labelled as such.
fn host_fact<T: Clone, G: Clone>(
    facts: &mut Vec<ViewFact>,
    name: FactName,
    fact: &HostFact<T>,
    guest: Option<&GuestAsserted<G>>,
    host_value: impl Fn(T) -> FactValue,
    guest_value: impl Fn(G) -> FactValue,
) {
    match fact {
        HostFact::Observed { observation } => facts.push(ViewFact::new(
            host_value(observation.value().clone()),
            host_basis(observation),
        )),
        HostFact::Unavailable { reason } => facts.push(ViewFact::new(
            FactValue::Unobserved { fact: name },
            FactBasis::NotObserved {
                reason: *reason,
                guest_asserted: guest.is_some(),
            },
        )),
    }
    if let Some(asserted) = guest {
        facts.push(ViewFact::new(
            guest_value(asserted.value().clone()),
            FactBasis::Asserted {
                by: AssertedBy::Guest,
                received_at: Some(asserted.received_at()),
            },
        ));
    }
}

/// Every fact the launch record yields, in a fixed order. A view's launch-record facts
/// must be exactly these ([`SandboxView::check_against`](super::SandboxView::check_against)).
pub(super) fn record_facts(record: &LaunchRecord) -> Vec<ViewFact> {
    let pinned = FactBasis::Asserted {
        by: AssertedBy::LaunchRequest,
        received_at: None,
    };
    let observed = record.host_observed();
    let guest = record.guest_asserted();
    let mut facts = vec![
        ViewFact::new(
            FactValue::Backend {
                backend: record.backend().clone(),
            },
            pinned.clone(),
        ),
        ViewFact::new(
            FactValue::PinnedArtifacts {
                pinned: record.pinned(),
            },
            pinned.clone(),
        ),
    ];
    host_fact::<_, ()>(
        &mut facts,
        FactName::GuestImage,
        &observed.guest_image,
        None,
        |image| FactValue::GuestImage { image },
        |()| FactValue::Unobserved {
            fact: FactName::GuestImage,
        },
    );
    host_fact::<_, ()>(
        &mut facts,
        FactName::Host,
        &observed.host,
        None,
        |host| FactValue::HostBuild { host },
        |()| FactValue::Unobserved {
            fact: FactName::Host,
        },
    );
    facts.push(ViewFact::new(
        FactValue::HypervisorAvailable {
            hypervisor: record.backend().hypervisor,
        },
        FactBasis::Core01Evidence {
            stamp: EvidenceStamp::of(record.hypervisor_evidence(), record.clock()),
        },
    ));
    host_fact(
        &mut facts,
        FactName::Accelerator,
        &HostFact::observed(record.accelerator().clone()),
        guest.accelerator.as_ref(),
        |accelerator| FactValue::Accelerator { accelerator },
        |accelerator| FactValue::Accelerator { accelerator },
    );
    host_fact(
        &mut facts,
        FactName::Isolation,
        &observed.isolation,
        guest.isolation.as_ref(),
        |isolation| FactValue::Isolation { isolation },
        |isolation| FactValue::Isolation { isolation },
    );
    host_fact(
        &mut facts,
        FactName::Confinement,
        &observed.confinement,
        guest.confinement.as_ref(),
        |controls| FactValue::Confinement { controls },
        |controls| FactValue::Confinement { controls },
    );
    host_fact(
        &mut facts,
        FactName::Confidentiality,
        &observed.confidentiality,
        guest.confidentiality.as_ref(),
        |confidentiality| FactValue::Confidentiality { confidentiality },
        |confidentiality| FactValue::Confidentiality { confidentiality },
    );
    facts.push(ViewFact::new(
        FactValue::DeviceProfile {
            profile: record.device_profile().clone(),
        },
        pinned,
    ));
    host_fact(
        &mut facts,
        FactName::Devices,
        &observed.devices,
        guest.devices.as_ref(),
        |inventory| FactValue::Devices { inventory },
        |inventory| FactValue::Devices { inventory },
    );
    host_fact(
        &mut facts,
        FactName::Credentials,
        &observed.credentials,
        guest.credentials.as_ref(),
        |exposure| FactValue::Credentials { exposure },
        |exposure| FactValue::Credentials { exposure },
    );
    host_fact(
        &mut facts,
        FactName::Persistence,
        &observed.persistence,
        guest.persistence.as_ref(),
        |persistence| FactValue::Persistence { persistence },
        |persistence| FactValue::Persistence { persistence },
    );
    host_fact(
        &mut facts,
        FactName::Network,
        &observed.network,
        guest.network.as_ref(),
        |authority| FactValue::Network { authority },
        |authority| FactValue::Network { authority },
    );
    facts
}

fn declared(value: FactValue) -> ViewFact {
    ViewFact::new(
        value,
        FactBasis::Asserted {
            by: AssertedBy::Declaration,
            received_at: None,
        },
    )
}

fn granted(value: FactValue) -> ViewFact {
    ViewFact::new(
        value,
        FactBasis::Asserted {
            by: AssertedBy::Contract,
            received_at: None,
        },
    )
}

fn access(lines: &[AccessLine]) -> impl Iterator<Item = ViewFact> + '_ {
    lines.iter().map(|line| {
        granted(FactValue::Access {
            access: line.clone(),
        })
    })
}

fn approvals(lines: &[ApprovalLine]) -> impl Iterator<Item = ViewFact> + '_ {
    lines.iter().map(|line| {
        granted(FactValue::Approval {
            approval: line.clone(),
        })
    })
}

/// What a planning refusal asks of the user: the CORE-01 remedy when host evidence was
/// refused, otherwise the help of its V08 code.
pub(super) fn refusal_remedy(refusal: &Refusal) -> WhatToDo {
    match &refusal.detail {
        RefusalDetail::RequirementUnmet {
            outcome: PredicateOutcome::EvidenceRefused { refusal: evidence },
            ..
        } => WhatToDo::Evidence {
            remedy: evidence.remedy(),
        },
        _ => WhatToDo::Refusal { code: refusal.code },
    }
}

/// The facts the contract, the declaration and planning yield, in a fixed order.
pub(super) fn contract_facts(
    contract: &ResolvedPolicy,
    preview: &PolicyPreview,
    network_mode: Option<NetworkMode>,
) -> Vec<ViewFact> {
    let mut facts: Vec<ViewFact> = preview
        .runs
        .iter()
        .map(|run| {
            declared(FactValue::Run {
                run: RunLine {
                    observed_runtime: None,
                    ..run.clone()
                },
            })
        })
        .collect();
    facts.extend(access(&preview.devices));
    facts.extend(access(&preview.reads));
    facts.extend(access(&preview.writes));
    facts.extend(preview.credentials.iter().map(|line| {
        granted(FactValue::Credential {
            credential: line.clone(),
        })
    }));
    facts.extend(preview.local_secrets.iter().map(|terms| {
        declared(FactValue::LocalSecret {
            secret: terms.clone(),
        })
    }));
    facts.extend(approvals(&preview.approvals.private_data_access));
    if let Some(mode) = network_mode {
        facts.push(declared(FactValue::NetworkMode { mode }));
    }
    let offline = ContractConstraint::NoNetworkAuthority
        .evaluate(contract.permitted(), contract.budgets())
        == PredicateOutcome::ContractHolds;
    facts.push(granted(FactValue::ContractNetwork { offline }));
    facts.extend(access(&preview.releases));
    facts.extend(approvals(&preview.approvals.ongoing_delegation));
    facts.extend(approvals(&preview.approvals.exact_release));
    facts.extend(preview.budgets.iter().map(|line| {
        granted(FactValue::Budget {
            budget: line.clone(),
        })
    }));
    facts.extend(preview.removed.iter().map(|removed| {
        ViewFact::new(
            FactValue::Requested {
                tuple: removed.tuple.clone(),
                need: removed.need,
            },
            FactBasis::NotPermitted {
                excluded_by: removed.excluded_by.clone(),
                effect: removed.effect,
            },
        )
    }));
    facts.extend(preview.refusals.iter().map(|refusal| {
        ViewFact::new(
            FactValue::Planning {
                refusal: refusal.clone(),
            },
            FactBasis::Refused {
                code: refusal.code,
                remedy: refusal_remedy(refusal),
            },
        )
    }));
    facts
}

/// Whether the preview's lines are the contract's: every permitted tuple appears in
/// exactly the preview's access lines, every removed tuple in its removed lines, and every
/// refusal is one planning makes.
pub(super) fn preview_matches(contract: &ResolvedPolicy, preview: &PolicyPreview) -> bool {
    let lines: Vec<&PermissionTuple> = preview
        .reads
        .iter()
        .chain(&preview.writes)
        .chain(&preview.releases)
        .chain(&preview.devices)
        .chain(preview.credentials.iter().map(|line| &line.access))
        .map(|line| &line.tuple)
        .collect();
    let shown: BTreeSet<&PermissionTuple> = lines.iter().copied().collect();
    let permitted = contract.permitted().tuples();
    let removed: BTreeSet<&PermissionTuple> =
        preview.removed.iter().map(|line| &line.tuple).collect();
    let expected_removed: BTreeSet<&PermissionTuple> =
        contract.removed().iter().map(|line| &line.tuple).collect();
    lines.len() == shown.len()
        && shown == permitted.iter().collect::<BTreeSet<_>>()
        && removed.len() == preview.removed.len()
        && removed == expected_removed
        && preview
            .refusals
            .iter()
            .all(|refusal| refusal.detail.launch_reason().is_some())
}
