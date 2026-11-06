//! The shared preview: VM-P46 and VM-P47 end to end, facets without a score, one value
//! in text and JSON, and no claim of enforcement.

use std::collections::BTreeSet;

use serde_json::{json, Value};

use super::tests::{
    all_grants, base, base_tuples, cap, connect_registry, create_issue, declaration, delegation,
    product, product_with, read_inputs, release_results, rule, text, tuple, write_outputs, Host,
    E1, E2,
};
use super::*;
use crate::foundation::ids::ExecutionCategory;
use crate::sandbox_contract::policy::{
    resolve, ApprovalKind, DeploymentFacet, IssuerIdentity, Operation, PermissionSet,
    PermissionTuple, Phase, PolicyLayer, ResourceKind, SecurityPredicate, SourceKind, Validator,
};

fn planned_evaluation() -> Evaluation {
    let tuples = base_tuples();
    let mut value = base();
    value["extensions"] = json!([{"name": "fmt", "role": "main", "runtime": "wasm"}]);
    value["capabilities"].as_array_mut().unwrap().push(cap(
        "required",
        "analysis",
        json!({"kind": "sandbox_local_secret", "name": "db-password"}),
    ));
    let evaluation = Host::ready()
        .evaluate(&text(&value), &product(&tuples), &delegation(&tuples))
        .unwrap();
    assert!(evaluation.launch().is_ok());
    evaluation
}

fn tuples_of(lines: &[AccessLine]) -> BTreeSet<PermissionTuple> {
    lines.iter().map(|line| line.tuple.clone()).collect()
}

fn keys(value: &Value, found: &mut BTreeSet<String>) {
    match value {
        Value::Object(fields) => {
            for (key, inner) in fields {
                found.insert(key.clone());
                keys(inner, found);
            }
        }
        Value::Array(items) => items.iter().for_each(|inner| keys(inner, found)),
        _ => {}
    }
}

#[test]
fn the_preview_shows_what_runs_what_it_reads_and_what_it_releases_where() {
    let evaluation = planned_evaluation();
    let plan = evaluation.launch().as_ref().unwrap();
    let preview = evaluation.preview(&[], None, None);
    assert_eq!(
        preview.decision,
        PreviewDecision::Allowed {
            fresh_until: plan.fresh_until()
        }
    );
    assert!(preview.refusals.is_empty());
    assert_eq!(preview.source.name.as_str(), "report-writer");
    assert_eq!(preview.source.kind, SourceKind::Tool);

    let [run] = preview.runs.as_slice() else {
        panic!("one sandbox");
    };
    assert_eq!(run.role.as_str(), "main");
    assert_eq!(run.profile, ExecutionProfile::Task);
    assert_eq!(run.persistence, PersistenceClass::Ephemeral);
    assert_eq!(run.required_runtime, ExecutionCategory::VmSandbox);
    assert_eq!(run.observed_runtime, Some(ExecutionCategory::VmSandbox));
    assert_eq!(run.extensions.len(), 1);

    assert_eq!(tuples_of(&preview.reads), BTreeSet::from([read_inputs()]));
    assert!(preview.reads[0].private_data);
    assert_eq!(preview.reads[0].need, Need::Required);
    assert_eq!(
        tuples_of(&preview.writes),
        BTreeSet::from([write_outputs()])
    );
    assert_eq!(
        tuples_of(&preview.releases),
        BTreeSet::from([connect_registry(), release_results(), create_issue()])
    );
    let route = preview
        .releases
        .iter()
        .find(|line| line.tuple == connect_registry())
        .unwrap();
    assert_eq!(route.need, Need::Optional);
    assert!(preview.credentials.is_empty() && preview.devices.is_empty());
    assert_eq!(preview.local_secrets.len(), 1);
    assert!(preview.removed.is_empty());

    let rendered = preview.render_text();
    for expected in [
        "What will run:",
        "  sandbox \"main\": task profile, ephemeral state, requires a VM sandbox; host evidence \
         shows: VM sandbox",
        "    extension \"fmt\" (Wasm) runs inside this VM as untrusted code and adds no authority",
        "What it can read:",
        "What it can release, and where:",
        "route \"registry.example.com:443\"",
        "release channel \"results\"",
        "perform operation \"issues.create\" on provider account \"forge\"",
        "  - \"db-password\" in sandbox \"main\": May exist in guest; cannot authorize host or \
         external privileges",
        "Removed or unavailable:\n  none",
    ] {
        assert!(
            rendered.contains(expected),
            "missing {expected:?} in\n{rendered}"
        );
    }
    assert!(rendered.contains(&format!("- {} [required; private data]", read_inputs())));
    assert!(rendered.contains(&format!("- {} [optional]", connect_registry())));
}

#[test]
fn vm_p46_private_data_ongoing_delegation_and_exact_release_are_kept_apart() {
    let evaluation = planned_evaluation();
    let preview = evaluation.preview(&[], Some(E1), None);
    let only = |lines: &[ApprovalLine], kind: ApprovalKind, tuple: PermissionTuple| {
        assert_eq!(
            lines,
            &[ApprovalLine {
                rule: rule(kind, &tuple),
                status: ApprovalStatus::Needed,
            }]
        );
    };
    only(
        &preview.approvals.private_data_access,
        ApprovalKind::PrivateDataAccess,
        read_inputs(),
    );
    only(
        &preview.approvals.ongoing_delegation,
        ApprovalKind::OngoingDelegation,
        create_issue(),
    );
    only(
        &preview.approvals.exact_release,
        ApprovalKind::ExactRelease,
        release_results(),
    );
    // Three separate groups in the JSON and three headings in the text, each holding only
    // its own kind.
    let json: Value = serde_json::from_str(&preview.to_json().unwrap()).unwrap();
    for group in ["private_data_access", "ongoing_delegation", "exact_release"] {
        let rules = json["approvals"][group].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["rule"]["kind"], json!(group));
    }
    let rendered = preview.render_text();
    let private = rendered.find("  Private-data access:").unwrap();
    let ongoing = rendered.find("  Ongoing delegation:").unwrap();
    let exact = rendered
        .find("  Exact release (bound to one payload digest, used once):")
        .unwrap();
    assert!(private < ongoing && ongoing < exact);
    let section = |from: usize, to: usize| &rendered[from..to];
    assert!(section(private, ongoing).contains("private-data access approval to read"));
    assert!(section(ongoing, exact).contains("ongoing delegation approval to perform"));
    assert!(rendered[exact..].contains("exact release approval to release through"));

    // Valid narrow grants at this authorization epoch are shown as given and not asked
    // again; at a new epoch they are needed again.
    let granted = evaluation.preview(&all_grants(E1), Some(E1), None);
    for line in granted
        .approvals
        .private_data_access
        .iter()
        .chain(&granted.approvals.ongoing_delegation)
        .chain(&granted.approvals.exact_release)
    {
        assert_eq!(line.status, ApprovalStatus::Granted);
    }
    assert!(granted
        .render_text()
        .contains("already granted for this authorization epoch"));
    assert!(!granted.render_text().contains(": needed"));
    let stale = evaluation.preview(&all_grants(E1), Some(E2), None);
    assert_eq!(
        stale.approvals.exact_release[0].status,
        ApprovalStatus::Needed
    );
    // The preview and the non-interactive decision judge approvals with one function.
    let needed = stale
        .approvals
        .private_data_access
        .iter()
        .chain(&stale.approvals.ongoing_delegation)
        .chain(&stale.approvals.exact_release)
        .filter(|line| line.status == ApprovalStatus::Needed)
        .count();
    let NonInteractiveDecision::Refuse { report } =
        evaluation.decide_non_interactive(&all_grants(E1), E2)
    else {
        panic!("stale grants must not count");
    };
    assert_eq!(report.refusals().len(), needed);
}

#[test]
fn an_approval_for_a_removed_capability_is_not_applicable() {
    let tuples = base_tuples();
    let granted: Vec<_> = tuples
        .iter()
        .filter(|tuple| **tuple != create_issue())
        .cloned()
        .collect();
    let mut value = base();
    value["capabilities"][4]["need"] = json!("optional");
    let evaluation = Host::ready()
        .evaluate(&text(&value), &product(&tuples), &delegation(&granted))
        .unwrap();
    let preview = evaluation.preview(&[], Some(E1), None);
    assert_eq!(
        preview.approvals.ongoing_delegation[0].status,
        ApprovalStatus::NotApplicable
    );
    assert_eq!(preview.removed[0].tuple, create_issue());
    assert_eq!(preview.removed[0].effect, RemovalEffect::Dropped);
}

#[test]
fn vm_p47_an_untrusted_request_never_overrides_host_policy_end_to_end() {
    let host = Host::ready();
    let tuples = base_tuples();
    // Broader rights: a route the product never permits, marked required. The request is
    // valid; the intersection removes the route, and planning refuses.
    let exfil = tuple(
        Operation::TransportConnect,
        ResourceKind::Route,
        "exfil.example.net:443",
        Phase::Analysis,
    );
    let mut capabilities = tuples_declaration_capabilities();
    capabilities.push(cap(
        "required",
        "analysis",
        json!({"kind": "connect", "destination": "exfil.example.net"}),
    ));
    let mut broad_delegation = tuples.clone();
    broad_delegation.push(exfil.clone());
    let evaluation = host
        .evaluate(
            &text(&declaration(capabilities)),
            &product(&tuples),
            &delegation(&broad_delegation),
        )
        .unwrap();
    assert!(!evaluation.resolved().permitted().covers(&exfil));
    let preview = evaluation.preview(&[], None, None);
    assert_eq!(preview.decision, PreviewDecision::Refused);
    assert_eq!(
        preview.removed,
        vec![RemovedLine {
            tuple: exfil.clone(),
            need: Need::Required,
            excluded_by: BTreeSet::from([PolicyLayer::ProductCeiling]),
            effect: RemovalEffect::LaunchRefused,
        }]
    );
    assert_eq!(
        preview.refusals[0].code,
        RefusalCode::RequiredAuthorityRemoved
    );

    // An omitted requirement: the declaration lists none, the product requires an
    // independent perimeter, and that requirement stays in force and unmet.
    let strict = product_with(
        &tuples,
        &[
            SecurityPredicate::VmSandbox,
            SecurityPredicate::IndependentPerimeter,
        ],
        Vec::new(),
    );
    let mut value = base();
    value["requires"] = json!([]);
    let evaluation = host
        .evaluate(&text(&value), &strict, &delegation(&tuples))
        .unwrap();
    assert!(evaluation
        .resolved()
        .requirements()
        .contains(SecurityPredicate::IndependentPerimeter));
    let preview = evaluation.preview(&[], None, None);
    let network = preview
        .facets
        .iter()
        .find(|facet| facet.facet == DeploymentFacet::NetworkAuthority)
        .unwrap();
    let perimeter = network
        .requirements
        .iter()
        .find(|line| line.predicate == SecurityPredicate::IndependentPerimeter)
        .unwrap();
    assert_eq!(perimeter.status, VerdictStatus::Unmet);
    assert_eq!(perimeter.judged_by, JudgedBy::HostEvidence);
    assert_eq!(preview.decision, PreviewDecision::Refused);

    // An unknown version and an unknown requirement are refused before resolution.
    let mut future = base();
    future["declaration_version"] = json!(2);
    let report = host
        .evaluate(&text(&future), &product(&tuples), &delegation(&tuples))
        .unwrap_err();
    assert_eq!(
        report.codes(),
        vec![RefusalCode::UnsupportedDeclarationVersion]
    );
    let mut unknown = base();
    unknown["requires"] = json!(["always_safe"]);
    let report = host
        .evaluate(&text(&unknown), &product(&tuples), &delegation(&tuples))
        .unwrap_err();
    assert_eq!(report.codes(), vec![RefusalCode::UnknownRequirement]);

    // Requiring a host predicate is never the same as meeting it: on a labelled runtime the
    // VM requirement stays unmet.
    let mut claims = base();
    claims["requires"] = json!(["vm_sandbox", "hardware_hypervisor_available"]);
    let labelled = Host::running(ExecutionCategory::ProviderContainerRuntime);
    let evaluation = labelled
        .evaluate(&text(&claims), &product(&tuples), &delegation(&tuples))
        .unwrap();
    let preview = evaluation.preview(&[], None, None);
    let vm = preview.facets[0]
        .requirements
        .iter()
        .find(|line| line.predicate == SecurityPredicate::VmSandbox)
        .unwrap();
    assert_eq!(vm.status, VerdictStatus::Unmet);
    assert!(preview.runs[0].observed_runtime.is_none());
}

fn tuples_declaration_capabilities() -> Vec<Value> {
    super::tests::base_capabilities()
}

#[test]
fn facets_are_listed_one_by_one_with_verdicts_and_never_scored() {
    let preview = planned_evaluation().preview(&[], None, None);
    let facets: Vec<DeploymentFacet> = preview.facets.iter().map(|view| view.facet).collect();
    assert_eq!(facets, DeploymentFacet::ALL.to_vec());
    let mut predicates = BTreeSet::new();
    for view in &preview.facets {
        for line in &view.requirements {
            assert_eq!(line.predicate.facet(), view.facet);
            assert_eq!(line.status, VerdictStatus::Met);
            assert!(!line.reason.is_empty());
            predicates.insert(line.predicate);
        }
    }
    assert_eq!(
        predicates,
        BTreeSet::from([
            SecurityPredicate::VmSandbox,
            SecurityPredicate::HardwareHypervisorAvailable,
            SecurityPredicate::ContractNoExternalCredentials,
            SecurityPredicate::ContractEphemeralState,
            SecurityPredicate::ContractBoundedLifetime,
            SecurityPredicate::ContractCpuOnly,
        ])
    );
    let mut found = BTreeSet::new();
    keys(&serde_json::to_value(&preview).unwrap(), &mut found);
    for forbidden in ["score", "tier", "level", "rank", "rating", "grade", "total"] {
        assert!(!found.contains(forbidden), "{forbidden}");
    }
    let rendered = preview.render_text();
    assert!(rendered
        .contains("Requirements by facet (each judged on its own; never combined into a score):"));
    for facet in DeploymentFacet::ALL {
        assert!(rendered.contains(&format!("\n  {facet}:\n")));
    }
    // A facet without a requirement is listed as such, not left out.
    assert!(rendered.contains("  operator confidentiality:\n    none\n"));
    assert!(rendered.contains("- vm_sandbox (host evidence): met; verified by a host probe"));
    assert!(
        rendered.contains("- contract_cpu_only (contract): met; the contract has this property")
    );
}

#[test]
fn a_refused_preview_marks_each_requirement_met_or_unmet_with_why() {
    let host = Host::ready();
    let gpu = tuple(
        Operation::DeviceUse,
        ResourceKind::Device,
        "gpu0",
        Phase::Analysis,
    );
    let value = declaration(vec![cap(
        "required",
        "analysis",
        json!({"kind": "gpu", "device": "gpu0"}),
    )]);
    let evaluation = host
        .evaluate(
            &text(&value),
            &product(std::slice::from_ref(&gpu)),
            &delegation(std::slice::from_ref(&gpu)),
        )
        .unwrap();
    let preview = evaluation.preview(&[], None, None);
    assert_eq!(preview.decision, PreviewDecision::Refused);
    assert_eq!(tuples_of(&preview.devices), BTreeSet::from([gpu]));
    let verdict = |predicate: SecurityPredicate| {
        preview
            .facets
            .iter()
            .flat_map(|facet| facet.requirements.iter())
            .find(|line| line.predicate == predicate)
            .unwrap()
            .clone()
    };
    let isolation = verdict(SecurityPredicate::AssignedGpuIsolated);
    assert_eq!(isolation.status, VerdictStatus::Unmet);
    assert!(isolation
        .reason
        .contains("no evidence capability observes it yet"));
    let vm = verdict(SecurityPredicate::VmSandbox);
    assert_eq!(vm.status, VerdictStatus::Met);
    assert_eq!(
        vm.reason,
        "verified by host evidence when the launch was planned"
    );
    let offline = verdict(SecurityPredicate::ContractOffline);
    assert_eq!(
        (offline.status, offline.judged_by),
        (VerdictStatus::Met, JudgedBy::Contract)
    );
    assert_eq!(preview.refusals.len(), 1);
    assert!(preview.render_text().contains("[requirement_unmet] "));
}

#[test]
fn an_unplanned_preview_judges_only_the_contract() {
    let evaluation = planned_evaluation();
    let preview = PolicyPreview::build(&PreviewInputs {
        context: evaluation.compiled().context(),
        request: evaluation.request(),
        outcome: LaunchOutcome::not_planned(evaluation.resolved()),
        grants: &[],
        epoch: None,
        issuer: None,
    });
    assert_eq!(preview.decision, PreviewDecision::NotPlanned);
    for line in preview
        .facets
        .iter()
        .flat_map(|facet| facet.requirements.iter())
    {
        match line.judged_by {
            JudgedBy::HostEvidence => assert_eq!(line.status, VerdictStatus::NotChecked),
            JudgedBy::Contract => assert_eq!(line.status, VerdictStatus::Met),
        }
    }
    assert!(preview.runs[0].observed_runtime.is_none());
    assert!(preview
        .render_text()
        .contains("Decision: not planned; host evidence has not been checked"));
}

#[test]
fn text_and_json_are_two_forms_of_one_value() {
    let tuples = base_tuples();
    let host = Host::ready();
    let planned = planned_evaluation();
    let refused = host
        .evaluate(&text(&base()), &product(&tuples[..2]), &delegation(&tuples))
        .unwrap();
    assert!(refused.launch().is_err());
    let previews = [
        planned.preview(&[], Some(E1), Some(IssuerIdentity::named("host-admin"))),
        refused.preview(&[], None, None),
        PolicyPreview::build(&PreviewInputs {
            context: planned.compiled().context(),
            request: planned.request(),
            outcome: LaunchOutcome::not_planned(planned.resolved()),
            grants: &[],
            epoch: None,
            issuer: None,
        }),
    ];
    for preview in previews {
        // Deterministic: the same inputs give the same value and the same text.
        let json = preview.to_json().unwrap();
        let read_back = PolicyPreview::from_json(&json).unwrap();
        assert_eq!(read_back, preview);
        // A UI that reads the JSON and a CLI that prints the text show the same thing.
        assert_eq!(read_back.render_text(), preview.render_text());
        let rendered = preview.render_text();
        assert!(!rendered.contains('\r'));
        for refusal in &preview.refusals {
            assert!(rendered.contains(&refusal.render_text()));
        }
        for line in preview
            .reads
            .iter()
            .chain(&preview.writes)
            .chain(&preview.releases)
            .chain(&preview.devices)
        {
            assert!(rendered.contains(&line.tuple.to_string()));
        }
        for removed in &preview.removed {
            assert!(rendered.contains(&removed.tuple.to_string()));
        }
        for budget in &preview.budgets {
            assert!(rendered.contains(&format!("- {}: {}", budget.key, budget.limit)));
        }
        // A changed version, an unknown field or a missing section is refused.
        let mut value: Value = serde_json::from_str(&json).unwrap();
        value["preview_version"] = json!(2);
        assert!(serde_json::from_value::<PolicyPreview>(value).is_err());
        let mut value: Value = serde_json::from_str(&json).unwrap();
        value["score"] = json!(10);
        assert!(serde_json::from_value::<PolicyPreview>(value).is_err());
        let mut value: Value = serde_json::from_str(&json).unwrap();
        value.as_object_mut().unwrap().remove("facets");
        assert!(serde_json::from_value::<PolicyPreview>(value).is_err());
    }
    // Two independent builds of one evaluation agree byte for byte.
    assert_eq!(
        planned.preview(&[], None, None).to_json().unwrap(),
        planned.preview(&[], None, None).to_json().unwrap()
    );
}

#[test]
fn a_preview_identifies_the_contract_and_issuer_and_never_claims_enforcement() {
    let evaluation = planned_evaluation();
    let issuer = IssuerIdentity::named("host-admin");
    let preview = evaluation.preview(&[], None, Some(issuer));
    assert_eq!(
        preview.contract.digest,
        evaluation.resolved().identity().digest()
    );
    assert_eq!(preview.issuer.unwrap().digest, issuer.digest());
    let json: Value = serde_json::to_value(&preview).unwrap();
    assert_eq!(json["contract"]["meaning"], json!(ContractMeaning::TEXT));
    assert_eq!(json["issuer"]["meaning"], json!(IssuerMeaning::TEXT));
    assert_eq!(json["notice"], json!(PreviewNotice::TEXT));
    // Every mention of enforcement in the text is a denial.
    let rendered = preview.render_text();
    for line in rendered.lines().filter(|line| line.contains("enforc")) {
        assert!(line.contains("not evidence that"), "{line}");
    }
    assert!(rendered.contains("Contract: ".to_owned().as_str()));
    assert!(rendered.contains(&format!("  {}", ContractMeaning::TEXT)));
    assert!(rendered.contains(&format!("  {}", IssuerMeaning::TEXT)));
    // A stored preview cannot be edited into a claim.
    for (pointer, claim) in [
        ("/contract/meaning", "proves the contract is enforced"),
        ("/issuer/meaning", "a trusted issuer guarantees enforcement"),
        ("/notice", "Enforced by the VM."),
    ] {
        let mut value = json.clone();
        *value.pointer_mut(pointer).unwrap() = json!(claim);
        assert!(serde_json::from_value::<PolicyPreview>(value).is_err());
    }
}

#[test]
fn a_launch_outcome_must_belong_to_its_contract() {
    let tuples = base_tuples();
    let host = Host::ready();
    let planned = planned_evaluation();
    let refused = host
        .evaluate(&text(&base()), &product(&tuples[..2]), &delegation(&tuples))
        .unwrap();
    let refusal = refused.launch().as_ref().unwrap_err();
    let mismatch = LaunchOutcome::refused(planned.resolved(), refusal).unwrap_err();
    assert_eq!(mismatch.planned, refusal.contract);
    assert_eq!(mismatch.resolved, planned.resolved().identity());
    assert!(LaunchOutcome::from_result(refused.resolved(), planned.launch()).is_err());
    assert!(LaunchOutcome::from_result(refused.resolved(), refused.launch()).is_ok());
    assert!(LaunchOutcome::from_result(planned.resolved(), planned.launch()).is_ok());
}

#[test]
fn credentials_are_shown_with_their_section_4_5_terms() {
    let token = tuple(
        Operation::ReceiveExternalCredential,
        ResourceKind::Credential,
        "upload-token",
        Phase::Analysis,
    );
    let value = declaration(vec![cap(
        "required",
        "analysis",
        json!({
            "kind": "short_lived_credential", "name": "upload-token",
            "audience": "uploads.example.com", "scope": "objects.put", "expires_in_seconds": 900,
            "delegated_effects": 20
        }),
    )]);
    let evaluation = Host::ready()
        .evaluate(
            &text(&value),
            &product(std::slice::from_ref(&token)),
            &delegation(std::slice::from_ref(&token)),
        )
        .unwrap();
    let preview = evaluation.preview(&[], None, None);
    let [credential] = preview.credentials.as_slice() else {
        panic!("one credential");
    };
    assert_eq!(credential.access.tuple, token);
    let terms = credential.terms.as_ref().unwrap();
    assert_eq!(terms.class, CredentialClass::ShortLivedExternalCapability);
    assert!(preview.render_text().contains(
        "[short-lived external capability; audience uploads.example.com; scope objects.put; \
         expires 900 s after issue; delegates at most 20 external effects; Scope, audience, \
         expiry and delegated budget explicit; still a credential]"
    ));
}

#[test]
fn vm_p03_the_preview_exposes_only_what_was_declared_and_permitted() {
    // The product and delegation permit more than the tool asked for, including a host
    // file grant; none of it appears, because permitted = ceiling ∩ requested ∩ delegated.
    let mut wide = base_tuples();
    let host_home = tuple(
        Operation::FileRead,
        ResourceKind::FileGrant,
        "host-home",
        Phase::Analysis,
    );
    let usb = tuple(
        Operation::DeviceUse,
        ResourceKind::Device,
        "usb0",
        Phase::Analysis,
    );
    wide.push(host_home.clone());
    wide.push(usb.clone());
    let evaluation = Host::ready()
        .evaluate(&text(&base()), &product(&wide), &delegation(&wide))
        .unwrap();
    let preview = evaluation.preview(&[], None, None);
    let shown: BTreeSet<PermissionTuple> = preview
        .reads
        .iter()
        .chain(&preview.writes)
        .chain(&preview.releases)
        .chain(&preview.devices)
        .chain(preview.credentials.iter().map(|line| &line.access))
        .map(|line| line.tuple.clone())
        .collect();
    assert_eq!(
        shown,
        evaluation
            .resolved()
            .permitted()
            .iter()
            .collect::<BTreeSet<_>>()
    );
    assert!(!shown.contains(&host_home) && !shown.contains(&usb));
    let requested: PermissionSet = evaluation.request().requested().clone();
    assert!(shown.iter().all(|tuple| requested.covers(tuple)));
    // And the same request against the narrow policy resolves identically.
    let narrow = base_tuples();
    let request = Validator::request(evaluation.compiled().document()).unwrap();
    assert_eq!(
        resolve(&product(&narrow), &request, &delegation(&narrow)).permitted(),
        evaluation.resolved().permitted()
    );
}
