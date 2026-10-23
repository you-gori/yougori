//! What the research realm must hold true. Each of these is a Phase 6 exit gate or a claim from
//! the threat model, and none of them starts a worker, a container, a machine or a network
//! connection: the whole profile is a database, a document and a seam, and the seam is tested with
//! a stub that records what it was handed and starts nothing.
use super::*;
use crate::core::{
    approval::Verdict,
    capability::{Attempt, Claims},
    identity::{PrincipalKind, Role},
    realm::{Capability, NetworkPolicy, RealmKind},
    work::{Commitment, GpuIsolation, Resources, Stage},
    Core,
};
use std::path::Path;

fn research_key() -> String {
    "a".repeat(64)
}

fn company_key() -> String {
    "b".repeat(64)
}

fn plenty() -> Resources {
    Resources { cpu: 16.0, memory_gb: 64.0, disk_gb: 500.0, gpu: true, vram_gb: 24.0 }
}

fn modest() -> Resources {
    Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 20.0, gpu: false, vram_gb: 0.0 }
}

fn manifest() -> Vec<SourceFile> {
    vec![
        SourceFile { path: "src/main.rs".into(), sha256: "1".repeat(64), bytes: 400 },
        SourceFile { path: "Cargo.toml".into(), sha256: "2".repeat(64), bytes: 120 },
    ]
}

/// Everybody a research grid needs: a researcher, somebody who can agree to things, a security
/// administrator, a computer and a host offering it.
struct Grid {
    core: Core,
    researcher: String,
    approver: String,
    admin: String,
    device: String,
    host: String,
}

fn research_grid(folder: &Path, now: i64) -> Grid {
    let mut core = Core::create(&folder.join("research.db"), "Study", RealmKind::Research, &[Capability::Research], &research_key(), now).unwrap();
    let researcher = core.add_principal("owner", PrincipalKind::Person, "Rae", &[Role::Researcher], now).unwrap().id;
    let approver = core.add_principal("owner", PrincipalKind::Person, "Ivo", &[Role::ResearchApprover], now).unwrap().id;
    let admin = core.add_principal("owner", PrincipalKind::Person, "Sam", &[Role::SecurityAdmin], now).unwrap().id;
    let (device, _) = core.enrol_device(&researcher, "Lab PC", "linux", now).unwrap();
    let host = core.offer_host(&device.id, "Lab PC", plenty(), plenty(), Commitment::Dedicated, now).unwrap();
    Grid { core, researcher, approver, admin, device: device.id, host: host.id }
}

/// A frozen scope, with the second person's agreement over its authorisation that freezing needs.
fn frozen_scope(grid: &mut Grid, limits: Limits, now: i64) -> Scope {
    let scope = grid
        .core
        .add_scope(
            &grid.researcher,
            &format!("Vendor appliance {now}"),
            "Look for ways the appliance can be broken into",
            "We own this appliance and authorise this study of it, in writing, on 19 October 2026.",
            Classification::Confidential,
            limits,
            now,
        )
        .unwrap();
    let asked = grid.core.ask_to_freeze(&grid.researcher, &scope.id, 600, now).unwrap();
    grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Once, now).unwrap();
    grid.core.freeze_scope(&grid.researcher, &scope.id, &asked.id, now).unwrap()
}

/// Lets one thing in, through the one approval path there is.
fn admit(grid: &mut Grid, scope_id: &str, kind: Admission, subject: &str, now: i64) -> Admitted {
    let asked = grid.core.ask_to_admit(&grid.researcher, scope_id, kind, subject, None, 600, now).unwrap();
    grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Once, now).unwrap();
    grid.core.admit_to_scope(&grid.approver, scope_id, kind, subject, &asked.id, None, now).unwrap()
}

/// A scope with material acquired and checked under it.
fn with_source(grid: &mut Grid, limits: Limits, now: i64) -> (Scope, Source) {
    let scope = frozen_scope(grid, limits, now);
    let admitted = admit(grid, &scope.id, Admission::Repository, "vendor/appliance", now);
    let source = grid
        .core
        .acquire_source(&grid.researcher, &scope.id, Origin::Repository, "vendor/appliance", "v2.1", &manifest(), &admitted.id, now)
        .unwrap();
    grid.core.verify_source(&grid.researcher, &source.id, &manifest(), now).unwrap();
    (scope, grid.core.source(&source.id).unwrap().unwrap())
}

/// A run that has been given a computer and has started.
fn running(grid: &mut Grid, scope: &Scope, source: &Source, now: i64) -> String {
    let work = grid.core.submit_research(&grid.researcher, &grid.device, &scope.id, Some(&source.id), Activity::Execute, modest(), now).unwrap();
    let lease = grid.core.grant_research_lease(&work.id, now).unwrap();
    grid.core.advance(&lease.id, Stage::Preparing, now).unwrap();
    grid.core.advance(&lease.id, Stage::Running, now).unwrap();
    work.id
}

/// A finding somebody else accepted, resting on one artifact somebody looked at and called clean.
fn accepted_finding(grid: &mut Grid, scope: &Scope, source: &Source, work_id: &str, now: i64) -> Finding {
    let artifact = grid
        .core
        .record_artifact(&grid.researcher, work_id, Some(&source.id), "crash.trace", "application/json", &"c".repeat(64), 2_048, now)
        .unwrap();
    grid.core.record_look(&grid.approver, &artifact.id, Scan::Clean, "read by hand", "no credentials and no personal data in it", now).unwrap();
    let finding = grid
        .core
        .record_finding(&grid.researcher, work_id, &source.id, "The console accepts a long name", "console", "A long name is written past the end of a buffer", Severity::High, &[artifact.id], now)
        .unwrap();
    grid.core.submit_finding(&grid.researcher, &finding.id, now).unwrap();
    let asked = grid.core.ask_to_review(&grid.researcher, &finding.id, 600, now).unwrap();
    grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Once, now).unwrap();
    grid.core.settle_finding(&grid.researcher, &finding.id, now).unwrap();
    let _ = scope;
    grid.core.finding(&finding.id).unwrap().unwrap()
}

/// A company grid, with somebody who may accept a research result and somebody else who agrees.
fn company_grid(folder: &Path, now: i64) -> (Core, String, String) {
    let mut core = Core::create(&folder.join("company.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Credentials], &company_key(), now).unwrap();
    let keeper = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::RealmAdmin], now).unwrap().id;
    let agrees = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::ResearchApprover], now).unwrap().id;
    (core, keeper, agrees)
}

/// An enclosure that records what it was handed and starts nothing at all. This is the whole of
/// how isolated execution is proven here: the core writes a plan, and something outside it would
/// build a container, a microVM, a machine or a GPU sandbox from that plan. Whether such an
/// enclosure actually holds is not a thing a Rust test can show, and this does not claim to.
#[derive(Default)]
struct Recorder {
    built: std::sync::Mutex<Vec<Plan>>,
    doing: std::sync::Mutex<Vec<String>>,
}

impl Enclosure for Recorder {
    fn build(&self, plan: &Plan) -> Result<String, String> {
        self.built.lock().unwrap().push(plan.clone());
        self.doing.lock().unwrap().push("build".into());
        Ok(format!("enclosure-for-{}", plan.workload_id))
    }
    fn start(&self, id: &str) -> Result<(), String> {
        self.doing.lock().unwrap().push(format!("start {id}"));
        Ok(())
    }
    fn stop(&self, id: &str) -> Result<(), String> {
        self.doing.lock().unwrap().push(format!("stop {id}"));
        Ok(())
    }
    fn collected(&self, _id: &str) -> Result<Vec<ArtifactRecord>, String> {
        self.doing.lock().unwrap().push("collected".into());
        Ok(vec![ArtifactRecord { name: "crash.trace".into(), media_type: "application/json".into(), sha256: "c".repeat(64), bytes: 2_048, scan: Scan::Pending }])
    }
    fn discard(&self, id: &str) -> Result<(), String> {
        self.doing.lock().unwrap().push(format!("discard {id}"));
        Ok(())
    }
}

#[test]
fn a_permission_from_the_research_grid_is_refused_by_the_company_grid_and_the_reverse() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_000;
    let mut grid = research_grid(folder.path(), now);
    let (mut company, keeper, _) = company_grid(folder.path(), now);
    let research_realm = grid.core.realm().id.clone();
    let company_realm = company.realm().id.clone();
    assert_ne!(research_realm, company_realm);

    // Minted in the research grid, offered to the company grid.
    let scope = frozen_scope(&mut grid, Limits::careful(), now);
    let claims = Claims::new(&research_realm, Capability::Research, &grid.researcher, &grid.device, "work-1", &scope.id, now, 60);
    let theirs = grid.core.mint(&claims).unwrap();
    let at_company = Attempt { realm_id: &company_realm, device_id: &grid.device, workload_id: "work-1", resource_id: &scope.id, ..Attempt::default() };
    assert!(company.accept(&theirs, &at_company, now).unwrap_err().contains("not issued by this grid"));

    // And the other way: minted in the company grid, offered to the research grid.
    let (device, _) = company.enrol_device(&keeper, "Ada's laptop", "windows", now).unwrap();
    let ours = company.mint(&Claims::new(&company_realm, Capability::Models, &keeper, &device.id, "work-2", "model-1", now, 60)).unwrap();
    let at_research = Attempt { realm_id: &research_realm, device_id: &device.id, workload_id: "work-2", resource_id: "model-1", ..Attempt::default() };
    assert!(grid.core.accept(&ours, &at_research, now).unwrap_err().contains("not issued by this grid"));

    // Both refusals are in the grid that refused, and in no other.
    assert!(company.snapshot().unwrap().audit.events.iter().any(|event| event.action == "capability.refused"));
    assert!(grid.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "capability.refused"));
}

#[test]
fn a_research_grid_cannot_reach_the_credential_broker() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_100;
    let mut grid = research_grid(folder.path(), now);
    let realm_id = grid.core.realm().id.clone();

    // The capability refuses it, even for the one caller every permission check lets through.
    let credential = crate::core::credential::Credential::new(&realm_id, "vendor api", crate::core::credential::Secret::ApiKey, "vendor-api", &"d".repeat(64), "https://api.vendor.test", &grid.researcher, now).unwrap();
    assert!(grid.core.add_credential("owner", credential, now).unwrap_err().contains("does not broker credentials"));

    // The broker refuses it before anything else happens.
    let ask = crate::core::broker::Ask {
        token: "whatever",
        realm_id: &realm_id,
        device_id: &grid.device,
        workload_id: "work-1",
        credential_id: "credential-1",
        method: "GET",
        url: "https://api.vendor.test/v1/things",
        headers: serde_json::Map::new(),
        body: Vec::new(),
    };
    assert!(grid.core.clear_to_send(&ask, now).unwrap_err().contains("does not broker credentials"));

    // And so does the database, for a row written with another tool.
    let path = grid.core.path().to_owned();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let written = connection.execute(
        "INSERT INTO credentials (id, realm_id, name, kind, vault_id, vault_version, fingerprint, destination, owner_id, created_at, generation)
         VALUES ('credential-1', ?1, 'vendor api', 'apiKey', 'vendor-api', 1, ?2, 'https://api.vendor.test', ?3, ?4, 1)",
        rusqlite::params![realm_id, "d".repeat(64), grid.researcher, now],
    );
    assert!(written.unwrap_err().to_string().contains("research grid cannot hold a company credential"));
}

#[test]
fn a_research_grid_cannot_address_the_companys_computers() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_200;
    let mut grid = research_grid(folder.path(), now);
    let scope = frozen_scope(&mut grid, Limits { outbound: true, ..Limits::careful() }, now);
    for company_address in [
        "https://10.0.0.8/api",
        "https://192.168.1.20:8443/api",
        "https://172.16.4.4/api",
        "https://127.0.0.1/api",
        "https://169.254.1.1/api",
        "https://[::1]/api",
        // The unspecified addresses are not private, loopback or link-local, and a connection to
        // either of them lands on the computer the enclosure is running on.
        "https://0.0.0.0:7465/api",
        "https://[::]:7465/api",
        "https://[::ffff:0.0.0.0]:7465/api",
        // IPv6 link-local only ever means a machine on the same link, the deprecated site-local
        // range beside it only ever meant a machine on the same site, and the deprecated
        // IPv4-compatible form is a company address written a second way.
        "https://[fe80::1]:8443/api",
        "https://[febf::1]:8443/api",
        "https://[fec0::1]:8443/api",
        "https://[::10.0.0.8]/api",
        "https://[::ffff:10.0.0.8]/api",
        "https://localhost/api",
        "https://hub.internal/api",
        "https://files.lan/api",
        "https://desk.local/api",
    ] {
        let refused = grid.core.ask_to_admit(&grid.researcher, &scope.id, Admission::Destination, company_address, None, 600, now);
        assert!(
            refused.as_ref().unwrap_err().contains("cannot address the company's own computers"),
            "{company_address} must be refused, and was {refused:?}"
        );
    }
    // Plain http is refused too, because the forwarder otherwise allows it for exactly the
    // addresses above and that would be the way back in.
    assert!(grid.core.ask_to_admit(&grid.researcher, &scope.id, Admission::Destination, "http://api.vendor.test/v1", None, 600, now).is_err());
    // An ordinary public address is still an address, written either way round. The rule is about
    // what an address can only ever mean, not about the shape it is written in.
    for outside in ["https://93.184.216.34/api", "https://[2606:2800:220:1:248:1893:25c8:1946]/api"] {
        assert_eq!(addressable(outside).unwrap(), outside, "an ordinary public address is still an address");
    }
    // Somewhere outside the company is let in through the ordinary agreement.
    let admitted = admit(&mut grid, &scope.id, Admission::Destination, "https://api.vendor.test/v1", now);
    assert_eq!(admitted.subject, "https://api.vendor.test/v1");
}

#[test]
fn the_brokers_egress_door_holds_a_research_grid_to_the_same_rules() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_250;
    let mut grid = research_grid(folder.path(), now);

    // There is one set of rules about what a research grid may reach, and the broker's door onto
    // the realm's policy asks them too. A second way in would be a way around them.
    assert!(grid.core.set_egress(&grid.admin, true, &[], now).unwrap_err().contains("empty list would mean anywhere"));
    assert!(grid.core.set_egress(&grid.admin, true, &["http://10.0.0.8:8080"], now).unwrap_err().contains("cannot address the company's own computers"));
    assert!(grid.core.set_egress(&grid.admin, true, &["https://api.vendor.test/v1"], now).unwrap_err().contains("has not been admitted"));
    assert_eq!(grid.core.realm().network, NetworkPolicy::offline(), "nothing that was refused was written");

    // What has been admitted to an open scope goes through this door exactly as through the other.
    let scope = frozen_scope(&mut grid, Limits { outbound: true, ..Limits::careful() }, now);
    admit(&mut grid, &scope.id, Admission::Destination, "https://api.vendor.test/v1", now);
    grid.core.set_egress(&grid.admin, true, &["https://api.vendor.test/v1"], now).unwrap();
    assert_eq!(grid.core.realm().network.destinations, vec!["https://api.vendor.test/v1".to_owned()]);
    grid.core.set_egress(&grid.admin, false, &[], now).unwrap();
    assert_eq!(grid.core.realm().network, NetworkPolicy::offline(), "a research grid that is not reaching out reaches nothing");
}

#[test]
fn an_agreement_given_for_something_other_than_research_lets_nothing_into_a_scope() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_260;
    let mut grid = research_grid(folder.path(), now);
    let elsewhere = grid.core.add_principal("owner", PrincipalKind::Person, "Cass", &[Role::CredentialApprover], now).unwrap().id;
    let scope = frozen_scope(&mut grid, Limits { outbound: true, ..Limits::careful() }, now);
    let subject = "https://api.vendor.test/v1";

    // Asked for under the credential action, so the people who may decide it are the ones who
    // approve credentials. Nothing in a research grid is theirs to agree to, and this is where
    // that holds: the request's own action is read back where the agreement would be spent.
    let crossed = grid
        .core
        .ask(&grid.researcher, Action::ApproveCredential, &format!("{}:destination:{subject}", scope.id), None, true, 600, now)
        .unwrap();
    grid.core.decide(&crossed.id, Action::ApproveCredential, &elsewhere, Verdict::Once, now).unwrap();
    let refused = grid.core.admit_to_scope(&grid.approver, &scope.id, Admission::Destination, subject, &crossed.id, None, now).unwrap_err();
    assert!(refused.contains("other than research"), "{refused}");
    assert!(grid.core.admitted(&scope.id, Admission::Destination, now).unwrap().is_empty());
    assert_eq!(grid.core.realm().network, NetworkPolicy::offline(), "and nothing was written into the realm's own policy");

    // A scope's authorisation cannot be frozen on one either.
    let second = grid
        .core
        .add_scope(&grid.researcher, "Second study", "Look again", "We own this and authorise the study.", Classification::Confidential, Limits::careful(), now)
        .unwrap();
    let digest = grid.core.scope(&second.id).unwrap().unwrap().authorisation_digest;
    let crossed = grid.core.ask(&grid.researcher, Action::ApproveCredential, &format!("{}:authorisation:{digest}", second.id), None, true, 600, now).unwrap();
    grid.core.decide(&crossed.id, Action::ApproveCredential, &elsewhere, Verdict::Once, now).unwrap();
    let refused = grid.core.freeze_scope(&grid.researcher, &second.id, &crossed.id, now).unwrap_err();
    assert!(refused.contains("other than research"), "{refused}");
    assert!(!grid.core.scope(&second.id).unwrap().unwrap().frozen());
}

#[test]
fn a_research_grid_is_offline_until_a_destination_is_admitted_and_an_empty_list_is_refused() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_300;
    let mut grid = research_grid(folder.path(), now);
    assert!(!grid.core.realm().network.outbound, "a research grid starts offline");

    let (scope, source) = with_source(&mut grid, Limits { outbound: true, ..Limits::careful() }, now);
    let work_id = running(&mut grid, &scope, &source, now);
    // With nothing admitted the plan the engine would build from carries no network at all.
    let plan = grid.core.plan_for(&work_id, Isolation::MicroVm, "/out", now).unwrap();
    assert_eq!(plan.network, NetworkPolicy::offline());
    assert!(grid.core.mint_research(&scope.id, &grid.researcher, &grid.device, &work_id, "https://api.vendor.test/v1", "GET", "/v1/things", 60, now).is_err());

    // An empty list with outbound on would mean anywhere, and is refused outright.
    let anywhere = NetworkPolicy { outbound: true, destinations: Vec::new(), published: false };
    assert!(grid.core.set_network(&grid.admin, anywhere, now).unwrap_err().contains("empty list would mean anywhere"));
    // So is a destination nobody admitted.
    let unadmitted = NetworkPolicy { outbound: true, destinations: vec!["https://elsewhere.test".into()], published: false };
    assert!(grid.core.set_network(&grid.admin, unadmitted, now).unwrap_err().contains("has not been admitted"));

    // Admitting one opens exactly that one, and the plan and the permission follow.
    let admitted = admit(&mut grid, &scope.id, Admission::Destination, "https://api.vendor.test/v1", now);
    assert_eq!(grid.core.realm().network.destinations, vec!["https://api.vendor.test/v1".to_owned()]);
    assert!(!grid.core.realm().network.allows("https://elsewhere.test"));
    let plan = grid.core.plan_for(&work_id, Isolation::MicroVm, "/out", now).unwrap();
    assert_eq!(plan.network.destinations, vec!["https://api.vendor.test/v1".to_owned()]);

    // A second scope's destination is in the realm's policy, because the policy is the union of
    // every open scope's admissions, and it is still not in this run's plan: a run under one scope
    // has no business reaching what was admitted to another.
    let other = frozen_scope(&mut grid, Limits { outbound: true, ..Limits::careful() }, now + 1);
    admit(&mut grid, &other.id, Admission::Destination, "https://api.other.test/v1", now + 1);
    assert_eq!(grid.core.realm().network.destinations.len(), 2);
    let plan = grid.core.plan_for(&work_id, Isolation::MicroVm, "/out", now).unwrap();
    assert_eq!(plan.network.destinations, vec!["https://api.vendor.test/v1".to_owned()]);
    assert!(grid.core.mint_research(&scope.id, &grid.researcher, &grid.device, &work_id, "https://api.other.test/v1", "GET", "/v1/things", 60, now).unwrap_err().contains("not been admitted to this scope"));

    let token = grid.core.mint_research(&scope.id, &grid.researcher, &grid.device, &work_id, "https://api.vendor.test/v1", "GET", "/v1/things", 60, now).unwrap();
    let attempt = Attempt {
        realm_id: &grid.core.realm().id.clone(),
        device_id: &grid.device,
        workload_id: &work_id,
        resource_id: &scope.id,
        destination: Some("https://api.vendor.test/v1"),
        method: Some("GET"),
        path: Some("/v1/things"),
        bytes: Some(10),
    };
    assert!(grid.core.accept(&token, &attempt, now).is_ok());

    // Taking it back out again closes the realm, and the permission minted a moment ago is
    // refused at its next use rather than lasting until it expires.
    let again = grid.core.mint_research(&scope.id, &grid.researcher, &grid.device, &work_id, "https://api.vendor.test/v1", "GET", "/v1/things", 60, now).unwrap();
    grid.core.withdraw_admission(&grid.approver, &admitted.id, "the study moved on", now + 2).unwrap();
    assert_eq!(grid.core.realm().network.destinations, vec!["https://api.other.test/v1".to_owned()], "what was taken back is gone, and what was not is left alone");
    assert!(!grid.core.realm().network.allows("https://api.vendor.test/v1"));
    assert!(grid.core.accept(&again, &attempt, now + 3).is_err());

    // And taking the last one back leaves the grid where it started: offline.
    let other_admission = grid.core.admitted(&other.id, Admission::Destination, now + 3).unwrap().into_iter().next().unwrap();
    grid.core.withdraw_admission(&grid.approver, &other_admission.id, "that study ended too", now + 3).unwrap();
    assert!(!grid.core.realm().network.outbound, "nothing admitted means offline again");
}

#[test]
fn no_standing_allowance_ever_covers_admitting_anything() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_400;
    let mut grid = research_grid(folder.path(), now);
    let scope = frozen_scope(&mut grid, Limits::careful(), now);
    let asked = grid.core.ask_to_admit(&grid.researcher, &scope.id, Admission::Tool, "ghidra", None, 600, now).unwrap();
    assert!(asked.every_time);
    let refused = grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Hours(4), now);
    assert!(refused.unwrap_err().contains("needs an approver every time"));
    grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Once, now).unwrap();
    assert!(grid.core.standing(&grid.researcher, &asked.resource_id, None, None, now).is_none());
    grid.core.admit_to_scope(&grid.approver, &scope.id, Admission::Tool, "ghidra", &asked.id, None, now).unwrap();

    // The same agreement cannot let a second thing in.
    let again = grid.core.admit_to_scope(&grid.approver, &scope.id, Admission::Tool, "ghidra", &asked.id, None, now);
    assert!(again.is_err());
}

#[test]
fn nobody_writes_their_own_authorisation_and_freezes_it_alone() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_500;
    let mut grid = research_grid(folder.path(), now);
    // Rae can approve research too, and so can Ivo. While Ivo could decide, Rae may not decide
    // her own request, so she cannot write an authorisation and freeze it by herself.
    grid.core.grant("owner", &grid.researcher, Role::ResearchApprover, now).unwrap();
    let scope = grid
        .core
        .add_scope(&grid.researcher, "Vendor appliance", "Look for flaws", "We own this appliance and authorise this study.", Classification::Internal, Limits::careful(), now)
        .unwrap();
    let asked = grid.core.ask_to_freeze(&grid.researcher, &scope.id, 600, now).unwrap();
    let herself = grid.core.decide(&asked.id, Action::ApproveResearch, &grid.researcher, Verdict::Once, now);
    assert!(herself.unwrap_err().contains("Someone else must agree"));
    assert!(grid.core.scope(&scope.id).unwrap().unwrap().digest.is_none(), "an unfrozen scope has no digest");

    // Work cannot be placed under a scope nobody has agreed to.
    assert!(grid.core.submit_research(&grid.researcher, &grid.device, &scope.id, None, Activity::Inspect, modest(), now).unwrap_err().contains("not open"));

    // Ivo agrees, and only then does the scope freeze and get its digest.
    grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Once, now).unwrap();
    let frozen = grid.core.freeze_scope(&grid.researcher, &scope.id, &asked.id, now).unwrap();
    assert_eq!(frozen.digest, Some(frozen.compute_digest()));
    assert_eq!(frozen.authorisation_approval_id, Some(asked.id.clone()));

    // An agreement given about another scope's words does not freeze this one.
    let other = grid
        .core
        .add_scope(&grid.researcher, "Another appliance", "Look for flaws", "Different words, different digest.", Classification::Internal, Limits::careful(), now)
        .unwrap();
    assert!(grid.core.freeze_scope(&grid.researcher, &other.id, &asked.id, now).unwrap_err().contains("for another scope or for other words"));

    // And a frozen scope cannot be edited into something else, whatever tool is used.
    let connection = rusqlite::Connection::open(grid.core.path()).unwrap();
    let edited = connection.execute("UPDATE research_scopes SET authorisation = 'something else' WHERE id = ?1", rusqlite::params![frozen.id]);
    assert!(edited.unwrap_err().to_string().contains("replaced by a new version"));
}

#[test]
fn research_is_done_by_a_named_person_and_never_by_the_grids_owner() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_600;
    let mut grid = research_grid(folder.path(), now);
    // "owner" passes the permission check everywhere else in the core, because a realm exists
    // before anybody is in it. Every research method refuses it in words rather than failing on a
    // foreign key with a message nobody can act on.
    let refused = grid.core.add_scope("owner", "Vendor appliance", "Look for flaws", "We own this.", Classification::Internal, Limits::careful(), now);
    assert!(refused.unwrap_err().contains("named person"));
    let scope = frozen_scope(&mut grid, Limits::careful(), now);
    assert!(grid.core.ask_to_admit("owner", &scope.id, Admission::Tool, "ghidra", None, 600, now).is_err());
    assert!(grid.core.quarantine_work("owner", "work-1", "because", now).is_err());
    assert!(grid.core.halt_scope("owner", &scope.id, "because", now).is_err());
    // And somebody who may place ordinary work still may not do research.
    let operator = grid.core.add_principal("owner", PrincipalKind::Person, "Opal", &[Role::Operator], now).unwrap().id;
    assert!(grid.core.add_scope(&operator, "Another", "Look", "We own this.", Classification::Internal, Limits::careful(), now).unwrap_err().contains("may not do research"));
}

#[test]
fn work_is_held_to_its_scopes_limits() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_700;
    let mut grid = research_grid(folder.path(), now);
    let limits = Limits { maximum_artifacts: 2, maximum_bytes: 4_096, maximum_files: 2, ..Limits::careful() };
    let (scope, source) = with_source(&mut grid, limits, now);

    // More than the scope allows is refused when the work is placed, not when it is running.
    let greedy = Resources { cpu: 64.0, memory_gb: 256.0, disk_gb: 900.0, gpu: false, vram_gb: 0.0 };
    assert!(grid.core.submit_research(&grid.researcher, &grid.device, &scope.id, Some(&source.id), Activity::Execute, greedy, now).is_err());
    let wants_a_card = Resources { gpu: true, ..modest() };
    assert!(grid.core.submit_research(&grid.researcher, &grid.device, &scope.id, Some(&source.id), Activity::Execute, wants_a_card, now).unwrap_err().contains("does not allow research to have a card"));

    // The reservation lasts as long as the scope says, not as long as a caller asks for.
    let work_id = running(&mut grid, &scope, &source, now);
    let lease = grid.core.snapshot().unwrap().leases.iter().find(|lease| lease.workload_id == work_id).cloned().unwrap();
    assert_eq!(lease.expires_at, now + limits.runtime_seconds);

    // The ceilings bind where the bytes actually arrive.
    grid.core.record_artifact(&grid.researcher, &work_id, Some(&source.id), "one.bin", "application/octet-stream", &"1".repeat(64), 2_048, now).unwrap();
    grid.core.record_artifact(&grid.researcher, &work_id, Some(&source.id), "two.bin", "application/octet-stream", &"2".repeat(64), 2_048, now).unwrap();
    let third = grid.core.record_artifact(&grid.researcher, &work_id, Some(&source.id), "three.bin", "application/octet-stream", &"3".repeat(64), 1, now);
    assert!(third.unwrap_err().contains("allows 2 artifacts"));

    // And a manifest larger than the scope allows is refused before anything is written.
    let admitted = grid.core.admissions(&scope.id).unwrap().into_iter().next().unwrap();
    let many: Vec<SourceFile> = (0..3).map(|at| SourceFile { path: format!("f{at}.rs"), sha256: "9".repeat(64), bytes: 1 }).collect();
    assert!(grid
        .core
        .acquire_source(&grid.researcher, &scope.id, Origin::Repository, "vendor/appliance", "v3", &many, &admitted.id, now)
        .unwrap_err()
        .contains("allows 2 files"));
}

#[test]
fn a_card_is_given_to_research_only_once_somebody_has_said_how_it_is_isolated() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_800;
    let mut grid = research_grid(folder.path(), now);
    let limits = Limits { resources: Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 100.0, gpu: true, vram_gb: 16.0 }, gpu_isolation: GpuIsolation::Partitioned, ..Limits::careful() };
    let (scope, source) = with_source(&mut grid, limits, now);
    let needs = Resources { cpu: 2.0, memory_gb: 8.0, disk_gb: 20.0, gpu: true, vram_gb: 8.0 };

    // Nothing has ever said how this computer's card is isolated, so research does not get it.
    let work = grid.core.submit_research(&grid.researcher, &grid.device, &scope.id, Some(&source.id), Activity::Execute, needs, now).unwrap();
    assert!(grid.core.grant_research_lease(&work.id, now).unwrap_err().contains("isolated well enough"));

    // Time slicing is not a boundary between tenants, so it is not enough either.
    grid.core.set_gpu_isolation(&grid.admin, &grid.host, GpuIsolation::TimeSliced, now).unwrap();
    assert!(grid.core.grant_research_lease(&work.id, now).unwrap_err().contains("isolated well enough"));

    // A named person asserts a hardware partition, and the record says it was asserted rather
    // than proved. Nothing in this grid attests it.
    grid.core.set_gpu_isolation(&grid.admin, &grid.host, GpuIsolation::Partitioned, now).unwrap();
    let said = grid.core.snapshot().unwrap().audit.events.iter().rev().find(|event| event.action == "host.gpu isolation").cloned().unwrap();
    assert!(said.reason.contains("asserted by a person"));
    let lease = grid.core.grant_research_lease(&work.id, now).unwrap();
    assert_eq!(lease.host_id, grid.host);
    let plan = grid.core.plan_for(&work.id, Isolation::GpuSandbox, "/out", now).unwrap();
    assert_eq!(plan.gpu_isolation, GpuIsolation::Partitioned);
}

#[test]
fn a_source_that_changed_after_it_was_acquired_is_quarantined() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_900;
    let mut grid = research_grid(folder.path(), now);
    let scope = frozen_scope(&mut grid, Limits::careful(), now);
    let admitted = admit(&mut grid, &scope.id, Admission::Repository, "vendor/appliance", now);
    let source = grid
        .core
        .acquire_source(&grid.researcher, &scope.id, Origin::Repository, "vendor/appliance", "v2.1", &manifest(), &admitted.id, now)
        .unwrap();
    assert_eq!(source.digest, manifest_digest(&manifest()));

    let mut altered = manifest();
    altered[0].sha256 = "f".repeat(64);
    let refused = grid.core.verify_source(&grid.researcher, &source.id, &altered, now);
    assert!(refused.unwrap_err().contains("src/main.rs"));
    let after = grid.core.source(&source.id).unwrap().unwrap();
    assert!(after.quarantined_at.is_some());
    assert!(!after.usable());
    assert!(grid.core.submit_research(&grid.researcher, &grid.device, &scope.id, Some(&source.id), Activity::Execute, modest(), now).unwrap_err().contains("quarantined"));
}

#[test]
fn a_dependency_that_does_not_match_its_lock_file_stops_the_work() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_000;
    let mut grid = research_grid(folder.path(), now);
    let (scope, source) = with_source(&mut grid, Limits::careful(), now);
    let substituted = Package::new(&source.id, "cargo", "serde", "1.0.0", &"a".repeat(64), Some(&"b".repeat(64)), now).unwrap();
    assert_eq!(substituted.state, Dependency::Mismatched);
    grid.core.record_dependencies(&grid.researcher, &source.id, &[substituted], now).unwrap();
    assert!(grid
        .core
        .submit_research(&grid.researcher, &grid.device, &scope.id, Some(&source.id), Activity::Execute, modest(), now)
        .unwrap_err()
        .contains("does not match its lock file"));

    // The same package, arriving as the lock file promised, lets the work through.
    let matching = Package::new(&source.id, "cargo", "serde", "1.0.0", &"a".repeat(64), Some(&"a".repeat(64)), now).unwrap();
    assert_eq!(matching.state, Dependency::Verified);
    grid.core.record_dependencies(&grid.researcher, &source.id, &[matching], now).unwrap();
    assert!(grid.core.submit_research(&grid.researcher, &grid.device, &scope.id, Some(&source.id), Activity::Execute, modest(), now).is_ok());
}

#[test]
fn a_stop_reaches_running_work_and_leaves_the_evidence() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_100;
    let mut grid = research_grid(folder.path(), now);
    let (scope, source) = with_source(&mut grid, Limits::careful(), now);
    let work_id = running(&mut grid, &scope, &source, now);
    let artifact = grid
        .core
        .record_artifact(&grid.researcher, &work_id, Some(&source.id), "crash.trace", "application/json", &"c".repeat(64), 2_048, now)
        .unwrap();
    // A run that has begun is draining, which Stage refuses to take to cancelled. A stop that
    // could not reach it would not be a stop.
    let leased = grid.core.store_for_tests().workload(&work_id).unwrap().unwrap().lease_id.unwrap();
    grid.core.advance(&leased, Stage::Draining, now).unwrap();
    let permission = grid.core.mint(&Claims::new(&grid.core.realm().id.clone(), Capability::Research, &grid.researcher, &grid.device, &work_id, &scope.id, now, 600)).unwrap();

    // The person holding the realm's stop switches can reach it too, which is what a stop switch
    // is for; it is not only the researcher's to pull.
    let stopped = grid.core.halt_scope(&grid.admin, &scope.id, "the owner withdrew the authorisation", now + 1).unwrap();
    assert_eq!(stopped, 1);
    let after = grid.core.snapshot().unwrap().workloads.iter().find(|work| work.id == work_id).cloned().unwrap();
    assert_eq!(after.stage, Stage::Quarantined, "a draining run is quarantined, not left running");
    assert!(after.stage.finished());

    // The evidence is all still there, and the computer is free again.
    assert_eq!(grid.core.research_artifacts(&scope.id).unwrap().len(), 1);
    assert_eq!(grid.core.artifact_record(&artifact.id).unwrap().unwrap().sha256, "c".repeat(64));
    assert!(grid.core.source(&source.id).unwrap().unwrap().id == source.id);
    assert_eq!(grid.core.free_on(&grid.host, now + 1), Some(plenty()));

    // And the permission the scope issued a moment ago is refused at its next use, without
    // anything having had to be found and deleted.
    let attempt = Attempt { realm_id: &grid.core.realm().id.clone(), device_id: &grid.device, workload_id: &work_id, resource_id: &scope.id, ..Attempt::default() };
    assert!(grid.core.accept(&permission, &attempt, now + 2).is_err());
    // The record says what happened and who decided it.
    assert!(grid.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "research.work.quarantined"));
    assert!(grid.core.verify_audit().is_ok());
}

#[test]
fn an_artifact_nobody_looked_at_cannot_cross() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_200;
    let mut grid = research_grid(folder.path(), now);
    let (scope, source) = with_source(&mut grid, Limits::careful(), now);
    let work_id = running(&mut grid, &scope, &source, now);
    let artifact = grid
        .core
        .record_artifact(&grid.researcher, &work_id, Some(&source.id), "crash.trace", "application/json", &"c".repeat(64), 2_048, now)
        .unwrap();
    assert_eq!(grid.core.scan_of(&artifact.id).unwrap(), Scan::Pending);
    let finding = grid
        .core
        .record_finding(&grid.researcher, &work_id, &source.id, "The console accepts a long name", "console", "A long name is written past the end", Severity::High, &[artifact.id.clone()], now)
        .unwrap();
    grid.core.submit_finding(&grid.researcher, &finding.id, now).unwrap();
    let asked = grid.core.ask_to_review(&grid.researcher, &finding.id, 600, now).unwrap();
    grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Once, now).unwrap();
    grid.core.settle_finding(&grid.researcher, &finding.id, now).unwrap();

    // Nobody has looked at the artifact, so nothing crosses.
    assert!(grid.core.seal_for_crossing(&grid.researcher, &finding.id, now).unwrap_err().contains("finds it clean"));
    // Somebody looks and flags it, which is still not clean.
    grid.core.record_look(&grid.approver, &artifact.id, Scan::Flagged, "yara 4.5.0", "it carries something that reads like a key", now).unwrap();
    assert!(grid.core.seal_for_crossing(&grid.researcher, &finding.id, now).unwrap_err().contains("finds it clean"));
    // A later look says otherwise, and both are kept: the first verdict is not erased.
    grid.core.record_look(&grid.approver, &artifact.id, Scan::Clean, "a person", "the key was a test fixture in the vendor's own repository", now).unwrap();
    assert_eq!(grid.core.looks(&artifact.id).unwrap().len(), 2);
    assert_eq!(grid.core.looks(&artifact.id).unwrap()[0].verdict, Scan::Flagged);
    assert_eq!(grid.core.scan_of(&artifact.id).unwrap(), Scan::Clean);
    assert!(grid.core.seal_for_crossing(&grid.researcher, &finding.id, now).is_ok());

    // A verdict stands as it was written, whatever tool opens the file.
    let connection = rusqlite::Connection::open(grid.core.path()).unwrap();
    let edited = connection.execute("UPDATE research_artifact_scans SET verdict = 'clean' WHERE verdict = 'flagged'", []);
    assert!(edited.unwrap_err().to_string().contains("cannot be changed"));
}

#[test]
fn a_finding_crosses_only_after_somebody_else_accepted_it_and_carries_no_key() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_300;
    let mut grid = research_grid(folder.path(), now);
    let (scope, source) = with_source(&mut grid, Limits::careful(), now);
    let work_id = running(&mut grid, &scope, &source, now);
    let artifact = grid
        .core
        .record_artifact(&grid.researcher, &work_id, Some(&source.id), "crash.trace", "application/json", &"c".repeat(64), 2_048, now)
        .unwrap();
    grid.core.record_look(&grid.approver, &artifact.id, Scan::Clean, "a person", "nothing of anybody's in it", now).unwrap();

    // A finding rests on evidence; one that rests on an assertion alone is refused.
    assert!(grid
        .core
        .record_finding(&grid.researcher, &work_id, &source.id, "Nothing to show", "console", "", Severity::Low, &[], now)
        .unwrap_err()
        .contains("rests on"));
    let finding = grid
        .core
        .record_finding(&grid.researcher, &work_id, &source.id, "The console accepts a long name", "console", "A long name is written past the end", Severity::High, &[artifact.id], now)
        .unwrap();

    // Nobody has reviewed it yet.
    grid.core.submit_finding(&grid.researcher, &finding.id, now).unwrap();
    assert!(grid.core.seal_for_crossing(&grid.researcher, &finding.id, now).unwrap_err().contains("somebody else has accepted it"));
    // The person who found it cannot accept it while anybody else could, because this is the
    // ordinary approval machinery and that rule already lives there.
    let asked = grid.core.ask_to_review(&grid.researcher, &finding.id, 600, now).unwrap();
    grid.core.grant("owner", &grid.researcher, Role::ResearchApprover, now).unwrap();
    assert!(grid.core.decide(&asked.id, Action::ApproveResearch, &grid.researcher, Verdict::Once, now).unwrap_err().contains("Someone else must agree"));
    grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Once, now).unwrap();
    grid.core.settle_finding(&grid.researcher, &finding.id, now).unwrap();
    let crossing = grid.core.seal_for_crossing(&grid.researcher, &finding.id, now).unwrap();

    // The document is whole, and it is sealed with the research grid's own key.
    assert!(crossing.intact().is_ok());
    assert!(crossing.sealed_by_key(&research_key()));
    assert!(!crossing.sealed_by_key(&company_key()));

    // It carries no key and no permission. The research grid's own key and a permission minted in
    // this grid are both looked for by value.
    let token = grid.core.mint(&Claims::new(&grid.core.realm().id.clone(), Capability::Research, &grid.researcher, &grid.device, &work_id, &scope.id, now, 60)).unwrap();
    let written = serde_json::to_string(&crossing).unwrap();
    for banned in [research_key(), token] {
        assert!(!written.contains(&banned), "a document that leaves a research grid carries no key and no permission");
    }
    // The fingerprint of that key is on it, deliberately: it lets an auditor tell one grid from
    // another, and it is a hash of the key rather than the key.
    assert_eq!(crossing.from_key_fingerprint, grid.core.realm().key_fingerprint);
    assert_ne!(crossing.from_key_fingerprint, research_key());
    // What it does carry is names, digests, sizes and the reviews it passed.
    assert_eq!(crossing.artifacts.len(), 1);
    assert_eq!(crossing.artifacts[0].sha256, "c".repeat(64));
    assert_eq!(crossing.source_digest, source.digest);
    assert!(crossing.reviews.iter().any(|review| review.granted && !review.self_issued));

    // Editing it breaks its own digest. That catches damage and transcription error, and not an
    // adversary, who recomputes the digest along with the edit; the seal is what they cannot
    // recompute, and only this grid can check that.
    let mut altered = crossing.clone();
    altered.finding.title = "Something else entirely".into();
    assert!(altered.intact().is_err());
    assert!(!altered.sealed_by_key(&research_key()));
    let mut forged = altered.clone();
    forged.digest = forged.compute_digest();
    assert!(forged.intact().is_ok(), "a keyless digest is recomputed by whoever edited the document");
    assert!(!forged.sealed_by_key(&research_key()), "the seal is what they cannot recompute");
}

#[test]
fn the_company_grid_records_its_own_decision_when_it_accepts_a_research_result() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_400;
    let mut grid = research_grid(folder.path(), now);
    let (scope, source) = with_source(&mut grid, Limits::careful(), now);
    let work_id = running(&mut grid, &scope, &source, now);
    let finding = accepted_finding(&mut grid, &scope, &source, &work_id, now);
    let crossing = grid.core.seal_for_crossing(&grid.researcher, &finding.id, now).unwrap();

    let (mut company, keeper, agrees) = company_grid(folder.path(), now);
    // Nothing is accepted on the research grid's authority: it takes a request in this grid,
    // decided by somebody other than the person accepting it.
    assert!(company.accept_crossing(&keeper, &crossing, "approval-nothing", "", now).is_err());
    let asked = company.ask(&keeper, Action::ApproveResearch, &crossing.digest, None, true, 600, now).unwrap();
    assert!(company.accept_crossing(&keeper, &crossing, &asked.id, "", now).unwrap_err().contains("has to agree"));
    company.decide(&asked.id, Action::ApproveResearch, &agrees, Verdict::Once, now).unwrap();
    let import = company.accept_crossing(&keeper, &crossing, &asked.id, "Worth fixing before the next release", now).unwrap();

    assert_eq!(import.crossing_digest, crossing.digest);
    assert_eq!(import.accepted_by, keeper);
    assert_eq!(import.artifacts, 1);
    assert!(import.stands());
    // Nothing of the research grid's people, computers or permissions came across.
    let record = company.snapshot().unwrap();
    assert!(record.principals.iter().all(|person| person.id != grid.researcher));
    assert!(record.devices.iter().all(|device| device.id != grid.device));
    assert!(company.verify_audit().is_ok());
    // The same document is never accepted twice.
    let again = company.ask(&keeper, Action::ApproveResearch, &crossing.digest, None, true, 600, now).unwrap();
    company.decide(&again.id, Action::ApproveResearch, &agrees, Verdict::Once, now).unwrap();
    assert!(company.accept_crossing(&keeper, &crossing, &again.id, "", now).unwrap_err().contains("already accepted"));

    // A research grid does not accept research results, and the database says so too.
    let refused = grid.core.accept_crossing(&grid.researcher, &crossing, &asked.id, "", now);
    assert!(refused.is_err());
    let connection = rusqlite::Connection::open(grid.core.path()).unwrap();
    let written = connection.execute(
        "INSERT INTO research_imports (id, realm_id, crossing_digest, from_realm_id, from_realm_name, from_key_fingerprint, scope_digest, source_digest, title, severity, artifacts, reviews, approval_id, accepted_by, accepted_at)
         VALUES ('import-1', ?1, ?2, 'realm-x', 'x', 'y', 'z', 'w', 't', 'low', 1, 1, ?3, ?4, ?5)",
        rusqlite::params![grid.core.realm().id, crossing.digest, asked.id, grid.researcher, now],
    );
    assert!(written.is_err());
}

#[test]
fn changing_the_source_or_the_scope_invalidates_acceptance() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_500;
    let mut grid = research_grid(folder.path(), now);
    let (scope, source) = with_source(&mut grid, Limits::careful(), now);
    let work_id = running(&mut grid, &scope, &source, now);
    let finding = accepted_finding(&mut grid, &scope, &source, &work_id, now);
    let crossing = grid.core.seal_for_crossing(&grid.researcher, &finding.id, now).unwrap();
    let (mut company, keeper, agrees) = company_grid(folder.path(), now);
    let asked = company.ask(&keeper, Action::ApproveResearch, &crossing.digest, None, true, 600, now).unwrap();
    company.decide(&asked.id, Action::ApproveResearch, &agrees, Verdict::Once, now).unwrap();
    company.accept_crossing(&keeper, &crossing, &asked.id, "", now).unwrap();

    // The material turns out to have changed. The research grid marks what it sealed as no longer
    // good and offers a notice, because it has no way to reach the company grid and should not.
    grid.core.quarantine_source(&grid.researcher, &source.id, "the vendor replaced the tag under us", now + 1).unwrap();
    let notices = grid.core.notices().unwrap();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].crossing_digest, crossing.digest);
    assert!(notices[0].reason.contains("the source changed"));

    // Somebody carries it, and the company grid sets its own acceptance aside. The acceptance
    // itself stands as it was made; what is written is the second row beside it.
    company.retract_import(&keeper, &notices[0].crossing_digest, &notices[0].reason, now + 2).unwrap();
    let import = company.imports().unwrap().into_iter().next().unwrap();
    assert!(!import.stands());
    assert_eq!(import.accepted_by, keeper);
    assert!(import.withdrawn_reason.contains("the source changed"));

    // Changing the scope does the same, and the new version starts again from a draft.
    let (scope_two, source_two) = with_source(&mut grid, Limits::careful(), now + 3);
    let work_two = running(&mut grid, &scope_two, &source_two, now + 3);
    let finding_two = accepted_finding(&mut grid, &scope_two, &source_two, &work_two, now + 3);
    let second = grid.core.seal_for_crossing(&grid.researcher, &finding_two.id, now + 3).unwrap();
    let next = grid
        .core
        .revise_scope(&grid.researcher, &scope_two.id, "Look again, with narrower limits", "We own this appliance and authorise a narrower study.", Classification::Confidential, Limits::careful(), now + 4)
        .unwrap();
    assert_eq!(next.version, scope_two.version + 1);
    assert_eq!(next.supersedes, Some(scope_two.id.clone()));
    assert!(!next.frozen(), "a new version is agreed to again before anything runs under it");
    assert!(grid.core.scope(&scope_two.id).unwrap().unwrap().closed_at.is_some());
    assert!(grid.core.notices().unwrap().iter().any(|notice| notice.crossing_digest == second.digest && notice.reason.contains("the scope changed")));
}

#[test]
fn a_research_backup_restores_with_its_own_key_and_carries_everything_it_held() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_600;
    let mut grid = research_grid(folder.path(), now);
    let (scope, source) = with_source(&mut grid, Limits::careful(), now);
    let work_id = running(&mut grid, &scope, &source, now);
    let finding = accepted_finding(&mut grid, &scope, &source, &work_id, now);
    let crossing = grid.core.seal_for_crossing(&grid.researcher, &finding.id, now).unwrap();
    grid.core.record_dependencies(&grid.researcher, &source.id, &[Package::new(&source.id, "cargo", "serde", "1.0.0", &"e".repeat(64), Some(&"e".repeat(64)), now).unwrap()], now).unwrap();
    let backup = grid.core.backup(now).unwrap();

    // The company's key is not this grid's key, and a backup carries neither.
    let written = serde_json::to_string(&backup).unwrap();
    assert!(!written.contains(&research_key()));
    assert!(Core::restore(&folder.path().join("wrong.db"), backup.clone(), &company_key()).is_err());

    let restored = Core::restore(&folder.path().join("restored.db"), backup, &research_key()).unwrap();
    assert_eq!(restored.realm().kind, RealmKind::Research);
    assert_eq!(restored.realm().capabilities, vec![Capability::Research]);
    assert!(!restored.realm().network.outbound, "a restored research grid is still offline");
    // Everything the profile held comes back, which is what the portable shape's research fields
    // are for: a restore that carried only the realm row would look like a working one.
    assert_eq!(restored.scopes().unwrap().len(), 1);
    assert_eq!(restored.scopes().unwrap()[0].digest, scope.digest);
    assert_eq!(restored.admissions(&scope.id).unwrap().len(), 1);
    assert_eq!(restored.sources(&scope.id).unwrap().len(), 1);
    assert_eq!(manifest_digest(&restored.source_files(&source.id).unwrap()), source.digest);
    assert_eq!(restored.dependencies(&source.id).unwrap().len(), 1);
    assert_eq!(restored.research_artifacts(&scope.id).unwrap().len(), 1);
    assert_eq!(restored.findings(&scope.id).unwrap().len(), 1);
    assert_eq!(restored.reviews_of(&finding.id).unwrap().len(), 1);
    assert_eq!(restored.crossings().unwrap().len(), 1);
    assert_eq!(restored.crossings().unwrap()[0].digest, crossing.digest);
    assert!(restored.verify_audit().is_ok());
}

#[test]
fn a_research_history_carries_out_and_resumes_where_it_left_off() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_700;
    let mut grid = research_grid(folder.path(), now);
    let (scope, source) = with_source(&mut grid, Limits::careful(), now);
    let early = grid.core.since(0).unwrap();
    assert!(!early.is_empty());
    let carried = early.last().unwrap().sequence;
    grid.core.exported("owner", carried, now).unwrap();

    // The grid goes on working with nothing to reach, and only the new events come out next time.
    let work_id = running(&mut grid, &scope, &source, now + 1);
    let later = grid.core.since(carried).unwrap();
    assert!(later.iter().all(|event| event.sequence > carried));
    assert!(later.iter().any(|event| event.workload_id.as_deref() == Some(work_id.as_str())));
    // The chain is still one unbroken chain afterwards.
    assert!(grid.core.verify_audit().is_ok());

    // An event nobody has carried out is not dropped, whatever tool opens the file.
    let connection = rusqlite::Connection::open(grid.core.path()).unwrap();
    let dropped = connection.execute("DELETE FROM audit_events WHERE sequence > ?1", rusqlite::params![carried as i64]);
    assert!(dropped.unwrap_err().to_string().contains("not been exported"));
}

#[test]
fn the_enclosure_is_handed_the_plan_and_the_core_starts_nothing() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_800;
    let mut grid = research_grid(folder.path(), now);
    let limits = Limits { maximum_artifacts: 4, ..Limits::careful() };
    let (scope, source) = with_source(&mut grid, limits, now);
    let work_id = running(&mut grid, &scope, &source, now);
    let plan = grid.core.plan_for(&work_id, Isolation::MicroVm, "/out", now).unwrap();

    // Everything the engine needs, and nothing it does not. There is no field here that reaches a
    // model: a plan says how much of a computer, for how long, what it may reach and where its
    // material is.
    assert_eq!(plan.scope_id, scope.id);
    assert_eq!(plan.scope_generation, scope.generation);
    assert_eq!(plan.classification, Classification::Confidential);
    assert_eq!(plan.source_digest, source.digest);
    assert_eq!(plan.network, NetworkPolicy::offline());
    assert_eq!(plan.runtime_seconds, limits.runtime_seconds);
    assert_eq!(plan.maximum_artifacts, 4);
    assert_eq!(plan.isolation, Isolation::MicroVm);

    // The stub is handed the plan and records what it was asked for. The core itself holds no
    // implementation of this trait and builds nothing.
    let recorder = Recorder::default();
    let id = recorder.build(&plan).unwrap();
    recorder.start(&id).unwrap();
    let collected = recorder.collected(&id).unwrap();
    recorder.stop(&id).unwrap();
    recorder.discard(&id).unwrap();
    assert_eq!(recorder.built.lock().unwrap().as_slice(), &[plan.clone()]);
    assert_eq!(recorder.doing.lock().unwrap().as_slice(), &["build".to_owned(), format!("start {id}"), "collected".to_owned(), format!("stop {id}"), format!("discard {id}")]);

    // What it says it produced becomes records in the realm, and nothing arrives unlooked-at.
    for record in &collected {
        let artifact = grid.core.record_artifact(&grid.researcher, &work_id, Some(&source.id), &record.name, &record.media_type, &record.sha256, record.bytes, now).unwrap();
        assert_eq!(grid.core.scan_of(&artifact.id).unwrap(), Scan::Pending);
    }
    assert_eq!(grid.core.research_artifacts(&scope.id).unwrap().len(), 1);
}

#[test]
fn artifacts_and_sources_are_kept_for_a_stated_time_and_let_go_of_with_a_reason() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_900;
    let mut grid = research_grid(folder.path(), now);
    let limits = Limits { retain_seconds: 60, ..Limits::careful() };
    let (scope, source) = with_source(&mut grid, limits, now);
    let work_id = running(&mut grid, &scope, &source, now);
    let artifact = grid
        .core
        .record_artifact(&grid.researcher, &work_id, Some(&source.id), "crash.trace", "application/json", &"c".repeat(64), 2_048, now)
        .unwrap();
    assert_eq!(artifact.retain_until, Some(now + 60));
    assert_eq!(grid.core.due_for_disposal(now).unwrap().0.len(), 0);
    let (artifacts, sources) = grid.core.due_for_disposal(now + 61).unwrap();
    assert_eq!(artifacts.len(), 1);
    assert_eq!(sources.len(), 1);

    // Nothing is dropped on a timer. Letting go of something is a decision somebody makes and a
    // row they write, and the record of what was produced stays where it is.
    grid.core.dispose_artifact(&grid.researcher, &artifact.id, "kept for the stated time and no longer needed", now + 62).unwrap();
    let after = grid.core.artifact_record(&artifact.id).unwrap().unwrap();
    assert!(after.disposed_at.is_some());
    assert!(after.disposed_reason.contains("no longer needed"));
    assert_eq!(after.sha256, "c".repeat(64));
    let connection = rusqlite::Connection::open(grid.core.path()).unwrap();
    let deleted = connection.execute("DELETE FROM research_artifacts WHERE id = ?1", rusqlite::params![artifact.id]);
    assert!(deleted.unwrap_err().to_string().contains("never deleted"));
}

#[test]
fn an_admission_that_simply_ran_out_leaves_the_grid_offline_again() {
    let folder = tempfile::tempdir().unwrap();
    let now = 12_000;
    let mut grid = research_grid(folder.path(), now);
    let scope = frozen_scope(&mut grid, Limits { outbound: true, ..Limits::careful() }, now);
    let asked = grid.core.ask_to_admit(&grid.researcher, &scope.id, Admission::Destination, "https://api.vendor.test/v1", None, 600, now).unwrap();
    grid.core.decide(&asked.id, Action::ApproveResearch, &grid.approver, Verdict::Once, now).unwrap();
    grid.core.admit_to_scope(&grid.approver, &scope.id, Admission::Destination, "https://api.vendor.test/v1", &asked.id, Some(now + 100), now).unwrap();
    assert!(grid.core.realm().network.allows("https://api.vendor.test/v1"));

    // An admission that lapses has to take the destination out of the stated policy with it, or
    // the policy and what was actually let in would disagree about what may be reached. The sweep
    // happens wherever a hub already lapses requests, so there is nothing extra to remember.
    grid.core.expire_approvals(now + 101);
    assert!(!grid.core.realm().network.outbound);
    assert!(grid.core.admitted(&scope.id, Admission::Destination, now + 101).unwrap().is_empty());
    // And the same thing can be let in again afterwards, through its own agreement.
    let again = admit(&mut grid, &scope.id, Admission::Destination, "https://api.vendor.test/v1", now + 102);
    assert!(again.live(now + 102));
}

#[test]
fn the_research_tables_hold_no_column_that_could_hold_a_value() {
    let folder = tempfile::tempdir().unwrap();
    let now = 12_100;
    let mut grid = research_grid(folder.path(), now);
    let (scope, _) = with_source(&mut grid, Limits::careful(), now);
    let _ = scope;
    let connection = rusqlite::Connection::open(grid.core.path()).unwrap();
    for table in [
        "research_scopes",
        "research_admissions",
        "research_sources",
        "research_source_files",
        "research_dependencies",
        "research_artifacts",
        "research_artifact_scans",
        "research_findings",
        "research_finding_artifacts",
        "research_reviews",
        "research_crossings",
        "research_imports",
    ] {
        let mut query = connection.prepare(&format!("SELECT name FROM pragma_table_info('{table}')")).unwrap();
        let columns: Vec<String> = query.query_map([], |row| row.get::<_, String>(0)).unwrap().map(Result::unwrap).collect();
        assert!(!columns.is_empty(), "{table} is part of this grid");
        for forbidden in ["value", "secret", "password", "token", "key", "material", "private_key", "cipher", "contents", "content", "body", "blob", "payload"] {
            assert!(!columns.iter().any(|column| column == forbidden), "{table} has no {forbidden}, and never will");
        }
    }
}

#[test]
fn version_six_can_be_taken_back_out_and_put_back() {
    let folder = tempfile::tempdir().unwrap();
    let now = 12_150;
    let mut grid = research_grid(folder.path(), now);
    let (scope, _) = with_source(&mut grid, Limits::careful(), now);
    let path = grid.core.path().to_owned();
    grid.core.close().unwrap();

    // Taking it back out leaves a grid a version five build can open. What that build cannot read
    // is the research profile, because it has no tables for it, and the runbook has to say that a
    // backup comes first: the sealed history still names every scope by id, and nothing else does.
    let mut store = crate::core::store::Store::open(&path).unwrap();
    store.roll_back(13).unwrap();
    store.roll_back(12).unwrap();
    store.roll_back(11).unwrap();
    store.roll_back(10).unwrap();
    store.roll_back(9).unwrap();
    store.roll_back(8).unwrap();
    store.roll_back(7).unwrap();
    store.roll_back(6).unwrap();
    assert_eq!(store.version().unwrap(), 5);
    assert!(store.scopes().unwrap_err().contains("research_scopes"));
    drop(store);

    // Opening it with this build runs the step again, and the realm is still the realm it was.
    let reopened = Core::open(&path, &research_key()).unwrap();
    assert_eq!(reopened.history().unwrap().len(), crate::core::store::SCHEMA_VERSION as usize);
    assert_eq!(reopened.realm().kind, RealmKind::Research);
    assert!(reopened.scopes().unwrap().is_empty(), "what version six held does not come back by itself");
    assert!(reopened.verify_audit().is_ok(), "and the history that named it is whole");
    let _ = scope;
}

#[test]
fn no_setting_in_this_profile_touches_a_models_behaviour() {
    // This is a containment boundary and nothing else. The research realm separates code, data,
    // keys and permissions; it does not and must not reach how any model behaves about a task.
    //
    // What this test proves is narrow and worth stating: it proves these words are absent from the
    // profile's own source and from the shape its database takes. It does not prove that a model
    // is safe, and nobody should read it as that. It is here so that a later change cannot quietly
    // turn a containment boundary into something else without somebody noticing.
    let profile = include_str!("../research.rs").to_ascii_lowercase();
    let shape = crate::core::store::schema::V6.to_ascii_lowercase();
    for banned in [
        "jailbreak",
        "uncensor",
        "bypass_safety",
        "bypasssafety",
        "disable_safety",
        "safety_off",
        "no_safety",
        "unrestricted_mode",
        "disable_guardrail",
        "ignore_refusal",
        "override_refusal",
        "no_refusal",
        "system_prompt",
        "unfiltered",
        "unaligned",
    ] {
        assert!(!profile.contains(banned), "the research profile has no {banned} setting, and a change that adds one fails here");
        assert!(!shape.contains(banned), "the research profile's database has no {banned} column, and a change that adds one fails here");
    }
    // And there is no model anywhere in it: a research realm holds no model plan, because
    // Capability::allowed_in refuses to put model serving and research in one realm.
    let folder = tempfile::tempdir().unwrap();
    let refused = Core::create(&folder.path().join("mixed.db"), "Mixed", RealmKind::Research, &[Capability::Research, Capability::Models], &research_key(), 12_200);
    assert!(refused.err().unwrap().contains("cannot serve models"));
}
