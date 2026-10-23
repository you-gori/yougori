//! The bridge from the shipped bounty host onto Grid Core's research profile.
//!
//! The host keeps one record: the bounty it published, the files that bounty is about, the
//! computers that joined to work it, and the findings they sent back. The core keeps a research
//! realm: a scope that says what may be researched under whose authorisation, the source acquired
//! under it with a manifest of every file, the computers that did the work, and the findings
//! recorded against the exact source they were found in. This turns one into the other, and can
//! turn it back.
//!
//! Nothing here changes the host's record. Every function takes it by reference. Nothing here
//! starts a worker, offers work, reaches a network or opens anything but the bytes it is given:
//! the only thing it does with the published files is decode and hash them, through the product's
//! own `bounty_project::snapshot`, so the manifest says what that component reported and not what
//! this one guessed.
//!
//! Three things are said out loud rather than quietly papered over:
//!
//! - **A research realm is a trust boundary of its own.** `Capability::allowed_in` refuses
//!   research in a company realm, and so does the realm's own database. This import refuses
//!   anything but a research realm, which the caller has already created with a key of its own;
//!   key custody is the application's decision and not this crate's.
//! - **The scope arrives as a draft.** A frozen scope is one a second person agreed to over its
//!   digest, and a bounty host has one administrator. So the scope comes across unfrozen, with the
//!   request that would let its source in still waiting, and nothing can be placed under it until
//!   somebody in the research realm decides that request and freezes it.
//! - **No worker's own files come across.** `swarm/workers.json`, `swarm/events/` and
//!   `swarm/receipts/` are written by the application, and the product deletes a worker's receipts
//!   with the worker on purpose. A bridge that carried them would be undoing a privacy measure.
use super::{
    observe::{Heading, Observation, Profile, Verdict},
    BountyRehearsal, Decided, Moved, Renamed, ResearchComparison, ResearchImported,
};
use crate::bounty;
use crate::core::{
    approval::{Approval, State},
    audit::{Decision, Entry},
    identity::{Action, Attestation, Device, Principal, PrincipalKind, Role},
    realm::{Capability, RealmKind},
    research::{Admission, Admitted, Classification, Finding, FindingState, Limits, Origin, Scope, Severity, Source, SourceFile},
    work::{Commitment, Host, Kind, Resources, Stage, Workload},
    Core,
};

/// The host's bounty as the core's own shapes, built in memory and written by nobody.
struct Translation {
    /// The account that stands for the host itself, which the scope and the source are recorded
    /// under, as the other bridges name theirs too.
    host_account: Principal,
    members: Vec<(String, Principal)>,
    devices: Vec<Device>,
    hosts: Vec<Host>,
    /// The hub's computer identifiers against the core's, in the record's own order.
    computers: Vec<(String, String)>,
    scope: Scope,
    /// The request that would let this source in, which nobody has decided.
    request: Approval,
    admitted: Admitted,
    source: Source,
    manifest: Vec<SourceFile>,
    work: Vec<Workload>,
    findings: Vec<(String, Finding)>,
    notes: Vec<String>,
}

/// The part of a host identifier that is its own, under the core's name for the same thing, so a
/// person looking at either can see they are the same thing and a migration can be traced without
/// keeping a table of what became what. The other bridges do exactly this.
fn same_tail(prefix: &str, legacy: &str) -> String {
    format!("{prefix}-{}", legacy.rsplit('-').next().unwrap_or(legacy))
}

fn name_of(raw: &str) -> String {
    crate::label(raw, "name").unwrap_or_else(|_| "Computer".to_owned())
}

/// A piece of text as eight hexadecimal characters, so two sides can be compared without the text
/// itself travelling. An observation never carries a title, a model's name or a path.
fn short(text: &str) -> String {
    crate::digest("bounty-observation", text)[..8].to_owned()
}

/// How bad a finding is, from the word the worker chose. The host takes any word at all, so
/// anything that is not one of the three the realm knows is unknown rather than guessed at.
fn severity_of(word: &str) -> Severity {
    match word.trim().to_ascii_lowercase().as_str() {
        "low" => Severity::Low,
        "medium" | "moderate" => Severity::Medium,
        "high" | "critical" => Severity::High,
        _ => Severity::Unknown,
    }
}

/// The scope's purpose and authorisation, from the bounty's own words.
///
/// A bounty's instruction and authorisation may each run to eight thousand characters and a
/// scope's are shorter, so anything past what a scope holds is left behind and counted. A bounty
/// that published neither says so in the scope rather than arriving with an empty authorisation,
/// because a scope with nothing in the owner's own words is one nobody could ever freeze.
fn words_of(text: &str, most: usize, instead: &str) -> (String, bool) {
    // A line break is the one control character a scope keeps, because a purpose and an
    // authorisation are both written as paragraphs. Everything else goes, including the tab and
    // the carriage return the hub takes and a scope does not.
    let text: String = text.trim().chars().filter(|letter| !letter.is_control() || *letter == '\n').collect();
    let kept: String = text.chars().take(most).collect();
    if kept.trim().is_empty() {
        return (instead.to_owned(), false);
    }
    (kept, text.chars().count() > most)
}

/// The host's bounty in the core's shapes. `realm_id` is the research realm it would belong to; a
/// rehearsal belongs to no realm, so it passes the host's own identifier.
fn translate(realm_id: &str, record: &bounty::Record, now: i64) -> Result<Translation, String> {
    let mut notes = Vec::new();
    let host_account = Principal {
        id: same_tail("principal", &record.id),
        realm_id: realm_id.to_owned(),
        kind: PrincipalKind::Service,
        name: name_of(&format!("{} host", record.name)),
        email: None,
        // The account the scope and the source are recorded under does research and approves
        // nothing, including its own: a bounty host has one administrator, and a migration does
        // not invent the second person a frozen scope needs.
        roles: vec![Role::Researcher],
        created_at: record.created_at,
        suspended_at: None,
    };

    let mut members = Vec::new();
    let mut devices = Vec::new();
    let mut hosts = Vec::new();
    let mut computers = Vec::new();
    for member in &record.members {
        let principal_id = same_tail("principal", &member.id);
        let device_id = same_tail("device", &member.id);
        let host_id = same_tail("host", &member.id);
        members.push((
            member.id.clone(),
            Principal {
                id: principal_id.clone(),
                realm_id: realm_id.to_owned(),
                kind: PrincipalKind::Service,
                // A computer joins a bounty with the host's password; there is no person behind
                // one of them to name, so each is an account standing for that computer.
                name: name_of(&member.name),
                email: None,
                roles: vec![Role::Researcher],
                created_at: member.joined_at,
                suspended_at: None,
            },
        ));
        devices.push(Device {
            id: device_id.clone(),
            realm_id: realm_id.to_owned(),
            principal_id: principal_id.clone(),
            name: name_of(&member.name),
            platform: member.platform.chars().filter(|letter| letter.is_ascii_alphanumeric() || matches!(letter, '-' | '_')).take(32).collect(),
            // The token this computer holds is the host's, for the host's own door. It is not
            // carried across, so nothing brought over can act in the realm until it enrols.
            token_hash: String::new(),
            enrolled_at: member.joined_at,
            last_seen_at: None,
            revoked_at: None,
            attestation: Attestation::default(),
        });
        hosts.push(Host {
            id: host_id.clone(),
            realm_id: realm_id.to_owned(),
            device_id,
            name: name_of(&member.name),
            // The host never asked a joined computer how large it is, and inventing a number here
            // would put research on a computer on the strength of something nobody measured. A
            // computer that offers nothing takes no work until it offers again in the realm.
            capacity: Resources::default(),
            offered: Resources::default(),
            gpu_isolation: Default::default(),
            commitment: Commitment::Share,
            draining: false,
            joined_at: member.joined_at,
        });
        computers.push((member.id.clone(), host_id));
    }
    notes.push("no computer brought across can act in the realm until it enrols: the token each one holds is the host's, and it is not carried over".to_owned());
    notes.push("the host never recorded how large a joined computer is, so every computer arrives offering nothing and takes no research until it offers again here".to_owned());

    // The published files, decoded and hashed by the product's own snapshot, which is the one
    // component that reads these bytes. Nothing here reads a byte of source a second time.
    let snapshot = record.bounty.snapshot()?;
    let mut manifest = Vec::new();
    for file in snapshot["files"].as_array().map(Vec::as_slice).unwrap_or_default() {
        manifest.push(SourceFile {
            path: file["path"].as_str().unwrap_or_default().to_owned(),
            sha256: file["sha256"].as_str().unwrap_or_default().to_owned(),
            bytes: file["bytes"].as_u64().unwrap_or_default(),
        });
    }
    let mut limits = Limits::careful();
    limits.maximum_files = limits.maximum_files.max(manifest.len() as u64);
    crate::core::research::checked_manifest(&manifest, limits.maximum_files)?;

    let (purpose, purpose_cut) = words_of(&record.bounty.instructions, 500, "The bounty published no instruction of its own");
    let (authorisation, authorisation_cut) = words_of(&record.bounty.authorization, 4_000, "The bounty host published no authorisation; a scope is not frozen without the material owner's own words");
    if purpose_cut || authorisation_cut {
        notes.push("the bounty's instruction or authorisation is longer than a scope holds, and what is past that is not carried; the scope's digest is over what is carried".to_owned());
    }
    if record.bounty.authorization.trim().is_empty() {
        notes.push("this bounty published no authorisation at all, so the scope arrives saying so; nobody should freeze a scope whose authorisation is not the material owner's own words".to_owned());
    }
    let mut scope = Scope::draft(
        realm_id,
        &record.bounty.title,
        &purpose,
        &authorisation,
        // Unreleased source somebody published for review, read at the careful end: the record
        // says nothing about how sensitive it is, and the safe direction to be wrong in is the
        // one that asks more of whoever places work.
        Classification::Confidential,
        limits,
        &host_account.id,
        record.created_at,
    )?;
    scope.id = same_tail("scope", &record.id);
    notes.push(
        "the scope arrives a draft: a frozen scope is one a second person agreed to over its digest, and a bounty host has one administrator, so nothing can be placed under it until somebody in the research realm freezes it with an approver"
            .to_owned(),
    );
    notes.push("the scope arrives marked confidential and holding the careful limits, because the bounty record says neither how sensitive its source is nor how large a run may be".to_owned());

    let request = Approval {
        id: same_tail("approval", &record.id),
        realm_id: realm_id.to_owned(),
        action: Action::ApproveResearch.name().to_owned(),
        resource_id: scope.id.clone(),
        method: None,
        path: None,
        requested_by: host_account.id.clone(),
        requested_at: record.created_at,
        expires_at: record.created_at + crate::core::approval::WAIT,
        // Letting source into a research realm always needs an approver; no standing allowance
        // ever covers one, which `research::Admission::every_time` says in its own words.
        every_time: true,
        state: State::Waiting,
        decided_by: None,
        decided_at: None,
        self_issued: false,
        reason: String::new(),
    };
    let admitted = Admitted {
        id: same_tail("admission", &record.id),
        realm_id: realm_id.to_owned(),
        scope_id: scope.id.clone(),
        kind: Admission::Source,
        subject: format!("bounty:{}", record.id),
        method: None,
        path: None,
        approval_id: request.id.clone(),
        admitted_by: host_account.id.clone(),
        admitted_at: record.created_at,
        expires_at: None,
        withdrawn_at: None,
        withdrawn_reason: String::new(),
    };
    notes.push(
        "the agreement that lets this source in is written as a request nobody has decided, because nobody here may agree on their own; it is not a permission, and the draft scope above is what actually stops work being placed"
            .to_owned(),
    );

    let source = Source {
        id: same_tail("source", &record.id),
        realm_id: realm_id.to_owned(),
        scope_id: scope.id.clone(),
        admission_id: admitted.id.clone(),
        // The files were published to the host rather than fetched from anywhere.
        origin: Origin::Upload,
        reference: format!("bounty:{}", record.id),
        revision: snapshot["revision"].as_str().unwrap_or_default().to_owned(),
        digest: crate::core::research::manifest_digest(&manifest),
        bytes: snapshot["bytes"].as_u64().unwrap_or_default(),
        file_count: manifest.len() as u64,
        retain_until: Some(record.created_at + scope.limits.retain_seconds),
        acquired_by: host_account.id.clone(),
        acquired_at: record.created_at,
        // Nothing has hashed these files a second time and compared the two, which is what
        // verifying a source is; the manifest below is the first reading of them.
        verified_at: None,
        quarantined_at: None,
        disposed_at: None,
        reason: String::new(),
    };

    // One piece of work per computer that reported anything, because a finding in a realm names
    // the run it came out of. The host keeps no record of a run at all, so what is written is the
    // one thing the record does say: this computer worked this bounty and reported these.
    let mut work = Vec::new();
    let mut findings = Vec::new();
    let mut unknown_severity = 0;
    let mut unnamed = 0;
    let mut without_a_member = 0;
    let mut cut = 0;
    for finding in &record.findings {
        let Some((_, principal)) = members.iter().find(|(hub_id, _)| hub_id == &finding.member_id) else {
            without_a_member += 1;
            continue;
        };
        let work_id = same_tail("work", &finding.member_id);
        if !work.iter().any(|one: &Workload| one.id == work_id) {
            let mut one = Workload::new(
                realm_id,
                Capability::Research,
                Kind::Research,
                &principal.id,
                &same_tail("device", &finding.member_id),
                Resources::default(),
                1,
                finding.created_at,
            );
            one.id = work_id.clone();
            // The one note the core's own research code reads off a piece of work, so a finding
            // brought across is readable by the code that records a native one.
            one.note = Some(format!("research:{}", scope.id));
            one.stage = Stage::Completed;
            work.push(one);
        }
        let severity = severity_of(&finding.severity);
        if severity == Severity::Unknown {
            unknown_severity += 1;
        }
        let (summary, summary_cut) = words_of(&finding.detail, 500, "No summary was written");
        if summary_cut {
            cut += 1;
        }
        findings.push((
            finding.id.clone(),
            Finding {
                id: same_tail("finding", &finding.id),
                realm_id: realm_id.to_owned(),
                scope_id: scope.id.clone(),
                source_id: source.id.clone(),
                workload_id: work_id,
                title: crate::label(&finding.title, "finding title").unwrap_or_else(|_| {
                    unnamed += 1;
                    "A finding".to_owned()
                }),
                // Which model found it, kept beside the finding because a realm records who
                // reported a finding and the host records which model did.
                component: finding.model.chars().filter(|letter| !letter.is_control()).take(128).collect(),
                summary,
                severity,
                // Reported to the host and not yet looked at by anybody: the host keeps no review
                // of a finding, so none crosses, and the realm's own review is where one is
                // accepted or rejected.
                state: FindingState::Submitted,
                artifacts: Vec::new(),
                reported_by: principal.id.clone(),
                created_at: finding.created_at,
                updated_at: finding.created_at,
            },
        ));
    }
    if unnamed > 0 {
        notes.push(format!("{unnamed} findings are titled in a way a realm will not hold, and they arrive called a finding; the host's own record keeps what each was called"));
    }
    if unknown_severity > 0 {
        notes.push(format!("{unknown_severity} findings carry a word for how bad they are that a realm does not know, and they arrive marked unknown rather than being read as something they might not be"));
    }
    if without_a_member > 0 {
        notes.push(format!("{without_a_member} findings name a computer this host no longer has, and they do not come across, because a finding in a realm names who reported it"));
    }
    if cut > 0 {
        notes.push(format!("{cut} findings are longer than a realm's summary holds, and what is past that is not carried; the host's own record keeps all of it"));
    }
    notes.push(
        "no finding rests on an artifact here: the host keeps no artifact at all, and a worker's own files are written by the application and deleted with the worker on purpose, so nothing of them crosses"
            .to_owned(),
    );
    notes.push("every finding arrives submitted and unreviewed, because the host keeps no review of one; accepting or rejecting a finding is the research realm's own decision".to_owned());
    let _ = now;
    Ok(Translation { host_account, members, devices, hosts, computers, scope, request, admitted, source, manifest, work, findings, notes })
}

/// What bringing this bounty host across would create, written down without writing any of it.
pub fn rehearse(record: &bounty::Record, now: i64) -> Result<BountyRehearsal, String> {
    let translation = translate(&record.id, record, now)?;
    Ok(BountyRehearsal {
        host_id: record.id.clone(),
        members: translation.members.len(),
        working: record.members.iter().filter(|member| member.model.is_some()).count(),
        findings: translation.findings.len(),
        source_files: translation.manifest.len(),
        source_bytes: translation.source.bytes,
        target_kind: record.bounty.target.kind.clone(),
        principals: translation.members.len() + 1,
        devices: translation.devices.len(),
        hosts: translation.hosts.len(),
        work: translation.work.len(),
        scopes: 1,
        scope_frozen: translation.scope.frozen(),
        notes: translation.notes,
    })
}

/// What is still missing once the bridge exists, said once, here, and repeated in
/// `docs/grid-core/rollout.md`. Each of these is a note on a rehearsal, never a silence.
pub fn missing() -> &'static [&'static str] {
    &[
        "the scope arrives a draft: freezing one needs an approver who is not its author, and a bounty host has one administrator, so nothing can be placed under it until the research realm decides that itself",
        "a research realm is a trust boundary with its own key, and this bridge refuses anything but one; creating it and keeping its key is the application's decision and not this crate's",
        "the worker's own files are written by the application, and the product deletes a worker's receipts with the worker on purpose, so nothing of them crosses and no finding rests on an artifact",
        "the host keeps no review of a finding, so every finding arrives submitted and unreviewed",
        "no worker may be run, started or tested in this repository, so this bridge has only ever been exercised against records and fixtures and never beside a host that is serving",
    ]
}

/// Brings a bounty host's computers, source and findings into a research realm.
///
/// The realm has to be a research realm the caller already created with a key of its own, and this
/// refuses anything else: `Capability::allowed_in` keeps research out of a company realm, the
/// realm's own database says the same to anything that opens the file, and this says it in words
/// before a row is written. Nothing here creates a realm or decides where a key lives.
pub fn import(core: &mut Core, by: &str, record: &bounty::Record, now: i64) -> Result<ResearchImported, String> {
    core.allowed(by, Action::ManagePeople)?;
    core.allowed(by, Action::DoResearch)?;
    if core.realm().kind != RealmKind::Research || !core.realm().can(Capability::Research) {
        return Err("A bounty is brought across into a research grid of its own, with a key of its own; this grid is not one".into());
    }
    if core.store.holds_any_scope_or_source()? {
        return Err("This grid already has research of its own; a bounty host is brought across into a grid of its own".into());
    }
    // There is no check here against the number of scopes a realm may hold, and that is not an
    // omission. A `Translation` carries one `Scope`, not a list of them, so one import is one
    // scope; and the line above has already refused a realm holding any. A check would be a
    // guard that cannot fire, which reads like protection and is not.
    let translation = translate(&core.realm().id, record, now)?;
    // Everything that could already be here is looked at before anything is written, so an import
    // either happens or does not; there is no half-brought-across host to clear up by hand.
    if core.store.principal(&translation.host_account.id)?.is_some() {
        return Err("This bounty has been brought across before; take that import back out first".into());
    }
    for (_, principal) in &translation.members {
        if core.store.principal(&principal.id)?.is_some() {
            return Err(format!("An account called {} is already in this grid", principal.id));
        }
    }
    for device in &translation.devices {
        if core.store.device(&device.id)?.is_some() {
            return Err(format!("A computer called {} is already in this grid", device.id));
        }
    }
    // And the realm has to have room for all of it. These are the realm's own limits, and the
    // doors that enforce them are all on `Core`; this writes through the store, underneath them.
    // The host's own account is always one more, because an account already here was refused above.
    super::room_for("accounts", core.store.people_count()?, translation.members.len() + 1, crate::core::limits::MAX_PEOPLE)?;
    super::room_for("computers", core.store.device_count()?, translation.devices.len(), crate::core::limits::MAX_DEVICES)?;
    super::room_for("computers offering resources", core.store.host_count()?, translation.hosts.len(), crate::core::limits::MAX_HOSTS)?;

    core.store.add_principal(&translation.host_account, by, now)?;
    for (_, principal) in &translation.members {
        core.store.add_principal(principal, by, now)?;
    }
    for device in &translation.devices {
        core.store.enrol_device(device)?;
    }
    for host in &translation.hosts {
        core.store.put_host(host)?;
    }
    core.store.put_scope(&translation.scope)?;
    core.store.put_request(&translation.request)?;
    core.store.put_admission(&translation.admitted)?;
    core.store.put_source(&translation.source, &translation.manifest)?;
    for one in &translation.work {
        core.store.put_workload(one)?;
    }
    for (_, finding) in &translation.findings {
        core.store.put_finding(finding)?;
    }

    let imported = ResearchImported {
        realm_id: core.realm().id.clone(),
        grid_id: record.id.clone(),
        at: now,
        members: translation.members.iter().map(|(member_id, principal)| Renamed { was: member_id.clone(), now: principal.id.clone() }).collect(),
        computers: translation
            .computers
            .iter()
            .map(|(member_id, host_id)| Moved { member_id: member_id.clone(), device_id: same_tail("device", member_id), host_id: host_id.clone() })
            .collect(),
        scope_id: translation.scope.id.clone(),
        source_id: translation.source.id.clone(),
        admission_id: translation.admitted.id.clone(),
        approval_id: translation.request.id.clone(),
        work: translation.work.iter().map(|one| one.id.clone()).collect(),
        findings: translation.findings.iter().map(|(host_id, finding)| Renamed { was: host_id.clone(), now: finding.id.clone() }).collect(),
        principal_id: translation.host_account.id.clone(),
    };
    // What this import created, written into the realm itself, for the same reason the other
    // bridges write it: a value in memory cannot undo anything after a restart.
    core.store.put_bridge_import(&super::BridgeImport {
        id: super::BridgeImport::name("research", now),
        realm_id: imported.realm_id.clone(),
        grid_id: imported.grid_id.clone(),
        at: now,
        undo: super::Undone::Research(imported.clone()),
    })?;
    core.note(
        Entry::new(&imported.realm_id, by, "grid.research.imported", Decision::Allowed).about(Capability::Research, &record.id).because(&format!(
            "{} computers, one draft scope over {} files and {} findings from a bounty host",
            imported.computers.len(),
            translation.manifest.len(),
            imported.findings.len()
        )),
        now,
    )?;
    Ok(imported)
}

/// Takes a bounty host import back out again, as far as a research realm ever lets anything be
/// taken back out.
///
/// That is not far, and it is the research profile's own doing rather than this bridge's. A scope
/// is closed and never deleted, an admission is withdrawn and never deleted, a source is disposed
/// of and never deleted, and a finding stays in the record; the realm's own database says each of
/// those to anything that opens the file, not only to the code that normally writes it. So what
/// this does is close the scope, withdraw the admission that let the source in, dispose of the
/// source and take the computers back off, in the realm's own words. What it does not do is make
/// the realm look as though the import never ran, and nothing here pretends otherwise.
///
/// A bounty is brought across into a research realm created for it, so the way to leave nothing
/// behind is to delete that realm and its key, which is exactly what the import stage's own undo
/// sentence tells an administrator to do.
///
/// It refuses before any of that if the realm has moved on: a scope somebody froze is one a second
/// person agreed to, a request somebody decided is a decision a realm never withdraws, and work
/// placed from one of these computers would be left naming something that is not there.
pub fn roll_back(core: &mut Core, by: &str, imported: &ResearchImported, now: i64) -> Result<(), String> {
    core.allowed(by, Action::ManagePeople)?;
    core.allowed(by, Action::DoResearch)?;
    if imported.realm_id != core.realm().id {
        return Err("That import was into another grid".into());
    }
    if core.store.scope(&imported.scope_id)?.is_some_and(|scope| scope.frozen()) {
        return Err("The scope this import brought in has been frozen, and a frozen scope is what somebody agreed to, so the import cannot be undone".into());
    }
    if core.store.request(&imported.approval_id)?.is_some_and(|request| request.state != State::Waiting) {
        return Err("Somebody has decided the request this import brought in, and a realm writes a decision once and never withdraws one, so the import cannot be undone".into());
    }
    let devices: Vec<String> = imported.computers.iter().map(|moved| moved.device_id.clone()).collect();
    let mut accounts: Vec<String> = imported.members.iter().map(|renamed| renamed.now.clone()).collect();
    accounts.push(imported.principal_id.clone());
    if core.store.any_other_device_of(&accounts, &devices)? {
        return Err("Somebody has enrolled a computer of their own against an account this import brought in, so the import cannot be undone".into());
    }
    let brought: Vec<String> = imported.work.clone();
    if core.store.work_from(&devices, &accounts)?.iter().any(|id| !brought.contains(id)) {
        return Err("Work in this grid was placed from a computer or an account this import brought in, so the import cannot be undone".into());
    }
    let undone = "the bounty host import this scope came from was taken back out";
    core.store.dispose_source(&imported.source_id, undone, now)?;
    core.store.withdraw_admission(&imported.admission_id, undone, now)?;
    core.store.close_scope(&imported.scope_id, undone, now)?;
    // Only the computers go. The accounts, the work and the request stay because the record that
    // stays names every one of them, and a realm that kept a finding naming an account it had
    // deleted would be a record that disagreed with itself.
    let hosts: Vec<String> = imported.computers.iter().map(|moved| moved.host_id.clone()).collect();
    core.store.forget_imported(&[], &devices, &hosts, &[])?;
    core.store.forget_bridge_import(&super::BridgeImport::name("research", imported.at))?;
    core.note(
        Entry::new(&core.realm().id, by, "grid.research.import undone", Decision::Allowed).about(Capability::Research, &imported.grid_id).because(&format!(
            "{} computers taken off, the scope closed, the source disposed of and the admission withdrawn; the research record itself stays, as a research grid never deletes one",
            hosts.len()
        )),
        now,
    )
}

/// What a research realm's own rules will not let an undo delete.
///
/// A rehearsal needs this in order to say the truth about what came back: these tables either hold
/// the rows the import wrote or hold them closed, withdrawn and disposed of, and neither is the
/// realm coming back to what it was. The list is here rather than in the rehearsal because it is a
/// fact about this bridge and this profile.
pub fn kept_by_the_realm() -> &'static [&'static str] {
    &["principals", "permissions", "requests", "workloads", "research_scopes", "research_admissions", "research_sources", "research_source_files", "research_findings"]
}

// -------------------------------------------------------------------------------------------
// Observation mode
// -------------------------------------------------------------------------------------------

/// Puts what the host holds beside what the research realm would hold, thing by thing.
///
/// What this can and cannot show has to be said rather than discovered. There is no second
/// placement algorithm here: the host decides nothing a realm also decides, because a joined
/// computer chooses its own model and works the source itself. So this is not two deciders being
/// asked the same question, as the model grid's comparison is. It is the carried record read back
/// against the record it was carried from: every file's digest, every computer's findings, and
/// every finding's severity, which is what would catch a bridge that lost or changed one.
///
/// Nothing is written, nothing is started, and the host's record is not touched.
pub fn compare(record: &bounty::Record, now: i64) -> Result<ResearchComparison, String> {
    let translation = translate(&record.id, record, now)?;
    let mut notes = translation.notes.clone();
    let mut carried = Vec::new();

    let snapshot = record.bounty.snapshot()?;
    // The whole source first, so a profile whose host has no computers and no findings still
    // answers under both headings rather than saying nothing at all.
    carried.push(Decided {
        subject: record.id.clone(),
        hub: format!("{} files, {} bytes", snapshot["fileCount"].as_u64().unwrap_or_default(), snapshot["bytes"].as_u64().unwrap_or_default()),
        core: format!("{} files, {} bytes", translation.source.file_count, translation.source.bytes),
    });
    carried.push(Decided {
        subject: format!("{}:work", record.id),
        hub: format!("{} computers, {} findings", record.members.len(), record.findings.len()),
        core: format!("{} computers, {} findings", translation.hosts.len(), translation.findings.len()),
    });
    for file in snapshot["files"].as_array().map(Vec::as_slice).unwrap_or_default() {
        let path = file["path"].as_str().unwrap_or_default();
        let host = format!("{} bytes, {}", file["bytes"].as_u64().unwrap_or_default(), &file["sha256"].as_str().unwrap_or_default()[..8.min(file["sha256"].as_str().unwrap_or_default().len())]);
        let realm = match translation.manifest.iter().find(|carried| carried.path == path) {
            Some(carried) => format!("{} bytes, {}", carried.bytes, &carried.sha256[..8.min(carried.sha256.len())]),
            None => "not in the manifest".to_owned(),
        };
        carried.push(Decided { subject: short(path), hub: host, core: realm });
    }

    for member in &record.members {
        let host = format!("{} findings", record.findings.iter().filter(|finding| finding.member_id == member.id).count());
        let realm = format!("{} findings", translation.findings.iter().filter(|(_, finding)| finding.reported_by == same_tail("principal", &member.id)).count());
        carried.push(Decided { subject: member.id.clone(), hub: host, core: realm });
    }

    for finding in &record.findings {
        let host = severity_of(&finding.severity).name().to_owned();
        let realm = translation
            .findings
            .iter()
            .find(|(host_id, _)| host_id == &finding.id)
            .map_or_else(|| "not in the realm".to_owned(), |(_, carried)| carried.severity.name().to_owned());
        carried.push(Decided { subject: finding.id.clone(), hub: host, core: realm });
    }

    notes.push(
        "this is not two deciders asked the same question: a joined computer chooses its own model and works the source itself, so the host decides nothing a realm also decides, and these lines say the realm would hold what the host holds and nothing more"
            .to_owned(),
    );
    Ok(ResearchComparison { host_id: record.id.clone(), carried, notes })
}

/// Both paths asked the six questions, for the research profile.
///
/// Two of the six can be asked from a record on disk and four cannot, and saying which is which is
/// the point of returning a line for every one of them. A ledger that simply omitted the four
/// would read as though the research profile had been observed, and it would not have been.
pub fn observe(record: &bounty::Record, now: i64) -> Vec<Observation> {
    let Ok(comparison) = compare(record, now) else {
        return Heading::all()
            .iter()
            .map(|heading| {
                Observation::new(
                    now,
                    Profile::Research,
                    *heading,
                    &record.id,
                    "a bounty host record",
                    "nothing: this record holds something a research realm will not hold",
                    Verdict::Unobserved("this host's record did not translate, so neither side was asked anything; the rehearsal says what and why".to_owned()),
                )
            })
            .collect();
    };
    let notes = comparison.notes.clone();
    let judge = crate::core::compat::observe::judge;
    let mut observations = Vec::new();

    // Every row is looked up by the subject it was written under rather than by where it sits in
    // the list, so adding a kind of row to the comparison cannot quietly move the lines below it
    // under somebody else's heading.
    let answered = |heading: Heading, subject: &str| {
        comparison.carried.iter().find(|row| row.subject == subject).map(|row| {
            let verdict = judge(heading, &row.hub, &row.core, &notes);
            Observation::new(now, Profile::Research, heading, &row.subject, &row.hub, &row.core, verdict)
        })
    };

    // Plans: what the administrator published, which for a bounty is one authorisation over one
    // set of files. Every answer is a count or a digest, because a title and a path are names.
    observations.extend(answered(Heading::Plans, &record.id));
    for file in &record.bounty.files {
        observations.extend(answered(Heading::Plans, &short(&file.path)));
    }

    // Workloads: what each joined computer did, which the record says only as how much it found,
    // and how bad each of those findings is.
    observations.extend(answered(Heading::Workloads, &format!("{}:work", record.id)));
    for member in &record.members {
        observations.extend(answered(Heading::Workloads, &member.id));
    }
    for finding in &record.findings {
        observations.extend(answered(Heading::Workloads, &finding.id));
    }

    // The four nothing here can ask, each with the reason it cannot.
    let unobservable = [
        (
            Heading::Assignments,
            "a joined computer picks its own model",
            "nothing: a realm places no bounty work",
            "a bounty host hands out no work: a joined computer chooses its own model and works the whole source, so there is no placement on the host's side for a realm's chooser to be compared against",
        ),
        (
            Heading::Permissions,
            "the host password and nothing else",
            "one account per computer, each a researcher",
            "a bounty host has no accounts: computers join with the host's password and no person signs in at all, so there is nothing on the host's side to compare an account against",
        ),
        (
            Heading::Audit,
            "a callback the application owns",
            "a sealed chain in the realm",
            "the host hands each event to a callback the application owns and keeps none of them in its record, so a reading of the record cannot compare the two histories",
        ),
        (
            Heading::Answers,
            "the host's own board",
            "nothing: no page and no command reads a research realm yet",
            "comparing what somebody asking would be told needs both paths serving, and no worker may be run, started or tested in this repository at all",
        ),
    ];
    for (heading, hub, core, why) in unobservable {
        observations.push(Observation::new(now, Profile::Research, heading, &record.id, hub, core, Verdict::Unobserved(why.to_owned())));
    }
    observations
}
