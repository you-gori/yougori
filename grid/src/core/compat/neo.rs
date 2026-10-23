//! The bridge from the Closed Neo Grid hub onto Grid Core.
//!
//! The hub keeps one record: the company's computers, the admin's plans, and which computer was
//! given which model. The core keeps a realm: accounts, the computers they act from, the
//! computers that offer resources, and the model plans placed on them. This turns one into the
//! other, and can turn it back.
//!
//! Nothing here changes the hub's record. Every function takes it by reference, and the one that
//! has to run the hub's own placement runs it on a copy, so a grid can be compared while it is
//! serving and nobody's model moves because somebody asked a question about it.
use super::{
    observe::{Heading, Observation, Profile, Verdict},
    Comparison, Imported, Moved, Named, PlanComparison, PlanShape, Placement, Rehearsal,
};
use crate::core::{
    audit::{Decision, Entry},
    identity::{Action, Attestation, Device, Principal, PrincipalKind},
    model::{self, ModelAssignment, ModelPlan},
    realm::Capability,
    work::{Commitment, Host, Resources},
    Core,
};
use crate::{hub, policy::IdlePolicy};
use std::collections::HashMap;

/// The hub's grid as the core's own shapes, built in memory and written by nobody.
struct Translation {
    principal: Principal,
    devices: Vec<Device>,
    hosts: Vec<Host>,
    plans: Vec<ModelPlan>,
    /// What each computer already has, carried across exactly as the hub left it.
    assignments: Vec<ModelAssignment>,
    /// The hub's computer identifiers against the core's, in the record's own order.
    computers: Vec<(String, String)>,
    /// The hub's plan identifiers against the core's.
    named: Vec<(String, String)>,
    notes: Vec<String>,
}

/// The part of a hub identifier that is its own, under the core's name for the same thing. A
/// computer that was `member-9f3a…` on the hub becomes `host-9f3a…` in the realm, so a person
/// looking at either one can see they are the same computer, and a migration can be traced
/// without keeping a table of what became what.
fn same_tail(prefix: &str, legacy: &str) -> String {
    format!("{prefix}-{}", legacy.rsplit('-').next().unwrap_or(legacy))
}

/// A computer's name as the core will hold it. Both sides check names the same way, and the hub
/// itself falls back to "Computer" when a joining computer sends something it cannot use.
fn name_of(raw: &str) -> String {
    crate::label(raw, "computer name").unwrap_or_else(|_| "Computer".to_owned())
}

/// What the realm may take from one computer.
///
/// The hub records this only for desks, and only once the admin has set it, so for most computers
/// there is nothing to carry and the offer is nothing but the graphics card. That is the honest
/// answer: the hub never asked how large these computers are, and inventing a number here would
/// put work on a computer on the strength of something nobody measured.
fn room(member: &hub::MemberRecord) -> Resources {
    let share = member.share.as_ref();
    Resources {
        cpu: share.map_or(0.0, |share| share.cpu),
        memory_gb: share.map_or(0.0, |share| share.memory_gb),
        disk_gb: share.map_or(0.0, |share| share.disk_gb),
        // Whether a computer can run models is what the computer itself reported. The desk
        // share's own graphics flag says what the grid may take for desks, which is a different
        // question and has never had any bearing on which model runs where.
        gpu: member.capable,
        vram_gb: 0.0,
    }
}

/// The hub's grid in the core's shapes. `realm_id` is the realm it would belong to; a comparison
/// belongs to no realm, so it passes the grid's own identifier, which nothing in placement reads.
fn translate(realm_id: &str, record: &hub::Record) -> Translation {
    let mut notes = Vec::new();
    let principal = Principal {
        id: same_tail("principal", &record.id),
        realm_id: realm_id.to_owned(),
        kind: PrincipalKind::Service,
        // The computers join a hub with the company password; there is no person behind any one
        // of them to name, so they belong to one account that stands for the company's computers.
        name: name_of(&format!("{} computers", record.name)),
        email: None,
        roles: Vec::new(),
        created_at: record.created_at,
        suspended_at: None,
    };
    let mut devices = Vec::new();
    let mut hosts = Vec::new();
    let mut computers = Vec::new();
    for member in &record.members {
        let device_id = same_tail("device", &member.id);
        let host_id = same_tail("host", &member.id);
        devices.push(Device {
            id: device_id.clone(),
            realm_id: realm_id.to_owned(),
            principal_id: principal.id.clone(),
            name: name_of(&member.name),
            platform: member.platform.clone(),
            // The secret this computer holds is the hub's, for the hub's own door. It is not
            // carried across, so nothing brought over can act in the realm until it enrols here.
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
            // The hub never recorded how large a computer is, only what it may take for desks,
            // so what it has and what it offers are the same thing until it offers again here.
            capacity: room(member),
            offered: room(member),
            gpu_isolation: Default::default(),
            // Every computer that can run models counts towards every plan's share on the hub,
            // whatever it gives to desks. Anything else would quietly resize every plan in the
            // grid, because a computer that contributes nothing leaves the share they divide.
            commitment: Commitment::Share,
            // The admin left this computer out of the grid's work; in the realm that is a
            // computer that takes no work, and it can be brought back the same way.
            draining: member.excluded,
            joined_at: member.joined_at,
        });
        computers.push((member.id.clone(), host_id));
    }

    let mut plans = Vec::new();
    let mut named = Vec::new();
    for plan in &record.plans {
        let id = same_tail("model-plan", &plan.id);
        let target = match &plan.target {
            hub::Target::All => model::Target::All,
            hub::Target::Remaining => model::Target::Remaining,
            hub::Target::Computers { members } => model::Target::Computers { hosts: members.iter().map(|member| same_tail("host", member)).collect() },
        };
        if let hub::Target::Computers { members } = &plan.target {
            let strangers = members.iter().filter(|member| !record.members.iter().any(|entry| &&entry.id == member)).count();
            if strangers > 0 {
                notes.push(format!("a plan names {strangers} computers that are not in this grid; they place nothing on either side"));
            }
        }
        plans.push(ModelPlan {
            id: id.clone(),
            realm_id: realm_id.to_owned(),
            model: plan.model.clone(),
            quant: plan.quant.clone(),
            percent: plan.percent,
            policy: plan.policy.clone(),
            target,
            created_at: plan.created_at,
        });
        named.push((plan.id.clone(), id));
    }

    let mut assignments = Vec::new();
    let mut undated = 0;
    let mut orphaned = 0;
    for member in &record.members {
        let Some(plan) = member.plan.as_ref() else { continue };
        let Some((_, plan_id)) = named.iter().find(|(hub_id, _)| hub_id == plan) else {
            orphaned += 1;
            continue;
        };
        if member.assigned_at.is_none() {
            undated += 1;
        }
        assignments.push(ModelAssignment {
            plan_id: plan_id.clone(),
            host_id: same_tail("host", &member.id),
            // The hub treats a computer with a model and no date as the one that has had it
            // longest, because nothing sorts before a date. The core holds a number, so that
            // meaning is written down as the oldest moment there is. Using the moment of the
            // import instead would turn the stickiest computer into the first one released.
            assigned_at: member.assigned_at.unwrap_or(0),
        });
    }
    if undated > 0 {
        notes.push(format!("{undated} computers have a model and no record of when they were given it; they keep it longest, as they do on the hub"));
    }
    if orphaned > 0 {
        notes.push(format!("{orphaned} computers hold a plan this grid no longer has; they come across with no model, as the hub's next pass would leave them"));
    }
    let unmeasured = record.members.iter().filter(|member| member.share.is_none()).count();
    if unmeasured > 0 {
        notes.push(format!("{unmeasured} computers offer no measured room, because the hub never recorded any; work that needs room waits until they offer again"));
    }
    notes.push("no computer brought across can act in the realm until it enrols: the secret each one holds is the hub's, and it is not carried over".to_owned());
    Translation { principal, devices, hosts, plans, assignments, computers, named, notes }
}

/// What bringing this grid across would create, written down without writing any of it.
pub fn rehearse(record: &hub::Record) -> Rehearsal {
    let translation = translate(&record.id, record);
    Rehearsal {
        grid_id: record.id.clone(),
        grid_name: record.name.clone(),
        principals: 1,
        devices: translation.devices.len(),
        hosts: translation.hosts.len(),
        model_capable: record.members.iter().filter(|member| member.capable).count(),
        left_out: record.members.iter().filter(|member| member.excluded).count(),
        plans: translation.plans.len(),
        assignments: translation.assignments.len(),
        notes: translation.notes,
    }
}

/// Brings a hub's grid into a realm: its computers, its plans, and the model each computer
/// already has.
///
/// Nothing is placed again. Every computer keeps the model the hub gave it, with the moment it
/// was given, so bringing a grid across costs nobody a download. The hub's record is not touched
/// and goes on being the grid that is actually serving until somebody decides otherwise.
pub fn import(core: &mut Core, by: &str, record: &hub::Record, now: i64) -> Result<Imported, String> {
    // It creates accounts and computers as well as plans, so it needs both.
    core.allowed(by, Action::ManagePeople)?;
    core.allowed(by, Action::ManageModels)?;
    if !core.realm().can(Capability::Models) {
        return Err("This grid does not serve models".into());
    }
    if core.store.holds_any_host_or_plan()? {
        return Err("This grid already has computers of its own; a hub is brought across into a grid of its own".into());
    }
    let translation = translate(&core.realm().id, record);
    // Everything that could already be here is looked at before anything is written, so an import
    // either happens or does not; there is no half-brought-across grid to clear up by hand.
    if core.store.principal(&translation.principal.id)?.is_some() {
        return Err("This grid has been brought across before; take that import back out first".into());
    }
    for device in &translation.devices {
        if core.store.device(&device.id)?.is_some() {
            return Err(format!("A computer called {} is already in this grid", device.id));
        }
    }
    core.store.add_principal(&translation.principal, by, now)?;
    for device in &translation.devices {
        core.store.enrol_device(device)?;
    }
    for host in &translation.hosts {
        core.store.put_host(host)?;
    }
    core.store.replace_model_state(&translation.plans, &translation.assignments)?;
    let imported = Imported {
        realm_id: core.realm().id.clone(),
        grid_id: record.id.clone(),
        at: now,
        computers: translation
            .computers
            .iter()
            .map(|(member_id, host_id)| Moved { member_id: member_id.clone(), device_id: same_tail("device", member_id), host_id: host_id.clone() })
            .collect(),
        plans: translation.named.iter().map(|(plan_id, model_plan_id)| Named { plan_id: plan_id.clone(), model_plan_id: model_plan_id.clone() }).collect(),
        principal_id: translation.principal.id.clone(),
        assignments: translation.assignments.len(),
    };
    // What this import created, written into the realm itself. Without this the only thing that
    // could undo it would be the value handed back here, which is gone the moment the process
    // ends, so an import could be taken back out on the day it ran and never afterwards.
    core.store.put_bridge_import(&super::BridgeImport {
        id: super::BridgeImport::name("neo", now),
        realm_id: imported.realm_id.clone(),
        grid_id: imported.grid_id.clone(),
        at: now,
        undo: super::Undone::Neo(imported.clone()),
    })?;
    core.note(
        Entry::new(&imported.realm_id, by, "grid.imported", Decision::Allowed)
            .about(Capability::Models, &record.id)
            .because(&format!("{} computers and {} model plans from a Closed Neo Grid hub", imported.computers.len(), imported.plans.len())),
        now,
    )?;
    Ok(imported)
}

/// Takes an import back out again, leaving the realm as it was before it ran.
///
/// What the import created goes; what happened stays, because the history is never rewritten. It
/// refuses rather than taking anything else with it: once work has been placed from one of these
/// computers, undoing the import would leave that work naming a computer that is not there.
pub fn roll_back(core: &mut Core, by: &str, imported: &Imported, now: i64) -> Result<(), String> {
    core.allowed(by, Action::ManagePeople)?;
    core.allowed(by, Action::ManageModels)?;
    if imported.realm_id != core.realm().id {
        return Err("That import was into another grid".into());
    }
    let devices: Vec<String> = imported.computers.iter().map(|moved| moved.device_id.clone()).collect();
    let hosts: Vec<String> = imported.computers.iter().map(|moved| moved.host_id.clone()).collect();
    let plans: Vec<String> = imported.plans.iter().map(|named| named.model_plan_id.clone()).collect();
    if core.store.any_work_of(&devices, &imported.principal_id)? {
        return Err("Work in this grid was placed from a computer this import brought in, so the import cannot be undone".into());
    }
    core.store.forget_imported(std::slice::from_ref(&imported.principal_id), &devices, &hosts, &plans)?;
    // The record of what it created goes with it. What happened stays in the history, which is
    // never rewritten, so nothing about the import is lost by taking this row out.
    core.store.forget_bridge_import(&super::BridgeImport::name("neo", imported.at))?;
    core.note(
        Entry::new(&core.realm().id, by, "grid.import undone", Decision::Allowed)
            .about(Capability::Models, &imported.grid_id)
            .because(&format!("{} computers and {} model plans taken back out", hosts.len(), plans.len())),
        now,
    )
}

/// Runs the hub's placement and the core's over the same grid and reports what each decided, for
/// every computer.
///
/// This is the one that runs beside a live grid: the hub goes on deciding, the core decides the
/// same question, and the two answers are put side by side. Nothing is written, and the hub's
/// record is not touched; its own placement runs on a copy.
///
/// `now` is the moment the core stamps a new assignment with, and it stands for the hub's clock.
/// It has to be later than every assignment already in the grid, exactly as the hub's clock is,
/// because both sides settle a tie between two computers given a model in the same pass by the
/// order the computers joined. A comparison run with an earlier moment says so rather than
/// pretending the two were asked the same question.
pub fn compare(record: &hub::Record, now: i64) -> Comparison {
    let translation = translate(&record.id, record);
    let mut notes = translation.notes;
    let latest = record.members.iter().filter_map(|member| member.assigned_at).max().unwrap_or(i64::MIN);
    if now <= latest || crate::now() <= latest {
        notes.push("this comparison used a moment that is not later than the models already given out, so the two were not asked the same question".to_owned());
    }
    // The hub's own placement, on a copy. The grid being compared goes on serving untouched.
    let mut mirror = record.clone();
    hub::reconcile(&mut mirror);
    let placed = model::reconcile(&translation.plans, &translation.hosts, &translation.devices, &translation.assignments, now);
    let back: HashMap<&str, &str> = translation.named.iter().map(|(hub_id, core_id)| (core_id.as_str(), hub_id.as_str())).collect();
    let computers = mirror
        .members
        .iter()
        .zip(translation.computers.iter())
        .map(|(member, (_, host_id))| Placement {
            member_id: member.id.clone(),
            hub: member.plan.clone(),
            core: placed
                .iter()
                .find(|assignment| &assignment.host_id == host_id)
                .and_then(|assignment| back.get(assignment.plan_id.as_str()).map(|hub_id| (*hub_id).to_owned())),
        })
        .collect();
    Comparison { grid_id: record.id.clone(), computers, notes }
}

/// Runs the hub's plan resolution and the core's over the same grid and the same new plan, and
/// reports the plans each ended with.
///
/// Adding a plan is where the two could differ before any computer is placed: picking a computer
/// that another plan already picked moves it, empties and perhaps removes that plan, or joins a
/// plan that already serves the same model. Comparing the plans themselves catches that, where
/// comparing placements alone would only see it one pass later.
pub fn compare_new_plan(record: &hub::Record, model_name: &str, quant: Option<&str>, percent: u8, policy: IdlePolicy, target: hub::Target, now: i64) -> PlanComparison {
    let translation = translate(&record.id, record);
    let core_target = match &target {
        hub::Target::All => model::Target::All,
        hub::Target::Remaining => model::Target::Remaining,
        hub::Target::Computers { members } => model::Target::Computers { hosts: members.iter().map(|member| same_tail("host", member)).collect() },
    };
    let mut mirror = record.clone();
    let hub_refused = hub::place(&mut mirror, model_name, quant, percent, policy.clone(), target).err();
    let mut plans = translation.plans.clone();
    let core_refused = model::place(&record.id, &mut plans, model_name, quant, percent, policy, core_target, &translation.hosts, now).err();
    let back: HashMap<&str, &str> = translation.computers.iter().map(|(member_id, host_id)| (host_id.as_str(), member_id.as_str())).collect();
    PlanComparison {
        hub: mirror
            .plans
            .iter()
            .map(|plan| PlanShape {
                model: plan.model.clone(),
                quant: plan.quant.clone(),
                percent: plan.percent,
                scope: scope(matches!(plan.target, hub::Target::All), matches!(plan.target, hub::Target::Remaining)),
                picked: plan.target.picked().to_vec(),
            })
            .collect(),
        core: plans
            .iter()
            .map(|plan| PlanShape {
                model: plan.model.clone(),
                quant: plan.quant.clone(),
                percent: plan.percent,
                scope: scope(plan.target == model::Target::All, plan.target == model::Target::Remaining),
                picked: plan.target.hosts().iter().map(|host| back.get(host.as_str()).map_or_else(|| host.clone(), |member| (*member).to_owned())).collect(),
            })
            .collect(),
        hub_refused,
        core_refused,
        notes: translation.notes,
    }
}

/// What one computer is told to serve: its plan's model and the rules it serves under.
///
/// The core's assignment says only which plan a computer is on. Everything a computer needs in
/// order to run the model is in the plan, and joining the two is the one piece of glue a bridge
/// has to write, because the core deliberately knows nothing about delivering it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Serving {
    pub plan_id: String,
    pub model: String,
    pub quant: Option<String>,
    /// Minutes without keyboard or mouse before this computer serves; 0 ignores activity.
    pub idle_after_minutes: u32,
    /// Weekly windows in local time, or none to serve at any time.
    pub schedule: Option<String>,
}

impl Serving {
    /// Whether this is the same model environment a computer already has, so that editing a plan
    /// does not send a computer to download weights it is already holding. Names and
    /// quantizations are compared without case, because `Q4_K_M` and `q4_k_m` are one file.
    pub fn same_model(&self, model: &str, quant: Option<&str>) -> bool {
        self.model.eq_ignore_ascii_case(model)
            && match (&self.quant, quant) {
                (Some(mine), Some(theirs)) => mine.eq_ignore_ascii_case(theirs),
                (None, None) => true,
                _ => false,
            }
    }
}

/// What a computer in a realm should be serving, if anything.
///
/// A computer serves its plan's model and nothing else. One that is taking no work, that offers
/// no card, or whose computer has been taken out of the grid serves nothing at all, whatever it
/// was told last, which is the rule the hub enforces when it hands out work today.
pub fn what_to_serve(core: &Core, host_id: &str) -> Result<Option<Serving>, String> {
    let Some(host) = core.store.host(host_id)? else { return Ok(None) };
    if !host.takes_work() || !host.offered.gpu || !core.store.device(&host.device_id)?.is_some_and(|device| device.active()) {
        return Ok(None);
    }
    let Some(assignment) = core.model_assignments()?.into_iter().find(|assignment| assignment.host_id == host_id) else { return Ok(None) };
    let Some(plan) = core.model_plan(&assignment.plan_id)? else { return Ok(None) };
    Ok(Some(Serving {
        plan_id: plan.id,
        model: plan.model,
        quant: plan.quant,
        idle_after_minutes: plan.policy.idle_after_minutes,
        schedule: plan.policy.schedule,
    }))
}

fn scope(all: bool, remaining: bool) -> &'static str {
    match (all, remaining) {
        (true, _) => "all",
        (_, true) => "remaining",
        _ => "computers",
    }
}

/// Both paths asked the six questions, for the models profile.
///
/// Two of the six can be asked from a record on disk and four cannot, and saying which is which
/// is the point of returning a line for every one of them. A ledger that simply omitted the four
/// would read as though the models profile had been observed, and it would not have been.
pub fn observe(record: &hub::Record, now: i64) -> Vec<Observation> {
    let comparison = compare(record, now);
    let notes = comparison.notes.clone();
    let translation = translate(&record.id, record);
    let judge = crate::core::compat::observe::judge;
    let mut observations = Vec::new();

    // Plans: what the administrator asked this grid to serve. The model is compared by a short
    // digest of its name rather than by the name, because a ledger line never carries a name of
    // anything and a company's model names are a name. Two sides serving the same model have the
    // same digest and two sides serving different models do not, which is the whole question.
    for (plan, (_, core_id)) in record.plans.iter().zip(translation.named.iter()) {
        let hub = format!("model {}, {} percent, {}", short(&plan.model), plan.percent, scope(matches!(plan.target, hub::Target::All), matches!(plan.target, hub::Target::Remaining)));
        let core = match translation.plans.iter().find(|made| &made.id == core_id) {
            Some(made) => format!("model {}, {} percent, {}", short(&made.model), made.percent, scope(made.target == model::Target::All, made.target == model::Target::Remaining)),
            None => "not in the realm".to_owned(),
        };
        let verdict = judge(Heading::Plans, &hub, &core, &notes);
        observations.push(Observation::new(now, Profile::Models, Heading::Plans, &plan.id, &hub, &core, verdict));
    }

    // Assignments: which computer runs which plan. Every difference here stops.
    for placement in &comparison.computers {
        let hub = placement.hub.clone().unwrap_or_else(|| "no model".to_owned());
        let core = placement.core.clone().unwrap_or_else(|| "no model".to_owned());
        let verdict = judge(Heading::Assignments, &hub, &core, &notes);
        observations.push(Observation::new(now, Profile::Models, Heading::Assignments, &placement.member_id, &hub, &core, verdict));
    }

    // The four nothing here can ask, each with the reason it cannot.
    let unobservable = [
        (
            Heading::Permissions,
            "the company password and an API key",
            "one service account with no roles",
            "the Closed Neo Grid has no accounts: computers join with the company password and no person signs in at all, so there is nothing on the hub's side to compare an account against",
        ),
        (
            Heading::Workloads,
            "a queue the hub keeps in memory",
            "workload rows in the realm",
            "the hub keeps its queue, its running requests and its retries in memory and writes none of it to the record, so a reading of the record cannot see what is running",
        ),
        (
            Heading::Audit,
            "a callback the application owns",
            "a sealed chain in the realm",
            "the hub hands each event to a callback the application owns and keeps none of them in its record, so a reading of the record cannot compare the two histories",
        ),
        (
            Heading::Answers,
            "the hub's own model endpoint",
            "nothing: no request reaches a realm yet",
            "comparing what somebody asking would be told needs both paths serving, and the Phase 3 gate is still open: the legacy transport stays behind its compatibility adapter until that adapter is wired and streaming parity is verified",
        ),
    ];
    for (heading, hub, core, why) in unobservable {
        observations.push(Observation::new(now, Profile::Models, heading, &record.id, hub, core, Verdict::Unobserved(why.to_owned())));
    }
    observations
}

/// A model's name as eight hexadecimal characters, so two sides can be compared without the name
/// itself travelling. It is a digest and nothing more: it says whether two answers are the same
/// model, and it says nothing about which model that is to anybody who does not already know.
fn short(model: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(crate::model_key(model).as_bytes());
    hex::encode(hasher.finalize())[..8].to_owned()
}
