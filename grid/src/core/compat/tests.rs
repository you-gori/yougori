//! What the bridge from the Closed Neo Grid hub must hold true.
//!
//! The grids here are built as JSON because that is the shape a hub actually writes to disk, so
//! these run against the record itself rather than against a convenience built for the test.
use super::neo;
use crate::core::{
    identity::{PrincipalKind, Role},
    realm::{Capability, RealmKind},
    work::Resources,
    Core,
};
use crate::{hub, policy::IdlePolicy};
use serde_json::{json, Value};

fn key() -> String {
    "c".repeat(64)
}

fn member(id: &str, joined_at: i64, capable: bool, excluded: bool, plan: Option<&str>, assigned_at: Option<i64>) -> Value {
    json!({
        "id": id, "name": format!("Computer {id}"), "platform": "windows", "tokenHash": "", "joinedAt": joined_at,
        "capable": capable, "excluded": excluded, "plan": plan, "assignedAt": assigned_at, "jobs": 0,
    })
}

fn plan(id: &str, created_at: i64, model: &str, percent: u8, target: Value) -> Value {
    json!({"id": id, "model": model, "percent": percent, "policy": IdlePolicy::default(), "createdAt": created_at, "target": target})
}

fn all(id: &str, created_at: i64, percent: u8) -> Value {
    plan(id, created_at, "Acme/Chat", percent, json!({"kind": "all"}))
}

fn remaining(id: &str, created_at: i64, percent: u8) -> Value {
    plan(id, created_at, "Acme/Chat", percent, json!({"kind": "remaining"}))
}

fn picked(id: &str, created_at: i64, model: &str, members: &[&str]) -> Value {
    plan(id, created_at, model, 100, json!({"kind": "computers", "members": members}))
}

/// A hub's record, in the shape one is written in.
fn grid(members: Vec<Value>, plans: Vec<Value>) -> hub::Record {
    serde_json::from_value(json!({
        "version": 1, "id": "grid-1a2b3c", "name": "Acme", "address": "10.0.0.5", "port": 7460,
        "certificate": "", "salt": "", "createdAt": 0, "members": members, "plans": plans,
    }))
    .expect("a record in the shape a hub writes")
}

/// Four computers that can all run models, none left out and none holding a model yet.
fn four() -> Vec<Value> {
    (0..4).map(|index| member(&format!("m{index}"), index, true, false, None, None)).collect()
}

/// The moment the core stamps a new assignment with. Later than everything in these grids, as a
/// hub's own clock is when it places a computer.
const NOW: i64 = 1_000_000;

#[test]
fn the_hub_and_the_core_place_the_same_computers_in_every_shape_of_grid() {
    let table: Vec<(&str, hub::Record, Vec<Option<&str>>)> = vec![
        ("a grid with no computers", grid(Vec::new(), vec![all("a", 0, 50)]), Vec::new()),
        ("one computer and a share of all of them", grid(vec![member("m0", 0, true, false, None, None)], vec![all("a", 0, 50)]), vec![Some("a")]),
        ("one computer that cannot run models", grid(vec![member("m0", 0, false, false, None, None)], vec![all("a", 0, 100)]), vec![None]),
        ("a grid with no plans at all", grid(four(), Vec::new()), vec![None, None, None, None]),
        ("half of four computers, oldest first", grid(four(), vec![all("a", 0, 50)]), vec![Some("a"), Some("a"), None, None]),
        (
            "a plan the admin picked computers for",
            grid(four(), vec![picked("pick", 0, "Acme/Code", &["m1"])]),
            vec![None, Some("pick"), None, None],
        ),
        (
            "a pick beside a share of everything",
            grid(four(), vec![all("a", 0, 100), picked("pick", 1, "Acme/Code", &["m1"])]),
            vec![Some("a"), Some("pick"), Some("a"), Some("a")],
        ),
        (
            "a share of the computers nobody picked",
            grid(
                (0..5).map(|index| member(&format!("m{index}"), index, true, false, None, None)).collect(),
                vec![picked("pick", 0, "Acme/Code", &["m0"]), remaining("rest", 1, 50)],
            ),
            vec![Some("pick"), Some("rest"), Some("rest"), None, None],
        ),
        (
            "a mixture of a pick, a share of the rest and a share of all",
            grid(
                (0..5).map(|index| member(&format!("m{index}"), index, true, false, None, None)).collect(),
                vec![picked("pick", 0, "Acme/Code", &["m0"]), remaining("rest", 1, 50), all("a", 2, 40)],
            ),
            vec![Some("pick"), Some("rest"), Some("rest"), Some("a"), Some("a")],
        ),
        (
            "a computer the admin left out of the grid's work",
            grid(
                vec![
                    member("m0", 0, true, true, None, None),
                    member("m1", 1, true, false, None, None),
                    member("m2", 2, true, false, None, None),
                    member("m3", 3, true, false, None, None),
                ],
                vec![all("a", 0, 50)],
            ),
            vec![None, Some("a"), Some("a"), None],
        ),
        (
            "a computer left out that a plan picked anyway",
            grid(vec![member("m0", 0, true, true, None, None), member("m1", 1, true, false, None, None)], vec![picked("pick", 0, "Acme/Code", &["m0"])]),
            vec![None, None],
        ),
        (
            "lowering a share releases the computer that was given it last",
            grid(
                vec![
                    member("m0", 0, true, false, Some("a"), Some(100)),
                    member("m1", 1, true, false, Some("a"), Some(100)),
                    member("m2", 2, true, false, None, None),
                    member("m3", 3, true, false, None, None),
                ],
                vec![all("a", 0, 25)],
            ),
            vec![Some("a"), None, None, None],
        ),
        (
            "a computer with a model and no record of when it was given it",
            grid(
                vec![
                    member("m0", 0, true, false, Some("a"), None),
                    member("m1", 1, true, false, Some("a"), Some(500)),
                    member("m2", 2, true, false, None, None),
                    member("m3", 3, true, false, None, None),
                ],
                vec![all("a", 0, 25)],
            ),
            vec![Some("a"), None, None, None],
        ),
        (
            "two plans that picked the same computer, which is serving the later one",
            grid(
                vec![member("m0", 0, true, false, Some("second"), Some(100)), member("m1", 1, true, false, None, None)],
                vec![picked("first", 0, "Acme/Chat", &["m0"]), picked("second", 1, "Acme/Code", &["m0"])],
            ),
            vec![Some("first"), None],
        ),
        (
            "a computer that went away, still named by the plan that picked it",
            grid(
                vec![member("m0", 0, true, false, None, None), member("m2", 2, true, false, None, None)],
                vec![picked("pick", 0, "Acme/Code", &["m1"]), all("a", 1, 50)],
            ),
            vec![Some("a"), None],
        ),
        (
            "a computer holding a model from a plan this grid no longer has",
            grid(vec![member("m0", 0, true, false, Some("gone"), Some(100)), member("m1", 1, true, false, None, None)], Vec::new()),
            vec![None, None],
        ),
        (
            "a plan that wants every computer, and one that is left with none",
            grid(vec![member("m0", 0, true, false, None, None), member("m1", 1, true, false, None, None)], vec![all("a", 0, 100), all("b", 1, 50)]),
            vec![Some("a"), Some("a")],
        ),
    ];
    for (what, record, expected) in table {
        let comparison = neo::compare(&record, NOW);
        assert!(comparison.agrees(), "{what}: {}", comparison.describe());
        let placed: Vec<Option<&str>> = comparison.computers.iter().map(|placement| placement.hub.as_deref()).collect();
        assert_eq!(placed, expected, "{what}");
    }
}

/// A deterministic source of made-up grids. Held here with its seed so that a failure can be run
/// again exactly as it happened; the clock and a random number generator would both make a
/// failure something nobody can reproduce.
struct Dice(u64);

impl Dice {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut mixed = self.0;
        mixed = (mixed ^ (mixed >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        mixed = (mixed ^ (mixed >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        mixed ^ (mixed >> 31)
    }

    fn upto(&mut self, most: u64) -> u64 {
        self.next() % most
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.upto(100) < percent
    }
}

#[test]
fn made_up_grids_are_placed_the_same_way_by_the_hub_and_by_the_core() {
    let mut dice = Dice(0x5EED_1234_ABCD_0001);
    let mut with_picks = 0;
    let mut with_models_already = 0;
    for round in 0..3_000 {
        let count = dice.upto(9);
        // Identifiers a hub would really hand out: twelve random characters, in no relation to
        // the order the computers joined. Names like m0, m1 would hide every tie, because
        // deciding a tie by the identifier would happen to give the same answer as deciding it by
        // the order they joined.
        let members: Vec<String> = (0..count).map(|_| format!("member-{:012x}", dice.next() & 0xffff_ffff_ffff)).collect();
        // Plans are made first, so a computer can be given one that exists, or one that does not.
        let how_many_plans = dice.upto(5);
        let mut plans = Vec::new();
        for index in 0..how_many_plans {
            let id = format!("p{index}");
            let model = if dice.chance(50) { "Acme/Chat" } else { "Acme/Code" };
            // Percentages that land on a boundary are worth more than evenly spread ones.
            let percent = [1, 10, 25, 33, 50, 66, 75, 99, 100][dice.upto(9) as usize];
            let scope = dice.upto(100);
            plans.push(if scope < 35 && !members.is_empty() {
                let chosen: Vec<&str> = members.iter().filter(|_| dice.chance(40)).map(String::as_str).collect();
                let chosen = if chosen.is_empty() { vec![members[dice.upto(count) as usize].as_str()] } else { chosen };
                with_picks += 1;
                picked(&id, index as i64, model, &chosen)
            } else if scope < 60 {
                remaining(&id, index as i64, percent)
            } else {
                all(&id, index as i64, percent)
            });
        }
        let computers: Vec<Value> = members
            .iter()
            .map(|id| {
                // Several computers joining in the same second is the ordinary case, not an edge.
                let joined_at = dice.upto(3) as i64;
                let holding = if how_many_plans > 0 && dice.chance(45) {
                    with_models_already += 1;
                    if dice.chance(10) { Some("p9".to_owned()) } else { Some(format!("p{}", dice.upto(how_many_plans))) }
                } else {
                    None
                };
                // Assignments made in one pass all carry the same moment, so ties are the normal
                // state rather than a rarity, and some records have no moment at all.
                let since = holding.as_ref().and_then(|_| if dice.chance(15) { None } else { Some(1 + dice.upto(3) as i64) });
                member(id, joined_at, dice.chance(80), dice.chance(15), holding.as_deref(), since)
            })
            .collect();
        let record = grid(computers, plans);
        let comparison = neo::compare(&record, NOW);
        assert!(
            comparison.agrees(),
            "round {round} of seed {:#x}: {}\n{}",
            0x5EED_1234_ABCD_0001u64,
            comparison.describe(),
            serde_json::to_string(&record).unwrap_or_default()
        );
    }
    // The sweep is worth nothing if it never reached the cases that used to differ.
    assert!(with_picks > 300, "the sweep should be full of plans that picked computers, not {with_picks}");
    assert!(with_models_already > 2_000, "and of computers that already have a model, not {with_models_already}");
}

#[test]
fn picking_a_computer_again_is_resolved_the_same_way_by_the_hub_and_by_the_core() {
    let record = grid(four(), Vec::new());
    // One model on two computers.
    let first = neo::compare_new_plan(&record, "Acme/Chat", None, 0, IdlePolicy::default(), hub::Target::Computers { members: vec!["m0".into(), "m1".into()] }, NOW);
    assert!(first.agrees(), "{}", first.describe());
    assert_eq!(first.hub.len(), 1);
    assert_eq!(first.hub[0].picked, vec!["m0".to_owned(), "m1".to_owned()]);

    // The same grid, with that plan already in it: picking one of its computers for another model
    // takes it off the first plan rather than leaving two plans claiming one computer.
    let record = grid(four(), vec![picked("chat", 0, "Acme/Chat", &["m0", "m1"])]);
    let moved = neo::compare_new_plan(&record, "Acme/Code", None, 0, IdlePolicy::default(), hub::Target::Computers { members: vec!["m1".into()] }, NOW);
    assert!(moved.agrees(), "{}", moved.describe());
    assert_eq!(moved.hub.iter().map(|plan| (plan.model.as_str(), plan.picked.clone())).collect::<Vec<_>>(), vec![
        ("Acme/Chat", vec!["m0".to_owned()]),
        ("Acme/Code", vec!["m1".to_owned()]),
    ]);

    // Taking its last computer away empties the first plan, so the plan goes.
    let record = grid(four(), vec![picked("chat", 0, "Acme/Chat", &["m0"]), picked("code", 1, "Acme/Code", &["m1"])]);
    let emptied = neo::compare_new_plan(&record, "Acme/Code", None, 0, IdlePolicy::default(), hub::Target::Computers { members: vec!["m0".into()] }, NOW);
    assert!(emptied.agrees(), "{}", emptied.describe());
    assert_eq!(emptied.hub.len(), 1, "an emptied plan goes, and the same model picked again joins its plan");
    assert_eq!(emptied.hub[0].picked, vec!["m1".to_owned(), "m0".to_owned()]);

    // And the two refuse the same things, in their own words.
    let nobody = neo::compare_new_plan(&record, "Acme/Chat", None, 0, IdlePolicy::default(), hub::Target::Computers { members: vec!["nobody".into()] }, NOW);
    assert!(nobody.agrees() && nobody.hub_refused.is_some(), "{}", nobody.describe());
    let share = neo::compare_new_plan(&record, "Acme/Chat", None, 0, IdlePolicy::default(), hub::Target::Remaining, NOW);
    assert!(share.agrees() && share.core_refused.as_deref().is_some_and(|said| said.contains("percent")), "a share still needs its percent");
}

#[test]
fn a_hub_grid_is_rehearsed_brought_across_and_taken_back_out() {
    let folder = tempfile::tempdir().unwrap();
    let now = 30_000;
    let record = grid(
        vec![
            member("m0", 10, true, false, Some("a"), Some(100)),
            member("m1", 11, true, true, None, None),
            member("m2", 12, false, false, None, None),
        ],
        vec![all("a", 0, 50)],
    );
    let before = serde_json::to_string(&record).unwrap();

    let rehearsal = neo::rehearse(&record);
    assert_eq!((rehearsal.devices, rehearsal.hosts, rehearsal.plans, rehearsal.assignments), (3, 3, 1, 1));
    assert_eq!((rehearsal.model_capable, rehearsal.left_out), (2, 1));
    assert!(rehearsal.describe().contains("Acme"));
    assert!(rehearsal.notes.iter().any(|note| note.contains("is not carried over")), "{:?}", rehearsal.notes);

    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let imported = neo::import(&mut core, "owner", &record, now).unwrap();
    assert_eq!(serde_json::to_string(&record).unwrap(), before, "the hub's record is never changed by any of this");
    assert_eq!(imported.computers.len(), rehearsal.devices);
    assert_eq!(core.model_plans().unwrap().len(), 1);

    // The computer keeps the model it already had, with the moment it was given it, so bringing a
    // grid across costs nobody a download.
    let assignments = core.model_assignments().unwrap();
    assert_eq!(assignments.len(), 1);
    assert_eq!(assignments[0].host_id, "host-m0");
    assert_eq!(assignments[0].assigned_at, 100);
    assert_eq!(core.model_plans().unwrap()[0].id, "model-plan-a");
    // What it was on the hub is still readable in what it is here.
    assert_eq!(imported.computers[0].member_id, "m0");
    assert_eq!(imported.computers[0].host_id, "host-m0");

    // The computer the admin left out takes no work, and the one that cannot run models offers no
    // card, so neither of them is ever given a model here either.
    let hosts = core.store.hosts().unwrap();
    assert!(hosts.iter().find(|host| host.id == "host-m1").unwrap().draining);
    assert!(!hosts.iter().find(|host| host.id == "host-m2").unwrap().offered.gpu);
    // And nothing brought across can act in the realm: the secret it holds is the hub's.
    assert!(core.authenticate("device-m0", &key(), now).is_err());

    // A second import into the same realm is refused rather than making a second copy of a grid.
    assert!(neo::import(&mut core, "owner", &record, now + 1).unwrap_err().contains("already has computers"));

    // Taken back out, the realm is as it was, and the history still says both things happened.
    neo::roll_back(&mut core, "owner", &imported, now + 2).unwrap();
    assert!(core.model_plans().unwrap().is_empty() && core.model_assignments().unwrap().is_empty());
    assert!(core.store.hosts().unwrap().is_empty() && core.store.devices().unwrap().is_empty());
    assert!(core.principal(&imported.principal_id).unwrap().is_none());
    core.verify_audit().unwrap();
    let history = core.snapshot().unwrap().audit.events;
    assert!(history.iter().any(|event| event.action == "grid.imported"));
    assert!(history.iter().any(|event| event.action == "grid.import undone"));

    // And it can be brought across again afterwards, because nothing of it was left behind.
    neo::import(&mut core, "owner", &record, now + 3).unwrap();
    assert_eq!(core.model_assignments().unwrap().len(), 1);
}

#[test]
fn an_import_cannot_be_undone_once_work_has_been_placed_from_what_it_brought_in() {
    let folder = tempfile::tempdir().unwrap();
    let now = 31_000;
    let record = grid(vec![member("m0", 10, true, false, Some("a"), Some(100))], vec![all("a", 0, 100)]);
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let imported = neo::import(&mut core, "owner", &record, now).unwrap();

    // The computers come across with no permissions of their own; an admin gives them what they
    // need, and from then on the realm has work of its own that an undo would orphan.
    core.grant("owner", &imported.principal_id, Role::User, now).unwrap();
    let plan = core.model_plans().unwrap()[0].id.clone();
    let nothing = Resources::default();
    core.submit_model(&imported.principal_id, &imported.computers[0].device_id, &plan, nothing, None, now + 1).unwrap();
    let refused = neo::roll_back(&mut core, "owner", &imported, now + 2).unwrap_err();
    assert!(refused.contains("cannot be undone"), "{refused}");
    assert_eq!(core.model_plans().unwrap().len(), 1, "and nothing of it was taken out on the way to refusing");
}

#[test]
fn bringing_a_grid_across_needs_a_realm_that_serves_models_and_someone_who_may_do_it() {
    let folder = tempfile::tempdir().unwrap();
    let now = 32_000;
    let record = grid(four(), vec![all("a", 0, 50)]);
    let mut workspaces = Core::create(&folder.path().join("desks.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    assert!(neo::import(&mut workspaces, "owner", &record, now).unwrap_err().contains("does not serve models"));

    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let operator = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let refused = neo::import(&mut core, &operator.id, &record, now).unwrap_err();
    assert!(refused.contains("may not manage people"), "{refused}");
    assert!(core.store.hosts().unwrap().is_empty(), "nothing is written by an import that is refused");
}

#[test]
fn a_computer_is_told_its_plans_model_and_the_rules_it_serves_under() {
    let folder = tempfile::tempdir().unwrap();
    let now = 33_000;
    let record = grid(
        vec![member("m0", 10, true, false, Some("a"), Some(100)), member("m1", 11, true, true, None, None)],
        vec![json!({
            "id": "a", "model": "Acme/Chat", "quant": "Q4_K_M", "percent": 100,
            "policy": {"idleAfterMinutes": 20, "schedule": "Mon-Fri 18:00-08:00"},
            "createdAt": 0, "target": {"kind": "all"}
        })],
    );
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    neo::import(&mut core, "owner", &record, now).unwrap();

    let serving = neo::what_to_serve(&core, "host-m0").unwrap().expect("the computer serves its plan");
    assert_eq!(serving.model, "Acme/Chat");
    assert_eq!(serving.quant.as_deref(), Some("Q4_K_M"));
    assert_eq!((serving.idle_after_minutes, serving.schedule.as_deref()), (20, Some("Mon-Fri 18:00-08:00")));
    // The same model environment under another spelling of the quantization, so editing a plan
    // does not send a computer to download weights it already holds.
    assert!(serving.same_model("acme/chat", Some("q4_k_m")));
    assert!(!serving.same_model("Acme/Chat", Some("Q8_0")) && !serving.same_model("Acme/Chat", None));

    // A computer the admin left out of the grid's work serves nothing, whatever it was told last.
    assert_eq!(neo::what_to_serve(&core, "host-m1").unwrap(), None);
    assert_eq!(neo::what_to_serve(&core, "host-nobody").unwrap(), None);
}

// ---- The Sandbox Grid's desks ----

/// A computer that hosts desks: the share its admin set is what the grid may take from it.
fn hosting(id: &str, joined_at: i64, cpu: f64, memory_gb: f64, disk_gb: f64, idle_only: bool) -> Value {
    json!({
        "id": id, "name": format!("Computer {id}"), "platform": "windows", "tokenHash": "", "joinedAt": joined_at,
        "capable": false, "excluded": false, "plan": null, "assignedAt": null, "jobs": 0,
        "share": {"cpu": cpu, "memoryGb": memory_gb, "diskGb": disk_gb, "gpu": false, "idleOnly": idle_only},
    })
}

fn spec(kind: &str, disk_gb: f64, image: &str) -> Value {
    json!({"kind": kind, "cpu": 2.0, "memoryGb": 4.0, "diskGb": disk_gb, "gpu": false, "image": image})
}

fn person(id: &str, username: &str, name: &str, admin_role: &str) -> Value {
    json!({"id": id, "username": username, "adminRole": admin_role, "name": name, "salt": "s", "keyHash": "h", "createdAt": 5})
}

fn desk(id: &str, name: &str, spec: Value, person: Option<&str>, state: &str, host: Option<&str>) -> Value {
    json!({
        "id": id, "name": name, "spec": spec, "access": "standard", "generation": 2, "person": person,
        "state": state, "host": host, "environmentId": host.map(|_| "env-4"), "note": "Ready",
        "trail": host.map(|host| vec![host.to_owned()]).unwrap_or_default(), "attempts": 1, "createdAt": 6, "updatedAt": 7,
    })
}

/// A Sandbox Grid as a hub writes one: three computers, two people, a catalogue image, a desk
/// built from it, a desk ordered by hand from the product's own default image, and a desk whose
/// data is packed up and waiting for a computer.
fn sandbox() -> hub::Record {
    let shipped = crate::desks::DeskSpec::checked(crate::desks::DeskKind::Container, 2.0, 4.0, 10.0, false, "").unwrap();
    let pinned = format!("docker.io/library/ubuntu@sha256:{}", "b".repeat(64));
    let mut packed = desk("desk-c", "Research", spec("vm", 20.0, "D:/Prepared Images/research.qcow2"), Some("person-b"), "moving", None);
    packed["parcel"] = json!({"store": "hub", "key": "desk-c", "bytes": 4096, "sha256": "a".repeat(64), "at": 8});
    packed["movingFrom"] = json!("m0");
    packed["trail"] = json!(["m0"]);
    serde_json::from_value(json!({
        "version": 1, "id": "grid-9f8e7d", "name": "Acme", "address": "10.0.0.5", "port": 7465,
        "certificate": "", "salt": "", "createdAt": 1,
        "members": [hosting("m0", 10, 4.0, 16.0, 100.0, false), hosting("m1", 11, 4.0, 16.0, 100.0, true), hosting("m2", 12, 2.0, 8.0, 50.0, false)],
        "people": [person("person-a", "ada", "Ada Lovelace", "user"), person("person-b", "grace", "Grace Hopper", "administrator")],
        "desks": [
            desk("desk-a", "Design", spec("container", 10.0, &pinned), Some("person-a"), "ready", Some("m0")),
            desk("desk-b", "Spare", spec("container", 10.0, &shipped.image), None, "planned", None),
            packed,
        ],
        "enterprise": {
            "images": [{
                "id": "image-1", "name": "Ubuntu with tools", "version": "24.04", "description": "The standard desk",
                "applications": ["code"], "spec": spec("container", 10.0, &pinned),
                "sha256": null, "createdAt": 3,
            }],
            "parking": {"provider": "awsS3", "location": "s3://acme-desks/parcels", "setAt": 4},
        },
    }))
    .expect("a record in the shape a hub writes")
}

#[test]
fn a_sandbox_grid_is_rehearsed_brought_across_and_taken_back_out() {
    use crate::core::compat::desks;
    use crate::core::identity::Action;
    use crate::core::workspace::{ArtifactStore, ImageSource, WorkspaceState};
    let folder = tempfile::tempdir().unwrap();
    let now = 40_000;
    let record = sandbox();
    let before = serde_json::to_string(&record).unwrap();

    // The rehearsal says what would happen and writes nothing at all.
    let rehearsal = desks::rehearse(&record, now).unwrap();
    assert_eq!((rehearsal.principals, rehearsal.devices, rehearsal.hosts, rehearsal.commitments), (3, 3, 3, 3));
    assert_eq!((rehearsal.workspaces, rehearsal.owned, rehearsal.placed, rehearsal.parcels), (3, 2, 1, 1));
    assert_eq!((rehearsal.images, rehearsal.images_for_desks, rehearsal.unpinned), (3, 2, 2));
    assert!(rehearsal.describe().contains("Acme"));
    assert!(rehearsal.notes.iter().any(|note| note.contains("administrators become workspace administrators")), "{:?}", rehearsal.notes);
    assert!(rehearsal.notes.iter().any(|note| note.contains("password comes across")));
    assert!(rehearsal.notes.iter().any(|note| note.contains("unhashed")));
    assert_eq!(serde_json::to_string(&record).unwrap(), before, "a rehearsal writes nothing, here or on the hub");

    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    let empty = core.backup(now).unwrap();
    let imported = desks::import(&mut core, "owner", &record, now).unwrap();
    assert_eq!(serde_json::to_string(&record).unwrap(), before, "the hub's record is never changed by any of this");
    assert_eq!((imported.people.len(), imported.computers.len(), imported.workspaces.len(), imported.images.len()), (2, 3, 3, 3));

    // Every desk arrives as a workspace with the person it belonged to, on the computer it was
    // on, with the trail that leads back to it.
    let design = core.workspace("workspace-a").unwrap().expect("the desk is here under a name that still shows what it was");
    assert_eq!((design.state, design.owner_id.as_deref()), (WorkspaceState::Assigned, Some("principal-a")));
    assert_eq!(design.generation, 3, "a generation starts at one here and at zero on the hub");
    assert_eq!(core.workspace_trail("workspace-a").unwrap(), vec!["host-m0".to_owned()]);
    assert_eq!(core.store.live_assignment("workspace-a").unwrap().unwrap().placement_ref.as_deref(), Some("env-4"));

    // The product's own default image is an OCI tag, and it comes across as one, unpinned.
    let spare = core.workspace("workspace-b").unwrap().unwrap();
    let image = core.image(&spare.image_id).unwrap().unwrap();
    assert_eq!(image.source, ImageSource::Oci { reference: "docker.io/library/ubuntu:24.04".to_owned() });
    assert!(!image.pinned() && spare.image_digest.is_none());

    // A prepared VM image is recorded by its file name alone; which folder it sat in is nobody
    // else's business and is deliberately not carried into a company record.
    let research = core.workspace("workspace-c").unwrap().unwrap();
    let media = core.image(&research.image_id).unwrap().unwrap();
    assert_eq!(media.source, ImageSource::Media { name: "research.qcow2".to_owned() });
    assert_eq!(research.state, WorkspaceState::Requested, "its data is packed and it is waiting for a computer");
    let parcel = core.store.waiting_artifact("workspace-c").unwrap().unwrap();
    assert_eq!((parcel.store, parcel.object_key.as_str(), parcel.bytes), (ArtifactStore::Hub, "desk-c", 4_096));
    assert_eq!(parcel.packed_by, "host-m0");

    // The share the admin set comes across, including "only while nobody is using it". The words
    // beside it are this grid's own: the hub keeps no agreed sentence to carry.
    let idle_only = core.commitments("host-m1").unwrap();
    assert_eq!(idle_only.len(), 1);
    assert!(idle_only[0].idle_only && idle_only[0].wording.contains("only while nobody is using the computer"));
    assert!(core.commitments("host-m0").unwrap()[0].wording.contains("may not read your own files"));

    // The Sandbox Grid's administrator becomes a workspace administrator and an operator, and
    // not the owner of the realm.
    let grace = core.principal("principal-b").unwrap().unwrap();
    assert!(grace.may(Action::ManageWorkspaces) && grace.may(Action::UseWorkspace));
    assert!(!grace.may(Action::ManagePeople), "running the realm is wider than the hub ever gave");

    // Nothing in the realm's database is a folder on anybody's computer.
    let travelling = serde_json::to_string(&core.snapshot().unwrap()).unwrap();
    assert!(!travelling.contains("Prepared Images"), "a prepared image's folder is not carried");

    // Running it twice is refused rather than bringing everything across again.
    assert!(desks::import(&mut core, "owner", &record, now + 1).unwrap_err().contains("already has workspaces"));

    // And it is reversible: what the import created goes, what happened stays, and the realm is
    // back to where the backup taken before it ran says it was.
    desks::roll_back(&mut core, "owner", &imported, now + 2).unwrap();
    let after = core.snapshot().unwrap();
    assert!(after.workspaces.is_empty() && after.images.is_empty() && after.assignments.is_empty() && after.artifacts.is_empty());
    assert!(after.commitments.is_empty() && after.hosts.is_empty() && after.devices.is_empty());
    assert_eq!(after.principals.len(), empty.record.principals.len(), "the realm is as it was before the import ran");
    core.verify_audit().unwrap();
    assert!(core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "grid.desks.imported"));
    assert!(core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "grid.desks.import undone"), "and both halves are in the history");
}

#[test]
fn an_import_that_somebody_is_already_using_cannot_be_taken_back_out() {
    use crate::core::compat::desks;
    let folder = tempfile::tempdir().unwrap();
    let now = 41_000;
    let record = sandbox();
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    let imported = desks::import(&mut core, "owner", &record, now).unwrap();

    // Ada enrols a computer of her own and opens the desk that came across.
    let (laptop, _) = core.enrol_device("principal-a", "Ada's laptop", "windows", now + 1).unwrap();
    core.open_workspace("principal-a", &laptop.id, "workspace-a", 600, now + 2).unwrap();
    let refused = desks::roll_back(&mut core, "owner", &imported, now + 3).unwrap_err();
    assert!(refused.contains("Somebody is in one of the workspaces"), "{refused}");

    // And once nobody is in it, the computer she enrolled against an imported account is its own
    // reason, said in its own words rather than as a database failure.
    core.close_workspace_sessions("owner", "workspace-a", "the day ended", now + 4).unwrap();
    let refused = desks::roll_back(&mut core, "owner", &imported, now + 5).unwrap_err();
    assert!(refused.contains("enrolled a computer of their own"), "{refused}");
    assert_eq!(core.workspaces().unwrap().len(), 3, "and nothing was half taken out while it was refusing");
}

#[test]
fn two_catalogue_labels_for_one_set_of_bytes_arrive_as_the_one_image() {
    use crate::core::compat::desks;
    let folder = tempfile::tempdir().unwrap();
    let now = 42_000;
    let mut record = sandbox();

    // The hub tells two catalogue entries apart by their name and their version, and invites a
    // second entry for the same image by refusing a duplicate with "publish a new version". So
    // the same bytes are published twice, under two labels and with a larger disk.
    let mut again = record.enterprise.images[0].clone();
    again.id = "image-2".to_owned();
    again.version = "24.04.1".to_owned();
    again.spec.disk_gb = 20.0;
    record.enterprise.images.push(again);

    // Here the digest is what an image is, and the database says so, so both labels are the one
    // image and the rehearsal says which count it gave and why.
    let rehearsal = desks::rehearse(&record, now).unwrap();
    assert_eq!(rehearsal.images, 3, "{:?}", rehearsal.notes);
    assert!(rehearsal.notes.iter().any(|note| note.contains("name bytes another image here already names")), "{:?}", rehearsal.notes);

    // And the import runs, rather than writing the accounts, the computers and the commitments
    // and then stopping on the second label with nothing handed back to undo what it had done.
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    let imported = desks::import(&mut core, "owner", &record, now).unwrap();
    assert_eq!(imported.images.len(), 3);
    assert!(core.image("image-2").unwrap().is_none(), "the second label is not an image of its own");
    assert_eq!(core.workspace("workspace-a").unwrap().unwrap().image_id, "image-1", "and a desk built from either arrives built from the one");
    assert_eq!(core.images().unwrap().iter().filter(|image| image.digest.is_some()).count(), 1);
}

#[test]
fn a_prepared_image_the_hub_itself_holds_comes_across_pinned_to_those_bytes() {
    use crate::core::compat::desks;
    use crate::core::workspace::ImageSource;
    let folder = tempfile::tempdir().unwrap();
    let now = 42_500;
    let checksum = "c".repeat(64);
    let mut record = sandbox();

    // A prepared disk image is published either as an https:// address every computer can reach
    // or as the checksum of bytes the hub itself holds, and the second of those is the only way
    // that is not an address at all.
    record.enterprise.images.push(
        serde_json::from_value(json!({
            "id": "image-2", "name": "Windows", "version": "11", "description": "A prepared disk the hub holds",
            "applications": [], "spec": spec("vm", 40.0, &format!("grid-image:{checksum}")),
            "sha256": checksum, "createdAt": 3,
        }))
        .expect("a catalogue entry in the shape a hub writes"),
    );

    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    desks::import(&mut core, "owner", &record, now).unwrap();
    let held = core.image("image-2").unwrap().expect("the catalogue entry came across");
    assert_eq!(held.source, ImageSource::Hub, "the realm already has a word for bytes the hub serves");
    assert_eq!(held.digest.as_deref(), Some(format!("sha256:{checksum}").as_str()));
    assert!(held.pinned(), "the checksum the hub was given is the digest, so it arrives pinned");
}

#[test]
fn undoing_a_desk_import_takes_off_the_commitments_it_wrote_and_leaves_the_computers() {
    use crate::core::compat::desks;
    let folder = tempfile::tempdir().unwrap();
    let now = 43_000;
    let record = sandbox();
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Workspaces], &key(), now).unwrap();

    // The model bridge brought this company's computers in first. Both bridges name a computer
    // after the member it was, so the desk import finds every one of them already here and
    // creates none, while still committing each of them to the realm.
    neo::import(&mut core, "owner", &record, now).unwrap();
    assert!(core.commitments("host-m0").unwrap().is_empty(), "the model bridge commits nothing");
    let imported = desks::import(&mut core, "owner", &record, now + 1).unwrap();
    assert!(imported.computers.is_empty(), "every computer was already in the realm");
    assert_eq!(imported.commitments.len(), 3, "and every commitment is this import's own");
    assert_eq!(core.commitments("host-m0").unwrap().len(), 1);

    // So undoing it has to take those off again. A commitment is what lets the realm place work
    // on a computer, and these computers could take nothing at all before this import ran.
    desks::roll_back(&mut core, "owner", &imported, now + 2).unwrap();
    for host in ["host-m0", "host-m1", "host-m2"] {
        assert!(core.commitments(host).unwrap().is_empty(), "{host} is as it was before the desk import ran");
        assert!(core.store.host(host).unwrap().is_some(), "and the computer the model bridge brought in stays");
    }
}

/// What the rest of the rollout has to hold true: the desk comparison, the rehearsal on copies,
/// the backup, the survey, the observation ledger and the stages.
///
/// The grids here are built as JSON for the same reason the ones above are: that is the shape a
/// hub actually writes to disk, so these run against the record itself.
mod rollout {
    use super::key;
    use crate::core::compat::{
        backup,
        frozen::{self, Product},
        observe::{self, Heading, Profile, Verdict},
        rehearsal, rollout, survey, Sources,
    };
    use crate::core::realm::{Capability, RealmKind};
    use crate::core::Core;
    use crate::{desks, hub};
    use serde_json::{json, Value};

    const NOW: i64 = 1_700_100_000;

    fn share(cpu: f64, memory_gb: f64, disk_gb: f64, idle_only: bool) -> Value {
        json!({"cpu": cpu, "memoryGb": memory_gb, "diskGb": disk_gb, "gpu": false, "idleOnly": idle_only})
    }

    fn member(id: &str, joined_at: i64, share: Value) -> Value {
        json!({"id": id, "name": format!("Computer {id}"), "platform": "linux", "tokenHash": "", "joinedAt": joined_at, "capable": false, "excluded": false, "jobs": 0, "share": share})
    }

    fn desk(id: &str, state: &str, host: Option<&str>, person: Option<&str>) -> Value {
        json!({
            "id": id, "name": format!("Desk {id}"),
            "spec": {"kind": "container", "cpu": 2.0, "memoryGb": 4.0, "diskGb": 40.0, "gpu": false, "image": "example/image:1"},
            "access": "standard", "generation": 0, "person": person, "state": state, "host": host,
            "note": "", "trail": [], "attempts": 0, "createdAt": 10, "updatedAt": 20
        })
    }

    fn person(id: &str, role: &str) -> Value {
        json!({"id": id, "username": id, "adminRole": role, "name": format!("Person {id}"), "salt": "s", "keyHash": "h", "createdAt": 5})
    }

    fn sandbox(members: Vec<Value>, desks: Vec<Value>, people: Vec<Value>) -> hub::Record {
        serde_json::from_value(json!({
            "version": 1, "id": "grid-d1d2d3", "name": "Acme Desks", "address": "10.0.0.5", "port": 7462,
            "certificate": "", "salt": "", "createdAt": 0, "members": members, "desks": desks, "people": people,
        }))
        .expect("a record in the shape a hub writes")
    }

    /// A computer that has reported how it is. `None` for one that has told the hub nothing,
    /// which is every computer when the only thing anybody has is the record on disk.
    fn view(id: &str, share: Option<desks::Share>, capacity: Option<desks::Capacity>) -> desks::HostView {
        desks::HostView { id: id.to_owned(), online: capacity.is_some(), excluded: false, going_away: false, capacity, share }
    }

    fn reported(free_disk_gb: f64, on_battery: bool, in_use: bool) -> desks::Capacity {
        desks::Capacity { cpu: 8, desk_protocol: 2, memory_gb: 16.0, free_disk_gb, on_battery, in_use, ..Default::default() }
    }

    fn views(record: &hub::Record, capacity: impl Fn(usize) -> Option<desks::Capacity>) -> Vec<desks::HostView> {
        record.members.iter().enumerate().map(|(index, member)| view(&member.id, member.share.clone(), capacity(index))).collect()
    }

    /// PROVES that the Sandbox Grid hub and Grid Core put the same desks on the same computers,
    /// over a table of grid shapes: nothing reported, one computer with room, a computer on
    /// battery, a computer whose person is back when the grid was lent only its idle time, a desk
    /// already placed, and more desks than one computer has room for.
    ///
    /// DOES NOT PROVE agreement under concurrency or over a real sequence of events. Each case is
    /// one record compared once, and the live view of each computer is supplied by the test rather
    /// than taken from a running hub, which is the thing this repository cannot do.
    #[test]
    fn the_hub_and_the_core_place_the_same_desks_in_every_shape_of_grid() {
        let folder = tempfile::tempdir().unwrap();
        let roomy = || Some(reported(200.0, false, false));
        /// One shape of grid: what it is called, the record, what each computer has reported,
        /// and which computer each desk should end on.
        type Shape = (&'static str, hub::Record, Box<dyn Fn(usize) -> Option<desks::Capacity>>, Vec<Option<&'static str>>);
        let table: Vec<Shape> = vec![
            (
                "no computer has said how it is",
                sandbox(vec![member("m0", 0, share(4.0, 8.0, 100.0, false))], vec![desk("d0", "planned", None, None)], Vec::new()),
                Box::new(|_| None),
                vec![None],
            ),
            (
                "one computer with room",
                sandbox(vec![member("m0", 0, share(4.0, 8.0, 100.0, false))], vec![desk("d0", "planned", None, None)], Vec::new()),
                Box::new(move |_| roomy()),
                vec![Some("m0")],
            ),
            (
                "the first computer is on battery",
                sandbox(
                    vec![member("m0", 0, share(4.0, 8.0, 100.0, false)), member("m1", 1, share(4.0, 8.0, 100.0, false))],
                    vec![desk("d0", "planned", None, None)],
                    Vec::new(),
                ),
                Box::new(move |index| if index == 0 { Some(reported(200.0, true, false)) } else { roomy() }),
                vec![Some("m1")],
            ),
            (
                "the first computer's person is back and the grid was lent only its idle time",
                sandbox(
                    vec![member("m0", 0, share(4.0, 8.0, 100.0, true)), member("m1", 1, share(4.0, 8.0, 100.0, false))],
                    vec![desk("d0", "planned", None, None)],
                    Vec::new(),
                ),
                Box::new(move |index| if index == 0 { Some(reported(200.0, false, true)) } else { roomy() }),
                vec![Some("m1")],
            ),
            (
                "a desk that is already on a computer stays where it is",
                sandbox(
                    vec![member("m0", 0, share(4.0, 8.0, 100.0, false)), member("m1", 1, share(4.0, 8.0, 100.0, false))],
                    vec![desk("d0", "ready", Some("m0"), Some("p0")), desk("d1", "planned", None, None)],
                    vec![person("p0", "user")],
                ),
                Box::new(move |_| roomy()),
                vec![Some("m0"), Some("m1")],
            ),
            (
                "two desks and only one computer with room for both",
                sandbox(
                    vec![member("m0", 0, share(4.0, 8.0, 100.0, false))],
                    vec![desk("d0", "planned", None, None), desk("d1", "planned", None, None)],
                    Vec::new(),
                ),
                Box::new(move |_| roomy()),
                vec![Some("m0"), Some("m0")],
            ),
            (
                "three desks and room for two",
                sandbox(
                    vec![member("m0", 0, share(4.0, 8.0, 100.0, false))],
                    vec![desk("d0", "planned", None, None), desk("d1", "planned", None, None), desk("d2", "planned", None, None)],
                    Vec::new(),
                ),
                Box::new(move |_| roomy()),
                vec![Some("m0"), Some("m0"), None],
            ),
        ];
        for (what, record, capacity, expected) in table {
            let hosts = views(&record, capacity);
            let comparison = crate::core::compat::desks::compare(&record, &hosts, &folder.path().join(what.replace(' ', "-")), NOW).expect(what);
            let hub: Vec<Option<&str>> = comparison.desks.iter().map(|placement| placement.hub.as_deref()).collect();
            let core: Vec<Option<&str>> = comparison.desks.iter().map(|placement| placement.core.as_deref()).collect();
            assert_eq!(hub, expected, "the hub places these desks differently from what this test expects: {what}");
            assert_eq!(core, expected, "the core and the hub disagree: {what}\n{}", comparison.describe());
            assert!(comparison.agrees(), "{what}\n{}", comparison.describe());
        }
    }

    /// PROVES that a desk already on a computer is compared against where the realm has it rather
    /// than against the hub's own answer handed back, so a placement the bridge did not carry
    /// across shows as a difference under Assignments, which is the heading a pilot is gated on.
    ///
    /// DOES NOT PROVE that the two would choose the same computer for a desk that is already on
    /// one. Neither side chooses one at all for those, and the comparison says so in a note
    /// instead of letting the row read as agreement about a choice.
    #[test]
    fn a_desk_already_on_a_computer_is_compared_against_where_the_realm_has_it() {
        let folder = tempfile::tempdir().unwrap();
        let roomy = |_: usize| Some(reported(200.0, false, false));
        // The hub has this desk on a computer that is not in its own member list, so the bridge
        // has nowhere to put it and the realm holds no placement for it at all.
        let adrift = sandbox(vec![member("m0", 0, share(4.0, 8.0, 100.0, false))], vec![desk("d0", "ready", Some("m9"), Some("p0"))], vec![person("p0", "user")]);
        let comparison = crate::core::compat::desks::compare(&adrift, &views(&adrift, roomy), &folder.path().join("adrift"), NOW).unwrap();
        assert_eq!(comparison.desks[0].hub.as_deref(), Some("m9"), "the hub has it on a computer it no longer knows");
        assert_eq!(comparison.desks[0].core, None, "and the realm has it nowhere, which is the difference that reading the hub's own field hid");
        assert!(!comparison.agrees(), "{}", comparison.describe());

        // And a settled desk the bridge did carry across agrees, with a note saying what that
        // agreement is worth.
        let settled = sandbox(vec![member("m0", 0, share(4.0, 8.0, 100.0, false))], vec![desk("d0", "ready", Some("m0"), Some("p0"))], vec![person("p0", "user")]);
        let comparison = crate::core::compat::desks::compare(&settled, &views(&settled, roomy), &folder.path().join("settled"), NOW).unwrap();
        assert_eq!(comparison.desks[0].core.as_deref(), Some("m0"), "the realm has it where the hub has it");
        assert!(comparison.agrees(), "{}", comparison.describe());
        assert!(
            comparison.notes.iter().any(|note| note.contains("neither side chooses one again for them")),
            "an agreement neither side chose has to say so: {:?}",
            comparison.notes
        );
    }

    /// PROVES that a comparison taken from a record alone, with no live view of any computer,
    /// says so in its own notes rather than reading as agreement.
    ///
    /// DOES NOT PROVE that a comparison with live views is right. It proves the weak one is
    /// labelled, which is the part that can be checked here at all.
    #[test]
    fn a_comparison_with_nothing_reported_says_that_is_all_it_proves() {
        let folder = tempfile::tempdir().unwrap();
        let record = sandbox(vec![member("m0", 0, share(4.0, 8.0, 100.0, false))], vec![desk("d0", "planned", None, None)], Vec::new());
        let hosts = crate::core::compat::desks::hosts_from_record(&record);
        let comparison = crate::core::compat::desks::compare(&record, &hosts, folder.path(), NOW).unwrap();
        assert!(comparison.agrees(), "both sides refuse a computer that has said nothing");
        assert!(
            comparison.notes.iter().any(|note| note.contains("this reading says only that both refuse a computer that has said nothing")),
            "a comparison with nothing reported has to say what it is worth: {:?}",
            comparison.notes
        );
    }

    /// PROVES that a difference about where something goes always ends a pilot, that a core which
    /// allows less than the hub did is a note, that a core which allows something the hub never
    /// granted stops, and that a difference the bridge wrote a note about is a note.
    ///
    /// DOES NOT PROVE that the note list is complete. A deliberate difference nobody wrote a note
    /// for stops the pilot, which is the safe direction and will cost a false stop.
    #[test]
    fn a_placement_difference_always_stops_and_a_narrower_permission_is_noted() {
        let notes = vec!["desks were ordered from a workspace role; the image and the access that role resolved to come across, and the role itself stays with the hub".to_owned()];
        assert_eq!(observe::judge(Heading::Assignments, "member-1", "member-1", &notes), Verdict::Agrees);
        assert!(observe::judge(Heading::Assignments, "member-1", "member-2", &notes).stops(), "two computers is a stop");
        assert!(observe::judge(Heading::Assignments, "member-1", "nowhere", &notes).stops(), "placed on one side and not the other is a stop");

        let wider = observe::judge(Heading::Permissions, "operator, user", "operator, realm administrator, user", &notes);
        assert!(wider.stops(), "the core granting something the hub never did is a stop: {wider:?}");
        let narrower = observe::judge(Heading::Permissions, "operator, realm administrator, user", "operator, user", &notes);
        assert!(matches!(narrower, Verdict::Noted(_)), "the core granting less is a note: {narrower:?}");

        let explained = observe::judge(Heading::Plans, "ordered from a workspace role", "ordered without a role", &notes);
        assert!(matches!(explained, Verdict::Noted(_)), "a difference the bridge wrote a note about is a note: {explained:?}");
        let unexplained = observe::judge(Heading::Plans, "40 GB disk", "80 GB disk", &notes);
        assert!(unexplained.stops(), "a difference nothing explains stops: {unexplained:?}");
    }

    /// PROVES that every profile is observed under every one of the six headings, and that a
    /// heading nothing on this computer can ask produces a line saying so and why, rather than
    /// producing nothing. A ledger that is silent about a question and one that says the question
    /// could not be asked read very differently to whoever decides whether a rollout may go on.
    ///
    /// DOES NOT PROVE that the observable profiles are observed well. What each profile can and
    /// cannot be asked from a record on disk is in its own bridge, and most of the headings need a
    /// running product.
    #[test]
    fn every_profile_is_observed_including_the_ones_that_cannot_be() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(folder.path());
        let passes = observe::watch(&sources, &folder.path().join("scratch"), NOW).unwrap();
        let profiles: Vec<Profile> = passes.iter().map(|pass| pass.profile).collect();
        assert_eq!(profiles, Profile::all().to_vec(), "every profile this deployment has is watched, in the rollout's order");
        for pass in &passes {
            for heading in Heading::all() {
                assert!(
                    pass.observations.iter().any(|observation| observation.heading == *heading),
                    "{} says nothing at all about {}",
                    pass.profile.word(),
                    heading.name()
                );
            }
        }
        for pass in &passes {
            assert!(
                pass.observations.iter().any(|observation| matches!(observation.verdict, Verdict::Unobserved(_))),
                "{} claims every one of the six can be asked from a record on a disk",
                pass.profile.word()
            );
            assert!(pass.clean(), "{}: {}", pass.profile.word(), pass.describe());
        }

        // The two bridges written last answer real questions rather than only saying they cannot.
        for profile in [Profile::Research, Profile::Credentials] {
            let pass = passes.iter().find(|pass| pass.profile == profile).unwrap();
            assert!(
                pass.observations.iter().any(|observation| matches!(observation.verdict, Verdict::Agrees)),
                "{} answers nothing at all, which a bridge should not",
                profile.word()
            );
        }
    }

    /// PROVES that an observation line carries counts, identifiers, state words and fixed
    /// sentences, and none of the names, emails, certificates, salts, hashes or sealed values
    /// that are in the records it was built from.
    ///
    /// DOES NOT PROVE that a field added later is safe. It checks the fields that exist against
    /// the secrets the fixtures themselves hold, so something new carrying something new has to
    /// be added here.
    #[test]
    fn an_observation_never_carries_a_name_an_email_or_a_secret() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(folder.path());
        let passes = observe::watch(&sources, &folder.path().join("scratch"), NOW).unwrap();
        let written = serde_json::to_string(&passes).unwrap();
        for secret in [
            "Person One",
            "one@example.invalid",
            "FIXTURE CERTIFICATE",
            "FIXTURE-SEALED",
            "FIXTURETOTP",
            "00112233445566778899aabbccddeeff",
            "example/one",
            "Review the example service",
            "grid.example.invalid",
            "10.0.0.5",
        ] {
            assert!(!written.contains(secret), "an observation carried {secret}");
        }
    }

    /// Every frozen fixture, copied into a folder, as a deployment this phase can be run against.
    /// They are the only records in this repository that are a whole grid, and they were made up
    /// here rather than taken from anywhere.
    fn fixtures(into: &std::path::Path) -> Sources {
        std::fs::create_dir_all(into).unwrap();
        let from = frozen::fixture_folder();
        let copy = |fixture: &str, name: &str| {
            let to = into.join(name);
            std::fs::copy(from.join(fixture), &to).unwrap();
            to
        };
        Sources {
            neo_hub: Some(copy("neo-hub-v1.json", "hub.json")),
            desks_hub: Some(copy("sandbox-hub-v1.json", "desks-hub.json")),
            bounty_host: Some(copy("bounty-host-v1.json", "host.json")),
            access_hub: Some(copy("access-hub-v1.json", "access-hub.json")),
            realms: Vec::new(),
        }
    }

    /// PROVES that a rehearsal reads every record it was given and writes nothing outside its own
    /// folder: every source file's bytes are what they were, and the realm's database is not
    /// brought forward by being looked at.
    ///
    /// DOES NOT PROVE that a rehearsal on a loaded production database is quick, or that taking a
    /// consistent copy does not contend with live writers. Nothing here is under load. Nor does it
    /// prove the realm's bytes never move: this realm was closed before it was read, so its
    /// journal was already check-pointed and empty. A realm a crash left with a journal beside it
    /// has its own test, `taking_a_copy_leaves_the_realm_holding_exactly_what_it_held`, which says
    /// what is claimed there and what is not.
    #[test]
    fn a_rehearsal_leaves_the_records_it_read_exactly_as_they_were() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(&folder.path().join("data"));
        let realm = folder.path().join("data/realm.db");
        Core::create(&realm, "a realm", RealmKind::Primary, &[crate::core::realm::Capability::Models], &key(), NOW).unwrap();
        let sources = Sources { realms: vec![realm.clone()], ..sources };

        let before: Vec<(std::path::PathBuf, Vec<u8>)> = sources
            .present()
            .into_iter()
            .map(|(_, path)| (path.to_owned(), std::fs::read(path).unwrap()))
            .chain(std::iter::once((realm.clone(), std::fs::read(&realm).unwrap())))
            .collect();

        let copies = rehearsal::take_copies(&sources, &folder.path().join("copies"), NOW).unwrap();
        let report = rehearsal::rehearse_all(&copies, "1.0.21", NOW).unwrap();

        for (path, bytes) in &before {
            assert_eq!(&std::fs::read(path).unwrap(), bytes, "{} was changed by a rehearsal", path.display());
        }
        assert_eq!(report.frozen.len(), 4, "every record the deployment has is checked against the register");
        assert!(report.frozen.iter().all(super::super::rehearsal::FrozenCheck::agrees), "{}", report.describe());
        assert!(report.neo.is_some() && report.desks.is_some() && report.swarm.is_some() && report.access.is_some(), "all four products are rehearsed");
        assert!(report.clean(), "{}", report.describe());
    }

    /// A realm as a crash leaves one: committed changes still in the journal beside the file,
    /// copied out from under a writer that was never closed.
    ///
    /// This is the state the ordinary tests never reach, because `Core`'s own drop check-points
    /// and truncates, so by the time a test reads the bytes the journal is already gone.
    fn as_a_crash_leaves_it(live: &std::path::Path, into: &std::path::Path) -> std::path::PathBuf {
        std::fs::create_dir_all(into).unwrap();
        let realm = into.join("realm.db");
        for beside in ["", "-wal", "-shm"] {
            let from = std::path::PathBuf::from(format!("{}{beside}", live.display()));
            if from.exists() {
                // The shared-memory file is SQLite's own and may be held; it is rebuilt from the
                // journal when it is missing, so failing to copy it still leaves a crashed realm.
                let _ = std::fs::copy(&from, into.join(format!("realm.db{beside}")));
            }
        }
        assert!(into.join("realm.db-wal").exists(), "a journal beside the file is what makes this a crash and not a close");
        realm
    }

    /// PROVES that opening a realm to look at it leaves the realm's own file byte for byte as it
    /// was, in the one case where that is not free: a realm a crash left with committed changes
    /// still in its journal.
    ///
    /// DOES NOT PROVE that nothing appears in the folder. SQLite may create `-shm` and `-wal`
    /// beside a write-ahead-logging realm in order to read it at all, and the realm's own file is
    /// what this is about. Nor does it prove anything about a folder that cannot be written,
    /// where a read-only handle may refuse to open the realm; a survey reports that as a refusal.
    #[test]
    fn looking_at_a_realm_a_crash_left_behind_does_not_rewrite_it() {
        // A read-write connection that is the last one to close a realm in write-ahead logging
        // check-points: whatever frames the crashed writer left are folded into the main file and
        // the files beside it are removed. `PRAGMA query_only` does not stop that, because it
        // refuses statements and a check-point is SQLite's own housekeeping, so a survey or a
        // rollout reading would rewrite somebody's realm for no reason but that a tool looked.
        let folder = tempfile::tempdir().unwrap();
        let live = folder.path().join("live/realm.db");
        let mut core = Core::create(&live, "a realm", RealmKind::Primary, &[crate::core::realm::Capability::Models], &key(), NOW).unwrap();
        let person = core.add_principal("owner", crate::core::identity::PrincipalKind::Person, "Ada", &[crate::core::identity::Role::Operator], NOW).unwrap();

        let realm = as_a_crash_leaves_it(&live, &folder.path().join("crashed"));
        let before = std::fs::read(&realm).unwrap();

        let read = crate::core::store::Store::open_for_reading(&realm).unwrap();
        assert_eq!(read.version().unwrap(), crate::core::store::SCHEMA_VERSION, "and it reads, journal and all");
        assert!(read.principals().unwrap().iter().any(|held| held.id == person.id), "including what the crashed writer had committed");
        drop(read);

        assert_eq!(std::fs::read(&realm).unwrap(), before, "looking at a realm a crash left behind rewrote the realm");
        core.close().unwrap();
    }

    /// PROVES that taking a copy of a realm a crash left behind gives a copy holding exactly what
    /// the realm holds, at the same version, with nothing migrated.
    ///
    /// DOES NOT PROVE that the realm's own bytes are untouched, and they may well not be.
    /// `VACUUM INTO` has to write, so the connection that takes a copy is read-write, and when it
    /// is the last one to close a realm in write-ahead logging SQLite check-points: the frames the
    /// crashed writer left are folded into the file and the two files beside it go. No row, no
    /// version and no answer changes. The bytes can.
    #[test]
    fn taking_a_copy_leaves_the_realm_holding_exactly_what_it_held() {
        let folder = tempfile::tempdir().unwrap();
        let live = folder.path().join("live/realm.db");
        let mut core = Core::create(&live, "a realm", RealmKind::Primary, &[crate::core::realm::Capability::Models], &key(), NOW).unwrap();
        core.add_principal("owner", crate::core::identity::PrincipalKind::Person, "Ada", &[crate::core::identity::Role::Operator], NOW).unwrap();

        let realm = as_a_crash_leaves_it(&live, &folder.path().join("crashed"));
        let held = {
            let read = crate::core::store::Store::open_for_reading(&realm).unwrap();
            (read.version().unwrap(), read.principals().unwrap().len(), read.history_shape().unwrap())
        };

        let copy = folder.path().join("copy/realm.db");
        crate::core::store::Store::copy_of(&realm, &copy).unwrap();
        let copied = crate::core::store::Store::open_for_reading(&copy).unwrap();
        assert_eq!((copied.version().unwrap(), copied.principals().unwrap().len(), copied.history_shape().unwrap()), held, "a copy holds what the realm held");

        let after = crate::core::store::Store::open_for_reading(&realm).unwrap();
        assert_eq!((after.version().unwrap(), after.principals().unwrap().len(), after.history_shape().unwrap()), held, "and the realm still holds it too");
        core.close().unwrap();
    }

    /// PROVES that each bridge's import, run on a copy and then taken back out, leaves the realm
    /// holding exactly the rows it held before, table by table and row by row.
    ///
    /// DOES NOT PROVE that nothing changed at all. The history is deliberately left out of the
    /// comparison, because a realm records the import and the undoing of it and never rewrites
    /// what it recorded; a pilot that goes wrong leaves permanent evidence that it happened.
    #[test]
    fn an_import_run_on_a_copy_and_rolled_back_leaves_the_realm_as_it_was() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(&folder.path().join("data"));
        let copies = rehearsal::take_copies(&sources, &folder.path().join("copies"), NOW).unwrap();
        let report = rehearsal::rehearse_all(&copies, "1.0.21", NOW).unwrap();
        let tried: Vec<&str> = report.trials.iter().map(|trial| trial.product.as_str()).collect();
        assert_eq!(tried, vec!["neo", "sandbox", "swarm", "access"], "every product is tried as a real import");
        for trial in &report.trials {
            assert!(trial.refusal.is_none(), "{}: {:?}", trial.product, trial.refusal);
            assert!(trial.audit_verified, "{}: the history did not verify after the import", trial.product);
            assert!(trial.returned_clean, "{}: {:?}", trial.product, trial.differences);
            assert!(trial.wrote.iter().any(|(_, how_many)| *how_many > 0), "{}: an import that wrote nothing proves nothing", trial.product);
        }
        // Every product is now rehearsed as an import that runs and comes back out, and what
        // each bridge still cannot carry is a line in `not_rehearsed` rather than a silence.
        assert_eq!(report.trials.len(), 4, "all four products are rehearsed as a real import");
        assert_eq!(report.not_rehearsed.len(), crate::core::compat::bounty::missing().len() + crate::core::compat::access::missing().len() + 1);
        assert!(report.not_rehearsed.iter().any(|line| line.contains("its activity log is a file of its own")));
    }

    /// PROVES that a backup copies every record, reads each one back with the loader that wrote
    /// it, names the vault entries it cannot be restored without, and refuses to be called a
    /// backup when a file does not read back.
    ///
    /// DOES NOT PROVE that those vault entries are present on this computer. Reading a vault is
    /// the application's half; the manifest names them so the runbook can prove them beforehand.
    #[test]
    fn a_backup_that_cannot_be_read_back_is_not_a_backup() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(&folder.path().join("data"));
        let stamp = folder.path().join("backup");
        let manifest = backup::take(&sources, &stamp, "1.0.21", "rehearsal", backup::KEEP_DAYS, NOW).unwrap();
        assert_eq!(manifest.files.len(), 4);
        assert!(manifest.whole(), "{}", manifest.describe());
        assert!(manifest.vault.contains(&"yougori-grid-hub-key".to_owned()) && manifest.vault.contains(&"yougori-access-hub-key".to_owned()));
        assert!(manifest.vault.iter().all(|entry| entry.starts_with("yougori-")), "a manifest names vault entries and never values");
        assert!(manifest.left_behind.iter().any(|line| line.contains("receipts")), "what was deliberately not copied has to be said");
        assert_eq!(manifest.kept_until, NOW + i64::from(backup::KEEP_DAYS) * 86_400);
        backup::verify(&stamp).unwrap();

        // A backup is only a backup while what is in it still reads.
        let damaged = stamp.join("neo/hub.json");
        std::fs::write(&damaged, b"not a record at all").unwrap();
        let refusal = backup::verify(&stamp).unwrap_err();
        assert!(refusal.contains("cannot be restored as it stands"), "{refusal}");

        // And a shorter retention than the floor is refused outright.
        let short = backup::take(&sources, &folder.path().join("short"), "1.0.21", "rehearsal", 1, NOW).unwrap_err();
        assert!(short.contains("at least"), "{short}");
    }

    /// PROVES that a backup of a realm names the vault entry that realm's key is actually in,
    /// one line per realm copied, rather than the placeholder the register carries.
    ///
    /// DOES NOT PROVE that the entry is present in this computer's vault. Reading a vault is the
    /// application's half; what this fixes is that the name in the manifest is one somebody can
    /// go and look for at all.
    #[test]
    fn a_backup_names_the_vault_entry_each_realm_it_copied_actually_uses() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(&folder.path().join("data"));
        let mut realms = Vec::new();
        let mut wanted = Vec::new();
        for name in ["one", "two"] {
            let path = folder.path().join(format!("data/{name}.db"));
            let core = Core::create(&path, name, RealmKind::Primary, &[crate::core::realm::Capability::Models], &key(), NOW).unwrap();
            wanted.push(crate::core::store::KeyReference::for_realm(&core.realm().id).id);
            core.close().unwrap();
            realms.push(path);
        }
        let sources = Sources { realms, ..sources };

        let manifest = backup::take(&sources, &folder.path().join("backup"), "1.0.21", "backup", backup::KEEP_DAYS, NOW).unwrap();
        for entry in &wanted {
            assert!(manifest.vault.contains(entry), "a backup of two realms names each one's own key entry: {:?}", manifest.vault);
        }
        assert!(
            !manifest.vault.iter().any(|entry| entry.contains("<realm-id>")),
            "nobody can prove a placeholder present in a vault: {:?}",
            manifest.vault
        );
    }

    /// PROVES that a record put back from a backup is the record that was copied, and that
    /// putting one back never writes over a record that is already there.
    ///
    /// DOES NOT PROVE that the product then runs: whether the vault still holds this grid's key
    /// is a question this crate cannot ask.
    #[test]
    fn a_record_put_back_is_the_record_that_was_taken() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(&folder.path().join("data"));
        let stamp = folder.path().join("backup");
        backup::take(&sources, &stamp, "1.0.21", "cutover", backup::KEEP_DAYS, NOW).unwrap();
        let original = std::fs::read(sources.neo_hub.as_ref().unwrap()).unwrap();

        let refused = backup::restore(&stamp, Product::NeoGrid, sources.neo_hub.as_ref().unwrap()).unwrap_err();
        assert!(refused.contains("already a record"), "{refused}");

        let back = folder.path().join("restored/hub.json");
        backup::restore(&stamp, Product::NeoGrid, &back).unwrap();
        assert_eq!(std::fs::read(&back).unwrap(), original, "what came back is what went in");
    }

    /// PROVES that a survey counts what is on this computer and carries no name, no email, no
    /// certificate, no salt, no hash, no address and no absolute path, and that it reads a realm
    /// without bringing it forward to this build's version.
    ///
    /// DOES NOT PROVE that the counts are right for a deployment shape nobody wrote a fixture
    /// for, and it proves nothing at all about any computer other than this one.
    #[test]
    fn a_survey_counts_without_naming_anybody() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(&folder.path().join("data"));
        let realm = folder.path().join("data/realm.db");
        Core::create(&realm, "a realm", RealmKind::Primary, &[crate::core::realm::Capability::Models], &key(), NOW).unwrap();
        let before = std::fs::read(&realm).unwrap();
        let sources = Sources { realms: vec![realm.clone()], ..sources };

        let taken = survey::survey(&sources, "1.0.21", NOW);
        assert_eq!(taken.installed().len(), 4, "{}", taken.describe());
        assert_eq!(taken.realms.len(), 1);
        assert_eq!(taken.realms[0].schema_version, crate::core::store::SCHEMA_VERSION);
        assert_eq!(std::fs::read(&realm).unwrap(), before, "a survey must not bring a realm forward by looking at it");

        let written = serde_json::to_string(&taken).unwrap();
        for secret in [
            "Person One",
            "one@example.invalid",
            "FIXTURE CERTIFICATE",
            "FIXTURE-SEALED",
            "00112233445566778899aabbccddeeff",
            "example/one",
            "Review the example service",
            "grid.example.invalid",
            "10.0.0.5",
            "Example API",
        ] {
            assert!(!written.contains(secret), "a survey carried {secret}");
        }
        assert!(!written.contains(&folder.path().display().to_string().replace('\\', "\\\\")), "a survey carries no absolute path");
        for seen in taken.installed() {
            assert!(!seen.path.contains(':') && !seen.path.starts_with('/'), "{} is not a path relative to the data folder", seen.path);
            assert!(seen.counts.values().all(|count| *count < 1_000_000), "every value in a survey is a count");
        }
    }

    /// PROVES that a profile moves one stage at a time, that every shipped product has a bridge
    /// so nothing is held back for want of one, that the order of the four is enforced rather than
    /// recommended, that only one profile is watched at a time, and that every stage can be taken
    /// back with a sentence saying what else has to be undone.
    ///
    /// DOES NOT PROVE that the world was changed back. This records where a rollout stands; the
    /// sentence it hands back is what somebody has to carry out.
    #[test]
    fn a_profile_moves_one_stage_at_a_time_and_only_after_the_one_before_it() {
        let mut state = rollout::Rollout::new(NOW);
        assert!(state.profiles.iter().all(|profile| profile.stage == rollout::Stage::Freeze));

        // Workspaces cannot pass the rehearsal while models is still behind it.
        for _ in 0..3 {
            state.advance(Profile::Workspaces, NOW).unwrap();
        }
        assert_eq!(state.state(Profile::Workspaces).unwrap().stage, rollout::Stage::Rehearsal);
        let refused = state.advance(Profile::Workspaces, NOW).unwrap_err();
        assert!(refused.starts_with("models moves before workspaces"), "{refused}");

        // Every one of the four has a bridge now, so the only thing that holds one back is the
        // order. The machinery that refuses a product without one is still here and still tested,
        // through `why_no_bridge`, which reads the register rather than naming a product.
        for profile in Profile::all() {
            assert!(rollout::has_a_bridge(*profile), "{profile:?} has a bridge");
            assert_eq!(rollout::why_no_bridge(*profile), "it has a bridge");
        }
        for profile in [Profile::Research, Profile::Credentials] {
            let mut alone = rollout::Rollout::new(NOW);
            for _ in 0..3 {
                alone.advance(profile, NOW).unwrap();
            }
            let refused = alone.advance(profile, NOW).unwrap_err();
            assert!(refused.contains("moves before"), "{profile:?}: {refused}");
        }

        // Models goes the whole way, and only then may workspaces be imported.
        for _ in 0..6 {
            state.advance(Profile::Models, NOW).unwrap();
        }
        assert_eq!(state.state(Profile::Models).unwrap().stage, rollout::Stage::Cutover);
        assert_eq!(state.state(Profile::Models).unwrap().kept_until, Some(NOW + i64::from(rollout::KEEP_DAYS) * 86_400));
        state.advance(Profile::Workspaces, NOW).unwrap();
        assert_eq!(state.state(Profile::Workspaces).unwrap().stage, rollout::Stage::Import);

        // The retention is a floor on retiring the old record, not a suggestion.
        let too_soon = state.advance(Profile::Models, NOW).unwrap_err();
        assert!(too_soon.contains("kept until"), "{too_soon}");
        state.advance(Profile::Models, NOW + i64::from(rollout::KEEP_DAYS) * 86_400).unwrap();

        // One profile is watched at a time. Both of these have a bridge, so the refusal is about
        // watching two pilots at once and nothing else.
        let mut two = rollout::Rollout::new(NOW);
        two.profiles[0].stage = rollout::Stage::Observation;
        two.profiles[1].stage = rollout::Stage::Import;
        let busy = two.advance(Profile::Workspaces, NOW).unwrap_err();
        assert!(busy.starts_with("models is already being observed"), "{busy}");
        assert!(rollout::has_a_bridge(Profile::Models) && rollout::has_a_bridge(Profile::Workspaces), "the refusal above is about watching two pilots and nothing else");

        state.advance(Profile::Workspaces, NOW).unwrap();
        assert_eq!(state.state(Profile::Workspaces).unwrap().stage, rollout::Stage::Observation);

        // Every stage has something that undoes it, and going back one stage says what.
        for stage in rollout::Stage::all() {
            assert!(!stage.undone_by().is_empty() && !stage.available_for().is_empty(), "{stage:?} has to say how it is undone and for how long");
        }
        let (back, undo) = state.go_back(Profile::Workspaces, NOW).unwrap();
        assert_eq!(back, rollout::Stage::Import);
        assert!(undo.contains("stop the comparator"), "{undo}");

        // And it survives being written down and read again.
        let path = tempfile::tempdir().unwrap().path().join("operations/rollout.json");
        state.save(&path).unwrap();
        assert_eq!(rollout::Rollout::read(&path).unwrap(), state);
    }


    /// PROVES that an import can still be undone after the process that ran it has gone: what it
    /// created is written into the realm's own database, read back by a second `Core::open`, and
    /// drives a rollback that leaves the realm holding exactly what it held before. It also
    /// proves the record travels with a backup, so a realm restored from one can still undo an
    /// import it had not undone yet.
    ///
    /// DOES NOT PROVE that the undo is complete for a realm that has been used since. Three
    /// refusals stand in the way of that on purpose, and they are in `compat::desks::roll_back`.
    #[test]
    fn an_import_can_still_be_undone_after_a_restart() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("realm.db");
        let record = sandbox(
            vec![member("m0", 0, share(4.0, 8.0, 100.0, false))],
            vec![desk("d0", "planned", None, None)],
            vec![person("p0", "administrator")],
        );

        let (before, at) = {
            let mut core = Core::create(&path, "Acme", RealmKind::Primary, &[crate::core::realm::Capability::Workspaces], &key(), NOW).unwrap();
            let before = core.store.tally().unwrap();
            crate::core::compat::desks::import(&mut core, "owner", &record, NOW).unwrap();
            let kept = crate::core::compat::undo_for(&core).unwrap();
            assert_eq!(kept.len(), 1, "an import writes down what it created");
            assert!(kept[0].describe().contains("Sandbox Grid"), "{}", kept[0].describe());
            // A backup taken now carries it, so a realm put back from one can still undo this.
            let backup = core.backup(NOW).unwrap();
            assert_eq!(backup.record.bridge_imports, kept, "a backup carries the only thing that can undo an import");
            core.close().unwrap();
            (before, kept[0].at)
        };

        // A second process, with nothing in memory from the first.
        let mut core = Core::open(&path, &key()).unwrap();
        let kept = crate::core::compat::undo_for(&core).unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].at, at);
        let crate::core::compat::Undone::Desks(imported) = &kept[0].undo else { panic!("that was a Sandbox Grid import") };
        crate::core::compat::desks::roll_back(&mut core, "owner", imported, NOW + 1).unwrap();

        let after = core.store.tally().unwrap();
        assert_eq!(after, before, "the realm after the undo is the realm before the import");
        assert!(crate::core::compat::undo_for(&core).unwrap().is_empty(), "the record of the import goes with the import");
        core.verify_audit().unwrap();
        // What cannot be undone is the history: it records the import and the undoing of it, and
        // a pilot that goes wrong leaves permanent evidence that it happened.
        let actions: Vec<String> = core.since(0).unwrap().into_iter().map(|event| event.action).filter(|action| action.starts_with("grid.desks.import")).collect();
        assert_eq!(actions, vec!["grid.desks.imported".to_owned(), "grid.desks.import undone".to_owned()]);
    }

    /// PROVES that what an import created is written once: the database itself refuses an edit,
    /// so an undo cannot be made to take out something the import never put in.
    ///
    /// DOES NOT PROVE that nobody can delete the row. A rollback deletes it on purpose, and
    /// anybody who can open the file can delete it too; what the trigger stops is the quieter
    /// mistake, a row that has been changed and still looks like a record of what happened.
    #[test]
    fn what_an_import_created_is_never_rewritten() {
        let folder = tempfile::tempdir().unwrap();
        let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[crate::core::realm::Capability::Workspaces], &key(), NOW).unwrap();
        let record = sandbox(vec![member("m0", 0, share(4.0, 8.0, 100.0, false))], vec![desk("d0", "planned", None, None)], Vec::new());
        crate::core::compat::desks::import(&mut core, "owner", &record, NOW).unwrap();
        let refused = core
            .store
            .connection_for_tests()
            .execute("UPDATE bridge_imports SET grid_id = 'another'", [])
            .unwrap_err()
            .to_string();
        assert!(refused.contains("never rewritten"), "{refused}");
    }


    /// PROVES that every refusal the runbook quotes is a sentence this crate actually prints, so
    /// the troubleshooting section cannot drift from what an operator will see on the day.
    ///
    /// DOES NOT PROVE that every refusal in the code is in the runbook. The check is
    /// one-directional, and making it both ways would mean putting every error string in this
    /// crate into a register of its own, which is a larger change than this phase is.
    #[test]
    fn every_refusal_the_runbook_quotes_is_a_sentence_in_the_code() {
        // Read as one run of words, because the document is wrapped and a sentence it quotes may
        // have a line break in the middle of it.
        let runbook: String = std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../docs/grid-core/rollout.md"))
            .expect("docs/grid-core/rollout.md is part of this repository")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        let sources = format!(
            "{}{}{}{}{}",
            include_str!("neo.rs"),
            include_str!("desks.rs"),
            include_str!("backup.rs"),
            include_str!("rollout.rs"),
            include_str!("bounty.rs")
        );
        let sources = format!("{sources}{}", include_str!("access.rs"));
        let quoted = [
            "Somebody is in one of the workspaces this import brought in, so the import cannot be undone",
            "Work in this grid was placed from a computer or an account this import brought in, so the import cannot be undone",
            "Somebody has enrolled a computer of their own against an account this import brought in, so the import cannot be undone",
        ];
        for refusal in quoted {
            assert!(sources.contains(refusal), "the runbook quotes a sentence this crate does not print: {refusal}");
            assert!(runbook.contains(refusal), "this crate prints a sentence the runbook quotes incompletely: {refusal}");
        }
        // The things the runbook exists to say, which no table renders and nothing else would
        // notice the loss of.
        for sentence in [
            "no stage may depend on the vendor knowing that a deployment exists",
            "Nothing is uploaded",
            "no bridge ever writes a hub's record",
            "There is no automatic path that deletes a customer's record",
            "must stay marked unmeasured",
        ] {
            assert!(runbook.contains(sentence), "the runbook has to say: {sentence}");
        }
        // And the two bridges written last have their own section, so nobody reads the runbook as
        // though either carried everything its product holds.
        for heading in ["Swarm Mining: what the bridge carries, and what it cannot", "The Access Grid: what the bridge carries, and what it cannot"] {
            assert!(runbook.contains(heading), "the runbook has to say plainly: {heading}");
        }
    }

    /// PROVES that a retired record is moved rather than deleted, can be put back, and cannot be
    /// deleted until its retention has run out unless somebody forces it.
    ///
    /// DOES NOT PROVE that ninety days is the right number. It is a default this phase proposes;
    /// nothing here measured it and nobody has reviewed it against a customer's obligations.
    #[test]
    fn a_retired_record_cannot_be_forgotten_until_its_retention_has_run_out() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(&folder.path().join("data"));
        let from = sources.neo_hub.clone().unwrap();
        let original = std::fs::read(&from).unwrap();
        let stamp = folder.path().join("retired");

        let retired = rollout::retire(&from, Product::NeoGrid, &stamp, rollout::KEEP_DAYS, NOW).unwrap();
        assert!(!from.exists(), "the record is moved aside, not copied and left");
        assert_eq!(retired.kept_until, NOW + i64::from(rollout::KEEP_DAYS) * 86_400);

        let too_soon = rollout::forget(&stamp, NOW, false).unwrap_err();
        assert!(too_soon.contains("kept until"), "{too_soon}");

        rollout::unretire(&stamp, &from).unwrap();
        assert_eq!(std::fs::read(&from).unwrap(), original, "what came back is what was retired");
        let in_the_way = rollout::unretire(&stamp, &from).unwrap_err();
        assert!(in_the_way.contains("already a record"), "{in_the_way}");

        rollout::forget(&stamp, NOW + i64::from(rollout::KEEP_DAYS) * 86_400, false).unwrap();
        assert!(!stamp.exists());
    }

    /// PROVES that the freeze stage's own sentence names which loaders read a version before
    /// anything else, by running all four: the two `hub::read` covers and `bounty::read` refuse a
    /// record from a newer build, and the Access Grid's loader reads one and keeps going.
    ///
    /// DOES NOT PROVE that the Access Grid should have a gate. Its record is **Dropped** in the
    /// register on purpose and those files belong to another part of this work; what is fixed
    /// here is a stage sentence that said all four were covered when three are.
    #[test]
    fn the_freeze_names_the_three_loaders_that_have_a_version_gate_and_the_one_that_has_not() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(folder.path());
        let from_a_newer_build = |path: &std::path::Path| -> Vec<u8> {
            let mut value: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            value["version"] = serde_json::json!(2);
            serde_json::to_vec(&value).unwrap()
        };

        for (what, bytes) in [("neo", sources.neo_hub.as_ref().unwrap()), ("sandbox", sources.desks_hub.as_ref().unwrap())] {
            let refused = crate::hub::read(&from_a_newer_build(bytes)).err().expect("a record from a newer build is refused");
            assert!(refused.contains("newer Yougori (version 2)"), "{what}: {refused}");
        }
        let refused = crate::bounty::read(&from_a_newer_build(sources.bounty_host.as_ref().unwrap())).err().expect("a record from a newer build is refused");
        assert!(refused.contains("newer Yougori (version 2)"), "{refused}");

        // And the fourth reads it, which is what Forward::Dropped means and what the stage
        // sentence now says out loud.
        let newer = from_a_newer_build(sources.access_hub.as_ref().unwrap());
        let read: crate::access::hub::Record = serde_json::from_slice(&newer).expect("the Access Grid's loader has no gate, so a newer record reads");
        assert_eq!(read.version, 2);
        let said = rollout::Stage::Freeze.changed();
        assert!(said.contains("the Access Grid's loader has none"), "{said}");
        let access = frozen::contracts().iter().find(|contract| contract.product == Product::AccessGrid).unwrap();
        assert_eq!(access.forward, frozen::Forward::Dropped, "the register and the stage sentence have to say the same thing");
    }

    /// PROVES that the import stage says plainly that no command in this build performs an import
    /// or takes one back out, in both sentences the engine prints, and that the rollout's own file
    /// carries no field nothing ever writes.
    ///
    /// DOES NOT PROVE that the bridges do not work. `compat::neo::import`, `compat::desks::import`
    /// and their roll backs are tested against copies by the rehearsal; what is missing is a verb
    /// anybody can type, and a stage that reads as though there were one is worse than a gap.
    #[test]
    fn the_import_stage_says_that_nothing_here_can_perform_it_or_take_it_back_out() {
        assert!(rollout::Stage::Import.changed().contains("no command in this build performs an import"), "{}", rollout::Stage::Import.changed());
        assert!(rollout::Stage::Import.undone_by().contains("No command in this build does either half"), "{}", rollout::Stage::Import.undone_by());

        // A field documented as the realm an import went into, and null in every file this build
        // can write, makes `status` read as though it could name what a rollback would target.
        let written = serde_json::to_string(&rollout::Rollout::new(NOW)).unwrap();
        assert!(!written.contains("realmId"), "the rollout's file carries a field nothing writes: {written}");

        // And a file written by an older build that had it still reads.
        let older = serde_json::json!({
            "rollout": 1, "updatedAt": NOW,
            "profiles": [{"profile": "models", "stage": "freeze", "since": NOW, "realmId": null, "keptUntil": null, "notes": []}],
        });
        let read: rollout::Rollout = serde_json::from_value(older).expect("a rollout file from a build that carried realmId still reads");
        assert_eq!(read.state(Profile::Models).unwrap().stage, rollout::Stage::Freeze);
    }

    /// PROVES that a second product cannot be retired into a folder that already holds a retired
    /// record, and that the refusal leaves both the first record and its manifest exactly as they
    /// were.
    ///
    /// DOES NOT PROVE that an administrator never meets this refusal. The engine gives every
    /// stamped folder a name only one product can take, and this is the rule underneath that, in
    /// the crate that owns what a stamped folder means.
    #[test]
    fn a_second_product_cannot_be_retired_into_the_same_folder() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(&folder.path().join("data"));
        let neo = sources.neo_hub.clone().unwrap();
        let sandbox = sources.desks_hub.clone().unwrap();
        let kept = std::fs::read(&sandbox).unwrap();
        let stamp = folder.path().join("retired");

        let first = rollout::retire(&neo, Product::NeoGrid, &stamp, rollout::KEEP_DAYS, NOW).unwrap();
        // The manifest is what a stamped folder can only hold one of: `retired`, `unretire` and
        // `forget` all read it, and `forget` deletes the whole folder on the retention it names.
        let refused = rollout::retire(&sandbox, Product::SandboxGrid, &stamp, rollout::KEEP_DAYS, NOW).unwrap_err();
        assert!(refused.contains("folder of its own"), "{refused}");
        assert!(sandbox.exists() && std::fs::read(&sandbox).unwrap() == kept, "a refused retire moves nothing");
        assert_eq!(rollout::retired(&stamp).unwrap(), first, "and leaves the first record's manifest as it was");
        assert!(!stamp.join("sandbox").exists(), "and copies nothing in");
    }

    /// PROVES that a record found on a disk is read, recognised and counted without the product
    /// that wrote it, and that reading it writes nothing: the folder holds exactly what it held.
    ///
    /// DOES NOT PROVE that it reads a version this build has never seen. The frozen fixtures are
    /// what say which versions are still understood.
    #[test]
    fn reading_a_record_found_on_a_disk_writes_nothing() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(folder.path());
        let before: Vec<String> = std::fs::read_dir(folder.path()).unwrap().flatten().map(|entry| entry.file_name().to_string_lossy().to_string()).collect();
        let sizes: Vec<u64> = std::fs::read_dir(folder.path()).unwrap().flatten().map(|entry| entry.metadata().unwrap().len()).collect();

        let reading = rollout::read_record(sources.neo_hub.as_ref().unwrap()).unwrap();
        assert_eq!(reading.shape.as_deref(), Some("a grid hub's record"));
        assert_eq!(reading.products.len(), 2, "both grids keep one type: {:?}", reading.products);
        assert_eq!(reading.counts.get("computers"), Some(&2));
        let bounty = rollout::read_record(sources.bounty_host.as_ref().unwrap()).unwrap();
        assert_eq!(bounty.counts.get("findings"), Some(&2));
        let access = rollout::read_record(sources.access_hub.as_ref().unwrap()).unwrap();
        assert_eq!(access.counts.get("credentials"), Some(&2));

        let after: Vec<String> = std::fs::read_dir(folder.path()).unwrap().flatten().map(|entry| entry.file_name().to_string_lossy().to_string()).collect();
        let after_sizes: Vec<u64> = std::fs::read_dir(folder.path()).unwrap().flatten().map(|entry| entry.metadata().unwrap().len()).collect();
        assert_eq!(before, after, "reading a record left a file behind");
        assert_eq!(sizes, after_sizes, "reading a record changed one");

        let refused = rollout::read_record(&folder.path().join("nothing.json")).unwrap_err();
        assert!(refused.starts_with("Cannot read that record"), "{refused}");
    }

    /// PROVES that an observation ledger is appended to rather than rewritten, that it reads back
    /// as it was written, and that a window with no joining, leaving or moving in it is reported
    /// as not being a pilot yet.
    ///
    /// DOES NOT PROVE that fourteen days is the right window. Neither number has been measured
    /// against a real grid, which is exactly what this repository cannot do.
    #[test]
    fn a_window_that_has_seen_nothing_happen_is_not_a_pilot() {
        let folder = tempfile::tempdir().unwrap();
        let ledger = folder.path().join("observations");
        let pass = |at: i64, subject: &str, host: &str| observe::Pass {
            profile: Profile::Workspaces,
            at,
            observations: vec![observe::Observation::new(at, Profile::Workspaces, Heading::Assignments, subject, host, host, Verdict::Agrees)],
        };
        observe::record(&ledger, &pass(NOW, "desk-1", "member-1")).unwrap();
        observe::record(&ledger, &pass(NOW + 86_400, "desk-1", "member-1")).unwrap();

        let lines = observe::read(&ledger, Profile::Workspaces).unwrap();
        assert_eq!(lines.len(), 2, "the ledger is appended to, never rewritten");
        let quiet = observe::coverage(&lines, Profile::Workspaces);
        assert!(!quiet.enough(), "two days in which nothing happened is a demonstration");
        assert!(quiet.describe().contains("this is not a pilot yet"), "{}", quiet.describe());
        assert!(quiet.describe().contains("joined and left between two passes"), "what a ledger cannot see has to be said");

        // The same window with something joining, something leaving and something moving.
        observe::record(&ledger, &pass(NOW + 2 * 86_400, "desk-2", "member-1")).unwrap();
        observe::record(&ledger, &pass(NOW + 15 * 86_400, "desk-2", "member-2")).unwrap();
        let busier = observe::coverage(&observe::read(&ledger, Profile::Workspaces).unwrap(), Profile::Workspaces);
        assert_eq!((busier.joined, busier.left, busier.moved), (1, 1, 1), "{}", busier.describe());
        assert!(busier.days >= observe::WINDOW_DAYS);
        assert!(busier.enough(), "{}", busier.describe());
    }

    /// PROVES that all four shipped products have a bridge: each one's record rehearses to the
    /// counts a person can check, imports into a realm of the right kind, and rolls back leaving
    /// that realm exactly as it was. It also proves the register says so for all four, so the
    /// frozen-contracts document cannot read as though two of them still had no migration path.
    ///
    /// DOES NOT PROVE that either of the two new bridges has ever run beside a product that is
    /// serving. Both are exercised here against the frozen fixtures and nothing else: no worker is
    /// started, no credential value exists to carry, and what neither can carry is in `missing`.
    #[test]
    fn all_four_products_have_a_bridge_and_can_be_brought_across() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(folder.path());

        let bounty = crate::bounty::load(sources.bounty_host.as_ref().unwrap()).unwrap();
        let counted = crate::core::compat::bounty::rehearse(&bounty, NOW).unwrap();
        assert_eq!((counted.members, counted.working, counted.findings, counted.source_files), (2, 1, 2, 2));
        assert_eq!((counted.principals, counted.devices, counted.hosts, counted.work, counted.scopes), (3, 2, 2, 1, 1));
        assert!(!counted.scope_frozen, "a scope a migration froze would be one nobody agreed to");
        assert!(crate::core::compat::bounty::missing().iter().any(|line| line.contains("no worker may be run")));

        let access = crate::access::hub::load(sources.access_hub.as_ref().unwrap()).unwrap();
        let counted = crate::core::compat::access::rehearse(&access, &[], NOW).unwrap();
        assert_eq!((counted.people, counted.credentials, counted.rules, counted.rules_that_ask), (2, 2, 2, 1));
        assert_eq!((counted.administrators, counted.approvers, counted.remembered_computers, counted.with_two_step), (1, 1, 2, 1));
        assert!(counted.has_identity_provider);
        assert_eq!((counted.principals, counted.rules_that_forbid, counted.every_time), (3, 1, 1));
        assert_eq!((counted.credentials_carried, counted.grants, counted.lapsed_computers), (1, 2, 1));
        // The fixture's GitHub App names no App ID, so the realm will not hold it and the note
        // says which check it failed rather than refusing its whole kind.
        assert!(counted.notes.iter().any(|note| note.contains("do not cross, because a realm checks what each one needs") && note.contains("no appId")), "{:?}", counted.notes);
        assert!(crate::core::compat::access::missing().iter().any(|line| line.contains("no credential value crosses")));

        // Both imports run, and both come back out again. The realm is compared table by table
        // before and after, which is what catches a rollback that left a row behind.
        let mut realm = Core::create(&folder.path().join("company.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), NOW).unwrap();
        let before = realm.store.tally().unwrap();
        let brought = crate::core::compat::access::import(&mut realm, "owner", &access, &[], NOW).unwrap();
        // One of the fixture's two credentials is a GitHub App with no App ID, which a realm will
        // not hold, so it does not cross and the counts say one rather than two.
        assert_eq!((brought.people.len(), brought.devices.len(), brought.credentials.len()), (2, 2, 1));
        assert!(brought.approvals.is_empty(), "no line of the hub's log was handed in, so no decision was written");
        assert_eq!(realm.credentials().unwrap().len(), 1);
        // Nothing that is a value, in any credential the realm now holds.
        let written = serde_json::to_string(&realm.credentials().unwrap()).unwrap();
        assert!(!written.contains("FIXTURE-SEALED"), "a credential in a realm is a reference and never a value");
        assert!(realm.verify_audit().is_ok());
        crate::core::compat::access::roll_back(&mut realm, "owner", &brought, NOW + 1).unwrap();
        assert_eq!(realm.store.tally().unwrap(), before, "the realm did not come back exactly as it was");
        realm.close().unwrap();

        let mut research = Core::create(&folder.path().join("research.db"), "Research", RealmKind::Research, &[Capability::Research], &key(), NOW).unwrap();
        let before = research.store.tally().unwrap();
        let brought = crate::core::compat::bounty::import(&mut research, "owner", &bounty, NOW).unwrap();
        assert_eq!((brought.members.len(), brought.computers.len(), brought.findings.len(), brought.work.len()), (2, 2, 2, 1));
        let scope = research.store.scope(&brought.scope_id).unwrap().expect("the scope is in the realm");
        assert!(!scope.frozen() && !scope.open(), "a draft scope places nothing");
        let source = research.store.source(&brought.source_id).unwrap().expect("the source is in the realm");
        assert_eq!((source.file_count, research.store.source_files(&source.id).unwrap().len()), (2, 2));
        assert!(research.verify_audit().is_ok());
        crate::core::compat::bounty::roll_back(&mut research, "owner", &brought, NOW + 1).unwrap();
        // A research realm closes a scope, withdraws an admission and disposes of a source, and
        // deletes none of them, so the undo takes the computers off and leaves the record. Every
        // table the realm does let go of comes back empty, and the ones it does not are the ones
        // the bridge names before the undo runs.
        let after = research.store.tally().unwrap();
        let kept = crate::core::compat::bounty::kept_by_the_realm();
        for (table, held) in &after {
            if !kept.contains(&table.as_str()) {
                assert_eq!(Some(held), before.get(table), "{table} did not come back as it was");
            }
        }
        assert_eq!(research.store.scope(&brought.scope_id).unwrap().unwrap().closed_at, Some(NOW + 1));
        assert!(research.store.source(&brought.source_id).unwrap().unwrap().disposed_at.is_some());
        assert!(research.store.host(&brought.computers[0].host_id).unwrap().is_none(), "the computers are off");
        assert!(crate::core::compat::undo_for(&research).unwrap().is_empty(), "the record of the import goes with it");
        research.close().unwrap();

        // And the register agrees about all four, so the document cannot read as though any of
        // them still had no migration path.
        for product in [Product::NeoGrid, Product::SandboxGrid, Product::SwarmMining, Product::AccessGrid] {
            let contract = frozen::contracts().iter().find(|contract| contract.product == product).unwrap();
            assert!(contract.bridge.imports(), "{} has a bridge", product.name());
        }
    }

    /// PROVES that an import is held to the realm's own limits, counting what the realm already
    /// holds together with what the import carries.
    ///
    /// `limits.rs` names, for every number in it, the door that enforces it: accounts at
    /// `Core::add_principal`, computers at `Core::enrol_device`, permissions at
    /// `Core::allow_credential`, computers offering at `Core::offer_host`. A bridge writes
    /// through the store instead, which is the layer underneath all four and enforces none of
    /// them — and an import is the one way a realm grows by hundreds in a single act. So the one
    /// door through which a realm could quietly pass the size it was designed for was the only
    /// door not asking. The counts are taken before anything is written, with the collision
    /// checks, so a refusal leaves nothing half brought across.
    ///
    /// DOES NOT PROVE that the limits themselves are the right numbers. They are design bounds,
    /// as `limits.rs` says plainly; what is proved here is that the bridge is held to whatever
    /// they are.
    #[test]
    fn an_import_is_held_to_the_realms_own_limits() {
        use crate::core::identity::PrincipalKind;
        use crate::core::limits;
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(folder.path());
        let access = crate::access::hub::load(sources.access_hub.as_ref().unwrap()).unwrap();
        let mut realm = Core::create(&folder.path().join("company.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), NOW).unwrap();

        // The hub carries its two people and its own account: three. Fill the realm to one short
        // of what three more would fit in, so the import is the thing that would pass the limit
        // and not the filling.
        let already = realm.store.people_count().unwrap();
        for index in already..limits::MAX_PEOPLE - 2 {
            realm.add_principal("owner", PrincipalKind::Person, &format!("Person {index}"), &[], NOW).unwrap();
        }
        assert_eq!(realm.store.people_count().unwrap(), limits::MAX_PEOPLE - 2);

        let refused = crate::core::compat::access::import(&mut realm, "owner", &access, &[], NOW).unwrap_err();
        assert!(refused.contains(&limits::MAX_PEOPLE.to_string()), "the refusal says what the limit is: {refused}");
        assert!(refused.contains("accounts"), "{refused}");

        // And nothing crossed: the refusal came before the first write, so there is no half
        // brought across grid for anybody to clear up.
        assert_eq!(realm.store.people_count().unwrap(), limits::MAX_PEOPLE - 2, "no account was written");
        assert_eq!(realm.store.device_count().unwrap(), 0);
        assert_eq!(realm.store.credential_count().unwrap(), 0);
        assert!(realm.store.bridge_imports().unwrap().is_empty(), "and nothing was recorded as imported");
        assert!(realm.verify_audit().is_ok());

        // With room for them, the same import goes through, which is what says the limit is a
        // limit and not a refusal of imports.
        realm.close().unwrap();
        let mut roomy = Core::create(&folder.path().join("roomy.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), NOW).unwrap();
        let brought = crate::core::compat::access::import(&mut roomy, "owner", &access, &[], NOW).unwrap();
        assert_eq!(brought.people.len(), 2);
        roomy.close().unwrap();

        // The bounty bridge is the same bridge with a different record behind it, and is held the
        // same way. Its host carries two members and the host's own account.
        let bounty = crate::bounty::load(sources.bounty_host.as_ref().unwrap()).unwrap();
        let mut research = Core::create(&folder.path().join("research.db"), "Research", RealmKind::Research, &[Capability::Research], &key(), NOW).unwrap();
        let already = research.store.people_count().unwrap();
        for index in already..limits::MAX_PEOPLE - 2 {
            research.add_principal("owner", PrincipalKind::Person, &format!("Person {index}"), &[], NOW).unwrap();
        }
        let refused = crate::core::compat::bounty::import(&mut research, "owner", &bounty, NOW).unwrap_err();
        assert!(refused.contains(&limits::MAX_PEOPLE.to_string()) && refused.contains("accounts"), "{refused}");
        assert_eq!(research.store.device_count().unwrap(), 0, "and nothing crossed");
        assert!(research.store.scope(&String::new()).is_ok());
        assert!(research.verify_audit().is_ok());
        research.close().unwrap();
    }

    /// PROVES that taking an Access Grid import back out refuses when work in the realm was
    /// placed by the account the import brought in, however that work got there.
    ///
    /// The undo deletes the grid's own account along with the people, and it is meant to refuse
    /// first if anything in the realm names one of them. It looked for work against the people
    /// and against the computers, but not against that account — which is the one account an
    /// import always creates and the one anything running on the grid's behalf places work as.
    /// Work from an imported computer was caught, because the computer was looked at; work from
    /// a computer of the realm's own was not, and `workloads.principal_id` has no foreign key to
    /// catch it either. The undo would then say it had put the realm back while leaving work
    /// naming an account that is gone, which is the one thing a realm must never do with its own
    /// record.
    ///
    /// DOES NOT PROVE anything about what should happen to that work. The answer is that the
    /// undo refuses and a person decides, which is what it does for every other thing it finds.
    #[test]
    fn an_undo_refuses_when_the_account_an_import_brought_has_placed_work() {
        use crate::core::identity::{PrincipalKind, Role};
        use crate::core::work::{Kind, Resources, Workload};
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(folder.path());
        let access = crate::access::hub::load(sources.access_hub.as_ref().unwrap()).unwrap();
        let mut realm = Core::create(&folder.path().join("company.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), NOW).unwrap();

        // Somebody of the realm's own, with a computer of their own: neither came from the hub,
        // so neither is in the list the undo walks.
        let ours = realm.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], NOW).unwrap();
        let (ours_device, _) = realm.enrol_device(&ours.id, "Ada's laptop", "windows", NOW).unwrap();

        let brought = crate::core::compat::access::import(&mut realm, "owner", &access, &[], NOW).unwrap();
        let account = brought.principal_id.clone().expect("the import created the grid's own account");

        // Work placed as the grid's own account, from a computer the import did not bring. This
        // is what anything running on the grid's behalf looks like once it is across.
        let work = Workload::new(&realm.realm().id.clone(), Capability::Credentials, Kind::ConnectorTask, &account, &ours_device.id, Resources::default(), 1, NOW + 1);
        let work_id = work.id.clone();
        realm.store.put_workload(&work).unwrap();

        let refused = crate::core::compat::access::roll_back(&mut realm, "owner", &brought, NOW + 2).unwrap_err();
        assert!(refused.contains("Work in this grid was placed"), "{refused}");

        // And nothing was half-taken-out on the way to that refusal: the account is still there,
        // and so is the work that names it.
        assert!(realm.store.principal(&account).unwrap().is_some(), "the account the work names is still in the realm");
        assert!(realm.store.workload(&work_id).unwrap().is_some());
        assert!(realm.verify_audit().is_ok());
        realm.close().unwrap();
    }

    /// PROVES that a bounty is refused by a company realm and taken only by a research realm, and
    /// that an Access Grid import which carried a decision out of the hub's own log refuses to
    /// roll back and says why.
    ///
    /// DOES NOT PROVE that carrying the log is a good idea on any particular grid. It proves that
    /// the one import an undo cannot reach is the one that refuses rather than half-undoing.
    #[test]
    fn research_needs_a_realm_of_its_own_and_a_carried_decision_cannot_be_undone() {
        let folder = tempfile::tempdir().unwrap();
        let sources = fixtures(folder.path());
        let bounty = crate::bounty::load(sources.bounty_host.as_ref().unwrap()).unwrap();
        let access = crate::access::hub::load(sources.access_hub.as_ref().unwrap()).unwrap();

        let mut company = Core::create(&folder.path().join("company.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), NOW).unwrap();
        let refused = crate::core::compat::bounty::import(&mut company, "owner", &bounty, NOW).unwrap_err();
        assert!(refused.contains("research grid of its own"), "{refused}");

        // One line of the hub's own log, in the shape the hub writes it: the person who asked is
        // the line's person and the approver is named in the outcome sentence.
        let decided = crate::access::activity::Entry {
            at: NOW,
            person: "two".to_owned(),
            action: "approve".to_owned(),
            credential: "Example API".to_owned(),
            target: "GET https://api.example.invalid/repos/example".to_owned(),
            outcome: "approved by one once".to_owned(),
            ..Default::default()
        };
        let read = crate::core::compat::access::decisions_in(&access, std::slice::from_ref(&decided));
        assert_eq!(read.len(), 1);
        assert_eq!((read[0].approver.as_str(), read[0].granted, read[0].path.as_deref()), ("one", true, Some("/repos/example")));

        let brought = crate::core::compat::access::import(&mut company, "owner", &access, std::slice::from_ref(&decided), NOW).unwrap();
        assert_eq!(brought.approvals.len(), 1);
        let request = company.store.request(&brought.approvals[0]).unwrap().expect("the decided request is in the realm");
        assert_eq!(request.state, crate::core::approval::State::Granted);
        assert!(!request.self_issued && request.decided_by.is_some(), "the approver was somebody other than the asker");
        let refused = crate::core::compat::access::roll_back(&mut company, "owner", &brought, NOW + 1).unwrap_err();
        assert!(refused.contains("never withdraws one"), "{refused}");
        company.close().unwrap();
    }
}
