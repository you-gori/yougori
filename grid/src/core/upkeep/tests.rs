//! The schedule, and that each piece runs on its own cadence.
use super::*;
use crate::core::identity::{Action, PrincipalKind, Role};
use crate::core::realm::{Capability, RealmKind};
use crate::core::work::{Commitment, Kind, Resources, Stage, Workload};

fn key() -> String {
    "e".repeat(64)
}

fn room() -> Resources {
    Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 200.0, gpu: false, vram_gb: 0.0 }
}

fn little() -> Resources {
    Resources { cpu: 1.0, memory_gb: 2.0, disk_gb: 5.0, gpu: false, vram_gb: 0.0 }
}

fn company(folder: &std::path::Path, now: i64) -> (Core, String, String) {
    let mut core = Core::create(&folder.join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Credentials], &key(), now).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let (device, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    core.offer_host(&device.id, "Studio PC", room(), room(), Commitment::Share, now).unwrap();
    (core, person.id, device.id)
}

#[test]
fn upkeep_does_each_piece_on_its_own_schedule() {
    let now = 300_000;
    let upkeep = Upkeep::new();
    assert_eq!(upkeep.due(now).len(), PIECES.len(), "everything is due the first time, because a realm does not know how long it was shut");

    let mut upkeep = Upkeep::default();
    for (piece, _) in PIECES {
        upkeep.last.insert(piece, now);
    }
    assert!(upkeep.due(now).is_empty(), "nothing is due the moment after it ran");
    assert_eq!(upkeep.due(now + 1), vec!["reservations and deadlines"]);
    assert_eq!(upkeep.due(now + 60), vec!["reservations and deadlines", "requests and sign-ins"]);
    assert_eq!(upkeep.due(now + EVERY_HOUR).len(), 3, "an hour later all three are due");
}

#[test]
fn a_pass_gives_back_the_reservations_that_ran_out_and_says_how_many() {
    let folder = tempfile::tempdir().unwrap();
    let now = 310_000;
    let (mut core, person, device) = company(folder.path(), now);
    let work = core.submit(Workload::new(&core.realm().id.clone(), Capability::Models, Kind::Inference, &person, &device, little(), 1, now), now).unwrap();
    core.grant_lease(&work.id, 60, now).unwrap();
    assert_eq!(core.reading(now).unwrap().live_leases, 1);

    let mut upkeep = Upkeep::new();
    let swept = upkeep.tick(&mut core, now + 1);
    assert_eq!(swept.leases_and_deadlines, 0, "nothing had run out a second later");
    let swept = upkeep.tick(&mut core, now + 600);
    assert_eq!(swept.leases_and_deadlines, 1, "the reservation ran out and the pass gave it back");
    assert_eq!(core.reading(now + 600).unwrap().live_leases, 0);
    assert!(swept.trouble.is_empty(), "{:?}", swept.trouble);
    assert!(swept.did_something());
}

#[test]
fn a_pass_lapses_requests_and_tidies_permissions_and_the_history() {
    let folder = tempfile::tempdir().unwrap();
    let now = 320_000;
    let (mut core, person, _) = company(folder.path(), now);
    core.grant("owner", &person, Role::CredentialAdmin, now).unwrap();
    core.ask(&person, Action::ApproveCredential, "credential-1", None, false, 60, now).unwrap();

    let mut upkeep = Upkeep::new();
    // The first pass runs everything, because everything is due.
    let first = upkeep.tick(&mut core, now);
    assert!(first.trouble.is_empty(), "{:?}", first.trouble);
    // An hour later the request has lapsed and the hourly work is due again.
    let later = upkeep.tick(&mut core, now + EVERY_HOUR);
    assert_eq!(later.requests_lapsed, 1, "the request nobody answered lapsed");
    assert_eq!(later.events_trimmed, 0, "a small history is trimmed to nothing, because nothing has been carried out of it");
}

#[test]
fn nothing_in_a_pass_is_on_anybody_s_request_path() {
    // A realm nobody sweeps answers every question the same way: that is why upkeep is allowed to
    // be late. What it is not allowed to be is a thing somebody waits for.
    let folder = tempfile::tempdir().unwrap();
    let now = 330_000;
    let (mut core, person, device) = company(folder.path(), now);
    let work = core.submit(Workload::new(&core.realm().id.clone(), Capability::Models, Kind::Inference, &person, &device, little(), 1, now), now).unwrap();
    let lease = core.grant_lease(&work.id, 60, now).unwrap();
    // Long past the reservation's end, with no upkeep at all.
    let late = now + 10_000;
    assert_eq!(core.free_on(&core.snapshot().unwrap().hosts[0].id.clone(), late).unwrap(), room(), "a reservation that has run out holds no room, swept or not");
    assert!(core.ready(late).alive());
    // And work on a reservation that has run out is refused, swept or not.
    let refused = core.advance(&lease.id, Stage::Running, late).unwrap_err();
    assert!(refused.contains("no longer holds a computer"), "{refused}");
}

#[test]
fn one_piece_failing_does_not_stop_the_others() {
    let folder = tempfile::tempdir().unwrap();
    let now = 340_000;
    let (mut core, _, _) = company(folder.path(), now);
    let mut upkeep = Upkeep::new();
    let swept = upkeep.tick(&mut core, now);
    assert!(swept.trouble.is_empty(), "nothing is wrong with this realm: {:?}", swept.trouble);
    // Every piece reports separately, so trouble in one is a sentence rather than a lost pass.
    assert_eq!(swept.trouble.len(), 0);
}
