//! What the core must hold true, whichever profile sits on it. Each test here is an exit gate
//! from the Grid Core plan, and none of them needs a product profile to run.
use super::*;
use approval::{State, Verdict};
use capability::{Attempt, Claims};
use identity::{Action, PrincipalKind, Role};
use model::Target;
use realm::{Capability, RealmKind};
use work::{Commitment, Kind, Resources, Stage, Workload};

fn key() -> String {
    "a".repeat(64)
}

fn big() -> Resources {
    Resources { cpu: 16.0, memory_gb: 64.0, disk_gb: 500.0, gpu: true, vram_gb: 24.0 }
}

fn small() -> Resources {
    Resources { cpu: 2.0, memory_gb: 8.0, disk_gb: 40.0, gpu: false, vram_gb: 0.0 }
}

/// A realm, a person, their computer, and a computer offering resources.
fn company(folder: &std::path::Path, now: i64) -> (Core, String, String, String) {
    let core = Core::create(&folder.join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Workspaces], &key(), now);
    let mut core = core.unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let (device, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    let host = core.offer_host(&device.id, "Studio PC", big(), big(), Commitment::Share, now).unwrap();
    (core, person.id, device.id, host.id)
}

/// The journal beside a realm's database.
fn journal(path: &std::path::Path) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}-wal", path.display()))
}

#[test]
fn model_plans_are_persisted_and_reconciled_on_the_core() {
    let folder = tempfile::tempdir().unwrap();
    let now = 1_500;
    let (mut core, _, _, first_host) = company(folder.path(), now);
    let second = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::ModelAdmin], now).unwrap();
    let (device, _) = core.enrol_device(&second.id, "Render PC", "linux", now).unwrap();
    let second_host = core.offer_host(&device.id, "Render PC", big(), big(), Commitment::Share, now + 1).unwrap();
    let plan = core
        .add_model_plan(
            "owner",
            "hf.co/Qwen/Qwen3",
            Some("Q4_K_M"),
            50,
            crate::policy::IdlePolicy::default(),
            Target::Computers { hosts: vec![first_host.clone(), first_host.clone()] },
            now + 2,
        )
        .unwrap();
    assert_eq!(plan.model, "Qwen/Qwen3");
    assert_eq!(core.model_assignments().unwrap().iter().map(|entry| entry.host_id.as_str()).collect::<Vec<_>>(), vec![first_host.as_str()]);

    // A restart keeps both the plan and the durable placement, so a runner can resume without
    // downloading a different model merely because the hub restarted.
    let path = core.path().to_owned();
    core.close().unwrap();
    let mut reopened = Core::open(&path, &key()).unwrap();
    assert_eq!(reopened.model_plans().unwrap(), vec![plan]);
    assert_eq!(reopened.model_assignments().unwrap()[0].host_id, first_host);

    // Changing the scope releases the old pick and uses the new eligible host.
    reopened
        .update_model_plan(
            "owner",
            &reopened.model_plans().unwrap()[0].id,
            None,
            None,
            None,
            None,
            Some(Target::Computers { hosts: vec![second_host.id.clone()] }),
            now + 3,
        )
        .unwrap();
    assert_eq!(reopened.model_assignments().unwrap()[0].host_id, second_host.id);
    let backup = reopened.backup(now + 4).unwrap();
    let restored = Core::restore(&folder.path().join("model-restored.db"), backup, &key()).unwrap();
    assert_eq!(restored.model_plans().unwrap().len(), 1);
    assert_eq!(restored.model_assignments().unwrap()[0].host_id, second_host.id);
}

#[test]
fn model_requests_use_the_plan_assignment_and_never_store_the_prompt() {
    let folder = tempfile::tempdir().unwrap();
    let now = 1_700;
    let (mut core, person, device, host) = company(folder.path(), now);
    let plan = core
        .add_model_plan("owner", "Qwen/Qwen3", None, 100, crate::policy::IdlePolicy::default(), Target::Computers { hosts: vec![host.clone()] }, now)
        .unwrap();
    let work = core.submit_model(&person, &device, &plan.id, small(), Some(now + 60), now + 1).unwrap();
    assert_eq!(work.stage, Stage::Queued);
    assert!(!core.snapshot().unwrap().workloads[0].note.as_deref().unwrap_or_default().contains("prompt"));
    let lease = core.grant_model_lease(&work.id, 600, now + 2).unwrap();
    assert_eq!(lease.host_id, host);
    assert_eq!(core.snapshot().unwrap().workloads.iter().find(|entry| entry.id == work.id).unwrap().stage, Stage::Leased);
}

#[test]
fn a_model_request_is_never_placed_off_its_plan() {
    let folder = tempfile::tempdir().unwrap();
    let now = 1_750;
    let (mut core, person, device, host) = company(folder.path(), now);
    // A second computer that no plan has picked, with more room than the first.
    let (spare, _) = core.enrol_device(&person, "Spare PC", "linux", now).unwrap();
    let roomier = Resources { cpu: 32.0, memory_gb: 128.0, disk_gb: 900.0, gpu: true, vram_gb: 48.0 };
    let elsewhere = core.offer_host(&spare.id, "Spare PC", roomier, roomier, Commitment::Share, now).unwrap();
    let plan = core
        .add_model_plan("owner", "Qwen/Qwen3", None, 100, crate::policy::IdlePolicy::default(), Target::Computers { hosts: vec![host.clone()] }, now)
        .unwrap();
    assert_eq!(core.model_assignments().unwrap().iter().filter(|entry| entry.plan_id == plan.id).count(), 1);

    // Asking the generic way still honours the plan, even though the other computer has more
    // room and would otherwise win on free memory.
    let work = core.submit_model(&person, &device, &plan.id, small(), None, now + 1).unwrap();
    let lease = core.grant_lease(&work.id, 600, now + 2).unwrap();
    assert_eq!(lease.host_id, host, "a model request goes to its plan's computer, not the roomiest one");
    assert_ne!(lease.host_id, elsewhere.id);

    // And when the plan's computer cannot take it, it waits rather than going elsewhere.
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();
    core.drain_host(&admin.id, &host, now + 3).unwrap();
    let next = core.submit_model(&person, &device, &plan.id, small(), None, now + 4).unwrap();
    let refused = core.grant_lease(&next.id, 600, now + 5).unwrap_err();
    assert!(refused.contains("No assigned computer in this model plan"), "{refused}");
}

#[test]
fn a_realm_only_takes_the_capabilities_its_kind_allows() {
    let folder = tempfile::tempdir().unwrap();
    // Research is its own realm; the company's realm cannot take it on.
    let refused = Core::create(&folder.path().join("a.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Research], &key(), 1_000);
    assert!(refused.unwrap_err().contains("cannot run authorised research"));
    let refused = Core::create(&folder.path().join("b.db"), "Acme", RealmKind::Research, &[Capability::Credentials], &key(), 1_000);
    assert!(refused.unwrap_err().contains("cannot broker credentials"));
    // And a research realm is offline until its own policy says otherwise.
    let research = Core::create(&folder.path().join("c.db"), "Study", RealmKind::Research, &[Capability::Research], &key(), 1_000).unwrap();
    assert!(!research.realm().network.outbound);
    assert!(!research.realm().network.allows("https://example.test"));
    let company = Core::create(&folder.path().join("d.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), 1_000).unwrap();
    assert!(company.realm().network.outbound);
}

#[test]
fn a_permission_minted_in_one_realm_is_refused_by_the_other() {
    let folder = tempfile::tempdir().unwrap();
    let now = 1_000;
    let (mut company, person, device, _) = company(folder.path(), now);
    let ours = company.realm().id.clone();
    let research = Core::create(&folder.path().join("research.db"), "Study", RealmKind::Research, &[Capability::Research], &"b".repeat(64), now).unwrap();
    let theirs_id = research.realm().id.clone();
    assert_ne!(theirs_id, ours, "a research realm is never the company's realm");

    let claims = Claims::new(&ours, Capability::Models, &person, &device, "work-1", "model-1", now, 60);
    let token = company.mint(&claims).unwrap();
    let attempt = Attempt { realm_id: &ours, device_id: &device, workload_id: "work-1", resource_id: "model-1", ..Attempt::default() };
    assert!(company.accept(&token, &attempt, now).is_ok(), "its own realm accepts it");

    // The research realm holds a different key, so the signature does not check out there. The
    // claims cannot be edited either, because that breaks the same signature.
    let mut theirs = research;
    let attempt = Attempt { realm_id: &theirs_id, device_id: &device, workload_id: "work-1", resource_id: "model-1", ..Attempt::default() };
    assert!(theirs.accept(&token, &attempt, now).unwrap_err().contains("not issued by this grid"));
}

#[test]
fn a_permission_is_bound_to_its_work_its_computer_and_its_destination() {
    let folder = tempfile::tempdir().unwrap();
    let now = 2_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    // A fresh permission each time: a token's identity is what is spent, so re-minting the same
    // claims would present the same permission twice.
    let fresh = || {
        Claims::new(&realm, Capability::Credentials, &person, &device, "work-7", "credential-1", now, 60).bound_to("https://api.acme.test", "post", "/v1/send", 1024)
    };
    let token = core.mint(&fresh()).unwrap();
    let right = Attempt {
        realm_id: &realm,
        device_id: &device,
        workload_id: "work-7",
        resource_id: "credential-1",
        destination: Some("https://api.acme.test"),
        method: Some("POST"),
        path: Some("/v1/send"),
        bytes: Some(900),
    };
    assert!(core.accept(&token, &right, now).is_ok());

    // Every narrowing is checked, and the same token cannot be used twice.
    let token = core.mint(&fresh()).unwrap();
    assert!(core.accept(&token, &Attempt { destination: Some("https://elsewhere.test"), ..right.clone() }, now).unwrap_err().contains("destination"));
    let token = core.mint(&fresh()).unwrap();
    assert!(core.accept(&token, &Attempt { method: Some("DELETE"), ..right.clone() }, now).unwrap_err().contains("method"));
    let token = core.mint(&fresh()).unwrap();
    assert!(core.accept(&token, &Attempt { path: Some("/v1/everything"), ..right.clone() }, now).unwrap_err().contains("path"));
    let token = core.mint(&fresh()).unwrap();
    assert!(core.accept(&token, &Attempt { bytes: Some(4096), ..right.clone() }, now).unwrap_err().contains("size"));
    let token = core.mint(&fresh()).unwrap();
    assert!(core.accept(&token, &Attempt { workload_id: "work-8", ..right.clone() }, now).unwrap_err().contains("piece of work"));
    let token = core.mint(&fresh()).unwrap();
    assert!(core.accept(&token, &Attempt { device_id: "device-other", ..right.clone() }, now).unwrap_err().contains("computer"));

    let once = core.mint(&fresh()).unwrap();
    assert!(core.accept(&once, &right, now).is_ok());
    assert!(core.accept(&once, &right, now).unwrap_err().contains("already used"), "a single-use permission is spent");
    assert!(core.accept(&core.mint(&fresh()).unwrap(), &right, now + 3_600).unwrap_err().contains("expired"));
}

#[test]
fn a_single_use_permission_is_still_spent_after_a_restart() {
    let folder = tempfile::tempdir().unwrap();
    let now = 2_500;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let path = core.path().to_owned();
    let claims = Claims::new(&realm, Capability::Models, &person, &device, "work-1", "model-1", now, 3_600);
    let token = core.mint(&claims).unwrap();
    let attempt = Attempt { realm_id: &realm, device_id: &device, workload_id: "work-1", resource_id: "model-1", ..Attempt::default() };
    assert!(core.accept(&token, &attempt, now).is_ok());
    core.close().unwrap();

    // Which permissions have been spent is in the database, not in memory, so restarting the
    // grid does not hand anyone a second use of a single-use permission.
    let mut again = Core::open(&path, &key()).unwrap();
    assert!(again.accept(&token, &attempt, now + 5).unwrap_err().contains("already used"));
}

#[test]
fn a_revoked_computer_stops_working_at_once() {
    let folder = tempfile::tempdir().unwrap();
    let now = 3_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let secret = {
        let (other, secret) = core.enrol_device(&person, "Spare laptop", "linux", now).unwrap();
        assert!(core.authenticate(&other.id, &secret, now).is_ok());
        (other.id, secret)
    };
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();

    // Work is running on the revoked computer.
    let work = Workload::new(&realm, Capability::Models, Kind::Inference, &person, &secret.0, small(), 1, now);
    let work = core.submit(work, now).unwrap();
    let leased = core.grant_lease(&work.id, 600, now).unwrap();
    core.advance(&leased.id, Stage::Preparing, now).unwrap();

    core.revoke_device(&admin.id, &secret.0, now + 10).unwrap();
    assert!(core.authenticate(&secret.0, &secret.1, now + 10).unwrap_err().contains("removed from the grid"));
    let after = core.snapshot().unwrap().workloads.iter().find(|entry| entry.id == work.id).unwrap().clone();
    assert_eq!(after.stage, Stage::Cancelled, "its work stops too");
    assert!(core.snapshot().unwrap().leases.iter().all(|lease| lease.released_at.is_some()), "and its reservation goes back");

    // Withdrawing trust is kept as its own record, with the generation it moved the computer to.
    let withdrawn = core.store.revocations().unwrap();
    assert!(withdrawn.iter().any(|(subject, id, generation, _)| subject == "device" && id == &secret.0 && *generation == 2));

    // And what the revoked computer was offering takes nothing more, whatever it last said.
    core.revoke_device(&admin.id, &device, now + 20).unwrap();
    let next = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now + 20), now + 20).unwrap();
    assert!(core.grant_lease(&next.id, 600, now + 20).unwrap_err().contains("No computer in this grid has room"));
}

#[test]
fn work_cannot_run_on_a_reservation_that_has_expired() {
    let folder = tempfile::tempdir().unwrap();
    let now = 4_000;
    let (mut core, person, device, host) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let work = Workload::new(&realm, Capability::Workspaces, Kind::Workspace, &person, &device, small(), 1, now);
    let work = core.submit(work, now).unwrap();
    let lease = core.grant_lease(&work.id, 60, now).unwrap();
    assert_eq!(lease.host_id, host);
    assert!(core.advance(&lease.id, Stage::Preparing, now).is_ok());

    // The reservation runs out while it is preparing.
    let later = now + 120;
    assert_eq!(core.expire(later), 1);
    assert!(core.advance(&lease.id, Stage::Running, later).unwrap_err().contains("no longer holds a computer"));
    let refused = core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "work.refused");
    assert!(refused, "the refusal is in the record");

    // The room it held is free again.
    let free = core.free_on(&host, later).unwrap();
    assert_eq!(free.memory_gb, big().memory_gb);
}

/// PROVES that work waiting for a computer is never still holding one, and that no piece of work
/// ever holds two reservations at once.
///
/// Moving work on is keyed on a reservation and used to accept `Queued`, which is the one stage
/// that means the work has no computer. Nothing gave the reservation back: the room stayed
/// subtracted from a computer that was doing nothing, the work was queued and could be given a
/// second reservation, and both were live at the same time. Giving work back is a door of its
/// own — `give_back` — because it has bookkeeping to do that moving work on does not.
///
/// The second reservation is the part that bites later: when the first one finally lapses, the
/// sweep sees work whose attempt ended and ends it, taking back the reservation the work is
/// actually running on. That is covered by the test below this one.
#[test]
fn work_waiting_for_a_computer_is_not_still_holding_one() {
    let folder = tempfile::tempdir().unwrap();
    let now = 5_500;
    let (mut core, person, device, host) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let work = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap();
    let first = core.grant_lease(&work.id, 600, now).unwrap();
    core.advance(&first.id, Stage::Preparing, now).unwrap();
    let held = core.free_on(&host, now).unwrap().memory_gb;
    assert!(held < big().memory_gb, "the computer is holding room for this work");

    // The runner says the work is waiting for a computer again. This is not the door for that.
    let refused = core.advance(&first.id, Stage::Queued, now + 1).unwrap_err();
    assert!(refused.contains("give"), "the refusal names the door that does this properly: {refused}");

    // Refused means nothing moved: not the work, not the room, not the reservation.
    let after = core.snapshot().unwrap();
    assert_eq!(after.workloads.iter().find(|entry| entry.id == work.id).unwrap().stage, Stage::Preparing);
    assert_eq!(core.free_on(&host, now + 1).unwrap().memory_gb, held, "the computer still holds the room it gave");
    assert_eq!(after.leases.iter().filter(|lease| lease.workload_id == work.id && lease.released_at.is_none()).count(), 1, "one piece of work, one reservation");

    // Through the right door the room goes back, and what the realm wrote down says what happened
    // rather than leaving an operator to work it out from a stage.
    core.give_back(&first.id, work::Setback::WentQuiet, now + 2).unwrap();
    let after = core.snapshot().unwrap();
    assert!(after.leases.iter().filter(|lease| lease.workload_id == work.id).all(|lease| lease.released_at.is_some()), "the reservation went back");
    assert_eq!(core.free_on(&host, now + 2).unwrap().memory_gb, big().memory_gb, "and the computer has all its room again");
}

/// PROVES that a reservation running out ends only the attempt that was made on it.
///
/// The sweep took a lapsed reservation, found its work and ended that work's attempt, without
/// checking that the work still held the reservation that lapsed. Giving one back checks exactly
/// that, for exactly this reason: a computer that wakes up late must not pull back work that has
/// since moved on. A stale reservation reaching the sweep instead took back the live one and
/// stopped a computer that was getting on with it.
///
/// The stale pair is built against the store rather than through a door, because the door that
/// used to make one is closed by the test above. The guard is still the sweep's to hold: a
/// database written by an older build, or any second door added later, puts the realm in this
/// state, and the sweep is where that must not become a stopped computer.
#[test]
fn a_reservation_that_ran_out_ends_only_its_own_attempt() {
    let folder = tempfile::tempdir().unwrap();
    let now = 5_600;
    let (mut core, person, device, host) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let work = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap();

    // One reservation that lapsed long ago and was never given back, and the live one the work
    // holds now and is running on.
    let stale = core.grant_lease(&work.id, 60, now).unwrap();
    let mut waiting = core.store.workload(&work.id).unwrap().unwrap();
    waiting.advance(Stage::Queued, now + 1).unwrap();
    waiting.lease_id = None;
    core.store.put_workload(&waiting).unwrap();
    let live = core.grant_lease(&work.id, 3_600, now + 2).unwrap();
    core.advance(&live.id, Stage::Preparing, now + 2).unwrap();
    core.advance(&live.id, Stage::Running, now + 3).unwrap();

    // The sweep runs well after the stale one ran out and well before the live one does.
    let later = now + 300;
    core.expire(later);

    let after = core.snapshot().unwrap();
    assert_eq!(after.workloads.iter().find(|entry| entry.id == work.id).unwrap().stage, Stage::Running, "the work carried on");
    let standing = after.leases.iter().find(|lease| lease.id == live.id).unwrap();
    assert!(standing.released_at.is_none(), "the reservation it is running on was not taken back");
    let swept = after.leases.iter().find(|lease| lease.id == stale.id).unwrap();
    assert!(swept.released_at.is_some(), "and the one that ran out was tidied away");
    assert_eq!(core.free_on(&host, later).unwrap().memory_gb, big().memory_gb - small().memory_gb, "the computer holds room for one attempt, not two");
}

#[test]
fn work_follows_one_lifecycle_and_cannot_go_backwards() {
    let folder = tempfile::tempdir().unwrap();
    let now = 5_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let work = Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now);
    let work = core.submit(work, now).unwrap();
    let lease = core.grant_lease(&work.id, 600, now).unwrap();
    for stage in [Stage::Preparing, Stage::Running, Stage::Draining, Stage::Completed] {
        core.advance(&lease.id, stage, now).unwrap();
    }
    // Finished is finished: nothing revives it.
    for stage in [Stage::Running, Stage::Queued, Stage::Preparing] {
        assert!(core.advance(&lease.id, stage, now).is_err());
    }
    assert!(Stage::Completed.finished() && !Stage::Running.finished());
}

#[test]
fn a_computer_offers_only_what_it_has_and_a_draining_one_takes_nothing() {
    let folder = tempfile::tempdir().unwrap();
    let now = 6_000;
    let (mut core, person, device, host) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let (other, _) = core.enrol_device(&person, "Small PC", "linux", now).unwrap();
    assert!(core.offer_host(&other.id, "Small PC", small(), big(), Commitment::Share, now).unwrap_err().contains("cannot offer more than it has"));

    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();
    core.drain_host(&admin.id, &host, now).unwrap();
    let work = Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now);
    let work = core.submit(work, now).unwrap();
    assert!(core.grant_lease(&work.id, 600, now).unwrap_err().contains("No computer in this grid has room"), "a draining computer is passed over");
}

#[test]
fn a_computer_that_offers_again_keeps_what_is_reserved_on_it() {
    let folder = tempfile::tempdir().unwrap();
    let now = 6_500;
    let (mut core, person, device, host) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let work = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap();
    let lease = core.grant_lease(&work.id, 600, now).unwrap();

    // The same computer offers a different share while work is reserved on it.
    let narrower = Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 250.0, gpu: true, vram_gb: 12.0 };
    let again = core.offer_host(&device, "Studio PC", big(), narrower, Commitment::Share, now + 10).unwrap();
    assert_eq!(again.id, host, "it is the same computer in the same place");
    assert_eq!(again.offered.memory_gb, narrower.memory_gb);
    assert_eq!(core.snapshot().unwrap().hosts.len(), 1, "and it is there once");
    assert!(core.snapshot().unwrap().leases.iter().any(|entry| entry.id == lease.id && entry.released_at.is_none()), "what was reserved is still reserved");
    assert_eq!(core.free_on(&host, now + 10).unwrap().memory_gb, narrower.memory_gb - small().memory_gb);
}

#[test]
fn a_shared_card_is_only_shared_when_its_isolation_allows_it() {
    let folder = tempfile::tempdir().unwrap();
    let now = 7_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let wants_gpu = Resources { cpu: 1.0, memory_gb: 4.0, disk_gb: 10.0, gpu: true, vram_gb: 4.0 };
    let first = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, wants_gpu, 1, now), now).unwrap();
    core.grant_lease(&first.id, 600, now).unwrap();
    let second = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, wants_gpu, 1, now), now).unwrap();
    // The card's isolation is unknown, so it is not handed to a second piece of work.
    assert!(core.grant_lease(&second.id, 600, now).is_err());
    assert!(!work::GpuIsolation::Unknown.shareable() && !work::GpuIsolation::TimeSliced.shareable());
    assert!(work::GpuIsolation::Partitioned.shareable() && work::GpuIsolation::Virtual.shareable());
}

#[test]
fn the_history_shows_when_it_has_been_altered() {
    let folder = tempfile::tempdir().unwrap();
    let now = 8_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let work = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap();
    core.grant_lease(&work.id, 600, now).unwrap();
    core.verify_audit().unwrap();

    // Editing an event, removing one, or reordering them is all visible.
    let mut edited = core.snapshot().unwrap().audit.clone();
    edited.events[2].reason = "something else".into();
    assert!(edited.verify(&key()).unwrap_err().contains("was altered"));
    let mut removed = core.snapshot().unwrap().audit.clone();
    removed.events.remove(2);
    assert!(removed.verify(&key()).is_err());
    let mut swapped = core.snapshot().unwrap().audit.clone();
    swapped.events.swap(1, 2);
    assert!(swapped.verify(&key()).is_err());
    // It is sealed with the realm's key, so another key does not verify it and cannot re-seal
    // an edit: a plain hash chain would let whoever edited the file repair it unnoticed.
    assert!(core.snapshot().unwrap().audit.verify(&"e".repeat(64)).is_err(), "another key never verifies this history");
}

#[test]
fn a_decision_and_the_history_cannot_be_rewritten_in_the_file() {
    let folder = tempfile::tempdir().unwrap();
    let now = 8_500;
    let (mut core, _, _, _) = company(folder.path(), now);
    let path = core.path().to_owned();
    let asker = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::CredentialAdmin], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialApprover], now).unwrap();
    let request = core.ask(&asker.id, Action::ApproveCredential, "credential-1", None, false, approval::WAIT, now).unwrap();
    core.decide(&request.id, Action::ApproveCredential, &approver.id, Verdict::Once, now).unwrap();
    core.exported("owner", 1, now).unwrap();
    core.close().unwrap();

    // The database itself refuses to change a decision or an event, or to drop an event that has
    // not been exported anywhere this computer cannot reach.
    let connection = rusqlite::Connection::open(&path).unwrap();
    assert!(connection.execute("UPDATE audit_events SET reason = 'rewritten' WHERE sequence = 3", []).unwrap_err().to_string().contains("cannot be changed"));
    assert!(connection.execute("UPDATE decisions SET verdict = 'approve_until'", []).unwrap_err().to_string().contains("cannot be changed"));
    assert!(connection.execute("DELETE FROM decisions", []).unwrap_err().to_string().contains("cannot be withdrawn"));
    assert!(connection.execute("DELETE FROM audit_events WHERE sequence = 3", []).unwrap_err().to_string().contains("not been exported"));
    // The one that was exported may go, and dropping the front of a chain is not tampering.
    connection.execute("DELETE FROM audit_events WHERE sequence = 1", []).unwrap();
    drop(connection);
    Core::open(&path, &key()).unwrap().verify_audit().unwrap();

    // Whoever can edit the file can drop those guards. The seal is what they cannot forge, and
    // it names the first event they touched.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("DROP TRIGGER audit_events_never_change; UPDATE audit_events SET reason = 'rewritten' WHERE sequence = 3;").unwrap();
    drop(connection);
    let spoiled = Core::open(&path, &key()).unwrap().verify_audit().unwrap_err();
    assert!(spoiled.contains("Event 3 was altered"), "{spoiled}");
}

#[test]
fn a_backup_restores_the_realm_and_only_with_its_key() {
    let folder = tempfile::tempdir().unwrap();
    let now = 9_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let work = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap();
    let taken = core.backup(now).unwrap();
    // A backup says which key is needed and where it is kept. It never carries the key.
    assert_eq!(taken.key_id, core.key_reference().unwrap().id);
    assert_eq!(taken.key_version, 1);
    assert!(!serde_json::to_string(&taken).unwrap().contains(&key()), "a backup never carries the key");

    assert!(Core::restore(&folder.path().join("copy.db"), taken.clone(), &"c".repeat(64)).unwrap_err().contains("not this grid's key"));
    let restored = Core::restore(&folder.path().join("copy.db"), taken, &key()).unwrap();
    assert_eq!(restored.realm().id, core.realm().id);
    assert_eq!(restored.realm().capabilities, core.realm().capabilities);
    assert_eq!(restored.snapshot().unwrap().principals.len(), core.snapshot().unwrap().principals.len());
    assert_eq!(restored.snapshot().unwrap().workloads.iter().filter(|entry| entry.id == work.id).count(), 1);
    assert_eq!(restored.key_reference().unwrap(), core.key_reference().unwrap(), "the same realm, and the same key to open it");
    restored.verify_audit().unwrap();

    // A backup edited after it was taken is refused: the state is sealed with the realm's key,
    // as each event is, so changing anything in it breaks a seal nobody without the key can put
    // back. See `a_backup_edited_after_it_was_taken_is_refused_whichever_part_was_edited` for the
    // other arm, where a chain edited before the backup passes the seal and fails verification.
    let mut spoiled = core.backup(now).unwrap();
    spoiled.record.audit.events[0].reason = "rewritten".into();
    assert!(Core::restore(&folder.path().join("spoiled.db"), spoiled, &key()).unwrap_err().contains("do not match its seal"));
}

#[test]
fn a_realm_is_still_there_after_a_restart_and_opens_only_with_its_key() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("realm.db");
    let now = 10_000;
    let (core, person, device, host) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let people = core.snapshot().unwrap().principals.len();
    core.close().unwrap();

    assert!(Core::open(&path, &"d".repeat(64)).unwrap_err().contains("not this grid's key"));
    let reopened = Core::open(&path, &key()).unwrap();
    assert_eq!(reopened.realm().name, "Acme");
    assert_eq!(reopened.realm().id, realm);
    let held = reopened.snapshot().unwrap();
    assert_eq!(held.version, store::VERSION);
    assert_eq!(held.principals.len(), people);
    assert!(held.principals.iter().any(|entry| entry.id == person));
    assert!(held.devices.iter().any(|entry| entry.id == device));
    assert!(held.hosts.iter().any(|entry| entry.id == host));
    reopened.verify_audit().unwrap();
    assert_eq!(reopened.history().unwrap().len(), store::SCHEMA_VERSION as usize, "every version it has been through is recorded");
    drop(reopened);

    // A database from a newer build is refused rather than guessed at.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute("INSERT INTO migrations (version, applied_at, description) VALUES (99, 0, 'from a newer Yougori')", []).unwrap();
    drop(connection);
    assert!(Core::open(&path, &key()).unwrap_err().contains("newer Yougori"));
}

#[test]
fn a_crash_leaves_the_last_committed_state_and_nothing_half_written() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_500;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let work = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap();
    core.grant_lease(&work.id, 600, now).unwrap();

    // What a power cut leaves behind: the file and its journal exactly as they stood, with the
    // last write never finished.
    let path = core.path().to_owned();
    let crashed = folder.path().join("crashed.db");
    std::fs::copy(&path, &crashed).unwrap();
    if journal(&path).exists() {
        std::fs::copy(journal(&path), journal(&crashed)).unwrap();
        use std::io::Write;
        let mut torn = std::fs::OpenOptions::new().append(true).open(journal(&crashed)).unwrap();
        torn.write_all(&[0x5a; 8192]).unwrap();
    }

    let recovered = Core::open(&crashed, &key()).unwrap();
    assert_eq!(recovered.realm().id, realm, "it is the same grid");
    let held = recovered.snapshot().unwrap();
    assert!(held.workloads.iter().any(|entry| entry.id == work.id), "what was committed is there");
    assert!(held.leases.iter().any(|lease| lease.workload_id == work.id), "and so is its reservation");
    recovered.verify_audit().unwrap();
}

#[test]
fn a_change_that_was_never_committed_leaves_nothing_behind() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_800;
    let (core, _, _, _) = company(folder.path(), now);
    let path = core.path().to_owned();
    let before = core.snapshot().unwrap().principals.len();
    let head = core.snapshot().unwrap().audit.events.len();
    core.close().unwrap();

    // A change that stopped halfway: the rows were written, the commit never came.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("BEGIN IMMEDIATE").unwrap();
    connection
        .execute(
            "INSERT INTO principals (id, realm_id, kind, name, created_at, generation) VALUES ('principal-ghost', (SELECT id FROM realms), 'person', 'Nobody', 0, 1)",
            [],
        )
        .unwrap();
    drop(connection);

    let reopened = Core::open(&path, &key()).unwrap();
    let held = reopened.snapshot().unwrap();
    assert_eq!(held.principals.len(), before, "a change that did not commit left nothing");
    assert!(held.principals.iter().all(|person| person.id != "principal-ghost"));
    assert_eq!(held.audit.events.len(), head);
    reopened.verify_audit().unwrap();
}

#[test]
fn sensitive_things_need_someone_elses_agreement() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_000;
    let (mut core, _, _, _) = company(folder.path(), now);
    let asker = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::CredentialAdmin, Role::CredentialApprover], now).unwrap();
    let request = core.ask(&asker.id, Action::ApproveCredential, "credential-1", None, false, approval::WAIT, now).unwrap();

    // While they are the only person who can decide, they may decide, and it is recorded as
    // self-issued rather than passed off as someone else's agreement.
    let (alone, _) = core.decide(&request.id, Action::ApproveCredential, &asker.id, Verdict::Once, now).unwrap();
    assert!(alone.self_issued && alone.stands(now));

    // Once someone else can approve, the requester may not decide their own.
    let other = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialApprover], now).unwrap();
    let second = core.ask(&asker.id, Action::ApproveCredential, "credential-2", None, false, approval::WAIT, now).unwrap();
    assert!(core.decide(&second.id, Action::ApproveCredential, &asker.id, Verdict::Once, now).unwrap_err().contains("Someone else must agree"));
    let (decided, allowance) = core.decide(&second.id, Action::ApproveCredential, &other.id, Verdict::Once, now).unwrap();
    assert!(!decided.self_issued && allowance.is_none());
    assert!(core.decide(&second.id, Action::ApproveCredential, &other.id, Verdict::Once, now).unwrap_err().contains("already decided"));

    // A refusal carries its reason.
    let third = core.ask(&asker.id, Action::ApproveCredential, "credential-3", None, false, approval::WAIT, now).unwrap();
    let (refused, _) = core.decide(&third.id, Action::ApproveCredential, &other.id, Verdict::Denied("not for this project".into()), now).unwrap();
    assert!(!refused.stands(now) && refused.reason.contains("not for this project"));

    // A request nobody answered lapses rather than waiting for ever.
    let fourth = core.ask(&asker.id, Action::ApproveCredential, "credential-4", None, false, approval::WAIT, now).unwrap();
    assert_eq!(core.expire_approvals(now + approval::WAIT + 1), 1);
    assert!(core.decide(&fourth.id, Action::ApproveCredential, &other.id, Verdict::Once, now + approval::WAIT + 1).unwrap_err().contains("expired"));
}

#[test]
fn an_agreement_is_decided_and_spent_under_the_action_it_was_asked_for() {
    use credential::fingerprint_of;
    let folder = tempfile::tempdir().unwrap();
    let now = 11_200;
    let mut broker = broker(folder.path(), now);
    let credential = billing(&mut broker.core, &broker.admin, &fingerprint_of("a value nobody here sees"), now);

    // Ada runs the realm, which brings both approving permissions with it. Nobody else holds the
    // research one yet, so naming it would leave her the only person who could decide her own
    // request, which is exactly the rule that someone else must agree.
    let runs_it = broker.core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::RealmAdmin], now).unwrap().id;
    broker.core.allow_credential(&broker.admin, &credential.id, &runs_it, &["post"], &["/v1/"], None, now).unwrap();
    let (device, _) = broker.core.enrol_device(&runs_it, "Ada's laptop", "windows", now).unwrap();
    let hers = broker.core.ask_for_credential(&runs_it, &credential.id, "post", "/v1/charge", approval::WAIT, now).unwrap();
    assert!(broker.core.decide(&hers.id, Action::ApproveResearch, &runs_it, Verdict::Once, now).unwrap_err().contains("approve a credential request"));
    assert!(broker.core.decide(&hers.id, Action::ApproveCredential, &runs_it, Verdict::Once, now).unwrap_err().contains("Someone else must agree"));

    // Nor may somebody who only approves research decide a credential request by naming their own
    // permission: the request says what it asks for, and that is what an approver has to hold.
    let research = broker.core.add_principal("owner", PrincipalKind::Person, "Rae", &[Role::ResearchApprover], now).unwrap().id;
    let refused = broker.core.decide(&hers.id, Action::ApproveResearch, &research, Verdict::Once, now).unwrap_err();
    assert!(refused.contains("approve a credential request"), "{refused}");
    assert!(broker.core.decide(&hers.id, Action::ApproveCredential, &research, Verdict::Once, now).unwrap_err().contains("may not"));

    // And asking under the other action in the first place does not work either. Anyone may ask
    // for anything, so what makes an agreement spendable on a credential is that it was asked for
    // as one, which is read back at the moment it would be spent.
    let crossed = broker
        .core
        .ask(&runs_it, Action::ApproveResearch, &credential.id, Some(("post", "/v1/charge")), false, approval::WAIT, now)
        .unwrap();
    broker.core.decide(&crossed.id, Action::ApproveResearch, &research, Verdict::Hours(2), now).unwrap();
    assert!(broker.core.standing(&runs_it, &credential.id, Some("POST"), Some("/v1/charge"), now).is_some(), "the allowance exists; it is simply not one of these");
    let refused = broker.core.use_credential(&runs_it, &device.id, "work-1", &credential.id, "post", "/v1/charge", 60, now).unwrap_err();
    assert!(refused.contains("agree to this use first"), "{refused}");

    // The ordinary way through is untouched.
    broker.core.decide(&hers.id, Action::ApproveCredential, &broker.approver, Verdict::Once, now).unwrap();
    broker.core.use_credential(&runs_it, &device.id, "work-1", &credential.id, "post", "/v1/charge", 60, now).unwrap();
}

#[test]
fn an_approver_can_allow_the_same_narrow_thing_for_a_while() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_500;
    let (mut core, _, _, _) = company(folder.path(), now);
    let asker = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::CredentialAdmin], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialApprover], now).unwrap();

    let request = core.ask(&asker.id, Action::ApproveCredential, "credential-1", Some(("post", "/v1/send")), false, approval::WAIT, now).unwrap();
    let (_, allowance) = core.decide(&request.id, Action::ApproveCredential, &approver.id, Verdict::Hours(2), now).unwrap();
    let allowance = allowance.expect("agreeing for a while leaves a standing allowance");
    assert!(allowance.describe().contains(&approver.id) && allowance.describe().contains(&request.id));

    // It covers that person, that credential, that method and that path, and nothing else.
    assert!(core.standing(&asker.id, "credential-1", Some("POST"), Some("/v1/send"), now).is_some());
    assert!(core.standing(&asker.id, "credential-1", Some("DELETE"), Some("/v1/send"), now).is_none());
    assert!(core.standing(&asker.id, "credential-1", Some("POST"), Some("/v1/everything"), now).is_none());
    assert!(core.standing(&approver.id, "credential-1", Some("POST"), Some("/v1/send"), now).is_none());
    assert!(core.standing(&asker.id, "credential-2", Some("POST"), Some("/v1/send"), now).is_none());

    // It runs out, and the sweep drops it.
    assert!(core.standing(&asker.id, "credential-1", Some("POST"), Some("/v1/send"), now + 3 * 3_600).is_none());
    core.expire_approvals(now + 3 * 3_600);
    assert!(core.snapshot().unwrap().allowances.is_empty());

    // Some requests need an approver every time and never become an allowance.
    let reveal = core.ask(&asker.id, Action::ApproveCredential, "credential-1", None, true, approval::WAIT, now).unwrap();
    assert!(core.decide(&reveal.id, Action::ApproveCredential, &approver.id, Verdict::Hours(2), now).unwrap_err().contains("needs an approver every time"));
    let (decided, allowance) = core.decide(&reveal.id, Action::ApproveCredential, &approver.id, Verdict::Once, now).unwrap();
    assert!(decided.stands(now) && allowance.is_none());

    // And an allowance is never longer than a day.
    let long = core.ask(&asker.id, Action::ApproveCredential, "credential-9", None, false, approval::WAIT, now).unwrap();
    assert!(core.decide(&long.id, Action::ApproveCredential, &approver.id, Verdict::Hours(48), now).unwrap_err().contains("1 to 24 hours"));
}

#[test]
fn every_verdict_is_kept_as_it_was_decided() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_800;
    let (mut core, _, _, _) = company(folder.path(), now);
    let path = core.path().to_owned();
    let asker = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::CredentialAdmin], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialApprover], now).unwrap();

    let once = core.ask(&asker.id, Action::ApproveCredential, "credential-1", None, false, approval::WAIT, now).unwrap();
    core.decide(&once.id, Action::ApproveCredential, &approver.id, Verdict::Once, now).unwrap();
    let hours = core.ask(&asker.id, Action::ApproveCredential, "credential-2", Some(("post", "/v1/send")), false, approval::WAIT, now).unwrap();
    core.decide(&hours.id, Action::ApproveCredential, &approver.id, Verdict::Hours(3), now).unwrap();
    let denied = core.ask(&asker.id, Action::ApproveCredential, "credential-3", None, false, approval::WAIT, now).unwrap();
    core.decide(&denied.id, Action::ApproveCredential, &approver.id, Verdict::Denied("not for this project".into()), now).unwrap();
    let lapsed = core.ask(&asker.id, Action::ApproveCredential, "credential-4", None, false, approval::WAIT, now).unwrap();
    core.expire_approvals(now + approval::WAIT + 1);
    core.close().unwrap();

    // All of it is still there, still attributable, after a restart.
    let reopened = Core::open(&path, &key()).unwrap();
    let held = reopened.snapshot().unwrap();
    let find = |id: &str| held.approvals.iter().find(|entry| entry.id == id).expect("the request is kept").clone();
    assert_eq!(find(&once.id).state, State::Granted);
    assert_eq!(find(&once.id).decided_by, Some(approver.id.clone()));
    assert!(!find(&once.id).self_issued);
    assert_eq!(find(&hours.id).state, State::Granted);
    assert_eq!(find(&denied.id).state, State::Refused);
    assert!(find(&denied.id).reason.contains("not for this project"));
    assert_eq!(find(&lapsed.id).state, State::Expired);
    assert!(find(&lapsed.id).decided_by.is_none(), "nothing is invented for a request nobody answered");

    let standing = held.allowances.iter().find(|allowance| allowance.approval_id == hours.id).expect("the standing allowance is kept");
    assert_eq!(standing.principal_id, asker.id);
    assert_eq!(standing.approved_by, approver.id);
    assert_eq!(standing.method.as_deref(), Some("POST"));
    assert_eq!(standing.path.as_deref(), Some("/v1/send"));
    assert_eq!(standing.expires_at, now + 3 * 3_600);
    assert!(reopened.standing(&asker.id, "credential-2", Some("POST"), Some("/v1/send"), now + 3_600).is_some());
    reopened.verify_audit().unwrap();
}

#[test]
fn roles_are_separate_and_nobody_approves_their_own() {
    assert!(Role::RealmAdmin.may(Action::ManagePeople) && Role::RealmAdmin.may(Action::ManageCredentials));
    // Administering does not itself approve. An administrator approves because they are given the
    // approving permissions as well, which is recorded separately and can be taken back on its own.
    assert!(!Role::RealmAdmin.may(Action::ApproveCredential) && !Role::RealmAdmin.may(Action::ApproveResearch));
    assert_eq!(Role::RealmAdmin.implies(), [Role::CredentialApprover, Role::ResearchApprover]);
    assert!(Role::CredentialApprover.implies().is_empty());
    assert!(!Role::Operator.may(Action::ApproveCredential) && !Role::Auditor.may(Action::ApproveCredential));
    assert!(Role::Auditor.may(Action::ReadAudit) && !Role::Auditor.may(Action::PlaceWork));
    assert!(Role::Operator.may(Action::PlaceWork) && !Role::Operator.may(Action::ManageCredentials));
    assert!(Role::CredentialAdmin.may(Action::ManageCredentials) && !Role::CredentialAdmin.may(Action::ApproveCredential));
    assert!(Role::User.may(Action::UseWorkspace) && !Role::User.may(Action::DrainHost));
}

#[test]
fn administering_and_approving_are_held_as_separate_permissions() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_900;
    let (mut core, _, _, _) = company(folder.path(), now);
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::RealmAdmin], now).unwrap();
    // A realm is never stuck with nobody able to decide: its administrator can.
    assert!(admin.may(Action::ApproveCredential) && admin.may(Action::ManagePeople));

    let held = core.permissions(&admin.id).unwrap();
    assert!(held.iter().any(|entry| entry.permission == Role::RealmAdmin && entry.derived_from.is_none()));
    let approving = held.iter().find(|entry| entry.permission == Role::CredentialApprover).expect("approving is held in its own right");
    assert_eq!(approving.derived_from, Some(Role::RealmAdmin), "and it says where it came from");

    // Approving can be taken back without taking the realm away from them.
    core.withdraw("owner", &admin.id, Role::CredentialApprover, now).unwrap();
    let after = core.principal(&admin.id).unwrap().unwrap();
    assert!(!after.may(Action::ApproveCredential) && after.may(Action::ManagePeople));
}

#[test]
fn a_suspended_account_and_an_unserving_realm_do_nothing() {
    let folder = tempfile::tempdir().unwrap();
    let now = 12_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();

    core.set_lifecycle(&admin.id, Lifecycle::Paused, now).unwrap();
    let work = Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now);
    assert!(core.submit(work, now).unwrap_err().contains("not serving work"));

    core.set_lifecycle(&admin.id, Lifecycle::Open, now).unwrap();
    core.suspend_principal("owner", &person, "left the company", now).unwrap();
    let (device_id, secret) = {
        let (enrolled, secret) = core.enrol_device(&admin.id, "Admin PC", "windows", now).unwrap();
        (enrolled.id, secret)
    };
    assert!(core.authenticate(&device_id, &secret, now).is_ok());
    let work = Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, small(), 1, now);
    assert!(core.submit(work, now).is_err(), "a suspended person places no work");
    assert!(core.enrol_device(&person, "New laptop", "linux", now).unwrap_err().contains("suspended"), "and takes no new computer into the grid");
    assert!(!core.principal(&person).unwrap().unwrap().active());
}

#[test]
fn a_permission_stops_working_when_its_computer_or_account_does() {
    let folder = tempfile::tempdir().unwrap();
    let now = 15_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let path = core.path().to_owned();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();

    // A permission minted while everything was in order, good for an hour and for many uses.
    let mut lasting = Claims::new(&realm, Capability::Credentials, &person, &device, "work-1", "credential-1", now, 3_600);
    lasting.single_use = false;
    let token = core.mint(&lasting).unwrap();
    let attempt = Attempt { realm_id: &realm, device_id: &device, workload_id: "work-1", resource_id: "credential-1", ..Attempt::default() };
    assert!(core.accept(&token, &attempt, now).is_ok());

    // The computer is taken out of the grid; the permission it holds stops working at once,
    // even though it was signed correctly and has not expired.
    core.revoke_device(&admin.id, &device, now + 10).unwrap();
    let refused = core.accept(&token, &attempt, now + 20).unwrap_err();
    assert!(refused.contains("no longer in this grid"), "{refused}");
    assert!(core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "capability.refused"));

    // And it is still refused after a restart, because what was withdrawn is in the database.
    core.close().unwrap();
    let mut reopened = Core::open(&path, &key()).unwrap();
    assert!(reopened.accept(&token, &attempt, now + 30).unwrap_err().contains("no longer in this grid"));
}

#[test]
fn a_permission_stops_working_when_the_policy_it_was_issued_under_changes() {
    let folder = tempfile::tempdir().unwrap();
    let now = 15_500;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();
    let mut lasting = Claims::new(&realm, Capability::Models, &person, &device, "work-1", "model-1", now, 3_600);
    lasting.single_use = false;
    let token = core.mint(&lasting).unwrap();
    let attempt = Attempt { realm_id: &realm, device_id: &device, workload_id: "work-1", resource_id: "model-1", ..Attempt::default() };
    assert!(core.accept(&token, &attempt, now).is_ok());

    assert_eq!(core.raise_policy(&admin.id, "the network rules changed", now + 5).unwrap(), 2);
    let refused = core.accept(&token, &attempt, now + 10).unwrap_err();
    assert!(refused.contains("policy changed"), "{refused}");
}

#[test]
fn a_realm_serves_only_what_it_was_given() {
    let folder = tempfile::tempdir().unwrap();
    let now = 13_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm = core.realm().id.clone();
    // This realm does models and workspaces; credentials were never turned on.
    let work = Workload::new(&realm, Capability::Credentials, Kind::CredentialRequest, &person, &device, small(), 1, now);
    assert!(core.submit(work, now).unwrap_err().contains("does not broker credentials"));
}

#[test]
fn what_a_computer_proved_about_itself_is_never_overstated() {
    use super::hardware::{Source, Trust, STALE_AFTER};
    use identity::Attestation;
    let now = 1_700_000_000;
    let nothing = Attestation::default();
    assert!(!nothing.verified() && nothing.describe().starts_with("unverified"));
    let partial = Attestation { secure_boot: Some(true), tpm: None, ..Attestation::default() };
    assert!(!partial.verified() && partial.describe().starts_with("unverified"));
    let proved = Attestation { secure_boot: Some(true), tpm: Some(true), os: Some("Windows 11".into()), agent_version: Some("1.0.21".into()), ..Attestation::default() };
    assert!(proved.verified() && proved.describe().starts_with("verified"));
    // What a report is worth is a second question, asked separately, and the answer to it is
    // lower than `verified` looks: a report with nothing saying how or when it was measured is
    // not evidence, whatever it claims.
    assert_eq!(proved.trust(now), Trust::Unverified);
    let measured = Attestation { source: Some(Source::SystemFile), measured_at: Some(now), ..proved.clone() };
    assert_eq!(measured.trust(now), Trust::SelfReported);
    assert_eq!(measured.trust(now + STALE_AFTER + 1), Trust::Unverified, "a month-old measurement proves nothing about today");
}

#[test]
fn a_realm_that_demands_evidence_takes_only_computers_that_have_shown_it() {
    use hardware::{Machine, Measured, Source, Tpm, Trust, CEILING};
    let folder = tempfile::tempdir().unwrap();
    let now = 1_700_000_000;
    let (mut core, _, device, host) = company(folder.path(), now);

    // A realm that was already running demands nothing, so turning any of this on changes nothing
    // for it until somebody decides otherwise.
    assert_eq!(core.demands_trust().unwrap(), Trust::Unverified);
    assert_eq!(core.may_host(&host, now).unwrap(), None);

    // The computer reports on itself. Nothing checks any of it, and the record says so.
    let measured = Machine {
        os: Some(Measured::new("linux".into(), Source::Syscall, now)),
        secure_boot: Some(Measured::new(true, Source::SystemFile, now)),
        tpm: Some(Measured::new(Tpm::Ready { version: "2.0".into() }, Source::SystemFile, now)),
        ..Machine::default()
    };
    let attestation = core.report_hardware(&device, &measured, "1.0.21", now).unwrap();
    assert!(attestation.verified() && attestation.trust(now) == Trust::SelfReported);
    assert_eq!(attestation.source, Some(Source::SystemFile));
    let said = core.snapshot().unwrap().audit.events.iter().find(|event| event.action == "device.reported itself").map(|event| event.reason.clone()).unwrap();
    assert!(said.contains("what this computer says about itself and nothing else"), "{said}");

    // A realm that demands that much takes it, and the same computer a day later has shown
    // nothing about today.
    core.demand_trust("owner", Trust::SelfReported, now).unwrap();
    assert_eq!(core.may_host(&host, now).unwrap(), None);
    let stale = core.may_host(&host, now + hardware::STALE_AFTER + 1).unwrap().unwrap();
    assert!(stale.contains("has shown unverified"), "{stale}");

    // A computer that reported nothing is refused in words that read as a gap and not as an
    // accusation: a computer that has shown nothing is usually one nobody set up to show anything.
    let other = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::Operator], now).unwrap();
    let (bare_device, _) = core.enrol_device(&other.id, "Render PC", "linux", now).unwrap();
    let bare = core.offer_host(&bare_device.id, "Render PC", big(), big(), Commitment::Share, now).unwrap();
    let refused = core.may_host(&bare.id, now).unwrap().unwrap();
    assert!(refused.contains("has shown nothing about its own state") && !refused.contains("Nothing in this version"), "{refused}");

    // And a realm that demands more than anything here can produce takes no computer at all,
    // which is the correct answer rather than a bug to work around. The sentence says so.
    core.demand_trust("owner", Trust::HardwareAttested, now).unwrap();
    assert!(Trust::HardwareAttested > CEILING);
    let impossible = core.may_host(&host, now).unwrap().unwrap();
    assert!(impossible.contains("Nothing in this version can show hardwareAttested"), "{impossible}");
    let decided = core.snapshot().unwrap().audit.events.iter().filter(|event| event.action == "realm.demands of a computer").count();
    assert_eq!(decided, 2, "what a realm demands of a computer is a decision, and the history keeps it");

    // Only a security administrator decides it, and the decision survives a restart.
    let nobody = core.add_principal("owner", PrincipalKind::Person, "Hopper", &[Role::User], now).unwrap();
    assert!(core.demand_trust(&nobody.id, Trust::Unverified, now).unwrap_err().contains("manage security"));
    let path = core.path().to_owned();
    core.close().unwrap();
    let reopened = Core::open(&path, &key()).unwrap();
    assert_eq!(reopened.demands_trust().unwrap(), Trust::HardwareAttested);
}

// ---- Credentials: what storage promises about them ----
//
// The broker that makes a request with a credential is Phase 5. What is held to here is the
// storage contract: a credential is a reference and never a value, using one needs both a grant
// and someone's agreement, and every permission names the agreement it came from.

/// A realm that brokers credentials, with an administrator, an approver, someone to use them,
/// and that person's computer. The three roles are held by three people on purpose.
struct Broker {
    core: Core,
    admin: String,
    approver: String,
    user: String,
    device: String,
}

fn broker(folder: &std::path::Path, now: i64) -> Broker {
    let mut core = Core::create(&folder.join("broker.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::CredentialApprover], now).unwrap();
    let user = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User], now).unwrap();
    let (device, _) = core.enrol_device(&user.id, "Ada's laptop", "windows", now).unwrap();
    Broker { core, admin: admin.id, approver: approver.id, user: user.id, device: device.id }
}

/// A credential that sends to one place, for the tests that need one.
fn billing(core: &mut Core, owner: &str, print: &str, now: i64) -> credential::Credential {
    let realm = core.realm().id.clone();
    let credential = credential::Credential::new(&realm, "Billing", credential::Secret::ApiKey, "yougori-credential-billing", print, "https://api.acme.test", owner, now)
        .unwrap()
        .narrowed_to(&["post"], &["/v1/"], Some(4_096));
    core.add_credential(owner, credential, now).unwrap()
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn a_credential_is_a_reference_and_never_a_value() {
    use credential::{fingerprint_of, Credential, Secret};
    let folder = tempfile::tempdir().unwrap();
    let now = 20_000;
    let mut broker = broker(folder.path(), now);
    let secret = "sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62";
    let print = fingerprint_of(secret);
    let realm = broker.core.realm().id.clone();

    // The value is refused wherever a reference belongs.
    assert!(Credential::new(&realm, "Billing", Secret::ApiKey, secret, &print, "https://api.acme.test", &broker.admin, now)
        .unwrap_err()
        .contains("not the name of the vault entry"));
    assert!(Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", secret, "https://api.acme.test", &broker.admin, now)
        .unwrap_err()
        .contains("fingerprint"));
    assert!(Credential::new(&realm, secret, Secret::ApiKey, "yougori-credential-billing", &print, "https://api.acme.test", &broker.admin, now)
        .unwrap_err()
        .contains("not the secret itself"));
    // And it goes to one place, over HTTPS.
    assert!(Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", &print, "http://api.acme.test", &broker.admin, now)
        .unwrap_err()
        .contains("over HTTPS"));

    let credential = billing(&mut broker.core, &broker.admin, &print, now);
    assert_eq!(credential.vault.id, "yougori-credential-billing");
    assert_eq!(credential.vault.version, 1);
    assert!(credential.allows("POST", "/v1/charge") && !credential.allows("DELETE", "/v1/charge") && !credential.allows("POST", "/v2/charge"));

    // Nothing anywhere in the realm's file is the secret.
    let path = broker.core.path().to_owned();
    broker.core.close().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    if journal(&path).exists() {
        bytes.extend(std::fs::read(journal(&path)).unwrap());
    }
    assert!(!holds(&bytes, secret.as_bytes()), "the value is never written to the grid's database");
    assert!(holds(&bytes, b"yougori-credential-billing"), "only the name of the vault entry that holds it");
}

#[test]
fn a_credential_that_never_went_through_its_constructor_is_checked_at_the_realms_door() {
    use credential::{fingerprint_of, Credential, Secret, Vault};
    let folder = tempfile::tempdir().unwrap();
    let now = 20_100;
    let mut broker = broker(folder.path(), now);
    let secret = "sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62";
    let print = fingerprint_of(secret);
    let realm = broker.core.realm().id.clone();
    // Every field of a credential is public and the type deserialises, so going through
    // `Credential::new` is a habit rather than a rule. One built any other way reaches the realm
    // with none of the constructor's checks behind it.
    let built = || Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", &print, "https://api.acme.test", &broker.admin, now).unwrap();

    let mut value_where_a_reference_belongs = built();
    value_where_a_reference_belongs.vault = Vault { id: secret.into(), version: 1 };
    assert!(broker
        .core
        .add_credential(&broker.admin, value_where_a_reference_belongs, now)
        .unwrap_err()
        .contains("not the name of the vault entry"));

    let mut unreadable_entry = built();
    unreadable_entry.vault = Vault { id: "billing key".into(), version: 1 };
    assert!(broker.core.add_credential(&broker.admin, unreadable_entry, now).unwrap_err().contains("A vault entry is named"));

    let mut value_for_a_name = built();
    value_for_a_name.name = secret.into();
    assert!(broker.core.add_credential(&broker.admin, value_for_a_name, now).unwrap_err().contains("not the secret itself"));

    let mut value_for_a_fingerprint = built();
    value_for_a_fingerprint.fingerprint = secret.into();
    assert!(broker.core.add_credential(&broker.admin, value_for_a_fingerprint, now).unwrap_err().contains("fingerprint"));

    let mut loose_destination = built();
    loose_destination.destination = "http://api.acme.test".into();
    loose_destination.destinations = vec![loose_destination.destination.clone()];
    assert!(broker.core.add_credential(&broker.admin, loose_destination, now).unwrap_err().contains("HTTPS"));

    let mut value_for_a_field = built();
    value_for_a_field.field = secret.into();
    assert!(broker.core.add_credential(&broker.admin, value_for_a_field, now).unwrap_err().contains("not the name it travels under"));

    // None of it was written, so none of it is in the realm, in a backup or in the file. A refused
    // credential matters more than most: what is stored becomes every brokered request's row, a
    // line in every backup and the sentence a vault failure puts in a history that is insert-only.
    assert!(broker.core.credentials().unwrap().is_empty(), "nothing that was refused reached the realm");
    assert!(!serde_json::to_string(&broker.core.backup(now).unwrap()).unwrap().contains(secret));
    broker.core.add_credential(&broker.admin, built(), now).unwrap();

    let path = broker.core.path().to_owned();
    broker.core.close().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    if journal(&path).exists() {
        bytes.extend(std::fs::read(journal(&path)).unwrap());
    }
    assert!(!holds(&bytes, secret.as_bytes()), "a value refused at the door never reached the grid's database");
}

#[test]
fn the_credentials_table_has_no_column_that_could_hold_a_value() {
    let folder = tempfile::tempdir().unwrap();
    let now = 20_200;
    let broker = broker(folder.path(), now);
    let path = broker.core.path().to_owned();
    broker.core.close().unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
    let mut query = connection.prepare("SELECT name FROM pragma_table_info('credentials')").unwrap();
    let columns: Vec<String> = query.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    for forbidden in ["value", "secret", "password", "token", "key", "material", "private_key", "cipher"] {
        assert!(!columns.iter().any(|column| column == forbidden), "a credential's {forbidden} is not something this grid keeps");
    }
    assert!(columns.iter().any(|column| column == "vault_id"), "where the value is kept");
    assert!(columns.iter().any(|column| column == "fingerprint"), "and enough to tell one from another");
}

#[test]
fn using_a_credential_needs_a_grant_and_someone_who_agreed() {
    use credential::fingerprint_of;
    let folder = tempfile::tempdir().unwrap();
    let now = 20_400;
    let mut broker = broker(folder.path(), now);
    let secret = "sk-live-0a1b2c3d4e5f60718293a4b5c6d7e8f90";
    let credential = billing(&mut broker.core, &broker.admin, &fingerprint_of(secret), now);
    let realm = broker.core.realm().id.clone();
    let use_it = |core: &mut Core, path: &str, at: i64| core.use_credential(&broker.user, &broker.device, "work-1", &credential.id, "post", path, 60, at);

    // Nobody has been given it.
    assert!(use_it(&mut broker.core, "/v1/charge", now).unwrap_err().contains("Nobody has given them"));
    broker.core.allow_credential(&broker.admin, &credential.id, &broker.user, &["post"], &["/v1/"], None, now).unwrap();

    // Having it is not agreement to use it.
    assert!(use_it(&mut broker.core, "/v1/charge", now).unwrap_err().contains("agree to this use first"));
    let request = broker.core.ask_for_credential(&broker.user, &credential.id, "post", "/v1/charge", approval::WAIT, now).unwrap();
    // Asking is not approving, and keeping credentials is not approving their use either.
    assert!(broker.core.decide(&request.id, Action::ApproveCredential, &broker.user, Verdict::Once, now).unwrap_err().contains("may not approve"));
    assert!(broker.core.decide(&request.id, Action::ApproveCredential, &broker.admin, Verdict::Once, now).unwrap_err().contains("may not approve"));
    broker.core.decide(&request.id, Action::ApproveCredential, &broker.approver, Verdict::Once, now).unwrap();

    // What comes back is a permission, not a credential.
    let token = use_it(&mut broker.core, "/v1/charge", now).unwrap();
    assert!(!token.contains(secret));
    let claims = capability::Authority::peek(&token).expect("the permission can be read");
    assert_eq!(claims.resource_id, credential.id);
    assert_eq!(claims.destination.as_deref(), Some("https://api.acme.test"));
    assert_eq!(claims.method.as_deref(), Some("POST"));
    assert_eq!(claims.path.as_deref(), Some("/v1/charge"));
    assert_eq!(claims.maximum_bytes, Some(4_096));
    assert_eq!(claims.approval_id.as_deref(), Some(request.id.as_str()), "it names the agreement it came from");
    assert!(claims.single_use);

    // Agreeing once is agreeing to one use.
    assert!(use_it(&mut broker.core, "/v1/charge", now).unwrap_err().contains("agree to this use first"));
    let attempt = Attempt {
        realm_id: &realm,
        device_id: &broker.device,
        workload_id: "work-1",
        resource_id: &credential.id,
        destination: Some("https://api.acme.test"),
        method: Some("POST"),
        path: Some("/v1/charge"),
        bytes: Some(100),
    };
    assert!(broker.core.accept(&token, &attempt, now).is_ok());
    assert!(broker.core.accept(&token, &attempt, now).unwrap_err().contains("already used"));

    // What was never granted is refused before anyone is asked.
    assert!(use_it(&mut broker.core, "/v2/charge", now).unwrap_err().contains("not for POST /v2/charge"));
    assert!(broker
        .core
        .use_credential(&broker.user, &broker.device, "work-1", &credential.id, "delete", "/v1/charge", 60, now)
        .unwrap_err()
        .contains("not for DELETE"));
}

#[test]
fn tidying_old_permissions_never_lets_a_one_time_agreement_be_used_twice() {
    use credential::fingerprint_of;
    let folder = tempfile::tempdir().unwrap();
    let now = 20_500;
    let mut broker = broker(folder.path(), now);
    let credential = billing(&mut broker.core, &broker.admin, &fingerprint_of("once"), now);
    broker.core.allow_credential(&broker.admin, &credential.id, &broker.user, &["post"], &["/v1/"], None, now).unwrap();
    let request = broker.core.ask_for_credential(&broker.user, &credential.id, "post", "/v1/charge", approval::WAIT, now).unwrap();
    broker.core.decide(&request.id, Action::ApproveCredential, &broker.approver, Verdict::Once, now).unwrap();
    broker.core.use_credential(&broker.user, &broker.device, "work-1", &credential.id, "post", "/v1/charge", 60, now + 10).unwrap();

    // That permission ran out a minute later, and routine housekeeping comes round after it. The
    // row it would drop is the only record anywhere that this agreement was already turned into
    // a permission, and the agreement is still standing, so it stays.
    assert_eq!(broker.core.store.forget_expired_capabilities(now + 120).unwrap(), 0, "the one record that this agreement was already used is not housekeeping");
    assert!(broker.core.store.approval_spent(&request.id).unwrap());
    let refused = broker
        .core
        .use_credential(&broker.user, &broker.device, "work-1", &credential.id, "post", "/v1/charge", 60, now + 300)
        .unwrap_err();
    assert!(refused.contains("agree to this use first"), "agreeing once is agreeing to one use, whenever the tidying ran: {refused}");

    // Once the agreement has itself run out it can allow nothing, so the row proves nothing and
    // goes with the rest.
    assert_eq!(broker.core.store.forget_expired_capabilities(now + approval::WAIT + 1).unwrap(), 1);
}

#[test]
fn an_approver_can_allow_a_credential_for_a_while_unless_it_needs_them_every_time() {
    use credential::{fingerprint_of, Credential, Secret};
    let folder = tempfile::tempdir().unwrap();
    let now = 20_600;
    let mut broker = broker(folder.path(), now);
    let credential = billing(&mut broker.core, &broker.admin, &fingerprint_of("one"), now);
    broker.core.allow_credential(&broker.admin, &credential.id, &broker.user, &["post"], &["/v1/"], None, now).unwrap();

    let request = broker.core.ask_for_credential(&broker.user, &credential.id, "post", "/v1/charge", approval::WAIT, now).unwrap();
    assert!(!request.every_time);
    broker.core.decide(&request.id, Action::ApproveCredential, &broker.approver, Verdict::Hours(2), now).unwrap();

    // A standing allowance covers that same narrow thing, more than once, until it runs out.
    for at in [now, now + 60, now + 3_000] {
        broker.core.use_credential(&broker.user, &broker.device, "work-1", &credential.id, "post", "/v1/charge", 60, at).unwrap();
    }
    assert!(broker
        .core
        .use_credential(&broker.user, &broker.device, "work-1", &credential.id, "post", "/v1/charge", 60, now + 3 * 3_600)
        .unwrap_err()
        .contains("agree to this use first"));

    // A credential that needs an approver every time is never covered by one.
    let realm = broker.core.realm().id.clone();
    let reveal = Credential::new(&realm, "Payroll", Secret::Password, "yougori-credential-payroll", &fingerprint_of("two"), "https://payroll.acme.test", &broker.admin, now)
        .unwrap()
        .every_time();
    let reveal = broker.core.add_credential(&broker.admin, reveal, now).unwrap();
    broker.core.allow_credential(&broker.admin, &reveal.id, &broker.user, &[], &[], None, now).unwrap();
    let request = broker.core.ask_for_credential(&broker.user, &reveal.id, "get", "/v1/employees", approval::WAIT, now).unwrap();
    assert!(request.every_time, "the request inherits it from the credential");
    assert!(broker.core.decide(&request.id, Action::ApproveCredential, &broker.approver, Verdict::Hours(2), now).unwrap_err().contains("every time"));
    broker.core.decide(&request.id, Action::ApproveCredential, &broker.approver, Verdict::Once, now).unwrap();
    broker.core.use_credential(&broker.user, &broker.device, "work-1", &reveal.id, "get", "/v1/employees", 60, now).unwrap();
    assert!(broker
        .core
        .use_credential(&broker.user, &broker.device, "work-1", &reveal.id, "get", "/v1/employees", 60, now + 1)
        .unwrap_err()
        .contains("agree to this use first"));
}

#[test]
fn a_rotated_credential_keeps_its_place_and_a_retired_one_is_used_no_more() {
    use credential::fingerprint_of;
    let folder = tempfile::tempdir().unwrap();
    let now = 20_800;
    let mut broker = broker(folder.path(), now);
    let credential = billing(&mut broker.core, &broker.admin, &fingerprint_of("before"), now);
    broker.core.allow_credential(&broker.admin, &credential.id, &broker.user, &["post"], &["/v1/"], None, now).unwrap();

    assert!(broker.core.rotate_credential(&broker.admin, &credential.id, "not a fingerprint", now).unwrap_err().contains("fingerprint"));
    assert_eq!(broker.core.rotate_credential(&broker.admin, &credential.id, &fingerprint_of("after"), now + 10).unwrap(), 2);
    let rotated = broker.core.credential(&credential.id).unwrap().unwrap();
    assert_eq!(rotated.vault.version, 2, "the vault entry is the same; which version of it is current has moved");
    assert_eq!(rotated.vault.id, credential.vault.id);
    assert_eq!(rotated.fingerprint, fingerprint_of("after"));
    assert_eq!(rotated.rotated_at, Some(now + 10));

    broker.core.retire_credential(&broker.admin, &credential.id, now + 20).unwrap();
    assert!(broker
        .core
        .use_credential(&broker.user, &broker.device, "work-1", &credential.id, "post", "/v1/charge", 60, now + 30)
        .unwrap_err()
        .contains("retired"));
    assert!(broker.core.allow_credential(&broker.admin, &credential.id, &broker.user, &[], &[], None, now + 30).unwrap_err().contains("retired"));
    assert!(broker.core.rotate_credential(&broker.admin, &credential.id, &fingerprint_of("later"), now + 30).is_err());
    // Nothing about it is deleted: it is still there, retired, with what was decided about it.
    assert!(broker.core.credential(&credential.id).unwrap().unwrap().retired_at == Some(now + 20));
}

#[test]
fn credentials_come_through_a_restart_and_a_backup_with_no_value_in_either() {
    use credential::fingerprint_of;
    let folder = tempfile::tempdir().unwrap();
    let now = 21_000;
    let mut broker = broker(folder.path(), now);
    let secret = "sk-live-fedcba98765432100123456789abcdef";
    let credential = billing(&mut broker.core, &broker.admin, &fingerprint_of(secret), now);
    broker.core.allow_credential(&broker.admin, &credential.id, &broker.user, &["post"], &["/v1/"], None, now).unwrap();
    let taken = broker.core.backup(now).unwrap();
    let path = broker.core.path().to_owned();
    let user = broker.user.clone();
    broker.core.close().unwrap();

    let reopened = Core::open(&path, &key()).unwrap();
    let held = reopened.snapshot().unwrap();
    assert_eq!(held.credentials.len(), 1);
    assert_eq!(held.credentials[0].vault.id, "yougori-credential-billing");
    assert_eq!(held.grants.len(), 1);
    assert_eq!(held.grants[0].principal_id, user);
    reopened.verify_audit().unwrap();
    drop(reopened);

    // A backup carries the reference and the fingerprint, and no value.
    let written = serde_json::to_string(&taken).unwrap();
    assert!(!written.contains(secret), "a backup never carries a credential's value");
    assert!(written.contains("yougori-credential-billing"));
    let restored = Core::restore(&folder.path().join("restored.db"), taken, &key()).unwrap();
    assert_eq!(restored.credentials().unwrap().len(), 1);
    assert_eq!(restored.credentials().unwrap()[0].id, credential.id);
    restored.verify_audit().unwrap();
}

#[test]
fn a_step_that_fails_leaves_the_grid_at_the_version_it_was_at() {
    let folder = tempfile::tempdir().unwrap();
    let now = 21_200;
    let (core, person, _, _) = company(folder.path(), now);
    let path = core.path().to_owned();
    let people = core.snapshot().unwrap().principals.len();
    core.close().unwrap();

    // Put the realm back as a build that only knew version one would have left it. Versions five,
    // six and seven were written with a way back, so those parts are the rollbacks themselves
    // rather than a second copy of them here, and six comes out before five because five's table
    // is what one of six's triggers hangs on.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch(store::schema::DOWN8).unwrap();
    connection.execute_batch(store::schema::DOWN7).unwrap();
    connection.execute_batch(store::schema::DOWN6).unwrap();
    connection.execute_batch(store::schema::DOWN5).unwrap();
    connection
        .execute_batch(
            // Version ten is only indexes, so unwinding it is only dropping them. The ones on
             // tables this batch drops anyway go with those tables. Version eleven is a table of
             // its own and goes first, newest out first.
             "DROP TRIGGER bridge_imports_never_change;
             DROP INDEX bridge_imports_by_time;
             DROP TABLE bridge_imports;
             DROP INDEX audit_events_by_time;
             DROP INDEX decisions_by_time;
             DROP INDEX revocations_by_time;
             DROP INDEX allowances_by_expiry;
             DROP INDEX requests_by_resource;
             DROP INDEX permissions_by_role;
             DROP INDEX workloads_by_deadline;
             DROP INDEX workloads_by_principal;
             DROP INDEX workloads_by_device;
             DROP INDEX leases_live_by_host;
             DROP INDEX leases_live_by_expiry;
             DROP INDEX leases_by_workload;
             DROP INDEX hosts_by_device;
             DROP TRIGGER audit_events_identifiers_are_identifiers;
             DROP TRIGGER revocations_never_vanish;
             DROP TRIGGER revocations_never_change;
             DROP TRIGGER capability_spending_is_final;
             DROP TRIGGER device_generation_only_rises;
             DROP TRIGGER principal_generation_only_rises;
             DROP TRIGGER realm_policy_version_only_rises;
             DROP TRIGGER realm_generation_only_rises;
             DROP TRIGGER host_commitments_never_change;
             DROP TRIGGER workspaces_are_archived_before_they_are_forgotten;
             DROP TRIGGER workspace_placement_release_is_final;
             DROP TRIGGER workspace_placement_number_never_repeats;
             DROP TRIGGER workspace_generation_only_rises;
             DROP TABLE host_conditions;
             DROP TABLE host_commitments;
             DROP TABLE workspace_sessions;
             DROP TABLE workspace_artifacts;
             DROP TABLE workspace_assignments;
             DROP TABLE workspaces;
             DROP TABLE workspace_images;
             ALTER TABLE capabilities DROP COLUMN resource_gen;
             DROP TABLE model_assignments;
             DROP TABLE model_plans;
             DROP INDEX capabilities_by_approval;
             ALTER TABLE capabilities DROP COLUMN approval_id;
             DROP TABLE credential_grants;
             DROP TABLE credentials;
             DELETE FROM migrations WHERE version >= 2;",
        )
        .unwrap();
    // And leave something in the way of the step that follows.
    connection.execute_batch("CREATE TABLE credentials (id TEXT)").unwrap();
    drop(connection);

    let refused = Core::open(&path, &key()).unwrap_err();
    assert!(refused.contains("version 2"), "{refused}");
    let connection = rusqlite::Connection::open(&path).unwrap();
    let at: i64 = connection.query_row("SELECT MAX(version) FROM migrations", [], |row| row.get(0)).unwrap();
    assert_eq!(at, 1, "a step that failed left the grid where it was");
    let mut query = connection.prepare("SELECT name FROM pragma_table_info('capabilities')").unwrap();
    let columns: Vec<String> = query.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    assert!(!columns.iter().any(|column| column == "approval_id"), "and the half of the step that had run was undone with it");
    drop(query);
    connection.execute_batch("DROP TABLE credentials").unwrap();
    drop(connection);

    // Out of the way, the step goes through, and everything from version one is untouched.
    let reopened = Core::open(&path, &key()).unwrap();
    assert_eq!(reopened.history().unwrap().len(), store::SCHEMA_VERSION as usize);
    assert_eq!(reopened.snapshot().unwrap().principals.len(), people);
    assert!(reopened.principal(&person).unwrap().is_some());
    reopened.verify_audit().unwrap();
}

/// A realm as the first core left it: one record in a file.
fn older_record(now: i64) -> store::Record {
    let realm = realm::Realm::new("Acme", RealmKind::Primary, &[Capability::Models, Capability::Credentials], &key(), now).unwrap();
    let mut record = store::Record::new(realm);
    let realm_id = record.realm.id.clone();
    let person = Principal::new(&realm_id, PrincipalKind::Person, "Ada", &[Role::RealmAdmin], now).unwrap();
    let (device, _) = Device::enrol(&realm_id, &person.id, "Ada's laptop", "windows", now).unwrap();
    let host = Host::new(&realm_id, &device.id, "Studio PC", big(), big(), Commitment::Share, now).unwrap();
    let mut work = Workload::new(&realm_id, Capability::Models, Kind::Inference, &person.id, &device.id, small(), 1, now);
    work.stage = Stage::Queued;

    let mut request = Approval::request(&realm_id, Action::ApproveCredential, "credential-1", &person.id, false, now, approval::WAIT).about("post", "/v1/send");
    request.state = State::Granted;
    request.decided_by = Some(person.id.clone());
    request.decided_at = Some(now);
    request.self_issued = true;
    let allowance = Allowance {
        id: "allowance-older".into(),
        realm_id: realm_id.clone(),
        principal_id: person.id.clone(),
        resource_id: "credential-1".into(),
        method: Some("POST".into()),
        path: Some("/v1/send".into()),
        approval_id: request.id.clone(),
        approved_by: person.id.clone(),
        granted_at: now,
        expires_at: now + 2 * 3_600,
    };

    record.audit.record(Entry::new(&realm_id, "owner", "realm.created", Decision::Allowed), now, &key());
    record.audit.record(Entry::new(&realm_id, &person.id, "device.enrolled", Decision::Allowed).from(&device.id), now, &key());
    record.audit.record(Entry::new(&realm_id, &person.id, "approval.decided", Decision::Allowed).because("self-issued"), now, &key());
    record.principals.push(person);
    record.devices.push(device);
    record.hosts.push(host);
    record.workloads.push(work);
    record.approvals.push(request);
    record.allowances.push(allowance);
    record
}

#[test]
fn a_record_from_the_first_core_is_brought_into_a_database_and_the_record_is_kept() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("realm.json");
    let now = 14_000;
    let record = older_record(now);
    let realm = record.realm.id.clone();
    let person = record.principals[0].id.clone();
    let request = record.approvals[0].id.clone();
    store::save(&path, &record).unwrap();

    let opened = Core::open(&path, &key()).unwrap();
    assert_eq!(opened.realm().id, realm, "it is still the same grid");
    assert_eq!(opened.path(), folder.path().join("realm.db"), "and it is a database now");
    let held = opened.snapshot().unwrap();
    assert_eq!(held.principals.len(), 1);
    assert_eq!(held.devices.len(), 1);
    assert_eq!(held.hosts.len(), 1);
    assert_eq!(held.workloads.len(), 1);
    assert_eq!(held.audit.events.len(), 3);
    opened.verify_audit().unwrap();

    // The decision came across as a decision, with who made it and that nobody else could.
    let decided = held.approvals.iter().find(|entry| entry.id == request).expect("the request came across");
    assert_eq!(decided.state, State::Granted);
    assert!(decided.self_issued && decided.decided_by == Some(person.clone()));
    assert!(opened.standing(&person, "credential-1", Some("POST"), Some("/v1/send"), now).is_some());

    // Administering now holds approving as a permission of its own, named for where it came from.
    let approving = opened.permissions(&person).unwrap();
    assert!(approving.iter().any(|entry| entry.permission == Role::CredentialApprover && entry.derived_from == Some(Role::RealmAdmin)));

    // The record as it was is kept beside the database, so a migration can be undone by hand.
    let kept = path.with_extension("v1.backup");
    assert!(kept.exists(), "the original is kept");
    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&kept).unwrap()).unwrap();
    assert_eq!(original["realm"]["id"], serde_json::json!(realm));
    assert!(!path.exists(), "and it is not left where something might still write to it");

    // Opening it again by either name finds the database, and nothing is migrated twice.
    drop(opened);
    let again = Core::open(&path, &key()).unwrap();
    assert_eq!(again.snapshot().unwrap().principals.len(), 1);
}

#[test]
fn a_migration_can_be_rehearsed_before_anything_is_written() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("realm.json");
    let now = 14_200;
    let record = older_record(now);
    let realm = record.realm.id.clone();
    store::save(&path, &record).unwrap();

    let rehearsal = Core::rehearse(&path, &key()).unwrap();
    assert_eq!(rehearsal.realm_id, realm);
    assert_eq!(rehearsal.version, store::VERSION);
    assert_eq!((rehearsal.principals, rehearsal.devices, rehearsal.hosts), (1, 1, 1));
    assert_eq!((rehearsal.workloads, rehearsal.requests, rehearsal.decided, rehearsal.allowances), (1, 1, 1, 1));
    assert_eq!(rehearsal.events, 3);
    assert_eq!(rehearsal.database, folder.path().join("realm.db"));
    assert!(rehearsal.describe().contains("Acme"));
    assert!(!rehearsal.database.exists(), "a rehearsal writes nothing");
    assert!(path.exists(), "and moves nothing");

    // It fails the same way the migration would, before anything is written.
    assert!(Core::rehearse(&path, &"f".repeat(64)).unwrap_err().contains("not this grid's key"));
    let spoiled = folder.path().join("spoiled.json");
    let mut tampered = record.clone();
    tampered.audit.events[0].reason = "rewritten".into();
    store::save(&spoiled, &tampered).unwrap();
    assert!(Core::rehearse(&spoiled, &key()).unwrap_err().contains("does not verify"));

    // Then the real thing matches what it said.
    let opened = Core::open(&path, &key()).unwrap();
    assert_eq!(opened.snapshot().unwrap().principals.len(), rehearsal.principals);
    assert_eq!(opened.snapshot().unwrap().audit.events.len(), rehearsal.events);
    assert!(rehearsal.keeping.exists());
}

#[test]
fn a_record_written_before_the_core_existed_is_brought_up_to_date() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("realm.json");
    let now = 14_500;
    let record = older_record(now);
    let realm = record.realm.id.clone();
    store::save(&path, &record).unwrap();

    // A record with no version at all is the shape the first build wrote.
    let mut older: serde_json::Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    older["version"] = serde_json::json!(0);
    std::fs::write(&path, serde_json::to_vec_pretty(&older).unwrap()).unwrap();

    let opened = Core::open(&path, &key()).unwrap();
    assert_eq!(opened.realm().id, realm);
    opened.verify_audit().unwrap();
    let kept = path.with_extension("v0.backup");
    assert!(kept.exists(), "the original is kept under the version it was written in");
    let original: serde_json::Value = serde_json::from_slice(&std::fs::read(&kept).unwrap()).unwrap();
    assert_eq!(original["version"], 0);
}

#[test]
fn a_record_from_a_newer_build_or_another_key_is_refused() {
    let folder = tempfile::tempdir().unwrap();
    let now = 14_800;
    let record = older_record(now);

    let ahead = folder.path().join("ahead.json");
    store::save(&ahead, &record).unwrap();
    let mut newer: serde_json::Value = serde_json::from_slice(&std::fs::read(&ahead).unwrap()).unwrap();
    newer["version"] = serde_json::json!(store::VERSION + 1);
    std::fs::write(&ahead, serde_json::to_vec_pretty(&newer).unwrap()).unwrap();
    assert!(Core::open(&ahead, &key()).unwrap_err().contains("newer Yougori"));
    assert!(!folder.path().join("ahead.db").exists(), "nothing is built from a record it cannot read");

    // The wrong key stops the migration before anything is written.
    let other = folder.path().join("other.json");
    store::save(&other, &record).unwrap();
    assert!(Core::open(&other, &"f".repeat(64)).unwrap_err().contains("not this grid's key"));
    assert!(!folder.path().join("other.db").exists());
    assert!(other.exists(), "and the record is left exactly where it was");

    // So does a record whose history has been tampered with.
    let spoiled = folder.path().join("spoiled.json");
    let mut tampered = record.clone();
    tampered.audit.events[1].reason = "rewritten".into();
    store::save(&spoiled, &tampered).unwrap();
    assert!(Core::open(&spoiled, &key()).unwrap_err().contains("does not verify"));
    assert!(!folder.path().join("spoiled.db").exists());
}

// ---- What a model request does when a computer lets it down ----

/// A realm with a model plan over two computers that can both take a request.
fn plan_over_two(folder: &std::path::Path, now: i64) -> (Core, String, String, model::ModelPlan) {
    let (mut core, person, device, _) = company(folder, now);
    let (second, _) = core.enrol_device(&person, "Render PC", "linux", now).unwrap();
    core.offer_host(&second.id, "Render PC", big(), big(), Commitment::Share, now).unwrap();
    let plan = core.add_model_plan("owner", "Qwen/Qwen3", None, 100, crate::policy::IdlePolicy::default(), Target::All, now).unwrap();
    assert_eq!(core.model_assignments().unwrap().len(), 2, "both computers serve the plan");
    (core, person, device, plan)
}

/// PROVES that a computer whose attempt the realm has already taken back cannot move that work on
/// at all, whichever step it asks for, once the work is on another computer. The stale computer
/// here is not confused and not malicious: it went quiet for a moment, the realm gave its work to
/// a second computer, and then it woke up and carried on reporting progress on the work it still
/// believes is its own.
///
/// Without the reservation in the signature this is not refused anywhere. `advance` looked up the
/// work, found the reservation the work holds *now*, saw that it was live, and let the step
/// through, so the first computer could walk the second computer's work from leased to preparing,
/// to running, to completed. The person waiting would be told their request was finished by a
/// computer that never produced the answer, and the computer actually doing it would then find
/// its own next step refused because the work had already finished.
///
/// DOES NOT PROVE anything about a computer that lies about which reservation it holds: a
/// reservation identifier is not a secret and Grid Core authenticates nobody. What it proves is
/// that holding a reservation the realm has moved past is no longer enough.
#[test]
fn a_computer_that_woke_up_late_cannot_move_on_work_that_went_to_another_computer() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_500;
    let (mut core, person, device, plan) = plan_over_two(folder.path(), now);
    let work = core.submit_model(&person, &device, &plan.id, small(), None, now + 1).unwrap();

    // The first computer takes it and begins to prepare, then goes quiet.
    let first = core.grant_model_lease(&work.id, 600, now + 2).unwrap();
    assert_eq!(core.advance(&first.id, Stage::Preparing, now + 3).unwrap(), Stage::Preparing);
    assert_eq!(core.give_back(&first.id, work::Setback::WentQuiet, now + 4).unwrap(), Stage::Queued);

    // The second computer takes the same work.
    let second = core.grant_model_lease(&work.id, 600, now + 5).unwrap();
    assert_ne!(second.id, first.id);
    assert_ne!(second.host_id, first.host_id);

    // The second computer gets as far as answering. This is the state the hole lived in: the
    // work is running, so the stage machine would take `Completed` from anybody, and the old
    // signature asked for a live reservation only before `Preparing` and `Running`, never before
    // finishing. So the first computer could finish the second computer's answer.
    core.advance(&second.id, Stage::Preparing, now + 6).unwrap();
    assert_eq!(core.advance(&second.id, Stage::Running, now + 7).unwrap(), Stage::Running);

    // The first computer wakes up and carries on. Every step it asks for is refused, finishing
    // included, and the sentence tells its runner what to do rather than inviting it to retry.
    for stage in [Stage::Preparing, Stage::Running, Stage::Draining, Stage::Completed, Stage::Failed] {
        let refused = core.advance(&first.id, stage, now + 8).unwrap_err();
        assert!(refused.contains("not the one this work holds now"), "{stage:?}: {refused}");
    }
    let held = core.snapshot().unwrap().workloads.iter().find(|entry| entry.id == work.id).unwrap().clone();
    assert_eq!((held.stage, held.lease_id.as_deref()), (Stage::Running, Some(second.id.as_str())), "nothing the stale computer asked for moved it");

    // The computer that actually holds it is unaffected and finishes its own answer.
    assert_eq!(core.advance(&second.id, Stage::Completed, now + 9).unwrap(), Stage::Completed);

    // And a reservation this grid never gave out moves nothing either.
    assert!(core.advance("lease-nobody-issued", Stage::Running, now + 10).unwrap_err().contains("No such reservation"));
}

#[test]
fn a_request_a_computer_lets_down_moves_to_another_computer_and_never_back() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_000;
    let (mut core, person, device, plan) = plan_over_two(folder.path(), now);
    let work = core.submit_model(&person, &device, &plan.id, small(), None, now + 1).unwrap();

    let first = core.grant_model_lease(&work.id, 600, now + 2).unwrap();
    assert_eq!(first.generation, 1, "the reservation's generation is the attempt number");
    assert_eq!(core.advance(&first.id, Stage::Preparing, now + 3).unwrap(), Stage::Preparing);

    // The computer goes quiet before it has begun the answer, so the work waits for another one.
    assert_eq!(core.give_back(&first.id, work::Setback::WentQuiet, now + 4).unwrap(), Stage::Queued);
    assert!(core.snapshot().unwrap().leases.iter().all(|lease| lease.released_at.is_some()), "its room goes back at once");

    let second = core.grant_model_lease(&work.id, 600, now + 5).unwrap();
    assert_ne!(second.host_id, first.host_id, "a retry never goes back to the computer that just let it down");
    assert_eq!(second.generation, 2);

    // A reservation that has already been given back cannot be given back again, so a computer
    // waking up late cannot pull back work that has moved on.
    assert!(core.give_back(&first.id, work::Setback::Busy, now + 6).unwrap_err().contains("already given back"));

    // The second computer begins the answer and then fails: part of the answer may be with the
    // caller, so nobody is sent a second one.
    core.advance(&second.id, Stage::Preparing, now + 7).unwrap();
    core.advance(&second.id, Stage::Running, now + 8).unwrap();
    assert_eq!(core.give_back(&second.id, work::Setback::Unusable, now + 9).unwrap(), Stage::Failed);
    let reason = core.snapshot().unwrap().audit.events.iter().rev().find(|event| event.action == "work.failed").unwrap().reason.clone();
    assert_eq!(reason, "the computer sent nothing that could be used");
}

#[test]
fn a_request_ends_once_every_computer_in_its_plan_has_tried_it() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_000;
    let (mut core, person, device, plan) = plan_over_two(folder.path(), now);
    let work = core.submit_model(&person, &device, &plan.id, small(), None, now + 1).unwrap();
    let first = core.grant_model_lease(&work.id, 600, now + 2).unwrap();
    assert_eq!(core.give_back(&first.id, work::Setback::ModelNotReady, now + 3).unwrap(), Stage::Queued);
    let second = core.grant_model_lease(&work.id, 600, now + 4).unwrap();
    // Nothing left to try: the work ends rather than going round the same computers again.
    assert_eq!(core.give_back(&second.id, work::Setback::ModelNotReady, now + 5).unwrap(), Stage::Failed);

    // And the same request, when the plan loses the computer that had not tried it yet, is told
    // so plainly instead of waiting for a computer that is not coming.
    let next = core.submit_model(&person, &device, &plan.id, small(), None, now + 6).unwrap();
    let held = core.grant_model_lease(&next.id, 600, now + 7).unwrap();
    assert_eq!(core.give_back(&held.id, work::Setback::Busy, now + 8).unwrap(), Stage::Queued);
    core.update_model_plan("owner", &plan.id, None, None, None, None, Some(Target::Computers { hosts: vec![held.host_id.clone()] }), now + 9).unwrap();
    let refused = core.grant_model_lease(&next.id, 600, now + 10).unwrap_err();
    assert!(refused.contains("Every computer in this model plan has already tried"), "{refused}");
}

#[test]
fn a_request_nobody_finishes_ends_at_its_deadline_with_the_room_given_back() {
    let folder = tempfile::tempdir().unwrap();
    let now = 42_000;
    let (mut core, person, device, plan) = plan_over_two(folder.path(), now);

    // No deadline from the caller does not mean for ever.
    let work = core.submit_model(&person, &device, &plan.id, small(), None, now).unwrap();
    assert_eq!(work.expires_at, Some(now + work::ANSWER_WITHIN));
    // And a caller cannot ask to be waited for longer than a day.
    let patient = core.submit_model(&person, &device, &plan.id, small(), Some(now + 30 * 24 * 60 * 60), now).unwrap();
    assert_eq!(patient.expires_at, Some(now + work::LONGEST_WAIT));

    // A reservation never outlives the caller's deadline.
    let soon = core.submit_model(&person, &device, &plan.id, small(), Some(now + 100), now).unwrap();
    let lease = core.grant_model_lease(&soon.id, 24 * 60 * 60, now + 1).unwrap();
    assert_eq!(lease.expires_at, now + 100);

    // It was answering when the deadline passed, so it failed rather than expired, and the room
    // it held is free again.
    core.advance(&lease.id, Stage::Preparing, now + 2).unwrap();
    core.advance(&lease.id, Stage::Running, now + 3).unwrap();
    assert!(core.expire(now + 101) >= 1);
    let after = core.snapshot().unwrap().workloads.iter().find(|entry| entry.id == soon.id).unwrap().clone();
    assert_eq!(after.stage, Stage::Failed);
    assert_eq!(core.free_on(&lease.host_id, now + 101).unwrap().memory_gb, big().memory_gb);

    // A request no computer ever picked up holds no reservation, so only its own deadline can
    // ever end it.
    let waiting = core.submit_model(&person, &device, &plan.id, small(), Some(now + 50), now).unwrap();
    assert_eq!(core.snapshot().unwrap().workloads.iter().find(|entry| entry.id == waiting.id).unwrap().stage, Stage::Queued);
    core.expire(now + 60);
    assert_eq!(core.snapshot().unwrap().workloads.iter().find(|entry| entry.id == waiting.id).unwrap().stage, Stage::Expired);
    let refused = core.grant_model_lease(&waiting.id, 600, now + 61).unwrap_err();
    assert!(refused.contains("queued"), "{refused}");

    // A reservation asked for after the deadline has gone is refused outright.
    let late = core.submit_model(&person, &device, &plan.id, small(), Some(now + 5), now).unwrap();
    assert!(core.grant_model_lease(&late.id, 600, now + 10).unwrap_err().contains("deadline has passed"));
}

#[test]
fn the_caller_can_stop_a_request_and_the_record_says_who_did() {
    let folder = tempfile::tempdir().unwrap();
    let now = 43_000;
    let (mut core, _, _, plan) = plan_over_two(folder.path(), now);
    let caller = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User], now).unwrap();
    let (laptop, _) = core.enrol_device(&caller.id, "Ada's laptop", "windows", now).unwrap();
    let stranger = core.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::User], now).unwrap();
    let operator = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::Operator], now).unwrap();

    let work = core.submit_model(&caller.id, &laptop.id, &plan.id, small(), None, now + 1).unwrap();
    let lease = core.grant_model_lease(&work.id, 600, now + 2).unwrap();
    core.advance(&lease.id, Stage::Preparing, now + 3).unwrap();
    assert!(core.cancel_work(&stranger.id, &work.id, now + 4).unwrap_err().contains("may not place work"));
    assert_eq!(core.cancel_work(&caller.id, &work.id, now + 5).unwrap(), Stage::Cancelled);

    // The reservation is back, the record still says which computer had it, and nothing of the
    // request itself was kept.
    let held = core.snapshot().unwrap().leases.iter().find(|entry| entry.id == lease.id).unwrap().clone();
    assert_eq!(held.released_at, Some(now + 5));
    let stopped = core.snapshot().unwrap().workloads.iter().find(|entry| entry.id == work.id).unwrap().clone();
    assert_eq!((stopped.stage, stopped.lease_id.as_deref(), stopped.updated_at), (Stage::Cancelled, Some(lease.id.as_str()), now + 5));
    assert_eq!(stopped.note.as_deref(), Some(format!("model-plan:{}:Qwen/Qwen3", plan.id).as_str()));
    let event = core.snapshot().unwrap().audit.events.iter().rev().find(|event| event.action == "work.cancelled").unwrap().clone();
    assert_eq!((event.principal_id.as_str(), event.reason.as_str()), (caller.id.as_str(), "the caller stopped waiting for this request"));

    // Work that has finished is never rewritten, and the computer that was running it is not
    // pushed anything: its next step is simply refused.
    assert!(core.cancel_work(&caller.id, &work.id, now + 6).unwrap_err().contains("already finished"));
    assert!(core.advance(&lease.id, Stage::Running, now + 6).unwrap_err().contains("no longer holds a computer"));

    // An operator may stop someone else's request, and the record names them.
    let next = core.submit_model(&caller.id, &laptop.id, &plan.id, small(), None, now + 7).unwrap();
    core.grant_model_lease(&next.id, 600, now + 8).unwrap();
    assert_eq!(core.cancel_work(&operator.id, &next.id, now + 9).unwrap(), Stage::Cancelled);
    let event = core.snapshot().unwrap().audit.events.iter().rev().find(|event| event.action == "work.cancelled").unwrap().clone();
    assert_eq!(event.reason, "stopped by Grace");

    // Work that is finishing up finishes.
    let last = core.submit_model(&caller.id, &laptop.id, &plan.id, small(), None, now + 10).unwrap();
    let held = core.grant_model_lease(&last.id, 600, now + 11).unwrap();
    for stage in [Stage::Preparing, Stage::Running, Stage::Draining] {
        core.advance(&held.id, stage, now + 12).unwrap();
    }
    assert!(core.cancel_work(&caller.id, &last.id, now + 13).unwrap_err().contains("finishing up"));
}

#[test]
fn nothing_a_model_request_carries_is_ever_written_to_the_grid() {
    let folder = tempfile::tempdir().unwrap();
    let now = 44_000;
    let (mut core, person, device, plan) = plan_over_two(folder.path(), now);
    // A whole request: placed, given a computer, let down by it, moved to another, and stopped.
    let work = core.submit_model(&person, &device, &plan.id, small(), None, now + 1).unwrap();
    let first = core.grant_model_lease(&work.id, 600, now + 2).unwrap();
    core.advance(&first.id, Stage::Preparing, now + 3).unwrap();
    core.give_back(&first.id, work::Setback::WentQuiet, now + 4).unwrap();
    let second = core.grant_model_lease(&work.id, 600, now + 5).unwrap();
    core.advance(&second.id, Stage::Preparing, now + 6).unwrap();
    core.advance(&second.id, Stage::Running, now + 7).unwrap();
    core.cancel_work(&person, &work.id, now + 8).unwrap();

    // Core is never handed any of this: no argument on any of the calls above could carry it, and
    // why a computer let the request down is chosen from words fixed in the core rather than sent
    // in by the computer. What the file holds is checked all the same, because that is what
    // somebody opening it with another tool sees.
    let path = core.path().to_owned();
    let work_id = work.id.clone();
    core.close().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    if journal(&path).exists() {
        bytes.extend(std::fs::read(journal(&path)).unwrap());
    }
    for forbidden in [
        "Summarise the acquisition memo",
        "The memo proposes",
        "You are a helpful assistant",
        "sk-live-9f2b7c41e8a24d6f",
        "ygrid_",
        "prompt_tokens",
        "choices",
        "text/event-stream",
    ] {
        assert!(!holds(&bytes, forbidden.as_bytes()), "{forbidden} is not something this grid keeps");
    }

    let connection = rusqlite::Connection::open(&path).unwrap();
    let mut query = connection.prepare("SELECT name FROM pragma_table_info('workloads')").unwrap();
    let columns: Vec<String> = query.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    for forbidden in ["prompt", "messages", "request", "response", "answer", "content", "body", "tokens", "usage"] {
        assert!(!columns.iter().any(|column| column == forbidden), "a request's {forbidden} is not something this grid keeps");
    }
    // The one free text field a workload has says which plan it belongs to, and nothing else.
    let note: String = connection.query_row("SELECT note FROM workloads WHERE id = ?1", [&work_id], |row| row.get(0)).unwrap();
    assert_eq!(note, format!("model-plan:{}:Qwen/Qwen3", plan.id));
    // And every reason in the history that could have come from a computer is one the core chose.
    let mut query = connection.prepare("SELECT reason FROM audit_events WHERE reason <> ''").unwrap();
    let reasons: Vec<String> = query.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    let chosen = [
        work::Setback::WentQuiet.say(),
        work::Setback::Busy.say(),
        work::Setback::ModelNotReady.say(),
        work::Setback::Unusable.say(),
        work::Setback::LeftTheGrid.say(),
        "the caller stopped waiting for this request",
        "the computer did not finish in time",
    ];
    for reason in reasons.iter().filter(|reason| reason.starts_with("the ")) {
        assert!(chosen.contains(&reason.as_str()), "{reason} is not one of the sentences the core chooses");
    }
}

#[test]
fn a_computer_taken_out_of_the_grid_leaves_the_plans_that_picked_it() {
    let folder = tempfile::tempdir().unwrap();
    let now = 45_000;
    let (mut core, person, device, host) = company(folder.path(), now);
    let (spare, _) = core.enrol_device(&person, "Render PC", "linux", now).unwrap();
    let other = core.offer_host(&spare.id, "Render PC", big(), big(), Commitment::Share, now + 1).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();
    let only = core
        .add_model_plan("owner", "Acme/Chat", None, 100, crate::policy::IdlePolicy::default(), Target::Computers { hosts: vec![host.clone()] }, now + 2)
        .unwrap();
    let shared = core
        .add_model_plan("owner", "Acme/Code", None, 100, crate::policy::IdlePolicy::default(), Target::Computers { hosts: vec![other.id.clone()] }, now + 3)
        .unwrap();

    core.revoke_device(&admin.id, &device, now + 4).unwrap();
    let plans = core.model_plans().unwrap();
    assert!(!plans.iter().any(|plan| plan.id == only.id), "a plan left with no computers goes rather than sitting there able to place nothing");
    assert_eq!(plans.len(), 1);
    assert_eq!(plans[0].target.hosts(), [other.id.clone()], "and the computer that left is in nobody's list");
    assert_eq!(core.model_assignments().unwrap()[0].plan_id, shared.id);
}

#[test]
fn a_computer_left_out_of_the_grids_work_can_be_brought_back() {
    let folder = tempfile::tempdir().unwrap();
    let now = 46_000;
    let (mut core, person, _, host) = company(folder.path(), now);
    let (spare, _) = core.enrol_device(&person, "Render PC", "linux", now).unwrap();
    let other = core.offer_host(&spare.id, "Render PC", big(), big(), Commitment::Share, now + 1).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();
    core.add_model_plan("owner", "Acme/Chat", None, 100, crate::policy::IdlePolicy::default(), Target::Computers { hosts: vec![host.clone()] }, now + 2).unwrap();
    assert_eq!(core.model_assignments().unwrap().len(), 1);

    core.drain_host(&admin.id, &host, now + 3).unwrap();
    assert!(core.model_assignments().unwrap().is_empty(), "a computer left out gets no model");
    core.bring_host_back(&admin.id, &host, now + 4).unwrap();
    assert_eq!(core.model_assignments().unwrap()[0].host_id, host, "brought back, its pick applies again");
    assert_ne!(core.model_assignments().unwrap()[0].host_id, other.id);
    assert!(core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "host.brought back"));
}

#[test]
fn a_request_whose_computer_stops_answering_does_not_sit_there_running_for_ever() {
    let folder = tempfile::tempdir().unwrap();
    let now = 42_500;
    let (mut core, person, device, plan) = plan_over_two(folder.path(), now);
    let work = core.submit_model(&person, &device, &plan.id, small(), None, now + 1).unwrap();
    let lease = core.grant_model_lease(&work.id, 30, now + 2).unwrap();
    core.advance(&lease.id, Stage::Preparing, now + 3).unwrap();
    core.advance(&lease.id, Stage::Running, now + 4).unwrap();

    // The reservation runs out while the computer is answering, half an hour before the caller's
    // own deadline. Nothing else would ever end this request: it cannot go back in the queue once
    // part of an answer may have been sent, so without this it would be running for ever with no
    // computer behind it.
    assert_eq!(core.expire(now + 40), 1);
    let after = core.snapshot().unwrap().workloads.iter().find(|entry| entry.id == work.id).unwrap().clone();
    assert_eq!(after.stage, Stage::Failed);
    assert_eq!(after.updated_at, now + 40);
    assert!(core.snapshot().unwrap().leases.iter().all(|held| held.released_at.is_some()), "and the room it held is back");
    assert_eq!(core.free_on(&lease.host_id, now + 40).unwrap().memory_gb, big().memory_gb);
    let reason = core.snapshot().unwrap().audit.events.iter().rev().find(|event| event.action == "work.failed").unwrap().reason.clone();
    assert_eq!(reason, "the computer stopped answering");
}

// ---- One typed command, and everything it caused ----

#[test]
fn every_event_one_command_causes_carries_its_name() {
    let folder = tempfile::tempdir().unwrap();
    let now = 51_000;
    let (mut core, _person, _, _) = company(folder.path(), now);
    let before = core.history_for("keen-heron-3f1a").unwrap();
    assert!(before.is_empty(), "nothing has been done under that name yet");

    let plan = core
        .during("keen-heron-3f1a", |core| {
            let plan = core.add_model_plan("owner", "hf.co/Qwen/Qwen3-8B", None, 50, crate::policy::IdlePolicy::default(), Target::All, now).unwrap();
            core.raise_policy("owner", "a model plan was ordered", now).unwrap();
            plan
        });
    assert!(!plan.id.is_empty());

    let caused = core.history_for("keen-heron-3f1a").unwrap();
    assert_eq!(caused.len(), 2, "both events the one command caused");
    assert!(caused.iter().all(|event| event.command.as_deref() == Some("keen-heron-3f1a")));
    assert_eq!(core.recorded_for("keen-heron-3f1a").unwrap(), caused.iter().map(|event| event.sequence).collect::<Vec<_>>());

    // What the command did not do does not carry its name, and the realm is not left inside it.
    assert_eq!(core.command(), None);
    core.raise_policy("owner", "an ordinary tick", now + 1).unwrap();
    assert_eq!(core.history_for("keen-heron-3f1a").unwrap().len(), 2);
    core.verify_audit().unwrap();
}

#[test]
fn a_history_sealed_before_commands_were_correlated_still_verifies() {
    let folder = tempfile::tempdir().unwrap();
    let now = 52_000;
    let (mut core, _person, _, _) = company(folder.path(), now);
    // Everything `company` wrote was written without a command, exactly as an earlier build
    // would have written it. Appending a correlated event must not disturb any of it.
    let sealed_before: Vec<String> = core.since(0).unwrap().iter().map(|event| event.seal.clone()).collect();
    assert!(sealed_before.len() >= 3);
    assert!(core.since(0).unwrap().iter().all(|event| event.command.is_none()));

    core.during("wise-otter-00ab", |core| core.raise_policy("owner", "under one command", now).unwrap());
    let after = core.since(0).unwrap();
    assert_eq!(after[..sealed_before.len()].iter().map(|event| event.seal.clone()).collect::<Vec<_>>(), sealed_before);
    assert_eq!(after.last().unwrap().command.as_deref(), Some("wise-otter-00ab"));
    core.verify_audit().unwrap();

    // The seal of an uncorrelated event is taken over the bytes it always was, so adding a name
    // to it afterwards is caught. The database refuses the edit outright; somebody who takes the
    // trigger out of the way first still cannot re-seal what they changed.
    let path = core.path().to_owned();
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let refused = connection.execute("UPDATE audit_events SET command = 'tidy-raven-ffff' WHERE sequence = 1", []).unwrap_err();
    assert!(refused.to_string().contains("an event cannot be changed once it is recorded"), "{refused}");
    connection.execute_batch("DROP TRIGGER audit_events_never_change").unwrap();
    connection.execute("UPDATE audit_events SET command = 'tidy-raven-ffff' WHERE sequence = 1", []).unwrap();
    drop(connection);
    let reopened = Core::open(&path, &key()).unwrap();
    assert!(reopened.verify_audit().unwrap_err().contains("Event 1 was altered"));
}

#[test]
fn a_command_name_reads_aloud_and_is_never_a_workers_name() {
    let folder = tempfile::tempdir().unwrap();
    let now = 53_000;
    let (mut core, _person, _, _) = company(folder.path(), now);
    let command = name::fresh_command();
    assert!(name::is_command(&command), "{command}");
    core.during(&command, |core| core.raise_policy("owner", "named for a person to repeat", now).unwrap());
    let caused = core.history_for(&command).unwrap();
    assert_eq!(caused.len(), 1);
    assert!(caused[0].command.as_deref().is_some_and(name::is_command));
}

// ---- Reliability, scale and operations ----

#[test]
fn a_grid_refuses_the_row_after_its_limit_and_says_which_number_it_reached() {
    // One case per limit the core enforces. The numbers themselves are design bounds, not
    // measured ones: what this proves is that each one is a door and not a sentence in a
    // document, and that the refusal names the number, so the answer to "how many may I have" is
    // in the refusal itself.
    let folder = tempfile::tempdir().unwrap();
    let now = 400_000;
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();

    // Rather than writing five hundred and twelve rows through the audited door, the count is
    // what the limit reads, so the limit is reached by making the count true.
    let realm_id = core.realm().id.clone();
    core.store
        .in_one_change(|change| {
            for at in 1..limits::MAX_PEOPLE {
                change
                    .execute(
                        "INSERT INTO principals (id, realm_id, kind, name, email, created_at, suspended_at, generation) VALUES (?1, ?2, 'person', ?3, NULL, ?4, NULL, 1)",
                        rusqlite::params![format!("principal-filler-{at}"), realm_id, format!("filler {at}"), now],
                    )
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        })
        .unwrap();
    let refused = core.add_principal("owner", PrincipalKind::Person, "one too many", &[Role::User], now).unwrap_err();
    assert_eq!(refused, format!("A grid can have at most {} people", limits::MAX_PEOPLE));

    // Computers, counted the same way.
    core.store
        .in_one_change(|change| {
            for at in 0..limits::MAX_DEVICES {
                change
                    .execute(
                        "INSERT INTO devices (id, realm_id, principal_id, name, platform, token_hash, attestation, enrolled_at, last_seen_at, revoked_at, generation)
                         VALUES (?1, ?2, ?3, ?4, 'linux', 'x', ?5, ?6, NULL, NULL, 1)",
                        rusqlite::params![format!("device-filler-{at}"), realm_id, person.id, format!("filler {at}"), "\"unverified\"", now],
                    )
                    .map_err(|error| error.to_string())?;
            }
            Ok(())
        })
        .unwrap();
    let refused = core.enrol_device(&person.id, "one too many", "linux", now).unwrap_err();
    assert_eq!(refused, format!("A grid can have at most {} computers", limits::MAX_DEVICES));
}

#[test]
fn work_in_flight_is_bounded_and_finished_work_does_not_count_towards_it() {
    let folder = tempfile::tempdir().unwrap();
    let now = 410_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let realm_id = core.realm().id.clone();
    core.store
        .in_one_change(|change| {
            for at in 0..limits::MAX_UNFINISHED_WORK {
                let mut work = Workload::new(&realm_id, Capability::Models, Kind::Inference, &person, &device, small(), 1, now);
                work.id = format!("work-filler-{at}");
                work.stage = Stage::Queued;
                store::Store::write_workload(change, &work)?;
            }
            Ok(())
        })
        .unwrap();
    let refused = core.submit(Workload::new(&realm_id, Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap_err();
    assert_eq!(refused, format!("A grid can have at most {} pieces of work in flight at once", limits::MAX_UNFINISHED_WORK));

    // Work that has finished is not in flight, so finishing one makes room for one.
    core.store
        .in_one_change(|change| {
            change.execute("UPDATE workloads SET stage = 'completed' WHERE id = 'work-filler-0'", []).map_err(|error| error.to_string())?;
            Ok(())
        })
        .unwrap();
    core.submit(Workload::new(&realm_id, Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap();
}

#[test]
fn an_upgrade_takes_a_copy_first_and_says_which_versions_can_be_taken_back_out() {
    let folder = tempfile::tempdir().unwrap();
    let now = 420_000;
    let path = folder.path().join("realm.db");
    let (core, _, _, _) = company(folder.path(), now);
    core.close().unwrap();

    let mut core = Core::open(&path, &key()).unwrap();
    let copies = folder.path().join("copies");
    let (copy, versions) = core.upgrade_with_a_copy(&copies, now).unwrap();
    assert_eq!(copy, None, "opening the realm already brought it up, so there was nothing left to do");
    assert!(versions.is_empty());

    // And the copy itself works, taken from a realm that is open.
    let beside = folder.path().join("copy.db");
    core.copy_to(&beside).unwrap();
    let copied = Core::open(&beside, &key()).unwrap();
    assert_eq!(copied.snapshot().unwrap().principals.len(), core.snapshot().unwrap().principals.len());
    assert_eq!(copied.store.version().unwrap(), store::SCHEMA_VERSION, "an exact copy is the same shape, which is the point of it and also its limit");
    copied.close().unwrap();
    assert!(core.copy_to(&beside).unwrap_err().contains("already a file"), "a copy never writes over one");

    // What a runbook says about each version comes out of the code rather than out of a list
    // somebody keeps up to date by hand.
    assert!(Core::how_to_undo(1).contains("the copy taken before the upgrade is the only way back"));
    assert!(Core::how_to_undo(store::SCHEMA_VERSION).contains("can be taken back out"));
}

#[test]
fn a_step_that_only_adds_indexes_does_not_record_having_changed_a_row() {
    // `schema::describe` is written into the realm's own `migrations` table and the survey reads
    // it back, so it is the permanent account of what each step did and nobody can check it
    // against the SQL years later. Version ten is seventeen `CREATE INDEX` statements and nothing
    // else; its record used to say it had also made there be one host row per computer, which no
    // statement in it does and which `put_host` has always done on its own.
    let mut index_only = Vec::new();
    for version in 1..=store::SCHEMA_VERSION {
        let sql = store::schema::step(version).expect("every version this build writes has a step");
        let without_comments = sql.lines().map(str::trim).filter(|line| !line.is_empty() && !line.starts_with("--")).collect::<Vec<&str>>().join(" ");
        let statements: Vec<String> = without_comments.split(';').map(|statement| statement.trim().to_uppercase()).filter(|statement| !statement.is_empty()).collect();
        if !statements.iter().all(|statement| statement.starts_with("CREATE INDEX")) {
            continue;
        }
        index_only.push(version);
        // An index-only step changes no row and enforces no rule, so its record may not use a
        // verb that says it did one of those. The words are the ones a description would reach
        // for; `one host row per computer` may still be mentioned, and now is, as the thing
        // `put_host` keeps true rather than as something this step did.
        let said = store::schema::describe(version).to_lowercase();
        for verb in ["de-dup", "dropped", "tidied", "merged", "removed", "enforc", "assumed"] {
            assert!(!said.contains(verb), "version {version} adds indexes and changes no row, and its own record says it {verb}: {said}");
        }
    }
    assert_eq!(index_only, vec![10], "version ten is the one step that is only indexes; if another is added this test should see it");
}

#[test]
fn a_restore_drill_says_what_a_restore_does_not_bring_back() {
    let folder = tempfile::tempdir().unwrap();
    let now = 430_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let work = core.submit(Workload::new(&core.realm().id.clone(), Capability::Models, Kind::Inference, &person, &device, small(), 1, now), now).unwrap();
    core.grant_lease(&work.id, 600, now).unwrap();
    let backup = core.backup(now).unwrap();
    let before = std::fs::metadata(core.path()).unwrap().len();

    let drill = Core::rehearse_restore(&folder.path().join("drill"), backup, &key(), now).unwrap();
    assert_eq!(drill.realm_id, core.realm().id);
    assert_eq!(drill.taken_at, now);
    assert_eq!(drill.schema_version, store::SCHEMA_VERSION);
    assert_eq!(drill.counts.people, 1);
    assert_eq!(drill.counts.leases, 1);
    assert!(drill.history_verified, "a drill that does not verify the history has not rehearsed anything");
    assert!(drill.faults.is_empty(), "{:?}", drill.faults);
    assert_eq!(drill.not_restored.len(), 3);
    assert!(drill.not_restored.iter().any(|said| said.starts_with("Sign-ins")));
    assert!(drill.not_restored.iter().any(|said| said.contains("permission the realm ever issued")));
    assert!(drill.not_restored.iter().any(|said| said.contains("last said about itself")));
    assert!(drill.kept_at.exists(), "and the realm the drill built is left where it can be looked at");

    // The live realm was not touched.
    assert_eq!(std::fs::metadata(core.path()).unwrap().len(), before);
    assert_eq!(core.snapshot().unwrap().leases.len(), 1);
}

#[test]
fn an_evidence_bundle_carries_identifiers_and_counts_and_nothing_anybody_would_mind_sharing() {
    let folder = tempfile::tempdir().unwrap();
    let now = 440_000;
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace Hopper", &[Role::CredentialAdmin], now).unwrap();
    let credential = credential::Credential::new(
        &core.realm().id.clone(),
        "Billing key",
        credential::Secret::ApiKey,
        "vault-billing",
        &"a".repeat(64),
        "https://api.acme.test",
        &admin.id,
        now,
    )
    .unwrap();
    core.add_credential(&admin.id, credential, now).unwrap();

    let bundle = core.evidence(0, now).unwrap();
    assert_eq!(bundle.realm_id, core.realm().id);
    assert!(bundle.checkup.alive());
    assert!(!bundle.migrations.is_empty(), "an engineer needs to know which versions this realm has been through");
    assert!(!bundle.recent.is_empty());
    let written = serde_json::to_string(&bundle).unwrap();
    for private in ["Grace Hopper", "Billing key", "api.acme.test", "vault-billing", &"a".repeat(64)] {
        assert!(!written.contains(private), "an evidence bundle carried {private}");
    }
    // What it does carry is what happened, by its fixed word, and the identifiers it happened to.
    assert!(written.contains("credential.added"), "{written}");
    assert!(written.contains(&admin.id), "and who did it, by identifier");
}

#[test]
fn the_words_for_a_finished_stage_are_the_ones_the_code_means() {
    // The queries that ask about work in flight spell the finished stages out in SQL. If
    // `Stage::finished` ever changes, this fails rather than the realm quietly sweeping the wrong
    // set of work.
    let folder = tempfile::tempdir().unwrap();
    let now = 450_000;
    let (core, person, device, _) = company(folder.path(), now);
    let realm_id = core.realm().id.clone();
    let every = [
        Stage::Draft,
        Stage::Validating,
        Stage::Queued,
        Stage::Leased,
        Stage::Preparing,
        Stage::Running,
        Stage::Draining,
        Stage::Completed,
        Stage::Rejected,
        Stage::Cancelled,
        Stage::Expired,
        Stage::Failed,
        Stage::Quarantined,
    ];
    core.store
        .in_one_change(|change| {
            for (at, stage) in every.iter().enumerate() {
                let mut work = Workload::new(&realm_id, Capability::Models, Kind::Inference, &person, &device, small(), 1, now);
                work.id = format!("work-stage-{at}");
                work.stage = *stage;
                store::Store::write_workload(change, &work)?;
            }
            Ok(())
        })
        .unwrap();
    let unfinished = core.store.unfinished_on(&device).unwrap();
    let expected = every.iter().filter(|stage| !stage.finished()).count();
    assert_eq!(unfinished.len(), expected, "the SQL and Stage::finished disagree about which stages are finished");
    assert_eq!(core.store.unfinished_count().unwrap(), expected);
}

#[test]
fn a_history_past_what_it_keeps_is_still_trimmed_without_counting_it_every_time() {
    // Trimming left the write path as a `SELECT COUNT(*)` run on every audited action and came
    // back as two index seeks. This proves the cheaper guard still fires: it builds a history
    // past `audit::KEEP`, carries it out, and then writes one ordinary event.
    let folder = tempfile::tempdir().unwrap();
    let now = 460_000;
    let (mut core, person, _, _) = company(folder.path(), now);
    let realm_id = core.realm().id.clone();
    let (head, _) = core.store.head().unwrap();
    let filler = audit::KEEP as u64 + 10;
    core.store
        .in_one_change(|change| {
            for at in 1..=filler {
                change
                    .execute(
                        "INSERT INTO audit_events (sequence, id, realm_id, at, capability, principal_id, device_id, workload_id, action, resource_id,
                                                   policy_version, decision, reason, command, previous_seal, seal)
                         VALUES (?1, ?2, ?3, ?4, NULL, 'owner', NULL, NULL, 'filler', NULL, 1, 'allowed', '', NULL, 'x', 'y')",
                        rusqlite::params![(head + at) as i64, format!("event-filler-{at}"), realm_id, now],
                    )
                    .map_err(|error| error.to_string())?;
            }
            change
                .execute("UPDATE audit_chain SET head_sequence = ?1, head_seal = 'y', updated_at = ?2", rusqlite::params![(head + filler) as i64, now])
                .map_err(|error| error.to_string())?;
            Ok(())
        })
        .unwrap();
    let (held, _, _) = core.store.history_shape().unwrap();
    assert!(held > audit::KEEP, "the history is past what it keeps: {held}");

    // Nothing is dropped while nothing has been carried off this computer, however long it gets.
    assert_eq!(core.store.trim().unwrap(), 0, "an unexported event is never dropped");

    // And this is the regime that matters: a realm that never exports drops nothing, so its
    // oldest sequence never moves and the cheap guard in `append_events` is true for ever once the
    // chain is past `KEEP`. Every audited action therefore reaches `trim`, and `trim` has to stay
    // cheap on the way in. The statement count cannot show that, because a `SELECT COUNT(*)` is
    // one statement returning one row however much of the table it adds up; what shows it is the
    // statements themselves.
    let meter = crate::core::bench::Meter::on(core.store_for_tests());
    core.grant("owner", &person, Role::Auditor, now).unwrap();
    let ran = meter.ran();
    drop(meter);
    core.withdraw("owner", &person, Role::Auditor, now).unwrap();
    assert!(
        !ran.iter().any(|statement| statement.contains("COUNT(*) FROM audit_events")),
        "recording one thing in a realm that never exports counted the whole history: {ran:?}"
    );

    // Once it has been carried out, one ordinary audited action is enough to tidy it.
    core.exported("owner", head + filler, now).unwrap();
    core.grant("owner", &person, Role::Auditor, now).unwrap();
    let (after, _, _) = core.store.history_shape().unwrap();
    assert!(after <= audit::KEEP + 1, "the history was trimmed back to what it keeps: {after}");
}

#[test]
fn a_history_trimmed_once_is_still_trimmed_the_next_time() {
    // Trimming worked out how far to go from a row count rather than a sequence number. The first
    // trim, from sequence one, happened to be right, because there the two are the same. Every
    // trim after it asked to drop a sequence far below the oldest one still held, matched nothing,
    // and left the history growing for ever while still counting the whole of it on the way in.
    let folder = tempfile::tempdir().unwrap();
    let now = 470_000;
    let (mut core, person, _, _) = company(folder.path(), now);
    let realm_id = core.realm().id.clone();
    let fill = |core: &mut Core, from: u64, many: u64| {
        core.store
            .in_one_change(|change| {
                for at in 1..=many {
                    change
                        .execute(
                            "INSERT INTO audit_events (sequence, id, realm_id, at, capability, principal_id, device_id, workload_id, action, resource_id,
                                                       policy_version, decision, reason, command, previous_seal, seal)
                             VALUES (?1, ?2, ?3, ?4, NULL, 'owner', NULL, NULL, 'filler', NULL, 1, 'allowed', '', NULL, 'x', 'y')",
                            rusqlite::params![(from + at) as i64, format!("event-filler-{from}-{at}"), realm_id, now],
                        )
                        .map_err(|error| error.to_string())?;
                }
                change
                    .execute("UPDATE audit_chain SET head_sequence = ?1, head_seal = 'y', updated_at = ?2", rusqlite::params![(from + many) as i64, now])
                    .map_err(|error| error.to_string())?;
                Ok(())
            })
            .unwrap();
    };

    // Past what it keeps and all of it carried out. Carrying out records that it happened, and
    // that one ordinary event is what reaches `trim`, so this is the real path rather than a
    // direct call. This much already worked: the chain comes back to what it keeps and its oldest
    // sequence moves well past one.
    let (head, _) = core.store.head().unwrap();
    fill(&mut core, head, audit::KEEP as u64 + 10);
    let (head, _) = core.store.head().unwrap();
    core.exported("owner", head, now).unwrap();
    let (after_first, oldest, _) = core.store.history_shape().unwrap();
    assert!(after_first <= audit::KEEP, "the first trim held it at what it keeps: {after_first}");
    assert!(oldest > 1, "and the oldest sequence has moved past one: {oldest}");

    // A handful more, carried out again. The only thing different about this trim is that the
    // front has already gone once, which is why a count of the rows is no longer a sequence
    // number: a few rows over the limit is a number far below the oldest sequence still held, so
    // the delete matched nothing and the history grew instead.
    let (head, _) = core.store.head().unwrap();
    fill(&mut core, head, 5);
    let (head, _) = core.store.head().unwrap();
    core.exported("owner", head, now).unwrap();
    let (after_second, _, _) = core.store.history_shape().unwrap();
    assert!(after_second <= audit::KEEP, "the second trim held it too, rather than letting it grow: {after_second}");

    // And it is still cheap on the write path: no counting the whole history to decide.
    let meter = crate::core::bench::Meter::on(core.store_for_tests());
    core.grant("owner", &person, Role::Auditor, now).unwrap();
    let ran = meter.ran();
    drop(meter);
    assert!(
        !ran.iter().any(|statement| statement.contains("COUNT(*) FROM audit_events")),
        "trimming counted the whole history again: {ran:?}"
    );
}
