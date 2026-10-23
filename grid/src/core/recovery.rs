//! Getting a realm back: power loss, a damaged file, a lost computer, two writers, a crash part
//! way through a migration.
//!
//! Several of these are already covered elsewhere and are not repeated here. What is covered,
//! and where, so that nobody has to go looking:
//!
//! | What | Test | Where |
//! | --- | --- | --- |
//! | Power loss with a torn journal | `a_crash_leaves_the_last_committed_state_and_nothing_half_written` | core/tests.rs |
//! | A change that never committed | `a_change_that_was_never_committed_leaves_nothing_behind` | core/tests.rs |
//! | A migration step that fails | `a_step_that_fails_leaves_the_grid_at_the_version_it_was_at` | core/tests.rs |
//! | Restart, with the right key and the wrong one | `a_realm_is_still_there_after_a_restart_and_opens_only_with_its_key` | core/tests.rs |
//! | A database from a newer build | the same test | core/tests.rs |
//! | Backup and restore | `a_backup_restores_the_realm_and_only_with_its_key` | core/tests.rs |
//! | A backup edited afterwards | `a_backup_edited_after_it_was_taken_is_refused_whichever_part_was_edited` | core/attack.rs |
//! | Host loss, workspace keeps its owner | `a_workspace_keeps_its_owner_when_its_computer_dies_and_waits_where_its_data_can_be_found` | workspace/tests.rs |
//! | Host loss while somebody is signed in | `a_desk_that_loses_its_computer_while_somebody_is_in_it_can_be_opened_again` | workspace/tests.rs |
//! | A restored realm hands nobody a live desk | `a_restored_realm_brings_every_placement_back_and_hands_nobody_a_live_workspace` | workspace/tests.rs |
//! | A reservation that lapses | `a_reservation_that_lapses_takes_the_placement_with_it_and_the_workspace_waits` | workspace/tests.rs |
//! | A request left open by a hub that stopped | `a_request_left_open_by_a_hub_that_stopped_is_closed_as_unknown` | broker/tests.rs |
//! | A damaged file | `a_damaged_database_is_reported_rather_than_read_half_way` | core/fuzz.rs |
//!
//! What is here is what was missing: a realm that can be asked about its own health, two writers
//! on one file, a power cut at the first version, a key offered at the wrong moment, and the
//! honest answer about key rotation, which does not exist.
use super::*;
use identity::{PrincipalKind, Role};
use realm::{Capability, RealmKind};

fn key() -> String {
    "a".repeat(64)
}

/// PROVES that a realm can be asked what is wrong with it without opening anything else: the
/// shape of its own file, whether every reference leads somewhere, and whether the history is
/// whole. A healthy realm answers with nothing. A realm whose reference was broken by direct SQL
/// names the table.
///
/// It is worth being plain about why this is worth having, because the realm sets
/// `PRAGMA foreign_keys = ON` when it opens and so a realm this process wrote through its own
/// doors will not have a broken reference. The value is after an import, after a restore, and
/// after a file has been damaged, where nothing was checked before and nothing could be.
///
/// DOES NOT PROVE that SQLite's own checks catch every corruption. They catch what they catch.
#[test]
fn a_realm_can_be_asked_what_is_wrong_with_it_without_opening_anything_else() {
    let folder = tempfile::tempdir().unwrap();
    let now = 60_000;
    let mut core = Core::create(&folder.path().join("health.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    assert!(core.check_storage().unwrap().is_empty(), "a healthy realm has nothing to report");

    // A reference broken behind the realm's back, with the rule switched off to do it.
    let path = core.path().to_owned();
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("PRAGMA foreign_keys = OFF; UPDATE devices SET principal_id = 'principal-gone'").unwrap();
    drop(connection);
    let reopened = Core::open(&path, &key()).unwrap();
    let faults = reopened.check_storage().unwrap();
    assert!(faults.iter().any(|fault| fault.contains("devices")), "a broken reference was not named: {faults:?}");

    // And a history edited behind its back is named too, by the same call.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("DROP TRIGGER audit_events_never_change").unwrap();
    connection.execute("UPDATE audit_events SET reason = 'rewritten' WHERE sequence = 1", []).unwrap();
    drop(connection);
    let reopened = Core::open(&path, &key()).unwrap();
    let faults = reopened.check_storage().unwrap();
    assert!(faults.iter().any(|fault| fault.contains("altered")), "an edited history was not named: {faults:?}");
}

/// PROVES that two handles writing to one realm do not interleave a change: the second waits for
/// the first to let go and then succeeds, the history still verifies, it holds no half-written
/// event and no gap, and both handles agree on what the realm holds afterwards.
///
/// The hold is released from another thread on purpose. A hold taken and released on the thread
/// that is also doing the writing cannot produce a wait at all, because the write has already come
/// back before the hold is let go, so that shape can only ever see the refusal.
///
/// DOES NOT PROVE serializability under real concurrency. This is one thread holding one
/// transaction open while the other writes, which is one interleaving chosen by the test. A
/// proper answer would need threads, a scheduler nobody controls, and many more runs than a test
/// suite can afford. It also does not cover a hold that outlasts the ten-second busy timeout:
/// that is refused with a sentence rather than waited out, and proving it here would cost those
/// ten seconds on every run.
#[test]
fn two_handles_on_one_realm_never_interleave_a_change() {
    let folder = tempfile::tempdir().unwrap();
    let now = 60_100;
    let path = folder.path().join("two.db");
    let mut first = Core::create(&path, "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    first.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let mut second = Core::open(&path, &key()).unwrap();

    // One handle holds the file while the other writes. The busy timeout is ten seconds and this
    // hold is three hundred milliseconds, so the second writer waits and then succeeds; a hold
    // that outlasted the timeout would be refused with a sentence instead, which is why the match
    // below still has both arms. The hold is let go from another thread because the write is
    // synchronous: releasing it on this thread could only happen after the write had already come
    // back, which is the refusal every time and never the wait.
    let holder = rusqlite::Connection::open(&path).unwrap();
    holder.execute_batch("BEGIN IMMEDIATE").unwrap();
    let releasing = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(300));
        holder.execute_batch("ROLLBACK").unwrap();
    });
    let blocked = second.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::Operator], now);
    releasing.join().unwrap();
    assert!(blocked.is_ok(), "a hold well inside the busy timeout is waited out, not refused: {:?}", blocked.err());

    // Whatever happened, both handles see a realm whose history is whole and whose events run
    // without a gap.
    for core in [&first, &second] {
        core.verify_audit().unwrap();
        let events = core.since(0).unwrap();
        for pair in events.windows(2) {
            assert_eq!(pair[1].sequence, pair[0].sequence + 1, "the history has a gap");
        }
    }
    // And the two handles agree on how many people there are.
    assert_eq!(first.snapshot().unwrap().principals.len(), second.snapshot().unwrap().principals.len());
}

/// PROVES that a realm which lost power part way through its first version, leaving only the
/// table that records versions, opens and finishes the job, with every version recorded once.
///
/// DOES NOT PROVE behaviour under a real power cut. The table is created outside a transaction on
/// purpose, because it is what records transactions, and this test reproduces the one state that
/// leaves behind.
#[test]
fn a_power_cut_at_the_first_version_leaves_a_realm_that_still_opens() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("cut.db");
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("CREATE TABLE migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL, description TEXT NOT NULL)").unwrap();
    drop(connection);

    let mut store = store::Store::open(&path).unwrap();
    store.migrate().unwrap();
    assert_eq!(store.version().unwrap(), store::SCHEMA_VERSION);
    let versions: Vec<u32> = store.history().unwrap().into_iter().map(|(version, _, _)| version).collect();
    assert_eq!(versions, (1..=store::SCHEMA_VERSION).collect::<Vec<_>>(), "every version is recorded once and in order");
}

/// PROVES that a realm's key is asked for at the moment it is needed and never kept anywhere a
/// backup or the database could carry it: the right key opens the realm, a wrong one is refused
/// with the same sentence whichever way it is wrong, and neither the file nor a backup holds it.
///
/// WHAT KEY ROTATION DOES, WHICH IS NOTHING. There is no way to rotate a realm key. `Chain::
/// verify` takes exactly one key and every event in a realm is sealed under it, so changing the
/// key would make every earlier seal fail. A realm whose key is believed to have leaked has one
/// answer today: take a backup, make a new realm, and carry what matters across by hand, which
/// means every permission and every sign-in it had handed out stops. This test pins what is
/// true rather than pretending rotation exists; adding it needs a table of key versions, a key
/// version on each event, and a verify that takes several keys, and that is production work this
/// phase did not do.
///
/// DOES NOT PROVE that the key is safe where it actually lives. Nothing in this crate reads or
/// writes an operating system vault; that is the engine's, and what a crash dump of this process
/// contains is not something anybody here can say. What this shows is that the realm's own two files do not
/// carry it.
#[test]
fn a_realm_key_is_asked_for_and_never_kept_and_there_is_no_way_to_rotate_one() {
    let folder = tempfile::tempdir().unwrap();
    let now = 60_300;
    let mut core = Core::create(&folder.path().join("keys.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let backup = serde_json::to_string(&core.backup(now).unwrap()).unwrap();
    let path = core.path().to_owned();
    core.close().unwrap();

    for wrong in ["b".repeat(64), "a".repeat(63) + "b", String::new(), "not a key".to_owned()] {
        let refused = Core::open(&path, &wrong).unwrap_err();
        assert!(refused.contains("not this grid's key"), "{wrong:?}: {refused}");
    }
    Core::open(&path, &key()).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend(std::fs::read(format!("{}-wal", path.display())).unwrap_or_default());
    let needle = key();
    assert!(!bytes.windows(needle.len()).any(|window| window == needle.as_bytes()), "the key is in the realm's file");
    assert!(!backup.contains(&needle), "the key is in a backup");

    // There is no door to rotate one, and this is the statement of that: a realm records which
    // vault entry holds its key and which version of it, and nothing moves that version on.
    let core = Core::open(&path, &key()).unwrap();
    assert_eq!(core.key_reference().unwrap().version, 1, "a key version exists and nothing in this build ever raises it");
}

/// PROVES what a realm does when a computer stops answering, in the two ways it happens: calling
/// `host_lost` stops anything new being placed there and takes its workspaces off it, and the
/// reservation the computer was holding goes back when it lapses, with the work recorded as
/// failed rather than left running for ever.
///
/// It is worth being plain that these are two different calls. `host_lost` is the workspace
/// answer and does not touch a reservation; what gives a reservation back is the reservation
/// running out and `expire` noticing. A realm nobody ever calls `expire` on holds that
/// reservation until somebody does.
///
/// DOES NOT PROVE that the computer stopped. Nothing in the core reaches it; what the realm does
/// is stop counting on it.
#[test]
fn a_realm_that_lost_a_computer_stops_placing_on_it_and_gets_its_reservation_back() {
    let folder = tempfile::tempdir().unwrap();
    let now = 60_400;
    let mut core = Core::create(&folder.path().join("lost.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::RealmAdmin], now).unwrap().id;
    let person = core.add_principal(&admin, PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let (device, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    let plenty = work::Resources { cpu: 16.0, memory_gb: 64.0, disk_gb: 500.0, gpu: true, vram_gb: 24.0 };
    let host = core.offer_host(&device.id, "Studio PC", plenty, plenty, work::Commitment::Share, now).unwrap();
    let realm = core.realm().id.clone();
    let needs = work::Resources { cpu: 1.0, memory_gb: 1.0, disk_gb: 1.0, gpu: false, vram_gb: 0.0 };
    let work = core
        .submit(work::Workload::new(&realm, Capability::Models, work::Kind::Inference, &person.id, &device.id, needs, 1, now), now)
        .unwrap();
    core.grant_lease(&work.id, 600, now).unwrap();
    assert_eq!(core.snapshot().unwrap().leases.iter().filter(|lease| lease.released_at.is_none()).count(), 1);

    // The computer is declared lost. Nothing new is placed on it from here.
    core.host_lost(&admin, &host.id, "the computer did not come back", now + 10).unwrap();
    assert!(core.snapshot().unwrap().hosts.iter().find(|found| found.id == host.id).unwrap().draining, "a lost computer is draining");
    let needs = work::Resources { cpu: 1.0, memory_gb: 1.0, disk_gb: 1.0, gpu: false, vram_gb: 0.0 };
    let next = core
        .submit(work::Workload::new(&realm, Capability::Models, work::Kind::Inference, &person.id, &device.id, needs, 1, now + 10), now + 10)
        .unwrap();
    assert!(core.grant_lease(&next.id, 600, now + 10).is_err(), "work is placed on a computer that stopped answering");

    // And when the reservation it was holding runs out, the realm takes it back and says the
    // work failed rather than leaving it running in the record.
    core.expire(now + 1_000);
    let record = core.snapshot().unwrap();
    assert_eq!(record.leases.iter().filter(|lease| lease.released_at.is_none()).count(), 0, "a lapsed reservation goes back");
    let after = record.workloads.iter().find(|found| found.id == work.id).unwrap();
    assert!(after.stage.finished(), "work on a computer that stopped answering is not left running: it is {:?}", after.stage);
    core.verify_audit().unwrap();

    // All of that survives a restart, because none of it was only in memory.
    let path = core.path().to_owned();
    core.close().unwrap();
    let reopened = Core::open(&path, &key()).unwrap();
    assert!(reopened.snapshot().unwrap().workloads.iter().find(|found| found.id == work.id).unwrap().stage.finished());
    reopened.verify_audit().unwrap();
}

/// PROVES that a realm carried to another computer as a backup and restored there is the realm it
/// was: the same identity, the same people, the same history, and it verifies.
///
/// DOES NOT PROVE a network partition was survived, because the core has no network. Partition,
/// slow reads, certificate pinning and tunnels belong to the hub, which is not built on the core,
/// and testing those would mean a loopback listener at best and a live address at worst. No test
/// in this phase reaches an address that is not this computer's own.
#[test]
fn a_realm_carried_to_another_computer_is_the_realm_it_was() {
    let folder = tempfile::tempdir().unwrap();
    let now = 60_500;
    let mut here = Core::create(&folder.path().join("here.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let person = here.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    here.grant("owner", &person.id, Role::Auditor, now).unwrap();
    let taken = here.backup(now).unwrap();
    let before = here.since(0).unwrap();

    let there = Core::restore(&folder.path().join("there.db"), taken, &key()).unwrap();
    assert_eq!(there.realm().id, here.realm().id);
    assert_eq!(there.snapshot().unwrap().principals.len(), 1);
    there.verify_audit().unwrap();
    let after = there.since(0).unwrap();
    assert_eq!(after.len(), before.len(), "the history came across whole");
    for (was, is) in before.iter().zip(after.iter()) {
        assert_eq!((was.sequence, &was.seal), (is.sequence, &is.seal), "an event changed in the crossing");
    }
}
