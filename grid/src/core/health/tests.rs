//! Whether a realm can answer, and whether it can take work.
use super::*;
use crate::core::identity::{PrincipalKind, Role};
use crate::core::realm::{Capability, RealmKind};
use crate::core::work::{Commitment, Resources};

fn key() -> String {
    "c".repeat(64)
}

fn room() -> Resources {
    Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 200.0, gpu: false, vram_gb: 0.0 }
}

fn company(folder: &std::path::Path, now: i64) -> (Core, String, String) {
    let mut core = Core::create(&folder.join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Workspaces], &key(), now).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::SecurityAdmin], now).unwrap();
    let (device, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    let host = core.offer_host(&device.id, "Studio PC", room(), room(), Commitment::Share, now).unwrap();
    (core, person.id, host.id)
}

#[test]
fn a_realm_with_no_computers_is_alive_and_not_ready_and_says_which() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_000;
    let core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let alive = core.healthy();
    assert_eq!(alive.health, Health::Serving, "a grid with nobody in it answers perfectly well");
    assert_eq!(alive.schema_version, SCHEMA_VERSION);
    assert!(alive.notes.is_empty(), "{:?}", alive.notes);

    let ready = core.ready(now);
    assert_eq!(ready.health, Health::Degraded);
    assert!(ready.notes.iter().any(|note| note.contains("No computer in this grid can take work")), "{:?}", ready.notes);
    assert!(ready.alive(), "not ready is not the same as not answering");
}

#[test]
fn readiness_turns_on_what_the_computers_are_doing_and_says_so() {
    let folder = tempfile::tempdir().unwrap();
    let now = 20_000;
    let (mut core, person, host) = company(folder.path(), now);
    assert_eq!(core.ready(now).health, Health::Serving);

    core.drain_host(&person, &host, now).unwrap();
    assert_eq!(core.ready(now).health, Health::Degraded, "a drained computer takes nothing");
    core.bring_host_back(&person, &host, now).unwrap();
    assert_eq!(core.ready(now).health, Health::Serving);

    // And a grid that has been paused says that instead, because it is the earlier reason.
    core.set_lifecycle(&person, crate::core::realm::Lifecycle::Paused, now).unwrap();
    let paused = core.ready(now);
    assert_eq!(paused.health, Health::Degraded);
    assert!(paused.notes.iter().any(|note| note.contains("paused")), "{:?}", paused.notes);
}

#[test]
fn a_health_check_never_verifies_the_history() {
    // Verifying reads every event and re-seals each one. A probe that did it would get slower
    // every day the realm ran. This is the test that stops somebody adding it.
    let folder = tempfile::tempdir().unwrap();
    let now = 30_000;
    let (mut core, person, _) = company(folder.path(), now);
    for at in 0..40 {
        core.grant("owner", &person, Role::Auditor, now + at).unwrap();
        core.withdraw("owner", &person, Role::Auditor, now + at).unwrap();
    }
    let (checkup, cost) = crate::core::bench::cost_of(core.store_for_tests(), || core.healthy());
    assert_eq!(checkup.health, Health::Serving);
    assert!(cost.rows <= 4, "a liveness check read {} rows, which means it is reading something it should not", cost.rows);

    // Readiness costs a little more and is still bounded: the four liveness statements, the one
    // that asks whether any computer can take work, and three that read the sizes of the things
    // nothing deletes from.
    //
    // The row bound is here because the statement count on its own cannot see the cost that
    // matters. The meter counts rows a statement gave back, never rows SQLite read, so a
    // `SELECT COUNT(*)` over a table of half a million is one statement and one row and looks
    // exactly like a seek. This assertion says readiness hands back a row per statement and no
    // more; what makes it cheap is that each of those statements is a seek or a bounded range,
    // and the thing that holds that is the SQL in `health.rs` and `store`, not this test.
    let (ready, cost) = crate::core::bench::cost_of(core.store_for_tests(), || core.ready(now));
    assert_eq!(ready.health, Health::Serving);
    assert_eq!(cost.statements, 8, "readiness is eight statements and this is the number the operations document carries");
    assert!(cost.rows <= 8, "readiness asked for {} rows, which is more than one answer per statement", cost.rows);
    // And the history is still there to be verified deliberately.
    core.verify_audit().unwrap();
}

#[test]
fn readiness_never_counts_the_three_tables_it_warns_about() {
    // The published sizes readiness warns at are 200 000 events, 200 000 reservations and
    // 500 000 brokered requests, and the runbook has an operator run this first in an incident.
    // A check that counted those three would walk roughly a million index entries to say so, and
    // would get slower every day the realm ran. Neither the statement count nor the row count can
    // see that: SQLite gives one row back for a count whatever it added up. So this asserts on
    // the statements themselves, which is where it shows.
    let folder = tempfile::tempdir().unwrap();
    let now = 35_000;
    let (core, _, _) = company(folder.path(), now);
    let meter = crate::core::bench::Meter::on(core.store_for_tests());
    let checkup = core.ready(now);
    let ran = meter.ran();
    crate::core::bench::Meter::off(core.store_for_tests());
    assert_eq!(checkup.health, Health::Serving);
    for counted in ["COUNT(*) FROM audit_events", "COUNT(*) FROM credential_uses", "COUNT(*) FROM leases"] {
        assert!(!ran.iter().any(|statement| statement.contains(counted)), "a readiness check ran `{counted}`: {ran:?}");
    }
    // The one count it does keep is the standing allowances still live, which rides
    // `allowances_by_expiry` and visits live rows only. It is here so that removing it has to be
    // a decision rather than an accident.
    assert!(ran.iter().any(|statement| statement.contains("FROM standing_allowances")), "{ran:?}");
}

#[test]
fn a_realm_whose_history_is_never_carried_out_says_so_before_the_file_does() {
    // The warning is the whole mechanism: nothing refuses to record what happened, because
    // refusing an event means refusing whatever caused it.
    let folder = tempfile::tempdir().unwrap();
    let now = 40_000;
    let (core, _, _) = company(folder.path(), now);
    let (held, _, waiting) = core.store_for_tests().history_shape().unwrap();
    assert_eq!(held, waiting, "nothing has been carried out of a new realm, so everything in it is waiting");
    assert!(held < crate::core::limits::WARN_AUDIT_EVENTS, "and a new realm is nowhere near the warning");
    assert_eq!(core.ready(now).health, Health::Serving);
}

#[test]
fn a_shape_newer_than_this_build_is_down_rather_than_degraded() {
    let folder = tempfile::tempdir().unwrap();
    let now = 50_000;
    let path = folder.path().join("realm.db");
    let (core, _, _) = company(folder.path(), now);
    core.close().unwrap();
    // A realm written by a newer build. Opening it is already refused; this is what a probe says
    // about one that was opened before the downgrade.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("INSERT INTO migrations (version, applied_at, description) VALUES (?1, ?2, 'from the future')", rusqlite::params![SCHEMA_VERSION as i64 + 1, now])
        .unwrap();
    drop(connection);
    let refused = Core::open(&path, &key()).unwrap_err();
    assert!(refused.contains("newer Yougori"), "{refused}");
}
