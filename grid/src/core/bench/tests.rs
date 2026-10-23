//! What the core asks the database, counted.
//!
//! Each test here builds the same realm at two sizes and asserts that the number of statements is
//! the same at both. That is the assertion worth making: a cost that does not grow with what the
//! grid holds is the property, and it is the same property on a slow machine as on a fast one.
//! Nothing here asserts a clock, and the one test that prints times asserts nothing at all.
use super::*;
use crate::core::identity::{PrincipalKind, Role};
use crate::core::realm::{Capability, RealmKind};
use crate::core::work::{Commitment, Kind, Lease, Resources, Workload};
use crate::core::{approval::Verdict, identity::Action, Core};

fn key() -> String {
    "b".repeat(64)
}

fn big() -> Resources {
    Resources { cpu: 64.0, memory_gb: 512.0, disk_gb: 4_000.0, gpu: false, vram_gb: 0.0 }
}

fn small() -> Resources {
    Resources { cpu: 1.0, memory_gb: 1.0, disk_gb: 1.0, gpu: false, vram_gb: 0.0 }
}

/// A realm with `hosts` computers offering room and `leases` reservations already granted.
///
/// The reservations are written straight through the store, in one transaction, because the point
/// of the fixture is the size of the table and going through the whole of `submit` and
/// `grant_lease` for each of them would make the fixture itself the slowest thing in the suite.
fn grid_of(folder: &std::path::Path, hosts: usize, leases: usize, now: i64) -> (Core, Vec<String>) {
    let mut core = Core::create(&folder.join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let mut offered = Vec::new();
    for at in 0..hosts {
        let (device, _) = core.enrol_device(&person.id, &format!("computer {at}"), "linux", now).unwrap();
        let host = core.offer_host(&device.id, &format!("computer {at}"), big(), big(), Commitment::Share, now).unwrap();
        offered.push(host.id);
    }
    // Reservations that have already been given back: they are the record of what work was tried
    // on, they are never deleted, and they are exactly what used to be read in full.
    let realm_id = core.realm().id.clone();
    let device = core.snapshot().unwrap().devices[0].id.clone();
    let store = core.store_for_tests();
    store
        .in_one_change(|change| {
            let mut work_id = String::new();
            for at in 0..leases {
                // One piece of work for every hundred reservations, which is roughly the shape a
                // grid reaches: work is retried a few times and the reservations outlive it.
                if at % 100 == 0 {
                    let mut work = Workload::new(&realm_id, Capability::Models, Kind::Inference, &person.id, &device, small(), 1, now - 2_000);
                    work.id = format!("work-old-{at}");
                    work.stage = crate::core::work::Stage::Completed;
                    crate::core::store::Store::write_workload(change, &work)?;
                    work_id = work.id.clone();
                }
                let lease = Lease {
                    id: format!("lease-old-{at}"),
                    realm_id: realm_id.clone(),
                    host_id: offered[at % offered.len()].clone(),
                    workload_id: work_id.clone(),
                    resources: small(),
                    generation: 1,
                    granted_at: now - 1_000,
                    expires_at: now - 500,
                    released_at: Some(now - 400),
                };
                crate::core::store::Store::write_lease(change, &lease)?;
            }
            Ok(())
        })
        .unwrap();
    (core, offered)
}

fn queued(core: &mut Core, person: &str, device: &str, now: i64) -> String {
    let work = Workload::new(&core.realm().id.clone(), Capability::Models, Kind::Inference, person, device, small(), 1, now);
    core.submit(work, now).unwrap().id
}

#[test]
fn one_reservation_costs_the_same_number_of_queries_whatever_the_grid_holds() {
    let now = 90_000;
    let small_folder = tempfile::tempdir().unwrap();
    let large_folder = tempfile::tempdir().unwrap();
    let (mut smaller, _) = grid_of(small_folder.path(), 2, 20, now);
    let (mut larger, _) = grid_of(large_folder.path(), 16, 4_000, now);

    let measure = |core: &mut Core| -> Cost {
        let person = core.snapshot().unwrap().principals[0].id.clone();
        let device = core.snapshot().unwrap().devices[0].id.clone();
        let work = queued(core, &person, &device, now);
        let meter = Meter::on(core.store_for_tests());
        core.grant_lease(&work, 60, now).unwrap();
        let cost = Cost { statements: meter.statements(), rows: meter.rows() };
        drop(meter);
        cost
    };
    let cheap = measure(&mut smaller);
    let dear = measure(&mut larger);

    // Eight times the computers and two hundred times the reservations, and the same work.
    assert_eq!(
        cheap.statements, dear.statements,
        "granting one reservation must not cost more because the grid holds more: {} statements at 2 computers and 20 reservations, {} at 16 and 4000",
        cheap.statements, dear.statements
    );
    assert!(dear.rows < 400, "and it must not read every reservation in the grid: {} rows", dear.rows);
}

#[test]
fn a_question_about_one_computer_never_reads_every_reservation() {
    let folder = tempfile::tempdir().unwrap();
    let now = 90_000;
    let (core, hosts) = grid_of(folder.path(), 4, 2_000, now);
    let (free, cost) = cost_of(core.store_for_tests(), || core.free_on(&hosts[0], now));
    assert!(free.is_some());
    // The host row and what is reserved on it. Nothing else.
    assert_eq!(cost.statements, 2, "what one computer has free is two statements");
    assert!(cost.rows <= 2, "and it reads the one host row, not two thousand reservations: {} rows", cost.rows);
}

#[test]
fn deciding_a_request_does_not_read_every_account_in_the_grid() {
    let now = 120_000;
    let cost_at = |people: usize| -> Cost {
        let folder = tempfile::tempdir().unwrap();
        let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
        let asker = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::CredentialAdmin], now).unwrap();
        let approver = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialApprover], now).unwrap();
        for at in 0..people {
            core.add_principal("owner", PrincipalKind::Person, &format!("person {at}"), &[Role::User], now).unwrap();
        }
        let request = core.ask(&asker.id, Action::ApproveCredential, "credential-1", None, false, 600, now).unwrap();
        let meter = Meter::on(core.store_for_tests());
        core.decide(&request.id, Action::ApproveCredential, &approver.id, Verdict::Once, now).unwrap();
        let cost = Cost { statements: meter.statements(), rows: meter.rows() };
        drop(meter);
        core.close().unwrap();
        cost
    };
    let few = cost_at(2);
    let many = cost_at(200);
    assert_eq!(few.statements, many.statements, "deciding costs {} statements with 4 people and {} with 202", few.statements, many.statements);
    assert!(many.rows < 60, "and does not read every account: {} rows", many.rows);
}

#[test]
fn whether_anybody_else_could_agree_is_the_same_answer_the_people_in_the_grid_give() {
    // The query that replaced `other_approvers` must answer exactly what it answered, including
    // that a suspended approver has never counted.
    let folder = tempfile::tempdir().unwrap();
    let now = 130_000;
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let asker = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::CredentialAdmin], now).unwrap();
    let roles = crate::core::approval::approving_roles(Action::ApproveCredential);
    let both = |core: &Core, besides: &str| -> (bool, bool) {
        let people = core.store_for_tests().principals().unwrap();
        let by_hand = !crate::core::approval::other_approvers(&people, Action::ApproveCredential, besides).is_empty();
        (by_hand, core.store_for_tests().another_holder_of(&roles, besides).unwrap())
    };

    let (by_hand, by_query) = both(&core, &asker.id);
    assert_eq!((by_hand, by_query), (false, false), "nobody else may approve yet");

    let approver = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialApprover], now).unwrap();
    let (by_hand, by_query) = both(&core, &asker.id);
    assert_eq!((by_hand, by_query), (true, true), "and now somebody may");

    core.suspend_principal("owner", &approver.id, "on leave", now).unwrap();
    let (by_hand, by_query) = both(&core, &asker.id);
    assert_eq!((by_hand, by_query), (false, false), "a suspended approver has never counted, and the query must not start counting one");

    // And an administrator counts, because administering brings the approving permission with it
    // as a permission of its own.
    let admin = core.add_principal("owner", PrincipalKind::Person, "Hopper", &[Role::RealmAdmin], now).unwrap();
    let (by_hand, by_query) = both(&core, &asker.id);
    assert_eq!((by_hand, by_query), (true, true), "a realm administrator holds the approving permission in its own right");
    assert!(both(&core, &admin.id).0 == both(&core, &admin.id).1, "and the two agree whoever is asking");
}

#[test]
fn recording_what_happened_costs_the_same_statements_whatever_the_history_holds() {
    // Both sizes here are well under `audit::KEEP`, so neither reaches the trim branch at all.
    // That is deliberate: this is the ordinary write, and what it shows is that the ordinary
    // write does not grow. Whether the trim branch still counts the history is a different
    // property, which the statement counter cannot see and
    // `a_history_past_what_it_keeps_is_still_trimmed_without_counting_it_every_time` asserts on
    // the statements themselves.
    let folder = tempfile::tempdir().unwrap();
    let now = 140_000;
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let cost_after = |core: &mut Core, events: usize| -> Cost {
        for at in 0..events {
            core.grant("owner", &person.id, Role::Auditor, now + at as i64).unwrap();
            core.withdraw("owner", &person.id, Role::Auditor, now + at as i64).unwrap();
        }
        let meter = Meter::on(core.store_for_tests());
        core.grant("owner", &person.id, Role::Auditor, now).unwrap();
        let cost = Cost { statements: meter.statements(), rows: meter.rows() };
        drop(meter);
        core.withdraw("owner", &person.id, Role::Auditor, now).unwrap();
        cost
    };
    let early = cost_after(&mut core, 10);
    let later = cost_after(&mut core, 400);
    assert_eq!(early.statements, later.statements, "writing one event costs {} statements with 20 events behind it and {} with 820", early.statements, later.statements);
    assert!(later.rows < 40, "and it does not walk the history: {} rows", later.rows);
}

#[test]
fn the_sweep_gives_back_only_the_reservations_that_have_run_out() {
    // Five reservations are due and the rest were given back long ago. What this shows is that
    // the sweep hands back those five and nothing else, at two sizes of grid: the number does not
    // move when the table grows by an order of magnitude, so the sweep is not materialising the
    // reservations.
    //
    // What it does not show is which index SQLite chose. The meter counts rows a statement gave
    // back, never rows SQLite read, so a whole-table scan that matches five rows counts five here
    // exactly as a range over `leases_live_by_expiry` does. The ignored load shape prints the
    // plan for the sweep's own statement, which is where a person can see that.
    let now = 150_000;
    let swept = |leases: usize| -> (usize, u64) {
        let folder = tempfile::tempdir().unwrap();
        let (mut core, hosts) = grid_of(folder.path(), 4, leases, now);
        let realm_id = core.realm().id.clone();
        let store = core.store_for_tests();
        store
            .in_one_change(|change| {
                for at in 0..5 {
                    crate::core::store::Store::write_lease(
                        change,
                        &Lease {
                            id: format!("lease-due-{at}"),
                            realm_id: realm_id.clone(),
                            host_id: hosts[at % hosts.len()].clone(),
                            workload_id: "work-old-0".to_owned(),
                            resources: small(),
                            generation: 1,
                            granted_at: now - 100,
                            expires_at: now - 10,
                            released_at: None,
                        },
                    )?;
                }
                Ok(())
            })
            .unwrap();
        let (_, cost) = cost_of(core.store_for_tests(), || ());
        assert_eq!(cost.statements, 0, "the meter starts at nought");
        let meter = Meter::on(core.store_for_tests());
        let acted = core.expire(now);
        let rows = meter.rows();
        drop(meter);
        core.close().unwrap();
        (acted, rows)
    };
    let (acted_small, rows_small) = swept(300);
    let (acted_large, rows_large) = swept(3_000);
    assert_eq!((acted_small, acted_large), (5, 5), "five reservations were due in each grid and nothing else was");
    assert_eq!(rows_large, rows_small, "a sweep gave back {rows_small} rows at 300 reservations and {rows_large} at 3000");
    assert!(rows_large < 50, "a sweep of a grid holding 3000 reservations gave back {rows_large} rows");
}

#[test]
fn the_health_check_touches_a_handful_of_rows_and_never_reads_the_history() {
    let folder = tempfile::tempdir().unwrap();
    let now = 160_000;
    let (core, _) = grid_of(folder.path(), 4, 2_000, now);
    let (checkup, cost) = cost_of(core.store_for_tests(), || core.healthy());
    assert!(checkup.alive());
    assert_eq!(cost.statements, 4, "liveness is four statements: does it answer, what shape is it, what is it doing, where did the history get to");
    assert!(cost.rows <= 4, "and four rows: {} rows", cost.rows);
}

#[test]
fn a_reading_costs_the_same_whatever_the_grid_holds() {
    let now = 170_000;
    let cost_at = |hosts: usize, leases: usize| -> (Cost, u64) {
        let folder = tempfile::tempdir().unwrap();
        let (core, _) = grid_of(folder.path(), hosts, leases, now);
        let (reading, cost) = cost_of(core.store_for_tests(), || core.reading(now).unwrap());
        assert_eq!(reading.hosts.offering, hosts);
        let rows = cost.rows;
        core.close().unwrap();
        (cost, rows)
    };
    let (cheap, _) = cost_at(2, 50);
    let (dear, rows) = cost_at(16, 4_000);
    assert_eq!(cheap.statements, dear.statements, "a reading is {} statements at 2 computers and {} at 16", cheap.statements, dear.statements);
    assert!(rows < 200, "and every number in it comes from a count or an aggregate: {rows} rows at 4000 reservations");
}

/// A realm with one workspace and `parcels` packed copies of it that nobody has taken.
///
/// That is the shape `workspace_artifacts` actually reaches: there is no uniqueness per workspace,
/// nothing deletes from the table, and a workspace packed again writes another row. The copies are
/// written straight through the store for the same reason the reservations are in `grid_of`.
fn grid_with_parcels(folder: &std::path::Path, parcels: usize, now: i64) -> Core {
    use crate::core::workspace::{Access, Artifact, ArtifactStore, Image, ImageSource, Quota, WorkspaceKind};
    let mut core = Core::create(&folder.join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::RealmAdmin], now).unwrap();
    let (device, _) = core.enrol_device(&admin.id, "Studio PC", "windows", now).unwrap();
    let host = core.offer_host(&device.id, "Studio PC", big(), big(), Commitment::Share, now).unwrap();
    let realm_id = core.realm().id.clone();
    let image = Image::new(
        &realm_id,
        "Ubuntu",
        "24.04",
        WorkspaceKind::Container,
        None,
        ImageSource::Oci { reference: "docker.io/library/ubuntu:24.04".to_owned() },
        Resources { cpu: 1.0, memory_gb: 2.0, disk_gb: 5.0, gpu: false, vram_gb: 0.0 },
        &admin.id,
        now,
    )
    .unwrap();
    let image = core.publish_image(&admin.id, image, now).unwrap();
    let workspace = core.order_workspace(&admin.id, "Ada's desk", &image.id, Access::Standard, Quota::for_disk(10.0).unwrap(), None, now).unwrap();
    let store = core.store_for_tests();
    store
        .in_one_change(|_| {
            for at in 0..parcels {
                store.put_artifact(&Artifact {
                    id: format!("parcel-{at}"),
                    realm_id: realm_id.clone(),
                    workspace_id: workspace.id.clone(),
                    workspace_generation: 1,
                    store: ArtifactStore::Hub,
                    destination: String::new(),
                    object_key: format!("parcel-{at}"),
                    bytes: 1,
                    sha256: "a".repeat(64),
                    packed_by: host.id.clone(),
                    // Older than `PARCEL_PATIENCE`, which is what makes a packed copy stuck.
                    packed_at: now - 2 * crate::core::workspace::PARCEL_PATIENCE,
                    taken_at: None,
                    removed_at: None,
                })?;
            }
            Ok(())
        })
        .unwrap();
    core
}

#[test]
fn a_reading_does_not_carry_back_a_row_for_every_packed_copy_ever_made() {
    // `grid_of` holds no workspace and no packed copy, so the reading measured there never
    // touched the one statement in a reading whose cost grew with what the realm had done. This
    // is that statement: the number of packed copies nobody has taken, which used to be answered
    // by building every one of them and taking the length of the list.
    let now = 180_000;
    let cost_at = |parcels: usize| -> Cost {
        let folder = tempfile::tempdir().unwrap();
        let core = grid_with_parcels(folder.path(), parcels, now);
        let (reading, cost) = cost_of(core.store_for_tests(), || core.reading(now).unwrap());
        assert_eq!(reading.workspaces.stuck_parcels, parcels, "every packed copy here is still waiting");
        core.close().unwrap();
        cost
    };
    let few = cost_at(2);
    let many = cost_at(400);
    assert_eq!(few.statements, many.statements, "a reading is {} statements with 2 packed copies waiting and {} with 400", few.statements, many.statements);
    assert_eq!(few.rows, many.rows, "a reading gave back {} rows with 2 packed copies waiting and {} with 400", few.rows, many.rows);
}

/// The load shape. Ignored on purpose: it builds a realm at the published sizes, runs the
/// measurements and prints what it found. It asserts nothing, because the numbers it prints
/// depend on the machine, and a test that asserted them would fail on a slower one.
///
/// Run it with `cargo test -p yougori-grid --lib -- --ignored --nocapture grid_core_load_shape`,
/// and paste what it prints into docs/grid-core/operations.md with the date and the machine.
#[test]
#[ignore]
fn grid_core_load_shape() {
    use crate::core::limits;
    let folder = tempfile::tempdir().unwrap();
    let now = 200_000;
    let began = std::time::Instant::now();
    let (mut core, hosts) = grid_of(folder.path(), limits::MAX_HOSTS, 50_000, now);
    println!("built {} computers and 50000 reservations in {:?}", hosts.len(), began.elapsed());

    let person = core.snapshot().unwrap().principals[0].id.clone();
    let device = core.snapshot().unwrap().devices[0].id.clone();
    let work = queued(&mut core, &person, &device, now);
    let began = std::time::Instant::now();
    let meter = Meter::on(core.store_for_tests());
    core.grant_lease(&work, 60, now).unwrap();
    println!("one reservation: {} statements, {} rows, {:?}", meter.statements(), meter.rows(), began.elapsed());
    drop(meter);

    let began = std::time::Instant::now();
    let meter = Meter::on(core.store_for_tests());
    let reading = core.reading(now).unwrap();
    println!("one reading: {} statements, {} rows, {:?}", meter.statements(), meter.rows(), began.elapsed());
    drop(meter);
    println!("counts: {:?}", reading.counts);

    let began = std::time::Instant::now();
    let meter = Meter::on(core.store_for_tests());
    core.expire(now);
    println!("one sweep: {} statements, {} rows, {:?}", meter.statements(), meter.rows(), began.elapsed());
    drop(meter);

    // The half the row counter cannot report: which index SQLite chose for the sweep. It is
    // printed and asserted on nowhere, because the plan text is SQLite's own wording and moves
    // with the bundled library, and a test that asserted it would fail on a dependency bump
    // rather than on a change to this code. A person running the load shape can read it.
    core.store_for_tests()
        .in_one_change(|change| {
            let mut plan = change
                .prepare("EXPLAIN QUERY PLAN SELECT id, workload_id FROM leases WHERE released_at IS NULL AND ?1 >= expires_at")
                .map_err(|error| error.to_string())?;
            let lines: Vec<String> = plan
                .query_map(rusqlite::params![now], |row| row.get::<_, String>(3))
                .map_err(|error| error.to_string())?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|error| error.to_string())?;
            println!("the sweep's plan: {}", lines.join("; "));
            Ok(())
        })
        .unwrap();

    let began = std::time::Instant::now();
    let meter = Meter::on(core.store_for_tests());
    core.reconcile_model_plans(now).unwrap();
    println!("one reconcile with no plans: {} statements, {} rows, {:?}", meter.statements(), meter.rows(), began.elapsed());
    drop(meter);

    let began = std::time::Instant::now();
    let record = core.snapshot().unwrap();
    println!("one snapshot of the whole realm: {:?}, {} reservations", began.elapsed(), record.leases.len());
}
