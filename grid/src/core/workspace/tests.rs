//! What the workspace profile must hold true.
//!
//! Each of these is a Phase 4 exit gate or one of the rules the profile is for: a workspace keeps
//! its owner when its computer dies, a placement that has been left behind can never reclaim it,
//! committing a computer is explicit and reversible and never means reading somebody's files, and
//! nothing that is inside a workspace is ever in the realm's database.
use super::*;
use crate::core::{
    capability::{Attempt, Authority},
    identity::{PrincipalKind, Role},
    realm::{Capability, Lifecycle, RealmKind},
    store,
    work::{self, Stage},
    Core,
};
use std::path::Path;

fn key() -> String {
    "d".repeat(64)
}

/// What a computer in these tests gives to the grid.
fn room() -> Resources {
    Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 200.0, gpu: false, vram_gb: 0.0 }
}

/// A grid that hosts workspaces: an administrator, a person with a workspace, and two computers
/// offering room, both committed and both reporting that they are well.
struct Company {
    core: Core,
    admin: String,
    person: String,
    /// The person's own computer, which they sign in from.
    device: String,
    first: String,
    first_device: String,
    second: String,
    second_device: String,
}

fn company(folder: &Path, now: i64) -> Company {
    let mut core = Core::create(&folder.join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::RealmAdmin], now).unwrap();
    let person = core.add_principal(&admin.id, PrincipalKind::Person, "Ada", &[Role::User], now).unwrap();
    let (laptop, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    let (first_device, _) = core.enrol_device(&admin.id, "Studio PC", "windows", now).unwrap();
    let (second_device, _) = core.enrol_device(&admin.id, "Render PC", "linux", now).unwrap();
    let first = core.offer_host(&first_device.id, "Studio PC", room(), room(), Commitment::Share, now).unwrap();
    let second = core.offer_host(&second_device.id, "Render PC", room(), room(), Commitment::Share, now + 1).unwrap();
    for (host, device) in [(&first.id, &first_device.id), (&second.id, &second_device.id)] {
        core.commit_host(&admin.id, host, Commitment::Share, room(), false, now).unwrap();
        core.report_condition(device, false, 500.0, false, false, now).unwrap();
    }
    Company {
        core,
        admin: admin.id,
        person: person.id,
        device: laptop.id,
        first: first.id,
        first_device: first_device.id,
        second: second.id,
        second_device: second_device.id,
    }
}

/// The image every container desk this product ships is built from: an OCI tag, with no digest
/// until a computer has fetched it.
fn ubuntu(core: &mut Core, by: &str, now: i64) -> Image {
    let shipped = crate::desks::DeskSpec::checked(crate::desks::DeskKind::Container, 2.0, 4.0, 10.0, false, "").unwrap();
    let image = Image::new(
        &core.realm().id,
        "Ubuntu",
        "24.04",
        WorkspaceKind::Container,
        None,
        ImageSource::Oci { reference: shipped.image.clone() },
        Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 10.0, gpu: false, vram_gb: 0.0 },
        by,
        now,
    )
    .unwrap();
    core.publish_image(by, image, now).unwrap()
}

fn quota() -> Quota {
    Quota::for_disk(10.0).unwrap()
}

/// What a computer must present to say anything about a workspace: both numbers and its own name.
fn claim_for(core: &Core, workspace_id: &str) -> Claim {
    let workspace = core.workspace(workspace_id).unwrap().unwrap();
    let placement = core.store.live_assignment(workspace_id).unwrap().unwrap();
    Claim::new(workspace_id, workspace.generation, placement.generation, &placement.host_id)
}

/// A workspace ordered for Ada, placed on the first computer and reported ready.
fn running(company: &mut Company, now: i64) -> String {
    let image = ubuntu(&mut company.core, &company.admin, now);
    let workspace = company.core.order_workspace(&company.admin, "Ada's desk", &image.id, Access::Standard, quota(), Some(&company.person), now).unwrap();
    company.core.place_workspace(&company.admin, &workspace.id, 3_600, now).unwrap();
    let claim = claim_for(&company.core, &workspace.id);
    company.core.report_workspace(&company.first_device, &claim, Report::new(Reported::Ready).built("env-1"), now).unwrap();
    workspace.id
}

fn plain_sha256(text: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|window| window == needle)
}

/// The journal beside a realm's database.
fn journal(path: &Path) -> std::path::PathBuf {
    std::path::PathBuf::from(format!("{}-wal", path.display()))
}

#[test]
fn a_workspace_is_ordered_placed_and_opened_and_the_shipped_image_fits_as_it_is() {
    let folder = tempfile::tempdir().unwrap();
    let now = 5_000;
    let mut company = company(folder.path(), now);

    // The product's own default image is an OCI tag with no digest. The realm records it as it
    // is, says so, and the identity is written down the first time a computer fetches the bytes.
    let image = ubuntu(&mut company.core, &company.admin, now);
    assert_eq!(image.source, ImageSource::Oci { reference: "docker.io/library/ubuntu:24.04".to_owned() });
    assert!(!image.pinned() && image.describe().ends_with("(not yet pinned)"));

    let workspace = company.core.order_workspace(&company.admin, "Ada's desk", &image.id, Access::Standard, quota(), Some(&company.person), now).unwrap();
    assert_eq!((workspace.state, workspace.generation), (WorkspaceState::Requested, 1));
    assert!(company.core.workspaces_of(&company.person).unwrap().iter().any(|held| held.id == workspace.id));

    let (work, lease, placement) = company.core.place_workspace(&company.admin, &workspace.id, 3_600, now).unwrap();
    assert_eq!((work.kind, work.stage, work.capability), (work::Kind::Workspace, Stage::Leased, Capability::Workspaces));
    assert_eq!((lease.host_id.as_str(), placement.generation, placement.workspace_generation), (company.first.as_str(), 1, 1));
    assert_eq!(company.core.workspace(&workspace.id).unwrap().unwrap().state, WorkspaceState::Provisioning);

    // The computer reports, pinning what it fetched, and the workspace is its person's.
    let claim = claim_for(&company.core, &workspace.id);
    let digest = format!("sha256:{}", plain_sha256("the ubuntu image"));
    let state = company.core.report_workspace(&company.first_device, &claim, Report::new(Reported::Ready).built("env-7").hashing(&digest), now + 1).unwrap();
    assert_eq!(state, WorkspaceState::Assigned);
    assert_eq!(company.core.image(&image.id).unwrap().unwrap().digest.as_deref(), Some(digest.as_str()));
    assert_eq!(company.core.workspace_placements(&workspace.id).unwrap()[0].placement_ref.as_deref(), Some("env-7"));

    // Ada opens it from her own computer. The permission names the piece of work that is running
    // the workspace, which is what `Authority::accept` is checked against.
    let token = company.core.open_workspace(&company.person, &company.device, &workspace.id, 600, now + 2).unwrap();
    let claims = Authority::peek(&token).expect("the permission can be read");
    assert_eq!((claims.capability, claims.resource_id.as_str(), claims.workload_id.as_str()), (Capability::Workspaces, workspace.id.as_str(), work.id.as_str()));
    assert_eq!(company.core.workspace(&workspace.id).unwrap().unwrap().state, WorkspaceState::Running);
    let realm = company.core.realm().id.clone();
    let attempt = Attempt { realm_id: &realm, device_id: &company.device, workload_id: &work.id, resource_id: &workspace.id, ..Attempt::default() };
    let (_, opened) = company.core.use_workspace(&token, &attempt, now + 3).unwrap();
    assert_eq!(opened.id, workspace.id);

    // Somebody else's computer cannot present it, and nor can it be used for another workspace.
    let elsewhere = Attempt { device_id: &company.first_device, ..attempt.clone() };
    assert!(company.core.use_workspace(&token, &elsewhere, now + 3).is_err());
}

#[test]
fn a_workspace_follows_one_lifecycle_and_an_archived_one_never_comes_back() {
    use WorkspaceState::*;
    let allowed = [
        (Requested, vec![Provisioning, Failed, Archived]),
        (Provisioning, vec![Ready, Assigned, Failed, Draining, Archived]),
        (Ready, vec![Assigned, Draining, Failed, Requested, Archived]),
        (Assigned, vec![Running, Ready, Draining, Failed, Requested, Archived]),
        (Running, vec![Assigned, Ready, Draining, Failed, Archived]),
        (Draining, vec![Requested, Ready, Archived, Failed]),
        (Failed, vec![Requested, Archived]),
        (Archived, Vec::new()),
    ];
    for (from, nexts) in &allowed {
        for to in [Requested, Provisioning, Ready, Assigned, Running, Draining, Archived, Failed] {
            assert_eq!(from.may_become(to), nexts.contains(&to), "{from:?} to {to:?}");
        }
    }
    assert!(Archived.finished() && !Failed.finished(), "a failed workspace can be asked for again; an archived one is done");
    assert!(Assigned.open_to_its_owner() && Running.open_to_its_owner());
    for shut in [Requested, Provisioning, Ready, Draining, Archived, Failed] {
        assert!(!shut.open_to_its_owner(), "{shut:?}");
    }
}

#[test]
fn a_placement_that_was_left_behind_can_never_reclaim_a_workspace_that_moved_on() {
    let folder = tempfile::tempdir().unwrap();
    let now = 6_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let before = claim_for(&company.core, &workspace);

    // The workspace is emptied, which moves it on a generation. The computer that was holding it
    // still believes what it believed a moment ago.
    company.core.reset_workspace(&company.admin, &workspace, "its person asked for a clean one", now + 1).unwrap();
    let after = company.core.workspace(&workspace).unwrap().unwrap();
    assert_eq!(after.generation, before.workspace_generation + 1);

    let refused = company.core.report_workspace(&company.first_device, &before, Report::new(Reported::Ready), now + 2).unwrap_err();
    assert!(refused.contains("superseded"), "{refused}");
    assert!(
        company.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "workspace.report.refused"),
        "and the refusal is in the record, so a computer can be told why"
    );

    // Equality, never "at least". A number below is a computer that has been left behind, and a
    // number above was never issued, so both are refused rather than one of them being tolerated.
    company.core.place_workspace(&company.admin, &workspace, 3_600, now + 3).unwrap();
    let now_placed = claim_for(&company.core, &workspace);
    let workspace_row = company.core.workspace(&workspace).unwrap().unwrap();
    let live = company.core.store.live_assignment(&workspace).unwrap().unwrap();
    assert!(now_placed.matches(&workspace_row, &live));
    for wrong in [
        Claim::new(&workspace, now_placed.workspace_generation - 1, now_placed.assignment_generation, &now_placed.host_id),
        Claim::new(&workspace, now_placed.workspace_generation + 1, now_placed.assignment_generation, &now_placed.host_id),
        Claim::new(&workspace, now_placed.workspace_generation, now_placed.assignment_generation - 1, &now_placed.host_id),
        Claim::new(&workspace, now_placed.workspace_generation, now_placed.assignment_generation + 1, &now_placed.host_id),
        Claim::new(&workspace, now_placed.workspace_generation, now_placed.assignment_generation, &company.second),
    ] {
        assert!(!wrong.matches(&workspace_row, &live), "{wrong:?}");
    }

    // The same comparison is made again inside the statement that writes, so a claim that was
    // true when it was read and false when it was written changes nothing.
    assert!(company.core.store.claim_placement(&now_placed, Some("env-9"), true, now + 4).unwrap());
    company.core.store.raise_workspace_generation(&workspace, now + 5).unwrap();
    assert!(!company.core.store.claim_placement(&now_placed, Some("env-10"), true, now + 6).unwrap(), "no rows changed is a refusal");
    assert_eq!(company.core.workspace_placements(&workspace).unwrap().last().unwrap().placement_ref.as_deref(), Some("env-9"));
}

#[test]
fn the_database_itself_refuses_a_reused_placement_number_a_falling_generation_and_an_early_delete() {
    let folder = tempfile::tempdir().unwrap();
    let now = 7_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let placement = company.core.store.live_assignment(&workspace).unwrap().unwrap();
    let path = company.core.path().to_owned();

    // An ordinary save rewrites every column, the generation among them, and must not abort:
    // SQLite fires a BEFORE UPDATE OF trigger whenever the column is named at all.
    let mut held = company.core.workspace(&workspace).unwrap().unwrap();
    held.note = "saved again with the same numbers".into();
    company.core.store.put_workspace(&held).unwrap();
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().note, "saved again with the same numbers");

    company.core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();

    let reused = connection.execute(
        "INSERT INTO workspace_assignments (id, realm_id, workspace_id, host_id, generation, workspace_gen, workload_id, placed_at)
         SELECT 'placement-again', realm_id, workspace_id, host_id, generation, workspace_gen, workload_id, placed_at FROM workspace_assignments WHERE id = ?1",
        rusqlite::params![placement.id],
    );
    assert!(format!("{reused:?}").contains("already used"), "{reused:?}");

    // A generation rises, and a number it has left behind can never come back.
    connection.execute("UPDATE workspaces SET generation = generation + 1 WHERE id = ?1", rusqlite::params![workspace]).unwrap();
    let standing = connection.execute("UPDATE workspaces SET generation = 2, note = 'an ordinary save' WHERE id = ?1", rusqlite::params![workspace]);
    assert!(standing.is_ok(), "a save that names the generation without changing it is not an abort: {standing:?}");
    let lowered = connection.execute("UPDATE workspaces SET generation = 1 WHERE id = ?1", rusqlite::params![workspace]);
    assert!(format!("{lowered:?}").contains("only rises"), "{lowered:?}");

    let early = connection.execute("DELETE FROM workspaces WHERE id = ?1", rusqlite::params![workspace]);
    assert!(format!("{early:?}").contains("archive this workspace"), "{early:?}");
}

#[test]
fn nothing_that_is_inside_a_workspace_is_ever_in_the_realms_database() {
    let folder = tempfile::tempdir().unwrap();
    let now = 8_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);

    // A workspace is packed up and moved. What the realm is told is where the packed file is and
    // what it hashes to; the file itself stays wherever the hub or the bucket put it.
    let inside = "Ada's private notes, which belong to Ada";
    company.core.move_workspace(&company.admin, &workspace, "its computer is going away", now + 1).unwrap();
    let claim = claim_for(&company.core, &workspace);
    let parcel = company
        .core
        .park_workspace(&company.first_device, &claim, ArtifactStore::Hub, "", &workspace, 4_096, &plain_sha256(inside), now + 2)
        .unwrap();
    assert_eq!(parcel.sha256, plain_sha256(inside));

    let path = company.core.path().to_owned();
    company.core.close().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    if journal(&path).exists() {
        bytes.extend(std::fs::read(journal(&path)).unwrap());
    }
    // This is provable for the one thing the test scripted, and that is what it claims: the
    // marker that stands for what is inside the workspace is not in the file, and the reference
    // and the checksum that stand for it are.
    assert!(!holds(&bytes, inside.as_bytes()), "what is inside a workspace never reaches the grid's database");
    assert!(holds(&bytes, plain_sha256(inside).as_bytes()), "only what it hashes to");
    assert!(holds(&bytes, workspace.as_bytes()), "and where to find it");

    // No column in this version is named for anything that could hold it, which is checked the
    // way the credentials table is checked rather than by trusting that nobody will add one.
    let connection = rusqlite::Connection::open(&path).unwrap();
    for table in ["workspace_images", "workspaces", "workspace_assignments", "workspace_artifacts", "workspace_sessions", "host_commitments", "host_conditions"] {
        let mut query = connection.prepare(&format!("SELECT name FROM pragma_table_info('{table}')")).unwrap();
        let columns: Vec<String> = query.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        for forbidden in ["path", "folder", "directory", "file", "filename", "contents", "content", "body", "blob", "payload", "home", "secret", "password", "value"] {
            assert!(!columns.iter().any(|column| column == forbidden), "{table} has no {forbidden}");
        }
    }

    // And the database refuses a key that is a place on somebody's computer, in each of the four
    // shapes one can take.
    for bad in ["/home/ada/desk.tar", "C:/Users/ada/desk.tar", "desks\\ada.tar", "parcels/../../etc/passwd"] {
        let refused = connection.execute(
            "INSERT INTO workspace_artifacts (id, realm_id, workspace_id, workspace_gen, store, object_key, bytes, sha256, packed_by, packed_at)
             SELECT 'parcel-bad', realm_id, workspace_id, workspace_gen, store, ?2, bytes, sha256, packed_by, packed_at FROM workspace_artifacts WHERE id = ?1",
            rusqlite::params![parcel.id, bad],
        );
        assert!(refused.is_err(), "a packed copy cannot be named {bad}");
    }
    // The same rule in Rust, so a caller hears it in words rather than as a database failure.
    for bad in ["/home/ada/desk.tar", "C:/Users/ada/desk.tar", "desks\\ada.tar", "parcels/../../etc/passwd"] {
        assert!(looks_like_a_path(bad), "{bad}");
    }
    assert!(!looks_like_a_path("acme/desks/workspace-1.tar"), "a key with folders in it is still a key");
    assert!(checked_placement_ref("env-1").is_ok() && checked_placement_ref("/var/lib/env-1").is_err());
}

#[test]
fn committing_a_computer_is_explicit_and_reversible_and_says_what_it_does_not_mean() {
    let folder = tempfile::tempdir().unwrap();
    let now = 9_000;
    let mut company = company(folder.path(), now);

    // Each of the three is a sentence somebody agreed to, and all three say that the grid may not
    // read what is on the computer.
    for commitment in [Commitment::Share, Commitment::Dedicated, Commitment::None] {
        let said = Pledge::wording_for(commitment, false);
        if commitment == Commitment::None {
            assert!(said.contains("runs nothing for the grid"));
        } else {
            assert!(said.contains("may not read your own files"), "{said}");
        }
    }
    assert!(Pledge::wording_for(Commitment::Dedicated, false).contains("the grid decides what runs on it"));
    assert!(Pledge::wording_for(Commitment::Share, true).contains("only while nobody is using the computer"));

    let pledge = company.core.commit_host(&company.admin, &company.first, Commitment::Dedicated, room(), false, now + 1).unwrap();
    assert_eq!(company.core.store.host(&company.first).unwrap().unwrap().commitment, Commitment::Dedicated);
    assert!(company.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "host.committed" && event.reason.contains("may not read your own files")));

    // A computer that offers again does not get to change what was agreed; that goes through
    // committing it, which records the new wording beside the old.
    company.core.offer_host(&company.first_device, "Studio PC", room(), room(), Commitment::None, now + 2).unwrap();
    assert_eq!(company.core.store.host(&company.first).unwrap().unwrap().commitment, Commitment::Dedicated, "the pledge stands, not what the computer last sent");

    // The record of what was agreed is never edited.
    let path = company.core.path().to_owned();
    let workspace = running(&mut company, now + 3);
    company.core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let edited = connection.execute("UPDATE host_commitments SET wording = 'anything at all' WHERE id = ?1", rusqlite::params![pledge.id]);
    assert!(format!("{edited:?}").contains("recorded as it was made"), "{edited:?}");
    drop(connection);

    // Taking it back is reversible and both halves stay: the computer stops taking work, what it
    // held moves off it, and what it is committed to becomes nothing.
    let mut core = Core::open(&path, &key()).unwrap();
    core.withdraw_commitment(&company.admin, &company.first, "its owner wants it back", now + 4).unwrap();
    let after = core.store.host(&company.first).unwrap().unwrap();
    assert_eq!((after.commitment, after.draining), (Commitment::None, true));
    assert!(!after.takes_work());
    assert_eq!(core.store.live_assignment(&workspace).unwrap(), None, "what it held is off it");
    let said = core.commitments(&company.first).unwrap();
    assert_eq!(said.len(), 2, "what was agreed and what replaced it are both there");
    assert!(said.iter().all(|pledge| !pledge.standing()), "and neither of them stands now");
    assert!(core.withdraw_commitment(&company.admin, &company.first, "again", now + 5).unwrap_err().contains("no commitment to take back"));
}

#[test]
fn a_computer_on_battery_short_of_disk_going_away_or_back_in_use_takes_no_workspace() {
    let folder = tempfile::tempdir().unwrap();
    let now = 10_000;
    let mut company = company(folder.path(), now);
    let shared = Pledge::new("realm-1", "host-1", Commitment::Share, room(), false, "owner", now);
    let idle_only = Pledge::new("realm-1", "host-1", Commitment::Share, room(), true, "owner", now);
    let well = Condition::new("host-1", false, 500.0, false, false, now);

    assert_eq!(may_take(Some(&shared), Some(&well)), None);
    assert_eq!(may_take(None, Some(&well)), Some("this computer has not been committed to the grid"));
    assert_eq!(may_take(Some(&shared), None), Some("this computer has not said how it is"));
    assert_eq!(may_take(Some(&Pledge::new("realm-1", "host-1", Commitment::None, room(), false, "owner", now)), Some(&well)), Some("this computer runs nothing for the grid"));
    assert_eq!(may_take(Some(&shared), Some(&Condition::new("host-1", false, 500.0, false, true, now))), Some("this computer is about to stop hosting"));
    assert_eq!(may_take(Some(&shared), Some(&Condition::new("host-1", true, 500.0, false, false, now))), Some("this computer is on battery"));
    assert_eq!(
        may_take(Some(&shared), Some(&Condition::new("host-1", false, crate::power::KEEP_FREE_DISK_GB - 1.0, false, false, now))),
        Some("this computer is nearly out of disk")
    );
    assert_eq!(
        may_take(Some(&idle_only), Some(&Condition::new("host-1", false, 500.0, true, false, now))),
        Some("its person is using it, and the grid takes it only while nobody is using it")
    );
    assert_eq!(may_take(Some(&shared), Some(&Condition::new("host-1", false, 500.0, true, false, now))), None, "being in use matters only where the admin said so");

    // A computer that says so gives up what it is holding, which is the same rule in the other
    // direction.
    assert!(gives_up(Some(&shared), Some(&Condition::new("host-1", false, 500.0, false, true, now))));
    assert!(gives_up(Some(&idle_only), Some(&Condition::new("host-1", false, 500.0, true, false, now))));
    assert!(!gives_up(Some(&shared), Some(&well)) && !gives_up(Some(&idle_only), Some(&well)));

    // And placement obeys it, with words somebody can act on.
    let image = ubuntu(&mut company.core, &company.admin, now);
    let workspace = company.core.order_workspace(&company.admin, "Ada's desk", &image.id, Access::Standard, quota(), Some(&company.person), now).unwrap();
    company.core.report_condition(&company.first_device, true, 500.0, false, false, now).unwrap();
    company.core.report_condition(&company.second_device, false, 2.0, false, false, now).unwrap();
    let refused = company.core.place_workspace(&company.admin, &workspace.id, 3_600, now).unwrap_err();
    assert!(refused.contains("on battery") || refused.contains("nearly out of disk"), "{refused}");
    assert!(company.core.snapshot().unwrap().workloads.is_empty(), "a placement that is refused leaves no piece of work behind");

    company.core.report_condition(&company.first_device, false, 500.0, false, false, now + 1).unwrap();
    let (_, lease, _) = company.core.place_workspace(&company.admin, &workspace.id, 3_600, now + 1).unwrap();
    assert_eq!(lease.host_id, company.first);
}

#[test]
fn a_workspace_keeps_its_owner_when_its_computer_dies_and_waits_where_its_data_can_be_found() {
    let folder = tempfile::tempdir().unwrap();
    let now = 11_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 1).unwrap();

    // The only computer that has ever held it stops answering. Its owner, its image and its trail
    // are all still there, and the record says plainly that the data went with the computer.
    let affected = company.core.host_lost(&company.admin, &company.first, "the computer stopped answering", now + 2).unwrap();
    assert_eq!(affected, vec![workspace.clone()]);
    let after = company.core.workspace(&workspace).unwrap().unwrap();
    assert_eq!((after.state, after.owner_id.as_deref()), (WorkspaceState::Failed, Some(company.person.as_str())));
    assert_eq!(company.core.workspace_trail(&workspace).unwrap(), vec![company.first.clone()]);
    assert!(company.core.workspace_sessions(&workspace).unwrap().iter().all(|session| session.ended_at.is_some()), "and nobody is still in it");
    assert!(company
        .core
        .snapshot().unwrap()
        .audit
        .events
        .iter()
        .any(|event| event.action == "workspace.host_lost" && event.reason.contains("failed")));

    // With its data packed up, or with another computer that has held it still in the grid, it
    // waits for a computer instead of failing.
    company.core.advance_workspace(&company.admin, &workspace, WorkspaceState::Requested, "trying again", now + 3).unwrap();
    company.core.report_condition(&company.second_device, false, 500.0, false, false, now + 3).unwrap();
    company.core.place_workspace(&company.admin, &workspace, 3_600, now + 3).unwrap();
    let claim = claim_for(&company.core, &workspace);
    company.core.report_workspace(&company.second_device, &claim, Report::new(Reported::Ready).built("env-2"), now + 4).unwrap();
    company.core.host_lost(&company.admin, &company.second, "that one stopped too", now + 5).unwrap();
    let after = company.core.workspace(&workspace).unwrap().unwrap();
    assert_eq!(after.state, WorkspaceState::Requested, "another computer on its trail is still here");
    assert_eq!(company.core.workspace_trail(&workspace).unwrap(), vec![company.second.clone(), company.first.clone()]);

    // Taking a computer out of the grid does the same thing, through the same path.
    company.core.advance_workspace(&company.admin, &workspace, WorkspaceState::Failed, "stuck", now + 6).unwrap();
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().owner_id.as_deref(), Some(company.person.as_str()));
    company.core.revoke_device(&company.admin, &company.first_device, now + 7).unwrap();
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().owner_id.as_deref(), Some(company.person.as_str()), "a computer leaving never takes the owner with it");
}

#[test]
fn a_workspace_moves_between_computers_with_its_data_and_goes_back_where_that_data_is() {
    let folder = tempfile::tempdir().unwrap();
    let now = 12_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);

    // A move is ordinary work with the one Stage machine, and it is placed on the computer that
    // holds the data, whichever way the reservation is asked for.
    let moving = company.core.move_workspace(&company.admin, &workspace, "its computer is going away", now + 1).unwrap();
    assert_eq!((moving.kind, moving.stage), (work::Kind::ArtifactTransfer, Stage::Leased));
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().state, WorkspaceState::Draining, "it keeps running for its person until the copy is done");

    // The computer packs it and says where it put it and what it hashes to.
    let claim = claim_for(&company.core, &workspace);
    let parcel = company
        .core
        .park_workspace(&company.first_device, &claim, ArtifactStore::Bucket, "s3://acme-desks/parcels", "parcels/ada.tar", 2_048, &plain_sha256("ada"), now + 2)
        .unwrap();
    assert_eq!((parcel.store, parcel.destination.as_str()), (ArtifactStore::Bucket, "s3://acme-desks/parcels"));
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().state, WorkspaceState::Requested);
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap(), None);

    // It goes to a computer that has held it if one still fits, and otherwise anywhere with room.
    company.core.report_condition(&company.first_device, false, 2.0, false, false, now + 3).unwrap();
    company.core.place_workspace(&company.admin, &workspace, 3_600, now + 3).unwrap();
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap().unwrap().host_id, company.second, "the first one is short of disk");

    // The computer taking it over is handed the key and the checksum, and nothing else.
    let taking = claim_for(&company.core, &workspace);
    let handed = company.core.adopt_workspace(&company.second_device, &taking, now + 4).unwrap();
    assert_eq!((handed.object_key.as_str(), handed.sha256.as_str()), ("parcels/ada.tar", plain_sha256("ada").as_str()));
    assert!(company.core.adopt_workspace(&company.second_device, &taking, now + 5).unwrap_err().contains("no packed copy waiting"), "a packed copy is handed over once");
    company.core.report_workspace(&company.second_device, &taking, Report::new(Reported::Adopted).built("env-3"), now + 5).unwrap();
    company.core.report_workspace(&company.second_device, &taking, Report::new(Reported::Ready).built("env-3"), now + 6).unwrap();
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().state, WorkspaceState::Assigned);

    // And now its trail leads back to both computers, newest first.
    assert_eq!(company.core.workspace_trail(&workspace).unwrap(), vec![company.second.clone(), company.first.clone()]);
    company.core.report_condition(&company.first_device, false, 500.0, false, false, now + 7).unwrap();
    company.core.reset_workspace(&company.admin, &workspace, "a clean one", now + 7).unwrap();
    company.core.place_workspace(&company.admin, &workspace, 3_600, now + 8).unwrap();
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap().unwrap().host_id, company.second, "a workspace goes back where its data already is");
}

#[test]
fn a_revoked_person_cannot_reopen_their_workspace() {
    let folder = tempfile::tempdir().unwrap();
    let now = 13_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let work = company.core.store.live_assignment(&workspace).unwrap().unwrap().workload_id;
    let token = company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 1).unwrap();
    let realm = company.core.realm().id.clone();
    let attempt = Attempt { realm_id: &realm, device_id: &company.device, workload_id: &work, resource_id: &workspace, ..Attempt::default() };
    assert!(company.core.use_workspace(&token, &attempt, now + 2).is_ok());

    // Suspending the account stops it at once: the permission they are holding is refused from
    // their own row rather than from anything the token says, and they cannot be given another.
    company.core.suspend_principal(&company.admin, &company.person, "they left the company", now + 3).unwrap();
    let refused = company.core.use_workspace(&token, &attempt, now + 4).unwrap_err();
    assert!(refused.contains("no longer in this grid"), "{refused}");
    assert!(company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 4).unwrap_err().contains("suspended"));
    assert!(company.core.workspace_sessions(&workspace).unwrap().iter().all(|session| session.ended_at.is_some()));
    assert!(company.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "capability.refused"));
    // The workspace itself keeps its owner: suspending somebody is not deleting their desk.
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().owner_id.as_deref(), Some(company.person.as_str()));

    // Taking the permission to use a workspace away does the same, and it reaches the sign-in
    // they are already holding as well as the next one they ask for. Nothing re-reads a person's
    // roles at the moment a permission is used, so what refuses this one is that the workspace
    // moved on a generation, which is the mechanism a suspension uses too.
    company.core.store.restore_principal(&company.person).unwrap();
    let held = company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 5).unwrap();
    assert!(company.core.use_workspace(&held, &attempt, now + 5).is_ok(), "she is in her desk when the permission is taken away");
    company.core.withdraw(&company.admin, &company.person, Role::User, now + 5).unwrap();
    let refused = company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 6).unwrap_err();
    assert!(refused.contains("may not use workspace"), "{refused}");
    let refused = company.core.use_workspace(&held, &attempt, now + 6).unwrap_err();
    assert!(refused.contains("no longer in this grid"), "{refused}");
    assert!(company.core.workspace_sessions(&workspace).unwrap().iter().all(|session| session.ended_at.is_some()), "and she is out of it rather than asked to leave next time");

    // A withdrawal that leaves them able to use a workspace throws nobody out of a desk.
    company.core.grant(&company.admin, &company.person, Role::User, now + 6).unwrap();
    company.core.grant(&company.admin, &company.person, Role::Auditor, now + 6).unwrap();
    let still = company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 6).unwrap();
    company.core.withdraw(&company.admin, &company.person, Role::Auditor, now + 7).unwrap();
    assert!(company.core.use_workspace(&still, &attempt, now + 7).is_ok(), "taking back the auditor's role is not taking back her desk");
    company.core.close_workspace_sessions(&company.admin, &workspace, "the day ended", now + 7).unwrap();

    // And a workspace that has changed hands refuses what was handed out before it did, through
    // the one mechanism that refuses a suspended account, not through a check beside it.
    company.core.grant(&company.admin, &company.person, Role::User, now + 7).unwrap();
    let other = company.core.add_principal(&company.admin, PrincipalKind::Person, "Alan", &[Role::User], now + 7).unwrap();
    let token = company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 8).unwrap();
    let claims = Authority::peek(&token).unwrap();
    company.core.assign_workspace(&company.admin, &workspace, Some(&company.person), Some(&other.id), Data::Reset, now + 9).unwrap();
    assert_eq!(company.core.store.check_capability(&claims, now + 10).unwrap(), Some(store::Stale::Withdrawn), "the workspace moved on and the permission with it");
    assert!(company.core.use_workspace(&token, &attempt, now + 10).is_err());
}

#[test]
fn a_workspace_nobody_owns_keeps_its_data_and_nobody_may_open_it() {
    let folder = tempfile::tempdir().unwrap();
    let now = 14_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 1).unwrap();
    let placement = company.core.store.live_assignment(&workspace).unwrap().unwrap();

    // Taking it away from its person leaves it running, with its data, and shut to everybody.
    let after = company.core.assign_workspace(&company.admin, &workspace, Some(&company.person), None, Data::Keep, now + 2).unwrap();
    assert_eq!((after.state, after.owner_id), (WorkspaceState::Ready, None));
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap().unwrap().id, placement.id, "its data is untouched");
    assert!(company.core.workspace_sessions(&workspace).unwrap().iter().all(|session| session.ended_at.is_some()));
    assert!(company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 3).unwrap_err().contains("not theirs"));
    assert!(company.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "workspace.access.revoked"));

    // A stale page cannot hand the wrong person's workspace on.
    let wrong = company.core.assign_workspace(&company.admin, &workspace, Some(&company.person), Some(&company.person), Data::Keep, now + 4).unwrap_err();
    assert!(wrong.contains("belongs to nobody now"), "{wrong}");

    // And the database itself refuses a workspace that nobody owns being in a state that lets
    // somebody in, whichever way somebody tries to put it there.
    let mut held = company.core.workspace(&workspace).unwrap().unwrap();
    assert!(held.advance(WorkspaceState::Assigned, "", now + 5).unwrap_err().contains("Nobody owns this workspace"));
    held.state = WorkspaceState::Assigned;
    assert!(company.core.store.put_workspace(&held).is_err(), "and the database says the same thing");
}

#[test]
fn the_sandbox_controls_reset_rebuild_revoke_archive_and_export() {
    let folder = tempfile::tempdir().unwrap();
    let now = 15_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let first_image = company.core.workspace(&workspace).unwrap().unwrap().image_id;

    // Reset: the person keeps the workspace and everything in it goes.
    company
        .core
        .park_workspace(&company.first_device, &claim_for(&company.core, &workspace), ArtifactStore::Hub, "", &workspace, 512, &plain_sha256("x"), now + 1)
        .unwrap();
    company.core.place_workspace(&company.admin, &workspace, 3_600, now + 2).unwrap();
    let after = company.core.reset_workspace(&company.admin, &workspace, "its person asked", now + 3).unwrap();
    assert_eq!((after.state, after.reset_count, after.attempts), (WorkspaceState::Requested, 1, 0));
    assert!(company.core.store.waiting_artifact(&workspace).unwrap().is_none(), "nothing of it is waiting anywhere");
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap(), None);

    // Rebuild from another image: the digest the record names changes with it.
    let other = Image::new(
        &company.core.realm().id,
        "Ubuntu with tools",
        "24.04",
        WorkspaceKind::Container,
        Some(&format!("sha256:{}", plain_sha256("another image"))),
        ImageSource::Oci { reference: "docker.io/acme/tools@sha256:abc".to_owned() },
        Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 10.0, gpu: false, vram_gb: 0.0 },
        &company.admin,
        now + 3,
    )
    .unwrap();
    let other = company.core.publish_image(&company.admin, other, now + 3).unwrap();
    let rebuilt = company.core.rebuild_workspace(&company.admin, &workspace, &other.id, Data::Keep, now + 4).unwrap();
    assert_eq!((rebuilt.image_id.as_str(), rebuilt.image_digest.as_deref()), (other.id.as_str(), other.digest.as_deref()));
    assert_ne!(rebuilt.image_id, first_image);
    assert!(company.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "workspace.rebuilt" && event.reason.contains("the data was kept")));

    // An image whose disk does not fit the workspace is refused at both doors.
    let large = Image::new(
        &company.core.realm().id,
        "Large",
        "1",
        WorkspaceKind::Vm,
        None,
        ImageSource::Media { name: "research.qcow2".to_owned() },
        Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 400.0, gpu: false, vram_gb: 0.0 },
        &company.admin,
        now + 4,
    )
    .unwrap();
    let large = company.core.publish_image(&company.admin, large, now + 4).unwrap();
    assert!(company.core.rebuild_workspace(&company.admin, &workspace, &large.id, Data::Reset, now + 5).unwrap_err().contains("400"));
    assert!(company.core.order_workspace(&company.admin, "Too large", &large.id, Access::Standard, quota(), None, now + 5).unwrap_err().contains("400"));

    // Export: metadata only, one event, and nothing that is in a workspace.
    let before = company.core.snapshot().unwrap().audit.events.len();
    let exported = company.core.export_workspaces(&company.admin, now + 6).unwrap();
    assert_eq!(exported.workspaces.len(), 1);
    assert_eq!(exported.images.len(), 3);
    assert!(exported.credentials.is_empty() && exported.model_plans.is_empty(), "only the workspace part travels");
    assert_eq!(company.core.snapshot().unwrap().audit.events.len(), before + 1, "exactly one event");
    assert!(company.core.snapshot().unwrap().audit.events.last().unwrap().action == "workspace.exported");

    // Retiring an image leaves what was built from it alone, and nothing new is built from it.
    company.core.retire_image(&company.admin, &other.id, now + 7).unwrap();
    assert!(company.core.order_workspace(&company.admin, "Another", &other.id, Access::Standard, quota(), None, now + 7).unwrap_err().contains("retired"));
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().image_digest.as_deref(), other.digest.as_deref());

    // Delete is always two steps, and forgetting says what it takes with it.
    assert!(company.core.forget_workspace(&company.admin, &workspace, now + 8).unwrap_err().contains("Archive this workspace"));
    company.core.archive_workspace(&company.admin, &workspace, "the person left", now + 8).unwrap();
    assert!(company.core.archive_workspace(&company.admin, &workspace, "again", now + 9).unwrap_err().contains("already been archived"));
    company.core.forget_workspace(&company.admin, &workspace, now + 9).unwrap();
    assert!(company.core.workspace(&workspace).unwrap().is_none());
    assert!(company.core.workspace_placements(&workspace).unwrap().is_empty(), "the record of where it had been goes with it");
    company.core.verify_audit().unwrap();
    assert!(
        company.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "workspace.forgotten" && event.reason.contains("the record of where it had been")),
        "and the history says so"
    );
}

#[test]
fn an_image_is_known_by_its_digest_once_anybody_has_hashed_it_and_a_mismatch_is_refused() {
    let folder = tempfile::tempdir().unwrap();
    let now = 16_000;
    let mut company = company(folder.path(), now);
    let image = ubuntu(&mut company.core, &company.admin, now);
    let digest = format!("sha256:{}", plain_sha256("the real bytes"));

    assert!(!image.is(&digest), "an image nobody has hashed is not anything yet");
    company.core.verify_image(&company.admin, &image.id, &digest, now + 1).unwrap();
    let pinned = company.core.image(&image.id).unwrap().unwrap();
    assert!(pinned.pinned() && pinned.is(&digest) && pinned.verified_at == Some(now + 1));

    let wrong = format!("sha256:{}", plain_sha256("something else"));
    let refused = company.core.verify_image(&company.admin, &image.id, &wrong, now + 2).unwrap_err();
    assert!(refused.contains("not that image's bytes"), "{refused}");
    assert!(company
        .core
        .snapshot().unwrap()
        .audit
        .events
        .iter()
        .any(|event| event.action == "workspace.image.refused" && event.reason.contains(&digest) && event.reason.contains(&wrong)));
    assert_eq!(company.core.image(&image.id).unwrap().unwrap().digest.as_deref(), Some(digest.as_str()), "and the image keeps what it is");

    // One set of bytes cannot acquire two identities.
    let twice = Image::new(
        &company.core.realm().id,
        "Ubuntu again",
        "24.04",
        WorkspaceKind::Container,
        Some(&digest),
        ImageSource::Oci { reference: "docker.io/library/ubuntu:24.04".to_owned() },
        Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 10.0, gpu: false, vram_gb: 0.0 },
        &company.admin,
        now + 3,
    )
    .unwrap();
    assert!(company.core.publish_image(&company.admin, twice, now + 3).unwrap_err().contains("already in this grid"));

    // Saying by hand what an image is, is an administrator's decision. A computer says it
    // through its report, because its right to say it comes from holding the placement.
    assert!(company.core.verify_image(&company.person, &image.id, &digest, now + 3).unwrap_err().contains("may not manage workspaces"));

    // A source that names a place on one computer is refused, whichever shape it takes.
    for bad in ["/srv/images/ubuntu.tar", "C:/Images/ubuntu.tar", "images\\ubuntu.tar", "../ubuntu.tar"] {
        assert!(ImageSource::Oci { reference: bad.to_owned() }.checked().is_err(), "{bad}");
    }
    assert!(ImageSource::Media { name: "C:/Prepared/research.qcow2".to_owned() }.checked().is_err());
    assert_eq!(ImageSource::Media { name: "research.qcow2".to_owned() }.checked().unwrap().word(), "media");
    assert!(ImageSource::Https { url: "http://example.test/image".to_owned() }.checked().is_err());
    assert!(checked_digest("sha256:nothex").is_err() && checked_digest(&plain_sha256("x")).is_ok());
}

#[test]
fn tidying_old_permissions_never_deletes_who_was_in_which_workspace() {
    let folder = tempfile::tempdir().unwrap();
    let now = 17_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let token = company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 1).unwrap();
    let claims = Authority::peek(&token).unwrap();

    // Routine housekeeping drops permissions that expired a while ago. The record of who was in
    // which workspace, and why their session ended, is not housekeeping and does not go with it.
    company.core.close_workspace_sessions(&company.admin, &workspace, "the day ended", now + 2).unwrap();
    assert!(company.core.store.forget_expired_capabilities(now + 100_000).unwrap() >= 1);
    let sessions = company.core.workspace_sessions(&workspace).unwrap();
    assert_eq!(sessions.len(), 1);
    assert_eq!((sessions[0].capability_id.as_str(), sessions[0].ended_reason.as_str()), (claims.id.as_str(), "the day ended"));

    // A sign-in whose permission simply ran out does not hold a one-person workspace for ever.
    company.core.assign_workspace(&company.admin, &workspace, Some(&company.person), Some(&company.person), Data::Keep, now + 3).unwrap();
    company.core.place_workspace(&company.admin, &workspace, 3_600, now + 3).unwrap_err();
    let claim = claim_for(&company.core, &workspace);
    company.core.report_workspace(&company.first_device, &claim, Report::new(Reported::Ready), now + 3).unwrap();
    company.core.open_workspace(&company.person, &company.device, &workspace, 60, now + 4).unwrap();
    assert!(company.core.open_workspace(&company.person, &company.device, &workspace, 60, now + 5).unwrap_err().contains("1 people in it at once"));
    assert_eq!(company.core.expire_workspace_sessions(now + 1_000), 1);
    assert!(company.core.open_workspace(&company.person, &company.device, &workspace, 60, now + 1_000).is_ok());
}

#[test]
fn a_computer_that_offers_again_keeps_the_workspaces_it_has_held() {
    let folder = tempfile::tempdir().unwrap();
    let now = 18_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);

    // A computer whose offer arrives under a new identity has its trail, its packed copies, its
    // sign-ins and what it agreed to carried onto the identity that stays. Before this, the
    // offer itself would have been refused by the database.
    company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 1).unwrap();
    let device = company.store_device(&company.first);
    let mut second = work::Host::new(&company.core.realm().id, &device, "Studio PC", room(), room(), Commitment::Share, now + 2).unwrap();
    second.id = "host-offered-again".to_owned();
    company.core.store.put_host(&second).unwrap();

    assert!(company.core.store.host(&company.first).unwrap().is_none(), "the old identity is gone");
    assert_eq!(company.core.workspace_trail(&workspace).unwrap(), vec![second.id.clone()], "and the trail came with it");
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap().unwrap().host_id, second.id);
    assert_eq!(company.core.workspace_sessions(&workspace).unwrap()[0].host_id, second.id);
    assert_eq!(company.core.commitments(&second.id).unwrap().len(), 1);
}

#[test]
fn a_restored_realm_brings_every_placement_back_and_hands_nobody_a_live_workspace() {
    let folder = tempfile::tempdir().unwrap();
    let now = 19_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let work = company.core.store.live_assignment(&workspace).unwrap().unwrap().workload_id;
    let token = company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 1).unwrap();

    // Several placements, so that bringing them back depends on the order they arrive in.
    for step in 0..3 {
        let at = now + 2 + step * 2;
        company.core.reset_workspace(&company.admin, &workspace, "again", at).unwrap();
        company.core.place_workspace(&company.admin, &workspace, 3_600, at + 1).unwrap();
    }
    let placements = company.core.workspace_placements(&workspace).unwrap();
    assert_eq!(placements.iter().map(|placement| placement.generation).collect::<Vec<_>>(), vec![1, 2, 3, 4]);

    let backup = company.core.backup(now + 10).unwrap();
    company.core.close().unwrap();
    let restored = Core::restore(&folder.path().join("restored.db"), backup, &key()).unwrap();
    assert_eq!(restored.workspace_placements(&workspace).unwrap().len(), 4, "every placement came back, in order");
    let brought = restored.workspace(&workspace).unwrap().unwrap();
    assert_eq!((brought.owner_id.as_deref(), brought.generation), (Some(company.person.as_str()), 4));
    assert_eq!(restored.images().unwrap().len(), 1);
    assert_eq!(restored.commitments(&company.first).unwrap().len(), 1, "what each computer agreed to came too");
    restored.verify_audit().unwrap();

    // A restored realm hands nobody a live workspace: a record carries no permissions, so the
    // sign-ins that named them are deliberately absent and the permission itself is unknown.
    let mut restored = restored;
    let realm = restored.realm().id.clone();
    let attempt = Attempt { realm_id: &realm, device_id: &company.device, workload_id: &work, resource_id: &workspace, ..Attempt::default() };
    assert!(restored.use_workspace(&token, &attempt, now + 11).unwrap_err().contains("no record of issuing"));
    assert!(restored.workspace_sessions(&workspace).unwrap().is_empty());
}

#[test]
fn work_that_names_a_workspace_is_placed_by_the_workspace_rule_whichever_door_it_comes_through() {
    let folder = tempfile::tempdir().unwrap();
    let now = 20_000;
    let mut company = company(folder.path(), now);
    let image = ubuntu(&mut company.core, &company.admin, now);
    let workspace = company.core.order_workspace(&company.admin, "Ada's desk", &image.id, Access::Standard, quota(), Some(&company.person), now).unwrap();

    // The generic door redirects, exactly as it does for a model request, so a runner cannot get
    // a computer that was never committed to hosting workspaces by calling the other method.
    let mut work = work::Workload::new(
        &company.core.realm().id,
        Capability::Workspaces,
        work::Kind::Workspace,
        &company.person,
        &company.device,
        workspace.shape,
        1,
        now,
    );
    work.note = Some(format!("workspace:{}", workspace.id));
    let work = company.core.submit(work, now).unwrap();
    company.core.report_condition(&company.first_device, false, 500.0, true, false, now).unwrap();
    company.core.store.withdraw_pledge(&company.second, &company.admin, now).unwrap();
    let mut idle_only = Pledge::new(&company.core.realm().id, &company.first, Commitment::Share, room(), true, &company.admin, now);
    idle_only.id = "pledge-idle-only".to_owned();
    company.core.store.withdraw_pledge(&company.first, &company.admin, now).unwrap();
    company.core.store.put_pledge(&idle_only).unwrap();

    let refused = company.core.grant_lease(&work.id, 600, now).unwrap_err();
    assert!(refused.contains("only while nobody is using") || refused.contains("has not been committed"), "{refused}");

    // Once the computer is free again the same door places it, and writes the placement with it.
    company.core.report_condition(&company.first_device, false, 500.0, false, false, now + 1).unwrap();
    let lease = company.core.grant_lease(&work.id, 600, now + 1).unwrap();
    assert_eq!(lease.host_id, company.first);
    let placement = company.core.store.live_assignment(&workspace.id).unwrap().unwrap();
    assert_eq!((placement.workload_id.as_str(), placement.generation), (work.id.as_str(), 1));
    assert_eq!(company.core.workspace(&workspace.id).unwrap().unwrap().state, WorkspaceState::Provisioning);
}

#[test]
fn quotas_and_ceilings_are_checked_rather_than_assumed() {
    assert!(Quota::checked(0.5, 1, 3_600, 1.0).is_err(), "a workspace has at least a gigabyte");
    assert!(Quota::checked(10.0, 0, 3_600, 1.0).is_err() && Quota::checked(10.0, 65, 3_600, 1.0).is_err());
    assert!(Quota::checked(10.0, 1, 30, 1.0).is_err() && Quota::checked(10.0, 1, 48 * 60 * 60, 1.0).is_err());
    assert!(Quota::checked(10.0, 1, 3_600, LARGEST_PARCEL_GB + 1.0).is_err(), "the hub carries the packed copy, and it has a size");
    let quota = Quota::for_disk(100.0).unwrap();
    assert_eq!((quota.sessions, quota.session_seconds, quota.artifact_gb), (1, SESSION_SECONDS, LARGEST_PARCEL_GB));
    assert!(quota.allows(&Resources { disk_gb: 100.0, ..Resources::default() }));
    assert!(!quota.allows(&Resources { disk_gb: 101.0, ..Resources::default() }));
    assert_eq!(MAX_WORKSPACES, crate::desks::MAX_DESKS, "the realm holds what the shipped grid holds, not more");
}

#[test]
fn a_reservation_that_lapses_takes_the_placement_with_it_and_the_workspace_waits() {
    let folder = tempfile::tempdir().unwrap();
    let now = 21_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let work = company.core.store.live_assignment(&workspace).unwrap().unwrap().workload_id;

    // The computer stops renewing. The reservation runs out, and what was holding the workspace
    // there runs out with it, so the record never says a computer is holding something it is not.
    assert_eq!(company.core.expire(now + 4_000), 1);
    assert_eq!(company.core.store.workload(&work).unwrap().unwrap().stage, Stage::Failed);
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap(), None);
    let after = company.core.workspace(&workspace).unwrap().unwrap();
    assert_eq!((after.state, after.owner_id.as_deref()), (WorkspaceState::Requested, Some(company.person.as_str())));
    assert_eq!(company.core.workspace_trail(&workspace).unwrap(), vec![company.first.clone()], "and where its data has been is still known");
    assert!(company.core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "workspace.placement.ended"));

    // Suspending its person does not take their desk off its computer: it stops them, and what
    // stops them is that their sign-ins close and nothing they hold is accepted.
    company.core.place_workspace(&company.admin, &workspace, 3_600, now + 4_001).unwrap();
    let claim = claim_for(&company.core, &workspace);
    company.core.report_workspace(&company.first_device, &claim, Report::new(Reported::Ready), now + 4_002).unwrap();
    let placement = company.core.store.live_assignment(&workspace).unwrap().unwrap();
    company.core.suspend_principal(&company.admin, &company.person, "they are away", now + 4_003).unwrap();
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap().unwrap().id, placement.id, "the desk stays where it is, with its data");
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().owner_id.as_deref(), Some(company.person.as_str()));
}

#[test]
fn a_desk_that_loses_its_computer_while_somebody_is_in_it_can_be_opened_again() {
    let folder = tempfile::tempdir().unwrap();
    let now = 22_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let work = company.core.store.live_assignment(&workspace).unwrap().unwrap().workload_id;
    let lease = company.core.store.workload(&work).unwrap().unwrap().lease_id.expect("the placement holds a reservation");
    let token = company.core.open_workspace(&company.person, &company.device, &workspace, 28_800, now + 1).unwrap();
    let realm = company.core.realm().id.clone();
    let attempt = Attempt { realm_id: &realm, device_id: &company.device, workload_id: &work, resource_id: &workspace, ..Attempt::default() };
    assert!(company.core.use_workspace(&token, &attempt, now + 2).is_ok());

    // The computer gives its reservation back while Ada is in the desk. The placement goes with
    // it, and a sign-in is bound to the placement it was opened against, so this one could never
    // be used again whatever else happened.
    company.core.give_back(&lease, work::Setback::WentQuiet, now + 3).unwrap();
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap(), None);
    assert!(company.core.use_workspace(&token, &attempt, now + 4).is_err());

    // So it is closed rather than left counting against the one person this desk allows at once.
    // Her desk is still hers, and she opens it again as soon as it has a computer.
    assert_eq!(company.core.store.live_sessions(&workspace, now + 4).unwrap(), 0, "an abandoned sign-in cannot lock a one-person desk");
    company.core.place_workspace(&company.admin, &workspace, 3_600, now + 5).unwrap();
    let claim = claim_for(&company.core, &workspace);
    company.core.report_workspace(&company.first_device, &claim, Report::new(Reported::Ready).built("env-2"), now + 6).unwrap();
    company.core.open_workspace(&company.person, &company.device, &workspace, 28_800, now + 7).unwrap();
    let sessions = company.core.workspace_sessions(&workspace).unwrap();
    assert_eq!(sessions.len(), 2);
    assert_eq!(sessions[0].ended_reason, "the workspace left its computer, so it must be opened again");
}

#[test]
fn a_paused_grid_serves_nobody_who_is_already_in_a_desk() {
    let folder = tempfile::tempdir().unwrap();
    let now = 23_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let work = company.core.store.live_assignment(&workspace).unwrap().unwrap().workload_id;
    let token = company.core.open_workspace(&company.person, &company.device, &workspace, 28_800, now + 1).unwrap();
    let realm = company.core.realm().id.clone();
    let attempt = Attempt { realm_id: &realm, device_id: &company.device, workload_id: &work, resource_id: &workspace, ..Attempt::default() };
    assert!(company.core.use_workspace(&token, &attempt, now + 2).is_ok());

    // A grid that is paused or being deleted answers but serves nothing, and that has to mean the
    // desks somebody is already in, not only the next sign-in asked for. Every further use is
    // refused at the door the computer knocks on for each one.
    company.core.set_lifecycle(&company.admin, Lifecycle::Paused, now + 3).unwrap();
    let refused = company.core.use_workspace(&token, &attempt, now + 4).unwrap_err();
    assert!(refused.contains("not serving work at the moment"), "{refused}");
    assert!(company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 4).unwrap_err().contains("not serving work"));

    // And opening the grid again does not hand back what was outstanding when it stopped: pausing
    // moved the policy on, so each of those is refused at its next use and asked for again.
    company.core.set_lifecycle(&company.admin, Lifecycle::Open, now + 5).unwrap();
    let refused = company.core.use_workspace(&token, &attempt, now + 6).unwrap_err();
    assert!(refused.contains("policy changed"), "{refused}");
    company.core.close_workspace_sessions(&company.admin, &workspace, "the grid was paused", now + 7).unwrap();
    assert!(company.core.open_workspace(&company.person, &company.device, &workspace, 600, now + 8).is_ok(), "and the grid serves again once it is open");
}

#[test]
fn building_a_desk_again_and_keeping_its_data_stays_where_the_data_is() {
    let folder = tempfile::tempdir().unwrap();
    let now = 24_000;
    let mut company = company(folder.path(), now);
    let workspace = running(&mut company, now);
    let first = company.core.workspace(&workspace).unwrap().unwrap().image_id;
    let newer = Image::new(
        &company.core.realm().id,
        "Ubuntu",
        "24.10",
        WorkspaceKind::Container,
        None,
        ImageSource::Oci { reference: "docker.io/library/ubuntu:24.10".to_owned() },
        Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 10.0, gpu: false, vram_gb: 0.0 },
        &company.admin,
        now,
    )
    .unwrap();
    let newer = company.core.publish_image(&company.admin, newer, now).unwrap().id;

    // Nobody has packed this desk up, so the only copy of what is in it is the disk on the
    // computer holding it. That computer is now one the queue would pass over, because its person
    // is using it and the grid was only ever lent its idle time.
    company.core.store.withdraw_pledge(&company.first, &company.admin, now + 1).unwrap();
    let mut idle_only = Pledge::new(&company.core.realm().id, &company.first, Commitment::Share, room(), true, &company.admin, now + 1);
    idle_only.id = "pledge-idle-only".to_owned();
    company.core.store.put_pledge(&idle_only).unwrap();
    company.core.report_condition(&company.first_device, false, 500.0, true, false, now + 1).unwrap();

    let refused = company.core.rebuild_workspace(&company.admin, &workspace, &newer, Data::Keep, now + 2).unwrap_err();
    assert!(refused.contains("is only on") && refused.contains("Move it first"), "{refused}");
    let held = company.core.workspace(&workspace).unwrap().unwrap();
    assert_eq!((held.image_id.as_str(), held.state), (first.as_str(), WorkspaceState::Assigned), "a refusal changes nothing");
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap().unwrap().host_id, company.first);

    // Once nobody is using that computer the rebuild happens there, on the disk that holds the
    // data, rather than going back in the queue where another computer would build an empty one.
    company.core.report_condition(&company.first_device, false, 500.0, false, false, now + 3).unwrap();
    let after = company.core.rebuild_workspace(&company.admin, &workspace, &newer, Data::Keep, now + 4).unwrap();
    assert_eq!((after.image_id.as_str(), after.state), (newer.as_str(), WorkspaceState::Provisioning));
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap().unwrap().host_id, company.first, "it never left the computer that has its data");
    let placement = company.core.store.live_assignment(&workspace).unwrap().unwrap().id;
    assert!(company.core.place_workspace(&company.admin, &workspace, 3_600, now + 5).unwrap_err().contains("not waiting for a computer"));

    // Every placement of a workspace is admitted in its owner's name, so whatever would refuse
    // that is said before the desk is taken off the computer holding its data, not after.
    company.core.suspend_principal(&company.admin, &company.person, "they are away", now + 6).unwrap();
    let refused = company.core.rebuild_workspace(&company.admin, &workspace, &first, Data::Keep, now + 7).unwrap_err();
    assert!(refused.contains("suspended"), "{refused}");
    assert_eq!(company.core.store.live_assignment(&workspace).unwrap().unwrap().id, placement, "and nothing moved while it was refusing");
    assert_eq!(company.core.workspace(&workspace).unwrap().unwrap().image_id, newer, "nor was it half built from the other image");
}

impl Company {
    /// Which computer offers this host, for a test that needs to offer again as somebody else.
    fn store_device(&self, host_id: &str) -> String {
        self.core.store.host(host_id).unwrap().unwrap().device_id
    }
}
