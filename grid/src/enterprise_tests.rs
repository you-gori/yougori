//! Real loopback TLS requests: delegated management, atomic provisioning and revocation.
use crate::{
    desks::{Capacity, DeskReport},
    enterprise::AdminRole,
    hub::{self, Hub},
    invite::Invite,
    member, net, password,
};
use serde_json::{json, Value};
use std::sync::Arc;
const PASSWORD: &str = "synthetic enterprise password";

async fn start(root: &std::path::Path) -> (Hub, Invite) {
    let salt = password::new_salt();
    let key = password::derive(PASSWORD, &salt).unwrap();
    let path = root.join("hub.json");
    let private = hub::create(
        &path,
        "Test company",
        "127.0.0.1".parse().unwrap(),
        0,
        None,
        None,
        &salt,
    )
    .unwrap();
    let hub = Hub::start(path, &private, &key, Arc::new(|_, _| {}))
        .await
        .unwrap();
    let invite = Invite {
        company: "Test company".into(),
        address: hub.address().into(),
        fingerprint: net::fingerprint(&hub.record().certificate).unwrap(),
    };
    (hub, invite)
}
fn account(username: &str, role: &str, workspace: Option<&str>) -> Value {
    let salt = password::new_salt();
    let key = password::derive(PASSWORD, &salt).unwrap();
    json!({"action":"personAdd","username":username,"name":username,"salt":salt,"key":key,"adminRole":role,"roleId":workspace})
}
fn image() -> Value {
    json!({"action":"imageAdd","name":"Research","version":"2026.10","applications":["Python","RStudio"],"spec":{"kind":"vm","cpu":2,"memoryGb":4,"diskGb":40,"gpu":false,"image":"https://images.example.test/research.qcow2"},"sha256":"a".repeat(64)})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn delegated_admin_roles_and_revocation_are_enforced_over_tls() {
    let root = tempfile::tempdir().unwrap();
    let (hub, invite) = start(root.path()).await;
    let admin = hub
        .enterprise(account("admin.one", "administrator", None))
        .unwrap();
    let session = member::person_login(&invite, "admin.one", PASSWORD, None).await
        .unwrap();
    assert_eq!(session.admin_role, AdminRole::Administrator);
    let img = session.session.manage(image()).await.unwrap();
    let role=session.session.manage(json!({"action":"roleAdd","name":"Research Kazakhstan","imageId":img["id"],"access":"restricted"})).await.unwrap();
    let workspace = role["id"].as_str().unwrap();
    let person = session
        .session
        .manage(account("researcher", "user", Some(workspace)))
        .await
        .unwrap();
    let auditor = session
        .session
        .manage(account("audit.reader", "auditor", None))
        .await
        .unwrap();
    assert!(!auditor["id"].is_null());
    let user = member::person_login(&invite, "researcher", PASSWORD, None).await
        .unwrap();
    assert!(user
        .session
        .manage(json!({"action":"status"}))
        .await
        .is_err());
    assert!(user
        .session
        .manage(json!({"action":"personUpdate","id":person["id"],"adminRole":"administrator"}))
        .await
        .is_err());
    let read = member::person_login(&invite, "audit.reader", PASSWORD, None).await
        .unwrap();
    assert!(read
        .session
        .manage(json!({"action":"status"}))
        .await
        .is_ok());
    assert!(read.session.manage(image()).await.is_err());
    for provider in ["citrix", "azureVirtualDesktop", "windows365", "horizon"] {
        session.session.manage(json!({"action":"connectionAdd","provider":provider,"name":provider,"url":"https://workspace.example.test/","roleIds":[workspace]})).await.unwrap();
    }
    assert_eq!(
        user.session
            .manage(json!({"action":"portal"}))
            .await
            .unwrap()["connections"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
    assert!(read
        .session
        .manage(json!({"action":"portal"}))
        .await
        .unwrap()["connections"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(session.session.manage(json!({"action":"connectionAdd","provider":"citrix","name":"bad","url":"https://user:secret@example.test","roleIds":[]})).await.is_err());
    // Same signed-in token loses write permission immediately on demotion.
    hub.enterprise(json!({"action":"personUpdate","id":admin["id"],"adminRole":"auditor"}))
        .unwrap();
    assert!(session.session.manage(image()).await.is_err());
    assert!(session
        .session
        .manage(json!({"action":"status"}))
        .await
        .is_ok());
    let mut reset = account("unused", "user", None);
    reset["action"] = json!("personPassword");
    reset["id"] = admin["id"].clone();
    hub.enterprise(reset).unwrap();
    assert!(session
        .session
        .manage(json!({"action":"status"}))
        .await
        .is_err());
    user.session
        .manage(json!({"action":"logout"}))
        .await
        .unwrap();
    assert!(user
        .session
        .manage(json!({"action":"portal"}))
        .await
        .is_err());
    let status = hub
        .enterprise(json!({"action":"status"}))
        .unwrap()
        .to_string();
    assert!(
        !status.contains("keyHash")
            && !status.contains("sessionToken")
            && !status.contains(PASSWORD)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn managed_desks_require_capable_hosts_and_revoke_old_assignments() {
    let root = tempfile::tempdir().unwrap();
    let (hub, _) = start(root.path()).await;
    let img = hub.enterprise(image()).unwrap();
    let role = hub
        .enterprise(json!({"action":"roleAdd","name":"IT India","imageId":img["id"]}))
        .unwrap();
    let role_id = role["id"].as_str().unwrap();
    let person = hub
        .enterprise(account("worker.one", "user", Some(role_id)))
        .unwrap();
    let other = hub.enterprise(account("worker.two", "user", None)).unwrap();
    let joined = member::join(
        "Test company",
        hub.address(),
        PASSWORD,
        "Cloud host",
        "linux",
        false,
        None,
    )
    .await
    .unwrap();
    let host = joined.membership;
    let mut capacity = Capacity {
        cpu: 16,
        memory_gb: 64.,
        free_disk_gb: 1000.,
        ..Default::default()
    };
    assert!(host
        .check_in("old", false, &[], Some(&capacity), &[])
        .await
        .unwrap()
        .desks
        .is_empty());
    capacity.desk_protocol = 2;
    let orders = host
        .check_in("new", false, &[], Some(&capacity), &[])
        .await
        .unwrap()
        .desks;
    assert_eq!(orders.len(), 1);
    let desk = &orders[0];
    assert_eq!(desk.access, crate::enterprise::DeskAccess::Restricted);
    assert!(host
        .desk_lease(&desk.id, person["id"].as_str().unwrap(), desk.generation)
        .await
        .is_ok());
    let failure = DeskReport {
        id: desk.id.clone(),
        state: "failed".into(),
        environment_id: Some("env-existing".into()),
        generation: desk.generation,
        ..Default::default()
    };
    assert_eq!(
        host.check_in("new", false, &[], Some(&capacity), &[failure])
            .await
            .unwrap()
            .desks
            .len(),
        1,
        "failure must not drop a host's data"
    );
    hub.enterprise(json!({"action":"deskAssign","id":desk.id,"person":other["id"]}))
        .unwrap();
    assert!(host
        .desk_lease(&desk.id, person["id"].as_str().unwrap(), desk.generation)
        .await
        .is_err());
    let stale = DeskReport {
        id: desk.id.clone(),
        state: "gone".into(),
        generation: desk.generation,
        ..Default::default()
    };
    let updated = host
        .check_in("new", false, &[], Some(&capacity), &[stale])
        .await
        .unwrap()
        .desks;
    assert_eq!(
        updated.len(),
        1,
        "a stale generation must not erase a reassigned desk's host"
    );
    assert!(host
        .desk_lease(
            &desk.id,
            other["id"].as_str().unwrap(),
            updated[0].generation
        )
        .await
        .is_ok());
    hub.enterprise(json!({"action":"personRemove","id":other["id"]}))
        .unwrap();
    assert!(host
        .desk_lease(
            &desk.id,
            other["id"].as_str().unwrap(),
            updated[0].generation
        )
        .await
        .is_err());
    // Removing the host puts its desk back into waiting; the data trail still leads to it.
    let removed = hub.enterprise(json!({"action":"computerRemove","id":host.member_id})).unwrap();
    assert_eq!(removed["removed"], true);
    let status = hub.enterprise(json!({"action":"status"})).unwrap();
    assert_eq!((status["desks"][0]["state"].as_str(), status["desks"][0]["hostId"].is_null(), status["members"].as_array().map(Vec::len)), (Some("planned"), true, Some(0)));
    assert!(host.check_in("new", false, &[], Some(&capacity), &[]).await.is_err(), "the removed computer is no longer a member");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn catalog_validation_and_compound_person_creation_are_atomic() {
    let root = tempfile::tempdir().unwrap();
    let (hub, _) = start(root.path()).await;
    let mut invalid = image();
    invalid["sha256"] = json!("bad");
    assert!(hub.enterprise(invalid).is_err());
    let before = hub.enterprise(json!({"action":"status"})).unwrap();
    assert!(hub
        .enterprise(account("rollback.user", "user", Some("missing-role")))
        .is_err());
    let after = hub.enterprise(json!({"action":"status"})).unwrap();
    assert_eq!(before["people"], after["people"]);
    assert_eq!(before["desks"], after["desks"]);
    let img = hub.enterprise(image()).unwrap();
    assert!(
        hub.enterprise(image()).is_err(),
        "image versions are immutable"
    );
    let role = hub
        .enterprise(json!({"action":"roleAdd","name":"Research","imageId":img["id"]}))
        .unwrap();
    assert!(hub
        .enterprise(json!({"action":"imageRemove","id":img["id"]}))
        .is_err());
    hub.enterprise(json!({"action":"computerLimit","limit":1}))
        .unwrap();
    member::join(
        "Test company",
        hub.address(),
        PASSWORD,
        "Host one",
        "linux",
        false,
        None,
    )
    .await
    .unwrap();
    assert!(member::join(
        "Test company",
        hub.address(),
        PASSWORD,
        "Host two",
        "linux",
        false,
        None
    )
    .await
    .is_err());
    hub.enterprise(json!({"action":"computerLimit","limit":null}))
        .unwrap();
    member::join(
        "Test company",
        hub.address(),
        PASSWORD,
        "Host two",
        "linux",
        false,
        None,
    )
    .await
    .unwrap();
    let saved = serde_json::to_value(hub::load(&root.path().join("hub.json")).unwrap()).unwrap();
    assert_eq!(saved["enterprise"]["roles"][0]["id"], role["id"]);
    assert_eq!(saved["members"].as_array().unwrap().len(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn private_image_distribution_requires_an_assigned_host() {
    use sha2::{Digest, Sha256};
    let root = tempfile::tempdir().unwrap();
    let (hub, _) = start(root.path()).await;
    let bytes = vec![0x5au8; 300_000];
    let checksum = hex::encode(Sha256::digest(&bytes));
    let mut request = image();
    request["sha256"] = json!(checksum);
    request["spec"]["image"] = json!(format!("grid-image:{checksum}"));
    assert!(
        hub.enterprise(request.clone()).is_err(),
        "cannot publish missing cached bytes"
    );
    std::fs::create_dir(root.path().join("images")).unwrap();
    std::fs::write(
        root.path().join("images").join(format!("{checksum}.img")),
        &bytes,
    )
    .unwrap();
    let image = hub.enterprise(request).unwrap();
    let role = hub
        .enterprise(json!({"action":"roleAdd","name":"Local image role","imageId":image["id"]}))
        .unwrap();
    hub.enterprise(account("local.image.user", "user", role["id"].as_str()))
        .unwrap();
    let assigned = member::join(
        "Test company",
        hub.address(),
        PASSWORD,
        "Assigned host",
        "linux",
        false,
        None,
    )
    .await
    .unwrap()
    .membership;
    let other = member::join(
        "Test company",
        hub.address(),
        PASSWORD,
        "Unassigned host",
        "linux",
        false,
        None,
    )
    .await
    .unwrap()
    .membership;
    assert!(assigned.desk_image_bytes(&checksum, 0).await.is_err());
    let capacity = Capacity {
        cpu: 16,
        memory_gb: 64.,
        free_disk_gb: 1000.,
        desk_protocol: 2,
        ..Default::default()
    };
    let orders = assigned
        .check_in("new", false, &[], Some(&capacity), &[])
        .await
        .unwrap()
        .desks;
    assert_eq!(orders.len(), 1);
    // Raw pieces of up to IMAGE_PIECE bytes, with the whole size announced: a small image is one piece.
    let (size, first) = assigned.desk_image_bytes(&checksum, 0).await.unwrap();
    assert_eq!((size, first.len()), (300_000, 300_000));
    assert_eq!(first.as_ref(), bytes.as_slice());
    let (_, tail) = assigned.desk_image_bytes(&checksum, 299_000).await.unwrap();
    assert_eq!(tail.as_ref(), &bytes[299_000..]);
    assert!(other.desk_image_bytes(&checksum, 0).await.is_err());
    assert!(assigned
        .desk_image_bytes("../../hub.json", 0)
        .await
        .is_err());
    assert!(assigned.desk_image_bytes(&checksum, 300_000).await.is_err(), "nothing lies at or past the end");
    hub.enterprise(json!({"action":"deskRemove","id":orders[0].id}))
        .unwrap();
    assert!(
        assigned.desk_image_bytes(&checksum, 0).await.is_err(),
        "removing the assignment revokes image access"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_can_be_added_with_a_sized_desk_without_any_catalog() {
    let root = tempfile::tempdir().unwrap();
    let (hub, _) = start(root.path()).await;
    let salt = password::new_salt();
    let key = password::derive(PASSWORD, &salt).unwrap();
    let spec = crate::desks::DeskSpec::checked(crate::desks::DeskKind::Container, 2.0, 8.0, 20.0, true, "").unwrap();
    let person = hub.add_person("Ada.Lovelace", "Ada Lovelace", &salt, &key, Some(spec)).unwrap();
    assert_eq!((person["username"].as_str(), person["desks"].as_array().map(Vec::len)), (Some("ada.lovelace"), Some(1)));
    assert_eq!((person["desk"]["name"].as_str(), person["desk"]["access"].as_str(), person["desk"]["spec"]["gpu"].as_bool(), person["desk"]["state"].as_str()), (Some("Ada Lovelace's desk"), Some("standard"), Some(true), Some("planned")));
    // The same rules as the catalog path: one record, one audit trail, a duplicate refused whole.
    assert!(hub.add_person("ada.lovelace", "Again", &salt, &key, Some(crate::desks::DeskSpec::checked(crate::desks::DeskKind::Container, 1.0, 1.0, 5.0, false, "").unwrap())).is_err());
    let status = hub.enterprise(json!({"action":"status"})).unwrap();
    assert_eq!((status["people"].as_array().map(Vec::len), status["desks"].as_array().map(Vec::len)), (Some(1), Some(1)));
    assert_eq!(status["enterprise"]["audit"][0]["action"], "personAdd");
    // Without a size or a role, only the account is made; a desk can follow by size alone.
    let alone = hub.add_person("grace", "Grace", &salt, &key, None).unwrap();
    assert!(alone.get("desk").is_none());
    let desk = hub.add_desk("Ops desk", crate::desks::DeskSpec::checked(crate::desks::DeskKind::Vm, 1.0, 2.0, 10.0, false, "prepared.qcow2").unwrap(), Some("grace")).unwrap();
    assert_eq!((desk["person"].as_str(), desk["summary"].as_str()), (Some("Grace"), Some("VM · 1 CPU · 2 GB memory · 10 GB disk")));
}
