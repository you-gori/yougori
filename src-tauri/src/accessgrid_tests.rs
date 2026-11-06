//! Several Access Grids on one computer, on throwaway folders and a fake OS vault: two hubs, two
//! sign-ins and their sessions side by side, each with its own record, port, keys, activity log,
//! backup and lookup; the computer's first Access Grid still read under its old names; and a key
//! already in the vault never written over. Nothing here touches the real vault or data folder.
use super::*;
use std::sync::Mutex;
use yougori_grid::access::seal::Sealer;

const SECRET: &str = "sk-fixture-0123456789abcdef";

/// The OS vault, kept in memory. `down` makes it answer like a vault that is not ready.
#[derive(Default)]
struct FakeVault {
    keys: Mutex<BTreeMap<String, String>>,
    down: Mutex<bool>,
}

impl FakeVault {
    fn get(&self, name: &str) -> Option<String> {
        self.keys.lock().unwrap().get(name).cloned()
    }
    fn put(&self, name: &str, value: &str) {
        self.keys.lock().unwrap().insert(name.to_owned(), value.to_owned());
    }
    fn names(&self) -> Vec<String> {
        self.keys.lock().unwrap().keys().cloned().collect()
    }
}

impl Vault for FakeVault {
    fn look_up(&self, name: &str) -> Secret {
        if *self.down.lock().unwrap() {
            return Secret::Unavailable;
        }
        self.get(name).map(Secret::Found).unwrap_or(Secret::Absent)
    }
    fn store(&self, name: &str, value: &str) -> Result<(), String> {
        if *self.down.lock().unwrap() {
            return Err("The fake vault is down".into());
        }
        self.put(name, value);
        Ok(())
    }
    fn remove(&self, name: &str) {
        self.keys.lock().unwrap().remove(name);
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Gives hubs that were just dropped the moment they need to let go of their ports.
async fn let_go() {
    tokio::time::sleep(Duration::from_millis(250)).await;
}

fn loopback() -> IpAddr {
    "127.0.0.1".parse().unwrap()
}

fn owner(username: &str) -> Owner {
    let salt = password::new_salt();
    let key = password::derive(&format!("{username} password 1"), &salt).unwrap();
    Owner { username: username.into(), name: username.into(), salt, key }
}

fn inner() -> Inner {
    let mut inner = Inner::default();
    inner.instances.entry(DEFAULT.to_owned()).or_default();
    inner
}

/// Makes a hub where `slot_for_hub` puts it and keeps it in `inner`, as `access_create` does.
async fn host(inner: &mut Inner, root: &Path, vault: &FakeVault, company: &str) -> Layout {
    let layout = slot_for_hub(inner, root, vault).unwrap();
    let hub = found_hub(&layout, vault, company, loopback(), free_port(), None, owner("root.admin"), None).await.unwrap();
    let instance = inner.instances.entry(layout.key().to_owned()).or_default();
    instance.loaded = true;
    instance.record = Some((hub.record().id, hub.record().company));
    instance.hub = Some(hub);
    layout
}

fn hub<'a>(inner: &'a Inner, layout: &Layout) -> &'a Hub {
    inner.instances[layout.key()].hub.as_ref().unwrap()
}

fn invite_for(hub: &Hub) -> Invite {
    Invite { company: hub.record().company, address: HubAddress::Direct(hub.address()), fingerprint: hub.fingerprint().to_owned() }
}

/// Signs `username` in to `hub` and keeps the sign-in where `slot_for_member` puts it, as
/// `access_signin` does.
async fn sign_in(inner: &mut Inner, root: &Path, vault: &FakeVault, invite: &Invite, username: &str) -> Layout {
    let signed = member::signin(invite, username, &format!("{username} password 1"), None, "Test PC").await.unwrap();
    let fingerprint = net::normalize_fingerprint(&invite.fingerprint).unwrap();
    let (layout, replace) = slot_for_member(inner, root, vault, &fingerprint).unwrap();
    let saved = Saved {
        version: 2,
        access_id: signed.access_id.clone(),
        company: signed.company.clone(),
        address: invite.address.to_string(),
        certificate: signed.certificate.clone(),
        fingerprint: signed.fingerprint.clone(),
        username: username.into(),
        person_id: signed.person["id"].as_str().unwrap_or_default().into(),
        device_id: signed.device_id.clone().unwrap_or_default(),
        signed_in_at: yougori_grid::now(),
    };
    keep_membership(&layout, vault, &saved, signed.device_token.as_deref().unwrap(), replace).unwrap();
    let instance = inner.instances.entry(layout.key().to_owned()).or_default();
    instance.loaded = true;
    instance.member = Some(saved);
    instance.session = Some((signed.token, signed.expires_at, signed.strong));
    layout
}

/// A credential's sealed value in the record on disk, opened with `seal_key`.
fn open_sealed(layout: &Layout, seal_key: &str) -> Result<String, String> {
    let record = hub::load(&layout.hub()).unwrap();
    let credential = record.credentials.first().expect("a credential");
    Sealer::new(seal_key)?.open(&credential.id, &credential.sealed)
}

#[tokio::test]
async fn the_first_access_grid_is_still_read_under_its_old_names_and_port() {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path();
    let vault = FakeVault::default();
    let mut inner = inner();
    let first = host(&mut inner, root, &vault, "Acme").await;
    assert!(first.is_default(), "the computer's first Access Grid is the default instance");
    assert_eq!(first.hub(), root.join("access-hub.json"));
    assert_eq!(vault.names(), ["yougori-access-hub-key", "yougori-access-hub-seal"]);
    assert_eq!(hub_ports(&first, root).unwrap(), (7465, 7466, Vec::new()), "the first one keeps 7465 and 7466");
    assert_eq!(instances::on_disk(root), ["default"]);

    // Read back as the engine does at startup: same file, same key names, the hub starts.
    let id = hub(&inner, &first).record().id;
    inner.instances.clear();
    let_go().await;
    let mut again = Instance::default();
    load(&Layout::default_in(root), &mut again, &vault).await;
    assert_eq!(again.hub.as_ref().map(|hub| hub.record().id), Some(id.clone()));
    assert_eq!(again.grid_id(), Some(id));

    // A sign-in saved before there could be several is read from its old file.
    let legacy = json!({"version": 2, "accessId": "access-legacy", "company": "Acme", "address": "10.0.0.5:7465", "certificate": "", "fingerprint": "AB", "username": "ada", "personId": "person-1", "deviceId": "device-1", "signedInAt": 1});
    std::fs::write(root.join("access-member.json"), legacy.to_string()).unwrap();
    let saved = read_member(&Layout::default_in(root)).unwrap().unwrap();
    assert_eq!((saved.access_id.as_str(), saved.username.as_str()), ("access-legacy", "ada"));
    assert_eq!(Layout::default_in(root).names().device, "yougori-access-device");
    assert_eq!(mcp(&Layout::default_in(root), Some("access-legacy")), json!({"name": "yougori-access", "command": "yougori", "args": ["access", "mcp"]}));
}

#[tokio::test]
async fn two_hubs_keep_their_own_records_ports_keys_and_activity_and_the_first_seal_still_opens() {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path();
    let vault = FakeVault::default();
    let mut inner = inner();
    let first = host(&mut inner, root, &vault, "Acme").await;
    hub(&inner, &first).manage_as_owner(json!({"action": "credentialAdd", "name": "GitHub", "kind": "bearer", "destinations": ["https://api.github.com"], "value": SECRET})).unwrap();
    let first_seal = vault.get("yougori-access-hub-seal").unwrap();
    let first_key = vault.get("yougori-access-hub-key").unwrap();
    assert_eq!(open_sealed(&first, &first_seal).unwrap(), SECRET);

    let second = host(&mut inner, root, &vault, "Globex").await;
    assert!(!second.is_default() && instances::is_key(second.key()));
    assert_eq!(second.hub(), root.join("access").join(second.key()).join("access-hub.json"));
    // Its own keys, beside the first one's, which are exactly as they were.
    let names = second.names();
    assert_eq!(names.seal_key, format!("yougori-access-hub-seal-{}", second.key()));
    assert_eq!(vault.get("yougori-access-hub-seal").as_deref(), Some(first_seal.as_str()));
    assert_eq!(vault.get("yougori-access-hub-key").as_deref(), Some(first_key.as_str()));
    assert_ne!(vault.get(&names.seal_key).unwrap(), first_seal);
    assert!(vault.get(&names.hub_key).is_some());

    // Independent records and listeners.
    let (one, two) = (hub(&inner, &first), hub(&inner, &second));
    assert_ne!(one.record().id, two.record().id);
    assert_ne!(one.address().port(), two.address().port());
    assert_ne!(one.fingerprint(), two.fingerprint());
    assert_eq!((one.record().credentials.len(), two.record().credentials.len()), (1, 0));

    // Each activity log is its own: the credential the first one added is not in the second's.
    assert_ne!(first.activity(), second.activity());
    two.manage_as_owner(json!({"action": "settingsSet", "requireTwoStep": false})).unwrap();
    let first_log = std::fs::read_to_string(first.activity()).unwrap();
    let second_log = std::fs::read_to_string(second.activity()).unwrap_or_default();
    assert!(first_log.contains("GitHub"), "{first_log}");
    assert!(!second_log.contains("GitHub"), "{second_log}");

    // The first grid's credential still opens with the first seal after the second was made,
    // and the second seal does not open it.
    assert_eq!(open_sealed(&first, &first_seal).unwrap(), SECRET);
    assert!(open_sealed(&first, &vault.get(&names.seal_key).unwrap()).is_err());

    // Both are found on disk, and both start again with their own keys.
    assert_eq!(instances::on_disk(root), ["default".to_owned(), second.key().to_owned()]);
    let ids = (one.record().id, two.record().id);
    inner.instances.clear();
    let_go().await;
    for (layout, id) in [(&first, &ids.0), (&second, &ids.1)] {
        let mut instance = Instance::default();
        load(layout, &mut instance, &vault).await;
        assert_eq!(instance.hub.as_ref().map(|hub| hub.record().id).as_ref(), Some(id), "{}", layout.key());
    }
    assert_eq!(open_sealed(&first, &first_seal).unwrap(), SECRET);
}

#[tokio::test]
async fn a_new_hub_never_writes_over_a_key_already_in_the_vault() {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path();
    let vault = FakeVault::default();
    // A seal key with no record beside it: it might be the only copy of some grid's seal.
    vault.put("yougori-access-hub-seal", "kept-as-it-is");
    let inner = inner();
    let layout = slot_for_hub(&inner, &root, &vault).unwrap();
    assert!(!layout.is_default(), "the default instance is not free while one of its names is held");
    found_hub(&layout, &vault, "Acme", loopback(), free_port(), None, owner("root.admin"), None).await.unwrap();
    assert_eq!(vault.get("yougori-access-hub-seal").as_deref(), Some("kept-as-it-is"));

    // Asked to make a hub where a name is held, it refuses and leaves nothing behind.
    let crowded = Layout::default_in(root);
    let refused = found_hub(&crowded, &vault, "Globex", loopback(), free_port(), None, owner("root.admin"), None).await.err().unwrap();
    assert!(refused.contains("already holds a key called yougori-access-hub-seal"), "{refused}");
    assert_eq!(vault.get("yougori-access-hub-seal").as_deref(), Some("kept-as-it-is"));
    assert!(vault.get("yougori-access-hub-key").is_none() && !crowded.hub().exists());

    // A hub that fails to start takes back only the keys it wrote itself.
    let taken = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let busy = taken.local_addr().unwrap().port();
    let spare = instances::fresh(root, |name| held(&vault, name)).unwrap();
    let before = vault.names();
    assert!(found_hub(&spare, &vault, "Initech", loopback(), busy, None, owner("root.admin"), None).await.is_err());
    assert_eq!(vault.names(), before);
    assert!(!spare.folder().exists(), "a hub that never started leaves no folder");

    // A vault that will not answer writes nothing at all.
    *vault.down.lock().unwrap() = true;
    assert!(slot_for_hub(&inner, root, &vault).unwrap_err().contains("would not answer"));
    assert!(found_hub(&spare, &vault, "Initech", loopback(), free_port(), None, owner("root.admin"), None).await.err().unwrap().contains("would not answer"));
    *vault.down.lock().unwrap() = false;
    assert_eq!(vault.names(), before);
}

#[tokio::test]
async fn two_sign_ins_and_their_sessions_live_side_by_side_and_lookups_name_the_right_one() {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path();
    let vault = FakeVault::default();
    let mut inner = inner();
    // This computer runs Acme's grid; Globex's grid runs on another computer.
    let acme = host(&mut inner, root, &vault, "Acme").await;
    let elsewhere = tempfile::tempdir().unwrap();
    let other_vault = FakeVault::default();
    let mut other = self::inner();
    let globex = host(&mut other, elsewhere.path(), &other_vault, "Globex").await;
    let globex_invite = invite_for(hub(&other, &globex));
    let acme_invite = invite_for(hub(&inner, &acme));

    // Signing in to the grid this computer runs keeps the sign-in in that grid's instance.
    let mine = sign_in(&mut inner, root, &vault, &acme_invite, "root.admin").await;
    assert_eq!(mine, acme);
    // Signing in to another grid makes an instance of its own, with its own device token.
    let theirs = sign_in(&mut inner, root, &vault, &globex_invite, "root.admin").await;
    assert!(!theirs.is_default());
    assert_ne!(mine.member(), theirs.member());
    let (one, two) = (vault.get(&mine.names().device).unwrap(), vault.get(&theirs.names().device).unwrap());
    assert_ne!(one, two);
    assert_eq!(read_member(&theirs).unwrap().unwrap().company, "Globex");
    assert_eq!(read_member(&mine).unwrap().unwrap().company, "Acme");

    // Two sessions, each good only at its own hub.
    let session = |layout: &Layout| inner.instances[layout.key()].session.clone().unwrap().0;
    let (acme_session, globex_session) = (session(&mine), session(&theirs));
    assert_ne!(acme_session, globex_session);
    let me = |invite: &Invite, layout: &Layout, token: String| {
        let saved = inner.instances[layout.key()].member.clone().unwrap();
        let address = invite.address.clone();
        async move { member::call(&address, &saved.certificate, &token, "me", &json!({})).await }
    };
    assert_eq!(me(&acme_invite, &mine, acme_session.clone()).await.unwrap()["company"], "Acme");
    assert_eq!(me(&globex_invite, &theirs, globex_session.clone()).await.unwrap()["company"], "Globex");
    assert!(me(&globex_invite, &theirs, acme_session).await.is_err(), "one grid's session is no good at the other");

    // Without a grid named, a command refuses and names both; named, it finds the right one.
    let refused = choose(&inner, root, None).unwrap_err();
    assert!(refused.starts_with("There are 2 Access Grids on this computer: Acme (access-") && refused.contains("Globex (access-") && refused.ends_with("Say which with gridId."), "{refused}");
    let globex_id = inner.instances[theirs.key()].grid_id().unwrap();
    assert_eq!(choose(&inner, root, Some(&globex_id)).unwrap(), theirs.key());
    assert_eq!(choose(&inner, root, Some(theirs.key())).unwrap(), theirs.key());
    assert_eq!(choose(&inner, root, Some(" default ")).unwrap(), "default");
    assert!(choose(&inner, root, Some("access-nothing")).unwrap_err().starts_with("There is no Access Grid access-nothing on this computer"));
    // Status describes the computer's first one in its old fields and lists both.
    assert_eq!(described(&inner, root).as_deref(), Some("default"));
    let (hubs, members) = listing(&inner, root);
    assert_eq!(hubs.len(), 1);
    assert_eq!(members.len(), 2);
    assert!(members.iter().all(|member| member["instance"].is_string() && member["gridId"].is_string()));
    let theirs_listed = members.iter().find(|member| member["instance"] == theirs.key()).unwrap();
    assert_eq!(theirs_listed["mcp"], json!({"name": format!("yougori-access-{}", theirs.key()), "command": "yougori", "args": ["access", "mcp", "--grid", globex_id]}));

    // Signing in to Globex again goes back to its own instance, which may renew its own token.
    let fingerprint = net::normalize_fingerprint(&globex_invite.fingerprint).unwrap();
    assert_eq!(slot_for_member(&inner, root, &vault, &fingerprint).unwrap(), (theirs.clone(), true));

    // Signing out of Globex forgets only Globex: Acme's token and sign-in stay.
    {
        let instance = inner.instances.get_mut(theirs.key()).unwrap();
        forget(&theirs, instance, &vault);
    }
    drop_if_empty(&mut inner, &theirs);
    assert!(vault.get(&theirs.names().device).is_none());
    assert_eq!(vault.get(&mine.names().device), Some(one));
    assert!(!theirs.folder().exists() && !inner.instances.contains_key(theirs.key()));
    // One grid left: a command needs no grid named again.
    assert_eq!(choose(&inner, root, None).unwrap(), "default");
}

#[test]
fn with_one_grid_no_id_is_needed_and_with_none_the_old_behaviour_holds() {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path();
    let mut inner = inner();
    // Nothing here: the default instance, exactly as before there could be several.
    assert_eq!(choose(&inner, root, None).unwrap(), "default");
    assert_eq!(described(&inner, root), None);
    // Only a sign-in in another instance: that one, without naming it.
    let layout = Layout::new(root, "i-0a0b0c0d").unwrap();
    std::fs::create_dir_all(layout.folder()).unwrap();
    std::fs::write(layout.member(), "{}").unwrap();
    inner.instances.entry(layout.key().to_owned()).or_default();
    assert_eq!(choose(&inner, root, None).unwrap(), "i-0a0b0c0d");
    assert_eq!(described(&inner, root).as_deref(), Some("i-0a0b0c0d"));
}

#[test]
fn an_approver_in_two_grids_is_told_about_each_grids_requests_once() {
    let waiting = |ids: &[&str]| json!({"person": {"permission": "approver", "username": "ada"}, "overview": {"waiting": ids.iter().map(|id| json!({"id": id, "person": "bob"})).collect::<Vec<_>>()}});
    let (mut acme, mut globex) = (HashSet::new(), HashSet::new());
    assert_eq!(fresh_waiting(&waiting(&["req-1"]), &mut acme), 1);
    assert_eq!(fresh_waiting(&waiting(&["req-1"]), &mut acme), 0, "told once");
    // The same id at another grid is another request, and its approver hears of it.
    assert_eq!(fresh_waiting(&waiting(&["req-1", "req-2"]), &mut globex), 2);
    assert_eq!(fresh_waiting(&waiting(&["req-3"]), &mut acme), 1);
    assert!(!acme.contains("req-2"));
    // A member is never told, and their own request is not news unless they may approve it.
    assert_eq!(fresh_waiting(&json!({"person": {"permission": "member"}, "overview": {"waiting": [{"id": "req-9"}]}}), &mut acme), 0);
    assert_eq!(fresh_waiting(&json!({"person": {"permission": "admin", "username": "ada"}, "overview": {"waiting": [{"id": "req-8", "person": "ada"}]}}), &mut acme), 0);
}

#[tokio::test]
async fn a_backup_is_restored_only_into_an_instance_of_its_own_and_never_over_another_seal() {
    let folder = tempfile::tempdir().unwrap();
    let root = folder.path();
    let vault = FakeVault::default();
    let mut inner = inner();
    let acme = host(&mut inner, root, &vault, "Acme").await;
    hub(&inner, &acme).manage_as_owner(json!({"action": "credentialAdd", "name": "GitHub", "kind": "bearer", "destinations": ["https://api.github.com"], "value": SECRET})).unwrap();
    let globex = host(&mut inner, root, &vault, "Globex").await;
    let passphrase = "a long backup passphrase";
    let acme_backup = backup::open(&backup_bytes(&acme, &vault, passphrase.into()).await.unwrap(), passphrase).unwrap();
    // A backup carries its own grid and its own seal, not the other grid's.
    assert_eq!(acme_backup.record["company"].as_str(), Some("Acme"));
    assert_eq!(acme_backup.seal_key, vault.get("yougori-access-hub-seal").unwrap());
    assert_ne!(acme_backup.seal_key, vault.get(&globex.names().seal_key).unwrap());
    assert_eq!(acme_backup.activity, std::fs::read_to_string(acme.activity()).unwrap());
    let acme_id = acme_backup.record["id"].as_str().unwrap().to_owned();
    let fingerprint = net::normalize_fingerprint(&net::fingerprint(acme_backup.record["certificate"].as_str().unwrap()).unwrap()).unwrap();

    // The same grid is never restored beside itself.
    assert!(restore_slot(&inner, root, &vault, &acme_id, Some(&fingerprint), None).unwrap_err().contains("already runs Acme's Access Grid"));

    // On another computer that already runs a grid of its own, Acme comes back in a new
    // instance: its seal under that instance's names, the other grid's seal untouched.
    let elsewhere = tempfile::tempdir().unwrap();
    let there = elsewhere.path();
    let their_vault = FakeVault::default();
    let mut theirs = self::inner();
    let initech = host(&mut theirs, there, &their_vault, "Initech").await;
    let initech_seal = their_vault.get("yougori-access-hub-seal").unwrap();
    // Not into the instance that runs Initech.
    assert!(restore_slot(&theirs, there, &their_vault, &acme_id, Some(&fingerprint), Some(initech.key())).unwrap_err().contains("already runs a hub here"));
    let target = restore_slot(&theirs, there, &their_vault, &acme_id, Some(&fingerprint), None).unwrap();
    assert!(!target.is_default());
    let ports = (free_port(), free_port());
    let record = install_backup(&target, &their_vault, &acme_backup, loopback(), Some(ports)).unwrap();
    assert_eq!((record.company.as_str(), record.port), ("Acme", ports.0));
    assert_eq!(their_vault.get("yougori-access-hub-seal").as_deref(), Some(initech_seal.as_str()));
    assert_eq!(their_vault.get(&target.names().seal_key).as_deref(), Some(acme_backup.seal_key.as_str()));
    assert_eq!(open_sealed(&target, &acme_backup.seal_key).unwrap(), SECRET);
    let mut restored = Instance::default();
    load(&target, &mut restored, &their_vault).await;
    assert_eq!(restored.hub.as_ref().map(|hub| hub.address().port()), Some(ports.0));
    assert_eq!(std::fs::read_to_string(target.activity()).unwrap(), acme_backup.activity);

    // A target whose names the vault already holds is refused with nothing written.
    let crowded = instances::fresh(there, |name| held(&their_vault, name)).unwrap();
    their_vault.put(&crowded.names().seal_key, "kept-as-it-is");
    let before = their_vault.names();
    assert!(install_backup(&crowded, &their_vault, &acme_backup, loopback(), Some((free_port(), free_port()))).err().unwrap().contains("already holds a key"));
    assert_eq!(their_vault.names(), before);
    assert_eq!(their_vault.get(&crowded.names().seal_key).as_deref(), Some("kept-as-it-is"));
    assert!(!crowded.hub().exists());

    // A computer signed in to Acme restores Acme into that same instance.
    let member_only = tempfile::tempdir().unwrap();
    let signed = Layout::new(member_only.path(), "i-1234abcd").unwrap();
    std::fs::create_dir_all(signed.folder()).unwrap();
    let saved = json!({"version": 2, "accessId": acme_id, "company": "Acme", "address": "10.0.0.5:7465", "certificate": "", "fingerprint": fingerprint, "username": "ada", "personId": "p", "signedInAt": 1});
    std::fs::write(signed.member(), saved.to_string()).unwrap();
    let mut held_here = self::inner();
    let instance = held_here.instances.entry(signed.key().to_owned()).or_default();
    instance.member = read_member(&signed).unwrap();
    assert_eq!(restore_slot(&held_here, member_only.path(), &FakeVault::default(), &acme_id, Some(&fingerprint), None).unwrap(), signed);
}

#[test]
fn another_instance_gets_ports_of_its_own_outside_the_fixed_ones() {
    let folder = tempfile::tempdir().unwrap();
    let layout = Layout::new(folder.path(), "i-abcdef01").unwrap();
    let (port, tunnel, allocated) = hub_ports(&layout, folder.path()).unwrap();
    crate::grid::instances::release_ports(&allocated);
    assert_eq!(allocated, [port, tunnel]);
    for chosen in [port, tunnel] {
        assert!((7480..=7599).contains(&chosen) && !(7460..=7467).contains(&chosen), "{chosen}");
    }
    assert_ne!(port, tunnel);
}
