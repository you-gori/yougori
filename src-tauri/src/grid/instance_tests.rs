//! Several Neo Grids on one computer, on temporary state only: no real data folder and no OS
//! vault (key names are checked as names; nothing is stored).
use super::*;

const PASSWORD: &str = "correct horse battery staple";

fn saved(grid_id: &str, name: &str, environment: Option<&str>) -> Saved {
    serde_json::from_value(json!({
        "version": 1, "gridId": grid_id, "gridName": name, "address": "10.0.0.5:7460", "certificate": "", "fingerprint": "",
        "memberId": format!("member-{grid_id}"), "joinedAt": 0, "environmentId": environment, "managed": environment.is_some(), "created": environment.is_some(),
    }))
    .unwrap()
}

fn member(grid_id: &str, name: &str) -> Slot {
    Slot { loaded: true, member_settled: true, member: Some(saved(grid_id, name, None)), ..Slot::default() }
}

fn hub_record(grid_id: &str, name: &str) -> Slot {
    Slot { loaded: true, hub_label: Some((grid_id.into(), name.into())), ..Slot::default() }
}

const SECOND: &str = "i-0000beef";
const THIRD: &str = "i-0000cafe";

#[test]
fn the_default_grid_keeps_every_old_name_and_a_second_gets_its_own() {
    let grid = std::path::Path::new("data").join("grid");
    for (file, legacy) in [("hub.json", "hub.json"), ("member.json", "member.json"), ("tunnel.json", "tunnel.json")] {
        assert_eq!(instances::file(&grid, DEFAULT, file), grid.join(legacy), "existing installations are read under their old names");
        assert_eq!(instances::file(&grid, SECOND, file), grid.join("neo").join(SECOND).join(file));
    }
    assert_eq!(vault(HUB_KEY, DEFAULT), "yougori-grid-hub-key");
    assert_eq!(vault(HUB_PASSWORD, DEFAULT), "yougori-grid-hub-password");
    assert_eq!(vault(MEMBER_TOKEN, DEFAULT), "yougori-grid-member-token");
    let mut names: Vec<String> = [DEFAULT, SECOND].iter().flat_map(|instance| [HUB_KEY, HUB_PASSWORD, MEMBER_TOKEN].map(|base| vault(base, instance))).collect();
    assert_eq!(names[3], format!("yougori-grid-hub-key-{SECOND}"));
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 6, "a second hub's keys never overwrite the first's");
}

#[test]
fn an_older_builds_membership_is_still_read_from_its_old_place() {
    let root = tempfile::tempdir().unwrap();
    let grid = root.path().join("grid");
    std::fs::create_dir_all(&grid).unwrap();
    // Exactly what 1.1.2 writes, field for field.
    std::fs::write(grid.join("member.json"), r#"{"version":1,"gridId":"grid-a","gridName":"Acme","address":"10.0.0.5:7460","certificate":"","fingerprint":"AB","memberId":"m","joinedAt":0,"managed":false,"created":false,"parked":false}"#).unwrap();
    assert_eq!(instances::on_disk(&grid), [DEFAULT]);
    let read: Saved = serde_json::from_slice(&std::fs::read(instances::file(&grid, DEFAULT, "member.json")).unwrap()).unwrap();
    assert_eq!((read.grid_id.as_str(), read.grid_name.as_str()), ("grid-a", "Acme"));
}

#[test]
fn a_command_about_one_grid_defaults_to_it_and_refuses_when_there_are_several() {
    let mut slots = BTreeMap::from([(DEFAULT.to_owned(), member("grid-a", "Acme"))]);
    let none = BTreeSet::new();
    let pick = |slots: &BTreeMap<String, Slot>, role, id: Option<&str>, files: &BTreeSet<String>| choose(&candidates(slots, role, files), |id| lookup(slots, id).is_some(), id, "none here");
    assert_eq!(pick(&slots, Role::Member, None, &none).unwrap(), DEFAULT, "one grid: no ID needed, exactly as before");
    assert_eq!(pick(&slots, Role::Hub, None, &none).unwrap_err(), "none here", "the old words when no grid can answer");
    slots.insert(SECOND.into(), member("grid-b", "Beta"));
    assert_eq!(
        pick(&slots, Role::Member, None, &none).unwrap_err(),
        "There are 2 Neo Grids on this computer: Acme (grid-a), Beta (grid-b). Say which with gridId."
    );
    assert_eq!(pick(&slots, Role::Member, Some("grid-b"), &none).unwrap(), SECOND, "by the grid's ID");
    assert_eq!(pick(&slots, Role::Member, Some(SECOND), &none).unwrap(), SECOND, "by the instance key");
    assert_eq!(pick(&slots, Role::Member, Some(" grid-a "), &none).unwrap(), DEFAULT);
    let unknown = pick(&slots, Role::Member, Some("grid-z"), &none).unwrap_err();
    assert!(unknown.contains("No Neo Grid on this computer has the ID grid-z") && unknown.contains("yougori grid status"), "{unknown}");
    assert_eq!(pick(&slots, Role::Hub, Some("grid-b"), &none).unwrap_err(), "none here", "a grid this computer only joined has no hub here");
    // A hub whose record is on disk but has not started can still be named, and deleted.
    slots.insert(THIRD.into(), hub_record("grid-c", "Coral"));
    let files = BTreeSet::from([THIRD.to_owned()]);
    assert_eq!(pick(&slots, Role::Hub, None, &files).unwrap(), THIRD);
    assert_eq!(pick(&slots, Role::Hub, None, &none).unwrap_err(), "none here", "no record, no hub");
}

#[test]
fn the_first_grid_keeps_the_legacy_layout_and_later_ones_get_their_own() {
    let empty = BTreeMap::new();
    let none = BTreeSet::new();
    assert_eq!(hub_target(&empty, &none), DEFAULT, "a computer's first grid is where older builds look for it");
    let mut slots = BTreeMap::from([(DEFAULT.to_owned(), member("grid-a", "Acme"))]);
    let second = hub_target(&slots, &none);
    assert!(second != DEFAULT && instances::is_key(&second), "{second}");
    assert!(instances::is_key(&hub_target(&empty, &BTreeSet::from([DEFAULT.to_owned()]))), "a membership on disk the vault has not given yet still holds default");
    // Joining: a grid this computer is already in is refused, whichever instance holds it.
    let refused = member_target(&slots, &none, None, "grid-a").unwrap_err();
    assert!(refused.contains("already in Acme's grid"), "{refused}");
    let joined = member_target(&slots, &none, None, "grid-b").unwrap();
    assert!(joined != DEFAULT && instances::is_key(&joined), "another grid becomes another instance");
    assert_eq!(member_target(&slots, &none, Some(SECOND), "grid-new").unwrap(), SECOND, "the hub just created here takes its own membership");
    slots.insert(THIRD.into(), hub_record("grid-c", "Coral"));
    assert_eq!(member_target(&slots, &none, None, "grid-c").unwrap(), THIRD, "a hub this computer runs takes its membership back");
    let free = BTreeMap::from([(DEFAULT.to_owned(), Slot { loaded: true, ..Slot::default() })]);
    assert_eq!(member_target(&free, &none, None, "grid-b").unwrap(), DEFAULT);
}

#[test]
fn a_model_one_grid_retires_is_kept_while_another_grid_on_this_computer_uses_it() {
    let mut slots = BTreeMap::from([
        (DEFAULT.to_owned(), Slot { member: Some(saved("grid-a", "Acme", Some("env-1"))), ..Slot::default() }),
        (SECOND.to_owned(), Slot { member: Some(Saved { managed: false, created: false, ..saved("grid-b", "Beta", Some("env-1")) }), ..Slot::default() }),
    ]);
    assert_eq!(keeper(&slots, DEFAULT, "env-1").as_deref(), Some(SECOND));
    assert_eq!(keeper(&slots, SECOND, "env-1").as_deref(), Some(DEFAULT));
    assert_eq!(keeper(&slots, DEFAULT, "env-2"), None);
    assert_eq!(borrowed(&slots, THIRD, "env-1", true, true), (false, false), "an environment another grid uses is borrowed, never this grid's to stop or delete");
    assert_eq!(borrowed(&slots, THIRD, "env-9", true, true), (true, true));
    let (left, kept) = hand_over_in(&mut slots, DEFAULT, Some(Retire::Delete("env-1".into())));
    assert!(left.is_none(), "nothing is stopped or deleted under the other grid");
    assert_eq!(kept, Some((SECOND.to_owned(), "env-1".to_owned())));
    let taker = slots[SECOND].member.as_ref().unwrap();
    assert!(taker.managed && taker.created, "the grid still using it takes it over, and deletes it once it is done");
    let (left, kept) = hand_over_in(&mut slots, DEFAULT, Some(Retire::Stop("env-2".into())));
    assert!(matches!(left, Some(Retire::Stop(id)) if id == "env-2") && kept.is_none(), "one nobody else uses is retired as before");
    assert!(matches!(hand_over_in(&mut slots, DEFAULT, None), (None, None)));
}

#[test]
fn status_keeps_its_old_fields_and_lists_every_grid() {
    let mut inner = Inner::default();
    inner.slots.insert(DEFAULT.into(), member("grid-a", "Acme"));
    inner.slots.insert(SECOND.into(), Slot { hub_error: Some("The grid hub's keys could not be read yet".into()), ..hub_record("grid-b", "Beta") });
    inner.slots.insert(THIRD.into(), member("grid-c", "Coral"));
    assert_eq!(primary(&inner.slots), DEFAULT);
    let status = status_of(&inner, &primary(&inner.slots));
    assert_eq!(status["instance"], DEFAULT);
    assert_eq!(status["member"]["gridId"], "grid-a", "member describes the default grid, as it always did");
    assert!(status["hub"].is_null() && status["hubError"].is_null());
    let hubs = status["hubs"].as_array().unwrap();
    assert_eq!(hubs.len(), 1);
    assert_eq!((hubs[0]["instance"].as_str(), hubs[0]["gridId"].as_str(), hubs[0]["name"].as_str()), (Some(SECOND), Some("grid-b"), Some("Beta")));
    assert!(hubs[0]["error"].as_str().unwrap().contains("could not be read"), "a hub that has not started is listed, never left out");
    let members: Vec<(&str, &str)> = status["members"].as_array().unwrap().iter().map(|entry| (entry["instance"].as_str().unwrap(), entry["gridId"].as_str().unwrap())).collect();
    assert_eq!(members, [(DEFAULT, "grid-a"), (THIRD, "grid-c")]);
    // The grid an ID names fills the old fields.
    assert_eq!(lookup(&inner.slots, "grid-b").as_deref(), Some(SECOND));
    assert_eq!(lookup(&inner.slots, THIRD).as_deref(), Some(THIRD));
    assert_eq!(lookup(&inner.slots, "grid-z"), None);
    let chosen = status_of(&inner, SECOND);
    assert_eq!(chosen["hubError"], "The grid hub's keys could not be read yet");
    assert!(chosen["member"].is_null());
    // With nothing in default, the first grid that holds something fills them.
    inner.slots.insert(DEFAULT.into(), Slot::default());
    assert_eq!(primary(&inner.slots), SECOND);
    assert_eq!(primary(&BTreeMap::new()), DEFAULT);
}

#[test]
fn every_membership_checks_in() {
    let key = rcgen::generate_simple_self_signed(vec!["127.0.0.1".into()]).unwrap();
    let membership = |id: &str| Membership::new(HubAddress::Direct("127.0.0.1:7480".parse().unwrap()), &key.cert.pem(), id.into(), "token".into()).unwrap();
    let mut slots = BTreeMap::from([
        (DEFAULT.to_owned(), Slot { membership: Some(membership("a")), ..member("grid-a", "Acme") }),
        (SECOND.to_owned(), Slot { membership: Some(membership("b")), ..member("grid-b", "Beta") }),
        (THIRD.to_owned(), hub_record("grid-c", "Coral")),
    ]);
    assert_eq!(checking_in(&slots), [DEFAULT, SECOND], "the tick loop covers every grid this computer is in");
    slots.get_mut(DEFAULT).unwrap().membership = None;
    assert_eq!(checking_in(&slots), [SECOND], "a membership the vault has not given yet waits");
}

/// Two real hubs on loopback, on temporary records: separate listeners and ports, separate
/// records and IDs, and a computer in both at once, checking in with each.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_hubs_and_two_memberships_run_side_by_side() {
    let root = tempfile::tempdir().unwrap();
    let grid = root.path().join("grid");
    let salt = password::new_salt();
    let password_key = password::derive(PASSWORD, &salt).unwrap();
    let quiet: hub::Events = Arc::new(|_: &'static str, _: Value| {});
    // The first hub keeps the legacy files. Port 0 stands in for 7460, which this computer may
    // be using for real.
    let first_path = instances::file(&grid, DEFAULT, "hub.json");
    let first_key = hub::create(&first_path, "Acme", "127.0.0.1".parse().unwrap(), 0, None, None, &salt).unwrap();
    let first = Hub::start(first_path.clone(), &first_key, &password_key, quiet.clone()).await.unwrap();
    // The second gets an instance of its own and ports from the shared range.
    let ports = instances::allocate_ports(&grid, 2).unwrap();
    let second_path = instances::file(&grid, SECOND, "hub.json");
    let second_key = hub::create(&second_path, "Beta", "127.0.0.1".parse().unwrap(), ports[0], None, Some(ports[1]), &salt).unwrap();
    let second = Hub::start(second_path.clone(), &second_key, &password_key, quiet).await.unwrap();
    instances::release_ports(&ports);
    assert_eq!(second.address().port(), ports[0]);
    assert_eq!(second.tunnel_address().map(|entry| entry.port()), Some(ports[1]));
    assert_ne!(first.address(), second.address(), "two listeners");
    assert!(ports.iter().all(|port| (instances::FIRST_PORT..=instances::LAST_PORT).contains(port) && !instances::FIXED_PORTS.contains(port)));
    let recorded = instances::recorded_ports(&grid);
    assert!(recorded.contains(&ports[0]) && recorded.contains(&ports[1]), "the record keeps its ports out of the next allocation");
    let next = instances::allocate_ports(&grid, 2).unwrap();
    instances::release_ports(&next);
    assert!(next.iter().all(|port| !ports.contains(port)));
    let (first_record, second_record) = (first.record(), second.record());
    assert_ne!(first_record.id, second_record.id);
    assert_eq!(hub::load(&grid.join("hub.json")).unwrap().id, first_record.id, "the first grid is read where it always was");
    assert_eq!(instances::on_disk(&grid), [DEFAULT, SECOND]);

    // This computer joins both, each membership in its grid's instance.
    let mut slots = BTreeMap::new();
    for (instance, hub, company) in [(DEFAULT, &first, "Acme"), (SECOND, &second, "Beta")] {
        let joined = member::join(company, HubAddress::Direct(hub.address()), PASSWORD, "Laptop", "windows", true, None).await.unwrap();
        let place = member_target(&slots, &BTreeSet::new(), Some(instance), &joined.grid_id).unwrap();
        assert_eq!(place, instance);
        let saved = Saved { address: hub.address().to_string(), fingerprint: joined.fingerprint.clone(), certificate: joined.certificate.clone(), member_id: joined.membership.member_id.clone(), ..saved(&joined.grid_id, &joined.grid_name, None) };
        let path = instances::file(&grid, instance, "member.json");
        std::fs::write(&path, serde_json::to_vec(&saved).unwrap()).unwrap();
        slots.insert(instance.to_owned(), Slot { loaded: true, member_settled: true, hub_label: Some((hub.record().id, company.into())), member: Some(saved), membership: Some(joined.membership), ..Slot::default() });
    }
    assert_ne!(slots[DEFAULT].member.as_ref().unwrap().member_id, slots[SECOND].member.as_ref().unwrap().member_id);
    // Joining the first grid again, through any instance, is refused.
    let again = member_target(&slots, &BTreeSet::new(), None, &first_record.id).unwrap_err();
    assert!(again.contains("already in Acme's grid"), "{again}");
    // Each checks in with its own hub.
    for instance in checking_in(&slots) {
        let membership = slots[&instance].membership.clone().unwrap();
        let answered = membership.heartbeat("test", true, &[]).await.unwrap();
        assert_eq!(answered.grid_name, slots[&instance].member.as_ref().unwrap().grid_name);
    }
    let mut inner = Inner { slots, ..Inner::default() };
    inner.slots.get_mut(DEFAULT).unwrap().hub = Some(first);
    inner.slots.get_mut(SECOND).unwrap().hub = Some(second);
    let status = status_of(&inner, &primary(&inner.slots));
    assert_eq!(status["hub"]["id"], first_record.id.as_str(), "the old field still describes the first grid");
    let hubs: Vec<(String, String)> = status["hubs"].as_array().unwrap().iter().map(|hub| (hub["instance"].as_str().unwrap().to_owned(), hub["gridId"].as_str().unwrap().to_owned())).collect();
    assert_eq!(hubs, [(DEFAULT.to_owned(), first_record.id.clone()), (SECOND.to_owned(), second_record.id.clone())]);
    assert_eq!(status["members"].as_array().unwrap().len(), 2);
    let files = BTreeSet::from([DEFAULT.to_owned(), SECOND.to_owned()]);
    let found = candidates(&inner.slots, Role::Hub, &files);
    let refused = choose(&found, |_| true, None, NO_HUB).unwrap_err();
    assert!(refused.starts_with("There are 2 Neo Grids on this computer: Acme (grid-") && refused.ends_with("Say which with gridId."), "{refused}");
    assert_eq!(choose(&found, |_| true, Some(&second_record.id), NO_HUB).unwrap(), SECOND);
}
