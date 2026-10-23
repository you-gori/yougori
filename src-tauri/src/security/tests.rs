use super::*;

fn environment(id: &str, kind: &str, provider: &str, status: &str) -> Environment {
    serde_json::from_value(json!({
        "id": id, "name": format!("name-{id}"), "kind": kind, "provider": provider, "status": status,
        "runtime": "docker.io/library/alpine:3.24", "description": "", "createdAt": "2026-10-11T00:00:00Z",
        "cpuUsage": 0.0, "memoryUsageGb": 0.0, "storageDeltaGb": 0.0, "networkRxMbps": 0.0, "networkAccess": true,
        "resourcePolicy": {"cpu": {"min": 1, "preferred": 2, "max": 2, "current": 2}, "memoryGb": {"min": 1, "preferred": 4, "max": 4, "current": 4}, "priority": "normal"},
    }))
    .unwrap()
}

fn state(environments: Vec<Environment>) -> PlatformState {
    let mut state = PlatformState::empty().unwrap();
    state.environments = environments;
    state
}

fn summary(environments: &[Environment]) -> Vec<Recorded> {
    environments.iter().map(Recorded::of).collect()
}

fn kinds(events: &[Event]) -> Vec<(&'static str, Option<String>)> {
    events.iter().map(|event| (event.kind(), event.environment().map(str::to_owned))).collect()
}

#[test]
fn committed_state_changes_become_lifecycle_events() {
    let web = environment("env-web", "container", "yougoriOci", "stopped");
    let vm = environment("env-vm", "microVm", "qemu", "running");
    let before = summary(&[web.clone(), vm.clone()]);
    let mut started = web.clone();
    started.status = EnvironmentStatus::Running;
    started.network_access = false;
    let mut paused = vm.clone();
    paused.status = EnvironmentStatus::Paused;
    let created = environment("env-new", "fullVm", "qemu", "provisioning");
    let events = lifecycle_events(&before, &state(vec![started, paused, created]));
    assert_eq!(kinds(&events), vec![
        ("environment.started", Some("env-web".into())),
        ("environment.internet", Some("env-web".into())),
        ("environment.paused", Some("env-vm".into())),
        ("environment.created", Some("env-new".into())),
    ]);
    let events = lifecycle_events(&summary(&[web.clone()]), &state(vec![]));
    assert_eq!(kinds(&events), vec![("environment.deleted", Some("env-web".into()))]);
    let mut resumed = vm.clone();
    resumed.status = EnvironmentStatus::Running;
    let mut was_paused = vm.clone();
    was_paused.status = EnvironmentStatus::Paused;
    assert_eq!(kinds(&lifecycle_events(&summary(&[was_paused]), &state(vec![resumed]))), vec![("environment.resumed", Some("env-vm".into()))]);
}

#[test]
fn imported_shared_environments_record_only_their_import_and_removal() {
    let mut shared = environment("env-shared", "cloud", "cloudSsh", "running");
    shared.runtime = "shared://192.168.1.20:4444".into();
    let mut stopped = shared.clone();
    stopped.status = EnvironmentStatus::Stopped;
    assert!(lifecycle_events(&summary(&[shared.clone()]), &state(vec![stopped])).is_empty());
    assert_eq!(kinds(&lifecycle_events(&[], &state(vec![shared]))), vec![("environment.created", Some("env-shared".into()))]);
}

#[test]
fn since_accepts_times_dates_and_durations() {
    let now = DateTime::parse_from_rfc3339("2026-10-11T12:00:00Z").unwrap().with_timezone(&Utc);
    assert_eq!(parse_since("2026-10-11T08:30:00Z", now).unwrap().to_rfc3339(), "2026-10-11T08:30:00+00:00");
    assert_eq!(parse_since("2026-10-10", now).unwrap().to_rfc3339(), "2026-10-10T00:00:00+00:00");
    assert_eq!(parse_since("90s", now).unwrap().to_rfc3339(), "2026-10-11T11:58:30+00:00");
    assert_eq!(parse_since("2h", now).unwrap().to_rfc3339(), "2026-10-11T10:00:00+00:00");
    assert_eq!(parse_since("7d", now).unwrap().to_rfc3339(), "2026-10-04T12:00:00+00:00");
    for bad in ["", "yesterday", "0m", "-5m", "5w", "99999999d", "h"] {
        assert!(parse_since(bad, now).is_err(), "{bad}");
    }
}

#[test]
fn terminal_owners_map_to_who_opened_them() {
    assert_eq!(terminal_actor("cli"), "cli");
    assert_eq!(terminal_actor("remote-0123"), "remote");
    assert_eq!(terminal_actor("share-0123"), "lan");
    assert_eq!(terminal_actor("environment-env-1"), "app");
    assert_eq!(terminal_actor("main"), "app");
}

#[test]
fn only_local_runtimes_can_be_contained() {
    assert!(controllable(&environment("a", "container", "yougoriOci", "running")).is_ok());
    assert!(controllable(&environment("b", "container", "yougoriCuda", "stopped")).is_ok());
    assert!(controllable(&environment("c", "microVm", "qemu", "running")).is_ok());
    assert!(controllable(&environment("d", "fullVm", "qemu", "paused")).is_ok());
    assert!(controllable(&environment("e", "cloud", "cloudSsh", "running")).is_err());
    assert!(controllable(&environment("f", "computerBranch", "nativeSandbox", "running")).is_err());
    let mut shared = environment("g", "container", "yougoriOci", "running");
    shared.runtime = "shared://10.0.0.2:1".into();
    assert!(controllable(&shared).is_err());
}

#[test]
fn usage_is_measured_against_the_allocation() {
    let mut container = environment("a", "container", "yougoriOci", "running");
    container.cpu_usage = 200.0;
    container.memory_usage_gb = 3.0;
    assert_eq!(usage(&container), (Some(1.0), Some(0.75)));
    let mut vm = environment("b", "microVm", "qemu", "running");
    vm.cpu_usage = 50.0;
    vm.memory_usage_gb = 4.0;
    assert_eq!(usage(&vm), (Some(0.5), None), "guest page cache makes VM memory meaningless");
    assert_eq!(usage(&environment("c", "cloud", "cloudSsh", "running")), (None, None));
}

#[test]
fn denial_windows_are_aggregated_without_link_chatter() {
    let stats = network::FilterStats::default();
    let host = std::collections::HashSet::new();
    let guest = [10, 0, 2, 15];
    for port in [22, 5900, 4444] {
        stats.denied(&network::tests::frame(guest, [10, 0, 2, 2], 6, 40000, port, 2), &host, true);
    }
    stats.denied(&network::tests::frame(guest, [224, 0, 0, 251], 17, 5353, 5353, 0), &host, true);
    let window = stats.drain().window;
    let mut denials = HashMap::new();
    accumulate(&mut denials, "env-a", &window, 100);
    let entry = &denials["env-a"];
    assert_eq!(entry.counts.get("hostPort"), Some(&3));
    assert!(!entry.counts.contains_key("ignored"));
    assert_eq!(entry.host_ports.len(), 3);
    accumulate(&mut denials, "env-b", &network::Window::default(), 100);
    assert!(!denials.contains_key("env-b"));
}

/// The engine's containment records, opened on a scratch file if no other test opened them.
/// A temporary folder of its own, removed when the test process ends rather than left in the
/// system temp folder for every run to add to.
fn containment_folder() -> &'static tempfile::TempDir {
    static FOLDER: std::sync::OnceLock<tempfile::TempDir> = std::sync::OnceLock::new();
    FOLDER.get_or_init(|| tempfile::tempdir().expect("a temporary folder for the containment tests"))
}

fn containment_records() -> &'static containment::Store {
    CONTAINMENT.get_or_init(|| containment::Store::load(&containment_folder().path().join("state.json")))
}

#[test]
fn records_that_cannot_be_read_lock_everything_down_rather_than_opening_it() {
    let folder = tempfile::tempdir().unwrap();
    // No file at all is the ordinary first run: nothing has ever been locked down.
    let fresh = containment::Store::load(&folder.path().join("state.json"));
    assert!(!fresh.contains("env-1"), "a first run must not lock anything down");
    // A file that is there but cannot be read is the dangerous case. Answering "not contained"
    // would silently lift every lockdown on this computer, so it answers the other way.
    let broken = folder.path().join("broken.json");
    std::fs::write(&broken, b"{ this is not the file we wrote").unwrap();
    let store = containment::Store::load(&broken);
    assert!(store.contains("env-1"), "unreadable records must count as contained");
    assert!(store.contains("any-environment-at-all"));
    let said = store.get("env-1").expect("a reason to show the person");
    assert!(said.reason.contains("could not read"), "{}", said.reason);
    assert!(store.unreadable());
    // Nothing may be written over records we could not read. The in-memory map is empty, so
    // saving it would replace a file full of lockdowns with one entry — losing the very thing
    // this is protecting, and from a read that may only have failed for a moment. A containment
    // applied now goes BESIDE the file instead, so the act is not forgotten and the file is safe.
    let record = containment::Containment { level: Level::Lockdown, since: "2026-10-20T00:00:00Z".into(), reason: "test".into(), via: "policy".into(), rule: None, restore_internet: false, resume: false };
    store.set("env-1", Some(record)).expect("a containment is recorded beside the unreadable file");
    assert_eq!(std::fs::read(&broken).unwrap(), b"{ this is not the file we wrote", "the file on disk is untouched");
    assert!(std::path::Path::new(&store.beside_path("env-1")).is_file(), "it went to {}", store.beside_path("env-1"));
    // Clearing one is still refused: we do not know what is locked, so we cannot say it is not.
    assert!(store.set("env-1", None).is_err());
    // The refusal a person sees must not send them to unlock, which cannot work here, and must
    // not print an empty date.
    let shown = containment::refusal("Alpha", "env-1", &said, "Starting it");
    assert!(!shown.contains("yougori unlock"), "{shown}");
    assert!(!shown.contains("since ."), "{shown}");
    assert!(shown.contains("broken.json"), "the way out must name the file: {shown}");
    // A sweep must not report that it tidied up records it cannot see.
    assert!(store.retain(&[]).is_err());
}

fn cut_off(id: &str) {
    let record = containment::Containment { level: Level::InternetCut, since: "2026-10-20T00:00:00Z".into(), reason: "test".into(), via: "policy".into(), rule: None, restore_internet: true, resume: false };
    containment_records().set(id, Some(record)).unwrap();
}

#[tokio::test]
async fn a_contained_environment_answers_no_new_connection_and_closes_open_ones() {
    containment_records();
    let id = "env-containment-links";
    // Open: a connection runs to the end.
    assert_eq!(while_open(id, async { 7 }).await, Some(7));
    // A connection still open when the kill switch fires is closed within a second.
    let open = tokio::spawn(async move { while_open(id, std::future::pending::<()>()).await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    cut_off(id);
    let closed = tokio::time::timeout(Duration::from_secs(2), open).await.expect("the open connection closes").unwrap();
    assert_eq!(closed, None);
    // While it is contained a new one is refused at once.
    assert_eq!(while_open(id, async { 7 }).await, None);
    // Unlocked, the same link answers again.
    containment_records().set(id, None).unwrap();
    assert_eq!(while_open(id, async { 7 }).await, Some(7));
}
