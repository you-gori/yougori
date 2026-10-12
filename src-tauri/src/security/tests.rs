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
