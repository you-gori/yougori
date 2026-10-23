//! What a realm says about itself, and what each number does not mean.
use super::*;
use crate::core::identity::{Action, PrincipalKind, Role};
use crate::core::realm::{Capability, RealmKind};
use crate::core::work::{Commitment, Kind, Resources, Workload};

fn key() -> String {
    "d".repeat(64)
}

fn room() -> Resources {
    Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 200.0, gpu: true, vram_gb: 16.0 }
}

fn little() -> Resources {
    Resources { cpu: 1.0, memory_gb: 2.0, disk_gb: 5.0, gpu: false, vram_gb: 0.0 }
}

fn company(folder: &std::path::Path, now: i64) -> (Core, String, String, String) {
    let mut core = Core::create(&folder.join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Credentials], &key(), now).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let (device, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    let host = core.offer_host(&device.id, "Studio PC", room(), room(), Commitment::Share, now).unwrap();
    (core, person.id, device.id, host.id)
}

#[test]
fn a_reading_counts_the_queue_the_reservations_and_the_computers() {
    let folder = tempfile::tempdir().unwrap();
    let now = 60_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    let work = core.submit(Workload::new(&core.realm().id.clone(), Capability::Models, Kind::Inference, &person, &device, little(), 1, now), now).unwrap();

    let reading = core.reading(now).unwrap();
    assert_eq!(reading.queue.queued, 1, "one piece of work is waiting");
    assert_eq!(reading.queue.total(), 1);
    assert_eq!(reading.hosts.offering, 1);
    assert_eq!(reading.hosts.taking_work, 1);
    assert_eq!(reading.live_leases, 0);
    assert_eq!(reading.counts.people, 1);
    assert_eq!(reading.counts.devices, 1);

    core.grant_lease(&work.id, 600, now).unwrap();
    let (reading, cost) = crate::core::bench::cost_of(core.store_for_tests(), || core.reading(now + 30).unwrap());
    assert_eq!(cost.statements, 12, "a reading is twelve statements, which is the number the operations document carries");
    assert_eq!(reading.queue.queued, 0);
    assert_eq!(reading.queue.leased, 1);
    assert_eq!(reading.live_leases, 1);
    assert_eq!(reading.oldest_lease_age, 30, "the oldest reservation was granted thirty seconds ago");
}

#[test]
fn computers_heard_from_recently_counts_only_what_writes_that_time() {
    // The honest caveat, as a test rather than as a sentence in a document. Nothing but
    // authenticating writes `last_seen_at`, so a computer that offers and never authenticates is
    // not counted, and that is the truth rather than a fault.
    let folder = tempfile::tempdir().unwrap();
    let now = 70_000;
    let (mut core, person, device, _) = company(folder.path(), now);
    assert_eq!(core.reading(now).unwrap().hosts.heard_from_recently, 0, "offering is not the same as being heard from");

    let (_, secret) = core.enrol_device(&person, "Second computer", "linux", now).unwrap();
    let second = core.snapshot().unwrap().devices.into_iter().find(|found| found.id != device).unwrap();
    core.authenticate(&second.id, &secret, now).unwrap();
    assert_eq!(core.reading(now).unwrap().hosts.heard_from_recently, 1);
    assert_eq!(core.reading(now + HEARD_FROM_WITHIN + 1).unwrap().hosts.heard_from_recently, 0, "and it stops counting once the window has passed");
}

#[test]
fn the_window_a_reading_reports_never_claims_more_than_the_history_holds() {
    let folder = tempfile::tempdir().unwrap();
    let now = 80_000;
    let (core, _, _, _) = company(folder.path(), now);
    // The realm is seconds old, so an hour-long window would be a claim about time the history
    // was not there for.
    let reading = core.reading(now).unwrap();
    assert!(reading.window <= now - reading.reaches, "the window is cut to how far the history reaches");
    assert!(reading.window < WINDOW, "and an hour-long window on a realm minutes old is not honest: {}", reading.window);

    let later = core.reading(now + 2 * WINDOW).unwrap();
    assert_eq!(later.window, WINDOW, "once the history is older than the window, the window is the window");
}

#[test]
fn a_workspace_ordered_a_moment_ago_has_not_waited_out_the_window() {
    // The window is cut to how far the history reaches, because a count taken out of the chain
    // cannot honestly reach past where the chain stops. Nothing trims `workspaces`, so cutting
    // the workspace question the same way would make a realm minutes old, or a realm whose chain
    // was just trimmed, report every desk ordered seconds ago as one that had waited an hour.
    let folder = tempfile::tempdir().unwrap();
    let now = 120_000;
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Workspaces], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::RealmAdmin], now).unwrap();
    let image = crate::core::workspace::Image::new(
        &core.realm().id.clone(),
        "Ubuntu",
        "24.04",
        crate::core::workspace::WorkspaceKind::Container,
        None,
        crate::core::workspace::ImageSource::Oci { reference: "docker.io/library/ubuntu:24.04".to_owned() },
        little(),
        &admin.id,
        now,
    )
    .unwrap();
    let image = core.publish_image(&admin.id, image, now).unwrap();
    core.order_workspace(
        &admin.id,
        "Ada's desk",
        &image.id,
        crate::core::workspace::Access::Standard,
        crate::core::workspace::Quota::for_disk(10.0).unwrap(),
        None,
        now,
    )
    .unwrap();

    let soon = core.reading(now + 120).unwrap();
    assert!(soon.window < WINDOW, "the realm is two minutes old, so the window is still cut to the history: {}", soon.window);
    assert_eq!(soon.workspaces.waiting_for_a_computer, 0, "a desk ordered two minutes ago has not waited out an hour");

    // And once it really has waited the hour, it is counted.
    let later = core.reading(now + 2 * WINDOW).unwrap();
    assert_eq!(later.window, WINDOW, "the history is now older than the window");
    assert_eq!(later.workspaces.waiting_for_a_computer, 1);
}

#[test]
fn a_reading_carries_no_name_no_path_and_no_value() {
    let folder = tempfile::tempdir().unwrap();
    let now = 90_000;
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace Hopper", &[Role::CredentialAdmin], now).unwrap();
    let credential = crate::core::credential::Credential::new(
        &core.realm().id.clone(),
        "Billing key",
        crate::core::credential::Secret::ApiKey,
        "vault-billing",
        &"f".repeat(64),
        "https://api.acme.test",
        &admin.id,
        now,
    )
    .unwrap();
    core.add_credential(&admin.id, credential, now).unwrap();

    let written = serde_json::to_string(&core.reading(now).unwrap()).unwrap();
    for secret in ["Grace Hopper", "Billing key", "api.acme.test", "vault-billing", &"f".repeat(64)] {
        assert!(!written.contains(secret), "a reading carried {secret}");
    }
    assert!(written.contains("\"counts\""), "and it does carry the counts: {written}");
}

#[test]
fn approval_latency_is_how_long_people_have_actually_waited() {
    let folder = tempfile::tempdir().unwrap();
    let now = 100_000;
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let asker = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::CredentialAdmin], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialApprover], now).unwrap();
    let request = core.ask(&asker.id, Action::ApproveCredential, "credential-1", None, false, 600, now).unwrap();

    let waiting = core.reading(now + 60).unwrap().approvals;
    assert_eq!(waiting.waiting, 1);
    assert_eq!(waiting.oldest_wait, 60);

    core.decide(&request.id, Action::ApproveCredential, &approver.id, crate::core::approval::Verdict::Once, now + 120).unwrap();
    let answered = core.reading(now + 180).unwrap().approvals;
    assert_eq!(answered.waiting, 0);
    assert_eq!(answered.decided_in_window, 1);
    assert_eq!(answered.average_wait, 120, "asked at nought, answered at a hundred and twenty");
}

#[test]
fn model_readiness_from_the_database_is_where_a_plan_landed_and_says_nothing_about_loading() {
    let folder = tempfile::tempdir().unwrap();
    let now = 110_000;
    let (mut core, _, _, host) = company(folder.path(), now);
    core.add_model_plan(
        "owner",
        "hf.co/Qwen/Qwen3",
        Some("Q4_K_M"),
        50,
        crate::policy::IdlePolicy::default(),
        crate::core::model::Target::Computers { hosts: vec![host.clone()] },
        now,
    )
    .unwrap();
    let models = core.reading(now).unwrap().models;
    assert_eq!(models.placed.len(), 1);
    assert_eq!(models.placed[0].1, "Qwen/Qwen3");
    assert_eq!(models.placed[0].2, 1, "one computer holds the plan");
    assert_eq!(models.reported, None, "nothing has reported what is actually loaded, and None says so rather than nought");
}
