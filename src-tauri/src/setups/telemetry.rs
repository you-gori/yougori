//! The operations reading: a scoped, redacted, read-only view across this computer's setups
//! (template platform plan section 15, row `operations-dashboard`; catalogue row 21).
//!
//! Four rules hold this module's shape, and the tests at the bottom are about each of them:
//!
//! 1. **Read-only.** Nothing here writes. The registry is reached through
//!    [`Service::observe`](super::service::Service::observe), which hands out a borrowed record
//!    and takes nothing back.
//! 2. **It never widens what a caller can already see.** The setups it reads are exactly the ones
//!    `setup_list` returns, and a named setup is fetched through `setup_get`, so the same refusal
//!    a person gets for a setup they may not read is the refusal they get here. There is no mode
//!    that shows more than that, for anybody.
//! 3. **Redacted by default, with nothing to turn off.** Only health, states, counts, durations
//!    and resource ids leave this module. No name a person typed, no secret, no credential name,
//!    no token, no address, no filesystem path, no account, no share link — and every id is put
//!    through [`safe_id`], so a value that is not a plain short id is replaced rather than shown.
//! 4. **Bounded.** A page holds at most [`MAX_PAGE`] setups, and only operations finished inside
//!    [`WINDOW_DAYS`] are counted. Both bounds are in the answer itself, so a reader never has to
//!    guess what it is looking at.
//!
//! Nothing here sends anything anywhere. There is no destination, no notifier and no schedule:
//! the reading exists only when something asks for it.
use super::{
    journal::OperationState,
    model::{Cost, Diagnostic, Health, Instance, Lifecycle, Observed, Resource},
    service::Service,
    store::Registry,
    views,
};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;

/// The most setups one reading answers with. A person with 200 setups gets a page, and the
/// `page.next` cursor to ask for the one after it.
pub(crate) const MAX_PAGE: usize = 50;
/// What a caller gets when it asks for no particular number.
const DEFAULT_PAGE: usize = 20;
/// How far back an operation is counted. Older ones are not read, not summarised and not shown:
/// the reading is a current picture, never a history.
pub(crate) const WINDOW_DAYS: i64 = 30;
const WINDOW_SECONDS: i64 = WINDOW_DAYS * 24 * 60 * 60;
/// The most operations counted for one setup, newest first, inside the window above.
const MAX_OPERATIONS: usize = 50;

/// What a reading was asked for. Every field may be left out.
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Call {
    /// One setup instead of the page. It is fetched the ordinary way first, so a setup the
    /// caller may not read is refused here in the same words.
    #[serde(default)]
    pub setup_id: Option<String>,
    #[serde(default)]
    pub cursor: Option<usize>,
    #[serde(default)]
    pub limit: Option<usize>,
}

/// An id as it is allowed to leave this module: short, and made only of the characters an engine
/// or template id uses. Anything else — a space, a slash, a backslash, an `@`, a colon, a longer
/// run of text — is not an id, so it is not shown at all.
///
/// This is the last gate rather than the first: nothing above it puts a person's words into a
/// reading, and this makes sure that stays true even if a record is ever hand-edited.
fn safe_id(value: &str) -> String {
    let fits = !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if fits {
        value.to_owned()
    } else {
        "(hidden)".to_owned()
    }
}

/// A code a refusal carries, such as `image_not_found`. Codes are chosen by the engine from a
/// fixed set of lowercase words, so one is safe to show; a refusal's *sentence* never is, and
/// none is read here.
fn safe_code(value: &str) -> String {
    let fits = !value.is_empty() && value.len() <= 48 && value.bytes().all(|byte| byte.is_ascii_lowercase() || byte == b'_');
    if fits {
        value.to_owned()
    } else {
        "(hidden)".to_owned()
    }
}

fn lifecycle_word(lifecycle: Lifecycle) -> &'static str {
    match lifecycle {
        Lifecycle::Draft => "draft",
        Lifecycle::Creating => "creating",
        Lifecycle::Running => "running",
        Lifecycle::Stopped => "stopped",
        Lifecycle::Updating => "updating",
        Lifecycle::Removing => "removing",
        Lifecycle::Retained => "retained",
        Lifecycle::Removed => "removed",
    }
}

fn health_word(health: Health) -> &'static str {
    match health {
        Health::Unknown => "not_checked",
        Health::Ready => "ready",
        Health::Starting => "starting",
        Health::NeedsSignIn => "needs_sign_in",
        Health::WaitingForComputer => "waiting_for_computer",
        Health::Degraded => "degraded",
        Health::Failed => "failed",
        Health::Unsupported => "unsupported",
    }
}

fn observed_word(observed: Observed) -> &'static str {
    match observed {
        Observed::Unknown => "not_checked",
        Observed::Missing => "missing",
        Observed::Present => "present",
        Observed::Running => "running",
        Observed::Stopped => "stopped",
    }
}

fn cost_word(cost: Cost) -> &'static str {
    match cost {
        Cost::Free => "free",
        Cost::Unknown => "not_known",
        Cost::Accruing => "accruing",
        Cost::Stopped => "stopped",
        Cost::ShutdownUnconfirmed => "shutdown_unconfirmed",
    }
}

/// Counts by word, always as a map so a reader can add a new word without the shape changing.
fn tally<'a>(words: impl Iterator<Item = &'a str>) -> Value {
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for word in words {
        *counts.entry(word).or_default() += 1;
    }
    Value::Object(counts.into_iter().map(|(word, count)| (word.to_owned(), json!(count))).collect::<Map<_, _>>())
}

/// What a setup's resources are doing: counts only, and the ids of the ones that are not as the
/// setup wants them, so a dashboard can point at something without naming anything private.
fn resources_reading(resources: &BTreeMap<String, Resource>) -> Value {
    let owned = resources.values().filter(|resource| !resource.borrowed()).collect::<Vec<_>>();
    let kinds = owned
        .iter()
        .map(|resource| serde_json::to_value(resource.kind).ok().and_then(|value| value.as_str().map(str::to_owned)).unwrap_or_else(|| "(hidden)".to_owned()))
        .collect::<Vec<_>>();
    let mut by_kind: BTreeMap<String, u64> = BTreeMap::new();
    for kind in kinds {
        *by_kind.entry(safe_id(&kind)).or_default() += 1;
    }
    let drifting = owned.iter().filter(|resource| resource.drift.is_some()).map(|resource| safe_id(&resource.id)).collect::<Vec<_>>();
    json!({
        "owned": owned.len(),
        "borrowed": resources.len() - owned.len(),
        "byKind": Value::Object(by_kind.into_iter().map(|(kind, count)| (kind, json!(count))).collect::<Map<_, _>>()),
        "byState": tally(owned.iter().map(|resource| observed_word(resource.observed))),
        "byCost": tally(owned.iter().map(|resource| cost_word(resource.cost))),
        "keepingData": owned.iter().filter(|resource| resource.retained_data).count(),
        // The ids only. Why a resource drifted is a sentence the engine wrote about a provider,
        // and a sentence is not something this reading shows.
        "drifting": drifting,
    })
}

/// A setup's operations inside the window: how many, how they went, and how long the last one
/// took. Only the refusal's *code* is read, never its sentence.
fn operations_reading(registry: &Registry, setup: &str, now: i64) -> Value {
    let mut recent = registry
        .operations
        .values()
        .filter(|operation| operation.setup == setup)
        .filter(|operation| {
            let at = views::seconds(operation.completed_at.as_deref().unwrap_or(&operation.updated_at));
            at == 0 || now - at <= WINDOW_SECONDS
        })
        .collect::<Vec<_>>();
    recent.sort_by_key(|operation| std::cmp::Reverse(views::seconds(&operation.updated_at)));
    recent.truncate(MAX_OPERATIONS);
    let last = recent.first();
    let duration = last.and_then(|operation| {
        let started = views::seconds(&operation.created_at);
        let finished = views::seconds(operation.completed_at.as_deref()?);
        (started > 0 && finished >= started).then_some(finished - started)
    });
    json!({
        "counted": recent.len(),
        "windowDays": WINDOW_DAYS,
        "running": recent.iter().filter(|operation| !operation.state.is_terminal()).count(),
        "failed": recent.iter().filter(|operation| matches!(operation.state, OperationState::Failed)).count(),
        "byState": tally(recent.iter().map(|operation| operation.state.as_str())),
        "byKind": tally(recent.iter().map(|operation| operation.kind.as_str())),
        "last": last.map(|operation| json!({
            "kind": operation.kind.as_str(),
            "state": operation.state.as_str(),
            "steps": operation.steps.len(),
            "stepsFailed": operation.steps.iter().filter(|step| step.error.is_some()).count(),
            "tookSeconds": duration,
            "finishedSecondsAgo": operation.completed_at.as_deref().map(views::seconds).filter(|at| *at > 0).map(|at| (now - at).max(0)),
            "errorCode": operation.error.as_ref().map(|error| safe_code(&error.code)),
        })),
    })
}

/// A setup's scheduled backups: how many are kept, how the last run went and when the next one
/// is due, in seconds from now rather than as a clock time, which says nothing about this
/// computer's time zone.
fn backups_reading(registry: &Registry, setup: &str, now: i64) -> Value {
    let schedules = registry.schedules.values().filter(|schedule| schedule.setup == setup).collect::<Vec<_>>();
    json!({
        "volumes": schedules.len(),
        "kept": schedules.iter().map(|schedule| schedule.backups.len()).sum::<usize>(),
        "paused": schedules.iter().filter(|schedule| schedule.paused).count(),
        "failingNow": schedules.iter().filter(|schedule| schedule.failures > 0).count(),
        "byLastOutcome": tally(schedules.iter().map(|schedule| schedule.last_outcome.as_str())),
        "volumesDetail": schedules.iter().map(|schedule| json!({
            "resource": safe_id(&schedule.resource),
            "keep": schedule.keep,
            "kept": schedule.backups.len(),
            "lastOutcome": schedule.last_outcome.as_str(),
            "lastFinishedSecondsAgo": schedule.last_finished_at.map(|at| (now - at).max(0)),
            "nextInSeconds": (!schedule.paused && schedule.next_at > 0).then(|| (schedule.next_at - now).max(0)),
            "failuresInARow": schedule.failures,
        })).collect::<Vec<_>>(),
    })
}

/// One setup's whole reading.
fn setup_reading(registry: &Registry, instance: &Instance, now: i64) -> Value {
    let age = views::seconds(&instance.created_at);
    json!({
        // The id, never the name: a name is what a person typed, and this reading does not carry
        // anything a person typed.
        "setupId": safe_id(&instance.id),
        "state": lifecycle_word(instance.lifecycle),
        "health": health_word(instance.health),
        "capabilities": instance.capabilities.iter().map(|id| safe_id(id)).collect::<Vec<_>>(),
        "revision": instance.revision,
        "ageSeconds": (age > 0).then(|| (now - age).max(0)),
        "busy": instance.current_operation.is_some(),
        "resources": resources_reading(&instance.resources),
        "operations": operations_reading(registry, &instance.id, now),
        "backups": backups_reading(registry, &instance.id, now),
    })
}

/// What this reading deliberately leaves out, said in the answer itself rather than only in a
/// document, so a person reading the JSON knows what it is not.
fn not_shown() -> Vec<&'static str> {
    vec![
        "No setup names, template names, questions or answers: this reading carries nothing a person typed.",
        "No secrets, credential names, tokens or sign-in state beyond the word needs_sign_in.",
        "No addresses, links, domains, ports or share links.",
        "No filesystem paths, folder names, image names or account names.",
        "No log lines and no refusal sentences; a failed operation is shown by its code only.",
    ]
}

/// The reading. `Call::setup_id` asks about one setup; without it, a bounded page across the
/// setups the caller can already list.
pub(crate) fn read(service: &Service, call: Call) -> Result<Value, Diagnostic> {
    let limit = call.limit.unwrap_or(DEFAULT_PAGE).clamp(1, MAX_PAGE);
    let cursor = call.cursor.unwrap_or(0);
    let now = chrono::Utc::now().timestamp();
    // The visible set, and nothing wider. For one setup that is `setup_get`'s own check; for a
    // page it is `setup_list`, which already answers with what this caller may see.
    let visible: Vec<String> = match &call.setup_id {
        Some(setup) => vec![service.get(setup)?.setup.summary.setup_id.clone()],
        None => service.list()?.into_iter().map(|summary| summary.setup_id).collect(),
    };
    let total = visible.len();
    let page: Vec<String> = visible.into_iter().skip(cursor).take(limit).collect();
    let shown = page.len();
    let setups = service.observe(|registry| {
        Ok(page
            .iter()
            .filter_map(|id| registry.instances.get(id))
            .map(|instance| setup_reading(registry, instance, now))
            .collect::<Vec<_>>())
    })?;
    let next = (cursor + shown < total).then_some(cursor + shown);
    Ok(json!({
        "readOnly": true,
        "setups": setups,
        "page": {
            "cursor": cursor,
            "shown": shown,
            "total": total,
            "limit": limit,
            "maxLimit": MAX_PAGE,
            "next": next,
        },
        "retention": {
            "windowDays": WINDOW_DAYS,
            "maxOperationsPerSetup": MAX_OPERATIONS,
            "words": format!(
                "This is a reading of right now, worked out when you asked for it. Nothing is stored for it and nothing is sent anywhere. Operations finished more than {WINDOW_DAYS} days ago are not counted, and at most {MAX_OPERATIONS} are counted for each setup."
            ),
        },
        "scope": "This shows the setups you can already list, and nothing beyond them. There is no wider view.",
        "notShown": not_shown(),
        "next": next.map(|cursor| format!("There are more setups. Ask again with cursor {cursor}.")),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setups::model::{Desired, Source};
    use yougori_setup::{dto::SourceRef, resource::Kind};

    fn instance(id: &str) -> Instance {
        Instance {
            id: id.into(),
            name: "Ada's private shop".into(),
            source: Source { reference: SourceRef::LocalFolder { path: "C:/Users/ada/recipes/shop".into() }, digest: "sha256:aa".into() },
            format_version: 2,
            protocol_version: 1,
            lock_digest: None,
            config_revision: 1,
            revision: 4,
            answers: BTreeMap::from([("admin_email".to_owned(), json!("ada@example.com"))]),
            secret_bindings: BTreeMap::from([("db_password".to_owned(), "setup-stp-1-db".to_owned())]),
            lock: None,
            customizations: BTreeMap::new(),
            capabilities: vec!["run.service".into(), "data.volumes".into()],
            realms: Vec::new(),
            storage: None,
            outputs: BTreeMap::from([("address".to_owned(), "https://shop.ada.example.com".to_owned())]),
            current_operation: None,
            lifecycle: Lifecycle::Running,
            health: Health::Degraded,
            history: Vec::new(),
            resources: BTreeMap::new(),
            created_at: "2026-10-01T00:00:00Z".into(),
            updated_at: "2026-10-20T00:00:00Z".into(),
        }
    }

    fn resource(id: &str, kind: Kind, observed: Observed, drift: Option<&str>) -> Resource {
        Resource {
            id: id.into(),
            kind,
            depends_on: Vec::new(),
            runtime_id: Some("yougori-ada-shop-app".into()),
            owner: None,
            borrowers: Vec::new(),
            generation: 1,
            desired: Desired::Running,
            observed,
            retained_data: kind == Kind::Volume,
            cost: Cost::Free,
            last_observed_at: Some("2026-10-20T00:00:00Z".into()),
            drift: drift.map(str::to_owned),
            spec: json!({"image": "ghcr.io/ada/shop:1.0.0", "token": "sk-live-9f3a"}),
            spec_digest: "sha256:bb".into(),
        }
    }

    /// Every planted value below is something a person would mind seeing in a dashboard. None of
    /// them may appear anywhere in the reading, at any depth.
    const PLANTED: &[&str] = &[
        "Ada's private shop",
        "C:/Users/ada/recipes/shop",
        "ada@example.com",
        "setup-stp-1-db",
        "https://shop.ada.example.com",
        "ghcr.io/ada/shop:1.0.0",
        "sk-live-9f3a",
        "yougori-ada-shop-app",
        "the provider said the container ada-shop-app is gone",
    ];

    fn registry_with(instances: Vec<Instance>) -> Registry {
        let mut registry = Registry::default();
        for instance in instances {
            registry.instances.insert(instance.id.clone(), instance);
        }
        registry
    }

    #[test]
    fn the_reading_holds_no_secret_no_path_no_address_and_no_name() {
        let mut one = instance("stp-1");
        one.resources.insert("app".into(), resource("app", Kind::Environment, Observed::Running, None));
        one.resources.insert(
            "store".into(),
            resource("store", Kind::Volume, Observed::Missing, Some("the provider said the container ada-shop-app is gone")),
        );
        let registry = registry_with(vec![one.clone()]);
        let reading = setup_reading(&registry, &one, 1_800_000_000);
        let text = serde_json::to_string(&reading).unwrap();
        for planted in PLANTED {
            assert!(!text.contains(planted), "the reading shows {planted}:\n{text}");
        }
        // What it does show: the ids, the words and the counts.
        assert_eq!(reading["setupId"], "stp-1");
        assert_eq!(reading["state"], "running");
        assert_eq!(reading["health"], "degraded");
        assert_eq!(reading["resources"]["owned"], 2);
        assert_eq!(reading["resources"]["byState"]["running"], 1);
        assert_eq!(reading["resources"]["byState"]["missing"], 1);
        assert_eq!(reading["resources"]["drifting"], json!(["store"]));
        assert_eq!(reading["resources"]["keepingData"], 1);
        assert_eq!(reading["capabilities"], json!(["run.service", "data.volumes"]));
    }

    #[test]
    fn anything_that_is_not_a_plain_id_is_hidden_rather_than_shown() {
        assert_eq!(safe_id("app-data"), "app-data");
        assert_eq!(safe_id("run.service"), "run.service");
        assert_eq!(safe_id("stp-6f1c2a1e"), "stp-6f1c2a1e");
        for not_an_id in ["C:/Users/ada/notes", "/home/ada/notes", "ada@example.com", "https://x.example.com", "my shop", "", "a:b"] {
            assert_eq!(safe_id(not_an_id), "(hidden)", "{not_an_id} was shown");
        }
        assert_eq!(safe_id(&"x".repeat(65)), "(hidden)");
        assert_eq!(safe_code("image_not_found"), "image_not_found");
        for not_a_code in ["The image ghcr.io/ada/shop:1.0.0 is gone", "Code", ""] {
            assert_eq!(safe_code(not_a_code), "(hidden)");
        }
    }

    #[test]
    fn a_failed_operation_is_shown_by_its_code_and_never_by_its_sentence() {
        use crate::setups::journal::{Operation, OperationKind};
        let mut registry = registry_with(vec![instance("stp-1")]);
        let mut operation = Operation {
            id: "op-1".into(),
            setup: "stp-1".into(),
            kind: OperationKind::Create,
            plan_digest: "sha256:cc".into(),
            source_digest: None,
            base_revision: 0,
            claimed_revision: 1,
            state: OperationState::Failed,
            steps: Vec::new(),
            change: None,
            cancel_requested: false,
            error: Some(Diagnostic::new("image_not_found", "The image ghcr.io/ada/shop:1.0.0 could not be found.")),
            created_at: "2026-10-20T00:00:00Z".into(),
            updated_at: "2026-10-20T00:02:00Z".into(),
            completed_at: Some("2026-10-20T00:02:00Z".into()),
            events: Vec::new(),
            next_seq: 0,
            consents: Default::default(),
        };
        operation.events.push(crate::setups::journal::Event {
            seq: 0,
            at: "2026-10-20T00:01:00Z".into(),
            state: "applying".into(),
            step: None,
            message: "pulling ghcr.io/ada/shop:1.0.0".into(),
        });
        registry.operations.insert(operation.id.clone(), operation);
        let now = views::seconds("2026-10-20T00:10:00Z");
        let reading = operations_reading(&registry, "stp-1", now);
        assert_eq!(reading["counted"], 1);
        assert_eq!(reading["failed"], 1);
        assert_eq!(reading["last"]["errorCode"], "image_not_found");
        assert_eq!(reading["last"]["tookSeconds"], 120);
        assert_eq!(reading["last"]["finishedSecondsAgo"], 480);
        let text = serde_json::to_string(&reading).unwrap();
        assert!(!text.contains("ghcr.io"), "the reading shows an image name:\n{text}");
        assert!(!text.contains("could not be found"), "the reading shows a refusal sentence:\n{text}");
    }

    #[test]
    fn operations_older_than_the_window_are_not_counted() {
        use crate::setups::journal::{Operation, OperationKind};
        let mut registry = registry_with(vec![instance("stp-1")]);
        let at = |stamp: &str| Operation {
            id: format!("op-{stamp}"),
            setup: "stp-1".into(),
            kind: OperationKind::Update,
            plan_digest: String::new(),
            source_digest: None,
            base_revision: 0,
            claimed_revision: 1,
            state: OperationState::Completed,
            steps: Vec::new(),
            change: None,
            cancel_requested: false,
            error: None,
            created_at: stamp.into(),
            updated_at: stamp.into(),
            completed_at: Some(stamp.into()),
            events: Vec::new(),
            next_seq: 0,
            consents: Default::default(),
        };
        for stamp in ["2026-10-19T00:00:00Z", "2026-05-01T00:00:00Z"] {
            let operation = at(stamp);
            registry.operations.insert(operation.id.clone(), operation);
        }
        let reading = operations_reading(&registry, "stp-1", views::seconds("2026-10-20T00:00:00Z"));
        assert_eq!(reading["counted"], 1, "an operation outside the {WINDOW_DAYS}-day window was counted");
        assert_eq!(reading["windowDays"], WINDOW_DAYS);
    }

    #[test]
    fn backups_are_counted_without_a_clock_time_or_a_path() {
        use crate::setups::schedules::tests::schedule;
        let mut registry = registry_with(vec![instance("stp-1")]);
        let mut one = schedule("stp-1/data", "daily 02:00", 1_800_003_600);
        one.setup = "stp-1".into();
        one.resource = "data".into();
        one.keep = 7;
        one.failures = 2;
        registry.schedules.insert(one.id.clone(), one);
        let reading = backups_reading(&registry, "stp-1", 1_800_000_000);
        assert_eq!(reading["volumes"], 1);
        assert_eq!(reading["failingNow"], 1);
        assert_eq!(reading["volumesDetail"][0]["resource"], "data");
        assert_eq!(reading["volumesDetail"][0]["nextInSeconds"], 3600);
        let text = serde_json::to_string(&reading).unwrap();
        assert!(!text.contains('/') || !text.contains("data/"), "a path reached the reading:\n{text}");
    }

    #[test]
    fn a_page_is_bounded_and_says_where_the_next_one_starts() {
        // The bounds themselves, without a service: a limit beyond the maximum is brought back
        // to it, and nothing can ask for everything at once.
        assert_eq!(300usize.clamp(1, MAX_PAGE), MAX_PAGE);
        assert_eq!(0usize.clamp(1, MAX_PAGE), 1);
        let registry = registry_with((0..3).map(|n| instance(&format!("stp-{n}"))).collect());
        let readings = registry.instances.values().map(|instance| setup_reading(&registry, instance, 1_800_000_000)).collect::<Vec<_>>();
        assert_eq!(readings.len(), 3);
    }

    #[test]
    fn what_it_does_not_show_is_part_of_the_answer() {
        let said = not_shown().join(" ");
        for word in ["secrets", "paths", "names", "addresses", "refusal sentences"] {
            assert!(said.contains(word), "what is left out does not mention {word}");
        }
    }
}
