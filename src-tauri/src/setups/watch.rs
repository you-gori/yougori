//! Watching the setups that ask to be watched: **Health check** (`web.health`), **Health and
//! logs** (`run.health_logs`) and **Notifications** (`run.notifications`).
//!
//! Once a minute the watcher checks each running setup that has one of them, the same check a
//! person's Refresh makes, so its health and its parts' own words stay current without anyone
//! asking. What it does with what it finds is only what those capabilities say:
//!
//! * **Notifications** tells this computer's person, with a desktop notification, when the setup
//!   stops being healthy and when it is healthy again, when a change to it fails, and when one of
//!   its jobs finishes, fails, or ends in a way somebody has to check. Each thing is said once.
//! * **Health check** restarts the sandbox behind a service whose health path has failed three
//!   checks in a row, at most once every fifteen minutes, and says so in the setup's notification
//!   when Notifications is on. A sandbox that is stopped is never started by it.
//! * **Budget** adds up what the setup's rented GPUs cost this calendar month, minute by minute
//!   at the hourly price NeoCloud recorded for each, and stops them before the next ten minutes
//!   could take the month past the budget. They stay stopped until the next month, or until the
//!   person starts the setup again.
//!
//! Nothing here plans, applies or removes anything, and a setup with a change in progress is left
//! alone until the change ends. The check itself is the setup engine's own refresh.
use super::model::{Health, Lifecycle, Observed};
use super::ordinary::BoxFuture;
use super::service::Service;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use yougori_setup::resource::Kind;

/// How often a watched setup is checked.
pub(crate) const EVERY: Duration = Duration::from_secs(60);
/// How many failing checks in a row restart a service with a health path.
const RESTART_AFTER: u32 = 3;
/// The least time between two restarts of one setup's service.
const RESTART_GAP: Duration = Duration::from_secs(15 * 60);

/// The capabilities that ask for a setup to be watched.
const WATCHED: &[&str] = &["web.health", "run.health_logs", "run.notifications", "run.budget"];
/// How far ahead a budget is kept: rented GPUs stop before this long at their price would pass it.
const BUDGET_AHEAD_HOURS: f64 = 10.0 / 60.0;

/// What the watcher does to the world outside the setup engine. The engine's own in `EngineEffects`;
/// a recording fake in the tests.
pub(crate) trait Effects: Send + Sync {
    /// A desktop notification on this computer.
    fn notify(&self, title: &str, body: &str);
    /// Stops the sandbox and starts it again, as its own restart would.
    fn restart<'a>(&'a self, sandbox: &'a str) -> BoxFuture<'a, Result<(), String>>;
    /// The rented GPUs in a Neo Grid's instance `key`: each one's NeoCloud environment, the
    /// hourly price NeoCloud recorded, and whether it is billing now.
    fn rented<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Vec<(String, f64, bool)>, String>> {
        let _ = key;
        Box::pin(async { Ok(Vec::new()) })
    }
    /// Stops a rented GPU, so it stops billing for its hours.
    fn stop_rented<'a>(&'a self, pod: &'a str) -> BoxFuture<'a, Result<(), String>> {
        let _ = pod;
        Box::pin(async { Ok(()) })
    }
    /// Where what this month's rented hours cost is kept between looks.
    fn spend_file(&self) -> Option<std::path::PathBuf> {
        None
    }
}

/// What one pool's rented GPUs cost this month, as the watcher adds it up.
#[derive(Clone, Debug, Default, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Spend {
    pub month: String,
    pub spent_usd: f64,
    /// When it was last added to, in Unix seconds.
    pub at: i64,
    /// The month the GPUs were stopped for the budget, so they are stopped once.
    #[serde(default)]
    pub stopped_in: Option<String>,
}

/// What the watcher last saw of one setup, so each thing is said once.
#[derive(Default)]
struct Seen {
    health: Option<Health>,
    failing: u32,
    restarted: Option<Instant>,
    /// The last failed operation already told about.
    failed: Option<String>,
    /// Each job's state already told about.
    jobs: BTreeMap<String, Observed>,
}

pub(crate) struct Watcher {
    service: Arc<Service>,
    effects: Arc<dyn Effects>,
    seen: Mutex<BTreeMap<String, Seen>>,
    /// What each budgeted pool's rented GPUs cost this month, by `SETUP/RESOURCE`.
    spend: Mutex<BTreeMap<String, Spend>>,
    /// When this watcher started: a change that failed before it is not news.
    since: chrono::DateTime<chrono::Utc>,
}

fn unhealthy(health: Health) -> bool {
    matches!(health, Health::Degraded | Health::Failed)
}

impl Watcher {
    pub(crate) fn new(service: Arc<Service>, effects: Arc<dyn Effects>) -> Arc<Watcher> {
        let spend = effects.spend_file().and_then(|file| std::fs::read(file).ok()).and_then(|bytes| serde_json::from_slice(&bytes).ok()).unwrap_or_default();
        Arc::new(Watcher { service, effects, seen: Mutex::new(BTreeMap::new()), spend: Mutex::new(spend), since: chrono::Utc::now() })
    }

    /// Checks every watched setup once a minute until the engine closes.
    pub(crate) async fn run(self: Arc<Self>, stopping: CancellationToken) {
        loop {
            tokio::select! {
                _ = stopping.cancelled() => return,
                _ = tokio::time::sleep(EVERY) => {}
            }
            self.tick().await;
        }
    }

    /// One look at every watched setup. Answers what it did, in words, for the tests.
    pub(crate) async fn tick(&self) -> Vec<String> {
        let mut did = Vec::new();
        let watched = self
            .service
            .observe(|registry| {
                Ok(registry
                    .instances
                    .values()
                    .filter(|instance| instance.lifecycle != Lifecycle::Removed && instance.capabilities.iter().any(|id| WATCHED.contains(&id.as_str())))
                    .map(|instance| (instance.id.clone(), instance.name.clone(), instance.capabilities.clone(), instance.lifecycle, instance.current_operation.is_some()))
                    .collect::<Vec<_>>())
            })
            .unwrap_or_default();
        for (setup, name, capabilities, lifecycle, busy) in watched {
            let on = |id: &str| capabilities.iter().any(|capability| capability == id);
            let tell = on("run.notifications");
            if tell {
                if let Some(said) = self.failed_change(&setup, &name) {
                    self.effects.notify(&format!("{name} · change failed"), &said);
                    did.push(format!("told {setup}: change failed"));
                }
            }
            if busy || lifecycle != Lifecycle::Running {
                continue;
            }
            if self.service.refresh(&setup).await.is_err() {
                continue;
            }
            let health = self.service.observe(|registry| Ok(registry.instances.get(&setup).map(|instance| instance.health))).ok().flatten().unwrap_or(Health::Unknown);
            let reports = self.service.health_reports(&setup);
            let why = reports.values().find(|report| unhealthy(report.health)).map(|report| report.detail.clone()).unwrap_or_default();
            let (before, failing) = {
                let mut seen = self.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let entry = seen.entry(setup.clone()).or_default();
                let before = entry.health.replace(health);
                entry.failing = if unhealthy(health) { entry.failing + 1 } else { 0 };
                (before, entry.failing)
            };
            if tell {
                match (before, health) {
                    (Some(was), now) if !unhealthy(was) && unhealthy(now) => {
                        self.effects.notify(&format!("{name} needs attention"), if why.is_empty() { "It isn't healthy. Open it in Yougori to see why." } else { &why });
                        did.push(format!("told {setup}: unhealthy"));
                    }
                    (Some(was), Health::Ready) if unhealthy(was) => {
                        self.effects.notify(&format!("{name} is healthy again"), "Its checks pass again.");
                        did.push(format!("told {setup}: healthy again"));
                    }
                    _ => {}
                }
                for said in self.job_changes(&setup) {
                    self.effects.notify(&name, &said);
                    did.push(format!("told {setup}: {said}"));
                }
            }
            if on("run.budget") {
                for said in self.keep_to_budget(&setup, &name, tell).await {
                    did.push(said);
                }
            }
            if on("web.health") && failing >= RESTART_AFTER {
                if let Some(restarted) = self.restart(&setup).await {
                    did.push(format!("restarted {restarted} of {setup}"));
                    if tell {
                        self.effects.notify(&format!("{name} was restarted"), &format!("Its health check failed {RESTART_AFTER} times in a row, so {restarted} was started again."));
                    }
                }
            }
        }
        did
    }

    /// The latest change to the setup, when it failed since this watcher started and nobody was
    /// told yet: in its own words.
    fn failed_change(&self, setup: &str, name: &str) -> Option<String> {
        let since = self.since;
        let (operation, message) = self
            .service
            .observe(|registry| {
                Ok(registry
                    .operations
                    .values()
                    .filter(|operation| operation.setup == setup)
                    .filter_map(|operation| operation.completed_at.as_deref().and_then(|at| chrono::DateTime::parse_from_rfc3339(at).ok()).map(|at| (at, operation)))
                    .max_by_key(|(at, _)| *at)
                    .filter(|(at, operation)| operation.state == super::journal::OperationState::Failed && *at >= since)
                    .map(|(_, operation)| (operation.id.clone(), operation.error.as_ref().map(|error| error.message.clone()))))
            })
            .ok()
            .flatten()?;
        let mut seen = self.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = seen.entry(setup.to_owned()).or_default();
        if entry.failed.as_deref() == Some(operation.as_str()) {
            return None;
        }
        entry.failed = Some(operation);
        Some(message.unwrap_or_else(|| format!("A change to {name} failed. Open it in Yougori to see why.")))
    }

    /// What the setup's jobs did since the last look: each one that finished, failed, or ended in
    /// a way somebody has to check, once.
    fn job_changes(&self, setup: &str) -> Vec<String> {
        let Ok(jobs) = self.service.resources_of(setup, Kind::Job) else { return Vec::new() };
        let mut seen = self.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = seen.entry(setup.to_owned()).or_default();
        let mut said = Vec::new();
        for job in jobs {
            let before = entry.jobs.insert(job.id.clone(), job.observed);
            if before.is_none() || before == Some(job.observed) {
                continue;
            }
            match job.observed {
                Observed::Present => said.push(format!("{} finished.", job.id)),
                Observed::Stopped => said.push(format!("{} ended without finishing. Open it in Yougori to read what it printed.", job.id)),
                Observed::Unknown => said.push(format!("Nobody knows whether {} did its work. Open it in Yougori to check, then settle it.", job.id)),
                _ => {}
            }
        }
        said
    }

    /// Adds up what each budgeted pool's rented GPUs cost since the last look, and stops them
    /// before the month could pass its budget. Answers what it did, in words.
    async fn keep_to_budget(&self, setup: &str, name: &str, tell: bool) -> Vec<String> {
        let mut did = Vec::new();
        let Ok(pools) = self.service.resources_of(setup, Kind::ComputePool) else { return did };
        let now = chrono::Utc::now();
        let month = now.format("%Y-%m").to_string();
        for pool in pools.into_iter().filter(|pool| pool.spec["source"] == "cloud" && pool.spec["cloud"]["provider"] == "runpod") {
            let Some(budget) = pool.spec["cloud"]["budget_usd"].as_f64().filter(|budget| *budget > 0.0) else { continue };
            let Some(grid) = pool.spec["grid"]["resource"].as_str().and_then(|grid| self.service.resource_of(setup, grid).ok()).and_then(|grid| grid.runtime_id) else { continue };
            let key = super::grids::located(&grid).1.to_owned();
            let Ok(rented) = self.effects.rented(&key).await else { continue };
            let ours: Vec<(String, f64, bool)> = rented.into_iter().filter(|(pod, _, _)| pool.runtime_id.as_deref() == Some(pod.as_str())).collect();
            let hourly: f64 = ours.iter().filter(|(_, _, billing)| *billing).map(|(_, price, _)| *price).sum();
            let entry = format!("{setup}/{}", pool.id);
            let (spent, stop) = {
                let mut spend = self.spend.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                let record = spend.entry(entry.clone()).or_default();
                if record.month != month {
                    *record = Spend { month: month.clone(), spent_usd: 0.0, at: now.timestamp(), stopped_in: None };
                }
                let hours = ((now.timestamp() - record.at).max(0) as f64 / 3600.0).min(1.0);
                record.spent_usd += hourly * hours;
                record.at = now.timestamp();
                let stop = hourly > 0.0 && record.spent_usd + hourly * BUDGET_AHEAD_HOURS >= budget && record.stopped_in.as_deref() != Some(month.as_str());
                if stop {
                    record.stopped_in = Some(month.clone());
                }
                (record.spent_usd, stop)
            };
            self.save_spend();
            if !stop {
                continue;
            }
            for (pod, _, billing) in &ours {
                if *billing && self.effects.stop_rented(pod).await.is_ok() {
                    did.push(format!("stopped {pod} of {setup} for its budget"));
                }
            }
            if tell {
                self.effects.notify(&format!("{name} reached its budget"), &format!("Its rented GPUs cost ${spent:.2} this month, close to its budget of ${budget:.2}, so they were stopped. Start the setup again, or raise the budget, to use them before next month."));
            }
        }
        did
    }

    fn save_spend(&self) {
        let Some(file) = self.effects.spend_file() else { return };
        let bytes = serde_json::to_vec(&*self.spend.lock().unwrap_or_else(|poisoned| poisoned.into_inner())).unwrap_or_default();
        let staged = file.with_extension("json.new");
        if std::fs::write(&staged, bytes).is_ok() {
            let _ = std::fs::rename(&staged, &file);
        }
    }

    /// Restarts the sandbox behind the setup's service, unless one was restarted lately.
    async fn restart(&self, setup: &str) -> Option<String> {
        {
            let seen = self.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            if seen.get(setup).and_then(|entry| entry.restarted).is_some_and(|at| at.elapsed() < RESTART_GAP) {
                return None;
            }
        }
        // The sandbox a publication with a health path opens, as the setup recorded it.
        let publications = self.service.resources_of(setup, Kind::ServicePublication).ok()?;
        let target = publications.iter().find(|publication| !publication.spec["health"].is_null()).and_then(|publication| publication.spec["target"]["resource"].as_str().map(str::to_owned))?;
        let sandbox = self.service.resource_of(setup, &target).ok()?;
        if sandbox.observed != Observed::Running {
            return None;
        }
        let id = sandbox.runtime_id?;
        if self.effects.restart(&id).await.is_err() {
            return None;
        }
        let mut seen = self.seen.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let entry = seen.entry(setup.to_owned()).or_default();
        entry.restarted = Some(Instant::now());
        entry.failing = 0;
        Some(target)
    }
}

/// The engine's own effects: the desktop's notifications, and the runtime's own stop and start.
pub(crate) struct EngineEffects {
    pub app: crate::AppHandle,
    /// The setups' data folder, where what rented GPUs cost this month is kept.
    pub folder: std::path::PathBuf,
}

impl Effects for EngineEffects {
    fn notify(&self, title: &str, body: &str) {
        #[cfg(target_os = "windows")]
        {
            use tauri_plugin_notification::NotificationExt;
            let _ = self.app.notification().builder().title(format!("Yougori · {title}")).body(body).show();
        }
        #[cfg(not(target_os = "windows"))]
        let _ = (title, body);
    }

    fn restart<'a>(&'a self, sandbox: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move {
            crate::automation::dispatch::dispatch(&self.app, "set_environment_status", &serde_json::json!({"environmentId": sandbox, "status": "stopped"})).await?;
            crate::automation::dispatch::dispatch(&self.app, "set_environment_status", &serde_json::json!({"environmentId": sandbox, "status": "running"})).await.map(|_| ())
        })
    }

    fn rented<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<Vec<(String, f64, bool)>, String>> {
        Box::pin(async move {
            let status = crate::automation::dispatch::dispatch(&self.app, "grid_neocloud_status", &serde_json::json!({"gridId": key})).await?;
            Ok(status["members"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|member| {
                    let pod = member["environmentId"].as_str()?.to_owned();
                    let billing = member["podState"].as_str().is_some_and(|state| matches!(state, "Running" | "Starting" | "Creating"));
                    Some((pod, member["hourlyUsd"].as_f64().unwrap_or_default(), billing))
                })
                .collect())
        })
    }

    fn stop_rented<'a>(&'a self, pod: &'a str) -> BoxFuture<'a, Result<(), String>> {
        Box::pin(async move { crate::automation::dispatch::dispatch(&self.app, "runpod_action", &serde_json::json!({"environmentId": pod, "action": "stop"})).await.map(|_| ()) })
    }

    fn spend_file(&self) -> Option<std::path::PathBuf> {
        Some(self.folder.join("rented-spend.json"))
    }
}
