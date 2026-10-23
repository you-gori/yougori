//! Lockdown and kill-switch containment: which steps to take, what to restore, and the
//! persisted record that keeps a contained environment offline until `unlock`.
//! Containment never stops, deletes, resets or restarts anything.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Level {
    /// A kill switch cut the Internet.
    InternetCut,
    /// A kill switch cut the Internet (when it could) and paused the environment.
    Paused,
    /// `yougori lockdown`: Internet cut and paused.
    Lockdown,
}

impl Level {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Level::InternetCut => "internet cut",
            Level::Paused => "paused",
            Level::Lockdown => "locked down",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Containment {
    pub level: Level,
    pub since: String,
    pub reason: String,
    pub via: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    /// Containment turned Internet access off; unlock turns it back on.
    pub restore_internet: bool,
    /// Containment paused a running environment; unlock resumes it.
    pub resume: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Power {
    Running,
    Paused,
    Stopped,
    /// Provisioning or failed: power is left alone.
    Other,
}

/// The parts of an environment containment can change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Target {
    pub internet: bool,
    pub power: Power,
    /// Internet can be switched (containers, GPU containers, microVMs, VMs).
    pub internet_control: bool,
    /// The environment can be paused.
    pub pause_control: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Step {
    CutInternet,
    Pause,
    RestoreInternet,
    Resume,
}

/// Steps to reach `level`, merged with any containment already in force. Repeating a
/// lockdown only performs steps that are still missing.
pub(crate) fn plan_contain(target: Target, existing: Option<&Containment>, level: Level, reason: &str, via: &str, rule: Option<&str>, now: &str) -> (Vec<Step>, Containment) {
    let mut steps = Vec::new();
    let cut = target.internet && target.internet_control;
    if cut {
        steps.push(Step::CutInternet);
    }
    let pause = level >= Level::Paused && target.power == Power::Running && target.pause_control;
    if pause {
        steps.push(Step::Pause);
    }
    let containment = match existing {
        Some(existing) => Containment {
            level: existing.level.max(level),
            since: existing.since.clone(),
            reason: if level > existing.level { reason.to_owned() } else { existing.reason.clone() },
            via: if level > existing.level { via.to_owned() } else { existing.via.clone() },
            rule: if level > existing.level { rule.map(str::to_owned) } else { existing.rule.clone() },
            restore_internet: existing.restore_internet || cut,
            resume: existing.resume || pause,
        },
        None => Containment {
            level,
            since: now.to_owned(),
            reason: reason.to_owned(),
            via: via.to_owned(),
            rule: rule.map(str::to_owned),
            restore_internet: cut,
            resume: pause,
        },
    };
    (steps, containment)
}

/// Steps that undo exactly what containment did, if those changes are still in place.
pub(crate) fn plan_release(target: Target, existing: Option<&Containment>) -> Vec<Step> {
    let Some(existing) = existing else { return Vec::new() };
    let mut steps = Vec::new();
    if existing.restore_internet && !target.internet && target.internet_control {
        steps.push(Step::RestoreInternet);
    }
    if existing.resume && target.power == Power::Paused && target.pause_control {
        steps.push(Step::Resume);
    }
    steps
}

/// The refusal for an action that would reopen a contained environment. `target` is what
/// to type in the suggested commands (the name when it is a single word, else the ID).
pub(crate) fn refusal(name: &str, target: &str, containment: &Containment, action: &str) -> String {
    // Records we could not read: unlocking is not the way out, so do not send anybody there. The
    // reason already says what to do, and there is no date to print because nothing was recorded.
    if containment.since.is_empty() {
        return format!("{action} stays blocked for {name}: {}.", containment.reason);
    }
    format!(
        "{name} is {} ({}) since {}. {action} stays blocked until you review `yougori audit {target}` and run `yougori unlock {target} --yes`.",
        containment.level.label(), containment.reason, containment.since
    )
}

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    version: u32,
    #[serde(default)]
    containment: BTreeMap<String, Containment>,
}

/// Containment records, persisted so they survive an engine restart.
pub(crate) struct Store {
    path: PathBuf,
    records: Mutex<BTreeMap<String, Containment>>,
    /// The records file is there but could not be read. Everything counts as contained until it
    /// can be: a kill switch that cannot read its own records has to assume the switch is on.
    unreadable: bool,
}

impl Store {
    pub(crate) fn load(path: &Path) -> Self {
        // Antivirus and backup software hold a file open for a moment on Windows, and the engine
        // starts while both are busy, so one failed read means little. Three tries over a second
        // separate a passing lock from a file that is genuinely gone wrong.
        let mut saved = None;
        for attempt in 0..3 {
            if attempt > 0 {
                std::thread::sleep(std::time::Duration::from_millis(300));
            }
            saved = match fs::read(path) {
                // No file is the ordinary first run: nothing has ever been locked down.
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Some(Saved::default()),
                Err(_) => None,
                Ok(data) => serde_json::from_slice::<Saved>(&data).ok(),
            };
            if saved.is_some() {
                break;
            }
        }
        let unreadable = saved.is_none();
        if unreadable {
            // Loud, and not only in the audit log, which may be unavailable for the same reason.
            eprintln!("Yougori could not read its lockdown records, so every environment stays locked down until it can. Nothing is changed on disk while this lasts. Repair or move aside {}, then start Yougori again.", path.display());
        }
        Self { path: path.to_owned(), records: Mutex::new(saved.unwrap_or_default().containment), unreadable }
    }

    /// Whether the records could not be read at startup. Everything counts as contained while this
    /// is true, and nothing may be written, so the status pages say so rather than showing an
    /// empty list beside refusals nobody can explain.
    pub(crate) fn unreadable(&self) -> bool {
        self.unreadable
    }

    /// Records a containment next to the unreadable file rather than over it. Nothing merges
    /// these back automatically — that is a decision for somebody looking at both files — but the
    /// act itself has already happened, and this is how it is not forgotten.
    fn set_beside(&self, id: &str, containment: Option<Containment>) -> Result<(), String> {
        let Some(containment) = containment else {
            return Err(self.unreadable_message());
        };
        let beside = self.path.with_extension(format!("pending-{id}.json"));
        let saved = Saved { version: 1, containment: [(id.to_owned(), containment)].into_iter().collect() };
        let bytes = serde_json::to_vec_pretty(&saved).map_err(|error| error.to_string())?;
        fs::write(&beside, bytes).map_err(|error| format!("Write {}: {error}", beside.display()))
    }

    /// Where a containment goes while the records cannot be read, so a message can name it.
    pub(crate) fn beside_path(&self, id: &str) -> String {
        self.path.with_extension(format!("pending-{id}.json")).display().to_string()
    }

    /// What to tell somebody while the records cannot be read. Names the file: the way out of this
    /// state is to repair or move it, and an instruction that does not say which file is one
    /// nobody can follow while everything on the computer is refusing them.
    pub(crate) fn unreadable_message(&self) -> String {
        format!("Yougori could not read its lockdown records when it started, so nothing can be unlocked yet. Repair or move aside {}, then start Yougori again.", self.path.display())
    }
    pub(crate) fn get(&self, id: &str) -> Option<Containment> {
        let found = self.records.lock().unwrap_or_else(|error| error.into_inner()).get(id).cloned();
        match found {
            Some(containment) => Some(containment),
            // Unreadable records: say so in the person's own terms rather than letting the action
            // through, and name what has to happen before anything is open again.
            None if self.unreadable => Some(Containment {
                level: Level::Lockdown,
                reason: format!("Yougori could not read its lockdown records when it started, so everything stays locked down. Repair or move aside {}, then start Yougori again", self.path.display()),
                since: String::new(),
                via: "engine".into(),
                rule: None,
                restore_internet: false,
                resume: false,
            }),
            None => None,
        }
    }
    /// Whether `id` is contained, without copying its record: open connections ask this twice a second.
    pub(crate) fn contains(&self, id: &str) -> bool {
        self.unreadable || self.records.lock().unwrap_or_else(|error| error.into_inner()).contains_key(id)
    }
    pub(crate) fn all(&self) -> BTreeMap<String, Containment> {
        self.records.lock().unwrap_or_else(|error| error.into_inner()).clone()
    }
    /// Saves before returning: callers act only after the record is durable.
    pub(crate) fn set(&self, id: &str, containment: Option<Containment>) -> Result<(), String> {
        // Never write over records we could not read. The in-memory map is empty in that state, so
        // saving it would replace a file full of lockdowns with a single entry — losing exactly
        // what this is here to protect, and from a transient read failure at that.
        if self.unreadable {
            // Never over the file we could not read: the in-memory map is empty, so saving it
            // would replace a file full of lockdowns with one entry. Beside it instead, so a
            // containment applied now is still evidence an admin can act on, and so the live
            // records are untouched until somebody repairs them.
            return self.set_beside(id, containment);
        }
        let mut records = self.records.lock().unwrap_or_else(|error| error.into_inner());
        let mut next = records.clone();
        match containment {
            Some(containment) => next.insert(id.to_owned(), containment),
            None => next.remove(id),
        };
        let saved = Saved { version: 1, containment: next.clone() };
        let bytes = serde_json::to_vec_pretty(&saved).map_err(|error| error.to_string())?;
        let parent = self.path.parent().ok_or("Security state folder missing")?;
        fs::create_dir_all(parent).map_err(|error| format!("Create security state folder: {error}"))?;
        let mut file = tempfile::NamedTempFile::new_in(parent).map_err(|error| error.to_string())?;
        file.write_all(&bytes).map_err(|error| error.to_string())?;
        file.as_file().sync_all().map_err(|error| error.to_string())?;
        file.persist(&self.path).map_err(|error| format!("Save containment state: {}", error.error))?;
        *records = next;
        Ok(())
    }
    /// Drops records of environments that no longer exist.
    pub(crate) fn retain(&self, live: &[String]) -> Result<(), String> {
        // Nothing to tidy that we can see, and nothing may be written anyway. Saying so beats
        // returning Ok from a sweep that looked at an empty map it knows is not the truth.
        if self.unreadable {
            return Err(format!("Yougori could not read its lockdown records, so old ones cannot be tidied up yet. Repair or move aside {}, then start Yougori again.", self.path.display()));
        }
        let stale: Vec<String> = self.all().into_keys().filter(|id| !live.contains(id)).collect();
        for id in stale {
            self.set(&id, None)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUNNING: Target = Target { internet: true, power: Power::Running, internet_control: true, pause_control: true };

    #[test]
    fn lockdown_cuts_and_pauses_then_unlock_restores_exactly_that() {
        let (steps, record) = plan_contain(RUNNING, None, Level::Lockdown, "manual lockdown", "cli", None, "t0");
        assert_eq!(steps, vec![Step::CutInternet, Step::Pause]);
        assert!(record.restore_internet && record.resume);
        let after = Target { internet: false, power: Power::Paused, ..RUNNING };
        assert_eq!(plan_release(after, Some(&record)), vec![Step::RestoreInternet, Step::Resume]);
    }

    #[test]
    fn repeating_lockdown_and_unlock_is_idempotent() {
        let (_, record) = plan_contain(RUNNING, None, Level::Lockdown, "manual lockdown", "cli", None, "t0");
        let contained = Target { internet: false, power: Power::Paused, ..RUNNING };
        let (steps, again) = plan_contain(contained, Some(&record), Level::Lockdown, "manual lockdown", "cli", None, "t1");
        assert!(steps.is_empty());
        assert_eq!(again, record, "restore flags and the original time are kept");
        assert!(plan_release(contained, None).is_empty(), "unlocking an unlocked environment does nothing");
        let restored = Target { internet: true, power: Power::Running, ..RUNNING };
        assert!(plan_release(restored, Some(&record)).is_empty(), "a second unlock finds nothing to undo");
    }

    #[test]
    fn unlock_leaves_choices_the_user_made_independently() {
        let offline_paused = Target { internet: false, power: Power::Paused, ..RUNNING };
        let (steps, record) = plan_contain(offline_paused, None, Level::Lockdown, "manual lockdown", "cli", None, "t0");
        assert!(steps.is_empty());
        assert!(!record.restore_internet && !record.resume);
        assert!(plan_release(offline_paused, Some(&record)).is_empty());
        let (_, record) = plan_contain(RUNNING, None, Level::Lockdown, "manual lockdown", "cli", None, "t0");
        let stopped_later = Target { internet: false, power: Power::Stopped, ..RUNNING };
        assert_eq!(plan_release(stopped_later, Some(&record)), vec![Step::RestoreInternet]);
    }

    #[test]
    fn kill_switch_levels_escalate_and_merge() {
        let (steps, cut) = plan_contain(RUNNING, None, Level::InternetCut, "31 blocked PC ports", "policy", Some("hostPortProbe"), "t0");
        assert_eq!(steps, vec![Step::CutInternet]);
        let offline = Target { internet: false, ..RUNNING };
        let (steps, paused) = plan_contain(offline, Some(&cut), Level::Paused, "still scanning", "policy", Some("hostPortProbe"), "t1");
        assert_eq!(steps, vec![Step::Pause]);
        assert_eq!(paused.level, Level::Paused);
        assert!(paused.restore_internet && paused.resume);
        assert_eq!(paused.since, "t0");
        let (steps, locked) = plan_contain(Target { power: Power::Paused, ..offline }, Some(&paused), Level::InternetCut, "x", "policy", None, "t2");
        assert!(steps.is_empty());
        assert_eq!(locked.level, Level::Paused, "a milder request never lowers containment");
    }

    #[test]
    fn unsupported_controls_are_skipped() {
        let stopped = Target { internet: true, power: Power::Stopped, internet_control: true, pause_control: true };
        assert_eq!(plan_contain(stopped, None, Level::Lockdown, "r", "cli", None, "t").0, vec![Step::CutInternet]);
        let app = Target { internet: false, power: Power::Running, internet_control: false, pause_control: false };
        assert!(plan_contain(app, None, Level::Lockdown, "r", "cli", None, "t").0.is_empty());
    }

    #[test]
    fn records_persist_and_refusals_name_the_way_out() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("security").join("state.json");
        let store = Store::load(&path);
        let (_, record) = plan_contain(RUNNING, None, Level::Lockdown, "manual lockdown", "cli", None, "2026-10-11T12:00:00Z");
        store.set("env-a", Some(record.clone())).unwrap();
        store.set("env-b", Some(record.clone())).unwrap();
        let reloaded = Store::load(&path);
        assert_eq!(reloaded.get("env-a"), Some(record.clone()));
        reloaded.retain(&["env-a".into()]).unwrap();
        assert!(Store::load(&path).get("env-b").is_none());
        let message = refusal("web", "web", &record, "Starting");
        assert!(message.contains("locked down") && message.contains("yougori unlock web --yes") && message.contains("yougori audit web"));
        reloaded.set("env-a", None).unwrap();
        assert!(Store::load(&path).all().is_empty());
    }
}
