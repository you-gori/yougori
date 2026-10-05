use std::{
    fs,
    io::ErrorKind,
    path::{Path, PathBuf},
    sync::Mutex,
    time::{SystemTime, UNIX_EPOCH},
};

use crate::models::{Environment, PlatformState};

pub struct PlatformStore {
    path: PathBuf,
    state: Mutex<PlatformState>,
    pub(crate) resource_admission: std::sync::Arc<crate::commands::resource_admission::HostResourceAdmission>,
}

impl PlatformStore {
    pub fn load(path: PathBuf) -> Result<Self, String> {
        let backup_path = path.with_extension("json.bak");
        let main = load_state_file(&path);
        let backup = load_state_file(&backup_path);
        let (state, recovered) = match (main, backup) {
            (Ok(Some(state)), _) => (state, false),
            (Ok(None), Ok(Some(state))) => (state, true),
            (Err(_), Ok(Some(state))) => (state, true),
            (Ok(None), Ok(None)) => (
                PlatformState::empty().map_err(|error| error.to_string())?,
                false,
            ),
            (main, backup) => {
                return Err(format!(
                    "Yougori state is unreadable; no files were changed. Primary: {}. Backup: {}",
                    state_load_error(main),
                    state_load_error(backup)
                ));
            }
        };
        let mut state = state.migrate().map_err(|error| {
            format!("Yougori state could not be migrated; no files were changed: {error}")
        })?;
        for job in state.duplication_jobs.values_mut() {
            if job.status == "running" { job.status = "interrupted".into(); job.error = Some("Yougori closed during this copy. Resume the saved operation to inspect its existing resources.".into()); }
        }
        if let Some(report) = &mut state.startup_report {
            if report.status == "running" {
                report.status = "interrupted".into();
                for environment in report.environments.iter_mut().filter(|environment| environment.status == "pending") {
                    environment.status = "interrupted".into();
                    environment.error = Some("Engine restarted before this startup stage was verified".into());
                    environment.recovery_action = Some("Native startup will reconcile the verified provider and original storage before retrying".into());
                }
            }
        }
        for environment in &mut state.environments {
            if environment.kind == crate::models::EnvironmentKind::Cloud {
                environment.status = crate::models::EnvironmentStatus::Stopped;
                environment.last_error = None;
                environment.console_endpoint = None;
                environment.control_endpoint = None;
            }
        }
        if recovered {
            recover_primary_from_backup(&path, &backup_path)?;
        }
        let store = Self {
            path,
            state: Mutex::new(state),
            resource_admission: Default::default(),
        };
        store.persist()?;
        Ok(store)
    }

    /// A folder beside the state file for per-feature data that is too large for platform state.
    pub fn data_folder(&self, name: &str) -> PathBuf {
        self.path.parent().unwrap_or(Path::new(".")).join(name)
    }

    pub fn snapshot(&self) -> Result<PlatformState, String> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| "Platform state is unavailable".to_string())
    }

    pub fn environment(&self, id: &str) -> Result<Environment, String> {
        self.state
            .lock()
            .map_err(|_| "Platform state is unavailable".to_string())?
            .environments
            .iter()
            .find(|environment| environment.id == id)
            .cloned()
            .ok_or_else(|| "Environment not found".into())
    }

    pub fn replace(&self, mut state: PlatformState) -> Result<PlatformState, String> {
        let mut current = self
            .state
            .lock()
            .map_err(|_| "Platform state is unavailable".to_string())?;
        state.settings_revision = next_settings_revision(&current, &state)?;
        persist_state(&self.path, &state)?;
        *current = state.clone();
        Ok(state)
    }

    pub fn mutate<F>(&self, operation: F) -> Result<PlatformState, String>
    where
        F: FnOnce(&mut PlatformState) -> Result<(), String>,
    {
        let mut current = self
            .state
            .lock()
            .map_err(|_| "Platform state is unavailable".to_string())?;
        let mut candidate = current.clone();
        operation(&mut candidate)?;
        candidate.settings_revision = next_settings_revision(&current, &candidate)?;
        persist_state(&self.path, &candidate)?;
        *current = candidate.clone();
        Ok(candidate)
    }

    pub fn mutate_ephemeral<F>(&self, operation: F) -> Result<PlatformState, String>
    where
        F: FnOnce(&mut PlatformState) -> Result<(), String>,
    {
        let mut current = self
            .state
            .lock()
            .map_err(|_| "Platform state is unavailable".to_string())?;
        let mut candidate = current.clone();
        operation(&mut candidate)?;
        candidate.settings_revision = next_settings_revision(&current, &candidate)?;
        *current = candidate.clone();
        Ok(candidate)
    }

    fn persist(&self) -> Result<(), String> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent).map_err(|error| error.to_string())?;
        }
        let state = self
            .state
            .lock()
            .map_err(|_| "Platform state is unavailable".to_string())?;
        persist_state(&self.path, &state)
    }
}

fn next_settings_revision(current: &PlatformState, next: &PlatformState) -> Result<u64, String> {
    if current.settings == next.settings { return Ok(current.settings_revision); }
    current.settings_revision.checked_add(1).ok_or_else(|| "Settings revision exhausted".into())
}

const MAX_STATE_BYTES: u64 = 32 * 1024 * 1024;

fn load_state_file(path: &Path) -> Result<Option<PlatformState>, String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("inspect {}: {error}", path.display())),
    };
    if !metadata.is_file() || metadata.len() > MAX_STATE_BYTES {
        return Err(format!(
            "{} is not a regular state file of at most {} MiB",
            path.display(),
            MAX_STATE_BYTES / 1024 / 1024
        ));
    }
    let contents = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&contents)
        .map(Some)
        .map_err(|error| format!("decode {}: {error}", path.display()))
}

fn state_load_error(result: Result<Option<PlatformState>, String>) -> String {
    match result {
        Ok(None) => "missing".into(),
        Ok(Some(_)) => "valid".into(),
        Err(error) => error,
    }
}

fn recover_primary_from_backup(path: &Path, backup_path: &Path) -> Result<(), String> {
    if path.exists() {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let corrupt_path = path.with_extension(format!("json.corrupt-{timestamp}"));
        fs::rename(path, &corrupt_path).map_err(|error| {
            format!(
                "preserve unreadable state as {}: {error}",
                corrupt_path.display()
            )
        })?;
    }
    let temporary = path.with_extension("json.recovering");
    let _ = fs::remove_file(&temporary);
    fs::copy(backup_path, &temporary)
        .map_err(|error| format!("copy backup state for recovery: {error}"))?;
    fs::File::options()
        .write(true)
        .open(&temporary)
        .and_then(|file| file.sync_all())
        .map_err(|error| format!("flush recovered state: {error}"))?;
    fs::rename(&temporary, path).map_err(|error| format!("activate recovered state: {error}"))
}

fn persist_state(path: &Path, state: &PlatformState) -> Result<(), String> {
    let contents = serde_json::to_vec_pretty(state).map_err(|error| error.to_string())?;
    write_atomic(path, &contents)
}

fn write_atomic(path: &Path, contents: &[u8]) -> Result<(), String> {
    let temp_path = path.with_extension("json.tmp");
    let backup_path = path.with_extension("json.bak");
    {
        use std::io::Write;
        let mut file = fs::File::create(&temp_path).map_err(|error| error.to_string())?;
        file.write_all(contents)
            .map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
    }
    if backup_path.exists() {
        fs::remove_file(&backup_path).map_err(|error| error.to_string())?;
    }
    if path.exists() {
        fs::rename(path, &backup_path).map_err(|error| error.to_string())?;
    }
    if let Err(error) = fs::rename(&temp_path, path) {
        if backup_path.exists() {
            let _ = fs::rename(&backup_path, path);
        }
        return Err(error.to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn persists_and_loads_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let store = PlatformStore::load(path.clone()).unwrap();
        let expected = store.snapshot().unwrap().environments.len();
        drop(store);
        assert_eq!(
            PlatformStore::load(path)
                .unwrap()
                .snapshot()
                .unwrap()
                .environments
                .len(),
            expected
        );
    }

    #[test]
    fn settings_revision_changes_only_with_settings_and_survives_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let store = PlatformStore::load(path.clone()).unwrap();
        let initial = store.snapshot().unwrap();
        store.mutate(|state| { state.host.hostname = "host-renamed".into(); Ok(()) }).unwrap();
        assert_eq!(store.snapshot().unwrap().settings_revision, initial.settings_revision);
        store.mutate(|state| { state.settings.keep_awake = !state.settings.keep_awake; Ok(()) }).unwrap();
        assert_eq!(store.snapshot().unwrap().settings_revision, initial.settings_revision + 1);
        drop(store);
        assert_eq!(PlatformStore::load(path).unwrap().snapshot().unwrap().settings_revision, initial.settings_revision + 1);
    }

    #[test]
    fn interrupted_native_startup_keeps_its_failed_stage_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let store = PlatformStore::load(path.clone()).unwrap();
        store.mutate(|state| {
            state.startup_report = Some(crate::lifecycle::StartupReport { started_at:"earlier".into(), completed_at:None, status:"running".into(), trigger:"engineLaunch".into(), starts_before_sign_in:false, service_registration:None, environments:vec![crate::lifecycle::StartupEnvironmentReport { environment_id:"test".into(), provider:crate::models::RuntimeProviderKind::YougoriCuda, storage_root:Some("D:/original/runtime".into()), stage:"publication".into(), status:"pending".into(), recovery:None, readiness:None, error:None, recovery_action:None }] });
            Ok(())
        }).unwrap();
        drop(store);
        let recovered = PlatformStore::load(path).unwrap().snapshot().unwrap().startup_report.unwrap();
        assert_eq!(recovered.status, "interrupted");
        assert_eq!(recovered.environments[0].stage, "publication");
        assert_eq!(recovered.environments[0].status, "interrupted");
        assert_eq!(recovered.environments[0].storage_root.as_deref(), Some("D:/original/runtime"));
    }

    #[test]
    fn failed_mutation_does_not_change_live_or_persisted_state() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let store = PlatformStore::load(path.clone()).unwrap();
        let expected = store.snapshot().unwrap().environments.len();

        let result = store.mutate(|state| {
            state.environments.clear();
            Err("deliberate failure".to_string())
        });

        assert!(result.is_err());
        assert_eq!(store.snapshot().unwrap().environments.len(), expected);
        drop(store);
        assert_eq!(
            PlatformStore::load(path)
                .unwrap()
                .snapshot()
                .unwrap()
                .environments
                .len(),
            expected
        );
    }

    #[test]
    fn corrupt_primary_recovers_from_durable_backup_without_discarding_evidence() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let store = PlatformStore::load(path.clone()).unwrap();
        store
            .mutate(|state| {
                state.settings.snapshot_retention = 42;
                Ok(())
            })
            .unwrap();
        drop(store);
        fs::write(&path, b"{truncated").unwrap();

        let recovered = PlatformStore::load(path.clone()).unwrap();
        assert_eq!(
            recovered.snapshot().unwrap().settings.snapshot_retention,
            30
        );
        assert!(directory
            .path()
            .read_dir()
            .unwrap()
            .filter_map(Result::ok)
            .any(|entry| entry.file_name().to_string_lossy().contains("corrupt-")));
        assert!(path.with_extension("json.bak").is_file());
    }

    #[test]
    fn corrupt_primary_and_backup_fail_without_overwriting_either() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.json");
        let backup = path.with_extension("json.bak");
        fs::write(&path, b"bad primary").unwrap();
        fs::write(&backup, b"bad backup").unwrap();

        assert!(PlatformStore::load(path.clone()).is_err());
        assert_eq!(fs::read(path).unwrap(), b"bad primary");
        assert_eq!(fs::read(backup).unwrap(), b"bad backup");
    }
}
