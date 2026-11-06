//! Explicit archival keeps exact terminal effects and their replay protection.
//! No TTL, deletion or compaction may silently turn an old request into new work.
use super::*;
use crate::sandbox_contract::remote_ssh::{confirmed_creation_cancelled, confirmed_remote_end};

pub(super) const MAX_HISTORY: usize = 4096;
const MAX_HISTORY_BYTES: u64 = 32 * 1024 * 1024;
const PAGE_SIZE: usize = 100;
const PAGE_BYTES: usize = 512 * 1024;

#[derive(Default)]
pub(super) struct History {
    pub records: BTreeMap<Digest, Run>,
    by_request: BTreeMap<Digest, Digest>,
    bytes: u64,
}

pub(super) fn view(run: &Run, archived: bool) -> Value {
    let mut view = run.view();
    view["archived"] = json!(archived);
    view
}

fn validate(run: &Run, path: &Path) -> Result<(), String> {
    if run.version != 1
        || path.file_stem().and_then(|s| s.to_str()) != Some(run.run.to_hex().as_str())
        || trust::target(&run.profile)?.0.host() != run.host
        || trust::target(run.cleanup_profile())?.0.host() != run.host
    {
        return Err("Remote journal identity is inconsistent.".into());
    }
    Ok(())
}

fn terminal_proof(run: &Run) -> Result<(), String> {
    let receipt = run
        .receipt
        .as_ref()
        .ok_or("Remote archive requires its original end proof.")?;
    match run.phase {
        Phase::CreationCancelled
            if run.observation.is_none() && confirmed_creation_cancelled(run.run, receipt) =>
        {
            Ok(())
        }
        Phase::Ended => {
            confirmed_remote_end(run.run, run.observation.as_ref(), receipt).map(|_| ())
        }
        _ => Err("Only a confirmed terminal remote run can be archived.".into()),
    }
}

fn same(a: &Run, b: &Run) -> bool {
    serde_json::to_value(a)
        .ok()
        .zip(serde_json::to_value(b).ok())
        .is_some_and(|(a, b)| a == b)
}

fn space(count: usize, bytes: u64, additional: u64) -> Result<u64, String> {
    let next = bytes
        .checked_add(additional)
        .ok_or("Remote archive size overflow.")?;
    if count >= MAX_HISTORY || next > MAX_HISTORY_BYTES {
        return Err("Remote archive is full (4,096 records or 32 MiB). Existing proofs and request keys are retained; no automatic pruning or replay is allowed.".into());
    }
    Ok(next)
}

/// An interrupted copy-before-unlink leaves two identical terminal records. The
/// archive is authoritative only after its proof and complete identity match.
pub(super) fn load(root: &Path) -> Result<(BTreeMap<Digest, Arc<Entry>>, History), String> {
    let directory = root.join("history");
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let mut history = History::default();
    let mut keys = BTreeSet::new();
    for path in bounded_journal_paths(&directory, MAX_HISTORY)? {
        let bytes = fs::symlink_metadata(&path)
            .map_err(|e| e.to_string())?
            .len();
        let total = space(history.records.len(), history.bytes, bytes)?;
        let run: Run = read_json(&path)?;
        validate(&run, &path)?;
        terminal_proof(&run)?;
        if run.request_key.is_some_and(|key| !keys.insert(key)) {
            return Err("Duplicate remote request key in archive.".into());
        }
        if let Some(key) = run.request_key {
            history.by_request.insert(key, run.run);
        }
        history.bytes = total;
        history.records.insert(run.run, run);
    }
    let mut runs = BTreeMap::new();
    for path in journal_paths(&root.join("runs"))? {
        let run: Run = read_json(&path)?;
        validate(&run, &path)?;
        if let Some(archived) = history.records.get(&run.run) {
            if !same(&run, archived) {
                return Err(
                    "Active and archived remote records disagree; neither was discarded.".into(),
                );
            }
            // Archive was atomically flushed before this unlink. Repeating this
            // after a crash is harmless and never schedules a worker.
            fs::remove_file(&path).map_err(|e| e.to_string())?;
            continue;
        }
        if run.request_key.is_some_and(|key| !keys.insert(key)) {
            return Err("Duplicate remote request key in recovery records.".into());
        }
        runs.insert(run.run, Arc::new(Entry::new(run)));
    }
    Ok((runs, history))
}

impl Manager {
    pub(super) fn find_request(
        &self,
        runs: &BTreeMap<Digest, Arc<Entry>>,
        key: Digest,
    ) -> Result<Option<(Run, bool)>, String> {
        if let Some(run) = runs
            .values()
            .map(|entry| entry.snapshot())
            .find(|run| run.request_key == Some(key))
        {
            return Ok(Some((run, false)));
        }
        let history = self
            .history
            .lock()
            .map_err(|_| "Remote history lock unavailable")?;
        Ok(history
            .by_request
            .get(&key)
            .and_then(|id| history.records.get(id))
            .map(|run| (run.clone(), true)))
    }

    pub(super) fn status(
        &self,
        run: Option<Digest>,
        request_key: Option<Digest>,
        archived: bool,
        after: Option<Digest>,
    ) -> Result<Value, String> {
        if (run.is_some() && request_key.is_some())
            || ((run.is_some() || request_key.is_some()) && (archived || after.is_some()))
            || (after.is_some() && !archived)
        {
            return Err(
                "Select a run, a request key, or a history page; --after requires --archived true."
                    .into(),
            );
        }
        let runs = self.runs.lock().map_err(|_| "Remote lock unavailable")?;
        if let Some(key) = request_key {
            return Ok(
                json!({"match":self.find_request(&runs,key)?.map(|(run,archived)|view(&run,archived))}),
            );
        }
        let history = self
            .history
            .lock()
            .map_err(|_| "Remote history lock unavailable")?;
        if let Some(run) = run {
            return runs
                .get(&run)
                .map(|r| r.snapshot().view())
                .or_else(|| history.records.get(&run).map(|r| view(r, true)))
                .ok_or("Unknown remote run.".into());
        }
        let (rows, next): (Vec<Value>, Option<Digest>) = if archived {
            let mut page = Vec::new();
            let mut bytes = 0;
            let mut last = None;
            let mut next = None;
            for (id, run) in history
                .records
                .iter()
                .filter(|(id, _)| after.is_none_or(|after| **id > after))
            {
                let row = view(run, true);
                let size = serde_json::to_vec(&row).map_err(|e| e.to_string())?.len();
                if page.len() >= PAGE_SIZE || (!page.is_empty() && bytes + size > PAGE_BYTES) {
                    next = last;
                    break;
                }
                bytes += size;
                last = Some(*id);
                page.push(row);
            }
            (page, next)
        } else {
            (runs.values().map(|r| r.snapshot().view()).collect(), None)
        };
        Ok(
            json!({"runs":rows,"archived_count":history.records.len(),"archive_limit":MAX_HISTORY,
            "archive_bytes":history.bytes,"archive_byte_limit":MAX_HISTORY_BYTES,"next_after":next}),
        )
    }

    pub(super) fn archive(&self, id: Digest) -> Result<Value, String> {
        // Same order as launch/status/stop. No worker can become active while
        // archival checks finished and removes this exact registered entry.
        let mut runs = self.runs.lock().map_err(|_| "Remote lock unavailable")?;
        let mut history = self
            .history
            .lock()
            .map_err(|_| "Remote history lock unavailable")?;
        let Some(entry) = runs.get(&id) else {
            return history
                .records
                .get(&id)
                .map(|r| view(r, true))
                .ok_or("Unknown remote run.".into());
        };
        if self.failed.load(Ordering::Acquire) {
            return Err("Remote journal recovery is required before further archival; all original records are retained.".into());
        }
        if !entry.finished.load(Ordering::Acquire) {
            return Err(
                "The remote cleanup worker is still finishing; archive after it ends.".into(),
            );
        }
        let run = entry.snapshot();
        terminal_proof(&run)?;
        if let Some(previous) = history.records.get(&id) {
            if !same(previous, &run) {
                return Err(
                    "Active and archived remote records disagree; neither was discarded.".into(),
                );
            }
        } else {
            let bytes = serde_json::to_vec(&run).map_err(|e| e.to_string())?;
            if bytes.len() as u64 > MAX_JOURNAL {
                return Err("Remote journal exceeds its bound.".into());
            }
            let total = space(history.records.len(), history.bytes, bytes.len() as u64)?;
            let path = self
                .root
                .join("history")
                .join(format!("{}.json", id.to_hex()));
            if let Err(error) = write_atomic(&path, &bytes) {
                // Rename may have succeeded before directory flush failed. Stop
                // further admission/archival until recovery accounts for both.
                self.failed.store(true, Ordering::Release);
                return Err(format!(
                    "Remote archive write is uncertain; original active record retained: {error}"
                ));
            }
            history.bytes = total;
            if let Some(key) = run.request_key {
                history.by_request.insert(key, id);
            }
            history.records.insert(id, run.clone());
        }
        match fs::remove_file(self.path(id)) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "Archive is retained, but the active slot could not be released: {error}"
                ))
            }
        }
        runs.remove(&id);
        Ok(view(&run, true))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(number: u8) -> Run {
        let profile = SshProfile {
            name: "fixture".into(),
            vendor: "manual".into(),
            host: "example.com".into(),
            port: 22,
            username: "owner".into(),
            identity_file: "not-opened".into(),
            host_key: "not-opened".into(),
        };
        let id = Digest::from_bytes([number; 32]);
        Run {
            version: 1,
            run: id,
            request_key: Some(Digest::from_bytes([number.wrapping_add(1); 32])),
            parent: SandboxId::new(ExecutionId::new("exe-parent").unwrap()),
            parent_boot: SandboxBootGeneration::FIRST,
            connection: "env-owned".into(),
            host: trust::target(&profile).unwrap().0.host(),
            profile,
            cleanup_profile: None,
            program: "/opt/engine".into(),
            endpoint: "/run/engine.sock".into(),
            engine_sha256: Digest::from_bytes([9; 32]),
            memory_mib: 512,
            lifetime_seconds: 60,
            phase: Phase::CreationCancelled,
            observation: None,
            receipt: Some(
                json!({"state":"creation_cancelled","run":id,"server_power_changed":false,"durable":true}),
            ),
            detail: None,
        }
    }
    fn manager(root: &Path) -> Manager {
        fs::create_dir_all(root.join("runs")).unwrap();
        let (runs, history) = load(root).unwrap();
        Manager {
            root: root.into(),
            runs: Mutex::new(runs),
            history: Mutex::new(history),
            hosts: Mutex::new(BTreeMap::new()),
            failed: AtomicBool::new(false),
        }
    }
    fn install(manager: &Manager, run: Run) -> Arc<Entry> {
        manager.save(&run).unwrap();
        let id = run.run;
        let entry = Arc::new(Entry::new(run));
        manager.runs.lock().unwrap().insert(id, entry.clone());
        entry
    }
    #[test]
    fn archive_preserves_exact_identity_and_key_lookup_after_restart_and_lost_reply() {
        let root = tempfile::tempdir().unwrap();
        let m = manager(root.path());
        let r = run(1);
        install(&m, r.clone());
        let result = m.archive(r.run).unwrap();
        assert_eq!(result["archived"], true);
        assert_eq!(m.archive(r.run).unwrap(), result);
        assert!(!m.path(r.run).exists());
        assert!(m.runs.lock().unwrap().is_empty());
        let reopened = manager(root.path());
        assert_eq!(
            reopened.status(Some(r.run), None, false, None).unwrap(),
            result
        );
        assert_eq!(
            reopened.status(None, r.request_key, false, None).unwrap()["match"],
            result
        );
        let found = reopened
            .find_request(&BTreeMap::new(), r.request_key.unwrap())
            .unwrap()
            .unwrap();
        assert!(found.1 && same(&found.0, &r));
    }
    #[test]
    fn crash_between_archive_and_unlink_is_idempotent_but_conflict_keeps_both_records() {
        let root = tempfile::tempdir().unwrap();
        let m = manager(root.path());
        let r = run(2);
        install(&m, r.clone());
        let archive = m
            .root
            .join("history")
            .join(format!("{}.json", r.run.to_hex()));
        write_atomic(&archive, &serde_json::to_vec(&r).unwrap()).unwrap();
        let reopened = manager(root.path());
        assert!(reopened.runs.lock().unwrap().is_empty());
        assert!(!m.path(r.run).exists());
        let mut different = r.clone();
        different.memory_mib = 1024;
        m.save(&different).unwrap();
        assert!(load(root.path()).is_err());
        assert!(m.path(r.run).exists() && archive.exists());
        assert!(same(&read_json::<Run>(&archive).unwrap(), &r));
    }
    #[test]
    fn active_uncertain_unproven_or_still_finishing_runs_cannot_be_archived() {
        let root = tempfile::tempdir().unwrap();
        let m = manager(root.path());
        for (index, phase) in [
            Phase::Starting,
            Phase::Ready,
            Phase::Stopping,
            Phase::Unconfirmed,
            Phase::Ended,
        ]
        .into_iter()
        .enumerate()
        {
            let mut r = run(index as u8);
            r.phase = phase;
            let id = r.run;
            install(&m, r);
            assert!(m.archive(id).is_err());
            assert!(m.path(id).exists());
        }
        let r = run(9);
        let entry = install(&m, r.clone());
        entry.finished.store(false, Ordering::Release);
        assert!(m.archive(r.run).is_err());
        assert!(m.history.lock().unwrap().records.is_empty());
        entry.finished.store(true, Ordering::Release);
        assert!(m.archive(r.run).is_ok());
    }
    #[test]
    fn quotas_fail_before_discarding_proofs_and_pages_keep_bounded_results() {
        assert!(space(MAX_HISTORY, 0, 1).is_err());
        assert!(space(0, MAX_HISTORY_BYTES, 1).is_err());
        assert!(space(0, u64::MAX, 1).is_err());
        assert_eq!(
            space(MAX_HISTORY - 1, MAX_HISTORY_BYTES - 1, 1).unwrap(),
            MAX_HISTORY_BYTES
        );
        let root = tempfile::tempdir().unwrap();
        let m = manager(root.path());
        for id in 0..105 {
            let r = run(id);
            install(&m, r.clone());
            m.archive(r.run).unwrap();
        }
        let first = m.status(None, None, true, None).unwrap();
        assert_eq!(first["runs"].as_array().unwrap().len(), 100);
        let next = serde_json::from_value(first["next_after"].clone()).unwrap();
        let second = m.status(None, None, true, Some(next)).unwrap();
        assert_eq!(second["runs"].as_array().unwrap().len(), 5);
        assert!(second["next_after"].is_null());
        let r = run(120);
        install(&m, r.clone());
        m.history.lock().unwrap().bytes = MAX_HISTORY_BYTES;
        assert!(m.archive(r.run).is_err());
        assert!(m.path(r.run).exists());
        assert_eq!(m.history.lock().unwrap().records.len(), 105);
        assert!(m.status(Some(r.run), None, true, None).is_err());
        assert!(m.status(None, None, false, Some(r.run)).is_err());
        for value in m.history.lock().unwrap().records.values_mut() {
            value.detail = Some("x".repeat(64 * 1024));
        }
        let bounded = m.status(None, None, true, None).unwrap();
        assert!(bounded["runs"].as_array().unwrap().len() < PAGE_SIZE);
        assert!(serde_json::to_vec(&bounded).unwrap().len() < PAGE_BYTES + 1024);
        assert!(bounded["next_after"].is_string());
    }

    #[test]
    fn archival_write_failure_keeps_original_and_blocks_further_admission_until_recovery() {
        let root = tempfile::tempdir().unwrap();
        let m = manager(root.path());
        let r = run(7);
        install(&m, r.clone());
        let before = fs::read(m.path(r.run)).unwrap();
        fs::rename(
            root.path().join("history"),
            root.path().join("history-kept"),
        )
        .unwrap();
        fs::write(root.path().join("history"), b"unavailable destination").unwrap();
        assert!(m.archive(r.run).is_err());
        assert!(m.failed.load(Ordering::Acquire));
        assert_eq!(fs::read(m.path(r.run)).unwrap(), before);
        assert!(m.history.lock().unwrap().records.is_empty());
        assert!(m.archive(r.run).is_err());
        assert!(m
            .find_request(&m.runs.lock().unwrap(), r.request_key.unwrap())
            .unwrap()
            .is_some());
    }

    #[test]
    fn archive_recovery_refuses_tampered_proofs_and_duplicate_request_keys() {
        let root = tempfile::tempdir().unwrap();
        let m = manager(root.path());
        let original = run(3);
        install(&m, original.clone());
        m.archive(original.run).unwrap();
        let mut duplicate = run(4);
        duplicate.request_key = original.request_key;
        install(&m, duplicate.clone());
        assert!(load(root.path()).is_err());
        assert!(m.path(duplicate.run).exists());
        let mut corrupt = original.clone();
        corrupt.receipt = None;
        let path = root
            .path()
            .join("history")
            .join(format!("{}.json", original.run.to_hex()));
        write_atomic(&path, &serde_json::to_vec(&corrupt).unwrap()).unwrap();
        assert!(load(root.path()).is_err());
        assert!(m.path(duplicate.run).exists() && path.exists());
    }
}
