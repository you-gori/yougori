//! What a realm keeps of its jobs' artifacts and for how long, and how they travel with a copy of
//! the realm.
//!
//! **Retention.** A realm keeps a finished job's artifacts for a bounded time and up to a bounded
//! number of bytes, both set by its administrator within the ranges in `limits` and defaulting to
//! thirty days and twenty gigabytes. Whatever a job still in play needs is kept whatever its age:
//! the job's own artifacts, the inputs it will read and the checkpoint it resumes from, where a job
//! is in play until it has finished, including while it waits for a person to settle it. Of the
//! rest, what is older than the realm keeps goes, and then the oldest goes until what is kept fits.
//! A removed artifact's record stays, saying when and why; its file goes once no kept record names
//! those bytes, because two records of the same bytes share one file.
//!
//! **Copies.** The bytes are beside the realm's database rather than in it, so a copy of the
//! database alone would carry records naming files that are not there. Every copy this crate takes
//! of a realm therefore carries the artifacts too, each hashed as it is read and again where it
//! landed, and a copy that cannot carry one whole is not kept at all.
//!
//! **The portable backup.** The portable shape has no place for jobs yet. Rather than leave that to
//! be discovered on the day of a restore, a backup of a realm that holds jobs says so in its own
//! words, and a restore drill reads those words out with everything else a restore does not bring
//! back.
use super::{
    rows,
    shelf::{self, Refusal, Shelf},
    JobArtifact, JobError, Retention,
};
use crate::core::{
    audit::{Decision, Entry},
    identity::Action,
    limits::{
        ABANDONED_STAGING_AFTER, LEAST_JOB_ARTIFACT_BYTES, LONGEST_JOB_ARTIFACT_KEEP, MAX_ARTIFACTS_REMOVED_PER_PASS, MOST_JOB_ARTIFACT_BYTES, SHORTEST_JOB_ARTIFACT_KEEP,
    },
    store::room,
    Core,
};
use rusqlite::{Connection, OpenFlags};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Why the sweep removed an artifact, in the words its record keeps.
const AGED: &str = "older than this grid keeps job artifacts";
const OVER: &str = "this grid was keeping more bytes of job artifacts than it is allowed";

/// What one pass of the artifact sweep did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tidied {
    /// Uploads nobody finished, taken out of the staging folder.
    pub abandoned_uploads: usize,
    pub artifacts_removed: usize,
    pub bytes_freed: u64,
    /// What the kept artifacts hold on the disk afterwards, each checksum counted once.
    pub bytes_kept: u64,
    /// More is kept than the realm's allowance, because jobs still in play need it. Nothing they
    /// need is removed to make it fit.
    pub over_allowance: bool,
}

/// What travelled with a copy of a realm: each kept artifact's checksum and size, every one hashed
/// again where it landed.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Carried {
    pub artifacts: Vec<(String, u64)>,
}

impl Carried {
    pub fn bytes(&self) -> u64 {
        self.artifacts.iter().map(|(_, bytes)| bytes).sum()
    }
}

/// A moment the core was handed, as the file system's clock reads it.
fn moment(seconds: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(seconds.max(0) as u64)
}

impl Core {
    /// How long, and how much, this realm keeps of its jobs' artifacts.
    pub fn job_retention(&self) -> Result<Retention, JobError> {
        if !self.has_jobs()? {
            return Ok(Retention::default());
        }
        Ok(rows::retention(self.store.connection(), &self.realm.id)?.unwrap_or_default())
    }

    /// Sets how long, and how much, this realm keeps of its jobs' artifacts, within the ranges in
    /// `limits`. For somebody who may place work.
    pub fn set_job_retention(&mut self, by: &str, retention: Retention, now: i64) -> Result<Retention, JobError> {
        self.job_capability()?;
        self.allowed(by, Action::PlaceWork).map_err(JobError::NotAllowed)?;
        if retention.keep_seconds < SHORTEST_JOB_ARTIFACT_KEEP {
            return Err(JobError::Limit(format!(
                "A grid keeps job artifacts for at least {} hours, so nobody loses a job's outputs before they could fetch them",
                SHORTEST_JOB_ARTIFACT_KEEP / 3_600
            )));
        }
        if retention.keep_seconds > LONGEST_JOB_ARTIFACT_KEEP {
            return Err(JobError::Limit(format!("A grid keeps job artifacts for at most {} days", LONGEST_JOB_ARTIFACT_KEEP / 86_400)));
        }
        if retention.keep_bytes < LEAST_JOB_ARTIFACT_BYTES {
            return Err(JobError::Limit(format!("A grid keeps at least {LEAST_JOB_ARTIFACT_BYTES} bytes of job artifacts, room for one of the largest")));
        }
        if retention.keep_bytes > MOST_JOB_ARTIFACT_BYTES {
            return Err(JobError::Limit(format!("A grid keeps at most {MOST_JOB_ARTIFACT_BYTES} bytes of job artifacts")));
        }
        self.jobs_ready()?;
        rows::put_retention(self.store.connection(), &self.realm.id, &retention, by, now)?;
        let mut entry = Entry::new(&self.realm.id, by, "jobs.retention set", Decision::Allowed)
            .because(&format!("keep job artifacts for {} days and up to {} bytes", retention.keep_seconds / 86_400, retention.keep_bytes));
        entry.resource_id = Some("job-artifacts".into());
        self.note(entry, now)?;
        Ok(retention)
    }

    /// One pass of the artifact sweep: uploads nobody finished, then artifacts past what the realm
    /// keeps. `expire_jobs` runs this every time; calling it directly does the same.
    ///
    /// A staged upload that nothing has been written to for `ABANDONED_STAGING_AFTER` is removed.
    /// Then, when anything is older than the realm keeps or more bytes are kept than it allows,
    /// what no job still in play needs is removed, oldest first, at most
    /// `MAX_ARTIFACTS_REMOVED_PER_PASS` at a time; the next pass carries on.
    pub fn tidy_job_artifacts(&mut self, now: i64) -> Result<Tidied, JobError> {
        let shelf = self.job_shelf();
        let mut tidied = Tidied { abandoned_uploads: shelf.sweep_staging(moment(now.saturating_sub(ABANDONED_STAGING_AFTER))), ..Tidied::default() };
        if !self.has_jobs()? {
            return Ok(tidied);
        }
        let connection = self.store.connection();
        let realm = self.realm.id.clone();
        let retention = rows::retention(connection, &realm)?.unwrap_or_default();
        let cutoff = now.saturating_sub(retention.keep_seconds);
        let kept_bytes = rows::kept_bytes(connection, &realm)?;
        tidied.bytes_kept = kept_bytes;
        if rows::kept_before(connection, &realm, cutoff)? == 0 && kept_bytes <= retention.keep_bytes {
            return Ok(tidied);
        }
        // What jobs still in play need, which nothing here touches.
        let mut needed_jobs: HashSet<String> = HashSet::new();
        let mut needed: HashSet<String> = HashSet::new();
        for job in rows::jobs_in_play(connection, &realm)? {
            needed.extend(job.spec.inputs.iter().map(|input| input.artifact_id.clone()));
            needed.extend(job.checkpoint.clone());
            needed_jobs.insert(job.id);
        }
        let kept = rows::kept_artifacts(connection, &realm)?;
        let mut holders: HashMap<&str, usize> = HashMap::new();
        for artifact in &kept {
            *holders.entry(artifact.sha256.as_str()).or_default() += 1;
        }
        let mut bytes = kept_bytes;
        let mut chosen: Vec<(&JobArtifact, &'static str)> = Vec::new();
        for artifact in &kept {
            if chosen.len() >= MAX_ARTIFACTS_REMOVED_PER_PASS {
                break;
            }
            if needed_jobs.contains(&artifact.job_id) || needed.contains(&artifact.id) {
                continue;
            }
            let reason = if artifact.recorded_at <= cutoff {
                AGED
            } else if bytes > retention.keep_bytes {
                OVER
            } else {
                continue;
            };
            chosen.push((artifact, reason));
            if let Some(left) = holders.get_mut(artifact.sha256.as_str()) {
                *left -= 1;
                if *left == 0 {
                    bytes = bytes.saturating_sub(artifact.bytes);
                }
            }
        }
        tidied.bytes_kept = bytes;
        tidied.over_allowance = bytes > retention.keep_bytes;
        if chosen.is_empty() {
            return Ok(tidied);
        }
        {
            let change = connection.unchecked_transaction().map_err(|error| JobError::Trouble(format!("Cannot begin a change: {error}")))?;
            for (artifact, reason) in &chosen {
                rows::mark_removed(&change, &artifact.id, now, reason)?;
            }
            change.commit().map_err(|error| JobError::Trouble(format!("Cannot finish this change: {error}")))?;
        }
        // The records say the bytes are gone; now the files go, each once nothing kept names it.
        // A file that cannot be removed now is still unnamed next time, and costs only room.
        let mut emptied: Vec<&str> = chosen.iter().map(|(artifact, _)| artifact.sha256.as_str()).collect();
        emptied.sort_unstable();
        emptied.dedup();
        for sha256 in emptied {
            if !rows::still_kept(connection, &realm, sha256)? {
                let _ = shelf.remove(sha256);
            }
        }
        tidied.artifacts_removed = chosen.len();
        tidied.bytes_freed = kept_bytes.saturating_sub(bytes);
        let mut entry = Entry::new(&realm, "owner", "jobs.artifacts removed", Decision::Allowed).because(&format!(
            "{} artifacts, {} bytes: older than {} days, or past the {} bytes this grid keeps. What a job still in play needs was kept{}",
            tidied.artifacts_removed,
            tidied.bytes_freed,
            retention.keep_seconds / 86_400,
            retention.keep_bytes,
            if tidied.over_allowance { ", and that alone is more than the allowance" } else { "" }
        ));
        entry.resource_id = Some("job-artifacts".into());
        self.note(entry, now)?;
        Ok(tidied)
    }

    /// What a portable backup of this realm leaves out, in words, when the realm holds jobs. The
    /// portable shape has no place for them yet, and a backup that left them out silently would be
    /// taken for the whole realm.
    pub(crate) fn jobs_left_out_of_backup(&self) -> Result<Vec<String>, String> {
        if !self.has_jobs()? {
            return Ok(Vec::new());
        }
        let connection = self.store.connection();
        let jobs = rows::job_count(connection, &self.realm.id)?;
        if jobs == 0 {
            return Ok(Vec::new());
        }
        let artifacts = rows::kept_artifacts(connection, &self.realm.id)?.len();
        let bytes = rows::kept_bytes(connection, &self.realm.id)?;
        Ok(vec![format!(
            "Jobs. This realm holds {jobs} jobs and {artifacts} kept job artifacts ({bytes} bytes), and the portable backup does not carry jobs, their attempts or their artifacts yet: a realm restored from it has an empty queue and no artifacts, and the core's record of each attempt's reservation comes back naming a job the restored realm does not hold. A copy taken with copy_to carries all of it, every artifact checked against its checksum"
        )])
    }
}

/// Where the job artifacts of the realm whose database is at `realm` are kept.
pub(crate) fn artifact_folder(realm: &Path) -> PathBuf {
    shelf::folder_beside(realm)
}

/// Carries a realm's kept job artifacts beside a copy of its database, checking every one.
///
/// What is carried is read from the copy itself, so it is exactly what the copy's records name,
/// whatever the realm did after the copy was taken. Each file is hashed as it is read and again
/// where it landed before it is kept there. A realm that has never had a job carries nothing and the
/// copy gets no folder. If one artifact cannot be carried whole, nothing of the folder is kept and
/// the error names the artifact: the caller then removes the copy too, because a copy whose records
/// name files that are not beside it is the one thing this must never leave behind.
pub(crate) fn carry_artifacts(from: &Path, to: &Path) -> Result<Carried, String> {
    let listed = {
        let copy = Connection::open_with_flags(to, OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX)
            .map_err(|error| format!("Cannot read the copy that was just taken: {error}"))?;
        if !rows::present(&copy)? {
            return Ok(Carried::default());
        }
        rows::kept_digests(&copy)?
    };
    if listed.is_empty() {
        return Ok(Carried::default());
    }
    let carried = Carried { artifacts: listed };
    let source = Shelf::beside(from);
    let destination = Shelf::beside(to);
    room::enough_for(destination.folder(), carried.bytes(), "for the job artifacts this copy carries")?;
    for (sha256, bytes) in &carried.artifacts {
        if let Err(refusal) = source.carry(&destination, *bytes, sha256) {
            let _ = std::fs::remove_dir_all(destination.folder());
            return Err(match refusal {
                Refusal::Damaged | Refusal::Mismatch | Refusal::Short(_) | Refusal::Long => {
                    format!("The copy was not kept: job artifact {sha256} no longer matches its checksum in this realm, so it cannot be carried exactly")
                }
                Refusal::Missing => format!("The copy was not kept: job artifact {sha256} is recorded in this realm and its bytes are not beside it"),
                Refusal::Trouble(why) => format!("The copy was not kept: {why}"),
            });
        }
    }
    // The staging folder is only how the bytes got there.
    let _ = std::fs::remove_dir(destination.folder().join("staging"));
    Ok(carried)
}
