//! Where jobs are kept: four tables in the realm's own database, written through the realm's one
//! connection, on a version track of their own.
//!
//! The realm's schema version is not raised for these. Builds that already shipped compare that
//! number exactly, and several of the realm's own tests walk it version by version, so moving it is
//! a coordinated change rather than something one profile does on the side. Instead the tables are
//! made the first time a job is admitted, each step and the record of it in one change, exactly as
//! `Store::migrate` does for the realm, and recorded in `job_migrations`. An older build that opens
//! the realm does not look at them and is not disturbed by them; a newer one that finds a later
//! version than it knows refuses to touch the jobs rather than guessing. The statements are written
//! so they can move into a step of the realm's own schema unchanged when that happens.
//!
//! Nothing here references a host, a computer, a workload or a reservation by foreign key. Those
//! rows are re-pointed and forgotten by the realm's own code (`Store::put_host`, a bridge's undo),
//! which knows nothing of jobs, and a key here would make the realm refuse to do either.
use super::{ArtifactRole, AttemptState, InFlight, Job, JobArtifact, JobAttempt, JobQueue, JobState, Retention};
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::collections::HashSet;

/// The version of the jobs tables this build writes.
pub const VERSION: u32 = 1;

/// Everything version 1 holds.
const V1: &str = r#"
-- A queue exists as a row only once somebody has set whether it admits work. A queue nobody has
-- closed is open, and has no row.
CREATE TABLE job_queues (
    realm_id   TEXT NOT NULL REFERENCES realms(id),
    name       TEXT NOT NULL,
    open       INTEGER NOT NULL CHECK (open IN (0, 1)),
    in_flight  TEXT CHECK (in_flight IN ('finish','stop')),
    reason     TEXT NOT NULL DEFAULT '',
    changed_by TEXT NOT NULL,
    changed_at INTEGER NOT NULL,
    PRIMARY KEY (realm_id, name)
);

CREATE TABLE jobs (
    id              TEXT PRIMARY KEY,
    realm_id        TEXT NOT NULL REFERENCES realms(id),
    queue           TEXT NOT NULL,
    principal_id    TEXT NOT NULL,
    device_id       TEXT NOT NULL,
    spec            TEXT NOT NULL,
    side_effects    TEXT NOT NULL CHECK (side_effects IN ('repeatable','dedupKey','manualReconcile')),
    dedup_key       TEXT,
    state           TEXT NOT NULL CHECK (state IN ('queued','running','cancelRequested','succeeded','failed','cancelled','stopped','outcomeUnknown')),
    attempts        INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    fence           INTEGER NOT NULL DEFAULT 0 CHECK (fence >= 0),
    current_attempt TEXT,
    checkpoint      TEXT,
    not_before      INTEGER NOT NULL,
    note            TEXT NOT NULL DEFAULT '',
    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    finished_at     INTEGER,
    -- A key exactly when the job said it hands one to the system it changes.
    CHECK ((side_effects = 'dedupKey') = (dedup_key IS NOT NULL))
);

-- One job per deduplication key in a realm, whatever has happened to it since: sending the same
-- work twice finds the first, and never makes a second.
CREATE UNIQUE INDEX jobs_by_dedup_key ON jobs (realm_id, dedup_key) WHERE dedup_key IS NOT NULL;
CREATE INDEX jobs_waiting ON jobs (realm_id, state, not_before, created_at);

-- Research belongs in a research grid, and a research grid runs no generic jobs. This says so to
-- anything that opens the file, not only to the code that normally writes it.
CREATE TRIGGER jobs_company_only BEFORE INSERT ON jobs
WHEN (SELECT kind FROM realms WHERE id = NEW.realm_id) <> 'primary'
BEGIN SELECT RAISE(ABORT, 'a research grid does not run generic jobs'); END;

-- A fencing token only rises, so a number that has been left behind can never come back.
CREATE TRIGGER job_fence_only_rises BEFORE UPDATE OF fence ON jobs
WHEN NEW.fence < OLD.fence
BEGIN SELECT RAISE(ABORT, 'a job''s fencing token only rises'); END;

-- A finished job is finished. A job whose outcome is unknown is waiting for a person, not finished.
CREATE TRIGGER finished_jobs_stay_finished BEFORE UPDATE OF state ON jobs
WHEN OLD.state IN ('succeeded','failed','cancelled','stopped') AND NEW.state <> OLD.state
BEGIN SELECT RAISE(ABORT, 'a finished job does not move again'); END;

CREATE TABLE job_attempts (
    id           TEXT PRIMARY KEY,
    realm_id     TEXT NOT NULL REFERENCES realms(id),
    job_id       TEXT NOT NULL REFERENCES jobs(id),
    number       INTEGER NOT NULL CHECK (number >= 1),
    fence        INTEGER NOT NULL CHECK (fence >= 1),
    host_id      TEXT NOT NULL,
    device_id    TEXT NOT NULL,
    workload_id  TEXT NOT NULL,
    lease_id     TEXT NOT NULL,
    state        TEXT NOT NULL CHECK (state IN ('leased','running','succeeded','failed','stopped','cancelled','lost','timedOut')),
    granted_at   INTEGER NOT NULL,
    started_at   INTEGER,
    heartbeat_at INTEGER NOT NULL,
    expires_at   INTEGER NOT NULL,
    deadline     INTEGER NOT NULL,
    ended_at     INTEGER,
    ending       TEXT NOT NULL DEFAULT '',
    UNIQUE (job_id, number),
    UNIQUE (job_id, fence)
);

CREATE INDEX job_attempts_live ON job_attempts (realm_id, state) WHERE state IN ('leased','running');
CREATE INDEX job_attempts_of_job ON job_attempts (job_id, number);

-- An attempt that has ended does not begin again; the next try is a new attempt with a new token.
CREATE TRIGGER ended_attempts_stay_ended BEFORE UPDATE OF state ON job_attempts
WHEN OLD.state NOT IN ('leased','running') AND NEW.state <> OLD.state
BEGIN SELECT RAISE(ABORT, 'an attempt that has ended does not start again'); END;

-- What an artifact is called, which attempt sent it under which token, how large it is and what it
-- hashed to. Never its bytes: those are in a file beside the realm named by the checksum. When the
-- retention sweep removes the bytes, the row stays and says when and why.
CREATE TABLE job_artifacts (
    id          TEXT PRIMARY KEY,
    realm_id    TEXT NOT NULL REFERENCES realms(id),
    job_id      TEXT NOT NULL REFERENCES jobs(id),
    attempt_id  TEXT NOT NULL REFERENCES job_attempts(id),
    fence       INTEGER NOT NULL CHECK (fence >= 1),
    role        TEXT NOT NULL CHECK (role IN ('output','checkpoint')),
    name        TEXT NOT NULL CHECK (
        length(name) BETWEEN 1 AND 64
        AND name NOT GLOB '*[^A-Za-z0-9._-]*'
        AND substr(name, 1, 1) GLOB '[A-Za-z0-9]'
        AND instr(name, '..') = 0
    ),
    bytes       INTEGER NOT NULL CHECK (bytes >= 0),
    sha256      TEXT NOT NULL CHECK (length(sha256) = 64 AND sha256 NOT GLOB '*[^0-9a-f]*'),
    recorded_at INTEGER NOT NULL,
    removed_at  INTEGER,
    removed_reason TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX job_outputs_once ON job_artifacts (attempt_id, name) WHERE role = 'output';
CREATE INDEX job_artifacts_of_attempt ON job_artifacts (attempt_id);
CREATE INDEX job_artifacts_of_job ON job_artifacts (job_id);
-- The artifacts whose bytes are still kept, oldest first: the set retention reads, and the only
-- part of the table that is not just history.
CREATE INDEX job_artifacts_kept ON job_artifacts (realm_id, recorded_at, sha256, bytes) WHERE removed_at IS NULL;

-- What was recorded is never rewritten. The one change allowed is the retention sweep saying, once,
-- when and why the bytes were removed; what they were, and who sent them, stays as it was.
CREATE TRIGGER job_artifacts_never_change BEFORE UPDATE ON job_artifacts
WHEN NEW.id <> OLD.id OR NEW.realm_id <> OLD.realm_id OR NEW.job_id <> OLD.job_id OR NEW.attempt_id <> OLD.attempt_id
  OR NEW.fence <> OLD.fence OR NEW.role <> OLD.role OR NEW.name <> OLD.name OR NEW.bytes <> OLD.bytes
  OR NEW.sha256 <> OLD.sha256 OR NEW.recorded_at <> OLD.recorded_at
  OR OLD.removed_at IS NOT NULL OR NEW.removed_at IS NULL
BEGIN SELECT RAISE(ABORT, 'a recorded artifact is never rewritten'); END;

-- How long, and how much, a realm keeps of its jobs' artifacts, once its administrator has said. A
-- realm nobody has set keeps the defaults in `limits`, and has no row.
CREATE TABLE job_retention (
    realm_id     TEXT PRIMARY KEY REFERENCES realms(id),
    keep_seconds INTEGER NOT NULL CHECK (keep_seconds > 0),
    keep_bytes   INTEGER NOT NULL CHECK (keep_bytes > 0),
    changed_by   TEXT NOT NULL,
    changed_at   INTEGER NOT NULL
);
"#;

fn step(version: u32) -> Option<&'static str> {
    match version {
        1 => Some(V1),
        _ => None,
    }
}

fn describe(version: u32) -> &'static str {
    match version {
        1 => "finite jobs: queues and whether they admit work, jobs, their fenced attempts, the artifacts each attempt sent, and how long a realm keeps them",
        _ => "unknown",
    }
}

fn trouble(what: &str, error: rusqlite::Error) -> String {
    format!("Cannot {what}: {error}")
}

/// Which version of the jobs tables this realm holds, nought when it holds none.
pub(super) fn version(connection: &Connection) -> Result<u32, String> {
    let present: bool = connection
        .query_row("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'job_migrations'", [], |_| Ok(true))
        .optional()
        .map_err(|error| trouble("read which jobs this grid holds", error))?
        .unwrap_or(false);
    if !present {
        return Ok(0);
    }
    connection
        .query_row("SELECT COALESCE(MAX(version), 0) FROM job_migrations", [], |row| row.get::<_, i64>(0))
        .map(|version| version.max(0) as u32)
        .map_err(|error| trouble("read which jobs this grid holds", error))
}

/// Whether this realm holds any jobs tables at all. Reading a realm that has never had a job
/// answers from this, and writes nothing.
pub(super) fn present(connection: &Connection) -> Result<bool, String> {
    Ok(version(connection)? > 0)
}

/// Brings the jobs tables up to this build's version, in one change with the record of it.
pub(super) fn ensure(connection: &Connection) -> Result<(), String> {
    let at = version(connection)?;
    if at == VERSION {
        return Ok(());
    }
    if at > VERSION {
        return Err(format!("The jobs in this grid were written by a newer Yougori (jobs version {at}); update Yougori to work with them"));
    }
    let change = connection.unchecked_transaction().map_err(|error| trouble("begin a change", error))?;
    change
        .execute_batch("CREATE TABLE IF NOT EXISTS job_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL, description TEXT NOT NULL)")
        .map_err(|error| trouble("prepare this grid for jobs", error))?;
    for version in (at + 1)..=VERSION {
        let Some(statements) = step(version) else {
            return Err(format!("This build has no step to jobs version {version}"));
        };
        change.execute_batch(statements).map_err(|error| trouble(&format!("move this grid's jobs to version {version}"), error))?;
        change
            .execute("INSERT INTO job_migrations (version, applied_at, description) VALUES (?1, ?2, ?3)", params![version as i64, crate::now(), describe(version)])
            .map_err(|error| trouble("record the change of version", error))?;
    }
    change.commit().map_err(|error| trouble("finish preparing this grid for jobs", error))
}

fn unreadable(column: usize, what: &str, detail: impl std::fmt::Display) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(column, rusqlite::types::Type::Text, Box::new(std::io::Error::other(format!("{what}: {detail}"))))
}

fn count(connection: &Connection, sql: &str, binding: impl rusqlite::Params) -> Result<usize, String> {
    connection.query_row(sql, binding, |row| row.get::<_, i64>(0)).map(|found| found.max(0) as usize).map_err(|error| trouble("count this grid's jobs", error))
}

// ---- Jobs ----

const JOBS: &str = "SELECT id, realm_id, queue, principal_id, device_id, spec, state, attempts, fence, current_attempt, checkpoint, not_before, note, created_at, updated_at, finished_at FROM jobs";

fn job_from(row: &Row<'_>) -> rusqlite::Result<Job> {
    let spec: String = row.get(5)?;
    let state: String = row.get(6)?;
    Ok(Job {
        id: row.get(0)?,
        realm_id: row.get(1)?,
        queue: row.get(2)?,
        principal_id: row.get(3)?,
        device_id: row.get(4)?,
        spec: serde_json::from_str(&spec).map_err(|error| unreadable(5, "a job's description", error))?,
        state: JobState::from_word(&state).ok_or_else(|| unreadable(6, "a job's state", &state))?,
        attempts: row.get::<_, i64>(7)?.clamp(0, i64::from(u32::MAX)) as u32,
        fence: row.get::<_, i64>(8)?.max(0) as u64,
        current_attempt: row.get(9)?,
        checkpoint: row.get(10)?,
        not_before: row.get(11)?,
        note: row.get(12)?,
        created_at: row.get(13)?,
        updated_at: row.get(14)?,
        finished_at: row.get(15)?,
    })
}

fn jobs_where(connection: &Connection, tail: &str, binding: impl rusqlite::Params) -> Result<Vec<Job>, String> {
    let mut query = connection.prepare(&format!("{JOBS} {tail}")).map_err(|error| trouble("read this grid's jobs", error))?;
    let rows = query.query_map(binding, job_from).map_err(|error| trouble("read this grid's jobs", error))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's jobs", error))
}

pub(super) fn insert_job(connection: &Connection, job: &Job) -> Result<(), String> {
    let spec = serde_json::to_string(&job.spec).map_err(|error| format!("Cannot write this job's description: {error}"))?;
    connection
        .execute(
            "INSERT INTO jobs (id, realm_id, queue, principal_id, device_id, spec, side_effects, dedup_key, state, attempts, fence, current_attempt, checkpoint,
                               not_before, note, created_at, updated_at, finished_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                job.id,
                job.realm_id,
                job.queue,
                job.principal_id,
                job.device_id,
                spec,
                job.spec.side_effects.word(),
                job.spec.side_effects.key(),
                job.state.word(),
                i64::from(job.attempts),
                job.fence as i64,
                job.current_attempt,
                job.checkpoint,
                job.not_before,
                job.note,
                job.created_at,
                job.updated_at,
                job.finished_at,
            ],
        )
        .map(|_| ())
        .map_err(|error| trouble("record this job", error))
}

/// Writes a job's moving parts, but only while it is still where the caller last saw it: in the
/// same state, under the same fencing token. Answers whether it was. The comparison is made here,
/// inside the change that writes, so a job that moved between being read and being written is not
/// moved a second time on the strength of a stale reading.
pub(super) fn move_job(connection: &Connection, job: &Job, was: JobState, fence_was: u64) -> Result<bool, String> {
    connection
        .execute(
            "UPDATE jobs SET state = ?2, attempts = ?3, fence = ?4, current_attempt = ?5, checkpoint = ?6, not_before = ?7, note = ?8, updated_at = ?9, finished_at = ?10
             WHERE id = ?1 AND state = ?11 AND fence = ?12",
            params![
                job.id,
                job.state.word(),
                i64::from(job.attempts),
                job.fence as i64,
                job.current_attempt,
                job.checkpoint,
                job.not_before,
                job.note,
                job.updated_at,
                job.finished_at,
                was.word(),
                fence_was as i64,
            ],
        )
        .map(|changed| changed == 1)
        .map_err(|error| trouble("move this job on", error))
}

pub(super) fn job(connection: &Connection, realm_id: &str, id: &str) -> Result<Option<Job>, String> {
    connection
        .query_row(&format!("{JOBS} WHERE realm_id = ?1 AND id = ?2"), params![realm_id, id], job_from)
        .optional()
        .map_err(|error| trouble("read this job", error))
}

pub(super) fn jobs(connection: &Connection, realm_id: &str) -> Result<Vec<Job>, String> {
    jobs_where(connection, "WHERE realm_id = ?1 ORDER BY created_at, rowid", params![realm_id])
}

pub(super) fn job_by_key(connection: &Connection, realm_id: &str, key: &str) -> Result<Option<Job>, String> {
    connection
        .query_row(&format!("{JOBS} WHERE realm_id = ?1 AND dedup_key = ?2"), params![realm_id, key], job_from)
        .optional()
        .map_err(|error| trouble("read this job", error))
}

/// Jobs waiting for a computer whose backoff has passed, oldest first.
pub(super) fn waiting_jobs(connection: &Connection, realm_id: &str, now: i64) -> Result<Vec<Job>, String> {
    jobs_where(connection, "WHERE realm_id = ?1 AND state = 'queued' AND not_before <= ?2 ORDER BY created_at, rowid", params![realm_id, now])
}

/// Jobs with an attempt in flight in one queue.
pub(super) fn running_in(connection: &Connection, realm_id: &str, queue: &str) -> Result<Vec<Job>, String> {
    jobs_where(connection, "WHERE realm_id = ?1 AND queue = ?2 AND state = 'running' ORDER BY created_at, rowid", params![realm_id, queue])
}

/// How many jobs have not finished: waiting, running, or asked to stop.
pub(super) fn unfinished_jobs(connection: &Connection, realm_id: &str) -> Result<usize, String> {
    count(connection, "SELECT COUNT(*) FROM jobs WHERE realm_id = ?1 AND state IN ('queued','running','cancelRequested')", params![realm_id])
}

/// Jobs still in play: not finished, including those waiting for a person to settle them, whose
/// artifacts somebody may yet need to look at.
pub(super) fn jobs_in_play(connection: &Connection, realm_id: &str) -> Result<Vec<Job>, String> {
    jobs_where(connection, "WHERE realm_id = ?1 AND state IN ('queued','running','cancelRequested','outcomeUnknown') ORDER BY created_at, rowid", params![realm_id])
}

/// How many jobs the realm holds at all.
pub(super) fn job_count(connection: &Connection, realm_id: &str) -> Result<usize, String> {
    count(connection, "SELECT COUNT(*) FROM jobs WHERE realm_id = ?1", params![realm_id])
}

// ---- Attempts ----

const ATTEMPTS: &str = "SELECT id, job_id, number, fence, host_id, device_id, workload_id, lease_id, state, granted_at, started_at, heartbeat_at, expires_at, deadline, ended_at, ending
                        FROM job_attempts";

fn attempt_from(row: &Row<'_>) -> rusqlite::Result<JobAttempt> {
    let state: String = row.get(8)?;
    Ok(JobAttempt {
        id: row.get(0)?,
        job_id: row.get(1)?,
        number: row.get::<_, i64>(2)?.clamp(0, i64::from(u32::MAX)) as u32,
        fence: row.get::<_, i64>(3)?.max(0) as u64,
        host_id: row.get(4)?,
        device_id: row.get(5)?,
        workload_id: row.get(6)?,
        lease_id: row.get(7)?,
        state: AttemptState::from_word(&state).ok_or_else(|| unreadable(8, "an attempt's state", &state))?,
        granted_at: row.get(9)?,
        started_at: row.get(10)?,
        heartbeat_at: row.get(11)?,
        expires_at: row.get(12)?,
        deadline: row.get(13)?,
        ended_at: row.get(14)?,
        ending: row.get(15)?,
    })
}

fn attempts_where(connection: &Connection, tail: &str, binding: impl rusqlite::Params) -> Result<Vec<JobAttempt>, String> {
    let mut query = connection.prepare(&format!("{ATTEMPTS} {tail}")).map_err(|error| trouble("read this grid's attempts", error))?;
    let rows = query.query_map(binding, attempt_from).map_err(|error| trouble("read this grid's attempts", error))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's attempts", error))
}

pub(super) fn insert_attempt(connection: &Connection, realm_id: &str, attempt: &JobAttempt) -> Result<(), String> {
    connection
        .execute(
            "INSERT INTO job_attempts (id, realm_id, job_id, number, fence, host_id, device_id, workload_id, lease_id, state, granted_at, started_at, heartbeat_at,
                                       expires_at, deadline, ended_at, ending)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17)",
            params![
                attempt.id,
                realm_id,
                attempt.job_id,
                i64::from(attempt.number),
                attempt.fence as i64,
                attempt.host_id,
                attempt.device_id,
                attempt.workload_id,
                attempt.lease_id,
                attempt.state.word(),
                attempt.granted_at,
                attempt.started_at,
                attempt.heartbeat_at,
                attempt.expires_at,
                attempt.deadline,
                attempt.ended_at,
                attempt.ending,
            ],
        )
        .map(|_| ())
        .map_err(|error| trouble("record this attempt", error))
}

/// Writes an attempt's moving parts while it is still in the state the caller last saw, under the
/// same token. Answers whether it was.
pub(super) fn move_attempt(connection: &Connection, attempt: &JobAttempt, was: AttemptState) -> Result<bool, String> {
    connection
        .execute(
            "UPDATE job_attempts SET state = ?2, started_at = ?3, heartbeat_at = ?4, expires_at = ?5, ended_at = ?6, ending = ?7
             WHERE id = ?1 AND state = ?8 AND fence = ?9",
            params![
                attempt.id,
                attempt.state.word(),
                attempt.started_at,
                attempt.heartbeat_at,
                attempt.expires_at,
                attempt.ended_at,
                attempt.ending,
                was.word(),
                attempt.fence as i64,
            ],
        )
        .map(|changed| changed == 1)
        .map_err(|error| trouble("move this attempt on", error))
}

pub(super) fn attempt(connection: &Connection, realm_id: &str, id: &str) -> Result<Option<JobAttempt>, String> {
    connection
        .query_row(&format!("{ATTEMPTS} WHERE realm_id = ?1 AND id = ?2"), params![realm_id, id], attempt_from)
        .optional()
        .map_err(|error| trouble("read this attempt", error))
}

pub(super) fn attempts_of(connection: &Connection, job_id: &str) -> Result<Vec<JobAttempt>, String> {
    attempts_where(connection, "WHERE job_id = ?1 ORDER BY number", params![job_id])
}

/// Every attempt still holding, or still meant to be holding, a computer.
pub(super) fn live_attempts(connection: &Connection, realm_id: &str) -> Result<Vec<JobAttempt>, String> {
    attempts_where(connection, "WHERE realm_id = ?1 AND state IN ('leased','running') ORDER BY granted_at, rowid", params![realm_id])
}

// ---- Artifacts ----

const ARTIFACTS: &str = "SELECT id, job_id, attempt_id, fence, role, name, bytes, sha256, recorded_at, removed_at, removed_reason FROM job_artifacts";

fn artifact_from(row: &Row<'_>) -> rusqlite::Result<JobArtifact> {
    let role: String = row.get(4)?;
    Ok(JobArtifact {
        id: row.get(0)?,
        job_id: row.get(1)?,
        attempt_id: row.get(2)?,
        fence: row.get::<_, i64>(3)?.max(0) as u64,
        role: ArtifactRole::from_word(&role).ok_or_else(|| unreadable(4, "an artifact's role", &role))?,
        name: row.get(5)?,
        bytes: row.get::<_, i64>(6)?.max(0) as u64,
        sha256: row.get(7)?,
        recorded_at: row.get(8)?,
        removed_at: row.get(9)?,
        removed_reason: row.get(10)?,
    })
}

fn artifacts_where(connection: &Connection, tail: &str, binding: impl rusqlite::Params) -> Result<Vec<JobArtifact>, String> {
    let mut query = connection.prepare(&format!("{ARTIFACTS} {tail}")).map_err(|error| trouble("read this grid's artifacts", error))?;
    let rows = query.query_map(binding, artifact_from).map_err(|error| trouble("read this grid's artifacts", error))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read this grid's artifacts", error))
}

/// Records an artifact, but only while the attempt that sent it is still its job's current attempt,
/// still running, under the same token. Answers whether it was, so an attempt that was replaced
/// between being checked and being written records nothing.
pub(super) fn insert_artifact(connection: &Connection, realm_id: &str, artifact: &JobArtifact) -> Result<bool, String> {
    connection
        .execute(
            "INSERT INTO job_artifacts (id, realm_id, job_id, attempt_id, fence, role, name, bytes, sha256, recorded_at)
             SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10
             WHERE EXISTS (SELECT 1 FROM jobs JOIN job_attempts ON job_attempts.id = jobs.current_attempt
                           WHERE jobs.id = ?3 AND job_attempts.id = ?4 AND jobs.fence = ?5 AND job_attempts.fence = ?5
                             AND job_attempts.state = 'running' AND jobs.state IN ('running','cancelRequested'))",
            params![
                artifact.id,
                realm_id,
                artifact.job_id,
                artifact.attempt_id,
                artifact.fence as i64,
                artifact.role.word(),
                artifact.name,
                artifact.bytes as i64,
                artifact.sha256,
                artifact.recorded_at,
            ],
        )
        .map(|written| written == 1)
        .map_err(|error| trouble("record this artifact", error))
}

pub(super) fn artifact(connection: &Connection, realm_id: &str, id: &str) -> Result<Option<JobArtifact>, String> {
    connection
        .query_row(&format!("{ARTIFACTS} WHERE realm_id = ?1 AND id = ?2"), params![realm_id, id], artifact_from)
        .optional()
        .map_err(|error| trouble("read this artifact", error))
}

pub(super) fn artifacts_of_attempt(connection: &Connection, attempt_id: &str) -> Result<Vec<JobArtifact>, String> {
    artifacts_where(connection, "WHERE attempt_id = ?1 ORDER BY recorded_at, rowid", params![attempt_id])
}

pub(super) fn artifacts_of_job(connection: &Connection, job_id: &str) -> Result<Vec<JobArtifact>, String> {
    artifacts_where(connection, "WHERE job_id = ?1 ORDER BY recorded_at, rowid", params![job_id])
}

/// Every artifact whose bytes are still kept, oldest first.
pub(super) fn kept_artifacts(connection: &Connection, realm_id: &str) -> Result<Vec<JobArtifact>, String> {
    artifacts_where(connection, "WHERE realm_id = ?1 AND removed_at IS NULL ORDER BY recorded_at, rowid", params![realm_id])
}

/// How many kept artifacts were recorded at or before `cutoff`.
pub(super) fn kept_before(connection: &Connection, realm_id: &str, cutoff: i64) -> Result<usize, String> {
    count(connection, "SELECT COUNT(*) FROM job_artifacts WHERE realm_id = ?1 AND removed_at IS NULL AND recorded_at <= ?2", params![realm_id, cutoff])
}

/// The bytes the kept artifacts hold on the disk. Two records of the same bytes share one file, so
/// a checksum is counted once.
pub(super) fn kept_bytes(connection: &Connection, realm_id: &str) -> Result<u64, String> {
    connection
        .query_row(
            "SELECT COALESCE(SUM(bytes), 0) FROM (SELECT sha256, MAX(bytes) AS bytes FROM job_artifacts WHERE realm_id = ?1 AND removed_at IS NULL GROUP BY sha256)",
            params![realm_id],
            |row| row.get::<_, i64>(0),
        )
        .map(|bytes| bytes.max(0) as u64)
        .map_err(|error| trouble("count the bytes this grid keeps for its jobs", error))
}

/// Every checksum a kept artifact names, with its size: what a copy of the realm has to carry. Read
/// from whichever database is handed in, which for a copy is the copy itself.
pub(super) fn kept_digests(connection: &Connection) -> Result<Vec<(String, u64)>, String> {
    let mut query = connection
        .prepare("SELECT sha256, MAX(bytes) FROM job_artifacts WHERE removed_at IS NULL GROUP BY sha256 ORDER BY sha256")
        .map_err(|error| trouble("read which job artifacts a copy carries", error))?;
    let rows = query
        .query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?.max(0) as u64)))
        .map_err(|error| trouble("read which job artifacts a copy carries", error))?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(|error| trouble("read which job artifacts a copy carries", error))
}

/// Whether any kept artifact still names these bytes, which decides whether their file may go.
pub(super) fn still_kept(connection: &Connection, realm_id: &str, sha256: &str) -> Result<bool, String> {
    count(connection, "SELECT COUNT(*) FROM job_artifacts WHERE realm_id = ?1 AND sha256 = ?2 AND removed_at IS NULL", params![realm_id, sha256]).map(|found| found > 0)
}

/// Says, once, that an artifact's bytes were removed, when, and why. Answers whether it was still kept.
pub(super) fn mark_removed(connection: &Connection, id: &str, now: i64, reason: &str) -> Result<bool, String> {
    connection
        .execute("UPDATE job_artifacts SET removed_at = ?2, removed_reason = ?3 WHERE id = ?1 AND removed_at IS NULL", params![id, now, reason])
        .map(|changed| changed == 1)
        .map_err(|error| trouble("record that an artifact was removed", error))
}

// ---- Queues ----

fn queue_from(row: &Row<'_>) -> rusqlite::Result<JobQueue> {
    let in_flight: Option<String> = row.get(2)?;
    Ok(JobQueue {
        name: row.get(0)?,
        open: row.get::<_, i64>(1)? != 0,
        in_flight: match in_flight {
            None => None,
            Some(word) => Some(InFlight::from_word(&word).ok_or_else(|| unreadable(2, "a queue's in-flight policy", &word))?),
        },
        reason: row.get(3)?,
        changed_by: row.get(4)?,
        changed_at: row.get(5)?,
    })
}

pub(super) fn queue(connection: &Connection, realm_id: &str, name: &str) -> Result<Option<JobQueue>, String> {
    connection
        .query_row("SELECT name, open, in_flight, reason, changed_by, changed_at FROM job_queues WHERE realm_id = ?1 AND name = ?2", params![realm_id, name], queue_from)
        .optional()
        .map_err(|error| trouble("read this queue", error))
}

pub(super) fn closed_queues(connection: &Connection, realm_id: &str) -> Result<HashSet<String>, String> {
    let mut query = connection.prepare("SELECT name FROM job_queues WHERE realm_id = ?1 AND open = 0").map_err(|error| trouble("read this grid's queues", error))?;
    let rows = query.query_map(params![realm_id], |row| row.get::<_, String>(0)).map_err(|error| trouble("read this grid's queues", error))?;
    rows.collect::<rusqlite::Result<HashSet<_>>>().map_err(|error| trouble("read this grid's queues", error))
}

pub(super) fn queue_count(connection: &Connection, realm_id: &str) -> Result<usize, String> {
    count(connection, "SELECT COUNT(*) FROM job_queues WHERE realm_id = ?1", params![realm_id])
}

// ---- Retention ----

pub(super) fn retention(connection: &Connection, realm_id: &str) -> Result<Option<Retention>, String> {
    connection
        .query_row("SELECT keep_seconds, keep_bytes FROM job_retention WHERE realm_id = ?1", params![realm_id], |row| {
            Ok(Retention { keep_seconds: row.get(0)?, keep_bytes: row.get::<_, i64>(1)?.max(0) as u64 })
        })
        .optional()
        .map_err(|error| trouble("read how long this grid keeps job artifacts", error))
}

pub(super) fn put_retention(connection: &Connection, realm_id: &str, retention: &Retention, by: &str, now: i64) -> Result<(), String> {
    connection
        .execute(
            "INSERT INTO job_retention (realm_id, keep_seconds, keep_bytes, changed_by, changed_at) VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(realm_id) DO UPDATE SET keep_seconds = excluded.keep_seconds, keep_bytes = excluded.keep_bytes,
                 changed_by = excluded.changed_by, changed_at = excluded.changed_at",
            params![realm_id, retention.keep_seconds, retention.keep_bytes as i64, by, now],
        )
        .map(|_| ())
        .map_err(|error| trouble("record how long this grid keeps job artifacts", error))
}

// ---- Queues ----

pub(super) fn put_queue(connection: &Connection, realm_id: &str, queue: &JobQueue) -> Result<(), String> {
    connection
        .execute(
            "INSERT INTO job_queues (realm_id, name, open, in_flight, reason, changed_by, changed_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(realm_id, name) DO UPDATE SET open = excluded.open, in_flight = excluded.in_flight, reason = excluded.reason,
                 changed_by = excluded.changed_by, changed_at = excluded.changed_at",
            params![realm_id, queue.name, queue.open as i64, queue.in_flight.map(InFlight::word), queue.reason, queue.changed_by, queue.changed_at],
        )
        .map(|_| ())
        .map_err(|error| trouble("record whether this queue takes work", error))
}
