//! How large a grid is supported to get, and why each number is where it is.
//!
//! Every number here is a design bound, not a measured one. None of them came from running a
//! realm at that size on real hardware: they are set by parity with the shipped products, by the
//! cost of the one query that has to walk the set, and by which tables nothing ever deletes from.
//! `docs/grid-core/operations.md` says the same thing beside the table, and
//! `core::bench` is the harness that would turn any of them into a measured number.
//!
//! A limit is worth having only if something enforces it. Each constant below names the door that
//! refuses the row after it, or says plainly that nothing refuses and only the reading warns. The
//! refusals are worded the way the rest of the core words a refusal: a sentence with the number
//! in it, so whoever hits one knows what to ask for.

/// People and services in one realm.
///
/// Parity with the shipped Sandbox Grid, which holds 512 (`crate::desks::MAX_PEOPLE`). The desks
/// bridge cannot bring across more people than the hub holds, so a larger number here would be one
/// nothing could reach. Enforced by `Core::add_principal`.
pub const MAX_PEOPLE: usize = 512;

/// Computers enrolled in one realm.
///
/// Two per person is the shape the product assumes: a laptop and a desktop. Enforced by
/// `Core::enrol_device`.
pub const MAX_DEVICES: usize = 2 * MAX_PEOPLE;

/// Computers offering resources at once.
///
/// One host row per computer that offers, which `Store::put_host` already keeps true. This is the
/// number that appears in every per-computer loop in placement, so it is the number the lease
/// benchmark is run at. Enforced by `Core::offer_host`.
pub const MAX_HOSTS: usize = 512;

/// Work in flight at once: everything not in a finished stage.
///
/// This is the set the sweep walks, and after version 10 it walks it through
/// `workloads_by_deadline` rather than through every workload ever submitted. Enforced by
/// `Core::submit`, which is the one door work comes in by.
pub const MAX_UNFINISHED_WORK: usize = 4_096;

/// Credentials one realm holds on people's behalf.
///
/// A company credential hub of this size is realistic, and `UNIQUE (realm_id, name)` means every
/// one of them was deliberately named by somebody. Enforced by `Core::add_credential`.
pub const MAX_CREDENTIALS: usize = 1_024;

/// Grants of a credential to a person.
///
/// Credentials times the people likely to hold any one of them, capped well below credentials
/// times people, which would be 524 288 and is not a shape anybody administers. Enforced by
/// `Core::allow_credential`.
pub const MAX_GRANTS: usize = 16_384;

/// Requests open at once: waiting for an answer, or answered and not yet run out.
///
/// A request lapses after `approval::WAIT`, fifteen minutes, unless the caller asked for longer,
/// so this is a rate as much as a size. Enforced by `Core::ask`.
pub const MAX_OPEN_REQUESTS: usize = 1_024;

/// Standing allowances live at once.
///
/// Each lasts at most `approval::MAX_HOURS`, and upkeep drops the ones that have run out. Nothing
/// refuses the row after this one: an allowance is created by a decision somebody already made,
/// and refusing to record it would lose the decision. The reading warns instead.
pub const MAX_LIVE_ALLOWANCES: usize = 4_096;

/// Events the history is allowed to reach before the realm says something is wrong.
///
/// `audit::KEEP` is 20 000 and `Store::trim` drops events only as far as they have been exported,
/// so a realm nobody ever carries a history out of grows for ever. Nothing refuses an event:
/// refusing to record what happened would mean refusing whatever operation caused it, which turns
/// a tidying problem into an outage. `Core::ready` reports Degraded with a sentence naming the
/// export instead, long before the file is a problem.
pub const WARN_AUDIT_EVENTS: usize = 200_000;

/// Brokered requests the ledger is allowed to reach before the realm says something is wrong.
///
/// `credential_uses` takes one row per brokered request and the database refuses to delete one, so
/// in a credential realm it is the fastest-growing table there is. Nothing refuses a brokered
/// request for the same reason nothing refuses an event. `Core::ready` warns, and because the
/// table is insert-only it warns on how many rows it has ever been given, which is one index
/// descent rather than a count of half a million.
pub const WARN_CREDENTIAL_USES: usize = 500_000;

/// Reservations kept before the realm says something is wrong.
///
/// Reservations are never deleted, only released, because they are the record of what a piece of
/// work has been tried on. One piece of work holds at most `work::TRIES` of them, so the
/// `MAX_UNFINISHED_WORK` in flight at any moment account for 12 288 and everything above that is
/// the work a realm has already finished, which nothing deletes. 200 000 is that count at roughly
/// 50 000 finished pieces of work. The 50 000 is a judgement about how much work one realm runs
/// before somebody should look at the size of the file, not a bound anything enforces.
pub const WARN_LEASES: usize = 200_000;

// Placements per workspace are deliberately not here. A placement number is monotone and never
// reused, so the rows accumulate for the life of a workspace, and noticing that would mean a
// query per workspace in a check that runs every few seconds. It is written down in
// docs/grid-core/operations.md as a thing nothing bounds rather than given a number nothing
// enforces.

// ---- Finite jobs (`core::jobs`) ----
//
// Each of these is enforced at the door named beside it, and each refusal there is a sentence
// with the number in it.

/// Jobs that have not finished, across every queue in a realm: waiting, running, or asked to stop.
///
/// Every one of them may become a running attempt, and every running attempt is a piece of work in
/// flight to the core, so this sits well under `MAX_UNFINISHED_WORK` and leaves room for every
/// other profile. Enforced by `Core::submit_job`.
pub const MAX_QUEUED_JOBS: usize = 1_024;

/// Attempts one job may have, started or not. A retry policy may ask for at most this many, and a
/// person running a job again by hand is held to it too. Enforced by `JobSpec::checked`,
/// `Core::lease_job` and `Core::settle_job`.
pub const MAX_ATTEMPTS_PER_JOB: u32 = 10;

/// The largest single job artifact, in bytes: one gigabyte.
///
/// The coordinator keeps the bytes on its own disk beside the realm, so this bounds what one
/// artifact can ask that disk to hold. Larger outputs belong in a bucket, which is a later step.
/// Enforced by `Core::prepare_job_output` and `Core::prepare_job_checkpoint`, before a byte is sent.
pub const MAX_ARTIFACT_BYTES: u64 = 1 << 30;

/// Artifacts one attempt may send, outputs and checkpoints together. Enforced when an artifact is
/// prepared and again when it is recorded.
pub const MAX_ARTIFACTS_PER_ATTEMPT: usize = 32;

/// Outputs one job may declare: half of what one attempt may send, so an attempt that sends every
/// output still has room to record checkpoints. Enforced by `JobSpec::checked`.
pub const MAX_OUTPUTS: usize = MAX_ARTIFACTS_PER_ATTEMPT / 2;

/// Inputs one job may read. Enforced by `JobSpec::checked`.
pub const MAX_INPUTS: usize = 16;

/// Parts of one job's command: the program and its arguments, or an image's arguments. Enforced by
/// `JobSpec::checked`, as are the two below.
pub const MAX_ARGS: usize = 256;

/// Bytes in one part of a job's command.
pub const MAX_ARG_BYTES: usize = 4_096;

/// Bytes in a job's whole command.
pub const MAX_COMMAND_BYTES: usize = 64 * 1_024;

/// Bytes in one job description as it arrives. Enforced by `JobSpec::from_json`.
pub const MAX_SPEC_BYTES: usize = 256 * 1_024;

/// Job queues whose admission has been set in one realm. A queue nobody has closed has no row, so
/// this only grows when somebody closes a queue they have not closed before. Enforced by
/// `Core::close_job_admission`.
pub const MAX_JOB_QUEUES: usize = 256;

/// The longest one attempt at a job may run: a day, the same ceiling as every other wait in a
/// realm. Enforced by `JobSpec::checked`.
pub const LONGEST_JOB: i64 = super::work::LONGEST_WAIT;

/// The longest a job waits between attempts, however far its backoff has doubled.
pub const MAX_BACKOFF_SECONDS: i64 = 60 * 60;

/// The shortest a computer may hold an attempt between heartbeats.
pub const MIN_LEASE_SECONDS: i64 = 30;

/// The longest a computer may hold an attempt between heartbeats. Short, so a computer that has
/// gone is noticed within minutes rather than at the job's own deadline.
pub const MAX_LEASE_SECONDS: i64 = 15 * 60;

/// How long a staged upload may go without a byte being written before the jobs sweep removes it
/// as abandoned: an hour. An upload that is still arriving keeps its file fresh, so it is never
/// taken from under the computer sending it.
pub const ABANDONED_STAGING_AFTER: i64 = 60 * 60;

/// How long a realm keeps a finished job's artifacts unless its administrator says otherwise:
/// thirty days. Nothing a job that has not finished still needs is ever removed, whatever its age.
pub const KEEP_JOB_ARTIFACTS_FOR: i64 = 30 * 24 * 60 * 60;

/// How many bytes of artifacts a realm keeps unless its administrator says otherwise: twenty
/// gigabytes, oldest removed first. Artifacts a job that has not finished still needs are kept even
/// past this, and the sweep says the realm is over its allowance rather than removing them.
pub const KEEP_JOB_ARTIFACT_BYTES: u64 = 20 << 30;

/// The shortest a realm may be set to keep artifacts: a day, so nobody loses a job's outputs before
/// they could have fetched them. Enforced by `Core::set_job_retention`, as are the three below.
pub const SHORTEST_JOB_ARTIFACT_KEEP: i64 = 24 * 60 * 60;

/// The longest a realm may be set to keep artifacts: a year.
pub const LONGEST_JOB_ARTIFACT_KEEP: i64 = 365 * 24 * 60 * 60;

/// The fewest bytes a realm may be set to keep: room for one artifact of the largest size.
pub const LEAST_JOB_ARTIFACT_BYTES: u64 = MAX_ARTIFACT_BYTES;

/// The most bytes a realm may be set to keep: one terabyte on the coordinator's own disk.
pub const MOST_JOB_ARTIFACT_BYTES: u64 = 1 << 40;

/// Artifacts one pass of the retention sweep removes, so a pass never takes long however much has
/// built up; the next pass carries on.
pub const MAX_ARTIFACTS_REMOVED_PER_PASS: usize = 512;

// The job bounds hang together with each other and with the core's own, and the build stops if a
// change to one of them ever makes that untrue.
const _: () = assert!(MAX_QUEUED_JOBS <= MAX_UNFINISHED_WORK);
const _: () = assert!(MAX_OUTPUTS < MAX_ARTIFACTS_PER_ATTEMPT);
const _: () = assert!(MIN_LEASE_SECONDS < MAX_LEASE_SECONDS && MAX_LEASE_SECONDS < LONGEST_JOB);
const _: () = assert!(SHORTEST_JOB_ARTIFACT_KEEP <= KEEP_JOB_ARTIFACTS_FOR && KEEP_JOB_ARTIFACTS_FOR <= LONGEST_JOB_ARTIFACT_KEEP);
const _: () = assert!(LEAST_JOB_ARTIFACT_BYTES <= KEEP_JOB_ARTIFACT_BYTES && KEEP_JOB_ARTIFACT_BYTES <= MOST_JOB_ARTIFACT_BYTES);
const _: () = assert!(SHORTEST_JOB_ARTIFACT_KEEP >= LONGEST_JOB, "a finished attempt's outputs outlive the longest attempt");

/// How a limit is said to whoever reached it: the sentence names the number, so the answer to
/// "how many may I have" is in the refusal itself.
pub fn reached(what: &str, limit: usize) -> String {
    format!("A grid can have at most {limit} {what}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_published_size_is_either_enforced_here_or_warned_about() {
        // The three the core already had keep their own homes, and these must not contradict them.
        assert_eq!(MAX_PEOPLE, crate::desks::MAX_PEOPLE, "the core and the shipped Sandbox Grid mean the same number by people");
        assert_eq!(super::super::workspace::MAX_WORKSPACES, crate::desks::MAX_DESKS, "and the same number by workspaces");
        assert!(MAX_DEVICES >= MAX_PEOPLE, "a person has at least one computer");
        assert!(MAX_HOSTS <= MAX_DEVICES, "only an enrolled computer can offer");
        // The first term of the sentence beside WARN_LEASES, tied to the constants it names.
        // Nothing can test the second term, the work a realm has already finished, because
        // nothing bounds it; that is why the sentence says so rather than implying a derivation.
        assert!(
            WARN_LEASES >= MAX_UNFINISHED_WORK * super::super::work::TRIES as usize,
            "every piece of work in flight can hold a reservation for every attempt it is allowed"
        );
        assert!(WARN_AUDIT_EVENTS > super::super::audit::KEEP, "the warning is above what the chain keeps once it is exported");
    }

    #[test]
    fn a_limit_says_the_number_in_the_sentence() {
        assert_eq!(reached("people", MAX_PEOPLE), "A grid can have at most 512 people");
    }
}
