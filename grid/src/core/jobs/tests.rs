//! What the jobs foundation must hold true. Where a test stands for a scenario in the plan's grid
//! table (docs/template-platform-implementation-plan.md, 21.5), its name ends with that scenario.
//!
//! Every realm here is a real database in a temporary folder, written through the same doors a
//! hub would use. Nothing here reaches another computer, runs a command or starts a sandbox: the
//! computers are enrolled records, and what they "do" is the calls they would make.
use super::*;
use crate::core::{
    audit::Decision,
    identity::{PrincipalKind, Role},
    limits::{
        ABANDONED_STAGING_AFTER, KEEP_JOB_ARTIFACT_BYTES, LONGEST_JOB, LONGEST_JOB_ARTIFACT_KEEP, MAX_ARGS, MAX_ARG_BYTES, MAX_ARTIFACTS_PER_ATTEMPT, MAX_ARTIFACTS_REMOVED_PER_PASS,
        MAX_ARTIFACT_BYTES, MAX_ATTEMPTS_PER_JOB, MAX_BACKOFF_SECONDS, MAX_COMMAND_BYTES, MAX_INPUTS, MAX_JOB_QUEUES, MAX_LEASE_SECONDS, MAX_OUTPUTS, MAX_QUEUED_JOBS, MAX_SPEC_BYTES,
        MIN_LEASE_SECONDS, MOST_JOB_ARTIFACT_BYTES, SHORTEST_JOB_ARTIFACT_KEEP,
    },
    realm::{Capability, RealmKind},
    work::{Commitment, Kind, Resources, Stage, Workload},
    Core,
};
use sha2::{Digest, Sha256};

const NOW: i64 = 50_000;

fn key() -> String {
    "c".repeat(64)
}

fn small() -> Resources {
    Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 10.0, gpu: false, vram_gb: 0.0 }
}

fn roomy() -> Resources {
    Resources { cpu: 16.0, memory_gb: 64.0, disk_gb: 500.0, gpu: true, vram_gb: 24.0 }
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone)]
struct Worker {
    device: String,
    host: String,
}

/// A company realm with one person who places work, the laptop they send it from, and two
/// computers offering room.
struct Grid {
    core: Core,
    person: String,
    laptop: String,
    first: Worker,
    second: Worker,
    _folder: tempfile::TempDir,
}

fn grid() -> Grid {
    let folder = tempfile::tempdir().unwrap();
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), NOW).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], NOW).unwrap();
    let (laptop, _) = core.enrol_device(&person.id, "Ada's laptop", "linux", NOW).unwrap();
    let first = offer(&mut core, &person.id, "Build PC", roomy());
    let second = offer(&mut core, &person.id, "Spare PC", roomy());
    Grid { core, person: person.id, laptop: laptop.id, first, second, _folder: folder }
}

fn offer(core: &mut Core, person: &str, name: &str, room: Resources) -> Worker {
    let (device, _) = core.enrol_device(person, name, "linux", NOW).unwrap();
    let host = core.offer_host(&device.id, name, room, room, Commitment::Share, NOW).unwrap();
    Worker { device: device.id, host: host.id }
}

/// A repeatable build that needs a little room and may be tried three times, ten seconds apart.
fn build(outputs: &[&str]) -> JobSpec {
    JobSpec {
        entrypoint: Entrypoint::Argv { argv: vec!["make".into(), "release".into()] },
        inputs: Vec::new(),
        outputs: outputs.iter().map(|name| name.to_string()).collect(),
        timeout_seconds: 3_600,
        needs: small(),
        retry: Retry { max_attempts: 3, backoff_seconds: 10 },
        side_effects: SideEffects::Repeatable,
        checkpoints: false,
    }
}

impl Grid {
    fn send(&mut self, spec: JobSpec, now: i64) -> Job {
        self.core.submit_job(&self.person, &self.laptop, "builds", spec, now).unwrap().job
    }

    fn lease(&mut self, worker: &Worker, now: i64) -> JobLease {
        self.core.lease_job(&worker.device, 60, now).unwrap().expect("a job for this computer")
    }

    fn start(&mut self, worker: &Worker, lease: &JobLease, now: i64) {
        self.core.start_job_attempt(&worker.device, &lease.attempt_id, lease.fence, now).unwrap();
    }

    /// Sends one artifact the way a computer does: leave first, the bytes staged without the realm,
    /// then recorded under the attempt's token.
    #[allow(clippy::too_many_arguments)]
    fn send_artifact(&mut self, worker: &Worker, lease: &JobLease, role: ArtifactRole, name: &str, size: u64, declared: &str, bytes: &[u8], now: i64) -> Result<JobArtifact, JobError> {
        let ticket = match role {
            ArtifactRole::Output => self.core.prepare_job_output(&worker.device, &lease.attempt_id, lease.fence, name, size, declared, now)?,
            ArtifactRole::Checkpoint => self.core.prepare_job_checkpoint(&worker.device, &lease.attempt_id, lease.fence, size, declared, now)?,
        };
        let staged = ticket.stage(&mut &bytes[..])?;
        self.core.record_job_artifact(staged, now)
    }

    fn output(&mut self, worker: &Worker, lease: &JobLease, name: &str, bytes: &[u8], now: i64) -> Result<JobArtifact, JobError> {
        self.send_artifact(worker, lease, ArtifactRole::Output, name, bytes.len() as u64, &sha(bytes), bytes, now)
    }

    fn checkpoint(&mut self, worker: &Worker, lease: &JobLease, bytes: &[u8], now: i64) -> Result<JobArtifact, JobError> {
        self.send_artifact(worker, lease, ArtifactRole::Checkpoint, "checkpoint", bytes.len() as u64, &sha(bytes), bytes, now)
    }

    fn finish(&mut self, worker: &Worker, lease: &JobLease, ending: Ending, now: i64) -> Result<JobState, JobError> {
        self.core.complete_job_attempt(&worker.device, &lease.attempt_id, lease.fence, ending, now)
    }

    fn job(&self, id: &str) -> Job {
        self.core.job(id).unwrap().unwrap()
    }

    fn actions(&self) -> Vec<String> {
        self.core.since(0).unwrap().into_iter().map(|event| event.action).collect()
    }

    /// The coordinator stops and starts again on the same file.
    fn restart(self) -> Grid {
        let Grid { core, person, laptop, first, second, _folder } = self;
        let path = core.path().to_owned();
        core.close().unwrap();
        Grid { core: Core::open(&path, &key()).unwrap(), person, laptop, first, second, _folder }
    }
}

// ---- What a job may say ----

#[test]
fn a_command_is_a_list_and_never_a_line_for_a_shell() {
    let with = |argv: &[&str]| JobSpec { entrypoint: Entrypoint::Argv { argv: argv.iter().map(|part| part.to_string()).collect() }, ..build(&[]) }.checked();
    assert!(with(&["make", "release"]).is_ok());
    assert!(with(&["./tools/convert", "--in", "data/raw.csv", "--label", "two words"]).is_ok(), "an argument may hold anything printable; it is never parsed");
    for line in [&["make release && rm -rf /"][..], &["ls;", "-la"], &["$(curl evil)"], &["echo`id`"]] {
        let refused = with(line).unwrap_err();
        assert!(refused.describe().contains("never runs through a shell"), "{line:?}: {refused}");
    }
    for shell in [&["sh", "-c", "make"][..], &["/bin/bash", "build.sh"], &["C:\\Windows\\System32\\cmd.exe", "/c", "dir"], &["pwsh", "-Command", "x"], &["/usr/bin/env", "FOO=1", "bash", "-c", "make"]] {
        let refused = with(shell).unwrap_err();
        assert!(refused.describe().contains("Jobs do not run a shell"), "{shell:?}: {refused}");
    }
    assert_eq!(with(&[]).unwrap_err().code(), "invalid_spec");
    assert!(with(&["make", "one\ntwo"]).unwrap_err().describe().contains("one line"));
    // A command line is somewhere a secret must never be, and the common shapes of one are refused.
    for leaky in [&["deploy", "--token=abc123"][..], &["curl", "-H", "Authorization: Bearer abc"], &["upload", "sk-0123456789"], &["login", "--key=ghp_abcdef"]] {
        assert!(with(leaky).unwrap_err().describe().contains("no secret values"), "{leaky:?}");
    }
    // What only looks long and random is not refused for that alone.
    assert!(with(&["deploy", "--commit", "0123456789abcdef0123456789abcdef01234567"]).is_ok(), "a commit name is not a secret");
    assert!(with(&["train", "--out", "/work/training_checkpoints_resnet50_version_two"]).is_ok(), "nor is a long file name");

    let image = |reference: &str| JobSpec { entrypoint: Entrypoint::Image { reference: reference.into(), args: vec!["--fast".into()] }, ..build(&[]) }.checked();
    assert!(image("registry.example/team/tool:1.2").is_ok());
    assert!(image(&format!("registry.example/team/tool@sha256:{}", "a".repeat(64))).is_ok());
    for refused in ["tool; rm -rf /", "registry.example/tool@sha256:short", "../escape:1", "-flag", ""] {
        assert_eq!(image(refused).unwrap_err().code(), "invalid_spec", "{refused:?}");
    }
}

#[test]
fn inputs_outputs_and_queues_are_named_never_placed() {
    for place in ["../escape", "/etc/passwd", "C:\\Windows\\win.ini", "C:report", "reports/q3", ".hidden", "a..b", "~root", "..", "dir\\file"] {
        let refused = JobSpec { outputs: vec![place.into()], ..build(&[]) }.checked().unwrap_err();
        assert_eq!(refused.code(), "path_like_name", "{place}: {refused}");
        assert!(refused.describe().contains("looks like a place on a computer"));
    }
    for unfit in ["", "two words", "ümlaut", "-first", "x".repeat(65).as_str()] {
        assert_eq!(JobSpec { outputs: vec![unfit.to_owned()], ..build(&[]) }.checked().unwrap_err().code(), "invalid_spec", "{unfit:?}");
    }
    assert!(JobSpec { outputs: vec!["result.tar.gz".into(), "model-v2_final".into(), "A1".into()], ..build(&[]) }.checked().is_ok());
    assert!(JobSpec { outputs: vec!["same".into(), "same".into()], ..build(&[]) }.checked().unwrap_err().describe().contains("Two outputs"));
    let input = |name: &str, artifact_id: &str| JobSpec { inputs: vec![InputRef { name: name.into(), artifact_id: artifact_id.into() }], ..build(&[]) }.checked();
    assert_eq!(input("../table", "artifact-0123456789abcdef").unwrap_err().code(), "path_like_name");
    assert_eq!(input("table", "/srv/data/table.csv").unwrap_err().code(), "invalid_spec", "an input names an artifact, never a file");

    let mut grid = grid();
    for place in ["../queue", "C:\\queue", "a/b"] {
        assert_eq!(grid.core.submit_job(&grid.person, &grid.laptop, place, build(&[]), NOW).unwrap_err().code(), "path_like_name");
    }
    assert!(grid.core.jobs().unwrap().is_empty(), "nothing was admitted on the way to refusing");
}

// ---- Leases, heartbeats and fencing ----

#[test]
fn a_computer_that_goes_quiet_loses_its_attempt_and_the_job_waits_again_g05() {
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());
    let job = grid.send(build(&["result"]), NOW);
    let lease = grid.lease(&first, NOW + 1);
    assert_eq!((lease.number, lease.fence, lease.expires_at, lease.deadline), (1, 1, NOW + 61, NOW + 1 + 3_600));
    grid.start(&first, &lease, NOW + 2);
    // The attempt's room is in the realm's own ledger, where every other profile sees it.
    assert_eq!(grid.core.free_on(&first.host, NOW + 3).unwrap().memory_gb, roomy().memory_gb - small().memory_gb);
    // A heartbeat keeps it, for as long as was asked within the bounds.
    let beat = grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 30).unwrap();
    assert_eq!((beat.expires_at, beat.stop_requested), (NOW + 90, false));
    assert_eq!(grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 1, NOW + 31).unwrap().expires_at, NOW + 31 + MIN_LEASE_SECONDS);
    assert_eq!(grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 86_400, NOW + 32).unwrap().expires_at, NOW + 32 + MAX_LEASE_SECONDS);
    let renewed = grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 40).unwrap();
    // Then nothing. Until the reservation runs out the attempt stands; after, the sweep ends it.
    assert_eq!(grid.core.expire_jobs(renewed.expires_at - 1), 0);
    assert_eq!(grid.core.expire_jobs(renewed.expires_at), 1);
    let waiting = grid.job(&job.id);
    assert_eq!(waiting.state, JobState::Queued);
    assert_eq!(waiting.current_attempt, None, "the attempt that ended no longer passes for current");
    assert_eq!(waiting.not_before, renewed.expires_at + 10, "it waits out its backoff");
    let attempts = grid.core.job_attempts(&job.id).unwrap();
    assert_eq!(attempts[0].state, AttemptState::Lost);
    assert!(attempts[0].ending.contains("stopped answering"), "{}", attempts[0].ending);
    // The room went back, and the core's own record of the attempt ended with it.
    assert_eq!(grid.core.free_on(&first.host, renewed.expires_at).unwrap().memory_gb, roomy().memory_gb);
    let work = grid.core.snapshot().unwrap().workloads.into_iter().find(|work| work.id == attempts[0].workload_id).unwrap();
    assert_eq!(work.stage, Stage::Failed);
    assert_eq!(work.note, Some(format!("job:{}", job.id)));
    // Nothing is handed out before the backoff has passed, and the job says why it waits.
    assert!(grid.core.lease_job(&second.device, 60, renewed.expires_at + 5).unwrap().is_none());
    assert_eq!(grid.core.why_job_waits(&job.id, renewed.expires_at + 5).unwrap().unwrap(), "It waits 5 more seconds before it is tried again");
    // After it, the next attempt carries the next token.
    let next = grid.lease(&second, renewed.expires_at + 10);
    assert_eq!((next.number, next.fence), (2, 2));
    assert_ne!(next.attempt_id, lease.attempt_id);
    assert!(grid.actions().iter().any(|action| action == "job.queued again"));
}

#[test]
fn the_cores_own_sweep_getting_there_first_loses_nothing_g05() {
    let mut grid = grid();
    let first = grid.first.clone();
    let job = grid.send(build(&[]), NOW);
    let lease = grid.lease(&first, NOW);
    grid.start(&first, &lease, NOW);
    assert!(grid.core.expire(NOW + 61) >= 1, "the core ends the lapsed reservation itself");
    assert_eq!(grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 62).unwrap_err(), JobError::LeaseLost);
    assert_eq!(grid.core.expire_jobs(NOW + 62), 1);
    assert_eq!(grid.job(&job.id).state, JobState::Queued);
    assert!(grid.core.job_attempts(&job.id).unwrap()[0].ending.contains("took its reservation back"));
    // Cancelling the core work that held an attempt is the realm taking its room back too.
    let lease = grid.lease(&first, NOW + 100);
    let attempt = grid.core.job_attempts(&job.id).unwrap().pop().unwrap();
    grid.core.cancel_work("owner", &attempt.workload_id, NOW + 101).unwrap();
    assert_eq!(grid.core.start_job_attempt(&first.device, &lease.attempt_id, lease.fence, NOW + 102).unwrap_err(), JobError::LeaseLost);
    assert_eq!(grid.core.expire_jobs(NOW + 102), 1);
    assert_eq!(grid.job(&job.id).state, JobState::Queued, "an attempt that never started is placed again");
}

#[test]
fn a_job_that_can_resume_is_handed_its_newest_checkpoint_g05() {
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());
    grid.send(JobSpec { checkpoints: true, ..build(&[]) }, NOW);
    let lease = grid.lease(&first, NOW);
    assert!(lease.resume_from.is_none());
    grid.start(&first, &lease, NOW);
    for (step, bytes) in [b"epoch 1".as_slice(), b"epoch 2".as_slice()].into_iter().enumerate() {
        grid.checkpoint(&first, &lease, bytes, NOW + 1 + step as i64).unwrap();
    }
    grid.core.expire_jobs(NOW + 61);
    let next = grid.lease(&second, NOW + 71);
    let resume = next.resume_from.clone().expect("the newest checkpoint");
    assert_eq!(resume.sha256, sha(b"epoch 2"));
    let mut read = Vec::new();
    grid.core.read_job_input(&second.device, &next.attempt_id, next.fence, &resume.artifact_id, &mut read, NOW + 72).unwrap();
    assert_eq!(read, b"epoch 2");
    // A job that did not say it can resume records no checkpoint.
    grid.send(build(&[]), NOW + 80);
    let plain = grid.lease(&first, NOW + 80);
    grid.start(&first, &plain, NOW + 80);
    assert_eq!(grid.checkpoint(&first, &plain, b"x", NOW + 81).unwrap_err(), JobError::NoCheckpoints);
}

#[test]
fn a_computer_left_behind_cannot_overwrite_the_attempt_that_replaced_it_g06() {
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());
    let job = grid.send(build(&["result"]), NOW);
    let old = grid.lease(&first, NOW);
    grid.start(&first, &old, NOW);
    grid.core.expire_jobs(NOW + 61);
    let new = grid.lease(&second, NOW + 71);
    grid.start(&second, &new, NOW + 72);
    // The old computer wakes up and tries everything it might.
    assert_eq!(grid.output(&first, &old, "result", b"stale", NOW + 73).unwrap_err(), JobError::StaleFence);
    assert_eq!(grid.finish(&first, &old, Ending::Succeeded, NOW + 73).unwrap_err(), JobError::StaleFence);
    assert_eq!(grid.finish(&first, &old, Ending::Failed(Failure::Crashed), NOW + 73).unwrap_err(), JobError::StaleFence);
    assert_eq!(grid.core.heartbeat_job(&first.device, &old.attempt_id, old.fence, 60, NOW + 73).unwrap_err(), JobError::StaleFence);
    assert_eq!(grid.core.start_job_attempt(&first.device, &old.attempt_id, old.fence, NOW + 73).unwrap_err(), JobError::StaleFence);
    // Even naming the new attempt gets it nowhere: its token is the old one, and it is not that computer.
    assert_eq!(grid.core.complete_job_attempt(&first.device, &new.attempt_id, old.fence, Ending::Succeeded, NOW + 73).unwrap_err(), JobError::StaleFence);
    assert_eq!(grid.core.complete_job_attempt(&first.device, &new.attempt_id, new.fence, Ending::Succeeded, NOW + 73).unwrap_err(), JobError::WrongComputer);
    // A token above the current one was never issued, and is refused the same way.
    assert_eq!(grid.core.heartbeat_job(&second.device, &new.attempt_id, new.fence + 1, 60, NOW + 73).unwrap_err(), JobError::StaleFence);
    assert!(grid.core.job_artifacts(&job.id).unwrap().is_empty(), "nothing the old attempt sent was recorded");
    // The same comparison is made again by the statements that write, so even a write that got past
    // the doors records nothing for the attempt that was replaced and moves nothing under its token.
    let forged = JobArtifact {
        id: "artifact-00000000000000ff".into(),
        job_id: job.id.clone(),
        attempt_id: old.attempt_id.clone(),
        fence: old.fence,
        role: ArtifactRole::Output,
        name: "result".into(),
        bytes: 5,
        sha256: sha(b"stale"),
        recorded_at: NOW + 73,
        removed_at: None,
        removed_reason: String::new(),
    };
    assert!(!rows::insert_artifact(grid.core.store.connection(), &grid.core.realm.id, &forged).unwrap());
    let mut overwritten = grid.job(&job.id);
    overwritten.state = JobState::Succeeded;
    assert!(!rows::move_job(grid.core.store.connection(), &overwritten, JobState::Running, old.fence).unwrap());
    assert!(grid.core.job_artifacts(&job.id).unwrap().is_empty());
    assert_eq!(grid.job(&job.id).state, JobState::Running);
    // The current attempt finishes, and its outputs are the job's.
    let sent = grid.output(&second, &new, "result", b"fresh", NOW + 74).unwrap();
    assert_eq!((sent.attempt_id.as_str(), sent.fence), (new.attempt_id.as_str(), 2));
    assert_eq!(grid.finish(&second, &new, Ending::Succeeded, NOW + 75).unwrap(), JobState::Succeeded);
    let outputs = grid.core.job_outputs(&job.id).unwrap();
    assert_eq!(outputs.iter().map(|output| output.sha256.clone()).collect::<Vec<_>>(), vec![sha(b"fresh")]);
    // And once the job has finished, the old computer is refused rather than reviving it.
    assert_eq!(grid.finish(&first, &old, Ending::Failed(Failure::Crashed), NOW + 76).unwrap_err(), JobError::StaleFence);
    assert_eq!(grid.job(&job.id).state, JobState::Succeeded);
}

#[test]
fn the_same_computer_given_a_job_again_cannot_act_on_its_earlier_attempt_g06() {
    let mut grid = grid();
    let first = grid.first.clone();
    let job = grid.send(build(&["result"]), NOW);
    let old = grid.lease(&first, NOW);
    grid.start(&first, &old, NOW);
    grid.core.expire_jobs(NOW + 61);
    let new = grid.lease(&first, NOW + 71);
    assert_eq!((new.job_id.as_str(), new.fence), (job.id.as_str(), 2));
    // A message from the first attempt arrives late, from the very computer that now holds the second.
    assert_eq!(grid.output(&first, &old, "result", b"late", NOW + 72).unwrap_err(), JobError::StaleFence);
    assert_eq!(grid.core.start_job_attempt(&first.device, &old.attempt_id, old.fence, NOW + 72).unwrap_err(), JobError::StaleFence);
    grid.start(&first, &new, NOW + 72);
    assert_eq!(grid.core.job_attempts(&job.id).unwrap()[1].state, AttemptState::Running);
}

// ---- Computers and room ----

#[test]
fn a_computer_being_emptied_gets_no_new_attempts_and_finishes_what_it_has_g10() {
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());
    grid.send(build(&[]), NOW);
    let lease = grid.lease(&first, NOW);
    grid.start(&first, &lease, NOW);
    let waiting = grid.send(build(&[]), NOW + 1);
    grid.core.drain_host("owner", &first.host, NOW + 2).unwrap();
    let refused = grid.core.lease_job(&first.device, 60, NOW + 3).unwrap_err();
    assert_eq!(refused, JobError::Draining);
    assert!(refused.describe().contains("what it is running may finish"));
    // What it already runs carries on to its end.
    grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 4).unwrap();
    assert_eq!(grid.finish(&first, &lease, Ending::Succeeded, NOW + 5).unwrap(), JobState::Succeeded);
    // The waiting job goes to a computer that is still taking work.
    assert_eq!(grid.lease(&second, NOW + 6).job_id, waiting.id);
    // Brought back, it takes work again.
    grid.core.bring_host_back("owner", &first.host, NOW + 7).unwrap();
    let third = grid.send(build(&[]), NOW + 8);
    assert_eq!(grid.lease(&first, NOW + 9).job_id, third.id);
    // A computer whose person lends it only while it is idle takes nothing while they use it.
    let desk = offer(&mut grid.core, &grid.person, "Desk PC", roomy());
    let person = grid.person.clone();
    grid.core.commit_host(&person, &desk.host, Commitment::Share, roomy(), true, NOW + 10).unwrap();
    grid.core.report_condition(&desk.device, false, 200.0, true, false, NOW + 10).unwrap();
    grid.send(build(&[]), NOW + 11);
    let refused = grid.core.lease_job(&desk.device, 60, NOW + 11).unwrap_err();
    assert_eq!(refused.code(), "host_refused");
    assert!(refused.describe().contains("using it"), "{refused}");
    // A computer that is not offering anything is not a worker at all.
    assert_eq!(grid.core.lease_job(&grid.laptop, 60, NOW + 12).unwrap_err(), JobError::NotAWorker);
}

#[test]
fn a_job_and_other_work_share_one_ledger_on_a_computer_g04() {
    let folder = tempfile::tempdir().unwrap();
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Models], &key(), NOW).unwrap();
    let realm = core.realm().id.clone();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Operator], NOW).unwrap();
    let (laptop, _) = core.enrol_device(&person.id, "Ada's laptop", "linux", NOW).unwrap();
    let card = Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 100.0, gpu: true, vram_gb: 24.0 };
    let only = offer(&mut core, &person.id, "GPU PC", card);
    let on_the_card = Resources { cpu: 1.0, memory_gb: 4.0, disk_gb: 1.0, gpu: true, vram_gb: 8.0 };
    // A piece of model work holds the card, which nobody has said can be shared.
    let model = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person.id, &laptop.id, on_the_card, 1, NOW), NOW).unwrap();
    core.grant_lease(&model.id, 600, NOW).unwrap();
    // A job that needs the card waits for it.
    let send = |core: &mut Core, needs: Resources, now: i64| core.submit_job(&person.id, &laptop.id, "train", JobSpec { needs, ..build(&[]) }, now).unwrap().job;
    let training = send(&mut core, Resources { cpu: 2.0, memory_gb: 8.0, disk_gb: 10.0, gpu: true, vram_gb: 8.0 }, NOW);
    assert!(core.lease_job(&only.device, 60, NOW + 1).unwrap().is_none());
    // A job that needs only processors and memory fits beside it, and memory is counted across both.
    let sums = send(&mut core, small(), NOW + 1);
    assert_eq!(core.lease_job(&only.device, 60, NOW + 2).unwrap().unwrap().job_id, sums.id);
    assert_eq!(core.free_on(&only.host, NOW + 3).unwrap().memory_gb, 32.0 - 4.0 - small().memory_gb);
    // One too large for what is left waits, and one too large for the computer at all is told so.
    let large = send(&mut core, Resources { memory_gb: 30.0, ..small() }, NOW + 3);
    assert!(core.lease_job(&only.device, 60, NOW + 4).unwrap().is_none());
    assert_eq!(core.why_job_waits(&large.id, NOW + 4).unwrap().unwrap(), "Waiting for a computer with room");
    let huge = send(&mut core, Resources { memory_gb: 100.0, ..small() }, NOW + 4);
    assert!(core.why_job_waits(&huge.id, NOW + 4).unwrap().unwrap().starts_with("No computer in this grid offers enough for it"));
    // The other way round: once the model work is done and a job holds the card, other work
    // asking for it is refused by the core's own placement, reading the same ledger.
    core.cancel_work("owner", &model.id, NOW + 5).unwrap();
    assert_eq!(core.lease_job(&only.device, 60, NOW + 6).unwrap().unwrap().job_id, training.id);
    let other = core.submit(Workload::new(&realm, Capability::Models, Kind::Inference, &person.id, &laptop.id, on_the_card, 1, NOW + 7), NOW + 7).unwrap();
    assert!(core.grant_lease(&other.id, 600, NOW + 7).unwrap_err().contains("No computer in this grid has room"));
}

// ---- Effects outside the grid ----

#[test]
fn work_that_cannot_be_repeated_is_never_run_again_by_itself_g12() {
    let mut grid = grid();
    let first = grid.first.clone();
    let charge = JobSpec { side_effects: SideEffects::ManualReconcile, retry: Retry { max_attempts: 3, backoff_seconds: 0 }, ..build(&[]) };
    let job = grid.send(charge, NOW);
    // An attempt that was handed out and never started did nothing, so it is placed again.
    grid.lease(&first, NOW);
    grid.core.expire_jobs(NOW + 61);
    assert_eq!(grid.job(&job.id).state, JobState::Queued);
    // One that started and then went quiet may have charged somebody. It is not run again.
    let started = grid.lease(&first, NOW + 62);
    assert_eq!(started.fence, 2);
    grid.start(&first, &started, NOW + 62);
    grid.core.expire_jobs(NOW + 123);
    let unknown = grid.job(&job.id);
    assert_eq!(unknown.state, JobState::OutcomeUnknown);
    assert!(unknown.note.contains("cannot be repeated safely"), "{}", unknown.note);
    assert!(grid.core.lease_job(&first.device, 60, NOW + 124).unwrap().is_none(), "nothing hands it out again");
    assert_eq!(grid.core.cancel_job(&grid.person, &job.id, NOW + 124).unwrap_err(), JobError::AwaitingSettlement);
    // A person checks, and decides it should run again. The decision is theirs, and recorded.
    assert_eq!(grid.core.settle_job(&grid.person, &job.id, Settled::RunAgain, NOW + 125).unwrap(), JobState::Queued);
    assert!(grid.job(&job.id).note.contains("decided it should"));
    let again = grid.lease(&first, NOW + 126);
    assert_eq!(again.fence, 3);
    // A failure it reports is not tried again either.
    grid.start(&first, &again, NOW + 126);
    assert_eq!(grid.finish(&first, &again, Ending::Failed(Failure::Exited), NOW + 127).unwrap(), JobState::Failed);
    assert!(grid.core.lease_job(&first.device, 60, NOW + 128).unwrap().is_none());
    assert_eq!(grid.core.settle_job(&grid.person, &job.id, Settled::RunAgain, NOW + 129).unwrap_err(), JobError::NotUnknown);
    // A job that says nothing about its effects is treated the careful way.
    let quiet = JobSpec::from_json(r#"{"entrypoint":{"kind":"argv","argv":["charge"]},"timeoutSeconds":60}"#).unwrap();
    assert_eq!(quiet.side_effects, SideEffects::ManualReconcile);
}

#[test]
fn a_deduplication_key_finds_the_job_already_sent_and_allows_a_safe_retry_g12() {
    let mut grid = grid();
    let first = grid.first.clone();
    let invoice = JobSpec { side_effects: SideEffects::DedupKey { key: "invoice-2026-10-0042".into() }, retry: Retry { max_attempts: 2, backoff_seconds: 0 }, ..build(&[]) };
    let sent = grid.core.submit_job(&grid.person, &grid.laptop, "billing", invoice.clone(), NOW).unwrap();
    assert!(!sent.replayed);
    let again = grid.core.submit_job(&grid.person, &grid.laptop, "billing", invoice.clone(), NOW + 1).unwrap();
    assert!(again.replayed);
    assert_eq!(again.job.id, sent.job.id);
    assert_eq!(grid.core.jobs().unwrap().len(), 1, "sending it twice made one job");
    let different = JobSpec { timeout_seconds: 60, ..invoice.clone() };
    assert_eq!(grid.core.submit_job(&grid.person, &grid.laptop, "billing", different, NOW + 2).unwrap_err(), JobError::DuplicateKey);
    // The key travels with every attempt, so the system it changes can recognise a repeat...
    let lease = grid.lease(&first, NOW + 3);
    assert_eq!(lease.dedup_key.as_deref(), Some("invoice-2026-10-0042"));
    grid.start(&first, &lease, NOW + 3);
    // ...which is what makes trying again after a lost attempt safe to do without a person.
    grid.core.expire_jobs(NOW + 64);
    assert_eq!(grid.job(&sent.job.id).state, JobState::Queued);
    let retry = grid.lease(&first, NOW + 65);
    assert_eq!(retry.dedup_key, lease.dedup_key);
    grid.start(&first, &retry, NOW + 65);
    // Its last allowed attempt going quiet leaves the outcome unknown, never failed: a timeout is
    // not proof of anything.
    grid.core.expire_jobs(NOW + 126);
    assert_eq!(grid.job(&sent.job.id).state, JobState::OutcomeUnknown);
    // Sending it again after all that still finds the same job rather than making a second one.
    assert!(grid.core.submit_job(&grid.person, &grid.laptop, "billing", invoice, NOW + 127).unwrap().replayed);
    assert_eq!(grid.core.jobs().unwrap().len(), 1);
    // A key that reads like a secret is refused, because every computer that runs the job sees it.
    let leaky = JobSpec { side_effects: SideEffects::DedupKey { key: "token=abc".into() }, ..build(&[]) };
    assert!(leaky.checked().unwrap_err().describe().contains("looks like a secret"));
    let uuid = JobSpec { side_effects: SideEffects::DedupKey { key: "550e8400-e29b-41d4-a716-446655440000".into() }, ..build(&[]) };
    assert!(uuid.checked().is_ok(), "a generated identifier is a fine key");
}

#[test]
fn what_follows_an_attempt_depends_on_what_the_job_does_outside() {
    let job = |side_effects: SideEffects, attempts: u32, state: JobState| Job {
        id: "job-0".into(),
        realm_id: "realm-0".into(),
        queue: "builds".into(),
        principal_id: "principal-0".into(),
        device_id: "device-0".into(),
        spec: JobSpec { side_effects, retry: Retry { max_attempts: 3, backoff_seconds: 0 }, ..build(&[]) },
        state,
        attempts,
        fence: u64::from(attempts),
        current_attempt: Some("attempt-0".into()),
        checkpoint: None,
        not_before: 0,
        note: String::new(),
        created_at: 0,
        updated_at: 0,
        finished_at: None,
    };
    let key = || SideEffects::DedupKey { key: "k-1".into() };
    let running = JobState::Running;
    let cases = [
        (job(SideEffects::Repeatable, 1, running), true, Ended::Lost, JobState::Queued),
        (job(SideEffects::Repeatable, 3, running), true, Ended::Lost, JobState::OutcomeUnknown),
        (job(SideEffects::Repeatable, 3, running), true, Ended::Reported(Failure::Exited), JobState::Failed),
        (job(key(), 1, running), true, Ended::TimedOut, JobState::Queued),
        (job(key(), 3, running), true, Ended::TimedOut, JobState::OutcomeUnknown),
        (job(SideEffects::ManualReconcile, 1, running), true, Ended::Lost, JobState::OutcomeUnknown),
        (job(SideEffects::ManualReconcile, 1, running), true, Ended::TimedOut, JobState::OutcomeUnknown),
        (job(SideEffects::ManualReconcile, 1, running), true, Ended::Reported(Failure::Crashed), JobState::Failed),
        (job(SideEffects::ManualReconcile, 1, running), false, Ended::Lost, JobState::Queued),
        (job(SideEffects::ManualReconcile, 3, running), false, Ended::Lost, JobState::Failed),
        (job(SideEffects::Repeatable, 1, JobState::CancelRequested), true, Ended::Lost, JobState::OutcomeUnknown),
        (job(SideEffects::Repeatable, 1, JobState::CancelRequested), true, Ended::Reported(Failure::Interrupted), JobState::Stopped),
    ];
    for (job, started, ended, wanted) in cases {
        let (state, _, note) = next_after(&job, started, ended, NOW);
        assert_eq!(state, wanted, "{:?} started={started} {ended:?}: {note}", job.spec.side_effects);
        assert!(!note.is_empty());
    }
}

#[test]
fn the_wait_between_attempts_doubles_and_stops_at_its_ceiling() {
    let retry = Retry { max_attempts: 10, backoff_seconds: 30 };
    assert_eq!([1, 2, 3, 4].map(|attempts| backoff(&retry, attempts)), [30, 60, 120, 240]);
    assert_eq!(backoff(&retry, 10), MAX_BACKOFF_SECONDS);
    assert_eq!(backoff(&Retry { max_attempts: 3, backoff_seconds: 0 }, 3), 0);
    assert_eq!(backoff(&Retry { max_attempts: 10, backoff_seconds: MAX_BACKOFF_SECONDS }, 40), MAX_BACKOFF_SECONDS, "however many attempts, nothing overflows");
}

// ---- Cancelling ----

#[test]
fn cancel_requested_stopped_and_outcome_unknown_are_kept_apart() {
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());
    // Waiting: cancelled at once.
    let waiting = grid.send(build(&[]), NOW);
    assert_eq!(grid.core.cancel_job(&grid.person, &waiting.id, NOW + 1).unwrap(), JobState::Cancelled);
    assert_eq!(grid.core.cancel_job(&grid.person, &waiting.id, NOW + 2).unwrap_err(), JobError::Finished);
    // Given to a computer that has not started it: cancelled at once, its room goes back, and the
    // computer's start is refused.
    let handed = grid.send(build(&[]), NOW + 3);
    let lease = grid.lease(&first, NOW + 3);
    assert_eq!(lease.job_id, handed.id);
    assert_eq!(grid.core.cancel_job(&grid.person, &handed.id, NOW + 4).unwrap(), JobState::Cancelled);
    assert_eq!(grid.core.start_job_attempt(&first.device, &lease.attempt_id, lease.fence, NOW + 5).unwrap_err(), JobError::LeaseLost);
    assert_eq!(grid.core.free_on(&first.host, NOW + 5).unwrap().memory_gb, roomy().memory_gb);
    // Running: asked to stop, told so on its next heartbeat, and stopped once it says it has.
    let running = grid.send(build(&[]), NOW + 6);
    let lease = grid.lease(&first, NOW + 6);
    grid.start(&first, &lease, NOW + 6);
    assert_eq!(grid.finish(&first, &lease, Ending::Stopped, NOW + 7).unwrap_err(), JobError::NothingAskedToStop);
    assert_eq!(grid.core.cancel_job(&grid.person, &running.id, NOW + 7).unwrap(), JobState::CancelRequested);
    assert_eq!(grid.core.cancel_job(&grid.person, &running.id, NOW + 8).unwrap(), JobState::CancelRequested, "asking twice is asking once");
    assert!(grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 9).unwrap().stop_requested);
    assert_eq!(grid.finish(&first, &lease, Ending::Stopped, NOW + 10).unwrap(), JobState::Stopped);
    // Running, asked to stop, and its computer goes quiet before saying so: nobody knows what it did.
    let quiet = grid.send(build(&[]), NOW + 11);
    let lease = grid.lease(&second, NOW + 11);
    grid.start(&second, &lease, NOW + 11);
    grid.core.cancel_job(&grid.person, &quiet.id, NOW + 12).unwrap();
    grid.core.expire_jobs(NOW + 72);
    let unknown = grid.job(&quiet.id);
    assert_eq!(unknown.state, JobState::OutcomeUnknown);
    assert!(unknown.note.contains("asked to stop"), "{}", unknown.note);
    // Each is recorded as what it is.
    let actions = grid.actions();
    for action in ["job.cancelled", "job.cancel requested", "job.stopped", "job.outcome unknown"] {
        assert!(actions.iter().any(|said| said == action), "{action} is in the history");
    }
    // Somebody who did not send a job and may not place work cannot cancel it.
    let auditor = grid.core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::Auditor], NOW).unwrap();
    let another = grid.send(build(&[]), NOW + 80);
    assert_eq!(grid.core.cancel_job(&auditor.id, &another.id, NOW + 81).unwrap_err().code(), "not_allowed");
}

// ---- Artifacts ----

#[test]
fn artifacts_are_checked_bounded_and_tied_to_the_attempt_that_sent_them() {
    let mut grid = grid();
    let first = grid.first.clone();
    let job = grid.send(build(&["report", "data.csv"]), NOW);
    let lease = grid.lease(&first, NOW);
    assert_eq!(grid.output(&first, &lease, "report", b"early", NOW).unwrap_err(), JobError::NotStarted);
    grid.start(&first, &lease, NOW);
    // Bytes that do not match the declared checksum, or are not as many as declared: refused, and
    // nothing kept or recorded.
    let report = ArtifactRole::Output;
    assert_eq!(grid.send_artifact(&first, &lease, report, "report", 5, &sha(b"other"), b"hello", NOW + 1).unwrap_err(), JobError::ChecksumMismatch);
    assert_eq!(grid.send_artifact(&first, &lease, report, "report", 10, &sha(b"hello"), b"hello", NOW + 1).unwrap_err(), JobError::SizeMismatch { declared: 10, arrived: Some(5) });
    assert_eq!(grid.send_artifact(&first, &lease, report, "report", 3, &sha(b"hel"), b"hello", NOW + 1).unwrap_err(), JobError::SizeMismatch { declared: 3, arrived: None });
    assert_eq!(grid.send_artifact(&first, &lease, report, "report", 1, "not a checksum", b"x", NOW + 1).unwrap_err().code(), "invalid_spec");
    assert!(grid.core.job_artifacts(&job.id).unwrap().is_empty());
    let shelf = grid.core.job_shelf();
    let left: Vec<_> = std::fs::read_dir(shelf.folder().join("staging")).map(|entries| entries.filter_map(Result::ok).collect()).unwrap_or_default();
    assert!(left.is_empty(), "no partial copy is left behind");
    assert!(!shelf.folder().join(sha(b"hello")).exists() && !shelf.folder().join(sha(b"hel")).exists(), "and nothing was kept");
    // A name that is a place, or one the job never declared.
    assert_eq!(grid.output(&first, &lease, "../report", b"x", NOW + 2).unwrap_err().code(), "path_like_name");
    assert_eq!(grid.output(&first, &lease, "C:\\report", b"x", NOW + 2).unwrap_err().code(), "path_like_name");
    assert_eq!(grid.output(&first, &lease, "passwords", b"x", NOW + 2).unwrap_err(), JobError::UndeclaredOutput("passwords".into()));
    // Success needs every declared output, from this attempt.
    let report = grid.output(&first, &lease, "report", b"all good", NOW + 3).unwrap();
    assert_eq!((report.attempt_id.as_str(), report.fence, report.bytes, report.sha256.as_str()), (lease.attempt_id.as_str(), 1, 8, sha(b"all good").as_str()));
    assert_eq!(grid.finish(&first, &lease, Ending::Succeeded, NOW + 4).unwrap_err(), JobError::OutputsMissing(vec!["data.csv".into()]));
    // The same output sent again, as a computer does when it never heard the answer, finds what
    // was recorded; different bytes under the same name never replace it.
    assert_eq!(grid.output(&first, &lease, "report", b"all good", NOW + 5).unwrap(), report);
    assert_eq!(grid.output(&first, &lease, "report", b"changed", NOW + 5).unwrap_err(), JobError::OutputAlreadySent("report".into()));
    let table = grid.output(&first, &lease, "data.csv", b"a,b\n1,2\n", NOW + 6).unwrap();
    assert_eq!(grid.finish(&first, &lease, Ending::Succeeded, NOW + 7).unwrap(), JobState::Succeeded);
    assert_eq!(grid.core.job_outputs(&job.id).unwrap().len(), 2);
    // The bytes are kept under their checksum and read back whole; a copy damaged on this disk is
    // reported as damaged, not handed on.
    let mut read = Vec::new();
    assert_eq!(grid.core.read_job_artifact(&grid.person, &report.id, &mut read).unwrap(), 8);
    assert_eq!(read, b"all good");
    std::fs::write(shelf.folder().join(&report.sha256), b"all bad!").unwrap();
    assert_eq!(grid.core.read_job_artifact(&grid.person, &report.id, &mut Vec::new()).unwrap_err(), JobError::Damaged);
    // A later job reads this one's output as an input, and its attempt reads that and nothing else.
    let reader = grid.send(JobSpec { inputs: vec![InputRef { name: "table".into(), artifact_id: table.id.clone() }], ..build(&[]) }, NOW + 8);
    let next = grid.lease(&first, NOW + 9);
    assert_eq!((next.job_id.as_str(), next.inputs[0].sha256.as_str()), (reader.id.as_str(), sha(b"a,b\n1,2\n").as_str()));
    let mut fetched = Vec::new();
    grid.core.read_job_input(&first.device, &next.attempt_id, next.fence, &table.id, &mut fetched, NOW + 10).unwrap();
    assert_eq!(fetched, b"a,b\n1,2\n");
    assert_eq!(grid.core.read_job_input(&first.device, &next.attempt_id, next.fence, &report.id, &mut Vec::new(), NOW + 10).unwrap_err().code(), "not_allowed");
    // An artifact from a job that has not finished is not an input anybody can name.
    grid.start(&first, &next, NOW + 10);
    let second = grid.second.clone();
    let unfinished = grid.send(build(&["partial"]), NOW + 11);
    let half = grid.lease(&second, NOW + 11);
    assert_eq!(half.job_id, unfinished.id);
    grid.start(&second, &half, NOW + 11);
    let partial = grid.output(&second, &half, "partial", b"half", NOW + 12).unwrap();
    let premature = JobSpec { inputs: vec![InputRef { name: "half".into(), artifact_id: partial.id }], ..build(&[]) };
    assert_eq!(grid.core.submit_job(&grid.person, &grid.laptop, "builds", premature, NOW + 13).unwrap_err(), JobError::InputNotReady);
}

// ---- Persistence ----

#[test]
fn the_queue_survives_a_restart_with_no_attempt_lost_or_issued_twice() {
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());
    let running = grid.send(build(&["result"]), NOW);
    let waiting = grid.send(build(&[]), NOW + 1);
    let lease = grid.lease(&first, NOW + 2);
    assert_eq!(lease.job_id, running.id);
    grid.start(&first, &lease, NOW + 3);
    let kept = grid.output(&first, &lease, "result", b"half way", NOW + 4).unwrap();
    grid.core.close_job_admission("owner", "nightly", InFlight::Finish, "budget spent", NOW + 5).unwrap();
    let before = grid.core.jobs().unwrap();
    let attempts_before = grid.core.job_attempts(&running.id).unwrap();

    let mut grid = grid.restart();
    assert_eq!(grid.core.jobs().unwrap(), before, "every job is as it was");
    assert_eq!(grid.core.job_attempts(&running.id).unwrap(), attempts_before, "and every attempt");
    assert_eq!(grid.core.job_artifacts(&running.id).unwrap(), vec![kept.clone()], "and every artifact");
    assert!(!grid.core.job_queue("nightly").unwrap().open, "and every queue");
    // The computer that held the attempt carries on under the same token, and what it sent is
    // still on this disk and still whole.
    grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 30).unwrap();
    let mut read = Vec::new();
    grid.core.read_job_artifact(&grid.person, &kept.id, &mut read).unwrap();
    assert_eq!(read, b"half way");
    // It goes quiet. When the coordinator next looks, the job waits again and its next attempt has
    // the next token: none lost, none issued twice.
    assert_eq!(grid.core.expire_jobs(NOW + 200), 1);
    let next = grid.lease(&second, NOW + 210);
    assert_eq!((next.job_id.as_str(), next.number, next.fence), (running.id.as_str(), 2, 2));
    let attempts = grid.core.job_attempts(&running.id).unwrap();
    assert_eq!(attempts.iter().map(|attempt| attempt.fence).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(attempts.iter().filter(|attempt| attempt.state.live()).count(), 1, "exactly one attempt holds a computer");
    // Two computers asking get two different jobs, never the same one twice.
    assert_eq!(grid.lease(&first, NOW + 211).job_id, waiting.id);
    assert!(grid.core.lease_job(&first.device, 60, NOW + 212).unwrap().is_none());
    // Restarting again in the middle of all that changes none of it.
    let before = grid.core.jobs().unwrap();
    let grid = grid.restart();
    assert_eq!(grid.core.jobs().unwrap(), before);
}

#[test]
fn a_realm_that_never_had_a_job_is_only_read() {
    let mut grid = grid();
    let first = grid.first.clone();
    assert!(grid.core.jobs().unwrap().is_empty());
    assert_eq!(grid.core.job("job-0123").unwrap(), None);
    assert!(grid.core.job_queue("builds").unwrap().open);
    // A computer asking for work, or somebody reopening a queue nobody closed, writes nothing either.
    assert!(grid.core.lease_job(&first.device, 60, NOW).unwrap().is_none());
    assert!(grid.core.reopen_job_admission("owner", "builds", NOW).unwrap().open);
    assert_eq!(grid.core.expire_jobs(NOW), 0);
    assert_eq!(rows::version(grid.core.store.connection()).unwrap(), 0, "no tables were made");
    let path = grid.core.path().to_owned();
    assert!(!shelf::Shelf::beside(&path).folder().exists(), "and no folder");
}

// ---- Bounds ----

#[test]
fn every_bound_is_enforced_and_named() {
    // A retry policy asking for more attempts than the bound is refused...
    let refused = JobSpec { retry: Retry { max_attempts: MAX_ATTEMPTS_PER_JOB + 1, backoff_seconds: 0 }, ..build(&[]) }.checked().unwrap_err();
    assert_eq!(refused.describe(), format!("A job can have at most {MAX_ATTEMPTS_PER_JOB} attempts"));
    // ...and so is one with more outputs, inputs or parts of a command than a job may have.
    let outputs = (0..=MAX_OUTPUTS).map(|n| format!("out{n}")).collect();
    assert_eq!(JobSpec { outputs, ..build(&[]) }.checked().unwrap_err().describe(), format!("A job can declare at most {MAX_OUTPUTS} outputs"));
    let inputs = (0..=MAX_INPUTS).map(|n| InputRef { name: format!("in{n}"), artifact_id: format!("artifact-{n:016x}") }).collect();
    assert_eq!(JobSpec { inputs, ..build(&[]) }.checked().unwrap_err().describe(), format!("A job can read at most {MAX_INPUTS} inputs"));
    let command = |argv: Vec<String>| JobSpec { entrypoint: Entrypoint::Argv { argv }, ..build(&[]) }.checked().unwrap_err().describe();
    assert_eq!(command(std::iter::once("make".to_owned()).chain((0..MAX_ARGS).map(|n| format!("arg{n}"))).collect()), format!("A job's command can have at most {MAX_ARGS} parts"));
    assert_eq!(command(vec!["make".into(), "x".repeat(MAX_ARG_BYTES + 1)]), format!("Each part of a job's command can be at most {MAX_ARG_BYTES} bytes"));
    let whole = MAX_COMMAND_BYTES / MAX_ARG_BYTES + 1;
    assert_eq!(command(std::iter::once("make".to_owned()).chain((0..whole).map(|_| "y".repeat(MAX_ARG_BYTES))).collect()), format!("A job's whole command can be at most {MAX_COMMAND_BYTES} bytes"));
    assert_eq!(JobSpec::from_json(&" ".repeat(MAX_SPEC_BYTES + 1)).unwrap_err().describe(), format!("A job description can be at most {MAX_SPEC_BYTES} bytes"));
    assert!(JobSpec { timeout_seconds: LONGEST_JOB + 1, ..build(&[]) }.checked().is_err());

    let mut grid = grid();
    let first = grid.first.clone();
    // At run time a job is given no more attempts than its policy allows.
    let flaky = grid.send(JobSpec { retry: Retry { max_attempts: 2, backoff_seconds: 0 }, ..build(&[]) }, NOW);
    for round in 0..2_i64 {
        let lease = grid.lease(&first, NOW + round * 100);
        grid.start(&first, &lease, NOW + round * 100);
        grid.core.expire_jobs(NOW + round * 100 + 61);
    }
    assert_eq!(grid.job(&flaky.id).state, JobState::OutcomeUnknown);
    assert_eq!(grid.core.job_attempts(&flaky.id).unwrap().len(), 2);
    assert!(grid.core.lease_job(&first.device, 60, NOW + 300).unwrap().is_none());
    // An artifact larger than the bound is refused before a byte of it is read.
    let big = grid.send(JobSpec { outputs: vec!["image".into()], checkpoints: true, ..build(&[]) }, NOW + 400);
    let lease = grid.lease(&first, NOW + 400);
    grid.start(&first, &lease, NOW + 400);
    let too_big = grid.core.prepare_job_output(&first.device, &lease.attempt_id, lease.fence, "image", MAX_ARTIFACT_BYTES + 1, &sha(b""), NOW + 401).unwrap_err();
    assert_eq!(too_big.describe(), format!("An artifact can be at most {MAX_ARTIFACT_BYTES} bytes, which is one gigabyte"));
    // One attempt sends at most so many artifacts, checkpoints included.
    for n in 0..MAX_ARTIFACTS_PER_ATTEMPT {
        grid.checkpoint(&first, &lease, format!("checkpoint {n}").as_bytes(), NOW + 402).unwrap();
    }
    let over = grid.output(&first, &lease, "image", b"x", NOW + 403).unwrap_err();
    assert_eq!(over.describe(), format!("One attempt can send at most {MAX_ARTIFACTS_PER_ATTEMPT} artifacts"));
    // A realm holds at most so many jobs that have not finished. The rows are written in one change,
    // because a thousand admissions one fsync at a time would test nothing more.
    {
        let connection = grid.core.store.connection();
        let change = connection.unchecked_transaction().unwrap();
        let already = rows::unfinished_jobs(&change, &grid.core.realm.id).unwrap();
        for n in already..MAX_QUEUED_JOBS {
            let mut filler = big.clone();
            filler.id = format!("job-{n:016x}");
            rows::insert_job(&change, &filler).unwrap();
        }
        change.commit().unwrap();
    }
    let full = grid.core.submit_job(&grid.person, &grid.laptop, "builds", build(&[]), NOW + 500).unwrap_err();
    assert_eq!(full.describe(), format!("A grid can have at most {MAX_QUEUED_JOBS} jobs that have not finished"));
    // And at most so many queues whose admission somebody has set.
    {
        let connection = grid.core.store.connection();
        let change = connection.unchecked_transaction().unwrap();
        for n in 0..MAX_JOB_QUEUES {
            let queue = JobQueue { name: format!("queue{n}"), open: true, in_flight: None, reason: String::new(), changed_by: "owner".into(), changed_at: NOW };
            rows::put_queue(&change, &grid.core.realm.id, &queue).unwrap();
        }
        change.commit().unwrap();
    }
    let queues = grid.core.close_job_admission("owner", "one-too-many", InFlight::Finish, "", NOW + 600).unwrap_err();
    assert_eq!(queues.describe(), format!("A grid can have at most {MAX_JOB_QUEUES} job queues whose admission has been set"));
    assert!(grid.core.close_job_admission("owner", "queue7", InFlight::Finish, "", NOW + 600).is_ok(), "a queue already counted can still be closed");
    // How the bounds relate to each other and to the core's own is checked when the crate is built,
    // beside the bounds themselves.
}

// ---- Budget ----

#[test]
fn a_closed_queue_admits_nothing_new_and_says_what_happens_to_running_work_g20() {
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());
    grid.send(build(&[]), NOW);
    let lease = grid.lease(&first, NOW);
    grid.start(&first, &lease, NOW);
    let waiting = grid.send(build(&[]), NOW + 1);
    let closed = grid.core.close_job_admission("owner", "builds", InFlight::Finish, "October's budget is spent", NOW + 2).unwrap();
    assert_eq!((closed.open, closed.in_flight), (false, Some(InFlight::Finish)));
    // Nothing new comes in, and the refusal says why.
    let refused = grid.core.submit_job(&grid.person, &grid.laptop, "builds", build(&[]), NOW + 3).unwrap_err();
    assert_eq!(refused.describe(), "The queue 'builds' is not taking new jobs just now: October's budget is spent");
    // Nothing waiting is started, retries included, and the waiting job says why.
    assert!(grid.core.lease_job(&second.device, 60, NOW + 4).unwrap().is_none());
    assert!(grid.core.why_job_waits(&waiting.id, NOW + 4).unwrap().unwrap().contains("October's budget is spent"));
    // What was running carries on, and what it sends is kept.
    grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 5).unwrap();
    assert_eq!(grid.finish(&first, &lease, Ending::Succeeded, NOW + 6).unwrap(), JobState::Succeeded);
    // Another queue is not affected.
    let other = grid.core.submit_job(&grid.person, &grid.laptop, "reports", build(&[]), NOW + 7).unwrap().job;
    assert_eq!(grid.lease(&second, NOW + 8).job_id, other.id);
    // Reopened, the waiting job is given a computer.
    grid.core.reopen_job_admission("owner", "builds", NOW + 9).unwrap();
    let lease = grid.lease(&first, NOW + 10);
    assert_eq!(lease.job_id, waiting.id);
    grid.start(&first, &lease, NOW + 10);
    // Closing with Stop asks running jobs to stop and kills nothing: the computer still renews,
    // hears that it should stop, and says when it has.
    grid.core.close_job_admission("owner", "builds", InFlight::Stop, "", NOW + 11).unwrap();
    assert_eq!(grid.job(&waiting.id).state, JobState::CancelRequested);
    let beat = grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 12).unwrap();
    assert!(beat.stop_requested);
    assert_eq!(grid.finish(&first, &lease, Ending::Stopped, NOW + 13).unwrap(), JobState::Stopped);
    // The record keeps what was decided, in the words it was decided in.
    let history = grid.core.since(0).unwrap();
    assert!(history.iter().any(|event| event.action == "jobs.admission closed" && event.reason.contains("finish: October's budget is spent")));
    assert!(history.iter().any(|event| event.action == "jobs.admission reopened"));
    // Closing a queue is for somebody who may place work.
    let auditor = grid.core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::Auditor], NOW).unwrap();
    assert_eq!(grid.core.close_job_admission(&auditor.id, "builds", InFlight::Finish, "", NOW + 14).unwrap_err().code(), "not_allowed");
}

// ---- The trust boundary ----

#[test]
fn a_research_grid_runs_no_generic_job_and_a_job_carries_no_research_step() {
    let folder = tempfile::tempdir().unwrap();
    let mut study = Core::create(&folder.path().join("study.db"), "Study", RealmKind::Research, &[Capability::Research], &key(), NOW).unwrap();
    let researcher = study.add_principal("owner", PrincipalKind::Person, "Rae", &[Role::Researcher, Role::RealmAdmin], NOW).unwrap();
    let (laptop, _) = study.enrol_device(&researcher.id, "Rae's laptop", "linux", NOW).unwrap();
    let refused = study.submit_job(&researcher.id, &laptop.id, "builds", build(&[]), NOW).unwrap_err();
    assert_eq!(refused, JobError::ResearchRealm);
    assert!(refused.describe().starts_with("Generic jobs do not run in a research grid"));
    assert!(study.since(0).unwrap().iter().any(|event| event.action == "job.refused" && event.decision == Decision::Refused), "the attempt is in the research grid's own history");
    // No other door opens either.
    let lab = offer(&mut study, &researcher.id, "Lab PC", roomy());
    assert_eq!(study.lease_job(&lab.device, 60, NOW).unwrap_err(), JobError::ResearchRealm);
    assert_eq!(study.close_job_admission("owner", "builds", InFlight::Finish, "", NOW).unwrap_err(), JobError::ResearchRealm);
    assert!(study.jobs().unwrap().is_empty());
    // And the database says the same to anything that writes to it directly.
    rows::ensure(study.store.connection()).unwrap();
    let smuggled = Job {
        id: "job-00000000000000aa".into(),
        realm_id: study.realm().id.clone(),
        queue: "builds".into(),
        principal_id: researcher.id.clone(),
        device_id: laptop.id.clone(),
        spec: build(&[]),
        state: JobState::Queued,
        attempts: 0,
        fence: 0,
        current_attempt: None,
        checkpoint: None,
        not_before: NOW,
        note: String::new(),
        created_at: NOW,
        updated_at: NOW,
        finished_at: None,
    };
    let written = rows::insert_job(study.store.connection(), &smuggled).unwrap_err();
    assert!(written.contains("a research grid does not run generic jobs"), "{written}");

    // In a company grid, a job description cannot carry a research step, at any depth...
    for carrying in [
        r#"{"entrypoint":{"kind":"argv","argv":["scan"]},"timeoutSeconds":60,"scope":"scope-1"}"#,
        r#"{"entrypoint":{"kind":"research","argv":["scan"]},"timeoutSeconds":60}"#,
        r#"{"entrypoint":{"kind":"argv","argv":["scan"]},"timeoutSeconds":60,"retry":{"maxAttempts":1,"activity":"execute"}}"#,
        r#"{"entrypoint":{"kind":"argv","argv":["scan"]},"timeoutSeconds":60,"Admission":{"id":"a"}}"#,
    ] {
        let refused = JobSpec::from_json(carrying).unwrap_err();
        assert_eq!(refused.code(), "research_action", "{carrying}");
        assert!(refused.describe().contains("cannot carry research work"));
    }
    // ...nor anything else that is not part of a job, which is refused by name rather than dropped.
    let stranger = JobSpec::from_json(r#"{"entrypoint":{"kind":"argv","argv":["x"]},"timeoutSeconds":60,"privileged":true}"#).unwrap_err();
    assert_eq!(stranger.describe(), "'privileged' is not part of a job");
    // A description that is part of a job reads back as exactly that job.
    let written = serde_json::to_string(&build(&["result"])).unwrap();
    assert_eq!(JobSpec::from_json(&written).unwrap(), build(&["result"]));
    // And a researcher's role does not place generic work, even in a company grid.
    let mut grid = grid();
    let rae = grid.core.add_principal("owner", PrincipalKind::Person, "Rae", &[Role::Researcher], NOW).unwrap();
    let (rae_laptop, _) = grid.core.enrol_device(&rae.id, "Rae's laptop", "linux", NOW).unwrap();
    let refused = grid.core.submit_job(&rae.id, &rae_laptop.id, "builds", build(&[]), NOW).unwrap_err();
    assert_eq!(refused, JobError::NotAllowed("Rae may not place work here".into()));
    // An attempt is never recorded as research: its core work is neither research's capability nor
    // its kind, and its note names a job rather than a scope.
    let job = grid.send(build(&[]), NOW);
    let first = grid.first.clone();
    grid.lease(&first, NOW);
    let attempt = grid.core.job_attempts(&job.id).unwrap().remove(0);
    let work = grid.core.snapshot().unwrap().workloads.into_iter().find(|work| work.id == attempt.workload_id).unwrap();
    assert_ne!(work.capability, Capability::Research);
    assert_ne!(work.kind, Kind::Research);
    assert!(work.note.unwrap().starts_with("job:"));
    // A grid that only brokers credentials runs nothing on its computers, and says so.
    let access = Core::create(&folder.path().join("access.db"), "Keys", RealmKind::Primary, &[Capability::Credentials], &key(), NOW).unwrap();
    assert_eq!(access.job_capability().unwrap_err(), JobError::NoComputers);
}

// ---- Staged uploads ----

fn staged_files(shelf: &shelf::Shelf) -> Vec<String> {
    std::fs::read_dir(shelf.folder().join("staging")).map(|entries| entries.flatten().map(|entry| entry.file_name().to_string_lossy().to_string()).collect()).unwrap_or_default()
}

fn at(seconds: i64) -> std::time::SystemTime {
    std::time::UNIX_EPOCH + std::time::Duration::from_secs(seconds as u64)
}

fn touch(path: &std::path::Path, seconds: i64) {
    std::fs::File::options().write(true).open(path).unwrap().set_modified(at(seconds)).unwrap();
}

#[test]
fn an_upload_is_staged_without_the_realm_and_recorded_under_its_token() {
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());
    let job = grid.send(build(&["result", "log"]), NOW);
    let lease = grid.lease(&first, NOW);
    grid.start(&first, &lease, NOW);
    let shelf = grid.core.job_shelf();
    let made = b"what the build made".to_vec();
    // Leave first, with everything that can be refused without the bytes refused there.
    let ticket = grid.core.prepare_job_output(&first.device, &lease.attempt_id, lease.fence, "result", made.len() as u64, &sha(&made), NOW + 1).unwrap();
    assert_eq!((ticket.attempt_id(), ticket.name(), ticket.bytes(), ticket.sha256()), (lease.attempt_id.as_str(), "result", made.len() as u64, sha(&made).as_str()));
    // The bytes are staged with nothing but the ticket, and the realm goes on answering while they
    // arrive: nothing about an upload holds it.
    let staged = ticket.stage(&mut &made[..]).unwrap();
    assert_eq!(staged_files(&shelf).len(), 1);
    grid.core.heartbeat_job(&first.device, &lease.attempt_id, lease.fence, 60, NOW + 2).unwrap();
    assert!(grid.core.job_artifacts(&job.id).unwrap().is_empty(), "staged is not recorded");
    // Then the realm is taken briefly to record them, under the attempt's token.
    let recorded = grid.core.record_job_artifact(staged, NOW + 3).unwrap();
    assert_eq!((recorded.attempt_id.as_str(), recorded.fence, recorded.sha256.as_str()), (lease.attempt_id.as_str(), 1, sha(&made).as_str()));
    assert!(shelf.folder().join(&recorded.sha256).exists());
    assert!(staged_files(&shelf).is_empty(), "nothing is left staged");
    // Bytes staged and then dropped without being recorded leave nothing behind.
    let log = b"the build's log".to_vec();
    let dropped = grid.core.prepare_job_output(&first.device, &lease.attempt_id, lease.fence, "log", log.len() as u64, &sha(&log), NOW + 4).unwrap().stage(&mut &log[..]).unwrap();
    drop(dropped);
    assert!(staged_files(&shelf).is_empty());
    assert!(!shelf.folder().join(sha(&log)).exists());
    // Bytes staged for an attempt that is replaced before they are recorded are refused when they
    // come to be recorded, and nothing of them is kept: not the staged file, not a kept copy, not a
    // record.
    let late = grid.core.prepare_job_output(&first.device, &lease.attempt_id, lease.fence, "log", log.len() as u64, &sha(&log), NOW + 5).unwrap().stage(&mut &log[..]).unwrap();
    grid.core.expire_jobs(NOW + 63);
    let replacement = grid.lease(&second, NOW + 73);
    assert_eq!(replacement.fence, 2);
    assert_eq!(grid.core.record_job_artifact(late, NOW + 74).unwrap_err(), JobError::StaleFence);
    assert!(staged_files(&shelf).is_empty(), "the stale upload's staged bytes are gone");
    assert!(!shelf.folder().join(sha(&log)).exists(), "and were never kept");
    assert_eq!(grid.core.job_artifacts(&job.id).unwrap(), vec![recorded.clone()], "and nothing new was recorded");
    // The same output staged twice is recorded once.
    grid.start(&second, &replacement, NOW + 75);
    let twice = |grid: &mut Grid| {
        let ticket = grid.core.prepare_job_output(&second.device, &replacement.attempt_id, replacement.fence, "result", made.len() as u64, &sha(&made), NOW + 76).unwrap();
        let staged = ticket.stage(&mut &made[..]).unwrap();
        grid.core.record_job_artifact(staged, NOW + 76).unwrap()
    };
    let once = twice(&mut grid);
    assert_eq!(twice(&mut grid), once);
    assert!(staged_files(&shelf).is_empty());
    // Bytes that do not match what was declared never get as far as staging.
    let refused = grid.core.prepare_job_output(&second.device, &replacement.attempt_id, replacement.fence, "log", 4, &sha(b"four"), NOW + 77).unwrap().stage(&mut &b"five!"[..]).unwrap_err();
    assert_eq!(refused, JobError::SizeMismatch { declared: 4, arrived: None });
    assert!(staged_files(&shelf).is_empty());
}

#[test]
fn an_upload_nobody_finished_is_swept_and_one_still_arriving_is_not() {
    let mut grid = grid();
    let shelf = grid.core.job_shelf();
    let staging = shelf.folder().join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    let abandoned = staging.join(format!("{}.0000aaaa.partial", sha(b"gone")));
    let arriving = staging.join(format!("{}.0000bbbb.partial", sha(b"still coming")));
    let unrelated = staging.join("notes.txt");
    for path in [&abandoned, &arriving, &unrelated] {
        std::fs::write(path, b"bytes").unwrap();
    }
    touch(&abandoned, NOW - ABANDONED_STAGING_AFTER - 1);
    touch(&arriving, NOW - 60);
    touch(&unrelated, NOW - 10 * ABANDONED_STAGING_AFTER);
    // The sweep the timer runs anyway.
    grid.core.expire_jobs(NOW);
    assert!(!abandoned.exists(), "nothing was written to it for longer than an upload is given");
    assert!(arriving.exists(), "an upload still arriving keeps its file fresh, and is left alone");
    assert!(unrelated.exists(), "only staged uploads are swept");
    // Once it too has gone quiet for long enough, it goes the same way.
    touch(&arriving, NOW - ABANDONED_STAGING_AFTER - 5);
    assert_eq!(grid.core.tidy_job_artifacts(NOW).unwrap().abandoned_uploads, 1);
    assert!(!arriving.exists());
}

// ---- Copies and backups ----

#[test]
fn a_copy_of_the_realm_carries_its_artifacts_and_checks_every_one() {
    let mut grid = grid();
    let first = grid.first.clone();
    let job = grid.send(build(&["report", "table"]), NOW);
    let lease = grid.lease(&first, NOW);
    grid.start(&first, &lease, NOW);
    let report = grid.output(&first, &lease, "report", b"quarterly numbers", NOW + 1).unwrap();
    let table = grid.output(&first, &lease, "table", b"a,b\n1,2\n", NOW + 1).unwrap();
    grid.finish(&first, &lease, Ending::Succeeded, NOW + 2).unwrap();
    let copies = grid._folder.path().join("copies");

    // The hourly copy carries the artifacts beside it, and the copy reads them back whole.
    let hourly = copies.join("hourly.db");
    grid.core.copy_to(&hourly).unwrap();
    let carried = artifact_folder(&hourly);
    assert!(carried.join(&report.sha256).exists() && carried.join(&table.sha256).exists());
    assert!(!carried.join("staging").exists(), "a finished copy keeps no staging folder");
    let copy = Core::open(&hourly, &key()).unwrap();
    let mut read = Vec::new();
    copy.read_job_artifact(&grid.person, &report.id, &mut read).unwrap();
    assert_eq!(read, b"quarterly numbers");
    assert_eq!(copy.job_outputs(&job.id).unwrap().len(), 2);
    copy.close().unwrap();
    // A second copy to the same place is refused, folder and all.
    assert!(grid.core.copy_to(&hourly).unwrap_err().contains("already a file"));
    std::fs::remove_file(&hourly).unwrap();
    assert!(grid.core.copy_to(&hourly).unwrap_err().contains("job artifacts would go"));

    // An artifact damaged on this disk cannot be carried exactly, so there is no copy at all, rather
    // than a copy whose records name bytes it does not have.
    let shelf = grid.core.job_shelf();
    std::fs::write(shelf.folder().join(&report.sha256), b"quarterly numbres").unwrap();
    let broken = copies.join("broken.db");
    let refused = grid.core.copy_to(&broken).unwrap_err();
    assert!(refused.contains(&report.sha256) && refused.contains("no longer matches its checksum"), "{refused}");
    assert!(!broken.exists() && !artifact_folder(&broken).exists(), "nothing is left looking like a copy");
    // And one missing from it, likewise.
    std::fs::remove_file(shelf.folder().join(&report.sha256)).unwrap();
    let refused = grid.core.copy_to(&broken).unwrap_err();
    assert!(refused.contains("its bytes are not beside it"), "{refused}");
    assert!(!broken.exists() && !artifact_folder(&broken).exists());

    // The copy taken without opening the realm carries the same way, and says what travelled.
    std::fs::write(shelf.folder().join(&report.sha256), b"quarterly numbers").unwrap();
    let taken = copies.join("taken.db");
    let travelled = crate::core::store::Store::copy_of(grid.core.path(), &taken).unwrap();
    let mut expected = vec![(report.sha256.clone(), report.bytes), (table.sha256.clone(), table.bytes)];
    expected.sort();
    assert_eq!(travelled.artifacts, expected);
    assert_eq!(travelled.bytes(), report.bytes + table.bytes);
    assert!(artifact_folder(&taken).join(&table.sha256).exists());

    // A realm that has never had a job is copied exactly as it always was: no folder beside it.
    let plain = self::grid();
    let alone = copies.join("plain.db");
    plain.core.copy_to(&alone).unwrap();
    assert!(alone.exists() && !artifact_folder(&alone).exists());
    assert_eq!(crate::core::store::Store::copy_of(plain.core.path(), &copies.join("plain-taken.db")).unwrap(), Carried::default());
}

#[test]
fn the_rollout_backup_carries_a_realms_artifacts_and_puts_them_back() {
    use crate::core::compat::{backup, frozen::Product, Sources};
    let mut grid = grid();
    let first = grid.first.clone();
    let job = grid.send(build(&["report"]), NOW);
    let lease = grid.lease(&first, NOW);
    grid.start(&first, &lease, NOW);
    let report = grid.output(&first, &lease, "report", b"quarterly numbers", NOW + 1).unwrap();
    grid.finish(&first, &lease, Ending::Succeeded, NOW + 2).unwrap();
    let sources = Sources { neo_hub: None, desks_hub: None, bounty_host: None, access_hub: None, realms: vec![grid.core.path().to_owned()] };
    let stamp = grid._folder.path().join("backup");
    let manifest = backup::take(&sources, &stamp, "1.1.2", "rehearsal", backup::KEEP_DAYS, NOW).unwrap();
    let artifact = manifest.files.iter().find(|file| file.shape.as_deref() == Some("a job artifact")).expect("the artifact is in the manifest");
    assert_eq!((artifact.path.as_str(), artifact.sha256.as_str(), artifact.bytes), (format!("core/realm.job-artifacts/{}", report.sha256).as_str(), report.sha256.as_str(), report.bytes));
    backup::verify(&stamp).unwrap();
    // Put back somewhere else, the realm comes with its artifacts, and they read back whole.
    let back = grid._folder.path().join("restored").join("realm.db");
    backup::restore(&stamp, Product::Core, &back).unwrap();
    let restored = Core::open(&back, &key()).unwrap();
    let mut read = Vec::new();
    restored.read_job_artifact(&grid.person, &report.id, &mut read).unwrap();
    assert_eq!(read, b"quarterly numbers");
    assert_eq!(restored.job(&job.id).unwrap().unwrap().state, JobState::Succeeded);
    restored.close().unwrap();
    // An artifact changed in the backup fails the check, and the realm is never put back without it.
    std::fs::write(stamp.join(&artifact.path), b"quarterly numbres").unwrap();
    assert!(backup::verify(&stamp).unwrap_err().contains("is not the file that was backed up"));
    let elsewhere = grid._folder.path().join("elsewhere").join("realm.db");
    assert!(backup::restore(&stamp, Product::Core, &elsewhere).is_err());
    assert!(!elsewhere.exists() && !artifact_folder(&elsewhere).exists());
}

#[test]
fn the_portable_backup_says_plainly_that_it_leaves_jobs_out() {
    // A realm that has never had a job writes the backup it always wrote.
    let plain = grid();
    let backup = plain.core.backup(NOW).unwrap();
    assert!(backup.left_out.is_empty());
    assert!(!serde_json::to_string(&backup).unwrap().contains("leftOut"));
    // One that holds jobs says what the backup does not carry.
    let mut grid = grid();
    let first = grid.first.clone();
    grid.send(build(&["report"]), NOW);
    let lease = grid.lease(&first, NOW);
    grid.start(&first, &lease, NOW);
    grid.output(&first, &lease, "report", b"quarterly numbers", NOW + 1).unwrap();
    grid.finish(&first, &lease, Ending::Succeeded, NOW + 2).unwrap();
    let backup = grid.core.backup(NOW + 3).unwrap();
    assert_eq!(backup.left_out.len(), 1);
    let said = &backup.left_out[0];
    assert!(said.starts_with("Jobs.") && said.contains("1 jobs and 1 kept job artifacts") && said.contains("does not carry jobs"), "{said}");
    assert!(said.contains("copy_to"), "and says what does carry them");
    // The statement travels in the file, and a restore drill reads it out with everything else a
    // restore does not bring back.
    let written = serde_json::to_string(&backup).unwrap();
    let read: crate::core::store::Backup = serde_json::from_str(&written).unwrap();
    let drill = Core::rehearse_restore(&grid._folder.path().join("drills"), read, &key(), NOW + 4).unwrap();
    assert_eq!(drill.not_restored.len(), 4);
    assert!(drill.not_restored.iter().any(|line| line.starts_with("Jobs.")));
    // And what the drill restored has no jobs, exactly as it said.
    let restored = Core::open(&drill.kept_at, &key()).unwrap();
    assert!(restored.jobs().unwrap().is_empty());
}

// ---- Retention ----

/// Writes an artifact's row directly, for the tests that need sizes or numbers no test should write
/// to a disk. Its bytes are not on the shelf, which the sweep treats as already gone.
fn record_raw(connection: &rusqlite::Connection, realm_id: &str, job_id: &str, attempt_id: &str, sha256: &str, bytes: u64, at: i64) {
    connection
        .execute(
            "INSERT INTO job_artifacts (id, realm_id, job_id, attempt_id, fence, role, name, bytes, sha256, recorded_at)
             VALUES (?1, ?2, ?3, ?4, 1, 'checkpoint', 'checkpoint', ?5, ?6, ?7)",
            rusqlite::params![format!("artifact-{}", &crate::token()[..16]), realm_id, job_id, attempt_id, bytes as i64, sha256, at],
        )
        .unwrap();
}

#[test]
fn retention_removes_only_what_no_job_still_needs() {
    let day = 24 * 60 * 60;
    let mut grid = grid();
    let (first, second) = (grid.first.clone(), grid.second.clone());

    // The policy has bounds, each named when it is crossed, and is for somebody who may place work.
    assert_eq!(grid.core.job_retention().unwrap(), Retention::default());
    for (retention, said) in [
        (Retention { keep_seconds: 60, ..Retention::default() }, "at least 24 hours"),
        (Retention { keep_seconds: LONGEST_JOB_ARTIFACT_KEEP + 1, ..Retention::default() }, "at most 365 days"),
        (Retention { keep_bytes: 1, ..Retention::default() }, "room for one of the largest"),
        (Retention { keep_bytes: MOST_JOB_ARTIFACT_BYTES + 1, ..Retention::default() }, &format!("at most {MOST_JOB_ARTIFACT_BYTES} bytes")),
    ] {
        let refused = grid.core.set_job_retention("owner", retention, NOW).unwrap_err();
        assert_eq!(refused.code(), "limit_reached");
        assert!(refused.describe().contains(said), "{refused}");
    }
    let auditor = grid.core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::Auditor], NOW).unwrap();
    assert_eq!(grid.core.set_job_retention(&auditor.id, Retention::default(), NOW).unwrap_err().code(), "not_allowed");

    // A finished job whose outputs nothing needs, one of them the same bytes a later job makes.
    let a = grid.send(build(&["a", "shared"]), NOW);
    let lease = grid.lease(&first, NOW);
    grid.start(&first, &lease, NOW);
    let alpha = grid.output(&first, &lease, "a", b"alpha", NOW + 1).unwrap();
    let shared = grid.output(&first, &lease, "shared", b"same bytes", NOW + 1).unwrap();
    grid.finish(&first, &lease, Ending::Succeeded, NOW + 2).unwrap();
    // A finished job whose output a job that is still waiting will read.
    grid.send(build(&["b"]), NOW + 3);
    let lease = grid.lease(&first, NOW + 3);
    grid.start(&first, &lease, NOW + 3);
    let beta = grid.output(&first, &lease, "b", b"beta", NOW + 4).unwrap();
    grid.finish(&first, &lease, Ending::Succeeded, NOW + 5).unwrap();
    let reads_beta = JobSpec { inputs: vec![InputRef { name: "table".into(), artifact_id: beta.id.clone() }], ..build(&[]) };
    grid.core.submit_job(&grid.person, &grid.laptop, "later", reads_beta, NOW + 6).unwrap();
    grid.core.close_job_admission("owner", "later", InFlight::Finish, "", NOW + 6).unwrap();
    // A job still running, with a checkpoint as old as the rest.
    let running = grid.send(JobSpec { checkpoints: true, ..build(&[]) }, NOW + 7);
    let held = grid.lease(&second, NOW + 7);
    assert_eq!(held.job_id, running.id);
    grid.start(&second, &held, NOW + 7);
    let halfway = grid.checkpoint(&second, &held, b"halfway", NOW + 8).unwrap();
    // A job whose computer went quiet while it ran, whose effects cannot be repeated: in play until
    // somebody settles it.
    let unknown = grid.send(JobSpec { outputs: vec!["receipt".into()], side_effects: SideEffects::ManualReconcile, ..build(&[]) }, NOW + 9);
    let quiet = grid.lease(&first, NOW + 9);
    grid.start(&first, &quiet, NOW + 9);
    let receipt = grid.output(&first, &quiet, "receipt", b"receipt", NOW + 10).unwrap();
    grid.core.heartbeat_job(&second.device, &held.attempt_id, held.fence, MAX_LEASE_SECONDS, NOW + 60).unwrap();
    grid.core.expire_jobs(NOW + 100);
    assert_eq!(grid.job(&unknown.id).state, JobState::OutcomeUnknown);
    assert_eq!(grid.job(&running.id).state, JobState::Running);
    // A later job that makes the same bytes as one of the first job's outputs.
    grid.send(build(&["copy"]), NOW + 150);
    let lease = grid.lease(&first, NOW + 150);
    grid.start(&first, &lease, NOW + 150);
    let copy = grid.output(&first, &lease, "copy", b"same bytes", NOW + 200).unwrap();
    grid.finish(&first, &lease, Ending::Succeeded, NOW + 201).unwrap();
    assert_eq!(copy.sha256, shared.sha256);

    // The realm keeps a day. A day and a little later, the first job's outputs are past it.
    grid.core.set_job_retention("owner", Retention { keep_seconds: day, keep_bytes: KEEP_JOB_ARTIFACT_BYTES }, NOW + 202).unwrap();
    let shelf = grid.core.job_shelf();
    let tidied = grid.core.tidy_job_artifacts(NOW + day + 100).unwrap();
    assert_eq!(tidied.artifacts_removed, 2, "only the first job's two outputs: {tidied:?}");
    assert_eq!(tidied.bytes_freed, alpha.bytes, "the shared bytes are still named by the later job, so their file stays");
    assert!(!shelf.folder().join(&alpha.sha256).exists());
    for kept in [&shared.sha256, &beta.sha256, &halfway.sha256, &receipt.sha256] {
        assert!(shelf.folder().join(kept).exists(), "{kept} is still needed, or still named");
    }
    // Their records stay, saying when and why; their bytes are not handed out again.
    let records = grid.core.job_outputs(&a.id).unwrap();
    assert!(records.iter().all(|record| record.removed_at == Some(NOW + day + 100) && record.removed_reason.contains("older than")), "{records:?}");
    assert_eq!(grid.core.read_job_artifact(&grid.person, &alpha.id, &mut Vec::new()).unwrap_err(), JobError::ArtifactRemoved);
    let reads_alpha = JobSpec { inputs: vec![InputRef { name: "old".into(), artifact_id: alpha.id.clone() }], ..build(&[]) };
    assert_eq!(grid.core.submit_job(&grid.person, &grid.laptop, "builds", reads_alpha, NOW + day + 101).unwrap_err(), JobError::ArtifactRemoved);
    assert!(grid.actions().iter().any(|action| action == "jobs.artifacts removed"));
    // A copy taken now carries what is kept and nothing that was removed.
    let hourly = grid._folder.path().join("copies").join("hourly.db");
    grid.core.copy_to(&hourly).unwrap();
    assert!(!artifact_folder(&hourly).join(&alpha.sha256).exists());
    assert!(artifact_folder(&hourly).join(&beta.sha256).exists());
    // When the later job's output passes the day too, nothing names the shared bytes, and they go.
    let tidied = grid.core.tidy_job_artifacts(NOW + day + 300).unwrap();
    assert_eq!(tidied.artifacts_removed, 1);
    assert!(!shelf.folder().join(&shared.sha256).exists());
    // What jobs still in play need is still here, however old.
    assert_eq!(grid.core.tidy_job_artifacts(NOW + 30 * day).unwrap().artifacts_removed, 0);
    for kept in [&beta.sha256, &halfway.sha256, &receipt.sha256] {
        assert!(shelf.folder().join(kept).exists());
    }
}

#[test]
fn retention_keeps_to_its_byte_allowance_a_bounded_amount_at_a_time() {
    let mut grid = grid();
    let first = grid.first.clone();
    let finished = grid.send(build(&[]), NOW);
    let done = grid.lease(&first, NOW);
    grid.start(&first, &done, NOW);
    grid.finish(&first, &done, Ending::Succeeded, NOW + 1).unwrap();
    let running = grid.send(JobSpec { checkpoints: true, ..build(&[]) }, NOW + 2);
    let held = grid.lease(&first, NOW + 2);
    grid.start(&first, &held, NOW + 2);
    let realm = grid.core.realm().id.clone();
    let mib = 1_u64 << 20;
    {
        let connection = grid.core.store.connection();
        record_raw(connection, &realm, &running.id, &held.attempt_id, &sha(b"still needed"), 600 * mib, NOW + 9);
        for n in 0..3 {
            record_raw(connection, &realm, &finished.id, &done.attempt_id, &sha(format!("large {n}").as_bytes()), 600 * mib, NOW + 10 + n);
        }
    }
    // 2400 MB kept against an allowance of 1024: the finished job's three go, oldest first, and the
    // running job's is untouched.
    grid.core.set_job_retention("owner", Retention { keep_seconds: LONGEST_JOB_ARTIFACT_KEEP, keep_bytes: 1024 * mib }, NOW + 13).unwrap();
    let tidied = grid.core.tidy_job_artifacts(NOW + 14).unwrap();
    assert_eq!((tidied.artifacts_removed, tidied.bytes_kept, tidied.over_allowance), (3, 600 * mib, false), "{tidied:?}");
    // When what jobs still in play need is past the allowance by itself, it is kept, and the sweep
    // says the realm is over.
    record_raw(grid.core.store.connection(), &realm, &running.id, &held.attempt_id, &sha(b"still needed too"), 600 * mib, NOW + 15);
    let tidied = grid.core.tidy_job_artifacts(NOW + 16).unwrap();
    assert_eq!((tidied.artifacts_removed, tidied.bytes_kept, tidied.over_allowance), (0, 1200 * mib, true), "{tidied:?}");
    // One pass removes a bounded number, and the next carries on.
    {
        let connection = grid.core.store.connection();
        let change = connection.unchecked_transaction().unwrap();
        for n in 0..MAX_ARTIFACTS_REMOVED_PER_PASS + 10 {
            record_raw(&change, &realm, &finished.id, &done.attempt_id, &sha(format!("old {n}").as_bytes()), 1, NOW + 20);
        }
        change.commit().unwrap();
    }
    grid.core.set_job_retention("owner", Retention { keep_seconds: SHORTEST_JOB_ARTIFACT_KEEP, keep_bytes: KEEP_JOB_ARTIFACT_BYTES }, NOW + 21).unwrap();
    let later = NOW + 21 + SHORTEST_JOB_ARTIFACT_KEEP;
    assert_eq!(grid.core.tidy_job_artifacts(later).unwrap().artifacts_removed, MAX_ARTIFACTS_REMOVED_PER_PASS);
    assert_eq!(grid.core.tidy_job_artifacts(later).unwrap().artifacts_removed, 10);
    assert_eq!(grid.core.tidy_job_artifacts(later).unwrap().artifacts_removed, 0);
}
