//! The grid's door to finite jobs: a company app sends work to a named queue, asks how it is
//! going and reads what it produced; a member computer asks for work, keeps its reservation
//! alive, sends what it made and says how it ended.
//!
//! Everything here is a thin door onto `core::jobs`, which holds every guarantee: the queue, the
//! fencing, the attempts, the staged and checksummed artifacts, the retries by side-effect class,
//! the cancel that is a request, and the research realm that runs no generic job. This module adds
//! three things and nothing else.
//!
//! **Who is asking.** The grid already knows a member computer by its token, exactly as every
//! other `/grid/v1/` door does. A member is only allowed near the queue once an applied setup has
//! tied it to a person and a computer inside the realm (`enrol`), so a computer that merely
//! belongs to the grid is not by that fact a worker for its jobs, and a member that is untied
//! (`forget`) stops being one at its next call rather than at some later sweep.
//!
//! **What may arrive.** Every request but one is JSON and bounded at `REQUEST_LIMIT`. The one that
//! is not is an artifact, whose bytes are streamed into the realm's staging folder as they come,
//! counted and hashed there, and compared with what the computer declared before anything is
//! recorded. The realm is taken twice around that upload, briefly, and never for the length of it.
//!
//! **What goes back.** A refusal carries the library's own stable word (`code`) and its own
//! sentence, so a person reads the same explanation here as anywhere else, and a program matches
//! on the same word. Nothing is reworded on the way out.
//!
//! What this door does not do, said rather than implied. It is off until a setup turns it on; a
//! grid with no jobs service answers every path here with the same plain "not turned on". Reading
//! an artifact holds the realm for as long as the bytes take to reach the computer asking, so a
//! computer that stops reading is cut off after `RELAY_STALL` rather than left holding it. And a
//! job never carries a place on this computer, a shell line or a credential: the library refuses
//! all three before this module sees a queue.
use super::*;
use crate::core::{
    jobs::{ArtifactRole, Ending, Failure, InFlight, JobError, JobSpec, Settled},
    Core,
};
use std::io::{Read, Write};

/// The longest an artifact may take to reach the computer reading it before the realm is given
/// back. The same stall the model relay allows, for the same reason.
const SEND_STALL: Duration = RELAY_STALL;

/// How many bytes of an artifact are in flight between the realm and the network at once.
const PIECE: usize = 64 * 1024;

/// A member computer tied to a person and a computer inside the realm, so its calls are placed by
/// somebody the realm knows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Worker {
    pub principal_id: String,
    pub device_id: String,
}

/// The jobs door of one realm. Held by the hub only once a setup has turned jobs on.
pub struct Service {
    realm: Mutex<Core>,
    workers: Mutex<HashMap<String, Worker>>,
}

impl Service {
    pub fn new(realm: Core) -> Service {
        Service { realm: Mutex::new(realm), workers: Mutex::new(HashMap::new()) }
    }

    /// Ties a member computer of the grid to a person and a computer inside the realm. Until this,
    /// a member is in the grid but is not one of the realm's workers.
    pub fn enrol(&self, member: &str, principal_id: &str, device_id: &str) {
        lock(&self.workers).insert(member.to_owned(), Worker { principal_id: principal_id.to_owned(), device_id: device_id.to_owned() });
    }

    /// Unties a member. Its next call is refused; nothing it already holds is killed, and its
    /// attempts end the way any attempt whose computer goes quiet does.
    pub fn forget(&self, member: &str) {
        lock(&self.workers).remove(member);
    }

    pub fn worker(&self, member: &str) -> Option<Worker> {
        lock(&self.workers).get(member).cloned()
    }

    /// Settles attempts whose reservations have ended and tidies kept artifacts. The hub's sweep
    /// calls this; a worker that went quiet is noticed here and its job placed again.
    pub fn sweep(&self, now: i64) -> usize {
        lock(&self.realm).expire_jobs(now)
    }

    /// Reads the realm for one short call. Never held across an upload or a download.
    fn with<T>(&self, work: impl FnOnce(&mut Core) -> T) -> T {
        work(&mut lock(&self.realm))
    }
}

/// A refusal from the library, as the door reports it: the library's own sentence and its own
/// stable word, under the status that matches what went wrong.
fn refused(error: &JobError) -> Response<Body> {
    let status = match error {
        JobError::ResearchRealm | JobError::ResearchAction(_) | JobError::NoComputers | JobError::NotAllowed(_) | JobError::NotAWorker => StatusCode::FORBIDDEN,
        JobError::InvalidSpec(_) | JobError::PathLikeName(_) | JobError::UndeclaredOutput(_) | JobError::NoCheckpoints | JobError::NotStarted | JobError::NothingAskedToStop => StatusCode::BAD_REQUEST,
        JobError::NoSuchJob | JobError::NoSuchAttempt | JobError::NoSuchArtifact | JobError::ArtifactRemoved | JobError::StagedGone => StatusCode::NOT_FOUND,
        JobError::Limit(_) | JobError::SizeMismatch { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        JobError::StaleFence | JobError::WrongComputer | JobError::LeaseLost => StatusCode::CONFLICT,
        JobError::QueueClosed { .. } | JobError::NotServing | JobError::Draining | JobError::HostRefused(_) => StatusCode::SERVICE_UNAVAILABLE,
        JobError::Trouble(_) | JobError::Damaged => StatusCode::INTERNAL_SERVER_ERROR,
        _ => StatusCode::CONFLICT,
    };
    error_response(status, error.code(), error.describe())
}

fn error_response(status: StatusCode, code: &str, message: impl Into<String>) -> Response<Body> {
    super::error(status, code, message)
}

fn answer<T: Serialize>(value: Result<T, JobError>) -> Response<Body> {
    match value {
        Ok(value) => json_response(StatusCode::OK, &serde_json::to_value(value).unwrap_or(Value::Null)),
        Err(error) => refused(&error),
    }
}

/// The paths this door serves, after `/grid/v1/queue/`.
pub(super) async fn route(service: &Arc<Service>, member: &str, rest: &str, request: Request<Incoming>) -> Response<Body> {
    let Some(worker) = service.worker(member) else {
        return error_response(
            StatusCode::FORBIDDEN,
            "not_a_worker",
            "This computer is in the grid but is not one of its job workers. Apply the setup that adds it, or ask the grid's admin to.",
        );
    };
    if rest == "artifact/send" {
        return send_artifact(service, &worker, request).await;
    }
    let body = match net::json_body(request.into_body(), REQUEST_LIMIT).await {
        Ok(body) => body,
        Err(message) => return error_response(StatusCode::BAD_REQUEST, "invalid_request_error", message),
    };
    act(service, &worker, rest, &body)
}

/// Everything but the artifact upload, once the request's body has been read. Separate so that
/// every door can be exercised without a socket.
fn act(service: &Arc<Service>, worker: &Worker, rest: &str, body: &Value) -> Response<Body> {
    let text = |key: &str| body[key].as_str().unwrap_or_default().to_owned();
    let at = now();
    match rest {
        "submit" => {
            let spec = match JobSpec::from_json(&body["spec"].to_string()) {
                Ok(spec) => spec,
                Err(error) => return refused(&error),
            };
            let result = service.with(|core| core.submit_job(&worker.principal_id, &worker.device_id, &text("queue"), spec, at));
            match result {
                Ok(submitted) => json_response(StatusCode::OK, &json!({"job": submitted.job, "replayed": submitted.replayed})),
                Err(error) => refused(&error),
            }
        }
        "list" => answer(service.with(|core| core.jobs())),
        "job" => {
            let id = text("jobId");
            let result = service.with(|core| {
                let job = core.job(&id)?.ok_or(JobError::NoSuchJob)?;
                let attempts = core.job_attempts(&id)?;
                let artifacts = core.job_artifacts(&id)?;
                let waiting = core.why_job_waits(&id, at)?;
                Ok::<_, JobError>(json!({"job": job, "attempts": attempts, "artifacts": artifacts, "waitingBecause": waiting}))
            });
            answer(result)
        }
        "outputs" => answer(service.with(|core| core.job_outputs(&text("jobId")))),
        "cancel" => answer(service.with(|core| core.cancel_job(&worker.principal_id, &text("jobId"), at)).map(|state| json!({"state": state}))),
        "settle" => {
            let Some(settled) = settlement(&text("outcome")) else {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request_error", "Say what you found: 'succeeded', 'failed' or 'runAgain'");
            };
            answer(service.with(|core| core.settle_job(&worker.principal_id, &text("jobId"), settled, at)).map(|state| json!({"state": state})))
        }
        "close" => {
            let in_flight = match body["inFlight"].as_str() {
                Some("finish") => InFlight::Finish,
                Some("stop") => InFlight::Stop,
                _ => return error_response(StatusCode::BAD_REQUEST, "invalid_request_error", "Say what happens to the attempts already running: 'finish' or 'stop'"),
            };
            answer(service.with(|core| core.close_job_admission(&worker.principal_id, &text("queue"), in_flight, &text("reason"), at)))
        }
        "open" => answer(service.with(|core| core.reopen_job_admission(&worker.principal_id, &text("queue"), at))),
        "state" => answer(service.with(|core| core.job_queue(&text("queue")))),
        "lease" => {
            let seconds = body["seconds"].as_i64().unwrap_or(60);
            answer(service.with(|core| core.lease_job(&worker.device_id, seconds, at)).map(|lease| json!({"lease": lease})))
        }
        "start" => answer(service.with(|core| core.start_job_attempt(&worker.device_id, &text("attemptId"), fence(body), at))),
        "heartbeat" => {
            let seconds = body["seconds"].as_i64().unwrap_or(60);
            answer(service.with(|core| core.heartbeat_job(&worker.device_id, &text("attemptId"), fence(body), seconds, at)))
        }
        "complete" => {
            let Some(ending) = ending(body) else {
                return error_response(StatusCode::BAD_REQUEST, "invalid_request_error", "Say how the attempt ended: 'succeeded', 'stopped', or 'failed' with a reason");
            };
            answer(service.with(|core| core.complete_job_attempt(&worker.device_id, &text("attemptId"), fence(body), ending, at)).map(|state| json!({"state": state})))
        }
        "input" => read_bytes(service, Reading::Input { worker: worker.clone(), attempt: text("attemptId"), fence: fence(body), artifact: text("artifactId") }),
        "artifact" => read_bytes(service, Reading::Artifact { worker: worker.clone(), artifact: text("artifactId") }),
        _ => error_response(StatusCode::NOT_FOUND, "not_found", "Unknown jobs path"),
    }
}

fn fence(body: &Value) -> u64 {
    body["fence"].as_u64().unwrap_or_default()
}

fn settlement(word: &str) -> Option<Settled> {
    match word {
        "succeeded" => Some(Settled::Succeeded),
        "failed" => Some(Settled::Failed),
        "runAgain" => Some(Settled::RunAgain),
        _ => None,
    }
}

/// How a computer says an attempt ended, in the closed set the library keeps. A member computer
/// never chooses the words that go into the realm's history; it chooses one of these.
fn ending(body: &Value) -> Option<Ending> {
    match body["ending"].as_str()? {
        "succeeded" => Some(Ending::Succeeded),
        "stopped" => Some(Ending::Stopped),
        "failed" => Some(Ending::Failed(match body["failure"].as_str().unwrap_or("exited") {
            "crashed" => Failure::Crashed,
            "interrupted" => Failure::Interrupted,
            "inputUnavailable" => Failure::InputUnavailable,
            _ => Failure::Exited,
        })),
        _ => None,
    }
}

/// What is being read out of the realm's shelf.
enum Reading {
    /// One of an attempt's own inputs, read by the computer holding that attempt.
    Input { worker: Worker, attempt: String, fence: u64, artifact: String },
    /// An artifact of a job, read by whoever may read this realm's jobs.
    Artifact { worker: Worker, artifact: String },
}

/// Streams bytes out of the realm, in pieces, checked against their checksum on the way.
///
/// The realm is held while the bytes travel, so a computer that stops reading is cut off after
/// `SEND_STALL` instead of holding the realm for as long as it likes.
fn read_bytes(service: &Arc<Service>, reading: Reading) -> Response<Body> {
    let (sender, receiver) = mpsc::channel::<Result<Frame<Bytes>, std::io::Error>>(4);
    let service = service.clone();
    tokio::task::spawn_blocking(move || {
        let mut into = Piping { sender, trouble: None };
        let at = now();
        let result = match &reading {
            Reading::Input { worker, attempt, fence, artifact } => service.with(|core| core.read_job_input(&worker.device_id, attempt, *fence, artifact, &mut into, at)),
            Reading::Artifact { worker, artifact } => service.with(|core| core.read_job_artifact(&worker.principal_id, artifact, &mut into)),
        };
        // A refusal after the first byte cannot change the status, so the stream simply ends; the
        // checksum the reader was given is what tells it the bytes are short.
        if let Err(error) = result {
            let _ = into.sender.blocking_send(Err(std::io::Error::other(error.describe())));
        }
    });
    let stream = futures_util::stream::unfold(receiver, |mut receiver| async move { receiver.recv().await.map(|item| (item, receiver)) });
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CACHE_CONTROL, "no-store")
        .body(StreamBody::new(stream).boxed_unsync())
        .expect("artifact response")
}

/// A `Write` that hands each piece to the network, giving up after `SEND_STALL` without a reader.
struct Piping {
    sender: mpsc::Sender<Result<Frame<Bytes>, std::io::Error>>,
    trouble: Option<std::io::Error>,
}

impl Write for Piping {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        if let Some(trouble) = &self.trouble {
            return Err(std::io::Error::new(trouble.kind(), trouble.to_string()));
        }
        for piece in buffer.chunks(PIECE) {
            let frame = Ok(Frame::data(Bytes::copy_from_slice(piece)));
            let sent = tokio::runtime::Handle::current().block_on(async { tokio::time::timeout(SEND_STALL, self.sender.send(frame)).await });
            if !matches!(sent, Ok(Ok(()))) {
                let trouble = std::io::Error::other("the computer reading this artifact stopped reading it");
                self.trouble = Some(std::io::Error::new(trouble.kind(), trouble.to_string()));
                return Err(trouble);
            }
        }
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// A `Read` fed by the request's body as it arrives, so staging an artifact never buffers it.
struct Arriving {
    receiver: mpsc::Receiver<Result<Bytes, String>>,
    held: Bytes,
    trouble: Option<String>,
}

impl Read for Arriving {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        while self.held.is_empty() {
            if let Some(trouble) = &self.trouble {
                return Err(std::io::Error::other(trouble.clone()));
            }
            match self.receiver.blocking_recv() {
                Some(Ok(piece)) => self.held = piece,
                Some(Err(trouble)) => {
                    self.trouble = Some(trouble.clone());
                    return Err(std::io::Error::other(trouble));
                }
                None => return Ok(0),
            }
        }
        let taken = self.held.len().min(buffer.len());
        buffer[..taken].copy_from_slice(&self.held[..taken]);
        self.held = self.held.slice(taken..);
        Ok(taken)
    }
}

/// An artifact an attempt made, in the two steps the library asks for: leave first, then the bytes
/// into staging without the realm, then the realm taken briefly to record them.
///
/// What the bytes are is in the headers, because the body is the bytes. A computer sending the
/// same output twice — because it never heard the first answer — finds the record it already made.
async fn send_artifact(service: &Arc<Service>, worker: &Worker, request: Request<Incoming>) -> Response<Body> {
    let header = |name: &str| request.headers().get(name).and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned();
    let attempt = header("x-attempt");
    let fence = header("x-fence").parse::<u64>().unwrap_or_default();
    let name = header("x-name");
    let sha256 = header("x-sha256");
    let role = if header("x-role") == "checkpoint" { ArtifactRole::Checkpoint } else { ArtifactRole::Output };
    let Ok(bytes) = header("x-bytes").parse::<u64>() else {
        return error_response(StatusCode::BAD_REQUEST, "invalid_request_error", "An artifact says how many bytes it is and what they hash to before it sends them");
    };
    let at = now();
    let ticket = service.with(|core| match role {
        ArtifactRole::Output => core.prepare_job_output(&worker.device_id, &attempt, fence, &name, bytes, &sha256, at),
        ArtifactRole::Checkpoint => core.prepare_job_checkpoint(&worker.device_id, &attempt, fence, bytes, &sha256, at),
    });
    let ticket = match ticket {
        Ok(ticket) => ticket,
        Err(error) => return refused(&error),
    };
    // The bytes go to the staging folder as they arrive. The realm is free throughout.
    let (sender, receiver) = mpsc::channel::<Result<Bytes, String>>(4);
    let mut body = request.into_body();
    tokio::spawn(async move {
        loop {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if sender.send(Ok(data)).await.is_err() {
                            return;
                        }
                    }
                }
                Some(Err(error)) => {
                    let _ = sender.send(Err(format!("The artifact did not arrive whole: {error}"))).await;
                    return;
                }
                None => return,
            }
        }
    });
    let staging = service.clone();
    let staged = tokio::task::spawn_blocking(move || {
        let mut arriving = Arriving { receiver, held: Bytes::new(), trouble: None };
        let staged = ticket.stage(&mut arriving)?;
        staging.with(|core| core.record_job_artifact(staged, now()))
    })
    .await;
    match staged {
        Ok(Ok(artifact)) => json_response(StatusCode::OK, &json!({"artifact": artifact})),
        Ok(Err(error)) => refused(&error),
        Err(_) => error_response(StatusCode::INTERNAL_SERVER_ERROR, "trouble", "This computer could not store the artifact. Try sending it again."),
    }
}

#[cfg(test)]
mod tests;
