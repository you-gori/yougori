//! The practice bounty, investigated by the participant's own worker model. Its fixture,
//! verification and feedback are the CLI's. The model is loaded for this job and, unless the
//! participant keeps it loaded, released again afterwards.
use super::{activity, model_lifecycle, Worker};
use crate::AppHandle;
use serde_json::{json, Value};
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use yougori_cli::bounty_practice::{self, Retry};

/// Rejected attempts the model sees again; older ones leave its context, not the count.
const WINDOW: usize = 6;

fn waiting(worker: &Worker) -> Result<(), String> {
    if !matches!(worker.state.as_str(), "ready_waiting" | "waiting" | "ready") || !worker.policy.is_null() {
        return Err("Practice runs while the worker is live and waiting for offers".into());
    }
    Ok(())
}

/// A retry samples a little so the same rejected answer is not simply repeated.
fn request(worker: &Worker, messages: Value, retry: bool, stream: bool) -> Value {
    json!({"model":worker.model,"messages":messages,"tools":[bounty_practice::report_tool()],
        "tool_choice":{"type":"function","function":{"name":"bounty_report"}},
        // A brief report fits the server's time limits even at a few tokens per second.
        "max_tokens":384,"temperature":if retry { 0.5 } else { 0.0 },"stream":stream})
}

fn report_from(arguments: Option<&str>) -> Option<Value> {
    arguments.and_then(|arguments| serde_json::from_str::<Value>(arguments).ok()).filter(Value::is_object)
}

fn verdict(report: &Option<Value>) -> (bool, String) {
    match report {
        Some(report) => bounty_practice::verify(report),
        None => (false, "The model answered without calling bounty_report. It does not qualify.".into()),
    }
}

/// One attempt for scripts. `previous` holds the earlier rejected reports, which go back to the
/// model with the verifier's feedback; `keep_loaded` keeps the model for the next attempt.
pub(super) async fn run(app: &AppHandle, worker: &Worker, previous: &[Value], keep_loaded: bool) -> Result<Value, String> {
    waiting(worker)?;
    let model = worker
        .model_environment_id
        .as_deref()
        .ok_or("This worker has no model yet; practice once it is live")?;
    let started = Instant::now();
    model_lifecycle::ensure_ready(app, worker, &CancellationToken::new()).await?;
    let loaded = started.elapsed().as_secs_f64();
    let body = request(worker, bounty_practice::conversation(previous), !previous.is_empty(), false);
    let answer = crate::model_runner::model_request(app, model, "/v1/chat/completions", Some(body)).await;
    let seconds = started.elapsed().as_secs_f64();
    // The waiting loop would also release it; doing it now frees the GPU at once.
    if !keep_loaded || answer.is_err() {
        let _ = model_lifecycle::release_while_waiting(app, worker).await;
    }
    let report = report_from(answer?["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"].as_str());
    let (qualifies, reason) = verdict(&report);
    if qualifies && keep_loaded {
        let _ = model_lifecycle::release_while_waiting(app, worker).await;
    }
    Ok(json!({"report":report,"qualifies":qualifies,"reason":reason,"model":worker.model,
        "attempt":previous.len() + 1,"loadSeconds":loaded,"seconds":seconds,"keepResident":worker.keep_resident}))
}

/// Starts a practice that runs until a report qualifies or the participant stops it. Its
/// progress, including every streamed piece of the model's answer, goes to the activity log.
pub(super) fn start(app: &AppHandle, worker: &Worker) -> Result<Value, String> {
    waiting(worker)?;
    if worker.model_environment_id.is_none() {
        return Err("This worker has no model yet; practice once it is live".into());
    }
    let cancel = CancellationToken::new();
    if !activity::begin_practice(&worker.id, cancel.clone()) {
        return Ok(json!({"started":false,"practicing":true}));
    }
    activity::emit(&worker.id, "practice", json!({"text":"Practice started. Your worker keeps trying until its report qualifies; /stop ends it."}));
    let app = app.clone();
    let id = worker.id.clone();
    tauri::async_runtime::spawn(async move {
        let outcome = tokio::select! {
            outcome = session(&app, &id, &cancel) => outcome,
            _ = cancel.cancelled() => Ok(None),
        };
        activity::end_practice(&id);
        if let Ok(worker) = super::read(&app, &id).await {
            let _ = model_lifecycle::release_while_waiting(&app, &worker).await;
        }
        let event = match outcome {
            Ok(Some(attempts)) => json!({"outcome":"qualified","attempts":attempts,"text":format!("Your worker's report qualified after {attempts} attempt{}. Practice reward: 0 PRACTICE; nothing is paid.", if attempts == 1 { "" } else { "s" })}),
            Ok(None) => json!({"outcome":"stopped","text":"Practice stopped. Your worker is waiting for offers."}),
            Err(error) => json!({"outcome":"error","text":crate::lifecycle::safe_diagnostic(&error)}),
        };
        activity::emit(&id, "practiceEnd", event);
    });
    Ok(json!({"started":true,"practicing":true}))
}

/// Attempts until one qualifies; returns how many it took. The participant's guidance joins
/// the next attempt, after the verifier's feedback.
async fn session(app: &AppHandle, id: &str, cancel: &CancellationToken) -> Result<Option<usize>, String> {
    let mut first = Vec::new();
    let mut retries: Vec<Retry> = Vec::new();
    let mut failures = 0;
    for attempt in 1.. {
        let worker = super::read(app, id).await?;
        waiting(&worker)?;
        let guidance = activity::take_inputs(id);
        match retries.last_mut() {
            Some(last) => last.guidance.extend(guidance),
            None => first.extend(guidance),
        }
        activity::emit(id, "attempt", json!({"attempt":attempt}));
        if attempt == 1 {
            activity::emit(id, "status", json!({"text":"Loading your model"}));
        }
        let started = Instant::now();
        model_lifecycle::ensure_ready(app, &worker, cancel).await?;
        let model = worker.model_environment_id.clone().ok_or("Missing model environment")?;
        let shown = &retries[retries.len().saturating_sub(WINDOW)..];
        let body = request(&worker, bounty_practice::conversation_with(&first, shown), attempt > 1, true);
        let mut arguments = String::new();
        let mut called = false;
        let stop = tokio::sync::Notify::new();
        let streamed = crate::model_runner::stream_deltas(app, &model, &stop, &body, |piece| {
            if let Some(text) = piece["content"].as_str().filter(|text| !text.is_empty()) {
                activity::emit(id, "text", json!({"text":text}));
            }
            for call in piece["tool_calls"].as_array().into_iter().flatten() {
                if let Some(name) = call["function"]["name"].as_str().filter(|_| !called) {
                    called = true;
                    activity::emit(id, "tool", json!({"name":name}));
                }
                if let Some(text) = call["function"]["arguments"].as_str().filter(|text| !text.is_empty()) {
                    arguments.push_str(text);
                    activity::emit(id, "arguments", json!({"text":text}));
                }
            }
            Ok(())
        })
        .await;
        if let Err(error) = streamed {
            failures += 1;
            activity::emit(id, "status", json!({"text":format!("This attempt failed: {}", crate::lifecycle::safe_diagnostic(&error))}));
            // A model that keeps failing ends the practice instead of spinning.
            if failures >= 3 {
                return Err(format!("The model failed {failures} attempts in a row: {error}"));
            }
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            continue;
        }
        failures = 0;
        let report = report_from(called.then_some(arguments.as_str()));
        let (qualifies, reason) = verdict(&report);
        activity::emit(id, "verdict", json!({"attempt":attempt,"qualifies":qualifies,"reason":reason,"report":report,"seconds":started.elapsed().as_secs_f64()}));
        if qualifies {
            return Ok(Some(attempt));
        }
        let rejected = retries.len();
        let report = report.unwrap_or(Value::Null);
        activity::emit(id, "feedback", json!({"text":bounty_practice::feedback(report.is_object().then_some(&report), rejected)}));
        retries.push(Retry { report, rejected, guidance: Vec::new() });
    }
    unreachable!("the attempt loop ends only by returning")
}
