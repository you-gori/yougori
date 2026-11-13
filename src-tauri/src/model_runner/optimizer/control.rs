//! Observation-fenced controls for the existing labelled model runtimes.
//!
//! These fences bind one runner instance and its state revision. They are not
//! CORE-04 VM authorization epochs, model activation identities, or host capacity
//! reservations: the existing runner has none of those authorities to supply.
use serde_json::{json, Value};
use std::{collections::HashSet, future::Future, time::Duration};
use tokio_util::sync::CancellationToken;

// Timeout is an unknown remote outcome, never proof of memory release.
pub(super) const TIMEOUT: Duration = Duration::from_secs(20);
const MAX_SEQUENCE: u64 = (1 << 53) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Action {
    Phase,
    Unload,
    Grant,
    /// Hold a resident model to a smaller grant (G03 co-residency): the runner caps its
    /// allocator and context at the terms sent, or at what it still holds plus a margin when
    /// that is more, and answers with what it accepted.
    Trim,
    /// Let a trimmed resident hold more again (G03 grow-back), once the ledger reserved it: the
    /// runner raises its allocator cap and context to exactly the terms sent, never past its
    /// stamp, and answers with them.
    Grow,
}

impl Action {
    fn name(self) -> &'static str {
        match self {
            Self::Phase => "phase",
            Self::Unload => "unload",
            Self::Grant => "grant",
            Self::Trim => "trim",
            Self::Grow => "grow",
        }
    }
    fn acknowledgement(self) -> &'static str {
        match self {
            Self::Phase => "phased",
            Self::Unload => "unloaded",
            Self::Grant => "granted",
            Self::Trim => "trimmed",
            Self::Grow => "grown",
        }
    }
    pub(super) fn body(self) -> Value {
        let mut body = json!({"action": self.name()});
        if self == Self::Phase {
            body["phase"] = json!("freeing_memory");
        }
        body
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Observation {
    // Only a genuinely absent protocol advertisement selects compatibility mode.
    Legacy,
    V1 { instance_id: String, sequence: u64 },
}

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Cancelled,
    TimedOut,
    Rejected,
    InvalidObservation,
    UnsupportedProtocol,
    StaleAcknowledgement,
}

/// Shared with the event consumer: malformed versioned state cannot clear known
/// occupancy or silently downgrade to the legacy protocol.
pub(super) fn observation(health: &Value) -> Result<Observation, Failure> {
    let optimizer = health
        .get("optimizer")
        .and_then(Value::as_object)
        .ok_or(Failure::InvalidObservation)?;
    let Some(version) = optimizer.get("controlProtocol") else {
        return if optimizer.contains_key("instanceId") || optimizer.contains_key("sequence") {
            Err(Failure::InvalidObservation)
        } else {
            Ok(Observation::Legacy)
        };
    };
    if version.as_u64() != Some(1) {
        return Err(Failure::UnsupportedProtocol);
    }
    let instance_id = optimizer
        .get("instanceId")
        .and_then(Value::as_str)
        .filter(|id| {
            id.len() == 32
                && id
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(Failure::InvalidObservation)?;
    let sequence = optimizer
        .get("sequence")
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SEQUENCE)
        .ok_or(Failure::InvalidObservation)?;
    // Unknown v1 states require a protocol update, not an optimistic reading of
    // false residency bits. This vocabulary comes from model_server/gpu_optimizer.
    if !matches!(
        health.get("status").and_then(Value::as_str),
        Some(
            "installing"
                | "downloading"
                | "verifying"
                | "loading"
                | "ready"
                | "error"
                | "idle"
                | "queued"
                | "freeing_memory"
                | "unloading"
        )
    ) || [
        "enabled",
        "pinned",
        "resident",
        "loading",
        "releaseUncertain",
    ]
    .iter()
    .any(|key| optimizer.get(*key).and_then(Value::as_bool).is_none())
        || ["active", "pending"]
            .iter()
            .any(|key| optimizer.get(*key).and_then(Value::as_u64).is_none())
    {
        return Err(Failure::InvalidObservation);
    }
    Ok(Observation::V1 {
        instance_id: instance_id.into(),
        sequence,
    })
}

/// A vLLM runner parked by sleep, with requests of its own waiting, whose runner ends the parked
/// engine on an unload even then (`endsParkedWhileWaiting`, gpu_optimizer.py `gpu_unload`): the
/// requests stay in line and its next load starts the engine again, instead of its leftover
/// keeping the model first in line refused while both wait. Older runners refuse that unload and
/// are never asked.
pub(super) fn ends_parked_while_waiting(health: &Value) -> bool {
    let o = &health["optimizer"];
    health["parked"] == "sleep"
        && o["endsParkedWhileWaiting"] == true
        && o["resident"] == false
        && o["releaseUncertain"] == false
        && o["active"] == 0
}

fn applicable(action: Action, health: &Value, observed: &Observation) -> Result<(), Failure> {
    if *observed == Observation::Legacy {
        return Ok(());
    }
    let o = &health["optimizer"];
    let allowed = match action {
        Action::Phase | Action::Grant => {
            o["enabled"] == true
                && o["resident"] == false
                && o["loading"] == false
                && o["releaseUncertain"] == false
                && o["active"] == 0
                && o["pending"].as_u64().is_some_and(|n| n > 0)
                && matches!(
                    health["status"].as_str(),
                    Some("idle" | "queued" | "freeing_memory")
                )
        }
        // Uncertain memory can be reclaimed; successful acknowledgement must
        // then explicitly prove that uncertainty cleared.
        Action::Unload => {
            o["enabled"] == true
                && o["pinned"] == false
                && o["loading"] == false
                && o["active"] == 0
                && (o["pending"] == 0 || ends_parked_while_waiting(health))
        }
        // A resident model is trimmed, or grows back, while serving; what it holds decides
        // how far.
        Action::Trim | Action::Grow => {
            o["enabled"] == true
                && o["resident"] == true
                && o["loading"] == false
                && o["releaseUncertain"] == false
        }
    };
    if allowed {
        Ok(())
    } else {
        Err(Failure::Rejected)
    }
}

fn body(action: Action, observed: &Observation) -> Result<Value, Failure> {
    let mut body = action.body();
    if let Observation::V1 {
        instance_id,
        sequence,
    } = observed
    {
        if *sequence == MAX_SEQUENCE {
            return Err(Failure::InvalidObservation);
        }
        body["expectedInstanceId"] = json!(instance_id);
        body["expectedSequence"] = json!(sequence);
    }
    Ok(body)
}

/// New configuration writes require CAS even when legacy scheduler controls are
/// supported. The caller durably records uncertainty before sending this body:
/// dropping a timed-out HTTP future cannot revoke a delayed remote configuration.
pub(super) fn fence_configuration(health: &Value, mut body: Value) -> Result<Value, Failure> {
    if body.get("action").and_then(Value::as_str) != Some("configure") {
        return Err(Failure::Rejected);
    }
    let Observation::V1 {
        instance_id,
        sequence,
    } = observation(health)?
    else {
        return Err(Failure::UnsupportedProtocol);
    };
    if sequence == MAX_SEQUENCE {
        return Err(Failure::InvalidObservation);
    }
    body["expectedInstanceId"] = json!(instance_id);
    body["expectedSequence"] = json!(sequence);
    Ok(body)
}

/// A causal configuration ACK confirms only acceptance of that command; it is
/// not proof that disabled/loading/resident capacity became available.
pub(super) fn configuration_acknowledged(health: &Value, answer: &Value) -> bool {
    let Ok(Observation::V1 {
        instance_id,
        sequence,
    }) = observation(health)
    else {
        return false;
    };
    let Some(expected) = sequence.checked_add(1).filter(|n| *n <= MAX_SEQUENCE) else {
        return false;
    };
    observation(answer)
        == Ok(Observation::V1 {
            instance_id: instance_id.clone(),
            sequence: expected,
        })
        && answer["controlAck"]["action"] == "configure"
        && answer["controlAck"]["instanceId"] == instance_id
        && answer["controlAck"]["expectedSequence"].as_u64() == Some(sequence)
        && answer["controlAck"]["sequence"].as_u64() == Some(expected)
}

/// `waiting`: the unload was sent to a runner whose parked engine it ends while its own requests
/// wait ([`ends_parked_while_waiting`]), so the answer may still count them; its answer no longer
/// says it was parked.
fn acknowledged(action: Action, before: &Observation, answer: &Value, waiting: bool) -> Result<(), Failure> {
    match before {
        Observation::Legacy => {
            // A runner upgraded/restarted after observation must be rediscovered
            // before issuing further controls; never continue on an unfenced ack.
            if answer.get("controlAck").is_some()
                || answer["optimizer"].get("controlProtocol").is_some()
                || answer["optimizer"].get("instanceId").is_some()
                || answer["optimizer"].get("sequence").is_some()
                || !answer.is_object()
                || (action == Action::Unload && answer["unloaded"] != true)
            {
                return Err(Failure::StaleAcknowledgement);
            }
        }
        Observation::V1 {
            instance_id,
            sequence,
        } => {
            let after = observation(answer).map_err(|_| Failure::StaleAcknowledgement)?;
            let expected = sequence
                .checked_add(1)
                .filter(|n| *n <= MAX_SEQUENCE)
                .ok_or(Failure::StaleAcknowledgement)?;
            if after
                != (Observation::V1 {
                    instance_id: instance_id.clone(),
                    sequence: expected,
                })
                || answer[action.acknowledgement()] != true
                || answer["controlAck"]["action"] != action.name()
                || answer["controlAck"]["instanceId"] != instance_id.as_str()
                || answer["controlAck"]["expectedSequence"].as_u64() != Some(*sequence)
                || answer["controlAck"]["sequence"].as_u64() != Some(expected)
            {
                return Err(Failure::StaleAcknowledgement);
            }
            let o = &answer["optimizer"];
            match action {
                Action::Phase => applicable(Action::Grant, answer, &after)?,
                Action::Unload
                    if o["resident"] != false
                        || o["loading"] != false
                        || o["releaseUncertain"] != false
                        || o["active"] != 0
                        || (o["pending"] != 0 && !waiting)
                        || o["enabled"] != true =>
                {
                    return Err(Failure::Rejected)
                }
                Action::Grant if o["enabled"] != true || o["releaseUncertain"] != false => {
                    return Err(Failure::Rejected)
                }
                _ => {}
            }
        }
    }
    Ok(())
}

pub(super) async fn request<F, Fut>(
    id: &str,
    action: Action,
    health: &Value,
    shutdown: &CancellationToken,
    timeout: Duration,
    send: &F,
) -> Result<Value, Failure>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    request_with(id, action, health, None, shutdown, timeout, send).await
}

/// [`request`] with the fields of `terms` added to the fenced body: a grant's terms (the
/// bytes the runner may hold and the context they cover, G03 co-residency). The fence
/// fields themselves are never overridden.
pub(super) async fn request_with<F, Fut>(
    id: &str,
    action: Action,
    health: &Value,
    terms: Option<&Value>,
    shutdown: &CancellationToken,
    timeout: Duration,
    send: &F,
) -> Result<Value, Failure>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if shutdown.is_cancelled() {
        return Err(Failure::Cancelled);
    }
    let observed = observation(health)?;
    applicable(action, health, &observed)?;
    let mut body = body(action, &observed)?;
    if let Some(Value::Object(terms)) = terms {
        for (key, value) in terms {
            if body.get(key).is_none() {
                body[key] = value.clone();
            }
        }
    }
    let answer = tokio::select! {
        biased;
        _ = shutdown.cancelled() => return Err(Failure::Cancelled),
        answer = tokio::time::timeout(timeout, async { send(id.to_owned(), body).await }) => {
            answer.map_err(|_| Failure::TimedOut)?.map_err(|_| Failure::Rejected)?
        }
    };
    if shutdown.is_cancelled() {
        return Err(Failure::Cancelled);
    }
    let waiting = action == Action::Unload && ends_parked_while_waiting(health);
    acknowledged(action, &observed, &answer, waiting)?;
    Ok(answer)
}

/// Consume one observation set. Any stale/restarted/refused/unknown result ends
/// this transition. The caller reconciles before a new attempt, without assuming
/// rollback or retrying any of these controls with a stale fence.
///
/// The host serializes configuration with this transition. Each runner must clear
/// old grants on unload and require a fresh grant for later demand; per-runner CAS
/// cannot reserve capacity against unmanaged GPU consumers or independent hosts.
pub(super) async fn switch<F, Fut>(
    target: &str,
    target_health: &Value,
    residents: &[(String, Value)],
    shutdown: &CancellationToken,
    timeout: Duration,
    send: &F,
) -> Result<(), Failure>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    let prepared =
        prepare_switch(target, target_health, residents, shutdown, timeout, send).await?;
    request(
        target,
        Action::Grant,
        &prepared.target,
        shutdown,
        timeout,
        send,
    )
    .await?;
    Ok(())
}

pub(super) struct Prepared {
    pub target: Value,
    pub released: Vec<(String, Value)>,
}

/// Complete eviction before the caller samples host capacity and reserves it.
/// This function cannot grant or initiate a target load.
pub(super) async fn prepare_switch<F, Fut>(
    target: &str,
    target_health: &Value,
    residents: &[(String, Value)],
    shutdown: &CancellationToken,
    timeout: Duration,
    send: &F,
) -> Result<Prepared, Failure>
where
    F: Fn(String, Value) -> Fut,
    Fut: Future<Output = Result<Value, String>>,
{
    if shutdown.is_cancelled() {
        return Err(Failure::Cancelled);
    }
    applicable(Action::Phase, target_health, &observation(target_health)?)?;
    let mut ids = HashSet::new();
    for (id, health) in residents {
        if id == target || !ids.insert(id) {
            return Err(Failure::InvalidObservation);
        }
        let observed = observation(health)?;
        applicable(Action::Unload, health, &observed)?;
        body(Action::Unload, &observed)?;
    }
    let phase = request(
        target,
        Action::Phase,
        target_health,
        shutdown,
        timeout,
        send,
    )
    .await?;
    let mut released = Vec::new();
    for (id, health) in residents {
        let answer = request(id, Action::Unload, health, shutdown, timeout, send).await?;
        released.push((id.clone(), answer));
    }
    // Legacy controls did not return full health. Keep only their genuine older
    // protocol behavior; versioned targets always use the phase acknowledgement.
    let target_fence = if observation(target_health)? == Observation::Legacy {
        target_health
    } else {
        &phase
    };
    Ok(Prepared {
        target: target_fence.clone(),
        released,
    })
}

#[cfg(test)]
mod tests;
