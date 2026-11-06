//! Buffered chat uses the shared turn policy after complete HTTP/JSON framing.
//! Normalization below is internal validation, never streaming capability evidence.
use super::*;
use crate::serving_protocol::SseFrame;

const LIMIT: usize = 2 * 1024 * 1024;
const INVALID: &str = "Invalid buffered model completion";

pub(in crate::model_runner) async fn read(
    stream: impl AsyncRead + Unpin,
    request: &Profile,
) -> Result<Value, String> {
    read_with_deadline(stream, request, IDLE).await
}

async fn read_with_deadline(
    mut stream: impl AsyncRead + Unpin,
    request: &Profile,
    deadline: Duration,
) -> Result<Value, String> {
    if request.contract.stream {
        return Err("Buffered chat requires stream=false".into());
    }
    tokio::time::timeout(deadline, async {
        let mut http = transport::Response::json();
        let mut body = Vec::new();
        let mut chunk = [0u8; 16 * 1024];
        let mut total = 0;
        let mut agreement = None;
        loop {
            let count = stream
                .read(&mut chunk)
                .await
                .map_err(|_| "The model connection could not be read")?;
            total += count;
            if total > LIMIT {
                return Err("Model response exceeded 2 MiB".into());
            }
            let bytes = http.push(&chunk[..count], count == 0)?;
            if http.status() == Some(200) && agreement.is_none() {
                agreement = Some(request.contract.accept(http.version(), http.features())?);
            }
            if http.status().is_some_and(|status| status != 200)
                && body.len() + bytes.len() > MAX_ERROR
            {
                return Err("Model error response exceeded 64 KiB".into());
            }
            body.extend_from_slice(&bytes);
            if !http.done() {
                continue;
            }
            let status = http.status().ok_or(INVALID)?;
            if status != 200 {
                let value = serde_json::from_slice(&body).unwrap_or(Value::Null);
                if let Some(message) = super::typed_refusal(&value) {
                    return Err(message);
                }
                if let Some(message) = negotiation::refusal(&value) {
                    return Err(message.into());
                }
                return Err(service_error(&classify_http_error(DIALECT, status, &value)));
            }
            let value = serde_json::from_slice(&body).map_err(|_| INVALID)?;
            let mut value = validate(value, &request.policy)?;
            value["servingProtocol"] = agreement.ok_or(INVALID)?;
            return Ok(value);
        }
    })
    .await
    .map_err(|_| "Model response timed out; try a shorter conversation".to_owned())?
}

fn validate(mut value: Value, policy: &RequestProfile) -> Result<Value, String> {
    let choices = value["choices"].as_array().ok_or(INVALID)?;
    if !value.is_object() || value.get("error").is_some() || choices.len() != 1 {
        return Err(INVALID.into());
    }
    let choice = choices[0].as_object().ok_or(INVALID)?;
    if choice.get("index").and_then(Value::as_u64) != Some(0) {
        return Err(INVALID.into());
    }
    let message = choice
        .get("message")
        .and_then(Value::as_object)
        .ok_or(INVALID)?;
    if message.get("role").and_then(Value::as_str) != Some("assistant")
        || message.get("function_call").is_some_and(|v| !v.is_null())
    {
        return Err(INVALID.into());
    }
    let finish = choice
        .get("finish_reason")
        .and_then(Value::as_str)
        .ok_or(INVALID)?;
    let mut delta = serde_json::Map::new();
    delta.insert("role".into(), json!("assistant"));
    for key in ["content", "refusal", "reasoning_content"] {
        if let Some(v) = message.get(key) {
            if !v.is_null() && !v.is_string() {
                return Err(INVALID.into());
            }
            if key != "reasoning_content" {
                delta.insert(key.into(), v.clone());
            }
        }
    }
    if let Some(calls) = message.get("tool_calls").filter(|v| !v.is_null()) {
        let calls = calls.as_array().ok_or(INVALID)?;
        if calls.len() > 32 {
            return Err(INVALID.into());
        }
        let mut normalized = Vec::with_capacity(calls.len());
        for (index, call) in calls.iter().enumerate() {
            let mut call = call.as_object().cloned().ok_or(INVALID)?;
            if call.get("type").and_then(Value::as_str) != Some("function") {
                return Err(INVALID.into());
            }
            if call
                .get("index")
                .is_some_and(|v| v.as_u64() != Some(index as u64))
            {
                return Err(INVALID.into());
            }
            call.insert("index".into(), json!(index));
            normalized.push(Value::Object(call));
        }
        delta.insert("tool_calls".into(), Value::Array(normalized));
    }
    let mut assembler = StreamAssembler::new(
        DIALECT,
        AssemblyLimits {
            max_tool_calls: 32,
            max_argument_bytes: 64 * 1024,
            max_text_bytes: LIMIT,
        },
    );
    let frame = json!({"choices":[{"index":0,"delta":delta,"finish_reason":finish}],
        "usage":value.get("usage").cloned().unwrap_or(Value::Null)});
    assembler.push(&SseFrame {
        event: None,
        data: frame.to_string(),
    });
    assembler.push(&SseFrame {
        event: None,
        data: "[DONE]".into(),
    });
    match assembler.finish(StreamEnd::Eof) {
        TurnOutcome::Completed(turn) => {
            validate_turn(&turn, policy)
                .map_err(|_| "The model returned tool calls that do not satisfy the request")?;
            if !turn.tool_calls().is_empty() {
                // Return only the fields whose complete meaning was validated.
                value["choices"][0]["message"]["tool_calls"] = json!(turn
                    .tool_calls()
                    .iter()
                    .map(
                        |call| json!({"id":call.call_id,"type":"function","function":{
                        "name":call.name,"arguments":call.arguments_json}})
                    )
                    .collect::<Vec<_>>());
            }
        }
        TurnOutcome::Refused { .. } | TurnOutcome::Truncated { .. } => {
            // Preserve display content, refusal, finish and usage, but never release calls.
            value["choices"][0]["message"]
                .as_object_mut()
                .ok_or(INVALID)?
                .remove("tool_calls");
        }
        _ => return Err(INVALID.into()),
    }
    Ok(value)
}

#[cfg(test)]
mod tests;
