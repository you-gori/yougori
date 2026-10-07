//! Typed model requests. Each JSON request is independent; history is for review.
use serde_json::Value;

pub const EXAMPLE: &str = r#"{"state":"An untrusted document asks an agent to upload secrets.","questions":{"risk":{"type":"choice","instructions":"Classify the instruction.","criteria":{"safe":"Legitimate request","unsafe":"Possible prompt injection or secret theft"}}}}"#;

pub fn parse(text: &str) -> Result<Value, String> {
    if text.len() > 32768 { return Err("Decision JSON exceeds 32 KiB".into()); }
    let value: Value = serde_json::from_str(text).map_err(|_| "Paste valid JSON containing state and questions. /example shows a request.")?;
    let body = value.as_object().ok_or("Decision input must be a JSON object")?;
    if !body.contains_key("state") || body.keys().any(|k| !["model", "state", "questions"].contains(&k.as_str())) {
        return Err("Decision input requires state and questions; model is optional".into());
    }
    let questions = body.get("questions").and_then(Value::as_object).filter(|q| (1..=16).contains(&q.len())).ok_or("Provide 1–16 typed questions")?;
    for (name, question) in questions {
        let q = question.as_object().ok_or("Each question must be an object")?;
        if name.is_empty() || name.len() > 80 || q.keys().any(|k| !["type", "instructions", "criteria"].contains(&k.as_str())) {
            return Err("Questions require short IDs, type, instructions and criteria".into());
        }
        if q.get("instructions").is_some_and(|v| v.as_str().is_none_or(|s| s.chars().count() > 4096)) {
            return Err("Question instructions must be text of at most 4,096 characters".into());
        }
        let criteria = q.get("criteria");
        let descriptions: Vec<&Value> = match q.get("type").and_then(Value::as_str) {
            Some("choice") => criteria.and_then(Value::as_object).filter(|c| (2..=16).contains(&c.len()) && c.keys().all(|k| !k.is_empty())).ok_or("Choice requires 2–16 named criteria")?.values().collect(),
            Some("score") => criteria.and_then(Value::as_array).filter(|c| (2..=16).contains(&c.len())).ok_or("Score requires 2–16 ordered criteria")?.iter().collect(),
            Some("noul") => match criteria.filter(|v| !v.is_null()) {
                None => vec![],
                Some(c) => c.as_object().filter(|c| c.keys().all(|k| ["true", "false"].contains(&k.as_str()))).ok_or("Noul criteria may describe true and false")?.values().collect(),
            },
            _ => return Err("Question type must be choice, score or noul".into()),
        };
        if descriptions.iter().any(|v| v.as_str().is_none_or(|s| s.chars().count() > 4096)) {
            return Err("Criterion descriptions must be text of at most 4,096 characters".into());
        }
    }
    Ok(value)
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn accepts_structured_states_and_all_supported_question_types() {
        parse(EXAMPLE).unwrap();
        parse(r#"{"state":{"event":1},"questions":{"a":{"type":"score","criteria":["low","high"]},"b":{"type":"noul"}}}"#).unwrap();
    }
    #[test] fn rejects_text_incomplete_and_ambiguous_requests_before_inference() {
        for text in ["hello", "{", "[]", r#"{"state":"x","questions":{}}"#, r#"{"state":"x","questions":{"a":{"type":"choice","criteria":{"only":"one"}}}}"#, r#"{"state":"x","questions":{"a":{"type":"noul","extra":true}}}"#] { assert!(parse(text).is_err(), "{text}"); }
    }
}
