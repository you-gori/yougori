use crate::projects::secrets;
use serde_json::{json, Value};
pub(crate) const TOKEN_REFERENCE: &str = "huggingface-model-downloads";
pub(crate) fn token() -> Option<String> {
    secrets::resolve(TOKEN_REFERENCE).ok().or_else(|| std::env::var("HF_TOKEN").ok())
        .filter(|value| !value.is_empty() && !value.contains(['\r', '\n', '\0']))
}
#[tauri::command]
pub fn model_huggingface_status() -> Value {
    json!({"configured": token().is_some(), "reference": TOKEN_REFERENCE,
        "tokensUrl": "https://huggingface.co/settings/tokens", "storage": "OS credential vault"})
}
pub(super) fn access_error(status: u16, model: &str) -> String {
    match status {
        401 | 403 => format!("Hugging Face denied access to {model} (HTTP {status}). Accept the model's access conditions at https://huggingface.co/{model}, then run `yougori model auth login` with a read token that can access it, or save it under Hugging Face access in the App. Private models also require permission; check the model ID. No environment was created."),
        404 => format!("Hugging Face model {model} was not found (HTTP 404). Check the model ID and access permissions. No environment was created."),
        429 => "Hugging Face rate-limited model metadata. Save a read token with `yougori model auth login` and retry shortly. No environment was created.".into(),
        _ => format!("Hugging Face model metadata returned HTTP {status}. Retry when the Hub is available. No environment was created."),
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn access_denial_is_actionable_without_claiming_a_missing_model_is_private() {
        for status in [401, 403] {
            let error=access_error(status,"superagent-ai/security-one-27b");
            assert!(error.contains("https://huggingface.co/superagent-ai/security-one-27b"));
            assert!(error.contains("model auth login"));
        }
        assert!(access_error(404,"test/missing").contains("not found"));
        assert!(access_error(429,"test/model").contains("rate-limited"));
    }
}
