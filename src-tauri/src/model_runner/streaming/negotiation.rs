//! Per-request wire agreement, not a model conformance/capability assertion.
use crate::serving_protocol::{Feature, RequestProfile};
use serde_json::{json, Value};

pub(super) const VERSION_HEADER: &str = "x-yougori-serving-protocol";
pub(super) const FEATURES_HEADER: &str = "x-yougori-serving-features";

pub(super) struct Contract {
    tools: bool,
    pub(super) stream: bool,
}

impl Contract {
    pub(super) fn new(body: &Value, profile: &RequestProfile) -> Self {
        // Tool-result continuations need the tool-aware route even without new tools.
        let history = body["messages"].as_array().is_some_and(|messages| {
            messages
                .iter()
                .any(|m| m["role"] == "tool" || m.get("tool_calls").is_some())
        });
        Self {
            tools: history || profile.needs().contains(&Feature::ToolSchema),
            stream: body["stream"] == true,
        }
    }

    pub(super) fn features(&self) -> &'static str {
        match (self.stream, self.tools) {
            (true, true) => "stream,tools",
            (true, false) => "stream",
            (false, true) => "json,tools",
            (false, false) => "json",
        }
    }

    pub(super) fn headers(&self) -> String {
        format!(
            "X-Yougori-Serving-Protocol: 1\r\nX-Yougori-Serving-Features: {}\r\n",
            self.features()
        )
    }

    pub(super) fn accept(
        &self,
        version: Option<&str>,
        features: Option<&str>,
    ) -> Result<Value, String> {
        match (version, features) {
            (None, None) if !self.tools => Ok(json!({"version":null,"mode":"legacy","features":[]})),
            (None, None) => Err("Restart this model with the updated engine before using tool-aware chat; the runner has no serving protocol agreement".into()),
            (Some("1"), Some(selected)) if selected == self.features() =>
                Ok(json!({"version":1,"mode":"negotiated","features":selected.split(',').collect::<Vec<_>>()})),
            (Some("1"), _) => Err("The model runner did not acknowledge the requested serving features; restart it with the matching engine".into()),
            _ => Err("Unsupported or malformed model serving protocol; update the engine and restart the model together".into()),
        }
    }
}

pub(super) fn refusal(body: &Value) -> Option<&'static str> {
    match body["error"]["code"].as_str()? {
        "yougori_serving_version" => Some("Model serving versions do not match; update the engine and restart the model together"),
        "yougori_serving_features" => Some("The model runner cannot accept the requested serving features; choose a tool-enabled runner for tool-aware chat"),
        "yougori_serving_request" => Some("The model runner rejected the serving agreement; restart it with the matching engine"),
        _ => None,
    }
}
