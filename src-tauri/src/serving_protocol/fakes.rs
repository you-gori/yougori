//! Test fakes: an executor that records what it was given, and a stand-in for a live
//! runner.

use super::conformance::{ConformanceCase, RecordedFrame, RecordedResponse};
use super::validation::{ToolExecutor, ValidatedToolCall};

/// Records every call it is asked to run, as `(call_id, name, arguments JSON)`.
#[derive(Debug, Default)]
pub struct RecordingExecutor {
    pub executed: Vec<(String, String, String)>,
}

impl ToolExecutor for RecordingExecutor {
    fn execute(&mut self, call: &ValidatedToolCall) {
        self.executed.push((
            call.call_id().to_owned(),
            call.name().to_owned(),
            serde_json::Value::Object(call.arguments().clone()).to_string(),
        ));
    }
}

/// A fake runner's answer to `case`'s request: the response the case recorded, as the
/// raw event text the host captures from the wire. Only tests answer this way; the live
/// harness itself never reads a case's recording.
pub fn served(case: &ConformanceCase) -> RecordedResponse {
    RecordedResponse {
        frames: case
            .response
            .frames
            .iter()
            .map(|frame| RecordedFrame {
                event: frame.event.clone(),
                data: None,
                data_text: Some(frame.to_sse().unwrap().data),
            })
            .collect(),
        ..case.response.clone()
    }
}
