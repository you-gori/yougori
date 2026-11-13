//! question: asks the person and waits for their answer.
use super::{bool_arg, required, Output, Tool, ToolCtx};
use crate::native::util;
use crate::protocol::{QuestionRequest, ToolContent, ToolKind};
use async_trait::async_trait;
use serde_json::{json, Value};

pub struct Question;

#[async_trait]
impl Tool for Question {
    fn name(&self) -> &str {
        "question"
    }

    fn description(&self) -> String {
        "Ask the person a question and wait for the answer. Use it only when you cannot go on without their decision \
         or information. Offer choices when there are clear options; they can also type their own answer."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "question": { "type": "string", "description": "The question, short and clear." },
                "choices": { "type": "array", "items": { "type": "string" }, "description": "Answers to pick from (optional)." },
                "multiple": { "type": "boolean", "description": "Several choices may be picked." }
            },
            "required": ["question"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Other
    }

    fn title(&self, args: &Value, _ctx: &ToolCtx<'_>) -> String {
        format!("Ask: {}", util::one_line(&super::text_arg(args, &["question", "text"]).unwrap_or_default(), 70))
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let question = required(&args, &["question", "text", "prompt"])?;
        let choices: Vec<String> = ["choices", "options"]
            .iter()
            .find_map(|key| args.get(*key).and_then(Value::as_array))
            .map(|items| {
                items
                    .iter()
                    .filter_map(|c| match c {
                        Value::String(text) => Some(text.trim().to_owned()),
                        Value::Object(map) => map.get("label").or_else(|| map.get("text")).and_then(Value::as_str).map(str::to_owned),
                        _ => None,
                    })
                    .filter(|c| !c.is_empty())
                    .take(12)
                    .collect()
            })
            .unwrap_or_default();
        let multiple = bool_arg(&args, &["multiple", "multi"]).unwrap_or(false) && !choices.is_empty();
        let request = QuestionRequest {
            id: util::new_id("q"),
            question: question.trim().to_owned(),
            choices,
            multiple,
            allow_text: true,
        };
        let shared = ctx.shared();
        let answer = shared.broker.question(&shared.events, request, ctx.cancel()).await.map_err(|_| "Stopped.".to_owned())?;
        let text = match answer {
            None => "The person closed the question without answering. Decide yourself if you can, or say what you need.".to_owned(),
            Some(answers) if answers.iter().all(|a| a.trim().is_empty()) => {
                "The person gave an empty answer. Decide yourself if you can, or say what you need.".to_owned()
            }
            Some(answers) => format!("The person answered: {}", answers.join(", ")),
        };
        Ok(Output { content: vec![ToolContent::Text { text: text.clone() }], text, bounded: true, ..Output::default() })
    }
}
