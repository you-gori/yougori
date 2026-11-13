//! todowrite: the to-do list for the task, shown to the person as the plan.
use super::{Output, Tool, ToolCtx};
use crate::native::agent::lock;
use crate::protocol::{Event, PlanEntry, PlanStatus, Priority, ToolKind};
use async_trait::async_trait;
use serde_json::{json, Value};

const MAX_ITEMS: usize = 50;

pub struct TodoWrite;

#[async_trait]
impl Tool for TodoWrite {
    fn name(&self) -> &str {
        "todowrite"
    }

    fn description(&self) -> String {
        "Write the to-do list for the current task; it replaces the previous list. Use it for work with three or more \
         steps. Keep exactly one item in_progress while you work, and mark items completed as soon as they are done."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "todos": {
                    "type": "array",
                    "description": "The whole list, in order.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "content": { "type": "string", "description": "What to do, in a few words." },
                            "status": { "type": "string", "enum": ["pending", "in_progress", "completed"] },
                            "priority": { "type": "string", "enum": ["high", "medium", "low"] }
                        },
                        "required": ["content", "status"]
                    }
                }
            },
            "required": ["todos"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Think
    }

    fn title(&self, _args: &Value, _ctx: &ToolCtx<'_>) -> String {
        "Update the to-do list".into()
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let entries = parse(&args)?;
        *lock(&ctx.shared().todos) = entries.clone();
        ctx.shared().events.send(Event::Plan { entries: entries.clone() });
        let working = entries.iter().filter(|e| e.status == PlanStatus::InProgress).count();
        let done = entries.iter().filter(|e| e.status == PlanStatus::Completed).count();
        let mut text = render(&entries);
        text.push_str(&format!("\n({done} of {} done.)", entries.len()));
        if working > 1 {
            text.push_str(" Keep only one item in_progress at a time.");
        }
        Ok(Output { text, title: Some(format!("To-do list: {done} of {} done", entries.len())), bounded: true, ..Output::default() })
    }
}

pub fn render(entries: &[PlanEntry]) -> String {
    if entries.is_empty() {
        return "(The to-do list is empty.)".into();
    }
    entries
        .iter()
        .map(|e| {
            let mark = match e.status {
                PlanStatus::Completed => "[x]",
                PlanStatus::InProgress => "[>]",
                PlanStatus::Pending => "[ ]",
            };
            format!("{mark} {}", e.content)
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// The list from the model's arguments, tolerant of the shapes small models send.
pub fn parse(args: &Value) -> Result<Vec<PlanEntry>, String> {
    let items = ["todos", "items", "tasks", "list"]
        .iter()
        .find_map(|key| match args.get(*key) {
            Some(Value::Array(items)) => Some(items.clone()),
            // Some models send the list as a JSON string.
            Some(Value::String(text)) => serde_json::from_str::<Vec<Value>>(text).ok(),
            _ => None,
        })
        .ok_or("todos is missing: give the whole list as an array of {content, status}.")?;
    if items.len() > MAX_ITEMS {
        return Err(format!("The list has {} items; keep it to {MAX_ITEMS} at most.", items.len()));
    }
    let mut entries = Vec::new();
    for item in items {
        let (content, status, priority) = match &item {
            Value::String(text) => (text.clone(), "pending".to_owned(), None),
            Value::Object(map) => (
                ["content", "text", "task", "title", "description"]
                    .iter()
                    .find_map(|k| map.get(*k).and_then(Value::as_str))
                    .unwrap_or("")
                    .to_owned(),
                map.get("status").and_then(Value::as_str).unwrap_or("pending").to_ascii_lowercase(),
                map.get("priority").and_then(Value::as_str).map(str::to_ascii_lowercase),
            ),
            _ => continue,
        };
        let content = content.trim().to_owned();
        if content.is_empty() {
            continue;
        }
        let (status, content) = match status.as_str() {
            "completed" | "complete" | "done" | "finished" => (PlanStatus::Completed, content),
            "in_progress" | "in-progress" | "inprogress" | "active" | "doing" | "working" => (PlanStatus::InProgress, content),
            "cancelled" | "canceled" | "skipped" => (PlanStatus::Completed, format!("{content} (dropped)")),
            _ => (PlanStatus::Pending, content),
        };
        let priority = match priority.as_deref() {
            Some("high") => Some(Priority::High),
            Some("medium") => Some(Priority::Medium),
            Some("low") => Some(Priority::Low),
            _ => None,
        };
        entries.push(PlanEntry { content, status, priority });
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lists_parse_from_the_shapes_models_send() {
        let entries = parse(&json!({"todos": [
            {"content": "Read the code", "status": "completed"},
            {"content": "Fix it", "status": "in-progress", "priority": "high"},
            {"text": "Test", "status": "todo"},
            {"content": "Old idea", "status": "cancelled"},
            "Write docs",
            {"content": "  ", "status": "pending"}
        ]}))
        .unwrap();
        let statuses: Vec<PlanStatus> = entries.iter().map(|e| e.status).collect();
        assert_eq!(
            statuses,
            vec![PlanStatus::Completed, PlanStatus::InProgress, PlanStatus::Pending, PlanStatus::Completed, PlanStatus::Pending]
        );
        assert_eq!(entries[1].priority, Some(Priority::High));
        assert_eq!(entries[3].content, "Old idea (dropped)");
        assert_eq!(render(&entries[..2]), "[x] Read the code\n[>] Fix it");
        let from_string = parse(&json!({"todos": "[{\"content\": \"A\", \"status\": \"pending\"}]"})).unwrap();
        assert_eq!(from_string.len(), 1);
        assert!(parse(&json!({})).is_err());
    }
}
