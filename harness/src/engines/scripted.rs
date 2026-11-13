//! A scripted engine: replays events from a JSON-lines file, one turn per prompt. Used by the
//! screen's tests and to show the screen without a model (`yougori-harness --script FILE`).
//!
//! The file holds events, one JSON object per line; a line `{"type":"turn"}` ends one turn's
//! events. A permission or question event waits for its answer before the replay goes on.
use crate::protocol::{Command, EngineHandle, Event, StopReason};
use serde_json::Value;
use std::path::Path;

pub fn load(path: &Path) -> anyhow::Result<Vec<Vec<Event>>> {
    let text = std::fs::read_to_string(path)?;
    parse(&text)
}

pub fn parse(text: &str) -> anyhow::Result<Vec<Vec<Event>>> {
    let mut turns = vec![Vec::new()];
    for (number, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("//") {
            continue;
        }
        let value: Value = serde_json::from_str(line).map_err(|e| anyhow::anyhow!("line {}: {e}", number + 1))?;
        if value["type"] == "turn" {
            turns.push(Vec::new());
            continue;
        }
        let event: Event = serde_json::from_value(value).map_err(|e| anyhow::anyhow!("line {}: {e}", number + 1))?;
        turns.last_mut().unwrap().push(event);
    }
    turns.retain(|turn| !turn.is_empty());
    Ok(turns)
}

/// The first turn plays at once (it should hold `Ready`); each prompt plays the next.
pub fn start(turns: Vec<Vec<Event>>) -> EngineHandle {
    let (handle, mut commands, events) = EngineHandle::pair();
    tokio::spawn(async move {
        let mut turns = turns.into_iter();
        if let Some(first) = turns.next() {
            for event in first {
                if events.send(event).is_err() {
                    return;
                }
            }
        }
        while let Some(command) = commands.recv().await {
            match command {
                Command::Prompt { .. } => {
                    let Some(turn) = turns.next() else {
                        let _ = events.send(Event::TurnEnd { reason: StopReason::EndTurn, detail: None });
                        continue;
                    };
                    for event in turn {
                        let waits = matches!(event, Event::Permission(_) | Event::Question(_));
                        if events.send(event).is_err() {
                            return;
                        }
                        if waits {
                            // Wait for the answer (or a cancel) before going on.
                            loop {
                                match commands.recv().await {
                                    Some(Command::Permission { .. } | Command::Answer { .. }) => break,
                                    Some(Command::Cancel) => {
                                        let _ = events.send(Event::TurnEnd { reason: StopReason::Cancelled, detail: None });
                                        break;
                                    }
                                    Some(Command::Shutdown) | None => return,
                                    Some(_) => {}
                                }
                            }
                        }
                    }
                }
                Command::SetModel { model } => {
                    let _ = events.send(Event::Model { model });
                }
                Command::Shutdown => return,
                _ => {}
            }
        }
    });
    handle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn replays_one_turn_per_prompt() {
        let turns = parse(
            r#"{"type":"ready","harness":"yougori","name":"Yougori","model":"m","model_switch":"live"}
{"type":"turn"}
{"type":"message","message":"1","text":"Hi"}
{"type":"turn_end","reason":"end_turn"}"#,
        )
        .unwrap();
        assert_eq!(turns.len(), 2);
        let mut engine = start(turns);
        assert!(matches!(engine.events.recv().await, Some(Event::Ready(_))));
        engine.commands.send(Command::Prompt { text: "hello".into() }).unwrap();
        assert!(matches!(engine.events.recv().await, Some(Event::Message { .. })));
        assert!(matches!(engine.events.recv().await, Some(Event::TurnEnd { .. })));
    }
}
