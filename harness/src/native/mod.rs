//! Our own agent engine, Yougori: a terminal coding agent built for open models in small
//! (32K) context windows, speaking to one OpenAI-compatible relay.
//!
//! - `llm`: the streaming relay client (tool-call deltas, reasoning, retries).
//! - `agent`: the loop (steps, stuck guard, cancel, permissions, subagents).
//! - `compaction`: keeping a conversation inside the window.
//! - `tools`: bash, read, write, edit, glob, grep, list, webfetch, todowrite, task, question.
//! - `permissions`, `profiles` (files with a prompt), `prompt` (the system prompt), `store`
//!   (sessions in SQLite), `mcp` (an MCP client), `engine` (commands, turns and sessions).
mod agent;
mod cancel;
mod compaction;
mod conversation;
mod engine;
mod events;
mod html;
mod llm;
mod mcp;
mod permissions;
mod profiles;
mod prompt;
mod shell;
mod sse;
mod store;
mod tools;
mod util;

#[cfg(test)]
mod testutil;

use crate::protocol::EngineHandle;
use crate::spec::EngineSpec;

/// Starts our own agent for the spec: its profile, model, MCP servers and state folder. Fails
/// with a plain message when the spec names a profile the engine does not know.
pub async fn start(spec: &EngineSpec) -> anyhow::Result<EngineHandle> {
    engine::start(spec).await
}
