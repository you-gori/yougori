//! How to start the chosen harness's engine: `engine.json`, written inside the VM by
//! `runtime.py` (profiles.headless) from the harness, model and setup answers, read here.
//!
//! The per-harness knowledge (config files, environment, the headless command) stays in the
//! Python profiles beside the other harness runtime code; this binary starts what the spec says
//! and speaks the spec's protocol.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// The relay every model request goes through inside the VM.
pub const RELAY: &str = "http://127.0.0.1:8080/v1";
/// Not a credential: the relay outside the VM holds the inference's key.
pub const RELAY_KEY: &str = "solver-local-relay";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct EngineSpec {
    /// The chosen harness, such as `opencode`, `strix` or `yougori`.
    pub harness: String,
    /// Its display name.
    pub name: String,
    /// `coding` or `security`.
    #[serde(default = "coding")]
    pub category: String,
    pub protocol: Protocol,
    /// The engine's command (not used by `native`).
    #[serde(default)]
    pub argv: Vec<String>,
    /// The engine's whole environment (nothing else is inherited).
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Secret setup answers the engine gets in its environment: engine variable -> answer id. The
    /// value comes from this process's `YOUGORI_SECRET_<ID>` variable (ID upper-cased), so secrets
    /// are never written into the spec, arguments, logs or reports.
    #[serde(default)]
    pub secret_env: BTreeMap<String, String>,
    /// Where the engine works: the workspace.
    pub cwd: PathBuf,
    pub model: String,
    /// This inference's models, for the model switcher.
    #[serde(default)]
    pub models: Vec<String>,
    #[serde(default)]
    pub model_switch: crate::protocol::ModelSwitch,
    /// A command that prints a new spec for another model (the model id is appended), for engines
    /// that restart to switch models: `["python3", "/opt/solver/runtime.py", "engine", "opencode"]`.
    #[serde(default)]
    pub respec: Vec<String>,
    /// Our own engine's primary profile for `native`: `yougori` (builds and edits) or `plan`.
    #[serde(default)]
    pub profile: Option<String>,
    /// MCP servers our own engine connects to (`native`), or passes to an ACP agent.
    #[serde(default)]
    pub mcp: Vec<McpServer>,
    /// Services started before the engine and stopped after it, in order.
    #[serde(default)]
    pub services: Vec<Service>,
    #[serde(default = "context_window")]
    pub context_window: u32,
    #[serde(default = "max_output")]
    pub max_output: u32,
    #[serde(default = "relay")]
    pub base_url: String,
    #[serde(default = "relay_key")]
    pub api_key: String,
    /// The setup answers (no secrets: those are in `env` only).
    #[serde(default)]
    pub answers: Value,
    /// What the VM can reach besides the inference.
    #[serde(default)]
    pub reach: Reach,
    /// Folder for this harness's own state (sessions, logs), inside the VM's home.
    pub state_dir: PathBuf,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    /// Our own agent engine.
    Native,
    /// Agent Client Protocol over the child's stdio (OpenCode, Kilo, Gemini CLI, Qwen Code,
    /// DeepSeek, and our Python bridges).
    Acp,
    /// Codex's app-server JSON-RPC over stdio.
    CodexAppServer,
    /// Claude Code's `--input-format stream-json --output-format stream-json`.
    ClaudeStreamJson,
    /// Pi's `--mode rpc`.
    PiRpc,
    /// The harness's own interactive terminal client (`argv`), shown in a terminal pane inside
    /// the Yougori screen: for harnesses without a headless interface we can drive.
    Terminal,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct McpServer {
    pub name: String,
    /// stdio: the command; empty for HTTP.
    #[serde(default)]
    pub command: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Streamable HTTP endpoint, when not stdio.
    #[serde(default)]
    pub url: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Service {
    pub name: String,
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    /// The service is ready once this URL answers (any HTTP status).
    #[serde(default)]
    pub ready_url: Option<String>,
    #[serde(default = "ready_seconds")]
    pub ready_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Reach {
    /// `inference`, `sites`, `targets` or `full`.
    #[serde(default = "inference")]
    pub mode: String,
    /// Sites (HTTPS) for `sites`.
    #[serde(default)]
    pub sites: Vec<String>,
    /// Hosts or addresses with ports for `targets`, as the person gave them.
    #[serde(default)]
    pub targets: Vec<String>,
}

impl Default for Reach {
    fn default() -> Self {
        Reach { mode: inference(), sites: Vec::new(), targets: Vec::new() }
    }
}

impl Reach {
    /// Whether the harness may fetch web pages at all (webfetch).
    pub fn web(&self) -> bool {
        self.mode != "inference"
    }
}

fn coding() -> String {
    "coding".into()
}
fn inference() -> String {
    "inference".into()
}
fn context_window() -> u32 {
    32768
}
fn max_output() -> u32 {
    4096
}
fn relay() -> String {
    RELAY.into()
}
fn relay_key() -> String {
    RELAY_KEY.into()
}
fn ready_seconds() -> u64 {
    120
}

/// The value of a secret setup answer, from `YOUGORI_SECRET_<ID>`.
pub fn secret(id: &str) -> Option<String> {
    std::env::var(format!("YOUGORI_SECRET_{}", id.to_ascii_uppercase())).ok().filter(|v| !v.is_empty())
}

/// Every secret setup answer this process holds, to mask them in what the screen shows.
pub fn secrets() -> Vec<String> {
    std::env::vars()
        .filter(|(name, value)| name.starts_with("YOUGORI_SECRET_") && value.chars().count() >= 4)
        .map(|(_, value)| value)
        .collect()
}

impl EngineSpec {
    /// The engine's environment with its secrets filled in.
    pub fn environment(&self) -> BTreeMap<String, String> {
        let mut env = self.env.clone();
        for (name, id) in &self.secret_env {
            if let Some(value) = secret(id) {
                env.insert(name.clone(), value);
            }
        }
        env
    }

    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let raw = std::fs::read(path).map_err(|e| anyhow::anyhow!("Cannot read the engine spec {}: {e}", path.display()))?;
        let spec: EngineSpec = serde_json::from_slice(&raw).map_err(|e| anyhow::anyhow!("Invalid engine spec: {e}"))?;
        spec.check()?;
        Ok(spec)
    }

    pub fn check(&self) -> anyhow::Result<()> {
        if self.harness.is_empty() || self.model.is_empty() {
            anyhow::bail!("The engine spec names no harness or model.");
        }
        if self.protocol != Protocol::Native && self.argv.is_empty() {
            anyhow::bail!("The engine spec has no command for {}.", self.harness);
        }
        if self.protocol == Protocol::Native && self.profile.is_none() {
            anyhow::bail!("The engine spec has no profile for our own engine.");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_minimal_spec_takes_the_defaults() {
        let spec: EngineSpec = serde_json::from_str(
            r#"{"harness":"opencode","name":"OpenCode","protocol":"acp","argv":["opencode","acp"],
                "cwd":"/workspace","model":"m","state_dir":"/home/node/.yougori"}"#,
        )
        .unwrap();
        spec.check().unwrap();
        assert_eq!((spec.context_window, spec.max_output), (32768, 4096));
        assert_eq!(spec.base_url, RELAY);
        assert_eq!(spec.reach.mode, "inference");
        assert!(!spec.reach.web());
        let native: EngineSpec = serde_json::from_str(
            r#"{"harness":"yougori","name":"Yougori","protocol":"native","cwd":"/workspace","model":"m","state_dir":"/s"}"#,
        )
        .unwrap();
        assert!(native.check().is_err(), "native needs a profile");
    }
}
