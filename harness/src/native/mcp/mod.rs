//! The MCP client. Servers come from the spec: a command run over stdio (newline-delimited
//! JSON-RPC 2.0, spawned with only its own environment, stderr kept for errors) or a Streamable
//! HTTP endpoint (POST, JSON or SSE answers, Mcp-Session-Id).
//!
//! A server with at most 12 tools offers them directly as `<server>_<tool>`. A larger one is
//! reached through three small tools instead (mcp_search, mcp_schema, mcp_call), so dozens of
//! schemas do not fill a 32K context.
mod http;
mod rpc;

use self::http::{HttpError, HttpPeer};
use self::rpc::{Peer, Tail};
use super::agent::lock;
use super::cancel::Cancel;
use super::events::Events;
use super::permissions::Subject;
use super::tools::{required, text_arg, Output, Tool, ToolCtx};
use super::util;
use crate::protocol::{Event, Level, Progress, ToolContent, ToolKind};
use crate::spec::McpServer;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const PROTOCOL_VERSION: &str = "2025-06-18";
/// Servers with more tools than this are reached through mcp_search / mcp_schema / mcp_call.
pub const DIRECT_LIMIT: usize = 12;
/// Starting a server may first download it.
const START: Duration = Duration::from_secs(60);
const LIST: Duration = Duration::from_secs(30);
const CALL: Duration = Duration::from_secs(600);
const DESCRIPTION: usize = 600;

#[derive(Clone, Debug, PartialEq)]
pub struct ToolInfo {
    pub name: String,
    pub description: String,
    pub schema: Value,
}

// One link per server, so the size of its variants does not matter.
#[allow(clippy::large_enum_variant)]
enum Link {
    Stdio { peer: Peer, child: Mutex<Option<tokio::process::Child>> },
    Http(HttpPeer),
}

pub struct Server {
    pub name: String,
    link: Link,
    instructions: Mutex<String>,
    tools: Mutex<Vec<ToolInfo>>,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Link::Stdio { child, .. } = &self.link {
            if let Some(pid) = lock(child).as_ref().and_then(|c| c.id()) {
                super::tools::bash::kill_tree(pid);
            }
        }
    }
}

/// `command` found on the environment's PATH (or this process's), as the child will need it.
fn find_program(command: &str, env: &BTreeMap<String, String>) -> PathBuf {
    if command.contains('/') || command.contains('\\') {
        return PathBuf::from(command);
    }
    let path = env.get("PATH").cloned().or_else(|| std::env::var("PATH").ok()).unwrap_or_default();
    let extensions: Vec<String> = if cfg!(windows) {
        let pathext = env.get("PATHEXT").cloned().or_else(|| std::env::var("PATHEXT").ok()).unwrap_or(".EXE;.CMD;.BAT".into());
        std::iter::once(String::new()).chain(pathext.split(';').map(|e| e.to_ascii_lowercase())).collect()
    } else {
        vec![String::new()]
    };
    for folder in std::env::split_paths(&path) {
        for extension in &extensions {
            let candidate = folder.join(format!("{command}{extension}"));
            if candidate.is_file() {
                return candidate;
            }
        }
    }
    PathBuf::from(command)
}

impl Server {
    /// Starts a server, introduces this client and lists its tools.
    pub async fn start(config: &McpServer, cwd: &Path, env: &BTreeMap<String, String>) -> Result<Server, String> {
        let server = match config.url.as_deref().map(str::trim).filter(|u| !u.is_empty()) {
            Some(url) => {
                let client = super::tools::web::client(env)?;
                Server::over_http(&config.name, url, client)
            }
            None if !config.command.is_empty() => Server::over_stdio(config, cwd, env)?,
            None => return Err("it has neither a command nor a url".into()),
        };
        server.handshake(None).await?;
        server.list(None).await?;
        Ok(server)
    }

    fn over_http(name: &str, url: &str, client: reqwest::Client) -> Server {
        Server {
            name: name.to_owned(),
            link: Link::Http(HttpPeer::new(name, url, client)),
            instructions: Mutex::new(String::new()),
            tools: Mutex::new(Vec::new()),
        }
    }

    fn over_stdio(config: &McpServer, cwd: &Path, base: &BTreeMap<String, String>) -> Result<Server, String> {
        // The server's environment is its own; none given means the engine's.
        let env = if config.env.is_empty() { base.clone() } else { config.env.clone() };
        let program = find_program(&config.command[0], &env);
        let mut command = tokio::process::Command::new(&program);
        command
            .args(&config.command[1..])
            .env_clear()
            .envs(&env)
            .current_dir(cwd)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(unix)]
        command.process_group(0);
        #[cfg(windows)]
        command.creation_flags(0x0800_0000);
        let mut child = command.spawn().map_err(|e| format!("{} could not start: {e}", config.command[0]))?;
        let (Some(stdin), Some(stdout), Some(stderr)) = (child.stdin.take(), child.stdout.take(), child.stderr.take()) else {
            return Err("its pipes could not be opened".into());
        };
        let tail = Arc::new(Mutex::new(Tail::default()));
        let keep = tail.clone();
        // Read stderr to its end whatever it holds, so the server never blocks on a full pipe.
        tokio::spawn(async move {
            use tokio::io::AsyncBufReadExt;
            let mut reader = tokio::io::BufReader::new(stderr);
            let mut line = Vec::new();
            loop {
                line.clear();
                match reader.read_until(b'\n', &mut line).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => lock(&keep).push(String::from_utf8_lossy(&line).into_owned()),
                }
                if line.len() > 1 << 20 {
                    line = Vec::new();
                }
            }
        });
        Ok(Server::with_peer(&config.name, Peer::start(&config.name, stdout, stdin, tail), Some(child)))
    }

    fn with_peer(name: &str, peer: Peer, child: Option<tokio::process::Child>) -> Server {
        Server {
            name: name.to_owned(),
            link: Link::Stdio { peer, child: Mutex::new(child) },
            instructions: Mutex::new(String::new()),
            tools: Mutex::new(Vec::new()),
        }
    }

    async fn raw(&self, method: &str, params: Value, wait: Duration, cancel: Option<&Cancel>) -> Result<Value, HttpError> {
        match &self.link {
            Link::Stdio { peer, .. } => peer.request(method, params, wait, cancel).await.map_err(HttpError::Other),
            Link::Http(peer) => peer.request(method, params, wait, cancel).await,
        }
    }

    async fn request(&self, method: &str, params: Value, wait: Duration, cancel: Option<&Cancel>) -> Result<Value, String> {
        match self.raw(method, params.clone(), wait, cancel).await {
            Ok(value) => Ok(value),
            Err(HttpError::Expired) => {
                // The server forgot the session: introduce ourselves again, then ask once more.
                if let Link::Http(peer) = &self.link {
                    peer.reset();
                }
                self.handshake(cancel).await?;
                self.raw(method, params, wait, cancel).await.map_err(HttpError::text)
            }
            Err(error) => Err(error.text()),
        }
    }

    async fn notify(&self, method: &str, params: Value) -> Result<(), String> {
        match &self.link {
            Link::Stdio { peer, .. } => peer.notify(method, params).await,
            Link::Http(peer) => peer.notify(method, params).await,
        }
    }

    async fn handshake(&self, cancel: Option<&Cancel>) -> Result<(), String> {
        let params = json!({
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": { "name": "yougori", "title": "Yougori", "version": env!("CARGO_PKG_VERSION") },
        });
        let result = self.raw("initialize", params, START, cancel).await.map_err(HttpError::text)?;
        let version = result.get("protocolVersion").and_then(Value::as_str).unwrap_or(PROTOCOL_VERSION);
        if let Link::Http(peer) = &self.link {
            peer.set_version(version);
        }
        if let Some(text) = result.get("instructions").and_then(Value::as_str) {
            *lock(&self.instructions) = text.trim().to_owned();
        }
        self.notify("notifications/initialized", Value::Null).await
    }

    /// Lists the server's tools, every page of them; a cancel stops the wait for an answer.
    pub async fn list(&self, cancel: Option<&Cancel>) -> Result<(), String> {
        let mut tools = Vec::new();
        let mut cursor: Option<String> = None;
        for _ in 0..100 {
            let params = match &cursor {
                Some(cursor) => json!({ "cursor": cursor }),
                None => json!({}),
            };
            let result = self.request("tools/list", params, LIST, cancel).await?;
            for item in result.get("tools").and_then(Value::as_array).into_iter().flatten() {
                let Some(name) = item.get("name").and_then(Value::as_str).filter(|n| !n.trim().is_empty()) else { continue };
                tools.push(ToolInfo {
                    name: name.to_owned(),
                    description: item.get("description").and_then(Value::as_str).unwrap_or("").trim().to_owned(),
                    schema: clean_schema(item.get("inputSchema")),
                });
            }
            match result.get("nextCursor").and_then(Value::as_str).filter(|c| !c.is_empty()) {
                Some(next) if tools.len() < 5000 => cursor = Some(next.to_owned()),
                _ => break,
            }
        }
        *lock(&self.tools) = tools;
        Ok(())
    }

    pub fn tools(&self) -> Vec<ToolInfo> {
        lock(&self.tools).clone()
    }

    fn change_flag(&self) -> &std::sync::atomic::AtomicBool {
        match &self.link {
            Link::Stdio { peer, .. } => &peer.changed,
            Link::Http(peer) => &peer.changed,
        }
    }

    /// Whether the server said its tools changed since the last look (the flag is cleared).
    fn changed(&self) -> bool {
        self.change_flag().swap(false, Ordering::SeqCst)
    }

    /// Calls a tool; its text and whether the server said it failed.
    pub async fn call(&self, tool: &str, arguments: Value, cancel: &Cancel) -> Result<(String, bool), String> {
        let result = self.request("tools/call", json!({ "name": tool, "arguments": arguments }), CALL, Some(cancel)).await?;
        Ok(render(&result))
    }

    pub async fn close(&self) {
        match &self.link {
            Link::Stdio { peer, child } => {
                peer.close_input().await;
                let child = lock(child).take();
                if let Some(mut child) = child {
                    if tokio::time::timeout(Duration::from_secs(2), child.wait()).await.is_err() {
                        if let Some(pid) = child.id() {
                            super::tools::bash::kill_tree(pid);
                        }
                        let _ = child.kill().await;
                    }
                }
            }
            Link::Http(peer) => peer.close().await,
        }
    }
}

/// An input schema as small models and strict servers take it: an object, without `$schema`.
fn clean_schema(schema: Option<&Value>) -> Value {
    let mut schema = match schema {
        Some(Value::Object(map)) => Value::Object(map.clone()),
        _ => json!({ "type": "object", "properties": {} }),
    };
    if let Some(map) = schema.as_object_mut() {
        map.remove("$schema");
        map.entry("type").or_insert_with(|| json!("object"));
        if map.get("type") == Some(&json!("object")) {
            map.entry("properties").or_insert_with(|| json!({}));
        }
    }
    schema
}

/// A tool result as text: text parts joined, other parts named.
fn render(result: &Value) -> (String, bool) {
    let failed = result.get("isError").and_then(Value::as_bool).unwrap_or(false);
    let mut parts = Vec::new();
    for item in result.get("content").and_then(Value::as_array).into_iter().flatten() {
        let kind = item.get("type").and_then(Value::as_str).unwrap_or("");
        let part = match kind {
            "text" => item.get("text").and_then(Value::as_str).unwrap_or("").to_owned(),
            "image" | "audio" => format!(
                "[{kind}: {}, {} KB]",
                item.get("mimeType").and_then(Value::as_str).unwrap_or("unknown type"),
                item.get("data").and_then(Value::as_str).map(|d| d.len() * 3 / 4 / 1024).unwrap_or(0)
            ),
            "resource" => {
                let resource = &item["resource"];
                match resource.get("text").and_then(Value::as_str) {
                    Some(text) => text.to_owned(),
                    None => format!("[resource {}]", resource.get("uri").and_then(Value::as_str).unwrap_or("")),
                }
            }
            "resource_link" => format!(
                "[link {}: {}]",
                item.get("name").and_then(Value::as_str).unwrap_or(""),
                item.get("uri").and_then(Value::as_str).unwrap_or("")
            ),
            _ => item.to_string(),
        };
        parts.push(part);
    }
    if parts.is_empty() {
        if let Some(structured) = result.get("structuredContent").filter(|s| !s.is_null()) {
            parts.push(serde_json::to_string_pretty(structured).unwrap_or_default());
        }
    }
    let text = parts.join("\n");
    (if text.trim().is_empty() { "(no output)".into() } else { text }, failed)
}

/// A name the relay accepts: letters, digits, `_` and `-`, at most 64 characters.
fn tool_name(server: &str, tool: &str) -> String {
    let joined = format!("{server}_{tool}");
    let clean: String = joined.chars().map(|c| if c.is_ascii_alphanumeric() || c == '_' || c == '-' { c } else { '_' }).collect();
    clean.chars().take(64).collect()
}

#[derive(Default)]
pub struct Mcp {
    servers: Vec<Arc<Server>>,
}

impl Mcp {
    /// Starts every server at once; one that fails is left out with a notice.
    pub async fn connect(configs: &[McpServer], cwd: &Path, env: &BTreeMap<String, String>, events: &Events) -> Mcp {
        if configs.is_empty() {
            return Mcp::default();
        }
        let total = configs.len() as u64;
        events.send(Event::Progress(Progress {
            id: "mcp-start".into(),
            label: "Starting MCP servers".into(),
            done: Some(0),
            total: Some(total),
            unit: Some("servers".into()),
            finished: false,
        }));
        let starts = configs.iter().map(|config| async move {
            let started = tokio::time::timeout(START + Duration::from_secs(15), Server::start(config, cwd, env)).await;
            (config.name.clone(), started)
        });
        let mut servers = Vec::new();
        for (name, started) in futures::future::join_all(starts).await {
            match started {
                Ok(Ok(server)) => servers.push(Arc::new(server)),
                Ok(Err(error)) => events.notice(Level::Warn, format!("The MCP server {name} is not available: {error}")),
                Err(_) => events.notice(Level::Warn, format!("The MCP server {name} did not start within {} s.", START.as_secs() + 15)),
            }
        }
        events.send(Event::Progress(Progress {
            id: "mcp-start".into(),
            label: format!("{} of {total} MCP servers ready", servers.len()),
            done: Some(servers.len() as u64),
            total: Some(total),
            unit: Some("servers".into()),
            finished: true,
        }));
        Mcp { servers }
    }

    #[cfg(test)]
    pub fn with(servers: Vec<Server>) -> Mcp {
        Mcp { servers: servers.into_iter().map(Arc::new).collect() }
    }

    pub fn instructions(&self) -> Vec<(String, String)> {
        self.servers.iter().map(|s| (s.name.clone(), lock(&s.instructions).clone())).collect()
    }

    /// Lists again the tools of servers that said their tools changed. The turn's cancel stops
    /// it at once; what was not listed then is listed at the next prompt.
    pub async fn refresh(&self, events: &Events, cancel: &Cancel) {
        for server in &self.servers {
            if cancel.is_cancelled() {
                return;
            }
            if server.changed() {
                match server.list(Some(cancel)).await {
                    Ok(()) => {}
                    Err(_) if cancel.is_cancelled() => {
                        server.change_flag().store(true, Ordering::SeqCst);
                        return;
                    }
                    Err(error) => {
                        events.notice(Level::Warn, format!("The tools of the MCP server {} could not be listed again: {error}", server.name))
                    }
                }
            }
        }
    }

    /// The tools to offer: each small server's own, and the three search tools for large ones.
    pub fn tools(&self) -> Vec<Arc<dyn Tool>> {
        let mut out: Vec<Arc<dyn Tool>> = Vec::new();
        let mut taken: Vec<String> = Vec::new();
        let mut large = Vec::new();
        for server in &self.servers {
            let tools = server.tools();
            if tools.len() > DIRECT_LIMIT {
                large.push(server.clone());
                continue;
            }
            for info in tools {
                let mut name = tool_name(&server.name, &info.name);
                let base = name.clone();
                let mut number = 2;
                while taken.contains(&name) || matches!(name.as_str(), "mcp_search" | "mcp_schema" | "mcp_call") {
                    let suffix = format!("_{number}");
                    name = format!("{}{suffix}", base.chars().take(64 - suffix.len()).collect::<String>());
                    number += 1;
                }
                taken.push(name.clone());
                out.push(Arc::new(McpTool { server: server.clone(), info, name }));
            }
        }
        if !large.is_empty() {
            out.push(Arc::new(McpSearch { servers: large.clone() }));
            out.push(Arc::new(McpSchema { servers: large.clone() }));
            out.push(Arc::new(McpCall { servers: large }));
        }
        out
    }

    pub async fn close(&self) {
        futures::future::join_all(self.servers.iter().map(|s| s.close())).await;
    }
}

/// One small server's tool, offered as it is.
struct McpTool {
    server: Arc<Server>,
    info: ToolInfo,
    name: String,
}

#[async_trait]
impl Tool for McpTool {
    fn name(&self) -> &str {
        &self.name
    }

    fn description(&self) -> String {
        let text = if self.info.description.is_empty() { format!("The {} tool", self.info.name) } else { self.info.description.clone() };
        format!("{} (MCP server {})", util::cut(&text, DESCRIPTION), self.server.name)
    }

    fn parameters(&self) -> Value {
        self.info.schema.clone()
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Other
    }

    fn title(&self, _args: &Value, _ctx: &ToolCtx<'_>) -> String {
        format!("{}: {}", self.server.name, self.info.name)
    }

    fn subjects(&self, _args: &Value, _ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        Ok(vec![Subject::new(&self.name, self.name.clone(), "*")])
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let (text, failed) = self.server.call(&self.info.name, args, ctx.cancel()).await?;
        Ok(Output { content: vec![ToolContent::Text { text: util::cut(&text, 2000).to_owned() }], text, failed, ..Output::default() })
    }
}

/// Finds a large server's tool by `server/tool`, `server_tool` or a name only one server has.
fn resolve(servers: &[Arc<Server>], wanted: &str) -> Result<(Arc<Server>, ToolInfo), String> {
    let wanted = wanted.trim();
    for server in servers {
        for info in server.tools() {
            let names = [
                format!("{}/{}", server.name, info.name),
                format!("{}.{}", server.name, info.name),
                tool_name(&server.name, &info.name),
            ];
            if names.iter().any(|n| n == wanted) {
                return Ok((server.clone(), info));
            }
        }
    }
    let mut found: Vec<(Arc<Server>, ToolInfo)> = Vec::new();
    for server in servers {
        for info in server.tools() {
            if info.name == wanted {
                found.push((server.clone(), info));
            }
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(format!("There is no MCP tool named {wanted}. Find tools with mcp_search.")),
        _ => Err(format!("Several servers have a tool named {wanted}; name it as server/tool.")),
    }
}

struct McpSearch {
    servers: Vec<Arc<Server>>,
}

#[async_trait]
impl Tool for McpSearch {
    fn name(&self) -> &str {
        "mcp_search"
    }

    fn description(&self) -> String {
        let names: Vec<&str> = self.servers.iter().map(|s| s.name.as_str()).collect();
        format!(
            "Search the tools of the MCP servers {} by words. Returns tool names (server/tool) with one line each. Then \
             get a tool's arguments with mcp_schema and call it with mcp_call.",
            names.join(", ")
        )
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "query": { "type": "string", "description": "Words for what the tool should do." } },
            "required": ["query"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Search
    }

    fn title(&self, args: &Value, _ctx: &ToolCtx<'_>) -> String {
        format!("Search MCP tools: {}", util::one_line(&text_arg(args, &["query", "q"]).unwrap_or_default(), 60))
    }

    async fn run(&self, args: Value, _ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let query = text_arg(&args, &["query", "q", "search"]).unwrap_or_default().to_lowercase();
        let words: Vec<&str> = query.split(|c: char| !c.is_alphanumeric()).filter(|w| !w.is_empty()).collect();
        let mut scored: Vec<(usize, String)> = Vec::new();
        for server in &self.servers {
            for info in server.tools() {
                let name = info.name.to_lowercase();
                let description = info.description.to_lowercase();
                let score: usize = words.iter().map(|w| if name.contains(w) { 3 } else if description.contains(w) { 1 } else { 0 }).sum();
                if score > 0 || words.is_empty() {
                    let line = util::one_line(info.description.split(['\n', '.']).next().unwrap_or(""), 120);
                    scored.push((score, format!("{}/{}: {line}", server.name, info.name)));
                }
            }
        }
        scored.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
        let total = scored.len();
        let lines: Vec<String> = scored.into_iter().take(15).map(|(_, line)| line).collect();
        let mut text = if lines.is_empty() { format!("No MCP tool matches {query}. Try other words.") } else { lines.join("\n") };
        if total > 15 {
            text.push_str(&format!("\n({total} tools match; use more specific words to see others.)"));
        }
        Ok(Output { text, bounded: true, ..Output::default() })
    }
}

struct McpSchema {
    servers: Vec<Arc<Server>>,
}

#[async_trait]
impl Tool for McpSchema {
    fn name(&self) -> &str {
        "mcp_schema"
    }

    fn description(&self) -> String {
        "Show what an MCP tool found with mcp_search does and the arguments it takes (a JSON schema).".into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": { "name": { "type": "string", "description": "The tool as server/tool." } },
            "required": ["name"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Search
    }

    fn title(&self, args: &Value, _ctx: &ToolCtx<'_>) -> String {
        format!("MCP tool {}", text_arg(args, &["name", "tool"]).unwrap_or_default())
    }

    async fn run(&self, args: Value, _ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let (server, info) = resolve(&self.servers, &required(&args, &["name", "tool"])?)?;
        let schema = serde_json::to_string_pretty(&info.schema).unwrap_or_default();
        Ok(Output::text(format!(
            "{}/{}: {}\n\nArguments (JSON schema):\n{schema}\n\nCall it with mcp_call, name \"{}/{}\".",
            server.name, info.name, info.description, server.name, info.name
        )))
    }
}

struct McpCall {
    servers: Vec<Arc<Server>>,
}

#[async_trait]
impl Tool for McpCall {
    fn name(&self) -> &str {
        "mcp_call"
    }

    fn description(&self) -> String {
        "Call an MCP tool found with mcp_search, with the arguments mcp_schema showed.".into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "name": { "type": "string", "description": "The tool as server/tool." },
                "arguments": { "type": "object", "description": "The tool's arguments." }
            },
            "required": ["name", "arguments"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Other
    }

    fn title(&self, args: &Value, _ctx: &ToolCtx<'_>) -> String {
        format!("MCP {}", text_arg(args, &["name", "tool"]).unwrap_or_default())
    }

    fn subjects(&self, args: &Value, _ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        let (server, info) = resolve(&self.servers, &required(args, &["name", "tool"])?)?;
        let name = tool_name(&server.name, &info.name);
        Ok(vec![Subject::new(&name, name.clone(), "*")])
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let (server, info) = resolve(&self.servers, &required(&args, &["name", "tool"])?)?;
        let arguments = match args.get("arguments").or_else(|| args.get("args")) {
            Some(Value::String(text)) => serde_json::from_str(text).map_err(|_| "arguments must be a JSON object.".to_owned())?,
            Some(Value::Object(map)) => Value::Object(map.clone()),
            None | Some(Value::Null) => json!({}),
            Some(_) => return Err("arguments must be a JSON object.".into()),
        };
        let (text, failed) = server.call(&info.name, arguments, ctx.cancel()).await?;
        Ok(Output { content: vec![ToolContent::Text { text: util::cut(&text, 2000).to_owned() }], text, failed, ..Output::default() })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::native::testutil::{FakeServer, Reply};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// A fake MCP server on in-memory pipes: `tools` tools over two pages, an echo tool, a
    /// tool that never answers, and a ping sent to the client.
    pub fn piped_server(name: &str, tools: usize) -> Server {
        let (client_out, server_in) = tokio::io::duplex(1 << 16);
        let (server_out, client_in) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut lines = BufReader::new(server_in).lines();
            let mut out = server_out;
            while let Ok(Some(line)) = lines.next_line().await {
                let message: Value = serde_json::from_str(&line).unwrap();
                let id = message.get("id").cloned();
                let method = message.get("method").and_then(Value::as_str).unwrap_or("").to_owned();
                let result = match method.as_str() {
                    "initialize" => {
                        // The server pings the client before it answers.
                        out.write_all(b"{\"jsonrpc\":\"2.0\",\"id\":\"s1\",\"method\":\"ping\"}\n").await.unwrap();
                        json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {}}, "serverInfo": {"name": "fake"}, "instructions": "Use echo to repeat."})
                    }
                    "tools/list" => {
                        let page = message["params"]["cursor"].as_str().map(|_| 1).unwrap_or(0);
                        let all: Vec<Value> = (0..tools)
                            .map(|n| json!({"name": if n == 0 { "echo".to_owned() } else if n == 1 { "hang".to_owned() } else { format!("tool{n}") }, "description": format!("Tool number {n}. More."), "inputSchema": {"$schema": "x", "type": "object", "properties": {"text": {"type": "string"}}}}))
                            .collect();
                        let half = all.len().div_ceil(2);
                        if page == 0 {
                            json!({"tools": all[..half], "nextCursor": "page2"})
                        } else {
                            json!({"tools": all[half..]})
                        }
                    }
                    "tools/call" => match message["params"]["name"].as_str() {
                        Some("echo") => json!({"content": [{"type": "text", "text": format!("echo: {}", message["params"]["arguments"]["text"].as_str().unwrap_or(""))}]}),
                        Some("hang") => continue,
                        _ => json!({"content": [{"type": "text", "text": "bad"}], "isError": true}),
                    },
                    _ => continue,
                };
                if let Some(id) = id {
                    let reply = json!({"jsonrpc": "2.0", "id": id, "result": result});
                    out.write_all(format!("{reply}\n").as_bytes()).await.unwrap();
                }
            }
        });
        let tail = Arc::new(Mutex::new(Tail::default()));
        Server::with_peer(name, Peer::start(name, client_in, client_out, tail), None)
    }

    /// A piped server, introduced and listed.
    pub async fn ready_server(name: &str, tools: usize) -> Server {
        let server = piped_server(name, tools);
        server.handshake(None).await.unwrap();
        server.list(None).await.unwrap();
        server
    }

    /// A piped server, introduced and listed, that then says its tools changed and never
    /// answers tools/list again.
    pub async fn changed_then_silent(name: &str) -> Server {
        let (client_out, server_in) = tokio::io::duplex(1 << 16);
        let (server_out, client_in) = tokio::io::duplex(1 << 16);
        tokio::spawn(async move {
            let mut lines = BufReader::new(server_in).lines();
            let mut out = server_out;
            let mut listed = false;
            while let Ok(Some(line)) = lines.next_line().await {
                let message: Value = serde_json::from_str(&line).unwrap();
                let id = message.get("id").cloned();
                let result = match message.get("method").and_then(Value::as_str).unwrap_or("") {
                    "initialize" => json!({"protocolVersion": "2025-06-18", "capabilities": {"tools": {"listChanged": true}}}),
                    "tools/list" if !listed => json!({"tools": [{"name": "echo", "inputSchema": {"type": "object"}}]}),
                    _ => continue,
                };
                if let Some(id) = id {
                    out.write_all(format!("{}\n", json!({"jsonrpc": "2.0", "id": id, "result": result})).as_bytes()).await.unwrap();
                }
                if !listed && result.get("tools").is_some() {
                    listed = true;
                    out.write_all(b"{\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n").await.unwrap();
                }
            }
        });
        let tail = Arc::new(Mutex::new(Tail::default()));
        let server = Server::with_peer(name, Peer::start(name, client_in, client_out, tail), None);
        server.handshake(None).await.unwrap();
        server.list(None).await.unwrap();
        for _ in 0..200 {
            if server.change_flag().load(Ordering::SeqCst) {
                return server;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the server's change notice never came");
    }

    #[tokio::test]
    async fn a_stop_ends_listing_changed_tools_at_once_and_they_are_listed_next_time() {
        let mcp = Mcp::with(vec![changed_then_silent("slow").await]);
        let (sender, mut screen) = tokio::sync::mpsc::unbounded_channel();
        let events = Events::new(sender);
        let cancel = Cancel::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            trigger.cancel();
        });
        let started = std::time::Instant::now();
        mcp.refresh(&events, &cancel).await;
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        assert!(screen.try_recv().is_err(), "a stop is no failure to warn about");
        assert!(mcp.servers[0].changed(), "still to be listed again");
        // Without a stop, a server that does not answer gets a warning after its wait.
        mcp.servers[0].change_flag().store(true, Ordering::SeqCst);
        let refreshed = tokio::time::timeout(Duration::from_millis(300), mcp.refresh(&events, &Cancel::new())).await;
        assert!(refreshed.is_err(), "it waits for the answer as long as nobody stops it");
    }

    #[tokio::test]
    async fn stdio_handshake_paging_calls_and_timeouts() {
        let server = piped_server("docs", 5);
        server.handshake(None).await.unwrap();
        server.list(None).await.unwrap();
        let tools = server.tools();
        assert_eq!(tools.len(), 5, "both pages were listed");
        assert!(tools[0].schema.get("$schema").is_none());
        assert_eq!(lock(&server.instructions).as_str(), "Use echo to repeat.");
        let (text, failed) = server.call("echo", json!({"text": "hi"}), &Cancel::new()).await.unwrap();
        assert_eq!((text.as_str(), failed), ("echo: hi", false));
        let (_, failed) = server.call("tool3", json!({}), &Cancel::new()).await.unwrap();
        assert!(failed);
        let error = server.request("tools/call", json!({"name": "hang"}), Duration::from_millis(200), None).await.unwrap_err();
        assert!(error.contains("did not answer tools/call"), "{error}");
        let cancel = Cancel::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            trigger.cancel();
        });
        assert_eq!(server.call("hang", json!({}), &cancel).await.unwrap_err(), "Stopped.");
    }

    #[tokio::test]
    async fn a_server_that_stops_says_so() {
        let (client_out, _server_in) = tokio::io::duplex(1024);
        let (mut server_out, client_in) = tokio::io::duplex(1024);
        let tail = Arc::new(Mutex::new(Tail::default()));
        lock(&tail).push("fatal: missing token".into());
        let peer = Peer::start("gh", client_in, client_out, tail);
        server_out.shutdown().await.unwrap();
        drop(server_out);
        let error = peer.request("tools/list", json!({}), Duration::from_secs(5), None).await.unwrap_err();
        assert!(error.contains("The MCP server gh stopped") && error.contains("missing token"), "{error}");
    }

    #[tokio::test]
    async fn small_servers_offer_their_tools_and_large_ones_three_search_tools() {
        let small = piped_server("docs", 3);
        let large = piped_server("big", 30);
        for server in [&small, &large] {
            server.handshake(None).await.unwrap();
            server.list(None).await.unwrap();
        }
        let mcp = Mcp::with(vec![small, large]);
        let names: Vec<String> = mcp.tools().iter().map(|t| t.name().to_owned()).collect();
        assert_eq!(names, vec!["docs_echo", "docs_hang", "docs_tool2", "mcp_search", "mcp_schema", "mcp_call"]);
        let servers = mcp.servers[1..].to_vec();
        let (server, info) = resolve(&servers, "big/tool7").unwrap();
        assert_eq!((server.name.as_str(), info.name.as_str()), ("big", "tool7"));
        assert!(resolve(&servers, "tool7").is_ok());
        assert!(resolve(&servers, "nope").err().unwrap().contains("mcp_search"));
        assert_eq!(tool_name("my server", "do.it"), "my_server_do_it");
        assert_eq!(
            render(&json!({"content": [{"type": "text", "text": "a"}, {"type": "image", "mimeType": "image/png", "data": "AAAA"}]})).0,
            "a\n[image: image/png, 0 KB]"
        );
    }

    #[tokio::test]
    async fn streamable_http_with_sessions_and_sse_answers() {
        let sessions = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let server = FakeServer::start(move |_, request| {
            let message = request.json();
            let method = message["method"].as_str().unwrap_or("").to_owned();
            let session = request.header("mcp-session-id");
            if request.method == "DELETE" {
                return Reply::empty(200);
            }
            match method.as_str() {
                "initialize" => {
                    assert!(session.is_none(), "a new session starts without the old id");
                    let id = if sessions.fetch_add(1, Ordering::SeqCst) == 0 { "abc" } else { "def" };
                    Reply::json(200, json!({"jsonrpc": "2.0", "id": message["id"], "result": {"protocolVersion": "2025-03-26", "capabilities": {}}}))
                        .header("Mcp-Session-Id", id)
                }
                "notifications/initialized" => {
                    assert!(session.is_some());
                    Reply::empty(202)
                }
                "tools/list" => {
                    assert_eq!(session.as_deref(), Some("abc"));
                    assert_eq!(request.header("mcp-protocol-version").as_deref(), Some("2025-03-26"));
                    let body = format!(
                        "event: message\ndata: {}\n\ndata: {}\n\n",
                        json!({"jsonrpc": "2.0", "method": "notifications/message", "params": {"level": "info"}}),
                        json!({"jsonrpc": "2.0", "id": message["id"], "result": {"tools": [{"name": "search", "description": "Find", "inputSchema": {"type": "object"}}]}})
                    );
                    Reply::sse(body.into_bytes())
                }
                "tools/call" if session.as_deref() == Some("abc") => Reply::empty(404),
                "tools/call" => Reply::json(200, json!({"jsonrpc": "2.0", "id": message["id"], "result": {"content": [{"type": "text", "text": "found"}]}})),
                _ => Reply::empty(400),
            }
        })
        .await;
        let config = McpServer { name: "web".into(), command: vec![], env: BTreeMap::new(), url: Some(format!("{}/mcp", server.url)) };
        let started = Server::start(&config, Path::new("."), &BTreeMap::new()).await.unwrap();
        assert_eq!(started.tools()[0].name, "search");
        assert_eq!(started.tools()[0].schema, json!({"type": "object", "properties": {}}));
        // The server forgets the session at the first call: the client starts a new one and asks again.
        let (text, _) = started.call("search", json!({}), &Cancel::new()).await.unwrap();
        assert_eq!(text, "found");
        let methods: Vec<String> = server.requests().iter().map(|r| r.json()["method"].as_str().unwrap_or("").to_owned()).collect();
        assert_eq!(methods, vec!["initialize", "notifications/initialized", "tools/list", "tools/call", "initialize", "notifications/initialized", "tools/call"]);
        started.close().await;
        assert_eq!(server.requests().last().unwrap().method, "DELETE");
    }
}
