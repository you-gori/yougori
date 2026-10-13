//! Runs an accepted bounty's uploaded project as a live service the worker's model attacks over
//! the network. The publisher is vetted by the operator before a bounty is published, and the
//! participant chose to accept it; the project runs on the participant's own machine, in a fresh
//! temporary folder, as a child process killed on teardown. The model reaches it only through the
//! http_request tool the runtime proxies here, so it can probe the service but nothing else.
use serde_json::Value;
use std::{path::PathBuf, process::Stdio, time::Duration};
use tokio::io::AsyncWriteExt;

/// What a live-target bounty supplies for the runtime to start the service.
pub(super) struct Spec {
    /// Project files as (relative path, bytes), from the accepted source snapshot.
    pub files: Vec<(String, Vec<u8>)>,
    /// Optional one-off preparation (for example installing dependencies).
    pub setup: Option<String>,
    /// The command that starts the service in the foreground.
    pub start: String,
    /// The port the service listens on, as the publisher declared it.
    pub port: u16,
    /// A path that answers once the service is ready (default `/`).
    pub health: String,
}

/// A started live target: its working folder, the running process and a client scoped to it.
pub(super) struct Service {
    dir: PathBuf,
    child: tokio::process::Child,
    base: String,
    client: reqwest::Client,
}

/// How much of a response body the model is shown, in bytes.
const RESPONSE_CLIP: usize = 2000;
/// How long preparation (dependency install) may run.
const SETUP_SECONDS: u64 = 600;
/// How long to wait for the service to answer its health check.
const HEALTH_SECONDS: u64 = 60;

impl Service {
    /// Writes the project, runs its setup, starts it and waits for it to answer. The service is
    /// reached only on loopback; `port` is the publisher's declared port.
    pub(super) async fn start(spec: &Spec) -> Result<Service, String> {
        let unique = uuid::Uuid::new_v4().simple().to_string();
        let dir = std::env::temp_dir().join(format!("yougori-bounty-target-{}-{unique}", std::process::id()));
        write_files(&dir, &spec.files).await?;

        if let Some(setup) = spec.setup.as_deref().map(str::trim).filter(|setup| !setup.is_empty()) {
            run_setup(&dir, setup, spec.port).await?;
        }

        let mut command = shell(&spec.start);
        command
            .current_dir(&dir)
            .env("PORT", spec.port.to_string())
            .env("HOST", "127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = tokio::fs::remove_dir_all(&dir).await;
                return Err(format!("could not start the target service: {error}"));
            }
        };
        let base = format!("http://127.0.0.1:{}", spec.port);
        let client = reqwest::Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|error| error.to_string())?;
        let service = Service { dir, child, base, client };
        if let Err(error) = service.await_health(&spec.health).await {
            service.stop().await;
            return Err(error);
        }
        Ok(service)
    }

    /// Polls the health path until the service answers or the timeout passes.
    async fn await_health(&self, health: &str) -> Result<(), String> {
        let path = if health.trim().is_empty() { "/" } else { health.trim() };
        let path = if path.starts_with('/') { path.to_owned() } else { format!("/{path}") };
        let deadline = tokio::time::Instant::now() + Duration::from_secs(HEALTH_SECONDS);
        loop {
            if self.client.get(format!("{}{path}", self.base)).send().await.is_ok() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err("the target service did not start answering in time".into());
            }
            tokio::time::sleep(Duration::from_millis(400)).await;
        }
    }

    /// Performs the model's requested HTTP call against the target and returns `{status, body}`.
    /// A failed request becomes an error body the model can read, never an engine failure.
    pub(super) async fn request(&self, arguments: &Value) -> Value {
        let method = arguments["method"].as_str().unwrap_or("GET").to_ascii_uppercase();
        let mut path = arguments["path"].as_str().unwrap_or("/").trim().to_owned();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        let body = arguments["body"].as_str().map(str::to_owned);
        match self.send(&method, &path, &arguments["headers"], body).await {
            Ok((status, text)) => {
                let shown: String = text.chars().take(RESPONSE_CLIP).collect();
                serde_json::json!({"status":status,"body":shown})
            }
            Err(error) => serde_json::json!({"status":0,"error":error}),
        }
    }

    async fn send(&self, method: &str, path: &str, headers: &Value, body: Option<String>) -> Result<(u16, String), String> {
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| "unsupported HTTP method".to_string())?;
        let mut request = self.client.request(method, format!("{}{path}", self.base));
        if let Some(headers) = headers.as_object() {
            for (name, value) in headers {
                if let Some(value) = value.as_str() {
                    request = request.header(name, value);
                }
            }
        }
        if let Some(body) = body {
            request = request.body(body);
        }
        let response = request.send().await.map_err(|error| error.to_string())?;
        let status = response.status().as_u16();
        let text = response.text().await.unwrap_or_default();
        Ok((status, text))
    }

    /// Stops the service and removes its folder.
    pub(super) async fn stop(mut self) {
        let _ = self.child.kill().await;
        let _ = tokio::fs::remove_dir_all(&self.dir).await;
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.child.start_kill();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// Writes the project files under `dir`, creating parent folders. Paths are from the accepted,
/// publisher-vetted source and were validated as safe relative paths when uploaded.
async fn write_files(dir: &PathBuf, files: &[(String, Vec<u8>)]) -> Result<(), String> {
    for (path, bytes) in files {
        let full = dir.join(path);
        if let Some(parent) = full.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|error| format!("could not set up the target: {error}"))?;
        }
        let mut file = tokio::fs::File::create(&full).await.map_err(|error| format!("could not write {path}: {error}"))?;
        file.write_all(bytes).await.map_err(|error| format!("could not write {path}: {error}"))?;
    }
    if files.is_empty() {
        tokio::fs::create_dir_all(dir).await.map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Runs the one-off setup command to completion, bounded.
async fn run_setup(dir: &PathBuf, setup: &str, port: u16) -> Result<(), String> {
    let mut command = shell(setup);
    command
        .current_dir(dir)
        .env("PORT", port.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let child = command.spawn().map_err(|error| format!("could not run setup: {error}"))?;
    let output = tokio::time::timeout(Duration::from_secs(SETUP_SECONDS), child.wait_with_output())
        .await
        .map_err(|_| "setup did not finish in time".to_string())?
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("setup failed: {}", crate::lifecycle::safe_diagnostic(stderr.trim())));
    }
    Ok(())
}

/// A shell command that runs the publisher's declared command line.
fn shell(command_line: &str) -> tokio::process::Command {
    let mut command = if cfg!(windows) {
        let mut command = tokio::process::Command::new("cmd");
        command.arg("/c").arg(command_line);
        command
    } else {
        let mut command = tokio::process::Command::new("sh");
        command.arg("-c").arg(command_line);
        command
    };
    command.env("CI", "1");
    command
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn starts_an_uploaded_service_and_proxies_requests_to_it() {
        // A tiny Node service stands in for an uploaded project; skipped where Node is absent.
        let server = "const http=require('node:http');const p=Number(process.env.PORT);http.createServer((q,r)=>{if(q.url==='/health'){r.writeHead(200).end('ok');return;}r.writeHead(200,{'content-type':'application/json'});r.end(JSON.stringify({hello:'world',url:q.url}))}).listen(p,'127.0.0.1')";
        let probe = shell("node -e \"process.exit(0)\"").status().await;
        if probe.map(|status| !status.success()).unwrap_or(true) {
            eprintln!("skipped: Node unavailable");
            return;
        }
        let spec = Spec {
            files: vec![("server.js".into(), server.as_bytes().to_vec())],
            setup: None,
            start: "node server.js".into(),
            port: 39517,
            health: "/health".into(),
        };
        let service = Service::start(&spec).await.expect("the service starts");
        let response = service.request(&serde_json::json!({"method":"GET","path":"/probe"})).await;
        assert_eq!(response["status"], 200, "{response}");
        assert!(response["body"].as_str().unwrap().contains("\"url\":\"/probe\""), "{response}");
        service.stop().await;
    }
}
