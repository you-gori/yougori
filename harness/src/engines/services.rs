//! The spec's services (a harness's own server, a practice app to test): started in order before
//! the engine, each ready once its `ready_url` answers, and stopped in reverse order after it.
use super::process::{self, Launch, ProcessGuard, Stdio2};
use crate::protocol::EngineHandle;
use crate::spec::{EngineSpec, Service};
use std::time::Duration;

/// Running services, stopped in reverse order when dropped.
pub struct Services(Vec<ProcessGuard>);

/// Starts the spec's services in order and waits until each is ready. On a failure the services
/// already started are stopped again.
pub async fn start(spec: &EngineSpec) -> anyhow::Result<Services> {
    let mut running = Services(Vec::new());
    for service in &spec.services {
        let guard = start_one(spec, service).await?;
        running.0.push(guard.clone());
        if let Err(error) = ready(spec, service, &guard).await {
            drop(running);
            return Err(error);
        }
    }
    Ok(running)
}

async fn start_one(spec: &EngineSpec, service: &Service) -> anyhow::Result<ProcessGuard> {
    if service.argv.is_empty() {
        anyhow::bail!("{}'s service {} has no command.", spec.name, service.name);
    }
    let env = process::service_environment(&spec.environment(), &service.env);
    let cwd = service.cwd.clone().unwrap_or_else(|| spec.cwd.clone());
    let name = format!("{}'s service {}", spec.name, service.name);
    let spawned = process::spawn(Launch {
        name: &name,
        log: &format!("{}.{}", spec.harness, service.name),
        argv: &service.argv,
        env: &env,
        cwd: &cwd,
        state_dir: &spec.state_dir,
        stdio: Stdio2::Logged,
    })
    .await?;
    Ok(spawned.guard)
}

/// Waits for the service's `ready_url` to answer with any HTTP status, up to `ready_seconds`.
/// Without a URL the service is ready once it has run a moment without ending.
async fn ready(spec: &EngineSpec, service: &Service, guard: &ProcessGuard) -> anyhow::Result<()> {
    let limit = Duration::from_secs(service.ready_seconds.max(1));
    let Some(url) = service.ready_url.as_deref() else {
        if let Some(status) = guard.wait_for(Duration::from_millis(500)).await {
            anyhow::bail!("{}", failed(spec, service, guard, &process::describe(status)));
        }
        return Ok(());
    };
    // The service is local: never through a proxy the VM sets for chosen sites.
    let client = reqwest::Client::builder()
        .no_proxy()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(5))
        .build()?;
    let deadline = tokio::time::Instant::now() + limit;
    let mut pause = Duration::from_millis(100);
    loop {
        if let Some(status) = guard.status() {
            anyhow::bail!("{}", failed(spec, service, guard, &process::describe(status)));
        }
        let attempt = tokio::time::timeout_at(deadline, client.get(url).send()).await;
        match attempt {
            Ok(Ok(_)) => return Ok(()),
            Ok(Err(_)) => {}
            Err(_) => break,
        }
        if tokio::time::Instant::now() >= deadline {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(pause) => {}
            _ = guard.wait() => {}
        }
        pause = (pause * 2).min(Duration::from_secs(1));
    }
    if let Some(status) = guard.status() {
        anyhow::bail!("{}", failed(spec, service, guard, &process::describe(status)));
    }
    anyhow::bail!("{}", failed(spec, service, guard, &format!("did not answer at {url} within {} seconds", limit.as_secs())))
}

fn failed(spec: &EngineSpec, service: &Service, guard: &ProcessGuard, how: &str) -> String {
    let tail = guard.tail();
    let mut text = format!("{} could not start its service {}: it {how}.", spec.name, service.name);
    if !tail.trim().is_empty() {
        text.push_str(" Its last output:\n");
        text.push_str(&tail);
    }
    text
}

impl Services {
    /// Keeps the services alive as long as the engine.
    pub fn attach(self, mut engine: EngineHandle) -> EngineHandle {
        if !self.0.is_empty() {
            engine.keep.push(Box::new(self));
        }
        engine
    }
}

impl Drop for Services {
    fn drop(&mut self) {
        // Last started, first stopped; each fully, so a restart finds its ports free.
        while let Some(guard) = self.0.pop() {
            guard.stop_blocking();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::Protocol;
    use std::collections::BTreeMap;
    use std::path::PathBuf;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn base_env() -> BTreeMap<String, String> {
        process::tests::child("sleep").1
    }

    fn spec(dir: &std::path::Path, services: Vec<Service>) -> EngineSpec {
        EngineSpec {
            harness: "hexstrike".into(),
            name: "HexStrike".into(),
            category: "security".into(),
            protocol: Protocol::Acp,
            argv: vec!["engine".into()],
            env: base_env(),
            secret_env: BTreeMap::new(),
            cwd: dir.to_path_buf(),
            model: "m".into(),
            models: vec!["m".into()],
            model_switch: Default::default(),
            respec: Vec::new(),
            profile: None,
            mcp: Vec::new(),
            services,
            context_window: 32768,
            max_output: 4096,
            base_url: crate::spec::RELAY.into(),
            api_key: crate::spec::RELAY_KEY.into(),
            answers: serde_json::Value::Null,
            reach: Default::default(),
            state_dir: dir.join("state"),
            session: Default::default(),
        }
    }

    /// A service run by this test binary: `fail` ends at once, anything else runs a minute.
    fn service(name: &str, mode: &str, ready_url: Option<String>, ready_seconds: u64) -> Service {
        let (argv, mut env) = process::tests::child(mode);
        env.remove("PATH");
        Service { name: name.into(), argv, env, cwd: None, ready_url, ready_seconds }
    }

    /// A tiny HTTP server in this process that answers every request, standing in for a
    /// service's port; it starts answering after `delay`.
    async fn answering(delay: Duration) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { return };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    let _ = socket.read(&mut buffer).await;
                    let _ = socket.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
                });
            }
        });
        (format!("http://{address}/health"), task)
    }

    #[tokio::test]
    async fn services_start_in_order_wait_for_ready_and_stop_in_reverse() {
        let dir = tempfile::tempdir().unwrap();
        let (url, server) = answering(Duration::from_millis(400)).await;
        let spec = spec(
            dir.path(),
            vec![
                service("first", "sleep", Some(url.clone()), 20),
                service("second", "sleep", None, 20),
            ],
        );
        let started = std::time::Instant::now();
        let services = start(&spec).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(350), "waited for the URL to answer");
        let guards: Vec<ProcessGuard> = services.0.clone();
        assert_eq!(guards.len(), 2);
        assert!(guards.iter().all(|g| !g.exited()));
        let (handle, _commands, _events) = EngineHandle::pair();
        let handle = services.attach(handle);
        assert_eq!(handle.keep.len(), 1);
        drop(handle);
        for guard in &guards {
            assert!(guard.wait_for(Duration::from_secs(10)).await.is_some(), "{} still runs", guard.name());
        }
        server.abort();
        assert!(dir.path().join("state/hexstrike.first.stderr.log").exists());
    }

    #[tokio::test]
    async fn a_service_that_ends_fails_with_its_last_lines_and_the_earlier_ones_stop() {
        let dir = tempfile::tempdir().unwrap();
        let spec = spec(
            dir.path(),
            vec![
                service("helper", "sleep", None, 5),
                service("server", "fail", Some("http://127.0.0.1:9/never".into()), 20),
            ],
        );
        let error = start(&spec).await.err().expect("the server fails");
        let text = format!("{error}");
        assert!(text.contains("server") && text.contains("port 8888 is taken"), "{text}");
    }

    #[tokio::test]
    async fn a_service_that_never_answers_times_out() {
        let dir = tempfile::tempdir().unwrap();
        let spec = spec(dir.path(), vec![service("quiet", "sleep", Some("http://127.0.0.1:9/never".into()), 1)]);
        let started = std::time::Instant::now();
        let error = start(&spec).await.err().unwrap();
        assert!(format!("{error}").contains("did not answer"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(8));
    }

    #[tokio::test]
    async fn no_services_start_nothing() {
        let spec = spec(&PathBuf::from("."), Vec::new());
        let services = start(&spec).await.unwrap();
        let (handle, _c, _e) = EngineHandle::pair();
        assert!(services.attach(handle).keep.is_empty());
    }
}
