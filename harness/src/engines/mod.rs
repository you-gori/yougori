//! Starting the chosen harness's engine, whatever protocol it speaks, behind one [`EngineHandle`].
use crate::protocol::EngineHandle;
use crate::spec::{EngineSpec, Protocol};

pub mod acp;
pub mod claude;
pub mod codex;
pub mod pi;
pub mod process;
pub mod scripted;
pub mod services;

/// Starts the spec's services, then its engine. The services stop when the engine ends.
pub async fn start(spec: &EngineSpec) -> anyhow::Result<EngineHandle> {
    let services = services::start(spec).await?;
    let engine = match spec.protocol {
        Protocol::Native => crate::native::start(spec).await,
        Protocol::Acp => acp::start(spec).await,
        Protocol::CodexAppServer => codex::start(spec).await,
        Protocol::ClaudeStreamJson => claude::start(spec).await,
        Protocol::PiRpc => pi::start(spec).await,
        // The screen runs these itself in its terminal pane (ui), never through an engine handle.
        Protocol::Terminal => Err(anyhow::anyhow!("{} runs in the screen's terminal pane.", spec.name)),
    }?;
    Ok(services.attach(engine))
}

/// A new spec for `model`, from the spec's `respec` command (engines that restart to switch).
/// Without one, the same spec with the model replaced.
pub async fn respec(spec: &EngineSpec, model: &str) -> anyhow::Result<EngineSpec> {
    if spec.respec.is_empty() {
        let mut next = spec.clone();
        next.model = model.to_owned();
        return Ok(next);
    }
    let output = tokio::process::Command::new(&spec.respec[0])
        .args(&spec.respec[1..])
        .arg(model)
        .env_clear()
        .envs(spec.environment())
        .current_dir(&spec.cwd)
        .stdin(std::process::Stdio::null())
        .output()
        .await
        .map_err(|e| anyhow::anyhow!("Could not prepare {} for {model}: {e}", spec.name))?;
    if !output.status.success() {
        anyhow::bail!(
            "Could not prepare {} for {model}: {}",
            spec.name,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    let next: EngineSpec = serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow::anyhow!("Invalid engine spec for {model}: {e}"))?;
    next.check()?;
    Ok(next)
}
