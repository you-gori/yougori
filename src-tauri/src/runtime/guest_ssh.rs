//! Authenticated command execution for full VMs without a Linux-only agent.
//! The forwarded listener is temporary and loopback-only; host keys are pinned.
use super::RuntimeManager;
use crate::models::{CommandResult, Environment};
use serde::Deserialize;
use std::{process::Stdio, time::Duration};
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GuestSsh {
    pub username: String,
    pub identity_file: String,
    pub host_key: String,
    #[serde(default = "default_port")]
    pub port: u16,
}
fn default_port() -> u16 { 22 }

async fn read_output(reader: impl AsyncRead + Unpin) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader.take(262_145).read_to_end(&mut bytes).await.map_err(|e| e.to_string())?;
    if bytes.len() > 262_144 { return Err("SSH output exceeded 256 KiB. Inspect the guest before retrying this command.".into()); }
    Ok(bytes)
}

impl RuntimeManager {
    pub async fn execute_vm_ssh(&self, environment: &Environment, ssh: &GuestSsh, command: &str) -> Result<CommandResult, String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return Box::pin(engine.execute_vm_ssh(environment, ssh, command)).await; }

        let profile = super::cloud::Profile { name: environment.name.clone(), vendor: "other".into(), host: "127.0.0.1".into(), port: ssh.port, username: ssh.username.clone(), identity_file: ssh.identity_file.clone(), host_key: ssh.host_key.clone() };
        super::cloud::validate(&profile, true)?;
        let known = tempfile::tempdir().map_err(|e| e.to_string())?;
        let path = known.path().join("known_hosts");
        if path.to_string_lossy().contains(['"', '\n', '\r']) { return Err("The temporary directory cannot be used for SSH configuration".into()); }
        let (qmp, port) = self.forward_workspace_vm_port(environment, ssh.port).await?;
        let result = async {
            tokio::fs::write(&path, format!("[127.0.0.1]:{port} {}\n", ssh.host_key)).await.map_err(|e| e.to_string())?;
            let mut process = super::cloud::command("ssh");
            process.args(["-F", "none", "-T", "-a", "-x", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no", "-o", "ClearAllForwardings=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=10", "-o", "ServerAliveCountMax=2", "-o", "PermitLocalCommand=no", "-o", "GlobalKnownHostsFile=none", "-o"])
                .arg(format!("UserKnownHostsFile=\"{}\"", path.display()))
                .arg("-i").arg(super::cloud::identity_path(&ssh.identity_file, known.path())?).arg("-p").arg(port.to_string())
                .arg("-l").arg(&ssh.username).arg("127.0.0.1").arg(command)
                .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
            let mut child = process.spawn().map_err(|e| format!("OpenSSH client is required: {e}"))?;
            let stdout = child.stdout.take().ok_or("Missing SSH output")?;
            let stderr = child.stderr.take().ok_or("Missing SSH diagnostics")?;
            let result = tokio::time::timeout(Duration::from_secs(120), async {
                tokio::try_join!(read_output(stdout), read_output(stderr), async { child.wait().await.map_err(|e| e.to_string()) })
            }).await.map_err(|_| "SSH command timed out after 120 seconds. Check guest processes before retrying.".to_string()).and_then(|value| value);
            if result.is_err() { let _ = child.kill().await; let _ = child.wait().await; }
            let (stdout, stderr, status) = result?;
            Ok(CommandResult { exit_code: status.code().unwrap_or(1), stdout: String::from_utf8_lossy(&stdout).into_owned(), stderr: String::from_utf8_lossy(&stderr).into_owned() })
        }.await;
        Self::remove_workspace_vm_port(&qmp, port).await;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn command_output_is_bounded_and_ssh_defaults_are_explicit() {
        assert_eq!(read_output(&b"hello"[..]).await.unwrap(), b"hello");
        assert!(read_output(&vec![b'x'; 262_145][..]).await.unwrap_err().contains("exceeded"));
        let config: GuestSsh = serde_json::from_value(serde_json::json!({"username":"guest","identityFile":"key","hostKey":"key"})).unwrap();
        assert_eq!(config.port, 22);
        assert!(serde_json::from_value::<GuestSsh>(serde_json::json!({"username":"guest","identityFile":"key","hostKey":"key","password":"secret"})).is_err());
    }
}
