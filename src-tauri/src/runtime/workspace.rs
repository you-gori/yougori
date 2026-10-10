use super::{available_port, RuntimeManager};
use crate::models::{Environment, EnvironmentKind};
use serde_json::{json, Value};
use std::time::Duration;

impl RuntimeManager {
    pub async fn update_local_service_ports(
        &self,
        ids: &[String],
        ports: &[u16],
        host_address: &str,
    ) -> Result<(), String> {
        let mut local = Vec::new();
        for (engine, group) in self.storage_groups(ids)? {
            if let Some(engine) = engine { Box::pin(engine.update_local_service_ports(&group, ports, host_address)).await?; }
            else { local = group; }
        }
        let ids = &local;
        // The host filter is independent of the guest firewall. Explicit local
        // publications may reach only these ports on the QEMU host gateway.
        {
            let processes = self.vms.lock().await;
            for id in ids {
                if let Some(network) = processes.get(id).and_then(|p| p.internet.as_ref()) {
                    network.set_local_services(ports)?;
                }
            }
        }
        let mut qemu_ids = Vec::new();
        let mut cuda_ids = Vec::new();
        for id in ids {
            match self.container_provider(id)? {
                crate::models::RuntimeProviderKind::YougoriCuda => cuda_ids.push(id.clone()),
                _ => qemu_ids.push(id.clone()),
            }
        }
        let mut batches = Vec::new();
        let endpoint = {
            let mut appliance = self.appliance.lock().await;
            match appliance.as_mut() {
                Some(process) => if process.child.try_wait().map_err(|e| e.to_string())?.is_none() { Some(process.endpoint.clone()) } else { None },
                _ => None,
            }
        };
        if let Some(endpoint) = endpoint {
            if let Some(process) = self.appliance.lock().await.as_ref() {
                process.internet.set_local_services(if qemu_ids.is_empty() { &[] } else { ports })?;
            }
            if !qemu_ids.is_empty() {
                batches.push((qemu_ids, endpoint, false));
            }
        }
        if let Ok(endpoint) = self.cuda.current_endpoint().await {
            batches.push((cuda_ids, super::AgentEndpoint { base_url: endpoint.base_url, token: endpoint.token }, true));
        }
        for (ids, endpoint, cuda) in batches {
        let mut body = json!({"ids":ids,"ports":ports});
        if cuda {
            // WSL has no QEMU 10.0.2.2 gateway. Grant only the explicitly
            // published ports on this PC's private LAN address, never its API.
            body["hostAddress"] = host_address.parse::<std::net::Ipv4Addr>().ok()
                .filter(|ip| ip.is_private()).map(|ip|ip.to_string()).unwrap_or_default().into();
        }
        let response = self
            .client
            .post(format!("{}/v1/services/local-ports", endpoint.base_url))
            .bearer_auth(endpoint.token)
            .json(&body)
            .timeout(Duration::from_secs(25))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(response.text().await.unwrap_or_default());
        }
        }
        Ok(())
    }
    pub async fn workspace_endpoint(
        &self,
        environment: &Environment,
    ) -> Result<(String, String), String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return Box::pin(engine.workspace_endpoint(environment)).await; }

        if environment.kind == EnvironmentKind::Container {
            let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
            if self.container_provider(id)? == crate::models::RuntimeProviderKind::YougoriCuda {
                let endpoint = self.cuda.current_endpoint().await?;
                return Ok((endpoint.base_url, endpoint.token));
            }
            // Workspace polling/cleanup must never boot or restart the utility VM.
            let mut appliance = self.appliance.lock().await;
            let process = appliance
                .as_mut()
                .ok_or("The container runtime is stopped")?;
            if process
                .child
                .try_wait()
                .map_err(|e| e.to_string())?
                .is_some()
            {
                return Err("The container runtime has stopped".into());
            }
            let endpoint = process.endpoint.clone();
            return Ok((endpoint.base_url, endpoint.token));
        }
        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        let processes = self.vms.lock().await;
        let endpoint = processes.get(id).and_then(|p| p.micro_endpoint.as_ref())
            .ok_or("This VM has no Yougori guest agent. Add a service port manually; run it on 0.0.0.0 inside the VM.")?;
        Ok((endpoint.base_url.clone(), endpoint.token.clone()))
    }

    pub async fn workspace_request(
        &self,
        environment: &Environment,
        path: &str,
        body: Value,
    ) -> Result<Value, String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return Box::pin(engine.workspace_request(environment, path, body)).await; }

        if crate::peer_sharing::is_shared(environment) {
            if let Some(action)=path.strip_prefix("/v1/terminal/") {let mut body=body;body["action"]=json!(action);return crate::peer_sharing::remote(environment,"terminal",body).await;}
            return Err("This capability is not granted by the remote environment share".into());
        }
        if environment.kind == EnvironmentKind::Cloud {
            return self.cloud.session(&environment.id).await?.request(path, body).await;
        }
        let (endpoint, token) = self.workspace_endpoint(environment).await?;
        if environment.kind == EnvironmentKind::MicroVm
            && (matches!(path, "/v1/terminal/create" | "/v1/shares/attach" | "/v1/cli/context") || path.starts_with("/v1/apps/"))
        {
            // QMP is ready before Alpine finishes booting. Probe with a read-only
            // request; never blindly retry terminal creation or other mutations.
            let deadline = tokio::time::Instant::now() + super::host_platform::guest_boot_timeout();
            loop {
                if self
                    .client
                    .get(format!("{endpoint}/v1/health"))
                    .bearer_auth(&token)
                    .timeout(Duration::from_secs(2))
                    .send()
                    .await
                    .is_ok_and(|r| r.status().is_success())
                {
                    break;
                }
                if tokio::time::Instant::now() >= deadline {
                    return Err("The microVM guest agent is still booting or unavailable. Try opening a new tab in a moment.".into());
                }
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
        let response = self
            .client
            .post(format!("{endpoint}{path}"))
            .bearer_auth(token)
            .json(&body)
            .timeout(Duration::from_secs(if path == "/v1/gpu/verify" { 40 } else { 25 }))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(
                "Restart this environment to load the updated guest agent (terminal, sharing and apps).".into(),
            );
        }
        if !response.status().is_success() {
            return Err(response.text().await.unwrap_or_default());
        }
        response.json().await.map_err(|e| e.to_string())
    }

    pub async fn forward_workspace_vm_port(
        &self,
        environment: &Environment,
        guest_port: u16,
    ) -> Result<(u16, u16), String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return Box::pin(engine.forward_workspace_vm_port(environment, guest_port)).await; }

        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        let qmp = self
            .vms
            .lock()
            .await
            .get(id)
            .ok_or("VM is not running")?
            .qmp_port;
        let port = available_port()?;
        let reply = tokio::time::timeout(Duration::from_secs(5), super::vm::qmp_request(qmp,"human-monitor-command",Some(json!({"command-line":format!("hostfwd_add net0 tcp:127.0.0.1:{port}-:{guest_port}")})))).await.map_err(|_| "VM port forwarding timed out")??;
        if reply
            .as_str()
            .is_some_and(|message| !message.trim().is_empty())
        {
            return Err(format!("VM port forwarding: {}", reply.as_str().unwrap()));
        }
        Ok((qmp, port))
    }

    pub async fn remove_workspace_vm_port(qmp: u16, port: u16) {
        let _ = super::vm::qmp_execute_bounded(
            qmp,
            "human-monitor-command",
            Some(json!({"command-line":format!("hostfwd_remove net0 tcp:127.0.0.1:{port}")})),
            Duration::from_secs(3),
        )
        .await;
    }
}
