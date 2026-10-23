// Personal Vault is Windows-only in this release. The gateway still compiles
// everywhere so the shared app state and port constants stay available.
#![cfg_attr(not(windows), allow(dead_code))]
use crate::{models::*, runtime::RuntimeManager, workspace};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{sync::Arc, time::Duration};
use tauri::Manager;
use crate::AppHandle;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_util::sync::CancellationToken;

pub const ID: &str = "yougori-private-vault-gateway-v1";
// Official Python multi-platform OCI manifest, pinned when this gateway was built.
const IMAGE: &str = "docker.io/library/python@sha256:1a63a53928ce53d2b0baf08092a703f4840ac5dfbd61fd48802dbf48e08c801e";
pub const HTTP_PORT: u16 = 49732;
#[derive(Default)]
pub struct GatewayState {
    active: Mutex<Option<CancellationToken>>,
    endpoint: Mutex<Option<(u16, u16, Option<String>)>>,
}

fn environment() -> Environment {
    serde_json::from_value(json!({"id":ID,"name":"Personal Vault MCP gateway","kind":"container","status":"running","runtime":IMAGE,"provider":"yougoriOci","networkAccess":false,"gpuAccess":false,"description":"Internal encrypted relay; no vault contents","createdAt":"","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"storageLimitGb":6,"networkRxMbps":0,"resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":0.25,"preferred":0.25,"max":0.25,"current":0},"priority":"normal","dynamic":false}})).expect("fixed internal environment")
}
pub async fn provision(runtime: &RuntimeManager) -> Result<(String, String), String> {
    // Setup retries and the legacy connection flow share one internal container.
    static PROVISION: Mutex<()> = Mutex::const_new(());
    let _provision = PROVISION.lock().await;
    let env = environment();
    runtime.register_container_provider(ID, &RuntimeProviderKind::YougoriOci)?;
    let mut options = yougori_cli::workload::Options::default();
    options.user = Some("65534:65534".into());
    runtime.save_workload_options(ID, &options)?;
    let code = STANDARD.encode(include_bytes!("vault_gateway.py"));
    let command=format!("exec python -I -u -c 'import base64;exec(compile(base64.b64decode(\"{code}\"),\"vault_gateway\",\"exec\"))'");
    // Start is idempotent in the appliance. Only create after the runtime
    // explicitly reports absence; never delete an existing container on retry.
    if let Err(error) = runtime.container_action(ID, "start", false).await {
        if !error.contains("no such object") {
            return Err(error);
        }
        runtime
            .provision_container_with_storage(
                ID,
                IMAGE,
                &command,
                &env.resource_policy,
                false,
                false,
                6.0,
            )
            .await?;
        runtime.container_action(ID, "start", false).await?;
    }
    let endpoint = runtime.workspace_endpoint(&env).await?;
    for _ in 0..40 {
        if let Ok(stream) = workspace::agent_stream(&endpoint.0, &endpoint.1, ID, 8443).await {
            drop(stream);
            return Ok(endpoint);
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Err("Vault gateway container did not become ready".into())
}
pub async fn start_http(app: &AppHandle, broker_port: u16, pin: String) -> Result<Value, String> {
    start_at(app, broker_port, HTTP_PORT, Some(pin)).await
}
async fn start_at(
    app: &AppHandle,
    broker_port: u16,
    port: u16,
    pin: Option<String>,
) -> Result<Value, String> {
    if broker_port == 0 {
        return Err("Invalid protected broker endpoint".into());
    }
    let state = app.state::<GatewayState>();
    let mut active = state.active.lock().await;
    let mut endpoint_state = state.endpoint.lock().await;
    if active.is_some() && *endpoint_state == Some((broker_port, port, pin.clone())) {
        return Ok(json!({"port":port,"container":ID}));
    }
    let restarting = active.is_some();
    if let Some(old) = active.take() {
        old.cancel();
    }
    let address = (
        if port == HTTP_PORT {
            std::net::Ipv4Addr::LOCALHOST
        } else {
            std::net::Ipv4Addr::UNSPECIFIED
        },
        port,
    );
    let mut attempts = 0;
    let listener = loop {
        match TcpListener::bind(address).await {
            Ok(listener) => break listener,
            Err(_) if restarting && attempts < 20 => {
                attempts += 1;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(_) => {
                return Err(format!(
                    "Port {port} is already in use; vault access was not started"
                ))
            }
        }
    };
    let endpoint = provision(&app.state::<RuntimeManager>()).await?;
    let cancel = CancellationToken::new();
    for _ in 0..8 {
        let endpoint = endpoint.clone();
        let stop = cancel.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {_ = stop.cancelled()=>break, _ = async {
                    let mut stream=workspace::agent_stream(&endpoint.0,&endpoint.1,ID,8444).await?;
                    if stream.read_u8().await.map_err(|_|"Gateway connection closed")? != 1 {return Err("Invalid gateway pairing".to_string());}
                    let mut broker=TcpStream::connect((std::net::Ipv4Addr::LOCALHOST,broker_port)).await.map_err(|_|"Protected broker unavailable")?;
                    tokio::io::copy_bidirectional(&mut stream,&mut broker).await.map_err(|_|"Gateway stream ended")?;
                    Ok::<(),String>(())
                }=>()}
                tokio::select! {_=stop.cancelled()=>break,_=tokio::time::sleep(Duration::from_millis(300))=>()}
            }
        });
    }
    let stop = cancel.clone();
    let gateway_pin = pin.clone();
    tokio::spawn(async move {
        let slots = Arc::new(tokio::sync::Semaphore::new(16));
        loop {
            let (mut client, _) = match tokio::select! {_=stop.cancelled()=>break, result=listener.accept()=>result} {
                Ok(v) => v,
                // A client reset before accept or descriptor pressure must not end the gateway.
                Err(_) => { tokio::time::sleep(Duration::from_millis(100)).await; continue }
            };
            let Ok(permit) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let endpoint = endpoint.clone();
            let stop = stop.clone();
            let pin = gateway_pin.clone();
            tokio::spawn(async move {
                let _permit = permit;
                tokio::select! {_=stop.cancelled()=>(), _=async {
                    let mut guest=workspace::agent_stream(&endpoint.0,&endpoint.1,ID,8443).await?;
                    if let Some(pin) = pin {
                        let mut sealed = yougori_vault::transport::seal_gateway(guest, &pin).await?;
                        tokio::io::copy_bidirectional(&mut client,&mut sealed).await.map_err(|_|"Device connection ended")?;
                    } else {
                        tokio::io::copy_bidirectional(&mut client,&mut guest).await.map_err(|_|"Device connection ended")?;
                    }
                    Ok::<(),String>(())
                }=>()}
            });
        }
    });
    *active = Some(cancel);
    *endpoint_state = Some((broker_port, port, pin));
    Ok(json!({"port":port,"container":ID}))
}
pub async fn stop(app: &AppHandle) -> Result<(), String> {
    if let Some(cancel) = app.state::<GatewayState>().active.lock().await.take() {
        cancel.cancel();
        app.state::<RuntimeManager>()
            .container_action(ID, "stop", false)
            .await?;
    }
    Ok(())
}
pub async fn status(app: &AppHandle) -> Value {
    let state = app.state::<GatewayState>();
    let running = state.active.lock().await.is_some();
    let port = state
        .endpoint
        .lock()
        .await
        .as_ref()
        .map(|(_, port, _)| *port)
        .unwrap_or(HTTP_PORT);
    let running = running && (port != HTTP_PORT || http_ready().await);
    json!({"running":running,"port":port,"container":ID})
}
pub async fn http_ready() -> bool {
    let Ok(client) = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
    else {
        return false;
    };
    client
        .post(format!("http://127.0.0.1:{HTTP_PORT}/mcp"))
        .body("{}")
        .send()
        .await
        .is_ok_and(|response| response.status() == reqwest::StatusCode::UNAUTHORIZED)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn internal_gateway_has_no_host_folders_network_or_secrets() {
        let e = environment();
        assert!(!e.network_access);
        assert!(!e.gpu_access);
        assert!(e.runtime.contains("@sha256:"));
    }
    #[cfg(windows)]
    #[tokio::test]
    #[ignore = "boots a disposable OCI gateway and verifies TLS through it; no vault credentials, OS consent, or user environments"]
    async fn vault_real_container_gateway_preserves_mutual_tls() {
        use sha2::{Digest, Sha256};
        use tokio::io::AsyncWriteExt;
        let data = tempfile::tempdir().unwrap();
        let runtime = RuntimeManager::new(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")),
            data.path(),
        )
        .unwrap();
        let result=async {
            eprintln!("Vault gateway integration: provision pinned OCI container");
            let endpoint=provision(&runtime).await?;
            // Creating twice used to fail with nerdctl's name-store collision.
            let repeated=provision(&runtime).await?;
            assert_eq!(endpoint,repeated);
            runtime.container_action(ID,"stop",false).await?;
            let restarted=provision(&runtime).await?;
            assert_eq!(endpoint,restarted);
            let server_key=yougori_vault::transport::DeviceKey::generate()?;
            let fingerprint=server_key.fingerprint()?;
            let config=Arc::new(yougori_vault::transport::server_config(&server_key)?);
            let device=data.path().join("test-device.json");
            let device_fingerprint=yougori_vault::transport::DeviceKey::create_file(&device)?;
            let mut reverse=workspace::agent_stream(&endpoint.0,&endpoint.1,ID,8444).await?;
            let server=tokio::spawn(async move {
                if reverse.read_u8().await.map_err(|e|e.to_string())?!=1{return Err("Invalid pairing".to_string());}
                let mut tls=tokio_rustls::TlsAcceptor::from(config).accept(reverse).await.map_err(|e|e.to_string())?;
                let cert=tls.get_ref().1.peer_certificates().and_then(|c|c.first()).ok_or("No authenticated device")?;
                if hex::encode(Sha256::digest(cert))!=device_fingerprint{return Err("Incorrect client identity".into());}
                let bytes=yougori_vault::protocol::read(&mut tls).await?;
                let message:Value=serde_json::from_slice(&bytes).map_err(|e|e.to_string())?;
                if message["method"]!="ping"{return Err("Request changed in transit".into());}
                yougori_vault::protocol::write(&mut tls,&json!({"result":"authenticated"})).await?;
                tls.shutdown().await.map_err(|e|e.to_string())?;
                Ok::<(),String>(())
            });
            let proxy=TcpListener::bind("127.0.0.1:0").await.map_err(|e|e.to_string())?;let address=proxy.local_addr().map_err(|e|e.to_string())?;
            let forward=tokio::spawn(async move {let (mut local,_)=proxy.accept().await.map_err(|e|e.to_string())?;let mut guest=workspace::agent_stream(&endpoint.0,&endpoint.1,ID,8443).await?;let _=tokio::io::copy_bidirectional(&mut local,&mut guest).await;Ok::<(),String>(())});
            let mut stream=yougori_vault::transport::connect(&address.to_string(),&fingerprint,&device).await?;
            yougori_vault::protocol::write(&mut stream,&json!({"method":"ping"})).await?;
            let response:Value=serde_json::from_slice(&yougori_vault::protocol::read(&mut stream).await?).map_err(|e|e.to_string())?;
            if response["result"]!="authenticated"{return Err("Response changed in transit".into());}
            drop(stream);server.await.map_err(|e|e.to_string())??;forward.await.map_err(|e|e.to_string())??;
            let options=runtime.workload_options(ID)?;assert!(options.binds.is_empty());assert!(options.volumes.is_empty());assert!(options.environment.is_empty());
            runtime.container_action(ID,"stop",false).await?;runtime.delete_container(ID).await?;
            eprintln!("Vault gateway integration: verified encrypted round trip and removed disposable container");
            Ok::<(),String>(())
        }.await;
        runtime.shutdown_all().await;
        result.unwrap();
    }
}
