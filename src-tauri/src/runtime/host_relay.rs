use super::{AgentEndpoint, RuntimeManager};
use crate::{
    host_files::HostFolderServer,
    models::{Environment, RuntimeProviderKind},
};
use serde_json::json;
use std::{collections::HashMap, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

pub(super) async fn channel(
    endpoint: &AgentEndpoint,
    path: &str,
    body: serde_json::Value,
) -> Result<(TcpStream, String), String> {
    let url = url::Url::parse(&endpoint.base_url).map_err(|e| e.to_string())?;
    if url.scheme() != "http"
        || url.host_str() != Some("127.0.0.1")
        || !matches!(path, "/v1/host-relay" | "/v1/fabric/stream")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
        || endpoint.token.len() != 64
        || !endpoint.token.bytes().all(|c| c.is_ascii_hexdigit())
    {
        return Err("Invalid authenticated guest stream endpoint".into());
    }
    let port = url.port().ok_or("Missing guest port")?;
    tokio::time::timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(("127.0.0.1",port)).await.map_err(|e| e.to_string())?;
        stream.set_nodelay(true).map_err(|e| e.to_string())?;
        let body = body.to_string();
        let request = format!("POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAuthorization: Bearer {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: Upgrade\r\n\r\n{body}",endpoint.token,body.len());
        stream.write_all(request.as_bytes()).await.map_err(|e| e.to_string())?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 8192 { return Err("Oversized guest stream response".into()); }
            header.push(stream.read_u8().await.map_err(|e| e.to_string())?);
        }
        let header = String::from_utf8(header).map_err(|e| e.to_string())?;
        if !header.starts_with("HTTP/1.1 101 ") { return Err("The guest rejected its private stream. Update/restart the CUDA runtime.".into()); }
        Ok((stream,header))
    }).await.map_err(|_| "Guest stream connection timed out")?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_remote_credentials_and_header_injection_without_connecting() {
        for base in [
            "http://192.168.1.1:12345",
            "http://user@127.0.0.1:12345",
            "http://127.0.0.1:12345/?secret=1",
            "https://127.0.0.1:12345",
        ] {
            let ep = AgentEndpoint {
                base_url: base.into(),
                token: "a".repeat(64),
            };
            assert!(channel(&ep, "/v1/host-relay", json!({"id":"env-test"}))
                .await
                .unwrap_err()
                .contains("Invalid authenticated"));
        }
        let ep = AgentEndpoint {
            base_url: "http://127.0.0.1:12345".into(),
            token: "a".repeat(64),
        };
        assert!(
            channel(&ep, "/v1/host-relay\r\nInjected: header", json!({}))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn malformed_frame_revokes_the_whole_channel() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let mut guest = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (host, _) = listener.accept().await.unwrap();
        let task = run(host, 9);
        let mut header = [0; 9];
        header[0] = 2;
        header[4] = 1;
        header[5..].copy_from_slice(&65537u32.to_be_bytes());
        guest.write_all(&header).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            guest.read_u8().await.unwrap_err().kind(),
            std::io::ErrorKind::UnexpectedEof
        );
    }
}

async fn frame(
    writer: &Mutex<tokio::net::tcp::OwnedWriteHalf>,
    kind: u8,
    id: u32,
    data: &[u8],
) -> Result<(), std::io::Error> {
    let mut writer = writer.lock().await;
    let mut header = [0; 9];
    header[0] = kind;
    header[1..5].copy_from_slice(&id.to_be_bytes());
    header[5..].copy_from_slice(&(data.len() as u32).to_be_bytes());
    tokio::time::timeout(Duration::from_secs(30), async {
        writer.write_all(&header).await?;
        writer.write_all(data).await
    })
    .await
    .map_err(std::io::Error::other)?
}

fn run(stream: TcpStream, port: u16) -> JoinHandle<()> {
    tokio::spawn(async move {
        let (mut reader, writer) = stream.into_split();
        let writer = Arc::new(Mutex::new(writer));
        let mut streams: HashMap<u32, mpsc::Sender<Vec<u8>>> = HashMap::new();
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            let mut header = [0; 9];
            if reader.read_exact(&mut header).await.is_err() {
                break;
            }
            let id = u32::from_be_bytes(header[1..5].try_into().unwrap());
            let size = u32::from_be_bytes(header[5..].try_into().unwrap()) as usize;
            if id == 0
                || size > 65536
                || !matches!(header[0], 1..=3)
                || (header[0] != 2 && size != 0)
            {
                break;
            }
            let mut payload = vec![0; size];
            if reader.read_exact(&mut payload).await.is_err() {
                break;
            }
            streams.retain(|_, tx| !tx.is_closed());
            while tasks.try_join_next().is_some() {}
            match header[0] {
                1 => {
                    if streams.len() >= 16 || streams.contains_key(&id) {
                        break;
                    }
                    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(8);
                    streams.insert(id, tx);
                    let writer = writer.clone();
                    tasks.spawn(async move {
                        if let Ok(Ok(mut target))=tokio::time::timeout(Duration::from_secs(3),TcpStream::connect(("127.0.0.1",port))).await {
                            let mut buffer=vec![0;65536];
                            loop {
                                tokio::select! {
                                    bytes=target.read(&mut buffer) => match bytes {
                                        Ok(n) if n>0 => { if frame(&writer,2,id,&buffer[..n]).await.is_err(){break;} },
                                        _ => break,
                                    },
                                    data=rx.recv() => match data {
                                        Some(data) => if !tokio::time::timeout(Duration::from_secs(15),target.write_all(&data)).await.is_ok_and(|r|r.is_ok()){break;},
                                        None => break,
                                    }
                                }
                            }
                        }
                        let _=frame(&writer,3,id,&[]).await;
                    });
                }
                2 => {
                    if let Some(tx) = streams.get(&id) {
                        if tx.try_send(payload).is_err() {
                            streams.remove(&id);
                            let _ = frame(&writer, 3, id, &[]).await;
                        }
                    }
                }
                3 => {
                    streams.remove(&id);
                }
                _ => break,
            }
        }
        tasks.abort_all();
        let _ = writer.lock().await.shutdown().await;
    })
}

impl RuntimeManager {
    pub async fn host_folder_endpoint(
        &self,
        environment: &Environment,
        server: &HostFolderServer,
    ) -> Result<String, String> {
        if let Some(engine) = self.storage_runtime(environment.runtime_id.as_deref().unwrap_or(&environment.id))? { return Box::pin(engine.host_folder_endpoint(environment, server)).await; }

        let id = environment.runtime_id.as_deref().unwrap_or(&environment.id);
        if environment.kind != crate::models::EnvironmentKind::Container {
            self.grant_qemu_host_service(id, server.port, server.network_access(), false).await?;
            return Ok(format!("http://10.0.2.2:{}", server.port));
        }
        self.workload_folder_endpoint(id, environment.provider == Some(RuntimeProviderKind::YougoriCuda), server).await
    }
    pub(super) async fn workload_folder_endpoint(&self, id: &str, cuda: bool, server: &HostFolderServer) -> Result<String, String> {
        if !cuda {
            self.grant_qemu_host_service(id, server.port, server.network_access(), true).await?;
            return Ok(format!("http://10.0.2.2:{}", server.port));
        }
        let ep = self.cuda.current_endpoint().await?;
        let key = format!("{id}:{}", ep.token);
        if let Some(endpoint) = server.relay_endpoint(&key) {
            return Ok(endpoint);
        }
        let endpoint = AgentEndpoint {
            base_url: ep.base_url,
            token: ep.token,
        };
        let (stream, header) = channel(&endpoint, "/v1/host-relay", json!({"id":id})).await?;
        let port = header
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.eq_ignore_ascii_case("yougori-port") || key.eq_ignore_ascii_case("opendock-port"))
                    .and_then(|(_, value)| value.trim().parse::<u16>().ok())
            })
            .filter(|p| *p > 0)
            .ok_or("The guest did not allocate a private relay port")?;
        let url = format!("http://127.0.0.1:{port}");
        server.retain_relay(key, url.clone(), run(stream, server.port));
        Ok(url)
    }
    pub(super) async fn grant_qemu_host_service(&self, id: &str, port: u16, lifetime: std::sync::Weak<std::sync::atomic::AtomicBool>, allow_appliance: bool) -> Result<(), String> {
        let processes = self.vms.lock().await;
        if let Some(process) = processes.get(id) {
            return process.internet.as_ref().ok_or("Restart the VM to enforce host service isolation")?.grant_host_service(port, lifetime);
        }
        drop(processes);
        if !allow_appliance || self.container_provider(id)? != RuntimeProviderKind::YougoriOci {
            return Err("Start the selected environment before attaching a host service".into());
        }
        let appliance = self.appliance.lock().await;
        if let Some(process) = appliance.as_ref() {
            return process.internet.grant_host_service(port, lifetime);
        }
        Err("Start the environment before attaching a host service".into())
    }
}
