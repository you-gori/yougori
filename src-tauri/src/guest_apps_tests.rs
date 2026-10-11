use super::*;
use std::{path::PathBuf, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "boots an isolated MicroVM, downloads graphical packages and checks app windows without screenshots"]
async fn micro_vm_graphical_apps_end_to_end() {
    let data = tempfile::tempdir().unwrap();
    let runtime =
        RuntimeManager::new(&PathBuf::from(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
    let env: Environment = serde_json::from_value(json!({
        "id":"env-apps-test","runtimeId":"env-apps-test","name":"App test","kind":"microVm","provider":"qemu","status":"running","runtime":"builtin:alpine",
        "description":"isolated graphical test","createdAt":"2026-01-01T00:00:00Z","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
        "resourcePolicy":{"cpu":{"min":1,"preferred":2,"max":2,"current":2},"memoryGb":{"min":0.5,"preferred":2,"max":2,"current":2},"priority":"normal","dynamic":false}
    })).unwrap();
    let result: Result<(),String> = async {
        eprintln!("Booting isolated graphical MicroVM (2 GB)");
        let disk = runtime.provision_micro_vm(&env.id,"builtin:alpine").await?;
        runtime.start_micro_vm(&env.id,&disk.disk_path,&disk.source_path,&env.resource_policy).await?;
        let body = json!({"id":env.id});
        runtime.workspace_request(&env,"/v1/apps/status",body.clone()).await?;
        eprintln!("Installing software display and Firefox inside the test VM");
        runtime.workspace_request(&env,"/v1/apps/install",json!({"id":env.id,"package":"browser"})).await?;
        let deadline = tokio::time::Instant::now()+Duration::from_secs(620);
        loop {
            let state = runtime.workspace_request(&env,"/v1/apps/status",body.clone()).await?;
            if state["installing"] == false {
                if state["ready"] != true || state["browserReady"] != true || state["error"].as_str().is_some_and(|e|!e.is_empty()) {return Err(format!("App install failed: {state}"));}
                break;
            }
            if tokio::time::Instant::now()>deadline {return Err("App installation timed out".into());}
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        for (id,name,command) in [("app-xterm","Terminal","xterm -title YougoriAppSmoke"),("app-firefox","Firefox","firefox --no-remote --new-window about:blank")] {
            runtime.workspace_request(&env,"/v1/apps/launch",json!({"id":env.id,"sessionId":id,"name":name,"command":command})).await?;
        }
        eprintln!("Waiting for two independent app displays");
        let deadline = tokio::time::Instant::now()+Duration::from_secs(35);
        loop {
            let state = runtime.workspace_request(&env,"/v1/apps/status",body.clone()).await?;
            let apps = state["apps"].as_array().ok_or("Missing app list")?;
            if apps.iter().any(|a|a["state"]=="stopped") {return Err(format!("App failed to launch: {state}"));}
            if apps.len()==2 && apps.iter().all(|a|a["state"]=="running") {break;}
            if tokio::time::Instant::now()>deadline {return Err(format!("App start timed out: {state}"));}
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        // Give applications enough time to map windows and expose delayed crashes.
        tokio::time::sleep(Duration::from_secs(5)).await;
        let (base,_) = runtime.workspace_endpoint(&env).await?;
        let client = reqwest::Client::new();
        for id in ["app-xterm","app-firefox"] {
            let denied = client.get(format!("{base}/v1/apps/display?sessionId={id}&key=wrong")).send().await.map_err(|e|e.to_string())?;
            if denied.status()!=403 {return Err("App display accepted a missing/invalid access key".into());}
            let value=runtime.workspace_request(&env,"/v1/apps/view",json!({"id":env.id,"sessionId":id})).await?;
            let key=value["key"].as_str().ok_or("Missing scoped display key")?;
            let endpoint=url::Url::parse(&base).map_err(|e|e.to_string())?;
            let mut stream=tokio::net::TcpStream::connect(("127.0.0.1",endpoint.port().unwrap())).await.map_err(|e|e.to_string())?;
            stream.write_all(format!("GET /v1/apps/display?sessionId={id}&key={key} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: binary\r\n\r\n").as_bytes()).await.map_err(|e|e.to_string())?;
            let mut received=Vec::new();
            tokio::time::timeout(Duration::from_secs(5),async {
                loop {
                    let mut buffer=[0u8;1024];let n=stream.read(&mut buffer).await.map_err(|e|e.to_string())?;
                    if n==0{return Err("Display closed before its RFB greeting".to_string());}
                    received.extend_from_slice(&buffer[..n]);
                    if received.windows(7).any(|w|w==b"RFB 003") {return Ok(());}
                    if received.len()>8192{return Err("Invalid display greeting".to_string());}
                }
            }).await.map_err(|_|"Display handshake timed out")??;
            if !received.starts_with(b"HTTP/1.1 101") {return Err("WebSocket display upgrade failed".into());}
        }
        eprintln!("Checking real X11 windows, user isolation and private display sockets");
        let inspection=runtime.execute_micro_vm_command(&env.id,"apk add --no-cache xwininfo >/dev/null 2>&1 && DISPLAY=:20 xwininfo -root -tree && DISPLAY=:21 xwininfo -root -tree; ps -o user,pid,args | grep -E 'firefox|Xvnc|xterm'; ss -lnt").await?;
        if !inspection.stdout.contains("YougoriAppSmoke") || !inspection.stdout.contains("Mozilla Firefox") {return Err(format!("Graphical app windows missing: {} {}",inspection.stdout,inspection.stderr));}
        if inspection.stdout.contains(":5920") || inspection.stdout.contains(":5921") {return Err("Private VNC display exposed a TCP listener".into());}
        eprintln!("Stopping one app leaves the other running");
        runtime.workspace_request(&env,"/v1/apps/stop",json!({"id":env.id,"sessionId":"app-xterm"})).await?;
        let state=runtime.workspace_request(&env,"/v1/apps/status",body.clone()).await?;
        if state["apps"].as_array().map(Vec::len)!=Some(1) || state["apps"][0]["state"]!="running" {return Err(format!("Stopping one app affected another: {state}"));}
        runtime.workspace_request(&env,"/v1/apps/stop",json!({"id":env.id,"sessionId":"app-firefox"})).await?;
        Ok(())
    }.await;
    runtime.shutdown_all().await;
    result.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "starts the container engine, installs a graphical app inside a container and checks its display without screenshots"]
async fn container_graphical_apps_end_to_end() {
    let data = tempfile::tempdir().unwrap();
    let runtime =
        RuntimeManager::new(&PathBuf::from(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
    let container: Environment = serde_json::from_value(json!({
        "id":"env-container-apps","runtimeId":"env-container-apps","name":"Container app test","kind":"container","provider":"yougoriOci","status":"running","runtime":"docker.io/library/alpine:3.24",
        "description":"graphical container test","createdAt":"2026-01-01T00:00:00Z","networkAccess":true,"cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,
        "resourcePolicy":{"cpu":{"min":0.5,"preferred":1,"max":2,"current":1},"memoryGb":{"min":0.5,"preferred":1,"max":2,"current":1},"priority":"normal","dynamic":false}
    })).unwrap();
    let neighbour = "env-container-apps-neighbour";
    let result: Result<(),String> = async {
        eprintln!("Starting two containers in the shared engine");
        for id in [container.id.as_str(), neighbour] {
            runtime.provision_container_with_storage(id,&container.runtime,"sleep 2147483647",&container.resource_policy,true,false,6.0).await?;
            runtime.container_action(id,"start",true).await?;
        }
        let body = json!({"id":container.id});
        let status = runtime.workspace_request(&container,"/v1/apps/status",body.clone()).await?;
        if status["container"]!=true {return Err(format!("Container apps were not offered: {status}"));}
        eprintln!("Installing the graphical app inside the container image itself");
        let installed = runtime.execute_container_command(&container.id,"apk add --no-cache xterm xwininfo >/dev/null 2>&1; command -v xterm xwininfo").await?;
        if installed.exit_code!=0 {return Err(format!("Test app install failed: {} {}",installed.stdout,installed.stderr));}
        eprintln!("Installing the software display in the container engine");
        runtime.workspace_request(&container,"/v1/apps/install",json!({"id":container.id,"package":"base"})).await?;
        let deadline = tokio::time::Instant::now()+Duration::from_secs(620);
        loop {
            let state = runtime.workspace_request(&container,"/v1/apps/status",body.clone()).await?;
            if state["installing"]==false {
                if state["ready"]!=true || state["error"].as_str().is_some_and(|e|!e.is_empty()) {return Err(format!("App install failed: {state}"));}
                if state["containerNotice"].as_str().is_some_and(|notice|!notice.is_empty()) {return Err(format!("Container is not ready for apps: {state}"));}
                break;
            }
            if tokio::time::Instant::now()>deadline {return Err("App installation timed out".into());}
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        runtime.workspace_request(&container,"/v1/apps/launch",json!({"id":container.id,"sessionId":"app-container","name":"Terminal","command":"xterm -title YougoriContainerApp"})).await?;
        let deadline = tokio::time::Instant::now()+Duration::from_secs(45);
        loop {
            let state = runtime.workspace_request(&container,"/v1/apps/status",body.clone()).await?;
            let apps = state["apps"].as_array().ok_or("Missing app list")?;
            if apps.iter().any(|a|a["state"]=="stopped") {return Err(format!("App failed to launch: {state}"));}
            if apps.len()==1 && apps[0]["state"]=="running" {break;}
            if tokio::time::Instant::now()>deadline {return Err(format!("App start timed out: {state}"));}
            tokio::time::sleep(Duration::from_millis(300)).await;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
        eprintln!("Checking the window, the private socket and the neighbouring container");
        let inspection = runtime.execute_container_command(&container.id,"ls /tmp/.X11-unix; DISPLAY=:20 xwininfo -root -tree").await?;
        if !inspection.stdout.contains("YougoriContainerApp") {return Err(format!("Container app window missing: {} {}",inspection.stdout,inspection.stderr));}
        let other = runtime.execute_container_command(neighbour,"ls -A /tmp/.X11-unix | wc -l").await?;
        if other.stdout.trim()!="0" {return Err(format!("Another container could see this display: {}",other.stdout));}
        let (base,_) = runtime.workspace_endpoint(&container).await?;
        let client = reqwest::Client::new();
        let denied = client.get(format!("{base}/v1/apps/display?sessionId=app-container&key=wrong")).send().await.map_err(|e|e.to_string())?;
        if denied.status()!=403 {return Err("App display accepted a missing/invalid access key".into());}
        let value = runtime.workspace_request(&container,"/v1/apps/view",json!({"id":container.id,"sessionId":"app-container"})).await?;
        let key = value["key"].as_str().ok_or("Missing scoped display key")?;
        let endpoint = url::Url::parse(&base).map_err(|e|e.to_string())?;
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1",endpoint.port().unwrap())).await.map_err(|e|e.to_string())?;
        stream.write_all(format!("GET /v1/apps/display?sessionId=app-container&key={key} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: binary\r\n\r\n").as_bytes()).await.map_err(|e|e.to_string())?;
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(5),async {
            loop {
                let mut buffer=[0u8;1024];let n=stream.read(&mut buffer).await.map_err(|e|e.to_string())?;
                if n==0 {return Err("Display closed before its RFB greeting".to_string());}
                received.extend_from_slice(&buffer[..n]);
                if received.windows(7).any(|w|w==b"RFB 003") {return Ok(());}
                if received.len()>8192 {return Err("Invalid display greeting".to_string());}
            }
        }).await.map_err(|_|"Display handshake timed out")??;
        if !received.starts_with(b"HTTP/1.1 101") {return Err("WebSocket display upgrade failed".into());}
        eprintln!("Stopping the app releases its display and leaves the container running");
        runtime.workspace_request(&container,"/v1/apps/stop",json!({"id":container.id,"sessionId":"app-container"})).await?;
        let state = runtime.workspace_request(&container,"/v1/apps/status",body.clone()).await?;
        if !state["apps"].as_array().is_some_and(Vec::is_empty) {return Err(format!("App session remained: {state}"));}
        let alive = runtime.execute_container_command(&container.id,"ls -A /tmp/.X11-unix | wc -l; printf CONTAINER_OK").await?;
        if !alive.stdout.contains("CONTAINER_OK") || !alive.stdout.contains('0') {return Err(format!("Container or display cleanup failed: {}",alive.stdout));}
        Ok(())
    }.await;
    for id in [container.id.as_str(), neighbour] {
        let _ = runtime.delete_container(id).await;
    }
    runtime.shutdown_all().await;
    result.unwrap();
}
