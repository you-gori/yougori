use super::RuntimeManager;
use crate::models::*;
use serde_json::json;
use std::path::{Path, PathBuf};

#[tokio::test]
#[ignore = "uses only the explicitly prepared build/cuda/integration-runtime WSL test distribution"]
async fn cuda_individual_storage_limits_grow_online() -> Result<(), String> {
    let root = PathBuf::from(std::env::var("OPENDOCK_CUDA_TEST_ROOT").map_err(|_| "Dedicated CUDA test root is required")?);
    let expected = Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/cuda/integration-runtime").canonicalize().map_err(|e| e.to_string())?;
    if root.canonicalize().map_err(|e| e.to_string())? != expected { return Err("Refusing user CUDA storage".into()); }
    let data = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
    runtime.cuda = yougori_cuda_runtime::CudaRuntime::new(root)?;
    if expected.join("installed.json").exists() { runtime.cuda.recover_abandoned().await?; }
    runtime.install_cuda().await?;
    let id = format!("quota-gpu-{}", uuid::Uuid::new_v4().simple());
    let peer = format!("quota-peer-{}", uuid::Uuid::new_v4().simple());
    let policy: ResourcePolicy = serde_json::from_value(json!({"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0},"priority":"normal","dynamic":true})).unwrap();
    let result = async {
        for (entry, limit) in [(&id, 1.0), (&peer, 2.0)] {
            runtime.register_container_provider(entry, &RuntimeProviderKind::YougoriCuda)?;
            runtime.provision_container_with_storage(entry, "docker.io/library/ubuntu:24.04", "sleep 2147483647", &policy, false, true, limit).await?;
            runtime.container_action(entry, "start", false).await?;
        }
        let full = runtime.execute_container_command(&id, "echo gpu-survives > /root/marker; dd if=/dev/zero of=/root/fill bs=1048576 count=1100").await?;
        if full.exit_code == 0 || !full.stderr.to_lowercase().contains("quota") { return Err(format!("GPU quota was not enforced: {}", full.stderr)); }
        let gpu = runtime.execute_container_command(&peer, "nvidia-smi -L; echo peer-survives > /root/marker").await?;
        if gpu.exit_code != 0 || !gpu.stdout.contains("NVIDIA") { return Err(format!("GPU peer failed: {} {}", gpu.stdout, gpu.stderr)); }
        runtime.set_container_storage(&id, 2.0).await?;
        let expanded = runtime.execute_container_command(&id, "cat /root/marker; dd if=/dev/zero of=/root/more bs=1048576 count=32 && df -k /").await?;
        if expanded.exit_code != 0 { return Err(expanded.stderr); }
        if runtime.container_storage_allocation(&peer).await?.capacity_gb != 2.0 { return Err("GPU peer limit changed".into()); }
        for entry in [&id, &peer] { runtime.container_action(entry, "stop", false).await?; }
        runtime.cuda.shutdown().await?;
        for entry in [&id, &peer] {
            runtime.container_action(entry, "start", false).await?;
            let marker = runtime.execute_container_command(entry, "cat /root/marker").await?;
            let allocation = runtime.container_storage_allocation(entry).await?;
            if marker.exit_code != 0 || !marker.stdout.contains("survives") || allocation.limit_enforced != Some(true) || allocation.capacity_gb != 2.0 { return Err("GPU storage did not survive restart".into()); }
        }
        eprintln!("GPU quota enforced, peer retained NVIDIA access, and online increase/restart preserved files: {}", expanded.stdout);
        Ok(())
    }.await;
    for entry in [&id, &peer] { let _ = runtime.delete_container(entry).await; }
    runtime.shutdown_all().await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "uses only the explicitly prepared build/cuda/integration-runtime WSL test distribution"]
async fn cuda_storage_reclamation_preserves_peer() -> Result<(), String> {
    cuda_cleanup_preserves_peer(true).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "uses only the explicitly prepared build/cuda/integration-runtime WSL test distribution"]
async fn cuda_outdated_runtime_deletion_preserves_peer() -> Result<(), String> {
    cuda_cleanup_preserves_peer(false).await
}

async fn cuda_cleanup_preserves_peer(compact: bool) -> Result<(), String> {
    let root = PathBuf::from(std::env::var("OPENDOCK_CUDA_TEST_ROOT").map_err(|_| "Dedicated CUDA test root is required")?);
    let expected = Path::new(env!("CARGO_MANIFEST_DIR")).join("../build/cuda/integration-runtime").canonicalize().map_err(|e| e.to_string())?;
    if root.canonicalize().map_err(|e| e.to_string())? != expected { return Err("Refusing user CUDA storage".into()); }
    let data = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
    runtime.cuda = yougori_cuda_runtime::CudaRuntime::new(root.clone())?;
    runtime.cuda.recover_abandoned().await?;
    runtime.install_cuda().await?;
    let id = format!("reclaim-delete-{}", uuid::Uuid::new_v4().simple());
    let peer = format!("reclaim-peer-{}", uuid::Uuid::new_v4().simple());
    let outdated = format!("outdated-delete-{}", uuid::Uuid::new_v4().simple());
    let policy: ResourcePolicy = serde_json::from_value(json!({"cpu":{"min":1,"preferred":1,"max":1,"current":0},"memoryGb":{"min":0.5,"preferred":0.5,"max":0.5,"current":0},"priority":"normal","dynamic":true})).unwrap();
    let result = async {
        for entry in [&id, &peer, &outdated] {
            runtime.register_container_provider(entry, &RuntimeProviderKind::YougoriCuda)?;
            runtime.provision_container(entry, "docker.io/library/ubuntu:24.04", "sleep 2147483647", &policy, false, true).await?;
            runtime.container_action(entry, "start", false).await?;
        }
        let mark = runtime.execute_container_command(&peer, "echo peer-safe > /root/reclaim-marker; sync").await?;
        if mark.exit_code != 0 { return Err(mark.stderr); }
        let written = runtime.execute_container_command(&id, "dd if=/dev/urandom of=/root/reclaim-data bs=1048576 count=256; sync").await?;
        if written.exit_code != 0 { return Err(written.stderr); }
        let snapshot_id = format!("cleanup-snapshot-{}", uuid::Uuid::new_v4().simple());
        let snapshot = runtime.create_container_snapshot(&outdated, &snapshot_id, "docker.io/library/ubuntu:24.04", "sleep 2147483647").await?;
        runtime.delete_container(&id).await?;
        let busy = runtime.reclaim_container_storage(&RuntimeProviderKind::YougoriCuda).await?;
        if !busy.warnings.iter().any(|w| w.contains("running or paused")) { return Err(format!("Missing live-workload warning: {:?}", busy)); }
        if runtime.execute_container_command(&peer, "cat /root/reclaim-marker").await?.stdout.trim() != "peer-safe" { return Err("Peer data changed".into()); }
        runtime.container_action(&peer, "stop", false).await?;
        runtime.container_action(&outdated, "stop", false).await?;
        runtime.cuda.shutdown().await?;
        // Simulate an installed application update only in the dedicated test
        // distribution. Cleanup must not require booting its obsolete agent.
        let manifest_path = root.join("installed.json");
        let original_manifest = std::fs::read(&manifest_path).map_err(|e| e.to_string())?;
        let mut obsolete: serde_json::Value = serde_json::from_slice(&original_manifest).map_err(|e| e.to_string())?;
        obsolete["payloadChecksum"] = json!("test-obsolete-payload");
        std::fs::write(&manifest_path, serde_json::to_vec(&obsolete).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let result = async {
            if runtime.require_cuda_installation().await.is_ok() { return Err("Outdated CUDA unexpectedly permits workload starts".into()); }
            runtime.delete_container_snapshot(&outdated, &snapshot_id).await?;
            if snapshot.path.exists() { return Err("Deleted snapshot artifact remains".into()); }
            runtime.delete_container(&outdated).await?;
            runtime.delete_container(&outdated).await?; // Retrying deletion remains safe.
            if runtime.cuda.current_endpoint().await.is_ok() { return Err("Temporary cleanup runtime was left running".into()); }
            if runtime.require_cuda_installation().await.is_ok() { return Err("Cleanup bypassed the normal CUDA update requirement".into()); }
            if compact {
                runtime.reclaim_container_storage(&RuntimeProviderKind::YougoriCuda).await
            } else {
                Ok(StorageCleanupResult::default())
            }
        }.await;
        std::fs::write(&manifest_path, original_manifest).map_err(|e| e.to_string())?;
        let compacted = result?;
        if compact {
            eprintln!("CUDA reclaim: {:?}", compacted);
            if !compacted.warnings.is_empty() { return Err(compacted.warnings.join("; ")); }
            if !compacted.notes.iter().any(|note| note.contains("without starting CUDA")) || runtime.cuda.current_endpoint().await.is_ok() { return Err("Outdated CUDA was started for compaction".into()); }
            if busy.reclaimed_disk_bytes + compacted.reclaimed_disk_bytes < 128 * 1024 * 1024 { return Err("CUDA host disk did not shrink".into()); }
        }
        runtime.container_action(&peer, "start", false).await?;
        if runtime.execute_container_command(&peer, "cat /root/reclaim-marker").await?.stdout.trim() != "peer-safe" { return Err("Peer data did not survive compaction".into()); }
        let probe = runtime.execute_container_command(&peer, "/opendock/bin/cuda-check").await?;
        if probe.exit_code != 0 { return Err(probe.stderr); }
        eprintln!("CUDA deletion and snapshot cleanup succeeded with an outdated runtime; peer files and CUDA kernel survived");
        Ok(())
    }.await;
    for entry in [&id, &peer, &outdated] { let _ = runtime.delete_container(entry).await; }
    runtime.shutdown_all().await;
    result
}

// Return errors rather than panicking so every disposable runtime is shut down
// and test containers are removed even when an integration assertion fails.
macro_rules! ensure {
    ($condition:expr $(, $($message:tt)+)?) => {
        if !$condition {
            return Err(format!(
                "integration check failed at line {}: {}",
                line!(),
                stringify!($condition)
            ));
        }
    };
}
macro_rules! ensure_eq {
    ($left:expr, $right:expr $(, $($message:tt)+)?) => {{
        let (left, right) = (&$left, &$right);
        if left != right {
            return Err(format!(
                "integration check at line {}: {:?} != {:?}",
                line!(),
                left,
                right
            ));
        }
    }};
}
macro_rules! ensure_ne {
    ($left:expr, $right:expr $(, $($message:tt)+)?) => {{
        let (left, right) = (&$left, &$right);
        if left == right {
            return Err(format!(
                "integration check at line {} unexpectedly matched: {:?}",
                line!(),
                left
            ));
        }
    }};
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "uses only the explicitly prepared build/cuda/integration-runtime WSL test distribution"]
async fn cuda_application_lifecycle_files_and_real_kernel() -> Result<(), String> {
    let test_root = PathBuf::from(
        std::env::var("OPENDOCK_CUDA_TEST_ROOT")
            .map_err(|_| "Set OPENDOCK_CUDA_TEST_ROOT to the dedicated integration runtime")?,
    );
    let expected = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../build/cuda/integration-runtime")
        .canonicalize()
        .map_err(|e| e.to_string())?;
    if test_root.canonicalize().map_err(|e| e.to_string())? != expected {
        return Err("Refusing to test against user CUDA storage".into());
    }
    let data = tempfile::tempdir().map_err(|e| e.to_string())?;
    let mut runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
    runtime.cuda = yougori_cuda_runtime::CudaRuntime::new(test_root.clone())?;
    // Recover only this explicitly named test distribution after a failed test.
    runtime.cuda.recover_abandoned().await?;
    runtime.install_cuda().await?;
    let storage = runtime.cuda_storage().await?;
    ensure!(storage.capacity_gb > 0.0 && storage.physical_gb > 0.0);
    let policy:ResourcePolicy=serde_json::from_value(json!({"cpu":{"min":1,"preferred":1,"max":1,"current":1},"memoryGb":{"min":0.5,"preferred":0.5,"max":1,"current":0.5},"priority":"normal","dynamic":true})).unwrap();
    let id = format!("cuda-app-test-{}", uuid::Uuid::new_v4().simple());
    let copy_id = format!("cuda-copy-test-{}", uuid::Uuid::new_v4().simple());
    let snap_id = format!("snapshot-cuda-{}", uuid::Uuid::new_v4().simple());
    let environment:Environment=serde_json::from_value(json!({"id":id,"name":"CUDA integration","kind":"container","provider":"yougoriCuda","status":"running","runtime":"docker.io/library/python:3.12-slim","description":"test","createdAt":"test","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"resourcePolicy":policy})).unwrap();
    let probe = format!(
        "python3 - <<'OPENDOCK_CUDA_TEST'\n{}\nOPENDOCK_CUDA_TEST",
        include_str!("../../../runtime/cuda/kernel-probe.py")
    );
    runtime.register_container_provider(&copy_id, &RuntimeProviderKind::YougoriCuda)?;
    let result=async {
        runtime.register_container_provider(&id,&RuntimeProviderKind::YougoriCuda)?;
        runtime.provision_container(&id,&environment.runtime,"sleep 2147483647",&policy,false,true).await?;
        runtime.container_action(&id,"start",false).await?;
        let result=runtime.execute_container_command(&id,&probe).await?;
        if result.exit_code!=0 || !result.stdout.contains("CUDA KERNEL PASS"){return Err(format!("CUDA computation failed: {result:?}"));}
        eprintln!("{}",result.stdout.trim());
        let verified=runtime.workspace_request(&environment,"/v1/gpu/verify",json!({"id":id})).await?;
        ensure_eq!(verified["exitCode"],0,"CUDA native check: {verified}");
        ensure!(verified["stdout"].as_str().unwrap_or_default().contains("256 GPU results verified"));
        eprintln!("Native C verification tool passed without Python/toolkit dependencies");
        let (cpus,memory)=runtime.cuda_capacity().await?;
        ensure!(cpus>=1.0 && memory>=0.5);
        let live_storage = runtime.cuda_storage().await?;
        ensure_eq!(live_storage.capacity_gb, storage.capacity_gb);
        ensure!(runtime.update_container_resources(&id,cpus+1.0,0.5).await.is_err());
        ensure!(runtime.update_container_resources(&id,1.0,memory+1.0).await.is_err());
        runtime.execute_container_command(&id,"printf persistent > /root/opendock-cuda-test").await?;
        let session_id=format!("terminal-{}",uuid::Uuid::new_v4().simple());
        let terminal=runtime.workspace_request(&environment,"/v1/terminal/create",json!({"id":id,"sessionId":session_id,"cols":80,"rows":24})).await?;
        ensure_eq!(terminal["sessionId"].as_str(),Some(session_id.as_str()));
        ensure_eq!(runtime.container_telemetry(&[id.clone()]).await?.len(),1);
        ensure!(runtime.appliance.lock().await.is_none(),"CUDA started the QEMU appliance");

        let share_dir=data.path().join("shared-test"); std::fs::create_dir(&share_dir).map_err(|e|e.to_string())?;
        std::fs::write(share_dir.join("hello.txt"),b"host-files").map_err(|e|e.to_string())?;
        let server=crate::host_files::HostFolderServer::start(share_dir.clone(),false).await?;
        let endpoint=runtime.host_folder_endpoint(&environment,&server).await?;
        let mounted=runtime.workspace_request(&environment,"/v1/shares/attach",json!({"id":id,"shareId":"share-cuda-test","endpoint":endpoint,"token":server.token,"readOnly":false})).await?;
        let mount=mounted["mountPath"].as_str().ok_or("CUDA host share did not mount")?;
        let files=runtime.execute_container_command(&id,&format!("cat {mount}/hello.txt; printf edited > {mount}/edited.txt")).await?;
        if files.exit_code!=0 || files.stdout!="host-files"{return Err(format!("CUDA My PC sharing failed: {files:?}"));}
        ensure_eq!(std::fs::read(share_dir.join("edited.txt")).unwrap(),b"edited");
        eprintln!("CUDA My PC read/write passed through private loopback relay");
        runtime.workspace_request(&environment,"/v1/shares/detach",json!({"id":id,"shareId":"share-cuda-test"})).await?;
        drop(server);

        let ep=runtime.container_endpoint(&id).await?;
        let (stream,_)=super::host_relay::channel(&ep,"/v1/fabric/stream",json!({"id":id,"address":super::fabric::ip_text(&id),"mac":super::fabric::mac_text(&id)})).await?;
        runtime.fabric.attach(&id,stream)?;
        let net=runtime.execute_container_command(&id,"python3 -c 'import socket; print(socket.if_nameindex())'").await?;
        ensure!(net.stdout.contains("odprivate"),"{net:?}");
        verify_cross_engine_connections(&runtime, &environment, data.path()).await?;
        runtime.container_action(&id,"stop",false).await?;
        let artifact=runtime.create_container_snapshot(&id,&snap_id,&environment.runtime,"sleep 2147483647").await?;
        runtime.import_container_snapshot(&snap_id,&artifact.path).await?;
        runtime.restore_container_snapshot(&copy_id,&snap_id,&environment.runtime,"sleep 2147483647",false,true).await?;
        runtime.container_action(&copy_id,"start",false).await?;
        let restored=runtime.execute_container_command(&copy_id,"cat /root/opendock-cuda-test").await?;
        ensure_eq!(restored.stdout,"persistent");
        ensure_eq!(runtime.execute_container_command(&copy_id,&probe).await?.exit_code,0);
        runtime.container_action(&copy_id,"stop",false).await?;
        runtime.update_container_configuration(&copy_id,false,false,false,true,"sleep 2147483647",&policy).await?;
        runtime.container_action(&copy_id,"start",false).await?;
        let denied=runtime.execute_container_command(&copy_id,&probe).await?;
        ensure_ne!(denied.exit_code,0,"CUDA remained accessible after GPU disconnect");
        let mut copy_environment=environment.clone();copy_environment.id=copy_id.clone();
        let verified=runtime.workspace_request(&copy_environment,"/v1/gpu/verify",json!({"id":copy_id})).await?;
        ensure_ne!(verified["exitCode"],0,"Native CUDA check bypassed GPU denial");
        eprintln!("Snapshot/restore preserved CUDA data; GPU disconnect denied computation");
        runtime.container_action(&copy_id,"stop",false).await?;
        runtime.cuda.shutdown().await?;
        runtime.container_action(&id,"start",false).await?;
        ensure_eq!(runtime.execute_container_command(&id,"cat /root/opendock-cuda-test").await?.stdout,"persistent");
        ensure_eq!(runtime.execute_container_command(&id,&probe).await?.exit_code,0);
        runtime.container_action(&id,"stop",false).await?;
        runtime.delete_container_snapshot(&id,&snap_id).await?;
        // Simulate losing the host process while its dedicated daemon remains.
        // Only our explicitly verified test distribution can be recovered.
        let abandoned = std::mem::replace(&mut runtime.cuda, yougori_cuda_runtime::CudaRuntime::new(test_root.clone())?);
        drop(abandoned);
        let busy = runtime.container_action(&id,"start",false).await.err().ok_or("An orphaned runtime was silently adopted")?;
        ensure!(busy.contains("YOUGORI_RUNTIME_BUSY") || busy.contains("OPENDOCK_RUNTIME_BUSY"),
            "Expected the competing-runtime ownership guard, got: {busy}");
        runtime.recover_container_provider(&RuntimeProviderKind::YougoriCuda).await?;
        runtime.container_action(&id,"start",false).await?;
        ensure_eq!(runtime.execute_container_command(&id,"cat /root/opendock-cuda-test").await?.stdout,"persistent");
        ensure_eq!(runtime.execute_container_command(&id,&probe).await?.exit_code,0);
        eprintln!("Stop-button orphan recovery restored the owned runtime; files and CUDA still passed");
        Ok(())
    }.await;
    for entry in [&id, &copy_id] {
        let _ = runtime.delete_container(entry).await;
    }
    runtime.shutdown_all().await;
    result
}

async fn verify_cross_engine_connections(
    runtime: &RuntimeManager,
    source: &Environment,
    root: &Path,
) -> Result<(), String> {
    let id = format!("oci-link-test-{}", uuid::Uuid::new_v4().simple());
    let connection = format!("conn-cuda-{}", uuid::Uuid::new_v4().simple());
    let mut target = source.clone();
    target.id = id.clone();
    target.name = "OCI bridge test".into();
    target.provider = Some(RuntimeProviderKind::YougoriOci);
    target.runtime = "docker.io/library/python:3.12-slim".into();
    target.gpu_access = false;
    let server_command="set -e; mkdir -p /tmp/od-http; printf private-network > /tmp/od-http/index.html; exec python3 -m http.server 8080 --directory /tmp/od-http";
    target.container_command = Some(server_command.into());
    runtime.register_container_provider(&id, &RuntimeProviderKind::YougoriOci)?;
    let store = crate::store::PlatformStore::load(root.join("test-platform.json"))?;
    let backup = crate::backup::BackupManager::new(root)?;
    let result=async {
        runtime.provision_container(&id,&target.runtime,server_command,&target.resource_policy,false,false).await?;
        runtime.container_action(&id,"start",false).await?;
        runtime.apply_environment_connection(&connection,source,&target,&ConnectionDirection::Bidirectional,&[PermissionKind::Network,PermissionKind::Files],&[]).await?;
        let mount=format!("/yougori/shared/{connection}");
        let written=runtime.execute_container_command(&source.id,&format!("printf cuda-to-oci > {mount}/from-cuda.txt")).await?;
        ensure_eq!(written.exit_code,0,"{written:?}");
        let read=runtime.execute_container_command(&id,&format!("cat {mount}/from-cuda.txt; printf oci-to-cuda > {mount}/from-oci.txt")).await?;
        ensure_eq!(read.stdout,"cuda-to-oci","{read:?}");
        ensure_eq!(runtime.execute_container_command(&source.id,&format!("cat {mount}/from-oci.txt")).await?.stdout,"oci-to-cuda");
        let server=runtime.execute_container_command(&id,"printf migration-data > /root/cuda-migration-marker").await?;
        ensure_eq!(server.exit_code,0,"{server:?}");
        let fetch=format!("python3 -c 'import http.client; c=http.client.HTTPConnection(\"{}\",8080,timeout=5); c.request(\"GET\",\"/\"); print(c.getresponse().read().decode())'",super::fabric::ip_text(&id));
        let response=runtime.execute_container_command(&source.id,&fetch).await?;
        if response.exit_code != 0 {
            let diagnostic=runtime.execute_container_command(&id,"cat /proc/net/tcp; cat /proc/net/dev").await?;
            return Err(format!("Private link failed: {response:?}; target: {diagnostic:?}"));
        }
        ensure_eq!(response.stdout.trim(),"private-network","{response:?}");
        runtime.remove_environment_connection(&connection,&source.id,&id,false).await?;
        ensure_ne!(runtime.execute_container_command(&source.id,&fetch).await?.exit_code,0,"Disconnected network remained reachable");
        eprintln!("CUDA ↔ standard OCI: private TCP and bidirectional files passed; disconnect revoked access");
        runtime.container_action(&id,"stop",false).await?;
        target.status=EnvironmentStatus::Stopped;
        store.mutate(|state| {state.environments=vec![target.clone()];state.connections.clear();state.snapshots.clear();Ok(())})?;
        let destination=root.join("migration-backups");std::fs::create_dir(&destination).map_err(|e|e.to_string())?;
        let path=crate::local_backup::export_backup(id.clone(),destination.to_string_lossy().into_owned(),&store,runtime).await?;
        let restored=crate::local_backup::import_backup_with_provider(path.clone(),Some(RuntimeProviderKind::YougoriCuda),&store,runtime,&backup).await?;
        let new=restored.environments.iter().find(|e|e.id!=id).ok_or("Migrated container missing")?;
        ensure_eq!(new.provider,Some(RuntimeProviderKind::YougoriCuda));ensure!(!new.gpu_access && !new.network_access);
        let new_id=new.runtime_id.as_deref().unwrap_or(&new.id);
        runtime.container_action(new_id,"start",false).await?;
        ensure_eq!(runtime.execute_container_command(new_id,"cat /root/cuda-migration-marker").await?.stdout,"migration-data");
        runtime.container_action(new_id,"stop",false).await?;
        runtime.update_container_configuration(new_id,false,true,false,false,server_command,&target.resource_policy).await?;
        runtime.container_action(new_id,"start",false).await?;
        let verification=runtime.workspace_request(new,"/v1/gpu/verify",json!({"id":new_id})).await?;
        ensure_eq!(verification["exitCode"],0);
        runtime.container_action(&id,"start",false).await?;
        ensure_eq!(runtime.execute_container_command(&id,"cat /root/cuda-migration-marker").await?.stdout,"migration-data");
        ensure!(Path::new(&path).is_file(),"Migration consumed the original backup");
        eprintln!("Portable OCI → CUDA backup migration preserved both original and restored data; no permissions auto-granted");
        Ok(())
    }.await;
    let _ = runtime
        .remove_environment_connection(&connection, &source.id, &id, false)
        .await;
    let _ = runtime.delete_container(&id).await;
    if let Ok(state) = store.snapshot() {
        for env in state
            .environments
            .into_iter()
            .filter(|e| e.provider == Some(RuntimeProviderKind::YougoriCuda))
        {
            let _ = runtime
                .delete_container(env.runtime_id.as_deref().unwrap_or(&env.id))
                .await;
        }
    }
    result
}
