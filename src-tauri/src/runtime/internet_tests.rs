use super::*;
use crate::models::{Priority, ResourcePolicy, ResourceRange};

fn policy() -> ResourcePolicy {
    ResourcePolicy {
        cpu: ResourceRange { min: 0.5, preferred: 1.0, max: 1.0, current: 0.0 },
        memory_gb: ResourceRange { min: 0.5, preferred: 0.5, max: 0.5, current: 0.0 },
        priority: Priority::Normal, dynamic: false,
    }
}

#[tokio::test]
#[ignore = "boots a disposable OCI appliance and tests real internet without restarting the container"]
async fn live_container_internet_cable_preserves_process_and_routes() -> Result<(), String> {
    let data = tempfile::tempdir().unwrap();
    let manager = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
    let id = "env-live-internet";
    let fetch = "wget -T 8 -qO- https://example.com | grep -q 'Example Domain'";
    let result = async {
        manager.provision_container(id, "quay.io/libpod/alpine:latest", "sleep 2147483647", &policy(), false, false).await?;
        manager.container_action(id, "start", false).await?;
        let before = manager.execute_container_command(id, "cat /proc/1/stat; echo alive > /tmp/internet-marker").await?;
        assert_ne!(manager.execute_container_command(id, fetch).await?.exit_code, 0);
        for _ in 0..2 {
            manager.update_container_internet(id, true).await?;
            let online = manager.execute_container_command(id, fetch).await?;
            assert_eq!(online.exit_code, 0, "online: {}", online.stderr);
            assert_ne!(manager.execute_container_command(id, "ping -c 1 -W 1 10.0.2.2").await?.exit_code, 0);
            manager.update_container_internet(id, false).await?;
            manager.update_container_internet(id, false).await?;
            assert_ne!(manager.execute_container_command(id, fetch).await?.exit_code, 0);
            let after = manager.execute_container_command(id, "cat /proc/1/stat; test -f /tmp/internet-marker").await?;
            assert_eq!(after.exit_code, 0);
            assert_eq!(before.stdout.split_whitespace().nth(21), after.stdout.split_whitespace().nth(21));
        }
        manager.container_action(id, "pause", false).await?;
        manager.update_container_internet(id, true).await?;
        manager.container_action(id, "resume", true).await?;
        assert_eq!(manager.execute_container_command(id, fetch).await?.exit_code, 0);
        manager.container_action(id, "stop", true).await?;
        manager.container_action(id, "start", false).await?;
        assert_ne!(manager.execute_container_command(id, fetch).await?.exit_code, 0);
        manager.update_container_internet(id, true).await?;
        assert_eq!(manager.execute_container_command(id, fetch).await?.exit_code, 0);
        manager.container_action(id, "restart", true).await?;
        assert_eq!(manager.execute_container_command(id, fetch).await?.exit_code, 0);
        manager.delete_container(id).await?;
        Ok(())
    }.await;
    manager.shutdown_all().await;
    result
}

#[tokio::test]
#[ignore = "boots a disposable OCI appliance; containerd restarts the container by its own policy"]
async fn container_restarted_by_its_policy_regains_its_internet() -> Result<(), String> {
    let data = tempfile::tempdir().unwrap();
    let manager = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
    let id = "env-restart-internet";
    let fetch = "wget -T 8 -qO- https://example.com | grep -q 'Example Domain'";
    // Exits with an error after a while, so containerd starts it again in a new network namespace.
    let command = "sh -c 'sleep 40; exit 1'";
    let started = |stat: &str| stat.split_whitespace().nth(21).map(str::to_owned);
    let result = async {
        manager.provision_container(id, "quay.io/libpod/alpine:latest", command, &policy(), true, false).await?;
        let mut options = manager.workload_options(id)?;
        options.restart = "on-failure".into();
        manager.save_workload_options(id, &options)?;
        manager.update_container_configuration(id, true, false, true, false, command, &policy()).await?;
        manager.container_action(id, "start", true).await?;
        let first = started(&manager.execute_container_command(id, "cat /proc/1/stat").await?.stdout);
        assert_eq!(manager.execute_container_command(id, fetch).await?.exit_code, 0);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(150);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            let Ok(stat) = manager.execute_container_command(id, "cat /proc/1/stat").await else { continue };
            if stat.exit_code == 0 && started(&stat.stdout).is_some() && started(&stat.stdout) != first {
                break;
            }
            assert!(std::time::Instant::now() < deadline, "containerd did not restart the container");
        }
        // Nothing on the host asked for this: the agent restores the enabled uplink.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
        while manager.execute_container_command(id, fetch).await?.exit_code != 0 {
            assert!(std::time::Instant::now() < deadline, "restarted container stayed offline");
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
        manager.delete_container(id).await?;
        Ok(())
    }.await;
    manager.shutdown_all().await;
    result
}

#[tokio::test]
#[ignore = "boots a disposable full VM and verifies its live link through QMP"]
async fn live_vm_internet_cable_preserves_process_and_display() -> Result<(), String> {
    let data = tempfile::tempdir().unwrap();
    let manager = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
    let id = "env-live-vm-internet";
    let result = async {
        let source = data.path().join("source.qcow2");
        command_output(&manager.layout.qemu_img, &["create".into(), "-f".into(), "qcow2".into(), source.to_string_lossy().into_owned(), "128M".into()], "test disk").await?;
        let disk = manager.provision_vm(id, source.to_str().unwrap()).await?;
        for initial in [false, true, false] {
            let console = manager.start_vm_with_network(id, &disk.disk_path, &disk.source_path, &policy(), false, initial).await?;
            let (pid, port) = { let vms = manager.vms.lock().await; let vm = vms.get(id).unwrap(); (vm.process_id, vm.qmp.clone()) };
            for enabled in [true, false, false, true] {
                manager.update_vm_internet(id, enabled).await?;
                assert_eq!(manager.vms.lock().await.get(id).unwrap().process_id, pid);
                assert_eq!(vm::qmp_request(&port, "query-status", None).await?["running"], true);
                let display_port: u16 = console.websocket_url.rsplit(':').next().unwrap().parse().unwrap();
                tokio::net::TcpStream::connect(("127.0.0.1", display_port)).await.map_err(|e| e.to_string())?;
            }
            manager.vm_action(id, "pause").await?;
            manager.update_vm_internet(id, false).await?;
            assert_eq!(vm::qmp_request(&port, "query-status", None).await?["running"], false);
            manager.vm_action(id, "stop").await?;
        }
        Ok(())
    }.await;
    manager.shutdown_all().await;
    result
}
