//! Disposable PC/Q35 guests exercise the same e1000e adapter and socket backend
//! used by Windows/Ubuntu full VMs. The Linux agent is only a test control channel.
use super::*;
use std::{path::Path, process::Stdio};
#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommandResult {
    stdout: String,
    #[serde(rename = "stderr")]
    _stderr: String,
    exit_code: i32,
}

struct Guest {
    child: tokio::process::Child,
    port: u16,
    token: String,
}
impl Guest {
    async fn exec(&self, runtime: &RuntimeManager, command: &str) -> Result<CommandResult, String> {
        runtime
            .client
            .post(format!("http://127.0.0.1:{}/v1/system/exec", self.port))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"command":command}))
            .timeout(Duration::from_secs(8))
            .send()
            .await
            .map_err(|e| e.to_string())?
            .error_for_status()
            .map_err(|e| e.to_string())?
            .json()
            .await
            .map_err(|e| e.to_string())
    }
}
async fn boot(runtime: &RuntimeManager, id: &str) -> Result<Guest, String> {
    let vm = runtime.provision_micro_vm(id, "builtin:alpine").await?;
    let control = super::super::available_port()?;
    let private = super::super::available_port()?;
    let token = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let root = runtime.data_root.join("environments").join(id);
    let serial =
        std::fs::File::create(root.join("pc-test-serial.log")).map_err(|e| e.to_string())?;
    let errors = std::fs::File::create(root.join("pc-test-qemu.log")).map_err(|e| e.to_string())?;
    let mut args=vec!["-name".into(),format!("Yougori test {id}"),"-machine".into(),"q35".into(),"-accel".into(),"tcg,thread=multi".into(),"-cpu".into(),"max".into(),"-m".into(),"512".into(),"-nodefaults".into(),"-display".into(),"none".into(),"-monitor".into(),"none".into(),"-serial".into(),"stdio".into(),
        "-kernel".into(),runtime.layout.appliance_kernel.to_string_lossy().into_owned(),"-initrd".into(),runtime.layout.appliance_initramfs.to_string_lossy().into_owned(),"-append".into(),format!("root=/dev/vda rw rootfstype=ext4 console=ttyS0 quiet modules=virtio_pci,virtio_blk,virtio_net,e1000e,ext4 softlevel=microvm yougori.mode=microvm yougori.token={token}"),
        "-drive".into(),format!("file={},format=qcow2,if=virtio",vm.disk_path.to_string_lossy().replace(',',",,")),"-netdev".into(),format!("user,id=net0,hostfwd=tcp:127.0.0.1:{control}-:7443"),"-device".into(),"virtio-net-pci,netdev=net0".into()];
    args.extend(qemu_args(id, private, false));
    let mut command = tokio::process::Command::new(&runtime.layout.qemu_system);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(serial))
        .stderr(Stdio::from(errors))
        .kill_on_drop(true);
    super::super::configure_background_process(&mut command);
    let child = command.spawn().map_err(|e| e.to_string())?;
    let guest = Guest {
        child,
        port: control,
        token,
    };
    let deadline = Instant::now() + Duration::from_secs(75);
    loop {
        if let Ok(socket) = TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, private)).await {
            runtime.fabric.attach(id, socket)?;
            break;
        }
        if Instant::now() > deadline {
            return Err("PC private socket did not start".into());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    loop {
        if guest.exec(runtime, "true").await.is_ok() {
            break;
        }
        if Instant::now() > deadline {
            return Err(format!(
                "PC guest did not boot: {}",
                std::fs::read_to_string(root.join("pc-test-serial.log")).unwrap_or_default()
            ));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(guest)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "boots two disposable Q35 Linux guests to verify the full-VM e1000e adapter, DHCP and private networking"]
async fn fabric_full_vm_pc_adapters_support_dhcp_and_private_traffic() -> Result<(), String> {
    let data = tempfile::tempdir().unwrap();
    let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path())?;
    let mut a = boot(&runtime, "fabric-pc-a").await?;
    let mut b = boot(&runtime, "fabric-pc-b").await?;
    let result=async {
        for (id,guest) in [("fabric-pc-a",&a),("fabric-pc-b",&b)] {
            let ip=ip_text(id); let mac=mac_text(id);
            // Remove the agent's static test setup and request a real DHCP lease.
            let output=guest.exec(&runtime,&format!(r#"dev=$(for nic in /sys/class/net/*; do [ "$(cat "$nic/address")" = "{mac}" ] && basename "$nic"; done); test -n "$dev" || exit 1; ip addr flush dev "$dev"; ip link set "$dev" up; udhcpc -i "$dev" -n -q -t 3 -T 2; ip -4 addr show dev "$dev"; ip route del default"#)).await?;
            if output.exit_code!=0 || !output.stdout.contains(&ip) { return Err(format!("PC DHCP failed for {id}: {output:?}")); }
        }
        runtime.fabric.apply("pc-link","fabric-pc-a","fabric-pc-b",&ConnectionDirection::OneWay,&[PermissionKind::Network],&[])?;
        let output=a.exec(&runtime,&format!("ping -c 2 -W 2 {}",ip_text("fabric-pc-b"))).await?;
        if output.exit_code!=0 { return Err(format!("PC private link failed: {output:?}")); }
        let reverse=b.exec(&runtime,&format!("ping -c 1 -W 1 {}",ip_text("fabric-pc-a"))).await?;
        if reverse.exit_code==0 { return Err("PC one-way rule allowed reverse traffic".into()); }
        runtime.fabric.remove("pc-link");
        let output=a.exec(&runtime,&format!("ping -c 1 -W 1 {}",ip_text("fabric-pc-b"))).await?;
        if output.exit_code==0 { return Err("PC link remained usable after removal".into()); }
        let env = |id| serde_json::from_value(serde_json::json!({"id":id,"name":id,"kind":"fullVm","status":"running","runtime":"test","description":"","createdAt":"test","cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"resourcePolicy":{"cpu":{"min":1,"preferred":1,"max":1,"current":1},"memoryGb":{"min":1,"preferred":1,"max":1,"current":1},"priority":"normal","dynamic":true}})).unwrap();
        runtime.apply_environment_connection("pc-files",&env("fabric-pc-a"),&env("fabric-pc-b"),&ConnectionDirection::Bidirectional,&[PermissionKind::Files],&[]).await?;
        for command in [r#"wget -T 5 -qO- --header='X-Yougori-Files: 1' --post-data='{"connectionId":"pc-files","operation":"create","path":"hello.txt"}' http://10.192.0.1:7444/api"#,r#"wget -T 5 -qO- --header='X-Yougori-Files: 1' --post-data='{"connectionId":"pc-files","operation":"write","path":"hello.txt","data":"aGVsbG8="}' http://10.192.0.1:7444/api"#] {
            let result=a.exec(&runtime,command).await?; if result.exit_code!=0 {return Err(format!("PC shared file write failed: {result:?}"));}
        }
        let result=b.exec(&runtime,r#"wget -T 5 -qO- --header='X-Yougori-Files: 1' --post-data='{"connectionId":"pc-files","operation":"read","path":"hello.txt","length":5}' http://10.192.0.1:7444/api"#).await?;
        if result.exit_code!=0 || !result.stdout.contains("aGVsbG8=") {return Err(format!("PC shared file read failed: {result:?}"));}
        let large=a.exec(&runtime,r#"printf '%s' '{"connectionId":"pc-files","operation":"write","path":"hello.txt","data":"' >/tmp/od-file-request; head -c 196608 /dev/zero | base64 | tr -d '\n' >>/tmp/od-file-request; printf '%s' '"}' >>/tmp/od-file-request; wget -T 5 -qO- --header='X-Yougori-Files: 1' --post-file=/tmp/od-file-request http://10.192.0.1:7444/api"#).await?;
        if large.exit_code!=0 || !large.stdout.contains("196608") {return Err(format!("PC large upload failed: {large:?}"));}
        let large=b.exec(&runtime,r#"wget -T 5 -qO /tmp/od-file-response --header='X-Yougori-Files: 1' --post-data='{"connectionId":"pc-files","operation":"read","path":"hello.txt","length":196608}' http://10.192.0.1:7444/api && wc -c </tmp/od-file-response"#).await?;
        if large.exit_code!=0 || large.stdout.trim().parse::<usize>().unwrap_or(0)<262144 {return Err(format!("PC large download failed: {large:?}"));}
        let repeated=a.exec(&runtime,"for n in $(seq 1 20); do wget -T 2 -qO /dev/null http://10.192.0.1:7444/connections || exit 1; done").await?;
        if repeated.exit_code!=0 {return Err(format!("PC file HTTP connection reuse failed: {repeated:?}"));}
        let browser=b.exec(&runtime,"wget -T 5 -qO- http://10.192.0.1:7444/").await?;
        if !browser.stdout.contains("Shared files") {return Err(format!("PC file browser missing: {browser:?}"));}
        runtime.remove_environment_connection("pc-files","fabric-pc-a","fabric-pc-b",false).await?;
        let revoked=b.exec(&runtime,r#"wget -T 3 -qO- --header='X-Yougori-Files: 1' --post-data='{"connectionId":"pc-files","operation":"list"}' http://10.192.0.1:7444/api"#).await?;
        if revoked.exit_code==0 {return Err("PC file access remained after disconnect".into());}
        eprintln!("Two full PC guests: DHCP, private network, file create/write/read, browser and revocation without Internet passed."); Ok(())
    }.await;
    let _ = a.child.kill().await;
    let _ = a.child.wait().await;
    let _ = b.child.kill().await;
    let _ = b.child.wait().await;
    runtime.shutdown_all().await;
    result
}
