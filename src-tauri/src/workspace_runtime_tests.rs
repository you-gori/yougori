use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};

fn print_guest_logs(directory: &Path) {
    use std::io::{Read, Seek, SeekFrom};

    for name in ["qemu.log", "serial.log"] {
        let Ok(mut file) = std::fs::File::open(directory.join(name)) else { continue };
        let length = file.metadata().map(|metadata| metadata.len()).unwrap_or(0);
        let _ = file.seek(SeekFrom::Start(length.saturating_sub(16 * 1024)));
        let mut bytes = Vec::new();
        let _ = file.take(16 * 1024).read_to_end(&mut bytes);
        eprintln!("Guest {name} (last 16 KiB):");
        for line in String::from_utf8_lossy(&bytes).lines() {
            if line.contains("yougori.token=") {
                eprintln!("[guest command line containing authentication token omitted]");
            } else {
                eprintln!("{line}");
            }
        }
    }
}

fn fixture(id: &str, kind: &str) -> Environment {
    serde_json::from_value(json!({
        "id":id,"name":id,"kind":kind,"status":"running","runtime":"builtin:alpine",
        "provider":if kind=="container"{"yougoriOci"}else{"qemu"},"runtimeId":id,
        "description":"workspace integration fixture","createdAt":"2026-01-01T00:00:00Z",
        "cpuUsage":0,"memoryUsageGb":0,"storageDeltaGb":0,"networkRxMbps":0,"networkAccess":kind=="container",
        "resourcePolicy":{"cpu":{"min":0.5,"preferred":1,"max":1,"current":1},"memoryGb":{"min":0.125,"preferred":0.25,"max":0.5,"current":0.25},"priority":"normal","dynamic":true}
    })).unwrap()
}

#[test]
fn ordinary_share_metadata_omits_bearer_capability() {
    let share=HostShare{id:"share-test".into(),environment_id:"env-test".into(),path:"selected-only".into(),read_only:true,mount_path:None,guest_url:"http://localhost:1234/private-bearer/".into()};
    let value=serde_json::to_value(&share).unwrap();
    assert!(value.get("guestUrl").is_none());
    assert!(!value.to_string().contains("private-bearer"));
}
#[test]
fn bounded_log_cursors_return_only_new_output_and_detect_rotation() {
    let first=log_window("first line\n",None,64,64).unwrap();
    let next=log_window("first line\nsecond line\n",first["nextCursor"].as_str(),64,64).unwrap();
    assert_eq!(next["stdout"],"second line\n");
    let same=log_window("first line\nsecond line\n",next["nextCursor"].as_str(),64,64).unwrap();
    assert_eq!(same["stdout"],"");
    let rotated=log_window("new rotated log\n",next["nextCursor"].as_str(),64,64).unwrap();
    assert_eq!(rotated["rotated"],true);assert_eq!(rotated["stdout"],"new rotated log\n");
    let unicode=log_window("αβγ",None,3,6).unwrap();assert_eq!(unicode["stdout"],"α");assert_eq!(unicode["truncated"],true);
    assert!(log_window("hello",Some("not-a-cursor"),64,64).is_err());
}
#[test]fn protected_log_output_withholds_split_secrets_and_keeps_byte_cursors(){
    let secrets=vec!["protected-credential".to_owned(),"aaaa".to_owned(),"日本語-key".to_owned()];
    let first=mask_secret_output("ordinary\nprotected-cred",&secrets,true);assert_eq!(first,"ordinary\n");
    let initial=log_window(&first,None,64,64).unwrap();
    let complete=mask_secret_output("ordinary\nprotected-credential\n",&secrets,true);let next=log_window(&complete,initial["nextCursor"].as_str(),64,64).unwrap();assert_eq!(next["stdout"],"********************\n");
    assert_eq!(mask_secret_output("aaaa",&secrets,true),"****");
    let unicode=mask_secret_output("日本語-key\n",&secrets,true);assert_eq!(unicode.len(),"日本語-key\n".len());assert!(!unicode.contains("日本語"));
}
async fn fixture_listener(manager:&WorkspaceManager,id:&str,environment_id:&str,kind:PublicationKind)->u16{
    let listener=TcpListener::bind(("127.0.0.1",0)).await.unwrap();let port=listener.local_addr().unwrap().port();
    let task=tokio::spawn(async move{while let Ok((mut stream,_))=listener.accept().await{let _=stream.write_all(b"still available").await;}});
    manager.publications.lock().await.insert(id.into(),LivePublication{info:Publication{id:id.into(),environment_id:environment_id.into(),port:8080,kind,host_port:port,urls:vec![format!("http://127.0.0.1:{port}")],status:"active".into(),message:"fixture".into(),cloudflare_account:false},task:Arc::new(ListenerTask(task)),cloudflare:None,logs:None,tunnel_id:None,_cloudflare_config:None,_vm_forward:None});
    port
}
#[tokio::test]
async fn publication_listener_reuse_keeps_original_and_survives_original_removal(){
    let data=tempfile::tempdir().unwrap();let runtime=RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")),data.path()).unwrap();let manager=WorkspaceManager::new(data.path());let store=PlatformStore::load(data.path().join("state.json")).unwrap();let env=fixture("env-reuse","fullVm");store.mutate(|s|{s.environments.push(env.clone());Ok(())}).unwrap();
    let port=fixture_listener(&manager,"pub-original",&env.id,PublicationKind::Cloudflare).await;
    let plan=publication_plan(&env.id,8080,&PublicationKind::Loopback,Some(port),None,&store,&manager).await.unwrap();assert_eq!(plan["action"],"reuseListener");assert_eq!(plan["allowed"],true);
    let published=publish_service(env.id.clone(),8080,PublicationKind::Loopback,Some(port),None,&store,&runtime,&manager).await.unwrap();assert_ne!(published.id,"pub-original");
    assert_eq!(published.urls,vec![format!("http://127.0.0.1:{port}")],"loopback-only listeners must not advertise LAN or guest-network access");
    manager.publications.lock().await.remove("pub-original");
    let mut stream=TcpStream::connect(("127.0.0.1",port)).await.unwrap();let mut bytes=Vec::new();stream.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes,b"still available");
    manager.shutdown(&runtime).await;
    tokio::time::sleep(Duration::from_millis(30)).await;assert!(TcpStream::connect(("127.0.0.1",port)).await.is_err());
    let saved=publication_metadata(&env.id,&store,&manager).await.unwrap();
    assert_eq!(saved.iter().find(|publication|publication.id==published.id).unwrap().urls,vec![format!("http://127.0.0.1:{port}")],"saved loopback intent must retain the same access scope");
}
#[tokio::test]
async fn failed_owned_route_transition_restores_working_listener_and_saved_intent(){
    let data=tempfile::tempdir().unwrap();let runtime=RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")),data.path()).unwrap();let manager=WorkspaceManager::new(data.path());let store=PlatformStore::load(data.path().join("state.json")).unwrap();let env=fixture("env-rollback","fullVm");store.mutate(|s|{s.environments.push(env.clone());Ok(())}).unwrap();
    let port=fixture_listener(&manager,"pub-original",&env.id,PublicationKind::Loopback).await;
    store.mutate(|s|{s.saved_environment_services.push(crate::models::SavedEnvironmentService{id:"pub-original".into(),environment_id:env.id.clone(),port:8080,kind:PublicationKind::Loopback,host_port:port,domain:None,cloudflare_hostname:None,remembered_account:false});Ok(())}).unwrap();
    let other=TcpListener::bind(("127.0.0.1",0)).await.unwrap();let other_port=other.local_addr().unwrap().port();
    assert!(publish_service(env.id.clone(),8080,PublicationKind::Loopback,Some(other_port),None,&store,&runtime,&manager).await.is_err());
    let restored=manager.publications.lock().await.get("pub-original").unwrap().info.clone();assert_eq!(restored.host_port,port);assert_eq!(store.snapshot().unwrap().saved_environment_services[0].host_port,port);
    let mut stream=TcpStream::connect(("127.0.0.1",port)).await.unwrap();let mut bytes=Vec::new();stream.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes,b"still available");
    store.mutate(|state|{state.environments.push(fixture("env-other","fullVm"));Ok(())}).unwrap();
    let conflict=publication_plan("env-other",8080,&PublicationKind::Loopback,Some(port),None,&store,&manager).await.unwrap();
    assert_eq!(conflict["allowed"],false);assert_eq!(conflict["owner"]["id"],"pub-original");
    let replacement=publication_plan(&env.id,8080,&PublicationKind::Loopback,Some(other_port),None,&store,&manager).await.unwrap();
    assert_eq!(replacement["allowed"],false);assert_eq!(replacement["owner"]["type"],"externalProcess");assert_eq!(replacement["existing"]["id"],"pub-original");
    manager.shutdown(&runtime).await;
}

#[tokio::test]
async fn saved_domain_transition_failure_preserves_old_route_and_domain_intent(){
    let data=tempfile::tempdir().unwrap();let runtime=RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")),data.path()).unwrap();let manager=WorkspaceManager::new(data.path());let store=PlatformStore::load(data.path().join("state.json")).unwrap();let env=fixture("env-domain-rollback","fullVm");store.mutate(|s|{s.environments.push(env.clone());Ok(())}).unwrap();
    let port=fixture_listener(&manager,"pub-domain",&env.id,PublicationKind::Cloudflare).await;
    {let mut routes=manager.publications.lock().await;let route=routes.get_mut("pub-domain").unwrap();route.info.cloudflare_account=true;route.info.urls=vec!["https://old.fixture.invalid".into()];route.tunnel_id=Some("01234567-89ab-4def-8123-456789abcdef".into());}
    store.mutate(|s|{s.saved_domains.push(crate::models::SavedDomain{id:"saved-fixture-domain".into(),credential_environment_id:"fixture-only".into(),port:8080,hostname:"old.fixture.invalid".into(),host_port:port});s.saved_environment_services.push(crate::models::SavedEnvironmentService{id:"pub-domain".into(),environment_id:env.id.clone(),port:8080,kind:PublicationKind::Cloudflare,host_port:port,domain:Some("saved-fixture-domain".into()),cloudflare_hostname:Some("old.fixture.invalid".into()),remembered_account:true});Ok(())}).unwrap();
    let before=serde_json::to_value(&store.snapshot().unwrap().saved_environment_services).unwrap();
    let occupied=TcpListener::bind(("127.0.0.1",0)).await.unwrap();let occupied_port=occupied.local_addr().unwrap().port();
    let token=STANDARD.encode(serde_json::to_vec(&json!({"a":"0123456789abcdef0123456789abcdef","t":"01234567-89ab-4def-8123-456789abcdef","s":STANDARD.encode([7u8;32])})).unwrap());
    let options=cloudflare::AccountOptions{hostname:"new.fixture.invalid".into(),token:Some(token.clone()),preset_id:None,preset_source_environment_id:None,preset_port:None,remember:false,routes_reviewed:true};
    let plan=publication_plan(&env.id,8080,&PublicationKind::Cloudflare,Some(occupied_port),Some(options.clone()),&store,&manager).await.unwrap();assert_eq!(plan["allowed"],false);assert_eq!(plan["owner"]["type"],"externalProcess");assert!(!plan.to_string().contains(&token));
    // The fixture has no guest/QMP endpoint, so replacement fails before any public tunnel starts.
    let error=match publish_service(env.id.clone(),8080,PublicationKind::Cloudflare,Some(occupied_port),Some(options),&store,&runtime,&manager).await{Err(error)=>error,Ok(_)=>panic!("Invalid fixture replacement must fail before public publication")};assert!(!error.contains(&token));
    assert_eq!(manager.publications.lock().await["pub-domain"].info.urls,vec!["https://old.fixture.invalid"]);assert_eq!(serde_json::to_value(&store.snapshot().unwrap().saved_environment_services).unwrap(),before);assert_eq!(store.snapshot().unwrap().saved_domains[0].hostname,"old.fixture.invalid");
    let mut stream=TcpStream::connect(("127.0.0.1",port)).await.unwrap();let mut bytes=Vec::new();stream.read_to_end(&mut bytes).await.unwrap();assert_eq!(bytes,b"still available");manager.shutdown(&runtime).await;
}

#[tokio::test]
async fn interrupted_saved_publication_reuses_its_id_and_failed_live_route_is_not_reused(){
    let data=tempfile::tempdir().unwrap();let runtime=RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")),data.path()).unwrap();let manager=WorkspaceManager::new(data.path());let store=PlatformStore::load(data.path().join("state.json")).unwrap();let env=fixture("env-saved-publication","fullVm");store.mutate(|s|{s.environments.push(env.clone());Ok(())}).unwrap();
    let port=fixture_listener(&manager,"pub-compatible-listener",&env.id,PublicationKind::Cloudflare).await;
    store.mutate(|s|{s.saved_environment_services.push(crate::models::SavedEnvironmentService{id:"pub-saved-stable".into(),environment_id:env.id.clone(),port:8080,kind:PublicationKind::Loopback,host_port:port,domain:None,cloudflare_hostname:None,remembered_account:false});Ok(())}).unwrap();
    let saved=publication_metadata(&env.id,&store,&manager).await.unwrap();assert_eq!(saved.iter().find(|p|p.id=="pub-saved-stable").unwrap().status,"error");
    let resumed=publish_service(env.id.clone(),8080,PublicationKind::Loopback,Some(port),None,&store,&runtime,&manager).await.unwrap();assert_eq!(resumed.id,"pub-saved-stable");assert_eq!(store.snapshot().unwrap().saved_environment_services.len(),1);
    manager.publications.lock().await.get_mut("pub-saved-stable").unwrap().info.status="error".into();
    let plan=publication_plan(&env.id,8080,&PublicationKind::Loopback,Some(port),None,&store,&manager).await.unwrap();assert_eq!(plan["action"],"replaceOwnedRoute");
    let retried=publish_service(env.id.clone(),8080,PublicationKind::Loopback,Some(port),None,&store,&runtime,&manager).await.unwrap();assert_eq!(retried.id,"pub-saved-stable");assert_eq!(retried.status,"active");assert_eq!(store.snapshot().unwrap().saved_environment_services.len(),1);manager.shutdown(&runtime).await;
}

#[tokio::test]
async fn cloud_model_publications_remain_visible_and_revocable() {
    let data = tempfile::tempdir().unwrap();
    let runtime = RuntimeManager::new(&PathBuf::from(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
    let manager = WorkspaceManager::new(data.path());
    let store = PlatformStore::load(data.path().join("state.json")).unwrap();
    let mut env = fixture("env-cloud-model", "container");
    env.kind = EnvironmentKind::Cloud;
    store.mutate(|state| { state.environments.push(env.clone()); Ok(()) }).unwrap();
    for (id, environment_id, kind, url) in [
        ("pub-model", env.id.as_str(), PublicationKind::Cloudflare, "https://model.example.com"),
        ("pub-local", env.id.as_str(), PublicationKind::Loopback, "http://127.0.0.1:45000"),
        ("pub-other", "env-other", PublicationKind::Cloudflare, "https://other.example.com"),
    ] {
        manager.publications.lock().await.insert(id.into(), LivePublication {
            info: Publication {
                id: id.into(), environment_id: environment_id.into(), port: 8000,
                kind, host_port: 45000, urls: vec![url.into()], status: "active".into(),
                message: String::new(), cloudflare_account: false,
            },
            task: Arc::new(ListenerTask(tokio::spawn(std::future::pending()))), cloudflare: None, logs: None,
            tunnel_id: None, _cloudflare_config: None, _vm_forward: None,
        });
    }
    let services = list_services(&env.id, &store, &runtime, &manager).await.unwrap();
    let publications = services["publications"].as_array().unwrap();
    assert_eq!(publications.len(), 2);
    assert!(publications.iter().any(|p| p["id"] == "pub-model" && p["urls"][0] == "https://model.example.com"));
    assert!(publications.iter().any(|p| p["id"] == "pub-local"));
    assert_eq!(services["services"], json!([]));
    assert_eq!(services["shares"], json!([]));
    manager.publications.lock().await.remove("pub-model");
    manager.publications.lock().await.remove("pub-local");
    let services = list_services(&env.id, &store, &runtime, &manager).await.unwrap();
    assert_eq!(services["publications"], json!([]));
    assert!(manager.publications.lock().await.contains_key("pub-other"));
}

async fn exercise_workspace(kind: &str) -> Result<(), String> {
    let data = tempfile::tempdir().unwrap();
    let selected = tempfile::tempdir().unwrap();
    std::fs::write(selected.path().join("hello.txt"), "selected-folder-only").unwrap();
    let runtime = RuntimeManager::new(&PathBuf::from(env!("CARGO_MANIFEST_DIR")), data.path())?;
    let manager = WorkspaceManager::new(data.path());
    let store = PlatformStore::load(data.path().join("platform-state.json"))?;
    let env = fixture("env-workspace-test", kind);
    let result=async {
        eprintln!("Booting isolated {kind} workspace fixture");
        if kind=="container" {
            runtime.provision_container(&env.id,"quay.io/libpod/alpine:latest","sleep 2147483647",&env.resource_policy,true,false).await?;
            eprintln!("Container provisioned; starting its process and internet connection");
            runtime.container_action(&env.id,"start",true).await?;
        } else {
            let provisioned=runtime.provision_micro_vm(&env.id,"builtin:alpine").await?;
            runtime.start_micro_vm(&env.id,&provisioned.disk_path,&provisioned.source_path,&env.resource_policy).await?;
        }
        store.mutate(|s|{s.environments.push(env.clone());Ok(())})?;
        eprintln!("Checking independent persistent PTYs");
        let request=|action:&str,session:&str,data:&str| (format!("/v1/terminal/{action}"),json!({"id":env.id,"sessionId":session,"data":data,"cols":100,"rows":30}));
        for session in ["term-one","term-two"] {let(path,body)=request("create",session,"");runtime.workspace_request(&env,&path,body).await?;}
        let(path,body)=request("write","term-one",&STANDARD.encode(b"export OD_SESSION_MARKER=one; cd /tmp; printf 'READY:%s:%s\\n' \"$OD_SESSION_MARKER\" \"$PWD\"\r"));runtime.workspace_request(&env,&path,body).await?;
        let(path,body)=request("write","term-two",&STANDARD.encode(b"printf 'SECOND:%s\\n' \"${OD_SESSION_MARKER:-empty}\"\r"));runtime.workspace_request(&env,&path,body).await?;
        for(session,expected)in[("term-one","READY:one:/tmp"),("term-two","SECOND:empty")] {
            let deadline=tokio::time::Instant::now()+Duration::from_secs(12);
            loop {let(path,body)=request("read",session,"");let output=runtime.workspace_request(&env,&path,body).await?;let bytes=STANDARD.decode(output["data"].as_str().unwrap_or_default()).map_err(|e|e.to_string())?;if String::from_utf8_lossy(&bytes).contains(expected){break}if tokio::time::Instant::now()>deadline{return Err(format!("Terminal did not produce {expected}: {}",String::from_utf8_lossy(&bytes)));}tokio::time::sleep(Duration::from_millis(150)).await;}
        }
        eprintln!("Checking the workspace file editor's guest commands");
        let guest=|command:String|{let runtime=&runtime;let id=env.id.clone();async move{if kind=="container"{runtime.execute_container_command(&id,&command).await}else{runtime.execute_micro_vm_command(&id,&command).await}}};
        let expect_ok=|label:&'static str,output:crate::models::CommandResult|->Result<String,String>{if output.exit_code!=0{return Err(format!("{label}: {} {}",output.stdout,output.stderr));}Ok(output.stdout)};
        expect_ok("prepare editor folder",guest("mkdir -p /tmp/editor-demo/nested && printf 'first line\\n' > /tmp/editor-demo/notes.txt".into()).await?)?;
        // The exact command shapes the Files tab sends, checked against this
        // guest's real shell and coreutils/BusyBox tools.
        let listing=expect_ok("list",guest("cd '/tmp/editor-demo' && pwd && ls -A -p".into()).await?)?;
        if !listing.starts_with("/tmp/editor-demo")||!listing.contains("nested/")||!listing.contains("notes.txt"){return Err(format!("File listing: {listing}"));}
        let size=expect_ok("size",guest("wc -c < '/tmp/editor-demo/notes.txt'".into()).await?)?;
        if size.trim()!="11"{return Err(format!("File size: {size}"));}
        let encoded=expect_ok("read",guest("base64 '/tmp/editor-demo/notes.txt'".into()).await?)?;
        if String::from_utf8(STANDARD.decode(encoded.replace(['\n','\r'],"")).map_err(|e|e.to_string())?).map_err(|e|e.to_string())?!="first line\n"{return Err("Editor read returned different bytes".into());}
        let payload=STANDARD.encode(b"saved by the workspace\n");
        expect_ok("truncate",guest(": > '/tmp/editor-demo/notes.txt.yougori-save'".into()).await?)?;
        expect_ok("append",guest(format!("printf %s '{payload}' >> '/tmp/editor-demo/notes.txt.yougori-save'")).await?)?;
        expect_ok("replace",guest("base64 -d < '/tmp/editor-demo/notes.txt.yougori-save' > '/tmp/editor-demo/notes.txt' && rm -f '/tmp/editor-demo/notes.txt.yougori-save'".into()).await?)?;
        let saved=expect_ok("verify",guest("cat '/tmp/editor-demo/notes.txt'".into()).await?)?;
        if saved!="saved by the workspace\n"{return Err(format!("Editor save wrote: {saved}"));}
        expect_ok("create file",guest("set -C && : > '/tmp/editor-demo/created.txt'".into()).await?)?;
        if guest("set -C && : > '/tmp/editor-demo/created.txt'".into()).await?.exit_code==0{return Err("Creating an existing file overwrote it".into());}
        expect_ok("delete file",guest("rm -f -- '/tmp/editor-demo/created.txt'".into()).await?)?;
        expect_ok("delete folder",guest("rmdir '/tmp/editor-demo/nested'".into()).await?)?;
        eprintln!("Starting a localhost-only guest HTTP service");
        let command="/bin/busybox sh -c 'while true; do printf \"HTTP/1.1 200 OK\\r\\nContent-Length: 17\\r\\nConnection: close\\r\\n\\r\\nworkspace-http-ok\" | /bin/busybox nc -l -s 127.0.0.1 -p 4200 -w 2; done' </dev/null >/tmp/yougori-workspace-server.log 2>&1 &";
        let output=if kind=="container"{runtime.execute_container_command(&env.id,command).await?}else{runtime.execute_micro_vm_command(&env.id,command).await?};
        if output.exit_code!=0{return Err(format!("Test HTTP server: {}",output.stderr));}
        tokio::time::sleep(Duration::from_millis(400)).await;
        let services=runtime.workspace_request(&env,"/v1/services/list",json!({"id":env.id})).await?;
        if !services.as_array().unwrap().iter().any(|s|s["port"]==4200){return Err(format!("Missing service discovery: {services}"));}
        let publication=publish_service(env.id.clone(),4200,PublicationKind::Local,None,None,&store,&runtime,&manager).await?;
        let client=reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap();
        let output=client.get(format!("http://127.0.0.1:{}",publication.host_port)).send().await.map_err(|e|e.to_string())?.text().await.map_err(|e|e.to_string())?;
        if output!="workspace-http-ok"{return Err(format!("Guest forwarding returned {output}"));}
        if kind=="container" {
            let output=runtime.execute_container_command(&env.id,&format!("wget -q -T 5 -O - http://10.0.2.2:{}",publication.host_port)).await?;
            if output.exit_code!=0||output.stdout!="workspace-http-ok"{return Err(format!("Local guest route: {} {}",output.stdout,output.stderr));}
            let blocked=runtime.execute_container_command(&env.id,"ping -c 1 -W 1 10.0.2.2 >/dev/null 2>&1").await?;
            if blocked.exit_code==0{return Err("Local publishing opened unrelated host access".into());}
        }
        eprintln!("Checking selected-folder FUSE mounts, write permissions and revocation");
        for read_only in [true,false] {
            let share=attach_folder(env.id.clone(),selected.path().to_string_lossy().into_owned(),read_only,&store,&runtime,&manager).await?;
            let mount=share.mount_path.as_ref().ok_or("Missing FUSE mount")?;
            let command=format!("cat '{mount}/hello.txt'; printf changed > '{mount}/written.txt'");
            let output=if kind=="container"{runtime.execute_container_command(&env.id,&command).await?}else{runtime.execute_micro_vm_command(&env.id,&command).await?};
            if output.stdout!="selected-folder-only"{return Err(format!("Read shared folder: {} {}",output.stdout,output.stderr));}
            if read_only && output.exit_code==0{return Err("Read-only share allowed a write".into());}
            if !read_only && (output.exit_code!=0||std::fs::read_to_string(selected.path().join("written.txt")).unwrap_or_default()!="changed"){return Err(format!("Writable share failed: {}",output.stderr));}
            manager.remove_share(&share.id,&runtime).await;
            let uri=url::Url::parse(&share.guest_url).unwrap();
            if client.get(format!("http://127.0.0.1:{}{}",uri.port().unwrap(),uri.path())).send().await.is_ok(){return Err("Share server still accessible after disconnect".into());}
        }
        for session in ["term-one","term-two"] {let(path,body)=request("close",session,"");runtime.workspace_request(&env,&path,body).await?;}
        if kind=="container"{runtime.container_action(&env.id,"stop",true).await?;}else{runtime.vm_action(&env.id,"stop").await?;}
        store.mutate(|s|{s.environments[0].status=EnvironmentStatus::Stopped;Ok(())})?;
        manager.cleanup(&store,&runtime).await;
        if !manager.publications.lock().await.is_empty(){return Err("Publication survived stopping the environment".into());}
        tokio::time::sleep(Duration::from_millis(100)).await;
        if client.get(format!("http://127.0.0.1:{}",publication.host_port)).send().await.is_ok(){return Err("Published host port remained open".into());}
        Ok(())
    }.await;
    if let Err(error) = &result {
        eprintln!("Workspace failed: {error}");
        let logs = if kind == "container" {
            data.path().join("runtime/appliance")
        } else {
            data.path().join("runtime/environments").join(&env.id)
        };
        print_guest_logs(&logs);
    }
    manager.shutdown(&runtime).await;
    runtime.shutdown_all().await;
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "boots an isolated microVM and tests real PTYs, folder mounts and local service forwarding"]
async fn workspace_microvm_end_to_end() {
    exercise_workspace("microVm").await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "boots an isolated OCI appliance and tests real PTYs, folder mounts and localhost forwarding"]
async fn workspace_container_end_to_end() {
    exercise_workspace("container").await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "starts an isolated q35 VM to check manual port forwarding and concurrent display connections"]
async fn workspace_fullvm_forwarding_and_viewers() {
    let data = tempfile::tempdir().unwrap();
    let resources = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let runtime = RuntimeManager::new(&resources, data.path()).unwrap();
    let manager = WorkspaceManager::new(data.path());
    let store = PlatformStore::load(data.path().join("state.json")).unwrap();
    let mut env = fixture("env-workspace-desktop", "fullVm");
    env.resource_policy.memory_gb.preferred = 0.5;
    let source = data.path().join("blank.qcow2");
    let mut command =
        tokio::process::Command::new(if cfg!(target_os = "linux") { PathBuf::from("/usr/bin/qemu-img") } else if cfg!(target_os = "macos") { std::env::var_os("YOUGORI_MACOS_QEMU_DIR").map(|directory| PathBuf::from(directory).join("qemu-img")).unwrap_or_else(|| PathBuf::from(if cfg!(target_arch = "aarch64") { "/opt/homebrew/opt/qemu/bin/qemu-img" } else { "/usr/local/opt/qemu/bin/qemu-img" })) } else { resources.join("resources/runtime/qemu/qemu-img.exe") });
    command
        .args(["create", "-f", "qcow2"])
        .arg(&source)
        .arg("128M");
    background(&mut command);
    assert!(command.output().await.unwrap().status.success());
    let provisioned = runtime
        .provision_vm(&env.id, source.to_str().unwrap())
        .await
        .unwrap();
    let console = runtime
        .start_vm(
            &env.id,
            &provisioned.disk_path,
            &provisioned.source_path,
            &env.resource_policy,
            false,
        )
        .await
        .unwrap();
    store
        .mutate(|s| {
            s.environments.push(env.clone());
            Ok(())
        })
        .unwrap();
    let result=async {
        let display_port=url::Url::parse(&console.websocket_url).unwrap().port().unwrap();
        let mut viewers=Vec::new();
        for _ in 0..2 {
            let mut stream=TcpStream::connect(("127.0.0.1",display_port)).await.map_err(|e|e.to_string())?;
            stream.write_all(b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").await.map_err(|e|e.to_string())?;
            let mut bytes=vec![0;1024];let n=tokio::time::timeout(Duration::from_secs(5),stream.read(&mut bytes)).await.map_err(|e|e.to_string())?.map_err(|e|e.to_string())?;
            if !String::from_utf8_lossy(&bytes[..n]).contains("101 Switching Protocols"){return Err("VM display handshake failed".into());}
            viewers.push(stream);
        }
        let publication=publish_service(env.id.clone(),3000,PublicationKind::Local,None,None,&store,&runtime,&manager).await?;
        let forward_port=manager.publications.lock().await[&publication.id]._vm_forward.as_ref().unwrap().1;
        let probe=TcpStream::connect(("127.0.0.1",forward_port)).await.map_err(|e|format!("QMP hostfwd was not created: {e}"))?;
        drop(probe);
        manager.publications.lock().await.remove(&publication.id);
        tokio::time::sleep(Duration::from_millis(300)).await;
        if TcpStream::connect(("127.0.0.1",forward_port)).await.is_ok(){return Err("QMP hostfwd survived disconnect".into());}
        let selected=tempfile::tempdir().unwrap();
        let share=attach_folder(env.id.clone(),selected.path().to_string_lossy().into_owned(),true,&store,&runtime,&manager).await?;
        if share.mount_path.is_some(){return Err("Agentless VM reported a mounted folder".into());}
        if !share.guest_url.starts_with("http://10.0.2.2:"){return Err("Agentless VM folder URL missing".into());}
        manager.remove_share(&share.id,&runtime).await;
        Ok::<(),String>(())
    }.await;
    manager.shutdown(&runtime).await;
    runtime.shutdown_all().await;
    result.unwrap();
}
