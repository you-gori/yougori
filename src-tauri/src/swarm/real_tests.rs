//! Explicit real-runtime QA. The private website fixture is provided separately;
//! this test creates disposable storage and never attaches installed app disks.
use super::*;
use crate::runtime::RuntimeManager;
use crate::{backup::BackupManager, workspace::WorkspaceManager};
use std::{
    path::Path,
    sync::{Arc, Mutex as StdMutex},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

/// Uses only a disposable loopback server and its synthetic accounts. This
/// deliberately does not instantiate the native runtime, allocate containers,
/// download a model, or transfer funds.
#[tokio::test]
#[ignore = "requires the private website YOUGORI_SWARM_FIXTURE_PATH; HTTP contract only, no model runtime"]
async fn swarm_http_direct_payment_contract_without_model_runtime() {
    use std::process::Stdio;
    let fixture = std::env::var("YOUGORI_SWARM_FIXTURE_PATH")
        .expect("Set YOUGORI_SWARM_FIXTURE_PATH to the private synthetic website fixture");
    assert!(Path::new(&fixture).is_file());
    let mut command = tokio::process::Command::new("node");
    command
        .args(["--disable-warning=ExperimentalWarning", &fixture])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut server = command.spawn().unwrap();
    let mut input = server.stdin.take().unwrap();
    let mut output = BufReader::new(server.stdout.take().unwrap()).lines();
    let outcome: Result<(), String> = async {
        let line = tokio::time::timeout(Duration::from_secs(30), output.next_line())
            .await.map_err(|_| "Synthetic fixture setup timed out")?
            .map_err(|_| "Could not read synthetic fixture setup")?
            .ok_or("Synthetic fixture stopped during setup")?;
        let ready: Value = serde_json::from_str(&line).map_err(|_| "Invalid fixture setup")?;
        let url = string(&ready, "url")?;
        let parsed = reqwest::Url::parse(url).map_err(|_| "Invalid loopback fixture URL")?;
        if parsed.scheme() != "http" || parsed.host_str() != Some("127.0.0.1") {
            return Err("HTTP contract tests must use their disposable loopback fixture".into());
        }
        assert_eq!(ready["simulated"], true);
        direct_source_policy(&ready["policy"])?;
        assert!(source_payment_consents(&ready["membership"], &ready["policy"]));
        let account = string(&ready, "accountToken")?;
        let client = reqwest::Client::builder().timeout(Duration::from_secs(15))
            .build().map_err(|_| "Could not initialize fixture HTTP client")?;
        async fn call(client: &reqwest::Client, url: &str, path: &str, token: &str, body: Option<Value>) -> Result<(reqwest::StatusCode, Value), String> {
            let mut request = client.request(if body.is_some() { reqwest::Method::POST } else { reqwest::Method::GET }, format!("{url}/api/swarm{path}"))
                .bearer_auth(token);
            if let Some(body) = body { request = request.json(&body); }
            let response = request.send().await.map_err(|_| "Synthetic HTTP request failed")?;
            let status = response.status();
            let value = response.json().await.map_err(|_| "Invalid synthetic HTTP reply")?;
            Ok((status, value))
        }
        let (status, configuration) = call(&client, url, "/config", account, None).await?;
        assert!(status.is_success());
        assert_eq!(configuration["paymentMode"], "publisher_direct_external");
        let registration_worker: Worker = serde_json::from_value(json!({"id":"worker-http-contract","name":"HTTP-only native contract worker","model":ready["model"],"environmentId":"env-http-only-contract","state":"preparing","stage":"HTTP only","site":url,"gpu":"cpu","resources":{"cpu":4,"memoryGb":8},"quotaGb":8,"keepResident":true})).map_err(|_| "Invalid registration fixture")?;
        let (status, registration) = call(&client, url, "/workers", account, Some(registration_request(&registration_worker, &configuration))).await?;
        assert!(status.is_success());
        let remote = string(&registration["worker"], "id")?;
        let (status, offers) = call(&client, url, &format!("/workers/{remote}/offers"), account, None).await?;
        assert!(status.is_success());
        let offer = offers["offers"].as_array().and_then(|rows| rows.first())
            .ok_or("The synthetic publisher did not approve a current-version offer")?;
        let request = yougori_cli::bounty::acceptance("worker-http-contract", offer, "review", 30)?;
        validate(&request)?;
        let body = json!({"bountyId":request["bountyId"],"termsVersion":request["termsVersion"],"termsDigest":request["termsDigest"],"sourceRevision":request["sourceRevision"],"sourceDigest":request["sourceDigest"],"authorizationDigest":request["authorizationDigest"],"authorizationAccepted":true,"directPaymentAccepted":true,"rulesAccepted":true,"rulesVersion":request["rulesVersion"],"rulesDigest":request["rulesDigest"],"reportPolicy":"review","budgetMinutes":30,"idempotencyKey":"native-http-contract-accept"});
        for consent in ["authorizationAccepted", "directPaymentAccepted"] {
            let mut denied = body.clone();
            denied[consent] = false.into();
            let (status, _) = call(&client, url, &format!("/workers/{remote}/accept"), account, Some(denied)).await?;
            assert!(!status.is_success(), "Missing {consent} must fail closed");
            let (_, details) = call(&client, url, &format!("/workers/{remote}"), account, None).await?;
            assert!(details["membership"].is_null(), "Rejected consent cannot enroll the worker");
        }
        let (status, accepted) = call(&client, url, &format!("/workers/{remote}/accept"), account, Some(body)).await?;
        assert!(status.is_success());
        direct_source_policy(&accepted["policy"])?;
        assert_eq!(accepted["policy"]["sourceDigest"], request["sourceDigest"]);
        assert_eq!(accepted["policy"]["termsDigest"], request["termsDigest"]);
        assert_eq!(accepted["policy"]["authorizationDigest"], request["authorizationDigest"]);
        assert!(source_payment_consents(&accepted["membership"], &accepted["policy"]));
        let agent_token = string(&accepted["credential"], "token")?;
        let (status, state) = call(&client, url, "/agent/state", agent_token, None).await?;
        assert!(status.is_success());
        let worker: Worker = serde_json::from_value(json!({"id":"worker-http-contract","name":"Synthetic","model":ready["model"],"state":"running","stage":"HTTP only","site":url,"gpu":"cpu","resources":{"cpu":4,"memoryGb":8},"quotaGb":8,"keepResident":true,"policy":accepted["policy"]})).map_err(|_| "Invalid synthetic native worker")?;
        assert!(execution_authorized(&state, &worker));
        let (status, rewards) = call(&client, url, "/rewards", account, None).await?;
        assert!(status.is_success());
        assert!(rewards["directAwards"].is_array());
        assert!(rewards["legacyAwards"].is_array());
        assert!(rewards["legacyReserves"].is_array());
        let stats = fixture_command(&mut input, &mut output, json!({"action":"stats"})).await?;
        assert_eq!(stats["ledgerRows"], 0, "Direct promises cannot create ledger credits");
        Ok(())
    }.await;
    let _ = fixture_command(&mut input, &mut output, json!({"action":"close"})).await;
    drop(input);
    let _ = tokio::time::timeout(Duration::from_secs(10), server.wait()).await;
    outcome.unwrap();
}

#[test]
#[ignore = "downloads a real HF GGUF model and pinned OpenCode into disposable local sandboxes; requires YOUGORI_SWARM_FIXTURE_PATH"]
fn swarm_real_local_model_opencode_bounty_journey() {
    let fixture = std::env::var("YOUGORI_SWARM_FIXTURE_PATH").expect(
        "Set YOUGORI_SWARM_FIXTURE_PATH to the private website's scripts/swarm-native-fixture.mjs",
    );
    assert!(Path::new(&fixture).is_file());
    crate::install_async_runtime();
    let data = tempfile::tempdir().unwrap();
    let result = Arc::new(StdMutex::new(None));
    let returned = result.clone();
    let store = PlatformStore::load(data.path().join("state.json")).unwrap();
    let runtime = RuntimeManager::new(Path::new(env!("CARGO_MANIFEST_DIR")), data.path()).unwrap();
    store
        .mutate(|state| {
            state.host = crate::commands::collect_host_metrics(&state.host, runtime.storage_root());
            state.providers = runtime.provider_statuses();
            Ok(())
        })
        .unwrap();
    let mut context = tauri::generate_context!();
    context.config_mut().identifier = format!("com.yougori.swarm-test-{}", key());
    context.config_mut().app.windows.clear();
    let app = tauri::Builder::default()
        .any_thread()
        .manage(store)
        .manage(runtime)
        .manage(BackupManager::new(data.path()).unwrap())
        .manage(WorkspaceManager::new(data.path()))
        .manage(crate::peer_sharing::Sharing::default())
        .manage(crate::market::Market::default())
        .manage(Swarm::default())
        .setup(move |app| {
            let app = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                // GPU admission is part of normal app startup. Exercise the
                // same scheduler against only this test's isolated store.
                let scheduler_stop = CancellationToken::new();
                let scheduler = crate::model_runner::optimizer::start_until(&app, scheduler_stop.clone());
                let exercise_app = app.clone();
                let outcome = tokio::spawn(async move { exercise(&exercise_app, &fixture).await })
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|v| v);
                if let Err(error) = &outcome { eprintln!("Swarm QA outcome: {error}"); }
                scheduler_stop.cancel();
                let _ = scheduler.await;
                for token in app.state::<Swarm>().operations.lock().await.values() {
                    token.cancel();
                }
                let workers = app
                    .state::<Swarm>()
                    .inner
                    .lock()
                    .await
                    .rows
                    .values()
                    .cloned()
                    .collect::<Vec<_>>();
                for worker in &workers {
                    let _execution = execution_gate(&app, &worker.id).await.lock_owned().await;
                    let _ = guest::stop_owned(&app, worker, true).await;
                }
                app.state::<WorkspaceManager>()
                    .shutdown(&app.state::<RuntimeManager>())
                    .await;
                app.state::<RuntimeManager>().shutdown_all().await;
                // OS vault entries belong only to the unique disposable workloads.
                for worker in &workers {
                    for reference in [
                        worker.credential_reference.as_ref(),
                        worker.opencode_password_reference.as_ref(),
                    ]
                    .into_iter()
                    .flatten()
                    {
                        if let Ok(entry) =
                            keyring::Entry::new("Yougori.DeploymentSecrets.v1", reference)
                        {
                            let _ = entry.delete_credential();
                        }
                    }
                }
                *returned.lock().unwrap() = Some(outcome);
                app.exit(0);
            });
            Ok(())
        })
        .build(context)
        .unwrap();
    assert_eq!(app.run_return(|_, _| {}), 0);
    if let Err(error) = remove_disposable_cuda_registration(data.path()) {
        let preserved = data.keep();
        panic!("Disposable CUDA cleanup failed: {error}. Storage preserved at {}", preserved.display());
    }
    // Keep disposable storage alive until Tauri drops managed runtime handles.
    // Removing it before app exit leaves Windows disk files locked.
    data.close()
        .expect("Disposable native QA storage could not be removed");
    result
        .lock()
        .unwrap()
        .take()
        .expect("Native Swarm QA did not finish")
        .unwrap();
}

/// Disposable QA diagnostics contain only tool names/statuses and finish codes,
/// never prompts, arguments, model reasoning, credentials or source contents.
pub(super) async fn trace_turn(app: &AppHandle, worker: &Worker, session: &str) {
    if std::env::var_os("YOUGORI_SWARM_FIXTURE_PATH").is_none() { return; }
    if let Ok(messages) = guest::opencode_request(app, worker, &format!("/session/{session}/message"), None).await {
        let trace = messages.as_array().into_iter().flatten().filter(|m|m["info"]["role"]=="assistant")
            .map(|m|json!({"finish":m["info"]["finish"],"tools":m["parts"].as_array().into_iter().flatten()
                .filter(|p|p["type"]=="tool").map(|p|json!({"name":p["tool"],"status":p["state"]["status"]})).collect::<Vec<_>>()}))
            .collect::<Vec<_>>();
        eprintln!("Swarm QA turn: {}",json!(trace));
    }
}

/// A GPU QA run imports its own WSL distribution. Removing only the temporary
/// disk would leave a broken registration behind. Verify ownership and a stopped
/// runtime before unregistering precisely this test's distribution.
fn remove_disposable_cuda_registration(data: &Path) -> Result<(), String> {
    use std::os::windows::{fs::OpenOptionsExt, process::CommandExt};
    let root = data.join("runtime/cuda");
    let installed = root.join("installed.json");
    if !installed.is_file() { return Ok(()); }
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    if !root.starts_with(data.canonicalize().map_err(|e| e.to_string())?) {
        return Err("QA CUDA storage escaped its temporary directory".into());
    }
    let value: Value = serde_json::from_slice(&std::fs::read(installed).map_err(|e|e.to_string())?)
        .map_err(|e|e.to_string())?;
    let distribution = string(&value, "distribution")?;
    let _ownership = std::fs::OpenOptions::new().read(true).write(true).share_mode(0)
        .open(root.join("runtime-owner.lock")).map_err(|_|"QA CUDA runtime still has a live owner")?;
    let status = std::process::Command::new("powershell.exe").creation_flags(0x08000000)
        .args(["-NoProfile","-NonInteractive","-ExecutionPolicy","Bypass","-File"])
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../runtime/cuda/verify-owned.ps1"))
        .arg("-DataDirectory").arg(&root).arg("-Distribution").arg(distribution).arg("-RequireStopped")
        .status().map_err(|e|e.to_string())?;
    if !status.success() { return Err("QA CUDA registration was not verified as owned and stopped".into()); }
    let status = std::process::Command::new("wsl.exe").creation_flags(0x08000000)
        .args(["--unregister",distribution]).status().map_err(|e|e.to_string())?;
    if !status.success() { return Err("QA CUDA registration removal failed".into()); }
    Ok(())
}

async fn fixture_command(
    input: &mut tokio::process::ChildStdin,
    output: &mut tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    body: Value,
) -> Result<Value, String> {
    input
        .write_all(format!("{body}\n").as_bytes())
        .await
        .map_err(|e| e.to_string())?;
    let line = tokio::time::timeout(Duration::from_secs(15), output.next_line())
        .await
        .map_err(|_| "Fixture command timed out")?
        .map_err(|e| e.to_string())?
        .ok_or("Fixture stopped before responding")?;
    let value: Value = serde_json::from_str(&line).map_err(|_| "Invalid fixture reply")?;
    if value.get("error").is_some() {
        return Err(value["error"].to_string());
    }
    Ok(value["result"].clone())
}

async fn exercise(app: &AppHandle, fixture: &str) -> Result<(), String> {
    use std::process::Stdio;
    let model = std::env::var("YOUGORI_SWARM_TEST_MODEL").unwrap_or("Qwen/Qwen3-0.6B-GGUF".into());
    let gpu = std::env::var("YOUGORI_SWARM_TEST_GPU").unwrap_or("cpu".into());
    let memory = std::env::var("YOUGORI_SWARM_TEST_MEMORY_GB").ok().map(|value|value.parse::<u32>())
        .transpose().map_err(|_|"Invalid QA memory allocation")?.unwrap_or(8);
    let quant = std::env::var("YOUGORI_SWARM_TEST_QUANT").ok();
    let mut command = tokio::process::Command::new("node");
    command
        .args([
            "--disable-warning=ExperimentalWarning",
            fixture,
            "--model",
            &model,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(windows)]
    command.creation_flags(0x08000000);
    let mut server = command.spawn().map_err(|e| e.to_string())?;
    let mut input = server.stdin.take().ok_or("Fixture input missing")?;
    let mut output = BufReader::new(server.stdout.take().ok_or("Fixture output missing")?).lines();
    let result=async{
        let line=tokio::time::timeout(Duration::from_secs(30),output.next_line()).await.map_err(|_|"Fixture setup timed out")?.map_err(|e|e.to_string())?.ok_or("Fixture setup failed")?;
        let ready:Value=serde_json::from_str(&line).map_err(|_|"Invalid fixture setup")?;
        std::env::set_var("YOUGORI_NETWORK_URL",string(&ready,"url")?);std::env::set_var("YOUGORI_SWARM_TEST_ACCOUNT",string(&ready,"accountToken")?);
        eprintln!("Swarm QA: isolated test website ready; preparing {model} on {gpu} and OpenCode.");
        let created=swarm_dispatch(json!({"action":"prepare","model":format!("hf.co/{model}"),"quant":quant,"name":"Disposable Swarm QA worker","gpu":gpu,"resources":{"cpu":4,"memoryGb":memory},"workspaceQuotaGb":8,"keepResident":true}),app.clone()).await?;
        let id=string(&created["worker"],"id")?.to_owned();
        let deadline=tokio::time::Instant::now()+Duration::from_secs(2400);let mut last=String::new();
        loop{
            let worker=read(app,&id).await?;
            if worker.stage!=last{eprintln!("Swarm QA: {}",worker.stage);last=worker.stage.clone();}
            if worker.state=="ready_waiting"{break}
            if worker.state=="failed"||worker.error.is_some(){return Err(worker.error.unwrap_or("Worker preparation failed".into()))}
            if tokio::time::Instant::now()>deadline{return Err("Native worker preparation timed out".into())}
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        let offers=swarm_dispatch(json!({"action":"offers","workerId":id}),app.clone()).await?;
        let offer=offers["offers"].as_array().and_then(|v|v.first()).ok_or("The prepared worker received no eligible offer")?;
        let accepted=swarm_dispatch(json!({"action":"accept","workerId":id,"bountyId":offer["bounty"]["id"],"termsVersion":offer["termsVersion"],"termsDigest":offer["termsDigest"],"sourceRevision":offer["sourceRevision"],"sourceDigest":offer["bounty"]["terms"]["sourceDigest"],"authorizationAccepted":true,"directPaymentAccepted":true,"authorizationDigest":offer["authorizationDigest"],"reportPolicy":"automatic","budgetMinutes":30,"confirmed":true,"rulesAccepted":true,"rulesVersion":offer["bounty"]["terms"]["serviceRules"]["version"],"rulesDigest":offer["bounty"]["terms"]["serviceRules"]["digest"]}),app.clone()).await?;
        assert_eq!(accepted["worker"]["state"],"preparing_bounty");
        eprintln!("Swarm QA: explicitly accepted authorized fixture bounty; checking actual agent execution.");
        let deadline=tokio::time::Instant::now()+Duration::from_secs(1200);
        let mut reproduced = false;
        let mut managed_attempt = false;
        let mut progress = (false, false, false);
        loop{
            let worker=read(app,&id).await?;
            if worker.stage!=last{eprintln!("Swarm QA: {}",worker.stage);last=worker.stage.clone();}
            if worker.error.is_some(){return Err(worker.error.unwrap())}
            reproduced |= worker.tool_results.values().any(|receipt| receipt["exitCode"] == 1
                && format!("{}{}",receipt["stdout"],receipt["stderr"]).contains("test_denies_other_account"));
            managed_attempt |= worker.tool_results.values().any(|receipt| receipt["attempt"]["id"].is_string());
            // An inconclusive turn is allowed, but cannot satisfy any of these
            // three required milestones. A later task may produce the finding.
            let detail=crate::market::swarm_account_request(reqwest::Method::GET,&format!("/api/swarm/workers/{}",worker.remote_id()?),None).await?;
            let report = detail["reports"].as_array().and_then(|rows| rows.iter().find(|report| report["state"] == "complete_received"));
            let current_progress = (reproduced, managed_attempt, report.is_some());
            if current_progress != progress {
                eprintln!("Swarm QA: failing check reproduced={reproduced}, managed attempt={managed_attempt}, complete report={}",report.is_some());
                progress = current_progress;
            }
            if reproduced && managed_attempt && report.is_some(){
                let report_id = report.unwrap()["id"].clone();
                eprintln!("Swarm QA: actual model/OpenCode reproduced the local failing check, recorded an attempt and submitted a complete report.");
                let messages=swarm_dispatch(json!({"action":"chat","workerId":id,"content":"What have you checked?","idempotencyKey":"qa-human-guidance"}),app.clone()).await?;
                assert!(messages["message"].is_object());
                let message_id=messages["message"]["id"].clone();
                let reply_deadline=tokio::time::Instant::now()+Duration::from_secs(360);
                loop{
                    let conversation=swarm_dispatch(json!({"action":"messages","workerId":id}),app.clone()).await?;
                    if conversation["messages"].as_array().is_some_and(|rows|rows.iter().any(|row|row["role"]=="agent"&&row["replyTo"]==message_id&&row["content"].as_str().is_some_and(|s|!s.trim().is_empty()))){break}
                    let current=read(app,&id).await?;if let Some(error)=current.error{return Err(error)}
                    if tokio::time::Instant::now()>reply_deadline{return Err("The participant's private agent conversation did not receive a reply".into())}
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
                // Prove a human pause cannot be undone by a background checkpoint.
                swarm_dispatch(json!({"action":"pause","workerId":id}),app.clone()).await?;
                assert_eq!(read(app,&id).await?.state,"paused");
                let reviewed=fixture_command(&mut input,&mut output,json!({"action":"review","reportId":report_id,"settle":true})).await?;
                assert_eq!(reviewed["report"]["state"],"accepted");
                assert_eq!(reviewed["award"]["reportId"],report_id);
                assert_eq!(reviewed["award"]["paymentMode"],"publisher_direct_external");
                assert_eq!(reviewed["award"]["simulated"],true);
                assert_eq!(reviewed["transferInitiated"],false);
                assert_eq!(reviewed["stats"]["ledgerRows"],0);
                assert!(reviewed["stats"]["balances"].as_array().is_some_and(|rows| rows.iter().all(|row|row["credit_micros"]==0 && row["earnings_micros"]==0)));
                eprintln!("Swarm QA: synthetic publisher review and award completed; no real funds moved.");
                let privacy=fixture_command(&mut input,&mut output,json!({"action":"assertPrivacy"})).await?;
                eprintln!("Swarm QA: separate human chat answered, authorization isolation checked: {}",privacy.to_string());
                return Ok(())
            }
            if tokio::time::Instant::now()>deadline{return Err(format!("Model/OpenCode journey incomplete: reproduced={reproduced}, managedAttempt={managed_attempt}, completeReport={}. No successful end-to-end result is claimed.",report.is_some()))}
            tokio::time::sleep(Duration::from_secs(3)).await;
        }
    }.await;
    let _ = fixture_command(&mut input, &mut output, json!({"action":"close"})).await;
    drop(input);
    let _ = tokio::time::timeout(Duration::from_secs(10), server.wait()).await;
    std::env::remove_var("YOUGORI_SWARM_TEST_ACCOUNT");
    std::env::remove_var("YOUGORI_NETWORK_URL");
    result
}
