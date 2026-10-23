//! A hub, member computers and a company app talking over real pinned TLS on loopback, with
//! local model servers simulated in memory.
use crate::{
    harness::{Harness, Strategy},
    hub::{self, Hub, ModelReport, PlanChange, Target},
    invite,
    member::{self, LocalModel, MemberError, WorkerEvent},
    net::{self, HubAddress},
    password,
    policy::IdlePolicy,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Incoming, header, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::{
    collections::HashSet,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::watch;

const PASSWORD: &str = "correct horse battery staple";
type Seen = Arc<Mutex<Vec<(String, Value)>>>;
type Connect = Box<dyn Fn() -> Pin<Box<dyn Future<Output = Result<LocalModel, String>> + Send>> + Send>;

/// A model server that records each request and answers with `status`.
fn local_model(seen: Seen, status: u16) -> Connect {
    Box::new(move || {
        let seen = seen.clone();
        Box::pin(async move {
            let (client, server) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let seen = seen.clone();
                    async move {
                        let authorization = request.headers()[header::AUTHORIZATION].to_str().unwrap().to_owned();
                        let body: Value = serde_json::from_slice(&request.into_body().collect().await.unwrap().to_bytes()).unwrap();
                        seen.lock().unwrap().push((authorization, body.clone()));
                        let response = Response::builder().status(status);
                        Ok::<_, std::convert::Infallible>(if status != 200 {
                            response.header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(r#"{"error":{"message":"busy"}}"#))).unwrap()
                        } else if body["stream"] == true {
                            let events = "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":2}}\n\ndata: [DONE]\n\n";
                            response.header(header::CONTENT_TYPE, "text/event-stream").body(Full::new(Bytes::from(events))).unwrap()
                        } else {
                            let reply = json!({"choices":[{"message":{"role":"assistant","content":"Hello"}}],"usage":{"prompt_tokens":5,"completion_tokens":1}});
                            response.header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(reply.to_string()))).unwrap()
                        })
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(server), service).await;
            });
            Ok(LocalModel { io: Box::new(client), api_key: "local-key".into() })
        })
    })
}

/// A company app calling the hub's API.
async fn app(address: SocketAddr, certificate: &str, method: &str, path: &str, key: &str, body: Option<Value>) -> (u16, Vec<u8>) {
    let tls = net::client_config(certificate).unwrap();
    let address = HubAddress::Direct(address);
    let request = Request::builder().method(method).uri(path).header(header::AUTHORIZATION, format!("Bearer {key}"));
    let response = match body {
        Some(body) => net::send(&address, &tls, request.header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(body.to_string()))).unwrap(), Duration::from_secs(60)).await,
        None => net::send(&address, &tls, request.body(Empty::<Bytes>::new()).unwrap(), Duration::from_secs(60)).await,
    }
    .unwrap();
    let status = response.status().as_u16();
    (status, response.into_body().collect().await.unwrap().to_bytes().to_vec())
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn report(model: &str, state: &str) -> Vec<ModelReport> {
    vec![ModelReport { model: model.into(), state: state.into(), reason: String::new(), quant: None, gpu: Some("Test GPU".into()), progress: None }]
}

async fn start_hub(folder: &std::path::Path) -> (Hub, Arc<Mutex<Vec<&'static str>>>) {
    let path = folder.join("hub.json");
    let salt = password::new_salt();
    let password_key = password::derive(PASSWORD, &salt).unwrap();
    let key = hub::create(&path, "Acme", "127.0.0.1".parse().unwrap(), 0, None, Some(0), &salt).unwrap();
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorder = events.clone();
    let hub = Hub::start(path, &key, &password_key, Arc::new(move |kind, _| recorder.lock().unwrap().push(kind))).await.unwrap();
    (hub, events)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admins_plan_members_serve_and_apps_get_answers() {
    let folder = tempfile::tempdir().unwrap();
    let (hub, events) = start_hub(folder.path()).await;
    let address = hub.address();
    let certificate = hub.record().certificate;
    let fingerprint = net::fingerprint(&certificate).unwrap();

    // Wrong company names, passwords and fingerprints are refused before anything is saved.
    assert!(member::join("Globex", address, PASSWORD, "PC", "linux", true, None).await.err().unwrap().contains("belongs to 'Acme'"));
    assert!(member::join("acme", address, "wrong password!", "PC", "linux", true, None).await.err().unwrap().contains("password is wrong"));
    let other = format!("{}{}", "00:".repeat(31), "00");
    assert!(member::join("acme", address, PASSWORD, "PC", "linux", true, Some(&other)).await.err().unwrap().contains("fingerprint"));

    // The admin's plan picks up computers as they join.
    hub.add_plan("hf.co/Acme/Chat-1B", None, 100, IdlePolicy::new(Some(15), Some("Mon-Fri 18:00-08:00")).unwrap(), Target::All).unwrap();
    let joined = member::join("ACME", address, PASSWORD, "Workstation 7", "linux", true, Some(&fingerprint.to_lowercase())).await.unwrap();
    assert_eq!((joined.grid_name.as_str(), joined.fingerprint.as_str()), ("Acme", fingerprint.as_str()));
    let assignment = joined.assignment.clone().expect("the plan assigns the new computer");
    assert_eq!((assignment.model.as_str(), assignment.idle_after_minutes, assignment.schedule.as_deref()), ("Acme/Chat-1B", 15, Some("Mon-Fri 18:00-08:00")));
    let laptop = member::join("Acme", address, PASSWORD, "Laptop", "macos", false, None).await.unwrap();
    assert_eq!(laptop.assignment, None, "computers that cannot run models get no plan");

    // A saved membership reconnects with only the pinned certificate and its token.
    let membership = member::Membership::new(address, &joined.certificate, joined.membership.member_id.clone(), joined.token.clone()).unwrap();
    let instructions = membership.heartbeat("test", true, &report("Acme/Chat-1B", "available")).await.unwrap();
    assert_eq!(instructions.assignment, Some(assignment));

    let (gate, gate_receiver) = watch::channel(true);
    let seen = Seen::default();
    let worker = tokio::spawn(member::serve(membership.clone(), "Acme/Chat-1B".into(), gate_receiver, local_model(seen.clone(), 200), |_| {}));
    let created = hub.create_key("Analytics").unwrap();
    let key = created["apiKey"].as_str().unwrap().to_owned();

    // A plain reply: the model name is removed and the member's own API key is used.
    let (status, body) = app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model":"acme/chat-1b","messages":[{"role":"user","content":"Hi"}]}))).await;
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json_of(&body)["choices"][0]["message"]["content"], "Hello");
    let (authorization, forwarded) = seen.lock().unwrap()[0].clone();
    assert_eq!(authorization, "Bearer local-key");
    assert!(forwarded.get("model").is_none() && forwarded["messages"][0]["content"] == "Hi");

    // A streamed reply arrives event by event.
    let (status, body) = app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model":"hf.co/Acme/Chat-1B","messages":[],"stream":true}))).await;
    let text = String::from_utf8(body).unwrap();
    assert_eq!(status, 200);
    assert!(text.contains("Hel") && text.contains("lo") && text.ends_with("data: [DONE]\n\n"), "{text}");

    let (status, body) = app(address, &certificate, "GET", "/v1/models", &key, None).await;
    assert_eq!(status, 200);
    assert_eq!(json_of(&body)["data"][0]["id"], "Acme/Chat-1B");
    assert_eq!(json_of(&body)["data"][0]["owned_by"], "Acme");

    // Wrong keys and unknown models are refused.
    let (status, _) = app(address, &certificate, "POST", "/v1/chat/completions", "ygrid_nope", Some(json!({"model":"acme/chat-1b","messages":[]}))).await;
    assert_eq!(status, 401);
    let (status, body) = app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model":"other/model","messages":[]}))).await;
    assert_eq!((status, json_of(&body)["error"]["code"].as_str()), (404, Some("model_not_found")));

    // Usage is counted per key, from both the JSON and the streamed reply.
    let status = hub.status();
    let usage = &status["keys"][0];
    assert_eq!((usage["requests"].as_u64(), usage["tokensIn"].as_u64(), usage["tokensOut"].as_u64(), usage["failures"].as_u64()), (Some(2), Some(10), Some(3), Some(0)));
    assert_eq!((status["plans"][0]["computers"].as_u64(), status["plans"][0]["target"].as_u64(), status["plans"][0]["ready"].as_u64()), (Some(1), Some(1), Some(1)));
    assert_eq!(status["computers"]["capable"], 1);
    assert!(!status.to_string().contains(&key) && !status.to_string().contains(&joined.token), "status never shows secrets");

    // When the person comes back the computer stops serving, and apps learn why.
    gate.send(false).unwrap();
    membership.heartbeat("test", true, &report("Acme/Chat-1B", "person_active")).await.unwrap();
    let (status, body) = app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model":"acme/chat-1b","messages":[]}))).await;
    assert_eq!(status, 503);
    assert!(json_of(&body)["error"]["message"].as_str().unwrap().contains("1 in use by their person"));

    // Changing the plan's rules keeps the computer; removing the plan frees it.
    let changed = hub.update_plan(&joined.assignment.as_ref().unwrap().plan_id, PlanChange { idle_after_minutes: Some(5), schedule: Some(String::new()), ..Default::default() }).unwrap();
    assert_eq!((changed["computers"].as_u64(), changed["plan"]["policy"]["idleAfterMinutes"].as_u64()), (Some(1), Some(5)));
    let instructions = membership.heartbeat("test", true, &[]).await.unwrap();
    assert_eq!(instructions.assignment.as_ref().map(|a| (a.idle_after_minutes, a.schedule.clone())), Some((5, None)));
    hub.remove_plan(changed["plan"]["id"].as_str().unwrap()).unwrap();
    assert_eq!(membership.heartbeat("test", true, &[]).await.unwrap().assignment, None);

    // A revoked key stops working; a removed computer learns it at its next check-in.
    hub.revoke_key(created["key"]["id"].as_str().unwrap()).unwrap();
    let (status, _) = app(address, &certificate, "GET", "/v1/models", &key, None).await;
    assert_eq!(status, 401);
    hub.remove_member(&membership.member_id).unwrap();
    assert_eq!(membership.heartbeat("test", true, &[]).await.err(), Some(MemberError::Removed));
    laptop.membership.leave().await.unwrap();
    assert_eq!(hub.status()["computers"]["total"], 0);
    let kinds = events.lock().unwrap().clone();
    assert!(kinds.contains(&"grid.join.refused") && kinds.contains(&"grid.member.joined") && kinds.contains(&"grid.member.left"), "{kinds:?}");
    drop(gate);
    worker.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_busy_computer_hands_the_request_to_another() {
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    let address = hub.address();
    let certificate = hub.record().certificate;
    let key = hub.create_key("App").unwrap()["apiKey"].as_str().unwrap().to_owned();
    let busy = member::join("Acme", address, PASSWORD, "Busy", "windows", true, None).await.unwrap().membership;
    let idle = member::join("Acme", address, PASSWORD, "Idle", "windows", true, None).await.unwrap().membership;
    for membership in [&busy, &idle] {
        membership.heartbeat("test", true, &report("Acme/Chat", "available")).await.unwrap();
    }
    // Only the busy computer is asking for work when the request arrives.
    let (busy_gate, receiver) = watch::channel(true);
    let busy_seen = Seen::default();
    let events = Arc::new(Mutex::new(Vec::new()));
    let recorder = events.clone();
    let busy_worker = tokio::spawn(member::serve(busy, "Acme/Chat".into(), receiver, local_model(busy_seen.clone(), 429), move |event| recorder.lock().unwrap().push(event)));
    let request = tokio::spawn({
        let certificate = certificate.clone();
        async move { app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model":"Acme/Chat","messages":[]}))).await }
    });
    while busy_seen.lock().unwrap().is_empty() {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (idle_gate, receiver) = watch::channel(true);
    let idle_seen = Seen::default();
    let idle_worker = tokio::spawn(member::serve(idle, "Acme/Chat".into(), receiver, local_model(idle_seen.clone(), 200), |_| {}));
    let (status, body) = request.await.unwrap();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    assert_eq!(json_of(&body)["choices"][0]["message"]["content"], "Hello");
    assert_eq!(idle_seen.lock().unwrap().len(), 1);
    assert!(matches!(events.lock().unwrap().iter().find(|event| matches!(event, WorkerEvent::Finished(_))), Some(WorkerEvent::Finished(member::Outcome::Released(_)))));
    drop((busy_gate, idle_gate));
    busy_worker.await.unwrap();
    idle_worker.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn computers_outside_the_network_join_and_serve_through_a_tunnel() {
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    let entry = hub.tunnel_address().expect("the hub opens its tunnel entry");
    assert!(entry.ip().is_loopback(), "only cloudflared on the hub computer can reach the entry");
    // Here the entry stands in for Cloudflare's edge; the grid's own pinned TLS runs inside.
    let tunnel = HubAddress::parse(&format!("http://127.0.0.1:{}", entry.port())).unwrap();
    let certificate = hub.record().certificate;
    let fingerprint = net::fingerprint(&certificate).unwrap();
    assert_eq!(hub.status()["tunnelPort"], entry.port());

    // Joining through the tunnel proves the password exactly as on the LAN.
    assert!(member::join("acme", tunnel.clone(), "wrong password!", "PC", "linux", true, None).await.err().unwrap().contains("password is wrong"));
    let code = invite::encode(&invite::Invite { company: "Acme".into(), address: tunnel.clone(), fingerprint: fingerprint.clone() });
    let read = invite::decode(&code).unwrap();
    let joined = member::join(&read.company, read.address.clone(), PASSWORD, "Home office", "windows", true, Some(&read.fingerprint)).await.unwrap();
    assert_eq!((joined.grid_name.as_str(), joined.fingerprint.as_str()), ("Acme", fingerprint.as_str()));

    // The saved membership reconnects through the tunnel and answers a company app on the LAN.
    let membership = member::Membership::new(tunnel.clone(), &joined.certificate, joined.membership.member_id.clone(), joined.token.clone()).unwrap();
    membership.heartbeat("test", true, &report("Acme/Chat", "available")).await.unwrap();
    let (gate, receiver) = watch::channel(true);
    let seen = Seen::default();
    let worker = tokio::spawn(member::serve(membership.clone(), "Acme/Chat".into(), receiver, local_model(seen.clone(), 200), |_| {}));
    let key = hub.create_key("App").unwrap()["apiKey"].as_str().unwrap().to_owned();
    let (status, body) = app(hub.address(), &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model":"Acme/Chat","messages":[],"stream":true}))).await;
    let text = String::from_utf8(body).unwrap();
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("Hel") && text.contains("lo") && text.ends_with("data: [DONE]

"), "{text}");
    assert_eq!(seen.lock().unwrap().len(), 1, "the tunneled computer ran the request");

    // A hub with another certificate is refused, even inside the tunnel.
    let impostor = net::new_identity("127.0.0.1".parse().unwrap(), None).unwrap().certificate;
    let forged = member::Membership::new(tunnel.clone(), &impostor, joined.membership.member_id.clone(), joined.token.clone()).unwrap();
    assert!(matches!(forged.heartbeat("test", true, &[]).await, Err(MemberError::Failed(_))));

    drop(gate);
    worker.await.unwrap();
}

/// The app's own copy of cloudflared, or YOUGORI_CLOUDFLARED_PATH.
fn cloudflared() -> std::path::PathBuf {
    std::env::var_os("YOUGORI_CLOUDFLARED_PATH").map(Into::into).unwrap_or_else(|| {
        std::path::PathBuf::from(std::env::var_os("APPDATA").expect("APPDATA")).join("com.yougori.desktop/tools/cloudflared-2026.8.3.exe")
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opens a real temporary no-account Cloudflare Quick Tunnel to a disposable hub and serves a streamed request through it; requires Internet and cloudflared"]
async fn a_member_serves_through_a_real_cloudflare_quick_tunnel() {
    use tokio::io::AsyncBufReadExt;
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    let entry = hub.tunnel_address().unwrap().port();
    let mut child = tokio::process::Command::new(cloudflared())
        .args(["tunnel", "--no-autoupdate", "--url", &format!("http://127.0.0.1:{entry}")])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("cloudflared starts");
    // cloudflared prints the Quick Tunnel's address on stderr.
    let mut lines = tokio::io::BufReader::new(child.stderr.take().unwrap()).lines();
    let url = tokio::time::timeout(Duration::from_secs(60), async {
        while let Some(line) = lines.next_line().await.unwrap() {
            if let Some(start) = line.find("https://") {
                let rest = &line[start..];
                let end = rest.find(|c: char| c.is_whitespace() || c == '|').unwrap_or(rest.len());
                if rest[..end].ends_with(".trycloudflare.com") {
                    return rest[..end].to_owned();
                }
            }
        }
        panic!("cloudflared ended without an address");
    })
    .await
    .expect("cloudflared publishes a Quick Tunnel within a minute");
    // Keep draining its output so cloudflared never blocks on a full pipe.
    tokio::spawn(async move { while let Ok(Some(_)) = lines.next_line().await {} });
    let address = HubAddress::parse(&url).unwrap();
    eprintln!("Quick Tunnel: {address}");

    // A tunnel created a moment ago can take a little while to answer everywhere.
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let joined = loop {
        match member::join("Acme", address.clone(), PASSWORD, "Remote office", "windows", true, None).await {
            Ok(joined) => break joined,
            Err(error) if std::time::Instant::now() < deadline => {
                eprintln!("not reachable yet: {error}");
                tokio::time::sleep(Duration::from_secs(3)).await;
            }
            Err(error) => panic!("joining through the tunnel failed: {error}"),
        }
    };
    let certificate = hub.record().certificate;
    assert_eq!(joined.fingerprint, net::fingerprint(&certificate).unwrap(), "the member pinned the hub itself, not Cloudflare");

    // The hub's 25-second wait for work survives a quiet trip through Cloudflare.
    let membership = member::Membership::new(address.clone(), &joined.certificate, joined.membership.member_id.clone(), joined.token.clone()).unwrap();
    membership.heartbeat("test", true, &report("Acme/Chat", "available")).await.unwrap();
    let waited = std::time::Instant::now();
    assert!(membership.next_job(&["Acme/Chat".into()]).await.unwrap().is_none());
    assert!(waited.elapsed() >= Duration::from_secs(20), "the long wait completed: {:?}", waited.elapsed());

    // A company app on the network gets a streamed reply from the computer behind the tunnel.
    let (gate, receiver) = watch::channel(true);
    let seen = Seen::default();
    let worker = tokio::spawn(member::serve(membership.clone(), "Acme/Chat".into(), receiver, local_model(seen.clone(), 200), |_| {}));
    let key = hub.create_key("App").unwrap()["apiKey"].as_str().unwrap().to_owned();
    let (status, body) = app(hub.address(), &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model":"Acme/Chat","messages":[{"role":"user","content":"Hi"}],"stream":true}))).await;
    let text = String::from_utf8(body).unwrap();
    assert_eq!(status, 200, "{text}");
    assert!(text.contains("Hel") && text.contains("lo") && text.ends_with("data: [DONE]\n\n"), "{text}");
    assert_eq!(seen.lock().unwrap().len(), 1);

    // A wrong password through Cloudflare is refused like on the network.
    let refused = member::join("Acme", address.clone(), "wrong password!", "Stranger", "windows", true, None).await.err().unwrap_or_default();
    assert!(refused.contains("password is wrong"), "{refused}");
    drop(gate);
    worker.await.unwrap();
    let _ = child.kill().await;
}

/// A model server that plays its part in a swarm: as the lead it plans three tasks and then
/// combines the results; as a worker it spends `delay` on its task, so parallel work shows.
fn team_model(delay: Duration) -> Connect {
    Box::new(move || {
        Box::pin(async move {
            let (client, server) = tokio::io::duplex(64 * 1024);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| async move {
                    let body: Value = serde_json::from_slice(&request.into_body().collect().await.unwrap().to_bytes()).unwrap();
                    let messages = body["messages"].as_array().unwrap();
                    let system = messages[0]["content"].as_str().unwrap_or_default().to_owned();
                    let user = messages.last().unwrap()["content"].as_str().unwrap_or_default().to_owned();
                    let text = if system.contains("Reply with only a JSON object") {
                        r#"{"tasks": [{"title": "Prices", "brief": "List prices."}, {"title": "Risks", "brief": "List risks."}, {"title": "Rivals", "brief": "Name rivals."}]}"#.to_owned()
                    } else if system.starts_with("You are one worker") {
                        tokio::time::sleep(delay).await;
                        format!("{} done", user.split("Your task: ").nth(1).unwrap().lines().next().unwrap())
                    } else {
                        format!("Combined: {}", ["Prices", "Risks", "Rivals"].iter().filter(|task| user.contains(&format!("{task} done"))).count())
                    };
                    let reply = json!({"choices": [{"message": {"role": "assistant", "content": text}}], "usage": {"prompt_tokens": 3, "completion_tokens": 2}});
                    Ok::<_, std::convert::Infallible>(Response::builder().header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(reply.to_string()))).unwrap())
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(server), service).await;
            });
            Ok(LocalModel { io: Box::new(client), api_key: "local-key".into() })
        })
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn one_call_runs_a_planned_team_across_several_computers() {
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    let address = hub.address();
    let certificate = hub.record().certificate;
    // A lead computer and three worker computers, each answering one request at a time.
    let mut gates = Vec::new();
    let mut workers = Vec::new();
    for (name, model) in [("Lead PC", "Acme/Lead"), ("Worker 1", "Acme/Worker"), ("Worker 2", "Acme/Worker"), ("Worker 3", "Acme/Worker")] {
        let joined = member::join("Acme", address, PASSWORD, name, "linux", true, None).await.unwrap();
        let membership = member::Membership::new(address, &joined.certificate, joined.membership.member_id.clone(), joined.token.clone()).unwrap();
        membership.heartbeat("test", true, &report(model, "available")).await.unwrap();
        let (gate, receiver) = watch::channel(true);
        gates.push(gate);
        workers.push(tokio::spawn(member::serve(membership, model.into(), receiver, team_model(Duration::from_millis(800)), |_| {})));
    }
    let added = hub.add_harness(Harness::new("team", Strategy::Plan, "hf.co/Acme/Lead", &["Acme/Worker".into()], 3, 3, 1).unwrap()).unwrap();
    assert_eq!(added["model"], "swarm/team");
    assert_eq!(added["missing"], json!(["acme/lead", "acme/worker"]), "no plan runs these models yet, which the admin is told");
    assert!(hub.add_harness(Harness::new("team", Strategy::Mixture, "acme/lead", &["acme/worker".into()], 2, 2, 1).unwrap()).unwrap_err().contains("already exists"));
    let key = hub.create_key("App").unwrap()["apiKey"].as_str().unwrap().to_owned();

    // Apps find the harness among the models.
    let (status, models) = app(address, &certificate, "GET", "/v1/models", &key, None).await;
    assert_eq!(status, 200);
    let listed = json_of(&models)["data"].as_array().unwrap().iter().find(|model| model["id"] == "swarm/team").cloned().expect("the harness is listed");
    assert_eq!((listed["ready"].clone(), listed["swarm"]["computers"].clone()), (json!(true), json!(3)));

    // One call: the lead plans, three computers work at once, the lead combines.
    let started = Instant::now();
    let (status, body) = app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model": "swarm/team", "messages": [{"role": "user", "content": "Should we open a shop in Lyon?"}]}))).await;
    let took = started.elapsed();
    assert_eq!(status, 200, "{}", String::from_utf8_lossy(&body));
    let reply = json_of(&body);
    assert_eq!((reply["model"].as_str(), reply["choices"][0]["message"]["content"].as_str()), (Some("swarm/team"), Some("Combined: 3")));
    let tasks = reply["yougori_swarm"]["rounds"][0]["tasks"].as_array().unwrap();
    let computers: HashSet<&str> = tasks.iter().map(|task| task["computer"].as_str().unwrap()).collect();
    assert_eq!(computers, HashSet::from(["Worker 1", "Worker 2", "Worker 3"]), "each task ran on its own computer");
    assert_eq!(reply["yougori_swarm"]["rounds"][0]["planner"], "Lead PC");
    assert_eq!(reply["yougori_swarm"]["final"]["computer"], "Lead PC");
    assert!(took < Duration::from_millis(2_000), "three 800 ms tasks side by side, not one after another: {took:?}");
    assert_eq!(reply["usage"]["total_tokens"], 25, "the plan, three tasks and the final answer");
    let usage = hub.status()["keys"][0].clone();
    assert!(usage["tokensIn"].as_u64().unwrap_or(0) >= 15, "the team's work counts against the app's key: {usage}");

    // A streaming caller gets the same answer as server-sent events.
    let (status, body) = app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model": "swarm/team", "messages": [{"role": "user", "content": "Again"}], "stream": true}))).await;
    let events = String::from_utf8(body).unwrap();
    assert_eq!(status, 200);
    assert!(events.contains("\"content\":\"Combined: 3\"") && events.contains("yougori_swarm") && events.trim_end().ends_with("data: [DONE]"), "{events}");

    // The admin runs it from the app, without an API key.
    let ran = hub.swarm().run("swarm/team", &[json!({"role": "user", "content": "Hi"})]).await.unwrap();
    assert_eq!(ran["answer"], "Combined: 3");
    assert_eq!(ran["trace"]["computersUsed"].as_array().unwrap().len(), 4);

    // A harness whose models nobody runs answers at once, and an unknown one is not found.
    hub.add_harness(Harness::new("ghost", Strategy::Plan, "acme/missing", &["acme/missing".into()], 2, 2, 1).unwrap()).unwrap();
    let (status, body) = app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model": "swarm/ghost", "messages": [{"role": "user", "content": "Hi"}]}))).await;
    assert_eq!(status, 503);
    assert!(String::from_utf8_lossy(&body).contains("acme/missing"));
    let (status, _) = app(address, &certificate, "POST", "/v1/chat/completions", &key, Some(json!({"model": "swarm/nobody", "messages": [{"role": "user", "content": "Hi"}]}))).await;
    assert_eq!(status, 404);
    assert_eq!(hub.remove_harness("swarm/ghost").unwrap()["removed"], true);
    assert_eq!(hub.status()["harnesses"].as_array().unwrap().len(), 1);

    drop(gates);
    for worker in workers {
        worker.abort();
    }
}

/// A closed bounty host serving a source, and a computer joining with the member client to fetch
/// the source and report a finding. The worker's model is not run here; this tests the hub
/// transport and its security, like the grid test above.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_computer_joins_a_closed_bounty_fetches_the_source_and_reports_a_finding() {
    use crate::bounty::{self, Bounty, SourceFile};
    use crate::invite::{self, Invite};
    use base64::Engine as _;

    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("bounty.json");
    let salt = password::new_salt();
    let password_key = password::derive(PASSWORD, &salt).unwrap();
    let file = SourceFile { path: "src/app.py".into(), data: base64::engine::general_purpose::STANDARD.encode("def checkout(cart):\n    return cart.total\n") };
    let bounty = Bounty::checked("Review checkout", "Look for logic flaws", "You may test this source", vec![file]).unwrap();
    let key = bounty::create(&path, "Acme", "127.0.0.1".parse().unwrap(), 0, None, None, &salt, bounty).unwrap();
    let hub = bounty::Hub::start(path, &key, &password_key, Arc::new(|_, _| {})).await.unwrap();
    let fingerprint = net::fingerprint(&hub.record().certificate).unwrap();
    let the_invite = Invite { company: "Acme".into(), address: HubAddress::Direct(hub.address()), fingerprint: fingerprint.clone() };

    // The invite round-trips through its code, as a person would paste it.
    let code = invite::encode_bounty(&the_invite);
    let read = invite::decode_bounty(&code).unwrap();

    // A wrong password is refused.
    assert!(bounty::member_join(&read, "wrong password!", "Design laptop", "windows", "hf.co/acme/model-GGUF").await.err().unwrap().to_lowercase().contains("password"));
    // A wrong fingerprint in the invite is refused before trusting the host.
    let forged = Invite { fingerprint: format!("{}00", "00:".repeat(31)), ..read.clone() };
    assert!(bounty::member_join(&forged, PASSWORD, "PC", "windows", "m").await.err().unwrap().contains("fingerprint"));

    // Join with the right password and the chosen model, over the pinned certificate.
    let member = bounty::member_join(&read, PASSWORD, "Design laptop", "windows", "hf.co/acme/model-GGUF").await.unwrap();
    assert_eq!((member.bounty_name.as_str(), member.bounty_title.as_str(), member.fingerprint.as_str()), ("Acme", "Review checkout", fingerprint.as_str()));

    // The source downloads and is checked; the worker checks in and reports what it found.
    let source = member.source().await.unwrap();
    assert_eq!((source.title.as_str(), source.files.len()), ("Review checkout", 1));
    assert_eq!(source.files[0].path, "src/app.py");
    member.heartbeat("running", "Reading the checkout code", "hf.co/acme/model-GGUF").await.unwrap();
    member.report("Total is not recomputed", "cart.total is trusted from the client", "high").await.unwrap();

    // The host sees the computer, its model and the finding.
    let shown = hub.status();
    assert_eq!(shown["computers"]["total"], 1);
    assert_eq!(shown["members"][0]["model"], "hf.co/acme/model-GGUF");
    assert_eq!(shown["members"][0]["state"], "running");
    assert_eq!(shown["findings"][0]["title"], "Total is not recomputed");
    assert_eq!(shown["findings"][0]["memberName"], "Design laptop");

    // Leaving removes the computer from the host.
    member.leave().await.unwrap();
    assert_eq!(hub.status()["computers"]["total"], 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_bounty_managed_protocol_persists_leases_reports_and_private_chat() {
    use crate::bounty::{self, Bounty, SourceFile};
    let folder=tempfile::tempdir().unwrap();let path=folder.path().join("host.json");
    let bounty=Bounty::checked("Managed fixture","Review fixture","Owner authorizes fixture",vec![SourceFile{path:"app.py".into(),data:"cHJpbnQoMSk=".into()}]).unwrap();
    let key=bounty::create(&path,"Fixture","127.0.0.1".parse().unwrap(),0,None,None,"fixture",bounty).unwrap();
    let hub=bounty::Hub::start(path.clone(),&key,"unused-owner-key",Arc::new(|_,_|{})).await.unwrap();
    let member=hub.local_member("Worker one").unwrap();let peer=hub.local_member("Worker two").unwrap();
    let policy=member.agent("GET","/api/swarm/agent/offer",None).await.unwrap()["policy"].clone();
    for client in [&member,&peer] {
        client.agent("POST","/api/swarm/agent/accept",Some(&json!({"confirmed":true,"termsDigest":policy["termsDigest"],"budgetMinutes":30,"reportPolicy":"review","deferUntilReady":true,"idempotencyKey":"accept"}))).await.unwrap();
        assert_eq!(client.agent("GET","/api/swarm/agent/state",None).await.unwrap()["executionAllowed"],false);
        client.agent("POST","/api/swarm/agent/activate",Some(&json!({"idempotencyKey":"activate"}))).await.unwrap();
    }
    let lease=member.agent("POST","/api/swarm/agent/tasks/reserve",Some(&json!({"component":"app.py","category":"authorization","conditions":"baseline","idempotencyKey":"reserve"}))).await.unwrap()["lease"].clone();
    member.agent("POST","/api/swarm/agent/observations",Some(&json!({"leaseId":lease["leaseId"],"generation":1,"kind":"observation","content":"Baseline tested","idempotencyKey":"share"}))).await.unwrap();
    assert_eq!(peer.agent("GET","/api/swarm/agent/events?after=0",None).await.unwrap()["events"][0]["body"]["content"],"Baseline tested");
    member.agent("POST","/api/swarm/agent/conversation",Some(&json!({"content":"Private question","idempotencyKey":"question"}))).await.unwrap();
    assert_eq!(peer.agent("GET","/api/swarm/agent/conversation",None).await.unwrap()["messages"],json!([]));
    let attempt=member.agent("POST","/api/swarm/agent/attempts",Some(&json!({"leaseId":lease["leaseId"],"generation":1,"outcome":"candidate","observations":"Fixture result","evidence":[{"name":"receipt.txt","contentBase64":"dGVzdA=="}],"idempotencyKey":"attempt"}))).await.unwrap();
    let evidence=member.agent("POST","/api/swarm/agent/evidence",Some(&json!({"name":"receipt.txt","contentBase64":"dGVzdA==","idempotencyKey":"evidence"}))).await.unwrap();
    let report=member.agent("POST","/api/swarm/agent/reports",Some(&json!({"sourceRevision":policy["sourceRevision"],"title":"Fixture finding","component":"app.py","reproduction":"Run fixture","observed":"Fixture result","expected":"Expected baseline","impact":"Test impact","attemptIds":[attempt["attempt"]["id"]],"evidenceIds":[evidence["evidence"]["id"]],"idempotencyKey":"report"}))).await.unwrap();
    assert_eq!(report["report"]["state"],"draft");assert_eq!(hub.status()["coordination"]["reports"],json!([]));
    member.agent("POST","/api/swarm/agent/submit",Some(&json!({"reportId":report["report"]["id"],"idempotencyKey":"submit"}))).await.unwrap();
    assert_eq!(hub.status()["coordination"]["reports"][0]["document"]["observed"],"Fixture result");
    drop(hub);
    let hub=bounty::Hub::start(path,&key,"unused-owner-key",Arc::new(|_,_|{})).await.unwrap();
    let restored=bounty::Member::restore(HubAddress::Direct(hub.address()),&member.certificate,member.member_id.clone(),member.token.clone()).unwrap();
    assert_eq!(restored.agent("GET","/api/swarm/agent/reports",None).await.unwrap()["reports"][0]["state"],"complete_received");
    hub.remove_member(&member.member_id).unwrap();assert!(restored.agent("GET","/api/swarm/agent/state",None).await.is_err());
}

/// The admin orders a desk for a person; a company computer builds and shares it within the
/// share the admin set, in use or not; the person signs in from elsewhere and receives the
/// invitation. Wrong passwords and unknown names are refused without saying which. The sandbox
/// itself is not built here: the host reports it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn people_sign_in_and_get_desks_within_each_computers_share() {
    use crate::desks::{Capacity, DeskKind, DeskReport, DeskSpec, Share};
    use crate::invite::Invite;
    const ADA: &str = "ada's own password";
    let folder = tempfile::tempdir().unwrap();
    let (hub, events) = start_hub(folder.path()).await;
    let address = hub.address();
    let fingerprint = net::fingerprint(&hub.record().certificate).unwrap();
    let the_invite = Invite { company: "Acme".into(), address: HubAddress::Direct(address), fingerprint: fingerprint.clone() };

    // The admin adds a person and orders a desk for them; nothing hosts it yet.
    let salt = password::new_salt();
    let key = password::derive(ADA, &salt).unwrap();
    let person = hub.add_person("Ada.Lovelace", "Ada Lovelace", &salt, &key, None).unwrap();
    assert_eq!(person["username"], "ada.lovelace");
    assert!(hub.add_person("ada.lovelace", "Again", &salt, &key, None).unwrap_err().contains("already"));
    let spec = DeskSpec::checked(DeskKind::Container, 2.0, 4.0, 20.0, false, "").unwrap();
    let desk = hub.add_desk("Design desk", spec, Some("ada.lovelace")).unwrap();
    assert_eq!((desk["state"].as_str(), desk["person"].as_str()), (Some("planned"), Some("Ada Lovelace")));
    assert!(hub.add_desk("Nobody's", DeskSpec::checked(DeskKind::Vm, 1.0, 2.0, 10.0, false, "prepared.qcow2").unwrap(), Some("grace")).unwrap_err().contains("No person"));
    let desk_id = desk["id"].as_str().unwrap().to_owned();

    // Signing in before the desk is built lists it without an invitation.
    let session = member::person_login(&the_invite, "ada.lovelace", ADA, None).await.unwrap();
    assert_eq!((session.name.as_str(), session.grid_name.as_str(), session.desks.len()), ("Ada Lovelace", "Acme", 1));
    assert!(session.desks[0].get("invitation").is_none());
    assert!(member::person_login(&the_invite, "ada.lovelace", "not her password", None).await.unwrap_err().contains("username or password is wrong"));
    assert!(member::person_login(&the_invite, "nobody", ADA, None).await.unwrap_err().contains("username or password is wrong"));
    let forged = Invite { fingerprint: format!("{}00", "00:".repeat(31)), ..the_invite.clone() };
    assert!(member::person_login(&forged, "ada.lovelace", ADA, None).await.unwrap_err().contains("fingerprint"));

    // A computer joins. Its admin first lets the grid use it only while idle: in use, it takes no
    // desk. Allowed a share whether in use or not, it is told to build the desk at once.
    let joined = member::join("Acme", address, PASSWORD, "Studio PC", "windows", false, None).await.unwrap();
    let host = &joined.membership;
    let member_id = joined.membership.member_id.clone();
    let busy = Capacity { desk_protocol: 2, battery_percent: None, going_away: None, cpu: 8, cpu_used_percent: 40.0, memory_gb: 32.0, used_memory_gb: 12.0, free_disk_gb: 300.0, gpu: false, gpu_used_percent: None, on_battery: false, in_use: true };
    hub.set_member_share(&member_id, Some(Share::checked(2.0, 8.0, 100.0, false, true).unwrap())).unwrap();
    let instructions = host.check_in("test", false, &[], Some(&busy), &[]).await.unwrap();
    assert!(instructions.desks.is_empty(), "a share that waits for idle takes no desk while someone is using the computer");
    let shown = hub.status()["members"][0].clone();
    assert_eq!((shown["capacity"]["cpuUsedPercent"].as_f64(), shown["capacity"]["inUse"].as_bool(), shown["share"]["cpu"].as_f64(), shown["shareSet"].as_bool()), (Some(40.0), Some(true), Some(2.0), Some(true)), "what it reports, and the admin's share");
    let suggested = hub.set_member_share(&member_id, None).unwrap();
    assert_eq!((suggested["share"]["cpu"].as_f64(), suggested["share"]["memoryGb"].as_f64(), suggested["share"]["idleOnly"].as_bool(), suggested["shareSet"].as_bool()), (Some(4.0), Some(15.0), Some(false), Some(false)), "back to the suggestion: half of it, in use or not");
    let instructions = host.check_in("test", false, &[], Some(&busy), &[]).await.unwrap();
    assert_eq!(instructions.desks.len(), 1, "within its share, a computer in use hosts the desk");
    assert_eq!((instructions.desks[0].id.as_str(), instructions.desks[0].person_name.as_str(), instructions.desks[0].needs_invitation), (desk_id.as_str(), "Ada Lovelace", false));
    assert_eq!(hub.status()["desks"][0]["state"], "building");
    let committed = busy.clone();
    // A host echoes the generation it was ordered; a report from an older order is ignored.
    let generation = instructions.desks[0].generation;

    // The host reports it ready and hands over the invitation; the hub keeps it in memory only.
    let invitation = json!({"version": 1, "address": "192.168.1.30:40123", "certificate": "PEM", "token": "t", "expiresAt": crate::now() + 86_400});
    let ready = DeskReport { generation, parcel: None, id: desk_id.clone(), state: "ready".into(), environment_id: Some("env-desk-1".into()), note: String::new(), invitation: Some(invitation.clone()), invitation_expires_at: Some(crate::now() + 86_400) };
    let instructions = host.check_in("test", false, &[], Some(&committed), &[ready]).await.unwrap();
    assert!(!instructions.desks[0].needs_invitation);
    let shown = hub.status();
    assert_eq!((shown["desks"][0]["state"].as_str(), shown["desks"][0]["reachable"].as_bool(), shown["desks"][0]["host"].as_str()), (Some("ready"), Some(true), Some("Studio PC")));
    assert!(shown["desks"][0].get("invitation").is_none(), "status never shows the secret");
    assert_eq!(shown["members"][0]["desks"], 1);
    assert!(!std::fs::read_to_string(folder.path().join("hub.json")).unwrap().contains("40123"), "invitations are never written to disk");

    // The person signs in and gets the invitation to their desk.
    let session = member::person_login(&the_invite, "ADA.LOVELACE", ADA, None).await.unwrap();
    assert_eq!(session.desks[0]["invitation"], invitation);
    assert_eq!(session.desks[0]["host"], "Studio PC");

    // A desk the host lost is placed again; one removed by the admin disappears from the host's orders.
    let gone = DeskReport { generation, id: desk_id.clone(), state: "gone".into(), ..DeskReport::default() };
    let instructions = host.check_in("test", false, &[], Some(&committed), &[gone]).await.unwrap();
    assert_eq!((instructions.desks.len(), instructions.desks[0].needs_invitation), (1, false), "placed again on the same computer, building from scratch");
    assert_eq!(hub.status()["desks"][0]["state"], "building");
    hub.remove_desk(&desk_id).unwrap();
    let instructions = host.check_in("test", false, &[], Some(&committed), &[]).await.unwrap();
    assert!(instructions.desks.is_empty());
    hub.remove_person("ada.lovelace").unwrap();
    assert!(member::person_login(&the_invite, "ada.lovelace", ADA, None).await.is_err());
    let seen = events.lock().unwrap().clone();
    for kind in ["grid.person.added", "grid.desk.added", "grid.computer.share", "grid.desk.shared", "grid.person.signed_in", "grid.person.refused", "grid.desk.removed", "grid.person.removed"] {
        assert!(seen.contains(&kind), "{kind} is audited");
    }
}

/// Deleting a grid: scheduled, it pauses and can be restored; deleted, every computer is told
/// when it next checks in, and the hub is finished once all have heard.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_deleted_grid_pauses_until_restored_then_tells_every_computer() {
    use crate::hub::Phase;
    let folder = tempfile::tempdir().unwrap();
    let (hub, events) = start_hub(folder.path()).await;
    let address = hub.address();
    let laptop = member::join("Acme", address, PASSWORD, "Laptop", "windows", false, None).await.unwrap().membership;
    let desktop = member::join("Acme", address, PASSWORD, "Desktop", "windows", false, None).await.unwrap().membership;

    // Scheduled: paused for three days. Computers hear when; nobody new joins; restore undoes it.
    let closing = hub.close(false).unwrap();
    let until = closing["until"].as_i64().unwrap();
    assert!(closing["gone"] == false && until - crate::now() > hub::GRACE - 60);
    assert_eq!(hub.phase(), Phase::Paused(until));
    assert_eq!(laptop.heartbeat("test", false, &[]).await.unwrap().paused_until, Some(until));
    assert!(member::join("Acme", address, PASSWORD, "Late", "windows", false, None).await.err().is_some_and(|error| error.contains("paused")), "nobody joins a paused grid");
    assert_eq!(hub.close(false).unwrap()["until"].as_i64(), Some(until), "asking again keeps the date");
    hub.restore().unwrap();
    assert_eq!(laptop.heartbeat("test", false, &[]).await.unwrap().paused_until, None);
    assert!(hub.restore().is_err(), "nothing to restore");

    // Deleted at once: each computer is told as it checks in, and the hub counts who heard.
    hub.close(true).unwrap();
    assert_eq!(hub.phase(), Phase::Gone);
    assert!(hub.restore().unwrap_err().contains("no longer"), "a deleted grid cannot be restored");
    assert_eq!(laptop.heartbeat("test", false, &[]).await.err(), Some(MemberError::Deleted));
    assert_eq!((hub.status()["closing"]["told"].as_u64(), hub.status()["closing"]["computers"].as_u64()), (Some(1), Some(2)));
    assert!(!hub.finished(), "the desktop has not heard yet");
    assert_eq!(desktop.heartbeat("test", false, &[]).await.err(), Some(MemberError::Deleted));
    assert!(hub.finished());
    assert!(laptop.leave().await.is_ok(), "leaving a deleted grid is not an error");
    let saved = hub::load(&folder.path().join("hub.json")).unwrap();
    assert!(serde_json::to_value(saved).unwrap()["closing"]["until"].is_i64(), "a restart keeps the deletion");
    let seen = events.lock().unwrap().clone();
    for kind in ["grid.closing", "grid.restored", "grid.member.told_deleted"] {
        assert!(seen.contains(&kind), "{kind} is audited");
    }
}

/// A computer that is going away hands its desk, with its data, to another computer: it packs
/// the data up, the hub holds it, and the computer that takes the desk over unpacks it. A desk
/// with nowhere to go waits, packed and safe, until a computer has room.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_computer_going_away_hands_its_desk_on_with_its_data() {
    use crate::desks::{Capacity, DeskKind, DeskReport, DeskSpec, Parcel, ParcelStore};
    let folder = tempfile::tempdir().unwrap();
    let (hub, events) = start_hub(folder.path()).await;
    let address = hub.address();
    let salt = password::new_salt();
    let key = password::derive(PASSWORD, &salt).unwrap();
    hub.add_person("ada", "Ada", &salt, &key, None).unwrap();
    let spec = DeskSpec::checked(DeskKind::Container, 1.0, 2.0, 10.0, false, "").unwrap();
    let desk_id = hub.add_desk("Ada's desk", spec, Some("ada")).unwrap()["id"].as_str().unwrap().to_owned();

    let laptop = member::join("Acme", address, PASSWORD, "Laptop", "windows", false, None).await.unwrap().membership;
    let desktop = member::join("Acme", address, PASSWORD, "Desktop", "windows", false, None).await.unwrap().membership;
    let roomy = Capacity { cpu: 8, memory_gb: 32.0, free_disk_gb: 400.0, desk_protocol: 2, ..Capacity::default() };
    // The laptop takes the desk; the desktop reports no room at all, so nothing moves there yet.
    let full = Capacity { free_disk_gb: 4.0, ..roomy.clone() };
    assert_eq!(laptop.check_in("test", false, &[], Some(&roomy), &[]).await.unwrap().desks.len(), 1);
    desktop.check_in("test", false, &[], Some(&full), &[]).await.unwrap();
    let ready = DeskReport { id: desk_id.clone(), state: "ready".into(), environment_id: Some("env-1".into()), generation: 1, ..DeskReport::default() };
    laptop.check_in("test", false, &[], Some(&roomy), &[ready]).await.unwrap();
    assert_eq!(hub.status()["desks"][0]["state"], "ready");

    // The laptop's battery is running out: it is told to pack the desk up, not to keep running it.
    let leaving = Capacity { on_battery: true, battery_percent: Some(9), going_away: Some("Its battery is running out".into()), ..roomy.clone() };
    let orders = laptop.check_in("test", false, &[], Some(&leaving), &[]).await.unwrap().desks;
    assert_eq!((orders.len(), orders[0].park, orders[0].adopt.is_none()), (1, true, true));
    let shown = hub.status()["desks"][0].clone();
    assert_eq!((shown["state"].as_str(), shown["movingFrom"].is_null(), shown["hostId"].is_null()), (Some("moving"), false, true));

    // It packs the data and sends it to the hub; the hub only lets that computer send it.
    let data = vec![7u8; 300_000];
    assert!(desktop.desk_parcel_put(&desk_id, 0, data.clone(), true).await.is_err(), "only the computer giving the desk up may send its data");
    laptop.desk_parcel_put(&desk_id, 0, data[..100_000].to_vec(), false).await.unwrap();
    laptop.desk_parcel_put(&desk_id, 100_000, data[100_000..].to_vec(), true).await.unwrap();
    let parcel = Parcel { store: ParcelStore::Hub, key: desk_id.clone(), bytes: data.len() as u64, sha256: "a".repeat(64), at: crate::now() };
    let parked = DeskReport { id: desk_id.clone(), state: "parked".into(), parcel: Some(parcel), generation: 1, ..DeskReport::default() };
    let orders = laptop.check_in("test", false, &[], Some(&leaving), &[parked]).await.unwrap().desks;
    assert!(orders.is_empty(), "the computer that gave it up has nothing left to do");
    let shown = hub.status()["desks"][0].clone();
    assert_eq!((shown["state"].as_str(), shown["parcelBytes"].as_u64(), shown["note"].as_str()), (Some("moving"), Some(300_000), Some("Its data is packed and waiting for a computer with room")));

    // Nobody has room yet: the data waits, safe. Then the desktop frees space and takes it.
    desktop.check_in("test", false, &[], Some(&full), &[]).await.unwrap();
    assert!(hub.status()["desks"][0]["hostId"].is_null(), "no room anywhere: it waits");
    let orders = desktop.check_in("test", false, &[], Some(&roomy), &[]).await.unwrap().desks;
    assert_eq!(orders.len(), 1);
    assert_eq!((orders[0].park, orders[0].adopt.as_ref().map(|parcel| parcel.bytes)), (false, Some(300_000)));

    // It fetches the data in pieces, unpacks it and reports the desk running again.
    let (size, first) = desktop.desk_parcel_get(&desk_id, 0).await.unwrap();
    assert_eq!((size, first.len()), (300_000, 300_000));
    assert_eq!(first.as_ref(), data.as_slice());
    assert!(laptop.desk_parcel_get(&desk_id, 0).await.is_err(), "only the computer taking it over may read it");
    let adopted = DeskReport { id: desk_id.clone(), state: "adopted".into(), environment_id: Some("env-2".into()), generation: 1, ..DeskReport::default() };
    desktop.check_in("test", false, &[], Some(&roomy), &[adopted]).await.unwrap();
    let shown = hub.status()["desks"][0].clone();
    assert_eq!((shown["state"].as_str(), shown["host"].as_str(), shown["parcelBytes"].is_null()), (Some("building"), Some("Desktop"), true));
    assert!(!folder.path().join("parcels").join(format!("{desk_id}.parcel")).exists(), "the hub keeps no copy once it is unpacked");
    assert!(desktop.desk_parcel_get(&desk_id, 0).await.is_err(), "and it can no longer be read");
    assert!(events.lock().unwrap().contains(&"grid.desk.added"));
}

/// With the company's bucket set up, desks park there: the hub saves only where, hands the
/// keys to a computer only while it packs or unpacks a desk, and never shows them.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn desks_park_in_the_companys_bucket_and_only_the_movers_get_its_keys() {
    use crate::desks::{Capacity, DeskKind, DeskReport, DeskSpec, Parcel, ParcelStore};
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    let address = hub.address();
    assert!(hub.enterprise(json!({"action":"parkingSet","provider":"awsS3","location":"https://not-a-bucket"})).is_err(), "AWS parking is an s3:// location");
    assert!(hub.enterprise(json!({"action":"parkingSet","provider":"awsS3","location":"s3://acme-desks/parking?region=eu-west-1"})).is_ok());
    let status = hub.status();
    assert_eq!(status["enterprise"]["parking"]["location"], "s3://acme-desks/parking?region=eu-west-1");
    assert!(!status.to_string().contains("secretKey"), "status never carries keys");
    assert!(!hub.parks_in_bucket(), "the place alone is not enough: the keys are loaded by the hub computer");
    hub.set_parking(Some(json!({"provider":"awsS3","location":"s3://acme-desks/parking?region=eu-west-1","accessKey":"AKIA-TEST","secretKey":"very-secret"})));
    assert!(hub.parks_in_bucket());
    assert!(!std::fs::read_to_string(folder.path().join("hub.json")).unwrap().contains("very-secret"), "keys are never written to disk");

    let salt = password::new_salt();
    let key = password::derive(PASSWORD, &salt).unwrap();
    hub.add_person("ada", "Ada", &salt, &key, None).unwrap();
    let desk_id = hub.add_desk("Ada's desk", DeskSpec::checked(DeskKind::Container, 1.0, 2.0, 10.0, false, "").unwrap(), Some("ada")).unwrap()["id"].as_str().unwrap().to_owned();
    let laptop = member::join("Acme", address, PASSWORD, "Laptop", "windows", false, None).await.unwrap().membership;
    let desktop = member::join("Acme", address, PASSWORD, "Desktop", "windows", false, None).await.unwrap().membership;
    let roomy = Capacity { cpu: 8, memory_gb: 32.0, free_disk_gb: 400.0, desk_protocol: 2, ..Capacity::default() };
    let full = Capacity { free_disk_gb: 4.0, ..roomy.clone() };
    let instructions = laptop.check_in("test", false, &[], Some(&roomy), &[]).await.unwrap();
    assert!(instructions.desks.len() == 1 && instructions.parking.is_none(), "running a desk needs no keys");
    desktop.check_in("test", false, &[], Some(&full), &[]).await.unwrap();

    // Giving the desk up: this computer is told to park in the bucket, and gets the keys for it.
    let leaving = Capacity { going_away: Some("Yougori is closing on this computer".into()), ..roomy.clone() };
    let instructions = laptop.check_in("test", false, &[], Some(&leaving), &[]).await.unwrap();
    assert_eq!((instructions.desks[0].park, instructions.desks[0].park_in), (true, ParcelStore::S3));
    assert_eq!(instructions.parking.as_ref().map(|keys| keys["secretKey"].as_str()), Some(Some("very-secret")));
    let parcel = Parcel { store: ParcelStore::S3, key: "yougori-desks/acme/desk-1.yougori-backup".into(), bytes: 5_000_000, sha256: "b".repeat(64), at: crate::now() };
    let parked = DeskReport { id: desk_id.clone(), state: "parked".into(), parcel: Some(parcel), generation: 1, ..DeskReport::default() };
    let instructions = laptop.check_in("test", false, &[], Some(&leaving), &[parked]).await.unwrap();
    assert!(instructions.desks.is_empty() && instructions.parking.is_none(), "once parked, this computer gets neither orders nor keys");

    // The computer that takes it over gets the keys with its adopt order; a bystander never does.
    let bystander = member::join("Acme", address, PASSWORD, "Bystander", "windows", false, None).await.unwrap().membership;
    assert!(bystander.check_in("test", false, &[], Some(&full), &[]).await.unwrap().parking.is_none());
    let instructions = desktop.check_in("test", false, &[], Some(&roomy), &[]).await.unwrap();
    assert_eq!(instructions.desks[0].adopt.as_ref().map(|parcel| parcel.store), Some(ParcelStore::S3));
    assert!(instructions.parking.is_some());
    assert!(!hub.status()["desks"][0].to_string().contains("secretKey"));
    hub.enterprise(json!({"action":"parkingClear"})).unwrap();
    hub.set_parking(None);
    assert!(hub.status()["enterprise"]["parking"].is_null() && !hub.parks_in_bucket());
}

/// When a desk waits too long with no room anywhere, the hub says a computer is needed; one it
/// creates itself takes up a membership made ahead of time, with a token instead of the password.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_computer_the_hub_creates_adopts_a_ready_made_membership() {
    use crate::desks::{Capacity, DeskKind, DeskSpec, CLOUD_AFTER};
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    assert!(hub.enterprise(json!({"action":"cloudFallbackSet","provider":"aws","account":"work","region":"eu-west-1","image":"ami-123","machineType":"t3.large","subnet":"subnet-1","securityGroup":"sg-1","keyPair":"desks","identityFile":"C:/keys/desks.pem","maxComputers":2})).is_ok());
    assert!(hub.enterprise(json!({"action":"cloudFallbackSet","provider":"aws","account":"work","region":"eu-west-1","image":"ami-123","machineType":"t3.large","subnet":"subnet-1","identityFile":"C:/keys/desks.pem"})).is_err(), "AWS needs a key pair and a security group");
    assert_eq!(hub.status()["enterprise"]["cloudFallback"]["maxComputers"], 2);

    // A desk nobody can take: not needed at once, needed once it has waited long enough.
    let salt = password::new_salt();
    let key = password::derive(PASSWORD, &salt).unwrap();
    hub.add_person("ada", "Ada", &salt, &key, None).unwrap();
    hub.add_desk("Ada's desk", DeskSpec::checked(DeskKind::Container, 1.0, 2.0, 10.0, false, "").unwrap(), Some("ada")).unwrap();
    assert!(hub.needs_computer().is_none(), "not yet: it only just started waiting");
    assert!(hub.needs_computer_at(crate::now() + CLOUD_AFTER + 1).is_some_and(|why| why.contains("Ada's desk")), "after waiting long enough with no room anywhere");

    // The hub makes the membership; the new computer adopts it with the token alone.
    let made = hub.preregister_member("yougori-desk-1", "cloud-fallback").unwrap();
    let joined = member::adopt("Acme", hub.address(), made["fingerprint"].as_str().unwrap(), made["memberId"].as_str().unwrap(), made["memberToken"].as_str().unwrap()).await.unwrap();
    assert_eq!(joined.grid_name, "Acme");
    assert!(member::adopt("Acme", hub.address(), made["fingerprint"].as_str().unwrap(), made["memberId"].as_str().unwrap(), &crate::token()).await.is_err(), "a wrong token is refused");
    let roomy = Capacity { cpu: 8, memory_gb: 32.0, free_disk_gb: 400.0, desk_protocol: 2, ..Capacity::default() };
    assert_eq!(joined.membership.check_in("test", false, &[], Some(&roomy), &[]).await.unwrap().desks.len(), 1, "the waiting desk lands on it");
    assert!(hub.needs_computer().is_none());
    assert_eq!(hub.status()["members"][0]["platform"], "cloud-fallback");
}

/// PROVES that a connector task interrupted by the hub stopping is picked up when it starts
/// again, rather than leaving that person unassignable at that provider for good.
///
/// This is the wiring rather than the decision: `resume_interrupted` is checked on its own in
/// `hub::tests`, and what is checked here is that starting a hub actually runs it against what
/// was saved, and that the grid will queue work for that person again afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_connector_task_is_picked_up_again_when_the_hub_starts() {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("hub.json");
    let salt = password::new_salt();
    let password_key = password::derive(PASSWORD, &salt).unwrap();
    let key = hub::create(&path, "Acme", "127.0.0.1".parse().unwrap(), 0, None, Some(0), &salt).unwrap();
    let quiet: crate::hub::Events = Arc::new(|_, _| {});

    let (task, connection, person) = {
        let hub = Hub::start(path.clone(), &key, &password_key, quiet.clone()).await.unwrap();
        let connection = hub.enterprise(json!({"action":"connectionAdd","name":"Horizon","provider":"horizon","url":"https://horizon.acme.example","target":{"username":"admin","domain":"ACME","pool":"pool-1"},"credentialSet":true})).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        hub.set_connection_credential(&connection, Some(json!({"password": "the admin's password"})));
        let person_salt = password::new_salt();
        let person_key = password::derive("ada's own password", &person_salt).unwrap();
        let person = hub.add_person("ada", "Ada", &person_salt, &person_key, None).unwrap()["id"].as_str().unwrap().to_owned();
        hub.enterprise(json!({"action":"personUpdate","id":person.clone(),"email":"ada@acme.example"})).unwrap();
        let task = hub.enterprise(json!({"action":"connectionProvision","id":connection.clone(),"personId":person.clone()})).unwrap()["taskId"].as_str().unwrap().to_owned();

        // Handed out, so it is running. Then the hub stops, which is the whole of the trouble:
        // the only thing that moves a task off running is the computer that was running it.
        assert_eq!(hub.provisioning_due().len(), 1);
        assert_eq!(hub.status()["enterprise"]["provisioning"][0]["state"], "running");
        // And while it is running, asking for the same thing again is swallowed as a duplicate.
        assert_eq!(hub.enterprise(json!({"action":"connectionProvision","id":connection.clone(),"personId":person})).unwrap()["taskId"], task);
        (task, connection, person)
    };

    // The same grid, opened again. Nothing is running, so nothing is marked as running.
    let hub = Hub::start(path, &key, &password_key, quiet).await.unwrap();
    let state = hub.status()["enterprise"]["provisioning"][0].clone();
    assert_eq!(state["id"], task);
    assert_eq!(state["state"], "pending", "it still needs doing: {state}");

    // The secret is not in the record and never was, so a hub that has just started does not
    // hold it; the task waits to be told rather than being thrown away.
    assert!(hub.provisioning_due().is_empty());
    assert_eq!(hub.status()["enterprise"]["provisioning"][0]["state"], "failed", "and it says which, rather than looking busy");
    assert!(hub.status()["enterprise"]["provisioning"][0]["note"].as_str().unwrap().contains("vault"));

    // With the credential loaded from this computer's vault, as the app does when it opens the
    // grid, the work this person was waiting on is asked for again and handed out.
    hub.set_connection_credential(&connection, Some(json!({"password": "the admin's password"})));
    let again = hub.enterprise(json!({"action":"connectionProvision","id":connection,"personId":person})).unwrap()["taskId"].as_str().unwrap().to_owned();
    assert_ne!(again, task, "the interrupted one is settled, so this is a new one rather than a duplicate swallowed");
    assert_eq!(hub.provisioning_due().len(), 1, "and it runs, instead of waiting for ever on a hub that is gone");
}

/// PROVES that a person is tied to their account at the identity provider, and not to an email.
///
/// An address is not an identity. Companies give a leaver's address to whoever takes the job, and
/// a provider can be asked for a token carrying an address its holder only claims; matching on
/// the address alone makes the next holder of an address the holder of the account. The provider
/// publishes its own id for an account, `sub`, which it never hands on. The first sign-in writes
/// it down and from then on only that account is this person — whatever address it carries, and
/// however convincing another account with the same address looks.
///
/// The way back is an admin's deliberate act on one named person, because a directory really can
/// be rebuilt and an account really can move.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_person_is_tied_to_their_account_at_the_identity_provider_not_to_an_email() {
    use crate::{invite::Invite, jwt::tests::Issuer, provisioning::tests::mock};
    let signer = Arc::new(Issuer::new("k2026"));
    let issuer_url: Arc<Mutex<String>> = Arc::default();
    let issuer_for_discovery = issuer_url.clone();
    let issuer_for_mock = signer.clone();
    // Only discovery and the keys: every token below is handed to the hub directly, so what is
    // under test is what the hub does with a token rather than how a browser fetched one.
    let (provider, _) = mock(move |method, path, _| {
        let base = issuer_for_discovery.lock().unwrap().clone();
        match (method, path) {
            ("GET", "/.well-known/openid-configuration") => (200, json!({"issuer": base, "authorization_endpoint": format!("{base}/authorize"), "token_endpoint": format!("{base}/token"), "jwks_uri": format!("{base}/keys")})),
            ("GET", "/keys") => (200, issuer_for_mock.jwks()),
            _ => (404, json!({"error": "no"})),
        }
    })
    .await;
    *issuer_url.lock().unwrap() = provider.clone();
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    let the_invite = Invite { company: "Acme".into(), address: HubAddress::Direct(hub.address()), fingerprint: net::fingerprint(&hub.record().certificate).unwrap() };
    let _ = &the_invite;
    hub.enterprise(json!({"action":"ssoSet","issuer":provider.clone(),"clientId":"desks-app"})).unwrap();

    let salt = password::new_salt();
    let key = password::derive("ada's own password", &salt).unwrap();
    let person_id = hub.add_person("ada", "Ada Lovelace", &salt, &key, None).unwrap()["id"].as_str().unwrap().to_owned();
    hub.enterprise(json!({"action":"personUpdate","id":person_id.clone(),"email":"ada@acme.example"})).unwrap();

    // One token from the provider, with whatever claims the case being checked needs.
    let certificate = hub.record().certificate.clone();
    let address = hub.address();
    let signed = {
        let signer = signer.clone();
        let provider = provider.clone();
        move |extra: Value| {
            let mut claims = json!({"iss": provider, "aud": "desks-app", "exp": crate::now() + 300, "iat": crate::now(), "nonce": "mine"});
            for (name, value) in extra.as_object().unwrap() {
                claims[name] = value.clone();
            }
            signer.token(&claims)
        }
    };
    let sign_in = |token: String| {
        let certificate = certificate.clone();
        async move { app(address, &certificate, "POST", "/grid/v1/person/sso", "", Some(json!({"idToken": token, "nonce": "mine"}))).await }
    };
    let said = |body: Vec<u8>| String::from_utf8_lossy(&body).into_owned();

    // A token naming no account is refused: there would be nothing to tie them to.
    let (status, body) = sign_in(signed(json!({"email": "ada@acme.example", "email_verified": true}))).await;
    assert!(status == 403 && said(body).contains("names no account"), "a token with no sub cannot sign anybody in");

    // An address the provider says it has not checked proves nothing about who holds it.
    let (status, body) = sign_in(signed(json!({"sub": "provider-ada", "email": "ada@acme.example", "email_verified": false}))).await;
    assert!(status == 403 && said(body).contains("has not verified"), "an unverified address is not an identity");

    // Her first sign-in ties her to the account it came from.
    let (status, body) = sign_in(signed(json!({"sub": "provider-ada", "email": "ada@acme.example", "email_verified": true}))).await;
    assert_eq!(status, 200, "{}", said(body));
    assert_eq!(hub.status()["people"][0]["id"], person_id);

    // Somebody else at the provider, holding the same address — the leaver's address given to
    // whoever replaced them — is not her, and is told so rather than being let in as her.
    let (status, body) = sign_in(signed(json!({"sub": "provider-eve", "email": "ada@acme.example", "email_verified": true}))).await;
    let refused = said(body);
    assert_eq!(status, 403, "{refused}");
    assert!(refused.contains("another account at the identity provider"), "{refused}");

    // Her own account signs her in whatever address it carries now, because the tie is to the
    // account. This is the case the address match got backwards.
    let (status, body) = sign_in(signed(json!({"sub": "provider-ada", "email": "ada.lovelace@acme.example", "email_verified": true}))).await;
    assert_eq!(status, 200, "{}", said(body));

    // The way back: an admin sets her address again, which unties her, and the next sign-in ties
    // her afresh to whichever account arrives with it.
    hub.enterprise(json!({"action":"personUpdate","id":person_id.clone(),"email":"ada.lovelace@acme.example"})).unwrap();
    let (status, body) = sign_in(signed(json!({"sub": "provider-ada-rebuilt", "email": "ada.lovelace@acme.example", "email_verified": true}))).await;
    assert_eq!(status, 200, "{}", said(body));
    let (status, _) = sign_in(signed(json!({"sub": "provider-ada", "email": "ada.lovelace@acme.example", "email_verified": true}))).await;
    assert_eq!(status, 403, "and the account she was tied to before is now the stranger");

    // Pointing the grid at another app registration makes every id it holds mean something else,
    // so everybody is untied and the next sign-in ties them again.
    hub.enterprise(json!({"action":"ssoSet","issuer":provider.clone(),"clientId":"desks-app-2"})).unwrap();
    let moved = {
        let signer = signer.clone();
        let provider = provider.clone();
        signer.token(&json!({"iss": provider, "aud": "desks-app-2", "sub": "provider-ada", "email": "ada.lovelace@acme.example", "email_verified": true, "exp": crate::now() + 300, "iat": crate::now(), "nonce": "mine"}))
    };
    let (status, body) = sign_in(moved).await;
    assert_eq!(status, 200, "a grid pointed somewhere new starts again rather than matching old ids: {}", said(body));
}

/// Two-step sign-in: a person turns it on from their own session, from then on the password
/// alone is not enough, and only the admin can reset it, never read it.
/// Sign-in through the company's identity provider: the hub trusts only tokens its issuer signed
/// for its client, for this very sign-in, naming a person's email; connectors assign that
/// person at the provider when asked and take it back when they go.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn people_sign_in_through_the_identity_provider_and_connectors_assign_them() {
    use crate::{invite::Invite, jwt::tests::Issuer, provisioning::tests::mock};
    const ADA: &str = "ada's own password";
    let signer = Arc::new(Issuer::new("k2026"));
    let nonce_seen: Arc<Mutex<String>> = Arc::default();
    let issuer_for_mock = signer.clone();
    let nonce_for_mock = nonce_seen.clone();
    let issuer_url: Arc<Mutex<String>> = Arc::default();
    let issuer_for_discovery = issuer_url.clone();
    let (provider, calls) = mock(move |method, path, body| {
        let base = issuer_for_discovery.lock().unwrap().clone();
        match (method, path) {
            ("GET", "/.well-known/openid-configuration") => (200, json!({"issuer": base, "authorization_endpoint": format!("{base}/authorize"), "token_endpoint": format!("{base}/token"), "jwks_uri": format!("{base}/keys")})),
            ("GET", "/keys") => (200, issuer_for_mock.jwks()),
            ("POST", "/token") => {
                if body["grant_type"] != "authorization_code" || body["code_verifier"].as_str().is_none_or(str::is_empty) || body["client_id"] != "desks-app" {
                    return (400, json!({"error": "invalid_grant"}));
                }
                let email = if body["code"] == "code-ada" { "Ada@Acme.example" } else if body["code"] == "code-eve" { "eve@else.example" } else { return (400, json!({"error": "invalid_grant"})) };
                let nonce = nonce_for_mock.lock().unwrap().clone();
                (200, json!({"id_token": issuer_for_mock.token(&json!({"iss": base, "aud": "desks-app", "sub": email, "email": email, "exp": crate::now() + 300, "iat": crate::now(), "nonce": nonce})), "token_type": "Bearer"}))
            }
            _ => (404, json!({"error": "no"})),
        }
    })
    .await;
    *issuer_url.lock().unwrap() = provider.clone();
    let folder = tempfile::tempdir().unwrap();
    let (hub, events) = start_hub(folder.path()).await;
    let the_invite = Invite { company: "Acme".into(), address: HubAddress::Direct(hub.address()), fingerprint: net::fingerprint(&hub.record().certificate).unwrap() };
    assert!(member::sso_config(&the_invite).await.unwrap().is_none(), "off until the admin sets it up");
    assert!(member::person_login_sso(&the_invite, |_| Ok(())).await.unwrap_err().contains("username and password"));
    assert!(hub.enterprise(json!({"action":"ssoSet","issuer":"http://provider.example","clientId":"desks-app"})).is_err(), "plain http only on this computer");
    hub.enterprise(json!({"action":"ssoSet","issuer":provider.clone(),"clientId":"desks-app"})).unwrap();
    let config = member::sso_config(&the_invite).await.unwrap().unwrap();
    assert_eq!((config["clientId"].as_str(), config["authorizationEndpoint"].as_str()), (Some("desks-app"), Some(format!("{provider}/authorize").as_str())));

    // What a browser does: it is sent to the provider, signs in there, and comes back to this
    // computer with a code. The provider remembers the nonce the sign-in asked for.
    let browser = |code: &'static str| {
        let nonce_seen = nonce_seen.clone();
        move |url: &str| {
            let fields = crate::https::fields(url.split_once('?').unwrap().1);
            let get = |name: &str| fields.iter().find(|(key, _)| key == name).map(|(_, value)| value.clone()).unwrap();
            assert_eq!((get("client_id").as_str(), get("code_challenge_method").as_str(), get("response_type").as_str()), ("desks-app", "S256", "code"));
            assert!(get("redirect_uri").starts_with("http://127.0.0.1:") && get("redirect_uri").ends_with("/callback"));
            *nonce_seen.lock().unwrap() = get("nonce");
            let back = format!("{}?code={code}&state={}", get("redirect_uri"), get("state"));
            tokio::spawn(async move {
                let answer = crate::https::call("GET", &back, &[], None, Duration::from_secs(10)).await.unwrap();
                assert!(String::from_utf8_lossy(&answer.body).contains("Signed in") || String::from_utf8_lossy(&answer.body).contains("failed"));
            });
            Ok(())
        }
    };
    let error = member::person_login_sso(&the_invite, browser("code-ada")).await.unwrap_err();
    assert!(error.contains("Nobody in this grid has the email ada@acme.example"), "{error}");

    let salt = password::new_salt();
    let key = password::derive(ADA, &salt).unwrap();
    let person = hub.add_person("ada", "Ada Lovelace", &salt, &key, None).unwrap();
    let person_id = person["id"].as_str().unwrap().to_owned();
    hub.enterprise(json!({"action":"personUpdate","id":person_id,"email":"ADA@acme.example"})).unwrap();
    assert_eq!(hub.status()["people"][0]["email"], "ada@acme.example");
    let session = member::person_login_sso(&the_invite, browser("code-ada")).await.unwrap();
    assert_eq!((session.name.as_str(), session.person_id.as_str()), ("Ada Lovelace", person_id.as_str()));
    assert!(session.session.manage(json!({"action":"portal"})).await.is_ok(), "the session is a real one");
    assert!(member::person_login_sso(&the_invite, browser("code-eve")).await.unwrap_err().contains("eve@else.example"));
    let wrong_state = |url: &str| {
        let fields = crate::https::fields(url.split_once('?').unwrap().1);
        let redirect = fields.iter().find(|(key, _)| key == "redirect_uri").map(|(_, value)| value.clone()).unwrap();
        tokio::spawn(async move {
            let _ = crate::https::call("GET", &format!("{redirect}?code=code-ada&state=forged"), &[], None, Duration::from_secs(10)).await;
        });
        Ok(())
    };
    assert!(member::person_login_sso(&the_invite, wrong_state).await.unwrap_err().contains("not the one that was started"));
    // A token the provider did not issue for this sign-in (another nonce) is refused by the hub.
    let forged = signer.token(&json!({"iss": provider, "aud": "desks-app", "email": "ada@acme.example", "exp": crate::now() + 300, "nonce": "other"}));
    let tls = net::client_config(&hub.record().certificate).unwrap();
    let (status, body) = app(hub.address(), &hub.record().certificate, "POST", "/grid/v1/person/sso", "", Some(json!({"idToken": forged, "nonce": "mine"}))).await;
    assert_eq!(status, 403, "{}", String::from_utf8_lossy(&body));
    let other_issuer = Issuer::new("k2026");
    let stranger = other_issuer.token(&json!({"iss": provider, "aud": "desks-app", "email": "ada@acme.example", "exp": crate::now() + 300, "nonce": "mine"}));
    let (status, body) = app(hub.address(), &hub.record().certificate, "POST", "/grid/v1/person/sso", "", Some(json!({"idToken": stranger, "nonce": "mine"}))).await;
    assert!(status == 403 && String::from_utf8_lossy(&body).contains("signature"), "{}", String::from_utf8_lossy(&body));
    drop(tls);
    // Passwords can be switched off; the provider alone signs people in.
    hub.enterprise(json!({"action":"ssoSet","issuer":provider.clone(),"clientId":"desks-app","passwordless":true})).unwrap();
    assert!(member::person_login(&the_invite, "ada", ADA, None).await.unwrap_err().contains("identity provider"));
    hub.enterprise(json!({"action":"ssoClear"})).unwrap();
    assert!(member::person_login(&the_invite, "ada", ADA, None).await.is_ok());

    // A connector: the admin enters a credential; the identifiers are on record, the secret is
    // loaded on the hub computer only. Tasks run from the queue and report back.
    let connection = hub.enterprise(json!({"action":"connectionAdd","name":"Horizon","provider":"horizon","url":"https://horizon.acme.example","target":{"username":"admin","domain":"ACME","pool":"pool-1"},"credentialSet":true})).unwrap()["id"].as_str().unwrap().to_owned();
    assert!(hub.enterprise(json!({"action":"connectionAdd","name":"Half","provider":"horizon","url":"https://horizon.acme.example","target":{"username":"admin"},"credentialSet":true})).unwrap_err().contains("domain"));
    assert!(hub.enterprise(json!({"action":"connectionAdd","name":"Leak","provider":"horizon","url":"https://horizon.acme.example","target":{"password":"pw"},"credentialSet":false})).unwrap_err().contains("password"), "secrets never go in the record");
    let asked = hub.enterprise(json!({"action":"connectionProvision","id":connection,"personId":person_id})).unwrap();
    let task = asked["taskId"].as_str().unwrap().to_owned();
    assert_eq!(hub.status()["enterprise"]["provisioning"][0]["state"], "pending");
    assert!(hub.provisioning_due().is_empty(), "without the secret loaded the task fails rather than runs");
    assert_eq!(hub.status()["enterprise"]["provisioning"][0]["state"], "failed");
    hub.set_connection_credential(&connection, Some(json!({"password": "pw"})));
    let asked = hub.enterprise(json!({"action":"connectionProvision","id":connection,"personId":person_id})).unwrap();
    assert_ne!(asked["taskId"], task, "a failed task is not reused");
    let due = hub.provisioning_due();
    assert_eq!(due.len(), 1);
    assert_eq!((due[0].1.email.as_str(), due[0].1.want), ("ada@acme.example", crate::provisioning::Want::Assign));
    assert_eq!(hub.status()["enterprise"]["provisioning"][1]["state"], "running");
    hub.provisioning_report(&due[0].0, Ok("ada@acme.example is entitled to the desktop pool".into()));
    assert_eq!(hub.status()["enterprise"]["provisioning"][1]["state"], "done");
    assert!(!hub.status().to_string().contains("\"pw\""), "the secret is nowhere in status");
    // Removing the person takes the assignment back; removing the connection forgets its secret.
    hub.remove_person(&person_id).unwrap();
    let due = hub.provisioning_due();
    assert_eq!((due.len(), due[0].1.want, due[0].1.email.as_str()), (1, crate::provisioning::Want::Revoke, "ada@acme.example"));
    hub.provisioning_report(&due[0].0, Err("Horizon refused the entitlement change".into()));
    assert_eq!(hub.status()["enterprise"]["provisioning"][2]["state"], "failed");
    hub.enterprise(json!({"action":"connectionRemove","id":connection})).unwrap();
    assert!(hub.status()["enterprise"]["provisioning"].as_array().is_none_or(|list| list.is_empty()));
    assert!(hub.connections_with_credentials().is_empty());
    let _ = calls;
    let seen = events.lock().unwrap().clone();
    for kind in ["grid.sso.set", "grid.person.signed_in", "grid.person.refused", "grid.connection.added", "grid.connection.assign", "grid.connection.done", "grid.connection.failed", "grid.connection.removed"] {
        assert!(seen.contains(&kind), "{kind} is audited");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_step_sign_in_needs_the_code_once_the_person_turns_it_on() {
    use crate::invite::Invite;
    const ADA: &str = "ada's own password";
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    let the_invite = Invite { company: "Acme".into(), address: HubAddress::Direct(hub.address()), fingerprint: net::fingerprint(&hub.record().certificate).unwrap() };
    let salt = password::new_salt();
    let key = password::derive(ADA, &salt).unwrap();
    hub.add_person("ada", "Ada", &salt, &key, None).unwrap();

    let session = member::person_login(&the_invite, "ada", ADA, None).await.unwrap();
    let enrolled = session.session.manage(json!({"action":"mfaEnroll"})).await.unwrap();
    let secret = enrolled["secret"].as_str().unwrap().to_owned();
    assert!(enrolled["otpauth"].as_str().unwrap().starts_with("otpauth://totp/Acme%20Sandbox%20Grid:ada?secret="));
    assert!(member::person_login(&the_invite, "ada", ADA, None).await.is_ok(), "not on until a first code confirms it");
    assert!(session.session.manage(json!({"action":"mfaConfirm","code":"000000"})).await.is_err());
    let code = |at: i64| {
        // The same arithmetic an authenticator app does, from the secret the hub showed.
        crate::totp::code_at(&secret, at).expect("the hub's own secret makes a code")
    };
    let now = crate::now();
    session.session.manage(json!({"action":"mfaConfirm","code":code(now)})).await.unwrap();
    assert_eq!(hub.status()["people"][0]["mfa"], true);
    assert!(!hub.status().to_string().contains(&secret), "the secret is never shown again");

    assert_eq!(member::person_login(&the_invite, "ada", ADA, None).await.unwrap_err(), crate::MFA_REQUIRED);
    assert!(member::person_login(&the_invite, "ada", ADA, Some("123456")).await.unwrap_err().contains("wrong, expired"));
    assert!(member::person_login(&the_invite, "ada", "wrong password", Some(&code(now))).await.unwrap_err().contains("username or password"), "a wrong password never gets as far as the code");

    // A code signs them in once. The second time it is somebody who saw it, and the leeway that
    // makes a code work a little early or a little late is exactly the minute and a half they
    // have to try it in. The code is a step on, because the one that turned two-step on is spent.
    let seen = code(crate::now() + crate::totp::STEP);
    let again = member::person_login(&the_invite, "ada", ADA, Some(&seen)).await.unwrap();
    let replayed = member::person_login(&the_invite, "ada", ADA, Some(&seen)).await.unwrap_err();
    assert!(replayed.contains("used already"), "{replayed}");
    assert!(again.session.manage(json!({"action":"mfaDisable","code":"000000"})).await.is_err());

    // Turning it off is somebody else's turn, because Ada has now spent two codes and the third
    // is not due yet. Bob turns his on and straight back off, which is the same two codes.
    let bob_salt = password::new_salt();
    let bob_key = password::derive("bob's own password", &bob_salt).unwrap();
    hub.add_person("bob", "Bob", &bob_salt, &bob_key, None).unwrap();
    let bob = member::person_login(&the_invite, "bob", "bob's own password", None).await.unwrap();
    let his = bob.session.manage(json!({"action":"mfaEnroll"})).await.unwrap()["secret"].as_str().unwrap().to_owned();
    let his_code = |at: i64| crate::totp::code_at(&his, at).expect("the hub's own secret makes a code");
    let at = crate::now();
    bob.session.manage(json!({"action":"mfaConfirm","code":his_code(at)})).await.unwrap();
    assert_eq!(member::person_login(&the_invite, "bob", "bob's own password", None).await.unwrap_err(), crate::MFA_REQUIRED);
    // The next code, not the one that turned it on: one code is used once, wherever it is offered.
    let stale = bob.session.manage(json!({"action":"mfaDisable","code":his_code(at)})).await.unwrap_err();
    assert!(stale.contains("used already"), "{stale}");
    bob.session.manage(json!({"action":"mfaDisable","code":his_code(at + crate::totp::STEP)})).await.unwrap();
    assert!(member::person_login(&the_invite, "bob", "bob's own password", None).await.is_ok());

    // The admin can only reset it, which also ends the person's sessions. Ada still has hers on.
    let person_id = hub.status()["people"][0]["id"].as_str().unwrap().to_owned();
    assert_eq!(hub.status()["people"][0]["mfa"], true);
    hub.enterprise(json!({"action":"mfaReset","id":person_id})).unwrap();
    assert_eq!(hub.status()["people"][0]["mfa"], false);
}

/// PROVES that moving two-step sign-in to another authenticator needs the one it is on now.
///
/// An open session was enough. Somebody with one — a computer left unlocked, a stolen session
/// token — could enrol their own phone, confirm it with their own code, and own the second factor
/// on that account from then on. The factor two-step adds is a thing the person holds, and a
/// sign-in that could replace it without it added nothing at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_step_cannot_be_moved_to_another_authenticator_without_the_one_it_is_on() {
    use crate::invite::Invite;
    const GRACE: &str = "grace's own password";
    let folder = tempfile::tempdir().unwrap();
    let (hub, _) = start_hub(folder.path()).await;
    let the_invite = Invite { company: "Acme".into(), address: HubAddress::Direct(hub.address()), fingerprint: net::fingerprint(&hub.record().certificate).unwrap() };
    let salt = password::new_salt();
    let key = password::derive(GRACE, &salt).unwrap();
    hub.add_person("grace", "Grace", &salt, &key, None).unwrap();

    // Turning it on for the first time asks for no code, because there is nothing yet to prove.
    let session = member::person_login(&the_invite, "grace", GRACE, None).await.unwrap();
    let hers = session.session.manage(json!({"action":"mfaEnroll"})).await.unwrap()["secret"].as_str().unwrap().to_owned();
    let code = |at: i64| crate::totp::code_at(&hers, at).expect("the hub's own secret makes a code");
    let at = crate::now();
    session.session.manage(json!({"action":"mfaConfirm","code":code(at)})).await.unwrap();
    assert_eq!(hub.status()["people"][0]["mfa"], true);

    // Now the session alone is not enough. This is the thief's position exactly: they hold the
    // session and want the factor, and the only thing they do not have is the authenticator.
    let refused = session.session.manage(json!({"action":"mfaEnroll"})).await.unwrap_err();
    assert!(refused.contains("already on"), "{refused}");
    let wrong = session.session.manage(json!({"action":"mfaEnroll","code":"000000"})).await.unwrap_err();
    assert!(wrong.contains("code from the one it is on"), "{wrong}");
    // And the secret is untouched, so the authenticator she holds still signs her in.
    assert_eq!(hub.status()["people"][0]["mfa"], true);

    // With a code from the authenticator it is on, she may move it, and the code is spent.
    let moving = code(at + crate::totp::STEP);
    let enrolled = session.session.manage(json!({"action":"mfaEnroll","code":moving.clone()})).await.unwrap();
    assert_ne!(enrolled["secret"].as_str().unwrap(), hers, "a new authenticator, not the old one again");
    let spent = session.session.manage(json!({"action":"mfaEnroll","code":moving})).await.unwrap_err();
    assert!(spent.contains("code from the one it is on"), "a code that moved it once does not move it again: {spent}");
}

/// A person away from the company network opens their desk through the hub: the computer that
/// hosts it holds connections open, the hub joins one to the person's, and the desk's own pinned
/// TLS runs inside, so the hub carries the session without being able to read it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_desk_is_opened_through_the_hub_from_outside_the_network() {
    use crate::desks::{Capacity, DeskKind, DeskReport, DeskSpec};
    use crate::invite::Invite;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    const ADA: &str = "ada's own password";
    let folder = tempfile::tempdir().unwrap();
    let (hub, events) = start_hub(folder.path()).await;
    let the_invite = Invite { company: "Acme".into(), address: HubAddress::Direct(hub.address()), fingerprint: net::fingerprint(&hub.record().certificate).unwrap() };

    // The desk itself: a tiny service on this computer's own address, with its own certificate,
    // exactly as a host shares a desk on its LAN.
    let identity = net::new_identity("127.0.0.1".parse().unwrap(), None).unwrap();
    let desk_certificate = identity.certificate.clone();
    let desk_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let desk_address = desk_listener.local_addr().unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(net::server_config(&identity).unwrap());
    tokio::spawn(async move {
        while let Ok((socket, _)) = desk_listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else { return };
                let mut seen = vec![0u8; 1024];
                let read = tls.read(&mut seen).await.unwrap_or(0);
                assert!(String::from_utf8_lossy(&seen[..read]).contains("POST /rpc"), "the desk receives the person's own request");
                let body = br#"{"environment":{"name":"Ada's desk"}}"#;
                let answer = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
                let _ = tls.write_all(answer.as_bytes()).await;
                let _ = tls.write_all(body).await;
                let _ = tls.shutdown().await;
            });
        }
    });

    // A person with a desk, and a computer hosting it.
    let salt = password::new_salt();
    let key = password::derive(ADA, &salt).unwrap();
    hub.add_person("ada", "Ada", &salt, &key, None).unwrap();
    let spec = DeskSpec::checked(DeskKind::Container, 2.0, 4.0, 20.0, false, "").unwrap();
    let desk = hub.add_desk("Ada's desk", spec, Some("ada")).unwrap()["id"].as_str().unwrap().to_owned();
    let joined = member::join("Acme", hub.address(), PASSWORD, "Studio PC", "windows", false, None).await.unwrap();
    let host = joined.membership.clone();
    let capacity = Capacity { desk_protocol: 2, battery_percent: None, going_away: None, cpu: 8, cpu_used_percent: 10.0, memory_gb: 32.0, used_memory_gb: 8.0, free_disk_gb: 300.0, gpu: false, gpu_used_percent: None, on_battery: false, in_use: false };
    let orders = host.check_in("test", false, &[], Some(&capacity), &[]).await.unwrap();
    let generation = orders.desks[0].generation;
    let invitation = json!({"version": 1, "address": desk_address.to_string(), "certificate": desk_certificate, "token": "t", "expiresAt": crate::now() + 86_400});
    let ready = DeskReport { generation, parcel: None, id: desk.clone(), state: "ready".into(), environment_id: Some("env-desk".into()), note: String::new(), invitation: Some(invitation), invitation_expires_at: Some(crate::now() + 86_400) };
    host.check_in("test", false, &[], Some(&capacity), &[ready]).await.unwrap();

    // The host holds connections open for desk sessions and carries each to the desk itself.
    let holder = host.clone();
    let carrying = tokio::spawn(async move {
        for _ in 0..4 {
            let Ok((wanted, relayed)) = holder.hold_desk_relay().await else { continue };
            let Ok(socket) = tokio::net::TcpStream::connect(desk_address).await else { continue };
            assert!(!wanted.is_empty());
            crate::relay::join_socket(relayed, socket).await;
            return wanted;
        }
        String::new()
    });
    // Give the host a moment to hold its first connection.
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The person signs in and opens the desk through the hub, speaking the desk's own TLS inside.
    let session = member::person_login(&the_invite, "ada", ADA, None).await.unwrap();
    let relayed = session.session.open_desk(&desk).await.unwrap();
    let tls = net::client_config(&desk_certificate).unwrap();
    let name = tokio_rustls::rustls::pki_types::ServerName::IpAddress(std::net::IpAddr::from([127, 0, 0, 1]).into());
    let stream = tokio_rustls::TlsConnector::from(tls).connect(name, relayed).await.expect("the desk's own certificate, end to end through the hub");
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await.unwrap();
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder().method("POST").uri("/rpc").header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(r#"{"method":"inspect","params":{}}"#))).unwrap();
    let answer = sender.send_request(request).await.unwrap();
    assert_eq!(answer.status(), 200);
    let body = answer.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(json_of(&body)["environment"]["name"], "Ada's desk");
    assert_eq!(carrying.await.unwrap(), desk, "the hub told the host which desk the session was for");
    assert!(events.lock().unwrap().contains(&"grid.desk.relayed"));

    // Someone else's session cannot open it, and neither can an unknown desk.
    let salt = password::new_salt();
    let key = password::derive("grace's own password", &salt).unwrap();
    hub.add_person("grace", "Grace", &salt, &key, None).unwrap();
    let other = member::person_login(&the_invite, "grace", "grace's own password", None).await.unwrap();
    assert!(other.session.open_desk(&desk).await.unwrap_err().contains("not ready, or is not yours"));
    assert!(session.session.open_desk("desk-nothing").await.unwrap_err().contains("not ready, or is not yours"));
}
