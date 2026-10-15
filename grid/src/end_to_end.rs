//! A hub, member computers and a company app talking over real pinned TLS on loopback, with
//! local model servers simulated in memory.
use crate::{
    hub::{self, Hub, ModelReport, PlanChange},
    member::{self, LocalModel, MemberError, WorkerEvent},
    net, password,
    policy::IdlePolicy,
};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{body::Incoming, header, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::{
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
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
    let request = Request::builder().method(method).uri(path).header(header::AUTHORIZATION, format!("Bearer {key}"));
    let response = match body {
        Some(body) => net::send(address, &tls, request.header(header::CONTENT_TYPE, "application/json").body(Full::new(Bytes::from(body.to_string()))).unwrap(), Duration::from_secs(60)).await,
        None => net::send(address, &tls, request.body(Empty::<Bytes>::new()).unwrap(), Duration::from_secs(60)).await,
    }
    .unwrap();
    let status = response.status().as_u16();
    (status, response.into_body().collect().await.unwrap().to_bytes().to_vec())
}

fn json_of(bytes: &[u8]) -> Value {
    serde_json::from_slice(bytes).unwrap()
}

fn report(model: &str, state: &str) -> Vec<ModelReport> {
    vec![ModelReport { model: model.into(), state: state.into(), reason: String::new(), quant: None, gpu: Some("Test GPU".into()) }]
}

async fn start_hub(folder: &std::path::Path) -> (Hub, Arc<Mutex<Vec<&'static str>>>) {
    let path = folder.join("hub.json");
    let salt = password::new_salt();
    let password_key = password::derive(PASSWORD, &salt).unwrap();
    let key = hub::create(&path, "Acme", "127.0.0.1".parse().unwrap(), 0, None, &salt).unwrap();
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
    hub.add_plan("hf.co/Acme/Chat-1B", None, 100, IdlePolicy::new(Some(15), Some("Mon-Fri 18:00-08:00")).unwrap()).unwrap();
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
    hub.remove_plan(&changed["plan"]["id"].as_str().unwrap().to_owned()).unwrap();
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
