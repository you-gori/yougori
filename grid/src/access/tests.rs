//! The Access Grid end to end over real pinned TLS on this computer: people sign in with an
//! invite (password, two-step code or the company's identity provider), rules decide, approvers
//! approve, and credentials reach services (as they are, as short-lived tokens, or as AWS
//! signatures) but never come back to the person or their agent.
use super::{
    backup,
    hub::{self, Hub, Owner},
    member::{self, CallError, SignedIn},
    seal, sigv4,
};
use crate::{
    invite::{self, Invite},
    net::{Body, HubAddress},
    password,
};
use hmac::{Hmac, Mac};
use http_body_util::BodyExt;
use hyper::{body::Incoming, HeaderMap, Request, Response};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

const SECRET: &str = "sk-test-0123456789abcdef";

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

type Handler = Arc<dyn Fn(&str, &str, &HeaderMap, &[u8]) -> (u16, String) + Send + Sync>;

/// A local HTTP service answering with whatever `handler` says for method, path?query, headers and body.
async fn mock(handler: Handler) -> SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { return };
            let handler = handler.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let handler = handler.clone();
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        let path = parts.uri.path_and_query().map(|value| value.as_str().to_owned()).unwrap_or_default();
                        let (status, text) = handler(parts.method.as_str(), &path, &parts.headers, &body);
                        Ok::<_, std::convert::Infallible>(Response::builder().status(status).header("content-type", if text.starts_with('<') { "text/xml" } else { "application/json" }).body(crate::net::full(text)).unwrap() as Response<Body>)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    address
}

/// A company service that answers with what it was sent, including the Authorization header.
async fn service() -> SocketAddr {
    mock(Arc::new(|method, path, headers, body| {
        let path = path.split('?').next().unwrap_or_default();
        (200, json!({"method": method, "path": path, "authorization": headers.get("authorization").and_then(|v| v.to_str().ok()), "body": String::from_utf8_lossy(body)}).to_string())
    }))
    .await
}

struct Grid {
    folder: tempfile::TempDir,
    hub: Hub,
    invite: Invite,
    tls_key: String,
    seal_key: String,
}

impl Grid {
    fn path(&self) -> PathBuf {
        self.folder.path().join("access-hub.json")
    }
}

async fn grid() -> Grid {
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("access-hub.json");
    let salt = password::new_salt();
    let key = password::derive("owner password 1", &salt).unwrap();
    let tls_key = hub::create(&path, "Acme", "127.0.0.1".parse().unwrap(), free_port(), None, Owner { username: "root.admin".into(), name: "Root".into(), salt, key }).unwrap();
    let seal_key = seal::new_key().unwrap();
    let hub = Hub::start(path, &tls_key, &seal_key, Arc::new(|_, _| {})).await.unwrap();
    let invite = Invite { company: "Acme".into(), address: HubAddress::Direct(hub.address()), fingerprint: hub.fingerprint().to_owned() };
    Grid { folder, hub, invite, tls_key, seal_key }
}

fn add_person(grid: &Grid, username: &str, permission: &str, teams: &[&str]) {
    let salt = password::new_salt();
    let key = password::derive(&format!("{username} password 1"), &salt).unwrap();
    grid.hub.manage_as_owner(json!({"action": "personAdd", "username": username, "permission": permission, "teams": teams, "salt": salt, "key": key, "email": format!("{username}@acme.example")})).unwrap();
}

fn secret_of(username: &str) -> String {
    if username == "root.admin" { "owner password 1".to_owned() } else { format!("{username} password 1") }
}

async fn sign_in(grid: &Grid, username: &str) -> SignedIn {
    member::signin(&grid.invite, username, &secret_of(username), None, "Test PC").await.unwrap()
}

async fn call(grid: &Grid, who: &SignedIn, action: &str, body: Value) -> Result<Value, CallError> {
    let value = member::call(&grid.invite.address, &who.certificate, &who.token, action, &body).await;
    if let Ok(value) = &value {
        assert!(!value.to_string().contains(SECRET), "the value leaked in {action}: {value}");
    }
    value
}

fn refused(error: &CallError, text: &str) -> bool {
    matches!(error, CallError::Refused { message, .. } if message.contains(text))
}

/// Asks until the request is no longer waiting or running.
async fn settled(grid: &Grid, who: &SignedIn, id: &str) -> Value {
    for _ in 0..100 {
        let value = member::call(&grid.invite.address, &who.certificate, &who.token, "request", &json!({"id": id})).await.unwrap();
        if !matches!(value["state"].as_str(), Some("waiting" | "running")) {
            return value;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("request {id} never settled");
}

/// The code an authenticator app shows for `secret` at `at`.
fn totp_code(secret: &str, at: i64) -> String {
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut buffer, mut bits, mut key) = (0u64, 0u32, Vec::new());
    for c in secret.bytes() {
        buffer = (buffer << 5) | alphabet.iter().position(|a| *a == c).unwrap() as u64;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            key.push(((buffer >> bits) & 0xff) as u8);
        }
    }
    let mut mac = Hmac::<sha1::Sha1>::new_from_slice(&key).unwrap();
    mac.update(&((at / 30) as u64).to_be_bytes());
    let digest = mac.finalize().into_bytes();
    let offset = (digest[19] & 0x0f) as usize;
    let binary = ((u32::from(digest[offset]) & 0x7f) << 24) | (u32::from(digest[offset + 1]) << 16) | (u32::from(digest[offset + 2]) << 8) | u32::from(digest[offset + 3]);
    format!("{:06}", binary % 1_000_000)
}

#[tokio::test]
async fn people_use_credentials_by_rule_and_approval_without_ever_seeing_them() {
    let grid = grid().await;
    let api = service().await;
    add_person(&grid, "ada", "member", &["Research"]);
    add_person(&grid, "bob", "approver", &[]);
    let added = grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "Echo", "kind": "bearer", "destinations": [format!("http://{api}/api")], "value": SECRET, "note": "The test service"})).unwrap();
    let credential = added["credentialId"].as_str().unwrap().to_owned();
    assert!(!std::fs::read_to_string(grid.path()).unwrap().contains(SECRET), "values are sealed at rest");

    let ada = sign_in(&grid, "ada").await;
    let bob = sign_in(&grid, "bob").await;
    assert_eq!(ada.company, "Acme");
    assert!(ada.device_token.is_some() && !ada.strong);
    let me = call(&grid, &ada, "me", json!({})).await.unwrap();
    assert_eq!(me["available"], json!([]));
    assert!(me.get("overview").is_none(), "members do not see the whole grid");
    let refusal = call(&grid, &ada, "use", json!({"credential": "Echo", "url": format!("http://{api}/api/read")})).await.unwrap_err();
    assert!(refused(&refusal, "No rule"), "{refusal:?}");

    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "Echo", "who": "team:research", "methods": ["GET"], "path": "/api/read", "decision": "allow"})).unwrap();
    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": credential, "who": "everyone", "methods": ["POST"], "decision": "ask", "reveal": true})).unwrap();
    let me = call(&grid, &ada, "me", json!({})).await.unwrap();
    assert_eq!(me["available"][0]["name"], "Echo");
    assert_eq!(me["available"][0]["uses"].as_array().unwrap().len(), 2);

    // Allowed: sent at once with the hub's credential, which the answer never shows.
    let done = call(&grid, &ada, "use", json!({"credential": "echo", "method": "get", "url": format!("http://{api}/api/read/item?x=1"), "headers": {"Authorization": "Bearer guess"}, "agent": "Claude Code"})).await.unwrap();
    assert_eq!(done["state"], "done", "{done}");
    let seen: Value = serde_json::from_str(done["answer"]["body"].as_str().unwrap()).unwrap();
    assert_eq!((seen["path"].as_str(), seen["authorization"].as_str()), (Some("/api/read/item"), Some("Bearer [hidden by Access Grid]")));
    let outside = call(&grid, &ada, "use", json!({"credential": "Echo", "url": format!("http://{api}/admin")})).await.unwrap_err();
    assert!(refused(&outside, "may only be sent to"), "{outside:?}");

    // Ask: waits for an approver; a member cannot decide, an approver can.
    let waiting = call(&grid, &ada, "use", json!({"credential": "Echo", "method": "POST", "url": format!("http://{api}/api/write"), "body": "{\"a\":1}"})).await.unwrap();
    assert_eq!(waiting["state"], "waiting");
    let id = waiting["id"].as_str().unwrap().to_owned();
    let overview = call(&grid, &bob, "manage", json!({"action": "overview"})).await.unwrap();
    assert_eq!(overview["waiting"][0]["bodyPreview"], "{\"a\":1}", "approvers see what will be sent");
    assert!(call(&grid, &ada, "manage", json!({"action": "decide", "request": id, "approve": true})).await.is_err());
    let decided = call(&grid, &bob, "manage", json!({"action": "decide", "request": id, "approve": true})).await.unwrap();
    assert_eq!(decided["state"], "running");
    let answer = settled(&grid, &ada, &id).await;
    assert_eq!((answer["state"].as_str(), answer["decidedBy"].as_str()), (Some("done"), Some("bob")));
    assert_eq!(serde_json::from_str::<Value>(answer["answer"]["body"].as_str().unwrap()).unwrap()["body"], "{\"a\":1}");
    assert!(call(&grid, &ada, "request", json!({"id": id})).await.is_err(), "an answer is handed over once");

    // Approved for an hour: the next POST goes straight through.
    let waiting = call(&grid, &ada, "use", json!({"credential": "Echo", "method": "POST", "url": format!("http://{api}/api/write")})).await.unwrap();
    call(&grid, &bob, "manage", json!({"action": "decide", "request": waiting["id"], "approve": true, "hours": 1})).await.unwrap();
    settled(&grid, &ada, waiting["id"].as_str().unwrap()).await;
    let direct = call(&grid, &ada, "use", json!({"credential": "Echo", "method": "POST", "url": format!("http://{api}/api/write")})).await.unwrap();
    assert_eq!(direct["state"], "done");

    // Seeing the value: always an approver's decision; a denial says why.
    let reveal = call(&grid, &ada, "reveal", json!({"credential": "Echo", "reason": "configure a CLI"})).await.unwrap();
    grid.hub.manage_as_owner(json!({"action": "decide", "request": reveal["id"], "approve": false, "reason": "use company_request"})).unwrap();
    let denied = settled(&grid, &ada, reveal["id"].as_str().unwrap()).await;
    assert_eq!(denied["state"], "denied");
    assert!(denied["reason"].as_str().unwrap().contains("use company_request"));
    let reveal = call(&grid, &ada, "reveal", json!({"credential": "Echo"})).await.unwrap();
    call(&grid, &bob, "manage", json!({"action": "decide", "request": reveal["id"], "approve": true})).await.unwrap();
    let shown = settled(&grid, &ada, reveal["id"].as_str().unwrap()).await;
    assert_eq!((shown["state"].as_str(), shown["value"].as_str()), (Some("done"), Some(SECRET)));

    // The activity log records uses and decisions, never values, in a chain that checks out.
    let overview = grid.hub.manage_as_owner(json!({"action": "overview"})).unwrap();
    let log = overview["activity"].to_string();
    assert!(log.contains("approved by bob") && log.contains("denied by root.admin") && !log.contains(SECRET), "{log}");
    assert!(!overview.to_string().contains(SECRET));
    assert!(!overview.to_string().contains("keyHash") && !overview.to_string().contains("sealed") && !overview.to_string().contains("\"hash\""));
    assert_eq!(grid.hub.manage_as_owner(json!({"action": "activityVerify"})).unwrap()["ok"], true);
    let exported = call(&grid, &bob, "manage", json!({"action": "activityExport", "limit": 5})).await.unwrap();
    assert_eq!(exported["entries"].as_array().unwrap().len(), 5);
    assert!(exported["entries"][0]["mac"].as_str().is_some_and(|mac| mac.len() == 64));

    // Removing a person ends their sign-in at once.
    grid.hub.manage_as_owner(json!({"action": "personRemove", "person": "ada"})).unwrap();
    assert_eq!(call(&grid, &ada, "me", json!({})).await.unwrap_err(), CallError::SignedOut);
}

#[tokio::test]
async fn approvers_never_approve_themselves_and_admins_alone_change_the_grid() {
    let grid = grid().await;
    let api = service().await;
    add_person(&grid, "bob", "approver", &[]);
    add_person(&grid, "cyd", "auditor", &[]);
    grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "Echo", "kind": "header", "field": "X-Api-Key", "destinations": [format!("http://{api}")], "value": SECRET})).unwrap();
    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "Echo", "who": "everyone", "decision": "ask"})).unwrap();
    let root = sign_in(&grid, "root.admin").await;
    let bob = sign_in(&grid, "bob").await;
    let cy = sign_in(&grid, "cyd").await;
    let waiting = call(&grid, &bob, "use", json!({"credential": "Echo", "url": format!("http://{api}/x")})).await.unwrap();
    let own = call(&grid, &bob, "manage", json!({"action": "decide", "request": waiting["id"], "approve": true})).await.unwrap_err();
    assert!(refused(&own, "Someone else"), "{own:?}");
    assert!(call(&grid, &cy, "manage", json!({"action": "decide", "request": waiting["id"], "approve": true})).await.is_err(), "auditors only read");
    assert!(call(&grid, &cy, "manage", json!({"action": "overview"})).await.is_ok());
    let change = call(&grid, &bob, "manage", json!({"action": "ruleAdd", "credential": "Echo", "who": "everyone", "decision": "allow"})).await.unwrap_err();
    assert!(refused(&change, "Only Access Grid admins"), "{change:?}");
    call(&grid, &root, "manage", json!({"action": "decide", "request": waiting["id"], "approve": true})).await.unwrap();
    assert_eq!(settled(&grid, &bob, waiting["id"].as_str().unwrap()).await["state"], "done");

    // The owner stays an admin and cannot be removed; a wrong password is refused.
    assert!(grid.hub.manage_as_owner(json!({"action": "personUpdate", "person": "root.admin", "permission": "member"})).is_err());
    assert!(grid.hub.manage_as_owner(json!({"action": "personRemove", "person": "root.admin"})).is_err());
    assert!(member::signin(&grid.invite, "bob", "not bob's password", None, "PC").await.unwrap_err().contains("wrong"));
    // A changed password ends existing sign-ins and remembered computers.
    let salt = password::new_salt();
    let key = password::derive("bob new password", &salt).unwrap();
    grid.hub.manage_as_owner(json!({"action": "personPassword", "person": "bob", "salt": salt, "key": key})).unwrap();
    assert_eq!(call(&grid, &bob, "me", json!({})).await.unwrap_err(), CallError::SignedOut);
    let ended = member::resume(&grid.invite.address, &bob.certificate, bob.device_token.as_deref().unwrap(), "PC").await.unwrap_err();
    assert!(matches!(&ended, CallError::Refused { code, .. } if code == "device_ended"), "{ended:?}");
    let again = member::signin(&grid.invite, "bob", "bob new password", None, "PC").await.unwrap();
    assert!(call(&grid, &again, "me", json!({})).await.is_ok());
}

#[tokio::test]
async fn invites_name_the_real_hub_and_company() {
    let grid = grid().await;
    let code = invite::encode_access(&grid.invite);
    assert!(code.starts_with("access-invite:"));
    assert_eq!(invite::decode_access(&code).unwrap(), grid.invite);
    assert!(invite::decode_desk(&code).is_err() && invite::decode(&code).is_err());
    let wrong_company = Invite { company: "Globex".into(), ..grid.invite.clone() };
    assert!(member::signin(&wrong_company, "root.admin", "owner password 1", None, "PC").await.unwrap_err().contains("belongs to"));
    let wrong_print = Invite { fingerprint: format!("{}AB", "01:".repeat(31)), ..grid.invite.clone() };
    assert!(member::signin(&wrong_print, "root.admin", "owner password 1", None, "PC").await.unwrap_err().contains("fingerprint"));
}

#[tokio::test]
async fn two_step_sign_in_and_remembered_computers() {
    let grid = grid().await;
    let api = service().await;
    add_person(&grid, "ada", "member", &[]);
    add_person(&grid, "bob", "member", &[]);
    grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "Echo", "destinations": [format!("http://{api}")], "value": SECRET})).unwrap();
    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "Echo", "who": "everyone"})).unwrap();
    let ada = sign_in(&grid, "ada").await;
    let started = call(&grid, &ada, "account", json!({"action": "twoStepStart"})).await.unwrap();
    let secret = started["secret"].as_str().unwrap().to_owned();
    assert!(started["link"].as_str().unwrap().starts_with("otpauth://totp/Acme%20Access%20Grid:ada?secret="));
    assert!(call(&grid, &ada, "account", json!({"action": "twoStepConfirm", "code": "000000"})).await.is_err());
    call(&grid, &ada, "account", json!({"action": "twoStepConfirm", "code": totp_code(&secret, crate::now())})).await.unwrap();
    assert!(!std::fs::read_to_string(grid.path()).unwrap().contains(&secret), "the two-step secret is sealed at rest");

    // From now on a password alone is not enough; a remembered computer still signs itself in.
    assert_eq!(member::signin(&grid.invite, "ada", "ada password 1", None, "PC").await.unwrap_err(), member::TWO_STEP);
    assert!(member::signin(&grid.invite, "ada", "ada password 1", Some("123456"), "PC").await.unwrap_err().contains("code"));
    // The code that confirmed two-step is spent; the next one (a step ahead, which the clock allows) signs in.
    let strong = member::signin(&grid.invite, "ada", "ada password 1", Some(&totp_code(&secret, crate::now() + 30)), "Laptop").await.unwrap();
    assert!(strong.strong);
    let resumed = member::resume(&grid.invite.address, &strong.certificate, strong.device_token.as_deref().unwrap(), "Laptop").await.unwrap();
    assert!(resumed.strong && resumed.device_token.is_none());

    // When the grid requires two-step, a sign-in without it can enroll but cannot use anything.
    grid.hub.manage_as_owner(json!({"action": "settingsSet", "requireTwoStep": true})).unwrap();
    let bob = sign_in(&grid, "bob").await;
    let blocked = call(&grid, &bob, "use", json!({"credential": "Echo", "url": format!("http://{api}/x")})).await.unwrap_err();
    assert!(matches!(&blocked, CallError::Refused { code, .. } if code == "two_step_required"), "{blocked:?}");
    assert_eq!(call(&grid, &bob, "me", json!({})).await.unwrap()["blocked"], true);
    assert_eq!(call(&grid, &resumed, "use", json!({"credential": "Echo", "url": format!("http://{api}/x")})).await.unwrap()["state"], "done");

    // Computers are seen, signed out one by one, or all at once.
    let me = call(&grid, &resumed, "me", json!({})).await.unwrap();
    let devices = me["person"]["devices"].as_array().unwrap().clone();
    assert_eq!(devices.len(), 2, "{devices:?}");
    assert!(!me.to_string().contains(strong.device_token.as_deref().unwrap()));
    let first = ada.device_id.clone().unwrap();
    grid.hub.manage_as_owner(json!({"action": "deviceRevoke", "person": "ada", "device": first})).unwrap();
    assert!(member::resume(&grid.invite.address, &ada.certificate, ada.device_token.as_deref().unwrap(), "PC").await.is_err());
    let others = call(&grid, &resumed, "account", json!({"action": "signOutOthers", "computer": "Laptop"})).await.unwrap();
    assert!(others["deviceToken"].as_str().is_some());
    assert!(member::resume(&grid.invite.address, &strong.certificate, strong.device_token.as_deref().unwrap(), "Laptop").await.is_err(), "the old token for this computer was replaced too");
    assert!(member::resume(&grid.invite.address, &strong.certificate, others["deviceToken"].as_str().unwrap(), "Laptop").await.is_ok());

    // An admin's reset turns two-step off and ends every sign-in.
    grid.hub.manage_as_owner(json!({"action": "personTwoStepReset", "person": "ada"})).unwrap();
    assert!(member::signin(&grid.invite, "ada", "ada password 1", None, "PC").await.is_ok());
}

#[tokio::test]
async fn hourly_limits_send_the_rest_to_an_approver() {
    let grid = grid().await;
    let api = service().await;
    add_person(&grid, "ada", "member", &[]);
    grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "Echo", "destinations": [format!("http://{api}")], "value": SECRET})).unwrap();
    assert!(grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "Echo", "decision": "ask", "limit": 2})).is_err(), "a limit belongs to an allow rule");
    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "Echo", "who": "ada", "methods": ["GET"], "limit": 2})).unwrap();
    let ada = sign_in(&grid, "ada").await;
    for _ in 0..2 {
        assert_eq!(call(&grid, &ada, "use", json!({"credential": "Echo", "url": format!("http://{api}/x")})).await.unwrap()["state"], "done");
    }
    let third = call(&grid, &ada, "use", json!({"credential": "Echo", "url": format!("http://{api}/x")})).await.unwrap();
    assert_eq!(third["state"], "waiting");
    assert!(third["message"].as_str().unwrap().contains("hourly limit of 2"), "{third}");
}

#[tokio::test]
async fn oauth_credentials_send_and_hand_out_only_short_lived_tokens() {
    let grid = grid().await;
    let issued = Arc::new(Mutex::new(0u32));
    let counter = issued.clone();
    let tokens = mock(Arc::new(move |method, _, headers, body| {
        let basic = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
        let expected = format!("Basic {}", base64::Engine::encode(&base64::engine::general_purpose::STANDARD, format!("app-1:{SECRET}")));
        if method != "POST" || basic != expected || !String::from_utf8_lossy(body).contains("grant_type=client_credentials") {
            return (401, json!({"error": "invalid_client"}).to_string());
        }
        let mut count = counter.lock().unwrap();
        *count += 1;
        (200, json!({"access_token": format!("at-{count}-0123456789"), "expires_in": 3600, "token_type": "Bearer"}).to_string())
    }))
    .await;
    let api = mock(Arc::new(|_, _, headers, _| (200, json!({"token": headers.get("authorization").and_then(|v| v.to_str().ok()).map(|v| v.starts_with("Bearer at-1"))}).to_string()))).await;
    add_person(&grid, "ada", "member", &[]);
    assert!(grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "Graph", "kind": "oauth", "destinations": [format!("http://{api}")], "value": SECRET, "config": {"clientId": "app-1"}})).is_err(), "a token URL is needed");
    grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "Graph", "kind": "oauth", "destinations": [format!("http://{api}")], "value": SECRET, "config": {"tokenUrl": format!("http://{tokens}/token"), "clientId": "app-1", "scope": "read"}})).unwrap();
    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "Graph", "reveal": true})).unwrap();
    let ada = sign_in(&grid, "ada").await;
    for _ in 0..2 {
        let done = call(&grid, &ada, "use", json!({"credential": "Graph", "url": format!("http://{api}/me")})).await.unwrap();
        assert_eq!(serde_json::from_str::<Value>(done["answer"]["body"].as_str().unwrap()).unwrap()["token"], true, "{done}");
    }
    assert_eq!(*issued.lock().unwrap(), 1, "the token is made once and kept until it nears its end");
    let reveal = call(&grid, &ada, "reveal", json!({"credential": "Graph", "reason": "a script"})).await.unwrap();
    grid.hub.manage_as_owner(json!({"action": "decide", "request": reveal["id"], "approve": true})).unwrap();
    let shown = settled(&grid, &ada, reveal["id"].as_str().unwrap()).await;
    assert_eq!((shown["value"].as_str(), shown["shortLived"].as_bool()), (Some("at-2-0123456789"), Some(true)), "a fresh short-lived token, never the client secret");
}

#[tokio::test]
async fn aws_requests_are_signed_on_the_hub_with_temporary_keys_from_a_role() {
    let grid = grid().await;
    let assumed = Arc::new(Mutex::new(String::new()));
    let seen = assumed.clone();
    let sts = mock(Arc::new(move |_, _, headers, body| {
        let auth = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default();
        if !auth.starts_with("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE000000000/") || !auth.contains("/us-east-1/sts/aws4_request") {
            return (403, "<ErrorResponse><Error><Message>bad signature</Message></Error></ErrorResponse>".into());
        }
        *seen.lock().unwrap() = String::from_utf8_lossy(body).into_owned();
        (200, "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMPORARY0000000</AccessKeyId><SecretAccessKey>temporarysecretkey000000000000</SecretAccessKey><SessionToken>session-token-0123456789</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>".into())
    }))
    .await;
    // The service checks the signature itself, with the temporary key the role gave.
    let api = mock(Arc::new(|method, path, headers, body| {
        let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or_default().to_owned();
        let keys = sigv4::Keys { access_key: "ASIATEMPORARY0000000".into(), secret_key: "temporarysecretkey000000000000".into(), session_token: Some(header("x-amz-security-token")) };
        let (path, query) = path.split_once('?').map_or((path, None), |(path, query)| (path, Some(query)));
        let expected = sigv4::sign(method, &header("host"), path, query, body, &keys, "us-east-1", "execute-api", &header("x-amz-date"), true);
        let authorization = expected.iter().find(|(name, _)| name == "authorization").map(|(_, value)| value.clone()).unwrap_or_default();
        (200, json!({"signed": header("authorization") == authorization, "token": header("x-amz-security-token")}).to_string())
    }))
    .await;
    add_person(&grid, "ada", "member", &[]);
    grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "AWS", "kind": "aws", "destinations": [format!("http://{api}")], "value": "AKIAEXAMPLE000000000:wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY", "config": {"region": "us-east-1", "service": "execute-api", "roleArn": "arn:aws:iam::123456789012:role/agents", "stsUrl": format!("http://{sts}/")}})).unwrap();
    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "AWS"})).unwrap();
    let ada = sign_in(&grid, "ada").await;
    let done = call(&grid, &ada, "use", json!({"credential": "AWS", "method": "POST", "url": format!("http://{api}/prod/items?b=2&a=1"), "body": "{\"n\":1}", "headers": {"X-Amz-Date": "19990101T000000Z"}})).await.unwrap();
    let answer: Value = serde_json::from_str(done["answer"]["body"].as_str().unwrap()).unwrap();
    assert_eq!(answer["signed"], true, "{done}");
    assert_eq!(answer["token"], "[hidden by Access Grid]", "the session token never comes back either");
    let request = assumed.lock().unwrap().clone();
    assert!(request.contains("Action=AssumeRole") && request.contains("RoleSessionName=access-ada"), "{request}");
}

#[tokio::test]
async fn single_sign_on_through_the_companys_identity_provider() {
    let grid = grid().await;
    let issuer = Arc::new(crate::jwt::tests::Issuer::new("k1"));
    let nonce = Arc::new(Mutex::new(String::new()));
    let provider = Arc::new(Mutex::new(String::new()));
    let (keys, wanted, address) = (issuer.clone(), nonce.clone(), provider.clone());
    let idp = mock(Arc::new(move |method, path, _, body| {
        let base = address.lock().unwrap().clone();
        match (method, path.split('?').next().unwrap_or_default()) {
            ("GET", "/.well-known/openid-configuration") => (200, json!({"issuer": base, "authorization_endpoint": format!("{base}/authorize"), "token_endpoint": format!("{base}/token"), "jwks_uri": format!("{base}/keys")}).to_string()),
            // As Entra answers for an issuer typed with the tenant's domain name: the issuer it
            // names, and its tokens carry, has the tenant's ID instead.
            ("GET", "/acme.example/v2.0/.well-known/openid-configuration") => (200, json!({"issuer": format!("{base}/9188040d/v2.0"), "authorization_endpoint": format!("{base}/authorize"), "token_endpoint": format!("{base}/token"), "jwks_uri": format!("{base}/keys")}).to_string()),
            ("POST", "/token") if String::from_utf8_lossy(body).contains("code=code-tenant") => (200, json!({"id_token": keys.token(&json!({"iss": format!("{base}/9188040d/v2.0"), "aud": "access-app", "sub": "ada-in-tenant", "email": "ada@acme.example", "exp": crate::now() + 300, "nonce": wanted.lock().unwrap().clone()}))}).to_string()),
            ("POST", "/token") if String::from_utf8_lossy(body).contains("code=code-stranger") => (200, json!({"id_token": keys.token(&json!({"iss": format!("{base}/5c1e7a2b/v2.0"), "aud": "access-app", "sub": "ada-in-tenant", "email": "ada@acme.example", "exp": crate::now() + 300, "nonce": wanted.lock().unwrap().clone()}))}).to_string()),
            ("GET", "/keys") => (200, keys.jwks().to_string()),
            ("POST", "/token") if String::from_utf8_lossy(body).contains("code=code-ada") => (200, json!({"id_token": keys.token(&json!({"iss": base, "aud": "access-app", "sub": "ada-at-idp", "email": "Ada@Acme.Example", "email_verified": true, "exp": crate::now() + 300, "nonce": wanted.lock().unwrap().clone()}))}).to_string()),
            // As Microsoft Entra sends it without the optional email claim.
            ("POST", "/token") if String::from_utf8_lossy(body).contains("code=code-entra") => (200, json!({"id_token": keys.token(&json!({"iss": base, "aud": "access-app", "sub": "ada-at-idp", "preferred_username": "ada@acme.example", "exp": crate::now() + 300, "nonce": wanted.lock().unwrap().clone()}))}).to_string()),
            // Another account at the provider carrying ada's email: reassigned, or typed in by its owner where the provider allows it.
            ("POST", "/token") if String::from_utf8_lossy(body).contains("code=code-other") => (200, json!({"id_token": keys.token(&json!({"iss": base, "aud": "access-app", "sub": "someone-else", "email": "ada@acme.example", "exp": crate::now() + 300, "nonce": wanted.lock().unwrap().clone()}))}).to_string()),
            ("POST", "/token") if String::from_utf8_lossy(body).contains("code=code-unverified") => (200, json!({"id_token": keys.token(&json!({"iss": base, "aud": "access-app", "sub": "ada-at-idp", "email": "ada@acme.example", "email_verified": false, "exp": crate::now() + 300, "nonce": wanted.lock().unwrap().clone()}))}).to_string()),
            _ => (400, json!({"error": "invalid_grant"}).to_string()),
        }
    }))
    .await;
    *provider.lock().unwrap() = format!("http://{idp}");
    add_person(&grid, "ada", "member", &[]);
    grid.hub.manage_as_owner(json!({"action": "ssoSet", "issuer": format!("http://{idp}"), "clientId": "access-app"})).unwrap();
    let browser = |code: &'static str, nonce: Arc<Mutex<String>>| {
        move |url: &str| -> Result<(), String> {
            let query = url.split_once('?').unwrap().1.to_owned();
            let get = |name: &str| query.split('&').find_map(|pair| pair.split_once('=').filter(|(key, _)| *key == name).map(|(_, value)| value.replace("%3A", ":").replace("%2F", "/"))).unwrap();
            *nonce.lock().unwrap() = get("nonce");
            let back = format!("{}?code={code}&state={}", get("redirect_uri"), get("state"));
            tokio::spawn(async move {
                let target = super::forward::target(&back).unwrap();
                let mut socket = tokio::net::TcpStream::connect((target.host.as_str(), target.port)).await.unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut socket, format!("GET {}?{} HTTP/1.1\r\nHost: x\r\n\r\n", target.path, target.query.unwrap_or_default()).as_bytes()).await.unwrap();
                let mut answer = Vec::new();
                let _ = tokio::io::AsyncReadExt::read_to_end(&mut socket, &mut answer).await;
            });
            Ok(())
        }
    };
    let signed = member::signin_sso(&grid.invite, "Laptop", browser("code-ada", nonce.clone())).await.unwrap();
    assert!(signed.strong && signed.device_token.is_some());
    assert_eq!(signed.person["username"], "ada");
    assert!(member::signin_sso(&grid.invite, "Laptop", browser("code-eve", nonce.clone())).await.unwrap_err().contains("refused to issue"));
    assert_eq!(member::signin_sso(&grid.invite, "Laptop", browser("code-entra", nonce.clone())).await.unwrap().person["username"], "ada", "preferred_username stands in for a missing email");

    // The first sign-in tied ada to her account at the provider: another account with her email
    // is refused, and so is an email the provider says it never verified.
    assert!(member::signin_sso(&grid.invite, "Laptop", browser("code-other", nonce.clone())).await.unwrap_err().contains("another"));
    assert!(member::signin_sso(&grid.invite, "Laptop", browser("code-unverified", nonce.clone())).await.unwrap_err().contains("verified"));
    // The admin screen sends the email with every edit: saving the same address keeps the tie.
    grid.hub.manage_as_owner(json!({"action": "personUpdate", "person": "ada", "email": "ada@acme.example", "teams": ["Research"]})).unwrap();
    assert!(member::signin_sso(&grid.invite, "Laptop", browser("code-other", nonce.clone())).await.unwrap_err().contains("another"));
    // Signing her out everywhere unties her, and the next sign-in ties the account it comes from.
    grid.hub.manage_as_owner(json!({"action": "personSignOut", "person": "ada"})).unwrap();
    assert_eq!(member::signin_sso(&grid.invite, "Laptop", browser("code-other", nonce.clone())).await.unwrap().person["username"], "ada");
    assert!(member::signin_sso(&grid.invite, "Laptop", browser("code-ada", nonce.clone())).await.unwrap_err().contains("another"));
    // So does a new email address.
    grid.hub.manage_as_owner(json!({"action": "personUpdate", "person": "ada", "email": "ada.l@acme.example"})).unwrap();
    grid.hub.manage_as_owner(json!({"action": "personUpdate", "person": "ada", "email": "ada@acme.example"})).unwrap();
    assert_eq!(member::signin_sso(&grid.invite, "Laptop", browser("code-ada", nonce.clone())).await.unwrap().person["username"], "ada");

    // The issuer typed with the tenant's domain name: tokens with the discovered issuer pass,
    // another tenant's do not.
    grid.hub.manage_as_owner(json!({"action": "ssoSet", "issuer": format!("http://{idp}/acme.example/v2.0"), "clientId": "access-app"})).unwrap();
    assert_eq!(member::signin_sso(&grid.invite, "Laptop", browser("code-tenant", nonce.clone())).await.unwrap().person["username"], "ada");
    assert!(member::signin_sso(&grid.invite, "Laptop", browser("code-stranger", nonce.clone())).await.unwrap_err().contains("issuer"));

    // A fixed sign-in port, for providers that match the redirect address port and all (Okta).
    let port = std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port();
    grid.hub.manage_as_owner(json!({"action": "ssoSet", "issuer": format!("http://{idp}"), "clientId": "access-app", "redirectPort": port})).unwrap();
    let seen = Arc::new(Mutex::new(String::new()));
    let (open, saw) = (browser("code-ada", nonce.clone()), seen.clone());
    member::signin_sso(&grid.invite, "Laptop", move |url: &str| {
        *saw.lock().unwrap() = url.to_owned();
        open(url)
    })
    .await
    .unwrap();
    assert!(seen.lock().unwrap().contains(&format!("redirect_uri=http%3A%2F%2F127.0.0.1%3A{port}%2Fcallback")));

    // Passwordless: the provider alone signs people in, except the person who runs the grid.
    grid.hub.manage_as_owner(json!({"action": "ssoSet", "issuer": format!("http://{idp}"), "clientId": "access-app", "passwordless": true})).unwrap();
    assert!(member::signin(&grid.invite, "ada", "ada password 1", None, "PC").await.unwrap_err().contains("identity provider"));
    assert!(member::signin(&grid.invite, "root.admin", "owner password 1", None, "PC").await.is_ok());
}

#[tokio::test]
async fn deleting_pauses_first_and_then_wipes_the_grid() {
    let grid = grid().await;
    let api = service().await;
    add_person(&grid, "ada", "member", &[]);
    grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "Echo", "destinations": [format!("http://{api}")], "value": SECRET})).unwrap();
    let ada = sign_in(&grid, "ada").await;
    grid.hub.close_later().unwrap();
    assert!(matches!(grid.hub.phase(), hub::Phase::Paused(_)));
    let paused = member::resume(&grid.invite.address, &ada.certificate, ada.device_token.as_deref().unwrap(), "PC").await.unwrap_err();
    assert!(matches!(&paused, CallError::Refused { code, .. } if code == "paused"), "{paused:?}");
    grid.hub.restore().unwrap();
    let back = member::resume(&grid.invite.address, &ada.certificate, ada.device_token.as_deref().unwrap(), "PC").await.unwrap();
    grid.hub.close_now().unwrap();
    assert!(matches!(call(&grid, &back, "me", json!({})).await.unwrap_err(), CallError::Deleted(_)));
    assert!(grid.hub.restore().is_err());
    let record = hub::load(&grid.path()).unwrap();
    assert!(record.credentials.is_empty() && record.people.is_empty());
    assert!(!grid.hub.told_enough());
}

#[tokio::test]
async fn a_deleted_grid_stays_deleted_and_a_second_pause_keeps_its_date() {
    let grid = grid().await;
    let until = grid.hub.close_later().unwrap();
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(grid.hub.close_later().unwrap(), until, "pausing again does not move the deletion date");
    grid.hub.close_now().unwrap();
    assert!(grid.hub.close_later().is_err(), "a wiped grid cannot be paused back to life");
    assert!(matches!(grid.hub.phase(), hub::Phase::Gone));
    assert!(grid.hub.restore().is_err());
}

#[tokio::test]
async fn a_two_step_code_signs_in_once() {
    let grid = grid().await;
    add_person(&grid, "ada", "member", &[]);
    let ada = sign_in(&grid, "ada").await;
    let started = call(&grid, &ada, "account", json!({"action": "twoStepStart"})).await.unwrap();
    let secret = started["secret"].as_str().unwrap().to_owned();
    let confirming = totp_code(&secret, crate::now());
    call(&grid, &ada, "account", json!({"action": "twoStepConfirm", "code": confirming})).await.unwrap();
    // The code that turned it on is spent: it signs nobody in afterwards.
    assert!(member::signin(&grid.invite, "ada", "ada password 1", Some(&confirming), "PC").await.unwrap_err().contains("code"));
    // The next code (a step ahead, which the clock allows) signs in once.
    let code = totp_code(&secret, crate::now() + 30);
    member::signin(&grid.invite, "ada", "ada password 1", Some(&code), "PC").await.unwrap();
    // Someone who saw the code (over a shoulder, in a log, through a phishing page) cannot use it again.
    assert!(member::signin(&grid.invite, "ada", "ada password 1", Some(&code), "PC").await.unwrap_err().contains("code"));
}

#[tokio::test]
async fn guessing_at_an_account_is_capped_and_the_cap_is_keyed_to_the_address_it_comes_from() {
    let grid = grid().await;
    add_person(&grid, "ada", "member", &[]);
    // Ten wrong tries at Ada's account from this address, and the next one is refused — even
    // though it is right. That is what a cap is: attempts stop before anyone knows if they are.
    for _ in 0..10 {
        assert!(member::signin(&grid.invite, "ada", "not ada's password", None, "PC").await.is_err());
    }
    let capped = member::signin(&grid.invite, "ada", "ada password 1", None, "PC").await.unwrap_err();
    assert!(capped.contains("wait 10 minutes"), "guessing must stop at the limit: {capped}");
    // The cap is keyed to (address, account), so it never reaches past this address or this
    // account. Bob, on the same address, signs in untouched: one person guessing at a colleague
    // does not shut an office out.
    add_person(&grid, "bob", "member", &[]);
    assert!(member::signin(&grid.invite, "bob", "bob password 1", None, "PC").await.is_ok(), "another account on the same address must be unaffected");
}

#[tokio::test]
async fn signing_in_clears_what_was_counted_so_a_later_slip_is_not_a_lock() {
    let grid = grid().await;
    add_person(&grid, "ada", "member", &[]);
    for _ in 0..9 {
        assert!(member::signin(&grid.invite, "ada", "mistyped", None, "PC").await.is_err());
    }
    assert!(member::signin(&grid.invite, "ada", "ada password 1", None, "PC").await.is_ok());
    // Without forgiving the count, this one slip would be the tenth and lock her out.
    assert!(member::signin(&grid.invite, "ada", "mistyped", None, "PC").await.unwrap_err().contains("username or password"));
    assert!(member::signin(&grid.invite, "ada", "ada password 1", None, "PC").await.is_ok());
}

#[tokio::test]
async fn a_backup_moves_the_grid_and_its_people_keep_their_sign_ins() {
    let grid = grid().await;
    let api = service().await;
    add_person(&grid, "ada", "member", &[]);
    grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "Echo", "destinations": [format!("http://{api}")], "value": SECRET})).unwrap();
    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "Echo"})).unwrap();
    let ada = sign_in(&grid, "ada").await;
    let bytes = backup::create(&grid.path(), &grid.tls_key, &grid.seal_key, "a long backup passphrase").unwrap();
    let Grid { folder, hub, invite, .. } = grid;
    drop(hub);
    drop(folder);
    let contents = backup::open(&bytes, "a long backup passphrase").unwrap();
    let moved = tempfile::tempdir().unwrap();
    let path = moved.path().join("access-hub.json");
    let mut record = hub::install(&path, &contents, Some("127.0.0.1".parse().unwrap())).unwrap();
    // The new computer listens on a port of its own.
    record.port = free_port();
    std::fs::write(&path, serde_json::to_vec(&record).unwrap()).unwrap();
    let hub = Hub::start(path, &contents.tls_key, &contents.seal_key, Arc::new(|_, _| {})).await.unwrap();
    assert_eq!(hub.fingerprint(), invite.fingerprint, "the certificate moved with it");
    let address = HubAddress::Direct(hub.address());
    let resumed = member::resume(&address, &ada.certificate, ada.device_token.as_deref().unwrap(), "PC").await.unwrap();
    let done = member::call(&address, &resumed.certificate, &resumed.token, "use", &json!({"credential": "Echo", "url": format!("http://{api}/x")})).await.unwrap();
    assert_eq!(done["state"], "done", "the credentials still open with the moved key");
    assert_eq!(hub.manage_as_owner(json!({"action": "activityVerify"})).unwrap()["ok"], true);
}

#[tokio::test]
async fn github_app_installation_tokens_are_made_on_the_hub() {
    // A throwaway RSA key from OpenSSL, made at test time; skipped where OpenSSL is not installed.
    let Ok(output) = std::process::Command::new("openssl").args(["genrsa", "2048"]).output() else {
        eprintln!("openssl is not installed; skipping the GitHub App test");
        return;
    };
    let key = String::from_utf8_lossy(&output.stdout).into_owned();
    if !key.contains("PRIVATE KEY-----") {
        eprintln!("openssl made no key; skipping the GitHub App test");
        return;
    }
    let grid = grid().await;
    let github = mock(Arc::new(|method, path, headers, _| {
        let jwt = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or_default().strip_prefix("Bearer ").unwrap_or_default().to_owned();
        let claims = jwt.split('.').nth(1).and_then(|part| base64::Engine::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, part).ok()).and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok()).unwrap_or_default();
        match (method, path) {
            ("POST", "/app/installations/99/access_tokens") if claims["iss"] == "42" && jwt.split('.').count() == 3 => (201, json!({"token": "ghs_installation_0123456789", "expires_at": "2099-01-01T00:00:00Z"}).to_string()),
            ("GET", "/repos/acme/app") => (200, json!({"auth": headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer ghs_installation_0123456789")}).to_string()),
            _ => (401, json!({"message": "Bad credentials"}).to_string()),
        }
    }))
    .await;
    add_person(&grid, "ada", "member", &[]);
    assert!(grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "GitHub", "kind": "github-app", "destinations": [format!("http://{github}/repos")], "value": "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----", "config": {"appId": "42", "installationId": "99", "apiUrl": format!("http://{github}")}})).is_err(), "a key that cannot sign is refused");
    grid.hub.manage_as_owner(json!({"action": "credentialAdd", "name": "GitHub", "kind": "github-app", "destinations": [format!("http://{github}/repos")], "value": key, "config": {"appId": "42", "installationId": "99", "apiUrl": format!("http://{github}")}})).unwrap();
    grid.hub.manage_as_owner(json!({"action": "ruleAdd", "credential": "GitHub"})).unwrap();
    let ada = sign_in(&grid, "ada").await;
    let done = call(&grid, &ada, "use", json!({"credential": "GitHub", "url": format!("http://{github}/repos/acme/app")})).await.unwrap();
    assert_eq!(serde_json::from_str::<Value>(done["answer"]["body"].as_str().unwrap()).unwrap()["auth"], true, "{done}");
    assert!(!grid.hub.manage_as_owner(json!({"action": "overview"})).unwrap().to_string().contains("PRIVATE KEY"));
}
