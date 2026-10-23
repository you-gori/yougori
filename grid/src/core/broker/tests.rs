//! What the credential broker must hold true.
//!
//! Every test here sends to a server on 127.0.0.1 and reads from a vault in memory. Nothing in
//! this file reaches the internet, and none of it proves that any real provider accepts the
//! request shape the broker builds.
use super::*;
use crate::core::{
    approval::{self, Verdict},
    audit::{Decision, Entry},
    capability::Authority,
    credential::{checked_settings, fingerprint_of, Credential, Kind, Secret},
    identity::{Action, PrincipalKind, Role},
    realm::{Capability, RealmKind},
    store,
    vault::{Keeper, MemoryVault, Unconnected},
};
use http_body_util::BodyExt;
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Map, Value};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tokio::{net::TcpListener, sync::Mutex};

fn key() -> String {
    "a".repeat(64)
}

/// A value with the characters that make its three forms differ from one another.
const SECRET: &str = "sk-live-7a\"b/c+d=0123456789abcdef";

/// Percent-encoding, the way the forwarder does it, so a test can look for that form.
fn encoded(text: &str) -> String {
    text.bytes().map(|byte| if byte.is_ascii_alphanumeric() || b"-._~".contains(&byte) { (byte as char).to_string() } else { format!("%{byte:02X}") }).collect()
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|window| window == needle)
}

/// A local service that echoes what it received, including the credential it was sent, in every
/// form a provider might hand back: raw, percent-encoded and escaped inside JSON. It sets a
/// cookie as well, because the forwarder is supposed to drop one.
async fn echo() -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { return };
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(|request: Request<Incoming>| async move {
                    let (parts, body) = request.into_parts();
                    let body = body.collect().await.unwrap().to_bytes();
                    let header = |name: &str| parts.headers.get(name).map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned()).unwrap_or_default();
                    let authorization = header("authorization");
                    let value = authorization
                        .strip_prefix("Bearer ")
                        .map(str::to_owned)
                        .unwrap_or_else(|| if header("x-api-key").is_empty() { parts.uri.query().unwrap_or_default().to_owned() } else { header("x-api-key") });
                    let seen = json!({
                        "method": parts.method.as_str(),
                        "uri": parts.uri.to_string(),
                        "authorization": authorization,
                        "apiKey": header("x-api-key"),
                        "accept": header("accept"),
                        // What a request signed for AWS carries. Empty for every other kind.
                        "amzDate": header("x-amz-date"),
                        "amzToken": header("x-amz-security-token"),
                        "body": String::from_utf8_lossy(&body),
                        "escaped": value,
                        "encoded": encoded(&value),
                    });
                    // The raw bytes of the value as well, outside the JSON, where nothing escapes
                    // them: that is the form a provider echoing a header would hand back.
                    let text = format!("{seen}\n{value}");
                    Ok::<_, std::convert::Infallible>(Response::builder()
                        .status(StatusCode::CREATED)
                        .header("set-cookie", "session=abc")
                        .header("x-echo", authorization)
                        .body(crate::net::full(text))
                        .unwrap() as Response<crate::net::Body>)
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (address, seen)
}

/// A realm that brokers credentials, the three people it takes, a vault with the value in it and
/// a local service to send to. The three roles are held by three people on purpose.
struct Grid {
    core: Arc<Mutex<Core>>,
    vault: Arc<MemoryVault>,
    keeper: Arc<dyn Vault>,
    /// The tokens this grid has made, in memory. Empty for every credential that sends its value
    /// as it is, which is most of this file.
    cache: mint::Cache,
    realm: String,
    admin: String,
    approver: String,
    user: String,
    device: String,
    credential: String,
    place: String,
    seen: Arc<AtomicUsize>,
    folder: tempfile::TempDir,
}

async fn grid(now: i64) -> Grid {
    let folder = tempfile::tempdir().unwrap();
    let mut core = Core::create(&folder.path().join("broker.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::CredentialApprover], now).unwrap();
    let user = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User], now).unwrap();
    let (device, _) = core.enrol_device(&user.id, "Ada's laptop", "windows", now).unwrap();
    let realm = core.realm().id.clone();

    let (address, seen) = echo().await;
    let place = format!("http://{address}");
    let credential = Credential::new(&realm, "Billing", Secret::ApiKey, "billing-key", &fingerprint_of(SECRET), &place, &admin.id, now)
        .unwrap()
        .narrowed_to(&["post"], &["/v1"], Some(4_096));
    let credential = core.add_credential(&admin.id, credential, now).unwrap();
    core.allow_credential(&admin.id, &credential.id, &user.id, &["post"], &["/v1"], None, now).unwrap();

    let vault = Arc::new(MemoryVault::new());
    vault.put(&vault::Entry::of(&credential), SECRET);
    let keeper: Arc<dyn Vault> = Arc::clone(&vault) as Arc<dyn Vault>;
    Grid {
        core: Arc::new(Mutex::new(core)),
        vault,
        keeper,
        cache: mint::Cache::new(),
        realm,
        admin: admin.id,
        approver: approver.id,
        user: user.id,
        device: device.id,
        credential: credential.id,
        place,
        seen,
        folder,
    }
}

impl Grid {
    /// Asks, has somebody agree, and takes the permission that comes back.
    async fn permit(&self, method: &str, path: &str, verdict: Verdict, seconds: i64, now: i64) -> String {
        let mut core = self.core.lock().await;
        let request = core.ask_for_credential(&self.user, &self.credential, method, path, approval::WAIT, now).unwrap();
        core.decide(&request.id, Action::ApproveCredential, &self.approver, verdict, now).unwrap();
        core.use_credential(&self.user, &self.device, "work-1", &self.credential, method, path, seconds, now).unwrap()
    }

    /// The ordinary permission the tests use: agreed once, good for ten minutes.
    async fn once(&self, method: &str, path: &str, now: i64) -> String {
        self.permit(method, path, Verdict::Once, 600, now).await
    }

    /// A permission from the shortest agreement a person can give, which is one minute, with the
    /// moment that agreement runs out. For the one test that needs time to pass under it.
    async fn briefly(&self, now: i64) -> (String, i64) {
        let mut core = self.core.lock().await;
        let request = core.ask_for_credential(&self.user, &self.credential, "post", "/v1/charge", 60, now).unwrap();
        core.decide(&request.id, Action::ApproveCredential, &self.approver, Verdict::Once, now).unwrap();
        let token = core.use_credential(&self.user, &self.device, "work-1", &self.credential, "post", "/v1/charge", 600, now).unwrap();
        (token, request.expires_at)
    }

    fn url(&self, path: &str) -> String {
        format!("{}{path}", self.place)
    }

    fn ask<'a>(&'a self, token: &'a str, method: &'a str, url: &'a str, body: Vec<u8>) -> Ask<'a> {
        Ask {
            token,
            realm_id: &self.realm,
            device_id: &self.device,
            workload_id: "work-1",
            credential_id: &self.credential,
            method,
            url,
            headers: Map::new(),
            body,
        }
    }

    async fn send(&self, ask: &Ask<'_>, now: i64) -> Result<Value, String> {
        send(&self.core, &self.keeper, &self.cache, ask, now).await
    }

    /// What the ledger of brokered requests holds.
    async fn uses(&self) -> Vec<Use> {
        self.core.lock().await.uses(None, 0).unwrap()
    }

    fn connections(&self) -> usize {
        self.seen.load(Ordering::SeqCst)
    }

    fn reads(&self) -> usize {
        self.vault.read_count()
    }
}

// ---- What is decided before a value is read ----

#[test]
fn paths_are_matched_by_segment_and_addresses_are_written_one_way() {
    let now = 30_000;
    let realm = "realm-1";
    let print = fingerprint_of(SECRET);
    // An address is normalised on the way in, so the spelling somebody typed cannot slip past a
    // list that holds the same place written differently.
    let shouting = Credential::new(realm, "Billing", Secret::ApiKey, "billing-key", &print, "HTTPS://API.ACME.TEST", "owner", now).unwrap();
    let trailing = Credential::new(realm, "Billing", Secret::ApiKey, "billing-key", &print, "https://api.acme.test/", "owner", now).unwrap();
    assert_eq!(shouting.destination, "https://api.acme.test");
    assert_eq!(trailing.destination, "https://api.acme.test");
    assert_eq!(shouting.places(), vec!["https://api.acme.test".to_owned()]);
    // Which is also the one spelling the allowlist is compared against.
    let target = crate::access::forward::target("https://API.acme.test:443/v1/charge").unwrap();
    assert!(Core::place_for(&shouting, &target, "not a permission").is_ok());
    let elsewhere = crate::access::forward::target("https://api.acme.test.evil.net/v1/charge").unwrap();
    assert!(Core::place_for(&shouting, &elsewhere, "not a permission").is_err());

    // A path prefix covers whole segments and never half a word.
    let narrowed = shouting.narrowed_to(&["post"], &["/v1"], None);
    assert!(narrowed.allows("POST", "/v1") && narrowed.allows("POST", "/v1/charge"));
    assert!(!narrowed.allows("POST", "/v1admin"), "a credential scoped to /v1 does not cover /v1admin");
    assert!(!narrowed.allows("POST", "/v1-internal"));
    assert!(!narrowed.allows("DELETE", "/v1/charge"));

    let grant = crate::core::credential::Grant::new(&narrowed, "person-1", &["post"], &["/v1"], "owner", None, now);
    assert!(grant.covers("POST", "/v1/charge", now));
    assert!(!grant.covers("POST", "/v1admin", now), "a grant scoped to /v1 does not cover /v1admin either");

    // And a vault entry is named by the same rule the operating system's vault layer uses.
    assert!(crate::core::credential::vault_entry("billing key").is_err());
    assert!(Credential::new(realm, "Billing", Secret::ApiKey, &"x".repeat(60), &print, "https://api.acme.test", "owner", now).is_err());
}

#[tokio::test]
async fn a_request_to_another_destination_is_never_sent() {
    let now = 30_100;
    let grid = grid(now).await;
    let (elsewhere, other) = echo().await;
    let token = grid.once("post", "/v1/charge", now).await;

    // Another computer, a look-alike name, the same host on another port, and the same host over
    // another scheme. A place is scheme, host and port together, so changing any one of the three
    // is somewhere else.
    let elsewhere_port = if elsewhere.port() == 9 { 10 } else { 9 };
    for url in [
        format!("http://{elsewhere}/v1/charge"),
        "https://api.acme.test.evil.net/v1/charge".to_owned(),
        format!("http://127.0.0.1:{elsewhere_port}/v1/charge"),
        grid.place.replacen("http://", "https://", 1) + "/v1/charge",
    ] {
        let ask = grid.ask(&token, "post", &url, Vec::new());
        let refused = grid.send(&ask, now).await.unwrap_err();
        assert!(refused.contains("not a place this credential may be sent to") || refused.contains("does not reach"), "{url}: {refused}");
    }
    assert_eq!((grid.connections(), other.load(Ordering::SeqCst), grid.reads()), (0, 0, 0), "nothing was sent anywhere and no value was read");
    assert!(grid.uses().await.is_empty(), "and no request was opened");
}

#[tokio::test]
async fn a_request_with_another_method_or_path_or_size_is_never_sent() {
    let now = 30_200;
    let grid = grid(now).await;

    // A method the credential does not allow is refused when the permission is asked for.
    let refused = {
        let mut core = grid.core.lock().await;
        let request = core.ask_for_credential(&grid.user, &grid.credential, "delete", "/v1/charge", approval::WAIT, now).unwrap();
        core.decide(&request.id, Action::ApproveCredential, &grid.approver, Verdict::Once, now).unwrap();
        core.use_credential(&grid.user, &grid.device, "work-1", &grid.credential, "delete", "/v1/charge", 600, now).unwrap_err()
    };
    assert!(refused.contains("not for DELETE"), "{refused}");

    // A permission for one path is not a permission for another, whichever way it is spelled.
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/refund");
    let ask = grid.ask(&token, "post", &url, Vec::new());
    assert!(grid.send(&ask, now).await.unwrap_err().contains("does not allow that path"));
    for ambiguous in ["/v1/../admin", "/v1/%2e%2e/admin", "/v1%2Fadmin", "/v1/..;/admin", "//v1/charge"] {
        let url = grid.url(ambiguous);
        let ask = grid.ask(&token, "post", &url, Vec::new());
        let refused = grid.send(&ask, now).await.unwrap_err();
        assert!(refused.contains("ambiguous") || refused.contains("full https"), "{ambiguous}: {refused}");
    }

    // One byte over what the credential carries is refused, and the permission says the same.
    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, vec![b'x'; 4_097]);
    let refused = grid.send(&ask, now).await.unwrap_err();
    assert!(refused.contains("does not allow that size"), "{refused}");

    assert_eq!((grid.connections(), grid.reads()), (0, 0), "nothing reached the service and no value was read");
    assert!(grid.uses().await.is_empty());
}

#[tokio::test]
async fn a_retired_credential_is_refused_before_any_value_is_read() {
    let now = 30_300;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    grid.core.lock().await.retire_credential(&grid.admin, &grid.credential, now + 1).unwrap();

    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());
    let refused = grid.send(&ask, now + 2).await.unwrap_err();
    assert!(refused.contains("has been retired"), "{refused}");
    assert_eq!((grid.connections(), grid.reads()), (0, 0));
    assert!(grid.uses().await.is_empty(), "a request that was refused before the record was opened leaves no record to close");
}

#[tokio::test]
async fn a_rotated_credential_refuses_the_permission_minted_before_it() {
    let now = 30_400;
    let grid = grid(now).await;
    let before = grid.once("post", "/v1/charge", now).await;

    // The administrator's tool writes the new value to the entry the grid names, and only then is
    // the rotation recorded.
    let second = "sk-live-rotated-0123456789abcdefghij";
    let entry = grid.core.lock().await.rotation_target(&grid.credential).unwrap();
    assert_eq!(entry.account(), "grid-core.billing-key.v2");
    grid.vault.put(&entry, second);
    assert_eq!(grid.core.lock().await.rotate_credential(&grid.admin, &grid.credential, &fingerprint_of(second), now + 10).unwrap(), 2);

    let url = grid.url("/v1/charge");
    let ask = grid.ask(&before, "post", &url, Vec::new());
    let refused = grid.send(&ask, now + 11).await.unwrap_err();
    assert!(refused.contains("rotated or retired after this permission was issued"), "{refused}");
    assert_eq!((grid.connections(), grid.reads()), (0, 0));

    // A permission minted afterwards reads the new entry and no other.
    let after = grid.once("post", "/v1/charge", now + 12).await;
    let url = grid.url("/v1/charge");
    let ask = grid.ask(&after, "post", &url, Vec::new());
    assert_eq!(grid.send(&ask, now + 13).await.unwrap()["status"], 201);
    let uses = grid.uses().await;
    assert_eq!(uses.len(), 1);
    assert_eq!((uses[0].vault_id.as_str(), uses[0].vault_version), ("billing-key", 2));
    assert_eq!(grid.reads(), 1, "the entry that is current, once");
}

#[tokio::test]
async fn a_permission_cannot_be_used_a_second_time() {
    let now = 30_500;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge");

    let ask = grid.ask(&token, "post", &url, Vec::new());
    assert_eq!(grid.send(&ask, now).await.unwrap()["status"], 201);
    let refused = grid.send(&ask, now + 1).await.unwrap_err();
    assert!(refused.contains("already used"), "{refused}");
    assert_eq!(grid.uses().await.len(), 1, "one record for one permission");

    // And it survives the realm being closed and opened again, because being spent is in the
    // database and not only in memory.
    let path = {
        let core = grid.core.lock().await;
        core.path().to_owned()
    };
    let reopened = Arc::new(Mutex::new(Core::open(&path, &key()).unwrap()));
    let refused = send(&reopened, &grid.keeper, &grid.cache, &ask, now + 2).await.unwrap_err();
    assert!(refused.contains("already used"), "{refused}");
    assert_eq!(grid.connections(), 1, "only the first send ever reached the service");
}

#[tokio::test]
async fn an_agreement_that_has_run_out_refuses_the_permission_it_allowed() {
    let now = 30_600;
    let grid = grid(now).await;
    // Allowed for two hours, with a permission that outlives the request the allowance came from.
    let token = grid.permit("post", "/v1/charge", Verdict::Hours(2), 24 * 3_600, now).await;
    let url = grid.url("/v1/charge");

    // Half an hour later the request itself has lapsed, and the standing allowance it created has
    // not. This is the common case, and refusing it would stop every standing allowance working.
    let ask = grid.ask(&token, "post", &url, Vec::new());
    assert_eq!(grid.send(&ask, now + 1_800).await.unwrap()["status"], 201);

    // Three hours later the allowance has run out, and the permission has not.
    let second = grid.core.lock().await.use_credential(&grid.user, &grid.device, "work-1", &grid.credential, "post", "/v1/charge", 24 * 3_600, now + 60).unwrap();
    let ask = grid.ask(&second, "post", &url, Vec::new());
    let refused = grid.send(&ask, now + 3 * 3_600).await.unwrap_err();
    assert!(refused.contains("agreement this use came from has run out"), "{refused}");
    assert_eq!(grid.connections(), 1, "the second request never reached the service");
}

// ---- The send itself ----

#[tokio::test]
async fn the_value_goes_on_the_request_and_no_form_of_it_comes_back() {
    let now = 30_700;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge?page=2");
    let mut ask = grid.ask(&token, "post", &url, b"{\"amount\":1}".to_vec());
    ask.headers = json!({"Accept": "application/json", "Authorization": "Bearer agent-guess", "Host": "evil"}).as_object().unwrap().clone();

    let answer = grid.send(&ask, now).await.unwrap();
    assert_eq!(answer["status"], 201);
    let printed = answer.to_string();
    let body = answer["body"].as_str().unwrap();
    let seen: Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();

    // The service got the grid's credential, not the workload's guess, and kept the rest.
    assert_eq!(seen["authorization"], "Bearer [hidden by Access Grid]");
    assert_eq!(seen["accept"], "application/json");
    assert_eq!(seen["uri"], "/v1/charge?page=2");
    assert_eq!(seen["body"], "{\"amount\":1}");

    // Every form the forwarder hides is hidden, in the headers and in the body.
    for form in [SECRET.to_owned(), encoded(SECRET), serde_json::to_string(SECRET).unwrap().trim_matches('"').to_owned()] {
        assert!(!printed.contains(&form), "the answer carries a form of the value: {form}");
    }
    assert!(!printed.contains("sk-live"));
    assert_eq!(answer["headers"]["x-echo"], "Bearer [hidden by Access Grid]");
    assert!(answer["headers"].get("set-cookie").is_none(), "a session the credential opened is not handed on");

    // And the record of it says what was sent, with no query in it.
    let uses = grid.uses().await;
    assert_eq!(uses.len(), 1);
    assert_eq!((uses[0].outcome.as_str(), uses[0].status, uses[0].method.as_str(), uses[0].path.as_str()), ("sent", Some(201), "POST", "/v1/charge"));
    assert_eq!(uses[0].destination, grid.place);
    assert!(uses[0].finished_at.is_some() && uses[0].reason.is_empty());
}

#[tokio::test]
async fn a_value_that_does_not_match_its_fingerprint_is_refused() {
    let now = 30_800;
    let grid = grid(now).await;
    // Somebody edited the vault entry outside the grid.
    grid.vault.put(&vault::Entry { realm_id: grid.realm.clone(), vault_id: "billing-key".into(), version: 1 }, "something-else-entirely");
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());

    let refused = grid.send(&ask, now).await.unwrap_err();
    assert!(refused.contains("not the one this grid recorded"), "{refused}");
    assert_eq!(grid.connections(), 0, "nothing was sent");
    let uses = grid.uses().await;
    assert_eq!((uses.len(), uses[0].outcome.as_str(), uses[0].reason.as_str()), (1, "refused", "fingerprint"));
    assert!(uses[0].finished_at.is_some(), "the record of a refused request is closed, not left open");
}

#[tokio::test]
async fn a_vault_this_build_cannot_open_refuses_rather_than_sending_without_a_credential() {
    let now = 30_900;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());

    let unconnected: Arc<dyn Vault> = Arc::new(Unconnected(Keeper::HashiCorpVault));
    let refused = send(&grid.core, &unconnected, &grid.cache, &ask, now).await.unwrap_err();
    assert!(refused.contains("HashiCorp Vault") && refused.contains("could not be reached"), "{refused}");
    assert_eq!(grid.connections(), 0);
    let uses = grid.uses().await;
    assert_eq!((uses[0].outcome.as_str(), uses[0].reason.as_str()), ("refused", "vault"));

    // And what this build can open is said plainly, in one place, for every keeper named.
    assert!(Keeper::OperatingSystem.connected());
    for keeper in Keeper::all().iter().filter(|keeper| **keeper != Keeper::OperatingSystem) {
        assert!(!keeper.connected(), "{} is not wired in", keeper.name());
        assert!(keeper.unconnected().contains("not connected in this build"));
        let row = crate::core::connector::registry::find(keeper.name()).expect("every keeper has a row in the adapter matrix");
        assert!(!row.state.may_change_a_tenant(), "{} claims more than this repository can show", keeper.name());
    }
}

#[tokio::test]
async fn the_realm_can_change_while_the_value_is_being_read() {
    let now = 31_000;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;

    // The vault takes its time, as a locked keychain or a prompt would, and an administrator
    // retires the credential while it does. Everything was in order when the request was cleared.
    let core = Arc::clone(&grid.core);
    let admin = grid.admin.clone();
    let credential = grid.credential.clone();
    *grid.vault.meanwhile.lock().unwrap() = Some(Box::new(move || {
        let mut realm = core.blocking_lock();
        if realm.credential(&credential).unwrap().unwrap().live(0) {
            realm.retire_credential(&admin, &credential, now + 1).unwrap();
        }
    }));

    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());
    let refused = grid.send(&ask, now + 2).await.unwrap_err();
    assert!(refused.contains("This credential changed between the agreement and the moment"), "{refused}");
    assert_eq!((grid.connections(), grid.reads()), (0, 1), "the value was read and the request still never went");
    let uses = grid.uses().await;
    assert_eq!((uses[0].outcome.as_str(), uses[0].reason.as_str()), ("refused", "rechecked"));
}

#[tokio::test]
async fn turning_egress_off_stops_every_credential_at_once() {
    let now = 31_100;
    let grid = grid(now).await;
    let security = grid.core.lock().await.add_principal("owner", PrincipalKind::Person, "Mary", &[Role::SecurityAdmin], now).unwrap().id;
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge");

    // A list that does not hold this place stops it, even though the credential allows it.
    grid.core.lock().await.set_egress(&security, true, &["https://api.acme.test"], now).unwrap();
    let ask = grid.ask(&token, "post", &url, Vec::new());
    assert!(grid.send(&ask, now).await.unwrap_err().contains("does not reach"));

    // Nothing leaves at all stops it as well.
    grid.core.lock().await.set_egress(&security, false, &[], now).unwrap();
    assert!(grid.send(&ask, now).await.unwrap_err().contains("not reaching anything outside"));

    // Put this place on the list and it goes. The permission is still unspent, because a refusal
    // before the permission is accepted does not spend it.
    grid.core.lock().await.set_egress(&security, true, &[&grid.place], now).unwrap();
    assert_eq!(grid.send(&ask, now).await.unwrap()["status"], 201);
    assert_eq!(grid.connections(), 1);

    // And only a security administrator may change any of it.
    assert!(grid.core.lock().await.set_egress(&grid.user, true, &[], now).unwrap_err().contains("may not"));
}

#[tokio::test]
async fn a_credential_may_be_sent_to_more_than_one_place_and_each_permission_is_for_one_of_them() {
    let now = 31_200;
    let grid = grid(now).await;
    let (second, other) = echo().await;
    let elsewhere = format!("http://{second}");

    let added = grid.core.lock().await.allow_destination(&grid.admin, &grid.credential, &format!("{elsewhere}/"), now).unwrap();
    assert_eq!(added, elsewhere, "written the one way an address is written");
    assert_eq!(grid.core.lock().await.destinations(&grid.credential).unwrap().len(), 2);

    // A permission pinned to the second place is not a permission for the first.
    let pinned = {
        let mut core = grid.core.lock().await;
        let request = core.ask_for_credential(&grid.user, &grid.credential, "post", "/v1/charge", approval::WAIT, now).unwrap();
        core.decide(&request.id, Action::ApproveCredential, &grid.approver, Verdict::Once, now).unwrap();
        core.use_credential_to(&grid.user, &grid.device, "work-1", &grid.credential, Some(&elsewhere), "post", "/v1/charge", 600, now).unwrap()
    };
    assert_eq!(Authority::peek(&pinned).unwrap().destination.as_deref(), Some(elsewhere.as_str()));
    let url = grid.url("/v1/charge");
    let ask = grid.ask(&pinned, "post", &url, Vec::new());
    assert!(grid.send(&ask, now).await.unwrap_err().contains("does not allow that destination"));
    let url = format!("{elsewhere}/v1/charge");
    let ask = grid.ask(&pinned, "post", &url, Vec::new());
    assert_eq!(grid.send(&ask, now).await.unwrap()["status"], 201);
    assert_eq!((grid.connections(), other.load(Ordering::SeqCst)), (0, 1));

    // The last place cannot be taken away: a credential with nowhere to go is retired instead.
    let mut core = grid.core.lock().await;
    core.deny_destination(&grid.admin, &grid.credential, &elsewhere, now).unwrap();
    assert!(core.deny_destination(&grid.admin, &grid.credential, &grid.place, now).unwrap_err().contains("retire it instead"));
}

// ---- What is written down, and what is not ----

#[tokio::test]
async fn nothing_about_the_value_reaches_the_database_the_history_or_a_backup() {
    let now = 31_300;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    // The request carries a query, because the sentinel at the end of this test is about queries:
    // without one on the wire nothing here could ever have written one down.
    let url = grid.url("/v1/charge?page=2");
    let ask = grid.ask(&token, "post", &url, Vec::new());
    grid.send(&ask, now).await.unwrap();

    let (path, taken) = {
        let core = grid.core.lock().await;
        // No event anywhere says anything of the value, and the record of the request says what
        // was sent rather than what was in it.
        for event in core.snapshot().unwrap().audit.events {
            assert!(!event.reason.contains(SECRET) && !event.reason.contains("sk-live"), "{}", event.reason);
        }
        let sent = core.uses(Some(&grid.credential), 0).unwrap();
        assert_eq!(sent[0].vault_id, "billing-key");
        (core.path().to_owned(), core.backup(now).unwrap())
    };

    // A backup carries the reference and no value.
    let written = serde_json::to_string(&taken).unwrap();
    assert!(!written.contains(SECRET) && !written.contains(&encoded(SECRET)));
    assert!(written.contains("billing-key"), "only the name of the entry holding it");

    // Nor is any form of it anywhere in the realm's own file or its journal.
    Arc::try_unwrap(grid.core).map_err(|_| "the realm is held somewhere else").unwrap().into_inner().close().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    let journal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    if journal.exists() {
        bytes.extend(std::fs::read(&journal).unwrap());
    }
    for form in [SECRET.to_owned(), encoded(SECRET), base64::Engine::encode(&base64::engine::general_purpose::STANDARD, SECRET)] {
        assert!(!holds(&bytes, form.as_bytes()), "a form of the value reached the grid's database: {form}");
    }
    assert!(holds(&bytes, b"billing-key"), "only the name of the vault entry that holds it");
    assert!(!holds(&bytes, b"page=2"), "and no query, because a query credential's value travels in one");
    drop(grid.folder);
}

#[test]
fn an_audit_reason_that_looks_like_a_value_is_withheld_whoever_wrote_it() {
    let secret = Entry::new("realm-1", "person-1", "credential.sent", Decision::Allowed).because(&format!("Bearer {SECRET}")).safe();
    assert_eq!(secret.reason, "withheld: this reason looked like a value");
    let ordinary = Entry::new("realm-1", "person-1", "credential.sent", Decision::Allowed).because("POST /v1/charge at https://api.acme.test: answered 201 in 40 bytes").safe();
    assert!(ordinary.reason.starts_with("POST /v1/charge"), "an ordinary reason is left alone: {}", ordinary.reason);
}

#[test]
fn a_held_value_cannot_be_printed_and_wiping_really_zeroes() {
    let mut bytes = SECRET.as_bytes().to_vec();
    vault::wipe(&mut bytes);
    assert!(bytes.iter().all(|byte| *byte == 0), "wiping leaves nothing of it behind");

    let held = Held::from(SECRET.as_bytes().to_vec());
    assert_eq!(format!("{held:?}"), "Held(hidden)");
    assert_eq!(held.len(), SECRET.len());
    assert_eq!(held.as_text().unwrap(), SECRET);
    assert_eq!(held.fingerprint().unwrap(), fingerprint_of(SECRET));
    // What is not UTF-8 is not a value this build can put on a request, and says so.
    assert_eq!(Held::from(vec![0xff, 0xfe]).as_text().unwrap_err(), vault::Trouble::Damaged);
}

#[test]
fn a_value_comes_back_out_of_a_vault_in_the_encoding_it_went_in_as() {
    let damaged = |blob: Vec<u8>| matches!(vault::unframed(blob), Err(vault::Trouble::Damaged));

    // What this grid writes, and what it reads back: the same bytes, the same fingerprint.
    let value = Held::from(SECRET.as_bytes().to_vec());
    let blob = vault::framed(&value);
    assert!(blob.expose().starts_with(vault::WRITTEN_AS), "the line that says which encoding this is goes first");
    let back = vault::unframed(blob.expose().to_vec()).unwrap();
    assert_eq!(back.as_text().unwrap(), SECRET);
    assert_eq!(back.fingerprint().unwrap(), fingerprint_of(SECRET));

    // The one this exists for. Windows Credential Manager's text door stores the UTF-16 of a
    // value, so an entry written through it and read as bytes is not the value's UTF-8: it is
    // bytes of the right length-ish and the wrong meaning, and it would fingerprint to something
    // else and refuse every send with nothing to point at. It is refused as damaged instead.
    let utf16: Vec<u8> = SECRET.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect();
    assert_ne!(utf16, SECRET.as_bytes(), "the two encodings of one value really are different bytes");
    assert!(damaged(utf16));

    // And so is an entry somebody else wrote, however plausible it looks.
    assert!(damaged(SECRET.as_bytes().to_vec()), "a bare value was not written by this grid");
    assert!(damaged(Vec::new()));
    assert!(damaged(vault::WRITTEN_AS[..4].to_vec()));
    assert!(damaged([vault::WRITTEN_AS, &[0xff, 0xfe]].concat()), "what follows the line still has to be text");
    assert!(damaged(vault::WRITTEN_AS.to_vec()), "and there has to be something there");
    assert!(damaged([vault::WRITTEN_AS, b"sk\0live"].concat()), "a NUL is not text a value is made of");

    // A line break is refused where the value would travel, not at the vault's door. A credential
    // that puts the value itself on a request cannot carry one, because it could end a header
    // early; a GitHub App's private key is a PEM block of several lines and never travels as
    // itself, so a vault that refused a break here would refuse the one value that needs them.
    for ending in ["sk\rlive", "sk\nlive"] {
        let held = vault::unframed([vault::WRITTEN_AS, ending.as_bytes()].concat()).expect("the vault holds it");
        assert_eq!(mint::value_in(Kind::Bearer, &held).unwrap_err(), vault::Trouble::Damaged, "{ending:?} could end a header early");
        assert_eq!(mint::value_in(Kind::Query, &held).unwrap_err(), vault::Trouble::Damaged, "{ending:?}");
        assert_eq!(mint::value_in(Kind::GithubApp, &held).unwrap(), ending, "a private key is read as it was written");
    }
    let key = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
    let held = vault::unframed([vault::WRITTEN_AS, key.as_bytes()].concat()).unwrap();
    assert_eq!(mint::value_in(Kind::GithubApp, &held).unwrap(), key);
    assert!(mint::value_in(Kind::Basic, &held).is_err());
}

#[tokio::test]
async fn the_broker_tables_have_no_column_that_could_hold_a_value_and_a_record_is_closed_once() {
    let now = 31_400;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());
    grid.send(&ask, now).await.unwrap();
    let path = {
        let core = grid.core.lock().await;
        core.path().to_owned()
    };
    Arc::try_unwrap(grid.core).map_err(|_| "the realm is held somewhere else").unwrap().into_inner().close().unwrap();

    let connection = rusqlite::Connection::open(&path).unwrap();
    for table in ["credential_uses", "credential_destinations"] {
        let mut query = connection.prepare(&format!("SELECT name FROM pragma_table_info('{table}')")).unwrap();
        let columns: Vec<String> = query.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
        for forbidden in ["value", "secret", "password", "token", "key", "material", "private_key", "cipher", "fingerprint"] {
            assert!(!columns.iter().any(|column| column == forbidden), "{table} has no {forbidden}, and never will");
        }
    }
    let mut query = connection.prepare("SELECT name FROM pragma_table_info('credential_uses')").unwrap();
    let columns: Vec<String> = query.query_map([], |row| row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap();
    assert!(columns.iter().any(|column| column == "vault_id") && columns.iter().any(|column| column == "vault_version"), "which entry was read, and which version of it");
    drop(query);

    // The database itself refuses a second close, a change to what was attempted, and a delete.
    for statement in [
        "UPDATE credential_uses SET outcome = 'refused', finished_at = 1",
        "UPDATE credential_uses SET path = '/v1/elsewhere', outcome = 'sent', finished_at = 1",
        "DELETE FROM credential_uses",
    ] {
        let refused = connection.execute_batch(statement).unwrap_err().to_string();
        assert!(refused.contains("closed once") || refused.contains("cannot be withdrawn"), "{statement}: {refused}");
    }
    // And a way of travelling that is not one of the seven is refused there as well, as is a
    // credential that says it is a client certificate, a value travelling in a URL with nobody's
    // name against the decision, and a settings map with something in it that reads as a secret.
    let refused = connection.execute_batch("UPDATE credentials SET presentation = 'mtls'").unwrap_err().to_string();
    assert!(refused.contains("bearer, header, basic, query, oauth, github-app or aws"), "{refused}");
    let refused = connection
        .execute_batch("INSERT INTO credentials (id, realm_id, name, kind, vault_id, fingerprint, destination, owner_id, created_at) SELECT 'c2', realm_id, 'Other', 'certificate', vault_id, fingerprint, destination, owner_id, created_at FROM credentials")
        .unwrap_err()
        .to_string();
    assert!(refused.contains("client certificate needs mutual TLS"), "{refused}");
    let refused = connection.execute_batch("UPDATE credentials SET query_allowed_by = 'owner'").unwrap_err().to_string();
    assert!(refused.contains("records who allowed it and when"), "{refused}");
    let refused = connection.execute_batch(r#"UPDATE credentials SET settings = '{"clientSecret":"abcdef"}'"#).unwrap_err().to_string();
    assert!(refused.contains("CHECK"), "{refused}");
    drop(connection);
    drop(grid.folder);
}

#[tokio::test]
async fn a_restored_grid_refuses_every_permission_it_handed_out_before() {
    let now = 31_500;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let taken = grid.core.lock().await.backup(now).unwrap();
    let url = grid.url("/v1/charge");

    let restored = Arc::new(Mutex::new(Core::restore(&grid.folder.path().join("restored.db"), taken, &key()).unwrap()));
    let ask = grid.ask(&token, "post", &url, Vec::new());
    let refused = send(&restored, &grid.keeper, &grid.cache, &ask, now).await.unwrap_err();
    assert!(refused.contains("no record of issuing this permission"), "{refused}");
    assert_eq!((grid.connections(), grid.reads()), (0, 0), "nothing was sent and no value was read");

    // The credential and its grant came across, so a fresh agreement and a fresh permission work.
    {
        let core = restored.lock().await;
        let credential = core.credential(&grid.credential).unwrap().unwrap();
        assert_eq!(credential.places(), vec![grid.place.clone()], "where it may be sent came across with it");
        assert_eq!(credential.generation, 1);
    }
    let fresh = {
        let mut core = restored.lock().await;
        let request = core.ask_for_credential(&grid.user, &grid.credential, "post", "/v1/charge", approval::WAIT, now + 1).unwrap();
        core.decide(&request.id, Action::ApproveCredential, &grid.approver, Verdict::Once, now + 1).unwrap();
        core.use_credential(&grid.user, &grid.device, "work-1", &grid.credential, "post", "/v1/charge", 600, now + 1).unwrap()
    };
    let ask = grid.ask(&fresh, "post", &url, Vec::new());
    assert_eq!(send(&restored, &grid.keeper, &grid.cache, &ask, now + 1).await.unwrap()["status"], 201);
}

#[tokio::test]
async fn two_hubs_cannot_be_inside_the_same_permission_at_once() {
    let now = 31_600;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());
    let cleared = grid.core.lock().await.clear_to_send(&ask, now).unwrap();

    // The record of a request is what settles the race, in the database, between two hubs that
    // both hold the same realm. The second insert for one permission is refused there.
    let second = Use { id: "use-second".into(), ..cleared_as_use(&cleared, now) };
    let core = grid.core.lock().await;
    let refused = core.store.open_use(&second).unwrap_err();
    assert!(refused.contains("Another computer is already using this permission"), "{refused}");
    drop(core);

    // The spent permission refuses the second hub before that, which is the guard that bites
    // first; both are here because only one of them survives a hub restarting.
    let refused = grid.send(&ask, now).await.unwrap_err();
    assert!(refused.contains("already used"), "{refused}");
}

/// The row one cleared request would open, for the test above.
fn cleared_as_use(cleared: &Cleared, now: i64) -> Use {
    Use {
        id: cleared.use_id.clone(),
        realm_id: cleared.realm_id.clone(),
        credential_id: cleared.credential_id.clone(),
        capability_id: cleared.capability_id.clone(),
        approval_id: cleared.approval_id.clone(),
        principal_id: cleared.principal_id.clone(),
        device_id: cleared.device_id.clone(),
        workload_id: cleared.workload_id.clone(),
        destination: cleared.place.clone(),
        method: cleared.outgoing.method.clone(),
        path: cleared.outgoing.target.path.clone(),
        request_bytes: 0,
        answer_bytes: None,
        status: None,
        vault_id: cleared.entry.vault_id.clone(),
        vault_version: cleared.entry.version,
        outcome: "opening".into(),
        reason: String::new(),
        policy_version: cleared.policy_version,
        started_at: now,
        finished_at: None,
    }
}

#[tokio::test]
async fn a_request_left_open_by_a_hub_that_stopped_is_closed_as_unknown() {
    let now = 31_700;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());

    let mut core = grid.core.lock().await;
    core.clear_to_send(&ask, now).unwrap();
    assert_eq!(core.reap_open_uses(now + 1).unwrap(), 0, "a request that may still be in flight is left alone");
    assert_eq!(core.reap_open_uses(now + OPEN_FOR + 1).unwrap(), 1);
    let uses = core.uses(None, 0).unwrap();
    assert_eq!((uses[0].outcome.as_str(), uses[0].reason.as_str()), ("unknown", "abandoned"));
    assert_eq!(core.reap_open_uses(now + OPEN_FOR + 2).unwrap(), 0, "and it is closed once");
}

#[tokio::test]
async fn a_research_realm_reaches_no_credential_and_no_permission_crosses_between_realms() {
    let now = 31_800;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let research = Core::create(&grid.folder.path().join("research.db"), "Study", RealmKind::Research, &[Capability::Research], &"b".repeat(64), now).unwrap();
    let realm = research.realm().id.clone();
    let research = Arc::new(Mutex::new(research));

    // A credential cannot exist there at all.
    let refused = {
        let mut core = research.lock().await;
        let credential = Credential::new(&realm, "Billing", Secret::ApiKey, "billing-key", &fingerprint_of(SECRET), "https://api.acme.test", "owner", now).unwrap();
        core.add_credential("owner", credential, now).unwrap_err()
    };
    assert!(refused.contains("does not broker credentials"), "{refused}");

    // And a permission minted by the company's realm is refused there, before anything else:
    // the realms hold different keys, so the signature simply fails.
    let url = grid.url("/v1/charge");
    let ask = Ask { realm_id: &realm, ..grid.ask(&token, "post", &url, Vec::new()) };
    let refused = send(&research, &grid.keeper, &grid.cache, &ask, now).await.unwrap_err();
    assert!(refused.contains("does not broker credentials"), "{refused}");
    let mut core = research.lock().await;
    let attempt = crate::core::capability::Attempt { realm_id: &realm, device_id: &grid.device, workload_id: "work-1", resource_id: &grid.credential, ..Default::default() };
    assert!(core.accept(&token, &attempt, now).unwrap_err().contains("not issued by this grid"));
    assert_eq!(grid.connections(), 0);
}

#[test]
fn version_five_can_be_taken_back_out_and_put_back() {
    let folder = tempfile::tempdir().unwrap();
    let now = 31_900;
    let path = folder.path().join("realm.db");
    let core = Core::create(&path, "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = {
        let mut core = core;
        let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap();
        let credential = Credential::new(core.realm().id.as_str(), "Billing", Secret::ApiKey, "billing-key", &fingerprint_of(SECRET), "https://api.acme.test", &admin.id, now).unwrap();
        core.add_credential(&admin.id, credential, now).unwrap();
        core.close().unwrap();
        admin.id
    };

    let mut store = store::Store::open(&path).unwrap();
    assert!(store.roll_back(4).unwrap_err().contains("at version 13"));
    // Versions come out in the order they went in: six's triggers hang on five's table, and
    // eight's connector tasks hang on five's credentials.
    store.roll_back(13).unwrap();
    store.roll_back(12).unwrap();
    store.roll_back(11).unwrap();
    store.roll_back(10).unwrap();
    store.roll_back(9).unwrap();
    store.roll_back(8).unwrap();
    store.roll_back(7).unwrap();
    store.roll_back(6).unwrap();
    store.roll_back(5).unwrap();
    assert_eq!(store.version().unwrap(), 4);
    assert!(store.credentials().unwrap_err().contains("presentation"), "a version 4 build reads a version 4 shape");
    drop(store);

    // Opening it with this build runs the step again, and what version 4 kept is still there.
    let reopened = Core::open(&path, &key()).unwrap();
    assert_eq!(reopened.history().unwrap().len(), crate::core::store::SCHEMA_VERSION as usize);
    let credentials = reopened.credentials().unwrap();
    assert_eq!(credentials.len(), 1);
    assert_eq!(credentials[0].places(), vec!["https://api.acme.test".to_owned()], "the destination it already had is its first place again");
    assert_eq!(credentials[0].owner_id, admin);
    reopened.verify_audit().unwrap();
}

// ---- Attacks on the way out ----
//
// The thirteenth family of the security pass: the core's own outbound path. Everything below
// binds 127.0.0.1 and reads a vault in memory, exactly as the rest of this file does. Nothing
// here reaches an address that is not this computer's own, and none of it proves anything about
// a real provider.

/// A local service that answers every request with a redirect to `elsewhere`.
async fn redirector(elsewhere: std::net::SocketAddr) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { return };
            counted.fetch_add(1, Ordering::SeqCst);
            let to = format!("http://{elsewhere}/v1/charge");
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |_request: Request<Incoming>| {
                    let to = to.clone();
                    async move {
                        Ok::<_, std::convert::Infallible>(Response::builder()
                            .status(StatusCode::FOUND)
                            .header("location", to)
                            .body(crate::net::full(String::new()))
                            .unwrap() as Response<crate::net::Body>)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (address, seen)
}

/// A realm that brokers one credential to one place, built here rather than through `grid` so
/// the place can be chosen.
async fn brokering(folder: &std::path::Path, name: &str, place: &str, presentation: Option<(crate::access::policy::Kind, &str)>, now: i64) -> (Arc<Mutex<Core>>, Arc<dyn Vault>, String, String, String, String) {
    let mut core = Core::create(&folder.join(format!("{name}.db")), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::CredentialApprover], now).unwrap();
    let user = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User], now).unwrap();
    let (device, _) = core.enrol_device(&user.id, "Ada's laptop", "windows", now).unwrap();
    let realm = core.realm().id.clone();
    let mut credential =
        Credential::new(&realm, "Billing", Secret::ApiKey, "billing-key", &fingerprint_of(SECRET), place, &admin.id, now).unwrap().narrowed_to(&["post"], &["/v1"], Some(4_096));
    if let Some((kind, field)) = presentation {
        credential = credential.travelling_as(kind, field).unwrap();
        // A value that travels in the URL goes nowhere until an administrator has said it may.
        // The test that proves that refusal is its own; this one is about what is doubled.
        if kind == crate::access::policy::Kind::Query {
            credential = credential.in_the_url_allowed_by(&admin.id, now);
        }
    }
    let credential = core.add_credential(&admin.id, credential, now).unwrap();
    core.allow_credential(&admin.id, &credential.id, &user.id, &["post"], &["/v1"], None, now).unwrap();
    let request = core.ask_for_credential(&user.id, &credential.id, "post", "/v1/charge", approval::WAIT, now).unwrap();
    core.decide(&request.id, Action::ApproveCredential, &approver.id, Verdict::Once, now).unwrap();
    let token = core.use_credential(&user.id, &device.id, "work-1", &credential.id, "post", "/v1/charge", 600, now).unwrap();

    let vault = Arc::new(MemoryVault::new());
    vault.put(&vault::Entry::of(&credential), SECRET);
    let keeper: Arc<dyn Vault> = Arc::clone(&vault) as Arc<dyn Vault>;
    (Arc::new(Mutex::new(core)), keeper, realm, device.id, credential.id, token)
}

/// PROVES that a service which answers with a redirect does not get the credential sent anywhere
/// a second time: the redirect comes back as the answer it is, the place it pointed at is never
/// connected to, and the record of the request says where it actually went.
///
/// A redirect is the simplest way to turn "send this credential where we agreed" into "send this
/// credential wherever I say", and a client library that follows redirects by default would do
/// exactly that. The forwarder follows none.
///
/// DOES NOT PROVE anything about a real provider's redirects, or about a provider that is itself
/// hostile in some other way. Both servers here are this computer's own.
#[tokio::test]
async fn a_redirect_is_answered_and_never_followed() {
    let now = 32_000;
    let folder = tempfile::tempdir().unwrap();
    let (target, reached) = echo().await;
    let (moved, bounced) = redirector(target).await;
    let place = format!("http://{moved}");
    let (core, keeper, realm, device, credential, token) = brokering(folder.path(), "redirect", &place, None, now).await;

    let url = format!("{place}/v1/charge");
    let ask = Ask { token: &token, realm_id: &realm, device_id: &device, workload_id: "work-1", credential_id: &credential, method: "post", url: &url, headers: Map::new(), body: Vec::new() };
    let answer = send(&core, &keeper, &mint::Cache::new(), &ask, now).await.unwrap();

    assert_eq!(answer["status"], 302, "the redirect is handed back as the answer it is");
    assert_eq!(bounced.load(Ordering::SeqCst), 1, "the place the credential was agreed for was reached once");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "the place the redirect pointed at was never reached");
    let uses = core.lock().await.uses(None, 0).unwrap();
    assert_eq!(uses.len(), 1, "one request, not two");
    assert_eq!(uses[0].destination, place, "the record says where it actually went");
    assert_eq!(uses[0].status, Some(302));
}

/// PROVES that taking a place away while a request is already cleared and the value is being read
/// stops that request before it goes.
///
/// This is the race the last look exists for. Everything was in order when the request was
/// cleared; by the time the value is in hand it is not, and the check happens between the two.
///
/// DOES NOT PROVE that a request already on the wire is stopped. Once the bytes have left there
/// is nothing in this code that can call them back, and no deployment should be told otherwise.
#[tokio::test]
async fn a_place_taken_away_while_the_value_is_being_read_stops_the_request() {
    let now = 32_100;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;

    let core = Arc::clone(&grid.core);
    let admin = grid.admin.clone();
    let credential = grid.credential.clone();
    let place = grid.place.clone();
    *grid.vault.meanwhile.lock().unwrap() = Some(Box::new(move || {
        let mut realm = core.blocking_lock();
        if realm.destinations(&credential).unwrap().contains(&place) {
            // Another place first, because a credential always has somewhere it may be sent.
            realm.allow_destination(&admin, &credential, "https://api.acme.test", now).unwrap();
            realm.deny_destination(&admin, &credential, &place, now + 1).unwrap();
        }
    }));

    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());
    let refused = grid.send(&ask, now + 2).await.unwrap_err();
    assert!(refused.contains("Where this credential may be sent changed"), "{refused}");
    assert_eq!((grid.connections(), grid.reads()), (0, 1), "the value was read and the request still never went");
    let uses = grid.uses().await;
    assert_eq!((uses[0].outcome.as_str(), uses[0].reason.as_str()), ("refused", "rechecked"));
    assert!(uses[0].finished_at.is_some(), "the record is closed rather than left open");
}

/// PROVES the same for the realm's own outbound switch: turning egress off while the value is
/// being read stops the request between the vault and the wire.
///
/// DOES NOT PROVE, again, that anything already sent is recalled.
#[tokio::test]
async fn egress_turned_off_while_the_value_is_being_read_stops_the_request() {
    let now = 32_200;
    let grid = grid(now).await;
    let security = grid.core.lock().await.add_principal("owner", PrincipalKind::Person, "Mary", &[Role::SecurityAdmin], now).unwrap().id;
    let token = grid.once("post", "/v1/charge", now).await;

    let core = Arc::clone(&grid.core);
    *grid.vault.meanwhile.lock().unwrap() = Some(Box::new(move || {
        let mut realm = core.blocking_lock();
        if realm.realm().network.outbound {
            realm.set_egress(&security, false, &[], now).unwrap();
        }
    }));

    let url = grid.url("/v1/charge");
    let ask = grid.ask(&token, "post", &url, Vec::new());
    let refused = grid.send(&ask, now + 1).await.unwrap_err();
    assert!(refused.contains("not reaching anything outside") || refused.contains("changed between"), "{refused}");
    assert_eq!((grid.connections(), grid.reads()), (0, 1), "the value was read and nothing was sent");
}

/// PROVES that an agreement which simply runs out while the value is being read stops the
/// request, because the last look is taken at the instant the request was asked at plus the time
/// actually spent waiting. The same request, at the same instant, with nothing slow in the way,
/// goes through: that is what shows it is the time that refused it and not anything else.
///
/// The two race tests above both move a row. This one moves nothing, which is the case the last
/// look could not see before: it was asked about the instant `clear_to_send` had already been
/// asked about, so every time-based rule in it answered the same twice.
///
/// DOES NOT PROVE anything about a request already on the wire. It also does not prove the time
/// is the wall clock's: it is measured monotonically from the moment the request was cleared, so
/// a clock corrected while a prompt was open cannot move the last look backwards, and a test's
/// made-up epoch still works.
#[tokio::test]
async fn an_agreement_that_runs_out_while_the_value_is_being_read_stops_the_request() {
    let now = 32_250;
    let grid = grid(now).await;
    let url = grid.url("/v1/charge");

    // One second before the agreement runs out, with a vault that answers at once.
    let (prompt, runs_out) = grid.briefly(now).await;
    let ask = grid.ask(&prompt, "post", &url, Vec::new());
    grid.send(&ask, runs_out - 1).await.unwrap();
    assert_eq!(grid.connections(), 1);

    // The same second, with a vault that takes longer to answer than the agreement has left. A
    // locked keychain or a prompt in front of the person at the computer is what this stands for.
    let (slow, runs_out) = grid.briefly(now).await;
    *grid.vault.meanwhile.lock().unwrap() = Some(Box::new(|| std::thread::sleep(std::time::Duration::from_millis(1_500))));
    let ask = grid.ask(&slow, "post", &url, Vec::new());
    let refused = grid.send(&ask, runs_out - 1).await.unwrap_err();
    assert!(refused.contains("has run out"), "{refused}");
    assert_eq!(grid.connections(), 1, "the value was read and the second request never went");
    let uses = grid.uses().await;
    let stopped = uses.iter().find(|use_of| use_of.reason == "rechecked").expect("the refusal is in the ledger");
    assert_eq!(stopped.outcome, "refused");
    assert!(uses.iter().all(|use_of| use_of.finished_at.is_some()), "every record is closed rather than left open");
}

/// PROVES that a workload cannot set the header its credential travels in, or any header the
/// forwarder owns, by either route: they are dropped when the request is cleared, and a request
/// that carries one by the time of the last look is refused outright.
///
/// Both routes matter. Dropping is what happens to an ordinary workload whose library sets
/// `Authorization` by itself; refusing at the last look is what happens if anything between the
/// two puts one back.
///
/// DOES NOT PROVE anything about a header a provider returns, or about what a provider does with
/// the headers it is sent.
#[tokio::test]
async fn a_workload_cannot_set_the_header_its_credential_travels_in() {
    let now = 32_300;
    let grid = grid(now).await;
    let token = grid.once("post", "/v1/charge", now).await;
    let url = grid.url("/v1/charge");
    let mut ask = grid.ask(&token, "post", &url, Vec::new());
    ask.headers = json!({
        "Authorization": "Bearer the-workloads-own-guess",
        "Host": "api.evil.test",
        "X-Forwarded-For": "10.0.0.1",
        "Content-Length": "0",
        "Accept": "application/json"
    })
    .as_object()
    .unwrap()
    .clone();

    let cleared = grid.core.lock().await.clear_to_send(&ask, now).unwrap();
    let carried: Vec<String> = cleared.outgoing.headers.iter().map(|(name, _)| name.to_ascii_lowercase()).collect();
    assert_eq!(carried, vec!["accept".to_owned()], "the grid's own headers are not the workload's to set");

    for reserved in ["Authorization", "host", "x-forwarded-for", "content-length"] {
        let mut smuggled = cleared.clone();
        smuggled.outgoing.headers.push((reserved.into(), "anything".into()));
        let refused = grid.core.lock().await.still_clear(&smuggled, now).unwrap_err();
        assert!(refused.contains("which the grid itself sets"), "{reserved}: {refused}");
    }
    grid.core.lock().await.closing_use(&cleared, &Ended::Refused("test", "this request was never sent".into()), now).unwrap();
    assert_eq!(grid.connections(), 0, "nothing was sent while this was checked");
}

/// PROVES that a credential travelling in a query parameter is put on the request by the grid and
/// not by the workload: the parameter the workload set is replaced rather than added beside it,
/// so the service sees one value and it is the grid's, and the rest of the query is kept.
///
/// A doubled parameter is a real way to confuse a service into reading the attacker's copy.
///
/// DOES NOT PROVE that the value stays private. It does not: a credential that travels in a query
/// is a value in a URL, and the service's own access log and every proxy in between keep a copy.
/// The grid keeps that query out of everything it writes and cannot keep it out of theirs, and
/// the threat model says so in as many words.
#[tokio::test]
async fn a_credential_that_travels_in_a_query_is_not_doubled_by_the_workloads_own() {
    let now = 32_400;
    let folder = tempfile::tempdir().unwrap();
    let (address, seen) = echo().await;
    let place = format!("http://{address}");
    let (core, keeper, realm, device, credential, token) =
        brokering(folder.path(), "query", &place, Some((crate::access::policy::Kind::Query, "api_key")), now).await;

    // The workload sets the same parameter, with a value of its own choosing.
    let url = format!("{place}/v1/charge?api_key=the-workloads-own-guess&page=2");
    let ask = Ask { token: &token, realm_id: &realm, device_id: &device, workload_id: "work-1", credential_id: &credential, method: "post", url: &url, headers: Map::new(), body: Vec::new() };
    let answer = send(&core, &keeper, &mint::Cache::new(), &ask, now).await.unwrap();

    assert_eq!(answer["status"], 201);
    assert_eq!(seen.load(Ordering::SeqCst), 1);
    let body = answer["body"].as_str().unwrap();
    let got: Value = serde_json::from_str(body.lines().next().unwrap()).unwrap();
    let uri = got["uri"].as_str().unwrap();
    assert_eq!(uri.matches("api_key=").count(), 1, "the parameter was doubled: {uri}");
    assert!(!uri.contains("the-workloads-own-guess"), "the workload's own value reached the service: {uri}");
    assert!(uri.contains("page=2"), "the rest of the query was dropped: {uri}");

    // And no form of the value comes back, or reaches what the realm wrote.
    let printed = answer.to_string();
    for form in [SECRET.to_owned(), encoded(SECRET), serde_json::to_string(SECRET).unwrap().trim_matches('"').to_owned()] {
        assert!(!printed.contains(&form), "the answer carries a form of the value");
    }
    let uses = core.lock().await.uses(None, 0).unwrap();
    assert_eq!(uses[0].path, "/v1/charge", "the record keeps the path and never the query");
    assert!(!format!("{:?}", uses[0]).contains("api_key="), "the record kept the query");
}

// ---- Credentials this grid makes a short-lived one from ----
//
// The fourteenth family. Every server below binds 127.0.0.1: the token endpoint, the AWS STS
// endpoint and the service the request finally goes to are all this computer's own, and no
// address outside it is reached by any of this. What is proved is this grid's half of each
// exchange: what it sends, what it keeps, what it caches and what never comes back. Nothing here
// proves that any real identity provider, GitHub or AWS accepts the request shapes it builds.

/// The client secret an OAuth credential's vault entry holds. Distinct from `SECRET` so a test
/// can look for it by itself.
const CLIENT_SECRET: &str = "cs-live-9f/zz+88==abcdefghijklmnop";

/// A long-lived AWS key as the vault holds one: the identifier and the secret, separated by a
/// colon. The two halves are the published SigV4 example's, so a signature can be read by anyone.
const AWS_KEY: &str = "AKIDEXAMPLE:wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";

/// A token endpoint on this computer. It answers one access token and remembers how it was asked,
/// so a test can see what went out as well as what came back.
async fn token_endpoint(token: &'static str, lifetime: i64) -> (std::net::SocketAddr, Arc<AtomicUsize>, Arc<std::sync::Mutex<Vec<(String, String)>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let asked: Arc<std::sync::Mutex<Vec<(String, String)>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let counted = Arc::clone(&calls);
    let written = Arc::clone(&asked);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { return };
            let counted = Arc::clone(&counted);
            let written = Arc::clone(&written);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let counted = Arc::clone(&counted);
                    let written = Arc::clone(&written);
                    async move {
                        let (parts, body) = request.into_parts();
                        let body = body.collect().await.unwrap().to_bytes();
                        counted.fetch_add(1, Ordering::SeqCst);
                        let authorization = parts.headers.get("authorization").map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned()).unwrap_or_default();
                        written.lock().unwrap().push((authorization, String::from_utf8_lossy(&body).into_owned()));
                        let answer = json!({"access_token": token, "token_type": "Bearer", "expires_in": lifetime});
                        Ok::<_, std::convert::Infallible>(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "application/json")
                            .body(crate::net::full(answer.to_string()))
                            .unwrap() as Response<crate::net::Body>)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (address, calls, asked)
}

/// An AWS STS endpoint on this computer, answering AssumeRole with temporary keys that last until
/// `until`.
async fn sts_endpoint(until: i64) -> (std::net::SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&calls);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { return };
            let counted = Arc::clone(&counted);
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let counted = Arc::clone(&counted);
                    async move {
                        let _ = request.into_body().collect().await;
                        counted.fetch_add(1, Ordering::SeqCst);
                        let expires = chrono::DateTime::from_timestamp(until, 0).unwrap().format("%Y-%m-%dT%H:%M:%SZ").to_string();
                        let xml = format!(
                            "<AssumeRoleResponse><AssumeRoleResult><Credentials><AccessKeyId>ASIATEMPORARY</AccessKeyId><SecretAccessKey>temporary/secret+key</SecretAccessKey><SessionToken>temporary-session-token-0123456789</SessionToken><Expiration>{expires}</Expiration></Credentials></AssumeRoleResult></AssumeRoleResponse>"
                        );
                        Ok::<_, std::convert::Infallible>(Response::builder()
                            .status(StatusCode::OK)
                            .header("content-type", "text/xml")
                            .body(crate::net::full(xml))
                            .unwrap() as Response<crate::net::Body>)
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (address, calls)
}

/// A realm holding one credential of a chosen kind, with its value in a vault in memory.
struct Minting {
    core: Arc<Mutex<Core>>,
    vault: Arc<MemoryVault>,
    keeper: Arc<dyn Vault>,
    cache: mint::Cache,
    realm: String,
    admin: String,
    approver: String,
    user: String,
    device: String,
    credential: String,
    place: String,
    folder: tempfile::TempDir,
}

/// `settings` is empty for the kinds that send the value as it is, and holds what the kind needs
/// for the three that mint. Nothing in it is a value.
async fn holding(place: &str, presentation: Kind, settings: &[(&str, &str)], value: &str, now: i64) -> Minting {
    let folder = tempfile::tempdir().unwrap();
    let mut core = Core::create(&folder.path().join("minting.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::CredentialApprover], now).unwrap();
    let user = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User], now).unwrap();
    let (device, _) = core.enrol_device(&user.id, "Ada's laptop", "windows", now).unwrap();
    let realm = core.realm().id.clone();
    let credential =
        Credential::new(&realm, "Billing", Secret::ServiceAccount, "billing-key", &fingerprint_of(value), place, &admin.id, now).unwrap().narrowed_to(&["post"], &["/v1"], Some(4_096));
    let credential = if presentation.mints() {
        credential.minting_as(presentation, settings).unwrap()
    } else {
        // Bearer takes no field; the other three name the header, parameter or username.
        credential.travelling_as(presentation, if presentation == Kind::Bearer { "" } else { "api_key" }).unwrap()
    };
    let credential = core.add_credential(&admin.id, credential, now).unwrap();
    core.allow_credential(&admin.id, &credential.id, &user.id, &["post"], &["/v1"], None, now).unwrap();

    let vault = Arc::new(MemoryVault::new());
    vault.put(&vault::Entry::of(&credential), value);
    let keeper: Arc<dyn Vault> = Arc::clone(&vault) as Arc<dyn Vault>;
    Minting {
        core: Arc::new(Mutex::new(core)),
        vault,
        keeper,
        cache: mint::Cache::new(),
        realm,
        admin: admin.id,
        approver: approver.id,
        user: user.id,
        device: device.id,
        credential: credential.id,
        place: place.to_owned(),
        folder,
    }
}

impl Minting {
    async fn once(&self, path: &str, now: i64) -> String {
        let mut core = self.core.lock().await;
        let request = core.ask_for_credential(&self.user, &self.credential, "post", path, approval::WAIT, now).unwrap();
        core.decide(&request.id, Action::ApproveCredential, &self.approver, Verdict::Once, now).unwrap();
        core.use_credential(&self.user, &self.device, "work-1", &self.credential, "post", path, 600, now).unwrap()
    }

    fn ask<'a>(&'a self, token: &'a str, url: &'a str) -> Ask<'a> {
        Ask {
            token,
            realm_id: &self.realm,
            device_id: &self.device,
            workload_id: "work-1",
            credential_id: &self.credential,
            method: "post",
            url,
            headers: Map::new(),
            body: Vec::new(),
        }
    }

    /// One whole request: ask, have somebody agree, and send.
    async fn request(&self, path: &str, now: i64) -> Result<Value, String> {
        let token = self.once(path, now).await;
        let url = format!("{}{path}", self.place);
        let ask = self.ask(&token, &url);
        send(&self.core, &self.keeper, &self.cache, &ask, now).await
    }

    fn reads(&self) -> usize {
        self.vault.read_count()
    }
}

/// What the service saw, out of the answer the agent was given.
fn as_seen(answer: &Value) -> Value {
    serde_json::from_str(answer["body"].as_str().unwrap().split('\n').next().unwrap()).unwrap()
}

/// Settings as the builders take them, from a list that owns its strings.
fn pairs<'a>(settings: &'a [(&'static str, String)]) -> Vec<(&'static str, &'a str)> {
    settings.iter().map(|(key, value)| (*key, value.as_str())).collect()
}

/// PROVES that an OAuth 2 client credential is brokered the way the shipped Access Grid brokers
/// one: the client secret goes to the token endpoint and nowhere else, the access token the
/// endpoint answers is what reaches the service, the service's echo of it is hidden, and the
/// token is made once and reused until the credential moves on.
///
/// DOES NOT PROVE that any real identity provider accepts this request shape. The token endpoint
/// here is this computer's own and it says yes to anything.
#[tokio::test]
async fn an_oauth_credential_buys_a_token_and_sends_that_instead() {
    let now = 33_000;
    let (api, reached) = echo().await;
    let (tokens, minted, asked) = token_endpoint("access-token-aaaaaaaaaaaaaaaa", 3_600).await;
    let settings = [("tokenUrl", format!("http://{tokens}/oauth/token")), ("clientId", "example-client".to_owned()), ("scope", "billing.write".to_owned())];
    let grid = holding(&format!("http://{api}"), Kind::Oauth, &pairs(&settings), CLIENT_SECRET, now).await;

    let answer = grid.request("/v1/charge", now).await.unwrap();
    assert_eq!(answer["status"], 201);
    assert_eq!(as_seen(&answer)["authorization"], "Bearer [hidden by Access Grid]", "the service got the minted token, and its echo of it is hidden");
    let written = answer.to_string();
    assert!(!written.contains(CLIENT_SECRET) && !written.contains("access-token-aaaa"), "neither the client secret nor the token comes back: {written}");

    // What the token endpoint was asked. The client secret travelled there and nowhere else.
    assert_eq!(minted.load(Ordering::SeqCst), 1);
    let (authorization, body) = asked.lock().unwrap()[0].clone();
    let pair = String::from_utf8(base64::Engine::decode(&base64::engine::general_purpose::STANDARD, authorization.trim_start_matches("Basic ")).unwrap()).unwrap();
    assert_eq!(pair, format!("example-client:{}", encoded(CLIENT_SECRET)), "the client secret goes under basic authentication, percent-encoded");
    assert!(body.contains("grant_type=client_credentials") && body.contains("scope=billing.write"), "{body}");
    assert!(!body.contains(CLIENT_SECRET), "and not in the form as well");

    // A second request reuses the token: the endpoint is asked once, the vault read twice.
    assert_eq!(grid.request("/v1/charge", now + 1).await.unwrap()["status"], 201);
    assert_eq!((minted.load(Ordering::SeqCst), grid.reads(), grid.cache.held()), (1, 2, 1));
    assert_eq!(reached.load(Ordering::SeqCst), 2);

    // A rotation makes it mint again, because the key a token is held under carries the
    // generation and the version of the entry it came from.
    {
        let mut core = grid.core.lock().await;
        core.rotate_credential(&grid.admin, &grid.credential, &fingerprint_of("cs-live-rotated-2222222222222222"), now + 2).unwrap();
        let rotated = core.credential(&grid.credential).unwrap().unwrap();
        grid.vault.put(&vault::Entry::of(&rotated), "cs-live-rotated-2222222222222222");
    }
    assert_eq!(grid.request("/v1/charge", now + 3).await.unwrap()["status"], 201);
    assert_eq!(minted.load(Ordering::SeqCst), 2, "the token made from the old value is never sent after a rotation");

    // And so does a token endpoint moved by an administrator: neither the generation nor the
    // vault version changes when settings do, so what a token was bought with is in the key too.
    {
        let moved = format!("http://{tokens}/oauth/elsewhere");
        let mut core = grid.core.lock().await;
        core.set_credential_settings(&grid.admin, &grid.credential, &[("tokenUrl", &moved), ("clientId", "example-client"), ("scope", "billing.write")], now + 4).unwrap();
    }
    assert_eq!(grid.request("/v1/charge", now + 5).await.unwrap()["status"], 201);
    assert_eq!(minted.load(Ordering::SeqCst), 3, "a token bought from the old endpoint is not a token for the new one");
    assert_eq!(asked.lock().unwrap().len(), 3);
    drop(grid.folder);
}

/// PROVES that nothing about an OAuth credential reaches the realm's database, its journal, its
/// history or a backup: not the client secret in the vault, and not the short-lived token this
/// grid made from it, which is a secret with an expiry and is held in memory alone.
#[tokio::test]
async fn neither_the_client_secret_nor_the_token_it_bought_is_ever_written_down() {
    let now = 33_100;
    let (api, _) = echo().await;
    let (tokens, _, _) = token_endpoint("access-token-bbbbbbbbbbbbbbbb", 3_600).await;
    let settings = [("tokenUrl", format!("http://{tokens}/oauth/token")), ("clientId", "example-client".to_owned())];
    let grid = holding(&format!("http://{api}"), Kind::Oauth, &pairs(&settings), CLIENT_SECRET, now).await;
    grid.request("/v1/charge", now).await.unwrap();

    let (path, taken) = {
        let core = grid.core.lock().await;
        for event in core.snapshot().unwrap().audit.events {
            assert!(!event.reason.contains(CLIENT_SECRET) && !event.reason.contains("access-token-"), "{}", event.reason);
        }
        (core.path().to_owned(), core.backup(now).unwrap())
    };
    let backup = serde_json::to_string(&taken).unwrap();
    assert!(!backup.contains(CLIENT_SECRET) && !backup.contains("access-token-"), "a backup carries neither");
    assert!(backup.contains("example-client"), "it does carry the settings, which are names and addresses");

    Arc::try_unwrap(grid.core).map_err(|_| "the realm is held somewhere else").unwrap().into_inner().close().unwrap();
    let mut bytes = std::fs::read(&path).unwrap();
    let journal = std::path::PathBuf::from(format!("{}-wal", path.display()));
    if journal.exists() {
        bytes.extend(std::fs::read(&journal).unwrap());
    }
    for form in [CLIENT_SECRET.to_owned(), encoded(CLIENT_SECRET), "access-token-bbbbbbbbbbbbbbbb".to_owned()] {
        assert!(!holds(&bytes, form.as_bytes()), "a form of a value reached the grid's database: {form}");
    }
    assert!(holds(&bytes, b"billing-key"), "only the name of the vault entry that holds it");
    drop(grid.folder);
}

/// PROVES that an AWS credential with no role signs the request in place: the request carries a
/// SigV4 authorization header naming the access key and the region, the secret half of the key
/// never leaves this process, nothing is fetched and nothing is cached.
///
/// DOES NOT PROVE that AWS accepts the signature. `sigv4::sign` is the shipped signer and its own
/// tests check it against the published test suite; what is checked here is that the broker calls
/// it with this credential's keys, region and service.
#[tokio::test]
async fn an_aws_credential_without_a_role_signs_the_request_with_the_key_in_place() {
    let now = 33_200;
    let (api, reached) = echo().await;
    let grid = holding(&format!("http://{api}"), Kind::Aws, &[("region", "us-east-1"), ("service", "execute-api")], AWS_KEY, now).await;

    let answer = grid.request("/v1/charge", now).await.unwrap();
    assert_eq!(answer["status"], 201);
    let seen = as_seen(&answer);
    let authorization = seen["authorization"].as_str().unwrap();
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"), "{authorization}");
    assert!(authorization.contains("/us-east-1/execute-api/aws4_request"), "{authorization}");
    assert!(seen["amzDate"].as_str().unwrap().ends_with('Z'), "the request carries the moment it was signed at");
    assert_eq!(seen["amzToken"], "", "a long-lived key carries no session token");
    assert!(!answer.to_string().contains("wJalrXUtnFEMI"), "the secret half of the key is never on the wire");
    assert_eq!((reached.load(Ordering::SeqCst), grid.cache.held()), (1, 0), "nothing was fetched and nothing is held");
    drop(grid.folder);
}

/// PROVES that an AWS credential naming a role buys temporary keys from STS first, signs with
/// those, and holds them for that person alone until they near their end.
///
/// DOES NOT PROVE anything about AWS. The STS endpoint here is this computer's own.
#[tokio::test]
async fn an_aws_credential_with_a_role_buys_temporary_keys_and_signs_with_those() {
    let now = 33_300;
    let (api, reached) = echo().await;
    let (sts, called) = sts_endpoint(crate::now() + 3_600).await;
    let settings = [
        ("region", "eu-west-1".to_owned()),
        ("service", "execute-api".to_owned()),
        ("roleArn", "arn:aws:iam::123456789012:role/billing".to_owned()),
        ("stsUrl", format!("http://{sts}/")),
    ];
    let grid = holding(&format!("http://{api}"), Kind::Aws, &pairs(&settings), AWS_KEY, now).await;

    let answer = grid.request("/v1/charge", crate::now()).await.unwrap();
    let seen = as_seen(&answer);
    let authorization = seen["authorization"].as_str().unwrap();
    assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=ASIATEMPORARY/"), "the temporary key signs it, not the long-lived one: {authorization}");
    assert!(!authorization.contains("AKIDEXAMPLE"), "{authorization}");
    assert_eq!(seen["amzToken"], "[hidden by Access Grid]", "the session token goes out and its echo is hidden");
    let written = answer.to_string();
    for form in ["wJalrXUtnFEMI", "temporary/secret+key", "temporary-session-token"] {
        assert!(!written.contains(form), "{form} came back: {written}");
    }
    assert_eq!((called.load(Ordering::SeqCst), reached.load(Ordering::SeqCst)), (1, 1));

    // The same person again reuses them; the keys are held under their name, so they are never
    // handed to somebody else.
    assert_eq!(grid.request("/v1/charge", crate::now()).await.unwrap()["status"], 201);
    assert_eq!((called.load(Ordering::SeqCst), grid.cache.held()), (1, 1));
    grid.cache.forget(&grid.credential);
    assert_eq!(grid.cache.held(), 0, "a credential that changed or went takes its tokens with it");
    assert_eq!(grid.request("/v1/charge", crate::now()).await.unwrap()["status"], 201);
    assert_eq!(called.load(Ordering::SeqCst), 2);
    drop(grid.folder);
}

/// PROVES that a GitHub App credential whose vault entry does not hold a private key is refused
/// before anything is sent, that the refusal says what is wrong without quoting what the entry
/// held, and that neither GitHub nor the service is reached.
///
/// DOES NOT PROVE that a real GitHub App assertion is signed and accepted. Signing one needs an
/// RSA private key and this repository holds none, for the same reason the shipped Access Grid's
/// own tests stop at this line. What is proved here is the wiring either side of it.
#[tokio::test]
async fn a_github_app_credential_is_refused_when_the_vault_holds_no_key() {
    let now = 33_400;
    let (api, reached) = echo().await;
    let (github, asked, _) = token_endpoint("installation-token", 3_600).await;
    let settings = [("appId", "42".to_owned()), ("installationId", "99".to_owned()), ("apiUrl", format!("http://{github}"))];
    let grid = holding(&format!("http://{api}"), Kind::GithubApp, &pairs(&settings), "not-a-private-key", now).await;

    let refused = grid.request("/v1/charge", now).await.unwrap_err();
    assert!(refused.contains("not a PEM private key"), "{refused}");
    assert!(!refused.contains("not-a-private-key"), "and it does not quote what the vault held: {refused}");
    assert_eq!((asked.load(Ordering::SeqCst), reached.load(Ordering::SeqCst), grid.cache.held()), (0, 0, 0));

    // The record of the request says it was refused, in one word, and the event says the sentence.
    let core = grid.core.lock().await;
    let sent = core.uses(None, 0).unwrap();
    assert_eq!((sent[0].outcome.as_str(), sent[0].reason.as_str()), ("refused", "minting"));
    assert!(core.snapshot().unwrap().audit.events.iter().any(|event| event.reason.contains("not a PEM private key")));
    drop(core);
    drop(grid.folder);
}

/// PROVES that where a token is made is bound by the realm's own outbound rules, and that the
/// refusal happens before any value is read.
#[tokio::test]
async fn a_token_endpoint_the_grid_may_not_reach_refuses_before_the_vault_is_opened() {
    let now = 33_500;
    let (api, reached) = echo().await;
    let (tokens, minted, _) = token_endpoint("access-token-cccccccccccccccc", 3_600).await;
    let settings = [("tokenUrl", format!("http://{tokens}/oauth/token")), ("clientId", "example-client".to_owned())];
    let place = format!("http://{api}");
    let grid = holding(&place, Kind::Oauth, &pairs(&settings), CLIENT_SECRET, now).await;

    // The service may be reached; the token endpoint may not.
    grid.core.lock().await.set_egress("owner", true, &[&place], now).unwrap();
    let refused = grid.request("/v1/charge", now).await.unwrap_err();
    assert!(refused.contains("does not reach") && refused.contains("short-lived token is made"), "{refused}");
    assert_eq!((grid.reads(), minted.load(Ordering::SeqCst), reached.load(Ordering::SeqCst)), (0, 0, 0));

    // Allowed, it works.
    let endpoint = format!("http://{tokens}");
    grid.core.lock().await.set_egress("owner", true, &[&place, &endpoint], now).unwrap();
    assert_eq!(grid.request("/v1/charge", now).await.unwrap()["status"], 201);
    assert_eq!(minted.load(Ordering::SeqCst), 1);
    drop(grid.folder);
}

/// PROVES that a credential whose value would travel in the URL goes nowhere until an
/// administrator has said it may, that the refusal says why, that allowing it is recorded with
/// their name on it, and that taking it back stops the next request.
#[tokio::test]
async fn a_value_travels_in_the_url_only_when_an_administrator_said_it_may() {
    let now = 33_600;
    let (api, reached) = echo().await;
    let grid = holding(&format!("http://{api}"), Kind::Query, &[], SECRET, now).await;

    // Nobody is even handed a permission for it, and nothing is read or reached.
    let refused = {
        let mut core = grid.core.lock().await;
        core.use_credential(&grid.user, &grid.device, "work-1", &grid.credential, "post", "/v1/charge", 600, now).unwrap_err()
    };
    assert!(refused.contains("travel in the URL") && refused.contains("access log"), "{refused}");
    assert_eq!((grid.reads(), reached.load(Ordering::SeqCst)), (0, 0));

    // Allowed by name, it sends, and the value is in the query and nowhere else.
    grid.core.lock().await.allow_query_credential(&grid.admin, &grid.credential, now).unwrap();
    let answer = grid.request("/v1/charge", now).await.unwrap();
    assert_eq!(answer["status"], 201);
    let seen = as_seen(&answer);
    assert!(seen["uri"].as_str().unwrap().contains("api_key=[hidden by Access Grid]"), "{}", seen["uri"]);
    {
        let core = grid.core.lock().await;
        let credential = core.credential(&grid.credential).unwrap().unwrap();
        assert_eq!(credential.query_allowed_by.as_deref(), Some(grid.admin.as_str()));
        assert_eq!(credential.query_allowed_at, Some(now));
        assert!(core.snapshot().unwrap().audit.events.iter().any(|event| event.action == "credential.in the url allowed" && event.reason.contains("access log")));
        // The record of the request has no query in it, because the value travelled in one.
        assert!(core.uses(None, 0).unwrap().iter().all(|used| !used.path.contains('?')));
    }

    // Taken back, nobody is handed another permission, and a permission already in somebody's
    // hand is refused at the moment it would be used.
    let standing = grid.once("/v1/charge", now + 1).await;
    let mut core = grid.core.lock().await;
    core.deny_query_credential(&grid.admin, &grid.credential, now + 2).unwrap();
    let refused = core.use_credential(&grid.user, &grid.device, "work-1", &grid.credential, "post", "/v1/charge", 600, now + 3).unwrap_err();
    assert!(refused.contains("travel in the URL"), "{refused}");
    drop(core);
    let url = format!("{}/v1/charge", grid.place);
    let ask = grid.ask(&standing, &url);
    let refused = send(&grid.core, &grid.keeper, &grid.cache, &ask, now + 3).await.unwrap_err();
    assert!(refused.contains("travel in the URL"), "{refused}");
    assert_eq!(reached.load(Ordering::SeqCst), 1, "nothing was sent after it was taken back");
    drop(grid.folder);
}

/// PROVES that taking back the permission to travel in the URL while the vault is open refuses
/// the request at the last look, with no connection made.
#[tokio::test]
async fn permission_to_travel_in_the_url_taken_back_mid_flight_stops_the_send() {
    let now = 33_700;
    let (api, reached) = echo().await;
    let grid = holding(&format!("http://{api}"), Kind::Query, &[], SECRET, now).await;
    grid.core.lock().await.allow_query_credential(&grid.admin, &grid.credential, now).unwrap();
    let token = grid.once("/v1/charge", now).await;

    // Taken back on the thread the vault read is on, so it happens after the request was cleared
    // and before the last look.
    let core = Arc::clone(&grid.core);
    let credential = grid.credential.clone();
    let admin = grid.admin.clone();
    *grid.vault.meanwhile.lock().unwrap() = Some(Box::new(move || {
        let core = Arc::clone(&core);
        let credential = credential.clone();
        let admin = admin.clone();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                core.lock().await.deny_query_credential(&admin, &credential, now).unwrap();
            });
        })
        .join()
        .unwrap();
    }));

    let url = format!("{}/v1/charge", grid.place);
    let ask = grid.ask(&token, &url);
    let refused = send(&grid.core, &grid.keeper, &grid.cache, &ask, now).await.unwrap_err();
    assert!(refused.contains("travel in the URL"), "{refused}");
    assert_eq!((grid.reads(), reached.load(Ordering::SeqCst)), (1, 0), "the value was read and nothing was sent");
    drop(grid.folder);
}

/// PROVES that a token endpoint moved while the vault was open refuses the request at the last
/// look, because the last look compares how the credential travels against how it travelled when
/// the request was cleared.
#[tokio::test]
async fn a_token_endpoint_changed_mid_flight_stops_the_send() {
    let now = 33_800;
    let (api, reached) = echo().await;
    let (tokens, minted, _) = token_endpoint("access-token-dddddddddddddddd", 3_600).await;
    let settings = [("tokenUrl", format!("http://{tokens}/oauth/token")), ("clientId", "example-client".to_owned())];
    let grid = holding(&format!("http://{api}"), Kind::Oauth, &pairs(&settings), CLIENT_SECRET, now).await;
    let token = grid.once("/v1/charge", now).await;

    let core = Arc::clone(&grid.core);
    let credential = grid.credential.clone();
    let admin = grid.admin.clone();
    let moved = format!("http://{tokens}/oauth/other");
    *grid.vault.meanwhile.lock().unwrap() = Some(Box::new(move || {
        let core = Arc::clone(&core);
        let credential = credential.clone();
        let admin = admin.clone();
        let moved = moved.clone();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                core.lock().await.set_credential_settings(&admin, &credential, &[("tokenUrl", &moved), ("clientId", "example-client")], now).unwrap();
            });
        })
        .join()
        .unwrap();
    }));

    let url = format!("{}/v1/charge", grid.place);
    let ask = grid.ask(&token, &url);
    let refused = send(&grid.core, &grid.keeper, &grid.cache, &ask, now).await.unwrap_err();
    assert!(refused.contains("How this credential travels changed"), "{refused}");
    assert_eq!(reached.load(Ordering::SeqCst), 0, "nothing was sent");
    assert_eq!(minted.load(Ordering::SeqCst), 1, "the token was bought before the last look, and then thrown away");
    drop(grid.folder);
}

/// PROVES what a credential of each kind has to say about itself before this grid will hold it,
/// and that a settings map is a map of names and addresses rather than a place to put a value.
#[test]
fn a_minting_credential_says_what_it_needs_and_none_of_it_is_a_value() {
    let now = 34_000;
    let realm = "realm-1";
    let print = fingerprint_of(SECRET);
    let built = || Credential::new(realm, "Billing", Secret::ServiceAccount, "billing-key", &print, "https://api.acme.test", "owner", now).unwrap();
    let token_url = "https://login.acme.test/oauth2/token";

    // Every kind that mints says what it is missing, by name.
    assert!(built().minting_as(Kind::Oauth, &[("clientId", "a")]).unwrap_err().contains("no tokenUrl"));
    assert!(built().minting_as(Kind::GithubApp, &[("installationId", "9")]).unwrap_err().contains("no appId"));
    assert!(built().minting_as(Kind::Aws, &[]).unwrap_err().contains("no region"));
    assert!(built().minting_as(Kind::Bearer, &[]).unwrap_err().contains("travelling_as"));
    assert!(built().travelling_as(Kind::Oauth, "").unwrap_err().contains("minting_as"));

    // What each one takes, and what it does not.
    let oauth = built().minting_as(Kind::Oauth, &[("tokenUrl", token_url), ("clientId", "acme"), ("auth", "body")]).unwrap();
    assert!(oauth.ready_to_send().is_ok());
    assert!(oauth.field.is_empty(), "a credential that mints travels in the authorization header and names no field");
    assert!(built().minting_as(Kind::Oauth, &[("tokenUrl", token_url), ("clientId", "acme"), ("clientSecret", "shh")]).unwrap_err().contains("not a setting"));
    assert!(built().minting_as(Kind::Oauth, &[("tokenUrl", token_url), ("clientId", "acme"), ("auth", "header")]).unwrap_err().contains("basic"));
    assert!(built().minting_as(Kind::Oauth, &[("tokenUrl", "http://login.acme.test/oauth2/token"), ("clientId", "acme")]).unwrap_err().contains("https://"));
    assert!(built().minting_as(Kind::Oauth, &[("tokenUrl", "HTTPS://LOGIN.ACME.TEST:443/oauth2/token"), ("clientId", "acme")]).unwrap_err().contains("written the way this grid writes an address"));
    assert!(built().minting_as(Kind::GithubApp, &[("appId", "42"), ("installationId", "9"), ("apiUrl", "https://github.acme.test/api/v3/")]).unwrap_err().contains("https://github.acme.test/api/v3"));
    assert!(built().minting_as(Kind::GithubApp, &[("appId", "four"), ("installationId", "9")]).unwrap_err().contains("the number GitHub gives it"));
    assert!(built().minting_as(Kind::Aws, &[("region", "US-EAST-1")]).unwrap_err().contains("lower-case"));
    assert!(built().minting_as(Kind::Aws, &[("region", "us-east-1"), ("roleArn", "billing")]).unwrap_err().contains("begins arn:"));
    assert!(built().minting_as(Kind::Aws, &[("region", "us-east-1"), ("sessionSeconds", "60")]).unwrap_err().contains("between 900 and 43200"));

    // A value cannot be hidden in a setting, whichever setting it is.
    for secret in ["sk-live-0123456789abcdef", "-----BEGIN PRIVATE KEY-----", "password=hunter2"] {
        let refused = built().minting_as(Kind::Aws, &[("region", "us-east-1"), ("externalId", secret)]).unwrap_err();
        assert!(refused.contains("not the secret itself"), "{secret}: {refused}");
    }

    // And a credential that sends its value as it is holds no settings at all.
    let mut plain = built();
    plain.settings.insert("tokenUrl".into(), token_url.into());
    assert!(plain.is_a_reference().unwrap_err().contains("takes no settings"));
    assert!(checked_settings(Kind::Bearer, &std::collections::BTreeMap::new()).is_ok());

    // A query credential with nobody's name against it is refused, and the pair moves together.
    let query = built().travelling_as(Kind::Query, "api_key").unwrap();
    assert!(query.ready_to_send().unwrap_err().contains("access log"));
    assert!(query.clone().in_the_url_allowed_by("owner", now).ready_to_send().is_ok());
    let mut half = query.clone();
    half.query_allowed_by = Some("owner".into());
    assert!(half.is_a_reference().unwrap_err().contains("who allowed it and when"));

    // How a credential travels is one digest, and every part of it moves it.
    assert_eq!(oauth.shape(), oauth.clone().shape());
    assert_ne!(oauth.shape(), built().minting_as(Kind::Oauth, &[("tokenUrl", token_url), ("clientId", "other"), ("auth", "body")]).unwrap().shape());
    assert_ne!(query.shape(), query.clone().in_the_url_allowed_by("owner", now).shape());
}

/// PROVES that a token with less life left in it than the margin is used for the one request it
/// was made for and not held, so nothing is ever handed out that could lapse in flight.
#[tokio::test]
async fn a_token_with_almost_nothing_left_is_used_once_and_not_kept() {
    let now = 33_900;
    let (api, reached) = echo().await;
    // A token endpoint that answers a token with a minute on it, where the margin is five.
    let (tokens, minted, _) = token_endpoint("access-token-ffffffffffffffff", 60).await;
    let settings = [("tokenUrl", format!("http://{tokens}/oauth/token")), ("clientId", "example-client".to_owned())];
    let grid = holding(&format!("http://{api}"), Kind::Oauth, &pairs(&settings), CLIENT_SECRET, now).await;

    assert_eq!(grid.request("/v1/charge", now).await.unwrap()["status"], 201);
    assert_eq!(grid.cache.held(), 0, "nothing worth reusing was kept");
    assert_eq!(grid.request("/v1/charge", now + 1).await.unwrap()["status"], 201);
    assert_eq!((minted.load(Ordering::SeqCst), reached.load(Ordering::SeqCst)), (2, 2), "so the next request buys its own");
    drop(grid.folder);
}

/// PROVES that a token this grid made is overwritten rather than merely let go, and that nothing
/// of one can be printed by accident.
#[test]
fn a_minted_token_is_overwritten_when_it_is_let_go() {
    use crate::access::forward::{Auth, Prepared};

    let mut prepared = Prepared::bearer("access-token-eeeeeeee", CLIENT_SECRET);
    mint::wipe_prepared(&mut prepared);
    match &prepared.auth {
        Auth::Header(name, value) => assert_eq!((name.as_str(), value.as_str()), ("authorization", "")),
        _ => panic!("a bearer token travels in a header"),
    }
    assert!(prepared.secrets.iter().all(String::is_empty));

    let mut signed = Prepared {
        secrets: vec!["wJalrXUtnFEMI".to_owned()],
        auth: Auth::Aws {
            keys: crate::access::sigv4::Keys { access_key: "AKIDEXAMPLE".into(), secret_key: "wJalrXUtnFEMI".into(), session_token: Some("session".into()) },
            region: "us-east-1".into(),
            service: None,
        },
    };
    mint::wipe_prepared(&mut signed);
    match &signed.auth {
        Auth::Aws { keys, .. } => {
            assert_eq!((keys.access_key.as_str(), keys.secret_key.as_str()), ("AKIDEXAMPLE", ""), "the identifier is not a secret; the key is");
            assert_eq!(keys.session_token.as_deref(), Some(""));
        }
        _ => panic!("AWS keys travel as AWS keys"),
    }
    assert_eq!(format!("{:?}", mint::Cache::new()), "Cache(0 held, hidden)");
}

/// PROVES that an administrator can read which credential destinations the upgrade to version 5
/// left behind, and that the report tells one this grid would refuse today from one an
/// administrator took away afterwards.
#[test]
fn the_destinations_the_upgrade_could_not_carry_can_be_read_by_name() {
    let folder = tempfile::tempdir().unwrap();
    let now = 34_100;
    let path = folder.path().join("realm.db");
    let mut core = Core::create(&path, "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap();
    let realm = core.realm().id.clone();
    let kept = Credential::new(&realm, "Billing", Secret::ApiKey, "billing-key", &fingerprint_of(SECRET), "https://api.acme.test", &admin.id, now).unwrap();
    let kept = core.add_credential(&admin.id, kept, now).unwrap();
    let moved = Credential::new(&realm, "Payroll", Secret::ApiKey, "payroll-key", &fingerprint_of("two"), "https://payroll.acme.test", &admin.id, now).unwrap();
    let moved = core.add_credential(&admin.id, moved, now).unwrap();
    assert!(core.destinations_left_out().unwrap().is_empty(), "both credentials are whole");

    // And now the thing this report exists for: a destination a version 4 build accepted, written
    // into the row the way that build wrote one, which version 5's backfill then could not carry.
    // The upgrade is run again by opening the realm with this build.
    core.close().unwrap();
    let mut store = store::Store::open(&path).unwrap();
    for version in (5..=crate::core::store::SCHEMA_VERSION).rev() {
        store.roll_back(version).unwrap();
    }
    store.write_destination_as_version_four_did(&kept.id, "https://api.acme.test/?token=guess").unwrap();
    drop(store);

    let mut core = Core::open(&path, &key()).unwrap();
    // And one place taken away by an administrator afterwards, which the report has to tell from
    // a place the upgrade could not carry.
    core.allow_destination(&admin.id, &moved.id, "https://payroll.eu.acme.test", now).unwrap();
    core.deny_destination(&admin.id, &moved.id, "https://payroll.acme.test", now).unwrap();

    let left_out = core.destinations_left_out().unwrap();
    assert_eq!(left_out.len(), 2);
    let refused = left_out.iter().find(|row| row.credential_id == kept.id).unwrap();
    assert_eq!(refused.credential_name, "Billing");
    assert_eq!(refused.destination, "https://api.acme.test/?token=guess");
    assert!(refused.why.contains("upgrade to version 5 could not carry it") && refused.why.contains("?query"), "{}", refused.why);
    let by_hand = left_out.iter().find(|row| row.credential_id == moved.id).unwrap();
    assert!(by_hand.why.contains("taken away after the upgrade"), "{}", by_hand.why);
    // No value and no secret is in the report; it is names and addresses.
    assert!(!serde_json::to_string(&left_out).unwrap().contains(SECRET));
    drop(folder);
}
