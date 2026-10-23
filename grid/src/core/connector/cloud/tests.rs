//! The read-only cloud adapters, against servers on this computer.
//!
//! Each fixture answers the way the provider's published API documents and records every call,
//! including the authorisation header, so three things can be asserted: the request shape is the
//! one the provider wants, the credential is presented the way the provider wants, and the value
//! itself goes nowhere but the provider's own sign-in when it goes anywhere at all.
//!
//! The AWS fixtures do more than record. They recompute the Signature Version 4 signature from
//! the canonical request and refuse a signature that does not match, so a signing mistake is a
//! failed test rather than a passing one. A wrong signature is a wrong signature whether the far
//! end is Amazon or a server in this file.
//!
//! What none of this proves is that Amazon, Microsoft, a Kubernetes cluster or an OpenStack cloud
//! would answer this way. There is no account here, no vendor library and no credential.
use super::super::wire::{Keyed, Keys, Opened, Present};
use super::super::{Change, Connector, Request, Subject, Ticket, Trouble};
use super::*;
use crate::core::capability::{Authority, Claims};
use crate::core::realm::Capability;
use serde_json::json;
use std::sync::{Arc, Mutex};

fn key() -> String {
    "d".repeat(64)
}

fn permission(credential_id: &str, destination: &str, now: i64) -> Ticket {
    let claims = Claims::new("realm-1", Capability::Credentials, "principal-ada", "device-ada", "work-1", credential_id, now, 3_600).bound_to(destination, "POST", "/", 1 << 20);
    Ticket::read(&Authority::new("realm-1", &key()).mint(&claims).unwrap(), now).unwrap()
}

fn ada() -> Subject {
    Subject::new("ada@acme.example", "Ada").unwrap()
}

/// This computer's vault, which answers for one credential and for nothing else. The name in the
/// permission is what chooses the value, exactly as it does for the four connectors that ship.
struct Vault {
    credential_id: &'static str,
    fields: serde_json::Value,
    version: u32,
}

impl Keys for Vault {
    fn open(&self, credential_id: &str) -> Result<Opened, String> {
        if credential_id == self.credential_id {
            Ok(Opened { fields: self.fields.clone(), version: self.version })
        } else {
            Err(format!("No credential called {credential_id} is in this computer's vault"))
        }
    }
}

/// What one call to a fixture looked like.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn header(&self, name: &str) -> String {
        self.headers.iter().find(|(had, _)| had == name).map(|(_, value)| value.clone()).unwrap_or_default()
    }
}

type Calls = Arc<Mutex<Vec<Seen>>>;

/// A provider's API on loopback. Unlike the JSON-only mock the desktop connectors use, this can
/// answer with any content type, because two of these providers answer in XML.
async fn provider(reply: impl Fn(&Seen) -> (u16, &'static str, String) + Send + Sync + 'static) -> (String, Calls) {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request as HyperRequest, Response};
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls: Calls = Arc::default();
    let reply = Arc::new(reply);
    let recorder = calls.clone();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            let (reply, recorder) = (reply.clone(), recorder.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: HyperRequest<Incoming>| {
                    let (reply, recorder) = (reply.clone(), recorder.clone());
                    async move {
                        let method = request.method().to_string();
                        let path = request.uri().path_and_query().map(|path| path.to_string()).unwrap_or_default();
                        let headers: Vec<(String, String)> =
                            request.headers().iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))).collect();
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let seen = Seen { method, path, headers, body: String::from_utf8_lossy(&bytes).into_owned() };
                        recorder.lock().unwrap().push(seen.clone());
                        let (status, content_type, body) = reply(&seen);
                        Ok::<_, std::convert::Infallible>(Response::builder().status(status).header("content-type", content_type).body(Full::new(bytes::Bytes::from(body))).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (format!("http://{address}"), calls)
}

/// Recomputes the signature the request carries and says whether it is the one the key makes.
///
/// This is the half that makes an AWS fixture worth anything: it signs the canonical request
/// itself, from the headers that went out, and compares. A connector that signed the wrong path,
/// the wrong query order or the wrong payload hash fails here.
fn signature_matches(seen: &Seen, host: &str, access_key: &str, secret_key: &str) -> bool {
    let authorization = seen.header("authorization");
    let Some(signed) = authorization.split("SignedHeaders=").nth(1).and_then(|rest| rest.split(',').next()) else { return false };
    let Some(scope) = authorization.split("Credential=").nth(1).and_then(|rest| rest.split(',').next()) else { return false };
    let mut scope = scope.split('/');
    if scope.next() != Some(access_key) {
        return false;
    }
    let (_date, region, service) = (scope.next().unwrap_or_default(), scope.next().unwrap_or_default().to_owned(), scope.next().unwrap_or_default().to_owned());
    let amz_date = seen.header("x-amz-date");
    let (path, query) = match seen.path.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (seen.path.as_str(), None),
    };
    let keys = crate::access::sigv4::Keys { access_key: access_key.to_owned(), secret_key: secret_key.to_owned(), session_token: None };
    let ours = crate::access::sigv4::sign(&seen.method, host, path, query, seen.body.as_bytes(), &keys, &region, &service, &amz_date, true);
    let expected = ours.iter().find(|(name, _)| name == "authorization").map(|(_, value)| value.clone()).unwrap_or_default();
    // The headers the connector said it signed have to be the ones the signature covers.
    expected == authorization && signed.contains("host") && signed.contains("x-amz-date")
}

fn settings(pairs: &[(&str, &str)]) -> Settings {
    pairs.iter().fold(Settings::new(), |settings, (name, value)| settings.with(name, value).unwrap())
}

/// Everything a read-only connector does, in order, so each test says what it found rather than
/// repeating the drive.
async fn read_only_drive(service: &ReadOnlyCloud, ticket: &Ticket, now: i64) -> (Discovery, Rehearsal, Seen2) {
    let found = service.discover(ticket, now).await.unwrap();
    let plan = service.plan(ticket, &Request::new(Change::Give, ada()), now).unwrap();
    assert_eq!(plan.connector(), service.integration());
    assert!(!plan.alters(), "every step of a read-only connector's plan reads");
    let rehearsal = service.dry_run(ticket, &plan, now).await.unwrap();
    let checked = service.validate(ticket, &plan, now).await.unwrap();
    let observed = service.observe(ticket, &plan, now).await.unwrap();

    // The three that change a provider are unreachable, and that is a fact about the calls: the
    // plan has no altering step, so `cleared` refuses it whatever the connector would have done.
    for refused in [
        service.apply(ticket, &plan, &checked, now).await,
        service.reconcile(ticket, &plan, &checked, now).await,
        service.revoke(ticket, &plan, &checked, now).await,
    ] {
        let trouble = refused.unwrap_err();
        assert!(matches!(trouble, Trouble::NotAllowed(_)), "{}", trouble.say());
        assert!(trouble.say().contains("only reads") && trouble.say().contains("changes nothing there"), "{}", trouble.say());
    }
    assert!(!service.alters_anything());
    (found, rehearsal, observed)
}

type Seen2 = super::super::Seen;

#[tokio::test]
async fn amazon_is_reached_with_a_signature_this_test_recomputes() {
    let now = 1_667_293_200;
    let instances = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><DescribeInstancesResponse xmlns=\"http://ec2.amazonaws.com/doc/2016-11-15/\"><reservationSet><item><instancesSet><item><instanceId>i-0abc</instanceId><instanceState><code>16</code><name>running</name></instanceState></item><item><instanceId>i-0def</instanceId><instanceState><code>80</code><name>stopped</name></instanceState></item></instancesSet></item></reservationSet></DescribeInstancesResponse>";
    let (base, calls) = provider(move |seen| {
        let host = seen.header("host");
        if !signature_matches(seen, &host, "AKIAEXAMPLE", "a-secret-nobody-reads") {
            return (403, "text/xml", "<Error><Code>SignatureDoesNotMatch</Code><Message>The request signature does not match</Message></Error>".to_owned());
        }
        (200, "text/xml", instances.to_owned())
    })
    .await;
    let wire = Keyed::new(
        "https://ec2.eu-west-1.amazonaws.com",
        &base,
        Present::AwsSigV4 { service: "ec2".into(), region: "eu-west-1".into(), access_field: "accessKeyId".into(), secret_field: "secretAccessKey".into() },
        Box::new(Vault { credential_id: "credential-aws", fields: json!({"accessKeyId": "AKIAEXAMPLE", "secretAccessKey": "a-secret-nobody-reads"}), version: 4 }),
        now,
    )
    .unwrap();
    let service = ReadOnlyCloud::new(Service::AmazonCompute, settings(&[("region", "eu-west-1")]), Box::new(wire));
    let ticket = permission("credential-aws", "https://ec2.eu-west-1.amazonaws.com", now);

    let (found, rehearsal, observed) = read_only_drive(&service, &ticket, now).await;
    assert_eq!(found.reached.len(), 2);
    assert_eq!((found.reached[0].id.as_str(), found.reached[0].description.as_str()), ("i-0abc", "running"));
    assert_eq!(found.reached[1].description, "stopped");
    assert!(found.note.contains("changes nothing"));
    assert!(rehearsal.reached && rehearsal.would_change().is_empty() && rehearsal.note.contains("nothing would be changed"));
    // What this connector can say is what the provider holds, and it says plainly that it has
    // nothing to say about one person, because this API is not about people at all.
    assert_eq!(observed.holds, None);
    assert!(observed.note.contains("2 machines") && observed.note.contains("not about people"), "{}", observed.note);

    let seen = calls.lock().unwrap().clone();
    assert!(seen.len() >= 4, "discover, dry run, validate and observe each read the provider");
    assert_eq!(seen[0].method, "POST");
    assert!(seen[0].path.starts_with("/?Action=DescribeInstances&Version=2016-11-15"), "{}", seen[0].path);
    assert!(seen[0].header("authorization").starts_with("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/"));
    assert!(!seen[0].header("x-amz-content-sha256").is_empty(), "a signed request names the hash of its payload");
    // The key itself never leaves this computer: what goes out is a signature over the request.
    for call in &seen {
        assert!(!call.header("authorization").contains("a-secret-nobody-reads"), "{}", call.header("authorization"));
        assert!(!call.body.contains("a-secret-nobody-reads"));
    }
    // Taken once, because taking a connector's notes empties it: a note handed over twice is a
    // note sealed into the realm's history twice.
    let kept = service.export_audit();
    assert!(kept.iter().all(|note| !note.reason.contains("a-secret-nobody-reads")));
    // A rotation shows up in the history as a version, and never as a value.
    assert!(kept.iter().any(|note| note.reason.contains("credential version 4")), "{kept:?}");
    assert!(service.export_audit().is_empty(), "and the connector is holding none afterwards");

    // A key that is not the key gets the provider's own refusal, in the provider's own words.
    let wrong = Keyed::new(
        "https://ec2.eu-west-1.amazonaws.com",
        &base,
        Present::AwsSigV4 { service: "ec2".into(), region: "eu-west-1".into(), access_field: "accessKeyId".into(), secret_field: "secretAccessKey".into() },
        Box::new(Vault { credential_id: "credential-aws", fields: json!({"accessKeyId": "AKIAEXAMPLE", "secretAccessKey": "not the key"}), version: 1 }),
        now,
    )
    .unwrap();
    let refused = ReadOnlyCloud::new(Service::AmazonCompute, settings(&[("region", "eu-west-1")]), Box::new(wrong)).discover(&ticket, now).await.unwrap_err();
    assert!(refused.say().contains("signature does not match"), "{}", refused.say());
}

#[tokio::test]
async fn amazon_storage_and_the_two_cluster_services_speak_their_own_shapes() {
    let now = 1_667_293_200;
    let listing = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><ListBucketResult><Name>acme-parking</Name><Contents><Key>desk-1.tar.zst</Key><Size>18234</Size></Contents><Contents><Key>desk-2.tar.zst</Key><Size>99</Size></Contents></ListBucketResult>";
    let (base, calls) = provider(move |seen| {
        let host = seen.header("host");
        if !signature_matches(seen, &host, "AKIAEXAMPLE", "a-secret-nobody-reads") {
            return (403, "text/xml", "<Error><Code>SignatureDoesNotMatch</Code><Message>no</Message></Error>".to_owned());
        }
        if seen.header("x-amz-target").contains("ListClusters") {
            return (200, "application/json", json!({"clusterArns": ["arn:aws:ecs:eu-west-1:1:cluster/finance"]}).to_string());
        }
        if seen.path.starts_with("/clusters") {
            return (200, "application/json", json!({"clusters": ["research"]}).to_string());
        }
        (200, "application/xml", listing.to_owned())
    })
    .await;
    let wire = |service: &str| {
        Keyed::new(
            "https://s3.eu-west-1.amazonaws.com",
            &base,
            Present::AwsSigV4 { service: service.to_owned(), region: "eu-west-1".into(), access_field: "accessKeyId".into(), secret_field: "secretAccessKey".into() },
            Box::new(Vault { credential_id: "credential-aws", fields: json!({"accessKeyId": "AKIAEXAMPLE", "secretAccessKey": "a-secret-nobody-reads"}), version: 1 }),
            now,
        )
        .unwrap()
    };
    let ticket = permission("credential-aws", "https://s3.eu-west-1.amazonaws.com", now);

    // S3: a REST listing with an XML answer, and the keys are what it reaches.
    let bucket = ReadOnlyCloud::new(Service::AmazonStorage, settings(&[("region", "eu-west-1"), ("bucket", "acme-parking")]), Box::new(wire("s3")));
    let (found, _, _) = read_only_drive(&bucket, &ticket, now).await;
    assert_eq!(found.reached.len(), 2);
    assert_eq!((found.reached[0].id.as_str(), found.reached[0].description.as_str()), ("desk-1.tar.zst", "18234 bytes"));
    assert_eq!(found.reached[0].kind, "object");
    let seen = calls.lock().unwrap().clone();
    assert!(seen[0].path.starts_with("/acme-parking?list-type=2&max-keys=100"), "{}", seen[0].path);

    // ECS: a JSON API that names what it wants in a header rather than in a path.
    calls.lock().unwrap().clear();
    let ecs = ReadOnlyCloud::new(Service::AmazonContainers, settings(&[("region", "eu-west-1")]), Box::new(wire("ecs")));
    let found = ecs.discover(&ticket, now).await.unwrap();
    assert_eq!(found.reached[0].id, "arn:aws:ecs:eu-west-1:1:cluster/finance");
    assert_eq!(found.reached[0].kind, "cluster");
    let seen = calls.lock().unwrap().clone();
    assert_eq!(seen[0].header("x-amz-target"), "AmazonEC2ContainerServiceV20141113.ListClusters");
    assert_eq!(seen[0].body, "{}", "a JSON API with no arguments is still a body, and an empty one");

    // EKS: a REST API with a plain path.
    calls.lock().unwrap().clear();
    let eks = ReadOnlyCloud::new(Service::AmazonKubernetes, settings(&[("region", "eu-west-1")]), Box::new(wire("eks")));
    assert_eq!(eks.discover(&ticket, now).await.unwrap().reached[0].id, "research");
    assert_eq!(calls.lock().unwrap()[0].path, "/clusters");

    // A connection that was not told which bucket says so before anything is sent.
    let bare = ReadOnlyCloud::new(Service::AmazonStorage, settings(&[("region", "eu-west-1")]), Box::new(wire("s3")));
    let missing = bare.discover(&ticket, now).await.unwrap_err();
    assert!(matches!(missing, Trouble::Missing(_)) && missing.say().contains("bucket"), "{}", missing.say());
}

#[tokio::test]
async fn azure_exchanges_its_credential_for_a_token_and_sends_the_token() {
    let now = 1_667_293_200;
    let (base, calls) = provider(|seen| {
        if seen.path == "/tenant-1/oauth2/v2.0/token" {
            if !seen.body.contains("client_secret=s3cret") {
                return (401, "application/json", json!({"error": "invalid_client", "error_description": "Invalid client secret"}).to_string());
            }
            return (200, "application/json", json!({"access_token": "arm-token", "expires_in": 3599}).to_string());
        }
        if seen.header("authorization") != "Bearer arm-token" {
            return (401, "application/json", json!({"error": {"code": "InvalidAuthenticationToken", "message": "not a token this tenant minted"}}).to_string());
        }
        (
            200,
            "application/json",
            json!({"value": [
                {"name": "build-01", "properties": {"hardwareProfile": {"vmSize": "Standard_D8s_v5"}}},
                {"name": "build-02", "properties": {"hardwareProfile": {"vmSize": "Standard_D4s_v5"}}}
            ]})
            .to_string(),
        )
    })
    .await;
    let wire = Keyed::new(
        "https://management.azure.com",
        &base,
        Present::ClientCredentials { token_url: format!("{base}/tenant-1/oauth2/v2.0/token"), client_id: "app-1".into(), scope: "https://management.azure.com/.default".into(), field: "clientSecret".into() },
        Box::new(Vault { credential_id: "credential-azure", fields: json!({"clientSecret": "s3cret"}), version: 2 }),
        now,
    )
    .unwrap();
    let service = ReadOnlyCloud::new(Service::AzureCompute, settings(&[("subscriptionId", "sub-1"), ("resourceGroup", "rg")]), Box::new(wire));
    let ticket = permission("credential-azure", "https://management.azure.com", now);

    let (found, _, observed) = read_only_drive(&service, &ticket, now).await;
    assert_eq!(found.reached.len(), 2);
    assert_eq!((found.reached[0].id.as_str(), found.reached[0].description.as_str()), ("build-01", "Standard_D8s_v5"));
    assert!(observed.note.contains("virtual machines in resource group rg"), "{}", observed.note);

    let seen = calls.lock().unwrap().clone();
    // The secret goes to the sign-in and nowhere else, and the token cache means it goes once.
    let signins: Vec<&Seen> = seen.iter().filter(|call| call.path.ends_with("/oauth2/v2.0/token")).collect();
    assert_eq!(signins.len(), 1, "a token that is still live is not minted again for every call");
    for call in &seen {
        assert!(!call.body.contains("s3cret") || call.path.ends_with("/oauth2/v2.0/token"), "{} {}", call.path, call.body);
        assert!(!call.header("authorization").contains("s3cret"));
    }
    let reads: Vec<&Seen> = seen.iter().filter(|call| call.method == "GET").collect();
    assert!(reads[0].path.starts_with("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines?api-version="), "{}", reads[0].path);
    assert!(reads[0].path.contains(AZURE_COMPUTE_VERSION), "every Resource Manager request names the API version it was written against");
    assert!(service.export_audit().iter().all(|note| !note.reason.contains("s3cret")));

    // A credential the tenant will not take is refused in the provider's words, before anything
    // else is asked for.
    let wrong = Keyed::new(
        "https://management.azure.com",
        &base,
        Present::ClientCredentials { token_url: format!("{base}/tenant-1/oauth2/v2.0/token"), client_id: "app-1".into(), scope: "https://management.azure.com/.default".into(), field: "clientSecret".into() },
        Box::new(Vault { credential_id: "credential-azure", fields: json!({"clientSecret": "wrong"}), version: 1 }),
        now,
    )
    .unwrap();
    let refused = ReadOnlyCloud::new(Service::AzureCompute, settings(&[("subscriptionId", "sub-1"), ("resourceGroup", "rg")]), Box::new(wrong)).discover(&ticket, now).await.unwrap_err();
    assert!(refused.say().contains("could not sign in"), "{}", refused.say());
}

#[tokio::test]
async fn azure_storage_signs_each_request_and_sends_no_key() {
    let now = 1_667_293_200;
    let key = "YSBzZWNyZXQgbm9ib2R5IHJlYWRz";
    let listing = "<?xml version=\"1.0\" encoding=\"utf-8\"?><EnumerationResults><Blobs><Blob><Name>desk-7.tar.zst</Name><Properties><Content-Length>4096</Content-Length></Properties></Blob></Blobs></EnumerationResults>";
    let (base, calls) = provider(move |seen| {
        if !seen.header("authorization").starts_with("SharedKey acme:") {
            return (403, "application/xml", "<Error><Code>AuthenticationFailed</Code><Message>no shared key</Message></Error>".to_owned());
        }
        (200, "application/xml", listing.to_owned())
    })
    .await;
    let wire = Keyed::new(
        "https://acme.blob.core.windows.net",
        &base,
        Present::AzureSharedKey { account: "acme".into(), field: "accountKey".into() },
        Box::new(Vault { credential_id: "credential-blob", fields: json!({"accountKey": key}), version: 1 }),
        now,
    )
    .unwrap();
    let service = ReadOnlyCloud::new(Service::AzureStorage, settings(&[("account", "acme"), ("container", "parking")]), Box::new(wire));
    let ticket = permission("credential-blob", "https://acme.blob.core.windows.net", now);

    let (found, _, _) = read_only_drive(&service, &ticket, now).await;
    assert_eq!(found.reached.len(), 1);
    assert_eq!((found.reached[0].id.as_str(), found.reached[0].description.as_str()), ("desk-7.tar.zst", "4096 bytes"));

    let seen = calls.lock().unwrap().clone();
    assert!(seen[0].path.starts_with("/parking?restype=container&comp=list"), "{}", seen[0].path);
    assert_eq!(seen[0].header("x-ms-version"), crate::core::connector::wire::AZURE_STORAGE_VERSION);
    assert_eq!(seen[0].header("x-ms-date"), crate::core::connector::wire::http_date(now));
    for call in &seen {
        assert!(!call.header("authorization").contains(key), "the key signs the request; it does not travel on it");
    }
}

#[tokio::test]
async fn kubernetes_and_openstack_present_their_credentials_the_way_each_one_wants() {
    let now = 1_667_293_200;

    // Kubernetes: a bearer token the cluster issued, on every request.
    let (base, calls) = provider(|seen| {
        if seen.header("authorization") != "Bearer a-service-account-token" {
            return (401, "application/json", json!({"kind": "Status", "message": "Unauthorized"}).to_string());
        }
        (
            200,
            "application/json",
            json!({"items": [
                {"metadata": {"name": "node-a"}, "status": {"conditions": [{"type": "MemoryPressure", "status": "False"}, {"type": "Ready", "status": "True"}]}},
                {"metadata": {"name": "node-b"}, "status": {"conditions": []}}
            ]})
            .to_string(),
        )
    })
    .await;
    let wire = Keyed::new("https://cluster.acme.example:6443", &base, Present::Bearer { field: "token".into() }, Box::new(Vault { credential_id: "credential-kube", fields: json!({"token": "a-service-account-token"}), version: 1 }), now).unwrap();
    let cluster = ReadOnlyCloud::new(Service::Kubernetes, Settings::new(), Box::new(wire));
    let ticket = permission("credential-kube", "https://cluster.acme.example:6443", now);
    let (found, _, observed) = read_only_drive(&cluster, &ticket, now).await;
    assert_eq!(found.reached.len(), 2);
    assert_eq!((found.reached[0].id.as_str(), found.reached[0].description.as_str()), ("node-a", "ready: True"));
    assert_eq!(found.reached[1].description, "ready: readiness not reported", "a node that reports no conditions is not a node that is not ready");
    assert!(observed.note.contains("the nodes of this cluster"));
    assert_eq!(calls.lock().unwrap()[0].path, "/api/v1/nodes");

    // OpenStack: a password exchanged at Keystone for a token that comes back in a header, not in
    // the body, and that token then travels in a header of its own rather than as a bearer.
    let (base, calls) = provider(|seen| {
        if seen.path == "/v3/auth/tokens" {
            if !seen.body.contains("\"password\":\"pw\"") {
                return (401, "application/json", json!({"error": {"message": "The request you have made requires authentication."}}).to_string());
            }
            return (201, "application/json", json!({"token": {"methods": ["password"]}}).to_string());
        }
        if seen.header("x-auth-token") != "a-keystone-token" {
            return (401, "application/json", json!({"error": {"message": "no token"}}).to_string());
        }
        (200, "application/json", json!({"servers": [{"name": "build-01", "status": "ACTIVE"}]}).to_string())
    })
    .await;
    // Keystone's token is a header on the answer, which is the one place in this seam where an
    // answer's headers matter, so the fixture has to put it there.
    let (keystone, _) = header_provider(base.clone()).await;
    let wire = Keyed::new(
        "https://nova.acme.example",
        &base,
        Present::Keystone {
            auth_url: keystone.clone(),
            user: "grid".into(),
            user_domain: "Default".into(),
            project: "research".into(),
            project_domain: "Default".into(),
            field: "password".into(),
        },
        Box::new(Vault { credential_id: "credential-openstack", fields: json!({"password": "pw"}), version: 1 }),
        now,
    )
    .unwrap();
    let cloud = ReadOnlyCloud::new(Service::OpenStack, Settings::new(), Box::new(wire));
    let ticket = permission("credential-openstack", "https://nova.acme.example", now);
    let found = cloud.discover(&ticket, now).await.unwrap();
    assert_eq!((found.reached[0].id.as_str(), found.reached[0].description.as_str()), ("build-01", "ACTIVE"));
    let seen = calls.lock().unwrap().clone();
    assert_eq!(seen[0].path, "/servers/detail");
    assert_eq!(seen[0].header("x-auth-token"), "a-keystone-token");
    assert!(seen.iter().all(|call| !call.body.contains("\"pw\"")), "the password goes to Keystone and nowhere else");
}

/// A Keystone that answers with its token in `X-Subject-Token`, which is where the standard puts
/// it. Separate from `provider` because that one answers with a body and nothing else.
async fn header_provider(_unused: String) -> (String, Calls) {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request as HyperRequest, Response};
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls: Calls = Arc::default();
    let recorder = calls.clone();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            let recorder = recorder.clone();
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: HyperRequest<Incoming>| {
                    let recorder = recorder.clone();
                    async move {
                        let path = request.uri().path().to_owned();
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let body = String::from_utf8_lossy(&bytes).into_owned();
                        recorder.lock().unwrap().push(Seen { method: "POST".into(), path: path.clone(), headers: Vec::new(), body: body.clone() });
                        let correct = body.contains("\"password\":\"pw\"");
                        let response = if correct {
                            Response::builder().status(201).header("content-type", "application/json").header("x-subject-token", "a-keystone-token").body(Full::new(bytes::Bytes::from("{\"token\":{}}")))
                        } else {
                            Response::builder().status(401).header("content-type", "application/json").body(Full::new(bytes::Bytes::from("{\"error\":{\"message\":\"wrong password\"}}")))
                        };
                        Ok::<_, std::convert::Infallible>(response.unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (format!("http://{address}"), calls)
}

#[tokio::test]
async fn a_read_only_connector_refuses_a_permission_for_somewhere_else_and_for_another_credential() {
    let now = 1_667_293_200;
    let (base, _) = provider(|_| (200, "application/json", json!({"items": []}).to_string())).await;
    let wire = Keyed::new("https://cluster.acme.example:6443", &base, Present::Bearer { field: "token".into() }, Box::new(Vault { credential_id: "credential-kube", fields: json!({"token": "t"}), version: 1 }), now).unwrap();
    let cluster = ReadOnlyCloud::new(Service::Kubernetes, Settings::new(), Box::new(wire));

    let elsewhere = permission("credential-kube", "https://cluster.other.example:6443", now);
    let refused = cluster.discover(&elsewhere, now).await.unwrap_err();
    assert!(matches!(refused, Trouble::NotAllowed(_)) && refused.say().contains("cluster.other.example"), "{}", refused.say());

    let stranger = permission("credential-somebody-else", "https://cluster.acme.example:6443", now);
    let refused = cluster.discover(&stranger, now).await.unwrap_err();
    assert!(refused.say().contains("credential-somebody-else"), "{}", refused.say());

    let lapsed = permission("credential-kube", "https://cluster.acme.example:6443", now);
    assert!(cluster.discover(&lapsed, lapsed.expires_at()).await.unwrap_err().say().contains("expired"));

    // A plan made for another credential is refused rather than carried out with whatever this
    // connection happens to hold.
    let ticket = permission("credential-kube", "https://cluster.acme.example:6443", now);
    let other_ticket = permission("credential-elsewhere", "https://cluster.acme.example:6443", now);
    let plan = cluster.plan(&other_ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let refused = cluster.validate(&ticket, &plan, now).await.unwrap_err();
    assert!(refused.say().contains("made for another credential"), "{}", refused.say());
}

#[tokio::test]
async fn a_connection_holds_itself_to_a_rate_and_stops_asking_a_provider_that_is_down() {
    let now = 1_667_293_200;
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let down = failing.clone();
    let (base, calls) = provider(move |_| {
        if down.load(std::sync::atomic::Ordering::SeqCst) {
            return (503, "application/json", json!({"message": "the service is unavailable"}).to_string());
        }
        (200, "application/json", json!({"items": []}).to_string())
    })
    .await;
    let wire = Keyed::new("https://cluster.acme.example:6443", &base, Present::Bearer { field: "token".into() }, Box::new(Vault { credential_id: "credential-kube", fields: json!({"token": "t"}), version: 1 }), now).unwrap();
    let cluster = ReadOnlyCloud::new(Service::Kubernetes, Settings::new(), Box::new(wire));
    let ticket = permission("credential-kube", "https://cluster.acme.example:6443", now);

    // The burst this connection allows itself, and then a refusal that reaches nobody. Being
    // throttled inside a customer's tenant is worse for them than being slow, because a throttle
    // applies to everything their own people are doing at the same time.
    for _ in 0..30 {
        assert!(cluster.discover(&ticket, now).await.is_ok());
    }
    let refused = cluster.discover(&ticket, now).await.unwrap_err();
    assert!(matches!(refused, Trouble::Refused(_)) && refused.say().contains("Nothing was sent"), "{}", refused.say());
    assert_eq!(calls.lock().unwrap().len(), 30, "the thirty-first never left this computer");

    // A second later there are five more and no more than five.
    for _ in 0..5 {
        assert!(cluster.discover(&ticket, now + 1).await.is_ok());
    }
    assert!(cluster.discover(&ticket, now + 1).await.is_err());
    assert_eq!(calls.lock().unwrap().len(), 35);

    // A provider that is down: five answers in the five-hundreds in a row and this connection
    // stops sending altogether, rather than keeping a queue of requests warm against a service
    // that is not answering.
    failing.store(true, std::sync::atomic::Ordering::SeqCst);
    calls.lock().unwrap().clear();
    for _ in 0..5 {
        assert!(cluster.discover(&ticket, now + 60).await.is_err());
    }
    let open = cluster.discover(&ticket, now + 60).await.unwrap_err();
    assert!(open.say().contains("stopped sending after 5 refusals"), "{}", open.say());
    assert_eq!(calls.lock().unwrap().len(), 5, "the sixth never left this computer either");

    // A provider's own refusal of one request is the connector's business and not the breaker's.
    // A wrong path answering 404 for ever must not look like an outage.
    let (base, _) = provider(|_| (404, "application/json", json!({"message": "no such thing"}).to_string())).await;
    let wire = Keyed::new("https://cluster.acme.example:6443", &base, Present::Bearer { field: "token".into() }, Box::new(Vault { credential_id: "credential-kube", fields: json!({"token": "t"}), version: 1 }), now).unwrap();
    let missing = ReadOnlyCloud::new(Service::Kubernetes, Settings::new(), Box::new(wire));
    for step in 0..8 {
        let refused = missing.discover(&ticket, now + step).await.unwrap_err();
        assert!(refused.say().contains("404"), "{}", refused.say());
    }
}

/// PROVES that a provider answering 429 with its own `Retry-After` stops this connection sending
/// for as long as it asked for, that the refusal reaches nobody and says what is happening, and
/// that the connection sends again once the wait is over.
///
/// This is the end of the path the unit test in `limits.rs` covers in pieces: the header is read
/// off the answer, turned into seconds, and handed to the breaker, and nothing between the
/// provider and the breaker drops it.
///
/// DOES NOT PROVE that a real provider throttles this way, or that these are the right waits.
/// Nothing here has ever been throttled by anybody; the fixture is a server on this computer.
#[tokio::test]
async fn a_provider_that_answers_too_many_requests_is_left_alone_for_as_long_as_it_asked() {
    let now = 1_667_300_000;
    let throttling = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let shedding = throttling.clone();
    let (base, calls) = throttling_provider(move || shedding.load(std::sync::atomic::Ordering::SeqCst), "45").await;
    let wire = Keyed::new("https://cluster.acme.example:6443", &base, Present::Bearer { field: "token".into() }, Box::new(Vault { credential_id: "credential-kube", fields: json!({"token": "t"}), version: 1 }), now).unwrap();
    let cluster = ReadOnlyCloud::new(Service::Kubernetes, Settings::new(), Box::new(wire));
    let ticket = permission("credential-kube", "https://cluster.acme.example:6443", now);

    // One throttle is enough. It does not take five, the way a refusal does.
    let refused = cluster.discover(&ticket, now).await.unwrap_err();
    assert!(refused.say().contains("429"), "the provider's own answer comes back first: {}", refused.say());
    assert_eq!(calls.lock().unwrap().len(), 1);

    let held = cluster.discover(&ticket, now + 1).await.unwrap_err();
    assert!(held.say().contains("slow down") && held.say().contains("Nothing was sent"), "{}", held.say());
    assert_eq!(calls.lock().unwrap().len(), 1, "the second request never left this computer");

    // The provider asked for forty-five seconds in its own header, so it gets forty-five and not
    // the thirty this grid would have guessed at.
    assert!(held.say().contains("44 seconds"), "the provider's own wait is the wait: {}", held.say());
    assert!(cluster.discover(&ticket, now + 44).await.unwrap_err().say().contains("slow down"));
    assert_eq!(calls.lock().unwrap().len(), 1);

    // And then it is asked again, and when it answers this time the connection carries on.
    throttling.store(false, std::sync::atomic::Ordering::SeqCst);
    assert!(cluster.discover(&ticket, now + 45).await.is_ok());
    assert!(cluster.discover(&ticket, now + 46).await.is_ok());
    assert_eq!(calls.lock().unwrap().len(), 3);
}

/// A provider that sheds requests while `shedding` says so, with its own wait in `Retry-After`.
///
/// Separate from `provider` because that one builds an answer with a content type and nothing
/// else, and the header is the thing being proved here: changing the shared fixture to carry
/// headers would have touched every test that uses it for the sake of one.
async fn throttling_provider(shedding: impl Fn() -> bool + Send + Sync + 'static, wait: &'static str) -> (String, Calls) {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request as HyperRequest, Response};
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls: Calls = Arc::default();
    let shedding = Arc::new(shedding);
    let recorder = calls.clone();
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            let (shedding, recorder) = (shedding.clone(), recorder.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: HyperRequest<Incoming>| {
                    let (shedding, recorder) = (shedding.clone(), recorder.clone());
                    async move {
                        let method = request.method().to_string();
                        let path = request.uri().path_and_query().map(|path| path.to_string()).unwrap_or_default();
                        let headers: Vec<(String, String)> =
                            request.headers().iter().filter_map(|(name, value)| value.to_str().ok().map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))).collect();
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        recorder.lock().unwrap().push(Seen { method, path, headers, body: String::from_utf8_lossy(&bytes).into_owned() });
                        let answer = if shedding() {
                            Response::builder().status(429).header("content-type", "application/json").header("retry-after", wait).body(Full::new(bytes::Bytes::from(json!({"message": "slow down"}).to_string())))
                        } else {
                            Response::builder().status(200).header("content-type", "application/json").body(Full::new(bytes::Bytes::from(json!({"items": []}).to_string())))
                        };
                        Ok::<_, std::convert::Infallible>(answer.unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (format!("http://{address}"), calls)
}

#[test]
fn every_service_has_a_row_that_says_what_it_really_is() {
    rows_are_honest().unwrap();
    for service in [
        Service::AmazonCompute,
        Service::AmazonContainers,
        Service::AmazonKubernetes,
        Service::AmazonStorage,
        Service::AzureCompute,
        Service::AzureStorage,
        Service::Kubernetes,
        Service::OpenStack,
    ] {
        let row = super::super::registry::find(service.row()).unwrap();
        assert!(row.evidence.contains("loopback"), "{}: a mock-tested row names the server it was exercised against", service.row());
        assert!(row.evidence.contains("read") || row.maps_to.contains("Read"), "{}: a read-only connector's row has to say so", service.row());
    }
}
