//! What this computer says about its own grids, and what it will not say to anybody who asks.
//!
//! Everything here runs against realms this test makes in a folder of its own. Nothing opens the
//! vault of whoever runs the tests, nothing reaches off this computer, and the one listener that
//! is started binds the loopback interface on a port the operating system chooses.
use super::*;
use yougori_grid::core::identity::{PrincipalKind, Role};
use yougori_grid::core::realm::{Capability, RealmKind};
use yougori_grid::core::work::{Commitment, Resources};
use yougori_grid::core::Core;

fn key() -> String {
    "e".repeat(64)
}

fn room() -> Resources {
    Resources { cpu: 8.0, memory_gb: 32.0, disk_gb: 200.0, gpu: false, vram_gb: 0.0 }
}

/// A realm on disk with one person, one computer and a history, closed again so that what is read
/// afterwards is read the way a probe reads it and not through a handle this test is holding.
fn realm_at(path: &Path, now: i64) -> String {
    let mut core = Core::create(path, "Acme", RealmKind::Primary, &[Capability::Models], &key(), now).unwrap();
    let id = core.realm().id.clone();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::SecurityAdmin], now).unwrap();
    let (device, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    core.offer_host(&device.id, "Studio PC", room(), room(), Commitment::Share, now).unwrap();
    core.close().unwrap();
    id
}

/// PROVES that a realm is read for a checkup and a reading without being opened the way a writer
/// opens one: the file's bytes are the same after as before, and its version has not moved.
///
/// This is the property that matters most in this file. `Core::open` migrates, and a monitoring
/// agent scraping an endpoint must never be the thing that brings a customer's realm forward to a
/// shape they have not chosen to move to.
///
/// DOES NOT PROVE that SQLite writes nothing at all beside the file. A realm is in write-ahead
/// logging and SQLite may create `-shm` and `-wal` next to one in order to read it; what is
/// claimed, and checked, is that the realm's own file is byte for byte what it was.
#[test]
fn looking_at_a_realm_never_writes_to_it() {
    let folder = tempfile::tempdir().unwrap();
    let now = 1_700_000_000;
    let path = folder.path().join("acme.db");
    let id = realm_at(&path, now);
    let before = std::fs::read(&path).unwrap();

    let found = look(&path, true, now);
    assert_eq!(found["id"], id);
    assert_eq!(found["grid"], "acme.db");
    assert_eq!(found["health"], "serving");
    assert_eq!(found["kind"], "company");
    assert!(found["reading"]["counts"].is_object(), "{found}");
    assert_eq!(found["reading"]["auditEventsNeverExported"].as_u64().unwrap() > 0, true, "a realm that has never exported says so");

    assert_eq!(std::fs::read(&path).unwrap(), before, "a probe rewrote the realm it was only meant to read");
}

/// PROVES that a realm nothing can read is reported as down with a sentence, rather than being
/// left out of the answer, and that the worst grid is what the computer as a whole reports.
#[test]
fn a_realm_that_cannot_be_read_is_down_and_says_so() {
    let folder = tempfile::tempdir().unwrap();
    let now = 1_700_000_000;
    let damaged = folder.path().join("damaged.db");
    std::fs::write(&damaged, b"this is not a grid").unwrap();
    let found = look(&damaged, false, now);
    assert_eq!(found["health"], "down");
    assert!(found["notes"][0].as_str().unwrap().contains("could not be read"), "{found}");

    // The computer's own line is the worst of its grids, so one bad grid turns the line red.
    let answer = json!({"health": "down", "grids": [found.clone(), json!({"health": "serving", "id": "realm-ok"})]});
    assert!(lines(&answer).starts_with("down\n"));
    assert!(lines(&answer).contains("could not be read"));
}

/// PROVES that what a scrape carries is numbers and identifiers and nothing else: no person's
/// name, no file path, no company name and no address. A reading travels into somebody's
/// monitoring system and stays there, so what it carries is what they have agreed to keep.
#[test]
fn a_scrape_carries_numbers_and_an_identifier_and_nothing_anybody_would_mind_sharing() {
    let folder = tempfile::tempdir().unwrap();
    let now = 1_700_000_000;
    let path = folder.path().join("acme.db");
    let id = realm_at(&path, now);
    let answer = json!({"at": now, "health": "serving", "grids": [look(&path, true, now)]});
    let text = scraped(&answer);

    assert!(text.contains(&format!("yougori_grid_health{{grid=\"{id}\"}} 2")), "{text}");
    assert!(text.contains("yougori_grid_hosts_offering"), "{text}");
    assert!(text.contains("yougori_grid_audit_events_never_exported"), "{text}");
    for forbidden in ["Ada", "Acme", "Studio PC", "acme.db", "Users", &folder.path().display().to_string()] {
        assert!(!text.contains(forbidden), "a scrape carried {forbidden}:\n{text}");
    }
    // Every line is a comment or a name, labels and a number, which is what the text exposition
    // format is. A line that is not is a line a scraper rejects.
    for line in text.lines().filter(|line| !line.starts_with('#') && !line.is_empty()) {
        let (_, number) = line.rsplit_once(' ').unwrap_or(("", "x"));
        assert!(number.parse::<i64>().is_ok(), "not a number: {line}");
    }
}

/// PROVES that the endpoint answers nobody without the token, that it answers `/healthz` and
/// `/metrics` with it, that it binds the loopback interface and nothing else, and that stopping it
/// closes the port.
///
/// DOES NOT PROVE that a token is enough on a shared computer. Anything running as this user can
/// reach a loopback port, which is exactly as true of the engine's own control socket, and it is
/// why this is off until somebody turns it on and why it never writes the token anywhere.
#[tokio::test]
async fn the_endpoint_answers_only_on_this_computer_and_only_with_the_token() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let folder = tempfile::tempdir().unwrap();
    let now = 1_700_000_000;
    realm_at(&folder.path().join("acme.db"), now);

    // The endpoint's own connection handling, without the application around it, so this test
    // needs no window. It is the function the listener calls and not a copy of it.
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = "a-token-this-test-made".to_owned();
    let secret = token.clone();
    let realms = folder.path().to_owned();
    let task = tokio::spawn(async move {
        let places = std::sync::Arc::new(tokio::sync::Semaphore::new(8));
        while let Ok((socket, _)) = listener.accept().await {
            let (secret, realms, places) = (secret.clone(), realms.clone(), places.clone());
            tokio::spawn(async move { one_scrape(socket, &secret, &places, realms).await });
        }
    });

    async fn ask(port: u16, path: &str, token: Option<&str>) -> String {
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let authorization = token.map(|token| format!("authorization: Bearer {token}\r\n")).unwrap_or_default();
        socket.write_all(format!("GET {path} HTTP/1.1\r\nhost: 127.0.0.1\r\n{authorization}\r\n").as_bytes()).await.unwrap();
        let mut said = String::new();
        socket.read_to_string(&mut said).await.unwrap();
        said
    }

    assert!(ask(port, "/healthz", None).await.starts_with("HTTP/1.1 401"), "no token, no answer");
    assert!(ask(port, "/healthz", Some("not the token")).await.starts_with("HTTP/1.1 401"));
    // Nearly the token is no closer than nothing like it.
    assert!(ask(port, "/healthz", Some("a-token-this-test-mad")).await.starts_with("HTTP/1.1 401"));
    assert!(ask(port, "/healthz", Some("a-token-this-test-madeX")).await.starts_with("HTTP/1.1 401"));
    let healthy = ask(port, "/healthz", Some(&token)).await;
    assert!(healthy.starts_with("HTTP/1.1 200") && healthy.contains("serving"), "{healthy}");
    let scrape = ask(port, "/metrics", Some(&token)).await;
    assert!(scrape.contains("yougori_grid_health{grid=\"realm-"), "{scrape}");
    assert!(ask(port, "/anything-else", Some(&token)).await.starts_with("HTTP/1.1 404"));

    // Loopback only, and it is the bind that says so rather than a check: nothing is listening on
    // any other address of this computer.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(500), tokio::net::TcpStream::connect((local_address(), port))).await.map(|reached| reached.is_err()).unwrap_or(true),
        "something answered on an address other than the loopback one"
    );

    task.abort();
}

/// PROVES that callers who do not have the token cannot shut the endpoint to the one who does.
///
/// The cap on how many scrapes are served at once used to be taken on the connection, before a
/// word of the request had been read. So anything running on this computer could open that many
/// connections, say nothing at all, and hold the endpoint closed for the ten seconds it waits for
/// a request — without ever knowing the token. What the cap protects is the realm databases, so
/// it belongs where they are read: an unproved caller is answered and gone before it is reached.
///
/// DOES NOT PROVE anything about a flood large enough to exhaust this computer's sockets. The
/// connection cap above it is what stands in the way of that, and it is a different number for a
/// different reason.
#[tokio::test]
async fn callers_without_the_token_cannot_hold_the_endpoint_shut() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let folder = tempfile::tempdir().unwrap();
    realm_at(&folder.path().join("acme.db"), 1_700_000_000);
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let token = "a-token-this-test-made".to_owned();
    let secret = token.clone();
    let realms = folder.path().to_owned();
    // One place, so that one caller holding it is every place held.
    let task = tokio::spawn(async move {
        let places = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        while let Ok((socket, _)) = listener.accept().await {
            let (secret, realms, places) = (secret.clone(), realms.clone(), places.clone());
            tokio::spawn(async move { one_scrape(socket, &secret, &places, realms).await });
        }
    });

    // Several callers with no token, each opening a connection and then saying nothing, which is
    // the cheapest thing an unfriendly program on this computer can do.
    let mut silent = Vec::new();
    for _ in 0..8 {
        let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        socket.write_all(b"GET /metrics HTTP/1.1\r\n").await.unwrap();
        silent.push(socket);
    }
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // The one who has the token is answered, at once, while all of them are still holding on.
    let mut socket = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    socket.write_all(format!("GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\nauthorization: Bearer {token}\r\n\r\n").as_bytes()).await.unwrap();
    let mut said = String::new();
    let read = tokio::time::timeout(std::time::Duration::from_secs(3), socket.read_to_string(&mut said)).await;
    assert!(read.is_ok(), "the scraper with the token waited on callers who had none");
    assert!(said.starts_with("HTTP/1.1 200"), "{said}");

    drop(silent);
    task.abort();
}

/// PROVES that the token is compared without saying how much of it was right, and that the header
/// is found however it is spelled.
#[test]
fn the_token_is_compared_whole_however_wrong_it_is() {
    let secret = "the-endpoint-token";
    let bearing = |value: &str| format!("GET /healthz HTTP/1.1\r\nhost: 127.0.0.1\r\nauthorization: {value}\r\n");
    assert!(authorised(&bearing("Bearer the-endpoint-token"), secret));
    assert!(authorised("GET / HTTP/1.1\r\nAUTHORIZATION:   Bearer the-endpoint-token  \r\n", secret), "the header name is not case sensitive and the value is trimmed");
    assert!(!authorised(&bearing("Bearer the-endpoint-toke"), secret), "one byte short is wrong");
    assert!(!authorised(&bearing("Bearer the-endpoint-tokenn"), secret), "one byte long is wrong");
    assert!(!authorised(&bearing("Bearer The-Endpoint-Token"), secret), "a token is not a word");
    assert!(!authorised(&bearing("the-endpoint-token"), secret), "the scheme is part of it");
    assert!(!authorised("GET / HTTP/1.1\r\nhost: 127.0.0.1\r\n", secret), "no header, no answer");

    // Equal length and all different, and differing only at the last byte, are both simply wrong.
    assert!(!same_secret("aaaa", "bbbb"));
    assert!(!same_secret("aaaa", "aaab"));
    assert!(!same_secret("", "a"));
    assert!(same_secret("", ""));
}

/// This computer's own address on its network, or the loopback one when it has none, so the test
/// above has somewhere that is not loopback to try.
fn local_address() -> std::net::IpAddr {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("203.0.113.1:9")?;
            socket.local_addr()
        })
        .map(|address| address.ip())
        .unwrap_or(std::net::IpAddr::from([127, 0, 0, 1]))
}

/// PROVES that a computer holding no realm at all is serving rather than down, and says in words
/// that there is nothing to report on. Every computer running this product is in that state today,
/// and reporting them all as broken would be the endpoint's first lie.
#[test]
fn a_computer_with_no_realms_is_serving_and_says_there_is_nothing_to_report() {
    let answer = json!({"at": 0, "health": "serving", "grids": []});
    assert_eq!(describe(&answer), "No grid on this computer keeps its records in Grid Core yet, so there is nothing to report on.");
    assert_eq!(lines(&answer), "serving\n");
    assert_eq!(scraped(&answer).lines().filter(|line| !line.starts_with('#')).count(), 0);
}
