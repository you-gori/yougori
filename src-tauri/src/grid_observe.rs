//! Whether the grids on this computer are healthy, and what they are doing.
//!
//! Grid Core hands a `Checkup` and a `Reading` over as values and binds no port; whether anything
//! serves them was left as a decision for the engine. This is that decision, and it is made the
//! narrow way: the engine reads them, the CLI asks for them through the one grids door, and a
//! monitoring agent on this computer can scrape them over HTTP on the loopback interface with a
//! token. Nothing is reachable from another computer and nothing is on by default.
//!
//! Three things are worth saying plainly rather than leaving to be discovered.
//!
//! **Every realm is opened read-only.** `Core::open` brings a realm up to this build's shape,
//! which is a write. A health endpoint that migrated somebody's realm because a monitoring agent
//! scraped it would be among the worst bugs this product could ship, so this goes through
//! `Store::open_for_reading`, which asks the operating system for a read-only handle and cannot
//! write the realm's file at all. A realm at a version this build does not know is still read, and
//! the checkup says which version it is, which is exactly what an operator needs to be told.
//!
//! **No key is needed and none is read.** Liveness, readiness and a reading are all statements
//! against the database; the realm's key signs permissions and seals the history and is not needed
//! to count anything. So this never opens anybody's vault, and a realm whose key has been lost is
//! still one this can report on, which is the moment an operator most needs it to.
//!
//! **The listener is off until somebody turns it on.** A desktop application that opens a port
//! nobody asked for is a desktop application that has made a decision for its owner. `serve` is
//! called by a command; nothing starts it at launch.
use crate::store::PlatformStore;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use crate::AppHandle;
use tauri::Manager;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use yougori_grid::core::health;
use yougori_grid::core::metrics;
use yougori_grid::core::store::Store;

/// The port the observation endpoint takes when nobody names one.
///
/// 7467, beside the Access Grid's hub (7465) and its tunnel (7466). Fixed rather than chosen at
/// random, because whoever is scraping it has to write it down somewhere, and a port that moves
/// every restart is a port nobody can scrape.
pub(crate) const PORT: u16 = 7467;

/// The longest one scrape may take to arrive. A monitoring agent that opens a connection and says
/// nothing must not hold one of this server's places for ever.
const PATIENCE: std::time::Duration = std::time::Duration::from_secs(10);

/// How many scrapes are served at once. A reading is a dozen statements against a database with
/// one writer, and a hundred agents asking at the same time would be a hundred read handles on
/// somebody's realm.
///
/// This counts answers, not connections. The cap used to be taken before the token was looked at,
/// which meant anything on this computer could open eight connections, say nothing, and hold the
/// endpoint shut for the ten seconds it waits, without ever knowing the token. What the cap is
/// protecting is the database, so it is taken where the database is read and nowhere earlier.
const AT_ONCE: usize = 8;

/// How many connections may be open at once, whether or not they have proved anything. Far above
/// `AT_ONCE`, because an unproved connection costs a socket and a read that gives up after
/// `PATIENCE`, and not a read handle on anybody's realm; this is only here so that a flood cannot
/// make this process spawn without bound.
const CONNECTIONS: usize = 64;

/// How many times accepting may fail in a row before this gives up on the listener.
///
/// A connection that died between the handshake and the accept, or a moment with no file handles
/// left, is this computer being busy and not this endpoint being over. Ending on the first of
/// them left the endpoint dead while everything else still said it was running, which, from a
/// health endpoint, is the one answer that must never be given.
const STUMBLES: u32 = 64;

/// Where this computer keeps its realms.
fn folder(app: &AppHandle) -> PathBuf {
    app.state::<PlatformStore>().data_folder("grid").join("core")
}

/// Every realm database on this computer, found by looking rather than by asking anything that
/// keeps a list, because a realm this build has never opened is still a realm.
fn realms_in(folder: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(folder) else { return Vec::new() };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_file() && path.extension().is_some_and(|extension| extension == "db"))
        .collect();
    found.sort();
    found
}

/// The name a realm is reported under: its file, without the folder.
///
/// Never the absolute path. A checkup travels into a log, a scrape and a support bundle, and an
/// absolute path on Windows carries the person's own name in it.
fn named(path: &Path) -> String {
    path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_else(|| "a grid".to_owned())
}

/// One realm, read without opening it the way a writer would.
///
/// `full` asks for the reading as well, which is a dozen more statements. Liveness does not need
/// it and a probe that runs every second should not pay for it.
fn look(path: &Path, full: bool, now: i64) -> Value {
    let file = named(path);
    let store = match Store::open_for_reading(path) {
        Ok(store) => store,
        Err(said) => {
            return json!({"grid": file, "health": "down", "notes": [format!("This grid could not be read: {said}")]});
        }
    };
    // The realm row is read once here and handed to both checks, so that each of them stays the
    // number of statements the operations document says it is.
    let realm = match store.realm() {
        Ok(realm) => realm,
        Err(said) => {
            return json!({"grid": file, "health": "down", "notes": [format!("What this grid is could not be read: {said}")]});
        }
    };
    let checkup = health::readiness(&store, realm.lifecycle, now);
    let mut answer = json!({
        "grid": file,
        "id": realm.id,
        "kind": if realm.kind == yougori_grid::core::realm::RealmKind::Research { "research" } else { "company" },
        "health": checkup.health.word(),
        "schemaVersion": checkup.schema_version,
        "buildSchemaVersion": checkup.build_schema_version,
        "lifecycle": checkup.lifecycle.word(),
        "headSequence": checkup.head_sequence,
        "notes": checkup.notes,
    });
    if full {
        let research = realm.capabilities.contains(&yougori_grid::core::realm::Capability::Research);
        match metrics::reading_over(&store, research, metrics::WINDOW, now) {
            Ok(reading) => answer["reading"] = serde_json::to_value(reading).unwrap_or(Value::Null),
            Err(said) => answer["notes"] = json!([format!("This grid could not be read for a reading: {said}")]),
        }
    }
    answer
}

/// What every realm on this computer says about itself.
pub(crate) fn checkups(app: &AppHandle, full: bool) -> Value {
    checkups_in(&folder(app), full)
}

/// The same, against a named folder. This is what the endpoint calls, so that serving a scrape
/// needs nothing but a path and can be put on a thread that is allowed to block.
fn checkups_in(folder: &Path, full: bool) -> Value {
    let now = chrono::Utc::now().timestamp();
    let grids: Vec<Value> = realms_in(folder).iter().map(|path| look(path, full, now)).collect();
    // The worst of them, because an operator watching one line needs the line to go red when any
    // one grid does. A computer holding no realm at all is serving: there is nothing wrong with
    // it, and reporting it as down would have every computer that has not moved yet look broken.
    let worst = if grids.iter().any(|grid| grid["health"] == "down") {
        "down"
    } else if grids.iter().any(|grid| grid["health"] == "degraded") {
        "degraded"
    } else {
        "serving"
    };
    json!({"at": now, "health": worst, "grids": grids})
}

/// What a person is told in one line.
pub(crate) fn describe(answer: &Value) -> String {
    let grids = answer["grids"].as_array().map(Vec::len).unwrap_or(0);
    match (grids, answer["health"].as_str().unwrap_or("serving")) {
        (0, _) => "No grid on this computer keeps its records in Grid Core yet, so there is nothing to report on.".to_owned(),
        (1, worst) => format!("One grid, {worst}."),
        (count, worst) => format!("{count} grids, and the worst of them is {worst}."),
    }
}

/// The reading, in the text format a monitoring agent scrapes.
///
/// Counts and gauges only, every one of them from a realm's own database, and the grid is named by
/// its file and its identifier. There is no person, no path, no model name beyond the plan an
/// administrator typed, and no value anywhere in it, which is the same rule
/// `metrics.rs` is already held to.
fn scraped(answer: &Value) -> String {
    let mut out = String::new();
    out.push_str("# HELP yougori_grid_health Whether a grid is serving: 2 serving, 1 degraded, 0 down.\n# TYPE yougori_grid_health gauge\n");
    let empty = Vec::new();
    let grids = answer["grids"].as_array().unwrap_or(&empty);
    for grid in grids {
        let tags = format!("grid=\"{}\"", grid["id"].as_str().unwrap_or("unknown"));
        let score = match grid["health"].as_str().unwrap_or("down") {
            "serving" => 2,
            "degraded" => 1,
            _ => 0,
        };
        out.push_str(&format!("yougori_grid_health{{{tags}}} {score}\n"));
    }
    for (name, help, at) in NUMBERS {
        out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} gauge\n"));
        for grid in grids {
            let tags = format!("grid=\"{}\"", grid["id"].as_str().unwrap_or("unknown"));
            let mut value = &grid["reading"];
            for step in at.split('.') {
                value = &value[step];
            }
            if let Some(number) = value.as_i64() {
                out.push_str(&format!("{name}{{{tags}}} {number}\n"));
            }
        }
    }
    out
}

/// Which numbers out of a reading are scraped, what each is called, and where it is read from.
///
/// A short list on purpose. Everything here is a number a realm already answers for itself, and
/// nothing in it grows a new query: a scrape is the same dozen statements `Core::reading` is.
const NUMBERS: &[(&str, &str, &str)] = &[
    ("yougori_grid_work_queued", "Work waiting for a computer.", "queue.queued"),
    ("yougori_grid_work_running", "Work a computer is answering.", "queue.running"),
    ("yougori_grid_leases_live", "Reservations still holding room on a computer.", "liveLeases"),
    ("yougori_grid_hosts_offering", "Computers offering part of themselves to the grid.", "hosts.offering"),
    ("yougori_grid_hosts_taking_work", "Computers that could take work right now.", "hosts.takingWork"),
    ("yougori_grid_approvals_waiting", "Requests nobody has answered yet.", "approvals.waiting"),
    ("yougori_grid_approvals_oldest_wait_seconds", "How long the oldest unanswered request has waited.", "approvals.oldestWait"),
    ("yougori_grid_workspaces_failed", "Desks that failed.", "workspaces.failed"),
    ("yougori_grid_workspaces_waiting", "Desks still without a computer.", "workspaces.waitingForAComputer"),
    ("yougori_grid_parcels_stuck", "Packed desk copies no computer has taken.", "workspaces.stuckParcels"),
    ("yougori_grid_credentials_refused", "Credential requests refused in the window.", "credentials.refusedInWindow"),
    ("yougori_grid_audit_events", "Events the sealed history holds.", "auditEvents"),
    ("yougori_grid_audit_events_never_exported", "Events that have never left this computer, which is what stops the history being trimmed.", "auditEventsNeverExported"),
];

/// A listener that is running, and the token it wants.
pub(crate) struct Observed {
    pub(crate) port: u16,
    pub(crate) token: String,
    /// Kept so that `serve` can tell a listener that is still answering from one that gave up.
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Observed {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// What this computer is serving, if anything.
#[derive(Default)]
pub(crate) struct Observation {
    pub(crate) live: Mutex<Option<Observed>>,
}

/// Starts serving `/healthz` and `/metrics` on the loopback interface, and hands back the token a
/// scraper has to present.
///
/// **Loopback only, and that is a fact about the bind rather than a check.** It binds
/// `127.0.0.1`, so there is no address on any other interface for anything outside this computer
/// to reach, and no option here can change that. A company that wants this scraped from somewhere
/// else puts their own agent on this computer, which is how every other local endpoint in this
/// product is reached.
///
/// **The token is how the rest of the engine's surface is authenticated, carried onto a port.**
/// The engine's own door is a named pipe with a protected access list naming this Windows user, or
/// a socket this user owns with mode 0600: same user, nobody else. A TCP port has no such thing,
/// so what stands in for it is a secret this process makes at random and hands back to whoever
/// asked for it. It is never written to a file, never logged, never put in an audit reason and
/// never in a command line; the person who started the endpoint is handed it once and gives it to
/// their agent. It goes away when the endpoint stops.
pub(crate) async fn serve(app: &AppHandle, port: Option<u16>) -> Result<Value, String> {
    let state = app.state::<Arc<Observation>>();
    let mut live = state.live.lock().await;
    // "Already running" has to mean it is still answering. The accept loop gives up after
    // `STUMBLES` failures in a row, and nothing told this: every later call handed back the port
    // and the token of a listener that had ended, so an agent scraped a dead address with a
    // token that no longer meant anything and nobody was told why. A finished task is cleared
    // here and the endpoint is started again below, with a new token, which is the only honest
    // answer to "is it on".
    if live.as_ref().is_some_and(|running| running.task.is_finished()) {
        live.take();
    }
    if let Some(running) = live.as_ref() {
        return Ok(json!({"port": running.port, "token": running.token, "already": true}));
    }
    let wanted = port.unwrap_or(PORT);
    let address = SocketAddr::from(([127, 0, 0, 1], wanted));
    let listener = TcpListener::bind(address)
        .await
        .map_err(|_| format!("Port {wanted} on this computer is already in use, so the health endpoint was not started. Choose another port with --port, or stop what is using that one."))?;
    let port = listener.local_addr().map_err(|error| error.to_string())?.port();
    let token = format!("{}{}", uuid::Uuid::new_v4().simple(), uuid::Uuid::new_v4().simple());
    let secret = token.clone();
    let realms = folder(app);
    let task = tokio::spawn(async move {
        let places = Arc::new(tokio::sync::Semaphore::new(AT_ONCE));
        let mut clients = tokio::task::JoinSet::new();
        let mut stumbles = 0u32;
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let socket = match accepted {
                        Ok((socket, _)) => {
                            stumbles = 0;
                            socket
                        }
                        Err(_) => {
                            stumbles += 1;
                            if stumbles >= STUMBLES {
                                break;
                            }
                            // Long enough not to spin on a listener that is briefly unhappy,
                            // short enough that a scrape a moment later is still answered.
                            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                            continue;
                        }
                    };
                    while clients.try_join_next().is_some() {}
                    if clients.len() >= CONNECTIONS {
                        let mut socket = socket;
                        tokio::spawn(async move { answer(&mut socket, 503, "text/plain; charset=utf-8", b"This computer is holding as many connections as it allows itself.\n".to_vec()).await });
                        continue;
                    }
                    let (secret, realms, places) = (secret.clone(), realms.clone(), places.clone());
                    clients.spawn(async move { one_scrape(socket, &secret, &places, realms).await });
                }
                Some(_) = clients.join_next() => {}
            }
        }
    });
    *live = Some(Observed { port, token: token.clone(), task });
    Ok(json!({"port": port, "token": token, "already": false}))
}

/// One connection, from the request to the answer.
///
/// The order here is the point. The token is checked on what was read and nothing else, so an
/// unproved caller is answered and gone without ever having been near a realm. Only then is a
/// place taken, and a place is for reading the databases: that is what there are eight of, and
/// what a ninth caller is told to come back for.
pub(crate) async fn one_scrape(mut socket: tokio::net::TcpStream, secret: &str, places: &tokio::sync::Semaphore, realms: PathBuf) {
    let Ok(Ok((header, _))) = tokio::time::timeout(PATIENCE, crate::host_files::read_http(&mut socket)).await else { return };
    if !authorised(&header, secret) {
        answer(&mut socket, 401, "text/plain; charset=utf-8", b"This endpoint needs the token the engine handed out when it was started.\n".to_vec()).await;
        return;
    }
    let path = header.lines().next().unwrap_or_default().split(' ').nth(1).unwrap_or_default().to_owned();
    if path != "/healthz" && path != "/metrics" {
        answer(&mut socket, 404, "text/plain; charset=utf-8", b"This endpoint answers /healthz and /metrics.\n".to_vec()).await;
        return;
    }
    // Refused rather than queued: a queue in front of a database with one writer is the thing
    // this cap exists to prevent.
    let Ok(_place) = places.try_acquire() else {
        answer(&mut socket, 503, "text/plain; charset=utf-8", b"This computer is already answering as many scrapes as it allows itself.\n".to_vec()).await;
        return;
    };
    // A dozen statements against every realm on this computer, on a thread that is allowed to
    // take its time. Run where it was, it stopped every other thing this runtime was doing,
    // including the connections this same endpoint had already accepted.
    let full = path == "/metrics";
    let Ok(found) = tokio::task::spawn_blocking(move || checkups_in(&realms, full)).await else {
        answer(&mut socket, 503, "text/plain; charset=utf-8", b"This computer could not read its grids just now.\n".to_vec()).await;
        return;
    };
    let (status, kind, body) = if full {
        (200, "text/plain; version=0.0.4; charset=utf-8", scraped(&found).into_bytes())
    } else {
        // Not serving is 503, so an agent that reads only the status gets the answer. Degraded is
        // still 200, because a grid that is answering is answering, and paging somebody at three
        // in the morning for a warning is how warnings get turned off.
        let status = if found["health"] == "down" { 503 } else { 200 };
        (status, "text/plain; charset=utf-8", lines(&found).into_bytes())
    };
    answer(&mut socket, status, kind, body).await;
}

/// Whether a request carries the token, compared without saying how far it got.
///
/// A comparison that stops at the first byte that differs takes longer the more of the token it
/// was given, and that difference is measurable over a loopback connection somebody can make as
/// often as they like: it turns guessing a 64-character secret from hopeless into a few thousand
/// tries. Every byte is looked at, whatever the first one says.
fn authorised(header: &str, secret: &str) -> bool {
    let wanted = format!("Bearer {secret}");
    header
        .lines()
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        .any(|(_, value)| same_secret(value.trim(), &wanted))
}

/// Two strings, compared in the time the longer of them takes, whatever they hold.
fn same_secret(given: &str, wanted: &str) -> bool {
    let (given, wanted) = (given.as_bytes(), wanted.as_bytes());
    let mut difference = u8::from(given.len() != wanted.len());
    for index in 0..given.len().max(wanted.len()) {
        difference |= given.get(index).copied().unwrap_or(0) ^ wanted.get(index).copied().unwrap_or(0);
    }
    difference == 0
}

/// Stops serving, and the token stops being a token.
pub(crate) async fn stop(app: &AppHandle) -> Result<Value, String> {
    let state = app.state::<Arc<Observation>>();
    let was = state.live.lock().await.take();
    Ok(json!({"stopped": was.is_some()}))
}

/// What `/healthz` says, in sentences rather than in a shape, because the first thing anybody does
/// with a health endpoint is read it with their eyes.
fn lines(found: &Value) -> String {
    let mut out = format!("{}\n", found["health"].as_str().unwrap_or("serving"));
    for grid in found["grids"].as_array().unwrap_or(&Vec::new()) {
        out.push_str(&format!("{} {}\n", grid["health"].as_str().unwrap_or("down"), grid["id"].as_str().unwrap_or("unknown")));
        for note in grid["notes"].as_array().unwrap_or(&Vec::new()) {
            if let Some(note) = note.as_str() {
                out.push_str(&format!("  {note}\n"));
            }
        }
    }
    out
}

async fn answer(socket: &mut tokio::net::TcpStream, status: u16, kind: &str, body: Vec<u8>) {
    let head = format!("HTTP/1.1 {status} \r\ncontent-type: {kind}\r\ncontent-length: {}\r\nconnection: close\r\ncache-control: no-store\r\n\r\n", body.len());
    let _ = socket.write_all(head.as_bytes()).await;
    let _ = socket.write_all(&body).await;
    let _ = socket.flush().await;
}

#[cfg(test)]
mod tests;
