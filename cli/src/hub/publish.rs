//! Publishing to the Hub and the other signed-in actions (star, fork, report, delete). Every
//! upload is checked, scanned for credentials and shown before it goes up; versions never change.
//! An upload that stops (a lost connection, Ctrl+C) carries on the next time the same version is
//! published: the website keeps an unfinished upload for 24 hours, and each new one counts toward
//! the day's 20.
use super::{
    client,
    format::{self, Folder, Tool},
    refs::{self, Ref},
    review,
    scan::{self, Files},
    tools, unicode,
};
use crate::cli_ui as ui;
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
};

/// At most this much JSON per batch of files, whatever the website allows.
pub const BATCH_LIMIT: usize = 600 * 1024;
/// Room left for the request around a batch.
const MARGIN: usize = 2 * 1024;
/// The website's limits for the manifest and the review (`server/hub/rules.mjs`).
pub const MANIFEST_BYTES: usize = 64 * 1024;
pub const REVIEW_BYTES: usize = 128 * 1024;
/// Room left around the upload's description in the engine's 1 MiB request.
const FRAME_MARGIN: usize = 4 * 1024;

/// What goes up: the upload document, the files, and what the person is shown first.
pub struct Upload {
    pub kind: &'static str,
    pub name: String,
    pub version: String,
    pub license: String,
    pub body: Value,
    pub files: Files,
    pub review: Value,
}

/// The value of the one top-level `FIELD:` line of a marker file (at the start of a line, not
/// indented), as the website reads it: cut at ` #`, trimmed and unquoted. `None` unless there is
/// exactly one.
pub fn top_level(text: &str, field: &str) -> Option<String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let found: Vec<&str> = text
        .split(['\n', '\r', '\u{2028}', '\u{2029}'])
        .filter_map(|line| line.strip_prefix(field)?.trim_start_matches([' ', '\t']).strip_prefix(':'))
        .collect();
    let [value] = found.as_slice() else { return None };
    let cut = value.char_indices().find(|(at, c)| unicode::js_space(*c) && value[at + c.len_utf8()..].starts_with('#')).map_or(*value, |(at, _)| &value[..at]);
    let value = unicode::js_trim(cut);
    let quoted = value.chars().count() >= 2 && ((value.starts_with('"') && value.ends_with('"')) || (value.starts_with('\'') && value.ends_with('\'')));
    Some(if quoted { value[1..value.len() - 1].to_owned() } else { value.to_owned() })
}

/// The largest part of one file in a request: about 560 KB once base64-encoded.
pub const PART: usize = 420 * 1024;

/// Batches of `{path, content}` entries whose JSON stays under `budget` bytes each, in path
/// order. Small files are packed together; a file too big for one request goes in consecutive
/// parts, each `{path, content, offset}` with `offset` the bytes of that file already sent.
pub fn batches(files: &Files, budget: usize) -> Result<Vec<Vec<Value>>, String> {
    batches_from(files, &Progress::default(), budget)
}

/// [`batches`] for what is still to send: files the website has whole are left out, and a file
/// sent partly continues from its offset.
pub fn batches_from(files: &Files, progress: &Progress, budget: usize) -> Result<Vec<Vec<Value>>, String> {
    let overhead = serde_json::to_string(&json!({"files": []})).map(|s| s.len()).unwrap_or(12);
    let length = |entry: &Value| serde_json::to_string(entry).map(|s| s.len()).unwrap_or(usize::MAX) + 1;
    let mut pieces: Vec<Value> = Vec::new();
    for (path, bytes) in files {
        if progress.done.contains(path) {
            continue;
        }
        let start = progress.partial.get(path).map_or(0, |sent| (*sent as usize).min(bytes.len()));
        if start == 0 {
            let whole = json!({"path": path, "content": B64.encode(bytes)});
            if overhead + length(&whole) <= budget {
                pieces.push(whole);
                continue;
            }
        }
        let room = budget.saturating_sub(overhead + 128 + serde_json::to_string(path).map_or(0, |p| p.len())) / 4 * 3;
        let part = PART.min(room);
        if part < 1024 {
            return Err(format!("The Hub accepts requests too small to send {}. Try again later.", scan::shown(path)));
        }
        let rest = &bytes[start..];
        if rest.is_empty() {
            pieces.push(json!({"path": path, "content": "", "offset": start}));
        }
        for (index, chunk) in rest.chunks(part).enumerate() {
            pieces.push(json!({"path": path, "content": B64.encode(chunk), "offset": start + index * part}));
        }
    }
    let mut all = Vec::new();
    let mut current: Vec<Value> = Vec::new();
    let mut size = overhead;
    for piece in pieces {
        let piece_length = length(&piece);
        if size + piece_length > budget && !current.is_empty() {
            all.push(std::mem::take(&mut current));
            size = overhead;
        }
        size += piece_length;
        current.push(piece);
    }
    if !current.is_empty() {
        all.push(current);
    }
    Ok(all)
}

fn file_list(files: &Files) -> Vec<Value> {
    files.iter().map(|(path, bytes)| json!({"path": path, "bytes": bytes.len(), "sha256": scan::sha256_hex(bytes)})).collect()
}

/// Reads, checks and scans a template folder for upload.
pub fn template(folder: &Path) -> Result<(Upload, Folder), String> {
    let collected = scan::collect(folder)?;
    if !collected.files.contains_key(format::TEMPLATE_FILE) {
        return Err(format!("{} has no {}. Start one with yougori template new NAME, or turn running sandboxes into one with yougori template capture ENV.", folder.display(), format::TEMPLATE_FILE));
    }
    let checked = format::template(&collected.files).map_err(|problems| tools::list("This template", &problems))?;
    let publishing = format::publishing_problems(&checked);
    if !publishing.is_empty() {
        return Err(tools::list("This template", &publishing));
    }
    let findings = scan::scan(&collected.files);
    if !findings.refused.is_empty() {
        return Err(tools::list("This template's folder", &findings.refused));
    }
    let notices: Vec<String> = findings.wallet_notice().into_iter().collect();
    let review = review::template(&checked, &notices, &Default::default());
    let template = &checked.template;
    let body = json!({
        "kind": "template", "name": template.name(), "version": template.version(), "title": template.title(),
        "summary": template.summary, "license": template.license, "topics": template.topics, "changelog": template.changelog,
        "manifest": template.manifest(), "review": review, "files": file_list(&collected.files),
    });
    Ok((Upload { kind: "template", name: template.name().into(), version: template.version().into(), license: template.license.clone().unwrap_or_default(), body, files: collected.files, review }, checked))
}

/// Reads, checks and scans a tool folder for upload.
pub fn tool(folder: &Path) -> Result<(Upload, Tool), String> {
    let (tool, files, findings) = tools::read_folder(folder)?;
    if !findings.refused.is_empty() {
        return Err(tools::list("This tool's folder", &findings.refused));
    }
    let notices: Vec<String> = findings.wallet_notice().into_iter().collect();
    let review = review::tool(&tool, &notices);
    let body = json!({
        "kind": "tool", "name": tool.name(), "version": tool.version(), "title": tool.title(),
        "summary": tool.summary, "license": tool.license, "topics": tool.topics, "changelog": tool.changelog,
        "manifest": tool.manifest(), "review": review, "files": file_list(&files),
    });
    Ok((Upload { kind: "tool", name: tool.name().into(), version: tool.version().into(), license: tool.license.clone().unwrap_or_default(), body, files, review }, tool))
}

fn json_size(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(usize::MAX, |bytes| bytes.len())
}

/// Everything the website or the engine would refuse in an upload, found before anything is
/// sent: the marker lines the website reads, the manifest and review sizes and the review's form,
/// and an upload description too large for one request to the engine.
pub fn preflight(upload: &Upload) -> Result<(), String> {
    let marker = if upload.kind == "tool" { format::TOOL_FILE } else { format::TEMPLATE_FILE };
    let text = upload.files.get(marker).and_then(|bytes| scan::text(bytes)).ok_or_else(|| format!("{marker} must be UTF-8 text."))?;
    for (field, value) in [("name", upload.name.as_str()), ("version", upload.version.as_str())] {
        if top_level(text, field).as_deref() != Some(value) {
            return Err(format!("{marker} must say {field}: {value} on exactly one line of its own at the top (not indented, not inside {{…}}), as the Hub reads it. Write it that way, then publish again."));
        }
    }
    if let Some(kind) = top_level(text, "kind").filter(|kind| kind != upload.kind) {
        return Err(format!("{marker} says kind: {}, but this is a {}.", scan::shown(&kind), upload.kind));
    }
    let manifest = json_size(&upload.body["manifest"]);
    if manifest > MANIFEST_BYTES {
        return Err(format!("{marker} is too large for the Hub once read ({} of at most 64 KB). Shorten it, then publish again.", scan::size(manifest as u64)));
    }
    let review_size = json_size(&upload.body["review"]);
    if review_size > REVIEW_BYTES {
        return Err(format!("The review built from the files is too large for the Hub ({} of at most 128 KB): there are too many sandboxes, tools, questions or steps to show. Make the {} smaller, then publish again.", scan::size(review_size as u64), upload.kind));
    }
    if let Some(problem) = review::shape_problem(&upload.body["review"]) {
        return Err(format!("{problem} Nothing was uploaded."));
    }
    let whole = json_size(&json!({"path": "/hub/uploads", "body": upload.body}));
    if whole + FRAME_MARGIN > crate::wire::MAX_REQUEST {
        let parts = [
            ("the list of files", json_size(&upload.body["files"]), "Leave files out with .yougoriignore, or use shorter paths."),
            ("the manifest", manifest, "Shorten the marker file."),
            ("the review", review_size, "Make the template smaller."),
            ("the changelog", json_size(&upload.body["changelog"]), "Shorten the changelog."),
        ];
        let (part, _, advice) = parts.iter().max_by_key(|(_, size, _)| *size).copied().unwrap_or(parts[0]);
        return Err(format!("The description of this upload is too large to send ({} of at most {}); {part} is the largest part. {advice} Nothing was uploaded.", scan::size(whole as u64), scan::size((crate::wire::MAX_REQUEST - FRAME_MARGIN) as u64)));
    }
    Ok(())
}

/// Leaving a question says what was left as it was, rather than that work keeps running.
fn left(error: String, said: &str) -> String {
    if error == ui::CANCELLED || error == ui::BACK { crate::wire::cancelled(said) } else { error }
}

/// The signed-in account as the Hub sees it: its publisher name, if any, and whether it is the owner.
async fn me() -> Result<Value, String> {
    client::signed_in().await?;
    client::account("/hub/me", None).await
}

/// The account's publisher name: its own, or the one chosen now for the first upload.
fn publisher(me: &Value, chosen: Option<&str>, interactive: bool) -> Result<String, String> {
    let owner = me["owner"] == true;
    if let Some(own) = me["publisher"].as_str() {
        if chosen.is_some_and(|chosen| !chosen.eq_ignore_ascii_case(own)) {
            return Err(format!("Your publisher name is {own}. Publish as {own}/NAME, without --publisher."));
        }
        return Ok(own.to_owned());
    }
    let check = |name: &str| -> Result<String, String> {
        let name = name.trim().to_ascii_lowercase();
        if !refs::valid_name(&name) {
            return Err(format!("Use {}.", refs::NAME_RULE));
        }
        if !owner && refs::reserved(&name) {
            return Err(format!("The publisher name {name} is reserved. Choose another name."));
        }
        Ok(name)
    };
    match chosen {
        Some(name) => check(name),
        None if interactive => {
            let _raw = ui::Raw::on()?;
            ui::input("Your publisher name on the Hub (it is public and cannot change)", "", false, &check).map_err(|e| left(e, "Cancelled. Nothing was uploaded."))
        }
        None => Err("This account has no publisher name yet. Choose one with --publisher NAME: lowercase letters, digits, - or _. It is public and shared with the model library.".into()),
    }
}

fn upload_id(value: &Value) -> Result<String, String> {
    value["upload"]["id"].as_str()
        .filter(|id| valid_id(id))
        .map(str::to_owned)
        .ok_or_else(|| "The Hub did not start the upload. Try again in a moment.".into())
}

fn valid_id(id: &str) -> bool {
    id.len() <= 64 && !id.is_empty() && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What of an upload the website already has, kept until the version is published.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Progress {
    pub id: String,
    pub item: String,
    pub version: String,
    pub kind: String,
    pub digest: String,
    /// Unix seconds when the website drops the unfinished upload.
    pub expires_at: i64,
    /// The largest batch the website takes, when it said.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub batch_bytes: Option<u64>,
    /// Files the website has whole.
    #[serde(default)]
    pub done: BTreeSet<String>,
    /// Bytes sent so far of a file going up in parts.
    #[serde(default)]
    pub partial: BTreeMap<String, u64>,
}

impl Progress {
    /// Notes what a batch the website accepted carried.
    fn sent(&mut self, batch: &[Value], files: &Files) {
        for entry in batch {
            let Some(path) = entry["path"].as_str() else { continue };
            let content = entry["content"].as_str().unwrap_or_default();
            let padding = content.bytes().rev().take_while(|b| *b == b'=').count();
            let length = (content.len() / 4 * 3).saturating_sub(padding) as u64;
            let end = entry["offset"].as_u64().unwrap_or(0) + length;
            if files.get(path).is_some_and(|bytes| end >= bytes.len() as u64) {
                self.partial.remove(path);
                self.done.insert(path.to_owned());
            } else {
                self.partial.insert(path.to_owned(), end);
            }
        }
    }
    /// The website asked for a file again from `from`.
    fn resend(&mut self, path: &str, from: u64) {
        self.done.remove(path);
        if from == 0 {
            self.partial.remove(path);
        } else {
            self.partial.insert(path.to_owned(), from);
        }
    }
}

/// Where unfinished uploads are remembered: `~/.yougori/hub/uploads/PUBLISHER/NAME@VERSION.json`.
pub struct Uploads {
    pub root: PathBuf,
}

impl Uploads {
    pub fn standard() -> Result<Uploads, String> {
        Ok(Uploads { root: client::home()?.join("hub").join("uploads") })
    }

    fn path(&self, item: &str, version: &str) -> Option<PathBuf> {
        let (publisher, name) = item.split_once('/')?;
        (refs::valid_name(publisher) && refs::valid_name(name) && refs::parse_version(version).is_ok()).then(|| self.root.join(publisher).join(format!("{name}@{version}.json")))
    }

    /// The unfinished upload of exactly these files, while the website still keeps it.
    pub fn load(&self, item: &str, version: &str, kind: &str, digest: &str, now: i64) -> Option<Progress> {
        let path = self.path(item, version)?;
        let progress: Progress = serde_json::from_slice(&std::fs::read(&path).ok()?).ok()?;
        let same = progress.item == item && progress.version == version && progress.kind == kind && progress.digest == digest && valid_id(&progress.id);
        // Ten minutes are left for the rest of the upload; an older one starts again.
        if !same || progress.expires_at < now + 600 {
            let _ = std::fs::remove_file(&path);
            return None;
        }
        Some(progress)
    }

    /// Saves what went up; a failure only means the next try starts again.
    pub fn save(&self, progress: &Progress) {
        let Some(path) = self.path(&progress.item, &progress.version) else { return };
        let Some(folder) = path.parent() else { return };
        if std::fs::create_dir_all(folder).is_err() {
            return;
        }
        if let Ok(mut file) = tempfile::Builder::new().prefix(".partial-").tempfile_in(folder) {
            if std::io::Write::write_all(&mut file, &serde_json::to_vec_pretty(progress).unwrap_or_default()).is_ok() {
                let _ = file.persist(&path);
            }
        }
    }

    pub fn forget(&self, item: &str, version: &str) {
        if let Some(path) = self.path(item, version) {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// How requests reach the website: through the engine, which adds the account.
trait Transport {
    async fn call(&self, path: &str, body: Option<Value>) -> Result<Value, String>;
    /// How long to wait before each new try of a request that failed on the way.
    fn waits(&self) -> Vec<Duration> {
        vec![Duration::from_secs(2), Duration::from_secs(5)]
    }
}

struct ThroughEngine;

impl Transport for ThroughEngine {
    async fn call(&self, path: &str, body: Option<Value>) -> Result<Value, String> {
        client::account(path, body).await
    }
}

/// A failure on the way (no connection, an interrupted or late answer, the website's own
/// trouble), worth trying again: a part that did arrive is named by the website on the next try.
fn transient(error: &str) -> bool {
    error.starts_with("Cannot reach the Yougori Network")
        || error.contains("answer was interrupted")
        || error.contains("returned HTTP 5")
        || error.contains("outcome may be unknown")
}

/// `Send PATH from byte N`: the website has a different part of a file than was sent.
fn resend_from(error: &str) -> Option<(String, u64)> {
    let (path, from) = error.strip_prefix("Send ")?.rsplit_once(" from byte ")?;
    Some((path.to_owned(), from.trim_end_matches('.').parse().ok()?))
}

/// The upload is no longer on the website: it expired, or it never was.
fn gone(error: &str) -> bool {
    error.starts_with("This upload does not exist") || error.starts_with("This upload expired")
}

enum Failure {
    Gone,
    Resend(String, u64),
    Other(String),
}

async fn with_retries<T: Transport>(transport: &T, path: &str, body: Value) -> Result<Value, String> {
    let mut waits = transport.waits().into_iter();
    loop {
        match transport.call(path, Some(body.clone())).await {
            Err(error) if transient(&error) => match waits.next() {
                Some(wait) => tokio::time::sleep(wait).await,
                None => return Err(error),
            },
            other => return other,
        }
    }
}

async fn start<T: Transport>(transport: &T, uploads: &Uploads, upload: &Upload, item: &str, digest: &str) -> Result<Progress, String> {
    let started = transport.call("/hub/uploads", Some(upload.body.clone())).await.map_err(|error| format!("{error} Nothing was uploaded."))?;
    let progress = Progress {
        id: upload_id(&started)?,
        item: item.to_owned(),
        version: upload.version.clone(),
        kind: upload.kind.to_owned(),
        digest: digest.to_owned(),
        expires_at: started["upload"]["expiresAt"].as_i64().unwrap_or_else(|| super::instances::now() as i64 + 23 * 3600),
        batch_bytes: started["upload"]["maxBatchBytes"].as_u64(),
        ..Default::default()
    };
    uploads.save(&progress);
    Ok(progress)
}

async fn send_files<T: Transport>(transport: &T, uploads: &Uploads, progress: &mut Progress, upload: &Upload) -> Result<(), Failure> {
    let limit = progress.batch_bytes.map(|bytes| bytes as usize).filter(|bytes| *bytes < BATCH_LIMIT).unwrap_or(BATCH_LIMIT);
    let batches = batches_from(&upload.files, progress, limit.saturating_sub(MARGIN).max(1024)).map_err(Failure::Other)?;
    for batch in batches {
        match with_retries(transport, &format!("/hub/uploads/{}/files", progress.id), json!({"files": batch})).await {
            Ok(_) => {
                progress.sent(&batch, &upload.files);
                uploads.save(progress);
            }
            Err(error) => {
                return Err(match resend_from(&error) {
                    Some((path, from)) => Failure::Resend(path, from),
                    None if gone(&error) => Failure::Gone,
                    None => Failure::Other(error),
                })
            }
        }
    }
    Ok(())
}

/// Sends an upload, carrying on an unfinished one of the same files. A part the website has
/// differently, an upload it forgot and a failure on the way are each handled; anything else
/// stops with what to do next, and the next publish carries on from there.
async fn send<T: Transport>(transport: &T, uploads: &Uploads, upload: &Upload, item: &str, now: i64) -> Result<Value, String> {
    let digest = scan::digest_of(&upload.files);
    let mut progress = match uploads.load(item, &upload.version, upload.kind, &digest, now) {
        Some(progress) => progress,
        None => start(transport, uploads, upload, item, &digest).await?,
    };
    let kept = "The files sent so far are kept by the Hub for 24 hours: run the same publish command again to carry on.";
    let mut restarted = false;
    let mut corrections = 0;
    loop {
        match send_files(transport, uploads, &mut progress, upload).await {
            Ok(()) => {}
            Err(Failure::Resend(path, from)) if corrections < 8 && upload.files.contains_key(&path) => {
                corrections += 1;
                progress.resend(&path, from);
                uploads.save(&progress);
                continue;
            }
            Err(Failure::Gone) if !restarted => {
                restarted = true;
                uploads.forget(item, &upload.version);
                progress = start(transport, uploads, upload, item, &digest).await?;
                continue;
            }
            Err(Failure::Resend(path, from)) => return Err(format!("Send {path} from byte {from}: the Hub kept asking for parts again. {kept}")),
            Err(Failure::Gone) => return Err("The Hub dropped this upload twice. Try again later; nothing was published.".into()),
            Err(Failure::Other(error)) => return Err(format!("{error}\n{kept}")),
        }
        match with_retries(transport, &format!("/hub/uploads/{}/finish", progress.id), json!({})).await {
            Ok(value) => {
                uploads.forget(item, &upload.version);
                return Ok(value);
            }
            // An earlier try finished it and its answer was lost on the way.
            Err(error) if error.starts_with("This upload is already published") => {
                uploads.forget(item, &upload.version);
                return Ok(json!({}));
            }
            Err(error) if error.contains("not arrived yet") && corrections < 8 => {
                corrections += 1;
                progress.done.clear();
                progress.partial.clear();
                uploads.save(&progress);
            }
            Err(error) if gone(&error) && !restarted => {
                restarted = true;
                uploads.forget(item, &upload.version);
                progress = start(transport, uploads, upload, item, &digest).await?;
            }
            Err(error) if gone(&error) => return Err(format!("{error} Nothing was published.")),
            Err(error) => {
                // A refusal at the end (a key found by the website's scan, a version taken) needs
                // a change and a new version or files; the upload is not carried on.
                if !transient(&error) {
                    uploads.forget(item, &upload.version);
                    return Err(format!("{error} Nothing was published."));
                }
                return Err(format!("{error}\n{kept}"));
            }
        }
    }
}

/// `template publish` and `tool publish`.
pub async fn publish(kind: &str, folder: &str, yes: bool, chosen: Option<&str>, interactive: bool) -> Result<Value, String> {
    let path = Path::new(folder);
    let mut upload = if kind == "tool" { tool(path)?.0 } else { template(path)?.0 };
    preflight(&upload)?;
    let bytes: u64 = upload.files.values().map(|b| b.len() as u64).sum();
    let me = if interactive { ui::busy("Checking your Yougori account", me()).await? } else { me().await? };
    let publisher = publisher(&me, chosen, interactive)?;
    let item = format!("{publisher}/{}", upload.name);
    let site = client::website();
    let page = format!("{site}/hub/{item}");
    let uploads = Uploads::standard()?;
    let now = super::instances::now() as i64;
    let resuming = uploads.load(&item, &upload.version, upload.kind, &scan::digest_of(&upload.files), now).is_some();
    let mut summary = vec![
        format!("{item} {} · {} · {} {} · {}", upload.version, upload.license, upload.files.len(), if upload.files.len() == 1 { "file" } else { "files" }, scan::size(bytes)),
        format!("The upload is public and open source: anyone can read every file at {page}."),
        "Versions can never be replaced: a change needs a higher version.".into(),
    ];
    if resuming {
        summary.push("An earlier upload of these exact files did not finish; it carries on from where it stopped.".into());
    }
    for warning in upload.review["warnings"].as_array().into_iter().flatten().filter_map(Value::as_str) {
        summary.push(format!("Review: {}", scan::shown(warning)));
    }
    if interactive && !yes {
        let _raw = ui::Raw::on()?;
        ui::intro(&format!("Publish a {kind}"), &item);
        ui::lines(summary.iter().map(|line| format!("{}  {}", ui::muted("│"), line)).collect());
        let choice = ui::select(&format!("Publish {item} {}?", upload.version), &[], &[ui::Choice::new("Publish", "public and open source, for everyone"), ui::Choice::new("Cancel", "nothing is uploaded")], 0).map_err(|e| left(e, "Cancelled. Nothing was uploaded."))?;
        if choice != 0 {
            return Err(crate::wire::cancelled("Cancelled. Nothing was uploaded."));
        }
    } else if !yes {
        return Err(format!("Publishing is public and cannot be undone for this version. Read the summary with yougori {kind} check {}, then add --yes. Nothing was uploaded.", shell_words::quote(folder)));
    }
    upload.body["publisher"] = json!(publisher);
    let sending = send(&ThroughEngine, &uploads, &upload, &item, now);
    let finished = if interactive { ui::busy(&format!("Uploading {item} {}", upload.version), sending).await? } else { sending.await? };
    let detail = if finished["item"].is_object() { finished["item"].clone() } else { finished };
    Ok(json!({
        "published": item, "kind": kind, "version": upload.version, "files": upload.files.len(), "bytes": bytes,
        "verified": detail["verified"], "page": page, "item": detail,
        "run": if kind == "tool" { format!("yougori tool add hub/{item}") } else { format!("yougori run hub/{item}") },
    }))
}

/// What Ctrl+C says during a publish.
pub const STOPPED: &str = "Stopped. Nothing was published. Any files already sent are kept by the Hub for 24 hours: run the same publish command again to carry on.";

/// A Hub reference for the signed-in actions, with the website in effect.
pub fn item(text: &str) -> Result<Ref, String> {
    refs::parse(text, &client::website())
}

fn path(reference: &Ref, action: &str) -> String {
    format!("/hub/items/{}/{}/{action}", reference.publisher, reference.name)
}

pub async fn star(reference: &Ref, starred: bool) -> Result<Value, String> {
    client::signed_in().await?;
    client::account(&path(reference, "star"), Some(json!({"starred": starred}))).await
}

/// The details of a report, by the website's rules: at most 2000 characters as it counts them,
/// nothing hidden.
fn report_details(details: &str) -> Result<String, String> {
    let problems = format::text_problems(details, "--details", 2000, true);
    if let Some(problem) = problems.first() {
        return Err(problem.clone());
    }
    Ok(unicode::js_trim(details).to_owned())
}

pub async fn report(reference: &Ref, reason: &str, details: Option<&str>) -> Result<Value, String> {
    if !matches!(reason, "harmful" | "stolen" | "abuse" | "other") {
        return Err("Choose a reason: --reason harmful, stolen, abuse or other.".into());
    }
    let details = details.map(report_details).transpose()?;
    client::signed_in().await?;
    let mut body = json!({"reason": reason});
    if let Some(details) = details.filter(|d| !d.is_empty()) {
        body["details"] = json!(details);
    }
    client::account(&path(reference, "report"), Some(body)).await
}

pub async fn delete(reference: &Ref) -> Result<Value, String> {
    client::signed_in().await?;
    client::account(&path(reference, "delete"), Some(json!({"confirm": reference.item()}))).await
}

pub async fn fork(reference: &Ref, name: Option<&str>, chosen: Option<&str>, interactive: bool) -> Result<Value, String> {
    if let Some(name) = name {
        if !refs::valid_name(name) {
            return Err(format!("{} is not a Hub name: use {}.", scan::shown(name), refs::NAME_RULE));
        }
    }
    let publisher = publisher(&me().await?, chosen, interactive)?;
    let mut body = json!({"publisher": publisher});
    if let Some(name) = name {
        body["name"] = json!(name);
    }
    let value = client::account(&path(reference, "fork"), Some(body)).await?;
    Ok(if value["item"].is_object() { value["item"].clone() } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    };

    #[test]
    fn batches_stay_under_the_cap_and_keep_every_file() {
        let files: Files = (0..40).map(|i| (format!("assets/file-{i:02}.bin"), vec![i as u8; 30_000 + i * 997])).collect();
        let budget = BATCH_LIMIT - MARGIN;
        let batches = batches(&files, budget).unwrap();
        assert!(batches.len() > 1);
        let mut seen = Vec::new();
        for batch in &batches {
            let body = serde_json::to_string(&json!({"files": batch})).unwrap();
            assert!(body.len() < budget, "{} >= {budget}", body.len());
            for entry in batch {
                seen.push(entry["path"].as_str().unwrap().to_owned());
                let bytes = B64.decode(entry["content"].as_str().unwrap()).unwrap();
                assert_eq!(&bytes, &files[entry["path"].as_str().unwrap()]);
            }
        }
        assert_eq!(seen, files.keys().cloned().collect::<Vec<_>>());
        assert!(batches.iter().flatten().all(|entry| entry.get("offset").is_none()), "small files go whole");
        assert_eq!(super::batches(&Files::new(), budget).unwrap().len(), 0);
    }

    #[test]
    fn a_big_file_goes_in_consecutive_parts_beside_packed_small_files() {
        let big: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        let files: Files = [
            ("a.txt".to_owned(), b"first".to_vec()),
            ("model.bin".to_owned(), big.clone()),
            ("z/one.txt".to_owned(), b"one".to_vec()),
            ("z/two.txt".to_owned(), b"two".to_vec()),
        ].into();
        let budget = BATCH_LIMIT - MARGIN;
        let batches = batches(&files, budget).unwrap();
        for batch in &batches {
            assert!(serde_json::to_string(&json!({"files": batch})).unwrap().len() < BATCH_LIMIT, "no request over the cap");
        }
        let parts: Vec<&Value> = batches.iter().flatten().filter(|e| e["path"] == "model.bin").collect();
        assert_eq!(parts.len(), 5, "2 MB in parts of at most 420 KB");
        let mut rebuilt = Vec::new();
        for part in &parts {
            assert_eq!(part["offset"].as_u64().unwrap() as usize, rebuilt.len(), "each part continues where the last ended");
            let bytes = B64.decode(part["content"].as_str().unwrap()).unwrap();
            assert!(bytes.len() <= PART);
            rebuilt.extend(bytes);
        }
        assert_eq!(rebuilt, big);
        let offsets: Vec<u64> = parts.iter().map(|p| p["offset"].as_u64().unwrap()).collect();
        assert_eq!(offsets, [0, 430_080, 860_160, 1_290_240, 1_720_320]);
        let order: Vec<&str> = batches.iter().flatten().map(|e| e["path"].as_str().unwrap()).collect();
        assert_eq!(order.first(), Some(&"a.txt"));
        assert_eq!(&order[order.len() - 2..], ["z/one.txt", "z/two.txt"]);
        let last = batches.last().unwrap();
        assert!(last.iter().any(|e| e["path"] == "model.bin") && last.iter().any(|e| e["path"] == "z/two.txt"), "small files share a request with the last part");
    }

    #[test]
    fn the_marker_lines_are_read_as_the_website_reads_them() {
        let text = "\u{feff}kind: template\nname: 'my-api' # the Hub name\nversion : \"1.0.0\"\n";
        assert_eq!(top_level(text, "name").as_deref(), Some("my-api"));
        assert_eq!(top_level(text, "version").as_deref(), Some("1.0.0"));
        assert_eq!(top_level(text, "kind").as_deref(), Some("template"));
        assert_eq!(top_level("{name: my-api, version: 1.0.0}", "name"), None);
        assert_eq!(top_level("names: my-api\n", "name"), None);
        assert_eq!(top_level("  name: my-api\n", "name"), None, "an indented line is a nested setting");
        assert_eq!(top_level("name: a\nname: b\n", "name"), None, "exactly one");
        assert_eq!(top_level("name: x\r\nversion: 1.0.0\r\n", "version").as_deref(), Some("1.0.0"));
    }

    fn upload_of(files: Files) -> Upload {
        let review = json!({"format": 1, "warnings": []});
        let body = json!({"kind": "template", "name": "shop", "version": "1.0.0", "title": "Shop", "summary": "A shop.", "license": "MIT", "manifest": {"name": "shop"}, "review": review, "files": file_list(&files)});
        Upload { kind: "template", name: "shop".into(), version: "1.0.0".into(), license: "MIT".into(), body, files, review }
    }

    #[test]
    fn sizes_the_website_or_the_engine_would_refuse_are_named_before_anything_is_sent() {
        let marker = "name: shop\nversion: 1.0.0\nsummary: A shop.\nlicense: MIT\n";
        let mut upload = upload_of(Files::from([(format::TEMPLATE_FILE.to_owned(), marker.as_bytes().to_vec())]));
        assert!(preflight(&upload).is_ok());
        upload.body["manifest"]["notes"] = json!("x".repeat(70 * 1024));
        assert!(preflight(&upload).unwrap_err().contains("is too large for the Hub once read"));
        upload.body["manifest"] = json!({"name": "shop"});
        upload.body["review"]["warnings"] = json!(vec!["w".repeat(3000); 50]);
        assert!(preflight(&upload).unwrap_err().contains("The review built from the files is too large for the Hub"));
        upload.body["review"]["warnings"] = json!([]);
        // A thousand of the longest paths, in four-byte characters, no longer fit one request.
        upload.body["files"] = json!((0..1000).map(|i| json!({"path": format!("{}/{}{i:04}.txt", "\u{1f600}".repeat(127), "\u{1f600}".repeat(120)), "bytes": 1, "sha256": "0".repeat(64)})).collect::<Vec<_>>());
        let said = preflight(&upload).unwrap_err();
        assert!(said.contains("too large to send") && said.contains("the list of files is the largest part"), "{said}");
        let twice = upload_of(Files::from([(format::TEMPLATE_FILE.to_owned(), b"name: shop\nname: shop\nversion: 1.0.0\n".to_vec())]));
        assert!(preflight(&twice).unwrap_err().contains("on exactly one line of its own"));
    }

    /// One upload as the website keeps it: the declared files (size, SHA-256), the parts received
    /// so far, the files stored whole, and whether it was finished.
    #[derive(Clone, Default)]
    struct Kept {
        declared: BTreeMap<String, (usize, String)>,
        partials: BTreeMap<String, Vec<u8>>,
        stored: BTreeSet<String>,
        finished: bool,
    }

    /// The website's upload endpoints, in memory, with its rules for parts.
    #[derive(Default)]
    struct Fake {
        uploads: Mutex<BTreeMap<String, Kept>>,
        created: AtomicUsize,
        file_requests: AtomicUsize,
        bytes: AtomicUsize,
        failures: Mutex<Vec<(usize, String)>>,
    }

    impl Transport for Fake {
        async fn call(&self, path: &str, body: Option<Value>) -> Result<Value, String> {
            let body = body.unwrap_or_default();
            if path.ends_with("/files") {
                let request = self.file_requests.fetch_add(1, Ordering::SeqCst) + 1;
                let mut failures = self.failures.lock().unwrap();
                if let Some(index) = failures.iter().position(|(at, _)| *at == request) {
                    return Err(failures.remove(index).1);
                }
            }
            let mut uploads = self.uploads.lock().unwrap();
            if path == "/hub/uploads" {
                let id = format!("hup_test{:04}", self.created.fetch_add(1, Ordering::SeqCst));
                let declared = body["files"].as_array().unwrap().iter().map(|f| (f["path"].as_str().unwrap().to_owned(), (f["bytes"].as_u64().unwrap() as usize, f["sha256"].as_str().unwrap().to_owned()))).collect();
                uploads.insert(id.clone(), Kept { declared, ..Default::default() });
                return Ok(json!({"upload": {"id": id, "expiresAt": 4_000_000_000i64, "maxBatchBytes": 600 * 1024}}));
            }
            let id = path.trim_start_matches("/hub/uploads/").split('/').next().unwrap().to_owned();
            let Some(Kept { declared, partials, stored, finished }) = uploads.get_mut(&id) else { return Err("This upload does not exist. Start the upload again.".into()) };
            if *finished {
                return Err("This upload is already published.".into());
            }
            if path.ends_with("/finish") {
                let missing: Vec<&String> = declared.keys().filter(|p| !stored.contains(*p)).collect();
                if let Some(first) = missing.first() {
                    return Err(format!("{} files have not arrived yet, such as {first}. Send them, then finish.", missing.len()));
                }
                *finished = true;
                return Ok(json!({"item": {"ref": "acme/shop", "verified": false}}));
            }
            // One transaction: a refusal applies nothing of the batch.
            let mut next_partials = partials.clone();
            let mut next_stored = stored.clone();
            for entry in body["files"].as_array().unwrap() {
                let path = entry["path"].as_str().unwrap();
                let (bytes, sha) = declared.get(path).ok_or(format!("{path} is not in this upload's file list"))?;
                let part = B64.decode(entry["content"].as_str().unwrap()).unwrap();
                self.bytes.fetch_add(part.len(), Ordering::SeqCst);
                let offset = entry["offset"].as_u64().unwrap_or(0) as usize;
                let have = if offset == 0 { 0 } else { next_partials.get(path).map_or(0, Vec::len) };
                if offset != have {
                    return Err(format!("Send {path} from byte {have}"));
                }
                let mut whole = if offset == 0 { Vec::new() } else { next_partials.get(path).cloned().unwrap_or_default() };
                whole.extend(part);
                if whole.len() < *bytes {
                    next_partials.insert(path.to_owned(), whole);
                    continue;
                }
                next_partials.remove(path);
                if scan::sha256_hex(&whole) != *sha {
                    return Err(format!("{path} does not match its SHA-256. Upload it again."));
                }
                next_stored.insert(path.to_owned());
            }
            *partials = next_partials;
            *stored = next_stored;
            Ok(json!({"received": stored.len(), "remaining": declared.len() - stored.len()}))
        }
        fn waits(&self) -> Vec<Duration> {
            vec![Duration::ZERO, Duration::ZERO]
        }
    }

    fn sample() -> Files {
        let big: Vec<u8> = (0..1_200_000).map(|i| (i % 253) as u8).collect();
        let mut files: Files = (0..6).map(|i| (format!("assets/{i}.bin"), vec![i as u8; 250_000])).collect();
        files.insert("model.bin".into(), big);
        files.insert(format::TEMPLATE_FILE.into(), b"name: shop\nversion: 1.0.0\n".to_vec());
        files
    }

    #[tokio::test]
    async fn an_interrupted_upload_carries_on_without_a_new_upload_or_sending_files_again() {
        let root = tempfile::tempdir().unwrap();
        let uploads = Uploads { root: root.path().to_path_buf() };
        let upload = upload_of(sample());
        let total: usize = upload.files.values().map(Vec::len).sum();
        let fake = Fake::default();
        fake.failures.lock().unwrap().push((3, "The Hub could not store the file. Try again later.".into()));
        let stopped = send(&fake, &uploads, &upload, "acme/shop", 1_000).await.unwrap_err();
        assert!(stopped.contains("run the same publish command again to carry on"), "{stopped}");
        let saved = uploads.load("acme/shop", "1.0.0", "template", &scan::digest_of(&upload.files), 1_000).unwrap();
        assert!(!saved.done.is_empty() || !saved.partial.is_empty(), "what went up is remembered");
        let sent_before = fake.bytes.load(Ordering::SeqCst);
        let finished = send(&fake, &uploads, &upload, "acme/shop", 1_000).await.unwrap();
        assert_eq!(finished["item"]["ref"], "acme/shop");
        assert_eq!(fake.created.load(Ordering::SeqCst), 1, "the same upload carries on; no new one counts toward the day's 20");
        assert_eq!(fake.bytes.load(Ordering::SeqCst), total, "no byte went up twice ({sent_before} before the stop)");
        assert!(uploads.load("acme/shop", "1.0.0", "template", &scan::digest_of(&upload.files), 1_000).is_none(), "a published upload is forgotten");
    }

    #[tokio::test]
    async fn parts_the_website_has_differently_failures_on_the_way_and_forgotten_uploads_are_handled() {
        let root = tempfile::tempdir().unwrap();
        let uploads = Uploads { root: root.path().to_path_buf() };
        let upload = upload_of(sample());
        let digest = scan::digest_of(&upload.files);
        // A lost connection is tried again by itself.
        let fake = Fake::default();
        fake.failures.lock().unwrap().push((2, "Cannot reach the Yougori Network at https://yougori.com: timed out".into()));
        send(&fake, &uploads, &upload, "acme/shop", 1_000).await.unwrap();
        assert_eq!(fake.created.load(Ordering::SeqCst), 1);
        // The saved progress says more of model.bin went up than the website has.
        let fake = Fake::default();
        let started = start(&fake, &uploads, &upload, "acme/shop", &digest).await.unwrap();
        let mut ahead = started.clone();
        ahead.partial.insert("model.bin".into(), 430_080);
        uploads.save(&ahead);
        send(&fake, &uploads, &upload, "acme/shop", 1_000).await.unwrap();
        assert_eq!(fake.created.load(Ordering::SeqCst), 1, "Send model.bin from byte 0 was followed, in the same upload");
        // An upload the website no longer has is started once more.
        let fake = Fake::default();
        uploads.save(&Progress { id: "hup_gone0000".into(), ..started });
        send(&fake, &uploads, &upload, "acme/shop", 1_000).await.unwrap();
        assert_eq!(fake.created.load(Ordering::SeqCst), 1);
        // A different set of files never reuses the upload.
        let fake = Fake::default();
        let mut changed = upload_of(sample());
        changed.files.insert("extra.txt".into(), b"new".to_vec());
        changed.body["files"] = json!(file_list(&changed.files));
        uploads.save(&Progress { id: "hup_test0000".into(), item: "acme/shop".into(), version: "1.0.0".into(), kind: "template".into(), digest: digest.clone(), expires_at: 4_000_000_000, ..Default::default() });
        assert!(uploads.load("acme/shop", "1.0.0", "template", &scan::digest_of(&changed.files), 1_000).is_none());
        send(&fake, &uploads, &changed, "acme/shop", 1_000).await.unwrap();
        assert_eq!(fake.created.load(Ordering::SeqCst), 1);
        assert_eq!(resend_from("Send site/a b.txt from byte 4096"), Some(("site/a b.txt".to_owned(), 4096)));
    }

    #[test]
    fn report_details_follow_the_websites_text_rules() {
        assert_eq!(report_details("  It installs a miner.\nSee line 3.  ").unwrap(), "It installs a miner.\nSee line 3.");
        assert!(report_details(&"\u{1f600}".repeat(1000)).is_ok(), "2000 UTF-16 units");
        assert!(report_details(&"\u{1f600}".repeat(1001)).unwrap_err().contains("longer than 2000 characters"));
        assert!(report_details("look \u{202e}here").unwrap_err().contains("invisible characters"));
    }

    #[test]
    fn a_template_folder_becomes_an_upload_document() {
        let root = tempfile::tempdir().unwrap();
        let write = |path: &str, text: &str| {
            let path = root.path().join(path);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, text).unwrap();
        };
        write("yougori-template.yaml", "name: shop\nsummary: A shop.\nversion: 1.2.0\nlicense: MIT\ntopics: [shop]\n");
        write("yougori.yaml", "project: shop\nenvironments:\n  web:\n    image: nginx:1.27\n");
        write("README.md", "# Shop\n");
        write("node_modules/x/index.js", "skipped");
        let (upload, _) = template(root.path()).unwrap();
        assert_eq!(upload.body["kind"], "template");
        assert_eq!(upload.body["manifest"]["name"], "shop");
        assert_eq!(upload.body["manifest"]["kind"], "template");
        assert_eq!(upload.body["files"].as_array().unwrap().len(), 3);
        assert_eq!(upload.body["files"][0]["sha256"], scan::sha256_hex(b"# Shop\n"));
        assert_eq!(upload.body["review"]["totals"]["environments"], 1);
        assert!(preflight(&upload).is_ok());
        write(".env", "TOKEN=abc\n");
        let refused = template(root.path()).err().unwrap();
        assert!(refused.contains(".env: environment files with values are never published"), "{refused}");
        std::fs::remove_file(root.path().join(".env")).unwrap();
        write("app.js", "const key = 'sk-proj-Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z';\n");
        assert!(template(root.path()).err().unwrap().contains("app.js line 1: looks like an OpenAI or Anthropic API key"));
    }

    #[test]
    fn upload_ids_are_checked_before_they_reach_a_path() {
        assert_eq!(upload_id(&json!({"upload": {"id": "hup_abc12345"}})).unwrap(), "hup_abc12345");
        for bad in [json!({}), json!({"upload": {"id": "../me"}}), json!({"upload": {"id": "a/b"}}), json!({"upload": {"id": ""}})] {
            assert!(upload_id(&bad).is_err(), "{bad}");
        }
    }
}
