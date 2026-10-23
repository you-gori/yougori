//! Talking to the Hub. Public reads go straight to the website; signed-in requests go through
//! the engine, which holds the account (`model_registry_request` with a `/hub/…` path). Downloads
//! are checked file by file and against the version digest before anything uses them, and a
//! checked copy is kept under `~/.yougori/hub/cache`.
use super::{
    refs::{self, Ref},
    scan::{self, Files},
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde_json::{json, Value};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

/// JSON answers are small; a version's bundle is at most 25 MiB of files, base64-encoded.
const JSON_LIMIT: usize = 4 * 1024 * 1024;
const BUNDLE_LIMIT: usize = 40 * 1024 * 1024;

/// `~/.yougori`, where the Hub keeps its cache, instances and the install id.
pub fn home() -> Result<PathBuf, String> {
    std::env::var_os("USERPROFILE")
        .filter(|home| !home.is_empty())
        .or_else(|| std::env::var_os("HOME"))
        .map(|home| PathBuf::from(home).join(".yougori"))
        .ok_or_else(|| "Cannot find your user profile folder.".into())
}

/// The website: `YOUGORI_NETWORK_URL` when it passes the same rules as the engine's (HTTPS, or
/// plain HTTP only to this computer with a port, never with a user, query or fragment), else
/// https://yougori.com.
pub fn website() -> String {
    std::env::var("YOUGORI_NETWORK_URL")
        .ok()
        .map(|value| value.trim_end_matches('/').to_owned())
        .filter(|value| allowed(value))
        .unwrap_or_else(|| "https://yougori.com".into())
}

pub fn allowed(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else { return false };
    if !url.username().is_empty() || url.password().is_some() || url.query().is_some() || url.fragment().is_some() {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => url.port().is_some() && matches!(url.host_str(), Some("127.0.0.1" | "localhost" | "[::1]")),
        _ => false,
    }
}

/// A failure from the website: `status` 0 when it could not be reached.
#[derive(Clone, Debug, PartialEq)]
pub struct SiteError {
    pub status: u16,
    pub code: String,
    pub message: String,
}

impl SiteError {
    /// The website could not be reached at all (no connection, a timeout, an interrupted answer):
    /// only then may a copy saved on this computer stand in. An error answer, even 5xx, is not.
    pub fn unreachable(&self) -> bool {
        self.status == 0
    }
    /// The message for a command that stops here, with what to do next.
    pub fn said(self) -> String {
        match self.status {
            0 => format!("{} Nothing was changed. Check your connection and try again.", self.message),
            500.. => format!("{} The Hub is having trouble; try again in a few minutes. Nothing was changed.", self.message),
            _ => self.message,
        }
    }
}

impl From<SiteError> for String {
    fn from(error: SiteError) -> String {
        error.message
    }
}

/// The website, for public reads.
pub struct Site {
    pub base: String,
    client: reqwest::Client,
}

impl Site {
    pub fn configured() -> Result<Site, String> {
        Site::at(&website())
    }

    pub fn at(base: &str) -> Result<Site, String> {
        let base = base.trim_end_matches('/').to_owned();
        if !allowed(&base) {
            return Err(format!("{base} is not a website Yougori can use. Use https, or http://127.0.0.1:PORT for a local website."));
        }
        let local = base.starts_with("http://");
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(60))
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("Yougori/", env!("CARGO_PKG_VERSION")));
        builder = if local { builder.no_proxy() } else { builder.https_only(true) };
        let client = builder.build().map_err(|e| format!("Cannot prepare a connection to the Hub: {e}"))?;
        Ok(Site { base, client })
    }

    fn url(&self, path: &str, query: &[(&str, String)]) -> Result<reqwest::Url, SiteError> {
        let mut url = reqwest::Url::parse(&format!("{}{path}", self.base)).map_err(|_| SiteError { status: 0, code: "invalid".into(), message: "Invalid Hub address".into() })?;
        if !query.is_empty() {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url)
    }

    async fn read(&self, request: reqwest::RequestBuilder, limit: usize) -> Result<Value, SiteError> {
        let site = self.base.clone();
        let mut response = request.send().await.map_err(|error| SiteError {
            status: 0,
            code: "network".into(),
            message: format!("Cannot reach the Hub at {site} ({}).", error.without_url()),
        })?;
        let status = response.status().as_u16();
        if response.content_length().is_some_and(|length| length > limit as u64) {
            return Err(SiteError { status, code: "response_limit".into(), message: "The Hub's answer is larger than Yougori accepts.".into() });
        }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| SiteError { status: 0, code: "network".into(), message: format!("The answer from {site} was interrupted.") })? {
            if bytes.len() + chunk.len() > limit {
                return Err(SiteError { status, code: "response_limit".into(), message: "The Hub's answer is larger than Yougori accepts.".into() });
            }
            bytes.extend_from_slice(&chunk);
        }
        let value: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        if (200..300).contains(&status) {
            if value.is_null() {
                return Err(SiteError { status, code: "invalid".into(), message: format!("{site} did not answer like the Yougori Hub.") });
            }
            return Ok(value);
        }
        Err(SiteError {
            status,
            code: value["code"].as_str().unwrap_or_default().into(),
            message: value["error"].as_str().map(scan::shown).unwrap_or_else(|| format!("The Hub answered HTTP {status}.")),
        })
    }

    pub async fn get(&self, path: &str, query: &[(&str, String)], limit: usize) -> Result<Value, SiteError> {
        let url = self.url(path, query)?;
        self.read(self.client.get(url), limit).await
    }

    pub async fn post(&self, path: &str, body: &Value) -> Result<Value, SiteError> {
        let url = self.url(path, &[])?;
        self.read(self.client.post(url).json(body), JSON_LIMIT).await
    }

    /// An item's page data (`Detail`), for one version or the latest.
    pub async fn item(&self, reference: &Ref) -> Result<Value, SiteError> {
        let query: Vec<(&str, String)> = reference.version.iter().map(|v| ("version", v.clone())).collect();
        let value = self.get(&format!("/api/hub/items/{}/{}", reference.publisher, reference.name), &query, JSON_LIMIT).await?;
        // The page data, whether or not it comes wrapped as {item: …}.
        Ok(if value["item"].is_object() { value["item"].clone() } else { value })
    }

    /// A version's files; a large one is given ten minutes on a slow connection.
    pub async fn bundle(&self, reference: &Ref, version: &str) -> Result<Value, SiteError> {
        let url = self.url(&format!("/api/hub/items/{}/{}/bundle", reference.publisher, reference.name), &[("version", version.to_owned())])?;
        self.read(self.client.get(url).timeout(Duration::from_secs(600)), BUNDLE_LIMIT).await
    }

    /// Adds this computer once to an item's clones, within five seconds. A failure is not worth
    /// stopping anything for; `None` means the Hub did not answer.
    pub async fn count_clone(&self, reference: &Ref, version: &str, install: &str) -> Option<u64> {
        let url = self.url(&format!("/api/hub/items/{}/{}/clones", reference.publisher, reference.name), &[]).ok()?;
        let request = self.client.post(url).timeout(Duration::from_secs(5)).json(&json!({"version": version, "install": install}));
        self.read(request, JSON_LIMIT).await.ok().and_then(|v| v["clones"].as_u64())
    }

    pub async fn search(&self, words: &str, sort: Option<&str>, kind: Option<&str>, page: Option<u32>) -> Result<Value, SiteError> {
        let mut query = Vec::new();
        if !words.is_empty() {
            query.push(("q", words.to_owned()));
        }
        if let Some(sort) = sort {
            query.push(("sort", sort.to_owned()));
        }
        if let Some(kind) = kind {
            query.push(("kind", kind.to_owned()));
        }
        if let Some(page) = page {
            query.push(("page", page.to_string()));
        }
        self.get("/api/hub/items", &query, JSON_LIMIT).await
    }
}

/// A version's files after every check.
#[derive(Clone, Debug)]
pub struct Bundle {
    pub reference: Ref,
    pub kind: String,
    pub version: String,
    pub digest: String,
    pub verified: bool,
    pub created_at: i64,
    pub files: Files,
}

impl Bundle {
    fn meta(&self) -> Value {
        json!({
            "ref": self.reference.item(), "publisher": self.reference.publisher, "name": self.reference.name,
            "kind": self.kind, "version": self.version, "digest": self.digest, "verified": self.verified,
            "createdAt": self.created_at,
            "files": self.files.iter().map(|(path, bytes)| json!({"path": path, "sha256": scan::sha256_hex(bytes), "bytes": bytes.len()})).collect::<Vec<_>>(),
        })
    }
}

const TAMPERED: &str = "Nothing was created, and the downloaded copy was removed. Try again later; if it happens again, report the item on the Hub.";

/// A version with a file this computer cannot store is no integrity failure: the website's rules
/// may differ from this Yougori's.
fn unstorable(reference: &Ref, version: &str, path: &str) -> String {
    format!("{} {version}: this version has a file name Yougori cannot store on this computer ({}). Nothing was created. Update Yougori with yougori update, or run another version.", reference.item(), scan::shown(path))
}

/// Checks a bundle from the website: the item and version asked for, every path, every file's
/// size and SHA-256, and the digest of the whole version (and the page's digest when known).
pub fn verify(value: &Value, reference: &Ref, version: &str, page_digest: Option<&str>) -> Result<Bundle, String> {
    let refused = |what: String| format!("{} {version} failed its integrity check: {what}. {TAMPERED}", reference.item());
    if value["publisher"] != reference.publisher.as_str() || value["name"] != reference.name.as_str() || value["version"] != version {
        return Err(refused("the website sent a different item or version".into()));
    }
    let digest = value["digest"].as_str().filter(|d| d.len() == 64 && d.bytes().all(|b| b.is_ascii_hexdigit())).ok_or_else(|| refused("it has no digest".into()))?.to_ascii_lowercase();
    if page_digest.is_some_and(|page| !page.eq_ignore_ascii_case(&digest)) {
        return Err(refused("its digest is not the one the Hub page shows".into()));
    }
    let entries = value["files"].as_array().filter(|files| !files.is_empty()).ok_or_else(|| refused("it lists no files".into()))?;
    if entries.len() > scan::LIMITS.files {
        return Err(refused("it has too many files".into()));
    }
    let mut files = Files::new();
    let mut total = 0u64;
    for entry in entries {
        let path = entry["path"].as_str().ok_or_else(|| refused("a file has no path".into()))?;
        if scan::check_path(path).is_err() {
            return Err(unstorable(reference, version, path));
        }
        if files.contains_key(path) {
            return Err(refused(format!("{} appears twice", scan::shown(path))));
        }
        let content = B64.decode(entry["content"].as_str().unwrap_or_default()).map_err(|_| refused(format!("{} is not base64", scan::shown(path))))?;
        let sha = scan::sha256_hex(&content);
        if entry["sha256"].as_str().is_none_or(|expected| !expected.eq_ignore_ascii_case(&sha)) || entry["bytes"].as_u64().is_some_and(|bytes| bytes != content.len() as u64) {
            return Err(refused(format!("{} does not match its SHA-256", scan::shown(path))));
        }
        if content.len() as u64 > scan::LIMITS.file_bytes {
            return Err(refused(format!("{} is larger than 5 MiB", scan::shown(path))));
        }
        total += content.len() as u64;
        files.insert(path.to_owned(), content);
    }
    if total > scan::LIMITS.total_bytes {
        return Err(refused("it is larger than 25 MiB".into()));
    }
    if let Some(path) = scan::clashing(files.keys().map(String::as_str)) {
        return Err(unstorable(reference, version, &path));
    }
    if scan::digest_of(&files) != digest {
        return Err(refused("its files do not add up to its digest".into()));
    }
    Ok(Bundle {
        reference: reference.at(version),
        kind: value["kind"].as_str().unwrap_or("template").to_owned(),
        version: version.to_owned(),
        digest,
        verified: value["verified"] == true,
        created_at: value["createdAt"].as_i64().unwrap_or_default(),
        files,
    })
}

/// Checked copies of versions on this computer: `cache/PUBLISHER/NAME/VERSION/` holds the files
/// and `VERSION.json` beside it what they must hash to.
pub struct Cache {
    pub root: PathBuf,
}

impl Cache {
    pub fn standard() -> Result<Cache, String> {
        Ok(Cache { root: home()?.join("hub").join("cache") })
    }

    fn item(&self, publisher: &str, name: &str) -> PathBuf {
        self.root.join(publisher).join(name)
    }

    fn folder(&self, publisher: &str, name: &str, version: &str) -> PathBuf {
        self.item(publisher, name).join(version)
    }

    fn meta(&self, publisher: &str, name: &str, version: &str) -> PathBuf {
        self.item(publisher, name).join(format!("{version}.json"))
    }

    /// Removes one cached version.
    pub fn drop(&self, publisher: &str, name: &str, version: &str) {
        let _ = std::fs::remove_dir_all(self.folder(publisher, name, version));
        let _ = std::fs::remove_file(self.meta(publisher, name, version));
    }

    /// Keeps a checked copy. Another run may store the same version at the same moment: its copy
    /// is kept when it checks out, and the loser's staging folder is simply dropped.
    pub fn store(&self, bundle: &Bundle) -> Result<(), String> {
        let (publisher, name, version) = (&bundle.reference.publisher, &bundle.reference.name, &bundle.version);
        let failed = |error: String| format!("Could not keep a copy of {} on this computer ({error}).", bundle.reference.item());
        let item = self.item(publisher, name);
        std::fs::create_dir_all(&item).map_err(|e| failed(e.to_string()))?;
        Cache::clean(&item);
        let staging = tempfile::Builder::new().prefix(".partial-").tempdir_in(&item).map_err(|e| failed(e.to_string()))?;
        write_files(staging.path(), &bundle.files).map_err(failed)?;
        let folder = self.folder(publisher, name, version);
        // Once renamed, dropping the staging folder finds nothing left to remove.
        if std::fs::rename(staging.path(), &folder).is_err() {
            if self.load(publisher, name, version).ok().flatten().is_some_and(|saved| saved.digest == bundle.digest) {
                return Ok(());
            }
            self.drop(publisher, name, version);
            std::fs::rename(staging.path(), &folder).map_err(|e| failed(e.to_string()))?;
        }
        let mut meta = tempfile::Builder::new().prefix(".partial-").tempfile_in(&item).map_err(|e| failed(e.to_string()))?;
        std::io::Write::write_all(&mut meta, &serde_json::to_vec_pretty(&bundle.meta()).unwrap_or_default()).map_err(|e| failed(e.to_string()))?;
        meta.persist(self.meta(publisher, name, version)).map(|_| ()).map_err(|e| failed(e.error.to_string()))
    }

    /// Removes staging folders and files an interrupted copy left behind, once they are an hour
    /// old: a younger one may belong to a run that is still writing it.
    fn clean(item: &Path) {
        let old = |entry: &std::fs::DirEntry| entry.metadata().ok().and_then(|m| m.modified().ok()).and_then(|at| at.elapsed().ok()).is_some_and(|age| age > Duration::from_secs(3600));
        for entry in std::fs::read_dir(item).into_iter().flatten().flatten() {
            if entry.file_name().to_string_lossy().starts_with(".partial-") && old(&entry) {
                let _ = std::fs::remove_dir_all(entry.path()).or_else(|_| std::fs::remove_file(entry.path()));
            }
        }
    }

    /// A cached version, checked again file by file. A copy that no longer matches is removed
    /// and refused; one that is not there is `None`.
    pub fn load(&self, publisher: &str, name: &str, version: &str) -> Result<Option<Bundle>, String> {
        let Ok(meta) = std::fs::read(self.meta(publisher, name, version)) else { return Ok(None) };
        let reference = Ref { publisher: publisher.into(), name: name.into(), version: Some(version.into()) };
        let tampered = || {
            self.drop(publisher, name, version);
            format!("The copy of {} {version} on this computer was changed after it was downloaded, so it was removed. {}", reference.item(), "Run the command again to download a fresh copy; nothing was created.")
        };
        let meta: Value = serde_json::from_slice(&meta).map_err(|_| tampered())?;
        let folder = self.folder(publisher, name, version);
        let mut entries = Vec::new();
        for entry in meta["files"].as_array().into_iter().flatten() {
            let path = entry["path"].as_str().ok_or_else(tampered)?;
            scan::check_path(path).map_err(|_| tampered())?;
            let bytes = std::fs::read(folder.join(path)).map_err(|_| tampered())?;
            entries.push(json!({"path": path, "sha256": entry["sha256"], "bytes": entry["bytes"], "content": B64.encode(&bytes)}));
        }
        let mut value = meta.clone();
        value["files"] = json!(entries);
        // Nothing may sit in the folder that the list does not name.
        let listed = entries.len();
        let present = walk_count(&folder);
        if present != listed {
            return Err(tampered());
        }
        verify(&value, &reference, version, meta["digest"].as_str()).map(Some).map_err(|_| tampered())
    }

    /// Cached versions of an item, newest first.
    pub fn versions(&self, publisher: &str, name: &str) -> Vec<String> {
        let mut versions: Vec<String> = std::fs::read_dir(self.item(publisher, name)).into_iter().flatten().flatten()
            .filter_map(|entry| entry.file_name().to_str().and_then(|n| n.strip_suffix(".json")).map(str::to_owned))
            .filter(|version| refs::parse_version(version).is_ok())
            .collect();
        versions.sort_by(|a, b| refs::compare(b, a).unwrap_or(std::cmp::Ordering::Equal));
        versions
    }
}

fn walk_count(folder: &Path) -> usize {
    let mut count = 0;
    let mut pending = vec![folder.to_path_buf()];
    while let Some(folder) = pending.pop() {
        for entry in std::fs::read_dir(&folder).into_iter().flatten().flatten() {
            match entry.file_type() {
                Ok(kind) if kind.is_dir() => pending.push(entry.path()),
                Ok(_) => count += 1,
                Err(_) => {}
            }
        }
    }
    count
}

/// A full path without the verbatim prefix Windows puts on canonical paths, as people read it.
pub fn plain(path: PathBuf) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if rest.as_bytes().get(1) == Some(&b':') => PathBuf::from(rest),
        _ => path,
    }
}

/// Writes files under `root`, creating folders; paths were checked before.
pub fn write_files(root: &Path, files: &Files) -> Result<(), String> {
    for (path, bytes) in files {
        scan::check_path(path)?;
        let target = root.join(path);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("Cannot write {path}: {e}"))?;
        }
        std::fs::write(&target, bytes).map_err(|e| format!("Cannot write {path}: {e}"))?;
    }
    Ok(())
}

/// Why an item cannot be used: its page says it was removed or deleted.
pub fn removed(detail: &Value) -> Option<String> {
    if detail["state"].as_str().is_none_or(|state| state == "active") {
        return None;
    }
    let item = detail["ref"].as_str().unwrap_or("This item");
    let message = detail["removed"]["message"].as_str().map(scan::shown).unwrap_or_else(|| "It was removed from the Hub.".into());
    Some(format!("{item} is no longer on the Hub. {message}"))
}

/// A version obtained for use: from the website, or from this computer when the website could
/// not be reached.
pub struct Obtained {
    pub bundle: Bundle,
    /// The item's page data when the website answered.
    pub detail: Option<Value>,
    /// Said before the review, such as running from a saved copy.
    pub notice: Option<String>,
}

/// The page's entry for one version: its digest and whether it is Verified.
fn page_version<'a>(detail: &'a Value, version: &str) -> Option<&'a Value> {
    if detail["version"]["version"] == version {
        return Some(&detail["version"]);
    }
    detail["versions"].as_array()?.iter().find(|entry| entry["version"] == version)
}

/// Downloads (or reuses) and checks the version a reference asks for, the latest when none. Only
/// when the website cannot be reached at all does a copy saved here stand in; a removed item, an
/// error answer or a version that does not exist never falls back to one.
pub async fn obtain(site: &Site, cache: &Cache, reference: &Ref) -> Result<Obtained, String> {
    match site.item(reference).await {
        Ok(detail) => {
            if let Some(reason) = removed(&detail) {
                return Err(format!("{reason} Nothing was created."));
            }
            let version = reference.version.clone()
                .or_else(|| detail["version"]["version"].as_str().map(str::to_owned))
                .or_else(|| detail["latestVersion"].as_str().map(str::to_owned))
                .ok_or_else(|| format!("{} has no published version yet.", reference.item()))?;
            if refs::parse_version(&version).is_err() {
                return Err(format!("The Hub offers {} as version {}, which this Yougori cannot read. Update Yougori with yougori update, or name another version with @VERSION. Nothing was created.", reference.item(), scan::shown(&version)));
            }
            let page = page_version(&detail, &version);
            let page_digest = page.and_then(|entry| entry["digest"].as_str()).map(str::to_owned);
            let page_verified = page.is_some_and(|entry| entry["verified"] == true);
            let page_kind = detail["kind"].as_str();
            // A saved copy is used only when it still matches the page; one that was changed has
            // already been removed, and a fresh copy is downloaded instead. Whether it is Verified
            // and what kind it is come from the page, never from the list saved beside the copy.
            if let Ok(Some(mut bundle)) = cache.load(&reference.publisher, &reference.name, &version) {
                let same = page_digest.as_deref().is_none_or(|digest| digest.eq_ignore_ascii_case(&bundle.digest)) && page_kind.is_none_or(|kind| kind == bundle.kind);
                if same {
                    bundle.verified = page_verified;
                    return Ok(Obtained { bundle, detail: Some(detail), notice: None });
                }
                cache.drop(&reference.publisher, &reference.name, &version);
            }
            let value = site.bundle(reference, &version).await.map_err(|error| match error.status {
                410 => format!("{} Nothing was created.", error.message),
                _ => error.said(),
            })?;
            let mut bundle = verify(&value, reference, &version, page_digest.as_deref())?;
            if page_kind.is_some_and(|kind| kind != bundle.kind) {
                return Err(format!("{} {version} failed its integrity check: the download is not the kind of item its page shows. {TAMPERED}", reference.item()));
            }
            if page.is_some() {
                bundle.verified &= page_verified;
            }
            // A copy that cannot be kept never stops a run: the checked download is used as it is.
            let notice = cache.store(&bundle).err().map(|error| format!("{error} The checked download is used as it is and will be downloaded again next time."));
            Ok(Obtained { bundle, detail: Some(detail), notice })
        }
        Err(error) if error.unreachable() => {
            let version = match &reference.version {
                Some(version) => Some(version.clone()),
                None => cache.versions(&reference.publisher, &reference.name).into_iter().next(),
            };
            let saved = match version {
                Some(version) => cache.load(&reference.publisher, &reference.name, &version)?,
                None => None,
            };
            match saved {
                Some(mut bundle) => {
                    // Offline, nothing can confirm the Verified badge: the copy counts as a
                    // community item.
                    let badge = if bundle.verified { " Its Verified badge cannot be checked offline, so it is treated as a community item." } else { "" };
                    bundle.verified = false;
                    let notice = format!("{} Using the copy of {} {} saved on this computer; it was checked again just now.{badge}", error.message, reference.item(), bundle.version);
                    Ok(Obtained { bundle, detail: None, notice: Some(notice) })
                }
                None => Err(format!("{} There is no saved copy of {} on this computer. Nothing was changed. Check your connection and try again.", error.message, reference.item())),
            }
        }
        Err(error) => Err(error.said()),
    }
}

/// The exact files an existing instance was made from: the checked copy on this computer when it
/// still matches `digest`, otherwise that version downloaded again. An item removed from the Hub
/// since keeps working from the copy here; only new runs are refused.
pub async fn own(site: &Site, cache: &Cache, reference: &Ref, digest: &str) -> Result<Obtained, String> {
    let version = reference.version.clone().ok_or("A Hub instance always names its version.")?;
    if let Ok(Some(bundle)) = cache.load(&reference.publisher, &reference.name, &version) {
        if bundle.digest.eq_ignore_ascii_case(digest) {
            return Ok(Obtained { bundle, detail: None, notice: None });
        }
    }
    let got = obtain(site, cache, reference).await.map_err(|error| format!("The files of {} {version} are no longer on this computer and could not be downloaded again: {error}", reference.item()))?;
    if !got.bundle.digest.eq_ignore_ascii_case(digest) {
        return Err(format!("The Hub's copy of {} {version} does not match the files this instance was made from, so it was not used. Nothing was changed.", reference.item()));
    }
    Ok(got)
}

/// The id that counts this computer once per item: 32 random characters kept in
/// `~/.yougori/hub/install-id`.
pub fn install_id(home: &Path) -> Result<String, String> {
    let path = home.join("hub").join("install-id");
    if let Ok(text) = std::fs::read_to_string(&path) {
        let text = text.trim();
        if (16..=128).contains(&text.len()) && text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Ok(text.to_owned());
        }
    }
    use ring::rand::SecureRandom;
    let mut bytes = [0u8; 24];
    ring::rand::SystemRandom::new().fill(&mut bytes).map_err(|_| "Cannot make an install id")?;
    let id = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
    std::fs::create_dir_all(path.parent().unwrap_or(home)).map_err(|e| format!("Cannot save the install id: {e}"))?;
    std::fs::write(&path, &id).map_err(|e| format!("Cannot save the install id: {e}"))?;
    Ok(id)
}

/// A signed-in request through the engine, which adds the account. `body` makes it a POST.
pub async fn account(path: &str, body: Option<Value>) -> Result<Value, String> {
    if !path.starts_with("/hub/") || path.contains("..") || path.contains(['#', '%', '\\', '?']) || path.contains("//") || path.len() > 512 {
        return Err("Invalid Hub request".into());
    }
    crate::public::call("model_registry_request", json!({"path": path, "body": body})).await
}

/// Makes sure the engine runs and this computer is signed in.
pub async fn signed_in() -> Result<(), String> {
    crate::client::start(None).await?;
    if !crate::network::signed_in().await? {
        return Err(crate::network::SIGN_IN_FIRST.into());
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use axum::{extract::{Path as UrlPath, State}, http::StatusCode, routing::{get, post}, Json, Router};
    use std::sync::{Arc, Mutex};

    pub(crate) fn bundle_json(publisher: &str, name: &str, version: &str, files: &Files) -> Value {
        let entries: Vec<Value> = files.iter().map(|(path, bytes)| json!({"path": path, "sha256": scan::sha256_hex(bytes), "bytes": bytes.len(), "content": B64.encode(bytes)})).collect();
        json!({"ref": format!("{publisher}/{name}"), "publisher": publisher, "name": name, "kind": "template", "version": version, "digest": scan::digest_of(files), "verified": false, "createdAt": 1_760_000_000, "files": entries})
    }

    fn reference() -> Ref {
        Ref { publisher: "acme".into(), name: "hello".into(), version: None }
    }

    fn sample() -> Files {
        [("yougori.yaml", "a"), ("app/x.js", "b")].iter().map(|(p, t)| (p.to_string(), t.as_bytes().to_vec())).collect()
    }

    #[test]
    fn websites_follow_the_engines_rules() {
        for good in ["https://yougori.com", "https://hub.example.org:8443", "http://127.0.0.1:8787", "http://localhost:3000", "http://[::1]:8080"] {
            assert!(allowed(good), "{good}");
        }
        for bad in ["http://yougori.com", "http://127.0.0.1", "https://user@yougori.com", "https://yougori.com?x=1", "https://yougori.com#x", "ftp://yougori.com", "http://localhost:@evil.example:80", "http://127.0.0.1:80", "yougori.com"] {
            assert!(!allowed(bad), "{bad}");
        }
        assert!(Site::at("http://evil.example:80").is_err());
    }

    #[test]
    fn bundles_are_verified_file_by_file_and_by_digest() {
        let files = sample();
        let good = bundle_json("acme", "hello", "1.0.0", &files);
        let digest = scan::digest_of(&files);
        let bundle = verify(&good, &reference(), "1.0.0", Some(&digest)).unwrap();
        assert_eq!(bundle.files, files);
        let mut changed = good.clone();
        changed["files"][0]["content"] = json!(B64.encode(b"z"));
        assert!(verify(&changed, &reference(), "1.0.0", None).unwrap_err().contains("does not match its SHA-256"));
        let mut swapped = good.clone();
        swapped["files"][0]["sha256"] = json!(scan::sha256_hex(b"z"));
        swapped["files"][0]["content"] = json!(B64.encode(b"z"));
        assert!(verify(&swapped, &reference(), "1.0.0", None).unwrap_err().contains("do not add up to its digest"));
        assert!(verify(&good, &reference(), "1.0.0", Some(&"0".repeat(64))).unwrap_err().contains("not the one the Hub page shows"));
        assert!(verify(&good, &reference(), "2.0.0", None).unwrap_err().contains("different item or version"));
        let mut escape = good.clone();
        escape["files"][0]["path"] = json!("../outside.txt");
        assert!(verify(&escape, &reference(), "1.0.0", None).unwrap_err().contains("a file name Yougori cannot store on this computer (../outside.txt)"), "nothing is ever written outside the folder");
    }

    #[test]
    fn a_cached_copy_is_checked_again_and_dropped_when_changed() {
        let root = tempfile::tempdir().unwrap();
        let cache = Cache { root: root.path().to_path_buf() };
        let bundle = verify(&bundle_json("acme", "hello", "1.0.0", &sample()), &reference(), "1.0.0", None).unwrap();
        cache.store(&bundle).unwrap();
        assert_eq!(cache.load("acme", "hello", "1.0.0").unwrap().unwrap().files, sample());
        assert_eq!(cache.versions("acme", "hello"), ["1.0.0"]);
        std::fs::write(root.path().join("acme/hello/1.0.0/app/x.js"), "tampered").unwrap();
        assert!(cache.load("acme", "hello", "1.0.0").unwrap_err().contains("was changed after it was downloaded"));
        assert!(!root.path().join("acme/hello/1.0.0").exists() && !root.path().join("acme/hello/1.0.0.json").exists(), "the entry is dropped");
        cache.store(&bundle).unwrap();
        std::fs::write(root.path().join("acme/hello/1.0.0/extra.sh"), "planted").unwrap();
        assert!(cache.load("acme", "hello", "1.0.0").is_err(), "a planted file is refused");
        assert!(cache.load("acme", "hello", "9.9.9").unwrap().is_none());
    }

    #[test]
    fn canonical_windows_paths_are_shown_plainly() {
        assert_eq!(plain(PathBuf::from(r"\\?\C:\Templates\shop")), PathBuf::from(r"C:\Templates\shop"));
        assert_eq!(plain(PathBuf::from(r"\\?\UNC\server\share")), PathBuf::from(r"\\?\UNC\server\share"), "network paths keep their prefix");
        assert_eq!(plain(PathBuf::from("/home/me/shop")), PathBuf::from("/home/me/shop"));
    }

    #[tokio::test]
    async fn an_existing_instance_uses_its_own_checked_copy_even_after_removal() {
        let files = sample();
        let digest = scan::digest_of(&files);
        let root = tempfile::tempdir().unwrap();
        let cache = Cache { root: root.path().to_path_buf() };
        let removed = Fixture::default();
        *removed.detail.lock().unwrap() = json!({"ref": "acme/hello", "state": "removed", "removed": {"message": "Removed by Yougori: harmful code."}});
        let site = Site::at(&serve(removed).await).unwrap();
        let pinned = reference().at("1.0.0");
        assert!(own(&site, &cache, &pinned, &digest).await.err().unwrap().contains("no longer on this computer and could not be downloaded again"));
        cache.store(&verify(&bundle_json("acme", "hello", "1.0.0", &files), &reference(), "1.0.0", None).unwrap()).unwrap();
        let kept = own(&site, &cache, &pinned, &digest).await.unwrap();
        assert_eq!(kept.bundle.files, files, "the copy here runs although the item was removed");
        assert!(obtain(&site, &cache, &reference()).await.err().unwrap().contains("no longer on the Hub"), "a new run is still refused");
        assert!(own(&site, &cache, &pinned, &"0".repeat(64)).await.is_err(), "other files are never used");
    }

    #[test]
    fn a_file_this_computer_cannot_store_is_said_plainly() {
        let mut files = sample();
        files.insert("docs/con.txt".into(), b"x".to_vec());
        let error = verify(&bundle_json("acme", "hello", "1.0.0", &files), &reference(), "1.0.0", None).unwrap_err();
        assert_eq!(error, "acme/hello 1.0.0: this version has a file name Yougori cannot store on this computer (docs/con.txt). Nothing was created. Update Yougori with yougori update, or run another version.");
        let mut accents = sample();
        accents.insert("caf\u{e9}.txt".into(), b"x".to_vec());
        accents.insert("cafe\u{301}.txt".into(), b"y".to_vec());
        let error = verify(&bundle_json("acme", "hello", "1.0.0", &accents), &reference(), "1.0.0", None).unwrap_err();
        assert!(error.contains("cannot store on this computer") && !error.contains("integrity"), "{error}");
    }

    #[test]
    fn two_runs_storing_the_same_version_both_succeed_and_old_leftovers_go() {
        let root = tempfile::tempdir().unwrap();
        let cache = Cache { root: root.path().to_path_buf() };
        let bundle = verify(&bundle_json("acme", "hello", "1.0.0", &sample()), &reference(), "1.0.0", None).unwrap();
        cache.store(&bundle).unwrap();
        // The second run finds the first one's copy in place, as when two runs race.
        cache.store(&bundle).unwrap();
        assert_eq!(cache.load("acme", "hello", "1.0.0").unwrap().unwrap().files, sample());
        // A copy left half-written (no list beside it) is replaced.
        std::fs::remove_file(root.path().join("acme/hello/1.0.0.json")).unwrap();
        std::fs::write(root.path().join("acme/hello/1.0.0/stray.txt"), "half").unwrap();
        cache.store(&bundle).unwrap();
        assert_eq!(cache.load("acme", "hello", "1.0.0").unwrap().unwrap().files, sample());
        // A staging file an interrupted run left an hour ago is removed; a fresh one is not.
        let old = root.path().join("acme/hello/.partial-old");
        let fresh = root.path().join("acme/hello/.partial-fresh");
        std::fs::write(&old, "x").unwrap();
        std::fs::write(&fresh, "x").unwrap();
        std::fs::File::options().write(true).open(&old).unwrap().set_modified(std::time::SystemTime::now() - Duration::from_secs(7200)).unwrap();
        cache.store(&bundle).unwrap();
        assert!(!old.exists() && fresh.exists());
    }

    #[test]
    fn the_install_id_is_made_once() {
        let home = tempfile::tempdir().unwrap();
        let id = install_id(home.path()).unwrap();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        assert_eq!(install_id(home.path()).unwrap(), id);
        std::fs::write(home.path().join("hub/install-id"), "bad id!").unwrap();
        assert_ne!(install_id(home.path()).unwrap(), "bad id!");
    }

    #[derive(Clone, Default)]
    pub(crate) struct Fixture {
        pub detail: Arc<Mutex<Value>>,
        pub bundle: Arc<Mutex<Value>>,
        pub clones: Arc<Mutex<Vec<Value>>>,
    }

    /// A local Hub on 127.0.0.1 serving one item.
    pub(crate) async fn serve(fixture: Fixture) -> String {
        async fn detail(State(f): State<Fixture>, UrlPath((p, n)): UrlPath<(String, String)>) -> (StatusCode, Json<Value>) {
            let value = f.detail.lock().unwrap().clone();
            if value["ref"] != format!("{p}/{n}").as_str() {
                return (StatusCode::NOT_FOUND, Json(json!({"error": format!("{p}/{n} is not on the Hub. Check the name or search the Hub."), "code": "not_found"})));
            }
            (StatusCode::OK, Json(value))
        }
        async fn bundle(State(f): State<Fixture>) -> (StatusCode, Json<Value>) {
            let value = f.bundle.lock().unwrap().clone();
            if value.is_null() {
                return (StatusCode::GONE, Json(json!({"error": "acme/hello is no longer on the Hub. Removed by Yougori: harmful code.", "code": "item_removed"})));
            }
            (StatusCode::OK, Json(value))
        }
        async fn clones(State(f): State<Fixture>, Json(body): Json<Value>) -> Json<Value> {
            f.clones.lock().unwrap().push(body);
            Json(json!({"clones": 1}))
        }
        let app = Router::new()
            .route("/api/hub/items/{p}/{n}", get(detail))
            .route("/api/hub/items/{p}/{n}/bundle", get(bundle))
            .route("/api/hub/items/{p}/{n}/clones", post(clones))
            .with_state(fixture);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{address}")
    }

    #[tokio::test]
    async fn obtain_downloads_reuses_and_refuses_as_the_spec_says() {
        let files = sample();
        let digest = scan::digest_of(&files);
        let fixture = Fixture::default();
        *fixture.detail.lock().unwrap() = json!({"ref": "acme/hello", "state": "active", "latestVersion": "1.0.0", "version": {"version": "1.0.0", "digest": digest, "review": {}}});
        *fixture.bundle.lock().unwrap() = bundle_json("acme", "hello", "1.0.0", &files);
        let base = serve(fixture.clone()).await;
        let site = Site::at(&base).unwrap();
        let root = tempfile::tempdir().unwrap();
        let cache = Cache { root: root.path().to_path_buf() };
        let got = obtain(&site, &cache, &reference()).await.unwrap();
        assert_eq!(got.bundle.version, "1.0.0");
        assert!(got.notice.is_none());
        assert!(root.path().join("acme/hello/1.0.0/app/x.js").exists());
        assert_eq!(site.count_clone(&reference(), "1.0.0", "install-id-0123456789").await, Some(1));
        assert_eq!(fixture.clones.lock().unwrap()[0], json!({"version": "1.0.0", "install": "install-id-0123456789"}));
        // A tampered download is refused and leaves no copy behind.
        cache.drop("acme", "hello", "1.0.0");
        let mut tampered = bundle_json("acme", "hello", "1.0.0", &files);
        tampered["files"][1]["content"] = json!(B64.encode(b"evil"));
        *fixture.bundle.lock().unwrap() = tampered;
        let error = obtain(&site, &cache, &reference()).await.err().unwrap();
        assert!(error.contains("failed its integrity check") && error.contains("Nothing was created"), "{error}");
        assert!(!root.path().join("acme/hello/1.0.0").exists());
        // A removed item is refused with its reason.
        *fixture.detail.lock().unwrap() = json!({"ref": "acme/hello", "state": "removed", "removed": {"reason": "harmful", "message": "Removed by Yougori: harmful code."}, "versions": [], "version": null});
        assert_eq!(obtain(&site, &cache, &reference()).await.err().unwrap(), "acme/hello is no longer on the Hub. Removed by Yougori: harmful code. Nothing was created.");
        // Unreachable: a saved copy runs with a notice; without one, nothing changes.
        let offline = Site::at("http://127.0.0.1:9").unwrap();
        let none = obtain(&offline, &cache, &reference()).await.err().unwrap();
        assert!(none.contains("Cannot reach the Hub") && none.contains("Nothing was changed"), "{none}");
        let mut verified = bundle_json("acme", "hello", "1.0.0", &files);
        verified["verified"] = json!(true);
        cache.store(&verify(&verified, &reference(), "1.0.0", None).unwrap()).unwrap();
        let saved = obtain(&offline, &cache, &reference()).await.unwrap();
        let notice = saved.notice.unwrap();
        assert!(notice.contains("Using the copy of acme/hello 1.0.0 saved on this computer") && notice.contains("treated as a community item"), "{notice}");
        assert!(saved.detail.is_none() && !saved.bundle.verified, "offline, nothing can confirm the badge");
    }

    #[tokio::test]
    async fn a_saved_copy_never_claims_more_than_the_page_and_errors_never_fall_back() {
        let files = sample();
        let digest = scan::digest_of(&files);
        let fixture = Fixture::default();
        *fixture.detail.lock().unwrap() = json!({"ref": "acme/hello", "kind": "template", "state": "active", "latestVersion": "1.0.0", "version": {"version": "1.0.0", "digest": digest, "verified": false, "review": {}}});
        *fixture.bundle.lock().unwrap() = bundle_json("acme", "hello", "1.0.0", &files);
        let site = Site::at(&serve(fixture.clone()).await).unwrap();
        let root = tempfile::tempdir().unwrap();
        let cache = Cache { root: root.path().to_path_buf() };
        assert!(!obtain(&site, &cache, &reference()).await.unwrap().bundle.verified);
        // Someone edits the list saved beside the copy to claim the badge.
        let meta_path = root.path().join("acme/hello/1.0.0.json");
        let mut meta: Value = serde_json::from_slice(&std::fs::read(&meta_path).unwrap()).unwrap();
        meta["verified"] = json!(true);
        std::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
        assert!(!obtain(&site, &cache, &reference()).await.unwrap().bundle.verified, "the page decides, not the saved list");
        // A saved copy of another kind is downloaded again.
        meta["kind"] = json!("tool");
        std::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).unwrap();
        assert_eq!(obtain(&site, &cache, &reference()).await.unwrap().bundle.kind, "template");
        // A 5xx answer is an error that changes nothing; the saved copy does not stand in.
        let broken = Router::new().route("/api/hub/items/{p}/{n}", get(|| async { (StatusCode::BAD_GATEWAY, Json(json!({"error": "Upstream unavailable."}))) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, broken).await.unwrap() });
        let error = obtain(&Site::at(&format!("http://{address}")).unwrap(), &cache, &reference()).await.err().unwrap();
        assert_eq!(error, "Upstream unavailable. The Hub is having trouble; try again in a few minutes. Nothing was changed.");
        // A version the server serves but this CLI cannot read is said plainly.
        fixture.detail.lock().unwrap()["version"]["version"] = json!("1.0.0-rc.01");
        let unreadable = obtain(&site, &cache, &reference()).await.err().unwrap();
        assert!(unreadable.starts_with("The Hub offers acme/hello as version 1.0.0-rc.01, which this Yougori cannot read."), "{unreadable}");
    }

    #[tokio::test]
    async fn a_run_goes_on_when_the_copy_cannot_be_kept() {
        let files = sample();
        let fixture = Fixture::default();
        *fixture.detail.lock().unwrap() = json!({"ref": "acme/hello", "state": "active", "latestVersion": "1.0.0", "version": {"version": "1.0.0", "digest": scan::digest_of(&files), "review": {}}});
        *fixture.bundle.lock().unwrap() = bundle_json("acme", "hello", "1.0.0", &files);
        let site = Site::at(&serve(fixture).await).unwrap();
        let root = tempfile::tempdir().unwrap();
        // The cache folder is a file, so nothing can be written there.
        let blocked = root.path().join("cache");
        std::fs::write(&blocked, "not a folder").unwrap();
        let got = obtain(&site, &Cache { root: blocked }, &reference()).await.unwrap();
        assert_eq!(got.bundle.files, files);
        assert!(got.notice.unwrap().contains("Could not keep a copy of acme/hello on this computer"));
    }
}
