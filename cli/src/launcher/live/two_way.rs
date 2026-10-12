//! Three-way reconciliation: only the side unchanged since the last shared
//! checksum may be overwritten. Concurrent edits remain on both sides.
use super::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Write},
};

/// NTFS, and APFS/HFS+ as normally formatted, resolve names regardless of letter case.
pub(super) const CASE_INSENSITIVE: bool = cfg!(any(windows, target_os = "macos"));

#[derive(Debug, PartialEq)]
enum Change {
    Same,
    Push,
    Pull,
    Conflict,
}

fn prioritized(change: Change, priority: sync::Priority) -> Change {
    if change != Change::Conflict { return change; }
    match priority { sync::Priority::Local => Change::Push, sync::Priority::Remote => Change::Pull, sync::Priority::KeepBoth => Change::Conflict }
}

fn change<'a>(base: Option<&'a str>, local: Option<&'a str>, remote: Option<&'a str>) -> Change {
    if local == remote {
        Change::Same
    } else if local == base {
        Change::Pull
    } else if remote == base {
        Change::Push
    } else {
        Change::Conflict
    }
}

fn skipped_links(reply: &Value, batch: &[String]) -> Result<BTreeSet<String>, String> {
    let entries = reply["skipped"].as_array().ok_or("Missing sync link inspection")?;
    let mut skipped = BTreeSet::new();
    for entry in entries {
        let path = entry.as_str().ok_or("Invalid sync link inspection")?;
        if !batch.iter().any(|p| p == path) { return Err("Unexpected sync link path".into()); }
        skipped.insert(path.to_owned());
    }
    Ok(skipped)
}

/// How this computer's filesystem identifies a path.
pub(super) fn identity(path: &str) -> String {
    if CASE_INSENSITIVE {
        path.split('/').map(sync::folded).collect::<Vec<_>>().join("/")
    } else {
        path.to_owned()
    }
}

fn windows_device(part: &str) -> bool {
    let base = part.split('.').next().unwrap_or("").trim_end_matches(' ').to_ascii_uppercase();
    matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$")
        || ["COM", "LPT"].iter().any(|device| {
            base.strip_prefix(device).is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"))
        })
}

/// Why this computer cannot store a path, if it cannot. Windows rules apply only on Windows.
fn unsupported(relative: &str) -> Option<&'static str> {
    if relative.is_empty() || relative.len() > 4096 || relative.split('/').count() > 128 {
        return Some("too long or nested too deeply");
    }
    if relative.chars().any(|c| c.is_control() || c == '\\') {
        return Some("control characters or backslashes");
    }
    for part in relative.split('/') {
        if part.is_empty() || part == "." || part == ".." || part.starts_with(".yougori-sync-") {
            return Some("an empty or reserved name");
        }
        if cfg!(windows) {
            if part.ends_with(['.', ' ']) || part.contains(['<', '>', ':', '"', '|', '?', '*']) {
                return Some("characters Windows filenames cannot contain");
            }
            if windows_device(part) {
                return Some("a name Windows reserves for devices");
            }
        }
    }
    None
}

fn validate(relative: &str) -> Result<(), String> {
    match unsupported(relative) {
        Some(reason) => Err(format!("Unsupported sync path ({reason}): {}", clean(relative))),
        None => Ok(()),
    }
}

pub(super) fn destination(root: &Path, relative: &str) -> Result<PathBuf, String> {
    validate(relative)?;
    let mut path = root.to_path_buf();
    for part in relative.split('/') {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(meta) if sync::linked(&meta) => {
                return Err(format!(
                    "A symlink or junction blocks sync: {}",
                    clean(relative)
                ))
            }
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(format!("Cannot inspect {}: {e}", clean(relative))),
        }
    }
    Ok(path)
}

/// Where to write or delete a container path on this computer. Every existing
/// component must be stored under exactly the requested name: letter case,
/// Windows short (8.3) names and characters HFS+ ignores could otherwise redirect
/// the path to a different file here, such as one in .git. Host-only folders
/// are never written.
pub(super) fn host_target(root: &Path, relative: &str) -> Result<PathBuf, String> {
    let path = destination(root, relative)?;
    if relative.split('/').any(sync::host_only) {
        return Err(format!("Two-way sync does not write {}", clean(relative)));
    }
    let mut parent = root.to_path_buf();
    for part in relative.split('/') {
        let next = parent.join(part);
        match fs::symlink_metadata(&next) {
            Ok(_) => {
                let stored = fs::read_dir(&parent)
                    .map_err(|e| format!("Cannot inspect {}: {e}", clean(relative)))?
                    .flatten()
                    .any(|entry| entry.file_name().to_str() == Some(part));
                if !stored {
                    return Err(format!("{} names a differently spelled file on this computer", clean(relative)));
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => break,
            Err(e) => return Err(format!("Cannot inspect {}: {e}", clean(relative))),
        }
        parent = next;
    }
    Ok(path)
}

fn local_hash(root: &Path, relative: &str) -> Result<Option<String>, String> {
    local_hash_until(root, relative, &AtomicBool::new(false))
}

/// [`local_hash`] that ends at its next chunk once `stop` is set.
fn local_hash_until(root: &Path, relative: &str, stop: &AtomicBool) -> Result<Option<String>, String> {
    let path = destination(root, relative)?;
    let meta = match fs::symlink_metadata(&path) {
        Ok(meta) => meta,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if !meta.is_file() {
        return Err(format!("Not a supported sync file: {}", clean(relative)));
    }
    let mut file = fs::File::open(&path).map_err(|e| e.to_string())?;
    let mut hash = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    let mut size = 0;
    loop {
        if stop.load(Ordering::Relaxed) {
            return Err(STOPPED.into());
        }
        let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        size += n as u64;
        hash.update(&buffer[..n]);
    }
    if size != meta.len()
        || file.metadata().map_err(|e| e.to_string())?.modified().ok() != meta.modified().ok()
    {
        return Err(format!("{} changed during sync; retrying", clean(relative)));
    }
    Ok(Some(format!("{:x}", hash.finalize())))
}

/// [`local_hash`] in a pass a launch may be waiting for. A file of a megabyte or more is read off
/// the runtime's thread, so Ctrl+C is noticed while it is read; a wait that is dropped ends it.
async fn local_hash_beside(root: &Path, relative: &str, size: u64) -> Result<Option<String>, String> {
    if size < 1024 * 1024 {
        return local_hash(root, relative);
    }
    let (root, relative) = (root.to_owned(), relative.to_owned());
    off_thread(move |stop| local_hash_until(&root, &relative, stop)).await
}

fn expect_local(root: &Path, relative: &str, expected: Option<&str>) -> Result<PathBuf, String> {
    if local_hash(root, relative)?.as_deref() != expected {
        return Err(format!(
            "{} changed during sync; both versions were kept",
            clean(relative)
        ));
    }
    destination(root, relative)
}

/// Renames a file in place when only the letter case of its name changed.
fn rename_case(root: &Path, from: &str, to: &str) -> Result<(), String> {
    let (parent, from_name) = from.rsplit_once('/').unwrap_or(("", from));
    let (to_parent, to_name) = to.rsplit_once('/').unwrap_or(("", to));
    if parent != to_parent || sync::folded(from_name) != sync::folded(to_name) {
        return Err("Only a change of letter case is renamed here".into());
    }
    validate(to)?;
    host_target(root, from)?;
    let folder = if parent.is_empty() { root.to_path_buf() } else { host_target(root, parent)? };
    let taken = fs::read_dir(&folder)
        .map_err(|e| e.to_string())?
        .flatten()
        .any(|entry| entry.file_name().to_str() == Some(to_name));
    if taken {
        return Err(format!("{} already exists", clean(to)));
    }
    fs::rename(folder.join(from_name), folder.join(to_name)).map_err(|e| e.to_string())
}

/// Paths whose names differ only by letter case, on a filesystem that cannot store both.
#[derive(Debug, PartialEq)]
enum CasePlan {
    /// Both copies use the new spelling; keep the shared checksum under it.
    Agree { from: String, to: String },
    /// This computer renamed `from` to `to`: rename it in the container too.
    Push { from: String, to: String },
    /// The container renamed the file `from` to `to` in the same folder.
    Pull { from: String, to: String },
    /// Leave every copy untouched until the spellings match again.
    Hold(Vec<String>),
}

fn case_plans(
    local: &BTreeMap<String, String>,
    remote: &BTreeMap<String, String>,
    common: &BTreeMap<String, String>,
) -> Vec<CasePlan> {
    let mut groups: BTreeMap<String, BTreeSet<&String>> = BTreeMap::new();
    for path in local.keys().chain(remote.keys()).chain(common.keys()) {
        groups.entry(identity(path)).or_default().insert(path);
    }
    // At most one spelling per side; two would be ambiguous.
    let one = |map: &BTreeMap<String, String>, names: &BTreeSet<&String>| -> Option<Option<String>> {
        let mut found = names.iter().filter(|name| map.contains_key(name.as_str()));
        let first = found.next().map(|name| (*name).clone());
        found.next().is_none().then_some(first)
    };
    let parent = |path: &str| path.rsplit_once('/').map_or("", |(parent, _)| parent).to_owned();
    groups
        .into_values()
        .filter(|names| names.len() > 1)
        .map(|names| {
            let hold = || CasePlan::Hold(names.iter().map(|name| (*name).clone()).collect());
            let (Some(l), Some(r), Some(c)) = (one(local, &names), one(remote, &names), one(common, &names)) else {
                return hold();
            };
            match (l, r, c) {
                (Some(l), Some(r), Some(c)) if l == r && c != l => CasePlan::Agree { from: c, to: l },
                (Some(l), Some(r), Some(c)) if c == r && l != r && remote[&r] == common[&c] => {
                    CasePlan::Push { from: r, to: l }
                }
                (Some(l), Some(r), Some(c))
                    if c == l && l != r && local[&l] == common[&c] && parent(&l) == parent(&r) =>
                {
                    CasePlan::Pull { from: l, to: r }
                }
                _ => hold(),
            }
        })
        .collect()
}

/// The shortest leading paths whose spellings differ, such as `src` and `Src` for
/// `src/a.js` and `Src/a.js`.
fn spelled_differently(names: &[String]) -> Vec<String> {
    let parts: Vec<Vec<&str>> = names.iter().map(|name| name.split('/').collect()).collect();
    let depth = parts.iter().map(Vec::len).min().unwrap_or(0);
    let first = (0..depth).find(|&i| parts.iter().any(|p| p[i] != parts[0][i])).unwrap_or(depth.saturating_sub(1));
    let mut prefixes: Vec<String> = parts.iter().map(|p| p[..=first].join("/")).collect();
    prefixes.sort();
    prefixes.dedup();
    prefixes
}

/// The container's workspace, classified for this computer.
#[derive(Debug, Default)]
struct Inventory {
    /// Regular files and their change stamps in the container.
    files: Vec<(String, String)>,
    directories: BTreeSet<String>,
    databases: BTreeSet<String>,
    /// Never transferred this pass; the warning explains why.
    held: Vec<(String, Option<String>)>,
}

fn beneath(held: &BTreeSet<String>, identity: &str) -> bool {
    held.contains(identity) || identity.match_indices('/').any(|(end, _)| held.contains(&identity[..end]))
}

fn classify(entries: &[Value], filter: &sync::Filter) -> Result<Inventory, String> {
    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let (Some(path), Some(kind)) = (entry["path"].as_str(), entry["kind"].as_str()) else {
            return Err("Invalid sync inventory".into());
        };
        if path.split('/').any(|part| part.is_empty() || part == "." || part == "..") {
            return Err("Invalid sync inventory path".into());
        }
        if !filter.excluded(path, kind == "dir") {
            parsed.push((path, kind, entry));
        }
    }
    let mut inventory = Inventory::default();
    let mut held = BTreeSet::new();
    let mut spellings: BTreeMap<String, Vec<&str>> = BTreeMap::new();
    // Entries arrive parents first, so a held folder also covers everything below it.
    for (path, _, entry) in &parsed {
        let id = identity(path);
        if beneath(&held, &id) {
            continue;
        }
        let warning = if entry["pruned"] == true {
            Some(format!("{} in the container could not be inspected; it was left unchanged", clean(path)))
        } else {
            unsupported(path).map(|reason| format!("{} in the container cannot be stored on this computer ({reason}); it stays in the container", clean(path)))
        };
        if warning.is_some() {
            held.insert(id);
            inventory.held.push(((*path).to_owned(), warning));
        } else {
            spellings.entry(id).or_default().push(*path);
        }
    }
    for (id, paths) in &spellings {
        if paths.len() > 1 && !beneath(&held, id) {
            held.insert(id.clone());
            let names = paths.iter().map(|path| clean(path)).collect::<Vec<_>>().join(" / ");
            inventory.held.push((paths[0].to_owned(), Some(format!("The container has names that differ only by letter case: {names}. This computer cannot store both; rename one in the container"))));
        }
    }
    for (path, kind, entry) in &parsed {
        if beneath(&held, &identity(path)) {
            continue;
        }
        match *kind {
            "dir" => { inventory.directories.insert((*path).to_owned()); }
            "sqlite" => { inventory.databases.insert((*path).to_owned()); }
            "file" => inventory.files.push(((*path).to_owned(), entry["stamp"].as_str().ok_or("Missing sync file stamp")?.to_owned())),
            // Linux dependencies create symlinks after installation. Do not follow
            // them or let one block unrelated file edits.
            _ => inventory.held.push(((*path).to_owned(), None)),
        }
    }
    Ok(inventory)
}

impl Session {
    pub(super) async fn rpc(&mut self, request: Value) -> Result<Value, String> {
        self.rpc_progress(request, None).await
    }
    pub(super) async fn rpc_progress(&mut self, request: Value, progress: Option<&ui::Task>) -> Result<Value, String> {
        let seq = nonce();
        self.write(
            format!(
                "X {seq} {}\n",
                B64.encode(serde_json::to_vec(&request).map_err(|e| e.to_string())?)
            )
            .as_bytes(),
        )
        .await?;
        let prefix = format!("rpc:{seq}:");
        let progress_prefix = format!("progress:{seq}:");
        let end = format!("end:{seq}");
        let mut deadline = Instant::now() + Duration::from_secs(60);
        let mut data = String::new();
        loop {
            let (_, events) = self.read().await?;
            for event in events {
                if let Some(encoded) = event.strip_prefix(&progress_prefix) {
                    let measurement: Value = serde_json::from_slice(&B64.decode(encoded).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                    if let Some(progress) = progress { progress.database_progress(&measurement, "container"); }
                    // A measured operation is active, even if a large database needs
                    // more than a minute to finish indexing or committing.
                    deadline = Instant::now() + Duration::from_secs(60);
                    continue;
                }
                if let Some(chunk) = event.strip_prefix(&prefix) {
                    data.push_str(chunk);
                    if data.len() > 256 * 1024 {
                        return Err("Sync reply exceeded its limit".into());
                    }
                } else if event == end {
                    let reply: Value =
                        serde_json::from_slice(&B64.decode(data).map_err(|e| e.to_string())?)
                            .map_err(|e| e.to_string())?;
                    if let Some(error) = reply["error"].as_str() {
                        return Err(error.into());
                    }
                    return Ok(reply["result"].clone());
                } else if let Some(error) = event.strip_prefix("error:") {
                    return Err(
                        String::from_utf8_lossy(&B64.decode(error).unwrap_or_default()).into(),
                    );
                }
            }
            if Instant::now() > deadline {
                return Err("Timed out waiting for two-way sync".into());
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
}

impl Live {
    pub(super) fn warn_once(&mut self, message: String) {
        if self.warned.insert(message.clone()) {
            ui::warn(&message);
        }
    }

    pub(super) fn hold(&mut self, path: &str, warning: Option<String>) {
        self.held.insert(identity(path));
        if let Some(message) = warning {
            self.warn_once(message);
        }
    }

    /// Links, unsupported names and unresolved letter-case differences: never
    /// transferred and never mistaken for deletions, including paths beneath them.
    pub(super) fn is_held(&self, path: &str) -> bool {
        !self.held.is_empty() && beneath(&self.held, &identity(path))
    }

    /// Recover an interrupted/missing checkpoint without replacing the workspace.
    /// Only host files and previously tracked deletions are candidates; guest-only
    /// runtime data must survive a reconnect.
    pub async fn reconcile_one_way(&mut self, manifest: &sync::Manifest) -> Result<(), String> {
        self.discover_databases(manifest).await;
        self.database_files.extend(self.saved.databases.keys().cloned());
        let paths: BTreeSet<_> = manifest.keys().chain(self.saved.files.keys())
            .chain(self.saved.pending.iter()).filter(|p| !sync::database_member(p, &self.database_files)).cloned().collect();
        let mut baseline = sync::Manifest::new();
        let progress = ui::task("Comparing project files to resume sync");
        let paths = paths.into_iter().collect::<Vec<_>>();
        progress.progress("Comparing files", 0, paths.len() as u64, "files");
        let mut completed = 0;
        let mut kept_links = 0;
        for batch in paths.chunks(32) {
            let reply = self.receiver.rpc(json!({"op":"hashes","paths":batch,"skipLinks":true})).await?;
            let skipped = skipped_links(&reply, batch)?;
            let remote = &reply["hashes"];
            for path in batch {
                // Linux package managers replace Windows command shims with links.
                // Keep the link, never follow it, and checkpoint the host version
                // so a reconnect does not try to overwrite it on every launch.
                if skipped.contains(path) {
                    if let Some(stamp) = manifest.get(path) { baseline.insert(path.clone(), *stamp); }
                    kept_links += 1;
                    continue;
                }
                let hash = remote.get(path).ok_or("Missing recovery checksum")?;
                if let Some(stamp) = manifest.get(path) {
                    if local_hash_beside(&self.folder, path, stamp.0).await?.as_deref() == hash.as_str() {
                        baseline.insert(path.clone(), *stamp);
                    }
                } else if !hash.is_null() {
                    baseline.insert(path.clone(), (0, 0));
                }
            }
            completed += batch.len() as u64;
            progress.progress("Comparing files", completed, paths.len() as u64, "files");
        }
        progress.clear();
        if kept_links > 0 { ui::info(&format!("Kept {kept_links} container symlink paths; sync does not follow links")); }
        self.saved.files = baseline;
        self.saved.pending.clear();
        self.saved.token.clear();
        self.saved.environment = self.receiver.environment.clone();
        self.saved.two_way = false;
        self.saved.save(&self.state_path)
    }

    /// Check destinations without reading link targets or hashing large files.
    pub(super) async fn keep_remote_links(&mut self, changed: &mut BTreeSet<String>, removed: &mut BTreeSet<String>) -> Result<(), String> {
        let paths: Vec<_> = changed.iter().chain(removed.iter()).cloned().collect();
        let mut skipped = BTreeSet::new();
        for batch in paths.chunks(64) {
            let reply = self.receiver.rpc(json!({"op":"links","paths":batch})).await?;
            skipped.extend(skipped_links(&reply, batch)?);
        }
        if !skipped.is_empty() {
            changed.retain(|p| !skipped.contains(p));
            removed.retain(|p| !skipped.contains(p));
            self.saved.pending.retain(|p| !skipped.contains(p));
            ui::info(&format!("Kept {} container symlink paths; sync does not follow links", skipped.len()));
        }
        Ok(())
    }

    /// The same bounded, atomic transfer works for large one-way edits too.
    pub(super) async fn sync_large_file(&mut self, path: &str) -> Result<(), String> {
        let local = local_hash(&self.folder, path)?.ok_or("File disappeared during sync; retrying")?;
        let reply = self.receiver.rpc(json!({"op":"hash","path":path})).await?;
        self.push_file(path, Some(&local), reply["hash"].as_str()).await
    }

    /// One paged inventory of the container's workspace. Host-only folders are not
    /// entered. Files whose change stamp is unchanged reuse their earlier checksum.
    async fn remote_hashes(
        &mut self,
        filter: &sync::Filter,
        progress: &ui::Task,
    ) -> Result<BTreeMap<String, String>, String> {
        let mut entries = Vec::new();
        let (mut cursor, mut offset) = (Value::Null, 0u64);
        loop {
            progress.copy_status(&format!("Finding container files · {} found", entries.len()));
            let reply = self
                .receiver
                .rpc(json!({"op":"tree","cursor":cursor,"offset":offset,"prune":sync::HOST_ONLY}))
                .await?;
            entries.extend(reply["entries"].as_array().ok_or("Invalid sync inventory")?.iter().cloned());
            cursor = reply["cursor"].clone();
            match reply["next"].as_u64() {
                Some(next) if next > offset => offset = next,
                Some(_) => return Err("Invalid sync inventory offset".into()),
                None => break,
            }
            self.pump().await?;
        }
        let inventory = classify(&entries, filter)?;
        drop(entries);
        for (path, warning) in inventory.held {
            self.hold(&path, warning);
        }
        self.remote_directories = inventory.directories;
        self.database_files.extend(inventory.databases);
        let mut hashes = BTreeMap::new();
        let mut stamps = BTreeMap::new();
        let mut unknown = Vec::new();
        for (path, stamp) in inventory.files {
            if sync::database_member(&path, &self.database_files) {
                continue;
            }
            match self.remote_stamps.remove(&path) {
                Some((known, hash)) if known == stamp => {
                    hashes.insert(path.clone(), hash.clone());
                    stamps.insert(path, (stamp, hash));
                }
                _ => unknown.push((path, stamp)),
            }
        }
        progress.progress("Checking container files", 0, unknown.len() as u64, "files");
        let mut completed = 0;
        for batch in unknown.chunks(32) {
            let paths: Vec<String> = batch.iter().map(|(path, _)| path.clone()).collect();
            let reply = self
                .receiver
                .rpc(json!({"op":"hashes","paths":paths,"skipLinks":true}))
                .await?;
            let skipped = skipped_links(&reply, &paths)?;
            for (path, stamp) in batch {
                if skipped.contains(path) {
                    self.hold(path, None);
                    continue;
                }
                match reply["hashes"].get(path) {
                    Some(Value::String(hash)) if hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()) => {
                        hashes.insert(path.clone(), hash.clone());
                        stamps.insert(path.clone(), (stamp.clone(), hash.clone()));
                    }
                    // Deleted after the inventory: absent from the container now.
                    Some(Value::Null) => {}
                    _ => return Err("Invalid sync checksum".into()),
                }
            }
            completed += batch.len() as u64;
            progress.progress("Checking container files", completed, unknown.len() as u64, "files");
            self.pump().await?;
        }
        self.remote_stamps = stamps;
        Ok(hashes)
    }

    /// Applies unambiguous letter-case renames and holds every other case difference.
    async fn reconcile_case(
        &mut self,
        local: &mut BTreeMap<String, String>,
        remote: &mut BTreeMap<String, String>,
        direction: sync::Direction,
    ) -> Result<(), String> {
        let visible = |map: &BTreeMap<String, String>| -> BTreeMap<String, String> {
            map.iter().filter(|(path, _)| !self.is_held(path)).map(|(p, h)| (p.clone(), h.clone())).collect()
        };
        let plans = case_plans(&visible(local), &visible(remote), &visible(&self.saved.common));
        for plan in plans {
            match plan {
                CasePlan::Agree { from, to } => {
                    if let Some(hash) = self.saved.common.remove(&from) {
                        self.saved.common.insert(to, hash);
                    }
                }
                CasePlan::Push { from, to } if direction.sends() => {
                    let (hash, previous) = (local[&to].clone(), remote[&from].clone());
                    let renamed = async {
                        self.push_file(&to, Some(&hash), None).await?;
                        self.receiver.rpc(json!({"op":"delete","path":from,"expected":previous})).await.map(|_| ())
                    }
                    .await;
                    match renamed {
                        Ok(()) => {
                            self.saved.common.remove(&from);
                            self.saved.common.insert(to.clone(), hash.clone());
                            remote.remove(&from);
                            remote.insert(to, hash);
                        }
                        Err(error) => self.hold(&to, Some(format!("Could not rename {} to {} in the container: {}. Both copies were kept", clean(&from), clean(&to), clean(&error)))),
                    }
                }
                CasePlan::Pull { from, to } if direction.receives() => {
                    let base = self.saved.common[&from].clone();
                    match expect_local(&self.folder, &from, Some(&base)).and_then(|_| rename_case(&self.folder, &from, &to)) {
                        Ok(()) => {
                            self.saved.common.remove(&from);
                            self.saved.common.insert(to.clone(), base.clone());
                            local.remove(&from);
                            local.insert(to, base);
                            self.local_hashes.remove(&from);
                        }
                        Err(error) => self.hold(&to, Some(format!("Could not rename {} to {} on this computer: {}. Both copies were kept", clean(&from), clean(&to), clean(&error)))),
                    }
                }
                // A one-directional sync leaves the rename for a sync the other way.
                CasePlan::Push { to, .. } | CasePlan::Pull { to, .. } => self.hold(&to, None),
                CasePlan::Hold(names) => {
                    // A folder spelled two ways holds everything beneath it, with one warning.
                    let spelled = spelled_differently(&names);
                    let spellings = spelled.iter().map(|name| clean(name)).collect::<Vec<_>>().join(" / ");
                    self.hold(&spelled[0], Some(format!("Names differ only by letter case: {spellings}. Both copies were kept; give them the same name to resume syncing them")));
                }
            }
        }
        Ok(())
    }

    async fn pull_file(
        &mut self,
        path: &str,
        local: Option<&str>,
        remote: Option<&str>,
    ) -> Result<(), String> {
        expect_local(&self.folder, path, local)?;
        let destination = host_target(&self.folder, path)?;
        let Some(hash) = remote else {
            if local.is_some() {
                // Recheck remote deletion before deleting the unchanged local file.
                let reply = self.receiver.rpc(json!({"op":"hash","path":path})).await?;
                if !reply["hash"].is_null() {
                    return Err("Remote file changed during sync; retrying".into());
                }
                expect_local(&self.folder, path, local)?;
                fs::remove_file(host_target(&self.folder, path)?).map_err(|e| e.to_string())?;
            }
            return Ok(());
        };
        let parent = destination.parent().ok_or("Missing sync directory")?;
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        let mut temp = tempfile::Builder::new()
            .prefix(".yougori-sync-")
            .tempfile_in(parent)
            .map_err(|e| e.to_string())?;
        let mut digest = Sha256::new();
        let mut offset = 0u64;
        let mut progress: Option<ui::Task> = None;
        loop {
            let reply = self
                .receiver
                .rpc(json!({"op":"read","path":path,"offset":offset}))
                .await?;
            let data = B64
                .decode(reply["data"].as_str().ok_or("Missing sync file data")?)
                .map_err(|e| e.to_string())?;
            offset += data.len() as u64;
            let total = reply["total"].as_u64().unwrap_or(offset);
            if total > 64 * 1024 && progress.is_none() {
                let task = ui::task("Downloading changed project file");
                task.detail(&clean(path)); progress = Some(task);
            }
            if let Some(progress) = &progress { progress.progress("Downloading file", offset, total, "bytes"); }
            if data.len() > 24 * 1024 {
                return Err("Sync file exceeded its limit".into());
            }
            temp.write_all(&data).map_err(|e| e.to_string())?;
            digest.update(&data);
            if reply["done"] == true {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mode = reply["mode"].as_u64().unwrap_or(0o644) as u32 & 0o777;
                    temp.as_file()
                        .set_permissions(fs::Permissions::from_mode(mode))
                        .map_err(|e| e.to_string())?;
                }
                break;
            }
            if data.is_empty() {
                return Err("Sync file read made no progress".into());
            }
            self.pump().await?;
        }
        if format!("{:x}", digest.finalize()) != hash {
            return Err(format!("{} changed during download; retrying", clean(path)));
        }
        let reply = self.receiver.rpc(json!({"op":"hash","path":path})).await?;
        if reply["hash"] != hash {
            return Err("Remote file changed during download; retrying".into());
        }
        expect_local(&self.folder, path, local)?;
        let destination = host_target(&self.folder, path)?;
        temp.as_file().sync_all().map_err(|e| e.to_string())?;
        temp.persist(destination).map_err(|e| e.to_string())?;
        if let Some(progress) = progress { progress.clear(); }
        Ok(())
    }

    async fn push_file(
        &mut self,
        path: &str,
        local: Option<&str>,
        remote: Option<&str>,
    ) -> Result<(), String> {
        let source = expect_local(&self.folder, path, local)?;
        let Some(hash) = local else {
            self.receiver
                .rpc(json!({"op":"delete","path":path,"expected":remote}))
                .await?;
            return Ok(());
        };
        self.receiver
            .rpc(json!({"op":"begin","path":path,"expected":remote}))
            .await?;
        let result = async {
            let mut file = fs::File::open(source).map_err(|e| e.to_string())?;
            let total = file.metadata().map_err(|e| e.to_string())?.len();
            let progress = (total > 64 * 1024).then(|| {
                let task = ui::task("Uploading changed project file"); task.detail(&clean(path));
                task.progress("Uploading file", 0, total, "bytes"); task
            });
            let mut completed = 0;
            let mut buffer = [0; 24 * 1024];
            loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 {
                    break;
                }
                self.receiver
                    .rpc(json!({"op":"chunk","data":B64.encode(&buffer[..n])}))
                    .await?;
                completed += n as u64;
                if let Some(progress) = &progress { progress.progress("Uploading file", completed, total, "bytes"); }
                self.pump().await?;
            }
            expect_local(&self.folder, path, local)?;
            self.receiver
                .rpc(json!({"op":"commit","hash":hash}))
                .await?;
            if let Some(progress) = progress { progress.clear(); }
            Ok(())
        }
        .await;
        if result.is_err() {
            let _ = self.receiver.rpc(json!({"op":"abort"})).await;
        }
        result
    }

    pub async fn sync_both(&mut self, env_files: bool) -> Result<usize, String> {
        self.sync_direction(env_files, sync::Direction::Both).await
    }

    /// This computer's checksum of each file, reusing those of files unchanged since the last
    /// pass. Paths that cannot be synced stay on this computer, held with a warning.
    async fn local_checksums(&mut self, paths: &[(String, (u64, i64))], progress: &ui::Task) -> Result<BTreeMap<String, String>, String> {
        let mut local = BTreeMap::new();
        progress.progress("Checking local files", 0, paths.len() as u64, "files");
        for (index, (path, stamp)) in paths.iter().enumerate() {
            if let Some(reason) = unsupported(path) {
                self.hold(path, Some(format!("{} cannot be synced ({reason}); it stays on this computer", clean(path))));
                continue;
            }
            progress.detail(&clean(path));
            if let Some((_, hash)) = self.local_hashes.get(path).filter(|(old, _)| old == stamp) {
                local.insert(path.clone(), hash.clone());
            } else if let Some(hash) = local_hash_beside(&self.folder, path, stamp.0).await? {
                self.local_hashes
                    .insert(path.clone(), (*stamp, hash.clone()));
                local.insert(path.clone(), hash);
            }
            progress.progress("Checking local files", index as u64 + 1, paths.len() as u64, "files");
            self.pump().await?;
            breathe(index + 1).await;
        }
        Ok(local)
    }

    pub(super) async fn sync_direction(&mut self, env_files: bool, direction: sync::Direction) -> Result<usize, String> {
        self.env_files = env_files;
        let progress = ui::task("Checking project changes");
        let filter = sync::Filter::load(&self.folder, env_files)?.two_way();
        let checkpoint = (self.saved.two_way, self.saved.environment.clone(), self.saved.common.clone());
        if self.saved.environment != self.receiver.environment || !self.saved.two_way {
            self.saved.common.clear();
        }
        self.saved.two_way = true;
        self.saved.environment = self.receiver.environment.clone();
        self.saved
            .common
            .retain(|path, _| !filter.excluded(path, false));
        self.held.clear();
        let (manifest, links) = sync::scan_links(&self.folder, &filter)?;
        // A folder replaced by a link here is not followed, and its earlier
        // files are not deletions either.
        for link in &links {
            self.hold(link, None);
        }
        self.discover_databases(&manifest).await;
        self.database_files.extend(self.saved.databases.keys().cloned());
        self.local_hashes
            .retain(|path, _| manifest.contains_key(path));
        let paths: Vec<_> = manifest.iter()
            .filter(|(path, _)| !sync::database_member(path, &self.database_files))
            .map(|(path, stamp)| (path.clone(), *stamp))
            .collect();
        let mut local = self.local_checksums(&paths, &progress).await?;
        let mut remote = self.remote_hashes(&filter, &progress).await?;
        if CASE_INSENSITIVE {
            self.reconcile_case(&mut local, &mut remote, direction).await?;
        }
        self.find_folder_conflicts(&local, &remote)?;
        let paths: BTreeSet<_> = local
            .keys()
            .chain(remote.keys())
            .chain(self.saved.common.keys())
            .cloned()
            .collect();
        let mut changed = Vec::new();
        let mut conflicts = BTreeSet::new();
        let reconciled: Result<(), String> = async {
            for path in paths {
                if sync::database_member(&path, &self.database_files) || self.is_held(&path) { continue; }
                let local_hash = local.get(&path).map(String::as_str);
                let remote_hash = remote.get(&path).map(String::as_str);
                let ordinary = change(
                    self.saved.common.get(&path).map(String::as_str),
                    local_hash,
                    remote_hash,
                );
                let action = prioritized(if ordinary != Change::Same && self.folder_conflict(&path) { Change::Conflict } else { ordinary }, self.priority);
                // Do not advance the common checkpoint for deferred changes. A later
                // handoff in the other direction must still see them, even after restart.
                if (action == Change::Push && !direction.sends()) || (action == Change::Pull && !direction.receives()) { continue; }
                if action != Change::Same {
                    progress.detail(&clean(&path));
                }
                let hash = match action {
                    Change::Conflict => {
                        if !self.conflicts.contains(&path) {
                            ui::warn(&format!("Sync conflict: {} — both versions kept. Make the two copies match to resume syncing this file.", clean(&path)));
                        }
                        conflicts.insert(path);
                        continue;
                    }
                    Change::Same => local_hash,
                    Change::Push => {
                        self.push_file(&path, local_hash, remote_hash).await?;
                        changed.push(path.clone());
                        local_hash
                    }
                    Change::Pull => {
                        self.pull_file(&path, local_hash, remote_hash).await?;
                        changed.push(path.clone());
                        remote_hash
                    }
                };
                if let Some(hash) = hash {
                    self.saved.common.insert(path, hash.into());
                } else {
                    self.saved.common.remove(&path);
                }
                self.pump().await?;
            }
            Ok(())
        }
        .await;
        if let Err(error) = reconciled {
            // Completed transfers stay recorded. Anything else is safe to retry:
            // copies that already match become their common version next pass.
            let _ = self.saved.save(&self.state_path);
            return Err(error);
        }
        if !conflicts.is_empty() {
            ui::dash(|d| {
                d.note(&format!(
                    "{} sync conflict(s) · both versions kept",
                    conflicts.len()
                ))
            });
        }
        self.conflicts = conflicts;
        let files = if changed.is_empty() { manifest } else { sync::scan(&self.folder, &filter)? };
        // One checkpoint per pass, and none when nothing changed.
        if self.saved.files != files || (self.saved.two_way, &self.saved.environment, &self.saved.common) != (checkpoint.0, &checkpoint.1, &checkpoint.2) {
            self.saved.files = files;
            self.saved.save(&self.state_path)?;
        }
        let restart = direction.sends() && !changed.is_empty()
            && (self.crashed
                || changed.iter().any(|p| sync::needs_install(p))
                || package::Project::load(&self.folder)?.is_python());
        if restart && self.dev.is_some() {
            let mut project = package::Project::load(&self.folder)?;
            project.custom_command = self.custom_command.clone();
            let env = environment(&self.folder, &project, &self.saved.files, true, self.app_port, &self.nonce);
            execute(
                &self.receiver.environment,
                &container_command(
                    self.container.as_deref(),
                    &format!(
                        "printf '%s' {} | base64 -d > /yougori/launch/dev.env",
                        shell(&B64.encode(env))
                    ),
                    false,
                ),
            )
            .await?;
            self.receiver.write(b"K\n").await?;
        }
        progress.clear();
        Ok(changed.len() + self.sync_databases_direction(true, direction).await? + self.sync_folders_direction(true, direction).await?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local_sql(root: &Path, sql: &str) -> Result<String, String> {
        let result = std::process::Command::new("node").args(["--no-warnings", "-e",
            "const d=new(require('node:sqlite').DatabaseSync)(process.argv[1]); d.exec('PRAGMA journal_mode=WAL'); if(process.argv[2].startsWith('SELECT')) console.log(JSON.stringify(d.prepare(process.argv[2]).all())); else d.exec(process.argv[2]); d.close();"])
            .arg(root.join("data/records.sqlite")).arg(sql).output().map_err(|e| e.to_string())?;
        if !result.status.success() { return Err(String::from_utf8_lossy(&result.stderr).into()); }
        Ok(String::from_utf8_lossy(&result.stdout).into())
    }

    async fn remote_sql(id: &str, sql: &str) -> Result<String, String> {
        let code = format!("const d=new(require('node:sqlite').DatabaseSync)('/workspace/data/records.sqlite'); const q={}; if(q.startsWith('SELECT')) console.log(JSON.stringify(d.prepare(q).all())); else d.exec(q); d.close();", serde_json::to_string(sql).unwrap());
        let result = call("execute_environment_command", json!({"request":{"environmentId":id,"command":format!("node --no-warnings -e {}", shell(&code))}})).await?;
        if result["exitCode"] != 0 { return Err(result["stderr"].as_str().unwrap_or("SQLite test command failed").into()); }
        Ok(result["stdout"].as_str().unwrap_or("").into())
    }

    #[tokio::test]
    #[ignore = "Creates and deletes an isolated container in the running engine; no public ports or host shares"]
    async fn real_container_syncs_both_ways_preserves_conflicts_and_resumes() {
        use yougori_cli::public;
        let folder = tempfile::tempdir().unwrap();
        let settings = tempfile::tempdir().unwrap();
        let state = settings.path().join("sync.json");
        fs::write(
            folder.path().join("package.json"),
            r#"{"name":"sync-test","scripts":{"dev":"node server.js"}}"#,
        )
        .unwrap();
        fs::write(folder.path().join("code.txt"), "original").unwrap();
        fs::write(folder.path().join("server.js"), "require('http').createServer((q,s)=>s.end('sync fixture')).listen(3000,'0.0.0.0')").unwrap();
        fs::write(folder.path().join(".env"), "not sent").unwrap();
        fs::create_dir(folder.path().join("data")).unwrap();
        fs::write(folder.path().join("data/app.db"), vec![173; 70000]).unwrap();
        local_sql(folder.path(), "CREATE TABLE records(id TEXT PRIMARY KEY, value TEXT); INSERT INTO records VALUES ('base','original')").unwrap();
        // Cross the 64-record batch boundary and the large-record fallback.
        local_sql(folder.path(), "WITH RECURSIVE n(x) AS (SELECT 0 UNION ALL SELECT x+1 FROM n WHERE x<129) INSERT INTO records SELECT 'batch-'||x, 'value-'||x FROM n; INSERT INTO records VALUES ('large',zeroblob(120000))").unwrap();
        fs::write(folder.path().join(".gitignore"), "data/\n").unwrap();
        fs::write(folder.path().join(".yougoriignore"), "data/\n").unwrap();
        fs::create_dir_all(folder.path().join("empty/nested")).unwrap();
        let project = package::Project::load(folder.path()).unwrap();
        let canonical = folder.path().canonicalize().unwrap();
        let label = format!("sync-test-{}", nonce());
        let flags = [
            "--name",
            &label,
            "--cpu",
            "1",
            "--memory",
            "1GB",
            "--storage",
            "2GB",
            "--internet",
            "false",
            "docker.io/library/node:24-bookworm",
        ]
        .map(String::from);
        let mut request = public::parse_run(&flags, false).unwrap().request;
        request["containerCommand"] = json!("sleep infinity");
        request["description"] = json!(label);
        let created = call("run_workload", json!({"request":request,"start":true}))
            .await
            .unwrap();
        let id = created["id"].as_str().unwrap();
        let verify = |ok: bool, message: &str| -> Result<(), String> {
            if ok {
                Ok(())
            } else {
                Err(message.into())
            }
        };
        let result: Result<(), String> = async {
            let manifest = sync::scan(folder.path(), &sync::Filter::load(folder.path(), false)?)?;
            let staging = sync::stage(folder.path(), &manifest)?;
            let mut measurements = Vec::new();
            let copied = public::call_with_progress("copy_files_to_environment", json!({"environmentId":id,"paths":[staging.path().join("project")]}), |progress| measurements.push(progress.clone())).await?;
            verify(measurements.iter().any(|p| p["totalBytes"].as_u64().is_some_and(|n| n > 0)), "Copy job did not report measured byte progress")?;
            let imported = format!("{}/project/workspace", copied["destination"].as_str().ok_or("Missing import destination")?);
            execute(id, &format!("ln -s {} /workspace; test $(wc -c < /workspace/data/app.db) = 70000; test ! -e /workspace/.env", shell(&imported))).await?;
            // Exercise chunked one-way edits through the bulk import's workspace symlink.
            fs::write(folder.path().join("data/app.db"), vec![174; 80000]).map_err(|e| e.to_string())?;
            let initial = staging.databases.keys().cloned().collect();
            let saved = sync::Saved { environment: id.into(), databases: staging.databases, ..Default::default() };
            let mut live = Live::prepare(id, &canonical, &project, &sync::Manifest::new(), true, 3000, &state, saved).await?;
            live.initial_databases = initial;
            let run: Result<(), String> = async {
                let manifest = sync::scan(folder.path(), &sync::Filter::load(folder.path(), false)?)?;
                live.sync_to(manifest.clone()).await?;
                execute(id, "test -d /workspace/empty/nested").await?;
                verify(remote_sql(id, "SELECT value FROM records WHERE id='base'").await?.contains("original"), "Initial SQLite rows not copied")?;
                verify(remote_sql(id, "SELECT count(*) AS n FROM records WHERE id LIKE 'batch-%'").await?.contains("130"), "Batched SQLite rows were lost")?;
                verify(remote_sql(id, "SELECT length(value) AS n FROM records WHERE id='large'").await?.contains("120000"), "Large SQLite record fallback was truncated")?;
                remote_sql(id, "INSERT INTO records VALUES ('guest','guest-only')").await?;
                live.sync_to(manifest.clone()).await?;
                verify(!local_sql(folder.path(), "SELECT value FROM records WHERE id='guest'")?.contains("guest-only"), "One-way SQLite sync pulled a guest record")?;
                execute(id, "test $(wc -c < /workspace/data/app.db) = 80000").await?;
                execute(id, "printf guest > /workspace/remote.txt; test ! -e /workspace/.env").await?;
                let token = live.saved.token.clone();
                verify(live.sync_to(manifest.clone()).await? == 0, "No-op launch transferred files")?;
                let checkpoint = fs::metadata(&state).map_err(|e| e.to_string())?.modified().map_err(|e| e.to_string())?;
                verify(live.sync_to(manifest.clone()).await? == 0, "Unchanged database pass did not stay idle")?;
                verify(fs::metadata(&state).map_err(|e| e.to_string())?.modified().map_err(|e| e.to_string())? == checkpoint, "Unchanged database pass rewrote its checkpoint")?;
                verify(live.saved.token == token, "No-op launch rewrote the checkpoint")?;
                verify(!folder.path().join("remote.txt").exists(), "One-way sync unexpectedly downloaded a file")?;
                // Simulate interruption after an addition reached the guest, followed
                // by a local deletion. Recovery must not recopy unchanged files or
                // erase guest-only runtime data.
                execute(id, "printf partial > /workspace/interrupted.txt; printf incomplete > /yougori/launch/sync-token").await?;
                live.saved.pending.insert("interrupted.txt".into());
                live.saved.save(&state)?;
                fs::write(folder.path().join("code.txt"), "changed-offline").map_err(|e| e.to_string())?;
                let next = sync::scan(folder.path(), &sync::Filter::load(folder.path(), false)?)?;
                live.reconcile_one_way(&next).await?;
                verify(live.sync_to(next).await? == 2, "Recovery did not limit transfer to the edit and deletion")?;
                execute(id, "test ! -e /workspace/interrupted.txt; test \"$(cat /workspace/remote.txt)\" = guest; test \"$(cat /workspace/code.txt)\" = changed-offline").await?;
                // Package managers create these links; they must not block all sync.
                execute(id, "mkdir -p /workspace/node_modules/.bin; ln -s ../../code.txt /workspace/node_modules/.bin/tool").await?;
                fs::create_dir_all(folder.path().join("node_modules/.bin")).map_err(|e| e.to_string())?;
                fs::write(folder.path().join("node_modules/.bin/tool"), "Windows npm shim").map_err(|e| e.to_string())?;
                live.sync_folders(false).await?;
                let resumed = sync::scan(folder.path(), &sync::Filter::load(folder.path(), false)?)?;
                live.reconcile_one_way(&resumed).await?;
                verify(live.sync_to(resumed.clone()).await? == 0, "Resume recopied a Windows shim onto a Linux link")?;
                fs::write(folder.path().join("node_modules/.bin/tool"), "edited Windows shim").map_err(|e| e.to_string())?;
                let edited = sync::scan(folder.path(), &sync::Filter::load(folder.path(), false)?)?;
                verify(live.sync_to(edited).await? == 0, "An edited shim overwrote a Linux link")?;
                fs::remove_file(folder.path().join("node_modules/.bin/tool")).map_err(|e| e.to_string())?;
                let deleted = sync::scan(folder.path(), &sync::Filter::load(folder.path(), false)?)?;
                verify(live.sync_to(deleted).await? == 0, "Deleting a Windows shim removed a Linux link")?;
                execute(id, "test -L /workspace/node_modules/.bin/tool; test \"$(cat /workspace/code.txt)\" = changed-offline").await?;
                live.sync_both(false).await?;
                verify(local_sql(folder.path(), "SELECT value FROM records WHERE id='guest'")?.contains("guest-only"), "Two-way SQLite sync did not pull a guest record")?;
                fs::write(folder.path().join("local-delete.txt"), "old").map_err(|e| e.to_string())?;
                fs::write(folder.path().join("remote-delete.txt"), "old").map_err(|e| e.to_string())?;
                local_sql(folder.path(), "INSERT INTO records VALUES ('local-delete-row','old'),('remote-delete-row','old')")?;
                live.sync_both(false).await?;
                // Wait beyond the former five-second interval. Manual sessions
                // must neither send a host edit nor pull a public-link edit.
                fs::write(folder.path().join("send-later.txt"), "host change").map_err(|e| e.to_string())?;
                fs::create_dir_all(folder.path().join("send-empty/nested")).map_err(|e| e.to_string())?;
                fs::remove_file(folder.path().join("local-delete.txt")).map_err(|e| e.to_string())?;
                local_sql(folder.path(), "INSERT INTO records VALUES ('send-later','host record'); DELETE FROM records WHERE id='local-delete-row'")?;
                execute(id, "printf 'container change' > /workspace/receive-later.txt; mkdir -p /workspace/receive-empty/nested; rm /workspace/remote-delete.txt").await?;
                remote_sql(id, "INSERT INTO records VALUES ('receive-later','container record'); DELETE FROM records WHERE id='remote-delete-row'").await?;
                live.start().await?;
                let cancelled = AtomicBool::new(false);
                let wait = async { tokio::time::sleep(Duration::from_secs(7)).await; cancelled.store(true, Ordering::Relaxed); };
                let (watched, _) = tokio::join!(live.watch("manual sync fixture", 3000, false, true, false, false, &cancelled), wait);
                watched?;
                execute(id, "test ! -e /workspace/send-later.txt; test -e /workspace/local-delete.txt; test ! -d /workspace/send-empty").await?;
                verify(!folder.path().join("receive-later.txt").exists() && folder.path().join("remote-delete.txt").exists(), "Manual watch transferred files")?;
                verify(!local_sql(folder.path(), "SELECT value FROM records WHERE id='receive-later'")?.contains("container record"), "Manual watch pulled records")?;
                verify(!remote_sql(id, "SELECT value FROM records WHERE id='send-later'").await?.contains("host record"), "Manual watch sent records")?;
                verify(live.handoff(false, false, sync::Direction::ToComputer).await.is_err(), "One-way mode allowed a receive handoff")?;
                live.handoff(false, true, sync::Direction::ToContainer).await?;
                execute(id, "test -e /workspace/send-later.txt; test ! -e /workspace/local-delete.txt; test -d /workspace/send-empty/nested").await?;
                verify(!folder.path().join("receive-later.txt").exists() && !folder.path().join("receive-empty").exists() && folder.path().join("remote-delete.txt").exists(), "Send handoff pulled files, folders or deletions")?;
                let sent = remote_sql(id, "SELECT id,value FROM records WHERE id='send-later'").await?;
                verify(sent.contains("host record"), &format!("Send handoff missed a host record: app read {sent:?}"))?;
                verify(!local_sql(folder.path(), "SELECT value FROM records WHERE id='receive-later'")?.contains("container record"), "Send handoff pulled a record")?;
                fs::write(folder.path().join("deferred-send.txt"), "pending host").map_err(|e| e.to_string())?;
                local_sql(folder.path(), "INSERT INTO records VALUES ('deferred-send','pending host record')")?;
                live.handoff(false, true, sync::Direction::ToComputer).await?;
                verify(folder.path().join("receive-later.txt").exists() && folder.path().join("receive-empty/nested").is_dir() && !folder.path().join("remote-delete.txt").exists(), "Receive handoff missed files, empty folders or deletions")?;
                execute(id, "test ! -e /workspace/deferred-send.txt").await?;
                verify(local_sql(folder.path(), "SELECT value FROM records WHERE id='receive-later'")?.contains("container record"), "Receive handoff missed a container record")?;
                verify(!remote_sql(id, "SELECT value FROM records WHERE id='deferred-send'").await?.contains("pending host record"), "Receive handoff sent records")?;
                live.close().await;
                live = Live::prepare(id, &canonical, &project, &sync::Manifest::new(), true, 3000, &state, sync::Saved::load(&state)).await?;
                live.handoff(false, true, sync::Direction::ToContainer).await?;
                execute(id, "test -e /workspace/deferred-send.txt").await?;
                verify(remote_sql(id, "SELECT value FROM records WHERE id='deferred-send'").await?.contains("pending host record"), "Receive consumed a deferred host checkpoint across restart")?;
                execute(id, "mkdir -p /workspace/guest-empty/nested; rmdir /workspace/empty/nested").await?;
                live.sync_both(false).await?;
                verify(folder.path().join("guest-empty/nested").is_dir(), "Empty guest folder not pulled")?;
                verify(!folder.path().join("empty/nested").exists(), "Empty guest folder deletion not pulled")?;
                local_sql(folder.path(), "UPDATE records SET value='from-pc' WHERE id='base'")?;
                live.sync_both(false).await?;
                verify(remote_sql(id, "SELECT value FROM records WHERE id='base'").await?.contains("from-pc"), "SQLite host update not sent")?;
                verify(fs::read_to_string(folder.path().join("remote.txt")).map_err(|e| e.to_string())? == "guest", "Remote addition was not downloaded")?;
                execute(id, "printf remote-edit > /workspace/code.txt; node -e \"require('fs').writeFileSync('/workspace/binary.bin', Buffer.alloc(70000, 173))\"").await?;
                live.sync_both(false).await?;
                verify(fs::read_to_string(folder.path().join("code.txt")).map_err(|e| e.to_string())? == "remote-edit", "Remote edit was not downloaded")?;
                verify(fs::read(folder.path().join("binary.bin")).map_err(|e| e.to_string())? == vec![173;70000], "Binary chunks were not reconstructed")?;
                fs::write(folder.path().join("code.txt"), "laptop-edit").map_err(|e| e.to_string())?;
                live.sync_both(false).await?;
                execute(id, "test \"$(cat /workspace/code.txt)\" = laptop-edit").await?;
                fs::write(folder.path().join("code.txt"), "local-conflict").map_err(|e| e.to_string())?;
                execute(id, "printf remote-conflict > /workspace/code.txt; rm /workspace/remote.txt").await?;
                live.sync_both(false).await?;
                verify(fs::read_to_string(folder.path().join("code.txt")).map_err(|e| e.to_string())? == "local-conflict", "Conflict overwrote the laptop")?;
                execute(id, "test \"$(cat /workspace/code.txt)\" = remote-conflict").await?;
                verify(!folder.path().join("remote.txt").exists(), "Remote deletion was not applied")?;
                fs::remove_file(folder.path().join("binary.bin")).map_err(|e| e.to_string())?;
                live.sync_both(false).await?;
                execute(id, "test ! -e /workspace/binary.bin").await?;
                Ok(())
            }.await;
            live.close().await;
            run?;
            // Resume from persisted common checksums, keeping the unresolved conflict.
            execute(id, "printf new > /workspace/after-reconnect.txt").await?;
            let mut live = Live::prepare(id, &canonical, &project, &sync::Manifest::new(), true, 3000, &state, sync::Saved::load(&state)).await?;
            let result = live.sync_both(false).await;
            live.close().await;
            result?;
            verify(fs::read_to_string(folder.path().join("after-reconnect.txt")).map_err(|e| e.to_string())? == "new", "Resume lost the remote addition")?;
            verify(fs::read_to_string(folder.path().join("code.txt")).map_err(|e| e.to_string())? == "local-conflict", "Resume lost the local conflict")?;
            execute(id, "test \"$(cat /workspace/code.txt)\" = remote-conflict").await?;
            local_sql(folder.path(), "UPDATE records SET value='pc-wins' WHERE id='base'")?;
            remote_sql(id, "UPDATE records SET value='guest-loses' WHERE id='base'").await?;
            // Priority is shared by file and record conflicts, including deletions.
            // Reopen the receiver after the prior check closed it.
            drop(live);
            let mut live = Live::prepare(id, &canonical, &project, &sync::Manifest::new(), true, 3000, &state, sync::Saved::load(&state)).await?;
            live.priority = sync::Priority::Local;
            let prioritized: Result<(), String> = async {
                live.sync_both(false).await?;
                execute(id, "test \"$(cat /workspace/code.txt)\" = local-conflict").await?;
                verify(remote_sql(id, "SELECT value FROM records WHERE id='base'").await?.contains("pc-wins"), "Local priority failed for SQLite")?;
                local_sql(folder.path(), "UPDATE records SET value='pc-loses' WHERE id='base'")?;
                remote_sql(id, "DELETE FROM records WHERE id='base'").await?;
                fs::write(folder.path().join("code.txt"), "local-loses").map_err(|e| e.to_string())?;
                execute(id, "rm /workspace/code.txt").await?;
                live.priority = sync::Priority::Remote;
                live.sync_both(false).await?;
                verify(!folder.path().join("code.txt").exists(), "Remote deletion did not win file conflict")?;
                verify(!local_sql(folder.path(), "SELECT id FROM records WHERE id='base'")?.contains("base"), "Remote deletion did not win SQLite conflict")?;
                let tree = folder.path().join("folder-conflict");
                fs::create_dir(&tree).map_err(|e| e.to_string())?;
                fs::write(tree.join("old.txt"), "old").map_err(|e| e.to_string())?;
                live.sync_both(false).await?;
                // A new child on one side conflicts with deleting its parent on the other.
                fs::remove_dir_all(&tree).map_err(|e| e.to_string())?;
                execute(id, "printf new > /workspace/folder-conflict/new.txt").await?;
                live.priority = sync::Priority::Local;
                live.sync_both(false).await?;
                execute(id, "test ! -e /workspace/folder-conflict").await?;
                fs::write(folder.path().join("priority-handoff.txt"), "base").map_err(|e| e.to_string())?;
                local_sql(folder.path(), "INSERT INTO records VALUES ('priority-handoff','base')")?;
                live.sync_both(false).await?;
                fs::write(folder.path().join("priority-handoff.txt"), "host wins").map_err(|e| e.to_string())?;
                local_sql(folder.path(), "UPDATE records SET value='host wins' WHERE id='priority-handoff'")?;
                execute(id, "printf 'container loses' > /workspace/priority-handoff.txt").await?;
                remote_sql(id, "UPDATE records SET value='container loses' WHERE id='priority-handoff'").await?;
                live.handoff(false, true, sync::Direction::ToComputer).await?;
                verify(fs::read_to_string(folder.path().join("priority-handoff.txt")).map_err(|e| e.to_string())? == "host wins", "Receive ignored host conflict priority")?;
                verify(local_sql(folder.path(), "SELECT value FROM records WHERE id='priority-handoff'")?.contains("host wins"), "Receive ignored host record priority")?;
                live.handoff(false, true, sync::Direction::ToContainer).await?;
                execute(id, "test \"$(cat /workspace/priority-handoff.txt)\" = 'host wins'").await?;
                verify(remote_sql(id, "SELECT value FROM records WHERE id='priority-handoff'").await?.contains("host wins"), "Deferred host record conflict was consumed")?;
                live.priority = sync::Priority::Remote;
                fs::write(folder.path().join("priority-handoff.txt"), "host loses").map_err(|e| e.to_string())?;
                local_sql(folder.path(), "UPDATE records SET value='host loses' WHERE id='priority-handoff'")?;
                execute(id, "printf 'container wins' > /workspace/priority-handoff.txt").await?;
                remote_sql(id, "UPDATE records SET value='container wins' WHERE id='priority-handoff'").await?;
                live.handoff(false, true, sync::Direction::ToContainer).await?;
                execute(id, "test \"$(cat /workspace/priority-handoff.txt)\" = 'container wins'").await?;
                verify(remote_sql(id, "SELECT value FROM records WHERE id='priority-handoff'").await?.contains("container wins"), "Send ignored container record priority")?;
                live.handoff(false, true, sync::Direction::ToComputer).await?;
                verify(fs::read_to_string(folder.path().join("priority-handoff.txt")).map_err(|e| e.to_string())? == "container wins", "Deferred container file conflict was consumed")?;
                verify(local_sql(folder.path(), "SELECT value FROM records WHERE id='priority-handoff'")?.contains("container wins"), "Deferred container record conflict was consumed")?;
                Ok(())
            }.await;
            live.close().await;
            prioritized?;
            Ok(())
        }.await;
        let cleanup = call("delete_environment", json!({"environmentId":id})).await;
        assert!(cleanup.is_ok(), "Test cleanup failed: {cleanup:?}");
        result.unwrap();
    }
    #[test]
    fn reconciliation_preserves_conflicts_and_propagates_unambiguous_edits_and_deletes() {
        assert_eq!(
            change(Some("base"), Some("base"), Some("remote")),
            Change::Pull
        );
        assert_eq!(
            change(Some("base"), Some("local"), Some("base")),
            Change::Push
        );
        assert_eq!(
            change(Some("base"), Some("local"), Some("remote")),
            Change::Conflict
        );
        assert_eq!(change(Some("base"), None, Some("remote")), Change::Conflict);
        assert_eq!(change(Some("base"), Some("local"), None), Change::Conflict);
        assert_eq!(change(Some("base"), None, Some("base")), Change::Push);
        assert_eq!(change(Some("base"), Some("base"), None), Change::Pull);
        assert_eq!(change(None, Some("new"), None), Change::Push);
        assert_eq!(change(None, None, Some("new")), Change::Pull);
        assert_eq!(
            change(None, Some("local"), Some("remote")),
            Change::Conflict
        );
        assert_eq!(
            change(Some("base"), Some("same"), Some("same")),
            Change::Same
        );
    }
    #[test]
    fn hashing_many_local_files_gives_a_waiting_launch_a_turn() {
        use std::{future::Future, task::{Context, Poll, Waker}};
        let folder = tempfile::tempdir().unwrap();
        fs::create_dir(folder.path().join("src")).unwrap();
        for i in 0..100 {
            fs::write(folder.path().join(format!("src/file-{i}.js")), format!("export const value = {i};")).unwrap();
        }
        let filter = sync::Filter::load(folder.path(), false).unwrap().two_way();
        let paths: Vec<_> = sync::scan(folder.path(), &filter).unwrap().into_iter().collect();
        let mut live = Live::offline(folder.path());
        let progress = ui::task("Checking local files");
        let mut cx = Context::from_waker(Waker::noop());
        let local = {
            let mut hashing = std::pin::pin!(live.local_checksums(&paths, &progress));
            assert!(hashing.as_mut().poll(&mut cx).is_pending(), "a launch waiting for the pass notices Ctrl+C meanwhile");
            loop {
                if let Poll::Ready(local) = hashing.as_mut().poll(&mut cx) { break local.unwrap(); }
            }
        };
        progress.clear();
        assert_eq!(local.len(), 100);
        assert_eq!(local["src/file-7.js"], format!("{:x}", Sha256::digest(b"export const value = 7;")));
        assert_eq!(live.local_hashes.len(), 100, "the next pass reuses them");
    }
    #[tokio::test]
    async fn a_large_local_file_is_read_beside_a_waiting_launch() {
        use std::{future::Future, task::{Context, Waker}};
        let folder = tempfile::tempdir().unwrap();
        let data: Vec<u8> = (0..4 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
        fs::write(folder.path().join("video.mp4"), &data).unwrap();
        let filter = sync::Filter::load(folder.path(), false).unwrap().two_way();
        let paths: Vec<_> = sync::scan(folder.path(), &filter).unwrap().into_iter().collect();
        let mut live = Live::offline(folder.path());
        let progress = ui::task("Checking local files");
        let local = {
            let mut hashing = std::pin::pin!(live.local_checksums(&paths, &progress));
            // The only file is read on another thread: the first turn ends before it is read.
            assert!(hashing.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending(), "a launch waiting for the pass notices Ctrl+C meanwhile");
            hashing.await.unwrap()
        };
        progress.clear();
        let expected = format!("{:x}", Sha256::digest(&data));
        assert_eq!(local["video.mp4"], expected);
        assert_eq!(local_hash(folder.path(), "video.mp4").unwrap().as_deref(), Some(expected.as_str()));
        // A wait that is dropped ends the read at its next chunk.
        assert_eq!(local_hash_until(folder.path(), "video.mp4", &AtomicBool::new(true)), Err(STOPPED.into()));
    }
    #[test]
    fn sync_paths_and_stale_local_writes_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        for path in [
            "../escape",
            "/absolute",
            "a\\b",
            "a/../b",
            "line\nbreak",
            ".yougori-sync-temp",
        ] {
            assert!(destination(root.path(), path).is_err(), "{path}");
        }
        // Names Windows cannot store are only unsupported on Windows.
        for path in ["C:/file", "CON", "aux.js", "com1.txt", "LPT\u{b9}", "a.", "b ", "app-12:00.log", "what?.md"] {
            assert_eq!(destination(root.path(), path).is_err(), cfg!(windows), "{path}");
        }
        assert!(unsupported("console.log").is_none() && unsupported("COM10").is_none() && unsupported("src/con-fig.js").is_none());
        fs::write(root.path().join("file.txt"), "first").unwrap();
        let hash = local_hash(root.path(), "file.txt").unwrap().unwrap();
        fs::write(root.path().join("file.txt"), "second").unwrap();
        assert!(expect_local(root.path(), "file.txt", Some(&hash)).is_err());
        assert_eq!(
            fs::read_to_string(root.path().join("file.txt")).unwrap(),
            "second"
        );
        assert!(expect_local(root.path(), "file.txt", None).is_err());
    }

    fn entry(path: &str, kind: &str) -> Value {
        json!({"path":path,"kind":kind,"stamp":"1:2:3:4"})
    }

    #[test]
    fn container_inventory_holds_what_this_computer_cannot_store_without_stopping() {
        let filter = sync::Filter::load(Path::new("."), false).unwrap().two_way();
        let entries = vec![
            entry("src", "dir"), entry("src/app.js", "file"), entry("src/data.db", "sqlite"),
            entry("node_modules", "dir"), entry("node_modules/x.js", "file"),
            json!({"path":".git","kind":"dir","pruned":true}),
            json!({"path":"deep","kind":"dir","pruned":true}),
            entry("deep/a.js", "file"),
            entry("bin", "link"), entry(".env", "file"),
            entry("logs", "dir"), entry("logs/app-12:00.log", "file"), entry("logs/aux.txt", "file"),
            entry("Docs", "dir"), entry("Docs/a.md", "file"), entry("docs", "dir"), entry("docs/b.md", "file"),
        ];
        let inventory = classify(&entries, &filter).unwrap();
        let files: Vec<_> = inventory.files.iter().map(|(path, _)| path.as_str()).collect();
        let held: BTreeMap<_, _> = inventory.held.iter().map(|(path, warning)| (path.as_str(), warning.is_some())).collect();
        // Host-only folders are not inventoried at all; a folder that could not be
        // inspected protects everything beneath it.
        assert!(!files.iter().any(|path| path.starts_with("node_modules") || path.starts_with("deep/")));
        assert_eq!(held.get("deep"), Some(&true));
        assert_eq!(held.get("bin"), Some(&false));
        assert!(!files.contains(&".env"));
        assert!(inventory.databases.contains("src/data.db"));
        assert!(files.contains(&"src/app.js"));
        if cfg!(windows) {
            assert_eq!(held.get("logs/app-12:00.log"), Some(&true));
            assert_eq!(held.get("logs/aux.txt"), Some(&true));
        } else {
            assert!(files.contains(&"logs/app-12:00.log") && files.contains(&"logs/aux.txt"));
        }
        if CASE_INSENSITIVE {
            assert_eq!(held.get("Docs"), Some(&true));
            assert!(!files.iter().any(|path| path.ends_with(".md")));
            assert!(!inventory.directories.contains("docs"));
        } else {
            assert!(files.contains(&"Docs/a.md") && files.contains(&"docs/b.md"));
        }
        assert!(classify(&[json!({"path":"../escape","kind":"file","stamp":"x"})], &filter).is_err());
    }

    fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries.iter().map(|(path, hash)| (path.to_string(), hash.to_string())).collect()
    }

    #[test]
    fn letter_case_renames_are_applied_once_or_held() {
        if !CASE_INSENSITIVE {
            assert!(case_plans(&map(&[("A.md", "1")]), &map(&[("a.md", "1")]), &map(&[("a.md", "1")])).is_empty());
            return;
        }
        // Renamed on this computer, unchanged in the container: rename it there.
        assert_eq!(
            case_plans(&map(&[("README.md", "2")]), &map(&[("readme.md", "1")]), &map(&[("readme.md", "1")])),
            [CasePlan::Push { from: "readme.md".into(), to: "README.md".into() }]
        );
        // Renamed in the container, unchanged here: rename the file in place.
        assert_eq!(
            case_plans(&map(&[("src/app.JS", "1")]), &map(&[("src/app.js", "3")]), &map(&[("src/app.JS", "1")])),
            [CasePlan::Pull { from: "src/app.JS".into(), to: "src/app.js".into() }]
        );
        // A renamed container folder is left for the user to match.
        assert!(matches!(
            case_plans(&map(&[("src/a.js", "1")]), &map(&[("Src/a.js", "1")]), &map(&[("src/a.js", "1")]))[..],
            [CasePlan::Hold(_)]
        ));
        // Both sides already agree on the new spelling.
        assert_eq!(
            case_plans(&map(&[("Src/a.js", "1")]), &map(&[("Src/a.js", "1")]), &map(&[("src/a.js", "1")])),
            [CasePlan::Agree { from: "src/a.js".into(), to: "Src/a.js".into() }]
        );
        // Edited in the container while renamed here, or created on both sides with
        // different spellings: keep both copies.
        for (local, remote, common) in [
            (map(&[("README.md", "2")]), map(&[("readme.md", "9")]), map(&[("readme.md", "1")])),
            (map(&[("Notes.md", "1")]), map(&[("notes.md", "2")]), map(&[])),
        ] {
            assert!(matches!(case_plans(&local, &remote, &common)[..], [CasePlan::Hold(_)]));
        }
        assert!(case_plans(&map(&[("a.md", "1")]), &map(&[("a.md", "1")]), &map(&[("a.md", "1")])).is_empty());
        // One warning names the folder rather than every file beneath it.
        assert_eq!(spelled_differently(&["Src/app/a.js".into(), "src/app/a.js".into()]), ["Src", "src"]);
        assert_eq!(spelled_differently(&["docs/README.md".into(), "docs/readme.md".into()]), ["docs/README.md", "docs/readme.md"]);
    }

    #[test]
    fn container_paths_never_write_through_another_spelling() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join(".git/hooks")).unwrap();
        fs::create_dir_all(root.path().join("Docs")).unwrap();
        fs::write(root.path().join("Docs/readme.md"), "x").unwrap();
        assert!(host_target(root.path(), ".git/hooks/pre-commit").is_err());
        assert!(host_target(root.path(), "Docs/new.md").is_ok());
        assert!(host_target(root.path(), "Docs/readme.md").is_ok());
        let insensitive = root.path().join("docs").exists();
        assert_eq!(host_target(root.path(), "docs/new.md").is_err(), insensitive);
        assert_eq!(host_target(root.path(), "Docs/README.md").is_err(), insensitive);
        if insensitive {
            rename_case(root.path(), "Docs/readme.md", "Docs/README.md").unwrap();
            let names: Vec<_> = fs::read_dir(root.path().join("Docs")).unwrap().flatten().map(|e| e.file_name().into_string().unwrap()).collect();
            assert_eq!(names, ["README.md"]);
            assert!(rename_case(root.path(), "Docs/README.md", "Other/README.md").is_err());
        }
    }
}
