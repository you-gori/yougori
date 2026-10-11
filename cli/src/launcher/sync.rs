//! Keeps the container's copy of a project identical to the PC folder. A full copy happens once;
//! after that only changed files travel, on demand or with optional continuous sync.
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority { Local, Remote, #[default] KeepBoth }

/// A handoff never consumes changes waiting to travel in the other direction.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Direction { ToContainer, ToComputer, Both }
impl Direction {
    pub fn sends(self) -> bool { self != Self::ToComputer }
    pub fn receives(self) -> bool { self != Self::ToContainer }
}

pub fn sqlite_file(path: &Path) -> bool {
    use std::io::Read;
    let mut header = [0; 16];
    fs::File::open(path).and_then(|mut f| f.read_exact(&mut header)).is_ok() && &header == b"SQLite format 3\0"
}

pub fn sqlite_files(root: &Path, files: &Manifest) -> BTreeSet<String> {
    files.iter().filter(|(path, (size, _))| *size >= 16 && sqlite_file(&root.join(path)))
        .map(|(path, _)| path.clone()).collect()
}

pub fn database_member(path: &str, databases: &BTreeSet<String>) -> bool {
    databases.contains(path) || ["-wal", "-shm", "-journal"].iter().any(|suffix|
        path.strip_suffix(suffix).is_some_and(|base| databases.contains(base)))
}

// Workspace package matching still uses the shared glob parser.
#[allow(dead_code)]
#[path = "../../../src-tauri/src/ignore_rules.rs"]
pub(super) mod ignore_rules;

/// Relative path → (size, modification time in ns). Paths use `/`.
pub type Manifest = BTreeMap<String, (u64, i64)>;

/// A version change asks for checksum reconciliation of the existing workspace.
pub const COPY_VERSION: u32 = 1;

/// Folders that tools manage separately on each computer: version-control metadata,
/// installed dependencies and interpreter caches. Two-way sync never exchanges them.
/// Their changes are invisible to a code review (`git diff`), yet hooks, package
/// binaries and bytecode in them run on this computer.
pub const HOST_ONLY: [&str; 7] = [".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__"];

/// A filename as case-insensitive filesystems compare it (NTFS, APFS, HFS+): ignoring
/// letter case, trailing dots and spaces (Windows) and the zero-width characters HFS+
/// ignores. The container helper (assets/two-way.cjs) folds names the same way.
pub fn folded(name: &str) -> String {
    let visible: String = name
        .chars()
        .filter(|c| !matches!(c, '\u{200c}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{206a}'..='\u{206f}' | '\u{feff}'))
        .collect();
    visible.trim_end_matches(['.', ' ']).to_uppercase()
}

/// Whether a path component names a HOST_ONLY folder, in any spelling this computer
/// may resolve to the same folder.
pub fn host_only(name: &str) -> bool {
    let name = folded(name);
    HOST_ONLY.iter().any(|protected| name == protected.to_uppercase())
}

fn env_name(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name == ".env" || name.starts_with(".env.")
}

/// Launch copies all project files regardless of ignore files. Only the user's .env
/// choice and transient sync protocol files are omitted. Two-way sync additionally
/// keeps HOST_ONLY folders on each side.
pub struct Filter {
    env_files: bool,
    two_way: bool,
}

impl Filter {
    pub fn load(_folder: &Path, env_files: bool) -> Result<Self, String> {
        Ok(Self { env_files, two_way: false })
    }
    pub fn two_way(mut self) -> Self {
        self.two_way = true;
        self
    }
    pub fn copies_env_files(&self) -> bool {
        self.env_files
    }
    pub fn excluded(&self, relative: &str, _folder: bool) -> bool {
        relative.split('/').any(|part| {
            part.is_empty() || part.starts_with(".yougori-sync-")
                || (!self.env_files && env_name(part))
                || (self.two_way && host_only(part))
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Excluded {
    /// Temporary files belonging to an in-progress sync.
    Always,
    /// .env files, which are copied only with consent.
    Env,
}

pub fn excluded_by(root: &Path, relative: &str, folder: bool, env_files: bool) -> Option<Excluded> {
    if !Filter::load(root, env_files).ok()?.excluded(relative, folder) {
        return None;
    }
    if relative.split('/').any(|p| p.is_empty() || p.starts_with(".yougori-sync-")) {
        Some(Excluded::Always)
    } else {
        Some(Excluded::Env)
    }
}

/// Build output folders a project recreates with its build step.
pub fn build_output(relative: &str) -> bool {
    relative.split('/').any(|part| matches!(part, "dist" | "build" | "out" | ".next" | ".nuxt" | ".output" | ".svelte-kit" | "target"))
}

fn env_file(name: &str) -> bool {
    name == ".env" || (name.starts_with(".env.") && !name.ends_with(".example") && !name.ends_with(".sample"))
}

/// Whether the project, or a package folder inside it (a server/ beside a client/), has .env
/// files a dev server would read.
pub fn has_env_files(folder: &Path) -> bool {
    let env_here = |dir: &Path| {
        fs::read_dir(dir).into_iter().flatten().flatten().any(|entry| entry.file_name().to_str().is_some_and(env_file))
    };
    if env_here(folder) {
        return true;
    }
    let mut stack = vec![(folder.to_path_buf(), 0)];
    while let Some((dir, depth)) = stack.pop() {
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else { continue };
            if name.starts_with('.') || ["node_modules", "venv", "__pycache__"].contains(&name.as_str()) || !entry.file_type().is_ok_and(|t| t.is_dir()) {
                continue;
            }
            let path = entry.path();
            if ["package.json", "requirements.txt", "pyproject.toml"].iter().any(|f| path.join(f).is_file()) && env_here(&path) {
                return true;
            }
            if depth < 2 {
                stack.push((path, depth + 1));
            }
        }
    }
    false
}

/// Symlinks and junctions. On Windows these are name-surrogate reparse points; other
/// reparse points, such as OneDrive/cloud-files placeholders and deduplicated files,
/// are ordinary files and folders whose contents can be read.
pub(super) fn linked(meta: &fs::Metadata) -> bool {
    meta.file_type().is_symlink()
}

/// Whether the path, or a folder above it, is now a link on this computer. Such paths
/// are not followed, and their earlier contents are not treated as deletions.
pub fn under_link(root: &Path, relative: &str) -> bool {
    let mut path = root.to_path_buf();
    relative.split('/').any(|part| {
        path.push(part);
        fs::symlink_metadata(&path).is_ok_and(|meta| linked(&meta))
    })
}

fn stamp(meta: &fs::Metadata) -> (u64, i64) {
    let modified = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0);
    (meta.len(), modified)
}

fn walk(
    root: &Path,
    relative: &str,
    filter: &Filter,
    out: &mut Manifest,
    links: &mut BTreeSet<String>,
    depth: usize,
) -> Result<(), String> {
    if depth > 128 {
        return Err("The project has folders nested more than 128 levels deep".into());
    }
    let folder = if relative.is_empty() {
        root.to_path_buf()
    } else {
        root.join(relative)
    };
    let entries = match fs::read_dir(&folder) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound && depth > 0 => return Ok(()),
        Err(e) => return Err(format!("Cannot read {}: {e}", folder.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("Cannot list {}: {e}", folder.display()))?;
        let name = entry.file_name().to_str().map(str::to_owned)
            .ok_or_else(|| format!("A filename in {} is not valid Unicode", folder.display()))?;
        let path = if relative.is_empty() {
            name
        } else {
            format!("{relative}/{name}")
        };
        let meta = match fs::symlink_metadata(entry.path()) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(format!("Cannot inspect {path}: {e}")),
        };
        if filter.excluded(&path, meta.is_dir()) {
            continue;
        }
        if linked(&meta) {
            links.insert(path);
        } else if meta.is_dir() {
            walk(root, &path, filter, out, links, depth + 1)?;
        } else if meta.is_file() {
            out.insert(path, stamp(&meta));
        }
    }
    Ok(())
}

pub fn scan(root: &Path, filter: &Filter) -> Result<Manifest, String> {
    Ok(scan_links(root, filter)?.0)
}

/// The project's files, and the links found instead of files or folders.
pub fn scan_links(root: &Path, filter: &Filter) -> Result<(Manifest, BTreeSet<String>), String> {
    let mut manifest = Manifest::new();
    let mut links = BTreeSet::new();
    walk(root, "", filter, &mut manifest, &mut links, 0)?;
    Ok((manifest, links))
}

pub fn directories(root: &Path, filter: &Filter) -> Result<BTreeSet<String>, String> {
    let mut result = BTreeSet::new();
    let mut pending = vec![(root.to_path_buf(), String::new())];
    while let Some((folder, relative)) = pending.pop() {
        if relative.split('/').count() > 128 { return Err("Project directories are nested too deeply".into()); }
        let entries = match fs::read_dir(folder) { Ok(entries) => entries, Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, Err(e) => return Err(e.to_string()) };
        for entry in entries {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = if relative.is_empty() { name } else { format!("{relative}/{name}") };
            let meta = match fs::symlink_metadata(entry.path()) { Ok(m) => m, Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue, Err(e) => return Err(e.to_string()) };
            if meta.is_dir() && !linked(&meta) && !filter.excluded(&path, true) {
                result.insert(path.clone()); pending.push((entry.path(), path));
            }
        }
    }
    Ok(result)
}

pub fn diff(old: &Manifest, new: &Manifest) -> (BTreeSet<String>, BTreeSet<String>) {
    let changed = new
        .iter()
        .filter(|(p, v)| old.get(*p) != Some(v))
        .map(|(p, _)| p.clone())
        .collect();
    let removed = old
        .keys()
        .filter(|p| !new.contains_key(*p))
        .cloned()
        .collect();
    (changed, removed)
}

/// Changes to these files, in the project or a package folder inside it, need a dependency
/// install and a dev-server restart.
pub fn needs_install(path: &str) -> bool {
    let mut parts = path.rsplit('/');
    let name = parts.next().unwrap_or(path);
    !parts.any(|part| part == "node_modules") && matches!(
        name,
        "package.json"
            | "package-lock.json"
            | "npm-shrinkwrap.json"
            | "pnpm-lock.yaml"
            | "pnpm-workspace.yaml"
            | "yarn.lock"
            | "bun.lock"
            | "bun.lockb"
            | ".npmrc"
            | ".yarnrc.yml"
            | "requirements.txt"
            | "pyproject.toml"
            | "setup.py"
            | "setup.cfg"
            | ".python-version"
    )
}

/// Receiver operations (see assets/sync.cjs), one per line.
pub fn write_op(path: &str, data: &[u8]) -> String {
    format!("W {} {}\n", B64.encode(path), B64.encode(data))
}
pub fn delete_op(path: &str) -> String {
    format!("D {}\n", B64.encode(path))
}

/// What the PC last sent to a container, so the next launch sends only differences.
#[derive(Serialize, Deserialize, Default)]
pub struct Saved {
    #[serde(default)]
    pub copy_version: u32,
    pub token: String,
    pub environment: String,
    pub files: Manifest,
    #[serde(default)]
    pub two_way: bool,
    #[serde(default)]
    pub common: BTreeMap<String, String>,
    /// Persisted before writes so interrupted additions/deletions can be reconciled.
    #[serde(default)]
    pub pending: BTreeSet<String>,
    #[serde(default)]
    pub databases: BTreeMap<String, BTreeMap<String, String>>,
    #[serde(default)]
    pub directories: BTreeSet<String>,
}

impl Saved {
    pub fn needs_reconcile(&self, environment: &str, token: &str) -> bool {
        self.copy_version != COPY_VERSION || self.two_way || self.environment != environment
            || self.token.is_empty() || token.trim() != self.token || !self.pending.is_empty()
    }

    pub fn changes(&self, next: &Manifest) -> (BTreeSet<String>, BTreeSet<String>) {
        let (mut changed, mut removed) = diff(&self.files, next);
        for path in &self.pending {
            if next.contains_key(path) { changed.insert(path.clone()); }
            else { removed.insert(path.clone()); }
        }
        (changed, removed)
    }
    pub fn load(path: &Path) -> Saved {
        fs::File::open(path)
            .ok()
            .and_then(|file| serde_json::from_reader(std::io::BufReader::new(file)).ok())
            .unwrap_or_default()
    }
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let folder = path.parent().ok_or("Missing launcher state folder")?;
        let mut file = tempfile::NamedTempFile::new_in(folder).map_err(|e| e.to_string())?;
        {
            use std::io::{BufWriter, Write};
            // Millions of row checksums should become large writes, rather than
            // a filesystem write for each JSON quote, key and separator.
            let mut output = BufWriter::new(file.as_file_mut());
            serde_json::to_writer(&mut output, self).map_err(|e| e.to_string())?;
            output.flush().map_err(|e| e.to_string())?;
        }
        file.persist(path)
            .map_err(|e| format!("Cannot save the sync state: {e}"))?;
        Ok(())
    }
}

/// Copies the project into a fresh staging folder (hard links where possible) for a bulk copy.
pub struct Staged {
    folder: tempfile::TempDir,
    pub databases: BTreeMap<String, BTreeMap<String, String>>,
}
impl Staged { pub fn path(&self) -> &Path { self.folder.path() } }

#[cfg(test)]
pub fn stage(root: &Path, manifest: &Manifest) -> Result<Staged, String> {
    stage_progress(root, manifest, |_| Ok(()))
}

pub fn stage_progress(root: &Path, manifest: &Manifest, mut progress: impl FnMut(&serde_json::Value) -> Result<(), String>) -> Result<Staged, String> {
    let staging = tempfile::tempdir().map_err(|e| e.to_string())?;
    // The outer folder has no .yougoriignore: the engine must not re-filter the
    // launcher's manifest using the project's own ignore file.
    let target = staging.path().join("project/workspace");
    fs::create_dir_all(&target).map_err(|e| e.to_string())?;
    let databases = sqlite_files(root, manifest);
    for directory in directories(root, &Filter::load(root, false)?)? {
        fs::create_dir_all(target.join(directory)).map_err(|e| e.to_string())?;
    }
    for (index, path) in manifest.keys().enumerate() {
        if index % 64 == 0 { progress(&serde_json::json!({"phase":"files","done":index,"total":manifest.len(),"path":path}))?; }
        if database_member(path, &databases) { continue; }
        let source = root.join(path);
        let destination: PathBuf = target.join(path);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        if fs::hard_link(&source, &destination).is_err() {
            fs::copy(&source, &destination).map_err(|e| format!("Cannot copy {path}: {e}"))?;
        }
    }
    progress(&serde_json::json!({"phase":"files","done":manifest.len(),"total":manifest.len()}))?;
    let baselines = if databases.is_empty() { BTreeMap::new() } else {
        use std::{io::{BufRead, BufReader, Write}, process::{Command, Stdio}};
        let script = staging.path().join("snapshot.cjs");
        let helper = staging.path().join("sqlite.cjs");
        fs::write(&script, include_bytes!("assets/sqlite-snapshot.cjs")).map_err(|e| e.to_string())?;
        fs::write(&helper, include_bytes!("assets/sqlite.cjs")).map_err(|e| e.to_string())?;
        let diagnostics = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
        let mut command = Command::new("node");
        command.args(["--no-warnings"]).arg(script).arg(root).arg(staging.path()).arg(helper)
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::from(diagnostics.as_file().try_clone().map_err(|e| e.to_string())?));
        #[cfg(windows)] { use std::os::windows::process::CommandExt; command.creation_flags(0x08000000); }
        let mut child = command.spawn().map_err(|e| format!("Initial SQLite copy needs Node.js 22.16 or newer: {e}"))?;
        let result: Result<(), String> = (|| {
            let mut input = child.stdin.take().ok_or("Missing snapshot input")?;
            input.write_all(&serde_json::to_vec(&databases).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
            drop(input);
            let output = child.stdout.take().ok_or("Missing snapshot progress")?;
            for line in BufReader::new(output).lines() {
                let measurement = serde_json::from_str(&line.map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
                progress(&measurement)?;
            }
            let status = child.wait().map_err(|e| e.to_string())?;
            if !status.success() {
                return Err(format!("Could not create a consistent SQLite snapshot: {}", fs::read_to_string(diagnostics.path()).unwrap_or_else(|_| status.to_string()).trim()));
            }
            Ok(())
        })();
        if result.is_err() { let _ = child.kill(); let _ = child.wait(); }
        result?;
        let checkpoint = fs::File::open(staging.path().join("database-baselines.json")).map_err(|e| e.to_string())?;
        serde_json::from_reader(BufReader::new(checkpoint)).map_err(|e| e.to_string())?
    };
    Ok(Staged { folder: staging, databases: baselines })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_addition_then_local_deletion_survives_relaunch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.json");
        let saved = Saved {
            copy_version: COPY_VERSION, token: "checkpoint".into(), environment: "env".into(),
            files: BTreeMap::from([("unchanged".into(), (10, 20))]),
            pending: BTreeSet::from(["new-then-deleted".into(), "edited".into()]),
            ..Default::default()
        };
        saved.save(&path).unwrap();
        let loaded = Saved::load(&path);
        let next = BTreeMap::from([("unchanged".into(), (10, 20)), ("edited".into(), (5, 6))]);
        let (changed, removed) = loaded.changes(&next);
        assert_eq!(changed, BTreeSet::from(["edited".into()]));
        assert_eq!(removed, BTreeSet::from(["new-then-deleted".into()]));
        assert!(loaded.needs_reconcile("env", "incomplete"));
        let clean = Saved { pending: BTreeSet::new(), ..loaded };
        assert!(!clean.needs_reconcile("env", "checkpoint\n"));
        assert!(clean.changes(&clean.files).0.is_empty());
    }

    #[test]
    fn two_way_baseline_survives_relaunch_and_old_state_defaults_to_one_way() {
        let old: Saved = serde_json::from_str(r#"{"token":"old","environment":"env","files":{}}"#).unwrap();
        assert!(!old.two_way);
        assert_ne!(old.copy_version, COPY_VERSION);
        assert!(old.common.is_empty());
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sync.json");
        let saved = Saved { environment: "env".into(), two_way: true, common: BTreeMap::from([("file".into(), "base".into())]), ..Default::default() };
        saved.save(&path).unwrap();
        let loaded = Saved::load(&path);
        assert!(loaded.two_way);
        assert_eq!(loaded.common["file"], "base");
    }

    #[test]
    fn sync_copies_ignored_files_and_respects_only_env_preferences() {
        let root = tempfile::tempdir().unwrap();
        fs::write(root.path().join(".gitignore"), "ignored/\nprivate.txt\n").unwrap();
        fs::write(root.path().join(".yougoriignore"), "generated/\n").unwrap();
        let filter = Filter::load(root.path(), false).unwrap();
        for path in [".env", ".env.production", "nested/.env", ".yougori-sync-temp"] {
            assert!(filter.excluded(path, false), "{path}");
        }
        assert!(!filter.excluded("src/app.js", false));
        let with_env = Filter::load(root.path(), true).unwrap();
        assert!(!with_env.excluded("nested/.env", false));
        for path in ["node_modules/package/a.js", ".git/config", ".yougori/preferences", ".venv/lib/a", "ignored/a", "private.txt", "generated/a", "dist/a", "backup.key"] {
            assert!(!with_env.excluded(path, false), "{path}");
        }
    }

    #[test]
    fn two_way_keeps_host_only_folders_in_every_spelling() {
        let root = tempfile::tempdir().unwrap();
        let one_way = Filter::load(root.path(), true).unwrap();
        let two_way = Filter::load(root.path(), true).unwrap().two_way();
        for path in [
            ".git/hooks/pre-commit", ".GIT/config", "packages/web/node_modules/.bin/vite",
            "Node_Modules/x.js", ".venv/Scripts/python.exe", "venv/bin/activate", "src/__pycache__/a.cpython-312.pyc",
            ".hg/hgrc", ".svn/entries", ".g\u{200c}it/hooks/post-checkout", ".g\u{131}t/config", ".git. /config",
        ] {
            assert!(two_way.excluded(path, false), "{path}");
        }
        for path in [".gitignore", ".github/workflows/ci.yml", ".gitmodules", "src/node_modules.ts", "git/hooks.md"] {
            assert!(!two_way.excluded(path, false), "{path}");
        }
        // The first copy and one-way sync still include dependencies and Git metadata.
        assert!(!one_way.excluded(".git/config", false) && !one_way.excluded("node_modules/a.js", false));
        let without_env = Filter::load(root.path(), false).unwrap().two_way();
        assert!(without_env.excluded(".ENV", false) && without_env.excluded("server/.Env.local", false));
    }

    #[test]
    fn links_are_reported_instead_of_followed() {
        let root = tempfile::tempdir().unwrap();
        fs::create_dir_all(root.path().join("src")).unwrap();
        fs::write(root.path().join("src/app.js"), "1").unwrap();
        let target = tempfile::tempdir().unwrap();
        fs::write(target.path().join("outside.js"), "x").unwrap();
        #[cfg(unix)]
        let linked_folder = std::os::unix::fs::symlink(target.path(), root.path().join("lib")).is_ok();
        #[cfg(windows)]
        let linked_folder = std::process::Command::new("cmd").args(["/C", "mklink", "/J"]).arg(root.path().join("lib")).arg(target.path())
            .output().is_ok_and(|output| output.status.success());
        let (files, links) = scan_links(root.path(), &Filter::load(root.path(), false).unwrap()).unwrap();
        assert_eq!(files.keys().cloned().collect::<Vec<_>>(), ["src/app.js"]);
        if linked_folder {
            assert_eq!(links.into_iter().collect::<Vec<_>>(), ["lib"]);
            assert!(under_link(root.path(), "lib/outside.js"));
        }
        assert!(!under_link(root.path(), "src/app.js"));
    }

    fn refresh(
        root: &Path,
        filter: &Filter,
        _relative: &str,
        manifest: &mut Manifest,
    ) -> (BTreeSet<String>, BTreeSet<String>) {
        let next = scan(root, filter).unwrap();
        let result = diff(manifest, &next);
        *manifest = next;
        result
    }

    fn project() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let write = |p: &str, s: &str| {
            let path = dir.path().join(p);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, s).unwrap();
        };
        write("package.json", "{}");
        write("src/app.js", "1");
        write(".env", "SECRET=1");
        write(".env.local", "LOCAL=1");
        write(".gitignore", "coverage/\n.env*\n");
        write("coverage/report.html", "x");
        write("node_modules/react/index.js", "x");
        write("packages/web/node_modules/x.js", "x");
        write("dist/app.js", "x");
        write("build/icon.png", "x");
        write("src/.app.js.swp", "x");
        write("key.pem", "x");
        dir
    }

    #[test]
    fn copies_dependencies_builds_keys_and_ignored_files() {
        let dir = project();
        let files = scan(dir.path(), &Filter::load(dir.path(), false).unwrap()).unwrap();
        assert_eq!(
            files.keys().cloned().collect::<Vec<_>>(),
            [".gitignore", "build/icon.png", "coverage/report.html", "dist/app.js", "key.pem", "node_modules/react/index.js", "package.json", "packages/web/node_modules/x.js", "src/.app.js.swp", "src/app.js"].map(String::from)
        );
        let with_env = scan(dir.path(), &Filter::load(dir.path(), true).unwrap()).unwrap();
        assert!(with_env.contains_key(".env") && with_env.contains_key(".env.local"));
        assert!(with_env.contains_key("key.pem"));
        assert!(has_env_files(dir.path()));
        fs::write(dir.path().join(".yougoriignore"), "!.env\n!.env.local\n").unwrap();
        let denied = scan(dir.path(), &Filter::load(dir.path(), false).unwrap()).unwrap();
        assert!(
            !denied.contains_key(".env"),
            "ignore rules cannot override consent"
        );
    }

    #[test]
    fn saved_changes_are_found_per_path() {
        let dir = project();
        let filter = Filter::load(dir.path(), false).unwrap();
        let mut files = scan(dir.path(), &filter).unwrap();
        fs::write(dir.path().join("src/app.js"), "22").unwrap();
        fs::write(dir.path().join("src/new.js"), "3").unwrap();
        let (changed, removed) = refresh(dir.path(), &filter, "src", &mut files);
        assert_eq!(
            changed.into_iter().collect::<Vec<_>>(),
            ["src/app.js", "src/new.js"]
        );
        assert!(removed.is_empty());
        fs::remove_dir_all(dir.path().join("src")).unwrap();
        let (changed, removed) = refresh(dir.path(), &filter, "src", &mut files);
        assert!(changed.is_empty());
        assert_eq!(
            removed.into_iter().collect::<Vec<_>>(),
            ["src/.app.js.swp", "src/app.js", "src/new.js"]
        );
        assert_eq!(
            files.keys().cloned().collect::<Vec<_>>(),
            [".gitignore", "build/icon.png", "coverage/report.html", "dist/app.js", "key.pem", "node_modules/react/index.js", "package.json", "packages/web/node_modules/x.js"]
        );
        let (changed, _) = refresh(
            dir.path(),
            &filter,
            "node_modules/react/index.js",
            &mut files,
        );
        assert!(changed.is_empty());
        assert!(needs_install("package.json") && needs_install("server/package-lock.json"));
        assert!(!needs_install("node_modules/react/package.json") && !needs_install("src/app.json"));
    }

    #[test]
    fn ignored_databases_are_included_and_nested_env_files_are_detected() {
        let dir = project();
        let root = dir.path();
        assert_eq!(excluded_by(root, "dist/app.js", false, false), None);
        assert_eq!(excluded_by(root, "coverage/report.html", false, false), None);
        assert_eq!(excluded_by(root, "packages/web/node_modules/x.js", false, false), None);
        assert_eq!(excluded_by(root, ".env.local", false, false), Some(Excluded::Env));
        assert_eq!(excluded_by(root, "src/app.js", false, false), None);
        fs::write(root.join(".yougoriignore"), "src/\n").unwrap();
        assert_eq!(excluded_by(root, "src/app.js", false, false), None);

        let nested = tempfile::tempdir().unwrap();
        fs::create_dir_all(nested.path().join("server")).unwrap();
        fs::write(nested.path().join("server/.env"), "KEY=1").unwrap();
        assert!(!has_env_files(nested.path()), "a folder without a package is not a project part");
        fs::write(nested.path().join("server/package.json"), "{}").unwrap();
        assert!(has_env_files(nested.path()));

        let data = tempfile::tempdir().unwrap();
        for (path, size) in [("server/data/crm.db", 300), ("server/data/backups/old.sqlite", 100), ("server/dist/cache.db", 50), ("logs/app.log", 10)] {
            let path = data.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, vec![0u8; size]).unwrap();
        }
        fs::write(data.path().join(".gitignore"), "data/\ndist/\nlogs/\n").unwrap();
        let filter = Filter::load(data.path(), false).unwrap();
        let files = scan(data.path(), &filter).unwrap();
        assert!(files.contains_key("server/data/crm.db"));
        assert!(files.contains_key("server/data/backups/old.sqlite"));
        // A sparse database beyond the old 256 MiB limit must survive staging.
        let large = fs::File::create(data.path().join("server/data/large.db")).unwrap();
        large.set_len(300 * 1024 * 1024).unwrap();
        fs::write(data.path().join(".yougoriignore"), "server/\n").unwrap();
        let files = scan(data.path(), &filter).unwrap();
        assert_eq!(files["server/data/large.db"].0, 300 * 1024 * 1024);
        let staging = stage(data.path(), &files).unwrap();
        assert!(!staging.path().join("project/.yougoriignore").exists());
        let copied = staging.path().join("project/workspace");
        assert!(copied.join(".yougoriignore").exists());
        assert_eq!(fs::metadata(copied.join("server/data/large.db")).unwrap().len(), large.metadata().unwrap().len());
    }

    #[test]
    fn paths_and_operations_are_portable() {
        assert_eq!(write_op("a b/c.js", b"hi"), "W YSBiL2MuanM= aGk=\n");
        assert_eq!(delete_op("x"), "D eA==\n");
    }
}
