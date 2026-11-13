//! The tools our agent offers the model. Schemas and descriptions are short and plain, written
//! for small models: one clear job per tool, few parameters, and the parameter names other
//! agents use accepted as aliases.
pub mod bash;
pub mod edit;
pub mod files;
pub mod matcher;
pub mod question;
pub mod search;
pub mod task;
pub mod todo;
pub mod web;

use super::agent::{Shared, Turn};
use super::cancel::Cancel;
use super::permissions::Subject;
use super::shell;
use super::util;
use crate::protocol::{Location, ToolContent, ToolKind, ToolUpdate};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

/// What a tool call produced.
#[derive(Debug, Default)]
pub struct Output {
    /// What the model reads.
    pub text: String,
    /// What the screen shows: a diff, a terminal, text.
    pub content: Vec<ToolContent>,
    /// A better title now that the call ran.
    pub title: Option<String>,
    pub locations: Vec<Location>,
    /// The call did not do what was asked (a command that exits non-zero still completed).
    pub failed: bool,
    /// The text is already within the output limits.
    pub bounded: bool,
}

impl Output {
    pub fn text(text: impl Into<String>) -> Output {
        Output { text: text.into(), ..Output::default() }
    }
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn name(&self) -> &str;
    fn description(&self) -> String;
    /// The JSON schema of the arguments.
    fn parameters(&self) -> Value;
    fn kind(&self) -> ToolKind;
    /// What the call does, in a few words: `Read src/main.rs`, `cargo test`.
    fn title(&self, args: &Value, ctx: &ToolCtx<'_>) -> String;
    fn locations(&self, _args: &Value, _ctx: &ToolCtx<'_>) -> Vec<Location> {
        Vec::new()
    }
    /// What permission rules judge; empty for a tool that needs no permission.
    fn subjects(&self, _args: &Value, _ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        Ok(Vec::new())
    }
    /// Shown while the person decides on a permission (the change a call would make).
    async fn preview(&self, _args: &Value, _ctx: &ToolCtx<'_>) -> Vec<ToolContent> {
        Vec::new()
    }
    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String>;
}

/// The tool as the relay's `tools` list takes it.
pub fn definition(tool: &dyn Tool) -> Value {
    json!({
        "type": "function",
        "function": { "name": tool.name(), "description": tool.description(), "parameters": tool.parameters() },
    })
}

/// The built-in tools every profile picks from (`task` is made per profile).
pub fn builtin(web: bool) -> Vec<Arc<dyn Tool>> {
    let mut tools: Vec<Arc<dyn Tool>> = vec![
        Arc::new(bash::Bash),
        Arc::new(files::Read),
        Arc::new(edit::Edit),
        Arc::new(files::Write),
        Arc::new(search::Glob),
        Arc::new(search::Grep),
        Arc::new(files::List),
        Arc::new(todo::TodoWrite),
        Arc::new(question::Question),
    ];
    if web {
        tools.push(Arc::new(web::WebFetch));
    }
    tools
}

/// Everything a tool call may use.
pub struct ToolCtx<'a> {
    pub turn: &'a Turn,
    /// This call's id on the screen.
    pub call: &'a str,
    /// The task call the agent making this call works for.
    pub parent: Option<String>,
}

impl ToolCtx<'_> {
    pub fn shared(&self) -> &Shared {
        &self.turn.shared
    }

    pub fn cwd(&self) -> &Path {
        &self.turn.shared.cwd
    }

    pub fn cancel(&self) -> &Cancel {
        &self.turn.cancel
    }

    pub fn limits(&self) -> Limits {
        self.turn.shared.limits
    }

    /// A path the model gave, made absolute against the working folder.
    pub fn resolve(&self, raw: &str) -> PathBuf {
        absolute(self.cwd(), raw, self.turn.shared.home.as_deref())
    }

    /// A path as the person reads it: relative inside the working folder.
    pub fn show(&self, path: &Path) -> String {
        shown(self.cwd(), path)
    }

    /// The permission subject for a path: its real location, so links cannot hide where it is.
    pub fn path_subject(&self, tool: &str, path: &Path) -> Subject {
        let real = real(path);
        let folder = if real.is_dir() { real.clone() } else { real.parent().map(Path::to_path_buf).unwrap_or_else(|| real.clone()) };
        Subject::new(tool, slash(&real), format!("{}/*", shell::escape(&slash(&folder))))
    }

    pub fn update(&self, update: ToolUpdate) {
        self.turn.shared.events.send(crate::protocol::Event::ToolUpdate(update));
    }

    /// Notes that this agent has seen the whole file as it is now (for write's read-first rule).
    /// Each agent has its own record: a helper's read tells the agent that started it nothing.
    pub fn mark_read(&self, path: &Path) {
        let stamp = modified(path);
        super::agent::lock(&self.turn.shared.files).insert((self.parent.clone(), real(path)), stamp);
    }

    /// When this agent last saw the file: None when it never read it this session.
    pub fn read_stamp(&self, path: &Path) -> Option<Option<SystemTime>> {
        super::agent::lock(&self.turn.shared.files).get(&(self.parent.clone(), real(path))).copied()
    }

    /// Whether this agent has seen the file as it is now.
    pub fn seen_as_it_is(&self, path: &Path) -> bool {
        self.read_stamp(path) == Some(modified(path))
    }
}

pub fn modified(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The first of `names` present as a string.
pub fn text_arg(args: &Value, names: &[&str]) -> Option<String> {
    names.iter().find_map(|name| match args.get(*name) {
        Some(Value::String(text)) => Some(text.clone()),
        Some(Value::Number(n)) => Some(n.to_string()),
        _ => None,
    })
}

pub fn required(args: &Value, names: &[&str]) -> Result<String, String> {
    match text_arg(args, names) {
        Some(text) if !text.trim().is_empty() => Ok(text),
        Some(_) => Err(format!("{} is empty.", names[0])),
        None => Err(format!("{} is missing.", names[0])),
    }
}

/// A number, also when written as a string.
pub fn number_arg(args: &Value, names: &[&str]) -> Option<f64> {
    names.iter().find_map(|name| match args.get(*name) {
        Some(Value::Number(n)) => n.as_f64(),
        Some(Value::String(text)) => text.trim().parse().ok(),
        _ => None,
    })
}

pub fn bool_arg(args: &Value, names: &[&str]) -> Option<bool> {
    names.iter().find_map(|name| match args.get(*name) {
        Some(Value::Bool(b)) => Some(*b),
        Some(Value::String(text)) => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "yes" | "1" => Some(true),
            "false" | "no" | "0" => Some(false),
            _ => None,
        },
        _ => None,
    })
}

/// `raw` made absolute against `cwd` (`~` is the home folder), with `.` and `..` resolved.
pub fn absolute(cwd: &Path, raw: &str, home: Option<&Path>) -> PathBuf {
    let raw = raw.trim().trim_matches(|c| c == '"' || c == '\'' || c == '`');
    let raw = raw.strip_prefix("file://").unwrap_or(raw);
    let path = if raw.is_empty() || raw == "." {
        cwd.to_path_buf()
    } else if raw == "~" {
        home.map(Path::to_path_buf).unwrap_or_else(|| cwd.to_path_buf())
    } else if let (Some(rest), Some(home)) = (raw.strip_prefix("~/"), home) {
        home.join(rest)
    } else {
        let given = Path::new(raw);
        if given.is_absolute() {
            given.to_path_buf()
        } else {
            cwd.join(given)
        }
    };
    normalize(&path)
}

/// `.` and `..` resolved without touching the disk.
pub fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !out.pop() {
                    out.push("..");
                }
            }
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Where a path really is: links resolved for the part that exists, and a link whose target
/// does not exist yet followed to that target, which is what writing through it would create.
pub fn real(path: &Path) -> PathBuf {
    real_within(path, 0)
}

/// How many links in a row `real` follows before it gives up (a loop).
const MAX_LINKS: u32 = 40;

fn real_within(path: &Path, links: u32) -> PathBuf {
    let path = normalize(path);
    let mut rest = Vec::new();
    let mut current = path.as_path();
    loop {
        if let Ok(found) = current.canonicalize() {
            let mut out = plain(found);
            let mut parts = rest.iter().rev();
            // The first missing part may be a link to something missing: judge its target.
            if let Some(first) = parts.next() {
                let link = out.join(first);
                match std::fs::read_link(&link) {
                    Ok(target) if links < MAX_LINKS => out = real_within(&out.join(target), links + 1),
                    _ => out = link,
                }
            }
            for part in parts {
                out.push(part);
            }
            return out;
        }
        match (current.parent(), current.file_name()) {
            (Some(parent), Some(name)) if !parent.as_os_str().is_empty() => {
                rest.push(name.to_owned());
                current = parent;
            }
            _ => return path,
        }
    }
}

/// A canonical path without Windows' `\\?\` prefix.
fn plain(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            if !rest.starts_with("UNC\\") {
                return PathBuf::from(rest);
            }
        }
    }
    path
}

/// The path with forward slashes.
pub fn slash(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// Relative to `cwd` when inside it, otherwise absolute; forward slashes.
pub fn shown(cwd: &Path, path: &Path) -> String {
    match path.strip_prefix(cwd) {
        Ok(rest) if rest.as_os_str().is_empty() => ".".into(),
        Ok(rest) => slash(rest),
        Err(_) => slash(path),
    }
}

/// Replaces a file's content safely: written beside it and moved into place, keeping its
/// permissions. Through a link, the file written is the link's target as `real` finds it (what
/// the permission rules judged), so the link stays a link; a path whose folders are links is
/// written where they lead.
pub fn write_file(path: &Path, content: &[u8]) -> std::io::Result<()> {
    let target = real(path);
    let path = target.as_path();
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    if std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink()) {
        // Only a loop of links is left unresolved: there is no file to write.
        return Err(std::io::Error::other("it is a link that leads nowhere (a loop of links)"));
    }
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let temp = parent.join(format!(".{name}.{}.yougori", util::call_id()));
    std::fs::write(&temp, content)?;
    if let Ok(meta) = std::fs::metadata(path) {
        let _ = std::fs::set_permissions(&temp, meta.permissions());
    }
    match std::fs::rename(&temp, path) {
        Ok(()) => Ok(()),
        Err(error) => {
            let _ = std::fs::remove_file(&temp);
            std::fs::write(path, content).map_err(|_| error)
        }
    }
}

/// Whether bytes look like a binary file (a NUL in the first 8 KB).
pub fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|b| *b == 0)
}

/// How much of one tool output the model gets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    pub lines: usize,
    pub bytes: usize,
}

impl Limits {
    /// At most 2,000 lines and 50 KB, less in small windows: one output may take about 30% of
    /// what the conversation has room for.
    pub fn for_window(window: u32, max_output: u32) -> Limits {
        let room = window.saturating_sub(max_output) as usize;
        Limits { lines: 2000, bytes: (room * 4 * 3 / 10).clamp(8 * 1024, 50 * 1024) }
    }
}

pub const OUTPUT_FOLDER: &str = "tool-output";

/// An output within the limits: its head and tail, with the whole of it saved under
/// `state_dir` and the model told where.
pub fn bound(text: &str, limits: Limits, state_dir: &Path, name: &str) -> String {
    let lines = text.lines().count();
    if text.len() <= limits.bytes && lines <= limits.lines {
        return text.to_owned();
    }
    let saved = save_output(state_dir, name, text);
    let head = take_head(text, limits.lines * 6 / 10, limits.bytes * 6 / 10);
    let tail = take_tail(&text[head.len()..], limits.lines * 3 / 10, limits.bytes * 3 / 10);
    let omitted = &text[head.len()..text.len() - tail.len()];
    let place = match saved {
        Ok(path) => format!("The whole output is in {}: read it with offset and limit, or search it with grep.", slash(&path)),
        Err(error) => format!("The whole output could not be saved: {error}."),
    };
    format!(
        "{}\n\n[... {} lines ({} KB) cut here. {place} ...]\n\n{}",
        head.trim_end_matches('\n'),
        omitted.lines().count(),
        omitted.len().div_ceil(1024),
        tail.trim_start_matches('\n')
    )
}

fn take_head(text: &str, lines: usize, bytes: usize) -> &str {
    let within = util::cut(text, bytes);
    let mut end = 0;
    for (count, (at, _)) in within.match_indices('\n').enumerate() {
        if count >= lines {
            break;
        }
        end = at + 1;
    }
    if end == 0 {
        within
    } else {
        &text[..end]
    }
}

fn take_tail(text: &str, lines: usize, bytes: usize) -> &str {
    let within = util::cut_tail(text, bytes);
    let offset = text.len() - within.len();
    let starts: Vec<usize> = within.match_indices('\n').map(|(at, _)| at + 1).filter(|at| *at < within.len()).collect();
    if starts.is_empty() {
        return within;
    }
    let skip = starts.len().saturating_sub(lines);
    &text[offset + starts[skip.min(starts.len() - 1)]..]
}

fn save_output(state_dir: &Path, name: &str, text: &str) -> std::io::Result<PathBuf> {
    let folder = state_dir.join(OUTPUT_FOLDER);
    std::fs::create_dir_all(&folder)?;
    let safe: String = name.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect();
    let path = folder.join(format!("{safe}.txt"));
    std::fs::write(&path, text)?;
    Ok(path)
}

/// Deletes saved outputs older than a week, and the oldest beyond 300.
pub fn cleanup_outputs(state_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(state_dir.join(OUTPUT_FOLDER)) else { return };
    let week = Duration::from_secs(7 * 24 * 3600);
    let now = SystemTime::now();
    let mut kept: Vec<(SystemTime, PathBuf)> = Vec::new();
    for entry in entries.filter_map(Result::ok) {
        let path = entry.path();
        let Some(time) = modified(&path) else { continue };
        if now.duration_since(time).is_ok_and(|age| age > week) {
            let _ = std::fs::remove_file(&path);
        } else {
            kept.push((time, path));
        }
    }
    if kept.len() > 300 {
        kept.sort();
        for (_, path) in &kept[..kept.len() - 300] {
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Lines numbered as read shows them.
pub fn numbered(text: &str, first: usize, last: usize) -> String {
    text.lines()
        .enumerate()
        .skip(first.saturating_sub(1))
        .take(last + 1 - first.min(last + 1))
        .map(|(index, line)| format!("{:>6}\t{}", index + 1, line.trim_end_matches('\r')))
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_resolve_against_the_folder() {
        let cwd = Path::new("/work/app");
        let home = Path::new("/home/u");
        assert_eq!(absolute(cwd, "src/../lib/./a.rs", Some(home)), Path::new("/work/app/lib/a.rs"));
        assert_eq!(absolute(cwd, "~/notes.md", Some(home)), Path::new("/home/u/notes.md"));
        assert_eq!(absolute(cwd, "\"src/a.rs\"", None), Path::new("/work/app/src/a.rs"));
        assert_eq!(absolute(cwd, "", None), Path::new("/work/app"));
        assert_eq!(shown(cwd, Path::new("/work/app/src/a.rs")), "src/a.rs");
        assert_eq!(shown(cwd, Path::new("/work/app")), ".");
    }

    #[test]
    fn long_outputs_keep_head_and_tail_and_are_saved() {
        let state = tempfile::tempdir().unwrap();
        let text: String = (1..=5000).map(|n| format!("line {n}\n")).collect();
        let limits = Limits { lines: 2000, bytes: 50 * 1024 };
        let bounded = bound(&text, limits, state.path(), "call-1");
        assert!(bounded.starts_with("line 1\n"));
        assert!(bounded.trim_end().ends_with("line 5000"));
        assert!(bounded.lines().count() <= 2000, "{}", bounded.lines().count());
        assert!(bounded.contains("lines ("));
        let saved = state.path().join(OUTPUT_FOLDER).join("call-1.txt");
        assert_eq!(std::fs::read_to_string(&saved).unwrap(), text);
        assert!(bounded.contains(&slash(&saved)));
        // One enormous line is cut by size.
        let wide = "x".repeat(200 * 1024);
        let bounded = bound(&wide, limits, state.path(), "call-2");
        assert!(bounded.len() < 50 * 1024, "{}", bounded.len());
        // Short outputs pass untouched.
        assert_eq!(bound("ok", limits, state.path(), "call-3"), "ok");
        assert_eq!(Limits::for_window(32768, 4096).bytes, 28672 * 4 * 3 / 10);
        assert_eq!(Limits::for_window(262144, 8192).bytes, 50 * 1024);
    }

    /// A link at `link` to `target` (which may not exist), when this system lets the test make
    /// one: symbolic links, or on Windows without that right a junction for a folder.
    pub fn make_link(target: &Path, link: &Path, folder: bool) -> bool {
        #[cfg(unix)]
        {
            let _ = folder;
            std::os::unix::fs::symlink(target, link).is_ok()
        }
        #[cfg(windows)]
        {
            let made =
                if folder { std::os::windows::fs::symlink_dir(target, link) } else { std::os::windows::fs::symlink_file(target, link) };
            made.is_ok()
                || (folder
                    && std::process::Command::new("cmd")
                        .args(["/D", "/C", "mklink", "/J"])
                        .arg(link)
                        .arg(target)
                        .stdin(std::process::Stdio::null())
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status()
                        .is_ok_and(|s| s.success()))
        }
    }

    #[test]
    fn a_link_to_something_missing_is_judged_and_written_at_its_target() {
        let folder = tempfile::tempdir().unwrap();
        let project = folder.path().join("project");
        let outside = folder.path().join("outside");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        let mut made = 0;
        // A folder link to a folder that does not exist yet.
        let out = project.join("out");
        if make_link(&outside.join("missing"), &out, true) {
            made += 1;
            assert_eq!(real(&out.join("a.txt")), real(&outside).join("missing").join("a.txt"));
            assert_eq!(real(&out), real(&outside).join("missing"));
            // Writing through it lands where it was judged, and the link stays.
            write_file(&out.join("a.txt"), b"through the link").unwrap();
            assert_eq!(std::fs::read_to_string(outside.join("missing").join("a.txt")).unwrap(), "through the link");
            assert!(std::fs::symlink_metadata(&out).unwrap().file_type().is_symlink(), "the link stays a link");
        }
        // A file link (a cloned repository's notes.md -> ~/.gitconfig) whose target is missing.
        let notes = project.join("notes.md");
        if make_link(&outside.join("gitconfig"), &notes, false) {
            made += 1;
            assert_eq!(real(&notes), real(&outside).join("gitconfig"), "judged where a write would land");
            write_file(&notes, b"[core]\n").unwrap();
            assert_eq!(std::fs::read_to_string(outside.join("gitconfig")).unwrap(), "[core]\n");
            assert!(std::fs::symlink_metadata(&notes).unwrap().file_type().is_symlink(), "the link stays a link");
            // A relative link, and a loop, which leads nowhere.
            let relative = project.join("relative.md");
            if make_link(Path::new("../outside/rel.txt"), &relative, false) {
                assert_eq!(real(&relative), real(&outside).join("rel.txt"));
            }
            let (a, b) = (project.join("a"), project.join("b"));
            if make_link(&b, &a, false) && make_link(&a, &b, false) {
                let _ = real(&a);
                assert!(write_file(&a, b"x").is_err());
            }
        }
        if made == 0 {
            eprintln!("This system made no links, so the link cases were not run.");
        }
        // Without links, a missing file is where it was given.
        assert_eq!(real(&project.join("new").join("file.txt")), real(&project).join("new").join("file.txt"));
    }

    #[test]
    fn files_are_replaced_in_place() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("deep").join("a.txt");
        write_file(&path, b"one").unwrap();
        write_file(&path, b"two").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "two");
        let leftovers: Vec<_> = std::fs::read_dir(path.parent().unwrap()).unwrap().collect();
        assert_eq!(leftovers.len(), 1, "no temporary files left");
        assert_eq!(numbered("a\nb\nc", 2, 3), "     2\tb\n     3\tc");
    }
}
