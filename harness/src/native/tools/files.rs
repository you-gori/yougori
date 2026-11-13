//! read, write and list.
use super::{is_binary, modified, number_arg, required, slash, text_arg, write_file, Output, Tool, ToolCtx};
use crate::native::permissions::Subject;
use crate::protocol::{Location, ToolContent, ToolKind};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};

const PATH: &[&str] = &["path", "file_path", "filePath", "file", "filename"];
const MAX_LINES: usize = 2000;
const LINE_CHARS: usize = 2000;

pub struct Read;

#[async_trait]
impl Tool for Read {
    fn name(&self) -> &str {
        "read"
    }

    fn description(&self) -> String {
        "Read a text file. Each line comes with its number and a tab before it; the numbers are not part of the file. \
         Long files come in parts of up to 2000 lines: use offset and limit to read more. Use list for folders."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The file, relative to the project folder or absolute." },
                "offset": { "type": "integer", "description": "The line to start at (1 is the first)." },
                "limit": { "type": "integer", "description": "How many lines to read (at most 2000)." }
            },
            "required": ["path"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Read
    }

    fn title(&self, args: &Value, ctx: &ToolCtx<'_>) -> String {
        let path = text_arg(args, PATH).map(|p| ctx.show(&ctx.resolve(&p))).unwrap_or_default();
        format!("Read {path}")
    }

    fn locations(&self, args: &Value, ctx: &ToolCtx<'_>) -> Vec<Location> {
        let line = number_arg(args, &["offset"]).map(|n| n.max(1.0) as u32);
        text_arg(args, PATH).map(|p| vec![Location { path: slash(&ctx.resolve(&p)), line }]).unwrap_or_default()
    }

    fn subjects(&self, args: &Value, ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        Ok(vec![ctx.path_subject("read", &ctx.resolve(&required(args, PATH)?))])
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let path = ctx.resolve(&required(&args, PATH)?);
        let shown = ctx.show(&path);
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(not_found(&path, &shown)),
            Err(e) => return Err(format!("Cannot read {shown}: {e}.")),
        };
        if meta.is_dir() {
            return Err(format!("{shown} is a folder. Use list to see what is in it."));
        }
        let offset = number_arg(&args, &["offset", "start_line", "line"]).map(|n| n.max(1.0) as usize).unwrap_or(1);
        let limit = number_arg(&args, &["limit", "lines", "count"]).map(|n| n.clamp(1.0, MAX_LINES as f64) as usize).unwrap_or(MAX_LINES);
        let budget = ctx.limits().bytes;
        let file = path.clone();
        let label = shown.clone();
        let size = meta.len();
        let (text, first, last) = tokio::task::spawn_blocking(move || read_lines(&file, &label, size, offset, limit, budget))
            .await
            .map_err(|e| format!("Reading {shown} failed: {e}."))??;
        ctx.mark_read(&path);
        let title = if first == 0 {
            format!("Read {shown}")
        } else if offset > 1 || limit < MAX_LINES {
            format!("Read {shown} (lines {first}-{last})")
        } else {
            format!("Read {shown} ({last} lines)")
        };
        Ok(Output {
            text,
            title: Some(title),
            locations: vec![Location { path: slash(&path), line: Some(first.max(1) as u32) }],
            bounded: true,
            ..Output::default()
        })
    }
}

/// Lines `offset..offset+limit` numbered, within `budget` bytes, with a line saying where
/// the file goes on. Returns the text and the first and last line shown (0, 0 for none).
fn read_lines(path: &Path, shown: &str, size: u64, offset: usize, limit: usize, budget: usize) -> Result<(String, usize, usize), String> {
    let file = std::fs::File::open(path).map_err(|e| format!("Cannot read {shown}: {e}."))?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let start = reader.fill_buf().map_err(|e| format!("Cannot read {shown}: {e}."))?;
    if is_binary(start) {
        return Err(format!("{shown} is a binary file ({} KB), not text.", size.div_ceil(1024)));
    }
    let mut out = String::new();
    let mut line = Vec::new();
    let (mut number, mut first, mut last) = (0usize, 0usize, 0usize);
    let mut full = false;
    // Counting the lines after the part shown stops after 64 MB.
    let mut scanned: u64 = 0;
    let mut counted_all = true;
    loop {
        line.clear();
        let read = reader.read_until(b'\n', &mut line).map_err(|e| format!("Cannot read {shown}: {e}."))?;
        if read == 0 {
            break;
        }
        scanned += read as u64;
        number += 1;
        if number < offset || number >= offset + limit || full {
            if number >= offset && scanned > 64 * 1024 * 1024 {
                counted_all = false;
                break;
            }
            continue;
        }
        let text = String::from_utf8_lossy(&line);
        let text = text.trim_end_matches('\n').trim_end_matches('\r');
        let text = if text.chars().count() > LINE_CHARS {
            let kept: String = text.chars().take(LINE_CHARS).collect();
            format!("{kept}\u{2026} [line cut: {} characters]", text.chars().count())
        } else {
            text.to_owned()
        };
        let entry = format!("{number:>6}\t{text}\n");
        if !out.is_empty() && out.len() + entry.len() > budget {
            full = true;
            continue;
        }
        out.push_str(&entry);
        if first == 0 {
            first = number;
        }
        last = number;
    }
    let total = if counted_all { number.to_string() } else { format!("more than {number}") };
    if number == 0 {
        return Ok(("(The file is empty.)".into(), 0, 0));
    }
    if first == 0 {
        return Err(format!("{shown} has only {total} lines; offset {offset} is past the end."));
    }
    let more = last < number || !counted_all;
    let footer = if !more {
        if first == 1 {
            format!("(End of file: {total} lines.)")
        } else {
            format!("(Lines {first}-{last} of {total}: the end of the file.)")
        }
    } else if full {
        format!("(Lines {first}-{last} of {total}; the rest did not fit. Read on with offset={}.)", last + 1)
    } else {
        format!("(Lines {first}-{last} of {total}. Read on with offset={}.)", last + 1)
    };
    out.push_str(&footer);
    Ok((out, first, last))
}

/// A missing file, with names nearby that look like it.
fn not_found(path: &Path, shown: &str) -> String {
    let Some(folder) = path.parent() else { return format!("{shown} does not exist.") };
    let Ok(entries) = std::fs::read_dir(folder) else {
        return format!("{shown} does not exist, nor does its folder.");
    };
    let wanted = path.file_name().map(|n| n.to_string_lossy().to_lowercase()).unwrap_or_default();
    let stem = wanted.split('.').next().unwrap_or("").to_owned();
    let mut close: Vec<(usize, String)> = entries
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter_map(|name| {
            let lower = name.to_lowercase();
            let distance = edit_distance(&lower, &wanted);
            let related = (!stem.is_empty() && lower.starts_with(&stem)) || lower.contains(&wanted) || wanted.contains(&lower);
            (distance <= 3 || related).then_some((distance, name))
        })
        .collect();
    close.sort();
    if close.is_empty() {
        return format!("{shown} does not exist.");
    }
    let names: Vec<String> = close.into_iter().take(3).map(|(_, n)| n).collect();
    format!("{shown} does not exist. Did you mean: {}?", names.join(", "))
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut previous = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let current = row[j + 1];
            row[j + 1] = if ca == *cb { previous } else { 1 + previous.min(row[j]).min(row[j + 1]) };
            previous = current;
        }
    }
    row[b.len()]
}

pub struct Write;

#[async_trait]
impl Tool for Write {
    fn name(&self) -> &str {
        "write"
    }

    fn description(&self) -> String {
        "Create a file, or replace a whole file, with the content given. Folders are made as needed. To change part of \
         an existing file use edit instead; to replace an existing file, read it first."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The file, relative to the project folder or absolute." },
                "content": { "type": "string", "description": "The whole new content of the file." }
            },
            "required": ["path", "content"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Edit
    }

    fn title(&self, args: &Value, ctx: &ToolCtx<'_>) -> String {
        let path = text_arg(args, PATH).map(|p| ctx.show(&ctx.resolve(&p))).unwrap_or_default();
        format!("Write {path}")
    }

    fn locations(&self, args: &Value, ctx: &ToolCtx<'_>) -> Vec<Location> {
        text_arg(args, PATH).map(|p| vec![Location { path: slash(&ctx.resolve(&p)), line: None }]).unwrap_or_default()
    }

    fn subjects(&self, args: &Value, ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        Ok(vec![ctx.path_subject("write", &ctx.resolve(&required(args, PATH)?))])
    }

    async fn preview(&self, args: &Value, ctx: &ToolCtx<'_>) -> Vec<ToolContent> {
        let (Ok(raw), Some(content)) = (required(args, PATH), content_of(args)) else { return Vec::new() };
        let path = ctx.resolve(&raw);
        let old = std::fs::read_to_string(&path).ok();
        vec![ToolContent::Diff { path: slash(&path), old, new: content }]
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let path = ctx.resolve(&required(&args, PATH)?);
        let shown = ctx.show(&path);
        let content = content_of(&args).ok_or("content is missing.")?;
        if path.is_dir() {
            return Err(format!("{shown} is a folder."));
        }
        let old = match std::fs::read(&path) {
            Ok(bytes) => Some(String::from_utf8_lossy(&bytes).into_owned()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
            Err(e) => return Err(format!("Cannot read {shown}: {e}.")),
        };
        if let Some(old) = &old {
            if *old == content {
                ctx.mark_read(&path);
                return Ok(Output::text(format!("{shown} already holds exactly this content; nothing changed.")));
            }
            match ctx.read_stamp(&path) {
                None => {
                    return Err(format!(
                        "{shown} already exists. Read it first, then write the whole new content, or change parts with edit."
                    ))
                }
                Some(stamp) if stamp != modified(&path) => {
                    return Err(format!("{shown} changed since you read it. Read it again first."));
                }
                Some(_) => {}
            }
        }
        // Keep a file's Windows line endings.
        let content = match &old {
            Some(old) if uses_crlf(old) && !content.contains('\r') => content.replace('\n', "\r\n"),
            _ => content,
        };
        write_file(&path, content.as_bytes()).map_err(|e| format!("Cannot write {shown}: {e}."))?;
        ctx.mark_read(&path);
        let lines = content.lines().count();
        let verb = if old.is_some() { "Wrote" } else { "Created" };
        Ok(Output {
            text: format!("{verb} {shown} ({lines} lines)."),
            content: vec![super::edit::diff(&path, old.as_deref(), &content)],
            locations: vec![Location { path: slash(&path), line: None }],
            ..Output::default()
        })
    }
}

fn content_of(args: &Value) -> Option<String> {
    text_arg(args, &["content", "contents", "text", "file_text", "data"])
}

pub fn uses_crlf(text: &str) -> bool {
    let crlf = text.matches("\r\n").count();
    crlf > 0 && crlf == text.matches('\n').count()
}

/// Folders list leaves out even when no .gitignore names them.
pub const SKIPPED: &[&str] = &[
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".next",
    ".nuxt", ".cache", ".gradle", ".idea", ".tox", "dist", "build", "target", ".turbo", ".svelte-kit",
];
const LIST_ENTRIES: usize = 300;

pub struct List;

#[async_trait]
impl Tool for List {
    fn name(&self) -> &str {
        "list"
    }

    fn description(&self) -> String {
        "Show the files and folders under a folder as a tree. Skips what .gitignore ignores and build or dependency \
         folders. Use glob to find files by name and grep to search inside them."
            .into()
    }

    fn parameters(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "path": { "type": "string", "description": "The folder (default: the project folder)." }
            }
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Search
    }

    fn title(&self, args: &Value, ctx: &ToolCtx<'_>) -> String {
        let path = ctx.resolve(&text_arg(args, &["path", "dir", "directory", "folder"]).unwrap_or_default());
        format!("List {}", ctx.show(&path))
    }

    fn subjects(&self, args: &Value, ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        let path = ctx.resolve(&text_arg(args, &["path", "dir", "directory", "folder"]).unwrap_or_default());
        Ok(vec![ctx.path_subject("list", &path)])
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let root = ctx.resolve(&text_arg(&args, &["path", "dir", "directory", "folder"]).unwrap_or_default());
        let shown = ctx.show(&root);
        if !root.exists() {
            return Err(not_found(&root, &shown));
        }
        if !root.is_dir() {
            return Err(format!("{shown} is a file. Use read to see it."));
        }
        let cancel = ctx.cancel().clone();
        let folder = root.clone();
        let tree = tokio::task::spawn_blocking(move || tree(&folder, LIST_ENTRIES, &cancel))
            .await
            .map_err(|e| format!("Listing {shown} failed: {e}."))?;
        Ok(Output {
            text: format!("{}/\n{tree}", slash(&root).trim_end_matches('/')),
            content: Vec::new(),
            ..Output::default()
        })
    }
}

/// A tree of `root`, broad before deep: every entry one level down before any two levels down,
/// until `cap` entries.
fn tree(root: &Path, cap: usize, cancel: &crate::native::cancel::Cancel) -> String {
    let mut all: Vec<(PathBuf, bool, usize)> = Vec::new();
    let walker = ignore::WalkBuilder::new(root)
        .hidden(false)
        .require_git(false)
        .follow_links(false)
        .filter_entry(|entry| entry.depth() == 0 || !SKIPPED.contains(&entry.file_name().to_string_lossy().as_ref()))
        .build();
    for entry in walker.filter_map(Result::ok) {
        if cancel.is_cancelled() || all.len() >= 20_000 {
            break;
        }
        if entry.depth() == 0 {
            continue;
        }
        let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
        let rel = entry.path().strip_prefix(root).unwrap_or(entry.path()).to_path_buf();
        all.push((rel, is_dir, entry.depth()));
    }
    let mut children: BTreeMap<PathBuf, usize> = BTreeMap::new();
    for (rel, _, _) in &all {
        *children.entry(rel.parent().map(Path::to_path_buf).unwrap_or_default()).or_default() += 1;
    }
    let mut chosen: BTreeSet<PathBuf> = BTreeSet::new();
    let deepest = all.iter().map(|(_, _, d)| *d).max().unwrap_or(0);
    'levels: for depth in 1..=deepest {
        for (rel, _, d) in &all {
            if *d != depth {
                continue;
            }
            if chosen.len() >= cap {
                break 'levels;
            }
            let parent_shown = rel.parent().is_none_or(|p| p.as_os_str().is_empty() || chosen.contains(p));
            if parent_shown {
                chosen.insert(rel.clone());
            }
        }
    }
    let kinds: BTreeMap<&PathBuf, bool> = all.iter().map(|(rel, dir, _)| (rel, *dir)).collect();
    let mut out = String::new();
    render(Path::new(""), 1, &chosen, &kinds, &children, &mut out);
    let left = all.len().saturating_sub(chosen.len());
    if all.is_empty() {
        out.push_str("(empty)\n");
    } else if left > 0 {
        out.push_str(&format!("({left} more entries not shown: list a subfolder to see them.)\n"));
    }
    out.trim_end().to_owned()
}

fn render(
    folder: &Path,
    depth: usize,
    chosen: &BTreeSet<PathBuf>,
    kinds: &BTreeMap<&PathBuf, bool>,
    children: &BTreeMap<PathBuf, usize>,
    out: &mut String,
) {
    let mut here: Vec<&PathBuf> = chosen.iter().filter(|p| p.parent() == Some(folder)).collect();
    // Folders first, then files, each by name.
    here.sort_by_key(|p| (!kinds.get(p).copied().unwrap_or(false), p.file_name().map(|n| n.to_string_lossy().to_lowercase())));
    for path in &here {
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let is_dir = kinds.get(path).copied().unwrap_or(false);
        out.push_str(&"  ".repeat(depth));
        out.push_str(&name);
        if is_dir {
            out.push('/');
            let total = children.get(*path).copied().unwrap_or(0);
            let shown = chosen.iter().filter(|p| p.parent() == Some(path.as_path())).count();
            if total > shown {
                out.push_str(&format!(" ({} {})", total - shown, if shown == 0 { "entries" } else { "more" }));
            }
        }
        out.push('\n');
        if is_dir {
            render(path, depth + 1, chosen, kinds, children, out);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::cancel::Cancel;

    #[test]
    fn read_numbers_lines_and_says_where_to_go_on() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("a.txt");
        let text: String = (1..=30).map(|n| format!("line {n}\r\n")).collect();
        std::fs::write(&path, &text).unwrap();
        let (out, first, last) = read_lines(&path, "a.txt", 0, 1, 10, 50_000).unwrap();
        assert_eq!((first, last), (1, 10));
        assert!(out.starts_with("     1\tline 1\n"), "{out}");
        assert!(out.ends_with("(Lines 1-10 of 30. Read on with offset=11.)"), "{out}");
        let (out, _, last) = read_lines(&path, "a.txt", 0, 25, 2000, 50_000).unwrap();
        assert_eq!(last, 30);
        assert!(out.ends_with("(Lines 25-30 of 30: the end of the file.)"), "{out}");
        let (out, _, _) = read_lines(&path, "a.txt", 0, 1, 2000, 60).unwrap();
        assert!(out.contains("the rest did not fit"), "{out}");
        assert!(read_lines(&path, "a.txt", 0, 99, 10, 50_000).unwrap_err().contains("only 30 lines"));
        std::fs::write(&path, b"bin\0ary").unwrap();
        assert!(read_lines(&path, "a.txt", 7, 1, 10, 50_000).unwrap_err().contains("binary"));
        std::fs::write(&path, "").unwrap();
        assert_eq!(read_lines(&path, "a.txt", 0, 1, 10, 50_000).unwrap().0, "(The file is empty.)");
    }

    #[test]
    fn a_missing_file_suggests_near_names() {
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join("config.toml"), "").unwrap();
        std::fs::write(folder.path().join("main.rs"), "").unwrap();
        let message = not_found(&folder.path().join("confg.toml"), "confg.toml");
        assert!(message.contains("Did you mean: config.toml"), "{message}");
        assert_eq!(edit_distance("kitten", "sitting"), 3);
    }

    #[test]
    fn list_shows_a_broad_tree_without_ignored_folders() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path();
        std::fs::create_dir_all(root.join("src").join("deep")).unwrap();
        std::fs::create_dir_all(root.join("node_modules").join("x")).unwrap();
        std::fs::create_dir_all(root.join("logs")).unwrap();
        std::fs::write(root.join("src").join("main.rs"), "").unwrap();
        std::fs::write(root.join("src").join("deep").join("a.rs"), "").unwrap();
        std::fs::write(root.join("README.md"), "").unwrap();
        std::fs::write(root.join(".gitignore"), "logs/\n").unwrap();
        std::fs::write(root.join("logs").join("x.log"), "").unwrap();
        let text = tree(root, 300, &Cancel::new());
        assert!(text.contains("  src/\n    deep/\n      a.rs\n    main.rs\n"), "{text}");
        assert!(text.contains("  README.md"), "{text}");
        assert!(!text.contains("node_modules") && !text.contains("x.log"), "{text}");
        let small = tree(root, 2, &Cancel::new());
        assert!(small.contains("more entries not shown"), "{small}");
    }
}
